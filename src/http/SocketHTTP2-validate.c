/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/*
 * SocketHTTP2-validate.c - HTTP/2 Header and TLS Validation (RFC 9113)
 */

#include <string.h>
#include <strings.h>

#include "http/SocketHPACK.h"
#include "http/SocketHTTP2-private.h"
#include "socket/Socket.h"

#if SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#include <openssl/ssl.h>
#endif

static const struct
{
  const char *name;
  size_t len;
} http2_forbidden_headers[] = {
  { "connection", 10 },
  { "keep-alive", 10 },
  { "proxy-authenticate", 18 },
  { "proxy-authorization", 19 },
  { "te", 2 },
  { "trailers", 8 },
  { "transfer-encoding", 17 },
  { "upgrade", 7 }
};

#define HTTP2_FORBIDDEN_HEADER_COUNT \
  (sizeof (http2_forbidden_headers) / sizeof (http2_forbidden_headers[0]))

int
http2_field_has_uppercase (const char *name, size_t len)
{
  for (size_t i = 0; i < len; i++)
    {
      unsigned char c = (unsigned char)name[i];
      if (c >= 'A' && c <= 'Z')
        return 1;
    }
  return 0;
}

int
http2_field_has_prohibited_chars (const char *data, size_t len)
{
  for (size_t i = 0; i < len; i++)
    {
      unsigned char c = (unsigned char)data[i];
      /* NUL (0x00), CR (0x0D), LF (0x0A) are prohibited */
      if (c == 0x00 || c == 0x0D || c == 0x0A)
        return 1;
    }
  return 0;
}

int
http2_field_name_has_prohibited_chars (const char *name, size_t len)
{
  /*
   * RFC 9113 §8.2.1: Field name validation
   *
   * "A field name MUST NOT contain characters in the ranges
   *  0x00-0x20, 0x41-0x5a, or 0x7f-0xff."
   *
   * Additionally:
   * "With the exception of pseudo-header fields, which have a name
   *  that starts with a single colon, field names MUST NOT include
   *  a colon."
   */
  for (size_t i = 0; i < len; i++)
    {
      unsigned char c = (unsigned char)name[i];

      /* 0x00-0x20: NUL, control characters (including TAB), and space */
      if (c <= 0x20)
        return 1;

      /* 0x41-0x5A: Uppercase A-Z */
      if (c >= 0x41 && c <= 0x5A)
        return 1;

      /* 0x7F-0xFF: DEL and extended ASCII */
      if (c >= 0x7F)
        return 1;

      /* Colon only allowed as first character (pseudo-headers) */
      if (c == ':' && i > 0)
        return 1;
    }
  return 0;
}

int
http2_field_has_boundary_whitespace (const char *value, size_t len)
{
  if (len == 0)
    return 0;

  /* Check leading whitespace (SP or HTAB) */
  unsigned char first = (unsigned char)value[0];
  if (first == ' ' || first == '\t')
    return 1;

  /* Check trailing whitespace */
  unsigned char last = (unsigned char)value[len - 1];
  if (last == ' ' || last == '\t')
    return 1;

  return 0;
}

int
http2_is_connection_header_forbidden (const SocketHPACK_Header *header)
{
  if (header == NULL || header->name == NULL)
    return 0;

  for (size_t i = 0; i < HTTP2_FORBIDDEN_HEADER_COUNT; i++)
    {
      if (header->name_len == http2_forbidden_headers[i].len
          && strncasecmp (header->name, http2_forbidden_headers[i].name,
                          http2_forbidden_headers[i].len)
                 == 0)
        {
          /*
           * TE header is a special case: it's allowed only with "trailers"
           * value. Return 0 here (not forbidden) and let caller validate
           * the value separately via http2_validate_te_header().
           */
          if (http2_forbidden_headers[i].len == 2)
            return 0;
          return 1;
        }
    }

  return 0;
}

int
http2_validate_te_header (const char *value, size_t len)
{
  /* Empty TE is equivalent to "trailers" and is allowed */
  if (len == 0 || value == NULL)
    return 0;

  /* TE must be exactly "trailers" */
  if (len == 8 && memcmp (value, "trailers", 8) == 0)
    return 0;

  /* Any other value is invalid in HTTP/2 */
  return -1;
}

int
http2_validate_regular_header (const SocketHPACK_Header *header)
{
  if (header == NULL)
    return -1;

  /* RFC 9113 §8.2.1: Complete field name validation
   * (includes lowercase check, control chars, space, DEL, extended ASCII,
   * and colon position) */
  if (http2_field_name_has_prohibited_chars (header->name, header->name_len))
    return -1;

  /* No prohibited characters in field value */
  if (http2_field_has_prohibited_chars (header->value, header->value_len))
    return -1;

  /* No leading/trailing whitespace in field value */
  if (http2_field_has_boundary_whitespace (header->value, header->value_len))
    return -1;

  /* Check for forbidden connection-specific headers */
  if (http2_is_connection_header_forbidden (header))
    return -1;

  /* Special TE header validation */
  if (header->name_len == 2 && memcmp (header->name, "te", 2) == 0)
    {
      if (http2_validate_te_header (header->value, header->value_len) != 0)
        return -1;
    }

  return 0;
}

/*
 * TLS Validation for HTTP/2 (RFC 9113 Section 9.2 and Appendix A)
 *
 * RFC 9113 Section 9.2:
 * "Implementations of HTTP/2 MUST use TLS version 1.2 or higher for HTTP/2
 *  over TLS."
 * "The TLS implementation MUST support the Server Name Indication (SNI)
 *  extension"
 * "HTTP/2 MUST be used over TLS using ALPN"
 *
 * RFC 9113 Appendix A - TLS 1.2 Cipher Suite Blocklist:
 * All cipher suites that do not offer forward secrecy or that use
 * encryption algorithms considered weak MUST NOT be used.
 */

#if SOCKET_HAS_TLS

/* RFC 9113 Appendix A: Forbidden cipher patterns */
static int
http2_is_cipher_forbidden (const char *cipher)
{
  if (cipher == NULL)
    return 1; /* No cipher is forbidden */

  /* NULL ciphers - no encryption */
  if (strstr (cipher, "NULL") != NULL)
    return 1;

  /* Export ciphers - weak */
  if (strstr (cipher, "EXPORT") != NULL)
    return 1;

  /* RC4 ciphers - broken */
  if (strstr (cipher, "RC4") != NULL)
    return 1;

  /* 3DES ciphers - weak (Sweet32) */
  if (strstr (cipher, "3DES") != NULL)
    return 1;
  if (strstr (cipher, "DES-CBC3") != NULL)
    return 1;

  /* Anonymous ciphers - no authentication */
  if (strstr (cipher, "ADH") != NULL)
    return 1;
  if (strstr (cipher, "AECDH") != NULL)
    return 1;
  if (strncmp (cipher, "aNULL", 5) == 0)
    return 1;

  /* DES ciphers (single DES) - very weak */
  if (strstr (cipher, "-DES-") != NULL
      && strstr (cipher, "3DES") == NULL
      && strstr (cipher, "DES-CBC3") == NULL)
    return 1;

  /* MD5 MAC - weak hash */
  if (strstr (cipher, "MD5") != NULL)
    return 1;

  return 0; /* Cipher is allowed */
}

#endif /* SOCKET_HAS_TLS */

SocketHTTP2_TLSResult
SocketHTTP2_validate_tls (Socket_T socket)
{
  if (socket == NULL)
    return HTTP2_TLS_NOT_ENABLED;

#if SOCKET_HAS_TLS
  /* Check if TLS is enabled on this socket */
  const char *version_str = SocketTLS_get_version (socket);
  if (version_str == NULL)
    {
      /* TLS not enabled - this is OK for h2c (cleartext HTTP/2) */
      return HTTP2_TLS_NOT_ENABLED;
    }

  /* RFC 9113 §9.2: TLS 1.2 or higher required */
  int protocol_version = SocketTLS_get_protocol_version (socket);
  if (protocol_version < TLS1_2_VERSION)
    {
      return HTTP2_TLS_VERSION_TOO_LOW;
    }

  /* RFC 9113 §9.2: ALPN "h2" must be negotiated for TLS connections */
  const char *alpn = SocketTLS_get_alpn_selected (socket);
  if (alpn == NULL || strcmp (alpn, "h2") != 0)
    {
      return HTTP2_TLS_ALPN_MISMATCH;
    }

  /* RFC 9113 Appendix A: Check cipher suite is not forbidden */
  const char *cipher = SocketTLS_get_cipher (socket);
  if (http2_is_cipher_forbidden (cipher))
    {
      return HTTP2_TLS_CIPHER_FORBIDDEN;
    }

  return HTTP2_TLS_OK;

#else
  /* TLS support not compiled in */
  return HTTP2_TLS_NOT_ENABLED;
#endif
}

const char *
SocketHTTP2_tls_result_string (SocketHTTP2_TLSResult result)
{
  switch (result)
    {
    case HTTP2_TLS_OK:
      return "TLS requirements satisfied";
    case HTTP2_TLS_NOT_ENABLED:
      return "TLS not enabled (cleartext HTTP/2)";
    case HTTP2_TLS_VERSION_TOO_LOW:
      return "TLS version too low (RFC 9113 requires TLS 1.2+)";
    case HTTP2_TLS_CIPHER_FORBIDDEN:
      return "Forbidden cipher suite (RFC 9113 Appendix A)";
    case HTTP2_TLS_ALPN_MISMATCH:
      return "ALPN protocol is not 'h2' (RFC 9113 §9.2)";
    default:
      return "Unknown TLS validation error";
    }
}
