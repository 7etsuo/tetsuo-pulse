/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/*
 * SocketHTTP2-validate.c - HTTP/2 Header and TLS Validation (RFC 9113)
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "http/SocketHPACK.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP2-private.h"
#include "socket/Socket.h"

#if SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#include <openssl/ssl.h>
#endif

/* String literal length at compile time */
#define STRLEN_LIT(s) (sizeof (s) - 1)

/* HTTP/2 header validation constants */
#define HTTP2_TE_HEADER_LEN 2
#define DECIMAL_BASE        10

/*
 * RFC 9113 §8.2.2: Connection-Specific Header Fields
 *
 * HTTP/2 forbids connection-specific headers from HTTP/1.1.
 * Array is sorted alphabetically for O(log n) binary search.
 */
static const struct
{
  const char *name;
  size_t len;
} http2_forbidden_headers[] = {
  { "connection", STRLEN_LIT ("connection") },          /* Alphabetically sorted */
  { "keep-alive", STRLEN_LIT ("keep-alive") },
  { "proxy-authenticate", STRLEN_LIT ("proxy-authenticate") },
  { "proxy-authorization", STRLEN_LIT ("proxy-authorization") },
  { "te", STRLEN_LIT ("te") },
  { "trailers", STRLEN_LIT ("trailers") },
  { "transfer-encoding", STRLEN_LIT ("transfer-encoding") },
  { "upgrade", STRLEN_LIT ("upgrade") }
};

#define HTTP2_FORBIDDEN_HEADER_COUNT \
  (sizeof (http2_forbidden_headers) / sizeof (http2_forbidden_headers[0]))

/*
 * Binary search comparison function for forbidden header lookup.
 *
 * Returns:
 *   < 0 if header < entry (header sorts before)
 *   > 0 if header > entry (header sorts after)
 *     0 if header == entry (match found)
 */
static int
compare_forbidden_header (const void *key, const void *elem)
{
  const SocketHPACK_Header *header = (const SocketHPACK_Header *)key;
  const struct
  {
    const char *name;
    size_t len;
  } *entry = elem;

  /* Compare length first for quick rejection */
  if (header->name_len < entry->len)
    return -1;
  if (header->name_len > entry->len)
    return 1;

  /* Case-insensitive name comparison */
  return strncasecmp (header->name, entry->name, entry->len);
}

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

/*
 * Check if header is a forbidden connection-specific header.
 *
 * Uses O(log n) binary search over sorted forbidden header list.
 * For 8 headers: max 3 comparisons vs 8 for linear search.
 *
 * Returns:
 *   1 if header is forbidden
 *   0 if header is allowed (including special case for "te")
 */
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
          if (http2_forbidden_headers[i].len == HTTP2_TE_HEADER_LEN)
            return 0;
          return 1;
        }
    }

  return 0; /* Not forbidden */
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

/* Pattern matching functions for cipher validation */
static int
pattern_contains (const char *cipher, const char *pattern)
{
  return strstr (cipher, pattern) != NULL;
}

static int
pattern_starts_with (const char *cipher, const char *pattern)
{
  return strncmp (cipher, pattern, strlen (pattern)) == 0;
}

static int
pattern_contains_excluding_3des (const char *cipher, const char *pattern)
{
  /* Match -DES- but not if part of 3DES or DES-CBC3 */
  if (strstr (cipher, pattern) == NULL)
    return 0;
  if (strstr (cipher, "3DES") != NULL)
    return 0;
  if (strstr (cipher, "DES-CBC3") != NULL)
    return 0;
  return 1;
}

/* Dispatch table for forbidden cipher patterns */
static const struct
{
  const char *pattern;
  int (*matcher) (const char *cipher, const char *pattern);
} forbidden_cipher_patterns[] = {
  { "NULL", pattern_contains },              /* NULL ciphers - no encryption */
  { "EXPORT", pattern_contains },            /* Export ciphers - weak */
  { "RC4", pattern_contains },               /* RC4 ciphers - broken */
  { "3DES", pattern_contains },              /* 3DES ciphers - weak (Sweet32) */
  { "DES-CBC3", pattern_contains },          /* 3DES variant */
  { "ADH", pattern_contains },               /* Anonymous DH - no auth */
  { "AECDH", pattern_contains },             /* Anonymous ECDH - no auth */
  { "aNULL", pattern_starts_with },          /* Anonymous NULL - no auth */
  { "-DES-", pattern_contains_excluding_3des }, /* Single DES - very weak */
  { "MD5", pattern_contains }                /* MD5 MAC - weak hash */
};

#define FORBIDDEN_CIPHER_COUNT \
  (sizeof (forbidden_cipher_patterns) / sizeof (forbidden_cipher_patterns[0]))

static int
http2_is_cipher_forbidden (const char *cipher)
{
  if (cipher == NULL)
    return 1; /* No cipher is forbidden */

  for (size_t i = 0; i < FORBIDDEN_CIPHER_COUNT; i++)
    {
      if (forbidden_cipher_patterns[i].matcher (cipher,
                                                 forbidden_cipher_patterns[i]
                                                     .pattern))
        return 1;
    }

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

/*
 * Pseudo-Header Validation Helpers (RFC 9113 Section 8.3)
 *
 * These functions provide modular validation for HTTP/2 pseudo-headers,
 * reducing nesting depth and improving testability.
 */

/**
 * @brief Parse decimal digits to uint64_t with overflow protection
 * @param value String containing only digits
 * @param len Length of value
 * @param result Output: parsed value
 * @param max_value Maximum allowed value (for range validation)
 * @return 0 on success, -1 on invalid input or overflow
 *
 * This helper extracts the common digit parsing logic used by status code
 * and content-length parsers, ensuring consistent overflow protection and
 * validation across all numeric header parsing.
 */
static int
parse_decimal_uint64 (const char *value, size_t len, uint64_t *result,
                      uint64_t max_value)
{
  if (value == NULL || result == NULL || len == 0)
    return -1;

  uint64_t num = 0;
  for (size_t i = 0; i < len; i++)
    {
      unsigned char c = (unsigned char)value[i];

      /* Validate digit */
      if (c < '0' || c > '9')
        return -1;

      uint64_t digit = c - '0';

      /* Overflow check before multiplication */
      if (num > (UINT64_MAX - digit) / 10)
        return -1;

      num = num * 10 + digit;

      /* Range check */
      if (num > max_value)
        return -1;
    }

  *result = num;
  return 0;
}

int
http2_parse_status_code (const char *value, size_t len, int *status)
{
  /* RFC 9113 §8.3.2: :status must be a 3-digit code */
  if (status == NULL || len != 3)
    return -1;

  int code = 0;
  for (size_t i = 0; i < 3; i++)
    {
      unsigned char c = (unsigned char)value[i];
      if (c < '0' || c > '9')
        return -1;
      code = code * DECIMAL_BASE + (c - '0');
    }

  /* Valid HTTP status codes are 100-599 */
  if (code < 100)
    return -1;

  *status = (int)code;
  return 0;
}

int
http2_parse_content_length (const char *value, size_t len, int64_t *cl)
{
  /* Empty or NULL value is invalid */
  if (cl == NULL)
    return -1;

  uint64_t length;
  if (parse_decimal_uint64 (value, len, &length, INT64_MAX) < 0)
    return -1;

  *cl = (int64_t)length;
  return 0;
}

/*
 * Individual Pseudo-Header Validators (RFC 9113 Section 8.3)
 */

int
http2_validate_method_header (const SocketHPACK_Header *h, int is_request,
                               HTTP2_PseudoHeaderState *state)
{
  if (h == NULL || state == NULL)
    return -1;

  state->has_method = 1;

  /* Track CONNECT method for RFC 9113/8441 pseudo-header rules */
  if (h->value_len == 7 && memcmp (h->value, "CONNECT", 7) == 0)
    state->is_connect_method = 1;

  /* Method must be valid HTTP method for requests */
  if (!is_request)
    return 0;

  if (SocketHTTP_method_parse (h->value, h->value_len) == HTTP_METHOD_UNKNOWN)
    return -1;

  return 0;
}

int
http2_validate_scheme_header (const SocketHPACK_Header *h,
                               HTTP2_PseudoHeaderState *state)
{
  if (h == NULL || state == NULL)
    return -1;

  state->has_scheme = 1;
  return 0;
}

int
http2_validate_authority_header (const SocketHPACK_Header *h,
                                  HTTP2_PseudoHeaderState *state)
{
  if (h == NULL || state == NULL)
    return -1;

  state->has_authority = 1;
  return 0;
}

int
http2_validate_path_header (const SocketHPACK_Header *h,
                             HTTP2_PseudoHeaderState *state)
{
  if (h == NULL || state == NULL)
    return -1;

  state->has_path = 1;
  return 0;
}

int
http2_validate_status_header (const SocketHPACK_Header *h, int is_request,
                               HTTP2_PseudoHeaderState *state)
{
  if (h == NULL || state == NULL)
    return -1;

  state->has_status = 1;

  /* Only validate status code format for responses */
  if (is_request)
    return 0;

  int status;
  if (http2_parse_status_code (h->value, h->value_len, &status) < 0)
    return -1;

  return 0;
}

int
http2_validate_protocol_header (SocketHTTP2_Conn_T conn,
                                 SocketHTTP2_Stream_T stream,
                                 const SocketHPACK_Header *h,
                                 HTTP2_PseudoHeaderState *state)
{
  if (conn == NULL || stream == NULL || h == NULL || state == NULL)
    return -1;

  /* RFC 8441: :protocol only valid in requests (server receiving) */
  if (conn->role != HTTP2_ROLE_SERVER)
    return -1;

  /* Server must have advertised SETTINGS_ENABLE_CONNECT_PROTOCOL=1 */
  if (conn->local_settings[SETTINGS_IDX_ENABLE_CONNECT_PROTOCOL] == 0)
    return -1;

  state->has_protocol = 1;
  stream->is_extended_connect = 1;

  /* Empty protocol is valid */
  if (h->value_len == 0)
    return 0;

  /* Store protocol value if it fits */
  if (h->value_len >= sizeof (stream->protocol))
    return -1;

  memcpy (stream->protocol, h->value, h->value_len);
  stream->protocol[h->value_len] = '\0';
  return 0;
}

/*
 * CONNECT Variant Validators (RFC 9113 Section 8.5, RFC 8441)
 */

int
http2_validate_standard_connect (const HTTP2_PseudoHeaderState *state)
{
  if (state == NULL)
    return -1;

  /* CONNECT requires :authority */
  if (!state->has_authority)
    return -1;

  /* Standard CONNECT must not have :scheme or :path */
  if (state->has_scheme || state->has_path)
    return -1;

  return 0;
}

int
http2_validate_extended_connect (const HTTP2_PseudoHeaderState *state)
{
  if (state == NULL)
    return -1;

  /* RFC 8441: Extended CONNECT requires :scheme, :path, :authority */
  if (!state->has_scheme || !state->has_path || !state->has_authority)
    return -1;

  return 0;
}
