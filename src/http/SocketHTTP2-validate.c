/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/*
 * SocketHTTP2-validate.c - HTTP/2 Header Validation (RFC 9113)
 */

#include <string.h>
#include <strings.h>

#include "http/SocketHPACK.h"
#include "http/SocketHTTP2-private.h"

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

  /* Field names must be lowercase */
  if (http2_field_has_uppercase (header->name, header->name_len))
    return -1;

  /* No prohibited characters in field name */
  if (http2_field_has_prohibited_chars (header->name, header->name_len))
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
