/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTP3-validate.c
 * @brief HTTP/3 header validation (RFC 9114 §4.1.2, §4.3).
 *
 * Validates request and response headers for HTTP/3 compliance:
 * - Pseudo-header ordering and requirements
 * - Connection-specific header prohibition
 * - Field name case restrictions
 * - CONNECT method special rules
 */

#include "http/SocketHTTP3-request.h"
#include "http/SocketHTTP3-constants.h"

#include <stdlib.h>
#include <string.h>

typedef struct
{
  const char *name;
  size_t len;
} ForbiddenHeader;

static const ForbiddenHeader forbidden_headers[] = {
  { "connection", 10 }, { "keep-alive", 10 },        { "proxy-connection", 16 },
  { "te", 2 },          { "transfer-encoding", 17 }, { "upgrade", 7 },
};

#define FORBIDDEN_COUNT \
  (sizeof (forbidden_headers) / sizeof (forbidden_headers[0]))

static int
compare_forbidden (const void *key, const void *entry)
{
  const ForbiddenHeader *k = key;
  const ForbiddenHeader *e = entry;
  size_t minlen = k->len < e->len ? k->len : e->len;
  int cmp = memcmp (k->name, e->name, minlen);
  if (cmp != 0)
    return cmp;
  if (k->len < e->len)
    return -1;
  if (k->len > e->len)
    return 1;
  return 0;
}

static int
is_forbidden_header (const char *name, size_t name_len)
{
  ForbiddenHeader key = { name, name_len };
  return bsearch (&key,
                  forbidden_headers,
                  FORBIDDEN_COUNT,
                  sizeof (ForbiddenHeader),
                  compare_forbidden)
         != NULL;
}

static int
has_uppercase (const char *name, size_t name_len)
{
  for (size_t i = 0; i < name_len; i++)
    {
      if (name[i] >= 'A' && name[i] <= 'Z')
        return 1;
    }
  return 0;
}

static int
is_pseudo_header (const char *name, size_t name_len)
{
  return name_len > 0 && name[0] == ':';
}

int
SocketHTTP3_validate_request_headers (const SocketHTTP_Headers_T headers)
{
  if (headers == NULL)
    return -(int)H3_MESSAGE_ERROR;

  size_t count = SocketHTTP_Headers_count (headers);
  if (count == 0)
    return -(int)H3_MESSAGE_ERROR;

  int has_method = 0;
  int has_scheme = 0;
  int has_path = 0;
  int has_authority = 0;
  int pseudo_done = 0;
  int is_connect = 0;

  for (size_t i = 0; i < count; i++)
    {
      const SocketHTTP_Header *h = SocketHTTP_Headers_at (headers, i);
      if (h == NULL)
        return -(int)H3_MESSAGE_ERROR;

      /* Check for uppercase field names */
      if (has_uppercase (h->name, h->name_len))
        return -(int)H3_MESSAGE_ERROR;

      if (is_pseudo_header (h->name, h->name_len))
        {
          /* Pseudo-headers must come before regular headers */
          if (pseudo_done)
            return -(int)H3_MESSAGE_ERROR;

          if (h->name_len == 7 && memcmp (h->name, ":method", 7) == 0)
            {
              if (has_method)
                return -(int)H3_MESSAGE_ERROR; /* duplicate */
              has_method = 1;
              if (h->value_len == 7 && memcmp (h->value, "CONNECT", 7) == 0)
                is_connect = 1;
            }
          else if (h->name_len == 7 && memcmp (h->name, ":scheme", 7) == 0)
            {
              if (has_scheme)
                return -(int)H3_MESSAGE_ERROR;
              has_scheme = 1;
            }
          else if (h->name_len == 5 && memcmp (h->name, ":path", 5) == 0)
            {
              if (has_path)
                return -(int)H3_MESSAGE_ERROR;
              has_path = 1;
            }
          else if (h->name_len == 10 && memcmp (h->name, ":authority", 10) == 0)
            {
              if (has_authority)
                return -(int)H3_MESSAGE_ERROR;
              has_authority = 1;
            }
          else if (h->name_len == 7 && memcmp (h->name, ":status", 7) == 0)
            {
              /* :status is a response pseudo-header, not valid in requests */
              return -(int)H3_MESSAGE_ERROR;
            }
          else
            {
              /* Undefined pseudo-header */
              return -(int)H3_MESSAGE_ERROR;
            }
        }
      else
        {
          pseudo_done = 1;

          /* Check forbidden connection-specific headers */
          if (is_forbidden_header (h->name, h->name_len))
            {
              /* TE with value "trailers" is allowed */
              if (h->name_len == 2 && memcmp (h->name, "te", 2) == 0
                  && h->value_len == 8 && memcmp (h->value, "trailers", 8) == 0)
                continue;
              return -(int)H3_MESSAGE_ERROR;
            }
        }
    }

  /* CONNECT method: only :method and :authority required */
  if (is_connect)
    {
      if (!has_method || !has_authority)
        return -(int)H3_MESSAGE_ERROR;
      if (has_scheme || has_path)
        return -(int)H3_MESSAGE_ERROR;
      return 0;
    }

  /* Normal request: :method, :scheme, :path required */
  if (!has_method || !has_scheme || !has_path)
    return -(int)H3_MESSAGE_ERROR;

  return 0;
}

int
SocketHTTP3_validate_response_headers (const SocketHTTP_Headers_T headers)
{
  if (headers == NULL)
    return -(int)H3_MESSAGE_ERROR;

  size_t count = SocketHTTP_Headers_count (headers);
  if (count == 0)
    return -(int)H3_MESSAGE_ERROR;

  int has_status = 0;
  int pseudo_done = 0;
  int status_code = 0;

  for (size_t i = 0; i < count; i++)
    {
      const SocketHTTP_Header *h = SocketHTTP_Headers_at (headers, i);
      if (h == NULL)
        return -(int)H3_MESSAGE_ERROR;

      /* Check for uppercase field names */
      if (has_uppercase (h->name, h->name_len))
        return -(int)H3_MESSAGE_ERROR;

      if (is_pseudo_header (h->name, h->name_len))
        {
          if (pseudo_done)
            return -(int)H3_MESSAGE_ERROR;

          if (h->name_len == 7 && memcmp (h->name, ":status", 7) == 0)
            {
              if (has_status)
                return -(int)H3_MESSAGE_ERROR;
              has_status = 1;

              /* Parse status code */
              if (h->value_len != 3)
                return -(int)H3_MESSAGE_ERROR;
              for (size_t j = 0; j < 3; j++)
                {
                  if (h->value[j] < '0' || h->value[j] > '9')
                    return -(int)H3_MESSAGE_ERROR;
                  status_code = status_code * 10 + (h->value[j] - '0');
                }
            }
          else
            {
              /* Undefined or request-only pseudo-header in response */
              return -(int)H3_MESSAGE_ERROR;
            }
        }
      else
        {
          pseudo_done = 1;

          if (is_forbidden_header (h->name, h->name_len))
            {
              if (h->name_len == 2 && memcmp (h->name, "te", 2) == 0
                  && h->value_len == 8 && memcmp (h->value, "trailers", 8) == 0)
                continue;
              return -(int)H3_MESSAGE_ERROR;
            }
        }
    }

  if (!has_status)
    return -(int)H3_MESSAGE_ERROR;

  /* RFC 9114 §4.5: 101 Switching Protocols is forbidden in HTTP/3 */
  if (status_code == 101)
    return -(int)H3_MESSAGE_ERROR;

  return 0;
}
