/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketHTTP-uri.c - URI Parsing (RFC 3986)
 *
 * Single-pass state machine parser for absolute URIs, relative references, IPv6.
 */

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>

#include "core/SocketUtil.h"
#include "http/SocketHTTP-private.h"
#include "http/SocketHTTP.h"

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#endif
SOCKET_DECLARE_MODULE_EXCEPTION (SocketHTTP);
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

/* ============================================================================
 * Constants
 * ============================================================================
 */

#define URI_MAX_USERINFO_LEN 128
#define URI_MAX_HOST_LEN 255
#define URI_MAX_PATH_LEN 4096
#define URI_MAX_QUERY_LEN 8192
#define URI_MAX_FRAGMENT_LEN 8192
#define URI_MAX_PORT 65535
#define URI_PORT_BUFSIZE 8
#define URI_SCHEME_HTTPS_LEN 5
#define URI_SCHEME_WSS_LEN 3
#define URI_IPV6_MIN_LEN 4
#define URI_MAX_SCHEME_LEN 64
#define MEDIATYPE_CHARSET_LEN 7
#define MEDIATYPE_BOUNDARY_LEN 8

/* ============================================================================
 * Validation Forward Declarations
 * ============================================================================
 */

static SocketHTTP_URIResult validate_reg_name (const char *host, size_t len);
static SocketHTTP_URIResult validate_userinfo (const char *userinfo, size_t len);
static SocketHTTP_URIResult validate_host (const char *host, size_t len, int *out_is_ipv6);
static SocketHTTP_URIResult validate_path_query (const char *s, size_t len, int is_path);
static SocketHTTP_URIResult validate_fragment (const char *s, size_t len);

/* ============================================================================
 * Character Classification
 * ============================================================================
 */

static inline int
is_scheme_char (char c, int first)
{
  if (first)
    return isalpha ((unsigned char)c);
  return isalnum ((unsigned char)c) || c == '+' || c == '-' || c == '.';
}

static SocketHTTP_URIResult
validate_scheme (const char *s, size_t len)
{
  if (len == 0)
    return URI_PARSE_INVALID_SCHEME;

  if (!is_scheme_char (s[0], 1))
    return URI_PARSE_INVALID_SCHEME;

  for (size_t i = 1; i < len; i++)
    {
      if (!is_scheme_char (s[i], 0))
        return URI_PARSE_INVALID_SCHEME;
    }

  return URI_PARSE_OK;
}

static inline int
is_control_char (char c)
{
  unsigned char uc = (unsigned char)c;
  return uc < 0x20 || uc == 0x7F;
}

/* ============================================================================
 * Arena String Allocation
 * ============================================================================
 */

static void
scheme_to_lower (char *scheme, size_t len)
{
  for (size_t i = 0; i < len; i++)
    {
      if (scheme[i] >= 'A' && scheme[i] <= 'Z')
        scheme[i] = scheme[i] + ('a' - 'A');
    }
}

static SocketHTTP_URIResult
uri_alloc_component (Arena_T arena, const char *start, const char *end,
                     const char **out_str, size_t *out_len)
{
  if (!start || !end || end <= start)
    return URI_PARSE_OK;

  size_t len = (size_t)(end - start);
  char *copy = arena_strndup (arena, start, len);
  if (!copy)
    return URI_PARSE_ERROR;

  *out_str = copy;
  *out_len = len;
  return URI_PARSE_OK;
}

typedef SocketHTTP_URIResult (*ComponentValidator) (const char *s, size_t len);

static SocketHTTP_URIResult
alloc_and_validate (Arena_T arena, const char *start, const char *end,
                    size_t max_len, ComponentValidator validator,
                    void (*post_process) (char *str, size_t len),
                    const char **out_str, size_t *out_len, int alloc_empty)
{
  *out_str = NULL;
  *out_len = 0;

  if (!start || end <= start)
    {
      if (alloc_empty)
        {
          char *empty = arena_strndup (arena, "", 0);
          if (!empty)
            return URI_PARSE_ERROR;
          *out_str = empty;
          *out_len = 0;
        }
      return URI_PARSE_OK;
    }

  size_t len = (size_t)(end - start);
  if (len > max_len)
    return URI_PARSE_TOO_LONG;

  if (validator)
    {
      SocketHTTP_URIResult vr = validator (start, len);
      if (vr != URI_PARSE_OK)
        return vr;
    }

  char *copy = arena_strndup (arena, start, len);
  if (!copy)
    return URI_PARSE_ERROR;

  if (post_process)
    post_process (copy, len);

  *out_str = copy;
  *out_len = len;
  return URI_PARSE_OK;
}

/* ============================================================================
 * URI Parser State Machine
 * ============================================================================
 */

typedef struct
{
  const char *scheme_start;
  const char *scheme_end;
  const char *authority_start;
  const char *userinfo_start;
  const char *userinfo_end;
  const char *host_start;
  const char *host_end;
  const char *port_start;
  const char *port_end;
  const char *path_start;
  const char *path_end;
  const char *query_start;
  const char *query_end;
  const char *fragment_start;
  const char *fragment_end;
  URIParserState state;
  int in_ipv6;
} URIParseContext;

static void
uri_init_context (URIParseContext *ctx)
{
  memset (ctx, 0, sizeof (*ctx));
  ctx->state = URI_STATE_START;
}

static void
uri_handle_start (URIParseContext *ctx, char c, const char *p)
{
  if (c == '/')
    {
      ctx->path_start = p;
      ctx->state = URI_STATE_PATH;
    }
  else if (c == '?')
    {
      ctx->path_start = p;
      ctx->path_end = p;
      ctx->query_start = p + 1;
      ctx->state = URI_STATE_QUERY;
    }
  else if (c == '#')
    {
      ctx->path_start = p;
      ctx->path_end = p;
      ctx->fragment_start = p + 1;
      ctx->state = URI_STATE_FRAGMENT;
    }
  else if (is_scheme_char (c, 1))
    {
      ctx->scheme_start = p;
      ctx->state = URI_STATE_SCHEME;
    }
  else
    {
      ctx->path_start = p;
      ctx->state = URI_STATE_PATH;
    }
}

static int
uri_handle_scheme (URIParseContext *ctx, char c, const char *p)
{
  if (c == ':')
    {
      ctx->scheme_end = p;
      ctx->state = URI_STATE_SCHEME_COLON;
      return 0;
    }
  if (!is_scheme_char (c, 0))
    {
      ctx->path_start = ctx->scheme_start;
      ctx->scheme_start = NULL;
      ctx->state = URI_STATE_PATH;
      return 1;
    }
  return 0;
}

static void
uri_handle_scheme_colon (URIParseContext *ctx, char c, const char *p)
{
  if (c == '/')
    {
      ctx->state = URI_STATE_AUTHORITY_START;
    }
  else if (c == '?')
    {
      ctx->path_start = p;
      ctx->path_end = p;
      ctx->query_start = p + 1;
      ctx->state = URI_STATE_QUERY;
    }
  else if (c == '#')
    {
      ctx->path_start = p;
      ctx->path_end = p;
      ctx->fragment_start = p + 1;
      ctx->state = URI_STATE_FRAGMENT;
    }
  else
    {
      ctx->path_start = p;
      ctx->state = URI_STATE_PATH;
    }
}

static int
uri_handle_authority_start (URIParseContext *ctx, char c, const char *p)
{
  if (c == '/')
    {
      ctx->authority_start = p + 1;
      ctx->host_start = p + 1;
      ctx->state = URI_STATE_AUTHORITY;
      return 0;
    }
  ctx->path_start = p - 1;
  ctx->state = URI_STATE_PATH;
  return 1;
}

static void
uri_finalize_authority (URIParseContext *ctx, const char *p)
{
  if (ctx->port_start && !ctx->port_end)
    ctx->port_end = p;
  if (!ctx->host_end)
    ctx->host_end = p;
}

static void
uri_handle_authority (URIParseContext *ctx, char c, const char *p)
{
  if (c == '/')
    {
      uri_finalize_authority (ctx, p);
      ctx->path_start = p;
      ctx->state = URI_STATE_PATH;
    }
  else if (c == '?')
    {
      uri_finalize_authority (ctx, p);
      ctx->path_start = p;
      ctx->path_end = p;
      ctx->query_start = p + 1;
      ctx->state = URI_STATE_QUERY;
    }
  else if (c == '#')
    {
      uri_finalize_authority (ctx, p);
      ctx->path_start = p;
      ctx->path_end = p;
      ctx->fragment_start = p + 1;
      ctx->state = URI_STATE_FRAGMENT;
    }
  else if (c == '@')
    {
      ctx->userinfo_start = ctx->authority_start;
      ctx->userinfo_end = p;
      ctx->host_start = p + 1;
      ctx->host_end = NULL;
      ctx->port_start = NULL;
      ctx->port_end = NULL;
    }
  else if (c == '[')
    {
      ctx->in_ipv6 = 1;
      ctx->state = URI_STATE_HOST_IPV6;
    }
  else if (c == ':' && !ctx->in_ipv6)
    {
      if (!ctx->host_end)
        ctx->host_end = p;
      ctx->port_start = p + 1;
    }
}

static void
uri_handle_host_ipv6 (URIParseContext *ctx, char c)
{
  if (c == ']')
    {
      ctx->in_ipv6 = 0;
      ctx->state = URI_STATE_AUTHORITY;
    }
}

static void
uri_handle_path (URIParseContext *ctx, char c, const char *p)
{
  if (c == '?')
    {
      ctx->path_end = p;
      ctx->query_start = p + 1;
      ctx->state = URI_STATE_QUERY;
    }
  else if (c == '#')
    {
      ctx->path_end = p;
      ctx->fragment_start = p + 1;
      ctx->state = URI_STATE_FRAGMENT;
    }
}

static void
uri_handle_query (URIParseContext *ctx, char c, const char *p)
{
  if (c == '#')
    {
      ctx->query_end = p;
      ctx->fragment_start = p + 1;
      ctx->state = URI_STATE_FRAGMENT;
    }
}

static SocketHTTP_URIResult
uri_run_state_machine (const char *uri, size_t len, URIParseContext *ctx)
{
  const char *p = uri;
  const char *end = uri + len;

  uri_init_context (ctx);

  while (p < end)
    {
      char c = *p;

      if (is_control_char (c))
        return URI_PARSE_ERROR;

      switch (ctx->state)
        {
        case URI_STATE_START:
          uri_handle_start (ctx, c, p);
          break;

        case URI_STATE_SCHEME:
          if (uri_handle_scheme (ctx, c, p))
            continue;
          break;

        case URI_STATE_SCHEME_COLON:
          uri_handle_scheme_colon (ctx, c, p);
          break;

        case URI_STATE_AUTHORITY_START:
          if (uri_handle_authority_start (ctx, c, p))
            continue;
          break;

        case URI_STATE_AUTHORITY:
          uri_handle_authority (ctx, c, p);
          break;

        case URI_STATE_HOST:
        case URI_STATE_PORT:
          break;

        case URI_STATE_HOST_IPV6:
          uri_handle_host_ipv6 (ctx, c);
          break;

        case URI_STATE_PATH:
          uri_handle_path (ctx, c, p);
          break;

        case URI_STATE_QUERY:
          uri_handle_query (ctx, c, p);
          break;

        case URI_STATE_FRAGMENT:
          break;
        }

      p++;
    }

  return URI_PARSE_OK;
}

static SocketHTTP_URIResult
uri_finalize_state (URIParseContext *ctx, const char *end)
{
  switch (ctx->state)
    {
    case URI_STATE_SCHEME:
      ctx->path_start = ctx->scheme_start;
      ctx->path_end = end;
      ctx->scheme_start = NULL;
      ctx->scheme_end = NULL;
      break;

    case URI_STATE_AUTHORITY:
      if (ctx->port_start && !ctx->port_end)
        ctx->port_end = end;
      if (!ctx->host_end)
        ctx->host_end = ctx->port_start ? (ctx->port_start - 1) : end;
      ctx->path_start = end;
      ctx->path_end = end;
      break;

    case URI_STATE_PORT:
      ctx->port_end = end;
      ctx->path_start = end;
      ctx->path_end = end;
      break;

    case URI_STATE_PATH:
      ctx->path_end = end;
      break;

    case URI_STATE_QUERY:
      ctx->query_end = end;
      break;

    case URI_STATE_FRAGMENT:
      ctx->fragment_end = end;
      break;

    case URI_STATE_HOST_IPV6:
      return URI_PARSE_INVALID_HOST;

    default:
      break;
    }

  return URI_PARSE_OK;
}

static SocketHTTP_URIResult
uri_parse_port (const char *start, const char *end, int *port_out)
{
  if (!start || !end || end <= start)
    return URI_PARSE_OK;

  int port = 0;
  for (const char *pp = start; pp < end; pp++)
    {
      if (!isdigit ((unsigned char)*pp))
        return URI_PARSE_INVALID_PORT;

      int digit = *pp - '0';
      if (port > (URI_MAX_PORT - digit) / 10)
        return URI_PARSE_INVALID_PORT;

      port = port * 10 + digit;
    }

  *port_out = port;
  return URI_PARSE_OK;
}

static SocketHTTP_URIResult
uri_alloc_all_components (const URIParseContext *ctx, SocketHTTP_URI *result,
                          Arena_T arena, const char *end)
{
  SocketHTTP_URIResult r;

  /* Scheme */
  if (ctx->scheme_start && ctx->scheme_end && ctx->scheme_end > ctx->scheme_start)
    {
      size_t slen = (size_t)(ctx->scheme_end - ctx->scheme_start);
      char *s = arena_strndup (arena, ctx->scheme_start, slen);
      if (!s)
        return URI_PARSE_ERROR;
      scheme_to_lower (s, slen);
      result->scheme = s;
      result->scheme_len = slen;
    }

  /* Userinfo */
  if (ctx->userinfo_start && ctx->userinfo_end > ctx->userinfo_start)
    {
      size_t ulen = (size_t)(ctx->userinfo_end - ctx->userinfo_start);
      if (ulen > URI_MAX_USERINFO_LEN)
        return URI_PARSE_TOO_LONG;
    }
  r = uri_alloc_component (arena, ctx->userinfo_start, ctx->userinfo_end,
                           &result->userinfo, &result->userinfo_len);
  if (r != URI_PARSE_OK)
    return r;

  if (result->userinfo && result->userinfo_len > 0)
    {
      r = validate_userinfo (result->userinfo, result->userinfo_len);
      if (r != URI_PARSE_OK)
        return r;
    }

  /* Host */
  if (ctx->host_start && ctx->host_end > ctx->host_start)
    {
      size_t hlen = (size_t)(ctx->host_end - ctx->host_start);
      if (hlen > URI_MAX_HOST_LEN)
        return URI_PARSE_TOO_LONG;
    }
  r = uri_alloc_component (arena, ctx->host_start, ctx->host_end,
                           &result->host, &result->host_len);
  if (r != URI_PARSE_OK)
    return r;

  if (result->host && result->host_len > 0)
    {
      int is_ipv6_dummy;
      r = validate_host (result->host, result->host_len, &is_ipv6_dummy);
      if (r != URI_PARSE_OK)
        return r;
    }

  /* Port */
  r = uri_parse_port (ctx->port_start, ctx->port_end, &result->port);
  if (r != URI_PARSE_OK)
    return r;

  /* Path */
  if (ctx->path_start)
    {
      const char *path_end = ctx->path_end ? ctx->path_end : end;
      size_t path_len_calc = (size_t)(path_end - ctx->path_start);
      if (path_len_calc > URI_MAX_PATH_LEN)
        return URI_PARSE_TOO_LONG;
      r = uri_alloc_component (arena, ctx->path_start, path_end, &result->path,
                               &result->path_len);
      if (r != URI_PARSE_OK)
        return r;

      if (result->path && result->path_len > 0)
        {
          r = validate_path_query (result->path, result->path_len, 1);
          if (r != URI_PARSE_OK)
            return r;
        }
    }
  else
    {
      char *path = arena_strndup (arena, "", 0);
      if (!path)
        return URI_PARSE_ERROR;
      result->path = path;
      result->path_len = 0;
    }

  /* Query */
  if (ctx->query_start)
    {
      const char *query_end = ctx->query_end ? ctx->query_end : end;
      size_t query_len_calc = (size_t)(query_end - ctx->query_start);
      if (query_len_calc > URI_MAX_QUERY_LEN)
        return URI_PARSE_TOO_LONG;
      r = uri_alloc_component (arena, ctx->query_start, query_end,
                               &result->query, &result->query_len);
      if (r != URI_PARSE_OK)
        return r;

      if (result->query && result->query_len > 0)
        {
          r = validate_path_query (result->query, result->query_len, 0);
          if (r != URI_PARSE_OK)
            return r;
        }
    }

  /* Fragment */
  if (ctx->fragment_start)
    {
      const char *fragment_end = ctx->fragment_end ? ctx->fragment_end : end;
      size_t frag_len_calc = (size_t)(fragment_end - ctx->fragment_start);
      if (frag_len_calc > URI_MAX_FRAGMENT_LEN)
        return URI_PARSE_TOO_LONG;
      r = uri_alloc_component (arena, ctx->fragment_start, fragment_end,
                               &result->fragment, &result->fragment_len);
      if (r != URI_PARSE_OK)
        return r;

      if (result->fragment && result->fragment_len > 0)
        {
          r = validate_fragment (result->fragment, result->fragment_len);
          if (r != URI_PARSE_OK)
            return r;
        }
    }

  return URI_PARSE_OK;
}

/* ============================================================================
 * Public API
 * ============================================================================
 */

const char *
SocketHTTP_URI_result_string (SocketHTTP_URIResult result)
{
  switch (result)
    {
    case URI_PARSE_OK:
      return "OK";
    case URI_PARSE_ERROR:
      return "Parse error";
    case URI_PARSE_INVALID_SCHEME:
      return "Invalid scheme";
    case URI_PARSE_INVALID_HOST:
      return "Invalid host";
    case URI_PARSE_INVALID_PORT:
      return "Invalid port";
    case URI_PARSE_INVALID_PATH:
      return "Invalid path";
    case URI_PARSE_INVALID_QUERY:
      return "Invalid query";
    case URI_PARSE_TOO_LONG:
      return "URI too long";
    default:
      return "Unknown error";
    }
}

SocketHTTP_URIResult
SocketHTTP_URI_parse (const char *uri, size_t len, SocketHTTP_URI *result,
                      Arena_T arena)
{
  if (!uri || !result || !arena)
    return URI_PARSE_ERROR;

  if (len == 0)
    len = strlen (uri);

  if (len > SOCKETHTTP_MAX_URI_LEN)
    return URI_PARSE_TOO_LONG;

  memset (result, 0, sizeof (*result));
  result->port = -1;

  URIParseContext ctx;
  SocketHTTP_URIResult r;

  r = uri_run_state_machine (uri, len, &ctx);
  if (r != URI_PARSE_OK)
    return r;

  const char *end = uri + len;
  r = uri_finalize_state (&ctx, end);
  if (r != URI_PARSE_OK)
    return r;

  return uri_alloc_all_components (&ctx, result, arena, end);
}

int
SocketHTTP_URI_get_port (const SocketHTTP_URI *uri, int default_port)
{
  if (!uri)
    return default_port;
  return uri->port >= 0 ? uri->port : default_port;
}

int
SocketHTTP_URI_is_secure (const SocketHTTP_URI *uri)
{
  if (!uri || !uri->scheme)
    return 0;

  if (uri->scheme_len == URI_SCHEME_HTTPS_LEN
      && memcmp (uri->scheme, "https", URI_SCHEME_HTTPS_LEN) == 0)
    return 1;
  if (uri->scheme_len == URI_SCHEME_WSS_LEN
      && memcmp (uri->scheme, "wss", URI_SCHEME_WSS_LEN) == 0)
    return 1;

  return 0;
}

ssize_t
SocketHTTP_URI_encode (const char *input, size_t len, char *output,
                       size_t output_size)
{
  static const char hex[] = "0123456789ABCDEF";

  if (!input || !output)
    return -1;

  size_t out_len = 0;

  for (size_t i = 0; i < len; i++)
    {
      unsigned char c = (unsigned char)input[i];

      if (SOCKETHTTP_IS_UNRESERVED (c))
        {
          if (out_len + 1 >= output_size)
            return -1;
          output[out_len++] = (char)c;
        }
      else
        {
          if (out_len + 3 >= output_size)
            return -1;
          output[out_len++] = '%';
          output[out_len++] = hex[c >> 4];
          output[out_len++] = hex[c & 0x0F];
        }
    }

  if (out_len >= output_size)
    return -1;
  output[out_len] = '\0';

  return (ssize_t)out_len;
}

ssize_t
SocketHTTP_URI_decode (const char *input, size_t len, char *output,
                       size_t output_size)
{
  if (!input || !output)
    return -1;

  size_t out_len = 0;

  for (size_t i = 0; i < len; i++)
    {
      if (input[i] == '%')
        {
          if (i + 2 >= len)
            return -1;

          unsigned char hi = SOCKETHTTP_HEX_VALUE (input[i + 1]);
          unsigned char lo = SOCKETHTTP_HEX_VALUE (input[i + 2]);

          if (hi == 255 || lo == 255)
            return -1;

          if (out_len + 1 > output_size)
            return -1;

          output[out_len++] = (char)((hi << 4) | lo);
          i += 2;
        }
      else if (input[i] == '+')
        {
          if (out_len + 1 > output_size)
            return -1;

          output[out_len++] = ' ';
        }
      else
        {
          if (out_len + 1 > output_size)
            return -1;

          output[out_len++] = input[i];
        }
    }

  if (out_len >= output_size)
    return -1;
  output[out_len] = '\0';

  return (ssize_t)out_len;
}

#define URI_APPEND_STR(out, pos, size, s, l)                                  \
  do                                                                          \
    {                                                                         \
      if ((pos) + (l) >= (size))                                              \
        return -1;                                                            \
      memcpy ((out) + (pos), (s), (l));                                       \
      (pos) += (l);                                                           \
    }                                                                         \
  while (0)

#define URI_APPEND_CHAR(out, pos, size, c)                                    \
  do                                                                          \
    {                                                                         \
      if ((pos) + 1 >= (size))                                                \
        return -1;                                                            \
      (out)[(pos)++] = (c);                                                   \
    }                                                                         \
  while (0)

ssize_t
SocketHTTP_URI_build (const SocketHTTP_URI *uri, char *output, size_t output_size)
{
  if (!uri || !output || output_size == 0)
    return -1;

  size_t pos = 0;

  if (uri->scheme && uri->scheme_len > 0)
    {
      URI_APPEND_STR (output, pos, output_size, uri->scheme, uri->scheme_len);
      URI_APPEND_CHAR (output, pos, output_size, ':');

      if (uri->host && uri->host_len > 0)
        {
          URI_APPEND_CHAR (output, pos, output_size, '/');
          URI_APPEND_CHAR (output, pos, output_size, '/');
        }
    }

  if (uri->host && uri->host_len > 0)
    {
      if (uri->userinfo && uri->userinfo_len > 0)
        {
          URI_APPEND_STR (output, pos, output_size, uri->userinfo, uri->userinfo_len);
          URI_APPEND_CHAR (output, pos, output_size, '@');
        }

      URI_APPEND_STR (output, pos, output_size, uri->host, uri->host_len);

      if (uri->port >= 0)
        {
          char port_buf[URI_PORT_BUFSIZE];
          int port_len = snprintf (port_buf, sizeof (port_buf), ":%d", uri->port);
          if (port_len > 0 && (size_t)port_len < sizeof (port_buf))
            URI_APPEND_STR (output, pos, output_size, port_buf, (size_t)port_len);
        }
    }

  if (uri->path && uri->path_len > 0)
    URI_APPEND_STR (output, pos, output_size, uri->path, uri->path_len);

  if (uri->query && uri->query_len > 0)
    {
      URI_APPEND_CHAR (output, pos, output_size, '?');
      URI_APPEND_STR (output, pos, output_size, uri->query, uri->query_len);
    }

  if (uri->fragment && uri->fragment_len > 0)
    {
      URI_APPEND_CHAR (output, pos, output_size, '#');
      URI_APPEND_STR (output, pos, output_size, uri->fragment, uri->fragment_len);
    }

  output[pos] = '\0';
  return (ssize_t)pos;
}

#undef URI_APPEND_STR
#undef URI_APPEND_CHAR

/* ============================================================================
 * Validation Helpers
 * ============================================================================
 */

static inline int
is_unreserved (unsigned char c)
{
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
         || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~';
}

static inline int
is_sub_delims (unsigned char c)
{
  return strchr ("!$&'()*+,;=", c) != NULL;
}

static inline int
is_pchar_raw (unsigned char c)
{
  return SOCKETHTTP_IS_UNRESERVED (c) || is_sub_delims (c) || c == ':' || c == '@';
}

static SocketHTTP_URIResult
validate_string_chars (const char *start, size_t len,
                       int (*validator) (unsigned char),
                       SocketHTTP_URIResult error_type)
{
  for (size_t i = 0; i < len; i++)
    {
      if (!validator ((unsigned char)start[i]))
        return error_type;
    }
  return URI_PARSE_OK;
}

static SocketHTTP_URIResult
validate_pct_encoded (const char *s, size_t len)
{
  size_t i = 0;
  while (i < len)
    {
      if (s[i] == '%')
        {
          if (i + 2 >= len)
            return URI_PARSE_ERROR;
          unsigned char hi = SOCKETHTTP_HEX_VALUE (s[i + 1]);
          unsigned char lo = SOCKETHTTP_HEX_VALUE (s[i + 2]);
          if (hi == 255 || lo == 255)
            return URI_PARSE_ERROR;
          i += 3;
        }
      else
        {
          i++;
        }
    }
  return URI_PARSE_OK;
}

static inline int
is_reg_name_raw (unsigned char c)
{
  return SOCKETHTTP_IS_UNRESERVED (c) || is_sub_delims (c) || c == '%';
}

static inline int
is_userinfo_raw (unsigned char c)
{
  return is_unreserved (c) || is_sub_delims (c) || c == ':' || c == '%';
}

static SocketHTTP_URIResult
validate_reg_name (const char *host, size_t len)
{
  SocketHTTP_URIResult r = validate_string_chars (host, len, is_reg_name_raw,
                                                  URI_PARSE_INVALID_HOST);
  if (r != URI_PARSE_OK)
    return r;
  return validate_pct_encoded (host, len);
}

static SocketHTTP_URIResult
validate_userinfo (const char *userinfo, size_t len)
{
  SocketHTTP_URIResult r = validate_string_chars (userinfo, len, is_userinfo_raw,
                                                  URI_PARSE_ERROR);
  if (r != URI_PARSE_OK)
    return r;
  return validate_pct_encoded (userinfo, len);
}

static inline int
is_ipv6_char (unsigned char c)
{
  return isxdigit (c) || c == ':' || c == '.';
}

static SocketHTTP_URIResult
validate_ipv6_literal (const char *host, size_t len)
{
  if (len < URI_IPV6_MIN_LEN || host[0] != '[' || host[len - 1] != ']')
    return URI_PARSE_INVALID_HOST;

  size_t inner_len = len - 2;
  if (inner_len == 0)
    return URI_PARSE_INVALID_HOST;

  SocketHTTP_URIResult r = validate_string_chars (host + 1, inner_len,
                                                  is_ipv6_char,
                                                  URI_PARSE_INVALID_HOST);
  if (r != URI_PARSE_OK)
    return r;

  if (strchr (host + 1, ']') != host + len - 1)
    return URI_PARSE_INVALID_HOST;

  return URI_PARSE_OK;
}

static SocketHTTP_URIResult
validate_host (const char *host, size_t len, int *out_is_ipv6)
{
  if (!host || len == 0)
    return URI_PARSE_OK;

  *out_is_ipv6 = 0;

  if (host[0] == '[' && host[len - 1] == ']')
    {
      *out_is_ipv6 = 1;
      return validate_ipv6_literal (host, len);
    }

  return validate_reg_name (host, len);
}

/* SECURITY: Detect path traversal attacks */
static SocketHTTP_URIResult
check_path_traversal (const char *path, size_t len)
{
  for (size_t i = 0; i + 1 < len; i++)
    {
      if (path[i] == '.' && path[i + 1] == '.')
        {
          if (i == 0 || path[i - 1] == '/')
            {
              if (i + 2 >= len || path[i + 2] == '/' || path[i + 2] == '?')
                return URI_PARSE_INVALID_PATH;
            }
        }
    }

  for (size_t i = 0; i + 5 < len; i++)
    {
      if (path[i] == '%' && (path[i + 1] == '2')
          && (path[i + 2] == 'e' || path[i + 2] == 'E') && path[i + 3] == '%'
          && (path[i + 4] == '2')
          && (path[i + 5] == 'e' || path[i + 5] == 'E'))
        {
          return URI_PARSE_INVALID_PATH;
        }
    }

  return URI_PARSE_OK;
}

static SocketHTTP_URIResult
validate_path_query (const char *s, size_t len, int is_path)
{
  SocketHTTP_URIResult err = is_path ? URI_PARSE_INVALID_PATH : URI_PARSE_INVALID_QUERY;
  size_t i = 0;
  while (i < len)
    {
      char c = s[i];
      if (c == '%')
        {
          SocketHTTP_URIResult r = validate_pct_encoded (s + i, len - i);
          if (r != URI_PARSE_OK)
            return err;
          i += 3;
          while (i + 2 < len && s[i] == '%')
            i += 3;
          continue;
        }
      if (c == '/' || c == '?')
        {
          i++;
          continue;
        }
      if (!is_pchar_raw ((unsigned char)c))
        return err;
      i++;
    }

  if (is_path)
    {
      SocketHTTP_URIResult traversal = check_path_traversal (s, len);
      if (traversal != URI_PARSE_OK)
        return traversal;
    }

  return URI_PARSE_OK;
}

static SocketHTTP_URIResult
validate_fragment (const char *s, size_t len)
{
  return validate_path_query (s, len, 0);
}

/* ============================================================================
 * Media Type Parsing
 * ============================================================================
 */

static const char *
find_token_end (const char *p, const char *end, const char *delims)
{
  while (p < end)
    {
      if (strchr (delims, *p))
        break;
      p++;
    }
  return p;
}

static const char *
parse_quoted_value (const char *p, const char *end, const char **value_start,
                    size_t *value_len)
{
  *value_start = p;
  while (p < end && *p != '"')
    {
      if (*p == '\\')
        {
          if (p + 1 >= end)
            {
              *value_start = NULL;
              *value_len = 0;
              return end;
            }
          p++;
          unsigned char esc = (unsigned char)*p;
          if (esc < 0x20 || esc == 0x7F)
            {
              *value_start = NULL;
              *value_len = 0;
              return end;
            }
        }
      p++;
    }
  *value_len = (size_t)(p - *value_start);
  if (p < end)
    p++;
  return p;
}

static const char *
mediatype_parse_type_subtype (const char *p, const char *end,
                              SocketHTTP_MediaType *result, Arena_T arena)
{
  p = skip_ows (p, end);

  const char *type_start = p;
  p = find_token_end (p, end, "/; \t");

  if (p == type_start || p >= end || *p != '/')
    return NULL;

  size_t type_len = (size_t)(p - type_start);
  if (!sockethttp_is_token_valid (type_start, type_len))
    return NULL;

  char *type = arena_strndup (arena, type_start, type_len);
  if (!type)
    return NULL;
  result->type = type;
  result->type_len = type_len;

  p++;

  const char *subtype_start = p;
  p = find_token_end (p, end, "; \t");

  if (p == subtype_start)
    return NULL;

  size_t subtype_len = (size_t)(p - subtype_start);
  if (!sockethttp_is_token_valid (subtype_start, subtype_len))
    return NULL;

  char *subtype = arena_strndup (arena, subtype_start, subtype_len);
  if (!subtype)
    return NULL;
  result->subtype = subtype;
  result->subtype_len = subtype_len;

  return p;
}

static const char *
mediatype_parse_parameter (const char *p, const char *end,
                           SocketHTTP_MediaType *result, Arena_T arena)
{
  while (p < end && (*p == ' ' || *p == '\t' || *p == ';'))
    p++;

  if (p >= end)
    return p;

  const char *param_start = p;
  p = find_token_end (p, end, "=; \t");

  if (p >= end || *p != '=')
    return NULL;

  size_t param_len = (size_t)(p - param_start);
  if (param_len == 0)
    return NULL;
  if (!sockethttp_is_token_valid (param_start, param_len))
    return NULL;

  p++;

  const char *value_start;
  size_t value_len;

  if (p < end && *p == '"')
    {
      p++;
      p = parse_quoted_value (p, end, &value_start, &value_len);
      if (value_start == NULL)
        return NULL;
    }
  else
    {
      value_start = p;
      p = find_token_end (p, end, "; \t");
      value_len = (size_t)(p - value_start);

      if (value_len == 0)
        return NULL;
      if (!sockethttp_is_token_valid (value_start, value_len))
        return NULL;
    }

  if (param_len == MEDIATYPE_CHARSET_LEN
      && strncasecmp (param_start, "charset", MEDIATYPE_CHARSET_LEN) == 0)
    {
      char *cs = arena_strndup (arena, value_start, value_len);
      if (cs)
        {
          result->charset = cs;
          result->charset_len = value_len;
        }
    }
  else if (param_len == MEDIATYPE_BOUNDARY_LEN
           && strncasecmp (param_start, "boundary", MEDIATYPE_BOUNDARY_LEN) == 0)
    {
      char *bd = arena_strndup (arena, value_start, value_len);
      if (bd)
        {
          result->boundary = bd;
          result->boundary_len = value_len;
        }
    }

  return p;
}

int
SocketHTTP_MediaType_parse (const char *value, size_t len,
                            SocketHTTP_MediaType *result, Arena_T arena)
{
  if (!value || !result || !arena)
    return -1;

  if (len == 0)
    len = strlen (value);

  memset (result, 0, sizeof (*result));

  const char *end = value + len;
  const char *p;

  p = mediatype_parse_type_subtype (value, end, result, arena);
  if (!p)
    return -1;

  while (p < end)
    {
      p = mediatype_parse_parameter (p, end, result, arena);
      if (p == NULL)
        return -1;
    }

  return 0;
}

int
SocketHTTP_MediaType_matches (const SocketHTTP_MediaType *type, const char *pattern)
{
  if (!type || !pattern)
    return 0;

  const char *slash = strchr (pattern, '/');
  if (!slash)
    return 0;

  size_t pat_type_len = (size_t)(slash - pattern);
  const char *pat_subtype = slash + 1;
  size_t pat_subtype_len = strlen (pat_subtype);

  if (pat_type_len != 1 || pattern[0] != '*')
    {
      if (type->type_len != pat_type_len
          || strncasecmp (type->type, pattern, pat_type_len) != 0)
        return 0;
    }

  if (pat_subtype_len != 1 || pat_subtype[0] != '*')
    {
      if (type->subtype_len != pat_subtype_len
          || strncasecmp (type->subtype, pat_subtype, pat_subtype_len) != 0)
        return 0;
    }

  return 1;
}

/* ============================================================================
 * Accept Header Parsing
 * ============================================================================
 */

static int
qvalue_compare (const void *a, const void *b)
{
  const SocketHTTP_QualityValue *qa = a;
  const SocketHTTP_QualityValue *qb = b;

  if (qa->quality > qb->quality)
    return -1;
  if (qa->quality < qb->quality)
    return 1;
  return 0;
}

static float
accept_parse_quality (const char *p, const char *end, const char **out_pos)
{
  float quality = 0.0f;
  const char *start = p;

  while (p < end && *p >= '0' && *p <= '9')
    {
      quality = quality * 10.0f + (*p - '0');
      p++;
    }

  if (p < end && *p == '.')
    {
      p++;
      float divisor = 10.0f;
      while (p < end && *p >= '0' && *p <= '9')
        {
          quality += (*p - '0') / divisor;
          divisor *= 10.0f;
          p++;
        }
    }

  *out_pos = (p > start) ? p : start;

  if (quality < 0.0f)
    quality = 0.0f;
  if (quality > 1.0f)
    quality = 1.0f;

  return quality;
}

static const char *
accept_parse_single (const char *p, const char *end,
                     SocketHTTP_QualityValue *result, Arena_T arena)
{
  while (p < end && (*p == ' ' || *p == '\t' || *p == ','))
    p++;

  if (p >= end)
    return p;

  const char *value_start = p;
  while (p < end && *p != ';' && *p != ',')
    p++;

  const char *value_end = p;
  while (value_end > value_start && (value_end[-1] == ' ' || value_end[-1] == '\t'))
    value_end--;

  if (value_end == value_start)
    return p;

  float quality = 1.0f;

  if (p < end && *p == ';')
    {
      p++;
      while (p < end && (*p == ' ' || *p == '\t'))
        p++;

      if (p + 2 < end && (p[0] == 'q' || p[0] == 'Q') && p[1] == '=')
        {
          p += 2;
          quality = accept_parse_quality (p, end, &p);
        }

      while (p < end && *p != ',')
        p++;
    }

  size_t vlen = (size_t)(value_end - value_start);
  char *v = arena_strndup (arena, value_start, vlen);
  if (!v)
    return p;

  result->value = v;
  result->value_len = vlen;
  result->quality = quality;

  return p;
}

size_t
SocketHTTP_parse_accept (const char *value, size_t len,
                         SocketHTTP_QualityValue *results, size_t max_results,
                         Arena_T arena)
{
  if (!value || !results || max_results == 0 || !arena)
    return 0;

  if (len == 0)
    len = strlen (value);

  size_t count = 0;
  const char *p = value;
  const char *end = value + len;

  while (p < end && count < max_results)
    {
      const char *prev = p;
      p = accept_parse_single (p, end, &results[count], arena);

      if (results[count].value)
        count++;

      if (p == prev)
        break;
    }

  if (count > 1)
    qsort (results, count, sizeof (results[0]), qvalue_compare);

  return count;
}
