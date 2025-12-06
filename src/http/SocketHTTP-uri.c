/**
 * SocketHTTP-uri.c - URI Parsing (RFC 3986)
 *
 * Part of the Socket Library
 *
 * Implements URI parsing using a single-pass state machine parser.
 * Handles absolute URIs, relative references, and IPv6 addresses.
 */

#include "http/SocketHTTP.h"
#include "http/SocketHTTP-private.h"
#include "core/SocketUtil.h"

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Module-Specific Error Handling
 * ============================================================================ */

SOCKET_DECLARE_MODULE_EXCEPTION (SocketHTTP);

/* ============================================================================
 * Constants for Media Type Parsing
 * ============================================================================ */

/** Length of "charset" parameter name */
#define MEDIATYPE_CHARSET_LEN 7

/** Length of "boundary" parameter name */
#define MEDIATYPE_BOUNDARY_LEN 8

/* ============================================================================
 * Internal Helper Functions - Character Classification
 * ============================================================================ */

/**
 * is_scheme_char - Check if character is valid scheme character
 * @c: Character to check
 * @first: Non-zero if this is the first character
 *
 * scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
 *
 * Returns: Non-zero if valid, zero otherwise
 */
static inline int
is_scheme_char (char c, int first)
{
  if (first)
    return isalpha ((unsigned char)c);
  return isalnum ((unsigned char)c) || c == '+' || c == '-' || c == '.';
}

/**
 * is_control_char - Check if character is a control character
 * @c: Character to check
 *
 * Rejects 0x00-0x1F and DEL (0x7F) for defense in depth.
 *
 * Returns: Non-zero if control character, zero otherwise
 */
static inline int
is_control_char (char c)
{
  unsigned char uc = (unsigned char)c;
  return uc < 0x20 || uc == 0x7F;
}

/* ============================================================================
 * Internal Helper Functions - String Allocation
 * ============================================================================ */

/**
 * arena_strdup_n - Allocate and copy string into arena
 * @arena: Memory arena
 * @str: Source string
 * @len: String length
 *
 * Returns: Null-terminated copy, or NULL on allocation failure
 */
static char *
arena_strdup_n (Arena_T arena, const char *str, size_t len)
{
  char *copy = ALLOC (arena, len + 1);
  if (!copy)
    return NULL;
  memcpy (copy, str, len);
  copy[len] = '\0';
  return copy;
}

/**
 * scheme_to_lower - Convert scheme to lowercase in place
 * @scheme: Scheme string
 * @len: String length
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

/**
 * uri_alloc_component - Allocate and assign a URI component
 * @arena: Memory arena
 * @start: Component start pointer
 * @end: Component end pointer
 * @out_str: Output string pointer
 * @out_len: Output length pointer
 *
 * Returns: URI_PARSE_OK on success, URI_PARSE_ERROR on allocation failure
 */
static SocketHTTP_URIResult
uri_alloc_component (Arena_T arena, const char *start, const char *end,
                     const char **out_str, size_t *out_len)
{
  if (!start || !end || end <= start)
    return URI_PARSE_OK;

  size_t len = (size_t)(end - start);
  char *copy = arena_strdup_n (arena, start, len);
  if (!copy)
    return URI_PARSE_ERROR;

  *out_str = copy;
  *out_len = len;
  return URI_PARSE_OK;
}

/* ============================================================================
 * URI Parsing - State Machine Helpers
 * ============================================================================ */

/**
 * URIParseContext - Context for URI parsing state machine
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

/**
 * uri_init_context - Initialize URI parsing context
 * @ctx: Context to initialize
 */
static void
uri_init_context (URIParseContext *ctx)
{
  memset (ctx, 0, sizeof (*ctx));
  ctx->state = URI_STATE_START;
}

/**
 * uri_handle_start - Handle URI_STATE_START
 * @ctx: Parse context
 * @c: Current character
 * @p: Current position
 */
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

/**
 * uri_handle_scheme - Handle URI_STATE_SCHEME
 * @ctx: Parse context
 * @c: Current character
 * @p: Current position
 *
 * Returns: 0 to continue to next char, 1 to re-process current char
 */
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

/**
 * uri_handle_scheme_colon - Handle URI_STATE_SCHEME_COLON
 * @ctx: Parse context
 * @c: Current character
 * @p: Current position
 */
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

/**
 * uri_handle_authority_start - Handle URI_STATE_AUTHORITY_START
 * @ctx: Parse context
 * @c: Current character
 * @p: Current position
 *
 * Returns: 0 to continue to next char, 1 to re-process current char
 */
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

/**
 * uri_finalize_authority - Finalize port_end and host_end for authority
 * @ctx: Parse context
 * @p: Current position
 */
static void
uri_finalize_authority (URIParseContext *ctx, const char *p)
{
  if (ctx->port_start && !ctx->port_end)
    ctx->port_end = p;
  if (!ctx->host_end)
    ctx->host_end = p;
}

/**
 * uri_handle_authority - Handle URI_STATE_AUTHORITY
 * @ctx: Parse context
 * @c: Current character
 * @p: Current position
 */
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

/**
 * uri_handle_host_ipv6 - Handle URI_STATE_HOST_IPV6
 * @ctx: Parse context
 * @c: Current character
 */
static void
uri_handle_host_ipv6 (URIParseContext *ctx, char c)
{
  if (c == ']')
    {
      ctx->in_ipv6 = 0;
      ctx->state = URI_STATE_AUTHORITY;
    }
}

/**
 * uri_handle_path - Handle URI_STATE_PATH
 * @ctx: Parse context
 * @c: Current character
 * @p: Current position
 */
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

/**
 * uri_handle_query - Handle URI_STATE_QUERY
 * @ctx: Parse context
 * @c: Current character
 * @p: Current position
 */
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

/**
 * uri_run_state_machine - Execute URI parsing state machine
 * @uri: Input URI string
 * @len: URI length
 * @ctx: Parse context (output)
 *
 * Returns: URI_PARSE_OK on success, error code otherwise
 */
static SocketHTTP_URIResult
uri_run_state_machine (const char *uri, size_t len, URIParseContext *ctx)
{
  const char *p = uri;
  const char *end = uri + len;

  uri_init_context (ctx);

  while (p < end)
    {
      char c = *p;

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
          if (is_control_char (c))
            return URI_PARSE_ERROR;
          break;
        }

      p++;
    }

  return URI_PARSE_OK;
}

/**
 * uri_finalize_state - Finalize parsing state after reaching end
 * @ctx: Parse context
 * @end: End of input
 *
 * Returns: URI_PARSE_OK on success, error code otherwise
 */
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

/**
 * uri_parse_port - Parse port number from string
 * @start: Start of port string
 * @end: End of port string
 * @port_out: Output port number
 *
 * Returns: URI_PARSE_OK on success, URI_PARSE_INVALID_PORT on error
 */
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
      port = port * 10 + (*pp - '0');
      if (port > 65535)
        return URI_PARSE_INVALID_PORT;
    }

  *port_out = port;
  return URI_PARSE_OK;
}

/**
 * uri_alloc_all_components - Allocate all URI components from context
 * @ctx: Parse context
 * @result: Output URI structure
 * @arena: Memory arena
 * @end: End of input
 *
 * Returns: URI_PARSE_OK on success, error code otherwise
 */
static SocketHTTP_URIResult
uri_alloc_all_components (const URIParseContext *ctx, SocketHTTP_URI *result,
                          Arena_T arena, const char *end)
{
  SocketHTTP_URIResult r;

  /* Scheme (with lowercase conversion) */
  if (ctx->scheme_start && ctx->scheme_end && ctx->scheme_end > ctx->scheme_start)
    {
      size_t slen = (size_t)(ctx->scheme_end - ctx->scheme_start);
      char *s = arena_strdup_n (arena, ctx->scheme_start, slen);
      if (!s)
        return URI_PARSE_ERROR;
      scheme_to_lower (s, slen);
      result->scheme = s;
      result->scheme_len = slen;
    }

  /* Userinfo */
  r = uri_alloc_component (arena, ctx->userinfo_start, ctx->userinfo_end,
                           &result->userinfo, &result->userinfo_len);
  if (r != URI_PARSE_OK)
    return r;

  /* Host */
  r = uri_alloc_component (arena, ctx->host_start, ctx->host_end,
                           &result->host, &result->host_len);
  if (r != URI_PARSE_OK)
    return r;

  /* Port */
  r = uri_parse_port (ctx->port_start, ctx->port_end, &result->port);
  if (r != URI_PARSE_OK)
    return r;

  /* Path (always present, may be empty) */
  if (ctx->path_start)
    {
      const char *path_end = ctx->path_end ? ctx->path_end : end;
      r = uri_alloc_component (arena, ctx->path_start, path_end,
                               &result->path, &result->path_len);
      if (r != URI_PARSE_OK)
        return r;
    }
  else
    {
      char *path = arena_strdup_n (arena, "", 0);
      if (!path)
        return URI_PARSE_ERROR;
      result->path = path;
      result->path_len = 0;
    }

  /* Query */
  if (ctx->query_start)
    {
      const char *query_end = ctx->query_end ? ctx->query_end : end;
      r = uri_alloc_component (arena, ctx->query_start, query_end,
                               &result->query, &result->query_len);
      if (r != URI_PARSE_OK)
        return r;
    }

  /* Fragment */
  if (ctx->fragment_start)
    {
      const char *fragment_end = ctx->fragment_end ? ctx->fragment_end : end;
      r = uri_alloc_component (arena, ctx->fragment_start, fragment_end,
                               &result->fragment, &result->fragment_len);
      if (r != URI_PARSE_OK)
        return r;
    }

  return URI_PARSE_OK;
}

/* ============================================================================
 * URI Parsing - Public API
 * ============================================================================ */

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

  if (uri->scheme_len == 5 && memcmp (uri->scheme, "https", 5) == 0)
    return 1;
  if (uri->scheme_len == 3 && memcmp (uri->scheme, "wss", 3) == 0)
    return 1;

  return 0;
}

/* ============================================================================
 * Percent Encoding/Decoding
 * ============================================================================ */

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
      if (out_len >= output_size)
        return -1;

      if (input[i] == '%')
        {
          if (i + 2 >= len)
            return -1;

          unsigned char hi = SOCKETHTTP_HEX_VALUE (input[i + 1]);
          unsigned char lo = SOCKETHTTP_HEX_VALUE (input[i + 2]);

          if (hi == 255 || lo == 255)
            return -1;

          output[out_len++] = (char)((hi << 4) | lo);
          i += 2;
        }
      else if (input[i] == '+')
        {
          output[out_len++] = ' ';
        }
      else
        {
          output[out_len++] = input[i];
        }
    }

  if (out_len >= output_size)
    return -1;
  output[out_len] = '\0';

  return (ssize_t)out_len;
}

/* ============================================================================
 * URI Build - Helper Macros
 * ============================================================================ */

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
SocketHTTP_URI_build (const SocketHTTP_URI *uri, char *output,
                      size_t output_size)
{
  if (!uri || !output || output_size == 0)
    return -1;

  size_t pos = 0;

  /* Scheme */
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

  /* Authority */
  if (uri->host && uri->host_len > 0)
    {
      if (uri->userinfo && uri->userinfo_len > 0)
        {
          URI_APPEND_STR (output, pos, output_size, uri->userinfo,
                          uri->userinfo_len);
          URI_APPEND_CHAR (output, pos, output_size, '@');
        }

      URI_APPEND_STR (output, pos, output_size, uri->host, uri->host_len);

      if (uri->port >= 0)
        {
          char port_buf[8];
          int port_len
              = snprintf (port_buf, sizeof (port_buf), ":%d", uri->port);
          if (port_len > 0 && (size_t)port_len < sizeof (port_buf))
            URI_APPEND_STR (output, pos, output_size, port_buf,
                            (size_t)port_len);
        }
    }

  /* Path */
  if (uri->path && uri->path_len > 0)
    URI_APPEND_STR (output, pos, output_size, uri->path, uri->path_len);

  /* Query */
  if (uri->query && uri->query_len > 0)
    {
      URI_APPEND_CHAR (output, pos, output_size, '?');
      URI_APPEND_STR (output, pos, output_size, uri->query, uri->query_len);
    }

  /* Fragment */
  if (uri->fragment && uri->fragment_len > 0)
    {
      URI_APPEND_CHAR (output, pos, output_size, '#');
      URI_APPEND_STR (output, pos, output_size, uri->fragment,
                      uri->fragment_len);
    }

  output[pos] = '\0';
  return (ssize_t)pos;
}

#undef URI_APPEND_STR
#undef URI_APPEND_CHAR

/* ============================================================================
 * Media Type Parsing - Helper Functions
 * ============================================================================ */

/**
 * skip_whitespace - Skip leading whitespace
 * @p: Current position
 * @end: End of input
 *
 * Returns: Position after whitespace
 */
static const char *
skip_whitespace (const char *p, const char *end)
{
  while (p < end && (*p == ' ' || *p == '\t'))
    p++;
  return p;
}

/**
 * find_token_end - Find end of token (stopped by delimiter chars)
 * @p: Current position
 * @end: End of input
 * @delims: Delimiter characters string
 *
 * Returns: Position at end of token
 */
static const char *
find_token_end (const char *p, const char *end, const char *delims)
{
  while (p < end)
    {
      char c = *p;
      if (strchr (delims, c))
        break;
      p++;
    }
  return p;
}

/**
 * parse_quoted_value - Parse a quoted parameter value
 * @p: Position after opening quote
 * @end: End of input
 * @value_start: Output value start
 * @value_len: Output value length
 *
 * Returns: Position after closing quote (or end if no closing quote)
 */
static const char *
parse_quoted_value (const char *p, const char *end, const char **value_start,
                    size_t *value_len)
{
  *value_start = p;
  while (p < end && *p != '"')
    {
      if (*p == '\\' && p + 1 < end)
        p++;
      p++;
    }
  *value_len = (size_t)(p - *value_start);
  if (p < end)
    p++;
  return p;
}

/**
 * mediatype_parse_type_subtype - Parse type/subtype from Content-Type
 * @p: Current position
 * @end: End of input
 * @result: Output structure
 * @arena: Memory arena
 *
 * Returns: Position after type/subtype, or NULL on error
 */
static const char *
mediatype_parse_type_subtype (const char *p, const char *end,
                              SocketHTTP_MediaType *result, Arena_T arena)
{
  p = skip_whitespace (p, end);

  const char *type_start = p;
  p = find_token_end (p, end, "/; \t");

  if (p == type_start || p >= end || *p != '/')
    return NULL;

  size_t type_len = (size_t)(p - type_start);
  char *type = ALLOC (arena, type_len + 1);
  if (!type)
    return NULL;
  memcpy (type, type_start, type_len);
  type[type_len] = '\0';
  result->type = type;
  result->type_len = type_len;

  p++;

  const char *subtype_start = p;
  p = find_token_end (p, end, "; \t");

  if (p == subtype_start)
    return NULL;

  size_t subtype_len = (size_t)(p - subtype_start);
  char *subtype = ALLOC (arena, subtype_len + 1);
  if (!subtype)
    return NULL;
  memcpy (subtype, subtype_start, subtype_len);
  subtype[subtype_len] = '\0';
  result->subtype = subtype;
  result->subtype_len = subtype_len;

  return p;
}

/**
 * mediatype_parse_parameter - Parse a single parameter
 * @p: Current position (after semicolon/whitespace)
 * @end: End of input
 * @result: Output structure
 * @arena: Memory arena
 *
 * Returns: Position after parameter
 */
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
    return p;

  size_t param_len = (size_t)(p - param_start);
  p++;

  const char *value_start;
  size_t value_len;

  if (p < end && *p == '"')
    {
      p++;
      p = parse_quoted_value (p, end, &value_start, &value_len);
    }
  else
    {
      value_start = p;
      p = find_token_end (p, end, "; \t");
      value_len = (size_t)(p - value_start);
    }

  /* Check for known parameters */
  if (param_len == MEDIATYPE_CHARSET_LEN
      && strncasecmp (param_start, "charset", MEDIATYPE_CHARSET_LEN) == 0)
    {
      char *cs = ALLOC (arena, value_len + 1);
      if (cs)
        {
          memcpy (cs, value_start, value_len);
          cs[value_len] = '\0';
          result->charset = cs;
          result->charset_len = value_len;
        }
    }
  else if (param_len == MEDIATYPE_BOUNDARY_LEN
           && strncasecmp (param_start, "boundary", MEDIATYPE_BOUNDARY_LEN)
                  == 0)
    {
      char *bd = ALLOC (arena, value_len + 1);
      if (bd)
        {
          memcpy (bd, value_start, value_len);
          bd[value_len] = '\0';
          result->boundary = bd;
          result->boundary_len = value_len;
        }
    }

  return p;
}

/* ============================================================================
 * Media Type Parsing - Public API
 * ============================================================================ */

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
    p = mediatype_parse_parameter (p, end, result, arena);

  return 0;
}

int
SocketHTTP_MediaType_matches (const SocketHTTP_MediaType *type,
                              const char *pattern)
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
 * ============================================================================ */

/**
 * qvalue_compare - Compare function for qsort by quality descending
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

/**
 * accept_parse_quality - Parse quality parameter value
 * @p: Position after "q="
 * @end: End of input (unused but kept for API consistency)
 *
 * Returns: Quality value clamped to [0.0, 1.0]
 */
static float
accept_parse_quality (const char *p, const char *end, const char **out_pos)
{
  char *qend;
  float quality;

  (void)end; /* Reserved for future bounds checking */

  quality = strtof (p, &qend);

  if (qend > p)
    *out_pos = qend;
  else
    *out_pos = p;

  if (quality < 0.0f)
    return 0.0f;
  if (quality > 1.0f)
    return 1.0f;
  return quality;
}

/**
 * accept_parse_single - Parse a single Accept header value
 * @p: Current position
 * @end: End of input
 * @result: Output quality value
 * @arena: Memory arena
 *
 * Returns: Position after this value (at comma or end)
 */
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
  while (value_end > value_start
         && (value_end[-1] == ' ' || value_end[-1] == '\t'))
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
  char *v = ALLOC (arena, vlen + 1);
  if (!v)
    return p;

  memcpy (v, value_start, vlen);
  v[vlen] = '\0';

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
