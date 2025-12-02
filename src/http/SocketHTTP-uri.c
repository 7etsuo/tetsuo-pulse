/**
 * SocketHTTP-uri.c - URI Parsing (RFC 3986)
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
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
 * Internal Helper Functions
 * ============================================================================ */

/**
 * Check if character is valid scheme character
 * scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
 */
static inline int
is_scheme_char (char c, int first)
{
  if (first)
    return isalpha ((unsigned char)c);
  return isalnum ((unsigned char)c) || c == '+' || c == '-' || c == '.';
}

/**
 * Check if character is valid for host
 * Allows unreserved chars, sub-delims, and colon for IPv6
 */
static inline int
is_host_char (char c)
{
  if (isalnum ((unsigned char)c))
    return 1;
  switch (c)
    {
    case '-':
    case '.':
    case '_':
    case '~':
    case '!':
    case '$':
    case '&':
    case '\'':
    case '(':
    case ')':
    case '*':
    case '+':
    case ',':
    case ';':
    case '=':
    case ':': /* For IPv6 */
      return 1;
    default:
      return 0;
    }
}

/**
 * Check if character is a control character (defense in depth)
 * Rejects 0x00-0x1F and DEL (0x7F)
 */
static inline int
is_control_char (char c)
{
  unsigned char uc = (unsigned char)c;
  return uc < 0x20 || uc == 0x7F;
}

/**
 * Allocate and copy string into arena (null-terminated)
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
 * Convert scheme to lowercase in place
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

/* ============================================================================
 * URI Parsing
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

  /* Initialize result */
  memset (result, 0, sizeof (*result));
  result->port = -1;

  const char *p = uri;
  const char *end = uri + len;

  /* Track component positions */
  const char *scheme_start = NULL;
  const char *scheme_end = NULL;
  const char *authority_start = NULL;
  const char *userinfo_start = NULL;
  const char *userinfo_end = NULL;
  const char *host_start = NULL;
  const char *host_end = NULL;
  const char *port_start = NULL;
  const char *port_end = NULL;
  const char *path_start = NULL;
  const char *path_end = NULL;
  const char *query_start = NULL;
  const char *query_end = NULL;
  const char *fragment_start = NULL;
  const char *fragment_end = NULL;

  /* State machine */
  URIParserState state = URI_STATE_START;
  int in_ipv6 = 0;

  while (p < end)
    {
      char c = *p;

      switch (state)
        {
        case URI_STATE_START:
          if (c == '/')
            {
              path_start = p;
              state = URI_STATE_PATH;
            }
          else if (c == '?')
            {
              path_start = p;
              path_end = p;
              query_start = p + 1;
              state = URI_STATE_QUERY;
            }
          else if (c == '#')
            {
              path_start = p;
              path_end = p;
              fragment_start = p + 1;
              state = URI_STATE_FRAGMENT;
            }
          else if (is_scheme_char (c, 1))
            {
              scheme_start = p;
              state = URI_STATE_SCHEME;
            }
          else
            {
              /* Start of path for relative reference */
              path_start = p;
              state = URI_STATE_PATH;
            }
          break;

        case URI_STATE_SCHEME:
          if (c == ':')
            {
              scheme_end = p;
              state = URI_STATE_SCHEME_COLON;
            }
          else if (!is_scheme_char (c, 0))
            {
              /* Not a valid scheme - reinterpret as relative path */
              path_start = scheme_start;
              scheme_start = NULL;
              state = URI_STATE_PATH;
              continue; /* Re-process this character */
            }
          break;

        case URI_STATE_SCHEME_COLON:
          if (c == '/')
            {
              state = URI_STATE_AUTHORITY_START;
            }
          else if (c == '?')
            {
              path_start = p;
              path_end = p;
              query_start = p + 1;
              state = URI_STATE_QUERY;
            }
          else if (c == '#')
            {
              path_start = p;
              path_end = p;
              fragment_start = p + 1;
              state = URI_STATE_FRAGMENT;
            }
          else
            {
              /* Path-only after scheme (e.g., mailto:user@host) */
              path_start = p;
              state = URI_STATE_PATH;
            }
          break;

        case URI_STATE_AUTHORITY_START:
          if (c == '/')
            {
              /* Second slash - authority follows */
              authority_start = p + 1;
              host_start = p + 1;
              state = URI_STATE_AUTHORITY;
            }
          else
            {
              /* Single slash - path starts here */
              path_start = p - 1; /* Include the previous slash */
              state = URI_STATE_PATH;
              continue; /* Re-process this character */
            }
          break;

        case URI_STATE_AUTHORITY:
          if (c == '/')
            {
              /* End of authority - finalize port_end if we tracked a port */
              if (port_start && !port_end)
                port_end = p;
              if (!host_end)
                host_end = p;
              path_start = p;
              state = URI_STATE_PATH;
            }
          else if (c == '?')
            {
              if (port_start && !port_end)
                port_end = p;
              if (!host_end)
                host_end = p;
              path_start = p;
              path_end = p;
              query_start = p + 1;
              state = URI_STATE_QUERY;
            }
          else if (c == '#')
            {
              if (port_start && !port_end)
                port_end = p;
              if (!host_end)
                host_end = p;
              path_start = p;
              path_end = p;
              fragment_start = p + 1;
              state = URI_STATE_FRAGMENT;
            }
          else if (c == '@')
            {
              /* Everything before @ is userinfo */
              userinfo_start = authority_start;
              userinfo_end = p;
              host_start = p + 1;
              host_end = NULL;
              /* Reset port if we tracked a colon position */
              port_start = NULL;
              port_end = NULL;
              /* Stay in AUTHORITY state to parse the actual host */
            }
          else if (c == '[')
            {
              in_ipv6 = 1;
              state = URI_STATE_HOST_IPV6;
            }
          else if (c == ':' && !in_ipv6)
            {
              /* Could be userinfo separator or port separator
               * Track position but stay in AUTHORITY to handle '@' later */
              if (!host_end)
                host_end = p;
              port_start = p + 1;
              /* Don't transition - we'll validate port at authority end */
            }
          break;

        case URI_STATE_HOST:
          /* Not used - we handle host parsing in URI_STATE_AUTHORITY */
          break;

        case URI_STATE_HOST_IPV6:
          if (c == ']')
            {
              in_ipv6 = 0;
              state = URI_STATE_AUTHORITY;
            }
          /* Accept any character inside brackets */
          break;

        case URI_STATE_PORT:
          /* This state is no longer used during parsing - 
           * port validation happens at finalization */
          break;

        case URI_STATE_PATH:
          if (c == '?')
            {
              path_end = p;
              query_start = p + 1;
              state = URI_STATE_QUERY;
            }
          else if (c == '#')
            {
              path_end = p;
              fragment_start = p + 1;
              state = URI_STATE_FRAGMENT;
            }
          /* Accept most characters in path */
          break;

        case URI_STATE_QUERY:
          if (c == '#')
            {
              query_end = p;
              fragment_start = p + 1;
              state = URI_STATE_FRAGMENT;
            }
          /* Accept most characters in query */
          break;

        case URI_STATE_FRAGMENT:
          /* Reject control characters for defense in depth */
          if (is_control_char (c))
            return URI_PARSE_ERROR;
          break;
        }

      p++;
    }

  /* Finalize state */
  switch (state)
    {
    case URI_STATE_SCHEME:
      /* URI ended during scheme - treat as relative path */
      path_start = scheme_start;
      path_end = end;
      scheme_start = NULL;
      scheme_end = NULL;
      break;

    case URI_STATE_AUTHORITY:
      /* If we tracked a port_start but haven't set port_end, set it now */
      if (port_start && !port_end)
        port_end = end;
      if (!host_end)
        host_end = port_start ? (port_start - 1) : end;
      path_start = end;
      path_end = end;
      break;

    case URI_STATE_PORT:
      /* This state is no longer used */
      port_end = end;
      path_start = end;
      path_end = end;
      break;

    case URI_STATE_PATH:
      path_end = end;
      break;

    case URI_STATE_QUERY:
      query_end = end;
      break;

    case URI_STATE_FRAGMENT:
      fragment_end = end;
      break;

    case URI_STATE_HOST_IPV6:
      /* Unclosed IPv6 bracket */
      return URI_PARSE_INVALID_HOST;

    default:
      break;
    }

  /* Allocate and copy components */

  /* Scheme */
  if (scheme_start && scheme_end && scheme_end > scheme_start)
    {
      size_t slen = (size_t)(scheme_end - scheme_start);
      char *s = arena_strdup_n (arena, scheme_start, slen);
      if (!s)
        return URI_PARSE_ERROR;
      scheme_to_lower (s, slen);
      result->scheme = s;
      result->scheme_len = slen;
    }

  /* Userinfo */
  if (userinfo_start && userinfo_end && userinfo_end > userinfo_start)
    {
      size_t ulen = (size_t)(userinfo_end - userinfo_start);
      char *u = arena_strdup_n (arena, userinfo_start, ulen);
      if (!u)
        return URI_PARSE_ERROR;
      result->userinfo = u;
      result->userinfo_len = ulen;
    }

  /* Host */
  if (host_start && host_end && host_end > host_start)
    {
      size_t hlen = (size_t)(host_end - host_start);
      char *h = arena_strdup_n (arena, host_start, hlen);
      if (!h)
        return URI_PARSE_ERROR;
      result->host = h;
      result->host_len = hlen;
    }

  /* Port */
  if (port_start && port_end && port_end > port_start)
    {
      int port = 0;
      for (const char *pp = port_start; pp < port_end; pp++)
        {
          if (!isdigit ((unsigned char)*pp))
            return URI_PARSE_INVALID_PORT;
          port = port * 10 + (*pp - '0');
          if (port > 65535)
            return URI_PARSE_INVALID_PORT;
        }
      result->port = port;
    }

  /* Path */
  if (path_start)
    {
      if (!path_end)
        path_end = end;
      size_t plen = (size_t)(path_end - path_start);
      char *path = arena_strdup_n (arena, path_start, plen);
      if (!path)
        return URI_PARSE_ERROR;
      result->path = path;
      result->path_len = plen;
    }
  else
    {
      /* Empty path */
      char *path = arena_strdup_n (arena, "", 0);
      if (!path)
        return URI_PARSE_ERROR;
      result->path = path;
      result->path_len = 0;
    }

  /* Query */
  if (query_start)
    {
      if (!query_end)
        query_end = end;
      size_t qlen = (size_t)(query_end - query_start);
      char *q = arena_strdup_n (arena, query_start, qlen);
      if (!q)
        return URI_PARSE_ERROR;
      result->query = q;
      result->query_len = qlen;
    }

  /* Fragment */
  if (fragment_start)
    {
      if (!fragment_end)
        fragment_end = end;
      size_t flen = (size_t)(fragment_end - fragment_start);
      char *f = arena_strdup_n (arena, fragment_start, flen);
      if (!f)
        return URI_PARSE_ERROR;
      result->fragment = f;
      result->fragment_len = flen;
    }

  return URI_PARSE_OK;
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
            return -1; /* Truncated encoding */

          unsigned char hi = SOCKETHTTP_HEX_VALUE (input[i + 1]);
          unsigned char lo = SOCKETHTTP_HEX_VALUE (input[i + 2]);

          if (hi == 255 || lo == 255)
            return -1; /* Invalid hex digit */

          output[out_len++] = (char)((hi << 4) | lo);
          i += 2;
        }
      else if (input[i] == '+')
        {
          /* Decode + as space (common in query strings) */
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

ssize_t
SocketHTTP_URI_build (const SocketHTTP_URI *uri, char *output,
                      size_t output_size)
{
  if (!uri || !output || output_size == 0)
    return -1;

  size_t pos = 0;

#define APPEND_STR(s, l)                                                      \
  do                                                                          \
    {                                                                         \
      if (pos + (l) >= output_size)                                           \
        return -1;                                                            \
      memcpy (output + pos, (s), (l));                                        \
      pos += (l);                                                             \
    }                                                                         \
  while (0)

#define APPEND_CHAR(c)                                                        \
  do                                                                          \
    {                                                                         \
      if (pos + 1 >= output_size)                                             \
        return -1;                                                            \
      output[pos++] = (c);                                                    \
    }                                                                         \
  while (0)

  /* Scheme */
  if (uri->scheme && uri->scheme_len > 0)
    {
      APPEND_STR (uri->scheme, uri->scheme_len);
      APPEND_CHAR (':');

      /* Only add // if we have a host */
      if (uri->host && uri->host_len > 0)
        {
          APPEND_CHAR ('/');
          APPEND_CHAR ('/');
        }
    }

  /* Authority */
  if (uri->host && uri->host_len > 0)
    {
      /* Userinfo */
      if (uri->userinfo && uri->userinfo_len > 0)
        {
          APPEND_STR (uri->userinfo, uri->userinfo_len);
          APPEND_CHAR ('@');
        }

      /* Host */
      APPEND_STR (uri->host, uri->host_len);

      /* Port */
      if (uri->port >= 0)
        {
          char port_buf[8];
          int port_len = snprintf (port_buf, sizeof (port_buf), ":%d", uri->port);
          if (port_len > 0 && (size_t)port_len < sizeof (port_buf))
            {
              APPEND_STR (port_buf, (size_t)port_len);
            }
        }
    }

  /* Path */
  if (uri->path && uri->path_len > 0)
    {
      APPEND_STR (uri->path, uri->path_len);
    }

  /* Query */
  if (uri->query && uri->query_len > 0)
    {
      APPEND_CHAR ('?');
      APPEND_STR (uri->query, uri->query_len);
    }

  /* Fragment */
  if (uri->fragment && uri->fragment_len > 0)
    {
      APPEND_CHAR ('#');
      APPEND_STR (uri->fragment, uri->fragment_len);
    }

#undef APPEND_STR
#undef APPEND_CHAR

  output[pos] = '\0';
  return (ssize_t)pos;
}

/* ============================================================================
 * Media Type Parsing
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

  const char *p = value;
  const char *end = value + len;

  /* Skip leading whitespace */
  while (p < end && (*p == ' ' || *p == '\t'))
    p++;

  /* Parse type */
  const char *type_start = p;
  while (p < end && *p != '/' && *p != ';' && *p != ' ' && *p != '\t')
    p++;

  if (p == type_start || p >= end || *p != '/')
    return -1;

  size_t type_len = (size_t)(p - type_start);
  char *type = ALLOC (arena, type_len + 1);
  if (!type)
    return -1;
  memcpy (type, type_start, type_len);
  type[type_len] = '\0';
  result->type = type;
  result->type_len = type_len;

  p++; /* Skip '/' */

  /* Parse subtype */
  const char *subtype_start = p;
  while (p < end && *p != ';' && *p != ' ' && *p != '\t')
    p++;

  if (p == subtype_start)
    return -1;

  size_t subtype_len = (size_t)(p - subtype_start);
  char *subtype = ALLOC (arena, subtype_len + 1);
  if (!subtype)
    return -1;
  memcpy (subtype, subtype_start, subtype_len);
  subtype[subtype_len] = '\0';
  result->subtype = subtype;
  result->subtype_len = subtype_len;

  /* Parse parameters */
  while (p < end)
    {
      /* Skip whitespace and semicolons */
      while (p < end && (*p == ' ' || *p == '\t' || *p == ';'))
        p++;

      if (p >= end)
        break;

      /* Parse parameter name */
      const char *param_start = p;
      while (p < end && *p != '=' && *p != ';' && *p != ' ' && *p != '\t')
        p++;

      if (p >= end || *p != '=')
        continue;

      size_t param_len = (size_t)(p - param_start);
      p++; /* Skip '=' */

      /* Parse parameter value */
      const char *value_start;
      size_t value_len;

      if (p < end && *p == '"')
        {
          /* Quoted value */
          p++;
          value_start = p;
          while (p < end && *p != '"')
            {
              if (*p == '\\' && p + 1 < end)
                p++; /* Skip escaped char */
              p++;
            }
          value_len = (size_t)(p - value_start);
          if (p < end)
            p++; /* Skip closing quote */
        }
      else
        {
          /* Unquoted value */
          value_start = p;
          while (p < end && *p != ';' && *p != ' ' && *p != '\t')
            p++;
          value_len = (size_t)(p - value_start);
        }

      /* Check for known parameters */
      if (param_len == 7
          && strncasecmp (param_start, "charset", 7) == 0)
        {
          char *cs = ALLOC (arena, value_len + 1);
          if (!cs)
            return -1;
          memcpy (cs, value_start, value_len);
          cs[value_len] = '\0';
          result->charset = cs;
          result->charset_len = value_len;
        }
      else if (param_len == 8
               && strncasecmp (param_start, "boundary", 8) == 0)
        {
          char *bd = ALLOC (arena, value_len + 1);
          if (!bd)
            return -1;
          memcpy (bd, value_start, value_len);
          bd[value_len] = '\0';
          result->boundary = bd;
          result->boundary_len = value_len;
        }
    }

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

  /* Check type */
  if (pat_type_len != 1 || pattern[0] != '*')
    {
      if (type->type_len != pat_type_len
          || strncasecmp (type->type, pattern, pat_type_len) != 0)
        return 0;
    }

  /* Check subtype */
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
 * Compare function for qsort - sort by quality descending
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
      /* Skip whitespace and commas */
      while (p < end && (*p == ' ' || *p == '\t' || *p == ','))
        p++;

      if (p >= end)
        break;

      /* Find end of value (before ; or ,) */
      const char *value_start = p;
      while (p < end && *p != ';' && *p != ',')
        p++;

      /* Trim trailing whitespace from value */
      const char *value_end = p;
      while (value_end > value_start
             && (value_end[-1] == ' ' || value_end[-1] == '\t'))
        value_end--;

      if (value_end == value_start)
        continue;

      /* Default quality */
      float quality = 1.0f;

      /* Check for quality parameter */
      if (p < end && *p == ';')
        {
          p++;

          /* Skip whitespace */
          while (p < end && (*p == ' ' || *p == '\t'))
            p++;

          /* Look for q= */
          if (p + 2 < end && (p[0] == 'q' || p[0] == 'Q') && p[1] == '=')
            {
              p += 2;
              char *qend;
              quality = strtof (p, &qend);
              if (qend > p)
                p = qend;

              /* Clamp to valid range */
              if (quality < 0.0f)
                quality = 0.0f;
              if (quality > 1.0f)
                quality = 1.0f;
            }

          /* Skip to next comma */
          while (p < end && *p != ',')
            p++;
        }

      /* Store result */
      size_t vlen = (size_t)(value_end - value_start);
      char *v = ALLOC (arena, vlen + 1);
      if (!v)
        break;
      memcpy (v, value_start, vlen);
      v[vlen] = '\0';

      results[count].value = v;
      results[count].value_len = vlen;
      results[count].quality = quality;
      count++;
    }

  /* Sort by quality descending */
  if (count > 1)
    qsort (results, count, sizeof (results[0]), qvalue_compare);

  return count;
}

