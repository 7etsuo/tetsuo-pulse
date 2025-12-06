/**
 * SocketHTTP-core.c - HTTP Core Utilities
 *
 * Part of the Socket Library
 *
 * Implements HTTP methods, status codes, versions, and character tables.
 */

#include "http/SocketHTTP.h"
#include "http/SocketHTTP-private.h"
#include "core/SocketUtil.h"

#include <assert.h>
#include <ctype.h>
#include <string.h>

/* ============================================================================
 * Exception Definitions
 * ============================================================================ */

const Except_T SocketHTTP_ParseError = { &SocketHTTP_ParseError, "HTTP parse error" };
const Except_T SocketHTTP_InvalidURI = { &SocketHTTP_InvalidURI, "Invalid URI" };
const Except_T SocketHTTP_InvalidHeader = { &SocketHTTP_InvalidHeader, "Invalid HTTP header" };

/* ============================================================================
 * Character Classification Tables
 * ============================================================================ */

/**
 * Token character table for RFC 9110
 * tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
 *         "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
 */
const unsigned char sockethttp_tchar_table[256] = {
  /* 0x00-0x0F */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  /* 0x10-0x1F */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  /* 0x20-0x2F */ 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0,
  /*             sp  !  "  #  $  %  &  '  (  )  *  +  ,  -  .  / */
  /* 0x30-0x3F */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
  /*              0  1  2  3  4  5  6  7  8  9  :  ;  <  =  >  ? */
  /* 0x40-0x4F */ 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  /*              @  A  B  C  D  E  F  G  H  I  J  K  L  M  N  O */
  /* 0x50-0x5F */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1,
  /*              P  Q  R  S  T  U  V  W  X  Y  Z  [  \  ]  ^  _ */
  /* 0x60-0x6F */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  /*              `  a  b  c  d  e  f  g  h  i  j  k  l  m  n  o */
  /* 0x70-0x7F */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0,
  /*              p  q  r  s  t  u  v  w  x  y  z  {  |  }  ~ DEL */
  /* 0x80-0xFF */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/**
 * Unreserved characters for URI per RFC 3986
 * unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
 */
const unsigned char sockethttp_uri_unreserved[256] = {
  /* 0x00-0x0F */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  /* 0x10-0x1F */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  /* 0x20-0x2F */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0,
  /*             sp  !  "  #  $  %  &  '  (  )  *  +  ,  -  .  / */
  /* 0x30-0x3F */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
  /*              0  1  2  3  4  5  6  7  8  9  :  ;  <  =  >  ? */
  /* 0x40-0x4F */ 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  /*              @  A  B  C  D  E  F  G  H  I  J  K  L  M  N  O */
  /* 0x50-0x5F */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1,
  /*              P  Q  R  S  T  U  V  W  X  Y  Z  [  \  ]  ^  _ */
  /* 0x60-0x6F */ 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  /*              `  a  b  c  d  e  f  g  h  i  j  k  l  m  n  o */
  /* 0x70-0x7F */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0,
  /*              p  q  r  s  t  u  v  w  x  y  z  {  |  }  ~ DEL */
  /* 0x80-0xFF */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/**
 * Hex value table for percent decoding
 * Returns 0-15 for '0'-'9', 'a'-'f', 'A'-'F', or 255 for invalid
 */
const unsigned char sockethttp_hex_value[256] = {
  /* 0x00-0x0F */ 255, 255, 255, 255, 255, 255, 255, 255,
                  255, 255, 255, 255, 255, 255, 255, 255,
  /* 0x10-0x1F */ 255, 255, 255, 255, 255, 255, 255, 255,
                  255, 255, 255, 255, 255, 255, 255, 255,
  /* 0x20-0x2F */ 255, 255, 255, 255, 255, 255, 255, 255,
                  255, 255, 255, 255, 255, 255, 255, 255,
  /* 0x30-0x3F */ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,       /* '0'-'9' */
                  255, 255, 255, 255, 255, 255,
  /* 0x40-0x4F */ 255, 10, 11, 12, 13, 14, 15,        /* 'A'-'F' */
                  255, 255, 255, 255, 255, 255, 255, 255, 255,
  /* 0x50-0x5F */ 255, 255, 255, 255, 255, 255, 255, 255,
                  255, 255, 255, 255, 255, 255, 255, 255,
  /* 0x60-0x6F */ 255, 10, 11, 12, 13, 14, 15,        /* 'a'-'f' */
                  255, 255, 255, 255, 255, 255, 255, 255, 255,
  /* 0x70-0x7F */ 255, 255, 255, 255, 255, 255, 255, 255,
                  255, 255, 255, 255, 255, 255, 255, 255,
  /* 0x80-0xFF */ 255, 255, 255, 255, 255, 255, 255, 255,
                  255, 255, 255, 255, 255, 255, 255, 255,
                  255, 255, 255, 255, 255, 255, 255, 255,
                  255, 255, 255, 255, 255, 255, 255, 255,
                  255, 255, 255, 255, 255, 255, 255, 255,
                  255, 255, 255, 255, 255, 255, 255, 255,
                  255, 255, 255, 255, 255, 255, 255, 255,
                  255, 255, 255, 255, 255, 255, 255, 255,
                  255, 255, 255, 255, 255, 255, 255, 255,
                  255, 255, 255, 255, 255, 255, 255, 255,
                  255, 255, 255, 255, 255, 255, 255, 255,
                  255, 255, 255, 255, 255, 255, 255, 255,
                  255, 255, 255, 255, 255, 255, 255, 255,
                  255, 255, 255, 255, 255, 255, 255, 255,
                  255, 255, 255, 255, 255, 255, 255, 255,
                  255, 255, 255, 255, 255, 255, 255, 255
};

/* ============================================================================
 * HTTP Version Functions
 * ============================================================================ */

const char *
SocketHTTP_version_string (SocketHTTP_Version version)
{
  switch (version)
    {
    case HTTP_VERSION_0_9:
      return "HTTP/0.9";
    case HTTP_VERSION_1_0:
      return "HTTP/1.0";
    case HTTP_VERSION_1_1:
      return "HTTP/1.1";
    case HTTP_VERSION_2:
      return "HTTP/2";
    case HTTP_VERSION_3:
      return "HTTP/3";
    default:
      return "HTTP/?";
    }
}

SocketHTTP_Version
SocketHTTP_version_parse (const char *str, size_t len)
{
  if (!str)
    return HTTP_VERSION_0_9;
  if (len == 0)
    len = strlen (str);

  if (len == 8)
    {
      if (memcmp (str, "HTTP/1.1", 8) == 0)
        return HTTP_VERSION_1_1;
      if (memcmp (str, "HTTP/1.0", 8) == 0)
        return HTTP_VERSION_1_0;
      if (memcmp (str, "HTTP/0.9", 8) == 0)
        return HTTP_VERSION_0_9;
    }
  else if (len == 6)
    {
      if (memcmp (str, "HTTP/2", 6) == 0)
        return HTTP_VERSION_2;
      if (memcmp (str, "HTTP/3", 6) == 0)
        return HTTP_VERSION_3;
    }

  return HTTP_VERSION_0_9;
}

/* ============================================================================
 * HTTP Method Functions
 * ============================================================================ */

/**
 * Method name lookup table
 */
static const struct
{
  const char *name;
  size_t len;
  SocketHTTP_Method method;
  SocketHTTP_MethodProperties props;
} method_table[] = {
  /* name, len, method, {safe, idempotent, cacheable, has_body, response_body} */
  { "GET", 3, HTTP_METHOD_GET, { 1, 1, 1, 0, 1 } },
  { "HEAD", 4, HTTP_METHOD_HEAD, { 1, 1, 1, 0, 0 } },
  { "POST", 4, HTTP_METHOD_POST, { 0, 0, 0, 1, 1 } },
  { "PUT", 3, HTTP_METHOD_PUT, { 0, 1, 0, 1, 1 } },
  { "DELETE", 6, HTTP_METHOD_DELETE, { 0, 1, 0, 0, 1 } },
  { "CONNECT", 7, HTTP_METHOD_CONNECT, { 0, 0, 0, 0, 1 } },
  { "OPTIONS", 7, HTTP_METHOD_OPTIONS, { 1, 1, 0, 0, 1 } },
  { "TRACE", 5, HTTP_METHOD_TRACE, { 1, 1, 0, 0, 1 } },
  { "PATCH", 5, HTTP_METHOD_PATCH, { 0, 0, 0, 1, 1 } },
  { NULL, 0, HTTP_METHOD_UNKNOWN, { 0, 0, 0, 0, 0 } }
};

const char *
SocketHTTP_method_name (SocketHTTP_Method method)
{
  for (int i = 0; method_table[i].name != NULL; i++)
    {
      if (method_table[i].method == method)
        return method_table[i].name;
    }
  return NULL;
}

SocketHTTP_Method
SocketHTTP_method_parse (const char *str, size_t len)
{
  if (!str)
    return HTTP_METHOD_UNKNOWN;
  if (len == 0)
    len = strlen (str);

  for (int i = 0; method_table[i].name != NULL; i++)
    {
      if (len == method_table[i].len
          && memcmp (str, method_table[i].name, len) == 0)
        return method_table[i].method;
    }

  return HTTP_METHOD_UNKNOWN;
}

SocketHTTP_MethodProperties
SocketHTTP_method_properties (SocketHTTP_Method method)
{
  for (int i = 0; method_table[i].name != NULL; i++)
    {
      if (method_table[i].method == method)
        return method_table[i].props;
    }

  /* Return safe defaults for unknown methods */
  SocketHTTP_MethodProperties props = { 0, 0, 0, 0, 1 };
  return props;
}

int
SocketHTTP_method_valid (const char *str, size_t len)
{
  if (!str || len == 0)
    return 0;

  /* Per RFC 9110, method is a token */
  for (size_t i = 0; i < len; i++)
    {
      if (!SOCKETHTTP_IS_TCHAR (str[i]))
        return 0;
    }
  return 1;
}

/* ============================================================================
 * HTTP Status Code Functions
 * ============================================================================ */

/**
 * Status code reason phrases
 */
static const struct
{
  int code;
  const char *reason;
} status_table[] = {
  /* 1xx Informational */
  { 100, "Continue" },
  { 101, "Switching Protocols" },
  { 102, "Processing" },
  { 103, "Early Hints" },

  /* 2xx Successful */
  { 200, "OK" },
  { 201, "Created" },
  { 202, "Accepted" },
  { 203, "Non-Authoritative Information" },
  { 204, "No Content" },
  { 205, "Reset Content" },
  { 206, "Partial Content" },
  { 207, "Multi-Status" },
  { 208, "Already Reported" },
  { 226, "IM Used" },

  /* 3xx Redirection */
  { 300, "Multiple Choices" },
  { 301, "Moved Permanently" },
  { 302, "Found" },
  { 303, "See Other" },
  { 304, "Not Modified" },
  { 305, "Use Proxy" },
  { 307, "Temporary Redirect" },
  { 308, "Permanent Redirect" },

  /* 4xx Client Error */
  { 400, "Bad Request" },
  { 401, "Unauthorized" },
  { 402, "Payment Required" },
  { 403, "Forbidden" },
  { 404, "Not Found" },
  { 405, "Method Not Allowed" },
  { 406, "Not Acceptable" },
  { 407, "Proxy Authentication Required" },
  { 408, "Request Timeout" },
  { 409, "Conflict" },
  { 410, "Gone" },
  { 411, "Length Required" },
  { 412, "Precondition Failed" },
  { 413, "Content Too Large" },
  { 414, "URI Too Long" },
  { 415, "Unsupported Media Type" },
  { 416, "Range Not Satisfiable" },
  { 417, "Expectation Failed" },
  { 418, "I'm a Teapot" },
  { 421, "Misdirected Request" },
  { 422, "Unprocessable Content" },
  { 423, "Locked" },
  { 424, "Failed Dependency" },
  { 425, "Too Early" },
  { 426, "Upgrade Required" },
  { 428, "Precondition Required" },
  { 429, "Too Many Requests" },
  { 431, "Request Header Fields Too Large" },
  { 451, "Unavailable For Legal Reasons" },

  /* 5xx Server Error */
  { 500, "Internal Server Error" },
  { 501, "Not Implemented" },
  { 502, "Bad Gateway" },
  { 503, "Service Unavailable" },
  { 504, "Gateway Timeout" },
  { 505, "HTTP Version Not Supported" },
  { 506, "Variant Also Negotiates" },
  { 507, "Insufficient Storage" },
  { 508, "Loop Detected" },
  { 510, "Not Extended" },
  { 511, "Network Authentication Required" },

  { 0, NULL }
};

const char *
SocketHTTP_status_reason (int code)
{
  /* Binary search would be faster, but table is small enough */
  for (int i = 0; status_table[i].reason != NULL; i++)
    {
      if (status_table[i].code == code)
        return status_table[i].reason;
    }
  return "Unknown";
}

SocketHTTP_StatusCategory
SocketHTTP_status_category (int code)
{
  if (code >= 100 && code < 200)
    return HTTP_STATUS_INFORMATIONAL;
  if (code >= 200 && code < 300)
    return HTTP_STATUS_SUCCESSFUL;
  if (code >= 300 && code < 400)
    return HTTP_STATUS_REDIRECTION;
  if (code >= 400 && code < 500)
    return HTTP_STATUS_CLIENT_ERROR;
  if (code >= 500 && code < 600)
    return HTTP_STATUS_SERVER_ERROR;
  return 0;
}

int
SocketHTTP_status_valid (int code)
{
  return code >= 100 && code <= 599;
}

/* ============================================================================
 * Header Validation Functions
 * ============================================================================ */

int
SocketHTTP_header_name_valid (const char *name, size_t len)
{
  if (!name || len == 0)
    return 0;

  if (len > SOCKETHTTP_MAX_HEADER_NAME)
    return 0;

  /* Header name must be a token per RFC 9110 */
  for (size_t i = 0; i < len; i++)
    {
      if (!SOCKETHTTP_IS_TCHAR (name[i]))
        return 0;
    }
  return 1;
}

int
SocketHTTP_header_value_valid (const char *value, size_t len)
{
  if (!value)
    return len == 0;

  if (len > SOCKETHTTP_MAX_HEADER_VALUE)
    return 0;

  /*
   * SECURITY: Reject NUL, CR, and LF in header values to prevent
   * HTTP header injection attacks (CWE-113).
   *
   * Per RFC 9110 Section 5.5, field values should not contain CR or LF
   * except in obsolete line folding (obs-fold), which is deprecated.
   * For security, we reject ALL CR and LF characters to prevent:
   *   - Header injection via CRLF sequences
   *   - Response splitting attacks
   *   - Cache poisoning
   *   - Session hijacking via injected Set-Cookie headers
   *
   * Note: Applications that need to include CR/LF must use proper
   * encoding (e.g., percent-encoding for URIs, quoted-string for some
   * headers, or multipart for bodies).
   */
  for (size_t i = 0; i < len; i++)
    {
      unsigned char c = (unsigned char)value[i];

      /* Reject NUL - always invalid in HTTP */
      if (c == 0)
        return 0;

      /* Reject CR - prevents CRLF injection */
      if (c == '\r')
        return 0;

      /* Reject LF - prevents header line termination injection */
      if (c == '\n')
        return 0;
    }
  return 1;
}

/* ============================================================================
 * Transfer/Content Coding Functions
 * ============================================================================ */

static const struct
{
  const char *name;
  size_t len;
  SocketHTTP_Coding coding;
} coding_table[] = {
  { "identity", 8, HTTP_CODING_IDENTITY },
  { "chunked", 7, HTTP_CODING_CHUNKED },
  { "gzip", 4, HTTP_CODING_GZIP },
  { "deflate", 7, HTTP_CODING_DEFLATE },
  { "compress", 8, HTTP_CODING_COMPRESS },
  { "br", 2, HTTP_CODING_BR },
  { NULL, 0, HTTP_CODING_UNKNOWN }
};

SocketHTTP_Coding
SocketHTTP_coding_parse (const char *name, size_t len)
{
  if (!name)
    return HTTP_CODING_UNKNOWN;
  if (len == 0)
    len = strlen (name);

  for (int i = 0; coding_table[i].name != NULL; i++)
    {
      if (len == coding_table[i].len)
        {
          /* Case-insensitive comparison */
          int match = 1;
          for (size_t j = 0; j < len; j++)
            {
              char a = name[j];
              char b = coding_table[i].name[j];
              if (a >= 'A' && a <= 'Z')
                a = a + ('a' - 'A');
              if (a != b)
                {
                  match = 0;
                  break;
                }
            }
          if (match)
            return coding_table[i].coding;
        }
    }

  return HTTP_CODING_UNKNOWN;
}

const char *
SocketHTTP_coding_name (SocketHTTP_Coding coding)
{
  for (int i = 0; coding_table[i].name != NULL; i++)
    {
      if (coding_table[i].coding == coding)
        return coding_table[i].name;
    }
  return NULL;
}

