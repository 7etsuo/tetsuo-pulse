/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketHTTP-core.c - HTTP Core Utilities
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Implements HTTP methods, status codes, versions, and character tables.
 */



#include <stdbool.h>
#include "http/SocketHTTP-private.h"
#include "http/SocketHTTP.h"

/* String length constants for HTTP token parsing (RFC 9110) */
#define SOCKETHTTP_VERSION_STR_LEN_FULL 8
#define SOCKETHTTP_VERSION_STR_LEN_SHORT 6
#define SOCKETHTTP_METHOD_LEN_GET 3
#define SOCKETHTTP_METHOD_LEN_PUT 3
#define SOCKETHTTP_METHOD_LEN_HEAD 4
#define SOCKETHTTP_METHOD_LEN_POST 4
#define SOCKETHTTP_METHOD_LEN_TRACE 5
#define SOCKETHTTP_METHOD_LEN_PATCH 5
#define SOCKETHTTP_METHOD_LEN_DELETE 6
#define SOCKETHTTP_METHOD_LEN_CONNECT 7
#define SOCKETHTTP_METHOD_LEN_OPTIONS 7
#define SOCKETHTTP_CODING_LEN_IDENTITY 8
#define SOCKETHTTP_CODING_LEN_CHUNKED 7
#define SOCKETHTTP_CODING_LEN_GZIP 4
#define SOCKETHTTP_CODING_LEN_DEFLATE 7
#define SOCKETHTTP_CODING_LEN_COMPRESS 8
#define SOCKETHTTP_CODING_LEN_BR 2
/* Exception Definitions */
const Except_T SocketHTTP_Failed = { &SocketHTTP_Failed, "HTTP core failure" };
const Except_T SocketHTTP_ParseError = { &SocketHTTP_Failed, "HTTP core parse error" };
const Except_T SocketHTTP_InvalidURI = { &SocketHTTP_Failed, "Invalid URI syntax" };
const Except_T SocketHTTP_InvalidHeader = { &SocketHTTP_Failed, "Invalid HTTP header" };

/* ============================================================================
 * Character Classification Tables
 * ============================================================================
 */

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
  /* 0x80-0xFF */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0
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
  /* 0x80-0xFF */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0
};

/* Hex value table for percent decoding (0-15 valid, 255 invalid) */
#define SOCKETHTTP_HEX_INVALID 255
#define X SOCKETHTTP_HEX_INVALID
const unsigned char sockethttp_hex_value[256] = {
  /* 0x00-0x0F */ X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X,
  /* 0x10-0x1F */ X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X,
  /* 0x20-0x2F */ X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X,
  /*             sp  !  "  #  $  %  &  '  (  )  *  +  ,  -  .  / */
  /* 0x30-0x3F */ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, X, X, X, X, X, X,
  /*              0  1  2  3  4  5  6  7  8  9  :  ;  <  =  >  ? */
  /* 0x40-0x4F */ X,10,11,12,13,14,15, X, X, X, X, X, X, X, X, X,
  /*              @  A  B  C  D  E  F  G  H  I  J  K  L  M  N  O */
  /* 0x50-0x5F */ X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X,
  /*              P  Q  R  S  T  U  V  W  X  Y  Z  [  \  ]  ^  _ */
  /* 0x60-0x6F */ X,10,11,12,13,14,15, X, X, X, X, X, X, X, X, X,
  /*              `  a  b  c  d  e  f  g  h  i  j  k  l  m  n  o */
  /* 0x70-0x7F */ X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X,
  /*              p  q  r  s  t  u  v  w  x  y  z  {  |  }  ~ DEL */
  /* 0x80-0x8F */ X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X,
  /* 0x90-0x9F */ X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X,
  /* 0xA0-0xAF */ X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X,
  /* 0xB0-0xBF */ X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X,
  /* 0xC0-0xCF */ X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X,
  /* 0xD0-0xDF */ X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X,
  /* 0xE0-0xEF */ X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X,
  /* 0xF0-0xFF */ X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X
};

#undef X

/* Forward declaration */
static size_t sockethttp_effective_length (const char *str, size_t len);

/* Parse entry for enum string mapping */
struct ParseEntry {
  size_t len;
  const char *str;
  int val;
  bool case_insens;
};

static int
sockethttp_parse_enum(const char *str, size_t len, const struct ParseEntry *table, size_t table_size, int default_val)
{
  if (!str)
    return default_val;
  len = sockethttp_effective_length(str, len);
  for (size_t i = 0; i < table_size; i++) {
    if (len == table[i].len &&
        (table[i].case_insens ? strncasecmp(str, table[i].str, len) == 0 :
                                memcmp(str, table[i].str, len) == 0)) {
      return table[i].val;
    }
  }
  return default_val;
}

/* Get effective string length (use strlen if len==0) */
static size_t
sockethttp_effective_length (const char *str, size_t len)
{
  if (!str)
    return 0;
  if (len == 0)
    return strlen (str);
  return len;
}

/* Validate token characters per RFC 9110 */
static int
sockethttp_is_token (const char *s, size_t len)
{
  for (size_t i = 0; i < len; i++)
    {
      if (!SOCKETHTTP_IS_TCHAR (s[i]))
        return 0;
    }
  return 1;
}

/* Check header value for injection chars (NUL, CR, LF) */
static int
sockethttp_header_value_is_safe (const char *s, size_t len)
{
  for (size_t i = 0; i < len; i++)
    {
      unsigned char c = (unsigned char)s[i];
      if (c == 0 || c == '\r' || c == '\n')
        return 0;
    }
  return 1;
}

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

static const struct ParseEntry version_table[] = {
    {SOCKETHTTP_VERSION_STR_LEN_FULL, "HTTP/0.9", HTTP_VERSION_0_9, false},
    {SOCKETHTTP_VERSION_STR_LEN_FULL, "HTTP/1.0", HTTP_VERSION_1_0, false},
    {SOCKETHTTP_VERSION_STR_LEN_FULL, "HTTP/1.1", HTTP_VERSION_1_1, false},
    {SOCKETHTTP_VERSION_STR_LEN_SHORT, "HTTP/2", HTTP_VERSION_2, false},
    {SOCKETHTTP_VERSION_STR_LEN_SHORT, "HTTP/3", HTTP_VERSION_3, false},
};

SocketHTTP_Version
SocketHTTP_version_parse (const char *str, size_t len)
{
  return (SocketHTTP_Version)sockethttp_parse_enum(str, len, version_table,
    sizeof(version_table) / sizeof(version_table[0]), HTTP_VERSION_0_9);
}

const char *
SocketHTTP_method_name (SocketHTTP_Method method)
{
  switch (method)
    {
    case HTTP_METHOD_GET:
      return "GET";
    case HTTP_METHOD_HEAD:
      return "HEAD";
    case HTTP_METHOD_POST:
      return "POST";
    case HTTP_METHOD_PUT:
      return "PUT";
    case HTTP_METHOD_DELETE:
      return "DELETE";
    case HTTP_METHOD_CONNECT:
      return "CONNECT";
    case HTTP_METHOD_OPTIONS:
      return "OPTIONS";
    case HTTP_METHOD_TRACE:
      return "TRACE";
    case HTTP_METHOD_PATCH:
      return "PATCH";
    default:
      return NULL;
    }
}

static const struct ParseEntry method_table[] = {
    {SOCKETHTTP_METHOD_LEN_GET, "GET", HTTP_METHOD_GET, false},
    {SOCKETHTTP_METHOD_LEN_PUT, "PUT", HTTP_METHOD_PUT, false},
    {SOCKETHTTP_METHOD_LEN_HEAD, "HEAD", HTTP_METHOD_HEAD, false},
    {SOCKETHTTP_METHOD_LEN_POST, "POST", HTTP_METHOD_POST, false},
    {SOCKETHTTP_METHOD_LEN_TRACE, "TRACE", HTTP_METHOD_TRACE, false},
    {SOCKETHTTP_METHOD_LEN_PATCH, "PATCH", HTTP_METHOD_PATCH, false},
    {SOCKETHTTP_METHOD_LEN_DELETE, "DELETE", HTTP_METHOD_DELETE, false},
    {SOCKETHTTP_METHOD_LEN_CONNECT, "CONNECT", HTTP_METHOD_CONNECT, false},
    {SOCKETHTTP_METHOD_LEN_OPTIONS, "OPTIONS", HTTP_METHOD_OPTIONS, false},
};

SocketHTTP_Method
SocketHTTP_method_parse (const char *str, size_t len)
{
  return (SocketHTTP_Method)sockethttp_parse_enum(str, len, method_table,
    sizeof(method_table) / sizeof(method_table[0]), HTTP_METHOD_UNKNOWN);
}

SocketHTTP_MethodProperties
SocketHTTP_method_properties (SocketHTTP_Method method)
{
  switch (method)
    {
    case HTTP_METHOD_GET:
      return (SocketHTTP_MethodProperties){ 1, 1, 1, 0, 1 };
    case HTTP_METHOD_HEAD:
      return (SocketHTTP_MethodProperties){ 1, 1, 1, 0, 0 };
    case HTTP_METHOD_POST:
      return (SocketHTTP_MethodProperties){ 0, 0, 0, 1, 1 };
    case HTTP_METHOD_PUT:
      return (SocketHTTP_MethodProperties){ 0, 1, 0, 1, 1 };
    case HTTP_METHOD_DELETE:
      return (SocketHTTP_MethodProperties){ 0, 1, 0, 0, 1 };
    case HTTP_METHOD_CONNECT:
      return (SocketHTTP_MethodProperties){ 0, 0, 0, 0, 1 };
    case HTTP_METHOD_OPTIONS:
      return (SocketHTTP_MethodProperties){ 1, 1, 0, 0, 1 };
    case HTTP_METHOD_TRACE:
      return (SocketHTTP_MethodProperties){ 1, 1, 0, 0, 1 };
    case HTTP_METHOD_PATCH:
      return (SocketHTTP_MethodProperties){ 0, 0, 0, 1, 1 };
    default:
      return (SocketHTTP_MethodProperties){ 0, 0, 0, 0, 1 };
    }
}

int
SocketHTTP_method_valid (const char *str, size_t len)
{
  if (!str)
    return 0;
  len = sockethttp_effective_length (str, len);
  if (len == 0)
    return 0;
  return sockethttp_is_token (str, len);
}

/* Status code reason phrases (indexed by code - 100) */
static const char
    *status_reasons[HTTP_STATUS_CODE_MAX - HTTP_STATUS_CODE_MIN + 1]
    = { NULL };

static const struct {
    int code;
    const char *phrase;
} status_phrases_static[] = {
    {HTTP_STATUS_CONTINUE, "Continue"},
    {HTTP_STATUS_SWITCHING_PROTOCOLS, "Switching Protocols"},
    {HTTP_STATUS_PROCESSING, "Processing"},
    {HTTP_STATUS_EARLY_HINTS, "Early Hints"},

    {HTTP_STATUS_OK, "OK"},
    {HTTP_STATUS_CREATED, "Created"},
    {HTTP_STATUS_ACCEPTED, "Accepted"},
    {HTTP_STATUS_NON_AUTHORITATIVE, "Non-Authoritative Information"},
    {HTTP_STATUS_NO_CONTENT, "No Content"},
    {HTTP_STATUS_RESET_CONTENT, "Reset Content"},
    {HTTP_STATUS_PARTIAL_CONTENT, "Partial Content"},
    {HTTP_STATUS_MULTI_STATUS, "Multi-Status"},
    {HTTP_STATUS_ALREADY_REPORTED, "Already Reported"},
    {HTTP_STATUS_IM_USED, "IM Used"},

    {HTTP_STATUS_MULTIPLE_CHOICES, "Multiple Choices"},
    {HTTP_STATUS_MOVED_PERMANENTLY, "Moved Permanently"},
    {HTTP_STATUS_FOUND, "Found"},
    {HTTP_STATUS_SEE_OTHER, "See Other"},
    {HTTP_STATUS_NOT_MODIFIED, "Not Modified"},
    {HTTP_STATUS_USE_PROXY, "Use Proxy"},
    {HTTP_STATUS_TEMPORARY_REDIRECT, "Temporary Redirect"},
    {HTTP_STATUS_PERMANENT_REDIRECT, "Permanent Redirect"},

    {HTTP_STATUS_BAD_REQUEST, "Bad Request"},
    {HTTP_STATUS_UNAUTHORIZED, "Unauthorized"},
    {HTTP_STATUS_PAYMENT_REQUIRED, "Payment Required"},
    {HTTP_STATUS_FORBIDDEN, "Forbidden"},
    {HTTP_STATUS_NOT_FOUND, "Not Found"},
    {HTTP_STATUS_METHOD_NOT_ALLOWED, "Method Not Allowed"},
    {HTTP_STATUS_NOT_ACCEPTABLE, "Not Acceptable"},
    {HTTP_STATUS_PROXY_AUTH_REQUIRED, "Proxy Authentication Required"},
    {HTTP_STATUS_REQUEST_TIMEOUT, "Request Timeout"},
    {HTTP_STATUS_CONFLICT, "Conflict"},
    {HTTP_STATUS_GONE, "Gone"},
    {HTTP_STATUS_LENGTH_REQUIRED, "Length Required"},
    {HTTP_STATUS_PRECONDITION_FAILED, "Precondition Failed"},
    {HTTP_STATUS_CONTENT_TOO_LARGE, "Content Too Large"},
    {HTTP_STATUS_URI_TOO_LONG, "URI Too Long"},
    {HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE, "Unsupported Media Type"},
    {HTTP_STATUS_RANGE_NOT_SATISFIABLE, "Range Not Satisfiable"},
    {HTTP_STATUS_EXPECTATION_FAILED, "Expectation Failed"},
    {HTTP_STATUS_IM_A_TEAPOT, "I'm a Teapot"},
    {HTTP_STATUS_MISDIRECTED_REQUEST, "Misdirected Request"},
    {HTTP_STATUS_UNPROCESSABLE_CONTENT, "Unprocessable Content"},
    {HTTP_STATUS_LOCKED, "Locked"},
    {HTTP_STATUS_FAILED_DEPENDENCY, "Failed Dependency"},
    {HTTP_STATUS_TOO_EARLY, "Too Early"},
    {HTTP_STATUS_UPGRADE_REQUIRED, "Upgrade Required"},
    {HTTP_STATUS_PRECONDITION_REQUIRED, "Precondition Required"},
    {HTTP_STATUS_TOO_MANY_REQUESTS, "Too Many Requests"},
    {HTTP_STATUS_HEADER_TOO_LARGE, "Request Header Fields Too Large"},
    {HTTP_STATUS_UNAVAILABLE_LEGAL, "Unavailable For Legal Reasons"},

    {HTTP_STATUS_INTERNAL_ERROR, "Internal Server Error"},
    {HTTP_STATUS_NOT_IMPLEMENTED, "Not Implemented"},
    {HTTP_STATUS_BAD_GATEWAY, "Bad Gateway"},
    {HTTP_STATUS_SERVICE_UNAVAILABLE, "Service Unavailable"},
    {HTTP_STATUS_GATEWAY_TIMEOUT, "Gateway Timeout"},
    {HTTP_STATUS_VERSION_NOT_SUPPORTED, "HTTP Version Not Supported"},
    {HTTP_STATUS_VARIANT_ALSO_NEGOTIATES, "Variant Also Negotiates"},
    {HTTP_STATUS_INSUFFICIENT_STORAGE, "Insufficient Storage"},
    {HTTP_STATUS_LOOP_DETECTED, "Loop Detected"},
    {HTTP_STATUS_NOT_EXTENDED, "Not Extended"},
    {HTTP_STATUS_NETWORK_AUTH_REQUIRED, "Network Authentication Required"},

    {0, NULL}
};

const char *
SocketHTTP_status_reason (int code)
{
  if (code < HTTP_STATUS_CODE_MIN || code > HTTP_STATUS_CODE_MAX)
    {
      return "Unknown";
    }
  const char *reason = status_reasons[code - HTTP_STATUS_CODE_MIN];
  return reason ? reason : "Unknown";
}

/* Static initializer for status_reasons (compile-time) */
static void sockethttp_status_reasons_init (void)
    __attribute__ ((constructor));
static void
sockethttp_status_reasons_init (void)
{
  for (size_t i = 0; status_phrases_static[i].code != 0; i++) {
    int idx = status_phrases_static[i].code - HTTP_STATUS_CODE_MIN;
    if (idx >= 0 && idx < (int)(sizeof(status_reasons) / sizeof(status_reasons[0]))) {
      status_reasons[idx] = status_phrases_static[i].phrase;
    }
  }
}

SocketHTTP_StatusCategory
SocketHTTP_status_category (int code)
{
  if (code >= HTTP_STATUS_1XX_MIN && code <= HTTP_STATUS_1XX_MAX)
    return HTTP_STATUS_INFORMATIONAL;
  if (code >= HTTP_STATUS_2XX_MIN && code <= HTTP_STATUS_2XX_MAX)
    return HTTP_STATUS_SUCCESSFUL;
  if (code >= HTTP_STATUS_3XX_MIN && code <= HTTP_STATUS_3XX_MAX)
    return HTTP_STATUS_REDIRECTION;
  if (code >= HTTP_STATUS_4XX_MIN && code <= HTTP_STATUS_4XX_MAX)
    return HTTP_STATUS_CLIENT_ERROR;
  if (code >= HTTP_STATUS_5XX_MIN && code <= HTTP_STATUS_5XX_MAX)
    return HTTP_STATUS_SERVER_ERROR;
  return 0;
}

int
SocketHTTP_status_valid (int code)
{
  return code >= HTTP_STATUS_CODE_MIN && code <= HTTP_STATUS_CODE_MAX;
}

int
SocketHTTP_header_name_valid (const char *name, size_t len)
{
  if (!name)
    return 0;
  len = sockethttp_effective_length (name, len);
  if (len == 0 || len > SOCKETHTTP_MAX_HEADER_NAME)
    return 0;
  return sockethttp_is_token (name, len);
}

/* SECURITY: Rejects NUL/CR/LF to prevent header injection (CWE-113) */
int
SocketHTTP_header_value_valid (const char *value, size_t len)
{
  if (!value)
    return len == 0;
  len = sockethttp_effective_length (value, len);
  if (len > SOCKETHTTP_MAX_HEADER_VALUE)
    return 0;
  return sockethttp_header_value_is_safe (value, len);
}

static const struct ParseEntry coding_table[] = {
    {SOCKETHTTP_CODING_LEN_BR, "br", HTTP_CODING_BR, true},
    {SOCKETHTTP_CODING_LEN_GZIP, "gzip", HTTP_CODING_GZIP, true},
    {SOCKETHTTP_CODING_LEN_CHUNKED, "chunked", HTTP_CODING_CHUNKED, true},
    {SOCKETHTTP_CODING_LEN_DEFLATE, "deflate", HTTP_CODING_DEFLATE, true},
    {SOCKETHTTP_CODING_LEN_IDENTITY, "identity", HTTP_CODING_IDENTITY, true},
    {SOCKETHTTP_CODING_LEN_COMPRESS, "compress", HTTP_CODING_COMPRESS, true},
};

SocketHTTP_Coding
SocketHTTP_coding_parse (const char *name, size_t len)
{
  return (SocketHTTP_Coding)sockethttp_parse_enum(name, len, coding_table,
    sizeof(coding_table) / sizeof(coding_table[0]), HTTP_CODING_UNKNOWN);
}

const char *
SocketHTTP_coding_name (SocketHTTP_Coding coding)
{
  switch (coding)
    {
    case HTTP_CODING_IDENTITY:
      return "identity";
    case HTTP_CODING_CHUNKED:
      return "chunked";
    case HTTP_CODING_GZIP:
      return "gzip";
    case HTTP_CODING_DEFLATE:
      return "deflate";
    case HTTP_CODING_COMPRESS:
      return "compress";
    case HTTP_CODING_BR:
      return "br";
    default:
      return NULL;
    }
}
