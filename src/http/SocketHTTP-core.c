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

#include <string.h>

#include "http/SocketHTTP-private.h"
#include "http/SocketHTTP.h"

/* ============================================================================
 * String Length Constants for HTTP Parsing
 * ============================================================================
 *
 * Named constants for HTTP token lengths used in parsing to eliminate magic
 * numbers. These match the canonical string representations in RFC 9110.
 */

/** @brief Length of "HTTP/X.Y" version strings (e.g., "HTTP/1.1") */
#define SOCKETHTTP_VERSION_STR_LEN_FULL 8

/** @brief Length of "HTTP/N" version strings (e.g., "HTTP/2") */
#define SOCKETHTTP_VERSION_STR_LEN_SHORT 6

/** @brief Length of "GET" method string */
#define SOCKETHTTP_METHOD_LEN_GET 3

/** @brief Length of "PUT" method string */
#define SOCKETHTTP_METHOD_LEN_PUT 3

/** @brief Length of "HEAD" method string */
#define SOCKETHTTP_METHOD_LEN_HEAD 4

/** @brief Length of "POST" method string */
#define SOCKETHTTP_METHOD_LEN_POST 4

/** @brief Length of "TRACE" method string */
#define SOCKETHTTP_METHOD_LEN_TRACE 5

/** @brief Length of "PATCH" method string */
#define SOCKETHTTP_METHOD_LEN_PATCH 5

/** @brief Length of "DELETE" method string */
#define SOCKETHTTP_METHOD_LEN_DELETE 6

/** @brief Length of "CONNECT" method string */
#define SOCKETHTTP_METHOD_LEN_CONNECT 7

/** @brief Length of "OPTIONS" method string */
#define SOCKETHTTP_METHOD_LEN_OPTIONS 7

/** @brief Length of "identity" coding string */
#define SOCKETHTTP_CODING_LEN_IDENTITY 8

/** @brief Length of "chunked" coding string */
#define SOCKETHTTP_CODING_LEN_CHUNKED 7

/** @brief Length of "gzip" coding string */
#define SOCKETHTTP_CODING_LEN_GZIP 4

/** @brief Length of "deflate" coding string */
#define SOCKETHTTP_CODING_LEN_DEFLATE 7

/** @brief Length of "compress" coding string */
#define SOCKETHTTP_CODING_LEN_COMPRESS 8

/** @brief Length of "br" (Brotli) coding string */
#define SOCKETHTTP_CODING_LEN_BR 2

/* Status code boundaries defined in SocketHTTP.h */
/* ============================================================================
 * Exception Definitions
 * ============================================================================
 */

const Except_T SocketHTTP_Failed = { &SocketHTTP_Failed, "HTTP core failure" };

/**
 * @internal
 * @brief Exception for HTTP core parsing failures.
 */
const Except_T SocketHTTP_ParseError = { &SocketHTTP_Failed, "HTTP core parse error" };

/**
 * @internal
 * @brief Exception for invalid URI syntax or validation errors.
 */
const Except_T SocketHTTP_InvalidURI = { &SocketHTTP_Failed, "Invalid URI syntax" };

/**
 * @internal
 * @brief Exception for invalid HTTP header names or values.
 */
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

/**
 * Invalid hex digit marker value for sockethttp_hex_value table.
 * Values 0-15 are valid hex digits; 255 indicates non-hex character.
 */
#define SOCKETHTTP_HEX_INVALID 255

/** Shorthand for invalid hex in table initialization */
#define X SOCKETHTTP_HEX_INVALID

/**
 * Hex value table for percent decoding
 * Returns 0-15 for '0'-'9', 'a'-'f', 'A'-'F', or SOCKETHTTP_HEX_INVALID (255)
 */
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

/* Version lookup optimized to switch/if in functions */

/* ============================================================================
 * Helper Functions
 * ============================================================================
 */

/**
 * sockethttp_effective_length - Get effective string length
 *
 * @str: Input string (non-NULL)
 * @len: Provided length, or 0 to use strlen
 *
 * Returns: Length of the string
 * Thread-safe: Yes
 */
static size_t
sockethttp_effective_length (const char *str, size_t len)
{
  if (!str)
    return 0;
  if (len == 0)
    return strlen (str);
  /* When explicit length is provided, return it as-is to allow
   * detection of embedded NUL bytes in validation functions */
  return len;
}

/**
 * sockethttp_is_token - Validate token characters
 *
 * @s: String to validate
 * @len: Length of string
 *
 * Per RFC 9110 token definition.
 *
 * Returns: 1 if all characters are valid tchar, 0 otherwise
 * Thread-safe: Yes
 */
static int
sockethttp_is_token (const char *s, size_t len)
{
  for (size_t i = 0; i < len; i++)
    {
      if (!SOCKETHTTP_IS_TCHAR (s[i]))
        {
          return 0;
        }
    }
  return 1;
}

/**
 * sockethttp_header_value_is_safe - Check header value for injection chars
 *
 * @s: Header value string
 * @len: Length
 *
 * Rejects NUL, CR, LF to prevent header injection.
 *
 * Returns: 1 if safe, 0 otherwise
 * Thread-safe: Yes
 */
static int
sockethttp_header_value_is_safe (const char *s, size_t len)
{
  for (size_t i = 0; i < len; i++)
    {
      unsigned char c = (unsigned char)s[i];
      if (c == 0 || c == '\r' || c == '\n')
        {
          return 0;
        }
    }
  return 1;
}

/* ============================================================================
 * HTTP Version Functions
 * ============================================================================
 */

/**
 * SocketHTTP_version_string - Get version string
 * @version: HTTP version
 *
 * Returns: Static string like "HTTP/1.1", or "HTTP/?" for unknown
 * Thread-safe: Yes
 */
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

/**
 * SocketHTTP_version_parse - Parse version string
 * @str: Version string (e.g., "HTTP/1.1")
 * @len: String length (0 for strlen)
 *
 * Returns: HTTP version, or HTTP_VERSION_0_9 if unrecognized
 * Thread-safe: Yes
 */
SocketHTTP_Version
SocketHTTP_version_parse (const char *str, size_t len)
{
  if (!str)
    return HTTP_VERSION_0_9;
  len = sockethttp_effective_length (str, len);

  if (len == SOCKETHTTP_VERSION_STR_LEN_FULL)
    {
      if (memcmp (str, "HTTP/0.9", SOCKETHTTP_VERSION_STR_LEN_FULL) == 0)
        return HTTP_VERSION_0_9;
      if (memcmp (str, "HTTP/1.0", SOCKETHTTP_VERSION_STR_LEN_FULL) == 0)
        return HTTP_VERSION_1_0;
      if (memcmp (str, "HTTP/1.1", SOCKETHTTP_VERSION_STR_LEN_FULL) == 0)
        return HTTP_VERSION_1_1;
    }
  if (len == SOCKETHTTP_VERSION_STR_LEN_SHORT)
    {
      if (memcmp (str, "HTTP/2", SOCKETHTTP_VERSION_STR_LEN_SHORT) == 0)
        return HTTP_VERSION_2;
      if (memcmp (str, "HTTP/3", SOCKETHTTP_VERSION_STR_LEN_SHORT) == 0)
        return HTTP_VERSION_3;
    }
  return HTTP_VERSION_0_9;
}

/* ============================================================================
 * HTTP Method Functions
 * ============================================================================
 */

/* Method lookup optimized to direct memcmp/switch in functions */

/**
 * SocketHTTP_method_name - Get method name string
 * @method: HTTP method
 *
 * Returns: Static string like "GET", or NULL for unknown
 * Thread-safe: Yes
 */
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

/**
 * SocketHTTP_method_parse - Parse method string
 * @str: Method string (e.g., "GET", "POST")
 * @len: String length (0 for strlen)
 *
 * Returns: HTTP method, or HTTP_METHOD_UNKNOWN if unrecognized
 * Thread-safe: Yes
 */
SocketHTTP_Method
SocketHTTP_method_parse (const char *str, size_t len)
{
  if (!str)
    return HTTP_METHOD_UNKNOWN;
  len = sockethttp_effective_length (str, len);

  /* Case-sensitive match for standard methods (RFC 9110 requires uppercase) */
  switch (len)
    {
    case SOCKETHTTP_METHOD_LEN_GET: /* 3: GET, PUT */
      if (memcmp (str, "GET", SOCKETHTTP_METHOD_LEN_GET) == 0)
        return HTTP_METHOD_GET;
      if (memcmp (str, "PUT", SOCKETHTTP_METHOD_LEN_PUT) == 0)
        return HTTP_METHOD_PUT;
      break;

    case SOCKETHTTP_METHOD_LEN_HEAD: /* 4: HEAD, POST */
      if (memcmp (str, "HEAD", SOCKETHTTP_METHOD_LEN_HEAD) == 0)
        return HTTP_METHOD_HEAD;
      if (memcmp (str, "POST", SOCKETHTTP_METHOD_LEN_POST) == 0)
        return HTTP_METHOD_POST;
      break;

    case SOCKETHTTP_METHOD_LEN_TRACE: /* 5: TRACE, PATCH */
      if (memcmp (str, "TRACE", SOCKETHTTP_METHOD_LEN_TRACE) == 0)
        return HTTP_METHOD_TRACE;
      if (memcmp (str, "PATCH", SOCKETHTTP_METHOD_LEN_PATCH) == 0)
        return HTTP_METHOD_PATCH;
      break;

    case SOCKETHTTP_METHOD_LEN_DELETE: /* 6: DELETE */
      if (memcmp (str, "DELETE", SOCKETHTTP_METHOD_LEN_DELETE) == 0)
        return HTTP_METHOD_DELETE;
      break;

    case SOCKETHTTP_METHOD_LEN_CONNECT: /* 7: CONNECT, OPTIONS */
      if (memcmp (str, "CONNECT", SOCKETHTTP_METHOD_LEN_CONNECT) == 0)
        return HTTP_METHOD_CONNECT;
      if (memcmp (str, "OPTIONS", SOCKETHTTP_METHOD_LEN_OPTIONS) == 0)
        return HTTP_METHOD_OPTIONS;
      break;
    }

  return HTTP_METHOD_UNKNOWN;
}

/**
 * SocketHTTP_method_properties - Get method semantic properties
 * @method: HTTP method
 *
 * Returns: Method properties structure
 * Thread-safe: Yes
 */
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

/**
 * SocketHTTP_method_valid - Check if string is valid HTTP method token
 * @str: Method string
 * @len: String length
 *
 * Returns: 1 if valid token per RFC 9110, 0 otherwise
 * Thread-safe: Yes
 *
 * Valid token chars: !#$%&'*+-.0-9A-Z^_`a-z|~
 */
int
SocketHTTP_method_valid (const char *str, size_t len)
{
  if (!str)
    return 0;
  len = sockethttp_effective_length (str, len);
  if (len == 0)
    return 0;

  /* Per RFC 9110, method is a token */
  return sockethttp_is_token (str, len);
}

/* ============================================================================
 * HTTP Status Code Functions
 * ============================================================================
 */

/**
 * Status code reason phrases lookup table
 *
 * Indexed by (code - HTTP_STATUS_CODE_MIN). Size 500 for codes 100-599.
 * NULL entries for undefined codes.
 */
static const char
    *status_reasons[HTTP_STATUS_CODE_MAX - HTTP_STATUS_CODE_MIN + 1]
    = { NULL };

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
  status_reasons[HTTP_STATUS_CONTINUE - HTTP_STATUS_CODE_MIN] = "Continue";
  status_reasons[HTTP_STATUS_SWITCHING_PROTOCOLS - HTTP_STATUS_CODE_MIN]
      = "Switching Protocols";
  status_reasons[HTTP_STATUS_PROCESSING - HTTP_STATUS_CODE_MIN] = "Processing";
  status_reasons[HTTP_STATUS_EARLY_HINTS - HTTP_STATUS_CODE_MIN]
      = "Early Hints";

  status_reasons[HTTP_STATUS_OK - HTTP_STATUS_CODE_MIN] = "OK";
  status_reasons[HTTP_STATUS_CREATED - HTTP_STATUS_CODE_MIN] = "Created";
  status_reasons[HTTP_STATUS_ACCEPTED - HTTP_STATUS_CODE_MIN] = "Accepted";
  status_reasons[HTTP_STATUS_NON_AUTHORITATIVE - HTTP_STATUS_CODE_MIN]
      = "Non-Authoritative Information";
  status_reasons[HTTP_STATUS_NO_CONTENT - HTTP_STATUS_CODE_MIN] = "No Content";
  status_reasons[HTTP_STATUS_RESET_CONTENT - HTTP_STATUS_CODE_MIN]
      = "Reset Content";
  status_reasons[HTTP_STATUS_PARTIAL_CONTENT - HTTP_STATUS_CODE_MIN]
      = "Partial Content";
  status_reasons[HTTP_STATUS_MULTI_STATUS - HTTP_STATUS_CODE_MIN]
      = "Multi-Status";
  status_reasons[HTTP_STATUS_ALREADY_REPORTED - HTTP_STATUS_CODE_MIN]
      = "Already Reported";
  status_reasons[HTTP_STATUS_IM_USED - HTTP_STATUS_CODE_MIN] = "IM Used";

  status_reasons[HTTP_STATUS_MULTIPLE_CHOICES - HTTP_STATUS_CODE_MIN]
      = "Multiple Choices";
  status_reasons[HTTP_STATUS_MOVED_PERMANENTLY - HTTP_STATUS_CODE_MIN]
      = "Moved Permanently";
  status_reasons[HTTP_STATUS_FOUND - HTTP_STATUS_CODE_MIN] = "Found";
  status_reasons[HTTP_STATUS_SEE_OTHER - HTTP_STATUS_CODE_MIN] = "See Other";
  status_reasons[HTTP_STATUS_NOT_MODIFIED - HTTP_STATUS_CODE_MIN]
      = "Not Modified";
  status_reasons[HTTP_STATUS_USE_PROXY - HTTP_STATUS_CODE_MIN] = "Use Proxy";
  status_reasons[HTTP_STATUS_TEMPORARY_REDIRECT - HTTP_STATUS_CODE_MIN]
      = "Temporary Redirect";
  status_reasons[HTTP_STATUS_PERMANENT_REDIRECT - HTTP_STATUS_CODE_MIN]
      = "Permanent Redirect";

  status_reasons[HTTP_STATUS_BAD_REQUEST - HTTP_STATUS_CODE_MIN]
      = "Bad Request";
  status_reasons[HTTP_STATUS_UNAUTHORIZED - HTTP_STATUS_CODE_MIN]
      = "Unauthorized";
  status_reasons[HTTP_STATUS_PAYMENT_REQUIRED - HTTP_STATUS_CODE_MIN]
      = "Payment Required";
  status_reasons[HTTP_STATUS_FORBIDDEN - HTTP_STATUS_CODE_MIN] = "Forbidden";
  status_reasons[HTTP_STATUS_NOT_FOUND - HTTP_STATUS_CODE_MIN] = "Not Found";
  status_reasons[HTTP_STATUS_METHOD_NOT_ALLOWED - HTTP_STATUS_CODE_MIN]
      = "Method Not Allowed";
  status_reasons[HTTP_STATUS_NOT_ACCEPTABLE - HTTP_STATUS_CODE_MIN]
      = "Not Acceptable";
  status_reasons[HTTP_STATUS_PROXY_AUTH_REQUIRED - HTTP_STATUS_CODE_MIN]
      = "Proxy Authentication Required";
  status_reasons[HTTP_STATUS_REQUEST_TIMEOUT - HTTP_STATUS_CODE_MIN]
      = "Request Timeout";
  status_reasons[HTTP_STATUS_CONFLICT - HTTP_STATUS_CODE_MIN] = "Conflict";
  status_reasons[HTTP_STATUS_GONE - HTTP_STATUS_CODE_MIN] = "Gone";
  status_reasons[HTTP_STATUS_LENGTH_REQUIRED - HTTP_STATUS_CODE_MIN]
      = "Length Required";
  status_reasons[HTTP_STATUS_PRECONDITION_FAILED - HTTP_STATUS_CODE_MIN]
      = "Precondition Failed";
  status_reasons[HTTP_STATUS_CONTENT_TOO_LARGE - HTTP_STATUS_CODE_MIN]
      = "Content Too Large";
  status_reasons[HTTP_STATUS_URI_TOO_LONG - HTTP_STATUS_CODE_MIN]
      = "URI Too Long";
  status_reasons[HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE - HTTP_STATUS_CODE_MIN]
      = "Unsupported Media Type";
  status_reasons[HTTP_STATUS_RANGE_NOT_SATISFIABLE - HTTP_STATUS_CODE_MIN]
      = "Range Not Satisfiable";
  status_reasons[HTTP_STATUS_EXPECTATION_FAILED - HTTP_STATUS_CODE_MIN]
      = "Expectation Failed";
  status_reasons[HTTP_STATUS_IM_A_TEAPOT - HTTP_STATUS_CODE_MIN]
      = "I'm a Teapot";
  status_reasons[HTTP_STATUS_MISDIRECTED_REQUEST - HTTP_STATUS_CODE_MIN]
      = "Misdirected Request";
  status_reasons[HTTP_STATUS_UNPROCESSABLE_CONTENT - HTTP_STATUS_CODE_MIN]
      = "Unprocessable Content";
  status_reasons[HTTP_STATUS_LOCKED - HTTP_STATUS_CODE_MIN] = "Locked";
  status_reasons[HTTP_STATUS_FAILED_DEPENDENCY - HTTP_STATUS_CODE_MIN]
      = "Failed Dependency";
  status_reasons[HTTP_STATUS_TOO_EARLY - HTTP_STATUS_CODE_MIN] = "Too Early";
  status_reasons[HTTP_STATUS_UPGRADE_REQUIRED - HTTP_STATUS_CODE_MIN]
      = "Upgrade Required";
  status_reasons[HTTP_STATUS_PRECONDITION_REQUIRED - HTTP_STATUS_CODE_MIN]
      = "Precondition Required";
  status_reasons[HTTP_STATUS_TOO_MANY_REQUESTS - HTTP_STATUS_CODE_MIN]
      = "Too Many Requests";
  status_reasons[HTTP_STATUS_HEADER_TOO_LARGE - HTTP_STATUS_CODE_MIN]
      = "Request Header Fields Too Large";
  status_reasons[HTTP_STATUS_UNAVAILABLE_LEGAL - HTTP_STATUS_CODE_MIN]
      = "Unavailable For Legal Reasons";

  status_reasons[HTTP_STATUS_INTERNAL_ERROR - HTTP_STATUS_CODE_MIN]
      = "Internal Server Error";
  status_reasons[HTTP_STATUS_NOT_IMPLEMENTED - HTTP_STATUS_CODE_MIN]
      = "Not Implemented";
  status_reasons[HTTP_STATUS_BAD_GATEWAY - HTTP_STATUS_CODE_MIN]
      = "Bad Gateway";
  status_reasons[HTTP_STATUS_SERVICE_UNAVAILABLE - HTTP_STATUS_CODE_MIN]
      = "Service Unavailable";
  status_reasons[HTTP_STATUS_GATEWAY_TIMEOUT - HTTP_STATUS_CODE_MIN]
      = "Gateway Timeout";
  status_reasons[HTTP_STATUS_VERSION_NOT_SUPPORTED - HTTP_STATUS_CODE_MIN]
      = "HTTP Version Not Supported";
  status_reasons[HTTP_STATUS_VARIANT_ALSO_NEGOTIATES - HTTP_STATUS_CODE_MIN]
      = "Variant Also Negotiates";
  status_reasons[HTTP_STATUS_INSUFFICIENT_STORAGE - HTTP_STATUS_CODE_MIN]
      = "Insufficient Storage";
  status_reasons[HTTP_STATUS_LOOP_DETECTED - HTTP_STATUS_CODE_MIN]
      = "Loop Detected";
  status_reasons[HTTP_STATUS_NOT_EXTENDED - HTTP_STATUS_CODE_MIN]
      = "Not Extended";
  status_reasons[HTTP_STATUS_NETWORK_AUTH_REQUIRED - HTTP_STATUS_CODE_MIN]
      = "Network Authentication Required";
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
  return 0; /**< Invalid or unknown category */
}

int
SocketHTTP_status_valid (int code)
{
  return code >= HTTP_STATUS_CODE_MIN && code <= HTTP_STATUS_CODE_MAX;
  /**< Valid HTTP status codes are 100-599 per RFC 9110 */
}

/* ============================================================================
 * Header Validation Functions
 * ============================================================================
 */

/**
 * SocketHTTP_header_name_valid - Validate header name
 * @name: Header name
 * @len: Name length
 *
 * Per RFC 9110, header names are tokens (tchar characters only).
 *
 * Returns: 1 if valid, 0 otherwise
 * Thread-safe: Yes
 */
int
SocketHTTP_header_name_valid (const char *name, size_t len)
{
  if (!name)
    return 0;
  len = sockethttp_effective_length (name, len);
  if (len == 0 || len > SOCKETHTTP_MAX_HEADER_NAME)
    return 0;

  /* Header name must be a token per RFC 9110 */
  return sockethttp_is_token (name, len);
}

/**
 * SocketHTTP_header_value_valid - Validate header value
 * @value: Header value
 * @len: Value length
 *
 * SECURITY: Rejects NUL, CR, and LF characters to prevent HTTP header
 * injection attacks (CWE-113). Per RFC 9110 Section 5.5, obs-fold (CRLF
 * followed by SP/HTAB) is deprecated and should not be generated.
 *
 * This stricter validation prevents:
 * - CRLF injection for header manipulation
 * - Response splitting attacks
 * - Cache poisoning via injected headers
 * - Session hijacking via injected Set-Cookie
 *
 * Returns: 1 if valid (no NUL/CR/LF), 0 otherwise
 * Thread-safe: Yes
 */
int
SocketHTTP_header_value_valid (const char *value, size_t len)
{
  if (!value)
    return len == 0;
  len = sockethttp_effective_length (value, len);
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
  return sockethttp_header_value_is_safe (value, len);
}

/* ============================================================================
 * Transfer/Content Coding Functions
 * ============================================================================
 */

/**
 * SocketHTTP_coding_parse - Parse coding name
 * @name: Coding name string
 * @len: Name length (0 for strlen)
 *
 * Returns: Coding type, or HTTP_CODING_UNKNOWN
 * Thread-safe: Yes
 */
SocketHTTP_Coding
SocketHTTP_coding_parse (const char *name, size_t len)
{
  if (!name)
    return HTTP_CODING_UNKNOWN;
  len = sockethttp_effective_length (name, len);

  /* Case-insensitive match per RFC 9110 */
  switch (len)
    {
    case SOCKETHTTP_CODING_LEN_BR: /* 2: br */
      if (strncasecmp (name, "br", SOCKETHTTP_CODING_LEN_BR) == 0)
        return HTTP_CODING_BR;
      break;

    case SOCKETHTTP_CODING_LEN_GZIP: /* 4: gzip */
      if (strncasecmp (name, "gzip", SOCKETHTTP_CODING_LEN_GZIP) == 0)
        return HTTP_CODING_GZIP;
      break;

    case SOCKETHTTP_CODING_LEN_CHUNKED: /* 7: chunked, deflate */
      if (strncasecmp (name, "chunked", SOCKETHTTP_CODING_LEN_CHUNKED) == 0)
        return HTTP_CODING_CHUNKED;
      if (strncasecmp (name, "deflate", SOCKETHTTP_CODING_LEN_DEFLATE) == 0)
        return HTTP_CODING_DEFLATE;
      break;

    case SOCKETHTTP_CODING_LEN_IDENTITY: /* 8: identity, compress */
      if (strncasecmp (name, "identity", SOCKETHTTP_CODING_LEN_IDENTITY) == 0)
        return HTTP_CODING_IDENTITY;
      if (strncasecmp (name, "compress", SOCKETHTTP_CODING_LEN_COMPRESS) == 0)
        return HTTP_CODING_COMPRESS;
      break;
    }

  return HTTP_CODING_UNKNOWN;
}

/* Coding table no longer needed; optimized to direct strncasecmp checks */

/**
 * SocketHTTP_coding_name - Get coding name string
 * @coding: Coding type
 *
 * Returns: Static string, or NULL for unknown
 * Thread-safe: Yes
 */
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
