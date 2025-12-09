/**
 * @file SocketHTTP.h
 * @ingroup http
 * @brief Protocol-agnostic HTTP types, header handling, URI parsing, and utilities.
 *
 * Provides protocol-agnostic HTTP types, header handling, URI parsing,
 * and date/media type utilities. Foundation for HTTP/1.1 and HTTP/2.
 *
 * Features:
 * - HTTP methods with semantic properties (safe, idempotent, cacheable)
 * - HTTP status codes with reason phrases and categories
 * - Header collection with O(1) case-insensitive lookup
 * - RFC 3986 URI parsing with percent-encoding support and syntax validation
 * - HTTP-date parsing (all 3 formats per RFC 9110)
 * - Media type parsing with token validation and escape handling
 * - Content negotiation (Accept header q-value parsing)
 *
 * Thread safety: All functions are thread-safe (no global state).
 * Header collections are not thread-safe; use external synchronization
 * if sharing across threads.
 *
 * Security notes:
 * - Rejects control characters and invalid syntax in URI components
 * - Validates host as reg-name or basic IPv6 literal
 * - Media types/parameters validated as HTTP tokens (RFC 7230)
 * - Per-component length limits prevent resource exhaustion
 * - Header names/values validated to reject injection attacks
 * - Integer overflow protection on all size calculations
 *
 * @see SocketHTTP_Method for HTTP methods.
 * @see SocketHTTP_Headers_T for header collections.
 * @see SocketHTTP_URI for URI parsing.
 */

#ifndef SOCKETHTTP_INCLUDED
#define SOCKETHTTP_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#include "core/Arena.h"
#include "core/Except.h"

/* ============================================================================
 * Configuration Limits
 * ============================================================================ */

/** Maximum header name length in bytes */
#ifndef SOCKETHTTP_MAX_HEADER_NAME
#define SOCKETHTTP_MAX_HEADER_NAME 256
#endif

/** Maximum header value length in bytes */
#ifndef SOCKETHTTP_MAX_HEADER_VALUE
#define SOCKETHTTP_MAX_HEADER_VALUE (8 * 1024)
#endif

/** Maximum total header size in bytes */
#ifndef SOCKETHTTP_MAX_HEADER_SIZE
#define SOCKETHTTP_MAX_HEADER_SIZE (64 * 1024)
#endif

/** Maximum header count */
#ifndef SOCKETHTTP_MAX_HEADERS
#define SOCKETHTTP_MAX_HEADERS 100
#endif

/** Maximum URI length in bytes */
#ifndef SOCKETHTTP_MAX_URI_LEN
#define SOCKETHTTP_MAX_URI_LEN (8 * 1024)
#endif

/** HTTP-date buffer size (30 bytes including null) */
#define SOCKETHTTP_DATE_BUFSIZE 30

/* ============================================================================
 * Exception Types
 * ============================================================================ */

/**
 * SocketHTTP_Failed - Generic HTTP module failure
 *
 * Use for general errors in HTTP core utilities. Specific errors should use
 * module exceptions like SocketHTTP1_ParseError for parsers.
 */
extern const Except_T SocketHTTP_Failed;


/* ============================================================================
 * HTTP Version
 * ============================================================================ */

/**
 * HTTP protocol versions
 */
typedef enum
{
  HTTP_VERSION_0_9 = 9,  /**< HTTP/0.9 (simple, no headers) */
  HTTP_VERSION_1_0 = 10, /**< HTTP/1.0 */
  HTTP_VERSION_1_1 = 11, /**< HTTP/1.1 */
  HTTP_VERSION_2 = 20,   /**< HTTP/2 */
  HTTP_VERSION_3 = 30    /**< HTTP/3 (future) */
} SocketHTTP_Version;

/**
 * SocketHTTP_version_string - Get version string
 * @version: HTTP version
 *
 * Returns: Static string like "HTTP/1.1", or "HTTP/?" for unknown
 * Thread-safe: Yes
 */
extern const char *SocketHTTP_version_string (SocketHTTP_Version version);

/**
 * SocketHTTP_version_parse - Parse version string
 * @str: Version string (e.g., "HTTP/1.1")
 * @len: String length (0 for strlen)
 *
 * Returns: HTTP version, or HTTP_VERSION_0_9 if unrecognized
 * Thread-safe: Yes
 */
extern SocketHTTP_Version SocketHTTP_version_parse (const char *str,
                                                    size_t len);

/* ============================================================================
 * HTTP Methods (RFC 9110 Section 9)
 * ============================================================================ */

/**
 * HTTP request methods
 */
typedef enum
{
  HTTP_METHOD_GET = 0,    /**< RFC 9110 Section 9.3.1 */
  HTTP_METHOD_HEAD,       /**< RFC 9110 Section 9.3.2 */
  HTTP_METHOD_POST,       /**< RFC 9110 Section 9.3.3 */
  HTTP_METHOD_PUT,        /**< RFC 9110 Section 9.3.4 */
  HTTP_METHOD_DELETE,     /**< RFC 9110 Section 9.3.5 */
  HTTP_METHOD_CONNECT,    /**< RFC 9110 Section 9.3.6 */
  HTTP_METHOD_OPTIONS,    /**< RFC 9110 Section 9.3.7 */
  HTTP_METHOD_TRACE,      /**< RFC 9110 Section 9.3.8 */
  HTTP_METHOD_PATCH,      /**< RFC 5789 */
  HTTP_METHOD_UNKNOWN = -1
} SocketHTTP_Method;

/**
 * Method semantic properties (RFC 9110 Section 9.2)
 */
typedef struct
{
  unsigned safe : 1;          /**< Does not modify resources */
  unsigned idempotent : 1;    /**< Multiple identical requests same as one */
  unsigned cacheable : 1;     /**< Response may be cached */
  unsigned has_body : 1;      /**< Request may have body */
  unsigned response_body : 1; /**< Response has body (except HEAD) */
} SocketHTTP_MethodProperties;

/**
 * SocketHTTP_method_name - Get method name string
 * @method: HTTP method
 *
 * Returns: Static string like "GET", or NULL for unknown
 * Thread-safe: Yes
 */
extern const char *SocketHTTP_method_name (SocketHTTP_Method method);

/**
 * SocketHTTP_method_parse - Parse method string
 * @str: Method string (e.g., "GET", "POST")
 * @len: String length (0 for strlen)
 *
 * Returns: HTTP method, or HTTP_METHOD_UNKNOWN if unrecognized
 * Thread-safe: Yes
 */
extern SocketHTTP_Method SocketHTTP_method_parse (const char *str, size_t len);

/**
 * SocketHTTP_method_properties - Get method semantic properties
 * @method: HTTP method
 *
 * Returns: Method properties structure
 * Thread-safe: Yes
 */
extern SocketHTTP_MethodProperties
SocketHTTP_method_properties (SocketHTTP_Method method);

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
extern int SocketHTTP_method_valid (const char *str, size_t len);

/* ============================================================================
 * HTTP Status Codes (RFC 9110 Section 15)
 * ============================================================================ */

/**
 * HTTP status codes
 */
typedef enum
{
  /* 1xx Informational */
  HTTP_STATUS_CONTINUE = 100,
  HTTP_STATUS_SWITCHING_PROTOCOLS = 101,
  HTTP_STATUS_PROCESSING = 102,  /**< RFC 2518 */
  HTTP_STATUS_EARLY_HINTS = 103, /**< RFC 8297 */

  /* 2xx Successful */
  HTTP_STATUS_OK = 200,
  HTTP_STATUS_CREATED = 201,
  HTTP_STATUS_ACCEPTED = 202,
  HTTP_STATUS_NON_AUTHORITATIVE = 203,
  HTTP_STATUS_NO_CONTENT = 204,
  HTTP_STATUS_RESET_CONTENT = 205,
  HTTP_STATUS_PARTIAL_CONTENT = 206,
  HTTP_STATUS_MULTI_STATUS = 207,      /**< RFC 4918 */
  HTTP_STATUS_ALREADY_REPORTED = 208,  /**< RFC 5842 */
  HTTP_STATUS_IM_USED = 226,           /**< RFC 3229 */

  /* 3xx Redirection */
  HTTP_STATUS_MULTIPLE_CHOICES = 300,
  HTTP_STATUS_MOVED_PERMANENTLY = 301,
  HTTP_STATUS_FOUND = 302,
  HTTP_STATUS_SEE_OTHER = 303,
  HTTP_STATUS_NOT_MODIFIED = 304,
  HTTP_STATUS_USE_PROXY = 305, /**< Deprecated */
  HTTP_STATUS_TEMPORARY_REDIRECT = 307,
  HTTP_STATUS_PERMANENT_REDIRECT = 308, /**< RFC 7538 */

  /* 4xx Client Error */
  HTTP_STATUS_BAD_REQUEST = 400,
  HTTP_STATUS_UNAUTHORIZED = 401,
  HTTP_STATUS_PAYMENT_REQUIRED = 402,
  HTTP_STATUS_FORBIDDEN = 403,
  HTTP_STATUS_NOT_FOUND = 404,
  HTTP_STATUS_METHOD_NOT_ALLOWED = 405,
  HTTP_STATUS_NOT_ACCEPTABLE = 406,
  HTTP_STATUS_PROXY_AUTH_REQUIRED = 407,
  HTTP_STATUS_REQUEST_TIMEOUT = 408,
  HTTP_STATUS_CONFLICT = 409,
  HTTP_STATUS_GONE = 410,
  HTTP_STATUS_LENGTH_REQUIRED = 411,
  HTTP_STATUS_PRECONDITION_FAILED = 412,
  HTTP_STATUS_CONTENT_TOO_LARGE = 413,
  HTTP_STATUS_URI_TOO_LONG = 414,
  HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE = 415,
  HTTP_STATUS_RANGE_NOT_SATISFIABLE = 416,
  HTTP_STATUS_EXPECTATION_FAILED = 417,
  HTTP_STATUS_IM_A_TEAPOT = 418,          /**< RFC 2324 */
  HTTP_STATUS_MISDIRECTED_REQUEST = 421,
  HTTP_STATUS_UNPROCESSABLE_CONTENT = 422,
  HTTP_STATUS_LOCKED = 423,               /**< RFC 4918 */
  HTTP_STATUS_FAILED_DEPENDENCY = 424,    /**< RFC 4918 */
  HTTP_STATUS_TOO_EARLY = 425,            /**< RFC 8470 */
  HTTP_STATUS_UPGRADE_REQUIRED = 426,
  HTTP_STATUS_PRECONDITION_REQUIRED = 428, /**< RFC 6585 */
  HTTP_STATUS_TOO_MANY_REQUESTS = 429,     /**< RFC 6585 */
  HTTP_STATUS_HEADER_TOO_LARGE = 431,      /**< RFC 6585 */
  HTTP_STATUS_UNAVAILABLE_LEGAL = 451,     /**< RFC 7725 */

  /* 5xx Server Error */
  HTTP_STATUS_INTERNAL_ERROR = 500,
  HTTP_STATUS_NOT_IMPLEMENTED = 501,
  HTTP_STATUS_BAD_GATEWAY = 502,
  HTTP_STATUS_SERVICE_UNAVAILABLE = 503,
  HTTP_STATUS_GATEWAY_TIMEOUT = 504,
  HTTP_STATUS_VERSION_NOT_SUPPORTED = 505,
  HTTP_STATUS_VARIANT_ALSO_NEGOTIATES = 506, /**< RFC 2295 */
  HTTP_STATUS_INSUFFICIENT_STORAGE = 507,    /**< RFC 4918 */
  HTTP_STATUS_LOOP_DETECTED = 508,           /**< RFC 5842 */
  HTTP_STATUS_NOT_EXTENDED = 510,            /**< RFC 2774 */
  HTTP_STATUS_NETWORK_AUTH_REQUIRED = 511    /**< RFC 6585 */
} SocketHTTP_StatusCode;


/**
 * Status code boundary constants
 *
 * Used for validation and categorization.
 * Note: Not all codes in range are defined in SocketHTTP_StatusCode enum;
 * enum only includes standard/common codes.
 */
#define HTTP_STATUS_CODE_MIN              100
#define HTTP_STATUS_CODE_MAX              599

#define HTTP_STATUS_1XX_MIN  HTTP_STATUS_CONTINUE
#define HTTP_STATUS_1XX_MAX               199

#define HTTP_STATUS_2XX_MIN  HTTP_STATUS_OK
#define HTTP_STATUS_2XX_MAX               299

#define HTTP_STATUS_3XX_MIN  HTTP_STATUS_MULTIPLE_CHOICES
#define HTTP_STATUS_3XX_MAX               399

#define HTTP_STATUS_4XX_MIN  HTTP_STATUS_BAD_REQUEST
#define HTTP_STATUS_4XX_MAX               499

#define HTTP_STATUS_5XX_MIN  HTTP_STATUS_INTERNAL_ERROR
#define HTTP_STATUS_5XX_MAX               599

/**
 * Status code categories
 */
typedef enum
{
  HTTP_STATUS_INFORMATIONAL = 1, /**< 1xx */
  HTTP_STATUS_SUCCESSFUL = 2,    /**< 2xx */
  HTTP_STATUS_REDIRECTION = 3,   /**< 3xx */
  HTTP_STATUS_CLIENT_ERROR = 4,  /**< 4xx */
  HTTP_STATUS_SERVER_ERROR = 5   /**< 5xx */
} SocketHTTP_StatusCategory;

/**
 * SocketHTTP_status_reason - Get reason phrase for status code
 * @code: HTTP status code
 *
 * Returns: Static reason phrase, or "Unknown" for unrecognized codes
 * Thread-safe: Yes
 */
extern const char *SocketHTTP_status_reason (int code);

/**
 * SocketHTTP_status_category - Get status code category
 * @code: HTTP status code
 *
 * Returns: Category (1-5), or 0 for invalid codes
 * Thread-safe: Yes
 */
extern SocketHTTP_StatusCategory SocketHTTP_status_category (int code);

/**
 * SocketHTTP_status_valid - Check if status code is valid
 * @code: HTTP status code
 *
 * Returns: 1 if code is 100-599, 0 otherwise
 * Thread-safe: Yes
 */
extern int SocketHTTP_status_valid (int code);

/* ============================================================================
 * HTTP Headers (RFC 9110 Section 5)
 * ============================================================================ */

/**
 * Single header field (for iteration)
 */
typedef struct
{
  const char *name;  /**< Header name (case-preserved) */
  size_t name_len;
  const char *value; /**< Header value */
  size_t value_len;
} SocketHTTP_Header;

/**
 * Header collection (opaque type)
 */
typedef struct SocketHTTP_Headers *SocketHTTP_Headers_T;

/**
 * SocketHTTP_Headers_new - Create new header collection
 * @arena: Arena for memory allocation
 *
 * Returns: New header collection, or NULL on allocation failure
 * Thread-safe: Yes (arena must be thread-safe or thread-local)
 */
extern SocketHTTP_Headers_T SocketHTTP_Headers_new (Arena_T arena);

/**
 * SocketHTTP_Headers_clear - Remove all headers
 * @headers: Header collection
 *
 * Clears all headers but keeps the collection usable.
 * Thread-safe: No (use external synchronization)
 */
extern void SocketHTTP_Headers_clear (SocketHTTP_Headers_T headers);

/**
 * SocketHTTP_Headers_add - Add header (null-terminated strings)
 * @headers: Header collection
 * @name: Header name
 * @value: Header value
 *
 * Adds header, allowing duplicates. Use set() to replace existing.
 *
 * Returns: 0 on success, -1 on error (invalid name/value, limits exceeded)
 * Thread-safe: No
 */
extern int SocketHTTP_Headers_add (SocketHTTP_Headers_T headers,
                                   const char *name, const char *value);

/**
 * SocketHTTP_Headers_add_n - Add header with explicit lengths
 * @headers: Header collection
 * @name: Header name
 * @name_len: Name length
 * @value: Header value
 * @value_len: Value length
 *
 * Returns: 0 on success, -1 on error
 * Thread-safe: No
 */
extern int SocketHTTP_Headers_add_n (SocketHTTP_Headers_T headers,
                                     const char *name, size_t name_len,
                                     const char *value, size_t value_len);

/**
 * SocketHTTP_Headers_set - Set header (replace if exists)
 * @headers: Header collection
 * @name: Header name
 * @value: Header value
 *
 * Removes all existing headers with same name, then adds new one.
 *
 * Returns: 0 on success, -1 on error
 * Thread-safe: No
 */
extern int SocketHTTP_Headers_set (SocketHTTP_Headers_T headers,
                                   const char *name, const char *value);

/**
 * SocketHTTP_Headers_get - Get first header value (case-insensitive)
 * @headers: Header collection
 * @name: Header name to find
 *
 * Returns: Header value (null-terminated), or NULL if not found
 * Thread-safe: No (value may be invalidated by modifications)
 */
extern const char *SocketHTTP_Headers_get (SocketHTTP_Headers_T headers,
                                           const char *name);

/**
 * SocketHTTP_Headers_get_int - Get header value as integer
 * @headers: Header collection
 * @name: Header name
 * @value: Output integer value
 *
 * Returns: 0 on success, -1 if not found or not a valid integer
 * Thread-safe: No
 */
extern int SocketHTTP_Headers_get_int (SocketHTTP_Headers_T headers,
                                       const char *name, int64_t *value);

/**
 * SocketHTTP_Headers_get_all - Get all values for header
 * @headers: Header collection
 * @name: Header name
 * @values: Output array of value pointers
 * @max_values: Maximum values to return
 *
 * Returns: Number of values found
 * Thread-safe: No
 */
extern size_t SocketHTTP_Headers_get_all (SocketHTTP_Headers_T headers,
                                          const char *name,
                                          const char **values,
                                          size_t max_values);

/**
 * SocketHTTP_Headers_has - Check if header exists
 * @headers: Header collection
 * @name: Header name
 *
 * Returns: 1 if exists, 0 otherwise
 * Thread-safe: No
 */
extern int SocketHTTP_Headers_has (SocketHTTP_Headers_T headers,
                                   const char *name);

/**
 * SocketHTTP_Headers_contains - Check if header contains token
 * @headers: Header collection
 * @name: Header name
 * @token: Token to search for (comma-separated list)
 *
 * Useful for headers like "Connection: keep-alive, upgrade"
 *
 * Returns: 1 if token found (case-insensitive), 0 otherwise
 * Thread-safe: No
 */
extern int SocketHTTP_Headers_contains (SocketHTTP_Headers_T headers,
                                        const char *name, const char *token);

/**
 * SocketHTTP_Headers_remove - Remove first header with name
 * @headers: Header collection
 * @name: Header name
 *
 * Returns: 1 if removed, 0 if not found
 * Thread-safe: No
 */
extern int SocketHTTP_Headers_remove (SocketHTTP_Headers_T headers,
                                      const char *name);

/**
 * SocketHTTP_Headers_remove_all - Remove all headers with name
 * @headers: Header collection
 * @name: Header name
 *
 * Returns: Number of headers removed
 * Thread-safe: No
 */
extern int SocketHTTP_Headers_remove_all (SocketHTTP_Headers_T headers,
                                          const char *name);

/**
 * SocketHTTP_Headers_count - Get total header count
 * @headers: Header collection
 *
 * Returns: Number of headers
 * Thread-safe: No
 */
extern size_t SocketHTTP_Headers_count (SocketHTTP_Headers_T headers);

/**
 * SocketHTTP_Headers_at - Get header by index
 * @headers: Header collection
 * @index: Header index (0-based)
 *
 * Returns: Pointer to header, or NULL if index out of range
 * Thread-safe: No
 */
extern const SocketHTTP_Header *
SocketHTTP_Headers_at (SocketHTTP_Headers_T headers, size_t index);

/**
 * Header iteration callback
 * Return non-zero to stop iteration
 */
typedef int (*SocketHTTP_HeaderCallback) (const char *name, size_t name_len,
                                          const char *value, size_t value_len,
                                          void *userdata);

/**
 * SocketHTTP_Headers_iterate - Iterate over all headers
 * @headers: Header collection
 * @callback: Callback function
 * @userdata: User data passed to callback
 *
 * Returns: 0 if completed, or value returned by callback that stopped iteration
 * Thread-safe: No
 */
extern int SocketHTTP_Headers_iterate (SocketHTTP_Headers_T headers,
                                       SocketHTTP_HeaderCallback callback,
                                       void *userdata);

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
extern int SocketHTTP_header_name_valid (const char *name, size_t len);

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
extern int SocketHTTP_header_value_valid (const char *value, size_t len);

/* ============================================================================
 * URI Parsing (RFC 3986)
 * ============================================================================ */

/**
 * Parsed URI components
 *
 * All string fields point into arena-allocated memory.
 * Strings are null-terminated for convenience.
 */
typedef struct
{
  const char *scheme;     /**< "http", "https", etc. (lowercase) */
  size_t scheme_len;
  const char *userinfo;   /**< username:password (deprecated, may be NULL) */
  size_t userinfo_len;
  const char *host;       /**< Hostname or IP (may be IPv6 in brackets) */
  size_t host_len;
  int port;               /**< Port number or -1 if not specified */
  const char *path;       /**< Path component (may be empty, not NULL) */
  size_t path_len;
  const char *query;      /**< Query string after ? (NULL if none) */
  size_t query_len;
  const char *fragment;   /**< Fragment after # (NULL if none) */
  size_t fragment_len;
} SocketHTTP_URI;

/**
 * URI parsing result codes
 */
typedef enum
{
  URI_PARSE_OK = 0,
  URI_PARSE_ERROR,           /**< Generic parse error */
  URI_PARSE_INVALID_SCHEME,  /**< Invalid scheme characters */
  URI_PARSE_INVALID_HOST,    /**< Invalid host (empty or bad chars) */
  URI_PARSE_INVALID_PORT,    /**< Port not a number or out of range */
  URI_PARSE_INVALID_PATH,    /**< Invalid path characters */
  URI_PARSE_INVALID_QUERY,   /**< Invalid query characters */
  URI_PARSE_TOO_LONG         /**< URI exceeds SOCKETHTTP_MAX_URI_LEN */
} SocketHTTP_URIResult;

/**
 * SocketHTTP_URI_parse - Parse URI
 * @uri: URI string
 * @len: URI length (0 for strlen)
 * @result: Output parsed URI structure
 * @arena: Arena for string allocations
 *
 * Parses absolute URI or relative reference per RFC 3986.
 * Handles IPv6 addresses in brackets.
 * Does NOT percent-decode components (use decode functions).
 *
 * Returns: URI_PARSE_OK on success, error code otherwise
 * Thread-safe: Yes (arena must be thread-safe or thread-local)
 */
extern SocketHTTP_URIResult SocketHTTP_URI_parse (const char *uri, size_t len,
                                                  SocketHTTP_URI *result,
                                                  Arena_T arena);

/**
 * SocketHTTP_URI_result_string - Get error description
 * @result: Parse result code
 *
 * Returns: Static string describing the result
 * Thread-safe: Yes
 */
extern const char *SocketHTTP_URI_result_string (SocketHTTP_URIResult result);

/**
 * SocketHTTP_URI_get_port - Get port with default fallback
 * @uri: Parsed URI
 * @default_port: Default port if not specified (e.g., 80 for http)
 *
 * Returns: Explicit port from URI, or default_port if uri->port == -1
 * Thread-safe: Yes
 */
extern int SocketHTTP_URI_get_port (const SocketHTTP_URI *uri, int default_port);

/**
 * SocketHTTP_URI_is_secure - Check if URI uses secure scheme
 * @uri: Parsed URI
 *
 * Returns: 1 if scheme is "https" or "wss", 0 otherwise
 * Thread-safe: Yes
 */
extern int SocketHTTP_URI_is_secure (const SocketHTTP_URI *uri);

/**
 * SocketHTTP_URI_encode - Percent-encode string
 * @input: Input string
 * @len: Input length
 * @output: Output buffer
 * @output_size: Output buffer size
 *
 * Encodes characters that are not unreserved per RFC 3986.
 * Unreserved: A-Z a-z 0-9 - . _ ~
 *
 * Returns: Output length (excluding null), or -1 if buffer too small
 * Thread-safe: Yes
 */
extern ssize_t SocketHTTP_URI_encode (const char *input, size_t len,
                                      char *output, size_t output_size);

/**
 * SocketHTTP_URI_decode - Percent-decode string
 * @input: Input string (may contain %XX sequences)
 * @len: Input length
 * @output: Output buffer
 * @output_size: Output buffer size
 *
 * Returns: Output length, or -1 on error (invalid encoding or buffer too small)
 * Thread-safe: Yes
 */
extern ssize_t SocketHTTP_URI_decode (const char *input, size_t len,
                                      char *output, size_t output_size);

/**
 * SocketHTTP_URI_build - Build URI string from components
 * @uri: URI components
 * @output: Output buffer
 * @output_size: Buffer size
 *
 * Builds: scheme://[userinfo@]host[:port]path[?query][#fragment]
 *
 * Returns: Length written (excluding null), or -1 if buffer too small
 * Thread-safe: Yes
 */
extern ssize_t SocketHTTP_URI_build (const SocketHTTP_URI *uri, char *output,
                                     size_t output_size);

/* ============================================================================
 * Date Parsing (RFC 9110 Section 5.6.7)
 * ============================================================================ */

/**
 * SocketHTTP_date_parse - Parse HTTP-date
 * @date_str: Date string in any valid HTTP-date format
 * @len: Length of string (0 for strlen)
 * @time_out: Output time_t (UTC)
 *
 * Accepts three formats per RFC 9110:
 * - IMF-fixdate: Sun, 06 Nov 1994 08:49:37 GMT (preferred)
 * - RFC 850: Sunday, 06-Nov-94 08:49:37 GMT (obsolete)
 * - ANSI C: Sun Nov  6 08:49:37 1994 (obsolete)
 *
 * Returns: 0 on success, -1 on error
 * Thread-safe: Yes
 */
extern int SocketHTTP_date_parse (const char *date_str, size_t len,
                                  time_t *time_out);

/**
 * SocketHTTP_date_format - Format time as HTTP-date (IMF-fixdate)
 * @t: Time to format (UTC)
 * @output: Output buffer (must be at least SOCKETHTTP_DATE_BUFSIZE bytes)
 *
 * Output format: "Sun, 06 Nov 1994 08:49:37 GMT"
 *
 * Returns: Length written (29), or -1 on error
 * Thread-safe: Yes
 */
extern int SocketHTTP_date_format (time_t t, char *output);

/* ============================================================================
 * Content Type Parsing (RFC 9110 Section 8.3)
 * ============================================================================ */

/**
 * Parsed media type
 */
typedef struct
{
  const char *type;       /**< "text", "application", etc. */
  size_t type_len;
  const char *subtype;    /**< "html", "json", etc. */
  size_t subtype_len;
  const char *charset;    /**< charset parameter value (NULL if not present) */
  size_t charset_len;
  const char *boundary;   /**< boundary parameter for multipart (NULL if not
                             present) */
  size_t boundary_len;
} SocketHTTP_MediaType;

/**
 * SocketHTTP_MediaType_parse - Parse Content-Type header
 * @value: Content-Type header value
 * @len: Length of value (0 for strlen)
 * @result: Output structure
 * @arena: Arena for parameter strings
 *
 * Parses: type/subtype[; param=value]*
 *
 * Returns: 0 on success, -1 on error
 * Thread-safe: Yes
 */
extern int SocketHTTP_MediaType_parse (const char *value, size_t len,
                                       SocketHTTP_MediaType *result,
                                       Arena_T arena);

/**
 * SocketHTTP_MediaType_matches - Check if media type matches pattern
 * @type: Parsed media type
 * @pattern: Pattern like "text/\*" or "application/json"
 *
 * Wildcard * matches any subtype.
 *
 * Returns: 1 if matches, 0 otherwise
 * Thread-safe: Yes
 */
extern int SocketHTTP_MediaType_matches (const SocketHTTP_MediaType *type,
                                         const char *pattern);

/* ============================================================================
 * Content Negotiation (RFC 9110 Section 12)
 * ============================================================================ */

/**
 * Quality value (q-value) from Accept headers
 */
typedef struct
{
  const char *value;   /**< Media type or other value */
  size_t value_len;
  float quality;       /**< 0.0 to 1.0, default 1.0 */
} SocketHTTP_QualityValue;

/**
 * SocketHTTP_parse_accept - Parse Accept-style header
 * @value: Header value
 * @len: Length (0 for strlen)
 * @results: Output array
 * @max_results: Maximum results to return
 * @arena: Arena for strings
 *
 * Parses comma-separated values with optional q= quality parameter.
 * Results sorted by quality (highest first).
 *
 * Returns: Number of results parsed
 * Thread-safe: Yes
 */
extern size_t SocketHTTP_parse_accept (const char *value, size_t len,
                                       SocketHTTP_QualityValue *results,
                                       size_t max_results, Arena_T arena);

/* ============================================================================
 * Transfer and Content Codings
 * ============================================================================ */

/**
 * Transfer/content encoding types
 */
typedef enum
{
  HTTP_CODING_IDENTITY = 0,
  HTTP_CODING_CHUNKED,
  HTTP_CODING_GZIP,
  HTTP_CODING_DEFLATE,
  HTTP_CODING_COMPRESS, /**< LZW - rarely used */
  HTTP_CODING_BR,       /**< Brotli (RFC 7932) */
  HTTP_CODING_UNKNOWN = -1
} SocketHTTP_Coding;

/**
 * SocketHTTP_coding_parse - Parse coding name
 * @name: Coding name string
 * @len: Name length (0 for strlen)
 *
 * Returns: Coding type, or HTTP_CODING_UNKNOWN
 * Thread-safe: Yes
 */
extern SocketHTTP_Coding SocketHTTP_coding_parse (const char *name, size_t len);

/**
 * SocketHTTP_coding_name - Get coding name string
 * @coding: Coding type
 *
 * Returns: Static string, or NULL for unknown
 * Thread-safe: Yes
 */
extern const char *SocketHTTP_coding_name (SocketHTTP_Coding coding);

/* ============================================================================
 * Request/Response Structures (Protocol-Agnostic)
 * ============================================================================ */

/**
 * HTTP Request (protocol-agnostic)
 *
 * This structure represents the semantics of an HTTP request,
 * independent of the wire format (HTTP/1.1 vs HTTP/2).
 */
typedef struct
{
  SocketHTTP_Method method;
  SocketHTTP_Version version;

  /* Request target (different forms per RFC 9112) */
  const char *scheme;     /**< "http" or "https" (for absolute-form) */
  const char *authority;  /**< host[:port] */
  const char *path;       /**< Path and query string */

  SocketHTTP_Headers_T headers;

  /* Body information */
  int has_body;
  int64_t content_length; /**< -1 if unknown/chunked */
} SocketHTTP_Request;

/**
 * HTTP Response (protocol-agnostic)
 */
typedef struct
{
  SocketHTTP_Version version;
  int status_code;
  const char *reason_phrase; /**< HTTP/1.x only, NULL for HTTP/2+ */

  SocketHTTP_Headers_T headers;

  /* Body information */
  int has_body;
  int64_t content_length; /**< -1 if unknown/chunked */
} SocketHTTP_Response;

#endif /* SOCKETHTTP_INCLUDED */

