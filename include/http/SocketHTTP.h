/**
 * @defgroup http HTTP Modules
 * @brief Complete HTTP/1.1 and HTTP/2 protocol implementation with client and server support.
 *
 * The HTTP group provides comprehensive HTTP protocol support including
 * parsing, serialization, client/server implementations, and advanced
 * features. Key components include:
 * - SocketHTTP (core): HTTP types, headers, URI parsing, status codes (@ref http)
 * - SocketHTTP1: HTTP/1.1 parsing and serialization (@ref http1 "HTTP/1.1 Module")
 * - SocketHTTP2: HTTP/2 protocol implementation (@ref http2 "HTTP/2 Module")
 * - SocketHTTPClient: High-level HTTP client with pooling (@ref http_client "HTTP Client Module")
 * - SocketHTTPServer: HTTP server implementation (@ref http_server "HTTP Server Module")
 * - SocketHPACK: HTTP/2 header compression (@ref hpack "HPACK Module")
 *
 * @see foundation for base infrastructure.
 * @see core_io for socket primitives.
 * @see security for TLS integration.
 * @see SocketHTTPClient_T for HTTP client usage.
 * @see SocketHTTPServer_T for HTTP server implementation.
 * @{
 */

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
 * @see SocketHTTP1_T for HTTP/1.1 protocol implementation.
 * @see SocketHTTP2_T for HTTP/2 protocol implementation.
 * @see SocketHTTPClient_T for HTTP client functionality.
 * @see SocketHTTPServer_T for HTTP server functionality.
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
 * ============================================================================
 */

/**
 * @brief Maximum allowed length for HTTP header names, in bytes.
 * @ingroup http
 *
 * This configurable limit protects against denial-of-service attacks via excessively long
 * header names. The default value of 256 bytes is sufficient for all standard HTTP headers
 * (e.g., "Authorization", "Content-Type") and most custom headers.
 *
 * Redefine before including SocketHTTP.h to adjust for specific needs, but keep conservative
 * for security. Exceeding this during parsing raises SocketHTTP_Failed.
 *
 * @note Header names must also be valid tokens per RFC 9110 (tchar characters only).
 * @see SocketHTTP_header_name_valid() for validation function.
 * @see SocketHTTP_MAX_HEADER_VALUE for value length limits.
 * @see SocketHTTP_MAX_HEADER_SIZE for total headers limit.
 */
#ifndef SOCKETHTTP_MAX_HEADER_NAME
#define SOCKETHTTP_MAX_HEADER_NAME 256
#endif

/**
 * @brief Maximum allowed length for individual HTTP header values, in bytes.
 * @ingroup http
 *
 * Limits single header values to prevent memory exhaustion or buffer overflows.
 * Default 8 KiB accommodates large values like base64-encoded data in Authorization or cookies.
 * Larger values may indicate attacks; adjust cautiously.
 *
 * Exceeding this during addition or parsing triggers error or exception.
 *
 * @note Values are validated to exclude control characters (CR/LF/NUL) for security.
 * @see SocketHTTP_header_value_valid() for validation.
 * @see SocketHTTP_MAX_HEADER_NAME for name limits.
 * @see SocketHTTP_MAX_HEADERS for count limits.
 */
#ifndef SOCKETHTTP_MAX_HEADER_VALUE
#define SOCKETHTTP_MAX_HEADER_VALUE (8 * 1024)
#endif

/**
 * @brief Maximum total size for all HTTP headers combined, in bytes.
 * @ingroup http
 *
 * Cumulative limit on header block size to mitigate DoS from many/small headers or few/large ones.
 * Default 64 KiB is generous for typical requests but protects servers from abuse.
 * Used in parsing to prevent excessive memory use.
 *
 * @note Enforced in header collection; exceeding raises SocketHTTP_Failed in parsers.
 * @see SocketHTTP_Headers_count() for number of headers.
 * @see SocketHTTP_MAX_HEADERS for maximum count.
 */
#ifndef SOCKETHTTP_MAX_HEADER_SIZE
#define SOCKETHTTP_MAX_HEADER_SIZE (64 * 1024)
#endif

/**
 * @brief Maximum number of HTTP headers allowed in a collection.
 * @ingroup http
 *
 * Limits header count to prevent resource exhaustion from header flooding attacks.
 * Default 100 is ample for standard HTTP/1.1 and HTTP/2 requests.
 * Duplicate headers (e.g., multiple Set-Cookie) count separately.
 *
 * @note HTTP/2 has separate frame limits; this applies to logical header sets.
 * @see SocketHTTP_Headers_T for header collection.
 * @see SocketHTTP_MAX_HEADER_SIZE for total size limit.
 */
#ifndef SOCKETHTTP_MAX_HEADERS
#define SOCKETHTTP_MAX_HEADERS 100
#endif

/**
 * @brief Maximum length for URI strings during parsing, in bytes.
 * @ingroup http
 *
 * Prevents DoS from oversized URIs. Default 8 KiB covers complex queries and paths.
 * Enforced in SocketHTTP_URI_parse(); longer URIs raise URI_PARSE_TOO_LONG.
 *
 * @note Does not limit encoded size; decoded may be smaller.
 * @see SocketHTTP_URI_parse() for URI parsing.
 * @see SocketHTTP_URI_encode() and SocketHTTP_URI_decode() for percent handling.
 */
#ifndef SOCKETHTTP_MAX_URI_LEN
#define SOCKETHTTP_MAX_URI_LEN (8 * 1024)
#endif

/**
 * @brief Recommended buffer size for HTTP-date formatting output.
 * @ingroup http
 *
 * IMF-fixdate format requires 29 bytes + null terminator = 30 bytes.
 * Use this constant for stack-allocated buffers in SocketHTTP_date_format().
 *
 * @note Fixed size; all valid HTTP-dates fit within this.
 * @see SocketHTTP_date_format() for formatting time_t to HTTP-date string.
 * @see SocketHTTP_date_parse() for parsing HTTP-date strings.
 */
#define SOCKETHTTP_DATE_BUFSIZE 30

/* ============================================================================
 * Exception Types
 * ============================================================================
 */

/**
 * @brief SocketHTTP_Failed - Generic HTTP module failure.
 * @ingroup http
 *
 * Use for general errors in HTTP core utilities. Specific errors should use
 * module exceptions like SocketHTTP1_ParseError for parsers.
 */
extern const Except_T SocketHTTP_Failed;

/* ============================================================================
 * HTTP Version
 * ============================================================================
 */

 /**
  * @brief HTTP protocol versions supported by the library.
  * @ingroup http
  *
  * Enum values are major version * 10 + minor version for easy comparison (e.g., 11 for HTTP/1.1).
  * Supports HTTP/0.9 to HTTP/3 for compatibility and future-proofing.
  * @see SocketHTTP_version_string() to get the string representation (e.g., "HTTP/1.1").
  * @see SocketHTTP_version_parse() to parse version from string.
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
 * @brief Get version string.
 * @ingroup http
 * @param version HTTP version
 * @return Static string like "HTTP/1.1", or "HTTP/?" for unknown
 * @threadsafe Yes
 */
extern const char *SocketHTTP_version_string (SocketHTTP_Version version);

/**
 * @brief Parse version string.
 * @ingroup http
 * @param str Version string (e.g., "HTTP/1.1")
 * @param len String length (0 for strlen)
 * @return HTTP version, or HTTP_VERSION_0_9 if unrecognized
 * @threadsafe Yes
 */
extern SocketHTTP_Version SocketHTTP_version_parse (const char *str,
                                                    size_t len);

/* ============================================================================
 * HTTP Methods (RFC 9110 Section 9)
 * ============================================================================
 */

 /**
  * @brief Standard HTTP request methods as defined in RFC 9110 and extensions.
  * @ingroup http
  *
  * Includes all methods from RFC 9110 Section 9 plus PATCH (RFC 5789).
  * HTTP_METHOD_UNKNOWN indicates an unrecognized or custom method.
  * @see SocketHTTP_method_name() to get canonical string name.
  * @see SocketHTTP_method_parse() to parse method from request line.
  * @see SocketHTTP_method_properties() for semantic properties like safety and idempotency.
  * @see SocketHTTP_method_valid() to validate custom method tokens per RFC 9110 token rules.
  */
typedef enum
{
  HTTP_METHOD_GET = 0,     /**< RFC 9110 Section 9.3.1 - Safe, idempotent, cacheable; retrieves resource */
  HTTP_METHOD_HEAD,        /**< RFC 9110 Section 9.3.2 - Like GET but response has no body; used for metadata */
  HTTP_METHOD_POST,        /**< RFC 9110 Section 9.3.3 - Not safe or idempotent; creates/submits data */
  HTTP_METHOD_PUT,         /**< RFC 9110 Section 9.3.4 - Idempotent; creates or replaces resource at URI */
  HTTP_METHOD_DELETE,      /**< RFC 9110 Section 9.3.5 - Idempotent; requests deletion of resource */
  HTTP_METHOD_CONNECT,     /**< RFC 9110 Section 9.3.6 - Establishes tunnel to target host; used by proxies */
  HTTP_METHOD_OPTIONS,     /**< RFC 9110 Section 9.3.7 - Safe; describes communication options for target resource */
  HTTP_METHOD_TRACE,       /**< RFC 9110 Section 9.3.8 - Safe, idempotent; performs test loop-back for diagnostics */
  HTTP_METHOD_PATCH,       /**< RFC 5789 - Applies partial modifications to resource; not always idempotent */
  HTTP_METHOD_UNKNOWN = -1 /**< Unrecognized or extension method */
} SocketHTTP_Method;

/**
 * @brief Semantic properties of an HTTP method as defined in RFC 9110 Section 9.2.
 * @ingroup http
 *
 * Bit fields indicating method safety, idempotency, cacheability, and body expectations.
 * Used for request validation, caching decisions, and protocol compliance.
 * @see SocketHTTP_method_properties() to retrieve properties for a method.
 */
typedef struct
{
  unsigned safe : 1;          /**< 1 if method is safe (does not modify server resources) */
  unsigned idempotent : 1;    /**< 1 if multiple identical requests have same effect as one */
  unsigned cacheable : 1;     /**< 1 if response to successful request is cacheable */
  unsigned has_body : 1;      /**< 1 if request is allowed to have a body */
  unsigned response_body : 1; /**< 1 if successful response includes a body (except for HEAD) */
} SocketHTTP_MethodProperties;

/**
 * @brief Get method name string.
 * @ingroup http
 * @param method HTTP method
 * @return Static string like "GET", or NULL for unknown
 * @threadsafe Yes
 */
extern const char *SocketHTTP_method_name (SocketHTTP_Method method);

/**
 * @brief Parse method string.
 * @ingroup http
 * @param str Method string (e.g., "GET", "POST")
 * @param len String length (0 for strlen)
 * @return HTTP method, or HTTP_METHOD_UNKNOWN if unrecognized
 * @threadsafe Yes
 */
extern SocketHTTP_Method SocketHTTP_method_parse (const char *str, size_t len);

/**
 * @brief Get method semantic properties.
 * @ingroup http
 * @param method HTTP method
 * @return Method properties structure
 * @threadsafe Yes
 */
extern SocketHTTP_MethodProperties
SocketHTTP_method_properties (SocketHTTP_Method method);

/**
 * @brief Check if string is valid HTTP method token.
 * @ingroup http
 * @param str Method string
 * @param len String length
 * @return 1 if valid token per RFC 9110, 0 otherwise
 * @threadsafe Yes
 *
 * Valid token chars: !#$%&'*+-.0-9A-Z^_`a-z|~
 */
extern int SocketHTTP_method_valid (const char *str, size_t len);

/* ============================================================================
 * HTTP Status Codes (RFC 9110 Section 15)
 * ============================================================================
 */

/**
 * @brief HTTP status codes as defined in RFC 9110 Section 15 and common extensions.
 * @ingroup http
 *
 * Includes standard 1xx-5xx codes plus WebDAV (RFC 4918), HTTP/2 extensions, and others.
 * Use SocketHTTP_status_valid() to check range, SocketHTTP_status_category() for class,
 * and SocketHTTP_status_reason() for reason phrase.
 * @see SocketHTTP_status_reason() to get standardized reason phrase.
 * @see SocketHTTP_status_category() to get category (1-5).
 * @see SocketHTTP_status_valid() to validate code is in 100-599 range.
 */
typedef enum
{
  /* 1xx Informational - Request received, continuing process */
  HTTP_STATUS_CONTINUE = 100,               /**< Continue with request */
  HTTP_STATUS_SWITCHING_PROTOCOLS = 101,    /**< Server agrees to upgrade protocol */
  HTTP_STATUS_PROCESSING = 102,             /**< RFC 2518 WebDAV - Processing request */
  HTTP_STATUS_EARLY_HINTS = 103,            /**< RFC 8297 - Early hints for resource links */

  /* 2xx Successful - Request successful */
  HTTP_STATUS_OK = 200,                     /**< Standard success */
  HTTP_STATUS_CREATED = 201,                /**< Resource created */
  HTTP_STATUS_ACCEPTED = 202,               /**< Accepted for processing */
  HTTP_STATUS_NON_AUTHORITATIVE = 203,      /**< Non-authoritative information */
  HTTP_STATUS_NO_CONTENT = 204,             /**< Success, no content */
  HTTP_STATUS_RESET_CONTENT = 205,          /**< Reset content (user agent refresh) */
  HTTP_STATUS_PARTIAL_CONTENT = 206,        /**< Partial content (range request) */
  HTTP_STATUS_MULTI_STATUS = 207,           /**< RFC 4918 WebDAV - Multiple statuses */
  HTTP_STATUS_ALREADY_REPORTED = 208,       /**< RFC 5842 WebDAV - Avoid infinite loops */
  HTTP_STATUS_IM_USED = 226,                /**< RFC 3229 Delta encoding - Instance manipulated */

  /* 3xx Redirection - Further action needed */
  HTTP_STATUS_MULTIPLE_CHOICES = 300,       /**< Multiple resource representations */
  HTTP_STATUS_MOVED_PERMANENTLY = 301,      /**< Permanent redirect */
  HTTP_STATUS_FOUND = 302,                  /**< Temporary redirect */
  HTTP_STATUS_SEE_OTHER = 303,              /**< See other location */
  HTTP_STATUS_NOT_MODIFIED = 304,           /**< Not modified (conditional request) */
  HTTP_STATUS_USE_PROXY = 305,              /**< Deprecated - Use proxy (absolute URI) */
  HTTP_STATUS_TEMPORARY_REDIRECT = 307,     /**< Temporary redirect, preserve method */
  HTTP_STATUS_PERMANENT_REDIRECT = 308,     /**< RFC 7238 - Permanent redirect, preserve method */

  /* 4xx Client Error - Client error */
  HTTP_STATUS_BAD_REQUEST = 400,            /**< Invalid request syntax */
  HTTP_STATUS_UNAUTHORIZED = 401,           /**< Authentication required */
  HTTP_STATUS_PAYMENT_REQUIRED = 402,       /**< Payment required (reserved) */
  HTTP_STATUS_FORBIDDEN = 403,              /**< Forbidden */
  HTTP_STATUS_NOT_FOUND = 404,              /**< Resource not found */
  HTTP_STATUS_METHOD_NOT_ALLOWED = 405,     /**< Method not allowed for resource */
  HTTP_STATUS_NOT_ACCEPTABLE = 406,         /**< No acceptable representation */
  HTTP_STATUS_PROXY_AUTH_REQUIRED = 407,    /**< Proxy authentication required */
  HTTP_STATUS_REQUEST_TIMEOUT = 408,        /**< Request timeout */
  HTTP_STATUS_CONFLICT = 409,               /**< Resource conflict */
  HTTP_STATUS_GONE = 410,                   /**< Resource permanently gone */
  HTTP_STATUS_LENGTH_REQUIRED = 411,        /**< Content-Length required */
  HTTP_STATUS_PRECONDITION_FAILED = 412,    /**< Precondition failed */
  HTTP_STATUS_CONTENT_TOO_LARGE = 413,      /**< Payload too large */
  HTTP_STATUS_URI_TOO_LONG = 414,           /**< URI too long */
  HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE = 415, /**< Unsupported media type */
  HTTP_STATUS_RANGE_NOT_SATISFIABLE = 416,  /**< Range not satisfiable */
  HTTP_STATUS_EXPECTATION_FAILED = 417,     /**< Expectation failed */
  HTTP_STATUS_IM_A_TEAPOT = 418,            /**< RFC 2324 - I'm a teapot (humorous) */
  HTTP_STATUS_MISDIRECTED_REQUEST = 421,    /**< Mis-directed request (HTTP/2+) */
  HTTP_STATUS_UNPROCESSABLE_CONTENT = 422,  /**< Unprocessable entity (WebDAV) */
  HTTP_STATUS_LOCKED = 423,                 /**< RFC 4918 WebDAV - Resource locked */
  HTTP_STATUS_FAILED_DEPENDENCY = 424,      /**< RFC 4918 WebDAV - Dependency failed */
  HTTP_STATUS_TOO_EARLY = 425,              /**< RFC 8470 - Too early (anti-replay) */
  HTTP_STATUS_UPGRADE_REQUIRED = 426,       /**< Upgrade required (e.g., TLS) */
  HTTP_STATUS_PRECONDITION_REQUIRED = 428,  /**< RFC 6585 - Precondition required */
  HTTP_STATUS_TOO_MANY_REQUESTS = 429,      /**< RFC 6585 - Rate limiting */
  HTTP_STATUS_HEADER_TOO_LARGE = 431,       /**< RFC 6585 - Header fields too large */
  HTTP_STATUS_UNAVAILABLE_LEGAL = 451,      /**< RFC 7725 - Unavailable for legal reasons */

  /* 5xx Server Error - Server failure */
  HTTP_STATUS_INTERNAL_ERROR = 500,         /**< Internal server error */
  HTTP_STATUS_NOT_IMPLEMENTED = 501,        /**< Not implemented */
  HTTP_STATUS_BAD_GATEWAY = 502,            /**< Bad gateway */
  HTTP_STATUS_SERVICE_UNAVAILABLE = 503,    /**< Service unavailable (maintenance) */
  HTTP_STATUS_GATEWAY_TIMEOUT = 504,        /**< Gateway timeout */
  HTTP_STATUS_VERSION_NOT_SUPPORTED = 505,  /**< HTTP version not supported */
  HTTP_STATUS_VARIANT_ALSO_NEGOTIATES = 506, /**< RFC 2295 - Variant also negotiates */
  HTTP_STATUS_INSUFFICIENT_STORAGE = 507,   /**< RFC 4918 WebDAV - Insufficient storage */
  HTTP_STATUS_LOOP_DETECTED = 508,          /**< RFC 5842 WebDAV - Loop detected */
  HTTP_STATUS_NOT_EXTENDED = 510,           /**< RFC 2774 - Not extended */
  HTTP_STATUS_NETWORK_AUTH_REQUIRED = 511   /**< RFC 6585 - Network authentication required */
} SocketHTTP_StatusCode;

/**
 * @brief Boundary constants for HTTP status code validation and categorization.
 * @ingroup http
 *
 * These defines provide ranges for status code classes (1xx-5xx) and overall valid range (100-599).
 * Used in SocketHTTP_status_valid(), SocketHTTP_status_category(), and internal checks.
 * The SocketHTTP_StatusCode enum defines specific codes; these are for range checks.
 *
 * @note Not all codes in 100-599 are standardized; custom codes should use valid range.
 * @see SocketHTTP_status_valid() to check if a code is in valid range.
 * @see SocketHTTP_status_category() to get category (1-5).
 * @see SocketHTTP_StatusCode for enumerated status codes.
 */

/**
 * @brief Minimum valid HTTP status code.
 * @ingroup http
 * @note Codes below 100 are informational or invalid per RFC 9110.
 */
#define HTTP_STATUS_CODE_MIN 100

/**
 * @brief Maximum valid HTTP status code.
 * @ingroup http
 * @note Codes above 599 are not standard; extensions may use higher but library limits to 599.
 */
#define HTTP_STATUS_CODE_MAX 599

/**
 * @brief Minimum 1xx informational status code.
 * @ingroup http
 */
#define HTTP_STATUS_1XX_MIN HTTP_STATUS_CONTINUE

/**
 * @brief Maximum 1xx informational status code.
 * @ingroup http
 */
#define HTTP_STATUS_1XX_MAX 199

/**
 * @brief Minimum 2xx successful status code.
 * @ingroup http
 */
#define HTTP_STATUS_2XX_MIN HTTP_STATUS_OK

/**
 * @brief Maximum 2xx successful status code.
 * @ingroup http
 */
#define HTTP_STATUS_2XX_MAX 299

/**
 * @brief Minimum 3xx redirection status code.
 * @ingroup http
 */
#define HTTP_STATUS_3XX_MIN HTTP_STATUS_MULTIPLE_CHOICES

/**
 * @brief Maximum 3xx redirection status code.
 * @ingroup http
 */
#define HTTP_STATUS_3XX_MAX 399

/**
 * @brief Minimum 4xx client error status code.
 * @ingroup http
 */
#define HTTP_STATUS_4XX_MIN HTTP_STATUS_BAD_REQUEST

/**
 * @brief Maximum 4xx client error status code.
 * @ingroup http
 */
#define HTTP_STATUS_4XX_MAX 499

/**
 * @brief Minimum 5xx server error status code.
 * @ingroup http
 */
#define HTTP_STATUS_5XX_MIN HTTP_STATUS_INTERNAL_ERROR

/**
 * @brief Maximum 5xx server error status code.
 * @ingroup http
 * @note Extends to 599 for future standard codes.
 */
#define HTTP_STATUS_5XX_MAX 599

/**
 * @brief Categories of HTTP status codes for quick classification.
 * @ingroup http
 *
 * Maps to first digit of status code (1-5).
 * Used for error handling, logging, and conditional logic.
 * @see SocketHTTP_status_category() to get category from code.
 */
typedef enum
{
  HTTP_STATUS_INFORMATIONAL = 1, /**< 1xx - Informational responses */
  HTTP_STATUS_SUCCESSFUL = 2,    /**< 2xx - Success responses */
  HTTP_STATUS_REDIRECTION = 3,   /**< 3xx - Redirection responses */
  HTTP_STATUS_CLIENT_ERROR = 4,  /**< 4xx - Client errors */
  HTTP_STATUS_SERVER_ERROR = 5   /**< 5xx - Server errors */
} SocketHTTP_StatusCategory;

/**
 * @brief Get reason phrase for status code.
 * @ingroup http
 * @param code HTTP status code
 * @return Static reason phrase, or "Unknown" for unrecognized codes
 * @threadsafe Yes
 */
extern const char *SocketHTTP_status_reason (int code);

/**
 * @brief Get status code category.
 * @ingroup http
 * @param code HTTP status code
 * @return Category (1-5), or 0 for invalid codes
 * @threadsafe Yes
 */
extern SocketHTTP_StatusCategory SocketHTTP_status_category (int code);

/**
 * @brief Check if status code is valid.
 * @ingroup http
 * @param code HTTP status code
 * @return 1 if code is 100-599, 0 otherwise
 * @threadsafe Yes
 */
extern int SocketHTTP_status_valid (int code);

/* ============================================================================
 * HTTP Headers (RFC 9110 Section 5)
 * ============================================================================
 */

/**
 * Single header field (for iteration)
 */
/**
 * @brief Single HTTP header field representation for iteration and access.
 * @ingroup http
 *
 * Used by functions like SocketHTTP_Headers_at() and SocketHTTP_Headers_iterate()
 * to provide access to individual headers without copying.
 * Name is case-preserved as received/sent; lookup is case-insensitive.
 * @see SocketHTTP_Headers_at() to get header by index.
 * @see SocketHTTP_Headers_iterate() for callback-based iteration.
 */
typedef struct
{
  const char *name;     /**< Header name (case-preserved, null-terminated) */
  size_t name_len;      /**< Length of name (excluding null) */
  const char *value;    /**< Header value (null-terminated; may be empty) */
  size_t value_len;     /**< Length of value (excluding null) */
} SocketHTTP_Header;

/**
 * @brief Opaque type for HTTP header collection with efficient operations.
 * @ingroup http
 *
 * Manages a dynamic collection of HTTP headers with O(1) case-insensitive lookup using hash table.
 * Memory allocated from provided arena; lifetime tied to arena.
 * Supports duplicates, iteration, and validation against HTTP limits.
 * Thread-unsafe; synchronize externally if shared across threads.
 * @see SocketHTTP_Headers_new() to create a new collection.
 * @see SocketHTTP_Headers_add() to add headers.
 * @see SocketHTTP_Headers_get() for lookup.
 * @see SocketHTTP_Headers_clear() to remove all headers without freeing collection.
 */
typedef struct SocketHTTP_Headers *SocketHTTP_Headers_T;

/**
 * @brief Create a new empty HTTP header collection.
 * @ingroup http
 * @param arena Arena used for all internal allocations; must outlive the collection.
 * @return New header collection instance.
 * @throws Arena_Failed if memory allocation fails (insufficient space in arena).
 * @throws SocketHTTP_Failed if arena is NULL or internal initialization fails.
 * @threadsafe Yes, provided the arena is thread-safe or thread-local.
 * @note All headers added to this collection will allocate from the provided arena.
 * @see SocketHTTP_Headers_clear() to reuse the collection after clearing.
 * @see SocketHTTP_Headers_add() to populate with headers.
 */
extern SocketHTTP_Headers_T SocketHTTP_Headers_new (Arena_T arena);

/**
 * @brief Remove all headers.
 * @ingroup http
 * @param headers Header collection
 *
 * Clears all headers but keeps the collection usable.
 * @threadsafe No (use external synchronization)
 */
extern void SocketHTTP_Headers_clear (SocketHTTP_Headers_T headers);

/**
 * @brief Add header (null-terminated strings).
 * @ingroup http
 * @param headers Header collection
 * @param name Header name
 * @param value Header value
 * @return 0 on success, -1 on error (invalid name/value, limits exceeded)
 * @threadsafe No
 *
 * Adds header, allowing duplicates. Use set() to replace existing.
 */
extern int SocketHTTP_Headers_add (SocketHTTP_Headers_T headers,
                                   const char *name, const char *value);

/**
 * @brief Add header with explicit lengths.
 * @ingroup http
 * @param headers Header collection
 * @param name Header name
 * @param name_len Name length
 * @param value Header value
 * @param value_len Value length
 * @return 0 on success, -1 on error
 * @threadsafe No
 */
extern int SocketHTTP_Headers_add_n (SocketHTTP_Headers_T headers,
                                     const char *name, size_t name_len,
                                     const char *value, size_t value_len);

/**
 * @brief Set header (replace if exists).
 * @ingroup http
 * @param headers Header collection
 * @param name Header name
 * @param value Header value
 * @return 0 on success, -1 on error
 * @threadsafe No
 *
 * Removes all existing headers with same name, then adds new one.
 */
extern int SocketHTTP_Headers_set (SocketHTTP_Headers_T headers,
                                   const char *name, const char *value);

/**
 * @brief Get first header value (case-insensitive).
 * @ingroup http
 * @param headers Header collection
 * @param name Header name to find
 * @return Header value (null-terminated), or NULL if not found
 * @threadsafe No (value may be invalidated by modifications)
 */
extern const char *SocketHTTP_Headers_get (SocketHTTP_Headers_T headers,
                                           const char *name);

/**
 * @brief Get header value as integer
 * @ingroup http
 * @param headers Header collection
 * @param name Header name
 * @param value Output integer value
 * @return 0 on success, -1 if not found or not a valid integer
 * @threadsafe No
 */
extern int SocketHTTP_Headers_get_int (SocketHTTP_Headers_T headers,
                                       const char *name, int64_t *value);

/**
 * @brief Get all values for header
 * @ingroup http
 * @param headers Header collection
 * @param name Header name
 * @param values Output array of value pointers
 * @param max_values Maximum values to return
 * @return Number of values found
 * @threadsafe No
 */
extern size_t SocketHTTP_Headers_get_all (SocketHTTP_Headers_T headers,
                                          const char *name,
                                          const char **values,
                                          size_t max_values);

/**
 * @brief Check if header exists
 * @ingroup http
 * @param headers Header collection
 * @param name Header name
 * @return 1 if exists, 0 otherwise
 * @threadsafe No
 */
extern int SocketHTTP_Headers_has (SocketHTTP_Headers_T headers,
                                   const char *name);

/**
 * @brief Check if header contains token
 * @ingroup http
 * @param headers Header collection
 * @param name Header name
 * @param token Token to search for (comma-separated list)
 * @return 1 if token found (case-insensitive), 0 otherwise
 * @threadsafe No
 *
 * Useful for headers like "Connection: keep-alive, upgrade"
 */
extern int SocketHTTP_Headers_contains (SocketHTTP_Headers_T headers,
                                        const char *name, const char *token);

/**
 * @brief Remove first header with name
 * @ingroup http
 * @param headers Header collection
 * @param name Header name
 * @return 1 if removed, 0 if not found
 * @threadsafe No
 */
extern int SocketHTTP_Headers_remove (SocketHTTP_Headers_T headers,
                                      const char *name);

/**
 * @brief Remove all headers with name
 * @ingroup http
 * @param headers Header collection
 * @param name Header name
 * @return Number of headers removed
 * @threadsafe No
 */
extern int SocketHTTP_Headers_remove_all (SocketHTTP_Headers_T headers,
                                          const char *name);

/**
 * @brief Get total header count
 * @ingroup http
 * @param headers Header collection
 * @return Number of headers
 * @threadsafe No
 */
extern size_t SocketHTTP_Headers_count (SocketHTTP_Headers_T headers);

/**
 * @brief Get header by index
 * @ingroup http
 * @param headers Header collection
 * @param index Header index (0-based)
 * @return Pointer to header, or NULL if index out of range
 * @threadsafe No
 */
extern const SocketHTTP_Header *
SocketHTTP_Headers_at (SocketHTTP_Headers_T headers, size_t index);

/**
 * @brief Callback function for iterating over HTTP headers in SocketHTTP_Headers_iterate().
 * @ingroup http
 *
 * Invoked for each header in the collection. Parameters provide name/value with lengths for efficiency.
 * Case-insensitive name matching via hash table in collection.
 *
 * @param name Header name (null-terminated string, case-preserved).
 * @param name_len Length of name (excluding null).
 * @param value Header value (null-terminated, may be empty string).
 * @param value_len Length of value (excluding null).
 * @param userdata User data passed from SocketHTTP_Headers_iterate().
 * @return 0 to continue iteration, non-zero to stop early.
 * @threadsafe No - called from caller context.
 *
 * @note Callback should not modify collection; undefined behavior.
 * @see SocketHTTP_Headers_iterate() for usage.
 * @see SocketHTTP_Header for structure with name/value.
 */
typedef int (*SocketHTTP_HeaderCallback) (const char *name, size_t name_len,
                                          const char *value, size_t value_len,
                                          void *userdata);

/**
 * @brief Iterate over all headers
 * @ingroup http
 * @param headers Header collection
 * @param callback Callback function
 * @param userdata User data passed to callback
 * @return 0 if completed, or value returned by callback that stopped iteration
 * @threadsafe No
 */
extern int SocketHTTP_Headers_iterate (SocketHTTP_Headers_T headers,
                                       SocketHTTP_HeaderCallback callback,
                                       void *userdata);

/**
 * @brief Validate header name
 * @ingroup http
 * @param name Header name
 * @param len Name length
 * @return 1 if valid, 0 otherwise
 * @threadsafe Yes
 *
 * Per RFC 9110, header names are tokens (tchar characters only).
 */
extern int SocketHTTP_header_name_valid (const char *name, size_t len);

/**
 * @brief Validate header value
 * @ingroup http
 * @param value Header value
 * @param len Value length
 * @return 1 if valid (no NUL/CR/LF), 0 otherwise
 * @threadsafe Yes
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
 */
extern int SocketHTTP_header_value_valid (const char *value, size_t len);

/* ============================================================================
 * URI Parsing (RFC 3986)
 * ============================================================================
 */

/**
 * @brief Parsed URI components according to RFC 3986.
 * @ingroup http
 *
 * Structure holding the generic syntax components of a URI or URI reference.
 * All string pointers reference substrings from the original input or arena-allocated copies;
 * they remain valid until the arena is cleared or disposed.
 * Strings are null-terminated for convenience but lengths are provided for efficiency.
 * Does not perform percent-decoding; use SocketHTTP_URI_decode() for that.
 * Supports absolute URIs, origin form, and relative references.
 * Host may include IPv6 literals in [brackets]; userinfo is parsed but deprecated per RFC 3986.
 * @see SocketHTTP_URI_parse() to populate this structure from URI string.
 * @see SocketHTTP_URI_get_port() to get effective port with defaults (80/443).
 * @see SocketHTTP_URI_is_secure() to check if scheme indicates TLS (https/wss).
 * @see SocketHTTP_URI_build() to serialize back to string.
 * @see SocketHTTP_URI_encode() and SocketHTTP_URI_decode() for percent handling.
 */
typedef struct
{
  const char *scheme;      /**< Scheme name (lowercase, e.g., "http", "https"; NULL for relative URI) */
  size_t scheme_len;       /**< Length of scheme */
  const char *userinfo;    /**< Userinfo "username:password" (deprecated by RFC 3986, may be NULL) */
  size_t userinfo_len;     /**< Length of userinfo */
  const char *host;        /**< Authority host (hostname, IPv4, or [IPv6]; required for absolute URI) */
  size_t host_len;         /**< Length of host */
  int port;                /**< Port number (0-65535) or -1 if not present */
  const char *path;        /**< Path component (absolute or relative; never NULL, may be empty "/") */
  size_t path_len;         /**< Length of path */
  const char *query;       /**< Query string (everything after ?; NULL if absent) */
  size_t query_len;        /**< Length of query */
  const char *fragment;    /**< Fragment identifier (after #; NULL if absent) */
  size_t fragment_len;     /**< Length of fragment */
} SocketHTTP_URI;

/**
 * @brief Result codes from URI parsing and related operations.
 * @ingroup http
 *
 * Indicates success or specific failure mode during URI parsing.
 * Use SocketHTTP_URI_result_string() to get human-readable description.
 * @see SocketHTTP_URI_parse() which returns one of these codes.
 * @see SocketHTTP_URI_result_string() for string representation.
 */
typedef enum
{
  URI_PARSE_OK = 0,               /**< Successful parse */
  URI_PARSE_ERROR,                /**< Generic syntax or validation error */
  URI_PARSE_INVALID_SCHEME,       /**< Scheme contains invalid characters or empty */
  URI_PARSE_INVALID_HOST,         /**< Host invalid: empty, bad characters, or malformed IPv6 */
  URI_PARSE_INVALID_PORT,         /**< Port not numeric or out of range (0-65535) */
  URI_PARSE_INVALID_PATH,         /**< Path contains disallowed characters (per RFC 3986) */
  URI_PARSE_INVALID_QUERY,        /**< Query contains disallowed characters */
  URI_PARSE_TOO_LONG              /**< URI length exceeds SOCKETHTTP_MAX_URI_LEN limit */
} SocketHTTP_URIResult;

/**
 * @brief Parse and validate a URI string into components.
 * @ingroup http
 * @param uri Input URI string (absolute or relative reference).
 * @param len Length of URI (0 to use strlen(uri)).
 * @param[out] result Pointer to SocketHTTP_URI structure to populate.
 * @param arena Arena for allocating parsed string components (must outlive result).
 * @return URI_PARSE_OK on success, or specific error code on failure.
 * @throws Arena_Failed if memory allocation for components fails.
 * @throws SocketHTTP_Failed on internal validation errors.
 * @threadsafe Yes, if arena is thread-safe or thread-local.
 *
 * Parses URI per RFC 3986 generic syntax, supporting absolute URIs, origin form, and relative refs.
 * Validates scheme, host (including [IPv6]), port, path, query, fragment.
 * Rejects overly long URIs (> SOCKETHTTP_MAX_URI_LEN) and invalid characters.
 * IPv6 hosts must be in RFC 3986 bracketed form.
 * Does not percent-decode; components retain original encoding (use SocketHTTP_URI_decode()).
 * Userinfo parsed but flagged as deprecated.
 * Path is always non-NULL (empty for no path).
 * @note Result strings point into arena-allocated memory or input buffer substrings.
 * @see SocketHTTP_URI struct for component details.
 * @see SocketHTTP_URI_build() to reconstruct URI string from parsed components.
 * @see SocketHTTP_URI_get_port() for port resolution with defaults.
 * @see SocketHTTP_URI_result_string() for error descriptions.
 */
extern SocketHTTP_URIResult SocketHTTP_URI_parse (const char *uri, size_t len,
                                                  SocketHTTP_URI *result,
                                                  Arena_T arena);

/**
 * @brief Get error description
 * @ingroup http
 * @param result Parse result code
 * @return Static string describing the result
 * @threadsafe Yes
 */
extern const char *SocketHTTP_URI_result_string (SocketHTTP_URIResult result);

/**
 * @brief Get port with default fallback
 * @ingroup http
 * @param uri Parsed URI
 * @param default_port Default port if not specified (e.g., 80 for http)
 * @return Explicit port from URI, or default_port if uri->port == -1
 * @threadsafe Yes
 */
extern int SocketHTTP_URI_get_port (const SocketHTTP_URI *uri,
                                    int default_port);

/**
 * @brief Check if URI uses secure scheme
 * @ingroup http
 * @param uri Parsed URI
 * @return 1 if scheme is "https" or "wss", 0 otherwise
 * @threadsafe Yes
 */
extern int SocketHTTP_URI_is_secure (const SocketHTTP_URI *uri);

/**
 * @brief Percent-encode string
 * @ingroup http
 * @param input Input string
 * @param len Input length
 * @param output Output buffer
 * @param output_size Output buffer size
 * @return Output length (excluding null), or -1 if buffer too small
 * @threadsafe Yes
 *
 * Encodes characters that are not unreserved per RFC 3986.
 * Unreserved: A-Z a-z 0-9 - . _ ~
 */
extern ssize_t SocketHTTP_URI_encode (const char *input, size_t len,
                                      char *output, size_t output_size);

/**
 * @brief Percent-decode string
 * @ingroup http
 * @param input Input string (may contain %XX sequences)
 * @param len Input length
 * @param output Output buffer
 * @param output_size Output buffer size
 * @return Output length, or -1 on error (invalid encoding or buffer too small)
 * @threadsafe Yes
 */
extern ssize_t SocketHTTP_URI_decode (const char *input, size_t len,
                                      char *output, size_t output_size);

/**
 * @brief Build URI string from components
 * @ingroup http
 * @param uri URI components
 * @param output Output buffer
 * @param output_size Buffer size
 * @return Length written (excluding null), or -1 if buffer too small
 * @threadsafe Yes
 *
 * Builds: scheme://[userinfo@]host[:port]path[?query][#fragment]
 */
extern ssize_t SocketHTTP_URI_build (const SocketHTTP_URI *uri, char *output,
                                     size_t output_size);

/* ============================================================================
 * Date Parsing (RFC 9110 Section 5.6.7)
 * ============================================================================
 */

/**
 * @brief Parse HTTP-date
 * @ingroup http
 * @param date_str Date string in any valid HTTP-date format
 * @param len Length of string (0 for strlen)
 * @param time_out Output time_t (UTC)
 * @return 0 on success, -1 on error
 * @threadsafe Yes
 *
 * Accepts three formats per RFC 9110:
 * - IMF-fixdate: Sun, 06 Nov 1994 08:49:37 GMT (preferred)
 * - RFC 850: Sunday, 06-Nov-94 08:49:37 GMT (obsolete)
 * - ANSI C: Sun Nov  6 08:49:37 1994 (obsolete)
 */
extern int SocketHTTP_date_parse (const char *date_str, size_t len,
                                  time_t *time_out);

/**
 * @brief Format time as HTTP-date (IMF-fixdate)
 * @ingroup http
 * @param t Time to format (UTC)
 * @param output Output buffer (must be at least SOCKETHTTP_DATE_BUFSIZE bytes)
 * @return Length written (29), or -1 on error
 * @threadsafe Yes
 *
 * Output format: "Sun, 06 Nov 1994 08:49:37 GMT"
 */
extern int SocketHTTP_date_format (time_t t, char *output);

/* ============================================================================
 * Content Type Parsing (RFC 9110 Section 8.3)
 * ============================================================================
 */

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcomment"
#endif
/**
 * @brief Parsed representation of an HTTP media type (Content-Type, Accept, etc.).
 * @ingroup http
 *
 * Extracts type/subtype from Content-Type header per RFC 9110 Section 8.3.
 * Also parses common parameters: charset (for text types) and boundary (for multipart types).
 * Other parameters ignored; full parsing requires custom handling.
 * Strings point into arena or input buffer; null-terminated with lengths provided.
 * @see SocketHTTP_MediaType_parse() to populate from header value string.
 * @see SocketHTTP_MediaType_matches() to check against pattern (supports wildcard patterns like * / * for any media type).
 */
typedef struct
{
  const char *type;        /**< Top-level type (e.g., "text", "application", "multipart"; token per RFC 9110) */
  size_t type_len;         /**< Length of type */
  const char *subtype;     /**< Subtype (e.g., "html", "json", "form-data"; token) */
  size_t subtype_len;      /**< Length of subtype */
  const char *charset;     /**< Charset parameter value (e.g., "utf-8"; NULL if absent) */
  size_t charset_len;      /**< Length of charset */
  const char *boundary;    /**< Multipart boundary parameter (NULL if absent or not multipart) */
  size_t boundary_len;     /**< Length of boundary */
} SocketHTTP_MediaType;

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

/**
 * @brief Parse Content-Type header
 * @ingroup http
 * @param value Content-Type header value
 * @param len Length of value (0 for strlen)
 * @param result Output structure
 * @param arena Arena for parameter strings
 * @return 0 on success, -1 on error
 * @threadsafe Yes
 *
 * Parses: type/subtype[; param=value]*
 */
extern int SocketHTTP_MediaType_parse (const char *value, size_t len,
                                       SocketHTTP_MediaType *result,
                                       Arena_T arena);

/**
 * @brief Check if media type matches pattern
 * @ingroup http
 * @param type Parsed media type
 * @param pattern Pattern like "text/\*" or "application/json"
 * @return 1 if matches, 0 otherwise
 * @threadsafe Yes
 *
 * Wildcard \* matches any subtype.
 */
extern int SocketHTTP_MediaType_matches (const SocketHTTP_MediaType *type,
                                         const char *pattern);

/* ============================================================================
 * Content Negotiation (RFC 9110 Section 12)
 * ============================================================================
 */

/**
 * @brief Single entry from quality-sorted list in Accept-like headers for content negotiation.
 * @ingroup http
 *
 * Represents a media type or language tag with its quality factor (q-value) from headers like Accept, Accept-Language.
 * Parsed and sorted by descending quality (highest preference first).
 * Quality defaults to 1.0 if not specified; 0.0 indicates rejection.
 * Used in content negotiation to select best match.
 * @see SocketHTTP_parse_accept() which populates arrays of this type.
 */
typedef struct
{
  const char *value;   /**< Value string (media type, language tag, etc.; null-terminated) */
  size_t value_len;    /**< Length of value */
  float quality;       /**< Preference level 0.0-1.0 (1.0 highest; default 1.0 if omitted) */
} SocketHTTP_QualityValue;

/**
 * @brief Parse Accept-style header
 * @ingroup http
 * @param value Header value
 * @param len Length (0 for strlen)
 * @param results Output array
 * @param max_results Maximum results to return
 * @param arena Arena for strings
 * @return Number of results parsed
 * @threadsafe Yes
 *
 * Parses comma-separated values with optional q= quality parameter.
 * Results sorted by quality (highest first).
 */
extern size_t SocketHTTP_parse_accept (const char *value, size_t len,
                                       SocketHTTP_QualityValue *results,
                                       size_t max_results, Arena_T arena);

/* ============================================================================
 * Transfer and Content Codings
 * ============================================================================
 */

/**
 * @brief Common HTTP transfer encodings and content codings per RFC 9110.
 * @ingroup http
 *
 * Used in Transfer-Encoding and Content-Encoding headers.
 * Supports standard compression algorithms and chunked for streaming.
 * HTTP_CODING_IDENTITY is no-encoding (default).
 * @see SocketHTTP_coding_parse() to parse from header value.
 * @see SocketHTTP_coding_name() to get string name.
 */
typedef enum
{
  HTTP_CODING_IDENTITY = 0, /**< No encoding (identity/default) */
  HTTP_CODING_CHUNKED,      /**< Chunked transfer encoding for unknown length */
  HTTP_CODING_GZIP,         /**< Gzip compression (RFC 1952) */
  HTTP_CODING_DEFLATE,      /**< Deflate compression (zlib, RFC 1950/1951) */
  HTTP_CODING_COMPRESS,     /**< Unix compress (LZW, rarely used/obsolete) */
  HTTP_CODING_BR,           /**< Brotli compression (RFC 7932) */
  HTTP_CODING_UNKNOWN = -1  /**< Unrecognized or unsupported encoding */
} SocketHTTP_Coding;

/**
 * @brief Parse coding name
 * @ingroup http
 * @param name Coding name string
 * @param len Name length (0 for strlen)
 * @return Coding type, or HTTP_CODING_UNKNOWN
 * @threadsafe Yes
 */
extern SocketHTTP_Coding SocketHTTP_coding_parse (const char *name,
                                                  size_t len);

/**
 * @brief Get coding name string
 * @ingroup http
 * @param coding Coding type
 * @return Static string, or NULL for unknown
 * @threadsafe Yes
 */
extern const char *SocketHTTP_coding_name (SocketHTTP_Coding coding);

/* ============================================================================
 * Request/Response Structures (Protocol-Agnostic)
 * ============================================================================
 */

/**
 * @brief Protocol-agnostic representation of an HTTP request message.
 * @ingroup http
 *
 * Captures the essential semantics of an HTTP request independent of transport (HTTP/1.x, HTTP/2, HTTP/3).
 * Request target can be in absolute form (scheme+authority+path), origin form (authority+path), or asterisk form.
 * Used by parsers, serializers, and high-level clients/servers.
 * Body information provided for transfer decisions; actual body data handled separately.
 * @see SocketHTTP1_Parser_get_request() for HTTP/1.1 parsing into this structure.
 * @see SocketHTTP2_Stream_send_request() for HTTP/2 usage.
 * @see SocketHTTP_Response for corresponding response structure.
 */
typedef struct
{
  SocketHTTP_Method method;     /**< Request method (e.g., GET, POST) */
  SocketHTTP_Version version;   /**< Protocol version (e.g., HTTP/1.1) */

  /* Request target components (per RFC 9110 Section 7; may be partial) */
  const char *scheme;           /**< Scheme for absolute-form URI (e.g., "https"; NULL otherwise) */
  const char *authority;        /**< Authority component (host[:port]; NULL for relative/asterisk form) */
  const char *path;             /**< Path and query (e.g., "/resource?param=value"; "*" for OPTIONS *) */

  SocketHTTP_Headers_T headers; /**< Request headers (NULL if none) */

  /* Body and transfer information */
  int has_body;                 /**< 1 if request includes body data */
  int64_t content_length;       /**< Exact body length or -1 for chunked/unknown */
} SocketHTTP_Request;

/**
 * @brief Protocol-agnostic representation of an HTTP response message.
 * @ingroup http
 *
 * Captures semantics of HTTP response independent of wire format.
 * Reason phrase is optional and only relevant for HTTP/1.x; ignored in HTTP/2+.
 * Used by protocol parsers and high-level APIs.
 * Body info for transfer; actual body separate.
 * @see SocketHTTP1_Parser_get_response() for HTTP/1.1 parsing.
 * @see SocketHTTP2_Stream_recv_headers() for HTTP/2 headers reception.
 * @see SocketHTTP_Request for request counterpart.
 */
typedef struct
{
  SocketHTTP_Version version;      /**< Protocol version of response */
  int status_code;                 /**< Status code (100-599) */
  const char *reason_phrase;       /**< Reason phrase (HTTP/1.x only; NULL or empty for HTTP/2+) */

  SocketHTTP_Headers_T headers;    /**< Response headers (NULL if none) */

  /* Body and transfer information */
  int has_body;                    /**< 1 if response includes body */
  int64_t content_length;          /**< Body length or -1 for chunked/unknown/transfer-encoding */
} SocketHTTP_Response;

/** @} */

#endif /* SOCKETHTTP_INCLUDED */
