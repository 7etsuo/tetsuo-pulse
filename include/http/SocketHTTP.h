/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @defgroup http HTTP Modules
 * @brief Complete HTTP/1.1 and HTTP/2 protocol implementation with client and
 * server support.
 *
 * The HTTP group provides comprehensive HTTP protocol support including
 * parsing, serialization, client/server implementations, and advanced
 * features. Key components include:
 * - SocketHTTP (core): HTTP types, headers, URI parsing, status codes (@ref
 * http)
 * - SocketHTTP1: HTTP/1.1 parsing and serialization (@ref http1 "HTTP/1.1
 * Module")
 * - SocketHTTP2: HTTP/2 protocol implementation (@ref http2 "HTTP/2 Module")
 * - SocketHTTPClient: High-level HTTP client with pooling (@ref http_client
 * "HTTP Client Module")
 * - SocketHTTPServer: HTTP server implementation (@ref http_server "HTTP
 * Server Module")
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
 * @brief Protocol-agnostic HTTP types, header handling, URI parsing, and
 * utilities.
 *
 * Provides protocol-agnostic HTTP types, header handling, URI parsing,
 * and date/media type utilities. Foundation for HTTP/1.1 and HTTP/2.
 *
 * Features: HTTP methods with semantic properties, status codes with reason
 * phrases, header collection with O(1) case-insensitive lookup, RFC 3986 URI
 * parsing with percent-encoding, HTTP-date parsing (all 3 RFC 9110 formats),
 * media type parsing, and content negotiation (Accept header q-value parsing).
 *
 * Thread safety: All functions are thread-safe (no global state).
 * Header collections are not thread-safe; use external synchronization if
 * sharing.
 *
 * Security notes: Rejects control characters and invalid syntax in URI
 * components, validates host as reg-name or IPv6 literal, validates media
 * types/parameters as HTTP tokens (RFC 7230), enforces per-component length
 * limits to prevent resource exhaustion, validates headers to reject injection
 * attacks, protects against integer overflow.
 */

#ifndef SOCKETHTTP_INCLUDED
#define SOCKETHTTP_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#include "core/Arena.h"
#include "core/Except.h"

/**
 * @brief Maximum allowed length for HTTP header names, in bytes.
 *
 * Default 256 bytes protects against DoS attacks via excessively long header
 * names. Exceeding this during parsing raises SocketHTTP_Failed.
 */
#ifndef SOCKETHTTP_MAX_HEADER_NAME
#define SOCKETHTTP_MAX_HEADER_NAME 256
#endif

/**
 * @brief Maximum allowed length for individual HTTP header values, in bytes.
 *
 * Default 8 KiB prevents memory exhaustion. Accommodates large values like
 * base64 Authorization or cookies. Values validated to exclude control
 * characters (CR/LF/NUL).
 */
#ifndef SOCKETHTTP_MAX_HEADER_VALUE
#define SOCKETHTTP_MAX_HEADER_VALUE (8 * 1024)
#endif

/**
 * @brief Maximum total size for all HTTP headers combined, in bytes.
 *
 * Default 64 KiB mitigates DoS from header flooding. Enforced in header
 * collection.
 */
#ifndef SOCKETHTTP_MAX_HEADER_SIZE
#define SOCKETHTTP_MAX_HEADER_SIZE (64 * 1024)
#endif

/**
 * @brief Maximum number of HTTP headers allowed in a collection.
 *
 * Default 100 prevents resource exhaustion. Duplicate headers count separately.
 */
#ifndef SOCKETHTTP_MAX_HEADERS
#define SOCKETHTTP_MAX_HEADERS 100
#endif

/**
 * @brief Maximum length for URI strings during parsing, in bytes.
 *
 * Default 8 KiB prevents DoS from oversized URIs. Enforced in
 * SocketHTTP_URI_parse().
 */
#ifndef SOCKETHTTP_MAX_URI_LEN
#define SOCKETHTTP_MAX_URI_LEN (8 * 1024)
#endif

/**
 * @brief Recommended buffer size for HTTP-date formatting output.
 *
 * IMF-fixdate format requires 29 bytes + null terminator = 30 bytes.
 */
#define SOCKETHTTP_DATE_BUFSIZE 30

/**
 * @brief Recommended buffer size for Content-Range header formatting.
 *
 * Supports "bytes START-END/TOTAL" format with up to 20-digit numbers.
 * Format: "bytes " (6) + START (20) + "-" (1) + END (20) + "/" (1) + TOTAL
 * (20) = 68 bytes + null terminator requires 69, rounded to 80 for safety.
 */
#define SOCKETHTTP_CONTENT_RANGE_BUFSIZE 80

/**
 * @brief Default HTTP port per RFC 9110 Section 4.2.3.
 *
 * Standard port for http:// scheme. Used when port is omitted in URI.
 */
#define HTTP_DEFAULT_PORT 80

/**
 * @brief Default HTTPS port per RFC 9110 Section 4.2.3.
 *
 * Standard port for https:// scheme. Used when port is omitted in URI.
 */
#define HTTPS_DEFAULT_PORT 443

/**
 * @brief ASCII character constants for HTTP validation.
 *
 * Used for header validation and protocol parsing per RFC 9110/9113.
 */
#define HTTP_CHAR_NUL 0x00   /**< Null character (prohibited in headers) */
#define HTTP_CHAR_CR 0x0D    /**< Carriage return (prohibited in headers) */
#define HTTP_CHAR_LF 0x0A    /**< Line feed (prohibited in headers) */
#define HTTP_CHAR_SPACE 0x20 /**< Space character */
#define HTTP_CHAR_DEL 0x7F   /**< Delete character (prohibited in headers) */

/**
 * @brief Uppercase letter range (ASCII).
 *
 * Used for case validation in HTTP/2 field names (RFC 9113 §8.2.1).
 */
#define HTTP_CHAR_UPPER_A 0x41 /**< 'A' */
#define HTTP_CHAR_UPPER_Z 0x5A /**< 'Z' */

/**
 * @brief HTTP status code constraints per RFC 9110.
 */
#define HTTP_STATUS_CODE_MIN 100 /**< Minimum valid HTTP status code */
#define HTTP_STATUS_CODE_MAX 599 /**< Maximum valid HTTP status code */

/**
 * @brief Generic HTTP module failure.
 *
 * Use for general errors in HTTP core utilities. Specific errors should use
 * module exceptions like SocketHTTP_ParseError, SocketHTTP1_ParseError.
 */
extern const Except_T SocketHTTP_Failed;

/**
 * @brief Error during core HTTP parsing operations.
 *
 * Raised for syntax errors in HTTP-date parsing, media type parsing, content
 * negotiation, or other core string parsing functions in SocketHTTP module.
 */
extern const Except_T SocketHTTP_ParseError;

/**
 * @brief Invalid URI syntax or validation failure.
 *
 * Raised for malformed scheme, invalid host (e.g., bad IPv6 literal),
 * out-of-range port, or disallowed characters in path/query/fragment per RFC
 * 3986.
 */
extern const Except_T SocketHTTP_InvalidURI;

/**
 * @brief Invalid HTTP header name or value.
 *
 * Raised when headers violate RFC 9110: invalid token characters in names,
 * control characters (CR/LF/NUL) in values (prevents injection), exceeding
 * max name/value size limits, or exceeding header count.
 */
extern const Except_T SocketHTTP_InvalidHeader;

/**
 * @brief HTTP protocol versions supported by the library.
 *
 * Enum values are major version * 10 + minor version for easy comparison
 * (e.g., 11 for HTTP/1.1). Supports HTTP/0.9 to HTTP/3.
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
 * @param version HTTP version
 * @return Static string like "HTTP/1.1", or "HTTP/?" for unknown
 */
extern const char *SocketHTTP_version_string (SocketHTTP_Version version);

/**
 * @brief Parse version string.
 * @param str Version string (e.g., "HTTP/1.1")
 * @param len String length (0 for strlen)
 * @return HTTP version, or HTTP_VERSION_0_9 if unrecognized
 */
extern SocketHTTP_Version
SocketHTTP_version_parse (const char *str, size_t len);

/**
 * @brief Standard HTTP request methods as defined in RFC 9110 and extensions.
 *
 * Includes all methods from RFC 9110 Section 9 plus PATCH (RFC 5789).
 * HTTP_METHOD_UNKNOWN indicates an unrecognized or custom method.
 */
typedef enum
{
  HTTP_METHOD_GET = 0, /**< RFC 9110 Section 9.3.1 - Safe, idempotent,
                          cacheable; retrieves resource */
  HTTP_METHOD_HEAD,   /**< RFC 9110 Section 9.3.2 - Like GET but response has no
                         body; used for metadata */
  HTTP_METHOD_POST,   /**< RFC 9110 Section 9.3.3 - Not safe or idempotent;
                         creates/submits data */
  HTTP_METHOD_PUT,    /**< RFC 9110 Section 9.3.4 - Idempotent; creates or
                         replaces resource at URI */
  HTTP_METHOD_DELETE, /**< RFC 9110 Section 9.3.5 - Idempotent; requests
                         deletion of resource */
  HTTP_METHOD_CONNECT, /**< RFC 9110 Section 9.3.6 - Establishes tunnel to
                          target host; used by proxies */
  HTTP_METHOD_OPTIONS, /**< RFC 9110 Section 9.3.7 - Safe; describes
                          communication options for target resource */
  HTTP_METHOD_TRACE,   /**< RFC 9110 Section 9.3.8 - Safe, idempotent; performs
                          test loop-back for diagnostics */
  HTTP_METHOD_PATCH, /**< RFC 5789 - Applies partial modifications to resource;
                        not always idempotent */
  HTTP_METHOD_UNKNOWN = -1 /**< Unrecognized or extension method */
} SocketHTTP_Method;

/**
 * @brief Semantic properties of an HTTP method as defined in RFC 9110
 * Section 9.2.
 *
 * Bit fields indicating method safety, idempotency, cacheability, and body
 * expectations. Used for request validation, caching decisions, and protocol
 * compliance.
 */
typedef struct
{
  unsigned
      safe : 1; /**< 1 if method is safe (does not modify server resources) */
  unsigned idempotent : 1; /**< 1 if multiple identical requests have same
                              effect as one */
  unsigned
      cacheable : 1; /**< 1 if response to successful request is cacheable */
  unsigned has_body : 1;      /**< 1 if request is allowed to have a body */
  unsigned response_body : 1; /**< 1 if successful response includes a body
                                 (except for HEAD) */
} SocketHTTP_MethodProperties;

/**
 * @brief Get method name string.
 * @param method HTTP method
 * @return Static string like "GET", or NULL for unknown
 */
extern const char *SocketHTTP_method_name (SocketHTTP_Method method);

/**
 * @brief Parse method string.
 * @param str Method string (e.g., "GET", "POST")
 * @param len String length (0 for strlen)
 * @return HTTP method, or HTTP_METHOD_UNKNOWN if unrecognized
 */
extern SocketHTTP_Method SocketHTTP_method_parse (const char *str, size_t len);

/**
 * @brief Get method semantic properties.
 * @param method HTTP method
 * @return Method properties structure
 */
extern SocketHTTP_MethodProperties
SocketHTTP_method_properties (SocketHTTP_Method method);

/**
 * @brief Check if string is valid HTTP method token.
 * @param str Method string
 * @param len String length
 * @return 1 if valid token per RFC 9110, 0 otherwise
 *
 * Valid token chars: !#$%&'*+-.0-9A-Z^_`a-z|~
 */
extern int SocketHTTP_method_valid (const char *str, size_t len);

/**
 * @brief HTTP status codes as defined in RFC 9110 Section 15 and common
 * extensions.
 *
 * Includes standard 1xx-5xx codes plus WebDAV (RFC 4918), HTTP/2 extensions,
 * and others.
 */
typedef enum
{
  /* 1xx Informational - Request received, continuing process */
  HTTP_STATUS_CONTINUE = 100, /**< Continue with request */
  HTTP_STATUS_SWITCHING_PROTOCOLS
  = 101,                        /**< Server agrees to upgrade protocol */
  HTTP_STATUS_PROCESSING = 102, /**< RFC 2518 WebDAV - Processing request */
  HTTP_STATUS_EARLY_HINTS
  = 103, /**< RFC 8297 - Early hints for resource links */

  /* 2xx Successful - Request successful */
  HTTP_STATUS_OK = 200,                /**< Standard success */
  HTTP_STATUS_CREATED = 201,           /**< Resource created */
  HTTP_STATUS_ACCEPTED = 202,          /**< Accepted for processing */
  HTTP_STATUS_NON_AUTHORITATIVE = 203, /**< Non-authoritative information */
  HTTP_STATUS_NO_CONTENT = 204,        /**< Success, no content */
  HTTP_STATUS_RESET_CONTENT = 205,   /**< Reset content (user agent refresh) */
  HTTP_STATUS_PARTIAL_CONTENT = 206, /**< Partial content (range request) */
  HTTP_STATUS_MULTI_STATUS = 207,    /**< RFC 4918 WebDAV - Multiple statuses */
  HTTP_STATUS_ALREADY_REPORTED
  = 208, /**< RFC 5842 WebDAV - Avoid infinite loops */
  HTTP_STATUS_IM_USED
  = 226, /**< RFC 3229 Delta encoding - Instance manipulated */

  /* 3xx Redirection - Further action needed */
  HTTP_STATUS_MULTIPLE_CHOICES = 300,  /**< Multiple resource representations */
  HTTP_STATUS_MOVED_PERMANENTLY = 301, /**< Permanent redirect */
  HTTP_STATUS_FOUND = 302,             /**< Temporary redirect */
  HTTP_STATUS_SEE_OTHER = 303,         /**< See other location */
  HTTP_STATUS_NOT_MODIFIED = 304, /**< Not modified (conditional request) */
  HTTP_STATUS_USE_PROXY = 305,    /**< Deprecated - Use proxy (absolute URI) */
  HTTP_STATUS_TEMPORARY_REDIRECT
  = 307, /**< Temporary redirect, preserve method */
  HTTP_STATUS_PERMANENT_REDIRECT
  = 308, /**< RFC 7238 - Permanent redirect, preserve method */

  /* 4xx Client Error - Client error */
  HTTP_STATUS_BAD_REQUEST = 400,         /**< Invalid request syntax */
  HTTP_STATUS_UNAUTHORIZED = 401,        /**< Authentication required */
  HTTP_STATUS_PAYMENT_REQUIRED = 402,    /**< Payment required (reserved) */
  HTTP_STATUS_FORBIDDEN = 403,           /**< Forbidden */
  HTTP_STATUS_NOT_FOUND = 404,           /**< Resource not found */
  HTTP_STATUS_METHOD_NOT_ALLOWED = 405,  /**< Method not allowed for resource */
  HTTP_STATUS_NOT_ACCEPTABLE = 406,      /**< No acceptable representation */
  HTTP_STATUS_PROXY_AUTH_REQUIRED = 407, /**< Proxy authentication required */
  HTTP_STATUS_REQUEST_TIMEOUT = 408,     /**< Request timeout */
  HTTP_STATUS_CONFLICT = 409,            /**< Resource conflict */
  HTTP_STATUS_GONE = 410,                /**< Resource permanently gone */
  HTTP_STATUS_LENGTH_REQUIRED = 411,     /**< Content-Length required */
  HTTP_STATUS_PRECONDITION_FAILED = 412, /**< Precondition failed */
  HTTP_STATUS_CONTENT_TOO_LARGE = 413,   /**< Payload too large */
  HTTP_STATUS_URI_TOO_LONG = 414,        /**< URI too long */
  HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE = 415, /**< Unsupported media type */
  HTTP_STATUS_RANGE_NOT_SATISFIABLE = 416,  /**< Range not satisfiable */
  HTTP_STATUS_EXPECTATION_FAILED = 417,     /**< Expectation failed */
  HTTP_STATUS_IM_A_TEAPOT = 418, /**< RFC 2324 - I'm a teapot (humorous) */
  HTTP_STATUS_MISDIRECTED_REQUEST = 421, /**< Mis-directed request (HTTP/2+) */
  HTTP_STATUS_UNPROCESSABLE_CONTENT = 422, /**< Unprocessable entity (WebDAV) */
  HTTP_STATUS_LOCKED = 423, /**< RFC 4918 WebDAV - Resource locked */
  HTTP_STATUS_FAILED_DEPENDENCY
  = 424,                       /**< RFC 4918 WebDAV - Dependency failed */
  HTTP_STATUS_TOO_EARLY = 425, /**< RFC 8470 - Too early (anti-replay) */
  HTTP_STATUS_UPGRADE_REQUIRED = 426, /**< Upgrade required (e.g., TLS) */
  HTTP_STATUS_PRECONDITION_REQUIRED
  = 428,                               /**< RFC 6585 - Precondition required */
  HTTP_STATUS_TOO_MANY_REQUESTS = 429, /**< RFC 6585 - Rate limiting */
  HTTP_STATUS_HEADER_TOO_LARGE = 431, /**< RFC 6585 - Header fields too large */
  HTTP_STATUS_UNAVAILABLE_LEGAL
  = 451, /**< RFC 7725 - Unavailable for legal reasons */

  /* 5xx Server Error - Server failure */
  HTTP_STATUS_INTERNAL_ERROR = 500,  /**< Internal server error */
  HTTP_STATUS_NOT_IMPLEMENTED = 501, /**< Not implemented */
  HTTP_STATUS_BAD_GATEWAY = 502,     /**< Bad gateway */
  HTTP_STATUS_SERVICE_UNAVAILABLE
  = 503,                             /**< Service unavailable (maintenance) */
  HTTP_STATUS_GATEWAY_TIMEOUT = 504, /**< Gateway timeout */
  HTTP_STATUS_VERSION_NOT_SUPPORTED = 505, /**< HTTP version not supported */
  HTTP_STATUS_VARIANT_ALSO_NEGOTIATES
  = 506, /**< RFC 2295 - Variant also negotiates */
  HTTP_STATUS_INSUFFICIENT_STORAGE
  = 507, /**< RFC 4918 WebDAV - Insufficient storage */
  HTTP_STATUS_LOOP_DETECTED = 508, /**< RFC 5842 WebDAV - Loop detected */
  HTTP_STATUS_NOT_EXTENDED = 510,  /**< RFC 2774 - Not extended */
  HTTP_STATUS_NETWORK_AUTH_REQUIRED
  = 511 /**< RFC 6585 - Network authentication required */
} SocketHTTP_StatusCode;

/** @brief Minimum valid HTTP status code (100-599 range per RFC 9110). */
#define HTTP_STATUS_CODE_MIN 100
/** @brief Maximum valid HTTP status code. */
#define HTTP_STATUS_CODE_MAX 599

/** @brief Status code range boundaries for validation. */
#define HTTP_STATUS_1XX_MIN HTTP_STATUS_CONTINUE
#define HTTP_STATUS_1XX_MAX 199
#define HTTP_STATUS_2XX_MIN HTTP_STATUS_OK
#define HTTP_STATUS_2XX_MAX 299
#define HTTP_STATUS_3XX_MIN HTTP_STATUS_MULTIPLE_CHOICES
#define HTTP_STATUS_3XX_MAX 399
#define HTTP_STATUS_4XX_MIN HTTP_STATUS_BAD_REQUEST
#define HTTP_STATUS_4XX_MAX 499
#define HTTP_STATUS_5XX_MIN HTTP_STATUS_INTERNAL_ERROR
#define HTTP_STATUS_5XX_MAX 599

/**
 * @brief Status code classification macros for quick category checking.
 *
 * Provide readable checks for HTTP status code ranges per RFC 9110.
 * Use these instead of magic number comparisons for improved readability
 * and maintainability.
 *
 * @param c HTTP status code to check
 * @return 1 if code is in the specified range, 0 otherwise
 */
#define HTTP_STATUS_IS_INFORMATIONAL(c) ((c) >= 100 && (c) < 200)
#define HTTP_STATUS_IS_SUCCESS(c) ((c) >= 200 && (c) < 300)
#define HTTP_STATUS_IS_REDIRECT(c) ((c) >= 300 && (c) < 400)
#define HTTP_STATUS_IS_CLIENT_ERROR(c) ((c) >= 400 && (c) < 500)
#define HTTP_STATUS_IS_SERVER_ERROR(c) ((c) >= 500 && (c) < 600)

/**
 * @brief Categories of HTTP status codes for quick classification.
 *
 * Maps to first digit of status code (1-5). Used for error handling,
 * logging, and conditional logic.
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
 * @param code HTTP status code
 * @return Static reason phrase, or "Unknown" for unrecognized codes
 */
extern const char *SocketHTTP_status_reason (int code);

/**
 * @brief Get status code category.
 * @param code HTTP status code
 * @return Category (1-5), or 0 for invalid codes
 */
extern SocketHTTP_StatusCategory SocketHTTP_status_category (int code);

/**
 * @brief Check if status code is valid.
 * @param code HTTP status code
 * @return 1 if code is 100-599, 0 otherwise
 */
extern int SocketHTTP_status_valid (int code);

/**
 * @brief Single HTTP header field representation for iteration and access.
 *
 * Used by SocketHTTP_Headers_at() and SocketHTTP_Headers_iterate() to provide
 * access to individual headers without copying. Name is case-preserved as
 * received/sent; lookup is case-insensitive.
 */
typedef struct
{
  const char *name;  /**< Header name (case-preserved, null-terminated) */
  size_t name_len;   /**< Length of name (excluding null) */
  const char *value; /**< Header value (null-terminated; may be empty) */
  size_t value_len;  /**< Length of value (excluding null) */
} SocketHTTP_Header;

/**
 * @brief Opaque type for HTTP header collection with efficient operations.
 *
 * Manages a dynamic collection of HTTP headers with O(1) case-insensitive
 * lookup using hash table. Memory allocated from provided arena; lifetime tied
 * to arena. Thread-unsafe; synchronize externally if shared across threads.
 */
typedef struct SocketHTTP_Headers *SocketHTTP_Headers_T;

/**
 * @brief Create a new empty HTTP header collection.
 * @param arena Arena used for all internal allocations; must outlive the
 * collection.
 * @return New header collection instance.
 * @throws Arena_Failed if memory allocation fails.
 * @throws SocketHTTP_Failed if arena is NULL or internal initialization fails.
 */
extern SocketHTTP_Headers_T SocketHTTP_Headers_new (Arena_T arena);

/** @brief Remove all headers from collection. */
extern void SocketHTTP_Headers_clear (SocketHTTP_Headers_T headers);

/**
 * @brief Add header (null-terminated strings).
 * @return 0 on success, -1 on error (invalid name/value, limits exceeded)
 *
 * Adds header, allowing duplicates. Use set() to replace existing.
 */
extern int SocketHTTP_Headers_add (SocketHTTP_Headers_T headers,
                                   const char *name,
                                   const char *value);

/** @brief Add header with explicit lengths. */
extern int SocketHTTP_Headers_add_n (SocketHTTP_Headers_T headers,
                                     const char *name,
                                     size_t name_len,
                                     const char *value,
                                     size_t value_len);

/**
 * @brief Add HTTP/2 or HTTP/3 pseudo-header with explicit lengths.
 * @return 0 on success, -1 on error
 *
 * Allows header names starting with ':' (e.g., ":method", ":status").
 * Standard header name validation rejects ':' since it is not a valid
 * HTTP/1.1 token character (RFC 7230). This function is for internal
 * use by HTTP/2 and HTTP/3 decoders and validators.
 */
extern int SocketHTTP_Headers_add_pseudo_n (SocketHTTP_Headers_T headers,
                                            const char *name,
                                            size_t name_len,
                                            const char *value,
                                            size_t value_len);

/**
 * @brief Add header as zero-copy reference (no string allocation).
 * @return 0 on success, -1 on error
 *
 * Stores pointers directly without copying. The name and value buffers
 * must remain valid until headers are freed or materialize() is called.
 * Used internally by parser for performance.
 */
extern int SocketHTTP_Headers_add_ref (SocketHTTP_Headers_T headers,
                                       const char *name,
                                       size_t name_len,
                                       const char *value,
                                       size_t value_len);

/**
 * @brief Materialize all reference headers by copying strings to arena.
 * @return 0 on success, -1 on error
 *
 * Converts zero-copy reference headers to owned copies. Call this before
 * the source buffers are reused or freed.
 */
extern int SocketHTTP_Headers_materialize (SocketHTTP_Headers_T headers);

/**
 * @brief Set header (replace if exists).
 * @return 0 on success, -1 on error
 *
 * Removes all existing headers with same name, then adds new one.
 */
extern int SocketHTTP_Headers_set (SocketHTTP_Headers_T headers,
                                   const char *name,
                                   const char *value);

/**
 * @brief Get first header value (case-insensitive).
 * @return Header value (null-terminated), or NULL if not found
 */
extern const char *
SocketHTTP_Headers_get (SocketHTTP_Headers_T headers, const char *name);

/**
 * @brief Get first header value with explicit name length (avoids strlen).
 * @param headers Header collection
 * @param name Header name to look up
 * @param name_len Length of name (excluding null terminator)
 * @return Header value (null-terminated), or NULL if not found
 */
extern const char *SocketHTTP_Headers_get_n (SocketHTTP_Headers_T headers,
                                             const char *name,
                                             size_t name_len);

/**
 * @brief Get header value as integer.
 * @return 0 on success, -1 if not found or not a valid integer
 */
extern int SocketHTTP_Headers_get_int (SocketHTTP_Headers_T headers,
                                       const char *name,
                                       int64_t *value);

/** @brief Get all values for header. */
extern size_t SocketHTTP_Headers_get_all (SocketHTTP_Headers_T headers,
                                          const char *name,
                                          const char **values,
                                          size_t max_values);

/** @brief Get all values for header with explicit name length (avoids strlen).
 */
extern size_t SocketHTTP_Headers_get_all_n (SocketHTTP_Headers_T headers,
                                            const char *name,
                                            size_t name_len,
                                            const char **values,
                                            size_t max_values);

/** @brief Check if header exists. */
extern int
SocketHTTP_Headers_has (SocketHTTP_Headers_T headers, const char *name);

/** @brief Check if header exists with explicit name length (avoids strlen). */
extern int SocketHTTP_Headers_has_n (SocketHTTP_Headers_T headers,
                                     const char *name,
                                     size_t name_len);

/**
 * @brief Check if header contains token.
 * @return 1 if token found (case-insensitive), 0 otherwise
 *
 * Useful for headers like "Connection: keep-alive, upgrade"
 */
extern int SocketHTTP_Headers_contains (SocketHTTP_Headers_T headers,
                                        const char *name,
                                        const char *token);

/**
 * @brief Check if header contains token with explicit lengths (avoids strlen).
 * @param headers Header collection
 * @param name Header name to look up
 * @param name_len Length of name
 * @param token Token to search for in header value
 * @param token_len Length of token
 * @return 1 if token found (case-insensitive), 0 otherwise
 */
extern int SocketHTTP_Headers_contains_n (SocketHTTP_Headers_T headers,
                                          const char *name,
                                          size_t name_len,
                                          const char *token,
                                          size_t token_len);

/** @brief Remove first header with name. */
extern int
SocketHTTP_Headers_remove (SocketHTTP_Headers_T headers, const char *name);

/** @brief Remove all headers with name. */
extern int
SocketHTTP_Headers_remove_all (SocketHTTP_Headers_T headers, const char *name);

/** @brief Get total header count. */
extern size_t SocketHTTP_Headers_count (SocketHTTP_Headers_T headers);

/** @brief Get header by index (0-based). */
extern const SocketHTTP_Header *
SocketHTTP_Headers_at (SocketHTTP_Headers_T headers, size_t index);

/**
 * @brief Callback function for iterating over HTTP headers.
 * @param name Header name (null-terminated string, case-preserved).
 * @param name_len Length of name (excluding null).
 * @param value Header value (null-terminated, may be empty string).
 * @param value_len Length of value (excluding null).
 * @param userdata User data passed from SocketHTTP_Headers_iterate().
 * @return 0 to continue iteration, non-zero to stop early.
 */
typedef int (*SocketHTTP_HeaderCallback) (const char *name,
                                          size_t name_len,
                                          const char *value,
                                          size_t value_len,
                                          void *userdata);

/** @brief Iterate over all headers with callback. */
extern int SocketHTTP_Headers_iterate (SocketHTTP_Headers_T headers,
                                       SocketHTTP_HeaderCallback callback,
                                       void *userdata);

/**
 * @brief Validate header name.
 * @return 1 if valid, 0 otherwise
 *
 * Per RFC 9110, header names are tokens (tchar characters only).
 */
extern int SocketHTTP_header_name_valid (const char *name, size_t len);

/**
 * @brief Validate header value.
 * @return 1 if valid (no NUL/CR/LF), 0 otherwise
 *
 * SECURITY: Rejects NUL, CR, and LF characters to prevent HTTP header
 * injection attacks (CWE-113). Per RFC 9110 Section 5.5, obs-fold (CRLF
 * followed by SP/HTAB) is deprecated and should not be generated.
 *
 * This stricter validation prevents CRLF injection for header manipulation,
 * response splitting attacks, cache poisoning via injected headers, and
 * session hijacking via injected Set-Cookie.
 */
extern int SocketHTTP_header_value_valid (const char *value, size_t len);

/**
 * @brief Parsed URI components according to RFC 3986.
 *
 * Structure holding the generic syntax components of a URI or URI reference.
 * All string pointers reference substrings from the original input or
 * arena-allocated copies; valid until arena is cleared. Strings are
 * null-terminated with lengths provided. Does not perform percent-decoding; use
 * SocketHTTP_URI_decode(). Supports absolute URIs, origin form, and relative
 * references. Host may include IPv6 literals in [brackets]; userinfo is parsed
 * but deprecated per RFC 3986.
 */
typedef struct
{
  const char *scheme;   /**< Scheme name (lowercase, e.g., "http", "https"; NULL
                           for relative URI) */
  size_t scheme_len;    /**< Length of scheme */
  const char *userinfo; /**< Userinfo "username:password" (deprecated by RFC
                           3986, may be NULL) */
  size_t userinfo_len;  /**< Length of userinfo */
  const char *host;     /**< Authority host (hostname, IPv4, or [IPv6]; required
                           for absolute URI) */
  size_t host_len;      /**< Length of host */
  int port;             /**< Port number (0-65535) or -1 if not present */
  const char *path;  /**< Path component (absolute or relative; never NULL, may
                        be empty "/") */
  size_t path_len;   /**< Length of path */
  const char *query; /**< Query string (everything after ?; NULL if absent) */
  size_t query_len;  /**< Length of query */
  const char *fragment; /**< Fragment identifier (after #; NULL if absent) */
  size_t fragment_len;  /**< Length of fragment */
} SocketHTTP_URI;

/**
 * @brief Result codes from URI parsing and related operations.
 *
 * Indicates success or specific failure mode during URI parsing.
 */
typedef enum
{
  URI_PARSE_OK = 0,         /**< Successful parse */
  URI_PARSE_ERROR,          /**< Generic syntax or validation error */
  URI_PARSE_INVALID_SCHEME, /**< Scheme contains invalid characters or empty */
  URI_PARSE_INVALID_HOST,   /**< Host invalid: empty, bad characters, or
                               malformed IPv6 */
  URI_PARSE_INVALID_PORT,   /**< Port not numeric or out of range (0-65535) */
  URI_PARSE_INVALID_PATH,   /**< Path contains disallowed characters (per RFC
                               3986) */
  URI_PARSE_INVALID_QUERY,  /**< Query contains disallowed characters */
  URI_PARSE_TOO_LONG /**< URI length exceeds SOCKETHTTP_MAX_URI_LEN limit */
} SocketHTTP_URIResult;

/**
 * @brief Parse and validate a URI string into components.
 * @param uri Input URI string (absolute or relative reference).
 * @param len Length of URI (0 to use strlen(uri)).
 * @param[out] result Pointer to SocketHTTP_URI structure to populate.
 * @param arena Arena for allocating parsed string components (must outlive
 * result).
 * @return URI_PARSE_OK on success, or specific error code on failure.
 * @throws Arena_Failed if memory allocation for components fails.
 * @throws SocketHTTP_InvalidURI on invalid URI syntax, malformed components,
 * or validation failures (e.g., invalid host, port out of range).
 *
 * Parses URI per RFC 3986 generic syntax, supporting absolute URIs, origin
 * form, and relative refs. Validates scheme, host (including [IPv6]), port,
 * path, query, fragment. Rejects overly long URIs (> SOCKETHTTP_MAX_URI_LEN)
 * and invalid characters. Does not percent-decode; use SocketHTTP_URI_decode().
 */
extern SocketHTTP_URIResult SocketHTTP_URI_parse (const char *uri,
                                                  size_t len,
                                                  SocketHTTP_URI *result,
                                                  Arena_T arena);

/** @brief Get error description for parse result code. */
extern const char *SocketHTTP_URI_result_string (SocketHTTP_URIResult result);

/** @brief Get port with default fallback (e.g., 80 for http). */
extern int
SocketHTTP_URI_get_port (const SocketHTTP_URI *uri, int default_port);

/** @brief Check if URI uses secure scheme ("https" or "wss"). */
extern int SocketHTTP_URI_is_secure (const SocketHTTP_URI *uri);

/**
 * @brief Percent-encode string.
 * @return Output length (excluding null), or -1 if buffer too small
 *
 * Encodes characters that are not unreserved per RFC 3986.
 * Unreserved: A-Z a-z 0-9 - . _ ~
 */
extern ssize_t SocketHTTP_URI_encode (const char *input,
                                      size_t len,
                                      char *output,
                                      size_t output_size);

/**
 * @brief Percent-decode string.
 * @return Output length, or -1 on error (invalid encoding or buffer too small)
 */
extern ssize_t SocketHTTP_URI_decode (const char *input,
                                      size_t len,
                                      char *output,
                                      size_t output_size);

/**
 * @brief Build URI string from components.
 * @return Length written (excluding null), or -1 if buffer too small
 *
 * Builds: scheme://[userinfo@]host[:port]path[?query][#fragment]
 */
extern ssize_t SocketHTTP_URI_build (const SocketHTTP_URI *uri,
                                     char *output,
                                     size_t output_size);

/**
 * @brief Parse HTTP-date.
 * @param date_str Date string in any valid HTTP-date format
 * @param len Length of string (0 for strlen)
 * @param time_out Output time_t (UTC)
 * @return 0 on success, -1 on error
 *
 * Accepts three formats per RFC 9110:
 * - IMF-fixdate: Sun, 06 Nov 1994 08:49:37 GMT (preferred)
 * - RFC 850: Sunday, 06-Nov-94 08:49:37 GMT (obsolete)
 * - ANSI C: Sun Nov  6 08:49:37 1994 (obsolete)
 */
extern int
SocketHTTP_date_parse (const char *date_str, size_t len, time_t *time_out);

/**
 * @brief Format time as HTTP-date (IMF-fixdate).
 * @param t Time to format (UTC)
 * @param output Output buffer (must be at least SOCKETHTTP_DATE_BUFSIZE bytes)
 * @return Length written (29), or -1 on error
 *
 * Output format: "Sun, 06 Nov 1994 08:49:37 GMT"
 */
extern int SocketHTTP_date_format (time_t t, char *output);

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcomment"
#endif
/**
 * @brief Parsed representation of an HTTP media type (Content-Type, Accept,
 * etc.).
 *
 * Extracts type/subtype from Content-Type header per RFC 9110 Section 8.3.
 * Also parses common parameters: charset (for text types) and boundary (for
 * multipart types). Strings point into arena or input buffer; null-terminated
 * with lengths provided.
 */
typedef struct
{
  const char *type; /**< Top-level type (e.g., "text", "application",
                       "multipart"; token per RFC 9110) */
  size_t type_len;  /**< Length of type */
  const char
      *subtype;       /**< Subtype (e.g., "html", "json", "form-data"; token) */
  size_t subtype_len; /**< Length of subtype */
  const char
      *charset; /**< Charset parameter value (e.g., "utf-8"; NULL if absent) */
  size_t charset_len;   /**< Length of charset */
  const char *boundary; /**< Multipart boundary parameter (NULL if absent or
                           not multipart) */
  size_t boundary_len;  /**< Length of boundary */
} SocketHTTP_MediaType;

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

/**
 * @brief Parse Content-Type header.
 * @param value Content-Type header value
 * @param len Length of value (0 for strlen)
 * @param result Output structure
 * @param arena Arena for parameter strings
 * @return 0 on success, -1 on error
 *
 * Parses: type/subtype[; param=value]*
 */
extern int SocketHTTP_MediaType_parse (const char *value,
                                       size_t len,
                                       SocketHTTP_MediaType *result,
                                       Arena_T arena);

/**
 * @brief Check if media type matches pattern.
 * @param pattern Pattern like "text/\*" or "application/json"
 * @return 1 if matches, 0 otherwise
 *
 * Wildcard \* matches any subtype.
 */
extern int SocketHTTP_MediaType_matches (const SocketHTTP_MediaType *type,
                                         const char *pattern);

/**
 * @brief Single entry from quality-sorted list in Accept-like headers.
 *
 * Represents a media type or language tag with its quality factor (q-value)
 * from headers like Accept, Accept-Language. Parsed and sorted by descending
 * quality (highest preference first). Quality defaults to 1.0 if not specified.
 */
typedef struct
{
  const char *value; /**< Value string (media type, language tag, etc.;
                        null-terminated) */
  size_t value_len;  /**< Length of value */
  float quality;     /**< Preference level 0.0-1.0 (1.0 highest; default 1.0 if
                        omitted) */
} SocketHTTP_QualityValue;

/**
 * @brief Parse Accept-style header.
 * @param value Header value
 * @param len Length (0 for strlen)
 * @param results Output array
 * @param max_results Maximum results to return
 * @param arena Arena for strings
 * @return Number of results parsed
 *
 * Parses comma-separated values with optional q= quality parameter.
 * Results sorted by quality (highest first).
 */
extern size_t SocketHTTP_parse_accept (const char *value,
                                       size_t len,
                                       SocketHTTP_QualityValue *results,
                                       size_t max_results,
                                       Arena_T arena);

/**
 * @brief Common HTTP transfer encodings and content codings per RFC 9110.
 *
 * Used in Transfer-Encoding and Content-Encoding headers. Supports standard
 * compression algorithms and chunked for streaming. HTTP_CODING_IDENTITY is
 * no-encoding (default).
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

/** @brief Parse coding name from string. */
extern SocketHTTP_Coding SocketHTTP_coding_parse (const char *name, size_t len);

/** @brief Get coding name string. */
extern const char *SocketHTTP_coding_name (SocketHTTP_Coding coding);

/**
 * @brief Protocol-agnostic representation of an HTTP request message.
 *
 * Captures the essential semantics of an HTTP request independent of transport
 * (HTTP/1.x, HTTP/2, HTTP/3). Request target can be in absolute form
 * (scheme+authority+path), origin form (authority+path), or asterisk form.
 * Body information provided for transfer decisions; actual body data handled
 * separately.
 */
typedef struct
{
  SocketHTTP_Method method;   /**< Request method (e.g., GET, POST) */
  SocketHTTP_Version version; /**< Protocol version (e.g., HTTP/1.1) */

  /* Request target components (per RFC 9110 Section 7; may be partial) */
  const char *scheme;    /**< Scheme for absolute-form URI (e.g., "https"; NULL
                            otherwise) */
  const char *authority; /**< Authority component (host[:port]; NULL for
                            relative/asterisk form) */
  const char *path; /**< Path and query (e.g., "/resource?param=value"; "*" for
                       OPTIONS *) */

  SocketHTTP_Headers_T headers; /**< Request headers (NULL if none) */

  /* Body and transfer information */
  int has_body;           /**< 1 if request includes body data */
  int64_t content_length; /**< Exact body length or -1 for chunked/unknown */
} SocketHTTP_Request;

/**
 * @brief Protocol-agnostic representation of an HTTP response message.
 *
 * Captures semantics of HTTP response independent of wire format.
 * Reason phrase is optional and only relevant for HTTP/1.x; ignored in HTTP/2+.
 * Body info for transfer; actual body separate.
 */
typedef struct
{
  SocketHTTP_Version version; /**< Protocol version of response */
  int status_code;            /**< Status code (100-599) */
  const char *reason_phrase;  /**< Reason phrase (HTTP/1.x only; NULL or empty
                                 for HTTP/2+) */

  SocketHTTP_Headers_T headers; /**< Response headers (NULL if none) */

  /* Body and transfer information */
  int has_body;           /**< 1 if response includes body */
  int64_t content_length; /**< Body length or -1 for
                             chunked/unknown/transfer-encoding */
} SocketHTTP_Response;

/** @} */

#endif /* SOCKETHTTP_INCLUDED */
