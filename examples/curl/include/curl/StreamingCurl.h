/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @defgroup curl Streaming Curl Module
 * @ingroup http
 * @brief Memory-efficient streaming HTTP client with curl-like API.
 *
 * Features: Streaming body read/write via callbacks, HTTP/1.1 and HTTP/2
 * support (via ALPN), redirect following, cookie handling, Basic/Digest/Bearer
 * authentication, connection pooling, proxy support (SOCKS4/5, HTTP CONNECT),
 * configurable timeouts and retries.
 *
 * Memory: Bodies are streamed through callbacks, never buffered in memory.
 * Suitable for large file downloads/uploads.
 *
 * Thread safety: Session instances are NOT thread-safe. Use one session per
 * thread.
 * @{
 */

/**
 * @file StreamingCurl.h
 * @ingroup curl
 * @brief Public API for streaming curl module.
 */

#ifndef STREAMINGCURL_INCLUDED
#define STREAMINGCURL_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHTTP.h"

/* Forward declarations for optional TLS */
#if SOCKET_HAS_TLS
#include "tls/SocketTLSContext.h"
#else
typedef struct SocketTLSContext_T *SocketTLSContext_T;
#endif

/**
 * @name Exception Types
 * @{
 */

/** @brief Generic curl operation failure. */
extern const Except_T Curl_Failed;

/** @brief DNS resolution failure. */
extern const Except_T Curl_DNSFailed;

/** @brief Connection failure. */
extern const Except_T Curl_ConnectFailed;

/** @brief TLS handshake failure. */
extern const Except_T Curl_TLSFailed;

/** @brief Operation timed out. */
extern const Except_T Curl_Timeout;

/** @brief HTTP protocol error. */
extern const Except_T Curl_ProtocolError;

/** @brief Too many redirects. */
extern const Except_T Curl_TooManyRedirects;

/** @brief Invalid URL syntax. */
extern const Except_T Curl_InvalidURL;

/** @} */

/**
 * @name Error Codes
 * @{
 */

/** @brief Error codes for non-exception error handling. */
typedef enum
{
  CURL_OK = 0,                     /**< Success */
  CURL_ERROR_DNS,                  /**< DNS resolution failed */
  CURL_ERROR_CONNECT,              /**< Connection failed */
  CURL_ERROR_TLS,                  /**< TLS handshake failed */
  CURL_ERROR_TIMEOUT,              /**< Operation timed out */
  CURL_ERROR_PROTOCOL,             /**< HTTP protocol error */
  CURL_ERROR_TOO_MANY_REDIRECTS,   /**< Exceeded redirect limit */
  CURL_ERROR_INVALID_URL,          /**< Malformed URL */
  CURL_ERROR_WRITE_CALLBACK,       /**< Write callback returned error */
  CURL_ERROR_READ_CALLBACK,        /**< Read callback returned error */
  CURL_ERROR_OUT_OF_MEMORY,        /**< Memory allocation failed */
  CURL_ERROR_ABORTED               /**< Operation aborted by callback */
} CurlError;

/**
 * @brief Get human-readable error string.
 * @param error Error code
 * @return Static error description string
 */
extern const char *Curl_error_string (CurlError error);

/** @} */

/**
 * @name Callback Types
 * @{
 */

/**
 * @brief Callback for writing received data (response body).
 *
 * Called as response body data arrives. Return the number of bytes handled.
 * Return a value different from size*nmemb to abort the transfer.
 *
 * @param data Pointer to received data
 * @param size Always 1
 * @param nmemb Number of bytes
 * @param userdata User-provided pointer from CurlOptions
 * @return Number of bytes handled (return != size*nmemb to abort)
 *
 * Example:
 * @code
 * size_t write_to_file(void *data, size_t size, size_t nmemb, void *userdata) {
 *     FILE *fp = (FILE *)userdata;
 *     return fwrite(data, size, nmemb, fp);
 * }
 * @endcode
 */
typedef size_t (*CurlWriteCallback) (void *data, size_t size, size_t nmemb,
                                      void *userdata);

/**
 * @brief Callback for reading data to send (request body).
 *
 * Called to read request body data. Fill buffer with up to size*nmemb bytes.
 * Return 0 to signal end of data, or CURL_READFUNC_ABORT to abort.
 *
 * @param buffer Buffer to fill with data
 * @param size Always 1
 * @param nmemb Maximum bytes to read
 * @param userdata User-provided pointer from CurlOptions
 * @return Number of bytes read, 0 for EOF, CURL_READFUNC_ABORT to abort
 */
typedef size_t (*CurlReadCallback) (void *buffer, size_t size, size_t nmemb,
                                     void *userdata);

/** @brief Return value to abort read callback. */
#define CURL_READFUNC_ABORT ((size_t)-1)

/**
 * @brief Callback for progress reporting.
 *
 * Called periodically during transfer. Return non-zero to abort.
 *
 * @param userdata User-provided pointer from CurlOptions
 * @param dltotal Total bytes to download (0 if unknown)
 * @param dlnow Bytes downloaded so far
 * @param ultotal Total bytes to upload (0 if unknown)
 * @param ulnow Bytes uploaded so far
 * @return 0 to continue, non-zero to abort
 */
typedef int (*CurlProgressCallback) (void *userdata, int64_t dltotal,
                                      int64_t dlnow, int64_t ultotal,
                                      int64_t ulnow);

/**
 * @brief Callback for receiving headers.
 *
 * Called for each header line received. Called after status line.
 *
 * @param data Header line data (includes trailing CRLF for HTTP/1.1)
 * @param size Always 1
 * @param nmemb Number of bytes in header line
 * @param userdata User-provided pointer from CurlOptions
 * @return Number of bytes handled (return != size*nmemb to abort)
 */
typedef size_t (*CurlHeaderCallback) (void *data, size_t size, size_t nmemb,
                                       void *userdata);

/** @} */

/**
 * @name Session State
 * @{
 */

/**
 * @brief Session state machine states.
 *
 * Tracks the current phase of an HTTP request/response cycle.
 */
typedef enum
{
  CURL_STATE_IDLE,             /**< No active request */
  CURL_STATE_CONNECTING,       /**< Establishing TCP connection */
  CURL_STATE_TLS_HANDSHAKE,    /**< Performing TLS handshake */
  CURL_STATE_SENDING_REQUEST,  /**< Sending request headers/body */
  CURL_STATE_READING_HEADERS,  /**< Reading response headers */
  CURL_STATE_READING_BODY,     /**< Reading response body */
  CURL_STATE_COMPLETE,         /**< Request completed successfully */
  CURL_STATE_ERROR             /**< Request failed with error */
} CurlState;

/** @} */

/**
 * @name Authentication
 * @{
 */

/**
 * @brief Authentication types.
 */
typedef enum
{
  CURL_AUTH_NONE = 0,  /**< No authentication */
  CURL_AUTH_BASIC,     /**< HTTP Basic authentication */
  CURL_AUTH_DIGEST,    /**< HTTP Digest authentication */
  CURL_AUTH_BEARER     /**< Bearer token authentication */
} CurlAuthType;

/**
 * @brief Authentication credentials.
 */
typedef struct
{
  CurlAuthType type;       /**< Authentication type */
  const char *username;    /**< Username (for Basic/Digest) */
  const char *password;    /**< Password (for Basic/Digest) */
  const char *token;       /**< Token (for Bearer) */
} CurlAuth;

/** @} */

/**
 * @name Parsed URL
 * @{
 */

/**
 * @brief Parsed URL components.
 *
 * Holds the components of a parsed URL. All strings are arena-allocated
 * and remain valid until the arena is freed.
 */
typedef struct
{
  char *scheme;       /**< "http" or "https" */
  size_t scheme_len;  /**< Length of scheme */
  char *userinfo;     /**< "user:pass" or NULL */
  size_t userinfo_len;/**< Length of userinfo */
  char *host;         /**< Hostname or IP address */
  size_t host_len;    /**< Length of host */
  int port;           /**< Port number (80, 443, or explicit) */
  char *path;         /**< Path starting with "/" */
  size_t path_len;    /**< Length of path */
  char *query;        /**< Query string (after ?) or NULL */
  size_t query_len;   /**< Length of query */
  char *fragment;     /**< Fragment (after #) or NULL */
  size_t fragment_len;/**< Length of fragment */
  int is_secure;      /**< 1 for https, 0 for http */
} CurlParsedURL;

/**
 * @brief Parse a URL string into components.
 *
 * Parses an absolute HTTP/HTTPS URL. Validates scheme, host, and port.
 * Returns error code for malformed URLs.
 *
 * @param url URL string to parse
 * @param len Length of URL (0 to use strlen)
 * @param result Output parsed URL structure
 * @param arena Arena for string allocations
 * @return CURL_OK on success, CURL_ERROR_INVALID_URL on failure
 */
extern CurlError Curl_parse_url (const char *url, size_t len,
                                  CurlParsedURL *result, Arena_T arena);

/**
 * @brief Get effective port from parsed URL.
 *
 * Returns the explicit port if present, otherwise the default port
 * for the scheme (80 for http, 443 for https).
 *
 * @param url Parsed URL
 * @return Port number
 */
extern int Curl_url_get_port (const CurlParsedURL *url);

/**
 * @brief Resolve a relative URL against a base URL.
 *
 * Handles relative paths, absolute paths, and full URLs.
 *
 * @param base Base URL (absolute)
 * @param relative Relative URL or absolute URL
 * @param result Output buffer for resolved URL
 * @param result_size Size of output buffer
 * @return Length written, or -1 on error
 */
extern ssize_t Curl_resolve_url (const CurlParsedURL *base,
                                  const char *relative,
                                  char *result, size_t result_size);

/** @} */

/**
 * @name Configuration Options
 * @{
 */

/**
 * @brief Configuration options for curl sessions.
 *
 * Initialize with Curl_options_defaults() before modifying.
 */
typedef struct
{
  /* Protocol settings */
  SocketHTTP_Version max_version;  /**< Maximum HTTP version (default: HTTP/2) */
  int allow_http2_cleartext;       /**< Allow HTTP/2 without TLS (default: 0) */

  /* Timeouts (milliseconds) */
  int connect_timeout_ms;          /**< Connection timeout (default: 30000) */
  int request_timeout_ms;          /**< Total request timeout (default: 0 = no limit) */
  int dns_timeout_ms;              /**< DNS resolution timeout (default: 5000) */

  /* Redirects */
  int follow_redirects;            /**< Follow redirects (default: 1) */
  int max_redirects;               /**< Maximum redirects (default: 50) */

  /* TLS settings */
  SocketTLSContext_T tls_context;  /**< Custom TLS context (NULL for default) */
  int verify_ssl;                  /**< Verify TLS certificates (default: 1) */

  /* Proxy settings */
  const char *proxy_url;           /**< Proxy URL (NULL for direct) */

  /* Request settings */
  const char *user_agent;          /**< User-Agent header (NULL for default) */
  int accept_encoding;             /**< Send Accept-Encoding (default: 1) */
  int auto_decompress;             /**< Auto-decompress responses (default: 1) */

  /* Callbacks */
  CurlWriteCallback write_callback;     /**< Body write callback */
  void *write_userdata;                 /**< User data for write callback */
  CurlReadCallback read_callback;       /**< Body read callback */
  void *read_userdata;                  /**< User data for read callback */
  CurlProgressCallback progress_callback; /**< Progress callback */
  void *progress_userdata;              /**< User data for progress callback */
  CurlHeaderCallback header_callback;   /**< Header callback */
  void *header_userdata;                /**< User data for header callback */

  /* Authentication */
  CurlAuth auth;                   /**< Authentication credentials */

  /* Cookie handling */
  const char *cookie_file;         /**< Cookie jar file (NULL for no cookies) */

  /* Retry settings */
  int enable_retry;                /**< Enable automatic retry (default: 0) */
  int max_retries;                 /**< Maximum retry attempts (default: 3) */
  int retry_on_connection_error;   /**< Retry on connection failure (default: 1) */
  int retry_on_timeout;            /**< Retry on timeout (default: 1) */
  int retry_on_5xx;                /**< Retry on 5xx responses (default: 0) */

  /* Verbose/debug */
  int verbose;                     /**< Enable verbose output (default: 0) */
} CurlOptions;

/**
 * @brief Initialize options with sensible defaults.
 *
 * Must be called before using a CurlOptions structure.
 *
 * @param options Options structure to initialize
 */
extern void Curl_options_defaults (CurlOptions *options);

/** @} */

/**
 * @name Response Information
 * @{
 */

/**
 * @brief Response information from a completed request.
 *
 * Contains status code and headers. Body is delivered via write callback.
 */
typedef struct
{
  int status_code;                 /**< HTTP status code (e.g., 200, 404) */
  SocketHTTP_Version version;      /**< HTTP version used */
  SocketHTTP_Headers_T headers;    /**< Response headers */
  int64_t content_length;          /**< Content-Length or -1 if chunked/unknown */
  size_t redirect_count;           /**< Number of redirects followed */
  CurlError error;                 /**< Error code if request failed */
} CurlResponse;

/** @} */

/**
 * @name Session Handle
 * @{
 */

/**
 * @brief Opaque session handle.
 *
 * Manages connection state, cookies, and can be reused for multiple requests.
 * Connection reuse is automatic for same-host requests.
 */
typedef struct CurlSession *CurlSession_T;

/**
 * @brief Create a new curl session.
 *
 * @param options Configuration options (NULL for defaults)
 * @return New session handle
 * @throws Curl_Failed if session creation fails
 */
extern CurlSession_T Curl_session_new (const CurlOptions *options);

/**
 * @brief Free a curl session.
 *
 * Closes any open connections and frees resources.
 *
 * @param session Pointer to session handle (set to NULL after free)
 */
extern void Curl_session_free (CurlSession_T *session);

/**
 * @brief Reset session state for a new request.
 *
 * Clears response data but keeps connections and cookies.
 *
 * @param session Session handle
 */
extern void Curl_session_reset (CurlSession_T session);

/**
 * @brief Get current session state.
 *
 * @param session Session handle
 * @return Current state
 */
extern CurlState Curl_session_state (CurlSession_T session);

/**
 * @brief Get last error from session.
 *
 * @param session Session handle
 * @return Last error code
 */
extern CurlError Curl_session_error (CurlSession_T session);

/**
 * @brief Get response information.
 *
 * Valid after request completion. Data is valid until next request or
 * session free.
 *
 * @param session Session handle
 * @return Pointer to response info (do not free)
 */
extern const CurlResponse *Curl_session_response (CurlSession_T session);

/** @} */

/**
 * @name Request Methods
 * @{
 */

/**
 * @brief Perform a GET request.
 *
 * Response body is delivered via write callback.
 *
 * @param session Session handle
 * @param url URL to fetch
 * @return CURL_OK on success, error code on failure
 */
extern CurlError Curl_get (CurlSession_T session, const char *url);

/**
 * @brief Perform a HEAD request.
 *
 * @param session Session handle
 * @param url URL to fetch
 * @return CURL_OK on success, error code on failure
 */
extern CurlError Curl_head (CurlSession_T session, const char *url);

/**
 * @brief Perform a POST request.
 *
 * Request body is read via read callback (if set) or from the provided data.
 *
 * @param session Session handle
 * @param url URL to post to
 * @param content_type Content-Type header value
 * @param body Request body data (NULL to use read callback)
 * @param body_len Length of body data
 * @return CURL_OK on success, error code on failure
 */
extern CurlError Curl_post (CurlSession_T session, const char *url,
                             const char *content_type, const void *body,
                             size_t body_len);

/**
 * @brief Perform a PUT request.
 *
 * @param session Session handle
 * @param url URL to put to
 * @param content_type Content-Type header value
 * @param body Request body data (NULL to use read callback)
 * @param body_len Length of body data
 * @return CURL_OK on success, error code on failure
 */
extern CurlError Curl_put (CurlSession_T session, const char *url,
                            const char *content_type, const void *body,
                            size_t body_len);

/**
 * @brief Perform a DELETE request.
 *
 * @param session Session handle
 * @param url URL to delete
 * @return CURL_OK on success, error code on failure
 */
extern CurlError Curl_delete (CurlSession_T session, const char *url);

/**
 * @brief Perform a request with custom method.
 *
 * @param session Session handle
 * @param method HTTP method
 * @param url URL
 * @param headers Additional headers (NULL for none)
 * @param body Request body (NULL for none)
 * @param body_len Length of body
 * @return CURL_OK on success, error code on failure
 */
extern CurlError Curl_request (CurlSession_T session, SocketHTTP_Method method,
                                const char *url, SocketHTTP_Headers_T headers,
                                const void *body, size_t body_len);

/** @} */

/**
 * @name Convenience Functions
 * @{
 */

/**
 * @brief One-shot GET request with write callback.
 *
 * Creates a temporary session, performs the request, and frees the session.
 *
 * @param url URL to fetch
 * @param write_cb Callback to receive response body
 * @param userdata User data for callback
 * @param options Options (NULL for defaults)
 * @return CURL_OK on success, error code on failure
 */
extern CurlError Curl_fetch (const char *url, CurlWriteCallback write_cb,
                              void *userdata, const CurlOptions *options);

/**
 * @brief Download a file.
 *
 * @param url URL to download
 * @param filepath Local file path to save to
 * @param options Options (NULL for defaults)
 * @return CURL_OK on success, error code on failure
 */
extern CurlError Curl_download (const char *url, const char *filepath,
                                 const CurlOptions *options);

/**
 * @brief Upload a file.
 *
 * @param url URL to upload to
 * @param filepath Local file path to upload
 * @param content_type Content-Type header value
 * @param options Options (NULL for defaults)
 * @return CURL_OK on success, error code on failure
 */
extern CurlError Curl_upload (const char *url, const char *filepath,
                               const char *content_type,
                               const CurlOptions *options);

/** @} */

/**
 * @name Session Configuration
 * @{
 */

/**
 * @brief Set custom header for all requests.
 *
 * @param session Session handle
 * @param name Header name
 * @param value Header value
 * @return 0 on success, -1 on error
 */
extern int Curl_session_set_header (CurlSession_T session, const char *name,
                                     const char *value);

/**
 * @brief Set authentication credentials.
 *
 * @param session Session handle
 * @param auth Authentication credentials
 */
extern void Curl_session_set_auth (CurlSession_T session, const CurlAuth *auth);

/**
 * @brief Update callbacks.
 *
 * @param session Session handle
 * @param write_cb Write callback (NULL to keep current)
 * @param write_userdata Write callback user data
 */
extern void Curl_session_set_write_callback (CurlSession_T session,
                                              CurlWriteCallback write_cb,
                                              void *write_userdata);

/**
 * @brief Update read callback.
 *
 * @param session Session handle
 * @param read_cb Read callback (NULL to keep current)
 * @param read_userdata Read callback user data
 */
extern void Curl_session_set_read_callback (CurlSession_T session,
                                             CurlReadCallback read_cb,
                                             void *read_userdata);

/** @} */

/** @} */

#endif /* STREAMINGCURL_INCLUDED */
