/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @defgroup http_client HTTP Client Module
 * @ingroup http
 * @brief High-level HTTP client with connection pooling, authentication, and
 * cookies.
 *
 * Features: HTTP/1.1 and HTTP/2 (ALPN), RFC 6265 cookies, Basic/Digest/Bearer
 * auth, compression, redirect following, configurable timeouts and retries.
 *
 * Thread safety: Client instances are NOT thread-safe. Cookie jar is
 * thread-safe.
 * @{
 */

/**
 * @file SocketHTTPClient.h
 * @ingroup http_client
 * @brief Public API for HTTP client module.
 */

#ifndef SOCKETHTTPCLIENT_INCLUDED
#define SOCKETHTTPCLIENT_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTPClient-config.h"

/* Forward declarations for optional TLS */
#if SOCKET_HAS_TLS
#include "tls/SocketTLSContext.h"
#else
typedef struct SocketTLSContext_T *SocketTLSContext_T;
#endif

/* ============================================================================
 * Exception Types
 * ============================================================================
 */

/** General client failure. Retryable: depends on cause. */
extern const Except_T SocketHTTPClient_Failed;

/** DNS resolution failure. Retryable: YES. */
extern const Except_T SocketHTTPClient_DNSFailed;

/** TCP connection failure. Retryable: YES. */
extern const Except_T SocketHTTPClient_ConnectFailed;

/** TLS/SSL handshake failure. Retryable: NO (config issue). */
extern const Except_T SocketHTTPClient_TLSFailed;

/** Request timeout exceeded. Retryable: YES. */
extern const Except_T SocketHTTPClient_Timeout;

/** HTTP protocol error. Retryable: NO (malformed response). */
extern const Except_T SocketHTTPClient_ProtocolError;

/** Redirect limit exceeded. Retryable: NO (redirect loop). */
extern const Except_T SocketHTTPClient_TooManyRedirects;

/** Response body exceeds limit. Retryable: NO. */
extern const Except_T SocketHTTPClient_ResponseTooLarge;

/* ============================================================================
 * Error Codes
 * ============================================================================
 */

/** Error codes for HTTP client operations. */
typedef enum
{
  HTTPCLIENT_OK = 0,
  HTTPCLIENT_ERROR_DNS,
  HTTPCLIENT_ERROR_CONNECT,
  HTTPCLIENT_ERROR_TLS,
  HTTPCLIENT_ERROR_TIMEOUT,
  HTTPCLIENT_ERROR_PROTOCOL,
  HTTPCLIENT_ERROR_TOO_MANY_REDIRECTS,
  HTTPCLIENT_ERROR_RESPONSE_TOO_LARGE,
  HTTPCLIENT_ERROR_CANCELLED,
  HTTPCLIENT_ERROR_OUT_OF_MEMORY,
  HTTPCLIENT_ERROR_LIMIT_EXCEEDED
} SocketHTTPClient_Error;

/**
 * @brief Check if error code is retryable.
 * @param error Error code
 * @return 1 if retryable, 0 if fatal
 */
extern int SocketHTTPClient_error_is_retryable (SocketHTTPClient_Error error);

/* ============================================================================
 * Authentication Types
 * ============================================================================
 */

/**
 * @brief Authentication scheme types.
 *
 * Supported: Basic (RFC 7617), Digest (RFC 7616), Bearer (RFC 6750).
 */
typedef enum
{
  HTTP_AUTH_NONE = 0,
  HTTP_AUTH_BASIC,
  HTTP_AUTH_DIGEST,
  HTTP_AUTH_BEARER
} SocketHTTPClient_AuthType;

/** Authentication credentials. */
typedef struct
{
  SocketHTTPClient_AuthType type;
  const char *username; /**< For Basic, Digest */
  const char *password; /**< For Basic, Digest */
  const char *token;    /**< For Bearer */
  const char *realm;    /**< Optional realm filter */
} SocketHTTPClient_Auth;

/* ============================================================================
 * Proxy Configuration
 * ============================================================================
 */

/** Proxy configuration (opaque). See include/socket/SocketProxy.h. */
typedef struct SocketProxy_Config SocketProxy_Config;

/* ============================================================================
 * Client Configuration
 * ============================================================================
 */

/** HTTP client configuration. */
typedef struct
{
  /* Protocol */
  SocketHTTP_Version max_version;
  int allow_http2_cleartext;

  /* Connection pooling */
  int enable_connection_pool;
  size_t max_connections_per_host;
  size_t max_total_connections;
  int idle_timeout_ms;
  int max_connection_age_ms;
  int acquire_timeout_ms;

  /* Timeouts */
  int connect_timeout_ms;
  int request_timeout_ms;
  int dns_timeout_ms;

  /* Redirects */
  int follow_redirects;
  int redirect_on_post;

  /* Compression */
  int accept_encoding; /**< Bitmask: GZIP | DEFLATE | BR */
  int auto_decompress;

  /* TLS */
  SocketTLSContext_T tls_context;
  int verify_ssl;

  /* Proxy */
  SocketProxy_Config *proxy;

  /* User agent */
  const char *user_agent;

  /* Limits */
  size_t max_response_size;

  /* Retry configuration */
  int enable_retry;
  int max_retries;
  int retry_initial_delay_ms;
  int retry_max_delay_ms;
  int retry_on_connection_error;
  int retry_on_timeout;
  int retry_on_5xx;

  /* Security */
  int enforce_samesite;
} SocketHTTPClient_Config;

/* ============================================================================
 * Opaque Types
 * ============================================================================
 */

typedef struct SocketHTTPClient *SocketHTTPClient_T;
typedef struct SocketHTTPClient_Request *SocketHTTPClient_Request_T;
typedef struct SocketHTTPClient_AsyncRequest *SocketHTTPClient_AsyncRequest_T;
typedef struct SocketHTTPClient_CookieJar *SocketHTTPClient_CookieJar_T;

/* ============================================================================
 * Response Structure
 * ============================================================================
 */

/** HTTP response. Caller must call SocketHTTPClient_Response_free(). */
typedef struct
{
  int status_code;
  SocketHTTP_Headers_T headers;
  void *body;
  size_t body_len;
  SocketHTTP_Version version;
  Arena_T arena;
} SocketHTTPClient_Response;

/* ============================================================================
 * Client Lifecycle
 * ============================================================================
 */

/**
 * @brief Initialize config with production-safe defaults.
 * @param config Config structure to initialize
 */
extern void SocketHTTPClient_config_defaults (SocketHTTPClient_Config *config);

/**
 * @brief Create new HTTP client instance.
 * @param config Configuration (NULL uses defaults)
 * @return Client handle or NULL on failure
 */
extern SocketHTTPClient_T
SocketHTTPClient_new (const SocketHTTPClient_Config *config);

/**
 * @brief Destroy HTTP client and release resources.
 * @param client Pointer to client handle (set to NULL)
 */
extern void SocketHTTPClient_free (SocketHTTPClient_T *client);

/* ============================================================================
 * Simple Synchronous API
 * ============================================================================
 */

/**
 * @brief Perform synchronous GET request.
 * @param client Client instance
 * @param url Full URL (http:// or https://)
 * @param response Output response (caller must free)
 * @return 0 on success, -1 on error
 */
extern int SocketHTTPClient_get (SocketHTTPClient_T client, const char *url,
                                 SocketHTTPClient_Response *response);

/**
 * @brief Perform synchronous HEAD request.
 * @param client Client instance
 * @param url Full URL
 * @param response Output response (caller must free)
 * @return 0 on success, -1 on error
 */
extern int SocketHTTPClient_head (SocketHTTPClient_T client, const char *url,
                                  SocketHTTPClient_Response *response);

/**
 * @brief Perform synchronous POST request.
 * @param client Client instance
 * @param url Full URL
 * @param content_type Content-Type header
 * @param body Request body data
 * @param body_len Body length
 * @param response Output response (caller must free)
 * @return 0 on success, -1 on error
 */
extern int SocketHTTPClient_post (SocketHTTPClient_T client, const char *url,
                                  const char *content_type, const void *body,
                                  size_t body_len,
                                  SocketHTTPClient_Response *response);

/**
 * @brief Perform synchronous PUT request.
 * @param client Client instance
 * @param url Full URL
 * @param content_type Content-Type header
 * @param body Request body data
 * @param body_len Body length
 * @param response Output response (caller must free)
 * @return 0 on success, -1 on error
 */
extern int SocketHTTPClient_put (SocketHTTPClient_T client, const char *url,
                                 const char *content_type, const void *body,
                                 size_t body_len,
                                 SocketHTTPClient_Response *response);

/**
 * @brief Perform synchronous DELETE request.
 * @param client Client instance
 * @param url Full URL
 * @param response Output response (caller must free)
 * @return 0 on success, -1 on error
 */
extern int SocketHTTPClient_delete (SocketHTTPClient_T client, const char *url,
                                    SocketHTTPClient_Response *response);

/**
 * @brief Free response resources.
 * @param response Response to free
 */
extern void
SocketHTTPClient_Response_free (SocketHTTPClient_Response *response);

/* ============================================================================
 * Custom Request API
 * ============================================================================
 */

/**
 * @brief Create request builder.
 * @param client Client instance
 * @param method HTTP method
 * @param url Full URL
 * @return Request builder
 */
extern SocketHTTPClient_Request_T
SocketHTTPClient_Request_new (SocketHTTPClient_T client,
                              SocketHTTP_Method method, const char *url);

/**
 * @brief Free request builder.
 * @param req Pointer to request handle (set to NULL)
 */
extern void SocketHTTPClient_Request_free (SocketHTTPClient_Request_T *req);

/**
 * @brief Add header to request.
 * @param req Request
 * @param name Header name
 * @param value Header value
 * @return 0 on success, -1 on error
 */
extern int SocketHTTPClient_Request_header (SocketHTTPClient_Request_T req,
                                            const char *name,
                                            const char *value);

/**
 * @brief Set request body.
 * @param req Request
 * @param data Body data
 * @param len Data length
 * @return 0 on success, -1 on error
 */
extern int SocketHTTPClient_Request_body (SocketHTTPClient_Request_T req,
                                          const void *data, size_t len);

/**
 * @brief Set streaming body.
 * @param req Request
 * @param read_cb Callback to read body data
 * @param userdata User data for callback
 * @return 0 on success, -1 on error
 */
extern int SocketHTTPClient_Request_body_stream (
    SocketHTTPClient_Request_T req,
    ssize_t (*read_cb) (void *buf, size_t len, void *userdata),
    void *userdata);

/**
 * @brief Set per-request timeout.
 * @param req Request
 * @param ms Timeout in milliseconds
 */
extern void SocketHTTPClient_Request_timeout (SocketHTTPClient_Request_T req,
                                              int ms);

/**
 * @brief Set per-request authentication.
 * @param req Request
 * @param auth Authentication credentials
 */
extern void SocketHTTPClient_Request_auth (SocketHTTPClient_Request_T req,
                                           const SocketHTTPClient_Auth *auth);

/**
 * @brief Execute request.
 * @param req Request
 * @param response Output response
 * @return 0 on success, -1 on error
 */
extern int
SocketHTTPClient_Request_execute (SocketHTTPClient_Request_T req,
                                  SocketHTTPClient_Response *response);

/* ============================================================================
 * Asynchronous API
 * ============================================================================
 */

/** Async completion callback. */
typedef void (*SocketHTTPClient_Callback) (SocketHTTPClient_AsyncRequest_T req,
                                           SocketHTTPClient_Response *response,
                                           SocketHTTPClient_Error error,
                                           void *userdata);

/** Start async GET. */
extern SocketHTTPClient_AsyncRequest_T
SocketHTTPClient_get_async (SocketHTTPClient_T client, const char *url,
                            SocketHTTPClient_Callback callback,
                            void *userdata);

/** Start async POST. */
extern SocketHTTPClient_AsyncRequest_T SocketHTTPClient_post_async (
    SocketHTTPClient_T client, const char *url, const char *content_type,
    const void *body, size_t body_len, SocketHTTPClient_Callback callback,
    void *userdata);

/** Start async custom request. */
extern SocketHTTPClient_AsyncRequest_T
SocketHTTPClient_Request_async (SocketHTTPClient_Request_T req,
                                SocketHTTPClient_Callback callback,
                                void *userdata);

/** Cancel async request. */
extern void
SocketHTTPClient_AsyncRequest_cancel (SocketHTTPClient_AsyncRequest_T req);

/**
 * @brief Process async requests.
 * @param client Client
 * @param timeout_ms Poll timeout
 * @return Number of completed requests
 */
extern int SocketHTTPClient_process (SocketHTTPClient_T client,
                                     int timeout_ms);

/* ============================================================================
 * Cookie Jar (RFC 6265)
 * ============================================================================
 */

/** Cookie SameSite attribute (RFC 6265bis). */
typedef enum
{
  COOKIE_SAMESITE_NONE = 0,
  COOKIE_SAMESITE_LAX = 1,
  COOKIE_SAMESITE_STRICT = 2
} SocketHTTPClient_SameSite;

/** Cookie attributes (RFC 6265). */
typedef struct
{
  const char *name;
  const char *value;
  const char *domain;
  const char *path;
  time_t expires;
  int secure;
  int http_only;
  SocketHTTPClient_SameSite same_site;
} SocketHTTPClient_Cookie;

/** Create cookie jar. */
extern SocketHTTPClient_CookieJar_T SocketHTTPClient_CookieJar_new (void);

/** Free cookie jar. */
extern void
SocketHTTPClient_CookieJar_free (SocketHTTPClient_CookieJar_T *jar);

/** Associate jar with client. */
extern void SocketHTTPClient_set_cookie_jar (SocketHTTPClient_T client,
                                             SocketHTTPClient_CookieJar_T jar);

/** Get associated cookie jar. */
extern SocketHTTPClient_CookieJar_T
SocketHTTPClient_get_cookie_jar (SocketHTTPClient_T client);

/** Set cookie. */
extern int
SocketHTTPClient_CookieJar_set (SocketHTTPClient_CookieJar_T jar,
                                const SocketHTTPClient_Cookie *cookie);

/** Get cookie by name. */
extern const SocketHTTPClient_Cookie *
SocketHTTPClient_CookieJar_get (SocketHTTPClient_CookieJar_T jar,
                                const char *domain, const char *path,
                                const char *name);

/** Clear all cookies. */
extern void
SocketHTTPClient_CookieJar_clear (SocketHTTPClient_CookieJar_T jar);

/** Clear expired cookies. */
extern void
SocketHTTPClient_CookieJar_clear_expired (SocketHTTPClient_CookieJar_T jar);

/** Load cookies from file. */
extern int SocketHTTPClient_CookieJar_load (SocketHTTPClient_CookieJar_T jar,
                                            const char *filename);

/** Save cookies to file. */
extern int SocketHTTPClient_CookieJar_save (SocketHTTPClient_CookieJar_T jar,
                                            const char *filename);

/* ============================================================================
 * Client Authentication
 * ============================================================================
 */

/**
 * @brief Set default authentication for all requests.
 * @param client Client instance
 * @param auth Authentication config (NULL to disable)
 */
extern void SocketHTTPClient_set_auth (SocketHTTPClient_T client,
                                       const SocketHTTPClient_Auth *auth);

/* ============================================================================
 * Connection Pool Management
 * ============================================================================
 */

/** Connection pool statistics. */
typedef struct
{
  size_t active_connections;
  size_t idle_connections;
  size_t total_requests;
  size_t reused_connections;
  size_t connections_created;
  size_t connections_failed;
  size_t connections_timed_out;
  size_t stale_connections_removed;
  size_t pool_exhausted_waits;
} SocketHTTPClient_PoolStats;

/** Get pool statistics. */
extern void SocketHTTPClient_pool_stats (SocketHTTPClient_T client,
                                         SocketHTTPClient_PoolStats *stats);

/** Close all pooled connections. */
extern void SocketHTTPClient_pool_clear (SocketHTTPClient_T client);

/* ============================================================================
 * Error Handling
 * ============================================================================
 */

/** Get last error code. */
extern SocketHTTPClient_Error
SocketHTTPClient_last_error (SocketHTTPClient_T client);

/** Get error description (static string). */
extern const char *
SocketHTTPClient_error_string (SocketHTTPClient_Error error);

/* ============================================================================
 * Convenience Functions
 * ============================================================================
 */

/**
 * @brief Download URL content to file.
 * @param client HTTP client
 * @param url URL to download
 * @param filepath Destination path
 * @return 0 on success, -1 on HTTP error, -2 on file error
 */
extern int SocketHTTPClient_download (SocketHTTPClient_T client, const char *url,
                                      const char *filepath);

/**
 * @brief Upload file to URL.
 * @param client HTTP client
 * @param url Destination URL
 * @param filepath Source file path
 * @return HTTP status code on success, -1 on HTTP error, -2 on file error
 */
extern int SocketHTTPClient_upload (SocketHTTPClient_T client, const char *url,
                                    const char *filepath);

/**
 * @brief GET with JSON response.
 * @param client HTTP client
 * @param url URL to fetch
 * @param json_out Output JSON string (caller must free)
 * @param json_len Output JSON length
 * @return HTTP status on success, -1 on HTTP error, -2 on content-type mismatch
 */
extern int SocketHTTPClient_json_get (SocketHTTPClient_T client, const char *url,
                                      char **json_out, size_t *json_len);

/**
 * @brief POST JSON and receive JSON response.
 * @param client HTTP client
 * @param url Destination URL
 * @param json_body JSON to send
 * @param json_out Output JSON response (caller must free)
 * @param json_len Output JSON length
 * @return HTTP status on success, -1 on HTTP error, -2 on content-type mismatch
 */
extern int SocketHTTPClient_json_post (SocketHTTPClient_T client,
                                       const char *url, const char *json_body,
                                       char **json_out, size_t *json_len);

/** @} */

#endif /* SOCKETHTTPCLIENT_INCLUDED */
