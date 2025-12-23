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

extern const Except_T SocketHTTPClient_Failed;
extern const Except_T SocketHTTPClient_DNSFailed;
extern const Except_T SocketHTTPClient_ConnectFailed;
extern const Except_T SocketHTTPClient_TLSFailed;
extern const Except_T SocketHTTPClient_Timeout;
extern const Except_T SocketHTTPClient_ProtocolError;
extern const Except_T SocketHTTPClient_TooManyRedirects;
extern const Except_T SocketHTTPClient_ResponseTooLarge;

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

extern int SocketHTTPClient_error_is_retryable (SocketHTTPClient_Error error);

typedef enum
{
  HTTP_AUTH_NONE = 0,
  HTTP_AUTH_BASIC,
  HTTP_AUTH_DIGEST,
  HTTP_AUTH_BEARER
} SocketHTTPClient_AuthType;

typedef struct
{
  SocketHTTPClient_AuthType type;
  const char *username;
  const char *password;
  const char *token;
  const char *realm;
} SocketHTTPClient_Auth;

typedef struct SocketProxy_Config SocketProxy_Config;

typedef struct
{
  SocketHTTP_Version max_version;
  int allow_http2_cleartext;

  int enable_connection_pool;
  size_t max_connections_per_host;
  size_t max_total_connections;
  int idle_timeout_ms;
  int max_connection_age_ms;
  int acquire_timeout_ms;

  int connect_timeout_ms;
  int request_timeout_ms;
  int dns_timeout_ms;

  int follow_redirects;
  int redirect_on_post;

  int accept_encoding;
  int auto_decompress;

  SocketTLSContext_T tls_context;
  int verify_ssl;

  SocketProxy_Config *proxy;

  const char *user_agent;

  size_t max_response_size;

  int enable_retry;
  int max_retries;
  int retry_initial_delay_ms;
  int retry_max_delay_ms;
  int retry_on_connection_error;
  int retry_on_timeout;
  int retry_on_5xx;

  int enforce_samesite;

  int discard_body; /**< Discard response body (benchmark mode) */
} SocketHTTPClient_Config;

typedef struct SocketHTTPClient *SocketHTTPClient_T;
typedef struct SocketHTTPClient_Request *SocketHTTPClient_Request_T;
typedef struct SocketHTTPClient_AsyncRequest *SocketHTTPClient_AsyncRequest_T;
typedef struct SocketHTTPClient_CookieJar *SocketHTTPClient_CookieJar_T;

typedef struct
{
  int status_code;
  SocketHTTP_Headers_T headers;
  void *body;
  size_t body_len;
  SocketHTTP_Version version;
  Arena_T arena;
} SocketHTTPClient_Response;

extern void SocketHTTPClient_config_defaults (SocketHTTPClient_Config *config);
extern SocketHTTPClient_T
SocketHTTPClient_new (const SocketHTTPClient_Config *config);
extern void SocketHTTPClient_free (SocketHTTPClient_T *client);

extern int SocketHTTPClient_get (SocketHTTPClient_T client, const char *url,
                                 SocketHTTPClient_Response *response);
extern int SocketHTTPClient_head (SocketHTTPClient_T client, const char *url,
                                  SocketHTTPClient_Response *response);
extern int SocketHTTPClient_post (SocketHTTPClient_T client, const char *url,
                                  const char *content_type, const void *body,
                                  size_t body_len,
                                  SocketHTTPClient_Response *response);
extern int SocketHTTPClient_put (SocketHTTPClient_T client, const char *url,
                                 const char *content_type, const void *body,
                                 size_t body_len,
                                 SocketHTTPClient_Response *response);
extern int SocketHTTPClient_delete (SocketHTTPClient_T client, const char *url,
                                    SocketHTTPClient_Response *response);
extern void
SocketHTTPClient_Response_free (SocketHTTPClient_Response *response);

extern SocketHTTPClient_Request_T
SocketHTTPClient_Request_new (SocketHTTPClient_T client,
                              SocketHTTP_Method method, const char *url);
extern void SocketHTTPClient_Request_free (SocketHTTPClient_Request_T *req);
extern int SocketHTTPClient_Request_header (SocketHTTPClient_Request_T req,
                                            const char *name,
                                            const char *value);
extern int SocketHTTPClient_Request_body (SocketHTTPClient_Request_T req,
                                          const void *data, size_t len);
extern int SocketHTTPClient_Request_body_stream (
    SocketHTTPClient_Request_T req,
    ssize_t (*read_cb) (void *buf, size_t len, void *userdata),
    void *userdata);
extern void SocketHTTPClient_Request_timeout (SocketHTTPClient_Request_T req,
                                              int ms);
extern void SocketHTTPClient_Request_auth (SocketHTTPClient_Request_T req,
                                           const SocketHTTPClient_Auth *auth);
extern int
SocketHTTPClient_Request_execute (SocketHTTPClient_Request_T req,
                                  SocketHTTPClient_Response *response);

/**
 * @brief Opaque prepared request handle for high-throughput use cases.
 *
 * Caches parsed URI, pre-built Host header, and pool lookup key to eliminate
 * per-request parsing overhead. Use for repeated requests to the same URL.
 */
typedef struct SocketHTTPClient_PreparedRequest
    *SocketHTTPClient_PreparedRequest_T;

/**
 * @brief Prepare a request for repeated execution.
 *
 * Parses URL once and caches Host header and pool key. Returns NULL on error.
 * Call SocketHTTPClient_PreparedRequest_free() when done.
 *
 * @param client HTTP client
 * @param method HTTP method (GET, POST, etc.)
 * @param url Full URL to request
 * @return Prepared request handle, or NULL on error
 */
extern SocketHTTPClient_PreparedRequest_T
SocketHTTPClient_prepare (SocketHTTPClient_T client, SocketHTTP_Method method,
                          const char *url);

/**
 * @brief Execute a prepared request.
 *
 * Uses cached URI and headers - no re-parsing. Thread-safe.
 *
 * @param prep Prepared request handle
 * @param response Output response (caller must free)
 * @return 0 on success, -1 on error
 */
extern int SocketHTTPClient_execute_prepared (
    SocketHTTPClient_PreparedRequest_T prep,
    SocketHTTPClient_Response *response);

/**
 * @brief Free a prepared request.
 *
 * @param prep Pointer to prepared request handle (set to NULL after free)
 */
extern void SocketHTTPClient_PreparedRequest_free (
    SocketHTTPClient_PreparedRequest_T *prep);

typedef void (*SocketHTTPClient_Callback) (SocketHTTPClient_AsyncRequest_T req,
                                           SocketHTTPClient_Response *response,
                                           SocketHTTPClient_Error error,
                                           void *userdata);

extern SocketHTTPClient_AsyncRequest_T
SocketHTTPClient_get_async (SocketHTTPClient_T client, const char *url,
                            SocketHTTPClient_Callback callback,
                            void *userdata);
extern SocketHTTPClient_AsyncRequest_T SocketHTTPClient_post_async (
    SocketHTTPClient_T client, const char *url, const char *content_type,
    const void *body, size_t body_len, SocketHTTPClient_Callback callback,
    void *userdata);
extern SocketHTTPClient_AsyncRequest_T
SocketHTTPClient_Request_async (SocketHTTPClient_Request_T req,
                                SocketHTTPClient_Callback callback,
                                void *userdata);
extern void
SocketHTTPClient_AsyncRequest_cancel (SocketHTTPClient_AsyncRequest_T req);
extern int SocketHTTPClient_process (SocketHTTPClient_T client,
                                     int timeout_ms);

typedef enum
{
  COOKIE_SAMESITE_NONE = 0,
  COOKIE_SAMESITE_LAX = 1,
  COOKIE_SAMESITE_STRICT = 2
} SocketHTTPClient_SameSite;

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

extern SocketHTTPClient_CookieJar_T SocketHTTPClient_CookieJar_new (void);
extern void
SocketHTTPClient_CookieJar_free (SocketHTTPClient_CookieJar_T *jar);
extern void SocketHTTPClient_set_cookie_jar (SocketHTTPClient_T client,
                                             SocketHTTPClient_CookieJar_T jar);
extern SocketHTTPClient_CookieJar_T
SocketHTTPClient_get_cookie_jar (SocketHTTPClient_T client);
extern int
SocketHTTPClient_CookieJar_set (SocketHTTPClient_CookieJar_T jar,
                                const SocketHTTPClient_Cookie *cookie);
extern const SocketHTTPClient_Cookie *
SocketHTTPClient_CookieJar_get (SocketHTTPClient_CookieJar_T jar,
                                const char *domain, const char *path,
                                const char *name);
extern void
SocketHTTPClient_CookieJar_clear (SocketHTTPClient_CookieJar_T jar);
extern void
SocketHTTPClient_CookieJar_clear_expired (SocketHTTPClient_CookieJar_T jar);
extern int SocketHTTPClient_CookieJar_load (SocketHTTPClient_CookieJar_T jar,
                                            const char *filename);
extern int SocketHTTPClient_CookieJar_save (SocketHTTPClient_CookieJar_T jar,
                                            const char *filename);

extern void SocketHTTPClient_set_auth (SocketHTTPClient_T client,
                                       const SocketHTTPClient_Auth *auth);

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

extern void SocketHTTPClient_pool_stats (SocketHTTPClient_T client,
                                         SocketHTTPClient_PoolStats *stats);
extern void SocketHTTPClient_pool_clear (SocketHTTPClient_T client);

extern SocketHTTPClient_Error
SocketHTTPClient_last_error (SocketHTTPClient_T client);
extern const char *
SocketHTTPClient_error_string (SocketHTTPClient_Error error);

extern int SocketHTTPClient_download (SocketHTTPClient_T client, const char *url,
                                      const char *filepath);
extern int SocketHTTPClient_upload (SocketHTTPClient_T client, const char *url,
                                    const char *filepath);
extern int SocketHTTPClient_json_get (SocketHTTPClient_T client, const char *url,
                                      char **json_out, size_t *json_len);
extern int SocketHTTPClient_json_post (SocketHTTPClient_T client,
                                       const char *url, const char *json_body,
                                       char **json_out, size_t *json_len);

/** @} */

#endif /* SOCKETHTTPCLIENT_INCLUDED */
