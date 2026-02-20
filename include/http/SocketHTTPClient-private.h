/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTPClient-private.h
 * @brief Internal HTTP client structures and connection pooling.
 * @ingroup http
 *
 * NOT for public consumption - use SocketHTTPClient.h instead.
 */

#ifndef SOCKETHTTPCLIENT_PRIVATE_INCLUDED
#define SOCKETHTTPCLIENT_PRIVATE_INCLUDED

#include "core/SocketUtil.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"
#include "http/SocketHTTP2.h"
#include "http/SocketHTTPClient-config.h"
#include "http/SocketHTTPClient.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"

/* Forward declare SocketAsync_T to avoid circular includes */
#ifndef SOCKETASYNC_INCLUDED
struct SocketAsync_T;
typedef struct SocketAsync_T *SocketAsync_T;
#endif

#include <pthread.h>
#include <time.h>

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "HTTPClient"

#define HTTPCLIENT_ERROR_FMT(fmt, ...) SOCKET_ERROR_FMT (fmt, ##__VA_ARGS__)
#define HTTPCLIENT_ERROR_MSG(fmt, ...) SOCKET_ERROR_MSG (fmt, ##__VA_ARGS__)
#define RAISE_HTTPCLIENT_ERROR(e) \
  SOCKET_RAISE_MODULE_ERROR (SocketHTTPClient, e)

/**
 * @brief Response body accumulator state.
 *
 * Used by both HTTP/1.1 and HTTP/2 response parsing for collecting
 * body data with size limits and benchmark/discard mode support.
 */
typedef struct HTTPBodyAccumulator
{
  char *body_buf;
  size_t total_body;
  size_t body_capacity;
  size_t max_size;  /**< Maximum allowed size (0 = unlimited) */
  int discard_body; /**< Benchmark mode: count bytes, skip memcpy */
  Arena_T arena;
} HTTPBodyAccumulator;

/**
 * @brief HTTP connection pool entry for host:port reuse.
 * @ingroup http
 */
typedef struct HTTPPoolEntry
{
  char *host;
  int port;
  int is_secure;
  char sni_hostname[256];

  SocketHTTP_Version version;

  union
  {
    struct
    {
      Socket_T socket;
      SocketHTTP1_Parser_T parser;
      SocketBuf_T inbuf;
      SocketBuf_T outbuf;
      Arena_T conn_arena;
    } h1;
    struct
    {
      SocketHTTP2_Conn_T conn;
      int active_streams;
    } h2;
  } proto;

  time_t created_at;
  time_t last_used;
  int in_use;
  int closed;

  struct HTTPPoolEntry *hash_next;
  struct HTTPPoolEntry *next;
  struct HTTPPoolEntry *prev;
} HTTPPoolEntry;

/**
 * @brief HTTP connection pool with per-host limits.
 * @ingroup http
 */
typedef struct HTTPPool
{
  HTTPPoolEntry **hash_table;
  size_t hash_size;

  HTTPPoolEntry *all_conns;
  HTTPPoolEntry *free_entries;

  size_t max_per_host;
  size_t max_total;
  size_t current_count;
  int idle_timeout_ms;

  Arena_T arena;
  pthread_mutex_t mutex;

  size_t total_requests;
  size_t reused_connections;
  size_t connections_failed;
} HTTPPool;

/**
 * @brief Main HTTP client instance.
 * @ingroup http
 */
struct SocketHTTPClient
{
  SocketHTTPClient_Config config;

  HTTPPool *pool;

  SocketHTTPClient_Auth *default_auth;

  SocketHTTPClient_CookieJar_T cookie_jar;

#if SOCKET_HAS_TLS
  SocketTLSContext_T default_tls_ctx;
#endif

  SocketHTTPClient_Error last_error;

  pthread_mutex_t mutex;

  Arena_T arena;

  /**
   * @brief Async I/O context for io_uring operations (optional).
   *
   * Non-NULL when config.enable_async_io is set and io_uring is available.
   * Used by httpclient_send_async() and httpclient_recv_async().
   */
  SocketAsync_T async;

  /**
   * @brief Tracks whether async I/O is actually available.
   *
   * Set to 1 if async != NULL and SocketAsync_is_available() returns true.
   * Used for fast path checking in I/O functions.
   */
  int async_available;
};

/**
 * @brief Per-request builder and state.
 * @ingroup http
 */
struct SocketHTTPClient_Request
{
  SocketHTTPClient_T client;

  SocketHTTP_Method method;
  SocketHTTP_URI uri;

  SocketHTTP_Headers_T headers;

  void *body;
  size_t body_len;
  ssize_t (*body_stream_cb) (void *buf, size_t len, void *userdata);
  void *body_stream_userdata;

  int timeout_ms;
  SocketHTTPClient_Auth *auth;

  Arena_T arena;
};

/**
 * @brief Cached request data for high-throughput execution.
 *
 * Pre-computed values to eliminate per-request overhead:
 * - Parsed URI (eliminates SocketHTTP_URI_parse call)
 * - Host header string (eliminates snprintf formatting)
 * - Pool hash key (eliminates strlen + hash computation)
 */
struct SocketHTTPClient_PreparedRequest
{
  SocketHTTPClient_T client;
  SocketHTTP_Method method;
  SocketHTTP_URI uri;
  char *host_header;
  size_t host_header_len;
  unsigned pool_hash;
  int is_secure;
  int effective_port;
  Arena_T arena;
};

/**
 * @brief Individual cookie storage entry.
 * @ingroup http
 */
typedef struct CookieEntry
{
  SocketHTTPClient_Cookie cookie;
  time_t created;
  struct CookieEntry *next;
} CookieEntry;

/**
 * @brief Cookie jar for storing HTTP cookies per domain.
 * @ingroup http
 */
struct SocketHTTPClient_CookieJar
{
  CookieEntry **hash_table;
  size_t hash_size;
  size_t count;
  size_t max_cookies;
  unsigned hash_seed;
  Arena_T arena;
  pthread_mutex_t mutex;
};

extern HTTPPool *
httpclient_pool_new (Arena_T arena, const SocketHTTPClient_Config *config);
extern void httpclient_pool_free (HTTPPool *pool);
extern HTTPPoolEntry *
httpclient_pool_get (HTTPPool *pool, const char *host, int port, int is_secure);
extern HTTPPoolEntry *httpclient_pool_get_prepared (HTTPPool *pool,
                                                    const char *host,
                                                    size_t host_len,
                                                    int port,
                                                    int is_secure,
                                                    unsigned precomputed_hash);
extern void httpclient_pool_release (HTTPPool *pool, HTTPPoolEntry *entry);
extern void httpclient_pool_close (HTTPPool *pool, HTTPPoolEntry *entry);
extern void httpclient_pool_cleanup_idle (HTTPPool *pool);

extern HTTPPoolEntry *
httpclient_connect (SocketHTTPClient_T client, const SocketHTTP_URI *uri);
extern int
httpclient_send_request (HTTPPoolEntry *conn, SocketHTTPClient_Request_T req);
extern int httpclient_receive_response (HTTPPoolEntry *conn,
                                        SocketHTTPClient_Response *response,
                                        Arena_T arena);
#define HTTPCLIENT_DIGEST_REALM_MAX_LEN 128
#define HTTPCLIENT_DIGEST_NONCE_MAX_LEN 128
#define HTTPCLIENT_DIGEST_OPAQUE_MAX_LEN 128
#define HTTPCLIENT_DIGEST_QOP_MAX_LEN 64
#define HTTPCLIENT_DIGEST_ALGORITHM_MAX_LEN 32
#define HTTPCLIENT_DIGEST_PARAM_NAME_MAX_LEN 32
#define HTTPCLIENT_DIGEST_VALUE_MAX_LEN 256

#define HTTPCLIENT_DIGEST_TOKEN_AUTH "auth"
#define HTTPCLIENT_DIGEST_TOKEN_AUTH_LEN 4
#define HTTPCLIENT_DIGEST_TOKEN_TRUE "true"
#define HTTPCLIENT_DIGEST_TOKEN_TRUE_LEN 4
#define HTTPCLIENT_DIGEST_TOKEN_STALE "stale"
#define HTTPCLIENT_DIGEST_TOKEN_STALE_LEN 5

#define HTTPCLIENT_DIGEST_PREFIX "Digest "
#define HTTPCLIENT_DIGEST_PREFIX_LEN 7
#define HTTPCLIENT_BASIC_PREFIX "Basic "
#define HTTPCLIENT_BASIC_PREFIX_LEN 6
#define HTTPCLIENT_BEARER_PREFIX "Bearer "
#define HTTPCLIENT_BEARER_PREFIX_LEN 7

#define HTTPCLIENT_DIGEST_BASIC_PREFIX HTTPCLIENT_BASIC_PREFIX
#define HTTPCLIENT_DIGEST_BASIC_PREFIX_LEN HTTPCLIENT_BASIC_PREFIX_LEN

#define HTTPCLIENT_DIGEST_HEX_SIZE (SOCKET_CRYPTO_SHA256_SIZE * 2 + 1)

#define HTTPCLIENT_DIGEST_CNONCE_SIZE 16

#define HTTPCLIENT_DIGEST_A_BUFFER_SIZE 512

extern int httpclient_auth_basic_header (const char *username,
                                         const char *password,
                                         char *output,
                                         size_t output_size);
extern int httpclient_auth_digest_response (const char *username,
                                            const char *password,
                                            const char *realm,
                                            const char *nonce,
                                            const char *uri,
                                            const char *method,
                                            const char *qop,
                                            const char *nc,
                                            const char *cnonce,
                                            int use_sha256,
                                            char *output,
                                            size_t output_size);
extern int httpclient_auth_digest_challenge (const char *www_authenticate,
                                             const char *username,
                                             const char *password,
                                             const char *method,
                                             const char *uri,
                                             const char *nc_value,
                                             char *output,
                                             size_t output_size);
extern int httpclient_auth_bearer_header (const char *token,
                                          char *output,
                                          size_t output_size);
extern int httpclient_auth_is_stale_nonce (const char *www_authenticate);
extern void httpclient_auth_clear_header (char *header, size_t header_size);

extern int httpclient_cookies_for_request (SocketHTTPClient_CookieJar_T jar,
                                           const SocketHTTP_URI *uri,
                                           char *output,
                                           size_t output_size,
                                           int enforce_samesite);
extern int httpclient_parse_set_cookie (const char *value,
                                        size_t len,
                                        const SocketHTTP_URI *request_uri,
                                        SocketHTTPClient_Cookie *cookie,
                                        Arena_T arena);

static inline unsigned
httpclient_host_hash (const char *host, int port, size_t table_size)
{
  size_t host_len = strlen (host);
  unsigned host_hash
      = socket_util_hash_djb2_ci_len (host, host_len, table_size);
  unsigned port_hash = socket_util_hash_uint ((unsigned)port, table_size);
  unsigned combined = host_hash ^ port_hash;
  return socket_util_hash_uint (combined, table_size);
}

/**
 * @brief Compute pool hash with pre-known host length (no strlen).
 *
 * Used by prepared requests to avoid strlen() on every request.
 */
static inline unsigned
httpclient_host_hash_len (const char *host,
                          size_t host_len,
                          int port,
                          size_t table_size)
{
  unsigned host_hash
      = socket_util_hash_djb2_ci_len (host, host_len, table_size);
  unsigned port_hash = socket_util_hash_uint ((unsigned)port, table_size);
  unsigned combined = host_hash ^ port_hash;
  return socket_util_hash_uint (combined, table_size);
}

extern int httpclient_should_retry_error (const SocketHTTPClient_T client,
                                          SocketHTTPClient_Error error);
extern int
httpclient_should_retry_status (const SocketHTTPClient_T client, int status);
extern int
httpclient_should_retry_status_with_method (const SocketHTTPClient_T client,
                                            int status,
                                            SocketHTTP_Method method);
extern int
httpclient_calculate_retry_delay (const SocketHTTPClient_T client, int attempt);
extern void httpclient_retry_sleep_ms (int ms);
extern int httpclient_grow_body_buffer (Arena_T arena,
                                        char **buf,
                                        size_t *capacity,
                                        size_t *total,
                                        size_t needed,
                                        size_t max_size);
extern void
httpclient_clear_response_for_retry (SocketHTTPClient_Response *response);

/* Thread-local arena cache functions (SocketHTTPClient-arena.c)
 * Eliminate per-request malloc/pthread_mutex_init overhead by caching
 * arenas in thread-local storage and using Arena_clear() for reset. */
extern Arena_T httpclient_acquire_request_arena (void);
extern void httpclient_release_request_arena (Arena_T *arena_ptr);
extern Arena_T httpclient_acquire_response_arena (void);
extern void httpclient_release_response_arena (Arena_T *arena_ptr);

/* Async I/O wrapper functions (SocketHTTPClient-async.c)
 * Provide synchronous-looking I/O that uses io_uring internally
 * when enabled. Falls back to standard Socket_send/recv if unavailable. */

/**
 * @brief Send data using async I/O if available, otherwise sync.
 *
 * When client->async_available is true, submits send to io_uring
 * and blocks until completion. Otherwise falls back to Socket_send().
 *
 * @param client HTTP client with optional async context
 * @param socket Socket to send on
 * @param data Data buffer to send
 * @param len Number of bytes to send
 * @return Bytes sent on success, -1 on error (errno set)
 */
extern ssize_t httpclient_io_send (SocketHTTPClient_T client,
                                   Socket_T socket,
                                   const void *data,
                                   size_t len);

/**
 * @brief Receive data using async I/O if available, otherwise sync.
 *
 * When client->async_available is true, submits recv to io_uring
 * and blocks until completion. Otherwise falls back to Socket_recv().
 *
 * @param client HTTP client with optional async context
 * @param socket Socket to receive from
 * @param buf Buffer for received data
 * @param len Maximum bytes to receive
 * @return Bytes received on success, 0 on EOF, -1 on error (errno set)
 */
extern ssize_t httpclient_io_recv (SocketHTTPClient_T client,
                                   Socket_T socket,
                                   void *buf,
                                   size_t len);

/**
 * @brief Initialize async I/O context for HTTP client.
 *
 * Called from SocketHTTPClient_new() when config.enable_async_io is set.
 * Creates SocketAsync context and checks if io_uring is available.
 *
 * @param client HTTP client to initialize
 * @return 0 on success, -1 on failure (falls back to sync I/O)
 */
extern int httpclient_async_init (SocketHTTPClient_T client);

/**
 * @brief Cleanup async I/O context for HTTP client.
 *
 * Called from SocketHTTPClient_free().
 *
 * @param client HTTP client to cleanup
 */
extern void httpclient_async_cleanup (SocketHTTPClient_T client);

/**
 * @brief Get effective auth (request-level or client default).
 */
static inline SocketHTTPClient_Auth *
httpclient_get_effective_auth (SocketHTTPClient_T client,
                               SocketHTTPClient_Request_T req)
{
  return req->auth != NULL ? req->auth : client->default_auth;
}

/**
 * @brief Get path from URI, defaulting to "/" if NULL.
 */
static inline const char *
httpclient_get_path_or_root (const SocketHTTP_URI *uri)
{
  return uri->path != NULL ? uri->path : "/";
}

/**
 * @brief Validate hostname for control characters.
 * SECURITY: Prevents CRLF injection in Host header.
 * @return 1 if safe, 0 if contains control characters
 */
static inline int
hostname_safe (const char *host, size_t len)
{
  for (size_t i = 0; i < len; i++)
    {
      unsigned char c = (unsigned char)host[i];
      if (c == '\r' || c == '\n' || c == '\0' || c < 0x20)
        return 0;
    }
  return 1;
}

extern ssize_t httpclient_io_safe_send (SocketHTTPClient_T client,
                                        HTTPPoolEntry *conn,
                                        const void *data,
                                        size_t len,
                                        const char *op_desc);

extern int httpclient_io_safe_recv (SocketHTTPClient_T client,
                                    HTTPPoolEntry *conn,
                                    char *buf,
                                    size_t size,
                                    ssize_t *n);

extern int httpclient_body_check_size_limit (HTTPBodyAccumulator *acc,
                                             size_t len,
                                             size_t *potential_size);

extern size_t httpclient_body_calculate_capacity (HTTPBodyAccumulator *acc,
                                                  size_t needed_size);

extern int
httpclient_body_grow_buffer (HTTPBodyAccumulator *acc, size_t needed_size);

extern int httpclient_body_accumulate_chunk (HTTPBodyAccumulator *acc,
                                             const char *data,
                                             size_t len);

extern void httpclient_body_fill_response (SocketHTTPClient_Response *response,
                                           const SocketHTTP_Response *parsed,
                                           HTTPBodyAccumulator *acc,
                                           Arena_T resp_arena);

extern void httpclient_headers_add_host (SocketHTTPClient_Request_T req);

extern void
httpclient_headers_add_accept_encoding (SocketHTTPClient_T client,
                                        SocketHTTPClient_Request_T req);

extern void httpclient_headers_add_standard (SocketHTTPClient_T client,
                                             SocketHTTPClient_Request_T req);

extern void httpclient_headers_add_cookie (SocketHTTPClient_T client,
                                           SocketHTTPClient_Request_T req);

extern void
httpclient_headers_add_initial_auth (SocketHTTPClient_T client,
                                     SocketHTTPClient_Request_T req);

extern void
httpclient_headers_add_content_length (SocketHTTPClient_Request_T req);

extern void httpclient_headers_prepare_request (SocketHTTPClient_T client,
                                                SocketHTTPClient_Request_T req);

extern void
httpclient_store_response_cookies (SocketHTTPClient_T client,
                                   SocketHTTPClient_Request_T req,
                                   SocketHTTPClient_Response *response);

extern void httpclient_http1_build_request (SocketHTTPClient_Request_T req,
                                            SocketHTTP_Request *http_req);

extern int httpclient_http1_send_headers (SocketHTTPClient_T client,
                                          HTTPPoolEntry *conn,
                                          const SocketHTTP_Request *http_req);

extern int httpclient_http1_send_body (SocketHTTPClient_T client,
                                       HTTPPoolEntry *conn,
                                       const void *body,
                                       size_t body_len);

extern int
httpclient_http1_receive_response (SocketHTTPClient_T client,
                                   HTTPPoolEntry *conn,
                                   SocketHTTPClient_Response *response,
                                   size_t max_response_size,
                                   int discard_body);

extern int httpclient_http1_execute (HTTPPoolEntry *conn,
                                     const SocketHTTPClient_Request_T req,
                                     SocketHTTPClient_Response *response,
                                     size_t max_response_size,
                                     int discard_body);

extern void
httpclient_http2_build_request (const SocketHTTPClient_Request_T req,
                                SocketHTTP_Request *http_req);

extern int
httpclient_http2_parse_response_headers (const SocketHPACK_Header *headers,
                                         size_t header_count,
                                         SocketHTTPClient_Response *response,
                                         Arena_T arena);

extern int httpclient_http2_send_request (SocketHTTP2_Stream_T stream,
                                          SocketHTTP2_Conn_T h2conn,
                                          const SocketHTTP_Request *http_req,
                                          const void *body,
                                          size_t body_len);

extern int httpclient_http2_recv_headers (SocketHTTP2_Stream_T stream,
                                          SocketHTTP2_Conn_T h2conn,
                                          SocketHTTPClient_Response *response,
                                          int *end_stream);

extern int httpclient_http2_recv_body (SocketHTTP2_Stream_T stream,
                                       SocketHTTP2_Conn_T h2conn,
                                       Arena_T arena,
                                       size_t max_response_size,
                                       unsigned char **body_out,
                                       size_t *body_len_out,
                                       int discard_body);

extern int httpclient_http2_execute (HTTPPoolEntry *conn,
                                     const SocketHTTPClient_Request_T req,
                                     SocketHTTPClient_Response *response,
                                     size_t max_response_size,
                                     int discard_body);

extern int httpclient_is_redirect_status (int status_code);

extern int httpclient_should_follow_redirect (SocketHTTPClient_T client,
                                              SocketHTTPClient_Request_T req,
                                              int status_code);

extern int httpclient_check_request_limits (SocketHTTPClient_T client,
                                            int redirect_count,
                                            int auth_retry_count);

extern void httpclient_release_connection (SocketHTTPClient_T client,
                                           HTTPPoolEntry *conn,
                                           int success);

#endif /* SOCKETHTTPCLIENT_PRIVATE_INCLUDED */
