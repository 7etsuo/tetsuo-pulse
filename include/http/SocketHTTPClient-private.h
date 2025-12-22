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

#include <pthread.h>
#include <time.h>

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "HTTPClient"

#define HTTPCLIENT_ERROR_FMT(fmt, ...) SOCKET_ERROR_FMT (fmt, ##__VA_ARGS__)
#define HTTPCLIENT_ERROR_MSG(fmt, ...) SOCKET_ERROR_MSG (fmt, ##__VA_ARGS__)
#define RAISE_HTTPCLIENT_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketHTTPClient, e)

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
 * @brief States for asynchronous HTTP requests.
 * @ingroup http
 */
typedef enum
{
  ASYNC_STATE_IDLE = 0,
  ASYNC_STATE_CONNECTING,
  ASYNC_STATE_SENDING,
  ASYNC_STATE_RECEIVING_HEADERS,
  ASYNC_STATE_RECEIVING_BODY,
  ASYNC_STATE_COMPLETE,
  ASYNC_STATE_FAILED,
  ASYNC_STATE_CANCELLED
} HTTPAsyncState;

/**
 * @brief Asynchronous HTTP request state.
 * @ingroup http
 */
struct SocketHTTPClient_AsyncRequest
{
  SocketHTTPClient_T client;
  SocketHTTPClient_Request_T request;

  HTTPAsyncState state;
  SocketHTTPClient_Error error;

  HTTPPoolEntry *conn;

  SocketHTTPClient_Response response;

  SocketHTTPClient_Callback callback;
  void *userdata;

  struct SocketHTTPClient_AsyncRequest *next;
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

extern HTTPPool *httpclient_pool_new (Arena_T arena,
                                      const SocketHTTPClient_Config *config);
extern void httpclient_pool_free (HTTPPool *pool);
extern HTTPPoolEntry *httpclient_pool_get (HTTPPool *pool, const char *host,
                                           int port, int is_secure);
extern void httpclient_pool_release (HTTPPool *pool, HTTPPoolEntry *entry);
extern void httpclient_pool_close (HTTPPool *pool, HTTPPoolEntry *entry);
extern void httpclient_pool_cleanup_idle (HTTPPool *pool);

extern HTTPPoolEntry *httpclient_connect (SocketHTTPClient_T client,
                                          const SocketHTTP_URI *uri);
extern int httpclient_send_request (HTTPPoolEntry *conn,
                                    SocketHTTPClient_Request_T req);
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
                                         const char *password, char *output,
                                         size_t output_size);
extern int httpclient_auth_digest_response (
    const char *username, const char *password, const char *realm,
    const char *nonce, const char *uri, const char *method, const char *qop,
    const char *nc, const char *cnonce, int use_sha256, char *output,
    size_t output_size);
extern int httpclient_auth_digest_challenge (
    const char *www_authenticate, const char *username, const char *password,
    const char *method, const char *uri, const char *nc_value, char *output,
    size_t output_size);
extern int httpclient_auth_bearer_header (const char *token, char *output,
                                          size_t output_size);
extern int httpclient_auth_is_stale_nonce (const char *www_authenticate);

extern int httpclient_cookies_for_request (
    SocketHTTPClient_CookieJar_T jar, const SocketHTTP_URI *uri, char *output,
    size_t output_size, int enforce_samesite);
extern int httpclient_parse_set_cookie (const char *value, size_t len,
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

extern int httpclient_should_retry_error (const SocketHTTPClient_T client,
                                          SocketHTTPClient_Error error);
extern int httpclient_should_retry_status (const SocketHTTPClient_T client,
                                           int status);
extern int httpclient_should_retry_status_with_method (
    const SocketHTTPClient_T client, int status, SocketHTTP_Method method);
extern int httpclient_calculate_retry_delay (const SocketHTTPClient_T client,
                                             int attempt);
extern void httpclient_retry_sleep_ms (int ms);
extern int httpclient_grow_body_buffer (Arena_T arena, char **buf,
                                        size_t *capacity, size_t *total,
                                        size_t needed, size_t max_size);
extern void
httpclient_clear_response_for_retry (SocketHTTPClient_Response *response);

/* Thread-local arena cache functions (SocketHTTPClient-arena.c)
 * Eliminate per-request malloc/pthread_mutex_init overhead by caching
 * arenas in thread-local storage and using Arena_clear() for reset. */
extern Arena_T httpclient_acquire_request_arena (void);
extern void httpclient_release_request_arena (Arena_T *arena_ptr);
extern Arena_T httpclient_acquire_response_arena (void);
extern void httpclient_release_response_arena (Arena_T *arena_ptr);

#endif /* SOCKETHTTPCLIENT_PRIVATE_INCLUDED */
