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

/* Exception handling - uses centralized infrastructure from SocketUtil.h */
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
  char *host;    /**< Target hostname (owned, null-terminated) */
  int port;      /**< Target port */
  int is_secure; /**< Using TLS */
  char sni_hostname[256];  /**< Hostname used for TLS SNI verification */

  SocketHTTP_Version version; /**< Negotiated protocol version */

  /* Protocol-specific state */
  union
  {
    struct
    {
      Socket_T socket;
      SocketHTTP1_Parser_T parser;
      SocketBuf_T inbuf;
      SocketBuf_T outbuf;
      Arena_T
          conn_arena; /**< Arena for connection resources (parser, buffers) */
    } h1;
    struct
    {
      SocketHTTP2_Conn_T conn;
      int active_streams; /**< Count of active streams */
    } h2;
  } proto;

  time_t created_at; /**< Connection creation time */
  time_t last_used;  /**< Last activity time */
  int in_use;        /**< For H1.1: currently handling request */
  int closed;        /**< Connection closed by peer */

  struct HTTPPoolEntry *hash_next; /**< Hash chain for host:port */
  struct HTTPPoolEntry *next;      /**< Free list / all connections list */
  struct HTTPPoolEntry *prev;      /**< Doubly linked for removal */
} HTTPPoolEntry;

/**
 * @brief HTTP connection pool with per-host limits.
 * @ingroup http
 */
typedef struct HTTPPool
{
  HTTPPoolEntry **hash_table; /**< Hash table for host:port lookup */
  size_t hash_size;           /**< Hash table size */

  HTTPPoolEntry *all_conns;    /**< All connections (for cleanup) */
  HTTPPoolEntry *free_entries; /**< Free entry pool */

  size_t max_per_host;  /**< Max connections per host */
  size_t max_total;     /**< Max total connections */
  size_t current_count; /**< Current connection count */
  int idle_timeout_ms;  /**< Idle connection timeout */

  Arena_T arena;         /**< Memory arena */
  pthread_mutex_t mutex; /**< Thread safety */

  /* Statistics */
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
  SocketHTTPClient_Config config; /**< Configuration copy */

  HTTPPool *pool; /**< Connection pool */

  /* Authentication */
  SocketHTTPClient_Auth *default_auth; /**< Default auth (owned) */

  /* Cookies */
  SocketHTTPClient_CookieJar_T cookie_jar; /**< Associated cookie jar */

#if SOCKET_HAS_TLS
  /* TLS */
  SocketTLSContext_T default_tls_ctx; /**< Default TLS context (owned) */
#endif

  /* Last error */
  SocketHTTPClient_Error last_error;

  /* Thread safety */
  pthread_mutex_t
      mutex; /**< Protects shared client state (auth, cookies, pool access) */

  /* Memory */
  Arena_T arena;
};

/**
 * @brief Per-request builder and state.
 * @ingroup http
 */
struct SocketHTTPClient_Request
{
  SocketHTTPClient_T client; /**< Parent client */

  SocketHTTP_Method method;
  SocketHTTP_URI uri;

  SocketHTTP_Headers_T headers; /**< Request headers */

  /* Body */
  void *body;
  size_t body_len;
  ssize_t (*body_stream_cb) (void *buf, size_t len, void *userdata);
  void *body_stream_userdata;

  /* Per-request overrides */
  int timeout_ms;              /**< -1 = use client default */
  SocketHTTPClient_Auth *auth; /**< NULL = use client default */

  /* Memory */
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

  HTTPPoolEntry *conn; /**< Connection being used */

  /* Response accumulation */
  SocketHTTPClient_Response response;

  /* Callback */
  SocketHTTPClient_Callback callback;
  void *userdata;

  /* Linked list for pending requests */
  struct SocketHTTPClient_AsyncRequest *next;
};

/**
 * @brief Individual cookie storage entry.
 * @ingroup http
 */
typedef struct CookieEntry
{
  SocketHTTPClient_Cookie cookie; /**< Cookie data (strings owned) */
  time_t created;                 /**< Creation timestamp for eviction */
  struct CookieEntry *next;       /**< Hash chain */
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
  unsigned hash_seed; /**< Random seed for hash collision resistance */
  Arena_T arena;
  pthread_mutex_t mutex;
};

/* Pool operations */

/** Create and initialize a new HTTP connection pool. */
extern HTTPPool *httpclient_pool_new (Arena_T arena,
                                      const SocketHTTPClient_Config *config);
/** Dispose of HTTP connection pool and close all connections. */
extern void httpclient_pool_free (HTTPPool *pool);
/** Get or create a pool entry for host:port. */
extern HTTPPoolEntry *httpclient_pool_get (HTTPPool *pool, const char *host,
                                           int port, int is_secure);

/** Release a pool entry back to available state. */
extern void httpclient_pool_release (HTTPPool *pool, HTTPPoolEntry *entry);

/** Close and remove a pool entry. */
extern void httpclient_pool_close (HTTPPool *pool, HTTPPoolEntry *entry);

/** Clean up idle connections that exceeded timeout. */
extern void httpclient_pool_cleanup_idle (HTTPPool *pool);

/* Connection management */

/** Establish connection to target URI, handling proxy and TLS. */
extern HTTPPoolEntry *httpclient_connect (SocketHTTPClient_T client,
                                          const SocketHTTP_URI *uri);

/** Send HTTP request over the connection entry. */
extern int httpclient_send_request (HTTPPoolEntry *conn,
                                    SocketHTTPClient_Request_T req);

/** Receive and parse HTTP response from connection. */
extern int httpclient_receive_response (HTTPPoolEntry *conn,
                                        SocketHTTPClient_Response *response,
                                        Arena_T arena);

/* Authentication constants */
#define HTTPCLIENT_DIGEST_REALM_MAX_LEN 128
#define HTTPCLIENT_DIGEST_NONCE_MAX_LEN 128
#define HTTPCLIENT_DIGEST_OPAQUE_MAX_LEN 128
#define HTTPCLIENT_DIGEST_QOP_MAX_LEN 64
#define HTTPCLIENT_DIGEST_ALGORITHM_MAX_LEN 32
#define HTTPCLIENT_DIGEST_PARAM_NAME_MAX_LEN 32
#define HTTPCLIENT_DIGEST_VALUE_MAX_LEN 256

/* Digest token constants */
#define HTTPCLIENT_DIGEST_TOKEN_AUTH "auth"
#define HTTPCLIENT_DIGEST_TOKEN_AUTH_LEN 4
#define HTTPCLIENT_DIGEST_TOKEN_TRUE "true"
#define HTTPCLIENT_DIGEST_TOKEN_TRUE_LEN 4
#define HTTPCLIENT_DIGEST_TOKEN_STALE "stale"
#define HTTPCLIENT_DIGEST_TOKEN_STALE_LEN 5

/* Auth prefixes and lengths */
#define HTTPCLIENT_DIGEST_PREFIX "Digest "
#define HTTPCLIENT_DIGEST_PREFIX_LEN 7
#define HTTPCLIENT_BASIC_PREFIX "Basic "
#define HTTPCLIENT_BASIC_PREFIX_LEN 6
#define HTTPCLIENT_BEARER_PREFIX "Bearer "
#define HTTPCLIENT_BEARER_PREFIX_LEN 7

/* Legacy alias for backward compatibility */
#define HTTPCLIENT_DIGEST_BASIC_PREFIX HTTPCLIENT_BASIC_PREFIX
#define HTTPCLIENT_DIGEST_BASIC_PREFIX_LEN HTTPCLIENT_BASIC_PREFIX_LEN

/* Hex digest size (max of MD5/SHA256) */
#define HTTPCLIENT_DIGEST_HEX_SIZE (SOCKET_CRYPTO_SHA256_SIZE * 2 + 1)

/* Basic auth credentials buffer size defined in SocketHTTPClient-config.h */

/* Client nonce sizes */
#define HTTPCLIENT_DIGEST_CNONCE_SIZE 16

/* Temporary buffers for hash computations */
#define HTTPCLIENT_DIGEST_A_BUFFER_SIZE 512

/* Authentication helpers */

/** Generate Basic auth header ("Basic base64(user:pass)"). */
extern int httpclient_auth_basic_header (const char *username,
                                         const char *password, char *output,
                                         size_t output_size);

/** Compute Digest auth response (RFC 2617, MD5 or SHA-256). */
extern int httpclient_auth_digest_response (
    const char *username, const char *password, const char *realm,
    const char *nonce, const char *uri, const char *method, const char *qop,
    const char *nc, const char *cnonce, int use_sha256, char *output,
    size_t output_size);

/** Handle Digest auth challenge and generate Authorization header. */
extern int httpclient_auth_digest_challenge (
    const char *www_authenticate, const char *username, const char *password,
    const char *method, const char *uri, const char *nc_value, char *output,
    size_t output_size);

/** Generate Bearer token header (RFC 6750). */
extern int httpclient_auth_bearer_header (const char *token, char *output,
                                          size_t output_size);

/** Check if Digest challenge indicates stale nonce. */
extern int httpclient_auth_is_stale_nonce (const char *www_authenticate);

/* Cookie helpers */

/** Generate Cookie header from jar for URI. */
extern int httpclient_cookies_for_request (
    SocketHTTPClient_CookieJar_T jar, const SocketHTTP_URI *uri, char *output,
    size_t output_size, int enforce_samesite);

/** Parse Set-Cookie header into cookie structure (RFC 6265). */
extern int httpclient_parse_set_cookie (const char *value, size_t len,
                                        const SocketHTTP_URI *request_uri,
                                        SocketHTTPClient_Cookie *cookie,
                                        Arena_T arena);

/** Hash host:port for pool lookup. */
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

/* Retry helpers */

/** Check if error is retryable per client policy. */
extern int httpclient_should_retry_error (const SocketHTTPClient_T client,
                                          SocketHTTPClient_Error error);

/** Check if status code warrants retry. */
extern int httpclient_should_retry_status (const SocketHTTPClient_T client,
                                           int status);

/** Check if status warrants retry with idempotency check. */
extern int httpclient_should_retry_status_with_method (
    const SocketHTTPClient_T client, int status, SocketHTTP_Method method);

/** Calculate exponential backoff delay with jitter. */
extern int httpclient_calculate_retry_delay (const SocketHTTPClient_T client,
                                             int attempt);

/** Sleep for retry backoff. */
extern void httpclient_retry_sleep_ms (int ms);

/** Grow arena-allocated body buffer. */
extern int httpclient_grow_body_buffer (Arena_T arena, char **buf,
                                        size_t *capacity, size_t *total,
                                        size_t needed, size_t max_size);

/** Clear response for retry. */
extern void
httpclient_clear_response_for_retry (SocketHTTPClient_Response *response);

#endif /* SOCKETHTTPCLIENT_PRIVATE_INCLUDED */
