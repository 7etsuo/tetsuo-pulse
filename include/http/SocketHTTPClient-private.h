/**
 * SocketHTTPClient-private.h - HTTP Client Internal Definitions
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Internal structures and helper functions for HTTP client implementation.
 * NOT part of public API - do not include from application code.
 */

#ifndef SOCKETHTTPCLIENT_PRIVATE_INCLUDED
#define SOCKETHTTPCLIENT_PRIVATE_INCLUDED

#include "http/SocketHTTPClient.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"
#include "http/SocketHTTP2.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"
#include "core/SocketUtil.h"

#include <pthread.h>
#include <time.h>

/* ============================================================================
 * Thread-Local Error Buffer
 * ============================================================================ */

#define HTTPCLIENT_ERROR_BUFSIZE 256

#ifdef _WIN32
extern __declspec(thread) char httpclient_error_buf[HTTPCLIENT_ERROR_BUFSIZE];
#else
extern __thread char httpclient_error_buf[HTTPCLIENT_ERROR_BUFSIZE];
#endif

/* Thread-local exception for detailed error messages */
#ifdef _WIN32
static __declspec(thread) Except_T HTTPClient_DetailedException;
#else
static __thread Except_T HTTPClient_DetailedException;
#endif

/* Error formatting macros using centralized utilities */
#define HTTPCLIENT_ERROR_FMT(fmt, ...)                                         \
  snprintf (httpclient_error_buf, HTTPCLIENT_ERROR_BUFSIZE,                    \
            fmt " (errno: %d - %s)", ##__VA_ARGS__, errno, strerror (errno))

#define HTTPCLIENT_ERROR_MSG(fmt, ...)                                         \
  snprintf (httpclient_error_buf, HTTPCLIENT_ERROR_BUFSIZE, fmt, ##__VA_ARGS__)

#define RAISE_HTTPCLIENT_ERROR(exception)                                      \
  do                                                                           \
    {                                                                          \
      HTTPClient_DetailedException = (exception);                              \
      HTTPClient_DetailedException.reason = httpclient_error_buf;              \
      RAISE (HTTPClient_DetailedException);                                    \
    }                                                                          \
  while (0)

/* ============================================================================
 * Connection Pool Entry
 * ============================================================================ */

/**
 * HTTP connection pool entry
 *
 * Manages a single connection that can be reused for requests to the
 * same host:port. Supports both HTTP/1.1 (one request at a time) and
 * HTTP/2 (multiplexed streams).
 */
typedef struct HTTPPoolEntry
{
  char *host;      /**< Target hostname (owned, null-terminated) */
  int port;        /**< Target port */
  int is_secure;   /**< Using TLS */

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
      Arena_T conn_arena; /**< Arena for connection resources (parser, buffers) */
    } h1;
    struct
    {
      SocketHTTP2_Conn_T conn;
      int active_streams; /**< Count of active streams */
    } h2;
  } proto;

  time_t created_at;   /**< Connection creation time */
  time_t last_used;    /**< Last activity time */
  int in_use;          /**< For H1.1: currently handling request */
  int closed;          /**< Connection closed by peer */

  struct HTTPPoolEntry *hash_next; /**< Hash chain for host:port */
  struct HTTPPoolEntry *next;      /**< Free list / all connections list */
  struct HTTPPoolEntry *prev;      /**< Doubly linked for removal */
} HTTPPoolEntry;

/* ============================================================================
 * Connection Pool
 * ============================================================================ */

/**
 * HTTP connection pool
 *
 * Manages connections keyed by host:port with per-host limits
 * and HTTP/2 multiplexing support.
 */
typedef struct HTTPPool
{
  HTTPPoolEntry **hash_table;    /**< Hash table for host:port lookup */
  size_t hash_size;              /**< Hash table size */

  HTTPPoolEntry *all_conns;      /**< All connections (for cleanup) */
  HTTPPoolEntry *free_entries;   /**< Free entry pool */

  size_t max_per_host;           /**< Max connections per host */
  size_t max_total;              /**< Max total connections */
  size_t current_count;          /**< Current connection count */
  int idle_timeout_ms;           /**< Idle connection timeout */

  Arena_T arena;                 /**< Memory arena */
  pthread_mutex_t mutex;         /**< Thread safety */

  /* Statistics */
  size_t total_requests;
  size_t reused_connections;
} HTTPPool;

/* ============================================================================
 * Client Structure
 * ============================================================================ */

/**
 * HTTP client main structure
 */
struct SocketHTTPClient
{
  SocketHTTPClient_Config config; /**< Configuration copy */

  HTTPPool *pool;                 /**< Connection pool */

  /* Authentication */
  SocketHTTPClient_Auth *default_auth; /**< Default auth (owned) */

  /* Cookies */
  SocketHTTPClient_CookieJar_T cookie_jar; /**< Associated cookie jar */

  /* TLS */
  SocketTLSContext_T default_tls_ctx; /**< Default TLS context (owned) */

  /* Last error */
  SocketHTTPClient_Error last_error;

  /* Memory */
  Arena_T arena;
};

/* ============================================================================
 * Request Structure
 * ============================================================================ */

/**
 * HTTP request builder
 */
struct SocketHTTPClient_Request
{
  SocketHTTPClient_T client;      /**< Parent client */

  SocketHTTP_Method method;
  SocketHTTP_URI uri;

  SocketHTTP_Headers_T headers;   /**< Request headers */

  /* Body */
  void *body;
  size_t body_len;
  ssize_t (*body_stream_cb) (void *buf, size_t len, void *userdata);
  void *body_stream_userdata;

  /* Per-request overrides */
  int timeout_ms;                 /**< -1 = use client default */
  SocketHTTPClient_Auth *auth;    /**< NULL = use client default */

  /* Memory */
  Arena_T arena;
};

/* ============================================================================
 * Async Request Structure
 * ============================================================================ */

/**
 * Async request state
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
 * Async HTTP request
 */
struct SocketHTTPClient_AsyncRequest
{
  SocketHTTPClient_T client;
  SocketHTTPClient_Request_T request;

  HTTPAsyncState state;
  SocketHTTPClient_Error error;

  HTTPPoolEntry *conn;            /**< Connection being used */

  /* Response accumulation */
  SocketHTTPClient_Response response;

  /* Callback */
  SocketHTTPClient_Callback callback;
  void *userdata;

  /* Linked list for pending requests */
  struct SocketHTTPClient_AsyncRequest *next;
};

/* ============================================================================
 * Cookie Storage
 * ============================================================================ */

/**
 * Cookie entry in jar
 */
typedef struct CookieEntry
{
  SocketHTTPClient_Cookie cookie; /**< Cookie data (strings owned) */
  struct CookieEntry *next;       /**< Hash chain */
} CookieEntry;

/**
 * Cookie jar structure
 */
struct SocketHTTPClient_CookieJar
{
  CookieEntry **hash_table;
  size_t hash_size;
  size_t count;
  Arena_T arena;
  pthread_mutex_t mutex;
};

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

/* Pool operations */
extern HTTPPool *httpclient_pool_new (Arena_T arena,
                                      const SocketHTTPClient_Config *config);
extern void httpclient_pool_free (HTTPPool *pool);
extern HTTPPoolEntry *httpclient_pool_get (HTTPPool *pool, const char *host,
                                           int port, int is_secure);
extern void httpclient_pool_release (HTTPPool *pool, HTTPPoolEntry *entry);
extern void httpclient_pool_close (HTTPPool *pool, HTTPPoolEntry *entry);
extern void httpclient_pool_cleanup_idle (HTTPPool *pool);

/* Connection management */
extern HTTPPoolEntry *httpclient_connect (SocketHTTPClient_T client,
                                          const SocketHTTP_URI *uri);
extern int httpclient_send_request (HTTPPoolEntry *conn,
                                    SocketHTTPClient_Request_T req);
extern int httpclient_receive_response (HTTPPoolEntry *conn,
                                        SocketHTTPClient_Response *response,
                                        Arena_T arena);

/* Authentication helpers (uses SocketCrypto) */
extern int httpclient_auth_basic_header (const char *username,
                                         const char *password, char *output,
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

/* Cookie helpers */
extern int httpclient_cookies_for_request (SocketHTTPClient_CookieJar_T jar,
                                           const SocketHTTP_URI *uri,
                                           char *output, size_t output_size);
extern int httpclient_parse_set_cookie (const char *value, size_t len,
                                        const SocketHTTP_URI *request_uri,
                                        SocketHTTPClient_Cookie *cookie,
                                        Arena_T arena);

/* Hash function for host:port */
static inline unsigned
httpclient_host_hash (const char *host, int port, size_t table_size)
{
  unsigned hash = 5381;
  while (*host)
    {
      unsigned char c = (unsigned char)*host++;
      /* Case-insensitive hash for hostname */
      if (c >= 'A' && c <= 'Z')
        c = c + ('a' - 'A');
      hash = ((hash << 5) + hash) ^ c;
    }
  hash = ((hash << 5) + hash) ^ (unsigned)port;
  return hash % table_size;
}

#endif /* SOCKETHTTPCLIENT_PRIVATE_INCLUDED */

