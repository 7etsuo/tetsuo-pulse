/**
 * SocketHTTPClient-private.h - HTTP Client Internal Definitions
 *
 * Part of the Socket Library
 *
 * Internal structures and helper functions for HTTP client implementation.
 * NOT part of public API - do not include from application code.
 */

#ifndef SOCKETHTTPCLIENT_PRIVATE_INCLUDED
#define SOCKETHTTPCLIENT_PRIVATE_INCLUDED

#include "http/SocketHTTPClient.h"
#include "http/SocketHTTPClient-config.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"
#include "http/SocketHTTP2.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"
#include "core/SocketUtil.h"

#include <pthread.h>
#include <time.h>

/* ============================================================================
 * Exception Handling (Centralized)
 * ============================================================================
 *
 * REFACTOR: Uses centralized exception infrastructure from SocketUtil.h
 * instead of module-specific thread-local buffers and exception copies.
 *
 * Benefits:
 * - Single thread-local error buffer (socket_error_buf) for all modules
 * - Consistent error formatting with SOCKET_ERROR_FMT/MSG macros
 * - Thread-safe exception raising via SOCKET_RAISE_MODULE_ERROR
 * - Automatic logging integration via SocketLog_emit
 *
 * The thread-local exception (HTTPClient_DetailedException) is declared
 * in SocketHTTPClient.c using SOCKET_DECLARE_MODULE_EXCEPTION(HTTPClient).
 */

/* Override log component for this module */
#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "HTTPClient"

/**
 * Error formatting macros - delegate to centralized infrastructure.
 * Uses socket_error_buf from SocketUtil.h (thread-local, 256 bytes).
 */
#define HTTPCLIENT_ERROR_FMT(fmt, ...) SOCKET_ERROR_FMT (fmt, ##__VA_ARGS__)
#define HTTPCLIENT_ERROR_MSG(fmt, ...) SOCKET_ERROR_MSG (fmt, ##__VA_ARGS__)

/**
 * RAISE_HTTPCLIENT_ERROR - Raise exception with detailed error message
 *
 * Creates a thread-local copy of the exception with reason from
 * socket_error_buf. Thread-safe: prevents race conditions when
 * multiple threads raise same exception type.
 *
 * Requires: SOCKET_DECLARE_MODULE_EXCEPTION(HTTPClient) in .c file.
 */
#define RAISE_HTTPCLIENT_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketHTTPClient, e)



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
  size_t connections_failed;
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

#if SOCKET_HAS_TLS
  /* TLS */
  SocketTLSContext_T default_tls_ctx; /**< Default TLS context (owned) */
#endif

  /* Last error */
  SocketHTTPClient_Error last_error;

  /* Thread safety */
  pthread_mutex_t mutex; /**< Protects shared client state (auth, cookies, pool access) */

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
  time_t created;                 /**< Creation timestamp for eviction */
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
  size_t max_cookies;
  unsigned hash_seed; /**< Random seed for hash collision resistance */
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

/* ============================================================================
 * Authentication Constants
 * ============================================================================ */

/* Buffer sizes for Digest authentication fields */
#define HTTPCLIENT_DIGEST_REALM_MAX_LEN       128
#define HTTPCLIENT_DIGEST_NONCE_MAX_LEN       128
#define HTTPCLIENT_DIGEST_OPAQUE_MAX_LEN      128
#define HTTPCLIENT_DIGEST_QOP_MAX_LEN         64
#define HTTPCLIENT_DIGEST_ALGORITHM_MAX_LEN   32
#define HTTPCLIENT_DIGEST_PARAM_NAME_MAX_LEN  32
#define HTTPCLIENT_DIGEST_VALUE_MAX_LEN       256

/* Digest token constants */
#define HTTPCLIENT_DIGEST_TOKEN_AUTH          "auth"
#define HTTPCLIENT_DIGEST_TOKEN_AUTH_LEN      4
#define HTTPCLIENT_DIGEST_TOKEN_TRUE          "true"
#define HTTPCLIENT_DIGEST_TOKEN_TRUE_LEN      4
#define HTTPCLIENT_DIGEST_TOKEN_STALE         "stale"
#define HTTPCLIENT_DIGEST_TOKEN_STALE_LEN     5

/* Digest prefixes and lengths */
#define HTTPCLIENT_DIGEST_PREFIX              "Digest "
#define HTTPCLIENT_DIGEST_PREFIX_LEN          7
#define HTTPCLIENT_DIGEST_BASIC_PREFIX        "Basic "
#define HTTPCLIENT_DIGEST_BASIC_PREFIX_LEN    6

/* Hex digest size (max of MD5/SHA256) */
#define HTTPCLIENT_DIGEST_HEX_SIZE            (SOCKET_CRYPTO_SHA256_SIZE * 2 + 1)

/* Basic auth credentials buffer size defined in SocketHTTPClient-config.h */

/* Client nonce sizes */
#define HTTPCLIENT_DIGEST_CNONCE_SIZE         16


/* Temporary buffers for hash computations */
#define HTTPCLIENT_DIGEST_A_BUFFER_SIZE       512

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

/**
 * httpclient_auth_digest_challenge - Handle Digest WWW-Authenticate challenge
 * @www_authenticate: WWW-Authenticate header value
 * @username: User's username
 * @password: User's password
 * @method: HTTP method (GET, POST, etc.)
 * @uri: Request URI
 * @nc_value: Nonce count (e.g., "00000001")
 * @output: Output buffer for Authorization header value
 * @output_size: Size of output buffer
 *
 * Returns: 0 on success, -1 on error
 *
 * Parses a Digest challenge and generates the appropriate Authorization
 * header value. Handles both MD5 and SHA-256 algorithms, qop=auth.
 * NOTE: qop=auth-int is NOT supported.
 */
extern int httpclient_auth_digest_challenge (const char *www_authenticate,
                                             const char *username,
                                             const char *password,
                                             const char *method,
                                             const char *uri,
                                             const char *nc_value,
                                             char *output,
                                             size_t output_size);

/**
 * httpclient_auth_bearer_header - Generate Bearer token Authorization header
 * @token: Bearer token string
 * @output: Output buffer for "Bearer <token>"
 * @output_size: Size of output buffer
 *
 * Returns: 0 on success, -1 if buffer too small
 * Thread-safe: Yes
 *
 * Format per RFC 6750: Authorization: Bearer <token>
 * Token is copied as-is, no validation or encoding.
 * Token length limited by output_size - 7.
 */

extern int httpclient_auth_bearer_header (const char *token, char *output, size_t output_size);

/**
 * httpclient_auth_is_stale_nonce - Check if WWW-Authenticate contains stale=true
 * @www_authenticate: WWW-Authenticate header value
 *
 * Returns: 1 if stale=true present, 0 otherwise
 *
 * Used to determine if a 401 response is due to an expired nonce
 * (which should be retried) vs. invalid credentials (which should not).
 */
extern int httpclient_auth_is_stale_nonce (const char *www_authenticate);

/* Cookie helpers */
extern int httpclient_cookies_for_request (SocketHTTPClient_CookieJar_T jar,
                                           const SocketHTTP_URI *uri,
                                           char *output, size_t output_size,
                                           int enforce_samesite);  /* 1 to enforce SameSite cookie policy */
extern int httpclient_parse_set_cookie (const char *value, size_t len,
                                        const SocketHTTP_URI *request_uri,
                                        SocketHTTPClient_Cookie *cookie,
                                        Arena_T arena);

/**
 * httpclient_host_hash - Hash function for host:port connection pool key
 * @host: Hostname (case-insensitive hashing)
 * @port: Port number
 * @table_size: Hash table size
 *
 * Returns: Hash bucket index
 *
 * Uses DJB2 algorithm with case-insensitive hostname hashing.
 * Combines hostname and port into a single hash for pool lookup.
 * Uses SOCKET_UTIL_DJB2_SEED from SocketUtil.h for consistency.
 */
static inline unsigned
httpclient_host_hash (const char *host, int port, size_t table_size)
{
  size_t host_len = strlen (host);
  unsigned host_hash = socket_util_hash_djb2_ci_len (host, host_len, table_size);
  unsigned port_hash = socket_util_hash_uint ((unsigned)port, table_size);
  unsigned combined = host_hash ^ port_hash;
  return socket_util_hash_uint (combined, table_size);
}

/* Retry helpers (from SocketHTTPClient-retry.c) */
extern int httpclient_should_retry_error (const SocketHTTPClient_T client, SocketHTTPClient_Error error);
extern int httpclient_should_retry_status (const SocketHTTPClient_T client, int status);
extern int httpclient_calculate_retry_delay (const SocketHTTPClient_T client, int attempt);
extern void httpclient_retry_sleep_ms (int ms);

extern void clear_response_for_retry (SocketHTTP_Response *response);
extern void httpclient_clear_response_for_retry (SocketHTTPClient_Response *response);

#endif /* SOCKETHTTPCLIENT_PRIVATE_INCLUDED */

