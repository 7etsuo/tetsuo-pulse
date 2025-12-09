/**
 * @file SocketHTTPClient-private.h
 * @brief Internal HTTP client structures and connection pooling.
 * @ingroup http
 *
 * This header contains internal structures for the HTTP client implementation.
 * NOT for public consumption - use SocketHTTPClient.h instead.
 *
 * Contains:
 * - Connection pool management with per-host limits
 * - HTTP/1.1 and HTTP/2 protocol state machines
 * - Request/response lifecycle management
 * - Cookie jar implementation
 * - Rate limiting and retry logic
 * - TLS integration and certificate validation
 * - Asynchronous operation state tracking
 *
 * The client supports both synchronous and asynchronous operations with
 * automatic protocol negotiation and connection reuse.
 *
 * @see SocketHTTPClient.h for public HTTP client API.
 * @see SocketHTTPClient-config.h for configuration constants.
 * @see SocketHTTP-private.h for core HTTP internal structures.
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
 * @brief Raise HTTP client exception with detailed error message.
 * @ingroup http
 *
 * Creates a thread-local copy of the exception with reason from
 * socket_error_buf. Thread-safe: prevents race conditions when
 * multiple threads raise same exception type.
 *
 * Requires: SOCKET_DECLARE_MODULE_EXCEPTION(HTTPClient) in .c file.
 *
 * @see SocketUtil.h for centralized error infrastructure.
 * @see docs/ERROR_HANDLING.md for exception patterns.
 */
#define RAISE_HTTPCLIENT_ERROR(e)                                             \
  SOCKET_RAISE_MODULE_ERROR (SocketHTTPClient, e)

/* ============================================================================
 * Connection Pool Entry
 * ============================================================================
 */

/**
 * @brief HTTP connection pool entry for reusing connections to the same host:port.
 * @ingroup http
 *
 * Manages a single connection supporting both HTTP/1.1 (sequential requests)
 * and HTTP/2 (multiplexed streams) protocols.
 * Includes protocol-specific state, buffers, and lifecycle tracking.
 *
 * @see HTTPPool for overall pool structure and management.
 * @see SocketHTTPClient.c for usage in client operations.
 */
typedef struct HTTPPoolEntry
{
  char *host;    /**< Target hostname (owned, null-terminated) */
  int port;      /**< Target port */
  int is_secure; /**< Using TLS */

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

/* ============================================================================
 * Connection Pool
 * ============================================================================
 */

/**
 * @brief HTTP connection pool managing reusable connections by host:port key.
 * @ingroup http
 *
 * Hash-based storage with per-host and total connection limits.
 * Supports idle timeout cleanup and statistics tracking.
 * Thread-safe with mutex protection.
 *
 * @see httpclient_pool_new() for creation.
 * @see SocketHTTPClient-pool.c for implementation.
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

/* ============================================================================
 * Client Structure
 * ============================================================================
 */

/**
 * @brief Main HTTP client instance managing configuration, pool, auth, and state.
 * @ingroup http
 *
 * Internal structure holding connection pool, default auth, cookie jar,
 * TLS context (if SOCKET_HAS_TLS), and last error state.
 * Protected by mutex for thread-safe shared access.
 *
 * @see SocketHTTPClient_new() in SocketHTTPClient.h for public creation.
 * @see SocketHTTPClient_free() for cleanup.
 * @see docs/HTTP-REFACTOR.md for design rationale.
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

/* ============================================================================
 * Request Structure
 * ============================================================================
 */

/**
 * @brief Per-request builder and state for custom HTTP requests.
 * @ingroup http
 *
 * Holds method, URI, headers, body data or stream callback, timeouts,
 * and authentication overrides for a single request.
 * Arena-allocated for temporary use.
 *
 * @see SocketHTTPClient_Request_new() for creation.
 * @see SocketHTTPClient_Request_execute() to send the request.
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

/* ============================================================================
 * Async Request Structure
 * ============================================================================
 */

/**
 * @brief States for asynchronous HTTP requests.
 * @ingroup http
 *
 * Tracks lifecycle from idle to complete, failed, or cancelled.
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
 * @brief Asynchronous HTTP request state and callback handler.
 * @ingroup http
 *
 * Manages async request lifecycle, connection, response accumulation,
 * and callback invocation upon completion or error.
 * Linked for pending queue in client.
 *
 * @see SocketHTTPClient_get_async() for starting async requests.
 * @see SocketHTTPClient_Callback for response handling.
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

/* ============================================================================
 * Cookie Storage
 * ============================================================================
 */

/**
 * @brief Individual cookie storage in the client cookie jar.
 * @ingroup http
 *
 * Stores cookie data, creation time for eviction, and hash chain link.
 *
 * @see SocketHTTPClient_CookieJar_T for jar structure.
 * @see SocketHTTPClient_Cookie for cookie fields.
 */
typedef struct CookieEntry
{
  SocketHTTPClient_Cookie cookie; /**< Cookie data (strings owned) */
  time_t created;                 /**< Creation timestamp for eviction */
  struct CookieEntry *next;       /**< Hash chain */
} CookieEntry;

/**
 * @brief Cookie jar for storing and managing HTTP cookies per domain.
 * @ingroup http
 *
 * Hash-based storage with eviction by age, max size limit, and thread safety.
 * Supports SameSite policy enforcement and automatic Set-Cookie parsing.
 *
 * @see SocketHTTPClient_set_cookie_jar() to associate with client.
 * @see SocketHTTPClient_CookieJar_new() for creation.
 * @see docs/SECURITY.md "Cookies" section for security notes.
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
 * ============================================================================
 */

/* Pool operations */
/**
 * @brief Create and initialize a new HTTP connection pool.
 * @ingroup http
 *
 * Allocates the pool structure and hash table from the provided arena.
 * Hash size computed from config max connections with security bounds.
 *
 * @param arena Memory arena for allocating pool structures and hash table.
 * @param config HTTP client configuration for sizing (max_total_connections, etc.).
 *
 * @return Pointer to new HTTPPool, or raises exception on failure.
 * @throws SocketHTTPClient_Failed if arena allocation fails or config invalid.
 * @threadsafe No - single-threaded initialization expected.
 *
 * @see httpclient_pool_free() to dispose the pool.
 * @see SocketSecurity_check_multiply() for size validation.
 */
extern HTTPPool *httpclient_pool_new (Arena_T arena,
                                      const SocketHTTPClient_Config *config);
/**
 * @brief Dispose of HTTP connection pool and all associated resources.
 * @ingroup http
 *
 * Closes all connections, frees entries, hash table, and clears statistics.
 * Does not free the arena; caller responsible for Arena_clear/dispose if needed.
 *
 * @param pool Pointer to pool (set to NULL on success).
 * @throws None - failures logged but not raised.
 * @threadsafe Conditional - hold pool mutex if concurrent access.
 *
 * @see httpclient_pool_new() for creation.
 * @see Arena_dispose() if pool owns the arena.
 */
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
 * ============================================================================
 */

/* Buffer sizes for Digest authentication fields */
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

/* Digest prefixes and lengths */
#define HTTPCLIENT_DIGEST_PREFIX "Digest "
#define HTTPCLIENT_DIGEST_PREFIX_LEN 7
#define HTTPCLIENT_DIGEST_BASIC_PREFIX "Basic "
#define HTTPCLIENT_DIGEST_BASIC_PREFIX_LEN 6

/* Hex digest size (max of MD5/SHA256) */
#define HTTPCLIENT_DIGEST_HEX_SIZE (SOCKET_CRYPTO_SHA256_SIZE * 2 + 1)

/* Basic auth credentials buffer size defined in SocketHTTPClient-config.h */

/* Client nonce sizes */
#define HTTPCLIENT_DIGEST_CNONCE_SIZE 16

/* Temporary buffers for hash computations */
#define HTTPCLIENT_DIGEST_A_BUFFER_SIZE 512

/* Authentication helpers (uses SocketCrypto) */
extern int httpclient_auth_basic_header (const char *username,
                                         const char *password, char *output,
                                         size_t output_size);
extern int httpclient_auth_digest_response (
    const char *username, const char *password, const char *realm,
    const char *nonce, const char *uri, const char *method, const char *qop,
    const char *nc, const char *cnonce, int use_sha256, char *output,
    size_t output_size);

/**
 * @brief Handle Digest authentication challenge from WWW-Authenticate header and generate Authorization response.
 * @param www_authenticate WWW-Authenticate header value from server 401 response.
 * @ingroup http
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
extern int httpclient_auth_digest_challenge (
    const char *www_authenticate, const char *username, const char *password,
    const char *method, const char *uri, const char *nc_value, char *output,
    size_t output_size);

/**
 * @brief Generate Authorization header for Bearer token authentication (RFC 6750).
 * @param token The Bearer token string (copied as-is, no validation).
 * @param output Buffer to receive the formatted "Bearer <token>" header value.
 * @param output_size Size of the output buffer (must be >= strlen(token) + 7).
 *
 * @return 0 on success, -1 if output buffer is too small or token is NULL.
 * @threadsafe Yes - stateless function.
 * @ingroup http
 *
 * No encoding, validation, or security checks are performed on the token.
 * Suitable for OAuth 2.0 Bearer tokens in HTTP requests.
 *
 * @see SocketHTTP_Headers_set() to add the header to a request.
 * @see docs/SECURITY.md for authentication security considerations.
 * @see https://datatracker.ietf.org/doc/html/rfc6750 for specification.
 */

extern int httpclient_auth_bearer_header (const char *token, char *output,
                                          size_t output_size);

/**
 * httpclient_auth_is_stale_nonce - Check if WWW-Authenticate contains
 * stale=true
 * @www_authenticate: WWW-Authenticate header value
 *
 * Returns: 1 if stale=true present, 0 otherwise
 *
 * Used to determine if a 401 response is due to an expired nonce
 * (which should be retried) vs. invalid credentials (which should not).
 */
extern int httpclient_auth_is_stale_nonce (const char *www_authenticate);

/* Cookie helpers */
extern int httpclient_cookies_for_request (
    SocketHTTPClient_CookieJar_T jar, const SocketHTTP_URI *uri, char *output,
    size_t output_size,
    int enforce_samesite); /* 1 to enforce SameSite cookie policy */
extern int httpclient_parse_set_cookie (const char *value, size_t len,
                                        const SocketHTTP_URI *request_uri,
                                        SocketHTTPClient_Cookie *cookie,
                                        Arena_T arena);

/**
 * @brief Compute hash value for host:port pair used as connection pool key.
 * @param host Hostname string (case-insensitive hashing via DJB2).
 * @param port Target port number.
 * @param table_size Size of the hash table (result modulo this value).
 * @ingroup http
 *
 * Uses DJB2 case-insensitive hash on hostname, XOR with port hash, final mod.
 * Ensures even distribution for collision-resistant pool lookup.
 *
 * @return Unsigned integer hash index (0 to table_size-1).
 *
 * @see socket_util_hash_djb2_ci_len() for hostname hashing.
 * @see socket_util_hash_uint() for port hashing.
 * @see docs/METRICS.md for performance considerations.
 */
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

/* Retry helpers (from SocketHTTPClient-retry.c) */
extern int httpclient_should_retry_error (const SocketHTTPClient_T client,
                                          SocketHTTPClient_Error error);
extern int httpclient_should_retry_status (const SocketHTTPClient_T client,
                                           int status);
extern int httpclient_calculate_retry_delay (const SocketHTTPClient_T client,
                                             int attempt);
extern void httpclient_retry_sleep_ms (int ms);

extern void clear_response_for_retry (SocketHTTP_Response *response);
extern void
httpclient_clear_response_for_retry (SocketHTTPClient_Response *response);

#endif /* SOCKETHTTPCLIENT_PRIVATE_INCLUDED */
