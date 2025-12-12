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
 * @brief HTTP connection pool entry for reusing connections to the same
 * host:port.
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
 * @brief Main HTTP client instance managing configuration, pool, auth, and
 * state.
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
 * Hash size computed from config max connections with security bounds to
 * ensure efficient lookups while preventing excessive memory allocation or DoS
 * via large configs. Security checks via SocketSecurity_check_multiply prevent
 * overflow. Initializes mutex for thread safety and sets limits from config.
 *
 * @param[in] arena Memory arena for allocating pool structures, hash table,
 * and entries.
 * @param[in] config HTTP client configuration for sizing
 * (max_total_connections, max_connections_per_host, idle_timeout_ms).
 *
 * @return Pointer to new HTTPPool instance, ready for use.
 *
 * @throws SocketHTTPClient_Failed if arena allocation fails, config invalid
 * (e.g. zero max), or mutex init fails.
 *
 * @threadsafe No - intended for single-threaded initialization; concurrent
 * calls may race on arena.
 *
 *  Usage Example
 *
 * @code{.c}
 * Arena_T arena = Arena_new();
 * SocketHTTPClient_Config cfg;
 * SocketHTTPClient_config_defaults(&cfg);
 * // Internally, SocketHTTPClient_new calls this:
 * HTTPPool *pool = httpclient_pool_new(arena, &cfg);
 * if (pool) {
 *     // Use pool for connections
 *     HTTPPoolEntry *entry = httpclient_pool_get(pool, "example.com", 443, 1);
 *     // ...
 *     httpclient_pool_release(pool, entry);
 * }
 * httpclient_pool_free(pool);
 * Arena_dispose(&arena);
 * @endcode
 *
 *  Configuration Impact
 *
 * | Config Field | Effect on Pool |
 * |--------------|----------------|
 * | max_total_connections | Upper bound on hash size and total entries |
 * | max_connections_per_host | Per-host limit during get() |
 * | idle_timeout_ms | Used in cleanup_idle() |
 *
 * @complexity O(1) time - constant allocations; O(hash_size) space where
 * hash_size ~ max_total / 8
 *
 * @note Pool does not own arena; caller manages lifetime. All entries freed on
 * pool_free but not arena_clear.
 * @warning Ensure config values reasonable to avoid large memory use or DoS;
 * security checks mitigate but validate inputs.
 *
 * @see httpclient_pool_free() for disposal and cleanup.
 * @see httpclient_pool_get() for acquiring connections.
 * @see SocketSecurity_check_multiply() for size validation used internally.
 * @see docs/HTTP-POOL.md for pool design details (if exists).
 */
extern HTTPPool *httpclient_pool_new (Arena_T arena,
                                      const SocketHTTPClient_Config *config);
/**
 * @brief Dispose of HTTP connection pool and all associated resources.
 * @ingroup http
 *
 * Closes all open connections by calling Socket_free on each entry's socket,
 * frees individual HTTPPoolEntry structures back to free list or arena,
 * destroys hash table entries, clears statistics counters, and destroys mutex.
 * Does not dispose or clear the underlying arena; caller must manage arena
 * lifetime to avoid leaks of any remaining arena-allocated data. Handles
 * partial failures gracefully (e.g. one connection close fail doesn't stop
 * others).
 *
 * @param[in,out] pool Pointer to HTTPPool (set to NULL after successful
 * disposal).
 *
 * @return void
 *
 * @throws None - socket close or mutex destroy failures are logged via
 * SocketLog but not raised as exceptions.
 *
 * @threadsafe Conditional - safe if no concurrent access to pool; acquire
 * pool->mutex externally if shared.
 *
 *  Usage Example
 *
 * @code{.c}
 * // Typical paired with creation
 * HTTPPool *pool = httpclient_pool_new(arena, &config);
 * // ... use pool ...
 * httpclient_pool_free(pool);  // Closes all conns, frees entries
 * pool = NULL;  // Set to NULL per convention
 * Arena_dispose(&arena);  // Finally dispose arena
 * @endcode
 *
 * @complexity O(n) time where n = current connection count (closes each); O(1)
 * space
 *
 * @note Caller must ensure no threads are using pool entries during free.
 * @warning Concurrent modifications during free may cause use-after-free or
 * mutex poisoning.
 *
 * @see httpclient_pool_new() for creation and initialization.
 * @see Arena_dispose() for arena cleanup after pool_free.
 * @see Socket_free() underlying connection closes.
 * @see docs/HTTP-POOL.md for lifecycle management.
 */
extern void httpclient_pool_free (HTTPPool *pool);
/**
 * @brief Get or create a pool entry for the specified host:port and security.
 * @ingroup http
 *
 * Searches the pool's hash table for an existing idle entry matching the key.
 * If found, returns it marked as in_use. If not, and under limits, creates a
 * new entry. Does not establish the connection; that's done by
 * httpclient_connect().
 *
 * @param pool The HTTP connection pool.
 * @param host The target hostname (copied).
 * @param port The target port.
 * @param is_secure 1 if TLS connection required, 0 for plain HTTP.
 * @return HTTPPoolEntry* for the connection slot, or raises exception.
 * @throws SocketHTTPClient_Failed if max per host/total reached or allocation
 * fails.
 * @threadsafe Yes - acquires pool mutex.
 * @see httpclient_pool_release() to return after use.
 * @see httpclient_connect() to connect the entry.
 * @see httpclient_pool_new() for pool creation.
 */
extern HTTPPoolEntry *httpclient_pool_get (HTTPPool *pool, const char *host,
                                           int port, int is_secure);
/**
 * @brief Release a pool entry back to available state.
 * @ingroup http
 *
 * Marks the entry as idle (in_use = 0), updates last_used timestamp.
 * Does not close the connection; it's kept for reuse.
 * The entry remains in the hash table until idle timeout or explicit close.
 *
 * @param pool The HTTP pool.
 * @param entry The entry to release.
 * @throws None - failures logged.
 * @threadsafe Yes - mutex protected.
 * @see httpclient_pool_get() to acquire entry.
 * @see httpclient_pool_close() to close instead.
 * @see httpclient_pool_cleanup_idle() for idle cleanup.
 */
extern void httpclient_pool_release (HTTPPool *pool, HTTPPoolEntry *entry);
/**
 * @brief Close and remove a pool entry from the pool.
 * @ingroup http
 *
 * Closes the underlying socket connection, marks entry as closed, removes from
 * hash table and lists. Updates pool stats for failed connections. Used when
 * connection error or explicit shutdown needed.
 *
 * @param pool The HTTP pool.
 * @param entry The entry to close.
 * @throws None - socket close errors logged, not raised.
 * @threadsafe Conditional - hold mutex if concurrent.
 * @see httpclient_pool_release() for normal release without close.
 * @see Socket_close() for low-level close.
 */
extern void httpclient_pool_close (HTTPPool *pool, HTTPPoolEntry *entry);
/**
 * @brief Clean up idle connections that have exceeded timeout.
 * @ingroup http
 *
 * Scans all connections in the pool, closes those idle longer than configured
 * timeout. Removes closed entries from hash and lists, updates stats. Called
 * periodically or on pool access.
 *
 * @param pool The HTTP pool to clean.
 * @throws None - close failures logged.
 * @threadsafe Yes - acquires mutex.
 * @see SocketHTTPClient_Config.idle_timeout_ms for timeout config.
 * @see SocketPool_drain() for pool drain during shutdown.
 */
extern void httpclient_pool_cleanup_idle (HTTPPool *pool);

/* Connection management */
/**
 * @brief Establish connection to target URI, handling proxy and TLS.
 * @ingroup http
 *
 * Resolves host via DNS, connects socket, applies TLS if secure or proxy TLS.
 * Performs HTTP CONNECT to proxy if configured in client config.
 * Negotiates HTTP version (1.1 or 2) via ALPN or upgrade.
 * Initializes protocol state (parser or conn) in the pool entry.
 *
 * @param client The HTTP client instance for config, pool, DNS, TLS.
 * @param uri The target URI to connect to (host/port from URI).
 * @return HTTPPoolEntry with connected and initialized protocol state.
 * @throws SocketHTTPClient_DNSFailed on resolve fail.
 * @throws SocketHTTPClient_ConnectFailed on socket connect error.
 * @throws SocketHTTPClient_TLSFailed on handshake fail.
 * @throws SocketHTTPClient_ProtocolError on HTTP negotiation fail.
 * @threadsafe Conditional - client mutex held.
 * @see SocketDNS_resolve_sync() for DNS.
 * @see SocketTLS_handshake_auto() for TLS.
 * @see SocketHTTPClient_Config for proxy configuration options.
 */
extern HTTPPoolEntry *httpclient_connect (SocketHTTPClient_T client,
                                          const SocketHTTP_URI *uri);
/**
 * @brief Send HTTP request over the connection entry.
 * @ingroup http
 *
 * Serializes request to outbuf, sends via socket (TLS if secure).
 * Handles HTTP/1.1 or HTTP/2 send (headers frame + data stream).
 * Adds auth headers if needed, cookies from jar.
 * Updates pool stats for requests.
 *
 * @param conn The pool entry with socket and proto state.
 * @param req The request to send (method, URI, headers, body).
 * @return 0 on success, -1 on send error (sets error in client).
 * @throws SocketHTTPClient_Failed on serialization or send fail.
 * @threadsafe No - conn must be exclusively held.
 * @see SocketHTTP1_serialize_request() for HTTP/1.1.
 * @see SocketHTTP2_Stream_send_request() for HTTP/2.
 * @see httpclient_receive_response() to receive reply.
 */
extern int httpclient_send_request (HTTPPoolEntry *conn,
                                    SocketHTTPClient_Request_T req);
/**
 * @brief Receive and parse HTTP response from connection.
 * @ingroup http
 *
 * Reads from inbuf/socket, parses headers/body based on proto (HTTP/1.1 or 2).
 * Handles chunked, content-length, trailers.
 * Stores in response struct, allocates from arena.
 * Updates last_used time, checks keep-alive.
 *
 * @param conn The pool entry with socket and proto state.
 * @param response Output response to fill.
 * @param arena Arena for response allocations (headers, body).
 * @return 0 on success, -1 on parse or read error.
 * @throws SocketHTTPClient_Failed on parse error, SocketHTTP_ParseError
 * propagated.
 * @threadsafe No - conn exclusive.
 * @see SocketHTTP1_Parser_execute() for HTTP/1.1 parse.
 * @see SocketHTTP2_Conn_process() for HTTP/2.
 * @see SocketHTTPClient_Response for fields.
 */
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

/* Authentication helpers (uses SocketCrypto) */
/**
 * @brief Generate Basic authentication header value.
 * @ingroup http
 *
 * Encodes "username:password" in Base64, formats as "Basic <base64>".
 * No validation on inputs; assumes valid UTF8.
 *
 * @param username The username string.
 * @param password The password string.
 * @param output Buffer for the header value string.
 * @param output_size Size of output buffer (recommended 512).
 * @return 0 on success, -1 if buffer too small or null inputs.
 * @threadsafe Yes - stateless.
 * @see SocketCrypto_base64_encode() underlying.
 * @see docs/SECURITY.md for auth security notes.
 */
extern int httpclient_auth_basic_header (const char *username,
                                         const char *password, char *output,
                                         size_t output_size);
/**
 * @brief Compute Digest authentication response value.
 * @ingroup http
 *
 * Implements RFC 2617 Digest auth response calculation.
 * Supports qop="auth", MD5 or SHA-256 algorithm.
 * Computes HA1 = H({username:realm:password}), HA2 = H({method:uri}),
 * response = H(HA1:nonce:nc:cnonce:qop:HA2).
 * Outputs hex digest to buffer.
 *
 * @param username The username.
 * @param password The password (not stored after call).
 * @param realm The realm from challenge.
 * @param nonce The server nonce.
 * @param uri The request URI without query.
 * @param method The HTTP method name (e.g., "GET").
 * @param qop The qop value ("auth").
 * @param nc The nonce count string (e.g., "00000001").
 * @param cnonce The client nonce string.
 * @param use_sha256 1 for SHA-256, 0 for MD5.
 * @param output Buffer for hex response string.
 * @param output_size Size of output (33 for MD5, 65 for SHA256 + null).
 * @return 0 on success, -1 on invalid params or hash error.
 * @threadsafe Yes - stateless.
 * @throws None - returns -1.
 * @see SocketCrypto_md5(), SocketCrypto_sha256().
 * @see httpclient_auth_digest_challenge() for full handling.
 * @see docs/SECURITY.md for auth details.
 * @note Password zeroed after use? No, but sensitive; use secure memory if
 * possible.
 */
extern int httpclient_auth_digest_response (
    const char *username, const char *password, const char *realm,
    const char *nonce, const char *uri, const char *method, const char *qop,
    const char *nc, const char *cnonce, int use_sha256, char *output,
    size_t output_size);

/**
 * @brief Handle Digest authentication challenge from WWW-Authenticate header
 * and generate Authorization response.
 * @ingroup http
 *
 * Parses the WWW-Authenticate header for Digest params (realm, nonce, qop,
 * etc.). Generates client nonce, computes response using
 * httpclient_auth_digest_response(). Formats Authorization: Digest ... header
 * value. Handles MD5 or SHA256 based on algorithm param. NOTE: Supports only
 * qop=auth; not auth-int.
 *
 * @param www_authenticate The WWW-Authenticate header value string.
 * @param username User's username.
 * @param password User's password (sensitive).
 * @param method HTTP method (e.g., "GET").
 * @param uri Request URI (without host).
 * @param nc_value Nonce count string like "00000001".
 * @param output Buffer for Authorization header value.
 * @param output_size Size of output buffer (recommended 1024).
 * @return 0 on success, -1 on parse or computation error.
 * @threadsafe Yes - stateless.
 * @throws None - returns -1 on failure.
 * @see httpclient_auth_digest_response() for response calc.
 * @see docs/SECURITY.md for Digest auth details.
 * @see https://datatracker.ietf.org/doc/html/rfc7616 for spec.
 */
extern int httpclient_auth_digest_challenge (
    const char *www_authenticate, const char *username, const char *password,
    const char *method, const char *uri, const char *nc_value, char *output,
    size_t output_size);

/**
 * @brief Generate Authorization header for Bearer token authentication (RFC
 * 6750).
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
 * @brief Check if Digest challenge indicates stale nonce.
 * @ingroup http
 *
 * Parses WWW-Authenticate for "stale=true" param.
 * Allows automatic retry on stale nonce (server-side expiration) vs bad
 * credentials.
 *
 * @param www_authenticate The WWW-Authenticate header string.
 * @return 1 if stale=true found, 0 otherwise (or parse fail).
 * @threadsafe Yes - stateless parse.
 * @see httpclient_auth_digest_challenge() for full auth.
 * @see docs/SECURITY.md for retry logic.
 */
extern int httpclient_auth_is_stale_nonce (const char *www_authenticate);

/* Cookie helpers */
/**
 * @brief Generate Cookie header value from jar cookies applicable to URI.
 * @ingroup http
 *
 * Queries jar for cookies matching URI domain/path, sorts by path length,
 * selects per domain. Formats as "name1=value1; name2=value2; ..." string.
 * Applies SameSite policy if enforce_samesite=1 (skip Lax/Strict for
 * cross-site). Handles secure/httponly flags implicitly by selection.
 *
 * @param jar The cookie jar to query.
 * @param uri The request URI for domain/path/secure match.
 * @param output Buffer for the Cookie header value string.
 * @param output_size Size of output buffer (grow as needed? No, fixed).
 * @param enforce_samesite 1 to enforce SameSite=Lax/Strict policy, 0 to
 * include all.
 * @return 0 on success (header written or empty), -1 if buffer too small.
 * @threadsafe Yes - jar mutex held during query.
 * @see SocketHTTPClient_CookieJar for jar details.
 * @see httpclient_parse_set_cookie() for setting cookies.
 * @see docs/SECURITY.md "Cookies" for policy.
 * @note Empty string if no cookies; caller adds header only if length >0.
 */
extern int httpclient_cookies_for_request (
    SocketHTTPClient_CookieJar_T jar, const SocketHTTP_URI *uri, char *output,
    size_t output_size,
    int enforce_samesite); /* 1 to enforce SameSite cookie policy */
/**
 * @brief Parse Set-Cookie header and populate cookie structure.
 * @ingroup http
 *
 * Parses RFC 6265 Set-Cookie string, extracts name=value, attributes (expires,
 * path, domain, secure, httpOnly, SameSite). Sets defaults from request_uri if
 * not specified (domain/path). Allocates strings from arena. Validates dates,
 * domains.
 *
 * @param value The Set-Cookie header value string.
 * @param len Length of value (for non-null term).
 * @param request_uri URI for default domain/path/secure.
 * @param cookie Output cookie struct to fill (strings allocated).
 * @param arena Arena for allocations.
 * @return 0 on success, -1 on parse error (invalid format, date, etc.).
 * @threadsafe No - arena not safe, but parse stateless.
 * @see SocketHTTPClient_Cookie for struct fields.
 * @see httpclient_cookies_for_request() for using cookies.
 * @see docs/SECURITY.md "Cookies" for parsing security.
 * @note Handles quoted values, multiple attrs; strict RFC compliance.
 */
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
/**
 * @brief Determine if an HTTP client error is retryable.
 * @ingroup http
 *
 * Checks error type against client config retry policy.
 * Retryable: transient like DNS fail, connect timeout, server 5xx.
 * Non-retryable: client errors, TLS cert fail, too large response.
 *
 * @param client The client for config (max_retries, retryable_errors).
 * @param error The error code to check.
 * @return 1 if retryable (within attempts), 0 otherwise.
 * @threadsafe Yes.
 * @see SocketHTTPClient_Error for codes.
 * @see SocketHTTPClient_Config.max_retries for policy.
 * @see docs/HTTP-REFACTOR.md for retry logic.
 */
extern int httpclient_should_retry_error (const SocketHTTPClient_T client,
                                          SocketHTTPClient_Error error);
/**
 * @brief Determine if HTTP status code warrants retry.
 * @ingroup http
 *
 * Typically retry on 5xx server errors, some 4xx like 429 too many requests.
 * Configurable via client retry policy for specific codes.
 * Does not retry client errors (4xx except retryable) or success.
 *
 * @param client The client for config retry policy.
 * @param status The HTTP status code received.
 * @return 1 if retryable, 0 otherwise.
 * @threadsafe Yes.
 * @see httpclient_should_retry_error() for error-based retry.
 * @see SocketHTTPClient_Config.retry_status_codes for custom codes.
 * @see docs/HTTP-REFACTOR.md for status handling.
 */
extern int httpclient_should_retry_status (const SocketHTTPClient_T client,
                                           int status);
/**
 * @brief Calculate exponential backoff delay for retry attempt.
 * @ingroup http
 *
 * Uses client retry policy: initial_delay * multiplier^ (attempt-1) + jitter.
 * Caps at max_delay.
 * Jitter to avoid thundering herd.
 *
 * @param client The client for retry policy config.
 * @param attempt The current attempt number (1 = first retry).
 * @return Delay in milliseconds for sleep before next attempt.
 * @threadsafe Yes.
 * @see SocketHTTPClient_Config.retry_policy for params.
 * @see httpclient_retry_sleep_ms() to sleep.
 * @see docs/HTTP-REFACTOR.md for backoff strategy.
 */
extern int httpclient_calculate_retry_delay (const SocketHTTPClient_T client,
                                             int attempt);
/**
 * @brief Sleep for the specified milliseconds during retry backoff.
 * @ingroup http
 *
 * Simple nanosleep or select for delay.
 * Interruptible by signals? Handled per SocketTimeout.
 * Used in retry loops after delay calc.
 *
 * @param ms Milliseconds to sleep.
 * @throws None - continues on interrupt.
 * @threadsafe Yes.
 * @see httpclient_calculate_retry_delay() for delay value.
 * @see Socket_get_monotonic_ms() for timing.
 */
extern void httpclient_retry_sleep_ms (int ms);

/**
 * @brief Clear HTTP response for retry, preserving useful fields.
 * @ingroup http
 *
 * Resets body buffer, status, headers for new request/response cycle.
 * Keeps connection info if keep-alive.
 * Used before retrying same connection.
 *
 * @param response The response struct to clear.
 * @throws None.
 * @threadsafe Conditional - no locks, caller synchronize.
 * @see SocketHTTP_Response for fields reset.
 * @see httpclient_clear_response_for_retry() for client-specific.
 */
extern void clear_response_for_retry (SocketHTTP_Response *response);
/**
 * @brief Clear client-specific HTTP response for retry.
 * @ingroup http
 *
 * Resets client response fields like body, headers, status, error.
 * Calls clear_response_for_retry on internal SocketHTTP_Response.
 * Prepares for new response on same or new connection.
 *
 * @param response The client response to clear.
 * @throws None.
 * @threadsafe Conditional.
 * @see clear_response_for_retry() for core response clear.
 * @see SocketHTTPClient_Response for fields.
 */
extern void
httpclient_clear_response_for_retry (SocketHTTPClient_Response *response);

#endif /* SOCKETHTTPCLIENT_PRIVATE_INCLUDED */
