/**
 * SocketProxy-private.h - Internal structures for Proxy Support
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * This header contains internal implementation details for the SocketProxy
 * module. Not for public use - structures may change without notice.
 */

#ifndef SOCKETPROXY_PRIVATE_INCLUDED
#define SOCKETPROXY_PRIVATE_INCLUDED

#include "core/Arena.h"
#include "core/SocketUtil.h"
#include "http/SocketHTTP1.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"
#include "socket/SocketHappyEyeballs.h"
#include "socket/SocketProxy.h"

#include <stdint.h>
#include <time.h>

/* ============================================================================
 * Internal Constants
 * ============================================================================ */

/** Error buffer size */
#ifndef SOCKET_PROXY_ERROR_BUFSIZE
#define SOCKET_PROXY_ERROR_BUFSIZE 256
#endif

/** Internal I/O buffer size */
#ifndef SOCKET_PROXY_BUFFER_SIZE
#define SOCKET_PROXY_BUFFER_SIZE 4096
#endif

/** Maximum URL length for parsing */
#ifndef SOCKET_PROXY_MAX_URL_LEN
#define SOCKET_PROXY_MAX_URL_LEN 2048
#endif

/** Static buffer size for URL parsing (thread-local) */
#ifndef SOCKET_PROXY_STATIC_BUFFER_SIZE
#define SOCKET_PROXY_STATIC_BUFFER_SIZE 1024
#endif

/** Milliseconds per second for time conversion */
#define SOCKET_PROXY_MS_PER_SEC 1000

/** Nanoseconds per millisecond */
#define SOCKET_PROXY_NS_PER_MS 1000000LL

/* ============================================================================
 * SOCKS Protocol Constants (RFC 1928, RFC 1929)
 * ============================================================================ */

/** SOCKS4 version */
#define SOCKS4_VERSION 4

/** SOCKS4 connect command */
#define SOCKS4_CMD_CONNECT 1

/** SOCKS4 reply codes */
#define SOCKS4_REPLY_GRANTED 90
#define SOCKS4_REPLY_REJECTED 91
#define SOCKS4_REPLY_NO_IDENTD 92
#define SOCKS4_REPLY_IDENTD_MISMATCH 93

/** SOCKS5 version */
#define SOCKS5_VERSION 5

/** SOCKS5 auth version (RFC 1929) */
#define SOCKS5_AUTH_VERSION 1

/** SOCKS5 authentication methods */
#define SOCKS5_AUTH_NONE 0x00
#define SOCKS5_AUTH_GSSAPI 0x01
#define SOCKS5_AUTH_PASSWORD 0x02
#define SOCKS5_AUTH_NO_ACCEPTABLE 0xFF

/** SOCKS5 commands */
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_CMD_BIND 0x02
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03

/** SOCKS5 address types */
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_ATYP_IPV6 0x04

/** SOCKS5 reply codes */
#define SOCKS5_REPLY_SUCCESS 0x00
#define SOCKS5_REPLY_GENERAL_FAILURE 0x01
#define SOCKS5_REPLY_NOT_ALLOWED 0x02
#define SOCKS5_REPLY_NETWORK_UNREACHABLE 0x03
#define SOCKS5_REPLY_HOST_UNREACHABLE 0x04
#define SOCKS5_REPLY_CONNECTION_REFUSED 0x05
#define SOCKS5_REPLY_TTL_EXPIRED 0x06
#define SOCKS5_REPLY_COMMAND_NOT_SUPPORTED 0x07
#define SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED 0x08

/* ============================================================================
 * Internal Protocol State
 * ============================================================================ */

/**
 * SocketProxy_ProtoState - Protocol-specific sub-state
 *
 * Tracks detailed state within each protocol's handshake.
 */
typedef enum
{
  /* Common */
  PROTO_STATE_INIT = 0,

  /* SOCKS5 states */
  PROTO_STATE_SOCKS5_GREETING_SENT,
  PROTO_STATE_SOCKS5_METHOD_RECEIVED,
  PROTO_STATE_SOCKS5_AUTH_SENT,
  PROTO_STATE_SOCKS5_AUTH_RECEIVED,
  PROTO_STATE_SOCKS5_CONNECT_SENT,
  PROTO_STATE_SOCKS5_CONNECT_RECEIVED,

  /* SOCKS4/4a states */
  PROTO_STATE_SOCKS4_CONNECT_SENT,
  PROTO_STATE_SOCKS4_CONNECT_RECEIVED,

  /* HTTP CONNECT states */
  PROTO_STATE_HTTP_REQUEST_SENT,
  PROTO_STATE_HTTP_RESPONSE_RECEIVED,

  /* Done */
  PROTO_STATE_DONE
} SocketProxy_ProtoState;

/* ============================================================================
 * Thread-Local Error Buffer
 * ============================================================================ */

#ifdef _WIN32
extern __declspec (thread) char proxy_error_buf[SOCKET_PROXY_ERROR_BUFSIZE];
#else
extern __thread char proxy_error_buf[SOCKET_PROXY_ERROR_BUFSIZE];
#endif

/* Thread-local exception for detailed error messages */
#ifdef _WIN32
static __declspec (thread) Except_T Proxy_DetailedException;
#else
static __thread Except_T Proxy_DetailedException;
#endif

/* Error formatting macros */
#define PROXY_ERROR_FMT(fmt, ...)                                              \
  snprintf (proxy_error_buf, SOCKET_PROXY_ERROR_BUFSIZE,                       \
            fmt " (errno: %d - %s)", ##__VA_ARGS__, errno, strerror (errno))

#define PROXY_ERROR_MSG(fmt, ...)                                              \
  snprintf (proxy_error_buf, SOCKET_PROXY_ERROR_BUFSIZE, fmt, ##__VA_ARGS__)

#define RAISE_PROXY_ERROR(exception)                                           \
  do                                                                           \
    {                                                                          \
      Proxy_DetailedException = (exception);                                   \
      Proxy_DetailedException.reason = proxy_error_buf;                        \
      RAISE (Proxy_DetailedException);                                         \
    }                                                                          \
  while (0)

/* ============================================================================
 * Main Context Structure
 * ============================================================================ */

/**
 * SocketProxy_Conn_T - Proxy connection context
 *
 * Manages the full proxy connection process including:
 * - Connection to proxy server via HappyEyeballs
 * - TLS handshake to proxy (HTTPS)
 * - Protocol-specific handshake (SOCKS/HTTP CONNECT)
 * - Result tracking and error reporting
 */
struct SocketProxy_Conn_T
{
  /* Configuration (copied from user) */
  SocketProxyType type;               /**< Proxy type */
  char *proxy_host;                   /**< Proxy hostname (arena copy) */
  int proxy_port;                     /**< Proxy port */
  char *username;                     /**< Username (arena copy, may be NULL) */
  char *password;                     /**< Password (arena copy, may be NULL) */
  char *target_host;                  /**< Target hostname (arena copy) */
  int target_port;                    /**< Target port */
  int connect_timeout_ms;             /**< Proxy connect timeout */
  int handshake_timeout_ms;           /**< Handshake timeout */
  SocketHTTP_Headers_T extra_headers; /**< HTTP CONNECT extra headers */

  /* Internal resources (owned) */
  Arena_T arena;      /**< Memory arena for all allocations */
  Socket_T socket;    /**< Proxy socket (transferred to caller on success) */
  SocketBuf_T recvbuf;/**< Receive buffer for protocol parsing */
  SocketHE_T he;      /**< HappyEyeballs context (during connect) */

  /* HTTP CONNECT specific */
  SocketHTTP1_Parser_T http_parser; /**< HTTP response parser */

  /* State machine */
  SocketProxy_State state;            /**< Main state */
  SocketProxy_ProtoState proto_state; /**< Protocol sub-state */
  SocketProxy_Result result;          /**< Final result */

  /* SOCKS5 state */
  int socks5_auth_method;           /**< Selected auth method */
  int socks5_need_auth;             /**< 1 if auth required */

  /* Timing */
  int64_t start_time_ms;            /**< When operation started */
  int64_t handshake_start_time_ms;  /**< When handshake started */

  /* I/O state */
  unsigned char send_buf[SOCKET_PROXY_BUFFER_SIZE]; /**< Send buffer */
  size_t send_len;                  /**< Data in send buffer */
  size_t send_offset;               /**< Bytes already sent */
  unsigned char recv_buf[SOCKET_PROXY_BUFFER_SIZE]; /**< Temp receive buffer */
  size_t recv_len;                  /**< Data in receive buffer */
  size_t recv_offset;               /**< Bytes already processed */

  /* Error tracking */
  char error_buf[SOCKET_PROXY_ERROR_BUFSIZE]; /**< Error message */
  int transferred;                  /**< 1 if socket transferred to caller */
};

/* ============================================================================
 * Internal Helper Functions - Time
 * ============================================================================ */

/**
 * socketproxy_get_time_ms - Get monotonic time in milliseconds
 *
 * Returns: Current monotonic time in milliseconds
 * Thread-safe: Yes
 */
static inline int64_t
socketproxy_get_time_ms (void)
{
  struct timespec ts;

  if (clock_gettime (CLOCK_MONOTONIC, &ts) < 0)
    return 0;

  return (int64_t)ts.tv_sec * SOCKET_PROXY_MS_PER_SEC
         + (int64_t)ts.tv_nsec / SOCKET_PROXY_NS_PER_MS;
}

/**
 * socketproxy_elapsed_ms - Calculate elapsed time in milliseconds
 * @start_ms: Start time from socketproxy_get_time_ms()
 *
 * Returns: Elapsed milliseconds (always non-negative)
 * Thread-safe: Yes
 */
static inline int64_t
socketproxy_elapsed_ms (int64_t start_ms)
{
  int64_t elapsed = socketproxy_get_time_ms () - start_ms;
  return (elapsed < 0) ? 0 : elapsed;
}

/* ============================================================================
 * Protocol Handler Function Types
 * ============================================================================ */

/**
 * Protocol send function type
 *
 * Builds protocol request into conn->send_buf.
 * Returns: 0 on success, -1 on error
 */
typedef int (*ProxySendFunc) (struct SocketProxy_Conn_T *conn);

/**
 * Protocol receive function type
 *
 * Parses protocol response from conn->recv_buf.
 * Returns: PROXY_OK on success, PROXY_IN_PROGRESS if more data needed,
 *          or error code
 */
typedef SocketProxy_Result (*ProxyRecvFunc) (struct SocketProxy_Conn_T *conn);

/* ============================================================================
 * Internal Protocol Functions - SOCKS5 (RFC 1928/1929)
 * ============================================================================ */

/**
 * proxy_socks5_send_greeting - Build SOCKS5 greeting message
 * @conn: Proxy connection context
 *
 * Returns: 0 on success, -1 on error
 */
extern int proxy_socks5_send_greeting (struct SocketProxy_Conn_T *conn);

/**
 * proxy_socks5_recv_method - Parse SOCKS5 method selection response
 * @conn: Proxy connection context
 *
 * Returns: Result code
 */
extern SocketProxy_Result
proxy_socks5_recv_method (struct SocketProxy_Conn_T *conn);

/**
 * proxy_socks5_send_auth - Build SOCKS5 username/password auth request
 * @conn: Proxy connection context
 *
 * Returns: 0 on success, -1 on error
 */
extern int proxy_socks5_send_auth (struct SocketProxy_Conn_T *conn);

/**
 * proxy_socks5_recv_auth - Parse SOCKS5 auth response
 * @conn: Proxy connection context
 *
 * Returns: Result code
 */
extern SocketProxy_Result
proxy_socks5_recv_auth (struct SocketProxy_Conn_T *conn);

/**
 * proxy_socks5_send_connect - Build SOCKS5 connect request
 * @conn: Proxy connection context
 *
 * Returns: 0 on success, -1 on error
 */
extern int proxy_socks5_send_connect (struct SocketProxy_Conn_T *conn);

/**
 * proxy_socks5_recv_connect - Parse SOCKS5 connect response
 * @conn: Proxy connection context
 *
 * Returns: Result code
 */
extern SocketProxy_Result
proxy_socks5_recv_connect (struct SocketProxy_Conn_T *conn);

/**
 * proxy_socks5_reply_to_result - Map SOCKS5 reply code to result
 * @reply: SOCKS5 reply code
 *
 * Returns: SocketProxy_Result
 */
extern SocketProxy_Result proxy_socks5_reply_to_result (int reply);

/* ============================================================================
 * Internal Protocol Functions - SOCKS4/4a
 * ============================================================================ */

/**
 * proxy_socks4_send_connect - Build SOCKS4 connect request
 * @conn: Proxy connection context
 *
 * Returns: 0 on success, -1 on error
 */
extern int proxy_socks4_send_connect (struct SocketProxy_Conn_T *conn);

/**
 * proxy_socks4a_send_connect - Build SOCKS4a connect request (hostname)
 * @conn: Proxy connection context
 *
 * Returns: 0 on success, -1 on error
 */
extern int proxy_socks4a_send_connect (struct SocketProxy_Conn_T *conn);

/**
 * proxy_socks4_recv_response - Parse SOCKS4 response
 * @conn: Proxy connection context
 *
 * Returns: Result code
 */
extern SocketProxy_Result
proxy_socks4_recv_response (struct SocketProxy_Conn_T *conn);

/**
 * proxy_socks4_reply_to_result - Map SOCKS4 reply code to result
 * @reply: SOCKS4 reply code
 *
 * Returns: SocketProxy_Result
 */
extern SocketProxy_Result proxy_socks4_reply_to_result (int reply);

/* ============================================================================
 * Internal Protocol Functions - HTTP CONNECT
 * ============================================================================ */

/**
 * proxy_http_send_connect - Build HTTP CONNECT request
 * @conn: Proxy connection context
 *
 * Returns: 0 on success, -1 on error
 */
extern int proxy_http_send_connect (struct SocketProxy_Conn_T *conn);

/**
 * proxy_http_recv_response - Parse HTTP CONNECT response
 * @conn: Proxy connection context
 *
 * Returns: Result code
 */
extern SocketProxy_Result
proxy_http_recv_response (struct SocketProxy_Conn_T *conn);

/**
 * proxy_http_status_to_result - Map HTTP status code to result
 * @status: HTTP status code
 *
 * Returns: SocketProxy_Result
 */
extern SocketProxy_Result proxy_http_status_to_result (int status);

/* ============================================================================
 * Internal State Machine Functions
 * ============================================================================ */

/**
 * socketproxy_advance_state - Advance state machine
 * @conn: Proxy connection context
 *
 * Called after I/O to advance to next state.
 */
extern void socketproxy_advance_state (struct SocketProxy_Conn_T *conn);

/**
 * socketproxy_set_error - Set error state with message
 * @conn: Proxy connection context
 * @result: Error result code
 * @fmt: Error message format
 */
extern void socketproxy_set_error (struct SocketProxy_Conn_T *conn,
                                   SocketProxy_Result result, const char *fmt,
                                   ...);

/**
 * socketproxy_do_send - Send pending data from send buffer
 * @conn: Proxy connection context
 *
 * Returns: 0 if all sent, 1 if more to send, -1 on error
 */
extern int socketproxy_do_send (struct SocketProxy_Conn_T *conn);

/**
 * socketproxy_do_recv - Receive data into receive buffer
 * @conn: Proxy connection context
 *
 * Returns: Bytes received, 0 on EOF, -1 on error (EAGAIN ok)
 */
extern int socketproxy_do_recv (struct SocketProxy_Conn_T *conn);

/* ============================================================================
 * Internal URL Parser Helpers
 * ============================================================================ */

/**
 * socketproxy_parse_scheme - Parse URL scheme and set proxy type
 * @url: URL string
 * @config: Output config
 * @end: Output - pointer after scheme://
 *
 * Returns: 0 on success, -1 on error
 */
extern int socketproxy_parse_scheme (const char *url, SocketProxy_Config *config,
                                     const char **end);

/**
 * socketproxy_parse_userinfo - Parse optional user:pass@
 * @start: Start of userinfo section
 * @config: Output config
 * @arena: Arena for allocation (or NULL for static buffer)
 * @end: Output - pointer after userinfo (or start if none)
 *
 * Returns: 0 on success, -1 on error
 */
extern int socketproxy_parse_userinfo (const char *start,
                                       SocketProxy_Config *config, Arena_T arena,
                                       const char **end);

/**
 * socketproxy_parse_hostport - Parse host[:port]
 * @start: Start of host section
 * @config: Output config
 * @arena: Arena for allocation (or NULL for static buffer)
 *
 * Returns: 0 on success, -1 on error
 */
extern int socketproxy_parse_hostport (const char *start,
                                       SocketProxy_Config *config,
                                       Arena_T arena);

#endif /* SOCKETPROXY_PRIVATE_INCLUDED */

