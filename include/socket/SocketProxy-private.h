/**
 * @file SocketProxy-private.h
 * @brief Internal structures and functions for SocketProxy module.
 * @ingroup core_io
 *
 * Part of the Socket Library.
 *
 * This header contains private implementation details for proxy protocol
 * support (SOCKS4/5, HTTP CONNECT). Not intended for public use - APIs and
 * structures may change without notice.
 *
 * @see SocketProxy.h for public API.
 * @see core_io for related socket primitives.
 */

#ifndef SOCKETPROXY_PRIVATE_INCLUDED
#define SOCKETPROXY_PRIVATE_INCLUDED

#include "core/Arena.h"
#include "core/SocketUtil.h"
#include "dns/SocketDNS.h"
#include "http/SocketHTTP1.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"
#include "socket/SocketHappyEyeballs.h"
#include "socket/SocketProxy.h"

#include <stdint.h>
#include <time.h>

/**
 * @brief Internal constants for buffer sizes and timeouts.
 * @ingroup core_io
 *
 * Configurable limits for error buffers, I/O buffers, URL lengths,
 * and default poll timeouts in proxy operations.
 *
 * @see SocketProxy_Conn_T fields using these (e.g., error_buf size).
 */

/** Error buffer size */
#ifndef SOCKET_PROXY_ERROR_BUFSIZE
#define SOCKET_PROXY_ERROR_BUFSIZE 256
#endif

/** Internal I/O buffer size */
#ifndef SOCKET_PROXY_BUFFER_SIZE
#define SOCKET_PROXY_BUFFER_SIZE                                              \
  65536 // Increased for large HTTP headers (64KB max per SocketHTTP.h)
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

/** Default poll timeout when no specific timeout is pending (ms) */
#ifndef SOCKET_PROXY_DEFAULT_POLL_TIMEOUT_MS
#define SOCKET_PROXY_DEFAULT_POLL_TIMEOUT_MS 1000
#endif

/**
 * @brief SOCKS Protocol Constants (RFC 1928, RFC 1929).
 * @ingroup core_io
 *
 * Defines for SOCKS4 and SOCKS5 protocol versions, commands, replies,
 * address types, and response sizes used in proxy handshakes.
 *
 * @see RFC 1928 "SOCKS Protocol Version 5"
 * @see RFC 1929 "Username/Password Authentication for SOCKS V5"
 */

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

/** SOCKS5 address sizes (RFC 1928 Section 4) */
#define SOCKS5_IPV4_ADDR_SIZE 4  /**< IPv4 address bytes */
#define SOCKS5_IPV6_ADDR_SIZE 16 /**< IPv6 address bytes */
#define SOCKS5_PORT_SIZE 2       /**< Port bytes (network order) */

/** SOCKS5 response sizes */
#define SOCKS5_METHOD_RESPONSE_SIZE 2 /**< VER + METHOD */
#define SOCKS5_AUTH_RESPONSE_SIZE 2   /**< VER + STATUS */
#define SOCKS5_CONNECT_HEADER_SIZE 4  /**< VER + REP + RSV + ATYP */

/** SOCKS5 greeting response sizes */
#define SOCKS5_CONNECT_IPV4_RESPONSE_SIZE                                     \
  (SOCKS5_CONNECT_HEADER_SIZE + SOCKS5_IPV4_ADDR_SIZE + SOCKS5_PORT_SIZE)
#define SOCKS5_CONNECT_IPV6_RESPONSE_SIZE                                     \
  (SOCKS5_CONNECT_HEADER_SIZE + SOCKS5_IPV6_ADDR_SIZE + SOCKS5_PORT_SIZE)

/* ============================================================================
 * Internal Protocol State
 * ============================================================================
 */

/**
 * @brief Protocol-specific sub-state for proxy handshakes.
 * @ingroup core_io
 *
 * Enumerates detailed states for SOCKS4/5 and HTTP CONNECT protocols
 * during the proxy negotiation process.
 *
 * @see SocketProxy_State for high-level connection state.
 * @see SocketProxy_Conn_T::proto_state for usage.
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

/**
 * @brief Centralized exception handling for SocketProxy module.
 * @ingroup core_io
 *
 * Uses SocketUtil.h infrastructure for consistent, thread-safe error handling:
 * - Thread-local socket_error_buf (SOCKET_PROXY_ERROR_BUFSIZE = 256 bytes).
 * - PROXY_ERROR_FMT/MSG macros delegate to SOCKET_ERROR_*.
 * - RAISE_PROXY_ERROR(e) raises Proxy_DetailedException with details.
 *
 * Benefits:
 * - Shared TLS buffer across modules.
 * - Automatic integration with SocketLog_emit for logging.
 * - Prevents race conditions in multi-threaded exception raising.
 *
 * @note Must declare SOCKET_DECLARE_MODULE_EXCEPTION(Proxy) in each .c file.
 * @note Use before RAISE_PROXY_ERROR: PROXY_ERROR_FMT("error: %s", reason);
 *
 * @see SocketUtil.h "Error Handling" section for base macros.
 * @see RAISE_PROXY_ERROR for raising.
 * @see docs/ERROR_HANDLING.md for patterns.
 */

/* Override log component for this module */
#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "Proxy"

/**
 * Error formatting macros - delegate to centralized infrastructure.
 * Uses socket_error_buf from SocketUtil.h (thread-local, 256 bytes).
 */
/**
 * @brief Format proxy error message with errno details.
 * @ingroup core_io
 *
 * Delegates to SOCKET_ERROR_FMT, populating thread-local socket_error_buf
 * with formatted message including strerror(errno).
 *
 * @param fmt printf-style format string.
 * @param ... Arguments for format.
 * @see SOCKET_ERROR_FMT for base implementation.
 * @see PROXY_ERROR_MSG for non-errno version.
 */
#define PROXY_ERROR_FMT(fmt, ...) SOCKET_ERROR_FMT (fmt, ##__VA_ARGS__)

/**
 * @brief Format proxy error message without errno details.
 * @ingroup core_io
 *
 * Delegates to SOCKET_ERROR_MSG, populating thread-local socket_error_buf
 * with formatted message (no strerror).
 *
 * @param fmt printf-style format string.
 * @param ... Arguments for format.
 * @see SOCKET_ERROR_MSG for base implementation.
 * @see PROXY_ERROR_FMT for errno version.
 */
#define PROXY_ERROR_MSG(fmt, ...) SOCKET_ERROR_MSG (fmt, ##__VA_ARGS__)

/**
 * @brief Raise a Proxy module exception with formatted error message.
 * @ingroup core_io
 *
 * Uses centralized exception infrastructure from SocketUtil.h.
 * Formats error using socket_error_buf (thread-local, 256 bytes) and raises
 * via SOCKET_RAISE_MODULE_ERROR(Proxy, e).
 *
 * @param e Specific exception type (e.g., Proxy_Failed, Proxy_Timeout).
 *
 * @note Thread-safe: Uses thread-local error buffer.
 * @note Requires SOCKET_DECLARE_MODULE_EXCEPTION(Proxy) in the .c file.
 *
 * @see PROXY_ERROR_FMT() and PROXY_ERROR_MSG() for error formatting.
 * @see SOCKET_RAISE_MODULE_ERROR() for base macro.
 * @see SocketUtil.h "Error Handling" section.
 */
#define RAISE_PROXY_ERROR(e) SOCKET_RAISE_MODULE_ERROR (Proxy, e)

/* ============================================================================
 * Main Context Structure
 * ============================================================================
 */

/**
 * @brief Proxy connection context structure.
 * @ingroup core_io
 *
 * Manages state and resources for a single proxy connection negotiation,
 * including DNS resolution, socket I/O, protocol handshakes (SOCKS4/5, HTTP CONNECT),
 * TLS (if enabled), and timeouts.
 *
 * Fields:
 * - Configuration: type, hosts, credentials, timeouts, headers.
 * - Resources: arena (lifecycle), socket (transferred on success), buffers.
 * - Async: dns, poll, HappyEyeballs context.
 * - State: main state, proto_state, result.
 * - I/O: send/recv buffers and offsets.
 *
 * @note Opaque to public API; access via SocketProxy_Conn_* functions (internal).
 * @note Thread-unsafe: Designed for single-threaded operation.
 * @note On success, socket is transferred to caller; other resources cleaned up.
 *
 * @see SocketProxy.h for public interface.
 * @see SocketProxy_ProtoState for protocol states.
 * @see SocketProxy_State for high-level states.
 */
struct SocketProxy_Conn_T
{
  /* Configuration (copied from user) */
  SocketProxyType type;     /**< Proxy type */
  char *proxy_host;         /**< Proxy hostname (arena copy) */
  int proxy_port;           /**< Proxy port */
  char *username;           /**< Username (arena copy, may be NULL) */
  char *password;           /**< Password (arena copy, may be NULL) */
  char *target_host;        /**< Target hostname (arena copy) */
  int target_port;          /**< Target port */
  int connect_timeout_ms;   /**< Proxy connect timeout */
  int handshake_timeout_ms; /**< Handshake timeout */
  SocketHTTP_Headers_T extra_headers; /**< HTTP CONNECT extra headers */
#if SOCKET_HAS_TLS
  SocketTLSContext_T tls_ctx; /**< TLS context from config (copied ptr) */
  int tls_enabled;            /**< 1 after successful TLS handshake to proxy */
#endif

  /* Internal resources (owned) */
  Arena_T arena;       /**< Memory arena for all allocations */
  Socket_T socket;     /**< Proxy socket (transferred to caller on success) */
  SocketBuf_T recvbuf; /**< Receive buffer for protocol parsing */

  /* Async connection resources */
  SocketDNS_T dns;   /**< DNS resolver for async connection */
  SocketPoll_T poll; /**< Poll instance for async connection */
  SocketHE_T he;     /**< HappyEyeballs context (during connect) */
  int owns_dns_poll; /**< 1 if we own dns/poll (sync wrapper), 0 if external */

  /* HTTP CONNECT specific */
  SocketHTTP1_Parser_T http_parser; /**< HTTP response parser */

  /* State machine */
  SocketProxy_State state;            /**< Main state */
  SocketProxy_ProtoState proto_state; /**< Protocol sub-state */
  SocketProxy_Result result;          /**< Final result */

  /* SOCKS5 state */
  int socks5_auth_method; /**< Selected auth method */
  int socks5_need_auth;   /**< 1 if auth required */

  /* Timing */
  int64_t start_time_ms;           /**< When operation started */
  int64_t handshake_start_time_ms; /**< When handshake started */

  /* I/O state */
  unsigned char send_buf[SOCKET_PROXY_BUFFER_SIZE]; /**< Send buffer */
  size_t send_len;                                  /**< Data in send buffer */
  size_t send_offset;                               /**< Bytes already sent */
  unsigned char recv_buf[SOCKET_PROXY_BUFFER_SIZE]; /**< Temp receive buffer */
  size_t recv_len;    /**< Data in receive buffer */
  size_t recv_offset; /**< Bytes already processed */

  /* Error tracking */
  char error_buf[SOCKET_PROXY_ERROR_BUFSIZE]; /**< Error message */
  int transferred; /**< 1 if socket transferred to caller */
};

/* ============================================================================
 * Internal Helper Functions - Time
 * ============================================================================
 */

/**
 * @brief Get current monotonic time in milliseconds.
 * @ingroup core_io
 *
 * Uses CLOCK_MONOTONIC for reliable, non-decreasing time suitable for timeouts.
 *
 * @return Monotonic time since some unspecified point (ms), or 0 on clock failure.
 *
 * @note Thread-safe: Yes, clock_gettime is atomic.
 * @note Prefer over gettimeofday() to avoid system time changes affecting timeouts.
 *
 * @see socketproxy_elapsed_ms() for elapsed time calculation.
 * @see SocketUtil.h "Timeout Utilities" for related functions.
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
 * @brief Calculate elapsed time since start in milliseconds.
 * @ingroup core_io
 * @param start_ms Start time from socketproxy_get_time_ms().
 *
 * Computes current time - start_ms, clamping to 0 if negative (clock issues).
 *
 * @return Non-negative elapsed milliseconds.
 *
 * @note Thread-safe: Yes, as it calls thread-safe functions.
 *
 * @see socketproxy_get_time_ms() for obtaining timestamps.
 * @see Socket_get_monotonic_ms() alternative in SocketUtil.h.
 */
static inline int64_t
socketproxy_elapsed_ms (int64_t start_ms)
{
  int64_t elapsed = socketproxy_get_time_ms () - start_ms;
  return (elapsed < 0) ? 0 : elapsed;
}

/* ============================================================================
 * Protocol Handler Function Types
 * ============================================================================
 */

/**
 * @brief Protocol send function type for building proxy requests.
 * @ingroup core_io
 *
 * Builds the protocol-specific request (e.g., SOCKS greeting, HTTP CONNECT)
 * into conn->send_buf and sets conn->send_len.
 *
 * @param conn Proxy connection context.
 * @return 0 on success, -1 on error (sets error via PROXY_ERROR_* macros).
 *
 * @see ProxyRecvFunc for receive counterpart.
 * @see SocketProxy_Conn_T::send_buf for buffer details.
 * @see socketproxy_do_send() for sending the built request.
 */
typedef int (*ProxySendFunc) (struct SocketProxy_Conn_T *conn);

/**
 * @brief Protocol receive function type for parsing proxy responses.
 * @ingroup core_io
 *
 * Parses the protocol-specific response from conn->recv_buf / recv_len,
 * updating conn->proto_state and result as needed.
 *
 * @param conn Proxy connection context.
 * @return SocketProxy_Result: PROXY_OK (complete), PROXY_IN_PROGRESS (need more data),
 *          or error (e.g., PROXY_PROTOCOL_ERROR).
 *
 * @see ProxySendFunc for send counterpart.
 * @see SocketProxy_Conn_T::recv_buf for buffer details.
 * @see socketproxy_do_recv() for receiving data into buffer.
 * @see socketproxy_advance_state() for state transitions after parse.
 */
typedef SocketProxy_Result (*ProxyRecvFunc) (struct SocketProxy_Conn_T *conn);

/* ============================================================================
 * Internal Protocol Functions - SOCKS5 (RFC 1928/1929)
 * ============================================================================
 */

/**
 * @brief Build and prepare SOCKS5 greeting message (RFC 1928).
 * @ingroup core_io
 * @param conn Proxy connection context.
 *
 * Constructs SOCKS5 version 5 greeting with supported authentication methods
 * (no auth, username/password if credentials provided).
 * Populates conn->send_buf and sets conn->send_len.
 *
 * @return 0 on success, -1 on error (e.g., invalid config, sets PROXY_ERROR_*).
 * @throws Proxy_Failed on build failure.
 *
 * @see proxy_socks5_recv_method() for response handling.
 * @see RFC 1928 Section 2 for protocol details.
 * @see SocketProxy_Conn_T::socks5_auth_method for selected method.
 */
extern int proxy_socks5_send_greeting (struct SocketProxy_Conn_T *conn);

/**
 * @brief Parse SOCKS5 method selection response (RFC 1928).
 * @ingroup core_io
 * @param conn Proxy connection context.
 *
 * Parses greeting response from conn->recv_buf, selects auth method,
 * updates conn->socks5_auth_method and advances proto_state.
 *
 * @return PROXY_OK if method selected, PROXY_PROTOCOL_ERROR on invalid response,
 *         PROXY_IN_PROGRESS if incomplete data.
 *
 * @see proxy_socks5_send_greeting() for request.
 * @see RFC 1928 Section 2 for response format.
 * @see SOCKS5_AUTH_* constants for methods.
 */
extern SocketProxy_Result
proxy_socks5_recv_method (struct SocketProxy_Conn_T *conn);

/**
 * @brief Build SOCKS5 username/password authentication request (RFC 1929).
 * @ingroup core_io
 * @param conn Proxy connection context (must have selected auth method 0x02).
 *
 * Constructs auth subnegotiation request using conn->username and conn->password.
 * Populates conn->send_buf and conn->send_len.
 *
 * @return 0 on success, -1 on error (e.g., missing credentials).
 * @throws Proxy_Failed if credentials invalid or too long.
 *
 * @see proxy_socks5_recv_auth() for response.
 * @see RFC 1929 for auth protocol.
 * @see SocketProxy_Conn_T::username, ::password
 */
extern int proxy_socks5_send_auth (struct SocketProxy_Conn_T *conn);

/**
 * @brief Parse SOCKS5 username/password authentication response (RFC 1929).
 * @ingroup core_io
 * @param conn Proxy connection context.
 *
 * Parses auth response from conn->recv_buf, checks status, advances state if success.
 *
 * @return PROXY_OK on success, PROXY_PROTOCOL_ERROR on failure/invalid, PROXY_IN_PROGRESS if incomplete.
 *
 * @see proxy_socks5_send_auth() for request.
 * @see RFC 1929 Section 2 for response format.
 */
extern SocketProxy_Result
proxy_socks5_recv_auth (struct SocketProxy_Conn_T *conn);

/**
 * @brief Build SOCKS5 CONNECT command request (RFC 1928).
 * @ingroup core_io
 * @param conn Proxy connection context (auth complete).
 *
 * Constructs connect command with target host/port and address type (IPv4/domain/IPv6).
 * Populates conn->send_buf and conn->send_len.
 *
 * @return 0 on success, -1 on error (e.g., invalid target).
 * @throws Proxy_Failed on build error.
 *
 * @see proxy_socks5_recv_connect() for response.
 * @see RFC 1928 Section 4 for command format.
 * @see SOCKS5_CMD_CONNECT, SOCKS5_ATYP_* constants.
 */
extern int proxy_socks5_send_connect (struct SocketProxy_Conn_T *conn);

/**
 * @brief Parse SOCKS5 CONNECT response (RFC 1928).
 * @ingroup core_io
 * @param conn Proxy connection context.
 *
 * Parses response from conn->recv_buf, checks reply code and bound address,
 * maps to SocketProxy_Result, sets conn->result and advances state.
 *
 * @return Mapped result: PROXY_OK on success (reply 0x00), errors otherwise,
 *         PROXY_IN_PROGRESS if data incomplete.
 *
 * @see proxy_socks5_send_connect() for request.
 * @see proxy_socks5_reply_to_result() for reply mapping.
 * @see RFC 1928 Section 4 for response format.
 */
extern SocketProxy_Result
proxy_socks5_recv_connect (struct SocketProxy_Conn_T *conn);

/**
 * @brief Map SOCKS5 reply code to SocketProxy_Result.
 * @ingroup core_io
 * @param reply SOCKS5 reply code (0x00-0x08, 0xFF).
 *
 * Converts protocol reply to library result for error propagation.
 *
 * @return Equivalent SocketProxy_Result (PROXY_OK for 0x00, PROXY_PROXY_ERROR otherwise).
 *
 * @see SOCKS5_REPLY_* constants for codes.
 * @see proxy_socks5_recv_connect() usage.
 */
extern SocketProxy_Result proxy_socks5_reply_to_result (int reply);

/**
 * @brief Internal functions for SOCKS4 and SOCKS4a protocol handling.
 * @ingroup core_io
 *
 * Implements SOCKS4 connect requests (IPv4 only) and SOCKS4a extension for domain names.
 *
 * @see RFC 1928 Appendix A for SOCKS4 details (informational).
 * @see proxy_socks4_send_connect(), proxy_socks4a_send_connect() for requests.
 */

/**
 * @brief Build SOCKS4 CONNECT request (IPv4 only).
 * @ingroup core_io
 * @param conn Proxy connection context (target must resolve to IPv4).
 *
 * Constructs SOCKS4 version 4 request with target IP/port and dummy user ID "socket".
 * Populates conn->send_buf and conn->send_len. No authentication.
 *
 * @return 0 on success, -1 if target not IPv4.
 * @throws Proxy_Failed on invalid target address.
 *
 * @see proxy_socks4_recv_response() for response.
 * @see RFC 1928 Appendix A for SOCKS4 format.
 */
extern int proxy_socks4_send_connect (struct SocketProxy_Conn_T *conn);

/**
 * @brief Build SOCKS4a CONNECT request with hostname (non-standard extension).
 * @ingroup core_io
 * @param conn Proxy connection context (target as domain name).
 *
 * SOCKS4 extension for domain names: sets IP to 0.0.0.nonzero, appends hostname.
 * Dummy user ID "socket". No authentication.
 *
 * @return 0 on success, -1 on error (e.g., hostname too long).
 * @throws Proxy_Failed on invalid hostname.
 *
 * @see proxy_socks4_recv_response() for response (shared with SOCKS4).
 * @see RFC 1928 Appendix A for base SOCKS4; 4a is unofficial extension.
 */
extern int proxy_socks4a_send_connect (struct SocketProxy_Conn_T *conn);

/**
 * @brief Parse SOCKS4/SOCKS4a response.
 * @ingroup core_io
 * @param conn Proxy connection context.
 *
 * Parses response from conn->recv_buf, checks version/reply, maps to result,
 * sets conn->result and advances state.
 *
 * @return Mapped result: PROXY_OK for granted (90), errors otherwise,
 *         PROXY_IN_PROGRESS if incomplete.
 *
 * @see proxy_socks4_send_connect(), proxy_socks4a_send_connect() for requests.
 * @see proxy_socks4_reply_to_result() for reply mapping.
 * @see RFC 1928 Appendix A for response format.
 */
extern SocketProxy_Result
proxy_socks4_recv_response (struct SocketProxy_Conn_T *conn);

/**
 * @brief Map SOCKS4 reply code to SocketProxy_Result.
 * @ingroup core_io
 * @param reply SOCKS4 reply code (90-93).
 *
 * Converts protocol reply to library result.
 *
 * @return PROXY_OK for 90 (granted), PROXY_PROXY_ERROR otherwise.
 *
 * @see SOCKS4_REPLY_* constants.
 * @see proxy_socks4_recv_response() usage.
 */
extern SocketProxy_Result proxy_socks4_reply_to_result (int reply);

/**
 * @brief Internal functions for HTTP CONNECT proxy method (RFC 7230).
 * @ingroup core_io
 *
 * Implements HTTP proxy tunneling via CONNECT method for HTTPS/TLS over proxy.
 *
 * @see RFC 7230 Section 5.3.2 for CONNECT semantics.
 * @see SocketHTTP1.h for HTTP parsing used in response.
 */

/**
 * @brief Build HTTP CONNECT request for proxy tunneling (RFC 7230).
 * @ingroup core_io
 * @param conn Proxy connection context.
 *
 * Constructs CONNECT target_host:target_port HTTP/1.1 request with basic auth
 * (if credentials) and extra_headers. Populates conn->send_buf/send_len.
 *
 * @return 0 on success, -1 on error (e.g., invalid URI).
 * @throws Proxy_Failed on build failure.
 *
 * @see proxy_http_recv_response() for response parsing.
 * @see RFC 7230 Section 5.3.2 for method details.
 * @see SocketHTTP_Headers_T for extra_headers.
 */
extern int proxy_http_send_connect (struct SocketProxy_Conn_T *conn);

/**
 * @brief Parse HTTP CONNECT response using SocketHTTP1 parser.
 * @ingroup core_io
 * @param conn Proxy connection context.
 *
 * Feeds recv_buf into http_parser, checks status code (200 expected for tunnel),
 * maps to result, advances state on success.
 *
 * @return PROXY_OK for 2xx status, PROXY_HTTP_ERROR otherwise,
 *         PROXY_IN_PROGRESS if response incomplete.
 *
 * @see proxy_http_send_connect() for request.
 * @see proxy_http_status_to_result() for status mapping.
 * @see SocketHTTP1_Parser_T for parsing details.
 */
extern SocketProxy_Result
proxy_http_recv_response (struct SocketProxy_Conn_T *conn);

/**
 * @brief Map HTTP status code to SocketProxy_Result for CONNECT.
 * @ingroup core_io
 * @param status HTTP status code (100-599).
 *
 * Maps status to result: 2xx -> OK, 4xx/5xx -> errors.
 *
 * @return Appropriate SocketProxy_Result based on category.
 *
 * @see SocketHTTP_status_category() related utility.
 * @see proxy_http_recv_response() usage.
 */
extern SocketProxy_Result proxy_http_status_to_result (int status);

/**
 * @brief Internal state machine functions for proxy negotiation.
 * @ingroup core_io
 *
 * Handles state transitions, I/O operations on buffers, and error setting
 * during the multi-step proxy handshake process.
 *
 * @see SocketProxy_State, SocketProxy_ProtoState for states.
 */

/**
 * @brief Advance proxy state machine based on current proto_state.
 * @ingroup core_io
 * @param conn Proxy connection context.
 *
 * Determines next action based on state (e.g., send greeting, parse response),
 * calls appropriate protocol functions or completes handshake.
 *
 * @note Called internally after send/recv completes successfully.
 *
 * @see SocketProxy_ProtoState for sub-states.
 * @see ProxySendFunc, ProxyRecvFunc for protocol handlers.
 */
extern void socketproxy_advance_state (struct SocketProxy_Conn_T *conn);

/**
 * @brief Set error state and format message in conn->error_buf.
 * @ingroup core_io
 * @param conn Proxy connection context.
 * @param result Error SocketProxy_Result code.
 * @param fmt printf-style format for error_buf.
 * @param ... Arguments for fmt.
 *
 * Formats message using vsnprintf into conn->error_buf, sets state to ERROR,
 * result, logs via SOCKET_LOG_ERROR_MSG.
 *
 * @note Truncates if message > SOCKET_PROXY_ERROR_BUFSIZE.
 *
 * @see SocketProxy_Conn_T::error_buf, ::result
 * @see RAISE_PROXY_ERROR for exception raising.
 */
extern void socketproxy_set_error (struct SocketProxy_Conn_T *conn,
                                   SocketProxy_Result result, const char *fmt,
                                   ...);

/**
 * @brief Send pending protocol data from conn->send_buf.
 * @ingroup core_io
 * @param conn Proxy connection context.
 *
 * Uses Socket_send or SocketTLS_send (if TLS) to send remaining bytes,
 * updates send_offset. Handles partial sends (non-blocking).
 *
 * @return 0 all sent, 1 partial (EAGAIN), -1 error (sets errno, may raise).
 *
 * @note Handles TLS if conn->tls_enabled.
 * @see SocketProxy_Conn_T::send_buf, ::send_len, ::send_offset
 * @see socketproxy_advance_state() called after full send.
 */
extern int socketproxy_do_send (struct SocketProxy_Conn_T *conn);

/**
 * @brief Receive protocol data into conn->recv_buf.
 * @ingroup core_io
 * @param conn Proxy connection context.
 *
 * Uses Socket_recv or SocketTLS_recv to fill recv_buf from recv_offset,
 * handles partial receives. Appends to existing data.
 *
 * @return >0 bytes received, 0 EOF, -1 error (EAGAIN returns -1 but ok, check errno).
 *
 * @note Updates recv_len, handles TLS if enabled.
 * @see SocketProxy_Conn_T::recv_buf, ::recv_len, ::recv_offset
 * @see socketproxy_advance_state() after successful recv.
 */
extern int socketproxy_do_recv (struct SocketProxy_Conn_T *conn);

/**
 * @brief Helper functions for parsing proxy URLs.
 * @ingroup core_io
 *
 * Parses proxy://userinfo@host:port format into config.
 * Supports socks4://, socks5://, http:// schemes.
 *
 * @see SocketProxy_Config for output structure.
 * @see socketproxy_parse_scheme(), parse_userinfo(), parse_hostport().
 */

/**
 * @brief Parse proxy URL scheme and set type.
 * @ingroup core_io
 * @param url Input URL string (e.g., "socks5://proxy.example.com").
 * @param[out] config Output config, sets type based on scheme.
 * @param[out] end Pointer after parsed scheme:// (for next parse step).
 *
 * Recognizes "socks4", "socks5", "http"; sets SOCKET_PROXY_SOCKS4 etc.
 *
 * @return 0 on success, -1 on unknown scheme (sets errno EINVAL).
 *
 * @see SocketProxyType enum values.
 * @see SocketProxy_Config::type
 */
extern int socketproxy_parse_scheme (const char *url,
                                     SocketProxy_Config *config,
                                     const char **end);

/**
 * @brief Parse optional [user[:pass]@] from URL.
 * @ingroup core_io
 * @param start Start of potential userinfo (after scheme://).
 * @param[out] config Output, sets username/password if present.
 * @param arena Arena for strdup copies; NULL uses static buffer (non-thread-safe).
 * @param[out] end Updated to after @ or start if none.
 *
 * Supports basic auth parsing; URL-decodes if needed? (simple colon split).
 *
 * @return 0 success (found or not), -1 parse error (long creds).
 *
 * @see SocketProxy_Config::username, ::password
 * @see Arena_T for memory management.
 */
extern int socketproxy_parse_userinfo (const char *start,
                                       SocketProxy_Config *config,
                                       Arena_T arena, const char **end);

/**
 * @brief Parse [host]:port from URL, handling IPv6 literals.
 * @ingroup core_io
 * @param start Start of host/port section (after userinfo@).
 * @param[out] config Output, sets proxy_host and proxy_port (default per type).
 * @param arena Arena for host copy; NULL uses static.
 * @param[out] consumed_out Optional: bytes parsed (including port).
 *
 * Parses host (domain/IPv4/IPv6), optional :port (defaults: 1080 socks, 8080 http).
 * Validates port range, copies host to arena or static buf.
 *
 * @return 0 success, -1 invalid host/port.
 *
 * @note IPv6 requires [] brackets.
 * @see SocketProxy_Config::proxy_host, ::proxy_port
 * @see socket_util_arena_strdup() for copying.
 */
extern int socketproxy_parse_hostport (const char *start,
                                       SocketProxy_Config *config,
                                       Arena_T arena, size_t *consumed_out);

#endif /* SOCKETPROXY_PRIVATE_INCLUDED */
