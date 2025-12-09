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
 * @defgroup proxy_private SocketProxy Private Implementation Details
 * @ingroup core_io
 * @internal
 *
 * Exposes opaque types, constants, state enums, error macros, and helper functions
 * for implementing proxy tunneling via SOCKS and HTTP CONNECT protocols.
 *
 * Key internals:
 * - SocketProxy_Conn_T: Opaque context for connection lifecycle management including
 *   DNS resolution, socket I/O, protocol handshakes, and timeouts.
 * - SocketProxy_ProtoState: Sub-states for SOCKS5 multi-step negotiation (greeting, auth, connect).
 * - Protocol handler types (ProxySendFunc, ProxyRecvFunc) for state machine dispatching.
 * - SOCKS-specific functions for request building and response parsing (RFC 1928/1929).
 * - HTTP CONNECT handlers using SocketHTTP1_Parser_T for response validation.
 * - Time utilities using CLOCK_MONOTONIC for reliable timeout enforcement.
 * - URL parsing helpers supporting standard proxy URL formats.
 *
 * Security considerations:
 * - Credentials (username/password) copied to arena and securely cleared after use.
 * - Protocol parsing bounds-checked to prevent buffer overflows or injection attacks.
 * - Timeouts enforced to mitigate denial-of-service from malicious/slow proxies.
 * - Integration with SocketSYNProtect possible via pool for server-side proxying.
 *
 * Dependencies and reuse:
 * - Socket (core I/O) for buffered send/recv and TLS passthrough.
 * - SocketBuf for temporary protocol message buffering.
 * - SocketPoll and SocketDNS for asynchronous connection establishment.
 * - SocketHappyEyeballs for parallel proxy server resolution/connect racing.
 * - SocketHTTP1 for HTTP response parsing in CONNECT method.
 * - SocketTLSContext (conditional) for HTTPS proxy (TLS to proxy server).
 *
 * Error handling: Uses module exceptions (Proxy_Failed, etc.) with formatted messages
 * via PROXY_ERROR_* macros delegating to SocketUtil infrastructure.
 *
 * @see SocketProxy.h for public synchronous/asynchronous APIs.
 * @see SocketHappyEyeballs.h for proxy server connection optimization.
 * @see SocketHTTP1.h for HTTP CONNECT integration.
 * @see SocketTLS.h for optional HTTPS proxy support (#if SOCKET_HAS_TLS).
 * @see @ref core_io "Core I/O Modules" for foundational socket operations.
 * @see docs/PROXY.md for overview, URL formats, and usage examples.
 * @see docs/SECURITY.md for credential and TLS best practices.
 * @see docs/ERROR_HANDLING.md for exception patterns.
 *
 * @{
 *
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
 * @brief Internal constants for buffer sizes, timeouts, and protocol limits.
 * @ingroup core_io
 * @ingroup proxy_private
 *
 * Defines configurable sizes for buffers, URL parsing, and default timeouts
 * used throughout proxy negotiation. These control memory usage and performance.
 *
 * @note Values can be overridden via preprocessor before build.
 * @see SocketProxy_Conn_T for usage in fields like error_buf, send_buf.
 * @see socketproxy_parse_* functions for URL limits.
 * @see socketproxy_get_time_ms() for time conversions.
 */

/**
 * @brief Size of per-connection error message buffer.
 * @ingroup proxy_private
 *
 * Value: 256 bytes - sufficient for errno strings + context (e.g., "SOCKS5 auth failed on fd=5").
 * Used in SocketProxy_Conn_T::error_buf for socketproxy_set_error formatting.
 * Thread-local fallback via SocketUtil if needed, but instance-specific here.
 *
 * @see SocketProxy_Conn_T::error_buf
 * @see PROXY_ERROR_FMT(), PROXY_ERROR_MSG()
 * @see socketproxy_set_error()
 * @see SocketUtil.h "Error Handling" for base buffer.
 */
#ifndef SOCKET_PROXY_ERROR_BUFSIZE
#define SOCKET_PROXY_ERROR_BUFSIZE 256
#endif

/**
 * @brief Default size for internal send/receive buffers during handshake.
 * @ingroup proxy_private
 *
 * Value: 65536 bytes (64KB) - accommodates large HTTP CONNECT responses or SOCKS5 addr.
 * Increased for HTTP headers (max per SocketHTTP.h); used in conn->send_buf/recv_buf.
 * Balances memory and performance for typical proxy messages.
 *
 * @see SocketProxy_Conn_T::send_buf, ::recv_buf
 * @see SocketBuf_T::recvbuf for main receive buffer.
 * @see socketproxy_do_send(), socketproxy_do_recv() for usage.
 * @see SocketHTTP1.h for header size limits.
 */
#ifndef SOCKET_PROXY_BUFFER_SIZE
#define SOCKET_PROXY_BUFFER_SIZE 65536
#endif

/**
 * @brief Maximum length for proxy URL strings in parsing.
 * @ingroup proxy_private
 *
 * Value: 2048 bytes - conservative limit for scheme://user:pass@host:port formats.
 * Prevents DoS from oversized URLs; enforced in SocketProxy_parse_url.
 *
 * @see SocketProxy_parse_url() for validation.
 * @see SocketProxy_Config for parsed output.
 * @see docs/PROXY.md#url-format for supported formats.
 */
#ifndef SOCKET_PROXY_MAX_URL_LEN
#define SOCKET_PROXY_MAX_URL_LEN 2048
#endif

/**
 * @brief Size of static buffer for temporary URL parsing (when no arena provided).
 * @ingroup proxy_private
 *
 * Value: 1024 bytes - used in socketproxy_parse_* helpers for host/port/userinfo.
 * Thread-local to avoid reallocation; overwritten on next call if no arena.
 * For thread-safety, always provide Arena_T in public APIs.
 *
 * @see socketproxy_parse_userinfo(), socketproxy_parse_hostport() for usage.
 * @see socket_util_arena_strdup() fallback with arena.
 * @see @ref foundation "Arena module" for safe memory.
 */
#ifndef SOCKET_PROXY_STATIC_BUFFER_SIZE
#define SOCKET_PROXY_STATIC_BUFFER_SIZE 1024
#endif

/**
 * @brief Milliseconds per second constant for timeout calculations.
 * @ingroup proxy_private
 *
 * Value: 1000 - standard conversion used in socketproxy_elapsed_ms and deadlines.
 *
 * @see socketproxy_get_time_ms() for time fetches.
 * @see SocketTimeout utilities in SocketUtil.h.
 */
#define SOCKET_PROXY_MS_PER_SEC 1000

/**
 * @brief Nanoseconds per millisecond for high-precision time conversion.
 * @ingroup proxy_private
 *
 * Value: 1,000,000 - used in clock_gettime to ms conversion for monotonic timing.
 * Ensures accurate timeout enforcement without drift.
 *
 * @see socketproxy_get_time_ms() implementation.
 * @see CLOCK_MONOTONIC for source.
 * @see Socket_get_monotonic_ms() related util.
 */
#define SOCKET_PROXY_NS_PER_MS 1000000LL

/**
 * @brief Default timeout for SocketPoll_wait when no deadline pending.
 * @ingroup proxy_private
 *
 * Value: 1000 ms (1s) - prevents busy loops in async poll while allowing progress checks.
 * Used when connect/handshake timeouts not active.
 *
 * @see SocketProxy_Conn_next_timeout_ms() for dynamic calc.
 * @see SocketPoll_wait() integration.
 * @see SocketProxy_Config timeouts for overrides.
 */
#ifndef SOCKET_PROXY_DEFAULT_POLL_TIMEOUT_MS
#define SOCKET_PROXY_DEFAULT_POLL_TIMEOUT_MS 1000
#endif

/**
 * @brief SOCKS4 and SOCKS5 protocol constants per RFCs.
 * @ingroup core_io
 * @ingroup proxy_private
 *
 * Protocol versions, commands, replies, auth methods, address types, and fixed sizes
 * for request/response parsing in proxy handshakes.
 * Used in proxy_socks* functions for building/parsing messages.
 *
 * SOCKS4: Basic IPv4 tunneling, no auth, single step.
 * SOCKS5: Advanced, supports IPv6/domain, auth (none/password/GSSAPI), multi-step.
 *
 * Reply codes mapped to SocketProxy_Result in recv functions.
 * Sizes ensure bounds-checked parsing to prevent overflows.
 *
 * @see RFC 1928 SOCKS5 protocol.
 * @see RFC 1929 SOCKS5 username/password auth.
 * @see RFC 1928 Appendix A for SOCKS4 informational.
 * @see proxy_socks5_* functions for usage.
 * @see SocketProxy_Result for error mapping.
 * @see docs/PROXY.md for SOCKS flow.
 */

/** @brief SOCKS4 protocol version number.
 * @ingroup proxy_private
 * Value: 4
 * Used in request header VN field.
 * @see proxy_socks4_send_connect()
 */
#define SOCKS4_VERSION 4

/** @brief SOCKS4 CONNECT command code.
 * @ingroup proxy_private
 * Value: 1
 * CD field in request for TCP connect.
 * @see proxy_socks4_send_connect(), proxy_socks4a_send_connect()
 */
#define SOCKS4_CMD_CONNECT 1

/** @brief SOCKS4 reply codes for connection result.
 * @ingroup proxy_private
 * 90: Granted, 91: Rejected, 92: No identd, 93: Ident mismatch.
 * Mapped in proxy_socks4_reply_to_result().
 * @see proxy_socks4_recv_response()
 */
#define SOCKS4_REPLY_GRANTED 90
#define SOCKS4_REPLY_REJECTED 91
#define SOCKS4_REPLY_NO_IDENTD 92
#define SOCKS4_REPLY_IDENTD_MISMATCH 93

/** @brief SOCKS5 protocol version number.
 * @ingroup proxy_private
 * Value: 5
 * VER field in all messages.
 * @see proxy_socks5_* functions.
 */
#define SOCKS5_VERSION 5

/** @brief SOCKS5 subnegotiation auth version (RFC 1929).
 * @ingroup proxy_private
 * Value: 1
 * VER in username/password auth request/response.
 * @see proxy_socks5_send_auth(), proxy_socks5_recv_auth()
 */
#define SOCKS5_AUTH_VERSION 1

/** @brief SOCKS5 authentication method codes.
 * @ingroup proxy_private
 * 0x00: No auth, 0x01: GSSAPI, 0x02: Password, 0xFF: No acceptable.
 * Listed in greeting; selected in response.
 * @see proxy_socks5_send_greeting(), proxy_socks5_recv_method()
 * @see SocketProxy_Conn_T::socks5_auth_method
 */
#define SOCKS5_AUTH_NONE 0x00
#define SOCKS5_AUTH_GSSAPI 0x01
#define SOCKS5_AUTH_PASSWORD 0x02
#define SOCKS5_AUTH_NO_ACCEPTABLE 0xFF

/** @brief SOCKS5 command codes.
 * @ingroup proxy_private
 * 0x01: Connect, 0x02: Bind, 0x03: UDP associate.
 * Only CONNECT used for tunneling.
 * @see proxy_socks5_send_connect()
 */
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_CMD_BIND 0x02
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03

/** @brief SOCKS5 address type codes (ATYP).
 * @ingroup proxy_private
 * 0x01: IPv4 (4 bytes), 0x03: Domain (len + bytes), 0x04: IPv6 (16 bytes).
 * Used in CONNECT request/reply.
 * @see proxy_socks5_send_connect(), proxy_socks5_recv_connect()
 * @see SocketProxy_SOCKS5H for domain resolution at proxy.
 */
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_ATYP_IPV6 0x04

/** @brief SOCKS5 reply codes (REP) for commands.
 * @ingroup proxy_private
 * 0x00: Success, 0x01-0x08: Various failures.
 * Mapped to SocketProxy_Result in recv_connect.
 * @see proxy_socks5_reply_to_result()
 * @see proxy_socks5_recv_connect()
 */
#define SOCKS5_REPLY_SUCCESS 0x00
#define SOCKS5_REPLY_GENERAL_FAILURE 0x01
#define SOCKS5_REPLY_NOT_ALLOWED 0x02
#define SOCKS5_REPLY_NETWORK_UNREACHABLE 0x03
#define SOCKS5_REPLY_HOST_UNREACHABLE 0x04
#define SOCKS5_REPLY_CONNECTION_REFUSED 0x05
#define SOCKS5_REPLY_TTL_EXPIRED 0x06
#define SOCKS5_REPLY_COMMAND_NOT_SUPPORTED 0x07
#define SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED 0x08

/** @brief Fixed address and port sizes for SOCKS5 messages (RFC 1928 Sec 4).
 * @ingroup proxy_private
 * IPv4: 4 bytes, IPv6: 16 bytes, Port: 2 bytes (big-endian).
 * Used for buffer allocation and parsing bounds.
 * @see SOCKS5_ATYP_* for types.
 */
#define SOCKS5_IPV4_ADDR_SIZE 4  /**< IPv4 address bytes */
#define SOCKS5_IPV6_ADDR_SIZE 16 /**< IPv6 address bytes */
#define SOCKS5_PORT_SIZE 2       /**< Port bytes (network order) */

/** @brief SOCKS5 response message size constants.
 * @ingroup proxy_private
 * Method response: 2 bytes, Auth response: 2 bytes, Connect header: 4 bytes (VER+REP+RSV+ATYP).
 * Used for expected recv lengths in state machine.
 * @see proxy_socks5_recv_method(), proxy_socks5_recv_auth(), proxy_socks5_recv_connect()
 */
#define SOCKS5_METHOD_RESPONSE_SIZE 2 /**< VER + METHOD */
#define SOCKS5_AUTH_RESPONSE_SIZE 2   /**< VER + STATUS */
#define SOCKS5_CONNECT_HEADER_SIZE 4  /**< VER + REP + RSV + ATYP */

/** @brief SOCKS5 CONNECT response total sizes for common address types.
 * @ingroup proxy_private
 * IPv4: Header + 4 + 2 = 10 bytes, IPv6: Header + 16 + 2 = 22 bytes.
 * Used to validate full response recv.
 * @see proxy_socks5_recv_connect() for parsing.
 */
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
 * @ingroup proxy_private
 *
 * Enumerates detailed states for SOCKS4/5 and HTTP CONNECT protocols
 * during the proxy negotiation process. Used in state machine to dispatch
 * send/recv handlers and track multi-step negotiation progress.
 *
 * Transitions driven by socketproxy_advance_state() after successful I/O operations.
 * Each state corresponds to a specific protocol phase, enabling modular handlers.
 *
 * @see SocketProxy_State for high-level connection state (e.g., HANDSHAKE_SEND/RECV).
 * @see SocketProxy_Conn_T::proto_state for field usage in context.
 * @see ProxySendFunc, ProxyRecvFunc for state-specific protocol handlers.
 * @see socketproxy_advance_state() for state machine advancement logic.
 * @see docs/PROXY.md for protocol flow diagrams.
 */
typedef enum
{
  PROTO_STATE_INIT = 0, /**< @brief Initial state before any protocol interaction.
 * Ready to build and send first message (greeting for SOCKS5, request for others). */

  /* SOCKS5 states (RFC 1928 multi-step negotiation) */
  PROTO_STATE_SOCKS5_GREETING_SENT, /**< @brief SOCKS5 version 5 greeting sent to proxy.
 * Lists supported auth methods (SOCKS5_AUTH_NONE, optional SOCKS5_AUTH_PASSWORD).
 * Awaiting method selection response (2-byte: VER=5, METHOD). */
  PROTO_STATE_SOCKS5_METHOD_RECEIVED, /**< @brief Method selection response parsed successfully.
 * Auth method stored in conn->socks5_auth_method; if none, proceed to connect;
 * else transition to auth subnegotiation. */
  PROTO_STATE_SOCKS5_AUTH_SENT, /**< @brief Username/password authentication request sent (method 0x02).
 * Format per RFC 1929: VER=1, ULEN, USERID, PLEN, PASSWD.
 * Awaiting 2-byte response (VER=1, STATUS=0x00 success). */
  PROTO_STATE_SOCKS5_AUTH_RECEIVED, /**< @brief Auth response received and validated.
 * On success (STATUS=0), proceed to CONNECT; failure maps to PROXY_ERROR_AUTH_FAILED. */
  PROTO_STATE_SOCKS5_CONNECT_SENT, /**< @brief SOCKS5 CONNECT command sent with target details.
 * CMD=0x01, ATYP (IPv4/domain/IPv6), ADDR, PORT; supports SOCKS5H (hostname at proxy).
 * Awaiting variable-length reply (VER=5, REP, bound addr/port). */
  PROTO_STATE_SOCKS5_CONNECT_RECEIVED, /**< @brief CONNECT reply fully parsed.
 * REP=0x00 success (tunnel ready, ignore bound addr); other REPs map to specific PROXY_ERROR_* via proxy_socks5_reply_to_result(). */

  /* SOCKS4/4a states (simpler single request/response cycle) */
  PROTO_STATE_SOCKS4_CONNECT_SENT, /**< @brief SOCKS4 CONNECT request sent (IPv4 only or 4a extension).
 * VN=4, CMD=1, DSTPORT, DSTIP (0.0.0.x for 4a domain), USERID="socket", null-term domain (4a).
 * Awaiting 8-byte reply (null VN, CD=90 granted or error). */
  PROTO_STATE_SOCKS4_CONNECT_RECEIVED, /**< @brief SOCKS4 reply received and checked.
 * CD=90 success; 91-93 errors mapped via proxy_socks4_reply_to_result(). No addr in reply. */

  /* HTTP CONNECT states (RFC 7230 Section 5.3 for tunneling) */
  PROTO_STATE_HTTP_REQUEST_SENT, /**< @brief HTTP CONNECT target_host:target_port HTTP/1.1 request sent.
 * Includes Host:, optional Proxy-Authorization (Basic), and extra_headers.
 * Uses Socket_send or TLS_send; awaiting response via incremental SocketHTTP1_Parser_execute(). */
  PROTO_STATE_HTTP_RESPONSE_RECEIVED, /**< @brief HTTP response headers fully parsed via http_parser.
 * Expect status 200 "Connection established"; 4xx/5xx map to PROXY_HTTP_ERROR via proxy_http_status_to_result().
 * Tunnel active on success; no body expected. */

  /* Terminal state */
  PROTO_STATE_DONE /**< @brief Handshake protocol phase complete.
 * Success or failure reflected in conn->result and high-level state.
 * No further proxy-specific I/O; ready for application data tunneling or error handling/cleanup. */
} SocketProxy_ProtoState;

/**
 * @brief Module-specific exception and logging macros for proxy operations.
 * @ingroup core_io
 * @ingroup proxy_private
 *
 * Centralized error handling using SocketUtil.h base for thread-safe formatting
 * and raising. Overrides log component to "Proxy" for SocketLog_emit.
 * Macros populate thread-local buffer before raising Except_T via module exception.
 *
 * Pattern:
 * - Declare in .c: SOCKET_DECLARE_MODULE_EXCEPTION(Proxy)
 * - Format: PROXY_ERROR_FMT("SOCKS5 connect failed: %s", reason);
 * - Raise: RAISE_PROXY_ERROR(Proxy_Failed);
 *
 * Benefits:
 * - Consistent with library-wide error patterns.
 * - Thread-local buf (256 bytes) prevents races.
 * - Auto-logs errors if SocketLog callback set.
 * - Supports retry categorization via SocketError_* utils.
 *
 * @note Declare exception in every .c file using these.
 * @note Buf size SOCKET_PROXY_ERROR_BUFSIZE; truncate if exceed.
 * @note Log component "Proxy" for module-specific tracing.
 *
 * @see SocketUtil.h error/logging sections.
 * @see PROXY_ERROR_FMT, PROXY_ERROR_MSG for formatting.
 * @see RAISE_PROXY_ERROR for raising.
 * @see SocketLog_emit for logging integration.
 * @see docs/ERROR_HANDLING.md for TRY/EXCEPT usage.
 * @see @ref foundation "Foundation" for Except_T.
 * @see @ref utilities "Utilities" for SocketLog, SocketError.
 */

/* Override log component for this module */
#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "Proxy"

/**
 * @brief Error formatting macros delegating to SocketUtil infrastructure.
 * @ingroup proxy_private
 *
 * Use socket_error_buf (thread-local, SOCKET_PROXY_ERROR_BUFSIZE bytes) for messages.
 * Called before RAISE_PROXY_ERROR to populate details.
 *
 * @see SocketUtil.h SOCKET_ERROR_* base macros.
 */

/**
 * @brief Format proxy error with errno details included.
 * @ingroup proxy_private
 *
 * Populates thread-local buffer with fmt + strerror(errno).
 * Use immediately before raise for detailed exceptions.
 *
 * @param fmt printf format.
 * @param ... fmt args.
 * @return Void - error in global buf.
 * @see PROXY_ERROR_MSG without errno.
 * @see SOCKET_ERROR_FMT base.
 * @see RAISE_PROXY_ERROR usage example.
 */
#define PROXY_ERROR_FMT(fmt, ...) SOCKET_ERROR_FMT (fmt, ##__VA_ARGS__)

/**
 * @brief Format proxy error without errno details.
 * @ingroup proxy_private
 *
 * Populates buffer with fmt only (no strerror).
 * For cases where errno not relevant or already included.
 *
 * @param fmt printf format.
 * @param ... fmt args.
 * @return Void - error in global buf.
 * @see PROXY_ERROR_FMT with errno.
 * @see SOCKET_ERROR_MSG base.
 */
#define PROXY_ERROR_MSG(fmt, ...) SOCKET_ERROR_MSG (fmt, ##__VA_ARGS__)

/**
 * @brief Raise formatted Proxy exception using module infrastructure.
 * @ingroup proxy_private
 *
 * Raises via SOCKET_RAISE_MODULE_ERROR(Proxy, e) after formatting in thread-local buf.
 * Integrates with Except stack for TRY/EXCEPT handling.
 *
 * @param e Exception type (e.g., Proxy_Failed, Proxy_Timeout).
 * @throws Specified e with details from buf.
 * @note Requires SOCKET_DECLARE_MODULE_EXCEPTION(Proxy) in .c.
 * @note Thread-safe via local buf.
 * @see PROXY_ERROR_* for pre-raise formatting.
 * @see SOCKET_RAISE_MODULE_ERROR base.
 * @see SocketUtil.h error section.
 * @see docs/ERROR_HANDLING.md patterns.
 */
#define RAISE_PROXY_ERROR(e) SOCKET_RAISE_MODULE_ERROR (Proxy, e)

/* ============================================================================
 * Main Context Structure
 * ============================================================================
 */

/**
 * @brief Opaque proxy connection context for managing tunneling negotiation.
 * @ingroup core_io
 * @ingroup proxy_private
 *
 * Central structure for a single proxy operation, handling configuration, resources,
 * asynchronous components, state machine, I/O buffering, timing, and error tracking.
 *
 * Lifecycle: Allocated from arena in public APIs like SocketProxy_Conn_new(); fields private.
 * Success transfers socket to caller; failure sets error; free cleans remaining.
 *
 * Groups:
 * - Configuration (copied from user config): proxy/target details, creds, timeouts, headers, TLS.
 * - Resources (owned/managed): arena for memory, socket for I/O (transferred), recvbuf for parsing.
 * - Async resources: dns resolver, poll instance, HappyEyeballs for connect racing (optional external).
 * - HTTP specific: http_parser for CONNECT response validation.
 * - State machine: high-level state, proto_state, result code, SOCKS5 auth flags.
 * - Timing: start times for timeout enforcement using monotonic clock.
 * - I/O state: send/recv buffers (SOCKET_PROXY_BUFFER_SIZE=64KB), offsets for partial transfers.
 * - Error handling: error_buf for messages, transferred flag to prevent double-free.
 *
 * Thread safety: No - single-threaded design; concurrent access undefined.
 * Memory safety: Arena-managed; secure clear for creds if implemented.
 * TLS conditional: tls_ctx and tls_enabled for HTTPS proxy support.
 *
 * @note Opaque to public; internal access only via module functions.
 * @note owns_dns_poll flag determines cleanup of async resources.
 * @note Buffer sizes configurable via defines; error_buf fixed size.
 *
 * @see SocketProxy.h public SocketProxy_Conn_* API for usage.
 * @see SocketProxy_Conn_T fields (internal reference).
 * @see SocketProxy_ProtoState for detailed protocol sub-states.
 * @see SocketProxy_State for connection lifecycle states.
 * @see SocketHappyEyeballs_T::he for proxy server connection.
 * @see SocketHTTP1_Parser_T::http_parser for HTTP parsing.
 * @see SocketBuf_T::recvbuf for receive buffering.
 * @see Arena_T::arena for memory management.
 * @see @ref dns "DNS module" for resolution.
 * @see @ref event_system "Event system" for poll integration.
 * @see @ref security "Security module" for TLS.
 * @see docs/PROXY.md for internals and examples.
 * @see docs/MEMORY_MANAGEMENT.md for arena usage.
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
 * @brief Function type for protocol-specific request building.
 * @ingroup core_io
 * @ingroup proxy_private
 *
 * Called by state machine to construct request message (e.g., SOCKS5 greeting,
 * HTTP CONNECT, SOCKS4 connect) into fixed send buffer.
 * Sets conn->send_len; does not send (handled by socketproxy_do_send).
 *
 * Expected to use PROXY_ERROR_* and RAISE_PROXY_ERROR on failure.
 *
 * @param conn Proxy context with config and buffers.
 * @return 0 success (buffer ready), -1 error (exception raised).
 * @throws Proxy_Failed on invalid config or build error.
 *
 * @see ProxyRecvFunc counterpart for response parsing.
 * @see SocketProxy_Conn_T::send_buf, ::send_len for output.
 * @see socketproxy_do_send() for actual transmission.
 * @see proxy_socks5_send_greeting() example implementation.
 * @see docs/PROXY.md for protocol flows.
 */
typedef int (*ProxySendFunc) (struct SocketProxy_Conn_T *conn);

/**
 * @brief Function type for protocol-specific response parsing.
 * @ingroup core_io
 * @ingroup proxy_private
 *
 * Called after recv to parse response from buffer, validate, update state/result.
 * Advances proto_state on partial/complete; returns progress status.
 *
 * Handles variable lengths (e.g., SOCKS5 addr types), maps replies to results.
 *
 * @param conn Context with recv_buf data and current proto_state.
 * @return SocketProxy_Result: OK complete success, IN_PROGRESS need more bytes,
 *         PROTOCOL_ERROR invalid data, other errors via result set.
 * @throws Proxy_Failed on parse failure (e.g., invalid VER).
 *
 * @see ProxySendFunc for request building.
 * @see SocketProxy_Conn_T::recv_buf, ::recv_len, ::proto_state for input/output.
 * @see socketproxy_do_recv() for data filling buffer.
 * @see socketproxy_advance_state() called after successful parse.
 * @see proxy_socks5_recv_connect() example.
 * @see SocketProxy_Result for return mapping.
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

/** @} */ /* proxy_private */

#endif /* SOCKETPROXY_PRIVATE_INCLUDED */
