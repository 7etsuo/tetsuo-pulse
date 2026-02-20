/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

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
 * Exposes opaque types, constants, state enums, error macros, and helper
 * functions for implementing proxy tunneling via SOCKS and HTTP CONNECT
 * protocols.
 *
 * Key internals:
 * - SocketProxy_Conn_T: Opaque context for connection lifecycle management
 * including DNS resolution, socket I/O, protocol handshakes, and timeouts.
 * - SocketProxy_ProtoState: Sub-states for SOCKS5 multi-step negotiation
 * (greeting, auth, connect).
 * - Protocol handler types (ProxySendFunc, ProxyRecvFunc) for state machine
 * dispatching.
 * - SOCKS-specific functions for request building and response parsing (RFC
 * 1928/1929).
 * - HTTP CONNECT handlers using SocketHTTP1_Parser_T for response validation.
 * - Time utilities using CLOCK_MONOTONIC for reliable timeout enforcement.
 * - URL parsing helpers supporting standard proxy URL formats.
 *
 * Security considerations:
 * - Credentials (username/password) copied to arena and securely cleared after
 * use.
 * - Protocol parsing bounds-checked to prevent buffer overflows or injection
 * attacks.
 * - Timeouts enforced to mitigate denial-of-service from malicious/slow
 * proxies.
 * - Integration with SocketSYNProtect possible via pool for server-side
 * proxying.
 *
 * Dependencies and reuse:
 * - Socket (core I/O) for buffered send/recv and TLS passthrough.
 * - SocketBuf for temporary protocol message buffering.
 * - SocketPoll and SocketDNS for asynchronous connection establishment.
 * - SocketHappyEyeballs for parallel proxy server resolution/connect racing.
 * - SocketHTTP1 for HTTP response parsing in CONNECT method.
 * - SocketTLSContext (conditional) for HTTPS proxy (TLS to proxy server).
 *
 * Error handling: Uses module exceptions (Proxy_Failed, etc.) with formatted
 * messages via PROXY_ERROR_* macros delegating to SocketUtil infrastructure.
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
#include "dns/SocketDNSResolver.h"
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
 * used throughout proxy negotiation. These control memory usage and
 * performance.
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
 * Value: 256 bytes - sufficient for errno strings + context (e.g., "SOCKS5
 * auth failed on fd=5"). Used in SocketProxy_Conn_T::error_buf for
 * socketproxy_set_error formatting. Thread-local fallback via SocketUtil if
 * needed, but instance-specific here.
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
 * Value: 65536 bytes (64KB) - accommodates large HTTP CONNECT responses or
 * SOCKS5 addr. Increased for HTTP headers (max per SocketHTTP.h); used in
 * conn->send_buf/recv_buf. Balances memory and performance for typical proxy
 * messages.
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
 * Value: 2048 bytes - conservative limit for scheme://user:pass@host:port
 * formats. Prevents DoS from oversized URLs; enforced in
 * SocketProxy_parse_url.
 *
 * @see SocketProxy_parse_url() for validation.
 * @see SocketProxy_Config for parsed output.
 * @see docs/PROXY.md#url-format for supported formats.
 */
#ifndef SOCKET_PROXY_MAX_URL_LEN
#define SOCKET_PROXY_MAX_URL_LEN 2048
#endif

/**
 * @brief Size of static buffer for temporary URL parsing (when no arena
 * provided).
 * @ingroup proxy_private
 *
 * Value: 1024 bytes - used in socketproxy_parse_* helpers for
 * host/port/userinfo. Thread-local to avoid reallocation; overwritten on next
 * call if no arena. For thread-safety, always provide Arena_T in public APIs.
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
 * Value: 1000 - standard conversion used in socketproxy_elapsed_ms and
 * deadlines.
 *
 * @see socketproxy_get_time_ms() for time fetches.
 * @see SocketTimeout utilities in SocketUtil.h.
 */
#define SOCKET_PROXY_MS_PER_SEC 1000

/**
 * @brief Nanoseconds per millisecond for high-precision time conversion.
 * @ingroup proxy_private
 *
 * Value: 1,000,000 - used in clock_gettime to ms conversion for monotonic
 * timing. Ensures accurate timeout enforcement without drift.
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
 * Value: 1000 ms (1s) - prevents busy loops in async poll while allowing
 * progress checks. Used when connect/handshake timeouts not active.
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
 * Protocol versions, commands, replies, auth methods, address types, and fixed
 * sizes for request/response parsing in proxy handshakes. Used in proxy_socks*
 * functions for building/parsing messages.
 *
 * SOCKS4: Basic IPv4 tunneling, no auth, single step.
 * SOCKS5: Advanced, supports IPv6/domain, auth (none/password/GSSAPI),
 * multi-step.
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

/** @brief SOCKS4 error message for buffer overflow during request building.
 * @ingroup proxy_private
 * Used when request size exceeds SOCKET_PROXY_BUFFER_SIZE.
 * @see proxy_socks4_send_connect(), proxy_socks4a_send_connect()
 * @see SOCKET_PROXY_BUFFER_SIZE
 */
#define SOCKS4_ERROR_MSG_REQUEST_TOO_LARGE "Request too large"

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
#define SOCKS5_DOMAIN_LENGTH_SIZE \
  1 /**< Domain name length byte (ATYP_DOMAIN) */

/** @brief SOCKS5 response message size constants.
 * @ingroup proxy_private
 * Method response: 2 bytes, Auth response: 2 bytes, Connect header: 4 bytes
 * (VER+REP+RSV+ATYP). Used for expected recv lengths in state machine.
 * @see proxy_socks5_recv_method(), proxy_socks5_recv_auth(),
 * proxy_socks5_recv_connect()
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
#define SOCKS5_CONNECT_IPV4_RESPONSE_SIZE \
  (SOCKS5_CONNECT_HEADER_SIZE + SOCKS5_IPV4_ADDR_SIZE + SOCKS5_PORT_SIZE)
#define SOCKS5_CONNECT_IPV6_RESPONSE_SIZE \
  (SOCKS5_CONNECT_HEADER_SIZE + SOCKS5_IPV6_ADDR_SIZE + SOCKS5_PORT_SIZE)

/**
 * @brief Protocol-specific sub-state for proxy handshakes.
 * @ingroup core_io
 * @ingroup proxy_private
 *
 * Enumerates detailed states for SOCKS4/5 and HTTP CONNECT protocols
 * during the proxy negotiation process. Used in state machine to dispatch
 * send/recv handlers and track multi-step negotiation progress.
 *
 * Transitions driven by socketproxy_advance_state() after successful I/O
 * operations. Each state corresponds to a specific protocol phase, enabling
 * modular handlers.
 *
 * @see SocketProxy_State for high-level connection state (e.g.,
 * HANDSHAKE_SEND/RECV).
 * @see SocketProxy_Conn_T::proto_state for field usage in context.
 * @see ProxySendFunc, ProxyRecvFunc for state-specific protocol handlers.
 * @see socketproxy_advance_state() for state machine advancement logic.
 * @see docs/PROXY.md for protocol flow diagrams.
 */
typedef enum
{
  PROTO_STATE_INIT = 0, /**< @brief Initial state before any protocol
                         * interaction. Ready to build and send first message
                         * (greeting for SOCKS5, request for others). */

  /* SOCKS5 states (RFC 1928 multi-step negotiation) */
  PROTO_STATE_SOCKS5_GREETING_SENT,   /**< @brief SOCKS5 version 5 greeting sent
                                       * to proxy. Lists supported auth methods
                                       * (SOCKS5_AUTH_NONE, optional
                                       * SOCKS5_AUTH_PASSWORD). Awaiting method
                                       * selection response (2-byte: VER=5,
                                       * METHOD). */
  PROTO_STATE_SOCKS5_METHOD_RECEIVED, /**< @brief Method selection response
                                       * parsed successfully. Auth method
                                       * stored in conn->socks5_auth_method; if
                                       * none, proceed to connect; else
                                       * transition to auth subnegotiation. */
  PROTO_STATE_SOCKS5_AUTH_SENT,     /**< @brief Username/password authentication
                                     * request sent (method 0x02). Format per RFC
                                     * 1929: VER=1, ULEN, USERID, PLEN, PASSWD.
                                     * Awaiting 2-byte response (VER=1, STATUS=0x00
                                     * success). */
  PROTO_STATE_SOCKS5_AUTH_RECEIVED, /**< @brief Auth response received and
                                     * validated. On success (STATUS=0),
                                     * proceed to CONNECT; failure maps to
                                     * PROXY_ERROR_AUTH_FAILED. */
  PROTO_STATE_SOCKS5_CONNECT_SENT,  /**< @brief SOCKS5 CONNECT command sent with
                                     * target details. CMD=0x01, ATYP
                                     * (IPv4/domain/IPv6), ADDR, PORT; supports
                                     * SOCKS5H (hostname at proxy). Awaiting
                                     * variable-length reply (VER=5, REP, bound
                                     * addr/port). */
  PROTO_STATE_SOCKS5_CONNECT_RECEIVED, /**< @brief CONNECT reply fully parsed.
                                        * REP=0x00 success (tunnel ready,
                                        * ignore bound addr); other REPs map to
                                        * specific PROXY_ERROR_* via
                                        * proxy_socks5_reply_to_result(). */

  /* SOCKS4/4a states (simpler single request/response cycle) */
  PROTO_STATE_SOCKS4_CONNECT_SENT,     /**< @brief SOCKS4 CONNECT request sent
                                        * (IPv4 only or 4a extension).     VN=4,
                                        * CMD=1,     DSTPORT, DSTIP (0.0.0.x for 4a
                                        * domain),     USERID="socket", null-term
                                        * domain     (4a).     Awaiting 8-byte reply
                                        * (null VN,     CD=90     granted or error). */
  PROTO_STATE_SOCKS4_CONNECT_RECEIVED, /**< @brief SOCKS4 reply received and
                                        * checked. CD=90 success; 91-93 errors
                                        * mapped via
                                        * proxy_socks4_reply_to_result(). No
                                        * addr in reply. */

  /* HTTP CONNECT states (RFC 7230 Section 5.3 for tunneling) */
  PROTO_STATE_HTTP_REQUEST_SENT,      /**< @brief HTTP CONNECT
                                       * target_host:target_port HTTP/1.1 request
                                       * sent.      Includes Host:, optional
                                       * Proxy-Authorization (Basic), and
                                       * extra_headers.      Uses Socket_send or
                                       * TLS_send; awaiting response via incremental
                                       * SocketHTTP1_Parser_execute(). */
  PROTO_STATE_HTTP_RESPONSE_RECEIVED, /**< @brief HTTP response headers fully
                                       * parsed via http_parser. Expect status
                                       * 200 "Connection established"; 4xx/5xx
                                       * map to PROXY_HTTP_ERROR via
                                       * proxy_http_status_to_result(). Tunnel
                                       * active on success; no body expected.
                                       */

  /* Terminal state */
  PROTO_STATE_DONE /**< @brief Handshake protocol phase complete.
                    * Success or failure reflected in conn->result and
                    * high-level state. No further proxy-specific I/O; ready
                    * for application data tunneling or error handling/cleanup.
                    */
} SocketProxy_ProtoState;

/**
 * @brief Module-specific exception and logging macros for proxy operations.
 * @ingroup core_io
 * @ingroup proxy_private
 *
 * Centralized error handling using SocketUtil.h base for thread-safe
 * formatting and raising. Overrides log component to "Proxy" for
 * SocketLog_emit. Macros populate thread-local buffer before raising Except_T
 * via module exception.
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
 * Use socket_error_buf (thread-local, SOCKET_PROXY_ERROR_BUFSIZE bytes) for
 * messages. Called before RAISE_PROXY_ERROR to populate details.
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
 * Raises via SOCKET_RAISE_MODULE_ERROR(Proxy, e) after formatting in
 * thread-local buf. Integrates with Except stack for TRY/EXCEPT handling.
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

/**
 * @brief Opaque proxy connection context for managing tunneling negotiation.
 * @ingroup core_io
 * @ingroup proxy_private
 *
 * Central structure for a single proxy operation, handling configuration,
 * resources, asynchronous components, state machine, I/O buffering, timing,
 * and error tracking.
 *
 * Lifecycle: Allocated from arena in public APIs like SocketProxy_Conn_new();
 * fields private. Success transfers socket to caller; failure sets error; free
 * cleans remaining.
 *
 * Groups:
 * - Configuration (copied from user config): proxy/target details, creds,
 * timeouts, headers, TLS.
 * - Resources (owned/managed): arena for memory, socket for I/O (transferred),
 * recvbuf for parsing.
 * - Async resources: dns resolver, poll instance, HappyEyeballs for connect
 * racing (optional external).
 * - HTTP specific: http_parser for CONNECT response validation.
 * - State machine: high-level state, proto_state, result code, SOCKS5 auth
 * flags.
 * - Timing: start times for timeout enforcement using monotonic clock.
 * - I/O state: send/recv buffers (SOCKET_PROXY_BUFFER_SIZE=64KB), offsets for
 * partial transfers.
 * - Error handling: error_buf for messages, transferred flag to prevent
 * double-free.
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
#if SOCKET_HAS_TLS
  SocketTLSContext_T tls_ctx; /**< TLS context from config (copied ptr) */
  int tls_enabled;            /**< 1 after successful TLS handshake to proxy */
#endif

  /* Internal resources (owned) */
  Arena_T arena;       /**< Memory arena for all allocations */
  Socket_T socket;     /**< Proxy socket (transferred to caller on success) */
  SocketBuf_T recvbuf; /**< Receive buffer for protocol parsing */

  /* Async connection resources */
  SocketDNSResolver_T resolver; /**< DNS resolver for async connection */
  SocketPoll_T poll;            /**< Poll instance for async connection */
  SocketHE_T he;                /**< HappyEyeballs context (during connect) */
  int owns_resolver_poll; /**< 1 if we own resolver/poll (sync wrapper), 0 if
                             external */

  /* HTTP CONNECT specific */
  SocketHTTP1_Parser_T http_parser; /**< HTTP response parser */

  /* State machine */
  SocketProxy_State state;            /**< Main state */
  SocketProxy_ProtoState proto_state; /**< Protocol sub-state */
  SocketProxy_Result result;          /**< Final result */

  /* SOCKS5 state */
  int socks5_auth_method; /**< Selected auth method */
  int socks5_need_auth;   /**< 1 if auth required */
  size_t password_len;    /**< Cached password length for secure_clear */

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

/**
 * @brief Get current monotonic time in milliseconds.
 * @ingroup core_io
 *
 * Uses CLOCK_MONOTONIC for reliable, non-decreasing time suitable for
 * timeouts.
 *
 * @return Monotonic time since some unspecified point (ms), or 0 on clock
 * failure.
 *
 * @note Thread-safe: Yes, clock_gettime is atomic.
 * @note Prefer over gettimeofday() to avoid system time changes affecting
 * timeouts.
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
 * Called after recv to parse response from buffer, validate, update
 * state/result. Advances proto_state on partial/complete; returns progress
 * status.
 *
 * Handles variable lengths (e.g., SOCKS5 addr types), maps replies to results.
 *
 * @param conn Context with recv_buf data and current proto_state.
 * @return SocketProxy_Result: OK complete success, IN_PROGRESS need more
 * bytes, PROTOCOL_ERROR invalid data, other errors via result set.
 * @throws Proxy_Failed on parse failure (e.g., invalid VER).
 *
 * @see ProxySendFunc for request building.
 * @see SocketProxy_Conn_T::recv_buf, ::recv_len, ::proto_state for
 * input/output.
 * @see socketproxy_do_recv() for data filling buffer.
 * @see socketproxy_advance_state() called after successful parse.
 * @see proxy_socks5_recv_connect() example.
 * @see SocketProxy_Result for return mapping.
 */
typedef SocketProxy_Result (*ProxyRecvFunc) (struct SocketProxy_Conn_T *conn);

/**
 * @brief Builds SOCKS5 greeting message for initial protocol negotiation (RFC
 * 1928).
 * @ingroup core_io
 * @ingroup proxy_private
 *
 * This function constructs the SOCKS5 version 5 greeting packet that is sent
 * to the proxy server to initiate the connection. It lists the supported
 * authentication methods: always includes no authentication (0x00), and
 * includes username/password (0x02) if credentials are configured in the
 * connection context.
 *
 * The greeting format is:
 * - VER = 5 (1 byte)
 * - NMETHODS = number of methods (1 byte)
 * - METHODS = list of auth methods (variable)
 *
 * Edge cases:
 * - If no credentials, only no-auth method sent (minimal 2-byte packet).
 * - Credentials present: 3-byte packet.
 * - Invalid config (e.g., malformed username) raises Proxy_Failed immediately.
 *
 * After building, the buffer is ready for transmission via
 * socketproxy_do_send(). Failure populates error_buf via PROXY_ERROR_FMT.
 *
 * @param[in] conn Proxy connection context containing configuration (type must
 * be SOCKS5, username/password if auth needed) and send_buf for output.
 *
 * @return 0 on successful build (send_len set, buffer populated), -1 on
 * failure.
 *
 * @throws Proxy_Failed If configuration invalid (e.g., missing credentials for
 * required auth) or buffer allocation issues in arena.
 *
 * @threadsafe No - Modifies conn->send_buf, conn->send_len, and potentially
 * error_buf. Caller must ensure exclusive access to conn during handshake.
 *
 *  Usage Example
 *
 * @code
 * // Internal call from state machine
 * if (conn->proto_state == PROTO_STATE_INIT && conn->type ==
 * SOCKET_PROXY_SOCKS5) { if (proxy_socks5_send_greeting(conn) < 0) {
 *         // Error already raised/handled via TRY/EXCEPT
 *         return PROXY_ERROR_CONFIG;
 *     }
 *     conn->proto_state = PROTO_STATE_SOCKS5_GREETING_SENT;
 *     // Proceed to send via socketproxy_do_send(conn)
 * }
 * @endcode
 *
 * @note This is the first step in SOCKS5 multi-step negotiation. Does not
 * perform I/O.
 * @warning Ensure conn->type is SOCKET_PROXY_SOCKS5 before calling; undefined
 * otherwise.
 * @complexity O(1) - Fixed-size message construction, no loops or allocations
 * beyond arena.
 *
 * @see proxy_socks5_recv_method() Paired function for receiving method
 * selection response.
 * @see socketproxy_do_send() For transmitting the built greeting.
 * @see socketproxy_advance_state() Advances state after send completion.
 * @see SocketProxy_Conn_T For context structure details.
 * @see docs/PROXY.md#socks5-negotiation For full SOCKS5 flow diagram.
 * @see RFC 1928 Section 2 "Greeting from Client to Server".
 */
extern int proxy_socks5_send_greeting (struct SocketProxy_Conn_T *conn);

/**
 * @brief Parses SOCKS5 server method selection response after greeting (RFC
 * 1928).
 * @ingroup core_io
 * @ingroup proxy_private
 *
 * This function processes the 2-byte response from the proxy server selecting
 * the authentication method for the session. The response format is:
 * - VER = 5 (must match, else protocol error)
 * - METHOD = selected auth method (0x00 none, 0x02 password, 0xFF no
 * acceptable)
 *
 * On success (valid VER and METHOD != 0xFF):
 * - Stores selected method in conn->socks5_auth_method
 * - Sets conn->socks5_need_auth = 1 if METHOD == SOCKS5_AUTH_PASSWORD, else 0
 * - Advances proto_state to SOCKS5_METHOD_RECEIVED or to auth/CONNECT as
 * appropriate
 *
 * Edge cases:
 * - Incomplete data (recv_len < 2): returns PROXY_IN_PROGRESS
 * - Invalid VER !=5: sets result to PROXY_PROTOCOL_ERROR, populates error_buf
 * - METHOD=0xFF (no methods acceptable): PROXY_PROXY_ERROR
 * - Unsupported methods (e.g., GSSAPI 0x01): treated as protocol error if
 * selected
 *
 * Failure updates conn->result and calls socketproxy_set_error if needed.
 * Does not perform I/O; assumes data in recv_buf from prior
 * socketproxy_do_recv().
 *
 * @param[in,out] conn Proxy connection context with recv_buf populated and
 * current proto_state == SOCKS5_GREETING_SENT. Updates socks5_auth_method,
 * socks5_need_auth, proto_state, result on parse.
 *
 * @return SocketProxy_Result indicating parse status:
 *         - PROXY_OK: Valid response, method selected, state advanced
 *         - PROXY_IN_PROGRESS: Need more data (recv_len < expected)
 *         - PROXY_PROTOCOL_ERROR: Invalid format (wrong VER, etc.)
 *         - PROXY_PROXY_ERROR: Server rejected all methods (0xFF)
 *
 * @throws Proxy_Failed On severe parse errors (e.g., buffer corruption),
 * though typically sets result instead.
 *
 * @threadsafe No - Modifies conn fields (state, auth method, result);
 * exclusive access required.
 *
 *  Usage Example
 *
 * @code
 * // Internal state machine after receiving data
 * SocketProxy_Result r = proxy_socks5_recv_method(conn);
 * if (r == PROXY_OK) {
 *     if (conn->socks5_need_auth) {
 *         conn->proto_state = PROTO_STATE_SOCKS5_AUTH_SENT;  // Next: send
 * auth } else { conn->proto_state = PROTO_STATE_SOCKS5_CONNECT_SENT;  // Skip
 * to connect
 *     }
 *     socketproxy_advance_state(conn);
 * } else if (r == PROXY_PROTOCOL_ERROR) {
 *     socketproxy_set_error(conn, r, "Invalid SOCKS5 method response");
 * }
 * @endcode
 *
 * @note Pair with proxy_socks5_send_greeting(); called after successful recv
 * in handshake loop.
 * @warning If METHOD=0x02 but no credentials configured, subsequent auth will
 * fail.
 * @complexity O(1) - Fixed 2-byte parse, constant time checks.
 *
 * @see proxy_socks5_send_greeting() Complementary send function.
 * @see socketproxy_do_recv() Fills recv_buf before calling this.
 * @see socketproxy_advance_state() For state progression after success.
 * @see SOCKS5_AUTH_* Constants for method values.
 * @see docs/PROXY.md#socks5-authentication For negotiation flow.
 * @see RFC 1928 Section 2 "Server's Choice" for response semantics.
 */
extern SocketProxy_Result
proxy_socks5_recv_method (struct SocketProxy_Conn_T *conn);

/**
 * @brief Constructs SOCKS5 username/password subnegotiation request (RFC
 * 1929).
 * @ingroup core_io
 * @ingroup proxy_private
 *
 * Builds the authentication request for SOCKS5 when password method (0x02) is
 * selected by the server. The request format per RFC 1929 is:
 * - VER = 1 (subnegotiation version, 1 byte)
 * - ULEN = length of username (1 byte, 1-255)
 * - USERID = username bytes (ULEN bytes)
 * - PLEN = length of password (1 byte, 1-255)
 * - PASSWD = password bytes (PLEN bytes)
 *
 * Credentials are copied from conn->username and conn->password
 * (arena-allocated). Validates lengths (max 255 per RFC); truncates or errors
 * if exceed.
 *
 * Edge cases:
 * - No credentials (NULL username/password): raises Proxy_Failed with "missing
 * credentials"
 * - Empty strings: treated as invalid, error raised
 * - Lengths >255: truncated with warning log, but prefer error in strict mode
 * - Non-UTF8 creds: sent as-is (protocol is binary-safe)
 *
 * Populates send_buf with exact packet size (2 + ULEN + 1 + PLEN), sets
 * send_len. Does not send; ready for socketproxy_do_send(). Failure uses
 * PROXY_ERROR_FMT.
 *
 * @param[in] conn Proxy connection context with socks5_auth_method ==
 * SOCKS5_AUTH_PASSWORD, non-NULL username and password fields.
 *
 * @return 0 on success (buffer ready), -1 on failure (e.g., missing/invalid
 * credentials).
 *
 * @throws Proxy_Failed If username or password NULL, empty, or too long (>255
 * bytes). Also on arena allocation failure for temp strings if needed.
 *
 * @threadsafe No - Reads/modifies conn->send_buf, send_len; exclusive access
 * needed.
 *
 *  Usage Example
 *
 * @code
 * // Called after method selection if password auth required
 * if (conn->socks5_auth_method == SOCKS5_AUTH_PASSWORD) {
 *     TRY {
 *         if (proxy_socks5_send_auth(conn) < 0) {
 *             RAISE_PROXY_ERROR(Proxy_Failed);
 *         }
 *         conn->proto_state = PROTO_STATE_SOCKS5_AUTH_SENT;
 *         // Follow with socketproxy_do_send() in handshake loop
 *     } EXCEPT(Proxy_Failed) {
 *         socketproxy_set_error(conn, PROXY_ERROR_AUTH_FAILED, "Auth request
 * build failed"); } END_TRY;
 * }
 * @endcode
 *
 * @note Credentials are not securely cleared here; consider
 * SocketBuf_secureclear if sensitive.
 * @warning Protocol allows up to 255 bytes per field; longer creds will fail
 * or truncate.
 * @complexity O(n) where n = len(username) + len(password) - string copy time.
 *
 * @see proxy_socks5_recv_auth() For parsing the server auth response.
 * @see socketproxy_do_send() To transmit the auth request.
 * @see SocketProxy_Conn_T::username, ::password Source of credentials.
 * @see docs/SECURITY.md For credential handling best practices.
 * @see RFC 1929 Section 2 "Client Request" for exact format.
 */
extern int proxy_socks5_send_auth (struct SocketProxy_Conn_T *conn);

/**
 * @brief Parses SOCKS5 authentication response for username/password method
 * (RFC 1929).
 * @ingroup core_io
 * @ingroup proxy_private
 *
 * Processes the 2-byte authentication response from the proxy server after
 * sending credentials. Response format:
 * - VER = 1 (subnegotiation version)
 * - STATUS = 0x00 success, 0x01 failure
 *
 * On success (VER=1, STATUS=0x00):
 * - Advances proto_state to SOCKS5_AUTH_RECEIVED
 * - Proceeds to CONNECT phase
 *
 * On failure:
 * - STATUS !=0: sets result to PROXY_ERROR_AUTH_FAILED, populates error_buf
 * with details
 * - Invalid VER: PROXY_PROTOCOL_ERROR
 * - Incomplete (recv_len <2): PROXY_IN_PROGRESS
 *
 * No further data expected; simple fixed parse. Integrates with state machine
 * for next steps.
 *
 * @param[in,out] conn Proxy context with recv_buf from do_recv, proto_state ==
 * SOCKS5_AUTH_SENT. Updates proto_state, result, error_buf on parse outcome.
 *
 * @return SocketProxy_Result:
 *         - PROXY_OK: Auth succeeded (STATUS=0), state advanced to CONNECT
 * ready
 *         - PROXY_IN_PROGRESS: Insufficient data received
 *         - PROXY_PROTOCOL_ERROR: Wrong VER or format error
 *         - PROXY_ERROR_AUTH_FAILED: Server rejected credentials (STATUS=1)
 *
 * @throws Proxy_Failed Rarely, only if unexpected buffer state (e.g.,
 * corruption).
 *
 * @threadsafe No - Updates conn state and buffers; single-threaded use only.
 *
 *  Usage Example
 *
 * @code
 * // After receiving response in handshake
 * SocketProxy_Result r = proxy_socks5_recv_auth(conn);
 * if (r == PROXY_OK) {
 *     conn->proto_state = PROTO_STATE_SOCKS5_CONNECT_SENT;
 *     // Build and send CONNECT request next
 *     socketproxy_advance_state(conn);
 * } else {
 *     socketproxy_set_error(conn, r, "SOCKS5 auth failed: status=%d", status);
 *     // Handle failure: close socket, raise error
 * }
 * @endcode
 *
 * @note Authentication complete; tunnel not yet established - next is CONNECT.
 * @warning STATUS=1 means invalid credentials; consider logging for security
 * audit.
 * @complexity O(1) - Minimal 2-byte validation.
 *
 * @see proxy_socks5_send_auth() Preceding send function.
 * @see socketproxy_do_recv() Provides data to parse.
 * @see proxy_socks5_send_connect() Next step after success.
 * @see docs/SECURITY.md#proxy-auth For secure credential practices.
 * @see RFC 1929 Section 2 "Server Response" for status details.
 */
extern SocketProxy_Result
proxy_socks5_recv_auth (struct SocketProxy_Conn_T *conn);

/**
 * @brief Builds SOCKS5 CONNECT command to establish tunnel to target (RFC
 * 1928).
 * @ingroup core_io
 * @ingroup proxy_private
 *
 * Constructs the CONNECT request packet sent to the proxy after authentication
 * (or directly if no auth). This requests the proxy to establish a TCP
 * connection to the target host/port on behalf of the client. Command format
 * (Section 4):
 * - VER = 5
 * - CMD = 0x01 (CONNECT)
 * - RSV = 0x00 (reserved)
 * - ATYP = address type (0x01 IPv4, 0x03 domain, 0x04 IPv6)
 * - DST.ADDR = target address (variable: 4/ variable/16 bytes)
 * - DST.PORT = target port (2 bytes, network order)
 *
 * Address resolution:
 * - If target_host is IP literal (IPv4/IPv6): uses ATYP accordingly
 * - If domain: ATYP=0x03 (SOCKS5H), sends hostname bytes (1-255 chars)
 * - Performs no DNS; uses pre-resolved or conn->target_host as-is
 *
 * Edge cases:
 * - Invalid target_host (empty, too long >255 for domain): Proxy_Failed
 * - Unsupported ATYP (e.g., no IPv6 if not configured): error
 * - Port out of range (0 or >65535): validation error
 *
 * Variable length packet size calculated dynamically; max ~300 bytes typical.
 * Populates send_buf, sets send_len; ready for transmission.
 *
 * @param[in] conn Proxy context post-auth (proto_state ready for CONNECT),
 *                 with target_host and target_port set.
 *
 * @return 0 success (packet built), -1 failure (invalid target details).
 *
 * @throws Proxy_Failed On invalid target configuration, address parsing
 * errors, or arena allocation for temp buffers.
 *
 * @threadsafe No - Modifies send_buf and send_len in conn.
 *
 *  Usage Example
 *
 * @code
 * // After auth success or no-auth
 * if (conn->proto_state == PROTO_STATE_SOCKS5_AUTH_RECEIVED ||
 *     conn->proto_state == PROTO_STATE_SOCKS5_METHOD_RECEIVED) {
 *     if (proxy_socks5_send_connect(conn) < 0) {
 *         socketproxy_set_error(conn, PROXY_ERROR_CONFIG, "Failed to build
 * CONNECT"); return;
 *     }
 *     conn->proto_state = PROTO_STATE_SOCKS5_CONNECT_SENT;
 *     // Enqueue send in poll or loop
 * }
 * @endcode
 *
 * @note Supports domain name resolution at proxy (SOCKS5H); no client-side DNS
 * here.
 * @warning Large hostnames (>255) will fail; trim or resolve to IP
 * client-side.
 * @complexity O(m) where m = length of target address string - copy and
 * serialization.
 *
 * @see proxy_socks5_recv_connect() Handles proxy response and bound address.
 * @see socketproxy_do_send() Transmits the CONNECT command.
 * @see SOCKS5_ATYP_* For address type details.
 * @see SocketProxy_Conn_T::target_host, ::target_port Input fields.
 * @see docs/PROXY.md#socks5-connect For command flow.
 * @see RFC 1928 Section 4 "Commands" and "Address Formats".
 */
extern int proxy_socks5_send_connect (struct SocketProxy_Conn_T *conn);

/**
 * @brief Parses SOCKS5 CONNECT response to determine tunnel establishment (RFC
 * 1928).
 * @ingroup core_io
 * @ingroup proxy_private
 *
 * Processes the variable-length response from the proxy after CONNECT command.
 * Response format (Section 4):
 * - VER = 5
 * - REP = reply code (0x00 success, 0x01-0x08 errors)
 * - RSV = 0x00
 * - ATYP = bound address type
 * - BND.ADDR = bound server address (variable)
 * - BND.PORT = bound server port (2 bytes)
 *
 * On success (REP=0x00):
 * - Tunnel established; application can now send/receive data through proxy
 * - Bound addr/port informational (often 0.0.0.0:0), but parsed for
 * completeness
 * - Sets result=PROXY_OK, advances to PROTO_STATE_DONE
 *
 * Error handling:
 * - Maps REP to specific SocketProxy_Result via proxy_socks5_reply_to_result()
 * - e.g., 0x05 connection refused -> PROXY_CONNECTION_REFUSED
 * - Parses full response including address (variable length: IPv4=10B,
 * IPv6=22B, domain=var)
 * - Incomplete data (recv_len < min expected): PROXY_IN_PROGRESS
 * - Invalid format: PROXY_PROTOCOL_ERROR, error_buf populated
 *
 * Consumes all response bytes; validates lengths to prevent buffer over-read.
 *
 * @param[in,out] conn Context with recv_buf filled by do_recv, proto_state ==
 * SOCKS5_CONNECT_SENT. Updates result, proto_state, consumes
 * recv_offset/recv_len.
 *
 * @return SocketProxy_Result:
 *         - PROXY_OK: Success (REP=0x00), tunnel ready, full response parsed
 *         - PROXY_IN_PROGRESS: Partial response, need more recv
 *         - PROXY_PROTOCOL_ERROR: Malformed response (wrong VER/ATYP/lengths)
 *         - Various PROXY_*_ERROR based on REP (e.g., PROXY_PROXY_ERROR for
 * general failure)
 *
 * @throws Proxy_Failed On parse anomalies (e.g., invalid address length).
 *
 * @threadsafe No - Modifies conn recv state and overall result/state.
 *
 *  Usage Example
 *
 * @code
 * // In handshake recv loop
 * int bytes = socketproxy_do_recv(conn);
 * if (bytes > 0) {
 *     SocketProxy_Result r = proxy_socks5_recv_connect(conn);
 *     if (r == PROXY_OK) {
 *         conn->state = SOCKET_PROXY_STATE_CONNECTED;  // Tunnel up
 *         socketproxy_advance_state(conn);  // To DONE
 *         // Transfer socket to user
 *     } else if (r != PROXY_IN_PROGRESS) {
 *         // Error: set_error, close socket
 *     }
 * }
 * @endcode
 *
 * @note Success means proxy connected to target; subsequent I/O is tunneled.
 * @warning Bound addr may be useful for logging but not for reply-to; ignore
 * for client.
 * @complexity O(l) where l = length of bound address - parse and copy time.
 *
 * @see proxy_socks5_send_connect() Issues the CONNECT command.
 * @see proxy_socks5_reply_to_result() Maps REP codes to results.
 * @see socketproxy_do_recv() Supplies response data.
 * @see SOCKS5_REPLY_* Constants for error codes.
 * @see docs/PROXY.md#connect-response For success criteria.
 * @see RFC 1928 Section 4 "Reply" and address types.
 */
extern SocketProxy_Result
proxy_socks5_recv_connect (struct SocketProxy_Conn_T *conn);

/**
 * @brief Maps SOCKS5 reply codes from CONNECT response to library result
 * enums.
 * @ingroup core_io
 * @ingroup proxy_private
 *
 * Utility function to convert raw SOCKS5 REP field (1 byte) into standardized
 * SocketProxy_Result for consistent error handling across protocol
 * implementations.
 *
 * Mapping table:
 * | REP | Meaning | Result |
 * |-----|---------|--------|
 * | 0x00 | Succeeded | PROXY_OK |
 * | 0x01 | General SOCKS server failure | PROXY_PROXY_ERROR |
 * | 0x02 | Not allowed by ruleset | PROXY_PROXY_ERROR |
 * | 0x03 | Network unreachable | PROXY_NETWORK_ERROR |
 * | 0x04 | Host unreachable | PROXY_NETWORK_ERROR |
 * | 0x05 | Connection refused | PROXY_CONNECTION_REFUSED |
 * | 0x06 | TTL expired | PROXY_TIMEOUT |
 * | 0x07 | Command not supported | PROXY_PROTOCOL_ERROR |
 * | 0x08 | Address type not supported | PROXY_PROTOCOL_ERROR |
 * | other | Unknown | PROXY_PROTOCOL_ERROR |
 *
 * Ensures specific errors like refused/timeout are distinguishable for retry
 * logic. No side effects; pure mapping function.
 *
 * @param[in] reply Raw REP code from SOCKS5 response (typically 0x00-0x08).
 *
 * @return Corresponding SocketProxy_Result; PROXY_OK only for success (0x00).
 *
 * @throws None - Pure function, no exceptions raised.
 *
 * @threadsafe Yes - Stateless, no shared state or side effects.
 *
 *  Usage Example
 *
 * @code
 * // Inside proxy_socks5_recv_connect after parsing REP
 * int raw_rep = recv_buf[1];  // REP field
 * SocketProxy_Result r = proxy_socks5_reply_to_result(raw_rep);
 * if (r != PROXY_OK) {
 *     // Map to conn->result, log specific error
 *     const char *msg = socketproxy_result_to_string(r);  // Hypothetical
 *     socketproxy_set_error(conn, r, "SOCKS5 REP %d: %s", raw_rep, msg);
 * }
 * @endcode
 *
 * @note Default to PROXY_PROXY_ERROR for unhandled codes to avoid silent
 * failures.
 * @complexity O(1) - Switch or table lookup.
 *
 * @see SOCKS5_REPLY_* Raw code constants.
 * @see proxy_socks5_recv_connect() Primary caller during response parsing.
 * @see SocketProxy_Result Enum for library-wide error codes.
 * @see docs/PROXY.md#error-mapping For integration with retry policies.
 * @see RFC 1928 Appendix A "Reply Codes".
 */
extern SocketProxy_Result proxy_socks5_reply_to_result (int reply);

/**
 * @brief Internal functions for SOCKS4 and SOCKS4a protocol handling.
 * @ingroup core_io
 *
 * Implements SOCKS4 connect requests (IPv4 only) and SOCKS4a extension for
 * domain names.
 *
 * @see RFC 1928 Appendix A for SOCKS4 details (informational).
 * @see proxy_socks4_send_connect(), proxy_socks4a_send_connect() for requests.
 */

/**
 * @brief Builds SOCKS4 CONNECT request for IPv4 targets (legacy protocol).
 * @ingroup core_io
 * @ingroup proxy_private
 *
 * Constructs the simple SOCKS4 request for establishing connection to IPv4
 * target. SOCKS4 is legacy (IPv4 only, no auth, no UDP); uses SOCKS4a
 * extension for domains. Format (RFC 1928 Appendix A):
 * - VN = 4
 * - CD = 1 (CONNECT)
 * - DSTPORT = 2 bytes network order
 * - DSTIP = 4 bytes IPv4 (or 0.0.0.x for SOCKS4a domain)
 * - USERID = null-terminated string ("socket\0")
 * - [DOMAIN] = null-terminated domain (SOCKS4a only, if IP starts
 * 0.0.0.nonzero)
 *
 * Limitations:
 * - IPv4 only for standard; domain via unofficial SOCKS4a (detected if
 * target_host not IP)
 * - No authentication; fixed userid "socket"
 * - Fixed packet size ~13 + userid + optional domain
 *
 * Determines type: if target_host parses as IPv4 -> standard SOCKS4; else
 * SOCKS4a with domain. Validates IP parse; errors if neither valid.
 *
 * @param[in] conn Context with type=SOCKET_PROXY_SOCKS4, target_host/port set.
 *                 Must be IPv4 or resolvable domain for SOCKS4a.
 *
 * @return 0 success (buffer set), -1 failure (invalid IPv4/domain).
 *
 * @throws Proxy_Failed If target_host not valid IPv4 or domain (>255 chars),
 * port invalid.
 *
 * @threadsafe No - Writes to conn send_buf/len.
 *
 *  Usage Example
 *
 * @code
 * // For SOCKS4 type after init state
 * if (conn->type == SOCKET_PROXY_SOCKS4 && conn->proto_state ==
 * PROTO_STATE_INIT) { if (proxy_socks4_send_connect(conn) < 0 &&
 * !proxy_socks4a_send_connect(conn)) {
 *         // Try SOCKS4a fallback if pure IPv4 fails? But here separate.
 *         socketproxy_set_error(conn, PROXY_ERROR_CONFIG, "Invalid SOCKS4
 * target"); } else { conn->proto_state = PROTO_STATE_SOCKS4_CONNECT_SENT;
 *     }
 * }
 * @endcode
 *
 * @note Prefer SOCKS5 for modern use; SOCKS4 deprecated but supported for
 * compatibility.
 * @warning No auth; insecure - use only trusted proxies.
 * @complexity O(1) for IPv4, O(d) for domain copy where d=domain len.
 *
 * @see proxy_socks4a_send_connect() For domain extension variant.
 * @see proxy_socks4_recv_response() Parses simple reply.
 * @see socketproxy_do_send() Sends the request.
 * @see docs/PROXY.md#socks4 For legacy protocol notes.
 * @see RFC 1928 Appendix A "SOCKS 4 Protocol".
 */
extern int proxy_socks4_send_connect (struct SocketProxy_Conn_T *conn);

/**
 * @brief Builds SOCKS4a CONNECT request using domain name (unofficial
 * extension).
 * @ingroup core_io
 * @ingroup proxy_private
 *
 * Extension to legacy SOCKS4 protocol enabling domain name targets (SOCKS4a).
 * Non-standard but widely supported; allows proxy to resolve hostname instead
 * of client. Format same as SOCKS4 but:
 * - DSTIP = 0.0.0.x where x!=0 (e.g., 0.0.0.1) signals domain follow
 * - After USERID\0: null-terminated domain string (no length prefix)
 *
 * Used when target_host cannot parse as IPv4 (falls back from
 * socks4_send_connect). Fixed userid "socket\0"; no auth. Packet size: 8
 * (header) + 8 (userid) + domain + \0
 *
 * Edge cases:
 * - Domain empty or > ~250 chars (practical limit): Proxy_Failed
 * - Contains null bytes: truncated at first null
 * - IPv6 or invalid: not supported (SOCKS4 limitation)
 *
 * Builds into send_buf; compatible response parser with standard SOCKS4.
 *
 * @param[in] conn Context with type=SOCKET_PROXY_SOCKS4, target_host as domain
 * (non-IP).
 *
 * @return 0 success, -1 failure (invalid domain length/format).
 *
 * @throws Proxy_Failed If domain invalid (empty, too long, malformed).
 *
 * @threadsafe No - Modifies conn send state.
 *
 *  Usage Example
 *
 * @code
 * // Fallback when SOCKS4 IPv4 fails
 * if (proxy_socks4_send_connect(conn) < 0) {
 *     if (proxy_socks4a_send_connect(conn) == 0) {
 *         // SOCKS4a succeeded
 *         conn->proto_state = PROTO_STATE_SOCKS4_CONNECT_SENT;
 *     } else {
 *         socketproxy_set_error(conn, PROXY_ERROR_CONFIG, "SOCKS4(a) target
 * invalid");
 *     }
 * }
 * @endcode
 *
 * @note Unofficial extension; some proxies may not support - prefer SOCKS5.
 * @warning Domain resolution at proxy; client has no control over DNS used.
 * @complexity O(d) domain length - string copy and null-term.
 *
 * @see proxy_socks4_send_connect() Standard IPv4 variant.
 * @see proxy_socks4_recv_response() Shared response parser (ignores bound
 * addr).
 * @see docs/PROXY.md#socks4a-extension For compatibility notes.
 * @see RFC 1928 Appendix A (base); SOCKS4a described in various
 * implementations.
 */
extern int proxy_socks4a_send_connect (struct SocketProxy_Conn_T *conn);

/**
 * @brief Parses SOCKS4/SOCKS4a response to check connection result.
 * @ingroup core_io
 * @ingroup proxy_private
 *
 * Handles response for both standard SOCKS4 and SOCKS4a requests (shared
 * format). Fixed 8-byte response:
 * - VN = 0 (null, not version)
 * - CD = status (90 granted, 91 rejected, 92 no identd, 93 ident mismatch)
 * - DSTPORT = 2 bytes (bound port, ignored)
 * - DSTIP = 4 bytes (bound IP, ignored for client)
 *
 * Validation:
 * - Expects exactly 8 bytes; shorter -> IN_PROGRESS
 * - VN must be 0, else PROTOCOL_ERROR
 * - Maps CD via proxy_socks4_reply_to_result() to result
 * - On success (90): tunnel ready, advance to DONE
 * - Errors set result, error_buf with details
 *
 * Simpler than SOCKS5; no variable addr types or auth.
 *
 * @param[in,out] conn With recv_buf (min 8 bytes expected), state
 * SOCKS4_CONNECT_SENT. Updates result, state, consumes bytes.
 *
 * @return SocketProxy_Result:
 *         - PROXY_OK: Granted (CD=90), tunnel established
 *         - PROXY_IN_PROGRESS: recv_len <8
 *         - PROXY_PROTOCOL_ERROR: Invalid VN or format
 *         - PROXY_PROXY_ERROR: Rejected (91-93)
 *
 * @throws Proxy_Failed On buffer issues.
 *
 * @threadsafe No - Modifies conn.
 *
 *  Usage Example
 *
 * @code
 * SocketProxy_Result r = proxy_socks4_recv_response(conn);
 * if (r == PROXY_OK) {
 *     // Success: SOCKS4 tunnel up
 *     conn->result = PROXY_OK;
 *     conn->proto_state = PROTO_STATE_DONE;
 * } else if (r == PROXY_PROXY_ERROR) {
 *     socketproxy_set_error(conn, r, "SOCKS4 connection rejected");
 *     Socket_close(conn->socket);
 * }
 * @endcode
 *
 * @note Bound port/IP ignored; for server-side bind use case (not client).
 * @warning Legacy protocol; limited error granularity (all failures ->
 * PROXY_PROXY_ERROR).
 * @complexity O(1) - Fixed-size parse.
 *
 * @see proxy_socks4_send_connect(), proxy_socks4a_send_connect() Request
 * builders.
 * @see proxy_socks4_reply_to_result() Status mapper.
 * @see SOCKS4_REPLY_* Codes.
 * @see docs/PROXY.md#socks4-response Simple reply handling.
 * @see RFC 1928 Appendix A "Reply Format".
 */
extern SocketProxy_Result
proxy_socks4_recv_response (struct SocketProxy_Conn_T *conn);

/**
 * @brief Maps SOCKS4 reply codes to SocketProxy_Result for error consistency.
 * @ingroup core_io
 * @ingroup proxy_private
 *
 * Converts SOCKS4 CD field (1 byte) to library result; simpler than SOCKS5.
 * All non-success map to PROXY_PROXY_ERROR (limited granularity in protocol).
 *
 * Mapping:
 * | CD | Meaning | Result |
 * |----|---------|--------|
 * | 90 | Request granted | PROXY_OK |
 * | 91 | Request rejected/died | PROXY_PROXY_ERROR |
 * | 92 | SOCKS server cannot connect to identd | PROXY_PROXY_ERROR |
 * | 93 | Identd protocol error/user ID mismatch | PROXY_PROXY_ERROR |
 * | other | Invalid | PROXY_PROTOCOL_ERROR |
 *
 * Used to normalize legacy errors for retry/is_retryable checks.
 * Pure function, no conn dependency.
 *
 * @param[in] reply CD code from response (90-93 typically).
 *
 * @return SocketProxy_Result; PROXY_OK only for 90.
 *
 * @throws None.
 *
 * @threadsafe Yes - Pure, stateless.
 *
 * @note SOCKS4 lacks detailed errors; all failures treated uniformly.
 * @complexity O(1).
 *
 * @see SOCKS4_REPLY_* Constants.
 * @see proxy_socks4_recv_response() Caller.
 * @see SocketProxy_Result For retry categorization.
 * @see RFC 1928 Appendix A "Status".
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
 * @brief Constructs HTTP CONNECT request to establish tunneled connection (RFC
 * 7230).
 * @ingroup core_io
 * @ingroup proxy_private
 *
 * Builds HTTP/1.1 CONNECT method request for proxying TCP traffic (typically
 * HTTPS). Request format: CONNECT target_host:target_port HTTP/1.1\r\n Host:
 * target_host:target_port\r\n [Proxy-Authorization: Basic
 * base64(user:pass)\r\n] if credentials [extra_headers]\r\n \r\n
 *
 * Uses SocketHTTP types internally for serialization; appends CRLF properly.
 * Supports Basic auth: encodes user:pass to base64 if username/password set.
 * Extra headers from conn->extra_headers added verbatim.
 *
 * Edge cases:
 * - No target_host/port: invalid, error
 * - Credentials with special chars: base64 handles
 * - Large headers: limited by buffer size (64KB)
 * - HTTP/1.0 proxies: still sends 1.1 but compatible
 *
 * Serializes to send_buf (text protocol); sets send_len. No I/O performed.
 *
 * @param[in] conn Context with type=SOCKET_PROXY_HTTP, target details,
 * optional creds/headers.
 *
 * @return 0 success (request string built), -1 failure (e.g., serialization
 * error).
 *
 * @throws Proxy_Failed On invalid config, header errors, or buffer overflow.
 *
 * @threadsafe No - Uses/modifies conn send_buf.
 *
 *  Usage Example
 *
 * @code
 * // For HTTP proxy type
 * if (conn->type == SOCKET_PROXY_HTTP && conn->proto_state ==
 * PROTO_STATE_INIT) { SocketHTTP_Headers_T headers =
 * SocketHTTP_Headers_new(conn->arena); SocketHTTP_Headers_add(headers,
 * "User-Agent", "SocketLib/1.0"); conn->extra_headers = headers; if
 * (proxy_http_send_connect(conn) < 0) { socketproxy_set_error(conn,
 * PROXY_ERROR_CONFIG, "HTTP CONNECT build failed"); } else { conn->proto_state
 * = PROTO_STATE_HTTP_REQUEST_SENT;
 *     }
 * }
 * @endcode
 *
 * @note HTTP proxies often require TLS after CONNECT for HTTPS; handled
 * separately.
 * @warning Basic auth transmitted base64 (not encrypted); use TLS to proxy for
 * security.
 * @complexity O(h + c) where h=headers size, c=creds encoded length.
 *
 * @see proxy_http_recv_response() Validates 200 response.
 * @see SocketHTTP_Headers_T Manages extra headers.
 * @see SocketHTTPClient.h Related high-level HTTP.
 * @see docs/PROXY.md#http-connect For tunneling setup.
 * @see RFC 7230 Section 5.3.2 CONNECT method; RFC 7235 for auth.
 */
extern int proxy_http_send_connect (struct SocketProxy_Conn_T *conn);

/**
 * @brief Parses HTTP response to CONNECT request for tunnel confirmation.
 * @ingroup core_io
 * @ingroup proxy_private
 *
 * Uses incremental SocketHTTP1_Parser to process response from recv_buf.
 * Expects HTTP/1.1 200 Connection established (or 2xx variants).
 * Handles headers fully; no body expected for successful tunnel.
 *
 * Parsing flow:
 * - Feeds data to parser->execute until headers complete or error
 * - Validates status: 2xx -> OK, 4xx/5xx -> map via status_to_result
 * - Checks Connection: close/keep-alive? But for tunnel, ignore after success
 * - Advances state to HTTP_RESPONSE_RECEIVED on complete headers
 *
 * Edge cases:
 * - Partial headers (IN_PROGRESS): returns if !body_complete
 * - Chunked/ content-length body: unexpected, PROTOCOL_ERROR (tunnel shouldn't
 * have body)
 * - Upgrade responses: not handled here (WebSocket separate)
 * - Parser errors (malformed HTTP): HTTP_PARSE_ERROR
 *
 * On success: tunnel ready; subsequent recv/send bypass HTTP parser.
 * Integrates with http_parser in conn for stateful incremental parse.
 *
 * @param[in,out] conn With recv_buf data, http_parser initialized for response
 * mode. Updates parser state, result, proto_state.
 *
 * @return SocketProxy_Result:
 *         - PROXY_OK: 2xx status, headers parsed, tunnel established
 *         - PROXY_IN_PROGRESS: Headers incomplete, need more data
 *         - PROXY_HTTP_ERROR: 4xx/5xx or parse failure
 *         - PROXY_PROTOCOL_ERROR: Unexpected body or upgrade
 *
 * @throws Proxy_Failed On parser exceptions or invalid response.
 *
 * @threadsafe No - Stateful parser in conn.
 *
 *  Usage Example
 *
 * @code
 * // Incremental parse in recv loop
 * while (SocketPoll_wait(...) ) {
 *     int bytes = socketproxy_do_recv(conn);
 *     if (bytes > 0) {
 *         size_t consumed;
 *         SocketProxy_Result r = proxy_http_recv_response(conn);  //
 * Internally calls parser_execute if (r == PROXY_OK) {
 *             // Tunnel up: discard parser, use raw socket I/O
 *             conn->proto_state = PROTO_STATE_DONE;
 *         } else if (r == PROXY_IN_PROGRESS) {
 *             continue;  // Wait for more data
 *         } else {
 *             // Error response, e.g., 407 proxy auth required
 *             socketproxy_set_error(conn, r, "HTTP proxy refused: %d",
 * status);
 *         }
 *     }
 * }
 * @endcode
 *
 * @note After success, may need to handle optional 100 Continue or pipelining
 * (rare).
 * @warning Proxies may require additional auth headers; use extra_headers for
 * Proxy-Authenticate.
 * @complexity O(b) bytes parsed - linear in response size.
 *
 * @see proxy_http_send_connect() Sends the CONNECT method.
 * @see proxy_http_status_to_result() Status code mapper.
 * @see SocketHTTP1_Parser_T Incremental HTTP/1.1 parser used.
 * @see SocketHTTP_status_category() For 2xx validation.
 * @see docs/PROXY.md#http-response For expected codes.
 * @see RFC 7230 Section 5.3.2 "CONNECT Response".
 */
extern SocketProxy_Result
proxy_http_recv_response (struct SocketProxy_Conn_T *conn);

/**
 * @brief Maps HTTP status codes from CONNECT response to SocketProxy_Result.
 * @ingroup core_io
 * @ingroup proxy_private
 *
 * Converts HTTP status to library result specifically for proxy CONNECT
 * context. Focuses on tunneling semantics:
 * - 2xx (esp. 200): Success, tunnel open
 * - 4xx: Client/proxy errors (auth, forbidden)
 * - 5xx: Server errors
 * - Informational (1xx): Incomplete, but rare for CONNECT
 *
 * Detailed mapping examples:
 * | Status | Meaning for CONNECT | Result |
 * |--------|---------------------|--------|
 * | 200 | Connection established | PROXY_OK |
 * | 407 | Proxy auth required | PROXY_ERROR_AUTH_REQUIRED |
 * | 403 | Forbidden | PROXY_PROXY_ERROR |
 * | 502 | Bad gateway | PROXY_SERVER_ERROR |
 * | 1xx | Informational (continue?) | PROXY_IN_PROGRESS |
 * | other 4xx/5xx | General failure | PROXY_HTTP_ERROR |
 *
 * Integrates with SocketHTTP_status_category for broad classification.
 * Enables retry logic: e.g., 407 may need re-auth, 5xx retryable.
 *
 * @param[in] status HTTP status code from parser (100-599 range).
 *
 * @return SocketProxy_Result based on status category and semantics.
 *
 * @throws None - Pure mapping.
 *
 * @threadsafe Yes - Stateless.
 *
 *  Usage Example
 *
 * @code
 * // In proxy_http_recv_response after getting status
 * int status = SocketHTTP1_Parser_get_response(conn->http_parser)->status;
 * SocketProxy_Result r = proxy_http_status_to_result(status);
 * if (r == PROXY_OK) {  // 2xx
 *     // Tunnel ready
 * } else if (r == PROXY_ERROR_AUTH_REQUIRED) {  // 407
 *     // Handle re-auth or abort
 * } else {
 *     socketproxy_set_error(conn, r, "HTTP %d", status);
 * }
 * @endcode
 *
 * @note Custom mappings for proxy-specific codes like 407.
 * @complexity O(1) - Conditional checks.
 *
 * @see SocketHTTP_status_category() Base category (1-5).
 * @see SocketHTTP_status_valid() Range check.
 * @see proxy_http_recv_response() Primary usage.
 * @see docs/PROXY.md#http-status For common proxy responses.
 * @see RFC 7230 Sections 6 (status codes), 5.3.2 CONNECT.
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
 * @brief Advances the protocol state machine for proxy negotiation.
 * @ingroup core_io
 * @ingroup proxy_private
 *
 * Central dispatcher for handshake progression based on proto_state and
 * high-level state. Dispatches to protocol-specific handlers
 * (ProxySendFunc/ProxyRecvFunc) or completes.
 *
 * Transitions overview (simplified):
 * - INIT -> Send greeting/request (socks5_send_greeting, socks4_send_connect,
 * http_send_connect)
 * - *_SENT -> Wait recv, then parse response func
 * - *_RECEIVED -> Success: DONE/CONNECTED; Fail: ERROR
 * - DONE: No-op, handshake complete
 *
 * Determines if next is send or recv phase via state (odd=even SENT/RECEIVED).
 * Calls appropriate build/parse func if needed, or sets final result/state.
 * Handles protocol switch (SOCKS4/5/HTTP) via conn->type.
 *
 * Edge cases:
 * - Invalid state: Logs error, sets ERROR
 * - During async: Integrates with poll events
 * - Timeout check integrated via elapsed_ms
 *
 * Called after successful socketproxy_do_send/do_recv or poll events.
 *
 * @param[in,out] conn Current proxy context with updated state/buffers from
 * prior I/O. Dispatches handlers, updates proto_state, result, may raise
 * errors.
 *
 * @return Void - Advances state in-place; check conn->result for outcome.
 *
 * @throws Proxy_Failed Via dispatched handlers on internal errors.
 *
 * @threadsafe No - Modifies conn state machine.
 *
 *  Usage Example
 *
 * Called after successful I/O operations to advance the proxy protocol state
 * machine.
 *
 * @note Idempotent in terminal states (DONE/ERROR).
 * @warning Avoid calling during I/O; post-I/O only to prevent races.
 * @complexity O(1) average - dispatches to O(1) handlers.
 *
 * @see SocketProxy_ProtoState Detailed sub-states.
 * @see ProxySendFunc, ProxyRecvFunc Typedefs for dispatched funcs.
 * @see socketproxy_do_send(), socketproxy_do_recv() I/O triggers.
 * @see docs/PROXY.md#state-machine For full transition diagram.
 */
extern void socketproxy_advance_state (struct SocketProxy_Conn_T *conn);

/**
 * @brief Sets error condition in connection context with formatted message.
 * @ingroup core_io
 * @ingroup proxy_private
 *
 * Records failure state during handshake: updates conn->result, ->state=ERROR,
 * formats user message into ->error_buf (thread-local safe via vsnprintf),
 * emits log via SOCKET_LOG_ERROR_MSG with "Proxy" component.
 *
 * Handles varargs printf-style; truncates at SOCKET_PROXY_ERROR_BUFSIZE
 * (256B). Called by handlers on protocol errors, timeouts, I/O fails. Allows
 * post-error inspection via conn->result / error_buf before cleanup.
 *
 * Edge cases:
 * - NULL conn: no-op (defensive)
 * - Invalid result: clamped to valid enum
 * - Long fmt: truncated, but logs attempt
 * - No log callback: silent log drop
 *
 * Integrates with Except via optional RAISE after set.
 *
 * @param[in,out] conn Context to update (non-NULL expected).
 * @param[in] result SocketProxy_Result error code to record.
 * @param[in] fmt printf format string for error message.
 * @param[in] ... Variable arguments matching fmt.
 *
 * @return Void - State updated in-place.
 *
 * @throws None - Logs instead of throwing; use RAISE_PROXY_ERROR for
 * exceptions.
 *
 * @threadsafe Partial - error_buf local to conn; log may need sync if callback
 * shared.
 *
 *  Usage Example
 *
 * @code
 * // On parse failure
 * socketproxy_set_error(conn, PROXY_PROTOCOL_ERROR,
 *                       "Invalid SOCKS5 VER=%d expected 5", ver);
 * // Logs: ERROR Proxy: Invalid SOCKS5 VER=...
 * // Caller checks conn->result != PROXY_OK, raises or returns
 * @endcode
 *
 * @note Message preserved until conn_free; useful for debug.
 * @warning Fixed buf size; avoid long formats to prevent truncation.
 * @complexity O(m) message length - formatting time.
 *
 * @see SocketProxy_Conn_T::error_buf, ::result Fields updated.
 * @see PROXY_ERROR_FMT() Pre-format macros.
 * @see SOCKET_LOG_ERROR_MSG Underlying log.
 * @see RAISE_PROXY_ERROR To propagate as exception.
 * @see docs/ERROR_HANDLING.md For integration patterns.
 */
extern void socketproxy_set_error (struct SocketProxy_Conn_T *conn,
                                   SocketProxy_Result result,
                                   const char *fmt,
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
 * @return >0 bytes received, 0 EOF, -1 error (EAGAIN returns -1 but ok, check
 * errno).
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
 * @param arena Arena for strdup copies; NULL uses static buffer
 * (non-thread-safe).
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
                                       Arena_T arena,
                                       const char **end);

/**
 * @brief Parse [host]:port from URL, handling IPv6 literals.
 * @ingroup core_io
 * @param start Start of host/port section (after userinfo@).
 * @param[out] config Output, sets proxy_host and proxy_port (default per
 * type).
 * @param arena Arena for host copy; NULL uses static.
 * @param[out] consumed_out Optional: bytes parsed (including port).
 *
 * Parses host (domain/IPv4/IPv6), optional :port (defaults: 1080 socks, 8080
 * http). Validates port range, copies host to arena or static buf.
 *
 * @return 0 success, -1 invalid host/port.
 *
 * @note IPv6 requires [] brackets.
 * @see SocketProxy_Config::proxy_host, ::proxy_port
 * @see socket_util_arena_strdup() for copying.
 */
extern int socketproxy_parse_hostport (const char *start,
                                       SocketProxy_Config *config,
                                       Arena_T arena,
                                       size_t *consumed_out);

/** @} */ /* proxy_private */

#endif /* SOCKETPROXY_PRIVATE_INCLUDED */
