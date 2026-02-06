/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETCOMMON_INCLUDED
#define SOCKETCOMMON_INCLUDED

#include <pthread.h>
#include <stdbool.h>

/**
 * @file SocketCommon.h
 * @ingroup core_io
 * @brief Common utilities shared between Socket and SocketDgram modules.
 *
 * Provides shared functionality for both TCP and UDP socket implementations,
 * including address resolution, timeout management, and socket configuration.
 *
 * @see Socket_T for TCP socket operations.
 * @see SocketDgram_T for UDP socket operations.
 */

#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h" /* Defines SocketTimeouts_T */

/* Common exception types (Except_T is defined in Except.h) */

/**
 * @brief General TCP socket operation failure exception.
 * @ingroup core_io
 *
 * See Socket.h for detailed documentation on when this is raised,
 * retryability, and error categorization.
 *
 * @see Socket_Failed in @ref Socket.h "Socket.h" for full details.
 */
extern const Except_T Socket_Failed;

/**
 * @brief General UDP/datagram socket operation failure exception.
 * @ingroup core_io
 *
 * Raised for errors specific to datagram sockets such as:
 * - Invalid multicast group addresses
 * - Broadcast permission failures
 * - TTL/hop limit setting errors
 *
 * Category: NETWORK
 * Retryable: Depends on errno
 *
 * @see SocketDgram.h for detailed documentation.
 * @see Socket_error_is_retryable() for retryability checking.
 */
extern const Except_T SocketDgram_Failed;

/**
 * @brief General failure in shared socket common utilities.
 * @ingroup core_io
 *
 * Category: NETWORK or APPLICATION
 * Retryable: Depends on errno - use Socket_error_is_retryable() to check
 *
 * Raised for errors in common functions such as:
 * - Address resolution failures (getaddrinfo errors)
 * - Hostname/port validation failures
 * - Socket option setting failures (setsockopt)
 * - iovec manipulation errors (overflow, invalid parameters)
 * - Bind/connect helper failures
 * - Multicast join/leave errors
 *
 * Always check errno via Socket_geterrno() for specific error details.
 *
 * @see Socket_resolve_address() for address resolution that may raise this.
 * @see SocketCommon_validate_port() for port validation.
 * @see SocketCommon_set_option_int() for option setting.
 * @see SocketCommon_calculate_total_iov_len() for iovec operations.
 * @see Socket_error_is_retryable() for retry decisions.
 * @see Socket_geterrno() for error code access.
 * @see docs/ERROR_HANDLING.md for exception handling patterns.
 */
extern const Except_T SocketCommon_Failed;

/**
 * @brief Initialize addrinfo hints structure for address resolution
 * operations.
 * @ingroup core_io
 *
 * Prepares a struct addrinfo hints for use with getaddrinfo() or
 * SocketCommon_resolve_address(). This function ensures dual-stack IPv4/IPv6
 * support by setting ai_family to AF_UNSPEC, and configures the socket type
 * and additional resolution flags. The hints structure must be
 * zero-initialized before calling this function to avoid garbage data.
 *
 * Important notes:
 * - Always zero the hints structure first with memset(hints, 0,
 * sizeof(*hints))
 * - ai_protocol remains 0 (default protocol for socktype)
 * - For binding operations, use AI_PASSIVE | AI_ADDRCONFIG flags
 * - For connecting/sending, use AI_ADDRCONFIG for preferring configured
 * interfaces
 * - This setup enables Happy Eyeballs (RFC 6555) compatible resolution when
 * used with SocketDNS
 *
 * @param[in,out] hints Pointer to addrinfo structure to initialize. Must point
 * to valid memory. The structure will be zeroed and configured with standard
 * values.
 * @param[in] socktype Socket type: SOCK_STREAM for TCP, SOCK_DGRAM for UDP.
 * @param[in] flags Resolution flags: e.g., AI_PASSIVE for bind, 0 for
 * connect/sendto. Common combinations: AI_PASSIVE | AI_ADDRCONFIG for servers.
 *
 * @return None (void function)
 *
 * @throws None
 *
 * @threadsafe Yes - operates only on caller-provided structure, no shared
 * state.
 *
 * ## Usage Example
 *
 * @code{.c}
 * // For TCP server bind (passive mode)
 * struct addrinfo hints, *res;
 * SocketCommon_setup_hints(&hints, SOCK_STREAM, AI_PASSIVE | AI_ADDRCONFIG);
 * int rv = getaddrinfo("0.0.0.0", "8080", &hints, &res);
 * if (rv == 0) {
 *     // Use res for binding
 *     freeaddrinfo(res);
 * }
 * @endcode
 *
 * ## Client Connection Setup
 *
 * @code{.c}
 * // For TCP client connect
 * struct addrinfo hints;
 * SocketCommon_setup_hints(&hints, SOCK_STREAM, AI_ADDRCONFIG);
 * struct addrinfo *res;
 * SocketCommon_resolve_address("example.com", 80, &hints, &res, Socket_Failed,
 * AF_UNSPEC, 1);
 * // Use res...
 * SocketCommon_free_addrinfo(res);  // If copied, use this instead of
 * freeaddrinfo
 * @endcode
 *
 * @note Always pair with SocketCommon_resolve_address() for exception-safe
 * resolution.
 * @note For Unix domain sockets, set ai_family = AF_UNIX manually after this
 * call.
 * @note This function does not set ai_protocol; it defaults to 0
 * (auto-select).
 *
 * @complexity O(1) - constant time memory operations
 *
 * @see SocketCommon_resolve_address() for complete resolution with error
 * handling
 * @see getaddrinfo(3) for POSIX specification
 * @see Socket_bind() and Socket_connect() which use similar setup internally
 * @see docs/ASYNC_IO.md for advanced resolution patterns with SocketDNS
 */
void SocketCommon_setup_hints (struct addrinfo *hints, int socktype, int flags);

/**
 * @brief Resolve hostname/port to addrinfo structure using getaddrinfo
 * wrapper.
 * @ingroup core_io
 * @param host Hostname or IP address (NULL for wildcard/any).
 * @param port Port number (1 to SOCKET_MAX_PORT).
 * @param hints Addrinfo hints structure (prepared via
 * SocketCommon_setup_hints()).
 * @param res Output pointer to resolved addrinfo list (caller must free with
 * freeaddrinfo()).
 * @param exception_type Exception type to raise on failure.
 * @param socket_family Preferred socket family to match (AF_UNSPEC for any).
 * @param use_exceptions If true, raise exceptions on failure; if false, return
 * error codes and set errno.
 * @return 0 on success, -1 on failure (if not using exceptions).
 * @throws Specified exception_type on resolution failure (getaddrinfo errors,
 * invalid port, etc.).
 * @note Uses global DNS resolver (SocketCommon_get_dns_resolver()) for timeout
 * guarantees if hostname provided.
 * @note Filters resolved addresses to match socket_family if specified (e.g.,
 * AF_INET only).
 * @note Caller responsible for validating and freeing the addrinfo chain.
 * @note Thread-safe: Yes (uses thread-local error buffers).
 * @see SocketCommon_setup_hints() for preparing hints structure.
 * @see Socket_bind() and Socket_connect() which use this internally.
 * @see SocketCommon_get_dns_resolver() for global DNS timeout configuration.
 * @see SocketCommon_copy_addrinfo() for duplicating resolved chains.
 * @see freeaddrinfo(3) for cleaning up resolved structures.
 * @see docs/ERROR_HANDLING.md for exception patterns in network code.
 */
int SocketCommon_resolve_address (const char *host,
                                  int port,
                                  const struct addrinfo *hints,
                                  struct addrinfo **res,
                                  Except_T exception_type,
                                  int socket_family,
                                  int use_exceptions);

/**
 * @brief Validate that a port number is within the valid range for socket
 * operations.
 * @ingroup core_io
 *
 * Ensures the provided port is between 0 and 65535 inclusive. Port 0 is
 * allowed for cases where the OS assigns an ephemeral port (e.g., during bind
 * for outgoing connections). Invalid ports trigger an immediate exception
 * raise with a descriptive message including the invalid value.
 *
 * This function is used internally by resolution and bind/connect operations
 * to catch invalid port parameters early. It does not perform any system calls
 * or allocations.
 *
 * Edge cases:
 * - port < 0: Invalid, raises exception
 * - port == 0: Valid (ephemeral)
 * - port > 65535: Invalid, raises exception
 * - Non-integer ports: Caller responsibility (port is int param)
 *
 * @param[in] port Port number to validate (int value).
 * @param[in] exception_type Except_T type to raise on validation failure.
 *
 * @return None (void function) - raises exception on failure.
 *
 * @throws exception_type with message "Invalid port number: %d (must be
 * 0-65535, 0 = OS-assigned)" where %d is the invalid port value.
 *
 * @threadsafe Yes - no shared state or system calls, pure validation.
 *
 * ## Usage Example
 *
 * @code{.c}
 * // In connect or bind preparation
 * TRY {
 *     SocketCommon_validate_port(8080, Socket_Failed);
 *     // Proceed with bind/connect using port 8080
 * } EXCEPT(Socket_Failed) {
 *     // This won't trigger for valid port
 * } END_TRY;
 * @endcode
 *
 * ## With Ephemeral Port
 *
 * @code{.c}
 * int ephemeral_port = 0;  // OS assign
 * SocketCommon_validate_port(ephemeral_port, Socket_Failed);  // Valid, no
 * exception
 * @endcode
 *
 * ## Invalid Port Handling
 *
 * @code{.c}
 * TRY {
 *     SocketCommon_validate_port(70000, Socket_Failed);  // Raises exception
 * } EXCEPT(Socket_Failed) {
 *     // Caught here with detailed message
 *     const char *msg = Except_message(Except_stack);  // Access error details
 *     SOCKET_LOG_ERROR_MSG("Port validation failed: %s", msg);
 * } END_TRY;
 * @endcode
 *
 * @note Commonly called before getaddrinfo(), Socket_bind(), Socket_connect().
 * @note For string ports, validate after parsing with strtol() or similar.
 * @note Does not check privileged ports (<1024) - that's OS permission check.
 *
 * @complexity O(1) - simple integer comparison
 *
 * @see SocketCommon_validate_hostname() for host validation
 * @see SocketCommon_resolve_address() which calls this internally
 * @see docs/SECURITY.md for port security considerations
 * @see SocketConfig.h for SOCKET_MAX_PORT definition (usually 65535)
 */
void SocketCommon_validate_port (int port, Except_T exception_type);

/**
 * @brief Validate that a hostname string is not excessively long for system
 * buffers.
 * @ingroup core_io
 *
 * Checks the length of the hostname string against the maximum allowed for
 * system network functions (typically NI_MAXHOST or 255 bytes). Too long
 * hostnames can cause failures in getaddrinfo(), getnameinfo(), etc. Raises
 * exception with details on failure.
 *
 * This validation prevents buffer overflows or truncation in underlying system
 * calls. Does not perform DNS resolution or syntax validation - only length
 * check. NULL host is considered invalid (use
 * SocketCommon_validate_host_not_null for that).
 *
 * Defined max length: SOCKET_MAX_HOSTNAME_LEN (from SocketConfig.h, usually
 * 255)
 *
 * @param[in] host C-string hostname to validate (non-NULL expected).
 * @param[in] exception_type Except_T to raise if length exceeds limit.
 *
 * @return None (void) - raises on failure.
 *
 * @throws exception_type with message detailing the length violation and max
 * allowed.
 *
 * @threadsafe Yes - reads only, no shared state.
 *
 * ## Usage Example
 *
 * @code{.c}
 * const char *hostname = "example.com";
 * TRY {
 *     SocketCommon_validate_hostname(hostname, Socket_Failed);
 *     // Safe to use in resolve_address or connect
 *     SocketCommon_resolve_address(hostname, 80, &hints, &res, Socket_Failed,
 * AF_UNSPEC, 1); } EXCEPT(Socket_Failed) { SOCKET_LOG_ERROR_MSG("Hostname too
 * long: %s", hostname); } END_TRY;
 * @endcode
 *
 * @note Call before resolution to catch early.
 * @note For IP addresses, length check still applies but usually pass.
 * @note Does not check for valid hostname format (use regex or library if
 * needed).
 *
 * @complexity O(n) where n=strlen(host) - linear scan for length.
 *
 * @see SocketCommon_validate_port() companion function
 * @see SocketCommon_validate_host_not_null() for NULL check
 * @see SocketCommon_resolve_address() internal caller
 * @see SocketConfig.h SOCKET_MAX_HOSTNAME_LEN constant
 */
void SocketCommon_validate_hostname (const char *host, Except_T exception_type);

/**
 * @brief Normalize wildcard/any-address host strings to NULL for internal use.
 * @ingroup core_io
 *
 * Converts common wildcard address strings to NULL, which is the canonical
 * representation for "bind/connect to any interface" in socket operations.
 * This simplifies internal logic in bind/connect where NULL host means
 * INADDR_ANY.
 *
 * Recognized wildcards:
 * - NULL input -> NULL (already canonical)
 * - "0.0.0.0" -> NULL (IPv4 any)
 * - "::" -> NULL (IPv6 any)
 * Other strings returned unchanged (caller responsible for resolution).
 *
 * Does not perform DNS resolution or validation - pure string comparison.
 * Case-sensitive match.
 *
 * @param[in] host Host string to normalize (may be NULL).
 *
 * @return NULL if input represents wildcard/any, otherwise original host
 * string (const). Return value is always either NULL or the input pointer (no
 * allocation).
 *
 * @throws None
 *
 * @threadsafe Yes - read-only string comparison, no shared state.
 *
 * ## Usage Example
 *
 * @code{.c}
 * const char *effective_host =
 * SocketCommon_normalize_wildcard_host("0.0.0.0");
 * // effective_host == NULL
 * SocketCommon_resolve_address(effective_host, 8080, &hints, &res, ...);  //
 * Resolves to any local addr
 * @endcode
 *
 * ## Non-Wildcard
 *
 * @code{.c}
 * const char *host = "192.168.1.1";
 * const char *norm = SocketCommon_normalize_wildcard_host(host);
 * // norm == host (unchanged)
 * @endcode
 *
 * @note Used internally by Socket_bind() and Socket_connect() for canonical
 * handling.
 * @note Does not handle other wildcard forms like "any" or "*" - only numeric
 * any addresses.
 * @note For IPv6, only "::" recognized; full "::0" or others not normalized
 * here.
 *
 * @complexity O(1) average - fixed string comparisons
 *
 * @see SocketCommon_resolve_address() which uses this for wildcard handling
 * @see Socket_bind() and Socket_connect() consumers
 */
const char *SocketCommon_normalize_wildcard_host (const char *host);

/**
 * @brief Extract and cache human-readable numeric address and port from
 * sockaddr structure.
 * @ingroup core_io
 *
 * Converts a binary sockaddr (from getsockname, getpeername, etc.) to numeric
 * string representation (IP:port) allocated from the provided arena. Uses
 * getnameinfo() with NI_NUMERICHOST and NI_NUMERICSERV flags for numeric-only
 * output (no reverse DNS).
 *
 * Purpose: Facilitates logging, metrics, debugging by providing string form of
 * endpoints without repeated formatting or temporary allocations. Arena
 * allocation ties lifetime to owning object (e.g., socket base).
 *
 * Supported families: AF_INET, AF_INET6, AF_UNIX (for Unix, addr_str may be
 * path, port=0). On failure, outputs unchanged, error logged via SocketLog,
 * errno not set.
 *
 * Edge cases:
 * - Invalid addr/addrlen: Logs error, returns -1
 * - Arena allocation fail: Returns -1, addr_out unchanged
 * - Unsupported family: getnameinfo fails, returns -1
 * - Unix domain: port=0, addr_str = socket path (if available)
 *
 * @param[in] arena Arena_T for allocating the address string copy. Must be
 * valid.
 * @param[in] addr const sockaddr* to format (IPv4, IPv6, Unix supported).
 * @param[in] addrlen socklen_t length of addr structure.
 * @param[out] addr_out char** set to arena-allocated numeric address string
 * (e.g., "127.0.0.1" or "[::1]"). Unchanged on failure. Caller does not free -
 * arena-managed.
 * @param[out] port_out int* set to extracted port number (host byte order, 0
 * if not available e.g., Unix).
 *
 * @return 0 on success (outputs populated), -1 on failure (getnameinfo or
 * alloc error). On failure, error details logged via SOCKET_ERROR_MSG; check
 * Socket_GetLastError().
 *
 * @throws None - returns error code instead of raising.
 *
 * @threadsafe Yes - local buffers, getnameinfo thread-safe on modern systems.
 *
 * ## Usage Example (After getsockname)
 *
 * @code{.c}
 * struct sockaddr_storage local_addr;
 * socklen_t len = sizeof(local_addr);
 * getsockname(fd, (struct sockaddr*)&local_addr, &len);
 *
 * char *cached_addr;
 * int cached_port;
 * if (SocketCommon_cache_endpoint(arena, (struct sockaddr*)&local_addr, len,
 *                                 &cached_addr, &cached_port) == 0) {
 *     SOCKET_LOG_INFO_MSG("Bound to %s:%d", cached_addr, cached_port);
 *     // cached_addr lifetime = arena
 * } else {
 *     SOCKET_LOG_WARN_MSG("Failed to cache local endpoint");
 * }
 * @endcode
 *
 * ## Peer Address Caching
 *
 * @code{.c}
 * // After accept or connect
 * struct sockaddr_storage peer;
 * socklen_t peer_len = sizeof(peer);
 * getpeername(sock_fd, (struct sockaddr*)&peer, &peer_len);
 * char *peer_ip;
 * int peer_port;
 * SocketCommon_cache_endpoint(SocketBase_arena(base), (struct sockaddr*)&peer,
 * peer_len, &peer_ip, &peer_port);
 * // Use for logging: "Peer %s:%d connected", peer_ip, peer_port
 * @endcode
 *
 * @note String format: IPv4 "x.x.x.x", IPv6 "[xxxx::xxxx]" per getnameinfo
 * numeric.
 * @note Port parsing from service string; fails gracefully to 0 if invalid.
 * @note For Unix domain, addr_str may be path up to NI_MAXHOST length.
 * @warning Buffers internally sized to NI_MAXHOST/NI_MAXSERV - truncation
 * possible but rare.
 *
 * @complexity O(1) - getnameinfo bounded time, arena alloc constant.
 *
 * @see getnameinfo(3) for numeric formatting details
 * @see SocketBase_T local/remote endpoint caching which uses this
 * @see Socket_getlocaladdr/port, Socket_getpeeraddr/port public wrappers
 * @see core/Arena.h for allocation management
 */
int SocketCommon_cache_endpoint (Arena_T arena,
                                 const struct sockaddr *addr,
                                 socklen_t addrlen,
                                 char **addr_out,
                                 int *port_out);

/**
 * @brief Set or clear the close-on-exec (CLOEXEC) flag on a file descriptor.
 * @ingroup core_io
 *
 * Modifies the FD_CLOEXEC file descriptor flag using fcntl(F_SETFD) to control
 * whether the file descriptor is automatically closed across execve() calls
 * (e.g., fork+exec).
 *
 * Enabling CLOEXEC (enable=1) is a security best practice to prevent
 * unintended FD leakage to child processes in multi-process applications.
 * Disabling (enable=0) is rarely needed but supported for compatibility.
 *
 * This function is called automatically after socket(), accept(), etc., to
 * ensure library sockets have CLOEXEC set by default (configurable via
 * SocketConfig).
 *
 * On failure, sets errno to EBADF (invalid fd) or EINVAL (invalid flag).
 *
 * @param[in] fd File descriptor to modify (must be valid open FD).
 * @param[in] enable Non-zero to set FD_CLOEXEC, 0 to clear it.
 *
 * @return 0 on success, -1 on failure (errno set).
 *
 * @throws None - uses return code/errno convention.
 *
 * @threadsafe Yes - fcntl operates on single FD atomically.
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Enable CLOEXEC on newly created socket FD
 * int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
 * if (SocketCommon_setcloexec(sock_fd, 1) < 0) {
 *     close(sock_fd);
 *     perror("Failed to set CLOEXEC");
 *     return -1;
 * }
 * // Now safe for exec after fork
 * @endcode
 *
 * ## Disable for Specific FD
 *
 * @code{.c}
 * // Rare: clear CLOEXEC (e.g., for FD passing)
 * SocketCommon_setcloexec(fd, 0);  // Allows FD to survive exec
 * @endcode
 *
 * @note Automatically called by library after socket creation for security
 * hardening.
 * @note Equivalent to fcntl(fd, F_SETFD, enable ? FD_CLOEXEC : 0)
 * @note On failure, check errno: EBADF invalid fd, EINVAL bad flag value.
 * @warning Always enable CLOEXEC unless FD inheritance is explicitly needed
 * (security risk).
 *
 * @complexity O(1) - single fcntl system call
 *
 * @see SocketCommon_has_cloexec() to query current flag state
 * @see fcntl(2) F_SETFD/F_GETFD for POSIX details
 * @see docs/SECURITY.md for FD leakage prevention best practices
 */
int SocketCommon_setcloexec (int fd, int enable);

/**
 * @brief Check if close-on-exec flag is set
 * @ingroup core_io
 * @param fd File descriptor to check
 * @return 1 if CLOEXEC is set, 0 if not set, -1 on error
 * @note Thread-safe: Yes (operates on single fd)
 */
int SocketCommon_has_cloexec (int fd);

/**
 * @brief Get integer socket option
 * @ingroup core_io
 * @param fd File descriptor
 * @param level Option level (SOL_SOCKET, IPPROTO_TCP, etc.)
 * @param optname Option name (SO_KEEPALIVE, TCP_NODELAY, etc.)
 * @param value Output pointer for option value
 * @param exception_type Exception type to raise on failure
 * @return 0 on success, -1 on failure
 * @throws Specified exception type on failure
 * @note Thread-safe: Yes (operates on single fd)
 */
int SocketCommon_getoption_int (
    int fd, int level, int optname, int *value, Except_T exception_type);

/**
 * @brief Get timeval socket option
 * @ingroup core_io
 * @param fd File descriptor
 * @param level Option level (SOL_SOCKET)
 * @param optname Option name (SO_RCVTIMEO, SO_SNDTIMEO)
 * @param tv Output pointer for timeval structure
 * @param exception_type Exception type to raise on failure
 * @return 0 on success, -1 on failure
 * @throws Specified exception type on failure
 * @note Thread-safe: Yes (operates on single fd)
 */
int SocketCommon_getoption_timeval (int fd,
                                    int level,
                                    int optname,
                                    struct timeval *tv,
                                    Except_T exception_type);

/**
 * @brief Perform reverse DNS lookup (getnameinfo wrapper)
 * @ingroup core_io
 * @param addr Socket address to look up
 * @param addrlen Length of socket address
 * @param host Output buffer for hostname (NULL to skip)
 * @param hostlen Size of host buffer
 * @param serv Output buffer for service/port (NULL to skip)
 * @param servlen Size of service buffer
 * @param flags getnameinfo flags (NI_NUMERICHOST, NI_NAMEREQD, etc.)
 * @param exception_type Exception type to raise on failure
 * @return 0 on success, -1 on failure
 * @throws Specified exception type on failure
 * @note Thread-safe: Yes
 * @note Wrapper around getnameinfo() for reverse DNS lookups.
 * @note Use NI_NUMERICHOST flag to get numeric IP address instead of hostname.
 */
int SocketCommon_reverse_lookup (const struct sockaddr *addr,
                                 socklen_t addrlen,
                                 char *host,
                                 socklen_t hostlen,
                                 char *serv,
                                 socklen_t servlen,
                                 int flags,
                                 Except_T exception_type);

/**
 * @brief Validate and parse IP address string
 * @ingroup core_io
 * @param ip_str IP address string to validate
 * @param family Output pointer for address family (AF_INET or AF_INET6), can
 * be NULL
 * @return 1 if valid IP address, 0 if invalid
 * @note Thread-safe: Yes
 * @note Validates both IPv4 and IPv6 addresses. Sets family to AF_INET for
 * IPv4, AF_INET6 for IPv6, or AF_UNSPEC if invalid.
 */
int SocketCommon_parse_ip (const char *ip_str, int *family);

/**
 * @brief Check if IP address matches CIDR range
 * @ingroup core_io
 * @param ip_str IP address string to check
 * @param cidr_str CIDR notation string (e.g., "192.168.1.0/24" or
 * "2001:db8::/32")
 * @return 1 if IP matches CIDR range, 0 if not, -1 on error
 * @note Thread-safe: Yes
 * @note Supports both IPv4 and IPv6 CIDR notation.
 * @note Returns -1 if IP or CIDR string is invalid.
 */
int SocketCommon_cidr_match (const char *ip_str, const char *cidr_str);

/**
 * @brief Opaque base structure for shared socket functionality.
 * @ingroup core_io
 *
 * Contains common fields shared across socket subtypes (Socket_T,
 * SocketDgram_T, etc.):
 * - File descriptor (fd)
 * - Memory arena for lifecycle management
 * - Local and remote endpoint information (addresses, ports)
 * - Timeouts configuration
 * - Metrics snapshot
 * - Domain, type, protocol
 *
 * Subtypes embed a pointer to SocketBase_T for shared resource management.
 * Allocation: Use SocketCommon_new_base() which creates arena and initializes.
 * Deallocation: Use SocketCommon_free_base() in reverse order.
 * Thread Safety: Individual fields not thread-safe; protect with external
 * mutexes if shared.
 *
 * Rationale: Reduces code duplication in creation, initialization, cleanup
 * across modules. Ensures consistent resource acquisition/cleanup order per
 * layered architecture rules.
 */
#define SocketBase_T SocketBase_T
typedef struct SocketBase_T *SocketBase_T;

/**
 * @brief Create a new socket base structure.
 * @ingroup core_io
 * @param domain Address family (AF_INET, AF_INET6, AF_UNIX).
 * @param type Socket type (SOCK_STREAM, SOCK_DGRAM).
 * @param protocol Protocol (usually 0 for default).
 * @return New socket base instance.
 * @throws SocketCommon_Failed on allocation failure.
 */
extern SocketBase_T SocketCommon_new_base (int domain, int type, int protocol);

/**
 * @brief Free a socket base structure.
 * @ingroup core_io
 * @param base_ptr Pointer to socket base (will be set to NULL).
 * @note Cleans up all resources associated with the socket base.
 */
extern void SocketCommon_free_base (SocketBase_T *base_ptr);

/**
 * @brief Set integer socket option
 * @ingroup core_io
 * @param base Base with fd
 * @param level Option level (SOL_SOCKET, IPPROTO_TCP, etc.)
 * @param optname Option name (SO_REUSEADDR, TCP_NODELAY, etc.)
 * @param value Value to set
 * @param exc_type Exception to raise on failure
 * @note Generic setter for standard socket options, unifies duplicated
 * setsockopt calls
 * @note Thread-safe: Yes for own resources
 */
extern void SocketCommon_set_option_int (
    SocketBase_T base, int level, int optname, int value, Except_T exc_type);

/**
 * @brief Set TTL or hop limit based on family
 * @ingroup core_io
 * @param base Base with fd
 * @param family AF_INET or AF_INET6
 * @param ttl TTL value
 * @param exc_type Raise on fail
 * @note Unifies set_ipv4_ttl and set_ipv6_hop_limit
 */
extern void SocketCommon_set_ttl (SocketBase_T base,
                                  int family,
                                  int ttl,
                                  Except_T exc_type);

/**
 * @brief Join multicast group
 * @ingroup core_io
 * @param base Socket base with fd (must be datagram for standard use)
 * @param group Multicast group string (e.g., "239.0.0.1" or "ff02::1")
 * @param interface Interface IP or NULL for default
 * @param exc_type Exception to raise on failure
 * @note Resolves group, joins via setsockopt based on family (IPv4/IPv6)
 * @note Handles resolution, interface setup, family-specific mreq
 * @note Thread-safe for own fd
 */
extern void SocketCommon_join_multicast (SocketBase_T base,
                                         const char *group,
                                         const char *interface,
                                         Except_T exc_type);

/**
 * @brief Leave multicast group
 * @ingroup core_io
 * @param base Socket base with fd
 * @param group Multicast group string
 * @param interface Interface IP or NULL
 * @param exc_type Exception to raise on failure
 * @note Symmetric to join; drops membership via setsockopt
 */
extern void SocketCommon_leave_multicast (SocketBase_T base,
                                          const char *group,
                                          const char *interface,
                                          Except_T exc_type);

/**
 * @brief Set non-blocking mode
 * @ingroup core_io
 * @param base Base with fd
 * @param enable True to enable non-block
 * @param exc_type Raise on fail
 * @note Unifies duplicated fcntl calls for O_NONBLOCK
 */
extern void
SocketCommon_set_nonblock (SocketBase_T base, bool enable, Except_T exc_type);

/**
 * @brief Calculate total length of iovec array with overflow protection
 * @ingroup core_io
 * @param iov Array of iovec structures
 * @param iovcnt Number of iovec structures (>0, <=IOV_MAX)
 * @return Total bytes across all iov_len
 * @throws SocketCommon_Failed on integer overflow during summation
 * @note Thread-safe: Yes
 * @note Unifies duplicated calculation loops across modules
 */
extern size_t
SocketCommon_calculate_total_iov_len (const struct iovec *iov, int iovcnt);

/**
 * @brief Validate iovec array base pointers are non-NULL for positive lengths
 * @ingroup core_io
 * @param iov Array of iovec structures to validate
 * @param iovcnt Number of iovec structures
 * @throws SocketCommon_Failed if any iov_base is NULL with positive iov_len
 * @note Thread-safe: Yes (read-only validation)
 * @note Unifies duplicated NULL validation in SocketIO sendv/recvv operations
 */
extern void
SocketCommon_validate_iov_bases (const struct iovec *iov, int iovcnt);

/**
 * @brief Advance iovec array past sent/received bytes (modifies in place)
 * @ingroup core_io
 * @param iov Array of iovec structures to advance
 * @param iovcnt Number of iovec structures
 * @param bytes Bytes to advance (must <= total iov len)
 * @note Behavior: Sets advanced iovs to len=0/base=NULL, partial to offset/len
 * reduced
 * @throws SocketCommon_Failed if bytes > total iov len or invalid params
 * @note Thread-safe: Yes (local ops)
 * @note Unifies duplicated advance logic for sendvall/recvvall
 */
extern void
SocketCommon_advance_iov (struct iovec *iov, int iovcnt, size_t bytes);

/**
 * @brief Find first non-empty iovec in array
 * @ingroup core_io
 * @param iov Array of iovec structures to search
 * @param iovcnt Number of iovec structures
 * @param active_iovcnt Output for count of remaining iovecs from active
 * position
 * @return Pointer to first iovec with iov_len > 0, or NULL if all empty
 * @note Thread-safe: Yes (read-only operation)
 * @note Used by sendvall/recvvall to find the next active buffer segment after
 * partial I/O operations have consumed some of the iovec array.
 */
extern struct iovec *SocketCommon_find_active_iov (struct iovec *iov,
                                                   int iovcnt,
                                                   int *active_iovcnt);

/**
 * @brief Sync original iovec with working copy progress
 * @ingroup core_io
 * @param original Original iovec array to update
 * @param copy Working copy that has been advanced
 * @param iovcnt Number of iovec structures
 * @note Updates the original iovec array to reflect progress made in the copy.
 * @note Used when recvvall needs to update caller's iovec on partial
 * completion.
 * @note Thread-safe: Yes (local ops)
 */
extern void SocketCommon_sync_iov_progress (struct iovec *original,
                                            const struct iovec *copy,
                                            int iovcnt);

/**
 * @brief Allocate and copy iovec array
 * @ingroup core_io
 * @param iov Source iovec array to copy
 * @param iovcnt Number of iovec structures (>0, <=IOV_MAX)
 * @param exc_type Exception type to raise on allocation failure
 * @return Newly allocated copy of iovec array (caller must free)
 * @throws exc_type on allocation failure
 * @note Thread-safe: Yes
 * @note Common helper for sendvall/recvvall implementations. Consolidates
 * duplicate calloc+memcpy patterns across Socket and SocketDgram modules.
 */
extern struct iovec *SocketCommon_alloc_iov_copy (const struct iovec *iov,
                                                  int iovcnt,
                                                  Except_T exc_type);

/**
 * @brief Set close-on-exec flag on fd (unifies dups)
 * @ingroup core_io
 * @param fd File descriptor
 * @param enable True to enable FD_CLOEXEC
 * @param exc_type Raise on fail
 * @note Uses fcntl F_SETFD; called after socket()/socketpair()/accept()
 * fallback
 */
extern void
SocketCommon_set_cloexec_fd (int fd, bool enable, Except_T exc_type);

/**
 * @brief Try bind fd to address (extracted from Socket.c)
 * @ingroup core_io
 * @param base Socket base with fd
 * @param addr Address to bind
 * @param addrlen Addr length
 * @param exc_type Raise on fail
 * @return 0 success, -1 fail (raises on error)
 * @note Integrates with base endpoints if success (caller handles)
 */
extern int SocketCommon_try_bind_address (SocketBase_T base,
                                          const struct sockaddr *addr,
                                          socklen_t addrlen,
                                          Except_T exc_type);

/**
 * @brief Try bind to resolved addrinfo list
 * @ingroup core_io
 * @param base Socket base with fd
 * @param res addrinfo list from resolve
 * @param family Preferred family (AF_INET etc)
 * @param exc_type Raise on all fails
 * @return 0 success (bound to first successful), -1 fail
 * @note Loops addresses, calls try_bind_address, sets base local endpoint on
 * success
 * @note Handles dual-stack, reuseaddr hints via set_option_int
 */
extern int SocketCommon_try_bind_resolved_addresses (SocketBase_T base,
                                                     struct addrinfo *res,
                                                     int family,
                                                     Except_T exc_type);

/**
 * @brief Log and raise bind error
 * @ingroup core_io
 * @param err errno from bind
 * @param addr_str Addr string for log
 * @param exc_type Type to raise
 * @note Graceful for non-fatal (e.g., EADDRINUSE log warn return -1), fatal
 * raise
 */
extern int SocketCommon_handle_bind_error (int err,
                                           const char *addr_str,
                                           Except_T exc_type);

/**
 * @brief Format descriptive bind error message
 * @ingroup core_io
 * @param host Host string (NULL defaults to "any")
 * @param port Port number
 * @note Formats error in socket_error_buf based on errno (EADDRINUSE, EACCES,
 * etc.)
 * @note Consolidated helper for Socket and SocketDgram bind error handling.
 * @note Does not raise - caller should raise after calling this.
 */
extern void SocketCommon_format_bind_error (const char *host, int port);

/**
 * @brief Update local endpoint information from getsockname.
 * @ingroup core_io
 * @param base Socket base to update.
 * @note Non-raising helper for updating local address/port after bind.
 */
extern void SocketCommon_update_local_endpoint (SocketBase_T base);

/**
 * @brief Get socket's address family
 * @ingroup core_io
 * @param base Socket base to query
 * @return Socket family or AF_UNSPEC on error
 * @note Uses SO_DOMAIN on Linux, falls back to getsockname() on other
 * platforms.
 */
extern int SocketCommon_get_socket_family (SocketBase_T base);

/**
 * @brief Validate host is not NULL
 * @ingroup core_io
 * @param host Host string to validate
 * @param exception_type Exception type to raise on NULL host
 * @throws Specified exception type if host is NULL
 * @note Thread-safe: Yes
 */
extern void
SocketCommon_validate_host_not_null (const char *host, Except_T exception_type);

/**
 * @brief Deep copy of addrinfo linked list
 * @ingroup core_io
 * @param src Source chain to copy (may be NULL)
 * @return malloc-allocated deep copy, or NULL on error
 * @note Deep copies the entire chain including ai_addr and ai_canonname
 * fields.
 * @note Caller takes ownership and MUST free with
 * SocketCommon_free_addrinfo().
 * @note Do NOT use freeaddrinfo() on the result - it's undefined behavior.
 * @note No exceptions raised; returns NULL on malloc failure or src==NULL.
 * @note Thread-safe: Yes
 */
extern struct addrinfo *SocketCommon_copy_addrinfo (const struct addrinfo *src);

/**
 * @brief Free addrinfo chain created by copy_addrinfo
 * @ingroup core_io
 * @param ai Chain to free (may be NULL, safe no-op)
 * @note Frees all nodes in the chain including ai_addr and ai_canonname
 * fields.
 * @note Use this instead of freeaddrinfo() for chains from
 * SocketCommon_copy_addrinfo.
 * @note Thread-safe: Yes
 */
extern void SocketCommon_free_addrinfo (struct addrinfo *ai);

/**
 * @brief Clear O_NONBLOCK flag on a raw file descriptor.
 * @ingroup core_io
 *
 * Unconditionally clears the O_NONBLOCK flag, restoring blocking mode.
 * Operates on a raw int fd without requiring SocketBase_T or saved
 * original flags. Intended for cleanup contexts where the high-level
 * socket wrapper is unavailable.
 *
 * @param[in] fd File descriptor to modify (must be valid open FD).
 * @return 0 on success, -1 on failure (errno set by fcntl).
 * @throws None - uses return code/errno convention.
 * @threadsafe Yes - fcntl operates on single FD.
 * @see SocketCommon_set_nonblock() for SocketBase_T variant with exceptions.
 * @see socket_common_restore_blocking_mode() for variant that restores
 * original flags.
 */
int SocketCommon_clear_nonblock (int fd);

/**
 * @brief Initialize a struct pollfd in one statement.
 * @ingroup core_io
 *
 * Replaces the common pattern of manually setting .fd, .events, .revents
 * fields on a struct pollfd. Ensures .revents is zeroed.
 *
 * @param pfd   The struct pollfd variable (not a pointer).
 * @param _fd   File descriptor value.
 * @param _ev   Events mask (POLLIN, POLLOUT, etc.).
 */
#define SOCKET_INIT_POLLFD(pfd, _fd, _ev) \
  do                                      \
    {                                     \
      (pfd).fd = (_fd);                   \
      (pfd).events = (_ev);               \
      (pfd).revents = 0;                  \
    }                                     \
  while (0)

/* Internal helpers defined in SocketCommon-private.h for module use
 * (getters/setters for base fields) */

/* Extern globals for shared defaults - defined in SocketCommon.c */

/**
 * @brief Global default timeout configuration for socket operations.
 * @ingroup core_io
 * @var socket_default_timeouts
 * @note Internal global variable.
 * @note Thread-safe access via SocketCommon_timeouts_getdefaults() and
 * SocketCommon_timeouts_setdefaults().
 * @note Modified only through public setter functions.
 * @see SocketCommon_timeouts_getdefaults()
 * @see SocketCommon_timeouts_setdefaults()
 */
extern SocketTimeouts_T socket_default_timeouts;

/**
 * @brief Mutex protecting the global default timeouts variable.
 * @ingroup core_io
 * @var socket_default_timeouts_mutex
 * @note Internal synchronization primitive.
 * @note Ensures thread-safe modification and reading of
 * socket_default_timeouts.
 * @warning Do not use directly - use the provided getter/setter functions.
 */
extern pthread_mutex_t socket_default_timeouts_mutex;

/**
 * @brief Get global default timeouts
 * @ingroup core_io
 * @param timeouts Output pointer for timeout structure
 * @note Thread-safe: Yes (uses mutex protection)
 */
extern void SocketCommon_timeouts_getdefaults (SocketTimeouts_T *timeouts);

/**
 * @brief Set global default timeouts
 * @ingroup core_io
 * @param timeouts Timeout values to set as defaults
 * @note Thread-safe: Yes (uses mutex protection)
 */
extern void
SocketCommon_timeouts_setdefaults (const SocketTimeouts_T *timeouts);

/* ==================== Socket State Helpers ==================== */

/**
 * @brief Check if IPv4 socket is bound
 * @ingroup core_io
 * @param addr sockaddr_storage containing address
 * @return 1 if bound (port != 0), 0 otherwise
 */
static inline int
SocketCommon_check_bound_ipv4 (const struct sockaddr_storage *addr)
{
  const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
  return sin->sin_port != 0;
}

/**
 * @brief Check if IPv6 socket is bound
 * @ingroup core_io
 * @param addr sockaddr_storage containing address
 * @return 1 if bound (port != 0), 0 otherwise
 */
static inline int
SocketCommon_check_bound_ipv6 (const struct sockaddr_storage *addr)
{
  const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
  return sin6->sin6_port != 0;
}

/**
 * @brief Check if Unix socket is bound
 * @ingroup core_io
 * @param addr sockaddr_storage containing address (unused)
 * @return 1 (Unix domain sockets are bound if getsockname succeeds)
 */
static inline int
SocketCommon_check_bound_unix (const struct sockaddr_storage *addr)
{
  (void)addr; /* Suppress unused parameter warning */
  return 1;   /* Unix domain sockets are bound if getsockname succeeds */
}

/**
 * @brief Check if socket is bound based on family
 * @ingroup core_io
 * @param addr sockaddr_storage containing address
 * @return 1 if bound, 0 otherwise
 */
static inline int
SocketCommon_check_bound_by_family (const struct sockaddr_storage *addr)
{
  if (addr->ss_family == AF_INET)
    return SocketCommon_check_bound_ipv4 (addr);
  else if (addr->ss_family == AF_INET6)
    return SocketCommon_check_bound_ipv6 (addr);
  else if (addr->ss_family == AF_UNIX)
    return SocketCommon_check_bound_unix (addr);
  return 0;
}

/* ============================================================================
 * Live Socket Count Tracking
 * ============================================================================
 */

/**
 * @brief Thread-safe live count tracker for socket instances.
 * @ingroup core_io
 *
 * Provides thread-safe increment/decrement operations for tracking live
 * socket instances. Used by both Socket_T and SocketDgram_T implementations
 * for debugging and leak detection.
 *
 * @see Socket_debug_live_count() for querying the count.
 */
struct SocketLiveCount
{
  int count;
  pthread_mutex_t mutex;
};

/**
 * @brief Static initializer for SocketLiveCount structure.
 * @ingroup core_io
 *
 * Initializes the count to 0 and the mutex to the default unlocked state
 * using PTHREAD_MUTEX_INITIALIZER.
 *
 * Usage:
 *   static struct SocketLiveCount tracker = SOCKETLIVECOUNT_STATIC_INIT;
 *
 * @see struct SocketLiveCount for field details.
 * @see SocketLiveCount_increment(), SocketLiveCount_decrement() for usage.
 */
#define SOCKETLIVECOUNT_STATIC_INIT \
  {                                 \
    0, PTHREAD_MUTEX_INITIALIZER    \
  }

/**
 * @brief Increment live count (thread-safe)
 * @ingroup core_io
 * @param tracker Live count tracker
 */
static inline void
SocketLiveCount_increment (struct SocketLiveCount *tracker)
{
  pthread_mutex_lock (&tracker->mutex);
  tracker->count++;
  pthread_mutex_unlock (&tracker->mutex);
}

/**
 * @brief Decrement live count (thread-safe)
 * @ingroup core_io
 * @param tracker Live count tracker
 */
static inline void
SocketLiveCount_decrement (struct SocketLiveCount *tracker)
{
  pthread_mutex_lock (&tracker->mutex);
  if (tracker->count > 0)
    tracker->count--;
  pthread_mutex_unlock (&tracker->mutex);
}

/**
 * @brief Get current live count (thread-safe)
 * @ingroup core_io
 * @param tracker Live count tracker
 * @return Current count value
 */
static inline int
SocketLiveCount_get (struct SocketLiveCount *tracker)
{
  int count;
  pthread_mutex_lock (&tracker->mutex);
  count = tracker->count;
  pthread_mutex_unlock (&tracker->mutex);
  return count;
}

/*
 * =============================================================================
 * Global DNS Resolution Configuration
 *
 * These functions configure the global DNS resolver used by Socket_bind(),
 * Socket_connect(), SocketDgram_bind(), and SocketDgram_connect(). The global
 * resolver provides timeout guarantees for all DNS operations.
 * =============================================================================
 */

/* Forward declaration - full type in SocketDNS.h */

/**
 * @brief Opaque handle for asynchronous DNS resolver.
 * @ingroup core_io
 *
 * Used by global DNS configuration functions for timeout guarantees
 * in socket operations like bind() and connect().
 *
 * Full API documentation in SocketDNS.h.
 *
 * @see SocketDNS.h for complete DNS resolution API.
 * @see SocketCommon_get_dns_resolver() for accessing the global instance.
 */
typedef struct SocketDNS_T *SocketDNS_T;

/**
 * @brief Get global DNS resolver instance
 * @ingroup core_io
 * @return Global DNS resolver (lazily initialized on first call)
 * @note Thread-safe: Yes - uses pthread_once for initialization
 * @note The global DNS resolver is shared across all Socket and SocketDgram
 * operations. It provides timeout guarantees for DNS resolution.
 */
extern SocketDNS_T SocketCommon_get_dns_resolver (void);

/**
 * @brief Set global DNS resolution timeout
 * @ingroup core_io
 * @param timeout_ms Timeout in milliseconds (0 = infinite, -1 = use default)
 * @note Thread-safe: Yes - protected by mutex
 * @note Affects all subsequent hostname resolution via Socket/SocketDgram
 * APIs.
 * @note Default: SOCKET_DEFAULT_DNS_TIMEOUT_MS (5000ms)
 * @note Setting timeout_ms to 0 disables timeout (infinite wait).
 * @note Setting timeout_ms to -1 resets to default.
 */
extern void SocketCommon_set_dns_timeout (int timeout_ms);

/**
 * @brief Get current global DNS timeout
 * @ingroup core_io
 * @return Current timeout in milliseconds (0 = infinite)
 * @note Thread-safe: Yes
 */
extern int SocketCommon_get_dns_timeout (void);

/**
 * @brief Wait for a file descriptor to be ready for I/O with timeout
 * @ingroup core_io
 *
 * Polls a file descriptor for readiness (read or write) with an optional
 * timeout. Automatically retries on EINTR interruption. This is a utility
 * function commonly used for implementing timeout-based socket operations.
 *
 * Purpose: Provides a reusable mechanism for waiting on file descriptors
 * with timeout support, eliminating code duplication across timeout-based
 * I/O operations in Socket and SocketDgram modules.
 *
 * Edge cases:
 * - timeout_ms == 0: Returns 1 immediately (no wait, proceed immediately)
 * - timeout_ms < 0: Blocks indefinitely until ready or error
 * - timeout_ms > 0: Waits up to timeout_ms milliseconds
 * - EINTR: Automatically retries poll() call
 * - POLLERR/POLLHUP/POLLNVAL: Returns -1 (error condition)
 *
 * @param[in] fd File descriptor to poll (must be valid).
 * @param[in] events Poll events mask (POLLIN for read, POLLOUT for write).
 * @param[in] timeout_ms Timeout in milliseconds:
 *                       - 0 = no wait (return immediately)
 *                       - -1 = block indefinitely
 *                       - >0 = wait up to this many milliseconds
 *
 * @return 1 if fd is ready for requested operation,
 *         0 if timeout occurred (no events within timeout_ms),
 *         -1 on error (poll failure or POLLERR/POLLHUP/POLLNVAL detected).
 *
 * @throws None - returns error code instead of raising.
 *
 * @threadsafe Yes - uses local variables only, poll(2) is thread-safe.
 *
 * ## Usage Example (Timeout-based send)
 *
 * @code{.c}
 * int fd = socket(AF_INET, SOCK_STREAM, 0);
 * int ready = SocketCommon_wait_for_fd(fd, POLLOUT, 5000); // 5 sec timeout
 * if (ready == 1) {
 *     ssize_t sent = send(fd, buf, len, 0);
 *     // Process send result
 * } else if (ready == 0) {
 *     // Timeout - socket not ready for write
 * } else {
 *     // Error during poll
 * }
 * @endcode
 *
 * ## Usage Example (Indefinite wait)
 *
 * @code{.c}
 * // Block until readable or error
 * int ready = SocketCommon_wait_for_fd(fd, POLLIN, -1);
 * if (ready < 0) {
 *     perror("poll failed");
 * } else {
 *     ssize_t n = recv(fd, buf, sizeof(buf), 0);
 * }
 * @endcode
 *
 * @note This function does NOT set errno. Check return value only.
 * @note For timeout_ms == 0, always returns 1 (no actual polling).
 * @note EINTR handling ensures robust behavior in signal-heavy environments.
 *
 * @complexity O(1) - single poll() system call (retried on EINTR).
 *
 * @see poll(2) for low-level polling semantics
 * @see Socket_sendall_timeout() for usage in timeout-based operations
 * @see Socket_recvall_timeout() for usage in timeout-based operations
 */
extern int SocketCommon_wait_for_fd (int fd, short events, int timeout_ms);

/**
 * @brief Convert DNS resolver result to addrinfo linked list
 * @ingroup core_io
 *
 * Creates a POSIX addrinfo chain from DNS resolver results for compatibility
 * with existing address iteration code. Uses a custom allocation pattern
 * where sockaddr is embedded in the same block as addrinfo.
 *
 * This function handles both IPv4 (AF_INET) and IPv6 (AF_INET6) addresses,
 * skipping any unsupported address families. The port is set in network byte
 * order (htons). Overflow validation is performed when allocating the combined
 * addrinfo+sockaddr structure.
 *
 * @param[in] result DNS resolver result containing addresses (may be NULL or
 * empty). Type: const SocketDNSResolver_Result* from dns/SocketDNSResolver.h
 * @param[in] port Port number in host byte order to set in each sockaddr
 *
 * @return Newly allocated addrinfo chain (caller must free with
 * SocketCommon_free_resolver_addrinfo), or NULL if result is NULL/empty or
 * allocation fails
 *
 * @throws None - returns NULL on allocation failure
 *
 * @threadsafe Yes - no shared state
 *
 * ## Usage Example
 *
 * @code{.c}
 * #include "dns/SocketDNSResolver.h"
 * SocketDNSResolver_Result result;
 * // ... populate result from DNS resolver ...
 * struct addrinfo *ai = SocketCommon_resolver_to_addrinfo(&result, 80);
 * if (ai) {
 *     // Use addrinfo chain for connection attempts
 *     for (struct addrinfo *rp = ai; rp; rp = rp->ai_next) {
 *         int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
 *         // ... connect using rp->ai_addr ...
 *     }
 *     SocketCommon_free_resolver_addrinfo(ai);
 * }
 * @endcode
 *
 * @note Must be freed with SocketCommon_free_resolver_addrinfo(), NOT
 * freeaddrinfo()
 * @note Sockaddr is embedded in addrinfo allocation, requiring single free
 * @note Returns NULL for empty result (count=0) - not an error
 * @note Requires dns/SocketDNSResolver.h to be included for type definition
 *
 * @complexity O(n) where n is result->count
 *
 * @see SocketCommon_free_resolver_addrinfo() for cleanup
 * @see SocketHappyEyeballs for usage in connection racing
 * @see dns/SocketDNSResolver.h for SocketDNSResolver_Result type
 */
extern struct addrinfo *
SocketCommon_resolver_to_addrinfo (const void *result, int port);

/**
 * @brief Free addrinfo list created by SocketCommon_resolver_to_addrinfo
 * @ingroup core_io
 *
 * Frees an addrinfo chain created by SocketCommon_resolver_to_addrinfo. Uses
 * custom allocation pattern where sockaddr is embedded in the same allocation
 * as addrinfo, requiring single free per node instead of separate frees.
 *
 * Safe to call with NULL pointer (no-op).
 *
 * @param[in] ai Addrinfo chain to free (may be NULL)
 *
 * @return None (void function)
 *
 * @throws None
 *
 * @threadsafe Yes - no shared state
 *
 * ## Usage Example
 *
 * @code{.c}
 * struct addrinfo *ai = SocketCommon_resolver_to_addrinfo(&result, 443);
 * // ... use ai ...
 * SocketCommon_free_resolver_addrinfo(ai);  // Safe even if ai is NULL
 * @endcode
 *
 * @note Do NOT use freeaddrinfo() on chains from
 * SocketCommon_resolver_to_addrinfo
 * @note NULL-safe - calling with NULL is valid and does nothing
 *
 * @complexity O(n) where n is chain length
 *
 * @see SocketCommon_resolver_to_addrinfo() for allocation
 */
extern void SocketCommon_free_resolver_addrinfo (struct addrinfo *ai);

/**
 * @brief Shutdown global resources (e.g., DNS resolver) to prevent leaks in
 * tests
 * @ingroup core_io
 * Call at program exit after all operations complete.
 * @threadsafe Yes - but call from main thread only.
 * @note Frees global DNS resolver and other static resources.
 */
extern void SocketCommon_shutdown_globals (void);

#endif /* SOCKETCOMMON_INCLUDED */
