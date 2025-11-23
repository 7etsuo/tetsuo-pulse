#ifndef SOCKETCOMMON_INCLUDED
#define SOCKETCOMMON_INCLUDED

#include <stdbool.h>

/**
 * SocketCommon.h - Common utilities shared between Socket and SocketDgram
 * modules
 */

#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include "core/Arena.h"

#include "core/Except.h"
#include <stdbool.h>
#include "core/SocketConfig.h"  /* Defines SocketTimeouts_T */

/* Common exception types (Except_T is defined in Except.h) */
extern const Except_T Socket_Failed;
extern const Except_T SocketDgram_Failed;

/**
 * SocketCommon_setup_hints - Initialize addrinfo hints structure
 * @hints: Hints structure to initialize
 * @socktype: Socket type (SOCK_STREAM or SOCK_DGRAM)
 * @flags: Additional flags (0 for connect/sendto, AI_PASSIVE for bind)
 */
void SocketCommon_setup_hints (struct addrinfo *hints, int socktype,
                               int flags);

/**
 * SocketCommon_resolve_address - Resolve hostname/port to addrinfo structure
 * @host: Hostname or IP address (NULL for wildcard)
 * @port: Port number (1 to SOCKET_MAX_PORT)
 * @hints: Addrinfo hints structure
 * @res: Output pointer to resolved addrinfo
 * @exception_type: Exception type to raise on failure
 * @socket_family: Socket family to match (AF_UNSPEC if none)
 * @use_exceptions: If true, raise exceptions; if false, return error codes
 * Returns: 0 on success, -1 on failure (if not using exceptions)
 * Raises: Specified exception type on failure (if using exceptions)
 */
int SocketCommon_resolve_address (const char *host, int port,
                                  const struct addrinfo *hints,
                                  struct addrinfo **res,
                                  Except_T exception_type, int socket_family,
                                  int use_exceptions);

/**
 * SocketCommon_validate_port - Validate port number is in valid range
 * @port: Port number to validate
 * @exception_type: Exception type to raise on invalid port
 * Raises: Specified exception type if port is invalid
 */
void SocketCommon_validate_port (int port, Except_T exception_type);

/**
 * SocketCommon_validate_hostname - Validate hostname length
 * @host: Hostname to validate
 * @exception_type: Exception type to raise on invalid hostname
 * Raises: Specified exception type if hostname is too long
 */
void SocketCommon_validate_hostname (const char *host,
                                     Except_T exception_type);

/**
 * SocketCommon_normalize_wildcard_host - Normalize wildcard host addresses to
 * NULL
 * @host: Host string to normalize
 * Returns: NULL if wildcard ("0.0.0.0" or "::"), original host otherwise
 */
const char *SocketCommon_normalize_wildcard_host (const char *host);

/**
 * SocketCommon_cache_endpoint - Cache numeric address/port from sockaddr
 * @arena: Arena to allocate cached address string
 * @addr: Socket address to format
 * @addrlen: Length of socket address
 * @addr_out: Output pointer updated to arena-allocated address string
 * @port_out: Output integer updated with numeric port (0 if unavailable)
 * Returns: 0 on success, -1 on failure (addr_out unchanged on failure)
 */
int SocketCommon_cache_endpoint (Arena_T arena, const struct sockaddr *addr,
                                 socklen_t addrlen, char **addr_out,
                                 int *port_out);

/**
 * SocketCommon_setcloexec - Set close-on-exec flag on file descriptor
 * @fd: File descriptor to modify
 * @enable: 1 to enable CLOEXEC, 0 to disable
 * Returns: 0 on success, -1 on failure
 * Thread-safe: Yes (operates on single fd)
 */
int SocketCommon_setcloexec (int fd, int enable);

/**
 * SocketCommon_has_cloexec - Check if close-on-exec flag is set
 * @fd: File descriptor to check
 * Returns: 1 if CLOEXEC is set, 0 if not set, -1 on error
 * Thread-safe: Yes (operates on single fd)
 */
int SocketCommon_has_cloexec (int fd);

/**
 * SocketCommon_getoption_int - Get integer socket option
 * @fd: File descriptor
 * @level: Option level (SOL_SOCKET, IPPROTO_TCP, etc.)
 * @optname: Option name (SO_KEEPALIVE, TCP_NODELAY, etc.)
 * @value: Output pointer for option value
 * @exception_type: Exception type to raise on failure
 * Returns: 0 on success, -1 on failure
 * Raises: Specified exception type on failure
 * Thread-safe: Yes (operates on single fd)
 */
int SocketCommon_getoption_int (int fd, int level, int optname, int *value,
                                Except_T exception_type);

/**
 * SocketCommon_getoption_timeval - Get timeval socket option
 * @fd: File descriptor
 * @level: Option level (SOL_SOCKET)
 * @optname: Option name (SO_RCVTIMEO, SO_SNDTIMEO)
 * @tv: Output pointer for timeval structure
 * @exception_type: Exception type to raise on failure
 * Returns: 0 on success, -1 on failure
 * Raises: Specified exception type on failure
 * Thread-safe: Yes (operates on single fd)
 */
int SocketCommon_getoption_timeval (int fd, int level, int optname,
                                    struct timeval *tv,
                                    Except_T exception_type);

/**
 * SocketCommon_reverse_lookup - Perform reverse DNS lookup (getnameinfo
 * wrapper)
 * @addr: Socket address to look up
 * @addrlen: Length of socket address
 * @host: Output buffer for hostname (NULL to skip)
 * @hostlen: Size of host buffer
 * @serv: Output buffer for service/port (NULL to skip)
 * @servlen: Size of service buffer
 * @flags: getnameinfo flags (NI_NUMERICHOST, NI_NAMEREQD, etc.)
 * @exception_type: Exception type to raise on failure
 * Returns: 0 on success, -1 on failure
 * Raises: Specified exception type on failure
 * Thread-safe: Yes
 * Note: Wrapper around getnameinfo() for reverse DNS lookups.
 * Use NI_NUMERICHOST flag to get numeric IP address instead of hostname.
 */
int SocketCommon_reverse_lookup (const struct sockaddr *addr,
                                 socklen_t addrlen, char *host,
                                 socklen_t hostlen, char *serv,
                                 socklen_t servlen, int flags,
                                 Except_T exception_type);

/**
 * SocketCommon_parse_ip - Validate and parse IP address string
 * @ip_str: IP address string to validate
 * @family: Output pointer for address family (AF_INET or AF_INET6), can be
 * NULL Returns: 1 if valid IP address, 0 if invalid Thread-safe: Yes Note:
 * Validates both IPv4 and IPv6 addresses. Sets family to AF_INET for IPv4,
 * AF_INET6 for IPv6, or AF_UNSPEC if invalid.
 */
int SocketCommon_parse_ip (const char *ip_str, int *family);

/**
 * SocketCommon_cidr_match - Check if IP address matches CIDR range
 * @ip_str: IP address string to check
 * @cidr_str: CIDR notation string (e.g., "192.168.1.0/24" or "2001:db8::/32")
 * Returns: 1 if IP matches CIDR range, 0 if not, -1 on error
 * Thread-safe: Yes
 * Note: Supports both IPv4 and IPv6 CIDR notation.
 * Returns -1 if IP or CIDR string is invalid.
 */
int SocketCommon_cidr_match (const char *ip_str, const char *cidr_str);

/**
 * SocketBase_T - Opaque base structure for shared socket functionality
 *
 * Contains common fields shared across socket subtypes (Socket_T, SocketDgram_T, etc.):
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
 * Thread Safety: Individual fields not thread-safe; protect with external mutexes if shared.
 * 
 * Rationale: Reduces code duplication in creation, initialization, cleanup across modules.
 * Ensures consistent resource acquisition/cleanup order per layered architecture rules.
 */
#define SocketBase_T SocketBase_T
typedef struct SocketBase_T *SocketBase_T;

extern SocketBase_T SocketCommon_new_base (int domain, int type, int protocol);
extern void SocketCommon_free_base (SocketBase_T *base);

/**
 * SocketCommon_set_option_int - Set integer socket option
 * @base: Base with fd
 * @level: Option level (SOL_SOCKET, IPPROTO_TCP, etc.)
 * @optname: Option name (SO_REUSEADDR, TCP_NODELAY, etc.)
 * @value: Value to set
 * @exc_type: Exception to raise on failure
 * Generic setter for standard socket options, unifies duplicated setsockopt calls
 * Thread-safe: Yes for own resources
 */
extern void SocketCommon_set_option_int (SocketBase_T base, int level, int optname, int value, Except_T exc_type);

/**
 * SocketCommon_set_ttl - Set TTL or hop limit based on family
 * @base: Base with fd
 * @family: AF_INET or AF_INET6
 * @ttl: TTL value
 * @exc_type: Raise on fail
 * Unifies set_ipv4_ttl and set_ipv6_hop_limit
 */
extern void SocketCommon_set_ttl (SocketBase_T base, int family, int ttl, Except_T exc_type);

/**
 * SocketCommon_set_nonblock - Set non-blocking mode
 * @base: Base with fd
 * @enable: True to enable non-block
 * @exc_type: Raise on fail
 * Unifies duplicated fcntl calls for O_NONBLOCK
 */
extern void SocketCommon_set_nonblock (SocketBase_T base, bool enable, Except_T exc_type);

/**
 * SocketCommon_calculate_total_iov_len - Calculate total length of iovec array with overflow protection
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures (>0, <=IOV_MAX)
 * @returns: Total bytes across all iov_len
 * Raises: SocketCommon_Failed on integer overflow during summation
 * Thread-safe: Yes
 * Unifies duplicated calculation loops across modules
 */
extern size_t SocketCommon_calculate_total_iov_len (const struct iovec *iov, int iovcnt);

/**
 * SocketCommon_advance_iov - Advance iovec array past sent/received bytes (modifies in place)
 * @iov: Array of iovec structures to advance
 * @iovcnt: Number of iovec structures
 * @bytes: Bytes to advance (must <= total iov len)
 * Behavior: Sets advanced iovs to len=0/base=NULL, partial to offset/len reduced
 * Raises: SocketCommon_Failed if bytes > total iov len or invalid params
 * Thread-safe: Yes (local ops)
 * Unifies duplicated advance logic for sendvall/recvvall
 */
extern void SocketCommon_advance_iov (struct iovec *iov, int iovcnt, size_t bytes);

/**
 * SocketCommon_set_cloexec_fd - Set close-on-exec flag on fd (unifies dups)
 * @fd: File descriptor
 * @enable: True to enable FD_CLOEXEC
 * @exc_type: Raise on fail
 * Uses fcntl F_SETFD; called after socket()/socketpair()/accept() fallback
 */
extern void SocketCommon_set_cloexec_fd (int fd, bool enable, Except_T exc_type);

/**
 * SocketCommon_try_bind_address - Try bind fd to address (extracted from Socket.c)
 * @base: Socket base with fd
 * @addr: Address to bind
 * @addrlen: Addr length
 * @exc_type: Raise on fail
 * Returns: 0 success, -1 fail (raises on error)
 * Integrates with base endpoints if success (caller handles)
 */
extern int SocketCommon_try_bind_address (SocketBase_T base, const struct sockaddr *addr, socklen_t addrlen, Except_T exc_type);

/**
 * SocketCommon_try_bind_resolved_addresses - Try bind to resolved addrinfo list
 * @base: Socket base with fd
 * @res: addrinfo list from resolve
 * @family: Preferred family (AF_INET etc)
 * @exc_type: Raise on all fails
 * Returns: 0 success (bound to first successful), -1 fail
 * Loops addresses, calls try_bind_address, sets base local endpoint on success
 * Handles dual-stack, reuseaddr hints via set_option_int
 */
extern int SocketCommon_try_bind_resolved_addresses (SocketBase_T base, struct addrinfo *res, int family, Except_T exc_type);

/**
 * SocketCommon_handle_bind_error - Log and raise bind error
 * @err: errno from bind
 * @addr_str: Addr string for log
 * @exc_type: Type to raise
 * Graceful for non-fatal (e.g., EADDRINUSE log warn return -1), fatal raise
 */
extern int SocketCommon_handle_bind_error (int err, const char *addr_str, Except_T exc_type);

extern void SocketCommon_update_local_endpoint (SocketBase_T base); /* Common endpoint update, non-raising */

/**
 * SocketCommon_copy_addrinfo - Deep copy of addrinfo linked list
 * @src: Source chain to copy (may be NULL)
 * @return: malloc-allocated deep copy, or NULL on error
 *
 * Deep copies the entire chain including ai_addr and ai_canonname fields.
 * All allocations use malloc() for compatibility with freeaddrinfo().
 * Caller takes ownership and must free with freeaddrinfo() when done.
 * No exceptions raised; returns NULL on malloc failure or src==NULL.
 * Thread-safe: Yes
 */
extern struct addrinfo *SocketCommon_copy_addrinfo (const struct addrinfo *src);

/* Internal helpers defined in SocketCommon-private.h for module use (getters/setters for base fields) */

/* Extern globals for shared defaults - defined in SocketCommon.c */
extern SocketTimeouts_T socket_default_timeouts;
extern pthread_mutex_t socket_default_timeouts_mutex;

#endif /* SOCKETCOMMON_INCLUDED */
