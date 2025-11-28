#ifndef SOCKETCOMMON_INCLUDED
#define SOCKETCOMMON_INCLUDED

#include <stdbool.h>
#include <pthread.h>

/**
 * SocketCommon.h - Common utilities shared between Socket and SocketDgram
 * modules
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
#include "core/SocketConfig.h"  /* Defines SocketTimeouts_T */

/* Common exception types (Except_T is defined in Except.h) */
extern const Except_T Socket_Failed;
extern const Except_T SocketDgram_Failed;
extern const Except_T SocketCommon_Failed;

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
extern void SocketCommon_free_base (SocketBase_T *base_ptr);

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
 * SocketCommon_join_multicast - Join multicast group
 * @base: Socket base with fd (must be datagram for standard use)
 * @group: Multicast group string (e.g., "239.0.0.1" or "ff02::1")
 * @interface: Interface IP or NULL for default
 * @exc_type: Exception to raise on failure
 * Resolves group, joins via setsockopt based on family (IPv4/IPv6)
 * Handles resolution, interface setup, family-specific mreq
 * Thread-safe for own fd
 */
extern void SocketCommon_join_multicast (SocketBase_T base, const char *group, const char *interface, Except_T exc_type);

/**
 * SocketCommon_leave_multicast - Leave multicast group
 * @base: Socket base with fd
 * @group: Multicast group string
 * @interface: Interface IP or NULL
 * @exc_type: Exception to raise on failure
 * Symmetric to join; drops membership via setsockopt
 */
extern void SocketCommon_leave_multicast (SocketBase_T base, const char *group, const char *interface, Except_T exc_type);

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
 * SocketCommon_find_active_iov - Find first non-empty iovec in array
 * @iov: Array of iovec structures to search
 * @iovcnt: Number of iovec structures
 * @active_iovcnt: Output for count of remaining iovecs from active position
 *
 * Returns: Pointer to first iovec with iov_len > 0, or NULL if all empty
 * Thread-safe: Yes (read-only operation)
 *
 * Used by sendvall/recvvall to find the next active buffer segment
 * after partial I/O operations have consumed some of the iovec array.
 */
extern struct iovec *SocketCommon_find_active_iov (struct iovec *iov, int iovcnt,
                                                   int *active_iovcnt);

/**
 * SocketCommon_sync_iov_progress - Sync original iovec with working copy progress
 * @original: Original iovec array to update
 * @copy: Working copy that has been advanced
 * @iovcnt: Number of iovec structures
 *
 * Updates the original iovec array to reflect progress made in the copy.
 * Used when recvvall needs to update caller's iovec on partial completion.
 * Thread-safe: Yes (local ops)
 */
extern void SocketCommon_sync_iov_progress (struct iovec *original,
                                            const struct iovec *copy, int iovcnt);

/**
 * SocketCommon_alloc_iov_copy - Allocate and copy iovec array
 * @iov: Source iovec array to copy
 * @iovcnt: Number of iovec structures (>0, <=IOV_MAX)
 * @exc_type: Exception type to raise on allocation failure
 *
 * Returns: Newly allocated copy of iovec array (caller must free)
 * Raises: exc_type on allocation failure
 * Thread-safe: Yes
 *
 * Common helper for sendvall/recvvall implementations. Consolidates
 * duplicate calloc+memcpy patterns across Socket and SocketDgram modules.
 */
extern struct iovec *SocketCommon_alloc_iov_copy (const struct iovec *iov,
                                                  int iovcnt,
                                                  Except_T exc_type);

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

/**
 * SocketCommon_format_bind_error - Format descriptive bind error message
 * @host: Host string (NULL defaults to "any")
 * @port: Port number
 *
 * Formats error in socket_error_buf based on errno (EADDRINUSE, EACCES, etc.)
 * Consolidated helper for Socket and SocketDgram bind error handling.
 * Does not raise - caller should raise after calling this.
 */
extern void SocketCommon_format_bind_error (const char *host, int port);

extern void SocketCommon_update_local_endpoint (SocketBase_T base); /* Common endpoint update, non-raising */

/**
 * SocketCommon_get_socket_family - Get socket's address family
 * @base: Socket base to query
 * Returns: Socket family or AF_UNSPEC on error
 * Uses SO_DOMAIN on Linux, falls back to getsockname() on other platforms.
 */
extern int SocketCommon_get_socket_family (SocketBase_T base);

/**
 * SocketCommon_validate_host_not_null - Validate host is not NULL
 * @host: Host string to validate
 * @exception_type: Exception type to raise on NULL host
 * Raises: Specified exception type if host is NULL
 * Thread-safe: Yes
 */
extern void SocketCommon_validate_host_not_null (const char *host, Except_T exception_type);

/**
 * SocketCommon_copy_addrinfo - Deep copy of addrinfo linked list
 * @src: Source chain to copy (may be NULL)
 * @return: malloc-allocated deep copy, or NULL on error
 *
 * Deep copies the entire chain including ai_addr and ai_canonname fields.
 * Caller takes ownership and MUST free with SocketCommon_free_addrinfo().
 * Do NOT use freeaddrinfo() on the result - it's undefined behavior.
 * No exceptions raised; returns NULL on malloc failure or src==NULL.
 * Thread-safe: Yes
 */
extern struct addrinfo *SocketCommon_copy_addrinfo (const struct addrinfo *src);

/**
 * SocketCommon_free_addrinfo - Free addrinfo chain created by copy_addrinfo
 * @ai: Chain to free (may be NULL, safe no-op)
 *
 * Frees all nodes in the chain including ai_addr and ai_canonname fields.
 * Use this instead of freeaddrinfo() for chains from SocketCommon_copy_addrinfo.
 * Thread-safe: Yes
 */
extern void SocketCommon_free_addrinfo (struct addrinfo *ai);

/* Internal helpers defined in SocketCommon-private.h for module use (getters/setters for base fields) */

/* Extern globals for shared defaults - defined in SocketCommon.c */
extern SocketTimeouts_T socket_default_timeouts;
extern pthread_mutex_t socket_default_timeouts_mutex;

/**
 * SocketCommon_timeouts_getdefaults - Get global default timeouts
 * @timeouts: Output pointer for timeout structure
 * Thread-safe: Yes (uses mutex protection)
 */
extern void SocketCommon_timeouts_getdefaults (SocketTimeouts_T *timeouts);

/**
 * SocketCommon_timeouts_setdefaults - Set global default timeouts
 * @timeouts: Timeout values to set as defaults
 * Thread-safe: Yes (uses mutex protection)
 */
extern void SocketCommon_timeouts_setdefaults (const SocketTimeouts_T *timeouts);

/* ==================== Socket State Helpers ==================== */

/**
 * SocketCommon_check_bound_ipv4 - Check if IPv4 socket is bound
 * @addr: sockaddr_storage containing address
 * Returns: 1 if bound (port != 0), 0 otherwise
 */
static inline int
SocketCommon_check_bound_ipv4 (const struct sockaddr_storage *addr)
{
  const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
  return sin->sin_port != 0;
}

/**
 * SocketCommon_check_bound_ipv6 - Check if IPv6 socket is bound
 * @addr: sockaddr_storage containing address
 * Returns: 1 if bound (port != 0), 0 otherwise
 */
static inline int
SocketCommon_check_bound_ipv6 (const struct sockaddr_storage *addr)
{
  const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
  return sin6->sin6_port != 0;
}

/**
 * SocketCommon_check_bound_unix - Check if Unix socket is bound
 * @addr: sockaddr_storage containing address (unused)
 * Returns: 1 (Unix domain sockets are bound if getsockname succeeds)
 */
static inline int
SocketCommon_check_bound_unix (const struct sockaddr_storage *addr)
{
  (void)addr; /* Suppress unused parameter warning */
  return 1;   /* Unix domain sockets are bound if getsockname succeeds */
}

/**
 * SocketCommon_check_bound_by_family - Check if socket is bound based on family
 * @addr: sockaddr_storage containing address
 * Returns: 1 if bound, 0 otherwise
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
 * ============================================================================ */

/**
 * SocketLiveCount - Thread-safe live count tracker for socket instances
 *
 * Provides thread-safe increment/decrement operations for tracking
 * live socket instances. Used by both Socket_T and SocketDgram_T
 * for debugging and leak detection.
 */
struct SocketLiveCount
{
  int count;
  pthread_mutex_t mutex;
};

#define SOCKETLIVECOUNT_STATIC_INIT                                           \
  {                                                                            \
    0, PTHREAD_MUTEX_INITIALIZER                                               \
  }

/**
 * SocketLiveCount_increment - Increment live count (thread-safe)
 * @tracker: Live count tracker
 */
static inline void
SocketLiveCount_increment (struct SocketLiveCount *tracker)
{
  pthread_mutex_lock (&tracker->mutex);
  tracker->count++;
  pthread_mutex_unlock (&tracker->mutex);
}

/**
 * SocketLiveCount_decrement - Decrement live count (thread-safe)
 * @tracker: Live count tracker
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
 * SocketLiveCount_get - Get current live count (thread-safe)
 * @tracker: Live count tracker
 * Returns: Current count value
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
typedef struct SocketDNS_T *SocketDNS_T;

/**
 * SocketCommon_get_dns_resolver - Get global DNS resolver instance
 *
 * Returns: Global DNS resolver (lazily initialized on first call)
 *
 * Thread-safe: Yes - uses pthread_once for initialization
 *
 * The global DNS resolver is shared across all Socket and SocketDgram
 * operations. It provides timeout guarantees for DNS resolution.
 */
extern SocketDNS_T SocketCommon_get_dns_resolver (void);

/**
 * SocketCommon_set_dns_timeout - Set global DNS resolution timeout
 * @timeout_ms: Timeout in milliseconds (0 = infinite, -1 = use default)
 *
 * Thread-safe: Yes - protected by mutex
 *
 * Affects all subsequent hostname resolution via Socket/SocketDgram APIs.
 * Default: SOCKET_DEFAULT_DNS_TIMEOUT_MS (5000ms)
 *
 * Setting timeout_ms to 0 disables timeout (infinite wait).
 * Setting timeout_ms to -1 resets to default.
 */
extern void SocketCommon_set_dns_timeout (int timeout_ms);

/**
 * SocketCommon_get_dns_timeout - Get current global DNS timeout
 *
 * Returns: Current timeout in milliseconds (0 = infinite)
 *
 * Thread-safe: Yes
 */
extern int SocketCommon_get_dns_timeout (void);

#endif /* SOCKETCOMMON_INCLUDED */
