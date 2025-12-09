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
 * @brief Initialize addrinfo hints structure for resolution.
 * @ingroup core_io
 * @param hints Hints structure to initialize (must be zeroed first with memset).
 * @param socktype Socket type (SOCK_STREAM or SOCK_DGRAM).
 * @param flags Additional flags (0 for connect/sendto, AI_PASSIVE for bind).
 * @note Sets ai_family to AF_UNSPEC for dual-stack support, ai_socktype, ai_protocol=0, ai_flags.
 * @see SocketCommon_resolve_address() for using initialized hints in resolution.
 * @see getaddrinfo(3) for full addrinfo hints documentation.
 */
void SocketCommon_setup_hints (struct addrinfo *hints, int socktype,
                               int flags);

/**
 * @brief Resolve hostname/port to addrinfo structure using getaddrinfo wrapper.
 * @ingroup core_io
 * @param host Hostname or IP address (NULL for wildcard/any).
 * @param port Port number (1 to SOCKET_MAX_PORT).
 * @param hints Addrinfo hints structure (prepared via SocketCommon_setup_hints()).
 * @param res Output pointer to resolved addrinfo list (caller must free with freeaddrinfo()).
 * @param exception_type Exception type to raise on failure.
 * @param socket_family Preferred socket family to match (AF_UNSPEC for any).
 * @param use_exceptions If true, raise exceptions on failure; if false, return error codes and set errno.
 * @return 0 on success, -1 on failure (if not using exceptions).
 * @throws Specified exception_type on resolution failure (getaddrinfo errors, invalid port, etc.).
 * @note Uses global DNS resolver (SocketCommon_get_dns_resolver()) for timeout guarantees if hostname provided.
 * @note Filters resolved addresses to match socket_family if specified (e.g., AF_INET only).
 * @note Caller responsible for validating and freeing the addrinfo chain.
 * @note Thread-safe: Yes (uses thread-local error buffers).
 * @see SocketCommon_setup_hints() for preparing hints structure.
 * @see Socket_bind() and Socket_connect() which use this internally.
 * @see SocketCommon_get_dns_resolver() for global DNS timeout configuration.
 * @see SocketCommon_copy_addrinfo() for duplicating resolved chains.
 * @see freeaddrinfo(3) for cleaning up resolved structures.
 * @see docs/ERROR_HANDLING.md for exception patterns in network code.
 */
int SocketCommon_resolve_address (const char *host, int port,
                                  const struct addrinfo *hints,
                                  struct addrinfo **res,
                                  Except_T exception_type, int socket_family,
                                  int use_exceptions);

/**
 * @brief Validate port number is in valid range
 * @ingroup core_io
 * @param port Port number to validate
 * @param exception_type Exception type to raise on invalid port
 * @throws Specified exception type if port is invalid
 */
void SocketCommon_validate_port (int port, Except_T exception_type);

/**
 * @brief Validate hostname length
 * @ingroup core_io
 * @param host Hostname to validate
 * @param exception_type Exception type to raise on invalid hostname
 * @throws Specified exception type if hostname is too long
 */
void SocketCommon_validate_hostname (const char *host,
                                     Except_T exception_type);

/**
 * @brief Normalize wildcard host addresses to NULL
 * @ingroup core_io
 * @param host Host string to normalize
 * @return NULL if wildcard ("0.0.0.0" or "::"), original host otherwise
 */
const char *SocketCommon_normalize_wildcard_host (const char *host);

/**
 * @brief Cache numeric address/port from sockaddr
 * @ingroup core_io
 * @param arena Arena to allocate cached address string
 * @param addr Socket address to format
 * @param addrlen Length of socket address
 * @param addr_out Output pointer updated to arena-allocated address string
 * @param port_out Output integer updated with numeric port (0 if unavailable)
 * @return 0 on success, -1 on failure (addr_out unchanged on failure)
 */
int SocketCommon_cache_endpoint (Arena_T arena, const struct sockaddr *addr,
                                 socklen_t addrlen, char **addr_out,
                                 int *port_out);

/**
 * @brief Set close-on-exec flag on file descriptor
 * @ingroup core_io
 * @param fd File descriptor to modify
 * @param enable 1 to enable CLOEXEC, 0 to disable
 * @return 0 on success, -1 on failure
 * @note Thread-safe: Yes (operates on single fd)
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
int SocketCommon_getoption_int (int fd, int level, int optname, int *value,
                                Except_T exception_type);

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
int SocketCommon_getoption_timeval (int fd, int level, int optname,
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
                                 socklen_t addrlen, char *host,
                                 socklen_t hostlen, char *serv,
                                 socklen_t servlen, int flags,
                                 Except_T exception_type);

/**
 * @brief Validate and parse IP address string
 * @ingroup core_io
 * @param ip_str IP address string to validate
 * @param family Output pointer for address family (AF_INET or AF_INET6), can be NULL
 * @return 1 if valid IP address, 0 if invalid
 * @note Thread-safe: Yes
 * @note Validates both IPv4 and IPv6 addresses. Sets family to AF_INET for IPv4, AF_INET6 for IPv6, or AF_UNSPEC if invalid.
 */
int SocketCommon_parse_ip (const char *ip_str, int *family);

/**
 * @brief Check if IP address matches CIDR range
 * @ingroup core_io
 * @param ip_str IP address string to check
 * @param cidr_str CIDR notation string (e.g., "192.168.1.0/24" or "2001:db8::/32")
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
 * @note Generic setter for standard socket options, unifies duplicated setsockopt calls
 * @note Thread-safe: Yes for own resources
 */
extern void SocketCommon_set_option_int (SocketBase_T base, int level,
                                         int optname, int value,
                                         Except_T exc_type);

/**
 * @brief Set TTL or hop limit based on family
 * @ingroup core_io
 * @param base Base with fd
 * @param family AF_INET or AF_INET6
 * @param ttl TTL value
 * @param exc_type Raise on fail
 * @note Unifies set_ipv4_ttl and set_ipv6_hop_limit
 */
extern void SocketCommon_set_ttl (SocketBase_T base, int family, int ttl,
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
extern void SocketCommon_join_multicast (SocketBase_T base, const char *group,
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
extern void SocketCommon_leave_multicast (SocketBase_T base, const char *group,
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
extern void SocketCommon_set_nonblock (SocketBase_T base, bool enable,
                                       Except_T exc_type);

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
extern size_t SocketCommon_calculate_total_iov_len (const struct iovec *iov,
                                                    int iovcnt);

/**
 * @brief Advance iovec array past sent/received bytes (modifies in place)
 * @ingroup core_io
 * @param iov Array of iovec structures to advance
 * @param iovcnt Number of iovec structures
 * @param bytes Bytes to advance (must <= total iov len)
 * @note Behavior: Sets advanced iovs to len=0/base=NULL, partial to offset/len reduced
 * @throws SocketCommon_Failed if bytes > total iov len or invalid params
 * @note Thread-safe: Yes (local ops)
 * @note Unifies duplicated advance logic for sendvall/recvvall
 */
extern void SocketCommon_advance_iov (struct iovec *iov, int iovcnt,
                                      size_t bytes);

/**
 * @brief Find first non-empty iovec in array
 * @ingroup core_io
 * @param iov Array of iovec structures to search
 * @param iovcnt Number of iovec structures
 * @param active_iovcnt Output for count of remaining iovecs from active position
 * @return Pointer to first iovec with iov_len > 0, or NULL if all empty
 * @note Thread-safe: Yes (read-only operation)
 * @note Used by sendvall/recvvall to find the next active buffer segment after partial I/O operations have consumed some of the iovec array.
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
 * @note Used when recvvall needs to update caller's iovec on partial completion.
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
 * @note Common helper for sendvall/recvvall implementations. Consolidates duplicate calloc+memcpy patterns across Socket and SocketDgram modules.
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
 * @note Uses fcntl F_SETFD; called after socket()/socketpair()/accept() fallback
 */
extern void SocketCommon_set_cloexec_fd (int fd, bool enable,
                                         Except_T exc_type);

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
 * @note Loops addresses, calls try_bind_address, sets base local endpoint on success
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
 * @note Graceful for non-fatal (e.g., EADDRINUSE log warn return -1), fatal raise
 */
extern int SocketCommon_handle_bind_error (int err, const char *addr_str,
                                           Except_T exc_type);

/**
 * @brief Format descriptive bind error message
 * @ingroup core_io
 * @param host Host string (NULL defaults to "any")
 * @param port Port number
 * @note Formats error in socket_error_buf based on errno (EADDRINUSE, EACCES, etc.)
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
 * @note Uses SO_DOMAIN on Linux, falls back to getsockname() on other platforms.
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
extern void SocketCommon_validate_host_not_null (const char *host,
                                                 Except_T exception_type);

/**
 * @brief Deep copy of addrinfo linked list
 * @ingroup core_io
 * @param src Source chain to copy (may be NULL)
 * @return malloc-allocated deep copy, or NULL on error
 * @note Deep copies the entire chain including ai_addr and ai_canonname fields.
 * @note Caller takes ownership and MUST free with SocketCommon_free_addrinfo().
 * @note Do NOT use freeaddrinfo() on the result - it's undefined behavior.
 * @note No exceptions raised; returns NULL on malloc failure or src==NULL.
 * @note Thread-safe: Yes
 */
extern struct addrinfo *
SocketCommon_copy_addrinfo (const struct addrinfo *src);

/**
 * @brief Free addrinfo chain created by copy_addrinfo
 * @ingroup core_io
 * @param ai Chain to free (may be NULL, safe no-op)
 * @note Frees all nodes in the chain including ai_addr and ai_canonname fields.
 * @note Use this instead of freeaddrinfo() for chains from SocketCommon_copy_addrinfo.
 * @note Thread-safe: Yes
 */
extern void SocketCommon_free_addrinfo (struct addrinfo *ai);

/* Internal helpers defined in SocketCommon-private.h for module use
 * (getters/setters for base fields) */

/* Extern globals for shared defaults - defined in SocketCommon.c */

/**
 * @brief Global default timeout configuration for socket operations.
 * @ingroup core_io
 * @var socket_default_timeouts
 * @note Internal global variable.
 * @note Thread-safe access via SocketCommon_timeouts_getdefaults() and SocketCommon_timeouts_setdefaults().
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
 * @note Ensures thread-safe modification and reading of socket_default_timeouts.
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
 * @brief SocketLiveCount - Thread-safe live count tracker for socket instances
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
  {                                                                           \
    0, PTHREAD_MUTEX_INITIALIZER                                              \
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
 * @note The global DNS resolver is shared across all Socket and SocketDgram operations. It provides timeout guarantees for DNS resolution.
 */
extern SocketDNS_T SocketCommon_get_dns_resolver (void);

/**
 * @brief Set global DNS resolution timeout
 * @ingroup core_io
 * @param timeout_ms Timeout in milliseconds (0 = infinite, -1 = use default)
 * @note Thread-safe: Yes - protected by mutex
 * @note Affects all subsequent hostname resolution via Socket/SocketDgram APIs.
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

#endif /* SOCKETCOMMON_INCLUDED */
