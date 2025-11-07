#ifndef SOCKETCOMMON_H
#define SOCKETCOMMON_H

/**
 * SocketCommon.h - Common utilities shared between Socket and SocketDgram modules
 */

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <fcntl.h>

#include "core/Arena.h"

#include "core/Except.h"
#include "core/SocketConfig.h"

/* Common exception types (Except_T is defined in Except.h) */
extern Except_T Socket_Failed;
extern Except_T SocketDgram_Failed;

/**
 * SocketCommon_setup_hints - Initialize addrinfo hints structure
 * @hints: Hints structure to initialize
 * @socktype: Socket type (SOCK_STREAM or SOCK_DGRAM)
 * @flags: Additional flags (0 for connect/sendto, AI_PASSIVE for bind)
 */
void SocketCommon_setup_hints(struct addrinfo *hints, int socktype, int flags);

/**
 * SocketCommon_resolve_address - Resolve hostname/port to addrinfo structure
 * @host: Hostname or IP address (NULL for wildcard)
 * @port: Port number (1-65535)
 * @hints: Addrinfo hints structure
 * @res: Output pointer to resolved addrinfo
 * @exception_type: Exception type to raise on failure
 * @socket_family: Socket family to match (AF_UNSPEC if none)
 * @use_exceptions: If true, raise exceptions; if false, return error codes
 * Returns: 0 on success, -1 on failure (if not using exceptions)
 * Raises: Specified exception type on failure (if using exceptions)
 */
int SocketCommon_resolve_address(const char *host, int port, const struct addrinfo *hints, struct addrinfo **res,
                                 Except_T exception_type, int socket_family, int use_exceptions);

/**
 * SocketCommon_validate_port - Validate port number is in valid range
 * @port: Port number to validate
 * @exception_type: Exception type to raise on invalid port
 * Raises: Specified exception type if port is invalid
 */
void SocketCommon_validate_port(int port, Except_T exception_type);

/**
 * SocketCommon_validate_hostname - Validate hostname length
 * @host: Hostname to validate
 * @exception_type: Exception type to raise on invalid hostname
 * Raises: Specified exception type if hostname is too long
 */
void SocketCommon_validate_hostname(const char *host, Except_T exception_type);

/**
 * SocketCommon_normalize_wildcard_host - Normalize wildcard host addresses to NULL
 * @host: Host string to normalize
 * Returns: NULL if wildcard ("0.0.0.0" or "::"), original host otherwise
 */
const char *SocketCommon_normalize_wildcard_host(const char *host);

/**
 * SocketCommon_cache_endpoint - Cache numeric address/port from sockaddr
 * @arena: Arena to allocate cached address string
 * @addr: Socket address to format
 * @addrlen: Length of socket address
 * @addr_out: Output pointer updated to arena-allocated address string
 * @port_out: Output integer updated with numeric port (0 if unavailable)
 * Returns: 0 on success, -1 on failure (addr_out unchanged on failure)
 */
int SocketCommon_cache_endpoint(Arena_T arena, const struct sockaddr *addr, socklen_t addrlen, char **addr_out,
                                int *port_out);

/**
 * SocketCommon_setcloexec - Set close-on-exec flag on file descriptor
 * @fd: File descriptor to modify
 * @enable: 1 to enable CLOEXEC, 0 to disable
 * Returns: 0 on success, -1 on failure
 * Thread-safe: Yes (operates on single fd)
 */
int SocketCommon_setcloexec(int fd, int enable);

/**
 * SocketCommon_has_cloexec - Check if close-on-exec flag is set
 * @fd: File descriptor to check
 * Returns: 1 if CLOEXEC is set, 0 if not set, -1 on error
 * Thread-safe: Yes (operates on single fd)
 */
int SocketCommon_has_cloexec(int fd);

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
int SocketCommon_getoption_int(int fd, int level, int optname, int *value, Except_T exception_type);

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
int SocketCommon_getoption_timeval(int fd, int level, int optname, struct timeval *tv, Except_T exception_type);

/**
 * SocketCommon_reverse_lookup - Perform reverse DNS lookup (getnameinfo wrapper)
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
int SocketCommon_reverse_lookup(const struct sockaddr *addr, socklen_t addrlen, char *host, socklen_t hostlen,
                                char *serv, socklen_t servlen, int flags, Except_T exception_type);

/**
 * SocketCommon_parse_ip - Validate and parse IP address string
 * @ip_str: IP address string to validate
 * @family: Output pointer for address family (AF_INET or AF_INET6), can be NULL
 * Returns: 1 if valid IP address, 0 if invalid
 * Thread-safe: Yes
 * Note: Validates both IPv4 and IPv6 addresses.
 * Sets family to AF_INET for IPv4, AF_INET6 for IPv6, or AF_UNSPEC if invalid.
 */
int SocketCommon_parse_ip(const char *ip_str, int *family);

/**
 * SocketCommon_cidr_match - Check if IP address matches CIDR range
 * @ip_str: IP address string to check
 * @cidr_str: CIDR notation string (e.g., "192.168.1.0/24" or "2001:db8::/32")
 * Returns: 1 if IP matches CIDR range, 0 if not, -1 on error
 * Thread-safe: Yes
 * Note: Supports both IPv4 and IPv6 CIDR notation.
 * Returns -1 if IP or CIDR string is invalid.
 */
int SocketCommon_cidr_match(const char *ip_str, const char *cidr_str);

#endif /* SOCKETCOMMON_H */
