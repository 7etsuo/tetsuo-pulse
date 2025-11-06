#ifndef SOCKETCOMMON_H
#define SOCKETCOMMON_H

/**
 * SocketCommon.h - Common utilities shared between Socket and SocketDgram modules
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 */

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

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
 *
 * Returns: 0 on success, -1 on failure (if not using exceptions)
 * Raises: Specified exception type on failure (if using exceptions)
 */
int SocketCommon_resolve_address(const char *host, int port, const struct addrinfo *hints,
                                struct addrinfo **res, Except_T exception_type,
                                int socket_family, int use_exceptions);

/**
 * SocketCommon_validate_port - Validate port number is in valid range
 * @port: Port number to validate
 * @exception_type: Exception type to raise on invalid port
 *
 * Raises: Specified exception type if port is invalid
 */
void SocketCommon_validate_port(int port, Except_T exception_type);

/**
 * SocketCommon_validate_hostname - Validate hostname length
 * @host: Hostname to validate
 * @exception_type: Exception type to raise on invalid hostname
 *
 * Raises: Specified exception type if hostname is too long
 */
void SocketCommon_validate_hostname(const char *host, Except_T exception_type);

/**
 * SocketCommon_normalize_wildcard_host - Normalize wildcard host addresses to NULL
 * @host: Host string to normalize
 *
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
 *
 * Returns: 0 on success, -1 on failure (addr_out unchanged on failure)
 */
int SocketCommon_cache_endpoint(Arena_T arena, const struct sockaddr *addr, socklen_t addrlen,
                               char **addr_out, int *port_out);

#endif /* SOCKETCOMMON_H */
