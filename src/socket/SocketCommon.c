/**
 * SocketCommon.c - Common utilities shared between Socket and SocketDgram modules
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 */

#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "socket/SocketCommon.h"

/* Forward declarations for exception types */
extern Except_T Socket_Failed;
extern Except_T SocketDgram_Failed;

/**
 * SocketCommon_setup_hints - Initialize addrinfo hints structure
 * @hints: Hints structure to initialize
 * @socktype: Socket type (SOCK_STREAM or SOCK_DGRAM)
 * @flags: Additional flags (0 for connect/sendto, AI_PASSIVE for bind)
 */
void SocketCommon_setup_hints(struct addrinfo *hints, int socktype, int flags)
{
    memset(hints, 0, sizeof(*hints));
    hints->ai_family = SOCKET_AF_UNSPEC;
    hints->ai_socktype = socktype;
    hints->ai_flags = flags;
    hints->ai_protocol = 0;
}

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
int SocketCommon_resolve_address(const char *host, int port, const struct addrinfo *hints, struct addrinfo **res,
                                 Except_T exception_type, int socket_family, int use_exceptions)
{
    char port_str[SOCKET_PORT_STR_BUFSIZE];
    int result;
    size_t host_len = host ? strlen(host) : 0;

    /* Validate hostname length */
    if (host_len > SOCKET_ERROR_MAX_HOSTNAME)
    {
        if (use_exceptions)
        {
            SOCKET_ERROR_MSG("Host name too long (max %d characters)", SOCKET_ERROR_MAX_HOSTNAME);
/* Use thread-local storage to avoid modifying global exception */
#ifdef _WIN32
            static __declspec(thread) Except_T Common_DetailedException;
#else
            static __thread Except_T Common_DetailedException;
#endif
            Common_DetailedException = exception_type;
            Common_DetailedException.reason = socket_error_buf;
            RAISE(Common_DetailedException);
        }
        else
        {
            SOCKET_ERROR_MSG("Host name too long (max %d characters)", SOCKET_ERROR_MAX_HOSTNAME);
            return -1;
        }
    }

    /* Convert port to string */
    result = snprintf(port_str, sizeof(port_str), "%d", port);
    assert(result > 0 && result < (int)sizeof(port_str));

    result = getaddrinfo(host, port_str, hints, res);
    if (result != 0)
    {
        const char *safe_host = host ? host : "any";
        if (use_exceptions)
        {
            SOCKET_ERROR_MSG("Invalid host/IP address: %.*s (%s)", SOCKET_ERROR_MAX_HOSTNAME, safe_host,
                             gai_strerror(result));
/* Use thread-local storage to avoid modifying global exception */
#ifdef _WIN32
            static __declspec(thread) Except_T Common_DetailedException;
#else
            static __thread Except_T Common_DetailedException;
#endif
            Common_DetailedException = exception_type;
            Common_DetailedException.reason = socket_error_buf;
            RAISE(Common_DetailedException);
        }
        else
        {
            SOCKET_ERROR_MSG("Invalid host/IP address: %.*s (%s)", SOCKET_ERROR_MAX_HOSTNAME, safe_host,
                             gai_strerror(result));
            return -1;
        }
    }

    /* Validate against socket family if specified */
    if (socket_family != SOCKET_AF_UNSPEC)
    {
        for (struct addrinfo *rp = *res; rp != NULL; rp = rp->ai_next)
        {
            if (rp->ai_family == socket_family)
            {
                return 0; /* Found matching family */
            }
        }
        freeaddrinfo(*res);
        *res = NULL;
        const char *safe_host = host ? host : "any";
        if (use_exceptions)
        {
            SOCKET_ERROR_MSG("No address found for family %d: %.*s:%d", socket_family, SOCKET_ERROR_MAX_HOSTNAME,
                             safe_host, port);
/* Use thread-local storage to avoid modifying global exception */
#ifdef _WIN32
            static __declspec(thread) Except_T Common_DetailedException;
#else
            static __thread Except_T Common_DetailedException;
#endif
            Common_DetailedException = exception_type;
            Common_DetailedException.reason = socket_error_buf;
            RAISE(Common_DetailedException);
        }
        else
        {
            SOCKET_ERROR_MSG("No address found for family %d: %.*s:%d", socket_family, SOCKET_ERROR_MAX_HOSTNAME,
                             safe_host, port);
            return -1;
        }
    }

    return 0;
}

/**
 * SocketCommon_validate_port - Validate port number is in valid range
 * @port: Port number to validate
 * @exception_type: Exception type to raise on invalid port
 *
 * Raises: Specified exception type if port is invalid
 */
void SocketCommon_validate_port(int port, Except_T exception_type)
{
    if (!SOCKET_VALID_PORT(port))
    {
        SOCKET_ERROR_MSG("Invalid port number: %d (must be 1-65535)", port);
/* Use thread-local storage to avoid modifying global exception */
#ifdef _WIN32
        static __declspec(thread) Except_T Common_DetailedException;
#else
        static __thread Except_T Common_DetailedException;
#endif
        Common_DetailedException = exception_type;
        Common_DetailedException.reason = socket_error_buf;
        RAISE(Common_DetailedException);
    }
}

/**
 * SocketCommon_validate_hostname - Validate hostname length
 * @host: Hostname to validate
 * @exception_type: Exception type to raise on invalid hostname
 *
 * Raises: Specified exception type if hostname is too long
 */
void SocketCommon_validate_hostname(const char *host, Except_T exception_type)
{
    size_t host_len = strlen(host);

    if (host_len > SOCKET_ERROR_MAX_HOSTNAME)
    {
        SOCKET_ERROR_MSG("Host name too long (max %d characters)", SOCKET_ERROR_MAX_HOSTNAME);
/* Use thread-local storage to avoid modifying global exception */
#ifdef _WIN32
        static __declspec(thread) Except_T Common_DetailedException;
#else
        static __thread Except_T Common_DetailedException;
#endif
        Common_DetailedException = exception_type;
        Common_DetailedException.reason = socket_error_buf;
        RAISE(Common_DetailedException);
    }
}

/**
 * SocketCommon_normalize_wildcard_host - Normalize wildcard host addresses to NULL
 * @host: Host string to normalize
 *
 * Returns: NULL if wildcard ("0.0.0.0" or "::"), original host otherwise
 */
const char *SocketCommon_normalize_wildcard_host(const char *host)
{
    if (host == NULL || strcmp(host, "0.0.0.0") == 0 || strcmp(host, "::") == 0)
        return NULL;
    return host;
}
