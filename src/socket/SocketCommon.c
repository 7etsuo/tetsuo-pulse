/**
 * SocketCommon.c - Common utilities shared between Socket and SocketDgram modules
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "socket/SocketCommon.h"

/* Forward declarations for exception types */
extern Except_T Socket_Failed;
extern Except_T SocketDgram_Failed;

/* Thread-local exception for detailed error messages */
#ifdef _WIN32
static __declspec(thread) Except_T Common_DetailedException;
#else
static __thread Except_T Common_DetailedException;
#endif

/* Macro to raise exception with detailed error message */
#define RAISE_COMMON_ERROR(exception)                                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        Common_DetailedException = (exception);                                                                        \
        Common_DetailedException.reason = socket_error_buf;                                                            \
        RAISE(Common_DetailedException);                                                                               \
    } while (0)

/**
 * socketcommon_get_safe_host
 * @host: Host string (may be NULL)
 * Thread-safe: Yes
 */
static const char *socketcommon_get_safe_host(const char *host)
{
    return host ? host : "any";
}

static char *socketcommon_duplicate_address(Arena_T arena, const char *addr_str)
{
    size_t addr_len;
    char *copy = NULL;

    assert(arena);
    assert(addr_str);

    addr_len = strlen(addr_str) + 1;
    copy = ALLOC(arena, addr_len);
    if (!copy)
    {
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate address buffer");
        return NULL;
    }
    memcpy(copy, addr_str, addr_len);
    return copy;
}

static int socketcommon_parse_port_string(const char *serv)
{
    char *endptr = NULL;
    long port_long = 0;

    assert(serv);

    errno = 0;
    port_long = strtol(serv, &endptr, 10);
    if (errno == 0 && endptr != serv && *endptr == '\0' && port_long >= 0 && port_long <= 65535)
        return (int)port_long;
    return 0;
}

/**
 * socketcommon_validate_hostname_length - Validate hostname length
 * @host: Hostname to validate
 * @use_exceptions: If true, raise exception; if false, return error code
 * @exception_type: Exception type to raise on failure
 * Returns: 0 on success, -1 on failure
 * Raises: Specified exception type if hostname too long (if using exceptions)
 * Thread-safe: Yes
 */
static int socketcommon_validate_hostname_length(const char *host, int use_exceptions, Except_T exception_type)
{
    size_t host_len = host ? strlen(host) : 0;

    if (host_len > SOCKET_ERROR_MAX_HOSTNAME)
    {
        SOCKET_ERROR_MSG("Host name too long (max %d characters)", SOCKET_ERROR_MAX_HOSTNAME);
        if (use_exceptions)
            RAISE_COMMON_ERROR(exception_type);
        return -1;
    }
    return 0;
}

/**
 * socketcommon_convert_port_to_string - Convert port number to string
 * @port: Port number
 * @port_str: Output buffer for port string
 * @bufsize: Size of output buffer
 * Thread-safe: Yes
 */
static void socketcommon_convert_port_to_string(int port, char *port_str, size_t bufsize)
{
    int result;

    result = snprintf(port_str, bufsize, "%d", port);
    assert(result > 0 && result < (int)bufsize);
}

/**
 * socketcommon_perform_getaddrinfo - Perform address resolution
 * @host: Hostname or IP address
 * @port_str: Port number as string
 * @hints: Addrinfo hints structure
 * @res: Output pointer to resolved addrinfo
 * @use_exceptions: If true, raise exception; if false, return error code
 * @exception_type: Exception type to raise on failure
 * Returns: 0 on success, -1 on failure
 * Raises: Specified exception type on failure (if using exceptions)
 * Thread-safe: Yes
 */
static int socketcommon_perform_getaddrinfo(const char *host, const char *port_str, const struct addrinfo *hints,
                                            struct addrinfo **res, int use_exceptions, Except_T exception_type)
{
    int result;
    const char *safe_host;

    result = getaddrinfo(host, port_str, hints, res);
    if (result != 0)
    {
        safe_host = socketcommon_get_safe_host(host);
        SOCKET_ERROR_MSG("Invalid host/IP address: %.*s (%s)", SOCKET_ERROR_MAX_HOSTNAME, safe_host,
                         gai_strerror(result));
        if (use_exceptions)
            RAISE_COMMON_ERROR(exception_type);
        return -1;
    }
    return 0;
}

/**
 * socketcommon_find_matching_family - Find address matching socket family
 * @res: Resolved address list
 * @socket_family: Socket family to match
 * Returns: 1 if matching family found, 0 otherwise
 * Thread-safe: Yes
 */
static int socketcommon_find_matching_family(struct addrinfo *res, int socket_family)
{
    struct addrinfo *rp;

    for (rp = res; rp != NULL; rp = rp->ai_next)
    {
        if (rp->ai_family == socket_family)
            return 1;
    }
    return 0;
}

/**
 * socketcommon_validate_address_family - Validate resolved address family
 * @res: Resolved address list
 * @socket_family: Socket family to match
 * @host: Hostname for error messages
 * @port: Port number for error messages
 * @use_exceptions: If true, raise exception; if false, return error code
 * @exception_type: Exception type to raise on failure
 * Returns: 0 on success, -1 on failure
 * Raises: Specified exception type if no matching family (if using exceptions)
 * Thread-safe: Yes
 */
static int socketcommon_validate_address_family(struct addrinfo **res, int socket_family, const char *host, int port,
                                                int use_exceptions, Except_T exception_type)
{
    const char *safe_host;

    if (socket_family == SOCKET_AF_UNSPEC)
        return 0;

    if (socketcommon_find_matching_family(*res, socket_family))
        return 0;

    freeaddrinfo(*res);
    *res = NULL;

    safe_host = socketcommon_get_safe_host(host);
    SOCKET_ERROR_MSG("No address found for family %d: %.*s:%d", socket_family, SOCKET_ERROR_MAX_HOSTNAME, safe_host,
                     port);
    if (use_exceptions)
        RAISE_COMMON_ERROR(exception_type);
    return -1;
}

/**
 * SocketCommon_setup_hints - Initialize addrinfo hints structure
 * @hints: Hints structure to initialize
 * @socktype: Socket type (SOCK_STREAM or SOCK_DGRAM)
 * @flags: Additional flags (0 for connect/sendto, AI_PASSIVE for bind)
 * Thread-safe: Yes
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
 * Returns: 0 on success, -1 on failure (if not using exceptions)
 * Raises: Specified exception type on failure (if using exceptions)
 * Thread-safe: Yes
 */
int SocketCommon_resolve_address(const char *host, int port, const struct addrinfo *hints, struct addrinfo **res,
                                 Except_T exception_type, int socket_family, int use_exceptions)
{
    char port_str[SOCKET_PORT_STR_BUFSIZE];

    if (socketcommon_validate_hostname_length(host, use_exceptions, exception_type) != 0)
        return -1;

    socketcommon_convert_port_to_string(port, port_str, sizeof(port_str));

    if (socketcommon_perform_getaddrinfo(host, port_str, hints, res, use_exceptions, exception_type) != 0)
        return -1;

    if (socketcommon_validate_address_family(res, socket_family, host, port, use_exceptions, exception_type) != 0)
        return -1;

    return 0;
}

/**
 * SocketCommon_validate_port - Validate port number is in valid range
 * @port: Port number to validate
 * @exception_type: Exception type to raise on invalid port
 * Raises: Specified exception type if port is invalid
 * Thread-safe: Yes
 */
void SocketCommon_validate_port(int port, Except_T exception_type)
{
    if (!SOCKET_VALID_PORT(port))
    {
        SOCKET_ERROR_MSG("Invalid port number: %d (must be 0-65535, 0 = OS-assigned)", port);
        RAISE_COMMON_ERROR(exception_type);
    }
}

/**
 * SocketCommon_validate_hostname - Validate hostname length
 * @host: Hostname to validate
 * @exception_type: Exception type to raise on invalid hostname
 * Raises: Specified exception type if hostname is too long
 * Thread-safe: Yes
 */
void SocketCommon_validate_hostname(const char *host, Except_T exception_type)
{
    if (socketcommon_validate_hostname_length(host, 1, exception_type) != 0)
        return; /* Exception already raised */
}

/**
 * SocketCommon_normalize_wildcard_host - Normalize wildcard host addresses to NULL
 * @host: Host string to normalize
 * Returns: NULL if wildcard ("0.0.0.0" or "::"), original host otherwise
 * Thread-safe: Yes
 */
const char *SocketCommon_normalize_wildcard_host(const char *host)
{
    if (host == NULL || strcmp(host, "0.0.0.0") == 0 || strcmp(host, "::") == 0)
        return NULL;
    return host;
}

int SocketCommon_cache_endpoint(Arena_T arena, const struct sockaddr *addr, socklen_t addrlen, char **addr_out,
                                int *port_out)
{
    char host[SOCKET_NI_MAXHOST];
    char serv[SOCKET_NI_MAXSERV];
    char *copy = NULL;
    int result;

    assert(arena);
    assert(addr);
    assert(addr_out);
    assert(port_out);

    result = getnameinfo(addr, addrlen, host, sizeof(host), serv, sizeof(serv),
                         SOCKET_NI_NUMERICHOST | SOCKET_NI_NUMERICSERV);
    if (result != 0)
    {
        SOCKET_ERROR_MSG("Failed to format socket address: %s", gai_strerror(result));
        return -1;
    }

    copy = socketcommon_duplicate_address(arena, host);
    if (!copy)
        return -1;

    *addr_out = copy;
    *port_out = socketcommon_parse_port_string(serv);
    return 0;
}

int SocketCommon_setcloexec(int fd, int enable)
{
    int flags;
    int new_flags;

    assert(fd >= 0);

    flags = fcntl(fd, F_GETFD);
    if (flags < 0)
        return -1;

    if (enable)
        new_flags = flags | SOCKET_FD_CLOEXEC;
    else
        new_flags = flags & ~SOCKET_FD_CLOEXEC;

    if (new_flags == flags)
        return 0; /* Already in desired state */

    if (fcntl(fd, F_SETFD, new_flags) < 0)
        return -1;

    return 0;
}

int SocketCommon_has_cloexec(int fd)
{
    int flags;

    assert(fd >= 0);

    flags = fcntl(fd, F_GETFD);
    if (flags < 0)
        return -1;

    return (flags & SOCKET_FD_CLOEXEC) ? 1 : 0;
}
