/**
 * SocketCommon.c - Common utilities shared between Socket and SocketDgram modules
 */

#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/SocketConfig.h"
#define SOCKET_LOG_COMPONENT "SocketCommon"
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
    if (errno == 0 && endptr != serv && *endptr == '\0' && port_long >= 0 && port_long <= SOCKET_MAX_PORT)
        return (int)port_long;
    return 0;
}

/**
 * socketcommon_validate_hostname_internal - Validate hostname length and characters
 * @host: Hostname to validate
 * @use_exceptions: If true, raise exception; if false, return error code
 * @exception_type: Exception type to raise on failure
 * Returns: 0 on success, -1 on failure
 * Raises: Specified exception type if hostname invalid (if using exceptions)
 * Thread-safe: Yes
 */
static int socketcommon_validate_hostname_internal(const char *host, int use_exceptions, Except_T exception_type)
{
    size_t host_len = host ? strlen(host) : 0;
    size_t i;

    if (host_len > SOCKET_ERROR_MAX_HOSTNAME)
    {
        SOCKET_ERROR_MSG("Host name too long (max %d characters)", SOCKET_ERROR_MAX_HOSTNAME);
        if (use_exceptions)
            RAISE_COMMON_ERROR(exception_type);
        return -1;
    }

    for (i = 0; i < host_len; i++)
    {
        char c = host[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' ||
              c == ':' || c == '%'))
        {
            SOCKET_ERROR_MSG("Invalid character in hostname: '%c'", c);
            if (use_exceptions)
                RAISE_COMMON_ERROR(exception_type);
            return -1;
        }
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
 * @port: Port number (1 to SOCKET_MAX_PORT)
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

    if (socketcommon_validate_hostname_internal(host, use_exceptions, exception_type) != 0)
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
        SOCKET_ERROR_MSG("Invalid port number: %d (must be 0-" SOCKET_TO_STRING(SOCKET_MAX_PORT) ", 0 = OS-assigned)", port);
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
    if (socketcommon_validate_hostname_internal(host, 1, exception_type) != 0)
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
int SocketCommon_getoption_int(int fd, int level, int optname, int *value, Except_T exception_type)
{
    socklen_t len = sizeof(*value);

    assert(fd >= 0);
    assert(value);

    if (getsockopt(fd, level, optname, value, &len) < 0)
    {
        SOCKET_ERROR_FMT("Failed to get socket option (level=%d, optname=%d)", level, optname);
        RAISE_COMMON_ERROR(exception_type);
        return -1;
    }

    return 0;
}

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
int SocketCommon_getoption_timeval(int fd, int level, int optname, struct timeval *tv, Except_T exception_type)
{
    socklen_t len = sizeof(*tv);

    assert(fd >= 0);
    assert(tv);

    if (getsockopt(fd, level, optname, tv, &len) < 0)
    {
        SOCKET_ERROR_FMT("Failed to get socket timeout option (level=%d, optname=%d)", level, optname);
        RAISE_COMMON_ERROR(exception_type);
        return -1;
    }

    return 0;
}

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
                                char *serv, socklen_t servlen, int flags, Except_T exception_type)
{
    int result;

    assert(addr);

    result = getnameinfo(addr, addrlen, host, hostlen, serv, servlen, flags);
    if (result != 0)
    {
        SOCKET_ERROR_MSG("Reverse lookup failed: %s", gai_strerror(result));
        RAISE_COMMON_ERROR(exception_type);
        return -1;
    }

    return 0;
}

/**
 * SocketCommon_parse_ip - Validate and parse IP address string
 * @ip_str: IP address string to validate
 * @family: Output pointer for address family (AF_INET or AF_INET6), can be NULL
 * Returns: 1 if valid IP address, 0 if invalid
 * Thread-safe: Yes
 * Note: Validates both IPv4 and IPv6 addresses.
 * Sets family to AF_INET for IPv4, AF_INET6 for IPv6, or AF_UNSPEC if invalid.
 */
int SocketCommon_parse_ip(const char *ip_str, int *family)
{
    struct in_addr addr4;
    struct in6_addr addr6;

    assert(ip_str);

    if (family)
        *family = AF_UNSPEC;

    /* Try IPv4 first */
    if (inet_pton(AF_INET, ip_str, &addr4) == 1)
    {
        if (family)
            *family = AF_INET;
        return 1;
    }

    /* Try IPv6 */
    if (inet_pton(AF_INET6, ip_str, &addr6) == 1)
    {
        if (family)
            *family = AF_INET6;
        return 1;
    }

    return 0;
}

/**
 * socketcommon_parse_cidr - Parse CIDR notation string
 * @cidr_str: CIDR notation string (e.g., "192.168.1.0/24")
 * @network: Output buffer for network address (4 or 16 bytes)
 * @prefix_len: Output pointer for prefix length
 * @family: Output pointer for address family
 * Returns: 0 on success, -1 on failure
 * Thread-safe: Yes
 */
static int socketcommon_parse_cidr(const char *cidr_str, unsigned char *network, int *prefix_len, int *family)
{
    char *cidr_copy = NULL;
    char *slash = NULL;
    char *endptr = NULL;
    struct in_addr addr4;
    struct in6_addr addr6;
    long prefix_long;

    assert(cidr_str);
    assert(network);
    assert(prefix_len);
    assert(family);

    /* Make a copy for strtok */
    cidr_copy = strdup(cidr_str);
    if (!cidr_copy)
        return -1;

    /* Find the '/' separator */
    slash = strchr(cidr_copy, '/');
    if (!slash)
    {
        free(cidr_copy);
        return -1;
    }

    *slash = '\0';
    slash++;

    /* Parse prefix length */
    errno = 0;
    prefix_long = strtol(slash, &endptr, 10);
    if (errno != 0 || endptr == slash || *endptr != '\0' || prefix_long < 0)
    {
        free(cidr_copy);
        return -1;
    }

    /* Try IPv4 first */
    if (inet_pton(AF_INET, cidr_copy, &addr4) == 1)
    {
        if (prefix_long > 32)
        {
            free(cidr_copy);
            return -1;
        }
        memcpy(network, &addr4, 4);
        *prefix_len = (int)prefix_long;
        *family = AF_INET;
        free(cidr_copy);
        return 0;
    }

    /* Try IPv6 */
    if (inet_pton(AF_INET6, cidr_copy, &addr6) == 1)
    {
        if (prefix_long > SOCKET_IPV6_MAX_PREFIX)
        {
            free(cidr_copy);
            return -1;
        }
        memcpy(network, &addr6, 16);
        *prefix_len = (int)prefix_long;
        *family = AF_INET6;
        free(cidr_copy);
        return 0;
    }

    free(cidr_copy);
    return -1;
}

/**
 * socketcommon_apply_mask - Apply CIDR mask to IP address
 * @ip: IP address bytes (4 for IPv4, 16 for IPv6)
 * @prefix_len: Prefix length (" SOCKET_IPV4_PREFIX_RANGE " for IPv4, " SOCKET_IPV6_PREFIX_RANGE " for IPv6)
 * @family: Address family (AF_INET or AF_INET6)
 * Thread-safe: Yes
 */
static void socketcommon_apply_mask(unsigned char *ip, int prefix_len, int family)
{
    int bytes_to_mask;
    int bits_to_mask;
    int i;

    if (family == AF_INET)
    {
        bytes_to_mask = prefix_len / 8;
        bits_to_mask = prefix_len % 8;

        /* Mask full bytes */
        for (i = bytes_to_mask; i < 4; i++)
            ip[i] = 0;

        /* Mask partial byte */
        if (bits_to_mask > 0 && bytes_to_mask < 4)
        {
            unsigned char mask = (0xFF << (8 - bits_to_mask)) & 0xFF;
            ip[bytes_to_mask] &= mask;
        }
    }
    else if (family == AF_INET6)
    {
        bytes_to_mask = prefix_len / 8;
        bits_to_mask = prefix_len % 8;

        /* Mask full bytes */
        for (i = bytes_to_mask; i < 16; i++)
            ip[i] = 0;

        /* Mask partial byte */
        if (bits_to_mask > 0 && bytes_to_mask < 16)
        {
            unsigned char mask = (0xFF << (8 - bits_to_mask)) & 0xFF;
            ip[bytes_to_mask] &= mask;
        }
    }
}

/**
 * SocketCommon_cidr_match - Check if IP address matches CIDR range
 * @ip_str: IP address string to check
 * @cidr_str: CIDR notation string (e.g., "192.168.1.0/24" or "2001:db8::/" SOCKET_TO_STRING(SOCKET_IPV6_MAX_PREFIX) ")
 * Returns: 1 if IP matches CIDR range, 0 if not, -1 on error
 * Thread-safe: Yes
 * Note: Supports both IPv4 and IPv6 CIDR notation.
 * Returns -1 if IP or CIDR string is invalid.
 */
int SocketCommon_cidr_match(const char *ip_str, const char *cidr_str)
{
    unsigned char network[16] = {0};
    unsigned char ip[16] = {0};
    int prefix_len;
    int cidr_family;
    int ip_family;
    int i;

    assert(ip_str);
    assert(cidr_str);

    /* Parse CIDR notation */
    if (socketcommon_parse_cidr(cidr_str, network, &prefix_len, &cidr_family) != 0)
        return -1;

    /* Parse IP address */
    if (!SocketCommon_parse_ip(ip_str, &ip_family))
        return -1;

    /* Family must match */
    if (ip_family != cidr_family)
        return 0;

    /* Convert IP string to bytes */
    if (ip_family == AF_INET)
    {
        struct in_addr addr4;
        if (inet_pton(AF_INET, ip_str, &addr4) != 1)
            return -1;
        memcpy(ip, &addr4, 4);
    }
    else if (ip_family == AF_INET6)
    {
        struct in6_addr addr6;
        if (inet_pton(AF_INET6, ip_str, &addr6) != 1)
            return -1;
        memcpy(ip, &addr6, 16);
    }
    else
    {
        return -1;
    }

    /* Apply mask to IP */
    socketcommon_apply_mask(ip, prefix_len, ip_family);

    /* Compare network addresses */
    if (ip_family == AF_INET)
    {
        for (i = 0; i < 4; i++)
        {
            if (ip[i] != network[i])
                return 0;
        }
    }
    else if (ip_family == AF_INET6)
    {
        for (i = 0; i < 16; i++)
        {
            if (ip[i] != network[i])
                return 0;
        }
    }

    return 1;
}
