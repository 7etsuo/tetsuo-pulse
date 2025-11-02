/**
 * SocketDgram.c - UDP/datagram socket implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "socket/SocketDgram.h"
#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "socket/SocketCommon.h"

#define T SocketDgram_T

/* Port string buffer size for snprintf */

Except_T SocketDgram_Failed = {"Datagram socket operation failed"};

/* Thread-local exception for detailed error messages */
#ifdef _WIN32
static __declspec(thread) Except_T SocketDgram_DetailedException;
#else
static __thread Except_T SocketDgram_DetailedException;
#endif

/* Macro to raise exception with detailed error message */
#define RAISE_DGRAM_ERROR(exception)                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        SocketDgram_DetailedException = (exception);                                                                   \
        SocketDgram_DetailedException.reason = socket_error_buf;                                                       \
        RAISE(SocketDgram_DetailedException);                                                                          \
    } while (0)

struct T
{
    int fd;
    struct sockaddr_storage addr;
    socklen_t addrlen;
    Arena_T arena;
};

/* Static helper functions */

/**
 * validate_dgram_port - Validate port is in valid range
 * @port: Port number to validate
 *
 * Raises: SocketDgram_Failed if port is invalid
 */
static void validate_dgram_port(int port)
{
    SocketCommon_validate_port(port, SocketDgram_Failed);
}

/**
 * validate_dgram_hostname - Validate hostname length
 * @host: Hostname to validate
 *
 * Raises: SocketDgram_Failed if hostname too long
 */
static void validate_dgram_hostname(const char *host)
{
    SocketCommon_validate_hostname(host, SocketDgram_Failed);
}

/**
 * setup_sendto_hints - Initialize addrinfo hints for sendto operations
 * @hints: Hints structure to initialize
 */
static void setup_sendto_hints(struct addrinfo *hints)
{
    SocketCommon_setup_hints(hints, SOCKET_DGRAM_TYPE, 0);
}

/**
 * resolve_sendto_address - Resolve address for sendto operation
 * @host: Hostname to resolve
 * @port: Port number
 * @res: Output resolved addresses
 *
 * Returns: 0 on success, raises exception on failure
 *
 * Raises: SocketDgram_Failed on resolution failure
 */
static int resolve_sendto_address(const char *host, int port, struct addrinfo **res)
{
    struct addrinfo hints;
    char port_str[SOCKET_PORT_STR_BUFSIZE];
    int result;

    result = snprintf(port_str, sizeof(port_str), "%d", port);
    assert(result > 0 && result < (int)sizeof(port_str));

    setup_sendto_hints(&hints);

    result = getaddrinfo(host, port_str, &hints, res);
    if (result != 0)
    {
        SOCKET_ERROR_MSG("Invalid host/IP address: %.*s (%s)", SOCKET_ERROR_MAX_HOSTNAME, host, gai_strerror(result));
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }

    return 0;
}

/**
 * perform_sendto - Send datagram to resolved address
 * @socket: Socket to send from
 * @buf: Data buffer
 * @len: Data length
 * @res: Resolved address info
 *
 * Returns: Bytes sent or 0 on EAGAIN/EWOULDBLOCK
 *
 * Raises: SocketDgram_Failed on send failure
 */
static ssize_t perform_sendto(T socket, const void *buf, size_t len, struct addrinfo *res)
{
    ssize_t sent = sendto(socket->fd, buf, len, 0, res->ai_addr, res->ai_addrlen);

    if (sent < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;

        /* Note: We can't include host/port in error since res is freed */
        SOCKET_ERROR_FMT("Failed to send datagram");
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }

    return sent;
}

/**
 * perform_recvfrom - Receive datagram from socket
 * @socket: Socket to receive from
 * @buf: Data buffer
 * @len: Buffer length
 * @addr: Output sender address
 * @addrlen: Input/output address length
 *
 * Returns: Bytes received or 0 on EAGAIN/EWOULDBLOCK
 *
 * Raises: SocketDgram_Failed on receive failure
 */
static ssize_t perform_recvfrom(T socket, void *buf, size_t len, struct sockaddr_storage *addr, socklen_t *addrlen)
{
    ssize_t received = recvfrom(socket->fd, buf, len, 0, (struct sockaddr *)addr, addrlen);

    if (received < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;

        SOCKET_ERROR_FMT("Failed to receive datagram");
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }

    return received;
}

/**
 * extract_sender_info - Extract sender address and port information
 * @addr: Sender address structure
 * @addrlen: Address length
 * @host: Output host buffer
 * @host_len: Host buffer length
 * @port: Output port pointer
 */
static void extract_sender_info(const struct sockaddr_storage *addr, socklen_t addrlen,
                               char *host, size_t host_len, int *port)
{
    char serv[SOCKET_NI_MAXSERV];
    int result;

    result = getnameinfo((struct sockaddr *)addr, addrlen, host, host_len, serv, SOCKET_NI_MAXSERV,
                         SOCKET_NI_NUMERICHOST | SOCKET_NI_NUMERICSERV);

    if (result == 0)
    {
        char *endptr;
        long port_long = strtol(serv, &endptr, 10);
        if (*endptr == '\0' && port_long > 0 && port_long <= 65535)
        {
            *port = (int)port_long;
        }
        else
        {
            *port = 0;
        }
    }
    else
    {
        /* Failed to get address info - set defaults */
        if (host_len > 0)
            host[0] = '\0';
        *port = 0;
    }
}

/**
 * resolve_multicast_group - Resolve multicast group address
 * @group: Multicast group address
 * @res: Output resolved address info
 *
 * Raises: SocketDgram_Failed on resolution failure
 */
static void resolve_multicast_group(const char *group, struct addrinfo **res)
{
    struct addrinfo hints;
    int result;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = SOCKET_AF_UNSPEC;
    hints.ai_socktype = SOCKET_DGRAM_TYPE;
    hints.ai_flags = SOCKET_AI_NUMERICHOST;

    result = getaddrinfo(group, NULL, &hints, res);
    if (result != 0)
    {
        SOCKET_ERROR_MSG("Invalid multicast group address: %s (%s)", group, gai_strerror(result));
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }
}

/**
 * setup_ipv4_multicast_interface - Set up IPv4 multicast interface
 * @mreq: Multicast request structure
 * @interface: Interface address or NULL
 *
 * Raises: SocketDgram_Failed on invalid interface
 */
static void setup_ipv4_multicast_interface(struct ip_mreq *mreq, const char *interface)
{
    if (interface)
    {
        if (inet_pton(SOCKET_AF_INET, interface, &mreq->imr_interface) <= 0)
        {
            SOCKET_ERROR_MSG("Invalid interface address: %s", interface);
            RAISE_DGRAM_ERROR(SocketDgram_Failed);
        }
    }
    else
    {
        mreq->imr_interface.s_addr = INADDR_ANY;
    }
}

/**
 * join_ipv4_multicast - Join IPv4 multicast group
 * @socket: Socket to join
 * @group_addr: Multicast group address
 * @interface: Interface address or NULL
 *
 * Raises: SocketDgram_Failed on join failure
 */
static void join_ipv4_multicast(T socket, struct in_addr group_addr, const char *interface)
{
    struct ip_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.imr_multiaddr = group_addr;
    setup_ipv4_multicast_interface(&mreq, interface);

    if (setsockopt(socket->fd, SOCKET_IPPROTO_IP, SOCKET_IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to join IPv4 multicast group");
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }
}

/**
 * join_ipv6_multicast - Join IPv6 multicast group
 * @socket: Socket to join
 * @group_addr: Multicast group address
 *
 * Raises: SocketDgram_Failed on join failure
 */
static void join_ipv6_multicast(T socket, struct in6_addr group_addr)
{
    struct ipv6_mreq mreq6;
    memset(&mreq6, 0, sizeof(mreq6));
    mreq6.ipv6mr_multiaddr = group_addr;
    mreq6.ipv6mr_interface = SOCKET_MULTICAST_DEFAULT_INTERFACE;

    if (setsockopt(socket->fd, SOCKET_IPPROTO_IPV6, SOCKET_IPV6_ADD_MEMBERSHIP, &mreq6, sizeof(mreq6)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to join IPv6 multicast group");
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }
}

/**
 * leave_ipv4_multicast - Leave IPv4 multicast group
 * @socket: Socket to leave
 * @group_addr: Multicast group address
 * @interface: Interface address or NULL
 *
 * Raises: SocketDgram_Failed on leave failure
 */
static void leave_ipv4_multicast(T socket, struct in_addr group_addr, const char *interface)
{
    struct ip_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.imr_multiaddr = group_addr;
    setup_ipv4_multicast_interface(&mreq, interface);

    if (setsockopt(socket->fd, SOCKET_IPPROTO_IP, SOCKET_IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to leave IPv4 multicast group");
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }
}

/**
 * leave_ipv6_multicast - Leave IPv6 multicast group
 * @socket: Socket to leave
 * @group_addr: Multicast group address
 *
 * Raises: SocketDgram_Failed on leave failure
 */
static void leave_ipv6_multicast(T socket, struct in6_addr group_addr)
{
    struct ipv6_mreq mreq6;
    memset(&mreq6, 0, sizeof(mreq6));
    mreq6.ipv6mr_multiaddr = group_addr;
    mreq6.ipv6mr_interface = SOCKET_MULTICAST_DEFAULT_INTERFACE;

    if (setsockopt(socket->fd, SOCKET_IPPROTO_IPV6, SOCKET_IPV6_DROP_MEMBERSHIP, &mreq6, sizeof(mreq6)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to leave IPv6 multicast group");
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }
}

/**
 * setup_dgram_bind_hints - Initialize addrinfo hints for datagram binding
 * @hints: Hints structure to initialize
 */
static void setup_dgram_bind_hints(struct addrinfo *hints)
{
    SocketCommon_setup_hints(hints, SOCKET_DGRAM_TYPE, SOCKET_AI_PASSIVE);
}

/**
 * setup_dgram_connect_hints - Initialize addrinfo hints for datagram connecting
 * @hints: Hints structure to initialize
 */
static void setup_dgram_connect_hints(struct addrinfo *hints)
{
    SocketCommon_setup_hints(hints, SOCKET_DGRAM_TYPE, 0);
}

/**
 * try_dgram_bind_addresses - Try binding datagram socket to resolved addresses
 * @socket: Socket to bind
 * @res: Resolved address list
 * @socket_family: Socket's address family
 *
 * Returns: 0 on success, -1 on failure
 */
static int try_dgram_bind_addresses(T socket, struct addrinfo *res, int socket_family)
{
    struct addrinfo *rp;

    for (rp = res; rp != NULL; rp = rp->ai_next)
    {
        if (socket_family != SOCKET_AF_UNSPEC && rp->ai_family != socket_family)
            continue;

        if (rp->ai_family == SOCKET_AF_INET6 && socket_family == SOCKET_AF_INET6)
        {
            int no = 0;
            setsockopt(socket->fd, SOCKET_IPPROTO_IPV6, SOCKET_IPV6_V6ONLY, &no, sizeof(no));
        }

        if (bind(socket->fd, rp->ai_addr, rp->ai_addrlen) == 0)
        {
            memcpy(&socket->addr, rp->ai_addr, rp->ai_addrlen);
            socket->addrlen = rp->ai_addrlen;
            return 0;
        }
    }
    return -1;
}

/**
 * handle_dgram_bind_error - Handle datagram bind error
 * @host: Host string
 * @port: Port number
 */
static void handle_dgram_bind_error(const char *host, int port)
{
    const char *safe_host = host ? host : "any";

    if (errno == EADDRINUSE)
    {
        SOCKET_ERROR_FMT(SOCKET_EADDRINUSE ": %.*s:%d", SOCKET_ERROR_MAX_HOSTNAME, safe_host, port);
    }
    else if (errno == EACCES)
    {
        SOCKET_ERROR_FMT("Permission denied to bind to port %d", port);
    }
    else
    {
        SOCKET_ERROR_FMT("Failed to bind to %.*s:%d", SOCKET_ERROR_MAX_HOSTNAME, safe_host, port);
    }
}

/**
 * try_dgram_connect_addresses - Try connecting datagram socket to resolved addresses
 * @socket: Socket to connect
 * @res: Resolved address list
 * @socket_family: Socket's address family
 *
 * Returns: 0 on success, -1 on failure
 */
static int try_dgram_connect_addresses(T socket, struct addrinfo *res, int socket_family)
{
    struct addrinfo *rp;

    for (rp = res; rp != NULL; rp = rp->ai_next)
    {
        if (socket_family != SOCKET_AF_UNSPEC && rp->ai_family != socket_family)
            continue;

        if (connect(socket->fd, rp->ai_addr, rp->ai_addrlen) == 0)
        {
            memcpy(&socket->addr, rp->ai_addr, rp->ai_addrlen);
            socket->addrlen = rp->ai_addrlen;
            return 0;
        }
    }
    return -1;
}

/**
 * get_dgram_socket_family - Get datagram socket's address family
 * @socket: Socket to query
 *
 * Returns: Socket family or SOCKET_AF_UNSPEC on error
 */
static int get_dgram_socket_family(T socket)
{
    int socket_family = SOCKET_AF_UNSPEC;
    socklen_t len = sizeof(socket_family);

    if (getsockopt(socket->fd, SOCKET_SOL_SOCKET, SOCKET_SO_DOMAIN, &socket_family, &len) < 0)
        socket_family = SOCKET_AF_UNSPEC;

    return socket_family;
}

T SocketDgram_new(int domain, int protocol)
{
    T sock;
    int fd;

    fd = socket(domain, SOCKET_DGRAM_TYPE, protocol);
    if (fd < 0)
    {
        SOCKET_ERROR_FMT("Failed to create datagram socket (domain=%d, protocol=%d)", domain, protocol);
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }

    sock = calloc(1, sizeof(*sock));
    if (sock == NULL)
    {
        int saved_errno = errno;
        SAFE_CLOSE(fd);
        errno = saved_errno;
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate socket structure");
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }

    sock->fd = -1;
    sock->addrlen = sizeof(sock->addr);

    sock->arena = Arena_new();
    if (!sock->arena)
    {
        int saved_errno = errno;
        SAFE_CLOSE(fd);
        free(sock);
        errno = saved_errno;
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate socket arena");
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }

    sock->fd = fd;

    return sock;
}

void SocketDgram_free(T *socket)
{
    assert(socket && *socket);

    if ((*socket)->fd >= 0)
    {
        int fd = (*socket)->fd;
        (*socket)->fd = -1;
        SAFE_CLOSE(fd);
    }

    if ((*socket)->arena)
        Arena_dispose(&(*socket)->arena);

    free(*socket);
    *socket = NULL;
}

/**
 * normalize_dgram_host - Normalize host for datagram binding
 * @host: Host string to normalize
 *
 * Returns: NULL if wildcard, normalized host otherwise
 */
static const char *normalize_dgram_host(const char *host)
{
    if (host != NULL && strcmp(host, "0.0.0.0") != 0 && strcmp(host, "::") != 0)
        return host;
    return NULL;
}

void SocketDgram_bind(T socket, const char *host, int port)
{
    struct addrinfo hints, *res = NULL;
    int socket_family;

    assert(socket);
    validate_dgram_port(port);

    host = normalize_dgram_host(host);
    if (host)
        validate_dgram_hostname(host);

    setup_dgram_bind_hints(&hints);
    SocketCommon_resolve_address(host, port, &hints, &res, SocketDgram_Failed, SOCKET_AF_UNSPEC, 1);

    socket_family = get_dgram_socket_family(socket);

    if (try_dgram_bind_addresses(socket, res, socket_family) == 0)
    {
        freeaddrinfo(res);
        return;
    }

    handle_dgram_bind_error(host, port);
    freeaddrinfo(res);
    RAISE_DGRAM_ERROR(SocketDgram_Failed);
}

/**
 * handle_dgram_connect_error - Handle datagram connect error
 * @host: Host string
 * @port: Port number
 */
static void handle_dgram_connect_error(const char *host, int port)
{
    SOCKET_ERROR_FMT("Failed to connect to %.*s:%d", SOCKET_ERROR_MAX_HOSTNAME, host, port);
}

void SocketDgram_connect(T socket, const char *host, int port)
{
    struct addrinfo hints, *res = NULL;
    int socket_family;

    assert(socket);
    assert(host);

    validate_dgram_port(port);
    validate_dgram_hostname(host);
    setup_dgram_connect_hints(&hints);
    SocketCommon_resolve_address(host, port, &hints, &res, SocketDgram_Failed, SOCKET_AF_UNSPEC, 1);

    socket_family = get_dgram_socket_family(socket);

    if (try_dgram_connect_addresses(socket, res, socket_family) == 0)
    {
        freeaddrinfo(res);
        return;
    }

    handle_dgram_connect_error(host, port);
    freeaddrinfo(res);
    RAISE_DGRAM_ERROR(SocketDgram_Failed);
}

ssize_t SocketDgram_sendto(T socket, const void *buf, size_t len, const char *host, int port)
{
    struct addrinfo *res = NULL;
    ssize_t sent;

    assert(socket);
    assert(buf);
    assert(len > 0);
    assert(host);

    validate_dgram_port(port);
    validate_dgram_hostname(host);
    resolve_sendto_address(host, port, &res);

    sent = perform_sendto(socket, buf, len, res);
    freeaddrinfo(res);

    return sent;
}

ssize_t SocketDgram_recvfrom(T socket, void *buf, size_t len, char *host, size_t host_len, int *port)
{
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    ssize_t received;

    assert(socket);
    assert(buf);
    assert(len > 0);

    received = perform_recvfrom(socket, buf, len, &addr, &addrlen);

    /* Get sender address and port if requested */
    if (host && host_len > 0 && port)
    {
        extract_sender_info(&addr, addrlen, host, host_len, port);
    }

    return received;
}

ssize_t SocketDgram_send(T socket, const void *buf, size_t len)
{
    ssize_t sent;

    assert(socket);
    assert(buf);
    assert(len > 0);

    sent = send(socket->fd, buf, len, 0);

    if (sent < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;

        SOCKET_ERROR_FMT("Failed to send datagram");
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }

    return sent;
}

ssize_t SocketDgram_recv(T socket, void *buf, size_t len)
{
    ssize_t received;

    assert(socket);
    assert(buf);
    assert(len > 0);

    received = recv(socket->fd, buf, len, 0);

    if (received < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;

        SOCKET_ERROR_FMT("Failed to receive datagram");
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }

    return received;
}

void SocketDgram_setnonblocking(T socket)
{
    int flags;

    assert(socket);

    flags = fcntl(socket->fd, F_GETFL, 0);
    if (flags < 0)
    {
        SOCKET_ERROR_FMT("Failed to get socket flags");
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }

    if (fcntl(socket->fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        SOCKET_ERROR_FMT("Failed to set non-blocking mode");
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }
}

void SocketDgram_setreuseaddr(T socket)
{
    int optval = 1;

    assert(socket);

    if (setsockopt(socket->fd, SOCKET_SOL_SOCKET, SOCKET_SO_REUSEADDR, &optval, sizeof(optval)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to set SO_REUSEADDR");
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }
}

void SocketDgram_setbroadcast(T socket, int enable)
{
    int optval = enable ? 1 : 0;

    assert(socket);

    if (setsockopt(socket->fd, SOCKET_SOL_SOCKET, SOCKET_SO_BROADCAST, &optval, sizeof(optval)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to set SO_BROADCAST");
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }
}

/**
 * join_multicast_by_family - Join multicast group based on address family
 * @socket: Socket to join
 * @res: Resolved address info
 * @interface: Interface address or NULL
 *
 * Raises: SocketDgram_Failed on unsupported family or join failure
 */
static void join_multicast_by_family(T socket, struct addrinfo *res, const char *interface)
{
    if (res->ai_family == SOCKET_AF_INET)
    {
        join_ipv4_multicast(socket, ((struct sockaddr_in *)res->ai_addr)->sin_addr, interface);
    }
    else if (res->ai_family == SOCKET_AF_INET6)
    {
        join_ipv6_multicast(socket, ((struct sockaddr_in6 *)res->ai_addr)->sin6_addr);
    }
    else
    {
        SOCKET_ERROR_MSG("Unsupported address family for multicast");
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }
}

void SocketDgram_joinmulticast(T socket, const char *group, const char *interface)
{
    struct addrinfo *res = NULL;

    assert(socket);
    assert(group);

    resolve_multicast_group(group, &res);
    join_multicast_by_family(socket, res, interface);
    freeaddrinfo(res);
}

/**
 * leave_multicast_by_family - Leave multicast group based on address family
 * @socket: Socket to leave
 * @res: Resolved address info
 * @interface: Interface address or NULL
 *
 * Raises: SocketDgram_Failed on unsupported family or leave failure
 */
static void leave_multicast_by_family(T socket, struct addrinfo *res, const char *interface)
{
    if (res->ai_family == SOCKET_AF_INET)
    {
        leave_ipv4_multicast(socket, ((struct sockaddr_in *)res->ai_addr)->sin_addr, interface);
    }
    else if (res->ai_family == SOCKET_AF_INET6)
    {
        leave_ipv6_multicast(socket, ((struct sockaddr_in6 *)res->ai_addr)->sin6_addr);
    }
    else
    {
        SOCKET_ERROR_MSG("Unsupported address family for multicast");
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }
}

void SocketDgram_leavemulticast(T socket, const char *group, const char *interface)
{
    struct addrinfo *res = NULL;

    assert(socket);
    assert(group);

    resolve_multicast_group(group, &res);
    leave_multicast_by_family(socket, res, interface);
    freeaddrinfo(res);
}

/**
 * validate_ttl_value - Validate TTL value
 * @ttl: TTL value to validate
 *
 * Raises: SocketDgram_Failed if invalid
 */
static void validate_ttl_value(int ttl)
{
    if (ttl < 1 || ttl > 255)
    {
        SOCKET_ERROR_MSG("Invalid TTL value: %d (must be 1-255)", ttl);
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }
}

/**
 * get_socket_domain - Get socket address family
 * @socket: Socket to query
 *
 * Returns: Socket family or SOCKET_AF_UNSPEC on error
 */
static int get_socket_domain(T socket)
{
    int socket_family = SOCKET_AF_UNSPEC;
    socklen_t len = sizeof(socket_family);

    if (getsockopt(socket->fd, SOL_SOCKET, SO_DOMAIN, &socket_family, &len) < 0)
    {
        SOCKET_ERROR_FMT("Failed to get socket domain");
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }
    return socket_family;
}

/**
 * set_ipv4_ttl - Set IPv4 TTL value
 * @socket: Socket to configure
 * @ttl: TTL value
 *
 * Raises: SocketDgram_Failed on failure
 */
static void set_ipv4_ttl(T socket, int ttl)
{
    if (setsockopt(socket->fd, SOCKET_IPPROTO_IP, SOCKET_IP_TTL, &ttl, sizeof(ttl)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to set IPv4 TTL");
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }
}

/**
 * set_ipv6_hop_limit - Set IPv6 hop limit
 * @socket: Socket to configure
 * @ttl: Hop limit value
 *
 * Raises: SocketDgram_Failed on failure
 */
static void set_ipv6_hop_limit(T socket, int ttl)
{
    if (setsockopt(socket->fd, SOCKET_IPPROTO_IPV6, SOCKET_IPV6_UNICAST_HOPS, &ttl, sizeof(ttl)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to set IPv6 hop limit");
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }
}

/**
 * set_ttl_by_family - Set TTL based on socket address family
 * @socket: Socket to configure
 * @socket_family: Socket address family
 * @ttl: TTL value
 *
 * Raises: SocketDgram_Failed on unsupported family or failure
 */
static void set_ttl_by_family(T socket, int socket_family, int ttl)
{
    if (socket_family == SOCKET_AF_INET)
        set_ipv4_ttl(socket, ttl);
    else if (socket_family == SOCKET_AF_INET6)
        set_ipv6_hop_limit(socket, ttl);
    else
    {
        SOCKET_ERROR_MSG("Unsupported address family for TTL");
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }
}

void SocketDgram_setttl(T socket, int ttl)
{
    int socket_family;

    assert(socket);
    validate_ttl_value(ttl);
    socket_family = get_socket_domain(socket);
    set_ttl_by_family(socket, socket_family, ttl);
}

void SocketDgram_settimeout(T socket, int timeout_sec)
{
    struct timeval tv;

    assert(socket);

    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    if (setsockopt(socket->fd, SOCKET_SOL_SOCKET, SOCKET_SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to set receive timeout");
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }

    if (setsockopt(socket->fd, SOCKET_SOL_SOCKET, SOCKET_SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to set send timeout");
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }
}

int SocketDgram_fd(const T socket)
{
    assert(socket);
    return socket->fd;
}

#undef T
