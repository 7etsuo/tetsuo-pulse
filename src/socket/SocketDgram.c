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

#define T SocketDgram_T

/* Port string buffer size for snprintf */
#define PORT_STR_BUFSIZE 16

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
        if (!SOCKET_VALID_PORT(port))
        {
                SOCKET_ERROR_MSG("Invalid port number: %d (must be 1-65535)", port);
                RAISE_DGRAM_ERROR(SocketDgram_Failed);
        }
}

/**
 * validate_dgram_hostname - Validate hostname length
 * @host: Hostname to validate
 *
 * Raises: SocketDgram_Failed if hostname too long
 */
static void validate_dgram_hostname(const char *host)
{
        size_t host_len = strlen(host);

        if (host_len > SOCKET_ERROR_MAX_HOSTNAME)
        {
                SOCKET_ERROR_MSG("Host name too long (max %d characters)", SOCKET_ERROR_MAX_HOSTNAME);
                RAISE_DGRAM_ERROR(SocketDgram_Failed);
        }
}

/**
 * setup_dgram_bind_hints - Initialize addrinfo hints for datagram binding
 * @hints: Hints structure to initialize
 */
static void setup_dgram_bind_hints(struct addrinfo *hints)
{
        memset(hints, 0, sizeof(*hints));
        hints->ai_family = AF_UNSPEC;
        hints->ai_socktype = SOCK_DGRAM;
        hints->ai_flags = AI_PASSIVE;
        hints->ai_protocol = 0;
}

/**
 * setup_dgram_connect_hints - Initialize addrinfo hints for datagram connecting
 * @hints: Hints structure to initialize
 */
static void setup_dgram_connect_hints(struct addrinfo *hints)
{
        memset(hints, 0, sizeof(*hints));
        hints->ai_family = AF_UNSPEC;
        hints->ai_socktype = SOCK_DGRAM;
        hints->ai_protocol = 0;
}

/**
 * resolve_dgram_address - Resolve datagram address
 * @host: Hostname or NULL for wildcard
 * @port: Port number
 * @hints: Address hints
 * @res: Output resolved addresses
 *
 * Returns: 0 on success, raises exception on failure
 */
static int resolve_dgram_address(const char *host, int port, const struct addrinfo *hints, struct addrinfo **res)
{
        char port_str[PORT_STR_BUFSIZE];
        int result;

        result = snprintf(port_str, sizeof(port_str), "%d", port);
        assert(result > 0 && result < (int)sizeof(port_str));

        result = getaddrinfo(host, port_str, hints, res);
        if (result != 0)
        {
                SOCKET_ERROR_MSG("Invalid host/IP address: %.*s (%s)", SOCKET_ERROR_MAX_HOSTNAME,
                                 host ? host : "any", gai_strerror(result));
                RAISE_DGRAM_ERROR(SocketDgram_Failed);
        }
        return 0;
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
                if (socket_family != AF_UNSPEC && rp->ai_family != socket_family)
                        continue;

                if (rp->ai_family == AF_INET6 && socket_family == AF_INET6)
                {
                        int no = 0;
                        setsockopt(socket->fd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no));
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
                if (socket_family != AF_UNSPEC && rp->ai_family != socket_family)
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
 * Returns: Socket family or AF_UNSPEC on error
 */
static int get_dgram_socket_family(T socket)
{
        int socket_family = AF_UNSPEC;
        socklen_t len = sizeof(socket_family);

        if (getsockopt(socket->fd, SOL_SOCKET, SO_DOMAIN, &socket_family, &len) < 0)
                socket_family = AF_UNSPEC;

        return socket_family;
}

T SocketDgram_new(int domain, int protocol)
{
    T sock;
    int fd;

    fd = socket(domain, SOCK_DGRAM, protocol);
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

void SocketDgram_bind(T socket, const char *host, int port)
{
        struct addrinfo hints, *res = NULL;
        int socket_family;

        assert(socket);

        validate_dgram_port(port);

        if (host != NULL && strcmp(host, "0.0.0.0") != 0 && strcmp(host, "::") != 0)
                validate_dgram_hostname(host);
        else
                host = NULL;

        setup_dgram_bind_hints(&hints);
        resolve_dgram_address(host, port, &hints, &res);

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

void SocketDgram_connect(T socket, const char *host, int port)
{
        struct addrinfo hints, *res = NULL;
        int socket_family;

        assert(socket);
        assert(host);

        validate_dgram_port(port);
        validate_dgram_hostname(host);
        setup_dgram_connect_hints(&hints);
        resolve_dgram_address(host, port, &hints, &res);

        socket_family = get_dgram_socket_family(socket);

        if (try_dgram_connect_addresses(socket, res, socket_family) == 0)
        {
                freeaddrinfo(res);
                return;
        }

        SOCKET_ERROR_FMT("Failed to connect to %.*s:%d", SOCKET_ERROR_MAX_HOSTNAME, host, port);
        freeaddrinfo(res);
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
}

ssize_t SocketDgram_sendto(T socket, const void *buf, size_t len, const char *host, int port)
{
    struct addrinfo hints, *res = NULL;
    char port_str[PORT_STR_BUFSIZE];
    int result;
    ssize_t sent;
    size_t host_len;

    assert(socket);
    assert(buf);
    assert(len > 0);
    assert(host);

    if (!SOCKET_VALID_PORT(port))
    {
        SOCKET_ERROR_MSG("Invalid port number: %d (must be 1-65535)", port);
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }

    host_len = strlen(host);
    if (host_len > SOCKET_ERROR_MAX_HOSTNAME)
    {
        SOCKET_ERROR_MSG("Host name too long (max %d characters)", SOCKET_ERROR_MAX_HOSTNAME);
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }

    result = snprintf(port_str, sizeof(port_str), "%d", port);
    assert(result > 0 && result < (int)sizeof(port_str));

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = 0;

    result = getaddrinfo(host, port_str, &hints, &res);
    if (result != 0)
    {
        SOCKET_ERROR_MSG("Invalid host/IP address: %.*s (%s)", SOCKET_ERROR_MAX_HOSTNAME, host, gai_strerror(result));
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }

    sent = sendto(socket->fd, buf, len, 0, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    if (sent < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;

        SOCKET_ERROR_FMT("Failed to send datagram to %.*s:%d", SOCKET_ERROR_MAX_HOSTNAME, host, port);
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }

    return sent;
}

ssize_t SocketDgram_recvfrom(T socket, void *buf, size_t len, char *host, size_t host_len, int *port)
{
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    ssize_t received;
    char serv[NI_MAXSERV];
    int result;

    assert(socket);
    assert(buf);
    assert(len > 0);

    received = recvfrom(socket->fd, buf, len, 0, (struct sockaddr *)&addr, &addrlen);

    if (received < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;

        SOCKET_ERROR_FMT("Failed to receive datagram");
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }

    /* Get sender address and port if requested */
    if (host && host_len > 0 && port)
    {
        result = getnameinfo((struct sockaddr *)&addr, addrlen, host, host_len, serv, NI_MAXSERV,
                             NI_NUMERICHOST | NI_NUMERICSERV);

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

    if (setsockopt(socket->fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to set SO_REUSEADDR");
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }
}

void SocketDgram_setbroadcast(T socket, int enable)
{
    int optval = enable ? 1 : 0;

    assert(socket);

    if (setsockopt(socket->fd, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to set SO_BROADCAST");
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }
}

void SocketDgram_joinmulticast(T socket, const char *group, const char *interface)
{
    struct addrinfo hints, *res = NULL;
    int result;

    assert(socket);
    assert(group);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_NUMERICHOST;

    result = getaddrinfo(group, NULL, &hints, &res);
    if (result != 0)
    {
        SOCKET_ERROR_MSG("Invalid multicast group address: %s (%s)", group, gai_strerror(result));
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }

    if (res->ai_family == AF_INET)
    {
        struct ip_mreq mreq;
        memset(&mreq, 0, sizeof(mreq));
        mreq.imr_multiaddr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;

        if (interface)
        {
            if (inet_pton(AF_INET, interface, &mreq.imr_interface) <= 0)
            {
                freeaddrinfo(res);
                SOCKET_ERROR_MSG("Invalid interface address: %s", interface);
                RAISE_DGRAM_ERROR(SocketDgram_Failed);
            }
        }
        else
        {
            mreq.imr_interface.s_addr = INADDR_ANY;
        }

        if (setsockopt(socket->fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
        {
            freeaddrinfo(res);
            SOCKET_ERROR_FMT("Failed to join IPv4 multicast group: %s", group);
            RAISE_DGRAM_ERROR(SocketDgram_Failed);
        }
    }
    else if (res->ai_family == AF_INET6)
    {
        struct ipv6_mreq mreq6;
        memset(&mreq6, 0, sizeof(mreq6));
        mreq6.ipv6mr_multiaddr = ((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
        mreq6.ipv6mr_interface = 0; /* Default interface */

        if (setsockopt(socket->fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq6, sizeof(mreq6)) < 0)
        {
            freeaddrinfo(res);
            SOCKET_ERROR_FMT("Failed to join IPv6 multicast group: %s", group);
            RAISE_DGRAM_ERROR(SocketDgram_Failed);
        }
    }
    else
    {
        freeaddrinfo(res);
        SOCKET_ERROR_MSG("Unsupported address family for multicast");
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }

    freeaddrinfo(res);
}

void SocketDgram_leavemulticast(T socket, const char *group, const char *interface)
{
    struct addrinfo hints, *res = NULL;
    int result;

    assert(socket);
    assert(group);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_NUMERICHOST;

    result = getaddrinfo(group, NULL, &hints, &res);
    if (result != 0)
    {
        SOCKET_ERROR_MSG("Invalid multicast group address: %s (%s)", group, gai_strerror(result));
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }

    if (res->ai_family == AF_INET)
    {
        struct ip_mreq mreq;
        memset(&mreq, 0, sizeof(mreq));
        mreq.imr_multiaddr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;

        if (interface)
        {
            if (inet_pton(AF_INET, interface, &mreq.imr_interface) <= 0)
            {
                freeaddrinfo(res);
                SOCKET_ERROR_MSG("Invalid interface address: %s", interface);
                RAISE_DGRAM_ERROR(SocketDgram_Failed);
            }
        }
        else
        {
            mreq.imr_interface.s_addr = INADDR_ANY;
        }

        if (setsockopt(socket->fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
        {
            freeaddrinfo(res);
            SOCKET_ERROR_FMT("Failed to leave IPv4 multicast group: %s", group);
            RAISE_DGRAM_ERROR(SocketDgram_Failed);
        }
    }
    else if (res->ai_family == AF_INET6)
    {
        struct ipv6_mreq mreq6;
        memset(&mreq6, 0, sizeof(mreq6));
        mreq6.ipv6mr_multiaddr = ((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
        mreq6.ipv6mr_interface = 0;

        if (setsockopt(socket->fd, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, &mreq6, sizeof(mreq6)) < 0)
        {
            freeaddrinfo(res);
            SOCKET_ERROR_FMT("Failed to leave IPv6 multicast group: %s", group);
            RAISE_DGRAM_ERROR(SocketDgram_Failed);
        }
    }
    else
    {
        freeaddrinfo(res);
        SOCKET_ERROR_MSG("Unsupported address family for multicast");
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }

    freeaddrinfo(res);
}

void SocketDgram_setttl(T socket, int ttl)
{
    int socket_family = AF_UNSPEC;
    socklen_t len = sizeof(socket_family);

    assert(socket);

    if (ttl < 1 || ttl > 255)
    {
        SOCKET_ERROR_MSG("Invalid TTL value: %d (must be 1-255)", ttl);
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }

    if (getsockopt(socket->fd, SOL_SOCKET, SO_DOMAIN, &socket_family, &len) < 0)
    {
        SOCKET_ERROR_FMT("Failed to get socket domain");
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }

    if (socket_family == AF_INET)
    {
        if (setsockopt(socket->fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
        {
            SOCKET_ERROR_FMT("Failed to set IPv4 TTL");
            RAISE_DGRAM_ERROR(SocketDgram_Failed);
        }
    }
    else if (socket_family == AF_INET6)
    {
        if (setsockopt(socket->fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl)) < 0)
        {
            SOCKET_ERROR_FMT("Failed to set IPv6 hop limit");
            RAISE_DGRAM_ERROR(SocketDgram_Failed);
        }
    }
    else
    {
        SOCKET_ERROR_MSG("Unsupported address family for TTL");
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }
}

void SocketDgram_settimeout(T socket, int timeout_sec)
{
    struct timeval tv;

    assert(socket);

    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    if (setsockopt(socket->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to set receive timeout");
        RAISE_DGRAM_ERROR(SocketDgram_Failed);
    }

    if (setsockopt(socket->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
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
