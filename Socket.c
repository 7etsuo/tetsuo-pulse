/**
 * Socket.c - Socket abstraction layer implementation
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
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* MSG_NOSIGNAL is not portable - provide fallback
 * On platforms without MSG_NOSIGNAL (macOS, BSD), applications MUST call
 * signal(SIGPIPE, SIG_IGN) during initialization. See Socket.h documentation. */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#include "Arena.h"
#include "Except.h"
#include "Socket.h"
#include "SocketConfig.h"
#include "SocketError.h"

#define T Socket_T

/* Port string buffer size for snprintf - 16 bytes is sufficient for:
 * - Maximum port "65535" (5 digits) + null terminator = 6 bytes
 * - Extra space for safety and alignment = 10 bytes
 * Total: 16 bytes provides comfortable margin */
#define PORT_STR_BUFSIZE 16

Except_T Socket_Failed = {"Socket operation failed"};
Except_T Socket_Closed = {"Socket closed"};

/* Thread-local exception for detailed error messages
 * This is a COPY of the base exception with thread-local reason string.
 * Each thread gets its own exception instance, preventing race conditions
 * when multiple threads raise the same exception type simultaneously. */
#ifdef _WIN32
static __declspec(thread) Except_T Socket_DetailedException;
#else
static __thread Except_T Socket_DetailedException;
#endif

/* Macro to raise exception with detailed error message
 * Creates a thread-local copy of the exception with detailed reason */
#define RAISE_SOCKET_ERROR(exception)                                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        Socket_DetailedException = (exception);                                                                        \
        Socket_DetailedException.reason = socket_error_buf;                                                            \
        RAISE(Socket_DetailedException);                                                                               \
    } while (0)

struct T
{
    int fd;
    struct sockaddr_storage addr;
    socklen_t addrlen;
    char *peeraddr; /* IPv4 or IPv6 address string */
    int peerport;
    Arena_T arena;
};

T Socket_new(int domain, int type, int protocol)
{
    T sock;
    int fd;

    fd = socket(domain, type, protocol);
    if (fd < 0)
    {
        SOCKET_ERROR_FMT("Failed to create socket (domain=%d, type=%d, protocol=%d)", domain, type, protocol);
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    /* Use calloc to zero-initialize the structure, avoiding GCC -O3 false positives */
    sock = calloc(1, sizeof(*sock));
    if (sock == NULL)
    {
        int saved_errno = errno;
        SAFE_CLOSE(fd);
        errno = saved_errno;
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate socket structure");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    /* Initialize non-zero fields after calloc has zeroed the structure */
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
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    /* Now that all allocations succeeded, set the actual file descriptor */
    sock->fd = fd;

    return sock;
}

void Socket_free(T *socket)
{
    assert(socket && *socket);

    /* Always attempt to close the file descriptor */
    if ((*socket)->fd >= 0)
    {
        int fd = (*socket)->fd;
        (*socket)->fd = -1; /* Mark as closed immediately */
        SAFE_CLOSE(fd);
    }

    if ((*socket)->arena)
        Arena_dispose(&(*socket)->arena);

    free(*socket);
    *socket = NULL;
}

void Socket_bind(T socket, const char *host, int port)
{
    struct addrinfo hints, *res = NULL, *rp;
    char port_str[PORT_STR_BUFSIZE];
    int result;
    size_t host_len;

    assert(socket);

    /* Validate port - runtime check for user input */
    if (!SOCKET_VALID_PORT(port))
    {
        SOCKET_ERROR_MSG("Invalid port number: %d (must be 1-65535)", port);
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    /* Normalize wildcard addresses to NULL and validate hostname length */
    if (host == NULL || strcmp(host, "0.0.0.0") == 0 || strcmp(host, "::") == 0)
    {
        host = NULL; /* Use wildcard address */
    }
    else
    {
        /* Validate hostname length to prevent denial of service
         * SECURITY: Prevents memory exhaustion attacks via extremely long hostnames.
         * Limit of 255 chars matches DNS label length restrictions (RFC 1035). */
        host_len = strlen(host);
        if (host_len > SOCKET_ERROR_MAX_HOSTNAME)
        {
            SOCKET_ERROR_MSG("Host name too long (max %d characters)", SOCKET_ERROR_MAX_HOSTNAME);
            RAISE_SOCKET_ERROR(Socket_Failed);
        }
    }

    /* PORT_STR_BUFSIZE (16 bytes) is sufficient for port range 1-65535 (max 5 digits + null) */
    result = snprintf(port_str, sizeof(port_str), "%d", port);
    assert(result > 0 && result < (int)sizeof(port_str));

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; /* For wildcard IP address */
    hints.ai_protocol = 0;       /* Any protocol */

    result = getaddrinfo(host, port_str, &hints, &res);
    if (result != 0)
    {
        SOCKET_ERROR_MSG("Invalid host/IP address: %.*s (%s)", SOCKET_ERROR_MAX_HOSTNAME, host ? host : "any",
                         gai_strerror(result));
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    /* Get socket's address family to ensure compatibility */
    int socket_family = AF_UNSPEC;
    socklen_t len = sizeof(socket_family);

    if (getsockopt(socket->fd, SOL_SOCKET, SO_DOMAIN, &socket_family, &len) < 0)
    {
        socket_family = AF_UNSPEC;
    }

    /* Try each address until we successfully bind */
    for (rp = res; rp != NULL; rp = rp->ai_next)
    {
        /* Skip addresses that don't match socket's family if socket has a specific family */
        if (socket_family != AF_UNSPEC && rp->ai_family != socket_family)
            continue;

        /* Enable dual-stack on IPv6 sockets
         *
         * Platform behavior varies:
         * - Linux: IPV6_V6ONLY defaults to 0 (dual-stack enabled)
         * - Windows/BSD: IPV6_V6ONLY defaults to 1 (IPv6 only)
         * - Older OpenBSD: May not support dual-stack even with IPV6_V6ONLY=0
         *
         * We explicitly set to 0 for consistent cross-platform behavior.
         * If this fails (some systems don't support IPV6_V6ONLY), the
         * socket will use platform default behavior.
         *
         * Failure is non-fatal since:
         * - On Linux: default already correct (dual-stack works)
         * - On Windows/BSD: socket still works for IPv6
         * - On systems without dual-stack support: use separate IPv4/IPv6 sockets
         */
        if (rp->ai_family == AF_INET6 && socket_family == AF_INET6)
        {
            int no = 0;
            if (setsockopt(socket->fd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no)) < 0)
            {
                /* Non-fatal: dual-stack may not be supported on this platform */
                /* Socket will work but may only accept IPv6 connections */
            }
        }

        result = bind(socket->fd, rp->ai_addr, rp->ai_addrlen);
        if (result == 0)
        {
            /* Bind succeeded */
            memcpy(&socket->addr, rp->ai_addr, rp->ai_addrlen);
            socket->addrlen = rp->ai_addrlen;
            freeaddrinfo(res);
            return;
        }
    }

    /* No address succeeded */
    if (errno == EADDRINUSE)
    {
        const char *safe_host = host ? host : "any";
        SOCKET_ERROR_FMT(SOCKET_EADDRINUSE ": %.*s:%d", SOCKET_ERROR_MAX_HOSTNAME, safe_host, port);
    }
    else if (errno == EACCES)
    {
        SOCKET_ERROR_FMT("Permission denied to bind to port %d", port);
    }
    else
    {
        const char *safe_host = host ? host : "any";
        SOCKET_ERROR_FMT("Failed to bind to %.*s:%d", SOCKET_ERROR_MAX_HOSTNAME, safe_host, port);
    }

    freeaddrinfo(res);
    RAISE_SOCKET_ERROR(Socket_Failed);
}

void Socket_listen(T socket, int backlog)
{
    int result;

    assert(socket);

    /* Validate backlog parameter */
    if (backlog <= 0)
    {
        SOCKET_ERROR_MSG("Invalid backlog value: %d (must be > 0)", backlog);
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    /* Enforce configured limit */
    if (backlog > SOCKET_MAX_LISTEN_BACKLOG)
        backlog = SOCKET_MAX_LISTEN_BACKLOG;

    result = listen(socket->fd, backlog);
    if (result < 0)
    {
        SOCKET_ERROR_FMT("Failed to listen on socket (backlog=%d)", backlog);
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
}

T Socket_accept(T socket)
{
    T newsocket;
    int newfd;
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    char host[NI_MAXHOST];
    char serv[NI_MAXSERV];
    int result;

    assert(socket);

    newfd = accept(socket->fd, (struct sockaddr *)&addr, &addrlen);
    if (newfd < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return NULL;
        SOCKET_ERROR_FMT("Failed to accept connection");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    /* Use calloc to zero-initialize the structure, avoiding GCC -O3 false positives */
    newsocket = calloc(1, sizeof(*newsocket));
    if (newsocket == NULL)
    {
        int saved_errno = errno;
        SAFE_CLOSE(newfd);
        errno = saved_errno;
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate new socket");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    newsocket->arena = Arena_new();
    if (!newsocket->arena)
    {
        int saved_errno = errno;
        SAFE_CLOSE(newfd);
        free(newsocket);
        errno = saved_errno;
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate socket arena");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    newsocket->fd = newfd;
    memcpy(&newsocket->addr, &addr, addrlen);
    newsocket->addrlen = addrlen;

    /* Get peer address and port using getnameinfo for both IPv4 and IPv6 */
    result = getnameinfo((struct sockaddr *)&addr, addrlen, host, NI_MAXHOST, serv, NI_MAXSERV,
                         NI_NUMERICHOST | NI_NUMERICSERV);

    if (result == 0)
    {
        char *endptr;
        long port_long;

        size_t addr_len = strlen(host) + 1;
        newsocket->peeraddr = ALLOC(newsocket->arena, addr_len);
        if (!newsocket->peeraddr)
        {
            int saved_errno = errno;
            SAFE_CLOSE(newfd);
            Arena_dispose(&newsocket->arena);
            free(newsocket);
            errno = saved_errno;
            SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate peer address buffer");
            RAISE_SOCKET_ERROR(Socket_Failed);
        }
        strcpy(newsocket->peeraddr, host);

        /* Use strtol instead of atoi for safe integer conversion */
        errno = 0;
        port_long = strtol(serv, &endptr, 10);
        if (errno == 0 && endptr != serv && *endptr == '\0' && port_long >= 0 && port_long <= 65535)
        {
            newsocket->peerport = (int)port_long;
        }
        else
        {
            /* Invalid port - set to 0 to indicate unknown */
            newsocket->peerport = 0;
        }
    }
    else
    {
        /* Failed to get address info - connection still valid */
        newsocket->peeraddr = NULL;
        newsocket->peerport = 0;
    }

    return newsocket;
}

void Socket_connect(T socket, const char *host, int port)
{
    struct addrinfo hints, *res = NULL, *rp;
    char port_str[PORT_STR_BUFSIZE];
    int result;
    int saved_errno = 0;

    assert(socket);

    /* Validate host - runtime check for user input */
    if (host == NULL)
    {
        SOCKET_ERROR_MSG("Invalid host: NULL pointer");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    /* Validate port - runtime check for user input */
    if (!SOCKET_VALID_PORT(port))
    {
        SOCKET_ERROR_MSG("Invalid port number: %d (must be 1-65535)", port);
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    /* Validate hostname length to prevent DoS
     * SECURITY: Prevents memory exhaustion attacks via extremely long hostnames.
     * Limit of 255 chars matches DNS label length restrictions (RFC 1035). */
    if (host)
    {
        size_t host_len = strlen(host);
        if (host_len > SOCKET_ERROR_MAX_HOSTNAME)
        {
            SOCKET_ERROR_MSG("Host name too long (max %d characters)", SOCKET_ERROR_MAX_HOSTNAME);
            RAISE_SOCKET_ERROR(Socket_Failed);
        }
    }

    /* PORT_STR_BUFSIZE (16 bytes) is sufficient for port range 1-65535 (max 5 digits + null) */
    result = snprintf(port_str, sizeof(port_str), "%d", port);
    assert(result > 0 && result < (int)sizeof(port_str));

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;

    result = getaddrinfo(host, port_str, &hints, &res);
    if (result != 0)
    {
        SOCKET_ERROR_MSG("Invalid host/IP address for connect: %.*s (%s)", SOCKET_ERROR_MAX_HOSTNAME, host,
                         gai_strerror(result));
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    /* Get socket's address family */
    int socket_family = AF_UNSPEC;
    socklen_t len = sizeof(socket_family);

    if (getsockopt(socket->fd, SOL_SOCKET, SO_DOMAIN, &socket_family, &len) < 0)
    {
        socket_family = AF_UNSPEC;
    }

    /* Try each address until we successfully connect */
    for (rp = res; rp != NULL; rp = rp->ai_next)
    {
        /* Skip addresses that don't match socket's family */
        if (socket_family != AF_UNSPEC && rp->ai_family != socket_family)
            continue;

        result = connect(socket->fd, rp->ai_addr, rp->ai_addrlen);
        if (result == 0 || errno == EINPROGRESS)
        {
            /* Connect succeeded or in progress (non-blocking) */
            memcpy(&socket->addr, rp->ai_addr, rp->ai_addrlen);
            socket->addrlen = rp->ai_addrlen;
            freeaddrinfo(res);
            return;
        }
        saved_errno = errno;
    }

    /* No address succeeded */
    errno = saved_errno;
    freeaddrinfo(res);

    if (errno == ECONNREFUSED)
    {
        SOCKET_ERROR_FMT(SOCKET_ECONNREFUSED ": %.*s:%d", SOCKET_ERROR_MAX_HOSTNAME, host, port);
    }
    else if (errno == ENETUNREACH)
    {
        SOCKET_ERROR_FMT(SOCKET_ENETUNREACH ": %.*s", SOCKET_ERROR_MAX_HOSTNAME, host);
    }
    else if (errno == ETIMEDOUT)
    {
        SOCKET_ERROR_FMT(SOCKET_ETIMEDOUT ": %.*s:%d", SOCKET_ERROR_MAX_HOSTNAME, host, port);
    }
    else
    {
        SOCKET_ERROR_FMT("Failed to connect to %.*s:%d", SOCKET_ERROR_MAX_HOSTNAME, host, port);
    }
    RAISE_SOCKET_ERROR(Socket_Failed);
}

ssize_t Socket_send(T socket, const void *buf, size_t len)
{
    ssize_t result;

    assert(socket);
    assert(buf);
    assert(len > 0);

    result = send(socket->fd, buf, len, MSG_NOSIGNAL);
    if (result < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        if (errno == EPIPE)
        {
            RAISE(Socket_Closed);
        }
        if (errno == ECONNRESET)
        {
            RAISE(Socket_Closed);
        }
        SOCKET_ERROR_FMT("Send failed (len=%zu)", len);
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    return result;
}

ssize_t Socket_recv(T socket, void *buf, size_t len)
{
    ssize_t result;

    assert(socket);
    assert(buf);
    assert(len > 0);

    result = recv(socket->fd, buf, len, 0);

    if (result < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        if (errno == ECONNRESET)
        {
            RAISE(Socket_Closed);
        }
        SOCKET_ERROR_FMT("Receive failed (len=%zu)", len);
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
    else if (result == 0)
    {
        RAISE(Socket_Closed);
    }

    return result;
}

void Socket_setnonblocking(T socket)
{
    int flags;

    assert(socket);

    flags = fcntl(socket->fd, F_GETFL, 0);
    if (flags < 0)
    {
        SOCKET_ERROR_FMT("Failed to get socket flags");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    if (fcntl(socket->fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        SOCKET_ERROR_FMT("Failed to set non-blocking mode");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
}

void Socket_setreuseaddr(T socket)
{
    int opt = 1;

    assert(socket);

    if (setsockopt(socket->fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to set SO_REUSEADDR");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
}

void Socket_settimeout(T socket, int timeout_sec)
{
    struct timeval tv;

    assert(socket);

    /* Validate timeout parameter */
    if (timeout_sec < 0)
    {
        SOCKET_ERROR_MSG("Invalid timeout value: %d (must be >= 0)", timeout_sec);
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    /* Set receive timeout */
    if (setsockopt(socket->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to set receive timeout");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    /* Set send timeout */
    if (setsockopt(socket->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to set send timeout");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
}

void Socket_setkeepalive(T socket, int idle, int interval, int count)
{
    int opt = 1;

    assert(socket);

    /* Validate keepalive parameters - user input, so don't use assert */
    if (idle <= 0 || interval <= 0 || count <= 0)
    {
        SOCKET_ERROR_MSG("Invalid keepalive parameters (idle=%d, interval=%d, count=%d): all must be > 0", idle,
                         interval, count);
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    /* Enable keepalive */
    if (setsockopt(socket->fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to enable keepalive");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    /* Platform-specific TCP keepalive options
     * Linux: TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT (all supported)
     * macOS/BSD: TCP_KEEPALIVE instead of TCP_KEEPIDLE (some versions)
     * Windows: Uses different mechanism via SIO_KEEPALIVE_VALS ioctl
     * Solaris: Similar to Linux but may have different defaults */

#ifdef TCP_KEEPIDLE
    /* Set idle time before first probe */
    if (setsockopt(socket->fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to set keepalive idle time");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
#endif

#ifdef TCP_KEEPINTVL
    /* Set interval between probes */
    if (setsockopt(socket->fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to set keepalive interval");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
#endif

#ifdef TCP_KEEPCNT
    /* Set number of probes */
    if (setsockopt(socket->fd, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to set keepalive count");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
#endif
}

void Socket_setnodelay(T socket, int nodelay)
{
    assert(socket);

    if (setsockopt(socket->fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to set TCP_NODELAY");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
}

int Socket_fd(const T socket)
{
    assert(socket);
    return socket->fd;
}

const char *Socket_getpeeraddr(const T socket)
{
    assert(socket);
    return socket->peeraddr ? socket->peeraddr : "(unknown)";
}

int Socket_getpeerport(const T socket)
{
    assert(socket);
    return socket->peerport;
}

#undef T
