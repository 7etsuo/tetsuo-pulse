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
#include <sys/un.h>
#include <unistd.h>

/* MSG_NOSIGNAL fallback for platforms without it (macOS, BSD).
 * Applications must call signal(SIGPIPE, SIG_IGN). See Socket.h. */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#include "core/Arena.h"
#include "core/Except.h"
#include "socket/Socket.h"
#include "core/SocketConfig.h"
#include "dns/SocketDNS.h"
#include "core/SocketError.h"

#define T Socket_T

/* Port string buffer size for snprintf - 16 bytes sufficient for "65535" + null */
#define PORT_STR_BUFSIZE 16

Except_T Socket_Failed = {"Socket operation failed"};
Except_T Socket_Closed = {"Socket closed"};

/* Thread-local exception for detailed error messages.
 * Prevents race conditions when multiple threads raise same exception. */
#ifdef _WIN32
static __declspec(thread) Except_T Socket_DetailedException;
#else
static __thread Except_T Socket_DetailedException;
#endif

/* Macro to raise exception with detailed error message */
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

/* Static helper functions */

/**
 * resolve_address - Resolve hostname/port to addrinfo structure
 * @host: Hostname or IP address (NULL for wildcard)
 * @port: Port number (1-65535)
 * @hints: Addrinfo hints structure
 * @res: Output pointer to resolved addrinfo
 * @socket_family: Socket family to match (AF_UNSPEC if none)
 *
 * Returns: 0 on success, sets errno and returns -1 on failure
 *
 * Resolves address and validates against socket family if specified.
 */
static int resolve_address(const char *host, int port, const struct addrinfo *hints, struct addrinfo **res, int socket_family)
{
    char port_str[PORT_STR_BUFSIZE];
    int result;
    size_t host_len = host ? strlen(host) : 0;

    /* Validate hostname length */
    if (host_len > SOCKET_ERROR_MAX_HOSTNAME)
    {
        SOCKET_ERROR_MSG("Host name too long (max %d characters)", SOCKET_ERROR_MAX_HOSTNAME);
        return -1;
    }

    /* Convert port to string */
    result = snprintf(port_str, sizeof(port_str), "%d", port);
    assert(result > 0 && result < (int)sizeof(port_str));

    result = getaddrinfo(host, port_str, hints, res);
    if (result != 0)
    {
        const char *safe_host = host ? host : "any";
        SOCKET_ERROR_MSG("Invalid host/IP address: %.*s (%s)", SOCKET_ERROR_MAX_HOSTNAME, safe_host, gai_strerror(result));
        return -1;
    }

    /* Validate against socket family if specified */
    if (socket_family != AF_UNSPEC)
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
        SOCKET_ERROR_MSG("No address found for family %d: %.*s:%d", socket_family, SOCKET_ERROR_MAX_HOSTNAME, safe_host, port);
        return -1;
    }

    return 0;
}

/**
 * setup_unix_sockaddr - Set up sockaddr_un structure for Unix domain socket
 * @addr: Output sockaddr_un structure
 * @path: Socket path (may start with '@' for abstract socket)
 *
 * Returns: 0 on success, -1 on failure with errno set
 */
static int setup_unix_sockaddr(struct sockaddr_un *addr, const char *path)
{
    size_t path_len;

    assert(addr);
    assert(path);

    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    path_len = strlen(path);

    /* Handle abstract namespace sockets on Linux */
    if (path[0] == '@')
    {
#ifdef __linux__
        /* Abstract socket - replace '@' with '\0' */
        addr->sun_path[0] = '\0';
        if (path_len > sizeof(addr->sun_path) - 1)
        {
            SOCKET_ERROR_MSG("Unix socket path too long (max %zu characters)", sizeof(addr->sun_path) - 1);
            return -1;
        }
        memcpy(addr->sun_path + 1, path + 1, path_len - 1);
#else
        SOCKET_ERROR_MSG("Abstract namespace sockets not supported on this platform");
        return -1;
#endif
    }
    else
    {
        /* Regular filesystem socket */
        if (path_len >= sizeof(addr->sun_path))
        {
            SOCKET_ERROR_MSG("Unix socket path too long (max %zu characters)", sizeof(addr->sun_path) - 1);
            return -1;
        }
        strncpy(addr->sun_path, path, sizeof(addr->sun_path) - 1);
        addr->sun_path[sizeof(addr->sun_path) - 1] = '\0';
    }

    return 0;
}

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

    /* Use calloc to zero-initialize structure */
    sock = calloc(1, sizeof(*sock));
    if (sock == NULL)
    {
        int saved_errno = errno;
        SAFE_CLOSE(fd);
        errno = saved_errno;
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate socket structure");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    /* Initialize non-zero fields */
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

    /* Set file descriptor after successful allocations */
    sock->fd = fd;

    return sock;
}

void Socket_free(T *socket)
{
    assert(socket && *socket);

    /* Close file descriptor */
    if ((*socket)->fd >= 0)
    {
        int fd = (*socket)->fd;
        (*socket)->fd = -1; /* Mark as closed */
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
    int socket_family = AF_UNSPEC;
    socklen_t len = sizeof(socket_family);

    assert(socket);

    /* Validate port */
    if (!SOCKET_VALID_PORT(port))
    {
        SOCKET_ERROR_MSG("Invalid port number: %d (must be 1-65535)", port);
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    /* Normalize wildcard addresses */
    if (host == NULL || strcmp(host, "0.0.0.0") == 0 || strcmp(host, "::") == 0)
    {
        host = NULL;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; /* For wildcard IP address */
    hints.ai_protocol = 0;       /* Any protocol */

    /* Resolve address */
    if (resolve_address(host, port, &hints, &res, AF_UNSPEC) != 0)
    {
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    /* Get socket's address family to ensure compatibility */
    if (getsockopt(socket->fd, SOL_SOCKET, SO_DOMAIN, &socket_family, &len) < 0)
    {
        socket_family = AF_UNSPEC;
    }

    /* Try each address */
    for (rp = res; rp != NULL; rp = rp->ai_next)
    {
        /* Skip addresses that don't match socket's family if socket has a specific family */
        if (socket_family != AF_UNSPEC && rp->ai_family != socket_family)
            continue;

        /* Enable dual-stack on IPv6 sockets */
        if (rp->ai_family == AF_INET6 && socket_family == AF_INET6)
        {
            int no = 0;
            if (setsockopt(socket->fd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no)) < 0)
            {
                /* Non-fatal: dual-stack may not be supported on this platform */
                /* Socket will work but may only accept IPv6 connections */
            }
        }

        if (bind(socket->fd, rp->ai_addr, rp->ai_addrlen) == 0)
        {
            /* Success */
            memcpy(&socket->addr, rp->ai_addr, rp->ai_addrlen);
            socket->addrlen = rp->ai_addrlen;
            freeaddrinfo(res);
            return;
        }
    }

    /* No address worked */
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

    /* Use calloc to zero-initialize structure */
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

    /* Get peer address and port */
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

        /* Convert port string to int */
        errno = 0;
        port_long = strtol(serv, &endptr, 10);
        if (errno == 0 && endptr != serv && *endptr == '\0' && port_long >= 0 && port_long <= 65535)
        {
            newsocket->peerport = (int)port_long;
        }
        else
        {
            /* Invalid port - set to 0 */
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
    int socket_family = AF_UNSPEC;
    socklen_t len = sizeof(socket_family);
    int saved_errno = 0;

    assert(socket);

    /* Validate host */
    if (host == NULL)
    {
        SOCKET_ERROR_MSG("Invalid host: NULL pointer");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    /* Validate port */
    if (!SOCKET_VALID_PORT(port))
    {
        SOCKET_ERROR_MSG("Invalid port number: %d (must be 1-65535)", port);
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;

    /* Resolve address */
    if (resolve_address(host, port, &hints, &res, AF_UNSPEC) != 0)
    {
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    /* Get socket's address family */
    if (getsockopt(socket->fd, SOL_SOCKET, SO_DOMAIN, &socket_family, &len) < 0)
    {
        socket_family = AF_UNSPEC;
    }

    /* Try each address */
    for (rp = res; rp != NULL; rp = rp->ai_next)
    {
        /* Skip addresses that don't match socket's family */
        if (socket_family != AF_UNSPEC && rp->ai_family != socket_family)
            continue;

        if (connect(socket->fd, rp->ai_addr, rp->ai_addrlen) == 0 || errno == EINPROGRESS)
        {
            /* Success or in progress */
            memcpy(&socket->addr, rp->ai_addr, rp->ai_addrlen);
            socket->addrlen = rp->ai_addrlen;
            freeaddrinfo(res);
            return;
        }
        saved_errno = errno;
    }

    /* No address worked */
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

    /* Validate timeout */
    if (timeout_sec < 0)
    {
        SOCKET_ERROR_MSG("Invalid timeout value: %d (must be >= 0)", timeout_sec);
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    /* Set timeouts */
    if (setsockopt(socket->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to set receive timeout");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

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

    /* Validate keepalive parameters */
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

    /* Set keepalive parameters (platform-specific) */

#ifdef TCP_KEEPIDLE
    if (setsockopt(socket->fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to set keepalive idle time");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
#endif

#ifdef TCP_KEEPINTVL
    if (setsockopt(socket->fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to set keepalive interval");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
#endif

#ifdef TCP_KEEPCNT
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

void Socket_bind_unix(T socket, const char *path)
{
    struct sockaddr_un addr;

    assert(socket);
    assert(path);

    if (setup_unix_sockaddr(&addr, path) != 0)
    {
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    if (bind(socket->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        if (errno == EADDRINUSE)
        {
            SOCKET_ERROR_FMT(SOCKET_EADDRINUSE ": %s", path);
        }
        else if (errno == EACCES)
        {
            SOCKET_ERROR_FMT("Permission denied to bind to %s", path);
        }
        else
        {
            SOCKET_ERROR_FMT("Failed to bind to Unix socket %s", path);
        }
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    memcpy(&socket->addr, &addr, sizeof(addr));
    socket->addrlen = sizeof(addr);
}

void Socket_connect_unix(T socket, const char *path)
{
    struct sockaddr_un addr;

    assert(socket);
    assert(path);

    if (setup_unix_sockaddr(&addr, path) != 0)
    {
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    if (connect(socket->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        if (errno == ENOENT)
        {
            SOCKET_ERROR_FMT("Unix socket does not exist: %s", path);
        }
        else if (errno == ECONNREFUSED)
        {
            SOCKET_ERROR_FMT(SOCKET_ECONNREFUSED ": %s", path);
        }
        else
        {
            SOCKET_ERROR_FMT("Failed to connect to Unix socket %s", path);
        }
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    memcpy(&socket->addr, &addr, sizeof(addr));
    socket->addrlen = sizeof(addr);
}

int Socket_getpeerpid(const T socket)
{
    assert(socket);

#ifdef SO_PEERCRED
    struct ucred cred;
    socklen_t len = sizeof(cred);

    if (getsockopt(socket->fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) == 0)
    {
        return cred.pid;
    }
#endif

    return -1;
}

int Socket_getpeeruid(const T socket)
{
    assert(socket);

#ifdef SO_PEERCRED
    struct ucred cred;
    socklen_t len = sizeof(cred);

    if (getsockopt(socket->fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) == 0)
    {
        return cred.uid;
    }
#endif

    return -1;
}

int Socket_getpeergid(const T socket)
{
    assert(socket);

#ifdef SO_PEERCRED
    struct ucred cred;
    socklen_t len = sizeof(cred);

    if (getsockopt(socket->fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) == 0)
    {
        return cred.gid;
    }
#endif

    return -1;
}

SocketDNS_Request_T Socket_bind_async(SocketDNS_T dns, T socket, const char *host, int port)
{
    assert(dns);
    assert(socket);

    /* Validate port */
    if (!SOCKET_VALID_PORT(port))
    {
        SOCKET_ERROR_MSG("Invalid port number: %d (must be 1-65535)", port);
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    /* Normalize wildcard addresses */
    if (host == NULL || strcmp(host, "0.0.0.0") == 0 || strcmp(host, "::") == 0)
    {
        host = NULL;
    }

    /* Start async DNS resolution */
    return SocketDNS_resolve(dns, host ? host : "0.0.0.0", port, NULL, NULL);
}

SocketDNS_Request_T Socket_connect_async(SocketDNS_T dns, T socket, const char *host, int port)
{
    assert(dns);
    assert(socket);

    /* Validate host */
    if (host == NULL)
    {
        SOCKET_ERROR_MSG("Invalid host: NULL pointer");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    /* Validate port */
    if (!SOCKET_VALID_PORT(port))
    {
        SOCKET_ERROR_MSG("Invalid port number: %d (must be 1-65535)", port);
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    /* Start async DNS resolution */
    return SocketDNS_resolve(dns, host, port, NULL, NULL);
}

void Socket_bind_with_addrinfo(T socket, struct addrinfo *res)
{
    struct addrinfo *rp;
    int socket_family = AF_UNSPEC;
    socklen_t len = sizeof(socket_family);

    assert(socket);
    assert(res);

    /* Get socket's address family to ensure compatibility */
    if (getsockopt(socket->fd, SOL_SOCKET, SO_DOMAIN, &socket_family, &len) < 0)
    {
        socket_family = AF_UNSPEC;
    }

    /* Try each address */
    for (rp = res; rp != NULL; rp = rp->ai_next)
    {
        /* Skip addresses that don't match socket's family if socket has a specific family */
        if (socket_family != AF_UNSPEC && rp->ai_family != socket_family)
            continue;

        /* Enable dual-stack on IPv6 sockets */
        if (rp->ai_family == AF_INET6 && socket_family == AF_INET6)
        {
            int no = 0;
            if (setsockopt(socket->fd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no)) < 0)
            {
                /* Non-fatal: dual-stack may not be supported on this platform */
            }
        }

        if (bind(socket->fd, rp->ai_addr, rp->ai_addrlen) == 0)
        {
            /* Success */
            memcpy(&socket->addr, rp->ai_addr, rp->ai_addrlen);
            socket->addrlen = rp->ai_addrlen;
            return;
        }
    }

    /* No address worked */
    if (errno == EADDRINUSE)
    {
        SOCKET_ERROR_FMT(SOCKET_EADDRINUSE ": Failed to bind (address in use)");
    }
    else if (errno == EACCES)
    {
        SOCKET_ERROR_FMT("Permission denied to bind");
    }
    else
    {
        SOCKET_ERROR_FMT("Failed to bind with resolved address");
    }
    RAISE_SOCKET_ERROR(Socket_Failed);
}

void Socket_connect_with_addrinfo(T socket, struct addrinfo *res)
{
    struct addrinfo *rp;
    int socket_family = AF_UNSPEC;
    socklen_t len = sizeof(socket_family);
    int saved_errno = 0;

    assert(socket);
    assert(res);

    /* Get socket's address family */
    if (getsockopt(socket->fd, SOL_SOCKET, SO_DOMAIN, &socket_family, &len) < 0)
    {
        socket_family = AF_UNSPEC;
    }

    /* Try each address */
    for (rp = res; rp != NULL; rp = rp->ai_next)
    {
        /* Skip addresses that don't match socket's family */
        if (socket_family != AF_UNSPEC && rp->ai_family != socket_family)
            continue;

        if (connect(socket->fd, rp->ai_addr, rp->ai_addrlen) == 0 || errno == EINPROGRESS)
        {
            /* Success or in progress */
            memcpy(&socket->addr, rp->ai_addr, rp->ai_addrlen);
            socket->addrlen = rp->ai_addrlen;
            return;
        }
        saved_errno = errno;
    }

    /* No address worked */
    errno = saved_errno;

    if (errno == ECONNREFUSED)
    {
        SOCKET_ERROR_FMT(SOCKET_ECONNREFUSED ": Connection refused");
    }
    else if (errno == ENETUNREACH)
    {
        SOCKET_ERROR_FMT(SOCKET_ENETUNREACH ": Network unreachable");
    }
    else if (errno == ETIMEDOUT)
    {
        SOCKET_ERROR_FMT(SOCKET_ETIMEDOUT ": Connection timed out");
    }
    else
    {
        SOCKET_ERROR_FMT("Failed to connect with resolved address");
    }
    RAISE_SOCKET_ERROR(Socket_Failed);
}

#undef T
