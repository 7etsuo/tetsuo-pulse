/**
 * Socket.c - Socket abstraction layer implementation
 */

/* Feature test macros for accept4() on Linux */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stddef.h>
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
#define SOCKET_LOG_COMPONENT "Socket"
#include "core/SocketError.h"
#include "socket/SocketCommon.h"
#include "core/SocketMetrics.h"
#include "core/SocketEvents.h"

#define T Socket_T

static int socket_live_count = 0;
static pthread_mutex_t socket_live_count_mutex = PTHREAD_MUTEX_INITIALIZER;
static SocketTimeouts_T socket_default_timeouts = {.connect_timeout_ms = SOCKET_DEFAULT_CONNECT_TIMEOUT_MS,
                                                   .dns_timeout_ms = SOCKET_DEFAULT_DNS_TIMEOUT_MS,
                                                   .operation_timeout_ms = SOCKET_DEFAULT_OPERATION_TIMEOUT_MS};
static pthread_mutex_t socket_default_timeouts_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * socket_live_increment - Increment live socket count (thread-safe)
 * Thread-safe: Yes - protected by mutex
 */
static void socket_live_increment(void)
{
    pthread_mutex_lock(&socket_live_count_mutex);
    socket_live_count++;
    pthread_mutex_unlock(&socket_live_count_mutex);
}

/**
 * socket_live_decrement - Decrement live socket count (thread-safe)
 * Thread-safe: Yes - protected by mutex
 * Prevents TOCTOU race condition by atomically checking and decrementing
 */
static void socket_live_decrement(void)
{
    pthread_mutex_lock(&socket_live_count_mutex);
    if (socket_live_count > 0)
        socket_live_count--;
    pthread_mutex_unlock(&socket_live_count_mutex);
}

static int sanitize_timeout(int timeout_ms)
{
    if (timeout_ms < 0)
        return 0;
    return timeout_ms;
}

/* Port string buffer size for snprintf - 16 bytes sufficient for "65535" + null */

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
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
    char *peeraddr; /* IPv4 or IPv6 address string */
    int peerport;
    char *localaddr;
    int localport;
    Arena_T arena;
    SocketTimeouts_T timeouts;
};

/* Static helper functions */

/**
 * validate_port_number
 * Raises: Socket_Failed if port is invalid
 */
static void validate_port_number(int port)
{
    SocketCommon_validate_port(port, Socket_Failed);
}

/**
 * validate_host_not_null
 * Raises: Socket_Failed if host is NULL
 */
static void validate_host_not_null(const char *host)
{
    if (host == NULL)
    {
        SOCKET_ERROR_MSG("Invalid host: NULL pointer");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
}

/**
 * setup_bind_hints
 */
static void setup_bind_hints(struct addrinfo *hints)
{
    SocketCommon_setup_hints(hints, SOCKET_STREAM_TYPE, SOCKET_AI_PASSIVE);
}

/**
 * setup_connect_hints
 */
static void setup_connect_hints(struct addrinfo *hints)
{
    SocketCommon_setup_hints(hints, SOCKET_STREAM_TYPE, 0);
}

/**
 * get_socket_family - Get socket's address family
 * @socket: Socket to query
 * Returns: Socket family or AF_UNSPEC on error
 * Uses SO_DOMAIN on Linux, falls back to getsockname() on other platforms.
 */
static int get_socket_family(T socket)
{
    socklen_t len;
#if SOCKET_HAS_SO_DOMAIN
    int socket_family = SOCKET_AF_UNSPEC;
    len = sizeof(socket_family);
    if (getsockopt(socket->fd, SOCKET_SOL_SOCKET, SOCKET_SO_DOMAIN, &socket_family, &len) == 0)
        return socket_family;
#endif
    /* Fallback: use getsockname() to get socket address family */
    struct sockaddr_storage addr;
    len = sizeof(addr);
    if (getsockname(socket->fd, (struct sockaddr *)&addr, &len) == 0)
        return addr.ss_family;
    return SOCKET_AF_UNSPEC;
}

/**
 * enable_dual_stack - Enable IPv6 dual-stack mode
 * @socket: Socket to configure
 * @socket_family: Socket's family
 * Non-fatal: May fail if platform doesn't support dual-stack
 */
static void enable_dual_stack(T socket, int socket_family)
{
    if (socket_family == SOCKET_AF_INET6)
    {
        int no = 0;
        setsockopt(socket->fd, SOCKET_IPPROTO_IPV6, SOCKET_IPV6_V6ONLY, &no, sizeof(no));
    }
}

/**
 * create_socket_fd - Create underlying socket file descriptor
 * @domain: Socket domain (AF_INET, AF_INET6, AF_UNIX)
 * @type: Socket type (SOCK_STREAM, SOCK_DGRAM)
 * @protocol: Socket protocol (usually 0)
 * Returns: Socket file descriptor or -1 on failure
 * Raises: Socket_Failed on socket creation failure
 * Note: All sockets are created with close-on-exec flag set by default.
 */
static int create_socket_fd(int domain, int type, int protocol)
{
    int fd;

#if SOCKET_HAS_SOCK_CLOEXEC
    fd = socket(domain, type | SOCKET_SOCK_CLOEXEC, protocol);
#else
    fd = socket(domain, type, protocol);
#endif

    if (fd < 0)
    {
        SOCKET_ERROR_FMT("Failed to create socket (domain=%d, type=%d, protocol=%d)", domain, type, protocol);
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

#if !SOCKET_HAS_SOCK_CLOEXEC
    /* Fallback: Set CLOEXEC via fcntl on older systems */
    if (SocketCommon_setcloexec(fd, 1) < 0)
    {
        int saved_errno = errno;
        SAFE_CLOSE(fd);
        errno = saved_errno;
        SOCKET_ERROR_FMT("Failed to set close-on-exec flag");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
#endif

    return fd;
}

/**
 * allocate_socket_structure - Allocate and zero-initialize socket structure
 * @fd: File descriptor for cleanup on failure
 * Returns: Pointer to allocated socket structure or NULL on failure
 * Raises: Socket_Failed on allocation failure (cleans up fd)
 */
static T allocate_socket_structure(int fd)
{
    T sock = calloc(1, sizeof(*sock));
    if (sock == NULL)
    {
        int saved_errno = errno;
        SAFE_CLOSE(fd);
        errno = saved_errno;
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate socket structure");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
    socket_live_increment();
    return sock;
}

/**
 * initialize_socket_structure - Initialize socket structure fields
 * @socket: Socket to initialize
 * @fd: File descriptor to assign
 * Returns: Initialized socket structure
 */
static T initialize_socket_structure(T socket, int fd)
{
    socket->fd = fd;
    socket->addrlen = sizeof(socket->addr);
    memset(&socket->addr, 0, sizeof(socket->addr));
    socket->local_addrlen = 0;
    memset(&socket->local_addr, 0, sizeof(socket->local_addr));
    socket->peeraddr = NULL;
    socket->peerport = 0;
    socket->localaddr = NULL;
    socket->localport = 0;

    /* Thread-safe copy of default timeouts */
    pthread_mutex_lock(&socket_default_timeouts_mutex);
    socket->timeouts = socket_default_timeouts;
    pthread_mutex_unlock(&socket_default_timeouts_mutex);

    return socket;
}

/**
 * create_socket_arena - Create arena for socket-related allocations
 * @fd: File descriptor for cleanup on failure
 * @sock: Socket structure for cleanup on failure
 * Returns: New arena or NULL on failure
 * Raises: Socket_Failed on arena creation failure (cleans up fd and sock)
 */
static Arena_T create_socket_arena(int fd, T sock)
{
    Arena_T arena = Arena_new();
    if (!arena)
    {
        int saved_errno = errno;
        SAFE_CLOSE(fd);
        free(sock);
        errno = saved_errno;
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate socket arena");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
    return arena;
}

/**
 * try_bind_address - Try to bind socket to address
 * @socket: Socket to bind
 * @addr: Address to bind to
 * @addrlen: Address length
 * Returns: 0 on success, -1 on failure
 */
static int try_bind_address(T socket, const struct sockaddr *addr, socklen_t addrlen)
{
    if (bind(socket->fd, addr, addrlen) == 0)
    {
        memcpy(&socket->addr, addr, addrlen);
        socket->addrlen = addrlen;
        return 0;
    }
    return -1;
}

static int socket_wait_for_connect(T socket, int timeout_ms)
{
    struct pollfd pfd;
    int result;
    int error = 0;
    socklen_t error_len = sizeof(error);

    assert(socket);
    assert(timeout_ms >= 0);

    pfd.fd = socket->fd;
    pfd.events = POLLOUT;
    pfd.revents = 0;

    while ((result = poll(&pfd, 1, timeout_ms)) < 0)
    {
        if (errno == EINTR)
            continue;
        return -1;
    }

    if (result == 0)
    {
        errno = ETIMEDOUT;
        return -1;
    }

    if (getsockopt(socket->fd, SOCKET_SOL_SOCKET, SO_ERROR, &error, &error_len) < 0)
        return -1;

    if (error != 0)
    {
        errno = error;
        return -1;
    }

    return 0;
}

/**
 * try_connect_address - Try to connect socket to address
 * @socket: Socket to connect
 * @addr: Address to connect to
 * @addrlen: Address length
 * Returns: 0 on success or EINPROGRESS, -1 on failure
 */
static int try_connect_address(T socket, const struct sockaddr *addr, socklen_t addrlen, int timeout_ms)
{
    int saved_errno;
    int original_flags = -1;
    int restore_blocking = 0;

    assert(socket);
    assert(addr);

    if (timeout_ms <= 0)
    {
        if (connect(socket->fd, addr, addrlen) == 0 || errno == EINPROGRESS || errno == EISCONN)
        {
            memcpy(&socket->addr, addr, addrlen);
            socket->addrlen = addrlen;
            return 0;
        }
        return -1;
    }

    original_flags = fcntl(socket->fd, F_GETFL);
    if (original_flags < 0)
        return -1;

    if ((original_flags & O_NONBLOCK) == 0)
    {
        if (fcntl(socket->fd, F_SETFL, original_flags | O_NONBLOCK) < 0)
            return -1;
        restore_blocking = 1;
    }

    if (connect(socket->fd, addr, addrlen) == 0 || errno == EISCONN)
    {
        if (restore_blocking)
        {
            if (fcntl(socket->fd, F_SETFL, original_flags) < 0)
            {
                SocketLog_emitf(SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                                "Failed to restore blocking mode after connect (fd=%d, errno=%d): %s", socket->fd,
                                errno, strerror(errno));
            }
        }
        memcpy(&socket->addr, addr, addrlen);
        socket->addrlen = addrlen;
        return 0;
    }

    saved_errno = errno;

    if (saved_errno == EINPROGRESS || saved_errno == EINTR)
    {
        if (socket_wait_for_connect(socket, timeout_ms) == 0)
        {
            if (restore_blocking)
            {
                if (fcntl(socket->fd, F_SETFL, original_flags) < 0)
                {
                    SocketLog_emitf(SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                                    "Failed to restore blocking mode after connect (fd=%d, errno=%d): %s", socket->fd,
                                    errno, strerror(errno));
                }
            }
            memcpy(&socket->addr, addr, addrlen);
            socket->addrlen = addrlen;
            return 0;
        }
        saved_errno = errno;
    }

    if (restore_blocking)
    {
        int restore_result = fcntl(socket->fd, F_SETFL, original_flags);
        if (restore_result < 0)
        {
            int restore_errno = errno;
            SocketLog_emitf(SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                            "Failed to restore blocking mode after connect failure (fd=%d, errno=%d): %s", socket->fd,
                            restore_errno, strerror(restore_errno));
        }
    }

    errno = saved_errno;
    return -1;
}

/**
 * handle_bind_error - Handle bind error and raise exception
 * @host: Host string for error message
 * @port: Port for error message
 */
static void handle_bind_error(const char *host, int port)
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
 * handle_connect_error - Handle connect error and raise exception
 * @host: Host string for error message
 * @port: Port for error message
 */
static void handle_connect_error(const char *host, int port)
{
    SocketMetrics_increment(SOCKET_METRIC_SOCKET_CONNECT_FAILURE, 1);

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
}

/**
 * allocate_peer_address - Allocate and copy peer address string
 * @newsocket: New socket to allocate for
 * @host: Host string to copy
 * Returns: 0 on success, -1 on failure
 * Raises: Socket_Failed on allocation failure
 */
/**
 * setup_peer_info - Set up peer address and port from getnameinfo result
 * @newsocket: New socket to set up
 * @addr: Address structure
 * @addrlen: Address length
 * Returns: 0 on success, -1 on failure
 */
static int setup_peer_info(T newsocket, const struct sockaddr *addr, socklen_t addrlen)
{
    if (SocketCommon_cache_endpoint(newsocket->arena, addr, addrlen, &newsocket->peeraddr, &newsocket->peerport) != 0)
    {
        newsocket->peeraddr = NULL;
        newsocket->peerport = 0;
    }
    return 0;
}

static void update_local_endpoint(T socket)
{
    struct sockaddr_storage local;
    socklen_t len = sizeof(local);

    assert(socket);

    if (getsockname(socket->fd, (struct sockaddr *)&local, &len) < 0)
    {
        memset(&socket->local_addr, 0, sizeof(socket->local_addr));
        socket->local_addrlen = 0;
        socket->localaddr = NULL;
        socket->localport = 0;
        return;
    }

    socket->local_addr = local;
    socket->local_addrlen = len;

    if (SocketCommon_cache_endpoint(socket->arena, (struct sockaddr *)&local, len, &socket->localaddr,
                                    &socket->localport) != 0)
    {
        socket->localaddr = NULL;
        socket->localport = 0;
    }
}

/**
 * validate_unix_path_length - Validate Unix socket path length
 * @path_len: Path length to validate
 * Returns: 0 on success, -1 on failure
 */
static int validate_unix_path_length(size_t path_len)
{
    if (path_len > sizeof(struct sockaddr_un) - offsetof(struct sockaddr_un, sun_path) - 1)
    {
        SOCKET_ERROR_MSG("Unix socket path too long (max %zu characters)",
                         sizeof(struct sockaddr_un) - offsetof(struct sockaddr_un, sun_path) - 1);
        return -1;
    }
    return 0;
}

/**
 * setup_abstract_unix_socket - Set up abstract namespace Unix socket
 * @addr: Output sockaddr_un structure
 * @path: Socket path starting with '@'
 * @path_len: Length of path
 * Returns: 0 on success, -1 on failure
 */
static int setup_abstract_unix_socket(struct sockaddr_un *addr, const char *path, size_t path_len)
{
#ifdef __linux__
    if (validate_unix_path_length(path_len) != 0)
        return -1;
    addr->sun_path[0] = '\0';
    memcpy(addr->sun_path + 1, path + 1, path_len - 1);
    return 0;
#else
    (void)addr;
    (void)path;
    (void)path_len;
    SOCKET_ERROR_MSG("Abstract namespace sockets not supported on this platform");
    return -1;
#endif
}

/**
 * setup_regular_unix_socket - Set up regular filesystem Unix socket
 * @addr: Output sockaddr_un structure
 * @path: Socket path
 * @path_len: Length of path
 * Returns: 0 on success, -1 on failure
 */
static int setup_regular_unix_socket(struct sockaddr_un *addr, const char *path, size_t path_len)
{
    if (validate_unix_path_length(path_len) != 0)
        return -1;
    strncpy(addr->sun_path, path, sizeof(addr->sun_path) - 1);
    addr->sun_path[sizeof(addr->sun_path) - 1] = '\0';
    return 0;
}

/**
 * setup_unix_sockaddr - Set up sockaddr_un structure for Unix domain socket
 * @addr: Output sockaddr_un structure
 * @path: Socket path (may start with '@' for abstract socket)
 * Returns: 0 on success, -1 on failure with errno set
 */
static int setup_unix_sockaddr(struct sockaddr_un *addr, const char *path)
{
    size_t path_len;

    assert(addr);
    assert(path);

    memset(addr, 0, sizeof(*addr));
    addr->sun_family = SOCKET_AF_UNIX;
    path_len = strlen(path);

    if (path[0] == '@')
        return setup_abstract_unix_socket(addr, path, path_len);
    else
        return setup_regular_unix_socket(addr, path, path_len);
}

T Socket_new(int domain, int type, int protocol)
{
    T sock;
    int fd;

    fd = create_socket_fd(domain, type, protocol);
    sock = allocate_socket_structure(fd);
    sock->arena = create_socket_arena(fd, sock);
    initialize_socket_structure(sock, fd);

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
    socket_live_decrement();
    *socket = NULL;
}

/**
 * try_bind_resolved_addresses - Try binding to resolved addresses
 * @socket: Socket to bind
 * @res: Resolved address list
 * @socket_family: Socket's address family
 * Returns: 0 on success, -1 on failure
 */
static int try_bind_resolved_addresses(T socket, struct addrinfo *res, int socket_family)
{
    struct addrinfo *rp;

    for (rp = res; rp != NULL; rp = rp->ai_next)
    {
        if (socket_family != AF_UNSPEC && rp->ai_family != socket_family)
            continue;

        enable_dual_stack(socket, rp->ai_family);

        if (try_bind_address(socket, rp->ai_addr, rp->ai_addrlen) == 0)
            return 0;
    }
    return -1;
}

void Socket_bind(T socket, const char *host, int port)
{
    struct addrinfo hints, *res = NULL;
    int socket_family;

    assert(socket);

    validate_port_number(port);
    host = SocketCommon_normalize_wildcard_host(host);
    setup_bind_hints(&hints);

    if (SocketCommon_resolve_address(host, port, &hints, &res, Socket_Failed, SOCKET_AF_UNSPEC, 1) != 0)
        RAISE_SOCKET_ERROR(Socket_Failed);

    socket_family = get_socket_family(socket);

    if (try_bind_resolved_addresses(socket, res, socket_family) == 0)
    {
        update_local_endpoint(socket);
        freeaddrinfo(res);
        return;
    }

    handle_bind_error(host, port);
    freeaddrinfo(res);
    RAISE_SOCKET_ERROR(Socket_Failed);
}

/**
 * validate_backlog - Validate listen backlog parameter
 * @backlog: Backlog value to validate
 * Raises: Socket_Failed if invalid
 */
static void validate_backlog(int backlog)
{
    if (backlog <= 0)
    {
        SOCKET_ERROR_MSG("Invalid backlog value: %d (must be > 0)", backlog);
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
}

/**
 * enforce_backlog_limit - Enforce maximum backlog limit
 * @backlog: Backlog value to enforce
 * Returns: Enforced backlog value
 */
static int enforce_backlog_limit(int backlog)
{
    if (backlog > SOCKET_MAX_LISTEN_BACKLOG)
        return SOCKET_MAX_LISTEN_BACKLOG;
    return backlog;
}

void Socket_listen(T socket, int backlog)
{
    int result;

    assert(socket);
    validate_backlog(backlog);
    backlog = enforce_backlog_limit(backlog);

    result = listen(socket->fd, backlog);
    if (result < 0)
    {
        SOCKET_ERROR_FMT("Failed to listen on socket (backlog=%d)", backlog);
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
}

/**
 * accept_connection - Accept a new connection
 * @socket: Listening socket
 * @addr: Output address structure
 * @addrlen: Input/output address length
 * Returns: New file descriptor or -1 on error
 * Note: All accepted sockets have close-on-exec flag set by default.
 */
static int accept_connection(T socket, struct sockaddr_storage *addr, socklen_t *addrlen)
{
    int newfd;

#if SOCKET_HAS_ACCEPT4
    /* Use accept4() with SOCK_CLOEXEC when available */
    newfd = accept4(socket->fd, (struct sockaddr *)addr, addrlen, SOCKET_SOCK_CLOEXEC);
#else
    newfd = accept(socket->fd, (struct sockaddr *)addr, addrlen);
#endif

    if (newfd < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return -1;
        SOCKET_ERROR_FMT("Failed to accept connection");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

#if !SOCKET_HAS_ACCEPT4
    /* Fallback: Set CLOEXEC via fcntl on older systems */
    if (SocketCommon_setcloexec(newfd, 1) < 0)
    {
        int saved_errno = errno;
        SAFE_CLOSE(newfd);
        errno = saved_errno;
        SOCKET_ERROR_FMT("Failed to set close-on-exec flag on accepted socket");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
#endif

    return newfd;
}

/**
 * create_accepted_socket - Create socket structure for accepted connection
 * @newfd: Accepted file descriptor
 * @addr: Peer address
 * @addrlen: Address length
 * Returns: New socket or NULL on failure
 * Raises: Socket_Failed on allocation failure
 */
static T create_accepted_socket(int newfd, const struct sockaddr_storage *addr, socklen_t addrlen)
{
    T newsocket = calloc(1, sizeof(*newsocket));

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
    memcpy(&newsocket->addr, addr, addrlen);
    newsocket->addrlen = addrlen;
    memset(&newsocket->local_addr, 0, sizeof(newsocket->local_addr));
    newsocket->local_addrlen = 0;
    newsocket->peeraddr = NULL;
    newsocket->peerport = 0;
    newsocket->localaddr = NULL;
    newsocket->localport = 0;
    socket_live_increment();

    return newsocket;
}

T Socket_accept(T socket)
{
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    int newfd;
    T newsocket;

    assert(socket);

    newfd = accept_connection(socket, &addr, &addrlen);
    if (newfd < 0)
        return NULL;

    newsocket = create_accepted_socket(newfd, &addr, addrlen);
    setup_peer_info(newsocket, (struct sockaddr *)&addr, addrlen);
    update_local_endpoint(newsocket);
    SocketEvent_emit_accept(newsocket->fd, newsocket->peeraddr, newsocket->peerport, newsocket->localaddr,
                            newsocket->localport);

    return newsocket;
}

/**
 * try_connect_resolved_addresses - Try connecting to resolved addresses
 * @socket: Socket to connect
 * @res: Resolved address list
 * @socket_family: Socket's address family
 * Returns: 0 on success, -1 on failure
 */
static int try_connect_resolved_addresses(T socket, struct addrinfo *res, int socket_family, int timeout_ms)
{
    struct addrinfo *rp;
    int saved_errno = 0;

    for (rp = res; rp != NULL; rp = rp->ai_next)
    {
        if (socket_family != AF_UNSPEC && rp->ai_family != socket_family)
            continue;

        if (try_connect_address(socket, rp->ai_addr, rp->ai_addrlen, timeout_ms) == 0)
            return 0;
        saved_errno = errno;
    }
    errno = saved_errno;
    return -1;
}

void Socket_connect(T socket, const char *host, int port)
{
    struct addrinfo hints, *res = NULL;
    int socket_family;

    assert(socket);

    validate_host_not_null(host);
    validate_port_number(port);
    setup_connect_hints(&hints);

    if (SocketCommon_resolve_address(host, port, &hints, &res, Socket_Failed, SOCKET_AF_UNSPEC, 1) != 0)
        RAISE_SOCKET_ERROR(Socket_Failed);

    socket_family = get_socket_family(socket);

    if (try_connect_resolved_addresses(socket, res, socket_family, socket->timeouts.connect_timeout_ms) == 0)
    {
        SocketMetrics_increment(SOCKET_METRIC_SOCKET_CONNECT_SUCCESS, 1);
        update_local_endpoint(socket);
        setup_peer_info(socket, (struct sockaddr *)&socket->addr, socket->addrlen);
        SocketEvent_emit_connect(socket->fd, socket->peeraddr, socket->peerport, socket->localaddr, socket->localport);
        freeaddrinfo(res);
        return;
    }

    handle_connect_error(host, port);
    freeaddrinfo(res);
    RAISE_SOCKET_ERROR(Socket_Failed);
}

ssize_t Socket_send(T socket, const void *buf, size_t len)
{
    ssize_t result;

    assert(socket);
    assert(buf);
    assert(len > 0);

    result = send(socket->fd, buf, len, SOCKET_MSG_NOSIGNAL);
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

    if (setsockopt(socket->fd, SOCKET_SOL_SOCKET, SOCKET_SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to set SO_REUSEADDR");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
}

void Socket_setreuseport(T socket)
{
    int opt = 1;

    assert(socket);

#if SOCKET_HAS_SO_REUSEPORT
    if (setsockopt(socket->fd, SOCKET_SOL_SOCKET, SOCKET_SO_REUSEPORT, &opt, sizeof(opt)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to set SO_REUSEPORT");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
#else
    (void)opt;
    SOCKET_ERROR_MSG("SO_REUSEPORT not supported on this platform");
    RAISE_SOCKET_ERROR(Socket_Failed);
#endif
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
    if (setsockopt(socket->fd, SOCKET_SOL_SOCKET, SOCKET_SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to set receive timeout");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    if (setsockopt(socket->fd, SOCKET_SOL_SOCKET, SOCKET_SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to set send timeout");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
}

/**
 * socket_shutdown_mode_valid - Check shutdown mode value
 * @how: Shutdown mode
 * Returns: 1 if valid, 0 otherwise
 * Thread-safe: Yes
 */
static int socket_shutdown_mode_valid(int how)
{
    return (how == SOCKET_SHUT_RD || how == SOCKET_SHUT_WR || how == SOCKET_SHUT_RDWR);
}

/**
 * Socket_shutdown - Disable further sends and/or receives
 * @socket: Connected socket
 * @how: Shutdown mode (SOCKET_SHUT_RD, SOCKET_SHUT_WR, SOCKET_SHUT_RDWR)
 * Raises: Socket_Failed on error
 */
void Socket_shutdown(T socket, int how)
{
    assert(socket);

    if (!socket_shutdown_mode_valid(how))
    {
        SOCKET_ERROR_MSG("Invalid shutdown mode: %d", how);
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    if (shutdown(socket->fd, how) < 0)
    {
        if (errno == ENOTCONN)
            SOCKET_ERROR_FMT("Socket is not connected (shutdown mode=%d)", how);
        else
            SOCKET_ERROR_FMT("Failed to shutdown socket (mode=%d)", how);
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    SocketMetrics_increment(SOCKET_METRIC_SOCKET_SHUTDOWN_CALL, 1);
}

/**
 * Socket_setcloexec - Control close-on-exec flag
 * @socket: Socket to modify
 * @enable: 1 to enable CLOEXEC, 0 to disable
 * Raises: Socket_Failed on error
 */
void Socket_setcloexec(T socket, int enable)
{
    assert(socket);

    if (SocketCommon_setcloexec(socket->fd, enable) < 0)
    {
        SOCKET_ERROR_FMT("Failed to %s close-on-exec flag", enable ? "set" : "clear");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
}

void Socket_timeouts_get(const T socket, SocketTimeouts_T *timeouts)
{
    assert(socket);
    assert(timeouts);

    *timeouts = socket->timeouts;
}

void Socket_timeouts_set(T socket, const SocketTimeouts_T *timeouts)
{
    assert(socket);

    if (timeouts == NULL)
    {
        /* Thread-safe copy of default timeouts */
        pthread_mutex_lock(&socket_default_timeouts_mutex);
        socket->timeouts = socket_default_timeouts;
        pthread_mutex_unlock(&socket_default_timeouts_mutex);
        return;
    }

    socket->timeouts.connect_timeout_ms = sanitize_timeout(timeouts->connect_timeout_ms);
    socket->timeouts.dns_timeout_ms = sanitize_timeout(timeouts->dns_timeout_ms);
    socket->timeouts.operation_timeout_ms = sanitize_timeout(timeouts->operation_timeout_ms);
}

void Socket_timeouts_getdefaults(SocketTimeouts_T *timeouts)
{
    assert(timeouts);

    /* Thread-safe copy of default timeouts */
    pthread_mutex_lock(&socket_default_timeouts_mutex);
    *timeouts = socket_default_timeouts;
    pthread_mutex_unlock(&socket_default_timeouts_mutex);
}

void Socket_timeouts_setdefaults(const SocketTimeouts_T *timeouts)
{
    SocketTimeouts_T local;

    assert(timeouts);

    /* Thread-safe read-modify-write of default timeouts */
    pthread_mutex_lock(&socket_default_timeouts_mutex);
    local = socket_default_timeouts;
    pthread_mutex_unlock(&socket_default_timeouts_mutex);

    local.connect_timeout_ms = sanitize_timeout(timeouts->connect_timeout_ms);
    local.dns_timeout_ms = sanitize_timeout(timeouts->dns_timeout_ms);
    local.operation_timeout_ms = sanitize_timeout(timeouts->operation_timeout_ms);

    pthread_mutex_lock(&socket_default_timeouts_mutex);
    socket_default_timeouts = local;
    pthread_mutex_unlock(&socket_default_timeouts_mutex);
}

/**
 * validate_keepalive_parameters - Validate keepalive parameters
 * @idle: Idle timeout
 * @interval: Interval between probes
 * @count: Probe count
 * Raises: Socket_Failed if parameters are invalid
 */
static void validate_keepalive_parameters(int idle, int interval, int count)
{
    if (idle <= 0 || interval <= 0 || count <= 0)
    {
        SOCKET_ERROR_MSG("Invalid keepalive parameters (idle=%d, interval=%d, count=%d): all must be > 0", idle,
                         interval, count);
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
}

/**
 * enable_socket_keepalive - Enable keepalive on socket
 * @socket: Socket to configure
 * Raises: Socket_Failed on failure
 */
static void enable_socket_keepalive(T socket)
{
    int opt = 1;
    if (setsockopt(socket->fd, SOCKET_SOL_SOCKET, SOCKET_SO_KEEPALIVE, &opt, sizeof(opt)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to enable keepalive");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
}

/**
 * set_keepalive_idle_time - Set keepalive idle timeout
 * @socket: Socket to configure
 * @idle: Idle timeout in seconds
 * Raises: Socket_Failed on failure
 */
static void set_keepalive_idle_time(T socket, int idle)
{
#ifdef TCP_KEEPIDLE
    if (setsockopt(socket->fd, SOCKET_IPPROTO_TCP, SOCKET_TCP_KEEPIDLE, &idle, sizeof(idle)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to set keepalive idle time");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
#else
    (void)socket;
    (void)idle;
#endif
}

/**
 * set_keepalive_interval - Set keepalive probe interval
 * @socket: Socket to configure
 * @interval: Interval in seconds
 * Raises: Socket_Failed on failure
 */
static void set_keepalive_interval(T socket, int interval)
{
#ifdef TCP_KEEPINTVL
    if (setsockopt(socket->fd, SOCKET_IPPROTO_TCP, SOCKET_TCP_KEEPINTVL, &interval, sizeof(interval)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to set keepalive interval");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
#endif
}

/**
 * set_keepalive_count - Set keepalive probe count
 * @socket: Socket to configure
 * @count: Probe count
 * Raises: Socket_Failed on failure
 */
static void set_keepalive_count(T socket, int count)
{
#ifdef TCP_KEEPCNT
    if (setsockopt(socket->fd, SOCKET_IPPROTO_TCP, SOCKET_TCP_KEEPCNT, &count, sizeof(count)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to set keepalive count");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
#endif
}

void Socket_setkeepalive(T socket, int idle, int interval, int count)
{
    assert(socket);
    validate_keepalive_parameters(idle, interval, count);
    enable_socket_keepalive(socket);
    set_keepalive_idle_time(socket, idle);
    set_keepalive_interval(socket, interval);
    set_keepalive_count(socket, count);
}

void Socket_setnodelay(T socket, int nodelay)
{
    assert(socket);

    if (setsockopt(socket->fd, SOCKET_IPPROTO_TCP, SOCKET_TCP_NODELAY, &nodelay, sizeof(nodelay)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to set TCP_NODELAY");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
}

/**
 * Socket_gettimeout - Get socket timeout
 * @socket: Socket to query
 * Returns: Timeout in seconds (0 if disabled)
 * Raises: Socket_Failed on error
 * Note: Returns receive timeout (send timeout may differ)
 */
int Socket_gettimeout(T socket)
{
    struct timeval tv;

    assert(socket);

    if (SocketCommon_getoption_timeval(socket->fd, SOCKET_SOL_SOCKET, SOCKET_SO_RCVTIMEO, &tv, Socket_Failed) < 0)
        RAISE_SOCKET_ERROR(Socket_Failed);

    return (int)tv.tv_sec;
}

/**
 * Socket_getkeepalive - Get TCP keepalive configuration
 * @socket: Socket to query
 * @idle: Output - idle timeout in seconds
 * @interval: Output - interval between probes in seconds
 * @count: Output - number of probes before declaring dead
 * Raises: Socket_Failed on error
 * Note: Returns 0 for parameters not supported on this platform
 */
void Socket_getkeepalive(T socket, int *idle, int *interval, int *count)
{
    int keepalive_enabled = 0;

    assert(socket);
    assert(idle);
    assert(interval);
    assert(count);

    /* Get SO_KEEPALIVE flag */
    if (SocketCommon_getoption_int(socket->fd, SOCKET_SOL_SOCKET, SOCKET_SO_KEEPALIVE, &keepalive_enabled,
                                   Socket_Failed) < 0)
        RAISE_SOCKET_ERROR(Socket_Failed);

    if (!keepalive_enabled)
    {
        *idle = 0;
        *interval = 0;
        *count = 0;
        return;
    }

    /* Get TCP_KEEPIDLE */
#ifdef TCP_KEEPIDLE
    if (SocketCommon_getoption_int(socket->fd, SOCKET_IPPROTO_TCP, SOCKET_TCP_KEEPIDLE, idle, Socket_Failed) < 0)
        RAISE_SOCKET_ERROR(Socket_Failed);
#else
    *idle = 0;
#endif

    /* Get TCP_KEEPINTVL */
#ifdef TCP_KEEPINTVL
    if (SocketCommon_getoption_int(socket->fd, SOCKET_IPPROTO_TCP, SOCKET_TCP_KEEPINTVL, interval, Socket_Failed) < 0)
        RAISE_SOCKET_ERROR(Socket_Failed);
#else
    *interval = 0;
#endif

    /* Get TCP_KEEPCNT */
#ifdef TCP_KEEPCNT
    if (SocketCommon_getoption_int(socket->fd, SOCKET_IPPROTO_TCP, SOCKET_TCP_KEEPCNT, count, Socket_Failed) < 0)
        RAISE_SOCKET_ERROR(Socket_Failed);
#else
    *count = 0;
#endif
}

/**
 * Socket_getnodelay - Get TCP_NODELAY setting
 * @socket: Socket to query
 * Returns: 1 if Nagle's algorithm is disabled, 0 if enabled
 * Raises: Socket_Failed on error
 */
int Socket_getnodelay(T socket)
{
    int nodelay = 0;

    assert(socket);

    if (SocketCommon_getoption_int(socket->fd, SOCKET_IPPROTO_TCP, SOCKET_TCP_NODELAY, &nodelay, Socket_Failed) < 0)
        RAISE_SOCKET_ERROR(Socket_Failed);

    return nodelay;
}

/**
 * Socket_getrcvbuf - Get receive buffer size
 * @socket: Socket to query
 * Returns: Receive buffer size in bytes
 * Raises: Socket_Failed on error
 */
int Socket_getrcvbuf(T socket)
{
    int bufsize = 0;

    assert(socket);

    if (SocketCommon_getoption_int(socket->fd, SOCKET_SOL_SOCKET, SOCKET_SO_RCVBUF, &bufsize, Socket_Failed) < 0)
        RAISE_SOCKET_ERROR(Socket_Failed);

    return bufsize;
}

/**
 * Socket_getsndbuf - Get send buffer size
 * @socket: Socket to query
 * Returns: Send buffer size in bytes
 * Raises: Socket_Failed on error
 */
int Socket_getsndbuf(T socket)
{
    int bufsize = 0;

    assert(socket);

    if (SocketCommon_getoption_int(socket->fd, SOCKET_SOL_SOCKET, SOCKET_SO_SNDBUF, &bufsize, Socket_Failed) < 0)
        RAISE_SOCKET_ERROR(Socket_Failed);

    return bufsize;
}

/**
 * Socket_isconnected - Check if socket is connected
 * @socket: Socket to check
 * Returns: 1 if connected, 0 if not connected
 * Thread-safe: Yes (operates on single socket)
 * Note: Uses getpeername() to determine connection state.
 * For TCP sockets, checks if peer address is available.
 */
int Socket_isconnected(T socket)
{
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);

    assert(socket);

    /* Check if we have cached peer address */
    if (socket->peeraddr != NULL)
        return 1;

    /* Use getpeername() to check connection state */
    if (getpeername(socket->fd, (struct sockaddr *)&addr, &len) == 0)
    {
        /* Socket is connected - update cached peer info if not already set */
        if (socket->peeraddr == NULL && socket->arena != NULL)
        {
            setup_peer_info(socket, (struct sockaddr *)&addr, len);
        }
        return 1;
    }

    /* Not connected or error occurred */
    if (errno == ENOTCONN)
        return 0;

    /* Other errors (EBADF, etc.) - treat as not connected */
    return 0;
}

/**
 * Socket_isbound - Check if socket is bound to an address
 * @socket: Socket to check
 * Returns: 1 if bound, 0 if not bound
 * Thread-safe: Yes (operates on single socket)
 * Note: Uses getsockname() to determine binding state.
 * A socket is bound if getsockname() succeeds and returns a valid address.
 * Wildcard addresses (0.0.0.0 or ::) still count as bound.
 */
int Socket_isbound(T socket)
{
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);

    assert(socket);

    /* Check if we have cached local address */
    if (socket->localaddr != NULL)
        return 1;

    /* Use getsockname() to check binding state */
    if (getsockname(socket->fd, (struct sockaddr *)&addr, &len) == 0)
    {
        /* Socket is bound if getsockname succeeds */
        /* For IPv4/IPv6, check if we have a valid port (address can be wildcard) */
        if (addr.ss_family == AF_INET)
        {
            struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
            if (sin->sin_port != 0)
                return 1;
        }
        else if (addr.ss_family == AF_INET6)
        {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr;
            if (sin6->sin6_port != 0)
                return 1;
        }
        else if (addr.ss_family == AF_UNIX)
        {
            /* Unix domain sockets are bound if getsockname succeeds */
            return 1;
        }
    }

    return 0;
}

/**
 * Socket_islistening - Check if socket is listening for connections
 * @socket: Socket to check
 * Returns: 1 if listening, 0 if not listening
 * Thread-safe: Yes (operates on single socket)
 * Note: Checks if socket is bound and not connected.
 * A socket is listening if it's bound but has no peer address.
 */
int Socket_islistening(T socket)
{
    assert(socket);

    /* Socket must be bound to be listening */
    if (!Socket_isbound(socket))
        return 0;

    /* Socket must not be connected to be listening */
    if (Socket_isconnected(socket))
        return 0;

    /* Additional check: verify socket is actually in listening state
     * by checking if accept() would work (non-blocking check) */
    {
        int error = 0;
        socklen_t error_len = sizeof(error);

        /* Check SO_ERROR - listening sockets should have no error */
        if (getsockopt(socket->fd, SOCKET_SOL_SOCKET, SO_ERROR, &error, &error_len) == 0)
        {
            /* If there's a connection error, socket might be in wrong state */
            if (error != 0 && error != ENOTCONN)
                return 0;
        }
    }

    return 1;
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

const char *Socket_getlocaladdr(const T socket)
{
    assert(socket);
    return socket->localaddr ? socket->localaddr : "(unknown)";
}

int Socket_getlocalport(const T socket)
{
    assert(socket);
    return socket->localport;
}

/**
 * handle_unix_bind_error - Handle Unix socket bind error
 * @path: Socket path
 */
static void handle_unix_bind_error(const char *path)
{
    if (errno == EADDRINUSE)
        SOCKET_ERROR_FMT(SOCKET_EADDRINUSE ": %s", path);
    else if (errno == EACCES)
        SOCKET_ERROR_FMT("Permission denied to bind to %s", path);
    else
        SOCKET_ERROR_FMT("Failed to bind to Unix socket %s", path);
}

/**
 * perform_unix_bind - Perform Unix socket bind operation
 * @socket: Socket to bind
 * @addr: Address structure
 * @path: Path for error messages
 * Raises: Socket_Failed on failure
 */
static void perform_unix_bind(T socket, const struct sockaddr_un *addr, const char *path)
{
    if (bind(socket->fd, (struct sockaddr *)addr, sizeof(*addr)) < 0)
    {
        handle_unix_bind_error(path);
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
}

void Socket_bind_unix(T socket, const char *path)
{
    struct sockaddr_un addr;

    assert(socket);
    assert(path);

    if (setup_unix_sockaddr(&addr, path) != 0)
        RAISE_SOCKET_ERROR(Socket_Failed);

    perform_unix_bind(socket, &addr, path);
    memcpy(&socket->addr, &addr, sizeof(addr));
    socket->addrlen = sizeof(addr);
    update_local_endpoint(socket);
}

/**
 * handle_unix_connect_error - Handle Unix socket connect error
 * @path: Socket path
 */
static void handle_unix_connect_error(const char *path)
{
    if (errno == ENOENT)
        SOCKET_ERROR_FMT("Unix socket does not exist: %s", path);
    else if (errno == ECONNREFUSED)
        SOCKET_ERROR_FMT(SOCKET_ECONNREFUSED ": %s", path);
    else
        SOCKET_ERROR_FMT("Failed to connect to Unix socket %s", path);
}

/**
 * perform_unix_connect - Perform Unix socket connect operation
 * @socket: Socket to connect
 * @addr: Address structure
 * @path: Path for error messages
 * Raises: Socket_Failed on failure
 */
static void perform_unix_connect(T socket, const struct sockaddr_un *addr, const char *path)
{
    if (connect(socket->fd, (struct sockaddr *)addr, sizeof(*addr)) < 0)
    {
        handle_unix_connect_error(path);
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
}

void Socket_connect_unix(T socket, const char *path)
{
    struct sockaddr_un addr;

    assert(socket);
    assert(path);

    if (setup_unix_sockaddr(&addr, path) != 0)
        RAISE_SOCKET_ERROR(Socket_Failed);

    perform_unix_connect(socket, &addr, path);
    memcpy(&socket->addr, &addr, sizeof(addr));
    socket->addrlen = sizeof(addr);
    update_local_endpoint(socket);
}

int Socket_getpeerpid(const T socket)
{
    assert(socket);

#ifdef SO_PEERCRED
    struct ucred cred;
    socklen_t len = sizeof(cred);

    if (getsockopt(socket->fd, SOCKET_SOL_SOCKET, SOCKET_SO_PEERCRED, &cred, &len) == 0)
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

    if (getsockopt(socket->fd, SOCKET_SOL_SOCKET, SOCKET_SO_PEERCRED, &cred, &len) == 0)
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

    if (getsockopt(socket->fd, SOCKET_SOL_SOCKET, SOCKET_SO_PEERCRED, &cred, &len) == 0)
    {
        return cred.gid;
    }
#endif

    return -1;
}

SocketDNS_Request_T Socket_bind_async(SocketDNS_T dns, T socket, const char *host, int port)
{
    struct addrinfo hints, *res = NULL;

    assert(dns);
    assert(socket);

    /* Validate port */
    if (!SOCKET_VALID_PORT(port))
    {
        SOCKET_ERROR_MSG("Invalid port number: %d (must be 1-65535)", port);
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    /* Normalize wildcard addresses to NULL */
    if (host == NULL || strcmp(host, "0.0.0.0") == 0 || strcmp(host, "::") == 0)
    {
        host = NULL;
    }

    /* For wildcard bind (NULL host), resolve synchronously and create completed request */
    if (host == NULL)
    {
        setup_bind_hints(&hints);
        if (SocketCommon_resolve_address(NULL, port, &hints, &res, Socket_Failed, SOCKET_AF_UNSPEC, 1) != 0)
            RAISE_SOCKET_ERROR(Socket_Failed);

        return SocketDNS_create_completed_request(dns, res, port);
    }

    /* For non-wildcard hosts, use async DNS resolution */
    {
        SocketDNS_Request_T req = SocketDNS_resolve(dns, host, port, NULL, NULL);
        if (socket->timeouts.dns_timeout_ms > 0)
            SocketDNS_request_settimeout(dns, req, socket->timeouts.dns_timeout_ms);
        return req;
    }
}

void Socket_bind_async_cancel(SocketDNS_T dns, SocketDNS_Request_T req)
{
    assert(dns);

    if (req)
        SocketDNS_cancel(dns, req);
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
    {
        SocketDNS_Request_T req = SocketDNS_resolve(dns, host, port, NULL, NULL);
        if (socket->timeouts.dns_timeout_ms > 0)
            SocketDNS_request_settimeout(dns, req, socket->timeouts.dns_timeout_ms);
        return req;
    }
}

void Socket_connect_async_cancel(SocketDNS_T dns, SocketDNS_Request_T req)
{
    assert(dns);

    if (req)
        SocketDNS_cancel(dns, req);
}

void Socket_bind_with_addrinfo(T socket, struct addrinfo *res)
{
    int socket_family;

    assert(socket);
    assert(res);

    socket_family = get_socket_family(socket);

    if (try_bind_resolved_addresses(socket, res, socket_family) == 0)
    {
        update_local_endpoint(socket);
        return;
    }

    handle_bind_error(NULL, 0);
    RAISE_SOCKET_ERROR(Socket_Failed);
}

void Socket_connect_with_addrinfo(T socket, struct addrinfo *res)
{
    int socket_family;

    assert(socket);
    assert(res);

    socket_family = get_socket_family(socket);

    if (try_connect_resolved_addresses(socket, res, socket_family, socket->timeouts.connect_timeout_ms) == 0)
    {
        SocketMetrics_increment(SOCKET_METRIC_SOCKET_CONNECT_SUCCESS, 1);
        update_local_endpoint(socket);
        setup_peer_info(socket, (struct sockaddr *)&socket->addr, socket->addrlen);
        SocketEvent_emit_connect(socket->fd, socket->peeraddr, socket->peerport, socket->localaddr, socket->localport);
        return;
    }

    handle_connect_error("resolved", 0);
    RAISE_SOCKET_ERROR(Socket_Failed);
}

#undef T

int Socket_debug_live_count(void)
{
    int count;

    /* Thread-safe read of live socket count */
    pthread_mutex_lock(&socket_live_count_mutex);
    count = socket_live_count;
    pthread_mutex_unlock(&socket_live_count_mutex);

    return count;
}
