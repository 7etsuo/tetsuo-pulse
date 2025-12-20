/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file Socket-convenience.c
 * @ingroup core_io
 * @brief High-level convenience functions for socket setup and connections
 *
 * This split implementation file provides simplified APIs for common socket
 * patterns, reducing boilerplate code while maintaining full control and safety.
 * Functions combine creation, configuration, binding, listening, connecting,
 * and timeout handling into single calls.
 *
 * ## Key Features
 *
 * - **TCP Convenience**: Quick server/client setup with reuseaddr and timeouts
 * - **Timed Operations**: Accept and connect with poll-based timeouts and EINTR retry
 * - **Non-blocking Support**: Initiate async connects, temporary mode management
 * - **Unix Domain**: Full support for filesystem and abstract sockets (Linux)
 * - **Error Handling**: Consistent exception raising with detailed messages
 * - **Mode Preservation**: Automatic restoration of original blocking/non-blocking state
 *
 * ## Module Dependencies
 *
 * - Foundation: Arena, Except for memory/error handling
 * - Core I/O: Socket base API (bind, listen, connect, accept)
 * - Utilities: SocketUtil for logging, timeouts, error categorization
 *
 * ## Usage Philosophy
 *
 * Designed for rapid prototyping and production use cases where simplicity
 * outweighs low-level customization. For advanced scenarios (e.g., custom options,
 * IPv6 dual-stack, event integration), use base Socket API directly.
 *
 * All functions are thread-safe and integrate seamlessly with SocketPoll and SocketPool.
 *
 * @see Socket.h for declarations and base API
 * @see core/SocketUtil.h for shared utilities and macros
 * @see docs/ASYNC_IO.md for integration with event systems
 * @see docs/ERROR_HANDLING.md for exception patterns
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>

#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "core/SocketConfig.h"
#define SOCKET_LOG_COMPONENT "SocketConvenience"
#include "core/SocketUtil.h"
#include "socket/Socket-private.h"
#include "socket/Socket.h"
#include "socket/SocketCommon-private.h"
#include "socket/SocketCommon.h"

#define T Socket_T

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketConvenience);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketConvenience, e)

/* ============================================================================
 * Static Helper Functions
 * ============================================================================
 */


/**
 * get_socket_flags - Get current socket flags with error handling
 * @fd: File descriptor to query
 * @flags_out: Output parameter for flags
 *
 * Returns: 0 on success, -1 on error (raises exception)
 * Thread-safe: Yes
 */
static int
get_socket_flags (int fd, int *flags_out)
{
        int flags;

        assert (flags_out != NULL);

        flags = fcntl (fd, F_GETFL);
        if (flags < 0)
                {
                        SOCKET_ERROR_FMT ("Failed to get socket flags");
                        RAISE_MODULE_ERROR (Socket_Failed);
                }

        *flags_out = flags;
        return 0;
}

/**
 * set_nonblocking_mode - Set socket to non-blocking mode
 * @fd: File descriptor
 * @original_flags: Current flags value
 *
 * Returns: 0 on success, -1 on error (raises exception)
 * Thread-safe: Yes
 */
static int
set_nonblocking_mode (int fd, int original_flags)
{
        if (fcntl (fd, F_SETFL, original_flags | O_NONBLOCK) < 0)
                {
                        SOCKET_ERROR_FMT ("Failed to set non-blocking mode");
                        RAISE_MODULE_ERROR (Socket_Failed);
                }
        return 0;
}

/**
 * restore_blocking_mode - Restore socket to original blocking mode
 * @fd: File descriptor
 * @original_flags: Original flags to restore
 *
 * Thread-safe: Yes
 *
 * Logs warning on failure but does not raise exception, as this is
 * typically called in cleanup paths where we want to continue.
 */
static void
restore_blocking_mode (int fd, int original_flags)
{
        if (fcntl (fd, F_SETFL, original_flags) < 0)
                {
                        SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                                         "Failed to restore blocking mode "
                                         "(fd=%d, errno=%d): %s",
                                         fd, errno, Socket_safe_strerror (errno));
                }
}

/**
 * check_connect_result - Check result of non-blocking connect via SO_ERROR
 * @fd: File descriptor
 * @context_path: Path or address for error message context
 *
 * Returns: 0 on success
 * Raises: Socket_Failed on error
 * Thread-safe: Yes
 */
static int
check_connect_result (int fd, const char *context_path)
{
        if (socket_check_so_error (fd) < 0)
                {
                        SOCKET_ERROR_FMT ("Connect to %.*s failed",
                                          SOCKET_ERROR_MAX_HOSTNAME, context_path);
                        RAISE_MODULE_ERROR (Socket_Failed);
                }

        return 0;
}

/**
 * parse_ip_address - Parse IPv4 or IPv6 address string
 * @ip_address: IP address string to parse
 * @addr: Output sockaddr_storage
 * @addrlen: Output address length
 *
 * Returns: 0 on success
 * Raises: Socket_Failed if address is invalid
 * Thread-safe: Yes
 */
static int
parse_ip_address (const char *ip_address, struct sockaddr_storage *addr,
                  socklen_t *addrlen, int port)
{
        struct sockaddr_in *addr4;
        struct sockaddr_in6 *addr6;

        assert (ip_address != NULL);
        assert (addr != NULL);
        assert (addrlen != NULL);

        memset (addr, 0, sizeof (*addr));

        /* Try IPv4 first */
        addr4 = (struct sockaddr_in *)addr;
        if (inet_pton (AF_INET, ip_address, &addr4->sin_addr) == 1)
                {
                        addr4->sin_family = AF_INET;
                        addr4->sin_port = htons ((uint16_t)port);
                        *addrlen = sizeof (struct sockaddr_in);
                        return 0;
                }

        /* Try IPv6 */
        addr6 = (struct sockaddr_in6 *)addr;
        if (inet_pton (AF_INET6, ip_address, &addr6->sin6_addr) == 1)
                {
                        addr6->sin6_family = AF_INET6;
                        addr6->sin6_port = htons ((uint16_t)port);
                        *addrlen = sizeof (struct sockaddr_in6);
                        return 0;
                }

        /* Invalid address */
        SOCKET_ERROR_MSG ("Invalid IP address (not IPv4 or IPv6): %.*s",
                          SOCKET_ERROR_MAX_HOSTNAME, ip_address);
        RAISE_MODULE_ERROR (Socket_Failed);

        return -1; /* Unreachable, but satisfies compiler */
}

/**
 * @brief Temporarily manage socket non-blocking mode for timed operations.
 * @ingroup core_io
 *
 * Centralizes logic to set socket to non-blocking mode before timed operations
 * and restore original mode afterward. Used by convenience functions to avoid
 * code duplication.
 *
 * Call with enable=1 before TRY to setup, and enable=0 in FINALLY to cleanup.
 * If socket already non-blocking, no change is made.
 *
 * @param[in] fd File descriptor of socket
 * @param[in] enable 1=setup non-blocking, 0=restore original
 * @param[out] original_flags Stores original flags when enabling (volatile compatible)
 * @param[out] need_restore Tracks if restore was needed (volatile compatible)
 *
 * @threadsafe Yes - atomic fcntl operations, no shared state
 *
 * @note Designed for use with volatile int locals in TRY/EXCEPT contexts to prevent clobbering
 * @note Does not raise exceptions; logs warnings on restore failure (non-fatal)
 * @note Uses local copy for fcntl to avoid volatile access issues in system calls
 *
 * @see Socket_accept_timeout()
 * @see Socket_connect_unix_timeout()
 * @see .cursorrules#volatile-variables-with-tryexcept-critical
 */
static void
with_nonblocking_scope (int fd, int enable, volatile int *original_flags, volatile int *need_restore)
{
        assert (fd >= 0);
        assert (original_flags != NULL);
        assert (need_restore != NULL);

        if (!enable) {
                /* Restore original blocking mode if we changed it */
                if (*need_restore) {
                        restore_blocking_mode (fd, (int)*original_flags);
                        *need_restore = 0;
                }
                return;
        }

        /* Setup non-blocking if not already set - use local copy for syscalls */
        int flags_copy;
        get_socket_flags (fd, &flags_copy);
        *original_flags = flags_copy;
        if ((flags_copy & O_NONBLOCK) == 0) {
                set_nonblocking_mode (fd, flags_copy);
                *need_restore = 1;
        } else {
                *need_restore = 0;
        }
}

/* ============================================================================
 * TCP Convenience Functions
 * ============================================================================
 */

/**
 * @brief Create and configure listening TCP server socket in single call.
 * @ingroup core_io
 *
 * High-level convenience for TCP server setup: creates IPv4 TCP socket,
 * enables SO_REUSEADDR for fast restarts, binds to specified host/port,
 * and starts listening with given backlog. Ready for immediate Socket_accept() calls.
 *
 * Supports INADDR_ANY (NULL or "") for all interfaces; port 0 assigns ephemeral port.
 * Does not support IPv6 (use Socket_new(AF_INET6, ...) for dual-stack).
 *
 * @param[in] host Bind address (IPv4 or NULL/"" for 0.0.0.0)
 * @param[in] port Local port (0-65535; 0=ephemeral)
 * @param[in] backlog Listen queue depth (SOMAXCONN recommended for production)
 *
 * @return New listening Socket_T ready for accepts
 *
 * @throws Socket_Failed On socket creation failure, bind error (EADDRINUSE, EACCES),
 *                       listen failure, or invalid params (port/backlog)
 *
 * @threadsafe Yes - creates independent new socket
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Simple HTTP server setup
 * Socket_T server = Socket_listen_tcp(NULL, 8080, SOMAXCONN);
 * if (server) {
 *   while (running) {
 *     Socket_T client = Socket_accept_timeout(server, 1000);  // Optional timeout
 *     if (client) {
 *       // Handle client...
 *       Socket_free(&client);
 *     }
 *   }
 *   Socket_free(&server);
 * }
 * @endcode
 *
 * ## Configuration Notes
 *
 * - SO_REUSEADDR enabled to allow bind after quick server crashes/restarts
 * - SO_REUSEPORT not set (use Socket_setreuseport() post-creation for load balancing)
 * - Backlog clamped internally if invalid (see listen(2) man page)
 * - No TLS/Proxy/DNS config; apply post-creation via SocketTLS_enable() etc.
 *
 * @note IPv4 only; for IPv6: Socket_new(AF_INET6, SOCK_STREAM, 0) + manual bind/listen
 * @warning Port <1024 requires root privileges (or setcap)
 * @note Ephemeral port: Check Socket_getlocalport(server) after bind
 * @complexity O(1)
 *
 * @see Socket_listen_unix() for Unix domain equivalent
 * @see Socket_bind() and Socket_listen() for low-level control
 * @see Socket_setreuseport() for multi-process sharing
 * @see SocketPool_accept_limited() for pooled accepts with limits
 */
T
Socket_listen_tcp (const char *host, int port, int backlog)
{
        T server = NULL;

        assert (port >= 0 && port <= SOCKET_MAX_PORT);
        assert (backlog > 0);

        TRY
        {
                /* Create IPv4 TCP socket */
                server = Socket_new (AF_INET, SOCK_STREAM, 0);

                /* Enable address reuse for quick restart */
                Socket_setreuseaddr (server);

                /* Bind to address/port */
                Socket_bind (server, host, port);

                /* Start listening */
                Socket_listen (server, backlog);
        }
        EXCEPT (Socket_Failed)
        {
                if (server)
                        Socket_free (&server);
                RERAISE;
        }
        END_TRY;

        return server;
}

/**
 * Socket_connect_tcp - Create a connected TCP client socket in one call
 * @host: Remote address (IP or hostname)
 * @port: Remote port (1-65535)
 * @timeout_ms: Connection timeout in milliseconds (0 = no timeout)
 *
 * Returns: New connected socket
 * Raises: Socket_Failed on error or timeout
 * Thread-safe: Yes
 *
 * Combines Socket_new(), timeout configuration, and Socket_connect()
 * into a single convenient call. If timeout_ms > 0, the connection
 * attempt will fail with ETIMEDOUT if it takes longer than specified.
 */
T
Socket_connect_tcp (const char *host, int port, int timeout_ms)
{
        T client = NULL;

        assert (host != NULL);
        assert (port > 0 && port <= SOCKET_MAX_PORT);
        assert (timeout_ms >= 0);

        TRY
        {
                /* Create IPv4 TCP socket */
                client = Socket_new (AF_INET, SOCK_STREAM, 0);

                /* Set connect timeout if specified */
                if (timeout_ms > 0)
                        {
                                SocketTimeouts_T timeouts = { 0 };
                                Socket_timeouts_get (client, &timeouts);
                                timeouts.connect_timeout_ms = timeout_ms;
                                Socket_timeouts_set (client, &timeouts);
                        }

                /* Connect to remote host */
                Socket_connect (client, host, port);
        }
        EXCEPT (Socket_Failed)
        {
                if (client)
                        Socket_free (&client);
                RERAISE;
        }
        END_TRY;

        return client;
}

/**
 * @brief Accept incoming connection with configurable timeout behavior.
 * @ingroup core_io
 *
 * Performs timed or blocking accept on listening socket. Behavior varies by timeout_ms:
 *
 * - -1: Blocks indefinitely using standard blocking accept (no mode change)
 * - 0: Immediate non-blocking check (temporarily enables non-blocking if needed)
 * - >0: Polls for POLLIN up to timeout_ms, then accepts if ready
 *
 * Returns NULL on timeout for positive timeouts without raising exception.
 * Restores original socket blocking mode after finite/immediate operations.
 *
 * @param[in] socket Listening Socket_T (must be bound and listening)
 * @param[in] timeout_ms Timeout: -1=infinite block, 0=immediate, >0=ms timeout
 *
 * @return New connected Socket_T on success, NULL on timeout (positive timeout_ms)
 *
 * @throws Socket_Failed On accept failure, poll error, invalid socket/fd, or system errors (EAGAIN not considered failure)
 *
 * @threadsafe Yes - per-socket operation, thread-local error buffers and mode restoration
 *
 * ## Usage Example
 *
 * @code{.c}
 * Socket_T server = Socket_listen_tcp("127.0.0.1", 8080, 128);
 *
 * // Block forever (traditional blocking accept)
 * Socket_T client1 = Socket_accept_timeout(server, -1);
 *
 * // Wait max 5s for connection
 * Socket_T client2 = Socket_accept_timeout(server, 5000);
 * if (client2 == NULL) {
 *     SOCKET_LOG_INFO_MSG("Accept timeout - no connection");
 *     // Continue or retry
 * }
 *
 * // Non-blocking immediate check
 * Socket_T client3 = Socket_accept_timeout(server, 0);
 * if (client3 == NULL) {
 *     // No pending connection
 * }
 *
 * Socket_free(&server);
 * @endcode
 *
 * ## Edge Cases and Notes
 *
 * - If socket already non-blocking, mode not changed
 * - Compatible with event loops (SocketPoll integration via non-blocking poll)
 * - For -1, relies on socket's configured timeouts if any (SO_RCVTIMEO etc.)
 * - Poll uses EINTR retry internally for signal safety
 * - On Windows, uses WSAPoll equivalent (poll emulation)
 *
 * @warning Listening socket state not validated; ensure Socket_islistening(socket) == 1
 * @note IPv4/IPv6/Unix domain supported via underlying Socket_accept()
 * @complexity O(1) average; O(timeout_ms / poll_interval) worst for long timeouts
 *
 * @see Socket_accept() base accept without timeout
 * @see Socket_listen_tcp() for TCP server creation
 * @see SocketPoll_add() for event-driven accept
 * @see docs/ASYNC_IO.md for non-blocking patterns
 */
T
Socket_accept_timeout (T socket, int timeout_ms)
{
        volatile T client = NULL;
        int fd = Socket_fd (socket);
        assert (socket);

        if (timeout_ms == -1) {
                /* Infinite block: use standard blocking accept, no mode change */
                TRY {
                        client = Socket_accept (socket);
                } EXCEPT (Socket_Failed) {
                        RERAISE;
                } END_TRY;
                return client;
        }

        /* Finite timeout or immediate: enable non-blocking mode temporarily */
        int original_flags;
        volatile int need_restore = 0;
        with_nonblocking_scope (fd, 1, &original_flags, &need_restore);

        TRY
        {
                int do_accept = 1;
                struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
                int poll_result;

                if (timeout_ms > 0) {
                        /* Poll for readiness with timeout */
                        poll_result = socket_poll_eintr_retry (&pfd, timeout_ms);
                        if (poll_result < 0) {
                                SOCKET_ERROR_FMT ("poll() failed in accept_timeout");
                                RAISE_MODULE_ERROR (Socket_Failed);
                        }
                        if (poll_result == 0) {
                                /* Timeout expired */
                                client = NULL;
                                do_accept = 0;
                        }
                } /* else timeout_ms == 0: immediate non-blocking accept, do_accept=1 */

                if (do_accept) {
                        client = Socket_accept (socket);
                }
        }
        FINALLY
        {
                /* Restore original mode */
                with_nonblocking_scope (fd, 0, &original_flags, &need_restore);
        }
        END_TRY;

        return client;
}

/**
 * Socket_connect_nonblocking - Initiate non-blocking connect (IP only)
 * @socket: Socket (will be set to non-blocking)
 * @ip_address: Remote IP address (IPv4 or IPv6, no hostnames)
 * @port: Remote port (1-65535)
 *
 * Returns: 0 if connected immediately, 1 if connection in progress
 * Raises: Socket_Failed on invalid IP or immediate failure
 * Thread-safe: Yes
 *
 * Initiates a non-blocking connect operation. The socket is set to
 * non-blocking mode before connecting. If the connection cannot be
 * completed immediately (common for TCP), returns 1 and the caller
 * should poll for POLLOUT to determine when the connection completes.
 *
 * Note: Does not accept hostnames - use Socket_connect() for hostname
 * resolution or SocketDNS for async resolution.
 */
int
Socket_connect_nonblocking (T socket, const char *ip_address, int port)
{
        struct sockaddr_storage addr;
        socklen_t addrlen = 0;
        int fd;
        int result;

        assert (socket);
        assert (ip_address != NULL);
        assert (port > 0 && port <= SOCKET_MAX_PORT);

        fd = Socket_fd (socket);

        /* Parse IP address */
        parse_ip_address (ip_address, &addr, &addrlen, port);

        /* Set socket to non-blocking mode */
        Socket_setnonblocking (socket);

        /* Initiate connect */
        result = connect (fd, (struct sockaddr *)&addr, addrlen);

        if (result == 0)
                {
                        /* Connected immediately (rare for TCP, common for Unix domain) */
                        return 0;
                }

        if (errno == EINPROGRESS || errno == EINTR)
                {
                        /* Connection in progress - caller should poll for POLLOUT */
                        return 1;
                }

        /* Immediate failure */
        SOCKET_ERROR_FMT ("Connect to %.*s:%d failed", SOCKET_ERROR_MAX_HOSTNAME,
                          ip_address, port);
        RAISE_MODULE_ERROR (Socket_Failed);
}

/* ============================================================================
 * Unix Domain Socket Convenience Functions
 * ============================================================================
 */

/**
 * Socket_listen_unix - Create a listening Unix domain socket in one call
 * @path: Socket file path (or '@' prefix for abstract namespace on Linux)
 * @backlog: Maximum pending connections (must be > 0)
 *
 * Returns: New listening Unix domain socket
 * Raises: Socket_Failed on error
 * Thread-safe: Yes
 *
 * Combines Socket_new(), Socket_bind_unix(), and Socket_listen() into
 * a single convenient call. For filesystem paths, any existing socket
 * file is removed before binding (handled by Socket_bind_unix).
 *
 * For abstract namespace sockets (Linux only), prefix the path with '@'.
 */
T
Socket_listen_unix (const char *path, int backlog)
{
        T server = NULL;

        assert (path != NULL);
        assert (backlog > 0);

        TRY
        {
                /* Create Unix domain stream socket */
                server = Socket_new (AF_UNIX, SOCK_STREAM, 0);

                /* Bind to path */
                Socket_bind_unix (server, path);

                /* Start listening */
                Socket_listen (server, backlog);
        }
        EXCEPT (Socket_Failed)
        {
                if (server)
                        Socket_free (&server);
                RERAISE;
        }
        END_TRY;

        return server;
}

/**
 * @brief Connect to Unix domain socket with optional timeout control.
 * @ingroup core_io
 *
 * Establishes a connection to a Unix domain server socket. Supports both blocking
 * and timed non-blocking connection attempts.
 *
 * - timeout_ms == 0: Performs blocking connect using high-level Socket_connect_unix() (no temporary mode change)
 * - timeout_ms > 0: Non-blocking connect initiation + POLLOUT poll up to timeout_ms, then verifies completion
 *
 * Supports filesystem paths and Linux abstract namespace (prefix path with '@').
 * Validates path length and builds sockaddr_un internally.
 *
 * @param[in] socket Pre-created AF_UNIX SOCK_STREAM socket
 * @param[in] path Socket file path or abstract name (e.g., "@abstract")
 * @param[in] timeout_ms 0=blocking (no timeout), >0=milliseconds timeout
 *
 * @throws Socket_Failed On immediate connect failure, poll failure, timeout expiration (ETIMEDOUT),
 *                       invalid path length (>=108 bytes), or system errors (EINPROGRESS handled internally)
 *
 * @threadsafe Yes - per-socket, thread-local errors, atomic mode changes
 *
 * ## Usage Example
 *
 * @code{.c}
 * Socket_T client = Socket_new(AF_UNIX, SOCK_STREAM, 0);
 *
 * TRY {
 *   // Blocking connect - waits indefinitely
 *   Socket_connect_unix_timeout(client, "/var/run/myserver.sock", 0);
 * } EXCEPT(Socket_Failed) {
 *   // Connect failed (e.g., no server, permission denied)
 *   Socket_free(&client);
 *   return -1;
 * }
 *
 * // Use client...
 * Socket_free(&client);
 *
 * TRY {
 *   Socket_T timed_client = Socket_new(AF_UNIX, SOCK_STREAM, 0);
 *   Socket_connect_unix_timeout(timed_client, "@abstract_server", 3000);  // 3s timeout
 * } EXCEPT(Socket_Failed) {
 *   // Timeout or error
 * }
 * @endcode
 *
 * ## Behavior Details
 *
 * - For blocking (0): Delegates to Socket_connect_unix() for consistency with library API
 * - For timed (>0): Manually constructs sockaddr_un and calls connect(); polls POLLOUT for completion
 * - Abstract sockets: '@' prefix sets sun_path[0]='\0' per Linux man pages
 * - Error checking: Uses getsockopt(SO_ERROR) post-poll to detect connect outcome
 * - Mode restoration: Always restores original blocking mode after timed operations
 * - EINTR/EAGAIN handled during poll and connect
 *
 * @note Path must be null-terminated; max length ~108 bytes (sizeof(sun_path)-1)
 * @warning Socket must be unused AF_UNIX stream; reuse raises undefined behavior
 * @note No support for -1 (infinite); use 0 for blocking
 * @complexity O(1) for blocking; O(timeout_ms) for timed polls
 *
 * @see Socket_connect_unix() for blocking connect without timeout param
 * @see Socket_listen_unix() for server-side Unix socket setup
 * @see with_nonblocking_scope() internal mode management helper
 * @see docs/SECURITY.md#unix-domain-sockets for security considerations
 */
void
Socket_connect_unix_timeout (T socket, const char *path, int timeout_ms)
{
        struct sockaddr_un addr;
        size_t path_len;
        int fd;
        volatile int original_flags = 0;
        volatile int need_restore = 0;
        int result;

        assert (socket);
        assert (path != NULL);
        assert (timeout_ms >= 0);

        fd = Socket_fd (socket);
        path_len = strlen (path);

        /* Validate path length */
        if (path_len == 0 || path_len >= sizeof (addr.sun_path)) {
                SOCKET_ERROR_MSG ("Invalid Unix socket path length: %zu", path_len);
                RAISE_MODULE_ERROR (Socket_Failed);
        }

        /* Build address */
        memset (&addr, 0, sizeof (addr));
        addr.sun_family = AF_UNIX;

        /* Handle abstract sockets (Linux: '@' prefix becomes '\0') */
        if (path[0] == '@') {
                addr.sun_path[0] = '\0';
                memcpy (addr.sun_path + 1, path + 1, path_len - 1);
        } else {
                memcpy (addr.sun_path, path, path_len);
        }

        if (timeout_ms == 0) {
                /* Blocking connect: delegate to high-level API, no mode change */
                TRY {
                        Socket_connect_unix (socket, path);
                } EXCEPT (Socket_Failed) {
                        RERAISE;
                } END_TRY;
                return;
        }

        /* Timed connect: enable non-blocking temporarily */
        with_nonblocking_scope (fd, 1, &original_flags, &need_restore);

        result = connect (fd, (struct sockaddr *)&addr, sizeof (addr));

        if (result == 0 || errno == EISCONN) {
                /* Immediate success - restore flags and return */
                with_nonblocking_scope (fd, 0, (int *)&original_flags, &need_restore);
                return;
        }

        if (errno != EINPROGRESS && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                /* Immediate failure - restore flags before raising */
                with_nonblocking_scope (fd, 0, (int *)&original_flags, &need_restore);
                SOCKET_ERROR_FMT ("Unix connect to %.*s failed",
                                  SOCKET_ERROR_MAX_HOSTNAME, path);
                RAISE_MODULE_ERROR (Socket_Failed);
        }

        /* In progress: poll for completion */
        TRY {
                struct pollfd pfd = { .fd = fd, .events = POLLOUT, .revents = 0 };
                int poll_result = socket_poll_eintr_retry (&pfd, timeout_ms);

                if (poll_result < 0) {
                        SOCKET_ERROR_FMT ("poll() failed during Unix connect");
                        RAISE_MODULE_ERROR (Socket_Failed);
                }

                if (poll_result == 0) {
                        errno = ETIMEDOUT;
                        SOCKET_ERROR_MSG ("%s: Unix connect to %.*s",
                                          SOCKET_ETIMEDOUT, SOCKET_ERROR_MAX_HOSTNAME, path);
                        RAISE_MODULE_ERROR (Socket_Failed);
                }

                /* Verify connect outcome */
                check_connect_result (fd, path);
        }
        FINALLY {
                /* Restore original mode */
                with_nonblocking_scope (fd, 0, (int *)&original_flags, &need_restore);
        }
        END_TRY;
}

#undef T
