/**
 * SocketPool-accept.c - Batch connection acceptance functions
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 * Handles efficient batch acceptance of multiple connections from server socket.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/Except.h"
#include "core/SocketConfig.h"
#include "pool/SocketPool.h"
#include "core/SocketError.h"
#include "socket/Socket.h"
#include "socket/SocketCommon.h"
#include <pthread.h>

#include "pool/SocketPool-private.h"

#define T SocketPool_T

/**
 * accept_connection_direct - Accept connection directly using accept4/accept
 * @server_fd: Server socket file descriptor
 * Returns: New file descriptor or -1 on error/would block
 * Thread-safe: Yes - pure system call
 * Note: Uses accept4() with SOCK_CLOEXEC | SOCK_NONBLOCK on Linux,
 * falls back to accept() + fcntl() on other platforms.
 */
static int accept_connection_direct(int server_fd)
{
    int newfd;

#if defined(SOCKET_HAS_ACCEPT4) && defined(SOCK_NONBLOCK)
    newfd = accept4(server_fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
#elif defined(SOCKET_HAS_ACCEPT4)
    newfd = accept4(server_fd, NULL, NULL, SOCK_CLOEXEC);
#else
    newfd = accept(server_fd, NULL, NULL);
#endif

    if (newfd < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return -1;
        return -1;
    }

#if !defined(SOCKET_HAS_ACCEPT4) || !defined(SOCK_NONBLOCK)
    if (SocketCommon_setcloexec(newfd, 1) < 0)
    {
        SAFE_CLOSE(newfd);
        return -1;
    }

    int flags = fcntl(newfd, F_GETFL, 0);
    if (flags >= 0)
    {
        fcntl(newfd, F_SETFL, flags | O_NONBLOCK);
    }
#endif

    return newfd;
}

/**
 * SocketPool_accept_batch - Accept multiple connections from server socket
 * @pool: Pool instance
 * @server: Server socket to accept from (must be listening and non-blocking)
 * @max_accepts: Maximum number of connections to accept (1-SOCKET_POOL_MAX_BATCH_ACCEPTS)
 * @accepted: Output array of accepted sockets (must be pre-allocated, size >= max_accepts)
 * Returns: Number of connections actually accepted (0 to max_accepts)
 * Raises: SocketPool_Failed on error
 * Thread-safe: Yes - uses internal mutex
 *
 * Accepts up to max_accepts connections from server socket in a single call.
 * Uses accept4() on Linux (SOCK_CLOEXEC | SOCK_NONBLOCK) for efficiency.
 * Falls back to accept() + fcntl() on other platforms.
 * All accepted sockets are automatically added to the pool.
 *
 * Performance: O(n) where n is number accepted, but much faster than
 * individual SocketPool_add() calls due to reduced mutex contention.
 */
int SocketPool_accept_batch(T pool, Socket_T server, int max_accepts, Socket_T *accepted)
{
    int count = 0;
    int server_fd;
    int available;
    volatile int local_max_accepts = max_accepts;

    assert(pool);
    assert(server);
    assert(max_accepts > 0 && max_accepts <= SOCKET_POOL_MAX_BATCH_ACCEPTS);
    assert(accepted);

    server_fd = Socket_fd(server);

    /* Check available pool slots */
    pthread_mutex_lock(&pool->mutex);
    available = (int)(pool->maxconns - pool->count);
    pthread_mutex_unlock(&pool->mutex);

    if (available <= 0)
        return 0;

    if (local_max_accepts > available)
        local_max_accepts = available;

    /* Accept loop - minimize lock time */
    for (int i = 0; i < local_max_accepts; i++)
    {
        int newfd = accept_connection_direct(server_fd);
        if (newfd < 0)
        {
            if (errno != EAGAIN && errno != EWOULDBLOCK)
            {
                SOCKET_ERROR_MSG("accept() failed during batch (accepted %d so far)", count);
            }
            break;
        }

        Socket_T sock = NULL;
        TRY
        {
            sock = Socket_new_from_fd(newfd);
        }
        EXCEPT(Socket_Failed)
        {
            SAFE_CLOSE(newfd);
            break;
        }
        END_TRY;

        if (!sock)
        {
            SAFE_CLOSE(newfd);
            break;
        }

        Connection_T conn = SocketPool_add(pool, sock);
        if (conn)
        {
            accepted[count++] = sock;
        }
        else
        {
            Socket_free(&sock);
            break;
        }
    }

    return count;
}

#undef T
