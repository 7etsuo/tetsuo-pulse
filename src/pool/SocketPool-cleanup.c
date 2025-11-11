/**
 * SocketPool-cleanup.c - Idle connection cleanup functions
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 * Handles automatic cleanup of idle connections to manage resources.
 */

#include <assert.h>
#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <stdlib.h>
#include <time.h>

#include "core/Except.h"
#include "core/SocketConfig.h"
#include "pool/SocketPool.h"
#include "pool/SocketPool-private.h" /* For structs */
#include "core/SocketError.h"
#include "socket/Socket.h"

#include "pool/SocketPool-core.h"    /* For safe_time */
#include "pool/SocketPool-private.h" /* For Connection_T and structs */

#define T SocketPool_T

extern Except_T SocketPool_Failed;
extern __thread Except_T SocketPool_DetailedException;

#define RAISE_POOL_ERROR(exception)                                                                                    \
    do                                                                                                                 \
    {                                                                                                                  \
        SocketPool_DetailedException = (exception);                                                                    \
        SocketPool_DetailedException.reason = socket_error_buf;                                                        \
        RAISE(SocketPool_DetailedException);                                                                           \
    } while (0)

/**
 * should_close_connection - Determine if connection should be closed
 * @idle_timeout: Idle timeout in seconds (0 means close all)
 * @now: Current time
 * @last_activity: Last activity time
 * Returns: 1 if close, 0 otherwise
 * Thread-safe: Yes - pure function
 */
static int should_close_connection(time_t idle_timeout, time_t now, time_t last_activity)
{
    if (idle_timeout == 0)
        return 1;
    return difftime(now, last_activity) > (double)idle_timeout;
}

/**
 * should_collect_socket - Check if socket should be collected
 * @conn: Conn
 * @idle_timeout: Timeout
 * @now: Time
 * Returns: 1 if collect
 */
static int should_collect_socket(const Connection_T conn, time_t idle_timeout, time_t now)
{
    if (!conn->active || !conn->socket)
        return 0;

    return should_close_connection(idle_timeout, now, conn->last_activity);
}

/**
 * collect_idle_sockets - Collect idle sockets into buffer
 * @pool: Pool
 * @idle_timeout: Timeout
 * @now: Time
 * Returns: Count collected
 * Thread-safe: Mutex held
 */
static size_t collect_idle_sockets(T pool, time_t idle_timeout, time_t now)
{
    size_t i;
    size_t close_count = 0;

    for (i = 0; i < pool->maxconns; i++)
    {
        if (should_collect_socket(&pool->connections[i], idle_timeout, now))
        {
            pool->cleanup_buffer[close_count++] = pool->connections[i].socket;
        }
    }
    return close_count;
}

/**
 * close_collected_sockets - Close and remove collected
 * @pool: Pool
 * @close_count: Count
 * Thread-safe: No mutex - call outside lock
 */
static void close_collected_sockets(T pool, size_t close_count)
{
    volatile size_t i;

    for (i = 0; i < close_count; i++)
    {
        TRY
        {
            SocketPool_remove(pool, pool->cleanup_buffer[i]);
            Socket_free(&pool->cleanup_buffer[i]);
        }
        EXCEPT(SocketPool_Failed)
        {
            /* Ignore - may already removed */
        }
        EXCEPT(Socket_Failed)
        {
            /* Ignore free fail */
        }
        END_TRY;
    }
}

/**
 * SocketPool_cleanup - Remove idle connections
 * @pool: Pool
 * @idle_timeout: Seconds idle before removal (0 = all)
 * Thread-safe: Yes
 * Performance: O(n) scan
 */
void SocketPool_cleanup(T pool, time_t idle_timeout)
{
    time_t now;
    size_t close_count;

    assert(pool);
    assert(pool->cleanup_buffer);

    TRY
    {
        now = safe_time();

        pthread_mutex_lock(&pool->mutex);
        close_count = collect_idle_sockets(pool, idle_timeout, now);
        pthread_mutex_unlock(&pool->mutex);

        close_collected_sockets(pool, close_count);
    }
    EXCEPT(SocketPool_Failed)
    {
        /* Already raised */
    }
    END_TRY;
}

#undef T
