#ifndef SOCKETPOOL_INCLUDED
#define SOCKETPOOL_INCLUDED

#include "core/Arena.h"
#include "core/Except.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"
#include <stddef.h>
#include <time.h>

/**
 * Socket Connection Pool
 * Manages a pool of socket connections with associated buffers and
 * metadata. Provides O(1) connection lookup using hash tables and
 * automatic cleanup of idle connections.
 * Features:
 * - Pre-allocated connection slots for predictable memory usage
 * - Hash table for O(1) socket lookup
 * - Automatic idle connection cleanup
 * - Per-connection input/output buffers
 * - User data storage per connection
 * The Connection_T type is opaque - use accessor functions to
 * access connection properties.
 */

#define T SocketPool_T
typedef struct T *T;

/* Opaque connection type - use accessor functions */
typedef struct Connection *Connection_T;

/* Exception types */
extern Except_T SocketPool_Failed; /**< Pool operation failure */

/**
 * SocketPool_new - Create a new connection pool
 * @arena: Arena for memory allocation
 * @maxconns: Maximum number of connections
 * @bufsize: Size of I/O buffers per connection
 * Returns: New pool instance (never returns NULL)
 * Raises: SocketPool_Failed on any allocation or initialization failure
 * Thread-safe: Yes - returns new instance
 */
extern T SocketPool_new(Arena_T arena, size_t maxconns, size_t bufsize);

/**
 * SocketPool_free - Free a connection pool
 * @pool: Pointer to pool (will be set to NULL)
 * Note: Does not close sockets - caller must do that
 */
extern void SocketPool_free(T *pool);

/**
 * SocketPool_get - Look up connection by socket
 * @pool: Pool instance
 * @socket: Socket to find
 * Returns: Connection or NULL if not found
 * Thread-safe: Yes - protected by internal mutex
 * O(1) operation using hash table lookup
 * Thread Safety Note: The returned Connection_T pointer is valid only while
 * the connection remains in the pool. The caller should not cache this pointer
 * across operations that might remove the connection (like cleanup). The
 * Connection_T structure itself is stable once allocated, but could be removed
 * from the pool by another thread.
 */
extern Connection_T SocketPool_get(T pool, Socket_T socket);

/**
 * SocketPool_add - Add socket to pool
 * @pool: Pool instance
 * @socket: Socket to add
 * Returns: New connection or NULL if pool is full
 * Thread-safe: Yes - protected by internal mutex
 * Allocates I/O buffers and initializes connection
 */
extern Connection_T SocketPool_add(T pool, Socket_T socket);

/**
 * SocketPool_accept_batch - Accept multiple connections from server socket
 * @pool: Pool instance
 * @server: Server socket to accept from (must be listening and non-blocking)
 * @max_accepts: Maximum number of connections to accept (1-1000)
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
 *
 * Example usage:
 *   Socket_T accepted[100];
 *   int count = SocketPool_accept_batch(pool, server, 100, accepted);
 *   for (int i = 0; i < count; i++) {
 *       SocketPoll_add(poll, accepted[i], POLL_READ | POLL_WRITE, NULL);
 *   }
 */
extern int SocketPool_accept_batch(T pool, Socket_T server, int max_accepts, Socket_T *accepted);

/**
 * SocketPool_remove - Remove socket from pool
 * @pool: Pool instance
 * @socket: Socket to remove
 * Clears buffers but does not close the socket
 * Thread-safe: Yes - protected by internal mutex
 */
extern void SocketPool_remove(T pool, Socket_T socket);

/**
 * SocketPool_cleanup - Remove idle connections
 * @pool: Pool instance
 * @idle_timeout: Seconds of inactivity before removal (0 = remove all)
 * Automatically closes and removes idle sockets.
 * Pass 0 for idle_timeout to close all connections immediately.
 * Thread-safe: Yes - collects sockets under mutex, closes outside lock
 * Performance: O(n) where n is maxconns (scans all connection slots)
 */
extern void SocketPool_cleanup(T pool, time_t idle_timeout);

/**
 * SocketPool_count - Get active connection count
 * @pool: Pool instance
 * Returns: Number of active connections
 * Thread-safe: Yes - protected by internal mutex
 */
extern size_t SocketPool_count(T pool);

/**
 * SocketPool_resize - Resize pool capacity at runtime
 * @pool: Pool instance
 * @new_maxconns: New maximum connection capacity
 * Raises: SocketPool_Failed on error
 * Thread-safe: Yes - uses internal mutex
 *
 * Dynamically grows or shrinks the pool capacity:
 * - Growing: Allocates new connection slots and buffers
 * - Shrinking: Closes excess active connections first, then reduces capacity
 * - Same size: No-op (returns immediately)
 *
 * When shrinking, excess connections are closed gracefully. The pool
 * maintains its existing connections up to the new limit.
 *
 * Performance: O(n) where n is maxconns (scans all slots for shrink).
 * Growing is typically faster than shrinking due to no connection cleanup.
 *
 * Example usage:
 *   // Grow pool for burst handling
 *   SocketPool_resize(pool, 10000);
 *
 *   // Shrink pool after burst subsides
 *   SocketPool_resize(pool, 1000);
 */
extern void SocketPool_resize(T pool, size_t new_maxconns);

/**
 * SocketPool_prewarm - Pre-allocate buffers for percentage of free slots
 * @pool: Pool instance
 * @percentage: Percentage of free slots to pre-warm (0-100)
 * Thread-safe: Yes - uses internal mutex
 *
 * Pre-allocates I/O buffers for a percentage of free connection slots.
 * This reduces latency during connection bursts by avoiding buffer
 * allocation at connection time.
 *
 * Default: Called automatically with 20% in SocketPool_new().
 * Can be called multiple times to adjust pre-warming level.
 *
 * Performance: O(n) where n is prewarm_count (iterates free list).
 * Typically called once during initialization.
 *
 * Example usage:
 *   // Pre-warm 50% of slots for high-traffic scenarios
 *   SocketPool_prewarm(pool, 50);
 */
extern void SocketPool_prewarm(T pool, int percentage);

/**
 * SocketPool_set_bufsize - Set buffer size for future connections
 * @pool: Pool instance
 * @new_bufsize: New buffer size in bytes
 * Thread-safe: Yes - uses internal mutex
 *
 * Changes the buffer size used for new connections. Existing connections
 * keep their current buffers. New buffers are allocated with the new size
 * when connections are added or reused.
 *
 * Validates against SOCKET_MIN_BUFFER_SIZE and SOCKET_MAX_BUFFER_SIZE.
 *
 * Example usage:
 *   // Increase buffer size for high-throughput connections
 *   SocketPool_set_bufsize(pool, 65536);
 */
extern void SocketPool_set_bufsize(T pool, size_t new_bufsize);

/**
 * SocketPool_foreach - Iterate over connections
 * @pool: Pool instance
 * @func: Callback function
 * @arg: User data for callback
 * Calls func for each active connection
 * Thread-safe: Yes - holds mutex during iteration
 * Performance: O(n) where n is maxconns (scans all connection slots)
 * Warning: Callback must not modify pool structure
 */
extern void SocketPool_foreach(T pool, void (*func)(Connection_T, void *), void *arg);

/* Connection accessor functions */

/**
 * Connection_socket - Get connection's socket
 * @conn: Connection instance
 * Returns: Associated socket
 */
extern Socket_T Connection_socket(const Connection_T conn);

/**
 * Connection_inbuf - Get input buffer
 * @conn: Connection instance
 * Returns: Input buffer for reading data
 */
extern SocketBuf_T Connection_inbuf(const Connection_T conn);

/**
 * Connection_outbuf - Get output buffer
 * @conn: Connection instance
 * Returns: Output buffer for writing data
 */
extern SocketBuf_T Connection_outbuf(const Connection_T conn);

/**
 * Connection_data - Get user data
 * @conn: Connection instance
 * Returns: User-defined data pointer
 */
extern void *Connection_data(const Connection_T conn);

/**
 * Connection_setdata - Set user data
 * @conn: Connection instance
 * @data: User data to store
 */
extern void Connection_setdata(Connection_T conn, void *data);

/**
 * Connection_lastactivity - Get last activity time
 * @conn: Connection instance
 * Returns: time_t of last activity
 */
extern time_t Connection_lastactivity(const Connection_T conn);

/**
 * Connection_isactive - Check if connection is active
 * @conn: Connection instance
 * Returns: Non-zero if active
 */
extern int Connection_isactive(const Connection_T conn);

#undef T
#endif
