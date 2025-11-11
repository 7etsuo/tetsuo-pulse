#ifndef SOCKETPOOL_INCLUDED
#define SOCKETPOOL_INCLUDED

#include <stddef.h>
#include <time.h>
#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketError.h" /* For socket_error_buf in macros */
#include "socket/Socket.h"
#include "socket/SocketBuf.h"

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
 * - Dynamic resize and pre-warming for performance
 * The Connection_T type is opaque - use accessor functions to
 * access connection properties.
 * Thread Safety: All operations are thread-safe via internal mutex.
 * The pool can be used from multiple threads simultaneously.
 * PLATFORM REQUIREMENTS:
 * - POSIX-compliant system (Linux, BSD, macOS)
 * - POSIX threads (pthread) for mutex synchronization
 * - NOT portable to Windows without pthreads adaptation
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
 * Automatically pre-warms SOCKET_POOL_DEFAULT_PREWARM_PCT slots.
 */
extern T SocketPool_new(Arena_T arena, size_t maxconns, size_t bufsize);

/**
 * SocketPool_free - Free a connection pool
 * @pool: Pointer to pool (will be set to NULL)
 * Note: Does not close sockets - caller must do that
 * Thread-safe: Yes
 */
extern void SocketPool_free(T *pool);

/**
 * SocketPool_get - Look up connection by socket
 * @pool: Pool instance
 * @socket: Socket to find
 * Returns: Connection or NULL if not found
 * Thread-safe: Yes
 * O(1) hash lookup. Updates last_activity timestamp.
 */
extern Connection_T SocketPool_get(T pool, Socket_T socket);

/**
 * SocketPool_add - Add socket to pool
 * @pool: Pool instance
 * @socket: Socket to add
 * Returns: New connection or NULL if pool is full
 * Thread-safe: Yes
 * Allocates I/O buffers and initializes connection metadata.
 */
extern Connection_T SocketPool_add(T pool, Socket_T socket);

/**
 * SocketPool_accept_batch - Accept multiple connections from server socket
 * @pool: Pool instance
 * @server: Server socket (listening, non-blocking)
 * @max_accepts: Max to accept (1-SOCKET_POOL_MAX_BATCH_ACCEPTS)
 * @accepted: Output array of accepted sockets (pre-allocated)
 * Returns: Number accepted (0 to max_accepts)
 * Raises: SocketPool_Failed on error
 * Thread-safe: Yes
 * Efficient batch accept using accept4() where available.
 * Automatically adds accepted sockets to pool.
 */
extern int SocketPool_accept_batch(T pool, Socket_T server, int max_accepts, Socket_T *accepted);

/**
 * SocketPool_remove - Remove socket from pool
 * @pool: Pool instance
 * @socket: Socket to remove
 * Clears buffers but does not close socket
 * Thread-safe: Yes
 */
extern void SocketPool_remove(T pool, Socket_T socket);

/**
 * SocketPool_cleanup - Remove idle connections
 * @pool: Pool instance
 * @idle_timeout: Seconds inactive before removal (0 = remove all)
 * Thread-safe: Yes
 * O(n) scan of all slots; closes/removes idle ones.
 */
extern void SocketPool_cleanup(T pool, time_t idle_timeout);

/**
 * SocketPool_count - Get active connection count
 * @pool: Pool instance
 * Returns: Number of active connections
 * Thread-safe: Yes
 */
extern size_t SocketPool_count(T pool);

/**
 * SocketPool_resize - Resize pool capacity at runtime
 * @pool: Pool instance
 * @new_maxconns: New maximum
 * Raises: SocketPool_Failed on error
 * Thread-safe: Yes
 * Grows/shrinks pool; closes excess on shrink.
 */
extern void SocketPool_resize(T pool, size_t new_maxconns);

/**
 * SocketPool_prewarm - Pre-allocate buffers for % of free slots
 * @pool: Pool instance
 * @percentage: % of free slots (0-100)
 * Thread-safe: Yes
 * Reduces latency by pre-allocating buffers.
 */
extern void SocketPool_prewarm(T pool, int percentage);

/**
 * SocketPool_set_bufsize - Set buffer size for future connections
 * @pool: Pool instance
 * @new_bufsize: New size
 * Thread-safe: Yes
 * Existing connections keep old size.
 */
extern void SocketPool_set_bufsize(T pool, size_t new_bufsize);

/**
 * SocketPool_foreach - Iterate over active connections
 * @pool: Pool instance
 * @func: Callback (Connection_T, void*)
 * @arg: User data
 * Thread-safe: Yes - holds mutex
 * O(n) scan; callback must not modify pool.
 */
extern void SocketPool_foreach(T pool, void (*func)(Connection_T, void *), void *arg);

/* Connection accessors */

/**
 * Connection_socket - Get connection's socket
 * @conn: Connection
 * Returns: Socket
 */
extern Socket_T Connection_socket(const Connection_T conn);

/**
 * Connection_inbuf - Get input buffer
 * @conn: Connection
 * Returns: Input buffer
 */
extern SocketBuf_T Connection_inbuf(const Connection_T conn);

/**
 * Connection_outbuf - Get output buffer
 * @conn: Connection
 * Returns: Output buffer
 */
extern SocketBuf_T Connection_outbuf(const Connection_T conn);

/**
 * Connection_data - Get user data
 * @conn: Connection
 * Returns: User data
 */
extern void *Connection_data(const Connection_T conn);

/**
 * Connection_setdata - Set user data
 * @conn: Connection
 * @data: Data
 */
extern void Connection_setdata(Connection_T conn, void *data);

/**
 * Connection_lastactivity - Get last activity time
 * @conn: Connection
 * Returns: time_t
 */
extern time_t Connection_lastactivity(const Connection_T conn);

/**
 * Connection_isactive - Check if active
 * @conn: Connection
 * Returns: Non-zero if active
 */
extern int Connection_isactive(const Connection_T conn);

#undef T
#endif
