/**
 * SocketPool-accessors.c - Connection accessor functions
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Provides accessor functions for Connection_T opaque type.
 */

#include <assert.h>
#include <time.h>

#include "pool/SocketPool-private.h"

/**
 * Connection_socket - Get connection's socket
 * @conn: Connection instance
 *
 * Returns: Associated socket
 * Thread-safe: Yes - read-only access
 */
Socket_T
Connection_socket (const Connection_T conn)
{
  assert (conn);
  return conn->socket;
}

/**
 * Connection_inbuf - Get input buffer
 * @conn: Connection instance
 *
 * Returns: Input buffer
 * Thread-safe: Yes - read-only access
 */
SocketBuf_T
Connection_inbuf (const Connection_T conn)
{
  assert (conn);
  return conn->inbuf;
}

/**
 * Connection_outbuf - Get output buffer
 * @conn: Connection instance
 *
 * Returns: Output buffer
 * Thread-safe: Yes - read-only access
 */
SocketBuf_T
Connection_outbuf (const Connection_T conn)
{
  assert (conn);
  return conn->outbuf;
}

/**
 * Connection_data - Get user data
 * @conn: Connection instance
 *
 * Returns: User data pointer
 * Thread-safe: Yes - read-only access
 */
void *
Connection_data (const Connection_T conn)
{
  assert (conn);
  return conn->data;
}

/**
 * Connection_setdata - Set user data
 * @conn: Connection instance
 * @data: User data pointer to store
 *
 * Thread-safe: No - caller must synchronize
 */
void
Connection_setdata (Connection_T conn, void *data)
{
  assert (conn);
  conn->data = data;
}

/**
 * Connection_lastactivity - Get last activity time
 * @conn: Connection instance
 *
 * Returns: Last activity timestamp
 * Thread-safe: Yes - read-only access
 */
time_t
Connection_lastactivity (const Connection_T conn)
{
  assert (conn);
  return conn->last_activity;
}

/**
 * Connection_isactive - Check if connection is active
 * @conn: Connection instance
 *
 * Returns: Non-zero if active
 * Thread-safe: Yes - read-only access
 */
int
Connection_isactive (const Connection_T conn)
{
  assert (conn);
  return conn->active;
}

