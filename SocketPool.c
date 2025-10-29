/**
 * SocketPool.c - Connection pool implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 */

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "Arena.h"
#include "Except.h"
#include "Socket.h"
#include "SocketBuf.h"
#include "SocketConfig.h"
#include "SocketError.h"
#include "SocketPool.h"

Except_T SocketPool_Failed = { "SocketPool operation failed" };

/* This is a COPY of the base exception with thread-local reason string.
 * Each thread gets its own exception instance, preventing race conditions
 * when multiple threads raise the same exception type simultaneously. */
#ifdef _WIN32
static __declspec (thread) Except_T SocketPool_DetailedException;
#else
static __thread Except_T SocketPool_DetailedException;
#endif

/* Creates a thread-local copy of the exception with detailed reason */
#define RAISE_POOL_ERROR(exception)                                            \
  do                                                                           \
    {                                                                          \
      SocketPool_DetailedException = (exception);                              \
      SocketPool_DetailedException.reason = socket_error_buf;                  \
      RAISE (SocketPool_DetailedException);                                    \
    }                                                                          \
  while (0)

/* Safe time retrieval - fails fast on system time errors */
static time_t
safe_time (void)
{
  time_t t = time (NULL);
  if (t == (time_t)-1)
    {
      SOCKET_ERROR_MSG ("System time() call failed");
      RAISE_POOL_ERROR (SocketPool_Failed);
    }
  return t;
}

#define T SocketPool_T

/* Connection structure - now opaque to users */
struct Connection
{
  Socket_T socket;
  SocketBuf_T inbuf;
  SocketBuf_T outbuf;
  void *data;
  time_t last_activity;
  int active;
  struct Connection *hash_next; /* For hash table chaining */
};

/* Use configured hash table size for socket data mapping */
#define SOCKET_HASH_SIZE SOCKET_HASH_TABLE_SIZE

/* Hash function for socket file descriptors */
static unsigned
socket_hash (const Socket_T socket)
{
  int fd;

  assert (socket);
  fd = Socket_fd (socket);

  /* Defensive check: socket FDs should never be negative */
  assert (fd >= 0);

  /* Multiplicative hash with golden ratio */
  return ((unsigned)fd * 2654435761u) % SOCKET_HASH_SIZE;
}

struct T
{
  struct Connection *connections; /* Array of connection structs */
  Connection_T *hash_table;       /* Hash table for O(1) lookup */
  Socket_T *cleanup_buffer; /* Pre-allocated buffer for cleanup operations */
  size_t maxconns;
  size_t bufsize;
  size_t count;
  Arena_T arena;
  pthread_mutex_t mutex; /* Mutex for thread safety */
};

T
SocketPool_new (Arena_T arena, size_t maxconns, size_t bufsize)
{
  T pool;
  size_t i;

  assert (arena);
  assert (SOCKET_VALID_CONNECTION_COUNT (maxconns));
  assert (SOCKET_VALID_BUFFER_SIZE (bufsize));

  /* Enforce configured limits */
  if (maxconns > SOCKET_MAX_CONNECTIONS)
    maxconns = SOCKET_MAX_CONNECTIONS;
  if (bufsize > SOCKET_MAX_BUFFER_SIZE)
    bufsize = SOCKET_MAX_BUFFER_SIZE;
  if (bufsize < SOCKET_MIN_BUFFER_SIZE)
    bufsize = SOCKET_MIN_BUFFER_SIZE;

  pool = ALLOC (arena, sizeof (*pool));
  if (!pool)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate pool structure");
      RAISE_POOL_ERROR (SocketPool_Failed);
    }

  pool->connections = CALLOC (arena, maxconns, sizeof (struct Connection));
  if (!pool->connections)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate connections array");
      RAISE_POOL_ERROR (SocketPool_Failed);
    }

  pool->hash_table = CALLOC (arena, SOCKET_HASH_SIZE, sizeof (Connection_T));
  if (!pool->hash_table)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate hash table");
      RAISE_POOL_ERROR (SocketPool_Failed);
    }

  /* Pre-allocate cleanup buffer */
  pool->cleanup_buffer = CALLOC (arena, maxconns, sizeof (Socket_T));
  if (!pool->cleanup_buffer)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate cleanup buffer");
      RAISE_POOL_ERROR (SocketPool_Failed);
    }

  pool->maxconns = maxconns;
  pool->bufsize = bufsize;
  pool->count = 0;
  pool->arena = arena;

  /* Initialize mutex */
  if (pthread_mutex_init (&pool->mutex, NULL) != 0)
    {
      SOCKET_ERROR_MSG ("Failed to initialize pool mutex");
      RAISE_POOL_ERROR (SocketPool_Failed);
    }

  for (i = 0; i < maxconns; i++)
    {
      pool->connections[i].socket = NULL;
      pool->connections[i].inbuf = NULL;
      pool->connections[i].outbuf = NULL;
      pool->connections[i].data = NULL;
      pool->connections[i].last_activity = 0;
      pool->connections[i].active = 0;
      pool->connections[i].hash_next = NULL;
    }

  return pool;
}

void
SocketPool_free (T *pool)
{
  assert (pool && *pool);

  /* Destroy mutex */
  pthread_mutex_destroy (&(*pool)->mutex);

  *pool = NULL;
}

/* find_slot - Look up active connection by socket
 * @pool: Pool instance
 * @socket: Socket to find
 *
 * Returns: Active connection or NULL if not found
 *
 * O(1) average case hash table lookup. Must be called with pool mutex held. */
static Connection_T
find_slot (T pool, Socket_T socket)
{
  unsigned hash = socket_hash (socket);
  Connection_T conn = pool->hash_table[hash];

  /* Search the hash chain */
  while (conn)
    {
      if (conn->active && conn->socket == socket)
        return conn;
      conn = conn->hash_next;
    }
  return NULL;
}

/* find_free_slot - Find an inactive connection slot in the pool
 * @pool: Pool instance
 *
 * Returns: Inactive connection slot or NULL if pool is full
 *
 * O(n) operation scanning the connection array. Must be called with
 * pool mutex held. */
static Connection_T
find_free_slot (T pool)
{
  size_t i;

  for (i = 0; i < pool->maxconns; i++)
    {
      if (!pool->connections[i].active)
        {
          return &pool->connections[i];
        }
    }
  return NULL;
}

Connection_T
SocketPool_get (T pool, Socket_T socket)
{
  Connection_T conn;
  time_t now;

  assert (pool);
  assert (socket);

  /* Get time before acquiring lock to minimize lock hold time */
  now = safe_time ();

  pthread_mutex_lock (&pool->mutex);
  conn = find_slot (pool, socket);
  if (conn)
    conn->last_activity = now;
  pthread_mutex_unlock (&pool->mutex);

  return conn;
}

Connection_T
SocketPool_add (T pool, Socket_T socket)
{
  Connection_T conn;
  unsigned hash;

  assert (pool);
  assert (socket);

  pthread_mutex_lock (&pool->mutex);

  conn = find_slot (pool, socket);
  if (conn)
    {
      pthread_mutex_unlock (&pool->mutex);
      return conn;
    }

  conn = find_free_slot (pool);
  if (!conn)
    {
      pthread_mutex_unlock (&pool->mutex);
      return NULL;
    }

  /* Allocate buffers from arena - memory persists until arena disposal */
  conn->inbuf = SocketBuf_new (pool->arena, pool->bufsize);
  if (!conn->inbuf)
    {
      pthread_mutex_unlock (&pool->mutex);
      return NULL;
    }

  conn->outbuf = SocketBuf_new (pool->arena, pool->bufsize);
  if (!conn->outbuf)
    {
      /* inbuf memory persists in arena (arena-based allocation limitation) */
      SocketBuf_release (&conn->inbuf);
      pthread_mutex_unlock (&pool->mutex);
      return NULL;
    }

  conn->socket = socket;
  conn->data = NULL;
  conn->last_activity = safe_time ();
  conn->active = 1;

  /* Insert into hash table */
  hash = socket_hash (socket);
  conn->hash_next = pool->hash_table[hash];
  pool->hash_table[hash] = conn;

  pool->count++;

  pthread_mutex_unlock (&pool->mutex);

  return conn;
}

void
SocketPool_remove (T pool, Socket_T socket)
{
  Connection_T conn;
  unsigned hash;

  assert (pool);
  assert (socket);

  pthread_mutex_lock (&pool->mutex);

  conn = find_slot (pool, socket);
  if (!conn)
    {
      pthread_mutex_unlock (&pool->mutex);
      return;
    }

  /* Remove from hash table
   * Note: Hash chain nodes are allocated from arena and are not individually
   * freed. They remain in arena memory until arena disposal. This is expected
   * arena behavior. */
  hash = socket_hash (socket);
  Connection_T *pp = &pool->hash_table[hash];
  while (*pp)
    {
      if (*pp == conn)
        {
          *pp = conn->hash_next;
          break;
        }
      pp = &(*pp)->hash_next;
    }

  if (conn->inbuf)
    {
      SocketBuf_secureclear (conn->inbuf);
      SocketBuf_release (&conn->inbuf);
    }

  if (conn->outbuf)
    {
      SocketBuf_secureclear (conn->outbuf);
      SocketBuf_release (&conn->outbuf);
    }

  conn->socket = NULL;
  conn->data = NULL;
  conn->last_activity = 0;
  conn->active = 0;
  conn->hash_next = NULL;
  pool->count--;

  pthread_mutex_unlock (&pool->mutex);
}

void
SocketPool_cleanup (T pool, time_t idle_timeout)
{
  size_t i;
  time_t now;
  size_t close_count = 0;

  assert (pool);
  assert (pool->cleanup_buffer);
  /* Note: idle_timeout of 0 means close all connections */

  now = safe_time ();

  /* Collect sockets to close under lock - use pre-allocated buffer */
  pthread_mutex_lock (&pool->mutex);

  for (i = 0; i < pool->maxconns; i++)
    {
      if (pool->connections[i].active)
        {
          /* If idle_timeout is 0, close all connections
           * Otherwise, check if connection has been idle too long
           * Use difftime() for safe time_t arithmetic (handles signed/unsigned
           * differences) */
          if (idle_timeout == 0)
            {
              Socket_T socket = pool->connections[i].socket;
              if (socket)
                {
                  pool->cleanup_buffer[close_count++] = socket;
                }
            }
          else
            {
              /* Calculate time difference safely */
              double idle_seconds
                  = difftime (now, pool->connections[i].last_activity);
              /* Validate result is non-negative and exceeds timeout */
              if (idle_seconds >= 0.0 && idle_seconds > (double)idle_timeout)
                {
                  Socket_T socket = pool->connections[i].socket;
                  if (socket)
                    {
                      pool->cleanup_buffer[close_count++] = socket;
                    }
                }
            }
        }
    }

  pthread_mutex_unlock (&pool->mutex);

  /* Close sockets outside of lock to avoid deadlock */
  for (i = 0; i < close_count; i++)
    {
      SocketPool_remove (pool, pool->cleanup_buffer[i]);
      Socket_free (&pool->cleanup_buffer[i]);
    }
}

size_t
SocketPool_count (T pool)
{
  size_t count;
  assert (pool);

  pthread_mutex_lock (&pool->mutex);
  count = pool->count;
  pthread_mutex_unlock (&pool->mutex);

  return count;
}

void
SocketPool_foreach (T pool, void (*func) (Connection_T, void *), void *arg)
{
  size_t i;

  assert (pool);
  assert (func);

  pthread_mutex_lock (&pool->mutex);

  for (i = 0; i < pool->maxconns; i++)
    {
      if (pool->connections[i].active)
        {
          func (&pool->connections[i], arg);
        }
    }

  pthread_mutex_unlock (&pool->mutex);
}

/* Connection accessor functions */
Socket_T
Connection_socket (const Connection_T conn)
{
  assert (conn);
  return conn->socket;
}

SocketBuf_T
Connection_inbuf (const Connection_T conn)
{
  assert (conn);
  return conn->inbuf;
}

SocketBuf_T
Connection_outbuf (const Connection_T conn)
{
  assert (conn);
  return conn->outbuf;
}

void *
Connection_data (const Connection_T conn)
{
  assert (conn);
  return conn->data;
}

void
Connection_setdata (Connection_T conn, void *data)
{
  assert (conn);
  conn->data = data;
}

time_t
Connection_lastactivity (const Connection_T conn)
{
  assert (conn);
  return conn->last_activity;
}

int
Connection_isactive (const Connection_T conn)
{
  assert (conn);
  return conn->active;
}

#undef T
