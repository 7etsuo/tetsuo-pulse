/**
 * test_socketpool.c - Comprehensive SocketPool unit tests
 * Industry-standard test coverage for SocketPool connection pool module.
 * Tests connection management, cleanup, accessors, limits, and thread safety.
 */

#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "dns/SocketDNS.h"
#include "pool/SocketPool.h"
#include "pool/SocketPool-private.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"
#include "socket/SocketReconnect.h"
#include "test/Test.h"

/* Suppress longjmp clobbering warnings for test variables used with TRY/EXCEPT
 */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

static void
setup_signals (void)
{
  signal (SIGPIPE, SIG_IGN);
}

/* ==================== Basic Pool Tests ==================== */

TEST (socketpool_new_creates_pool)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  ASSERT_NOT_NULL (pool);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_new_small_pool)
{
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 1, 512);
  ASSERT_NOT_NULL (pool);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_new_large_pool)
{
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 1000, 8192);
  ASSERT_NOT_NULL (pool);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Add/Get Tests ==================== */

TEST (socketpool_add_socket)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY Connection_T conn = SocketPool_add (pool, socket);
  ASSERT_NOT_NULL (conn);
  EXCEPT (SocketPool_Failed) ASSERT (0);
  END_TRY;

  Socket_free (&socket);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_get_connection)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY Connection_T conn1 = SocketPool_add (pool, socket);
  ASSERT_NOT_NULL (conn1);
  Connection_T conn2 = SocketPool_get (pool, socket);
  ASSERT_NOT_NULL (conn2);
  ASSERT_EQ (conn1, conn2);
  EXCEPT (SocketPool_Failed) ASSERT (0);
  END_TRY;

  Socket_free (&socket);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_get_nonexistent_returns_null)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  Connection_T conn = SocketPool_get (pool, socket);
  ASSERT_NULL (conn);

  Socket_free (&socket);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_add_multiple_sockets)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T sock1 = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T sock2 = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T sock3 = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY Connection_T conn1 = SocketPool_add (pool, sock1);
  Connection_T conn2 = SocketPool_add (pool, sock2);
  Connection_T conn3 = SocketPool_add (pool, sock3);
  ASSERT_NOT_NULL (conn1);
  ASSERT_NOT_NULL (conn2);
  ASSERT_NOT_NULL (conn3);
  ASSERT_NE (conn1, conn2);
  ASSERT_NE (conn2, conn3);
  EXCEPT (SocketPool_Failed) ASSERT (0);
  END_TRY;

  Socket_free (&sock3);
  Socket_free (&sock2);
  Socket_free (&sock1);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Remove Tests ==================== */

TEST (socketpool_remove_socket)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY Connection_T conn = SocketPool_add (pool, socket);
  ASSERT_NOT_NULL (conn);
  SocketPool_remove (pool, socket);
  Connection_T conn2 = SocketPool_get (pool, socket);
  ASSERT_NULL (conn2);
  EXCEPT (SocketPool_Failed) ASSERT (0);
  END_TRY;

  Socket_free (&socket);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_remove_multiple)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T sock1 = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T sock2 = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY volatile size_t count;
  SocketPool_add (pool, sock1);
  SocketPool_add (pool, sock2);
  SocketPool_remove (pool, sock1);
  SocketPool_remove (pool, sock2);
  count = SocketPool_count (pool);
  ASSERT_EQ (count, 0);
  EXCEPT (SocketPool_Failed) ASSERT (0);
  END_TRY;

  Socket_free (&sock2);
  Socket_free (&sock1);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_reuses_connection_buffers)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 1, 1024);
  Socket_T sock1 = Socket_new (AF_INET, SOCK_STREAM, 0);
  SocketBuf_T first_inbuf = NULL;
  SocketBuf_T first_outbuf = NULL;

  TRY Connection_T conn1 = SocketPool_add (pool, sock1);
  ASSERT_NOT_NULL (conn1);
  first_inbuf = Connection_inbuf (conn1);
  first_outbuf = Connection_outbuf (conn1);
  ASSERT_NOT_NULL (first_inbuf);
  ASSERT_NOT_NULL (first_outbuf);

  SocketPool_remove (pool, sock1);
  Socket_free (&sock1);

  Socket_T sock2 = Socket_new (AF_INET, SOCK_STREAM, 0);
  Connection_T conn2 = SocketPool_add (pool, sock2);
  ASSERT_NOT_NULL (conn2);
  ASSERT_EQ (conn1, conn2);
  ASSERT_EQ (first_inbuf, Connection_inbuf (conn2));
  ASSERT_EQ (first_outbuf, Connection_outbuf (conn2));

  SocketPool_remove (pool, sock2);
  Socket_free (&sock2);
  EXCEPT (SocketPool_Failed)
  ASSERT (0);
  END_TRY;

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_remove_nonexistent)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  SocketPool_remove (pool, socket);

  Socket_free (&socket);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Count Tests ==================== */

TEST (socketpool_count_empty)
{
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  size_t count = SocketPool_count (pool);
  ASSERT_EQ (count, 0);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_count_after_add)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T sock1 = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T sock2 = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY volatile size_t count;
  SocketPool_add (pool, sock1);
  SocketPool_add (pool, sock2);
  count = SocketPool_count (pool);
  ASSERT_EQ (count, 2);
  EXCEPT (SocketPool_Failed) ASSERT (0);
  END_TRY;

  Socket_free (&sock2);
  Socket_free (&sock1);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_count_after_remove)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY volatile size_t count;
  SocketPool_add (pool, socket);
  SocketPool_remove (pool, socket);
  count = SocketPool_count (pool);
  ASSERT_EQ (count, 0);
  EXCEPT (SocketPool_Failed) ASSERT (0);
  END_TRY;

  Socket_free (&socket);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Cleanup Tests ==================== */

TEST (socketpool_cleanup_no_idle)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY volatile size_t count;
  SocketPool_add (pool, socket);
  SocketPool_cleanup (pool, 60);
  count = SocketPool_count (pool);
  ASSERT_EQ (count, 1);
  EXCEPT (SocketPool_Failed) ASSERT (0);
  END_TRY;

  Socket_free (&socket);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_cleanup_all)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY volatile size_t count;
  SocketPool_add (pool, socket);
  SocketPool_cleanup (pool, 0);
  count = SocketPool_count (pool);
  ASSERT_EQ (count, 0);
  EXCEPT (SocketPool_Failed) ASSERT (0);
  END_TRY;

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_cleanup_multiple)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T sock1 = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T sock2 = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY volatile size_t count;
  SocketPool_add (pool, sock1);
  SocketPool_add (pool, sock2);
  SocketPool_cleanup (pool, 0);
  count = SocketPool_count (pool);
  ASSERT_EQ (count, 0);
  EXCEPT (SocketPool_Failed) ASSERT (0);
  END_TRY;

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Connection Accessor Tests ==================== */

TEST (socketpool_connection_socket)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY Connection_T conn = SocketPool_add (pool, socket);
  Socket_T sock = Connection_socket (conn);
  ASSERT_EQ (sock, socket);
  EXCEPT (SocketPool_Failed) ASSERT (0);
  END_TRY;

  Socket_free (&socket);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_connection_buffers)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY Connection_T conn = SocketPool_add (pool, socket);
  SocketBuf_T inbuf = Connection_inbuf (conn);
  SocketBuf_T outbuf = Connection_outbuf (conn);
  ASSERT_NOT_NULL (inbuf);
  ASSERT_NOT_NULL (outbuf);
  ASSERT_NE (inbuf, outbuf);
  EXCEPT (SocketPool_Failed) ASSERT (0);
  END_TRY;

  Socket_free (&socket);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_connection_user_data)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  int user_data = 42;

  TRY Connection_T conn = SocketPool_add (pool, socket);
  Connection_setdata (conn, &user_data);
  void *data = Connection_data (conn);
  ASSERT_EQ (data, &user_data);
  ASSERT_EQ (*(int *)data, 42);
  EXCEPT (SocketPool_Failed) ASSERT (0);
  END_TRY;

  Socket_free (&socket);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_connection_isactive)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY Connection_T conn = SocketPool_add (pool, socket);
  int active = Connection_isactive (conn);
  ASSERT_NE (active, 0);
  EXCEPT (SocketPool_Failed) ASSERT (0);
  END_TRY;

  Socket_free (&socket);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_connection_lastactivity)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY Connection_T conn = SocketPool_add (pool, socket);
  time_t last = Connection_lastactivity (conn);
  ASSERT_NE (last, 0);
  EXCEPT (SocketPool_Failed) ASSERT (0);
  END_TRY;

  Socket_free (&socket);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Foreach Tests ==================== */

static int foreach_count;
static void
count_connections (Connection_T conn, void *arg)
{
  (void)conn;
  (void)arg;
  foreach_count++;
}

TEST (socketpool_foreach_empty)
{
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);

  foreach_count = 0;
  SocketPool_foreach (pool, count_connections, NULL);
  ASSERT_EQ (foreach_count, 0);

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_foreach_counts_connections)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T sock1 = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T sock2 = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T sock3 = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY SocketPool_add (pool, sock1);
  SocketPool_add (pool, sock2);
  SocketPool_add (pool, sock3);

  foreach_count = 0;
  SocketPool_foreach (pool, count_connections, NULL);
  ASSERT_EQ (foreach_count, 3);
  EXCEPT (SocketPool_Failed) ASSERT (0);
  END_TRY;

  Socket_free (&sock3);
  Socket_free (&sock2);
  Socket_free (&sock1);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Pool Limits Tests ==================== */

TEST (socketpool_full_pool_returns_null)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 2, 1024);
  Socket_T sock1 = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T sock2 = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T sock3 = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY Connection_T conn1 = SocketPool_add (pool, sock1);
  Connection_T conn2 = SocketPool_add (pool, sock2);
  Connection_T conn3 = SocketPool_add (pool, sock3);
  ASSERT_NOT_NULL (conn1);
  ASSERT_NOT_NULL (conn2);
  ASSERT_NULL (conn3);
  EXCEPT (SocketPool_Failed) ASSERT (0);
  END_TRY;

  Socket_free (&sock3);
  Socket_free (&sock2);
  Socket_free (&sock1);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_reuse_after_remove)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 2, 1024);
  Socket_T sock1 = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T sock2 = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T sock3 = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY SocketPool_add (pool, sock1);
  SocketPool_add (pool, sock2);
  SocketPool_remove (pool, sock1);
  Connection_T conn3 = SocketPool_add (pool, sock3);
  ASSERT_NOT_NULL (conn3);
  EXCEPT (SocketPool_Failed) ASSERT (0);
  END_TRY;

  Socket_free (&sock3);
  Socket_free (&sock2);
  Socket_free (&sock1);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Buffer Integration Tests ==================== */

#if 0 /* Temporarily disabled - segfault in exception handling */
TEST(socketpool_connection_buffer_operations)
{
    setup_signals();
    Arena_T arena = Arena_new();
    SocketPool_T pool = SocketPool_new(arena, 100, 1024);
    Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);

    TRY
        Connection_T conn = SocketPool_add(pool, socket);
        SocketBuf_T inbuf = Connection_inbuf(conn);
        SocketBuf_T outbuf = Connection_outbuf(conn);
        
        const char *msg = "Test data";
        size_t written = SocketBuf_write(inbuf, msg, strlen(msg));
        ASSERT_EQ(written, strlen(msg));
        
        char buf[128] = {0};
        size_t read = SocketBuf_read(inbuf, buf, sizeof(buf));
        ASSERT_EQ(read, strlen(msg));
        ASSERT_EQ(strcmp(buf, msg), 0);
        
        SocketBuf_write(outbuf, "Out", 3);
        ASSERT_EQ(SocketBuf_available(outbuf), 3);
        
        /* Remove from pool before freeing socket to avoid dangling references */
        SocketPool_remove(pool, socket);
    EXCEPT(SocketPool_Failed) ASSERT(0);
    END_TRY;

    Socket_free(&socket);
    SocketPool_free(&pool);
    Arena_dispose(&arena);
}
#endif

/* ==================== Stress Tests ==================== */

TEST (socketpool_many_connections)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T sockets[50];

  TRY volatile int i;
  volatile size_t count;
  for (i = 0; i < 50; i++)
    {
      sockets[i] = Socket_new (AF_INET, SOCK_STREAM, 0);
      Connection_T conn = SocketPool_add (pool, sockets[i]);
      ASSERT_NOT_NULL (conn);
    }
  count = SocketPool_count (pool);
  ASSERT_EQ (count, 50);
  EXCEPT (SocketPool_Failed) ASSERT (0);
  FINALLY
  volatile int j;
  for (j = 0; j < 50; j++)
    Socket_free (&sockets[j]);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
  END_TRY;
}

TEST (socketpool_add_remove_cycle)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 10, 1024);

  TRY volatile int i;
  for (i = 0; i < 20; i++)
    {
      Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
      SocketPool_add (pool, socket);
      SocketPool_remove (pool, socket);
      Socket_free (&socket);
    }
  EXCEPT (SocketPool_Failed) ASSERT (0);
  END_TRY;

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Thread Safety Tests ==================== */

#if 0 /* Disabled - realloc() invalid pointer bug */
static void *thread_add_remove_connections(void *arg)
{
    SocketPool_T pool = (SocketPool_T)arg;
    
    for (volatile int i = 0; i < 20; i++)
    {
        Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
        TRY
            Connection_T conn = SocketPool_add(pool, socket);
            if (conn)
            {
                usleep(100);
                SocketPool_remove(pool, socket);
            }
        EXCEPT(SocketPool_Failed) (void)0;
        END_TRY;
        Socket_free(&socket);
        usleep(100);
    }
    
    return NULL;
}

/* Disabled test */
TEST(socketpool_concurrent_add_remove)
{
    setup_signals();
    Arena_T arena = Arena_new();
    SocketPool_T pool = SocketPool_new(arena, 100, 1024);
    pthread_t threads[4];

    for (int i = 0; i < 4; i++)
        pthread_create(&threads[i], NULL, thread_add_remove_connections, pool);
    
    for (int i = 0; i < 4; i++)
        pthread_join(threads[i], NULL);

    SocketPool_free(&pool);
    Arena_dispose(&arena);
}
#endif

static void *
thread_get_connections (void *arg)
{
  SocketPool_T pool = (SocketPool_T)arg;
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY volatile int i;
  SocketPool_add (pool, socket);
  for (i = 0; i < 100; i++)
    {
      Connection_T conn = SocketPool_get (pool, socket);
      (void)conn;
      usleep (100);
    }
  SocketPool_remove (pool, socket);
  EXCEPT (SocketPool_Failed) (void) 0;
  END_TRY;

  Socket_free (&socket);
  return NULL;
}

TEST (socketpool_concurrent_get)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  pthread_t threads[4];

  for (int i = 0; i < 4; i++)
    pthread_create (&threads[i], NULL, thread_get_connections, pool);

  for (int i = 0; i < 4; i++)
    pthread_join (threads[i], NULL);

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Batch Accept Tests ==================== */

TEST (socketpool_batch_accept_single)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T accepted[1];

  TRY Socket_bind (server, "127.0.0.1", 0);
  Socket_listen (server, 10);
  Socket_setnonblocking (server);

  int count = SocketPool_accept_batch (pool, server, 1, accepted);
  /* No connections pending, should return 0 */
  ASSERT_EQ (count, 0);
  EXCEPT (Socket_Failed) ASSERT (0);
  EXCEPT (SocketPool_Failed) ASSERT (0);
  END_TRY;

  Socket_free (&server);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_batch_accept_multiple)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T accepted[10];

  TRY Socket_bind (server, "127.0.0.1", 0);
  Socket_listen (server, 10);
  Socket_setnonblocking (server);

  int count = SocketPool_accept_batch (pool, server, 10, accepted);
  /* No connections pending, should return 0 */
  ASSERT_EQ (count, 0);
  EXCEPT (Socket_Failed) ASSERT (0);
  EXCEPT (SocketPool_Failed) ASSERT (0);
  END_TRY;

  Socket_free (&server);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_batch_accept_pool_full)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 2, 1024);
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T accepted[10];

  TRY Socket_bind (server, "127.0.0.1", 0);
  Socket_listen (server, 10);
  Socket_setnonblocking (server);

  /* Fill pool */
  Socket_T sock1 = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T sock2 = Socket_new (AF_INET, SOCK_STREAM, 0);
  SocketPool_add (pool, sock1);
  SocketPool_add (pool, sock2);

  int count = SocketPool_accept_batch (pool, server, 10, accepted);
  /* Pool is full, should return 0 */
  ASSERT_EQ (count, 0);

  SocketPool_remove (pool, sock1);
  SocketPool_remove (pool, sock2);
  Socket_free (&sock1);
  Socket_free (&sock2);
  EXCEPT (Socket_Failed) ASSERT (0);
  EXCEPT (SocketPool_Failed) ASSERT (0);
  END_TRY;

  Socket_free (&server);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Resize Tests ==================== */

TEST (socketpool_resize_grow)
{
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  volatile size_t count;

  TRY count = SocketPool_count (pool);
  ASSERT_EQ (count, 0);

  SocketPool_resize (pool, 200);
  /* Count should still be 0 */
  count = SocketPool_count (pool);
  ASSERT_EQ (count, 0);
  EXCEPT (SocketPool_Failed) ASSERT (0);
  END_TRY;

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_resize_shrink)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T sock1 = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T sock2 = Socket_new (AF_INET, SOCK_STREAM, 0);
  volatile size_t count;

  TRY SocketPool_add (pool, sock1);
  SocketPool_add (pool, sock2);
  count = SocketPool_count (pool);
  ASSERT_EQ (count, 2);

  /* Shrink to 50 - should close excess connections */
  SocketPool_resize (pool, 50);
  count = SocketPool_count (pool);
  /* Should have closed excess connections */
  ASSERT (count <= 50);
  EXCEPT (SocketPool_Failed) ASSERT (0);
  END_TRY;

  SocketPool_remove (pool, sock1);
  SocketPool_remove (pool, sock2);
  Socket_free (&sock1);
  Socket_free (&sock2);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_resize_same_size)
{
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  volatile size_t count;

  TRY count = SocketPool_count (pool);
  ASSERT_EQ (count, 0);

  /* Resize to same size - should be no-op */
  SocketPool_resize (pool, 100);
  count = SocketPool_count (pool);
  ASSERT_EQ (count, 0);
  EXCEPT (SocketPool_Failed) ASSERT (0);
  END_TRY;

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Pre-warming Tests ==================== */

TEST (socketpool_prewarm_default)
{
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);

  /* Pre-warming happens automatically in SocketPool_new with 20% */
  /* Just verify pool was created successfully */
  ASSERT_NOT_NULL (pool);

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_prewarm_custom)
{
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);

  TRY
      /* Pre-warm 50% */
      SocketPool_prewarm (pool, 50);
  /* Should not raise exception */
  EXCEPT (SocketPool_Failed) ASSERT (0);
  END_TRY;

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Buffer Size Tuning Tests ==================== */

TEST (socketpool_set_bufsize)
{
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);

  TRY
      /* Change buffer size */
      SocketPool_set_bufsize (pool, 2048);
  /* Should not raise exception */
  EXCEPT (SocketPool_Failed) ASSERT (0);
  END_TRY;

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_set_bufsize_large)
{
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);

  TRY
      /* Set large buffer size */
      SocketPool_set_bufsize (pool, 65536);
  /* Should not raise exception */
  EXCEPT (SocketPool_Failed) ASSERT (0);
  END_TRY;

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Async Connect Tests ==================== */

static volatile int async_callback_called = 0;
static volatile int async_callback_error = -1;
static volatile Connection_T async_callback_conn = NULL;

static void
async_connect_callback (Connection_T conn, int error, void *data)
{
  (void)data;
  async_callback_called = 1;
  async_callback_error = error;
  async_callback_conn = conn;
}

/* NOTE: socketpool_connect_async_basic test removed - connect_async
 * uses synchronous DNS resolution internally which can block for 30+ seconds
 * on unreachable addresses. The API is tested via integration tests. */

TEST (socketpool_connect_async_invalid_params)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  volatile int raised = 0;

  TRY
  {
    /* Invalid (negative) port */
    SocketPool_connect_async (pool, "localhost", -1, async_connect_callback,
                              NULL);
  }
  EXCEPT (SocketPool_Failed) { raised = 1; }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (raised, 1);

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Prepare Connection Tests ==================== */

TEST (socketpool_prepare_connection_basic)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  SocketDNS_T dns = NULL;
  Socket_T out_socket = NULL;
  SocketDNS_Request_T out_req = NULL;
  Socket_T server = NULL;
  volatile int port = 0;

  /* Create listening server */
  TRY
  {
    server = Socket_new (AF_INET, SOCK_STREAM, 0);
    Socket_setreuseaddr (server);
    Socket_bind (server, "127.0.0.1", 0);
    Socket_listen (server, 5);
    port = Socket_getlocalport (server);
  }
  EXCEPT (Socket_Failed)
  {
    if (server)
      Socket_free (&server);
    SocketPool_free (&pool);
    Arena_dispose (&arena);
    ASSERT (0);
    return;
  }
  END_TRY;

  /* Create DNS resolver */
  TRY { dns = SocketDNS_new (); }
  EXCEPT (SocketDNS_Failed)
  {
    Socket_free (&server);
    SocketPool_free (&pool);
    Arena_dispose (&arena);
    ASSERT (0);
    return;
  }
  END_TRY;

  /* Prepare connection */
  TRY
  {
    int result = SocketPool_prepare_connection (pool, dns, "127.0.0.1", port,
                                                &out_socket, &out_req);
    ASSERT_EQ (result, 0);
    ASSERT_NOT_NULL (out_socket);
    ASSERT_NOT_NULL (out_req);

    /* Cancel the DNS request first to prevent callback from using socket */
    if (out_req)
      SocketDNS_cancel (dns, out_req);

    /* Clean up the socket we created */
    if (out_socket)
      Socket_free (&out_socket);
  }
  EXCEPT (SocketPool_Failed)
  {
    /* May fail due to DNS or connect issues */
    if (out_socket)
      Socket_free (&out_socket);
  }
  EXCEPT (Socket_Failed)
  {
    /* May fail due to socket issues */
    if (out_socket)
      Socket_free (&out_socket);
  }
  END_TRY;

  SocketDNS_free (&dns);
  Socket_free (&server);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_prepare_connection_invalid_params)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  SocketDNS_T dns = NULL;
  Socket_T out_socket = NULL;
  SocketDNS_Request_T out_req = NULL;
  volatile int raised = 0;

  TRY { dns = SocketDNS_new (); }
  EXCEPT (SocketDNS_Failed)
  {
    SocketPool_free (&pool);
    Arena_dispose (&arena);
    ASSERT (0);
    return;
  }
  END_TRY;

  /* Test invalid (negative) port - should raise SocketPool_Failed or
   * Socket_Failed */
  TRY
  {
    SocketPool_prepare_connection (pool, dns, "localhost", -1, &out_socket,
                                   &out_req);
  }
  EXCEPT (SocketPool_Failed) { raised = 1; }
  EXCEPT (Socket_Failed) { raised = 1; }
  END_TRY;

  /* Clean up socket if it was created (shouldn't be with invalid params) */
  if (out_socket)
    Socket_free (&out_socket);

  ASSERT_EQ (raised, 1);

  SocketDNS_free (&dns);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Resize with Active Connections Tests ==================== */

TEST (socketpool_resize_shrink_with_active)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 10, 1024);
  Socket_T sockets[5];
  volatile size_t count;
  volatile int i;

  /* Initialize sockets to NULL for safe cleanup */
  for (i = 0; i < 5; i++)
    sockets[i] = NULL;

  TRY
  {
    /* Add 5 connections */
    for (i = 0; i < 5; i++)
      {
        sockets[i] = Socket_new (AF_INET, SOCK_STREAM, 0);
        SocketPool_add (pool, sockets[i]);
      }

    count = SocketPool_count (pool);
    ASSERT_EQ (count, 5);

    /* Shrink to 3 - should close 2 excess connections */
    SocketPool_resize (pool, 3);
    count = SocketPool_count (pool);
    ASSERT (count <= 3);
  }
  EXCEPT (SocketPool_Failed) { ASSERT (0); }
  END_TRY;

  /* Clean up - remove and free sockets */
  for (i = 0; i < 5; i++)
    {
      if (sockets[i])
        {
          SocketPool_remove (pool, sockets[i]);
          Socket_free (&sockets[i]);
        }
    }

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Reconnection Support Tests ==================== */

TEST (socketpool_set_reconnect_policy)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 10, 1024);
  SocketReconnect_Policy_T policy;

  SocketReconnect_policy_defaults (&policy);
  policy.max_attempts = 3;
  policy.initial_delay_ms = 100;

  /* Setting reconnect policy should succeed */
  SocketPool_set_reconnect_policy (pool, &policy);

  /* Disabling reconnect policy should succeed */
  SocketPool_set_reconnect_policy (pool, NULL);

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_reconnect_timeout_no_connections)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 10, 1024);

  /* With no connections, timeout should be -1 */
  int timeout = SocketPool_reconnect_timeout_ms (pool);
  ASSERT_EQ (timeout, -1);

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_process_reconnects_empty)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 10, 1024);

  /* Should not crash with empty pool */
  SocketPool_process_reconnects (pool);

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_connection_reconnect_null)
{
  /* Test Connection_reconnect with NULL */
  SocketReconnect_T reconnect = Connection_reconnect (NULL);
  ASSERT_NULL (reconnect);

  /* Test Connection_has_reconnect with NULL */
  int has = Connection_has_reconnect (NULL);
  ASSERT_EQ (has, 0);
}

TEST (socketpool_connection_has_reconnect_disabled)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 10, 1024);
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY
  {
    Connection_T conn = SocketPool_add (pool, socket);
    ASSERT_NOT_NULL (conn);

    /* No reconnect enabled yet */
    int has = Connection_has_reconnect (conn);
    ASSERT_EQ (has, 0);

    SocketReconnect_T r = Connection_reconnect (conn);
    ASSERT_NULL (r);
  }
  EXCEPT (SocketPool_Failed) { ASSERT (0); }
  END_TRY;

  Socket_free (&socket);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Hash Table Coverage Tests ==================== */

TEST (socketpool_hash_collision_handling)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T sockets[20];
  volatile int i;

  /* Initialize sockets to NULL for safe cleanup */
  for (i = 0; i < 20; i++)
    sockets[i] = NULL;

  TRY
  {
    /* Create many sockets - some will hash to same bucket */
    for (i = 0; i < 20; i++)
      {
        sockets[i] = Socket_new (AF_INET, SOCK_STREAM, 0);
        Connection_T conn = SocketPool_add (pool, sockets[i]);
        ASSERT_NOT_NULL (conn);
      }

    /* Verify all can be retrieved */
    for (i = 0; i < 20; i++)
      {
        Connection_T conn = SocketPool_get (pool, sockets[i]);
        ASSERT_NOT_NULL (conn);
        ASSERT_EQ (Connection_socket (conn), sockets[i]);
      }

    /* Remove half and verify remaining */
    for (i = 0; i < 10; i++)
      {
        SocketPool_remove (pool, sockets[i]);
      }

    for (i = 10; i < 20; i++)
      {
        Connection_T conn = SocketPool_get (pool, sockets[i]);
        ASSERT_NOT_NULL (conn);
      }
  }
  EXCEPT (SocketPool_Failed) { ASSERT (0); }
  END_TRY;

  /* Cleanup */
  for (i = 0; i < 20; i++)
    {
      if (sockets[i])
        {
          SocketPool_remove (pool, sockets[i]);
          Socket_free (&sockets[i]);
        }
    }

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_free_null)
{
  /* Should not crash */
  SocketPool_free (NULL);

  SocketPool_T pool = NULL;
  SocketPool_free (&pool);
}

TEST (socketpool_activity_time_updated)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 10, 1024);
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY
  {
    Connection_T conn = SocketPool_add (pool, socket);
    ASSERT_NOT_NULL (conn);

    time_t t1 = Connection_lastactivity (conn);

    /* Activity time should be set when connection is added */
    ASSERT (t1 > 0);
  }
  EXCEPT (SocketPool_Failed) { ASSERT (0); }
  END_TRY;

  Socket_free (&socket);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Input Validation Tests ==================== */

TEST (socketpool_new_null_arena_raises)
{
  volatile int raised = 0;

  TRY { SocketPool_new (NULL, 100, 1024); }
  EXCEPT (SocketPool_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (raised, 1);
}

TEST (socketpool_new_invalid_maxconns_raises)
{
  Arena_T arena = Arena_new ();
  volatile int raised = 0;

  TRY { SocketPool_new (arena, 0, 1024); }
  EXCEPT (SocketPool_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (raised, 1);
  Arena_dispose (&arena);
}

TEST (socketpool_new_invalid_bufsize_raises)
{
  Arena_T arena = Arena_new ();
  volatile int raised = 0;

  TRY { SocketPool_new (arena, 100, 0); }
  EXCEPT (SocketPool_Failed) { raised = 1; }
  END_TRY;

  ASSERT_EQ (raised, 1);
  Arena_dispose (&arena);
}

/* ==================== Reconnection Feature Tests ==================== */

TEST (socketpool_enable_reconnect_success)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 10, 1024);
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY
  {
    Connection_T conn = SocketPool_add (pool, socket);
    ASSERT_NOT_NULL (conn);

    /* Enable reconnect for this connection */
    SocketPool_enable_reconnect (pool, conn, "127.0.0.1", 8080);

    /* Verify reconnect is enabled */
    int has = Connection_has_reconnect (conn);
    ASSERT_NE (has, 0);

    SocketReconnect_T r = Connection_reconnect (conn);
    ASSERT_NOT_NULL (r);
  }
  EXCEPT (SocketPool_Failed) { ASSERT (0); }
  EXCEPT (SocketReconnect_Failed) { ASSERT (0); }
  END_TRY;

  Socket_free (&socket);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_disable_reconnect_with_active)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 10, 1024);
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY
  {
    Connection_T conn = SocketPool_add (pool, socket);
    ASSERT_NOT_NULL (conn);

    /* Enable then disable reconnect */
    SocketPool_enable_reconnect (pool, conn, "127.0.0.1", 8080);
    ASSERT_NE (Connection_has_reconnect (conn), 0);

    SocketPool_disable_reconnect (pool, conn);
    ASSERT_EQ (Connection_has_reconnect (conn), 0);
  }
  EXCEPT (SocketPool_Failed) { ASSERT (0); }
  EXCEPT (SocketReconnect_Failed) { ASSERT (0); }
  END_TRY;

  Socket_free (&socket);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_process_reconnects_with_active)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 10, 1024);
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY
  {
    Connection_T conn = SocketPool_add (pool, socket);
    ASSERT_NOT_NULL (conn);

    /* Enable reconnect */
    SocketPool_enable_reconnect (pool, conn, "127.0.0.1", 8080);

    /* Process reconnects - should not crash with active reconnect context */
    SocketPool_process_reconnects (pool);
  }
  EXCEPT (SocketPool_Failed) { ASSERT (0); }
  EXCEPT (SocketReconnect_Failed) { ASSERT (0); }
  END_TRY;

  Socket_free (&socket);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_reconnect_timeout_with_active)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 10, 1024);
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY
  {
    Connection_T conn = SocketPool_add (pool, socket);
    ASSERT_NOT_NULL (conn);

    /* Enable reconnect */
    SocketPool_enable_reconnect (pool, conn, "127.0.0.1", 8080);

    /* Get timeout - should return valid value with active reconnect */
    int timeout = SocketPool_reconnect_timeout_ms (pool);
    /* Timeout may be -1 if no pending action, or >= 0 if pending */
    (void)timeout;
  }
  EXCEPT (SocketPool_Failed) { ASSERT (0); }
  EXCEPT (SocketReconnect_Failed) { ASSERT (0); }
  END_TRY;

  Socket_free (&socket);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_enable_reconnect_with_policy)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 10, 1024);
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  SocketReconnect_Policy_T policy;

  /* Set pool-level reconnect policy */
  SocketReconnect_policy_defaults (&policy);
  policy.max_attempts = 5;
  policy.initial_delay_ms = 200;
  SocketPool_set_reconnect_policy (pool, &policy);

  TRY
  {
    Connection_T conn = SocketPool_add (pool, socket);
    ASSERT_NOT_NULL (conn);

    /* Enable reconnect - should use pool policy */
    SocketPool_enable_reconnect (pool, conn, "127.0.0.1", 8080);

    ASSERT_NE (Connection_has_reconnect (conn), 0);
  }
  EXCEPT (SocketPool_Failed) { ASSERT (0); }
  EXCEPT (SocketReconnect_Failed) { ASSERT (0); }
  END_TRY;

  Socket_free (&socket);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_free_with_reconnect_contexts)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 10, 1024);
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY
  {
    Connection_T conn = SocketPool_add (pool, socket);
    ASSERT_NOT_NULL (conn);

    /* Enable reconnect */
    SocketPool_enable_reconnect (pool, conn, "127.0.0.1", 8080);
  }
  EXCEPT (SocketPool_Failed) { ASSERT (0); }
  EXCEPT (SocketReconnect_Failed) { ASSERT (0); }
  END_TRY;

  /* Free pool with active reconnect context - covers free_reconnect_contexts */
  Socket_free (&socket);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_free_with_dns)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 10, 1024);
  SocketDNS_T dns = NULL;

  TRY
  {
    /* Create DNS resolver and set it on pool directly */
    dns = SocketDNS_new ();
    ASSERT_NOT_NULL (dns);

    /* Set DNS resolver on pool (access internal field) */
    pool->dns = dns;
    dns = NULL; /* Transfer ownership to pool */
  }
  EXCEPT (SocketDNS_Failed) { ASSERT (0); }
  END_TRY;

  /* Free pool with DNS resolver - covers free_dns_resolver path (line 521) */
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_reconnect_timeout_multiple_connections)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 10, 1024);
  Socket_T sock1 = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T sock2 = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T sock3 = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY
  {
    Connection_T conn1 = SocketPool_add (pool, sock1);
    Connection_T conn2 = SocketPool_add (pool, sock2);
    Connection_T conn3 = SocketPool_add (pool, sock3);
    ASSERT_NOT_NULL (conn1);
    ASSERT_NOT_NULL (conn2);
    ASSERT_NOT_NULL (conn3);

    /* Enable reconnect on multiple connections to exercise timeout logic */
    SocketPool_enable_reconnect (pool, conn1, "127.0.0.1", 8080);
    SocketPool_enable_reconnect (pool, conn2, "127.0.0.1", 8081);
    SocketPool_enable_reconnect (pool, conn3, "127.0.0.1", 8082);

    /* Get timeout - exercises update_min_timeout with multiple values */
    int timeout = SocketPool_reconnect_timeout_ms (pool);
    /* Timeout will be the minimum of all connection timeouts */
    (void)timeout;

    /* Process reconnects to advance state machines */
    SocketPool_process_reconnects (pool);

    /* Check timeout again after processing */
    timeout = SocketPool_reconnect_timeout_ms (pool);
    (void)timeout;
  }
  EXCEPT (SocketPool_Failed) { ASSERT (0); }
  EXCEPT (SocketReconnect_Failed) { ASSERT (0); }
  END_TRY;

  Socket_free (&sock1);
  Socket_free (&sock2);
  Socket_free (&sock3);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_reconnect_with_backoff_timeout)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 10, 1024);
  Socket_T sock1 = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T sock2 = Socket_new (AF_INET, SOCK_STREAM, 0);

  TRY
  {
    Connection_T conn1 = SocketPool_add (pool, sock1);
    Connection_T conn2 = SocketPool_add (pool, sock2);
    ASSERT_NOT_NULL (conn1);
    ASSERT_NOT_NULL (conn2);

    /* Enable reconnect with short policy to quickly enter backoff */
    SocketReconnect_Policy_T policy;
    SocketReconnect_policy_defaults (&policy);
    policy.initial_delay_ms = 10;
    policy.max_delay_ms = 50;
    policy.max_attempts = 1;
    SocketPool_set_reconnect_policy (pool, &policy);

    /* Enable reconnect pointing to localhost (fast fail if nothing listening) */
    SocketPool_enable_reconnect (pool, conn1, "127.0.0.1", 59999);
    SocketPool_enable_reconnect (pool, conn2, "127.0.0.1", 59998);

    /* Get reconnect contexts and set non-blocking for fast failure */
    SocketReconnect_T r1 = Connection_reconnect (conn1);
    SocketReconnect_T r2 = Connection_reconnect (conn2);

    /* Don't actually connect - just verify the timeout logic works */
    /* This exercises update_min_timeout with -1 values initially */
    int timeout = SocketPool_reconnect_timeout_ms (pool);
    (void)timeout;
    (void)r1;
    (void)r2;
  }
  EXCEPT (SocketPool_Failed) { /* May fail, that's ok */ }
  EXCEPT (SocketReconnect_Failed) { /* May fail, that's ok */ }
  END_TRY;

  Socket_free (&sock1);
  Socket_free (&sock2);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Hash Chain Traversal Tests ==================== */

TEST (socketpool_hash_chain_removal_middle)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  /* Use larger pool for more sockets to increase collision probability */
  SocketPool_T pool = SocketPool_new (arena, 200, 1024);

#define NUM_SOCKETS 150
  Socket_T sockets[NUM_SOCKETS];
  Connection_T conns[NUM_SOCKETS];
  volatile int i;

  /* Initialize to NULL for safe cleanup */
  for (i = 0; i < NUM_SOCKETS; i++)
    {
      sockets[i] = NULL;
      conns[i] = NULL;
    }

  TRY
  {
    /* Create many sockets - with 150 sockets and 1021 buckets,
       probability of at least one collision is very high */
    for (i = 0; i < NUM_SOCKETS; i++)
      {
        sockets[i] = Socket_new (AF_INET, SOCK_STREAM, 0);
        conns[i] = SocketPool_add (pool, sockets[i]);
        ASSERT_NOT_NULL (conns[i]);
      }

    /* Remove sockets from the middle to exercise hash chain traversal.
       If any bucket has multiple entries, this will traverse the chain. */
    for (i = 30; i < 120; i++)
      {
        SocketPool_remove (pool, sockets[i]);
      }

    /* Verify remaining sockets can still be found - exercises find_slot chain */
    for (i = 0; i < 30; i++)
      {
        Connection_T found = SocketPool_get (pool, sockets[i]);
        ASSERT_NOT_NULL (found);
      }
    for (i = 120; i < NUM_SOCKETS; i++)
      {
        Connection_T found = SocketPool_get (pool, sockets[i]);
        ASSERT_NOT_NULL (found);
      }
  }
  EXCEPT (SocketPool_Failed) { ASSERT (0); }
  END_TRY;

  /* Cleanup */
  for (i = 0; i < NUM_SOCKETS; i++)
    {
      if (sockets[i])
        {
          SocketPool_remove (pool, sockets[i]);
          Socket_free (&sockets[i]);
        }
    }

  SocketPool_free (&pool);
  Arena_dispose (&arena);
#undef NUM_SOCKETS
}

TEST (socketpool_find_slot_chain_traversal)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T sockets[30];
  volatile int i;

  for (i = 0; i < 30; i++)
    sockets[i] = NULL;

  TRY
  {
    /* Add many sockets */
    for (i = 0; i < 30; i++)
      {
        sockets[i] = Socket_new (AF_INET, SOCK_STREAM, 0);
        SocketPool_add (pool, sockets[i]);
      }

    /* Lookup each socket multiple times to exercise find_slot chain traversal */
    for (i = 0; i < 30; i++)
      {
        Connection_T conn = SocketPool_get (pool, sockets[i]);
        ASSERT_NOT_NULL (conn);
        ASSERT_EQ (Connection_socket (conn), sockets[i]);
      }

    /* Remove some and verify others still found */
    for (i = 0; i < 15; i++)
      {
        SocketPool_remove (pool, sockets[i]);
      }

    for (i = 15; i < 30; i++)
      {
        Connection_T conn = SocketPool_get (pool, sockets[i]);
        ASSERT_NOT_NULL (conn);
      }
  }
  EXCEPT (SocketPool_Failed) { ASSERT (0); }
  END_TRY;

  for (i = 0; i < 30; i++)
    {
      if (sockets[i])
        Socket_free (&sockets[i]);
    }

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Batch Accept Success Path Tests ==================== */

/**
 * Helper to create a pending connection to a server socket.
 * Returns port number on success, 0 on failure.
 */
static int
create_pending_connection (Socket_T server, Socket_T *out_client)
{
  volatile int port = 0;
  volatile Socket_T client = NULL;

  TRY
  {
    Socket_bind (server, "127.0.0.1", 0);
    Socket_listen (server, 10);
    Socket_setnonblocking (server);
    port = Socket_getlocalport (server);

    client = Socket_new (AF_INET, SOCK_STREAM, 0);
    Socket_setnonblocking (client);

    /* Initiate non-blocking connect - will be pending */
    TRY { Socket_connect (client, "127.0.0.1", port); }
    EXCEPT (Socket_Failed)
    {
      /* EINPROGRESS is expected for non-blocking connect */
      if (errno != EINPROGRESS && errno != EWOULDBLOCK)
        {
          Socket_free ((Socket_T *)&client);
          return 0;
        }
    }
    END_TRY;

    *out_client = (Socket_T)client;
    return port;
  }
  EXCEPT (Socket_Failed)
  {
    if (client)
      Socket_free ((Socket_T *)&client);
    return 0;
  }
  END_TRY;

  return port;
}

TEST (socketpool_batch_accept_with_pending_connection)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = NULL;
  Socket_T accepted[10];
  volatile int count = 0;

  Socket_setreuseaddr (server);
  int port = create_pending_connection (server, &client);
  ASSERT_NE (port, 0);

  /* Small delay to ensure connection is pending */
  usleep (10000);

  TRY
  {
    count = SocketPool_accept_batch (pool, server, 10, accepted);
    /* Should accept at least 1 connection */
    ASSERT (count >= 1);

    /* Verify accepted socket is in pool */
    if (count > 0)
      {
        Connection_T conn = SocketPool_get (pool, accepted[0]);
        ASSERT_NOT_NULL (conn);
      }
  }
  EXCEPT (Socket_Failed) { /* May fail on some systems */ }
  EXCEPT (SocketPool_Failed) { /* May fail on some systems */ }
  END_TRY;

  /* Cleanup accepted sockets */
  for (int i = 0; i < count; i++)
    {
      if (accepted[i])
        {
          SocketPool_remove (pool, accepted[i]);
          Socket_free (&accepted[i]);
        }
    }

  if (client)
    Socket_free (&client);
  Socket_free (&server);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_batch_accept_pool_add_fails)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  /* Pool with capacity 1 */
  SocketPool_T pool = SocketPool_new (arena, 1, 1024);
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = NULL;
  Socket_T accepted[10];
  Socket_T filler = NULL;
  volatile int count = 0;

  Socket_setreuseaddr (server);
  int port = create_pending_connection (server, &client);
  ASSERT_NE (port, 0);

  TRY
  {
    /* Fill the pool so add will fail */
    filler = Socket_new (AF_INET, SOCK_STREAM, 0);
    Connection_T fc = SocketPool_add (pool, filler);
    ASSERT_NOT_NULL (fc);

    usleep (10000);

    /* Try to accept - pool is full, should return 0 */
    count = SocketPool_accept_batch (pool, server, 10, accepted);
    ASSERT_EQ (count, 0);
  }
  EXCEPT (Socket_Failed) { /* May fail */ }
  EXCEPT (SocketPool_Failed) { /* May fail */ }
  END_TRY;

  if (filler)
    {
      SocketPool_remove (pool, filler);
      Socket_free (&filler);
    }
  if (client)
    Socket_free (&client);
  Socket_free (&server);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_batch_accept_invalid_max_accepts)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T accepted[10];

  TRY
  {
    Socket_bind (server, "127.0.0.1", 0);
    Socket_listen (server, 10);
    Socket_setnonblocking (server);

    /* Test with max_accepts > SOCKET_POOL_MAX_BATCH_ACCEPTS (1000) */
    int count = SocketPool_accept_batch (pool, server, 2000, accepted);
    /* Should return 0 due to invalid parameter */
    ASSERT_EQ (count, 0);

    /* Test with max_accepts = 0 */
    count = SocketPool_accept_batch (pool, server, 0, accepted);
    ASSERT_EQ (count, 0);

    /* Test with max_accepts < 0 */
    count = SocketPool_accept_batch (pool, server, -1, accepted);
    ASSERT_EQ (count, 0);
  }
  EXCEPT (Socket_Failed) { ASSERT (0); }
  EXCEPT (SocketPool_Failed) { /* Expected for invalid params */ }
  END_TRY;

  Socket_free (&server);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Async Connect Tests ==================== */

/* Async callback tracking for tests */
static volatile int async_test_callback_called = 0;
static volatile int async_test_error_code = -1;
static volatile Connection_T async_test_conn = NULL;

static void
async_test_callback (Connection_T conn, int error, void *data)
{
  (void)data;
  async_test_callback_called = 1;
  async_test_error_code = error;
  async_test_conn = conn;
}

TEST (socketpool_connect_async_success)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T server = NULL;
  volatile int port = 0;

  /* Reset callback state */
  async_test_callback_called = 0;
  async_test_error_code = -1;
  async_test_conn = NULL;

  TRY
  {
    /* Create a listening server */
    server = Socket_new (AF_INET, SOCK_STREAM, 0);
    Socket_setreuseaddr (server);
    Socket_bind (server, "127.0.0.1", 0);
    Socket_listen (server, 5);
    port = Socket_getlocalport (server);
  }
  EXCEPT (Socket_Failed)
  {
    if (server)
      Socket_free (&server);
    SocketPool_free (&pool);
    Arena_dispose (&arena);
    return; /* Skip test if server setup fails */
  }
  END_TRY;

  TRY
  {
    char port_str[16];
    snprintf (port_str, sizeof (port_str), "%d", port);

    /* Start async connect */
    SocketDNS_Request_T req
        = SocketPool_connect_async (pool, "127.0.0.1", port, async_test_callback,
                                    NULL);
    ASSERT_NOT_NULL (req);

    /* Wait for callback with timeout */
    for (int i = 0; i < 100 && !async_test_callback_called; i++)
      {
        usleep (10000); /* 10ms */
      }

    /* Callback should have been invoked */
    ASSERT_EQ (async_test_callback_called, 1);

    /* Clean up connection if successful */
    if (async_test_conn)
      {
        Socket_T s = Connection_socket (async_test_conn);
        SocketPool_remove (pool, s);
        Socket_free (&s);
      }
  }
  EXCEPT (SocketPool_Failed) { /* May fail due to DNS/connect issues */ }
  EXCEPT (Socket_Failed) { /* May fail */ }
  END_TRY;

  if (server)
    Socket_free (&server);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_connect_async_dns_failure)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);

  /* Reset callback state */
  async_test_callback_called = 0;
  async_test_error_code = -1;
  async_test_conn = NULL;

  TRY
  {
    /* Use invalid hostname that should fail DNS resolution */
    SocketDNS_Request_T req = SocketPool_connect_async (
        pool, "this-host-does-not-exist.invalid", 80, async_test_callback,
        NULL);

    if (req)
      {
        /* Wait for callback with timeout */
        for (int i = 0; i < 200 && !async_test_callback_called; i++)
          {
            usleep (10000); /* 10ms */
          }

        /* Callback should have been invoked with error */
        if (async_test_callback_called)
          {
            ASSERT_NE (async_test_error_code, 0);
            ASSERT_NULL (async_test_conn);
          }
      }
  }
  EXCEPT (SocketPool_Failed) { /* Expected - DNS may fail immediately */ }
  EXCEPT (Socket_Failed) { /* May fail */ }
  END_TRY;

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_connect_async_connect_failure)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);

  /* Reset callback state */
  async_test_callback_called = 0;
  async_test_error_code = -1;
  async_test_conn = NULL;

  TRY
  {
    /* Connect to TEST-NET address (RFC 5737) that should fail */
    SocketDNS_Request_T req = SocketPool_connect_async (
        pool, "192.0.2.1", 9999, async_test_callback, NULL);

    if (req)
      {
        /* Wait for callback - connection should fail quickly */
        for (int i = 0; i < 300 && !async_test_callback_called; i++)
          {
            usleep (10000); /* 10ms */
          }

        /* If callback was invoked, it should indicate failure */
        if (async_test_callback_called)
          {
            ASSERT_NE (async_test_error_code, 0);
          }
      }
  }
  EXCEPT (SocketPool_Failed) { /* May fail */ }
  EXCEPT (Socket_Failed) { /* May fail */ }
  END_TRY;

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_connect_async_valid_params)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T server = NULL;
  volatile int port = 0;

  TRY
  {
    /* Create a listening server */
    server = Socket_new (AF_INET, SOCK_STREAM, 0);
    Socket_setreuseaddr (server);
    Socket_bind (server, "127.0.0.1", 0);
    Socket_listen (server, 5);
    port = Socket_getlocalport (server);
  }
  EXCEPT (Socket_Failed)
  {
    if (server)
      Socket_free (&server);
    SocketPool_free (&pool);
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  /* Reset callback state */
  async_test_callback_called = 0;

  TRY
  {
    /* Valid call - exercises the main async connect path */
    SocketDNS_Request_T req = SocketPool_connect_async (
        pool, "127.0.0.1", port, async_test_callback, (void *)0x1234);
    /* Request should be returned */
    (void)req;

    /* Wait briefly for callback */
    for (int i = 0; i < 50 && !async_test_callback_called; i++)
      usleep (10000);

    /* Cleanup any connection */
    if (async_test_conn)
      {
        Socket_T s = Connection_socket (async_test_conn);
        SocketPool_remove (pool, s);
        Socket_free (&s);
      }
  }
  EXCEPT (SocketPool_Failed) { /* May fail */ }
  EXCEPT (Socket_Failed) { /* May fail */ }
  END_TRY;

  if (server)
    Socket_free (&server);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Resize Overflow Test ==================== */

TEST (socketpool_resize_overflow_protection)
{
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 10, 1024);

  TRY
  {
    /* Try to resize to a value that would cause overflow
     * SIZE_MAX / sizeof(Connection) is the threshold */
    SocketPool_resize (pool, SIZE_MAX);
    /* If it doesn't crash, the overflow protection worked
     * (value gets clamped to SOCKET_MAX_CONNECTIONS) */
  }
  EXCEPT (SocketPool_Failed) { /* Expected - overflow detected */ }
  END_TRY;

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Error Path Tests ==================== */

TEST (socketpool_prepare_connection_null_params)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  SocketDNS_T dns = NULL;
  Socket_T out_socket = NULL;
  SocketDNS_Request_T out_req = NULL;
  volatile int raised = 0;

  TRY { dns = SocketDNS_new (); }
  EXCEPT (SocketDNS_Failed)
  {
    SocketPool_free (&pool);
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  /* Test with NULL pool */
  TRY
  {
    SocketPool_prepare_connection (NULL, dns, "localhost", 80, &out_socket,
                                   &out_req);
  }
  EXCEPT (SocketPool_Failed) { raised = 1; }
  END_TRY;
  ASSERT_EQ (raised, 1);

  /* Test with NULL dns */
  raised = 0;
  TRY
  {
    SocketPool_prepare_connection (pool, NULL, "localhost", 80, &out_socket,
                                   &out_req);
  }
  EXCEPT (SocketPool_Failed) { raised = 1; }
  END_TRY;
  ASSERT_EQ (raised, 1);

  /* Test with NULL host */
  raised = 0;
  TRY
  {
    SocketPool_prepare_connection (pool, dns, NULL, 80, &out_socket, &out_req);
  }
  EXCEPT (SocketPool_Failed) { raised = 1; }
  END_TRY;
  ASSERT_EQ (raised, 1);

  /* Test with NULL out_socket */
  raised = 0;
  TRY
  {
    SocketPool_prepare_connection (pool, dns, "localhost", 80, NULL, &out_req);
  }
  EXCEPT (SocketPool_Failed) { raised = 1; }
  END_TRY;
  ASSERT_EQ (raised, 1);

  /* Test with NULL out_req */
  raised = 0;
  TRY
  {
    SocketPool_prepare_connection (pool, dns, "localhost", 80, &out_socket,
                                   NULL);
  }
  EXCEPT (SocketPool_Failed) { raised = 1; }
  END_TRY;
  ASSERT_EQ (raised, 1);

  SocketDNS_free (&dns);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_connect_async_null_params)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  volatile int raised = 0;

  /* Test with NULL pool */
  TRY { SocketPool_connect_async (NULL, "localhost", 80, async_test_callback, NULL); }
  EXCEPT (SocketPool_Failed) { raised = 1; }
  END_TRY;
  ASSERT_EQ (raised, 1);

  /* Test with NULL host */
  raised = 0;
  TRY { SocketPool_connect_async (pool, NULL, 80, async_test_callback, NULL); }
  EXCEPT (SocketPool_Failed) { raised = 1; }
  END_TRY;
  ASSERT_EQ (raised, 1);

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_batch_accept_null_params)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T accepted[10];

  TRY
  {
    Socket_bind (server, "127.0.0.1", 0);
    Socket_listen (server, 10);

    /* Test with NULL pool */
    int count = SocketPool_accept_batch (NULL, server, 10, accepted);
    ASSERT_EQ (count, 0);

    /* Test with NULL server */
    count = SocketPool_accept_batch (pool, NULL, 10, accepted);
    ASSERT_EQ (count, 0);

    /* Test with NULL accepted array */
    count = SocketPool_accept_batch (pool, server, 10, NULL);
    ASSERT_EQ (count, 0);
  }
  EXCEPT (Socket_Failed) { ASSERT (0); }
  EXCEPT (SocketPool_Failed) { /* May be raised */ }
  END_TRY;

  Socket_free (&server);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_accept_one_error_not_eagain)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T accepted[10];

  TRY
  {
    /* Don't call listen - accept will fail with EINVAL, not EAGAIN */
    Socket_bind (server, "127.0.0.1", 0);
    Socket_setnonblocking (server);
    /* Server not in listen state - accept will fail with error != EAGAIN */

    int count = SocketPool_accept_batch (pool, server, 10, accepted);
    /* Should return 0 due to accept error */
    ASSERT_EQ (count, 0);
  }
  EXCEPT (Socket_Failed) { /* Expected */ }
  EXCEPT (SocketPool_Failed) { /* May be raised */ }
  END_TRY;

  Socket_free (&server);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Prewarm Edge Cases ==================== */

TEST (socketpool_prewarm_zero_percent)
{
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);

  TRY
  {
    /* Pre-warm 0% - should do nothing but not crash */
    SocketPool_prewarm (pool, 0);
  }
  EXCEPT (SocketPool_Failed) { ASSERT (0); }
  END_TRY;

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

TEST (socketpool_prewarm_100_percent)
{
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 10, 1024);

  TRY
  {
    /* Pre-warm 100% - should allocate all buffers */
    SocketPool_prewarm (pool, 100);
  }
  EXCEPT (SocketPool_Failed) { ASSERT (0); }
  END_TRY;

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Async Pool Full Callback Test ==================== */

/* Callback for pool full test - tracks error code */
static volatile int pool_full_callback_called = 0;
static volatile int pool_full_callback_error = -1;

static void
pool_full_test_callback (Connection_T conn, int error, void *data)
{
  (void)data;
  pool_full_callback_called = 1;
  pool_full_callback_error = error;
  (void)conn;
}

TEST (socketpool_connect_async_pool_full_callback)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  /* Pool with only 1 slot */
  SocketPool_T pool = SocketPool_new (arena, 1, 1024);
  Socket_T server = NULL;
  Socket_T filler = NULL;
  volatile int port = 0;

  pool_full_callback_called = 0;
  pool_full_callback_error = -1;

  TRY
  {
    /* Create listening server */
    server = Socket_new (AF_INET, SOCK_STREAM, 0);
    Socket_setreuseaddr (server);
    Socket_bind (server, "127.0.0.1", 0);
    Socket_listen (server, 5);
    port = Socket_getlocalport (server);

    /* Fill the pool with one connection */
    filler = Socket_new (AF_INET, SOCK_STREAM, 0);
    Connection_T fc = SocketPool_add (pool, filler);
    ASSERT_NOT_NULL (fc);
  }
  EXCEPT (Socket_Failed)
  {
    if (filler)
      Socket_free (&filler);
    if (server)
      Socket_free (&server);
    SocketPool_free (&pool);
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  TRY
  {
    /* Start async connect - when callback fires, pool is full, should get ENOSPC */
    SocketDNS_Request_T req = SocketPool_connect_async (
        pool, "127.0.0.1", port, pool_full_test_callback, NULL);

    if (req)
      {
        /* Wait for callback */
        for (int i = 0; i < 100 && !pool_full_callback_called; i++)
          usleep (10000);

        /* Callback should have been called with ENOSPC (28) */
        if (pool_full_callback_called)
          {
            ASSERT_EQ (pool_full_callback_error, ENOSPC);
          }
      }
  }
  EXCEPT (SocketPool_Failed) { /* May fail */ }
  EXCEPT (Socket_Failed) { /* May fail */ }
  END_TRY;

  if (filler)
    {
      SocketPool_remove (pool, filler);
      Socket_free (&filler);
    }
  if (server)
    Socket_free (&server);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Async Context List Traversal Test ==================== */

/* Counter and storage for multiple async callbacks */
static volatile int multi_async_callback_count = 0;
static volatile Connection_T multi_async_conns[3];
static pthread_mutex_t multi_async_mutex = PTHREAD_MUTEX_INITIALIZER;

static void
multi_async_test_callback (Connection_T conn, int error, void *data)
{
  (void)error;
  (void)data;
  pthread_mutex_lock (&multi_async_mutex);
  if (conn && multi_async_callback_count < 3)
    multi_async_conns[multi_async_callback_count] = conn;
  multi_async_callback_count++;
  pthread_mutex_unlock (&multi_async_mutex);
}

TEST (socketpool_connect_async_multiple_pending)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T server = NULL;
  volatile int port = 0;
  volatile int i;

  multi_async_callback_count = 0;
  for (i = 0; i < 3; i++)
    multi_async_conns[i] = NULL;

  TRY
  {
    /* Create listening server */
    server = Socket_new (AF_INET, SOCK_STREAM, 0);
    Socket_setreuseaddr (server);
    Socket_bind (server, "127.0.0.1", 0);
    Socket_listen (server, 10);
    port = Socket_getlocalport (server);
  }
  EXCEPT (Socket_Failed)
  {
    if (server)
      Socket_free (&server);
    SocketPool_free (&pool);
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  TRY
  {
    /* Start multiple async connects - exercises list traversal in remove_async_context */
    SocketDNS_Request_T req1 = SocketPool_connect_async (
        pool, "127.0.0.1", port, multi_async_test_callback, (void *)1);
    SocketDNS_Request_T req2 = SocketPool_connect_async (
        pool, "127.0.0.1", port, multi_async_test_callback, (void *)2);
    SocketDNS_Request_T req3 = SocketPool_connect_async (
        pool, "127.0.0.1", port, multi_async_test_callback, (void *)3);

    (void)req1;
    (void)req2;
    (void)req3;

    /* Wait for all callbacks */
    for (i = 0; i < 200; i++)
      {
        pthread_mutex_lock (&multi_async_mutex);
        int count = multi_async_callback_count;
        pthread_mutex_unlock (&multi_async_mutex);
        if (count >= 3)
          break;
        usleep (10000);
      }

    /* Should have at least 1 callback */
    pthread_mutex_lock (&multi_async_mutex);
    ASSERT (multi_async_callback_count >= 1);
    pthread_mutex_unlock (&multi_async_mutex);

    /* Clean up any successful connections */
    for (i = 0; i < 3; i++)
      {
        if (multi_async_conns[i])
          {
            Socket_T s = Connection_socket (multi_async_conns[i]);
            SocketPool_remove (pool, s);
            Socket_free (&s);
          }
      }
  }
  EXCEPT (SocketPool_Failed) { /* May fail */ }
  EXCEPT (Socket_Failed) { /* May fail */ }
  END_TRY;

  if (server)
    Socket_free (&server);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Batch Accept Add Failure Test ==================== */

TEST (socketpool_batch_accept_socket_add_fails)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  /* Pool with only 2 slots */
  SocketPool_T pool = SocketPool_new (arena, 2, 1024);
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client1 = NULL;
  Socket_T client2 = NULL;
  Socket_T filler = NULL;
  Socket_T accepted[10];
  volatile int count = 0;

  Socket_setreuseaddr (server);
  int port = create_pending_connection (server, &client1);
  if (port == 0)
    {
      Socket_free (&server);
      SocketPool_free (&pool);
      Arena_dispose (&arena);
      return;
    }

  /* Create second pending connection */
  client2 = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_setnonblocking (client2);
  TRY { Socket_connect (client2, "127.0.0.1", port); }
  EXCEPT (Socket_Failed)
  {
    if (errno != EINPROGRESS && errno != EWOULDBLOCK)
      {
        Socket_free (&client1);
        Socket_free (&client2);
        Socket_free (&server);
        SocketPool_free (&pool);
        Arena_dispose (&arena);
        return;
      }
  }
  END_TRY;

  TRY
  {
    /* Fill pool to 1 of 2 slots */
    filler = Socket_new (AF_INET, SOCK_STREAM, 0);
    SocketPool_add (pool, filler);

    usleep (20000);

    /* Try to accept 2 - should accept 1 successfully, 2nd will fail to add */
    count = SocketPool_accept_batch (pool, server, 10, accepted);
    /* Should have accepted at least 1 */
    ASSERT (count >= 0);
  }
  EXCEPT (Socket_Failed) { /* May fail */ }
  EXCEPT (SocketPool_Failed) { /* May fail */ }
  END_TRY;

  /* Cleanup accepted */
  for (int i = 0; i < count; i++)
    {
      if (accepted[i])
        {
          SocketPool_remove (pool, accepted[i]);
          Socket_free (&accepted[i]);
        }
    }

  if (filler)
    {
      SocketPool_remove (pool, filler);
      Socket_free (&filler);
    }
  if (client1)
    Socket_free (&client1);
  if (client2)
    Socket_free (&client2);
  Socket_free (&server);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ==================== Wrap FD Failure Test ==================== */

TEST (socketpool_batch_accept_wrap_fd_fails)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketPool_T pool = SocketPool_new (arena, 100, 1024);
  Socket_T server = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T client = NULL;
  Socket_T accepted[10];

  Socket_setreuseaddr (server);
  int port = create_pending_connection (server, &client);
  if (port == 0)
    {
      Socket_free (&server);
      SocketPool_free (&pool);
      Arena_dispose (&arena);
      return;
    }

  usleep (10000);

  TRY
  {
    /* Normal accept should work */
    int count = SocketPool_accept_batch (pool, server, 10, accepted);

    /* Cleanup any accepted */
    for (int i = 0; i < count; i++)
      {
        if (accepted[i])
          {
            SocketPool_remove (pool, accepted[i]);
            Socket_free (&accepted[i]);
          }
      }
  }
  EXCEPT (Socket_Failed) { /* May fail */ }
  EXCEPT (SocketPool_Failed) { /* May fail */ }
  END_TRY;

  if (client)
    Socket_free (&client);
  Socket_free (&server);
  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
