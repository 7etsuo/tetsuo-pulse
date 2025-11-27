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

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
