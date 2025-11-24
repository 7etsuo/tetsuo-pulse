#ifndef SOCKETPOOL_PRIVATE_H_INCLUDED
#define SOCKETPOOL_PRIVATE_H_INCLUDED

#include <time.h>

#include "core/Arena.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"

#ifdef SOCKET_HAS_TLS
#include "tls/SocketTLSContext.h"
#include <openssl/ssl.h>
#endif

#include "SocketPool.h"

struct Connection
{
  Socket_T socket;
  SocketBuf_T inbuf;
  SocketBuf_T outbuf;
  void *data;
  time_t last_activity;
  int active;
  struct Connection *hash_next;
  struct Connection *free_next;
#ifdef SOCKET_HAS_TLS
  SocketTLSContext_T tls_ctx; /* TLS context for this connection */
  int tls_handshake_complete; /* TLS handshake state */
  SSL_SESSION *tls_session; /* Saved TLS session for potential reuse */
#endif
};

typedef struct Connection *Connection_T;

#define SOCKET_HASH_SIZE                                                      \
  1021 /* Hash table size - prime for good distribution */

#define T SocketPool_T
struct T
{
  struct Connection *connections;
  Connection_T *hash_table;
  Connection_T free_list;
  Socket_T *cleanup_buffer;
  size_t maxconns;
  size_t bufsize;
  size_t count;
  Arena_T arena;
  pthread_mutex_t mutex;
};
#undef T

extern struct Connection *
SocketPool_connections_allocate_array (size_t maxconns);

extern Connection_T *
SocketPool_connections_allocate_hash_table (Arena_T arena);

extern void SocketPool_connections_initialize_slot (struct Connection *conn);

extern int SocketPool_connections_alloc_buffers (Arena_T arena, size_t bufsize,
                                                 Connection_T conn);

extern Connection_T find_slot (SocketPool_T pool, const Socket_T socket);

extern Connection_T find_free_slot (SocketPool_T pool);

extern int check_pool_full (SocketPool_T pool);

extern void remove_from_free_list (SocketPool_T pool, Connection_T conn);

extern void return_to_free_list (SocketPool_T pool, Connection_T conn);

extern int prepare_free_slot (SocketPool_T pool, Connection_T conn);

extern void update_existing_slot (Connection_T conn, time_t now);

extern void insert_into_hash_table (SocketPool_T pool, Connection_T conn,
                                    Socket_T socket);

extern void increment_pool_count (SocketPool_T pool);

extern void initialize_connection (Connection_T conn, Socket_T socket,
                                   time_t now);

extern Connection_T find_or_create_slot (SocketPool_T pool, Socket_T socket,
                                         time_t now);

extern void remove_from_hash_table (SocketPool_T pool, Connection_T conn,
                                    Socket_T socket);

extern void SocketPool_connections_release_buffers (Connection_T conn);

extern void SocketPool_connections_reset_slot (Connection_T conn);

extern void decrement_pool_count (SocketPool_T pool);

#ifdef SOCKET_HAS_TLS
extern void validate_saved_session (Connection_T conn);
#endif

extern Socket_T *SocketPool_cleanup_allocate_buffer (Arena_T arena,
                                                     size_t maxconns);

#endif /* SOCKETPOOL_PRIVATE_H_INCLUDED */
