#ifndef SOCKETASYNC_PRIVATE_H_INCLUDED
#define SOCKETASYNC_PRIVATE_H_INCLUDED

#include "core/Arena.h"
#include "core/SocketConfig.h"
#include "socket/Socket.h"
#include "socket/SocketAsync.h"

/* Async request tracking structure */
struct AsyncRequest
{
  unsigned request_id;
  Socket_T socket;
  SocketAsync_Callback cb;
  void *user_data;
  enum
  {
    REQ_SEND,
    REQ_RECV
  } type;
  const void *send_buf; /* For send: data to send */
  void *recv_buf;       /* For recv: user's buffer (must remain valid) */
  size_t len;           /* Original length */
  size_t completed;     /* Bytes completed so far */
  SocketAsync_Flags flags;
  struct AsyncRequest *next; /* Hash table chain */
  time_t submitted_at;       /* For timeout tracking */
};

/* Async context structure */
struct SocketAsync_T
{
  Arena_T arena;

  /* Request tracking */
  struct AsyncRequest *requests[SOCKET_HASH_TABLE_SIZE];
  unsigned next_request_id;
  pthread_mutex_t mutex;

  /* Platform-specific async context */
#ifdef SOCKET_HAS_IO_URING
  struct io_uring *ring; /* io_uring ring (if available) */
  int io_uring_fd;       /* Eventfd for completion notifications */
#elif defined(__APPLE__) || defined(__FreeBSD__)
  int kqueue_fd; /* kqueue fd for AIO */
#else
  /* Fallback: edge-triggered polling */
  int fallback_mode;
#endif

  int available; /* Non-zero if async available */
  const char *backend_name;
};

#endif /* SOCKETASYNC_PRIVATE_H_INCLUDED */
