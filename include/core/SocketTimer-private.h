/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETTIMER_PRIVATE_INCLUDED
#define SOCKETTIMER_PRIVATE_INCLUDED

#include "core/Arena.h"
#include "core/SocketTimer.h"
#include <pthread.h>
#include <stdint.h>

/* Internal timer heap implementation. Not part of public API. */

/* Internal timer structure. */
struct SocketTimer_T
{
  int64_t expiry_ms;
  int64_t interval_ms;
  SocketTimerCallback callback;
  void *userdata;
  int cancelled;
  int paused;
  int64_t paused_remaining_ms;
  uint64_t id;
  size_t heap_index;
};

/* Binary min-heap for timer management. Thread-safe via mutex. */
struct SocketTimer_heap_T
{
  struct SocketTimer_T **timers;
  size_t count;
  size_t capacity;
  uint64_t next_id;
  Arena_T arena;
  pthread_mutex_t mutex;
};

typedef struct SocketTimer_heap_T SocketTimer_heap_T;

#define SOCKET_TIMER_INVALID_HEAP_INDEX ((size_t) - 1)

SocketTimer_heap_T *SocketTimer_heap_new (Arena_T arena);

void SocketTimer_heap_free (SocketTimer_heap_T **heap);

void SocketTimer_heap_push (SocketTimer_heap_T *heap,
                            struct SocketTimer_T *timer);
struct SocketTimer_T *SocketTimer_heap_pop (SocketTimer_heap_T *heap);
struct SocketTimer_T *SocketTimer_heap_peek (SocketTimer_heap_T *heap);
int64_t SocketTimer_heap_peek_delay (SocketTimer_heap_T *heap);
int SocketTimer_process_expired (SocketTimer_heap_T *heap);
int SocketTimer_heap_cancel (SocketTimer_heap_T *heap,
                             struct SocketTimer_T *timer);
int64_t SocketTimer_heap_remaining (SocketTimer_heap_T *heap,
                                    const struct SocketTimer_T *timer);

#endif /* SOCKETTIMER_PRIVATE_INCLUDED */
