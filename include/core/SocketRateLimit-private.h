/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETRATELIMIT_PRIVATE_INCLUDED
#define SOCKETRATELIMIT_PRIVATE_INCLUDED

/**
 * @file SocketRateLimit-private.h
 * @internal
 *
 * Private implementation details for token bucket rate limiter.
 * Include only from SocketRateLimit.c and related files.
 */

#include "core/Arena.h"
#include "core/SocketRateLimit.h"
#include "core/SocketUtil.h"
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#ifndef SOCKET_RATELIMIT_IMPOSSIBLE_WAIT
#define SOCKET_RATELIMIT_IMPOSSIBLE_WAIT (-1)
#endif

#ifndef SOCKET_RATELIMIT_FREE_MAX_RETRIES
#define SOCKET_RATELIMIT_FREE_MAX_RETRIES 10000
#endif

#ifdef SOCKET_RATELIMIT_DEBUG_WARNINGS
#include <stdio.h>
#define SOCKET_RATELIMIT_WARN(msg) fprintf (stderr, "WARN: %s\n", (msg))
#else
#define SOCKET_RATELIMIT_WARN(msg) ((void)0)
#endif

#define T SocketRateLimit_T

struct T
{
  size_t tokens_per_sec;
  size_t bucket_size;
  size_t tokens;
  int64_t last_refill_ms;
  pthread_mutex_t mutex;
  Arena_T arena;
  int initialized;
};

#undef T

#endif /* SOCKETRATELIMIT_PRIVATE_INCLUDED */
