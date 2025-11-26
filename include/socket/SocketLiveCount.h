#ifndef SOCKETLIVECOUNT_INCLUDED
#define SOCKETLIVECOUNT_INCLUDED

/**
 * SocketLiveCount.h - Consolidated live socket count tracking
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Provides thread-safe live count tracking for socket instances.
 * Used by both Socket_T and SocketDgram_T for debugging and leak detection.
 *
 * Features:
 * - Thread-safe increment/decrement operations
 * - Atomic-like count retrieval
 * - Mutex-protected critical sections
 */

#include <pthread.h>

/**
 * SocketLiveCount_T - Opaque type for live count tracker
 * Each socket type (Socket, SocketDgram) maintains its own instance.
 */
typedef struct SocketLiveCount_T *SocketLiveCount_T;

/**
 * SocketLiveCount_static_init - Static initializer for live count tracker
 *
 * Usage: static struct SocketLiveCount socket_live_tracker
 *            = SOCKETLIVECOUNT_STATIC_INIT;
 */
struct SocketLiveCount
{
  int count;
  pthread_mutex_t mutex;
};

#define SOCKETLIVECOUNT_STATIC_INIT                                           \
  {                                                                            \
    0, PTHREAD_MUTEX_INITIALIZER                                               \
  }

/**
 * SocketLiveCount_increment - Increment live count (thread-safe)
 * @tracker: Live count tracker
 * Thread-safe: Yes - protected by mutex
 */
static inline void
SocketLiveCount_increment (struct SocketLiveCount *tracker)
{
  pthread_mutex_lock (&tracker->mutex);
  tracker->count++;
  pthread_mutex_unlock (&tracker->mutex);
}

/**
 * SocketLiveCount_decrement - Decrement live count (thread-safe)
 * @tracker: Live count tracker
 * Thread-safe: Yes - protected by mutex
 * Prevents TOCTOU race condition by atomically checking and decrementing
 */
static inline void
SocketLiveCount_decrement (struct SocketLiveCount *tracker)
{
  pthread_mutex_lock (&tracker->mutex);
  if (tracker->count > 0)
    tracker->count--;
  pthread_mutex_unlock (&tracker->mutex);
}

/**
 * SocketLiveCount_get - Get current live count (thread-safe)
 * @tracker: Live count tracker
 * Returns: Current count value
 * Thread-safe: Yes - protected by mutex
 */
static inline int
SocketLiveCount_get (struct SocketLiveCount *tracker)
{
  int count;
  pthread_mutex_lock (&tracker->mutex);
  count = tracker->count;
  pthread_mutex_unlock (&tracker->mutex);
  return count;
}

#endif /* SOCKETLIVECOUNT_INCLUDED */

