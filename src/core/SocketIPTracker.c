/**
 * SocketIPTracker.c - Per-IP Connection Tracking Implementation
 *
 * Part of the Socket Library
 *
 * Hash table-based IP connection tracking with:
 * - Chained collision handling using DJB2 hash algorithm
 * - Automatic cleanup of zero-count entries
 * - Thread-safe operations via mutex
 * - O(1) average lookup, insert, and delete operations
 *
 * Thread Safety:
 * - All public functions use mutex protection
 * - Internal helpers assume mutex is held by caller
 *
 * REFACTORED: Eliminated redundant O(n) search in release path.
 * Previously find_and_unlink_zero_entry re-searched for an entry
 * the caller already had. Now we track prev pointer during lookup
 * for direct O(1) unlinking.
 */

#include "core/SocketIPTracker.h"
#include "core/SocketConfig.h"
#include "core/SocketUtil.h"
#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define T SocketIPTracker_T

/* ============================================================================
 * Exception Definitions
 * ============================================================================ */

const Except_T SocketIPTracker_Failed
    = { &SocketIPTracker_Failed, "IP tracker operation failed" };

/* Thread-local exception using centralized macro */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketIPTracker);

/* ============================================================================
 * Internal Structures
 * ============================================================================ */

/**
 * IPEntry - IP entry in hash table
 *
 * Stores connection count for a single IP address with chaining
 * for hash collision resolution.
 */
typedef struct IPEntry
{
  char ip[SOCKET_IP_MAX_LEN]; /**< IP address string */
  int count;                  /**< Connection count */
  struct IPEntry *next;       /**< Next in hash chain */
} IPEntry;

/**
 * struct T - IP tracker structure
 *
 * Hash table implementation with mutex for thread safety.
 * Supports both arena and heap allocation.
 */
struct T
{
  IPEntry **buckets;     /**< Hash table buckets */
  size_t bucket_count;   /**< Number of buckets */
  int max_per_ip;        /**< Maximum connections per IP */
  size_t total_conns;    /**< Total tracked connections */
  size_t unique_ips;     /**< Number of unique IPs */
  pthread_mutex_t mutex; /**< Thread safety mutex */
  Arena_T arena;         /**< Arena for allocation (NULL if malloc) */
  int initialized;       /**< 1 if mutex initialized */
};

/* ============================================================================
 * Internal Helper Functions - Hash Computation
 * ============================================================================ */

/**
 * compute_bucket_index - Compute bucket index for IP address
 * @ip: IP address string
 * @bucket_count: Number of buckets in hash table
 *
 * Returns: Bucket index (0 to bucket_count-1)
 * Thread-safe: Yes (no shared state)
 *
 * Uses DJB2 hash algorithm via socket_util_hash_djb2.
 */
static unsigned
compute_bucket_index (const char *ip, size_t bucket_count)
{
  assert (ip != NULL);
  assert (bucket_count > 0);
  return socket_util_hash_djb2 (ip, (unsigned)bucket_count);
}

/* ============================================================================
 * Internal Helper Functions - Entry Lookup
 * ============================================================================ */

/**
 * find_entry_with_prev - Find IP entry and previous pointer in one pass
 * @tracker: IP tracker instance (caller must hold mutex)
 * @ip: IP address string
 * @bucket_out: Output bucket index
 * @prev_out: Output previous entry pointer (NULL if entry is at head)
 *
 * Returns: Entry pointer or NULL if not found
 * Thread-safe: No (caller must hold mutex)
 *
 * This function combines lookup and prev tracking in a single O(n) pass,
 * enabling O(1) unlinking without a second search.
 */
static IPEntry *
find_entry_with_prev (const T tracker, const char *ip, unsigned *bucket_out,
                      IPEntry **prev_out)
{
  unsigned idx;
  IPEntry *prev = NULL;
  IPEntry *entry;

  assert (tracker != NULL);
  assert (ip != NULL);
  assert (bucket_out != NULL);
  assert (prev_out != NULL);

  idx = compute_bucket_index (ip, tracker->bucket_count);
  *bucket_out = idx;

  for (entry = tracker->buckets[idx]; entry != NULL; entry = entry->next)
    {
      if (strcmp (entry->ip, ip) == 0)
        {
          *prev_out = prev;
          return entry;
        }
      prev = entry;
    }

  *prev_out = NULL;
  return NULL;
}

/**
 * find_entry_simple - Find IP entry without prev tracking
 * @tracker: IP tracker instance (caller must hold mutex)
 * @ip: IP address string
 * @bucket_out: Output bucket index (optional, may be NULL)
 *
 * Returns: Entry pointer or NULL if not found
 * Thread-safe: No (caller must hold mutex)
 *
 * Simplified lookup for cases where we don't need to unlink.
 */
static IPEntry *
find_entry_simple (const T tracker, const char *ip, unsigned *bucket_out)
{
  unsigned idx;
  IPEntry *entry;

  assert (tracker != NULL);
  assert (ip != NULL);

  idx = compute_bucket_index (ip, tracker->bucket_count);

  if (bucket_out != NULL)
    *bucket_out = idx;

  for (entry = tracker->buckets[idx]; entry != NULL; entry = entry->next)
    {
      if (strcmp (entry->ip, ip) == 0)
        return entry;
    }

  return NULL;
}

/* ============================================================================
 * Internal Helper Functions - Entry Allocation
 * ============================================================================ */

/**
 * allocate_entry - Allocate IPEntry from arena or heap
 * @tracker: IP tracker instance
 *
 * Returns: New entry or NULL on allocation failure
 * Thread-safe: No (caller must hold mutex)
 */
static IPEntry *
allocate_entry (const T tracker)
{
  if (tracker->arena != NULL)
    return Arena_alloc (tracker->arena, sizeof (IPEntry), __FILE__, __LINE__);

  return malloc (sizeof (IPEntry));
}

/**
 * create_and_insert_entry - Create new entry and insert at bucket head
 * @tracker: IP tracker instance (caller must hold mutex)
 * @ip: IP address string to copy
 * @bucket: Bucket index
 * @initial_count: Initial connection count for entry
 *
 * Returns: New entry or NULL on allocation failure
 * Thread-safe: No (caller must hold mutex)
 *
 * Combines allocation, initialization, and insertion in one function.
 */
static IPEntry *
create_and_insert_entry (T tracker, const char *ip, unsigned bucket,
                         int initial_count)
{
  IPEntry *entry;

  assert (tracker != NULL);
  assert (ip != NULL);
  assert (bucket < tracker->bucket_count);

  entry = allocate_entry (tracker);
  if (entry == NULL)
    return NULL;

  /* Initialize entry */
  strncpy (entry->ip, ip, SOCKET_IP_MAX_LEN - 1);
  entry->ip[SOCKET_IP_MAX_LEN - 1] = '\0';
  entry->count = initial_count;
  entry->next = tracker->buckets[bucket];

  /* Insert at head */
  tracker->buckets[bucket] = entry;
  tracker->unique_ips++;

  return entry;
}

/* ============================================================================
 * Internal Helper Functions - Entry Removal
 * ============================================================================ */

/**
 * unlink_entry - Remove entry from bucket chain (O(1) with prev pointer)
 * @tracker: IP tracker instance (caller must hold mutex)
 * @entry: Entry to unlink (must not be NULL)
 * @prev: Previous entry in chain (NULL if entry is at head)
 * @bucket: Bucket index
 *
 * Thread-safe: No (caller must hold mutex)
 */
static void
unlink_entry (T tracker, IPEntry *entry, IPEntry *prev, unsigned bucket)
{
  assert (tracker != NULL);
  assert (entry != NULL);
  assert (bucket < tracker->bucket_count);

  if (prev != NULL)
    prev->next = entry->next;
  else
    tracker->buckets[bucket] = entry->next;

  tracker->unique_ips--;

  /* Free if heap-allocated */
  if (tracker->arena == NULL)
    free (entry);
}

/* ============================================================================
 * Internal Helper Functions - Bucket Operations
 * ============================================================================ */

/**
 * calculate_buckets_size - Calculate bucket array size with overflow check
 * @bucket_count: Number of buckets
 * @size_out: Output for calculated size
 *
 * Returns: 1 on success, 0 on overflow
 * Thread-safe: Yes (no shared state)
 */
static int
calculate_buckets_size (size_t bucket_count, size_t *size_out)
{
  assert (size_out != NULL);

  if (bucket_count > SIZE_MAX / sizeof (IPEntry *))
    return 0;

  *size_out = bucket_count * sizeof (IPEntry *);
  return 1;
}

/**
 * allocate_buckets - Allocate hash table buckets
 * @tracker: IP tracker instance
 * @buckets_size: Size in bytes
 *
 * Returns: Bucket array or NULL on failure
 * Thread-safe: No (caller must hold mutex during init)
 */
static IPEntry **
allocate_buckets (const T tracker, size_t buckets_size)
{
  if (tracker->arena != NULL)
    return Arena_alloc (tracker->arena, buckets_size, __FILE__, __LINE__);

  return malloc (buckets_size);
}

/**
 * free_bucket_chain - Free all entries in a bucket chain
 * @entry: Head of chain (may be NULL)
 *
 * Thread-safe: No (caller must hold mutex)
 */
static void
free_bucket_chain (IPEntry *entry)
{
  while (entry != NULL)
    {
      IPEntry *next = entry->next;
      free (entry);
      entry = next;
    }
}

/**
 * free_all_buckets - Free all bucket chains (heap-allocated only)
 * @tracker: IP tracker instance
 *
 * Thread-safe: No (caller must hold mutex)
 */
static void
free_all_buckets (T tracker)
{
  size_t i;

  for (i = 0; i < tracker->bucket_count; i++)
    {
      free_bucket_chain (tracker->buckets[i]);
      tracker->buckets[i] = NULL;
    }
}

/* ============================================================================
 * Internal Helper Functions - Tracker Initialization
 * ============================================================================ */

/**
 * allocate_tracker - Allocate tracker structure
 * @arena: Arena for allocation (NULL for heap)
 *
 * Returns: New tracker or NULL on failure
 * Thread-safe: Yes (no shared state)
 */
static T
allocate_tracker (Arena_T arena)
{
  if (arena != NULL)
    return Arena_alloc (arena, sizeof (struct T), __FILE__, __LINE__);

  return malloc (sizeof (struct T));
}

/**
 * init_tracker_fields - Initialize tracker fields
 * @tracker: Tracker to initialize (must not be NULL)
 * @arena: Arena for allocation
 * @max_per_ip: Maximum connections per IP
 *
 * Thread-safe: No (called during construction)
 */
static void
init_tracker_fields (T tracker, Arena_T arena, int max_per_ip)
{
  assert (tracker != NULL);

  memset (tracker, 0, sizeof (*tracker));
  tracker->bucket_count = SOCKET_IP_TRACKER_HASH_SIZE;
  tracker->max_per_ip = max_per_ip;
  tracker->arena = arena;
  tracker->initialized = 0;
}

/**
 * init_tracker_buckets - Initialize tracker bucket array
 * @tracker: Tracker instance
 *
 * Returns: 0 on success, -1 on failure
 * Thread-safe: No (called during construction)
 */
static int
init_tracker_buckets (T tracker)
{
  size_t buckets_size;

  if (!calculate_buckets_size (tracker->bucket_count, &buckets_size))
    {
      SOCKET_ERROR_MSG ("Bucket size overflow");
      return -1;
    }

  tracker->buckets = allocate_buckets (tracker, buckets_size);
  if (tracker->buckets == NULL)
    {
      SOCKET_ERROR_MSG ("Failed to allocate IP tracker hash table");
      return -1;
    }

  memset (tracker->buckets, 0, buckets_size);
  return 0;
}

/**
 * init_tracker_mutex - Initialize tracker mutex
 * @tracker: Tracker to initialize
 *
 * Returns: 0 on success, -1 on failure
 * Thread-safe: No (called during construction)
 */
static int
init_tracker_mutex (T tracker)
{
  assert (tracker != NULL);

  if (pthread_mutex_init (&tracker->mutex, NULL) != 0)
    return -1;

  tracker->initialized = 1;
  return 0;
}

/**
 * cleanup_failed_tracker - Clean up partially initialized tracker
 * @tracker: Tracker to clean up
 *
 * Thread-safe: No (called during failed construction)
 */
static void
cleanup_failed_tracker (T tracker)
{
  if (tracker->arena == NULL)
    {
      if (tracker->buckets != NULL)
        free (tracker->buckets);
      free (tracker);
    }
}

/* ============================================================================
 * Internal Helper Functions - Track Operations
 * ============================================================================ */

/**
 * track_unlimited_mode - Track connection in unlimited mode
 * @tracker: IP tracker instance (caller must hold mutex)
 * @ip: IP address string
 *
 * Returns: Always 1 (allowed in unlimited mode)
 * Thread-safe: No (caller must hold mutex)
 *
 * BEHAVIOR: In unlimited mode (max_per_ip == 0), connections are ALWAYS
 * allowed, even if internal allocation fails. This is intentional:
 * - Unlimited mode is a "no enforcement" policy
 * - Allocation failure should not block legitimate traffic
 * - Counter tracking is best-effort only in this mode
 *
 * If allocation succeeds, connection count is tracked for statistics.
 * If allocation fails, the connection is still allowed but not tracked.
 */
static int
track_unlimited_mode (T tracker, const char *ip)
{
  unsigned bucket;
  IPEntry *entry = find_entry_simple (tracker, ip, &bucket);

  if (entry == NULL)
    entry = create_and_insert_entry (tracker, ip, bucket, 0);

  if (entry != NULL)
    {
      entry->count++;
      tracker->total_conns++;
    }
  /* Allocation failure: allow connection but skip tracking (intentional) */

  return 1;
}

/**
 * track_limited_mode - Track connection with per-IP limit
 * @tracker: IP tracker instance (caller must hold mutex)
 * @ip: IP address string
 *
 * Returns: 1 if allowed, 0 if limit reached or allocation failed
 * Thread-safe: No (caller must hold mutex)
 *
 * BEHAVIOR: In limited mode, connections are rejected when:
 * - The IP has reached max_per_ip connections, OR
 * - Memory allocation fails for a new IP entry
 */
static int
track_limited_mode (T tracker, const char *ip)
{
  unsigned bucket;
  IPEntry *entry = find_entry_simple (tracker, ip, &bucket);

  if (entry == NULL)
    {
      /* New IP - create entry with count 1 */
      entry = create_and_insert_entry (tracker, ip, bucket, 1);
      if (entry == NULL)
        return 0;

      tracker->total_conns++;
      return 1;
    }

  /* Existing IP - check limit */
  if (entry->count < tracker->max_per_ip)
    {
      entry->count++;
      tracker->total_conns++;
      return 1;
    }

  return 0;
}

/* ============================================================================
 * Public API Implementation
 * ============================================================================ */

/**
 * SocketIPTracker_new - Create a new IP connection tracker
 */
T
SocketIPTracker_new (Arena_T arena, int max_per_ip)
{
  T tracker = allocate_tracker (arena);

  if (tracker == NULL)
    SOCKET_RAISE_MSG (SocketIPTracker, SocketIPTracker_Failed,
                      "Failed to allocate IP tracker");

  init_tracker_fields (tracker, arena, max_per_ip);

  if (init_tracker_buckets (tracker) != 0)
    {
      cleanup_failed_tracker (tracker);
      SOCKET_RAISE_MODULE_ERROR (SocketIPTracker, SocketIPTracker_Failed);
    }

  if (init_tracker_mutex (tracker) != 0)
    {
      cleanup_failed_tracker (tracker);
      SOCKET_RAISE_FMT (SocketIPTracker, SocketIPTracker_Failed,
                        "Failed to initialize IP tracker mutex");
    }

  return tracker;
}

/**
 * SocketIPTracker_free - Free an IP tracker
 */
void
SocketIPTracker_free (T *tracker)
{
  T t;

  if (tracker == NULL || *tracker == NULL)
    return;

  t = *tracker;

  if (t->initialized)
    pthread_mutex_destroy (&t->mutex);

  if (t->arena == NULL)
    {
      free_all_buckets (t);
      free (t->buckets);
      free (t);
    }

  *tracker = NULL;
}

/**
 * SocketIPTracker_track - Track a new connection from IP
 */
int
SocketIPTracker_track (T tracker, const char *ip)
{
  int result;

  assert (tracker != NULL);

  if (!SOCKET_VALID_IP_STRING (ip))
    return 1;

  pthread_mutex_lock (&tracker->mutex);

  if (tracker->max_per_ip == 0)
    result = track_unlimited_mode (tracker, ip);
  else
    result = track_limited_mode (tracker, ip);

  pthread_mutex_unlock (&tracker->mutex);
  return result;
}

/**
 * SocketIPTracker_release - Release a connection from IP
 *
 * Uses find_entry_with_prev for O(1) unlinking.
 */
void
SocketIPTracker_release (T tracker, const char *ip)
{
  unsigned bucket;
  IPEntry *prev;
  IPEntry *entry;

  assert (tracker != NULL);

  if (!SOCKET_VALID_IP_STRING (ip))
    return;

  pthread_mutex_lock (&tracker->mutex);

  entry = find_entry_with_prev (tracker, ip, &bucket, &prev);

  if (entry != NULL && entry->count > 0)
    {
      entry->count--;
      tracker->total_conns--;

      /* Remove entry if count reaches zero (O(1) with prev pointer) */
      if (entry->count == 0)
        unlink_entry (tracker, entry, prev, bucket);
    }

  pthread_mutex_unlock (&tracker->mutex);
}

/**
 * SocketIPTracker_count - Get current connection count for IP
 */
int
SocketIPTracker_count (T tracker, const char *ip)
{
  const IPEntry *entry;
  int count = 0;

  assert (tracker != NULL);

  if (!SOCKET_VALID_IP_STRING (ip))
    return 0;

  pthread_mutex_lock (&tracker->mutex);

  entry = find_entry_simple (tracker, ip, NULL);
  if (entry != NULL)
    count = entry->count;

  pthread_mutex_unlock (&tracker->mutex);
  return count;
}

/**
 * SocketIPTracker_setmax - Set maximum connections per IP
 */
void
SocketIPTracker_setmax (T tracker, int max_per_ip)
{
  assert (tracker != NULL);

  pthread_mutex_lock (&tracker->mutex);
  tracker->max_per_ip = max_per_ip;
  pthread_mutex_unlock (&tracker->mutex);
}

/**
 * SocketIPTracker_getmax - Get maximum connections per IP
 */
int
SocketIPTracker_getmax (T tracker)
{
  int max;

  assert (tracker != NULL);

  pthread_mutex_lock (&tracker->mutex);
  max = tracker->max_per_ip;
  pthread_mutex_unlock (&tracker->mutex);

  return max;
}

/**
 * SocketIPTracker_total - Get total tracked connections
 */
size_t
SocketIPTracker_total (T tracker)
{
  size_t total;

  assert (tracker != NULL);

  pthread_mutex_lock (&tracker->mutex);
  total = tracker->total_conns;
  pthread_mutex_unlock (&tracker->mutex);

  return total;
}

/**
 * SocketIPTracker_unique_ips - Get number of unique IPs being tracked
 */
size_t
SocketIPTracker_unique_ips (T tracker)
{
  size_t unique;

  assert (tracker != NULL);

  pthread_mutex_lock (&tracker->mutex);
  unique = tracker->unique_ips;
  pthread_mutex_unlock (&tracker->mutex);

  return unique;
}

/**
 * SocketIPTracker_clear - Clear all tracked connections
 */
void
SocketIPTracker_clear (T tracker)
{
  assert (tracker != NULL);

  pthread_mutex_lock (&tracker->mutex);

  if (tracker->arena == NULL)
    free_all_buckets (tracker);
  else
    memset (tracker->buckets, 0,
            tracker->bucket_count * sizeof (IPEntry *));

  tracker->total_conns = 0;
  tracker->unique_ips = 0;

  pthread_mutex_unlock (&tracker->mutex);
}

#undef T
