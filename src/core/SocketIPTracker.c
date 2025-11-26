/**
 * SocketIPTracker.c - Per-IP Connection Tracking Implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Hash table-based IP connection tracking with:
 * - Chained collision handling using DJB2 hash algorithm
 * - Automatic cleanup of zero-count entries
 * - Thread-safe operations via mutex
 *
 * Thread Safety:
 * - All public functions use mutex protection
 * - Internal helpers assume mutex is held by caller
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
 * Configuration Constants
 * ============================================================================ */

/**
 * DJB2 hash algorithm seed value
 * Standard initial value for DJB2 hash function
 */
#define DJB2_HASH_SEED 5381u

/* ============================================================================
 * Exception Definitions
 * ============================================================================ */

const Except_T SocketIPTracker_Failed
    = { &SocketIPTracker_Failed, "IP tracker operation failed" };

/* Thread-local exception using centralized macro */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketIPTracker);

#define RAISE_IPTRACKER_ERROR(exception)                                       \
  SOCKET_RAISE_MODULE_ERROR (SocketIPTracker, exception)

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
 * Internal Helper Functions - Hash Operations
 * ============================================================================ */

/**
 * ip_hash - Compute hash for IP address using DJB2 algorithm
 * @ip: IP address string
 * @bucket_count: Number of buckets
 *
 * Returns: Hash bucket index
 * Thread-safe: Yes (no shared state)
 *
 * Uses DJB2 hash: hash = hash * 33 + c
 * The multiplication by 33 is optimized as (hash << 5) + hash.
 */
static unsigned
ip_hash (const char *ip, size_t bucket_count)
{
  unsigned hash = DJB2_HASH_SEED;
  int c;

  while ((c = *ip++) != '\0')
    hash = ((hash << 5) + hash) + (unsigned)c; /* hash * 33 + c */

  return hash % bucket_count;
}

/* ============================================================================
 * Internal Helper Functions - Entry Lookup
 * ============================================================================ */

/**
 * find_entry - Find IP entry in hash table
 * @tracker: IP tracker instance (caller must hold mutex)
 * @ip: IP address string
 * @bucket_out: Output bucket index (optional, may be NULL)
 *
 * Returns: Entry pointer or NULL if not found
 * Thread-safe: No (caller must hold mutex)
 */
static IPEntry *
find_entry (T tracker, const char *ip, unsigned *bucket_out)
{
  const unsigned idx = ip_hash (ip, tracker->bucket_count);

  if (bucket_out != NULL)
    *bucket_out = idx;

  for (IPEntry *entry = tracker->buckets[idx]; entry; entry = entry->next)
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
allocate_entry (T tracker)
{
  if (tracker->arena != NULL)
    return Arena_alloc (tracker->arena, sizeof (IPEntry), __FILE__, __LINE__);

  return malloc (sizeof (IPEntry));
}

/**
 * init_entry - Initialize a new IP entry
 * @entry: Entry to initialize
 * @ip: IP address string to copy
 *
 * Thread-safe: No (caller must hold mutex)
 */
static void
init_entry (IPEntry *entry, const char *ip)
{
  strncpy (entry->ip, ip, SOCKET_IP_MAX_LEN - 1);
  entry->ip[SOCKET_IP_MAX_LEN - 1] = '\0';
  entry->count = 0;
  entry->next = NULL;
}

/**
 * insert_entry_at_head - Insert entry at head of bucket chain
 * @tracker: IP tracker instance (caller must hold mutex)
 * @entry: Entry to insert
 * @bucket: Bucket index
 *
 * Thread-safe: No (caller must hold mutex)
 */
static void
insert_entry_at_head (T tracker, IPEntry *entry, unsigned bucket)
{
  entry->next = tracker->buckets[bucket];
  tracker->buckets[bucket] = entry;
  tracker->unique_ips++;
}

/**
 * create_entry - Create new IP entry (allocate, init, insert)
 * @tracker: IP tracker instance (caller must hold mutex)
 * @ip: IP address string
 * @bucket: Bucket index to insert into
 *
 * Returns: New entry or NULL on allocation failure
 * Thread-safe: No (caller must hold mutex)
 */
static IPEntry *
create_entry (T tracker, const char *ip, unsigned bucket)
{
  IPEntry *entry = allocate_entry (tracker);
  if (entry == NULL)
    return NULL;

  init_entry (entry, ip);
  insert_entry_at_head (tracker, entry, bucket);

  return entry;
}

/* ============================================================================
 * Internal Helper Functions - Entry Removal
 * ============================================================================ */

/**
 * unlink_entry_from_chain - Remove entry from bucket chain
 * @tracker: IP tracker instance (caller must hold mutex)
 * @entry: Entry to unlink
 * @prev: Previous entry in chain (NULL if at head)
 * @bucket: Bucket index
 *
 * Thread-safe: No (caller must hold mutex)
 */
static void
unlink_entry_from_chain (T tracker, IPEntry *entry, IPEntry *prev,
                         unsigned bucket)
{
  if (prev != NULL)
    prev->next = entry->next;
  else
    tracker->buckets[bucket] = entry->next;

  tracker->unique_ips--;
}

/**
 * free_entry_if_heap - Free entry if not arena-allocated
 * @tracker: IP tracker instance
 * @entry: Entry to potentially free
 *
 * Thread-safe: No (caller must hold mutex)
 */
static void
free_entry_if_heap (T tracker, IPEntry *entry)
{
  if (tracker->arena == NULL)
    free (entry);
}

/**
 * find_and_unlink_zero_entry - Find and remove entry with zero count
 * @tracker: IP tracker instance (caller must hold mutex)
 * @ip: IP address string
 * @bucket: Bucket index
 *
 * Thread-safe: No (caller must hold mutex)
 *
 * Searches bucket chain for matching IP with count == 0,
 * unlinks and frees if found.
 */
static void
find_and_unlink_zero_entry (T tracker, const char *ip, unsigned bucket)
{
  IPEntry *prev = NULL;

  for (IPEntry *entry = tracker->buckets[bucket]; entry; entry = entry->next)
    {
      if (strcmp (entry->ip, ip) == 0)
        {
          if (entry->count > 0)
            return;

          unlink_entry_from_chain (tracker, entry, prev, bucket);
          free_entry_if_heap (tracker, entry);
          return;
        }
      prev = entry;
    }
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
allocate_buckets (T tracker, size_t buckets_size)
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
  for (size_t i = 0; i < tracker->bucket_count; i++)
    {
      free_bucket_chain (tracker->buckets[i]);
      tracker->buckets[i] = NULL;
    }
}

/* ============================================================================
 * Internal Helper Functions - Tracker Allocation
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
 * @tracker: Tracker to initialize
 * @arena: Arena for allocation
 * @max_per_ip: Maximum connections per IP
 *
 * Thread-safe: No (called during construction)
 */
static void
init_tracker_fields (T tracker, Arena_T arena, int max_per_ip)
{
  memset (tracker, 0, sizeof (*tracker));
  tracker->bucket_count = SOCKET_IP_TRACKER_HASH_SIZE;
  tracker->max_per_ip = max_per_ip;
  tracker->arena = arena;
  tracker->initialized = 0;
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
 * Internal Helper Functions - Tracker Initialization Steps
 * ============================================================================ */

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

/* ============================================================================
 * Internal Helper Functions - Track Operations
 * ============================================================================ */

/**
 * increment_entry_count - Increment entry count and total
 * @tracker: IP tracker instance (caller must hold mutex)
 * @entry: Entry to increment
 *
 * Thread-safe: No (caller must hold mutex)
 */
static void
increment_entry_count (T tracker, IPEntry *entry)
{
  entry->count++;
  tracker->total_conns++;
}

/**
 * track_unlimited_mode - Track connection in unlimited mode
 * @tracker: IP tracker instance (caller must hold mutex)
 * @ip: IP address string
 *
 * Returns: Always 1 (allowed)
 * Thread-safe: No (caller must hold mutex)
 */
static int
track_unlimited_mode (T tracker, const char *ip)
{
  unsigned bucket;
  IPEntry *entry = find_entry (tracker, ip, &bucket);

  if (entry == NULL)
    entry = create_entry (tracker, ip, bucket);

  if (entry != NULL)
    increment_entry_count (tracker, entry);

  return 1;
}

/**
 * track_new_ip - Track first connection from new IP
 * @tracker: IP tracker instance (caller must hold mutex)
 * @ip: IP address string
 * @bucket: Bucket index
 *
 * Returns: 1 on success, 0 on allocation failure
 * Thread-safe: No (caller must hold mutex)
 */
static int
track_new_ip (T tracker, const char *ip, unsigned bucket)
{
  IPEntry *entry = create_entry (tracker, ip, bucket);
  if (entry == NULL)
    return 0;

  entry->count = 1;
  tracker->total_conns++;
  return 1;
}

/**
 * track_existing_ip - Track additional connection from existing IP
 * @tracker: IP tracker instance (caller must hold mutex)
 * @entry: Existing entry for IP
 *
 * Returns: 1 if under limit, 0 if limit reached
 * Thread-safe: No (caller must hold mutex)
 */
static int
track_existing_ip (T tracker, IPEntry *entry)
{
  if (entry->count < tracker->max_per_ip)
    {
      increment_entry_count (tracker, entry);
      return 1;
    }

  return 0;
}

/**
 * track_limited_mode - Track connection with per-IP limit
 * @tracker: IP tracker instance (caller must hold mutex)
 * @ip: IP address string
 *
 * Returns: 1 if allowed, 0 if limit reached
 * Thread-safe: No (caller must hold mutex)
 */
static int
track_limited_mode (T tracker, const char *ip)
{
  unsigned bucket;
  IPEntry *entry = find_entry (tracker, ip, &bucket);

  if (entry == NULL)
    return track_new_ip (tracker, ip, bucket);

  return track_existing_ip (tracker, entry);
}

/* ============================================================================
 * Internal Helper Functions - Release Operations
 * ============================================================================ */

/**
 * decrement_entry_count - Decrement entry count and total
 * @tracker: IP tracker instance (caller must hold mutex)
 * @entry: Entry to decrement
 *
 * Thread-safe: No (caller must hold mutex)
 */
static void
decrement_entry_count (T tracker, IPEntry *entry)
{
  entry->count--;
  tracker->total_conns--;
}

/**
 * release_connection - Release a tracked connection
 * @tracker: IP tracker instance (caller must hold mutex)
 * @ip: IP address string
 * @entry: Entry for the IP
 * @bucket: Bucket index
 *
 * Thread-safe: No (caller must hold mutex)
 */
static void
release_connection (T tracker, const char *ip, IPEntry *entry, unsigned bucket)
{
  decrement_entry_count (tracker, entry);

  if (entry->count == 0)
    find_and_unlink_zero_entry (tracker, ip, bucket);
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
    {
      SOCKET_ERROR_MSG ("Failed to allocate IP tracker");
      RAISE_IPTRACKER_ERROR (SocketIPTracker_Failed);
    }

  init_tracker_fields (tracker, arena, max_per_ip);

  if (init_tracker_buckets (tracker) != 0)
    {
      cleanup_failed_tracker (tracker);
      RAISE_IPTRACKER_ERROR (SocketIPTracker_Failed);
    }

  if (init_tracker_mutex (tracker) != 0)
    {
      cleanup_failed_tracker (tracker);
      SOCKET_ERROR_FMT ("Failed to initialize IP tracker mutex");
      RAISE_IPTRACKER_ERROR (SocketIPTracker_Failed);
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

  if (ip == NULL || ip[0] == '\0')
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
 */
void
SocketIPTracker_release (T tracker, const char *ip)
{
  unsigned bucket;
  IPEntry *entry;

  assert (tracker != NULL);

  if (ip == NULL || ip[0] == '\0')
    return;

  pthread_mutex_lock (&tracker->mutex);

  entry = find_entry (tracker, ip, &bucket);
  if (entry != NULL && entry->count > 0)
    release_connection (tracker, ip, entry, bucket);

  pthread_mutex_unlock (&tracker->mutex);
}

/**
 * SocketIPTracker_count - Get current connection count for IP
 */
int
SocketIPTracker_count (T tracker, const char *ip)
{
  IPEntry *entry;
  int count = 0;

  assert (tracker != NULL);

  if (ip == NULL || ip[0] == '\0')
    return 0;

  pthread_mutex_lock (&tracker->mutex);

  entry = find_entry (tracker, ip, NULL);
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
