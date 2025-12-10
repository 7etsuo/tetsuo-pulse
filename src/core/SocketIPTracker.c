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

#include "core/SocketConfig.h"
#include "core/SocketCrypto.h"
#include "core/SocketIPTracker.h"
#include "core/SocketUtil.h"
#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define T SocketIPTracker_T

/* ============================================================================
 * Exception Definitions
 * ============================================================================
 */

const Except_T SocketIPTracker_Failed
    = { &SocketIPTracker_Failed, "IP tracker operation failed" };

/* Thread-local exception using centralized macro */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketIPTracker);

/* ============================================================================
 * Internal Structures
 * ============================================================================
 */

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
  size_t max_unique_ips; /**< Maximum unique IPs tracked (0=unlimited) */
  unsigned hash_seed;    /**< Hash salt for DoS resistance */
  size_t total_conns;    /**< Total tracked connections */
  size_t unique_ips;     /**< Number of unique IPs */
  pthread_mutex_t mutex; /**< Thread safety mutex */
  Arena_T arena;         /**< Arena for allocation (NULL if malloc) */
  int initialized;       /**< 1 if mutex initialized */
};

/**
 * validate_ip_format - Validate IP string format using inet_pton
 * @ip: IP address string
 *
 * Returns: true if valid IPv4 or IPv6, false otherwise
 * Thread-safe: Yes (pure function)
 */
static bool
validate_ip_format (const char *ip)
{
  struct in_addr ipv4;
  if (inet_pton (AF_INET, ip, &ipv4) == 1)
    return true;

  struct in6_addr ipv6;
  if (inet_pton (AF_INET6, ip, &ipv6) == 1)
    return true;

  return false;
}

/* ============================================================================
 * Internal Helper Functions - Hash Computation
 * ============================================================================
 */

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
static unsigned salted_djb2 (const char *str, unsigned seed,
                             unsigned table_size);

static unsigned
compute_bucket_index (const T tracker, const char *ip, size_t bucket_count)
{
  assert (tracker != NULL);
  assert (ip != NULL);
  assert (bucket_count > 0);
  return salted_djb2 (ip, tracker->hash_seed, (unsigned)bucket_count);
}

static unsigned
salted_djb2 (const char *str, unsigned seed, unsigned table_size)
{
  unsigned hash = SOCKET_UTIL_DJB2_SEED ^ seed;
  int c;

  while ((c = *str++) != '\0')
    hash = ((hash << 5) + hash) + (unsigned)c;

  return table_size > 0 ? hash % table_size : hash;
}

/* ============================================================================
 * Internal Helper Functions - Entry Lookup
 * ============================================================================
 */

/**
 * search_chain - Search IP in linked list chain with prev tracking
 * @head: Head of the chain to search
 * @ip: IP address string to match
 * @prev_out: Optional output for previous entry (for O(1) unlink)
 *
 * Returns: Matching entry or NULL
 * Thread-safe: No (caller must hold mutex)
 *
 * Performs linear search in chain, tracking previous pointer if requested.
 * Used by find_entry for hash table lookup.
 */
static IPEntry *
search_chain (IPEntry *head, const char *ip, IPEntry **prev_out /* optional */)
{
  IPEntry *prev = NULL;
  IPEntry *entry;

  for (entry = head; entry != NULL; entry = entry->next)
    {
      if (strcmp (entry->ip, ip) == 0)
        {
          if (prev_out != NULL)
            *prev_out = prev;
          return entry;
        }
      prev = entry;
    }

  if (prev_out != NULL)
    *prev_out = NULL;
  return NULL;
}

/**
 * find_entry - Find IP entry with optional previous pointer tracking
 * @tracker: IP tracker instance (caller must hold mutex)
 * @ip: IP address string
 * @bucket_out: Output bucket index (optional, may be NULL)
 * @prev_out: Output previous entry pointer (optional, NULL if not needed or
 * entry at head; pass NULL to skip tracking)
 *
 * Returns: Entry pointer or NULL if not found
 * Thread-safe: No (caller must hold mutex)
 *
 * Computes bucket index and searches chain using search_chain.
 * Supports both simple lookup and prev tracking for O(1) unlinking.
 */
static IPEntry *
find_entry (const T tracker, const char *ip, unsigned *bucket_out,
            IPEntry **prev_out /* optional */)
{
  unsigned idx;

  assert (tracker != NULL);
  assert (ip != NULL);

  idx = compute_bucket_index (tracker, ip, tracker->bucket_count);

  if (bucket_out != NULL)
    *bucket_out = idx;

  return search_chain (tracker->buckets[idx], ip, prev_out);
}
/* find_entry_simple removed - use find_entry(..., NULL) for prev_out */
/* ============================================================================
 * Internal Helper Functions - Generic Allocation/Free
 * ============================================================================
 */

/**
 * tracker_alloc_raw - Allocate memory from arena or heap
 * @tracker: IP tracker instance
 * @size: Number of bytes to allocate
 *
 * Returns: Pointer to allocated memory or NULL on failure
 * Thread-safe: No (caller must hold mutex for arena consistency)
 * Note: Uses __FILE__ and __LINE__ for Arena_alloc debug info
 */
static void *
tracker_alloc_raw (const T tracker, size_t size)
{
  if (tracker->arena != NULL)
    return Arena_alloc (tracker->arena, size, __FILE__, __LINE__);

  return malloc (size);
}

/**
 * tracker_free_raw - Free heap-allocated memory (ignores arena allocations)
 * @tracker: IP tracker instance
 * @ptr: Pointer to free (ignored if arena-based)
 *
 * Thread-safe: No (caller must hold mutex)
 * Note: Arena memory is freed collectively; this only frees malloc'd ptrs
 */
static void
tracker_free_raw (const T tracker, void *ptr)
{
  if (tracker->arena == NULL && ptr != NULL)
    free (ptr);
}

/* ============================================================================
 * Internal Helper Functions - Entry Allocation
 * ============================================================================
 */

/**
 * allocate_entry - Allocate IPEntry from arena or heap
 * @tracker: IP tracker instance
 *
 * Returns: New entry or NULL on allocation failure
 * Thread-safe: No (caller must hold mutex)
 */
/**
 * allocate_entry - Allocate and initialize IPEntry from arena or heap
 * @tracker: Tracker instance (determines arena vs malloc)
 *
 * Returns: Allocated entry or NULL on failure
 * Thread-safe: No (caller must hold mutex)
 */
static IPEntry *
allocate_entry (const T tracker)
{
  return tracker_alloc_raw (tracker, sizeof (IPEntry));
}

/**
 * alloc_and_init_entry - Allocate and initialize IPEntry
 * @tracker: For allocation source (arena/malloc)
 * @ip: IP string to copy
 * @initial_count: Starting count
 *
 * Returns: Initialized entry or NULL on alloc fail
 * Thread-safe: No
 *
 * Copies IP with null termination, sets count, next=NULL.
 */
static IPEntry *
alloc_and_init_entry (const T tracker, const char *ip, int initial_count)
{
  IPEntry *entry = allocate_entry (tracker);
  if (entry == NULL)
    return NULL;

  strncpy (entry->ip, ip, SOCKET_IP_MAX_LEN - 1);
  entry->ip[SOCKET_IP_MAX_LEN - 1] = '\0';
  entry->count = initial_count;
  entry->next = NULL;

  return entry;
}

/**
 * create_and_insert_entry - Insert new entry at bucket head
 * @tracker: IP tracker instance (caller must hold mutex)
 * @ip: IP address string to copy
 * @bucket: Bucket index
 * @initial_count: Initial connection count for entry
 *
 * Returns: New entry or NULL on allocation failure
 * Thread-safe: No (caller must hold mutex)
 *
 * Allocates via alloc_and_init_entry, links into bucket, increments
 * unique_ips.
 */
static IPEntry *
create_and_insert_entry (T tracker, const char *ip, unsigned bucket,
                         int initial_count)
{
  IPEntry *entry;

  assert (tracker != NULL);
  assert (ip != NULL);
  assert (bucket < tracker->bucket_count);

  entry = alloc_and_init_entry (tracker, ip, initial_count);
  if (entry == NULL)
    return NULL;

  entry->next = tracker->buckets[bucket];
  tracker->buckets[bucket] = entry;
  tracker->unique_ips++;

  return entry;
}

/* ============================================================================
 * Internal Helper Functions - Entry Removal
 * ============================================================================
 */

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
  tracker_free_raw (tracker, entry);
}

/* ============================================================================
 * Internal Helper Functions - Bucket Operations
 * ============================================================================
 */

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
  return (IPEntry **)tracker_alloc_raw (tracker, buckets_size);
}

/**
 * free_bucket_chain - Free all entries in a bucket chain
 * @tracker: IP tracker instance (for arena check)
 * @entry: Head of chain (may be NULL)
 *
 * Thread-safe: No (caller must hold mutex)
 */
static void
free_bucket_chain (T tracker, IPEntry *entry)
{
  while (entry != NULL)
    {
      IPEntry *next = entry->next;
      tracker_free_raw (tracker, entry);
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
      free_bucket_chain (tracker, tracker->buckets[i]);
      tracker->buckets[i] = NULL;
    }
}

/* ============================================================================
 * Internal Helper Functions - Tracker Initialization
 * ============================================================================
 */

/**
 * arena_or_malloc - Allocate from arena or standard malloc
 * @arena: Arena (NULL for malloc)
 * @size: Bytes to allocate
 *
 * Returns: Allocated pointer or NULL
 * Thread-safe: Yes
 */
static void *
arena_or_malloc (Arena_T arena, size_t size)
{
  if (arena != NULL)
    return Arena_alloc (arena, size, __FILE__, __LINE__);

  return malloc (size);
}

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
  return (T)arena_or_malloc (arena, sizeof (struct T));
}

/**
 * init_tracker_fields - Initialize tracker fields
 * @tracker: Tracker to initialize (must not be NULL)
 * @arena: Arena for allocation
 * @max_per_ip: Maximum connections per IP (clamped >= 0)
 *
 * Thread-safe: No (called during construction)
 *
 * Clamps negative max_per_ip to 0 (unlimited).
 */
static void
init_tracker_fields (T tracker, Arena_T arena, int max_per_ip)
{
  assert (tracker != NULL);

  memset (tracker, 0, sizeof (*tracker));
  tracker->bucket_count = SOCKET_IP_TRACKER_HASH_SIZE;
  tracker->max_per_ip = max_per_ip;
  if (tracker->max_per_ip < 0)
    tracker->max_per_ip = 0;
  tracker->max_unique_ips = SOCKET_MAX_CONNECTIONS;
  tracker->hash_seed = 0; /* set after mutex init */
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
 * cleanup_failed_tracker - Clean up partially constructed tracker
 * @tracker: Partially initialized tracker
 *
 * Thread-safe: No (called only during failed new())
 *
 * Frees heap allocations (buckets array and tracker struct) if not
 * arena-based. Assumes mutex not yet initialized or already destroyed. Does
 * not touch arena-allocated memory (caller disposes arena).
 */
static void
cleanup_failed_tracker (T tracker)
{
  if (tracker->arena == NULL)
    {
      if (tracker->buckets != NULL)
        {
          /* Free bucket chains if allocated */
          free_all_buckets (tracker);
          tracker_free_raw (tracker, tracker->buckets);
        }
      tracker_free_raw (tracker, tracker);
    }
}

/* ============================================================================
 * Internal Helper Functions - Track Operations
 * ============================================================================
 */

/**
 * is_unlimited_mode - Check if tracker is in unlimited mode
 * @tracker: Tracker instance
 *
 * Returns: true if max_per_ip <= 0 (unlimited tracking)
 * Thread-safe: No (caller must hold mutex)
 */
static bool
is_unlimited_mode (const T tracker)
{
  return tracker->max_per_ip <= 0;
}

/**
 * create_new_entry_and_track - Create and insert new IP entry with count=1
 * @tracker: Tracker instance (caller must hold mutex)
 * @ip: IP address
 * @bucket: Computed bucket index
 *
 * Returns: 1 if tracked (allowed), 0 if alloc failed in limited mode
 * Thread-safe: No (caller must hold mutex)
 *
 * Handles allocation failure gracefully: allows in unlimited mode.
 * Updates total_conns on success.
 */
static int
create_new_entry_and_track (T tracker, const char *ip, unsigned bucket)
{
  if (tracker->max_unique_ips > 0
      && tracker->unique_ips >= tracker->max_unique_ips)
    {
      SOCKET_LOG_WARN_MSG (
          "IP tracker unique limit reached: skipping new IP %s", ip);
      return 0;
    }

  IPEntry *entry = create_and_insert_entry (tracker, ip, bucket, 1);
  if (entry == NULL)
    {
      return is_unlimited_mode (tracker) ? 1 : 0;
    }
  tracker->total_conns++;
  return 1;
}

/**
 * increment_existing_entry - Increment count for existing IP entry
 * @tracker: Tracker instance (caller must hold mutex)
 * @entry: Existing entry
 *
 * Returns: 1 if incremented (under limit), 0 if rejected
 * Thread-safe: No (caller must hold mutex)
 *
 * Checks limit before incrementing. Updates total_conns.
 */
static int
increment_existing_entry (T tracker, IPEntry *entry)
{
  if (entry->count >= INT_MAX - 1)
    {
      SOCKET_LOG_ERROR_MSG ("IP tracker count overflow for IP %s", entry->ip);
      return 0;
    }

  size_t attempted = (size_t)entry->count + 1;
  if (is_unlimited_mode (tracker) || attempted <= (size_t)tracker->max_per_ip)
    {
      entry->count++;
      tracker->total_conns++;
      return 1;
    }
  return 0;
}

/**
 * track_internal - Track connection for IP address
 * @tracker: IP tracker instance (caller must hold mutex)
 * @ip: IP address string
 *
 * Returns: 1 if allowed/tracked, 0 if rejected (limit reached)
 * Thread-safe: No (caller must hold mutex)
 *
 * Delegates to create_new_entry_and_track or increment_existing_entry.
 * Handles new vs existing IP logic.
 */
static int
track_internal (T tracker, const char *ip)
{
  unsigned bucket;
  IPEntry *entry = find_entry (tracker, ip, &bucket, NULL);

  if (entry == NULL)
    {
      return create_new_entry_and_track (tracker, ip, bucket);
    }
  return increment_existing_entry (tracker, entry);
}

/* ============================================================================
 * Public API Implementation
 * ============================================================================
 */

/**
 * SocketIPTracker_new - Create new IP tracker (implementation)
 * @arena: Memory arena (NULL for malloc/free)
 * @max_per_ip: Initial max connections per IP (clamped >=0, 0=unlimited)
 *
 * Returns: New tracker instance
 * Raises: SocketIPTracker_Failed on alloc/mutex failure
 * Thread-safe: Yes (returns unique instance)
 *
 * Initializes hash table, mutex, clamps max_per_ip.
 * Cleanup on partial failure via cleanup_failed_tracker.
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

  /* Generate secure hash seed for collision resistance */
  {
    unsigned char seed_bytes[sizeof (unsigned)];
    ssize_t got_bytes
        = SocketCrypto_random_bytes (seed_bytes, sizeof (seed_bytes));
    if (got_bytes == (ssize_t)sizeof (seed_bytes))
      {
        memcpy (&tracker->hash_seed, seed_bytes, sizeof (tracker->hash_seed));
      }
    else
      {
        /* Fallback: time + PID */
        tracker->hash_seed = (unsigned)time (NULL) ^ (unsigned)getpid ();
        SOCKET_LOG_WARN_MSG (
            "SocketIPTracker: fallback hash seed (crypto random failed: %zd)",
            got_bytes);
      }
  }

  return tracker;
}

/**
 * SocketIPTracker_free - Free IP tracker instance (implementation)
 * @tracker: Pointer to tracker instance (set to NULL on success)
 *
 * Thread-safe: Yes (but avoid concurrent access during free)
 *
 * - Destroys internal mutex if initialized
 * - Frees all heap-allocated buckets and entries if not using arena
 * - Arena-based trackers defer free to Arena_dispose (no-op here except NULL)
 * - Safe to call on NULL or already-freed tracker
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
      tracker_free_raw (t, t->buckets);
      tracker_free_raw (t, t);
    }

  *tracker = NULL;
}

/**
 * SocketIPTracker_track - Track new connection (implementation)
 * @tracker: IP tracker instance
 * @ip: Client IP address string
 *
 * Returns: 1 if allowed and tracked, 0 if rejected (limit reached)
 * Thread-safe: Yes
 *
 * Validates IP string before locking. Delegates to track_internal.
 * Invalid/empty IP always allowed (no tracking).
 */
int
SocketIPTracker_track (T tracker, const char *ip)
{
  int result;

  assert (tracker != NULL);

  if (!SOCKET_VALID_IP_STRING (ip))
    return 1;

  size_t ip_len = strlen (ip);
  if (ip_len >= (size_t)SOCKET_IP_MAX_LEN || !validate_ip_format (ip))
    {
      SOCKET_LOG_WARN_MSG ("Invalid IP for tracking: %s (len=%zu)", ip,
                           ip_len);
      return 0; /* Reject invalid IPs */
    }

  pthread_mutex_lock (&tracker->mutex);

  result = track_internal (tracker, ip);

  pthread_mutex_unlock (&tracker->mutex);
  return result;
}

/**
 * SocketIPTracker_release - Release connection count for IP (implementation)
 * @tracker: IP tracker instance
 * @ip: Client IP address string
 *
 * Thread-safe: Yes
 *
 * Decrements count if >0, updates total_conns. Removes entry if count==0.
 * Invalid IP is no-op. Uses prev pointer for O(1) unlink.
 * Safe if IP not tracked (no-op).
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

  size_t ip_len = strlen (ip);
  if (ip_len >= (size_t)SOCKET_IP_MAX_LEN || !validate_ip_format (ip))
    {
      SOCKET_LOG_WARN_MSG ("Invalid IP for release: %s", ip);
      return;
    }

  pthread_mutex_lock (&tracker->mutex);

  entry = find_entry (tracker, ip, &bucket, &prev);

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
 * SocketIPTracker_count - Get connection count for IP (implementation)
 * @tracker: IP tracker instance
 * @ip: IP address string
 *
 * Returns: Current count (0 if not tracked or invalid IP)
 * Thread-safe: Yes
 *
 * Snapshot under mutex lock. Invalid IP returns 0.
 */
int
SocketIPTracker_count (T tracker, const char *ip)
{
  const IPEntry *entry;
  int count = 0;

  assert (tracker != NULL);

  if (!SOCKET_VALID_IP_STRING (ip))
    return 0;

  size_t ip_len = strlen (ip);
  if (ip_len >= (size_t)SOCKET_IP_MAX_LEN || !validate_ip_format (ip))
    return 0;

  pthread_mutex_lock (&tracker->mutex);

  entry = find_entry (tracker, ip, NULL, NULL);
  if (entry != NULL)
    count = entry->count;

  pthread_mutex_unlock (&tracker->mutex);
  return count;
}

/**
 * SocketIPTracker_setmax - Set maximum connections per IP (implementation)
 * @tracker: IP tracker instance
 * @max_per_ip: New maximum (clamped to >=0, 0=unlimited)
 *
 * Thread-safe: Yes
 *
 * Clamps negative values to 0. Does not retroactively close excess
 * connections. Future track() calls will enforce the new limit.
 */
void
SocketIPTracker_setmax (T tracker, int max_per_ip)
{
  assert (tracker != NULL);

  pthread_mutex_lock (&tracker->mutex);
  tracker->max_per_ip = (max_per_ip < 0 ? 0 : max_per_ip);
  pthread_mutex_unlock (&tracker->mutex);
}

/**
 * SocketIPTracker_getmax - Get configured max per IP (implementation)
 * @tracker: IP tracker instance
 *
 * Returns: Current max_per_ip (>=0, 0=unlimited)
 * Thread-safe: Yes
 *
 * Atomic snapshot of configuration.
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
 * SocketIPTracker_setmaxunique - Set maximum unique IPs tracked
 * @tracker: IP tracker instance
 * @max_unique: New limit (0=unlimited)
 *
 * Thread-safe: Yes
 *
 * Limits total entries to prevent memory exhaustion.
 * Existing entries not affected; new unique IPs rejected.
 */
void
SocketIPTracker_setmaxunique (T tracker, size_t max_unique)
{
  assert (tracker != NULL);

  pthread_mutex_lock (&tracker->mutex);
  tracker->max_unique_ips = max_unique;
  pthread_mutex_unlock (&tracker->mutex);
}

/**
 * SocketIPTracker_getmaxunique - Get maximum unique IPs limit
 * @tracker: IP tracker instance
 *
 * Returns: Current limit (0=unlimited)
 * Thread-safe: Yes
 */
size_t
SocketIPTracker_getmaxunique (T tracker)
{
  size_t maxu;

  assert (tracker != NULL);

  pthread_mutex_lock (&tracker->mutex);
  maxu = tracker->max_unique_ips;
  pthread_mutex_unlock (&tracker->mutex);

  return maxu;
}

/**
 * SocketIPTracker_total - Get total active connections (implementation)
 * @tracker: IP tracker instance
 *
 * Returns: Sum of all IP connection counts
 * Thread-safe: Yes
 *
 * Atomic snapshot of total tracked connections.
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
 * SocketIPTracker_unique_ips - Get count of unique tracked IPs
 * (implementation)
 * @tracker: IP tracker instance
 *
 * Returns: Number of IPs with count > 0
 * Thread-safe: Yes
 *
 * Atomic snapshot. Updates on entry creation/removal when count==0.
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
 * SocketIPTracker_clear - Reset tracker to empty state (implementation)
 * @tracker: IP tracker instance
 *
 * Thread-safe: Yes
 *
 * Clears all entries: frees heap entries or zeros arena buckets.
 * Resets counters to 0. Does not change config (max_per_ip).
 */
void
SocketIPTracker_clear (T tracker)
{
  assert (tracker != NULL);

  pthread_mutex_lock (&tracker->mutex);

  if (tracker->arena == NULL)
    free_all_buckets (tracker);
  else
    memset (tracker->buckets, 0, tracker->bucket_count * sizeof (IPEntry *));

  tracker->total_conns = 0;
  tracker->unique_ips = 0;

  pthread_mutex_unlock (&tracker->mutex);
}

#undef T
