/**
 * SocketIPTracker.c - Per-IP Connection Tracking Implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Hash table-based IP connection tracking with:
 * - Chained collision handling
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
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Configuration
 * ============================================================================ */

/* Use existing hash table size from config, or define default */
#ifndef SOCKET_IP_TRACKER_HASH_SIZE
#define SOCKET_IP_TRACKER_HASH_SIZE 1021
#endif

/* Maximum IP address string length (IPv6 with scope) */
#define IP_MAX_LEN 64

/* ============================================================================
 * Exception Definitions
 * ============================================================================ */

const Except_T SocketIPTracker_Failed = { &SocketIPTracker_Failed, "IP tracker operation failed" };

/* Thread-local exception for detailed error messages */
#ifdef _WIN32
static __declspec (thread) Except_T SocketIPTracker_DetailedException;
#else
static __thread Except_T SocketIPTracker_DetailedException;
#endif

#define RAISE_IPTRACKER_ERROR(exception)                                       \
  do                                                                           \
    {                                                                          \
      SocketIPTracker_DetailedException = (exception);                         \
      SocketIPTracker_DetailedException.reason = socket_error_buf;             \
      RAISE (SocketIPTracker_DetailedException);                               \
    }                                                                          \
  while (0)

/* ============================================================================
 * Internal Structures
 * ============================================================================ */

/**
 * IP entry in hash table
 */
typedef struct IPEntry
{
  char ip[IP_MAX_LEN];    /**< IP address string */
  int count;              /**< Connection count */
  struct IPEntry *next;   /**< Next in hash chain */
} IPEntry;

/**
 * IP tracker structure
 */
struct SocketIPTracker_T
{
  IPEntry **buckets;       /**< Hash table buckets */
  size_t bucket_count;     /**< Number of buckets */
  int max_per_ip;          /**< Maximum connections per IP */
  size_t total_conns;      /**< Total tracked connections */
  size_t unique_ips;       /**< Number of unique IPs */
  pthread_mutex_t mutex;   /**< Thread safety mutex */
  Arena_T arena;           /**< Arena for allocation (NULL if malloc) */
  int initialized;         /**< 1 if mutex initialized */
};

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

/**
 * ip_hash - Compute hash for IP address string
 * @ip: IP address string
 * @bucket_count: Number of buckets
 *
 * Returns: Hash bucket index
 *
 * Uses DJB2 hash algorithm.
 */
static unsigned
ip_hash (const char *ip, size_t bucket_count)
{
  unsigned hash = 5381;
  int c;

  while ((c = *ip++))
    {
      hash = ((hash << 5) + hash) + (unsigned)c; /* hash * 33 + c */
    }

  return hash % bucket_count;
}

/**
 * find_entry - Find IP entry in hash table
 * @tracker: IP tracker instance (caller must hold mutex)
 * @ip: IP address string
 * @bucket: Output bucket index (optional)
 *
 * Returns: Entry pointer or NULL if not found
 */
static IPEntry *
find_entry (SocketIPTracker_T tracker, const char *ip, unsigned *bucket)
{
  unsigned idx;
  IPEntry *entry;

  idx = ip_hash (ip, tracker->bucket_count);
  if (bucket)
    {
      *bucket = idx;
    }

  entry = tracker->buckets[idx];
  while (entry)
    {
      if (strcmp (entry->ip, ip) == 0)
        {
          return entry;
        }
      entry = entry->next;
    }

  return NULL;
}

/**
 * create_entry - Create new IP entry
 * @tracker: IP tracker instance (caller must hold mutex)
 * @ip: IP address string
 * @bucket: Bucket index to insert into
 *
 * Returns: New entry or NULL on allocation failure
 */
static IPEntry *
create_entry (SocketIPTracker_T tracker, const char *ip, unsigned bucket)
{
  IPEntry *entry;

  /* Allocate entry */
  if (tracker->arena)
    {
      entry = Arena_alloc (tracker->arena, sizeof (*entry), __FILE__, __LINE__);
    }
  else
    {
      entry = malloc (sizeof (*entry));
    }

  if (!entry)
    {
      return NULL;
    }

  /* Initialize entry */
  strncpy (entry->ip, ip, IP_MAX_LEN - 1);
  entry->ip[IP_MAX_LEN - 1] = '\0';
  entry->count = 0;

  /* Insert at head of bucket chain */
  entry->next = tracker->buckets[bucket];
  tracker->buckets[bucket] = entry;
  tracker->unique_ips++;

  return entry;
}

/**
 * remove_entry - Remove IP entry from hash table
 * @tracker: IP tracker instance (caller must hold mutex)
 * @ip: IP address string
 * @bucket: Bucket index
 *
 * Note: Only removes if count is zero.
 */
static void
remove_entry (SocketIPTracker_T tracker, const char *ip, unsigned bucket)
{
  IPEntry *entry;
  IPEntry *prev = NULL;

  entry = tracker->buckets[bucket];
  while (entry)
    {
      if (strcmp (entry->ip, ip) == 0)
        {
          /* Only remove if count is zero */
          if (entry->count > 0)
            {
              return;
            }

          /* Unlink from chain */
          if (prev)
            {
              prev->next = entry->next;
            }
          else
            {
              tracker->buckets[bucket] = entry->next;
            }

          /* Free if not arena-allocated */
          if (!tracker->arena)
            {
              free (entry);
            }

          tracker->unique_ips--;
          return;
        }
      prev = entry;
      entry = entry->next;
    }
}

/* ============================================================================
 * Public API Implementation
 * ============================================================================ */

/**
 * SocketIPTracker_new - Create a new IP connection tracker
 */
SocketIPTracker_T
SocketIPTracker_new (Arena_T arena, int max_per_ip)
{
  SocketIPTracker_T tracker;
  size_t buckets_size;

  /* Allocate structure */
  if (arena)
    {
      tracker = Arena_alloc (arena, sizeof (*tracker), __FILE__, __LINE__);
    }
  else
    {
      tracker = malloc (sizeof (*tracker));
    }

  if (!tracker)
    {
      SOCKET_ERROR_MSG ("Failed to allocate IP tracker");
      RAISE_IPTRACKER_ERROR (SocketIPTracker_Failed);
    }

  /* Initialize structure */
  memset (tracker, 0, sizeof (*tracker));
  tracker->bucket_count = SOCKET_IP_TRACKER_HASH_SIZE;
  tracker->max_per_ip = max_per_ip;
  tracker->arena = arena;
  tracker->initialized = 0;

  /* Allocate hash table buckets */
  buckets_size = tracker->bucket_count * sizeof (IPEntry *);
  if (arena)
    {
      tracker->buckets = Arena_alloc (arena, buckets_size, __FILE__, __LINE__);
    }
  else
    {
      tracker->buckets = malloc (buckets_size);
    }

  if (!tracker->buckets)
    {
      if (!arena)
        {
          free (tracker);
        }
      SOCKET_ERROR_MSG ("Failed to allocate IP tracker hash table");
      RAISE_IPTRACKER_ERROR (SocketIPTracker_Failed);
    }

  memset (tracker->buckets, 0, buckets_size);

  /* Initialize mutex */
  if (pthread_mutex_init (&tracker->mutex, NULL) != 0)
    {
      if (!arena)
        {
          free (tracker->buckets);
          free (tracker);
        }
      SOCKET_ERROR_FMT ("Failed to initialize IP tracker mutex");
      RAISE_IPTRACKER_ERROR (SocketIPTracker_Failed);
    }

  tracker->initialized = 1;
  return tracker;
}

/**
 * SocketIPTracker_free - Free an IP tracker
 */
void
SocketIPTracker_free (SocketIPTracker_T *tracker)
{
  SocketIPTracker_T t;
  size_t i;
  IPEntry *entry;
  IPEntry *next;

  if (!tracker || !*tracker)
    {
      return;
    }

  t = *tracker;

  /* Destroy mutex */
  if (t->initialized)
    {
      pthread_mutex_destroy (&t->mutex);
    }

  /* Free entries if not arena-allocated */
  if (!t->arena)
    {
      for (i = 0; i < t->bucket_count; i++)
        {
          entry = t->buckets[i];
          while (entry)
            {
              next = entry->next;
              free (entry);
              entry = next;
            }
        }
      free (t->buckets);
      free (t);
    }

  *tracker = NULL;
}

/**
 * SocketIPTracker_track - Track a new connection from IP
 */
int
SocketIPTracker_track (SocketIPTracker_T tracker, const char *ip)
{
  unsigned bucket;
  IPEntry *entry;
  int result = 1;

  assert (tracker);

  /* NULL or empty IP - always allow */
  if (!ip || !ip[0])
    {
      return 1;
    }

  pthread_mutex_lock (&tracker->mutex);

  /* Unlimited mode - always allow but still track */
  if (tracker->max_per_ip == 0)
    {
      entry = find_entry (tracker, ip, &bucket);
      if (!entry)
        {
          entry = create_entry (tracker, ip, bucket);
        }
      if (entry)
        {
          entry->count++;
          tracker->total_conns++;
        }
      pthread_mutex_unlock (&tracker->mutex);
      return 1;
    }

  /* Find or create entry */
  entry = find_entry (tracker, ip, &bucket);

  if (!entry)
    {
      /* New IP - create entry if under limit */
      if (tracker->max_per_ip > 0)
        {
          entry = create_entry (tracker, ip, bucket);
          if (entry)
            {
              entry->count = 1;
              tracker->total_conns++;
            }
          else
            {
              result = 0; /* Allocation failed */
            }
        }
    }
  else
    {
      /* Existing IP - check limit */
      if (entry->count < tracker->max_per_ip)
        {
          entry->count++;
          tracker->total_conns++;
        }
      else
        {
          result = 0; /* Limit reached */
        }
    }

  pthread_mutex_unlock (&tracker->mutex);
  return result;
}

/**
 * SocketIPTracker_release - Release a connection from IP
 */
void
SocketIPTracker_release (SocketIPTracker_T tracker, const char *ip)
{
  unsigned bucket;
  IPEntry *entry;

  assert (tracker);

  /* NULL or empty IP - nothing to release */
  if (!ip || !ip[0])
    {
      return;
    }

  pthread_mutex_lock (&tracker->mutex);

  entry = find_entry (tracker, ip, &bucket);
  if (entry && entry->count > 0)
    {
      entry->count--;
      tracker->total_conns--;

      /* Remove entry if count reaches zero */
      if (entry->count == 0)
        {
          remove_entry (tracker, ip, bucket);
        }
    }

  pthread_mutex_unlock (&tracker->mutex);
}

/**
 * SocketIPTracker_count - Get current connection count for IP
 */
int
SocketIPTracker_count (SocketIPTracker_T tracker, const char *ip)
{
  IPEntry *entry;
  int count = 0;

  assert (tracker);

  if (!ip || !ip[0])
    {
      return 0;
    }

  pthread_mutex_lock (&tracker->mutex);

  entry = find_entry (tracker, ip, NULL);
  if (entry)
    {
      count = entry->count;
    }

  pthread_mutex_unlock (&tracker->mutex);
  return count;
}

/**
 * SocketIPTracker_setmax - Set maximum connections per IP
 */
void
SocketIPTracker_setmax (SocketIPTracker_T tracker, int max_per_ip)
{
  assert (tracker);

  pthread_mutex_lock (&tracker->mutex);
  tracker->max_per_ip = max_per_ip;
  pthread_mutex_unlock (&tracker->mutex);
}

/**
 * SocketIPTracker_getmax - Get maximum connections per IP
 */
int
SocketIPTracker_getmax (SocketIPTracker_T tracker)
{
  int max;

  assert (tracker);

  pthread_mutex_lock (&tracker->mutex);
  max = tracker->max_per_ip;
  pthread_mutex_unlock (&tracker->mutex);

  return max;
}

/**
 * SocketIPTracker_total - Get total tracked connections
 */
size_t
SocketIPTracker_total (SocketIPTracker_T tracker)
{
  size_t total;

  assert (tracker);

  pthread_mutex_lock (&tracker->mutex);
  total = tracker->total_conns;
  pthread_mutex_unlock (&tracker->mutex);

  return total;
}

/**
 * SocketIPTracker_unique_ips - Get number of unique IPs being tracked
 */
size_t
SocketIPTracker_unique_ips (SocketIPTracker_T tracker)
{
  size_t unique;

  assert (tracker);

  pthread_mutex_lock (&tracker->mutex);
  unique = tracker->unique_ips;
  pthread_mutex_unlock (&tracker->mutex);

  return unique;
}

/**
 * SocketIPTracker_clear - Clear all tracked connections
 */
void
SocketIPTracker_clear (SocketIPTracker_T tracker)
{
  size_t i;
  IPEntry *entry;
  IPEntry *next;

  assert (tracker);

  pthread_mutex_lock (&tracker->mutex);

  /* Free all entries if not arena-allocated */
  if (!tracker->arena)
    {
      for (i = 0; i < tracker->bucket_count; i++)
        {
          entry = tracker->buckets[i];
          while (entry)
            {
              next = entry->next;
              free (entry);
              entry = next;
            }
          tracker->buckets[i] = NULL;
        }
    }
  else
    {
      /* Just clear pointers - arena will free memory */
      memset (tracker->buckets, 0,
              tracker->bucket_count * sizeof (IPEntry *));
    }

  tracker->total_conns = 0;
  tracker->unique_ips = 0;

  pthread_mutex_unlock (&tracker->mutex);
}

