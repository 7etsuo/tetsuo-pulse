/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* Per-IP connection tracking with hash table and thread-safe operations */

#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Platform-specific secure random sources */
#ifdef __linux__
#include <sys/syscall.h>
#endif

#include "core/Except.h"
#include "core/HashTable.h"
#include "core/SocketConfig.h"
#include "core/SocketCrypto.h"
#include "core/SocketIPTracker.h"
#include "core/SocketUtil.h"

#define T SocketIPTracker_T

const Except_T SocketIPTracker_Failed
    = { &SocketIPTracker_Failed, "IP tracker operation failed" };

SOCKET_DECLARE_MODULE_EXCEPTION (SocketIPTracker);

typedef struct IPEntry
{
  char ip[SOCKET_IP_MAX_LEN];
  int count;
  struct IPEntry *next;
} IPEntry;

struct T
{
  HashTable_T table;
  int max_per_ip;
  size_t max_unique_ips;
  size_t total_conns;
  size_t unique_ips;
  pthread_mutex_t mutex;
  Arena_T arena;
  int initialized;
};

#define TRACKER_LOCK(t)                                                       \
  SOCKET_MUTEX_LOCK_OR_RAISE (&(t)->mutex, SocketIPTracker,                  \
                              SocketIPTracker_Failed)
#define TRACKER_UNLOCK(t) SOCKET_MUTEX_UNLOCK (&(t)->mutex)
#define TRACKER_READ_FIELD(t, field, var)                                     \
  do                                                                          \
    {                                                                         \
      TRACKER_LOCK (t);                                                       \
      var = (t)->field;                                                       \
      TRACKER_UNLOCK (t);                                                     \
    }                                                                         \
  while (0)
#define TRACKER_WRITE_FIELD(t, field, val)                                    \
  do                                                                          \
    {                                                                         \
      TRACKER_LOCK (t);                                                       \
      (t)->field = (val);                                                     \
      TRACKER_UNLOCK (t);                                                     \
    }                                                                         \
  while (0)

static inline int
clamp_max_per_ip (int val)
{
  return val < 0 ? 0 : val;
}

typedef enum
{
  IP_VALID,
  IP_BASIC_INVALID,
  IP_ADVANCED_INVALID
} IPValidationResult;

/* Validates IP using inet_pton for IPv4/IPv6, logs if caller provided */
static IPValidationResult
validate_ip (const char *ip, const char *caller)
{
  if (!SOCKET_VALID_IP_STRING (ip))
    return IP_BASIC_INVALID;

  size_t ip_len = strlen (ip);
  if (ip_len >= (size_t)SOCKET_IP_MAX_LEN)
    {
      if (caller != NULL)
        SOCKET_LOG_WARN_MSG ("Invalid IP for %s: %s (len=%zu)", caller, ip,
                             ip_len);
      return IP_ADVANCED_INVALID;
    }

  struct in_addr ipv4;
  if (inet_pton (AF_INET, ip, &ipv4) == 1)
    return IP_VALID;

  struct in6_addr ipv6;
  if (inet_pton (AF_INET6, ip, &ipv6) == 1)
    return IP_VALID;

  if (caller != NULL)
    SOCKET_LOG_WARN_MSG ("Invalid IP format for %s: %s (len=%zu)", caller, ip,
                         ip_len);
  return IP_ADVANCED_INVALID;
}

/* Uses DJB2 string hash with seed for DoS resistance */
static unsigned
iptracker_hash (const void *key, unsigned seed, unsigned table_size)
{
  const char *str = (const char *)key;
  unsigned str_hash = socket_util_hash_djb2 (str, table_size);

  if (table_size == 0)
    return str_hash;

  return socket_util_hash_uint_seeded (str_hash, table_size, (uint32_t)seed);
}

static int
iptracker_compare (const void *entry, const void *key)
{
  const IPEntry *e = (const IPEntry *)entry;
  return strcmp (e->ip, (const char *)key);
}

static void **
iptracker_next_ptr (void *entry)
{
  IPEntry *e = (IPEntry *)entry;
  return (void **)&e->next;
}

/* Caller must hold mutex */
static IPEntry *
find_entry (const T tracker, const char *ip, IPEntry **prev_out)
{
  assert (tracker != NULL);
  assert (ip != NULL);

  return (IPEntry *)HashTable_find (tracker->table, ip, (void **)prev_out);
}

static void *
tracker_alloc_raw (const T tracker, size_t size)
{
  if (tracker->arena != NULL)
    return Arena_alloc (tracker->arena, size, __FILE__, __LINE__);

  return malloc (size);
}

/* Arena memory freed collectively; only frees malloc'd pointers */
static void
tracker_free_raw (const T tracker, void *ptr)
{
  if (tracker->arena == NULL && ptr != NULL)
    free (ptr);
}

static IPEntry *
allocate_entry (const T tracker)
{
  return tracker_alloc_raw (tracker, sizeof (IPEntry));
}

static IPEntry *
alloc_and_init_entry (const T tracker, const char *ip, int initial_count)
{
  IPEntry *entry = allocate_entry (tracker);
  if (entry == NULL)
    return NULL;

  socket_util_safe_copy_ip (entry->ip, ip, sizeof (entry->ip));
  entry->count = initial_count;
  entry->next = NULL;

  return entry;
}

/* Caller must hold mutex */
static IPEntry *
create_and_insert_entry (T tracker, const char *ip, int initial_count)
{
  IPEntry *entry;

  assert (tracker != NULL);
  assert (ip != NULL);

  entry = alloc_and_init_entry (tracker, ip, initial_count);
  if (entry == NULL)
    return NULL;

  HashTable_insert (tracker->table, entry, entry->ip);
  tracker->unique_ips++;

  return entry;
}

/* O(1) removal with prev pointer, caller must hold mutex */
static void
unlink_entry (T tracker, IPEntry *entry, IPEntry *prev)
{
  assert (tracker != NULL);
  assert (entry != NULL);

  HashTable_remove (tracker->table, entry, prev, entry->ip);
  tracker->unique_ips--;

  tracker_free_raw (tracker, entry);
}

static int
free_entry_callback (void *entry, void *context)
{
  T tracker = (T)context;
  tracker_free_raw (tracker, entry);
  return 0;
}

static void
free_all_entries (T tracker)
{
  if (tracker->arena == NULL && tracker->table != NULL)
    HashTable_foreach (tracker->table, free_entry_callback, tracker);
}

static T
allocate_tracker (Arena_T arena)
{
  if (arena != NULL)
    return (T)Arena_alloc (arena, sizeof (struct T), __FILE__, __LINE__);

  return (T)malloc (sizeof (struct T));
}

static void
init_tracker_fields (T tracker, Arena_T arena, int max_per_ip)
{
  assert (tracker != NULL);

  memset (tracker, 0, sizeof (*tracker));
  tracker->max_per_ip = clamp_max_per_ip (max_per_ip);
  tracker->max_unique_ips = SOCKET_MAX_CONNECTIONS;
  tracker->arena = arena;
  tracker->initialized = SOCKET_MUTEX_UNINITIALIZED;
}

/* Try OpenSSL/LibreSSL RAND_bytes for cryptographically secure randomness */
static int
try_openssl_random (unsigned char *seed_bytes, size_t size)
{
  return SocketCrypto_random_bytes (seed_bytes, size);
}

/* Try getrandom() syscall on Linux (kernel 3.17+) */
static int
try_getrandom (unsigned char *seed_bytes, size_t size)
{
#ifdef __linux__
#ifndef SYS_getrandom
#define SYS_getrandom 318
#endif
#ifndef GRND_NONBLOCK
#define GRND_NONBLOCK 0x0001
#endif
  ssize_t n = syscall (SYS_getrandom, seed_bytes, size, GRND_NONBLOCK);
  return (n == (ssize_t)size) ? 0 : -1;
#else
  (void)seed_bytes;
  (void)size;
  return -1;
#endif
}

/* Try getentropy() on BSD/macOS systems */
static int
try_getentropy (unsigned char *seed_bytes, size_t size)
{
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
  return getentropy (seed_bytes, size);
#else
  (void)seed_bytes;
  (void)size;
  return -1;
#endif
}

/* Last resort weak fallback using time and PID */
static unsigned
get_weak_fallback_seed (void)
{
  return (unsigned)time (NULL) ^ (unsigned)getpid ();
}

/* Generate secure random seed with fallback hierarchy for DoS resistance */
static unsigned
generate_hash_seed (void)
{
  unsigned char seed_bytes[sizeof (unsigned)];
  unsigned seed;
  int result;

  /* Try OpenSSL/LibreSSL first */
  result = try_openssl_random (seed_bytes, sizeof (seed_bytes));
  if (result == 0)
    {
      memcpy (&seed, seed_bytes, sizeof (seed));
      return seed;
    }

  /* Try getrandom() on Linux */
  if (try_getrandom (seed_bytes, sizeof (seed_bytes)) == 0)
    {
      memcpy (&seed, seed_bytes, sizeof (seed));
      SOCKET_LOG_WARN_MSG (
          "SocketIPTracker: using getrandom fallback (crypto random failed: "
          "%d)",
          result);
      return seed;
    }

  /* Try getentropy() on BSD/macOS */
  if (try_getentropy (seed_bytes, sizeof (seed_bytes)) == 0)
    {
      memcpy (&seed, seed_bytes, sizeof (seed));
      SOCKET_LOG_WARN_MSG (
          "SocketIPTracker: using getentropy fallback (crypto random failed: "
          "%d)",
          result);
      return seed;
    }

  /* Last resort - weak but logged heavily */
  seed = get_weak_fallback_seed ();
  SOCKET_LOG_ERROR_MSG (
      "SocketIPTracker: CRITICAL - all secure random sources failed (code: "
      "%d), using weak fallback",
      result);
  SOCKET_LOG_ERROR_MSG (
      "SocketIPTracker: hash DoS protection may be compromised - investigate "
      "random source failure");

  return seed;
}

static int
init_tracker_table (T tracker)
{
  HashTable_Config config = { .bucket_count = SOCKET_IP_TRACKER_HASH_SIZE,
                              .hash_seed = generate_hash_seed (),
                              .hash = iptracker_hash,
                              .compare = iptracker_compare,
                              .next_ptr = iptracker_next_ptr };

  TRY { tracker->table = HashTable_new (tracker->arena, &config); }
  EXCEPT (HashTable_Failed)
  {
    SOCKET_ERROR_MSG ("Failed to allocate IP tracker hash table");
    return -1;
  }
  END_TRY;

  return 0;
}

static int
init_tracker_mutex (T tracker)
{
  assert (tracker != NULL);

  if (pthread_mutex_init (&tracker->mutex, NULL) != 0)
    return -1;

  tracker->initialized = SOCKET_MUTEX_INITIALIZED;
  return 0;
}

/* Clean up partially constructed tracker, only frees heap allocations */
static void
cleanup_failed_tracker (T tracker)
{
  if (tracker->arena == NULL)
    {
      if (tracker->table != NULL)
        {
          free_all_entries (tracker);
          HashTable_free (&tracker->table);
        }
      tracker_free_raw (tracker, tracker);
    }
}

static bool
is_unlimited_mode (const T tracker)
{
  return tracker->max_per_ip <= 0;
}

/* Handles allocation failure: allows in unlimited mode, caller must hold mutex
 */
static int
create_new_entry_and_track (T tracker, const char *ip)
{
  if (tracker->max_unique_ips > 0
      && tracker->unique_ips >= tracker->max_unique_ips)
    {
      SOCKET_LOG_WARN_MSG (
          "IP tracker unique limit reached: skipping new IP %s", ip);
      return 0;
    }

  IPEntry *entry = create_and_insert_entry (tracker, ip, 1);
  if (entry == NULL)
    {
      return is_unlimited_mode (tracker) ? 1 : 0;
    }
  tracker->total_conns++;
  return 1;
}

/* Caller must hold mutex */
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

/* Caller must hold mutex */
static int
track_internal (T tracker, const char *ip)
{
  IPEntry *entry = find_entry (tracker, ip, NULL);

  if (entry == NULL)
    {
      return create_new_entry_and_track (tracker, ip);
    }
  return increment_existing_entry (tracker, entry);
}

T
SocketIPTracker_new (Arena_T arena, int max_per_ip)
{
  T tracker = allocate_tracker (arena);

  if (tracker == NULL)
    SOCKET_RAISE_MSG (SocketIPTracker, SocketIPTracker_Failed,
                      "Failed to allocate IP tracker");

  init_tracker_fields (tracker, arena, max_per_ip);

  if (init_tracker_table (tracker) != 0)
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

void
SocketIPTracker_free (T *tracker)
{
  T t;

  if (tracker == NULL || *tracker == NULL)
    return;

  t = *tracker;

  if (t->initialized == SOCKET_MUTEX_INITIALIZED)
    pthread_mutex_destroy (&t->mutex);

  if (t->arena == NULL)
    {
      free_all_entries (t);
      HashTable_free (&t->table);
      tracker_free_raw (t, t);
    }

  *tracker = NULL;
}

int
SocketIPTracker_track (T tracker, const char *ip)
{
  int result;

  assert (tracker != NULL);

  IPValidationResult res = validate_ip (ip, "tracking");
  if (res == IP_BASIC_INVALID)
    return 1;
  if (res != IP_VALID)
    return 0;

  TRACKER_LOCK (tracker);

  result = track_internal (tracker, ip);

  TRACKER_UNLOCK (tracker);
  return result;
}

void
SocketIPTracker_release (T tracker, const char *ip)
{
  IPEntry *prev;
  IPEntry *entry;

  assert (tracker != NULL);

  IPValidationResult res = validate_ip (ip, "release");
  if (res != IP_VALID)
    return;

  TRACKER_LOCK (tracker);

  entry = find_entry (tracker, ip, &prev);

  if (entry != NULL && entry->count > 0)
    {
      entry->count--;
      tracker->total_conns--;

      if (entry->count == 0)
        unlink_entry (tracker, entry, prev);
    }

  TRACKER_UNLOCK (tracker);
}

int
SocketIPTracker_count (T tracker, const char *ip)
{
  const IPEntry *entry;
  int count = 0;

  assert (tracker != NULL);

  IPValidationResult res = validate_ip (ip, NULL);
  if (res != IP_VALID)
    return 0;

  TRACKER_LOCK (tracker);

  entry = find_entry (tracker, ip, NULL);
  if (entry != NULL)
    count = entry->count;

  TRACKER_UNLOCK (tracker);
  return count;
}

void
SocketIPTracker_setmax (T tracker, int max_per_ip)
{
  assert (tracker != NULL);

  TRACKER_WRITE_FIELD (tracker, max_per_ip, clamp_max_per_ip (max_per_ip));
}

int
SocketIPTracker_getmax (T tracker)
{
  int max;

  assert (tracker != NULL);

  TRACKER_READ_FIELD (tracker, max_per_ip, max);

  return max;
}

void
SocketIPTracker_setmaxunique (T tracker, size_t max_unique)
{
  assert (tracker != NULL);

  TRACKER_WRITE_FIELD (tracker, max_unique_ips, max_unique);
}

size_t
SocketIPTracker_getmaxunique (T tracker)
{
  size_t maxu;

  assert (tracker != NULL);

  TRACKER_LOCK (tracker);
  maxu = tracker->max_unique_ips;
  TRACKER_UNLOCK (tracker);

  return maxu;
}

size_t
SocketIPTracker_total (T tracker)
{
  size_t total;

  assert (tracker != NULL);

  TRACKER_READ_FIELD (tracker, total_conns, total);

  return total;
}

size_t
SocketIPTracker_unique_ips (T tracker)
{
  size_t unique;

  assert (tracker != NULL);

  TRACKER_READ_FIELD (tracker, unique_ips, unique);

  return unique;
}

void
SocketIPTracker_clear (T tracker)
{
  assert (tracker != NULL);

  TRACKER_LOCK (tracker);

  if (tracker->arena == NULL)
    free_all_entries (tracker);

  HashTable_clear (tracker->table);

  tracker->total_conns = 0;
  tracker->unique_ips = 0;

  TRACKER_UNLOCK (tracker);
}

#undef T
