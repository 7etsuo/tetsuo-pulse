/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketPool-health.c - Active health checking and circuit breaker
 *
 * Part of the Socket Library
 *
 * Implements:
 * - Per-host circuit breaker with three-state model
 * - Background health probe thread
 * - Lock-free fast path for circuit state reads
 */

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "core/SocketCrypto.h"
#include "pool/SocketPool-private.h"
#include "pool/SocketPoolHealth-private.h"

/* SOCKET_LOG_COMPONENT defined in SocketPool-private.h */

/* ============================================================================
 * Time Utilities
 * ============================================================================ */

/**
 * @brief Get current monotonic time in milliseconds.
 * @return Monotonic time in ms.
 */
int64_t
health_monotonic_ms (void)
{
  struct timespec ts;
  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (int64_t)socket_util_timespec_to_ms (ts);
}

/* ============================================================================
 * Hash Functions
 * ============================================================================ */

/**
 * @brief DJB2 hash for string keys with seed randomization.
 * @param key String to hash.
 * @param seed Hash seed for randomization (prevents hash collision DoS).
 * @param table_size Hash table size for modulo operation.
 * @return Hash value in range [0, table_size).
 *
 * Security: The seed is mixed into the hash to randomize the hash
 * distribution per-instance, preventing attackers from crafting keys
 * that cause hash collisions.
 *
 * Delegates to socket_util_hash_djb2_seeded() from SocketUtil.h.
 */
unsigned int
health_hash_key (const char *key, unsigned int seed, unsigned int table_size)
{
  return socket_util_hash_djb2_seeded (key, table_size, seed);
}

/**
 * @brief Generate "host:port" key string.
 * @param host Hostname or IP.
 * @param port Port number.
 * @param buf Output buffer.
 * @param len Buffer length.
 * @return Bytes written (excluding NUL), -1 if truncated.
 */
int
health_make_host_key (const char *host, int port, char *buf, size_t len)
{
  int n = snprintf (buf, len, "%s:%d", host, port);
  if (n < 0 || (size_t)n >= len)
    return -1;
  return n;
}

/* ============================================================================
 * Circuit Entry Management
 * ============================================================================ */

/**
 * @brief Find or create circuit entry.
 *
 * Caller must hold circuit_mutex for create=true.
 *
 * @param health Health context.
 * @param host Hostname.
 * @param port Port number.
 * @param create If true, create entry if not found.
 * @return Entry or NULL.
 */
SocketPoolCircuit_Entry_T
health_find_circuit (SocketPoolHealth_T health, const char *host, int port,
                     int create)
{
  char key[SOCKET_HEALTH_MAX_HOST_KEY_LEN];
  SocketPoolCircuit_Entry_T entry;
  unsigned int bucket;

  if (!health || !host)
    return NULL;

  if (health_make_host_key (host, port, key, sizeof (key)) < 0)
    return NULL;

  bucket = health_hash_key (key, health->hash_seed, SOCKET_HEALTH_HASH_SIZE);
  entry = health->circuit_table[bucket];

  /* Search chain */
  while (entry)
    {
      if (strcmp (entry->host_key, key) == 0)
        return entry;
      entry = entry->hash_next;
    }

  if (!create)
    return NULL;

  /* Enforce max_circuits limit to prevent unbounded memory growth */
  if (health->circuit_count >= health->config.max_circuits)
    {
      SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                       "Circuit limit reached (%d), not tracking %s:%d",
                       health->config.max_circuits, host, port);
      return NULL;
    }

  /* Create new entry - caller must hold circuit_mutex */
  entry = Arena_alloc (health->arena, sizeof (*entry), __FILE__, __LINE__);
  if (!entry)
    return NULL;

  size_t key_len = strlen (key);
  entry->host_key = Arena_alloc (health->arena, key_len + 1, __FILE__, __LINE__);
  if (!entry->host_key)
    return NULL;
  memcpy (entry->host_key, key, key_len + 1);

  atomic_init (&entry->state, POOL_CIRCUIT_CLOSED);
  atomic_init (&entry->consecutive_failures, 0);
  atomic_init (&entry->half_open_probes, 0);
  entry->circuit_open_time_ms = 0;
  entry->last_success_ms = health_monotonic_ms ();
  entry->total_failures = 0;
  entry->total_successes = 0;
  entry->hash_next = health->circuit_table[bucket];
  health->circuit_table[bucket] = entry;
  health->circuit_count++;

  return entry;
}

/**
 * @brief Check if circuit should transition OPEN -> HALF_OPEN.
 * @param health Health context.
 * @param entry Circuit entry in OPEN state.
 * @return Non-zero if should transition.
 */
int
health_should_transition_half_open (SocketPoolHealth_T health,
                                    SocketPoolCircuit_Entry_T entry)
{
  int64_t now_ms = health_monotonic_ms ();
  int64_t elapsed = now_ms - entry->circuit_open_time_ms;
  return elapsed >= health->config.reset_timeout_ms;
}

/**
 * @brief Try to claim a probe slot in HALF_OPEN state.
 *
 * Uses atomic compare-exchange loop to prevent TOCTOU race conditions
 * that could allow more probes than the configured maximum.
 *
 * @param entry Circuit entry in HALF_OPEN state.
 * @param max_probes Maximum number of concurrent probes allowed.
 * @return 1 if probe slot claimed successfully, 0 if max probes reached.
 */
int
circuit_try_half_open_probe (SocketPoolCircuit_Entry_T entry, int max_probes)
{
  int probes
      = atomic_load_explicit (&entry->half_open_probes, memory_order_acquire);

  while (probes < max_probes)
    {
      if (atomic_compare_exchange_weak_explicit (
              &entry->half_open_probes, &probes, probes + 1,
              memory_order_acq_rel, memory_order_acquire))
        {
          return 1; /* Successfully claimed a probe slot */
        }
      /* probes updated by compare_exchange on failure, retry */
    }

  return 0; /* Max probes reached */
}

/* ============================================================================
 * Default Health Probe
 * ============================================================================ */

/**
 * @brief Default probe using poll() to detect connection errors.
 * @param pool Connection pool.
 * @param conn Connection to probe.
 * @param timeout_ms Maximum probe time.
 * @param data Unused.
 * @return 1 if healthy, 0 if unhealthy.
 */
int
health_default_probe (struct SocketPool_T *pool, struct Connection *conn,
                      int timeout_ms, void *data)
{
  struct pollfd pfd;
  int ret;

  (void)pool;
  (void)data;

  if (!conn || !conn->socket)
    return 0;

  pfd.fd = Socket_fd (conn->socket);
  pfd.events = POLLIN;
  pfd.revents = 0;

  ret = poll (&pfd, 1, timeout_ms);

  if (ret < 0)
    return 0; /* Error */

  if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
    return 0; /* Connection broken */

  return 1; /* Healthy */
}

/* ============================================================================
 * Background Worker Thread
 * ============================================================================ */

/**
 * @brief Run one probe cycle.
 *
 * Selects connections and probes them.
 * Updates circuit states based on results.
 *
 * @param health Health context.
 */
void
health_run_probe_cycle (SocketPoolHealth_T health)
{
  struct SocketPool_T *pool = health->pool;
  SocketPool_HealthProbeCallback cb;
  void *cb_data;
  int timeout_ms;
  int probes_per_cycle;
  int probed = 0;

  /* Get callback under pool mutex */
  pthread_mutex_lock (&pool->mutex);
  cb = health->probe_cb ? health->probe_cb : health_default_probe;
  cb_data = health->probe_cb_data;
  timeout_ms = health->config.probe_timeout_ms;
  probes_per_cycle = health->config.probes_per_cycle;
  pthread_mutex_unlock (&pool->mutex);

  /* Iterate connections and probe */
  pthread_mutex_lock (&pool->mutex);
  Connection_T conn = pool->active_head;
  while (conn && probed < probes_per_cycle)
    {
      /* Skip if not idle or no socket */
      if (!conn->socket || !conn->active)
        {
          conn = conn->active_next;
          continue;
        }

      /* Get connection info while holding mutex */
      Socket_T socket = conn->socket;
      Connection_T probe_conn = conn;
      conn = conn->active_next;

      /* Release mutex for probe */
      pthread_mutex_unlock (&pool->mutex);

      /* Execute probe */
      atomic_fetch_add (&health->stats_probes_sent, 1);
      int result = cb (pool, probe_conn, timeout_ms, cb_data);

      if (result)
        atomic_fetch_add (&health->stats_probes_passed, 1);
      else
        atomic_fetch_add (&health->stats_probes_failed, 1);

      probed++;

      /* Re-acquire mutex */
      pthread_mutex_lock (&pool->mutex);

      /* Security: TOCTOU check - verify connection still valid AND socket
       * hasn't changed while we released the mutex. The socket handle could
       * have been replaced if the connection was removed and re-added. */
      if (!probe_conn->active || probe_conn->socket != socket)
        continue;
    }
  pthread_mutex_unlock (&pool->mutex);

  /* Check for OPEN -> HALF_OPEN transitions */
  pthread_mutex_lock (&health->circuit_mutex);
  for (unsigned int i = 0; i < SOCKET_HEALTH_HASH_SIZE; i++)
    {
      SocketPoolCircuit_Entry_T entry = health->circuit_table[i];
      while (entry)
        {
          int state = atomic_load_explicit (&entry->state, memory_order_acquire);
          if (state == POOL_CIRCUIT_OPEN
              && health_should_transition_half_open (health, entry))
            {
              atomic_store_explicit (&entry->state, POOL_CIRCUIT_HALF_OPEN,
                                     memory_order_release);
              atomic_store (&entry->half_open_probes, 0);
            }
          entry = entry->hash_next;
        }
    }
  pthread_mutex_unlock (&health->circuit_mutex);
}

/**
 * @brief Worker thread entry point.
 * @param arg SocketPoolHealth_T context.
 * @return NULL.
 */
void *
health_worker_thread (void *arg)
{
  SocketPoolHealth_T health = arg;
  struct timespec ts;
  int interval_ms;

  while (!atomic_load (&health->shutdown))
    {
      /* Run probe cycle with exception handling */
      TRY { health_run_probe_cycle (health); }
      ELSE
      {
        /* Log error but continue */
        SocketLog_emitf (SOCKET_LOG_ERROR, SOCKET_LOG_COMPONENT,
                         "Health probe cycle failed");
      }
      END_TRY;

      /* Wait for next cycle or shutdown */
      pthread_mutex_lock (&health->worker_mutex);
      if (!atomic_load (&health->shutdown))
        {
          struct timespec interval;
          interval_ms = health->config.probe_interval_ms;
          clock_gettime (CLOCK_REALTIME, &ts);
          interval = socket_util_ms_to_timespec ((unsigned long)interval_ms);
          ts.tv_sec += interval.tv_sec;
          ts.tv_nsec += interval.tv_nsec;
          if (ts.tv_nsec >= 1000000000)
            {
              ts.tv_sec++;
              ts.tv_nsec -= 1000000000;
            }
          pthread_cond_timedwait (&health->worker_cond, &health->worker_mutex,
                                  &ts);
        }
      pthread_mutex_unlock (&health->worker_mutex);
    }

  return NULL;
}

/**
 * @brief Start background worker thread.
 * @param health Health context.
 * @return 0 on success, -1 on failure.
 */
int
health_start_worker (SocketPoolHealth_T health)
{
  pthread_attr_t attr;
  int ret;

  if (pthread_attr_init (&attr) != 0)
    return -1;

#ifdef SOCKET_HEALTH_WORKER_STACK_SIZE
  pthread_attr_setstacksize (&attr, SOCKET_HEALTH_WORKER_STACK_SIZE);
#endif

  ret = pthread_create (&health->worker, &attr, health_worker_thread, health);
  pthread_attr_destroy (&attr);

  if (ret != 0)
    return -1;

  health->worker_started = 1;
  return 0;
}

/**
 * @brief Stop background worker thread.
 * @param health Health context.
 */
void
health_stop_worker (SocketPoolHealth_T health)
{
  if (!health->worker_started)
    return;

  atomic_store (&health->shutdown, 1);

  pthread_mutex_lock (&health->worker_mutex);
  pthread_cond_broadcast (&health->worker_cond);
  pthread_mutex_unlock (&health->worker_mutex);

  pthread_join (health->worker, NULL);
  health->worker_started = 0;
}

/* ============================================================================
 * Health Context Lifecycle
 * ============================================================================ */

/**
 * @brief Initialize circuit breaker hash table.
 * @param health Health context.
 * @return 0 on success, -1 on failure.
 */
int
health_init_circuit_table (SocketPoolHealth_T health)
{
  size_t size = SOCKET_HEALTH_HASH_SIZE * sizeof (SocketPoolCircuit_Entry_T);

  health->circuit_table = Arena_alloc (health->arena, size, __FILE__, __LINE__);
  if (!health->circuit_table)
    return -1;

  memset (health->circuit_table, 0, size);
  return 0;
}

/**
 * @brief Create health subsystem context.
 * @param pool Owning pool.
 * @param arena Arena for allocations.
 * @return New context or NULL.
 */
SocketPoolHealth_T
health_create (struct SocketPool_T *pool, Arena_T arena)
{
  SocketPoolHealth_T health;

  health = Arena_alloc (arena, sizeof (*health), __FILE__, __LINE__);
  if (!health)
    return NULL;

  memset (health, 0, sizeof (*health));
  health->pool = pool;
  health->arena = arena;

  /* Security: Initialize hash seed for hash collision DoS prevention.
   * Uses cryptographically secure random number generator. */
  health->hash_seed = SocketCrypto_random_uint32 ();

  if (pthread_mutex_init (&health->circuit_mutex, NULL) != 0)
    return NULL;

  if (pthread_mutex_init (&health->worker_mutex, NULL) != 0)
    {
      pthread_mutex_destroy (&health->circuit_mutex);
      return NULL;
    }

  if (pthread_cond_init (&health->worker_cond, NULL) != 0)
    {
      pthread_mutex_destroy (&health->circuit_mutex);
      pthread_mutex_destroy (&health->worker_mutex);
      return NULL;
    }

  atomic_init (&health->shutdown, 0);
  health->worker_started = 0;

  atomic_init (&health->stats_probes_sent, 0);
  atomic_init (&health->stats_probes_passed, 0);
  atomic_init (&health->stats_probes_failed, 0);
  atomic_init (&health->stats_circuits_opened, 0);

  return health;
}

/* ============================================================================
 * Public API Implementation
 * ============================================================================ */

void
SocketPoolHealth_config_defaults (SocketPoolHealth_Config *config)
{
  if (!config)
    return;

  config->failure_threshold = SOCKET_HEALTH_DEFAULT_FAILURE_THRESHOLD;
  config->reset_timeout_ms = SOCKET_HEALTH_DEFAULT_RESET_TIMEOUT_MS;
  config->half_open_max_probes = SOCKET_HEALTH_DEFAULT_HALF_OPEN_MAX_PROBES;
  config->probe_interval_ms = SOCKET_HEALTH_DEFAULT_PROBE_INTERVAL_MS;
  config->probe_timeout_ms = SOCKET_HEALTH_DEFAULT_PROBE_TIMEOUT_MS;
  config->probes_per_cycle = SOCKET_HEALTH_DEFAULT_PROBES_PER_CYCLE;
  config->max_circuits = SOCKET_HEALTH_DEFAULT_MAX_CIRCUITS;
}

int
SocketPool_enable_health_checks (struct SocketPool_T *pool,
                                 const SocketPoolHealth_Config *config)
{
  SocketPoolHealth_T health;

  if (!pool || !config)
    return -1;

  if (config->failure_threshold < 1 || config->probe_interval_ms < 100
      || config->max_circuits < 1)
    return -1;

  pthread_mutex_lock (&pool->mutex);

  /* Already enabled - update config */
  if (pool->health)
    {
      pool->health->config = *config;
      pthread_mutex_unlock (&pool->mutex);
      return 0;
    }

  /* Create health context */
  health = health_create (pool, pool->arena);
  if (!health)
    {
      pthread_mutex_unlock (&pool->mutex);
      return -1;
    }

  health->config = *config;

  if (health_init_circuit_table (health) < 0)
    {
      pthread_mutex_destroy (&health->circuit_mutex);
      pthread_mutex_destroy (&health->worker_mutex);
      pthread_cond_destroy (&health->worker_cond);
      pthread_mutex_unlock (&pool->mutex);
      return -1;
    }

  pool->health = health;
  pthread_mutex_unlock (&pool->mutex);

  /* Start worker thread outside of pool mutex */
  if (health_start_worker (health) < 0)
    {
      pthread_mutex_lock (&pool->mutex);
      pool->health = NULL;
      pthread_mutex_unlock (&pool->mutex);
      pthread_mutex_destroy (&health->circuit_mutex);
      pthread_mutex_destroy (&health->worker_mutex);
      pthread_cond_destroy (&health->worker_cond);
      return -1;
    }

  SocketLog_emitf (SOCKET_LOG_INFO, SOCKET_LOG_COMPONENT,
                   "Health checks enabled (interval=%dms, threshold=%d)",
                   config->probe_interval_ms, config->failure_threshold);

  return 0;
}

void
SocketPool_disable_health_checks (struct SocketPool_T *pool)
{
  SocketPoolHealth_T health;

  if (!pool)
    return;

  pthread_mutex_lock (&pool->mutex);
  health = pool->health;
  pool->health = NULL;
  pthread_mutex_unlock (&pool->mutex);

  if (!health)
    return;

  health_stop_worker (health);
  pthread_mutex_destroy (&health->circuit_mutex);
  pthread_mutex_destroy (&health->worker_mutex);
  pthread_cond_destroy (&health->worker_cond);

  SocketLog_emitf (SOCKET_LOG_INFO, SOCKET_LOG_COMPONENT,
                   "Health checks disabled");
}

void
SocketPool_set_health_callback (struct SocketPool_T *pool,
                                SocketPool_HealthProbeCallback callback,
                                void *data)
{
  if (!pool)
    return;

  pthread_mutex_lock (&pool->mutex);
  if (pool->health)
    {
      pool->health->probe_cb = callback;
      pool->health->probe_cb_data = data;
    }
  pthread_mutex_unlock (&pool->mutex);
}

SocketPoolCircuit_State
SocketPool_circuit_state (struct SocketPool_T *pool, const char *host,
                          int port)
{
  SocketPoolCircuit_Entry_T entry;
  SocketPoolCircuit_State state = POOL_CIRCUIT_CLOSED;

  if (!pool || !host)
    return POOL_CIRCUIT_CLOSED;

  pthread_mutex_lock (&pool->mutex);
  if (!pool->health)
    {
      pthread_mutex_unlock (&pool->mutex);
      return POOL_CIRCUIT_CLOSED;
    }

  pthread_mutex_lock (&pool->health->circuit_mutex);
  entry = health_find_circuit (pool->health, host, port, 0);
  if (entry)
    state = atomic_load_explicit (&entry->state, memory_order_acquire);
  pthread_mutex_unlock (&pool->health->circuit_mutex);
  pthread_mutex_unlock (&pool->mutex);

  return state;
}

int
SocketPool_circuit_allows (struct SocketPool_T *pool, const char *host,
                           int port)
{
  SocketPoolCircuit_Entry_T entry;
  int state;
  int allows = 1;

  if (!pool || !host)
    return 1; /* Allow by default if invalid args */

  pthread_mutex_lock (&pool->mutex);
  if (!pool->health)
    {
      pthread_mutex_unlock (&pool->mutex);
      return 1; /* Health checks not enabled - always allow */
    }

  pthread_mutex_lock (&pool->health->circuit_mutex);
  entry = health_find_circuit (pool->health, host, port, 0);
  if (!entry)
    {
      pthread_mutex_unlock (&pool->health->circuit_mutex);
      pthread_mutex_unlock (&pool->mutex);
      return 1; /* No entry - first connection, allow */
    }

  state = atomic_load_explicit (&entry->state, memory_order_acquire);

  switch (state)
    {
    case POOL_CIRCUIT_CLOSED:
      allows = 1;
      break;

    case POOL_CIRCUIT_OPEN:
      /* Check for timeout transition */
      if (health_should_transition_half_open (pool->health, entry))
        {
          atomic_store_explicit (&entry->state, POOL_CIRCUIT_HALF_OPEN,
                                 memory_order_release);
          atomic_store (&entry->half_open_probes, 0);
          allows = 1;
          atomic_fetch_add (&entry->half_open_probes, 1);
        }
      else
        {
          allows = 0;
        }
      break;

    case POOL_CIRCUIT_HALF_OPEN:
      allows = circuit_try_half_open_probe (
          entry, pool->health->config.half_open_max_probes);
      break;
    }

  pthread_mutex_unlock (&pool->health->circuit_mutex);
  pthread_mutex_unlock (&pool->mutex);

  return allows;
}

void
SocketPool_circuit_report_success (struct SocketPool_T *pool, const char *host,
                                   int port)
{
  SocketPoolCircuit_Entry_T entry;
  int state;

  if (!pool || !host)
    return;

  pthread_mutex_lock (&pool->mutex);
  if (!pool->health)
    {
      pthread_mutex_unlock (&pool->mutex);
      return;
    }

  pthread_mutex_lock (&pool->health->circuit_mutex);
  entry = health_find_circuit (pool->health, host, port, 1);
  if (!entry)
    {
      pthread_mutex_unlock (&pool->health->circuit_mutex);
      pthread_mutex_unlock (&pool->mutex);
      return;
    }

  state = atomic_load_explicit (&entry->state, memory_order_acquire);

  /* Reset failure counter */
  atomic_store (&entry->consecutive_failures, 0);
  entry->last_success_ms = health_monotonic_ms ();
  entry->total_successes++;

  /* In HALF_OPEN, success closes the circuit */
  if (state == POOL_CIRCUIT_HALF_OPEN)
    {
      atomic_store_explicit (&entry->state, POOL_CIRCUIT_CLOSED,
                             memory_order_release);
      SocketLog_emitf (SOCKET_LOG_INFO, SOCKET_LOG_COMPONENT,
                       "Circuit closed for %s:%d (recovered)", host, port);
    }

  pthread_mutex_unlock (&pool->health->circuit_mutex);
  pthread_mutex_unlock (&pool->mutex);
}

void
SocketPool_circuit_report_failure (struct SocketPool_T *pool, const char *host,
                                   int port)
{
  SocketPoolCircuit_Entry_T entry;
  int state;
  int failures;

  if (!pool || !host)
    return;

  pthread_mutex_lock (&pool->mutex);
  if (!pool->health)
    {
      pthread_mutex_unlock (&pool->mutex);
      return;
    }

  pthread_mutex_lock (&pool->health->circuit_mutex);
  entry = health_find_circuit (pool->health, host, port, 1);
  if (!entry)
    {
      pthread_mutex_unlock (&pool->health->circuit_mutex);
      pthread_mutex_unlock (&pool->mutex);
      return;
    }

  state = atomic_load_explicit (&entry->state, memory_order_acquire);
  entry->total_failures++;

  switch (state)
    {
    case POOL_CIRCUIT_CLOSED:
      failures = atomic_fetch_add (&entry->consecutive_failures, 1) + 1;
      if (failures >= pool->health->config.failure_threshold)
        {
          atomic_store_explicit (&entry->state, POOL_CIRCUIT_OPEN,
                                 memory_order_release);
          entry->circuit_open_time_ms = health_monotonic_ms ();
          atomic_fetch_add (&pool->health->stats_circuits_opened, 1);
          SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                           "Circuit opened for %s:%d (failures=%d)", host, port,
                           failures);
        }
      break;

    case POOL_CIRCUIT_HALF_OPEN:
      /* Failure in HALF_OPEN - back to OPEN */
      atomic_store_explicit (&entry->state, POOL_CIRCUIT_OPEN,
                             memory_order_release);
      entry->circuit_open_time_ms = health_monotonic_ms ();
      atomic_store (&entry->consecutive_failures, 0);
      SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                       "Circuit re-opened for %s:%d (probe failed)", host,
                       port);
      break;

    case POOL_CIRCUIT_OPEN:
      /* Already open - just update counter */
      atomic_fetch_add (&entry->consecutive_failures, 1);
      break;
    }

  pthread_mutex_unlock (&pool->health->circuit_mutex);
  pthread_mutex_unlock (&pool->mutex);
}

int
SocketPool_circuit_reset (struct SocketPool_T *pool, const char *host,
                          int port)
{
  SocketPoolCircuit_Entry_T entry;
  int found = 0;

  if (!pool || !host)
    return -1;

  pthread_mutex_lock (&pool->mutex);
  if (!pool->health)
    {
      pthread_mutex_unlock (&pool->mutex);
      return -1;
    }

  pthread_mutex_lock (&pool->health->circuit_mutex);
  entry = health_find_circuit (pool->health, host, port, 0);
  if (entry)
    {
      atomic_store_explicit (&entry->state, POOL_CIRCUIT_CLOSED,
                             memory_order_release);
      atomic_store (&entry->consecutive_failures, 0);
      atomic_store (&entry->half_open_probes, 0);
      entry->last_success_ms = health_monotonic_ms ();
      found = 1;
      SocketLog_emitf (SOCKET_LOG_INFO, SOCKET_LOG_COMPONENT,
                       "Circuit manually reset for %s:%d", host, port);
    }
  pthread_mutex_unlock (&pool->health->circuit_mutex);
  pthread_mutex_unlock (&pool->mutex);

  return found ? 0 : -1;
}

void
SocketPool_health_stats (struct SocketPool_T *pool, uint64_t *probes_sent,
                         uint64_t *probes_passed, uint64_t *probes_failed,
                         uint64_t *circuits_opened)
{
  if (!pool)
    return;

  pthread_mutex_lock (&pool->mutex);
  if (!pool->health)
    {
      pthread_mutex_unlock (&pool->mutex);
      if (probes_sent)
        *probes_sent = 0;
      if (probes_passed)
        *probes_passed = 0;
      if (probes_failed)
        *probes_failed = 0;
      if (circuits_opened)
        *circuits_opened = 0;
      return;
    }

  if (probes_sent)
    *probes_sent = atomic_load (&pool->health->stats_probes_sent);
  if (probes_passed)
    *probes_passed = atomic_load (&pool->health->stats_probes_passed);
  if (probes_failed)
    *probes_failed = atomic_load (&pool->health->stats_probes_failed);
  if (circuits_opened)
    *circuits_opened = atomic_load (&pool->health->stats_circuits_opened);

  pthread_mutex_unlock (&pool->mutex);
}
