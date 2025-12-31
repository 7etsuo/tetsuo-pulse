/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETPOOLHEALTH_PRIVATE_H_INCLUDED
#define SOCKETPOOLHEALTH_PRIVATE_H_INCLUDED

/**
 * @file SocketPoolHealth-private.h
 * @brief Private implementation details for health checking subsystem.
 * @ingroup connection_mgmt
 * @internal
 *
 * NOT FOR PUBLIC USE - Internal header for SocketPool-health.c.
 * Defines internal structures for circuit breaker hash table and
 * background health worker thread.
 *
 * KEY COMPONENTS:
 * - struct SocketPoolCircuit_Entry: Per-host circuit breaker state
 * - struct SocketPoolHealth_T: Health subsystem context with worker thread
 *
 * THREAD SAFETY:
 * - Circuit state reads use atomic operations (lock-free fast path)
 * - Circuit state writes protected by circuit_mutex
 * - Worker thread signaling via worker_mutex + worker_cond
 * - Lock hierarchy: pool->mutex > circuit_mutex > worker_mutex
 *
 * MEMORY:
 * - All allocations from pool's arena (no manual free)
 * - Circuit entries allocated on demand, never freed (arena cleanup)
 *
 * @warning Direct use from application code undefined.
 * @see SocketPoolHealth.h for public API.
 */

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>

#include "core/Arena.h"
#include "core/SocketConfig.h"
#include "pool/SocketPoolHealth.h"

/* Forward declaration */
struct SocketPool_T;

/**
 * @brief Per-host circuit breaker entry.
 * @internal
 *
 * Tracks circuit state for a single host:port endpoint.
 * Stored in hash table with chaining for collision resolution.
 *
 * Atomic fields allow lock-free reads from the fast path.
 * State transitions and counter updates protected by circuit_mutex.
 */
typedef struct SocketPoolCircuit_Entry
{
  /**
   * @brief Hash key: "host:port" string.
   *
   * Allocated from arena. Used for hash table lookup.
   * Max length: SOCKET_HEALTH_MAX_HOST_KEY_LEN.
   */
  char *host_key;

  /**
   * @brief Current circuit state.
   *
   * Atomic for lock-free reads. Writes protected by circuit_mutex.
   * Values: POOL_CIRCUIT_CLOSED, POOL_CIRCUIT_OPEN, POOL_CIRCUIT_HALF_OPEN.
   */
  _Atomic int state;

  /**
   * @brief Consecutive failure count.
   *
   * Atomic increment for thread-safe counting. Reset on success.
   * When >= failure_threshold, circuit transitions to OPEN.
   */
  _Atomic int consecutive_failures;

  /**
   * @brief Active probe count in HALF_OPEN state.
   *
   * Atomic for lock-free comparison. Tracks probes in flight.
   * Limited to half_open_max_probes to prevent thundering herd.
   */
  _Atomic int half_open_probes;

  /**
   * @brief Timestamp when circuit transitioned to OPEN (ms).
   *
   * Used to calculate when OPEN -> HALF_OPEN transition is allowed.
   * Set via monotonic clock for immunity to wall clock changes.
   */
  int64_t circuit_open_time_ms;

  /**
   * @brief Timestamp of last successful operation (ms).
   *
   * Monotonic time of last SocketPool_circuit_report_success() call.
   * Used for monitoring and debugging.
   */
  int64_t last_success_ms;

  /**
   * @brief Lifetime failure counter.
   *
   * Total failures since entry creation. For monitoring/metrics.
   * Not atomic - protected by circuit_mutex on write.
   */
  uint64_t total_failures;

  /**
   * @brief Lifetime success counter.
   *
   * Total successes since entry creation. For monitoring/metrics.
   * Not atomic - protected by circuit_mutex on write.
   */
  uint64_t total_successes;

  /**
   * @brief Hash chain pointer.
   *
   * For collision resolution in hash table.
   * NULL if last entry in bucket.
   */
  struct SocketPoolCircuit_Entry *hash_next;
} *SocketPoolCircuit_Entry_T;

/**
 * @brief Health subsystem context.
 * @internal
 *
 * Contains all state for circuit breaker and background health probes.
 * Allocated from pool's arena in SocketPool_enable_health_checks().
 *
 * Lifecycle:
 * - Created by SocketPool_enable_health_checks()
 * - Destroyed by SocketPool_disable_health_checks() (thread join only)
 * - Memory freed when pool arena is disposed
 */
typedef struct SocketPoolHealth_T
{
  /**
   * @brief Back-pointer to owning pool.
   *
   * Used to access connections during probe cycles.
   * Never NULL after initialization.
   */
  struct SocketPool_T *pool;

  /**
   * @brief Arena for all health allocations.
   *
   * Same as pool->arena. Used for circuit entries and host keys.
   */
  Arena_T arena;

  /* ========================================================================
   * Circuit Breaker Hash Table
   * ======================================================================== */

  /**
   * @brief Hash table of circuit entries.
   *
   * Array of SOCKET_HEALTH_HASH_SIZE bucket pointers.
   * NULL buckets indicate no entries with that hash.
   * Collisions resolved via chaining (hash_next).
   */
  SocketPoolCircuit_Entry_T *circuit_table;

  /**
   * @brief Mutex protecting circuit table modifications.
   *
   * Required for: entry creation, state transitions, counter updates.
   * NOT required for: atomic state reads, circuit_allows() fast path.
   *
   * Lock hierarchy: Acquire AFTER pool->mutex, BEFORE worker_mutex.
   */
  pthread_mutex_t circuit_mutex;

  /**
   * @brief Count of entries in circuit table.
   *
   * For monitoring. Protected by circuit_mutex.
   */
  int circuit_count;

  /**
   * @brief Hash seed for DJB2 randomization.
   *
   * Security: Randomized at initialization to prevent hash collision
   * DoS attacks where attacker crafts host:port keys that collide.
   * Generated from time + pid for per-instance uniqueness.
   */
  unsigned int hash_seed;

  /* ========================================================================
   * Probe Callback
   * ======================================================================== */

  /**
   * @brief User-defined health probe callback.
   *
   * Called from worker thread WITHOUT pool mutex held.
   * NULL means use default poll-based check.
   */
  SocketPool_HealthProbeCallback probe_cb;

  /**
   * @brief User data for probe callback.
   */
  void *probe_cb_data;

  /* ========================================================================
   * Background Worker Thread
   * ======================================================================== */

  /**
   * @brief Worker thread handle.
   *
   * Runs health_worker_thread() function.
   * Joined in SocketPool_disable_health_checks().
   */
  pthread_t worker;

  /**
   * @brief Mutex for worker thread signaling.
   *
   * Used with worker_cond for sleep/wake coordination.
   * Lock hierarchy: Acquire AFTER circuit_mutex.
   */
  pthread_mutex_t worker_mutex;

  /**
   * @brief Condition variable for worker sleep/wake.
   *
   * Worker waits on this between probe cycles.
   * Signaled for shutdown or config changes.
   */
  pthread_cond_t worker_cond;

  /**
   * @brief Shutdown flag for worker thread.
   *
   * Atomic for lock-free polling in worker loop.
   * Set by SocketPool_disable_health_checks().
   */
  _Atomic int shutdown;

  /**
   * @brief Flag indicating worker thread is running.
   *
   * Set after successful pthread_create().
   * Cleared before pthread_join() completes.
   */
  int worker_started;

  /* ========================================================================
   * Configuration
   * ======================================================================== */

  /**
   * @brief Copied configuration.
   *
   * Set in SocketPool_enable_health_checks().
   * Can be updated at runtime (mutex protected).
   */
  SocketPoolHealth_Config config;

  /* ========================================================================
   * Statistics
   * ======================================================================== */

  /**
   * @brief Total probe operations executed.
   *
   * Atomic increment in worker thread.
   */
  _Atomic uint64_t stats_probes_sent;

  /**
   * @brief Probes that returned healthy.
   */
  _Atomic uint64_t stats_probes_passed;

  /**
   * @brief Probes that returned unhealthy or timed out.
   */
  _Atomic uint64_t stats_probes_failed;

  /**
   * @brief Times any circuit transitioned to OPEN.
   */
  _Atomic uint64_t stats_circuits_opened;

} *SocketPoolHealth_T;

/* ============================================================================
 * Internal Function Declarations
 * ============================================================================
 */

/**
 * @brief Create health subsystem context.
 * @internal
 *
 * Allocates and initializes SocketPoolHealth_T structure.
 * Does NOT start worker thread (see health_start_worker).
 *
 * @param pool  Owning pool.
 * @param arena Arena for allocations.
 *
 * @return New health context, or NULL on failure.
 */
SocketPoolHealth_T health_create (struct SocketPool_T *pool, Arena_T arena);

/**
 * @brief Initialize circuit breaker hash table.
 * @internal
 *
 * Allocates bucket array from arena.
 *
 * @param health Health context.
 *
 * @return 0 on success, -1 on failure.
 */
int health_init_circuit_table (SocketPoolHealth_T health);

/**
 * @brief Start background worker thread.
 * @internal
 *
 * Creates thread running health_worker_thread().
 *
 * @param health Health context.
 *
 * @return 0 on success, -1 on failure.
 */
int health_start_worker (SocketPoolHealth_T health);

/**
 * @brief Stop background worker thread.
 * @internal
 *
 * Sets shutdown flag, signals condition, joins thread.
 *
 * @param health Health context.
 */
void health_stop_worker (SocketPoolHealth_T health);

/**
 * @brief Worker thread entry point.
 * @internal
 *
 * Runs probe cycles until shutdown signaled.
 *
 * @param arg SocketPoolHealth_T context.
 *
 * @return NULL.
 */
void *health_worker_thread (void *arg);

/**
 * @brief Run one probe cycle.
 * @internal
 *
 * Selects connections for probing, executes probes, updates state.
 * Called from worker thread.
 *
 * @param health Health context.
 */
void health_run_probe_cycle (SocketPoolHealth_T health);

/**
 * @brief Find or create circuit entry for host:port.
 * @internal
 *
 * Looks up entry in hash table. Creates new entry if not found.
 * Caller must hold circuit_mutex for creation.
 *
 * @param health    Health context.
 * @param host      Hostname or IP.
 * @param port      Port number.
 * @param create    If true, create entry if not found.
 *
 * @return Entry pointer, or NULL if not found and create=false.
 */
SocketPoolCircuit_Entry_T health_find_circuit (SocketPoolHealth_T health,
                                               const char *host,
                                               int port,
                                               int create);

/**
 * @brief Generate host key string.
 * @internal
 *
 * Formats "host:port" into buffer.
 *
 * @param host Hostname or IP.
 * @param port Port number.
 * @param buf  Output buffer.
 * @param len  Buffer length.
 *
 * @return Bytes written (excluding NUL), or -1 if truncated.
 */
int health_make_host_key (const char *host, int port, char *buf, size_t len);

/**
 * @brief Hash function for host keys.
 * @internal
 *
 * DJB2 hash for string keys with per-instance seed randomization.
 * The seed prevents hash collision DoS attacks.
 *
 * Delegates to socket_util_hash_djb2_seeded() from SocketUtil.h.
 *
 * @param key  Host key string.
 * @param seed Hash seed from health context (health->hash_seed).
 * @param table_size Hash table size (SOCKET_HEALTH_HASH_SIZE).
 *
 * @return Hash value in range [0, table_size).
 */
unsigned int
health_hash_key (const char *key, unsigned int seed, unsigned int table_size);

/**
 * @brief Check if circuit should transition OPEN -> HALF_OPEN.
 * @internal
 *
 * Compares current time against circuit_open_time + reset_timeout.
 *
 * @param health Health context.
 * @param entry  Circuit entry in OPEN state.
 *
 * @return Non-zero if should transition, 0 otherwise.
 */
int health_should_transition_half_open (SocketPoolHealth_T health,
                                        SocketPoolCircuit_Entry_T entry);

/**
 * @brief Default health probe implementation.
 * @internal
 *
 * Uses poll() to check for connection errors/hangups.
 * Used when no custom callback is registered.
 *
 * @param pool       Connection pool.
 * @param conn       Connection to probe.
 * @param timeout_ms Maximum probe time.
 * @param data       Unused.
 *
 * @return 1 if healthy, 0 if unhealthy.
 */
int health_default_probe (struct SocketPool_T *pool,
                          struct Connection *conn,
                          int timeout_ms,
                          void *data);

/**
 * @brief Get current monotonic time in milliseconds.
 * @internal
 *
 * Uses CLOCK_MONOTONIC for immunity to wall clock changes.
 *
 * @return Monotonic time in milliseconds.
 */
int64_t health_monotonic_ms (void);

#endif /* SOCKETPOOLHEALTH_PRIVATE_H_INCLUDED */
