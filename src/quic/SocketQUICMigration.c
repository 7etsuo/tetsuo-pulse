/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICMigration.c
 * @brief QUIC Connection Migration Implementation (RFC 9000 Section 9).
 */

#include "quic/SocketQUICMigration.h"
#include "quic/SocketQUICConstants.h"
#include "core/SocketUtil.h"
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>

/* For random challenge generation */
#ifdef __linux__
#include <sys/random.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#include <stdlib.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

/* ============================================================================
 * Exception Definition
 * ============================================================================
 */

const Except_T SocketQUICMigration_Failed = { &SocketQUICMigration_Failed,
                                              "SocketQUICMigration failed" };

/* ============================================================================
 * Helper Functions (Forward Declarations)
 * ============================================================================
 */

static int generate_random_bytes (uint8_t *buf, size_t len);
static int sockaddr_equal (const struct sockaddr_storage *a,
                          const struct sockaddr_storage *b);
static void sockaddr_to_string (const struct sockaddr_storage *addr, char *buf,
                                size_t size);
static SocketQUICPath_T *find_path_by_challenge (
    SocketQUICMigration_T *migration, const uint8_t challenge[8]);
static SocketQUICPath_T *allocate_path_slot (SocketQUICMigration_T *migration);

/* ============================================================================
 * Lifecycle Functions
 * ============================================================================
 */

SocketQUICMigration_T *
SocketQUICMigration_new (Arena_T arena, SocketQUICConnection_T connection,
                         SocketQUICMigration_Role role)
{
  SocketQUICMigration_T *migration;

  if (arena == NULL || connection == NULL)
    return NULL;

  migration = Arena_alloc (arena, sizeof (*migration), __FILE__, __LINE__);
  if (migration == NULL)
    return NULL;

  SocketQUICMigration_init (migration, connection, role);
  migration->arena = arena;

  return migration;
}

void
SocketQUICMigration_init (SocketQUICMigration_T *migration,
                          SocketQUICConnection_T connection,
                          SocketQUICMigration_Role role)
{
  if (migration == NULL)
    return;

  memset (migration, 0, sizeof (*migration));
  migration->connection = connection;
  migration->role = role;
  migration->active_path_index = 0;
  migration->migration_in_progress = 0;
  migration->nat_rebinding_detected = 0;
}

void
SocketQUICMigration_free (SocketQUICMigration_T **migration)
{
  if (migration == NULL || *migration == NULL)
    return;

  /* No dynamic allocations to free - arena-managed */
  *migration = NULL;
}

/* ============================================================================
 * Path Management Functions
 * ============================================================================
 */

SocketQUICMigration_Result
SocketQUICMigration_init_path (SocketQUICMigration_T *migration,
                               const struct sockaddr_storage *local_addr,
                               const struct sockaddr_storage *peer_addr,
                               const SocketQUICConnectionID_T *cid)
{
  SocketQUICPath_T *path;

  if (migration == NULL || local_addr == NULL || peer_addr == NULL
      || cid == NULL)
    return QUIC_MIGRATION_ERROR_NULL;

  if (migration->path_count >= QUIC_MIGRATION_MAX_PATHS)
    return QUIC_MIGRATION_ERROR_PATH_LIMIT;

  /* Use first slot for initial path */
  path = &migration->paths[0];
  memset (path, 0, sizeof (*path));

  /* Copy addresses */
  memcpy (&path->local_addr, local_addr, sizeof (path->local_addr));
  memcpy (&path->peer_addr, peer_addr, sizeof (path->peer_addr));

  /* Copy connection ID */
  SocketQUICConnectionID_copy (&path->cid, cid);

  /* Initial path is pre-validated (handshake established it) */
  path->state = QUIC_PATH_VALIDATED;

  /* Initialize congestion control to initial window */
  path->cwnd = QUIC_INITIAL_CWND;
  path->ssthresh = QUIC_MAX_CWND;
  path->bytes_in_flight = 0;
  path->rtt_us = QUIC_INITIAL_RTT_US;

  migration->path_count = 1;
  migration->active_path_index = 0;

  return QUIC_MIGRATION_OK;
}

const SocketQUICPath_T *
SocketQUICMigration_get_active_path (const SocketQUICMigration_T *migration)
{
  if (migration == NULL || migration->path_count == 0)
    return NULL;

  if (migration->active_path_index >= migration->path_count)
    return NULL;

  return &migration->paths[migration->active_path_index];
}

SocketQUICPath_T *
SocketQUICMigration_find_path (SocketQUICMigration_T *migration,
                               const struct sockaddr_storage *peer_addr)
{
  size_t i;

  if (migration == NULL || peer_addr == NULL)
    return NULL;

  for (i = 0; i < migration->path_count; i++)
    {
      if (sockaddr_equal (&migration->paths[i].peer_addr, peer_addr))
        return &migration->paths[i];
    }

  return NULL;
}

/* ============================================================================
 * Path Validation Functions (RFC 9000 Section 8.2)
 * ============================================================================
 */

SocketQUICMigration_Result
SocketQUICMigration_probe_path (SocketQUICMigration_T *migration,
                                const struct sockaddr_storage *peer_addr)
{
  SocketQUICPath_T *path;
  SocketQUICPath_T *new_path;
  uint64_t current_time_ms;

  if (migration == NULL || peer_addr == NULL)
    return QUIC_MIGRATION_ERROR_NULL;

  /* Check if path already exists */
  path = SocketQUICMigration_find_path (migration, peer_addr);

  if (path == NULL)
    {
      /* Allocate new path slot */
      new_path = allocate_path_slot (migration);
      if (new_path == NULL)
        return QUIC_MIGRATION_ERROR_PATH_LIMIT;

      path = new_path;
      memset (path, 0, sizeof (*path));
      memcpy (&path->peer_addr, peer_addr, sizeof (path->peer_addr));

      /* Copy local address from active path */
      const SocketQUICPath_T *active = SocketQUICMigration_get_active_path (migration);
      if (active != NULL)
        memcpy (&path->local_addr, &active->local_addr, sizeof (path->local_addr));

      migration->path_count++;
    }

  /* Generate random challenge data */
  if (generate_random_bytes (path->challenge, QUIC_PATH_CHALLENGE_SIZE) != 0)
    return QUIC_MIGRATION_ERROR_RANDOM;

  /* Set validation state */
  path->state = QUIC_PATH_VALIDATING;
  path->challenge_count = 1;

  /* Record timestamp using monotonic clock */
  current_time_ms = Socket_get_monotonic_ms ();
  path->challenge_sent_time = current_time_ms;

  /* Initialize congestion control for this path */
  if (path->cwnd == 0)
    {
      path->cwnd = QUIC_INITIAL_CWND;
      path->ssthresh = QUIC_MAX_CWND;
      path->rtt_us = QUIC_INITIAL_RTT_US;
    }

  /* NOTE: Caller must send PATH_CHALLENGE frame with path->challenge data */

  return QUIC_MIGRATION_OK;
}

SocketQUICMigration_Result
SocketQUICMigration_handle_path_response (SocketQUICMigration_T *migration,
                                          const uint8_t response_data[8])
{
  SocketQUICPath_T *path;

  if (migration == NULL || response_data == NULL)
    return QUIC_MIGRATION_ERROR_NULL;

  /* Find path matching the challenge */
  path = find_path_by_challenge (migration, response_data);
  if (path == NULL)
    return QUIC_MIGRATION_ERROR_INVALID_STATE;

  /* Validate that path is in VALIDATING state */
  if (path->state != QUIC_PATH_VALIDATING)
    return QUIC_MIGRATION_ERROR_INVALID_STATE;

  /* Mark path as validated */
  path->state = QUIC_PATH_VALIDATED;

  /* If this was the target of migration, complete migration */
  if (migration->migration_in_progress)
    {
      for (size_t i = 0; i < migration->path_count; i++)
        {
          if (&migration->paths[i] == path)
            {
              migration->target_path_index = i;
              /* Caller should invoke SocketQUICMigration_initiate next */
              break;
            }
        }
    }

  return QUIC_MIGRATION_OK;
}

SocketQUICMigration_Result
SocketQUICMigration_handle_path_challenge (
    SocketQUICMigration_T *migration, const uint8_t challenge_data[8],
    uint8_t response_out[8])
{
  if (migration == NULL || challenge_data == NULL || response_out == NULL)
    return QUIC_MIGRATION_ERROR_NULL;

  /* RFC 9000 Section 8.2.2: Response must contain same data as challenge */
  memcpy (response_out, challenge_data, QUIC_PATH_CHALLENGE_SIZE);

  return QUIC_MIGRATION_OK;
}

int
SocketQUICMigration_check_timeouts (SocketQUICMigration_T *migration,
                                    uint64_t current_time_ms)
{
  size_t i;
  int timeout_count = 0;
  uint64_t elapsed;

  if (migration == NULL)
    return 0;

  for (i = 0; i < migration->path_count; i++)
    {
      SocketQUICPath_T *path = &migration->paths[i];

      if (path->state != QUIC_PATH_VALIDATING)
        continue;

      elapsed = current_time_ms - path->challenge_sent_time;

      if (elapsed >= QUIC_PATH_VALIDATION_TIMEOUT_MS)
        {
          if (path->challenge_count < QUIC_PATH_MAX_CHALLENGES)
            {
              /* Retry challenge */
              path->challenge_count++;
              path->challenge_sent_time = current_time_ms;

              /* Regenerate challenge data */
              generate_random_bytes (path->challenge,
                                    QUIC_PATH_CHALLENGE_SIZE);

              /* Caller must resend PATH_CHALLENGE frame */
            }
          else
            {
              /* Max retries exceeded, mark as failed */
              path->state = QUIC_PATH_FAILED;
              timeout_count++;
            }
        }
    }

  return timeout_count;
}

/* ============================================================================
 * Migration Functions (RFC 9000 Section 9)
 * ============================================================================
 */

SocketQUICMigration_Result
SocketQUICMigration_initiate (SocketQUICMigration_T *migration,
                              SocketQUICPath_T *new_path)
{
  const SocketQUICPath_T *old_path;
  SocketQUICConnectionID_T new_cid;
  size_t new_path_index;

  if (migration == NULL || new_path == NULL)
    return QUIC_MIGRATION_ERROR_NULL;

  /* Check if migration is allowed */
  if (!SocketQUICMigration_can_migrate (migration))
    return QUIC_MIGRATION_ERROR_NOT_ALLOWED;

  /* Validate that new path is in VALIDATED state */
  if (new_path->state != QUIC_PATH_VALIDATED)
    return QUIC_MIGRATION_ERROR_INVALID_STATE;

  /* Get current active path */
  old_path = SocketQUICMigration_get_active_path (migration);

  /* RFC 9000 Section 9.5: Must use new connection ID when migrating */
  /* In real implementation, would request new CID from connection manager */
  /* For now, generate a new random CID */
  if (SocketQUICConnectionID_generate (&new_cid, 8) != QUIC_CONNID_OK)
    return QUIC_MIGRATION_ERROR_NO_CID;

  new_cid.sequence = old_path ? old_path->cid.sequence + 1 : 1;

  /* Copy new CID to path */
  SocketQUICConnectionID_copy (&new_path->cid, &new_cid);

  /* Reset congestion control for new path */
  SocketQUICMigration_reset_congestion (new_path, old_path);

  /* Find index of new path */
  for (new_path_index = 0; new_path_index < migration->path_count;
       new_path_index++)
    {
      if (&migration->paths[new_path_index] == new_path)
        break;
    }

  if (new_path_index >= migration->path_count)
    return QUIC_MIGRATION_ERROR_INVALID_STATE;

  /* Switch active path */
  migration->active_path_index = new_path_index;
  migration->migration_in_progress = 0;

  /* Update connection routing with new CID */
  if (migration->connection != NULL)
    {
      SocketQUICConnection_update_dcid (migration->connection, &new_cid);
    }

  return QUIC_MIGRATION_OK;
}

SocketQUICMigration_Result
SocketQUICMigration_handle_peer_address_change (
    SocketQUICMigration_T *migration,
    const struct sockaddr_storage *peer_addr, uint64_t current_time_ms)
{
  const SocketQUICPath_T *active_path;
  uint64_t time_since_last_change;

  if (migration == NULL || peer_addr == NULL)
    return QUIC_MIGRATION_ERROR_NULL;

  active_path = SocketQUICMigration_get_active_path (migration);
  if (active_path == NULL)
    return QUIC_MIGRATION_ERROR_INVALID_STATE;

  /* Check if address actually changed */
  if (sockaddr_equal (&active_path->peer_addr, peer_addr))
    return QUIC_MIGRATION_OK; /* No change */

  /* Calculate time since last address change */
  time_since_last_change = current_time_ms - migration->last_peer_addr_change_time;

  /* Detect NAT rebinding vs intentional migration */
  if (time_since_last_change < QUIC_NAT_REBIND_WINDOW_MS)
    {
      /* Likely NAT rebinding - rapid address changes */
      migration->nat_rebinding_detected = 1;

      /* RFC 9000 Section 9.3.3: Validate new address before using */
      return SocketQUICMigration_probe_path (migration, peer_addr);
    }

  /* Update timestamp */
  migration->last_peer_addr_change_time = current_time_ms;

  /* Initiate path validation for new address */
  return SocketQUICMigration_probe_path (migration, peer_addr);
}

/* ============================================================================
 * Congestion Control Functions (RFC 9000 Section 9.4)
 * ============================================================================
 */

void
SocketQUICMigration_reset_congestion (SocketQUICPath_T *new_path,
                                      const SocketQUICPath_T *old_path)
{
  if (new_path == NULL)
    return;

  /* RFC 9000 Section 9.4: Reset congestion controller for new path */
  new_path->cwnd = QUIC_INITIAL_CWND;
  new_path->ssthresh = QUIC_MAX_CWND;
  new_path->bytes_in_flight = 0;

  /* RFC 9000 allows reusing RTT if paths share infrastructure */
  if (old_path != NULL && old_path->rtt_us > 0)
    {
      /* Optionally inherit RTT estimate */
      new_path->rtt_us = old_path->rtt_us;
    }
  else
    {
      /* Use initial RTT estimate */
      new_path->rtt_us = QUIC_INITIAL_RTT_US;
    }

  /* Reset statistics */
  new_path->packets_sent = 0;
  new_path->packets_received = 0;
  new_path->bytes_sent = 0;
  new_path->bytes_received = 0;
}

void
SocketQUICMigration_update_rtt (SocketQUICPath_T *path, uint64_t rtt_us)
{
  if (path == NULL)
    return;

  /* Exponential moving average (RFC 6298) */
  if (path->rtt_us == 0)
    {
      /* First RTT sample */
      path->rtt_us = rtt_us;
    }
  else
    {
      /* Smoothed RTT = (1 - alpha) * SRTT + alpha * RTT */
      path->rtt_us = (uint64_t) ((1.0 - QUIC_RTT_ALPHA) * path->rtt_us
                                 + QUIC_RTT_ALPHA * rtt_us);
    }
}

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

int
SocketQUICMigration_can_migrate (const SocketQUICMigration_T *migration)
{
  if (migration == NULL)
    return 0;

  /* RFC 9000 Section 9.3: Only clients can initiate voluntary migration */
  /* Servers can only migrate to preferred_address */
  if (migration->role == QUIC_MIGRATION_ROLE_RESPONDER)
    return 0; /* Server cannot initiate migration */

  /* Check if connection is in valid state */
  if (migration->connection == NULL)
    return 0;

  /* Check if we have available CIDs */
  /* In real implementation, would check connection's CID pool */

  return 1;
}

const char *
SocketQUICMigration_state_string (SocketQUICPath_State state)
{
  switch (state)
    {
    case QUIC_PATH_UNKNOWN:
      return "UNKNOWN";
    case QUIC_PATH_VALIDATING:
      return "VALIDATING";
    case QUIC_PATH_VALIDATED:
      return "VALIDATED";
    case QUIC_PATH_FAILED:
      return "FAILED";
    case QUIC_PATH_ABANDONED:
      return "ABANDONED";
    default:
      return "INVALID";
    }
}

const char *
SocketQUICMigration_result_string (SocketQUICMigration_Result result)
{
  switch (result)
    {
    case QUIC_MIGRATION_OK:
      return "OK";
    case QUIC_MIGRATION_ERROR_NULL:
      return "NULL pointer";
    case QUIC_MIGRATION_ERROR_INVALID_STATE:
      return "Invalid state";
    case QUIC_MIGRATION_ERROR_NO_CID:
      return "No connection ID available";
    case QUIC_MIGRATION_ERROR_PATH_LIMIT:
      return "Maximum paths exceeded";
    case QUIC_MIGRATION_ERROR_TIMEOUT:
      return "Path validation timeout";
    case QUIC_MIGRATION_ERROR_NOT_ALLOWED:
      return "Migration not allowed";
    case QUIC_MIGRATION_ERROR_RANDOM:
      return "Random generation failed";
    case QUIC_MIGRATION_ERROR_MEMORY:
      return "Memory allocation failed";
    default:
      return "Unknown error";
    }
}

int
SocketQUICMigration_path_to_string (const SocketQUICPath_T *path, char *buf,
                                    size_t size)
{
  char local_str[QUIC_SOCKADDR_STRING_MAX];
  char peer_str[QUIC_SOCKADDR_STRING_MAX];
  char cid_str[QUIC_SOCKADDR_STRING_MAX];
  int written;

  if (path == NULL || buf == NULL || size == 0)
    return -1;

  sockaddr_to_string (&path->local_addr, local_str, sizeof (local_str));
  sockaddr_to_string (&path->peer_addr, peer_str, sizeof (peer_str));
  SocketQUICConnectionID_to_hex (&path->cid, cid_str, sizeof (cid_str));

  written = snprintf (buf, size,
                      "Path[%s -> %s, CID=%s, state=%s, cwnd=%lu, "
                      "rtt=%lu us]",
                      local_str, peer_str, cid_str,
                      SocketQUICMigration_state_string (path->state),
                      (unsigned long)path->cwnd,
                      (unsigned long)path->rtt_us);

  return (written < 0 || (size_t)written >= size) ? -1 : written;
}

/* ============================================================================
 * Helper Function Implementations
 * ============================================================================
 */

/**
 * @brief Generate cryptographically random bytes.
 *
 * Uses platform-specific secure random source.
 *
 * @param buf Output buffer.
 * @param len Number of bytes to generate.
 *
 * @return 0 on success, -1 on failure.
 */
static int
generate_random_bytes (uint8_t *buf, size_t len)
{
  if (buf == NULL || len == 0)
    return -1;

#ifdef __linux__
  /* Use getrandom() on Linux with retry loop for EINTR and partial reads */
  size_t total = 0;
  while (total < len)
    {
      ssize_t ret = getrandom (buf + total, len - total, 0);
      if (ret < 0)
        {
          if (errno == EINTR)
            continue; /* Retry on signal interruption */
          return -1;  /* Real error */
        }
      total += (size_t)ret;
    }
  return 0;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
  /* Use arc4random_buf() on BSD/macOS */
  arc4random_buf (buf, len);
  return 0;
#else
  /* Fallback: use /dev/urandom with retry logic for partial reads */
  int fd = open ("/dev/urandom", O_RDONLY);
  size_t total = 0;

  if (fd < 0)
    return -1;

  /* Retry loop to handle partial reads */
  while (total < len)
    {
      ssize_t n = read (fd, buf + total, len - total);
      if (n <= 0)
        {
          close (fd);
          /* Zero buffer to avoid leaving weak cryptographic material */
          memset (buf, 0, len);
          return -1;
        }
      total += n;
    }

  close (fd);
  return 0;
#endif
}

/**
 * @brief Compare two sockaddr_storage structures for equality.
 *
 * Compares address family, IP address, and port.
 *
 * @param a First address.
 * @param b Second address.
 *
 * @return 1 if equal, 0 otherwise.
 */
static int
sockaddr_equal (const struct sockaddr_storage *a,
                const struct sockaddr_storage *b)
{
  const struct sockaddr_in *a4, *b4;
  const struct sockaddr_in6 *a6, *b6;

  if (a == NULL || b == NULL)
    return 0;

  if (a->ss_family != b->ss_family)
    return 0;

  if (a->ss_family == AF_INET)
    {
      a4 = (const struct sockaddr_in *)a;
      b4 = (const struct sockaddr_in *)b;

      return (a4->sin_addr.s_addr == b4->sin_addr.s_addr
              && a4->sin_port == b4->sin_port);
    }
  else if (a->ss_family == AF_INET6)
    {
      a6 = (const struct sockaddr_in6 *)a;
      b6 = (const struct sockaddr_in6 *)b;

      return (memcmp (&a6->sin6_addr, &b6->sin6_addr,
                     sizeof (a6->sin6_addr))
                  == 0
              && a6->sin6_port == b6->sin6_port);
    }

  return 0;
}

/**
 * @brief Convert sockaddr_storage to string.
 *
 * Formats as "IP:port".
 *
 * @param addr Address to convert.
 * @param buf  Output buffer.
 * @param size Size of output buffer.
 */
static void
sockaddr_to_string (const struct sockaddr_storage *addr, char *buf,
                    size_t size)
{
  const struct sockaddr_in *addr4;
  const struct sockaddr_in6 *addr6;
  char ip[INET6_ADDRSTRLEN];

  if (addr == NULL || buf == NULL || size == 0)
    {
      if (buf != NULL && size > 0)
        buf[0] = '\0';
      return;
    }

  if (addr->ss_family == AF_INET)
    {
      addr4 = (const struct sockaddr_in *)addr;
      if (inet_ntop (AF_INET, &addr4->sin_addr, ip, sizeof (ip)) == NULL)
        {
          snprintf (buf, size, "invalid:0");
          return;
        }
      snprintf (buf, size, "%s:%u", ip, ntohs (addr4->sin_port));
    }
  else if (addr->ss_family == AF_INET6)
    {
      addr6 = (const struct sockaddr_in6 *)addr;
      if (inet_ntop (AF_INET6, &addr6->sin6_addr, ip, sizeof (ip)) == NULL)
        {
          snprintf (buf, size, "[invalid]:0");
          return;
        }
      snprintf (buf, size, "[%s]:%u", ip, ntohs (addr6->sin6_port));
    }
  else
    {
      snprintf (buf, size, "unknown");
    }
}

/**
 * @brief Find path by challenge data.
 *
 * Searches for a path with matching challenge data.
 *
 * @param migration Migration manager.
 * @param challenge Challenge data to match.
 *
 * @return Pointer to matching path, or NULL if not found.
 */
static SocketQUICPath_T *
find_path_by_challenge (SocketQUICMigration_T *migration,
                        const uint8_t challenge[8])
{
  size_t i;

  if (migration == NULL || challenge == NULL)
    return NULL;

  for (i = 0; i < migration->path_count; i++)
    {
      if (memcmp (migration->paths[i].challenge, challenge,
                 QUIC_PATH_CHALLENGE_SIZE)
          == 0)
        {
          return &migration->paths[i];
        }
    }

  return NULL;
}

/**
 * @brief Allocate a new path slot.
 *
 * Finds an unused or failed path slot for reuse.
 *
 * @param migration Migration manager.
 *
 * @return Pointer to available path slot, or NULL if all slots used.
 */
static SocketQUICPath_T *
allocate_path_slot (SocketQUICMigration_T *migration)
{
  size_t i;

  if (migration == NULL)
    return NULL;

  /* First try to find a FAILED or ABANDONED slot */
  for (i = 0; i < migration->path_count; i++)
    {
      if (migration->paths[i].state == QUIC_PATH_FAILED
          || migration->paths[i].state == QUIC_PATH_ABANDONED)
        {
          return &migration->paths[i];
        }
    }

  /* If no reusable slot, check if we can add new path */
  if (migration->path_count < QUIC_MIGRATION_MAX_PATHS)
    {
      return &migration->paths[migration->path_count];
    }

  return NULL;
}
