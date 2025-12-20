/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketHappyEyeballs.c - Happy Eyeballs (RFC 8305) Implementation
 *
 * Part of the Socket Library
 *
 * Implements the Happy Eyeballs algorithm for fast dual-stack connection
 * establishment. Races IPv6 and IPv4 connection attempts with a 250ms
 * delay between attempts to minimize latency when one family is slow.
 */

#include "socket/SocketHappyEyeballs-private.h"
#include "socket/SocketHappyEyeballs.h"

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"
#include "dns/SocketDNS.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"
#include "socket/SocketCommon.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h> /* For INT_MAX */
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define T SocketHE_T

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "HappyEyeballs"

/* ============================================================================
 * Exception Definition
 * ============================================================================
 */

const Except_T SocketHE_Failed
    = { &SocketHE_Failed, "Happy Eyeballs connection failed" };

SOCKET_DECLARE_MODULE_EXCEPTION (SocketHE);

#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketHE, e)

/* ============================================================================
 * Forward Declarations - DNS and Address Management
 * ============================================================================
 */

static void he_cancel_dns (T he);
static int he_start_dns_resolution (T he);
static void he_process_dns_completion (T he);
static void he_sort_addresses (T he);
static SocketHE_AddressEntry_T *he_get_next_address (T he);

/* ============================================================================
 * Forward Declarations - Connection Attempt Management
 * ============================================================================
 */

static int he_start_attempt (T he, SocketHE_AddressEntry_T *entry);
static int he_initiate_connect (T he, SocketHE_Attempt_T *attempt,
                                SocketHE_AddressEntry_T *entry);
static void he_check_attempts (T he);
static void he_cleanup_attempts (T he);
static void he_declare_winner (T he, SocketHE_Attempt_T *attempt);
static void he_fail_attempt (T he, SocketHE_Attempt_T *attempt, int error);
static int he_all_attempts_done (const T he);

/* ============================================================================
 * Forward Declarations - State and Timeout Management
 * ============================================================================
 */

static void he_transition_to_failed (T he, const char *reason);
static int he_should_start_fallback (const T he);
static int he_check_total_timeout (const T he);

/* ============================================================================
 * Configuration Defaults
 * ============================================================================
 */

/**
 * SocketHappyEyeballs_config_defaults - Initialize config with defaults
 * @config: Configuration to initialize
 *
 * Thread-safe: Yes
 */
void
SocketHappyEyeballs_config_defaults (SocketHE_Config_T *config)
{
  assert (config);
  config->first_attempt_delay_ms = SOCKET_HE_DEFAULT_FIRST_ATTEMPT_DELAY_MS;
  config->attempt_timeout_ms = SOCKET_HE_DEFAULT_ATTEMPT_TIMEOUT_MS;
  config->total_timeout_ms = SOCKET_HE_DEFAULT_TOTAL_TIMEOUT_MS;
  config->dns_timeout_ms = SOCKET_HE_DEFAULT_DNS_TIMEOUT_MS;
  config->prefer_ipv6 = 1;
  config->max_attempts = SOCKET_HE_DEFAULT_MAX_ATTEMPTS;
}

/* ============================================================================
 * Context Initialization Helpers
 * ============================================================================
 */

/**
 * he_init_config - Initialize context configuration
 * @he: Context to initialize
 * @config: User config or NULL for defaults
 */
static void
he_init_config (T he, const SocketHE_Config_T *config)
{
  if (config)
    he->config = *config;
  else
    SocketHappyEyeballs_config_defaults (&he->config);

  /* Clamp max_attempts to prevent resource exhaustion and poll array overflow
   */
  if (he->config.max_attempts < 1)
    he->config.max_attempts = SOCKET_HE_DEFAULT_MAX_ATTEMPTS;
  else if (he->config.max_attempts > SOCKET_HE_MAX_ATTEMPTS)
    he->config.max_attempts = SOCKET_HE_MAX_ATTEMPTS;
}

/**
 * he_copy_hostname - Copy hostname into context arena
 * @he: Context (must not be NULL)
 * @host: Hostname to copy (must not be NULL)
 *
 * Returns: 0 on success, -1 on failure
 */
static int
he_copy_hostname (T he, const char *host)
{
  size_t len = strlen (host);
  if (len == 0 || len > 255)
    {
      RAISE_MODULE_ERROR (SocketHE_Failed);
    }
  SocketCommon_validate_hostname (host, SocketHE_Failed);

  size_t host_len = len + 1;
  he->host = Arena_alloc (he->arena, host_len, __FILE__, __LINE__);
  if (!he->host)
    return -1;

  memcpy (he->host, host, host_len);
  return 0;
}

/**
 * he_init_context_fields - Initialize context fields after allocation
 * @he: Context to initialize
 * @dns: DNS resolver (may be NULL for sync API)
 * @poll: Poll instance (may be NULL for sync API)
 * @port: Target port (1-65535)
 *
 * Sets initial field values including start timestamp for timeout tracking.
 */
static void
he_init_context_fields (T he, const SocketDNS_T dns, const SocketPoll_T poll,
                        const int port)
{
  he->port = port;
  he->dns = dns;
  he->poll = poll;
  he->state = HE_STATE_IDLE;
  he->start_time_ms = Socket_get_monotonic_ms ();
}

/**
 * he_alloc_base_context - Allocate and initialize base context
 *
 * Returns: New context or NULL on failure
 */
static T
he_alloc_base_context (void)
{
  T he = calloc (1, sizeof (*he));
  if (!he)
    return NULL;

  he->arena = Arena_new ();
  if (!he->arena)
    {
      free (he);
      return NULL;
    }

  return he;
}

/**
 * he_create_context - Create Happy Eyeballs context
 * @dns: DNS resolver (may be NULL for sync API)
 * @poll: Poll instance (may be NULL for sync API)
 * @host: Target hostname (will be copied into context)
 * @port: Target port (1-65535)
 * @config: Configuration options (NULL for defaults)
 *
 * Returns: New context or NULL on allocation failure
 *
 * Allocates context and arena, copies hostname, initializes fields.
 * Caller owns the returned context and must free with SocketHappyEyeballs_free.
 */
static T
he_create_context (const SocketDNS_T dns, const SocketPoll_T poll,
                   const char *host, const int port,
                   const SocketHE_Config_T *config)
{
  T he = he_alloc_base_context ();
  if (!he)
    return NULL;

  he_init_config (he, config);

  if (he_copy_hostname (he, host) < 0)
    {
      Arena_dispose (&he->arena);
      free (he);
      return NULL;
    }

  he_init_context_fields (he, dns, poll, port);
  return he;
}

/* ============================================================================
 * Context Destruction
 * ============================================================================
 */

/**
 * he_free_resolved - Free resolved address list
 * @he: Context
 */
static void
he_free_resolved (T he)
{
  if (he->resolved)
    {
      SocketCommon_free_addrinfo (he->resolved);
      he->resolved = NULL;
    }
}

/**
 * he_free_owned_resources - Free resources we created
 * @he: Context
 */
static void
he_free_owned_resources (T he)
{
  if (he->dns_poll_wrapper) {
    if (he->poll) {
      TRY {
        SocketPoll_del (he->poll, he->dns_poll_wrapper);
      } EXCEPT (SocketPoll_Failed) {
        /* Ignore poll del failure during cleanup */
      } END_TRY;
    }
    Socket_free (&he->dns_poll_wrapper);
  }

  if (he->owns_dns && he->dns)
    SocketDNS_free (&he->dns);

  if (he->owns_poll && he->poll)
    SocketPoll_free (&he->poll);

  if (he->arena)
    Arena_dispose (&he->arena);
}

/**
 * SocketHappyEyeballs_free - Free Happy Eyeballs context
 * @he: Pointer to context (will be set to NULL)
 *
 * Thread-safe: No
 */
void
SocketHappyEyeballs_free (T *he)
{
  if (!he || !*he)
    return;

  T ctx = *he;

  if (ctx->state == HE_STATE_RESOLVING || ctx->state == HE_STATE_CONNECTING)
    SocketHappyEyeballs_cancel (ctx);

  /* Always cleanup attempts to close sockets/fds */
  he_cleanup_attempts (ctx);

  /* Close unclaimed winner socket if connected but not transferred via
   * result() */
  if (ctx->state == HE_STATE_CONNECTED && ctx->winner)
    {
      Socket_free (&ctx->winner);
      ctx->winner = NULL;
    }

  he_free_resolved (ctx);
  he_free_owned_resources (ctx);

  free (ctx);
  *he = NULL;
}

/**
 * SocketHappyEyeballs_cancel - Cancel in-progress operation
 * @he: Happy Eyeballs context
 *
 * Thread-safe: No
 */
void
SocketHappyEyeballs_cancel (T he)
{
  assert (he);

  if (he->state == HE_STATE_CONNECTED || he->state == HE_STATE_FAILED
      || he->state == HE_STATE_CANCELLED)
    return;

  he_cancel_dns (he);
  he_cleanup_attempts (he);
  he->state = HE_STATE_CANCELLED;

  SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                   "Happy Eyeballs cancelled for %s:%d", he->host, he->port);
}

/* ============================================================================
 * DNS Resolution
 * ============================================================================
 */

/**
 * he_cancel_dns - Cancel active DNS request
 * @he: Happy Eyeballs context
 */
static void
he_cancel_dns (T he)
{
  if (he->dns_request && he->dns)
    {
      SocketDNS_cancel (he->dns, he->dns_request);
      he->dns_request = NULL;
    }
}

/**
 * he_calculate_dns_timeout - Calculate effective DNS timeout
 * @he: Happy Eyeballs context (read-only access)
 *
 * Returns: DNS timeout in milliseconds (0 = no timeout)
 *
 * Uses dns_timeout_ms if set, otherwise limits by total_timeout_ms.
 * Prioritizes explicit DNS timeout over total timeout when both are set.
 */
static int
he_calculate_dns_timeout (const T he)
{
  int dns_timeout = he->config.dns_timeout_ms;

  /* If explicit DNS timeout set, use it */
  if (dns_timeout > 0)
    return dns_timeout;

  /* Otherwise, limit DNS phase to total timeout */
  if (he->config.total_timeout_ms > 0)
    return he->config.total_timeout_ms;

  return 0; /* No timeout */
}

/**
 * he_start_dns_resolution - Start async DNS resolution
 * @he: Happy Eyeballs context
 *
 * Returns: 0 on success, -1 on failure
 */
static int
he_start_dns_resolution (T he)
{
  int dns_timeout;

  assert (he);
  assert (he->dns);

  he->dns_request
      = SocketDNS_resolve (he->dns, he->host, he->port, NULL, NULL);
  if (!he->dns_request)
    {
      he_transition_to_failed (he, "Failed to start DNS resolution");
      return -1;
    }

  /* Propagate DNS timeout to resolver */
  dns_timeout = he_calculate_dns_timeout (he);
  if (dns_timeout > 0)
    SocketDNS_request_settimeout (he->dns, he->dns_request, dns_timeout);

  he->state = HE_STATE_RESOLVING;
  SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                   "Started DNS resolution for %s:%d (timeout=%dms)", he->host,
                   he->port, dns_timeout);

  /* Integrate DNS completion FD with poll if available */
  if (he->poll && he->dns && he->dns_request && !he->dns_poll_wrapper) {
    int orig_fd = SocketDNS_pollfd (he->dns);
    if (orig_fd >= 0) {
      int dup_fd = fcntl (orig_fd, F_DUPFD_CLOEXEC, 10);
      if (dup_fd >= 0) {
        TRY {
          he->dns_poll_wrapper = Socket_new_from_fd (dup_fd);
          if (he->dns_poll_wrapper != NULL) {
            SocketPoll_add (he->poll, he->dns_poll_wrapper, POLL_READ, he);
          }
        } EXCEPT (Socket_Failed) {
          close (dup_fd);
          SOCKET_LOG_WARN_MSG ("Failed to create DNS poll wrapper");
        } END_TRY;
      } else {
        SOCKET_LOG_WARN_MSG ("Failed to dup DNS pollfd %d: %s", orig_fd, strerror (errno));
      }
    } else {
      SOCKET_LOG_DEBUG_MSG ("No DNS pollfd available for integration");
    }
  }

  return 0;
}

/**
 * he_setup_dns_hints - Setup addrinfo hints for DNS resolution
 * @hints: Pointer to hints structure to initialize
 */
static void
he_setup_dns_hints (struct addrinfo *hints)
{
  memset (hints, 0, sizeof (*hints));
  hints->ai_family = AF_UNSPEC;
  hints->ai_socktype = SOCK_STREAM;
  hints->ai_flags = AI_ADDRCONFIG;
}

/**
 * he_format_port_string - Format port number as string
 * @port: Port number (1-65535)
 * @port_str: Output buffer (must be at least SOCKET_HE_PORT_STR_SIZE)
 * @port_str_size: Size of output buffer
 *
 * Formats the port number for use with getaddrinfo() which requires
 * a string representation of the service/port.
 */
static void
he_format_port_string (const int port, char *port_str, const size_t port_str_size)
{
  snprintf (port_str, port_str_size, "%d", port);
}

/**
 * he_set_dns_error - Set DNS error in context
 * @he: Happy Eyeballs context
 * @error: Error code from DNS resolution (EAI_* constants)
 *
 * Formats the DNS error using gai_strerror() for human-readable output.
 */
static void
he_set_dns_error (T he, const int error)
{
  snprintf (he->error_buf, sizeof (he->error_buf), "DNS resolution failed: %s",
            gai_strerror (error));
  he->dns_error = error;
}

/* REMOVED: DNS error handling unified in he_handle_dns_error; no separate getaddrinfo error handler. */

/* REMOVED: DNS resolution unified with async path in process(); no separate blocking resolve needed.
 * Uses SocketDNS integration for both sync and async modes.
 */

/**
 * he_handle_dns_error - Handle DNS resolution error
 * @he: Happy Eyeballs context
 * @error: Error code from DNS (EAI_* constants)
 *
 * Sets DNS error state and transitions to FAILED state.
 */
static void
he_handle_dns_error (T he, const int error)
{
  he_set_dns_error (he, error);
  he->dns_complete = 1;
  he->dns_request = NULL;
  he_transition_to_failed (he, he->error_buf);
}

/**
 * he_handle_dns_success - Handle DNS resolution success
 * @he: Happy Eyeballs context
 * @result: Resolved addresses
 */
static void
he_handle_dns_success (T he, struct addrinfo *result)
{
  he->resolved = result;
  he->dns_complete = 1;
  he->dns_request = NULL;

  SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                   "DNS resolution complete for %s:%d", he->host, he->port);

  he_sort_addresses (he);
  he->state = HE_STATE_CONNECTING;

  /* Cleanup DNS poll integration since resolution complete */
  if (he->poll && he->dns_poll_wrapper) {
    TRY {
      SocketPoll_del (he->poll, he->dns_poll_wrapper);
    } EXCEPT (SocketPoll_Failed) {
      SOCKET_LOG_WARN_MSG ("Failed to remove DNS wrapper from poll");
    } END_TRY;
  }
}

/**
 * he_process_dns_completion - Check and process DNS completion
 * @he: Happy Eyeballs context
 */
static void
he_process_dns_completion (T he)
{
  struct addrinfo *result;

  if (!he->dns || !he->dns_request)
    return;

  result = SocketDNS_getresult (he->dns, he->dns_request);
  if (!result)
    {
      int error = SocketDNS_geterror (he->dns, he->dns_request);
      if (error != 0)
        he_handle_dns_error (he, error);
      return;
    }

  he_handle_dns_success (he, result);
}

static void
he_process_dns_event (T he)
{
  struct addrinfo *result;

  if (!he->dns || !he->dns_request)
    return;

  result = SocketDNS_getresult (he->dns, he->dns_request);
  if (!result)
    {
      int error = SocketDNS_geterror (he->dns, he->dns_request);
      if (error != 0)
        he_handle_dns_error (he, error);
      return;
    }

  he_handle_dns_success (he, result);
}

/* ============================================================================
 * Address Sorting (RFC 8305)
 * ============================================================================
 */

/**
 * he_count_addresses_by_family - Count addresses of each family
 * @res: Address list (read-only)
 * @ipv6_count: Output for IPv6 count
 * @ipv4_count: Output for IPv4 count
 *
 * Iterates through the resolved address list and counts IPv6 and IPv4
 * addresses separately for RFC 8305 interleaving logic.
 */
static void
he_count_addresses_by_family (const struct addrinfo *res, int *ipv6_count,
                              int *ipv4_count)
{
  *ipv6_count = 0;
  *ipv4_count = 0;

  for (const struct addrinfo *rp = res; rp; rp = rp->ai_next)
    {
      if (rp->ai_family == AF_INET6)
        (*ipv6_count)++;
      else if (rp->ai_family == AF_INET)
        (*ipv4_count)++;
    }
}

/**
 * he_create_address_entry - Create address entry from addrinfo
 * @he: Happy Eyeballs context
 * @rp: Address info to wrap
 *
 * Returns: New entry or NULL on allocation failure
 */
static SocketHE_AddressEntry_T *
he_create_address_entry (T he, struct addrinfo *rp)
{
  SocketHE_AddressEntry_T *entry;

  entry = Arena_alloc (he->arena, sizeof (*entry), __FILE__, __LINE__);
  if (!entry)
    return NULL;

  entry->addr = rp;
  entry->family = rp->ai_family;
  entry->tried = 0;
  entry->next = NULL;

  return entry;
}

/**
 * he_append_to_family_list - Append entry to family-specific list
 * @entry: Entry to append
 * @tail: Pointer to tail pointer (updated)
 */
static void
he_append_to_family_list (SocketHE_AddressEntry_T *entry,
                          SocketHE_AddressEntry_T ***tail)
{
  **tail = entry;
  *tail = &entry->next;
}

/**
 * he_build_family_lists - Build separate IPv6 and IPv4 lists
 * @he: Happy Eyeballs context
 * @ipv6_list: Output for IPv6 list head
 * @ipv4_list: Output for IPv4 list head
 */
static void
he_build_family_lists (T he, SocketHE_AddressEntry_T **ipv6_list,
                       SocketHE_AddressEntry_T **ipv4_list)
{
  SocketHE_AddressEntry_T **ipv6_tail = ipv6_list;
  SocketHE_AddressEntry_T **ipv4_tail = ipv4_list;

  *ipv6_list = NULL;
  *ipv4_list = NULL;

  for (struct addrinfo *rp = he->resolved; rp; rp = rp->ai_next)
    {
      SocketHE_AddressEntry_T *entry = he_create_address_entry (he, rp);
      if (!entry)
        continue;

      if (rp->ai_family == AF_INET6)
        he_append_to_family_list (entry, &ipv6_tail);
      else if (rp->ai_family == AF_INET)
        he_append_to_family_list (entry, &ipv4_tail);
    }
}

/**
 * he_setup_interleave_order - Setup interleave pointers per RFC 8305
 * @he: Happy Eyeballs context
 * @ipv6_list: IPv6 address list
 * @ipv4_list: IPv4 address list
 */
static void
he_setup_interleave_order (T he, SocketHE_AddressEntry_T *ipv6_list,
                           SocketHE_AddressEntry_T *ipv4_list)
{
  if (he->config.prefer_ipv6)
    {
      he->next_ipv6 = ipv6_list;
      he->next_ipv4 = ipv4_list;
      he->interleave_prefer_ipv6 = 1;
    }
  else
    {
      he->next_ipv6 = ipv4_list;
      he->next_ipv4 = ipv6_list;
      he->interleave_prefer_ipv6 = 0;
    }

  he->addresses = he->next_ipv6 ? he->next_ipv6 : he->next_ipv4;
}

/**
 * he_sort_addresses - Sort addresses per RFC 8305
 * @he: Happy Eyeballs context
 */
static void
he_sort_addresses (T he)
{
  SocketHE_AddressEntry_T *ipv6_list;
  SocketHE_AddressEntry_T *ipv4_list;
  int ipv6_count, ipv4_count;

  he_count_addresses_by_family (he->resolved, &ipv6_count, &ipv4_count);
  SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                   "Resolved %d IPv6 and %d IPv4 addresses", ipv6_count,
                   ipv4_count);

  he_build_family_lists (he, &ipv6_list, &ipv4_list);
  he_setup_interleave_order (he, ipv6_list, ipv4_list);
}

/* ============================================================================
 * Address Selection (RFC 8305 Interleaving)
 * ============================================================================
 */

/**
 * he_get_from_preferred - Get next address from preferred family
 * @he: Happy Eyeballs context
 *
 * Returns: Address entry or NULL
 */
static SocketHE_AddressEntry_T *
he_get_from_preferred (T he)
{
  SocketHE_AddressEntry_T *entry;

  if (he->interleave_prefer_ipv6 && he->next_ipv6)
    {
      entry = he->next_ipv6;
      he->next_ipv6 = entry->next;
      he->interleave_prefer_ipv6 = 0;
      return entry;
    }

  if (!he->interleave_prefer_ipv6 && he->next_ipv4)
    {
      entry = he->next_ipv4;
      he->next_ipv4 = entry->next;
      he->interleave_prefer_ipv6 = 1;
      return entry;
    }

  return NULL;
}

/**
 * he_get_from_remaining - Get next address from remaining family
 * @he: Happy Eyeballs context
 *
 * Returns: Address entry or NULL
 */
static SocketHE_AddressEntry_T *
he_get_from_remaining (T he)
{
  SocketHE_AddressEntry_T *entry;

  if (he->next_ipv6)
    {
      entry = he->next_ipv6;
      he->next_ipv6 = entry->next;
      return entry;
    }

  if (he->next_ipv4)
    {
      entry = he->next_ipv4;
      he->next_ipv4 = entry->next;
      return entry;
    }

  return NULL;
}

/**
 * he_get_next_address - Get next address to try
 * @he: Happy Eyeballs context
 *
 * Returns: Next address entry, or NULL if none available
 */
static SocketHE_AddressEntry_T *
he_get_next_address (T he)
{
  SocketHE_AddressEntry_T *entry = he_get_from_preferred (he);

  if (!entry)
    entry = he_get_from_remaining (he);

  return entry;
}

/* ============================================================================
 * Socket Creation
 * ============================================================================
 */

/**
 * he_clear_nonblocking - Clear non-blocking mode from socket
 * @fd: File descriptor
 *
 * Note: No public API exists for clearing non-blocking mode on Socket_T,
 * so we use direct fcntl here. Socket_setnonblocking() only enables it.
 *
 * This restores the socket to blocking mode after the Happy Eyeballs
 * racing is complete, providing the expected behavior for callers who
 * want a regular blocking socket.
 */
static void
he_clear_nonblocking (const int fd)
{
  int flags = fcntl (fd, F_GETFL);

  if (flags >= 0)
    fcntl (fd, F_SETFL, flags & ~O_NONBLOCK);
}

/**
 * he_create_socket_for_address - Create non-blocking socket for address
 * @addr: Address to create socket for
 *
 * Creates a socket matching the address family and sets it to non-blocking
 * mode for async connection attempts.
 *
 * Returns: New non-blocking socket or NULL on failure
 */
static Socket_T
he_create_socket_for_address (const struct addrinfo *addr)
{
  Socket_T sock = NULL;

  TRY
  {
    sock = Socket_new (addr->ai_family, addr->ai_socktype, addr->ai_protocol);
  }
  EXCEPT (Socket_Failed) { return NULL; }
  END_TRY;

  TRY { Socket_setnonblocking (sock); }
  EXCEPT (Socket_Failed)
  {
    Socket_free (&sock);
    return NULL;
  }
  END_TRY;

  return sock;
}

/* ============================================================================
 * Connection Attempt Management
 * ============================================================================
 */

/**
 * he_allocate_attempt - Allocate attempt structure
 * @he: Happy Eyeballs context
 * @sock: Socket for this attempt
 * @entry: Address entry being tried
 *
 * Returns: New attempt or NULL on failure
 */
static SocketHE_Attempt_T *
he_allocate_attempt (T he, Socket_T sock, const SocketHE_AddressEntry_T *entry)
{
  SocketHE_Attempt_T *attempt;

  attempt = Arena_alloc (he->arena, sizeof (*attempt), __FILE__, __LINE__);
  if (!attempt)
    return NULL;

  attempt->socket = sock;
  attempt->addr = entry->addr;
  attempt->state = HE_ATTEMPT_CONNECTING;
  attempt->error = 0;
  attempt->start_time_ms = Socket_get_monotonic_ms ();
  attempt->next = NULL;

  return attempt;
}

/**
 * he_add_attempt_to_list - Add attempt to context's attempt list
 * @he: Happy Eyeballs context
 * @attempt: Attempt to add
 */
static void
he_add_attempt_to_list (T he, SocketHE_Attempt_T *attempt)
{
  attempt->next = he->attempts;
  he->attempts = attempt;
  he->attempt_count++;
}

/**
 * he_add_attempt_to_poll - Register attempt with poll
 * @he: Happy Eyeballs context
 * @attempt: Attempt to monitor
 *
 * Returns: 0 on success, -1 on failure
 */
static int
he_add_attempt_to_poll (T he, SocketHE_Attempt_T *attempt)
{
  if (!he->poll)
    return 0;

  TRY { SocketPoll_add (he->poll, attempt->socket, POLL_WRITE, attempt); }
  EXCEPT (SocketPoll_Failed) { return -1; }
  END_TRY;

  return 0;
}

/**
 * he_family_name - Get address family name string
 * @family: Address family (AF_INET or AF_INET6)
 *
 * Returns: "IPv6" for AF_INET6, "IPv4" otherwise
 *
 * Used for logging connection attempts with human-readable family names.
 */
static const char *
he_family_name (const int family)
{
  return (family == AF_INET6) ? "IPv6" : "IPv4";
}

/**
 * he_log_attempt_start - Log connection attempt start
 * @entry: Address entry being tried
 */
static void
he_log_attempt_start (const SocketHE_AddressEntry_T *entry)
{
  SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                   "Started %s connection attempt",
                   he_family_name (entry->family));
}

/**
 * he_log_attempt_fail - Log connection attempt failure
 * @entry: Address entry that failed
 * @error: Error code
 */
static void
he_log_attempt_fail (const SocketHE_AddressEntry_T *entry, int error)
{
  SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                   "%s connection failed: %s", he_family_name (entry->family),
                   strerror (error));
}

/**
 * he_handle_connect_result - Handle connect() result
 * @he: Happy Eyeballs context
 * @attempt: Attempt structure
 * @entry: Address entry
 * @result: Result from connect()
 *
 * Returns: 0 on success or in-progress, -1 on failure
 */
static int
he_handle_connect_result (T he, SocketHE_Attempt_T *attempt,
                          const SocketHE_AddressEntry_T *entry, int result)
{
  if (result == 0)
    {
      he_declare_winner (he, attempt);
      return 0;
    }

  if (errno != EINPROGRESS)
    {
      attempt->state = HE_ATTEMPT_FAILED;
      attempt->error = errno;
      Socket_free (&attempt->socket);
      attempt->socket = NULL;
      he_log_attempt_fail (entry, attempt->error);
      return -1;
    }

  return 0;
}

/**
 * he_register_attempt - Register attempt with poll and list
 * @he: Happy Eyeballs context
 * @attempt: Attempt to register
 * @entry: Address entry
 *
 * Returns: 0 on success, -1 on failure
 */
static int
he_register_attempt (T he, SocketHE_Attempt_T *attempt,
                     const SocketHE_AddressEntry_T *entry)
{
  he_add_attempt_to_list (he, attempt);

  if (he_add_attempt_to_poll (he, attempt) < 0)
    {
      he->attempts = attempt->next;
      he->attempt_count--;
      Socket_free (&attempt->socket);
      return -1;
    }

  he_log_attempt_start (entry);
  return 0;
}

/**
 * he_initiate_connect - Initiate non-blocking connect
 * @he: Happy Eyeballs context
 * @attempt: Attempt structure
 * @entry: Address entry
 *
 * Returns: 0 on success/in-progress, -1 on failure
 */
static int
he_initiate_connect (T he, SocketHE_Attempt_T *attempt,
                     SocketHE_AddressEntry_T *entry)
{
  int result = connect (Socket_fd (attempt->socket), entry->addr->ai_addr,
                        entry->addr->ai_addrlen);

  if (he_handle_connect_result (he, attempt, entry, result) < 0)
    return -1;

  if (he->state == HE_STATE_CONNECTED)
    return 0;

  return he_register_attempt (he, attempt, entry);
}

/**
 * he_create_attempt_socket - Create socket for connection attempt
 * @entry: Address entry to connect to
 *
 * Returns: Socket on success, NULL on failure
 */
static Socket_T
he_create_attempt_socket (const SocketHE_AddressEntry_T *entry)
{
  Socket_T sock = he_create_socket_for_address (entry->addr);
  if (!sock)
    he_log_attempt_fail (entry, errno);
  return sock;
}

/**
 * he_start_attempt - Start connection attempt for address
 * @he: Happy Eyeballs context
 * @entry: Address entry to connect to
 *
 * Returns: 0 on success, -1 on failure
 */
static int
he_start_attempt (T he, SocketHE_AddressEntry_T *entry)
{
  Socket_T sock;
  SocketHE_Attempt_T *attempt;

  if (entry->tried)
    return -1;

  entry->tried = 1;

  if (he->attempt_count >= he->config.max_attempts)
    {
      entry->tried = 0; /* Allow potential retry */
      return -1;
    }

  sock = he_create_attempt_socket (entry);
  if (!sock)
    return -1;

  attempt = he_allocate_attempt (he, sock, entry);
  if (!attempt)
    {
      Socket_free (&sock);
      return -1;
    }

  return he_initiate_connect (he, attempt, entry);
}

/* ============================================================================
 * Attempt Cleanup
 * ============================================================================
 */

/**
 * he_close_attempt - Close single attempt socket
 * @he: Happy Eyeballs context
 * @attempt: Attempt to close
 */
static void
he_close_attempt (T he, SocketHE_Attempt_T *attempt)
{
  if (!attempt->socket)
    return;

  if (he->poll && attempt->state == HE_ATTEMPT_CONNECTING)
    SocketPoll_del (he->poll, attempt->socket);

  if (attempt->socket != he->winner)
    Socket_free (&attempt->socket);
}

/**
 * he_cleanup_attempts - Close all pending connection attempts
 * @he: Happy Eyeballs context
 */
static void
he_cleanup_attempts (T he)
{
  HE_FOREACH_ATTEMPT (he, attempt)
  he_close_attempt (he, attempt);

  he->attempts = NULL;
  he->attempt_count = 0;
}

/* ============================================================================
 * Winner Declaration
 * ============================================================================
 */

/**
 * he_cancel_losing_attempts - Cancel all non-winning attempts
 * @he: Happy Eyeballs context
 * @winner: The winning attempt
 */
static void
he_cancel_losing_attempts (T he, const SocketHE_Attempt_T *winner)
{
  HE_FOREACH_ATTEMPT (he, other)
  {
    if (other == winner || !other->socket)
      continue;

    if (he->poll && other->state == HE_ATTEMPT_CONNECTING)
      SocketPoll_del (he->poll, other->socket);

    Socket_free (&other->socket);
  }
}

/**
 * he_declare_winner - Handle successful connection
 * @he: Happy Eyeballs context
 * @attempt: Winning attempt
 */
static void
he_declare_winner (T he, SocketHE_Attempt_T *attempt)
{
  attempt->state = HE_ATTEMPT_CONNECTED;
  he->winner = attempt->socket;
  he->state = HE_STATE_CONNECTED;

  if (he->poll)
    SocketPoll_del (he->poll, attempt->socket);

  he_cancel_dns (he);
  he_cancel_losing_attempts (he, attempt);

  SocketLog_emitf (SOCKET_LOG_INFO, SOCKET_LOG_COMPONENT,
                   "Happy Eyeballs connected to %s:%d via %s", he->host,
                   he->port, he_family_name (attempt->addr->ai_family));
}

/**
 * he_fail_attempt - Mark attempt as failed
 * @he: Happy Eyeballs context
 * @attempt: Failed attempt
 * @error: Error code
 */
static void
he_fail_attempt (T he, SocketHE_Attempt_T *attempt, int error)
{
  attempt->state = HE_ATTEMPT_FAILED;
  attempt->error = error;

  if (he->poll && attempt->socket)
    SocketPoll_del (he->poll, attempt->socket);

  if (attempt->socket)
    {
      Socket_free (&attempt->socket);
      attempt->socket = NULL;
    }

  SocketLog_emitf (
      SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT, "%s connection failed: %s",
      he_family_name (attempt->addr->ai_family), strerror (error));
}

/* ============================================================================
 * Attempt Completion Checking
 * ============================================================================
 */

/**
 * he_poll_attempt_status - Poll single attempt for completion
 * @fd: File descriptor to check
 * @revents: Output for poll results
 *
 * Returns: 1 if ready, 0 if pending, -1 on error
 *
 * Uses poll() with zero timeout for non-blocking status check.
 * EINTR is handled gracefully by returning 0 (still pending).
 */
static int
he_poll_attempt_status (const int fd, short *revents)
{
  struct pollfd pfd;
  int result;

  pfd.fd = fd;
  pfd.events = POLLOUT;
  pfd.revents = 0;

  result = poll (&pfd, 1, 0);
  if (result < 0)
    return (errno == EINTR) ? 0 : -1;

  *revents = pfd.revents;
  return result;
}

/**
 * he_check_socket_error - Check socket for connection error
 * @fd: File descriptor to check
 *
 * Returns: 0 if connected, error code otherwise
 *
 * Uses getsockopt(SO_ERROR) to retrieve the pending socket error,
 * which is the standard POSIX way to check async connect() result.
 */
static int
he_check_socket_error (const int fd)
{
  int error = 0;
  socklen_t len = sizeof (error);

  if (getsockopt (fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
    return errno;

  return error;
}

/**
 * he_check_attempt_timeout - Check if attempt has timed out
 * @he: Happy Eyeballs context
 * @attempt: Attempt to check
 *
 * Returns: 1 if timed out, 0 otherwise
 */
static int
he_check_attempt_timeout (const T he, const SocketHE_Attempt_T *attempt)
{
  int64_t elapsed;

  if (he->config.attempt_timeout_ms <= 0)
    return 0;

  int64_t now_ms = Socket_get_monotonic_ms ();
  elapsed = (now_ms > attempt->start_time_ms)
                ? (now_ms - attempt->start_time_ms)
                : 0;
  return elapsed >= he->config.attempt_timeout_ms;
}

/**
 * he_handle_poll_error - Handle poll error for attempt
 * @he: Happy Eyeballs context
 * @attempt: Attempt with error
 * @fd: File descriptor
 *
 * Returns: -1 always (indicates failure)
 */
static int
he_handle_poll_error (T he, SocketHE_Attempt_T *attempt, int fd)
{
  int error = he_check_socket_error (fd);
  he_fail_attempt (he, attempt, error ? error : ECONNREFUSED);
  return -1;
}

/**
 * he_handle_poll_success - Handle successful poll for attempt
 * @he: Happy Eyeballs context
 * @attempt: Attempt to check
 * @fd: File descriptor
 *
 * Returns: 1 if connected, -1 if error
 */
static int
he_handle_poll_success (T he, SocketHE_Attempt_T *attempt, int fd)
{
  int error = he_check_socket_error (fd);
  if (error != 0)
    {
      he_fail_attempt (he, attempt, error);
      return -1;
    }

  he_declare_winner (he, attempt);
  return 1;
}

/**
 * he_handle_pending_poll - Handle pending poll state
 * @he: Happy Eyeballs context
 * @attempt: Attempt being checked
 *
 * Returns: 0 if still pending, -1 if timed out
 */
static int
he_handle_pending_poll (T he, SocketHE_Attempt_T *attempt)
{
  if (he_check_attempt_timeout (he, attempt))
    {
      he_fail_attempt (he, attempt, ETIMEDOUT);
      return -1;
    }
  return 0;
}

/**
 * he_process_poll_result - Process poll result for attempt
 * @he: Happy Eyeballs context
 * @attempt: Attempt being checked
 * @fd: File descriptor
 * @poll_result: Result from poll (0=pending, >0=ready, <0=error)
 * @revents: Poll events if ready
 *
 * Returns: 1 if connected, 0 if pending, -1 if failed
 */
static int
he_process_poll_result (T he, SocketHE_Attempt_T *attempt, int fd,
                        int poll_result, short revents)
{
  if (poll_result < 0)
    {
      he_fail_attempt (he, attempt, errno);
      return -1;
    }

  if (poll_result == 0)
    return he_handle_pending_poll (he, attempt);

  if (revents & (POLLERR | POLLHUP | POLLNVAL))
    return he_handle_poll_error (he, attempt, fd);

  return he_handle_poll_success (he, attempt, fd);
}

/**
 * he_check_attempt_completion - Check if attempt has completed
 * @he: Happy Eyeballs context
 * @attempt: Attempt to check
 *
 * Returns: 1 if connected, 0 if still pending, -1 if failed
 */
static int
he_check_attempt_completion_with_events (T he, SocketHE_Attempt_T *attempt, unsigned poll_events)
{
  short revents = (short) poll_events;
  int fd;
  int poll_result;
  short actual_revents;
  bool has_event = (poll_events != 0);

  if (attempt->state != HE_ATTEMPT_CONNECTING)
    return attempt->state == HE_ATTEMPT_CONNECTED ? 1 : -1;

  if (!attempt->socket)
    return -1;

  fd = Socket_fd (attempt->socket);

  if (!has_event) {
    poll_result = he_poll_attempt_status (fd, &actual_revents);
    if (poll_result < 0)
      return -1;
    revents = actual_revents;
  } else {
    poll_result = 1;
    actual_revents = revents;
  }

  return he_process_poll_result (he, attempt, fd, poll_result, revents);
}

static int
he_check_attempt_completion (T he, SocketHE_Attempt_T *attempt)
{
  return he_check_attempt_completion_with_events (he, attempt, 0);
}

/**
 * he_check_attempts - Check all active connection attempts
 * @he: Happy Eyeballs context
 */
static void
he_check_attempts (T he)
{
  HE_FOREACH_ATTEMPT (he, attempt)
  {
    if (he->state == HE_STATE_CONNECTED)
      break;

    if (attempt->state == HE_ATTEMPT_CONNECTING)
      he_check_attempt_completion (he, attempt);
  }
}

/**
 * he_all_attempts_done - Check if all attempts are complete
 * @he: Happy Eyeballs context
 *
 * Returns: 1 if all done, 0 if some still pending
 */
static int
he_all_attempts_done (const T he)
{
  if (he->next_ipv6 || he->next_ipv4)
    return 0;

  HE_FOREACH_ATTEMPT (he, attempt)
  {
    if (attempt->state == HE_ATTEMPT_CONNECTING)
      return 0;
  }

  return 1;
}

/* ============================================================================
 * State Transitions
 * ============================================================================
 */

/**
 * he_set_error - Set error message in context
 * @he: Happy Eyeballs context
 * @reason: Error message
 *
 * Checks if reason already points to error_buf to avoid self-copy which
 * triggers -Wrestrict warnings with GCC 13's aggressive inlining + fortify.
 *
 * Uses snprintf with "%s" format for safety against format string injection
 * if reason contains user-influenced data from DNS or socket errors.
 */
static void
he_set_error (T he, const char *reason)
{
  /* Skip if no reason, already set, or reason IS the error_buf */
  if (!reason || he->error_buf[0] != '\0' || reason == he->error_buf)
    return;

  /* Use snprintf for guaranteed null-termination and format safety */
  snprintf (he->error_buf, sizeof (he->error_buf), "%s", reason);
}

/**
 * he_transition_to_failed - Mark operation as failed
 * @he: Happy Eyeballs context
 * @reason: Failure reason
 */
static void
he_transition_to_failed (T he, const char *reason)
{
  he_cleanup_attempts (he); /* Close any pending sockets on failure */

  he->state = HE_STATE_FAILED;
  he_set_error (he, reason);

  SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                   "Happy Eyeballs failed for %s:%d: %s", he->host, he->port,
                   he->error_buf);
}

/* ============================================================================
 * Timer and Timeout Checks
 * ============================================================================
 */

/**
 * he_should_start_fallback - Check if fallback attempt should start
 * @he: Happy Eyeballs context
 *
 * Returns: 1 if should start fallback, 0 otherwise
 */
static int
he_should_start_fallback (const T he)
{
  int64_t elapsed;

  if (!he->fallback_timer_armed || he->first_attempt_time_ms == 0)
    return 0;

  int64_t now_ms = Socket_get_monotonic_ms ();
  elapsed = (now_ms > he->first_attempt_time_ms)
                ? (now_ms - he->first_attempt_time_ms)
                : 0;
  return elapsed >= he->config.first_attempt_delay_ms;
}

/**
 * he_check_total_timeout - Check for total operation timeout
 * @he: Happy Eyeballs context
 *
 * Returns: 1 if timed out, 0 otherwise
 */
static int
he_check_total_timeout (const T he)
{
  if (he->config.total_timeout_ms <= 0)
    return 0;

  int64_t now_ms = Socket_get_monotonic_ms ();
  int64_t elapsed;
  if (now_ms < he->start_time_ms)
    {
      /* Time warp or overflow: treat as expired */
      return 1;
    }
  elapsed = now_ms - he->start_time_ms;
  int64_t total = he->config.total_timeout_ms;
  return elapsed >= total;
}

/* ============================================================================
 * Timeout Calculation Helpers
 * ============================================================================
 */

/**
 * he_apply_timeout_limit - Apply a remaining time limit to timeout
 * @current_timeout: Current timeout value (-1 for infinite)
 * @remaining_ms: Remaining time in milliseconds
 *
 * Returns: Updated timeout value (minimum of current and remaining)
 *
 * Clamps remaining_ms to INT_MAX to avoid overflow when casting to int.
 * A negative or zero remaining_ms returns 0 (immediate timeout).
 */
static int
he_apply_timeout_limit (const int current_timeout, const int64_t remaining_ms)
{
  if (remaining_ms <= 0)
    return 0;

  int64_t clamped = (remaining_ms > INT_MAX) ? INT_MAX : remaining_ms;

  if (current_timeout < 0 || clamped < current_timeout)
    return (int)clamped;

  return current_timeout;
}

/**
 * he_calculate_total_timeout_remaining - Calculate remaining total timeout
 * @he: Happy Eyeballs context
 * @current_timeout: Current timeout value
 *
 * Returns: Updated timeout accounting for total timeout
 */
static int
he_calculate_total_timeout_remaining (const T he, int current_timeout)
{
  int64_t remaining;

  if (he->config.total_timeout_ms <= 0)
    return current_timeout;

  int64_t now_ms = Socket_get_monotonic_ms ();
  if (now_ms < he->start_time_ms)
    {
      return 0; /* Time warp: expired */
    }
  int64_t elapsed = now_ms - he->start_time_ms;

  int64_t total = he->config.total_timeout_ms;
  if (total <= elapsed || total <= 0)
    {
      return 0;
    }
  remaining = total - elapsed;
  return he_apply_timeout_limit (current_timeout, remaining);
}

/**
 * he_calculate_fallback_timeout_remaining - Calculate remaining fallback timer
 * @he: Happy Eyeballs context
 * @current_timeout: Current timeout value
 *
 * Returns: Updated timeout accounting for fallback timer
 */
static int
he_calculate_fallback_timeout_remaining (const T he, int current_timeout)
{
  int64_t remaining;

  if (he->state != HE_STATE_CONNECTING || !he->fallback_timer_armed
      || he->first_attempt_time_ms <= 0)
    return current_timeout;

  int64_t now_ms = Socket_get_monotonic_ms ();
  if (now_ms < he->first_attempt_time_ms)
    {
      return 0; /* Time warp: expired */
    }
  int64_t elapsed = now_ms - he->first_attempt_time_ms;

  int64_t delay = he->config.first_attempt_delay_ms;
  if (delay <= elapsed || delay <= 0)
    {
      return 0;
    }
  remaining = delay - elapsed;
  return he_apply_timeout_limit (current_timeout, remaining);
}

/**
 * he_calculate_next_timeout - Calculate next timeout for poll
 * @he: Happy Eyeballs context
 * @timeout: Current timeout (or -1)
 *
 * Returns: Updated timeout value
 */
static int
he_calculate_next_timeout (const T he, int timeout)
{
  timeout = he_calculate_total_timeout_remaining (he, timeout);
  timeout = he_calculate_fallback_timeout_remaining (he, timeout);
  return timeout;
}

/* ============================================================================
 * Async State Machine Processing
 * ============================================================================
 */

/**
 * he_start_first_attempt - Start first connection attempt
 * @he: Happy Eyeballs context
 */
static void
he_start_first_attempt (T he)
{
  SocketHE_AddressEntry_T *entry;

  if (he->attempt_count != 0)
    return;

  entry = he_get_next_address (he);
  if (!entry)
    return;

  he_start_attempt (he, entry);
  he->first_attempt_time_ms = Socket_get_monotonic_ms ();
  he->fallback_timer_armed = 1;
}

/**
 * he_start_fallback_attempt - Start fallback family attempt
 * @he: Happy Eyeballs context
 */
static void
he_start_fallback_attempt (T he)
{
  SocketHE_AddressEntry_T *entry;

  if (!he_should_start_fallback (he))
    return;

  if (he->attempt_count >= he->config.max_attempts)
    return;

  entry = he_get_next_address (he);
  if (entry)
    he_start_attempt (he, entry);

  he->fallback_timer_armed = 0;
}

/**
 * he_check_complete_failure - Check if all attempts have failed
 * @he: Happy Eyeballs context
 */
static void
he_check_complete_failure (T he)
{
  if (!he_all_attempts_done (he) || he->state == HE_STATE_CONNECTED)
    return;

  snprintf (he->error_buf, sizeof (he->error_buf),
            "All connection attempts failed");
  he_transition_to_failed (he, he->error_buf);
}

/**
 * he_handle_total_timeout - Handle total timeout expiry
 * @he: Happy Eyeballs context
 */
static void
he_handle_total_timeout (T he)
{
  snprintf (he->error_buf, sizeof (he->error_buf), "Connection timed out");
  he_cleanup_attempts (he);
  he_transition_to_failed (he, he->error_buf);
}

/**
 * he_process_connecting_state - Process connections in CONNECTING state
 * @he: Happy Eyeballs context
 */
static void
he_process_connecting_state (T he)
{
  if (he_check_total_timeout (he))
    {
      he_handle_total_timeout (he);
      return;
    }

  he_check_attempts (he);

  if (he->state == HE_STATE_CONNECTED)
    return;

  he_start_first_attempt (he);
  he_start_fallback_attempt (he);
  he_check_complete_failure (he);
}

/**
 * he_process_idle_state - Process IDLE state
 * @he: Happy Eyeballs context
 */
static void
he_process_idle_state (T he)
{
  if (he->dns)
    he_start_dns_resolution (he);
}

/**
 * he_process_resolving_state - Process RESOLVING state
 * @he: Happy Eyeballs context
 */
static void
he_process_resolving_state (T he)
{
  if (he->dns)
    {
      SocketDNS_check (he->dns);
      he_process_dns_completion (he);
    }
}

/**
 * SocketHappyEyeballs_process - Process events and advance state machine
 * @he: Happy Eyeballs context
 *
 * Thread-safe: No
 */
void
SocketHappyEyeballs_process (T he)
{
  assert (he);

  switch (he->state)
    {
    case HE_STATE_IDLE:
      he_process_idle_state (he);
      break;

    case HE_STATE_RESOLVING:
      he_process_resolving_state (he);
      break;

    case HE_STATE_CONNECTING:
      he_process_connecting_state (he);
      break;

    case HE_STATE_CONNECTED:
    case HE_STATE_FAILED:
    case HE_STATE_CANCELLED:
      break;
    }
}

void
SocketHappyEyeballs_process_events (T he, SocketEvent_T *events, int num_events)
{
  assert (he);
  if (num_events <= 0 || !events)
    return;

  for (int i = 0; i < num_events; ++i) {
    SocketEvent_T *ev = &events[i];
    void *data = ev->data;
    unsigned ev_events = ev->events;

    if (data == he && he->dns_poll_wrapper && ev->socket == he->dns_poll_wrapper) {
      /* DNS completion event */
      he_process_dns_event (he);
    } else if (data != NULL) {
      /* Connection attempt event */
      SocketHE_Attempt_T *attempt = (SocketHE_Attempt_T *) data;
      he_check_attempt_completion_with_events (he, attempt, ev_events);
    }
    /* Ignore other events on poll */
  }
}

/* ============================================================================
 * Asynchronous API
 * ============================================================================
 */

/**
 * he_validate_start_params - Validate parameters for start
 * @dns: DNS resolver
 * @poll: Poll instance
 * @host: Hostname
 * @port: Port number
 *
 * Validates all input parameters for the async start API.
 * Uses asserts for development-time checks; parameters are
 * marked as used to avoid warnings in release builds.
 */
static void
he_validate_start_params (const SocketDNS_T dns, const SocketPoll_T poll,
                          const char *host, int port)
{
  assert (dns);
  assert (poll);
  assert (host);
  assert (port > 0 && port <= SOCKET_MAX_PORT);
  (void)dns;
  (void)poll;
  (void)host;
  (void)port;
}

/**
 * SocketHappyEyeballs_start - Start async Happy Eyeballs connection
 * @dns: DNS resolver instance
 * @poll: Poll instance for connection monitoring
 * @host: Hostname or IP address
 * @port: Port number (1-65535)
 * @config: Configuration options (NULL for defaults)
 *
 * Returns: Happy Eyeballs context handle
 * Raises: SocketHE_Failed on initialization failure
 * Thread-safe: No
 */
T
SocketHappyEyeballs_start (SocketDNS_T dns, SocketPoll_T poll,
                           const char *host, int port,
                           const SocketHE_Config_T *config)
{
  T he;

  he_validate_start_params (dns, poll, host, port);

  he = he_create_context (dns, poll, host, port, config);
  if (!he)
    {
      SOCKET_RAISE_MSG (SocketHE, SocketHE_Failed,
                        "Failed to create Happy Eyeballs context");
    }

  if (he_start_dns_resolution (he) < 0)
    {
      char errmsg_copy[SOCKET_HE_ERROR_BUFSIZE];
      snprintf (errmsg_copy, sizeof (errmsg_copy), "%s", he->error_buf);
      SocketHappyEyeballs_free (&he);
      SOCKET_RAISE_MSG (SocketHE, SocketHE_Failed, "%s", errmsg_copy);
    }

  return he;
}

/**
 * SocketHappyEyeballs_poll - Check if operation is complete
 * @he: Happy Eyeballs context
 *
 * Returns: 1 if complete (success or failure), 0 if still in progress
 * Thread-safe: No
 */
int
SocketHappyEyeballs_poll (T he)
{
  assert (he);
  return he->state == HE_STATE_CONNECTED || he->state == HE_STATE_FAILED
         || he->state == HE_STATE_CANCELLED;
}

/**
 * SocketHappyEyeballs_result - Get connected socket from completed operation
 * @he: Happy Eyeballs context
 *
 * Returns: Connected socket, or NULL if failed/cancelled/pending
 * Thread-safe: No
 */
Socket_T
SocketHappyEyeballs_result (T he)
{
  Socket_T result;

  assert (he);

  if (he->state != HE_STATE_CONNECTED)
    return NULL;

  result = he->winner;
  he->winner = NULL;

  /* Clear the socket pointer in the winning attempt to prevent double-free
   * when he_cleanup_attempts is called during SocketHappyEyeballs_free */
  if (result)
    {
      HE_FOREACH_ATTEMPT (he, attempt)
      {
        if (attempt->socket == result)
          {
            attempt->socket = NULL;
            break;
          }
      }
      he_clear_nonblocking (Socket_fd (result));
    }

  return result;
}

/**
 * SocketHappyEyeballs_state - Get current operation state
 * @he: Happy Eyeballs context
 *
 * Returns: Current state
 * Thread-safe: No
 */
SocketHE_State
SocketHappyEyeballs_state (T he)
{
  assert (he);
  return he->state;
}

/**
 * SocketHappyEyeballs_error - Get error message for failed operation
 * @he: Happy Eyeballs context
 *
 * Returns: Error message string, or NULL if no error
 * Thread-safe: No
 */
const char *
SocketHappyEyeballs_error (T he)
{
  assert (he);

  if (he->state != HE_STATE_FAILED)
    return NULL;

  return he->error_buf[0] ? he->error_buf : "Unknown error";
}

/**
 * SocketHappyEyeballs_next_timeout_ms - Get time until next timer expiry
 * @he: Happy Eyeballs context
 *
 * Returns: Milliseconds until next timeout, or -1 if no pending timers
 * Thread-safe: No
 */
int
SocketHappyEyeballs_next_timeout_ms (T he)
{
  assert (he);

  if (he->state != HE_STATE_RESOLVING && he->state != HE_STATE_CONNECTING)
    return -1;

  return he_calculate_next_timeout (he, -1);
}

/* ============================================================================
 * Synchronous API Helpers
 * ============================================================================
 */

/**
 * sync_build_poll_set - Build poll array for active attempts
 * @he: Happy Eyeballs context
 * @pfds: Poll file descriptor array (output)
 * @attempt_map: Attempt pointer array (output)
 *
 * Returns: Number of descriptors added
 */
static int
sync_build_poll_set (const T he, struct pollfd *pfds,
                     SocketHE_Attempt_T **attempt_map)
{
  int nfds = 0;

  for (SocketHE_Attempt_T *attempt = he->attempts;
       attempt && nfds < SOCKET_HE_MAX_ATTEMPTS; attempt = attempt->next)
    {
      if (attempt->state != HE_ATTEMPT_CONNECTING || !attempt->socket)
        continue;

      pfds[nfds].fd = Socket_fd (attempt->socket);
      pfds[nfds].events = POLLOUT;
      pfds[nfds].revents = 0;
      attempt_map[nfds] = attempt;
      nfds++;
    }

  return nfds;
}

/**
 * sync_calculate_poll_timeout - Calculate timeout for sync poll
 * @he: Happy Eyeballs context
 *
 * Returns: Timeout in milliseconds
 */
static int
sync_calculate_poll_timeout (const T he)
{
  int timeout = SOCKET_HE_SYNC_POLL_INTERVAL_MS;

  if (he_should_start_fallback (he))
    return 0;

  return he_calculate_fallback_timeout_remaining (he, timeout);
}

/**
 * sync_process_poll_results - Process poll results for sync API
 * @he: Happy Eyeballs context
 * @pfds: Poll file descriptor array (read-only)
 * @attempt_map: Attempt pointer array
 * @nfds: Number of descriptors
 *
 * Iterates poll results and checks each attempt for completion.
 * Stops early if a connection succeeds.
 */
static void
sync_process_poll_results (T he, const struct pollfd *pfds,
                           SocketHE_Attempt_T **attempt_map, const int nfds)
{
  for (int i = 0; i < nfds && he->state != HE_STATE_CONNECTED; i++)
    {
      if (pfds[i].revents)
        he_check_attempt_completion (he, attempt_map[i]);
    }
}

/**
 * sync_check_attempt_timeouts - Check timeouts for all attempts
 * @he: Happy Eyeballs context
 */
static void
sync_check_attempt_timeouts (T he)
{
  HE_FOREACH_ATTEMPT (he, attempt)
  {
    if (he->state == HE_STATE_CONNECTED)
      break;
    if (attempt->state != HE_ATTEMPT_CONNECTING)
      continue;

    if (he_check_attempt_timeout (he, attempt))
      he_fail_attempt (he, attempt, ETIMEDOUT);
  }
}

/**
 * sync_try_start_fallback - Try to start fallback attempt
 * @he: Happy Eyeballs context
 *
 * Returns: 1 if connected immediately, 0 otherwise
 */
static int
sync_try_start_fallback (T he)
{
  SocketHE_AddressEntry_T *entry;

  if (!he_should_start_fallback (he))
    return 0;

  if (he->attempt_count >= he->config.max_attempts)
    return 0;

  entry = he_get_next_address (he);
  if (entry)
    {
      if (he_start_attempt (he, entry) == 0 && he->state == HE_STATE_CONNECTED)
        return 1;
    }

  he->fallback_timer_armed = 0;
  return 0;
}

/**
 * sync_should_exit_loop - Check if sync loop should exit
 * @he: Happy Eyeballs context (read-only)
 * @nfds: Number of poll descriptors
 *
 * Returns: 1 if should exit, 0 otherwise
 *
 * Exit conditions: no fds to poll, no pending fallback, all attempts done.
 */
static int
sync_should_exit_loop (const T he, const int nfds)
{
  return nfds == 0 && !he_should_start_fallback (he)
         && he_all_attempts_done (he);
}

/**
 * sync_check_all_failed - Check if all attempts failed
 * @he: Happy Eyeballs context
 */
static void
sync_check_all_failed (T he)
{
  if (he_all_attempts_done (he) && he->state != HE_STATE_CONNECTED)
    {
      snprintf (he->error_buf, sizeof (he->error_buf),
                "All connection attempts failed");
    }
}

/**
 * sync_handle_timeout_check - Check for total timeout in sync loop
 * @he: Happy Eyeballs context
 *
 * Returns: 1 if timed out, 0 otherwise
 */
static int
sync_handle_timeout_check (T he)
{
  if (!he_check_total_timeout (he))
    return 0;

  snprintf (he->error_buf, sizeof (he->error_buf), "Connection timed out");
  return 1;
}

/**
 * sync_do_poll - Execute poll syscall with error handling
 * @pfds: Poll file descriptors
 * @nfds: Number of descriptors
 * @timeout: Timeout in milliseconds
 *
 * Returns: poll() result, or 0 on EINTR
 *
 * Handles EINTR gracefully by returning 0 (continue polling).
 * Other errors return negative values.
 */
static int
sync_do_poll (struct pollfd *pfds, const int nfds, const int timeout)
{
  int result = poll (pfds, nfds, timeout);

  if (result < 0 && errno == EINTR)
    return 0;

  return result;
}

/* REMOVED: Poll cycle now handled by SocketPoll_wait + process_events in unified loop. */

/* REMOVED: Sync loop iteration unified into connect() main loop using process_events and process calls. */

/* REMOVED: Synchronous loop now unified with event-driven process_events + process in connect(). Uses internal poll for blocking wait. */

/* REMOVED: Result retrieval and failure handling now unified in connect() loop and SocketHappyEyeballs_result(). */

/* ============================================================================
 * Synchronous API
 * ============================================================================
 */

/* REMOVED: Sync mode now uses unified async state machine with internal DNS and poll resources. No separate creation needed. */

/* REMOVED: Address sorting and state transition now handled in unified he_handle_dns_success(). */

/* REMOVED: Error message handling unified; no separate copy needed. */

/* REMOVED: Error raising now inlined in connect() using SOCKET_RAISE_FMT for formatted messages. */

/**
 * SocketHappyEyeballs_connect - Connect using Happy Eyeballs (blocking)
 * @host: Hostname or IP address to connect to
 * @port: Port number (1-65535)
 * @config: Configuration options (NULL for defaults)
 *
 * Returns: Connected socket
 * Raises: SocketHE_Failed on connection failure or timeout
 * Thread-safe: Yes
 */
Socket_T
SocketHappyEyeballs_connect (const char *host, int port,
                             const SocketHE_Config_T *config)
{
  T he = NULL;
  Socket_T volatile sock = NULL;
  SocketDNS_T temp_dns = NULL;
  SocketPoll_T temp_poll = NULL;
  SocketEvent_T *events = NULL;
  const char *volatile err_msg = NULL;

  assert (host);
  assert (port > 0 && port <= SOCKET_MAX_PORT);

  TRY
  {
    temp_dns = SocketDNS_new ();
  }
  EXCEPT (SocketDNS_Failed)
  {
    err_msg = Socket_GetLastError ();
    SOCKET_RAISE_FMT (SocketHE, SocketHE_Failed, "Failed to create DNS resolver: %s", err_msg ? err_msg : "Unknown error");
  }
  END_TRY;

  TRY
  {
    temp_poll = SocketPoll_new (SOCKET_HE_MAX_ATTEMPTS);
  }
  EXCEPT (SocketPoll_Failed)
  {
    SocketDNS_free (&temp_dns);
    err_msg = Socket_GetLastError ();
    SOCKET_RAISE_FMT (SocketHE, SocketHE_Failed, "Failed to create poll: %s", err_msg ? err_msg : "Unknown error");
  }
  END_TRY;

  TRY
  {
    he = he_create_context (temp_dns, temp_poll, host, port, config);
    he->owns_dns = 1;
    he->owns_poll = 1;
  }
  EXCEPT (SocketHE_Failed)
  {
    SocketPoll_free (&temp_poll);
    SocketDNS_free (&temp_dns);
    err_msg = Socket_GetLastError ();
    SOCKET_RAISE_FMT (SocketHE, SocketHE_Failed, "Failed to create context: %s", err_msg ? err_msg : "Unknown error");
  }
  END_TRY;

  he->state = HE_STATE_IDLE;
  SocketHappyEyeballs_process (he);  // Starts async DNS resolution and poll integration

  // Blocking loop until complete
  while (he->state == HE_STATE_RESOLVING || he->state == HE_STATE_CONNECTING)
    {
      int timeout = SocketHappyEyeballs_next_timeout_ms (he);
      if (timeout == 0)
        {
          he_handle_total_timeout (he);
          break;
        }
      /* Cap to shorter interval for frequent DNS/state checking.
       * Without poll integration for DNS, we need to poll frequently
       * to detect DNS completion and start connection attempts. */
      if (timeout < 0 || timeout > SOCKET_HE_SYNC_POLL_INTERVAL_MS)
        timeout = SOCKET_HE_SYNC_POLL_INTERVAL_MS;

      events = NULL;
      int n = SocketPoll_wait (he->poll, &events, timeout);
      if (n < 0)
        {
          if (errno == EINTR)
            continue;
          char tmp_err[256];
          snprintf (tmp_err, sizeof (tmp_err), "Internal poll failed during connect: %s", strerror (errno));
          he_transition_to_failed (he, tmp_err);
          break;
        }

      SocketHappyEyeballs_process_events (he, events, n);

      SocketHappyEyeballs_process (he);

      // Note: events is internal to poll, no free needed
    }

  if (he->state == HE_STATE_CONNECTED)
    {
      sock = SocketHappyEyeballs_result (he);
    }
  else
    {
      /* Copy error message before freeing context to avoid use-after-free */
      const char *tmp_err = SocketHappyEyeballs_error (he);
      if (tmp_err)
        {
          static _Thread_local char err_buf[512];
          size_t len = strlen (tmp_err);
          if (len >= sizeof (err_buf))
            len = sizeof (err_buf) - 1;
          memcpy (err_buf, tmp_err, len);
          err_buf[len] = '\0';
          err_msg = err_buf;
        }
      else
        {
          err_msg = "Connection failed (unknown reason)";
        }
    }

  SocketHappyEyeballs_free (&he);

  if (!sock)
    {
      SOCKET_RAISE_MSG (SocketHE, SocketHE_Failed, "%s", err_msg);
    }

  return sock;
}

#undef T
