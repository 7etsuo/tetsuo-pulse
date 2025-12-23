/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#include "socket/SocketHappyEyeballs-private.h"
#include "socket/SocketHappyEyeballs.h"

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"
#include "dns/SocketDNSResolver.h"
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

const Except_T SocketHE_Failed
    = { &SocketHE_Failed, "Happy Eyeballs connection failed" };

SOCKET_DECLARE_MODULE_EXCEPTION (SocketHE);

#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketHE, e)

static void he_cancel_dns (T he);
static int he_start_dns_resolution (T he);
static void he_process_dns_completion (T he);
static void he_sort_addresses (T he);
static SocketHE_AddressEntry_T *he_get_next_address (T he);
static void he_dns_callback (SocketDNSResolver_Query_T query,
                             const SocketDNSResolver_Result *result, int error,
                             void *userdata);
static struct addrinfo *
he_convert_resolver_result (const SocketDNSResolver_Result *result, int port);
static void he_free_converted_addrinfo (struct addrinfo *ai);

static int he_start_attempt (T he, SocketHE_AddressEntry_T *entry);
static int he_initiate_connect (T he, SocketHE_Attempt_T *attempt,
                                SocketHE_AddressEntry_T *entry);
static void he_check_attempts (T he);
static void he_cleanup_attempts (T he);
static void he_declare_winner (T he, SocketHE_Attempt_T *attempt);
static void he_fail_attempt (T he, SocketHE_Attempt_T *attempt, int error);
static int he_all_attempts_done (const T he);

static void he_transition_to_failed (T he, const char *reason);
static int he_should_start_fallback (const T he);
static int he_check_total_timeout (const T he);

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

static void
he_init_context_fields (T he, const SocketDNSResolver_T resolver,
                        const SocketPoll_T poll, const int port)
{
  he->port = port;
  he->resolver = resolver;
  he->poll = poll;
  he->state = HE_STATE_IDLE;
  he->start_time_ms = Socket_get_monotonic_ms ();
}

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

static T
he_create_context (const SocketDNSResolver_T resolver, const SocketPoll_T poll,
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

  he_init_context_fields (he, resolver, poll, port);
  return he;
}

static void
he_free_resolved (T he)
{
  if (he->resolved)
    {
      he_free_converted_addrinfo (he->resolved);
      he->resolved = NULL;
    }
}

static void
he_free_owned_resources (T he)
{
  if (he->owns_resolver && he->resolver)
    SocketDNSResolver_free (&he->resolver);

  /* Dispose resolver's arena after freeing resolver (only if we created it) */
  if (he->owns_resolver && he->resolver_arena)
    Arena_dispose (&he->resolver_arena);

  if (he->owns_poll && he->poll)
    SocketPoll_free (&he->poll);

  if (he->arena)
    Arena_dispose (&he->arena);
}

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

static void
he_cancel_dns (T he)
{
  if (he->dns_query && he->resolver)
    {
      SocketDNSResolver_cancel (he->resolver, he->dns_query);
      /* Process immediately to invoke the cancellation callback while
       * the HE context is still valid. This prevents use-after-free if
       * the resolver is freed after the HE context. */
      SocketDNSResolver_process (he->resolver, 0);
      he->dns_query = NULL;
    }
}

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
 * @brief Free addrinfo list created by he_convert_resolver_result.
 *
 * Our allocation pattern embeds sockaddr in the same allocation as addrinfo,
 * so we need a custom free function instead of freeaddrinfo().
 */
static void
he_free_converted_addrinfo (struct addrinfo *ai)
{
  while (ai)
    {
      struct addrinfo *next = ai->ai_next;
      free (ai); /* sockaddr is embedded, single free */
      ai = next;
    }
}

/**
 * @brief Convert SocketDNSResolver_Result to struct addrinfo linked list.
 *
 * Creates a POSIX addrinfo chain from resolver results for compatibility
 * with existing address iteration code. Uses a custom allocation pattern
 * where sockaddr is embedded in the same block as addrinfo.
 *
 * @note Must be freed with he_free_converted_addrinfo(), NOT freeaddrinfo().
 */
static struct addrinfo *
he_convert_resolver_result (const SocketDNSResolver_Result *result, int port)
{
  struct addrinfo *head = NULL;
  struct addrinfo **tail = &head;
  size_t i;

  if (!result || result->count == 0)
    return NULL;

  for (i = 0; i < result->count; i++)
    {
      const SocketDNSResolver_Address *addr = &result->addresses[i];
      struct addrinfo *ai;
      size_t addrlen;

      /* Allocate addrinfo structure */
      if (addr->family == AF_INET)
        addrlen = sizeof (struct sockaddr_in);
      else if (addr->family == AF_INET6)
        addrlen = sizeof (struct sockaddr_in6);
      else
        continue; /* Skip unsupported families */

      ai = calloc (1, sizeof (struct addrinfo) + addrlen);
      if (!ai)
        {
          /* Free already allocated entries on failure */
          he_free_converted_addrinfo (head);
          return NULL;
        }

      ai->ai_family = addr->family;
      ai->ai_socktype = SOCK_STREAM;
      ai->ai_protocol = IPPROTO_TCP;
      ai->ai_addrlen = addrlen;
      ai->ai_addr = (struct sockaddr *)(ai + 1);

      if (addr->family == AF_INET)
        {
          struct sockaddr_in *sin = (struct sockaddr_in *)ai->ai_addr;
          sin->sin_family = AF_INET;
          sin->sin_port = htons ((uint16_t)port);
          memcpy (&sin->sin_addr, &addr->addr.v4, sizeof (struct in_addr));
        }
      else
        {
          struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ai->ai_addr;
          sin6->sin6_family = AF_INET6;
          sin6->sin6_port = htons ((uint16_t)port);
          memcpy (&sin6->sin6_addr, &addr->addr.v6, sizeof (struct in6_addr));
        }

      /* Append to list */
      *tail = ai;
      tail = &ai->ai_next;
    }

  return head;
}

/**
 * @brief DNS resolution callback from SocketDNSResolver.
 *
 * Called when DNS resolution completes (success or error).
 * May be called synchronously for IP address literals.
 */
static void
he_dns_callback (SocketDNSResolver_Query_T query,
                 const SocketDNSResolver_Result *result, int error,
                 void *userdata)
{
  T he = (T)userdata;

  (void)query; /* May be NULL for IP literals */

  /* If the HE context is already in a terminal state, ignore this callback.
   * This can happen when the context was cancelled but the callback is
   * still invoked during resolver cleanup. */
  if (he->state == HE_STATE_CANCELLED || he->state == HE_STATE_FAILED
      || he->state == HE_STATE_CONNECTED)
    return;

  he->dns_callback_pending = 1;

  if (error != RESOLVER_OK)
    {
      /* Resolution failed or cancelled */
      if (error == RESOLVER_ERROR_CANCELLED)
        {
          /* Cancellation is normal during shutdown - don't transition to failed */
          he->dns_error = error;
          he->dns_complete = 1;
          he->dns_query = NULL;
          return;
        }

      snprintf (he->error_buf, sizeof (he->error_buf),
                "DNS resolution failed: %s", SocketDNSResolver_strerror (error));
      he->dns_error = error;
      he->dns_complete = 1;
      he->dns_query = NULL;

      /* Only transition if not already done (avoid double transition) */
      if (he->state == HE_STATE_RESOLVING || he->state == HE_STATE_IDLE)
        he_transition_to_failed (he, he->error_buf);
      return;
    }

  /* Convert resolver result to addrinfo format */
  struct addrinfo *resolved = he_convert_resolver_result (result, he->port);
  if (!resolved)
    {
      snprintf (he->error_buf, sizeof (he->error_buf),
                "DNS resolution returned no usable addresses");
      he->dns_error = RESOLVER_ERROR_NXDOMAIN;
      he->dns_complete = 1;
      he->dns_query = NULL;
      he_transition_to_failed (he, he->error_buf);
      return;
    }

  /* Success - store result and transition to connecting */
  he->resolved = resolved;
  he->dns_complete = 1;
  he->dns_query = NULL;

  SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                   "DNS resolution complete for %s:%d", he->host, he->port);

  he_sort_addresses (he);
  he->state = HE_STATE_CONNECTING;
}

static int
he_start_dns_resolution (T he)
{
  int dns_timeout;
  int flags;

  assert (he);
  assert (he->resolver);

  /* Reset callback state */
  he->dns_complete = 0;
  he->dns_callback_pending = 0;

  /* Use RESOLVER_FLAG_BOTH to get both IPv4 and IPv6 addresses */
  flags = RESOLVER_FLAG_BOTH;

  /* Configure resolver timeout before query */
  dns_timeout = he_calculate_dns_timeout (he);
  if (dns_timeout > 0)
    SocketDNSResolver_set_timeout (he->resolver, dns_timeout);

  /* Start async resolution with callback.
   * Note: For IP address literals, the callback fires immediately
   * before resolve() returns, with dns_query = NULL. */
  he->dns_query = SocketDNSResolver_resolve (he->resolver, he->host, flags,
                                             he_dns_callback, he);

  /* Check if callback already fired (IP address fast path) */
  if (he->dns_callback_pending)
    {
      /* Callback already processed the result */
      SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                       "DNS resolution immediate for %s:%d (IP literal)",
                       he->host, he->port);
      return 0;
    }

  /* For hostname queries, dns_query should be non-NULL */
  if (!he->dns_query && !he->dns_complete)
    {
      he_transition_to_failed (he, "Failed to start DNS resolution");
      return -1;
    }

  he->state = HE_STATE_RESOLVING;
  SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                   "Started DNS resolution for %s:%d (timeout=%dms)", he->host,
                   he->port, dns_timeout);

  return 0;
}

static void
he_setup_dns_hints (struct addrinfo *hints)
{
  memset (hints, 0, sizeof (*hints));
  hints->ai_family = AF_UNSPEC;
  hints->ai_socktype = SOCK_STREAM;
  hints->ai_flags = AI_ADDRCONFIG;
}

static void
he_format_port_string (const int port, char *port_str, const size_t port_str_size)
{
  snprintf (port_str, port_str_size, "%d", port);
}

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
 * @brief Process pending DNS resolution.
 *
 * Drives the async resolver to process incoming responses.
 * The actual result handling is done in he_dns_callback().
 */
static void
he_process_dns_completion (T he)
{
  if (!he->resolver)
    return;

  /* If callback already fired, nothing more to do */
  if (he->dns_complete)
    return;

  /* Drive the resolver - this will call he_dns_callback when complete */
  SocketDNSResolver_process (he->resolver, 0);
}

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

static void
he_append_to_family_list (SocketHE_AddressEntry_T *entry,
                          SocketHE_AddressEntry_T ***tail)
{
  **tail = entry;
  *tail = &entry->next;
}

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

static SocketHE_AddressEntry_T *
he_get_next_address (T he)
{
  SocketHE_AddressEntry_T *entry = he_get_from_preferred (he);

  if (!entry)
    entry = he_get_from_remaining (he);

  return entry;
}

static void
he_clear_nonblocking (const int fd)
{
  int flags = fcntl (fd, F_GETFL);

  if (flags >= 0)
    fcntl (fd, F_SETFL, flags & ~O_NONBLOCK);
}

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

static void
he_add_attempt_to_list (T he, SocketHE_Attempt_T *attempt)
{
  attempt->next = he->attempts;
  he->attempts = attempt;
  he->attempt_count++;
}

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

static const char *
he_family_name (const int family)
{
  return (family == AF_INET6) ? "IPv6" : "IPv4";
}

static void
he_log_attempt_start (const SocketHE_AddressEntry_T *entry)
{
  SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                   "Started %s connection attempt",
                   he_family_name (entry->family));
}

static void
he_log_attempt_fail (const SocketHE_AddressEntry_T *entry, int error)
{
  SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                   "%s connection failed: %s", he_family_name (entry->family),
                   strerror (error));
}

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

static Socket_T
he_create_attempt_socket (const SocketHE_AddressEntry_T *entry)
{
  Socket_T sock = he_create_socket_for_address (entry->addr);
  if (!sock)
    he_log_attempt_fail (entry, errno);
  return sock;
}

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

static void
he_cleanup_attempts (T he)
{
  HE_FOREACH_ATTEMPT (he, attempt)
  he_close_attempt (he, attempt);

  he->attempts = NULL;
  he->attempt_count = 0;
}

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

static int
he_check_socket_error (const int fd)
{
  int error = 0;
  socklen_t len = sizeof (error);

  if (getsockopt (fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
    return errno;

  return error;
}

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

static int
he_handle_poll_error (T he, SocketHE_Attempt_T *attempt, int fd)
{
  int error = he_check_socket_error (fd);
  he_fail_attempt (he, attempt, error ? error : ECONNREFUSED);
  return -1;
}

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

static void
he_set_error (T he, const char *reason)
{
  /* Skip if no reason, already set, or reason IS the error_buf */
  if (!reason || he->error_buf[0] != '\0' || reason == he->error_buf)
    return;

  /* Use snprintf for guaranteed null-termination and format safety */
  snprintf (he->error_buf, sizeof (he->error_buf), "%s", reason);
}

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

static int
he_calculate_next_timeout (const T he, int timeout)
{
  timeout = he_calculate_total_timeout_remaining (he, timeout);
  timeout = he_calculate_fallback_timeout_remaining (he, timeout);
  return timeout;
}

/**
 * @brief Check if there are more addresses to try after the current one.
 *
 * Used to determine if fallback timer should be armed. For single-address
 * hosts (e.g., numeric IP addresses), there's no fallback needed so we
 * skip the delay timer (RFC 8305 §5.1 optimization).
 */
static int
he_has_more_addresses (const T he)
{
  return (he->next_ipv6 != NULL || he->next_ipv4 != NULL);
}

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

  /* Only arm fallback timer if there are more addresses to try.
   * For single-address hosts (e.g., numeric IP), skip the delay. */
  he->fallback_timer_armed = he_has_more_addresses (he) ? 1 : 0;
}

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

static void
he_check_complete_failure (T he)
{
  if (!he_all_attempts_done (he) || he->state == HE_STATE_CONNECTED)
    return;

  snprintf (he->error_buf, sizeof (he->error_buf),
            "All connection attempts failed");
  he_transition_to_failed (he, he->error_buf);
}

static void
he_handle_total_timeout (T he)
{
  snprintf (he->error_buf, sizeof (he->error_buf), "Connection timed out");
  he_cleanup_attempts (he);
  he_transition_to_failed (he, he->error_buf);
}

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

static void
he_process_idle_state (T he)
{
  if (he->resolver)
    he_start_dns_resolution (he);
}

static void
he_process_resolving_state (T he)
{
  if (he->resolver)
    he_process_dns_completion (he);
}

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

  for (int i = 0; i < num_events; ++i)
    {
      SocketEvent_T *ev = &events[i];
      void *data = ev->data;
      unsigned ev_events = ev->events;

      /* DNS is now callback-based via SocketDNSResolver, no poll events needed */
      if (data != NULL)
        {
          /* Connection attempt event */
          SocketHE_Attempt_T *attempt = (SocketHE_Attempt_T *)data;
          he_check_attempt_completion_with_events (he, attempt, ev_events);
        }
      /* Ignore other events on poll */
    }
}

static void
he_validate_start_params (const SocketDNSResolver_T resolver,
                          const SocketPoll_T poll, const char *host, int port)
{
  assert (resolver);
  assert (poll);
  assert (host);
  assert (port > 0 && port <= SOCKET_MAX_PORT);
  (void)resolver;
  (void)poll;
  (void)host;
  (void)port;
}

T
SocketHappyEyeballs_start (SocketDNSResolver_T resolver, SocketPoll_T poll,
                           const char *host, int port,
                           const SocketHE_Config_T *config)
{
  T he;

  he_validate_start_params (resolver, poll, host, port);

  he = he_create_context (resolver, poll, host, port, config);
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

int
SocketHappyEyeballs_poll (T he)
{
  assert (he);
  return he->state == HE_STATE_CONNECTED || he->state == HE_STATE_FAILED
         || he->state == HE_STATE_CANCELLED;
}

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

SocketHE_State
SocketHappyEyeballs_state (T he)
{
  assert (he);
  return he->state;
}

const char *
SocketHappyEyeballs_error (T he)
{
  assert (he);

  if (he->state != HE_STATE_FAILED)
    return NULL;

  return he->error_buf[0] ? he->error_buf : "Unknown error";
}

int
SocketHappyEyeballs_next_timeout_ms (T he)
{
  assert (he);

  if (he->state != HE_STATE_RESOLVING && he->state != HE_STATE_CONNECTING)
    return -1;

  return he_calculate_next_timeout (he, -1);
}

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

static int
sync_calculate_poll_timeout (const T he)
{
  int timeout = SOCKET_HE_SYNC_POLL_INTERVAL_MS;

  if (he_should_start_fallback (he))
    return 0;

  return he_calculate_fallback_timeout_remaining (he, timeout);
}

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

static int
sync_should_exit_loop (const T he, const int nfds)
{
  return nfds == 0 && !he_should_start_fallback (he)
         && he_all_attempts_done (he);
}

static void
sync_check_all_failed (T he)
{
  if (he_all_attempts_done (he) && he->state != HE_STATE_CONNECTED)
    {
      snprintf (he->error_buf, sizeof (he->error_buf),
                "All connection attempts failed");
    }
}

static int
sync_handle_timeout_check (T he)
{
  if (!he_check_total_timeout (he))
    return 0;

  snprintf (he->error_buf, sizeof (he->error_buf), "Connection timed out");
  return 1;
}

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

/* REMOVED: Sync mode now uses unified async state machine with internal DNS and poll resources. No separate creation needed. */

/* REMOVED: Address sorting and state transition now handled in unified he_handle_dns_success(). */

/* REMOVED: Error message handling unified; no separate copy needed. */

/* REMOVED: Error raising now inlined in connect() using SOCKET_RAISE_FMT for formatted messages. */

Socket_T
SocketHappyEyeballs_connect (const char *host, int port,
                             const SocketHE_Config_T *config)
{
  T he = NULL;
  Socket_T volatile sock = NULL;
  Arena_T temp_arena = NULL;
  SocketDNSResolver_T temp_resolver = NULL;
  SocketPoll_T temp_poll = NULL;
  SocketEvent_T *events = NULL;
  const char *volatile err_msg = NULL;

  assert (host);
  assert (port > 0 && port <= SOCKET_MAX_PORT);

  temp_arena = Arena_new ();
  if (!temp_arena)
    {
      SOCKET_RAISE_MSG (SocketHE, SocketHE_Failed,
                        "Failed to create arena for DNS resolver");
    }

  TRY
  {
    temp_resolver = SocketDNSResolver_new (temp_arena);
    SocketDNSResolver_load_resolv_conf (temp_resolver);
  }
  EXCEPT (SocketDNSResolver_Failed)
  {
    Arena_dispose (&temp_arena);
    err_msg = Socket_GetLastError ();
    SOCKET_RAISE_FMT (SocketHE, SocketHE_Failed,
                      "Failed to create DNS resolver: %s",
                      err_msg ? err_msg : "Unknown error");
  }
  END_TRY;

  TRY
  {
    temp_poll = SocketPoll_new (SOCKET_HE_MAX_ATTEMPTS);
  }
  EXCEPT (SocketPoll_Failed)
  {
    SocketDNSResolver_free (&temp_resolver);
    Arena_dispose (&temp_arena);
    err_msg = Socket_GetLastError ();
    SOCKET_RAISE_FMT (SocketHE, SocketHE_Failed, "Failed to create poll: %s",
                      err_msg ? err_msg : "Unknown error");
  }
  END_TRY;

  TRY
  {
    he = he_create_context (temp_resolver, temp_poll, host, port, config);
    he->owns_resolver = 1;
    he->resolver_arena = temp_arena; /* Track resolver's arena for cleanup */
    he->owns_poll = 1;
  }
  EXCEPT (SocketHE_Failed)
  {
    SocketPoll_free (&temp_poll);
    SocketDNSResolver_free (&temp_resolver);
    Arena_dispose (&temp_arena);
    err_msg = Socket_GetLastError ();
    SOCKET_RAISE_FMT (SocketHE, SocketHE_Failed,
                      "Failed to create context: %s",
                      err_msg ? err_msg : "Unknown error");
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
      /* If no active attempts yet but we're in CONNECTING state (e.g., DNS
       * just resolved for an IP literal), don't wait - process immediately
       * to start the first connection attempt. */
      if (he->attempt_count == 0 && he->state == HE_STATE_CONNECTING)
        timeout = 0;
      /* Cap to shorter interval for frequent DNS/state checking.
       * Without poll integration for DNS, we need to poll frequently
       * to detect DNS completion and start connection attempts. */
      else if (timeout < 0 || timeout > SOCKET_HE_SYNC_POLL_INTERVAL_MS)
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
