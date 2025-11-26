/**
 * SocketHappyEyeballs.c - Happy Eyeballs (RFC 8305) Implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Implements the Happy Eyeballs algorithm for fast dual-stack connection
 * establishment. Races IPv6 and IPv4 connection attempts with a 250ms
 * delay between attempts to minimize latency when one family is slow.
 *
 * RFC 8305 Key Requirements:
 * - Prefer IPv6 but start IPv4 after 250ms if IPv6 hasn't connected
 * - Interleave addresses by family for better resilience
 * - Cancel losing connections immediately on winner
 * - Implement proper timeout handling
 */

#include "socket/SocketHappyEyeballs.h"
#include "socket/SocketHappyEyeballs-private.h"

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "core/SocketUtil.h"
#include "dns/SocketDNS.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define T SocketHE_T

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "HappyEyeballs"

/* Exception definition */
const Except_T SocketHE_Failed
    = { &SocketHE_Failed, "Happy Eyeballs connection failed" };

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketHE);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketHE, e)

/* ============================================================================
 * Internal Helper Function Declarations
 * ============================================================================ */

static void he_cleanup_attempts (T he);
static void he_cancel_dns (T he);
static int he_start_dns_resolution (T he);
static void he_process_dns_completion (T he);
static void he_sort_addresses (T he);
static SocketHE_AddressEntry_T *he_get_next_address (T he);
static int he_start_attempt (T he, SocketHE_AddressEntry_T *entry);
static void he_check_attempts (T he);
static void he_declare_winner (T he, SocketHE_Attempt_T *attempt);
static void he_fail_attempt (T he, SocketHE_Attempt_T *attempt, int error);
static int he_all_attempts_done (T he);
static void he_transition_to_failed (T he, const char *reason);

/* ============================================================================
 * Configuration Defaults
 * ============================================================================ */

void
SocketHappyEyeballs_config_defaults (SocketHE_Config_T *config)
{
  assert (config);
  config->first_attempt_delay_ms = SOCKET_HE_DEFAULT_FIRST_ATTEMPT_DELAY_MS;
  config->attempt_timeout_ms = SOCKET_HE_DEFAULT_ATTEMPT_TIMEOUT_MS;
  config->total_timeout_ms = SOCKET_HE_DEFAULT_TOTAL_TIMEOUT_MS;
  config->prefer_ipv6 = 1;
  config->max_attempts = SOCKET_HE_DEFAULT_MAX_ATTEMPTS;
}

/* ============================================================================
 * Context Creation and Destruction
 * ============================================================================ */

/**
 * he_create_context - Allocate and initialize Happy Eyeballs context
 * @dns: DNS resolver (may be NULL for sync API)
 * @poll: Poll instance (may be NULL for sync API)
 * @host: Target hostname
 * @port: Target port
 * @config: Configuration options
 *
 * Returns: New context or NULL on failure
 */
static T
he_create_context (SocketDNS_T dns, SocketPoll_T poll, const char *host,
                   int port, const SocketHE_Config_T *config)
{
  T he;
  size_t host_len;

  he = calloc (1, sizeof (*he));
  if (!he)
    return NULL;

  he->arena = Arena_new ();
  if (!he->arena)
    {
      free (he);
      return NULL;
    }

  /* Copy configuration */
  if (config)
    {
      he->config = *config;
    }
  else
    {
      SocketHappyEyeballs_config_defaults (&he->config);
    }

  /* Copy hostname */
  host_len = strlen (host) + 1;
  he->host = Arena_alloc (he->arena, host_len, __FILE__, __LINE__);
  if (!he->host)
    {
      Arena_dispose (&he->arena);
      free (he);
      return NULL;
    }
  memcpy (he->host, host, host_len);
  he->port = port;

  /* Store external resources */
  he->dns = dns;
  he->poll = poll;

  /* Initialize state */
  he->state = HE_STATE_IDLE;
  he->start_time_ms = sockethe_get_time_ms ();

  return he;
}

void
SocketHappyEyeballs_free (T *he)
{
  if (!he || !*he)
    return;

  T ctx = *he;

  /* Cancel any in-progress operation */
  if (ctx->state == HE_STATE_RESOLVING || ctx->state == HE_STATE_CONNECTING)
    {
      SocketHappyEyeballs_cancel (ctx);
    }

  /* Free resolved addresses */
  if (ctx->resolved)
    {
      freeaddrinfo (ctx->resolved);
      ctx->resolved = NULL;
    }

  /* Free owned resources */
  if (ctx->owns_dns && ctx->dns)
    {
      SocketDNS_free (&ctx->dns);
    }

  if (ctx->owns_poll && ctx->poll)
    {
      SocketPoll_free (&ctx->poll);
    }

  /* Free arena (frees host, addresses, attempts) */
  if (ctx->arena)
    {
      Arena_dispose (&ctx->arena);
    }

  free (ctx);
  *he = NULL;
}

void
SocketHappyEyeballs_cancel (T he)
{
  assert (he);

  if (he->state == HE_STATE_CONNECTED || he->state == HE_STATE_FAILED
      || he->state == HE_STATE_CANCELLED)
    {
      return;
    }

  /* Cancel DNS request if active */
  he_cancel_dns (he);

  /* Close all pending connection attempts */
  he_cleanup_attempts (he);

  he->state = HE_STATE_CANCELLED;
  SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                   "Happy Eyeballs cancelled for %s:%d", he->host, he->port);
}

/* ============================================================================
 * DNS Resolution
 * ============================================================================ */

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
 * he_start_dns_resolution - Start async DNS resolution
 * @he: Happy Eyeballs context
 *
 * Returns: 0 on success, -1 on failure
 */
static int
he_start_dns_resolution (T he)
{
  assert (he);
  assert (he->dns);

  he->dns_request = SocketDNS_resolve (he->dns, he->host, he->port, NULL, NULL);
  if (!he->dns_request)
    {
      he_transition_to_failed (he, "Failed to start DNS resolution");
      return -1;
    }

  he->state = HE_STATE_RESOLVING;
  SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                   "Started DNS resolution for %s:%d", he->host, he->port);
  return 0;
}

/**
 * he_dns_blocking_resolve - Perform blocking DNS resolution
 * @he: Happy Eyeballs context
 *
 * Returns: 0 on success, -1 on failure
 */
static int
he_dns_blocking_resolve (T he)
{
  struct addrinfo hints;
  char port_str[8];
  int result;

  memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_UNSPEC; /* IPv4 and IPv6 */
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_ADDRCONFIG; /* Only return usable addresses */

  snprintf (port_str, sizeof (port_str), "%d", he->port);

  result = getaddrinfo (he->host, port_str, &hints, &he->resolved);
  if (result != 0)
    {
      snprintf (he->error_buf, sizeof (he->error_buf),
                "DNS resolution failed: %s", gai_strerror (result));
      he->dns_error = result;
      return -1;
    }

  if (!he->resolved)
    {
      snprintf (he->error_buf, sizeof (he->error_buf), "No addresses found");
      return -1;
    }

  he->dns_complete = 1;
  return 0;
}

/**
 * he_process_dns_completion - Check and process DNS completion
 * @he: Happy Eyeballs context
 */
static void
he_process_dns_completion (T he)
{
  if (!he->dns || !he->dns_request)
    return;

  struct addrinfo *result = SocketDNS_getresult (he->dns, he->dns_request);
  if (!result)
    {
      /* Check for error */
      int error = SocketDNS_geterror (he->dns, he->dns_request);
      if (error != 0)
        {
          snprintf (he->error_buf, sizeof (he->error_buf),
                    "DNS resolution failed: %s", gai_strerror (error));
          he->dns_error = error;
          he->dns_complete = 1;
          he->dns_request = NULL;
          he_transition_to_failed (he, he->error_buf);
          return;
        }
      /* Still pending */
      return;
    }

  /* Success */
  he->resolved = result;
  he->dns_complete = 1;
  he->dns_request = NULL;

  SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                   "DNS resolution complete for %s:%d", he->host, he->port);

  /* Sort addresses and start connecting */
  he_sort_addresses (he);
  he->state = HE_STATE_CONNECTING;
}

/* ============================================================================
 * Address Sorting (RFC 8305)
 * ============================================================================ */

/**
 * he_count_addresses_by_family - Count addresses of each family
 * @res: Address list
 * @ipv6_count: Output for IPv6 count
 * @ipv4_count: Output for IPv4 count
 */
static void
he_count_addresses_by_family (struct addrinfo *res, int *ipv6_count,
                              int *ipv4_count)
{
  *ipv6_count = 0;
  *ipv4_count = 0;

  for (struct addrinfo *rp = res; rp; rp = rp->ai_next)
    {
      if (rp->ai_family == AF_INET6)
        (*ipv6_count)++;
      else if (rp->ai_family == AF_INET)
        (*ipv4_count)++;
    }
}

/**
 * he_sort_addresses - Sort addresses per RFC 8305
 * @he: Happy Eyeballs context
 *
 * Creates sorted address list with IPv6 first (if preferred), then
 * interleaves for resilience. Sets up next_ipv6 and next_ipv4 pointers.
 */
static void
he_sort_addresses (T he)
{
  SocketHE_AddressEntry_T *ipv6_list = NULL;
  SocketHE_AddressEntry_T *ipv4_list = NULL;
  SocketHE_AddressEntry_T **ipv6_tail = &ipv6_list;
  SocketHE_AddressEntry_T **ipv4_tail = &ipv4_list;
  SocketHE_AddressEntry_T *entry;
  int ipv6_count, ipv4_count;

  /* Count addresses */
  he_count_addresses_by_family (he->resolved, &ipv6_count, &ipv4_count);

  SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                   "Resolved %d IPv6 and %d IPv4 addresses", ipv6_count,
                   ipv4_count);

  /* Build separate lists for each family */
  for (struct addrinfo *rp = he->resolved; rp; rp = rp->ai_next)
    {
      entry
          = Arena_alloc (he->arena, sizeof (*entry), __FILE__, __LINE__);
      if (!entry)
        continue;

      entry->addr = rp;
      entry->family = rp->ai_family;
      entry->tried = 0;
      entry->next = NULL;

      if (rp->ai_family == AF_INET6)
        {
          *ipv6_tail = entry;
          ipv6_tail = &entry->next;
        }
      else if (rp->ai_family == AF_INET)
        {
          *ipv4_tail = entry;
          ipv4_tail = &entry->next;
        }
    }

  /* Store pointers for interleaved access */
  if (he->config.prefer_ipv6)
    {
      he->next_ipv6 = ipv6_list;
      he->next_ipv4 = ipv4_list;
    }
  else
    {
      /* Swap: prefer IPv4 */
      he->next_ipv6 = ipv4_list;
      he->next_ipv4 = ipv6_list;
    }

  /* Build interleaved list for iteration */
  he->addresses = he->next_ipv6 ? he->next_ipv6 : he->next_ipv4;
}

/**
 * he_get_next_address - Get next address to try
 * @he: Happy Eyeballs context
 *
 * Returns: Next address entry, or NULL if none available
 *
 * Implements RFC 8305 interleaving: alternates between preferred
 * and fallback families.
 */
static SocketHE_AddressEntry_T *
he_get_next_address (T he)
{
  SocketHE_AddressEntry_T *entry;

  /* Try preferred family first */
  if (he->next_ipv6)
    {
      entry = he->next_ipv6;
      he->next_ipv6 = entry->next;
      return entry;
    }

  /* Fall back to other family */
  if (he->next_ipv4)
    {
      entry = he->next_ipv4;
      he->next_ipv4 = entry->next;
      return entry;
    }

  return NULL;
}

/* ============================================================================
 * Connection Attempts
 * ============================================================================ */

/**
 * he_create_socket_for_address - Create socket for address family
 * @he: Happy Eyeballs context
 * @addr: Address to create socket for
 *
 * Returns: New socket or NULL on failure
 */
static Socket_T
he_create_socket_for_address (T he, struct addrinfo *addr)
{
  Socket_T sock = NULL;

  (void)he; /* Currently unused but may be needed for future options */

  TRY { sock = Socket_new (addr->ai_family, addr->ai_socktype, addr->ai_protocol); }
  EXCEPT (Socket_Failed) { return NULL; }
  END_TRY;

  if (!sock)
    return NULL;

  /* Set non-blocking for racing */
  int fd = Socket_fd (sock);
  int flags = fcntl (fd, F_GETFL);
  if (flags < 0 || fcntl (fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
      Socket_free (&sock);
      return NULL;
    }

  return sock;
}

/**
 * he_start_attempt - Start connection attempt for address
 * @he: Happy Eyeballs context
 * @entry: Address entry to connect to
 *
 * Returns: 0 on success (attempt started or connected), -1 on failure
 */
static int
he_start_attempt (T he, SocketHE_AddressEntry_T *entry)
{
  SocketHE_Attempt_T *attempt;
  Socket_T sock;
  int result;
  int fd;

  if (entry->tried)
    return -1;

  entry->tried = 1;

  /* Create socket */
  sock = he_create_socket_for_address (he, entry->addr);
  if (!sock)
    {
      SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                       "Failed to create socket for %s family",
                       entry->family == AF_INET6 ? "IPv6" : "IPv4");
      return -1;
    }

  /* Allocate attempt structure */
  attempt = Arena_alloc (he->arena, sizeof (*attempt), __FILE__, __LINE__);
  if (!attempt)
    {
      Socket_free (&sock);
      return -1;
    }

  attempt->socket = sock;
  attempt->addr = entry->addr;
  attempt->state = HE_ATTEMPT_CONNECTING;
  attempt->error = 0;
  attempt->start_time_ms = sockethe_get_time_ms ();

  /* Start non-blocking connect */
  fd = Socket_fd (sock);
  result = connect (fd, entry->addr->ai_addr, entry->addr->ai_addrlen);

  if (result == 0)
    {
      /* Immediate success (rare, usually localhost) */
      he_declare_winner (he, attempt);
      return 0;
    }

  if (errno == EINPROGRESS)
    {
      /* Normal case: connect in progress */
      attempt->next = he->attempts;
      he->attempts = attempt;
      he->attempt_count++;

      /* Add to poll for completion monitoring */
      if (he->poll)
        {
          TRY { SocketPoll_add (he->poll, sock, POLL_WRITE, attempt); }
          EXCEPT (SocketPoll_Failed)
          {
            /* Remove from attempt list on poll failure */
            he->attempts = attempt->next;
            he->attempt_count--;
            Socket_free (&sock);
            return -1;
          }
          END_TRY;
        }

      SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                       "Started %s connection attempt",
                       entry->family == AF_INET6 ? "IPv6" : "IPv4");
      return 0;
    }

  /* Connect failed immediately */
  attempt->state = HE_ATTEMPT_FAILED;
  attempt->error = errno;
  Socket_free (&sock);
  attempt->socket = NULL;

  SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                   "%s connection failed: %s",
                   entry->family == AF_INET6 ? "IPv6" : "IPv4",
                   strerror (attempt->error));
  return -1;
}

/**
 * he_cleanup_attempts - Close all pending connection attempts
 * @he: Happy Eyeballs context
 */
static void
he_cleanup_attempts (T he)
{
  SocketHE_Attempt_T *attempt = he->attempts;

  while (attempt)
    {
      if (attempt->socket)
        {
          if (he->poll && attempt->state == HE_ATTEMPT_CONNECTING)
            {
              SocketPoll_del (he->poll, attempt->socket);
            }
          /* Don't free the winner */
          if (attempt->socket != he->winner)
            {
              Socket_free (&attempt->socket);
            }
        }
      attempt = attempt->next;
    }

  he->attempts = NULL;
  he->attempt_count = 0;
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

  /* Remove winner from poll */
  if (he->poll)
    {
      SocketPoll_del (he->poll, attempt->socket);
    }

  /* Cancel DNS if still in progress */
  he_cancel_dns (he);

  /* Close all other attempts */
  for (SocketHE_Attempt_T *other = he->attempts; other; other = other->next)
    {
      if (other != attempt && other->socket)
        {
          if (he->poll && other->state == HE_ATTEMPT_CONNECTING)
            {
              SocketPoll_del (he->poll, other->socket);
            }
          Socket_free (&other->socket);
        }
    }

  SocketLog_emitf (
      SOCKET_LOG_INFO, SOCKET_LOG_COMPONENT,
      "Happy Eyeballs connected to %s:%d via %s", he->host, he->port,
      attempt->addr->ai_family == AF_INET6 ? "IPv6" : "IPv4");
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
    {
      SocketPoll_del (he->poll, attempt->socket);
    }

  if (attempt->socket)
    {
      Socket_free (&attempt->socket);
      attempt->socket = NULL;
    }

  SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                   "%s connection failed: %s",
                   attempt->addr->ai_family == AF_INET6 ? "IPv6" : "IPv4",
                   strerror (error));
}

/**
 * he_check_attempt_completion - Check if single attempt has completed
 * @he: Happy Eyeballs context
 * @attempt: Attempt to check
 *
 * Returns: 1 if connected, 0 if still pending, -1 if failed
 */
static int
he_check_attempt_completion (T he, SocketHE_Attempt_T *attempt)
{
  int fd, error;
  socklen_t len;
  struct pollfd pfd;

  if (attempt->state != HE_ATTEMPT_CONNECTING)
    return attempt->state == HE_ATTEMPT_CONNECTED ? 1 : -1;

  if (!attempt->socket)
    return -1;

  fd = Socket_fd (attempt->socket);

  /* Poll for write readiness */
  pfd.fd = fd;
  pfd.events = POLLOUT;
  pfd.revents = 0;

  int result = poll (&pfd, 1, 0); /* Non-blocking check */
  if (result < 0)
    {
      if (errno == EINTR)
        return 0;
      he_fail_attempt (he, attempt, errno);
      return -1;
    }

  if (result == 0)
    {
      /* Check for timeout */
      int64_t elapsed = sockethe_elapsed_ms (attempt->start_time_ms);
      if (he->config.attempt_timeout_ms > 0
          && elapsed >= he->config.attempt_timeout_ms)
        {
          he_fail_attempt (he, attempt, ETIMEDOUT);
          return -1;
        }
      return 0; /* Still connecting */
    }

  /* Check for error */
  if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
    {
      error = 0;
      len = sizeof (error);
      getsockopt (fd, SOL_SOCKET, SO_ERROR, &error, &len);
      he_fail_attempt (he, attempt, error ? error : ECONNREFUSED);
      return -1;
    }

  /* Check SO_ERROR */
  error = 0;
  len = sizeof (error);
  if (getsockopt (fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
    {
      he_fail_attempt (he, attempt, errno);
      return -1;
    }

  if (error != 0)
    {
      he_fail_attempt (he, attempt, error);
      return -1;
    }

  /* Success! */
  he_declare_winner (he, attempt);
  return 1;
}

/**
 * he_check_attempts - Check all active connection attempts
 * @he: Happy Eyeballs context
 */
static void
he_check_attempts (T he)
{
  SocketHE_Attempt_T *attempt;

  for (attempt = he->attempts; attempt; attempt = attempt->next)
    {
      if (he->state == HE_STATE_CONNECTED)
        break; /* We have a winner */

      if (attempt->state == HE_ATTEMPT_CONNECTING)
        {
          he_check_attempt_completion (he, attempt);
        }
    }
}

/**
 * he_all_attempts_done - Check if all attempts are complete
 * @he: Happy Eyeballs context
 *
 * Returns: 1 if all done, 0 if some still pending
 */
static int
he_all_attempts_done (T he)
{
  /* Check if we can start more attempts */
  if (he->next_ipv6 || he->next_ipv4)
    return 0;

  /* Check active attempts */
  for (SocketHE_Attempt_T *attempt = he->attempts; attempt;
       attempt = attempt->next)
    {
      if (attempt->state == HE_ATTEMPT_CONNECTING)
        return 0;
    }

  return 1;
}

/**
 * he_transition_to_failed - Mark operation as failed
 * @he: Happy Eyeballs context
 * @reason: Failure reason
 */
static void
he_transition_to_failed (T he, const char *reason)
{
  he->state = HE_STATE_FAILED;

  if (reason && he->error_buf[0] == '\0')
    {
      snprintf (he->error_buf, sizeof (he->error_buf), "%s", reason);
    }

  SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                   "Happy Eyeballs failed for %s:%d: %s", he->host, he->port,
                   he->error_buf);
}

/* ============================================================================
 * State Machine Processing
 * ============================================================================ */

/**
 * he_should_start_fallback - Check if fallback attempt should start
 * @he: Happy Eyeballs context
 *
 * Returns: 1 if should start fallback, 0 otherwise
 */
static int
he_should_start_fallback (T he)
{
  int64_t elapsed;

  if (!he->fallback_timer_armed)
    return 0;

  if (he->first_attempt_time_ms == 0)
    return 0;

  elapsed = sockethe_elapsed_ms (he->first_attempt_time_ms);
  return elapsed >= he->config.first_attempt_delay_ms;
}

/**
 * he_check_total_timeout - Check for total operation timeout
 * @he: Happy Eyeballs context
 *
 * Returns: 1 if timed out, 0 otherwise
 */
static int
he_check_total_timeout (T he)
{
  if (he->config.total_timeout_ms <= 0)
    return 0;

  int64_t elapsed = sockethe_elapsed_ms (he->start_time_ms);
  return elapsed >= he->config.total_timeout_ms;
}

/**
 * he_process_connecting_state - Process connections in CONNECTING state
 * @he: Happy Eyeballs context
 */
static void
he_process_connecting_state (T he)
{
  /* Check total timeout */
  if (he_check_total_timeout (he))
    {
      snprintf (he->error_buf, sizeof (he->error_buf), "Connection timed out");
      he_cleanup_attempts (he);
      he_transition_to_failed (he, he->error_buf);
      return;
    }

  /* Check existing attempts */
  he_check_attempts (he);

  if (he->state == HE_STATE_CONNECTED)
    return;

  /* Start first attempt if none active */
  if (he->attempt_count == 0)
    {
      SocketHE_AddressEntry_T *entry = he_get_next_address (he);
      if (entry)
        {
          he_start_attempt (he, entry);
          he->first_attempt_time_ms = sockethe_get_time_ms ();
          he->fallback_timer_armed = 1;
        }
    }

  /* Check if should start fallback attempt */
  if (he_should_start_fallback (he)
      && he->attempt_count < he->config.max_attempts)
    {
      SocketHE_AddressEntry_T *entry = he_get_next_address (he);
      if (entry)
        {
          he_start_attempt (he, entry);
          he->fallback_timer_armed = 0; /* Only one fallback */
        }
    }

  /* Check for complete failure */
  if (he_all_attempts_done (he) && he->state != HE_STATE_CONNECTED)
    {
      snprintf (he->error_buf, sizeof (he->error_buf),
                "All connection attempts failed");
      he_transition_to_failed (he, he->error_buf);
    }
}

void
SocketHappyEyeballs_process (T he)
{
  assert (he);

  switch (he->state)
    {
    case HE_STATE_IDLE:
      /* Start DNS resolution */
      if (he->dns)
        {
          he_start_dns_resolution (he);
        }
      break;

    case HE_STATE_RESOLVING:
      /* Check DNS completion */
      if (he->dns)
        {
          SocketDNS_check (he->dns);
          he_process_dns_completion (he);
        }
      break;

    case HE_STATE_CONNECTING:
      he_process_connecting_state (he);
      break;

    case HE_STATE_CONNECTED:
    case HE_STATE_FAILED:
    case HE_STATE_CANCELLED:
      /* Terminal states - nothing to do */
      break;
    }
}

/* ============================================================================
 * Asynchronous API
 * ============================================================================ */

T
SocketHappyEyeballs_start (SocketDNS_T dns, SocketPoll_T poll, const char *host,
                           int port, const SocketHE_Config_T *config)
{
  T he;

  assert (dns);
  assert (poll);
  assert (host);
  assert (port > 0 && port <= 65535);

  he = he_create_context (dns, poll, host, port, config);
  if (!he)
    {
      SOCKET_ERROR_MSG ("Failed to create Happy Eyeballs context");
      RAISE_MODULE_ERROR (SocketHE_Failed);
    }

  /* Start DNS resolution */
  if (he_start_dns_resolution (he) < 0)
    {
      char errmsg_copy[SOCKET_HE_ERROR_BUFSIZE];
      snprintf (errmsg_copy, sizeof (errmsg_copy), "%s", he->error_buf);
      SocketHappyEyeballs_free (&he);
      SOCKET_ERROR_MSG ("%s", errmsg_copy);
      RAISE_MODULE_ERROR (SocketHE_Failed);
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

  /* Transfer ownership */
  result = he->winner;
  he->winner = NULL;

  /* Restore blocking mode */
  if (result)
    {
      int fd = Socket_fd (result);
      int flags = fcntl (fd, F_GETFL);
      if (flags >= 0)
        {
          fcntl (fd, F_SETFL, flags & ~O_NONBLOCK);
        }
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
  int64_t remaining;
  int timeout = -1;

  assert (he);

  if (he->state != HE_STATE_RESOLVING && he->state != HE_STATE_CONNECTING)
    return -1;

  /* Total timeout */
  if (he->config.total_timeout_ms > 0)
    {
      remaining = he->config.total_timeout_ms
                  - sockethe_elapsed_ms (he->start_time_ms);
      if (remaining <= 0)
        return 0;
      timeout = (int)remaining;
    }

  /* Fallback timer */
  if (he->state == HE_STATE_CONNECTING && he->fallback_timer_armed
      && he->first_attempt_time_ms > 0)
    {
      remaining = he->config.first_attempt_delay_ms
                  - sockethe_elapsed_ms (he->first_attempt_time_ms);
      if (remaining <= 0)
        return 0;
      if (timeout < 0 || remaining < timeout)
        timeout = (int)remaining;
    }

  return timeout;
}

/* ============================================================================
 * Synchronous API
 * ============================================================================ */

Socket_T
SocketHappyEyeballs_connect (const char *host, int port,
                             const SocketHE_Config_T *config)
{
  T he;
  Socket_T result = NULL;
  int timeout;

  assert (host);
  assert (port > 0 && port <= 65535);

  /* Create context with internal resources */
  he = he_create_context (NULL, NULL, host, port, config);
  if (!he)
    {
      SOCKET_ERROR_MSG ("Failed to create Happy Eyeballs context");
      RAISE_MODULE_ERROR (SocketHE_Failed);
    }

  /* Perform blocking DNS resolution */
  if (he_dns_blocking_resolve (he) < 0)
    {
      const char *errmsg = he->error_buf;
      SocketHappyEyeballs_free (&he);
      SOCKET_ERROR_MSG ("%s", errmsg);
      RAISE_MODULE_ERROR (SocketHE_Failed);
    }

  /* Sort addresses */
  he_sort_addresses (he);
  he->state = HE_STATE_CONNECTING;

  /* Run connection loop */
  while (he->state == HE_STATE_CONNECTING)
    {
      /* Check total timeout */
      if (he_check_total_timeout (he))
        {
          snprintf (he->error_buf, sizeof (he->error_buf),
                    "Connection timed out");
          break;
        }

      /* Start first attempt if none active */
      if (he->attempt_count == 0)
        {
          SocketHE_AddressEntry_T *entry = he_get_next_address (he);
          if (entry)
            {
              if (he_start_attempt (he, entry) == 0
                  && he->state == HE_STATE_CONNECTED)
                break; /* Immediate connect (rare) */
              he->first_attempt_time_ms = sockethe_get_time_ms ();
              he->fallback_timer_armed = 1;
            }
        }

      /* Calculate poll timeout */
      timeout = he_should_start_fallback (he) ? 0 : 50; /* Poll every 50ms */
      if (he->fallback_timer_armed && he->first_attempt_time_ms > 0)
        {
          int64_t remaining = he->config.first_attempt_delay_ms
                              - sockethe_elapsed_ms (he->first_attempt_time_ms);
          if (remaining > 0 && remaining < timeout)
            timeout = (int)remaining;
        }

      /* Build poll set for active attempts */
      int nfds = 0;
      struct pollfd pfds[SOCKET_HE_MAX_ATTEMPTS];
      SocketHE_Attempt_T *attempt_map[SOCKET_HE_MAX_ATTEMPTS];

      for (SocketHE_Attempt_T *attempt = he->attempts;
           attempt && nfds < SOCKET_HE_MAX_ATTEMPTS; attempt = attempt->next)
        {
          if (attempt->state == HE_ATTEMPT_CONNECTING && attempt->socket)
            {
              pfds[nfds].fd = Socket_fd (attempt->socket);
              pfds[nfds].events = POLLOUT;
              pfds[nfds].revents = 0;
              attempt_map[nfds] = attempt;
              nfds++;
            }
        }

      if (nfds == 0 && !he_should_start_fallback (he))
        {
          /* No active attempts and no fallback pending */
          if (he_all_attempts_done (he))
            break;
        }

      /* Poll for events */
      int result_poll = poll (pfds, nfds, timeout);
      if (result_poll < 0 && errno != EINTR)
        break;

      /* Check results */
      for (int i = 0; i < nfds && he->state != HE_STATE_CONNECTED; i++)
        {
          if (pfds[i].revents)
            {
              he_check_attempt_completion (he, attempt_map[i]);
            }
        }

      /* Start fallback if timer expired */
      if (he_should_start_fallback (he)
          && he->attempt_count < he->config.max_attempts)
        {
          SocketHE_AddressEntry_T *entry = he_get_next_address (he);
          if (entry)
            {
              if (he_start_attempt (he, entry) == 0
                  && he->state == HE_STATE_CONNECTED)
                break;
            }
          he->fallback_timer_armed = 0;
        }

      /* Check for timeout on individual attempts */
      for (SocketHE_Attempt_T *attempt = he->attempts;
           attempt && he->state != HE_STATE_CONNECTED; attempt = attempt->next)
        {
          if (attempt->state == HE_ATTEMPT_CONNECTING)
            {
              int64_t elapsed = sockethe_elapsed_ms (attempt->start_time_ms);
              if (he->config.attempt_timeout_ms > 0
                  && elapsed >= he->config.attempt_timeout_ms)
                {
                  he_fail_attempt (he, attempt, ETIMEDOUT);
                }
            }
        }

      /* Check if all done */
      if (he_all_attempts_done (he) && he->state != HE_STATE_CONNECTED)
        {
          snprintf (he->error_buf, sizeof (he->error_buf),
                    "All connection attempts failed");
          break;
        }
    }

  /* Get result */
  if (he->state == HE_STATE_CONNECTED)
    {
      result = SocketHappyEyeballs_result (he);
    }
  else
    {
      he_cleanup_attempts (he);
      he_transition_to_failed (he, he->error_buf);
    }

  /* Cleanup - copy error message BEFORE freeing context */
  char errmsg_copy[SOCKET_HE_ERROR_BUFSIZE] = { 0 };
  if (!result && he->error_buf[0])
    {
      snprintf (errmsg_copy, sizeof (errmsg_copy), "%s", he->error_buf);
    }

  SocketHappyEyeballs_free (&he);

  if (!result)
    {
      SOCKET_ERROR_MSG ("%s",
                        errmsg_copy[0] ? errmsg_copy : "Happy Eyeballs failed");
      RAISE_MODULE_ERROR (SocketHE_Failed);
    }

  return result;
}

#undef T

