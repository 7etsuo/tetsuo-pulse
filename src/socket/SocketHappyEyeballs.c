/**
 * SocketHappyEyeballs.c - Happy Eyeballs (RFC 8305) Implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Implements the Happy Eyeballs algorithm for fast dual-stack connection
 * establishment. Races IPv6 and IPv4 connection attempts with a 250ms
 * delay between attempts to minimize latency when one family is slow.
 */

#include "socket/SocketHappyEyeballs.h"
#include "socket/SocketHappyEyeballs-private.h"

#include "core/Arena.h"
#include "core/Except.h"
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
#include <stdio.h>
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
 * Forward Declarations - Internal Helpers
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
static int he_should_start_fallback (T he);
static int he_check_total_timeout (T he);

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
 * Context Creation Helpers
 * ============================================================================ */

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
}

/**
 * he_copy_hostname - Copy hostname into context arena
 * @he: Context
 * @host: Hostname to copy
 *
 * Returns: 0 on success, -1 on failure
 */
static int
he_copy_hostname (T he, const char *host)
{
  size_t host_len = strlen (host) + 1;

  he->host = Arena_alloc (he->arena, host_len, __FILE__, __LINE__);
  if (!he->host)
    return -1;

  memcpy (he->host, host, host_len);
  return 0;
}

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
  T he = calloc (1, sizeof (*he));
  if (!he)
    return NULL;

  he->arena = Arena_new ();
  if (!he->arena)
    {
      free (he);
      return NULL;
    }

  he_init_config (he, config);

  if (he_copy_hostname (he, host) < 0)
    {
      Arena_dispose (&he->arena);
      free (he);
      return NULL;
    }

  he->port = port;
  he->dns = dns;
  he->poll = poll;
  he->state = HE_STATE_IDLE;
  he->start_time_ms = sockethe_get_time_ms ();

  return he;
}

/* ============================================================================
 * Context Destruction
 * ============================================================================ */

/**
 * he_free_resolved - Free resolved address list
 * @he: Context
 */
static void
he_free_resolved (T he)
{
  if (he->resolved)
    {
      freeaddrinfo (he->resolved);
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
  if (he->owns_dns && he->dns)
    SocketDNS_free (&he->dns);

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
  char port_str[SOCKET_HE_PORT_STR_SIZE];
  int result;

  memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_ADDRCONFIG;

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
 * he_handle_dns_error - Handle DNS resolution error
 * @he: Happy Eyeballs context
 * @error: Error code from DNS
 */
static void
he_handle_dns_error (T he, int error)
{
  snprintf (he->error_buf, sizeof (he->error_buf), "DNS resolution failed: %s",
            gai_strerror (error));
  he->dns_error = error;
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
}

/**
 * he_process_dns_completion - Check and process DNS completion
 * @he: Happy Eyeballs context
 */
static void
he_process_dns_completion (T he)
{
  struct addrinfo *result;
  int error;

  if (!he->dns || !he->dns_request)
    return;

  result = SocketDNS_getresult (he->dns, he->dns_request);
  if (!result)
    {
      error = SocketDNS_geterror (he->dns, he->dns_request);
      if (error != 0)
        he_handle_dns_error (he, error);
      return;
    }

  he_handle_dns_success (he, result);
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
 * @tail: Pointer to tail pointer (updated to point to entry->next)
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
  SocketHE_AddressEntry_T *entry;

  *ipv6_list = NULL;
  *ipv4_list = NULL;

  for (struct addrinfo *rp = he->resolved; rp; rp = rp->ai_next)
    {
      entry = he_create_address_entry (he, rp);
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
 * ============================================================================ */

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
 * ============================================================================ */

/**
 * he_set_nonblocking - Set socket to non-blocking mode
 * @fd: File descriptor
 *
 * Returns: 0 on success, -1 on failure
 */
static int
he_set_nonblocking (int fd)
{
  int flags = fcntl (fd, F_GETFL);

  if (flags < 0)
    return -1;

  return fcntl (fd, F_SETFL, flags | O_NONBLOCK);
}

/**
 * he_clear_nonblocking - Clear non-blocking mode from socket
 * @fd: File descriptor
 */
static void
he_clear_nonblocking (int fd)
{
  int flags = fcntl (fd, F_GETFL);

  if (flags >= 0)
    fcntl (fd, F_SETFL, flags & ~O_NONBLOCK);
}

/**
 * he_create_socket_for_address - Create socket for address family
 * @addr: Address to create socket for
 *
 * Returns: New socket or NULL on failure
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

  if (!sock)
    return NULL;

  if (he_set_nonblocking (Socket_fd (sock)) < 0)
    {
      Socket_free (&sock);
      return NULL;
    }

  return sock;
}

/* ============================================================================
 * Connection Attempt Management
 * ============================================================================ */

/**
 * he_allocate_attempt - Allocate attempt structure
 * @he: Happy Eyeballs context
 * @sock: Socket for this attempt
 * @entry: Address entry being tried
 *
 * Returns: New attempt or NULL on failure
 */
static SocketHE_Attempt_T *
he_allocate_attempt (T he, Socket_T sock, SocketHE_AddressEntry_T *entry)
{
  SocketHE_Attempt_T *attempt;

  attempt = Arena_alloc (he->arena, sizeof (*attempt), __FILE__, __LINE__);
  if (!attempt)
    return NULL;

  attempt->socket = sock;
  attempt->addr = entry->addr;
  attempt->state = HE_ATTEMPT_CONNECTING;
  attempt->error = 0;
  attempt->start_time_ms = sockethe_get_time_ms ();
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
 * he_add_attempt_to_poll - Register attempt with poll for monitoring
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
 * he_log_attempt_start - Log connection attempt start
 * @entry: Address entry being tried
 */
static void
he_log_attempt_start (const SocketHE_AddressEntry_T *entry)
{
  SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                   "Started %s connection attempt",
                   entry->family == AF_INET6 ? "IPv6" : "IPv4");
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
                   "%s connection failed: %s",
                   entry->family == AF_INET6 ? "IPv6" : "IPv4",
                   strerror (error));
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
  int result;

  if (entry->tried)
    return -1;

  entry->tried = 1;
  sock = he_create_socket_for_address (entry->addr);
  if (!sock)
    {
      he_log_attempt_fail (entry, errno);
      return -1;
    }

  attempt = he_allocate_attempt (he, sock, entry);
  if (!attempt)
    {
      Socket_free (&sock);
      return -1;
    }

  result = connect (Socket_fd (sock), entry->addr->ai_addr,
                    entry->addr->ai_addrlen);

  if (result == 0)
    {
      he_declare_winner (he, attempt);
      return 0;
    }

  if (errno != EINPROGRESS)
    {
      attempt->state = HE_ATTEMPT_FAILED;
      attempt->error = errno;
      Socket_free (&sock);
      attempt->socket = NULL;
      he_log_attempt_fail (entry, attempt->error);
      return -1;
    }

  he_add_attempt_to_list (he, attempt);

  if (he_add_attempt_to_poll (he, attempt) < 0)
    {
      he->attempts = attempt->next;
      he->attempt_count--;
      Socket_free (&sock);
      return -1;
    }

  he_log_attempt_start (entry);
  return 0;
}

/* ============================================================================
 * Attempt Cleanup
 * ============================================================================ */

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
  SocketHE_Attempt_T *attempt = he->attempts;

  while (attempt)
    {
      he_close_attempt (he, attempt);
      attempt = attempt->next;
    }

  he->attempts = NULL;
  he->attempt_count = 0;
}

/* ============================================================================
 * Winner Declaration
 * ============================================================================ */

/**
 * he_cancel_losing_attempts - Cancel all non-winning attempts
 * @he: Happy Eyeballs context
 * @winner: The winning attempt
 */
static void
he_cancel_losing_attempts (T he, const SocketHE_Attempt_T *winner)
{
  for (SocketHE_Attempt_T *other = he->attempts; other; other = other->next)
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
                   he->port, attempt->addr->ai_family == AF_INET6 ? "IPv6"
                                                                  : "IPv4");
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

  SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                   "%s connection failed: %s",
                   attempt->addr->ai_family == AF_INET6 ? "IPv6" : "IPv4",
                   strerror (error));
}

/* ============================================================================
 * Attempt Completion Checking
 * ============================================================================ */

/**
 * he_poll_attempt_status - Poll single attempt for completion
 * @fd: File descriptor to check
 * @revents: Output for poll results
 *
 * Returns: 1 if ready, 0 if pending, -1 on error
 */
static int
he_poll_attempt_status (int fd, short *revents)
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
 */
static int
he_check_socket_error (int fd)
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

  elapsed = sockethe_elapsed_ms (attempt->start_time_ms);
  return elapsed >= he->config.attempt_timeout_ms;
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
  int fd, result, error;
  short revents;

  if (attempt->state != HE_ATTEMPT_CONNECTING)
    return attempt->state == HE_ATTEMPT_CONNECTED ? 1 : -1;

  if (!attempt->socket)
    return -1;

  fd = Socket_fd (attempt->socket);
  result = he_poll_attempt_status (fd, &revents);

  if (result < 0)
    {
      he_fail_attempt (he, attempt, errno);
      return -1;
    }

  if (result == 0)
    {
      if (he_check_attempt_timeout (he, attempt))
        {
          he_fail_attempt (he, attempt, ETIMEDOUT);
          return -1;
        }
      return 0;
    }

  if (revents & (POLLERR | POLLHUP | POLLNVAL))
    {
      error = he_check_socket_error (fd);
      he_fail_attempt (he, attempt, error ? error : ECONNREFUSED);
      return -1;
    }

  error = he_check_socket_error (fd);
  if (error != 0)
    {
      he_fail_attempt (he, attempt, error);
      return -1;
    }

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
  for (SocketHE_Attempt_T *attempt = he->attempts; attempt;
       attempt = attempt->next)
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
he_all_attempts_done (T he)
{
  if (he->next_ipv6 || he->next_ipv4)
    return 0;

  for (SocketHE_Attempt_T *attempt = he->attempts; attempt;
       attempt = attempt->next)
    {
      if (attempt->state == HE_ATTEMPT_CONNECTING)
        return 0;
    }

  return 1;
}

/* ============================================================================
 * State Transitions
 * ============================================================================ */

/**
 * he_set_error - Set error message in context
 * @he: Happy Eyeballs context
 * @reason: Error message
 */
static void
he_set_error (T he, const char *reason)
{
  if (reason && he->error_buf[0] == '\0')
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
  he->state = HE_STATE_FAILED;
  he_set_error (he, reason);

  SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                   "Happy Eyeballs failed for %s:%d: %s", he->host, he->port,
                   he->error_buf);
}

/* ============================================================================
 * Timer and Timeout Checks
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

  if (!he->fallback_timer_armed || he->first_attempt_time_ms == 0)
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
  int64_t elapsed;

  if (he->config.total_timeout_ms <= 0)
    return 0;

  elapsed = sockethe_elapsed_ms (he->start_time_ms);
  return elapsed >= he->config.total_timeout_ms;
}

/* ============================================================================
 * Async State Machine Processing
 * ============================================================================ */

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
  he->first_attempt_time_ms = sockethe_get_time_ms ();
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
 * he_process_connecting_state - Process connections in CONNECTING state
 * @he: Happy Eyeballs context
 */
static void
he_process_connecting_state (T he)
{
  if (he_check_total_timeout (he))
    {
      snprintf (he->error_buf, sizeof (he->error_buf), "Connection timed out");
      he_cleanup_attempts (he);
      he_transition_to_failed (he, he->error_buf);
      return;
    }

  he_check_attempts (he);

  if (he->state == HE_STATE_CONNECTED)
    return;

  he_start_first_attempt (he);
  he_start_fallback_attempt (he);
  he_check_complete_failure (he);
}

void
SocketHappyEyeballs_process (T he)
{
  assert (he);

  switch (he->state)
    {
    case HE_STATE_IDLE:
      if (he->dns)
        he_start_dns_resolution (he);
      break;

    case HE_STATE_RESOLVING:
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
  char errmsg_copy[SOCKET_HE_ERROR_BUFSIZE];

  assert (dns);
  assert (poll);
  assert (host);
  assert (port > 0 && port <= SOCKET_MAX_PORT);

  he = he_create_context (dns, poll, host, port, config);
  if (!he)
    {
      SOCKET_ERROR_MSG ("Failed to create Happy Eyeballs context");
      RAISE_MODULE_ERROR (SocketHE_Failed);
    }

  if (he_start_dns_resolution (he) < 0)
    {
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

  result = he->winner;
  he->winner = NULL;

  if (result)
    he_clear_nonblocking (Socket_fd (result));

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

/**
 * he_calculate_next_timeout - Calculate next timeout for poll
 * @he: Happy Eyeballs context
 * @timeout: Current timeout (or -1)
 *
 * Returns: Updated timeout value
 */
static int
he_calculate_next_timeout (T he, int timeout)
{
  int64_t remaining;

  if (he->config.total_timeout_ms > 0)
    {
      remaining
          = he->config.total_timeout_ms - sockethe_elapsed_ms (he->start_time_ms);
      if (remaining <= 0)
        return 0;
      if (timeout < 0 || remaining < timeout)
        timeout = (int)remaining;
    }

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
 * ============================================================================ */

/**
 * sync_build_poll_set - Build poll array for active attempts
 * @he: Happy Eyeballs context
 * @pfds: Poll file descriptor array (output)
 * @attempt_map: Attempt pointer array (output)
 *
 * Returns: Number of descriptors added
 */
static int
sync_build_poll_set (T he, struct pollfd *pfds,
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
sync_calculate_poll_timeout (T he)
{
  int timeout = SOCKET_HE_SYNC_POLL_INTERVAL_MS;
  int64_t remaining;

  if (he_should_start_fallback (he))
    return 0;

  if (he->fallback_timer_armed && he->first_attempt_time_ms > 0)
    {
      remaining = he->config.first_attempt_delay_ms
                  - sockethe_elapsed_ms (he->first_attempt_time_ms);
      if (remaining > 0 && remaining < timeout)
        timeout = (int)remaining;
    }

  return timeout;
}

/**
 * sync_process_poll_results - Process poll results for sync API
 * @he: Happy Eyeballs context
 * @pfds: Poll file descriptor array
 * @attempt_map: Attempt pointer array
 * @nfds: Number of descriptors
 */
static void
sync_process_poll_results (T he, const struct pollfd *pfds,
                           SocketHE_Attempt_T **attempt_map, int nfds)
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
  for (SocketHE_Attempt_T *attempt = he->attempts;
       attempt && he->state != HE_STATE_CONNECTED; attempt = attempt->next)
    {
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
      if (he_start_attempt (he, entry) == 0
          && he->state == HE_STATE_CONNECTED)
        return 1;
    }

  he->fallback_timer_armed = 0;
  return 0;
}

/**
 * sync_run_connection_loop - Run synchronous connection loop
 * @he: Happy Eyeballs context
 */
static void
sync_run_connection_loop (T he)
{
  struct pollfd pfds[SOCKET_HE_MAX_ATTEMPTS];
  SocketHE_Attempt_T *attempt_map[SOCKET_HE_MAX_ATTEMPTS];

  while (he->state == HE_STATE_CONNECTING)
    {
      if (he_check_total_timeout (he))
        {
          snprintf (he->error_buf, sizeof (he->error_buf),
                    "Connection timed out");
          break;
        }

      he_start_first_attempt (he);
      if (he->state == HE_STATE_CONNECTED)
        break;

      int timeout = sync_calculate_poll_timeout (he);
      int nfds = sync_build_poll_set (he, pfds, attempt_map);

      if (nfds == 0 && !he_should_start_fallback (he) && he_all_attempts_done (he))
        break;

      int result = poll (pfds, nfds, timeout);
      if (result < 0 && errno != EINTR)
        break;

      sync_process_poll_results (he, pfds, attempt_map, nfds);

      if (sync_try_start_fallback (he))
        break;

      sync_check_attempt_timeouts (he);

      if (he_all_attempts_done (he) && he->state != HE_STATE_CONNECTED)
        {
          snprintf (he->error_buf, sizeof (he->error_buf),
                    "All connection attempts failed");
          break;
        }
    }
}

/**
 * sync_finalize_result - Finalize result for sync API
 * @he: Happy Eyeballs context
 *
 * Returns: Connected socket or NULL
 */
static Socket_T
sync_finalize_result (T he)
{
  if (he->state == HE_STATE_CONNECTED)
    return SocketHappyEyeballs_result (he);

  he_cleanup_attempts (he);
  he_transition_to_failed (he, he->error_buf);
  return NULL;
}

/* ============================================================================
 * Synchronous API
 * ============================================================================ */

Socket_T
SocketHappyEyeballs_connect (const char *host, int port,
                             const SocketHE_Config_T *config)
{
  T he;
  Socket_T result;
  char errmsg_copy[SOCKET_HE_ERROR_BUFSIZE] = { 0 };

  assert (host);
  assert (port > 0 && port <= SOCKET_MAX_PORT);

  he = he_create_context (NULL, NULL, host, port, config);
  if (!he)
    {
      SOCKET_ERROR_MSG ("Failed to create Happy Eyeballs context");
      RAISE_MODULE_ERROR (SocketHE_Failed);
    }

  if (he_dns_blocking_resolve (he) < 0)
    {
      snprintf (errmsg_copy, sizeof (errmsg_copy), "%s", he->error_buf);
      SocketHappyEyeballs_free (&he);
      SOCKET_ERROR_MSG ("%s", errmsg_copy);
      RAISE_MODULE_ERROR (SocketHE_Failed);
    }

  he_sort_addresses (he);
  he->state = HE_STATE_CONNECTING;

  sync_run_connection_loop (he);
  result = sync_finalize_result (he);

  if (!result && he->error_buf[0])
    snprintf (errmsg_copy, sizeof (errmsg_copy), "%s", he->error_buf);

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
