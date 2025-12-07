/**
 * SocketCommon.c - Common utilities shared between Socket and SocketDgram
 *
 * Consolidated module containing core functionality, bind helpers, I/O vector
 * utilities, address resolution utilities, network-specific utilities,
 * multicast operations, validation, and socket options.
 *
 * Features:
 * - Base lifecycle management (new/free/init)
 * - Global timeout defaults
 * - Accessor functions
 * - Bind operation helpers and error handling
 * - I/O vector operations with overflow protection
 * - Address resolution utilities
 * - Endpoint caching
 * - Multicast join/leave operations (IPv4/IPv6)
 * - Port and hostname validation
 * - IP parsing and CIDR matching
 * - Socket option get/set operations
 * - File descriptor utilities (CLOEXEC, non-blocking)
 * - Reverse DNS lookup
 */

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#define SOCKET_LOG_COMPONENT "SocketCommon"
#include "core/SocketUtil.h"
#include "core/SocketSecurity.h"
#include "dns/SocketDNS.h"
#include "socket/SocketCommon-private.h"
#include "socket/SocketCommon.h"

/* Global defaults for socket timeouts - shared across modules */
SocketTimeouts_T socket_default_timeouts
    = { .connect_timeout_ms = SOCKET_DEFAULT_CONNECT_TIMEOUT_MS,
        .dns_timeout_ms = SOCKET_DEFAULT_DNS_TIMEOUT_MS,
        .operation_timeout_ms = SOCKET_DEFAULT_OPERATION_TIMEOUT_MS };
pthread_mutex_t socket_default_timeouts_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * =============================================================================
 * Global DNS Resolver with Lazy Initialization
 *
 * Provides timeout-guaranteed DNS resolution for all Socket/SocketDgram APIs.
 * The resolver is lazily initialized on first use via pthread_once.
 * =============================================================================
 */
static SocketDNS_T g_dns_resolver = NULL;
static pthread_once_t g_dns_init_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_dns_config_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_dns_timeout_ms = SOCKET_DEFAULT_DNS_TIMEOUT_MS;

/**
 * init_global_dns_resolver - One-time initialization of global DNS resolver
 *
 * Called exactly once via pthread_once. Creates the global DNS resolver
 * with default configuration.
 */
static void
init_global_dns_resolver (void)
{
  g_dns_resolver = SocketDNS_new ();
  if (g_dns_resolver)
    SocketDNS_settimeout (g_dns_resolver, g_dns_timeout_ms);
}

SocketDNS_T
SocketCommon_get_dns_resolver (void)
{
  pthread_once (&g_dns_init_once, init_global_dns_resolver);
  return g_dns_resolver;
}

void
SocketCommon_set_dns_timeout (int timeout_ms)
{
  pthread_mutex_lock (&g_dns_config_mutex);

  /* Handle -1 as "reset to default" */
  if (timeout_ms == -1)
    timeout_ms = SOCKET_DEFAULT_DNS_TIMEOUT_MS;
  else if (timeout_ms < 0)
    timeout_ms = 0;

  g_dns_timeout_ms = timeout_ms;

  /* Update the resolver if already initialized */
  if (g_dns_resolver)
    SocketDNS_settimeout (g_dns_resolver, timeout_ms);

  pthread_mutex_unlock (&g_dns_config_mutex);
}

int
SocketCommon_get_dns_timeout (void)
{
  int timeout;
  pthread_mutex_lock (&g_dns_config_mutex);
  timeout = g_dns_timeout_ms;
  pthread_mutex_unlock (&g_dns_config_mutex);
  return timeout;
}

const Except_T SocketCommon_Failed
    = { &SocketCommon_Failed, "SocketCommon operation failed" };

SOCKET_DECLARE_MODULE_EXCEPTION (SocketCommon);

#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketCommon, e)

/* ==================== Timeout Utilities ==================== */

int
socketcommon_sanitize_timeout (int timeout_ms)
{
  if (timeout_ms < 0)
    return 0;
  return timeout_ms;
}

/* ==================== Validation Operations ==================== */

void
SocketCommon_validate_port (int port, Except_T exception_type)
{
  if (!SOCKET_VALID_PORT (port))
    {
      SOCKET_RAISE_MSG (SocketCommon, exception_type, "Invalid port number: %d (must be 0-65535, 0 = OS-assigned)", port);
    }
}

void
SocketCommon_validate_host_not_null (const char *host, Except_T exception_type)
{
  if (host == NULL)
    {
      SOCKET_RAISE_MSG (SocketCommon, exception_type, "Invalid host: NULL pointer");
    }
}

const char *
SocketCommon_normalize_wildcard_host (const char *host)
{
  if (host == NULL || strcmp (host, "0.0.0.0") == 0
      || strcmp (host, "::") == 0)
    return NULL;
  return host;
}

int
SocketCommon_parse_ip (const char *ip_str, int *family)
{
  struct in_addr addr4;
  struct in6_addr addr6;

    if (!ip_str) {
    if (family) *family = AF_UNSPEC;
    return 0;
  }

  size_t len = strlen(ip_str);
  if (len == 0 || len > SOCKET_ERROR_MAX_HOSTNAME) {
    if (family) *family = AF_UNSPEC;
    return 0;
  }

  if (family)
    *family = AF_UNSPEC;

  if (inet_pton (SOCKET_AF_INET, ip_str, &addr4) == 1)
    {
      if (family)
        *family = SOCKET_AF_INET;
      return 1;
    }

  if (inet_pton (SOCKET_AF_INET6, ip_str, &addr6) == 1)
    {
      if (family)
        *family = SOCKET_AF_INET6;
      return 1;
    }

  return 0;
}

/**
 * cidr_parse_prefix - Parse prefix length from CIDR suffix string
 * @prefix_str: String containing prefix length (e.g., "24")
 * @prefix_out: Output for parsed prefix length
 *
 * Returns: 0 on success, -1 on parse error
 */
static int
cidr_parse_prefix (const char *prefix_str, long *prefix_out)
{
  char *endptr = NULL;
  long prefix_long;

  errno = 0;
  prefix_long = strtol (prefix_str, &endptr, 10);

  if (errno != 0 || endptr == prefix_str || *endptr != '\0' || prefix_long < 0)
    return -1;

  *prefix_out = prefix_long;
  return 0;
}

/**
 * cidr_parse_ipv4 - Try to parse address as IPv4 and validate prefix
 * @addr_str: IP address string
 * @prefix: Prefix length to validate
 * @network: Output buffer for network address (at least SOCKET_IPV4_ADDR_BYTES)
 * @prefix_len: Output for validated prefix length
 * @family: Output for address family
 *
 * Returns: 0 on success, -1 if not IPv4 or prefix invalid
 */
static int
cidr_parse_ipv4 (const char *addr_str, long prefix, unsigned char *network,
                 int *prefix_len, int *family)
{
  struct in_addr addr4;

  if (inet_pton (SOCKET_AF_INET, addr_str, &addr4) != 1)
    return -1;

  if (prefix > SOCKET_IPV4_MAX_PREFIX)
    return -1;

  memcpy (network, &addr4, SOCKET_IPV4_ADDR_BYTES);
  *prefix_len = (int)prefix;
  *family = SOCKET_AF_INET;
  return 0;
}

/**
 * cidr_parse_ipv6 - Try to parse address as IPv6 and validate prefix
 * @addr_str: IP address string
 * @prefix: Prefix length to validate
 * @network: Output buffer for network address (at least SOCKET_IPV6_ADDR_BYTES)
 * @prefix_len: Output for validated prefix length
 * @family: Output for address family
 *
 * Returns: 0 on success, -1 if not IPv6 or prefix invalid
 */
static int
cidr_parse_ipv6 (const char *addr_str, long prefix, unsigned char *network,
                 int *prefix_len, int *family)
{
  struct in6_addr addr6;

  if (inet_pton (SOCKET_AF_INET6, addr_str, &addr6) != 1)
    return -1;

  if (prefix > SOCKET_IPV6_MAX_PREFIX)
    return -1;

  memcpy (network, &addr6, SOCKET_IPV6_ADDR_BYTES);
  *prefix_len = (int)prefix;
  *family = SOCKET_AF_INET6;
  return 0;
}

/**
 * socketcommon_parse_cidr - Parse CIDR notation into network and prefix
 * @cidr_str: CIDR string (e.g., "192.168.1.0/24" or "2001:db8::/32")
 * @network: Output buffer for network address
 * @prefix_len: Output for prefix length
 * @family: Output for address family (AF_INET or AF_INET6)
 *
 * Returns: 0 on success, -1 on parse error
 */
static int
socketcommon_parse_cidr (const char *cidr_str, unsigned char *network,
                         int *prefix_len, int *family)
{
  char *cidr_copy = NULL;
  char *slash = NULL;
  long prefix_long;
  int result = -1;

  if (!cidr_str || !network || !prefix_len || !family) return -1;

  size_t len = strlen(cidr_str);
  if (len == 0 || len > SOCKET_ERROR_MAX_HOSTNAME + 10) return -1;

  cidr_copy = strdup (cidr_str);
  if (!cidr_copy)
    return -1;

  slash = strchr (cidr_copy, '/');
  if (!slash)
    {
      free (cidr_copy);
      return -1;
    }

  *slash = '\0';
  slash++;

  if (cidr_parse_prefix (slash, &prefix_long) < 0)
    {
      free (cidr_copy);
      return -1;
    }

  /* Try IPv4 first, then IPv6 */
  if (cidr_parse_ipv4 (cidr_copy, prefix_long, network, prefix_len, family) == 0)
    result = 0;
  else if (cidr_parse_ipv6 (cidr_copy, prefix_long, network, prefix_len, family) == 0)
    result = 0;

  free (cidr_copy);
  return result;
}

static void
socketcommon_apply_mask (unsigned char *ip, int prefix_len, int family)
{
  int addr_bytes = (family == SOCKET_AF_INET) ? SOCKET_IPV4_ADDR_BYTES
                                              : SOCKET_IPV6_ADDR_BYTES;
  int bytes_to_mask = prefix_len / SOCKET_BITS_PER_BYTE;
  int bits_to_mask = prefix_len % SOCKET_BITS_PER_BYTE;

  for (int i = bytes_to_mask; i < addr_bytes; i++)
    ip[i] = 0;

  if (bits_to_mask > 0 && bytes_to_mask < addr_bytes)
    ip[bytes_to_mask]
        &= (unsigned char)(0xFF << (SOCKET_BITS_PER_BYTE - bits_to_mask));
}

/**
 * socketcommon_compare_masked_addresses - Compare masked addresses byte-by-byte
 * @masked_ip: IP address with mask applied
 * @network: Network address from CIDR
 * @family: Address family (SOCKET_AF_INET or SOCKET_AF_INET6)
 *
 * Returns: 1 if addresses match, 0 if they differ
 */
static int
socketcommon_compare_masked_addresses (const unsigned char *masked_ip,
                                       const unsigned char *network,
                                       int family)
{
  int addr_bytes = (family == SOCKET_AF_INET) ? SOCKET_IPV4_ADDR_BYTES
                                              : SOCKET_IPV6_ADDR_BYTES;

  for (int i = 0; i < addr_bytes; i++)
    {
      if (masked_ip[i] != network[i])
        return 0;
    }
  return 1;
}

int
SocketCommon_cidr_match (const char *ip_str, const char *cidr_str)
{
  if (!ip_str || !cidr_str) return -1;

  size_t ip_len = strlen(ip_str);
  size_t cidr_len = strlen(cidr_str);
  if (ip_len == 0 || ip_len > SOCKET_ERROR_MAX_HOSTNAME ||
      cidr_len == 0 || cidr_len > SOCKET_ERROR_MAX_HOSTNAME + 10 /* for /prefix */) {
    return -1;
  }

  unsigned char network[SOCKET_IPV6_ADDR_BYTES] = { 0 };
  unsigned char ip[SOCKET_IPV6_ADDR_BYTES] = { 0 };
  int prefix_len;
  int cidr_family;
  int ip_family;

  if (socketcommon_parse_cidr (cidr_str, network, &prefix_len, &cidr_family)
      != 0)
    return -1;

  if (!SocketCommon_parse_ip (ip_str, &ip_family))
    return -1;

  if (ip_family != cidr_family)
    return 0;

  if (ip_family == SOCKET_AF_INET)
    {
      struct in_addr addr4;
      if (inet_pton (SOCKET_AF_INET, ip_str, &addr4) != 1)
        return -1;
      memcpy (ip, &addr4, SOCKET_IPV4_ADDR_BYTES);
    }
  else if (ip_family == SOCKET_AF_INET6)
    {
      struct in6_addr addr6;
      if (inet_pton (SOCKET_AF_INET6, ip_str, &addr6) != 1)
        return -1;
      memcpy (ip, &addr6, SOCKET_IPV6_ADDR_BYTES);
    }
  else
    {
      return -1;
    }

  socketcommon_apply_mask (ip, prefix_len, ip_family);

  return socketcommon_compare_masked_addresses (ip, network, ip_family);
}

/* ==================== RFC 1123 Hostname Validation ==================== */

/**
 * socketcommon_is_valid_label_char - Check if character is valid for hostname
 * label
 * @c: Character to check
 * @at_start: True if this is the first character of a label
 *
 * Returns: true if valid character for position
 *
 * Per RFC 1123: label start must be alphanumeric; other positions allow hyphen.
 * This prevents malformed hostnames from reaching getaddrinfo() and causing
 * 5+ second DNS timeouts.
 */
static bool
socketcommon_is_valid_label_char (char c, bool at_start)
{
  if (at_start)
    return isalnum ((unsigned char)c) != 0;
  return isalnum ((unsigned char)c) != 0 || c == '-';
}

/**
 * socketcommon_is_valid_label_length - Check label length within RFC 1035
 * bounds
 * @label_len: Current label length
 *
 * Returns: true if within bounds (1 to SOCKET_DNS_MAX_LABEL_LENGTH)
 *
 * Labels must be 1-63 characters per RFC 1035. Empty labels (from consecutive
 * dots "..") are invalid.
 */
static bool
socketcommon_is_valid_label_length (int label_len)
{
  return label_len > 0 && label_len <= SOCKET_DNS_MAX_LABEL_LENGTH;
}

/**
 * socketcommon_validate_hostname_labels - Validate RFC 1123 hostname labels
 * @hostname: Hostname string to validate
 *
 * Returns: 1 if all labels valid, 0 if invalid
 *
 * Validates that each dot-separated label:
 * - Starts with alphanumeric character (not hyphen or dot)
 * - Contains only alphanumeric or hyphen characters
 * - Has length between 1 and 63 characters
 */
static int
socketcommon_validate_hostname_labels (const char *hostname)
{
  const char *p = hostname;
  int label_len = 0;
  bool at_label_start = true;

  while (*p)
    {
      if (*p == '.')
        {
          /* Dot separator - validate completed label and reset
           * Rejects consecutive dots (label_len=0) as empty labels per RFC 1035
           */
          if (!socketcommon_is_valid_label_length (label_len))
            return 0;
          at_label_start = true;
          label_len = 0;
        }
      else
        {
          /* Label character - validate and update state */
          if (!socketcommon_is_valid_label_char (*p, at_label_start))
            return 0;
          at_label_start = false;
          label_len++;
        }
      p++;
    }

  /* Validate final label - reject trailing dot with empty final label */
  return socketcommon_is_valid_label_length (label_len);
}

/**
 * socketcommon_is_ip_address - Check if string is an IP address
 * @host: String to check
 *
 * Returns: 1 if valid IPv4 or IPv6 address, 0 if hostname
 *
 * IP addresses bypass hostname validation since they go directly to
 * inet_pton() without DNS resolution.
 */
bool
socketcommon_is_ip_address (const char *host)
{
  if (!host) return false;

  size_t len = strlen(host);
  if (len == 0 || len > SOCKET_ERROR_MAX_HOSTNAME) return false;

  struct in_addr addr4;
  struct in6_addr addr6;

  if (inet_pton (SOCKET_AF_INET, host, &addr4) == 1)
    return true;
  if (inet_pton (SOCKET_AF_INET6, host, &addr6) == 1)
    return true;
  return false;
}

/**
 * socketcommon_validate_hostname_internal - Validate hostname with RFC 1123
 * compliance
 * @host: Hostname to validate (NULL allowed for wildcard bind)
 * @use_exceptions: If true, raise exception on invalid; if false, return -1
 * @exception_type: Exception type to raise on failure
 *
 * Returns: 0 on success, -1 on failure
 *
 * WARNING: This function only validates hostname SYNTAX per RFC 1123.
 * It does NOT prevent DNS resolution delays for non-existent domains.
 * DNS resolution via getaddrinfo() can block for 5+ seconds with retries.
 *
 * For applications requiring non-blocking behavior:
 * - Use IP addresses directly (no DNS lookup needed)
 * - Use SocketDNS for async resolution with timeout control
 * - Use "localhost" for local testing
 */
int
socketcommon_validate_hostname_internal (const char *host, int use_exceptions,
                                         Except_T exception_type)
{
  size_t host_len;

  /* NULL is valid - used for wildcard bind with AI_PASSIVE */
  if (!host)
    return 0;

  host_len = strlen (host);

  /* Check length bounds */
  if (host_len == 0 || host_len > SOCKET_ERROR_MAX_HOSTNAME) {
    if (use_exceptions) {
      SOCKET_RAISE_MSG (SocketCommon, exception_type, "Invalid hostname length: %zu (max %d)", host_len, SOCKET_ERROR_MAX_HOSTNAME);
    } else {
      SOCKET_ERROR_MSG ("Invalid hostname length: %zu (max %d)", host_len,
                        SOCKET_ERROR_MAX_HOSTNAME);
    }
    return -1;
  }

  /* Skip validation for IP addresses - they bypass DNS resolution */
  if (socketcommon_is_ip_address (host))
    return 0;

  /* RFC 1123 hostname validation */
  if (!socketcommon_validate_hostname_labels (host)) {
    if (use_exceptions) {
      SOCKET_RAISE_MSG (SocketCommon, exception_type, "Invalid hostname format: %.64s", host);
    } else {
      SOCKET_ERROR_MSG ("Invalid hostname format: %.64s", host);
    }
    return -1;
  }

  return 0;
}

void
SocketCommon_validate_hostname (const char *host, Except_T exception_type)
{
  if (socketcommon_validate_hostname_internal (host, 1, exception_type) != 0)
    return;
}

/* ==================== Socket Option Operations ==================== */

static void
set_single_timeout_opt (int fd, int optname, const char *opt_desc, const struct timeval *tv, Except_T exc_type)
{
  if (setsockopt (fd, SOCKET_SOL_SOCKET, optname, tv, sizeof (*tv)) < 0)
    {
      SOCKET_RAISE_FMT (SocketCommon, exc_type, "Failed to set %s timeout", opt_desc);
    }
}

int
SocketCommon_create_fd (int domain, int type, int protocol, Except_T exc_type)
{
  /* Validate supported domain, type, protocol for security (Section 4) */
  if (domain != AF_INET && domain != AF_INET6 && domain != AF_UNIX) {
    SOCKET_RAISE_FMT (SocketCommon, exc_type, "Unsupported address domain: %d (only AF_INET/AF_INET6/AF_UNIX)", domain);
  }
  if (type != SOCK_STREAM && type != SOCK_DGRAM) {
    SOCKET_RAISE_FMT (SocketCommon, exc_type, "Unsupported socket type: %d (only SOCK_STREAM/SOCK_DGRAM)", type);
  }
  if (protocol != 0 && protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
    SOCKET_RAISE_FMT (SocketCommon, exc_type, "Unsupported protocol: %d (only 0/TCP/UDP)", protocol);
  }

  int fd;

#if SOCKET_HAS_SOCK_CLOEXEC
  fd = socket (domain, type | SOCK_CLOEXEC, protocol);
#else
  fd = socket (domain, type, protocol);
#endif

  if (fd < 0)
    {
      SOCKET_RAISE_FMT (SocketCommon, exc_type,
          "Failed to create socket (domain=%d, type=%d, protocol=%d)",
          domain, type, protocol);
    }

#if !SOCKET_HAS_SOCK_CLOEXEC
  if (fcntl (fd, F_SETFD, FD_CLOEXEC) < 0)
    {
      int saved_errno = errno;
      SAFE_CLOSE (fd);
      errno = saved_errno;
      SOCKET_RAISE_MSG (SocketCommon, exc_type, "Failed to set close-on-exec flag");
    }
#endif

  return fd;
}

int
SocketCommon_setcloexec (int fd, int enable)
{
  int flags;
  int new_flags;

  assert (fd >= 0);

  flags = fcntl (fd, F_GETFD);
  if (flags < 0)
    return -1;

  if (enable)
    new_flags = flags | SOCKET_FD_CLOEXEC;
  else
    new_flags = flags & ~SOCKET_FD_CLOEXEC;

  if (new_flags == flags)
    return 0;

  if (fcntl (fd, F_SETFD, new_flags) < 0)
    return -1;

  return 0;
}

int
SocketCommon_has_cloexec (int fd)
{
  int flags;

  assert (fd >= 0);

  flags = fcntl (fd, F_GETFD);
  if (flags < 0)
    return -1;

  return (flags & SOCKET_FD_CLOEXEC) ? 1 : 0;
}

void
SocketCommon_set_cloexec_fd (int fd, bool enable, Except_T exc_type)
{
  /* Delegate to low-level function and raise exception on failure */
  if (SocketCommon_setcloexec (fd, enable ? 1 : 0) < 0)
    {
      SOCKET_RAISE_FMT (SocketCommon, exc_type, "Failed to %s close-on-exec flag on fd %d",
                        enable ? "set" : "clear", fd);
    }
}

void
SocketCommon_set_nonblock (SocketBase_T base, bool enable, Except_T exc_type)
{
  int flags = fcntl (SocketBase_fd (base), F_GETFL, 0);
  if (flags < 0)
    {
      SOCKET_RAISE_MSG (SocketCommon, exc_type, "Failed to get file flags");
    }

  if (enable)
    flags |= O_NONBLOCK;
  else
    flags &= ~O_NONBLOCK;

  if (fcntl (SocketBase_fd (base), F_SETFL, flags) < 0)
    {
      SOCKET_RAISE_MSG (SocketCommon, exc_type, "Failed to set non-blocking mode");
    }
}

int
SocketCommon_getoption_int (int fd, int level, int optname, int *value,
                            Except_T exception_type)
{
  socklen_t len = sizeof (*value);

  assert (fd >= 0);
  assert (value);

  if (getsockopt (fd, level, optname, value, &len) < 0)
    {
      SOCKET_RAISE_FMT (SocketCommon, exception_type, "Failed to get socket option (level=%d, optname=%d)", level, optname);
      return -1;
    }

  return 0;
}

int
SocketCommon_getoption_timeval (int fd, int level, int optname,
                                struct timeval *tv, Except_T exception_type)
{
  socklen_t len = sizeof (*tv);

  assert (fd >= 0);
  assert (tv);

  if (getsockopt (fd, level, optname, tv, &len) < 0)
    {
      SOCKET_RAISE_FMT (SocketCommon, exception_type,
          "Failed to get socket timeout option (level=%d, optname=%d)", level, optname);
      return -1;
    }

  return 0;
}

int
SocketCommon_get_family (SocketBase_T base, bool raise_on_fail,
                         Except_T exc_type)
{
#if SOCKET_HAS_SO_DOMAIN
  {
    int family;
    socklen_t opt_len = sizeof (family);
    if (getsockopt (SocketBase_fd (base), SOL_SOCKET, SO_DOMAIN, &family,
                    &opt_len)
        == 0)
      return family;
  }
#endif

  struct sockaddr_storage addr;
  socklen_t addr_len = sizeof (addr);
  memset (&addr, 0, sizeof (addr));
  if (getsockname (SocketBase_fd (base), (struct sockaddr *)&addr, &addr_len)
      == 0)
    return addr.ss_family;

  if (raise_on_fail)
    {
      SOCKET_RAISE_MSG (SocketCommon, exc_type, "Failed to get socket family via SO_DOMAIN or getsockname");
    }

  return AF_UNSPEC;
}

int
SocketCommon_get_socket_family (SocketBase_T base)
{
  Except_T dummy = { NULL, NULL };
  return SocketCommon_get_family (base, false, dummy);
}

void
SocketCommon_set_option_int (SocketBase_T base, int level, int optname,
                             int value, Except_T exc_type)
{
  if (setsockopt (SocketBase_fd (base), level, optname, &value, sizeof (value))
      < 0)
    {
      SOCKET_RAISE_FMT (SocketCommon, exc_type,
          "Failed to set socket option level=%d optname=%d value=%d",
          level, optname, value);
    }
}

void
SocketCommon_setreuseaddr (SocketBase_T base, Except_T exc_type)
{
  if (!base) {
    SOCKET_RAISE_MSG (SocketCommon, exc_type, "Invalid base pointer");
  }
  SocketCommon_set_option_int (base, SOCKET_SOL_SOCKET, SOCKET_SO_REUSEADDR, 1,
                               exc_type);
}

void
SocketCommon_setreuseport (SocketBase_T base, Except_T exc_type)
{
  if (!base) {
    SOCKET_RAISE_MSG (SocketCommon, exc_type, "Invalid base pointer");
  }

#if SOCKET_HAS_SO_REUSEPORT
  SocketCommon_set_option_int (base, SOCKET_SOL_SOCKET, SOCKET_SO_REUSEPORT, 1,
                               exc_type);
#else
  SOCKET_RAISE_MSG (SocketCommon, exc_type, "SO_REUSEPORT not supported on this platform");
#endif
}

void
SocketCommon_settimeout (SocketBase_T base, int timeout_sec, Except_T exc_type)
{
  struct timeval tv;

  if (!base) {
    SOCKET_RAISE_MSG (SocketCommon, exc_type, "Invalid base pointer");
  }

  if (timeout_sec < 0)
    {
      SOCKET_RAISE_MSG (SocketCommon, exc_type, "Invalid timeout value: %d (must be >= 0)", timeout_sec);
    }

  tv.tv_sec = timeout_sec;
  tv.tv_usec = 0;

  set_single_timeout_opt (SocketBase_fd (base), SOCKET_SO_RCVTIMEO, "receive", &tv, exc_type);

  set_single_timeout_opt (SocketBase_fd (base), SOCKET_SO_SNDTIMEO, "send", &tv, exc_type);
}

void
SocketCommon_setcloexec_with_error (SocketBase_T base, int enable,
                                    Except_T exc_type)
{
  assert (base);

  if (SocketCommon_setcloexec (SocketBase_fd (base), enable) < 0)
    {
      SOCKET_RAISE_FMT (SocketCommon, exc_type, "Failed to %s close-on-exec flag",
                        enable ? "set" : "clear");
    }
}

void
SocketCommon_disable_sigpipe (int fd)
{
  /* On BSD/macOS, use SO_NOSIGPIPE to suppress SIGPIPE at socket level.
   * This is a one-time setup done at socket creation.
   * On Linux, MSG_NOSIGNAL is used per-send operation instead. */
#if SOCKET_HAS_SO_NOSIGPIPE
  int optval = 1;
  if (setsockopt (fd, SOL_SOCKET, SO_NOSIGPIPE, &optval, sizeof (optval)) < 0)
    {
      /* Log but don't fail - this is a secondary defense.
       * Primary SIGPIPE suppression is via MSG_NOSIGNAL on send operations,
       * which is always used on all platforms. SO_NOSIGPIPE failure is rare
       * and does not affect functionality. */
      SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                       "Failed to set SO_NOSIGPIPE on fd %d: %s", fd,
                       Socket_safe_strerror (errno));
    }
#else
  (void)fd; /* Suppress unused parameter warning on Linux */
#endif
}

/* ==================== Base Lifecycle ==================== */

SocketBase_T
SocketCommon_new_base (int domain, int type, int protocol)
{
  Arena_T arena;
  SocketBase_T base;
  int fd;
  Except_T exc_type = Socket_Failed;

  arena = Arena_new ();

  base = Arena_calloc (arena, 1, sizeof (struct SocketBase_T), __FILE__,
                       __LINE__);
  if (!base)
    {
      Arena_dispose (&arena);
      SOCKET_RAISE_MSG (SocketCommon, exc_type, SOCKET_ENOMEM ": Cannot allocate base structure");
    }

  base->arena = arena;

  fd = SocketCommon_create_fd (domain, type, protocol, exc_type);
  SocketCommon_init_base (base, fd, domain, type, protocol, exc_type);

  return base;
}

void
SocketCommon_free_base (SocketBase_T *base_ptr)
{
  SocketBase_T base = *base_ptr;
  if (!base)
    return;

  if (base->fd >= 0)
    {
      int fd = base->fd;
      base->fd = -1;
      SAFE_CLOSE (fd);
    }

  *base_ptr = NULL;
  Arena_T arena_to_dispose = base->arena;
  Arena_dispose (&arena_to_dispose);
}

void
SocketCommon_init_base (SocketBase_T base, int fd, int domain, int type,
                        int protocol, Except_T exc_type)
{
  (void)exc_type;
  base->fd = fd;
  base->domain = domain;
  base->type = type;
  base->protocol = protocol;

  base->remote_addrlen = sizeof (base->remote_addr);
  memset (&base->remote_addr, 0, sizeof (base->remote_addr));
  base->local_addrlen = 0;
  memset (&base->local_addr, 0, sizeof (base->local_addr));
  base->remoteaddr = NULL;
  base->remoteport = 0;
  base->localaddr = NULL;
  base->localport = 0;

  pthread_mutex_lock (&socket_default_timeouts_mutex);
  base->timeouts = socket_default_timeouts;
  pthread_mutex_unlock (&socket_default_timeouts_mutex);

  /* Suppress SIGPIPE at socket level on BSD/macOS */
  SocketCommon_disable_sigpipe (fd);
}

void
SocketCommon_update_local_endpoint (SocketBase_T base)
{
  struct sockaddr_storage local;
  socklen_t len = sizeof (local);

  /* Initialize to zero to avoid Valgrind warnings about uninitialized memory
   * when getsockname only partially fills the structure (e.g., Unix sockets). */
  memset (&local, 0, sizeof (local));

  if (getsockname (SocketBase_fd (base), (struct sockaddr *)&local, &len) < 0)
    {
      SOCKET_ERROR_MSG ("Failed to update local endpoint: %s",
                        Socket_safe_strerror (errno));
      memset (&base->local_addr, 0, sizeof (base->local_addr));
      base->local_addrlen = 0;
      base->localaddr = NULL;
      base->localport = 0;
      return;
    }

  base->local_addr = local;
  base->local_addrlen = len;

  if (SocketCommon_cache_endpoint (SocketBase_arena (base),
                                   (struct sockaddr *)&local, len,
                                   &base->localaddr, &base->localport)
      != 0)
    {
      base->localaddr = NULL;
      base->localport = 0;
    }
}

/* ==================== Accessor Functions ==================== */

int
SocketBase_fd (SocketBase_T base)
{
  return base ? base->fd : -1;
}

Arena_T
SocketBase_arena (SocketBase_T base)
{
  return base ? base->arena : NULL;
}

int
SocketBase_domain (SocketBase_T base)
{
  return base ? base->domain : AF_UNSPEC;
}

void
SocketBase_set_timeouts (SocketBase_T base, const SocketTimeouts_T *timeouts)
{
  if (base && timeouts)
    base->timeouts = *timeouts;
}

void
SocketCommon_timeouts_getdefaults (SocketTimeouts_T *timeouts)
{
  if (!timeouts) {
    SOCKET_ERROR_MSG ("NULL pointer for timeouts output");
    return;
  }

  pthread_mutex_lock (&socket_default_timeouts_mutex);
  *timeouts = socket_default_timeouts;
  pthread_mutex_unlock (&socket_default_timeouts_mutex);
}

void
SocketCommon_timeouts_setdefaults (const SocketTimeouts_T *timeouts)
{
  if (!timeouts) {
    SOCKET_ERROR_MSG ("NULL pointer for timeouts input");
    return;
  }

  SocketTimeouts_T local;

  pthread_mutex_lock (&socket_default_timeouts_mutex);
  local = socket_default_timeouts;
  local.connect_timeout_ms = socketcommon_sanitize_timeout (timeouts->connect_timeout_ms);
  local.dns_timeout_ms = socketcommon_sanitize_timeout (timeouts->dns_timeout_ms);
  local.operation_timeout_ms = socketcommon_sanitize_timeout (timeouts->operation_timeout_ms);
  socket_default_timeouts = local;
  pthread_mutex_unlock (&socket_default_timeouts_mutex);
}

/* ==================== Address Resolution ==================== */

void
SocketCommon_setup_hints (struct addrinfo *hints, int socktype, int flags)
{
  memset (hints, 0, sizeof (*hints));
  hints->ai_family = SOCKET_AF_UNSPEC;
  hints->ai_socktype = socktype;
  hints->ai_flags = flags;
  hints->ai_protocol = 0;
}

/**
 * socketcommon_perform_getaddrinfo - Perform DNS resolution with timeout
 * @host: Hostname or IP address (NULL for wildcard)
 * @port_str: Port number as string
 * @hints: Address resolution hints
 * @res: Output pointer for result
 * @use_exceptions: If true, raise exceptions on error
 * @exception_type: Exception type to raise
 *
 * Returns: 0 on success, -1 on failure
 *
 * Uses the global DNS resolver with timeout guarantees. This prevents
 * unbounded blocking on DNS failures (which could block for 30+ seconds
 * with direct getaddrinfo calls).
 */
static int
socketcommon_perform_getaddrinfo (const char *host, const char *port_str,
                                  const struct addrinfo *hints,
                                  struct addrinfo **res, int use_exceptions,
                                  Except_T exception_type)
{
  SocketDNS_T dns;
  volatile int port;
  int timeout_ms;

  /* Parse port string safely with validation */
  port = 0;
  if (port_str && *port_str) {
    char *endptr;
    long p = strtol (port_str, &endptr, 10);
    if (endptr != port_str && *endptr == '\0' && p >= 1 && p <= 65535) {
      port = (int)p;
    } else {
      /* Invalid port - will use default in getaddrinfo */
      port = 0;
    }
  }

  /* Get global DNS resolver with timeout support */
  dns = SocketCommon_get_dns_resolver ();
  if (!dns)
    {
      /* Fallback to direct getaddrinfo if resolver unavailable */
      struct addrinfo *tmp = NULL;
      int result = getaddrinfo (host, port_str, hints, &tmp);
      if (result != 0)
        {
          const char *safe_host = socketcommon_get_safe_host (host);
          if (use_exceptions) {
            SOCKET_RAISE_MSG (SocketCommon, exception_type, "Invalid host/IP address: %.*s (%s)",
                              SOCKET_ERROR_MAX_HOSTNAME, safe_host,
                              gai_strerror (result));
          } else {
            SOCKET_ERROR_MSG ("Invalid host/IP address: %.*s (%s)",
                              SOCKET_ERROR_MAX_HOSTNAME, safe_host,
                              gai_strerror (result));
          }
          return -1;
        }

      /* Copy to ensure consistent allocation for SocketCommon_free_addrinfo */
      *res = SocketCommon_copy_addrinfo (tmp);
      freeaddrinfo (tmp);

      if (!*res)
        {
          if (use_exceptions) {
            SOCKET_RAISE_MSG (SocketCommon, exception_type, "Failed to copy address info");
          } else {
            SOCKET_ERROR_MSG ("Failed to copy address info");
          }
          return -1;
        }
      return 0;
    }

  /* Fast path for IP addresses and NULL host: direct getaddrinfo with copy */
  if (host == NULL || socketcommon_is_ip_address (host))
    {
      struct addrinfo *tmp_res = NULL;
      int gai_err = getaddrinfo (host, port_str, hints, &tmp_res);
      if (gai_err != 0)
        {
          const char *err_msg = gai_strerror (gai_err);
          const char *safe_host = host ? host : "<any>";
          if (use_exceptions)
            {
              SOCKET_RAISE_MSG (SocketCommon, exception_type,
                                "getaddrinfo failed for %s:%s: %s",
                                safe_host, port_str, err_msg);
            }
          else
            {
              SOCKET_ERROR_MSG ("getaddrinfo failed for %s:%s: %s",
                                safe_host, port_str, err_msg);
              return -1;
            }
        }
      *res = SocketCommon_copy_addrinfo (tmp_res);
      freeaddrinfo (tmp_res);
      if (!*res)
        {
          if (use_exceptions)
            SOCKET_RAISE_MSG (SocketCommon, exception_type, "Failed to copy addrinfo from getaddrinfo");
          else
            {
              SOCKET_ERROR_MSG ("Failed to copy addrinfo from getaddrinfo");
              return -1;
            }
        }
      return 0;
    }

  /* Hostname resolution: use DNS resolver with timeout */
  timeout_ms = SocketCommon_get_dns_timeout ();

  TRY
    *res = SocketDNS_resolve_sync (dns, host, port, hints, timeout_ms);
  EXCEPT (SocketDNS_Failed)
    {
      const char *safe_host = socketcommon_get_safe_host (host);
      if (use_exceptions) {
        SOCKET_RAISE_MSG (SocketCommon, exception_type, "DNS resolution failed: %.*s", SOCKET_ERROR_MAX_HOSTNAME, safe_host);
      } else {
        SOCKET_ERROR_MSG ("DNS resolution failed: %.*s", SOCKET_ERROR_MAX_HOSTNAME, safe_host);
      }
      return -1;
    }
  END_TRY;

  return 0;
}

static int
socketcommon_find_matching_family (struct addrinfo *res, int socket_family)
{
  const struct addrinfo *rp;

  for (rp = res; rp != NULL; rp = rp->ai_next)
    {
      if (rp->ai_family == socket_family)
        return 1;
    }
  return 0;
}

static int
socketcommon_validate_address_family (struct addrinfo **res, int socket_family,
                                      const char *host, int port,
                                      int use_exceptions,
                                      Except_T exception_type)
{
  const char *safe_host;

  if (socket_family == SOCKET_AF_UNSPEC)
    return 0;

  if (socketcommon_find_matching_family (*res, socket_family))
    return 0;

  /* Free the result before reporting error to prevent memory leak */
  SocketCommon_free_addrinfo (*res);
  *res = NULL;

  safe_host = socketcommon_get_safe_host (host);
  if (use_exceptions) {
    SOCKET_RAISE_MSG (SocketCommon, exception_type, "No address found for family %d: %.*s:%d", socket_family, SOCKET_ERROR_MAX_HOSTNAME, safe_host, port);
  } else {
    SOCKET_ERROR_MSG ("No address found for family %d: %.*s:%d", socket_family, SOCKET_ERROR_MAX_HOSTNAME, safe_host, port);
  }
  return -1;
}

/**
 * resolve_prepare_params - Validate hostname and prepare port string
 * @host: Hostname to validate
 * @port: Port number to convert
 * @port_str: Output buffer for port string
 * @port_str_size: Size of port string buffer
 * @use_exceptions: If true, raise exceptions on error
 * @exception_type: Exception type to raise
 *
 * Returns: 0 on success, -1 on validation failure
 * Thread-safe: Yes (uses thread-local error buffer)
 */
static int
resolve_prepare_params (const char *host, int port, char *port_str,
                        size_t port_str_size, int use_exceptions,
                        Except_T exception_type)
{
  if (socketcommon_validate_hostname_internal (host, use_exceptions,
                                               exception_type)
      != 0)
    return -1;

  socketcommon_convert_port_to_string (port, port_str, port_str_size);
  return 0;
}

int
SocketCommon_resolve_address (const char *host, int port,
                              const struct addrinfo *hints,
                              struct addrinfo **res, Except_T exception_type,
                              int socket_family, int use_exceptions)
{
  char port_str[SOCKET_PORT_STR_BUFSIZE];

  if (resolve_prepare_params (host, port, port_str, sizeof (port_str),
                              use_exceptions, exception_type)
      != 0)
    return -1;

  if (socketcommon_perform_getaddrinfo (host, port_str, hints, res,
                                        use_exceptions, exception_type)
      != 0)
    return -1;

  if (socketcommon_validate_address_family (res, socket_family, host, port,
                                            use_exceptions, exception_type)
      != 0)
    return -1;

  return 0;
}

/**
 * copy_addrinfo_address - Copy address from addrinfo node
 * @dst: Destination node (must be allocated)
 * @src: Source node
 *
 * Returns: 0 on success, -1 on allocation failure
 */
static int
copy_addrinfo_address (struct addrinfo *dst, const struct addrinfo *src)
{
  if (src->ai_addr && src->ai_addrlen > 0)
    {
      dst->ai_addr = malloc (src->ai_addrlen);
      if (!dst->ai_addr)
        return -1;
      memcpy (dst->ai_addr, src->ai_addr, src->ai_addrlen);
    }
  else
    {
      dst->ai_addr = NULL;
      dst->ai_addrlen = 0;
    }
  return 0;
}

/**
 * copy_addrinfo_canonname - Copy canonical name from addrinfo node
 * @dst: Destination node (must be allocated)
 * @src: Source node
 *
 * Returns: 0 on success, -1 on allocation failure
 */
static int
copy_addrinfo_canonname (struct addrinfo *dst, const struct addrinfo *src)
{
  if (src->ai_canonname)
    {
      size_t len = strlen (src->ai_canonname) + 1;
      dst->ai_canonname = malloc (len);
      if (!dst->ai_canonname)
        return -1;
      memcpy (dst->ai_canonname, src->ai_canonname, len);
    }
  else
    {
      dst->ai_canonname = NULL;
    }
  return 0;
}

/**
 * copy_single_addrinfo_node - Copy a single addrinfo node
 * @src: Source node to copy
 *
 * Returns: Newly allocated copy, or NULL on failure
 */
static struct addrinfo *
copy_single_addrinfo_node (const struct addrinfo *src)
{
  struct addrinfo *new_node = malloc (sizeof (struct addrinfo));
  if (!new_node)
    return NULL;

  memcpy (new_node, src, sizeof (struct addrinfo));
  new_node->ai_next = NULL;

  if (copy_addrinfo_address (new_node, src) < 0)
    {
      free (new_node);
      return NULL;
    }

  if (copy_addrinfo_canonname (new_node, src) < 0)
    {
      if (new_node->ai_addr)
        free (new_node->ai_addr);
      free (new_node);
      return NULL;
    }

  return new_node;
}

/**
 * SocketCommon_free_addrinfo - Free addrinfo chain created by copy_addrinfo
 * @ai: Chain to free (may be NULL, safe no-op)
 *
 * Frees all nodes in the chain including ai_addr and ai_canonname fields.
 * Use this instead of freeaddrinfo() for chains from SocketCommon_copy_addrinfo.
 */
void
SocketCommon_free_addrinfo (struct addrinfo *ai)
{
  while (ai)
    {
      struct addrinfo *next = ai->ai_next;
      if (ai->ai_addr)
        free (ai->ai_addr);
      if (ai->ai_canonname)
        free (ai->ai_canonname);
      free (ai);
      ai = next;
    }
}

static void
free_partial_addrinfo_chain (struct addrinfo *head)
{
  SocketCommon_free_addrinfo (head);
}

struct addrinfo *
SocketCommon_copy_addrinfo (const struct addrinfo *src)
{
  struct addrinfo *head = NULL;
  struct addrinfo *tail = NULL;
  const struct addrinfo *p;

  if (!src)
    return NULL;

  p = src;
  while (p)
    {
      struct addrinfo *new_node = copy_single_addrinfo_node (p);
      if (!new_node)
        {
          free_partial_addrinfo_chain (head);
          return NULL;
        }

      if (!head)
        {
          head = tail = new_node;
        }
      else
        {
          tail->ai_next = new_node;
          tail = new_node;
        }
      p = p->ai_next;
    }

  return head;
}

int
SocketCommon_reverse_lookup (const struct sockaddr *addr, socklen_t addrlen,
                             char *host, socklen_t hostlen, char *serv,
                             socklen_t servlen, int flags,
                             Except_T exception_type)
{
  int result;

  if (!addr || addrlen == 0) {
    SOCKET_ERROR_MSG ("Invalid address for reverse lookup");
    RAISE_MODULE_ERROR (exception_type);
    return -1;
  }

  if ((host && hostlen == 0) || (serv && servlen == 0)) {
    SOCKET_ERROR_MSG ("Invalid buffer sizes for reverse lookup");
    RAISE_MODULE_ERROR (exception_type);
    return -1;
  }

  result = getnameinfo (addr, addrlen, host, hostlen, serv, servlen, flags);
  if (result != 0)
    {
      SOCKET_ERROR_MSG ("Reverse lookup failed: %s", gai_strerror (result));
      RAISE_MODULE_ERROR (exception_type);
      return -1;
    }

  return 0;
}

/* ==================== Bind Operations ==================== */

int
SocketCommon_try_bind_address (SocketBase_T base, const struct sockaddr *addr,
                               socklen_t addrlen, Except_T exc_type)
{
  int fd = SocketBase_fd (base);
  int ret = bind (fd, addr, addrlen);
  if (ret == 0)
    {
      SocketCommon_update_local_endpoint (base);
      return 0;
    }

  SocketCommon_handle_bind_error (errno, "unknown addr", exc_type);
  return -1;
}

int
SocketCommon_try_bind_resolved_addresses (SocketBase_T base,
                                          struct addrinfo *res, int family,
                                          Except_T exc_type)
{
  struct addrinfo *rp;

  SocketCommon_set_option_int (base, SOL_SOCKET, SO_REUSEADDR, 1, exc_type);

  for (rp = res; rp != NULL; rp = rp->ai_next)
    {
      if (family != AF_UNSPEC && rp->ai_family != family)
        continue;

      if (SocketCommon_try_bind_address (base, rp->ai_addr, rp->ai_addrlen,
                                         exc_type)
          == 0)
        {
          return 0;
        }
    }

  SOCKET_RAISE_MSG (SocketCommon, exc_type, "Bind failed for all resolved addresses");
  return -1;
}

int
SocketCommon_handle_bind_error (int err, const char *addr_str,
                                Except_T exc_type)
{
  if (err == EADDRINUSE)
    {
      SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                       "Address %s already in use - retry later?", addr_str);
      return -1;
    }
  else if (err == EADDRNOTAVAIL)
    {
      SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                       "Address %s not available on local machine", addr_str);
      return -1;
    }
  else if (err == EACCES || err == EPERM)
    SOCKET_RAISE_FMT (SocketCommon, exc_type, "Permission denied binding %s (cap_net_bind_service?)", addr_str);
  else
    SOCKET_RAISE_FMT (SocketCommon, exc_type, "Unexpected bind error for %s", addr_str);
  return -1;
}

void
SocketCommon_format_bind_error (const char *host, int port)
{
  const char *addr_str = host ? host : "any";

  switch (errno)
    {
    case EADDRINUSE:
      SOCKET_ERROR_MSG ("Address %s:%d already in use", addr_str, port);
      break;
    case EADDRNOTAVAIL:
      SOCKET_ERROR_MSG ("Address %s not available", addr_str);
      break;
    case EACCES:
    case EPERM:
      SOCKET_ERROR_MSG ("Permission denied binding to %s:%d", addr_str, port);
      break;
    case EAFNOSUPPORT:
      SOCKET_ERROR_MSG ("Address family not supported for %s", addr_str);
      break;
    default:
      SOCKET_ERROR_FMT ("Bind failed for %s:%d", addr_str, port);
      break;
    }
}

/* ==================== I/O Vector Operations ==================== */

size_t
SocketCommon_calculate_total_iov_len (const struct iovec *iov, int iovcnt)
{
  size_t total = 0;
  int i;

  if (!iov || iovcnt <= 0 || iovcnt > IOV_MAX)
    {
      SOCKET_RAISE_FMT (SocketCommon, SocketCommon_Failed, "Invalid iov params: iov=%p iovcnt=%d", (void *)iov, iovcnt);
    }

  for (i = 0; i < iovcnt; i++)
    {
      size_t new_total;
      if (!SocketSecurity_check_add(total, iov[i].iov_len, &new_total))
        {
          SOCKET_RAISE_FMT (SocketCommon, SocketCommon_Failed, "iov[%d] overflow: total=%zu + len=%zu > SIZE_MAX", i, total, iov[i].iov_len);
        }
      total = new_total;
    }

  return total;
}

void
SocketCommon_advance_iov (struct iovec *iov, int iovcnt, size_t bytes)
{
  size_t remaining = bytes;
  int i;
  size_t total_len;

  if (!iov || iovcnt <= 0 || iovcnt > IOV_MAX)
    {
      SOCKET_RAISE_FMT (SocketCommon, SocketCommon_Failed, "Invalid advance params: iov=%p iovcnt=%d bytes=%zu", (void *)iov, iovcnt, bytes);
    }

  total_len = SocketCommon_calculate_total_iov_len (iov, iovcnt);

  if (bytes > total_len)
    {
      SOCKET_RAISE_FMT (SocketCommon, SocketCommon_Failed, "Advance too far: bytes=%zu > total=%zu", bytes, total_len);
    }

  for (i = 0; i < iovcnt && remaining > 0; i++)
    {
      if (remaining >= iov[i].iov_len)
        {
          remaining -= iov[i].iov_len;
          iov[i].iov_base = NULL;
          iov[i].iov_len = 0;
        }
      else
        {
          iov[i].iov_base = (char *)iov[i].iov_base + remaining;
          iov[i].iov_len -= remaining;
          remaining = 0;
        }
    }
}

struct iovec *
SocketCommon_find_active_iov (struct iovec *iov, int iovcnt, int *active_iovcnt)
{
  int i;

  assert (iov);
  assert (iovcnt > 0);
  assert (active_iovcnt);

  for (i = 0; i < iovcnt; i++)
    {
      if (iov[i].iov_len > 0)
        {
          *active_iovcnt = iovcnt - i;
          return &iov[i];
        }
    }

  *active_iovcnt = 0;
  return NULL;
}

void
SocketCommon_sync_iov_progress (struct iovec *original, const struct iovec *copy,
                                int iovcnt)
{
  int i;

  assert (original);
  assert (copy);
  assert (iovcnt > 0);

  for (i = 0; i < iovcnt; i++)
    {
      /* If the copy base differed from the original base, the copy was
       * advanced. Update the original iovec to reflect bytes consumed. Be
       * defensive: both bases may be NULL (fully consumed) or one may be NULL.
       * Only do pointer arithmetic when both are non-NULL. */
      if (copy[i].iov_base != original[i].iov_base)
        {
          const char *copy_base = (const char *)copy[i].iov_base;
          const char *orig_base = (const char *)original[i].iov_base;

          /* If original is already NULL we assume it was already fully
           * consumed earlier; nothing to do. */
          if (orig_base == NULL)
            continue;

          /* If the copy base is NULL, the copy was advanced past the end of
           * this vector so the original is now fully consumed. */
          if (copy_base == NULL)
            {
              original[i].iov_len = 0;
              original[i].iov_base = NULL;
              continue;
            }

          /* Normal case: both bases non-NULL. Ensure subtraction yields a
           * non-negative size and clamp against original length. */
          if (copy_base >= orig_base)
            {
              size_t copied = (size_t)(copy_base - orig_base);
              if (copied >= original[i].iov_len)
                {
                  original[i].iov_len = 0;
                  original[i].iov_base = NULL;
                }
              else
                {
                  original[i].iov_len -= copied;
                  original[i].iov_base = (char *)orig_base + copied;
                }
            }
          /* else: Unexpected - copy base is before original base. Ignore to
           * avoid UB. */
        }
    }
}

struct iovec *
SocketCommon_alloc_iov_copy (const struct iovec *iov, int iovcnt,
                             Except_T exc_type)
{
  struct iovec *copy;

  assert (iov);
  assert (iovcnt > 0);
  assert (iovcnt <= IOV_MAX);

  copy = calloc ((size_t)iovcnt, sizeof (struct iovec));
  if (!copy)
    {
      SOCKET_RAISE_MSG (SocketCommon, exc_type, SOCKET_ENOMEM ": Cannot allocate iovec copy");
    }
  memcpy (copy, iov, (size_t)iovcnt * sizeof (struct iovec));
  return copy;
}

/* ==================== Address Utilities ==================== */

const char *
socketcommon_get_safe_host (const char *host)
{
  return host ? host : "any";
}

static char *
socketcommon_duplicate_address (Arena_T arena, const char *addr_str)
{
  size_t addr_len;
  char *copy = NULL;

  assert (arena);
  assert (addr_str);

  addr_len = strlen (addr_str) + 1;
  copy = ALLOC (arena, addr_len);
  if (!copy)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate address buffer");
      return NULL;
    }
  memcpy (copy, addr_str, addr_len);
  return copy;
}

static int
socketcommon_parse_port_string (const char *serv)
{
  char *endptr = NULL;
  long port_long = 0;

  assert (serv);

  errno = 0;
  port_long = strtol (serv, &endptr, 10);
  if (errno == 0 && endptr != serv && *endptr == '\0' && port_long >= 0
      && port_long <= SOCKET_MAX_PORT)
    return (int)port_long;
  return 0;
}

void
socketcommon_convert_port_to_string (int port, char *port_str, size_t bufsize)
{
  int result;

  result = snprintf (port_str, bufsize, "%d", port);
  assert (result > 0 && result < (int)bufsize);
  (void)result; /* Suppress warning when NDEBUG disables assert */
}

int
SocketCommon_cache_endpoint (Arena_T arena, const struct sockaddr *addr,
                             socklen_t addrlen, char **addr_out, int *port_out)
{
  char host[SOCKET_NI_MAXHOST];
  char serv[SOCKET_NI_MAXSERV];
  char *copy = NULL;
  int result;

  assert (arena);
  assert (addr);
  assert (addr_out);
  assert (port_out);

  /* Initialize buffers to ensure deterministic behavior even if getnameinfo
   * doesn't fully populate them (e.g., for Unix domain sockets). */
  memset (host, 0, sizeof (host));
  memset (serv, 0, sizeof (serv));

  result
      = getnameinfo (addr, addrlen, host, sizeof (host), serv, sizeof (serv),
                     SOCKET_NI_NUMERICHOST | SOCKET_NI_NUMERICSERV);
  if (result != 0)
    {
      SOCKET_ERROR_MSG ("Failed to format socket address: %s",
                        gai_strerror (result));
      return -1;
    }

  copy = socketcommon_duplicate_address (arena, host);
  if (!copy)
    return -1;

  *addr_out = copy;
  *port_out = socketcommon_parse_port_string (serv);
  return 0;
}

/* ==================== Multicast Operations ==================== */

/* Multicast operation type */
typedef enum
{
  MCAST_OP_JOIN,
  MCAST_OP_LEAVE
} MulticastOpType;

static void
common_resolve_multicast_group (const char *group, struct addrinfo **res,
                                Except_T exc_type)
{
  struct addrinfo hints;
  int result;

  memset (&hints, 0, sizeof (hints));
  hints.ai_family = SOCKET_AF_UNSPEC;
  hints.ai_socktype = SOCKET_DGRAM_TYPE;
  hints.ai_flags = SOCKET_AI_NUMERICHOST;

  result = getaddrinfo (group, NULL, &hints, res);
  if (result != 0)
    {
      SOCKET_RAISE_MSG (SocketCommon, exc_type, "Invalid multicast group address: %s (%s)", group, gai_strerror (result));
    }
}

static void
common_setup_ipv4_mreq (struct ip_mreq *mreq, struct in_addr group_addr,
                        const char *interface, Except_T exc_type)
{
  memset (mreq, 0, sizeof (*mreq));
  mreq->imr_multiaddr = group_addr;
  if (interface)
    {
      if (inet_pton (SOCKET_AF_INET, interface, &mreq->imr_interface) <= 0)
        {
          SOCKET_RAISE_MSG (SocketCommon, exc_type, "Invalid interface address: %s", interface);
        }
    }
  else
    {
      mreq->imr_interface.s_addr = INADDR_ANY;
    }
}

/**
 * common_ipv4_multicast - Join or leave IPv4 multicast group
 * @base: Socket base
 * @group_addr: Multicast group address
 * @interface: Interface address (NULL for any)
 * @op: MCAST_OP_JOIN or MCAST_OP_LEAVE
 * @exc_type: Exception to raise on error
 */
static void
common_ipv4_multicast (SocketBase_T base, struct in_addr group_addr,
                       const char *interface, MulticastOpType op,
                       Except_T exc_type)
{
  struct ip_mreq mreq;
  int opt = (op == MCAST_OP_JOIN) ? SOCKET_IP_ADD_MEMBERSHIP
                                  : SOCKET_IP_DROP_MEMBERSHIP;
  const char *op_name = (op == MCAST_OP_JOIN) ? "join" : "leave";

  common_setup_ipv4_mreq (&mreq, group_addr, interface, exc_type);

  if (setsockopt (SocketBase_fd (base), SOCKET_IPPROTO_IP, opt, &mreq,
                  sizeof (mreq))
      < 0)
    {
      SOCKET_RAISE_FMT (SocketCommon, exc_type, "Failed to %s IPv4 multicast group", op_name);
    }
}

/**
 * common_ipv6_multicast - Join or leave IPv6 multicast group
 * @base: Socket base
 * @group_addr: Multicast group address
 * @op: MCAST_OP_JOIN or MCAST_OP_LEAVE
 * @exc_type: Exception to raise on error
 */
static void
common_ipv6_multicast (SocketBase_T base, struct in6_addr group_addr,
                       MulticastOpType op, Except_T exc_type)
{
  struct ipv6_mreq mreq6;
  int opt = (op == MCAST_OP_JOIN) ? SOCKET_IPV6_ADD_MEMBERSHIP
                                  : SOCKET_IPV6_DROP_MEMBERSHIP;
  const char *op_name = (op == MCAST_OP_JOIN) ? "join" : "leave";

  memset (&mreq6, 0, sizeof (mreq6));
  mreq6.ipv6mr_multiaddr = group_addr;
  mreq6.ipv6mr_interface = SOCKET_MULTICAST_DEFAULT_INTERFACE;

  if (setsockopt (SocketBase_fd (base), SOCKET_IPPROTO_IPV6, opt, &mreq6,
                  sizeof (mreq6))
      < 0)
    {
      SOCKET_RAISE_FMT (SocketCommon, exc_type, "Failed to %s IPv6 multicast group", op_name);
    }
}

/**
 * common_multicast_operation - Unified multicast join/leave
 * @base: Socket base
 * @group: Multicast group address string
 * @interface: Interface for IPv4 (NULL for any)
 * @op: MCAST_OP_JOIN or MCAST_OP_LEAVE
 * @exc_type: Exception to raise on error
 *
 * Consolidates common code for SocketCommon_join_multicast and
 * SocketCommon_leave_multicast.
 */
static void
common_multicast_operation (SocketBase_T base, const char *group,
                            const char *interface, MulticastOpType op,
                            Except_T exc_type)
{
  struct addrinfo *res = NULL;

  assert (base);
  assert (group);

  common_resolve_multicast_group (group, &res, exc_type);

  TRY
  {
    volatile int family = SocketCommon_get_family (base, true, exc_type);

    if (family == SOCKET_AF_INET)
      {
        const struct sockaddr_in *sin
            = (const struct sockaddr_in *)res->ai_addr;
        common_ipv4_multicast (base, sin->sin_addr, interface, op, exc_type);
      }
    else if (family == SOCKET_AF_INET6)
      {
        const struct sockaddr_in6 *sin6
            = (const struct sockaddr_in6 *)res->ai_addr;
        common_ipv6_multicast (base, sin6->sin6_addr, op, exc_type);
      }
    else
      {
        SOCKET_RAISE_MSG (SocketCommon, exc_type, "Unsupported address family %d for multicast", family);
      }
  }
  FINALLY { freeaddrinfo (res); }
  END_TRY;
}

void
SocketCommon_join_multicast (SocketBase_T base, const char *group,
                             const char *interface, Except_T exc_type)
{
  if (!base || !group) {
    SOCKET_RAISE_MSG (SocketCommon, exc_type, "Invalid parameters for join_multicast");
  }

  size_t group_len = strlen(group);
  if (group_len == 0 || group_len > SOCKET_ERROR_MAX_HOSTNAME) {
    SOCKET_RAISE_MSG (SocketCommon, exc_type, "Invalid group length for join_multicast");
  }

  common_multicast_operation (base, group, interface, MCAST_OP_JOIN, exc_type);
}

void
SocketCommon_leave_multicast (SocketBase_T base, const char *group,
                              const char *interface, Except_T exc_type)
{
  if (!base || !group) {
    SOCKET_RAISE_MSG (SocketCommon, exc_type, "Invalid parameters for leave_multicast");
  }

  size_t group_len = strlen(group);
  if (group_len == 0 || group_len > SOCKET_ERROR_MAX_HOSTNAME) {
    SOCKET_RAISE_MSG (SocketCommon, exc_type, "Invalid group length for leave_multicast");
  }

  common_multicast_operation (base, group, interface, MCAST_OP_LEAVE, exc_type);
}

void
SocketCommon_set_ttl (SocketBase_T base, int family, int ttl,
                      Except_T exc_type)
{
  int level = 0, opt = 0;
  if (family == SOCKET_AF_INET)
    {
      level = IPPROTO_IP;
      opt = IP_TTL;
    }
  else if (family == SOCKET_AF_INET6)
    {
      level = IPPROTO_IPV6;
      opt = IPV6_UNICAST_HOPS;
    }
  else
    {
      SOCKET_ERROR_FMT ("Unsupported family %d for TTL", family);
      RAISE_MODULE_ERROR (exc_type);
    }

  SocketCommon_set_option_int (base, level, opt, ttl, exc_type);
}
