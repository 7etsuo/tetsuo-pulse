/**
 * SocketCommon-resolve.c - DNS and address resolution utilities
 *
 * Contains DNS resolution, address validation, and caching functions
 * extracted from the main SocketCommon.c file.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "core/Arena.h"
#include "core/SocketConfig.h"
#define SOCKET_LOG_COMPONENT "SocketCommon"
#include "core/SocketError.h"
#include "socket/SocketCommon-private.h"
#include "socket/SocketCommon.h"

/* Forward declarations for exception types */
extern const Except_T Socket_Failed;
extern const Except_T SocketDgram_Failed;

/* Thread-local exception for detailed error messages */
#ifdef _WIN32
static __declspec (thread) Except_T SocketCommon_DetailedException;
#else
static __thread Except_T SocketCommon_DetailedException;
#endif

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e)                                                 \
  do                                                                          \
    {                                                                         \
      SocketCommon_DetailedException = (e);                                   \
      SocketCommon_DetailedException.reason = socket_error_buf;               \
      RAISE (SocketCommon_DetailedException);                                 \
    }                                                                         \
  while (0)

/**
 * socketcommon_get_safe_host
 * @host: Host string (may be NULL)
 * Thread-safe: Yes
 */
static const char *
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

/**
 * socketcommon_validate_hostname_internal - Validate hostname length and
 * characters
 * @host: Hostname to validate
 * @use_exceptions: If true, raise exception; if false, return error code
 * @exception_type: Exception type to raise on failure
 * Returns: 0 on success, -1 on failure
 * Raises: Specified exception type if hostname invalid (if using exceptions)
 * Thread-safe: Yes
 */
static int
socketcommon_validate_hostname_internal (const char *host, int use_exceptions,
                                         Except_T exception_type)
{
  size_t host_len = host ? strlen (host) : 0;
  size_t i;

  if (host_len > SOCKET_ERROR_MAX_HOSTNAME)
    {
      SOCKET_ERROR_MSG ("Host name too long (max %d characters)",
                        SOCKET_ERROR_MAX_HOSTNAME);
      if (use_exceptions)
        RAISE_MODULE_ERROR (exception_type);
      return -1;
    }

  for (i = 0; i < host_len; i++)
    {
      char c = host[i];
      if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
            || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == ':'
            || c == '%'))
        {
          SOCKET_ERROR_MSG ("Invalid character in hostname: '%c'", c);
          if (use_exceptions)
            RAISE_MODULE_ERROR (exception_type);
          return -1;
        }
    }

  return 0;
}

/**
 * socketcommon_convert_port_to_string - Convert port number to string
 * @port: Port number
 * @port_str: Output buffer for port string
 * @bufsize: Size of output buffer
 * Thread-safe: Yes
 */
static void
socketcommon_convert_port_to_string (int port, char *port_str, size_t bufsize)
{
  int result;

  result = snprintf (port_str, bufsize, "%d", port);
  assert (result > 0 && result < (int)bufsize);
}

/**
 * socketcommon_perform_getaddrinfo - Perform address resolution
 * @host: Hostname or IP address
 * @port_str: Port number as string
 * @hints: Addrinfo hints structure
 * @res: Output pointer to resolved addrinfo
 * @use_exceptions: If true, raise exception; if false, return error code
 * @exception_type: Exception type to raise on failure
 * Returns: 0 on success, -1 on failure
 * Raises: Specified exception type on failure (if using exceptions)
 * Thread-safe: Yes
 */
static int
socketcommon_perform_getaddrinfo (const char *host, const char *port_str,
                                  const struct addrinfo *hints,
                                  struct addrinfo **res, int use_exceptions,
                                  Except_T exception_type)
{
  int result;
  const char *safe_host;

  result = getaddrinfo (host, port_str, hints, res);
  if (result != 0)
    {
      safe_host = socketcommon_get_safe_host (host);
      SOCKET_ERROR_MSG ("Invalid host/IP address: %.*s (%s)",
                        SOCKET_ERROR_MAX_HOSTNAME, safe_host,
                        gai_strerror (result));
      if (use_exceptions)
        RAISE_MODULE_ERROR (exception_type);
      return -1;
    }
  return 0;
}

/**
 * socketcommon_find_matching_family - Find address matching socket family
 * @res: Resolved address list
 * @socket_family: Socket family to match
 * Returns: 1 if matching family found, 0 otherwise
 * Thread-safe: Yes
 */
static int
socketcommon_find_matching_family (struct addrinfo *res, int socket_family)
{
  struct addrinfo *rp;

  for (rp = res; rp != NULL; rp = rp->ai_next)
    {
      if (rp->ai_family == socket_family)
        return 1;
    }
  return 0;
}

/**
 * socketcommon_validate_address_family - Validate resolved address family
 * @res: Resolved address list
 * @socket_family: Socket family to match
 * @host: Hostname for error messages
 * @port: Port number for error messages
 * @use_exceptions: If true, raise exception; if false, return error code
 * @exception_type: Exception type to raise on failure
 * Returns: 0 on success, -1 on failure
 * Raises: Specified exception type if no matching family (if using exceptions)
 * Thread-safe: Yes
 */
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

  /* Caller will free res on error */

  safe_host = socketcommon_get_safe_host (host);
  SOCKET_ERROR_MSG ("No address found for family %d: %.*s:%d", socket_family,
                    SOCKET_ERROR_MAX_HOSTNAME, safe_host, port);
  if (use_exceptions)
    RAISE_MODULE_ERROR (exception_type);
  return -1;
}

/**
 * SocketCommon_setup_hints - Initialize addrinfo hints structure
 * @hints: Hints structure to initialize
 * @socktype: Socket type (SOCK_STREAM or SOCK_DGRAM)
 * @flags: Additional flags (0 for connect/sendto, AI_PASSIVE for bind)
 * Thread-safe: Yes
 */
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
 * SocketCommon_resolve_address - Resolve hostname/port to addrinfo structure
 * @host: Hostname or IP address (NULL for wildcard)
 * @port: Port number (1 to SOCKET_MAX_PORT)
 * @hints: Addrinfo hints structure
 * @res: Output pointer to resolved addrinfo
 * @exception_type: Exception type to raise on failure
 * @socket_family: Socket family to match (AF_UNSPEC if none)
 * @use_exceptions: If true, raise exceptions; if false, return error codes
 * Returns: 0 on success, -1 on failure (if not using exceptions)
 * Raises: Specified exception type on failure (if using exceptions)
 * Thread-safe: Yes
 */
int
SocketCommon_resolve_address (const char *host, int port,
                              const struct addrinfo *hints,
                              struct addrinfo **res, Except_T exception_type,
                              int socket_family, int use_exceptions)
{
  char port_str[SOCKET_PORT_STR_BUFSIZE];

  if (socketcommon_validate_hostname_internal (host, use_exceptions,
                                               exception_type)
      != 0)
    return -1;

  socketcommon_convert_port_to_string (port, port_str, sizeof (port_str));

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
 * SocketCommon_validate_hostname - Validate hostname length
 * @host: Hostname to validate
 * @exception_type: Exception type to raise on invalid hostname
 * Raises: Specified exception type if hostname is too long
 * Thread-safe: Yes
 */
void
SocketCommon_validate_hostname (const char *host, Except_T exception_type)
{
  if (socketcommon_validate_hostname_internal (host, 1, exception_type) != 0)
    return; /* Exception already raised */
}

/**
 * SocketCommon_cache_endpoint - Cache endpoint address and port from sockaddr
 * @arena: Arena for string allocation
 * @addr: Socket address to cache
 * @addrlen: Length of address
 * @addr_out: Output pointer for address string
 * @port_out: Output pointer for port number
 * Returns: 0 on success, -1 on failure
 * Thread-safe: Yes (arena operations are thread-safe)
 */
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

/**
 * SocketCommon_copy_addrinfo - Deep copy addrinfo chain to heap memory
 *
 * @src: Source addrinfo chain from getaddrinfo() or similar
 *
 * Creates a deep copy of the entire linked list, allocating each node,
 * ai_addr, and ai_canonname using malloc(). The structure is fully independent
 * of src.
 *
 * Returns: Head of new chain, or NULL if src is NULL or any malloc() fails
 *
 * Caller MUST call freeaddrinfo() on returned value when done.
 *
 * Thread-safe: Yes
 *
 * Raises: None - returns NULL on error (errno set to ENOMEM typically)
 */
struct addrinfo *
SocketCommon_copy_addrinfo (const struct addrinfo *src)
{
  struct addrinfo *head = NULL;
  struct addrinfo *tail = NULL;
  struct addrinfo *new_node = NULL;
  const struct addrinfo *p;

  if (!src)
    return NULL;

  p = src;
  while (p)
    {
      new_node = malloc (sizeof (struct addrinfo));
      if (!new_node)
        {
          /* Allocation failed - free partial chain */
          if (head)
            freeaddrinfo (head);
          return NULL;
        }
      memcpy (new_node, p, sizeof (struct addrinfo));
      new_node->ai_next = NULL;

      if (p->ai_addr && p->ai_addrlen > 0)
        {
          new_node->ai_addr = malloc (p->ai_addrlen);
          if (!new_node->ai_addr)
            {
              free (new_node);
              if (head)
                freeaddrinfo (head);
              return NULL;
            }
          memcpy (new_node->ai_addr, p->ai_addr, p->ai_addrlen);
        }
      else
        {
          new_node->ai_addr = NULL;
          new_node->ai_addrlen = 0;
        }

      if (p->ai_canonname)
        {
          size_t len = strlen (p->ai_canonname) + 1;
          new_node->ai_canonname = malloc (len);
          if (!new_node->ai_canonname)
            {
              if (new_node->ai_addr)
                free (new_node->ai_addr);
              free (new_node);
              if (head)
                freeaddrinfo (head);
              return NULL;
            }
          memcpy (new_node->ai_canonname, p->ai_canonname, len);
        }
      else
        {
          new_node->ai_canonname = NULL;
        }

      new_node->ai_addrlen = p->ai_addrlen;

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

/**
 * SocketCommon_reverse_lookup - Perform reverse DNS lookup (getnameinfo
 * wrapper)
 * @addr: Socket address to look up
 * @addrlen: Length of socket address
 * @host: Output buffer for hostname (NULL to skip)
 * @hostlen: Size of host buffer
 * @serv: Output buffer for service/port (NULL to skip)
 * @servlen: Size of service buffer
 * @flags: getnameinfo flags (NI_NUMERICHOST, NI_NAMEREQD, etc.)
 * @exception_type: Exception type to raise on failure
 * Returns: 0 on success, -1 on failure
 * Raises: Specified exception type on failure
 * Thread-safe: Yes
 * Note: Wrapper around getnameinfo() for reverse DNS lookups.
 * Use NI_NUMERICHOST flag to get numeric IP address instead of hostname.
 */
int
SocketCommon_reverse_lookup (const struct sockaddr *addr, socklen_t addrlen,
                             char *host, socklen_t hostlen, char *serv,
                             socklen_t servlen, int flags,
                             Except_T exception_type)
{
  int result;

  assert (addr);

  result = getnameinfo (addr, addrlen, host, hostlen, serv, servlen, flags);
  if (result != 0)
    {
      SOCKET_ERROR_MSG ("Reverse lookup failed: %s", gai_strerror (result));
      RAISE_MODULE_ERROR (exception_type);
      return -1;
    }

  return 0;
}
