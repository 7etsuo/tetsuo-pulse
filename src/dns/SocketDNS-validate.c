/**
 * SocketDNS-validate.c - Hostname validation for async DNS resolution
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Contains hostname and parameter validation functions.
 */

#include "core/SocketConfig.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <stdbool.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketError.h"
#include "dns/SocketDNS.h"
#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketDNS-validate"
#define T SocketDNS_T
#define Request_T SocketDNS_Request_T
#include "dns/SocketDNS-private.h"

/**
 * is_ip_address - Check if string is a valid IP address (IPv4 or IPv6)
 * @host: Host string to check
 * Returns: 1 if valid IP address, 0 otherwise
 */
bool
is_ip_address (const char *host)
{
  if (!host)
    return false;

  struct in_addr ipv4;
  struct in6_addr ipv6;

  return inet_pton (AF_INET, host, &ipv4) == 1
         || inet_pton (AF_INET6, host, &ipv6) == 1;
}

/**
 * is_valid_label_char - Check if character is valid in hostname label
 * @c: Character to check
 * Returns: true if valid (alphanumeric or hyphen)
 */
static bool
is_valid_label_char (char c)
{
  return isalnum ((unsigned char)c) || c == '-';
}

/**
 * is_valid_label_start - Check if character can start a label
 * @c: Character to check
 * Returns: true if valid label start (alphanumeric only)
 */
static bool
is_valid_label_start (char c)
{
  return isalnum ((unsigned char)c);
}

/**
 * check_label_bounds - Check label length is within bounds
 * @label_len: Current label length
 * Returns: true if within bounds
 */
static bool
check_label_bounds (int label_len)
{
  return label_len > 0 && label_len <= SOCKET_DNS_MAX_LABEL_LENGTH;
}

/**
 * validate_hostname_label - Validate hostname labels per RFC 1123
 * @label: Hostname string containing one or more dot-separated labels
 * @len: Output parameter for total validated length (can be NULL)
 *
 * Returns: 1 if all labels valid, 0 otherwise
 *
 * Thread-safe: Yes - no shared state modified
 */
int
validate_hostname_label (const char *label, size_t *len)
{
  const char *p = label;
  int label_len = 0;
  bool at_label_start = true;

  while (*p)
    {
      if (*p == '.')
        {
          if (!check_label_bounds (label_len))
            return 0;
          at_label_start = true;
          label_len = 0;
        }
      else
        {
          if (at_label_start && !is_valid_label_start (*p))
            return 0;
          if (!is_valid_label_char (*p))
            return 0;

          at_label_start = false;
          label_len++;
        }
      p++;
    }

  if (!check_label_bounds (label_len))
    return 0;

  if (len)
    *len = p - label;
  return 1;
}

/**
 * validate_hostname - Validate hostname format and constraints
 * @hostname: Hostname string to validate
 * Returns: 1 if valid hostname, 0 otherwise
 * Validates hostname length and calls validate_hostname_label for each label.
 */
int
validate_hostname (const char *hostname)
{
  if (!hostname)
    return 0;

  size_t len = strlen (hostname);
  if (len == 0 || len > SOCKET_ERROR_MAX_HOSTNAME)
    return 0;

  return validate_hostname_label (hostname, NULL);
}

/**
 * validate_resolve_params - Validate parameters for DNS resolution
 * @host: Hostname to validate (NULL allowed for wildcard bind)
 * @port: Port number to validate
 * Raises: SocketDNS_Failed on invalid parameters
 */
void
validate_resolve_params (const char *host, int port)
{
  size_t host_len;

  if (host != NULL)
    {
      host_len = strlen (host);
      if (host_len == 0 || host_len > SOCKET_ERROR_MAX_HOSTNAME)
        {
          SOCKET_ERROR_MSG ("Invalid hostname length");
          RAISE_DNS_ERROR (SocketDNS_Failed);
        }

      if (!is_ip_address (host) && !validate_hostname (host))
        {
          SOCKET_ERROR_MSG ("Invalid hostname format");
          RAISE_DNS_ERROR (SocketDNS_Failed);
        }
    }

  if (!SOCKET_VALID_PORT (port))
    {
      SOCKET_ERROR_MSG ("Invalid port number");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }
}

#undef T
#undef Request_T

