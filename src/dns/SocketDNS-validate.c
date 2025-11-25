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
 * validate_hostname_label - Validate a single hostname label
 * @label: Label string to validate
 * @len: Length of label (output)
 * Returns: 1 if valid label, 0 otherwise
 * Validates label characters, length, and format according to DNS rules.
 */
int
validate_hostname_label (const char *label, size_t *len)
{
  const char *p = label;
  int label_len = 0;
  bool new_label = true; /* Start of label */

  while (*p)
    {
      if (*p == '.')
        {
          if (new_label || label_len == 0
              || label_len > SOCKET_DNS_MAX_LABEL_LENGTH)
            return 0; /* Empty label or too long */
          new_label = true;
          label_len = 0;
        }
      else
        {
          if (new_label)
            {
              if (!isalnum ((unsigned char)*p))
                return 0; /* Label must start with alnum */
              new_label = false;
            }
          if (!isalnum ((unsigned char)*p) && *p != '-')
            return 0; /* Invalid char in label */
          if (*p == '-' && label_len == 0)
            return 0; /* Can't start label with - */
          label_len++;
          if (label_len > SOCKET_DNS_MAX_LABEL_LENGTH)
            return 0;
        }
      p++;
    }

  /* Final label check */
  if (new_label || label_len == 0 || label_len > SOCKET_DNS_MAX_LABEL_LENGTH)
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

