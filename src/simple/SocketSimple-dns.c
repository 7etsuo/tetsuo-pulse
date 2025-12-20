/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketSimple-dns.c
 * @brief DNS implementation for Simple API using SocketDNS module.
 */

#include "SocketSimple-internal.h"

#include "socket/SocketCommon.h"

#include <netdb.h>

/* ============================================================================
 * DNS Resolution
 * ============================================================================
 */

int
Socket_simple_dns_resolve_timeout (const char *hostname,
                                   SocketSimple_DNSResult *result,
                                   int timeout_ms)
{
  SocketDNS_T dns = SocketCommon_get_dns_resolver ();
  volatile struct addrinfo *res = NULL;
  struct addrinfo *p;
  struct addrinfo hints;
  int count = 0;

  Socket_simple_clear_error ();

  if (!hostname || !result)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  memset (result, 0, sizeof (*result));

  if (!dns)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_DNS, "DNS resolver not available");
      return -1;
    }

  SocketCommon_setup_hints (&hints, SOCK_STREAM, 0);

  TRY { res = SocketDNS_resolve_sync (dns, hostname, 0, &hints, timeout_ms); }
  EXCEPT (SocketDNS_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_DNS, "DNS resolution failed");
    return -1;
  }
  END_TRY;

  if (!res)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_TIMEOUT, "DNS resolution timed out");
      return -1;
    }

  /* Count addresses */
  for (p = (struct addrinfo *)res; p != NULL; p = p->ai_next)
    {
      count++;
    }

  if (count == 0)
    {
      freeaddrinfo ((struct addrinfo *)res);
      simple_set_error (SOCKET_SIMPLE_ERR_DNS, "No addresses found");
      return -1;
    }

  result->addresses = calloc ((size_t)count + 1, sizeof (char *));
  if (!result->addresses)
    {
      freeaddrinfo ((struct addrinfo *)res);
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Memory allocation failed");
      return -1;
    }

  int i = 0;
  for (p = (struct addrinfo *)res; p != NULL && i < count; p = p->ai_next)
    {
      char host[NI_MAXHOST];
      /* Use library's reverse lookup wrapper */
      if (SocketCommon_reverse_lookup (p->ai_addr, p->ai_addrlen, host,
                                       sizeof (host), NULL, 0, NI_NUMERICHOST,
                                       SocketCommon_Failed)
          == 0)
        {
          result->addresses[i] = strdup (host);
          if (result->addresses[i])
            {
              i++;
            }
        }
    }

  result->count = i;
  result->family = ((struct addrinfo *)res)->ai_family;
  freeaddrinfo ((struct addrinfo *)res);

  if (result->count == 0)
    {
      free (result->addresses);
      result->addresses = NULL;
      simple_set_error (SOCKET_SIMPLE_ERR_DNS, "Failed to resolve addresses");
      return -1;
    }

  return 0;
}

int
Socket_simple_dns_resolve (const char *hostname, SocketSimple_DNSResult *result)
{
  return Socket_simple_dns_resolve_timeout (hostname, result, 5000);
}

int
Socket_simple_dns_lookup (const char *hostname, char *buf, size_t len)
{
  SocketSimple_DNSResult result;

  if (Socket_simple_dns_resolve (hostname, &result) != 0)
    {
      return -1;
    }

  if (result.count > 0 && result.addresses[0])
    {
      snprintf (buf, len, "%s", result.addresses[0]);
    }

  Socket_simple_dns_result_free (&result);
  return 0;
}

int
Socket_simple_dns_lookup4 (const char *hostname, char *buf, size_t len)
{
  SocketDNS_T dns = SocketCommon_get_dns_resolver ();
  volatile struct addrinfo *res = NULL;
  struct addrinfo hints;

  Socket_simple_clear_error ();

  if (!hostname || !buf)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  if (!dns)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_DNS, "DNS resolver not available");
      return -1;
    }

  SocketCommon_setup_hints (&hints, SOCK_STREAM, 0);
  hints.ai_family = AF_INET; /* Override for IPv4 only */

  TRY { res = SocketDNS_resolve_sync (dns, hostname, 0, &hints, 5000); }
  EXCEPT (SocketDNS_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_DNS, "DNS resolution failed");
    return -1;
  }
  END_TRY;

  if (!res)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_DNS, "No IPv4 address found");
      return -1;
    }

  char host[NI_MAXHOST];
  if (SocketCommon_reverse_lookup (((struct addrinfo *)res)->ai_addr,
                                   ((struct addrinfo *)res)->ai_addrlen, host,
                                   sizeof (host), NULL, 0, NI_NUMERICHOST,
                                   SocketCommon_Failed)
      == 0)
    {
      snprintf (buf, len, "%s", host);
    }
  else
    {
      freeaddrinfo ((struct addrinfo *)res);
      simple_set_error (SOCKET_SIMPLE_ERR_DNS, "Failed to get address string");
      return -1;
    }

  freeaddrinfo ((struct addrinfo *)res);
  return 0;
}

int
Socket_simple_dns_lookup6 (const char *hostname, char *buf, size_t len)
{
  SocketDNS_T dns = SocketCommon_get_dns_resolver ();
  volatile struct addrinfo *res = NULL;
  struct addrinfo hints;

  Socket_simple_clear_error ();

  if (!hostname || !buf)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  if (!dns)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_DNS, "DNS resolver not available");
      return -1;
    }

  SocketCommon_setup_hints (&hints, SOCK_STREAM, 0);
  hints.ai_family = AF_INET6; /* Override for IPv6 only */

  TRY { res = SocketDNS_resolve_sync (dns, hostname, 0, &hints, 5000); }
  EXCEPT (SocketDNS_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_DNS, "DNS resolution failed");
    return -1;
  }
  END_TRY;

  if (!res)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_DNS, "No IPv6 address found");
      return -1;
    }

  char host[NI_MAXHOST];
  if (SocketCommon_reverse_lookup (((struct addrinfo *)res)->ai_addr,
                                   ((struct addrinfo *)res)->ai_addrlen, host,
                                   sizeof (host), NULL, 0, NI_NUMERICHOST,
                                   SocketCommon_Failed)
      == 0)
    {
      snprintf (buf, len, "%s", host);
    }
  else
    {
      freeaddrinfo ((struct addrinfo *)res);
      simple_set_error (SOCKET_SIMPLE_ERR_DNS, "Failed to get address string");
      return -1;
    }

  freeaddrinfo ((struct addrinfo *)res);
  return 0;
}

int
Socket_simple_dns_reverse (const char *ip, char *hostname, size_t len)
{
  struct addrinfo hints, *res;

  Socket_simple_clear_error ();

  if (!ip || !hostname)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  /* Validate IP address format using library utility */
  if (!SocketCommon_parse_ip (ip, NULL))
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid IP address");
      return -1;
    }

  /* Use library's resolve for IP parsing */
  SocketCommon_setup_hints (&hints, SOCK_STREAM, AI_NUMERICHOST);

  if (SocketCommon_resolve_address (ip, 0, &hints, &res, SocketCommon_Failed,
                                    AF_UNSPEC, 0)
      != 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_DNS, "Invalid IP address format");
      return -1;
    }

  /* Use library's reverse lookup (without NI_NUMERICHOST to get hostname) */
  if (SocketCommon_reverse_lookup (res->ai_addr, res->ai_addrlen, hostname, len,
                                   NULL, 0, 0, SocketCommon_Failed)
      != 0)
    {
      freeaddrinfo (res);
      simple_set_error (SOCKET_SIMPLE_ERR_DNS, "Reverse lookup failed");
      return -1;
    }

  freeaddrinfo (res);
  return 0;
}

void
Socket_simple_dns_result_free (SocketSimple_DNSResult *result)
{
  if (!result)
    return;

  if (result->addresses)
    {
      for (int i = 0; i < result->count; i++)
        {
          free (result->addresses[i]);
        }
      free (result->addresses);
    }
  memset (result, 0, sizeof (*result));
}
