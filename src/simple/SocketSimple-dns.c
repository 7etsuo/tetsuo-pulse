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
#include "dns/SocketDNS.h"

#include <netdb.h>

/* ============================================================================
 * Constants
 * ============================================================================
 */

/**
 * @brief Maximum number of addresses allowed in DNS response.
 *
 * Protects against integer overflow in calloc() when processing malicious
 * DNS responses. Set to reasonable upper limit that exceeds typical use
 * cases while preventing memory exhaustion attacks.
 */
#define DNS_MAX_ADDRESSES 1024

/* ============================================================================
 * DNS Resolution - Helper Functions
 * ============================================================================
 */

/**
 * @brief Count the number of addresses in an addrinfo linked list.
 * @param res The addrinfo list to count.
 * @return Number of addresses in the list.
 */
static int
count_addrinfo (struct addrinfo *res)
{
  int count = 0;
  for (struct addrinfo *p = res; p != NULL; p = p->ai_next)
    count++;
  return count;
}

/**
 * @brief Perform synchronous DNS resolution with exception handling.
 * @param dns The DNS resolver instance.
 * @param hostname The hostname to resolve.
 * @param hints The addrinfo hints for resolution.
 * @param timeout_ms Timeout in milliseconds.
 * @param exception_occurred Output parameter set to 1 if exception occurs.
 * @return addrinfo result or NULL on error/timeout.
 */
static struct addrinfo *
resolve_hostname_sync (SocketDNS_T dns, const char *hostname,
                       struct addrinfo *hints, int timeout_ms,
                       int *exception_occurred)
{
  struct addrinfo *volatile res = NULL;

  TRY { res = SocketDNS_resolve_sync (dns, hostname, 0, hints, timeout_ms); }
  EXCEPT (SocketDNS_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_DNS, "DNS resolution failed");
    *exception_occurred = 1;
  }
  FINALLY
  {
    /* Cleanup res on exception - normal path handles it in caller */
    if (*exception_occurred && res)
      {
        SocketCommon_free_addrinfo (res);
        res = NULL;
      }
  }
  END_TRY;

  return res;
}

/**
 * @brief Convert addrinfo linked list to SocketSimple_DNSResult.
 * @param res The addrinfo list to convert.
 * @param result The output SocketSimple_DNSResult structure.
 * @return 0 on success, -1 on error.
 */
static int
convert_addrinfo_to_result (struct addrinfo *res, SocketSimple_DNSResult *result)
{
  int count = count_addrinfo (res);

  if (count == 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_DNS, "No addresses found");
      return -1;
    }

  if (count > DNS_MAX_ADDRESSES)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_DNS, "Too many addresses in DNS response");
      return -1;
    }

  result->addresses = calloc ((size_t)count + 1, sizeof (char *));
  if (!result->addresses)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Memory allocation failed");
      return -1;
    }

  int i = 0;
  for (struct addrinfo *p = res; p != NULL && i < count; p = p->ai_next)
    {
      char host[NI_MAXHOST];
      /* Use library's reverse lookup wrapper - returns 0 on success */
      if (SocketCommon_reverse_lookup (p->ai_addr, p->ai_addrlen, host,
                                       sizeof (host), NULL, 0, NI_NUMERICHOST,
                                       SocketCommon_Failed)
          == 0)
        {
          result->addresses[i] = strdup (host);
          if (result->addresses[i])
            i++;
        }
    }

  result->count = i;
  result->family = res->ai_family;

  if (result->count == 0)
    {
      free (result->addresses);
      result->addresses = NULL;
      simple_set_error (SOCKET_SIMPLE_ERR_DNS, "Failed to resolve addresses");
      return -1;
    }

  return 0;
}

/* ============================================================================
 * DNS Resolution - Public API
 * ============================================================================
 */

#define SOCKET_SIMPLE_DNS_DEFAULT_TIMEOUT_MS 5000

int
Socket_simple_dns_resolve_timeout (const char *hostname,
                                   SocketSimple_DNSResult *result,
                                   int timeout_ms)
{
  volatile int exception_occurred = 0;
  struct addrinfo hints;
  struct addrinfo *res = NULL;

  Socket_simple_clear_error ();

  if (!hostname || !result)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  memset (result, 0, sizeof (*result));

  SocketDNS_T dns = SocketCommon_get_dns_resolver ();
  if (!dns)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_DNS, "DNS resolver not available");
      return -1;
    }

  SocketCommon_setup_hints (&hints, SOCK_STREAM, 0);

  /* Resolve hostname with exception handling */
  res = resolve_hostname_sync (dns, hostname, &hints, timeout_ms,
                               (int *)&exception_occurred);
  if (exception_occurred)
    return -1;

  if (!res)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_TIMEOUT, "DNS resolution timed out");
      return -1;
    }

  /* Convert addrinfo to result structure */
  int ret = convert_addrinfo_to_result (res, result);
  SocketCommon_free_addrinfo (res);

  return ret;
}

int
Socket_simple_dns_resolve (const char *hostname, SocketSimple_DNSResult *result)
{
  return Socket_simple_dns_resolve_timeout (hostname, result, SOCKET_SIMPLE_DNS_DEFAULT_TIMEOUT_MS);
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
  volatile int exception_occurred = 0;
  int ret = -1;

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

  TRY { res = SocketDNS_resolve_sync (dns, hostname, 0, &hints, SOCKET_SIMPLE_DNS_DEFAULT_TIMEOUT_MS); }
  EXCEPT (SocketDNS_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_DNS, "DNS resolution failed");
    exception_occurred = 1;
  }
  FINALLY
  {
    if (exception_occurred && res)
      {
        SocketCommon_free_addrinfo ((struct addrinfo *)res);
        res = NULL;
      }
  }
  END_TRY;

  if (exception_occurred)
    return -1;

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
      ret = 0;
    }
  else
    {
      simple_set_error (SOCKET_SIMPLE_ERR_DNS, "Failed to get address string");
    }

  SocketCommon_free_addrinfo ((struct addrinfo *)res);
  return ret;
}

int
Socket_simple_dns_lookup6 (const char *hostname, char *buf, size_t len)
{
  SocketDNS_T dns = SocketCommon_get_dns_resolver ();
  volatile struct addrinfo *res = NULL;
  struct addrinfo hints;
  volatile int exception_occurred = 0;
  int ret = -1;

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

  TRY { res = SocketDNS_resolve_sync (dns, hostname, 0, &hints, SOCKET_SIMPLE_DNS_DEFAULT_TIMEOUT_MS); }
  EXCEPT (SocketDNS_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_DNS, "DNS resolution failed");
    exception_occurred = 1;
  }
  FINALLY
  {
    if (exception_occurred && res)
      {
        SocketCommon_free_addrinfo ((struct addrinfo *)res);
        res = NULL;
      }
  }
  END_TRY;

  if (exception_occurred)
    return -1;

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
      ret = 0;
    }
  else
    {
      simple_set_error (SOCKET_SIMPLE_ERR_DNS, "Failed to get address string");
    }

  SocketCommon_free_addrinfo ((struct addrinfo *)res);
  return ret;
}

int
Socket_simple_dns_reverse (const char *ip, char *hostname, size_t len)
{
  struct addrinfo hints;
  struct addrinfo *res = NULL;
  int ret = -1;

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
      == 0)
    {
      ret = 0;
    }
  else
    {
      simple_set_error (SOCKET_SIMPLE_ERR_DNS, "Reverse lookup failed");
    }

  SocketCommon_free_addrinfo (res);
  return ret;
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

/* ============================================================================
 * Async DNS Internal Structures
 * ============================================================================
 */

struct SocketSimple_DNS
{
  SocketDNS_T dns;
};

struct SocketSimple_DNSRequest
{
  SocketDNS_Request_T *core_req;
  SocketDNS_T dns;
  int complete;
  int error;
  struct addrinfo *result;
};

/* Callback wrapper for async mode */
struct simple_dns_callback_ctx
{
  SocketSimple_DNSCallback callback;
  void *userdata;
  SocketDNS_T dns;
};

static void
simple_dns_callback_wrapper (SocketDNS_Request_T *req, struct addrinfo *result,
                             int error, void *data)
{
  struct simple_dns_callback_ctx *ctx = data;
  SocketSimple_DNSResult simple_result;

  (void)req;

  memset (&simple_result, 0, sizeof (simple_result));

  if (error == 0 && result)
    {
      /* Convert addrinfo to simple result */
      struct addrinfo *p;
      int count = 0;

      for (p = result; p != NULL; p = p->ai_next)
        count++;

      if (count > 0 && count <= DNS_MAX_ADDRESSES)
        {
          simple_result.addresses = calloc ((size_t)count + 1, sizeof (char *));
          if (simple_result.addresses)
            {
              int i = 0;
              for (p = result; p != NULL && i < count; p = p->ai_next)
                {
                  char host[NI_MAXHOST];
                  if (SocketCommon_reverse_lookup (p->ai_addr, p->ai_addrlen,
                                                   host, sizeof (host), NULL, 0,
                                                   NI_NUMERICHOST,
                                                   SocketCommon_Failed)
                      == 0)
                    {
                      simple_result.addresses[i] = strdup (host);
                      if (simple_result.addresses[i])
                        i++;
                    }
                }
              simple_result.count = i;
              simple_result.family = result->ai_family;
            }
        }
    }

  /* Call user callback */
  if (ctx->callback)
    {
      ctx->callback (error == 0 ? &simple_result : NULL, error, ctx->userdata);
    }

  /* Cleanup */
  Socket_simple_dns_result_free (&simple_result);
  if (result)
    SocketCommon_free_addrinfo (result);
  free (ctx);
}

/* ============================================================================
 * Async DNS Resolver Lifecycle
 * ============================================================================
 */

SocketSimple_DNS_T
Socket_simple_dns_new (void)
{
  volatile SocketDNS_T dns = NULL;
  struct SocketSimple_DNS *handle = NULL;

  Socket_simple_clear_error ();

  TRY { dns = SocketDNS_new (); }
  EXCEPT (SocketDNS_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_DNS, "Failed to create DNS resolver");
    return NULL;
  }
  END_TRY;

  if (!dns)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_DNS, "Failed to create DNS resolver");
      return NULL;
    }

  handle = calloc (1, sizeof (*handle));
  if (!handle)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Memory allocation failed");
      SocketDNS_free ((SocketDNS_T *)&dns);
      return NULL;
    }

  handle->dns = dns;
  return handle;
}

void
Socket_simple_dns_free (SocketSimple_DNS_T *dns)
{
  if (!dns || !*dns)
    return;

  struct SocketSimple_DNS *handle = *dns;

  if (handle->dns)
    {
      SocketDNS_free (&handle->dns);
    }

  free (handle);
  *dns = NULL;
}

/* ============================================================================
 * Async DNS Configuration
 * ============================================================================
 */

void
Socket_simple_dns_set_timeout (SocketSimple_DNS_T dns, int timeout_ms)
{
  if (!dns || !dns->dns)
    return;
  SocketDNS_settimeout (dns->dns, timeout_ms);
}

int
Socket_simple_dns_get_timeout (SocketSimple_DNS_T dns)
{
  if (!dns || !dns->dns)
    return 0;
  return SocketDNS_gettimeout (dns->dns);
}

void
Socket_simple_dns_set_max_pending (SocketSimple_DNS_T dns, size_t max_pending)
{
  if (!dns || !dns->dns)
    return;

  TRY { SocketDNS_setmaxpending (dns->dns, max_pending); }
  EXCEPT (SocketDNS_Failed) { /* Ignore errors */
  }
  END_TRY;
}

void
Socket_simple_dns_prefer_ipv6 (SocketSimple_DNS_T dns, int prefer_ipv6)
{
  if (!dns || !dns->dns)
    return;
  SocketDNS_prefer_ipv6 (dns->dns, prefer_ipv6);
}

/* ============================================================================
 * Async DNS Resolution (Callback Mode)
 * ============================================================================
 */

int
Socket_simple_dns_resolve_async (SocketSimple_DNS_T dns, const char *hostname,
                                 SocketSimple_DNSCallback callback,
                                 void *userdata)
{
  struct simple_dns_callback_ctx *ctx;

  Socket_simple_clear_error ();

  if (!dns || !dns->dns || !hostname || !callback)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  ctx = malloc (sizeof (*ctx));
  if (!ctx)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Memory allocation failed");
      return -1;
    }

  ctx->callback = callback;
  ctx->userdata = userdata;
  ctx->dns = dns->dns;

  TRY
  {
    SocketDNS_resolve (dns->dns, hostname, 0, simple_dns_callback_wrapper, ctx);
  }
  EXCEPT (SocketDNS_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_DNS, "Failed to start DNS resolution");
    free (ctx);
    return -1;
  }
  END_TRY;

  return 0;
}

/* ============================================================================
 * Async DNS Resolution (Polling Mode)
 * ============================================================================
 */

SocketSimple_DNSRequest_T
Socket_simple_dns_resolve_start (SocketSimple_DNS_T dns, const char *hostname)
{
  SocketDNS_Request_T *volatile req = NULL;
  struct SocketSimple_DNSRequest *volatile handle = NULL;
  volatile int exception_occurred = 0;

  Socket_simple_clear_error ();

  if (!dns || !dns->dns || !hostname)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return NULL;
    }

  handle = calloc (1, sizeof (*handle));
  if (!handle)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Memory allocation failed");
      return NULL;
    }

  TRY { req = SocketDNS_resolve (dns->dns, hostname, 0, NULL, NULL); }
  EXCEPT (SocketDNS_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_DNS, "Failed to start DNS resolution");
    exception_occurred = 1;
  }
  END_TRY;

  if (exception_occurred)
    {
      free ((void *)handle);
      return NULL;
    }

  if (!req)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_DNS, "Failed to start DNS resolution");
      free ((void *)handle);
      return NULL;
    }

  handle->core_req = (SocketDNS_Request_T *)req;
  handle->dns = dns->dns;
  handle->complete = 0;
  handle->error = 0;
  handle->result = NULL;

  return (SocketSimple_DNSRequest_T)handle;
}

int
Socket_simple_dns_pollfd (SocketSimple_DNS_T dns)
{
  if (!dns || !dns->dns)
    return -1;
  return SocketDNS_pollfd (dns->dns);
}

int
Socket_simple_dns_check (SocketSimple_DNS_T dns)
{
  if (!dns || !dns->dns)
    return 0;
  return SocketDNS_check (dns->dns);
}

int
Socket_simple_dns_request_done (SocketSimple_DNSRequest_T req)
{
  if (!req || !req->core_req || !req->dns)
    return 1; /* Consider invalid as done */

  /* Check if result is available */
  struct addrinfo *result = SocketDNS_getresult (req->dns, req->core_req);
  if (result)
    {
      req->result = result;
      req->error = SocketDNS_geterror (req->dns, req->core_req);
      req->complete = 1;
      return 1;
    }

  /* Check for error without result */
  int err = SocketDNS_geterror (req->dns, req->core_req);
  if (err != 0)
    {
      req->error = err;
      req->complete = 1;
      return 1;
    }

  return 0;
}

int
Socket_simple_dns_request_result (SocketSimple_DNSRequest_T req,
                                  SocketSimple_DNSResult *result)
{
  Socket_simple_clear_error ();

  if (!req || !result)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  memset (result, 0, sizeof (*result));

  if (!req->complete)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_DNS, "Request not complete");
      return -1;
    }

  if (req->error != 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_DNS, "DNS resolution failed");
      return -1;
    }

  if (!req->result)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_DNS, "No result available");
      return -1;
    }

  /* Convert addrinfo to simple result */
  struct addrinfo *p;
  int count = 0;

  for (p = req->result; p != NULL; p = p->ai_next)
    count++;

  if (count == 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_DNS, "No addresses found");
      return -1;
    }

  if (count > DNS_MAX_ADDRESSES)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_DNS, "Too many addresses in DNS response");
      return -1;
    }

  result->addresses = calloc ((size_t)count + 1, sizeof (char *));
  if (!result->addresses)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Memory allocation failed");
      return -1;
    }

  int i = 0;
  for (p = req->result; p != NULL && i < count; p = p->ai_next)
    {
      char host[NI_MAXHOST];
      if (SocketCommon_reverse_lookup (p->ai_addr, p->ai_addrlen, host,
                                       sizeof (host), NULL, 0, NI_NUMERICHOST,
                                       SocketCommon_Failed)
          == 0)
        {
          result->addresses[i] = strdup (host);
          if (result->addresses[i])
            i++;
        }
    }

  result->count = i;
  result->family = req->result->ai_family;

  if (result->count == 0)
    {
      free (result->addresses);
      result->addresses = NULL;
      simple_set_error (SOCKET_SIMPLE_ERR_DNS, "Failed to convert addresses");
      return -1;
    }

  return 0;
}

int
Socket_simple_dns_request_error (SocketSimple_DNSRequest_T req)
{
  if (!req)
    return -1;
  return req->error;
}

void
Socket_simple_dns_request_cancel (SocketSimple_DNS_T dns,
                                  SocketSimple_DNSRequest_T req)
{
  if (!dns || !dns->dns || !req || !req->core_req)
    return;

  SocketDNS_cancel (dns->dns, req->core_req);
  req->complete = 1;
  req->error = -1;
}

void
Socket_simple_dns_request_free (SocketSimple_DNSRequest_T *req)
{
  if (!req || !*req)
    return;

  struct SocketSimple_DNSRequest *handle = *req;

  if (handle->result)
    SocketCommon_free_addrinfo (handle->result);

  free (handle);
  *req = NULL;
}

/* ============================================================================
 * DNS Cache Control
 * ============================================================================
 */

void
Socket_simple_dns_cache_clear (SocketSimple_DNS_T dns)
{
  if (!dns || !dns->dns)
    return;
  SocketDNS_cache_clear (dns->dns);
}

void
Socket_simple_dns_cache_set_ttl (SocketSimple_DNS_T dns, int ttl_seconds)
{
  if (!dns || !dns->dns)
    return;
  SocketDNS_cache_set_ttl (dns->dns, ttl_seconds);
}
