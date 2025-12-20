/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * dns_lookup.c - DNS Resolution Example
 *
 * Demonstrates DNS resolution using the SocketDNS API.
 * Shows both synchronous and asynchronous DNS lookups.
 *
 * Build:
 *   cmake -DBUILD_EXAMPLES=ON ..
 *   make example_dns_lookup
 *
 * Usage:
 *   ./example_dns_lookup [hostname] [type]
 *   ./example_dns_lookup google.com A
 *   ./example_dns_lookup example.com sync
 *
 * Types:
 *   sync  - Synchronous resolution (default)
 *   async - Asynchronous resolution with timeout
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Except.h"
#include "dns/SocketDNS.h"

static const char *
rrtype_string (int rrtype)
{
  switch (rrtype)
    {
    case 1:
      return "A";
    case 28:
      return "AAAA";
    default:
      return "UNKNOWN";
    }
}

int
main (int argc, char **argv)
{
  /* Variables that might be clobbered by longjmp must be volatile */
  const char *volatile hostname = "google.com";
  const char *volatile lookup_type = "sync";
  SocketDNS_T dns = NULL;
  volatile int result = 0;

  /* Parse command line arguments */
  if (argc > 1)
    hostname = argv[1];
  if (argc > 2)
    lookup_type = argv[2];

  printf ("DNS Lookup Example\n");
  printf ("==================\n\n");
  printf ("Looking up: %s\n", hostname);
  printf ("Method: %s\n\n", lookup_type);

  TRY
  {
    /* Create DNS resolver */
    dns = SocketDNS_new ();

    if (strcmp (lookup_type, "async") == 0)
      {
        /* Asynchronous lookup */
        printf ("Starting asynchronous DNS resolution...\n");

        Request_T req;
        req = SocketDNS_resolve (dns, hostname, 80, NULL, NULL);

        if (req)
          {
            printf ("Request submitted, waiting for completion...\n");

            /* Wait for completion with 5 second timeout */
            int timeout_ms = 5000;
            while (timeout_ms > 0 && !SocketDNS_check (dns))
              {
                usleep (100000); /* 100ms */
                timeout_ms -= 100;
              }

            if (timeout_ms > 0)
              {
                /* Get result */
                struct addrinfo *res = SocketDNS_getresult (dns, req);

                if (res)
                  {
                    printf ("✅ DNS resolution successful!\n");
                    printf ("Addresses found:\n");

                    struct addrinfo *rp;
                    for (rp = res; rp != NULL; rp = rp->ai_next)
                      {
                        char addr_str[INET6_ADDRSTRLEN];
                        void *addr;

                        if (rp->ai_family == AF_INET)
                          {
                            struct sockaddr_in *ipv4
                                = (struct sockaddr_in *)rp->ai_addr;
                            addr = &(ipv4->sin_addr);
                          }
                        else if (rp->ai_family == AF_INET6)
                          {
                            struct sockaddr_in6 *ipv6
                                = (struct sockaddr_in6 *)rp->ai_addr;
                            addr = &(ipv6->sin6_addr);
                          }
                        else
                          {
                            continue;
                          }

                        inet_ntop (rp->ai_family, addr, addr_str,
                                   sizeof (addr_str));
                        printf (
                            "  %s %s\n",
                            rrtype_string (rp->ai_family == AF_INET ? 1 : 28),
                            addr_str);
                      }

                    freeaddrinfo (res);
                  }
                else
                  {
                    printf ("❌ DNS resolution failed\n");
                    result = 1;
                  }
              }
            else
              {
                printf ("❌ DNS resolution timed out\n");
                result = 1;
              }
          }
        else
          {
            printf ("❌ Failed to submit DNS request\n");
            result = 1;
          }
      }
    else
      {
        /* Synchronous lookup */
        printf ("Performing synchronous DNS resolution...\n");

        struct addrinfo hints
            = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM };
        struct addrinfo *res;

        if (SocketDNS_resolve_sync (dns, hostname, 80, &hints, 5000))
          {
            printf ("✅ DNS resolution successful!\n");
            printf ("Addresses found:\n");

            for (res
                 = SocketDNS_resolve_sync (dns, hostname, 80, &hints, 5000);
                 res != NULL; res = res->ai_next)
              {
                char addr_str[INET6_ADDRSTRLEN];
                void *addr;

                if (res->ai_family == AF_INET)
                  {
                    struct sockaddr_in *ipv4
                        = (struct sockaddr_in *)res->ai_addr;
                    addr = &(ipv4->sin_addr);
                  }
                else if (res->ai_family == AF_INET6)
                  {
                    struct sockaddr_in6 *ipv6
                        = (struct sockaddr_in6 *)res->ai_addr;
                    addr = &(ipv6->sin6_addr);
                  }
                else
                  {
                    continue;
                  }

                inet_ntop (res->ai_family, addr, addr_str, sizeof (addr_str));
                printf ("  %s %s\n",
                        rrtype_string (res->ai_family == AF_INET ? 1 : 28),
                        addr_str);
              }

            freeaddrinfo (res);
          }
        else
          {
            printf ("❌ DNS resolution failed\n");
            result = 1;
          }
      }
  }
  EXCEPT (SocketDNS_Failed)
  {
    fprintf (stderr, "DNS error\n");
    result = 1;
  }
  END_TRY;

  /* Cleanup */
  if (dns)
    SocketDNS_free (&dns);

  return result;
}
