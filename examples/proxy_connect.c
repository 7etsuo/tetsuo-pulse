/**
 * proxy_connect.c - Proxy Tunneling Example
 *
 * Demonstrates connecting to a target server through various proxy types:
 * - SOCKS5 (most common for general proxying)
 * - SOCKS4/4a (legacy)
 * - HTTP CONNECT (for HTTP proxies)
 *
 * Build:
 *   cmake -DBUILD_EXAMPLES=ON ..
 *   make example_proxy_connect
 *
 * Usage:
 *   ./example_proxy_connect <proxy_url> <target_host> <target_port>
 *
 * Examples:
 *   # SOCKS5 proxy without authentication
 *   ./example_proxy_connect socks5://localhost:1080 example.com 80
 *
 *   # SOCKS5 proxy with authentication
 *   ./example_proxy_connect socks5://user:pass@proxy.example.com:1080
 * example.com 443
 *
 *   # HTTP CONNECT proxy
 *   ./example_proxy_connect http://proxy.example.com:8080 example.com 443
 *
 *   # SOCKS5H (hostname resolution at proxy)
 *   ./example_proxy_connect socks5h://localhost:1080 internal.example.com 80
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Except.h"
#include "socket/Socket.h"
#include "socket/SocketProxy.h"

#if SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#include "tls/SocketTLSContext.h"
#endif

static const char *
proxy_type_name (SocketProxyType type)
{
  switch (type)
    {
    case SOCKET_PROXY_NONE:
      return "NONE";
    case SOCKET_PROXY_HTTP:
      return "HTTP CONNECT";
    case SOCKET_PROXY_HTTPS:
      return "HTTPS CONNECT";
    case SOCKET_PROXY_SOCKS4:
      return "SOCKS4";
    case SOCKET_PROXY_SOCKS4A:
      return "SOCKS4a";
    case SOCKET_PROXY_SOCKS5:
      return "SOCKS5";
    case SOCKET_PROXY_SOCKS5H:
      return "SOCKS5H";
    default:
      return "Unknown";
    }
}

static const char *
proxy_result_string (SocketProxy_Result result)
{
  switch (result)
    {
    case PROXY_OK:
      return "Success";
    case PROXY_IN_PROGRESS:
      return "In Progress";
    case PROXY_ERROR:
      return "Error";
    case PROXY_ERROR_CONNECT:
      return "Connection Failed";
    case PROXY_ERROR_AUTH_REQUIRED:
      return "Authentication Required";
    case PROXY_ERROR_AUTH_FAILED:
      return "Authentication Failed";
    case PROXY_ERROR_FORBIDDEN:
      return "Forbidden";
    case PROXY_ERROR_HOST_UNREACHABLE:
      return "Host Unreachable";
    case PROXY_ERROR_NETWORK_UNREACHABLE:
      return "Network Unreachable";
    case PROXY_ERROR_CONNECTION_REFUSED:
      return "Connection Refused";
    case PROXY_ERROR_TTL_EXPIRED:
      return "TTL Expired";
    case PROXY_ERROR_PROTOCOL:
      return "Protocol Error";
    case PROXY_ERROR_UNSUPPORTED:
      return "Unsupported";
    case PROXY_ERROR_TIMEOUT:
      return "Timeout";
    case PROXY_ERROR_CANCELLED:
      return "Cancelled";
    default:
      return "Unknown Error";
    }
}

static void
print_usage (const char *program)
{
  printf ("Usage: %s <proxy_url> <target_host> <target_port>\n", program);
  printf ("\n");
  printf ("Proxy URL formats:\n");
  printf ("  socks5://[user:pass@]host[:port]\n");
  printf ("  socks5h://[user:pass@]host[:port]  (hostname at proxy)\n");
  printf ("  socks4://host[:port]\n");
  printf ("  socks4a://host[:port]\n");
  printf ("  http://[user:pass@]host[:port]\n");
  printf ("  https://[user:pass@]host[:port]\n");
  printf ("\n");
  printf ("Examples:\n");
  printf ("  %s socks5://localhost:1080 example.com 80\n", program);
  printf ("  %s socks5://user:pass@proxy.com:1080 google.com 443\n", program);
  printf ("  %s http://proxy.corp.com:8080 api.example.com 443\n", program);
}

int
main (int argc, char **argv)
{
  const char *proxy_url;
  const char *target_host;
  int target_port;
  SocketProxy_Config proxy_config;
  Socket_T sock = NULL;
  volatile int result = 0;

  /* Parse arguments */
  if (argc < 4)
    {
      print_usage (argv[0]);
      return 1;
    }

  proxy_url = argv[1];
  target_host = argv[2];
  target_port = atoi (argv[3]);

  if (target_port <= 0 || target_port > 65535)
    {
      fprintf (stderr, "Invalid port: %s\n", argv[3]);
      return 1;
    }

  /* Handle SIGPIPE */
  signal (SIGPIPE, SIG_IGN);

  printf ("Proxy Connect Example\n");
  printf ("=====================\n\n");

  /* Parse proxy URL */
  SocketProxy_config_defaults (&proxy_config);
  if (SocketProxy_parse_url (proxy_url, &proxy_config, NULL) < 0)
    {
      fprintf (stderr, "Failed to parse proxy URL: %s\n", proxy_url);
      return 1;
    }

  /* Print connection info */
  printf ("Proxy Type: %s\n", proxy_type_name (proxy_config.type));
  printf ("Proxy Host: %s\n", proxy_config.host);
  printf ("Proxy Port: %d\n", proxy_config.port);
  if (proxy_config.username)
    {
      printf ("Username:   %s\n", proxy_config.username);
      printf ("Password:   %s\n", proxy_config.password ? "****" : "(none)");
    }
  printf ("\n");
  printf ("Target:     %s:%d\n", target_host, target_port);
  printf ("\n");

  TRY
  {
    printf ("Connecting through proxy...\n");

    /* Connect through proxy (blocking) */
    sock = SocketProxy_connect (&proxy_config, target_host, target_port);

    if (!sock)
      {
        fprintf (stderr, "Proxy connection returned NULL\n");
        result = 1;
      }
    else
      {
        printf ("SUCCESS: Tunnel established!\n\n");

        /* Demonstrate the connection is working */
        printf ("Connected to %s:%d through proxy\n", target_host,
                target_port);
        printf ("Socket fd: %d\n", Socket_fd (sock));
        printf ("Local address: %s:%d\n", Socket_getlocaladdr (sock),
                Socket_getlocalport (sock));

        /* If target is HTTPS (443), demonstrate TLS setup */
        if (target_port == 443)
          {
#if SOCKET_HAS_TLS
            printf ("\nTarget port is 443 - performing TLS handshake...\n");

            /* Create TLS context */
            SocketTLSContext_T tls_ctx = SocketTLSContext_new_client (NULL);

            /* Enable TLS on socket */
            SocketTLS_enable (sock, tls_ctx);
            SocketTLS_set_hostname (sock, target_host);

            /* Perform TLS handshake */
            while (SocketTLS_handshake (sock) > 0)
              {
                /* Handshake in progress */
              }

            printf ("TLS Version: %s\n", SocketTLS_get_version (sock));
            printf ("TLS Cipher:  %s\n", SocketTLS_get_cipher (sock));

            /* Send a simple HTTP request over TLS */
            char request[512];
            snprintf (request, sizeof (request),
                      "GET / HTTP/1.1\r\n"
                      "Host: %s\r\n"
                      "Connection: close\r\n\r\n",
                      target_host);

            printf ("\nSending HTTPS request...\n");
            SocketTLS_send (sock, request, strlen (request));

            /* Read response */
            char response[4096];
            ssize_t n = SocketTLS_recv (sock, response, sizeof (response) - 1);
            if (n > 0)
              {
                response[n] = '\0';
                /* Print first 500 chars of response */
                printf ("\nResponse (first 500 chars):\n");
                printf ("%.500s\n", response);
              }

            SocketTLS_shutdown (sock);
            SocketTLSContext_free (&tls_ctx);
#else
            printf ("\nTarget port is 443 but TLS support not compiled in.\n");
            printf ("Compile with -DENABLE_TLS=ON for HTTPS over proxy "
                    "support.\n");
#endif
          }
        else
          {
            /* For non-TLS, send a simple HTTP request */
            char request[512];
            snprintf (request, sizeof (request),
                      "GET / HTTP/1.1\r\n"
                      "Host: %s\r\n"
                      "Connection: close\r\n\r\n",
                      target_host);

            printf ("\nSending HTTP request...\n");
            Socket_sendall (sock, request, strlen (request));

            /* Read response */
            char response[4096];
            ssize_t n = Socket_recv (sock, response, sizeof (response) - 1);
            if (n > 0)
              {
                response[n] = '\0';
                /* Print first 500 chars of response */
                printf ("\nResponse (first 500 chars):\n");
                printf ("%.500s\n", response);
              }
          }
      }
  }
  EXCEPT (SocketProxy_Failed)
  {
    fprintf (stderr, "Proxy connection failed\n");
    result = 1;
  }
  EXCEPT (Socket_Failed)
  {
    fprintf (stderr, "Socket error\n");
    result = 1;
  }
#if SOCKET_HAS_TLS
  EXCEPT (SocketTLS_HandshakeFailed)
  {
    fprintf (stderr, "TLS handshake failed\n");
    result = 1;
  }
  EXCEPT (SocketTLS_VerifyFailed)
  {
    fprintf (stderr, "TLS certificate verification failed\n");
    result = 1;
  }
#endif
  FINALLY
  {
    if (sock)
      {
        Socket_free (&sock);
      }
  }
  END_TRY;

  return result;
}
