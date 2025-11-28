/**
 * fuzz_connect.c - Fuzzer for Socket connection operations
 *
 * Tests connection establishment code paths in Socket-connect.c:
 * - Address resolution
 * - Timeout handling
 * - Non-blocking connect
 * - Poll/wait helpers
 * - Error handling paths
 * - Unix domain socket connections
 */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "socket/Socket.h"
#include "socket/SocketCommon.h"

/* Suppress GCC clobbered warnings for volatile variables */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/* Operation types */
typedef enum
{
  OP_CONNECT_IP = 0,     /* Connect to IP address */
  OP_CONNECT_TIMEOUT,    /* Connect with timeout variations */
  OP_CONNECT_NONBLOCK,   /* Non-blocking connect */
  OP_CONNECT_UNIX,       /* Unix domain socket connect */
  OP_CONNECT_REFUSE,     /* Connect to refused port */
  OP_TIMEOUT_CONFIG,     /* Test timeout configuration */
  OP_SOCKET_OPTIONS,     /* Socket options during connect */
  OP_MULTI_CONNECT       /* Multiple connect attempts */
} ConnectOp;

/* Pre-defined test addresses (RFC 5737 TEST-NET, won't route) */
static const char *test_ips[]
    = { "192.0.2.1",   /* TEST-NET-1 */
        "198.51.100.1", /* TEST-NET-2 */
        "203.0.113.1",  /* TEST-NET-3 */
        "127.0.0.1",    /* Loopback (may connect if service running) */
        "::1"           /* IPv6 loopback */
      };

static uint8_t
get_op (const uint8_t *data, size_t size)
{
  return size > 0 ? data[0] % 8 : 0;
}

static uint16_t
get_port (const uint8_t *data, size_t size)
{
  if (size < 3)
    return 12345;
  uint16_t port = (uint16_t)data[1] | ((uint16_t)data[2] << 8);
  /* Use high ports to avoid privileged ports */
  if (port < 1024)
    port += 1024;
  if (port > 65530)
    port = 65530;
  return port;
}

static int
get_timeout (const uint8_t *data, size_t size)
{
  if (size < 5)
    return 10;
  /* Use small timeouts for fuzzing (0-100ms) */
  return (data[3] | (data[4] << 8)) % 100;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 2)
    return 0;

  Socket_T socket = NULL;
  volatile uint8_t op = get_op (data, size);
  volatile uint16_t port = get_port (data, size);
  volatile int timeout = get_timeout (data, size);

  TRY
  {
    switch (op)
      {
      case OP_CONNECT_IP:
        {
          /* Test connect to various IP addresses */
          socket = Socket_new (AF_INET, SOCK_STREAM, 0);

          /* Select test IP based on fuzz data */
          int ip_idx = (size > 5 ? data[5] : 0)
                       % (sizeof (test_ips) / sizeof (test_ips[0]));
          const char *ip = test_ips[ip_idx];

          /* Set short timeout to avoid blocking */
          Socket_settimeout (socket, 0);

          TRY { Socket_connect (socket, ip, port); }
          EXCEPT (Socket_Failed)
          {
            /* Expected - connection refused or timeout */
          }
          END_TRY;

          Socket_free (&socket);
        }
        break;

      case OP_CONNECT_TIMEOUT:
        {
          /* Test connect with various timeout values */
          socket = Socket_new (AF_INET, SOCK_STREAM, 0);

          /* Test different timeout configurations */
          int timeouts[] = { 0, 1, 10, 50, 100, -1 };
          int idx = (size > 5 ? data[5] : 0)
                    % (sizeof (timeouts) / sizeof (timeouts[0]));

          if (timeouts[idx] >= 0)
            {
              Socket_settimeout (socket, timeouts[idx]);
            }

          TRY
          {
            /* Use TEST-NET address that won't route */
            Socket_connect (socket, "192.0.2.1", port);
          }
          EXCEPT (Socket_Failed)
          {
            /* Expected */
          }
          END_TRY;

          Socket_free (&socket);
        }
        break;

      case OP_CONNECT_NONBLOCK:
        {
          /* Test non-blocking connect */
          socket = Socket_new (AF_INET, SOCK_STREAM, 0);

          /* Set non-blocking before connect */
          Socket_setnonblocking (socket);

          TRY { Socket_connect (socket, "192.0.2.1", port); }
          EXCEPT (Socket_Failed)
          {
            /* Expected - EINPROGRESS or connection refused */
          }
          END_TRY;

          /* Try to check connection status */
          int fd = Socket_fd (socket);
          (void)fd;

          Socket_free (&socket);
        }
        break;

      case OP_CONNECT_UNIX:
        {
          /* Test Unix domain socket connect */
          socket = Socket_new (AF_UNIX, SOCK_STREAM, 0);

          /* Use a path that won't exist */
          char path[108];
          snprintf (path, sizeof (path), "/tmp/fuzz_connect_%d_%u.sock",
                    getpid (), (unsigned)(size > 5 ? data[5] : 0));

          TRY { Socket_connect (socket, path, 0); }
          EXCEPT (Socket_Failed)
          {
            /* Expected - path doesn't exist */
          }
          END_TRY;

          Socket_free (&socket);

          /* Test abstract namespace (Linux) */
#ifdef __linux__
          socket = Socket_new (AF_UNIX, SOCK_STREAM, 0);

          /* Abstract namespace paths start with null byte */
          char abstract_path[108];
          memset (abstract_path, 0, sizeof (abstract_path));
          snprintf (abstract_path + 1, sizeof (abstract_path) - 1,
                    "fuzz_abstract_%d", getpid ());

          TRY { Socket_connect (socket, abstract_path, 0); }
          EXCEPT (Socket_Failed)
          {
            /* Expected */
          }
          END_TRY;

          Socket_free (&socket);
#endif
        }
        break;

      case OP_CONNECT_REFUSE:
        {
          /* Test connection refused scenarios */
          socket = Socket_new (AF_INET, SOCK_STREAM, 0);
          Socket_settimeout (socket, 10);

          /* Connect to localhost on unlikely port */
          TRY { Socket_connect (socket, "127.0.0.1", 1); }
          EXCEPT (Socket_Failed)
          {
            /* Expected - connection refused or permission denied */
          }
          END_TRY;

          Socket_free (&socket);

          /* Try IPv6 */
          TRY
          {
            socket = Socket_new (AF_INET6, SOCK_STREAM, 0);
            Socket_settimeout (socket, 10);

            TRY { Socket_connect (socket, "::1", 1); }
            EXCEPT (Socket_Failed)
            {
              /* Expected */
            }
            END_TRY;

            Socket_free (&socket);
            socket = NULL;
          }
          EXCEPT (Socket_Failed)
          {
            /* IPv6 socket creation failed - OK */
          }
          END_TRY;
        }
        break;

      case OP_TIMEOUT_CONFIG:
        {
          /* Test timeout configuration APIs */
          socket = Socket_new (AF_INET, SOCK_STREAM, 0);

          /* Set various timeouts */
          Socket_settimeout (socket, timeout);
          int current = Socket_gettimeout (socket);
          (void)current;

          /* Set to 0 (no timeout) */
          Socket_settimeout (socket, 0);

          /* Set larger timeout */
          Socket_settimeout (socket, 1000);

          /* Test global timeout defaults */
          SocketCommon_set_dns_timeout (timeout);
          int dns_timeout = SocketCommon_get_dns_timeout ();
          (void)dns_timeout;

          /* Reset to default */
          SocketCommon_set_dns_timeout (-1);

          Socket_free (&socket);
        }
        break;

      case OP_SOCKET_OPTIONS:
        {
          /* Test socket options that affect connect */
          socket = Socket_new (AF_INET, SOCK_STREAM, 0);

          /* Set options before connect */
          Socket_setreuseaddr (socket);
          Socket_setnodelay (socket, 1);
          Socket_setkeepalive (socket, 60, 10, 3); /* idle=60s, interval=10s, count=3 */

          /* Set non-blocking */
          Socket_setnonblocking (socket);

          TRY { Socket_connect (socket, "192.0.2.1", port); }
          EXCEPT (Socket_Failed)
          {
            /* Expected */
          }
          END_TRY;

          Socket_free (&socket);
        }
        break;

      case OP_MULTI_CONNECT:
        {
          /* Test multiple connect attempts */
          int num_attempts = (size > 5 ? data[5] % 5 : 2) + 1;

          for (int i = 0; i < num_attempts; i++)
            {
              socket = Socket_new (AF_INET, SOCK_STREAM, 0);
              Socket_settimeout (socket, 1);

              int ip_idx = (size > (size_t)(6 + i) ? data[6 + i] : (uint8_t)i)
                           % (int)(sizeof (test_ips) / sizeof (test_ips[0]));

              TRY { Socket_connect (socket, test_ips[ip_idx], port + i); }
              EXCEPT (Socket_Failed)
              {
                /* Expected */
              }
              END_TRY;

              Socket_free (&socket);
              socket = NULL;
            }
        }
        break;

      default:
        break;
      }
  }
  EXCEPT (Socket_Failed)
  {
    /* Expected for most operations */
  }
  EXCEPT (SocketCommon_Failed)
  {
    /* Address resolution errors */
  }
  ELSE
  {
    /* Other exceptions */
  }
  END_TRY;

  /* Cleanup */
  if (socket)
    Socket_free (&socket);

  return 0;
}

