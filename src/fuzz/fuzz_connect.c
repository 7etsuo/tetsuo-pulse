/**
 * fuzz_connect.c - Fuzzer for Socket connection operations
 *
 * Tests connection establishment code paths in Socket-connect.c:
 * - Address resolution
 * - Timeout handling
 * - Non-blocking connect
 * - Socket options
 *
 * NOTE: This fuzzer avoids nested TRY/EXCEPT blocks to prevent
 * stack-use-after-scope issues with setjmp/longjmp and AddressSanitizer.
 */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
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
  OP_CONNECT_IP = 0,
  OP_CONNECT_TIMEOUT,
  OP_CONNECT_NONBLOCK,
  OP_CONNECT_OPTIONS,
  OP_TIMEOUT_CONFIG,
  OP_MULTI_SOCKET,
  OP_IPV6_CONNECT,
  OP_SOCKET_CREATE
} ConnectOp;

/* Pre-defined test addresses (RFC 5737 TEST-NET, won't route) */
static const char *test_ips[]
    = { "192.0.2.1",    /* TEST-NET-1 - immediate failure */
        "198.51.100.1", /* TEST-NET-2 - immediate failure */
        "203.0.113.1",  /* TEST-NET-3 - immediate failure */
        "127.0.0.1"     /* Loopback */
      };

#define NUM_TEST_IPS (sizeof (test_ips) / sizeof (test_ips[0]))

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
  if (port < 1024)
    port += 1024;
  if (port > 65530)
    port = 65530;
  return port;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 2)
    return 0;

  volatile uint8_t op = get_op (data, size);
  volatile uint16_t port = get_port (data, size);
  volatile int ip_idx = (size > 3 ? data[3] : 0) % (int)NUM_TEST_IPS;
  Socket_T socket = NULL;

  /* Single TRY block - no nesting to avoid ASan scope issues */
  TRY
  {
    switch (op)
      {
      case OP_CONNECT_IP:
        socket = Socket_new (AF_INET, SOCK_STREAM, 0);
        Socket_settimeout (socket, 1); /* 1ms timeout */
        Socket_connect (socket, test_ips[ip_idx], port);
        break;

      case OP_CONNECT_TIMEOUT:
        socket = Socket_new (AF_INET, SOCK_STREAM, 0);
        Socket_settimeout (socket, (size > 4 ? (data[4] % 10) : 1) + 1);
        Socket_connect (socket, "192.0.2.1", port);
        break;

      case OP_CONNECT_NONBLOCK:
        socket = Socket_new (AF_INET, SOCK_STREAM, 0);
        Socket_setnonblocking (socket);
        Socket_connect (socket, "192.0.2.1", port);
        break;

      case OP_CONNECT_OPTIONS:
        socket = Socket_new (AF_INET, SOCK_STREAM, 0);
        Socket_setreuseaddr (socket);
        Socket_setnodelay (socket, 1);
        Socket_setkeepalive (socket, 60, 10, 3);
        Socket_setnonblocking (socket);
        Socket_connect (socket, "192.0.2.1", port);
        break;

      case OP_TIMEOUT_CONFIG:
        /* Test timeout configuration without connecting */
        socket = Socket_new (AF_INET, SOCK_STREAM, 0);
        Socket_settimeout (socket, 1);
        (void)Socket_gettimeout (socket);
        Socket_settimeout (socket, 5);
        (void)Socket_gettimeout (socket);

        /* Test global DNS timeout config */
        SocketCommon_set_dns_timeout (100);
        (void)SocketCommon_get_dns_timeout ();
        SocketCommon_set_dns_timeout (-1); /* Reset */
        break;

      case OP_MULTI_SOCKET:
        /* Create and immediately free multiple sockets */
        for (int i = 0; i < 3; i++)
          {
            Socket_T s = Socket_new (AF_INET, SOCK_STREAM, 0);
            Socket_settimeout (s, 1);
            Socket_setnonblocking (s);
            Socket_free (&s);
          }
        break;

      case OP_IPV6_CONNECT:
        socket = Socket_new (AF_INET6, SOCK_STREAM, 0);
        Socket_settimeout (socket, 1);
        Socket_connect (socket, "::1", port);
        break;

      case OP_SOCKET_CREATE:
        /* Test various socket creation patterns */
        socket = Socket_new (AF_INET, SOCK_STREAM, 0);
        (void)Socket_fd (socket);
        Socket_setreuseaddr (socket);
        break;

      default:
        break;
      }
  }
  EXCEPT (Socket_Failed)
  {
    /* Expected for most connect operations */
  }
  EXCEPT (SocketCommon_Failed)
  {
    /* DNS/address resolution errors */
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
