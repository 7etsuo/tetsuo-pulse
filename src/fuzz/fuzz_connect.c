/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_connect.c - Fuzzer for Socket connection operations
 *
 * Tests connection establishment code paths in Socket-connect.c:
 * - Socket creation and options
 * - Non-blocking connect behavior
 * - Address validation
 *
 * NOTE: Only uses loopback addresses (127.0.0.1, ::1) because:
 * - They fail immediately with ECONNREFUSED (no TCP retries)
 * - TEST-NET addresses (192.0.2.x) cause 30+ second TCP timeouts
 * - Non-blocking mode doesn't help - kernel still retries SYN packets
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "core/Except.h"
#include "socket/Socket.h"
#include "socket/SocketCommon.h"

/* Suppress GCC clobbered warnings */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/* Operation types */
typedef enum
{
  OP_CONNECT_IPV4 = 0,
  OP_CONNECT_IPV6,
  OP_SOCKET_OPTIONS,
  OP_MULTI_SOCKET,
  OP_TIMEOUT_CONFIG,
  OP_NONBLOCK_OPTIONS,
  OP_SOCKET_INFO,
  OP_SOCKET_REUSE
} ConnectOp;

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
  /* Use high ports that are unlikely to have services */
  if (port < 10000)
    port += 10000;
  if (port > 65000)
    port = 65000;
  return port;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 2)
    return 0;

  volatile uint8_t op = get_op (data, size);
  volatile uint16_t port = get_port (data, size);
  Socket_T socket = NULL;

  TRY
  {
    switch (op)
      {
      case OP_CONNECT_IPV4:
        /* Connect to loopback - fails immediately with ECONNREFUSED */
        socket = Socket_new (AF_INET, SOCK_STREAM, 0);
        Socket_setnonblocking (socket);
        Socket_connect (socket, "127.0.0.1", port);
        break;

      case OP_CONNECT_IPV6:
        /* Connect to IPv6 loopback - fails immediately with ECONNREFUSED */
        socket = Socket_new (AF_INET6, SOCK_STREAM, 0);
        Socket_setnonblocking (socket);
        Socket_connect (socket, "::1", port);
        break;

      case OP_SOCKET_OPTIONS:
        /* Test various socket options without connecting */
        socket = Socket_new (AF_INET, SOCK_STREAM, 0);
        Socket_setreuseaddr (socket);
        Socket_setnodelay (socket, 1);
        Socket_setkeepalive (socket, 60, 10, 3);
        Socket_setnonblocking (socket);
        Socket_settimeout (socket, 1);
        (void)Socket_gettimeout (socket);
        (void)Socket_fd (socket);
        break;

      case OP_MULTI_SOCKET:
        /* Rapid socket create/destroy */
        for (int i = 0; i < 5; i++)
          {
            Socket_T s = Socket_new (AF_INET, SOCK_STREAM, 0);
            Socket_setreuseaddr (s);
            Socket_setnonblocking (s);
            Socket_free (&s);
          }
        break;

      case OP_TIMEOUT_CONFIG:
        /* Test timeout configuration */
        socket = Socket_new (AF_INET, SOCK_STREAM, 0);
        Socket_settimeout (socket, (size > 3 ? data[3] % 10 : 1) + 1);
        (void)Socket_gettimeout (socket);

        /* Test global DNS timeout config */
        SocketCommon_set_dns_timeout ((size > 4 ? data[4] % 100 : 50) + 10);
        (void)SocketCommon_get_dns_timeout ();
        SocketCommon_set_dns_timeout (-1); /* Reset */
        break;

      case OP_NONBLOCK_OPTIONS:
        /* Test non-blocking with various options then connect */
        socket = Socket_new (AF_INET, SOCK_STREAM, 0);
        Socket_setnonblocking (socket);
        Socket_setreuseaddr (socket);
        Socket_settimeout (socket, 1);
        Socket_connect (socket, "127.0.0.1", port);
        break;

      case OP_SOCKET_INFO:
        /* Test socket info queries */
        socket = Socket_new (AF_INET, SOCK_STREAM, 0);
        (void)Socket_fd (socket);
        (void)Socket_gettimeout (socket);
        (void)Socket_isconnected (socket);
        break;

      case OP_SOCKET_REUSE:
        /* Test address reuse patterns */
        socket = Socket_new (AF_INET, SOCK_STREAM, 0);
        Socket_setreuseaddr (socket);
        Socket_setnonblocking (socket);

        /* Quick connect attempt to loopback */
        Socket_connect (socket, "127.0.0.1", port);
        break;

      default:
        break;
      }
  }
  EXCEPT (Socket_Failed) {}
  EXCEPT (SocketCommon_Failed) {}
  ELSE {}
  END_TRY;

  if (socket)
    Socket_free (&socket);

  return 0;
}
