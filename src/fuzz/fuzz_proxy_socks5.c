/**
 * fuzz_proxy_socks5.c - Fuzzing harness for SOCKS5 protocol parsing
 *
 * Part of the Socket Library
 *
 * Fuzzes SOCKS5 response parsing:
 * - Method selection response
 * - Authentication response
 * - Connect response (all address types)
 */

#include "socket/SocketProxy-private.h"
#include "socket/SocketProxy.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  struct SocketProxy_Conn_T conn;

  /* Skip empty or tiny input */
  if (size < 2)
    return 0;

  /* Initialize connection structure */
  memset (&conn, 0, sizeof (conn));

  /* Test method selection response parsing */
  memcpy (conn.recv_buf, data,
          size < sizeof (conn.recv_buf) ? size : sizeof (conn.recv_buf) - 1);
  conn.recv_len
      = size < sizeof (conn.recv_buf) ? size : sizeof (conn.recv_buf) - 1;
  conn.username = "testuser";
  conn.password = "testpass";

  proxy_socks5_recv_method (&conn);

  /* Test authentication response parsing */
  conn.recv_len
      = size < sizeof (conn.recv_buf) ? size : sizeof (conn.recv_buf) - 1;
  proxy_socks5_recv_auth (&conn);

  /* Test connect response parsing */
  conn.recv_len
      = size < sizeof (conn.recv_buf) ? size : sizeof (conn.recv_buf) - 1;
  proxy_socks5_recv_connect (&conn);

  /* Test reply code mapping */
  if (size >= 1)
    {
      proxy_socks5_reply_to_result ((int)data[0]);
    }

  return 0;
}
