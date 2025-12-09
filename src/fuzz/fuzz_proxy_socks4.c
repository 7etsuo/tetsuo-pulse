/**
 * fuzz_proxy_socks4.c - Fuzzing harness for SOCKS4/4a protocol parsing
 *
 * Part of the Socket Library
 *
 * Fuzzes SOCKS4 response parsing:
 * - Connect response
 * - Reply code mapping
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

  /* Copy fuzzed data into receive buffer */
  memcpy (conn.recv_buf, data,
          size < sizeof (conn.recv_buf) ? size : sizeof (conn.recv_buf) - 1);
  conn.recv_len
      = size < sizeof (conn.recv_buf) ? size : sizeof (conn.recv_buf) - 1;

  /* Test SOCKS4 response parsing */
  proxy_socks4_recv_response (&conn);

  /* Test reply code mapping */
  if (size >= 1)
    {
      proxy_socks4_reply_to_result ((int)data[0]);
    }

  return 0;
}
