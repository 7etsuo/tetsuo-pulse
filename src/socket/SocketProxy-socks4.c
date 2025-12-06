/**
 * SocketProxy-socks4.c - SOCKS4/4a Protocol Implementation
 *
 * Part of the Socket Library
 *
 * Implements SOCKS4 and SOCKS4a protocols (de-facto standards, no RFC).
 *
 * SOCKS4 Protocol:
 * - Supports only IPv4 addresses
 * - Client sends: VN(4), CD(1=connect), DSTPORT, DSTIP, USERID, NULL
 * - Server responds: VN(0), CD(90=granted), DSTPORT, DSTIP
 *
 * SOCKS4a Extension:
 * - Allows hostname resolution at the proxy server
 * - Uses "invalid" IP 0.0.0.x to signal hostname follows
 * - Format: VN(4), CD(1), DSTPORT, 0.0.0.x, USERID, NULL, HOSTNAME, NULL
 *
 * Reply Codes (CD field):
 * - 90: Request granted
 * - 91: Request rejected or failed
 * - 92: Request rejected - no identd running
 * - 93: Request rejected - identd mismatch
 */

#include "socket/SocketProxy-private.h"
#include "socket/SocketProxy.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

/* ============================================================================
 * SOCKS4 Connect Request
 * ============================================================================
 *
 * Request format:
 * +----+----+----+----+----+----+----+----+----+----+...+----+
 * | VN | CD | DSTPORT |      DSTIP        | USERID  |NULL|
 * +----+----+----+----+----+----+----+----+----+----+...+----+
 *   1    1      2              4           variable    1
 *
 * VN: SOCKS version (0x04)
 * CD: Command code (0x01 = CONNECT)
 * DSTPORT: Destination port (network byte order)
 * DSTIP: Destination IP (network byte order)
 * USERID: User ID string (can be empty)
 * NULL: Null terminator for USERID
 */

int
proxy_socks4_send_connect (struct SocketProxy_Conn_T *conn)
{
  unsigned char *buf = conn->send_buf;
  size_t len = 0;
  struct in_addr ipv4;
  const char *userid;
  size_t userid_len;

  /* Parse target as IPv4 address */
  if (inet_pton (AF_INET, conn->target_host, &ipv4) != 1)
    {
      snprintf (conn->error_buf, sizeof (conn->error_buf),
                "SOCKS4 requires IPv4 address (use SOCKS4A for hostnames)");
      return -1;
    }

  /* Build request */
  buf[len++] = SOCKS4_VERSION;        /* VN = 0x04 */
  buf[len++] = SOCKS4_CMD_CONNECT;    /* CD = CONNECT */

  /* DSTPORT (network byte order) */
  buf[len++] = (unsigned char)((conn->target_port >> 8) & 0xFF);
  buf[len++] = (unsigned char)(conn->target_port & 0xFF);

  /* DSTIP (network byte order) */
  memcpy (buf + len, &ipv4, 4);
  len += 4;

  /* USERID (use username if provided, otherwise empty) */
  userid = conn->username != NULL ? conn->username : "";
  userid_len = strlen (userid);

  if (len + userid_len + 1 > sizeof (conn->send_buf))
    {
      snprintf (conn->error_buf, sizeof (conn->error_buf),
                "Request too large");
      return -1;
    }

  memcpy (buf + len, userid, userid_len);
  len += userid_len;
  buf[len++] = 0x00; /* NULL terminator */

  conn->send_len = len;
  conn->send_offset = 0;
  conn->proto_state = PROTO_STATE_SOCKS4_CONNECT_SENT;

  return 0;
}

/* ============================================================================
 * SOCKS4a Connect Request
 * ============================================================================
 *
 * SOCKS4a extension format:
 * +----+----+----+----+----+----+----+----+----+...+----+----+...+----+
 * | VN | CD | DSTPORT |      DSTIP        | USERID  |NULL| HOSTNAME |NULL|
 * +----+----+----+----+----+----+----+----+----+...+----+----+...+----+
 *   1    1      2        0.0.0.x (4)       variable   1    variable   1
 *
 * DSTIP: Set to 0.0.0.x where x != 0 to signal hostname follows
 * HOSTNAME: Domain name to resolve at proxy
 *
 * This allows the proxy to resolve the hostname, avoiding DNS leaks
 * when the client shouldn't be making DNS queries.
 */

int
proxy_socks4a_send_connect (struct SocketProxy_Conn_T *conn)
{
  unsigned char *buf = conn->send_buf;
  size_t len = 0;
  struct in_addr ipv4;
  const char *userid;
  size_t userid_len;
  size_t host_len;

  /* Check if target is already an IPv4 address */
  if (inet_pton (AF_INET, conn->target_host, &ipv4) == 1)
    {
      /* Use regular SOCKS4 for IPv4 addresses */
      return proxy_socks4_send_connect (conn);
    }

  /* Get hostname length */
  host_len = strlen (conn->target_host);
  if (host_len > SOCKET_PROXY_MAX_HOSTNAME_LEN)
    {
      snprintf (conn->error_buf, sizeof (conn->error_buf),
                "Hostname too long: %zu bytes", host_len);
      return -1;
    }

  /* Build SOCKS4a request */
  buf[len++] = SOCKS4_VERSION;        /* VN = 0x04 */
  buf[len++] = SOCKS4_CMD_CONNECT;    /* CD = CONNECT */

  /* DSTPORT (network byte order) */
  buf[len++] = (unsigned char)((conn->target_port >> 8) & 0xFF);
  buf[len++] = (unsigned char)(conn->target_port & 0xFF);

  /* DSTIP: 0.0.0.x where x != 0 signals SOCKS4a */
  buf[len++] = 0x00;
  buf[len++] = 0x00;
  buf[len++] = 0x00;
  buf[len++] = 0x01; /* Any non-zero value works */

  /* USERID (use username if provided, otherwise empty) */
  userid = conn->username != NULL ? conn->username : "";
  userid_len = strlen (userid);

  if (len + userid_len + 1 + host_len + 1 > sizeof (conn->send_buf))
    {
      snprintf (conn->error_buf, sizeof (conn->error_buf),
                "Request too large");
      return -1;
    }

  memcpy (buf + len, userid, userid_len);
  len += userid_len;
  buf[len++] = 0x00; /* NULL terminator for USERID */

  /* HOSTNAME followed by NULL */
  memcpy (buf + len, conn->target_host, host_len);
  len += host_len;
  buf[len++] = 0x00; /* NULL terminator for HOSTNAME */

  conn->send_len = len;
  conn->send_offset = 0;
  conn->proto_state = PROTO_STATE_SOCKS4_CONNECT_SENT;

  return 0;
}

/* ============================================================================
 * SOCKS4 Response
 * ============================================================================
 *
 * Response format:
 * +----+----+----+----+----+----+----+----+
 * | VN | CD | DSTPORT |      DSTIP        |
 * +----+----+----+----+----+----+----+----+
 *   1    1      2              4
 *
 * VN: Reply version (0x00, not 0x04!)
 * CD: Result code
 * DSTPORT: Server-assigned port (or 0)
 * DSTIP: Server-assigned IP (or 0)
 *
 * Result codes:
 * 90: Request granted
 * 91: Request rejected or failed
 * 92: Request rejected - no identd
 * 93: Request rejected - identd mismatch
 */

SocketProxy_Result
proxy_socks4_recv_response (struct SocketProxy_Conn_T *conn)
{
  unsigned char *buf = conn->recv_buf;

  /* Need exactly 8 bytes */
  if (conn->recv_len < 8)
    return PROXY_IN_PROGRESS;

  /* Note: Reply VN should be 0, not 4 */
  if (buf[0] != 0)
    {
      snprintf (conn->error_buf, sizeof (conn->error_buf),
                "Invalid SOCKS4 reply version: 0x%02X (expected 0x00)", buf[0]);
      return PROXY_ERROR_PROTOCOL;
    }

  /* Check result code */
  if (buf[1] != SOCKS4_REPLY_GRANTED)
    {
      return proxy_socks4_reply_to_result (buf[1]);
    }

  /* Success - tunnel established */
  conn->proto_state = PROTO_STATE_SOCKS4_CONNECT_RECEIVED;
  return PROXY_OK;
}

/* ============================================================================
 * SOCKS4 Reply Code Mapping
 * ============================================================================ */

SocketProxy_Result
proxy_socks4_reply_to_result (int reply)
{
  switch (reply)
    {
    case SOCKS4_REPLY_GRANTED:
      return PROXY_OK;

    case SOCKS4_REPLY_REJECTED:
      return PROXY_ERROR_FORBIDDEN;

    case SOCKS4_REPLY_NO_IDENTD:
      /* REFACTOR: Now uses centralized socket_error_buf from SocketUtil.h */
      PROXY_ERROR_MSG ("SOCKS4 rejected: no identd service on client");
      return PROXY_ERROR_AUTH_REQUIRED;

    case SOCKS4_REPLY_IDENTD_MISMATCH:
      PROXY_ERROR_MSG ("SOCKS4 rejected: identd user mismatch");
      return PROXY_ERROR_AUTH_FAILED;

    default:
      PROXY_ERROR_MSG ("Unknown SOCKS4 reply code: %d", reply);
      return PROXY_ERROR_PROTOCOL;
    }
}

