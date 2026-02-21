/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

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

#include "core/SocketUTF8.h"
#include "socket/SocketCommon.h"
#include "socket/SocketCommon-private.h"
#include "socket/SocketProxy-private.h"
#include "socket/SocketProxy.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

/** SOCKS4 response size in bytes */
#define SOCKS4_RESPONSE_SIZE 8

/** SOCKS4a marker IP: 0.0.0.1 signals hostname follows */
static const unsigned char SOCKS4A_MARKER_IP[4] = { 0x00, 0x00, 0x00, 0x01 };

/**
 * socks4_ensure_buffer_space - Validate buffer space before write
 * @conn: Proxy connection context for error reporting
 * @current_len: Current number of bytes in send buffer
 * @needed_bytes: Additional bytes needed for next write
 *
 * Returns: 0 on success (sufficient space), -1 on overflow (error set in conn)
 *
 * Provides consistent buffer validation for all SOCKS4/4a request building.
 * Prevents buffer overflow by checking that current_len + needed_bytes does
 * not exceed send_buf capacity.
 *
 * Sets PROXY_ERROR_PROTOCOL with "Request too large" message on failure,
 * following the pattern established at line 329 in
 * proxy_socks4a_send_connect().
 */
static inline int
socks4_ensure_buffer_space (struct SocketProxy_Conn_T *conn,
                            size_t current_len,
                            size_t needed_bytes)
{
  if (current_len + needed_bytes > sizeof (conn->send_buf))
    {
      socketproxy_set_error (
          conn, PROXY_ERROR_PROTOCOL, "SOCKS4 request too large for buffer");
      return -1;
    }
  return 0;
}

/**
 * socks4_write_header - Write SOCKS4 request header (version + command + port)
 * @buf: Output buffer (must have at least 4 bytes available)
 * @port: Destination port (1-65535)
 *
 * Returns: Number of bytes written (always 4)
 *
 * Writes the common header for both SOCKS4 and SOCKS4a requests:
 * VN(4), CD(1=CONNECT), DSTPORT(2 bytes, network order)
 */
static size_t
socks4_write_header (unsigned char *buf, int port)
{
  buf[0] = SOCKS4_VERSION;
  buf[1] = SOCKS4_CMD_CONNECT;
  buf[2] = (unsigned char)((port >> 8) & 0xFF);
  buf[3] = (unsigned char)(port & 0xFF);
  return 4;
}

/**
 * socks4_write_userid - Write userid string with null terminator
 * @buf: Output buffer
 * @buf_remaining: Remaining buffer space
 * @username: Username or NULL (empty string if NULL)
 * @bytes_written: Output - bytes written including null terminator
 *
 * Returns: 0 on success, -1 if buffer overflow
 *
 * Username length and validity already checked by caller
 * (socks4_validate_inputs).
 */
static int
socks4_write_userid (unsigned char *buf,
                     size_t buf_remaining,
                     const char *username,
                     size_t *bytes_written)
{
  const char *userid = (username != NULL) ? username : "";
  size_t userid_len = strlen (userid);

  /* userid_len already validated <= SOCKET_PROXY_MAX_USERNAME_LEN and UTF-8 by
   * caller */

  /* Need space for userid + null terminator */
  if (userid_len + 1 > buf_remaining)
    {
      *bytes_written = 0;
      return -1;
    }

  memcpy (buf, userid, userid_len);
  buf[userid_len] = 0x00;
  *bytes_written = userid_len + 1;
  return 0;
}

/**
 * socks4_validate_username - Validate username for SOCKS4/4a requests
 * @conn: Proxy connection context
 *
 * Returns: 0 on success, -1 on validation failure (error set in conn)
 *
 * Validates that username (if provided) does not exceed maximum length
 * and contains valid UTF-8 encoding. Sets PROXY_ERROR_PROTOCOL on failure.
 */
static int
socks4_validate_username (struct SocketProxy_Conn_T *conn)
{
  if (conn->username == NULL)
    return 0;

  size_t user_len = strlen (conn->username);
  if (user_len > SOCKET_PROXY_MAX_USERNAME_LEN)
    {
      socketproxy_set_error (conn,
                             PROXY_ERROR_PROTOCOL,
                             "Username too long (max %d): %zu",
                             SOCKET_PROXY_MAX_USERNAME_LEN,
                             user_len);
      return -1;
    }

  if (SocketUTF8_validate_str (conn->username) != UTF8_VALID)
    {
      socketproxy_set_error (
          conn, PROXY_ERROR_PROTOCOL, "Invalid UTF-8 in username");
      return -1;
    }

  return 0;
}

/**
 * socks4_validate_inputs - Common input validation for SOCKS4/4a requests
 * @conn: Proxy connection context
 * @out_host_len: Optional output for target_host length (may be NULL)
 *
 * Returns: 0 on success, -1 on validation failure (error set in conn)
 *
 * Validates port (1-65535), hostname (RFC 1123 syntax, UTF-8, length <=255),
 * and optional username (length <=255, UTF-8) for SOCKS4/4a requests.
 *
 * If out_host_len is non-NULL, sets it to strlen(target_host), avoiding
 * redundant strlen() calls in the caller.
 *
 * Sets PROXY_ERROR_PROTOCOL on validation failures.
 */
static int
socks4_validate_inputs (struct SocketProxy_Conn_T *conn, size_t *out_host_len)
{
  size_t host_len = 0;

  TRY
  {
    SocketCommon_validate_port (conn->target_port, SocketProxy_Failed);

    /* Validate hostname and optionally get its length */
    if (socketcommon_validate_hostname_internal (
            conn->target_host, 1, SocketProxy_Failed, &host_len)
        != 0)
      {
        RETURN - 1;
      }

    /* UTF-8 validation for target host (hostnames may be internationalized) */
    if (SocketUTF8_validate_str (conn->target_host) != UTF8_VALID)
      {
        socketproxy_set_error (
            conn, PROXY_ERROR_PROTOCOL, "Invalid UTF-8 in target host");
        RETURN - 1;
      }
  }
  EXCEPT (SocketProxy_Failed)
  {
    socketproxy_set_error (conn, PROXY_ERROR_PROTOCOL, "%s", socket_error_buf);
    RETURN - 1;
  }
  END_TRY;

  /* Validate username (outside TRY block since it sets error directly) */
  if (socks4_validate_username (conn) != 0)
    return -1;

  /* Return computed host length if requested */
  if (out_host_len)
    *out_host_len = host_len;

  return 0;
}


/**
 * socks4_write_ipv4_address - Write IPv4 destination address to SOCKS4 request
 * @conn: Proxy connection for error reporting and buffer access
 * @buf: Output buffer
 * @len: Current offset (updated on success)
 * @ipv4: Parsed IPv4 address
 *
 * Returns: 0 on success, -1 on buffer overflow
 */
static int
socks4_write_ipv4_address (struct SocketProxy_Conn_T *conn,
                           unsigned char *buf,
                           size_t *len,
                           const struct in_addr *ipv4)
{
  if (socks4_ensure_buffer_space (conn, *len, 4) < 0)
    return -1;

  memcpy (buf + *len, ipv4, 4);
  *len += 4;
  return 0;
}

int
proxy_socks4_send_connect (struct SocketProxy_Conn_T *conn)
{
  unsigned char *buf = conn->send_buf;
  size_t len = 0;
  struct in_addr ipv4;
  size_t userid_written;

  assert (conn != NULL);

  if (socks4_validate_inputs (conn, NULL) < 0)
    return -1;

  /* Parse target as IPv4 address */
  if (inet_pton (AF_INET, conn->target_host, &ipv4) != 1)
    {
      socketproxy_set_error (
          conn,
          PROXY_ERROR_PROTOCOL,
          "SOCKS4 requires IPv4 address (use SOCKS4A for hostnames)");
      return -1;
    }

  /* Write header */
  if (socks4_ensure_buffer_space (conn, len, 4) < 0)
    return -1;
  len += socks4_write_header (buf + len, conn->target_port);

  /* Write destination IP */
  if (socks4_write_ipv4_address (conn, buf, &len, &ipv4) < 0)
    return -1;

  /* Write userid */
  if (socks4_write_userid (buf + len,
                           sizeof (conn->send_buf) - len,
                           conn->username,
                           &userid_written)
      < 0)
    {
      socketproxy_set_error (
          conn, PROXY_ERROR_PROTOCOL, "SOCKS4 request too large for buffer");
      return -1;
    }
  len += userid_written;

  conn->send_len = len;
  conn->send_offset = 0;
  conn->proto_state = PROTO_STATE_SOCKS4_CONNECT_SENT;

  return 0;
}

/**
 * socks4a_is_ipv4_target - Check if target is an IPv4 address
 * @host: Target hostname
 *
 * Returns: 1 if IPv4 address, 0 otherwise
 */
static int
socks4a_is_ipv4_target (const char *host)
{
  struct in_addr ipv4;
  return inet_pton (AF_INET, host, &ipv4) == 1;
}

/**
 * socks4a_write_marker_ip - Write SOCKS4a marker IP (0.0.0.1)
 * @conn: Proxy connection
 * @buf: Buffer to write to
 * @len: Current buffer offset (updated)
 *
 * Returns: 0 on success, -1 on error
 */
static int
socks4a_write_marker_ip (struct SocketProxy_Conn_T *conn,
                         unsigned char *buf,
                         size_t *len)
{
  if (socks4_ensure_buffer_space (conn, *len, 4) < 0)
    return -1;

  memcpy (buf + *len, SOCKS4A_MARKER_IP, 4);
  *len += 4;
  return 0;
}

/**
 * socks4a_write_hostname - Write hostname with null terminator
 * @conn: Proxy connection
 * @buf: Buffer to write to
 * @len: Current buffer offset (updated)
 * @host: Hostname to write
 * @host_len: Length of hostname
 *
 * Returns: 0 on success, -1 on error
 */
static int
socks4a_write_hostname (struct SocketProxy_Conn_T *conn,
                        unsigned char *buf,
                        size_t *len,
                        const char *host,
                        size_t host_len)
{
  if (socks4_ensure_buffer_space (conn, *len, host_len + 1) < 0)
    return -1;

  memcpy (buf + *len, host, host_len);
  *len += host_len;
  buf[(*len)++] = 0x00;
  return 0;
}

int
proxy_socks4a_send_connect (struct SocketProxy_Conn_T *conn)
{
  unsigned char *buf = conn->send_buf;
  size_t len = 0;
  size_t userid_written;
  size_t host_len;

  assert (conn != NULL);

  if (socks4_validate_inputs (conn, &host_len) < 0)
    return -1;

  /* Delegate to plain SOCKS4 if target is already IPv4 */
  if (socks4a_is_ipv4_target (conn->target_host))
    return proxy_socks4_send_connect (conn);

  /* Write header */
  if (socks4_ensure_buffer_space (conn, len, 4) < 0)
    return -1;
  len += socks4_write_header (buf + len, conn->target_port);

  /* Write SOCKS4a marker IP */
  if (socks4a_write_marker_ip (conn, buf, &len) < 0)
    return -1;

  /* Write userid */
  if (socks4_write_userid (buf + len,
                           sizeof (conn->send_buf) - len,
                           conn->username,
                           &userid_written)
      < 0)
    {
      socketproxy_set_error (
          conn, PROXY_ERROR_PROTOCOL, "SOCKS4 request too large for buffer");
      return -1;
    }
  len += userid_written;

  /* Write hostname */
  if (socks4a_write_hostname (conn, buf, &len, conn->target_host, host_len) < 0)
    return -1;

  conn->send_len = len;
  conn->send_offset = 0;
  conn->proto_state = PROTO_STATE_SOCKS4_CONNECT_SENT;
  return 0;
}

SocketProxy_Result
proxy_socks4_recv_response (struct SocketProxy_Conn_T *conn)
{
  unsigned char *buf = conn->recv_buf;

  assert (conn != NULL);

  /* Need exactly 8 bytes */
  if (conn->recv_len < SOCKS4_RESPONSE_SIZE)
    return PROXY_IN_PROGRESS;

  /* Reply VN must be 0, not 4 (per SOCKS4 spec) */
  if (buf[0] != 0)
    {
      socketproxy_set_error (
          conn,
          PROXY_ERROR_PROTOCOL,
          "Invalid SOCKS4 reply version: 0x%02X (expected 0x00)",
          buf[0]);
      return PROXY_ERROR_PROTOCOL;
    }

  /* Check result code */
  if (buf[1] != SOCKS4_REPLY_GRANTED)
    return proxy_socks4_reply_to_result (buf[1]);

  /* Success - tunnel established */
  conn->proto_state = PROTO_STATE_SOCKS4_CONNECT_RECEIVED;
  conn->recv_offset += SOCKS4_RESPONSE_SIZE; /* Consume response bytes */
  return PROXY_OK;
}

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
