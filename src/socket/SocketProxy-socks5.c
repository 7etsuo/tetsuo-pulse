/**
 * SocketProxy-socks5.c - SOCKS5 Protocol Implementation
 *
 * Part of the Socket Library
 *
 * Implements SOCKS Protocol Version 5 (RFC 1928) and
 * Username/Password Authentication (RFC 1929).
 *
 * Protocol Overview:
 * 1. Client sends greeting with supported auth methods
 * 2. Server responds with selected method
 * 3. If method 0x02, client sends username/password auth
 * 4. Server responds with auth status
 * 5. Client sends connect request with target address
 * 6. Server responds with connection status and bound address
 *
 * Address Types (ATYP):
 * - 0x01: IPv4 (4 bytes)
 * - 0x03: Domain name (1 byte length + name)
 * - 0x04: IPv6 (16 bytes)
 */

#include "socket/SocketProxy-private.h"
#include "socket/SocketProxy.h"

#include "core/SocketCrypto.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include "core/SocketUTF8.h"
#include "socket/SocketCommon.h"

        /* ============================================================================
         * Internal Helper Functions
         * ============================================================================ */

        static SocketProxy_Result
        proxy_socks5_check_version (struct SocketProxy_Conn_T *conn, unsigned char got,
                                    unsigned char expected, const char *field)
        {
                if (got != expected) {
                        socketproxy_set_error (conn, PROXY_ERROR_PROTOCOL,
                                               "Invalid SOCKS5 %s version: got 0x%02X expected 0x%02X",
                                               field, got, expected);
                        return PROXY_ERROR_PROTOCOL;
                }
                return PROXY_OK;
        }

        static inline SocketProxy_Result
        proxy_socks5_ensure_data (struct SocketProxy_Conn_T *conn, size_t needed)
        {
                if (conn->recv_len < needed)
                        return PROXY_IN_PROGRESS;
                return PROXY_OK;
        }

/* ============================================================================
 * SOCKS5 Greeting (RFC 1928 Section 3)
 * ============================================================================
 *
 * Client greeting format:
 * +----+----------+----------+
 * |VER | NMETHODS | METHODS  |
 * +----+----------+----------+
 * | 1  |    1     | 1 to 255 |
 * +----+----------+----------+
 *
 * VER: Protocol version (0x05)
 * NMETHODS: Number of authentication methods supported
 * METHODS: List of method identifiers
 *
 * We support:
 * - 0x00: No authentication
 * - 0x02: Username/password (if credentials provided)
 */

int
proxy_socks5_send_greeting (struct SocketProxy_Conn_T *conn)
{
  unsigned char *buf = conn->send_buf;
  size_t len = 0;

  /* Version */
  buf[len++] = SOCKS5_VERSION;

  /* Number of methods and methods list */
  if (conn->username != NULL && conn->password != NULL)
    {
      /* Offer both no-auth and password auth */
      buf[len++] = 2;                   /* NMETHODS */
      buf[len++] = SOCKS5_AUTH_NONE;    /* Method 0: no auth */
      buf[len++] = SOCKS5_AUTH_PASSWORD;/* Method 2: username/password */
    }
  else
    {
      /* Only offer no-auth */
      buf[len++] = 1;                   /* NMETHODS */
      buf[len++] = SOCKS5_AUTH_NONE;    /* Method 0: no auth */
    }

  conn->send_len = len;
  conn->send_offset = 0;
  conn->proto_state = PROTO_STATE_SOCKS5_GREETING_SENT;

  return 0;
}

/* ============================================================================
 * SOCKS5 Method Selection (RFC 1928 Section 3)
 * ============================================================================
 *
 * Server response format:
 * +----+--------+
 * |VER | METHOD |
 * +----+--------+
 * | 1  |   1    |
 * +----+--------+
 *
 * METHOD: Selected authentication method, or 0xFF if none acceptable
 */

SocketProxy_Result
proxy_socks5_recv_method (struct SocketProxy_Conn_T *conn)
{
  unsigned char *buf = conn->recv_buf;

  /* Need at least VER + METHOD bytes */
  {
    SocketProxy_Result res = proxy_socks5_ensure_data (conn, SOCKS5_METHOD_RESPONSE_SIZE);
    if (res != PROXY_OK) return res;
  }

  /* Validate version */
  {
    SocketProxy_Result res = proxy_socks5_check_version (conn, buf[0], SOCKS5_VERSION, "protocol");
    if (res != PROXY_OK)
      return res;
  }

  /* Check selected method */
  conn->socks5_auth_method = buf[1];

  if (conn->socks5_auth_method == SOCKS5_AUTH_NO_ACCEPTABLE)
    {
      socketproxy_set_error (conn, PROXY_ERROR_AUTH_REQUIRED,
                             "No acceptable authentication method");
      return PROXY_ERROR_AUTH_REQUIRED;
    }

  if (conn->socks5_auth_method == SOCKS5_AUTH_NONE)
    {
      /* No authentication required */
      conn->socks5_need_auth = 0;
      conn->proto_state = PROTO_STATE_SOCKS5_METHOD_RECEIVED;
      conn->recv_len = 0;
      conn->recv_offset = 0;
      return PROXY_OK;
    }

  if (conn->socks5_auth_method == SOCKS5_AUTH_PASSWORD)
    {
      /* Username/password authentication required */
      if (conn->username == NULL || conn->password == NULL)
        {
          socketproxy_set_error (conn, PROXY_ERROR_AUTH_REQUIRED,
                             "Server requires authentication but no credentials provided");
          return PROXY_ERROR_AUTH_REQUIRED;
        }
      conn->socks5_need_auth = 1;
      conn->proto_state = PROTO_STATE_SOCKS5_METHOD_RECEIVED;
      conn->recv_len = 0;
      conn->recv_offset = 0;
      return PROXY_OK;
    }

  /* Unsupported method */
  socketproxy_set_error (conn, PROXY_ERROR_UNSUPPORTED,
                          "Unsupported authentication method: 0x%02X", buf[1]);
  return PROXY_ERROR_UNSUPPORTED;
}

/* ============================================================================
 * SOCKS5 Username/Password Authentication (RFC 1929)
 * ============================================================================
 *
 * Client request format:
 * +----+------+----------+------+----------+
 * |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
 * +----+------+----------+------+----------+
 * | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
 * +----+------+----------+------+----------+
 *
 * VER: Auth sub-negotiation version (0x01)
 * ULEN: Username length
 * UNAME: Username
 * PLEN: Password length
 * PASSWD: Password
 */

int
proxy_socks5_send_auth (struct SocketProxy_Conn_T *conn)
{
  unsigned char *buf = conn->send_buf;
  size_t len = 0;
  size_t ulen;
  size_t plen;

  assert (conn->username != NULL);
  assert (conn->password != NULL);

  ulen = strlen (conn->username);
  plen = strlen (conn->password);

  /* Validate lengths */
  if (ulen > SOCKET_PROXY_MAX_USERNAME_LEN)
    {
      socketproxy_set_error (conn, PROXY_ERROR,
                             "Username too long: %zu bytes", ulen);
      return -1;
    }
  if (plen > SOCKET_PROXY_MAX_PASSWORD_LEN)
    {
      socketproxy_set_error (conn, PROXY_ERROR,
                             "Password too long: %zu bytes", plen);
      return -1;
    }

  /* Additional validation using common helpers */
  TRY
    SocketCommon_validate_hostname (conn->username, SocketProxy_Failed);
    if (SocketUTF8_validate_str (conn->username) != UTF8_VALID) {
      PROXY_ERROR_MSG ("Invalid UTF-8 in username");
      socketproxy_set_error (conn, PROXY_ERROR, "%s", socket_error_buf);
      return -1;
    }
    SocketCommon_validate_hostname (conn->password, SocketProxy_Failed);
    if (SocketUTF8_validate_str (conn->password) != UTF8_VALID) {
      PROXY_ERROR_MSG ("Invalid UTF-8 in password");
      socketproxy_set_error (conn, PROXY_ERROR, "%s", socket_error_buf);
      return -1;
    }
  EXCEPT (SocketProxy_Failed)
    socketproxy_set_error (conn, PROXY_ERROR, "%s", socket_error_buf);
    return -1;
  END_TRY;

  /* Build auth request */
  buf[len++] = SOCKS5_AUTH_VERSION; /* VER = 0x01 */
  buf[len++] = (unsigned char)ulen;
  memcpy (buf + len, conn->username, ulen);
  len += ulen;
  buf[len++] = (unsigned char)plen;
  memcpy (buf + len, conn->password, plen);
  len += plen;

  conn->send_len = len;
  conn->send_offset = 0;
  conn->proto_state = PROTO_STATE_SOCKS5_AUTH_SENT;

  return 0;
}

/* ============================================================================
 * SOCKS5 Auth Response (RFC 1929)
 * ============================================================================
 *
 * Server response format:
 * +----+--------+
 * |VER | STATUS |
 * +----+--------+
 * | 1  |   1    |
 * +----+--------+
 *
 * VER: Auth sub-negotiation version (0x01)
 * STATUS: 0x00 = success, other = failure
 */

SocketProxy_Result
proxy_socks5_recv_auth (struct SocketProxy_Conn_T *conn)
{
  unsigned char *buf = conn->recv_buf;

  /* Need at least VER + STATUS bytes */
  {
    SocketProxy_Result res = proxy_socks5_ensure_data (conn, SOCKS5_AUTH_RESPONSE_SIZE);
    if (res != PROXY_OK) return res;
  }

  /* Validate version */
  {
    SocketProxy_Result res = proxy_socks5_check_version (conn, buf[0], SOCKS5_AUTH_VERSION, "auth sub-negotiation");
    if (res != PROXY_OK)
      return res;
  }

  /* Check status */
  if (buf[1] != 0)
    {
      socketproxy_set_error (conn, PROXY_ERROR_AUTH_FAILED,
                             "Authentication failed (status: 0x%02X)", buf[1]);
      return PROXY_ERROR_AUTH_FAILED;
    }

  /* Clear password from memory after successful auth */
  if (conn->password != NULL)
    {
      SocketCrypto_secure_clear (conn->password, strlen (conn->password));
    }

  conn->proto_state = PROTO_STATE_SOCKS5_AUTH_RECEIVED;
  conn->recv_len = 0;
  conn->recv_offset = 0;

  return PROXY_OK;
}

/* ============================================================================
 * SOCKS5 Connect Request (RFC 1928 Section 4)
 * ============================================================================
 *
 * Client request format:
 * +----+-----+-------+------+----------+----------+
 * |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
 * +----+-----+-------+------+----------+----------+
 * | 1  |  1  | X'00' |  1   | Variable |    2     |
 * +----+-----+-------+------+----------+----------+
 *
 * VER: Protocol version (0x05)
 * CMD: Command (0x01 = CONNECT)
 * RSV: Reserved (0x00)
 * ATYP: Address type
 * DST.ADDR: Destination address
 * DST.PORT: Destination port (network byte order)
 *
 * Address types:
 * - 0x01: IPv4 (4 bytes)
 * - 0x03: Domain (1 byte length + name)
 * - 0x04: IPv6 (16 bytes)
 */

int
proxy_socks5_send_connect (struct SocketProxy_Conn_T *conn)
{
  unsigned char *buf = conn->send_buf;
  size_t len = 0;
  struct in_addr ipv4;
  struct in6_addr ipv6;
  size_t host_len;

  /* Additional validation using common helpers */
  TRY
    SocketCommon_validate_port (conn->target_port, SocketProxy_Failed);
    SocketCommon_validate_hostname (conn->target_host, SocketProxy_Failed);
    if (SocketUTF8_validate_str (conn->target_host) != UTF8_VALID) {
      PROXY_ERROR_MSG ("Invalid UTF-8 in target host");
      socketproxy_set_error (conn, PROXY_ERROR, "%s", socket_error_buf);
      return -1;
    }
  EXCEPT (SocketProxy_Failed)
    socketproxy_set_error (conn, PROXY_ERROR, "%s", socket_error_buf);
    return -1;
  END_TRY;

  /* Header */
  buf[len++] = SOCKS5_VERSION;    /* VER */
  buf[len++] = SOCKS5_CMD_CONNECT;/* CMD = CONNECT */
  buf[len++] = 0x00;              /* RSV */

  /* Determine address type */
  if (inet_pton (AF_INET, conn->target_host, &ipv4) == 1)
    {
      /* IPv4 address */
      buf[len++] = SOCKS5_ATYP_IPV4;
      memcpy (buf + len, &ipv4, SOCKS5_IPV4_ADDR_SIZE);
      len += SOCKS5_IPV4_ADDR_SIZE;
    }
  else if (inet_pton (AF_INET6, conn->target_host, &ipv6) == 1)
    {
      /* IPv6 address */
      buf[len++] = SOCKS5_ATYP_IPV6;
      memcpy (buf + len, &ipv6, SOCKS5_IPV6_ADDR_SIZE);
      len += SOCKS5_IPV6_ADDR_SIZE;
    }
  else
    {
      /* Domain name */
      host_len = strlen (conn->target_host);

      /* Validate length and content */
      if (host_len == 0 || host_len > SOCKET_PROXY_MAX_HOSTNAME_LEN)
        {
          socketproxy_set_error (conn, PROXY_ERROR,
                                 "Hostname invalid length: %zu bytes (must be 1-%d)", host_len, SOCKET_PROXY_MAX_HOSTNAME_LEN);
          return -1;
        }
      if (strpbrk (conn->target_host, "\r\n") != NULL)
        {
          socketproxy_set_error (conn, PROXY_ERROR,
                                 "Hostname contains forbidden characters (CR or LF)");
          return -1;
        }
      if (conn->target_port < 1 || conn->target_port > 65535)
        {
          socketproxy_set_error (conn, PROXY_ERROR,
                                 "Invalid target port %d (must be 1-65535)", conn->target_port);
          return -1;
        }

      buf[len++] = SOCKS5_ATYP_DOMAIN;
      buf[len++] = (unsigned char)host_len;
      memcpy (buf + len, conn->target_host, host_len);
      len += host_len;
    }

  /* Port (network byte order) */
  buf[len++] = (unsigned char)((conn->target_port >> 8) & 0xFF);
  buf[len++] = (unsigned char)(conn->target_port & 0xFF);

  conn->send_len = len;
  conn->send_offset = 0;
  conn->proto_state = PROTO_STATE_SOCKS5_CONNECT_SENT;

  return 0;
}

/* ============================================================================
 * SOCKS5 Connect Response (RFC 1928 Section 6)
 * ============================================================================
 *
 * Server response format:
 * +----+-----+-------+------+----------+----------+
 * |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
 * +----+-----+-------+------+----------+----------+
 * | 1  |  1  | X'00' |  1   | Variable |    2     |
 * +----+-----+-------+------+----------+----------+
 *
 * REP field values:
 * 0x00: succeeded
 * 0x01: general SOCKS server failure
 * 0x02: connection not allowed by ruleset
 * 0x03: Network unreachable
 * 0x04: Host unreachable
 * 0x05: Connection refused
 * 0x06: TTL expired
 * 0x07: Command not supported
 * 0x08: Address type not supported
 */

SocketProxy_Result
proxy_socks5_recv_connect (struct SocketProxy_Conn_T *conn)
{
  unsigned char *buf = conn->recv_buf;
  size_t needed;
  size_t addr_len;

  /* Need at least VER + REP + RSV + ATYP bytes for header */
  {
    SocketProxy_Result res = proxy_socks5_ensure_data (conn, SOCKS5_CONNECT_HEADER_SIZE);
    if (res != PROXY_OK) return res;
  }

  /* Validate version */
  {
    SocketProxy_Result res = proxy_socks5_check_version (conn, buf[0], SOCKS5_VERSION, "connect response");
    if (res != PROXY_OK)
      return res;
  }

  /* Check reply code */
  if (buf[1] != SOCKS5_REPLY_SUCCESS)
    {
      return proxy_socks5_reply_to_result (buf[1]);
    }

  /* Calculate total response length based on address type */
  switch (buf[3])
    {
    case SOCKS5_ATYP_IPV4:
      /* header + IPv4 + port */
      needed = SOCKS5_CONNECT_IPV4_RESPONSE_SIZE;
      break;

    case SOCKS5_ATYP_DOMAIN:
      /* Need header + length byte to read domain length */
      {
        SocketProxy_Result res = proxy_socks5_ensure_data (conn, SOCKS5_CONNECT_HEADER_SIZE + 1);
        if (res != PROXY_OK) return res;
      }
      addr_len = buf[4];
      /* header + len byte + domain + port */
      needed = SOCKS5_CONNECT_HEADER_SIZE + 1 + addr_len + SOCKS5_PORT_SIZE;
      break;

    case SOCKS5_ATYP_IPV6:
      /* header + IPv6 + port */
      needed = SOCKS5_CONNECT_IPV6_RESPONSE_SIZE;
      break;

    default:
      socketproxy_set_error (conn, PROXY_ERROR_PROTOCOL,
                             "Unknown address type in response: 0x%02X", buf[3]);
      return PROXY_ERROR_PROTOCOL;
    }

  /* Wait for complete response */
  {
    SocketProxy_Result res = proxy_socks5_ensure_data (conn, needed);
    if (res != PROXY_OK) return res;
  }

  /* Success - tunnel established */
  conn->proto_state = PROTO_STATE_SOCKS5_CONNECT_RECEIVED;
  return PROXY_OK;
}

/* ============================================================================
 * SOCKS5 Reply Code Mapping
 * ============================================================================ */

SocketProxy_Result
proxy_socks5_reply_to_result (int reply)
{
  switch (reply)
    {
    case SOCKS5_REPLY_SUCCESS:
      return PROXY_OK;

    case SOCKS5_REPLY_GENERAL_FAILURE:
      return PROXY_ERROR;

    case SOCKS5_REPLY_NOT_ALLOWED:
      return PROXY_ERROR_FORBIDDEN;

    case SOCKS5_REPLY_NETWORK_UNREACHABLE:
      return PROXY_ERROR_NETWORK_UNREACHABLE;

    case SOCKS5_REPLY_HOST_UNREACHABLE:
      return PROXY_ERROR_HOST_UNREACHABLE;

    case SOCKS5_REPLY_CONNECTION_REFUSED:
      return PROXY_ERROR_CONNECTION_REFUSED;

    case SOCKS5_REPLY_TTL_EXPIRED:
      return PROXY_ERROR_TTL_EXPIRED;

    case SOCKS5_REPLY_COMMAND_NOT_SUPPORTED:
      return PROXY_ERROR_UNSUPPORTED;

    case SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED:
      return PROXY_ERROR_UNSUPPORTED;

    default:
      return PROXY_ERROR_PROTOCOL;
    }
}

