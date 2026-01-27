/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketSimple-proxy.c
 * @brief Simple proxy tunneling implementation.
 *
 * Wraps SocketProxy core module with Simple API patterns.
 */

#include "SocketSimple-internal.h"
#include "simple/SocketSimple-proxy.h"

#include "core/SocketCrypto.h"
#include "socket/SocketProxy.h"

#include <ctype.h>
#include <errno.h>

/* ============================================================================
 * Configuration Functions
 * ============================================================================
 */

void
Socket_simple_proxy_config_init (SocketSimple_ProxyConfig *config)
{
  if (!config)
    return;

  memset (config, 0, sizeof (*config));
  config->type = SOCKET_SIMPLE_PROXY_NONE;
  config->port = 0;
  config->connect_timeout_ms = 0;   /* Use default */
  config->handshake_timeout_ms = 0; /* Use default */
}

void
Socket_simple_proxy_config_clear (SocketSimple_ProxyConfig *config)
{
  if (!config)
    return;

  /* Securely clear sensitive credential data to prevent memory disclosure */
  SocketCrypto_secure_clear (config->username, sizeof (config->username));
  SocketCrypto_secure_clear (config->password, sizeof (config->password));

  /* Clear the rest of the structure */
  memset (config, 0, sizeof (*config));
}

/* Helper to convert simple proxy type to core proxy type */
static SocketProxyType
simple_to_core_proxy_type (SocketSimple_ProxyType type)
{
  switch (type)
    {
    case SOCKET_SIMPLE_PROXY_NONE:
      return SOCKET_PROXY_NONE;
    case SOCKET_SIMPLE_PROXY_HTTP:
      return SOCKET_PROXY_HTTP;
    case SOCKET_SIMPLE_PROXY_HTTPS:
      return SOCKET_PROXY_HTTPS;
    case SOCKET_SIMPLE_PROXY_SOCKS4:
      return SOCKET_PROXY_SOCKS4;
    case SOCKET_SIMPLE_PROXY_SOCKS4A:
      return SOCKET_PROXY_SOCKS4A;
    case SOCKET_SIMPLE_PROXY_SOCKS5:
      return SOCKET_PROXY_SOCKS5;
    case SOCKET_SIMPLE_PROXY_SOCKS5H:
      return SOCKET_PROXY_SOCKS5H;
    default:
      return SOCKET_PROXY_NONE;
    }
}

/* Helper to set error from proxy result */
static void
set_proxy_error (SocketProxy_Result result, const char *default_msg)
{
  switch (result)
    {
    case PROXY_ERROR_CONNECT:
      simple_set_error (SOCKET_SIMPLE_ERR_PROXY, "Failed to connect to proxy");
      break;
    case PROXY_ERROR_AUTH_REQUIRED:
      simple_set_error (SOCKET_SIMPLE_ERR_PROXY_AUTH,
                        "Proxy requires authentication");
      break;
    case PROXY_ERROR_AUTH_FAILED:
      simple_set_error (SOCKET_SIMPLE_ERR_PROXY_AUTH,
                        "Proxy authentication failed");
      break;
    case PROXY_ERROR_FORBIDDEN:
      simple_set_error (SOCKET_SIMPLE_ERR_PROXY_DENIED,
                        "Proxy denied connection");
      break;
    case PROXY_ERROR_HOST_UNREACHABLE:
      simple_set_error (SOCKET_SIMPLE_ERR_PROXY, "Target host unreachable");
      break;
    case PROXY_ERROR_NETWORK_UNREACHABLE:
      simple_set_error (SOCKET_SIMPLE_ERR_PROXY, "Target network unreachable");
      break;
    case PROXY_ERROR_CONNECTION_REFUSED:
      simple_set_error (SOCKET_SIMPLE_ERR_PROXY,
                        "Connection refused by target");
      break;
    case PROXY_ERROR_TTL_EXPIRED:
      simple_set_error (SOCKET_SIMPLE_ERR_PROXY, "TTL expired");
      break;
    case PROXY_ERROR_PROTOCOL:
      simple_set_error (SOCKET_SIMPLE_ERR_PROXY, "Proxy protocol error");
      break;
    case PROXY_ERROR_UNSUPPORTED:
      simple_set_error (SOCKET_SIMPLE_ERR_PROXY, "Proxy command not supported");
      break;
    case PROXY_ERROR_TIMEOUT:
      simple_set_error (SOCKET_SIMPLE_ERR_TIMEOUT, "Proxy operation timed out");
      break;
    case PROXY_ERROR_CANCELLED:
      simple_set_error (SOCKET_SIMPLE_ERR_PROXY, "Proxy operation cancelled");
      break;
    default:
      simple_set_error (SOCKET_SIMPLE_ERR_PROXY, default_msg);
      break;
    }
}

/* Scheme lookup table for URL parsing */
typedef struct
{
  const char *prefix;
  size_t prefix_len;
  SocketSimple_ProxyType type;
} SchemeEntry;

static const SchemeEntry scheme_table[] = {
  /* Order matters: longer prefixes first to avoid partial matches */
  { "socks5h://", 10, SOCKET_SIMPLE_PROXY_SOCKS5H },
  { "socks4a://", 10, SOCKET_SIMPLE_PROXY_SOCKS4A },
  { "socks5://", 9, SOCKET_SIMPLE_PROXY_SOCKS5 },
  { "socks4://", 9, SOCKET_SIMPLE_PROXY_SOCKS4 },
  { "socks://", 8, SOCKET_SIMPLE_PROXY_SOCKS5 }, /* Alias for socks5 */
  { "https://", 8, SOCKET_SIMPLE_PROXY_HTTPS },
  { "http://", 7, SOCKET_SIMPLE_PROXY_HTTP },
};

#define SCHEME_COUNT (sizeof (scheme_table) / sizeof (scheme_table[0]))

/* Helper to parse scheme from URL */
static int
parse_scheme (const char *url, SocketSimple_ProxyType *type, const char **rest)
{
  for (size_t i = 0; i < SCHEME_COUNT; i++)
    {
      if (strncasecmp (url, scheme_table[i].prefix, scheme_table[i].prefix_len)
          == 0)
        {
          *type = scheme_table[i].type;
          *rest = url + scheme_table[i].prefix_len;
          return 0;
        }
    }
  return -1; /* Unknown scheme */
}

/* URL decoding utilities are now in SocketUtil.h:
 * - socket_util_hex_digit() - decode hex digit character
 * - socket_util_url_decode() - decode percent-encoded string
 * See SocketUtil.h for full documentation.
 */

/**
 * @brief Parse and decode userinfo from proxy URL.
 * @param userinfo_start Start of userinfo section.
 * @param userinfo_end End of userinfo section (@ character).
 * @param config Config structure to populate.
 * @return 0 on success, -1 on error (credentials too long).
 */
static int
parse_userinfo (const char *userinfo_start,
                const char *userinfo_end,
                SocketSimple_ProxyConfig *config)
{
  const char *colon
      = memchr (userinfo_start, ':', userinfo_end - userinfo_start);

  if (colon)
    {
      /* user:pass format */
      if (socket_util_url_decode (userinfo_start,
                                  colon - userinfo_start,
                                  config->username,
                                  sizeof (config->username),
                                  NULL)
          != 0)
        {
          simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                            "Proxy username too long");
          return -1;
        }

      if (socket_util_url_decode (colon + 1,
                                  userinfo_end - colon - 1,
                                  config->password,
                                  sizeof (config->password),
                                  NULL)
          != 0)
        {
          simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                            "Proxy password too long");
          return -1;
        }
    }
  else
    {
      /* username only */
      if (socket_util_url_decode (userinfo_start,
                                  userinfo_end - userinfo_start,
                                  config->username,
                                  sizeof (config->username),
                                  NULL)
          != 0)
        {
          simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                            "Proxy username too long");
          return -1;
        }
    }

  return 0;
}

/**
 * @brief Parse host and port from URL remainder.
 * @param host_start Start of host[:port] section.
 * @param config Config structure to populate with hostname.
 * @return Pointer to port section (or NULL if no port), or (const char*)-1 on
 * error.
 */
static const char *
parse_host_port (const char *host_start, SocketSimple_ProxyConfig *config)
{
  const char *host_end = host_start;
  const char *port_start = NULL;

  /* Handle IPv6 [address] notation */
  if (*host_start == '[')
    {
      const char *bracket = strchr (host_start, ']');
      if (!bracket)
        {
          simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                            "Invalid IPv6 address in URL");
          return (const char *)-1;
        }

      /* Copy IPv6 address without brackets */
      size_t addr_len = bracket - host_start - 1;
      if (addr_len >= sizeof (config->host))
        {
          simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Hostname too long");
          return (const char *)-1;
        }

      memcpy (config->host, host_start + 1, addr_len);
      config->host[addr_len] = '\0';
      host_end = bracket + 1;

      if (*host_end == ':')
        port_start = host_end + 1;
    }
  else
    {
      /* Regular hostname or IPv4 */
      while (*host_end && *host_end != ':' && *host_end != '/')
        host_end++;

      size_t host_len = host_end - host_start;
      if (host_len >= sizeof (config->host))
        {
          simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Hostname too long");
          return (const char *)-1;
        }

      memcpy (config->host, host_start, host_len);
      config->host[host_len] = '\0';

      if (*host_end == ':')
        port_start = host_end + 1;
    }

  return port_start;
}

/**
 * @brief Parse port number from string.
 * @param port_str String containing port number.
 * @return Parsed port on success, -1 on error.
 */
static int
parse_port_number (const char *port_str)
{
  char *endptr;
  errno = 0; /* Reset errno before strtol */
  long port = strtol (port_str, &endptr, 10);

  /* Check for parse failure (no digits consumed) */
  if (endptr == port_str)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid port: not a number");
      return -1;
    }

  /* Check that strtol stopped at valid terminator */
  if (*endptr != '\0' && *endptr != '/')
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid port: contains non-numeric characters");
      return -1;
    }

  /* Check for overflow or out of range */
  if (errno == ERANGE || port <= 0 || port > 65535)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid port: out of range");
      return -1;
    }

  return (int)port;
}

/**
 * @brief Get default port for proxy type.
 * @param type Proxy type.
 * @return Default port number.
 */
static int
get_default_proxy_port (SocketSimple_ProxyType type)
{
  switch (type)
    {
    case SOCKET_SIMPLE_PROXY_HTTP:
    case SOCKET_SIMPLE_PROXY_HTTPS:
      return 8080;
    case SOCKET_SIMPLE_PROXY_SOCKS4:
    case SOCKET_SIMPLE_PROXY_SOCKS4A:
    case SOCKET_SIMPLE_PROXY_SOCKS5:
    case SOCKET_SIMPLE_PROXY_SOCKS5H:
      return 1080;
    default:
      return 8080;
    }
}

int
Socket_simple_proxy_parse_url (const char *url,
                               SocketSimple_ProxyConfig *config)
{
  Socket_simple_clear_error ();

  if (!url || !config)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "NULL url or config");
      return -1;
    }

  Socket_simple_proxy_config_init (config);

  /* Parse scheme */
  const char *rest = NULL;
  if (parse_scheme (url, &config->type, &rest) != 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Unknown proxy URL scheme");
      return -1;
    }

  /* Parse optional userinfo */
  const char *at = strchr (rest, '@');
  const char *slash = strchr (rest, '/');
  const char *host_start = rest;

  if (at && (!slash || at < slash))
    {
      if (parse_userinfo (rest, at, config) != 0)
        return -1;
      host_start = at + 1;
    }

  /* Parse host and port */
  const char *port_start = parse_host_port (host_start, config);
  if (port_start == (const char *)-1)
    return -1;

  /* Parse explicit port or use default */
  if (port_start)
    {
      int port = parse_port_number (port_start);
      if (port < 0)
        return -1;
      config->port = port;
    }
  else
    {
      config->port = get_default_proxy_port (config->type);
    }

  /* Validate hostname */
  if (config->host[0] == '\0')
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Missing hostname in proxy URL");
      return -1;
    }

  return 0;
}

const char *
Socket_simple_proxy_type_name (SocketSimple_ProxyType type)
{
  switch (type)
    {
    case SOCKET_SIMPLE_PROXY_NONE:
      return "direct";
    case SOCKET_SIMPLE_PROXY_HTTP:
      return "HTTP";
    case SOCKET_SIMPLE_PROXY_HTTPS:
      return "HTTPS";
    case SOCKET_SIMPLE_PROXY_SOCKS4:
      return "SOCKS4";
    case SOCKET_SIMPLE_PROXY_SOCKS4A:
      return "SOCKS4a";
    case SOCKET_SIMPLE_PROXY_SOCKS5:
      return "SOCKS5";
    case SOCKET_SIMPLE_PROXY_SOCKS5H:
      return "SOCKS5h";
    default:
      return "unknown";
    }
}

/* ============================================================================
 * Synchronous Connection
 * ============================================================================
 */

/* Helper to build core config from simple config */
static void
build_core_config (const SocketSimple_ProxyConfig *simple,
                   SocketProxy_Config *core)
{
  SocketProxy_config_defaults (core);

  core->type = simple_to_core_proxy_type (simple->type);
  core->host = simple->host;
  core->port = simple->port;

  if (simple->username[0] != '\0')
    {
      core->username = simple->username;
      if (simple->password[0] != '\0')
        {
          core->password = simple->password;
        }
    }

  core->connect_timeout_ms = simple->connect_timeout_ms;
  core->handshake_timeout_ms = simple->handshake_timeout_ms;
}

SocketSimple_Socket_T
Socket_simple_proxy_connect (const SocketSimple_ProxyConfig *config,
                             const char *target_host,
                             int target_port)
{
  return Socket_simple_proxy_connect_timeout (
      config, target_host, target_port, 0);
}

SocketSimple_Socket_T
Socket_simple_proxy_connect_timeout (const SocketSimple_ProxyConfig *config,
                                     const char *target_host,
                                     int target_port,
                                     int timeout_ms_arg)
{
  volatile Socket_T sock = NULL;
  volatile int timeout_ms = timeout_ms_arg;

  Socket_simple_clear_error ();

  if (!config)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "NULL proxy config");
      return NULL;
    }

  if (config->type == SOCKET_SIMPLE_PROXY_NONE)
    {
      /* Direct connection, no proxy */
      if (timeout_ms > 0)
        return Socket_simple_connect_timeout (
            target_host, target_port, timeout_ms);
      else
        return Socket_simple_connect (target_host, target_port);
    }

  if (!target_host || target_port <= 0 || target_port > 65535)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid target host or port");
      return NULL;
    }

  if (config->host[0] == '\0' || config->port <= 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid proxy host or port");
      return NULL;
    }

  /* Build core config */
  SocketProxy_Config core_config;
  build_core_config (config, &core_config);

  /* Override timeout if specified */
  if (timeout_ms > 0)
    {
      core_config.connect_timeout_ms = timeout_ms;
      core_config.handshake_timeout_ms = timeout_ms;
    }

  TRY
  {
    sock = SocketProxy_connect (&core_config, target_host, target_port);
  }
  EXCEPT (SocketProxy_Failed)
  {
    /* Use generic PROXY_ERROR since specific SocketProxy_Result is not
     * available in this exception handler - only the exception itself */
    set_proxy_error (PROXY_ERROR, "Proxy connection failed");
    if (sock)
      Socket_free ((Socket_T *)&sock);
    return NULL;
  }
  EXCEPT (Socket_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_PROXY,
                            "Socket error during proxy connect");
    if (sock)
      Socket_free ((Socket_T *)&sock);
    return NULL;
  }
  END_TRY;

  if (!sock)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_PROXY, "Proxy connection failed");
      return NULL;
    }

  SocketSimple_Socket_T handle = simple_create_handle (sock, 0, 0);
  if (!handle)
    {
      Socket_free ((Socket_T *)&sock);
    }
  else
    {
      handle->is_connected = 1;
    }
  return handle;
}

SocketSimple_Socket_T
Socket_simple_proxy_connect_tls (const SocketSimple_ProxyConfig *config,
                                 const char *target_host,
                                 int target_port)
{
#ifdef SOCKET_HAS_TLS
  Socket_simple_clear_error ();

  /* First connect through proxy */
  SocketSimple_Socket_T sock
      = Socket_simple_proxy_connect (config, target_host, target_port);
  if (!sock)
    {
      /* Error already set */
      return NULL;
    }

  /* Upgrade to TLS */
  if (Socket_simple_enable_tls (sock, target_host) != 0)
    {
      /* Error already set by tls_upgrade */
      Socket_simple_close (&sock);
      return NULL;
    }

  return sock;
#else
  Socket_simple_clear_error ();
  simple_set_error (SOCKET_SIMPLE_ERR_TLS, "TLS not available");
  (void)config;
  (void)target_host;
  (void)target_port;
  return NULL;
#endif
}

/* ============================================================================
 * Tunnel on Existing Socket
 * ============================================================================
 */

int
Socket_simple_proxy_tunnel (SocketSimple_Socket_T sock,
                            const SocketSimple_ProxyConfig *config,
                            const char *target_host,
                            int target_port)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->socket)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid socket");
      return -1;
    }

  if (!config)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "NULL proxy config");
      return -1;
    }

  if (config->type == SOCKET_SIMPLE_PROXY_NONE)
    {
      /* No tunneling needed */
      return 0;
    }

  if (!target_host || target_port <= 0 || target_port > 65535)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid target host or port");
      return -1;
    }

  /* Build core config */
  SocketProxy_Config core_config;
  build_core_config (config, &core_config);

  volatile SocketProxy_Result result = PROXY_ERROR;

  TRY
  {
    result = SocketProxy_tunnel (
        sock->socket, &core_config, target_host, target_port, NULL);
  }
  EXCEPT (SocketProxy_Failed)
  {
    set_proxy_error (result, "Proxy handshake failed");
    return -1;
  }
  EXCEPT (Socket_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_PROXY,
                            "Socket error during tunnel handshake");
    return -1;
  }
  END_TRY;

  if (result != PROXY_OK)
    {
      set_proxy_error (result, "Proxy handshake failed");
      return -1;
    }

  sock->is_connected = 1;
  return 0;
}
