/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketSimple-happyeyeballs.c
 * @brief Happy Eyeballs (RFC 8305) implementation for Simple API.
 */

#include "SocketSimple-internal.h"
#include "simple/SocketSimple-happyeyeballs.h"

#include "socket/SocketHappyEyeballs.h"

#include <sys/socket.h>

/*============================================================================
 * Configuration Helpers
 *============================================================================*/

void
Socket_simple_happyeyeballs_config_defaults (
    SocketSimple_HappyEyeballs_Config *config)
{
  if (!config)
    return;

  config->resolution_delay_ms = SOCKET_HE_DEFAULT_RESOLUTION_DELAY_MS;
  config->connection_delay_ms = SOCKET_HE_DEFAULT_CONNECTION_DELAY_MS;
  config->prefer_ipv6 = 1;
  config->max_attempts = 0;
}

/*============================================================================
 * Connection Functions
 *============================================================================*/

SocketSimple_Socket_T
Socket_simple_happyeyeballs_connect (const char *host, int port, int timeout_ms)
{
  return Socket_simple_happyeyeballs_connect_config (host, port, timeout_ms,
                                                      NULL);
}

SocketSimple_Socket_T
Socket_simple_happyeyeballs_connect_config (
    const char *host, int port, int timeout_ms,
    const SocketSimple_HappyEyeballs_Config *config)
{
  volatile Socket_T sock = NULL;

  Socket_simple_clear_error ();

  if (!host || host[0] == '\0')
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid host");
      return NULL;
    }

  if (port <= 0 || port > 65535)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid port");
      return NULL;
    }

  if (timeout_ms <= 0)
    {
      timeout_ms = 30000; /* Default 30 seconds */
    }

  /* Build core config from simple config */
  SocketHE_Config_T core_config;
  SocketHappyEyeballs_config_defaults (&core_config);

  /* Map simple config fields to core config fields */
  core_config.total_timeout_ms = timeout_ms;

  if (config)
    {
      core_config.dns_timeout_ms = config->resolution_delay_ms;
      core_config.first_attempt_delay_ms = config->connection_delay_ms;
      core_config.prefer_ipv6 = config->prefer_ipv6;
      if (config->max_attempts > 0)
        core_config.max_attempts = config->max_attempts;
    }

  TRY { sock = SocketHappyEyeballs_connect (host, port, &core_config); }
  EXCEPT (SocketHE_Failed)
  {
    int err = Socket_geterrno ();
    if (err == ETIMEDOUT)
      {
        simple_set_error (SOCKET_SIMPLE_ERR_TIMEOUT, "Connection timed out");
      }
    else
      {
        simple_set_error_errno (SOCKET_SIMPLE_ERR_CONNECT,
                                "Happy Eyeballs connect failed");
      }
    if (sock)
      Socket_free ((Socket_T *)&sock);
    return NULL;
  }
  EXCEPT (Socket_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_CONNECT, "Connection failed");
    if (sock)
      Socket_free ((Socket_T *)&sock);
    return NULL;
  }
  END_TRY;

  SocketSimple_Socket_T handle = simple_create_handle (sock, 0, 0);
  if (!handle)
    {
      Socket_free ((Socket_T *)&sock);
    }
  return handle;
}

/*============================================================================
 * Query Functions
 *============================================================================*/

int
Socket_simple_get_family (SocketSimple_Socket_T sock)
{
  if (!sock || !sock->socket)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid socket");
      return -1;
    }

  int fd = Socket_fd (sock->socket);
  if (fd < 0)
    return -1;

  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof (addr);
  if (getsockname (fd, (struct sockaddr *)&addr, &addrlen) < 0)
    {
      simple_set_error_errno (SOCKET_SIMPLE_ERR_SOCKET,
                              "Failed to get socket family");
      return -1;
    }

  return addr.ss_family;
}

int
Socket_simple_is_ipv6 (SocketSimple_Socket_T sock)
{
  int family = Socket_simple_get_family (sock);
  if (family < 0)
    return -1;
  return (family == AF_INET6) ? 1 : 0;
}

int
Socket_simple_is_ipv4 (SocketSimple_Socket_T sock)
{
  int family = Socket_simple_get_family (sock);
  if (family < 0)
    return -1;
  return (family == AF_INET) ? 1 : 0;
}
