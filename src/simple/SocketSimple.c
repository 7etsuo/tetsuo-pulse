/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketSimple.c
 * @brief Core error handling and shared helpers for Simple API.
 *
 * Implementations are split across:
 *   - SocketSimple-tcp.c  (TCP/UDP)
 *   - SocketSimple-tls.c  (TLS)
 *   - SocketSimple-dns.c  (DNS)
 *   - SocketSimple-http.c (HTTP)
 *   - SocketSimple-ws.c   (WebSocket)
 */

#include "SocketSimple-internal.h"

/* ============================================================================
 * Thread-Local Error State
 * ============================================================================
 */

__thread SimpleError simple_error = { 0 };

/* ============================================================================
 * Error Helper Functions (used by sub-modules)
 * ============================================================================
 */

void
simple_set_error (SocketSimple_ErrorCode code, const char *msg)
{
  simple_error.code = code;
  simple_error.errno_value = errno;
  if (msg)
    {
      snprintf (simple_error.message, sizeof (simple_error.message), "%s",
                msg);
    }
  else
    {
      simple_error.message[0] = '\0';
    }
}

void
simple_set_error_errno (SocketSimple_ErrorCode code, const char *prefix)
{
  simple_error.code = code;
  simple_error.errno_value = errno;
  snprintf (simple_error.message, sizeof (simple_error.message), "%s: %s",
            prefix, strerror (errno));
}

/* ============================================================================
 * Error Access Functions (public API)
 * ============================================================================
 */

const char *
Socket_simple_error (void)
{
  if (simple_error.code == SOCKET_SIMPLE_OK)
    {
      return NULL;
    }
  return simple_error.message[0] ? simple_error.message : "Unknown error";
}

int
Socket_simple_errno (void)
{
  return simple_error.errno_value;
}

SocketSimple_ErrorCode
Socket_simple_code (void)
{
  return simple_error.code;
}

int
Socket_simple_is_retryable (void)
{
  int err = simple_error.errno_value;
  return err == EAGAIN || err == EWOULDBLOCK || err == EINTR
         || err == ECONNREFUSED || err == ETIMEDOUT || err == ENETUNREACH
         || err == EHOSTUNREACH;
}

void
Socket_simple_clear_error (void)
{
  simple_error.code = SOCKET_SIMPLE_OK;
  simple_error.errno_value = 0;
  simple_error.message[0] = '\0';
}

/* ============================================================================
 * Handle Helper Functions (used by sub-modules)
 * ============================================================================
 */

SocketSimple_Socket_T
simple_create_handle (Socket_T sock, int is_server, int is_tls)
{
  struct SocketSimple_Socket *handle = calloc (1, sizeof (*handle));
  if (!handle)
    {
      int saved_errno = errno; /* Preserve errno immediately */
      errno = saved_errno;     /* Restore before helper call */
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Memory allocation failed");
      return NULL;
    }
  handle->socket = sock;
  handle->is_server = is_server;
  handle->is_tls = is_tls;
  handle->is_connected = !is_server;
  handle->is_udp = 0;
  return handle;
}

SocketSimple_Socket_T
simple_create_udp_handle (SocketDgram_T dgram)
{
  struct SocketSimple_Socket *handle = calloc (1, sizeof (*handle));
  if (!handle)
    {
      int saved_errno = errno; /* Preserve errno immediately */
      errno = saved_errno;     /* Restore before helper call */
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Memory allocation failed");
      return NULL;
    }
  handle->dgram = dgram;
  handle->is_udp = 1;
  return handle;
}
