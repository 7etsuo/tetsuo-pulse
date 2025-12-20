/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketSimple-ws.c
 * @brief WebSocket implementation for Simple API.
 *
 * TODO: Wrap SocketWS module.
 */

#include "SocketSimple-internal.h"

/* ============================================================================
 * WebSocket Options
 * ============================================================================
 */

void
Socket_simple_ws_options_init (SocketSimple_WSOptions *opts)
{
  if (!opts)
    return;
  memset (opts, 0, sizeof (*opts));
  opts->connect_timeout_ms = 30000;
}

/* ============================================================================
 * Connection (TODO)
 * ============================================================================
 */

SocketSimple_WS_T
Socket_simple_ws_connect (const char *url)
{
  (void)url;
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED,
                    "WebSocket not yet implemented");
  return NULL;
}

SocketSimple_WS_T
Socket_simple_ws_connect_ex (const char *url, const SocketSimple_WSOptions *opts)
{
  (void)url;
  (void)opts;
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED,
                    "WebSocket not yet implemented");
  return NULL;
}

/* ============================================================================
 * Send (TODO)
 * ============================================================================
 */

int
Socket_simple_ws_send_text (SocketSimple_WS_T ws, const char *text, size_t len)
{
  (void)ws;
  (void)text;
  (void)len;
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED,
                    "WebSocket not yet implemented");
  return -1;
}

int
Socket_simple_ws_send_binary (SocketSimple_WS_T ws, const void *data,
                              size_t len)
{
  (void)ws;
  (void)data;
  (void)len;
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED,
                    "WebSocket not yet implemented");
  return -1;
}

int
Socket_simple_ws_send_json (SocketSimple_WS_T ws, const char *json)
{
  (void)ws;
  (void)json;
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED,
                    "WebSocket not yet implemented");
  return -1;
}

int
Socket_simple_ws_ping (SocketSimple_WS_T ws)
{
  (void)ws;
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED,
                    "WebSocket not yet implemented");
  return -1;
}

/* ============================================================================
 * Receive (TODO)
 * ============================================================================
 */

int
Socket_simple_ws_recv (SocketSimple_WS_T ws, SocketSimple_WSMessage *msg)
{
  (void)ws;
  (void)msg;
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED,
                    "WebSocket not yet implemented");
  return -1;
}

int
Socket_simple_ws_recv_timeout (SocketSimple_WS_T ws, SocketSimple_WSMessage *msg,
                               int timeout_ms)
{
  (void)ws;
  (void)msg;
  (void)timeout_ms;
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED,
                    "WebSocket not yet implemented");
  return -1;
}

/* ============================================================================
 * Close
 * ============================================================================
 */

int
Socket_simple_ws_close (SocketSimple_WS_T ws, int code, const char *reason)
{
  (void)ws;
  (void)code;
  (void)reason;
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED,
                    "WebSocket not yet implemented");
  return -1;
}

void
Socket_simple_ws_free (SocketSimple_WS_T *ws)
{
  if (ws)
    *ws = NULL;
}

void
Socket_simple_ws_message_free (SocketSimple_WSMessage *msg)
{
  if (!msg)
    return;
  free (msg->data);
  free (msg->close_reason);
  memset (msg, 0, sizeof (*msg));
}

/* ============================================================================
 * Status
 * ============================================================================
 */

int
Socket_simple_ws_is_open (SocketSimple_WS_T ws)
{
  (void)ws;
  return 0;
}

const char *
Socket_simple_ws_protocol (SocketSimple_WS_T ws)
{
  (void)ws;
  return NULL;
}

int
Socket_simple_ws_fd (SocketSimple_WS_T ws)
{
  (void)ws;
  return -1;
}
