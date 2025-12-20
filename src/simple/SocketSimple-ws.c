/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketSimple-ws.c
 * @brief WebSocket implementation for Simple API.
 *
 * Wraps the SocketWS module with exception-safe Simple API patterns.
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
 * Connection Functions
 * ============================================================================
 */

SocketSimple_WS_T
Socket_simple_ws_connect (const char *url)
{
  return Socket_simple_ws_connect_ex (url, NULL);
}

SocketSimple_WS_T
Socket_simple_ws_connect_ex (const char *url,
                             const SocketSimple_WSOptions *opts_param)
{
  volatile SocketWS_T ws = NULL;
  volatile int exception_occurred = 0;
  struct SocketSimple_WS *handle = NULL;
  SocketSimple_WSOptions opts_local;
  const char *protocols;

  Socket_simple_clear_error ();

  if (!url)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid URL");
      return NULL;
    }

  if (!opts_param)
    {
      Socket_simple_ws_options_init (&opts_local);
      opts_param = &opts_local;
    }

  protocols = opts_param->subprotocols;

  TRY { ws = SocketWS_connect (url, protocols); }
  EXCEPT (SocketWS_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_CONNECT, "WebSocket connection failed");
    exception_occurred = 1;
  }
  EXCEPT (SocketWS_ProtocolError)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_WS_PROTOCOL, "WebSocket protocol error");
    exception_occurred = 1;
  }
  FINALLY
  {
    if (exception_occurred && ws)
      {
        SocketWS_free ((SocketWS_T *)&ws);
      }
  }
  END_TRY;

  if (exception_occurred)
    return NULL;

  if (!ws)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_CONNECT, "WebSocket connection failed");
      return NULL;
    }

  handle = calloc (1, sizeof (*handle));
  if (!handle)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Memory allocation failed");
      SocketWS_free ((SocketWS_T *)&ws);
      return NULL;
    }

  handle->ws = ws;
  return handle;
}

/* ============================================================================
 * Send Functions
 * ============================================================================
 */

int
Socket_simple_ws_send_text (SocketSimple_WS_T ws, const char *text, size_t len)
{
  volatile int ret = -1;
  volatile int exception_occurred = 0;

  Socket_simple_clear_error ();

  if (!ws || !ws->ws || !text)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  TRY { ret = SocketWS_send_text (ws->ws, text, len); }
  EXCEPT (SocketWS_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_SEND, "WebSocket send failed");
    exception_occurred = 1;
  }
  EXCEPT (SocketWS_Closed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_CLOSED, "WebSocket connection closed");
    exception_occurred = 1;
  }
  END_TRY;

  if (exception_occurred)
    return -1;

  if (ret != 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_SEND, "WebSocket send failed");
      return -1;
    }

  return 0;
}

int
Socket_simple_ws_send_binary (SocketSimple_WS_T ws, const void *data,
                              size_t len)
{
  volatile int ret = -1;
  volatile int exception_occurred = 0;

  Socket_simple_clear_error ();

  if (!ws || !ws->ws || !data)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  TRY { ret = SocketWS_send_binary (ws->ws, data, len); }
  EXCEPT (SocketWS_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_SEND, "WebSocket send failed");
    exception_occurred = 1;
  }
  EXCEPT (SocketWS_Closed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_CLOSED, "WebSocket connection closed");
    exception_occurred = 1;
  }
  END_TRY;

  if (exception_occurred)
    return -1;

  if (ret != 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_SEND, "WebSocket send failed");
      return -1;
    }

  return 0;
}

int
Socket_simple_ws_send_json (SocketSimple_WS_T ws, const char *json)
{
  volatile int ret = -1;
  volatile int exception_occurred = 0;

  Socket_simple_clear_error ();

  if (!ws || !ws->ws || !json)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  TRY { ret = SocketWS_send_json (ws->ws, json); }
  EXCEPT (SocketWS_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_SEND, "WebSocket send failed");
    exception_occurred = 1;
  }
  EXCEPT (SocketWS_Closed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_CLOSED, "WebSocket connection closed");
    exception_occurred = 1;
  }
  END_TRY;

  if (exception_occurred)
    return -1;

  if (ret != 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_SEND, "WebSocket send failed");
      return -1;
    }

  return 0;
}

int
Socket_simple_ws_ping (SocketSimple_WS_T ws)
{
  volatile int ret = -1;
  volatile int exception_occurred = 0;

  Socket_simple_clear_error ();

  if (!ws || !ws->ws)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid WebSocket");
      return -1;
    }

  TRY { ret = SocketWS_ping (ws->ws, NULL, 0); }
  EXCEPT (SocketWS_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_SEND, "WebSocket ping failed");
    exception_occurred = 1;
  }
  EXCEPT (SocketWS_Closed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_CLOSED, "WebSocket connection closed");
    exception_occurred = 1;
  }
  END_TRY;

  if (exception_occurred)
    return -1;

  if (ret != 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_SEND, "WebSocket ping failed");
      return -1;
    }

  return 0;
}

/* ============================================================================
 * Receive Functions
 * ============================================================================
 */

static SocketSimple_WSMessageType
map_opcode_to_simple_type (SocketWS_Opcode opcode)
{
  switch (opcode)
    {
    case WS_OPCODE_TEXT:
      return SOCKET_SIMPLE_WS_TEXT;
    case WS_OPCODE_BINARY:
      return SOCKET_SIMPLE_WS_BINARY;
    case WS_OPCODE_PING:
      return SOCKET_SIMPLE_WS_PING;
    case WS_OPCODE_PONG:
      return SOCKET_SIMPLE_WS_PONG;
    case WS_OPCODE_CLOSE:
      return SOCKET_SIMPLE_WS_CLOSE;
    default:
      return SOCKET_SIMPLE_WS_BINARY;
    }
}

int
Socket_simple_ws_recv (SocketSimple_WS_T ws, SocketSimple_WSMessage *msg)
{
  volatile int ret = -1;
  volatile int exception_occurred = 0;
  SocketWS_Message lib_msg;

  Socket_simple_clear_error ();

  if (!ws || !ws->ws || !msg)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  memset (msg, 0, sizeof (*msg));
  memset (&lib_msg, 0, sizeof (lib_msg));

  TRY { ret = SocketWS_recv_message (ws->ws, &lib_msg); }
  EXCEPT (SocketWS_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_RECV, "WebSocket receive failed");
    exception_occurred = 1;
  }
  EXCEPT (SocketWS_Closed)
  {
    /* Get close info before marking as exception */
    msg->type = SOCKET_SIMPLE_WS_CLOSE;
    msg->close_code = SocketWS_close_code (ws->ws);
    const char *reason = SocketWS_close_reason (ws->ws);
    if (reason)
      msg->close_reason = strdup (reason);
    return 0; /* Not an error, just closed */
  }
  EXCEPT (SocketWS_ProtocolError)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_WS_PROTOCOL, "WebSocket protocol error");
    exception_occurred = 1;
  }
  END_TRY;

  if (exception_occurred)
    return -1;

  if (ret == 0)
    {
      /* Clean close */
      msg->type = SOCKET_SIMPLE_WS_CLOSE;
      msg->close_code = SocketWS_close_code (ws->ws);
      const char *reason = SocketWS_close_reason (ws->ws);
      if (reason)
        msg->close_reason = strdup (reason);
      return 0;
    }

  if (ret < 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_RECV, "WebSocket receive failed");
      return -1;
    }

  /* Copy message to simple struct */
  msg->type = map_opcode_to_simple_type (lib_msg.type);
  msg->len = lib_msg.len;
  msg->data = lib_msg.data; /* Transfer ownership */

  return 0;
}

int
Socket_simple_ws_recv_timeout (SocketSimple_WS_T ws, SocketSimple_WSMessage *msg,
                               int timeout_ms)
{
  Socket_simple_clear_error ();

  if (!ws || !ws->ws || !msg)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  /* Use Socket_probe on the underlying socket for timeout */
  Socket_T sock = SocketWS_socket (ws->ws);
  if (!sock)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_SOCKET, "Invalid socket");
      return -1;
    }

  volatile int ready = 0;
  volatile int exception_occurred = 0;

  TRY { ready = Socket_probe (sock, timeout_ms); }
  EXCEPT (Socket_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_RECV, "Socket probe failed");
    exception_occurred = 1;
  }
  END_TRY;

  if (exception_occurred)
    return -1;

  if (!ready)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_TIMEOUT, "Receive timed out");
      return 1; /* Timeout */
    }

  return Socket_simple_ws_recv (ws, msg);
}

/* ============================================================================
 * Close Functions
 * ============================================================================
 */

int
Socket_simple_ws_close (SocketSimple_WS_T ws, int code, const char *reason)
{
  volatile int ret = -1;
  volatile int exception_occurred = 0;

  Socket_simple_clear_error ();

  if (!ws || !ws->ws)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid WebSocket");
      return -1;
    }

  TRY { ret = SocketWS_close (ws->ws, code, reason); }
  EXCEPT (SocketWS_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_SOCKET, "WebSocket close failed");
    exception_occurred = 1;
  }
  EXCEPT (SocketWS_Closed)
  {
    /* Already closed, not an error */
    return 0;
  }
  END_TRY;

  if (exception_occurred)
    return -1;

  if (ret != 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_SOCKET, "WebSocket close failed");
      return -1;
    }

  return 0;
}

void
Socket_simple_ws_free (SocketSimple_WS_T *ws)
{
  if (!ws || !*ws)
    return;

  struct SocketSimple_WS *handle = *ws;

  if (handle->ws)
    {
      SocketWS_free (&handle->ws);
    }

  free (handle);
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
 * Status Functions
 * ============================================================================
 */

int
Socket_simple_ws_is_open (SocketSimple_WS_T ws)
{
  if (!ws || !ws->ws)
    return 0;
  return SocketWS_state (ws->ws) == WS_STATE_OPEN;
}

const char *
Socket_simple_ws_protocol (SocketSimple_WS_T ws)
{
  if (!ws || !ws->ws)
    return NULL;
  return SocketWS_selected_subprotocol (ws->ws);
}

int
Socket_simple_ws_fd (SocketSimple_WS_T ws)
{
  if (!ws || !ws->ws)
    return -1;
  return SocketWS_pollfd (ws->ws);
}

/* ============================================================================
 * Server Functions
 * ============================================================================ */

void
Socket_simple_ws_server_config_init (SocketSimple_WSServerConfig *config)
{
  if (!config)
    return;
  memset (config, 0, sizeof (*config));
  config->max_frame_size = 16 * 1024 * 1024;   /* 16MB */
  config->max_message_size = 64 * 1024 * 1024; /* 64MB */
  config->validate_utf8 = 1;
  config->enable_compression = 0;
  config->ping_interval_ms = 0;
  config->subprotocols = NULL;
}

int
Socket_simple_ws_is_upgrade (const char *method, const char **headers)
{
  int has_upgrade = 0;
  int has_connection = 0;
  int has_key = 0;
  int has_version = 0;

  if (!method || !headers)
    return 0;

  /* Must be GET request */
  if (strcasecmp (method, "GET") != 0)
    return 0;

  /* Check headers */
  for (const char **h = headers; *h != NULL; h++)
    {
      if (strncasecmp (*h, "Upgrade:", 8) == 0)
        {
          const char *val = *h + 8;
          while (*val == ' ')
            val++;
          if (strcasecmp (val, "websocket") == 0)
            has_upgrade = 1;
        }
      else if (strncasecmp (*h, "Connection:", 11) == 0)
        {
          const char *val = *h + 11;
          while (*val == ' ')
            val++;
          /* Check for "upgrade" in Connection header */
          if (strcasestr (val, "upgrade") != NULL)
            has_connection = 1;
        }
      else if (strncasecmp (*h, "Sec-WebSocket-Key:", 18) == 0)
        {
          has_key = 1;
        }
      else if (strncasecmp (*h, "Sec-WebSocket-Version:", 22) == 0)
        {
          const char *val = *h + 22;
          while (*val == ' ')
            val++;
          if (strcmp (val, "13") == 0)
            has_version = 1;
        }
    }

  return has_upgrade && has_connection && has_key && has_version;
}

SocketSimple_WS_T
Socket_simple_ws_accept (void *http_req,
                         const SocketSimple_WSServerConfig *config)
{
  (void)http_req;
  (void)config;

  /* TODO: Implement WebSocket upgrade from HTTP server request.
   * This requires access to internal HTTP server request structure.
   * For now, use Socket_simple_ws_accept_raw with a raw socket
   * and parsed WebSocket key.
   */
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED,
                    "WebSocket upgrade from HTTP server not yet implemented. "
                    "Use Socket_simple_ws_accept_raw with a raw socket.");
  return NULL;
}

SocketSimple_WS_T
Socket_simple_ws_accept_raw (void *sock, const char *ws_key,
                             const SocketSimple_WSServerConfig *config)
{
  (void)sock;
  (void)ws_key;
  (void)config;

  /* TODO: Implement WebSocket accept on raw socket.
   * This requires building internal HTTP request structures.
   * For production use, the WebSocket client API is fully functional.
   */
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED,
                    "WebSocket raw accept not yet implemented");
  return NULL;
}

void
Socket_simple_ws_reject (void *http_req, int status, const char *reason)
{
  (void)http_req;
  (void)status;
  (void)reason;

  /* TODO: Implement WebSocket rejection.
   * This requires access to internal HTTP server request structure.
   */
}
