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
#include "core/Arena.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTPServer-private.h"
#include "simple/SocketSimple-http-server.h"

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
  opts->connect_timeout_ms = SOCKET_SIMPLE_WS_DEFAULT_TIMEOUT_MS;
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
    simple_set_error (SOCKET_SIMPLE_ERR_CONNECT,
                      "WebSocket connection failed");
    exception_occurred = 1;
  }
  EXCEPT (SocketWS_ProtocolError)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_WS_PROTOCOL,
                      "WebSocket protocol error");
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
      simple_set_error (SOCKET_SIMPLE_ERR_CONNECT,
                        "WebSocket connection failed");
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

/**
 * @brief Function pointer type for WebSocket send operations.
 *
 * This type is used to abstract different send operations (text, binary, json)
 * in the common error handling wrapper.
 *
 * @param ws The WebSocket handle
 * @param data Pointer to data to send
 * @param len Length of data (may be ignored for some operations like json)
 * @return 0 on success, non-zero on failure
 */
typedef int (*ws_send_fn) (SocketWS_T ws, const void *data, size_t len);

/**
 * @brief Common wrapper for WebSocket send operations.
 *
 * Centralizes exception handling for send operations to avoid code duplication.
 * Handles validation, exception catching, and error reporting.
 *
 * @param ws Simple API WebSocket wrapper
 * @param data Data to send (validated for NULL)
 * @param len Length parameter (passed to send_fn)
 * @param send_fn Function pointer to the actual send operation
 * @return 0 on success, -1 on error (error details in simple error state)
 */
static int
ws_send_wrapper (SocketSimple_WS_T ws, const void *data, size_t len,
                 ws_send_fn send_fn)
{
  volatile int ret = -1;
  volatile int exception_occurred = 0;

  Socket_simple_clear_error ();

  if (!ws || !ws->ws || !data)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  TRY { ret = send_fn (ws->ws, data, len); }
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
Socket_simple_ws_send_text (SocketSimple_WS_T ws, const char *text, size_t len)
{
  return ws_send_wrapper (ws, text, len,
                          (ws_send_fn)SocketWS_send_text);
}

int
Socket_simple_ws_send_binary (SocketSimple_WS_T ws, const void *data,
                              size_t len)
{
  return ws_send_wrapper (ws, data, len,
                          (ws_send_fn)SocketWS_send_binary);
}

/**
 * @brief Adapter to make SocketWS_send_json compatible with ws_send_fn signature.
 *
 * SocketWS_send_json computes length internally via strlen, so we ignore
 * the len parameter.
 */
static int
ws_send_json_adapter (SocketWS_T ws, const void *data, size_t len)
{
  (void)len; /* Unused - json send computes length internally */
  return SocketWS_send_json (ws, (const char *)data);
}

int
Socket_simple_ws_send_json (SocketSimple_WS_T ws, const char *json)
{
  return ws_send_wrapper (ws, json, 0, ws_send_json_adapter);
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
      {
        msg->close_reason = strdup (reason);
        if (!msg->close_reason)
          {
            /* Allocation failed, but still return gracefully with NULL reason */
            msg->close_reason = NULL;
          }
      }
    return 0; /* Not an error, just closed */
  }
  EXCEPT (SocketWS_ProtocolError)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_WS_PROTOCOL,
                      "WebSocket protocol error");
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
        {
          msg->close_reason = strdup (reason);
          if (!msg->close_reason)
            {
              /* Allocation failed, but still return gracefully with NULL reason */
              msg->close_reason = NULL;
            }
        }
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
Socket_simple_ws_recv_timeout (SocketSimple_WS_T ws,
                               SocketSimple_WSMessage *msg, int timeout_ms)
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
 * ============================================================================
 */

void
Socket_simple_ws_server_config_init (SocketSimple_WSServerConfig *config)
{
  if (!config)
    return;
  memset (config, 0, sizeof (*config));
  config->max_frame_size = SOCKET_SIMPLE_WS_DEFAULT_MAX_FRAME_SIZE;
  config->max_message_size = SOCKET_SIMPLE_WS_DEFAULT_MAX_MESSAGE_SIZE;
  config->validate_utf8 = 1;
  config->enable_compression = 0;
  config->ping_interval_ms = 0;
  config->subprotocols = NULL;
}

/**
 * @brief Check if header matches name and has expected value.
 *
 * @param header Full header line (e.g., "Upgrade: websocket")
 * @param name Header name with colon (e.g., "Upgrade:")
 * @param name_len Length of header name including colon
 * @param expected_value Expected value (NULL to just check presence)
 * @return 1 if match, 0 otherwise
 */
static int
check_header_value (const char *header, const char *name, size_t name_len,
                    const char *expected_value)
{
  if (strncasecmp (header, name, name_len) != 0)
    return 0;

  const char *val = header + name_len;
  while (*val == ' ')
    val++;

  if (expected_value)
    return strcasecmp (val, expected_value) == 0;

  return *val != '\0'; /* Just check presence */
}

/**
 * @brief Check if header contains substring in value.
 *
 * @param header Full header line
 * @param name Header name with colon
 * @param name_len Length of header name including colon
 * @param substring Substring to find (case-insensitive)
 * @return 1 if found, 0 otherwise
 */
static int
check_header_contains (const char *header, const char *name, size_t name_len,
                       const char *substring)
{
  if (strncasecmp (header, name, name_len) != 0)
    return 0;

  const char *val = header + name_len;
  while (*val == ' ')
    val++;

  return strcasestr (val, substring) != NULL;
}

int
Socket_simple_ws_is_upgrade (const char *method, const char **headers)
{
  if (!method || !headers || strcasecmp (method, "GET") != 0)
    return 0;

  int has_upgrade = 0, has_connection = 0, has_key = 0, has_version = 0;

  for (const char **h = headers; *h != NULL; h++)
    {
      if (check_header_value (*h, "Upgrade:", 8, "websocket"))
        has_upgrade = 1;
      else if (check_header_contains (*h, "Connection:", 11, "upgrade"))
        has_connection = 1;
      else if (check_header_value (*h, "Sec-WebSocket-Key:", 18, NULL))
        has_key = 1;
      else if (check_header_value (*h, "Sec-WebSocket-Version:", 22, "13"))
        has_version = 1;
    }

  return has_upgrade && has_connection && has_key && has_version;
}

/**
 * @brief Convert Simple API config to core SocketWS_Config.
 */
static void
convert_ws_server_config (const SocketSimple_WSServerConfig *simple_config,
                          SocketWS_Config *ws_config)
{
  SocketWS_config_defaults (ws_config);
  ws_config->role = WS_ROLE_SERVER;

  if (simple_config)
    {
      ws_config->max_frame_size = simple_config->max_frame_size;
      ws_config->max_message_size = simple_config->max_message_size;
      ws_config->validate_utf8 = simple_config->validate_utf8;
      ws_config->enable_permessage_deflate = simple_config->enable_compression;
      ws_config->ping_interval_ms = simple_config->ping_interval_ms;
      ws_config->subprotocols = simple_config->subprotocols;
    }
}

/**
 * @brief Perform WebSocket handshake with error handling.
 *
 * Executes the handshake polling loop and handles errors by freeing
 * the WebSocket on failure.
 *
 * @param ws Pointer to volatile WebSocket handle
 * @param exception_occurred Pointer to exception flag
 * @return 0 on success, -1 on failure
 */
static int
perform_ws_handshake (volatile SocketWS_T *ws, volatile int *exception_occurred)
{
  int handshake_result;

  do
    {
      handshake_result = SocketWS_handshake (*ws);
    }
  while (handshake_result > 0);

  if (handshake_result < 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_WS_PROTOCOL,
                        "WebSocket handshake failed");
      SocketWS_free ((SocketWS_T *)ws);
      *exception_occurred = 1;
      return -1;
    }

  return 0;
}

SocketSimple_WS_T
Socket_simple_ws_accept (void *http_req,
                         const SocketSimple_WSServerConfig *config)
{
  volatile SocketWS_T ws = NULL;
  volatile int exception_occurred = 0;
  struct SocketSimple_WS *handle = NULL;
  SocketWS_Config ws_config;

  Socket_simple_clear_error ();

  if (!http_req)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "HTTP request is NULL");
      return NULL;
    }

  /* Get the Simple API HTTP server request wrapper */
  SocketSimple_HTTPServerRequest_T simple_req
      = (SocketSimple_HTTPServerRequest_T)http_req;

  /* Access the core HTTP server request through the simple wrapper */
  SocketHTTPServer_Request_T core_req = simple_req->core_req;
  if (!core_req)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid HTTP server request");
      return NULL;
    }

  /* Get the underlying connection and socket */
  ServerConnection *conn = core_req->conn;
  if (!conn || !conn->socket)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "HTTP connection has no socket");
      return NULL;
    }

  /* Get the parsed HTTP request */
  const SocketHTTP_Request *request = conn->request;
  if (!request)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "HTTP request not parsed");
      return NULL;
    }

  /* Convert Simple API config to core config */
  convert_ws_server_config (config, &ws_config);

  TRY
  {
    /* Accept the WebSocket upgrade */
    ws = SocketWS_server_accept (conn->socket, request, &ws_config);

    if (ws)
      {
        /* Complete the handshake (sends 101 Switching Protocols) */
        if (perform_ws_handshake (&ws, &exception_occurred) < 0)
          {
            ws = NULL; /* Already freed by helper */
          }
      }
  }
  EXCEPT (SocketWS_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_SOCKET,
                      "WebSocket server accept failed");
    exception_occurred = 1;
  }
  EXCEPT (SocketWS_ProtocolError)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_WS_PROTOCOL,
                      "WebSocket protocol error during accept");
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
      simple_set_error (SOCKET_SIMPLE_ERR_SOCKET, "WebSocket accept failed");
      return NULL;
    }

  /* Create the simple wrapper handle */
  handle = calloc (1, sizeof (*handle));
  if (!handle)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Memory allocation failed");
      SocketWS_free ((SocketWS_T *)&ws);
      return NULL;
    }

  handle->ws = ws;

  /* Mark the HTTP connection as upgraded - prevent normal response handling.
   * The socket is now owned by the WebSocket, so we need to prevent the
   * HTTP server from closing it. Set conn->socket to NULL to indicate this. */
  conn->socket = NULL;

  return handle;
}

SocketSimple_WS_T
Socket_simple_ws_accept_raw (void *sock, const char *ws_key,
                             const SocketSimple_WSServerConfig *config)
{
  volatile SocketWS_T ws = NULL;
  volatile int exception_occurred = 0;
  struct SocketSimple_WS *handle = NULL;
  SocketWS_Config ws_config;
  volatile Arena_T arena = NULL;
  volatile SocketHTTP_Request *request = NULL;
  volatile SocketHTTP_Headers_T headers = NULL;

  Socket_simple_clear_error ();

  if (!sock)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Socket is NULL");
      return NULL;
    }

  if (!ws_key || strlen (ws_key) == 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "WebSocket key is required");
      return NULL;
    }

  /* Cast the socket handle */
  Socket_T socket = (Socket_T)sock;

  /* Convert Simple API config to core config */
  convert_ws_server_config (config, &ws_config);

  TRY
  {
    /* Create a temporary arena for the fake HTTP request */
    arena = Arena_new ();

    /* Build a minimal HTTP request structure for WebSocket upgrade */
    request
        = Arena_alloc (arena, sizeof (SocketHTTP_Request), __FILE__, __LINE__);
    memset ((void *)request, 0, sizeof (SocketHTTP_Request));

    /* Create headers container */
    headers = SocketHTTP_Headers_new (arena);

    /* Add required WebSocket upgrade headers */
    SocketHTTP_Headers_add (headers, "Upgrade", "websocket");
    SocketHTTP_Headers_add (headers, "Connection", "Upgrade");
    SocketHTTP_Headers_add (headers, "Sec-WebSocket-Key", ws_key);
    SocketHTTP_Headers_add (headers, "Sec-WebSocket-Version", "13");

    /* Set up the request structure */
    ((SocketHTTP_Request *)request)->method = HTTP_METHOD_GET;
    ((SocketHTTP_Request *)request)->headers = headers;
    ((SocketHTTP_Request *)request)->path = "/";
    ((SocketHTTP_Request *)request)->version = HTTP_VERSION_1_1;

    /* Accept the WebSocket upgrade */
    ws = SocketWS_server_accept (socket, (const SocketHTTP_Request *)request,
                                 &ws_config);

    if (ws)
      {
        /* Complete the handshake (sends 101 Switching Protocols) */
        if (perform_ws_handshake (&ws, &exception_occurred) < 0)
          {
            ws = NULL; /* Already freed by helper */
          }
      }
  }
  EXCEPT (SocketWS_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_SOCKET,
                      "WebSocket server accept failed");
    exception_occurred = 1;
  }
  EXCEPT (SocketWS_ProtocolError)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_WS_PROTOCOL,
                      "WebSocket protocol error during accept");
    exception_occurred = 1;
  }
  EXCEPT (Arena_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Memory allocation failed");
    exception_occurred = 1;
  }
  FINALLY
  {
    /* Clean up the temporary arena - the WebSocket has its own copy of
     * what it needs */
    if (arena)
      {
        Arena_dispose ((Arena_T *)&arena);
      }
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
      simple_set_error (SOCKET_SIMPLE_ERR_SOCKET, "WebSocket accept failed");
      return NULL;
    }

  /* Create the simple wrapper handle */
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

void
Socket_simple_ws_reject (void *http_req, int status, const char *reason)
{
  Socket_simple_clear_error ();

  if (!http_req)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "HTTP request is NULL");
      return;
    }

  /* Get the Simple API HTTP server request wrapper */
  SocketSimple_HTTPServerRequest_T simple_req
      = (SocketSimple_HTTPServerRequest_T)http_req;

  /* Access the core HTTP server request through the simple wrapper */
  SocketHTTPServer_Request_T core_req = simple_req->core_req;
  if (!core_req)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid HTTP server request");
      return;
    }

  /* Get the underlying connection and socket */
  ServerConnection *conn = core_req->conn;
  if (!conn || !conn->socket)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "HTTP connection has no socket");
      return;
    }

  /* Use SocketWS_server_reject to send rejection response */
  TRY { SocketWS_server_reject (conn->socket, status, reason); }
  EXCEPT (Socket_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_SEND,
                      "Failed to send rejection response");
  }
  END_TRY;
}
