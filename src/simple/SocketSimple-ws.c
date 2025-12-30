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
  opts->connect_timeout_ms = SOCKET_SIMPLE_DEFAULT_TIMEOUT_MS;
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
 * @brief Common exception handling wrapper for WebSocket send operations.
 *
 * This macro implements the standard pattern for Simple API WebSocket send
 * functions, eliminating code duplication across send_text, send_binary,
 * send_json, and ping.
 *
 * @param data_check Additional validation check (e.g., "|| !text")
 * @param invalid_msg Error message for invalid arguments
 * @param ws_call The SocketWS_* function call to execute
 * @param op_name Operation name for error messages (e.g., "send", "ping")
 */
#define WS_SEND_WRAPPER(data_check, invalid_msg, ws_call, op_name)            \
  do                                                                           \
    {                                                                          \
      volatile int ret = -1;                                                   \
      volatile int exception_occurred = 0;                                     \
                                                                               \
      Socket_simple_clear_error ();                                            \
                                                                               \
      if (!ws || !ws->ws data_check)                                           \
        {                                                                      \
          simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, invalid_msg);       \
          return -1;                                                           \
        }                                                                      \
                                                                               \
      TRY { ret = ws_call; }                                                   \
      EXCEPT (SocketWS_Failed)                                                 \
      {                                                                        \
        simple_set_error (SOCKET_SIMPLE_ERR_SEND,                              \
                          "WebSocket " op_name " failed");                     \
        exception_occurred = 1;                                                \
      }                                                                        \
      EXCEPT (SocketWS_Closed)                                                 \
      {                                                                        \
        simple_set_error (SOCKET_SIMPLE_ERR_CLOSED,                            \
                          "WebSocket connection closed");                      \
        exception_occurred = 1;                                                \
      }                                                                        \
      END_TRY;                                                                 \
                                                                               \
      if (exception_occurred)                                                  \
        return -1;                                                             \
                                                                               \
      if (ret != 0)                                                            \
        {                                                                      \
          simple_set_error (SOCKET_SIMPLE_ERR_SEND,                            \
                            "WebSocket " op_name " failed");                   \
          return -1;                                                           \
        }                                                                      \
                                                                               \
      return 0;                                                                \
    }                                                                          \
  while (0)

int
Socket_simple_ws_send_text (SocketSimple_WS_T ws, const char *text, size_t len)
{
  WS_SEND_WRAPPER (|| !text, "Invalid argument",
                   SocketWS_send_text (ws->ws, text, len), "send");
}

int
Socket_simple_ws_send_binary (SocketSimple_WS_T ws, const void *data,
                              size_t len)
{
  WS_SEND_WRAPPER (|| !data, "Invalid argument",
                   SocketWS_send_binary (ws->ws, data, len), "send");
}

int
Socket_simple_ws_send_json (SocketSimple_WS_T ws, const char *json)
{
  WS_SEND_WRAPPER (|| !json, "Invalid argument",
                   SocketWS_send_json (ws->ws, json), "send");
}

int
Socket_simple_ws_ping (SocketSimple_WS_T ws)
{
  WS_SEND_WRAPPER (/* no extra check */, "Invalid WebSocket",
                   SocketWS_ping (ws->ws, NULL, 0), "ping");
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

/**
 * @brief Copy WebSocket close information to a Simple API message.
 *
 * Extracts the close code and reason from the WebSocket and populates
 * the Simple API message structure. Handles strdup failure gracefully
 * since the close event is more important than preserving the reason.
 *
 * @param ws WebSocket connection
 * @param msg Message structure to populate
 */
static void
copy_ws_close_info (SocketSimple_WS_T ws, SocketSimple_WSMessage *msg)
{
  msg->type = SOCKET_SIMPLE_WS_CLOSE;
  msg->close_code = SocketWS_close_code (ws->ws);

  const char *reason = SocketWS_close_reason (ws->ws);
  if (reason)
    {
      msg->close_reason = strdup (reason);
      /* If strdup fails, msg->close_reason will be NULL
       * Caller can still handle close event */
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
    copy_ws_close_info (ws, msg);
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
      copy_ws_close_info (ws, msg);
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
 * @brief Build a minimal HTTP request structure for WebSocket upgrade.
 *
 * Creates a fake HTTP request with the required headers for WebSocket
 * upgrade acceptance. The request is allocated in the provided arena.
 *
 * @param arena Arena for memory allocation
 * @param ws_key WebSocket key from client handshake
 * @return Pointer to the constructed request, or NULL on failure
 */
static SocketHTTP_Request *
build_fake_ws_request (Arena_T arena, const char *ws_key)
{
  SocketHTTP_Request *request;
  SocketHTTP_Headers_T headers;

  /* Allocate and zero the request structure */
  request = Arena_alloc (arena, sizeof (SocketHTTP_Request), __FILE__, __LINE__);
  memset (request, 0, sizeof (SocketHTTP_Request));

  /* Create headers container */
  headers = SocketHTTP_Headers_new (arena);

  /* Add required WebSocket upgrade headers */
  SocketHTTP_Headers_add (headers, "Upgrade", "websocket");
  SocketHTTP_Headers_add (headers, "Connection", "Upgrade");
  SocketHTTP_Headers_add (headers, "Sec-WebSocket-Key", ws_key);
  SocketHTTP_Headers_add (headers, "Sec-WebSocket-Version", "13");

  /* Set up the request structure */
  request->method = HTTP_METHOD_GET;
  request->headers = headers;
  request->path = "/";
  request->version = HTTP_VERSION_1_1;

  return request;
}

/**
 * @brief Complete the WebSocket handshake.
 *
 * Performs the handshake loop until completion or failure.
 * On failure, sets an appropriate error and cleans up the WebSocket.
 *
 * @param ws WebSocket instance (volatile pointer)
 * @param exception_occurred Pointer to exception flag (volatile)
 * @return 0 on success, -1 on failure
 */
static int
perform_ws_handshake (volatile SocketWS_T *ws, volatile int *exception_occurred)
{
  int handshake_result;

  if (!*ws)
    return -1;

  /* Complete the handshake (sends 101 Switching Protocols) */
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

/**
 * @brief Create a Simple API WebSocket handle from a core WebSocket.
 *
 * Allocates and initializes a Simple API wrapper handle.
 * On failure, frees the WebSocket and sets an error.
 *
 * @param ws Core WebSocket instance
 * @return Simple API handle, or NULL on failure
 */
static struct SocketSimple_WS *
create_simple_ws_handle (SocketWS_T ws)
{
  struct SocketSimple_WS *handle;

  if (!ws)
    return NULL;

  handle = calloc (1, sizeof (*handle));
  if (!handle)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Memory allocation failed");
      SocketWS_free (&ws);
      return NULL;
    }

  handle->ws = ws;
  return handle;
}

SocketSimple_WS_T
Socket_simple_ws_accept (void *http_req,
                         const SocketSimple_WSServerConfig *config)
{
  volatile SocketWS_T ws = NULL;
  volatile int exception_occurred = 0;
  struct SocketSimple_WS *handle = NULL;
  SocketWS_Config ws_config;
  SocketSimple_HTTPServerRequest_T simple_req;
  SocketHTTPServer_Request_T core_req;
  ServerConnection *conn;
  const SocketHTTP_Request *request;

  Socket_simple_clear_error ();

  if (!http_req)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "HTTP request is NULL");
      return NULL;
    }

  /* Get the Simple API HTTP server request wrapper */
  simple_req = (SocketSimple_HTTPServerRequest_T)http_req;

  /* Access the core HTTP server request through the simple wrapper */
  core_req = simple_req->core_req;
  if (!core_req)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid HTTP server request");
      return NULL;
    }

  /* Get the underlying connection and socket */
  conn = core_req->conn;
  if (!conn || !conn->socket)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "HTTP connection has no socket");
      return NULL;
    }

  /* Get the parsed HTTP request */
  request = conn->request;
  if (!request)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "HTTP request not parsed");
      return NULL;
    }

  convert_ws_server_config (config, &ws_config);

  TRY
  {
    /* Accept the WebSocket upgrade */
    ws = SocketWS_server_accept (conn->socket, request, &ws_config);

    /* Complete the handshake */
    if (ws)
      perform_ws_handshake (&ws, &exception_occurred);
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
      SocketWS_free ((SocketWS_T *)&ws);
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
  handle = create_simple_ws_handle (ws);
  if (!handle)
    return NULL;

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
  volatile Arena_T arena = NULL;
  SocketWS_Config ws_config;
  Socket_T socket;

  Socket_simple_clear_error ();

  /* Validate arguments */
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

  socket = (Socket_T)sock;
  convert_ws_server_config (config, &ws_config);

  TRY
  {
    SocketHTTP_Request *request;

    /* Create temporary arena for the fake HTTP request */
    arena = Arena_new ();

    /* Build minimal HTTP request structure for WebSocket upgrade */
    request = build_fake_ws_request (arena, ws_key);

    /* Accept the WebSocket upgrade */
    ws = SocketWS_server_accept (socket, request, &ws_config);

    /* Complete the handshake */
    if (ws)
      perform_ws_handshake (&ws, &exception_occurred);
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
    /* Clean up temporary arena - WebSocket has its own copy */
    if (arena)
      Arena_dispose ((Arena_T *)&arena);

    if (exception_occurred && ws)
      SocketWS_free ((SocketWS_T *)&ws);
  }
  END_TRY;

  if (exception_occurred)
    return NULL;

  if (!ws)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_SOCKET, "WebSocket accept failed");
      return NULL;
    }

  return create_simple_ws_handle (ws);
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
