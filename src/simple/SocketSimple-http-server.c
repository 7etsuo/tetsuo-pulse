/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketSimple-http-server.c
 * @brief Simple HTTP server implementation.
 *
 * Wraps the SocketHTTPServer module for return-code-based API.
 */

#include "SocketSimple-internal.h"
#include "simple/SocketSimple-http-server.h"

#include "http/SocketHTTPServer.h"

#include <stdio.h>
#include <string.h>

/* ============================================================================
 * Internal Structures
 * ============================================================================
 */

struct SocketSimple_HTTPServer
{
  SocketHTTPServer_T server;
  SocketSimple_HTTPServerHandler user_handler;
  void *user_handler_data;
  SocketSimple_HTTPServerValidator user_validator;
  void *user_validator_data;
  SocketSimple_HTTPServerDrainCallback user_drain_callback;
  void *user_drain_data;
};

/* Note: struct SocketSimple_HTTPServerRequest is defined in
 * SocketSimple-internal.h for cross-module access by WebSocket upgrade */

/* ============================================================================
 * Internal Callback Wrappers
 * ============================================================================
 */

static void
internal_handler_wrapper (SocketHTTPServer_Request_T core_req, void *userdata)
{
  struct SocketSimple_HTTPServer *server = userdata;
  if (!server || !server->user_handler)
    {
      /* No handler set - send 500 error */
      SocketHTTPServer_Request_status (core_req, 500);
      SocketHTTPServer_Request_body_string (core_req, "No handler configured");
      SocketHTTPServer_Request_finish (core_req);
      return;
    }

  /* Create wrapper request on stack */
  struct SocketSimple_HTTPServerRequest req_wrapper;
  req_wrapper.core_req = core_req;

  /* Call user handler */
  server->user_handler (&req_wrapper, server->user_handler_data);
}

static int
internal_validator_wrapper (SocketHTTPServer_Request_T core_req,
                            int *reject_status, void *userdata)
{
  struct SocketSimple_HTTPServer *server = userdata;
  if (!server || !server->user_validator)
    {
      return 1; /* Allow by default */
    }

  /* Create wrapper request on stack */
  struct SocketSimple_HTTPServerRequest req_wrapper;
  req_wrapper.core_req = core_req;

  return server->user_validator (&req_wrapper, reject_status,
                                 server->user_validator_data);
}

static void
internal_drain_callback_wrapper (SocketHTTPServer_T core_server, int timed_out,
                                 void *userdata)
{
  struct SocketSimple_HTTPServer *server = userdata;
  (void)core_server;

  if (server && server->user_drain_callback)
    {
      server->user_drain_callback (server, timed_out, server->user_drain_data);
    }
}

/* ============================================================================
 * Configuration
 * ============================================================================
 */

void
Socket_simple_http_server_config_init (SocketSimple_HTTPServerConfig *config)
{
  if (!config)
    return;

  memset (config, 0, sizeof (*config));
  config->port = 8080;
  config->bind_address = NULL;
  config->backlog = 128;
  config->max_header_size = 64 * 1024;
  config->max_body_size = 10 * 1024 * 1024;
  config->request_timeout_ms = 30000;
  config->keepalive_timeout_ms = 60000;
  config->max_connections = 1000;
  config->max_connections_per_client = 100;
  config->enable_tls = 0;
  config->tls_cert_file = NULL;
  config->tls_key_file = NULL;
}

/* ============================================================================
 * Server Lifecycle
 * ============================================================================
 */

SocketSimple_HTTPServer_T
Socket_simple_http_server_new (const char *host, int port)
{
  SocketSimple_HTTPServerConfig config;
  Socket_simple_http_server_config_init (&config);
  config.bind_address = host;
  config.port = port;
  return Socket_simple_http_server_new_ex (&config);
}

SocketSimple_HTTPServer_T
Socket_simple_http_server_new_ex (const SocketSimple_HTTPServerConfig *config)
{
  volatile SocketHTTPServer_T core_server = NULL;

  Socket_simple_clear_error ();

  if (!config)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Config is NULL");
      return NULL;
    }

  /* Allocate wrapper */
  struct SocketSimple_HTTPServer *server = calloc (1, sizeof (*server));
  if (!server)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Memory allocation failed");
      return NULL;
    }

  /* Build core config */
  SocketHTTPServer_Config core_config;
  SocketHTTPServer_config_defaults (&core_config);

  core_config.port = config->port;
  core_config.bind_address = config->bind_address;
  core_config.backlog = config->backlog;
  core_config.max_header_size = config->max_header_size;
  core_config.max_body_size = config->max_body_size;
  core_config.request_timeout_ms = config->request_timeout_ms;
  core_config.keepalive_timeout_ms = config->keepalive_timeout_ms;
  core_config.max_connections = config->max_connections;
  core_config.max_connections_per_client = config->max_connections_per_client;

  /* TLS configuration */
#ifdef SOCKET_HAS_TLS
  if (config->enable_tls)
    {
      if (!config->tls_cert_file || !config->tls_key_file)
        {
          free (server);
          simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                            "TLS enabled but cert/key files not provided");
          return NULL;
        }

      volatile SocketTLSContext_T tls_ctx = NULL;
      TRY
      {
        tls_ctx = SocketTLSContext_new_server (config->tls_cert_file,
                                               config->tls_key_file, NULL);
      }
      EXCEPT (SocketTLS_Failed)
      {
        free (server);
        simple_set_error (SOCKET_SIMPLE_ERR_TLS,
                          "Failed to create TLS context");
        return NULL;
      }
      END_TRY;

      core_config.tls_context = tls_ctx;
    }
#else
  if (config->enable_tls)
    {
      free (server);
      simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED,
                        "TLS not supported in this build");
      return NULL;
    }
#endif

  /* Create core server */
  TRY { core_server = SocketHTTPServer_new (&core_config); }
  EXCEPT (SocketHTTPServer_Failed)
  {
#ifdef SOCKET_HAS_TLS
    if (core_config.tls_context)
      {
        SocketTLSContext_free ((SocketTLSContext_T *)&core_config.tls_context);
      }
#endif
    free (server);
    simple_set_error (SOCKET_SIMPLE_ERR_SERVER,
                      "Failed to create HTTP server");
    return NULL;
  }
  END_TRY;

  server->server = core_server;
  server->user_handler = NULL;
  server->user_handler_data = NULL;
  server->user_validator = NULL;
  server->user_validator_data = NULL;
  server->user_drain_callback = NULL;
  server->user_drain_data = NULL;

  /* Set internal handler wrapper */
  SocketHTTPServer_set_handler (server->server, internal_handler_wrapper,
                                server);

  return server;
}

void
Socket_simple_http_server_free (SocketSimple_HTTPServer_T *server)
{
  if (!server || !*server)
    return;

  struct SocketSimple_HTTPServer *s = *server;

  if (s->server)
    {
      SocketHTTPServer_free (&s->server);
    }

  free (s);
  *server = NULL;
}

int
Socket_simple_http_server_start (SocketSimple_HTTPServer_T server)
{
  volatile int result = -1;

  Socket_simple_clear_error ();

  if (!server)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid server handle");
      return -1;
    }

  TRY { result = SocketHTTPServer_start (server->server); }
  EXCEPT (SocketHTTPServer_BindFailed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_BIND, "Failed to bind server socket");
    return -1;
  }
  EXCEPT (SocketHTTPServer_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_SERVER, "Failed to start server");
    return -1;
  }
  END_TRY;

  return result;
}

void
Socket_simple_http_server_stop (SocketSimple_HTTPServer_T server)
{
  if (!server)
    return;

  SocketHTTPServer_stop (server->server);
}

/* ============================================================================
 * Handler Registration
 * ============================================================================
 */

void
Socket_simple_http_server_set_handler (SocketSimple_HTTPServer_T server,
                                       SocketSimple_HTTPServerHandler handler,
                                       void *userdata)
{
  if (!server)
    return;

  server->user_handler = handler;
  server->user_handler_data = userdata;
}

void
Socket_simple_http_server_set_validator (
    SocketSimple_HTTPServer_T server,
    SocketSimple_HTTPServerValidator validator, void *userdata)
{
  if (!server)
    return;

  server->user_validator = validator;
  server->user_validator_data = userdata;

  if (validator)
    {
      SocketHTTPServer_set_validator (server->server,
                                      internal_validator_wrapper, server);
    }
  else
    {
      SocketHTTPServer_set_validator (server->server, NULL, NULL);
    }
}

/* ============================================================================
 * Event Loop
 * ============================================================================
 */

int
Socket_simple_http_server_poll (SocketSimple_HTTPServer_T server,
                                int timeout_ms)
{
  volatile int result = -1;

  Socket_simple_clear_error ();

  if (!server)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid server handle");
      return -1;
    }

  TRY { result = SocketHTTPServer_process (server->server, timeout_ms); }
  EXCEPT (SocketHTTPServer_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_SERVER, "Server processing failed");
    return -1;
  }
  END_TRY;

  return result;
}

int
Socket_simple_http_server_fd (SocketSimple_HTTPServer_T server)
{
  if (!server)
    return -1;

  return SocketHTTPServer_fd (server->server);
}

/* ============================================================================
 * Request Accessors
 * ============================================================================
 */

const char *
Socket_simple_http_server_request_method (SocketSimple_HTTPServerRequest_T req)
{
  if (!req || !req->core_req)
    return NULL;

  SocketHTTP_Method method = SocketHTTPServer_Request_method (req->core_req);
  return SocketHTTP_method_name (method);
}

const char *
Socket_simple_http_server_request_path (SocketSimple_HTTPServerRequest_T req)
{
  if (!req || !req->core_req)
    return NULL;

  return SocketHTTPServer_Request_path (req->core_req);
}

const char *
Socket_simple_http_server_request_query (SocketSimple_HTTPServerRequest_T req)
{
  if (!req || !req->core_req)
    return NULL;

  return SocketHTTPServer_Request_query (req->core_req);
}

const char *
Socket_simple_http_server_request_header (SocketSimple_HTTPServerRequest_T req,
                                          const char *name)
{
  if (!req || !req->core_req || !name)
    return NULL;

  SocketHTTP_Headers_T headers
      = SocketHTTPServer_Request_headers (req->core_req);
  if (!headers)
    return NULL;

  return SocketHTTP_Headers_get (headers, name);
}

const void *
Socket_simple_http_server_request_body (SocketSimple_HTTPServerRequest_T req,
                                        size_t *len)
{
  if (!req || !req->core_req)
    {
      if (len)
        *len = 0;
      return NULL;
    }

  const void *body = SocketHTTPServer_Request_body (req->core_req);
  if (len)
    {
      *len = SocketHTTPServer_Request_body_len (req->core_req);
    }

  return body;
}

const char *
Socket_simple_http_server_request_client_addr (
    SocketSimple_HTTPServerRequest_T req)
{
  if (!req || !req->core_req)
    return NULL;

  return SocketHTTPServer_Request_client_addr (req->core_req);
}

int
Socket_simple_http_server_request_is_http2 (
    SocketSimple_HTTPServerRequest_T req)
{
  if (!req || !req->core_req)
    return 0;

  return SocketHTTPServer_Request_is_http2 (req->core_req);
}

/* ============================================================================
 * Response Building
 * ============================================================================
 */

void
Socket_simple_http_server_response_status (
    SocketSimple_HTTPServerRequest_T req, int code)
{
  if (!req || !req->core_req)
    return;

  SocketHTTPServer_Request_status (req->core_req, code);
}

void
Socket_simple_http_server_response_header (
    SocketSimple_HTTPServerRequest_T req, const char *name, const char *value)
{
  if (!req || !req->core_req || !name || !value)
    return;

  SocketHTTPServer_Request_header (req->core_req, name, value);
}

void
Socket_simple_http_server_response_body (SocketSimple_HTTPServerRequest_T req,
                                         const void *data, size_t len)
{
  if (!req || !req->core_req)
    return;

  SocketHTTPServer_Request_body_data (req->core_req, data, len);
}

void
Socket_simple_http_server_response_body_string (
    SocketSimple_HTTPServerRequest_T req, const char *str)
{
  if (!req || !req->core_req)
    return;

  SocketHTTPServer_Request_body_string (req->core_req, str);
}

void
Socket_simple_http_server_response_finish (
    SocketSimple_HTTPServerRequest_T req)
{
  if (!req || !req->core_req)
    return;

  SocketHTTPServer_Request_finish (req->core_req);
}

/* ============================================================================
 * JSON Convenience
 * ============================================================================
 */

/**
 * json_escape_string - Escape a string for safe JSON insertion
 * @dest: Destination buffer for escaped string
 * @dest_size: Size of destination buffer
 * @src: Source string to escape (may be NULL)
 *
 * Escapes special JSON characters per RFC 8259 Section 7:
 * - Quotation mark (U+0022)
 * - Reverse solidus (U+005C)
 * - Control characters (U+0000 through U+001F)
 *
 * Prevents JSON injection attacks by ensuring user input cannot break
 * JSON structure or inject malicious fields.
 *
 * NOTE: Not static to allow testing. This is an internal implementation
 * detail and should not be used directly by library users.
 */
void
json_escape_string (char *dest, size_t dest_size, const char *src)
{
  size_t i = 0;

  if (dest_size == 0)
    return;

  if (!src)
    {
      dest[0] = '\0';
      return;
    }

  while (*src && i < dest_size - 1)
    {
      unsigned char c = (unsigned char)*src;

      if (c == '\"' && i < dest_size - 2)
        {
          dest[i++] = '\\';
          dest[i++] = '\"';
        }
      else if (c == '\\' && i < dest_size - 2)
        {
          dest[i++] = '\\';
          dest[i++] = '\\';
        }
      else if (c == '\b' && i < dest_size - 2)
        {
          dest[i++] = '\\';
          dest[i++] = 'b';
        }
      else if (c == '\f' && i < dest_size - 2)
        {
          dest[i++] = '\\';
          dest[i++] = 'f';
        }
      else if (c == '\n' && i < dest_size - 2)
        {
          dest[i++] = '\\';
          dest[i++] = 'n';
        }
      else if (c == '\r' && i < dest_size - 2)
        {
          dest[i++] = '\\';
          dest[i++] = 'r';
        }
      else if (c == '\t' && i < dest_size - 2)
        {
          dest[i++] = '\\';
          dest[i++] = 't';
        }
      else if (c < 0x20)
        {
          /* Escape other control characters as \uXXXX */
          int written = snprintf (&dest[i], dest_size - i, "\\u%04x", c);
          if (written > 0 && (size_t)written < dest_size - i)
            {
              i += written;
            }
          else
            {
              break; /* Not enough space */
            }
        }
      else
        {
          dest[i++] = c;
        }

      src++;
    }

  dest[i] = '\0';
}

void
Socket_simple_http_server_response_json (SocketSimple_HTTPServerRequest_T req,
                                         int status, const char *json)
{
  if (!req || !req->core_req)
    return;

  SocketHTTPServer_Request_status (req->core_req, status);
  SocketHTTPServer_Request_header (req->core_req, "Content-Type",
                                   "application/json");
  if (json)
    {
      SocketHTTPServer_Request_body_string (req->core_req, json);
    }
  SocketHTTPServer_Request_finish (req->core_req);
}

void
Socket_simple_http_server_response_error (SocketSimple_HTTPServerRequest_T req,
                                          int status, const char *message)
{
  char json[512];
  char escaped[256];

  if (!req || !req->core_req)
    return;

  json_escape_string (escaped, sizeof (escaped), message);
  snprintf (json, sizeof (json), "{\"error\":\"%s\"}", escaped);

  Socket_simple_http_server_response_json (req, status, json);
}

/* ============================================================================
 * Streaming Responses
 * ============================================================================
 */

int
Socket_simple_http_server_response_begin_stream (
    SocketSimple_HTTPServerRequest_T req)
{
  if (!req || !req->core_req)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid request handle");
      return -1;
    }

  return SocketHTTPServer_Request_begin_stream (req->core_req);
}

int
Socket_simple_http_server_response_send_chunk (
    SocketSimple_HTTPServerRequest_T req, const void *data, size_t len)
{
  if (!req || !req->core_req)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid request handle");
      return -1;
    }

  return SocketHTTPServer_Request_send_chunk (req->core_req, data, len);
}

int
Socket_simple_http_server_response_end_stream (
    SocketSimple_HTTPServerRequest_T req)
{
  if (!req || !req->core_req)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid request handle");
      return -1;
    }

  return SocketHTTPServer_Request_end_stream (req->core_req);
}

/* ============================================================================
 * Graceful Shutdown
 * ============================================================================
 */

int
Socket_simple_http_server_drain (SocketSimple_HTTPServer_T server,
                                 int timeout_ms)
{
  Socket_simple_clear_error ();

  if (!server)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid server handle");
      return -1;
    }

  return SocketHTTPServer_drain (server->server, timeout_ms);
}

int
Socket_simple_http_server_drain_poll (SocketSimple_HTTPServer_T server)
{
  if (!server)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid server handle");
      return -1;
    }

  return SocketHTTPServer_drain_poll (server->server);
}

int
Socket_simple_http_server_drain_wait (SocketSimple_HTTPServer_T server,
                                      int timeout_ms)
{
  Socket_simple_clear_error ();

  if (!server)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid server handle");
      return -1;
    }

  return SocketHTTPServer_drain_wait (server->server, timeout_ms);
}

void
Socket_simple_http_server_set_drain_callback (
    SocketSimple_HTTPServer_T server,
    SocketSimple_HTTPServerDrainCallback callback, void *userdata)
{
  if (!server)
    return;

  server->user_drain_callback = callback;
  server->user_drain_data = userdata;

  if (callback)
    {
      SocketHTTPServer_set_drain_callback (
          server->server, internal_drain_callback_wrapper, server);
    }
  else
    {
      SocketHTTPServer_set_drain_callback (server->server, NULL, NULL);
    }
}

SocketSimple_HTTPServerState
Socket_simple_http_server_state (SocketSimple_HTTPServer_T server)
{
  if (!server)
    return SOCKET_SIMPLE_SERVER_STOPPED;

  SocketHTTPServer_State state = SocketHTTPServer_state (server->server);

  switch (state)
    {
    case HTTPSERVER_STATE_RUNNING:
      return SOCKET_SIMPLE_SERVER_RUNNING;
    case HTTPSERVER_STATE_DRAINING:
      return SOCKET_SIMPLE_SERVER_DRAINING;
    case HTTPSERVER_STATE_STOPPED:
    default:
      return SOCKET_SIMPLE_SERVER_STOPPED;
    }
}

/* ============================================================================
 * Statistics
 * ============================================================================
 */

int
Socket_simple_http_server_get_stats (SocketSimple_HTTPServer_T server,
                                     SocketSimple_HTTPServerStats *stats)
{
  Socket_simple_clear_error ();

  if (!server || !stats)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid server or stats");
      return -1;
    }

  SocketHTTPServer_Stats core_stats;
  SocketHTTPServer_stats (server->server, &core_stats);

  stats->active_connections = core_stats.active_connections;
  stats->total_connections = core_stats.total_connections;
  stats->connections_rejected = core_stats.connections_rejected;
  stats->total_requests = core_stats.total_requests;
  stats->total_bytes_sent = core_stats.total_bytes_sent;
  stats->total_bytes_received = core_stats.total_bytes_received;
  stats->errors_4xx = core_stats.errors_4xx;
  stats->errors_5xx = core_stats.errors_5xx;
  stats->timeouts = core_stats.timeouts;
  stats->rate_limited = core_stats.rate_limited;
  stats->avg_request_time_us = core_stats.avg_request_time_us;
  stats->max_request_time_us = core_stats.max_request_time_us;

  return 0;
}

int
Socket_simple_http_server_connection_count (SocketSimple_HTTPServer_T server)
{
  if (!server)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid server handle");
      return -1;
    }

  SocketHTTPServer_Stats stats;
  SocketHTTPServer_stats (server->server, &stats);

  return (int)stats.active_connections;
}
