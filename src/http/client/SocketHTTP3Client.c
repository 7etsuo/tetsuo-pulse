/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTP3Client.c
 * @brief HTTP/3 client implementation (RFC 9114).
 *
 * Wraps SocketQUICTransport_T and SocketHTTP3_Conn_T into a user-facing
 * HTTP/3 client API. The output queue model bridges H3 framing with
 * QUIC transport: H3 generates wire data -> flush sends via transport ->
 * transport delivers received data back to H3 via stream callback.
 */

#ifdef SOCKET_HAS_TLS

#include "http/SocketHTTP3-client.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "core/Arena.h"
#include "http/SocketHTTP3-private.h"
#include "quic/SocketQUICTransport.h"

#define H3_CLIENT_RESP_BUF_INIT 4096

struct SocketHTTP3_Client
{
  Arena_T arena;
  SocketHTTP3_ClientConfig config;

  /* QUIC transport */
  SocketQUICTransport_T transport;

  /* HTTP/3 connection */
  SocketHTTP3_Conn_T h3_conn;

  /* State */
  char *connected_host;
  int connected_port;
  int connected;
};

static uint64_t
now_us (void)
{
  struct timespec ts;
  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

static int
flush_h3_output (SocketHTTP3_Client_T client)
{
  size_t count = SocketHTTP3_Conn_output_count (client->h3_conn);
  for (size_t i = 0; i < count; i++)
    {
      const SocketHTTP3_Output *entry
          = SocketHTTP3_Conn_get_output (client->h3_conn, i);
      if (!entry)
        continue;
      if (SocketQUICTransport_send_stream (
              client->transport, entry->stream_id, entry->data, entry->len, 0)
          < 0)
        {
          SocketHTTP3_Conn_drain_output (client->h3_conn);
          return -1;
        }
    }
  SocketHTTP3_Conn_drain_output (client->h3_conn);
  return 0;
}

static void
h3_stream_callback (uint64_t stream_id,
                    const uint8_t *data,
                    size_t len,
                    int fin,
                    void *userdata)
{
  SocketHTTP3_Client_T client = userdata;
  if (!client || !client->h3_conn)
    return;

  SocketHTTP3_Conn_feed_stream (client->h3_conn, stream_id, data, len, fin);
  flush_h3_output (client);
}

void
SocketHTTP3_ClientConfig_defaults (SocketHTTP3_ClientConfig *config)
{
  if (!config)
    return;
  memset (config, 0, sizeof (*config));
  config->idle_timeout_ms = 30000;
  config->max_stream_data = 262144;
  config->initial_max_streams_bidi = 100;
  SocketHTTP3_Settings_init (&config->h3_settings);
  config->ca_file = NULL;
  config->verify_peer = 1;
  config->connect_timeout_ms = 5000;
  config->request_timeout_ms = 30000;
}

SocketHTTP3_Client_T
SocketHTTP3_Client_new (Arena_T arena, const SocketHTTP3_ClientConfig *config)
{
  if (!arena)
    return NULL;

  SocketHTTP3_Client_T client
      = Arena_alloc (arena, sizeof (*client), __FILE__, __LINE__);
  memset (client, 0, sizeof (*client));
  client->arena = arena;

  if (config)
    client->config = *config;
  else
    SocketHTTP3_ClientConfig_defaults (&client->config);

  /* Create QUIC transport */
  SocketQUICTransportConfig transport_config;
  SocketQUICTransportConfig_defaults (&transport_config);
  transport_config.idle_timeout_ms = client->config.idle_timeout_ms;
  transport_config.max_stream_data = client->config.max_stream_data;
  transport_config.initial_max_streams_bidi
      = client->config.initial_max_streams_bidi;
  transport_config.connect_timeout_ms = client->config.connect_timeout_ms;
  transport_config.ca_file = client->config.ca_file;
  transport_config.verify_peer = client->config.verify_peer;

  client->transport = SocketQUICTransport_new (arena, &transport_config);
  if (!client->transport)
    return NULL;

  /* Create H3 connection */
  SocketHTTP3_ConnConfig h3_config;
  SocketHTTP3_ConnConfig_defaults (&h3_config, H3_ROLE_CLIENT);
  h3_config.local_settings = client->config.h3_settings;

  client->h3_conn = SocketHTTP3_Conn_new (arena, NULL, &h3_config);
  if (!client->h3_conn)
    return NULL;

  /* Set stream callback on transport pointing to h3_stream_callback */
  SocketQUICTransport_set_stream_callback (
      client->transport, h3_stream_callback, client);

  return client;
}

int
SocketHTTP3_Client_connect (SocketHTTP3_Client_T client,
                            const char *host,
                            int port)
{
  if (!client || !host || client->connected)
    return -1;

  /* Blocking QUIC handshake */
  if (SocketQUICTransport_connect (client->transport, host, port) < 0)
    return -1;

  /* Initialize H3 connection (opens critical streams, sends SETTINGS) */
  if (SocketHTTP3_Conn_init (client->h3_conn) < 0)
    return -1;

  /* Flush H3 output (SETTINGS on control stream, type bytes on all) */
  if (flush_h3_output (client) < 0)
    return -1;

  /* Store connection info */
  size_t host_len = strlen (host);
  client->connected_host
      = Arena_alloc (client->arena, host_len + 1, __FILE__, __LINE__);
  memcpy (client->connected_host, host, host_len + 1);
  client->connected_port = port;
  client->connected = 1;

  return 0;
}

int
SocketHTTP3_Client_close (SocketHTTP3_Client_T client)
{
  if (!client)
    return -1;

  if (client->connected && client->h3_conn)
    {
      /* Send GOAWAY */
      SocketHTTP3_Conn_shutdown (client->h3_conn, UINT64_MAX);
      flush_h3_output (client);
    }

  /* Close QUIC transport */
  if (client->transport)
    SocketQUICTransport_close (client->transport);

  client->connected = 0;
  return 0;
}

int
SocketHTTP3_Client_request (SocketHTTP3_Client_T client,
                            SocketHTTP_Method method,
                            const char *path,
                            const SocketHTTP_Headers_T headers,
                            const void *body,
                            size_t body_len,
                            SocketHTTP_Headers_T *resp_headers,
                            int *status_code,
                            void **resp_body,
                            size_t *resp_body_len)
{
  if (!client || !client->connected || !path)
    return -1;

  /* Create request */
  SocketHTTP3_Request_T req = SocketHTTP3_Request_new (client->h3_conn);
  if (!req)
    return -1;

  /* Build request headers with pseudo-headers */
  SocketHTTP_Headers_T req_headers = SocketHTTP_Headers_new (client->arena);
  if (!req_headers)
    return -1;

  const char *method_str = SocketHTTP_method_name (method);
  if (!method_str)
    method_str = "GET";

  SocketHTTP_Headers_add (req_headers, ":method", method_str);
  SocketHTTP_Headers_add (req_headers, ":scheme", "https");

  /* Build :authority from connected host and port */
  char authority[256];
  if (client->connected_port == 443)
    snprintf (authority, sizeof (authority), "%s", client->connected_host);
  else
    snprintf (authority,
              sizeof (authority),
              "%s:%d",
              client->connected_host,
              client->connected_port);
  SocketHTTP_Headers_add (req_headers, ":authority", authority);
  SocketHTTP_Headers_add (req_headers, ":path", path);

  /* Copy caller-supplied headers (skip pseudo-headers) */
  if (headers)
    {
      size_t count = SocketHTTP_Headers_count (headers);
      for (size_t i = 0; i < count; i++)
        {
          const SocketHTTP_Header *h = SocketHTTP_Headers_at (headers, i);
          if (h && h->name && h->name[0] != ':')
            SocketHTTP_Headers_add_n (
                req_headers, h->name, h->name_len, h->value, h->value_len);
        }
    }

  /* Send HEADERS */
  int end_stream = (!body || body_len == 0) ? 1 : 0;
  if (SocketHTTP3_Request_send_headers (req, req_headers, end_stream) < 0)
    return -1;
  if (flush_h3_output (client) < 0)
    return -1;

  /* Send DATA if present */
  if (body && body_len > 0)
    {
      if (SocketHTTP3_Request_send_data (req, body, body_len, 1) < 0)
        return -1;
      if (flush_h3_output (client) < 0)
        return -1;
    }

  /* Poll for response */
  uint64_t deadline_us
      = now_us () + (uint64_t)client->config.request_timeout_ms * 1000;

  while (SocketHTTP3_Request_recv_state (req) != H3_REQ_RECV_COMPLETE)
    {
      uint64_t current = now_us ();
      if (current >= deadline_us)
        return -1;

      int remaining_ms = (int)((deadline_us - current) / 1000);
      if (remaining_ms <= 0)
        remaining_ms = 1;

      int events = SocketQUICTransport_poll (client->transport, remaining_ms);
      if (events < 0)
        return -1;
    }

  /* Extract response headers */
  if (resp_headers || status_code)
    {
      SocketHTTP_Headers_T hdrs = NULL;
      int code = 0;
      if (SocketHTTP3_Request_recv_headers (req, &hdrs, &code) == 0)
        {
          if (resp_headers)
            *resp_headers = hdrs;
          if (status_code)
            *status_code = code;
        }
      else
        {
          if (resp_headers)
            *resp_headers = NULL;
          if (status_code)
            *status_code = 0;
        }
    }

  /* Extract response body */
  if (resp_body && resp_body_len)
    {
      size_t buf_cap = H3_CLIENT_RESP_BUF_INIT;
      uint8_t *buf = Arena_alloc (client->arena, buf_cap, __FILE__, __LINE__);
      size_t total = 0;
      int end = 0;

      while (!end)
        {
          ssize_t n = SocketHTTP3_Request_recv_data (
              req, buf + total, buf_cap - total, &end);
          if (n < 0)
            break;
          total += (size_t)n;
          if (n == 0)
            break;

          /* Grow buffer if needed */
          if (total >= buf_cap && !end)
            {
              size_t new_cap = buf_cap * 2;
              uint8_t *new_buf
                  = Arena_alloc (client->arena, new_cap, __FILE__, __LINE__);
              memcpy (new_buf, buf, total);
              buf = new_buf;
              buf_cap = new_cap;
            }
        }

      *resp_body = buf;
      *resp_body_len = total;
    }

  return 0;
}

SocketHTTP3_Request_T
SocketHTTP3_Client_new_request (SocketHTTP3_Client_T client)
{
  if (!client || !client->connected || !client->h3_conn)
    return NULL;
  return SocketHTTP3_Request_new (client->h3_conn);
}

int
SocketHTTP3_Client_flush (SocketHTTP3_Client_T client)
{
  if (!client || !client->connected)
    return -1;
  return flush_h3_output (client);
}

int
SocketHTTP3_Client_poll (SocketHTTP3_Client_T client, int timeout_ms)
{
  if (!client || !client->connected || !client->transport)
    return -1;
  return SocketQUICTransport_poll (client->transport, timeout_ms);
}

SocketHTTP3_Conn_T
SocketHTTP3_Client_conn (SocketHTTP3_Client_T client)
{
  if (!client)
    return NULL;
  return client->h3_conn;
}

int
SocketHTTP3_Client_is_connected (SocketHTTP3_Client_T client)
{
  return client && client->connected;
}

uint16_t
SocketHTTP3_parse_alt_svc (const char *alt_svc_value,
                           char *host_out,
                           size_t host_len)
{
  if (!alt_svc_value)
    return 0;

  /* Look for h3="[host:]port" or h3=":port" */
  const char *p = alt_svc_value;
  while (*p)
    {
      /* Skip whitespace and commas */
      while (*p == ' ' || *p == '\t' || *p == ',')
        p++;

      /* Check for h3= */
      if (strncmp (p, "h3=\"", 4) == 0)
        {
          p += 4;

          /* Parse host:port or :port */
          const char *start = p;
          const char *colon = NULL;
          while (*p && *p != '"')
            {
              if (*p == ':')
                colon = p;
              p++;
            }

          if (!colon || *p != '"')
            return 0;

          /* Extract port */
          uint16_t port = 0;
          const char *port_str = colon + 1;
          while (port_str < p)
            {
              if (*port_str < '0' || *port_str > '9')
                return 0;
              port = (uint16_t)(port * 10 + (*port_str - '0'));
              port_str++;
            }

          if (port == 0)
            return 0;

          /* Extract host if present (before the last colon) */
          if (host_out && host_len > 0)
            {
              size_t hlen = (size_t)(colon - start);
              if (hlen > 0 && hlen < host_len)
                {
                  memcpy (host_out, start, hlen);
                  host_out[hlen] = '\0';
                }
              else
                {
                  host_out[0] = '\0';
                }
            }

          return port;
        }

      /* Skip to next entry */
      while (*p && *p != ',')
        p++;
    }

  return 0;
}

#endif /* SOCKET_HAS_TLS */
