/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* SocketHTTP2-connection.c - HTTP/2 Connection Management (RFC 9113) */

#include "http/SocketHTTP2-private.h"
#include "http/SocketHTTP2.h"

#include "core/SocketCrypto.h"
#include "core/SocketUtil.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"
#include "core/TimeWindow.h"

#include <assert.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <string.h>

const Except_T SocketHTTP2 = { NULL, "HTTP/2" };

const Except_T SocketHTTP2_Failed = { &SocketHTTP2, "HTTP/2 operation failed" };

const Except_T SocketHTTP2_ProtocolError
    = { &SocketHTTP2, "HTTP/2 protocol error" };

const Except_T SocketHTTP2_StreamError
    = { &SocketHTTP2, "HTTP/2 stream error" };

const Except_T SocketHTTP2_FlowControlError
    = { &SocketHTTP2, "HTTP/2 flow control error" };

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "HTTP2"

SOCKET_DECLARE_MODULE_EXCEPTION (SocketHTTP2);

void
SocketHTTP2_config_defaults (SocketHTTP2_Config *config, SocketHTTP2_Role role)
{
  assert (config);

  memset (config, 0, sizeof (*config));

  config->role = role;

  /* RFC 9113 Section 6.5.2 default values */
  config->header_table_size = SOCKETHTTP2_DEFAULT_HEADER_TABLE_SIZE;
  config->enable_push
      = (role == HTTP2_ROLE_SERVER) ? SOCKETHTTP2_DEFAULT_ENABLE_PUSH : 0;
  config->max_concurrent_streams = SOCKETHTTP2_DEFAULT_MAX_CONCURRENT_STREAMS;
  config->initial_window_size = SOCKETHTTP2_DEFAULT_INITIAL_WINDOW_SIZE;
  config->max_frame_size = SOCKETHTTP2_DEFAULT_MAX_FRAME_SIZE;
  config->max_header_list_size = SOCKETHTTP2_DEFAULT_MAX_HEADER_LIST_SIZE;
  config->enable_connect_protocol = 0; /* RFC 8441: disabled by default */

  /* Security defaults for rate limiting */
  config->max_stream_open_rate = 100; /* streams/sec */
  config->max_stream_open_burst = 10;
  config->max_stream_close_rate = 200; /* closes/sec, higher as natural */
  config->max_stream_close_burst = 20;

  /* Sliding window stream rate limiting (CVE-2023-44487 protection) */
  config->stream_window_size_ms = SOCKETHTTP2_STREAM_WINDOW_SIZE_MS;
  config->stream_max_per_window = SOCKETHTTP2_STREAM_MAX_PER_WINDOW;
  config->stream_burst_threshold = SOCKETHTTP2_STREAM_BURST_THRESHOLD;
  config->stream_burst_interval_ms = SOCKETHTTP2_STREAM_BURST_INTERVAL_MS;
  config->stream_churn_threshold = SOCKETHTTP2_STREAM_CHURN_THRESHOLD;

  config->connection_window_size = SOCKETHTTP2_CONNECTION_WINDOW_SIZE;

  /* Default timeouts */
  config->settings_timeout_ms = SOCKETHTTP2_DEFAULT_SETTINGS_TIMEOUT_MS;
  config->ping_timeout_ms = SOCKETHTTP2_DEFAULT_PING_TIMEOUT_MS;
  config->idle_timeout_ms = 0; /* No idle timeout by default */
}

static void
init_local_settings (SocketHTTP2_Conn_T conn, const SocketHTTP2_Config *config)
{
  conn->local_settings[SETTINGS_IDX_HEADER_TABLE_SIZE]
      = config->header_table_size;
  conn->local_settings[SETTINGS_IDX_ENABLE_PUSH] = config->enable_push;
  conn->local_settings[SETTINGS_IDX_MAX_CONCURRENT_STREAMS]
      = config->max_concurrent_streams;
  conn->local_settings[SETTINGS_IDX_INITIAL_WINDOW_SIZE]
      = config->initial_window_size;
  conn->local_settings[SETTINGS_IDX_MAX_FRAME_SIZE] = config->max_frame_size;
  conn->local_settings[SETTINGS_IDX_MAX_HEADER_LIST_SIZE]
      = config->max_header_list_size;
  conn->local_settings[SETTINGS_IDX_ENABLE_CONNECT_PROTOCOL]
      = config->enable_connect_protocol;
}

static const uint32_t peer_setting_defaults[HTTP2_SETTINGS_COUNT] = {
  SOCKETHTTP2_DEFAULT_HEADER_TABLE_SIZE,
  SOCKETHTTP2_DEFAULT_ENABLE_PUSH,
  UINT32_MAX, /* SETTINGS_MAX_CONCURRENT_STREAMS: unbounded initially */
  SOCKETHTTP2_DEFAULT_INITIAL_WINDOW_SIZE,
  SOCKETHTTP2_DEFAULT_MAX_FRAME_SIZE,
  UINT32_MAX, /* SETTINGS_MAX_HEADER_LIST_SIZE: unbounded initially */
  0           /* SETTINGS_ENABLE_CONNECT_PROTOCOL: disabled by default */
};

/* RFC 9113 Section 6.5.2: UINT32_MAX used for unbounded settings */
static void
init_peer_settings (SocketHTTP2_Conn_T conn)
{
  memcpy (conn->peer_settings,
          peer_setting_defaults,
          sizeof (peer_setting_defaults));
}

static void
init_flow_control (SocketHTTP2_Conn_T conn, const SocketHTTP2_Config *config)
{
  /* Clamp windows to prevent signed overflow */
  uint32_t recv_win = config->connection_window_size;
  if (recv_win > (uint32_t)INT32_MAX)
    recv_win = INT32_MAX;
  conn->recv_window = (int32_t)recv_win;

  uint32_t init_recv_win = config->initial_window_size;
  if (init_recv_win > (uint32_t)INT32_MAX)
    init_recv_win = INT32_MAX;
  conn->initial_recv_window = (int32_t)init_recv_win;

  conn->send_window = SOCKETHTTP2_DEFAULT_INITIAL_WINDOW_SIZE;
  conn->initial_send_window = SOCKETHTTP2_DEFAULT_INITIAL_WINDOW_SIZE;
}

static void
create_io_buffers (SocketHTTP2_Conn_T conn)
{
  size_t buf_size = SOCKETHTTP2_IO_BUFFER_SIZE;

  SocketBuf_T recv_temp = SocketBuf_new (conn->arena, buf_size);
  if (!recv_temp)
    {
      SOCKET_RAISE_MSG (SocketHTTP2,
                        SocketHTTP2_ProtocolError,
                        "Failed to allocate HTTP/2 recv I/O buffer");
    }

  SocketBuf_T send_temp = SocketBuf_new (conn->arena, buf_size);
  if (!send_temp)
    {
      SocketBuf_release (&recv_temp);
      SOCKET_RAISE_MSG (SocketHTTP2,
                        SocketHTTP2_ProtocolError,
                        "Failed to allocate HTTP/2 send I/O buffer");
    }

  conn->recv_buf = recv_temp;
  conn->send_buf = send_temp;
}

static void
create_hpack_encoder (SocketHTTP2_Conn_T conn, uint32_t header_table_size)
{
  SocketHPACK_EncoderConfig enc_config;

  SocketHPACK_encoder_config_defaults (&enc_config);
  enc_config.max_table_size = header_table_size;
  conn->encoder = SocketHPACK_Encoder_new (&enc_config, conn->arena);
  if (!conn->encoder)
    {
      SOCKET_RAISE_MSG (SocketHTTP2,
                        SocketHTTP2_ProtocolError,
                        "Failed to create HPACK encoder");
    }
}

static void
create_hpack_decoder (SocketHTTP2_Conn_T conn,
                      uint32_t header_table_size,
                      uint32_t max_header_list_size)
{
  SocketHPACK_DecoderConfig dec_config;

  SocketHPACK_decoder_config_defaults (&dec_config);
  dec_config.max_table_size = header_table_size;
  dec_config.max_header_list_size = max_header_list_size;
  conn->decoder = SocketHPACK_Decoder_new (&dec_config, conn->arena);
  if (!conn->decoder)
    {
      SOCKET_RAISE_MSG (SocketHTTP2,
                        SocketHTTP2_ProtocolError,
                        "Failed to create HPACK decoder");
    }
}

static void
create_stream_hash_table (SocketHTTP2_Conn_T conn)
{
  conn->streams = Arena_calloc (conn->arena,
                                HTTP2_STREAM_HASH_SIZE,
                                sizeof (*conn->streams),
                                __FILE__,
                                __LINE__);
  if (!conn->streams)
    {
      SOCKET_RAISE_MSG (SocketHTTP2,
                        SocketHTTP2_ProtocolError,
                        "Failed to allocate stream hash table");
    }
}

static SocketHTTP2_Conn_T
alloc_conn (Arena_T arena)
{
  SocketHTTP2_Conn_T conn;

  conn = Arena_calloc (arena, 1, sizeof (*conn), __FILE__, __LINE__);
  if (!conn)
    {
      SOCKET_RAISE_MSG (SocketHTTP2,
                        SocketHTTP2_ProtocolError,
                        "Failed to allocate HTTP/2 connection");
    }

  return conn;
}

static void
init_connection_components (SocketHTTP2_Conn_T conn,
                            const SocketHTTP2_Config *config)
{
  create_io_buffers (conn);

  create_hpack_encoder (conn, config->header_table_size);

  create_hpack_decoder (
      conn, config->header_table_size, config->max_header_list_size);

  create_stream_hash_table (conn);
}

/* Suppress GCC-specific clobbered warning (doesn't exist in Clang) */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

static int
generate_hash_seed (SocketHTTP2_Conn_T conn)
{
  unsigned char seed_bytes[sizeof (uint32_t)];
  /* SocketCrypto_random_bytes returns 0 on success, -1 on failure */
  ssize_t rv = SocketCrypto_random_bytes (seed_bytes, sizeof (seed_bytes));
  if (rv != 0)
    return -1;

  memcpy (&conn->hash_seed, seed_bytes, sizeof (conn->hash_seed));
  return 0;
}

static int
init_rate_limiters (SocketHTTP2_Conn_T conn, const SocketHTTP2_Config *cfg)
{
  conn->stream_open_rate_limit = SocketRateLimit_new (
      conn->arena, cfg->max_stream_open_rate, cfg->max_stream_open_burst);
  if (!conn->stream_open_rate_limit)
    return -1;

  conn->stream_close_rate_limit = SocketRateLimit_new (
      conn->arena, cfg->max_stream_close_rate, cfg->max_stream_close_burst);
  if (!conn->stream_close_rate_limit)
    return -1;

  return 0;
}

static void
init_stream_id_and_timeouts (SocketHTTP2_Conn_T conn,
                             const SocketHTTP2_Config *cfg)
{
  conn->next_stream_id = (cfg->role == HTTP2_ROLE_CLIENT) ? 1 : 2;
  conn->settings_timeout_ms = cfg->settings_timeout_ms;
  conn->ping_timeout_ms = cfg->ping_timeout_ms;
  conn->idle_timeout_ms = cfg->idle_timeout_ms;
  conn->settings_sent_time = 0;
  conn->ping_sent_time = 0;
  conn->last_activity_time = Socket_get_monotonic_ms ();
}

static void
init_rate_limiting_windows (SocketHTTP2_Conn_T conn,
                            const SocketHTTP2_Config *cfg)
{
  int64_t now = conn->last_activity_time;

  /* Frame rate limiters */
  TimeWindow_init (
      &conn->settings_window, SOCKETHTTP2_SETTINGS_RATE_WINDOW_MS, now);
  TimeWindow_init (&conn->ping_window, SOCKETHTTP2_PING_RATE_WINDOW_MS, now);
  TimeWindow_init (&conn->rst_window, SOCKETHTTP2_RST_RATE_WINDOW_MS, now);

  /* Sliding window stream rate limiters (CVE-2023-44487 protection) */
  TimeWindow_init (
      &conn->stream_create_window, (int)cfg->stream_window_size_ms, now);
  TimeWindow_init (
      &conn->stream_burst_window, (int)cfg->stream_burst_interval_ms, now);
  TimeWindow_init (
      &conn->stream_churn_window, (int)cfg->stream_window_size_ms, now);
  conn->stream_max_per_window = cfg->stream_max_per_window;
  conn->stream_burst_threshold = cfg->stream_burst_threshold;
  conn->stream_churn_threshold = cfg->stream_churn_threshold;
}

SocketHTTP2_Conn_T
SocketHTTP2_Conn_new (Socket_T socket,
                      const SocketHTTP2_Config *config,
                      Arena_T arena)
{
  SocketHTTP2_Conn_T conn = NULL;
  SocketHTTP2_Config default_config;
  const SocketHTTP2_Config *cfg;

  assert (socket);
  assert (arena);

  /* RFC 9113 §9.2: Validate TLS requirements for HTTP/2 over TLS */
  SocketHTTP2_TLSResult tls_result = SocketHTTP2_validate_tls (socket);
  if (tls_result != HTTP2_TLS_OK && tls_result != HTTP2_TLS_NOT_ENABLED)
    {
      /* TLS is enabled but doesn't meet HTTP/2 requirements */
      SOCKET_RAISE_MSG (SocketHTTP2,
                        SocketHTTP2_ProtocolError,
                        "HTTP/2 TLS validation failed: %s",
                        SocketHTTP2_tls_result_string (tls_result));
    }

  /* Use default config if none provided */
  if (config == NULL)
    {
      SocketHTTP2_config_defaults (&default_config, HTTP2_ROLE_CLIENT);
      cfg = &default_config;
    }
  else
    {
      cfg = config;
    }

  TRY
  {
    /* Allocate and initialize connection structure */
    conn = alloc_conn (arena);

    conn->socket = socket;
    conn->arena = arena;
    conn->role = cfg->role;
    conn->state = HTTP2_CONN_STATE_INIT;

    /* Initialize settings and flow control */
    init_local_settings (conn, cfg);
    init_peer_settings (conn);
    init_flow_control (conn, cfg);

    /* Initialize security features - hash seed for stream table */
    if (generate_hash_seed (conn) < 0)
      RAISE (SocketHTTP2_Failed);

    /* Initialize rate limiters */
    conn->client_initiated_count = 0;
    conn->server_initiated_count = 0;

    if (init_rate_limiters (conn, cfg) < 0)
      RAISE (SocketHTTP2_Failed);

    /* Initialize internal components (buffers, HPACK, streams) */
    init_connection_components (conn, cfg);

    /* Initialize stream IDs and timeouts */
    init_stream_id_and_timeouts (conn, cfg);

    /* Initialize TimeWindow-based rate limiters */
    init_rate_limiting_windows (conn, cfg);
  }
  EXCEPT (SocketHTTP2)
  {
    SocketHTTP2_Conn_free (&conn);
    RERAISE;
  }
  END_TRY;

  return conn;
}

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

void
SocketHTTP2_Conn_free (SocketHTTP2_Conn_T *conn)
{
  if (!conn || !*conn)
    return;

  SocketHTTP2_Conn_T c = *conn;

  /* Free HPACK encoder/decoder */
  if (c->encoder)
    SocketHPACK_Encoder_free (&c->encoder);

  /* Free rate limiters */
  SocketRateLimit_free (&c->stream_open_rate_limit);
  SocketRateLimit_free (&c->stream_close_rate_limit);
  if (c->decoder)
    SocketHPACK_Decoder_free (&c->decoder);

  /* Free buffers */
  if (c->recv_buf)
    SocketBuf_release (&c->recv_buf);
  if (c->send_buf)
    SocketBuf_release (&c->send_buf);

  /* Connection memory managed by arena */
  *conn = NULL;
}

Socket_T
SocketHTTP2_Conn_socket (SocketHTTP2_Conn_T conn)
{
  assert (conn);
  return conn->socket;
}

int
SocketHTTP2_Conn_is_closed (SocketHTTP2_Conn_T conn)
{
  assert (conn);
  return conn->state == HTTP2_CONN_STATE_CLOSED || conn->goaway_sent
         || conn->goaway_received;
}

Arena_T
SocketHTTP2_Conn_arena (SocketHTTP2_Conn_T conn)
{
  assert (conn);
  return conn->arena;
}

static inline uint32_t
get_setting_array (const uint32_t *settings_array, SocketHTTP2_SettingsId id)
{
  if (id >= 1 && id <= HTTP2_SETTINGS_COUNT)
    return settings_array[id - 1];
  return 0;
}

uint32_t
SocketHTTP2_Conn_get_setting (SocketHTTP2_Conn_T conn,
                              SocketHTTP2_SettingsId id)
{
  assert (conn);
  return get_setting_array (conn->peer_settings, id);
}

uint32_t
SocketHTTP2_Conn_get_local_setting (SocketHTTP2_Conn_T conn,
                                    SocketHTTP2_SettingsId id)
{
  assert (conn);
  return get_setting_array (conn->local_settings, id);
}

uint32_t
SocketHTTP2_Conn_last_stream_id (SocketHTTP2_Conn_T conn)
{
  assert (conn);
  return conn->last_peer_stream_id;
}

int32_t
SocketHTTP2_Conn_send_window (SocketHTTP2_Conn_T conn)
{
  assert (conn);
  return conn->send_window;
}

int32_t
SocketHTTP2_Conn_recv_window (SocketHTTP2_Conn_T conn)
{
  assert (conn);
  return conn->recv_window;
}

void
SocketHTTP2_Conn_set_stream_callback (SocketHTTP2_Conn_T conn,
                                      SocketHTTP2_StreamCallback callback,
                                      void *userdata)
{
  assert (conn);
  conn->stream_callback = callback;
  conn->stream_callback_data = userdata;
}

void
SocketHTTP2_Conn_set_conn_callback (SocketHTTP2_Conn_T conn,
                                    SocketHTTP2_ConnCallback callback,
                                    void *userdata)
{
  assert (conn);
  conn->conn_callback = callback;
  conn->conn_callback_data = userdata;
}

static int
should_send_setting (uint16_t id, uint32_t value)
{
  switch (id)
    {
    case HTTP2_SETTINGS_HEADER_TABLE_SIZE:
      return value != SOCKETHTTP2_DEFAULT_HEADER_TABLE_SIZE;
    case HTTP2_SETTINGS_ENABLE_PUSH:
      return value != SOCKETHTTP2_DEFAULT_ENABLE_PUSH;
    case HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
      return 1; /* Always send this one */
    case HTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
      return value != SOCKETHTTP2_DEFAULT_INITIAL_WINDOW_SIZE;
    case HTTP2_SETTINGS_MAX_FRAME_SIZE:
      return value != SOCKETHTTP2_DEFAULT_MAX_FRAME_SIZE;
    case HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE:
      return 1; /* Always send this one */
    case HTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL:
      return value
             != 0; /* RFC 8441: Send if enabled (differs from default 0) */
    default:
      return 0;
    }
}

static size_t
build_settings_payload (SocketHTTP2_Conn_T conn, unsigned char *payload)
{
  size_t payload_len = 0;

  for (int i = 0; i < HTTP2_SETTINGS_COUNT; i++)
    {
      uint16_t id = (uint16_t)(i + 1);
      uint32_t value = conn->local_settings[i];

      if (should_send_setting (id, value))
        {
          write_u16_be (payload + payload_len, id);
          write_u32_be (payload + payload_len + 2, value);
          payload_len += HTTP2_SETTING_ENTRY_SIZE;
        }
    }

  return payload_len;
}

static int
send_initial_settings (SocketHTTP2_Conn_T conn)
{
  SocketHTTP2_FrameHeader header;
  unsigned char payload[HTTP2_SETTINGS_COUNT * HTTP2_SETTING_ENTRY_SIZE];
  size_t payload_len;

  payload_len = build_settings_payload (conn, payload);

  header.length = (uint32_t)payload_len;
  header.type = HTTP2_FRAME_SETTINGS;
  header.flags = 0;
  header.stream_id = 0;

  return http2_frame_send (conn, &header, payload, payload_len);
}

static int
handshake_send_client_preface (SocketHTTP2_Conn_T conn)
{
  if (SocketBuf_write (conn->send_buf, HTTP2_CLIENT_PREFACE, HTTP2_PREFACE_SIZE)
      != HTTP2_PREFACE_SIZE)
    return -1;

  conn->state = HTTP2_CONN_STATE_PREFACE_SENT;
  return 0;
}

static int
handshake_send_settings (SocketHTTP2_Conn_T conn)
{
  if (send_initial_settings (conn) < 0)
    return -1;

  conn->settings_ack_pending = 1;
  conn->settings_sent_time = Socket_get_monotonic_ms ();
  conn->state = HTTP2_CONN_STATE_SETTINGS_SENT;

  /* If connection-level window is larger than default, send WINDOW_UPDATE */
  if (conn->recv_window > SOCKETHTTP2_DEFAULT_INITIAL_WINDOW_SIZE)
    {
      uint32_t increment = (uint32_t)conn->recv_window
                           - SOCKETHTTP2_DEFAULT_INITIAL_WINDOW_SIZE;
      SocketHTTP2_Conn_window_update (conn, increment);
    }

  return 0;
}

int
SocketHTTP2_Conn_handshake (SocketHTTP2_Conn_T conn)
{
  assert (conn);

  switch (conn->state)
    {
    case HTTP2_CONN_STATE_INIT:
      /* Server waits for client preface */
      if (conn->role != HTTP2_ROLE_CLIENT)
        return 1;

      /* Client sends preface then settings */
      if (handshake_send_client_preface (conn) < 0)
        return -1;

      if (handshake_send_settings (conn) < 0)
        return -1;

      return 1;

    case HTTP2_CONN_STATE_PREFACE_SENT:
    case HTTP2_CONN_STATE_PREFACE_RECV:
      if (handshake_send_settings (conn) < 0)
        return -1;
      return 1;

    case HTTP2_CONN_STATE_SETTINGS_SENT:
    case HTTP2_CONN_STATE_SETTINGS_RECV:
      return 1; /* Waiting for peer */

    case HTTP2_CONN_STATE_READY:
      return 0; /* Complete */

    default:
      return -1;
    }
}

int
SocketHTTP2_Conn_settings (SocketHTTP2_Conn_T conn,
                           const SocketHTTP2_Setting *settings,
                           size_t count)
{
  SocketHTTP2_FrameHeader header;
  unsigned char *payload;
  size_t payload_len;

  assert (conn);

  payload_len = count * HTTP2_SETTING_ENTRY_SIZE;
  payload = Arena_alloc (conn->arena, payload_len, __FILE__, __LINE__);
  if (!payload)
    return -1;

  /* Build payload and update local settings */
  for (size_t i = 0; i < count; i++)
    {
      size_t offset = i * HTTP2_SETTING_ENTRY_SIZE;
      write_u16_be (payload + offset, settings[i].id);
      write_u32_be (payload + offset + 2, settings[i].value);

      /* Update local settings */
      if (settings[i].id >= 1 && settings[i].id <= HTTP2_SETTINGS_COUNT)
        conn->local_settings[settings[i].id - 1] = settings[i].value;

      /* Update our encoder for header table size changes */
      if (settings[i].id == HTTP2_SETTINGS_HEADER_TABLE_SIZE)
        SocketHPACK_Encoder_set_table_size (conn->encoder, settings[i].value);
    }

  header.length = (uint32_t)payload_len;
  header.type = HTTP2_FRAME_SETTINGS;
  header.flags = 0;
  header.stream_id = 0;

  int rv = http2_frame_send (conn, &header, payload, payload_len);
  if (rv < 0)
    return -1;

  conn->settings_ack_pending = 1;
  conn->settings_sent_time = Socket_get_monotonic_ms ();
  return 0;
}

int
SocketHTTP2_Conn_ping (SocketHTTP2_Conn_T conn, const unsigned char opaque[8])
{
  SocketHTTP2_FrameHeader header;
  unsigned char payload[HTTP2_PING_PAYLOAD_SIZE];

  assert (conn);

  if (opaque)
    {
      memcpy (payload, opaque, HTTP2_PING_PAYLOAD_SIZE);
    }
  else
    {
      /* Generate opaque data using monotonic time */
      int64_t time_ms = Socket_get_monotonic_ms ();
      memcpy (payload, &time_ms, sizeof (time_ms));
    }

  /* Store for matching ACK */
  memcpy (conn->ping_opaque, payload, HTTP2_PING_PAYLOAD_SIZE);
  conn->ping_pending = 1;
  conn->ping_sent_time = Socket_get_monotonic_ms ();

  header.length = HTTP2_PING_PAYLOAD_SIZE;
  header.type = HTTP2_FRAME_PING;
  header.flags = 0;
  header.stream_id = 0;

  return http2_frame_send (conn, &header, payload, HTTP2_PING_PAYLOAD_SIZE);
}

int
SocketHTTP2_Conn_goaway (SocketHTTP2_Conn_T conn,
                         SocketHTTP2_ErrorCode error_code,
                         const void *debug_data,
                         size_t debug_len)
{
  SocketHTTP2_FrameHeader header;
  unsigned char *payload;
  size_t payload_len;

  assert (conn);

  payload_len = HTTP2_GOAWAY_HEADER_SIZE + debug_len;
  payload = Arena_alloc (conn->arena, payload_len, __FILE__, __LINE__);
  if (!payload)
    return -1;

  /* Last stream ID and error code */
  write_u31_be (payload, conn->last_peer_stream_id);
  write_u32_be (payload + 4, (uint32_t)error_code);

  /* Debug data */
  if (debug_len > 0 && debug_data)
    memcpy (payload + HTTP2_GOAWAY_HEADER_SIZE, debug_data, debug_len);

  header.length = (uint32_t)payload_len;
  header.type = HTTP2_FRAME_GOAWAY;
  header.flags = 0;
  header.stream_id = 0;

  conn->goaway_sent = 1;
  conn->goaway_error_code = error_code;

  return http2_frame_send (conn, &header, payload, payload_len);
}

int
SocketHTTP2_Conn_window_update (SocketHTTP2_Conn_T conn, uint32_t increment)
{
  SocketHTTP2_FrameHeader header;
  unsigned char payload[HTTP2_WINDOW_UPDATE_SIZE];

  assert (conn);
  assert (increment > 0 && increment <= SOCKETHTTP2_MAX_WINDOW_SIZE);

  write_u31_be (payload, increment);

  header.length = HTTP2_WINDOW_UPDATE_SIZE;
  header.type = HTTP2_FRAME_WINDOW_UPDATE;
  header.flags = 0;
  header.stream_id = 0;

  return http2_frame_send (conn, &header, payload, HTTP2_WINDOW_UPDATE_SIZE);
}

static int
read_socket_to_buffer (SocketHTTP2_Conn_T conn)
{
  size_t space;
  void *write_ptr = SocketBuf_writeptr (conn->recv_buf, &space);

  if (!write_ptr || space == 0)
    return 0;

  ssize_t n = Socket_recv (conn->socket, write_ptr, space);
  if (n > 0)
    {
      SocketBuf_written (conn->recv_buf, (size_t)n);
      /* Update activity time on recv */
      conn->last_activity_time = Socket_get_monotonic_ms ();
    }
  else if (n < 0)
    return -1;

  return 0;
}

static int
verify_client_preface (SocketHTTP2_Conn_T conn)
{
  size_t available = SocketBuf_available (conn->recv_buf);
  if (available < HTTP2_PREFACE_SIZE)
    return 0;

  unsigned char preface[HTTP2_PREFACE_SIZE];
  SocketBuf_peek (conn->recv_buf, preface, HTTP2_PREFACE_SIZE);

  if (memcmp (preface, HTTP2_CLIENT_PREFACE, HTTP2_PREFACE_SIZE) != 0)
    {
      http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
      return -1;
    }

  SocketBuf_consume (conn->recv_buf, HTTP2_PREFACE_SIZE);
  conn->state = HTTP2_CONN_STATE_PREFACE_RECV;
  return 1;
}

static int
process_single_frame (SocketHTTP2_Conn_T conn)
{
  SocketHTTP2_FrameHeader header;
  SocketHTTP2_ErrorCode error;
  const unsigned char *payload;
  size_t read_len;

  size_t available = SocketBuf_available (conn->recv_buf);
  if (available < HTTP2_FRAME_HEADER_SIZE)
    return 0;

  /* Peek at frame header */
  unsigned char *data
      = (unsigned char *)SocketBuf_readptr (conn->recv_buf, &read_len);
  if (!data || read_len < HTTP2_FRAME_HEADER_SIZE)
    return 0;

  SocketHTTP2_frame_header_parse (data, HTTP2_FRAME_HEADER_SIZE, &header);

  /* Check if we have complete frame */
  if (available < HTTP2_FRAME_HEADER_SIZE + header.length)
    return 0;

  /* Validate frame */
  error = http2_frame_validate (conn, &header);
  if (error != HTTP2_NO_ERROR)
    {
      if (header.stream_id == 0)
        {
          http2_send_connection_error (conn, error);
          return -1;
        }
      http2_send_stream_error (conn, header.stream_id, error);
      SocketBuf_consume (conn->recv_buf,
                         HTTP2_FRAME_HEADER_SIZE + header.length);
      return 1; /* Continue processing other frames */
    }

  /* Get payload pointer and process the frame */
  payload = data + HTTP2_FRAME_HEADER_SIZE;
  if (http2_process_frame (conn, &header, payload) < 0)
    return -1;

  /* Update activity time on frame process */
  conn->last_activity_time = Socket_get_monotonic_ms ();

  /* Consume the frame */
  SocketBuf_consume (conn->recv_buf, HTTP2_FRAME_HEADER_SIZE + header.length);
  return 1;
}

static int
enforce_timeouts (SocketHTTP2_Conn_T conn, int64_t now_ms)
{
  /* SETTINGS ACK timeout */
  if (conn->settings_ack_pending && conn->settings_timeout_ms > 0
      && (now_ms - conn->settings_sent_time
          >= (int64_t)conn->settings_timeout_ms))
    {
      SOCKET_LOG_WARN_MSG ("HTTP/2 SETTINGS ACK timeout (%" PRId64 " ms)",
                           now_ms - conn->settings_sent_time);
      SocketHTTP2_Conn_goaway (
          conn, HTTP2_SETTINGS_TIMEOUT, "SETTINGS ACK timeout", 20);
      return -1;
    }

  /* PING ACK timeout */
  if (conn->ping_pending && conn->ping_timeout_ms > 0
      && (now_ms - conn->ping_sent_time >= (int64_t)conn->ping_timeout_ms))
    {
      SOCKET_LOG_WARN_MSG ("HTTP/2 PING ACK timeout (%" PRId64 " ms)",
                           now_ms - conn->ping_sent_time);
      SocketHTTP2_Conn_goaway (
          conn, HTTP2_PROTOCOL_ERROR, "PING ACK timeout", 16);
      return -1;
    }

  /* Idle timeout (only if no active streams) */
  if (conn->idle_timeout_ms > 0)
    {
      uint32_t active = SocketHTTP2_Conn_get_concurrent_streams (conn);
      if (active == 0
          && (now_ms - conn->last_activity_time
              >= (int64_t)conn->idle_timeout_ms))
        {
          SOCKET_LOG_INFO_MSG ("HTTP/2 idle connection timeout (%" PRId64
                               " ms, no active streams)",
                               now_ms - conn->last_activity_time);
          SocketHTTP2_Conn_goaway (conn, HTTP2_NO_ERROR, "Idle timeout", 12);
          return -1;
        }
    }

  return 0;
}

int
SocketHTTP2_Conn_process (SocketHTTP2_Conn_T conn, unsigned events)
{
  int result;

  assert (conn);
  (void)events; /* May use for POLL_READ/POLL_WRITE optimization later */

  int64_t now_ms = Socket_get_monotonic_ms ();

  /* Enforce HTTP/2 timeouts (RFC 9113) */
  if (enforce_timeouts (conn, now_ms) < 0)
    return -1;

  /* Read data from socket into receive buffer */
  if (read_socket_to_buffer (conn) < 0)
    return -1;

  /* Check for client preface (server only) */
  if (conn->role == HTTP2_ROLE_SERVER && conn->state == HTTP2_CONN_STATE_INIT)
    {
      result = verify_client_preface (conn);
      if (result < 0)
        return -1;
      if (result == 0)
        return 0; /* Need more data */

      /* Now send our settings */
      if (SocketHTTP2_Conn_handshake (conn) < 0)
        return -1;
    }

  /* Process frames */
  while ((result = process_single_frame (conn)) == 1)
    ; /* Continue processing */

  return result;
}

int
SocketHTTP2_Conn_flush (SocketHTTP2_Conn_T conn)
{
  assert (conn);

  while (!SocketBuf_empty (conn->send_buf))
    {
      size_t available;
      const void *data = SocketBuf_readptr (conn->send_buf, &available);

      if (!data || available == 0)
        break;

      ssize_t sent = Socket_send (conn->socket, data, available);
      if (sent > 0)
        {
          SocketBuf_consume (conn->send_buf, (size_t)sent);
          /* Update activity time on send */
          conn->last_activity_time = Socket_get_monotonic_ms ();
        }
      else if (sent == 0)
        return 1; /* Would block */
      else
        return -1;
    }

  return 0;
}

int
http2_process_frame (SocketHTTP2_Conn_T conn,
                     const SocketHTTP2_FrameHeader *header,
                     const unsigned char *payload)
{
  switch (header->type)
    {
    case HTTP2_FRAME_DATA:
      return http2_process_data (conn, header, payload);
    case HTTP2_FRAME_HEADERS:
      return http2_process_headers (conn, header, payload);
    case HTTP2_FRAME_PRIORITY:
      /* Deprecated per RFC 9113 §6.3: ignore PRIORITY frame with logging for
       * compatibility */
      SOCKET_LOG_DEBUG_MSG (
          "Ignoring deprecated PRIORITY frame: stream=%u len=%u",
          header->stream_id,
          (unsigned)header->length);
      return 0;
    case HTTP2_FRAME_RST_STREAM:
      return http2_process_rst_stream (conn, header, payload);
    case HTTP2_FRAME_SETTINGS:
      return http2_process_settings (conn, header, payload);
    case HTTP2_FRAME_PUSH_PROMISE:
      return http2_process_push_promise (conn, header, payload);
    case HTTP2_FRAME_PING:
      return http2_process_ping (conn, header, payload);
    case HTTP2_FRAME_GOAWAY:
      return http2_process_goaway (conn, header, payload);
    case HTTP2_FRAME_WINDOW_UPDATE:
      return http2_process_window_update (conn, header, payload);
    case HTTP2_FRAME_CONTINUATION:
      return http2_process_continuation (conn, header, payload);
    case HTTP2_FRAME_PRIORITY_UPDATE:
      /* RFC 9218: Extensible Priorities */
      return http2_process_priority_update (conn, header, payload);
    default:
      /* Unknown frame types are ignored (RFC 9113 Section 4.1) */
      return 0;
    }
}

static int
send_settings_ack (SocketHTTP2_Conn_T conn)
{
  SocketHTTP2_FrameHeader ack_header;

  ack_header.length = 0;
  ack_header.type = HTTP2_FRAME_SETTINGS;
  ack_header.flags = HTTP2_FLAG_ACK;
  ack_header.stream_id = 0;

  return http2_frame_send (conn, &ack_header, NULL, 0);
}

static void
process_settings_ack (SocketHTTP2_Conn_T conn)
{
  if (conn->settings_ack_pending)
    {
      conn->settings_ack_pending = 0;
      if (conn->state == HTTP2_CONN_STATE_SETTINGS_SENT)
        conn->state = HTTP2_CONN_STATE_READY;
      http2_emit_conn_event (conn, HTTP2_EVENT_SETTINGS_ACK);
    }
}

/* Maps RFC 9113 setting IDs to 0-based array indices;
 * SETTINGS_ENABLE_CONNECT_PROTOCOL (0x8) maps to index 6 */
static inline size_t
setting_id_to_index (uint16_t id)
{
  /* Standard settings 1-6 map directly to indices 0-5 */
  if (id >= 1 && id <= 6)
    return (size_t)(id - 1);

  /* RFC 8441: SETTINGS_ENABLE_CONNECT_PROTOCOL (0x8) maps to index 6 */
  if (id == HTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL)
    return SETTINGS_IDX_ENABLE_CONNECT_PROTOCOL;

  /* Unknown settings ignored per RFC 9113 Section 6.5.2 */
  return SIZE_MAX;
}

static int
validate_enable_push (SocketHTTP2_Conn_T conn, uint32_t value)
{
  if (value > 1)
    {
      http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
      return -1;
    }
  return 0;
}

static int
validate_initial_window_size (SocketHTTP2_Conn_T conn, uint32_t value)
{
  if (value > SOCKETHTTP2_MAX_WINDOW_SIZE)
    {
      http2_send_connection_error (conn, HTTP2_FLOW_CONTROL_ERROR);
      return -1;
    }

  /* Adjust existing stream windows */
  int32_t delta
      = (int32_t)value
        - (int32_t)conn->peer_settings[SETTINGS_IDX_INITIAL_WINDOW_SIZE];

  for (size_t j = 0; j < HTTP2_STREAM_HASH_SIZE; j++)
    {
      SocketHTTP2_Stream_T s = conn->streams[j];
      while (s)
        {
          if (http2_flow_adjust_window (&s->send_window, delta) < 0)
            {
              http2_send_connection_error (conn, HTTP2_FLOW_CONTROL_ERROR);
              return -1;
            }
          s = s->hash_next;
        }
    }

  conn->initial_send_window = (int32_t)value;
  return 0;
}

static int
validate_max_frame_size (SocketHTTP2_Conn_T conn, uint32_t value)
{
  if (value < SOCKETHTTP2_DEFAULT_MAX_FRAME_SIZE
      || value > SOCKETHTTP2_MAX_MAX_FRAME_SIZE)
    {
      http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
      return -1;
    }
  return 0;
}

/* RFC 8441 Section 3: Once enabled, cannot be disabled */
static int
validate_enable_connect_protocol (SocketHTTP2_Conn_T conn, uint32_t value)
{
  if (value > 1)
    {
      SOCKET_LOG_ERROR_MSG (
          "SETTINGS_ENABLE_CONNECT_PROTOCOL invalid value: %u", value);
      http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
      return -1;
    }

  /* RFC 8441 Section 3: sender MUST NOT send 0 after previously sending 1 */
  if (value == 0
      && conn->peer_settings[SETTINGS_IDX_ENABLE_CONNECT_PROTOCOL] == 1)
    {
      SOCKET_LOG_ERROR_MSG (
          "SETTINGS_ENABLE_CONNECT_PROTOCOL reverted from 1 to 0");
      http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
      return -1;
    }

  return 0;
}

/* Unknown settings ignored per RFC 9113 Section 6.5.2 */
static int
validate_and_apply_setting (SocketHTTP2_Conn_T conn,
                            uint16_t id,
                            uint32_t value)
{
  /* Validate setting based on type */
  switch (id)
    {
    case HTTP2_SETTINGS_ENABLE_PUSH:
      if (validate_enable_push (conn, value) < 0)
        return -1;
      break;

    case HTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
      if (validate_initial_window_size (conn, value) < 0)
        return -1;
      break;

    case HTTP2_SETTINGS_MAX_FRAME_SIZE:
      if (validate_max_frame_size (conn, value) < 0)
        return -1;
      break;

    case HTTP2_SETTINGS_HEADER_TABLE_SIZE:
      SocketHPACK_Decoder_set_table_size (conn->decoder, value);
      break;

    case HTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL:
      if (validate_enable_connect_protocol (conn, value) < 0)
        return -1;
      break;

    case HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
    case HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE:
      /* These are limits on what we can send - no validation needed */
      break;

    default:
      /* Unknown settings ignored per RFC 9113 Section 6.5.2 */
      break;
    }

  /* Store setting using efficient ID-to-index mapping */
  size_t array_index = setting_id_to_index (id);
  if (array_index != SIZE_MAX)
    conn->peer_settings[array_index] = value;

  return 0;
}

static void
update_conn_state_after_settings (SocketHTTP2_Conn_T conn)
{
  if (conn->state == HTTP2_CONN_STATE_SETTINGS_SENT
      || conn->state == HTTP2_CONN_STATE_PREFACE_RECV)
    {
      conn->state = HTTP2_CONN_STATE_SETTINGS_RECV;
      if (!conn->settings_ack_pending)
        conn->state = HTTP2_CONN_STATE_READY;
    }
}

static int
parse_and_apply_all_settings (SocketHTTP2_Conn_T conn,
                              const unsigned char *payload,
                              size_t length)
{
  if (length % HTTP2_SETTING_ENTRY_SIZE != 0)
    {
      http2_send_connection_error (conn, HTTP2_FRAME_SIZE_ERROR);
      return -1;
    }

  size_t count = length / HTTP2_SETTING_ENTRY_SIZE;
  for (size_t i = 0; i < count; i++)
    {
      size_t offset = i * HTTP2_SETTING_ENTRY_SIZE;
      uint16_t id = read_u16_be (payload + offset);
      uint32_t value = read_u32_be (payload + offset + 2);

      if (validate_and_apply_setting (conn, id, value) < 0)
        return -1;
    }

  return 0;
}

int
http2_process_settings (SocketHTTP2_Conn_T conn,
                        const SocketHTTP2_FrameHeader *header,
                        const unsigned char *payload)
{
  /* Handle SETTINGS ACK frame */
  if (header->flags & HTTP2_FLAG_ACK)
    {
      process_settings_ack (conn);
      return 0;
    }

  /* Rate limit non-ACK SETTINGS frames to prevent flood attacks (using
   * TimeWindow) */
  int64_t now_ms = Socket_get_monotonic_ms ();
  TimeWindow_record (&conn->settings_window, now_ms);
  if (conn->settings_window.current_count > SOCKETHTTP2_SETTINGS_RATE_LIMIT)
    {
      int64_t elapsed_ms = now_ms - conn->settings_window.window_start_ms;
      SOCKET_LOG_WARN_MSG ("HTTP/2 SETTINGS rate limit exceeded "
                           "(%" PRIu32 " in approx %" PRId64 "ms), "
                           "closing connection",
                           conn->settings_window.current_count,
                           elapsed_ms);
      http2_send_connection_error (conn, HTTP2_ENHANCE_YOUR_CALM);
      return -1;
    }

  /* Parse and apply settings from payload */
  if (parse_and_apply_all_settings (conn, payload, header->length) < 0)
    return -1;

  /* Acknowledge receipt of settings */
  if (send_settings_ack (conn) < 0)
    return -1;

  /* Update connection state based on handshake progress */
  update_conn_state_after_settings (conn);
  return 0;
}

int
http2_process_ping (SocketHTTP2_Conn_T conn,
                    const SocketHTTP2_FrameHeader *header,
                    const unsigned char *payload)
{
  /* Rate limit PING frames to prevent flood attacks (using TimeWindow) */
  int64_t now_ms = Socket_get_monotonic_ms ();
  TimeWindow_record (&conn->ping_window, now_ms);
  if (conn->ping_window.current_count > SOCKETHTTP2_PING_RATE_LIMIT)
    {
      int64_t elapsed_ms = now_ms - conn->ping_window.window_start_ms;
      SOCKET_LOG_WARN_MSG ("HTTP/2 PING rate limit exceeded "
                           "(%" PRIu32 " in approx %" PRId64 "ms), "
                           "closing connection",
                           conn->ping_window.current_count,
                           elapsed_ms);
      http2_send_connection_error (conn, HTTP2_ENHANCE_YOUR_CALM);
      return -1;
    }

  /* PING ACK - verify opaque data matches our pending request */
  if (header->flags & HTTP2_FLAG_ACK)
    {
      if (conn->ping_pending
          && memcmp (payload, conn->ping_opaque, HTTP2_PING_PAYLOAD_SIZE) == 0)
        {
          conn->ping_pending = 0;
          http2_emit_conn_event (conn, HTTP2_EVENT_PING_ACK);
        }
      return 0;
    }

  /* Echo PING with ACK flag */
  SocketHTTP2_FrameHeader response = { .length = HTTP2_PING_PAYLOAD_SIZE,
                                       .type = HTTP2_FRAME_PING,
                                       .flags = HTTP2_FLAG_ACK,
                                       .stream_id = 0 };

  return http2_frame_send (conn, &response, payload, HTTP2_PING_PAYLOAD_SIZE);
}

int
http2_process_goaway (SocketHTTP2_Conn_T conn,
                      const SocketHTTP2_FrameHeader *header,
                      const unsigned char *payload)
{
  /* header already validated by caller - length and stream_id checked */
  (void)header;

  /* Parse last stream ID and error code */
  conn->max_peer_stream_id = read_u31_be (payload);
  conn->goaway_error_code = (SocketHTTP2_ErrorCode)read_u32_be (payload + 4);
  conn->goaway_received = 1;

  http2_emit_conn_event (conn, HTTP2_EVENT_GOAWAY_RECEIVED);
  return 0;
}

static int
process_connection_window_update (SocketHTTP2_Conn_T conn, uint32_t increment)
{
  if (http2_flow_update_send (conn, NULL, increment) < 0)
    {
      http2_send_connection_error (conn, HTTP2_FLOW_CONTROL_ERROR);
      return -1;
    }
  return 0;
}

/* Ignores unknown streams per RFC 9113 (may be closed) */
static int
process_stream_window_update (SocketHTTP2_Conn_T conn,
                              uint32_t stream_id,
                              uint32_t increment)
{
  SocketHTTP2_Stream_T stream = http2_stream_lookup (conn, stream_id);
  if (stream)
    {
      if (http2_flow_update_send (conn, stream, increment) < 0)
        {
          http2_send_stream_error (conn, stream_id, HTTP2_FLOW_CONTROL_ERROR);
          return -1;
        }
      http2_emit_stream_event (conn, stream, HTTP2_EVENT_WINDOW_UPDATE);
    }
  /* Ignore for unknown streams as per RFC 9113 */
  return 0;
}

int
http2_process_window_update (SocketHTTP2_Conn_T conn,
                             const SocketHTTP2_FrameHeader *header,
                             const unsigned char *payload)
{
  uint32_t increment = read_u31_be (payload);

  /* Zero increment is protocol error per RFC 9113 Section 6.9 */
  if (increment == 0)
    {
      SocketHTTP2_ErrorCode e = HTTP2_PROTOCOL_ERROR;
      if (header->stream_id == 0)
        http2_send_connection_error (conn, e);
      else
        http2_send_stream_error (conn, header->stream_id, e);
      return -1;
    }

  /* Dispatch to connection or stream handler */
  if (header->stream_id == 0)
    return process_connection_window_update (conn, increment);
  else
    return process_stream_window_update (conn, header->stream_id, increment);
}

/* SECURITY: CVE-2023-44487 protection - rate limits RST_STREAM frames to
 * prevent Rapid Reset DoS */
int
http2_process_rst_stream (SocketHTTP2_Conn_T conn,
                          const SocketHTTP2_FrameHeader *header,
                          const unsigned char *payload)
{
  uint32_t error_code = read_u32_be (payload);

  /* CVE-2023-44487: Rate limit RST_STREAM frames to prevent Rapid Reset DoS
   * (using TimeWindow) */
  int64_t now_ms = Socket_get_monotonic_ms ();
  TimeWindow_record (&conn->rst_window, now_ms);
  if (conn->rst_window.current_count > SOCKETHTTP2_RST_RATE_LIMIT)
    {
      int64_t elapsed_ms = now_ms - conn->rst_window.window_start_ms;
      SOCKET_LOG_WARN_MSG ("HTTP/2 RST_STREAM rate limit exceeded "
                           "(%" PRIu32 " in approx %" PRId64 "ms), "
                           "closing connection (CVE-2023-44487 protection)",
                           conn->rst_window.current_count,
                           elapsed_ms);
      http2_send_connection_error (conn, HTTP2_ENHANCE_YOUR_CALM);
      return -1;
    }

  /* Normal RST_STREAM processing */
  SocketHTTP2_Stream_T stream = http2_stream_lookup (conn, header->stream_id);
  if (stream)
    {
      /* RFC 9113: MUST NOT send RST_STREAM in response to RST_STREAM */
      stream->rst_received = 1;
      stream->state = HTTP2_STREAM_STATE_CLOSED;
      http2_emit_stream_event (conn, stream, HTTP2_EVENT_STREAM_RESET);
    }

  (void)error_code; /* Could log or store for debugging */
  return 0;
}

SocketHTTP2_Conn_T
SocketHTTP2_Conn_upgrade_client (Socket_T socket,
                                 const unsigned char *settings_payload,
                                 size_t settings_len,
                                 Arena_T arena)
{
  SocketHTTP2_Config config;
  SocketHTTP2_Conn_T conn;

  (void)settings_payload;
  (void)settings_len;

  SocketHTTP2_config_defaults (&config, HTTP2_ROLE_CLIENT);
  conn = SocketHTTP2_Conn_new (socket, &config, arena);
  if (!conn)
    return NULL;

  /* For h2c upgrade, skip the preface - it was implied by the upgrade */
  conn->state = HTTP2_CONN_STATE_PREFACE_SENT;

  /* Send SETTINGS */
  if (send_initial_settings (conn) < 0)
    {
      SocketHTTP2_Conn_free (&conn);
      return NULL;
    }
  conn->settings_ack_pending = 1;
  conn->settings_sent_time = Socket_get_monotonic_ms ();
  conn->state = HTTP2_CONN_STATE_SETTINGS_SENT;

  return conn;
}

SocketHTTP2_Conn_T
SocketHTTP2_Conn_upgrade_server (Socket_T socket,
                                 const SocketHTTP_Request *initial_request,
                                 const unsigned char *settings_payload,
                                 size_t settings_len,
                                 Arena_T arena)
{
  SocketHTTP2_Config config;
  SocketHTTP2_Conn_T conn;
  SocketHTTP2_Stream_T stream;

  (void)initial_request;

  SocketHTTP2_config_defaults (&config, HTTP2_ROLE_SERVER);
  conn = SocketHTTP2_Conn_new (socket, &config, arena);
  if (!conn)
    return NULL;

  /* For h2c upgrade, skip the preface - client already sent HTTP/1.1 upgrade
   */
  conn->state = HTTP2_CONN_STATE_PREFACE_RECV;

  /* Create stream 1 for the upgraded request */
  stream = http2_stream_create (conn, 1, 0 /* peer initiated upgrade */);
  if (!stream)
    {
      SocketHTTP2_Conn_free (&conn);
      return NULL;
    }
  stream->state = HTTP2_STREAM_STATE_HALF_CLOSED_REMOTE;
  conn->last_peer_stream_id = 1;

  /* Apply the client's HTTP2-Settings (RFC 9113 / legacy RFC 7540 upgrade). */
  if (settings_payload != NULL && settings_len > 0)
    {
      if (parse_and_apply_all_settings (conn, settings_payload, settings_len)
          < 0)
        {
          SocketHTTP2_Conn_free (&conn);
          return NULL;
        }
      if (send_settings_ack (conn) < 0)
        {
          SocketHTTP2_Conn_free (&conn);
          return NULL;
        }
    }

  /* Send SETTINGS */
  if (send_initial_settings (conn) < 0)
    {
      SocketHTTP2_Conn_free (&conn);
      return NULL;
    }
  conn->settings_ack_pending = 1;
  conn->settings_sent_time = Socket_get_monotonic_ms ();
  conn->state = HTTP2_CONN_STATE_SETTINGS_SENT;

  return conn;
}

SocketHTTP2_Stream_T
SocketHTTP2_Conn_get_stream (SocketHTTP2_Conn_T conn, uint32_t stream_id)
{
  assert (conn != NULL);

  if (stream_id == 0)
    return NULL;

  return http2_stream_lookup (conn, stream_id);
}

int
SocketHTTP2_Conn_ping_wait (SocketHTTP2_Conn_T conn, int timeout_ms)
{
  int64_t start_ms;
  int64_t deadline_ms;
  int64_t remaining;

  assert (conn);

  start_ms = Socket_get_monotonic_ms ();
  deadline_ms = start_ms + timeout_ms;

  /* Send PING */
  if (SocketHTTP2_Conn_ping (conn, NULL) < 0)
    return -1;

  /* Wait for ACK */
  while (conn->ping_pending)
    {
      remaining = deadline_ms - Socket_get_monotonic_ms ();
      if (remaining <= 0)
        {
          conn->ping_pending = 0;
          return -1; /* Timeout */
        }

      /* Poll for readability */
      struct pollfd pfd;
      pfd.fd = Socket_fd (conn->socket);
      pfd.events = POLLIN;
      pfd.revents = 0;

      int ret = poll (&pfd, 1, (int)remaining);
      if (ret < 0 && errno != EINTR)
        {
          conn->ping_pending = 0;
          return -1;
        }
      if (ret <= 0)
        continue;

      /* Process incoming frames to receive PING ACK */
      /* SOCKETPOLL_EVENTS_READ = 1 */
      if (SocketHTTP2_Conn_process (conn, 1) < 0)
        {
          conn->ping_pending = 0;
          return -1;
        }
    }

  /* Return RTT in milliseconds */
  return (int)(Socket_get_monotonic_ms () - start_ms);
}

uint32_t
SocketHTTP2_Conn_get_concurrent_streams (SocketHTTP2_Conn_T conn)
{
  uint32_t count = 0;

  assert (conn);

  /* Count active streams (non-idle, non-closed) */
  for (uint32_t i = 0; i < HTTP2_STREAM_HASH_SIZE; i++)
    {
      struct SocketHTTP2_Stream *s;
      for (s = conn->streams[i]; s != NULL; s = s->hash_next)
        {
          SocketHTTP2_StreamState state = s->state;
          if (state != HTTP2_STREAM_STATE_IDLE
              && state != HTTP2_STREAM_STATE_CLOSED)
            {
              count++;
            }
        }
    }

  return count;
}

int
SocketHTTP2_Conn_set_max_concurrent (SocketHTTP2_Conn_T conn, uint32_t max)
{
  SocketHTTP2_Setting setting;

  assert (conn);

  if (max == 0 || max > 0x7FFFFFFF)
    return -1;

  /* Update local setting (index is id - 1) */
  conn->local_settings[SETTINGS_IDX_MAX_CONCURRENT_STREAMS] = max;

  /* Send SETTINGS frame to peer */
  setting.id = HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  setting.value = max;

  return SocketHTTP2_Conn_settings (conn, &setting, 1);
}
