/**
 * SocketHTTP2-connection.c - HTTP/2 Connection Management
 *
 * Part of the Socket Library
 *
 * Implements:
 * - Connection lifecycle (new, free)
 * - Connection preface exchange
 * - SETTINGS frame handling
 * - PING/GOAWAY handling
 * - Frame processing dispatch
 */

#include "http/SocketHTTP2-private.h"
#include "http/SocketHTTP2.h"

#include "core/SocketUtil.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"

#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Module Exception Setup
 * ============================================================================ */

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "HTTP2"

SOCKET_DECLARE_MODULE_EXCEPTION (SocketHTTP2);

#define RAISE_HTTP2_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketHTTP2, e)

/* ============================================================================
 * Default Configuration
 * ============================================================================ */

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

  config->connection_window_size = SOCKETHTTP2_CONNECTION_WINDOW_SIZE;

  /* Default timeouts */
  config->settings_timeout_ms = 30000; /* 30 seconds */
  config->ping_timeout_ms = 30000;     /* 30 seconds */
  config->idle_timeout_ms = 0;         /* No idle timeout by default */
}

/* ============================================================================
 * Connection Creation
 * ============================================================================ */

SocketHTTP2_Conn_T
SocketHTTP2_Conn_new (Socket_T socket, const SocketHTTP2_Config *config,
                      Arena_T arena)
{
  SocketHTTP2_Conn_T conn;
  SocketHTTP2_Config default_config;
  SocketHPACK_EncoderConfig enc_config;
  SocketHPACK_DecoderConfig dec_config;

  assert (socket);
  assert (arena);

  /* Use default config if none provided */
  if (config == NULL)
    {
      SocketHTTP2_config_defaults (&default_config, HTTP2_ROLE_CLIENT);
      config = &default_config;
    }

  /* Allocate connection structure */
  conn = Arena_alloc (arena, sizeof (*conn), __FILE__, __LINE__);
  if (!conn)
    {
      SOCKET_ERROR_MSG ("Failed to allocate HTTP/2 connection");
      RAISE_HTTP2_ERROR (SocketHTTP2_ProtocolError);
    }
  memset (conn, 0, sizeof (*conn));

  conn->socket = socket;
  conn->arena = arena;
  conn->role = config->role;
  conn->state = HTTP2_CONN_STATE_INIT;

  /* Initialize local settings from config */
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

  /* Initialize peer settings to RFC defaults */
  conn->peer_settings[SETTINGS_IDX_HEADER_TABLE_SIZE]
      = SOCKETHTTP2_DEFAULT_HEADER_TABLE_SIZE;
  conn->peer_settings[SETTINGS_IDX_ENABLE_PUSH] = 1;
  conn->peer_settings[SETTINGS_IDX_MAX_CONCURRENT_STREAMS] = UINT32_MAX;
  conn->peer_settings[SETTINGS_IDX_INITIAL_WINDOW_SIZE]
      = SOCKETHTTP2_DEFAULT_INITIAL_WINDOW_SIZE;
  conn->peer_settings[SETTINGS_IDX_MAX_FRAME_SIZE]
      = SOCKETHTTP2_DEFAULT_MAX_FRAME_SIZE;
  conn->peer_settings[SETTINGS_IDX_MAX_HEADER_LIST_SIZE] = UINT32_MAX;

  /* Initialize flow control */
  conn->send_window = SOCKETHTTP2_DEFAULT_INITIAL_WINDOW_SIZE;
  conn->recv_window = (int32_t)config->connection_window_size;
  conn->initial_send_window = SOCKETHTTP2_DEFAULT_INITIAL_WINDOW_SIZE;
  conn->initial_recv_window = (int32_t)config->initial_window_size;

  /* Create I/O buffers */
  conn->recv_buf = SocketBuf_new (arena, 64 * 1024); /* 64KB receive buffer */
  conn->send_buf = SocketBuf_new (arena, 64 * 1024); /* 64KB send buffer */
  if (!conn->recv_buf || !conn->send_buf)
    {
      SOCKET_ERROR_MSG ("Failed to allocate HTTP/2 I/O buffers");
      RAISE_HTTP2_ERROR (SocketHTTP2_ProtocolError);
    }

  /* Create HPACK encoder */
  SocketHPACK_encoder_config_defaults (&enc_config);
  enc_config.max_table_size = config->header_table_size;
  conn->encoder = SocketHPACK_Encoder_new (&enc_config, arena);
  if (!conn->encoder)
    {
      SOCKET_ERROR_MSG ("Failed to create HPACK encoder");
      RAISE_HTTP2_ERROR (SocketHTTP2_ProtocolError);
    }

  /* Create HPACK decoder */
  SocketHPACK_decoder_config_defaults (&dec_config);
  dec_config.max_table_size = config->header_table_size;
  dec_config.max_header_list_size = config->max_header_list_size;
  conn->decoder = SocketHPACK_Decoder_new (&dec_config, arena);
  if (!conn->decoder)
    {
      SOCKET_ERROR_MSG ("Failed to create HPACK decoder");
      RAISE_HTTP2_ERROR (SocketHTTP2_ProtocolError);
    }

  /* Allocate stream hash table */
  conn->streams = Arena_calloc (arena, HTTP2_STREAM_HASH_SIZE,
                                sizeof (*conn->streams), __FILE__, __LINE__);
  if (!conn->streams)
    {
      SOCKET_ERROR_MSG ("Failed to allocate stream hash table");
      RAISE_HTTP2_ERROR (SocketHTTP2_ProtocolError);
    }

  /* Initialize stream IDs based on role */
  if (config->role == HTTP2_ROLE_CLIENT)
    {
      conn->next_stream_id = 1; /* Client uses odd IDs */
    }
  else
    {
      conn->next_stream_id = 2; /* Server uses even IDs */
    }

  /* Store timeouts */
  conn->settings_timeout_ms = config->settings_timeout_ms;
  conn->ping_timeout_ms = config->ping_timeout_ms;
  conn->idle_timeout_ms = config->idle_timeout_ms;

  return conn;
}

void
SocketHTTP2_Conn_free (SocketHTTP2_Conn_T *conn)
{
  if (!conn || !*conn)
    return;

  SocketHTTP2_Conn_T c = *conn;

  /* Free all streams */
  for (size_t i = 0; i < HTTP2_STREAM_HASH_SIZE; i++)
    {
      SocketHTTP2_Stream_T stream = c->streams[i];
      while (stream)
        {
          SocketHTTP2_Stream_T next = stream->hash_next;
          /* Stream memory managed by arena, just clear the pointer */
          stream = next;
        }
    }

  /* Free HPACK encoder/decoder */
  if (c->encoder)
    SocketHPACK_Encoder_free (&c->encoder);
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

/* ============================================================================
 * Connection Accessors
 * ============================================================================ */

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

uint32_t
SocketHTTP2_Conn_get_setting (SocketHTTP2_Conn_T conn,
                              SocketHTTP2_SettingsId id)
{
  assert (conn);
  if (id >= 1 && id <= HTTP2_SETTINGS_COUNT)
    {
      return conn->peer_settings[id - 1];
    }
  return 0;
}

uint32_t
SocketHTTP2_Conn_get_local_setting (SocketHTTP2_Conn_T conn,
                                    SocketHTTP2_SettingsId id)
{
  assert (conn);
  if (id >= 1 && id <= HTTP2_SETTINGS_COUNT)
    {
      return conn->local_settings[id - 1];
    }
  return 0;
}

uint32_t
SocketHTTP2_Conn_last_stream_id (SocketHTTP2_Conn_T conn)
{
  assert (conn);
  return conn->last_peer_stream_id;
}

/* ============================================================================
 * Flow Control Accessors
 * ============================================================================ */

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

/* ============================================================================
 * Callbacks
 * ============================================================================ */

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

/* ============================================================================
 * Connection Preface and Handshake
 * ============================================================================ */

/**
 * send_initial_settings - Send our SETTINGS frame
 */
static int
send_initial_settings (SocketHTTP2_Conn_T conn)
{
  SocketHTTP2_FrameHeader header;
  unsigned char payload[HTTP2_SETTINGS_COUNT * 6];
  size_t payload_len = 0;

  /* Build settings payload - only send non-default values */
  for (int i = 0; i < HTTP2_SETTINGS_COUNT; i++)
    {
      uint32_t value = conn->local_settings[i];
      uint16_t id = i + 1;

      /* Skip default values to reduce frame size */
      int skip = 0;
      switch (id)
        {
        case HTTP2_SETTINGS_HEADER_TABLE_SIZE:
          skip = (value == SOCKETHTTP2_DEFAULT_HEADER_TABLE_SIZE);
          break;
        case HTTP2_SETTINGS_ENABLE_PUSH:
          skip = (value == 1);
          break;
        case HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
          skip = 0; /* Always send this one */
          break;
        case HTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
          skip = (value == SOCKETHTTP2_DEFAULT_INITIAL_WINDOW_SIZE);
          break;
        case HTTP2_SETTINGS_MAX_FRAME_SIZE:
          skip = (value == SOCKETHTTP2_DEFAULT_MAX_FRAME_SIZE);
          break;
        case HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE:
          skip = 0; /* Always send this one */
          break;
        }

      if (!skip)
        {
          /* ID: 16-bit big-endian */
          payload[payload_len++] = (unsigned char)((id >> 8) & 0xFF);
          payload[payload_len++] = (unsigned char)(id & 0xFF);
          /* Value: 32-bit big-endian */
          payload[payload_len++] = (unsigned char)((value >> 24) & 0xFF);
          payload[payload_len++] = (unsigned char)((value >> 16) & 0xFF);
          payload[payload_len++] = (unsigned char)((value >> 8) & 0xFF);
          payload[payload_len++] = (unsigned char)(value & 0xFF);
        }
    }

  header.length = (uint32_t)payload_len;
  header.type = HTTP2_FRAME_SETTINGS;
  header.flags = 0;
  header.stream_id = 0;

  return http2_frame_send (conn, &header, payload, payload_len);
}

int
SocketHTTP2_Conn_handshake (SocketHTTP2_Conn_T conn)
{
  assert (conn);

  switch (conn->state)
    {
    case HTTP2_CONN_STATE_INIT:
      if (conn->role == HTTP2_ROLE_CLIENT)
        {
          /* Client sends preface first */
          if (SocketBuf_write (conn->send_buf, HTTP2_CLIENT_PREFACE,
                               HTTP2_PREFACE_SIZE)
              != HTTP2_PREFACE_SIZE)
            {
              return -1;
            }
          conn->state = HTTP2_CONN_STATE_PREFACE_SENT;
        }
      else
        {
          /* Server waits for client preface */
          conn->state = HTTP2_CONN_STATE_INIT;
          return 1; /* In progress - waiting for preface */
        }
      /* Fall through to send settings */
      /* FALLTHROUGH */

    case HTTP2_CONN_STATE_PREFACE_SENT:
    case HTTP2_CONN_STATE_PREFACE_RECV:
      /* Send our SETTINGS */
      if (send_initial_settings (conn) < 0)
        {
          return -1;
        }
      conn->settings_ack_pending = 1;
      conn->state = HTTP2_CONN_STATE_SETTINGS_SENT;

      /* If connection-level window is larger than default, send WINDOW_UPDATE
       */
      if (conn->recv_window > SOCKETHTTP2_DEFAULT_INITIAL_WINDOW_SIZE)
        {
          uint32_t increment
              = (uint32_t)conn->recv_window - SOCKETHTTP2_DEFAULT_INITIAL_WINDOW_SIZE;
          SocketHTTP2_Conn_window_update (conn, increment);
        }
      return 1; /* In progress */

    case HTTP2_CONN_STATE_SETTINGS_SENT:
      /* Waiting for SETTINGS from peer */
      return 1;

    case HTTP2_CONN_STATE_SETTINGS_RECV:
      /* Received peer SETTINGS, still waiting for ACK */
      return 1;

    case HTTP2_CONN_STATE_READY:
      return 0; /* Complete */

    default:
      return -1;
    }
}

/* ============================================================================
 * SETTINGS Frame
 * ============================================================================ */

int
SocketHTTP2_Conn_settings (SocketHTTP2_Conn_T conn,
                           const SocketHTTP2_Setting *settings, size_t count)
{
  SocketHTTP2_FrameHeader header;
  unsigned char *payload;
  size_t payload_len;

  assert (conn);

  payload_len = count * 6;
  payload = Arena_alloc (conn->arena, payload_len, __FILE__, __LINE__);
  if (!payload)
    {
      return -1;
    }

  /* Build payload */
  for (size_t i = 0; i < count; i++)
    {
      size_t offset = i * 6;
      payload[offset + 0] = (unsigned char)((settings[i].id >> 8) & 0xFF);
      payload[offset + 1] = (unsigned char)(settings[i].id & 0xFF);
      payload[offset + 2]
          = (unsigned char)((settings[i].value >> 24) & 0xFF);
      payload[offset + 3]
          = (unsigned char)((settings[i].value >> 16) & 0xFF);
      payload[offset + 4] = (unsigned char)((settings[i].value >> 8) & 0xFF);
      payload[offset + 5] = (unsigned char)(settings[i].value & 0xFF);

      /* Update local settings */
      if (settings[i].id >= 1 && settings[i].id <= HTTP2_SETTINGS_COUNT)
        {
          conn->local_settings[settings[i].id - 1] = settings[i].value;
        }
    }

  header.length = (uint32_t)payload_len;
  header.type = HTTP2_FRAME_SETTINGS;
  header.flags = 0;
  header.stream_id = 0;

  conn->settings_ack_pending = 1;
  return http2_frame_send (conn, &header, payload, payload_len);
}

/* ============================================================================
 * PING Frame
 * ============================================================================ */

int
SocketHTTP2_Conn_ping (SocketHTTP2_Conn_T conn, const unsigned char opaque[8])
{
  SocketHTTP2_FrameHeader header;
  unsigned char payload[8];

  assert (conn);

  if (opaque)
    {
      memcpy (payload, opaque, 8);
    }
  else
    {
      /* Generate opaque data using monotonic time */
      int64_t time_ms = Socket_get_monotonic_ms ();
      memcpy (payload, &time_ms, sizeof (time_ms));
    }

  /* Store for matching ACK */
  memcpy (conn->ping_opaque, payload, 8);
  conn->ping_pending = 1;

  header.length = 8;
  header.type = HTTP2_FRAME_PING;
  header.flags = 0;
  header.stream_id = 0;

  return http2_frame_send (conn, &header, payload, 8);
}

/* ============================================================================
 * GOAWAY Frame
 * ============================================================================ */

int
SocketHTTP2_Conn_goaway (SocketHTTP2_Conn_T conn,
                         SocketHTTP2_ErrorCode error_code,
                         const void *debug_data, size_t debug_len)
{
  SocketHTTP2_FrameHeader header;
  unsigned char *payload;
  size_t payload_len;

  assert (conn);

  payload_len = 8 + debug_len;
  payload = Arena_alloc (conn->arena, payload_len, __FILE__, __LINE__);
  if (!payload)
    {
      return -1;
    }

  /* Last stream ID: 31-bit big-endian */
  payload[0] = (unsigned char)((conn->last_peer_stream_id >> 24) & 0x7F);
  payload[1] = (unsigned char)((conn->last_peer_stream_id >> 16) & 0xFF);
  payload[2] = (unsigned char)((conn->last_peer_stream_id >> 8) & 0xFF);
  payload[3] = (unsigned char)(conn->last_peer_stream_id & 0xFF);

  /* Error code: 32-bit big-endian */
  payload[4] = (unsigned char)((error_code >> 24) & 0xFF);
  payload[5] = (unsigned char)((error_code >> 16) & 0xFF);
  payload[6] = (unsigned char)((error_code >> 8) & 0xFF);
  payload[7] = (unsigned char)(error_code & 0xFF);

  /* Debug data */
  if (debug_len > 0 && debug_data)
    {
      memcpy (payload + 8, debug_data, debug_len);
    }

  header.length = (uint32_t)payload_len;
  header.type = HTTP2_FRAME_GOAWAY;
  header.flags = 0;
  header.stream_id = 0;

  conn->goaway_sent = 1;
  conn->goaway_error_code = error_code;

  return http2_frame_send (conn, &header, payload, payload_len);
}

/* ============================================================================
 * WINDOW_UPDATE Frame
 * ============================================================================ */

int
SocketHTTP2_Conn_window_update (SocketHTTP2_Conn_T conn, uint32_t increment)
{
  SocketHTTP2_FrameHeader header;
  unsigned char payload[4];

  assert (conn);
  assert (increment > 0 && increment <= 0x7FFFFFFF);

  /* Increment: 31-bit big-endian */
  payload[0] = (unsigned char)((increment >> 24) & 0x7F);
  payload[1] = (unsigned char)((increment >> 16) & 0xFF);
  payload[2] = (unsigned char)((increment >> 8) & 0xFF);
  payload[3] = (unsigned char)(increment & 0xFF);

  header.length = 4;
  header.type = HTTP2_FRAME_WINDOW_UPDATE;
  header.flags = 0;
  header.stream_id = 0;

  return http2_frame_send (conn, &header, payload, 4);
}

/* ============================================================================
 * Frame Processing
 * ============================================================================ */

int
SocketHTTP2_Conn_process (SocketHTTP2_Conn_T conn, unsigned events)
{
  ssize_t n;
  size_t available;
  unsigned char *data;

  assert (conn);
  (void)events; /* May use for POLL_READ/POLL_WRITE optimization later */

  /* Read data from socket into receive buffer */
  {
    size_t space;
    void *write_ptr = SocketBuf_writeptr (conn->recv_buf, &space);
    if (write_ptr && space > 0)
      {
        n = Socket_recv (conn->socket, write_ptr, space);
        if (n > 0)
          {
            SocketBuf_written (conn->recv_buf, (size_t)n);
          }
        else if (n < 0)
          {
            return -1;
          }
      }
  }

  /* Check for client preface (server only) */
  if (conn->role == HTTP2_ROLE_SERVER
      && conn->state == HTTP2_CONN_STATE_INIT)
    {
      available = SocketBuf_available (conn->recv_buf);
      if (available >= HTTP2_PREFACE_SIZE)
        {
          unsigned char preface[HTTP2_PREFACE_SIZE];
          SocketBuf_peek (conn->recv_buf, preface, HTTP2_PREFACE_SIZE);

          if (memcmp (preface, HTTP2_CLIENT_PREFACE, HTTP2_PREFACE_SIZE) != 0)
            {
              http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
              return -1;
            }

          SocketBuf_consume (conn->recv_buf, HTTP2_PREFACE_SIZE);
          conn->state = HTTP2_CONN_STATE_PREFACE_RECV;

          /* Now send our settings */
          if (SocketHTTP2_Conn_handshake (conn) < 0)
            {
              return -1;
            }
        }
      else
        {
          return 0; /* Need more data */
        }
    }

  /* Process frames */
  while (1)
    {
      SocketHTTP2_FrameHeader header;
      SocketHTTP2_ErrorCode error;
      const unsigned char *payload;
      size_t read_len;

      available = SocketBuf_available (conn->recv_buf);
      if (available < HTTP2_FRAME_HEADER_SIZE)
        {
          break; /* Need more data */
        }

      /* Peek at frame header */
      data = (unsigned char *)SocketBuf_readptr (conn->recv_buf, &read_len);
      if (!data || read_len < HTTP2_FRAME_HEADER_SIZE)
        {
          break;
        }

      SocketHTTP2_frame_header_parse (data, &header);

      /* Check if we have complete frame */
      if (available < HTTP2_FRAME_HEADER_SIZE + header.length)
        {
          break; /* Need more data */
        }

      /* Validate frame */
      error = http2_frame_validate (conn, &header);
      if (error != HTTP2_NO_ERROR)
        {
          if (header.stream_id == 0)
            {
              http2_send_connection_error (conn, error);
              return -1;
            }
          else
            {
              http2_send_stream_error (conn, header.stream_id, error);
              /* Skip this frame and continue */
              SocketBuf_consume (conn->recv_buf,
                                 HTTP2_FRAME_HEADER_SIZE + header.length);
              continue;
            }
        }

      /* Get payload pointer */
      payload = data + HTTP2_FRAME_HEADER_SIZE;

      /* Process the frame */
      if (http2_process_frame (conn, &header, payload) < 0)
        {
          return -1;
        }

      /* Consume the frame */
      SocketBuf_consume (conn->recv_buf,
                         HTTP2_FRAME_HEADER_SIZE + header.length);
    }

  return 0;
}

/* ============================================================================
 * Flush Output
 * ============================================================================ */

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
        }
      else if (sent == 0)
        {
          /* Would block */
          return 1;
        }
      else
        {
          return -1;
        }
    }

  return 0;
}

/* ============================================================================
 * Frame Processing Dispatch
 * ============================================================================ */

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
      return http2_process_priority (conn, header, payload);

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

    default:
      /* Unknown frame types are ignored (RFC 9113 Section 4.1) */
      return 0;
    }
}

/* ============================================================================
 * SETTINGS Processing
 * ============================================================================ */

int
http2_process_settings (SocketHTTP2_Conn_T conn,
                        const SocketHTTP2_FrameHeader *header,
                        const unsigned char *payload)
{
  /* SETTINGS ACK */
  if (header->flags & HTTP2_FLAG_ACK)
    {
      if (conn->settings_ack_pending)
        {
          conn->settings_ack_pending = 0;
          if (conn->state == HTTP2_CONN_STATE_SETTINGS_SENT)
            {
              conn->state = HTTP2_CONN_STATE_READY;
            }
          http2_emit_conn_event (conn, HTTP2_EVENT_SETTINGS_ACK);
        }
      return 0;
    }

  /* Parse settings */
  size_t count = header->length / 6;
  for (size_t i = 0; i < count; i++)
    {
      size_t offset = i * 6;
      uint16_t id = ((uint16_t)payload[offset] << 8) | payload[offset + 1];
      uint32_t value = ((uint32_t)payload[offset + 2] << 24)
                       | ((uint32_t)payload[offset + 3] << 16)
                       | ((uint32_t)payload[offset + 4] << 8)
                       | payload[offset + 5];

      /* Validate setting values */
      switch (id)
        {
        case HTTP2_SETTINGS_ENABLE_PUSH:
          if (value > 1)
            {
              http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
              return -1;
            }
          break;

        case HTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
          if (value > 0x7FFFFFFF)
            {
              http2_send_connection_error (conn, HTTP2_FLOW_CONTROL_ERROR);
              return -1;
            }
          /* Adjust existing stream windows */
          {
            int32_t delta
                = (int32_t)value
                  - (int32_t)conn->peer_settings[SETTINGS_IDX_INITIAL_WINDOW_SIZE];
            for (size_t j = 0; j < HTTP2_STREAM_HASH_SIZE; j++)
              {
                SocketHTTP2_Stream_T s = conn->streams[j];
                while (s)
                  {
                    s->send_window += delta;
                    s = s->hash_next;
                  }
              }
            conn->initial_send_window = (int32_t)value;
          }
          break;

        case HTTP2_SETTINGS_MAX_FRAME_SIZE:
          if (value < SOCKETHTTP2_DEFAULT_MAX_FRAME_SIZE
              || value > SOCKETHTTP2_MAX_MAX_FRAME_SIZE)
            {
              http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
              return -1;
            }
          break;

        case HTTP2_SETTINGS_HEADER_TABLE_SIZE:
          /* Update HPACK encoder table size */
          SocketHPACK_Encoder_set_table_size (conn->encoder, value);
          break;
        }

      /* Store setting */
      if (id >= 1 && id <= HTTP2_SETTINGS_COUNT)
        {
          conn->peer_settings[id - 1] = value;
        }
    }

  /* Send SETTINGS ACK */
  {
    SocketHTTP2_FrameHeader ack_header;
    ack_header.length = 0;
    ack_header.type = HTTP2_FRAME_SETTINGS;
    ack_header.flags = HTTP2_FLAG_ACK;
    ack_header.stream_id = 0;
    http2_frame_send (conn, &ack_header, NULL, 0);
  }

  /* Update connection state */
  if (conn->state == HTTP2_CONN_STATE_SETTINGS_SENT
      || conn->state == HTTP2_CONN_STATE_PREFACE_RECV)
    {
      conn->state = HTTP2_CONN_STATE_SETTINGS_RECV;
      if (!conn->settings_ack_pending)
        {
          conn->state = HTTP2_CONN_STATE_READY;
        }
    }

  return 0;
}

/* ============================================================================
 * PING Processing
 * ============================================================================ */

int
http2_process_ping (SocketHTTP2_Conn_T conn,
                    const SocketHTTP2_FrameHeader *header,
                    const unsigned char *payload)
{
  /* PING ACK */
  if (header->flags & HTTP2_FLAG_ACK)
    {
      if (conn->ping_pending
          && memcmp (payload, conn->ping_opaque, 8) == 0)
        {
          conn->ping_pending = 0;
          http2_emit_conn_event (conn, HTTP2_EVENT_PING_ACK);
        }
      return 0;
    }

  /* Echo PING with ACK flag */
  SocketHTTP2_FrameHeader response;
  response.length = 8;
  response.type = HTTP2_FRAME_PING;
  response.flags = HTTP2_FLAG_ACK;
  response.stream_id = 0;

  return http2_frame_send (conn, &response, payload, 8);
}

/* ============================================================================
 * GOAWAY Processing
 * ============================================================================ */

int
http2_process_goaway (SocketHTTP2_Conn_T conn,
                      const SocketHTTP2_FrameHeader *header,
                      const unsigned char *payload)
{
  (void)header;

  /* Parse last stream ID and error code */
  conn->max_peer_stream_id = ((uint32_t)(payload[0] & 0x7F) << 24)
                             | ((uint32_t)payload[1] << 16)
                             | ((uint32_t)payload[2] << 8) | payload[3];

  conn->goaway_error_code = (SocketHTTP2_ErrorCode) (
      ((uint32_t)payload[4] << 24) | ((uint32_t)payload[5] << 16)
      | ((uint32_t)payload[6] << 8) | payload[7]);

  conn->goaway_received = 1;

  http2_emit_conn_event (conn, HTTP2_EVENT_GOAWAY_RECEIVED);

  return 0;
}

/* ============================================================================
 * WINDOW_UPDATE Processing
 * ============================================================================ */

int
http2_process_window_update (SocketHTTP2_Conn_T conn,
                             const SocketHTTP2_FrameHeader *header,
                             const unsigned char *payload)
{
  uint32_t increment = ((uint32_t)(payload[0] & 0x7F) << 24)
                       | ((uint32_t)payload[1] << 16)
                       | ((uint32_t)payload[2] << 8) | payload[3];

  if (increment == 0)
    {
      if (header->stream_id == 0)
        {
          http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
        }
      else
        {
          http2_send_stream_error (conn, header->stream_id,
                                   HTTP2_PROTOCOL_ERROR);
        }
      return -1;
    }

  if (header->stream_id == 0)
    {
      /* Connection-level window update */
      if (http2_flow_update_send (conn, NULL, increment) < 0)
        {
          http2_send_connection_error (conn, HTTP2_FLOW_CONTROL_ERROR);
          return -1;
        }
    }
  else
    {
      /* Stream-level window update */
      SocketHTTP2_Stream_T stream = http2_stream_lookup (conn, header->stream_id);
      if (stream)
        {
          if (http2_flow_update_send (conn, stream, increment) < 0)
            {
              http2_send_stream_error (conn, header->stream_id,
                                       HTTP2_FLOW_CONTROL_ERROR);
              return -1;
            }
          http2_emit_stream_event (conn, stream, HTTP2_EVENT_WINDOW_UPDATE);
        }
      /* Ignore window updates for unknown streams (they may be closed) */
    }

  return 0;
}

/* ============================================================================
 * RST_STREAM Processing
 * ============================================================================ */

/**
 * http2_process_rst_stream - Process RST_STREAM frame with rate limiting
 * @conn: HTTP/2 connection
 * @header: Frame header
 * @payload: Frame payload (4 bytes error code)
 *
 * Returns: 0 on success, -1 on error (connection closed)
 *
 * Security: Implements rate limiting to protect against CVE-2023-44487
 * (HTTP/2 Rapid Reset Attack). If a client sends RST_STREAM frames
 * faster than SOCKETHTTP2_RST_RATE_LIMIT per SOCKETHTTP2_RST_RATE_WINDOW_MS,
 * the connection is terminated with ENHANCE_YOUR_CALM.
 */
int
http2_process_rst_stream (SocketHTTP2_Conn_T conn,
                          const SocketHTTP2_FrameHeader *header,
                          const unsigned char *payload)
{
  uint32_t error_code = ((uint32_t)payload[0] << 24)
                        | ((uint32_t)payload[1] << 16)
                        | ((uint32_t)payload[2] << 8) | payload[3];
  int64_t now_ms;

  /* CVE-2023-44487: Rate limit RST_STREAM frames to prevent Rapid Reset DoS */
  now_ms = Socket_get_monotonic_ms ();

  /* Reset window if expired */
  if (now_ms - conn->rst_window_start_ms > SOCKETHTTP2_RST_RATE_WINDOW_MS)
    {
      conn->rst_window_start_ms = now_ms;
      conn->rst_count_in_window = 0;
    }

  /* Increment count and check limit */
  conn->rst_count_in_window++;
  if (conn->rst_count_in_window > SOCKETHTTP2_RST_RATE_LIMIT)
    {
      /* Rate limit exceeded - send GOAWAY with ENHANCE_YOUR_CALM */
      SOCKET_LOG_WARN_MSG ("HTTP/2 RST_STREAM rate limit exceeded "
                           "(%" PRIu32 " in %" PRId64 "ms), "
                           "closing connection (CVE-2023-44487 protection)",
                           conn->rst_count_in_window,
                           now_ms - conn->rst_window_start_ms);
      http2_send_connection_error (conn, HTTP2_ENHANCE_YOUR_CALM);
      return -1;
    }

  /* Normal RST_STREAM processing */
  SocketHTTP2_Stream_T stream = http2_stream_lookup (conn, header->stream_id);
  if (stream)
    {
      stream->state = HTTP2_STREAM_STATE_CLOSED;
      http2_emit_stream_event (conn, stream, HTTP2_EVENT_STREAM_RESET);
    }

  (void)error_code; /* Could log or store for debugging */

  return 0;
}

/* ============================================================================
 * PRIORITY Processing (Deprecated)
 * ============================================================================ */

int
http2_process_priority (SocketHTTP2_Conn_T conn,
                        const SocketHTTP2_FrameHeader *header,
                        const unsigned char *payload)
{
  /* RFC 9113: PRIORITY frames are deprecated and should be ignored */
  (void)conn;
  (void)header;
  (void)payload;
  return 0;
}

/* ============================================================================
 * h2c Upgrade Support
 * ============================================================================ */

SocketHTTP2_Conn_T
SocketHTTP2_Conn_upgrade_client (Socket_T socket,
                                 const unsigned char *settings_payload,
                                 size_t settings_len, Arena_T arena)
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
  conn->state = HTTP2_CONN_STATE_SETTINGS_SENT;

  return conn;
}

SocketHTTP2_Conn_T
SocketHTTP2_Conn_upgrade_server (Socket_T socket,
                                 const SocketHTTP_Request *initial_request,
                                 const unsigned char *settings_payload,
                                 size_t settings_len, Arena_T arena)
{
  SocketHTTP2_Config config;
  SocketHTTP2_Conn_T conn;
  SocketHTTP2_Stream_T stream;

  (void)settings_payload;
  (void)settings_len;
  (void)initial_request;

  SocketHTTP2_config_defaults (&config, HTTP2_ROLE_SERVER);
  conn = SocketHTTP2_Conn_new (socket, &config, arena);
  if (!conn)
    return NULL;

  /* For h2c upgrade, skip the preface - client already sent HTTP/1.1 upgrade
   */
  conn->state = HTTP2_CONN_STATE_PREFACE_RECV;

  /* Create stream 1 for the upgraded request */
  stream = http2_stream_create (conn, 1);
  if (!stream)
    {
      SocketHTTP2_Conn_free (&conn);
      return NULL;
    }
  stream->state = HTTP2_STREAM_STATE_HALF_CLOSED_REMOTE;
  conn->last_peer_stream_id = 1;

  /* Send SETTINGS */
  if (send_initial_settings (conn) < 0)
    {
      SocketHTTP2_Conn_free (&conn);
      return NULL;
    }
  conn->settings_ack_pending = 1;
  conn->state = HTTP2_CONN_STATE_SETTINGS_SENT;

  return conn;
}

