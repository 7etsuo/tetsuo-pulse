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
#include <string.h>

/* ============================================================================
 * Module Exception Setup
 * ============================================================================ */

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "HTTP2"

SOCKET_DECLARE_MODULE_EXCEPTION (SocketHTTP2);

#define RAISE_HTTP2_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketHTTP2, e)

/* ============================================================================
 * Configuration Constants
 * ============================================================================ */









/* I/O buffer size defined in SocketHTTP2.h */



/* Timeouts and max window defined in SocketHTTP2.h */

/* ============================================================================
 * Big-Endian Serialization Helpers
 * ============================================================================ */

/**
 * write_u16_be - Write 16-bit value in big-endian format
 * @buf: Output buffer (at least 2 bytes)
 * @value: Value to write
 */
static inline void
write_u16_be (unsigned char *buf, uint16_t value)
{
  buf[0] = (unsigned char) ((value >> 8) & 0xFF);
  buf[1] = (unsigned char) (value & 0xFF);
}

/**
 * write_u32_be - Write 32-bit value in big-endian format
 * @buf: Output buffer (at least 4 bytes)
 * @value: Value to write
 */
static inline void
write_u32_be (unsigned char *buf, uint32_t value)
{
  buf[0] = (unsigned char) ((value >> 24) & 0xFF);
  buf[1] = (unsigned char) ((value >> 16) & 0xFF);
  buf[2] = (unsigned char) ((value >> 8) & 0xFF);
  buf[3] = (unsigned char) (value & 0xFF);
}

/**
 * write_u31_be - Write 31-bit value (high bit clear) in big-endian format
 * @buf: Output buffer (at least 4 bytes)
 * @value: Value to write (must be <= 0x7FFFFFFF)
 */
static inline void
write_u31_be (unsigned char *buf, uint32_t value)
{
  buf[0] = (unsigned char) ((value >> 24) & 0x7F);
  buf[1] = (unsigned char) ((value >> 16) & 0xFF);
  buf[2] = (unsigned char) ((value >> 8) & 0xFF);
  buf[3] = (unsigned char) (value & 0xFF);
}

/**
 * read_u16_be - Read 16-bit value from big-endian buffer
 * @buf: Input buffer (at least 2 bytes)
 *
 * Returns: 16-bit value
 */
static inline uint16_t
read_u16_be (const unsigned char *buf)
{
  return ((uint16_t) buf[0] << 8) | buf[1];
}

/**
 * read_u32_be - Read 32-bit value from big-endian buffer
 * @buf: Input buffer (at least 4 bytes)
 *
 * Returns: 32-bit value
 */
static inline uint32_t
read_u32_be (const unsigned char *buf)
{
  return ((uint32_t) buf[0] << 24) | ((uint32_t) buf[1] << 16)
         | ((uint32_t) buf[2] << 8) | buf[3];
}

/**
 * read_u31_be - Read 31-bit value (masking high bit) from big-endian buffer
 * @buf: Input buffer (at least 4 bytes)
 *
 * Returns: 31-bit value
 */
static inline uint32_t
read_u31_be (const unsigned char *buf)
{
  return ((uint32_t) (buf[0] & 0x7F) << 24) | ((uint32_t) buf[1] << 16)
         | ((uint32_t) buf[2] << 8) | buf[3];
}

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
  config->settings_timeout_ms = SOCKETHTTP2_DEFAULT_SETTINGS_TIMEOUT_MS;
  config->ping_timeout_ms = SOCKETHTTP2_DEFAULT_PING_TIMEOUT_MS;
  config->idle_timeout_ms = 0; /* No idle timeout by default */
}

/* ============================================================================
 * Connection Creation Helpers
 * ============================================================================ */

/**
 * init_local_settings - Copy configuration settings to local settings array
 * @conn: Connection structure containing local_settings array
 * @config: Source configuration with desired settings values
 *
 * Initializes the connection's local settings array with values from the
 * provided configuration. These settings will be sent to the peer during
 * the initial SETTINGS frame exchange.
 *
 * Thread-safe: No - connection must not be accessed concurrently
 */
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
}

static const uint32_t peer_setting_defaults[HTTP2_SETTINGS_COUNT] = {
    SOCKETHTTP2_DEFAULT_HEADER_TABLE_SIZE,
    SOCKETHTTP2_DEFAULT_ENABLE_PUSH,
    UINT32_MAX,  /* SETTINGS_MAX_CONCURRENT_STREAMS: unbounded initially */
    SOCKETHTTP2_DEFAULT_INITIAL_WINDOW_SIZE,
    SOCKETHTTP2_DEFAULT_MAX_FRAME_SIZE,
    UINT32_MAX   /* SETTINGS_MAX_HEADER_LIST_SIZE: unbounded initially */
};

/**
 * init_peer_settings - Set peer settings to RFC 9113 default values
 * @conn: Connection structure containing peer_settings array
 *
 * Initializes the peer settings array to default values as specified in
 * RFC 9113 Section 6.5.2. These values are used until the peer sends
 * their SETTINGS frame. UINT32_MAX is used for unbounded settings.
 *
 * Thread-safe: No - connection must not be accessed concurrently
 */
static void
init_peer_settings (SocketHTTP2_Conn_T conn)
{
  memcpy (conn->peer_settings, peer_setting_defaults, sizeof (peer_setting_defaults));
}

/**
 * init_flow_control - Initialize flow control windows
 * @conn: Connection to initialize
 * @config: Configuration source
 */
static void
init_flow_control (SocketHTTP2_Conn_T conn, const SocketHTTP2_Config *config)
{
  conn->send_window = SOCKETHTTP2_DEFAULT_INITIAL_WINDOW_SIZE;
  conn->recv_window = (int32_t) config->connection_window_size;
  conn->initial_send_window = SOCKETHTTP2_DEFAULT_INITIAL_WINDOW_SIZE;
  conn->initial_recv_window = (int32_t) config->initial_window_size;
}

/**
 * create_io_buffers - Create send and receive buffers
 * @conn: Connection to initialize
 *
 * Raises: SocketHTTP2_ProtocolError on allocation failure
 */
static void
create_io_buffers (SocketHTTP2_Conn_T conn)
{
  size_t buf_size = SOCKETHTTP2_IO_BUFFER_SIZE;

  SocketBuf_T recv_temp = SocketBuf_new (conn->arena, buf_size);
  if (!recv_temp) {
    SOCKET_RAISE_MSG (SocketHTTP2, SocketHTTP2_ProtocolError,
                      "Failed to allocate HTTP/2 recv I/O buffer");
  }

  SocketBuf_T send_temp = SocketBuf_new (conn->arena, buf_size);
  if (!send_temp) {
    SocketBuf_release (&recv_temp);
    SOCKET_RAISE_MSG (SocketHTTP2, SocketHTTP2_ProtocolError,
                      "Failed to allocate HTTP/2 send I/O buffer");
  }

  conn->recv_buf = recv_temp;
  conn->send_buf = send_temp;
}

/**
 * create_hpack_encoder - Create HPACK encoder
 * @conn: Connection to initialize
 * @header_table_size: Maximum dynamic table size
 *
 * Raises: SocketHTTP2_ProtocolError on creation failure
 */
static void
create_hpack_encoder (SocketHTTP2_Conn_T conn, uint32_t header_table_size)
{
  SocketHPACK_EncoderConfig enc_config;

  SocketHPACK_encoder_config_defaults (&enc_config);
  enc_config.max_table_size = header_table_size;
  conn->encoder = SocketHPACK_Encoder_new (&enc_config, conn->arena);
  if (!conn->encoder) {
    SOCKET_RAISE_MSG (SocketHTTP2, SocketHTTP2_ProtocolError,
                      "Failed to create HPACK encoder");
  }
}

/**
 * create_hpack_decoder - Create HPACK decoder
 * @conn: Connection to initialize
 * @header_table_size: Maximum dynamic table size
 * @max_header_list_size: Maximum header list size
 *
 * Raises: SocketHTTP2_ProtocolError on creation failure
 */
static void
create_hpack_decoder (SocketHTTP2_Conn_T conn, uint32_t header_table_size,
                      uint32_t max_header_list_size)
{
  SocketHPACK_DecoderConfig dec_config;

  SocketHPACK_decoder_config_defaults (&dec_config);
  dec_config.max_table_size = header_table_size;
  dec_config.max_header_list_size = max_header_list_size;
  conn->decoder = SocketHPACK_Decoder_new (&dec_config, conn->arena);
  if (!conn->decoder) {
    SOCKET_RAISE_MSG (SocketHTTP2, SocketHTTP2_ProtocolError,
                      "Failed to create HPACK decoder");
  }
}

/**
 * create_stream_hash_table - Allocate stream hash table
 * @conn: Connection to initialize
 *
 * Raises: SocketHTTP2_ProtocolError on allocation failure
 */
static void
create_stream_hash_table (SocketHTTP2_Conn_T conn)
{
  conn->streams = Arena_calloc (conn->arena, HTTP2_STREAM_HASH_SIZE,
                                sizeof (*conn->streams), __FILE__, __LINE__);
  if (!conn->streams) {
    SOCKET_RAISE_MSG (SocketHTTP2, SocketHTTP2_ProtocolError,
                      "Failed to allocate stream hash table");
  }
}

/**
 * init_connection_components - Initialize internal components (I/O buffers, HPACK encoder/decoder, stream hash table)
 * @conn: Connection to initialize
 * @config: Configuration source for HPACK settings
 *
 * Raises: SocketHTTP2_ProtocolError on any allocation or creation failure
 */
/**
 * alloc_conn - Allocate and zero-initialize connection structure
 * @arena: Memory arena
 *
 * Returns: Allocated connection, raises on failure
 * Raises: SocketHTTP2_ProtocolError on allocation failure
 */
static SocketHTTP2_Conn_T
alloc_conn (Arena_T arena)
{
  SocketHTTP2_Conn_T conn;

  conn = Arena_calloc (arena, 1, sizeof (*conn), __FILE__, __LINE__);
  if (!conn)
    {
      SOCKET_RAISE_MSG (SocketHTTP2, SocketHTTP2_ProtocolError,
                        "Failed to allocate HTTP/2 connection");
    }

  return conn;
}

static void
init_connection_components (SocketHTTP2_Conn_T conn, const SocketHTTP2_Config *config)
{
  create_io_buffers (conn);

  create_hpack_encoder (conn, config->header_table_size);

  create_hpack_decoder (conn, config->header_table_size,
                            config->max_header_list_size);

  create_stream_hash_table (conn);  /* Now raises internally */
}

/* ============================================================================
 * Connection Creation
 * ============================================================================ */

/* Suppress GCC-specific clobbered warning (doesn't exist in Clang) */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

SocketHTTP2_Conn_T
SocketHTTP2_Conn_new (Socket_T socket, const SocketHTTP2_Config *config,
                      Arena_T arena)
{
  SocketHTTP2_Conn_T conn = NULL;
  SocketHTTP2_Config default_config;
  const SocketHTTP2_Config *cfg;

  assert (socket);
  assert (arena);

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

      /* Initialize internal components (buffers, HPACK, streams) */
      init_connection_components (conn, cfg);

      /* Initialize stream IDs based on role */
      conn->next_stream_id = (cfg->role == HTTP2_ROLE_CLIENT) ? 1 : 2;

      /* Store timeouts */
      conn->settings_timeout_ms = cfg->settings_timeout_ms;
      conn->ping_timeout_ms = cfg->ping_timeout_ms;
      conn->idle_timeout_ms = cfg->idle_timeout_ms;
    }
  EXCEPT (SocketHTTP2_ProtocolError)
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
 * SETTINGS Frame Building
 * ============================================================================ */

/**
 * should_send_setting - Check if setting differs from default
 * @id: Setting identifier (1-based)
 * @value: Setting value
 *
 * Returns: 1 if setting should be sent, 0 to skip
 */
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
    default:
      return 0;
    }
}

/**
 * build_settings_payload - Build SETTINGS frame payload
 * @conn: Connection with local settings
 * @payload: Output buffer (must be at least HTTP2_SETTINGS_COUNT *
 * HTTP2_SETTING_ENTRY_SIZE)
 *
 * Returns: Payload length in bytes
 */
static size_t
build_settings_payload (SocketHTTP2_Conn_T conn, unsigned char *payload)
{
  size_t payload_len = 0;

  for (int i = 0; i < HTTP2_SETTINGS_COUNT; i++)
    {
      uint16_t id = (uint16_t) (i + 1);
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

/**
 * send_initial_settings - Send our SETTINGS frame
 * @conn: Connection
 *
 * Returns: 0 on success, -1 on error
 */
static int
send_initial_settings (SocketHTTP2_Conn_T conn)
{
  SocketHTTP2_FrameHeader header;
  unsigned char payload[HTTP2_SETTINGS_COUNT * HTTP2_SETTING_ENTRY_SIZE];
  size_t payload_len;

  payload_len = build_settings_payload (conn, payload);

  header.length = (uint32_t) payload_len;
  header.type = HTTP2_FRAME_SETTINGS;
  header.flags = 0;
  header.stream_id = 0;

  return http2_frame_send (conn, &header, payload, payload_len);
}

/* ============================================================================
 * Connection Preface and Handshake
 * ============================================================================ */

/**
 * handshake_send_client_preface - Send client connection preface
 * @conn: Connection
 *
 * Returns: 0 on success, -1 on error
 */
static int
handshake_send_client_preface (SocketHTTP2_Conn_T conn)
{
  if (SocketBuf_write (conn->send_buf, HTTP2_CLIENT_PREFACE, HTTP2_PREFACE_SIZE)
      != HTTP2_PREFACE_SIZE)
    return -1;

  conn->state = HTTP2_CONN_STATE_PREFACE_SENT;
  return 0;
}

/**
 * handshake_send_settings - Send initial SETTINGS and optional WINDOW_UPDATE
 * @conn: Connection
 *
 * Returns: 0 on success, -1 on error
 */
static int
handshake_send_settings (SocketHTTP2_Conn_T conn)
{
  if (send_initial_settings (conn) < 0)
    return -1;

  conn->settings_ack_pending = 1;
  conn->state = HTTP2_CONN_STATE_SETTINGS_SENT;

  /* If connection-level window is larger than default, send WINDOW_UPDATE */
  if (conn->recv_window > SOCKETHTTP2_DEFAULT_INITIAL_WINDOW_SIZE)
    {
      uint32_t increment
          = (uint32_t) conn->recv_window - SOCKETHTTP2_DEFAULT_INITIAL_WINDOW_SIZE;
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
      if (conn->role == HTTP2_ROLE_CLIENT)
        {
          if (handshake_send_client_preface (conn) < 0)
            return -1;
          return handshake_send_settings (conn) < 0 ? -1 : 1;
        }
      /* Server waits for client preface */
      return 1;

    case HTTP2_CONN_STATE_PREFACE_SENT:
    case HTTP2_CONN_STATE_PREFACE_RECV:
      return handshake_send_settings (conn) < 0 ? -1 : 1;

    case HTTP2_CONN_STATE_SETTINGS_SENT:
    case HTTP2_CONN_STATE_SETTINGS_RECV:
      return 1; /* Waiting for peer */

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
    }

  header.length = (uint32_t) payload_len;
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

  header.length = HTTP2_PING_PAYLOAD_SIZE;
  header.type = HTTP2_FRAME_PING;
  header.flags = 0;
  header.stream_id = 0;

  return http2_frame_send (conn, &header, payload, HTTP2_PING_PAYLOAD_SIZE);
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

  payload_len = HTTP2_GOAWAY_HEADER_SIZE + debug_len;
  payload = Arena_alloc (conn->arena, payload_len, __FILE__, __LINE__);
  if (!payload)
    return -1;

  /* Last stream ID and error code */
  write_u31_be (payload, conn->last_peer_stream_id);
  write_u32_be (payload + 4, (uint32_t) error_code);

  /* Debug data */
  if (debug_len > 0 && debug_data)
    memcpy (payload + HTTP2_GOAWAY_HEADER_SIZE, debug_data, debug_len);

  header.length = (uint32_t) payload_len;
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

/* ============================================================================
 * Frame Processing Helpers
 * ============================================================================ */

/* Removed unused frame processing helpers: read_frame_header, has_complete_frame, validate_and_respond_to_invalid_frame */
/**
 * read_socket_to_buffer - Read data from socket into receive buffer
 * @conn: Connection
 *
 * Returns: 0 on success, -1 on error
 * Thread-safe: No
 */
static int
read_socket_to_buffer (SocketHTTP2_Conn_T conn)
{
  size_t space;
  void *write_ptr = SocketBuf_writeptr (conn->recv_buf, &space);

  if (!write_ptr || space == 0)
    return 0;

  ssize_t n = Socket_recv (conn->socket, write_ptr, space);
  if (n > 0)
    SocketBuf_written (conn->recv_buf, (size_t) n);
  else if (n < 0)
    return -1;

  return 0;
}

/**
 * verify_client_preface - Verify client connection preface (server only)
 * @conn: Connection
 *
 * Returns: 1 if verified, 0 if need more data, -1 on error
 */
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

/**
 * process_single_frame - Parse and process one frame from buffer
 * @conn: Connection
 *
 * Returns: 1 if frame processed, 0 if need more data, -1 on error
 */
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
      = (unsigned char *) SocketBuf_readptr (conn->recv_buf, &read_len);
  if (!data || read_len < HTTP2_FRAME_HEADER_SIZE)
    return 0;

  SocketHTTP2_frame_header_parse (data, &header);

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

  /* Consume the frame */
  SocketBuf_consume (conn->recv_buf, HTTP2_FRAME_HEADER_SIZE + header.length);
  return 1;
}

/* ============================================================================
 * Frame Processing
 * ============================================================================ */

int
SocketHTTP2_Conn_process (SocketHTTP2_Conn_T conn, unsigned events)
{
  int result;

  assert (conn);
  (void) events; /* May use for POLL_READ/POLL_WRITE optimization later */

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
        SocketBuf_consume (conn->send_buf, (size_t) sent);
      else if (sent == 0)
        return 1; /* Would block */
      else
        return -1;
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

/**
 * send_settings_ack - Send SETTINGS acknowledgement frame
 * @conn: Connection
 *
 * Returns: 0 on success, -1 on error
 */
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

/**
 * process_settings_ack - Handle SETTINGS ACK frame
 * @conn: Connection
 */
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

/**
 * validate_and_apply_setting - Validate and apply a single setting
 * @conn: Connection
 * @id: Setting identifier
 * @value: Setting value
 *
 * Returns: 0 on success, -1 on error (sends connection error)
 */
static int
validate_and_apply_setting (SocketHTTP2_Conn_T conn, uint16_t id,
                            uint32_t value)
{
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
      if (value > SOCKETHTTP2_MAX_WINDOW_SIZE)
        {
          http2_send_connection_error (conn, HTTP2_FLOW_CONTROL_ERROR);
          return -1;
        }
      /* Adjust existing stream windows */
      {
        int32_t delta
            = (int32_t) value
              - (int32_t) conn->peer_settings[SETTINGS_IDX_INITIAL_WINDOW_SIZE];
        for (size_t j = 0; j < HTTP2_STREAM_HASH_SIZE; j++)
          {
            SocketHTTP2_Stream_T s = conn->streams[j];
            while (s)
              {
                s->send_window += delta;
                s = s->hash_next;
              }
          }
        conn->initial_send_window = (int32_t) value;
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
      SocketHPACK_Encoder_set_table_size (conn->encoder, value);
      break;
    }

  /* Store setting */
  if (id >= 1 && id <= HTTP2_SETTINGS_COUNT)
    conn->peer_settings[id - 1] = value;

  return 0;
}

/**
 * update_conn_state_after_settings - Update connection state after processing
 * SETTINGS
 * @conn: Connection
 */
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

/**
 * parse_and_apply_all_settings - Parse SETTINGS frame payload and apply each setting
 * @conn: Connection
 * @payload: SETTINGS payload data
 * @length: Payload length
 *
 * Parses the SETTINGS payload into individual setting entries and applies each
 * to the connection. Validates payload length must be multiple of entry size.
 * Calls validate_and_apply_setting for each, propagating errors.
 *
 * Returns: 0 on success, -1 on error (sends connection error and returns)
 * Raises: None - errors handled by sending GOAWAY
 * Thread-safe: No
 */
static int
parse_and_apply_all_settings (SocketHTTP2_Conn_T conn, const unsigned char *payload, size_t length)
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
          && memcmp (payload, conn->ping_opaque, HTTP2_PING_PAYLOAD_SIZE) == 0)
        {
          conn->ping_pending = 0;
          http2_emit_conn_event (conn, HTTP2_EVENT_PING_ACK);
        }
      return 0;
    }

  /* Echo PING with ACK flag */
  SocketHTTP2_FrameHeader response;
  response.length = HTTP2_PING_PAYLOAD_SIZE;
  response.type = HTTP2_FRAME_PING;
  response.flags = HTTP2_FLAG_ACK;
  response.stream_id = 0;

  return http2_frame_send (conn, &response, payload, HTTP2_PING_PAYLOAD_SIZE);
}

/* ============================================================================
 * GOAWAY Processing
 * ============================================================================ */

int
http2_process_goaway (SocketHTTP2_Conn_T conn,
                      const SocketHTTP2_FrameHeader *header,
                      const unsigned char *payload)
{
  (void) header;

  /* Parse last stream ID and error code */
  conn->max_peer_stream_id = read_u31_be (payload);
  conn->goaway_error_code
      = (SocketHTTP2_ErrorCode) read_u32_be (payload + 4);
  conn->goaway_received = 1;

  http2_emit_conn_event (conn, HTTP2_EVENT_GOAWAY_RECEIVED);
  return 0;
}

/* ============================================================================
 * WINDOW_UPDATE Processing
 * ============================================================================ */

/**
 * process_connection_window_update - Handle connection-level WINDOW_UPDATE
 * @conn: Connection
 * @increment: Window increment value
 *
 * Updates the connection send window. Sends FLOW_CONTROL_ERROR if overflow.
 *
 * Returns: 0 on success, -1 on error (sends GOAWAY)
 * Thread-safe: No
 */
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

/**
 * process_stream_window_update - Handle stream-level WINDOW_UPDATE
 * @conn: Connection
 * @stream_id: Stream ID
 * @increment: Window increment value
 *
 * Looks up stream and updates its send window. Emits event if successful.
 * Ignores unknown streams per RFC (may be closed).
 * Sends RST_STREAM if overflow on existing stream.
 *
 * Returns: 0 on success, -1 on error (sends RST_STREAM)
 * Thread-safe: No
 */
static int
process_stream_window_update (SocketHTTP2_Conn_T conn, uint32_t stream_id, uint32_t increment)
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
  uint32_t error_code = read_u32_be (payload);
  int64_t now_ms = Socket_get_monotonic_ms ();

  /* CVE-2023-44487: Rate limit RST_STREAM frames to prevent Rapid Reset DoS */

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

  (void) error_code; /* Could log or store for debugging */
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

  (void) settings_payload;
  (void) settings_len;

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

  (void) settings_payload;
  (void) settings_len;
  (void) initial_request;

  SocketHTTP2_config_defaults (&config, HTTP2_ROLE_SERVER);
  conn = SocketHTTP2_Conn_new (socket, &config, arena);
  if (!conn)
    return NULL;

  /* For h2c upgrade, skip the preface - client already sent HTTP/1.1 upgrade */
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
