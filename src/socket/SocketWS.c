/**
 * SocketWS.c - WebSocket Protocol Core (RFC 6455)
 *
 * Part of the Socket Library
 *
 * Core WebSocket lifecycle, configuration, state management, and I/O.
 * Frame parsing and handshake logic are in separate files.
 *
 * Module Reuse (zero duplication):
 * - SocketCrypto: websocket_key(), websocket_accept(), random_bytes()
 * - SocketUTF8: Incremental UTF-8 validation for text frames
 * - SocketHTTP1: HTTP upgrade request/response parsing
 * - SocketBuf: Circular buffer I/O
 * - Socket_get_monotonic_ms(): Timestamp tracking
 * - SocketTimer: Auto-ping timer integration
 *
 * Thread Safety:
 * - SocketWS_T instances are NOT thread-safe
 * - Multiple instances can be used from different threads
 */

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketCrypto.h"
#include "core/SocketTimer.h"
#include "core/SocketUTF8.h"
#define SOCKET_LOG_COMPONENT "SocketWS"
#include "core/SocketUtil.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"
#include "socket/SocketWS-private.h"

/* ============================================================================
 * Exception Definitions
 * ============================================================================ */

const Except_T SocketWS_Failed = { &SocketWS_Failed,
                                   "WebSocket operation failed" };
const Except_T SocketWS_ProtocolError = { &SocketWS_ProtocolError,
                                          "WebSocket protocol error" };
const Except_T SocketWS_Closed = { &SocketWS_Closed,
                                   "WebSocket connection closed" };

/* Thread-local exception - defined via macro in private header */

/* ============================================================================
 * Configuration Defaults
 * ============================================================================ */

void
SocketWS_config_defaults (SocketWS_Config *config)
{
  assert (config);

  memset (config, 0, sizeof (*config));

  config->role = WS_ROLE_CLIENT;
  config->max_frame_size = SOCKETWS_MAX_FRAME_SIZE;
  config->max_message_size = SOCKETWS_MAX_MESSAGE_SIZE;
  config->max_fragments = SOCKETWS_MAX_FRAGMENTS;
  config->validate_utf8 = 1;
  config->enable_permessage_deflate = 0;
  config->deflate_no_context_takeover = 0;
  config->deflate_max_window_bits = SOCKETWS_DEFAULT_DEFLATE_WINDOW_BITS;
  config->subprotocols = NULL;
  config->ping_interval_ms = SOCKETWS_DEFAULT_PING_INTERVAL_MS;
  config->ping_timeout_ms = SOCKETWS_DEFAULT_PING_TIMEOUT_MS;
}

/* ============================================================================
 * Internal Helpers
 * ============================================================================ */

/**
 * ws_alloc_context - Allocate and initialize WebSocket context
 * @arena: Memory arena
 * @config: Configuration (NULL for defaults)
 *
 * Returns: Allocated context, or NULL on error
 */
static SocketWS_T
ws_alloc_context (Arena_T arena, const SocketWS_Config *config)
{
  SocketWS_T ws;

  ws = ALLOC (arena, sizeof (*ws));
  if (!ws)
    return NULL;

  memset (ws, 0, sizeof (*ws));
  ws->arena = arena;

  /* Copy configuration */
  if (config)
    memcpy (&ws->config, config, sizeof (ws->config));
  else
    SocketWS_config_defaults (&ws->config);

  ws->role = ws->config.role;
  ws->state = WS_STATE_CONNECTING;

  /* Allocate buffers */
  ws->recv_buf = SocketBuf_new (arena, SOCKETWS_RECV_BUFFER_SIZE);
  if (!ws->recv_buf)
    return NULL;

  ws->send_buf = SocketBuf_new (arena, SOCKETWS_SEND_BUFFER_SIZE);
  if (!ws->send_buf)
    return NULL;

  /* Initialize frame parsing */
  ws_frame_reset (&ws->frame);

  /* Initialize message assembly */
  ws_message_reset (&ws->message);

  /* Initialize timestamps using monotonic clock */
  ws->last_pong_received_time = Socket_get_monotonic_ms ();

  return ws;
}

/* ws_copy_string is declared in private header and defined in SocketWS-handshake.c */

/* ============================================================================
 * Error Handling
 * ============================================================================ */

void
ws_set_error (SocketWS_T ws, SocketWS_Error error, const char *fmt, ...)
{
  va_list args;

  assert (ws);

  ws->last_error = error;

  if (fmt)
    {
      va_start (args, fmt);
      vsnprintf (ws->error_buf, sizeof (ws->error_buf), fmt, args);
      va_end (args);

      SocketLog_emit (SOCKET_LOG_ERROR, SOCKET_LOG_COMPONENT, ws->error_buf);
    }
  else
    {
      ws->error_buf[0] = '\0';
    }
}

/* ============================================================================
 * Frame State Management
 * ============================================================================ */

void
ws_frame_reset (SocketWS_FrameParse *frame)
{
  assert (frame);

  memset (frame, 0, sizeof (*frame));
  frame->state = WS_FRAME_STATE_HEADER;
  frame->header_needed = 2; /* Minimum header size */
}

/* ============================================================================
 * Message Assembly Management
 * ============================================================================ */

void
ws_message_reset (SocketWS_MessageAssembly *message)
{
  assert (message);

  /* Don't free data - it's arena allocated */
  message->type = WS_OPCODE_CONTINUATION;
  message->len = 0;
  message->fragment_count = 0;
  message->compressed = 0;
  message->utf8_initialized = 0;
}

int
ws_message_append (SocketWS_T ws, const unsigned char *data, size_t len,
                   int is_text)
{
  SocketWS_MessageAssembly *msg;
  size_t new_len;
  size_t new_capacity;
  unsigned char *new_data;

  assert (ws);
  msg = &ws->message;

  /* Check fragment limit */
  if (msg->fragment_count >= ws->config.max_fragments)
    {
      ws_set_error (ws, WS_ERROR_MESSAGE_TOO_LARGE,
                    "Too many message fragments: %zu", msg->fragment_count);
      return -1;
    }

  /* Check message size limit */
  new_len = msg->len + len;
  if (new_len > ws->config.max_message_size)
    {
      ws_set_error (ws, WS_ERROR_MESSAGE_TOO_LARGE,
                    "Message too large: %zu > %zu", new_len,
                    ws->config.max_message_size);
      return -1;
    }

  /* Grow buffer if needed */
  if (new_len > msg->capacity)
    {
      new_capacity = msg->capacity ? msg->capacity * 2 : 4096;
      while (new_capacity < new_len)
        new_capacity *= 2;

      if (new_capacity > ws->config.max_message_size)
        new_capacity = ws->config.max_message_size;

      new_data = ALLOC (ws->arena, new_capacity);
      if (!new_data)
        {
          ws_set_error (ws, WS_ERROR, "Failed to allocate message buffer");
          return -1;
        }

      if (msg->data && msg->len > 0)
        memcpy (new_data, msg->data, msg->len);

      msg->data = new_data;
      msg->capacity = new_capacity;
    }

  /* Append data */
  if (len > 0)
    {
      memcpy (msg->data + msg->len, data, len);
      msg->len = new_len;
    }

  msg->fragment_count++;

  /* Validate UTF-8 incrementally for text messages */
  if (is_text && ws->config.validate_utf8)
    {
      SocketUTF8_Result result;

      if (!msg->utf8_initialized)
        {
          SocketUTF8_init (&msg->utf8_state);
          msg->utf8_initialized = 1;
        }

      result = SocketUTF8_update (&msg->utf8_state, data, len);
      if (result != UTF8_VALID && result != UTF8_INCOMPLETE)
        {
          ws_set_error (ws, WS_ERROR_INVALID_UTF8,
                        "Invalid UTF-8 in text message: %s",
                        SocketUTF8_result_string (result));
          return -1;
        }
    }

  return 0;
}

int
ws_message_finalize (SocketWS_T ws)
{
  SocketWS_MessageAssembly *msg;

  assert (ws);
  msg = &ws->message;

  /* Finalize UTF-8 validation for text messages */
  if (msg->type == WS_OPCODE_TEXT && ws->config.validate_utf8
      && msg->utf8_initialized)
    {
      SocketUTF8_Result result = SocketUTF8_finish (&msg->utf8_state);
      if (result != UTF8_VALID)
        {
          ws_set_error (ws, WS_ERROR_INVALID_UTF8,
                        "Incomplete UTF-8 sequence at end of message");
          return -1;
        }
    }

  return 0;
}

/* ============================================================================
 * I/O Helpers
 * ============================================================================ */

ssize_t
ws_flush_send_buffer (SocketWS_T ws)
{
  size_t available;
  const void *ptr;
  ssize_t sent;

  assert (ws);
  assert (ws->socket);

  available = SocketBuf_available (ws->send_buf);
  if (available == 0)
    return 0;

  /* Get contiguous read pointer */
  ptr = SocketBuf_readptr (ws->send_buf, &available);
  if (!ptr || available == 0)
    return 0;

  /* Send data */
  sent = Socket_send (ws->socket, ptr, available);
  if (sent < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return 0;
      ws_set_error (ws, WS_ERROR, "Socket send failed");
      return -1;
    }

  /* Consume sent bytes */
  SocketBuf_consume (ws->send_buf, (size_t)sent);

  return sent;
}

ssize_t
ws_fill_recv_buffer (SocketWS_T ws)
{
  size_t space;
  void *ptr;
  ssize_t received;

  assert (ws);
  assert (ws->socket);

  /* Get contiguous write pointer */
  ptr = SocketBuf_writeptr (ws->recv_buf, &space);
  if (!ptr || space == 0)
    {
      /* Buffer full */
      return 0;
    }

  /* Receive data */
  received = Socket_recv (ws->socket, ptr, space);
  if (received < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return 0;
      ws_set_error (ws, WS_ERROR, "Socket recv failed");
      return -1;
    }

  if (received == 0)
    {
      /* EOF */
      return 0;
    }

  /* Commit received bytes */
  SocketBuf_written (ws->recv_buf, (size_t)received);

  return received;
}

/* ============================================================================
 * Control Frame Handling
 * ============================================================================ */

int
ws_send_close (SocketWS_T ws, SocketWS_CloseCode code, const char *reason)
{
  unsigned char payload[SOCKETWS_MAX_CONTROL_PAYLOAD];
  size_t payload_len = 0;
  size_t reason_len;

  assert (ws);

  /* Build payload: 2-byte code + optional reason */
  if (code != WS_CLOSE_NO_STATUS)
    {
      payload[0] = (code >> 8) & 0xFF;
      payload[1] = code & 0xFF;
      payload_len = 2;

      if (reason)
        {
          reason_len = strlen (reason);
          if (reason_len > SOCKETWS_MAX_CLOSE_REASON)
            reason_len = SOCKETWS_MAX_CLOSE_REASON;

          memcpy (payload + 2, reason, reason_len);
          payload_len += reason_len;
        }
    }

  /* Store close info */
  ws->close_code = code;
  if (reason)
    {
      reason_len = strlen (reason);
      if (reason_len > SOCKETWS_MAX_CLOSE_REASON)
        reason_len = SOCKETWS_MAX_CLOSE_REASON;
      memcpy (ws->close_reason, reason, reason_len);
      ws->close_reason[reason_len] = '\0';
    }
  else
    {
      ws->close_reason[0] = '\0';
    }

  ws->close_sent = 1;

  /* Transition state */
  if (ws->state == WS_STATE_OPEN)
    ws->state = WS_STATE_CLOSING;

  /* Send the frame - implementation in SocketWS-frame.c */
  return ws_send_control_frame (ws, WS_OPCODE_CLOSE, payload, payload_len);
}

int
ws_send_ping (SocketWS_T ws, const unsigned char *payload, size_t len)
{
  assert (ws);

  if (len > SOCKETWS_MAX_CONTROL_PAYLOAD)
    {
      ws_set_error (ws, WS_ERROR_PROTOCOL,
                    "Ping payload too large: %zu > %d", len,
                    SOCKETWS_MAX_CONTROL_PAYLOAD);
      return -1;
    }

  /* Track ping for timeout */
  if (payload && len > 0)
    {
      memcpy (ws->pending_ping_payload, payload, len);
      ws->pending_ping_len = len;
    }
  else
    {
      ws->pending_ping_len = 0;
    }

  ws->last_ping_sent_time = Socket_get_monotonic_ms ();
  ws->awaiting_pong = 1;

  return ws_send_control_frame (ws, WS_OPCODE_PING, payload, len);
}

int
ws_send_pong (SocketWS_T ws, const unsigned char *payload, size_t len)
{
  assert (ws);

  if (len > SOCKETWS_MAX_CONTROL_PAYLOAD)
    len = SOCKETWS_MAX_CONTROL_PAYLOAD;

  ws->last_pong_sent_time = Socket_get_monotonic_ms ();

  return ws_send_control_frame (ws, WS_OPCODE_PONG, payload, len);
}

int
ws_handle_control_frame (SocketWS_T ws, SocketWS_Opcode opcode,
                         const unsigned char *payload, size_t len)
{
  assert (ws);

  switch (opcode)
    {
    case WS_OPCODE_CLOSE:
      {
        int code = WS_CLOSE_NO_STATUS;
        const char *reason = NULL;
        size_t reason_len = 0;

        /* Parse close payload */
        if (len >= 2)
          {
            code = (payload[0] << 8) | payload[1];
            if (len > 2)
              {
                reason = (const char *)(payload + 2);
                reason_len = len - 2;

                /* Validate close reason as UTF-8 */
                if (ws->config.validate_utf8)
                  {
                    SocketUTF8_Result result
                        = SocketUTF8_validate (payload + 2, reason_len);
                    if (result != UTF8_VALID)
                      {
                        ws_set_error (ws, WS_ERROR_INVALID_UTF8,
                                      "Invalid UTF-8 in close reason");
                        ws_send_close (ws, WS_CLOSE_INVALID_PAYLOAD,
                                       "Invalid UTF-8");
                        return -1;
                      }
                  }
              }
          }

        /* Store peer's close info */
        ws->close_received = 1;
        if (code != WS_CLOSE_NO_STATUS)
          ws->close_code = (SocketWS_CloseCode)code;
        if (reason && reason_len > 0)
          {
            if (reason_len > SOCKETWS_MAX_CLOSE_REASON)
              reason_len = SOCKETWS_MAX_CLOSE_REASON;
            memcpy (ws->close_reason, reason, reason_len);
            ws->close_reason[reason_len] = '\0';
          }

        /* Respond with close if we haven't sent one */
        if (!ws->close_sent)
          {
            ws_send_close (ws, (SocketWS_CloseCode)code, NULL);
          }

        /* Transition to closed */
        ws->state = WS_STATE_CLOSED;
        break;
      }

    case WS_OPCODE_PING:
      /* Echo payload back as PONG */
      return ws_send_pong (ws, payload, len);

    case WS_OPCODE_PONG:
      /* Track pong receipt */
      ws->last_pong_received_time = Socket_get_monotonic_ms ();
      ws->awaiting_pong = 0;
      break;

    default:
      ws_set_error (ws, WS_ERROR_PROTOCOL, "Unknown control opcode: 0x%02X",
                    opcode);
      return -1;
    }

  return 0;
}

/* ============================================================================
 * Auto-Ping Timer Integration
 * ============================================================================ */

void
ws_auto_ping_callback (void *userdata)
{
  SocketWS_T ws = (SocketWS_T)userdata;
  int64_t now;
  int64_t elapsed;

  if (!ws || ws->state != WS_STATE_OPEN)
    return;

  now = Socket_get_monotonic_ms ();

  /* Check for pong timeout */
  if (ws->awaiting_pong && ws->config.ping_timeout_ms > 0)
    {
      elapsed = now - ws->last_ping_sent_time;
      if (elapsed > ws->config.ping_timeout_ms)
        {
          SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                           "Ping timeout after %lld ms", (long long)elapsed);
          ws_send_close (ws, WS_CLOSE_GOING_AWAY, "Ping timeout");
          return;
        }
    }

  /* Send ping */
  ws_send_ping (ws, NULL, 0);
}

int
ws_auto_ping_start (SocketWS_T ws, SocketPoll_T poll)
{
  assert (ws);

  if (ws->config.ping_interval_ms <= 0)
    return 0; /* Disabled */

  if (!poll)
    {
      ws_set_error (ws, WS_ERROR, "Poll required for auto-ping");
      return -1;
    }

  ws->poll = poll;
  ws->ping_timer
      = SocketTimer_add_repeating (poll, ws->config.ping_interval_ms,
                                   ws_auto_ping_callback, ws);

  if (!ws->ping_timer)
    {
      ws_set_error (ws, WS_ERROR, "Failed to create ping timer");
      return -1;
    }

  return 0;
}

void
ws_auto_ping_stop (SocketWS_T ws)
{
  assert (ws);

  if (ws->ping_timer && ws->poll)
    {
      SocketTimer_cancel (ws->poll, ws->ping_timer);
      ws->ping_timer = NULL;
    }
}

/* ============================================================================
 * Public API - Lifecycle
 * ============================================================================ */

SocketWS_T
SocketWS_client_new (Socket_T socket, const char *host, const char *path,
                     const SocketWS_Config *config)
{
  Arena_T arena = NULL;
  volatile SocketWS_T ws = NULL;
  SocketWS_Config cfg;

  assert (socket);
  assert (host);

  TRY
  {
    arena = Arena_new ();
    if (!arena)
      {
        SOCKET_ERROR_MSG ("Failed to create arena");
        RAISE_WS_ERROR (SocketWS_Failed);
      }

    /* Set role to client */
    if (config)
      {
        cfg = *config;
        cfg.role = WS_ROLE_CLIENT;
      }
    else
      {
        SocketWS_config_defaults (&cfg);
        cfg.role = WS_ROLE_CLIENT;
      }

    ws = ws_alloc_context (arena, &cfg);
    if (!ws)
      {
        SOCKET_ERROR_MSG ("Failed to allocate WebSocket context");
        RAISE_WS_ERROR (SocketWS_Failed);
      }

    ((SocketWS_T)ws)->socket = socket;
    ((SocketWS_T)ws)->host = ws_copy_string (arena, host);
    ((SocketWS_T)ws)->path = ws_copy_string (arena, path ? path : "/");

    /* Initialize client handshake */
    if (ws_handshake_client_init ((SocketWS_T)ws) < 0)
      {
        SOCKET_ERROR_MSG ("Failed to initialize handshake");
        RAISE_WS_ERROR (SocketWS_Failed);
      }
  }
  EXCEPT (SocketWS_Failed)
  {
    if (arena)
      Arena_dispose (&arena);
    RERAISE;
  }
  END_TRY;

  return (SocketWS_T)ws;
}

SocketWS_T
SocketWS_server_accept (Socket_T socket, const SocketHTTP_Request *request,
                        const SocketWS_Config *config)
{
  Arena_T arena = NULL;
  volatile SocketWS_T ws = NULL;
  SocketWS_Config cfg;

  assert (socket);
  assert (request);

  TRY
  {
    arena = Arena_new ();
    if (!arena)
      {
        SOCKET_ERROR_MSG ("Failed to create arena");
        RAISE_WS_ERROR (SocketWS_Failed);
      }

    /* Set role to server */
    if (config)
      {
        cfg = *config;
        cfg.role = WS_ROLE_SERVER;
      }
    else
      {
        SocketWS_config_defaults (&cfg);
        cfg.role = WS_ROLE_SERVER;
      }

    ws = ws_alloc_context (arena, &cfg);
    if (!ws)
      {
        SOCKET_ERROR_MSG ("Failed to allocate WebSocket context");
        RAISE_WS_ERROR (SocketWS_Failed);
      }

    ((SocketWS_T)ws)->socket = socket;

    /* Initialize server handshake */
    if (ws_handshake_server_init ((SocketWS_T)ws, request) < 0)
      {
        SOCKET_ERROR_MSG ("Failed to initialize server handshake");
        RAISE_WS_ERROR (SocketWS_Failed);
      }
  }
  EXCEPT (SocketWS_Failed)
  {
    if (arena)
      Arena_dispose (&arena);
    RERAISE;
  }
  END_TRY;

  return (SocketWS_T)ws;
}

void
SocketWS_free (SocketWS_T *wsp)
{
  SocketWS_T ws;
  Arena_T arena;

  if (!wsp || !*wsp)
    return;

  ws = *wsp;
  arena = ws->arena;

  /* Stop auto-ping timer */
  ws_auto_ping_stop (ws);

  /* Free compression resources */
#ifdef SOCKETWS_HAS_DEFLATE
  if (ws->compression_enabled)
    ws_compression_free (ws);
#endif

  /* Clear sensitive data */
  SocketCrypto_secure_clear (ws->handshake.client_key,
                             sizeof (ws->handshake.client_key));

  /* Dispose arena (frees all allocations) */
  if (arena)
    Arena_dispose (&arena);

  *wsp = NULL;
}

/* ============================================================================
 * Public API - State Accessors
 * ============================================================================ */

SocketWS_State
SocketWS_state (SocketWS_T ws)
{
  assert (ws);
  return ws->state;
}

Socket_T
SocketWS_socket (SocketWS_T ws)
{
  assert (ws);
  return ws->socket;
}

const char *
SocketWS_selected_subprotocol (SocketWS_T ws)
{
  assert (ws);
  return ws->handshake.selected_subprotocol;
}

int
SocketWS_compression_enabled (SocketWS_T ws)
{
  assert (ws);
#ifdef SOCKETWS_HAS_DEFLATE
  return ws->compression_enabled;
#else
  (void)ws; /* Suppress unused parameter warning when NDEBUG defined */
  return 0;
#endif
}

int
SocketWS_close_code (SocketWS_T ws)
{
  assert (ws);
  return (int)ws->close_code;
}

const char *
SocketWS_close_reason (SocketWS_T ws)
{
  assert (ws);
  return ws->close_reason[0] ? ws->close_reason : NULL;
}

SocketWS_Error
SocketWS_last_error (SocketWS_T ws)
{
  assert (ws);
  return ws->last_error;
}

const char *
SocketWS_error_string (SocketWS_Error error)
{
  switch (error)
    {
    case WS_OK:
      return "OK";
    case WS_ERROR:
      return "General error";
    case WS_ERROR_HANDSHAKE:
      return "Handshake failed";
    case WS_ERROR_PROTOCOL:
      return "Protocol error";
    case WS_ERROR_FRAME_TOO_LARGE:
      return "Frame too large";
    case WS_ERROR_MESSAGE_TOO_LARGE:
      return "Message too large";
    case WS_ERROR_INVALID_UTF8:
      return "Invalid UTF-8";
    case WS_ERROR_COMPRESSION:
      return "Compression error";
    case WS_ERROR_CLOSED:
      return "Connection closed";
    case WS_ERROR_WOULD_BLOCK:
      return "Would block";
    case WS_ERROR_TIMEOUT:
      return "Timeout";
    default:
      return "Unknown error";
    }
}

/* ============================================================================
 * Public API - Handshake
 * ============================================================================ */

int
SocketWS_handshake (SocketWS_T ws)
{
  int result;

  assert (ws);

  if (ws->state != WS_STATE_CONNECTING)
    {
      ws_set_error (ws, WS_ERROR, "Not in connecting state");
      return -1;
    }

  if (ws->role == WS_ROLE_CLIENT)
    result = ws_handshake_client_process (ws);
  else
    result = ws_handshake_server_process (ws);

  if (result == 0)
    {
      /* Handshake complete */
      ws->state = WS_STATE_OPEN;
    }

  return result;
}

/* ============================================================================
 * Public API - Event Loop Integration
 * ============================================================================ */

int
SocketWS_pollfd (SocketWS_T ws)
{
  assert (ws);
  assert (ws->socket);
  return Socket_fd (ws->socket);
}

unsigned
SocketWS_poll_events (SocketWS_T ws)
{
  unsigned events = 0;

  assert (ws);

  /* Always interested in read */
  events |= POLL_READ;

  /* Interested in write if we have data to send */
  if (SocketBuf_available (ws->send_buf) > 0)
    events |= POLL_WRITE;

  return events;
}

int
SocketWS_process (SocketWS_T ws, unsigned events)
{
  ssize_t n;

  assert (ws);

  /* Handle write events */
  if (events & POLL_WRITE)
    {
      n = ws_flush_send_buffer (ws);
      if (n < 0)
        return -1;
    }

  /* Handle read events */
  if (events & POLL_READ)
    {
      n = ws_fill_recv_buffer (ws);
      if (n < 0)
        return -1;
      if (n == 0 && ws->state == WS_STATE_OPEN)
        {
          /* EOF received */
          ws->state = WS_STATE_CLOSED;
          ws->close_code = WS_CLOSE_ABNORMAL;
        }
    }

  /* Handle errors */
  if (events & (POLL_ERROR | POLL_HANGUP))
    {
      ws->state = WS_STATE_CLOSED;
      ws->close_code = WS_CLOSE_ABNORMAL;
    }

  return 0;
}

/* ============================================================================
 * Public API - Sending
 * ============================================================================ */

int
SocketWS_send_text (SocketWS_T ws, const char *data, size_t len)
{
  assert (ws);

  if (ws->state != WS_STATE_OPEN)
    {
      ws_set_error (ws, WS_ERROR_CLOSED, "Connection not open");
      return -1;
    }

  /* Validate UTF-8 if configured */
  if (ws->config.validate_utf8)
    {
      SocketUTF8_Result result
          = SocketUTF8_validate ((const unsigned char *)data, len);
      if (result != UTF8_VALID)
        {
          ws_set_error (ws, WS_ERROR_INVALID_UTF8,
                        "Invalid UTF-8 in outgoing text: %s",
                        SocketUTF8_result_string (result));
          return -1;
        }
    }

  return ws_send_data_frame (ws, WS_OPCODE_TEXT, (const unsigned char *)data,
                             len, 1);
}

int
SocketWS_send_binary (SocketWS_T ws, const void *data, size_t len)
{
  assert (ws);

  if (ws->state != WS_STATE_OPEN)
    {
      ws_set_error (ws, WS_ERROR_CLOSED, "Connection not open");
      return -1;
    }

  return ws_send_data_frame (ws, WS_OPCODE_BINARY, data, len, 1);
}

int
SocketWS_ping (SocketWS_T ws, const void *data, size_t len)
{
  assert (ws);

  if (ws->state != WS_STATE_OPEN)
    {
      ws_set_error (ws, WS_ERROR_CLOSED, "Connection not open");
      return -1;
    }

  return ws_send_ping (ws, data, len);
}

int
SocketWS_pong (SocketWS_T ws, const void *data, size_t len)
{
  assert (ws);

  if (ws->state != WS_STATE_OPEN)
    {
      ws_set_error (ws, WS_ERROR_CLOSED, "Connection not open");
      return -1;
    }

  return ws_send_pong (ws, data, len);
}

int
SocketWS_close (SocketWS_T ws, int code, const char *reason)
{
  assert (ws);

  if (ws->state == WS_STATE_CLOSED)
    return 0;

  if (ws->close_sent)
    return 0;

  return ws_send_close (ws, (SocketWS_CloseCode)code, reason);
}


