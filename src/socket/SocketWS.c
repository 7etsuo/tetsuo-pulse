/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* SocketWS.c - WebSocket Protocol Core (RFC 6455)
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
#include <netdb.h>
#include <poll.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketCrypto.h"
#include "core/SocketTimer.h"
#include "core/SocketUTF8.h"
#define SOCKET_LOG_COMPONENT "SocketWS"
#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"
#include "socket/SocketWS-private.h"

#define T SocketWS_T

static unsigned
ws_translate_poll_revents (short revents)
{
  unsigned ev = 0;

  if (revents & POLLIN)
    ev |= POLL_READ;
  if (revents & POLLOUT)
    ev |= POLL_WRITE;
  if (revents & POLLERR)
    ev |= POLL_ERROR;
  if (revents & POLLHUP)
    ev |= POLL_HANGUP;

  return ev;
}

const Except_T SocketWS_Failed
    = { &SocketWS_Failed, "WebSocket operation failed" };
const Except_T SocketWS_ProtocolError
    = { &SocketWS_ProtocolError, "WebSocket protocol error" };
const Except_T SocketWS_Closed
    = { &SocketWS_Closed, "WebSocket connection closed" };

SOCKET_DECLARE_MODULE_EXCEPTION (SocketWS);

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

static SocketWS_T
ws_alloc_struct (Arena_T arena)
{
  SocketWS_T ws;

  ws = ALLOC (arena, sizeof (*ws));
  if (!ws)
    return NULL;

  memset (ws, 0, sizeof (*ws));
  ws->arena = arena;

  return ws;
}

static void
ws_init_config (SocketWS_T ws, const SocketWS_Config *config)
{
  if (config)
    memcpy (&ws->config, config, sizeof (ws->config));
  else
    SocketWS_config_defaults (&ws->config);

  ws->role = ws->config.role;
  ws->state = WS_STATE_CONNECTING;
}

static int
ws_init_buffers (SocketWS_T ws)
{
  ws->recv_buf = SocketBuf_new (ws->arena, SOCKETWS_RECV_BUFFER_SIZE);
  if (!ws->recv_buf)
    return -1;

  ws->send_buf = SocketBuf_new (ws->arena, SOCKETWS_SEND_BUFFER_SIZE);
  if (!ws->send_buf)
    {
      SocketBuf_release (&ws->recv_buf);
      return -1;
    }

  return 0;
}

static void
ws_init_parsers (SocketWS_T ws)
{
  ws_frame_reset (&ws->frame);
  ws_message_reset (&ws->message);
  ws->last_pong_received_time = Socket_get_monotonic_ms ();
}

static SocketWS_T
ws_alloc_context (Arena_T arena, const SocketWS_Config *config)
{
  SocketWS_T ws;
  int rc;

  ws = ws_alloc_struct (arena);
  if (!ws)
    return NULL;

  ws_init_config (ws, config);

  rc = ws_init_buffers (ws);
  if (rc < 0)
    return NULL;

  ws_init_parsers (ws);

  return ws;
}

/* ws_copy_string is declared in private header and defined in
 * SocketWS-handshake.c */

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

static int
ws_ensure_open (SocketWS_T ws)
{
  if (ws->state != WS_STATE_OPEN)
    {
      ws_set_error (ws, WS_ERROR_CLOSED, "Connection not open");
      return 0;
    }
  return 1;
}

void
ws_frame_reset (SocketWS_FrameParse *frame)
{
  assert (frame);

  memset (frame, 0, sizeof (*frame));
  frame->state = WS_FRAME_STATE_HEADER;
  frame->header_needed = 2; /* Minimum header size */
}

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

static int
ws_message_check_limits (SocketWS_T ws, size_t additional_len)
{
  SocketWS_MessageAssembly *msg = &ws->message;
  size_t new_len;
  if (!SocketSecurity_check_add (msg->len, additional_len, &new_len))
    {
      ws_set_error (ws,
                    WS_ERROR_MESSAGE_TOO_LARGE,
                    "Message size addition overflow in check_limits");
      return -1;
    }

  if (msg->fragment_count >= ws->config.max_fragments)
    {
      ws_set_error (ws,
                    WS_ERROR_MESSAGE_TOO_LARGE,
                    "Too many message fragments: %zu",
                    msg->fragment_count);
      return -1;
    }

  if (new_len > ws->config.max_message_size)
    {
      ws_set_error (ws,
                    WS_ERROR_MESSAGE_TOO_LARGE,
                    "Message too large: %zu > %zu",
                    new_len,
                    ws->config.max_message_size);
      return -1;
    }

  return 0;
}

static int
ws_message_grow_buffer (SocketWS_T ws, size_t required_len)
{
  SocketWS_MessageAssembly *msg = &ws->message;
  size_t new_capacity;
  unsigned char *new_data;

  if (required_len <= msg->capacity)
    return 0;

  new_capacity
      = msg->capacity ? msg->capacity : SOCKET_INITIAL_MESSAGE_CAPACITY;
  size_t iterations = 0;
  while (new_capacity < required_len
         && iterations < SOCKETWS_MAX_GROWTH_ITERATIONS)
    { /* Prevent potential loop on overflow */
      size_t temp;
      if (!SocketSecurity_check_multiply (
              new_capacity, SOCKET_BUFFER_GROWTH_FACTOR, &temp))
        {
          new_capacity = required_len > new_capacity ? required_len : SIZE_MAX;
          break;
        }
      new_capacity = temp;
      iterations++;
    }

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
  return 0;
}

static int
ws_message_validate_utf8 (SocketWS_T ws, const unsigned char *data, size_t len)
{
  SocketWS_MessageAssembly *msg = &ws->message;
  SocketUTF8_Result result;

  if (!msg->utf8_initialized)
    {
      SocketUTF8_init (&msg->utf8_state);
      msg->utf8_initialized = 1;
    }

  result = SocketUTF8_update (&msg->utf8_state, data, len);
  if (result != UTF8_VALID && result != UTF8_INCOMPLETE)
    {
      ws_set_error (ws,
                    WS_ERROR_INVALID_UTF8,
                    "Invalid UTF-8 in text message: %s",
                    SocketUTF8_result_string (result));
      return -1;
    }

  return 0;
}

int
ws_message_append (SocketWS_T ws,
                   const unsigned char *data,
                   size_t len,
                   int is_text)
{
  SocketWS_MessageAssembly *msg;
  size_t new_len;

  assert (ws);
  msg = &ws->message;
  if (!SocketSecurity_check_add (msg->len, len, &new_len))
    {
      ws_set_error (ws,
                    WS_ERROR_MESSAGE_TOO_LARGE,
                    "Message size addition overflow in append");
      return -1;
    }

  if (ws_message_check_limits (ws, len) < 0)
    return -1;

  if (ws_message_grow_buffer (ws, new_len) < 0)
    return -1;

  if (len > 0)
    {
      memcpy (msg->data + msg->len, data, len);
      msg->len = new_len;
    }

  msg->fragment_count++;

  if (is_text && ws->config.validate_utf8)
    {
      if (ws_message_validate_utf8 (ws, data, len) < 0)
        return -1;
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
          ws_set_error (ws,
                        WS_ERROR_INVALID_UTF8,
                        "Incomplete UTF-8 sequence at end of message");
          return -1;
        }
    }

  return 0;
}

static int
ws_finalize_assembled_message (SocketWS_T ws)
{
  assert (ws);

  /* Nothing to do if no payload yet */
  if (ws->message.len == 0 || ws->message.fragment_count == 0)
    return 0;

  if (ws->message.compressed)
    {
#ifdef SOCKETWS_HAS_DEFLATE
      unsigned char *decompressed = NULL;
      size_t decompressed_len = 0;

      if (ws_decompress_message (ws,
                                 ws->message.data,
                                 ws->message.len,
                                 &decompressed,
                                 &decompressed_len)
          < 0)
        return -1;

      ws->message.data = decompressed;
      ws->message.len = decompressed_len;
      ws->message.compressed = 0;
#else
      ws_set_error (
          ws,
          WS_ERROR_COMPRESSION,
          "Compressed message received but permessage-deflate not enabled");
      return -1;
#endif
    }

  return 0;
}

int
ws_requires_masking (SocketWS_T ws)
{
  assert (ws);

  /* Use transport's masking flag if transport is set */
  if (ws->transport)
    {
      return SocketWS_Transport_requires_masking (ws->transport);
    }

  /* Fallback: RFC 6455 rule - client frames must be masked */
  return ws->role == WS_ROLE_CLIENT;
}

static ssize_t
ws_send_contiguous (SocketWS_T ws, const void *ptr, size_t available)
{
  volatile ssize_t sent = 0;
  volatile int failed = 0;

  /* Use transport abstraction if available */
  if (ws->transport)
    {
      sent = SocketWS_Transport_send (ws->transport, ptr, available);
      if (sent < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
              /* Would block - not an error */
              sent = 0;
            }
          else if (errno == EPIPE)
            {
              ws_set_error (ws, WS_ERROR_CLOSED, NULL);
              ws->state = WS_STATE_CLOSED;
              ws->close_code = WS_CLOSE_ABNORMAL;
              return -1;
            }
          else
            {
              ws_set_error (ws, WS_ERROR, "Transport send failed");
              return -1;
            }
        }
    }
  else
    {
      /* Fallback to direct socket I/O for backward compatibility */
      TRY
      {
        sent = Socket_send (ws->socket, ptr, available);
      }
      EXCEPT (Socket_Closed)
      {
        /* Normal/expected close path: don't spam error logs. */
        ws_set_error (ws, WS_ERROR_CLOSED, NULL);
        ws->state = WS_STATE_CLOSED;
        ws->close_code = WS_CLOSE_ABNORMAL;
        failed = 1;
      }
      EXCEPT (Socket_Failed)
      {
        ws_set_error (ws, WS_ERROR, "Socket send failed");
        failed = 1;
      }
      END_TRY;

      if (failed)
        return -1;
    }

  if (sent <= 0)
    return 0; /* Would block / no progress */

  SocketBuf_consume (ws->send_buf, (size_t)sent);
  return sent;
}

ssize_t
ws_flush_send_buffer (SocketWS_T ws)
{
  size_t available;
  const void *ptr;

  assert (ws);
  assert (ws->socket || ws->transport); /* Need either socket or transport */

  available = SocketBuf_available (ws->send_buf);
  if (available == 0)
    return 0;

  /* Get contiguous read pointer */
  ptr = SocketBuf_readptr (ws->send_buf, &available);
  if (!ptr || available == 0)
    return 0;

  return ws_send_contiguous (ws, ptr, available);
}

static ssize_t
ws_recv_transport (SocketWS_T ws, void *ptr, size_t space)
{
  ssize_t received = SocketWS_Transport_recv (ws->transport, ptr, space);

  /* Handle would-block case */
  if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
    return 0; /* Would block - not an error */

  /* Handle other errors */
  if (received < 0)
    {
      ws_set_error (ws, WS_ERROR, "Transport recv failed");
      return -1;
    }

  /* Handle EOF */
  if (received == 0)
    {
      ws_set_error (ws, WS_ERROR_CLOSED, NULL);
      ws->state = WS_STATE_CLOSED;
      ws->close_code = WS_CLOSE_ABNORMAL;
    }

  return received;
}

static ssize_t
ws_recv_socket (SocketWS_T ws, void *ptr, size_t space)
{
  volatile ssize_t received = 0;
  volatile int failed = 0;

  TRY
  {
    received = Socket_recv (ws->socket, ptr, space);
  }
  EXCEPT (Socket_Closed)
  {
    /* EOF / connection closed */
    /* Normal/expected close path: don't spam error logs. */
    ws_set_error (ws, WS_ERROR_CLOSED, NULL);
    ws->state = WS_STATE_CLOSED;
    ws->close_code = WS_CLOSE_ABNORMAL;
    received = 0;
  }
  EXCEPT (Socket_Failed)
  {
    ws_set_error (ws, WS_ERROR, "Socket recv failed");
    failed = 1;
  }
  END_TRY;

  if (failed)
    return -1;

  return received;
}

static ssize_t
ws_recv_contiguous (SocketWS_T ws, void *ptr, size_t space)
{
  ssize_t received;

  /* Dispatch to appropriate transport */
  if (ws->transport)
    received = ws_recv_transport (ws, ptr, space);
  else
    received = ws_recv_socket (ws, ptr, space);

  /* Early return on would-block or error */
  if (received <= 0)
    return received;

  /* Success path: update buffer state */
  SocketBuf_written (ws->recv_buf, (size_t)received);
  return received;
}

ssize_t
ws_fill_recv_buffer (SocketWS_T ws)
{
  size_t space;
  void *ptr;

  assert (ws);
  assert (ws->socket || ws->transport); /* Need either socket or transport */

  /* Get contiguous write pointer */
  ptr = SocketBuf_writeptr (ws->recv_buf, &space);
  if (!ptr || space == 0)
    {
      /* Buffer full */
      return 0;
    }

  return ws_recv_contiguous (ws, ptr, space);
}

static void
ws_store_close_reason (SocketWS_T ws, const char *reason, size_t reason_len)
{
  if (reason && reason_len > 0)
    {
      /* Bound reason_len to prevent buffer overflow */
      if (reason_len > SOCKETWS_MAX_CLOSE_REASON)
        reason_len = SOCKETWS_MAX_CLOSE_REASON;
      memcpy (ws->close_reason, reason, reason_len);
      ws->close_reason[reason_len] = '\0';
    }
  else
    {
      ws->close_reason[0] = '\0';
    }
}

static int
ws_build_close_payload (unsigned char *payload,
                        size_t *payload_len,
                        SocketWS_CloseCode code,
                        const char *reason)
{
  size_t reason_len = 0;

  *payload_len = 0;

  if (reason)
    {
      reason_len = strlen (reason);
      if (reason_len > SOCKETWS_MAX_CLOSE_REASON)
        reason_len = SOCKETWS_MAX_CLOSE_REASON;
    }

  if (code != WS_CLOSE_NO_STATUS)
    {
      payload[0] = (code >> 8) & 0xFF;
      payload[1] = code & 0xFF;
      *payload_len = 2;

      if (reason_len > 0)
        {
          memcpy (payload + 2, reason, reason_len);
          *payload_len += reason_len;
        }
    }

  return 0;
}

static int
ws_prepare_close_state (SocketWS_T ws,
                        SocketWS_CloseCode code,
                        const char *reason,
                        unsigned char *payload,
                        size_t *payload_len)
{
  if (ws->state == WS_STATE_CLOSED || ws->close_sent)
    return 0; /* Already closed/sent */

  if (!ws_is_valid_close_code (code))
    {
      ws_set_error (ws, WS_ERROR_PROTOCOL, "Invalid close code %d", (int)code);
      return -1;
    }

  if (ws_build_close_payload (payload, payload_len, code, reason) < 0)
    return -1;

  ws->close_code = code;
  ws_store_close_reason (ws, reason, *payload_len > 2 ? *payload_len - 2 : 0);
  ws->close_sent = 1;

  if (ws->state == WS_STATE_OPEN)
    ws->state = WS_STATE_CLOSING;

  return 1; /* Prepared, send needed */
}

int
ws_send_close (SocketWS_T ws, SocketWS_CloseCode code, const char *reason)
{
  unsigned char payload[SOCKETWS_MAX_CONTROL_PAYLOAD];
  size_t payload_len;
  int prepared;

  assert (ws);

  prepared = ws_prepare_close_state (ws, code, reason, payload, &payload_len);
  if (prepared < 0)
    return -1;
  if (prepared == 0)
    return 0; /* Already closed */

  /* Send the frame */
  return ws_send_control_frame (ws, WS_OPCODE_CLOSE, payload, payload_len);
}

int
ws_send_ping (SocketWS_T ws, const unsigned char *payload, size_t len)
{
  assert (ws);

  if (len > SOCKETWS_MAX_CONTROL_PAYLOAD)
    {
      ws_set_error (ws,
                    WS_ERROR_PROTOCOL,
                    "Ping payload too large: %zu > %d",
                    len,
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

static int
ws_parse_close_payload (const unsigned char *payload,
                        size_t len,
                        SocketWS_CloseCode *code_out,
                        const char **reason_out,
                        size_t *reason_len_out)
{
  *code_out = WS_CLOSE_NO_STATUS;
  *reason_out = NULL;
  *reason_len_out = 0;

  if (len < 2)
    return 0;

  *code_out = (SocketWS_CloseCode)((payload[0] << 8) | payload[1]);
  if (len > 2)
    {
      *reason_out = (const char *)(payload + 2);
      *reason_len_out = len - 2;
    }

  return 1;
}

static int
ws_validate_and_store_close_reason (SocketWS_T ws,
                                    const char *reason,
                                    size_t reason_len)
{
  if (reason_len > SOCKETWS_MAX_CLOSE_REASON)
    reason_len = SOCKETWS_MAX_CLOSE_REASON;

  /* Validate close reason as UTF-8 */
  if (ws->config.validate_utf8 && reason_len > 0)
    {
      SocketUTF8_Result result
          = SocketUTF8_validate ((const unsigned char *)reason, reason_len);
      if (result != UTF8_VALID)
        {
          ws_set_error (
              ws, WS_ERROR_INVALID_UTF8, "Invalid UTF-8 in close reason");
          return -1;
        }
    }

  ws_store_close_reason (ws, reason, reason_len);
  return 0;
}

static int
ws_handle_close_frame (SocketWS_T ws, const unsigned char *payload, size_t len)
{
  SocketWS_CloseCode code;
  const char *reason;
  size_t reason_len;
  int parsed;

  parsed = ws_parse_close_payload (payload, len, &code, &reason, &reason_len);
  if (!parsed)
    {
      /* Invalid payload, but per RFC treat as no status */
      code = WS_CLOSE_NO_STATUS;
      reason = NULL;
      reason_len = 0;
    }

  /* Store peer's close info */
  ws->close_received = 1;
  if (code != WS_CLOSE_NO_STATUS)
    ws->close_code = code;

  if (ws_validate_and_store_close_reason (ws, reason, reason_len) < 0)
    {
      /* Send protocol error close */
      ws_send_close (
          ws, WS_CLOSE_INVALID_PAYLOAD, "Invalid UTF-8 in close reason");
      ws->state = WS_STATE_CLOSED;
      return -1;
    }

  /* Respond with close if we haven't sent one (echo code) */
  if (!ws->close_sent)
    ws_send_close (ws, code, NULL);

  /* Transition to closed */
  ws->state = WS_STATE_CLOSED;
  return 0;
}

int
ws_handle_control_frame (SocketWS_T ws,
                         SocketWS_Opcode opcode,
                         const unsigned char *payload,
                         size_t len)
{
  assert (ws);

  switch (opcode)
    {
    case WS_OPCODE_CLOSE:
      return ws_handle_close_frame (ws, payload, len);

    case WS_OPCODE_PING:
      return ws_send_pong (ws, payload, len);

    case WS_OPCODE_PONG:
      ws->last_pong_received_time = Socket_get_monotonic_ms ();
      ws->awaiting_pong = 0;

      /* Optional: Validate pong payload matches pending ping (prevents
       * spoofing) */
      if (ws->pending_ping_len > 0
          && (len != (size_t)ws->pending_ping_len
              || SocketCrypto_secure_compare (
                     payload,
                     (const unsigned char *)ws->pending_ping_payload,
                     len)
                     != 0))
        {
          SOCKET_LOG_WARN_MSG (
              "Pong payload mismatch - possible spoofing; closing connection");
          ws_send_close (ws, WS_CLOSE_PROTOCOL_ERROR, "Pong payload mismatch");
          return -1;
        }

      return 0;

    default:
      ws_set_error (
          ws, WS_ERROR_PROTOCOL, "Unknown control opcode: 0x%02X", opcode);
      return -1;
    }
}

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
          SocketLog_emitf (SOCKET_LOG_WARN,
                           SOCKET_LOG_COMPONENT,
                           "Ping timeout after %lld ms",
                           (long long)elapsed);
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
  ws->ping_timer = SocketTimer_add_repeating (
      poll, ws->config.ping_interval_ms, ws_auto_ping_callback, ws);

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

static void
ws_prepare_config (SocketWS_Config *cfg,
                   const SocketWS_Config *config,
                   SocketWS_Role role)
{
  if (config)
    *cfg = *config;
  else
    SocketWS_config_defaults (cfg);

  cfg->role = role;
}

static SocketWS_T
ws_create_context (const SocketWS_Config *config)
{
  Arena_T arena;
  SocketWS_T ws;

  arena = Arena_new ();
  if (!arena)
    {
      SOCKET_RAISE_MSG (SocketWS, SocketWS_Failed, "Failed to create arena");
    }

  ws = ws_alloc_context (arena, config);
  if (!ws)
    {
      Arena_dispose (&arena);
      SOCKET_RAISE_MSG (
          SocketWS, SocketWS_Failed, "Failed to allocate WebSocket context");
    }

  return ws;
}

SocketWS_T
SocketWS_client_new (Socket_T socket,
                     const char *host,
                     const char *path,
                     const SocketWS_Config *config)
{
  SocketWS_Config cfg;
  SocketWS_T ws;

  assert (socket);
  assert (host);

  ws_prepare_config (&cfg, config, WS_ROLE_CLIENT);
  ws = ws_create_context (&cfg);

  TRY
  {
    ws->socket = socket;
    /* SocketWS_process() is event-driven and relies on non-blocking I/O. */
    Socket_setnonblocking (ws->socket);
    ws->host = ws_copy_string (ws->arena, host);
    ws->path = ws_copy_string (ws->arena, path ? path : "/");

    if (ws_handshake_client_init (ws) < 0)
      {
        SOCKET_RAISE_MSG (
            SocketWS, SocketWS_Failed, "Failed to initialize handshake");
      }
  }
  EXCEPT (Socket_Failed)
  {
    SOCKET_RAISE_MSG (SocketWS,
                      SocketWS_Failed,
                      "Failed to set WebSocket socket to non-blocking mode");
  }
  EXCEPT (SocketWS_Failed)
  {
    Arena_T arena = ws->arena;
    Arena_dispose (&arena);
    RERAISE;
  }
  END_TRY;

  return ws;
}

SocketWS_T
SocketWS_server_accept (Socket_T socket,
                        const SocketHTTP_Request *request,
                        const SocketWS_Config *config)
{
  SocketWS_Config cfg;
  SocketWS_T ws;

  assert (socket);
  assert (request);

  ws_prepare_config (&cfg, config, WS_ROLE_SERVER);
  ws = ws_create_context (&cfg);

  TRY
  {
    ws->socket = socket;
    /* SocketWS_process() is event-driven and relies on non-blocking I/O. */
    Socket_setnonblocking (ws->socket);

    if (ws_handshake_server_init (ws, request) < 0)
      {
        SOCKET_RAISE_MSG (
            SocketWS, SocketWS_Failed, "Failed to initialize server handshake");
      }
  }
  EXCEPT (Socket_Failed)
  {
    SOCKET_RAISE_MSG (SocketWS,
                      SocketWS_Failed,
                      "Failed to set WebSocket socket to non-blocking mode");
  }
  EXCEPT (SocketWS_Failed)
  {
    Arena_T arena = ws->arena;
    Arena_dispose (&arena);
    RERAISE;
  }
  END_TRY;

  return ws;
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

int
SocketWS_pollfd (SocketWS_T ws)
{
  assert (ws);

  /* Use transport abstraction if available */
  if (ws->transport)
    {
      return SocketWS_Transport_get_fd (ws->transport);
    }

  /* Fallback to direct socket access */
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

static int
ws_process_frames (SocketWS_T ws)
{
  SocketWS_FrameParse frame = { 0 };

  assert (ws);

  /* If a message is already assembled, do not consume further frames until the
   * caller retrieves it. */
  if (ws->message.len > 0 && ws->message.fragment_count > 0)
    return 1;

  while (1)
    {
      int result = ws_recv_frame (ws, &frame);
      if (result == -2)
        return 0; /* Would block / need more data */
      if (result < 0)
        return -1; /* Error */

      /* Control frames handled internally; continue draining */
      if (result == 0)
        continue;

      /* Data message completed */
      if (ws_finalize_assembled_message (ws) < 0)
        return -1;
      return 1;
    }
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

      /* Parse any buffered frames into messages */
      if (ws->state == WS_STATE_OPEN)
        {
          int frame_result = ws_process_frames (ws);
          if (frame_result < 0)
            return -1;
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

int
SocketWS_send_text (SocketWS_T ws, const char *data, size_t len)
{
  assert (ws);

  if (!ws_ensure_open (ws))
    return -1;

  /* Validate UTF-8 if configured */
  if (ws->config.validate_utf8)
    {
      SocketUTF8_Result result
          = SocketUTF8_validate ((const unsigned char *)data, len);
      if (result != UTF8_VALID)
        {
          ws_set_error (ws,
                        WS_ERROR_INVALID_UTF8,
                        "Invalid UTF-8 in outgoing text: %s",
                        SocketUTF8_result_string (result));
          return -1;
        }
    }

  return ws_send_data_frame (
      ws, WS_OPCODE_TEXT, (const unsigned char *)data, len, 1);
}

int
SocketWS_send_binary (SocketWS_T ws, const void *data, size_t len)
{
  assert (ws);

  if (!ws_ensure_open (ws))
    return -1;

  return ws_send_data_frame (ws, WS_OPCODE_BINARY, data, len, 1);
}

int
SocketWS_ping (SocketWS_T ws, const void *data, size_t len)
{
  assert (ws);

  if (!ws_ensure_open (ws))
    return -1;

  return ws_send_ping (ws, data, len);
}

int
SocketWS_pong (SocketWS_T ws, const void *data, size_t len)
{
  assert (ws);

  if (!ws_ensure_open (ws))
    return -1;

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

/**
 * @brief Parse WebSocket URL scheme (ws:// or wss://).
 * @internal
 * @param url Pointer to URL pointer (advanced past scheme on success)
 * @param[out] use_tls TLS flag (1 for wss://, 0 for ws://)
 * @param[out] port Default port (443 for wss://, 80 for ws://)
 * @return 0 on success, -1 on invalid scheme
 */
static int
ws_parse_url_scheme (const char **url, int *use_tls, int *port)
{
  if (strncmp (*url, "wss://", 6) == 0)
    {
      *use_tls = 1;
      *port = 443;
      *url += 6;
      return 0;
    }
  if (strncmp (*url, "ws://", 5) == 0)
    {
      *use_tls = 0;
      *port = 80;
      *url += 5;
      return 0;
    }
  SOCKET_ERROR_MSG ("Invalid WebSocket URL scheme (expected ws:// or wss://)");
  return -1;
}

/**
 * @brief Extract host from URL (up to port colon or path slash).
 * @internal
 * @param url URL string after scheme
 * @param port_start Position of ':' or NULL
 * @param path_start Position of '/' or NULL
 * @param[out] host Buffer for hostname (size NI_MAXHOST)
 */
static void
ws_extract_host (const char *url,
                 const char *port_start,
                 const char *path_start,
                 char *host)
{
  size_t host_len;

  if (port_start && (!path_start || port_start < path_start))
    host_len = (size_t)(port_start - url);
  else if (path_start)
    host_len = (size_t)(path_start - url);
  else
    host_len = strlen (url);

  if (host_len >= NI_MAXHOST)
    host_len = NI_MAXHOST - 1;

  memcpy (host, url, host_len);
  host[host_len] = '\0';
}

/**
 * @brief Parse port number from URL.
 * @internal
 * @param port_start Position of ':' in URL
 * @param path_start Position of '/' or NULL (for bounds checking)
 * @param[out] port Parsed port number
 * @return 0 on success, -1 on invalid port
 */
static int
ws_parse_url_port (const char *port_start, const char *path_start, int *port)
{
  char *endptr;
  long p;

  if (!port_start || (path_start && port_start >= path_start))
    return 0;

  p = strtol (port_start + 1, &endptr, 10);
  if (endptr == port_start + 1 || p < 1 || p > 65535)
    {
      SOCKET_ERROR_MSG ("Invalid port in WebSocket URL");
      return -1;
    }
  *port = (int)p;
  return 0;
}

/**
 * @brief Extract path from URL.
 * @internal
 * @param path_start Position of '/' in URL or NULL
 * @param[out] path Buffer for path (size SOCKETWS_MAX_PATH_SIZE)
 */
static void
ws_extract_path (const char *path_start, char *path)
{
  if (path_start)
    {
      strncpy (path, path_start, SOCKETWS_MAX_PATH_SIZE - 1);
      path[SOCKETWS_MAX_PATH_SIZE - 1] = '\0';
    }
  else
    {
      path[0] = '/';
      path[1] = '\0';
    }
}

/**
 * @brief Parse WebSocket URL into host, port, path, and TLS flag.
 * @internal
 * @param url The WebSocket URL (ws:// or wss://)
 * @param[out] host Buffer for hostname (size NI_MAXHOST)
 * @param[out] port Port number (default 80/443)
 * @param[out] path Buffer for path (size SOCKETWS_MAX_PATH_SIZE)
 * @param[out] use_tls TLS flag (1 for wss://, 0 for ws://)
 * @return 0 on success, -1 on error
 */
static int
ws_parse_url (const char *url, char *host, int *port, char *path, int *use_tls)
{
  const char *path_start;
  const char *port_start;

  assert (url);
  assert (host);
  assert (port);
  assert (path);
  assert (use_tls);

  if (ws_parse_url_scheme (&url, use_tls, port) < 0)
    return -1;

  path_start = strchr (url, '/');
  port_start = strchr (url, ':');

  ws_extract_host (url, port_start, path_start, host);

  if (ws_parse_url_port (port_start, path_start, port) < 0)
    return -1;

  ws_extract_path (path_start, path);

  return 0;
}

/**
 * @brief Create and connect socket with optional TLS.
 * @internal
 * @param host Hostname to connect to
 * @param port Port number
 * @param use_tls Enable TLS if non-zero
 * @return Socket_T on success, NULL on error (raises exception)
 */
static Socket_T
ws_create_and_connect_socket (const char *host, int port, int use_tls)
{
  Socket_T sock = NULL;

  assert (host);

  sock = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_connect (sock, host, port);

#if SOCKET_HAS_TLS
  if (use_tls)
    {
      extern void SocketTLS_enable (Socket_T, void *);
      extern int SocketTLS_handshake_loop (Socket_T, int);
      extern void SocketTLS_set_hostname (Socket_T, const char *);

      /* Enable TLS with default context */
      SocketTLS_enable (sock, NULL);
      SocketTLS_set_hostname (sock, host);
      if (SocketTLS_handshake_loop (sock, 10000) < 0)
        {
          SOCKET_ERROR_MSG ("TLS handshake failed");
          RAISE_WS_ERROR (SocketWS_Failed);
        }
    }
#else
  if (use_tls)
    {
      Socket_free (&sock);
      SOCKET_ERROR_MSG ("TLS not available (compile with -DENABLE_TLS=ON)");
      RAISE_WS_ERROR (SocketWS_Failed);
      return NULL;
    }
#endif

  return sock;
}

/**
 * @brief Complete WebSocket handshake with polling.
 * @internal
 * @param ws WebSocket context
 * @param sock Underlying socket
 * @return 0 on success, -1 on error
 */
static int
ws_complete_handshake (SocketWS_T ws, Socket_T sock)
{
  int result;

  assert (ws);
  assert (sock);

  while ((result = SocketWS_handshake (ws)) > 0)
    {
      struct pollfd pfd
          = { .fd = Socket_fd (sock), .events = POLLIN | POLLOUT };
      poll (&pfd, 1, SOCKETWS_HANDSHAKE_TIMEOUT_MS);
      SocketWS_process (ws, ws_translate_poll_revents (pfd.revents));
    }

  if (result < 0 || ws->state != WS_STATE_OPEN)
    return -1;

  return 0;
}

/**
 * @brief Set up WebSocket configuration with optional subprotocols.
 * @internal
 * @param[out] config Configuration structure to populate
 * @param protocols Optional comma-separated subprotocols string
 * @param[out] proto_array Storage for subprotocols array
 */
static void
ws_setup_websocket_config (SocketWS_Config *config,
                           const char *protocols,
                           const char **proto_array)
{
  assert (config);
  assert (proto_array);

  SocketWS_config_defaults (config);
  config->role = WS_ROLE_CLIENT;

  if (protocols)
    {
      proto_array[0] = protocols;
      proto_array[1] = NULL;
      config->subprotocols = proto_array;
    }
}

/**
 * @brief Create WebSocket and complete handshake.
 * @internal
 * @param sock Connected socket
 * @param host Hostname for WebSocket handshake
 * @param path URL path for WebSocket handshake
 * @param config WebSocket configuration
 * @return WebSocket context on success, NULL on error
 */
static SocketWS_T
ws_create_and_handshake (Socket_T sock,
                         const char *host,
                         const char *path,
                         const SocketWS_Config *config)
{
  SocketWS_T ws;

  assert (sock);
  assert (host);
  assert (path);
  assert (config);

  ws = SocketWS_client_new (sock, host, path, config);
  if (!ws)
    {
      Socket_free (&sock);
      return NULL;
    }

  if (ws_complete_handshake (ws, sock) != 0)
    {
      SocketWS_free (&ws);
      return NULL;
    }

  return ws;
}

SocketWS_T
SocketWS_connect (const char *url, const char *protocols)
{
  SocketWS_T ws = NULL;
  Socket_T sock = NULL;
  SocketWS_Config config;
  char host[NI_MAXHOST] = { 0 };
  char path[SOCKETWS_MAX_PATH_SIZE] = { 0 };
  volatile int port = 80;
  volatile int use_tls = 0;
  const char *proto_array[2] = { NULL, NULL };

  assert (url);

  /* Parse URL */
  if (ws_parse_url (url, host, (int *)&port, path, (int *)&use_tls) != 0)
    {
      RAISE_WS_ERROR (SocketWS_Failed);
      return NULL;
    }

  /* Create and connect socket, set up WebSocket */
  TRY
  {
    sock = ws_create_and_connect_socket (host, port, use_tls);
    ws_setup_websocket_config (&config, protocols, proto_array);
    ws = ws_create_and_handshake (sock, host, path, &config);
  }
  EXCEPT (Socket_Failed)
  {
    if (sock)
      Socket_free (&sock);
    RERAISE;
  }
  EXCEPT (SocketWS_Failed)
  {
    if (ws)
      SocketWS_free (&ws);
    else if (sock)
      Socket_free (&sock);
    RERAISE;
  }
  END_TRY;

  return ws;
}

int
SocketWS_send_json (SocketWS_T ws, const char *json)
{
  assert (ws);
  assert (json);

  return SocketWS_send_text (ws, json, strlen (json));
}

SocketWS_Error
SocketWS_recv_json (SocketWS_T ws, char **json_out, size_t *json_len)
{
  assert (ws);
  assert (json_out);
  assert (json_len);

  *json_out = NULL;
  *json_len = 0;

  SocketWS_Message msg = { 0 };
  int recv_result = SocketWS_recv_message (ws, &msg);
  if (recv_result < 0)
    return ws->last_error;

  /* Only accept text frames for JSON */
  if (msg.type != WS_OPCODE_TEXT)
    {
      if (msg.data)
        free (msg.data);
      ws_set_error (ws, WS_ERROR_PROTOCOL, "Expected text frame for JSON");
      return WS_ERROR_PROTOCOL;
    }

  /* Check for overflow before malloc(msg.len + 1) */
  size_t alloc_size;
  if (!SocketSecurity_check_add (msg.len, 1, &alloc_size))
    {
      if (msg.data)
        free (msg.data);
      ws_set_error (ws, WS_ERROR, "Message size overflow");
      return WS_ERROR;
    }

  *json_out = malloc (alloc_size);
  if (!*json_out)
    {
      if (msg.data)
        free (msg.data);
      ws_set_error (ws, WS_ERROR, "Out of memory");
      return WS_ERROR;
    }

  memcpy (*json_out, msg.data, msg.len);
  (*json_out)[msg.len] = '\0';
  *json_len = msg.len;

  free (msg.data);
  return WS_OK;
}

int64_t
SocketWS_get_ping_latency (SocketWS_T ws)
{
  assert (ws);

  /* If no ping sent yet or still awaiting pong, no data */
  if (ws->last_ping_sent_time == 0)
    return -1;

  /* If awaiting pong, use last successful measurement */
  if (ws->awaiting_pong)
    {
      /* Check if we have any previous successful ping */
      if (ws->last_pong_received_time <= 0)
        return -1;

      /* Return last known RTT if we have historical data */
      /* This requires storing the last RTT - for now return -1 */
      return -1;
    }

  /* Calculate RTT from most recent ping/pong cycle */
  if (ws->last_pong_received_time > ws->last_ping_sent_time)
    return ws->last_pong_received_time - ws->last_ping_sent_time;

  return -1;
}

int
SocketWS_recv_available (SocketWS_T ws)
{
  assert (ws);

  /* Check if we have a complete message assembled */
  if (ws->message.len > 0 && ws->message.fragment_count > 0)
    {
      /* Only return data messages to user - control frames are handled
       * internally */
      return (ws->message.type == WS_OPCODE_TEXT
              || ws->message.type == WS_OPCODE_BINARY)
                 ? 1
                 : 0;
    }

  return 0;
}

static int
ws_poll_for_message (SocketWS_T ws)
{
  assert (ws);

  while (1)
    {
      /* Deliver if message already assembled */
      if (ws->message.len > 0 && ws->message.fragment_count > 0)
        return 0;

      /* Closed? */
      if (ws->state == WS_STATE_CLOSED)
        {
          ws_set_error (ws, WS_ERROR_CLOSED, "Connection closed");
          return -1;
        }

      /* Poll for events and process */
      struct pollfd pfd = { 0 };
      pfd.fd = Socket_fd (ws->socket);
      pfd.events = POLLIN;
      if (SocketBuf_available (ws->send_buf) > 0)
        pfd.events |= POLLOUT;

      int timeout_ms
          = (ws->config.ping_timeout_ms > 0) ? ws->config.ping_timeout_ms : -1;

      int poll_result = poll (&pfd, 1, timeout_ms);
      if (poll_result < 0)
        {
          if (errno == EINTR)
            continue;
          ws_set_error (ws, WS_ERROR, "Poll failed");
          return -1;
        }
      if (poll_result == 0)
        {
          ws_set_error (ws, WS_ERROR_TIMEOUT, "Timeout waiting for message");
          return -1;
        }

      unsigned ev = ws_translate_poll_revents (pfd.revents);
      if (ev == 0)
        continue;

      if (SocketWS_process (ws, ev) < 0)
        return -1;
    }
}

static int
ws_validate_message_type (SocketWS_T ws)
{
  assert (ws);

  /* Only return data messages - control frames are handled internally */
  if (ws->message.type != WS_OPCODE_TEXT
      && ws->message.type != WS_OPCODE_BINARY)
    {
      ws_message_reset (&ws->message);
      ws_set_error (ws,
                    WS_ERROR_PROTOCOL,
                    "Control frame received but not returned to user");
      return -1;
    }

  return 0;
}

static int
ws_copy_message_to_output (SocketWS_T ws, SocketWS_Message *msg)
{
  assert (ws);
  assert (msg);

  /* Allocate buffer for the message */
  msg->data = malloc (ws->message.len);
  if (!msg->data)
    {
      ws_set_error (ws, WS_ERROR, "Out of memory allocating message buffer");
      return -1;
    }

  /* Copy message data */
  memcpy (msg->data, ws->message.data, ws->message.len);
  msg->len = ws->message.len;
  msg->type = ws->message.type;

  return 0;
}

int
SocketWS_recv_message (SocketWS_T ws, SocketWS_Message *msg)
{
  assert (ws);
  assert (msg);

  /* Initialize output */
  memset (msg, 0, sizeof (*msg));
  msg->type = WS_OPCODE_TEXT;

  /* Poll until message is ready */
  if (ws_poll_for_message (ws) < 0)
    return -1;

  /* Validate message type */
  if (ws_validate_message_type (ws) < 0)
    return -1;

  /* Finalize assembled message (decompress if needed) */
  if (ws_finalize_assembled_message (ws) < 0)
    return -1;

  /* Copy to output buffer */
  if (ws_copy_message_to_output (ws, msg) < 0)
    return -1;

  /* Reset message assembly for next message */
  ws_message_reset (&ws->message);

  /* Return 1 on success per API contract */
  return 1;
}

void
SocketWS_compression_options_defaults (SocketWS_CompressionOptions *options)
{
  assert (options);

  memset (options, 0, sizeof (*options));
  options->level = SOCKETWS_DEFAULT_DEFLATE_COMPRESSION_LEVEL;
  options->server_no_context_takeover = 0;
  options->client_no_context_takeover = 0;
  options->server_max_window_bits = SOCKETWS_DEFAULT_DEFLATE_WINDOW_BITS;
  options->client_max_window_bits = SOCKETWS_DEFAULT_DEFLATE_WINDOW_BITS;
}

int
SocketWS_enable_compression (SocketWS_T ws,
                             const SocketWS_CompressionOptions *options)
{
  assert (ws);

#ifdef SOCKETWS_HAS_DEFLATE
  /* Can only enable before handshake completes */
  if (ws->state != WS_STATE_CONNECTING)
    {
      ws_set_error (ws, WS_ERROR, "Cannot enable compression after handshake");
      return -1;
    }

  /* Enable compression in config */
  ws->config.enable_permessage_deflate = 1;

  if (options)
    {
      /* Store compression parameters for handshake */
      /* Note: compression level is not stored in config, used during handshake
       */
      (void)options; /* Compression options handled during handshake */
    }

  return 0;
#else
  (void)options;
  ws_set_error (
      ws, WS_ERROR, "Compression not available (compile with zlib support)");
  return -1;
#endif
}

#undef T
