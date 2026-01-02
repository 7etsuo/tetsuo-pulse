/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/*
 * SocketHTTP2-priority.c - RFC 9218 Extensible Priorities for HTTP/2
 *
 * Implements the Extensible Priority scheme that replaces the deprecated
 * RFC 7540 priority mechanism. Supports:
 * - Priority header field parsing/serialization
 * - PRIORITY_UPDATE frame (type 0x10) processing and sending
 * - Stream priority tracking
 */

#include "http/SocketHTTP2-private.h"
#include "http/SocketHTTP2.h"

#include "core/SocketUtil.h"

#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <string.h>

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "HTTP2"

/* PRIORITY_UPDATE frame minimum payload size: 4 bytes for stream ID */
#define PRIORITY_UPDATE_MIN_PAYLOAD_SIZE 4

/* Stream ID size in PRIORITY_UPDATE payload (always 4 bytes) */
#define PRIORITY_UPDATE_STREAM_ID_SIZE 4

void
SocketHTTP2_Priority_init (SocketHTTP2_Priority *priority)
{
  assert (priority);
  priority->urgency = SOCKETHTTP2_PRIORITY_DEFAULT_URGENCY;
  priority->incremental = 0;
}

/*
 * Skip whitespace in a string.
 * Returns pointer to first non-whitespace character.
 */
static const char *
skip_ows (const char *p, const char *end)
{
  while (p < end && (*p == ' ' || *p == '\t'))
    p++;
  return p;
}


/*
 * Parse a Structured Fields Dictionary key.
 * RFC 8941: key = ( lcalpha / "*" ) *( lcalpha / DIGIT / "_" / "-" / "." / "*"
 * ) For priority, we only care about "u" and "i".
 */
static int
parse_key (const char **pp,
           const char *end,
           const char **key_start,
           size_t *key_len)
{
  const char *p = *pp;
  const char *start;

  if (p >= end)
    return -1;

  /* First character must be lcalpha or '*' */
  if (!((*p >= 'a' && *p <= 'z') || *p == '*'))
    return -1;

  start = p;
  p++;

  /* Subsequent characters: lcalpha, DIGIT, '_', '-', '.', '*' */
  while (p < end)
    {
      char c = *p;
      if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'
          || c == '-' || c == '.' || c == '*')
        {
          p++;
        }
      else
        {
          break;
        }
    }

  *key_start = start;
  *key_len = (size_t)(p - start);
  *pp = p;
  return 0;
}

/*
 * Parse urgency value from Priority header (RFC 9218, RFC 8941).
 * Parses integer in range [0-7] following RFC 8941 integer grammar.
 * Returns parsed urgency value on success, -1 on error.
 */
static int
parse_urgency_value (const char **pp, const char *end)
{
  const char *p = *pp;
  int urgency = 0;
  int digits = 0;

  if (p >= end)
    {
      SOCKET_LOG_DEBUG_MSG ("Priority parse error: invalid u value");
      return -1;
    }

  /* Parse digits (RFC 8941: integer = ["-"] 1*15DIGIT) */
  while (p < end && *p >= '0' && *p <= '9')
    {
      int digit = *p - '0';

      /* Check BEFORE multiplication to prevent integer overflow */
      if (urgency > (INT_MAX - digit) / 10)
        {
          SOCKET_LOG_DEBUG_MSG ("Priority parse error: u value would overflow");
          return -1;
        }

      urgency = urgency * 10 + digit;
      digits++;
      p++;

      /* Bounds check for valid urgency range [0-7] */
      if (urgency > SOCKETHTTP2_PRIORITY_MAX_URGENCY)
        {
          SOCKET_LOG_DEBUG_MSG (
              "Priority parse error: u=%d out of range [0-7]", urgency);
          return -1;
        }

      if (digits > 15)
        {
          SOCKET_LOG_DEBUG_MSG (
              "Priority parse error: invalid u value (too many digits)");
          return -1;
        }
    }

  if (digits == 0)
    {
      SOCKET_LOG_DEBUG_MSG ("Priority parse error: invalid u value");
      return -1;
    }

  *pp = p;
  return urgency;
}

/*
 * Parse Priority header field value (RFC 9218 Section 4).
 *
 * Grammar (subset of SF-Dictionary):
 *   priority = sf-dictionary
 *   sf-dictionary = dict-member *( OWS "," OWS dict-member )
 *   dict-member = member-key ( "=" member-value )?
 *
 * For Priority:
 *   u = urgency (integer 0-7)
 *   i = incremental (boolean, presence means true)
 *
 * Examples:
 *   "u=3"       -> urgency=3, incremental=false
 *   "u=0, i"    -> urgency=0, incremental=true
 *   "i, u=5"    -> urgency=5, incremental=true
 *   "u=3, i=?0" -> urgency=3, incremental=false (explicit false)
 */
int
SocketHTTP2_Priority_parse (const char *value,
                            size_t len,
                            SocketHTTP2_Priority *priority)
{
  const char *p;
  const char *end;
  int found_urgency = 0;
  int found_incremental = 0;

  assert (priority);

  /* Initialize to defaults */
  SocketHTTP2_Priority_init (priority);

  if (!value || len == 0)
    return 0; /* Empty value uses defaults */

  p = value;
  end = value + len;

  while (p < end)
    {
      const char *key_start;
      size_t key_len;

      /* Skip leading whitespace */
      p = skip_ows (p, end);
      if (p >= end)
        break;

      /* Parse key */
      if (parse_key (&p, end, &key_start, &key_len) < 0)
        {
          SOCKET_LOG_DEBUG_MSG ("Priority parse error: invalid key");
          return -1;
        }

      /* Check for known keys */
      if (key_len == 1 && *key_start == 'u')
        {
          /* Urgency parameter */
          int urgency;

          p = skip_ows (p, end);
          if (p >= end || *p != '=')
            {
              SOCKET_LOG_DEBUG_MSG ("Priority parse error: u requires value");
              return -1;
            }
          p++; /* Skip '=' */
          p = skip_ows (p, end);

          urgency = parse_urgency_value (&p, end);
          if (urgency < 0)
            return -1;

          priority->urgency = (uint8_t)urgency;
          found_urgency = 1;
        }
      else if (key_len == 1 && *key_start == 'i')
        {
          /* Incremental parameter (boolean) */
          p = skip_ows (p, end);

          /* Handle bare "i" (no explicit value) */
          if (p >= end || *p != '=')
            {
              priority->incremental = 1;
              found_incremental = 1;
              goto next_parameter;
            }

          /* Parse explicit boolean value */
          p++; /* Skip '=' */
          p = skip_ows (p, end);

          if (p >= end || *p != '?')
            {
              SOCKET_LOG_DEBUG_MSG (
                  "Priority parse error: i= requires ?0 or ?1");
              return -1;
            }

          p++; /* Skip '?' */
          if (p >= end)
            {
              SOCKET_LOG_DEBUG_MSG (
                  "Priority parse error: invalid boolean for i");
              return -1;
            }

          if (*p == '1')
            {
              priority->incremental = 1;
            }
          else if (*p == '0')
            {
              priority->incremental = 0;
            }
          else
            {
              SOCKET_LOG_DEBUG_MSG (
                  "Priority parse error: invalid boolean for i");
              return -1;
            }

          p++;
          found_incremental = 1;
        }
      else
        {
          /* Unknown parameter - skip to next comma or end */
          /* RFC 9218: Unknown parameters MUST be ignored */
          while (p < end && *p != ',')
            p++;
        }

    next_parameter:
      /* Skip to next parameter */
      p = skip_ows (p, end);
      if (p < end && *p == ',')
        {
          p++; /* Skip comma */
        }
    }

  /* Log parsed values for debugging */
  if (found_urgency || found_incremental)
    {
      SOCKET_LOG_DEBUG_MSG ("Parsed Priority: u=%d, i=%d",
                            priority->urgency,
                            priority->incremental);
    }

  return 0;
}

ssize_t
SocketHTTP2_Priority_serialize (const SocketHTTP2_Priority *priority,
                                char *buf,
                                size_t buf_size)
{
  size_t len = 0;
  int wrote_param = 0;

  assert (priority);
  assert (buf || buf_size == 0);

  /* Only write urgency if not default */
  if (priority->urgency != SOCKETHTTP2_PRIORITY_DEFAULT_URGENCY)
    {
      /* "u=N" is 3 characters */
      if (buf_size < 3)
        return -1;
      buf[len++] = 'u';
      buf[len++] = '=';
      buf[len++] = (char)('0' + priority->urgency);
      wrote_param = 1;
    }

  /* Write incremental if true */
  if (priority->incremental)
    {
      if (wrote_param)
        {
          /* ", i" needs 3 more characters */
          if (len + 3 > buf_size)
            return -1;
          buf[len++] = ',';
          buf[len++] = ' ';
        }
      if (len + 1 > buf_size)
        return -1;
      buf[len++] = 'i';
    }

  /* If nothing written, we could write nothing or write defaults */
  /* RFC 9218: omitting a parameter is equivalent to the default value */

  return (ssize_t)len;
}

int
SocketHTTP2_Stream_get_priority (SocketHTTP2_Stream_T stream,
                                 SocketHTTP2_Priority *priority)
{
  assert (stream);
  assert (priority);

  *priority = stream->priority;
  return 0;
}

int
SocketHTTP2_Stream_set_priority (SocketHTTP2_Stream_T stream,
                                 const SocketHTTP2_Priority *priority)
{
  assert (stream);
  assert (priority);

  if (priority->urgency > SOCKETHTTP2_PRIORITY_MAX_URGENCY)
    return -1;

  stream->priority = *priority;
  return 0;
}

int
SocketHTTP2_send_priority_update (SocketHTTP2_Conn_T conn,
                                  uint32_t stream_id,
                                  const SocketHTTP2_Priority *priority)
{
  SocketHTTP2_FrameHeader header;
  unsigned char payload[SOCKETHTTP2_PRIORITY_UPDATE_MAX_PAYLOAD];
  char priority_field[SOCKETHTTP2_PRIORITY_FIELD_MAX_LEN];
  ssize_t priority_len;
  size_t payload_len;

  assert (conn);
  assert (priority);

  if (stream_id == 0)
    return -1; /* Stream 0 cannot be reprioritized */

  /* Serialize priority to SF-Dictionary format */
  priority_len = SocketHTTP2_Priority_serialize (
      priority, priority_field, sizeof (priority_field));
  if (priority_len < 0)
    return -1;

  /* Build payload: Prioritized Stream ID (4 bytes) + Priority Field Value */
  payload_len = PRIORITY_UPDATE_STREAM_ID_SIZE + (size_t)priority_len;
  if (payload_len > sizeof (payload))
    return -1;

  /* Write stream ID (31-bit, R bit reserved) */
  write_u31_be (payload, stream_id);

  /* Copy priority field value */
  if (priority_len > 0)
    memcpy (payload + PRIORITY_UPDATE_STREAM_ID_SIZE,
            priority_field,
            (size_t)priority_len);

  /* Build frame header */
  header.length = (uint32_t)payload_len;
  header.type = HTTP2_FRAME_PRIORITY_UPDATE;
  header.flags = 0;
  header.stream_id = 0; /* PRIORITY_UPDATE is sent on stream 0 */

  SOCKET_LOG_DEBUG_MSG ("Sending PRIORITY_UPDATE: stream=%u u=%d i=%d",
                        stream_id,
                        priority->urgency,
                        priority->incremental);

  return http2_frame_send (conn, &header, payload, payload_len);
}

int
http2_process_priority_update (SocketHTTP2_Conn_T conn,
                               const SocketHTTP2_FrameHeader *header,
                               const unsigned char *payload)
{
  uint32_t prioritized_stream_id;
  SocketHTTP2_Stream_T stream;
  SocketHTTP2_Priority priority;

  assert (conn);
  assert (header);
  assert (payload || header->length == 0);

  /* RFC 9218 Section 7.1: PRIORITY_UPDATE on non-zero stream is error */
  if (header->stream_id != 0)
    {
      SOCKET_LOG_WARN_MSG ("PRIORITY_UPDATE received on stream %u (must be 0)",
                           header->stream_id);
      http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
      return -1;
    }

  /* Minimum payload: 4 bytes for Prioritized Stream ID */
  if (header->length < PRIORITY_UPDATE_MIN_PAYLOAD_SIZE)
    {
      SOCKET_LOG_WARN_MSG ("PRIORITY_UPDATE frame too small: %u bytes",
                           header->length);
      http2_send_connection_error (conn, HTTP2_FRAME_SIZE_ERROR);
      return -1;
    }

  /* Extract Prioritized Stream ID */
  prioritized_stream_id = read_u31_be (payload);

  /* RFC 9218 Section 7.1: Prioritized Stream ID = 0 is error */
  if (prioritized_stream_id == 0)
    {
      SOCKET_LOG_WARN_MSG ("PRIORITY_UPDATE with zero Prioritized Stream ID");
      http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
      return -1;
    }

  /* RFC 9218 Section 7.1: For server, Prioritized Stream ID must be
   * client-initiated (odd). For client, must be server-initiated (even). */
  int expected_parity = (conn->role == HTTP2_ROLE_SERVER) ? 1 : 0;
  if ((prioritized_stream_id & 1U) != (unsigned int)expected_parity)
    {
      SOCKET_LOG_WARN_MSG (
          "PRIORITY_UPDATE for wrong-parity stream %u (role=%d)",
          prioritized_stream_id,
          conn->role);
      http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
      return -1;
    }

  /* Parse priority field value */
  SocketHTTP2_Priority_init (&priority);
  if (header->length > PRIORITY_UPDATE_MIN_PAYLOAD_SIZE)
    {
      const char *priority_value
          = (const char *)(payload + PRIORITY_UPDATE_STREAM_ID_SIZE);
      size_t priority_len = header->length - PRIORITY_UPDATE_STREAM_ID_SIZE;

      if (SocketHTTP2_Priority_parse (priority_value, priority_len, &priority)
          < 0)
        {
          /* RFC 9218: Parse errors should use defaults, not connection error */
          SOCKET_LOG_DEBUG_MSG ("PRIORITY_UPDATE parse error, using defaults");
          SocketHTTP2_Priority_init (&priority);
        }
    }

  /* Find or ignore stream */
  stream = http2_stream_lookup (conn, prioritized_stream_id);
  if (stream)
    {
      /* Update stream priority */
      stream->priority = priority;
      SOCKET_LOG_DEBUG_MSG ("PRIORITY_UPDATE applied: stream=%u u=%d i=%d",
                            prioritized_stream_id,
                            priority.urgency,
                            priority.incremental);
    }
  else
    {
      /* RFC 9218: PRIORITY_UPDATE can arrive for streams not yet created
       * or already closed. For simplicity, we ignore unknown streams. */
      SOCKET_LOG_DEBUG_MSG ("PRIORITY_UPDATE for unknown stream %u ignored",
                            prioritized_stream_id);
    }

  return 0;
}
