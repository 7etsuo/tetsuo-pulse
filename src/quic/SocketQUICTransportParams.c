/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketQUICTransportParams.c - QUIC Transport Parameters (RFC 9000 Section 18)
 *
 * Implements encoding, decoding, and validation of transport parameters
 * exchanged during the TLS handshake.
 */

#include <string.h>

#include "quic/SocketQUICTransportParams.h"
#include "quic/SocketQUICVarInt.h"
#include "quic/SocketQUICConstants.h"

/* ============================================================================
 * Result Strings
 * ============================================================================
 */

static const char *result_strings[] = {
  [QUIC_TP_OK] = "OK",
  [QUIC_TP_ERROR_NULL] = "NULL pointer argument",
  [QUIC_TP_ERROR_BUFFER] = "Buffer too small",
  [QUIC_TP_ERROR_INCOMPLETE] = "Need more input data",
  [QUIC_TP_ERROR_INVALID_VALUE] = "Invalid parameter value",
  [QUIC_TP_ERROR_DUPLICATE] = "Duplicate parameter",
  [QUIC_TP_ERROR_ROLE] = "Parameter not allowed for role",
  [QUIC_TP_ERROR_REQUIRED] = "Required parameter missing",
  [QUIC_TP_ERROR_ENCODING] = "Encoding error",
};

DEFINE_RESULT_STRING_FUNC (SocketQUICTransportParams, QUIC_TP_ERROR_ENCODING)

/* ============================================================================
 * Parameter ID Strings
 * ============================================================================
 */

const char *
SocketQUICTransportParams_id_string (SocketQUICTransportParamID id)
{
  switch (id)
    {
    case QUIC_TP_ORIGINAL_DCID:
      return "original_destination_connection_id";
    case QUIC_TP_MAX_IDLE_TIMEOUT:
      return "max_idle_timeout";
    case QUIC_TP_STATELESS_RESET_TOKEN:
      return "stateless_reset_token";
    case QUIC_TP_MAX_UDP_PAYLOAD_SIZE:
      return "max_udp_payload_size";
    case QUIC_TP_INITIAL_MAX_DATA:
      return "initial_max_data";
    case QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
      return "initial_max_stream_data_bidi_local";
    case QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
      return "initial_max_stream_data_bidi_remote";
    case QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI:
      return "initial_max_stream_data_uni";
    case QUIC_TP_INITIAL_MAX_STREAMS_BIDI:
      return "initial_max_streams_bidi";
    case QUIC_TP_INITIAL_MAX_STREAMS_UNI:
      return "initial_max_streams_uni";
    case QUIC_TP_ACK_DELAY_EXPONENT:
      return "ack_delay_exponent";
    case QUIC_TP_MAX_ACK_DELAY:
      return "max_ack_delay";
    case QUIC_TP_DISABLE_ACTIVE_MIGRATION:
      return "disable_active_migration";
    case QUIC_TP_PREFERRED_ADDRESS:
      return "preferred_address";
    case QUIC_TP_ACTIVE_CONNID_LIMIT:
      return "active_connection_id_limit";
    case QUIC_TP_INITIAL_SCID:
      return "initial_source_connection_id";
    case QUIC_TP_RETRY_SCID:
      return "retry_source_connection_id";
    case QUIC_TP_VERSION_INFO:
      return "version_information";
    case QUIC_TP_MAX_DATAGRAM_FRAME_SIZE:
      return "max_datagram_frame_size";
    default:
      return "unknown";
    }
}

/* ============================================================================
 * Initialization Functions
 * ============================================================================
 */

void
SocketQUICTransportParams_init (SocketQUICTransportParams_T *params)
{
  if (params == NULL)
    return;

  memset (params, 0, sizeof (*params));

  /* RFC 9000 Section 18.2 default values */
  params->max_udp_payload_size = QUIC_TP_DEFAULT_MAX_UDP_PAYLOAD_SIZE;
  params->ack_delay_exponent = QUIC_TP_DEFAULT_ACK_DELAY_EXPONENT;
  params->max_ack_delay = QUIC_TP_DEFAULT_MAX_ACK_DELAY;
  params->active_connection_id_limit = QUIC_TP_DEFAULT_ACTIVE_CONNID_LIMIT;
}

void
SocketQUICTransportParams_set_defaults (SocketQUICTransportParams_T *params,
                                        SocketQUICRole role)
{
  if (params == NULL)
    return;

  SocketQUICTransportParams_init (params);

  /* Set reasonable defaults for a typical connection */
  params->max_idle_timeout = 30000;               /* 30 seconds */
  params->initial_max_data = 1048576;             /* 1 MB */
  params->initial_max_stream_data_bidi_local = 262144;  /* 256 KB */
  params->initial_max_stream_data_bidi_remote = 262144; /* 256 KB */
  params->initial_max_stream_data_uni = 262144;         /* 256 KB */
  params->initial_max_streams_bidi = 100;
  params->initial_max_streams_uni = 100;
  params->active_connection_id_limit = 8;

  (void)role; /* May be used for role-specific defaults in future */
}

/* ============================================================================
 * Encoding Helper Functions
 * ============================================================================
 */

static size_t
encode_varint_param (uint8_t *buf, size_t buf_size, uint64_t id, uint64_t value)
{
  size_t pos = 0;
  size_t len;

  /* Encode parameter ID */
  len = SocketQUICVarInt_encode (id, buf + pos, buf_size - pos);
  if (len == 0)
    return 0;
  pos += len;

  /* Calculate value encoding size */
  size_t value_size = SocketQUICVarInt_size (value);
  if (value_size == 0)
    return 0;

  /* Encode length */
  len = SocketQUICVarInt_encode (value_size, buf + pos, buf_size - pos);
  if (len == 0)
    return 0;
  pos += len;

  /* Encode value */
  len = SocketQUICVarInt_encode (value, buf + pos, buf_size - pos);
  if (len == 0)
    return 0;
  pos += len;

  return pos;
}

static size_t
encode_connid_param (uint8_t *buf, size_t buf_size, uint64_t id,
                     const SocketQUICConnectionID_T *cid)
{
  size_t pos = 0;
  size_t len;

  /* Encode parameter ID */
  len = SocketQUICVarInt_encode (id, buf + pos, buf_size - pos);
  if (len == 0)
    return 0;
  pos += len;

  /* Encode length (CID length) */
  len = SocketQUICVarInt_encode (cid->len, buf + pos, buf_size - pos);
  if (len == 0)
    return 0;
  pos += len;

  /* Encode CID data */
  if (cid->len > 0)
    {
      if (buf_size - pos < cid->len)
        return 0;
      memcpy (buf + pos, cid->data, cid->len);
      pos += cid->len;
    }

  return pos;
}

static size_t
encode_token_param (uint8_t *buf, size_t buf_size, uint64_t id,
                    const uint8_t *token, size_t token_len)
{
  size_t pos = 0;
  size_t len;

  /* Encode parameter ID */
  len = SocketQUICVarInt_encode (id, buf + pos, buf_size - pos);
  if (len == 0)
    return 0;
  pos += len;

  /* Encode length */
  len = SocketQUICVarInt_encode (token_len, buf + pos, buf_size - pos);
  if (len == 0)
    return 0;
  pos += len;

  /* Encode token data */
  if (token_len > 0)
    {
      if (buf_size - pos < token_len)
        return 0;
      memcpy (buf + pos, token, token_len);
      pos += token_len;
    }

  return pos;
}

static size_t
encode_empty_param (uint8_t *buf, size_t buf_size, uint64_t id)
{
  size_t pos = 0;
  size_t len;

  /* Encode parameter ID */
  len = SocketQUICVarInt_encode (id, buf + pos, buf_size - pos);
  if (len == 0)
    return 0;
  pos += len;

  /* Encode length = 0 */
  len = SocketQUICVarInt_encode (0, buf + pos, buf_size - pos);
  if (len == 0)
    return 0;
  pos += len;

  return pos;
}

static size_t
encode_preferred_address (uint8_t *buf, size_t buf_size,
                          const SocketQUICPreferredAddress_T *paddr)
{
  size_t pos = 0;
  size_t len;

  /* Calculate content size */
  size_t content_size = 4 + 2 + 16 + 2 + 1 + paddr->connection_id.len + 16;

  /* Encode parameter ID */
  len = SocketQUICVarInt_encode (QUIC_TP_PREFERRED_ADDRESS, buf + pos,
                                 buf_size - pos);
  if (len == 0)
    return 0;
  pos += len;

  /* Encode length */
  len = SocketQUICVarInt_encode (content_size, buf + pos, buf_size - pos);
  if (len == 0)
    return 0;
  pos += len;

  /* Check buffer space */
  if (buf_size - pos < content_size)
    return 0;

  /* IPv4 address and port */
  memcpy (buf + pos, paddr->ipv4_address, 4);
  pos += 4;
  buf[pos++] = (uint8_t)(paddr->ipv4_port >> 8);
  buf[pos++] = (uint8_t)(paddr->ipv4_port & 0xFF);

  /* IPv6 address and port */
  memcpy (buf + pos, paddr->ipv6_address, 16);
  pos += 16;
  buf[pos++] = (uint8_t)(paddr->ipv6_port >> 8);
  buf[pos++] = (uint8_t)(paddr->ipv6_port & 0xFF);

  /* Connection ID length and data */
  buf[pos++] = paddr->connection_id.len;
  if (paddr->connection_id.len > 0)
    {
      memcpy (buf + pos, paddr->connection_id.data, paddr->connection_id.len);
      pos += paddr->connection_id.len;
    }

  /* Stateless reset token */
  memcpy (buf + pos, paddr->stateless_reset_token, 16);
  pos += 16;

  return pos;
}

/* ============================================================================
 * Size Calculation
 * ============================================================================
 */

static size_t
varint_param_size (uint64_t id, uint64_t value)
{
  size_t id_size = SocketQUICVarInt_size (id);
  size_t value_size = SocketQUICVarInt_size (value);
  size_t len_size = SocketQUICVarInt_size (value_size);
  return id_size + len_size + value_size;
}

static size_t
connid_param_size (uint64_t id, const SocketQUICConnectionID_T *cid)
{
  size_t id_size = SocketQUICVarInt_size (id);
  size_t len_size = SocketQUICVarInt_size (cid->len);
  return id_size + len_size + cid->len;
}

static size_t
token_param_size (uint64_t id, size_t token_len)
{
  size_t id_size = SocketQUICVarInt_size (id);
  size_t len_size = SocketQUICVarInt_size (token_len);
  return id_size + len_size + token_len;
}

static size_t
empty_param_size (uint64_t id)
{
  return SocketQUICVarInt_size (id) + 1; /* ID + length(0) */
}

static size_t
preferred_address_size (const SocketQUICPreferredAddress_T *paddr)
{
  size_t content_size = 4 + 2 + 16 + 2 + 1 + paddr->connection_id.len + 16;
  size_t id_size = SocketQUICVarInt_size (QUIC_TP_PREFERRED_ADDRESS);
  size_t len_size = SocketQUICVarInt_size (content_size);
  return id_size + len_size + content_size;
}

size_t
SocketQUICTransportParams_encoded_size (const SocketQUICTransportParams_T *params,
                                        SocketQUICRole role)
{
  size_t size = 0;

  if (params == NULL)
    return 0;

  /* Connection IDs */
  if (role == QUIC_ROLE_SERVER && params->has_original_dcid)
    size += connid_param_size (QUIC_TP_ORIGINAL_DCID, &params->original_dcid);

  if (params->has_initial_scid)
    size += connid_param_size (QUIC_TP_INITIAL_SCID, &params->initial_scid);

  if (role == QUIC_ROLE_SERVER && params->has_retry_scid)
    size += connid_param_size (QUIC_TP_RETRY_SCID, &params->retry_scid);

  /* Stateless reset token (server only) */
  if (role == QUIC_ROLE_SERVER && params->has_stateless_reset_token)
    size += token_param_size (QUIC_TP_STATELESS_RESET_TOKEN,
                              QUIC_STATELESS_RESET_TOKEN_LEN);

  /* Variable integer parameters (only encode non-default values) */
  if (params->max_idle_timeout != QUIC_TP_DEFAULT_MAX_IDLE_TIMEOUT)
    size += varint_param_size (QUIC_TP_MAX_IDLE_TIMEOUT,
                               params->max_idle_timeout);

  if (params->max_udp_payload_size != QUIC_TP_DEFAULT_MAX_UDP_PAYLOAD_SIZE)
    size += varint_param_size (QUIC_TP_MAX_UDP_PAYLOAD_SIZE,
                               params->max_udp_payload_size);

  if (params->initial_max_data != QUIC_TP_DEFAULT_INITIAL_MAX_DATA)
    size += varint_param_size (QUIC_TP_INITIAL_MAX_DATA,
                               params->initial_max_data);

  if (params->initial_max_stream_data_bidi_local != QUIC_TP_DEFAULT_INITIAL_MAX_STREAM_DATA)
    size += varint_param_size (QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                               params->initial_max_stream_data_bidi_local);

  if (params->initial_max_stream_data_bidi_remote != QUIC_TP_DEFAULT_INITIAL_MAX_STREAM_DATA)
    size += varint_param_size (QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                               params->initial_max_stream_data_bidi_remote);

  if (params->initial_max_stream_data_uni != QUIC_TP_DEFAULT_INITIAL_MAX_STREAM_DATA)
    size += varint_param_size (QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI,
                               params->initial_max_stream_data_uni);

  if (params->initial_max_streams_bidi != QUIC_TP_DEFAULT_INITIAL_MAX_STREAMS)
    size += varint_param_size (QUIC_TP_INITIAL_MAX_STREAMS_BIDI,
                               params->initial_max_streams_bidi);

  if (params->initial_max_streams_uni != QUIC_TP_DEFAULT_INITIAL_MAX_STREAMS)
    size += varint_param_size (QUIC_TP_INITIAL_MAX_STREAMS_UNI,
                               params->initial_max_streams_uni);

  if (params->ack_delay_exponent != QUIC_TP_DEFAULT_ACK_DELAY_EXPONENT)
    size += varint_param_size (QUIC_TP_ACK_DELAY_EXPONENT,
                               params->ack_delay_exponent);

  if (params->max_ack_delay != QUIC_TP_DEFAULT_MAX_ACK_DELAY)
    size += varint_param_size (QUIC_TP_MAX_ACK_DELAY, params->max_ack_delay);

  if (params->active_connection_id_limit != QUIC_TP_DEFAULT_ACTIVE_CONNID_LIMIT)
    size += varint_param_size (QUIC_TP_ACTIVE_CONNID_LIMIT,
                               params->active_connection_id_limit);

  /* Boolean parameter */
  if (params->disable_active_migration)
    size += empty_param_size (QUIC_TP_DISABLE_ACTIVE_MIGRATION);

  /* Preferred address (server only) */
  if (role == QUIC_ROLE_SERVER && params->preferred_address.present)
    size += preferred_address_size (&params->preferred_address);

  /* Extension: DATAGRAM */
  if (params->has_max_datagram_frame_size)
    size += varint_param_size (QUIC_TP_MAX_DATAGRAM_FRAME_SIZE,
                               params->max_datagram_frame_size);

  return size;
}

/* ============================================================================
 * Encoding
 * ============================================================================
 */

size_t
SocketQUICTransportParams_encode (const SocketQUICTransportParams_T *params,
                                  SocketQUICRole role, uint8_t *output,
                                  size_t output_size)
{
  size_t pos = 0;
  size_t len;

  if (params == NULL || output == NULL)
    return 0;

  /* Connection IDs */
  if (role == QUIC_ROLE_SERVER && params->has_original_dcid)
    {
      len = encode_connid_param (output + pos, output_size - pos,
                                 QUIC_TP_ORIGINAL_DCID, &params->original_dcid);
      if (len == 0)
        return 0;
      pos += len;
    }

  if (params->has_initial_scid)
    {
      len = encode_connid_param (output + pos, output_size - pos,
                                 QUIC_TP_INITIAL_SCID, &params->initial_scid);
      if (len == 0)
        return 0;
      pos += len;
    }

  if (role == QUIC_ROLE_SERVER && params->has_retry_scid)
    {
      len = encode_connid_param (output + pos, output_size - pos,
                                 QUIC_TP_RETRY_SCID, &params->retry_scid);
      if (len == 0)
        return 0;
      pos += len;
    }

  /* Stateless reset token (server only) */
  if (role == QUIC_ROLE_SERVER && params->has_stateless_reset_token)
    {
      len = encode_token_param (output + pos, output_size - pos,
                                QUIC_TP_STATELESS_RESET_TOKEN,
                                params->stateless_reset_token,
                                QUIC_STATELESS_RESET_TOKEN_LEN);
      if (len == 0)
        return 0;
      pos += len;
    }

  /* Variable integer parameters (only encode non-default values) */
  if (params->max_idle_timeout != QUIC_TP_DEFAULT_MAX_IDLE_TIMEOUT)
    {
      len = encode_varint_param (output + pos, output_size - pos,
                                 QUIC_TP_MAX_IDLE_TIMEOUT,
                                 params->max_idle_timeout);
      if (len == 0)
        return 0;
      pos += len;
    }

  if (params->max_udp_payload_size != QUIC_TP_DEFAULT_MAX_UDP_PAYLOAD_SIZE)
    {
      len = encode_varint_param (output + pos, output_size - pos,
                                 QUIC_TP_MAX_UDP_PAYLOAD_SIZE,
                                 params->max_udp_payload_size);
      if (len == 0)
        return 0;
      pos += len;
    }

  if (params->initial_max_data != QUIC_TP_DEFAULT_INITIAL_MAX_DATA)
    {
      len = encode_varint_param (output + pos, output_size - pos,
                                 QUIC_TP_INITIAL_MAX_DATA,
                                 params->initial_max_data);
      if (len == 0)
        return 0;
      pos += len;
    }

  if (params->initial_max_stream_data_bidi_local
      != QUIC_TP_DEFAULT_INITIAL_MAX_STREAM_DATA)
    {
      len = encode_varint_param (output + pos, output_size - pos,
                                 QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                                 params->initial_max_stream_data_bidi_local);
      if (len == 0)
        return 0;
      pos += len;
    }

  if (params->initial_max_stream_data_bidi_remote
      != QUIC_TP_DEFAULT_INITIAL_MAX_STREAM_DATA)
    {
      len = encode_varint_param (output + pos, output_size - pos,
                                 QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                                 params->initial_max_stream_data_bidi_remote);
      if (len == 0)
        return 0;
      pos += len;
    }

  if (params->initial_max_stream_data_uni != QUIC_TP_DEFAULT_INITIAL_MAX_STREAM_DATA)
    {
      len = encode_varint_param (output + pos, output_size - pos,
                                 QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI,
                                 params->initial_max_stream_data_uni);
      if (len == 0)
        return 0;
      pos += len;
    }

  if (params->initial_max_streams_bidi != QUIC_TP_DEFAULT_INITIAL_MAX_STREAMS)
    {
      len = encode_varint_param (output + pos, output_size - pos,
                                 QUIC_TP_INITIAL_MAX_STREAMS_BIDI,
                                 params->initial_max_streams_bidi);
      if (len == 0)
        return 0;
      pos += len;
    }

  if (params->initial_max_streams_uni != QUIC_TP_DEFAULT_INITIAL_MAX_STREAMS)
    {
      len = encode_varint_param (output + pos, output_size - pos,
                                 QUIC_TP_INITIAL_MAX_STREAMS_UNI,
                                 params->initial_max_streams_uni);
      if (len == 0)
        return 0;
      pos += len;
    }

  if (params->ack_delay_exponent != QUIC_TP_DEFAULT_ACK_DELAY_EXPONENT)
    {
      len = encode_varint_param (output + pos, output_size - pos,
                                 QUIC_TP_ACK_DELAY_EXPONENT,
                                 params->ack_delay_exponent);
      if (len == 0)
        return 0;
      pos += len;
    }

  if (params->max_ack_delay != QUIC_TP_DEFAULT_MAX_ACK_DELAY)
    {
      len = encode_varint_param (output + pos, output_size - pos,
                                 QUIC_TP_MAX_ACK_DELAY, params->max_ack_delay);
      if (len == 0)
        return 0;
      pos += len;
    }

  if (params->active_connection_id_limit != QUIC_TP_DEFAULT_ACTIVE_CONNID_LIMIT)
    {
      len = encode_varint_param (output + pos, output_size - pos,
                                 QUIC_TP_ACTIVE_CONNID_LIMIT,
                                 params->active_connection_id_limit);
      if (len == 0)
        return 0;
      pos += len;
    }

  /* Boolean parameter */
  if (params->disable_active_migration)
    {
      len = encode_empty_param (output + pos, output_size - pos,
                                QUIC_TP_DISABLE_ACTIVE_MIGRATION);
      if (len == 0)
        return 0;
      pos += len;
    }

  /* Preferred address (server only) */
  if (role == QUIC_ROLE_SERVER && params->preferred_address.present)
    {
      len = encode_preferred_address (output + pos, output_size - pos,
                                      &params->preferred_address);
      if (len == 0)
        return 0;
      pos += len;
    }

  /* Extension: DATAGRAM */
  if (params->has_max_datagram_frame_size)
    {
      len = encode_varint_param (output + pos, output_size - pos,
                                 QUIC_TP_MAX_DATAGRAM_FRAME_SIZE,
                                 params->max_datagram_frame_size);
      if (len == 0)
        return 0;
      pos += len;
    }

  return pos;
}

/* ============================================================================
 * Decoding Helper Functions
 * ============================================================================
 */

static SocketQUICTransportParams_Result
decode_varint_value (const uint8_t *data, size_t len, uint64_t *value,
                     size_t *consumed)
{
  SocketQUICVarInt_Result res;

  res = SocketQUICVarInt_decode (data, len, value, consumed);
  if (res == QUIC_VARINT_INCOMPLETE)
    return QUIC_TP_ERROR_INCOMPLETE;
  if (res != QUIC_VARINT_OK)
    return QUIC_TP_ERROR_ENCODING;

  return QUIC_TP_OK;
}

static SocketQUICTransportParams_Result
decode_connid_value (const uint8_t *data, size_t len,
                     SocketQUICConnectionID_T *cid)
{
  SocketQUICConnectionID_Result res;

  if (len > QUIC_CONNID_MAX_LEN)
    return QUIC_TP_ERROR_INVALID_VALUE;

  res = SocketQUICConnectionID_set (cid, data, len);
  if (res != QUIC_CONNID_OK)
    return QUIC_TP_ERROR_INVALID_VALUE;

  return QUIC_TP_OK;
}

static SocketQUICTransportParams_Result
decode_preferred_address (const uint8_t *data, size_t len,
                          SocketQUICPreferredAddress_T *paddr)
{
  size_t pos = 0;

  /* Minimum size: 4+2+16+2+1+0+16 = 41 bytes */
  if (len < 41)
    return QUIC_TP_ERROR_INCOMPLETE;

  /* IPv4 address */
  memcpy (paddr->ipv4_address, data + pos, 4);
  pos += 4;

  /* IPv4 port (big-endian) */
  paddr->ipv4_port = ((uint16_t)data[pos] << 8) | data[pos + 1];
  pos += 2;

  /* IPv6 address */
  memcpy (paddr->ipv6_address, data + pos, 16);
  pos += 16;

  /* IPv6 port (big-endian) */
  paddr->ipv6_port = ((uint16_t)data[pos] << 8) | data[pos + 1];
  pos += 2;

  /* Connection ID length */
  uint8_t cid_len = data[pos++];
  if (cid_len > QUIC_CONNID_MAX_LEN)
    return QUIC_TP_ERROR_INVALID_VALUE;
  if (pos + cid_len + 16 > len)
    return QUIC_TP_ERROR_INCOMPLETE;

  /* Connection ID */
  SocketQUICConnectionID_set (&paddr->connection_id, data + pos, cid_len);
  pos += cid_len;

  /* Stateless reset token */
  memcpy (paddr->stateless_reset_token, data + pos, 16);
  pos += 16;

  paddr->present = 1;

  return QUIC_TP_OK;
}

/* ============================================================================
 * Parameter Decode Handlers
 * ============================================================================
 */

/**
 * @brief Handler function type for transport parameter decoding.
 */
typedef SocketQUICTransportParams_Result (*ParamDecodeHandler) (
    const uint8_t *data, size_t param_len, SocketQUICRole peer_role,
    SocketQUICTransportParams_T *params);

/**
 * @brief Transport parameter handler table entry.
 */
typedef struct
{
  uint64_t param_id;
  ParamDecodeHandler handler;
} ParamHandlerEntry;

/**
 * @brief Check if parameter is server-only.
 */
static SocketQUICTransportParams_Result
check_server_only (SocketQUICRole peer_role)
{
  return (peer_role != QUIC_ROLE_SERVER) ? QUIC_TP_ERROR_ROLE : QUIC_TP_OK;
}

/**
 * @brief Decode a varint parameter value into a uint64_t field.
 */
static SocketQUICTransportParams_Result
decode_varint_to_field (const uint8_t *data, size_t param_len, uint64_t *field)
{
  uint64_t value;
  size_t consumed;
  SocketQUICTransportParams_Result result;

  result = decode_varint_value (data, param_len, &value, &consumed);
  if (result != QUIC_TP_OK)
    return result;

  *field = value;
  return QUIC_TP_OK;
}

/* Individual parameter handlers */

static SocketQUICTransportParams_Result
decode_param_original_dcid (const uint8_t *data, size_t param_len,
                            SocketQUICRole peer_role,
                            SocketQUICTransportParams_T *params)
{
  SocketQUICTransportParams_Result result = check_server_only (peer_role);
  if (result != QUIC_TP_OK)
    return result;

  result = decode_connid_value (data, param_len, &params->original_dcid);
  if (result != QUIC_TP_OK)
    return result;

  params->has_original_dcid = 1;
  return QUIC_TP_OK;
}

static SocketQUICTransportParams_Result
decode_param_max_idle_timeout (const uint8_t *data, size_t param_len,
                               SocketQUICRole peer_role,
                               SocketQUICTransportParams_T *params)
{
  (void)peer_role;
  return decode_varint_to_field (data, param_len, &params->max_idle_timeout);
}

static SocketQUICTransportParams_Result
decode_param_stateless_reset_token (const uint8_t *data, size_t param_len,
                                    SocketQUICRole peer_role,
                                    SocketQUICTransportParams_T *params)
{
  SocketQUICTransportParams_Result result = check_server_only (peer_role);
  if (result != QUIC_TP_OK)
    return result;

  if (param_len != QUIC_STATELESS_RESET_TOKEN_LEN)
    return QUIC_TP_ERROR_INVALID_VALUE;

  memcpy (params->stateless_reset_token, data, QUIC_STATELESS_RESET_TOKEN_LEN);
  params->has_stateless_reset_token = 1;
  return QUIC_TP_OK;
}

static SocketQUICTransportParams_Result
decode_param_max_udp_payload_size (const uint8_t *data, size_t param_len,
                                   SocketQUICRole peer_role,
                                   SocketQUICTransportParams_T *params)
{
  (void)peer_role;
  return decode_varint_to_field (data, param_len, &params->max_udp_payload_size);
}

static SocketQUICTransportParams_Result
decode_param_initial_max_data (const uint8_t *data, size_t param_len,
                               SocketQUICRole peer_role,
                               SocketQUICTransportParams_T *params)
{
  (void)peer_role;
  return decode_varint_to_field (data, param_len, &params->initial_max_data);
}

static SocketQUICTransportParams_Result
decode_param_initial_max_stream_data_bidi_local (const uint8_t *data,
                                                  size_t param_len,
                                                  SocketQUICRole peer_role,
                                                  SocketQUICTransportParams_T *params)
{
  (void)peer_role;
  return decode_varint_to_field (data, param_len,
                                 &params->initial_max_stream_data_bidi_local);
}

static SocketQUICTransportParams_Result
decode_param_initial_max_stream_data_bidi_remote (const uint8_t *data,
                                                   size_t param_len,
                                                   SocketQUICRole peer_role,
                                                   SocketQUICTransportParams_T *params)
{
  (void)peer_role;
  return decode_varint_to_field (data, param_len,
                                 &params->initial_max_stream_data_bidi_remote);
}

static SocketQUICTransportParams_Result
decode_param_initial_max_stream_data_uni (const uint8_t *data, size_t param_len,
                                          SocketQUICRole peer_role,
                                          SocketQUICTransportParams_T *params)
{
  (void)peer_role;
  return decode_varint_to_field (data, param_len,
                                 &params->initial_max_stream_data_uni);
}

static SocketQUICTransportParams_Result
decode_param_initial_max_streams_bidi (const uint8_t *data, size_t param_len,
                                       SocketQUICRole peer_role,
                                       SocketQUICTransportParams_T *params)
{
  (void)peer_role;
  return decode_varint_to_field (data, param_len,
                                 &params->initial_max_streams_bidi);
}

static SocketQUICTransportParams_Result
decode_param_initial_max_streams_uni (const uint8_t *data, size_t param_len,
                                      SocketQUICRole peer_role,
                                      SocketQUICTransportParams_T *params)
{
  (void)peer_role;
  return decode_varint_to_field (data, param_len,
                                 &params->initial_max_streams_uni);
}

static SocketQUICTransportParams_Result
decode_param_ack_delay_exponent (const uint8_t *data, size_t param_len,
                                 SocketQUICRole peer_role,
                                 SocketQUICTransportParams_T *params)
{
  (void)peer_role;
  return decode_varint_to_field (data, param_len, &params->ack_delay_exponent);
}

static SocketQUICTransportParams_Result
decode_param_max_ack_delay (const uint8_t *data, size_t param_len,
                            SocketQUICRole peer_role,
                            SocketQUICTransportParams_T *params)
{
  (void)peer_role;
  return decode_varint_to_field (data, param_len, &params->max_ack_delay);
}

static SocketQUICTransportParams_Result
decode_param_disable_active_migration (const uint8_t *data, size_t param_len,
                                       SocketQUICRole peer_role,
                                       SocketQUICTransportParams_T *params)
{
  (void)data;
  (void)peer_role;

  if (param_len != 0)
    return QUIC_TP_ERROR_INVALID_VALUE;

  params->disable_active_migration = 1;
  return QUIC_TP_OK;
}

static SocketQUICTransportParams_Result
decode_param_preferred_address (const uint8_t *data, size_t param_len,
                                SocketQUICRole peer_role,
                                SocketQUICTransportParams_T *params)
{
  SocketQUICTransportParams_Result result = check_server_only (peer_role);
  if (result != QUIC_TP_OK)
    return result;

  return decode_preferred_address (data, param_len, &params->preferred_address);
}

static SocketQUICTransportParams_Result
decode_param_active_connid_limit (const uint8_t *data, size_t param_len,
                                  SocketQUICRole peer_role,
                                  SocketQUICTransportParams_T *params)
{
  (void)peer_role;
  return decode_varint_to_field (data, param_len,
                                 &params->active_connection_id_limit);
}

static SocketQUICTransportParams_Result
decode_param_initial_scid (const uint8_t *data, size_t param_len,
                           SocketQUICRole peer_role,
                           SocketQUICTransportParams_T *params)
{
  SocketQUICTransportParams_Result result;
  (void)peer_role;

  result = decode_connid_value (data, param_len, &params->initial_scid);
  if (result != QUIC_TP_OK)
    return result;

  params->has_initial_scid = 1;
  return QUIC_TP_OK;
}

static SocketQUICTransportParams_Result
decode_param_retry_scid (const uint8_t *data, size_t param_len,
                         SocketQUICRole peer_role,
                         SocketQUICTransportParams_T *params)
{
  SocketQUICTransportParams_Result result = check_server_only (peer_role);
  if (result != QUIC_TP_OK)
    return result;

  result = decode_connid_value (data, param_len, &params->retry_scid);
  if (result != QUIC_TP_OK)
    return result;

  params->has_retry_scid = 1;
  return QUIC_TP_OK;
}

static SocketQUICTransportParams_Result
decode_param_max_datagram_frame_size (const uint8_t *data, size_t param_len,
                                      SocketQUICRole peer_role,
                                      SocketQUICTransportParams_T *params)
{
  SocketQUICTransportParams_Result result;
  (void)peer_role;

  result = decode_varint_to_field (data, param_len,
                                   &params->max_datagram_frame_size);
  if (result != QUIC_TP_OK)
    return result;

  params->has_max_datagram_frame_size = 1;
  return QUIC_TP_OK;
}

/* Handler lookup table */
static const ParamHandlerEntry param_handlers[] = {
  { QUIC_TP_ORIGINAL_DCID, decode_param_original_dcid },
  { QUIC_TP_MAX_IDLE_TIMEOUT, decode_param_max_idle_timeout },
  { QUIC_TP_STATELESS_RESET_TOKEN, decode_param_stateless_reset_token },
  { QUIC_TP_MAX_UDP_PAYLOAD_SIZE, decode_param_max_udp_payload_size },
  { QUIC_TP_INITIAL_MAX_DATA, decode_param_initial_max_data },
  { QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
    decode_param_initial_max_stream_data_bidi_local },
  { QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
    decode_param_initial_max_stream_data_bidi_remote },
  { QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI, decode_param_initial_max_stream_data_uni },
  { QUIC_TP_INITIAL_MAX_STREAMS_BIDI, decode_param_initial_max_streams_bidi },
  { QUIC_TP_INITIAL_MAX_STREAMS_UNI, decode_param_initial_max_streams_uni },
  { QUIC_TP_ACK_DELAY_EXPONENT, decode_param_ack_delay_exponent },
  { QUIC_TP_MAX_ACK_DELAY, decode_param_max_ack_delay },
  { QUIC_TP_DISABLE_ACTIVE_MIGRATION, decode_param_disable_active_migration },
  { QUIC_TP_PREFERRED_ADDRESS, decode_param_preferred_address },
  { QUIC_TP_ACTIVE_CONNID_LIMIT, decode_param_active_connid_limit },
  { QUIC_TP_INITIAL_SCID, decode_param_initial_scid },
  { QUIC_TP_RETRY_SCID, decode_param_retry_scid },
  { QUIC_TP_MAX_DATAGRAM_FRAME_SIZE, decode_param_max_datagram_frame_size },
};

#define PARAM_HANDLER_COUNT (sizeof (param_handlers) / sizeof (param_handlers[0]))

/**
 * @brief Find handler for a parameter ID.
 */
static ParamDecodeHandler
find_param_handler (uint64_t param_id)
{
  for (size_t i = 0; i < PARAM_HANDLER_COUNT; i++)
    {
      if (param_handlers[i].param_id == param_id)
        return param_handlers[i].handler;
    }
  return NULL;
}

/* ============================================================================
 * Decoding
 * ============================================================================
 */

SocketQUICTransportParams_Result
SocketQUICTransportParams_decode (const uint8_t *data, size_t len,
                                  SocketQUICRole peer_role,
                                  SocketQUICTransportParams_T *params,
                                  size_t *consumed)
{
  size_t pos = 0;
  SocketQUICTransportParams_Result result;
  uint32_t seen_params = 0; /* Bitmap for duplicate detection */

  if (data == NULL || params == NULL || consumed == NULL)
    return QUIC_TP_ERROR_NULL;

  /* Initialize with defaults */
  SocketQUICTransportParams_init (params);

  while (pos < len)
    {
      uint64_t param_id;
      uint64_t param_len;
      size_t bytes_consumed;

      /* Decode parameter ID */
      result = decode_varint_value (data + pos, len - pos, &param_id,
                                    &bytes_consumed);
      if (result != QUIC_TP_OK)
        return result;
      pos += bytes_consumed;

      /* Decode parameter length */
      result = decode_varint_value (data + pos, len - pos, &param_len,
                                    &bytes_consumed);
      if (result != QUIC_TP_OK)
        return result;
      pos += bytes_consumed;

      /* Check we have enough data for the parameter value */
      if (pos + param_len > len)
        return QUIC_TP_ERROR_INCOMPLETE;

      /* Check for duplicates (for known parameters) */
      if (param_id <= 31)
        {
          uint32_t mask = 1u << param_id;
          if (seen_params & mask)
            return QUIC_TP_ERROR_DUPLICATE;
          seen_params |= mask;
        }

      /* Parse parameter based on ID using table-driven dispatch */
      ParamDecodeHandler handler = find_param_handler (param_id);
      if (handler != NULL)
        {
          result = handler (data + pos, (size_t)param_len, peer_role, params);
          if (result != QUIC_TP_OK)
            return result;
        }
      /* Unknown parameters are ignored per RFC 9000 Section 18.1 */

      pos += (size_t)param_len;
    }

  *consumed = pos;
  return QUIC_TP_OK;
}

/* ============================================================================
 * Validation
 * ============================================================================
 */

SocketQUICTransportParams_Result
SocketQUICTransportParams_validate (const SocketQUICTransportParams_T *params,
                                    SocketQUICRole role)
{
  if (params == NULL)
    return QUIC_TP_ERROR_NULL;

  /* Validate max_udp_payload_size (minimum 1200) */
  if (params->max_udp_payload_size < QUIC_TP_MIN_UDP_PAYLOAD_SIZE)
    return QUIC_TP_ERROR_INVALID_VALUE;

  /* Validate ack_delay_exponent (maximum 20) */
  if (params->ack_delay_exponent > QUIC_TP_MAX_ACK_DELAY_EXPONENT)
    return QUIC_TP_ERROR_INVALID_VALUE;

  /* Validate max_ack_delay (maximum 2^14 ms) */
  if (params->max_ack_delay > QUIC_TP_MAX_MAX_ACK_DELAY)
    return QUIC_TP_ERROR_INVALID_VALUE;

  /* Validate active_connection_id_limit (minimum 2) */
  if (params->active_connection_id_limit < QUIC_TP_MIN_ACTIVE_CONNID_LIMIT)
    return QUIC_TP_ERROR_INVALID_VALUE;

  /* Validate max_streams values (max 2^60) */
  if (params->initial_max_streams_bidi > (1ULL << 60))
    return QUIC_TP_ERROR_INVALID_VALUE;
  if (params->initial_max_streams_uni > (1ULL << 60))
    return QUIC_TP_ERROR_INVALID_VALUE;

  /* Server-only parameter validation */
  if (role == QUIC_ROLE_CLIENT)
    {
      if (params->has_original_dcid || params->has_stateless_reset_token
          || params->has_retry_scid || params->preferred_address.present)
        return QUIC_TP_ERROR_ROLE;
    }

  return QUIC_TP_OK;
}

SocketQUICTransportParams_Result
SocketQUICTransportParams_validate_required (
    const SocketQUICTransportParams_T *params, SocketQUICRole role)
{
  if (params == NULL)
    return QUIC_TP_ERROR_NULL;

  /* initial_source_connection_id is required for both client and server */
  if (!params->has_initial_scid)
    return QUIC_TP_ERROR_REQUIRED;

  /* Server MUST include original_destination_connection_id */
  if (role == QUIC_ROLE_SERVER && !params->has_original_dcid)
    return QUIC_TP_ERROR_REQUIRED;

  return QUIC_TP_OK;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

SocketQUICTransportParams_Result
SocketQUICTransportParams_copy (SocketQUICTransportParams_T *dst,
                                const SocketQUICTransportParams_T *src)
{
  if (dst == NULL || src == NULL)
    return QUIC_TP_ERROR_NULL;

  memcpy (dst, src, sizeof (*dst));
  return QUIC_TP_OK;
}

uint64_t
SocketQUICTransportParams_effective_idle_timeout (
    const SocketQUICTransportParams_T *local,
    const SocketQUICTransportParams_T *remote)
{
  if (local == NULL || remote == NULL)
    return 0;

  /* If either is zero, timeout is disabled */
  if (local->max_idle_timeout == 0 || remote->max_idle_timeout == 0)
    return 0;

  /* Use minimum of both values */
  if (local->max_idle_timeout < remote->max_idle_timeout)
    return local->max_idle_timeout;

  return remote->max_idle_timeout;
}
