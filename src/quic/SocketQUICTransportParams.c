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

#include <assert.h>
#include <stddef.h>
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
  params->max_idle_timeout = QUIC_TP_TYPICAL_IDLE_TIMEOUT_MS;
  params->initial_max_data = QUIC_TP_TYPICAL_INITIAL_MAX_DATA;
  params->initial_max_stream_data_bidi_local = QUIC_TP_TYPICAL_INITIAL_MAX_STREAM_DATA;
  params->initial_max_stream_data_bidi_remote = QUIC_TP_TYPICAL_INITIAL_MAX_STREAM_DATA;
  params->initial_max_stream_data_uni = QUIC_TP_TYPICAL_INITIAL_MAX_STREAM_DATA;
  params->initial_max_streams_bidi = QUIC_TP_TYPICAL_INITIAL_MAX_STREAMS;
  params->initial_max_streams_uni = QUIC_TP_TYPICAL_INITIAL_MAX_STREAMS;
  params->active_connection_id_limit = QUIC_TP_TYPICAL_ACTIVE_CONNID_LIMIT;

  (void)role; /* May be used for role-specific defaults in future */
}

/* ============================================================================
 * Encoding Helper Functions
 * ============================================================================
 */

/**
 * @brief Calculate preferred address content size.
 *
 * Computes the total size of preferred address parameter content based on
 * RFC 9000 Section 18.2 format:
 * - IPv4 address (4 bytes) + port (2 bytes)
 * - IPv6 address (16 bytes) + port (2 bytes)
 * - Connection ID length (1 byte) + Connection ID data
 * - Stateless Reset Token (16 bytes)
 *
 * @param cid_len Connection ID length in bytes (must be <= QUIC_CONNID_MAX_LEN)
 * @return Total content size in bytes
 */
static inline size_t
quic_preferred_addr_content_size(uint8_t cid_len)
{
  return 4 + 2 +      /* IPv4 address + port */
         16 + 2 +     /* IPv6 address + port */
         1 +          /* Connection ID length byte */
         cid_len +    /* Connection ID data */
         QUIC_STATELESS_RESET_TOKEN_LEN;
}

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

  /* Validate inputs */
  if (buf == NULL || cid == NULL)
    return 0;

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

  /* Validate inputs */
  if (buf == NULL || (token_len > 0 && token == NULL))
    return 0;

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
  size_t content_size = quic_preferred_addr_content_size(paddr->connection_id.len);

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
  memcpy (buf + pos, paddr->ipv4_address, QUIC_IPV4_ADDR_LEN);
  pos += QUIC_IPV4_ADDR_LEN;
  buf[pos++] = (uint8_t)(paddr->ipv4_port >> 8);
  buf[pos++] = (uint8_t)(paddr->ipv4_port & 0xFF);

  /* IPv6 address and port */
  memcpy (buf + pos, paddr->ipv6_address, QUIC_IPV6_ADDR_LEN);
  pos += QUIC_IPV6_ADDR_LEN;
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
  memcpy (buf + pos, paddr->stateless_reset_token, QUIC_STATELESS_RESET_TOKEN_LEN);
  pos += QUIC_STATELESS_RESET_TOKEN_LEN;

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
  size_t content_size = quic_preferred_addr_content_size(paddr->connection_id.len);
  size_t id_size = SocketQUICVarInt_size (QUIC_TP_PREFERRED_ADDRESS);
  size_t len_size = SocketQUICVarInt_size (content_size);
  return id_size + len_size + content_size;
}

/* ============================================================================
 * Table-Driven Parameter Encoding
 * ============================================================================
 */

/**
 * @brief Metadata for varint-type transport parameters.
 *
 * This table drives the encoding and size calculation for parameters that
 * are simple variable-length integers with default values.
 */
typedef struct
{
  uint64_t param_id;      /* Transport parameter ID */
  size_t offset;          /* offsetof() into SocketQUICTransportParams_T */
  uint64_t default_value; /* Default value (skip encoding if equal) */
} VarIntParamMetadata;

/**
 * @brief Table of varint parameters with their metadata.
 *
 * This table eliminates repetitive code by consolidating parameter
 * definitions. Adding new varint parameters requires only a table entry.
 */
static const VarIntParamMetadata varint_params[] = {
  { QUIC_TP_MAX_IDLE_TIMEOUT,
    offsetof (SocketQUICTransportParams_T, max_idle_timeout),
    QUIC_TP_DEFAULT_MAX_IDLE_TIMEOUT },
  { QUIC_TP_MAX_UDP_PAYLOAD_SIZE,
    offsetof (SocketQUICTransportParams_T, max_udp_payload_size),
    QUIC_TP_DEFAULT_MAX_UDP_PAYLOAD_SIZE },
  { QUIC_TP_INITIAL_MAX_DATA,
    offsetof (SocketQUICTransportParams_T, initial_max_data),
    QUIC_TP_DEFAULT_INITIAL_MAX_DATA },
  { QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
    offsetof (SocketQUICTransportParams_T, initial_max_stream_data_bidi_local),
    QUIC_TP_DEFAULT_INITIAL_MAX_STREAM_DATA },
  { QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
    offsetof (SocketQUICTransportParams_T, initial_max_stream_data_bidi_remote),
    QUIC_TP_DEFAULT_INITIAL_MAX_STREAM_DATA },
  { QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI,
    offsetof (SocketQUICTransportParams_T, initial_max_stream_data_uni),
    QUIC_TP_DEFAULT_INITIAL_MAX_STREAM_DATA },
  { QUIC_TP_INITIAL_MAX_STREAMS_BIDI,
    offsetof (SocketQUICTransportParams_T, initial_max_streams_bidi),
    QUIC_TP_DEFAULT_INITIAL_MAX_STREAMS },
  { QUIC_TP_INITIAL_MAX_STREAMS_UNI,
    offsetof (SocketQUICTransportParams_T, initial_max_streams_uni),
    QUIC_TP_DEFAULT_INITIAL_MAX_STREAMS },
  { QUIC_TP_ACK_DELAY_EXPONENT,
    offsetof (SocketQUICTransportParams_T, ack_delay_exponent),
    QUIC_TP_DEFAULT_ACK_DELAY_EXPONENT },
  { QUIC_TP_MAX_ACK_DELAY,
    offsetof (SocketQUICTransportParams_T, max_ack_delay),
    QUIC_TP_DEFAULT_MAX_ACK_DELAY },
  { QUIC_TP_ACTIVE_CONNID_LIMIT,
    offsetof (SocketQUICTransportParams_T, active_connection_id_limit),
    QUIC_TP_DEFAULT_ACTIVE_CONNID_LIMIT },
};

#define VARINT_PARAM_COUNT (sizeof (varint_params) / sizeof (varint_params[0]))

/**
 * @brief Get value of a uint64_t field by offset.
 *
 * Performs bounds checking to ensure the offset is valid and within struct bounds.
 * The assertions verify:
 *   - params pointer is non-NULL
 *   - offset is within the struct
 *   - offset + sizeof(uint64_t) does not exceed struct bounds
 *
 * While offsets are compile-time constants from offsetof(), these assertions
 * provide defense-in-depth against memory corruption or misuse.
 */
static inline uint64_t
get_param_value (const SocketQUICTransportParams_T *params, size_t offset)
{
  assert (params != NULL);
  assert (offset <= sizeof (*params) - sizeof (uint64_t));
  return *(const uint64_t *)((const uint8_t *)params + offset);
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

  /* Variable integer parameters (table-driven, only encode non-defaults) */
  for (size_t i = 0; i < VARINT_PARAM_COUNT; i++)
    {
      uint64_t value = get_param_value (params, varint_params[i].offset);
      if (value != varint_params[i].default_value)
        size += varint_param_size (varint_params[i].param_id, value);
    }

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

  /* Variable integer parameters (table-driven, only encode non-defaults) */
  for (size_t i = 0; i < VARINT_PARAM_COUNT; i++)
    {
      uint64_t value = get_param_value (params, varint_params[i].offset);
      if (value != varint_params[i].default_value)
        {
          len = encode_varint_param (output + pos, output_size - pos,
                                     varint_params[i].param_id, value);
          if (len == 0)
            return 0;
          pos += len;
        }
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

  /* Minimum size when CID length is 0 */
  if (len < QUIC_PREFERRED_ADDR_MIN_SIZE)
    return QUIC_TP_ERROR_INCOMPLETE;

  /* IPv4 address */
  memcpy (paddr->ipv4_address, data + pos, QUIC_IPV4_ADDR_LEN);
  pos += QUIC_IPV4_ADDR_LEN;

  /* IPv4 port (big-endian) */
  paddr->ipv4_port = ((uint16_t)data[pos] << 8) | data[pos + 1];
  pos += 2;

  /* IPv6 address */
  memcpy (paddr->ipv6_address, data + pos, QUIC_IPV6_ADDR_LEN);
  pos += QUIC_IPV6_ADDR_LEN;

  /* IPv6 port (big-endian) */
  paddr->ipv6_port = ((uint16_t)data[pos] << 8) | data[pos + 1];
  pos += 2;

  /* Connection ID length */
  uint8_t cid_len = data[pos++];
  if (cid_len > QUIC_CONNID_MAX_LEN)
    return QUIC_TP_ERROR_INVALID_VALUE;
  if (pos + cid_len + QUIC_STATELESS_RESET_TOKEN_LEN > len)
    return QUIC_TP_ERROR_INCOMPLETE;

  /* Connection ID */
  SocketQUICConnectionID_Result res =
      SocketQUICConnectionID_set (&paddr->connection_id, data + pos, cid_len);
  if (res != QUIC_CONNID_OK)
    return QUIC_TP_ERROR_INVALID_VALUE;
  pos += cid_len;

  /* Stateless reset token */
  memcpy (paddr->stateless_reset_token, data + pos, QUIC_STATELESS_RESET_TOKEN_LEN);
  pos += QUIC_STATELESS_RESET_TOKEN_LEN;

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

/**
 * @brief Decode and validate a single transport parameter.
 *
 * Extracts one parameter from the data stream, validates it, and dispatches
 * to the appropriate handler.
 *
 * @param data Input buffer
 * @param len Length of input buffer
 * @param pos Current position (updated on success)
 * @param peer_role Role of the peer sending these parameters
 * @param params Output parameter structure
 * @param seen_params Bitmap for duplicate detection (only tracks IDs 0-63)
 * @return QUIC_TP_OK on success, error code otherwise
 */
static SocketQUICTransportParams_Result
decode_single_param (const uint8_t *data, size_t len, size_t *pos,
                     SocketQUICRole peer_role,
                     SocketQUICTransportParams_T *params, uint64_t *seen_params)
{
  uint64_t param_id;
  uint64_t param_len;
  size_t bytes_consumed;
  SocketQUICTransportParams_Result result;

  /* Decode parameter ID */
  result = decode_varint_value (data + *pos, len - *pos, &param_id,
                                &bytes_consumed);
  if (result != QUIC_TP_OK)
    return result;
  *pos += bytes_consumed;

  /* Decode parameter length */
  result = decode_varint_value (data + *pos, len - *pos, &param_len,
                                &bytes_consumed);
  if (result != QUIC_TP_OK)
    return result;
  *pos += bytes_consumed;

  /* Check we have enough data for the parameter value */
  if (*pos + param_len > len)
    return QUIC_TP_ERROR_INCOMPLETE;

  /* Check for duplicates (limited to param IDs 0-63 by bitmap size).
   * Parameters with ID >= 64 bypass duplicate detection, but this is
   * acceptable since RFC 9000 permits ignoring unknown parameters.
   */
  if (param_id <= QUIC_TP_DUPLICATE_CHECK_MAX_ID)
    {
      uint64_t mask = 1ULL << param_id;
      if (*seen_params & mask)
        return QUIC_TP_ERROR_DUPLICATE;
      *seen_params |= mask;
    }

  /* Parse parameter based on ID using table-driven dispatch */
  ParamDecodeHandler handler = find_param_handler (param_id);
  if (handler != NULL)
    {
      result = handler (data + *pos, (size_t)param_len, peer_role, params);
      if (result != QUIC_TP_OK)
        return result;
    }
  /* Unknown parameters are ignored per RFC 9000 Section 18.1 */

  *pos += (size_t)param_len;
  return QUIC_TP_OK;
}

SocketQUICTransportParams_Result
SocketQUICTransportParams_decode (const uint8_t *data, size_t len,
                                  SocketQUICRole peer_role,
                                  SocketQUICTransportParams_T *params,
                                  size_t *consumed)
{
  size_t pos = 0;
  /* Bitmap for duplicate detection.
   * Only tracks param IDs 0-63 due to 64-bit limit.
   * Extension params >= 64 won't be checked for duplicates,
   * which is acceptable per RFC 9000 Section 18.1 (ignore unknown).
   * Current known params (all < 64):
   *   0x00-0x10: Core parameters (RFC 9000)
   *   0x11: VERSION_INFO (RFC 9369)
   *   0x20: MAX_DATAGRAM_FRAME_SIZE (RFC 9221)
   */
  uint64_t seen_params = 0;
  SocketQUICTransportParams_Result result;

  if (data == NULL || params == NULL || consumed == NULL)
    return QUIC_TP_ERROR_NULL;

  /* Initialize with defaults */
  SocketQUICTransportParams_init (params);

  while (pos < len)
    {
      result =
          decode_single_param (data, len, &pos, peer_role, params, &seen_params);
      if (result != QUIC_TP_OK)
        return result;
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
