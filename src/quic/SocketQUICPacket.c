/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketQUICPacket.c - QUIC Packet Header Parsing (RFC 9000 Section 17)
 *
 * Implements parsing and serialization of QUIC packet headers for all
 * packet types: Initial, 0-RTT, Handshake, Retry, and 1-RTT.
 */

#include <limits.h>
#include <string.h>

#include "quic/SocketQUICPacket.h"
#include "quic/SocketQUICVarInt.h"
#include "quic/SocketQUICConstants.h"
#include "core/SocketUtil.h"

#ifdef SOCKET_HAS_TLS
#include <openssl/evp.h>
#include <openssl/crypto.h>
#endif

#ifdef SOCKET_HAS_TLS
static const uint8_t RETRY_KEY[16]
    = { 0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
        0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e };

static const uint8_t RETRY_NONCE[12] = { 0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63,
                                         0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb };
#endif /* SOCKET_HAS_TLS */

static const char *result_strings[] = {
  [QUIC_PACKET_OK] = "OK",
  [QUIC_PACKET_ERROR_NULL] = "NULL pointer argument",
  [QUIC_PACKET_ERROR_TRUNCATED] = "Insufficient input data",
  [QUIC_PACKET_ERROR_BUFFER] = "Output buffer too small",
  [QUIC_PACKET_ERROR_INVALID] = "Invalid packet format",
  [QUIC_PACKET_ERROR_FIXED_BIT] = "Fixed bit not set",
  [QUIC_PACKET_ERROR_VERSION] = "Invalid version",
  [QUIC_PACKET_ERROR_CONNID] = "Invalid Connection ID",
  [QUIC_PACKET_ERROR_TOKEN] = "Token too long",
  [QUIC_PACKET_ERROR_PNLEN] = "Invalid packet number length",
};

static const char *type_strings[] = {
  [QUIC_PACKET_TYPE_INITIAL] = "Initial",
  [QUIC_PACKET_TYPE_0RTT] = "0-RTT",
  [QUIC_PACKET_TYPE_HANDSHAKE] = "Handshake",
  [QUIC_PACKET_TYPE_RETRY] = "Retry",
  [QUIC_PACKET_TYPE_1RTT] = "1-RTT",
};

DEFINE_RESULT_STRING_FUNC (SocketQUICPacket, QUIC_PACKET_ERROR_PNLEN)

const char *
SocketQUICPacket_type_string (SocketQUICPacket_Type type)
{
  if (type > QUIC_PACKET_TYPE_1RTT)
    return "Unknown";
  return type_strings[type];
}

void
SocketQUICPacketHeader_init (SocketQUICPacketHeader_T *header)
{
  if (header == NULL)
    return;

  memset (header, 0, sizeof (*header));
}

/* Big-endian pack/unpack helpers - using shared utilities from SocketUtil.h */
#define unpack_be32(data) socket_util_unpack_be32 (data)
#define pack_be32(data, value) socket_util_pack_be32 (data, value)

/* Variable-length packet number encoding - QUIC specific */
static inline uint32_t
unpack_pn (const uint8_t *data, uint8_t pn_length)
{
  uint32_t pn = 0;

  for (uint8_t i = 0; i < pn_length; i++)
    pn = (pn << 8) | data[i];

  return pn;
}

static inline void
pack_pn (uint8_t *data, uint32_t pn, uint8_t pn_length)
{
  for (uint8_t i = 0; i < pn_length; i++)
    data[i] = (uint8_t)((pn >> (8 * (pn_length - 1 - i))) & 0xFF);
}

static SocketQUICPacket_Result
parse_initial_header (const uint8_t *data,
                      size_t len,
                      SocketQUICPacketHeader_T *header,
                      size_t *offset,
                      size_t *consumed);

static SocketQUICPacket_Result
parse_protected_header (const uint8_t *data,
                        size_t len,
                        SocketQUICPacketHeader_T *header,
                        size_t *offset,
                        size_t *consumed);

static SocketQUICPacket_Result
parse_retry_header (const uint8_t *data,
                    size_t len,
                    SocketQUICPacketHeader_T *header,
                    size_t *offset,
                    size_t *consumed);

static size_t serialize_initial_fields (const SocketQUICPacketHeader_T *header,
                                        uint8_t *output,
                                        size_t output_size,
                                        size_t offset);

static size_t
serialize_protected_fields (const SocketQUICPacketHeader_T *header,
                            uint8_t *output,
                            size_t output_size,
                            size_t offset);

static size_t serialize_retry_fields (const SocketQUICPacketHeader_T *header,
                                      uint8_t *output,
                                      size_t output_size,
                                      size_t offset);

static SocketQUICPacket_Result
parse_long_header (const uint8_t *data,
                   size_t len,
                   SocketQUICPacketHeader_T *header,
                   size_t *consumed)
{
  size_t offset = 0;
  SocketQUICConnectionID_Result cid_result;
  size_t cid_consumed;

  /* Minimum: flags(1) + version(4) + dcid_len(1) + scid_len(1) */
  if (len < QUIC_PACKET_LONG_HEADER_MIN_SIZE)
    return QUIC_PACKET_ERROR_TRUNCATED;

  header->is_long_header = 1;
  header->first_byte = data[0];
  header->type = SocketQUICPacket_parse_long_type (data[0]);
  header->pn_length = (data[0] & QUIC_PACKET_LONG_PNLEN_MASK) + 1;
  offset = 1;

  /* Version field (4 bytes, big-endian) */
  header->version = unpack_be32 (data + offset);
  offset += 4;

  /* Destination Connection ID */
  cid_result = SocketQUICConnectionID_decode (
      data + offset, len - offset, &header->dcid, &cid_consumed);
  if (cid_result == QUIC_CONNID_ERROR_INCOMPLETE)
    return QUIC_PACKET_ERROR_TRUNCATED;
  if (cid_result != QUIC_CONNID_OK)
    return QUIC_PACKET_ERROR_CONNID;
  offset += cid_consumed;

  /* Source Connection ID */
  cid_result = SocketQUICConnectionID_decode (
      data + offset, len - offset, &header->scid, &cid_consumed);
  if (cid_result == QUIC_CONNID_ERROR_INCOMPLETE)
    return QUIC_PACKET_ERROR_TRUNCATED;
  if (cid_result != QUIC_CONNID_OK)
    return QUIC_PACKET_ERROR_CONNID;
  offset += cid_consumed;

  /* Type-specific fields */
  switch (header->type)
    {
    case QUIC_PACKET_TYPE_INITIAL:
      return parse_initial_header (data, len, header, &offset, consumed);

    case QUIC_PACKET_TYPE_RETRY:
      return parse_retry_header (data, len, header, &offset, consumed);

    case QUIC_PACKET_TYPE_0RTT:
    case QUIC_PACKET_TYPE_HANDSHAKE:
      return parse_protected_header (data, len, header, &offset, consumed);

    default:
      return QUIC_PACKET_ERROR_INVALID;
    }
}

static SocketQUICPacket_Result
parse_initial_header (const uint8_t *data,
                      size_t len,
                      SocketQUICPacketHeader_T *header,
                      size_t *offset,
                      size_t *consumed)
{
  SocketQUICVarInt_Result vi_result;
  uint64_t token_len;
  size_t vi_consumed;

  /* Token length (varint) */
  vi_result = SocketQUICVarInt_decode (
      data + *offset, len - *offset, &token_len, &vi_consumed);
  if (vi_result == QUIC_VARINT_INCOMPLETE)
    return QUIC_PACKET_ERROR_TRUNCATED;
  if (vi_result != QUIC_VARINT_OK)
    return QUIC_PACKET_ERROR_INVALID;
  *offset += vi_consumed;

  if (token_len > QUIC_PACKET_TOKEN_MAX_LEN)
    return QUIC_PACKET_ERROR_TOKEN;

  if (len - *offset < token_len)
    return QUIC_PACKET_ERROR_TRUNCATED;

  header->token = (token_len > 0) ? (data + *offset) : NULL;
  header->token_length = token_len;
  *offset += token_len;

  return parse_protected_header (data, len, header, offset, consumed);
}

static SocketQUICPacket_Result
parse_protected_header (const uint8_t *data,
                        size_t len,
                        SocketQUICPacketHeader_T *header,
                        size_t *offset,
                        size_t *consumed)
{
  SocketQUICVarInt_Result vi_result;
  size_t vi_consumed;

  /* Length field (varint) */
  vi_result = SocketQUICVarInt_decode (
      data + *offset, len - *offset, &header->length, &vi_consumed);
  if (vi_result == QUIC_VARINT_INCOMPLETE)
    return QUIC_PACKET_ERROR_TRUNCATED;
  if (vi_result != QUIC_VARINT_OK)
    return QUIC_PACKET_ERROR_INVALID;
  *offset += vi_consumed;

  /* Packet number (1-4 bytes, before header protection removal) */
  if (len - *offset < header->pn_length)
    return QUIC_PACKET_ERROR_TRUNCATED;

  header->packet_number = unpack_pn (data + *offset, header->pn_length);
  *offset += header->pn_length;

  header->header_length = *offset;
  *consumed = *offset;
  return QUIC_PACKET_OK;
}

static SocketQUICPacket_Result
parse_retry_header (const uint8_t *data,
                    size_t len,
                    SocketQUICPacketHeader_T *header,
                    size_t *offset,
                    size_t *consumed)
{
  /* Retry packet has no Length or Packet Number fields */
  /* The Retry Token is everything except the last 16 bytes (integrity tag) */

  if (len - *offset < QUIC_RETRY_INTEGRITY_TAG_LEN)
    return QUIC_PACKET_ERROR_TRUNCATED;

  size_t retry_token_len = len - *offset - QUIC_RETRY_INTEGRITY_TAG_LEN;

  header->retry_token = (retry_token_len > 0) ? (data + *offset) : NULL;
  header->retry_token_length = retry_token_len;
  *offset += retry_token_len;

  /* Copy the 16-byte Retry Integrity Tag */
  memcpy (header->retry_integrity_tag,
          data + *offset,
          QUIC_RETRY_INTEGRITY_TAG_LEN);
  header->has_retry_integrity_tag = 1;
  *offset += QUIC_RETRY_INTEGRITY_TAG_LEN;

  header->header_length = *offset;
  *consumed = *offset;
  return QUIC_PACKET_OK;
}

static SocketQUICPacket_Result
parse_short_header (const uint8_t *data,
                    size_t len,
                    SocketQUICPacketHeader_T *header,
                    size_t *consumed)
{
  size_t offset = 0;
  SocketQUICConnectionID_Result cid_result;

  header->is_long_header = 0;
  header->type = QUIC_PACKET_TYPE_1RTT;
  header->first_byte = data[0];

  /* Parse first byte fields */
  header->spin_bit = (data[0] & QUIC_PACKET_SHORT_SPIN_BIT) ? 1 : 0;
  header->key_phase = (data[0] & QUIC_PACKET_SHORT_KEY_PHASE_BIT) ? 1 : 0;
  header->pn_length = (data[0] & QUIC_PACKET_SHORT_PNLEN_MASK) + 1;
  offset = 1;

  /* DCID (length must be known from connection state) */
  if (header->dcid_length > 0)
    {
      cid_result = SocketQUICConnectionID_decode_fixed (
          data + offset, len - offset, &header->dcid, header->dcid_length);

      if (cid_result == QUIC_CONNID_ERROR_INCOMPLETE)
        return QUIC_PACKET_ERROR_TRUNCATED;
      if (cid_result != QUIC_CONNID_OK)
        return QUIC_PACKET_ERROR_CONNID;

      offset += header->dcid_length;
    }

  /* Packet number (1-4 bytes) */
  if (len - offset < header->pn_length)
    return QUIC_PACKET_ERROR_TRUNCATED;

  header->packet_number = unpack_pn (data + offset, header->pn_length);
  offset += header->pn_length;

  header->header_length = offset;
  *consumed = offset;
  return QUIC_PACKET_OK;
}

SocketQUICPacket_Result
SocketQUICPacketHeader_parse (const uint8_t *data,
                              size_t len,
                              SocketQUICPacketHeader_T *header,
                              size_t *consumed)
{
  uint8_t saved_dcid_length;

  if (data == NULL || header == NULL || consumed == NULL)
    return QUIC_PACKET_ERROR_NULL;

  if (len < 1)
    return QUIC_PACKET_ERROR_TRUNCATED;

  /* Check fixed bit (Section 17.2 / 17.3) */
  if (!SocketQUICPacket_has_fixed_bit (data[0]))
    return QUIC_PACKET_ERROR_FIXED_BIT;

  /* Preserve dcid_length for short header parsing (caller sets it) */
  saved_dcid_length = header->dcid_length;

  SocketQUICPacketHeader_init (header);

  if (SocketQUICPacket_is_long_header (data[0]))
    return parse_long_header (data, len, header, consumed);
  else
    {
      /* Restore dcid_length for short header */
      header->dcid_length = saved_dcid_length;
      return parse_short_header (data, len, header, consumed);
    }
}

size_t
SocketQUICPacketHeader_size (const SocketQUICPacketHeader_T *header)
{
  size_t size = 0;

  if (header == NULL)
    return 0;

  if (header->is_long_header)
    {
      /* Flags(1) + Version(4) + DCID_len(1) + DCID + SCID_len(1) + SCID */
      size = 1 + 4 + 1 + header->dcid.len + 1 + header->scid.len;

      switch (header->type)
        {
        case QUIC_PACKET_TYPE_INITIAL:
          /* Token length (varint) + Token */
          size += SocketQUICVarInt_size (header->token_length);
          size += header->token_length;
          /* Fall through for Length + PN */
          /* FALLTHROUGH */

        case QUIC_PACKET_TYPE_0RTT:
        case QUIC_PACKET_TYPE_HANDSHAKE:
          /* Length (varint) + Packet Number */
          size += SocketQUICVarInt_size (header->length);
          size += header->pn_length;
          break;

        case QUIC_PACKET_TYPE_RETRY:
          /* Retry Token + Integrity Tag (16 bytes) */
          size += header->retry_token_length;
          size += QUIC_RETRY_INTEGRITY_TAG_LEN;
          break;

        default:
          return 0;
        }
    }
  else
    {
      /* Flags(1) + DCID + Packet Number */
      size = 1 + header->dcid.len + header->pn_length;
    }

  return size;
}

static size_t
serialize_initial_fields (const SocketQUICPacketHeader_T *header,
                          uint8_t *output,
                          size_t output_size,
                          size_t offset)
{
  size_t written;

  /* Token length (varint) */
  written = SocketQUICVarInt_encode (
      header->token_length, output + offset, output_size - offset);
  if (written == 0)
    return 0;
  offset += written;

  /* Token data */
  if (header->token_length > 0 && header->token != NULL)
    {
      if (output_size - offset < header->token_length)
        return 0;
      memcpy (output + offset, header->token, header->token_length);
      offset += header->token_length;
    }

  /* Continue with protected fields (Length + PN) */
  return serialize_protected_fields (header, output, output_size, offset);
}

static size_t
serialize_protected_fields (const SocketQUICPacketHeader_T *header,
                            uint8_t *output,
                            size_t output_size,
                            size_t offset)
{
  size_t written;

  /* Length field (varint) */
  written = SocketQUICVarInt_encode (
      header->length, output + offset, output_size - offset);
  if (written == 0)
    return 0;
  offset += written;

  /* Packet Number */
  if (output_size - offset < header->pn_length)
    return 0;
  pack_pn (output + offset, header->packet_number, header->pn_length);
  offset += header->pn_length;

  return offset;
}

static size_t
serialize_retry_fields (const SocketQUICPacketHeader_T *header,
                        uint8_t *output,
                        size_t output_size,
                        size_t offset)
{
  /* Retry Token */
  if (header->retry_token_length > 0 && header->retry_token != NULL)
    {
      if (output_size - offset < header->retry_token_length)
        return 0;
      memcpy (output + offset, header->retry_token, header->retry_token_length);
      offset += header->retry_token_length;
    }

  /* Retry Integrity Tag (16 bytes) */
  if (output_size - offset < QUIC_RETRY_INTEGRITY_TAG_LEN)
    return 0;
  memcpy (output + offset,
          header->retry_integrity_tag,
          QUIC_RETRY_INTEGRITY_TAG_LEN);
  offset += QUIC_RETRY_INTEGRITY_TAG_LEN;

  return offset;
}

static size_t
serialize_long_header (const SocketQUICPacketHeader_T *header,
                       uint8_t *output,
                       size_t output_size)
{
  size_t offset = 0;
  size_t required = SocketQUICPacketHeader_size (header);
  uint8_t first_byte;
  size_t written;

  if (output_size < required)
    return 0;

  /* First byte: Form(1) | Fixed(1) | Type(2) | Reserved(2) | PN_Len(2) */
  first_byte = QUIC_PACKET_FORM_BIT | QUIC_PACKET_FIXED_BIT;
  first_byte |= ((uint8_t)header->type << QUIC_PACKET_LONG_TYPE_SHIFT);
  first_byte |= (header->pn_length - 1) & QUIC_PACKET_LONG_PNLEN_MASK;
  output[offset++] = first_byte;

  /* Version */
  pack_be32 (output + offset, header->version);
  offset += 4;

  /* DCID with length prefix */
  written = SocketQUICConnectionID_encode_with_length (
      &header->dcid, output + offset, output_size - offset);
  if (written == 0 && header->dcid.len > 0)
    return 0;
  offset += (written > 0) ? written : 1; /* At least length byte */

  /* SCID with length prefix */
  written = SocketQUICConnectionID_encode_with_length (
      &header->scid, output + offset, output_size - offset);
  if (written == 0 && header->scid.len > 0)
    return 0;
  offset += (written > 0) ? written : 1;

  /* Type-specific fields */
  switch (header->type)
    {
    case QUIC_PACKET_TYPE_INITIAL:
      return serialize_initial_fields (header, output, output_size, offset);

    case QUIC_PACKET_TYPE_0RTT:
    case QUIC_PACKET_TYPE_HANDSHAKE:
      return serialize_protected_fields (header, output, output_size, offset);

    case QUIC_PACKET_TYPE_RETRY:
      return serialize_retry_fields (header, output, output_size, offset);

    default:
      return 0;
    }
}

static size_t
serialize_short_header (const SocketQUICPacketHeader_T *header,
                        uint8_t *output,
                        size_t output_size)
{
  size_t offset = 0;
  size_t required = SocketQUICPacketHeader_size (header);
  uint8_t first_byte;

  if (output_size < required)
    return 0;

  /* First byte: Form(0) | Fixed(1) | Spin(1) | Reserved(2) | KeyPhase(1) |
   * PN_Len(2) */
  first_byte = QUIC_PACKET_FIXED_BIT;
  if (header->spin_bit)
    first_byte |= QUIC_PACKET_SHORT_SPIN_BIT;
  if (header->key_phase)
    first_byte |= QUIC_PACKET_SHORT_KEY_PHASE_BIT;
  first_byte |= (header->pn_length - 1) & QUIC_PACKET_SHORT_PNLEN_MASK;
  output[offset++] = first_byte;

  /* DCID (no length prefix) */
  if (header->dcid.len > 0)
    {
      memcpy (output + offset, header->dcid.data, header->dcid.len);
      offset += header->dcid.len;
    }

  /* Packet Number */
  pack_pn (output + offset, header->packet_number, header->pn_length);
  offset += header->pn_length;

  return offset;
}

size_t
SocketQUICPacketHeader_serialize (const SocketQUICPacketHeader_T *header,
                                  uint8_t *output,
                                  size_t output_size)
{
  if (header == NULL || output == NULL)
    return 0;

  if (header->is_long_header)
    return serialize_long_header (header, output, output_size);
  else
    return serialize_short_header (header, output, output_size);
}

static SocketQUICPacket_Result
validate_pn_length (uint8_t pn_length)
{
  if (pn_length < QUIC_PACKET_NUMBER_MIN_LEN
      || pn_length > QUIC_PACKET_NUMBER_MAX_LEN)
    return QUIC_PACKET_ERROR_PNLEN;
  return QUIC_PACKET_OK;
}

SocketQUICPacket_Result
SocketQUICPacketHeader_build_initial (SocketQUICPacketHeader_T *header,
                                      uint32_t version,
                                      const SocketQUICConnectionID_T *dcid,
                                      const SocketQUICConnectionID_T *scid,
                                      const uint8_t *token,
                                      size_t token_len,
                                      uint8_t pn_length,
                                      uint32_t pn)
{
  SocketQUICPacket_Result result;

  if (header == NULL)
    return QUIC_PACKET_ERROR_NULL;

  result = validate_pn_length (pn_length);
  if (result != QUIC_PACKET_OK)
    return result;

  if (token_len > QUIC_PACKET_TOKEN_MAX_LEN)
    return QUIC_PACKET_ERROR_TOKEN;

  SocketQUICPacketHeader_init (header);
  header->is_long_header = 1;
  header->type = QUIC_PACKET_TYPE_INITIAL;
  header->version = version;
  header->pn_length = pn_length;
  header->packet_number = pn;

  if (dcid != NULL)
    SocketQUICConnectionID_copy (&header->dcid, dcid);

  if (scid != NULL)
    SocketQUICConnectionID_copy (&header->scid, scid);

  header->token = token;
  header->token_length = token_len;

  return QUIC_PACKET_OK;
}

SocketQUICPacket_Result
SocketQUICPacketHeader_build_handshake (SocketQUICPacketHeader_T *header,
                                        uint32_t version,
                                        const SocketQUICConnectionID_T *dcid,
                                        const SocketQUICConnectionID_T *scid,
                                        uint8_t pn_length,
                                        uint32_t pn)
{
  SocketQUICPacket_Result result;

  if (header == NULL)
    return QUIC_PACKET_ERROR_NULL;

  result = validate_pn_length (pn_length);
  if (result != QUIC_PACKET_OK)
    return result;

  SocketQUICPacketHeader_init (header);
  header->is_long_header = 1;
  header->type = QUIC_PACKET_TYPE_HANDSHAKE;
  header->version = version;
  header->pn_length = pn_length;
  header->packet_number = pn;

  if (dcid != NULL)
    SocketQUICConnectionID_copy (&header->dcid, dcid);

  if (scid != NULL)
    SocketQUICConnectionID_copy (&header->scid, scid);

  return QUIC_PACKET_OK;
}

SocketQUICPacket_Result
SocketQUICPacketHeader_build_0rtt (SocketQUICPacketHeader_T *header,
                                   uint32_t version,
                                   const SocketQUICConnectionID_T *dcid,
                                   const SocketQUICConnectionID_T *scid,
                                   uint8_t pn_length,
                                   uint32_t pn)
{
  SocketQUICPacket_Result result;

  if (header == NULL)
    return QUIC_PACKET_ERROR_NULL;

  result = validate_pn_length (pn_length);
  if (result != QUIC_PACKET_OK)
    return result;

  SocketQUICPacketHeader_init (header);
  header->is_long_header = 1;
  header->type = QUIC_PACKET_TYPE_0RTT;
  header->version = version;
  header->pn_length = pn_length;
  header->packet_number = pn;

  if (dcid != NULL)
    SocketQUICConnectionID_copy (&header->dcid, dcid);

  if (scid != NULL)
    SocketQUICConnectionID_copy (&header->scid, scid);

  return QUIC_PACKET_OK;
}

SocketQUICPacket_Result
SocketQUICPacketHeader_build_short (SocketQUICPacketHeader_T *header,
                                    const SocketQUICConnectionID_T *dcid,
                                    int spin_bit,
                                    int key_phase,
                                    uint8_t pn_length,
                                    uint32_t pn)
{
  SocketQUICPacket_Result result;

  if (header == NULL)
    return QUIC_PACKET_ERROR_NULL;

  result = validate_pn_length (pn_length);
  if (result != QUIC_PACKET_OK)
    return result;

  SocketQUICPacketHeader_init (header);
  header->is_long_header = 0;
  header->type = QUIC_PACKET_TYPE_1RTT;
  header->spin_bit = spin_bit ? 1 : 0;
  header->key_phase = key_phase ? 1 : 0;
  header->pn_length = pn_length;
  header->packet_number = pn;

  if (dcid != NULL)
    SocketQUICConnectionID_copy (&header->dcid, dcid);

  return QUIC_PACKET_OK;
}

uint8_t
SocketQUICPacket_pn_length (uint64_t pn, uint64_t largest_ack)
{
  uint64_t num_unacked;

  /* Calculate the range needed */
  if (pn > largest_ack)
    num_unacked = pn - largest_ack;
  else
    num_unacked = 0;

  /* Determine minimum bytes needed for twice the range (per RFC 9000) */
  num_unacked *= 2;

  if (num_unacked <= 0x7F)
    return 1;
  if (num_unacked <= 0x3FFF)
    return 2;
  if (num_unacked <= 0x3FFFFF)
    return 3;
  return 4;
}

uint32_t
SocketQUICPacket_encode_pn (uint64_t pn, uint8_t pn_length)
{
  switch (pn_length)
    {
    case 1:
      return (uint32_t)(pn & 0xFF);
    case 2:
      return (uint32_t)(pn & 0xFFFF);
    case 3:
      return (uint32_t)(pn & 0xFFFFFF);
    case 4:
      return (uint32_t)(pn & 0xFFFFFFFF);
    default:
      return 0;
    }
}

uint64_t
SocketQUICPacket_decode_pn (uint32_t truncated_pn,
                            uint8_t pn_length,
                            uint64_t largest_pn)
{
  uint64_t expected_pn;
  uint64_t pn_win;
  uint64_t pn_hwin;
  uint64_t pn_mask;
  uint64_t candidate_pn;

  /* Validate pn_length to prevent integer overflow in shift operation */
  if (pn_length < QUIC_PACKET_NUMBER_MIN_LEN
      || pn_length > QUIC_PACKET_NUMBER_MAX_LEN)
    return 0;

  /* Calculate the expected packet number window */
  expected_pn = largest_pn + 1;
  pn_win = (uint64_t)1 << (pn_length * 8);
  pn_hwin = pn_win / 2;
  pn_mask = pn_win - 1;

  /* The truncated PN is in the lower bits */
  candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;

  /* Check if we need to adjust up or down */
  if (candidate_pn + pn_hwin <= expected_pn && candidate_pn < (1ULL << 62))
    return candidate_pn + pn_win;

  if (candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win)
    return candidate_pn - pn_win;

  return candidate_pn;
}

#ifdef SOCKET_HAS_TLS

/**
 * @brief Build Retry pseudo-packet for AEAD AAD.
 *
 * The pseudo-packet format per RFC 9001 §5.8:
 *   ODCID Length (1 byte)
 *   Original Destination Connection ID (0..20 bytes)
 *   Retry packet header and payload (without integrity tag)
 *
 * @param odcid           Original Destination Connection ID.
 * @param retry_packet    Retry packet data (without integrity tag).
 * @param retry_packet_len Length of retry packet.
 * @param pseudo_packet   Output buffer (must be at least
 *                        1 + QUIC_CONNECTION_ID_MAX_LEN + retry_packet_len).
 * @param pseudo_packet_len Output: actual length written.
 *
 * @return 0 on success, -1 on error.
 */
static int
build_retry_pseudo_packet (const SocketQUICConnectionID_T *odcid,
                           const uint8_t *retry_packet,
                           size_t retry_packet_len,
                           uint8_t *pseudo_packet,
                           size_t *pseudo_packet_len)
{
  size_t offset = 0;

  if (odcid == NULL || retry_packet == NULL || pseudo_packet == NULL
      || pseudo_packet_len == NULL)
    return -1;

  if (odcid->len > QUIC_CONNID_MAX_LEN)
    return -1;

  /* Write ODCID length (1 byte) */
  pseudo_packet[offset++] = odcid->len;

  /* Write ODCID data */
  if (odcid->len > 0)
    {
      memcpy (pseudo_packet + offset, odcid->data, odcid->len);
      offset += odcid->len;
    }

  /* Write retry packet (without integrity tag) */
  memcpy (pseudo_packet + offset, retry_packet, retry_packet_len);
  offset += retry_packet_len;

  *pseudo_packet_len = offset;
  return 0;
}

/**
 * @brief Compute AEAD tag using fixed Retry key and nonce.
 *
 * Uses AEAD_AES_128_GCM with empty plaintext. The AAD is the
 * Retry pseudo-packet.
 *
 * @param aad     Associated data (Retry pseudo-packet).
 * @param aad_len Length of AAD.
 * @param tag     Output: 16-byte integrity tag.
 *
 * @return QUIC_PACKET_OK on success, error code otherwise.
 */
static SocketQUICPacket_Result
compute_retry_aead_tag (const uint8_t *aad,
                        size_t aad_len,
                        uint8_t tag[QUIC_RETRY_INTEGRITY_TAG_LEN])
{
  EVP_CIPHER_CTX *ctx = NULL;
  int len;
  int ret = QUIC_PACKET_ERROR_INVALID;

  if (aad == NULL || tag == NULL)
    return QUIC_PACKET_ERROR_NULL;

  /* Prevent overflow when casting to int for OpenSSL API */
  if (aad_len > INT_MAX)
    return QUIC_PACKET_ERROR_BUFFER;

  ctx = EVP_CIPHER_CTX_new ();
  if (ctx == NULL)
    return QUIC_PACKET_ERROR_INVALID;

  /* Initialize AES-128-GCM encryption */
  if (EVP_EncryptInit_ex (ctx, EVP_aes_128_gcm (), NULL, NULL, NULL) != 1)
    goto cleanup;

  /* Set IV length to 12 bytes */
  if (EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1)
    goto cleanup;

  /* Set key and nonce */
  if (EVP_EncryptInit_ex (ctx, NULL, NULL, RETRY_KEY, RETRY_NONCE) != 1)
    goto cleanup;

  /* Provide AAD (no output for AAD) */
  if (EVP_EncryptUpdate (ctx, NULL, &len, aad, (int)aad_len) != 1)
    goto cleanup;

  /* Finalize encryption (empty plaintext) */
  if (EVP_EncryptFinal_ex (ctx, NULL, &len) != 1)
    goto cleanup;

  /* Get the authentication tag */
  if (EVP_CIPHER_CTX_ctrl (
          ctx, EVP_CTRL_GCM_GET_TAG, QUIC_RETRY_INTEGRITY_TAG_LEN, tag)
      != 1)
    goto cleanup;

  ret = QUIC_PACKET_OK;

cleanup:
  EVP_CIPHER_CTX_free (ctx);
  return ret;
}

SocketQUICPacket_Result
SocketQUICPacket_compute_retry_tag (const SocketQUICConnectionID_T *odcid,
                                    const uint8_t *retry_packet,
                                    size_t retry_packet_len,
                                    uint8_t tag[QUIC_RETRY_INTEGRITY_TAG_LEN])
{
  /*
   * Maximum pseudo-packet size:
   * 1 (ODCID length) + 20 (max ODCID) + retry_packet_len
   *
   * We use a stack buffer for reasonable sizes, with bounds check.
   */
  uint8_t pseudo_packet[1 + QUIC_CONNID_MAX_LEN + 1500];
  size_t pseudo_packet_len;

  if (odcid == NULL || retry_packet == NULL || tag == NULL)
    return QUIC_PACKET_ERROR_NULL;

  /* Bounds check for our stack buffer */
  if (retry_packet_len > 1500)
    return QUIC_PACKET_ERROR_BUFFER;

  /* Build the pseudo-packet (AAD) */
  if (build_retry_pseudo_packet (odcid,
                                 retry_packet,
                                 retry_packet_len,
                                 pseudo_packet,
                                 &pseudo_packet_len)
      != 0)
    return QUIC_PACKET_ERROR_INVALID;

  /* Compute the AEAD tag */
  return compute_retry_aead_tag (pseudo_packet, pseudo_packet_len, tag);
}

SocketQUICPacket_Result
SocketQUICPacket_verify_retry_tag (const SocketQUICConnectionID_T *odcid,
                                   const uint8_t *retry_packet,
                                   size_t retry_packet_len)
{
  uint8_t computed_tag[QUIC_RETRY_INTEGRITY_TAG_LEN];
  const uint8_t *expected_tag;
  size_t packet_without_tag_len;
  SocketQUICPacket_Result result;

  if (odcid == NULL || retry_packet == NULL)
    return QUIC_PACKET_ERROR_NULL;

  /* Retry packet must have at least the 16-byte integrity tag */
  if (retry_packet_len < QUIC_RETRY_INTEGRITY_TAG_LEN)
    return QUIC_PACKET_ERROR_TRUNCATED;

  /* Split packet: data before tag and the tag itself */
  packet_without_tag_len = retry_packet_len - QUIC_RETRY_INTEGRITY_TAG_LEN;
  expected_tag = retry_packet + packet_without_tag_len;

  /* Compute tag over packet without the trailing tag */
  result = SocketQUICPacket_compute_retry_tag (
      odcid, retry_packet, packet_without_tag_len, computed_tag);
  if (result != QUIC_PACKET_OK)
    return result;

  /* Constant-time comparison to prevent timing attacks */
  if (CRYPTO_memcmp (computed_tag, expected_tag, QUIC_RETRY_INTEGRITY_TAG_LEN)
      != 0)
    return QUIC_PACKET_ERROR_INVALID;

  return QUIC_PACKET_OK;
}

#else /* !SOCKET_HAS_TLS */

SocketQUICPacket_Result
SocketQUICPacket_compute_retry_tag (const SocketQUICConnectionID_T *odcid,
                                    const uint8_t *retry_packet,
                                    size_t retry_packet_len,
                                    uint8_t tag[QUIC_RETRY_INTEGRITY_TAG_LEN])
{
  (void)odcid;
  (void)retry_packet;
  (void)retry_packet_len;
  (void)tag;
  return QUIC_PACKET_ERROR_INVALID; /* TLS support required */
}

SocketQUICPacket_Result
SocketQUICPacket_verify_retry_tag (const SocketQUICConnectionID_T *odcid,
                                   const uint8_t *retry_packet,
                                   size_t retry_packet_len)
{
  (void)odcid;
  (void)retry_packet;
  (void)retry_packet_len;
  return QUIC_PACKET_ERROR_INVALID; /* TLS support required */
}

#endif /* SOCKET_HAS_TLS */
