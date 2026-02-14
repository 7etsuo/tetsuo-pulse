/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketQUICPacket-receive.c - QUIC Packet Reception (RFC 9001 Section 5.5)
 *
 * Implements the packet reception pipeline for protected QUIC packets:
 * 1. Parse unprotected header fields
 * 2. Remove header protection
 * 3. Decode packet number using window-based reconstruction (RFC 9000 App A)
 * 4. Decrypt AEAD payload
 * 5. Update largest PN if decryption succeeds
 *
 * Security requirements (RFC 9001 §5.5):
 * - Do NOT update largest_pn on decryption failure
 * - Track decryption failures for AEAD integrity limits (§6.6)
 */

#include <string.h>

#include "quic/SocketQUICPacket.h"
#include "quic/SocketQUICCrypto.h"
#include "quic/SocketQUICConstants.h"
#include "quic/SocketQUICVarInt.h"

/* ============================================================================
 * Result String Table
 * ============================================================================
 */

static const char *result_strings[]
    = { [QUIC_RECEIVE_OK] = "OK",
        [QUIC_RECEIVE_ERROR_NULL] = "NULL pointer argument",
        [QUIC_RECEIVE_ERROR_TRUNCATED] = "Packet too short",
        [QUIC_RECEIVE_ERROR_HEADER] = "Header parse error",
        [QUIC_RECEIVE_ERROR_NO_KEYS] = "Keys not available for packet type",
        [QUIC_RECEIVE_ERROR_UNPROTECT] = "Header protection removal failed",
        [QUIC_RECEIVE_ERROR_DECRYPT] = "AEAD decryption/auth failed",
        [QUIC_RECEIVE_ERROR_PN_DECODE] = "Packet number decode failed",
        [QUIC_RECEIVE_ERROR_VERSION] = "Unsupported version",
        [QUIC_RECEIVE_ERROR_KEY_PHASE] = "Key phase mismatch" };

DEFINE_RESULT_STRING_FUNC (SocketQUICReceive, QUIC_RECEIVE_ERROR_KEY_PHASE)

/* ============================================================================
 * Receive Context Management
 * ============================================================================
 */

void
SocketQUICReceive_init (SocketQUICReceive_T *ctx)
{
  if (ctx == NULL)
    return;

  memset (ctx, 0, sizeof (*ctx));
  ctx->initialized = 1;
}

SocketQUICReceive_Result
SocketQUICReceive_set_initial_keys (SocketQUICReceive_T *ctx,
                                    const SocketQUICInitialKeys_T *keys)
{
  if (ctx == NULL)
    return QUIC_RECEIVE_ERROR_NULL;

  ctx->initial_keys = keys;
  return QUIC_RECEIVE_OK;
}

SocketQUICReceive_Result
SocketQUICReceive_set_handshake_keys (SocketQUICReceive_T *ctx,
                                      const struct SocketQUICPacketKeys *keys)
{
  if (ctx == NULL)
    return QUIC_RECEIVE_ERROR_NULL;

  ctx->handshake_keys = keys;
  return QUIC_RECEIVE_OK;
}

SocketQUICReceive_Result
SocketQUICReceive_set_0rtt_keys (SocketQUICReceive_T *ctx,
                                 const struct SocketQUICPacketKeys *keys)
{
  if (ctx == NULL)
    return QUIC_RECEIVE_ERROR_NULL;

  ctx->zero_rtt_keys = keys;
  return QUIC_RECEIVE_OK;
}

SocketQUICReceive_Result
SocketQUICReceive_set_1rtt_keys (SocketQUICReceive_T *ctx,
                                 struct SocketQUICKeyUpdate *state)
{
  if (ctx == NULL)
    return QUIC_RECEIVE_ERROR_NULL;

  ctx->key_update = state;
  return QUIC_RECEIVE_OK;
}

int
SocketQUICReceive_get_largest_pn (const SocketQUICReceive_T *ctx,
                                  SocketQUIC_PNSpace space,
                                  uint64_t *out_pn)
{
  if (ctx == NULL || out_pn == NULL)
    return 0;

  if (space < 0 || space >= QUIC_PN_SPACE_COUNT)
    return 0;

  if (!ctx->spaces[space].has_received)
    return 0;

  *out_pn = ctx->spaces[space].largest_pn;
  return 1;
}

/* ============================================================================
 * Helper Functions
 * ============================================================================
 */

/**
 * @brief Map packet type to packet number space.
 *
 * @param type Packet type.
 *
 * @return Packet number space, or -1 for invalid types.
 */
static int
packet_type_to_pn_space (SocketQUICPacket_Type type)
{
  switch (type)
    {
    case QUIC_PACKET_TYPE_INITIAL:
      return QUIC_PN_SPACE_INITIAL;

    case QUIC_PACKET_TYPE_HANDSHAKE:
      return QUIC_PN_SPACE_HANDSHAKE;

    case QUIC_PACKET_TYPE_0RTT:
    case QUIC_PACKET_TYPE_1RTT:
      return QUIC_PN_SPACE_APPLICATION;

    default:
      return -1;
    }
}

/**
 * @brief Calculate pn_offset for long header packets.
 *
 * For Initial packets: 7 + DCID len + SCID len + token length field + token
 * For Handshake/0-RTT: 7 + DCID len + SCID len
 *
 * @param packet     Packet buffer.
 * @param packet_len Packet length.
 * @param type       Packet type.
 * @param pn_offset  Output: offset to packet number field.
 *
 * @return 0 on success, -1 on error.
 */
static int
calculate_pn_offset_long (const uint8_t *packet,
                          size_t packet_len,
                          SocketQUICPacket_Type type,
                          size_t *pn_offset,
                          size_t *out_packet_len)
{
  /* Minimum long header: 1 + 4 + 1 + DCID + 1 + SCID = 7 + DCID + SCID */
  if (packet_len < 7)
    return -1;

  size_t offset = 5; /* Skip first byte and version */

  /* DCID length and DCID */
  uint8_t dcid_len = packet[offset++];
  if (dcid_len > QUIC_CONNID_MAX_LEN || offset + dcid_len > packet_len)
    return -1;
  offset += dcid_len;

  /* SCID length and SCID */
  if (offset >= packet_len)
    return -1;
  uint8_t scid_len = packet[offset++];
  if (scid_len > QUIC_CONNID_MAX_LEN || offset + scid_len > packet_len)
    return -1;
  offset += scid_len;

  /* For Initial packets, skip token */
  if (type == QUIC_PACKET_TYPE_INITIAL)
    {
      if (offset >= packet_len)
        return -1;

      /* Decode variable-length token length */
      uint64_t token_len;
      size_t token_len_bytes;
      SocketQUICVarInt_Result vr = SocketQUICVarInt_decode (
          packet + offset, packet_len - offset, &token_len, &token_len_bytes);
      if (vr != QUIC_VARINT_OK)
        return -1;

      offset += token_len_bytes;
      if (offset + token_len > packet_len)
        return -1;
      offset += (size_t)token_len;
    }

  /* Decode Length field (variable-length integer) */
  if (offset >= packet_len)
    return -1;

  uint64_t length_field;
  size_t len_bytes;
  SocketQUICVarInt_Result vr = SocketQUICVarInt_decode (
      packet + offset, packet_len - offset, &length_field, &len_bytes);
  if (vr != QUIC_VARINT_OK)
    return -1;

  offset += len_bytes;

  *pn_offset = offset;

  /* Compute actual packet boundary from Length field (RFC 9000 §17.2):
   * Length = PN bytes + payload + AEAD tag.
   * Actual packet ends at pn_offset + Length. */
  if (out_packet_len != NULL)
    {
      size_t actual_len = offset + (size_t)length_field;
      if (actual_len > packet_len)
        return -1;
      *out_packet_len = actual_len;
    }

  return 0;
}

/**
 * @brief Extract truncated packet number from packet.
 *
 * @param packet     Packet buffer.
 * @param packet_len Packet buffer length.
 * @param pn_offset  Offset to PN field.
 * @param pn_length  Length of PN (1-4 bytes).
 * @param out_pn     Output: truncated packet number.
 *
 * @return 0 on success, -1 on bounds error.
 */
static int
extract_truncated_pn (const uint8_t *packet,
                      size_t packet_len,
                      size_t pn_offset,
                      uint8_t pn_length,
                      uint32_t *out_pn)
{
  /* Bounds check: ensure PN field fits within packet */
  if (pn_length == 0 || pn_length > 4)
    return -1;

  if (pn_offset > packet_len || pn_length > packet_len - pn_offset)
    return -1;

  uint32_t pn = 0;
  for (uint8_t i = 0; i < pn_length; i++)
    pn = (pn << 8) | packet[pn_offset + i];

  *out_pn = pn;
  return 0;
}

/* ============================================================================
 * Header Parsing Functions
 * ============================================================================
 */

/**
 * @brief Parse long header packet type and connection IDs.
 *
 * @param packet     Packet buffer.
 * @param packet_len Packet length.
 * @param out_type   Output: packet type.
 * @param result     Output: result struct for connection IDs.
 * @param pn_offset  Output: offset to packet number field.
 *
 * @return QUIC_RECEIVE_OK on success, error code otherwise.
 */
static SocketQUICReceive_Result
parse_long_header (const uint8_t *packet,
                   size_t packet_len,
                   SocketQUICPacket_Type *out_type,
                   SocketQUICReceiveResult_T *result,
                   size_t *pn_offset,
                   size_t *actual_packet_len)
{
  if (packet_len < 7)
    return QUIC_RECEIVE_ERROR_TRUNCATED;

  /* Extract long header type from bits 4-5 of first byte */
  uint8_t long_type = (packet[0] & 0x30) >> 4;
  SocketQUICPacket_Type type;

  switch (long_type)
    {
    case 0:
      type = QUIC_PACKET_TYPE_INITIAL;
      break;
    case 1:
      type = QUIC_PACKET_TYPE_0RTT;
      break;
    case 2:
      type = QUIC_PACKET_TYPE_HANDSHAKE;
      break;
    case 3:
      /* Retry packets are not protected */
      return QUIC_RECEIVE_ERROR_HEADER;
    default:
      return QUIC_RECEIVE_ERROR_HEADER;
    }

  /* Extract connection IDs */
  size_t offset = 5;

  result->dcid.len = packet[offset++];
  if (result->dcid.len > QUIC_CONNID_MAX_LEN
      || offset + result->dcid.len > packet_len)
    return QUIC_RECEIVE_ERROR_HEADER;
  memcpy (result->dcid.data, packet + offset, result->dcid.len);
  offset += result->dcid.len;

  if (offset >= packet_len)
    return QUIC_RECEIVE_ERROR_TRUNCATED;

  result->scid.len = packet[offset++];
  if (result->scid.len > QUIC_CONNID_MAX_LEN
      || offset + result->scid.len > packet_len)
    return QUIC_RECEIVE_ERROR_HEADER;
  memcpy (result->scid.data, packet + offset, result->scid.len);

  /* Calculate pn_offset */
  if (calculate_pn_offset_long (
          packet, packet_len, type, pn_offset, actual_packet_len)
      < 0)
    return QUIC_RECEIVE_ERROR_HEADER;

  *out_type = type;
  return QUIC_RECEIVE_OK;
}

/**
 * @brief Parse short header (1-RTT) packet.
 *
 * @param packet     Packet buffer.
 * @param packet_len Packet length.
 * @param dcid_len   Expected DCID length.
 * @param result     Output: result struct for DCID and spin bit.
 * @param pn_offset  Output: offset to packet number field.
 *
 * @return QUIC_RECEIVE_OK on success, error code otherwise.
 */
static SocketQUICReceive_Result
parse_short_header (const uint8_t *packet,
                    size_t packet_len,
                    uint8_t dcid_len,
                    SocketQUICReceiveResult_T *result,
                    size_t *pn_offset)
{
  /* Validate dcid_len per RFC 9000 §17.2 */
  if (dcid_len > QUIC_CONNID_MAX_LEN)
    return QUIC_RECEIVE_ERROR_HEADER;

  /* Ensure DCID fits in packet */
  if ((size_t)(1 + dcid_len) > packet_len)
    return QUIC_RECEIVE_ERROR_TRUNCATED;

  result->dcid.len = dcid_len;
  memcpy (result->dcid.data, packet + 1, dcid_len);

  /* PN offset is right after DCID */
  *pn_offset = 1 + dcid_len;

  /* Extract spin bit (key phase read after header protection removed) */
  result->spin_bit = (packet[0] >> 5) & 0x01;

  return QUIC_RECEIVE_OK;
}

/* ============================================================================
 * Packet Type Processing Functions
 * ============================================================================
 */

/**
 * @brief Process and decrypt an Initial packet.
 *
 * @param ctx        Receive context.
 * @param packet     Packet buffer.
 * @param packet_len Packet length.
 * @param pn_offset  Offset to packet number field.
 * @param is_server  True if we are the server.
 * @param largest_pn Largest PN received in this space.
 * @param result     Output: result struct.
 *
 * @return QUIC_RECEIVE_OK on success, error code otherwise.
 */
static SocketQUICReceive_Result
receive_initial_packet (SocketQUICReceive_T *ctx,
                        uint8_t *packet,
                        size_t packet_len,
                        size_t pn_offset,
                        int is_server,
                        uint64_t largest_pn,
                        SocketQUICReceiveResult_T *result)
{
  uint8_t pn_length;
  uint32_t truncated_pn;

  if (ctx->initial_keys == NULL)
    return QUIC_RECEIVE_ERROR_NO_KEYS;

  /* Remove header protection and decrypt */
  SocketQUICInitial_Result unprotect_result = SocketQUICInitial_unprotect (
      packet,
      packet_len,
      pn_offset,
      ctx->initial_keys,
      is_server ? 0 : 1, /* is_client for key selection */
      &pn_length);

  if (unprotect_result != QUIC_INITIAL_OK)
    {
      ctx->decryption_failures++;
      if (unprotect_result == QUIC_INITIAL_ERROR_AUTH)
        return QUIC_RECEIVE_ERROR_DECRYPT;
      return QUIC_RECEIVE_ERROR_UNPROTECT;
    }

  /* Extract truncated PN with bounds checking */
  if (extract_truncated_pn (
          packet, packet_len, pn_offset, pn_length, &truncated_pn)
      < 0)
    return QUIC_RECEIVE_ERROR_PN_DECODE;

  /* Decode full packet number */
  uint64_t full_pn
      = SocketQUICPacket_decode_pn (truncated_pn, pn_length, largest_pn);

  /* Calculate payload bounds with underflow protection */
  if (pn_offset > SIZE_MAX - pn_length)
    return QUIC_RECEIVE_ERROR_TRUNCATED;
  size_t header_len = pn_offset + pn_length;
  if (packet_len < QUIC_AEAD_TAG_LEN)
    return QUIC_RECEIVE_ERROR_TRUNCATED;
  if (header_len > packet_len - QUIC_AEAD_TAG_LEN)
    return QUIC_RECEIVE_ERROR_TRUNCATED;

  result->packet_number = full_pn;
  result->payload = packet + header_len;
  result->payload_len = packet_len - header_len - QUIC_AEAD_TAG_LEN;

  return QUIC_RECEIVE_OK;
}

/**
 * @brief Process and decrypt a Handshake or 0-RTT packet.
 *
 * Both use SocketQUICPacketKeys_T with generic AEAD operations.
 *
 * @param keys       Packet protection keys.
 * @param packet     Packet buffer (modified in place).
 * @param packet_len Packet length.
 * @param pn_offset  Offset to packet number field.
 * @param largest_pn Largest PN received in this space.
 * @param result     Output: result struct.
 * @param failures   Pointer to decryption failure counter.
 *
 * @return QUIC_RECEIVE_OK on success, error code otherwise.
 */
static SocketQUICReceive_Result
receive_protected_packet (const SocketQUICPacketKeys_T *keys,
                          uint8_t *packet,
                          size_t packet_len,
                          size_t pn_offset,
                          uint64_t largest_pn,
                          SocketQUICReceiveResult_T *result,
                          uint64_t *failures)
{
  uint8_t pn_length;
  uint32_t truncated_pn;
  SocketQUICCrypto_Result cr;

  /* Remove header protection */
  cr = SocketQUICCrypto_unprotect_header_ex (
      keys, packet, packet_len, pn_offset);
  if (cr != QUIC_CRYPTO_OK)
    {
      (*failures)++;
      return QUIC_RECEIVE_ERROR_UNPROTECT;
    }

  /* Extract PN length from unprotected first byte (bits 0-1) */
  pn_length = (packet[0] & QUIC_PN_LENGTH_MASK) + 1;

  /* Extract truncated PN with bounds checking */
  if (extract_truncated_pn (
          packet, packet_len, pn_offset, pn_length, &truncated_pn)
      < 0)
    return QUIC_RECEIVE_ERROR_PN_DECODE;

  /* Decode full packet number */
  uint64_t full_pn
      = SocketQUICPacket_decode_pn (truncated_pn, pn_length, largest_pn);

  /* Calculate header and payload bounds */
  if (pn_offset > SIZE_MAX - pn_length)
    return QUIC_RECEIVE_ERROR_TRUNCATED;
  size_t header_len = pn_offset + pn_length;
  if (packet_len < QUIC_AEAD_TAG_LEN)
    return QUIC_RECEIVE_ERROR_TRUNCATED;
  if (header_len > packet_len - QUIC_AEAD_TAG_LEN)
    return QUIC_RECEIVE_ERROR_TRUNCATED;

  size_t ciphertext_len = packet_len - header_len;

  /* Decrypt payload in place */
  size_t plaintext_len = ciphertext_len;
  cr = SocketQUICCrypto_decrypt_payload (keys,
                                         full_pn,
                                         packet,
                                         header_len,
                                         packet + header_len,
                                         ciphertext_len,
                                         packet + header_len,
                                         &plaintext_len);
  if (cr != QUIC_CRYPTO_OK)
    {
      (*failures)++;
      if (cr == QUIC_CRYPTO_ERROR_TAG)
        return QUIC_RECEIVE_ERROR_DECRYPT;
      return QUIC_RECEIVE_ERROR_UNPROTECT;
    }

  result->packet_number = full_pn;
  result->payload = packet + header_len;
  result->payload_len = plaintext_len;

  return QUIC_RECEIVE_OK;
}

/**
 * @brief Process and decrypt a 1-RTT (short header) packet.
 *
 * Handles key phase bit and key update mechanism per RFC 9001 §6.
 *
 * @param ctx        Receive context.
 * @param packet     Packet buffer (modified in place).
 * @param packet_len Packet length.
 * @param pn_offset  Offset to packet number field.
 * @param largest_pn Largest PN received in Application space.
 * @param result     Output: result struct.
 *
 * @return QUIC_RECEIVE_OK on success, error code otherwise.
 */
static SocketQUICReceive_Result
receive_1rtt_packet (SocketQUICReceive_T *ctx,
                     uint8_t *packet,
                     size_t packet_len,
                     size_t pn_offset,
                     uint64_t largest_pn,
                     SocketQUICReceiveResult_T *result)
{
  uint8_t pn_length;
  uint32_t truncated_pn;
  SocketQUICCrypto_Result cr;
  const SocketQUICPacketKeys_T *keys;

  struct SocketQUICKeyUpdate *ku = ctx->key_update;

  /*
   * For 1-RTT, we need to:
   * 1. Remove header protection to reveal key phase and PN length
   * 2. Select appropriate keys based on key phase
   * 3. Decrypt payload
   */

  /* Use current read keys for header unprotection (HP key doesn't change) */
  cr = SocketQUICCrypto_unprotect_header_ex (
      &ku->read_keys, packet, packet_len, pn_offset);
  if (cr != QUIC_CRYPTO_OK)
    {
      SocketQUICKeyUpdate_on_decrypt_failure (ku);
      ctx->decryption_failures++;
      return QUIC_RECEIVE_ERROR_UNPROTECT;
    }

  /* Extract PN length from unprotected first byte */
  pn_length = (packet[0] & QUIC_PN_LENGTH_MASK) + 1;

  /* Extract truncated PN with bounds checking */
  if (extract_truncated_pn (
          packet, packet_len, pn_offset, pn_length, &truncated_pn)
      < 0)
    return QUIC_RECEIVE_ERROR_PN_DECODE;

  /* Decode full packet number */
  uint64_t full_pn
      = SocketQUICPacket_decode_pn (truncated_pn, pn_length, largest_pn);

  /* Extract key phase from unprotected first byte */
  int received_phase = SocketQUICCrypto_get_key_phase (packet[0]);
  result->key_phase = received_phase;

  /* Select appropriate keys based on key phase and packet number */
  cr = SocketQUICKeyUpdate_get_read_keys (ku, received_phase, full_pn, &keys);
  if (cr != QUIC_CRYPTO_OK)
    {
      SocketQUICKeyUpdate_on_decrypt_failure (ku);
      ctx->decryption_failures++;
      return QUIC_RECEIVE_ERROR_KEY_PHASE;
    }

  /* Calculate header and payload bounds */
  if (pn_offset > SIZE_MAX - pn_length)
    return QUIC_RECEIVE_ERROR_TRUNCATED;
  size_t header_len = pn_offset + pn_length;
  if (packet_len < QUIC_AEAD_TAG_LEN)
    return QUIC_RECEIVE_ERROR_TRUNCATED;
  if (header_len > packet_len - QUIC_AEAD_TAG_LEN)
    return QUIC_RECEIVE_ERROR_TRUNCATED;

  size_t ciphertext_len = packet_len - header_len;

  /* Decrypt payload */
  size_t plaintext_len = ciphertext_len;
  cr = SocketQUICCrypto_decrypt_payload (keys,
                                         full_pn,
                                         packet,
                                         header_len,
                                         packet + header_len,
                                         ciphertext_len,
                                         packet + header_len,
                                         &plaintext_len);
  if (cr != QUIC_CRYPTO_OK)
    {
      SocketQUICKeyUpdate_on_decrypt_failure (ku);
      ctx->decryption_failures++;
      if (cr == QUIC_CRYPTO_ERROR_TAG)
        return QUIC_RECEIVE_ERROR_DECRYPT;
      return QUIC_RECEIVE_ERROR_UNPROTECT;
    }

  /* Successful decryption - track metrics */
  SocketQUICKeyUpdate_on_decrypt (ku);

  /* Process key update if key phase changed */
  if (received_phase != ku->key_phase)
    {
      cr = SocketQUICKeyUpdate_process_received (ku, received_phase);
      if (cr != QUIC_CRYPTO_OK)
        {
          /* Key update processing failed, but decryption succeeded */
          /* This shouldn't happen in normal operation */
        }
    }

  result->packet_number = full_pn;
  result->payload = packet + header_len;
  result->payload_len = plaintext_len;

  return QUIC_RECEIVE_OK;
}

/**
 * @brief Update largest PN after successful decryption.
 *
 * RFC 9001 §5.5: Only update largest_pn on successful decryption.
 *
 * @param ctx   Receive context.
 * @param space Packet number space.
 * @param pn    Successfully decrypted packet number.
 */
static void
update_largest_pn (SocketQUICReceive_T *ctx,
                   SocketQUIC_PNSpace space,
                   uint64_t pn)
{
  if (!ctx->spaces[space].has_received || pn > ctx->spaces[space].largest_pn)
    {
      ctx->spaces[space].largest_pn = pn;
      ctx->spaces[space].has_received = 1;
    }
}

/* ============================================================================
 * Main Receive Pipeline
 * ============================================================================
 */

SocketQUICReceive_Result
SocketQUICReceive_packet (SocketQUICReceive_T *ctx,
                          uint8_t *packet,
                          size_t packet_len,
                          uint8_t dcid_len,
                          int is_server,
                          SocketQUICReceiveResult_T *result)
{
  SocketQUICPacket_Type type;
  SocketQUIC_PNSpace space;
  size_t pn_offset;
  SocketQUICReceive_Result r;

  /* Validate inputs */
  if (ctx == NULL || packet == NULL || result == NULL)
    return QUIC_RECEIVE_ERROR_NULL;

  if (!ctx->initialized)
    return QUIC_RECEIVE_ERROR_NULL;

  if (packet_len < 1)
    return QUIC_RECEIVE_ERROR_TRUNCATED;

  memset (result, 0, sizeof (*result));

  /* Parse header based on header form bit */
  if (packet[0] & QUIC_HEADER_FORM_BIT)
    {
      size_t actual_len = 0;
      r = parse_long_header (
          packet, packet_len, &type, result, &pn_offset, &actual_len);
      if (r != QUIC_RECEIVE_OK)
        return r;
      /* Use the Length-field-derived packet boundary for long headers
       * so coalesced packets don't corrupt AEAD decryption. */
      if (actual_len > 0 && actual_len <= packet_len)
        packet_len = actual_len;
    }
  else
    {
      type = QUIC_PACKET_TYPE_1RTT;
      r = parse_short_header (packet, packet_len, dcid_len, result, &pn_offset);
      if (r != QUIC_RECEIVE_OK)
        return r;
    }

  /* Map packet type to PN space */
  int space_int = packet_type_to_pn_space (type);
  if (space_int < 0)
    return QUIC_RECEIVE_ERROR_HEADER;
  space = (SocketQUIC_PNSpace)space_int;

  result->type = type;
  result->pn_space = space;

  /* Get largest PN for this space (0 if none received yet) */
  uint64_t largest_pn = 0;
  if (ctx->spaces[space].has_received)
    largest_pn = ctx->spaces[space].largest_pn;

  /* Process based on packet type */
  switch (type)
    {
    case QUIC_PACKET_TYPE_INITIAL:
      r = receive_initial_packet (
          ctx, packet, packet_len, pn_offset, is_server, largest_pn, result);
      if (r != QUIC_RECEIVE_OK)
        return r;
      break;

    case QUIC_PACKET_TYPE_HANDSHAKE:
      if (ctx->handshake_keys == NULL)
        return QUIC_RECEIVE_ERROR_NO_KEYS;
      r = receive_protected_packet (ctx->handshake_keys,
                                    packet,
                                    packet_len,
                                    pn_offset,
                                    largest_pn,
                                    result,
                                    &ctx->decryption_failures);
      if (r != QUIC_RECEIVE_OK)
        return r;
      break;

    case QUIC_PACKET_TYPE_0RTT:
      if (ctx->zero_rtt_keys == NULL)
        return QUIC_RECEIVE_ERROR_NO_KEYS;
      r = receive_protected_packet (ctx->zero_rtt_keys,
                                    packet,
                                    packet_len,
                                    pn_offset,
                                    largest_pn,
                                    result,
                                    &ctx->decryption_failures);
      if (r != QUIC_RECEIVE_OK)
        return r;
      break;

    case QUIC_PACKET_TYPE_1RTT:
      if (ctx->key_update == NULL || !ctx->key_update->initialized)
        return QUIC_RECEIVE_ERROR_NO_KEYS;
      r = receive_1rtt_packet (
          ctx, packet, packet_len, pn_offset, largest_pn, result);
      if (r != QUIC_RECEIVE_OK)
        return r;
      break;

    default:
      return QUIC_RECEIVE_ERROR_HEADER;
    }

  /* Record bytes consumed for coalesced packet support (RFC 9000 §12.2) */
  result->consumed = packet_len;

  /* Update largest PN on successful decryption (RFC 9001 §5.5) */
  update_largest_pn (ctx, space, result->packet_number);

  return QUIC_RECEIVE_OK;
}
