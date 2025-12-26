/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICVersion.c
 * @brief Implementation of QUIC Version Negotiation (RFC 9000 Section 6).
 *
 * Implements creation and parsing of Version Negotiation packets.
 * These packets are sent by servers when they receive an Initial packet
 * with an unsupported version number.
 */

#include "quic/SocketQUICVersion.h"
#include "quic/SocketQUICConnectionID.h"

#include <string.h>

/* ============================================================================
 * Version Negotiation Packet Creation (RFC 9000 Section 17.2.1)
 * ============================================================================
 */

/**
 * @brief Create a Version Negotiation packet.
 *
 * Version Negotiation packet format:
 *   Byte 0:    0x80 | random_bits (Header Form=1, Fixed Bit=0)
 *   Bytes 1-4: 0x00000000 (Version field)
 *   Byte 5:    DCID Length
 *   Bytes 6+:  DCID bytes
 *   Next byte: SCID Length
 *   Next:      SCID bytes
 *   Remaining: Supported Version list (4 bytes each)
 */
int
SocketQUICVersion_create_negotiation (const SocketQUICConnectionID_T *dcid,
                                       const SocketQUICConnectionID_T *scid,
                                       const uint32_t *versions, size_t count,
                                       uint8_t *output, size_t output_size)
{
  /* Validate inputs */
  if (!dcid || !scid || !versions || !output)
    return -QUIC_VERSION_NEG_ERROR_NULL;

  if (count == 0)
    return -QUIC_VERSION_NEG_ERROR_LENGTH;

  /* Calculate required size */
  size_t required = 1           /* first byte */
                    + 4         /* version (0x00000000) */
                    + 1         /* DCID length */
                    + dcid->len /* DCID */
                    + 1         /* SCID length */
                    + scid->len /* SCID */
                    + (count * 4); /* version list */

  if (output_size < required)
    return -QUIC_VERSION_NEG_ERROR_BUFFER;

  size_t pos = 0;

  /* First byte: Long Header Form (0x80) with random lower bits */
  /* RFC 9000 Section 17.2.1: Fixed bit MUST NOT be set */
  /* For simplicity, we use 0x80 (no random bits for now) */
  output[pos++] = 0x80;

  /* Version field: 0x00000000 (network byte order = big endian) */
  output[pos++] = 0x00;
  output[pos++] = 0x00;
  output[pos++] = 0x00;
  output[pos++] = 0x00;

  /* DCID Length and DCID */
  output[pos++] = dcid->len;
  if (dcid->len > 0)
    {
      memcpy (&output[pos], dcid->data, dcid->len);
      pos += dcid->len;
    }

  /* SCID Length and SCID */
  output[pos++] = scid->len;
  if (scid->len > 0)
    {
      memcpy (&output[pos], scid->data, scid->len);
      pos += scid->len;
    }

  /* Supported Versions (4 bytes each, network byte order) */
  for (size_t i = 0; i < count; i++)
    {
      uint32_t version = versions[i];
      output[pos++] = (version >> 24) & 0xFF;
      output[pos++] = (version >> 16) & 0xFF;
      output[pos++] = (version >> 8) & 0xFF;
      output[pos++] = version & 0xFF;
    }

  return (int)pos;
}

/* ============================================================================
 * Version Negotiation Packet Parsing
 * ============================================================================
 */

/**
 * @brief Parse a Version Negotiation packet.
 *
 * Extracts Connection IDs and the list of supported versions.
 */
SocketQUICVersion_NegResult
SocketQUICVersion_parse_negotiation (const uint8_t *data, size_t len,
                                      SocketQUICConnectionID_T *dcid,
                                      SocketQUICConnectionID_T *scid,
                                      uint32_t *versions_out,
                                      size_t max_versions, size_t *count_out)
{
  /* Validate inputs */
  if (!data || !dcid || !scid || !versions_out || !count_out)
    return QUIC_VERSION_NEG_ERROR_NULL;

  /* Minimum packet size: 1 (header) + 4 (version) + 1 (DCID len) + 1 (SCID
   * len) */
  if (len < 7)
    return QUIC_VERSION_NEG_ERROR_PARSE;

  size_t pos = 0;

  /* First byte: Should have long header form (0x80) */
  uint8_t first_byte = data[pos++];
  if ((first_byte & 0x80) == 0)
    return QUIC_VERSION_NEG_ERROR_PARSE;

  /* Version field: Must be 0x00000000 */
  uint32_t version = ((uint32_t)data[pos] << 24) | ((uint32_t)data[pos + 1] << 16)
                     | ((uint32_t)data[pos + 2] << 8) | data[pos + 3];
  pos += 4;

  if (version != QUIC_VERSION_NEGOTIATION)
    return QUIC_VERSION_NEG_ERROR_PARSE;

  /* DCID Length and DCID */
  if (pos >= len)
    return QUIC_VERSION_NEG_ERROR_PARSE;

  uint8_t dcid_len = data[pos++];
  if (dcid_len > QUIC_CONNID_MAX_LEN)
    return QUIC_VERSION_NEG_ERROR_LENGTH;

  if (pos + dcid_len > len)
    return QUIC_VERSION_NEG_ERROR_PARSE;

  SocketQUICConnectionID_init (dcid);
  if (dcid_len > 0)
    {
      memcpy (dcid->data, &data[pos], dcid_len);
      dcid->len = dcid_len;
      pos += dcid_len;
    }

  /* SCID Length and SCID */
  if (pos >= len)
    return QUIC_VERSION_NEG_ERROR_PARSE;

  uint8_t scid_len = data[pos++];
  if (scid_len > QUIC_CONNID_MAX_LEN)
    return QUIC_VERSION_NEG_ERROR_LENGTH;

  if (pos + scid_len > len)
    return QUIC_VERSION_NEG_ERROR_PARSE;

  SocketQUICConnectionID_init (scid);
  if (scid_len > 0)
    {
      memcpy (scid->data, &data[pos], scid_len);
      scid->len = scid_len;
      pos += scid_len;
    }

  /* Parse Supported Versions list */
  size_t remaining = len - pos;

  /* Remaining bytes must be a multiple of 4 (version size) */
  if (remaining % 4 != 0)
    return QUIC_VERSION_NEG_ERROR_PARSE;

  size_t version_count = remaining / 4;
  size_t versions_to_copy = version_count < max_versions ? version_count : max_versions;

  for (size_t i = 0; i < versions_to_copy; i++)
    {
      versions_out[i] = ((uint32_t)data[pos] << 24)
                        | ((uint32_t)data[pos + 1] << 16)
                        | ((uint32_t)data[pos + 2] << 8) | data[pos + 3];
      pos += 4;
    }

  *count_out = versions_to_copy;

  return QUIC_VERSION_NEG_OK;
}
