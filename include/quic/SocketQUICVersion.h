/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICVersion.h
 * @brief QUIC Version Constants and Validation (RFC 9000 Section 15).
 *
 * QUIC versions are identified using 32-bit unsigned integers. This module
 * provides version constants, validation macros, and helper functions.
 *
 * Version Ranges:
 *   - 0x00000000:     Reserved for version negotiation (not a real version)
 *   - 0x00000001:     QUIC version 1 (RFC 9000)
 *   - 0x?a?a?a?a:     GREASE versions for forcing negotiation
 *   - 0x0000????:     Reserved for IETF (top 16 bits cleared)
 *
 * Thread Safety: All functions and macros are thread-safe (pure computation).
 *
 * @defgroup quic_version QUIC Version Module
 * @{
 * @see https://www.rfc-editor.org/rfc/rfc9000#section-15
 */

#ifndef SOCKETQUICVERSION_INCLUDED
#define SOCKETQUICVERSION_INCLUDED

#include <stddef.h>
#include <stdint.h>

/* ============================================================================
 * Version Constants (RFC 9000 Section 15)
 * ============================================================================
 */

/**
 * @brief QUIC protocol version identifiers.
 *
 * Version numbers are 32-bit unsigned integers. Only version 1 is defined
 * in RFC 9000. Version 0 is reserved for version negotiation packets.
 */
typedef enum
{
  /**
   * Version negotiation marker. Not a real protocol version.
   * Used in Version Negotiation packets (Section 6).
   */
  QUIC_VERSION_NEGOTIATION = 0x00000000,

  /**
   * QUIC version 1 (RFC 9000).
   * Uses TLS 1.3 for cryptographic handshake.
   */
  QUIC_VERSION_1 = 0x00000001,

  /**
   * QUIC version 2 (RFC 9369).
   * Same as version 1 but with different keys/salts.
   */
  QUIC_VERSION_2 = 0x6b3343cf

} SocketQUIC_Version;

/* ============================================================================
 * GREASE Version Detection (RFC 9000 Section 15)
 * ============================================================================
 */

/**
 * @brief Check if a version is a GREASE version.
 *
 * GREASE versions follow the pattern 0x?a?a?a?a where the low 4 bits of
 * each byte are 1010 (binary). These versions are reserved for forcing
 * version negotiation to be exercised.
 *
 * @param v Version to check (uint32_t).
 * @return Non-zero if v is a GREASE version, zero otherwise.
 *
 * Example GREASE versions: 0x0a0a0a0a, 0x1a1a1a1a, 0xfafafafa
 */
#define QUIC_VERSION_IS_GREASE(v) (((v) & 0x0f0f0f0f) == 0x0a0a0a0a)

/**
 * @brief Generate a GREASE version from a seed nibble.
 *
 * Creates a valid GREASE version by setting the pattern 0x?a?a?a?a
 * where ? is the provided nibble value (0-15).
 *
 * @param nibble Value 0-15 for the high nibble of each byte.
 * @return A valid GREASE version number.
 */
#define QUIC_VERSION_GREASE(nibble)                                            \
  ((((uint32_t)(nibble) & 0x0f) << 28) | 0x0a0a0a0a                            \
   | (((uint32_t)(nibble) & 0x0f) << 20) | (((uint32_t)(nibble) & 0x0f) << 12) \
   | (((uint32_t)(nibble) & 0x0f) << 4))

/* ============================================================================
 * IETF Reserved Version Detection (RFC 9000 Section 15)
 * ============================================================================
 */

/**
 * @brief Check if a version is in the IETF reserved range.
 *
 * Versions with the most significant 16 bits cleared are reserved for
 * use in future IETF consensus documents.
 *
 * @param v Version to check (uint32_t).
 * @return Non-zero if v is IETF reserved (0x0000????), zero otherwise.
 */
#define QUIC_VERSION_IS_IETF_RESERVED(v) (((v) & 0xFFFF0000) == 0)

/* ============================================================================
 * Version Support Checking
 * ============================================================================
 */

/**
 * @brief Check if a version is supported by this implementation.
 *
 * Currently supports QUIC version 1 (RFC 9000) and version 2 (RFC 9369).
 *
 * @param v Version to check (uint32_t).
 * @return Non-zero if version is supported, zero otherwise.
 */
#define QUIC_VERSION_IS_SUPPORTED(v) \
  ((v) == QUIC_VERSION_1 || (v) == QUIC_VERSION_2)

/**
 * @brief Check if a version represents a real protocol version.
 *
 * Returns false for the version negotiation marker (0x00000000) and
 * GREASE versions (0x?a?a?a?a), which should never be used for actual
 * QUIC connections.
 *
 * @param v Version to check (uint32_t).
 * @return Non-zero if v is a real protocol version, zero otherwise.
 */
#define QUIC_VERSION_IS_REAL(v) \
  ((v) != QUIC_VERSION_NEGOTIATION && !QUIC_VERSION_IS_GREASE (v))

/* ============================================================================
 * Version Validation Functions
 * ============================================================================
 */

/**
 * @brief Validate a version for use in a connection.
 *
 * Checks that the version is a valid, supported QUIC version.
 * Returns 1 for versions we can use to establish a connection.
 *
 * @param version Version to validate.
 * @return 1 if valid for connection, 0 otherwise.
 */
static inline int
SocketQUIC_version_is_valid (uint32_t version)
{
  /* Version negotiation marker is not valid for connections */
  if (version == QUIC_VERSION_NEGOTIATION)
    return 0;

  /* GREASE versions are not valid for connections */
  if (QUIC_VERSION_IS_GREASE (version))
    return 0;

  /* Check if we support this version */
  return QUIC_VERSION_IS_SUPPORTED (version);
}

/**
 * @brief Check if a version should trigger version negotiation.
 *
 * A server should send Version Negotiation if it receives an unsupported
 * version, unless it's a GREASE version (which should be ignored for
 * version negotiation purposes in some cases).
 *
 * @param version Version from client Initial packet.
 * @return 1 if version negotiation should be initiated, 0 otherwise.
 */
static inline int
SocketQUIC_version_needs_negotiation (uint32_t version)
{
  /* Version 0 means client is already doing version negotiation */
  if (version == QUIC_VERSION_NEGOTIATION)
    return 0;

  /* Supported versions don't need negotiation */
  if (QUIC_VERSION_IS_SUPPORTED (version))
    return 0;

  return 1;
}

/* ============================================================================
 * Version String Conversion
 * ============================================================================
 */

/**
 * @brief Get human-readable string for a QUIC version.
 *
 * Returns a descriptive string for known versions, or a hex representation
 * for unknown versions.
 *
 * @param version Version to convert.
 * @return Static string describing the version. Never returns NULL.
 *
 * @note For unknown versions, uses a thread-local buffer. Concurrent calls
 *       with different unknown versions may overwrite the buffer.
 */
static inline const char *
SocketQUIC_version_string (uint32_t version)
{
  switch (version)
    {
    case QUIC_VERSION_NEGOTIATION:
      return "VERSION_NEGOTIATION";
    case QUIC_VERSION_1:
      return "QUICv1 (RFC 9000)";
    case QUIC_VERSION_2:
      return "QUICv2 (RFC 9369)";
    default:
      if (QUIC_VERSION_IS_GREASE (version))
        return "GREASE";
      return "UNKNOWN";
    }
}

/**
 * @brief Get the list of supported versions.
 *
 * Returns a pointer to an array of supported version numbers.
 * Useful for building Version Negotiation packets.
 *
 * @param count Output: number of versions in the returned array.
 * @return Pointer to array of supported versions.
 */
static inline const uint32_t *
SocketQUIC_supported_versions (size_t *count)
{
  static const uint32_t versions[] = { QUIC_VERSION_1, QUIC_VERSION_2 };

  if (count)
    *count = sizeof (versions) / sizeof (versions[0]);

  return versions;
}

/* ============================================================================
 * Version Negotiation Packet (RFC 9000 Section 6)
 * ============================================================================
 */

/* Forward declarations for ConnectionID type */
struct SocketQUICConnectionID;
typedef struct SocketQUICConnectionID SocketQUICConnectionID_T;

/**
 * @brief Result codes for Version Negotiation operations.
 */
typedef enum
{
  QUIC_VERSION_NEG_OK = 0,       /**< Operation succeeded */
  QUIC_VERSION_NEG_ERROR_NULL,   /**< NULL pointer argument */
  QUIC_VERSION_NEG_ERROR_BUFFER, /**< Output buffer too small */
  QUIC_VERSION_NEG_ERROR_LENGTH, /**< Invalid length or count */
  QUIC_VERSION_NEG_ERROR_PARSE   /**< Parse error */
} SocketQUICVersion_NegResult;

/**
 * @brief Create a Version Negotiation packet.
 *
 * Generates a Version Negotiation packet containing the list of versions
 * supported by the server. This packet is sent in response to an Initial
 * packet with an unsupported version.
 *
 * Packet format (RFC 9000 Section 17.2.1):
 *   - First byte: 0x80 | random bits (long header, no fixed bit)
 *   - Version: 0x00000000 (4 bytes)
 *   - DCID Length: 1 byte
 *   - DCID: dcid->len bytes (from client's SCID)
 *   - SCID Length: 1 byte
 *   - SCID: scid->len bytes (from client's DCID)
 *   - Supported Versions: count * 4 bytes
 *
 * @param dcid        Destination CID (copied from client's source CID).
 * @param scid        Source CID (copied from client's destination CID).
 * @param versions    Array of supported version numbers.
 * @param count       Number of versions in array.
 * @param output      Output buffer for the packet.
 * @param output_size Size of output buffer.
 *
 * @return Number of bytes written, or negative error code.
 *
 * @note The first byte will have random bits in positions 0-5 for greasing.
 * @note Version Negotiation packets are NOT cryptographically protected.
 */
extern int
SocketQUICVersion_create_negotiation (const SocketQUICConnectionID_T *dcid,
                                      const SocketQUICConnectionID_T *scid,
                                      const uint32_t *versions,
                                      size_t count,
                                      uint8_t *output,
                                      size_t output_size);

/**
 * @brief Parse a Version Negotiation packet.
 *
 * Extracts the list of supported versions from a Version Negotiation packet.
 * The caller must first verify this is a Version Negotiation packet by
 * checking that the version field is 0x00000000.
 *
 * @param data         Input packet data (starting at first byte).
 * @param len          Length of input data.
 * @param dcid         Output: Destination Connection ID from packet.
 * @param scid         Output: Source Connection ID from packet.
 * @param versions_out Output buffer for version numbers.
 * @param max_versions Maximum number of versions to store.
 * @param count_out    Output: number of versions extracted.
 *
 * @return QUIC_VERSION_NEG_OK on success, error code otherwise.
 *
 * @note Connection IDs in Version Negotiation are copied from the triggering
 *       Initial packet (swapped: DCID <- client SCID, SCID <- client DCID).
 * @note Client MUST verify the CIDs match before accepting the packet.
 */
extern SocketQUICVersion_NegResult
SocketQUICVersion_parse_negotiation (const uint8_t *data,
                                     size_t len,
                                     SocketQUICConnectionID_T *dcid,
                                     SocketQUICConnectionID_T *scid,
                                     uint32_t *versions_out,
                                     size_t max_versions,
                                     size_t *count_out);

/** @} */

#endif /* SOCKETQUICVERSION_INCLUDED */
