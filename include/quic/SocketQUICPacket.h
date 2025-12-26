/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICPacket.h
 * @brief QUIC Packet Header Parsing and Serialization (RFC 9000 Section 17).
 *
 * Implements parsing and serialization for QUIC packet headers:
 *
 * Long Header Format (Section 17.2):
 *   - Used for Initial, 0-RTT, Handshake, and Retry packets
 *   - Contains Version, DCID, SCID, and type-specific fields
 *   - First byte: 1 (Form) | 1 (Fixed) | 2 (Type) | 4 (Type-Specific)
 *
 * Short Header Format (Section 17.3):
 *   - Used for 1-RTT (post-handshake) packets
 *   - Minimal header with just DCID and packet number
 *   - First byte: 0 (Form) | 1 (Fixed) | 1 (Spin) | 2 (Reserved) | 1 (Key Phase) | 2 (PN Len)
 *
 * Thread Safety: Parsing/serialization functions are thread-safe (no shared state).
 * Individual packet header structures should not be shared across threads.
 *
 * @defgroup quic_packet QUIC Packet Format Module
 * @{
 * @see https://www.rfc-editor.org/rfc/rfc9000#section-17
 */

#ifndef SOCKETQUICPACKET_INCLUDED
#define SOCKETQUICPACKET_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include "quic/SocketQUICConnectionID.h"
#include "quic/SocketQUICVersion.h"

/* ============================================================================
 * Constants (RFC 9000 Section 17)
 * ============================================================================
 */

/**
 * @brief Maximum packet header size (worst case: long header with max CIDs).
 *
 * Long header: 1 (flags) + 4 (version) + 1 (DCID len) + 20 (DCID) +
 *              1 (SCID len) + 20 (SCID) + 8 (token len) + 8 (length) + 4 (PN)
 */
#define QUIC_PACKET_HEADER_MAX_SIZE 67

/**
 * @brief Minimum long header size (zero-length CIDs, minimal fields).
 *
 * 1 (flags) + 4 (version) + 1 (DCID len) + 1 (SCID len)
 */
#define QUIC_PACKET_LONG_HEADER_MIN_SIZE 7

/**
 * @brief Minimum short header size (with 1-byte packet number).
 *
 * 1 (flags) + 0 (min DCID) + 1 (PN)
 */
#define QUIC_PACKET_SHORT_HEADER_MIN_SIZE 2

/**
 * @brief Maximum packet number length in bytes (1-4).
 */
#define QUIC_PACKET_NUMBER_MAX_LEN 4

/**
 * @brief Minimum packet number length in bytes.
 */
#define QUIC_PACKET_NUMBER_MIN_LEN 1

/**
 * @brief Maximum Initial packet token length.
 *
 * RFC 9000 does not specify a maximum, but we use a reasonable limit.
 */
#define QUIC_PACKET_TOKEN_MAX_LEN 1024

/* ============================================================================
 * First Byte Bit Masks (RFC 9000 Section 17.2, 17.3)
 * ============================================================================
 */

/**
 * @brief Header form bit (bit 7): 1 = Long Header, 0 = Short Header.
 */
#define QUIC_PACKET_FORM_BIT 0x80

/**
 * @brief Fixed bit (bit 6): Must be 1 in all QUIC packets.
 */
#define QUIC_PACKET_FIXED_BIT 0x40

/**
 * @brief Long header type mask (bits 4-5).
 */
#define QUIC_PACKET_LONG_TYPE_MASK 0x30

/**
 * @brief Long header type shift amount.
 */
#define QUIC_PACKET_LONG_TYPE_SHIFT 4

/**
 * @brief Long header reserved bits mask (bits 2-3).
 */
#define QUIC_PACKET_LONG_RESERVED_MASK 0x0C

/**
 * @brief Long header packet number length mask (bits 0-1).
 */
#define QUIC_PACKET_LONG_PNLEN_MASK 0x03

/**
 * @brief Short header spin bit (bit 5).
 */
#define QUIC_PACKET_SHORT_SPIN_BIT 0x20

/**
 * @brief Short header reserved bits mask (bits 3-4).
 */
#define QUIC_PACKET_SHORT_RESERVED_MASK 0x18

/**
 * @brief Short header key phase bit (bit 2).
 */
#define QUIC_PACKET_SHORT_KEY_PHASE_BIT 0x04

/**
 * @brief Short header packet number length mask (bits 0-1).
 */
#define QUIC_PACKET_SHORT_PNLEN_MASK 0x03

/* ============================================================================
 * Packet Types (RFC 9000 Section 17.2)
 * ============================================================================
 */

/**
 * @brief QUIC packet types.
 */
typedef enum
{
  /**
   * Initial packet (Section 17.2.2).
   * First packet sent by client, contains CRYPTO frames for handshake.
   * May contain Token from Retry or NEW_TOKEN frame.
   */
  QUIC_PACKET_TYPE_INITIAL = 0x00,

  /**
   * 0-RTT packet (Section 17.2.3).
   * Contains early data sent before handshake completes.
   * Only sent by client.
   */
  QUIC_PACKET_TYPE_0RTT = 0x01,

  /**
   * Handshake packet (Section 17.2.4).
   * Contains CRYPTO frames for TLS handshake.
   * Sent by both client and server.
   */
  QUIC_PACKET_TYPE_HANDSHAKE = 0x02,

  /**
   * Retry packet (Section 17.2.5).
   * Sent by server to provide address validation token.
   * Does not contain protected payload.
   */
  QUIC_PACKET_TYPE_RETRY = 0x03,

  /**
   * 1-RTT (Short Header) packet.
   * Used after handshake completes. Not in long header type field.
   */
  QUIC_PACKET_TYPE_1RTT = 0x04

} SocketQUICPacket_Type;

/* ============================================================================
 * Result Codes
 * ============================================================================
 */

/**
 * @brief Result codes for packet header operations.
 */
typedef enum
{
  QUIC_PACKET_OK = 0,              /**< Operation succeeded */
  QUIC_PACKET_ERROR_NULL,          /**< NULL pointer argument */
  QUIC_PACKET_ERROR_TRUNCATED,     /**< Insufficient input data */
  QUIC_PACKET_ERROR_BUFFER,        /**< Output buffer too small */
  QUIC_PACKET_ERROR_INVALID,       /**< Invalid packet format */
  QUIC_PACKET_ERROR_FIXED_BIT,     /**< Fixed bit not set (not QUIC) */
  QUIC_PACKET_ERROR_VERSION,       /**< Invalid/unsupported version */
  QUIC_PACKET_ERROR_CONNID,        /**< Invalid Connection ID */
  QUIC_PACKET_ERROR_TOKEN,         /**< Token too long */
  QUIC_PACKET_ERROR_PNLEN          /**< Invalid packet number length */
} SocketQUICPacket_Result;

/* ============================================================================
 * Data Structures
 * ============================================================================
 */

/**
 * @brief QUIC packet header (unified structure for all types).
 *
 * This structure can represent any QUIC packet header type.
 * Use `is_long_header` to determine the header format.
 */
typedef struct SocketQUICPacketHeader
{
  /* Common fields */
  int is_long_header;             /**< 1 = Long Header, 0 = Short Header */
  SocketQUICPacket_Type type;     /**< Packet type */
  uint8_t first_byte;             /**< Raw first byte (for reserved bits) */

  /* Long header fields (Section 17.2) */
  uint32_t version;               /**< QUIC version (0 for Version Negotiation) */
  SocketQUICConnectionID_T dcid;  /**< Destination Connection ID */
  SocketQUICConnectionID_T scid;  /**< Source Connection ID */

  /* Initial packet fields (Section 17.2.2) */
  const uint8_t *token;           /**< Token (Initial only, may be NULL) */
  uint64_t token_length;          /**< Token length */

  /* Retry packet fields (Section 17.2.5) */
  const uint8_t *retry_token;     /**< Retry Token (Retry only) */
  size_t retry_token_length;      /**< Retry Token length */
  uint8_t retry_integrity_tag[16]; /**< 16-byte Retry Integrity Tag */
  int has_retry_integrity_tag;    /**< 1 if integrity tag is present */

  /* Protected packet fields */
  uint64_t length;                /**< Payload Length (varint encoded) */
  uint8_t pn_length;              /**< Packet Number length (1-4 bytes) */
  uint32_t packet_number;         /**< Truncated Packet Number */

  /* Short header fields (Section 17.3) */
  int spin_bit;                   /**< Latency Spin Bit (1-RTT only) */
  int key_phase;                  /**< Key Phase bit (1-RTT only) */
  uint8_t dcid_length;            /**< Known DCID length for short header */

  /* Parsing state */
  size_t header_length;           /**< Total parsed header length in bytes */

} SocketQUICPacketHeader_T;

/* ============================================================================
 * Parsing Functions
 * ============================================================================
 */

/**
 * @brief Determine if a packet has a long or short header.
 *
 * Checks the header form bit (bit 7) of the first byte.
 *
 * @param first_byte First byte of the packet.
 *
 * @return 1 if long header, 0 if short header.
 */
static inline int
SocketQUICPacket_is_long_header (uint8_t first_byte)
{
  return (first_byte & QUIC_PACKET_FORM_BIT) != 0;
}

/**
 * @brief Check if the fixed bit is set (validates QUIC packet).
 *
 * @param first_byte First byte of the packet.
 *
 * @return 1 if fixed bit is set, 0 otherwise.
 */
static inline int
SocketQUICPacket_has_fixed_bit (uint8_t first_byte)
{
  return (first_byte & QUIC_PACKET_FIXED_BIT) != 0;
}

/**
 * @brief Initialize a packet header structure.
 *
 * Zeros all fields. Call this before parsing or building a header.
 *
 * @param header Packet header structure to initialize.
 */
extern void SocketQUICPacketHeader_init (SocketQUICPacketHeader_T *header);

/**
 * @brief Parse a QUIC packet header from wire format.
 *
 * Parses the unprotected header fields. For protected packets (Initial,
 * 0-RTT, Handshake, 1-RTT), the packet number is encrypted and must be
 * decrypted separately after header protection removal.
 *
 * For short headers, the caller must provide the expected DCID length
 * via header->dcid_length before calling this function.
 *
 * @param data        Input buffer containing packet.
 * @param len         Size of input buffer.
 * @param header      Output: parsed header structure.
 * @param consumed    Output: number of bytes consumed.
 *
 * @return QUIC_PACKET_OK on success, error code otherwise.
 *
 * @note For Retry packets, the full packet must be present to parse
 *       the Retry Integrity Tag at the end.
 */
extern SocketQUICPacket_Result
SocketQUICPacketHeader_parse (const uint8_t *data, size_t len,
                              SocketQUICPacketHeader_T *header,
                              size_t *consumed);

/**
 * @brief Parse only the long header type from the first byte.
 *
 * Useful for quick packet type identification without full parsing.
 *
 * @param first_byte First byte of a long header packet.
 *
 * @return Packet type (INITIAL, 0RTT, HANDSHAKE, or RETRY).
 */
static inline SocketQUICPacket_Type
SocketQUICPacket_parse_long_type (uint8_t first_byte)
{
  return (SocketQUICPacket_Type)((first_byte & QUIC_PACKET_LONG_TYPE_MASK)
                                  >> QUIC_PACKET_LONG_TYPE_SHIFT);
}

/* ============================================================================
 * Serialization Functions
 * ============================================================================
 */

/**
 * @brief Calculate the serialized size of a packet header.
 *
 * Returns the number of bytes needed to serialize the header.
 * Does not include payload or packet number (which may vary).
 *
 * @param header Packet header to measure.
 *
 * @return Size in bytes, or 0 on error.
 */
extern size_t
SocketQUICPacketHeader_size (const SocketQUICPacketHeader_T *header);

/**
 * @brief Serialize a packet header to wire format.
 *
 * Writes the packet header to the output buffer. For protected packets,
 * the packet number field is written but should be encrypted later.
 *
 * @param header      Packet header to serialize.
 * @param output      Output buffer.
 * @param output_size Size of output buffer.
 *
 * @return Number of bytes written, or 0 on error.
 */
extern size_t
SocketQUICPacketHeader_serialize (const SocketQUICPacketHeader_T *header,
                                  uint8_t *output, size_t output_size);

/* ============================================================================
 * Builder Functions
 * ============================================================================
 */

/**
 * @brief Build an Initial packet header.
 *
 * @param header    Output header structure.
 * @param version   QUIC version.
 * @param dcid      Destination Connection ID.
 * @param scid      Source Connection ID.
 * @param token     Token from Retry or NEW_TOKEN (may be NULL).
 * @param token_len Token length.
 * @param pn_length Packet number length (1-4).
 * @param pn        Truncated packet number.
 *
 * @return QUIC_PACKET_OK on success, error code otherwise.
 */
extern SocketQUICPacket_Result
SocketQUICPacketHeader_build_initial (SocketQUICPacketHeader_T *header,
                                      uint32_t version,
                                      const SocketQUICConnectionID_T *dcid,
                                      const SocketQUICConnectionID_T *scid,
                                      const uint8_t *token, size_t token_len,
                                      uint8_t pn_length, uint32_t pn);

/**
 * @brief Build a Handshake packet header.
 *
 * @param header    Output header structure.
 * @param version   QUIC version.
 * @param dcid      Destination Connection ID.
 * @param scid      Source Connection ID.
 * @param pn_length Packet number length (1-4).
 * @param pn        Truncated packet number.
 *
 * @return QUIC_PACKET_OK on success, error code otherwise.
 */
extern SocketQUICPacket_Result
SocketQUICPacketHeader_build_handshake (SocketQUICPacketHeader_T *header,
                                        uint32_t version,
                                        const SocketQUICConnectionID_T *dcid,
                                        const SocketQUICConnectionID_T *scid,
                                        uint8_t pn_length, uint32_t pn);

/**
 * @brief Build a 0-RTT packet header.
 *
 * @param header    Output header structure.
 * @param version   QUIC version.
 * @param dcid      Destination Connection ID.
 * @param scid      Source Connection ID.
 * @param pn_length Packet number length (1-4).
 * @param pn        Truncated packet number.
 *
 * @return QUIC_PACKET_OK on success, error code otherwise.
 */
extern SocketQUICPacket_Result
SocketQUICPacketHeader_build_0rtt (SocketQUICPacketHeader_T *header,
                                   uint32_t version,
                                   const SocketQUICConnectionID_T *dcid,
                                   const SocketQUICConnectionID_T *scid,
                                   uint8_t pn_length, uint32_t pn);

/**
 * @brief Build a Short (1-RTT) packet header.
 *
 * @param header    Output header structure.
 * @param dcid      Destination Connection ID.
 * @param spin_bit  Latency spin bit value.
 * @param key_phase Key phase bit value.
 * @param pn_length Packet number length (1-4).
 * @param pn        Truncated packet number.
 *
 * @return QUIC_PACKET_OK on success, error code otherwise.
 */
extern SocketQUICPacket_Result
SocketQUICPacketHeader_build_short (SocketQUICPacketHeader_T *header,
                                    const SocketQUICConnectionID_T *dcid,
                                    int spin_bit, int key_phase,
                                    uint8_t pn_length, uint32_t pn);

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

/**
 * @brief Get string representation of packet type.
 *
 * @param type Packet type.
 *
 * @return Static string describing the packet type.
 */
extern const char *SocketQUICPacket_type_string (SocketQUICPacket_Type type);

/**
 * @brief Get string representation of result code.
 *
 * @param result Result code.
 *
 * @return Static string describing the result.
 */
extern const char *
SocketQUICPacket_result_string (SocketQUICPacket_Result result);

/**
 * @brief Calculate required packet number length.
 *
 * Determines the minimum number of bytes needed to encode the
 * packet number with sufficient range for acknowledgment.
 *
 * @param pn          Packet number to encode.
 * @param largest_ack Largest acknowledged packet number.
 *
 * @return 1, 2, 3, or 4 bytes.
 */
extern uint8_t SocketQUICPacket_pn_length (uint64_t pn, uint64_t largest_ack);

/**
 * @brief Encode a packet number (truncation).
 *
 * Truncates the packet number to the specified length.
 *
 * @param pn        Full packet number.
 * @param pn_length Number of bytes to use (1-4).
 *
 * @return Truncated packet number.
 */
extern uint32_t SocketQUICPacket_encode_pn (uint64_t pn, uint8_t pn_length);

/**
 * @brief Decode a truncated packet number.
 *
 * Reconstructs the full packet number from the truncated value
 * and the largest acknowledged packet number.
 *
 * @param truncated_pn Truncated packet number from header.
 * @param pn_length    Length of truncated PN (1-4 bytes).
 * @param largest_pn   Largest packet number seen so far.
 *
 * @return Reconstructed full packet number.
 */
extern uint64_t SocketQUICPacket_decode_pn (uint32_t truncated_pn,
                                            uint8_t pn_length,
                                            uint64_t largest_pn);

/* ============================================================================
 * Initial Packet Constants (RFC 9000 Section 17.2.2, RFC 9001)
 * ============================================================================
 */

/**
 * @brief Minimum size for client Initial packets (RFC 9000 Section 14.1).
 *
 * Client Initial packets MUST be padded to at least 1200 bytes to prevent
 * amplification attacks and ensure path MTU discovery.
 */
#define QUIC_INITIAL_MIN_SIZE 1200

/**
 * @brief Initial salt for QUIC v1 key derivation (RFC 9001 Section 5.2).
 *
 * This 20-byte salt is used with HKDF-Extract to derive the Initial secret.
 */
#define QUIC_V1_INITIAL_SALT_LEN 20

/**
 * @brief AES-128-GCM key length for Initial packet protection.
 */
#define QUIC_INITIAL_KEY_LEN 16

/**
 * @brief AES-128-GCM IV length for Initial packet protection.
 */
#define QUIC_INITIAL_IV_LEN 12

/**
 * @brief Header protection key length.
 */
#define QUIC_INITIAL_HP_KEY_LEN 16

/**
 * @brief AEAD authentication tag length (AES-128-GCM).
 */
#define QUIC_INITIAL_TAG_LEN 16

/**
 * @brief Header protection sample length (RFC 9001 Section 5.4.3).
 */
#define QUIC_HP_SAMPLE_LEN 16

/* ============================================================================
 * Initial Packet Key Structure (RFC 9001 Section 5)
 * ============================================================================
 */

/**
 * @brief Keys for Initial packet encryption/decryption.
 *
 * Contains derived keys for both client and server sides.
 * Keys are derived from the client's Destination Connection ID using
 * HKDF-Extract and HKDF-Expand-Label (RFC 9001 Section 5.2).
 */
typedef struct SocketQUICInitialKeys
{
  /* Client secrets and keys */
  uint8_t client_key[QUIC_INITIAL_KEY_LEN];     /**< Client AEAD key */
  uint8_t client_iv[QUIC_INITIAL_IV_LEN];       /**< Client AEAD IV */
  uint8_t client_hp_key[QUIC_INITIAL_HP_KEY_LEN]; /**< Client header protection key */

  /* Server secrets and keys */
  uint8_t server_key[QUIC_INITIAL_KEY_LEN];     /**< Server AEAD key */
  uint8_t server_iv[QUIC_INITIAL_IV_LEN];       /**< Server AEAD IV */
  uint8_t server_hp_key[QUIC_INITIAL_HP_KEY_LEN]; /**< Server header protection key */

  int is_client;    /**< 1 if keys for client, 0 for server */
  int initialized;  /**< 1 if keys have been derived */

} SocketQUICInitialKeys_T;

/* ============================================================================
 * Initial Packet Result Codes
 * ============================================================================
 */

/**
 * @brief Result codes for Initial packet operations.
 */
typedef enum
{
  QUIC_INITIAL_OK = 0,              /**< Operation succeeded */
  QUIC_INITIAL_ERROR_NULL,          /**< NULL pointer argument */
  QUIC_INITIAL_ERROR_CRYPTO,        /**< Cryptographic operation failed */
  QUIC_INITIAL_ERROR_BUFFER,        /**< Buffer too small */
  QUIC_INITIAL_ERROR_TRUNCATED,     /**< Packet too short */
  QUIC_INITIAL_ERROR_INVALID,       /**< Invalid packet format */
  QUIC_INITIAL_ERROR_AUTH,          /**< AEAD authentication failed */
  QUIC_INITIAL_ERROR_SIZE,          /**< Packet size below minimum */
  QUIC_INITIAL_ERROR_TOKEN,         /**< Server Initial has non-zero token */
  QUIC_INITIAL_ERROR_VERSION        /**< Unsupported QUIC version */
} SocketQUICInitial_Result;

/* ============================================================================
 * Initial Key Derivation (RFC 9001 Section 5.2)
 * ============================================================================
 */

/**
 * @brief Initialize Initial keys structure.
 *
 * Zeros all key material. Call before deriving keys.
 *
 * @param keys Keys structure to initialize.
 */
extern void SocketQUICInitialKeys_init (SocketQUICInitialKeys_T *keys);

/**
 * @brief Securely clear Initial keys from memory.
 *
 * Uses secure memory clearing to prevent key material from
 * remaining in memory after use.
 *
 * @param keys Keys structure to clear.
 */
extern void SocketQUICInitialKeys_clear (SocketQUICInitialKeys_T *keys);

/**
 * @brief Derive Initial packet keys from connection ID.
 *
 * Derives the Initial encryption keys per RFC 9001 Section 5.2.
 * The keys are derived from the client's Destination Connection ID
 * using HKDF-Extract with a version-specific salt.
 *
 * @param dcid    Client's Destination Connection ID.
 * @param version QUIC version (must support Initial packet protection).
 * @param keys    Output: derived Initial keys.
 *
 * @return QUIC_INITIAL_OK on success, error code otherwise.
 *
 * @note Keys should be cleared with SocketQUICInitialKeys_clear() when done.
 */
extern SocketQUICInitial_Result
SocketQUICInitial_derive_keys (const SocketQUICConnectionID_T *dcid,
                               uint32_t version,
                               SocketQUICInitialKeys_T *keys);

/* ============================================================================
 * Initial Packet Protection (RFC 9001 Section 5.4)
 * ============================================================================
 */

/**
 * @brief Apply header and payload protection to Initial packet.
 *
 * Performs AEAD encryption on the payload and applies header protection.
 * The packet must already have the complete header with unprotected
 * packet number.
 *
 * @param packet    Packet buffer (modified in-place).
 * @param packet_len Current packet length (input) and new length (output).
 * @param header_len Length of the packet header (up to and including PN).
 * @param keys      Derived Initial keys.
 * @param is_client 1 if sending as client, 0 if as server.
 *
 * @return QUIC_INITIAL_OK on success, error code otherwise.
 */
extern SocketQUICInitial_Result
SocketQUICInitial_protect (uint8_t *packet, size_t *packet_len,
                           size_t header_len,
                           const SocketQUICInitialKeys_T *keys,
                           int is_client);

/**
 * @brief Remove header and payload protection from Initial packet.
 *
 * Removes header protection to reveal the packet number, then
 * performs AEAD decryption on the payload.
 *
 * @param packet    Packet buffer (modified in-place).
 * @param packet_len Input packet length.
 * @param pn_offset Offset of the packet number in the header.
 * @param keys      Derived Initial keys.
 * @param is_client 1 if receiving as client, 0 if as server.
 * @param pn_length Output: revealed packet number length.
 *
 * @return QUIC_INITIAL_OK on success, error code otherwise.
 */
extern SocketQUICInitial_Result
SocketQUICInitial_unprotect (uint8_t *packet, size_t packet_len,
                             size_t pn_offset,
                             const SocketQUICInitialKeys_T *keys,
                             int is_client,
                             uint8_t *pn_length);

/* ============================================================================
 * Initial Packet Validation (RFC 9000 Section 17.2.2)
 * ============================================================================
 */

/**
 * @brief Validate Initial packet constraints.
 *
 * Checks RFC-mandated constraints:
 * - Client Initial must be at least 1200 bytes
 * - Server Initial must have zero-length token
 * - Token length must be within limits
 *
 * @param header    Parsed Initial packet header.
 * @param total_len Total packet length (including payload).
 * @param is_client 1 if packet is from client, 0 if from server.
 *
 * @return QUIC_INITIAL_OK if valid, error code otherwise.
 */
extern SocketQUICInitial_Result
SocketQUICInitial_validate (const SocketQUICPacketHeader_T *header,
                            size_t total_len, int is_client);

/**
 * @brief Calculate padding needed for client Initial packet.
 *
 * Returns the number of PADDING frame bytes needed to meet
 * the 1200-byte minimum requirement for client Initial packets.
 *
 * @param current_len Current packet length.
 *
 * @return Number of padding bytes needed (0 if already sufficient).
 */
extern size_t SocketQUICInitial_padding_needed (size_t current_len);

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

/**
 * @brief Get string representation of Initial result code.
 *
 * @param result Result code.
 *
 * @return Static string describing the result.
 */
extern const char *
SocketQUICInitial_result_string (SocketQUICInitial_Result result);

/**
 * @brief Get the Initial salt for a QUIC version.
 *
 * Returns the version-specific Initial salt used in key derivation.
 *
 * @param version QUIC version.
 * @param salt    Output: pointer to salt bytes.
 * @param salt_len Output: salt length.
 *
 * @return QUIC_INITIAL_OK if version is supported, error otherwise.
 */
extern SocketQUICInitial_Result
SocketQUICInitial_get_salt (uint32_t version, const uint8_t **salt,
                            size_t *salt_len);

/** @} */

#endif /* SOCKETQUICPACKET_INCLUDED */
