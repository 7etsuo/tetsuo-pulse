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
 *   - First byte: 0 (Form) | 1 (Fixed) | 1 (Spin) | 2 (Reserved) | 1 (Key
 * Phase) | 2 (PN Len)
 *
 * Thread Safety: Parsing/serialization functions are thread-safe (no shared
 * state). Individual packet header structures should not be shared across
 * threads.
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

/**
 * @brief Result codes for packet header operations.
 */
typedef enum
{
  QUIC_PACKET_OK = 0,          /**< Operation succeeded */
  QUIC_PACKET_ERROR_NULL,      /**< NULL pointer argument */
  QUIC_PACKET_ERROR_TRUNCATED, /**< Insufficient input data */
  QUIC_PACKET_ERROR_BUFFER,    /**< Output buffer too small */
  QUIC_PACKET_ERROR_INVALID,   /**< Invalid packet format */
  QUIC_PACKET_ERROR_FIXED_BIT, /**< Fixed bit not set (not QUIC) */
  QUIC_PACKET_ERROR_VERSION,   /**< Invalid/unsupported version */
  QUIC_PACKET_ERROR_CONNID,    /**< Invalid Connection ID */
  QUIC_PACKET_ERROR_TOKEN,     /**< Token too long */
  QUIC_PACKET_ERROR_PNLEN      /**< Invalid packet number length */
} SocketQUICPacket_Result;

/**
 * @brief QUIC packet header (unified structure for all types).
 *
 * This structure can represent any QUIC packet header type.
 * Use `is_long_header` to determine the header format.
 */
typedef struct SocketQUICPacketHeader
{
  /* Common fields */
  int is_long_header;         /**< 1 = Long Header, 0 = Short Header */
  SocketQUICPacket_Type type; /**< Packet type */
  uint8_t first_byte;         /**< Raw first byte (for reserved bits) */

  /* Long header fields (Section 17.2) */
  uint32_t version; /**< QUIC version (0 for Version Negotiation) */
  SocketQUICConnectionID_T dcid; /**< Destination Connection ID */
  SocketQUICConnectionID_T scid; /**< Source Connection ID */

  /* Initial packet fields (Section 17.2.2) */
  const uint8_t *token;  /**< Token (Initial only, may be NULL) */
  uint64_t token_length; /**< Token length */

  /* Retry packet fields (Section 17.2.5) */
  const uint8_t *retry_token;      /**< Retry Token (Retry only) */
  size_t retry_token_length;       /**< Retry Token length */
  uint8_t retry_integrity_tag[16]; /**< 16-byte Retry Integrity Tag */
  int has_retry_integrity_tag;     /**< 1 if integrity tag is present */

  /* Protected packet fields */
  uint64_t length;        /**< Payload Length (varint encoded) */
  uint8_t pn_length;      /**< Packet Number length (1-4 bytes) */
  uint32_t packet_number; /**< Truncated Packet Number */

  /* Short header fields (Section 17.3) */
  int spin_bit;        /**< Latency Spin Bit (1-RTT only) */
  int key_phase;       /**< Key Phase bit (1-RTT only) */
  uint8_t dcid_length; /**< Known DCID length for short header */

  /* Parsing state */
  size_t header_length; /**< Total parsed header length in bytes */

} SocketQUICPacketHeader_T;

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
SocketQUICPacketHeader_parse (const uint8_t *data,
                              size_t len,
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
                                  uint8_t *output,
                                  size_t output_size);

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
                                      const uint8_t *token,
                                      size_t token_len,
                                      uint8_t pn_length,
                                      uint32_t pn);

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
                                        uint8_t pn_length,
                                        uint32_t pn);

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
                                   uint8_t pn_length,
                                   uint32_t pn);

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
                                    int spin_bit,
                                    int key_phase,
                                    uint8_t pn_length,
                                    uint32_t pn);

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

/**
 * @brief QUIC Retry Integrity Tag length (RFC 9000 Section 17.2.5).
 *
 * The Retry packet includes a 16-byte integrity tag to prevent
 * off-path attackers from injecting Retry packets.
 */
#define QUIC_RETRY_INTEGRITY_TAG_LEN 16

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
  uint8_t client_key[QUIC_INITIAL_KEY_LEN];       /**< Client AEAD key */
  uint8_t client_iv[QUIC_INITIAL_IV_LEN];         /**< Client AEAD IV */
  uint8_t client_hp_key[QUIC_INITIAL_HP_KEY_LEN]; /**< Client header protection
                                                     key */

  /* Server secrets and keys */
  uint8_t server_key[QUIC_INITIAL_KEY_LEN];       /**< Server AEAD key */
  uint8_t server_iv[QUIC_INITIAL_IV_LEN];         /**< Server AEAD IV */
  uint8_t server_hp_key[QUIC_INITIAL_HP_KEY_LEN]; /**< Server header protection
                                                     key */

  int is_client;   /**< 1 if keys for client, 0 for server */
  int initialized; /**< 1 if keys have been derived */

} SocketQUICInitialKeys_T;

/**
 * @brief Result codes for Initial packet operations.
 */
typedef enum
{
  QUIC_INITIAL_OK = 0,          /**< Operation succeeded */
  QUIC_INITIAL_ERROR_NULL,      /**< NULL pointer argument */
  QUIC_INITIAL_ERROR_CRYPTO,    /**< Cryptographic operation failed */
  QUIC_INITIAL_ERROR_BUFFER,    /**< Buffer too small */
  QUIC_INITIAL_ERROR_TRUNCATED, /**< Packet too short */
  QUIC_INITIAL_ERROR_INVALID,   /**< Invalid packet format */
  QUIC_INITIAL_ERROR_AUTH,      /**< AEAD authentication failed */
  QUIC_INITIAL_ERROR_SIZE,      /**< Packet size below minimum */
  QUIC_INITIAL_ERROR_TOKEN,     /**< Server Initial has non-zero token */
  QUIC_INITIAL_ERROR_VERSION    /**< Unsupported QUIC version */
} SocketQUICInitial_Result;

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
SocketQUICInitial_protect (uint8_t *packet,
                           size_t *packet_len,
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
SocketQUICInitial_unprotect (uint8_t *packet,
                             size_t packet_len,
                             size_t pn_offset,
                             const SocketQUICInitialKeys_T *keys,
                             int is_client,
                             uint8_t *pn_length);

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
                            size_t total_len,
                            int is_client);

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
SocketQUICInitial_get_salt (uint32_t version,
                            const uint8_t **salt,
                            size_t *salt_len);

/**
 * @brief Compute Retry packet integrity tag (RFC 9001 §5.8).
 *
 * Computes the 16-byte integrity tag for a Retry packet using
 * AEAD_AES_128_GCM with the fixed Retry key and nonce.
 *
 * The AAD (additional authenticated data) is formed as:
 *   - ODCID length (1 byte)
 *   - Original Destination Connection ID (0..20 bytes)
 *   - Retry packet (header and Retry Token, without integrity tag)
 *
 * @param odcid           Original Destination Connection ID from client.
 * @param retry_packet    Retry packet data (without integrity tag).
 * @param retry_packet_len Length of retry packet data.
 * @param tag             Output: 16-byte integrity tag.
 *
 * @return QUIC_PACKET_OK on success, error code otherwise.
 *
 * @note Requires TLS support (SOCKET_HAS_TLS). Returns
 * QUIC_PACKET_ERROR_INVALID if TLS is not enabled.
 */
extern SocketQUICPacket_Result
SocketQUICPacket_compute_retry_tag (const SocketQUICConnectionID_T *odcid,
                                    const uint8_t *retry_packet,
                                    size_t retry_packet_len,
                                    uint8_t tag[QUIC_RETRY_INTEGRITY_TAG_LEN]);

/**
 * @brief Verify Retry packet integrity tag (RFC 9001 §5.8).
 *
 * Verifies that a received Retry packet has a valid integrity tag.
 * Uses constant-time comparison to prevent timing attacks.
 *
 * @param odcid           Original Destination Connection ID sent by client.
 * @param retry_packet    Complete Retry packet (with integrity tag at end).
 * @param retry_packet_len Length of complete Retry packet.
 *
 * @return QUIC_PACKET_OK if tag is valid,
 *         QUIC_PACKET_ERROR_INVALID if tag is invalid,
 *         QUIC_PACKET_ERROR_TRUNCATED if packet too short for tag,
 *         other error codes on failure.
 *
 * @note Requires TLS support (SOCKET_HAS_TLS). Returns
 * QUIC_PACKET_ERROR_INVALID if TLS is not enabled.
 */
extern SocketQUICPacket_Result
SocketQUICPacket_verify_retry_tag (const SocketQUICConnectionID_T *odcid,
                                   const uint8_t *retry_packet,
                                   size_t retry_packet_len);

/**
 * @brief QUIC packet number spaces.
 *
 * QUIC uses three independent packet number spaces:
 * - Initial: Used for Initial packets
 * - Handshake: Used for Handshake packets
 * - Application: Used for 0-RTT and 1-RTT packets
 */
typedef enum
{
  QUIC_PN_SPACE_INITIAL = 0, /**< Initial packet number space */
  QUIC_PN_SPACE_HANDSHAKE,   /**< Handshake packet number space */
  QUIC_PN_SPACE_APPLICATION, /**< Application data (0-RTT/1-RTT) PN space */
  QUIC_PN_SPACE_COUNT        /**< Number of packet number spaces */
} SocketQUIC_PNSpace;

/**
 * @brief Per-space receive state for packet number tracking.
 *
 * Maintains the largest successfully decrypted packet number
 * for window-based PN reconstruction (RFC 9000 Appendix A).
 */
typedef struct SocketQUICRecvState
{
  uint64_t largest_pn; /**< Largest successfully decrypted PN */
  int has_received;    /**< At least one packet received in this space */
} SocketQUICRecvState_T;

/* Forward declaration for key update state */
struct SocketQUICKeyUpdate;

/* Forward declaration for generic packet keys */
struct SocketQUICPacketKeys;

/**
 * @brief Context for packet reception operations.
 *
 * Holds all state needed for receiving protected packets:
 * - Per-space packet number state
 * - Key material references
 * - Decryption failure counters for AEAD limits
 *
 * Thread Safety: NOT thread-safe. Caller must synchronize access.
 */
typedef struct SocketQUICReceive
{
  SocketQUICRecvState_T spaces[QUIC_PN_SPACE_COUNT]; /**< PN state per space */

  /* Key material references (not owned, caller manages lifecycle) */
  const SocketQUICInitialKeys_T *initial_keys;       /**< Initial packet keys */
  const struct SocketQUICPacketKeys *handshake_keys; /**< Handshake keys */
  const struct SocketQUICPacketKeys *zero_rtt_keys;  /**< 0-RTT keys */
  struct SocketQUICKeyUpdate *key_update;            /**< 1-RTT key state */

  /* AEAD limit tracking (RFC 9001 Section 6.6) */
  uint64_t decryption_failures; /**< Total failed decryptions */

  /* State flags */
  int initialized; /**< Structure has been initialized */
} SocketQUICReceive_T;

/**
 * @brief Result of packet reception attempt.
 *
 * Contains decoded packet information on success.
 */
typedef struct SocketQUICReceiveResult
{
  SocketQUICPacket_Type type;  /**< Packet type */
  uint64_t packet_number;      /**< Full reconstructed packet number */
  SocketQUIC_PNSpace pn_space; /**< Packet number space */

  /* Decrypted payload (points into modified input buffer) */
  uint8_t *payload;   /**< Pointer to decrypted payload */
  size_t payload_len; /**< Length of decrypted payload */

  /* Header info */
  SocketQUICConnectionID_T dcid; /**< Destination Connection ID */
  SocketQUICConnectionID_T scid; /**< Source Connection ID (long header) */

  /* Short header specific */
  int key_phase; /**< Key Phase bit (1-RTT only) */
  int spin_bit;  /**< Spin bit (1-RTT only) */

  /* Coalesced packet support (RFC 9000 §12.2) */
  size_t consumed; /**< Total bytes consumed from datagram */
} SocketQUICReceiveResult_T;

/**
 * @brief Result codes for packet reception.
 */
typedef enum
{
  QUIC_RECEIVE_OK = 0,          /**< Success */
  QUIC_RECEIVE_ERROR_NULL,      /**< NULL pointer argument */
  QUIC_RECEIVE_ERROR_TRUNCATED, /**< Packet too short */
  QUIC_RECEIVE_ERROR_HEADER,    /**< Header parse error */
  QUIC_RECEIVE_ERROR_NO_KEYS,   /**< Keys not available for packet type */
  QUIC_RECEIVE_ERROR_UNPROTECT, /**< Header protection removal failed */
  QUIC_RECEIVE_ERROR_DECRYPT,   /**< AEAD decryption/auth failed */
  QUIC_RECEIVE_ERROR_PN_DECODE, /**< Packet number decode failed */
  QUIC_RECEIVE_ERROR_VERSION,   /**< Unsupported version */
  QUIC_RECEIVE_ERROR_KEY_PHASE  /**< Key phase mismatch */
} SocketQUICReceive_Result;

/**
 * @brief Initialize receive context.
 *
 * Zeros all fields and sets largest_pn to 0 for each space.
 *
 * @param ctx Receive context to initialize (may be NULL, no-op).
 */
extern void SocketQUICReceive_init (SocketQUICReceive_T *ctx);

/**
 * @brief Set Initial packet keys.
 *
 * @param ctx   Receive context.
 * @param keys  Initial keys (caller retains ownership).
 *
 * @return QUIC_RECEIVE_OK on success.
 */
extern SocketQUICReceive_Result
SocketQUICReceive_set_initial_keys (SocketQUICReceive_T *ctx,
                                    const SocketQUICInitialKeys_T *keys);

/**
 * @brief Set Handshake packet keys.
 *
 * @param ctx   Receive context.
 * @param keys  Handshake keys (caller retains ownership).
 *
 * @return QUIC_RECEIVE_OK on success.
 */
extern SocketQUICReceive_Result
SocketQUICReceive_set_handshake_keys (SocketQUICReceive_T *ctx,
                                      const struct SocketQUICPacketKeys *keys);

/**
 * @brief Set 0-RTT packet keys.
 *
 * @param ctx   Receive context.
 * @param keys  0-RTT keys (caller retains ownership).
 *
 * @return QUIC_RECEIVE_OK on success.
 */
extern SocketQUICReceive_Result
SocketQUICReceive_set_0rtt_keys (SocketQUICReceive_T *ctx,
                                 const struct SocketQUICPacketKeys *keys);

/**
 * @brief Set 1-RTT key update state.
 *
 * @param ctx    Receive context.
 * @param state  Key update state (caller retains ownership).
 *
 * @return QUIC_RECEIVE_OK on success.
 */
extern SocketQUICReceive_Result
SocketQUICReceive_set_1rtt_keys (SocketQUICReceive_T *ctx,
                                 struct SocketQUICKeyUpdate *state);

/**
 * @brief Receive and decrypt a protected QUIC packet (RFC 9001 Section 5.5).
 *
 * Performs the complete packet reception pipeline:
 * 1. Parse unprotected header fields
 * 2. Remove header protection
 * 3. Decode packet number using window-based reconstruction
 * 4. Decrypt AEAD payload
 * 5. Update largest PN if decryption succeeds
 *
 * The packet buffer is modified in-place during decryption.
 *
 * @param ctx         Receive context with keys and PN state.
 * @param packet      Packet buffer (MODIFIED in-place on success).
 * @param packet_len  Packet length.
 * @param dcid_len    Expected DCID length for short headers.
 * @param is_server   1 if receiving as server, 0 as client.
 * @param result      Output: reception result details.
 *
 * @return QUIC_RECEIVE_OK on success, error code on failure.
 *
 * @note On decryption failure, largest_pn is NOT updated per RFC 9001 §5.5.
 * @note Caller should check decryption_failures for AEAD limits (§6.6).
 */
extern SocketQUICReceive_Result
SocketQUICReceive_packet (SocketQUICReceive_T *ctx,
                          uint8_t *packet,
                          size_t packet_len,
                          uint8_t dcid_len,
                          int is_server,
                          SocketQUICReceiveResult_T *result);

/**
 * @brief Get largest received packet number for a space.
 *
 * @param ctx     Receive context.
 * @param space   Packet number space.
 * @param out_pn  Output: largest PN (undefined if returns 0).
 *
 * @return 1 if at least one packet received in space, 0 otherwise.
 */
extern int SocketQUICReceive_get_largest_pn (const SocketQUICReceive_T *ctx,
                                             SocketQUIC_PNSpace space,
                                             uint64_t *out_pn);

/**
 * @brief Get string representation of receive result code.
 *
 * @param result Result code.
 *
 * @return Static string describing the result.
 */
extern const char *
SocketQUICReceive_result_string (SocketQUICReceive_Result result);
/** @} */

#endif /* SOCKETQUICPACKET_INCLUDED */
