/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICConnectionID.h
 * @brief QUIC Connection ID Management (RFC 9000 Section 5.1).
 *
 * Connection IDs are used to route QUIC packets to the correct endpoint
 * and to allow connections to survive address changes (migration).
 *
 * Key properties:
 *   - Connection IDs are 0-20 bytes in length
 *   - Each CID has a sequence number (starting from 0 for initial)
 *   - CIDs include a 16-byte stateless reset token
 *   - Multiple CIDs can be active for a single connection
 *
 * Thread Safety: Individual CID structures are not thread-safe.
 * Use external synchronization when sharing across threads.
 *
 * @defgroup quic_connid QUIC Connection ID Module
 * @{
 * @see https://www.rfc-editor.org/rfc/rfc9000#section-5.1
 */

#ifndef SOCKETQUICCONNECTIONID_INCLUDED
#define SOCKETQUICCONNECTIONID_INCLUDED

#include <stddef.h>
#include <stdint.h>

/* ============================================================================
 * Constants (RFC 9000 Section 5.1)
 * ============================================================================
 */

/**
 * @brief Maximum length of a QUIC Connection ID in bytes.
 *
 * Connection IDs can be 0-20 bytes. Zero-length CIDs are valid but
 * limit connection migration capabilities.
 */
#define QUIC_CONNID_MAX_LEN 20

/**
 * @brief Minimum length of a non-zero Connection ID.
 *
 * When a non-zero-length CID is used, it must be at least 1 byte.
 * NEW_CONNECTION_ID frame requires length 1-20.
 */
#define QUIC_CONNID_MIN_LEN 1

/**
 * @brief Size of the Stateless Reset Token in bytes.
 *
 * Each Connection ID has an associated 16-byte (128-bit) stateless
 * reset token used to identify Stateless Reset packets.
 */
#define QUIC_STATELESS_RESET_TOKEN_LEN 16

/**
 * @brief Sequence number for the initial Connection ID.
 *
 * The initial CID exchanged during handshake has sequence 0.
 */
#define QUIC_CONNID_INITIAL_SEQUENCE 0

/**
 * @brief Sequence number for preferred_address CID.
 *
 * If preferred_address transport parameter is sent, its CID has sequence 1.
 */
#define QUIC_CONNID_PREFERRED_ADDRESS_SEQUENCE 1

/**
 * @brief Default active_connection_id_limit.
 *
 * Minimum value that endpoints must support (RFC 9000 Section 18.2).
 */
#define QUIC_CONNID_DEFAULT_LIMIT 2

/* ============================================================================
 * Data Structures
 * ============================================================================
 */

/**
 * @brief QUIC Connection ID structure.
 *
 * Represents a single Connection ID with its associated metadata.
 * Connection IDs are used in packet headers to route packets.
 */
typedef struct SocketQUICConnectionID
{
  uint8_t data[QUIC_CONNID_MAX_LEN]; /**< Raw Connection ID bytes */
  uint8_t len;                       /**< Length of Connection ID (0-20) */

  uint64_t sequence; /**< Sequence number assigned to this CID */

  uint8_t stateless_reset_token[QUIC_STATELESS_RESET_TOKEN_LEN];
  /**< 16-byte stateless reset token */

  int has_reset_token; /**< Non-zero if reset token is valid */

} SocketQUICConnectionID_T;

/**
 * @brief Result codes for Connection ID operations.
 */
typedef enum
{
  QUIC_CONNID_OK = 0,            /**< Operation succeeded */
  QUIC_CONNID_ERROR_NULL,        /**< NULL pointer argument */
  QUIC_CONNID_ERROR_LENGTH,      /**< Invalid CID length */
  QUIC_CONNID_ERROR_BUFFER,      /**< Output buffer too small */
  QUIC_CONNID_ERROR_INCOMPLETE,  /**< Need more input data */
  QUIC_CONNID_ERROR_RANDOM       /**< Random generation failed */
} SocketQUICConnectionID_Result;

/* ============================================================================
 * Initialization Functions
 * ============================================================================
 */

/**
 * @brief Initialize a Connection ID structure.
 *
 * Zeros all fields. Call this before using a CID structure.
 *
 * @param cid Connection ID structure to initialize.
 */
extern void SocketQUICConnectionID_init (SocketQUICConnectionID_T *cid);

/**
 * @brief Initialize a Connection ID with specific data.
 *
 * Copies the provided bytes into the CID structure.
 *
 * @param cid   Connection ID structure to initialize.
 * @param data  Raw Connection ID bytes.
 * @param len   Length of data (0-20).
 *
 * @return QUIC_CONNID_OK on success, error code otherwise.
 */
extern SocketQUICConnectionID_Result
SocketQUICConnectionID_set (SocketQUICConnectionID_T *cid, const uint8_t *data,
                            size_t len);

/* ============================================================================
 * Generation Functions
 * ============================================================================
 */

/**
 * @brief Generate a random Connection ID.
 *
 * Creates a cryptographically random CID of the specified length.
 * Uses the system's secure random number generator.
 *
 * @param cid Connection ID structure to populate.
 * @param len Desired length (1-20). Use 0 for zero-length CID.
 *
 * @return QUIC_CONNID_OK on success, error code otherwise.
 *
 * @note The sequence number is NOT set by this function.
 *       Set it separately after calling this.
 */
extern SocketQUICConnectionID_Result
SocketQUICConnectionID_generate (SocketQUICConnectionID_T *cid, size_t len);

/**
 * @brief Generate a random Stateless Reset Token.
 *
 * Creates a cryptographically random 16-byte token.
 *
 * @param cid Connection ID structure to populate token in.
 *
 * @return QUIC_CONNID_OK on success, error code otherwise.
 */
extern SocketQUICConnectionID_Result
SocketQUICConnectionID_generate_reset_token (SocketQUICConnectionID_T *cid);

/* ============================================================================
 * Comparison Functions
 * ============================================================================
 */

/**
 * @brief Compare two Connection IDs for equality.
 *
 * Compares only the CID data and length, not sequence or reset token.
 *
 * @param a First Connection ID.
 * @param b Second Connection ID.
 *
 * @return 1 if equal, 0 if not equal or either is NULL.
 */
extern int SocketQUICConnectionID_equal (const SocketQUICConnectionID_T *a,
                                         const SocketQUICConnectionID_T *b);

/**
 * @brief Compare a Connection ID with raw bytes.
 *
 * @param cid  Connection ID structure.
 * @param data Raw bytes to compare.
 * @param len  Length of data.
 *
 * @return 1 if equal, 0 otherwise.
 */
extern int SocketQUICConnectionID_equal_raw (const SocketQUICConnectionID_T *cid,
                                             const uint8_t *data, size_t len);

/**
 * @brief Copy a Connection ID.
 *
 * Copies all fields from src to dst.
 *
 * @param dst Destination Connection ID.
 * @param src Source Connection ID.
 *
 * @return QUIC_CONNID_OK on success, error code otherwise.
 */
extern SocketQUICConnectionID_Result
SocketQUICConnectionID_copy (SocketQUICConnectionID_T *dst,
                             const SocketQUICConnectionID_T *src);

/* ============================================================================
 * Wire Format Functions
 * ============================================================================
 */

/**
 * @brief Encode Connection ID length for long header packets.
 *
 * In long header packets, the CID length is encoded as a single byte.
 *
 * @param cid         Connection ID to encode length for.
 * @param output      Output buffer.
 * @param output_size Size of output buffer.
 *
 * @return Number of bytes written (1), or 0 on error.
 */
extern size_t
SocketQUICConnectionID_encode_length (const SocketQUICConnectionID_T *cid,
                                      uint8_t *output, size_t output_size);

/**
 * @brief Encode Connection ID for packet header.
 *
 * Writes the raw CID bytes without length prefix.
 *
 * @param cid         Connection ID to encode.
 * @param output      Output buffer.
 * @param output_size Size of output buffer.
 *
 * @return Number of bytes written, or 0 on error.
 */
extern size_t SocketQUICConnectionID_encode (const SocketQUICConnectionID_T *cid,
                                             uint8_t *output, size_t output_size);

/**
 * @brief Encode Connection ID with length prefix.
 *
 * Writes length byte followed by CID bytes. Used in long header packets.
 *
 * @param cid         Connection ID to encode.
 * @param output      Output buffer.
 * @param output_size Size of output buffer.
 *
 * @return Number of bytes written (1 + len), or 0 on error.
 */
extern size_t
SocketQUICConnectionID_encode_with_length (const SocketQUICConnectionID_T *cid,
                                           uint8_t *output, size_t output_size);

/**
 * @brief Decode Connection ID from packet with length prefix.
 *
 * Reads a length byte followed by CID bytes.
 *
 * @param data     Input buffer.
 * @param len      Size of input buffer.
 * @param cid      Output Connection ID structure.
 * @param consumed Output: number of bytes consumed.
 *
 * @return QUIC_CONNID_OK on success, error code otherwise.
 */
extern SocketQUICConnectionID_Result
SocketQUICConnectionID_decode (const uint8_t *data, size_t len,
                               SocketQUICConnectionID_T *cid, size_t *consumed);

/**
 * @brief Decode Connection ID with known length.
 *
 * Reads exactly cid_len bytes as the CID (no length prefix).
 *
 * @param data    Input buffer.
 * @param len     Size of input buffer.
 * @param cid     Output Connection ID structure.
 * @param cid_len Expected CID length.
 *
 * @return QUIC_CONNID_OK on success, error code otherwise.
 */
extern SocketQUICConnectionID_Result
SocketQUICConnectionID_decode_fixed (const uint8_t *data, size_t len,
                                     SocketQUICConnectionID_T *cid,
                                     size_t cid_len);

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

/**
 * @brief Compute hash of Connection ID for hash tables.
 *
 * Returns a hash suitable for use in hash table lookups.
 *
 * @param cid Connection ID to hash.
 *
 * @return Hash value.
 */
extern uint32_t SocketQUICConnectionID_hash (const SocketQUICConnectionID_T *cid);

/**
 * @brief Check if Connection ID is zero-length.
 *
 * @param cid Connection ID to check.
 *
 * @return 1 if zero-length, 0 otherwise.
 */
static inline int
SocketQUICConnectionID_is_empty (const SocketQUICConnectionID_T *cid)
{
  return (cid == NULL || cid->len == 0);
}

/**
 * @brief Check if Connection ID length is valid.
 *
 * @param len Length to check.
 *
 * @return 1 if valid (0-20), 0 otherwise.
 */
static inline int
SocketQUICConnectionID_is_valid_length (size_t len)
{
  return (len <= QUIC_CONNID_MAX_LEN);
}

/**
 * @brief Get string representation of result code.
 *
 * @param result Result code to convert.
 *
 * @return Human-readable string describing the result.
 */
extern const char *
SocketQUICConnectionID_result_string (SocketQUICConnectionID_Result result);

/**
 * @brief Format Connection ID as hex string.
 *
 * Writes the CID as a hex string to the provided buffer.
 * Format: "XX:XX:XX:..." for non-empty CIDs, "empty" for zero-length.
 *
 * @param cid  Connection ID to format.
 * @param buf  Output buffer for string.
 * @param size Size of output buffer.
 *
 * @return Number of characters written (excluding null), or -1 on error.
 */
extern int SocketQUICConnectionID_to_hex (const SocketQUICConnectionID_T *cid,
                                          char *buf, size_t size);

/** @} */

#endif /* SOCKETQUICCONNECTIONID_INCLUDED */
