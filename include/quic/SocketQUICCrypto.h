/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICCrypto.h
 * @brief QUIC Packet Protection Keys (RFC 9001 Sections 5.1-5.2).
 *
 * Provides cryptographic key derivation for QUIC packet protection:
 * - Initial packets: Keys derived from client DCID (Section 5.2)
 * - Handshake/1-RTT packets: Keys derived from TLS secrets (Section 5.1)
 *
 * Derivation process (Section 5.1):
 *   key    = HKDF-Expand-Label(secret, "quic key", "", key_len)
 *   iv     = HKDF-Expand-Label(secret, "quic iv", "", 12)
 *   hp_key = HKDF-Expand-Label(secret, "quic hp", "", hp_len)
 *
 * Key sizes and hash functions depend on the AEAD algorithm (RFC 9001 §5.1):
 *   AES-128-GCM:       key=16, iv=12, hp=16, hash=SHA-256 (32-byte secret)
 *   AES-256-GCM:       key=32, iv=12, hp=32, hash=SHA-384 (48-byte secret)
 *   ChaCha20-Poly1305: key=32, iv=12, hp=32, hash=SHA-256 (32-byte secret)
 *
 * Thread Safety: All functions are thread-safe (no shared state).
 *
 * @defgroup quic_crypto QUIC Cryptographic Module
 * @{
 * @see https://www.rfc-editor.org/rfc/rfc9001#section-5.1
 */

#ifndef SOCKETQUICCRYPTO_INCLUDED
#define SOCKETQUICCRYPTO_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include "core/SocketCrypto.h"
#include "quic/SocketQUICConnectionID.h"
#include "quic/SocketQUICPacket.h"

/* ============================================================================
 * Constants
 * ============================================================================
 */

/**
 * @brief Initial salt length in bytes.
 *
 * Both QUIC v1 and v2 use 20-byte (160-bit) salts for HKDF-Extract.
 */
#define QUIC_INITIAL_SALT_LEN 20

/* ============================================================================
 * Result Codes
 * ============================================================================
 */

/**
 * @brief Result codes for QUIC crypto operations.
 */
typedef enum
{
  QUIC_CRYPTO_OK = 0,           /**< Operation succeeded */
  QUIC_CRYPTO_ERROR_NULL,       /**< NULL pointer argument */
  QUIC_CRYPTO_ERROR_VERSION,    /**< Unsupported QUIC version */
  QUIC_CRYPTO_ERROR_HKDF,       /**< HKDF operation failed */
  QUIC_CRYPTO_ERROR_NO_TLS,     /**< TLS support not available */
  QUIC_CRYPTO_ERROR_AEAD,       /**< Invalid AEAD algorithm */
  QUIC_CRYPTO_ERROR_SECRET_LEN, /**< Secret length doesn't match AEAD */
  QUIC_CRYPTO_ERROR_BUFFER,     /**< Output buffer too small */
  QUIC_CRYPTO_ERROR_TAG,        /**< AEAD tag verification failed */
  QUIC_CRYPTO_ERROR_INPUT       /**< Invalid input (e.g., too short) */
} SocketQUICCrypto_Result;

/* ============================================================================
 * AEAD Algorithm Types (RFC 9001 Section 5.1)
 * ============================================================================
 */

/**
 * @brief AEAD algorithms supported for QUIC packet protection.
 *
 * These correspond to TLS 1.3 cipher suites. Each algorithm has
 * different key/IV/HP sizes per RFC 9001 Section 5.1.
 */
typedef enum
{
  QUIC_AEAD_AES_128_GCM = 0,   /**< TLS_AES_128_GCM_SHA256 */
  QUIC_AEAD_AES_256_GCM,       /**< TLS_AES_256_GCM_SHA384 */
  QUIC_AEAD_CHACHA20_POLY1305, /**< TLS_CHACHA20_POLY1305_SHA256 */
  QUIC_AEAD_COUNT              /**< Number of supported algorithms */
} SocketQUIC_AEAD;

/* ============================================================================
 * Packet Protection Keys (RFC 9001 Section 5.1)
 * ============================================================================
 */

/** Maximum AEAD key length (AES-256 / ChaCha20) */
#define QUIC_PACKET_KEY_MAX_LEN 32

/** AEAD IV length (fixed for all algorithms) */
#define QUIC_PACKET_IV_LEN 12

/** Maximum header protection key length (AES-256 / ChaCha20) */
#define QUIC_PACKET_HP_MAX_LEN 32

/**
 * @brief Packet protection keys for any encryption level.
 *
 * Generalized structure that holds keys for any AEAD algorithm.
 * Key sizes are algorithm-dependent; actual lengths stored in key_len/hp_len.
 *
 * Per RFC 9001 Section 5.1:
 *   key    = HKDF-Expand-Label(secret, "quic key", "", key_len)
 *   iv     = HKDF-Expand-Label(secret, "quic iv", "", 12)
 *   hp_key = HKDF-Expand-Label(secret, "quic hp", "", hp_len)
 */
typedef struct SocketQUICPacketKeys
{
  uint8_t key[QUIC_PACKET_KEY_MAX_LEN];   /**< AEAD encryption key */
  uint8_t iv[QUIC_PACKET_IV_LEN];         /**< AEAD initialization vector */
  uint8_t hp_key[QUIC_PACKET_HP_MAX_LEN]; /**< Header protection key */
  size_t key_len;                         /**< Actual key length in bytes */
  size_t hp_len;                          /**< Actual HP key length in bytes */
  SocketQUIC_AEAD aead;                   /**< Algorithm in use */
} SocketQUICPacketKeys_T;

/* ============================================================================
 * Intermediate Secrets Structure (for testing)
 * ============================================================================
 */

/**
 * @brief Intermediate secrets from Initial key derivation.
 *
 * Exposes intermediate values for validation against RFC 9001 Appendix A.1
 * test vectors. Production code typically only needs the final keys.
 *
 * The derivation hierarchy is:
 *   initial_secret
 *     ├── client_initial_secret (for client keys)
 *     └── server_initial_secret (for server keys)
 */
typedef struct SocketQUICCryptoSecrets
{
  uint8_t initial_secret[SOCKET_CRYPTO_SHA256_SIZE];
  /**< HKDF-Extract(salt, DCID) result (32 bytes) */

  uint8_t client_initial_secret[SOCKET_CRYPTO_SHA256_SIZE];
  /**< Client secret derived with "client in" label (32 bytes) */

  uint8_t server_initial_secret[SOCKET_CRYPTO_SHA256_SIZE];
  /**< Server secret derived with "server in" label (32 bytes) */

} SocketQUICCryptoSecrets_T;

/* ============================================================================
 * Key Derivation Functions
 * ============================================================================
 */

/**
 * @brief Derive Initial packet keys from client DCID.
 *
 * Derives all client and server keys needed for Initial packet protection.
 * This is the primary function for normal QUIC operation.
 *
 * @param dcid    Client's Destination Connection ID.
 * @param version QUIC version (determines salt: v1 or v2).
 * @param keys    Output: derived key material.
 *
 * @return QUIC_CRYPTO_OK on success, error code otherwise.
 *
 * @note Uses version-specific salt per RFC 9001 §5.2 (v1) and RFC 9369 (v2).
 */
extern SocketQUICCrypto_Result
SocketQUICCrypto_derive_initial_keys (const SocketQUICConnectionID_T *dcid,
                                      uint32_t version,
                                      SocketQUICInitialKeys_T *keys);

/**
 * @brief Derive Initial keys with intermediate secrets exposed.
 *
 * Same as SocketQUICCrypto_derive_initial_keys() but also outputs
 * intermediate secrets for test vector validation.
 *
 * @param dcid    Client's Destination Connection ID.
 * @param version QUIC version (determines salt).
 * @param secrets Output: intermediate secrets (may be NULL if not needed).
 * @param keys    Output: derived key material.
 *
 * @return QUIC_CRYPTO_OK on success, error code otherwise.
 *
 * @see RFC 9001 Appendix A.1 for test vectors.
 */
extern SocketQUICCrypto_Result
SocketQUICCrypto_derive_initial_secrets (const SocketQUICConnectionID_T *dcid,
                                         uint32_t version,
                                         SocketQUICCryptoSecrets_T *secrets,
                                         SocketQUICInitialKeys_T *keys);

/**
 * @brief Derive traffic keys from a secret.
 *
 * Derives key, IV, and header protection key from an initial secret
 * using the "quic key", "quic iv", and "quic hp" labels.
 *
 * @param secret     Input secret (32 bytes).
 * @param secret_len Length of secret (must be SOCKET_CRYPTO_SHA256_SIZE).
 * @param key        Output: AEAD key (QUIC_INITIAL_KEY_LEN bytes).
 * @param iv         Output: AEAD IV (QUIC_INITIAL_IV_LEN bytes).
 * @param hp_key     Output: header protection key (QUIC_INITIAL_HP_KEY_LEN).
 *
 * @return QUIC_CRYPTO_OK on success, error code otherwise.
 */
extern SocketQUICCrypto_Result
SocketQUICCrypto_derive_traffic_keys (const uint8_t *secret,
                                      size_t secret_len,
                                      uint8_t *key,
                                      uint8_t *iv,
                                      uint8_t *hp_key);

/* ============================================================================
 * Salt Access Functions
 * ============================================================================
 */

/**
 * @brief Get the Initial salt for a QUIC version.
 *
 * Returns a pointer to the version-specific salt used in HKDF-Extract.
 *
 * @param version  QUIC version (QUIC_VERSION_1 or QUIC_VERSION_2).
 * @param salt     Output: pointer to salt bytes.
 * @param salt_len Output: salt length (always QUIC_INITIAL_SALT_LEN).
 *
 * @return QUIC_CRYPTO_OK on success, QUIC_CRYPTO_ERROR_VERSION for
 *         unsupported versions.
 */
extern SocketQUICCrypto_Result
SocketQUICCrypto_get_initial_salt (uint32_t version,
                                   const uint8_t **salt,
                                   size_t *salt_len);

/* ============================================================================
 * Security Functions
 * ============================================================================
 */

/**
 * @brief Securely clear intermediate secrets.
 *
 * Overwrites all fields with zeros using OPENSSL_cleanse or equivalent
 * to prevent compiler optimization from removing the clear operation.
 *
 * @param secrets Secrets structure to clear (may be NULL).
 */
extern void SocketQUICCryptoSecrets_clear (SocketQUICCryptoSecrets_T *secrets);

/* ============================================================================
 * Packet Protection Key Derivation (RFC 9001 Section 5.1)
 * ============================================================================
 */

/**
 * @brief Derive packet protection keys from a TLS secret.
 *
 * Derives key, IV, and header protection key using HKDF-Expand-Label
 * with "quic key", "quic iv", and "quic hp" labels. Key sizes depend
 * on the specified AEAD algorithm.
 *
 * @param secret     TLS secret (32 or 48 bytes depending on cipher suite).
 * @param secret_len Length of secret.
 * @param aead       AEAD algorithm determining key sizes.
 * @param keys       Output: derived packet protection keys.
 *
 * @return QUIC_CRYPTO_OK on success, error code otherwise.
 *
 * @see RFC 9001 Section 5.1
 */
extern SocketQUICCrypto_Result
SocketQUICCrypto_derive_packet_keys (const uint8_t *secret,
                                     size_t secret_len,
                                     SocketQUIC_AEAD aead,
                                     SocketQUICPacketKeys_T *keys);

/**
 * @brief Get key sizes for an AEAD algorithm.
 *
 * Returns the key, IV, and HP key lengths for the specified algorithm.
 *
 * @param aead    AEAD algorithm.
 * @param key_len Output: key length in bytes (may be NULL).
 * @param iv_len  Output: IV length in bytes (may be NULL).
 * @param hp_len  Output: HP key length in bytes (may be NULL).
 *
 * @return QUIC_CRYPTO_OK on success, QUIC_CRYPTO_ERROR_AEAD if invalid.
 */
extern SocketQUICCrypto_Result SocketQUICCrypto_get_aead_key_sizes (
    SocketQUIC_AEAD aead, size_t *key_len, size_t *iv_len, size_t *hp_len);

/**
 * @brief Get required secret length for an AEAD algorithm.
 *
 * Returns the expected TLS secret length based on the hash function
 * used by the cipher suite:
 *   - AES-128-GCM (SHA-256): 32 bytes
 *   - AES-256-GCM (SHA-384): 48 bytes
 *   - ChaCha20-Poly1305 (SHA-256): 32 bytes
 *
 * @param aead       AEAD algorithm.
 * @param secret_len Output: required secret length in bytes (may be NULL).
 *
 * @return QUIC_CRYPTO_OK on success, QUIC_CRYPTO_ERROR_AEAD if invalid.
 */
extern SocketQUICCrypto_Result
SocketQUICCrypto_get_aead_secret_len (SocketQUIC_AEAD aead, size_t *secret_len);

/**
 * @brief Initialize packet keys structure.
 *
 * Zeros all fields including key material.
 *
 * @param keys Keys structure to initialize (may be NULL).
 */
extern void SocketQUICPacketKeys_init (SocketQUICPacketKeys_T *keys);

/**
 * @brief Securely clear packet protection keys.
 *
 * Overwrites all key material with zeros using secure clear.
 *
 * @param keys Keys structure to clear (may be NULL).
 */
extern void SocketQUICPacketKeys_clear (SocketQUICPacketKeys_T *keys);

/**
 * @brief Get string name for AEAD algorithm.
 *
 * @param aead AEAD algorithm.
 *
 * @return Human-readable algorithm name, or "UNKNOWN" if invalid.
 */
extern const char *SocketQUIC_AEAD_string (SocketQUIC_AEAD aead);

/* ============================================================================
 * AEAD Packet Payload Encryption/Decryption (RFC 9001 Section 5.3)
 * ============================================================================
 */

/**
 * @brief Encrypt a QUIC packet payload using AEAD (RFC 9001 §5.3).
 *
 * Encrypts the payload and appends the 16-byte authentication tag.
 * The nonce is formed by XORing the IV with the packet number.
 *
 * @param keys           Packet protection keys (key, IV, algorithm).
 * @param packet_number  Full 62-bit packet number (for nonce construction).
 * @param header         Packet header bytes (used as AAD).
 * @param header_len     Length of header in bytes.
 * @param plaintext      Input plaintext payload.
 * @param plaintext_len  Length of plaintext in bytes.
 * @param ciphertext     Output buffer for ciphertext + tag.
 * @param ciphertext_len Input: buffer size. Output: bytes written.
 *
 * @return QUIC_CRYPTO_OK on success, error code otherwise.
 *
 * @note Output size = plaintext_len + 16 (authentication tag).
 * @note Buffer must be at least plaintext_len + 16 bytes.
 *
 * @see RFC 9001 Section 5.3 "AEAD Usage"
 */
extern SocketQUICCrypto_Result
SocketQUICCrypto_encrypt_payload (const SocketQUICPacketKeys_T *keys,
                                  uint64_t packet_number,
                                  const uint8_t *header,
                                  size_t header_len,
                                  const uint8_t *plaintext,
                                  size_t plaintext_len,
                                  uint8_t *ciphertext,
                                  size_t *ciphertext_len);

/**
 * @brief Decrypt a QUIC packet payload using AEAD (RFC 9001 §5.3).
 *
 * Verifies the authentication tag and decrypts the ciphertext.
 * The nonce is formed by XORing the IV with the packet number.
 *
 * @param keys           Packet protection keys (key, IV, algorithm).
 * @param packet_number  Full 62-bit packet number (for nonce construction).
 * @param header         Packet header bytes (used as AAD).
 * @param header_len     Length of header in bytes.
 * @param ciphertext     Input ciphertext including 16-byte tag.
 * @param ciphertext_len Length of ciphertext (including tag).
 * @param plaintext      Output buffer for decrypted payload.
 * @param plaintext_len  Input: buffer size. Output: bytes written.
 *
 * @return QUIC_CRYPTO_OK on success.
 *         QUIC_CRYPTO_ERROR_TAG if authentication fails.
 *         Other error codes for invalid parameters.
 *
 * @note Input must be at least 16 bytes (tag only, zero payload).
 * @note Output size = ciphertext_len - 16.
 *
 * @see RFC 9001 Section 5.3 "AEAD Usage"
 */
extern SocketQUICCrypto_Result
SocketQUICCrypto_decrypt_payload (const SocketQUICPacketKeys_T *keys,
                                  uint64_t packet_number,
                                  const uint8_t *header,
                                  size_t header_len,
                                  const uint8_t *ciphertext,
                                  size_t ciphertext_len,
                                  uint8_t *plaintext,
                                  size_t *plaintext_len);

/* ============================================================================
 * Header Protection (RFC 9001 Section 5.4)
 * ============================================================================
 */

/** Header protection sample size in bytes. */
#define QUIC_HP_SAMPLE_LEN 16

/** Header protection mask size in bytes. */
#define QUIC_HP_MASK_LEN 5

/**
 * @brief Apply header protection to a QUIC packet (RFC 9001 §5.4).
 *
 * Protects the packet number and lower bits of the first byte by XORing
 * with a mask derived from the header protection key and ciphertext sample.
 *
 * @param hp_key     Header protection key.
 * @param hp_key_len Key length (16 for AES-128, 32 for AES-256/ChaCha20).
 * @param aead       AEAD algorithm (determines mask generation method).
 * @param packet     Packet buffer (modified in place).
 * @param packet_len Packet length in bytes.
 * @param pn_offset  Offset of packet number field in packet.
 *
 * @return QUIC_CRYPTO_OK on success, error code otherwise.
 */
extern SocketQUICCrypto_Result
SocketQUICCrypto_protect_header (const uint8_t *hp_key,
                                 size_t hp_key_len,
                                 SocketQUIC_AEAD aead,
                                 uint8_t *packet,
                                 size_t packet_len,
                                 size_t pn_offset);

/**
 * @brief Remove header protection from a QUIC packet (RFC 9001 §5.4).
 *
 * Removes protection from packet number and first byte by XORing with
 * the same mask used during protection.
 *
 * @param hp_key     Header protection key.
 * @param hp_key_len Key length (16 for AES-128, 32 for AES-256/ChaCha20).
 * @param aead       AEAD algorithm.
 * @param packet     Packet buffer (modified in place).
 * @param packet_len Packet length in bytes.
 * @param pn_offset  Offset of packet number field in packet.
 *
 * @return QUIC_CRYPTO_OK on success, error code otherwise.
 */
extern SocketQUICCrypto_Result
SocketQUICCrypto_unprotect_header (const uint8_t *hp_key,
                                   size_t hp_key_len,
                                   SocketQUIC_AEAD aead,
                                   uint8_t *packet,
                                   size_t packet_len,
                                   size_t pn_offset);

/**
 * @brief Apply header protection using packet keys struct.
 *
 * Convenience wrapper that extracts hp_key, hp_len, and aead from
 * SocketQUICPacketKeys_T.
 *
 * @param keys       Packet protection keys containing HP key and algorithm.
 * @param packet     Packet buffer (modified in place).
 * @param packet_len Packet length in bytes.
 * @param pn_offset  Offset of packet number field.
 *
 * @return QUIC_CRYPTO_OK on success, error code otherwise.
 */
extern SocketQUICCrypto_Result
SocketQUICCrypto_protect_header_ex (const SocketQUICPacketKeys_T *keys,
                                    uint8_t *packet,
                                    size_t packet_len,
                                    size_t pn_offset);

/**
 * @brief Remove header protection using packet keys struct.
 *
 * Convenience wrapper that extracts hp_key, hp_len, and aead from
 * SocketQUICPacketKeys_T.
 *
 * @param keys       Packet protection keys containing HP key and algorithm.
 * @param packet     Packet buffer (modified in place).
 * @param packet_len Packet length in bytes.
 * @param pn_offset  Offset of packet number field.
 *
 * @return QUIC_CRYPTO_OK on success, error code otherwise.
 */
extern SocketQUICCrypto_Result
SocketQUICCrypto_unprotect_header_ex (const SocketQUICPacketKeys_T *keys,
                                      uint8_t *packet,
                                      size_t packet_len,
                                      size_t pn_offset);

/* ============================================================================
 * Key Update (RFC 9001 Section 6)
 * ============================================================================
 */

/**
 * @defgroup quic_key_update QUIC Key Update Mechanism
 * @brief Post-handshake key rotation using Key Phase bit.
 *
 * RFC 9001 Section 6 defines the key update mechanism for 1-RTT packets:
 * - Key Phase bit in short header toggles to signal key update
 * - New secrets derived: secret_<n+1> = HKDF-Expand-Label(secret_<n>, "quic
 * ku", "", Hash.length)
 * - Header protection key is NOT updated (remains constant)
 * - Both endpoints must update keys when key phase changes
 *
 * @{
 */

/**
 * @brief Maximum secret length (SHA-384 output for AES-256-GCM).
 */
#define QUIC_SECRET_MAX_LEN 48

/**
 * @brief AEAD confidentiality limit for AES-GCM (2^23 packets).
 *
 * Per RFC 9001 Section 6.6 and Appendix B.1, endpoints MUST initiate
 * a key update before encrypting more than this many packets.
 */
#define QUIC_AEAD_AES_GCM_CONFIDENTIALITY_LIMIT (1ULL << 23)

/**
 * @brief AEAD integrity limit for AES-GCM (2^52 failed decryptions).
 *
 * Per RFC 9001 Section 6.6, if this many packets fail authentication
 * across all keys, the connection MUST be closed with AEAD_LIMIT_REACHED.
 */
#define QUIC_AEAD_AES_GCM_INTEGRITY_LIMIT (1ULL << 52)

/**
 * @brief AEAD integrity limit for ChaCha20-Poly1305 (2^36 failed decryptions).
 *
 * Per RFC 9001 Section 6.6, ChaCha20 has no practical confidentiality limit
 * but does have an integrity limit.
 */
#define QUIC_AEAD_CHACHA20_INTEGRITY_LIMIT (1ULL << 36)

/**
 * @brief Key Phase bit position in short header first byte.
 *
 * Per RFC 9000 Section 17.3.1, the Key Phase bit is bit 2 (0x04) of
 * the first byte of a short header packet.
 */
#define QUIC_KEY_PHASE_BIT 0x04

/**
 * @brief Key update state tracking.
 *
 * Manages the key rotation lifecycle per RFC 9001 Section 6:
 * - Tracks current, previous, and next key generations
 * - Maintains secrets for deriving subsequent key generations
 * - Counts packets for AEAD usage limits
 * - Tracks whether key update is permitted (acknowledgment received)
 *
 * Thread Safety: NOT thread-safe. Caller must synchronize access.
 */
typedef struct SocketQUICKeyUpdate
{
  /* Current write keys (used for sending) */
  SocketQUICPacketKeys_T write_keys;
  uint8_t write_secret[QUIC_SECRET_MAX_LEN];
  size_t write_secret_len;

  /* Current read keys (used for receiving) */
  SocketQUICPacketKeys_T read_keys;
  uint8_t read_secret[QUIC_SECRET_MAX_LEN];
  size_t read_secret_len;

  /* Previous read keys (for delayed packets during key update) */
  SocketQUICPacketKeys_T prev_read_keys;
  int prev_read_keys_valid;

  /* Next read keys (pre-computed for timing side-channel protection) */
  SocketQUICPacketKeys_T next_read_keys;
  uint8_t next_read_secret[QUIC_SECRET_MAX_LEN];
  int next_read_keys_valid;

  /* Key phase tracking */
  int key_phase;       /**< Current key phase bit (0 or 1) */
  uint32_t generation; /**< Key generation counter (starts at 0) */

  /* Key update permission tracking (RFC 9001 §6.1) */
  uint64_t lowest_pn_current_phase; /**< Lowest PN sent with current keys */
  uint64_t highest_acked_pn;        /**< Highest acknowledged PN */
  int update_permitted;             /**< Can initiate another key update */

  /* AEAD usage counters (RFC 9001 §6.6) */
  uint64_t packets_encrypted;   /**< Packets encrypted with current write key */
  uint64_t packets_decrypted;   /**< Packets decrypted (any key) */
  uint64_t decryption_failures; /**< Total failed decryptions (all keys) */

  /* Algorithm for limit checking */
  SocketQUIC_AEAD aead;

  /* State flags */
  int initialized; /**< Structure has been initialized */

} SocketQUICKeyUpdate_T;

/**
 * @brief Initialize key update state structure.
 *
 * Zeros all fields and marks as uninitialized.
 *
 * @param state Key update state to initialize (may be NULL).
 */
extern void SocketQUICKeyUpdate_init (SocketQUICKeyUpdate_T *state);

/**
 * @brief Securely clear key update state.
 *
 * Overwrites all key material with zeros using secure clear.
 *
 * @param state Key update state to clear (may be NULL).
 */
extern void SocketQUICKeyUpdate_clear (SocketQUICKeyUpdate_T *state);

/**
 * @brief Set initial 1-RTT keys for key update tracking.
 *
 * Called after TLS handshake completes to install the first set of
 * 1-RTT keys. Pre-computes next read keys for timing protection.
 *
 * @param state         Key update state.
 * @param write_secret  Initial write secret from TLS.
 * @param read_secret   Initial read secret from TLS.
 * @param secret_len    Secret length (32 for SHA-256, 48 for SHA-384).
 * @param aead          AEAD algorithm.
 *
 * @return QUIC_CRYPTO_OK on success, error code otherwise.
 */
extern SocketQUICCrypto_Result
SocketQUICKeyUpdate_set_initial_keys (SocketQUICKeyUpdate_T *state,
                                      const uint8_t *write_secret,
                                      const uint8_t *read_secret,
                                      size_t secret_len,
                                      SocketQUIC_AEAD aead);

/**
 * @brief Derive next secret from current secret (RFC 9001 §6.1).
 *
 * Computes: secret_<n+1> = HKDF-Expand-Label(secret_<n>, "quic ku", "",
 * Hash.length)
 *
 * @param current_secret Current traffic secret.
 * @param secret_len     Secret length.
 * @param aead           AEAD algorithm (determines hash function).
 * @param next_secret    Output: next generation secret.
 *
 * @return QUIC_CRYPTO_OK on success, error code otherwise.
 */
extern SocketQUICCrypto_Result
SocketQUICCrypto_derive_next_secret (const uint8_t *current_secret,
                                     size_t secret_len,
                                     SocketQUIC_AEAD aead,
                                     uint8_t *next_secret);

/**
 * @brief Check if a key update can be initiated (RFC 9001 §6.1).
 *
 * A key update can be initiated only after:
 * 1. Handshake is confirmed
 * 2. An acknowledgment has been received for a packet sent with current keys
 *
 * @param state Key update state.
 *
 * @return 1 if key update is permitted, 0 otherwise.
 */
extern int
SocketQUICKeyUpdate_can_initiate (const SocketQUICKeyUpdate_T *state);

/**
 * @brief Initiate a key update (RFC 9001 §6.1).
 *
 * Updates write keys and toggles key phase bit. Also updates read
 * keys since the peer will respond with updated keys.
 *
 * @param state Key update state.
 *
 * @return QUIC_CRYPTO_OK on success, error code otherwise.
 *
 * @note Caller must verify update is permitted via
 * SocketQUICKeyUpdate_can_initiate().
 */
extern SocketQUICCrypto_Result
SocketQUICKeyUpdate_initiate (SocketQUICKeyUpdate_T *state);

/**
 * @brief Process a received packet with different key phase (RFC 9001 §6.2).
 *
 * When a packet is received with a key phase different from the current
 * sending key phase, this indicates the peer has initiated a key update.
 * The endpoint must update its send keys in response.
 *
 * @param state           Key update state.
 * @param received_phase  Key phase bit from received packet (0 or 1).
 *
 * @return QUIC_CRYPTO_OK if key update processed successfully,
 *         error code if update is invalid.
 */
extern SocketQUICCrypto_Result
SocketQUICKeyUpdate_process_received (SocketQUICKeyUpdate_T *state,
                                      int received_phase);

/**
 * @brief Get keys for decrypting a packet based on key phase.
 *
 * Returns the appropriate keys for decryption considering:
 * - Current keys (key phase matches)
 * - Next keys (key phase differs, peer initiated update)
 * - Previous keys (for delayed packets after key update)
 *
 * Uses packet number to disambiguate when key phase matches but
 * could be previous or next generation.
 *
 * @param state            Key update state.
 * @param received_phase   Key phase bit from received packet.
 * @param packet_number    Recovered packet number.
 * @param keys             Output: pointer to appropriate keys.
 *
 * @return QUIC_CRYPTO_OK if keys found, error otherwise.
 */
extern SocketQUICCrypto_Result
SocketQUICKeyUpdate_get_read_keys (const SocketQUICKeyUpdate_T *state,
                                   int received_phase,
                                   uint64_t packet_number,
                                   const SocketQUICPacketKeys_T **keys);

/**
 * @brief Record that a packet was sent (for key update tracking).
 *
 * Updates the lowest packet number for current key phase if needed.
 *
 * @param state         Key update state.
 * @param packet_number Packet number of sent packet.
 */
extern void SocketQUICKeyUpdate_on_packet_sent (SocketQUICKeyUpdate_T *state,
                                                uint64_t packet_number);

/**
 * @brief Record that an acknowledgment was received.
 *
 * Updates highest acknowledged packet number and checks if key
 * update is now permitted.
 *
 * @param state         Key update state.
 * @param acked_pn      Highest packet number acknowledged.
 */
extern void SocketQUICKeyUpdate_on_ack_received (SocketQUICKeyUpdate_T *state,
                                                 uint64_t acked_pn);

/**
 * @brief Record successful packet encryption.
 *
 * Increments encrypted packet counter for AEAD limit tracking.
 *
 * @param state Key update state.
 */
extern void SocketQUICKeyUpdate_on_encrypt (SocketQUICKeyUpdate_T *state);

/**
 * @brief Record successful packet decryption.
 *
 * Increments decrypted packet counter for AEAD limit tracking.
 *
 * @param state Key update state.
 */
extern void SocketQUICKeyUpdate_on_decrypt (SocketQUICKeyUpdate_T *state);

/**
 * @brief Record failed packet decryption.
 *
 * Increments failure counter for AEAD integrity limit tracking.
 *
 * @param state Key update state.
 */
extern void
SocketQUICKeyUpdate_on_decrypt_failure (SocketQUICKeyUpdate_T *state);

/**
 * @brief Check if AEAD confidentiality limit requires key update.
 *
 * Returns true if encrypted packet count is approaching the limit
 * for the current AEAD algorithm.
 *
 * @param state Key update state.
 *
 * @return 1 if key update should be initiated, 0 otherwise.
 */
extern int SocketQUICKeyUpdate_confidentiality_limit_reached (
    const SocketQUICKeyUpdate_T *state);

/**
 * @brief Check if AEAD integrity limit is exceeded.
 *
 * If true, the connection MUST be closed with AEAD_LIMIT_REACHED.
 *
 * @param state Key update state.
 *
 * @return 1 if integrity limit exceeded, 0 otherwise.
 */
extern int SocketQUICKeyUpdate_integrity_limit_exceeded (
    const SocketQUICKeyUpdate_T *state);

/**
 * @brief Get confidentiality limit for an AEAD algorithm.
 *
 * @param aead AEAD algorithm.
 *
 * @return Maximum packets that can be encrypted, or UINT64_MAX if no limit.
 */
extern uint64_t
SocketQUICCrypto_get_confidentiality_limit (SocketQUIC_AEAD aead);

/**
 * @brief Get integrity limit for an AEAD algorithm.
 *
 * @param aead AEAD algorithm.
 *
 * @return Maximum failed decryptions allowed.
 */
extern uint64_t SocketQUICCrypto_get_integrity_limit (SocketQUIC_AEAD aead);

/**
 * @brief Extract Key Phase bit from short header packet.
 *
 * @param first_byte First byte of short header packet.
 *
 * @return Key phase bit value (0 or 1).
 */
static inline int
SocketQUICCrypto_get_key_phase (uint8_t first_byte)
{
  return (first_byte & QUIC_KEY_PHASE_BIT) ? 1 : 0;
}

/**
 * @brief Set Key Phase bit in short header packet.
 *
 * @param first_byte Pointer to first byte of short header.
 * @param phase      Key phase bit value (0 or 1).
 */
static inline void
SocketQUICCrypto_set_key_phase (uint8_t *first_byte, int phase)
{
  if (phase)
    *first_byte |= QUIC_KEY_PHASE_BIT;
  else
    *first_byte &= (uint8_t)~QUIC_KEY_PHASE_BIT;
}

/** @} */ /* End of quic_key_update group */

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

/**
 * @brief Get string representation of result code.
 *
 * @param result Result code to convert.
 *
 * @return Human-readable string describing the result.
 */
extern const char *
SocketQUICCrypto_result_string (SocketQUICCrypto_Result result);

/** @} */

#endif /* SOCKETQUICCRYPTO_INCLUDED */
