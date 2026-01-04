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
 * Key sizes depend on the AEAD algorithm:
 *   AES-128-GCM:       key=16, iv=12, hp=16
 *   AES-256-GCM:       key=32, iv=12, hp=32
 *   ChaCha20-Poly1305: key=32, iv=12, hp=32
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
  QUIC_CRYPTO_OK = 0,        /**< Operation succeeded */
  QUIC_CRYPTO_ERROR_NULL,    /**< NULL pointer argument */
  QUIC_CRYPTO_ERROR_VERSION, /**< Unsupported QUIC version */
  QUIC_CRYPTO_ERROR_HKDF,    /**< HKDF operation failed */
  QUIC_CRYPTO_ERROR_NO_TLS,  /**< TLS support not available */
  QUIC_CRYPTO_ERROR_AEAD     /**< Invalid AEAD algorithm */
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
