/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICCrypto.h
 * @brief QUIC Initial Secrets Derivation (RFC 9001 Section 5.2).
 *
 * Provides cryptographic key derivation for QUIC Initial packets. Keys are
 * derived from the client's Destination Connection ID using HKDF-Extract
 * and HKDF-Expand-Label per RFC 9001.
 *
 * Derivation process:
 *   1. HKDF-Extract(salt, DCID) -> initial_secret
 *   2. HKDF-Expand-Label(initial_secret, "client in", "") -> client_initial_secret
 *   3. HKDF-Expand-Label(initial_secret, "server in", "") -> server_initial_secret
 *   4. HKDF-Expand-Label(client_initial_secret, "quic key", "") -> client_key
 *   5. HKDF-Expand-Label(client_initial_secret, "quic iv", "")  -> client_iv
 *   6. HKDF-Expand-Label(client_initial_secret, "quic hp", "")  -> client_hp_key
 *   7. (Repeat 4-6 for server using server_initial_secret)
 *
 * Thread Safety: All functions are thread-safe (no shared state).
 *
 * @defgroup quic_crypto QUIC Cryptographic Module
 * @{
 * @see https://www.rfc-editor.org/rfc/rfc9001#section-5.2
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
  QUIC_CRYPTO_OK = 0,          /**< Operation succeeded */
  QUIC_CRYPTO_ERROR_NULL,      /**< NULL pointer argument */
  QUIC_CRYPTO_ERROR_VERSION,   /**< Unsupported QUIC version */
  QUIC_CRYPTO_ERROR_HKDF,      /**< HKDF operation failed */
  QUIC_CRYPTO_ERROR_NO_TLS     /**< TLS support not available */
} SocketQUICCrypto_Result;

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
extern void
SocketQUICCryptoSecrets_clear (SocketQUICCryptoSecrets_T *secrets);

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
