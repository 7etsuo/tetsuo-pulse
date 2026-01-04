/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketCrypto.h
 * @brief Cryptographic utility functions for secure operations.
 * @ingroup foundation
 *
 * Provides crypto primitives (hashing, HMAC, Base64/hex encoding, secure RNG,
 * WebSocket handshake helpers, constant-time comparisons) as thin wrappers
 * around OpenSSL or fallbacks when TLS unavailable. All functions thread-safe.
 */

#ifndef SOCKETCRYPTO_INCLUDED
#define SOCKETCRYPTO_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "core/Except.h"

/* ============================================================================
 * Constants
 * ============================================================================
 */

/** @brief SHA-1 digest size in bytes. */
#define SOCKET_CRYPTO_SHA1_SIZE 20

/** @brief SHA-256 digest size in bytes. */
#define SOCKET_CRYPTO_SHA256_SIZE 32

/** @brief MD5 digest size in bytes. */
#define SOCKET_CRYPTO_MD5_SIZE 16

/** @brief WebSocket GUID for Sec-WebSocket-Accept (RFC 6455). */
#define SOCKET_CRYPTO_WEBSOCKET_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/** @brief Sec-WebSocket-Key buffer size (Base64-encoded). */
#define SOCKET_CRYPTO_WEBSOCKET_KEY_SIZE 25

/** @brief Sec-WebSocket-Accept buffer size (Base64-encoded). */
#define SOCKET_CRYPTO_WEBSOCKET_ACCEPT_SIZE 29

/* ============================================================================
 * Exception Types
 * ============================================================================
 */

/**
 * @brief Exception for cryptographic operation failures.
 *
 * Raised on: library errors, invalid parameters, resource constraints, or
 * missing crypto support (SOCKET_HAS_TLS == 0).
 */
extern const Except_T SocketCrypto_Failed;

/* ============================================================================
 * Hash Functions
 * ============================================================================
 */

/**
 * @brief Compute SHA-1 hash of input data (RFC 3174).
 *
 * @param[in] input Input data to hash.
 * @param[in] input_len Length of input data in bytes.
 * @param[out] output Output buffer (SOCKET_CRYPTO_SHA1_SIZE bytes).
 *
 * Raises: SocketCrypto_Failed on error or if TLS not available.
 * @threadsafe Yes.
 * @complexity O(input_len)
 */
extern void SocketCrypto_sha1 (const void *input,
                               size_t input_len,
                               unsigned char output[SOCKET_CRYPTO_SHA1_SIZE]);

/**
 * @brief Compute SHA-256 hash of input data (FIPS 180-4).
 *
 * @param[in] input Input data to hash.
 * @param[in] input_len Length of input data in bytes.
 * @param[out] output Output buffer (SOCKET_CRYPTO_SHA256_SIZE bytes).
 *
 * Raises: SocketCrypto_Failed on error or if TLS not available.
 * @threadsafe Yes.
 * @complexity O(input_len)
 */
extern void
SocketCrypto_sha256 (const void *input,
                     size_t input_len,
                     unsigned char output[SOCKET_CRYPTO_SHA256_SIZE]);

/**
 * @brief Compute MD5 hash of input data (RFC 1321).
 *
 * @param[in] input Input data to hash.
 * @param[in] input_len Length of input data in bytes.
 * @param[out] output Output buffer (SOCKET_CRYPTO_MD5_SIZE bytes).
 *
 * Raises: SocketCrypto_Failed on error or if TLS not available.
 * @threadsafe Yes.
 */
extern void SocketCrypto_md5 (const void *input,
                              size_t input_len,
                              unsigned char output[SOCKET_CRYPTO_MD5_SIZE]);

/* ============================================================================
 * HMAC Functions
 * ============================================================================
 */

/**
 * @brief Compute HMAC-SHA256 message authentication code (RFC 2104, FIPS
 * 198-1).
 *
 * @param[in] key HMAC key (should be cryptographically strong random bytes).
 * @param[in] key_len Key length in bytes (recommended: >= 32 bytes).
 * @param[in] data Input data to authenticate.
 * @param[in] data_len Data length in bytes.
 * @param[out] output Output buffer (SOCKET_CRYPTO_SHA256_SIZE bytes).
 *
 * Raises: SocketCrypto_Failed on error or if TLS not available.
 * @threadsafe Yes.
 */
extern void
SocketCrypto_hmac_sha256 (const void *key,
                          size_t key_len,
                          const void *data,
                          size_t data_len,
                          unsigned char output[SOCKET_CRYPTO_SHA256_SIZE]);

/* ============================================================================
 * HKDF Functions (RFC 5869)
 * ============================================================================
 */

/**
 * @brief HKDF-Extract: Extract a PRK from salt and IKM (RFC 5869 §2.2).
 *
 * PRK = HMAC-SHA256(salt, IKM)
 *
 * @param[in] salt Salt value (can be NULL for zero-length salt).
 * @param[in] salt_len Salt length in bytes.
 * @param[in] ikm Input Keying Material.
 * @param[in] ikm_len IKM length in bytes.
 * @param[out] prk Output PRK buffer (SOCKET_CRYPTO_SHA256_SIZE bytes).
 *
 * Raises: SocketCrypto_Failed on error or if TLS not available.
 * @threadsafe Yes.
 */
extern void
SocketCrypto_hkdf_extract (const void *salt,
                           size_t salt_len,
                           const void *ikm,
                           size_t ikm_len,
                           unsigned char prk[SOCKET_CRYPTO_SHA256_SIZE]);

/**
 * @brief HKDF-Expand-Label: TLS 1.3 style key derivation (RFC 8446 §7.1).
 *
 * Constructs HkdfLabel and expands PRK to output_len bytes.
 * Used by QUIC for "quic key", "quic iv", "quic hp", "quic ku" labels.
 *
 * @param[in] prk Pseudorandom key from HKDF-Extract.
 * @param[in] prk_len PRK length (typically SOCKET_CRYPTO_SHA256_SIZE).
 * @param[in] label Label string WITHOUT "tls13 " prefix (added internally).
 * @param[in] context Context data (can be NULL for empty context).
 * @param[in] context_len Context length in bytes.
 * @param[out] output Output buffer.
 * @param[in] output_len Desired output length (max 255 bytes).
 *
 * Raises: SocketCrypto_Failed on error or if TLS not available.
 * @threadsafe Yes.
 */
extern void SocketCrypto_hkdf_expand_label (const unsigned char *prk,
                                            size_t prk_len,
                                            const char *label,
                                            const void *context,
                                            size_t context_len,
                                            unsigned char *output,
                                            size_t output_len);

/* ============================================================================
 * Base64 Encoding (RFC 4648)
 * ============================================================================
 */

/**
 * @brief Encode binary data to Base64 string (RFC 4648).
 *
 * @param[in] input Input binary data.
 * @param[in] input_len Length in bytes.
 * @param[out] output Output buffer (null-terminated).
 * @param[in] output_size Buffer size (use SocketCrypto_base64_encoded_size()).
 *
 * Returns: Encoded length (excluding null) on success, -1 on error.
 * Raises: SocketCrypto_Failed if TLS not available or internal error.
 * @threadsafe Yes.
 */
extern ssize_t SocketCrypto_base64_encode (const void *input,
                                           size_t input_len,
                                           char *output,
                                           size_t output_size);

/**
 * @brief Decode Base64 string to binary data (RFC 4648).
 *
 * @param[in] input Base64 string (null-terminated if input_len == 0).
 * @param[in] input_len Length (0 for auto-detection).
 * @param[out] output Output buffer.
 * @param[in] output_size Buffer size.
 *
 * Returns: Decoded length on success, -1 on error.
 * Raises: SocketCrypto_Failed if TLS not available or internal error.
 * @threadsafe Yes.
 */
extern ssize_t SocketCrypto_base64_decode (const char *input,
                                           size_t input_len,
                                           unsigned char *output,
                                           size_t output_size);

/**
 * @brief Calculate buffer size for Base64 encoding.
 *
 * @param[in] input_len Input data length.
 * Returns: Required buffer size including null terminator.
 * @threadsafe Yes.
 */
extern size_t SocketCrypto_base64_encoded_size (size_t input_len);

/**
 * @brief Calculate maximum buffer size for Base64 decoding.
 *
 * @param[in] input_len Base64 string length.
 * Returns: Maximum decoded size.
 * @threadsafe Yes.
 */
extern size_t SocketCrypto_base64_decoded_size (size_t input_len);

/* ============================================================================
 * Hexadecimal Encoding
 * ============================================================================
 */

/**
 * @brief Encode binary data to hexadecimal string.
 *
 * @param[in] input Input binary data.
 * @param[in] input_len Length in bytes.
 * @param[out] output Output buffer (null-terminated, size: input_len * 2 + 1).
 * @param[in] lowercase 1 for lowercase (a-f), 0 for uppercase (A-F).
 *
 * @threadsafe Yes.
 */
extern void SocketCrypto_hex_encode (const void *input,
                                     size_t input_len,
                                     char *output,
                                     int lowercase);

/**
 * @brief Decode hexadecimal string to binary data.
 *
 * @param[in] input Hex string (0 for auto-detect; must be even length).
 * @param[in] input_len Length (0 for auto-detection via null terminator).
 * @param[out] output Output buffer (size: input_len / 2).
 * @param[in] output_capacity Buffer capacity in bytes.
 *
 * Returns: Decoded bytes on success, -1 on error.
 * @threadsafe Yes.
 */
extern ssize_t SocketCrypto_hex_decode (const char *input,
                                        size_t input_len,
                                        unsigned char *output,
                                        size_t output_capacity);

/* ============================================================================
 * Random Number Generation
 * ============================================================================
 */

/**
 * @brief Generate cryptographically secure random bytes.
 *
 * @param[out] output Output buffer.
 * @param[in] len Number of bytes to generate.
 *
 * Returns: 0 on success, -1 on error.
 * Raises: SocketCrypto_Failed on internal error.
 * @threadsafe Yes.
 */
extern int SocketCrypto_random_bytes (void *output, size_t len);

/**
 * @brief Generate a cryptographically secure 32-bit random integer.
 *
 * Returns: Random uint32_t value.
 * Raises: SocketCrypto_Failed on RNG failure.
 * @threadsafe Yes.
 */
extern uint32_t SocketCrypto_random_uint32 (void);

/**
 * @brief Clean up internal cryptographic resources.
 *
 * Releases cached resources (e.g., /dev/urandom fd when TLS unavailable).
 * Safe to call multiple times.
 *
 * @threadsafe Yes.
 */
extern void SocketCrypto_cleanup (void);

/* ============================================================================
 * WebSocket Handshake Helpers (RFC 6455)
 * ============================================================================
 */

/**
 * @brief Compute Sec-WebSocket-Accept for server handshake (RFC 6455 §4.2.2).
 *
 * @param[in] client_key Client Sec-WebSocket-Key (Base64, 24 chars).
 * @param[out] output Output buffer (SOCKET_CRYPTO_WEBSOCKET_ACCEPT_SIZE bytes).
 *
 * Returns: 0 on success, -1 on error.
 * Raises: SocketCrypto_Failed on internal error.
 * @threadsafe Yes.
 */
extern int SocketCrypto_websocket_accept (
    const char *client_key, char output[SOCKET_CRYPTO_WEBSOCKET_ACCEPT_SIZE]);

/**
 * @brief Generate Sec-WebSocket-Key for client handshake (RFC 6455 §4.1).
 *
 * @param[out] output Output buffer (SOCKET_CRYPTO_WEBSOCKET_KEY_SIZE bytes).
 *
 * Returns: 0 on success, -1 on error.
 * Raises: SocketCrypto_Failed on internal error.
 * @threadsafe Yes.
 */
extern int
SocketCrypto_websocket_key (char output[SOCKET_CRYPTO_WEBSOCKET_KEY_SIZE]);

/* ============================================================================
 * Lifecycle Management
 * ============================================================================
 */

/**
 * @brief Cleanup cryptographic resources.
 *
 * Releases resources allocated by the SocketCrypto module. Safe to call
 * multiple times. After cleanup, subsequent SocketCrypto operations will
 * reinitialize resources as needed.
 *
 * - When SOCKET_HAS_TLS is defined: No operation (OpenSSL handles cleanup).
 * - When SOCKET_HAS_TLS is NOT defined: Closes the /dev/urandom file
 *   descriptor used for random number generation.
 *
 * Raises: SocketCrypto_Failed on mutex lock failure.
 * @threadsafe Yes (mutex protected).
 */
extern void SocketCrypto_cleanup (void);

/* ============================================================================
 * Security Utilities
 * ============================================================================
 */

/**
 * @brief Constant-time comparison to prevent timing attacks.
 *
 * @param[in] a First buffer.
 * @param[in] b Second buffer.
 * @param[in] len Bytes to compare.
 *
 * Returns: 0 if equal, non-zero otherwise.
 * @threadsafe Yes.
 */
extern int
SocketCrypto_secure_compare (const void *a, const void *b, size_t len);

/**
 * @brief Securely clear sensitive data from memory.
 *
 * @param[in,out] ptr Buffer to clear.
 * @param[in] len Buffer length in bytes.
 *
 * @threadsafe Yes.
 * @complexity O(len)
 */
extern void SocketCrypto_secure_clear (void *ptr, size_t len);

#endif /* SOCKETCRYPTO_INCLUDED */
