/**
 * @file SocketCrypto.h
 * @ingroup foundation
 * @brief Cryptographic utility functions for secure operations.
 *
 * Provides essential crypto primitives as thin wrappers around OpenSSL (or
 * fallbacks when #SOCKET_HAS_TLS is 0). Used across HTTP, WebSocket, TLS,
 * and security modules.
 *
 * Key features:
 * - Hashing: SHA-1/256, MD5 (with security warnings)
 * - HMAC-SHA256 for authentication
 * - Encoding: Base64 (RFC 4648), Hex
 * - Secure RNG for keys/nonces
 * - WebSocket handshake crypto (RFC 6455)
 * - Timing-safe comparisons and secure memory clearing
 *
 * All functions are thread-safe with no global mutable state.
 *
 * Security guidance:
 * - Prefer SHA-256/HMAC over legacy SHA-1/MD5 except where protocol requires.
 * - Always clear sensitive data with @ref SocketCrypto_secure_clear().
 * - Use @ref SocketCrypto_secure_compare() for MAC/hash validation.
 *
 * @see @ref foundation "Foundation module" for base infrastructure.
 * @see SocketCrypto_sha256() primary hashing function.
 * @see SocketCrypto_hmac_sha256() for message authentication.
 * @see SocketCrypto_random_bytes() for secure randomness.
 * @see SocketCrypto_base64_encode() for data encoding.
 * @see @ref http "HTTP module" for protocol integration.
 * @see @ref security "Security module" for TLS/crypto consumers.
 * @see SocketWS for WebSocket-specific usage.
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

/**
 * @brief Size of SHA-1 digest in bytes.
 * @ingroup foundation
 *
 * Standard SHA-1 output length (20 bytes / 160 bits).
 *
 * @see SocketCrypto_sha1()
 */
#define SOCKET_CRYPTO_SHA1_SIZE 20

/**
 * @brief Size of SHA-256 digest in bytes.
 * @ingroup foundation
 *
 * Standard SHA-256 output length (32 bytes / 256 bits).
 *
 * @see SocketCrypto_sha256()
 * @see SocketCrypto_hmac_sha256()
 */
#define SOCKET_CRYPTO_SHA256_SIZE 32

/**
 * @brief Size of MD5 digest in bytes.
 * @ingroup foundation
 *
 * Standard MD5 output length (16 bytes / 128 bits).
 * Note: MD5 is deprecated for security-critical uses.
 *
 * @see SocketCrypto_md5()
 */
#define SOCKET_CRYPTO_MD5_SIZE 16

/**
 * @brief Fixed GUID string for WebSocket Sec-WebSocket-Accept computation (RFC 6455).
 * @ingroup foundation
 *
 * Magic GUID concatenated with client key for SHA-1 hashing in server handshake.
 * Per RFC 6455 Section 4.2.2.
 *
 * @see SocketCrypto_websocket_accept()
 * @see SocketWS for WebSocket implementation.
 */
#define SOCKET_CRYPTO_WEBSOCKET_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/**
 * @brief Size of Sec-WebSocket-Key string buffer (Base64-encoded).
 * @ingroup foundation
 *
 * 16 random bytes Base64-encoded to 24 chars + null terminator = 25 bytes.
 * Per RFC 6455 Section 4.1.
 *
 * @see SocketCrypto_websocket_key()
 */
#define SOCKET_CRYPTO_WEBSOCKET_KEY_SIZE 25

/**
 * @brief Size of Sec-WebSocket-Accept string buffer (Base64-encoded).
 * @ingroup foundation
 *
 * SHA-1 digest (20 bytes) Base64-encoded to 28 chars + null terminator = 29 bytes.
 * Per RFC 6455 Section 4.2.2.
 *
 * @see SocketCrypto_websocket_accept()
 */
#define SOCKET_CRYPTO_WEBSOCKET_ACCEPT_SIZE 29

/* ============================================================================
 * Exception Types
 * ============================================================================
 */

/**
 * @brief General exception for cryptographic operation failures.
 * @ingroup foundation
 *
 * Thrown when cryptographic operations fail due to:
 * - Underlying library errors (e.g., OpenSSL API failures)
 * - Invalid parameters (null pointers, out-of-bounds lengths)
 * - Resource constraints (buffer too small, allocation limits)
 * - Missing crypto support (SOCKET_HAS_TLS == 0)
 *
 * @see Except_T for C exception handling mechanism.
 * @see SocketCrypto functions that may throw this exception.
 */
extern const Except_T SocketCrypto_Failed;

/* ============================================================================
 * Hash Functions
 * ============================================================================
 */

/**
 * @brief Compute SHA-1 hash of input data (RFC 3174).
 * @ingroup foundation
 *
 * Computes the SHA-1 message digest of the input data.
 *
 * Security: SHA-1 is cryptographically broken for signatures but acceptable
 * for WebSocket Sec-WebSocket-Accept computation per RFC 6455.
 *
 * @param input Input data.
 * @param input_len Length of input data in bytes (must not exceed
 * @ref SOCKET_SECURITY_MAX_ALLOCATION).
 * @param output Output buffer (must be at least SOCKET_CRYPTO_SHA1_SIZE bytes).
 *
 * @throws SocketCrypto_Failed on error or if TLS not available.
 * @threadsafe Yes.
 *
 * @see SocketCrypto_sha256() for a stronger alternative.
 * @see SocketCrypto_websocket_accept() for WebSocket usage.
 */
extern void SocketCrypto_sha1 (const void *input, size_t input_len,
                               unsigned char output[SOCKET_CRYPTO_SHA1_SIZE]);

/**
 * @brief Compute SHA-256 hash of input data (FIPS 180-4).
 * @ingroup foundation
 *
 * Computes the SHA-256 message digest of the input data.
 *
 * @param input Input data.
 * @param input_len Length of input data in bytes (must not exceed
 * @ref SOCKET_SECURITY_MAX_ALLOCATION).
 * @param output Output buffer (must be at least SOCKET_CRYPTO_SHA256_SIZE bytes).
 *
 * @throws SocketCrypto_Failed on error or if TLS not available.
 * @threadsafe Yes.
 *
 * @see SocketCrypto_sha1() for legacy compatibility.
 * @see SocketCrypto_hmac_sha256() for message authentication.
 */
extern void
SocketCrypto_sha256 (const void *input, size_t input_len,
                     unsigned char output[SOCKET_CRYPTO_SHA256_SIZE]);

/**
 * @brief Compute MD5 hash of input data (RFC 1321).
 * @ingroup foundation
 *
 * Computes the MD5 message digest of the input data.
 *
 * Security: MD5 is cryptographically broken. Only use where required by
 * specification (e.g., HTTP Digest authentication per RFC 7616).
 *
 * @param input Input data.
 * @param input_len Length of input data in bytes (must not exceed
 * @ref SOCKET_SECURITY_MAX_ALLOCATION).
 * @param output Output buffer (must be at least SOCKET_CRYPTO_MD5_SIZE bytes).
 *
 * @throws SocketCrypto_Failed on error or if TLS not available.
 * @threadsafe Yes.
 *
 * @see SocketHTTPClient for HTTP authentication usage.
 * @see SocketCrypto_sha256() for secure alternative.
 */
extern void SocketCrypto_md5 (const void *input, size_t input_len,
                              unsigned char output[SOCKET_CRYPTO_MD5_SIZE]);

/* ============================================================================
 * HMAC Functions
 * ============================================================================
 */

/**
 * @brief Compute HMAC-SHA256 message authentication code.
 * @ingroup foundation
 *
 * Computes HMAC-SHA256 (RFC 2104, FIPS 198-1) of data using the given key.
 *
 * Used for cookie signing, session tokens, and message authentication.
 *
 * Security: Provides integrity and authenticity. Key should be at least 32 bytes
 * for full security.
 *
 * @param key HMAC key.
 * @param key_len Key length in bytes (recommended: 32+ bytes).
 * @param data Input data to authenticate.
 * @param data_len Data length in bytes (must not exceed
 * @ref SOCKET_SECURITY_MAX_ALLOCATION).
 * @param output Output buffer (must be at least SOCKET_CRYPTO_SHA256_SIZE bytes).
 *
 * @throws SocketCrypto_Failed on error or if TLS not available.
 * @threadsafe Yes.
 *
 * @see SocketCrypto_sha256() for plain hashing without key.
 * @see SocketHTTPServer for cookie signing examples.
 */
extern void
SocketCrypto_hmac_sha256 (const void *key, size_t key_len, const void *data,
                          size_t data_len,
                          unsigned char output[SOCKET_CRYPTO_SHA256_SIZE]);

/* ============================================================================
 * Base64 Encoding (RFC 4648)
 * ============================================================================
 */

/**
 * @brief Encode binary data to Base64 string (RFC 4648).
 * @ingroup foundation
 *
 * Encodes binary data as Base64 string per RFC 4648. Output is null-terminated.
 *
 * Required buffer size: ((input_len + 2) / 3) * 4 + 1 bytes.
 * Use @ref SocketCrypto_base64_encoded_size() to calculate required size.
 *
 * @param input Input binary data.
 * @param input_len Length of input data in bytes (must not exceed
 * @ref SOCKET_SECURITY_MAX_ALLOCATION).
 * @param output Output buffer for null-terminated Base64 string.
 * @param output_size Size of output buffer in bytes (must be sufficient).
 *
 * @return Length of encoded string (excluding null terminator) on success,
 * or -1 on error (insufficient output size or invalid input).
 * @throws SocketCrypto_Failed if TLS not available or internal error.
 * @threadsafe Yes.
 *
 * @see SocketCrypto_base64_decode() for decoding.
 * @see SocketCrypto_base64_encoded_size() for buffer sizing.
 * @see SocketWS for WebSocket key generation.
 */
extern ssize_t SocketCrypto_base64_encode (const void *input, size_t input_len,
                                           char *output, size_t output_size);

/**
 * @brief Decode Base64-encoded string to binary data (RFC 4648).
 * @ingroup foundation
 *
 * Decodes Base64 string to binary data per RFC 4648.
 *
 * Supports:
 * - Standard Base64 alphabet (A-Za-z0-9+/).
 * - URL-safe variant (-_ instead of +/) per RFC 4648 Section 5.
 * - Padding with '=' characters.
 * - Ignores whitespace per RFC 4648 Section 3.3.
 *
 * @param input Base64-encoded input string.
 * @param input_len Length of input (0 for null-terminated string auto-detection).
 * @param output Output buffer for decoded binary data.
 * @param output_size Size of output buffer in bytes (use
 * @ref SocketCrypto_base64_decoded_size() for max size).
 *
 * @return Length of decoded data on success, or -1 on error (invalid Base64 input,
 * insufficient output size).
 * @throws SocketCrypto_Failed if TLS not available or internal error.
 * @threadsafe Yes.
 *
 * @see SocketCrypto_base64_encode() for encoding.
 * @see SocketCrypto_base64_decoded_size() for buffer sizing.
 * @see SocketHTTP for header value decoding.
 */
extern ssize_t SocketCrypto_base64_decode (const char *input, size_t input_len,
                                           unsigned char *output,
                                           size_t output_size);

/**
 * @brief Calculate buffer size required for Base64 encoding.
 * @ingroup foundation
 *
 * Computes the exact buffer size needed for @ref SocketCrypto_base64_encode(),
 * including space for null terminator.
 *
 * Formula: ((input_len + 2) / 3) * 4 + 1
 *
 * @param input_len Length of input data in bytes (must not exceed
 * @ref SOCKET_SECURITY_MAX_ALLOCATION).
 *
 * @return Required output buffer size in bytes, including null terminator.
 * @threadsafe Yes.
 *
 * @see SocketCrypto_base64_encode() for encoding.
 * @see SocketCrypto_base64_decoded_size() for decoding size calculation.
 */
extern size_t SocketCrypto_base64_encoded_size (size_t input_len);

/**
 * @brief Calculate maximum buffer size needed for Base64 decoding.
 * @ingroup foundation
 *
 * Computes the maximum possible decoded size for @ref SocketCrypto_base64_decode().
 * Actual decoded size may be smaller due to padding.
 *
 * Formula: (input_len * 3 / 4) rounded up, excluding padding.
 *
 * @param input_len Length of Base64 input string in bytes.
 *
 * @return Maximum possible decoded binary size in bytes.
 * @threadsafe Yes.
 *
 * @see SocketCrypto_base64_decode() for decoding.
 * @see SocketCrypto_base64_encoded_size() for encoding size.
 */
extern size_t SocketCrypto_base64_decoded_size (size_t input_len);

/* ============================================================================
 * Hexadecimal Encoding
 * ============================================================================
 */

/**
 * @brief Encode binary data to hexadecimal string.
 * @ingroup foundation
 *
 * Encodes binary data as hexadecimal string (null-terminated).
 * Each byte becomes two hex digits.
 *
 * Required output buffer size: input_len * 2 + 1 bytes.
 *
 * @param input Input binary data.
 * @param input_len Length of input in bytes (must not exceed
 * @ref SOCKET_SECURITY_MAX_ALLOCATION / 2 for output fit).
 * @param output Output buffer for null-terminated hex string.
 * @param lowercase Non-zero for lowercase (a-f), zero for uppercase (A-F).
 *
 * @threadsafe Yes.
 *
 * @see SocketCrypto_hex_decode() for decoding.
 * @see SocketCrypto_base64_encode() for alternative encoding.
 */
extern void SocketCrypto_hex_encode (const void *input, size_t input_len,
                                     char *output, int lowercase);

/**
 * @brief Decode hexadecimal string to binary data.
 * @ingroup foundation
 *
 * Decodes null-terminated or length-specified hex string to binary data.
 * Accepts both uppercase (A-F) and lowercase (a-f) digits.
 *
 * Input length must be even. Invalid characters cause error.
 *
 * Required output capacity: input_len / 2 bytes.
 *
 * @param input Hex-encoded input string.
 * @param input_len Length of input string (0 for null-terminated auto-detect;
 * must be even).
 * @param output Output buffer for decoded binary data.
 * @param output_capacity Capacity of output buffer in bytes (at least
 * input_len / 2).
 *
 * @return Number of decoded bytes on success (min(input_len / 2, output_capacity)),
 * or -1 on error (odd length, invalid chars, insufficient capacity).
 * @threadsafe Yes.
 *
 * @see SocketCrypto_hex_encode() for encoding.
 * @see SocketCrypto_secure_compare() for comparing decoded values securely.
 */
extern ssize_t SocketCrypto_hex_decode (const char *input, size_t input_len,
                                        unsigned char *output,
                                        size_t output_capacity);

/* ============================================================================
 * Random Number Generation
 * ============================================================================
 */

/**
 * @brief Generate cryptographically secure random bytes.
 * @ingroup foundation
 *
 * Fills output buffer with cryptographically secure random bytes.
 * Uses OpenSSL RAND_bytes() if available, falls back to /dev/urandom or
 * equivalent secure source.
 *
 * @param output Output buffer to fill with random bytes.
 * @param len Number of bytes to generate (must not exceed
 * @ref SOCKET_SECURITY_MAX_ALLOCATION).
 *
 * @return 0 on success, -1 on error (RNG failure or insufficient entropy).
 * @throws SocketCrypto_Failed on internal error.
 * @threadsafe Yes.
 *
 * @see SocketCrypto_random_uint32() for 32-bit random integers.
 * @see SocketCrypto_websocket_key() for WebSocket key generation.
 * @see @ref security "Security module" for TLS session randomness.
 */
extern int SocketCrypto_random_bytes (void *output, size_t len);

/**
 * @brief Generate a cryptographically secure 32-bit random integer.
 * @ingroup foundation
 *
 * Produces a uniform random uint32_t using secure RNG source.
 *
 * @return Random uint32_t value (0 to UINT32_MAX).
 * @throws SocketCrypto_Failed on RNG failure.
 * @threadsafe Yes.
 *
 * @see SocketCrypto_random_bytes() for arbitrary-length randomness.
 * @see SocketRateLimit for using random in token bucket jitter.
 */
extern uint32_t SocketCrypto_random_uint32 (void);

/* ============================================================================
 * WebSocket Handshake Helpers (RFC 6455)
 * ============================================================================
 */

/**
 * @brief Compute Sec-WebSocket-Accept value for server handshake (RFC 6455).
 * @ingroup foundation
 *
 * Validates client Sec-WebSocket-Key by computing base64(SHA1(key + GUID)),
 * where GUID is "258EAFA5-E914-47DA-95CA-C5AB0DC85B11".
 * Per RFC 6455 Section 4.2.2 server handshake.
 *
 * @param client_key Client-provided Sec-WebSocket-Key (24 chars Base64).
 * @param output Output buffer (must be at least
 * @ref SOCKET_CRYPTO_WEBSOCKET_ACCEPT_SIZE bytes; null-terminated on success).
 *
 * @return 0 on success, -1 on error (invalid key length or crypto failure).
 * @throws SocketCrypto_Failed on internal crypto error.
 * @threadsafe Yes.
 *
 * @see SocketCrypto_websocket_key() for client key generation.
 * @see SocketWS for full WebSocket protocol implementation.
 */
extern int SocketCrypto_websocket_accept (
    const char *client_key, char output[SOCKET_CRYPTO_WEBSOCKET_ACCEPT_SIZE]);

/**
 * @brief Generate random Sec-WebSocket-Key for client handshake (RFC 6455).
 * @ingroup foundation
 *
 * Generates 16 cryptographically secure random bytes, Base64-encodes them to
 * 24 characters, and null-terminates the output.
 * Per RFC 6455 Section 4.1 client handshake.
 *
 * @param output Output buffer (must be at least
 * @ref SOCKET_CRYPTO_WEBSOCKET_KEY_SIZE bytes; null-terminated on success).
 *
 * @return 0 on success, -1 on error (RNG failure).
 * @throws SocketCrypto_Failed on internal error.
 * @threadsafe Yes.
 *
 * @see SocketCrypto_websocket_accept() for server validation.
 * @see SocketWS for WebSocket client connections.
 */
extern int
SocketCrypto_websocket_key (char output[SOCKET_CRYPTO_WEBSOCKET_KEY_SIZE]);

/* ============================================================================
 * Security Utilities
 * ============================================================================
 */

/**
 * @brief Perform constant-time comparison of two buffers.
 * @ingroup foundation
 *
 * Compares two memory buffers in constant time, regardless of content, to
 * prevent timing side-channel attacks.
 * Essential for comparing MACs, hashes, signatures, or other security-sensitive
 * data where early exits could leak information.
 *
 * @param a First buffer.
 * @param b Second buffer.
 * @param len Number of bytes to compare (0 returns 0).
 *
 * @return 0 if buffers are equal, non-zero otherwise.
 * @threadsafe Yes.
 *
 * @see SocketCrypto_hmac_sha256() for generating comparison values.
 * @see SocketCrypto_secure_clear() for cleaning sensitive data after comparison.
 * @see @ref security "Security module" for protection mechanisms.
 */
extern int SocketCrypto_secure_compare (const void *a, const void *b,
                                        size_t len);

/**
 * @brief Securely clear sensitive data from memory.
 * @ingroup foundation
 *
 * Overwrites memory buffer with zeros using volatile operations and memory
 * barriers to prevent compiler optimizations from eliminating the clear.
 * Essential for securely erasing passwords, private keys, and other sensitive
 * data from memory.
 *
 * @param ptr Buffer containing sensitive data to clear.
 * @param len Length of buffer in bytes.
 *
 * @threadsafe Yes.
 * @note Does not clear file system or swap; use full secure erase for that.
 *
 * @see SocketBuf_secureclear() for buffer-specific clearing.
 * @see SocketCrypto_random_bytes() for generating sensitive data.
 * @see @ref security "Security module" for data protection best practices.
 */
extern void SocketCrypto_secure_clear (void *ptr, size_t len);

#endif /* SOCKETCRYPTO_INCLUDED */
