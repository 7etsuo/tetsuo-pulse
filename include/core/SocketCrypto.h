/**
 * SocketCrypto.h - Cryptographic Utilities for Socket Library
 *
 * Part of the Socket Library
 *
 * Provides cryptographic primitives required for HTTP/2, WebSocket, and
 * security features. Thin wrappers around OpenSSL with fallbacks when
 * TLS is disabled.
 *
 * Features:
 * - SHA-1, SHA-256, MD5 hash functions
 * - HMAC-SHA256 for message authentication
 * - Base64 encoding/decoding (RFC 4648)
 * - Hexadecimal encoding/decoding
 * - Cryptographically secure random number generation
 * - WebSocket handshake helpers (RFC 6455)
 * - Constant-time comparison for security-sensitive operations
 *
 * Thread safety: All functions are thread-safe (no global state).
 *
 * Security notes:
 * - SHA-1 and MD5 are cryptographically broken for signatures but
 *   acceptable for WebSocket handshake (RFC 6455) and HTTP Digest auth
 *   (RFC 7616) respectively, as required by those specifications.
 * - Use HMAC-SHA256 for new security-sensitive applications.
 * - All sensitive data is cleared from stack after use.
 */

#ifndef SOCKETCRYPTO_INCLUDED
#define SOCKETCRYPTO_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "core/Except.h"

/* ============================================================================
 * Constants
 * ============================================================================ */

/** SHA-1 digest size in bytes */
#define SOCKET_CRYPTO_SHA1_SIZE 20

/** SHA-256 digest size in bytes */
#define SOCKET_CRYPTO_SHA256_SIZE 32

/** MD5 digest size in bytes */
#define SOCKET_CRYPTO_MD5_SIZE 16

/** WebSocket GUID for Sec-WebSocket-Accept computation (RFC 6455 Section 4.2.2) */
#define SOCKET_CRYPTO_WEBSOCKET_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/** WebSocket key size (16 random bytes, base64 encoded = 24 chars + null) */
#define SOCKET_CRYPTO_WEBSOCKET_KEY_SIZE 25

/** WebSocket accept size (SHA1 base64 encoded = 28 chars + null) */
#define SOCKET_CRYPTO_WEBSOCKET_ACCEPT_SIZE 29

/* ============================================================================
 * Exception Types
 * ============================================================================ */

/**
 * SocketCrypto_Failed - General cryptographic operation failure
 *
 * Raised when:
 * - OpenSSL functions fail
 * - Invalid input parameters
 * - Buffer too small for output
 * - TLS not available (when SOCKET_HAS_TLS is not defined)
 */
extern const Except_T SocketCrypto_Failed;

/* ============================================================================
 * Hash Functions
 * ============================================================================ */

/**
 * SocketCrypto_sha1 - Compute SHA-1 hash (RFC 3174)
 * @input: Input data
 * @input_len: Length of input data in bytes
 * @output: Output buffer (must be at least SOCKET_CRYPTO_SHA1_SIZE bytes)
 *
 * Computes the SHA-1 message digest of the input data.
 *
 * Security: SHA-1 is cryptographically broken for signatures but
 * acceptable for WebSocket Sec-WebSocket-Accept computation per RFC 6455.
 *
 * Thread-safe: Yes
 * Raises: SocketCrypto_Failed on error or if TLS not available
 */
extern void SocketCrypto_sha1 (const void *input, size_t input_len,
                               unsigned char output[SOCKET_CRYPTO_SHA1_SIZE]);

/**
 * SocketCrypto_sha256 - Compute SHA-256 hash (FIPS 180-4)
 * @input: Input data
 * @input_len: Length of input data in bytes
 * @output: Output buffer (must be at least SOCKET_CRYPTO_SHA256_SIZE bytes)
 *
 * Computes the SHA-256 message digest of the input data.
 *
 * Thread-safe: Yes
 * Raises: SocketCrypto_Failed on error or if TLS not available
 */
extern void SocketCrypto_sha256 (const void *input, size_t input_len,
                                 unsigned char output[SOCKET_CRYPTO_SHA256_SIZE]);

/**
 * SocketCrypto_md5 - Compute MD5 hash (RFC 1321)
 * @input: Input data
 * @input_len: Length of input data in bytes
 * @output: Output buffer (must be at least SOCKET_CRYPTO_MD5_SIZE bytes)
 *
 * Computes the MD5 message digest of the input data.
 *
 * Security: MD5 is cryptographically broken. Only use where required
 * by specification (e.g., HTTP Digest authentication RFC 7616).
 *
 * Thread-safe: Yes
 * Raises: SocketCrypto_Failed on error or if TLS not available
 */
extern void SocketCrypto_md5 (const void *input, size_t input_len,
                              unsigned char output[SOCKET_CRYPTO_MD5_SIZE]);

/* ============================================================================
 * HMAC Functions
 * ============================================================================ */

/**
 * SocketCrypto_hmac_sha256 - Compute HMAC-SHA256
 * @key: HMAC key
 * @key_len: Key length in bytes
 * @data: Input data
 * @data_len: Data length in bytes
 * @output: Output buffer (must be at least SOCKET_CRYPTO_SHA256_SIZE bytes)
 *
 * Computes HMAC-SHA256 message authentication code.
 *
 * Used for: Cookie signing, session tokens, message authentication
 *
 * Thread-safe: Yes
 * Raises: SocketCrypto_Failed on error or if TLS not available
 */
extern void SocketCrypto_hmac_sha256 (const void *key, size_t key_len,
                                      const void *data, size_t data_len,
                                      unsigned char output[SOCKET_CRYPTO_SHA256_SIZE]);

/* ============================================================================
 * Base64 Encoding (RFC 4648)
 * ============================================================================ */

/**
 * SocketCrypto_base64_encode - Base64 encode data
 * @input: Input data
 * @input_len: Length of input data in bytes
 * @output: Output buffer for encoded string
 * @output_size: Size of output buffer in bytes
 *
 * Encodes binary data as Base64 string. Output is null-terminated.
 *
 * Required buffer size: ((input_len + 2) / 3) * 4 + 1
 * Use SocketCrypto_base64_encoded_size() to calculate.
 *
 * Returns: Length of encoded string (excluding null terminator), or -1 on error
 * Thread-safe: Yes
 */
extern ssize_t SocketCrypto_base64_encode (const void *input, size_t input_len,
                                           char *output, size_t output_size);

/**
 * SocketCrypto_base64_decode - Base64 decode data
 * @input: Base64 encoded string
 * @input_len: Length of input (0 to auto-detect from null terminator)
 * @output: Output buffer for decoded data
 * @output_size: Size of output buffer in bytes
 *
 * Decodes Base64 string to binary data.
 *
 * Handles:
 * - Standard Base64 alphabet (A-Za-z0-9+/)
 * - URL-safe Base64 variant (A-Za-z0-9-_) per RFC 4648 Section 5
 * - Padding with '=' characters
 * - Whitespace is ignored per RFC 4648 Section 3.3
 *
 * Returns: Length of decoded data, or -1 on error (invalid input)
 * Thread-safe: Yes
 */
extern ssize_t SocketCrypto_base64_decode (const char *input, size_t input_len,
                                           unsigned char *output,
                                           size_t output_size);

/**
 * SocketCrypto_base64_encoded_size - Calculate required encoded buffer size
 * @input_len: Length of input data in bytes
 *
 * Returns: Required buffer size including null terminator
 * Thread-safe: Yes
 */
extern size_t SocketCrypto_base64_encoded_size (size_t input_len);

/**
 * SocketCrypto_base64_decoded_size - Calculate maximum decoded size
 * @input_len: Length of Base64 string
 *
 * Returns: Maximum decoded size (actual may be less due to padding)
 * Thread-safe: Yes
 */
extern size_t SocketCrypto_base64_decoded_size (size_t input_len);

/* ============================================================================
 * Hexadecimal Encoding
 * ============================================================================ */

/**
 * SocketCrypto_hex_encode - Encode binary data as hexadecimal
 * @input: Input data
 * @input_len: Length of input in bytes
 * @output: Output buffer (must be at least input_len * 2 + 1 bytes)
 * @lowercase: Use lowercase hex digits (0) or uppercase (non-zero)
 *
 * Encodes binary data as hexadecimal string. Output is null-terminated.
 *
 * Thread-safe: Yes
 */
extern void SocketCrypto_hex_encode (const void *input, size_t input_len,
                                     char *output, int lowercase);

/**
 * SocketCrypto_hex_decode - Decode hexadecimal string
 * @input: Hex string
 * @input_len: Length of string (must be even)
 * @output: Output buffer (must be at least input_len / 2 bytes)
 *
 * Decodes hexadecimal string to binary data.
 * Accepts both uppercase and lowercase hex digits.
 *
 * Returns: Decoded length (input_len / 2), or -1 on error
 * Thread-safe: Yes
 */
extern ssize_t SocketCrypto_hex_decode (const char *input, size_t input_len,
                                        unsigned char *output);

/* ============================================================================
 * Random Number Generation
 * ============================================================================ */

/**
 * SocketCrypto_random_bytes - Generate cryptographically secure random bytes
 * @output: Output buffer
 * @len: Number of bytes to generate
 *
 * Generates cryptographically secure random bytes using OpenSSL RAND_bytes()
 * or /dev/urandom fallback when TLS is not available.
 *
 * Returns: 0 on success, -1 on error
 * Thread-safe: Yes
 */
extern int SocketCrypto_random_bytes (void *output, size_t len);

/**
 * SocketCrypto_random_uint32 - Generate random 32-bit integer
 *
 * Returns: Random uint32_t value
 * Thread-safe: Yes
 * Raises: SocketCrypto_Failed on RNG failure
 */
extern uint32_t SocketCrypto_random_uint32 (void);

/* ============================================================================
 * WebSocket Handshake Helpers (RFC 6455)
 * ============================================================================ */

/**
 * SocketCrypto_websocket_accept - Compute Sec-WebSocket-Accept value
 * @client_key: Sec-WebSocket-Key from client request (24 chars base64)
 * @output: Output buffer (must be at least SOCKET_CRYPTO_WEBSOCKET_ACCEPT_SIZE bytes)
 *
 * Computes: base64(SHA1(client_key + GUID))
 * Per RFC 6455 Section 4.2.2
 *
 * Returns: 0 on success, -1 on error
 * Thread-safe: Yes
 */
extern int SocketCrypto_websocket_accept (const char *client_key,
                                          char output[SOCKET_CRYPTO_WEBSOCKET_ACCEPT_SIZE]);

/**
 * SocketCrypto_websocket_key - Generate random Sec-WebSocket-Key
 * @output: Output buffer (must be at least SOCKET_CRYPTO_WEBSOCKET_KEY_SIZE bytes)
 *
 * Generates 16 random bytes and base64 encodes to 24 chars + null.
 * Per RFC 6455 Section 4.1
 *
 * Returns: 0 on success, -1 on error
 * Thread-safe: Yes
 */
extern int SocketCrypto_websocket_key (char output[SOCKET_CRYPTO_WEBSOCKET_KEY_SIZE]);

/* ============================================================================
 * Security Utilities
 * ============================================================================ */

/**
 * SocketCrypto_secure_compare - Constant-time memory comparison
 * @a: First buffer
 * @b: Second buffer
 * @len: Length to compare
 *
 * Compares two buffers in constant time to prevent timing attacks.
 * Use for comparing MACs, hashes, or other security-sensitive data.
 *
 * Returns: 0 if equal, non-zero if different
 * Thread-safe: Yes
 */
extern int SocketCrypto_secure_compare (const void *a, const void *b,
                                        size_t len);

/**
 * SocketCrypto_secure_clear - Securely clear sensitive data
 * @ptr: Buffer to clear
 * @len: Length of buffer
 *
 * Clears memory in a way that won't be optimized away by the compiler.
 * Use for clearing passwords, keys, and other sensitive data.
 *
 * Thread-safe: Yes
 */
extern void SocketCrypto_secure_clear (void *ptr, size_t len);

#endif /* SOCKETCRYPTO_INCLUDED */

