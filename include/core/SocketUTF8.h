/**
 * SocketUTF8.h - UTF-8 Validation for Socket Library
 *
 * Part of the Socket Library
 *
 * Provides complete UTF-8 validation per Unicode Standard with incremental
 * API for streaming. Required for WebSocket text frame validation
 * (RFC 6455 Section 8.1).
 *
 * Features:
 * - One-shot validation for complete data
 * - Incremental validation for streaming data
 * - DFA-based O(n) time, O(1) space algorithm
 * - Strict security validation (rejects overlong, surrogates, invalid)
 * - Encode/decode utilities
 *
 * Thread safety: All functions are thread-safe (no global state).
 * State structures are per-call, enabling concurrent validation.
 *
 * Security notes:
 * - Rejects overlong encodings (e.g., C0 80 for NUL) - critical for security
 * - Rejects UTF-16 surrogates (U+D800-U+DFFF) - invalid in UTF-8
 * - Rejects code points > U+10FFFF - beyond Unicode range
 * - No dynamic memory allocation - immune to allocation attacks
 */

#ifndef SOCKETUTF8_INCLUDED
#define SOCKETUTF8_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include "core/Except.h"

/* ============================================================================
 * Constants
 * ============================================================================ */

/** Maximum bytes in a UTF-8 sequence */
#define SOCKET_UTF8_MAX_BYTES 4

/** Maximum valid Unicode code point */
#define SOCKET_UTF8_MAX_CODEPOINT 0x10FFFF

/** First UTF-16 surrogate code point (invalid in UTF-8) */
#define SOCKET_UTF8_SURROGATE_MIN 0xD800

/** Last UTF-16 surrogate code point (invalid in UTF-8) */
#define SOCKET_UTF8_SURROGATE_MAX 0xDFFF

/* ============================================================================
 * Byte Length Boundaries
 * ============================================================================ */

/**
 * Maximum code point encodable in 1 byte (ASCII range)
 */
#define SOCKET_UTF8_1BYTE_MAX      0x7F

/**
 * Maximum code point encodable in 2 bytes
 */
#define SOCKET_UTF8_2BYTE_MAX      0x7FF

/**
 * Maximum code point encodable in 3 bytes
 */
#define SOCKET_UTF8_3BYTE_MAX      0xFFFF

/**
 * Minimum code point requiring 4 bytes
 */
#define SOCKET_UTF8_4BYTE_MIN      0x10000

/* ============================================================================
 * Exception Types
 * ============================================================================ */

/**
 * SocketUTF8_Failed - UTF-8 operation failure
 *
 * Raised when:
 * - Invalid UTF-8 sequence detected during strict validation
 * - Invalid code point provided for encoding
 * - NULL pointer passed to required parameter
 */
extern const Except_T SocketUTF8_Failed;

/* ============================================================================
 * UTF-8 Validation Result
 * ============================================================================ */

/**
 * UTF-8 validation result codes
 *
 * These codes indicate the result of UTF-8 validation operations.
 * For security, invalid sequences are categorized by failure type.
 */
typedef enum
{
  UTF8_VALID = 0,    /**< Complete valid UTF-8 sequence */
  UTF8_INVALID,      /**< Invalid byte sequence detected */
  UTF8_INCOMPLETE,   /**< Valid prefix, needs more bytes */
  UTF8_OVERLONG,     /**< Overlong encoding (security issue) */
  UTF8_SURROGATE,    /**< UTF-16 surrogate (U+D800-U+DFFF) */
  UTF8_TOO_LARGE     /**< Code point > U+10FFFF */
} SocketUTF8_Result;

/* ============================================================================
 * One-Shot Validation
 * ============================================================================ */

/**
 * SocketUTF8_validate - Validate UTF-8 data (complete check)
 * @data: Input data (may be NULL if len is 0)
 * @len: Length of data in bytes
 *
 * Validates that the entire input is well-formed UTF-8.
 *
 * Rejects:
 * - Invalid continuation bytes
 * - Overlong encodings (e.g., 0xC0 0x80 for NUL)
 * - UTF-16 surrogates (U+D800-U+DFFF)
 * - Code points > U+10FFFF
 * - Truncated sequences at end
 *
 * Returns: UTF8_VALID if entire sequence is valid UTF-8, error code otherwise
 * Thread-safe: Yes (no global state)
 */
extern SocketUTF8_Result SocketUTF8_validate (const unsigned char *data,
                                              size_t len);

/**
 * SocketUTF8_validate_str - Validate null-terminated string
 * @str: Null-terminated string (may be NULL)
 *
 * Convenience wrapper for SocketUTF8_validate() that handles
 * null-terminated strings.
 *
 * Returns: UTF8_VALID if valid UTF-8, error code otherwise
 * Thread-safe: Yes
 */
extern SocketUTF8_Result SocketUTF8_validate_str (const char *str);

/* ============================================================================
 * Incremental Validation (for streaming)
 * ============================================================================ */

/**
 * UTF-8 incremental validator state
 * Public structure for stack allocation - initialized via SocketUTF8_init()
 *
 * This structure maintains validation state across multiple chunks of data,
 * enabling streaming validation where multi-byte sequences may be split
 * across chunk boundaries.
 */
typedef struct
{
  uint32_t state;        /**< DFA state (internal) */
  uint8_t bytes_needed;  /**< Remaining bytes in sequence */
  uint8_t bytes_seen;    /**< Bytes seen in current sequence */
} SocketUTF8_State;

/**
 * SocketUTF8_init - Initialize incremental validator
 * @state: State structure to initialize (must not be NULL)
 *
 * Initializes state for incremental validation. Must be called before
 * first use of SocketUTF8_update().
 *
 * Thread-safe: Yes (state is caller-provided)
 */
extern void SocketUTF8_init (SocketUTF8_State *state);

/**
 * SocketUTF8_update - Feed data to incremental validator
 * @state: Validator state (must be initialized)
 * @data: Input data chunk (may be NULL if len is 0)
 * @len: Length of chunk in bytes
 *
 * Validates a chunk of data, updating state for multi-byte sequences
 * that span chunk boundaries.
 *
 * Returns:
 * - UTF8_VALID: All bytes processed, no errors, complete sequences
 * - UTF8_INCOMPLETE: All bytes processed, ends mid-sequence (valid so far)
 * - UTF8_INVALID/UTF8_OVERLONG/etc.: Error detected
 *
 * Can be called multiple times with chunks of data. State is preserved
 * between calls for multi-byte sequences split across chunks.
 *
 * Thread-safe: Yes (state is caller-provided)
 */
extern SocketUTF8_Result SocketUTF8_update (SocketUTF8_State *state,
                                            const unsigned char *data,
                                            size_t len);

/**
 * SocketUTF8_finish - Finalize incremental validation
 * @state: Validator state (must not be NULL)
 *
 * Checks if the stream ended on a complete UTF-8 sequence.
 * Must be called after all data has been fed to detect truncated sequences.
 *
 * Returns: UTF8_VALID if complete, UTF8_INCOMPLETE if truncated
 * Thread-safe: Yes (state is caller-provided, read-only)
 */
extern SocketUTF8_Result SocketUTF8_finish (const SocketUTF8_State *state);

/**
 * SocketUTF8_reset - Reset validator for reuse
 * @state: Validator state (must not be NULL)
 *
 * Equivalent to SocketUTF8_init() - resets state for new validation.
 *
 * Thread-safe: Yes
 */
extern void SocketUTF8_reset (SocketUTF8_State *state);

/* ============================================================================
 * UTF-8 Utilities
 * ============================================================================ */

/**
 * SocketUTF8_codepoint_len - Get UTF-8 byte length for code point
 * @codepoint: Unicode code point (U+0000 to U+10FFFF)
 *
 * Calculates how many bytes are needed to encode the code point.
 *
 * Returns: 1-4 for valid code points, 0 for invalid (surrogates, >U+10FFFF)
 * Thread-safe: Yes
 */
extern int SocketUTF8_codepoint_len (uint32_t codepoint);

/**
 * SocketUTF8_sequence_len - Get length of UTF-8 sequence from first byte
 * @first_byte: First byte of UTF-8 sequence
 *
 * Determines sequence length from the leading byte pattern:
 * - 0xxxxxxx (0x00-0x7F): 1 byte (ASCII)
 * - 110xxxxx (0xC2-0xDF): 2 bytes
 * - 1110xxxx (0xE0-0xEF): 3 bytes
 * - 11110xxx (0xF0-0xF4): 4 bytes
 *
 * Returns: 1-4 for valid start bytes, 0 for invalid/continuation bytes
 * Thread-safe: Yes
 */
extern int SocketUTF8_sequence_len (unsigned char first_byte);

/**
 * SocketUTF8_encode - Encode code point to UTF-8
 * @codepoint: Unicode code point (U+0000 to U+10FFFF, excluding surrogates)
 * @output: Output buffer (must be at least SOCKET_UTF8_MAX_BYTES bytes)
 *
 * Encodes a single Unicode code point as UTF-8.
 *
 * Returns: Number of bytes written (1-4), or 0 for invalid code point
 * Thread-safe: Yes
 */
extern int SocketUTF8_encode (uint32_t codepoint, unsigned char *output);

/**
 * SocketUTF8_decode - Decode one code point from UTF-8
 * @data: Input data (must not be NULL)
 * @len: Available bytes (must be > 0)
 * @codepoint: Output code point (may be NULL to skip)
 * @consumed: Output bytes consumed (may be NULL to skip)
 *
 * Decodes a single UTF-8 sequence to its Unicode code point.
 *
 * Returns:
 * - UTF8_VALID: Successfully decoded, *consumed bytes used
 * - UTF8_INCOMPLETE: Need more bytes (partial sequence)
 * - UTF8_INVALID/UTF8_OVERLONG/etc.: Invalid sequence
 *
 * Thread-safe: Yes
 */
extern SocketUTF8_Result SocketUTF8_decode (const unsigned char *data,
                                            size_t len, uint32_t *codepoint,
                                            size_t *consumed);

/**
 * SocketUTF8_count_codepoints - Count code points in UTF-8 string
 * @data: Input data (may be NULL if len is 0)
 * @len: Length in bytes
 * @count: Output code point count (must not be NULL)
 *
 * Counts the number of Unicode code points in the UTF-8 data.
 * Also validates the UTF-8 encoding.
 *
 * Returns: UTF8_VALID if valid (count is set), error code otherwise
 * Thread-safe: Yes
 */
extern SocketUTF8_Result SocketUTF8_count_codepoints (const unsigned char *data,
                                                      size_t len,
                                                      size_t *count);

/**
 * SocketUTF8_result_string - Get human-readable result description
 * @result: Validation result code
 *
 * Returns: Static string describing the result (never NULL)
 * Thread-safe: Yes
 */
extern const char *SocketUTF8_result_string (SocketUTF8_Result result);

#endif /* SOCKETUTF8_INCLUDED */

