/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketUTF8.h
 * @brief Strict UTF-8 validation and encoding utilities.
 *
 * Implements secure UTF-8 validation compliant with Unicode Standard and RFC 3629,
 * optimized for streaming data (e.g., WebSocket text frames per RFC 6455 §8.1).
 * Features DFA-based algorithm for O(n) time, O(1) space validation with rejection
 * of security-critical malformed sequences.
 *
 * Key capabilities:
 * - Complete buffer validation (one-shot)
 * - Incremental/streaming validation for partial data
 * - Encoding/decoding of individual code points
 * - Code point counting with validation
 * - No heap allocation; suitable for real-time and embedded systems
 *
 * Security emphasis:
 * - Rejects overlong encodings, surrogates (U+D800–U+DFFF), and out-of-range code points
 * - Prevents canonical equivalence attacks and decoding bombs
 * - Thread-safe pure functions (no globals)
 *
 * @code{.c}
 * const char *text = "Valid UTF-8: café, 世界, 😊";
 * SocketUTF8_Result res = SocketUTF8_validate_str(text);
 * if (res == UTF8_VALID) {
 *     size_t count;
 *     SocketUTF8_count_codepoints((const unsigned char*)text, strlen(text), &count);
 *     printf("Valid, %zu code points\n", count);
 * }
 * @endcode
 */

#ifndef SOCKETUTF8_INCLUDED
#define SOCKETUTF8_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include "core/Except.h"

/**
 * Maximum bytes required to encode any single Unicode code point in UTF-8.
 * All valid UTF-8 sequences are 1-4 bytes long.
 */
#define SOCKET_UTF8_MAX_BYTES 4

/**
 * Highest valid Unicode code point (end of UTF-8 encodable range).
 */
#define SOCKET_UTF8_MAX_CODEPOINT 0x10FFFF

/**
 * Start of UTF-16 surrogate range (invalid in pure UTF-8).
 */
#define SOCKET_UTF8_SURROGATE_MIN 0xD800

/**
 * End of UTF-16 surrogate range (invalid in pure UTF-8).
 */
#define SOCKET_UTF8_SURROGATE_MAX 0xDFFF

/**
 * Maximum code point encodable in a single UTF-8 byte (ASCII range).
 */
#define SOCKET_UTF8_1BYTE_MAX 0x7F

/**
 * Maximum code point encodable in two UTF-8 bytes.
 */
#define SOCKET_UTF8_2BYTE_MAX 0x7FF

/**
 * Maximum code point encodable in three UTF-8 bytes.
 */
#define SOCKET_UTF8_3BYTE_MAX 0xFFFF

/**
 * Minimum code point requiring four UTF-8 bytes.
 */
#define SOCKET_UTF8_4BYTE_MIN 0x10000

/**
 * Exception for UTF-8 validation and encoding failures.
 *
 * Thrown for invalid UTF-8 sequences, invalid code points, or null pointer errors.
 */
extern const Except_T SocketUTF8_Failed;

/**
 * Enumeration of UTF-8 validation results.
 */
typedef enum
{
  UTF8_VALID = 0,  /**< Complete valid UTF-8 sequence processed. */
  UTF8_INVALID,    /**< Generic invalid byte sequence detected. */
  UTF8_INCOMPLETE, /**< Valid prefix; requires more input bytes. */
  UTF8_OVERLONG,   /**< Overlong encoding (security vulnerability). */
  UTF8_SURROGATE,  /**< Invalid UTF-16 surrogate range (U+D800-U+DFFF). */
  UTF8_TOO_LARGE   /**< Code point exceeds Unicode maximum (U+10FFFF). */
} SocketUTF8_Result;

/**
 * Perform one-shot validation of complete UTF-8 data buffer.
 * @param data Input byte buffer to validate (may be NULL if len==0).
 * @param len Number of bytes in the input buffer.
 *
 * Strictly validates the entire buffer as well-formed UTF-8 per Unicode Standard (RFC 3629).
 * Uses a deterministic finite automaton (DFA) for O(n) time and O(1) space.
 *
 * Security: Rejects overlong encodings, UTF-16 surrogates (U+D800–U+DFFF),
 * code points beyond U+10FFFF, and truncated sequences.
 *
 * @return UTF8_VALID if buffer contains only valid UTF-8; otherwise a specific error code.
 * @throws SocketUTF8_Failed if data is NULL when len > 0.
 * @threadsafe Yes - pure function with no global or shared state.
 * @see SocketUTF8_update() for incremental/streaming validation.
 */
extern SocketUTF8_Result SocketUTF8_validate (const unsigned char *data,
                                              size_t len);

/**
 * Validate a null-terminated C string as UTF-8.
 * @param str Null-terminated input string (may be NULL, treated as empty).
 *
 * Convenience function that computes length and calls SocketUTF8_validate().
 *
 * @return UTF8_VALID if string is well-formed UTF-8; error code otherwise.
 * @threadsafe Yes - pure function.
 */
extern SocketUTF8_Result SocketUTF8_validate_str (const char *str);

/**
 * State structure for incremental UTF-8 validation.
 *
 * Opaque state for streaming UTF-8 validation. Allocate on stack and initialize
 * with SocketUTF8_init(). Maintains DFA state across data chunks to handle
 * multi-byte sequences split by boundaries (e.g., network packets).
 *
 * Thread-safe when not shared across threads without synchronization.
 */
typedef struct SocketUTF8_State
{
  uint32_t state;       /**< Internal DFA automaton state. */
  uint8_t bytes_needed; /**< Expected remaining bytes for current sequence. */
  uint8_t bytes_seen;   /**< Bytes already processed in current sequence. */
} SocketUTF8_State;

/**
 * Initialize UTF-8 incremental validation state.
 * @param state Pointer to SocketUTF8_State structure to initialize (must not be NULL).
 *
 * Resets the state machine to initial conditions. Required before first call to
 * SocketUTF8_update().
 *
 * @throws SocketUTF8_Failed if state is NULL.
 * @threadsafe Conditional - safe if state is not concurrently accessed.
 */
extern void SocketUTF8_init (SocketUTF8_State *state);

/**
 * Process a chunk of data through incremental UTF-8 validator.
 * @param state Initialized SocketUTF8_State (must not be NULL).
 * @param data Input data chunk (may be NULL if len==0).
 * @param len Number of bytes in the current chunk.
 *
 * Feeds bytes into the DFA state machine, validating incrementally.
 * Handles multi-byte sequences split across multiple calls.
 *
 * @return Validation result for processed bytes:
 * @retval UTF8_VALID All bytes valid and sequences complete.
 * @retval UTF8_INCOMPLETE Valid so far, but ends expecting more bytes.
 * @retval UTF8_INVALID or specific error: Failure detected in chunk.
 *
 * @throws SocketUTF8_Failed if state is NULL or data is NULL when len > 0.
 * @threadsafe Conditional - safe for single-threaded use per state instance.
 * @note Call SocketUTF8_finish() after all chunks to check final completeness.
 */
extern SocketUTF8_Result SocketUTF8_update (SocketUTF8_State *state,
                                            const unsigned char *data,
                                            size_t len);

/**
 * Finalize incremental UTF-8 validation and check completeness.
 * @param state Initialized and updated SocketUTF8_State (must not be NULL).
 *
 * Verifies that the validation stream ended in a valid complete state with no
 * pending multi-byte sequence. Essential after processing all chunks to detect
 * truncation.
 *
 * @return UTF8_VALID if stream completed successfully; UTF8_INCOMPLETE or error otherwise.
 * @throws SocketUTF8_Failed if state is NULL.
 * @threadsafe Yes - read-only operation on state.
 */
extern SocketUTF8_Result SocketUTF8_finish (const SocketUTF8_State *state);

/**
 * Reset incremental validator state for reuse.
 * @param state Pointer to SocketUTF8_State to reset (must not be NULL).
 *
 * Equivalent to SocketUTF8_init(); clears all internal state for a fresh validation
 * session.
 *
 * @throws SocketUTF8_Failed if state is NULL.
 * @threadsafe Conditional - safe if not shared across threads.
 */
extern void SocketUTF8_reset (SocketUTF8_State *state);

/**
 * Determine byte length required to encode a Unicode code point in UTF-8.
 * @param codepoint Unicode scalar value (0 to U+10FFFF).
 *
 * Computes the minimal number of bytes needed for canonical UTF-8 encoding.
 * Returns 0 for invalid ranges (surrogates U+D800–U+DFFF or >U+10FFFF).
 *
 * @return Number of bytes: 1 (ASCII), 2, 3, or 4; 0 if invalid.
 * @threadsafe Yes - pure function, no state.
 */
extern int SocketUTF8_codepoint_len (uint32_t codepoint);

/**
 * Infer expected length of UTF-8 sequence from leading byte.
 * @param first_byte The first (leading) byte of a potential UTF-8 sequence.
 *
 * Valid patterns:
 * - 0xxxxxxx (0x00-0x7F): 1 byte (ASCII/7-bit)
 * - 110xxxxx (0xC2-0xDF): 2 bytes
 * - 1110xxxx (0xE0-0xEF): 3 bytes
 * - 11110xxx (0xF0-0xF4): 4 bytes
 *
 * Returns 0 for invalid lead bytes.
 *
 * @return Expected sequence length (1-4) or 0 if invalid lead byte.
 * @threadsafe Yes - pure function.
 */
extern int SocketUTF8_sequence_len (unsigned char first_byte);

/**
 * Encode a single Unicode code point into UTF-8 bytes.
 * @param codepoint Valid Unicode scalar (0 to U+10FFFF, excluding surrogates).
 * @param output Output buffer for encoded bytes (must have space for at least 4 bytes).
 *
 * Writes canonical (shortest) UTF-8 encoding to output buffer. Caller must ensure
 * sufficient space using SocketUTF8_codepoint_len().
 *
 * @return Number of bytes written (1-4) on success; 0 if codepoint invalid or output is NULL.
 * @threadsafe Yes - pure function.
 * @note Does not null-terminate output.
 */
extern int SocketUTF8_encode (uint32_t codepoint, unsigned char *output);

/**
 * Decode the next complete UTF-8 sequence to a Unicode code point.
 * @param data Input buffer containing UTF-8 sequence start (may be NULL if len == 0).
 * @param len Available bytes in input buffer (may be 0).
 * @param codepoint Output for decoded Unicode scalar (may be NULL to skip).
 * @param consumed Output for number of bytes consumed (may be NULL to skip).
 *
 * Attempts to decode one full UTF-8 sequence from the buffer start.
 * Validates and categorizes errors during decoding.
 *
 * @return Result of decoding attempt:
 * @retval UTF8_VALID Successfully decoded one code point; outputs set.
 * @retval UTF8_INCOMPLETE Partial sequence; need more bytes.
 * @retval Error code on invalid or malformed input.
 *
 * @throws SocketUTF8_Failed if data is NULL when len > 0.
 * @threadsafe Yes - pure function.
 * @note Does not modify input buffer.
 */
extern SocketUTF8_Result SocketUTF8_decode (const unsigned char *data,
                                            size_t len, uint32_t *codepoint,
                                            size_t *consumed);

/**
 * Count the number of Unicode code points in a UTF-8 buffer while validating.
 * @param data Input UTF-8 buffer (may be NULL if len==0).
 * @param len Length of buffer in bytes.
 * @param count Output pointer for code point count (must not be NULL; set on success).
 *
 * Iterates through buffer, decoding each code point and incrementing count.
 * Performs full validation; aborts on first error without setting count.
 *
 * @return UTF8_VALID if buffer valid and count set; error code on failure (count unchanged).
 * @throws SocketUTF8_Failed if count is NULL or data is NULL when len > 0.
 * @threadsafe Yes - pure function.
 */
extern SocketUTF8_Result
SocketUTF8_count_codepoints (const unsigned char *data, size_t len,
                             size_t *count);

/**
 * Retrieve descriptive string for a UTF-8 validation result code.
 * @param result SocketUTF8_Result code from validation function.
 *
 * Returns a static, human-readable string describing the result (e.g., "valid",
 * "invalid sequence"). Useful for logging and error reporting.
 *
 * @return Const C string (never NULL); static storage, do not free.
 * @threadsafe Yes - returns static strings.
 */
extern const char *SocketUTF8_result_string (SocketUTF8_Result result);

#endif /* SOCKETUTF8_INCLUDED */
