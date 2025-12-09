/**
 * @file SocketUTF8.h
 * @ingroup utilities
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
 * @see @ref foundation "Core Foundation Modules" for related utilities.
 * @see SocketUTF8_validate() primary one-shot validation entry point.
 * @see SocketUTF8_update() for incremental processing.
 * @see SocketUTF8_encode() and SocketUTF8_decode() for conversion utilities.
 * @see SocketWS.h WebSocket module integration (text frame validation).
 * @see docs/SECURITY_GUIDE.md for security considerations in protocol handling.
 */

#ifndef SOCKETUTF8_INCLUDED
#define SOCKETUTF8_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include "core/Except.h"

/* ============================================================================
 * Constants
 * ============================================================================
 */

/**
 * @brief Maximum bytes required to encode any single Unicode code point in UTF-8.
 * @ingroup utilities
 *
 * All valid UTF-8 sequences are 1-4 bytes long; buffers should accommodate this maximum.
 * @see SocketUTF8_encode()
 */
#define SOCKET_UTF8_MAX_BYTES 4

/**
 * @brief Highest valid Unicode code point (end of UTF-8 encodable range).
 * @ingroup utilities
 *
 * Code points above this are invalid and rejected by validation/encoding functions.
 * Corresponds to the last scalar in Unicode (plane 17, but practically U+10FFFF).
 * @see SocketUTF8_validate()
 * @see SocketUTF8_codepoint_len()
 */
#define SOCKET_UTF8_MAX_CODEPOINT 0x10FFFF

/**
 * @brief Start of UTF-16 surrogate range (invalid in pure UTF-8).
 * @ingroup utilities
 *
 * High surrogates U+D800–U+DBFF are rejected to prevent mixed UTF-8/UTF-16 issues.
 * @see SocketUTF8_validate()
 */
#define SOCKET_UTF8_SURROGATE_MIN 0xD800

/**
 * @brief End of UTF-16 surrogate range (invalid in pure UTF-8).
 * @ingroup utilities
 *
 * Low surrogates U+DC00–U+DFFF rejected for security and standard compliance.
 * @see SocketUTF8_validate()
 */
#define SOCKET_UTF8_SURROGATE_MAX 0xDFFF

/* ============================================================================
 * Byte Length Boundaries
 * ============================================================================
 */

/**
 * @brief Maximum code point encodable in a single UTF-8 byte.
 * @ingroup utilities
 * Corresponds to 7-bit ASCII range (U+0000 to U+007F); lead byte 0xxxxxxx.
 * @see SocketUTF8_codepoint_len()
 */
#define SOCKET_UTF8_1BYTE_MAX 0x7F

/**
 * @brief Maximum code point encodable in two UTF-8 bytes.
 * @ingroup utilities
 * Range U+0080 to U+07FF; lead byte 110xxxxx followed by continuation byte.
 * @see SocketUTF8_codepoint_len()
 */
#define SOCKET_UTF8_2BYTE_MAX 0x7FF

/**
 * @brief Maximum code point encodable in three UTF-8 bytes.
 * @ingroup utilities
 * Range U+0800 to U+FFFF (excluding surrogates); lead byte 1110xxxx.
 * Note: U+D800–U+DFFF invalid surrogates not encodable.
 * @see SocketUTF8_codepoint_len()
 */
#define SOCKET_UTF8_3BYTE_MAX 0xFFFF

/**
 * @brief Minimum code point requiring four UTF-8 bytes.
 * @ingroup utilities
 * Start of 4-byte encodings for supplementary planes (U+10000+); lead byte 11110xxx.
 * @see SocketUTF8_codepoint_len()
 */
#define SOCKET_UTF8_4BYTE_MIN 0x10000

/* ============================================================================
 * Exception Types
 * ============================================================================
 */

/**
 * @brief Exception for UTF-8 validation and encoding failures.
 * @ingroup utilities
 *
 * Thrown in cases of:
 * - Detection of invalid UTF-8 sequences during strict validation
 * - Invalid Unicode code points supplied for encoding/decoding
 * - Critical errors like null pointer dereferences in required parameters
 *
 * @see Except_T for exception handling framework.
 * @see SocketUTF8_validate() where validation errors may propagate as exceptions internally.
 * @see docs/ERROR_HANDLING.md "Error Handling Guide" for TRY/EXCEPT patterns.
 */
extern const Except_T SocketUTF8_Failed;

/* ============================================================================
 * UTF-8 Validation Result
 * ============================================================================
 */

/**
 * @brief Enumeration of UTF-8 validation results.
 * @ingroup utilities
 *
 * Result codes returned by validation functions to indicate success or specific failure modes.
 * Specific error codes enable security-focused handling (e.g., rejecting overlong encodings).
 *
 * @see SocketUTF8_validate() returns one of these codes.
 * @see SocketUTF8_update() for incremental validation results.
 * @see SocketUTF8_result_string() for human-readable descriptions.
 */
typedef enum
{
  UTF8_VALID = 0,     /**< Complete valid UTF-8 sequence processed. */
  UTF8_INVALID,       /**< Generic invalid byte sequence detected. */
  UTF8_INCOMPLETE,    /**< Valid prefix; requires more input bytes. */
  UTF8_OVERLONG,      /**< Overlong encoding (security vulnerability). */
  UTF8_SURROGATE,     /**< Invalid UTF-16 surrogate range (U+D800-U+DFFF). */
  UTF8_TOO_LARGE      /**< Code point exceeds Unicode maximum (U+10FFFF). */
} SocketUTF8_Result;

/* ============================================================================
 * One-Shot Validation
 * ============================================================================
 */

/**
 * @brief Perform one-shot validation of complete UTF-8 data buffer.
 * @ingroup utilities
 * @param data Input byte buffer to validate (may be NULL if len==0).
 * @param len Number of bytes in the input buffer.
 *
 * @throws SocketUTF8_Failed if data is NULL when len > 0 (invalid argument).
 *
 * Strictly validates the entire buffer as well-formed UTF-8 per Unicode Standard
 * (RFC 3629). Uses a deterministic finite automaton (DFA) for O(n) time and O(1) space.
 *
 * Detection and rejection criteria (for security):
 * - Malformed byte sequences or invalid continuation bytes (10xxxxxx)
 * - Overlong encodings (e.g., C0 80 for U+0000) - prevents security bypasses
 * - UTF-16 surrogate code points (U+D800–U+DFFF) - invalid in UTF-8
 * - Code points beyond Unicode plane limit (U+10FFFF)
 * - Truncated multi-byte sequences at buffer end
 *
 * @return UTF8_VALID if buffer contains only valid UTF-8; otherwise a specific
 *         error code indicating failure type.
 * @retval UTF8_INCOMPLETE if buffer ends mid-sequence (rare for complete buffers)
 * @threadsafe Yes - pure function with no global or shared state.
 * @note No dynamic allocation; suitable for embedded or high-performance use.
 * @note Intended for WebSocket text frame validation (RFC 6455 §8.1).
 *
 * @see SocketUTF8_validate_str() convenience for null-terminated C strings.
 * @see SocketUTF8_update() for incremental/streaming validation.
 * @see SocketUTF8_decode() for single code point decoding.
 * @see SocketUTF8_Result enumeration for detailed error codes.
 * @see SocketWS.h WebSocket module which requires this validation.
 */
extern SocketUTF8_Result SocketUTF8_validate (const unsigned char *data,
                                              size_t len);

/**
 * @brief Validate a null-terminated C string as UTF-8.
 * @ingroup utilities
 * @param str Null-terminated input string (may be NULL, treated as empty).
 *
 * Convenience function that computes length and calls SocketUTF8_validate().
 * Validates up to but not including the null terminator.
 *
 * @return UTF8_VALID if string is well-formed UTF-8; error code otherwise.
 * @threadsafe Yes - pure function.
 *
 * @see SocketUTF8_validate() underlying validation function.
 * @see SocketUTF8_Result for possible return values.
 */
extern SocketUTF8_Result SocketUTF8_validate_str (const char *str);

/* ============================================================================
 * Incremental Validation (for streaming)
 * ============================================================================
 */

/**
 * @brief State structure for incremental UTF-8 validation.
 * @ingroup utilities
 *
 * Opaque state for streaming UTF-8 validation. Allocate on stack and initialize
 * with SocketUTF8_init() or SocketUTF8_reset(). Maintains DFA state across data chunks
 * to handle multi-byte sequences split by boundaries (e.g., network packets).
 *
 * Fields are internal; do not modify directly. Size is fixed for predictability.
 *
 * @see SocketUTF8_init() to initialize.
 * @see SocketUTF8_update() to process data chunks.
 * @see SocketUTF8_finish() to finalize validation.
 * @note Thread-safe when not shared across threads without synchronization.
 */
typedef struct SocketUTF8_State
{
  uint32_t state;         /**< Internal DFA automaton state. */
  uint8_t bytes_needed;   /**< Expected remaining bytes for current sequence. */
  uint8_t bytes_seen;     /**< Bytes already processed in current sequence. */
                          /**< Padding/reserved for alignment (internal use). */
} SocketUTF8_State;

/**
 * @brief Initialize UTF-8 incremental validation state.
 * @ingroup utilities
 * @param state Pointer to SocketUTF8_State structure to initialize (must not be NULL).
 *
 * Resets the state machine to initial conditions for a new validation stream.
 * Required before first call to SocketUTF8_update().
 *
 * @return None (void).
 * @throws SocketUTF8_Failed if state is NULL (via assertion or explicit check).
 * @threadsafe Conditional - safe if state is not concurrently accessed.
 *
 * @see SocketUTF8_State structure details.
 * @see SocketUTF8_reset() equivalent for reuse.
 * @see SocketUTF8_update() next step after initialization.
 */
extern void SocketUTF8_init (SocketUTF8_State *state);

/**
 * @brief Process a chunk of data through incremental UTF-8 validator.
 * @ingroup utilities
 * @param state Initialized SocketUTF8_State (must not be NULL).
 * @param data Input data chunk (may be NULL if len==0).
 * @param len Number of bytes in the current chunk.
 *
 * Feeds bytes into the DFA state machine, validating incrementally.
 * Handles multi-byte sequences split across multiple calls by preserving
 * partial state (e.g., expecting 2 more continuation bytes).
 *
 * Processes as many bytes as possible from the chunk. Advances input pointer
 * implicitly via state updates.
 *
 * @return Validation result for processed bytes:
 * @retval UTF8_VALID All bytes valid and sequences complete.
 * @retval UTF8_INCOMPLETE Valid so far, but ends expecting more bytes.
 * @retval UTF8_INVALID or specific error: Failure detected in chunk.
 *
 * @throws SocketUTF8_Failed if state is NULL or data is NULL when len > 0 (invalid arguments).
 * @threadsafe Conditional - safe for single-threaded use per state instance.
 *
 * @note Call SocketUTF8_finish() after all chunks to check final completeness.
 * @note For complete buffers, prefer SocketUTF8_validate() for simplicity.
 *
 * @see SocketUTF8_init() or SocketUTF8_reset() before first use.
 * @see SocketUTF8_finish() to complete validation.
 * @see SocketUTF8_State for state management.
 * @see SocketUTF8_validate() for non-incremental alternative.
 */
extern SocketUTF8_Result SocketUTF8_update (SocketUTF8_State *state,
                                            const unsigned char *data,
                                            size_t len);

/**
 * @brief Finalize incremental UTF-8 validation and check completeness.
 * @ingroup utilities
 * @param state Initialized and updated SocketUTF8_State (must not be NULL).
 *
 * Verifies that the validation stream ended in a valid complete state,
 * i.e., no pending multi-byte sequence or error condition.
 * Essential after processing all chunks to detect truncation.
 *
 * @return UTF8_VALID if stream completed successfully; UTF8_INCOMPLETE or error otherwise.
 * @throws SocketUTF8_Failed if state is NULL.
 * @threadsafe Yes - read-only operation on state.
 *
 * @note Always call after final SocketUTF8_update() call, even if expecting completeness.
 *
 * @see SocketUTF8_update() for feeding data.
 * @see SocketUTF8_State for state details.
 * @see SocketUTF8_validate() for single-call validation of complete data.
 */
extern SocketUTF8_Result SocketUTF8_finish (const SocketUTF8_State *state);

/**
 * @brief Reset incremental validator state for reuse.
 * @ingroup utilities
 * @param state Pointer to SocketUTF8_State to reset (must not be NULL).
 *
 * Equivalent to SocketUTF8_init(); clears all internal state for a fresh validation session.
 * Allows reusing the same state structure without reallocation.
 *
 * @return None (void).
 * @throws SocketUTF8_Failed if state is NULL.
 * @threadsafe Conditional - safe if not shared across threads.
 *
 * @see SocketUTF8_init() identical functionality.
 * @see SocketUTF8_State for allocation.
 */
extern void SocketUTF8_reset (SocketUTF8_State *state);

/* ============================================================================
 * UTF-8 Utilities
 * ============================================================================
 */

/**
 * @brief Determine byte length required to encode a Unicode code point in UTF-8.
 * @ingroup utilities
 * @param codepoint Unicode scalar value (0 to U+10FFFF).
 *
 * Computes the minimal number of bytes needed for canonical UTF-8 encoding.
 * Returns 0 for invalid ranges (surrogates U+D800–U+DFFF or >U+10FFFF).
 *
 * @return Number of bytes: 1 (ASCII), 2, 3, or 4; 0 if invalid.
 * @threadsafe Yes - pure function, no state.
 *
 * @see SocketUTF8_encode() to perform the encoding.
 * @see SocketUTF8_MAX_CODEPOINT constant.
 */
extern int SocketUTF8_codepoint_len (uint32_t codepoint);

/**
 * @brief Infer expected length of UTF-8 sequence from leading byte.
 * @ingroup utilities
 * @param first_byte The first (leading) byte of a potential UTF-8 sequence.
 *
 * Quick lookup to determine the expected number of bytes for a multi-byte sequence
 * based on the start byte pattern. Useful for buffer management or partial decoding.
 *
 * Valid patterns:
 * - 0xxxxxxx (0x00-0x7F): 1 byte (ASCII/7-bit)
 * - 110xxxxx (0xC2-0xDF): 2 bytes
 * - 1110xxxx (0xE0-0xEF): 3 bytes
 * - 11110xxx (0xF0-0xF4): 4 bytes
 *
 * Returns 0 for invalid lead bytes (e.g., 0xC0-0xC1 overlong starts, continuation bytes).
 *
 * @return Expected sequence length (1-4) or 0 if invalid lead byte.
 * @threadsafe Yes - pure function.
 *
 * @see SocketUTF8_validate() which uses this internally.
 * @see SocketUTF8_decode() for full sequence decoding.
 */
extern int SocketUTF8_sequence_len (unsigned char first_byte);

/**
 * @brief Encode a single Unicode code point into UTF-8 bytes.
 * @ingroup utilities
 * @param codepoint Valid Unicode scalar (0 to U+10FFFF, excluding surrogates).
 * @param output Output buffer for encoded bytes (must have space for at least 4 bytes).
 *
 * Writes canonical (shortest) UTF-8 encoding to output buffer. No validation
 * of output buffer size; caller must ensure sufficient space using
 * SocketUTF8_codepoint_len().
 *
 * @return Number of bytes written (1-4) on success; 0 if codepoint invalid or if output is NULL.

 * @threadsafe Yes - pure function.
 * @note Does not null-terminate output.
 *
 * @see SocketUTF8_codepoint_len() to determine required buffer size.
 * @see SocketUTF8_decode() inverse operation.
 * @see SOCKET_UTF8_MAX_BYTES maximum output size.
 */
extern int SocketUTF8_encode (uint32_t codepoint, unsigned char *output);

/**
 * @brief Decode the next complete UTF-8 sequence to a Unicode code point.
 * @ingroup utilities
 * @param data Input buffer containing UTF-8 sequence start (may be NULL if len == 0).
 * @param len Available bytes in input buffer (may be 0).
 * @param codepoint Output for decoded Unicode scalar (may be NULL to skip).
 * @param consumed Output for number of bytes consumed (may be NULL to skip).
 *
 * Attempts to decode one full UTF-8 sequence from the buffer start.
 * Validates and categorizes errors during decoding.
 * Advances by reporting consumed bytes for iterative decoding.
 *
 * @return Result of decoding attempt:
 * @retval UTF8_VALID Successfully decoded one code point; outputs set.
 * @retval UTF8_INCOMPLETE Partial sequence; need more bytes.
 * @retval Error code on invalid or malformed input.
 *
 * @throws SocketUTF8_Failed if data is NULL when len > 0 (invalid argument).
 * @threadsafe Yes - pure function.
 * @note Caller must ensure buffer has enough bytes based on lead byte.
 * @note Does not modify input buffer.
 *
 * @see SocketUTF8_sequence_len() to check expected length from lead byte.
 * @see SocketUTF8_encode() inverse encoding function.
 * @see SocketUTF8_validate() for full buffer validation without decoding.
 */
extern SocketUTF8_Result SocketUTF8_decode (const unsigned char *data,
                                            size_t len, uint32_t *codepoint,
                                            size_t *consumed);

/**
 * @brief Count the number of Unicode code points in a UTF-8 buffer while validating.
 * @ingroup utilities
 * @param data Input UTF-8 buffer (may be NULL if len==0).
 * @param len Length of buffer in bytes.
 * @param count Output pointer for code point count (must not be NULL; set on success).
 *
 * Iterates through buffer, decoding each code point and incrementing count.
 * Performs full validation; aborts on first error without setting count.
 * Useful for string length in characters vs. bytes (e.g., UI display).
 *
 * @return UTF8_VALID if buffer valid and count set; error code on failure (count unchanged).
 * @throws SocketUTF8_Failed if count is NULL or data is NULL when len > 0 (invalid arguments).
 * @threadsafe Yes - pure function.
 *
 * @see SocketUTF8_validate() for validation without counting.
 * @see SocketUTF8_decode() low-level decoding used internally.
 */
extern SocketUTF8_Result
SocketUTF8_count_codepoints (const unsigned char *data, size_t len,
                             size_t *count);

/**
 * @brief Retrieve descriptive string for a UTF-8 validation result code.
 * @ingroup utilities
 * @param result SocketUTF8_Result code from validation function.
 *
 * Returns a static, human-readable string describing the result (e.g., "valid", "invalid sequence").
 * Useful for logging, error reporting, or debugging without custom mapping.
 *
 * @return Const C string (never NULL); static storage, do not free.
 * @threadsafe Yes - returns static strings.
 * @note Strings are English; consider localization for user-facing apps.
 *
 * @see SocketUTF8_Result enumeration of codes.
 * @see SocketUTF8_validate() which produces these results.
 */
extern const char *SocketUTF8_result_string (SocketUTF8_Result result);

#endif /* SOCKETUTF8_INCLUDED */
