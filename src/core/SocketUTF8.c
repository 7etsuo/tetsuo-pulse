/**
 * SocketUTF8.c - UTF-8 Validation Implementation
 *
 * Part of the Socket Library
 *
 * Implements DFA-based UTF-8 validation using the Hoehrmann algorithm,
 * which provides O(n) time complexity with O(1) space complexity.
 *
 * The DFA approach handles all UTF-8 security requirements:
 * - Overlong encoding rejection (built into state transitions)
 * - Surrogate rejection (U+D800-U+DFFF)
 * - Maximum code point validation (U+10FFFF)
 * - Proper continuation byte checking
 *
 * Reference: http://bjoern.hoehrmann.de/utf-8/decoder/dfa/
 *
 * Thread safety: All functions are thread-safe (no global state).
 */

#include "core/SocketUTF8.h"
#include "core/SocketUtil.h"

#include <assert.h>
#include <string.h>

/* ============================================================================
 * Exception Definition
 * ============================================================================ */

const Except_T SocketUTF8_Failed
    = { &SocketUTF8_Failed, "UTF-8 validation failed" };

/* Thread-local exception for detailed error messages */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketUTF8);

/* ============================================================================
 * Hoehrmann DFA Tables
 * ============================================================================
 *
 * The DFA uses two tables:
 * 1. utf8_class[256]: Maps each byte to a character class (0-11)
 * 2. utf8_state[UTF8_NUM_DFA_STATES * UTF8_NUM_CHAR_CLASSES]: State transitions
 *
 * States (UTF8_NUM_DFA_STATES = 9):
 *   0 = UTF8_DFA_ACCEPT (valid complete sequence)
 *   1 = UTF8_DFA_REJECT (invalid sequence)
 *   2-8 = intermediate states (expecting continuation bytes)
 *
 * Character classes (UTF8_NUM_CHAR_CLASSES = 12):
 *   0: 00..7F (ASCII)
 *   1: 80..8F (continuation byte, lower)
 *   2: 90..9F (continuation byte, middle-low)
 *   3: A0..BF (continuation byte, upper)
 *   4: C0..C1 (invalid overlong 2-byte start)
 *   5: C2..DF (valid 2-byte start)
 *   6: E0     (3-byte start, special: next must be A0..BF)
 *   7: E1..EC, EE..EF (3-byte start)
 *   8: ED     (3-byte start, special: next must be 80..9F for surrogates)
 *   9: F0     (4-byte start, special: next must be 90..BF)
 *  10: F1..F3 (4-byte start)
 *  11: F4     (4-byte start, special: next must be 80..8F)
 */

/** DFA accept state alias (valid complete sequence) */
#define UTF8_DFA_ACCEPT UTF8_STATE_ACCEPT

/** DFA reject state alias (invalid sequence) */
#define UTF8_DFA_REJECT UTF8_STATE_REJECT

/** Number of character classes in the DFA (byte classification) */
#define UTF8_NUM_CHAR_CLASSES 12

/** Number of states in the DFA */
#define UTF8_NUM_DFA_STATES 9

/* clang-format off */

/**
 * UTF-8 byte classification table
 *
 * Maps each byte value (0x00-0xFF) to a character class for the DFA.
 * This table encodes the UTF-8 byte patterns and their roles.
 */
static const uint8_t utf8_class[256] = {
  /*      0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F */
  /* 0 */ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
  /* 1 */ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
  /* 2 */ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
  /* 3 */ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
  /* 4 */ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
  /* 5 */ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
  /* 6 */ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
  /* 7 */ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
  /* 8 */ 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
  /* 9 */ 2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,
  /* A */ 3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,
  /* B */ 3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,
  /* C */ 4,  4,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,
  /* D */ 5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,
  /* E */ 6,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  8,  7,  7,
  /* F */ 9, 10, 10, 10, 11,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4
};

/**
 * UTF-8 state transition table
 *
 * Given current state and character class, returns next state.
 * Indexed as: utf8_state[state * UTF8_NUM_CHAR_CLASSES + class]
 *
 * The table is organized with UTF8_NUM_CHAR_CLASSES (12) columns per row
 * (one per character class), and rows represent states 0 through 8
 * (UTF8_NUM_DFA_STATES = 9 total states).
 */
static const uint8_t utf8_state[] = {
  /* State UTF8_STATE_ACCEPT: From accept state (initial or complete sequence) */
  /*        ASCII 80-8F 90-9F A0-BF C0-C1 C2-DF  E0  E1-EC/EE-EF ED  F0 F1-F3 F4 */
  /* ACCEPT*/  0,    1,    1,    1,    1,    2,   3,    4,    5,  6,   7,   8,

  /* State UTF8_STATE_REJECT: Sink state for invalid sequences - stay rejected */
  /* REJECT*/  1,    1,    1,    1,    1,    1,   1,    1,    1,  1,   1,   1,

  /* State UTF8_STATE_2BYTE_EXPECT: Expecting 1 continuation byte (2-byte final) */
  /* 2BYTE */  1,    0,    0,    0,    1,    1,   1,    1,    1,  1,   1,   1,

  /* State UTF8_STATE_E0_SPECIAL: After E0, expect A0-BF (avoid overlong), then cont */
  /* E0_SP  */  1,    1,    1,    2,    1,    1,   1,    1,    1,  1,   1,   1,

  /* State UTF8_STATE_3BYTE_EXPECT: Expecting 2 continuation bytes (3-byte or 4-byte mid) */
  /* 3BYTE */  1,    2,    2,    2,    1,    1,   1,    1,    1,  1,   1,   1,

  /* State UTF8_STATE_ED_SPECIAL: After ED, expect 80-9F (avoid surrogates), then cont */
  /* ED_SP  */  1,    2,    2,    1,    1,    1,   1,    1,    1,  1,   1,   1,

  /* State UTF8_STATE_F0_SPECIAL: After F0, expect 90-BF (avoid overlong), then 2 cont */
  /* F0_SP  */  1,    1,    4,    4,    1,    1,   1,    1,    1,  1,   1,   1,

  /* State UTF8_STATE_4BYTE_EXPECT: Expecting 3 continuation bytes (4-byte) */
  /* 4BYTE */  1,    4,    4,    4,    1,    1,   1,    1,    1,  1,   1,   1,

  /* State UTF8_STATE_F4_SPECIAL: After F4, expect 80-8F (avoid >U+10FFFF), then 2 cont */
  /* F4_SP  */  1,    4,    1,    1,    1,    1,   1,    1,    1,  1,   1,   1,
};

/* clang-format on */

/**
 * Number of bytes expected for each starting state
 * Maps intermediate state -> total bytes in sequence
 */
static const uint8_t utf8_state_bytes[] = {
  1, /* UTF8_STATE_ACCEPT: ASCII/single-byte complete */
  0, /* UTF8_STATE_REJECT: Invalid - no bytes */
  2, /* UTF8_STATE_2BYTE_EXPECT: 2-byte total */
  3, /* UTF8_STATE_E0_SPECIAL: 3-byte total (after E0) */
  3, /* UTF8_STATE_3BYTE_EXPECT: 3-byte total */
  3, /* UTF8_STATE_ED_SPECIAL: 3-byte total (after ED) */
  4, /* UTF8_STATE_F0_SPECIAL: 4-byte total (after F0) */
  4, /* UTF8_STATE_4BYTE_EXPECT: 4-byte total */
  4, /* UTF8_STATE_F4_SPECIAL: 4-byte total (after F4) */
};

/* ============================================================================
 * DFA State Constants
 * ============================================================================ */

/**
 * DFA state identifiers for readability
 */
#define UTF8_STATE_ACCEPT          0
#define UTF8_STATE_REJECT          1
#define UTF8_STATE_2BYTE_EXPECT    2  /* Expecting 1 continuation */
#define UTF8_STATE_E0_SPECIAL      3  /* After E0, expect A0-BF then cont */
#define UTF8_STATE_3BYTE_EXPECT    4  /* Expecting 2 continuations (3-byte mid) */
#define UTF8_STATE_ED_SPECIAL      5  /* After ED, expect 80-9F then cont */
#define UTF8_STATE_F0_SPECIAL      6  /* After F0, expect 90-BF then 2 cont */
#define UTF8_STATE_4BYTE_EXPECT    7  /* Expecting 3 continuations */
#define UTF8_STATE_F4_SPECIAL      8  /* After F4, expect 80-8F then 2 cont */

/* ============================================================================
 * Result String Table
 * ============================================================================ */

static const char *utf8_result_strings[] = {
  "Valid UTF-8",                            /* UTF8_VALID */
  "Invalid byte sequence",                  /* UTF8_INVALID */
  "Incomplete sequence (needs more bytes)", /* UTF8_INCOMPLETE */
  "Overlong encoding (security issue)",     /* UTF8_OVERLONG */
  "UTF-16 surrogate (U+D800-U+DFFF)",       /* UTF8_SURROGATE */
  "Code point exceeds U+10FFFF"             /* UTF8_TOO_LARGE */
};

/* ============================================================================
 * Byte Pattern Constants
 * ============================================================================ */

/**
 * UTF-8 byte masks and start bytes for lead/continuation identification
 */
#define UTF8_CONTINUATION_MASK     0xC0
#define UTF8_CONTINUATION_START    0x80
#define UTF8_ASCII_HIGH_BIT        0x80

#define UTF8_2BYTE_MASK            0xE0
#define UTF8_2BYTE_START           0xC0
#define UTF8_2BYTE_OVERLONG_END    0xC1  /* C0-C1 invalid overlong starts */
#define UTF8_2BYTE_MIN_VALID       0xC2  /* C2-DF valid, C0-C1 overlong invalid */

#define UTF8_3BYTE_MASK            0xF0
#define UTF8_3BYTE_START           0xE0

#define UTF8_4BYTE_MASK            0xF8
#define UTF8_4BYTE_START           0xF0
#define UTF8_4BYTE_MAX_VALID       0xF4  /* F0-F4 valid, F5-FF invalid */

#define UTF8_INVALID_5BYTE_START   0xF5

/* Lead byte payload bit masks */
#define UTF8_2BYTE_LEAD_MASK       0x1F  /* 5 bits after 110 */
#define UTF8_3BYTE_LEAD_MASK       0x0F  /* 4 bits after 1110 */
#define UTF8_4BYTE_LEAD_MASK       0x07  /* 3 bits after 11110 */

/* Continuation payload mask (6 bits) */
#define UTF8_CONTINUATION_MASK_VAL 0x3F  /* 6 bits after 10 */

/* Specific overlong/surrogate/too-large ranges */
#define UTF8_E0_OVERLONG_MIN       0x80
#define UTF8_E0_OVERLONG_MAX       0x9F

#define UTF8_ED_SURROGATE_MIN      0xA0
#define UTF8_ED_SURROGATE_MAX      0xBF

#define UTF8_F0_OVERLONG_MIN       0x80
#define UTF8_F0_OVERLONG_MAX       0x8F

#define UTF8_F4_TOO_LARGE_MIN      0x90
#define UTF8_F4_TOO_LARGE_MAX      0xBF

/* ============================================================================
 * DFA Helpers
 * ============================================================================ */

/**
 * dfa_transition - Compute next DFA state from current state and char class
 * @state: Current DFA state (0-8)
 * @char_class: Character class from utf8_class[byte] (0-11)
 *
 * Returns: Next DFA state per utf8_state table lookup
 * Thread-safe: Yes (pure function)
 */
static inline uint32_t
dfa_transition (uint32_t state, uint8_t char_class)
{
  return utf8_state[state * UTF8_NUM_CHAR_CLASSES + char_class];
}

/**
 * update_sequence_tracking - Update bytes tracking for incremental validation
 * @state: Incremental state structure to update (not NULL)
 * @prev_state: DFA state before processing current byte
 * @curr_state: DFA state after processing current byte
 *
 * Updates state->bytes_needed and state->bytes_seen based on transition.
 * Used only in incremental mode to track partial multi-byte sequences.
 *
 * Thread-safe: Yes (modifies caller-owned state)
 */
static void
update_sequence_tracking (SocketUTF8_State *state, uint32_t prev_state, uint32_t curr_state)
{
  if (prev_state == UTF8_STATE_ACCEPT && curr_state != UTF8_STATE_ACCEPT) {
    state->bytes_needed = utf8_state_bytes[curr_state];
    state->bytes_seen = 1;
  } else if (prev_state != UTF8_STATE_ACCEPT) {
    state->bytes_seen++;
    if (curr_state == UTF8_STATE_ACCEPT) {
      state->bytes_needed = 0;
      state->bytes_seen = 0;
    }
  }
}

/* ============================================================================
 * Internal Helpers
 * ============================================================================ */

/**
 * is_continuation_byte - Check if byte is valid UTF-8 continuation
 * @byte: Byte to check
 *
 * Returns: 1 if valid continuation (10xxxxxx), 0 otherwise
 */
static inline int
is_continuation_byte (unsigned char byte)
{
  return (byte & UTF8_CONTINUATION_MASK) == UTF8_CONTINUATION_START;
}

/**
 * validate_continuations - Validate a sequence of continuation bytes
 * @data: Pointer to continuation bytes (starts at data[1])
 * @count: Number of continuation bytes to validate
 * @consumed: Output - set to index of first invalid byte on failure
 *
 * Returns: 1 if all valid, 0 if invalid (consumed set to failure index)
 */
static int
validate_continuations (const unsigned char *data, int count, int *consumed)
{
  int i;

  for (i = 1; i <= count; i++)
    {
      if (!is_continuation_byte (data[i]))
        {
          *consumed = i;
          return 0;
        }
    }
  return 1;
}

/**
 * classify_error - Classify error type based on DFA state and byte
 * @prev_state: DFA state before the error
 * @byte: Byte that caused the error
 *
 * Returns: Specific error type for better diagnostics
 *
 * When we hit reject state, determine what kind of error occurred.
 */
static SocketUTF8_Result
classify_error (uint32_t prev_state, unsigned char byte)
{
  /* Check for overlong 2-byte encodings (C0-C1 starts) - only from accept */
  if (prev_state == UTF8_STATE_ACCEPT && byte >= UTF8_2BYTE_START && byte <= UTF8_2BYTE_OVERLONG_END)
    return UTF8_OVERLONG;

  /* Check for invalid bytes (F5-FF) - only from accept state */
  if (prev_state == UTF8_STATE_ACCEPT && byte >= UTF8_INVALID_5BYTE_START)
    return UTF8_INVALID;

  /* E0 followed by 80-9F is overlong 3-byte */
  if (prev_state == UTF8_STATE_E0_SPECIAL && byte >= UTF8_E0_OVERLONG_MIN && byte <= UTF8_E0_OVERLONG_MAX)
    return UTF8_OVERLONG;

  /* ED followed by A0-BF is surrogate */
  if (prev_state == UTF8_STATE_ED_SPECIAL && byte >= UTF8_ED_SURROGATE_MIN && byte <= UTF8_ED_SURROGATE_MAX)
    return UTF8_SURROGATE;

  /* F0 followed by 80-8F is overlong 4-byte */
  if (prev_state == UTF8_STATE_F0_SPECIAL && byte >= UTF8_F0_OVERLONG_MIN && byte <= UTF8_F0_OVERLONG_MAX)
    return UTF8_OVERLONG;

  /* F4 followed by 90-BF exceeds U+10FFFF */
  if (prev_state == UTF8_STATE_F4_SPECIAL && byte >= UTF8_F4_TOO_LARGE_MIN && byte <= UTF8_F4_TOO_LARGE_MAX)
    return UTF8_TOO_LARGE;

  return UTF8_INVALID;
}

/**
 * classify_first_byte_error - Classify error for invalid first byte
 * @byte: First byte that was invalid
 *
 * Returns: Specific error type
 */
static SocketUTF8_Result
classify_first_byte_error (unsigned char byte)
{
  if (byte >= UTF8_2BYTE_START && byte <= UTF8_2BYTE_OVERLONG_END)
    return UTF8_OVERLONG;
  return UTF8_INVALID;
}

/* ============================================================================
 * One-Shot Validation
 * ============================================================================ */

SocketUTF8_Result
SocketUTF8_validate (const unsigned char *data, size_t len)
{
  if (len > 0 && !data) {
    SOCKET_RAISE_MSG (SocketUTF8, SocketUTF8_Failed,
                      "data must not be NULL when len > 0");
  }

  uint32_t state = UTF8_STATE_ACCEPT;
  uint32_t prev_state;
  size_t i;

  if (len == 0)
    return UTF8_VALID;

  for (i = 0; i < len; i++)
    {
      uint8_t byte_class = utf8_class[data[i]];
      prev_state = state;
      state = dfa_transition (state, byte_class);

      if (state == UTF8_STATE_REJECT)
        return classify_error (prev_state, data[i]);
    }

  return (state == UTF8_STATE_ACCEPT) ? UTF8_VALID : UTF8_INCOMPLETE;
}

SocketUTF8_Result
SocketUTF8_validate_str (const char *str)
{
  if (!str)
    return UTF8_VALID;

  return SocketUTF8_validate ((const unsigned char *)str, strlen (str));
}

/* ============================================================================
 * Incremental Validation
 * ============================================================================ */

void
SocketUTF8_init (SocketUTF8_State *state)
{
  if (!state) {
    SOCKET_RAISE_MSG (SocketUTF8, SocketUTF8_Failed, "state must not be NULL");
  }

  state->state = UTF8_STATE_ACCEPT;
  state->bytes_needed = 0;
  state->bytes_seen = 0;
}

/**
 * get_current_status - Get current validation status from DFA state
 * @dfa_state: Current DFA state
 *
 * Returns: UTF8_VALID if accept, UTF8_INVALID if reject, UTF8_INCOMPLETE otherwise
 */
static inline SocketUTF8_Result
get_current_status (uint32_t state)
{
  if (state == UTF8_STATE_ACCEPT)
    return UTF8_VALID;
  if (state == UTF8_STATE_REJECT)
    return UTF8_INVALID;
  return UTF8_INCOMPLETE;
}

SocketUTF8_Result
SocketUTF8_update (SocketUTF8_State *state, const unsigned char *data,
                   size_t len)
{
  if (!state) {
    SOCKET_RAISE_MSG (SocketUTF8, SocketUTF8_Failed, "state must not be NULL");
  }
  if (len > 0 && !data) {
    SOCKET_RAISE_MSG (SocketUTF8, SocketUTF8_Failed,
                      "data must not be NULL when len > 0");
  }

  uint32_t dfa_state;
  uint32_t prev_state;
  size_t i;

  dfa_state = state->state;

  if (dfa_state == UTF8_STATE_REJECT)
    return UTF8_INVALID;

  if (len == 0)
    return get_current_status (dfa_state);

  for (i = 0; i < len; i++)
    {
      uint8_t byte_class = utf8_class[data[i]];
      prev_state = dfa_state;
      dfa_state = dfa_transition (dfa_state, byte_class);

      if (dfa_state == UTF8_STATE_REJECT)
        {
          state->state = UTF8_STATE_REJECT;
          return classify_error (prev_state, data[i]);
        }

      /* Track bytes for multi-byte sequences */
      update_sequence_tracking (state, prev_state, dfa_state);
    }

  state->state = dfa_state;
  return get_current_status (dfa_state);
}

SocketUTF8_Result
SocketUTF8_finish (const SocketUTF8_State *state)
{
  if (!state) {
    SOCKET_RAISE_MSG (SocketUTF8, SocketUTF8_Failed, "state must not be NULL");
  }
  return get_current_status (state->state);
}

void
SocketUTF8_reset (SocketUTF8_State *state)
{
  SocketUTF8_init (state);
}

/* ============================================================================
 * UTF-8 Utilities
 * ============================================================================ */

int
SocketUTF8_codepoint_len (uint32_t codepoint)
{
  /* Check for surrogate (invalid) */
  if (codepoint >= SOCKET_UTF8_SURROGATE_MIN
      && codepoint <= SOCKET_UTF8_SURROGATE_MAX)
    return 0;

  /* Check for out of range */
  if (codepoint > SOCKET_UTF8_MAX_CODEPOINT)
    return 0;

  if (codepoint <= SOCKET_UTF8_1BYTE_MAX)
    return 1;
  if (codepoint <= SOCKET_UTF8_2BYTE_MAX)
    return 2;
  if (codepoint <= SOCKET_UTF8_3BYTE_MAX)
    return 3;
  return 4;
}

int
SocketUTF8_sequence_len (unsigned char first_byte)
{
  /* ASCII: 0xxxxxxx (high bit 0) */
  if ((first_byte & UTF8_ASCII_HIGH_BIT) == 0)
    return 1;

  /* Continuation bytes: 10xxxxxx - invalid as start */
  if ((first_byte & UTF8_CONTINUATION_MASK) == UTF8_CONTINUATION_START)
    return 0;

  /* 2-byte: 110xxxxx (C2-DF valid, C0-C1 overlong) */
  if ((first_byte & UTF8_2BYTE_MASK) == UTF8_2BYTE_START)
    return (first_byte >= UTF8_2BYTE_MIN_VALID) ? 2 : 0;

  /* 3-byte: 1110xxxx (E0-EF) */
  if ((first_byte & UTF8_3BYTE_MASK) == UTF8_3BYTE_START)
    return 3;

  /* 4-byte: 11110xxx (F0-F4 valid, F5-FF invalid) */
  if ((first_byte & UTF8_4BYTE_MASK) == UTF8_4BYTE_START)
    return (first_byte <= UTF8_4BYTE_MAX_VALID) ? 4 : 0;

  /* Invalid: 111110xx or higher (F5-FF, or malformed) */
  return 0;
}

int
SocketUTF8_encode (uint32_t codepoint, unsigned char *output)
{
  int len;

  if (!output) {
    return 0;
  }

  len = SocketUTF8_codepoint_len (codepoint);
  if (len == 0)
    return 0;

  switch (len)
    {
    case 1:
      output[0] = (unsigned char)codepoint;
      break;

    case 2:
      output[0] = (unsigned char)(UTF8_2BYTE_START | ((codepoint >> 6) & UTF8_2BYTE_LEAD_MASK));
      output[1] = (unsigned char)(UTF8_CONTINUATION_START | (codepoint & UTF8_CONTINUATION_MASK_VAL));
      break;

    case 3:
      output[0] = (unsigned char)(UTF8_3BYTE_START | ((codepoint >> 12) & UTF8_3BYTE_LEAD_MASK));
      output[1] = (unsigned char)(UTF8_CONTINUATION_START | ((codepoint >> 6) & UTF8_CONTINUATION_MASK_VAL));
      output[2] = (unsigned char)(UTF8_CONTINUATION_START | (codepoint & UTF8_CONTINUATION_MASK_VAL));
      break;

    case 4:
      output[0] = (unsigned char)(UTF8_4BYTE_START | ((codepoint >> 18) & UTF8_4BYTE_LEAD_MASK));
      output[1] = (unsigned char)(UTF8_CONTINUATION_START | ((codepoint >> 12) & UTF8_CONTINUATION_MASK_VAL));
      output[2] = (unsigned char)(UTF8_CONTINUATION_START | ((codepoint >> 6) & UTF8_CONTINUATION_MASK_VAL));
      output[3] = (unsigned char)(UTF8_CONTINUATION_START | (codepoint & UTF8_CONTINUATION_MASK_VAL));
      break;
    }

  return len;
}

/**
 * decode_2byte - Decode a 2-byte UTF-8 sequence
 * @data: Pointer to 2-byte sequence
 * @codepoint: Output codepoint
 * @consumed: Output bytes consumed
 *
 * Returns: UTF8_VALID on success, error code on failure
 */
static SocketUTF8_Result
decode_2byte (const unsigned char *data, uint32_t *codepoint, size_t *consumed)
{
  uint32_t cp;

  if (!is_continuation_byte (data[1]))
    {
      if (consumed)
        *consumed = 1;
      return UTF8_INVALID;
    }

  cp = ((uint32_t)(data[0] & UTF8_2BYTE_LEAD_MASK) << 6) | (data[1] & UTF8_CONTINUATION_MASK_VAL);

  if (cp < (SOCKET_UTF8_1BYTE_MAX + 1u))
    {
      if (consumed)
        *consumed = 2;
      return UTF8_OVERLONG;
    }

  *codepoint = cp;
  if (consumed)
    *consumed = 2;
  return UTF8_VALID;
}

/**
 * decode_3byte - Decode a 3-byte UTF-8 sequence
 * @data: Pointer to 3-byte sequence
 * @codepoint: Output codepoint
 * @consumed: Output bytes consumed
 *
 * Returns: UTF8_VALID on success, error code on failure
 */
static SocketUTF8_Result
decode_3byte (const unsigned char *data, uint32_t *codepoint, size_t *consumed)
{
  uint32_t cp;
  int fail_idx;

  if (!validate_continuations (data, 2, &fail_idx))
    {
      if (consumed)
        *consumed = (size_t)fail_idx;
      return UTF8_INVALID;
    }

  cp = ((uint32_t)(data[0] & UTF8_3BYTE_LEAD_MASK) << 12) | ((uint32_t)(data[1] & UTF8_CONTINUATION_MASK_VAL) << 6)
       | (data[2] & UTF8_CONTINUATION_MASK_VAL);

  if (cp < (SOCKET_UTF8_2BYTE_MAX + 1u))
    {
      if (consumed)
        *consumed = 3;
      return UTF8_OVERLONG;
    }

  if (cp >= SOCKET_UTF8_SURROGATE_MIN && cp <= SOCKET_UTF8_SURROGATE_MAX)
    {
      if (consumed)
        *consumed = 3;
      return UTF8_SURROGATE;
    }

  *codepoint = cp;
  if (consumed)
    *consumed = 3;
  return UTF8_VALID;
}

/**
 * decode_4byte - Decode a 4-byte UTF-8 sequence
 * @data: Pointer to 4-byte sequence
 * @codepoint: Output codepoint
 * @consumed: Output bytes consumed
 *
 * Returns: UTF8_VALID on success, error code on failure
 */
static SocketUTF8_Result
decode_4byte (const unsigned char *data, uint32_t *codepoint, size_t *consumed)
{
  uint32_t cp;
  int fail_idx;

  if (!validate_continuations (data, 3, &fail_idx))
    {
      if (consumed)
        *consumed = (size_t)fail_idx;
      return UTF8_INVALID;
    }

  cp = ((uint32_t)(data[0] & UTF8_4BYTE_LEAD_MASK) << 18) | ((uint32_t)(data[1] & UTF8_CONTINUATION_MASK_VAL) << 12)
       | ((uint32_t)(data[2] & UTF8_CONTINUATION_MASK_VAL) << 6) | (data[3] & UTF8_CONTINUATION_MASK_VAL);

  if (cp < SOCKET_UTF8_4BYTE_MIN)
    {
      if (consumed)
        *consumed = 4;
      return UTF8_OVERLONG;
    }

  if (cp > SOCKET_UTF8_MAX_CODEPOINT)
    {
      if (consumed)
        *consumed = 4;
      return UTF8_TOO_LARGE;
    }

  *codepoint = cp;
  if (consumed)
    *consumed = 4;
  return UTF8_VALID;
}

SocketUTF8_Result
SocketUTF8_decode (const unsigned char *data, size_t len, uint32_t *codepoint,
                   size_t *consumed)
{
  uint32_t cp = 0;
  int seq_len;
  SocketUTF8_Result result;

  if (len > 0 && !data) {
    SOCKET_RAISE_MSG (SocketUTF8, SocketUTF8_Failed,
                      "data must not be NULL when len > 0");
  }

  if (len == 0)
    {
      if (consumed)
        *consumed = 0;
      return UTF8_INCOMPLETE;
    }

  seq_len = SocketUTF8_sequence_len (data[0]);
  if (seq_len == 0)
    {
      if (consumed)
        *consumed = 1;
      return classify_first_byte_error (data[0]);
    }

  if ((size_t)seq_len > len)
    {
      if (consumed)
        *consumed = len;
      return UTF8_INCOMPLETE;
    }

  switch (seq_len)
    {
    case 1:
      cp = data[0];
      if (consumed)
        *consumed = 1;
      result = UTF8_VALID;
      break;

    case 2:
      result = decode_2byte (data, &cp, consumed);
      break;

    case 3:
      result = decode_3byte (data, &cp, consumed);
      break;

    case 4:
      result = decode_4byte (data, &cp, consumed);
      break;

    default:
      if (consumed)
        *consumed = 1;
      return UTF8_INVALID;
    }

  if (result == UTF8_VALID && codepoint)
    *codepoint = cp;

  return result;
}

SocketUTF8_Result
SocketUTF8_count_codepoints (const unsigned char *data, size_t len,
                             size_t *count)
{
  if (!count) {
    SOCKET_RAISE_MSG (SocketUTF8, SocketUTF8_Failed, "count output must not be NULL");
  }
  if (len > 0 && !data) {
    SOCKET_RAISE_MSG (SocketUTF8, SocketUTF8_Failed,
                      "data must not be NULL when len > 0");
  }

  size_t cp_count = 0;
  size_t pos = 0;
  SocketUTF8_Result result;
  size_t consumed;

  *count = 0;

  if (len == 0)
    return UTF8_VALID;

  while (pos < len)
    {
      result = SocketUTF8_decode (data + pos, len - pos, NULL, &consumed);
      if (result != UTF8_VALID)
        return result;

      if (consumed == 0) {  /* Safety: prevent infinite loop */
        return UTF8_INVALID;
      }

      cp_count++;
      pos += consumed;
    }

  *count = cp_count;
  return UTF8_VALID;
}

const char *
SocketUTF8_result_string (SocketUTF8_Result result)
{
  if (result < 0 || result > UTF8_TOO_LARGE)
    return "Unknown result code";

  return utf8_result_strings[result];
}
