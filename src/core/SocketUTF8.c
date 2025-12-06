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

/** DFA accept state (valid complete sequence) */
#define UTF8_DFA_ACCEPT 0

/** DFA reject state (invalid sequence) */
#define UTF8_DFA_REJECT 1

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
  /* State 0: Accept (initial/complete sequence) */
  /*        ASC  80-8F 90-9F A0-BF C0-C1 C2-DF  E0  E1-EF  ED   F0  F1-F3  F4  */
  /*    0 */  0,    1,    1,    1,    1,    2,   3,    4,   5,   6,    7,   8,

  /* State 1: Reject (invalid) */
  /*    1 */  1,    1,    1,    1,    1,    1,   1,    1,   1,   1,    1,   1,

  /* State 2: Expecting 1 continuation byte (final before accept) */
  /*    2 */  1,    0,    0,    0,    1,    1,   1,    1,   1,   1,    1,   1,

  /* State 3: After E0, need A0-BF then 1 more continuation (prevents overlong) */
  /*    3 */  1,    1,    1,    2,    1,    1,   1,    1,   1,   1,    1,   1,

  /* State 4: Need 2 continuations (3-byte middle, 4-byte after special first) */
  /*    4 */  1,    2,    2,    2,    1,    1,   1,    1,   1,   1,    1,   1,

  /* State 5: After ED, need 80-9F then 1 more continuation (prevents surrogates) */
  /*    5 */  1,    2,    2,    1,    1,    1,   1,    1,   1,   1,    1,   1,

  /* State 6: After F0, need 90-BF then 2 more continuations (prevents overlong) */
  /*    6 */  1,    1,    4,    4,    1,    1,   1,    1,   1,   1,    1,   1,

  /* State 7: Need 3 continuations (4-byte start) */
  /*    7 */  1,    4,    4,    4,    1,    1,   1,    1,   1,   1,    1,   1,

  /* State 8: After F4, need 80-8F then 2 more continuations (prevents >U+10FFFF) */
  /*    8 */  1,    4,    1,    1,    1,    1,   1,    1,   1,   1,    1,   1,
};

/* clang-format on */

/**
 * Number of bytes expected for each starting state
 * Maps intermediate state -> total bytes in sequence
 */
static const uint8_t utf8_state_bytes[] = {
  1, /* 0: Accept (ASCII complete) */
  0, /* 1: Reject */
  2, /* 2: 2-byte sequence */
  3, /* 3: 3-byte after E0 */
  3, /* 4: 3-byte sequence */
  3, /* 5: 3-byte after ED */
  4, /* 6: 4-byte after F0 */
  4, /* 7: 4-byte sequence */
  4, /* 8: 4-byte after F4 */
};

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
  return (byte & 0xC0) == 0x80;
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
  if (prev_state == UTF8_DFA_ACCEPT && byte >= 0xC0 && byte <= 0xC1)
    return UTF8_OVERLONG;

  /* Check for invalid bytes (F5-FF) - only from accept state */
  if (prev_state == UTF8_DFA_ACCEPT && byte >= 0xF5)
    return UTF8_INVALID;

  /* E0 followed by 80-9F is overlong 3-byte */
  if (prev_state == 3 && byte >= 0x80 && byte <= 0x9F)
    return UTF8_OVERLONG;

  /* ED followed by A0-BF is surrogate */
  if (prev_state == 5 && byte >= 0xA0 && byte <= 0xBF)
    return UTF8_SURROGATE;

  /* F0 followed by 80-8F is overlong 4-byte */
  if (prev_state == 6 && byte >= 0x80 && byte <= 0x8F)
    return UTF8_OVERLONG;

  /* F4 followed by 90-BF exceeds U+10FFFF */
  if (prev_state == 8 && byte >= 0x90 && byte <= 0xBF)
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
  if (byte >= 0xC0 && byte <= 0xC1)
    return UTF8_OVERLONG;
  return UTF8_INVALID;
}

/* ============================================================================
 * One-Shot Validation
 * ============================================================================ */

SocketUTF8_Result
SocketUTF8_validate (const unsigned char *data, size_t len)
{
  uint32_t state = UTF8_DFA_ACCEPT;
  uint32_t prev_state;
  size_t i;

  if (len == 0 || !data)
    return UTF8_VALID;

  for (i = 0; i < len; i++)
    {
      uint8_t byte_class = utf8_class[data[i]];
      prev_state = state;
      state = utf8_state[state * UTF8_NUM_CHAR_CLASSES + byte_class];

      if (state == UTF8_DFA_REJECT)
        return classify_error (prev_state, data[i]);
    }

  return (state == UTF8_DFA_ACCEPT) ? UTF8_VALID : UTF8_INCOMPLETE;
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
  assert (state);

  state->state = UTF8_DFA_ACCEPT;
  state->codepoint = 0;
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
get_current_status (uint32_t dfa_state)
{
  if (dfa_state == UTF8_DFA_ACCEPT)
    return UTF8_VALID;
  if (dfa_state == UTF8_DFA_REJECT)
    return UTF8_INVALID;
  return UTF8_INCOMPLETE;
}

SocketUTF8_Result
SocketUTF8_update (SocketUTF8_State *state, const unsigned char *data,
                   size_t len)
{
  uint32_t dfa_state;
  uint32_t prev_state;
  size_t i;

  assert (state);

  if (len == 0 || !data)
    return get_current_status (state->state);

  dfa_state = state->state;

  if (dfa_state == UTF8_DFA_REJECT)
    return UTF8_INVALID;

  for (i = 0; i < len; i++)
    {
      uint8_t byte_class = utf8_class[data[i]];
      prev_state = dfa_state;
      dfa_state = utf8_state[dfa_state * UTF8_NUM_CHAR_CLASSES + byte_class];

      if (dfa_state == UTF8_DFA_REJECT)
        {
          state->state = UTF8_DFA_REJECT;
          return classify_error (prev_state, data[i]);
        }

      /* Track bytes for multi-byte sequences */
      if (prev_state == UTF8_DFA_ACCEPT && dfa_state != UTF8_DFA_ACCEPT)
        {
          state->bytes_needed = utf8_state_bytes[dfa_state];
          state->bytes_seen = 1;
        }
      else if (prev_state != UTF8_DFA_ACCEPT)
        {
          state->bytes_seen++;
          if (dfa_state == UTF8_DFA_ACCEPT)
            {
              state->bytes_needed = 0;
              state->bytes_seen = 0;
            }
        }
    }

  state->state = dfa_state;
  return get_current_status (dfa_state);
}

SocketUTF8_Result
SocketUTF8_finish (const SocketUTF8_State *state)
{
  assert (state);
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

  if (codepoint <= 0x7F)
    return 1;
  if (codepoint <= 0x7FF)
    return 2;
  if (codepoint <= 0xFFFF)
    return 3;
  return 4;
}

int
SocketUTF8_sequence_len (unsigned char first_byte)
{
  /* ASCII: 0xxxxxxx */
  if ((first_byte & 0x80) == 0)
    return 1;

  /* Continuation bytes: 10xxxxxx - invalid as start */
  if ((first_byte & 0xC0) == 0x80)
    return 0;

  /* 2-byte: 110xxxxx (C2-DF valid, C0-C1 overlong) */
  if ((first_byte & 0xE0) == 0xC0)
    return (first_byte >= 0xC2) ? 2 : 0;

  /* 3-byte: 1110xxxx (E0-EF) */
  if ((first_byte & 0xF0) == 0xE0)
    return 3;

  /* 4-byte: 11110xxx (F0-F4 valid, F5-F7 invalid) */
  if ((first_byte & 0xF8) == 0xF0)
    return (first_byte <= 0xF4) ? 4 : 0;

  /* Invalid: 11111xxx (F8-FF) */
  return 0;
}

int
SocketUTF8_encode (uint32_t codepoint, unsigned char *output)
{
  int len;

  if (!output)
    return 0;

  len = SocketUTF8_codepoint_len (codepoint);
  if (len == 0)
    return 0;

  switch (len)
    {
    case 1:
      output[0] = (unsigned char)codepoint;
      break;

    case 2:
      output[0] = (unsigned char)(0xC0 | (codepoint >> 6));
      output[1] = (unsigned char)(0x80 | (codepoint & 0x3F));
      break;

    case 3:
      output[0] = (unsigned char)(0xE0 | (codepoint >> 12));
      output[1] = (unsigned char)(0x80 | ((codepoint >> 6) & 0x3F));
      output[2] = (unsigned char)(0x80 | (codepoint & 0x3F));
      break;

    case 4:
      output[0] = (unsigned char)(0xF0 | (codepoint >> 18));
      output[1] = (unsigned char)(0x80 | ((codepoint >> 12) & 0x3F));
      output[2] = (unsigned char)(0x80 | ((codepoint >> 6) & 0x3F));
      output[3] = (unsigned char)(0x80 | (codepoint & 0x3F));
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

  cp = ((uint32_t)(data[0] & 0x1F) << 6) | (data[1] & 0x3F);

  if (cp < 0x80)
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

  cp = ((uint32_t)(data[0] & 0x0F) << 12) | ((uint32_t)(data[1] & 0x3F) << 6)
       | (data[2] & 0x3F);

  if (cp < 0x800)
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

  cp = ((uint32_t)(data[0] & 0x07) << 18) | ((uint32_t)(data[1] & 0x3F) << 12)
       | ((uint32_t)(data[2] & 0x3F) << 6) | (data[3] & 0x3F);

  if (cp < 0x10000)
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

  if (!data || len == 0)
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
  size_t cp_count = 0;
  size_t pos = 0;
  SocketUTF8_Result result;
  size_t consumed;

  assert (count);
  *count = 0;

  if (len == 0 || !data)
    return UTF8_VALID;

  while (pos < len)
    {
      result = SocketUTF8_decode (data + pos, len - pos, NULL, &consumed);
      if (result != UTF8_VALID)
        return result;

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
