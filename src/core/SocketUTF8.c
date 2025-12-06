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

#define RAISE_UTF8_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketUTF8, e)

/* ============================================================================
 * Hoehrmann DFA Tables
 * ============================================================================
 *
 * The DFA uses two tables:
 * 1. utf8_class[256]: Maps each byte to a character class (0-11)
 * 2. utf8_state[108]: State transitions (12 states x 9 classes)
 *
 * States:
 *   0 = UTF8_DFA_ACCEPT (valid complete sequence)
 *   1 = UTF8_DFA_REJECT (invalid sequence)
 *   2-11 = intermediate states (expecting continuation bytes)
 *
 * Character classes:
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

#define UTF8_DFA_ACCEPT 0
#define UTF8_DFA_REJECT 1

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
 * Indexed as: state_table[state * 12 + class]
 *
 * The table is organized with 12 columns per row (one per character class),
 * and rows represent states 0 through 8.
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
 * Classify error type based on DFA state and byte
 *
 * When we hit reject state, determine what kind of error occurred.
 */
static SocketUTF8_Result
classify_error (uint32_t prev_state, unsigned char byte)
{
  /* Check for overlong 2-byte encodings (C0-C1 starts) - only from accept state */
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

  /* Generic invalid sequence */
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

  /* Handle NULL/empty input */
  if (len == 0)
    return UTF8_VALID;

  if (!data)
    return UTF8_VALID;

  /* Process each byte through DFA */
  for (i = 0; i < len; i++)
    {
      uint8_t byte_class = utf8_class[data[i]];
      prev_state = state;
      state = utf8_state[state * 12 + byte_class];

      if (state == UTF8_DFA_REJECT)
        return classify_error (prev_state, data[i]);
    }

  /* Check for incomplete sequence at end */
  if (state != UTF8_DFA_ACCEPT)
    return UTF8_INCOMPLETE;

  return UTF8_VALID;
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

SocketUTF8_Result
SocketUTF8_update (SocketUTF8_State *state, const unsigned char *data,
                   size_t len)
{
  uint32_t dfa_state;
  uint32_t prev_state;
  size_t i;

  assert (state);

  /* Handle NULL/empty chunk */
  if (len == 0 || !data)
    {
      /* Return current status */
      if (state->state == UTF8_DFA_ACCEPT)
        return UTF8_VALID;
      if (state->state == UTF8_DFA_REJECT)
        return UTF8_INVALID;
      return UTF8_INCOMPLETE;
    }

  dfa_state = state->state;

  /* If already in reject state, stay rejected */
  if (dfa_state == UTF8_DFA_REJECT)
    return UTF8_INVALID;

  /* Process each byte */
  for (i = 0; i < len; i++)
    {
      uint8_t byte_class = utf8_class[data[i]];
      prev_state = dfa_state;
      dfa_state = utf8_state[dfa_state * 12 + byte_class];

      if (dfa_state == UTF8_DFA_REJECT)
        {
          state->state = UTF8_DFA_REJECT;
          return classify_error (prev_state, data[i]);
        }

      /* Track bytes for multi-byte sequences */
      if (prev_state == UTF8_DFA_ACCEPT && dfa_state != UTF8_DFA_ACCEPT)
        {
          /* Starting new multi-byte sequence */
          state->bytes_needed = utf8_state_bytes[dfa_state];
          state->bytes_seen = 1;
        }
      else if (prev_state != UTF8_DFA_ACCEPT)
        {
          /* Continuing multi-byte sequence */
          state->bytes_seen++;
          if (dfa_state == UTF8_DFA_ACCEPT)
            {
              /* Completed sequence */
              state->bytes_needed = 0;
              state->bytes_seen = 0;
            }
        }
    }

  state->state = dfa_state;

  /* Return appropriate status */
  if (dfa_state == UTF8_DFA_ACCEPT)
    return UTF8_VALID;

  return UTF8_INCOMPLETE;
}

SocketUTF8_Result
SocketUTF8_finish (const SocketUTF8_State *state)
{
  assert (state);

  if (state->state == UTF8_DFA_ACCEPT)
    return UTF8_VALID;

  if (state->state == UTF8_DFA_REJECT)
    return UTF8_INVALID;

  /* In intermediate state = incomplete sequence */
  return UTF8_INCOMPLETE;
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

  /* Determine byte length */
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
    {
      /* C0-C1 are overlong, but still indicate 2-byte sequence */
      return (first_byte >= 0xC2) ? 2 : 0;
    }

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

SocketUTF8_Result
SocketUTF8_decode (const unsigned char *data, size_t len, uint32_t *codepoint,
                   size_t *consumed)
{
  uint32_t cp = 0;
  int seq_len;
  int i;

  if (!data || len == 0)
    {
      if (consumed)
        *consumed = 0;
      return UTF8_INCOMPLETE;
    }

  /* Get expected sequence length from first byte */
  seq_len = SocketUTF8_sequence_len (data[0]);
  if (seq_len == 0)
    {
      if (consumed)
        *consumed = 1;
      /* Check for specific error types */
      if (data[0] >= 0xC0 && data[0] <= 0xC1)
        return UTF8_OVERLONG;
      if (data[0] >= 0xF5)
        return UTF8_INVALID;
      return UTF8_INVALID;
    }

  /* Check if we have enough bytes */
  if ((size_t)seq_len > len)
    {
      if (consumed)
        *consumed = len;
      return UTF8_INCOMPLETE;
    }

  /* Decode based on sequence length */
  switch (seq_len)
    {
    case 1:
      cp = data[0];
      break;

    case 2:
      /* Validate continuation byte */
      if ((data[1] & 0xC0) != 0x80)
        {
          if (consumed)
            *consumed = 1;
          return UTF8_INVALID;
        }
      cp = ((uint32_t)(data[0] & 0x1F) << 6) | (data[1] & 0x3F);
      /* Check for overlong encoding */
      if (cp < 0x80)
        {
          if (consumed)
            *consumed = 2;
          return UTF8_OVERLONG;
        }
      break;

    case 3:
      /* Validate continuation bytes */
      for (i = 1; i < 3; i++)
        {
          if ((data[i] & 0xC0) != 0x80)
            {
              if (consumed)
                *consumed = (size_t)i;
              return UTF8_INVALID;
            }
        }
      cp = ((uint32_t)(data[0] & 0x0F) << 12) | ((uint32_t)(data[1] & 0x3F) << 6)
           | (data[2] & 0x3F);
      /* Check for overlong encoding */
      if (cp < 0x800)
        {
          if (consumed)
            *consumed = 3;
          return UTF8_OVERLONG;
        }
      /* Check for surrogate */
      if (cp >= SOCKET_UTF8_SURROGATE_MIN && cp <= SOCKET_UTF8_SURROGATE_MAX)
        {
          if (consumed)
            *consumed = 3;
          return UTF8_SURROGATE;
        }
      break;

    case 4:
      /* Validate continuation bytes */
      for (i = 1; i < 4; i++)
        {
          if ((data[i] & 0xC0) != 0x80)
            {
              if (consumed)
                *consumed = (size_t)i;
              return UTF8_INVALID;
            }
        }
      cp = ((uint32_t)(data[0] & 0x07) << 18)
           | ((uint32_t)(data[1] & 0x3F) << 12)
           | ((uint32_t)(data[2] & 0x3F) << 6) | (data[3] & 0x3F);
      /* Check for overlong encoding */
      if (cp < 0x10000)
        {
          if (consumed)
            *consumed = 4;
          return UTF8_OVERLONG;
        }
      /* Check for out of range */
      if (cp > SOCKET_UTF8_MAX_CODEPOINT)
        {
          if (consumed)
            *consumed = 4;
          return UTF8_TOO_LARGE;
        }
      break;
    }

  if (codepoint)
    *codepoint = cp;
  if (consumed)
    *consumed = (size_t)seq_len;

  return UTF8_VALID;
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

  if (len == 0)
    {
      return UTF8_VALID;
    }

  if (!data)
    {
      return UTF8_VALID;
    }

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

