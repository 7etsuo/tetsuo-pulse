/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* UTF-8 validation using Hoehrmann DFA algorithm */


#include <string.h>

#include "core/SocketUTF8.h"
#include "core/SocketUtil.h"

/* ==================== Exception Definition ==================== */

const Except_T SocketUTF8_Failed
    = { &SocketUTF8_Failed, "UTF-8 validation failed" };

SOCKET_DECLARE_MODULE_EXCEPTION (SocketUTF8);

/* ==================== DFA State Constants ==================== */

#define UTF8_STATE_ACCEPT 0
#define UTF8_STATE_REJECT 1
#define UTF8_STATE_2BYTE_EXPECT 2
#define UTF8_STATE_E0_SPECIAL 3
#define UTF8_STATE_3BYTE_EXPECT 4
#define UTF8_STATE_ED_SPECIAL 5
#define UTF8_STATE_F0_SPECIAL 6
#define UTF8_STATE_4BYTE_EXPECT 7
#define UTF8_STATE_F4_SPECIAL 8
#define UTF8_NUM_CHAR_CLASSES 12
#define UTF8_NUM_DFA_STATES 9

/* ==================== Hoehrmann DFA Tables ==================== */

/* clang-format off */

/* Maps each byte (0x00-0xFF) to a character class (0-11) */
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

/* DFA state transitions: utf8_state[state * UTF8_NUM_CHAR_CLASSES + class] */
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

/* Maps DFA state to total bytes in sequence */
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

/* ==================== Result String Table ==================== */

static const char *utf8_result_strings[] = {
  "Valid UTF-8",                            /* UTF8_VALID */
  "Invalid byte sequence",                  /* UTF8_INVALID */
  "Incomplete sequence (needs more bytes)", /* UTF8_INCOMPLETE */
  "Overlong encoding (security issue)",     /* UTF8_OVERLONG */
  "UTF-16 surrogate (U+D800-U+DFFF)",       /* UTF8_SURROGATE */
  "Code point exceeds U+10FFFF"             /* UTF8_TOO_LARGE */
};

/* ==================== Byte Pattern Constants ==================== */

#define UTF8_CONTINUATION_MASK 0xC0
#define UTF8_CONTINUATION_START 0x80
#define UTF8_ASCII_HIGH_BIT 0x80

#define UTF8_2BYTE_MASK 0xE0
#define UTF8_2BYTE_START 0xC0
#define UTF8_2BYTE_OVERLONG_END 0xC1 /* C0-C1 invalid overlong starts */
#define UTF8_2BYTE_MIN_VALID 0xC2    /* C2-DF valid, C0-C1 overlong invalid */

#define UTF8_3BYTE_MASK 0xF0
#define UTF8_3BYTE_START 0xE0

#define UTF8_4BYTE_MASK 0xF8
#define UTF8_4BYTE_START 0xF0
#define UTF8_4BYTE_MAX_VALID 0xF4 /* F0-F4 valid, F5-FF invalid */

#define UTF8_INVALID_5BYTE_START 0xF5

/* Lead byte payload bit masks */
#define UTF8_2BYTE_LEAD_MASK 0x1F /* 5 bits after 110 */
#define UTF8_3BYTE_LEAD_MASK 0x0F /* 4 bits after 1110 */
#define UTF8_4BYTE_LEAD_MASK 0x07 /* 3 bits after 11110 */

/* Continuation payload mask (6 bits) */
#define UTF8_CONTINUATION_MASK_VAL 0x3F /* 6 bits after 10 */

/* Specific overlong/surrogate/too-large ranges */
#define UTF8_E0_OVERLONG_MIN 0x80
#define UTF8_E0_OVERLONG_MAX 0x9F

#define UTF8_ED_SURROGATE_MIN 0xA0
#define UTF8_ED_SURROGATE_MAX 0xBF

#define UTF8_F0_OVERLONG_MIN 0x80
#define UTF8_F0_OVERLONG_MAX 0x8F

#define UTF8_F4_TOO_LARGE_MIN 0x90
#define UTF8_F4_TOO_LARGE_MAX 0xBF

/* ==================== DFA Helpers ==================== */

static inline uint32_t
dfa_transition (uint32_t state, uint8_t char_class)
{
  return utf8_state[state * UTF8_NUM_CHAR_CLASSES + char_class];
}

/* Returns 1 if transition successful, 0 if reject state reached */
static inline int
dfa_step (uint32_t *state, unsigned char byte, uint32_t *prev_out)
{
  uint8_t char_class = utf8_class[byte];
  *prev_out = *state;
  *state = dfa_transition (*state, char_class);
  return (*state != UTF8_STATE_REJECT) ? 1 : 0;
}

/* Update bytes_needed and bytes_seen for incremental validation */
static void
update_sequence_tracking (SocketUTF8_State *state, uint32_t prev_state,
                          uint32_t curr_state)
{
  if (prev_state == UTF8_STATE_ACCEPT && curr_state != UTF8_STATE_ACCEPT)
    {
      state->bytes_needed = utf8_state_bytes[curr_state];
      state->bytes_seen = 1;
    }
  else if (prev_state != UTF8_STATE_ACCEPT)
    {
      state->bytes_seen++;
      if (curr_state == UTF8_STATE_ACCEPT)
        {
          state->bytes_needed = 0;
          state->bytes_seen = 0;
        }
    }
}

/* ==================== Internal Helpers ==================== */

static void
raise_arg_error (const char *msg)
{
  SOCKET_RAISE_MSG (SocketUTF8, SocketUTF8_Failed, "%s", msg);
}

static inline int
is_continuation_byte (unsigned char byte)
{
  return (byte & UTF8_CONTINUATION_MASK) == UTF8_CONTINUATION_START;
}

/* Returns 1 if all valid, 0 if invalid (consumed set to failure index) */
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

/* Classify error type based on DFA state and byte that caused rejection */
static inline SocketUTF8_Result
classify_error (uint32_t prev_state, unsigned char byte)
{
  if (prev_state == UTF8_STATE_ACCEPT && byte >= UTF8_2BYTE_START
      && byte <= UTF8_2BYTE_OVERLONG_END)
    return UTF8_OVERLONG;

  if (prev_state == UTF8_STATE_ACCEPT && byte >= UTF8_INVALID_5BYTE_START)
    return UTF8_INVALID;

  if (prev_state == UTF8_STATE_E0_SPECIAL && byte >= UTF8_E0_OVERLONG_MIN
      && byte <= UTF8_E0_OVERLONG_MAX)
    return UTF8_OVERLONG;

  if (prev_state == UTF8_STATE_ED_SPECIAL && byte >= UTF8_ED_SURROGATE_MIN
      && byte <= UTF8_ED_SURROGATE_MAX)
    return UTF8_SURROGATE;

  if (prev_state == UTF8_STATE_F0_SPECIAL && byte >= UTF8_F0_OVERLONG_MIN
      && byte <= UTF8_F0_OVERLONG_MAX)
    return UTF8_OVERLONG;

  if (prev_state == UTF8_STATE_F4_SPECIAL && byte >= UTF8_F4_TOO_LARGE_MIN
      && byte <= UTF8_F4_TOO_LARGE_MAX)
    return UTF8_TOO_LARGE;

  return UTF8_INVALID;
}

static inline SocketUTF8_Result
classify_first_byte_error (unsigned char byte)
{
  if (byte >= UTF8_2BYTE_START && byte <= UTF8_2BYTE_OVERLONG_END)
    return UTF8_OVERLONG;
  return UTF8_INVALID;
}

/* ==================== One-Shot Validation ==================== */

SocketUTF8_Result
SocketUTF8_validate (const unsigned char *data, size_t len)
{
  if (len > 0 && !data)
    raise_arg_error ("data must not be NULL when len > 0");

  uint32_t state = UTF8_STATE_ACCEPT;
  size_t i;
  uint32_t prev;

  if (len == 0)
    return UTF8_VALID;

  for (i = 0; i < len; i++)
    {
      if (!dfa_step (&state, data[i], &prev))
        return classify_error (prev, data[i]);
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

/* ==================== Incremental Validation ==================== */

void
SocketUTF8_init (SocketUTF8_State *state)
{
  if (!state)
    raise_arg_error ("state must not be NULL");

  state->state = UTF8_STATE_ACCEPT;
  state->bytes_needed = 0;
  state->bytes_seen = 0;
}

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
  if (!state)
    raise_arg_error ("state must not be NULL");
  if (len > 0 && !data)
    raise_arg_error ("data must not be NULL when len > 0");

  uint32_t dfa_state;
  size_t i;
  uint32_t prev;

  dfa_state = state->state;

  if (len == 0)
    return get_current_status (dfa_state);

  for (i = 0; i < len; i++)
    {
      if (!dfa_step (&dfa_state, data[i], &prev))
        {
          state->state = UTF8_STATE_REJECT;
          return classify_error (prev, data[i]);
        }

      update_sequence_tracking (state, prev, dfa_state);
    }

  state->state = dfa_state;
  return get_current_status (dfa_state);
}

SocketUTF8_Result
SocketUTF8_finish (const SocketUTF8_State *state)
{
  if (!state)
    raise_arg_error ("state must not be NULL");
  return get_current_status (state->state);
}

void
SocketUTF8_reset (SocketUTF8_State *state)
{
  if (!state)
    raise_arg_error ("state must not be NULL");
  SocketUTF8_init (state);
}

/* ==================== UTF-8 Utilities ==================== */

int
SocketUTF8_codepoint_len (uint32_t codepoint)
{
  if (codepoint >= SOCKET_UTF8_SURROGATE_MIN
      && codepoint <= SOCKET_UTF8_SURROGATE_MAX)
    return 0;

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
  if ((first_byte & UTF8_ASCII_HIGH_BIT) == 0)
    return 1;

  if ((first_byte & UTF8_CONTINUATION_MASK) == UTF8_CONTINUATION_START)
    return 0;

  if ((first_byte & UTF8_2BYTE_MASK) == UTF8_2BYTE_START)
    return (first_byte >= UTF8_2BYTE_MIN_VALID) ? 2 : 0;

  if ((first_byte & UTF8_3BYTE_MASK) == UTF8_3BYTE_START)
    return 3;

  if ((first_byte & UTF8_4BYTE_MASK) == UTF8_4BYTE_START)
    return (first_byte <= UTF8_4BYTE_MAX_VALID) ? 4 : 0;

  return 0;
}

static const uint8_t utf8_lead_start[5] =
  { 0x00, 0x00, 0xC0, 0xE0, 0xF0 };

static const uint8_t utf8_lead_mask[5] =
  { 0x00, 0x7F, 0x1F, 0x0F, 0x07 };

int
SocketUTF8_encode (uint32_t codepoint, unsigned char *output)
{
  int len;

  if (!output)
    return 0;

  len = SocketUTF8_codepoint_len (codepoint);
  if (len == 0)
    return 0;

  if (len == 1)
    {
      output[0] = (unsigned char) codepoint;
      return 1;
    }

  uint32_t temp_cp = codepoint;
  int pos = len - 1;
  output[pos] = (unsigned char) (UTF8_CONTINUATION_START | (temp_cp & UTF8_CONTINUATION_MASK_VAL));
  temp_cp >>= 6;
  pos--;
  while (pos > 0)
    {
      output[pos] = (unsigned char) (UTF8_CONTINUATION_START | (temp_cp & UTF8_CONTINUATION_MASK_VAL));
      temp_cp >>= 6;
      pos--;
    }
  output[0] = (unsigned char) (utf8_lead_start[len] | (temp_cp & utf8_lead_mask[len]));

  return len;
}

static SocketUTF8_Result
decode_2byte (const unsigned char *data, uint32_t *codepoint, size_t *consumed)
{
  uint32_t cp;
  size_t bytes_used = 2;
  SocketUTF8_Result result;
  int fail_idx;

  if (!validate_continuations (data, 1, &fail_idx))
    {
      bytes_used = (size_t) fail_idx;
      result = UTF8_INVALID;
      goto done;
    }

  cp = ((uint32_t)(data[0] & UTF8_2BYTE_LEAD_MASK) << 6)
       | (data[1] & UTF8_CONTINUATION_MASK_VAL);

  if (cp < (SOCKET_UTF8_1BYTE_MAX + 1u))
    {
      result = UTF8_OVERLONG;
      goto done;
    }

  *codepoint = cp;
  result = UTF8_VALID;

done:
  if (consumed)
    *consumed = bytes_used;
  return result;
}

static SocketUTF8_Result
decode_3byte (const unsigned char *data, uint32_t *codepoint, size_t *consumed)
{
  uint32_t cp;
  int fail_idx;
  size_t bytes_used = 3;
  SocketUTF8_Result result;

  if (!validate_continuations (data, 2, &fail_idx))
    {
      bytes_used = (size_t)fail_idx;
      result = UTF8_INVALID;
      goto done;
    }

  cp = ((uint32_t)(data[0] & UTF8_3BYTE_LEAD_MASK) << 12)
       | ((uint32_t)(data[1] & UTF8_CONTINUATION_MASK_VAL) << 6)
       | (data[2] & UTF8_CONTINUATION_MASK_VAL);

  if (cp < (SOCKET_UTF8_2BYTE_MAX + 1u))
    {
      result = UTF8_OVERLONG;
      goto done;
    }

  if (cp >= SOCKET_UTF8_SURROGATE_MIN && cp <= SOCKET_UTF8_SURROGATE_MAX)
    {
      result = UTF8_SURROGATE;
      goto done;
    }

  *codepoint = cp;
  result = UTF8_VALID;

done:
  if (consumed)
    *consumed = bytes_used;
  return result;
}

static SocketUTF8_Result
decode_4byte (const unsigned char *data, uint32_t *codepoint, size_t *consumed)
{
  uint32_t cp;
  int fail_idx;
  size_t bytes_used = 4;
  SocketUTF8_Result result;

  if (!validate_continuations (data, 3, &fail_idx))
    {
      bytes_used = (size_t)fail_idx;
      result = UTF8_INVALID;
      goto done;
    }

  cp = ((uint32_t)(data[0] & UTF8_4BYTE_LEAD_MASK) << 18)
       | ((uint32_t)(data[1] & UTF8_CONTINUATION_MASK_VAL) << 12)
       | ((uint32_t)(data[2] & UTF8_CONTINUATION_MASK_VAL) << 6)
       | (data[3] & UTF8_CONTINUATION_MASK_VAL);

  if (cp < SOCKET_UTF8_4BYTE_MIN)
    {
      result = UTF8_OVERLONG;
      goto done;
    }

  if (cp > SOCKET_UTF8_MAX_CODEPOINT)
    {
      result = UTF8_TOO_LARGE;
      goto done;
    }

  *codepoint = cp;
  result = UTF8_VALID;

done:
  if (consumed)
    *consumed = bytes_used;
  return result;
}

SocketUTF8_Result
SocketUTF8_decode (const unsigned char *data, size_t len, uint32_t *codepoint,
                   size_t *consumed)
{
  uint32_t cp = 0;
  int seq_len;
  SocketUTF8_Result result;

  if (len > 0 && !data)
    raise_arg_error ("data must not be NULL when len > 0");

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
  if (!count)
    raise_arg_error ("count output must not be NULL");
  if (len > 0 && !data)
    raise_arg_error ("data must not be NULL when len > 0");

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
        {
          *count = cp_count;  /* Report partial count on error */
          return result;
        }

      if (consumed == 0)
        { /* Safety: prevent infinite loop */
          *count = cp_count;
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
