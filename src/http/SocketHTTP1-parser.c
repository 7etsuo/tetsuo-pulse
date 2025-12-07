/**
 * SocketHTTP1-parser.c - HTTP/1.1 DFA-based Incremental Parser
 *
 * Part of the Socket Library
 *
 * Implements RFC 9112 HTTP/1.1 message parsing with:
 * - O(n) time complexity via DFA state machine
 * - Single-pass parsing (no backtracking)
 * - Request smuggling prevention
 * - Configurable limits
 */

#include "http/SocketHTTP1.h"
#include "http/SocketHTTP1-private.h"
#include "http/SocketHTTP-private.h"
#include "core/SocketUtil.h"

#include <assert.h>




/* ============================================================================
 * Table-Driven DFA Tables (Hoehrmann-style)
 * ============================================================================ */

/* clang-format off */

/**
 * Character classification table (256 bytes)
 *
 * Maps each byte to its HTTP1_CharClass. Designed for O(1) lookup
 * in the parsing hot loop. Classes are chosen to minimize table size
 * while capturing all HTTP/1.1 grammar distinctions.
 *
 * Key classes:
 * - CTL (0): Control chars except HTAB - invalid in most contexts
 * - SP (1): Space - field separator
 * - HTAB (2): Tab - OWS (optional whitespace)
 * - CR (3): Carriage return - line ending
 * - LF (4): Line feed - line ending
 * - COLON (5): Header name/value separator
 * - SLASH (6): Version separator (HTTP/x.y)
 * - DOT (7): Version separator
 * - DIGIT (8): 0-9
 * - HEX (9): a-f, A-F (for chunk sizes)
 * - ALPHA (10): Letters except H, T, P
 * - H (11): 'H' - HTTP version start
 * - T (12): 'T' - HTTP version
 * - P (13): 'P' - HTTP version
 * - TCHAR (14): Other token chars
 * - VCHAR (15): Other visible chars
 * - OBS (16): obs-text (0x80-0xFF)
 * - INVALID (17): NUL, DEL, etc.
 */
const uint8_t http1_char_class[256] = {
  /* 0x00-0x0F: Control characters */
  /*      NUL   SOH   STX   ETX   EOT   ENQ   ACK   BEL */
  /*  0 */ 17,   0,    0,    0,    0,    0,    0,    0,
  /*      BS    HT    LF    VT    FF    CR    SO    SI  */
  /*  8 */  0,   2,    4,    0,    0,    3,    0,    0,

  /* 0x10-0x1F: More control characters */
  /*      DLE   DC1   DC2   DC3   DC4   NAK   SYN   ETB */
  /* 10 */  0,   0,    0,    0,    0,    0,    0,    0,
  /*      CAN   EM    SUB   ESC   FS    GS    RS    US  */
  /* 18 */  0,   0,    0,    0,    0,    0,    0,    0,

  /* 0x20-0x2F: Punctuation and digits */
  /*      SP    !     "     #     $     %     &     '   */
  /* 20 */  1,  14,   15,   14,   14,   14,   14,   14,
  /*       (    )     *     +     ,     -     .     /   */
  /* 28 */ 15,  15,   14,   14,   15,   14,    7,    6,

  /* 0x30-0x3F: Digits and punctuation */
  /*       0    1     2     3     4     5     6     7   */
  /* 30 */  8,   8,    8,    8,    8,    8,    8,    8,
  /*       8    9     :     ;     <     =     >     ?   */
  /* 38 */  8,   8,    5,   15,   15,   15,   15,   15,

  /* 0x40-0x4F: Uppercase letters */
  /*       @    A     B     C     D     E     F     G   */
  /* 40 */ 15,   9,    9,    9,    9,    9,    9,   10,
  /*       H    I     J     K     L     M     N     O   */
  /* 48 */ 11,  10,   10,   10,   10,   10,   10,   10,

  /* 0x50-0x5F: More uppercase and punctuation */
  /*       P    Q     R     S     T     U     V     W   */
  /* 50 */ 13,  10,   10,   10,   12,   10,   10,   10,
  /*       X    Y     Z     [     \     ]     ^     _   */
  /* 58 */ 10,  10,   10,   15,   15,   15,   14,   14,

  /* 0x60-0x6F: Lowercase letters */
  /*       `    a     b     c     d     e     f     g   */
  /* 60 */ 14,   9,    9,    9,    9,    9,    9,   10,
  /*       h    i     j     k     l     m     n     o   */
  /* 68 */ 11,  10,   10,   10,   10,   10,   10,   10,

  /* 0x70-0x7F: More lowercase and DEL */
  /*       p    q     r     s     t     u     v     w   */
  /* 70 */ 13,  10,   10,   10,   12,   10,   10,   10,
  /*       x    y     z     {     |     }     ~    DEL  */
  /* 78 */ 10,  10,   10,   15,   14,   15,   14,   17,

  /* 0x80-0xFF: obs-text (high bytes) - all class 16 */
  /* 80 */ 16,  16,   16,   16,   16,   16,   16,   16,
  /* 88 */ 16,  16,   16,   16,   16,   16,   16,   16,
  /* 90 */ 16,  16,   16,   16,   16,   16,   16,   16,
  /* 98 */ 16,  16,   16,   16,   16,   16,   16,   16,
  /* A0 */ 16,  16,   16,   16,   16,   16,   16,   16,
  /* A8 */ 16,  16,   16,   16,   16,   16,   16,   16,
  /* B0 */ 16,  16,   16,   16,   16,   16,   16,   16,
  /* B8 */ 16,  16,   16,   16,   16,   16,   16,   16,
  /* C0 */ 16,  16,   16,   16,   16,   16,   16,   16,
  /* C8 */ 16,  16,   16,   16,   16,   16,   16,   16,
  /* D0 */ 16,  16,   16,   16,   16,   16,   16,   16,
  /* D8 */ 16,  16,   16,   16,   16,   16,   16,   16,
  /* E0 */ 16,  16,   16,   16,   16,   16,   16,   16,
  /* E8 */ 16,  16,   16,   16,   16,   16,   16,   16,
  /* F0 */ 16,  16,   16,   16,   16,   16,   16,   16,
  /* F8 */ 16,  16,   16,   16,   16,   16,   16,   16,
};

/* Shorthand for table entries */
#define __ HTTP1_PS_ERROR   /* Error transition */
#define _C HTTP1_PS_COMPLETE

/* State abbreviations for readability */
#define ST HTTP1_PS_START
#define ME HTTP1_PS_METHOD
#define S1 HTTP1_PS_SP_AFTER_METHOD
#define UR HTTP1_PS_URI
#define S2 HTTP1_PS_SP_AFTER_URI
#define SC HTTP1_PS_STATUS_CODE
#define S3 HTTP1_PS_SP_AFTER_STATUS
#define RE HTTP1_PS_REASON
#define VH HTTP1_PS_VERSION_H
#define V1 HTTP1_PS_VERSION_T1
#define V2 HTTP1_PS_VERSION_T2
#define VP HTTP1_PS_VERSION_P
#define VS HTTP1_PS_VERSION_SLASH
#define VM HTTP1_PS_VERSION_MAJOR
#define VD HTTP1_PS_VERSION_DOT
#define Vm HTTP1_PS_VERSION_MINOR
#define CR HTTP1_PS_LINE_CR
#define LF HTTP1_PS_LINE_LF
#define HS HTTP1_PS_HEADER_START
#define HN HTTP1_PS_HEADER_NAME
#define HC HTTP1_PS_HEADER_COLON
#define HV HTTP1_PS_HEADER_VALUE
#define HR HTTP1_PS_HEADER_CR
#define HL HTTP1_PS_HEADERS_END_LF

/**
 * State transition table for REQUEST parsing
 *
 * Indexed by [current_state][char_class] -> next_state
 * Uses HTTP1_PS_ERROR (__) for invalid transitions
 *
 * Row order matches HTTP1_InternalState enum
 * Column order matches HTTP1_CharClass enum:
 *   CTL  SP  HTAB  CR  LF  COLON SLASH DOT DIGIT HEX ALPHA  H    T    P  TCHAR VCHAR OBS INVALID
 */
const uint8_t http1_req_state[HTTP1_NUM_STATES][HTTP1_NUM_CLASSES] = {
  /*                    CTL  SP  HTAB  CR   LF COLON SLASH DOT DIGIT HEX ALPHA   H    T    P TCHAR VCHAR  OBS INVLD */
  /* START         */ {  __,  __,  __,  __,  __,  __,  __,  __,  __,  ME,  ME,  ME,  ME,  ME,  ME,  __,  __,  __ },
  /* METHOD        */ {  __,  S1,  __,  __,  __,  __,  __,  __,  ME,  ME,  ME,  ME,  ME,  ME,  ME,  __,  __,  __ },
  /* SP_AFTER_METH */ {  __,  __,  __,  __,  __,  UR,  UR,  UR,  UR,  UR,  UR,  UR,  UR,  UR,  UR,  UR,  __,  __ },
  /* URI           */ {  __,  S2,  __,  CR,  HS,  UR,  UR,  UR,  UR,  UR,  UR,  UR,  UR,  UR,  UR,  UR,  __,  __ },
  /* SP_AFTER_URI  */ {  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  VH,  __,  __,  __,  __,  __,  __ },
  /* STATUS_CODE   */ {  __,  S3,  __,  CR,  __,  __,  __,  __,  SC,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
  /* SP_AFTER_STAT */ {  __,  RE,  RE,  CR,  HS,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  __ },
  /* REASON        */ {  __,  RE,  RE,  CR,  HS,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  __ },
  /* VERSION_H     */ {  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  V1,  __,  __,  __,  __,  __ },
  /* VERSION_T1    */ {  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  V2,  __,  __,  __,  __,  __ },
  /* VERSION_T2    */ {  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  VP,  __,  __,  __,  __ },
  /* VERSION_P     */ {  __,  __,  __,  __,  __,  __,  VS,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
  /* VERSION_SLASH */ {  __,  __,  __,  __,  __,  __,  __,  __,  VM,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
  /* VERSION_MAJOR */ {  __,  __,  __,  __,  __,  __,  __,  VD,  VM,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
  /* VERSION_DOT   */ {  __,  __,  __,  __,  __,  __,  __,  __,  Vm,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
  /* VERSION_MINOR */ {  __,  __,  __,  CR,  HS,  __,  __,  __,  Vm,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
  /* LINE_CR       */ {  __,  __,  __,  __,  HS,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
  /* LINE_LF       */ {  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
  /* HEADER_START  */ {  __,  __,  __,  HL,  _C,  __,  __,  HN,  HN,  HN,  HN,  HN,  HN,  HN,  HN,  __,  __,  __ },
  /* HEADER_NAME   */ {  __,  __,  __,  __,  __,  HC,  __,  HN,  HN,  HN,  HN,  HN,  HN,  HN,  HN,  __,  __,  __ },
  /* HEADER_COLON  */ {  __,  HC,  HC,  HR,  HS,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  __ },
  /* HEADER_VALUE  */ {  __,  HV,  HV,  HR,  HS,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  __ },
  /* HEADER_V_OWS  */ {  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
  /* HEADER_CR     */ {  __,  __,  __,  __,  HS,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
  /* HEADER_LF     */ {  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
  /* HEADERS_END   */ {  __,  __,  __,  __,  _C,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
  /* remaining states use default error - body states handled separately */
};

/**
 * State transition table for RESPONSE parsing
 *
 * Similar to request table but starts with HTTP version
 * and includes status code parsing.
 */
const uint8_t http1_resp_state[HTTP1_NUM_STATES][HTTP1_NUM_CLASSES] = {
  /*                    CTL  SP  HTAB  CR   LF COLON SLASH DOT DIGIT HEX ALPHA   H    T    P TCHAR VCHAR  OBS INVLD */
  /* START         */ {  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  VH,  __,  __,  __,  __,  __,  __ },
  /* METHOD        */ {  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
  /* SP_AFTER_METH */ {  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
  /* URI           */ {  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
  /* SP_AFTER_URI  */ {  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
  /* STATUS_CODE   */ {  __,  S3,  __,  CR,  __,  __,  __,  __,  SC,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
  /* SP_AFTER_STAT */ {  __,  RE,  RE,  CR,  HS,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  __ },
  /* REASON        */ {  __,  RE,  RE,  CR,  HS,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  __ },
  /* VERSION_H     */ {  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  V1,  __,  __,  __,  __,  __ },
  /* VERSION_T1    */ {  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  V2,  __,  __,  __,  __,  __ },
  /* VERSION_T2    */ {  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  VP,  __,  __,  __,  __ },
  /* VERSION_P     */ {  __,  __,  __,  __,  __,  __,  VS,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
  /* VERSION_SLASH */ {  __,  __,  __,  __,  __,  __,  __,  __,  VM,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
  /* VERSION_MAJOR */ {  __,  __,  __,  __,  __,  __,  __,  VD,  VM,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
  /* VERSION_DOT   */ {  __,  __,  __,  __,  __,  __,  __,  __,  Vm,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
  /* VERSION_MINOR */ {  __,  SC,  __,  __,  __,  __,  __,  __,  Vm,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
  /* LINE_CR       */ {  __,  __,  __,  __,  HS,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
  /* LINE_LF       */ {  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
  /* HEADER_START  */ {  __,  __,  __,  HL,  _C,  __,  __,  HN,  HN,  HN,  HN,  HN,  HN,  HN,  HN,  __,  __,  __ },
  /* HEADER_NAME   */ {  __,  __,  __,  __,  __,  HC,  __,  HN,  HN,  HN,  HN,  HN,  HN,  HN,  HN,  __,  __,  __ },
  /* HEADER_COLON  */ {  __,  HC,  HC,  HR,  HS,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  __ },
  /* HEADER_VALUE  */ {  __,  HV,  HV,  HR,  HS,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  __ },
  /* HEADER_V_OWS  */ {  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
  /* HEADER_CR     */ {  __,  __,  __,  __,  HS,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
  /* HEADER_LF     */ {  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
  /* HEADERS_END   */ {  __,  __,  __,  __,  _C,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
};

/* Action abbreviations */
#define _N HTTP1_ACT_NONE
#define _M HTTP1_ACT_STORE_METHOD
#define _U HTTP1_ACT_STORE_URI
#define _R HTTP1_ACT_STORE_REASON
#define _h HTTP1_ACT_STORE_NAME
#define _v HTTP1_ACT_STORE_VALUE
#define ME_ HTTP1_ACT_METHOD_END
#define UE_ HTTP1_ACT_URI_END
#define MJ HTTP1_ACT_VERSION_MAJ
#define Mn HTTP1_ACT_VERSION_MIN
#define SD HTTP1_ACT_STATUS_DIGIT
#define HE HTTP1_ACT_HEADER_END
#define HD HTTP1_ACT_HEADERS_DONE
#define _E HTTP1_ACT_ERROR

/**
 * Action table for REQUEST parsing
 *
 * Maps [state][char_class] -> action to execute
 *
 * IMPORTANT: Header is added only in HEADER_CR+LF or directly on bare LF.
 * When HEADER_VALUE/COLON sees CR, we just transition (no action).
 */
const uint8_t http1_req_action[HTTP1_NUM_STATES][HTTP1_NUM_CLASSES] = {
  /*                    CTL  SP  HTAB  CR   LF COLON SLASH DOT DIGIT HEX ALPHA   H    T    P TCHAR VCHAR  OBS INVLD */
  /* START         */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _M,  _M,  _M,  _M,  _M,  _M,  _E,  _E,  _E },
  /* METHOD        */ {  _E, ME_,  _E,  _E,  _E,  _E,  _E,  _E,  _M,  _M,  _M,  _M,  _M,  _M,  _M,  _E,  _E,  _E },
  /* SP_AFTER_METH */ {  _E,  _E,  _E,  _E,  _E,  _U,  _U,  _U,  _U,  _U,  _U,  _U,  _U,  _U,  _U,  _U,  _E,  _E },
  /* URI           */ {  _E, UE_,  _E,  _N,  _N,  _U,  _U,  _U,  _U,  _U,  _U,  _U,  _U,  _U,  _U,  _U,  _E,  _E },
  /* SP_AFTER_URI  */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _N,  _E,  _E,  _E,  _E,  _E,  _E },
  /* STATUS_CODE   */ {  _E,  _N,  _E,  _N,  _E,  _E,  _E,  _E,  SD,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
  /* SP_AFTER_STAT */ {  _E,  _N,  _N,  _N,  _N,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _E },
  /* REASON        */ {  _E,  _R,  _R,  _N,  _N,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _E },
  /* VERSION_H     */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _N,  _E,  _E,  _E,  _E,  _E },
  /* VERSION_T1    */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _N,  _E,  _E,  _E,  _E,  _E },
  /* VERSION_T2    */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _N,  _E,  _E,  _E,  _E },
  /* VERSION_P     */ {  _E,  _E,  _E,  _E,  _E,  _E,  _N,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
  /* VERSION_SLASH */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  MJ,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
  /* VERSION_MAJOR */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _N,  MJ,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
  /* VERSION_DOT   */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  Mn,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
  /* VERSION_MINOR */ {  _E,  _E,  _E,  _N,  _N,  _E,  _E,  _E,  Mn,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
  /* LINE_CR       */ {  _E,  _E,  _E,  _E,  _N,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
  /* LINE_LF       */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
  /* HEADER_START  */ {  _E,  _E,  _E,  _N,  HD,  _E,  _E,  _h,  _h,  _h,  _h,  _h,  _h,  _h,  _h,  _E,  _E,  _E },
  /* HEADER_NAME   */ {  _E,  _E,  _E,  _E,  _E,  _N,  _E,  _h,  _h,  _h,  _h,  _h,  _h,  _h,  _h,  _E,  _E,  _E },
  /* HEADER_COLON  */ {  _E,  _N,  _N,  _N,  HE,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _E },
  /* HEADER_VALUE  */ {  _E,  _v,  _v,  _N,  HE,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _E },
  /* HEADER_V_OWS  */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
  /* HEADER_CR     */ {  _E,  _E,  _E,  _E,  HE,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
  /* HEADER_LF     */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
  /* HEADERS_END   */ {  _E,  _E,  _E,  _E,  HD,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
};

/**
 * Action table for RESPONSE parsing
 *
 * IMPORTANT: Header is added only in HEADER_CR+LF or directly on bare LF.
 * When HEADER_VALUE/COLON sees CR, we just transition (no action).
 */
const uint8_t http1_resp_action[HTTP1_NUM_STATES][HTTP1_NUM_CLASSES] = {
  /*                    CTL  SP  HTAB  CR   LF COLON SLASH DOT DIGIT HEX ALPHA   H    T    P TCHAR VCHAR  OBS INVLD */
  /* START         */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _N,  _E,  _E,  _E,  _E,  _E,  _E },
  /* METHOD        */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
  /* SP_AFTER_METH */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
  /* URI           */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
  /* SP_AFTER_URI  */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
  /* STATUS_CODE   */ {  _E,  _N,  _E,  _N,  _E,  _E,  _E,  _E,  SD,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
  /* SP_AFTER_STAT */ {  _E,  _N,  _N,  _N,  _N,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _E },
  /* REASON        */ {  _E,  _R,  _R,  _N,  _N,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _E },
  /* VERSION_H     */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _N,  _E,  _E,  _E,  _E,  _E },
  /* VERSION_T1    */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _N,  _E,  _E,  _E,  _E,  _E },
  /* VERSION_T2    */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _N,  _E,  _E,  _E,  _E },
  /* VERSION_P     */ {  _E,  _E,  _E,  _E,  _E,  _E,  _N,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
  /* VERSION_SLASH */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  MJ,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
  /* VERSION_MAJOR */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _N,  MJ,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
  /* VERSION_DOT   */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  Mn,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
  /* VERSION_MINOR */ {  _E,  _N,  _E,  _E,  _E,  _E,  _E,  _E,  Mn,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
  /* LINE_CR       */ {  _E,  _E,  _E,  _E,  _N,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
  /* LINE_LF       */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
  /* HEADER_START  */ {  _E,  _E,  _E,  _N,  HD,  _E,  _E,  _h,  _h,  _h,  _h,  _h,  _h,  _h,  _h,  _E,  _E,  _E },
  /* HEADER_NAME   */ {  _E,  _E,  _E,  _E,  _E,  _N,  _E,  _h,  _h,  _h,  _h,  _h,  _h,  _h,  _h,  _E,  _E,  _E },
  /* HEADER_COLON  */ {  _E,  _N,  _N,  _N,  HE,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _E },
  /* HEADER_VALUE  */ {  _E,  _v,  _v,  _N,  HE,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _E },
  /* HEADER_V_OWS  */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
  /* HEADER_CR     */ {  _E,  _E,  _E,  _E,  HE,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
  /* HEADER_LF     */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
  /* HEADERS_END   */ {  _E,  _E,  _E,  _E,  HD,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
};

/* clang-format on */

/* Undefine table shorthand macros */
#undef __
#undef _C
#undef ST
#undef ME
#undef S1
#undef UR
#undef S2
#undef SC
#undef S3
#undef RE
#undef VH
#undef V1
#undef V2
#undef VP
#undef VS
#undef VM
#undef VD
#undef Vm
#undef CR
#undef LF
#undef HS
#undef HN
#undef HC
#undef HV
#undef HR
#undef HL
#undef _N
#undef _M
#undef _U
#undef _R
#undef _h
#undef _v
#undef ME_
#undef UE_
#undef MJ
#undef Mn
#undef SD
#undef HE
#undef HD
#undef _E

/* ============================================================================
 * Exception Definition
 * ============================================================================ */

const Except_T SocketHTTP1_ParseError
    = { &SocketHTTP1_ParseError, "HTTP/1.1 parse error" };

/* Thread-local exception for detailed error messages */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketHTTP1);

#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketHTTP1, e)

/* ============================================================================
 * Constants
 * ============================================================================ */

/* Initial token buffer sizes - see SocketHTTP1-private.h for defaults */

/* HTTP version single-digit limit */
#define HTTP1_MAX_VERSION_DIGIT 9

/* Maximum 3-digit status code value */
#define HTTP1_MAX_STATUS_CODE 999

/* Header size calculation overhead (": \r\n") */
#define HTTP1_HEADER_OVERHEAD 4

/* ============================================================================
 * Result Strings
 * ============================================================================ */

static const char *result_strings[] = {
  [HTTP1_OK] = "OK",
  [HTTP1_INCOMPLETE] = "Incomplete - need more data",
  [HTTP1_ERROR] = "Parse error",
  [HTTP1_ERROR_LINE_TOO_LONG] = "Request/status line too long",
  [HTTP1_ERROR_INVALID_METHOD] = "Invalid HTTP method",
  [HTTP1_ERROR_INVALID_URI] = "Invalid request target",
  [HTTP1_ERROR_INVALID_VERSION] = "Invalid HTTP version",
  [HTTP1_ERROR_INVALID_STATUS] = "Invalid status code",
  [HTTP1_ERROR_INVALID_HEADER_NAME] = "Invalid header name",
  [HTTP1_ERROR_INVALID_HEADER_VALUE] = "Invalid header value",
  [HTTP1_ERROR_HEADER_TOO_LARGE] = "Header too large",
  [HTTP1_ERROR_TOO_MANY_HEADERS] = "Too many headers",
  [HTTP1_ERROR_INVALID_CONTENT_LENGTH] = "Invalid Content-Length",
  [HTTP1_ERROR_INVALID_CHUNK_SIZE] = "Invalid chunk size",
  [HTTP1_ERROR_CHUNK_TOO_LARGE] = "Chunk too large",
  [HTTP1_ERROR_INVALID_TRAILER] = "Invalid trailer",
  [HTTP1_ERROR_UNEXPECTED_EOF] = "Unexpected end of input",
  [HTTP1_ERROR_SMUGGLING_DETECTED] = "Request smuggling attempt detected"
};

const char *
SocketHTTP1_result_string (SocketHTTP1_Result result)
{
  size_t max_result = sizeof (result_strings) / sizeof (result_strings[0]);

  if (result >= 0 && (size_t)result < max_result && result_strings[result])
    return result_strings[result];

  return "Unknown error";
}

/* ============================================================================
 * Configuration
 * ============================================================================ */

void
SocketHTTP1_config_defaults (SocketHTTP1_Config *config)
{
  assert (config);

  config->max_request_line = SOCKETHTTP1_MAX_REQUEST_LINE;
  config->max_header_name = SOCKETHTTP1_MAX_HEADER_NAME;
  config->max_header_value = SOCKETHTTP1_MAX_HEADER_VALUE;
  config->max_headers = SOCKETHTTP1_MAX_HEADERS;
  config->max_header_size = SOCKETHTTP1_MAX_HEADER_SIZE;
  config->max_chunk_size = SOCKETHTTP1_MAX_CHUNK_SIZE;
  config->max_trailer_size = SOCKETHTTP1_MAX_TRAILER_SIZE;
  config->allow_obs_fold = 0;
  config->strict_mode = 1;
}

/* ============================================================================
 * Parser Lifecycle - Static Helpers
 * ============================================================================ */

/**
 * init_token_buffers - Initialize all token buffers for parser
 * @parser: Parser instance to initialize
 *
 * Returns: 0 on success, -1 on failure
 */
static int
init_token_buffers (SocketHTTP1_Parser_T parser)
{
  if (http1_tokenbuf_init (&parser->method_buf, parser->arena,
                           HTTP1_DEFAULT_METHOD_BUF_SIZE)
          < 0
      || http1_tokenbuf_init (&parser->uri_buf, parser->arena,
                              HTTP1_DEFAULT_URI_BUF_SIZE)
             < 0
      || http1_tokenbuf_init (&parser->reason_buf, parser->arena,
                              HTTP1_DEFAULT_REASON_BUF_SIZE)
             < 0
      || http1_tokenbuf_init (&parser->name_buf, parser->arena,
                              HTTP1_DEFAULT_HEADER_NAME_BUF_SIZE)
             < 0
      || http1_tokenbuf_init (&parser->value_buf, parser->arena,
                              HTTP1_DEFAULT_HEADER_VALUE_BUF_SIZE)
             < 0)
    {
      return -1;
    }
  return 0;
}

/**
 * reset_token_buffers - Reset all token buffers for reuse
 * @parser: Parser instance
 */
static void
reset_token_buffers (SocketHTTP1_Parser_T parser)
{
  http1_tokenbuf_reset (&parser->method_buf);
  http1_tokenbuf_reset (&parser->uri_buf);
  http1_tokenbuf_reset (&parser->reason_buf);
  http1_tokenbuf_reset (&parser->name_buf);
  http1_tokenbuf_reset (&parser->value_buf);
}

/**
 * reset_body_tracking - Reset body-related fields
 * @parser: Parser instance
 */
static void
reset_body_tracking (SocketHTTP1_Parser_T parser)
{
  parser->body_mode = HTTP1_BODY_NONE;
  parser->content_length = -1;
  parser->body_remaining = -1;
  parser->body_complete = 0;
  parser->chunk_size = 0;
  parser->chunk_remaining = 0;
}

/* ============================================================================
 * Parser Lifecycle - Public API
 * ============================================================================ */

SocketHTTP1_Parser_T
SocketHTTP1_Parser_new (SocketHTTP1_ParseMode mode,
                        const SocketHTTP1_Config *config, Arena_T arena)
{
  SocketHTTP1_Parser_T parser;

  assert (arena);

  parser = CALLOC (arena, 1, sizeof (*parser));
  if (!parser)
    {
      SOCKET_ERROR_MSG ("Cannot allocate HTTP/1.1 parser");
      RAISE_MODULE_ERROR (SocketHTTP1_ParseError);
    }



  parser->mode = mode;
  parser->arena = arena;

  /* Apply configuration */
  if (config)
    parser->config = *config;
  else
    SocketHTTP1_config_defaults (&parser->config);

  /* Initialize state */
  parser->state = HTTP1_STATE_START;
  parser->internal_state = HTTP1_PS_START;
  parser->error = HTTP1_OK;

  /* Initialize headers */
  parser->headers = SocketHTTP_Headers_new (arena);
  if (!parser->headers)
    {
      SOCKET_ERROR_MSG ("Cannot allocate headers collection");
      RAISE_MODULE_ERROR (SocketHTTP1_ParseError);
    }

  /* Initialize token buffers */
  if (init_token_buffers (parser) < 0)
    {
      SOCKET_ERROR_MSG ("Cannot allocate token buffers");
      RAISE_MODULE_ERROR (SocketHTTP1_ParseError);
    }

  reset_body_tracking (parser);

  return parser;
}

void
SocketHTTP1_Parser_free (SocketHTTP1_Parser_T *parser)
{
  if (parser && *parser)
    {
      /* Arena handles memory - just clear pointer */
      *parser = NULL;
    }
}

void
SocketHTTP1_Parser_reset (SocketHTTP1_Parser_T parser)
{
  assert (parser);

  /* Reset state */
  parser->state = HTTP1_STATE_START;
  parser->internal_state = HTTP1_PS_START;
  parser->error = HTTP1_OK;

  /* Clear headers */
  SocketHTTP_Headers_clear (parser->headers);
  if (parser->trailers)
    SocketHTTP_Headers_clear (parser->trailers);

  /* Reset token buffers */
  reset_token_buffers (parser);

  /* Reset counters */
  parser->header_count = 0;
  parser->total_header_size = 0;
  parser->line_length = 0;

  /* Reset body tracking */
  reset_body_tracking (parser);

  /* Reset version */
  parser->version_major = 0;
  parser->version_minor = 0;
  parser->status_code = 0;

  /* Reset connection flags */
  parser->keepalive = 0;
  parser->is_upgrade = 0;
  parser->upgrade_protocol = NULL;
  parser->expects_continue = 0;

  /* Clear message union */
  memset (&parser->message, 0, sizeof (parser->message));
}

/* ============================================================================
 * Body Mode Determination (RFC 9112 Section 6) - Static Helpers
 * ============================================================================ */

/**
 * parse_content_length - Parse and validate Content-Length header
 * @headers: Headers collection to search
 *
 * Returns: Value on success, -1 on error, -2 if not present
 */
static int64_t
parse_content_length (const SocketHTTP_Headers_T headers)
{
  const size_t MAX_CL_HEADERS = 2;
  const char *cl_values[MAX_CL_HEADERS];
  size_t count;
  int64_t value;
  const char *cl;
  const char *p;

  count = SocketHTTP_Headers_get_all (headers, "Content-Length", cl_values, MAX_CL_HEADERS);

  if (count == 0)
    return -2; /* Not present */

  /* Multiple headers must have identical values (RFC 9112 Section 6.3) */
  if (count > 1 && strcmp (cl_values[0], cl_values[1]) != 0)
    return -1; /* Different values = smuggling attempt */

  cl = cl_values[0];
  value = 0;
  p = cl;

  /* Skip leading whitespace */
  while (*p == ' ' || *p == '\t')
    p++;

  if (*p == '\0')
    return -1; /* Empty value */

  /* Must start with digit */
  if (!http1_is_digit (*p))
    return -1;

  while (http1_is_digit (*p))
    {
      int64_t digit = *p - '0';

      /* Check overflow before multiplication */
      if (value > (INT64_MAX - digit) / 10)
        return -1;

      value = value * 10 + digit;
      p++;
    }

  /* Skip trailing whitespace */
  while (*p == ' ' || *p == '\t')
    p++;

  if (*p != '\0')
    return -1; /* Trailing garbage */

  return value;
}

/**
 * has_chunked_encoding - Check if Transfer-Encoding includes chunked
 * @headers: Headers collection
 *
 * Returns: 1 if chunked, 0 otherwise
 */
static int
has_chunked_encoding (const SocketHTTP_Headers_T headers)
{
  return SocketHTTP_Headers_contains (headers, "Transfer-Encoding", "chunked");
}

/**
 * set_body_mode_chunked - Set parser to chunked body mode
 * @parser: Parser instance
 */
static void
set_body_mode_chunked (SocketHTTP1_Parser_T parser)
{
  parser->body_mode = HTTP1_BODY_CHUNKED;
  parser->content_length = -1;
  parser->body_remaining = -1;
}

/**
 * set_body_mode_until_close - Set parser to read until close
 * @parser: Parser instance
 */
static void
set_body_mode_until_close (SocketHTTP1_Parser_T parser)
{
  parser->body_mode = HTTP1_BODY_UNTIL_CLOSE;
  parser->content_length = -1;
  parser->body_remaining = -1;
}

/**
 * set_body_mode_content_length - Set parser to fixed content length
 * @parser: Parser instance
 * @length: Content length value
 */
static void
set_body_mode_content_length (SocketHTTP1_Parser_T parser, int64_t length)
{
  parser->body_mode = HTTP1_BODY_CONTENT_LENGTH;
  parser->content_length = length;
  parser->body_remaining = length;

  if (length == 0)
    parser->body_complete = 1;
}

/**
 * set_body_mode_none - Set parser to no body mode
 * @parser: Parser instance
 */
static void
set_body_mode_none (SocketHTTP1_Parser_T parser)
{
  parser->body_mode = HTTP1_BODY_NONE;
  parser->content_length = -1;
  parser->body_remaining = 0;
  parser->body_complete = 1;
}

/**
 * determine_body_mode - Determine body transfer mode from headers
 * @parser: Parser instance
 *
 * Returns: HTTP1_OK or error code (smuggling detected)
 */
static SocketHTTP1_Result
determine_body_mode (SocketHTTP1_Parser_T parser)
{
  int has_te;
  int64_t cl_value;
  int has_cl;

  has_te = SocketHTTP_Headers_has (parser->headers, "Transfer-Encoding");
  cl_value = parse_content_length (parser->headers);
  has_cl = (cl_value >= -1); /* -1 = invalid, -2 = not present */

  /* CRITICAL: Detect request smuggling attempts (RFC 9112 Section 6.3) */
  if (parser->config.strict_mode)
    {
      if (has_cl && cl_value >= 0 && has_te)
        return HTTP1_ERROR_SMUGGLING_DETECTED;

      if (has_cl && cl_value == -1)
        return HTTP1_ERROR_INVALID_CONTENT_LENGTH;
    }

  /* Transfer-Encoding takes precedence over Content-Length */
  if (has_te)
    {
      if (has_chunked_encoding (parser->headers))
        set_body_mode_chunked (parser);
      else
        set_body_mode_until_close (parser);
      return HTTP1_OK;
    }

  /* Content-Length present */
  if (cl_value >= 0)
    {
      set_body_mode_content_length (parser, cl_value);
      return HTTP1_OK;
    }

  /* No body indicator */
  set_body_mode_none (parser);
  return HTTP1_OK;
}

/* ============================================================================
 * HTTP Version and Connection Helpers
 * ============================================================================ */

/**
 * map_http_version - Map version major/minor to enum
 * @major: HTTP major version
 * @minor: HTTP minor version
 *
 * Returns: SocketHTTP_Version enum value
 */
static SocketHTTP_Version
map_http_version (int major, int minor)
{
  if (major == 1 && minor == 1)
    return HTTP_VERSION_1_1;
  if (major == 1 && minor == 0)
    return HTTP_VERSION_1_0;
  if (major == 0 && minor == 9)
    return HTTP_VERSION_0_9;
  if (major == 2 && minor == 0)
    return HTTP_VERSION_2;

  return HTTP_VERSION_1_1; /* Default */
}

/**
 * determine_keepalive - Determine connection persistence from version/headers
 * @version: HTTP version enum
 * @headers: Headers collection
 *
 * Returns: 1 if keep-alive, 0 if close
 */
static int
determine_keepalive (SocketHTTP_Version version,
                     const SocketHTTP_Headers_T headers)
{
  if (version == HTTP_VERSION_1_1)
    {
      /* HTTP/1.1: keep-alive by default unless "Connection: close" */
      return !SocketHTTP_Headers_contains (headers, "Connection", "close");
    }

  /* HTTP/1.0: close by default unless "Connection: keep-alive" */
  return SocketHTTP_Headers_contains (headers, "Connection", "keep-alive");
}

/**
 * check_upgrade - Check and set upgrade protocol if present
 * @parser: Parser instance
 */
static void
check_upgrade (SocketHTTP1_Parser_T parser)
{
  if (SocketHTTP_Headers_has (parser->headers, "Upgrade"))
    {
      parser->is_upgrade = 1;
      parser->upgrade_protocol
          = SocketHTTP_Headers_get (parser->headers, "Upgrade");
    }
}

/**
 * finalize_common - Common finalization for request/response after headers
 * @parser: Parser instance
 * @version: Parsed HTTP version
 *
 * Handles body mode determination, keepalive, upgrade checks.
 * Caller must set message.version and message.headers before calling.
 *
 * Returns: HTTP1_OK or error
 */
static SocketHTTP1_Result
finalize_common (SocketHTTP1_Parser_T parser, SocketHTTP_Version version)
{
  SocketHTTP1_Result result;

  result = determine_body_mode (parser);
  if (result != HTTP1_OK)
    return result;

  parser->keepalive = determine_keepalive (version, parser->headers);
  check_upgrade (parser);

  return HTTP1_OK;
}

/* ============================================================================
 * Message Finalization
 * ============================================================================ */

/**
 * finalize_request - Finalize request after headers are complete
 * @parser: Parser instance
 *
 * Returns: HTTP1_OK or error code
 */
static SocketHTTP1_Result
finalize_request (SocketHTTP1_Parser_T parser)
{
  SocketHTTP_Request *req = &parser->message.request;
  SocketHTTP1_Result result;
  SocketHTTP_Version version;

  /* Set method */
  req->method = SocketHTTP_method_parse (parser->method_buf.data,
                                         parser->method_buf.len);

  /* Set version */
  version
      = map_http_version (parser->version_major, parser->version_minor);
  req->version = version;

  /* Set request target (path) - already null-terminated */
  req->path = parser->uri_buf.data;

  /* Extract authority from Host header */
  req->authority = SocketHTTP_Headers_get (parser->headers, "Host");

  /* Set headers */
  req->headers = parser->headers;

  result = finalize_common (parser, version);
  if (result != HTTP1_OK)
    return result;

  req->has_body = (parser->body_mode != HTTP1_BODY_NONE);
  req->content_length = parser->content_length;

  /* Check for Expect: 100-continue */
  if (SocketHTTP_Headers_contains (parser->headers, "Expect", "100-continue"))
    parser->expects_continue = 1;

  return HTTP1_OK;
}

/**
 * finalize_response - Finalize response after headers are complete
 * @parser: Parser instance
 *
 * Returns: HTTP1_OK or error code
 */
static SocketHTTP1_Result
finalize_response (SocketHTTP1_Parser_T parser)
{
  SocketHTTP_Response *resp = &parser->message.response;
  SocketHTTP1_Result result;
  SocketHTTP_Version version;

  /* Set version */
  version
      = map_http_version (parser->version_major, parser->version_minor);
  resp->version = version;

  /* Set status code and reason */
  resp->status_code = parser->status_code;
  resp->reason_phrase = parser->reason_buf.data;

  /* Set headers */
  resp->headers = parser->headers;

  /* 1xx, 204, 304 responses have no body (RFC 9112 Section 6.3) */
  if ((parser->status_code >= 100 && parser->status_code < 200)
      || parser->status_code == 204 || parser->status_code == 304)
    {
      parser->body_mode = HTTP1_BODY_NONE;
      parser->body_complete = 1;
      resp->has_body = 0;
      resp->content_length = 0;
      return HTTP1_OK;
    }

  result = finalize_common (parser, version);
  if (result != HTTP1_OK)
    return result;

  resp->has_body = (parser->body_mode != HTTP1_BODY_NONE);
  resp->content_length = parser->content_length;

  return HTTP1_OK;
}

/* ============================================================================
 * DFA Parser Core - Error and State Helpers
 * ============================================================================ */

/**
 * set_error - Set parser error state
 * @parser: Parser instance
 * @error: Error code to set
 */
static void
set_error (SocketHTTP1_Parser_T parser, SocketHTTP1_Result error)
{
  parser->state = HTTP1_STATE_ERROR;
  parser->internal_state = HTTP1_PS_ERROR;
  parser->error = error;
}

/**
 * Macro to set error and return from parse loop
 *
 * Eliminates repeated error return pattern throughout the parser.
 */
#define RETURN_PARSE_ERROR(parser, err, p, data, consumed)                     \
  do                                                                           \
    {                                                                          \
      set_error ((parser), (err));                                             \
      *(consumed) = (size_t)((p) - (data));                                    \
      return (parser)->error;                                                  \
    }                                                                          \
  while (0)

/**
 * add_current_header - Add accumulated header to collection
 * @parser: Parser instance
 *
 * Returns: HTTP1_OK or error code
 */
static SocketHTTP1_Result
add_current_header (SocketHTTP1_Parser_T parser)
{
  char *name;
  char *value;

  name = http1_tokenbuf_terminate (&parser->name_buf, parser->arena,
                                   parser->config.max_header_name);
  value = http1_tokenbuf_terminate (&parser->value_buf, parser->arena,
                                    parser->config.max_header_value);

  if (!name || !value)
    return HTTP1_ERROR_HEADER_TOO_LARGE;

  if (parser->header_count >= parser->config.max_headers)
    return HTTP1_ERROR_TOO_MANY_HEADERS;

  parser->total_header_size
      += parser->name_buf.len + parser->value_buf.len + HTTP1_HEADER_OVERHEAD;
  if (parser->total_header_size > parser->config.max_header_size)
    return HTTP1_ERROR_HEADER_TOO_LARGE;

  if (SocketHTTP_Headers_add_n (parser->headers, name, parser->name_buf.len,
                                value, parser->value_buf.len)
      < 0)
    return HTTP1_ERROR_INVALID_HEADER_VALUE;

  parser->header_count++;

  http1_tokenbuf_reset (&parser->name_buf);
  http1_tokenbuf_reset (&parser->value_buf);

  return HTTP1_OK;
}

/**
 * state_to_error - Map internal state to appropriate error code
 * @state: Current internal parser state
 *
 * Returns: Appropriate SocketHTTP1_Result error code
 */
static SocketHTTP1_Result
state_to_error (HTTP1_InternalState state)
{
  switch (state)
    {
    case HTTP1_PS_START:
    case HTTP1_PS_METHOD:
      return HTTP1_ERROR_INVALID_METHOD;

    case HTTP1_PS_URI:
    case HTTP1_PS_SP_AFTER_METHOD:
      return HTTP1_ERROR_INVALID_URI;

    case HTTP1_PS_VERSION_H:
    case HTTP1_PS_VERSION_T1:
    case HTTP1_PS_VERSION_T2:
    case HTTP1_PS_VERSION_P:
    case HTTP1_PS_VERSION_SLASH:
    case HTTP1_PS_VERSION_MAJOR:
    case HTTP1_PS_VERSION_DOT:
    case HTTP1_PS_VERSION_MINOR:
    case HTTP1_PS_SP_AFTER_URI:
      return HTTP1_ERROR_INVALID_VERSION;

    case HTTP1_PS_STATUS_CODE:
    case HTTP1_PS_SP_AFTER_STATUS:
    case HTTP1_PS_REASON:
      return HTTP1_ERROR_INVALID_STATUS;

    case HTTP1_PS_HEADER_START:
    case HTTP1_PS_HEADER_NAME:
      return HTTP1_ERROR_INVALID_HEADER_NAME;

    case HTTP1_PS_HEADER_COLON:
    case HTTP1_PS_HEADER_VALUE:
    case HTTP1_PS_HEADER_CR:
      return HTTP1_ERROR_INVALID_HEADER_VALUE;

    default:
      return HTTP1_ERROR;
    }
}

/* ============================================================================
 * DFA Parser Core - Action Handlers
 * ============================================================================ */

/**
 * handle_store_action - Handle token buffer store actions
 * @parser: Parser instance
 * @action: Action type
 * @c: Character to store
 * @p: Current position
 * @data: Data start
 * @consumed: Consumed output
 *
 * Returns: HTTP1_OK or error code
 */
static SocketHTTP1_Result
handle_store_action (SocketHTTP1_Parser_T parser, uint8_t action, char c,
                     const char *p, const char *data, size_t *consumed)
{
  int ret;

  switch (action)
    {
    case HTTP1_ACT_STORE_METHOD:
      ret = http1_tokenbuf_append (&parser->method_buf, parser->arena, c,
                                   SOCKETHTTP1_MAX_METHOD_LEN);
      if (ret < 0)
        RETURN_PARSE_ERROR (parser, HTTP1_ERROR_INVALID_METHOD, p, data,
                            consumed);
      break;

    case HTTP1_ACT_STORE_URI:
      ret = http1_tokenbuf_append (&parser->uri_buf, parser->arena, c,
                                   parser->config.max_request_line);
      if (ret < 0)
        RETURN_PARSE_ERROR (parser, HTTP1_ERROR_LINE_TOO_LONG, p, data,
                            consumed);
      break;

    case HTTP1_ACT_STORE_REASON:
      ret = http1_tokenbuf_append (&parser->reason_buf, parser->arena, c,
                                   parser->config.max_request_line);
      if (ret < 0)
        RETURN_PARSE_ERROR (parser, HTTP1_ERROR_LINE_TOO_LONG, p, data,
                            consumed);
      break;

    case HTTP1_ACT_STORE_NAME:
      ret = http1_tokenbuf_append (&parser->name_buf, parser->arena, c,
                                   parser->config.max_header_name);
      if (ret < 0)
        RETURN_PARSE_ERROR (parser, HTTP1_ERROR_INVALID_HEADER_NAME, p, data,
                            consumed);
      break;

    case HTTP1_ACT_STORE_VALUE:
      ret = http1_tokenbuf_append (&parser->value_buf, parser->arena, c,
                                   parser->config.max_header_value);
      if (ret < 0)
        RETURN_PARSE_ERROR (parser, HTTP1_ERROR_HEADER_TOO_LARGE, p, data,
                            consumed);
      break;

    default:
      break;
    }

  return HTTP1_OK;
}

/**
 * handle_method_end - Handle method completion action
 * @parser: Parser instance
 * @p: Current position
 * @data: Data start
 * @consumed: Consumed output
 *
 * Returns: HTTP1_OK or error code
 */
static SocketHTTP1_Result
handle_method_end (SocketHTTP1_Parser_T parser, const char *p,
                   const char *data, size_t *consumed)
{
  if (parser->method_buf.len == 0)
    RETURN_PARSE_ERROR (parser, HTTP1_ERROR_INVALID_METHOD, p, data, consumed);

  if (!http1_tokenbuf_terminate (&parser->method_buf, parser->arena,
                                 parser->config.max_request_line))
    RETURN_PARSE_ERROR (parser, HTTP1_ERROR_LINE_TOO_LONG, p, data, consumed);

  return HTTP1_OK;
}

/**
 * handle_uri_end - Handle URI completion action
 * @parser: Parser instance
 * @p: Current position
 * @data: Data start
 * @consumed: Consumed output
 *
 * Returns: HTTP1_OK or error code
 */
static SocketHTTP1_Result
handle_uri_end (SocketHTTP1_Parser_T parser, const char *p, const char *data,
                size_t *consumed)
{
  if (!http1_tokenbuf_terminate (&parser->uri_buf, parser->arena,
                                 parser->config.max_request_line))
    RETURN_PARSE_ERROR (parser, HTTP1_ERROR_LINE_TOO_LONG, p, data, consumed);

  return HTTP1_OK;
}

/**
 * handle_version_digit - Handle version digit action
 * @parser: Parser instance
 * @action: VERSION_MAJ or VERSION_MIN
 * @c: Digit character
 * @p: Current position
 * @data: Data start
 * @consumed: Consumed output
 *
 * Returns: HTTP1_OK or error code
 */
static SocketHTTP1_Result
handle_version_digit (SocketHTTP1_Parser_T parser, uint8_t action, char c,
                      const char *p, const char *data, size_t *consumed)
{
  if (action == HTTP1_ACT_VERSION_MAJ)
    {
      parser->version_major = parser->version_major * 10 + (c - '0');
      if (parser->version_major > HTTP1_MAX_VERSION_DIGIT)
        RETURN_PARSE_ERROR (parser, HTTP1_ERROR_INVALID_VERSION, p, data,
                            consumed);
    }
  else
    {
      parser->version_minor = parser->version_minor * 10 + (c - '0');
      if (parser->version_minor > HTTP1_MAX_VERSION_DIGIT)
        RETURN_PARSE_ERROR (parser, HTTP1_ERROR_INVALID_VERSION, p, data,
                            consumed);
    }

  return HTTP1_OK;
}

/**
 * handle_status_digit - Handle status code digit action
 * @parser: Parser instance
 * @c: Digit character
 * @p: Current position
 * @data: Data start
 * @consumed: Consumed output
 *
 * Returns: HTTP1_OK or error code
 */
static SocketHTTP1_Result
handle_status_digit (SocketHTTP1_Parser_T parser, char c, const char *p,
                     const char *data, size_t *consumed)
{
  parser->status_code = parser->status_code * 10 + (c - '0');

  if (parser->status_code > HTTP1_MAX_STATUS_CODE)
    RETURN_PARSE_ERROR (parser, HTTP1_ERROR_INVALID_STATUS, p, data, consumed);

  return HTTP1_OK;
}

/**
 * calculate_next_body_state - Calculate next state/internal_state after
 * headers
 * @parser: Parser instance
 * @next_state: Output internal state
 */
static void
calculate_next_body_state (SocketHTTP1_Parser_T parser,
                           HTTP1_InternalState *next_state)
{
  if (parser->body_complete)
    {
      parser->state = HTTP1_STATE_COMPLETE;
      *next_state = HTTP1_PS_COMPLETE;
    }
  else if (parser->body_mode == HTTP1_BODY_CHUNKED)
    {
      parser->state = HTTP1_STATE_CHUNK_SIZE;
      *next_state = HTTP1_PS_CHUNK_SIZE;
    }
  else
    {
      parser->state = HTTP1_STATE_BODY;
      *next_state = HTTP1_PS_BODY_IDENTITY;
    }
}

/* ============================================================================
 * DFA Parser Core - Header Parsing Loop
 * ============================================================================ */

/**
 * parse_headers_loop - Inner DFA loop for header parsing
 * @parser: Parser instance
 * @data: Input data
 * @len: Input length
 * @consumed: Bytes consumed output
 * @state_table: State transition table
 * @action_table: Action table
 *
 * Processes bytes using DFA tables until body state or end.
 * Updates parser state and internal_state.
 *
 * Returns: HTTP1_INCOMPLETE if more data needed, HTTP1_OK if headers/body ready or error.
 * On error, sets parser->error and *consumed.
 */
/**
 * handle_dfa_action - Execute DFA action for current byte
 * @parser: Parser instance
 * @action: Action to execute
 * @c: Current byte
 * @p: Current position
 * @loop_data: Data start for consumed calc
 * @data: Original data start
 * @consumed: Consumed output
 * @next_state: Output next state (modified)
 *
 * Returns: HTTP1_OK or error code
 */
static SocketHTTP1_Result
handle_dfa_action (SocketHTTP1_Parser_T parser, uint8_t action, uint8_t c,
                   const char *p, const char *data,
                   size_t *consumed, HTTP1_InternalState current_state,
                   HTTP1_InternalState *next_state)
{
  SocketHTTP1_Result result;

  switch (action)
    {
    case HTTP1_ACT_NONE:
      /* Just transition, no side effect */
      return HTTP1_OK;

    case HTTP1_ACT_STORE_METHOD:
    case HTTP1_ACT_STORE_URI:
    case HTTP1_ACT_STORE_REASON:
    case HTTP1_ACT_STORE_NAME:
    case HTTP1_ACT_STORE_VALUE:
      result = handle_store_action (parser, action, (char)c, p, data, consumed);
      return result;

    case HTTP1_ACT_METHOD_END:
      result = handle_method_end (parser, p, data, consumed);
      return result;

    case HTTP1_ACT_URI_END:
      result = handle_uri_end (parser, p, data, consumed);
      return result;

    case HTTP1_ACT_VERSION_MAJ:
    case HTTP1_ACT_VERSION_MIN:
      result = handle_version_digit (parser, action, (char)c, p, data, consumed);
      return result;

    case HTTP1_ACT_STATUS_DIGIT:
      result = handle_status_digit (parser, (char)c, p, data, consumed);
      return result;

    case HTTP1_ACT_HEADER_END:
      result = add_current_header (parser);
      if (result != HTTP1_OK)
        {
          set_error (parser, result);
          *consumed = (size_t)(p - data);
          return result;
        }
      return HTTP1_OK;

    case HTTP1_ACT_HEADERS_DONE:
      /* Headers complete - finalize message */
      if (parser->mode == HTTP1_PARSE_REQUEST)
        result = finalize_request (parser);
      else
        result = finalize_response (parser);

      if (result != HTTP1_OK)
        {
          set_error (parser, result);
          *consumed = (size_t)(p - data) + 1;
          return result;
        }

      calculate_next_body_state (parser, next_state);
      parser->internal_state = *next_state;
      *consumed = (size_t)(p - data) + 1;
      return HTTP1_OK;

    case HTTP1_ACT_ERROR:
    default:
      set_error (parser, state_to_error (current_state));
      *consumed = (size_t)(p - data);
      return parser->error;
    }
}

static SocketHTTP1_Result
parse_headers_loop (SocketHTTP1_Parser_T parser,
                    const char *data, size_t len, size_t *consumed,
                    const uint8_t (*state_table)[HTTP1_NUM_CLASSES],
                    const uint8_t (*action_table)[HTTP1_NUM_CLASSES])
{
  const char *p;
  const char *end;
  HTTP1_InternalState state;
  SocketHTTP1_Result result;


  *consumed = 0;

  p = data;
  end = data + len;
  state = parser->internal_state;

  while (p < end)
    {
      uint8_t c = (uint8_t)*p;
      uint8_t cc = http1_char_class[c];
      HTTP1_InternalState next_state;
      uint8_t action;

      /* Handle body/trailer states outside the table-driven loop */
      if (state >= HTTP1_PS_BODY_IDENTITY)
        {
          parser->internal_state = state;
          *consumed = (size_t)(p - data);
          if (state == HTTP1_PS_COMPLETE)
            return HTTP1_OK;
          if (state == HTTP1_PS_ERROR)
            return parser->error;
          /* Body states handled by read_body function */
          return HTTP1_OK;
        }

      /* Table lookups - the core of the optimization */
      next_state = (HTTP1_InternalState)state_table[state][cc];
      action = action_table[state][cc];

      result = handle_dfa_action (parser, action, c, p, data, consumed, state, &next_state);
      if (result != HTTP1_OK)
        return result;

      /* Check for error transition */
      if (next_state == HTTP1_PS_ERROR)
        {
          set_error (parser, state_to_error (state));
          *consumed = (size_t)(p - data);
          return parser->error;
        }

      /* Update state and counters */
      state = next_state;
      parser->line_length++;

      /* Check line length limit */
      if (state <= HTTP1_PS_LINE_CR
          && parser->line_length > parser->config.max_request_line)
        {
          set_error (parser, HTTP1_ERROR_LINE_TOO_LONG);
          *consumed = (size_t)(p - data);
          return parser->error;
        }

      /* Reset line length on header start */
      if (state == HTTP1_PS_HEADER_START)
        {
          parser->line_length = 0;
          parser->state = HTTP1_STATE_HEADERS;
        }

      p++;

      if (state >= HTTP1_PS_BODY_IDENTITY)
        {
          parser->internal_state = state;
          *consumed = (size_t)(p - data);
          if (state == HTTP1_PS_COMPLETE)
            return HTTP1_OK;
          if (state == HTTP1_PS_ERROR)
            return parser->error;
          /* Body states handled by read_body function */
          return HTTP1_OK;
        }

    }

  parser->internal_state = state;
  *consumed = len;
  return HTTP1_INCOMPLETE;
}

/* ============================================================================
 * DFA Parser Core - Main Loop
 * ============================================================================ */

/**
 * SocketHTTP1_Parser_execute - Main DFA parsing function
 * @parser: Parser instance
 * @data: Input data buffer
 * @len: Input data length
 * @consumed: Output - bytes consumed
 *
 * Returns: Parse result (HTTP1_OK, HTTP1_INCOMPLETE, or error)
 *
 * Uses precomputed state transition and action tables for O(1) per-byte
 * processing with minimal branch misprediction.
 */
SocketHTTP1_Result
SocketHTTP1_Parser_execute (SocketHTTP1_Parser_T parser, const char *data,
                            size_t len, size_t *consumed)
{
  const uint8_t (*state_table)[HTTP1_NUM_CLASSES];
  const uint8_t (*action_table)[HTTP1_NUM_CLASSES];

  assert (parser);
  assert (data || len == 0);
  assert (consumed);

  *consumed = 0;

  if (parser->state == HTTP1_STATE_ERROR)
    return parser->error;

  if (parser->state == HTTP1_STATE_COMPLETE)
    return HTTP1_OK;

  /* Select appropriate tables based on parsing mode */
  if (parser->mode == HTTP1_PARSE_REQUEST)
    {
      state_table = http1_req_state;
      action_table = http1_req_action;
    }
  else
    {
      state_table = http1_resp_state;
      action_table = http1_resp_action;
    }

  return parse_headers_loop (parser, data, len, consumed, state_table, action_table);
}

/* Undefine internal macro */
#undef RETURN_PARSE_ERROR

/* ============================================================================
 * State Accessors
 * ============================================================================ */

SocketHTTP1_State
SocketHTTP1_Parser_state (SocketHTTP1_Parser_T parser)
{
  assert (parser);
  return parser->state;
}

const SocketHTTP_Request *
SocketHTTP1_Parser_get_request (SocketHTTP1_Parser_T parser)
{
  assert (parser);

  if (parser->mode != HTTP1_PARSE_REQUEST)
    return NULL;

  if (parser->state < HTTP1_STATE_BODY)
    return NULL;

  return &parser->message.request;
}

const SocketHTTP_Response *
SocketHTTP1_Parser_get_response (SocketHTTP1_Parser_T parser)
{
  assert (parser);

  if (parser->mode != HTTP1_PARSE_RESPONSE)
    return NULL;

  if (parser->state < HTTP1_STATE_BODY)
    return NULL;

  return &parser->message.response;
}

/* ============================================================================
 * Body Handling
 * ============================================================================ */

SocketHTTP1_BodyMode
SocketHTTP1_Parser_body_mode (SocketHTTP1_Parser_T parser)
{
  assert (parser);
  return parser->body_mode;
}

int64_t
SocketHTTP1_Parser_content_length (SocketHTTP1_Parser_T parser)
{
  assert (parser);
  return parser->content_length;
}

int64_t
SocketHTTP1_Parser_body_remaining (SocketHTTP1_Parser_T parser)
{
  assert (parser);
  return parser->body_remaining;
}

int
SocketHTTP1_Parser_body_complete (SocketHTTP1_Parser_T parser)
{
  assert (parser);
  return parser->body_complete;
}

SocketHTTP_Headers_T
SocketHTTP1_Parser_get_trailers (SocketHTTP1_Parser_T parser)
{
  assert (parser);
  return parser->trailers;
}

/* ============================================================================
 * Connection Management
 * ============================================================================ */

int
SocketHTTP1_Parser_should_keepalive (SocketHTTP1_Parser_T parser)
{
  assert (parser);
  return parser->keepalive;
}

int
SocketHTTP1_Parser_is_upgrade (SocketHTTP1_Parser_T parser)
{
  assert (parser);
  return parser->is_upgrade;
}

const char *
SocketHTTP1_Parser_upgrade_protocol (SocketHTTP1_Parser_T parser)
{
  assert (parser);
  return parser->upgrade_protocol;
}

int
SocketHTTP1_Parser_expects_continue (SocketHTTP1_Parser_T parser)
{
  assert (parser);
  return parser->expects_continue;
}
