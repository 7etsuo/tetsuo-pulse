/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* SocketHTTP1-parser.c - HTTP/1.1 DFA-based Incremental Parser (RFC 9112)
 * O(n) single-pass parsing with request smuggling prevention.
 */

#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"
#include "http/SocketHTTP-private.h"
#include "http/SocketHTTP1-private.h"
#include "http/SocketHTTP1.h"

#include <assert.h>
#include <string.h>

/* Compile-time string literal length (avoids strlen at runtime) */
#define STRLEN_LIT(s) (sizeof (s) - 1)

/* Decimal base for numeric conversion */
#define HTTP1_DECIMAL_BASE 10

/* clang-format off */

/* Common row macros for state tables to reduce duplication */
#define STATUS_CODE_ROW     {  __,  S3,  __,  CR,  __,  __,  __,  __,  SC,  __,  __,  __,  __,  __,  __,  __,  __,  __ }
#define SP_AFTER_STAT_ROW   {  __,  RE,  RE,  CR,  HS,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  __ }
#define REASON_ROW          {  __,  RE,  RE,  CR,  HS,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  RE,  __ }
#define VERSION_H_ROW       {  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  V1,  __,  __,  __,  __,  __ }
#define VERSION_T1_ROW      {  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  V2,  __,  __,  __,  __,  __ }
#define VERSION_T2_ROW      {  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  VP,  __,  __,  __,  __ }
#define VERSION_P_ROW       {  __,  __,  __,  __,  __,  __,  VS,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __ }
#define VERSION_SLASH_ROW   {  __,  __,  __,  __,  __,  __,  __,  __,  VM,  __,  __,  __,  __,  __,  __,  __,  __,  __ }
#define VERSION_MAJOR_ROW   {  __,  __,  __,  __,  __,  __,  __,  VD,  VM,  __,  __,  __,  __,  __,  __,  __,  __,  __ }
#define VERSION_DOT_ROW     {  __,  __,  __,  __,  __,  __,  __,  __,  Vm,  __,  __,  __,  __,  __,  __,  __,  __,  __ }
#define LINE_CR_ROW         {  __,  __,  __,  __,  HS,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __ }
#define LINE_LF_ROW         {  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __ }
#define HEADER_START_ROW    {  __,  __,  __,  HL,  _C,  __,  __,  HN,  HN,  HN,  HN,  HN,  HN,  HN,  HN,  __,  __,  __ }
#define HEADER_NAME_ROW     {  __,  __,  __,  __,  __,  HC,  __,  HN,  HN,  HN,  HN,  HN,  HN,  HN,  HN,  __,  __,  __ }
#define HEADER_COLON_ROW    {  __,  HC,  HC,  HR,  HS,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  __ }
#define HEADER_VALUE_ROW    {  __,  HV,  HV,  HR,  HS,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  HV,  __ }
#define HEADER_V_OWS_ROW    {  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __ }
#define HEADER_CR_ROW       {  __,  __,  __,  __,  HS,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __ }
#define HEADER_LF_ROW       {  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __ }
#define HEADERS_END_ROW     {  __,  __,  __,  __,  _C,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __ }

/* Common action rows */
#define STATUS_CODE_ACT_ROW     {  _E,  _N,  _E,  _N,  _E,  _E,  _E,  _E,  SD,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E }
#define SP_AFTER_STAT_ACT_ROW   {  _E,  _N,  _N,  _N,  _N,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _E }
#define REASON_ACT_ROW          {  _E,  _R,  _R,  _N,  _N,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _R,  _E }
#define VERSION_H_ACT_ROW       {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _N,  _E,  _E,  _E,  _E,  _E }
#define VERSION_T1_ACT_ROW      {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _N,  _E,  _E,  _E,  _E,  _E }
#define VERSION_T2_ACT_ROW      {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _N,  _E,  _E,  _E,  _E }
#define VERSION_P_ACT_ROW       {  _E,  _E,  _E,  _E,  _E,  _E,  _N,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E }
#define VERSION_SLASH_ACT_ROW   {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  MJ,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E }
#define VERSION_MAJOR_ACT_ROW   {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _N,  MJ,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E }
#define VERSION_DOT_ACT_ROW     {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  Mn,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E }
#define LINE_CR_ACT_ROW         {  _E,  _E,  _E,  _E,  _N,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E }
#define LINE_LF_ACT_ROW         {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E }
#define HEADER_START_ACT_ROW    {  _E,  _E,  _E,  _N,  HD,  _E,  _E,  _h,  _h,  _h,  _h,  _h,  _h,  _h,  _h,  _E,  _E,  _E }
#define HEADER_NAME_ACT_ROW     {  _E,  _E,  _E,  _E,  _E,  _N,  _E,  _h,  _h,  _h,  _h,  _h,  _h,  _h,  _h,  _E,  _E,  _E }
#define HEADER_COLON_ACT_ROW    {  _E,  _N,  _N,  _N,  HE,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _E }
#define HEADER_VALUE_ACT_ROW    {  _E,  _v,  _v,  _N,  HE,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _v,  _E }
#define HEADER_V_OWS_ACT_ROW    {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E }
#define HEADER_CR_ACT_ROW       {  _E,  _E,  _E,  _E,  HE,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E }
#define HEADER_LF_ACT_ROW       {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E }
#define HEADERS_END_ACT_ROW     {  _E,  _E,  _E,  _E,  HD,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E }



/* Character classification table for O(1) lookup in parsing hot loop */
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

/* State transition table for REQUEST parsing: [current_state][char_class] -> next_state */
const uint8_t http1_req_state[HTTP1_NUM_STATES][HTTP1_NUM_CLASSES] = {
  /*                    CTL  SP  HTAB  CR   LF COLON SLASH DOT DIGIT HEX ALPHA   H    T    P TCHAR VCHAR  OBS INVLD */
  /* START         */ {  __,  __,  __,  __,  __,  __,  __,  __,  __,  ME,  ME,  ME,  ME,  ME,  ME,  __,  __,  __ },
  /* METHOD        */ {  __,  S1,  __,  __,  __,  __,  __,  __,  ME,  ME,  ME,  ME,  ME,  ME,  ME,  __,  __,  __ },
  /* SP_AFTER_METH */ {  __,  __,  __,  __,  __,  UR,  UR,  UR,  UR,  UR,  UR,  UR,  UR,  UR,  UR,  UR,  __,  __ },
  /* URI           */ {  __,  S2,  __,  CR,  HS,  UR,  UR,  UR,  UR,  UR,  UR,  UR,  UR,  UR,  UR,  UR,  __,  __ },
  /* SP_AFTER_URI  */ {  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  VH,  __,  __,  __,  __,  __,  __ },
  /* STATUS_CODE   */ STATUS_CODE_ROW,
  /* SP_AFTER_STAT */ SP_AFTER_STAT_ROW,
  /* REASON        */ REASON_ROW,
  /* VERSION_H     */ VERSION_H_ROW,
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

/* State transition table for RESPONSE parsing */
const uint8_t http1_resp_state[HTTP1_NUM_STATES][HTTP1_NUM_CLASSES] = {
  /*                    CTL  SP  HTAB  CR   LF COLON SLASH DOT DIGIT HEX ALPHA   H    T    P TCHAR VCHAR  OBS INVLD */
  /* START         */ {  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  VH,  __,  __,  __,  __,  __,  __ },
  /* METHOD        */ {  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
  /* SP_AFTER_METH */ {  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
  /* URI           */ {  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
  /* SP_AFTER_URI  */ {  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __,  __ },
  /* STATUS_CODE   */ STATUS_CODE_ROW,
  /* SP_AFTER_STAT */ SP_AFTER_STAT_ROW,
  /* REASON        */ REASON_ROW,
  /* VERSION_H     */ VERSION_H_ROW,
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

/* Action table for REQUEST parsing: [state][char_class] -> action */
const uint8_t http1_req_action[HTTP1_NUM_STATES][HTTP1_NUM_CLASSES] = {
  /*                    CTL  SP  HTAB  CR   LF COLON SLASH DOT DIGIT HEX ALPHA   H    T    P TCHAR VCHAR  OBS INVLD */
  /* START         */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _M,  _M,  _M,  _M,  _M,  _M,  _E,  _E,  _E },
  /* METHOD        */ {  _E, ME_,  _E,  _E,  _E,  _E,  _E,  _E,  _M,  _M,  _M,  _M,  _M,  _M,  _M,  _E,  _E,  _E },
  /* SP_AFTER_METH */ {  _E,  _E,  _E,  _E,  _E,  _U,  _U,  _U,  _U,  _U,  _U,  _U,  _U,  _U,  _U,  _U,  _E,  _E },
  /* URI           */ {  _E, UE_,  _E,  _N,  _N,  _U,  _U,  _U,  _U,  _U,  _U,  _U,  _U,  _U,  _U,  _U,  _E,  _E },
  /* SP_AFTER_URI  */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _N,  _E,  _E,  _E,  _E,  _E,  _E },
  /* STATUS_CODE   */ STATUS_CODE_ACT_ROW,
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

/* Action table for RESPONSE parsing */
const uint8_t http1_resp_action[HTTP1_NUM_STATES][HTTP1_NUM_CLASSES] = {
  /*                    CTL  SP  HTAB  CR   LF COLON SLASH DOT DIGIT HEX ALPHA   H    T    P TCHAR VCHAR  OBS INVLD */
  /* START         */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _N,  _E,  _E,  _E,  _E,  _E,  _E },
  /* METHOD        */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
  /* SP_AFTER_METH */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
  /* URI           */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
  /* SP_AFTER_URI  */ {  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E,  _E },
  /* STATUS_CODE   */ STATUS_CODE_ACT_ROW,
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

const Except_T SocketHTTP1_ParseError
    = { &SocketHTTP1_ParseError, "HTTP/1.1 parse error" };

/* Thread-local exception for detailed error messages */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketHTTP1);

#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketHTTP1, e)

/* Initial token buffer sizes - see SocketHTTP1-private.h for defaults */

/* HTTP version single-digit limit */
#define HTTP1_MAX_VERSION_DIGIT 9

/* Maximum 3-digit status code value */
#define HTTP1_MAX_STATUS_CODE 999

/* Header size calculation overhead (": \r\n") */
#define HTTP1_HEADER_OVERHEAD 4

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
  [HTTP1_ERROR_BODY_TOO_LARGE] = "Body too large",
  [HTTP1_ERROR_INVALID_TRAILER] = "Invalid trailer",
  [HTTP1_ERROR_UNSUPPORTED_TRANSFER_CODING] = "Unsupported transfer coding",
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

void
SocketHTTP1_config_defaults (SocketHTTP1_Config *config)
{
  assert (config);

  config->max_request_line = SOCKETHTTP1_MAX_REQUEST_LINE;
  config->max_header_name = SOCKETHTTP1_MAX_HEADER_NAME;
  config->max_header_value = SOCKETHTTP1_MAX_HEADER_VALUE;
  config->max_decompressed_size = SOCKET_SECURITY_MAX_BODY_SIZE;
  config->max_headers = SOCKETHTTP1_MAX_HEADERS;
  config->max_header_size = SOCKETHTTP1_MAX_HEADER_SIZE;
  config->max_chunk_size = SOCKETHTTP1_MAX_CHUNK_SIZE;
  config->max_chunk_ext = SOCKETHTTP1_MAX_CHUNK_EXT;
  config->max_trailer_size = SOCKETHTTP1_MAX_TRAILER_SIZE;
  config->max_header_line = SOCKETHTTP1_MAX_HEADER_LINE;
  config->trailer_entry_overhead = SOCKETHTTP1_TRAILER_ENTRY_OVERHEAD;
  config->allow_obs_fold = 0;
  config->strict_mode = 1;
}

static int
init_token_buffers (SocketHTTP1_Parser_T parser)
{
  if (http1_tokenbuf_init (
          &parser->method_buf, parser->arena, HTTP1_DEFAULT_METHOD_BUF_SIZE)
          < 0
      || http1_tokenbuf_init (
             &parser->uri_buf, parser->arena, HTTP1_DEFAULT_URI_BUF_SIZE)
             < 0
      || http1_tokenbuf_init (
             &parser->reason_buf, parser->arena, HTTP1_DEFAULT_REASON_BUF_SIZE)
             < 0
      || http1_tokenbuf_init (&parser->name_buf,
                              parser->arena,
                              HTTP1_DEFAULT_HEADER_NAME_BUF_SIZE)
             < 0
      || http1_tokenbuf_init (&parser->value_buf,
                              parser->arena,
                              HTTP1_DEFAULT_HEADER_VALUE_BUF_SIZE)
             < 0)
    {
      return -1;
    }
  return 0;
}

static void
reset_token_buffers (SocketHTTP1_Parser_T parser)
{
  http1_tokenbuf_reset (&parser->method_buf);
  http1_tokenbuf_reset (&parser->uri_buf);
  http1_tokenbuf_reset (&parser->reason_buf);
  http1_tokenbuf_reset (&parser->name_buf);
  http1_tokenbuf_reset (&parser->value_buf);
}

static void
reset_body_tracking (SocketHTTP1_Parser_T parser)
{
  parser->body_mode = HTTP1_BODY_NONE;
  parser->content_length = -1;
  parser->body_remaining = -1;
  parser->body_complete = 0;
  parser->body_read = 0;
  parser->chunk_size = 0;
  parser->chunk_remaining = 0;
}

SocketHTTP1_Parser_T
SocketHTTP1_Parser_new (SocketHTTP1_ParseMode mode,
                        const SocketHTTP1_Config *config,
                        Arena_T arena)
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
  parser->trailer_count = 0;
  parser->total_trailer_size = 0;
  parser->line_length = 0;
  parser->header_line_length = 0;

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

static int64_t
parse_cl_value (const char *str, size_t len)
{
  const char *p = str;
  size_t i = 0;
  int64_t value = 0;

  if (len == 0)
    len = strlen (str);
  if (len == 0)
    return -1;

  /* Skip leading OWS */
  while (i < len && http1_is_ows (p[i]))
    i++;
  if (i == len)
    return -1;

  /* Digits (no sign for CL) */
  while (i < len && http1_is_digit (p[i]))
    {
      int digit = p[i] - '0';
      if (value > (INT64_MAX - digit) / HTTP1_DECIMAL_BASE)
        return -1;
      value = value * HTTP1_DECIMAL_BASE + digit;
      i++;
    }

  /* Trailing OWS only */
  while (i < len && http1_is_ows (p[i]))
    i++;
  if (i < len)
    return -1; /* Garbage */

  return value;
}

static int
cl_validator (const char *name,
              size_t name_len,
              const char *value,
              size_t value_len,
              void *userdata)
{
  int64_t *expected = (int64_t *)userdata;

  if (!sockethttp_name_equal (name, name_len, "Content-Length", 14))
    return 0; /* Continue */

  int64_t this_val = parse_cl_value (value, value_len);
  if (this_val < 0 || this_val != *expected)
    return -1; /* Error */

  return 0;
}

/* Parse and validate Content-Length (RFC 9112 Section 6.3)
 * Returns: value on success, -1 on error, -2 if not present */
static int64_t
parse_content_length (SocketHTTP_Headers_T headers)
{
  if (!headers)
    return -1;

  const char *first_cl = SocketHTTP_Headers_get_n (
      headers, "Content-Length", STRLEN_LIT ("Content-Length"));
  if (!first_cl)
    return -2; /* Not present */

  size_t first_len = strlen (first_cl);
  int64_t cl_val = parse_cl_value (first_cl, first_len);
  if (cl_val < 0)
    return -1;

  /* Validate all CL headers match (RFC 9112 Section 6.3 strict) */
  int err = SocketHTTP_Headers_iterate (headers, cl_validator, &cl_val);
  if (err != 0)
    return -1; /* Mismatch or invalid */

  return cl_val;
}

/* HTTP/1.1 token delimiter predicate (space, tab, comma per RFC 9110) */
static inline int
http1_is_token_delimiter (char c)
{
  return c == ' ' || c == '\t' || c == ',';
}

static const char *
http1_skip_token_delimiters (const char *p)
{
  while (http1_is_token_delimiter (*p))
    p++;
  return p;
}

static size_t
http1_extract_token_bounds (const char *start, const char **end)
{
  const char *p = start;
  while (*p && !http1_is_token_delimiter (*p))
    p++;
  *end = p;
  return (size_t)(p - start);
}

static int
http1_contains_token (const char *value, const char *token)
{
  size_t tlen = strlen (token);
  if (tlen == 0)
    return 0;

  const char *p = value;
  while (*p)
    {
      p = http1_skip_token_delimiters (p);
      if (*p == '\0')
        break;

      const char *tok_end;
      size_t tok_len = http1_extract_token_bounds (p, &tok_end);

      if (sockethttp_name_equal (p, tok_len, token, tlen))
        return 1;

      p = tok_end;
    }

  return 0;
}

/* Validate chunked is last transfer coding per RFC 9112 */
static int
te_chunked_is_last (const char *te_value)
{
  /* Find "chunked" token */
  const char *chunked = strcasestr (te_value, "chunked");
  if (!chunked)
    return 1; /* No chunked - valid */

  /* Check nothing follows "chunked" except whitespace/comma */
  const char *after = chunked + STRLEN_LIT ("chunked");
  while (*after)
    {
      if (*after == ',')
        {
          /* Another coding follows - chunked is not last */
          const char *next = after + 1;
          while (*next == ' ' || *next == '\t')
            next++;
          if (*next && *next != '\0')
            return 0; /* Another token follows */
        }
      after++;
    }
  return 1;
}

static int
has_chunked_encoding (SocketHTTP_Headers_T headers)
{
  if (!headers)
    return 0;

  const char *te_values[SOCKETHTTP_MAX_HEADERS];
  size_t count = SocketHTTP_Headers_get_all_n (headers,
                                               "Transfer-Encoding",
                                               STRLEN_LIT ("Transfer-Encoding"),
                                               te_values,
                                               SOCKETHTTP_MAX_HEADERS);

  for (size_t i = 0; i < count; i++)
    {
      if (http1_contains_token (te_values[i], "chunked"))
        return 1;
    }

  return 0;
}

/* Check for unsupported transfer codings */
static int
has_other_transfer_coding (SocketHTTP_Headers_T headers)
{
  static const char *unsupported[]
      = { "gzip", "x-gzip", "compress", "deflate", "identity", NULL };
  if (!headers)
    return 0;

  const char *te_values[SOCKETHTTP_MAX_HEADERS];
  size_t count = SocketHTTP_Headers_get_all_n (headers,
                                               "Transfer-Encoding",
                                               STRLEN_LIT ("Transfer-Encoding"),
                                               te_values,
                                               SOCKETHTTP_MAX_HEADERS);

  for (size_t i = 0; i < count; i++)
    {
      for (const char **u = unsupported; *u; u++)
        {
          if (http1_contains_token (te_values[i], *u))
            return 1;
        }
    }

  return 0;
}

/* Validate chunked is last in all Transfer-Encoding headers */
static int
validate_chunked_is_last (SocketHTTP_Headers_T headers)
{
  const char *te_values[SOCKETHTTP_MAX_HEADERS];
  size_t count = SocketHTTP_Headers_get_all_n (headers,
                                               "Transfer-Encoding",
                                               STRLEN_LIT ("Transfer-Encoding"),
                                               te_values,
                                               SOCKETHTTP_MAX_HEADERS);

  for (size_t i = 0; i < count; i++)
    {
      if (!te_chunked_is_last (te_values[i]))
        return 0;
    }

  return 1;
}

static void
set_body_mode_chunked (SocketHTTP1_Parser_T parser)
{
  parser->body_mode = HTTP1_BODY_CHUNKED;
  parser->content_length = -1;
  parser->body_remaining = -1;
}

static void
set_body_mode_until_close (SocketHTTP1_Parser_T parser)
{
  parser->body_mode = HTTP1_BODY_UNTIL_CLOSE;
  parser->content_length = -1;
  parser->body_remaining = -1;
}

static void
set_body_mode_content_length (SocketHTTP1_Parser_T parser, int64_t length)
{
  parser->body_mode = HTTP1_BODY_CONTENT_LENGTH;
  parser->content_length = length;
  parser->body_remaining = length;

  if (length == 0)
    parser->body_complete = 1;
}

static void
set_body_mode_none (SocketHTTP1_Parser_T parser)
{
  parser->body_mode = HTTP1_BODY_NONE;
  parser->content_length = -1;
  parser->body_remaining = 0;
  parser->body_complete = 1;
}

static SocketHTTP1_Result
determine_body_mode (SocketHTTP1_Parser_T parser)
{
  int has_te;
  int64_t cl_value;
  int has_cl;

  has_te = SocketHTTP_Headers_has_n (
      parser->headers, "Transfer-Encoding", STRLEN_LIT ("Transfer-Encoding"));
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

  /* Transfer-Encoding takes precedence over Content-Length, with strict
   * validation */
  if (has_te)
    {
      /* Early return: no chunked encoding */
      if (!has_chunked_encoding (parser->headers))
        {
          if (parser->config.strict_mode)
            return HTTP1_ERROR_UNSUPPORTED_TRANSFER_CODING;
          set_body_mode_until_close (parser);
          return HTTP1_OK;
        }

      /* Early return: unsupported transfer codings in strict mode */
      if (parser->config.strict_mode
          && has_other_transfer_coding (parser->headers))
        return HTTP1_ERROR_UNSUPPORTED_TRANSFER_CODING;

      /* Early return: chunked not last per RFC 9112 */
      if (!validate_chunked_is_last (parser->headers))
        return HTTP1_ERROR_UNSUPPORTED_TRANSFER_CODING;

      set_body_mode_chunked (parser);
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

static int
determine_keepalive (SocketHTTP_Version version,
                     const SocketHTTP_Headers_T headers)
{
  if (version == HTTP_VERSION_1_1)
    {
      /* HTTP/1.1: keep-alive by default unless "Connection: close" */
      return !SocketHTTP_Headers_contains_n (headers,
                                             "Connection",
                                             STRLEN_LIT ("Connection"),
                                             "close",
                                             STRLEN_LIT ("close"));
    }

  /* HTTP/1.0: close by default unless "Connection: keep-alive" */
  return SocketHTTP_Headers_contains_n (headers,
                                        "Connection",
                                        STRLEN_LIT ("Connection"),
                                        "keep-alive",
                                        STRLEN_LIT ("keep-alive"));
}

static void
check_upgrade (SocketHTTP1_Parser_T parser)
{
  if (SocketHTTP_Headers_has_n (
          parser->headers, "Upgrade", STRLEN_LIT ("Upgrade")))
    {
      parser->is_upgrade = 1;
      parser->upgrade_protocol = SocketHTTP_Headers_get_n (
          parser->headers, "Upgrade", STRLEN_LIT ("Upgrade"));
    }
}

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
  version = map_http_version (parser->version_major, parser->version_minor);
  req->version = version;

  /*
   * Null-terminate URI buffer if not already done.
   * This handles HTTP/0.9 simple requests where bare LF transitions
   * directly from URI state to HEADER_START without URI_END action.
   */
  if (!http1_tokenbuf_terminate (
          &parser->uri_buf, parser->arena, parser->config.max_request_line))
    return HTTP1_ERROR_LINE_TOO_LONG;

  /* Set request target (path) - now null-terminated */
  req->path = parser->uri_buf.data;

  /* Validate URI syntax for security (basic format, encoding) */
  SocketHTTP_URI uri_temp;
  SocketHTTP_URIResult uri_res = SocketHTTP_URI_parse (
      req->path, parser->uri_buf.len, &uri_temp, parser->arena);
  if (uri_res != URI_PARSE_OK)
    return HTTP1_ERROR_INVALID_URI;

  /* Extract authority from Host header */
  req->authority
      = SocketHTTP_Headers_get_n (parser->headers, "Host", STRLEN_LIT ("Host"));

  /* Set headers */
  req->headers = parser->headers;

  result = finalize_common (parser, version);
  if (result != HTTP1_OK)
    return result;

  req->has_body = (parser->body_mode != HTTP1_BODY_NONE);
  req->content_length = parser->content_length;

  /* Check for Expect: 100-continue */
  if (SocketHTTP_Headers_contains_n (parser->headers,
                                     "Expect",
                                     STRLEN_LIT ("Expect"),
                                     "100-continue",
                                     STRLEN_LIT ("100-continue")))
    parser->expects_continue = 1;

  return HTTP1_OK;
}

static SocketHTTP1_Result
finalize_response (SocketHTTP1_Parser_T parser)
{
  SocketHTTP_Response *resp = &parser->message.response;
  SocketHTTP1_Result result;
  SocketHTTP_Version version;

  /* Set version */
  version = map_http_version (parser->version_major, parser->version_minor);
  resp->version = version;

  /*
   * Null-terminate reason buffer if not already done.
   * This handles bare LF line endings where REASON state transitions
   * directly to HEADER_START without REASON_END action.
   * Note: reason phrase is optional and may be empty.
   */
  if (!http1_tokenbuf_terminate (
          &parser->reason_buf, parser->arena, parser->config.max_request_line))
    return HTTP1_ERROR_LINE_TOO_LONG;

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

static void
set_error (SocketHTTP1_Parser_T parser, SocketHTTP1_Result error)
{
  parser->state = HTTP1_STATE_ERROR;
  parser->internal_state = HTTP1_PS_ERROR;
  parser->error = error;
}

#define RETURN_PARSE_ERROR(parser, err, p, data, consumed) \
  do                                                       \
    {                                                      \
      set_error ((parser), (err));                         \
      *(consumed) = (size_t)((p) - (data));                \
      return (parser)->error;                              \
    }                                                      \
  while (0)

static SocketHTTP1_Result
add_current_header (SocketHTTP1_Parser_T parser)
{
  char *name;
  char *value;
  size_t name_len;
  size_t value_len;

  /* Capture lengths before terminate modifies buffer */
  name_len = parser->name_buf.len;
  value_len = parser->value_buf.len;

  name = http1_tokenbuf_terminate (
      &parser->name_buf, parser->arena, parser->config.max_header_name);
  value = http1_tokenbuf_terminate (
      &parser->value_buf, parser->arena, parser->config.max_header_value);

  if (!name || !value)
    return HTTP1_ERROR_HEADER_TOO_LARGE;

  if (parser->header_count >= parser->config.max_headers)
    return HTTP1_ERROR_TOO_MANY_HEADERS;

  parser->total_header_size += name_len + value_len + HTTP1_HEADER_OVERHEAD;
  if (parser->total_header_size > parser->config.max_header_size)
    return HTTP1_ERROR_HEADER_TOO_LARGE;

  /* Use zero-copy: store pointers directly into arena buffer, no second copy */
  if (SocketHTTP_Headers_add_ref (
          parser->headers, name, name_len, value, value_len)
      < 0)
    return HTTP1_ERROR_INVALID_HEADER_VALUE;

  parser->header_count++;

  /* Release buffer ownership - data stays in arena for header reference */
  http1_tokenbuf_release (&parser->name_buf);
  http1_tokenbuf_release (&parser->value_buf);

  return HTTP1_OK;
}

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

static SocketHTTP1_Result
handle_store_action (SocketHTTP1_Parser_T parser,
                     uint8_t action,
                     char c,
                     const char *p,
                     const char *data,
                     size_t *consumed)
{
  int ret;

  switch (action)
    {
    case HTTP1_ACT_STORE_METHOD:
      ret = http1_tokenbuf_append (
          &parser->method_buf, parser->arena, c, SOCKETHTTP1_MAX_METHOD_LEN);
      if (ret < 0)
        RETURN_PARSE_ERROR (
            parser, HTTP1_ERROR_INVALID_METHOD, p, data, consumed);
      break;

    case HTTP1_ACT_STORE_URI:
      ret = http1_tokenbuf_append (
          &parser->uri_buf, parser->arena, c, parser->config.max_request_line);
      if (ret < 0)
        RETURN_PARSE_ERROR (
            parser, HTTP1_ERROR_LINE_TOO_LONG, p, data, consumed);
      break;

    case HTTP1_ACT_STORE_REASON:
      ret = http1_tokenbuf_append (&parser->reason_buf,
                                   parser->arena,
                                   c,
                                   parser->config.max_request_line);
      if (ret < 0)
        RETURN_PARSE_ERROR (
            parser, HTTP1_ERROR_LINE_TOO_LONG, p, data, consumed);
      break;

    case HTTP1_ACT_STORE_NAME:
      ret = http1_tokenbuf_append (
          &parser->name_buf, parser->arena, c, parser->config.max_header_name);
      if (ret < 0)
        RETURN_PARSE_ERROR (
            parser, HTTP1_ERROR_INVALID_HEADER_NAME, p, data, consumed);
      break;

    case HTTP1_ACT_STORE_VALUE:
      ret = http1_tokenbuf_append (&parser->value_buf,
                                   parser->arena,
                                   c,
                                   parser->config.max_header_value);
      if (ret < 0)
        RETURN_PARSE_ERROR (
            parser, HTTP1_ERROR_HEADER_TOO_LARGE, p, data, consumed);
      break;

    default:
      break;
    }

  return HTTP1_OK;
}

static SocketHTTP1_Result
handle_method_end (SocketHTTP1_Parser_T parser,
                   const char *p,
                   const char *data,
                   size_t *consumed)
{
  if (parser->method_buf.len == 0)
    RETURN_PARSE_ERROR (parser, HTTP1_ERROR_INVALID_METHOD, p, data, consumed);

  if (!http1_tokenbuf_terminate (
          &parser->method_buf, parser->arena, parser->config.max_request_line))
    RETURN_PARSE_ERROR (parser, HTTP1_ERROR_LINE_TOO_LONG, p, data, consumed);

  return HTTP1_OK;
}

static SocketHTTP1_Result
handle_uri_end (SocketHTTP1_Parser_T parser,
                const char *p,
                const char *data,
                size_t *consumed)
{
  if (!http1_tokenbuf_terminate (
          &parser->uri_buf, parser->arena, parser->config.max_request_line))
    RETURN_PARSE_ERROR (parser, HTTP1_ERROR_LINE_TOO_LONG, p, data, consumed);

  return HTTP1_OK;
}

static SocketHTTP1_Result
handle_version_digit (SocketHTTP1_Parser_T parser,
                      uint8_t action,
                      char c,
                      const char *p,
                      const char *data,
                      size_t *consumed)
{
  if (action == HTTP1_ACT_VERSION_MAJ)
    {
      parser->version_major = parser->version_major * 10 + (c - '0');
      if (parser->version_major > HTTP1_MAX_VERSION_DIGIT)
        RETURN_PARSE_ERROR (
            parser, HTTP1_ERROR_INVALID_VERSION, p, data, consumed);
    }
  else
    {
      parser->version_minor = parser->version_minor * 10 + (c - '0');
      if (parser->version_minor > HTTP1_MAX_VERSION_DIGIT)
        RETURN_PARSE_ERROR (
            parser, HTTP1_ERROR_INVALID_VERSION, p, data, consumed);
    }

  return HTTP1_OK;
}

static SocketHTTP1_Result
handle_status_digit (SocketHTTP1_Parser_T parser,
                     char c,
                     const char *p,
                     const char *data,
                     size_t *consumed)
{
  parser->status_code = parser->status_code * 10 + (c - '0');

  if (parser->status_code > HTTP1_MAX_STATUS_CODE)
    RETURN_PARSE_ERROR (parser, HTTP1_ERROR_INVALID_STATUS, p, data, consumed);

  return HTTP1_OK;
}

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

static inline int
in_header_state (HTTP1_InternalState state)
{
  return state >= HTTP1_PS_HEADER_START && state <= HTTP1_PS_HEADERS_END_LF;
}

static inline SocketHTTP1_Result
handle_body_state_exit (SocketHTTP1_Parser_T parser,
                        HTTP1_InternalState state,
                        size_t consumed_bytes,
                        size_t *consumed)
{
  parser->internal_state = state;
  *consumed = consumed_bytes;
  if (state == HTTP1_PS_COMPLETE)
    return HTTP1_OK;
  if (state == HTTP1_PS_ERROR)
    return parser->error;
  /* Body states handled by read_body function */
  return HTTP1_OK;
}

static SocketHTTP1_Result
handle_dfa_action (SocketHTTP1_Parser_T parser,
                   uint8_t action,
                   uint8_t c,
                   const char *p,
                   const char *data,
                   size_t *consumed,
                   HTTP1_InternalState current_state,
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
      result
          = handle_version_digit (parser, action, (char)c, p, data, consumed);
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

/* Fast path: batch process header values until CR
 * Returns pointer to first non-value byte (CR or invalid), or end if all valid
 */
static inline const char *
scan_header_value (const char *p, const char *end)
{
  /* Find CR - marks end of header value */
  const char *cr = memchr (p, '\r', (size_t)(end - p));
  if (cr)
    {
      /* Validate all bytes before CR are valid field content */
      for (const char *v = p; v < cr; v++)
        {
          unsigned char c = (unsigned char)*v;
          /* field-content = field-vchar [ 1*( SP / HTAB / field-vchar ) ]
           * field-vchar = VCHAR / obs-text
           * VCHAR = 0x21-0x7E, obs-text = 0x80-0xFF, SP = 0x20, HTAB = 0x09 */
          if (c < 0x20 && c != 0x09)
            return v; /* Invalid control character */
          if (c == 0x7F)
            return v; /* DEL is invalid */
        }
      return cr;
    }
  /* No CR found - validate all remaining bytes */
  for (const char *v = p; v < end; v++)
    {
      unsigned char c = (unsigned char)*v;
      if (c < 0x20 && c != 0x09)
        return v;
      if (c == 0x7F)
        return v;
    }
  return end;
}

/* Fast path: batch process header names until colon
 * Returns pointer to first non-tchar byte (colon or invalid), or end
 */
static inline const char *
scan_header_name (const char *p, const char *end)
{
  while (p < end)
    {
      unsigned char c = (unsigned char)*p;
      if (c == ':')
        return p;
      /* tchar validation via lookup table */
      if (!SOCKETHTTP_IS_TCHAR (c))
        return p;
      p++;
    }
  return end;
}

/* Process a chunk of header value data (optimization helper)
 * Returns 0 on success, -1 on error (sets parser error state)
 */
static inline int
process_header_value_chunk (SocketHTTP1_Parser_T parser,
                             const char *chunk,
                             size_t chunk_len)
{
  /* Guard: check line length limit */
  if (parser->header_line_length + chunk_len > parser->config.max_header_line)
    {
      set_error (parser, HTTP1_ERROR_HEADER_TOO_LARGE);
      return -1;
    }

  /* Guard: batch append to value buffer */
  if (http1_tokenbuf_append_block (&parser->value_buf,
                                   parser->arena,
                                   chunk,
                                   chunk_len,
                                   parser->config.max_header_value)
      < 0)
    {
      set_error (parser, HTTP1_ERROR_HEADER_TOO_LARGE);
      return -1;
    }

  /* Update counters */
  parser->line_length += chunk_len;
  parser->header_line_length += chunk_len;
  return 0;
}

/* Process a chunk of header name data (optimization helper)
 * Returns 0 on success, -1 on error (sets parser error state)
 */
static inline int
process_header_name_chunk (SocketHTTP1_Parser_T parser,
                            const char *chunk,
                            size_t chunk_len)
{
  /* Guard: check line length limit */
  if (parser->header_line_length + chunk_len > parser->config.max_header_line)
    {
      set_error (parser, HTTP1_ERROR_HEADER_TOO_LARGE);
      return -1;
    }

  /* Guard: batch append to name buffer */
  if (http1_tokenbuf_append_block (&parser->name_buf,
                                   parser->arena,
                                   chunk,
                                   chunk_len,
                                   parser->config.max_header_name)
      < 0)
    {
      set_error (parser, HTTP1_ERROR_INVALID_HEADER_NAME);
      return -1;
    }

  /* Update counters */
  parser->line_length += chunk_len;
  parser->header_line_length += chunk_len;
  return 0;
}

static SocketHTTP1_Result
parse_headers_loop (SocketHTTP1_Parser_T parser,
                    const char *data,
                    size_t len,
                    size_t *consumed,
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
      /* Handle body/trailer states outside the table-driven loop */
      if (state >= HTTP1_PS_BODY_IDENTITY)
        return handle_body_state_exit (
            parser, state, (size_t)(p - data), consumed);

      /*
       * OPTIMIZATION 1: Batch processing for header values
       * Header values are typically 10-100+ bytes. Instead of per-byte
       * processing, scan ahead to find CR and copy the entire block.
       */
      if (state == HTTP1_PS_HEADER_VALUE)
        {
          const char *value_end = scan_header_value (p, end);
          size_t chunk_len = (size_t)(value_end - p);

          if (chunk_len > 0)
            {
              /* Process chunk with guard clauses */
              if (process_header_value_chunk (parser, p, chunk_len) < 0)
                {
                  *consumed = (size_t)(p - data);
                  return parser->error;
                }

              p = value_end;
              continue; /* Next iteration will handle CR or invalid char */
            }
          /* Fall through to normal byte processing for CR/invalid */
        }

      /*
       * OPTIMIZATION 2: Batch processing for header names
       */
      if (state == HTTP1_PS_HEADER_NAME)
        {
          const char *name_end = scan_header_name (p, end);
          size_t chunk_len = (size_t)(name_end - p);

          if (chunk_len > 0)
            {
              /* Process chunk with guard clauses */
              if (process_header_name_chunk (parser, p, chunk_len) < 0)
                {
                  *consumed = (size_t)(p - data);
                  return parser->error;
                }

              p = name_end;
              continue;
            }
        }

      /* Standard byte-by-byte processing for state transitions */
      {
        uint8_t c = (uint8_t)*p;
        uint8_t cc = http1_char_class[c];
        HTTP1_InternalState next_state;
        uint8_t action;

        next_state = (HTTP1_InternalState)state_table[state][cc];
        action = action_table[state][cc];

        /*
         * OPTIMIZATION 3: Inline trivial actions
         * Only call handle_dfa_action for non-trivial cases.
         */
        if (action == HTTP1_ACT_NONE)
          {
            /* Just transition, no side effect - skip function call */
          }
        else if (action == HTTP1_ACT_STORE_VALUE)
          {
            /* Inline single-byte value append (for bytes after batch) */
            if (http1_tokenbuf_append (&parser->value_buf,
                                       parser->arena,
                                       (char)c,
                                       parser->config.max_header_value)
                < 0)
              {
                set_error (parser, HTTP1_ERROR_HEADER_TOO_LARGE);
                *consumed = (size_t)(p - data);
                return parser->error;
              }
          }
        else if (action == HTTP1_ACT_STORE_NAME)
          {
            /* Inline single-byte name append */
            if (http1_tokenbuf_append (&parser->name_buf,
                                       parser->arena,
                                       (char)c,
                                       parser->config.max_header_name)
                < 0)
              {
                set_error (parser, HTTP1_ERROR_INVALID_HEADER_NAME);
                *consumed = (size_t)(p - data);
                return parser->error;
              }
          }
        else
          {
            /* Non-trivial action - use full handler */
            result = handle_dfa_action (
                parser, action, c, p, data, consumed, state, &next_state);
            if (result != HTTP1_OK)
              return result;
          }

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
        if (in_header_state (state))
          parser->header_line_length++;

        /* Check line length limits */
        if (in_header_state (state)
            && parser->header_line_length > parser->config.max_header_line)
          {
            set_error (parser, HTTP1_ERROR_HEADER_TOO_LARGE);
            *consumed = (size_t)(p - data);
            return parser->error;
          }
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
            parser->header_line_length = 0;
            parser->state = HTTP1_STATE_HEADERS;
          }

        p++;

        /* Handle transition to body/complete/error states */
        if (state >= HTTP1_PS_BODY_IDENTITY)
          return handle_body_state_exit (
              parser, state, (size_t)(p - data), consumed);
      }
    }

  parser->internal_state = state;
  *consumed = len;
  return HTTP1_INCOMPLETE;
}

SocketHTTP1_Result
SocketHTTP1_Parser_execute (SocketHTTP1_Parser_T parser,
                            const char *data,
                            size_t len,
                            size_t *consumed)
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

  return parse_headers_loop (
      parser, data, len, consumed, state_table, action_table);
}

/* Undefine internal macro */
#undef RETURN_PARSE_ERROR

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
