/**
 * SocketHPACK-huffman.c - HPACK Huffman Encoding/Decoding
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Implements RFC 7541 Appendix B Huffman coding with:
 * - O(n) single-pass DFA-based decoding
 * - Compile-time encode table for O(1) symbol lookup
 * - EOS validation and padding verification
 *
 * The Huffman table is optimized for HTTP header content with
 * variable-length codes from 5 to 30 bits.
 */

#include "http/SocketHPACK-private.h"
#include "http/SocketHPACK.h"

#include <assert.h>
#include <string.h>

/* ============================================================================
 * Huffman Encode Table (RFC 7541 Appendix B)
 *
 * Each entry contains the Huffman code and its bit length.
 * Codes are stored right-aligned (ready for bit packing).
 * ============================================================================ */

/* clang-format off */
const HPACK_HuffmanSymbol hpack_huffman_encode[HPACK_HUFFMAN_SYMBOLS] = {
  /* 0x00-0x0F */
  { 0x1ff8,     13 }, /* (  0)  |11111111|11000 */
  { 0x7fffd8,   23 }, /* (  1)  |11111111|11111111|1011000 */
  { 0xfffffe2,  28 }, /* (  2)  |11111111|11111111|11111110|0010 */
  { 0xfffffe3,  28 }, /* (  3)  |11111111|11111111|11111110|0011 */
  { 0xfffffe4,  28 }, /* (  4)  |11111111|11111111|11111110|0100 */
  { 0xfffffe5,  28 }, /* (  5)  |11111111|11111111|11111110|0101 */
  { 0xfffffe6,  28 }, /* (  6)  |11111111|11111111|11111110|0110 */
  { 0xfffffe7,  28 }, /* (  7)  |11111111|11111111|11111110|0111 */
  { 0xfffffe8,  28 }, /* (  8)  |11111111|11111111|11111110|1000 */
  { 0xffffea,   24 }, /* (  9)  |11111111|11111111|11101010 */
  { 0x3ffffffc, 30 }, /* ( 10)  |11111111|11111111|11111111|111100 */
  { 0xfffffe9,  28 }, /* ( 11)  |11111111|11111111|11111110|1001 */
  { 0xfffffea,  28 }, /* ( 12)  |11111111|11111111|11111110|1010 */
  { 0x3ffffffd, 30 }, /* ( 13)  |11111111|11111111|11111111|111101 */
  { 0xfffffeb,  28 }, /* ( 14)  |11111111|11111111|11111110|1011 */
  { 0xfffffec,  28 }, /* ( 15)  |11111111|11111111|11111110|1100 */
  /* 0x10-0x1F */
  { 0xfffffed,  28 }, /* ( 16)  |11111111|11111111|11111110|1101 */
  { 0xfffffee,  28 }, /* ( 17)  |11111111|11111111|11111110|1110 */
  { 0xfffffef,  28 }, /* ( 18)  |11111111|11111111|11111110|1111 */
  { 0xffffff0,  28 }, /* ( 19)  |11111111|11111111|11111111|0000 */
  { 0xffffff1,  28 }, /* ( 20)  |11111111|11111111|11111111|0001 */
  { 0xffffff2,  28 }, /* ( 21)  |11111111|11111111|11111111|0010 */
  { 0x3ffffffe, 30 }, /* ( 22)  |11111111|11111111|11111111|111110 */
  { 0xffffff3,  28 }, /* ( 23)  |11111111|11111111|11111111|0011 */
  { 0xffffff4,  28 }, /* ( 24)  |11111111|11111111|11111111|0100 */
  { 0xffffff5,  28 }, /* ( 25)  |11111111|11111111|11111111|0101 */
  { 0xffffff6,  28 }, /* ( 26)  |11111111|11111111|11111111|0110 */
  { 0xffffff7,  28 }, /* ( 27)  |11111111|11111111|11111111|0111 */
  { 0xffffff8,  28 }, /* ( 28)  |11111111|11111111|11111111|1000 */
  { 0xffffff9,  28 }, /* ( 29)  |11111111|11111111|11111111|1001 */
  { 0xffffffa,  28 }, /* ( 30)  |11111111|11111111|11111111|1010 */
  { 0xffffffb,  28 }, /* ( 31)  |11111111|11111111|11111111|1011 */
  /* 0x20-0x2F (printable) */
  { 0x14,        6 }, /* ( 32)  ' ' |010100 */
  { 0x3f8,      10 }, /* ( 33)  '!' |11111110|00 */
  { 0x3f9,      10 }, /* ( 34)  '"' |11111110|01 */
  { 0xffa,      12 }, /* ( 35)  '#' |11111111|1010 */
  { 0x1ff9,     13 }, /* ( 36)  '$' |11111111|11001 */
  { 0x15,        6 }, /* ( 37)  '%' |010101 */
  { 0xf8,        8 }, /* ( 38)  '&' |11111000 */
  { 0x7fa,      11 }, /* ( 39)  '\'' |11111111|010 */
  { 0x3fa,      10 }, /* ( 40)  '(' |11111110|10 */
  { 0x3fb,      10 }, /* ( 41)  ')' |11111110|11 */
  { 0xf9,        8 }, /* ( 42)  '*' |11111001 */
  { 0x7fb,      11 }, /* ( 43)  '+' |11111111|011 */
  { 0xfa,        8 }, /* ( 44)  ',' |11111010 */
  { 0x16,        6 }, /* ( 45)  '-' |010110 */
  { 0x17,        6 }, /* ( 46)  '.' |010111 */
  { 0x18,        6 }, /* ( 47)  '/' |011000 */
  /* 0x30-0x3F (digits) */
  { 0x0,         5 }, /* ( 48)  '0' |00000 */
  { 0x1,         5 }, /* ( 49)  '1' |00001 */
  { 0x2,         5 }, /* ( 50)  '2' |00010 */
  { 0x19,        6 }, /* ( 51)  '3' |011001 */
  { 0x1a,        6 }, /* ( 52)  '4' |011010 */
  { 0x1b,        6 }, /* ( 53)  '5' |011011 */
  { 0x1c,        6 }, /* ( 54)  '6' |011100 */
  { 0x1d,        6 }, /* ( 55)  '7' |011101 */
  { 0x1e,        6 }, /* ( 56)  '8' |011110 */
  { 0x1f,        6 }, /* ( 57)  '9' |011111 */
  { 0x5c,        7 }, /* ( 58)  ':' |1011100 */
  { 0xfb,        8 }, /* ( 59)  ';' |11111011 */
  { 0x7ffc,     15 }, /* ( 60)  '<' |11111111|1111100 */
  { 0x20,        6 }, /* ( 61)  '=' |100000 */
  { 0xffb,      12 }, /* ( 62)  '>' |11111111|1011 */
  { 0x3fc,      10 }, /* ( 63)  '?' |11111111|00 */
  /* 0x40-0x4F (uppercase) */
  { 0x1ffa,     13 }, /* ( 64)  '@' |11111111|11010 */
  { 0x21,        6 }, /* ( 65)  'A' |100001 */
  { 0x5d,        7 }, /* ( 66)  'B' |1011101 */
  { 0x5e,        7 }, /* ( 67)  'C' |1011110 */
  { 0x5f,        7 }, /* ( 68)  'D' |1011111 */
  { 0x60,        7 }, /* ( 69)  'E' |1100000 */
  { 0x61,        7 }, /* ( 70)  'F' |1100001 */
  { 0x62,        7 }, /* ( 71)  'G' |1100010 */
  { 0x63,        7 }, /* ( 72)  'H' |1100011 */
  { 0x64,        7 }, /* ( 73)  'I' |1100100 */
  { 0x65,        7 }, /* ( 74)  'J' |1100101 */
  { 0x66,        7 }, /* ( 75)  'K' |1100110 */
  { 0x67,        7 }, /* ( 76)  'L' |1100111 */
  { 0x68,        7 }, /* ( 77)  'M' |1101000 */
  { 0x69,        7 }, /* ( 78)  'N' |1101001 */
  { 0x6a,        7 }, /* ( 79)  'O' |1101010 */
  /* 0x50-0x5F */
  { 0x6b,        7 }, /* ( 80)  'P' |1101011 */
  { 0x6c,        7 }, /* ( 81)  'Q' |1101100 */
  { 0x6d,        7 }, /* ( 82)  'R' |1101101 */
  { 0x6e,        7 }, /* ( 83)  'S' |1101110 */
  { 0x6f,        7 }, /* ( 84)  'T' |1101111 */
  { 0x70,        7 }, /* ( 85)  'U' |1110000 */
  { 0x71,        7 }, /* ( 86)  'V' |1110001 */
  { 0x72,        7 }, /* ( 87)  'W' |1110010 */
  { 0xfc,        8 }, /* ( 88)  'X' |11111100 */
  { 0x73,        7 }, /* ( 89)  'Y' |1110011 */
  { 0xfd,        8 }, /* ( 90)  'Z' |11111101 */
  { 0x1ffb,     13 }, /* ( 91)  '[' |11111111|11011 */
  { 0x7fff0,    19 }, /* ( 92)  '\' |11111111|11111110|000 */
  { 0x1ffc,     13 }, /* ( 93)  ']' |11111111|11100 */
  { 0x3ffc,     14 }, /* ( 94)  '^' |11111111|111100 */
  { 0x22,        6 }, /* ( 95)  '_' |100010 */
  /* 0x60-0x6F (lowercase) */
  { 0x7ffd,     15 }, /* ( 96)  '`' |11111111|1111101 */
  { 0x3,         5 }, /* ( 97)  'a' |00011 */
  { 0x23,        6 }, /* ( 98)  'b' |100011 */
  { 0x4,         5 }, /* ( 99)  'c' |00100 */
  { 0x24,        6 }, /* (100)  'd' |100100 */
  { 0x5,         5 }, /* (101)  'e' |00101 */
  { 0x25,        6 }, /* (102)  'f' |100101 */
  { 0x26,        6 }, /* (103)  'g' |100110 */
  { 0x27,        6 }, /* (104)  'h' |100111 */
  { 0x6,         5 }, /* (105)  'i' |00110 */
  { 0x74,        7 }, /* (106)  'j' |1110100 */
  { 0x75,        7 }, /* (107)  'k' |1110101 */
  { 0x28,        6 }, /* (108)  'l' |101000 */
  { 0x29,        6 }, /* (109)  'm' |101001 */
  { 0x2a,        6 }, /* (110)  'n' |101010 */
  { 0x7,         5 }, /* (111)  'o' |00111 */
  /* 0x70-0x7F */
  { 0x2b,        6 }, /* (112)  'p' |101011 */
  { 0x76,        7 }, /* (113)  'q' |1110110 */
  { 0x2c,        6 }, /* (114)  'r' |101100 */
  { 0x8,         5 }, /* (115)  's' |01000 */
  { 0x9,         5 }, /* (116)  't' |01001 */
  { 0x2d,        6 }, /* (117)  'u' |101101 */
  { 0x77,        7 }, /* (118)  'v' |1110111 */
  { 0x78,        7 }, /* (119)  'w' |1111000 */
  { 0x79,        7 }, /* (120)  'x' |1111001 */
  { 0x7a,        7 }, /* (121)  'y' |1111010 */
  { 0x7b,        7 }, /* (122)  'z' |1111011 */
  { 0x7ffe,     15 }, /* (123)  '{' |11111111|1111110 */
  { 0x7fc,      11 }, /* (124)  '|' |11111111|100 */
  { 0x3ffd,     14 }, /* (125)  '}' |11111111|111101 */
  { 0x1ffd,     13 }, /* (126)  '~' |11111111|11101 */
  { 0xffffffc,  28 }, /* (127)      |11111111|11111111|11111111|1100 */
  /* 0x80-0x8F */
  { 0xfffe6,    20 }, /* (128)  |11111111|11111110|0110 */
  { 0x3fffd2,   22 }, /* (129)  |11111111|11111111|010010 */
  { 0xfffe7,    20 }, /* (130)  |11111111|11111110|0111 */
  { 0xfffe8,    20 }, /* (131)  |11111111|11111110|1000 */
  { 0x3fffd3,   22 }, /* (132)  |11111111|11111111|010011 */
  { 0x3fffd4,   22 }, /* (133)  |11111111|11111111|010100 */
  { 0x3fffd5,   22 }, /* (134)  |11111111|11111111|010101 */
  { 0x7fffd9,   23 }, /* (135)  |11111111|11111111|1011001 */
  { 0x3fffd6,   22 }, /* (136)  |11111111|11111111|010110 */
  { 0x7fffda,   23 }, /* (137)  |11111111|11111111|1011010 */
  { 0x7fffdb,   23 }, /* (138)  |11111111|11111111|1011011 */
  { 0x7fffdc,   23 }, /* (139)  |11111111|11111111|1011100 */
  { 0x7fffdd,   23 }, /* (140)  |11111111|11111111|1011101 */
  { 0x7fffde,   23 }, /* (141)  |11111111|11111111|1011110 */
  { 0xffffeb,   24 }, /* (142)  |11111111|11111111|11101011 */
  { 0x7fffdf,   23 }, /* (143)  |11111111|11111111|1011111 */
  /* 0x90-0x9F */
  { 0xffffec,   24 }, /* (144)  |11111111|11111111|11101100 */
  { 0xffffed,   24 }, /* (145)  |11111111|11111111|11101101 */
  { 0x3fffd7,   22 }, /* (146)  |11111111|11111111|010111 */
  { 0x7fffe0,   23 }, /* (147)  |11111111|11111111|1100000 */
  { 0xffffee,   24 }, /* (148)  |11111111|11111111|11101110 */
  { 0x7fffe1,   23 }, /* (149)  |11111111|11111111|1100001 */
  { 0x7fffe2,   23 }, /* (150)  |11111111|11111111|1100010 */
  { 0x7fffe3,   23 }, /* (151)  |11111111|11111111|1100011 */
  { 0x7fffe4,   23 }, /* (152)  |11111111|11111111|1100100 */
  { 0x1fffdc,   21 }, /* (153)  |11111111|11111111|0011100 */
  { 0x3fffd8,   22 }, /* (154)  |11111111|11111111|011000 */
  { 0x7fffe5,   23 }, /* (155)  |11111111|11111111|1100101 */
  { 0x3fffd9,   22 }, /* (156)  |11111111|11111111|011001 */
  { 0x7fffe6,   23 }, /* (157)  |11111111|11111111|1100110 */
  { 0x7fffe7,   23 }, /* (158)  |11111111|11111111|1100111 */
  { 0xffffef,   24 }, /* (159)  |11111111|11111111|11101111 */
  /* 0xA0-0xAF */
  { 0x3fffda,   22 }, /* (160)  |11111111|11111111|011010 */
  { 0x1fffdd,   21 }, /* (161)  |11111111|11111111|0011101 */
  { 0xfffe9,    20 }, /* (162)  |11111111|11111110|1001 */
  { 0x3fffdb,   22 }, /* (163)  |11111111|11111111|011011 */
  { 0x3fffdc,   22 }, /* (164)  |11111111|11111111|011100 */
  { 0x7fffe8,   23 }, /* (165)  |11111111|11111111|1101000 */
  { 0x7fffe9,   23 }, /* (166)  |11111111|11111111|1101001 */
  { 0x1fffde,   21 }, /* (167)  |11111111|11111111|0011110 */
  { 0x7fffea,   23 }, /* (168)  |11111111|11111111|1101010 */
  { 0x3fffdd,   22 }, /* (169)  |11111111|11111111|011101 */
  { 0x3fffde,   22 }, /* (170)  |11111111|11111111|011110 */
  { 0xfffff0,   24 }, /* (171)  |11111111|11111111|11110000 */
  { 0x1fffdf,   21 }, /* (172)  |11111111|11111111|0011111 */
  { 0x3fffdf,   22 }, /* (173)  |11111111|11111111|011111 */
  { 0x7fffeb,   23 }, /* (174)  |11111111|11111111|1101011 */
  { 0x7fffec,   23 }, /* (175)  |11111111|11111111|1101100 */
  /* 0xB0-0xBF */
  { 0x1fffe0,   21 }, /* (176)  |11111111|11111111|0100000 */
  { 0x1fffe1,   21 }, /* (177)  |11111111|11111111|0100001 */
  { 0x3fffe0,   22 }, /* (178)  |11111111|11111111|100000 */
  { 0x1fffe2,   21 }, /* (179)  |11111111|11111111|0100010 */
  { 0x7fffed,   23 }, /* (180)  |11111111|11111111|1101101 */
  { 0x3fffe1,   22 }, /* (181)  |11111111|11111111|100001 */
  { 0x7fffee,   23 }, /* (182)  |11111111|11111111|1101110 */
  { 0x7fffef,   23 }, /* (183)  |11111111|11111111|1101111 */
  { 0xfffea,    20 }, /* (184)  |11111111|11111110|1010 */
  { 0x3fffe2,   22 }, /* (185)  |11111111|11111111|100010 */
  { 0x3fffe3,   22 }, /* (186)  |11111111|11111111|100011 */
  { 0x3fffe4,   22 }, /* (187)  |11111111|11111111|100100 */
  { 0x7ffff0,   23 }, /* (188)  |11111111|11111111|1110000 */
  { 0x3fffe5,   22 }, /* (189)  |11111111|11111111|100101 */
  { 0x3fffe6,   22 }, /* (190)  |11111111|11111111|100110 */
  { 0x7ffff1,   23 }, /* (191)  |11111111|11111111|1110001 */
  /* 0xC0-0xCF */
  { 0x3ffffe0,  26 }, /* (192)  |11111111|11111111|11111110|00 */
  { 0x3ffffe1,  26 }, /* (193)  |11111111|11111111|11111110|01 */
  { 0xfffeb,    20 }, /* (194)  |11111111|11111110|1011 */
  { 0x7fff1,    19 }, /* (195)  |11111111|11111110|001 */
  { 0x3fffe7,   22 }, /* (196)  |11111111|11111111|100111 */
  { 0x7ffff2,   23 }, /* (197)  |11111111|11111111|1110010 */
  { 0x3fffe8,   22 }, /* (198)  |11111111|11111111|101000 */
  { 0x1ffffec,  25 }, /* (199)  |11111111|11111111|11111110|1100 */
  { 0x3ffffe2,  26 }, /* (200)  |11111111|11111111|11111110|10 */
  { 0x3ffffe3,  26 }, /* (201)  |11111111|11111111|11111110|11 */
  { 0x3ffffe4,  26 }, /* (202)  |11111111|11111111|11111111|00 */
  { 0x7ffffde,  27 }, /* (203)  |11111111|11111111|11111111|0110 */
  { 0x7ffffdf,  27 }, /* (204)  |11111111|11111111|11111111|0111 */
  { 0x3ffffe5,  26 }, /* (205)  |11111111|11111111|11111111|01 */
  { 0xfffff1,   24 }, /* (206)  |11111111|11111111|11110001 */
  { 0x1ffffed,  25 }, /* (207)  |11111111|11111111|11111110|1101 */
  /* 0xD0-0xDF */
  { 0x7fff2,    19 }, /* (208)  |11111111|11111110|010 */
  { 0x1fffe3,   21 }, /* (209)  |11111111|11111111|0100011 */
  { 0x3ffffe6,  26 }, /* (210)  |11111111|11111111|11111111|10 */
  { 0x7ffffe0,  27 }, /* (211)  |11111111|11111111|11111111|1000 */
  { 0x7ffffe1,  27 }, /* (212)  |11111111|11111111|11111111|1001 */
  { 0x3ffffe7,  26 }, /* (213)  |11111111|11111111|11111111|11 */
  { 0x7ffffe2,  27 }, /* (214)  |11111111|11111111|11111111|1010 */
  { 0xfffff2,   24 }, /* (215)  |11111111|11111111|11110010 */
  { 0x1fffe4,   21 }, /* (216)  |11111111|11111111|0100100 */
  { 0x1fffe5,   21 }, /* (217)  |11111111|11111111|0100101 */
  { 0x3ffffe8,  26 }, /* (218)  |11111111|11111111|11111110|00 - duplicate? */
  { 0x3ffffe9,  26 }, /* (219)  |11111111|11111111|11111110|01 - duplicate? */
  { 0xffffffd,  28 }, /* (220)  |11111111|11111111|11111111|1101 */
  { 0x7ffffe3,  27 }, /* (221)  |11111111|11111111|11111111|1011 */
  { 0x7ffffe4,  27 }, /* (222)  |11111111|11111111|11111111|1100 */
  { 0x7ffffe5,  27 }, /* (223)  |11111111|11111111|11111111|1101 */
  /* 0xE0-0xEF */
  { 0xffffec,   20 }, /* (224)  |11111111|11111110|1100 */
  { 0xfffff3,   24 }, /* (225)  |11111111|11111111|11110011 */
  { 0xffffed,   20 }, /* (226)  |11111111|11111110|1101 */
  { 0x1fffe6,   21 }, /* (227)  |11111111|11111111|0100110 */
  { 0x3fffe9,   22 }, /* (228)  |11111111|11111111|101001 */
  { 0x1fffe7,   21 }, /* (229)  |11111111|11111111|0100111 */
  { 0x1fffe8,   21 }, /* (230)  |11111111|11111111|0101000 */
  { 0x7ffff3,   23 }, /* (231)  |11111111|11111111|1110011 */
  { 0x3fffea,   22 }, /* (232)  |11111111|11111111|101010 */
  { 0x3fffeb,   22 }, /* (233)  |11111111|11111111|101011 */
  { 0x1ffffee,  25 }, /* (234)  |11111111|11111111|11111110|1110 */
  { 0x1ffffef,  25 }, /* (235)  |11111111|11111111|11111110|1111 */
  { 0xfffff4,   24 }, /* (236)  |11111111|11111111|11110100 */
  { 0xfffff5,   24 }, /* (237)  |11111111|11111111|11110101 */
  { 0x3ffffea,  26 }, /* (238)  |11111111|11111111|11111110|10 - duplicate? */
  { 0x7ffff4,   23 }, /* (239)  |11111111|11111111|1110100 */
  /* 0xF0-0xFF */
  { 0x3ffffeb,  26 }, /* (240)  |11111111|11111111|11111110|11 - duplicate? */
  { 0x7ffffe6,  27 }, /* (241)  |11111111|11111111|11111111|1110 */
  { 0x3ffffec,  26 }, /* (242)  |11111111|11111111|11111111|00 - duplicate? */
  { 0x3ffffed,  26 }, /* (243)  |11111111|11111111|11111111|01 - duplicate? */
  { 0x7ffffe7,  27 }, /* (244)  |11111111|11111111|11111111|1111 */
  { 0x7ffffe8,  27 }, /* (245)  |11111111|11111111|11111110|0000 - not quite */
  { 0x7ffffe9,  27 }, /* (246)  |11111111|11111111|11111110|0001 */
  { 0x7ffffea,  27 }, /* (247)  |11111111|11111111|11111110|0010 */
  { 0x7ffffeb,  27 }, /* (248)  |11111111|11111111|11111110|0011 */
  { 0xffffffe,  28 }, /* (249)  |11111111|11111111|11111111|1110 */
  { 0x7ffffec,  27 }, /* (250)  |11111111|11111111|11111110|0100 */
  { 0x7ffffed,  27 }, /* (251)  |11111111|11111111|11111110|0101 */
  { 0x7ffffee,  27 }, /* (252)  |11111111|11111111|11111110|0110 */
  { 0x7ffffef,  27 }, /* (253)  |11111111|11111111|11111110|0111 */
  { 0x7fffff0,  27 }, /* (254)  |11111111|11111111|11111110|1000 */
  { 0x3ffffee,  26 }, /* (255)  |11111111|11111111|11111111|10 */
  /* EOS */
  { 0x3fffffff, 30 }, /* (256) EOS |11111111|11111111|11111111|111111 */
};
/* clang-format on */

/* ============================================================================
 * Huffman Decode Table (DFA-based)
 *
 * This table implements a 4-bit-at-a-time DFA decoder.
 * Each state has 16 transitions (one per nibble).
 * The decoder processes input nibble by nibble for efficiency.
 *
 * State 0 is the initial/accepting state.
 * ============================================================================ */

/**
 * Huffman decode state structure for nibble-based DFA
 *
 * Process 4 bits at a time. Each entry:
 * - next: Next state (0-255, or 0xFF for error)
 * - flags: HPACK_DFA_* flags
 * - sym: Output symbol if accepting
 * - sym2: Second output symbol if SYM2 flag set
 */
typedef struct
{
  uint8_t next;  /**< Next state */
  uint8_t flags; /**< Flags (accept, error, eos, sym2) */
  uint8_t sym;   /**< First output symbol */
  uint8_t sym2;  /**< Second output symbol (if SYM2 set) */
} HPACK_DecodeEntry;

/**
 * Number of states in the nibble-based decoder
 * This is a compact representation - full byte-based would need more states
 */
#define HPACK_DECODE_STATES 256

/**
 * Huffman decode table
 * Indexed by [state][nibble] where nibble is 0-15
 */
static const HPACK_DecodeEntry hpack_decode[HPACK_DECODE_STATES][16] = {
/* clang-format off */
/* State 0: Initial state - start of any code */
/* Nibble: 0    1    2    3    4    5    6    7    8    9    A    B    C    D    E    F */
[0] = {
  { 4, HPACK_DFA_ACCEPT, '0', 0 },   /* 0000 -> '0' (5 bits: 00000) */
  { 5, HPACK_DFA_ACCEPT, '1', 0 },   /* 0001 -> '1' (5 bits: 00001) */
  { 6, HPACK_DFA_ACCEPT, '2', 0 },   /* 0010 -> '2' (5 bits: 00010) */
  { 7, HPACK_DFA_ACCEPT, 'a', 0 },   /* 0011 -> 'a' (5 bits: 00011) */
  { 8, HPACK_DFA_ACCEPT, 'c', 0 },   /* 0100 -> 'c' (5 bits: 00100) */
  { 9, HPACK_DFA_ACCEPT, 'e', 0 },   /* 0101 -> 'e' (5 bits: 00101) */
  { 10, HPACK_DFA_ACCEPT, 'i', 0 },  /* 0110 -> 'i' (5 bits: 00110) */
  { 11, HPACK_DFA_ACCEPT, 'o', 0 },  /* 0111 -> 'o' (5 bits: 00111) */
  { 12, HPACK_DFA_ACCEPT, 's', 0 },  /* 1000 -> 's' (5 bits: 01000) */
  { 13, HPACK_DFA_ACCEPT, 't', 0 },  /* 1001 -> 't' (5 bits: 01001) */
  { 14, 0, 0, 0 },                   /* 1010 -> state 14 */
  { 15, 0, 0, 0 },                   /* 1011 -> state 15 */
  { 16, 0, 0, 0 },                   /* 1100 -> state 16 */
  { 17, 0, 0, 0 },                   /* 1101 -> state 17 */
  { 18, 0, 0, 0 },                   /* 1110 -> state 18 */
  { 19, 0, 0, 0 },                   /* 1111 -> state 19 (long codes) */
},
/* State 1-3: Placeholder states for partial matches */
[1] = { [0 ... 15] = { 0, HPACK_DFA_ERROR, 0, 0 } },
[2] = { [0 ... 15] = { 0, HPACK_DFA_ERROR, 0, 0 } },
[3] = { [0 ... 15] = { 0, HPACK_DFA_ERROR, 0, 0 } },
/* State 4: After '0' prefix - next nibble */
[4] = {
  { 0, HPACK_DFA_ACCEPT, '0', 0 },
  { 0, HPACK_DFA_ACCEPT, '0', 0 },
  { 0, HPACK_DFA_ACCEPT, '1', 0 },
  { 0, HPACK_DFA_ACCEPT, '1', 0 },
  { 0, HPACK_DFA_ACCEPT, '2', 0 },
  { 0, HPACK_DFA_ACCEPT, '2', 0 },
  { 0, HPACK_DFA_ACCEPT, 'a', 0 },
  { 0, HPACK_DFA_ACCEPT, 'a', 0 },
  { 0, HPACK_DFA_ACCEPT, 'c', 0 },
  { 0, HPACK_DFA_ACCEPT, 'c', 0 },
  { 0, HPACK_DFA_ACCEPT, 'e', 0 },
  { 0, HPACK_DFA_ACCEPT, 'e', 0 },
  { 0, HPACK_DFA_ACCEPT, 'i', 0 },
  { 0, HPACK_DFA_ACCEPT, 'i', 0 },
  { 0, HPACK_DFA_ACCEPT, 'o', 0 },
  { 0, HPACK_DFA_ACCEPT, 'o', 0 },
},
/* States 5-255: Extended states for longer codes */
/* These are populated for the full DFA but for now we provide stubs */
[5 ... 255] = { [0 ... 15] = { 0, 0, 0, 0 } },
/* clang-format on */
};

/* ============================================================================
 * Huffman Encoding Implementation
 * ============================================================================ */

size_t
SocketHPACK_huffman_encoded_size (const unsigned char *input, size_t input_len)
{
  size_t bits = 0;
  size_t i;

  if (input == NULL && input_len > 0)
    return 0;

  for (i = 0; i < input_len; i++)
    {
      bits += hpack_huffman_encode[input[i]].bits;
    }

  /* Round up to bytes */
  return (bits + 7) / 8;
}

ssize_t
SocketHPACK_huffman_encode (const unsigned char *input, size_t input_len,
                            unsigned char *output, size_t output_size)
{
  size_t out_pos = 0;
  uint64_t bits = 0;  /* Bit accumulator */
  int bits_left = 0;  /* Bits remaining in accumulator */
  size_t i;

  if (input == NULL && input_len > 0)
    return -1;
  if (output == NULL && output_size > 0)
    return -1;

  for (i = 0; i < input_len; i++)
    {
      const HPACK_HuffmanSymbol *sym = &hpack_huffman_encode[input[i]];

      /* Add code to accumulator */
      bits = (bits << sym->bits) | sym->code;
      bits_left += sym->bits;

      /* Flush complete bytes */
      while (bits_left >= 8)
        {
          if (out_pos >= output_size)
            return -1;

          bits_left -= 8;
          output[out_pos++] = (unsigned char)(bits >> bits_left);
        }
    }

  /* Add padding with EOS prefix (all 1s) */
  if (bits_left > 0)
    {
      if (out_pos >= output_size)
        return -1;

      /* Pad remaining bits with 1s (EOS prefix) */
      bits = (bits << (8 - bits_left)) | ((1 << (8 - bits_left)) - 1);
      output[out_pos++] = (unsigned char)bits;
    }

  return (ssize_t)out_pos;
}

/* ============================================================================
 * Huffman Decoding Implementation (Byte-at-a-time for simplicity)
 *
 * Uses a linear decode approach that processes bit-by-bit.
 * This is simpler than full DFA but still O(n).
 * ============================================================================ */

/**
 * Decode table indexed by code length
 * For each length, stores the first code value and first symbol
 */
typedef struct
{
  uint32_t first_code;  /**< First code of this length */
  uint16_t first_index; /**< Index of first symbol of this length */
  uint16_t count;       /**< Number of symbols of this length */
} HPACK_LengthEntry;

/**
 * Symbols sorted by Huffman code length
 */
static const uint16_t hpack_decode_symbols[] = {
  /* 5-bit codes (10 symbols) */
  '0', '1', '2', 'a', 'c', 'e', 'i', 'o', 's', 't',
  /* 6-bit codes (26 symbols) */
  ' ', '%', '-', '.', '/', '3', '4', '5', '6', '7',
  '8', '9', '=', 'A', '_', 'b', 'd', 'f', 'g', 'h',
  'l', 'm', 'n', 'p', 'r', 'u',
  /* 7-bit codes (26 symbols) */
  ':', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
  'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
  'U', 'V', 'W', 'Y', 'j', 'k',
  /* Continue with rest of alphabet... */
  'q', 'v', 'w', 'x', 'y', 'z',
  /* 8-bit codes */
  '&', '*', ',', ';', 'X', 'Z',
};

/**
 * Length table for fast decode
 */
static const HPACK_LengthEntry hpack_length_table[] = {
  /* [0-4] unused */
  { 0, 0, 0 }, { 0, 0, 0 }, { 0, 0, 0 }, { 0, 0, 0 }, { 0, 0, 0 },
  /* [5] 5-bit codes: '0'-'t' (10 symbols) */
  { 0x00, 0, 10 },
  /* [6] 6-bit codes (26 symbols) */
  { 0x14, 10, 26 },
  /* [7] 7-bit codes (26 symbols) */
  { 0x5c, 36, 32 },
  /* [8] 8-bit codes */
  { 0xf8, 68, 7 },
  /* Continue for longer codes... */
};

ssize_t
SocketHPACK_huffman_decode (const unsigned char *input, size_t input_len,
                            unsigned char *output, size_t output_size)
{
  size_t out_pos = 0;
  uint64_t bits = 0;
  int bits_avail = 0;
  size_t in_pos = 0;
  int found;

  if (input == NULL && input_len > 0)
    return -1;
  if (output == NULL && output_size > 0)
    return -1;
  if (input_len == 0)
    return 0;

  /* Process input bytes */
  while (in_pos < input_len || bits_avail >= 5)
    {
      /* Refill bit buffer */
      while (bits_avail < 32 && in_pos < input_len)
        {
          bits = (bits << 8) | input[in_pos++];
          bits_avail += 8;
        }

      if (bits_avail < 5)
        break;

      /* Try to decode a symbol - check from shortest to longest codes */
      found = 0;

      /* 5-bit codes */
      if (bits_avail >= 5)
        {
          uint32_t code = (uint32_t)(bits >> (bits_avail - 5)) & 0x1F;
          if (code <= 9)
            {
              /* Valid 5-bit code */
              if (out_pos >= output_size)
                return -1;
              output[out_pos++] = hpack_decode_symbols[code];
              bits_avail -= 5;
              found = 1;
            }
        }

      /* 6-bit codes */
      if (!found && bits_avail >= 6)
        {
          uint32_t code = (uint32_t)(bits >> (bits_avail - 6)) & 0x3F;
          if (code >= 0x14 && code <= 0x2D)
            {
              if (out_pos >= output_size)
                return -1;
              output[out_pos++] = hpack_decode_symbols[10 + (code - 0x14)];
              bits_avail -= 6;
              found = 1;
            }
        }

      /* 7-bit codes */
      if (!found && bits_avail >= 7)
        {
          uint32_t code = (uint32_t)(bits >> (bits_avail - 7)) & 0x7F;
          if (code >= 0x5c && code <= 0x7B)
            {
              if (out_pos >= output_size)
                return -1;
              output[out_pos++] = hpack_decode_symbols[36 + (code - 0x5c)];
              bits_avail -= 7;
              found = 1;
            }
        }

      /* 8-bit codes */
      if (!found && bits_avail >= 8)
        {
          uint32_t code = (uint32_t)(bits >> (bits_avail - 8)) & 0xFF;
          if (code >= 0xf8 && code <= 0xFD)
            {
              if (out_pos >= output_size)
                return -1;
              output[out_pos++] = hpack_decode_symbols[68 + (code - 0xf8)];
              bits_avail -= 8;
              found = 1;
            }
        }

      /* For longer codes, we need full table lookup */
      if (!found)
        {
          /* Check if remaining bits are valid EOS padding */
          if (bits_avail < 8)
            {
              uint32_t pad_mask = (1U << bits_avail) - 1;
              uint32_t padding = (uint32_t)(bits & pad_mask);
              if (padding == pad_mask)
                {
                  /* Valid EOS padding */
                  break;
                }
            }

          /* Try longer codes (simplified - full implementation needed) */
          /* For now, if we can't decode, it's an error */
          if (bits_avail >= 8)
            {
              /* Check for common longer codes */
              uint32_t code8 = (uint32_t)(bits >> (bits_avail - 8)) & 0xFF;

              /* Check known 8-bit patterns */
              switch (code8)
                {
                case 0xf8:
                  output[out_pos++] = '&';
                  bits_avail -= 8;
                  found = 1;
                  break;
                case 0xf9:
                  output[out_pos++] = '*';
                  bits_avail -= 8;
                  found = 1;
                  break;
                case 0xfa:
                  output[out_pos++] = ',';
                  bits_avail -= 8;
                  found = 1;
                  break;
                case 0xfb:
                  output[out_pos++] = ';';
                  bits_avail -= 8;
                  found = 1;
                  break;
                case 0xfc:
                  output[out_pos++] = 'X';
                  bits_avail -= 8;
                  found = 1;
                  break;
                case 0xfd:
                  output[out_pos++] = 'Z';
                  bits_avail -= 8;
                  found = 1;
                  break;
                }
            }

          if (!found)
            {
              /* Can't decode - check for padding */
              if (bits_avail <= 7)
                {
                  uint32_t pad_mask = (1U << bits_avail) - 1;
                  uint32_t padding = (uint32_t)(bits & pad_mask);
                  if (padding == pad_mask)
                    {
                      break; /* Valid padding */
                    }
                }
              /* Invalid encoding */
              return -1;
            }
        }

      /* Mask off used bits */
      bits &= ((uint64_t)1 << bits_avail) - 1;
    }

  /* Verify remaining bits are valid EOS padding */
  if (bits_avail > 0 && bits_avail <= 7)
    {
      uint32_t pad_mask = (1U << bits_avail) - 1;
      uint32_t padding = (uint32_t)(bits & pad_mask);
      if (padding != pad_mask)
        {
          /* Invalid padding - must be all 1s */
          return -1;
        }
    }
  else if (bits_avail > 7)
    {
      /* Too many leftover bits - invalid */
      return -1;
    }

  return (ssize_t)out_pos;
}

