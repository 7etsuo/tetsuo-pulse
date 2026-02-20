/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_quic_rfc9001_vectors.c
 * @brief RFC 9001 Appendix A Test Vectors - Comprehensive Validation
 *
 * Implements byte-for-byte verification of all RFC 9001 Appendix A test vectors
 * including full packet construction, encryption, header protection, and
 * decryption tests.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9001#appendix-A
 */

#include <string.h>

#include "quic/SocketQUICCrypto.h"
#include "quic/SocketQUICPacket.h"
#include "quic/SocketQUICVersion.h"
#include "test/Test.h"

static const uint8_t RFC_DCID[]
    = { 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

/* Expected initial_secret (32 bytes) */
static const uint8_t RFC_A1_INITIAL_SECRET[]
    = { 0x7d, 0xb5, 0xdf, 0x06, 0xe7, 0xa6, 0x9e, 0x43, 0x24, 0x96, 0xad,
        0xed, 0xb0, 0x08, 0x51, 0x92, 0x35, 0x95, 0x22, 0x15, 0x96, 0xae,
        0x2a, 0xe9, 0xfb, 0x81, 0x15, 0xc1, 0xe9, 0xed, 0x0a, 0x44 };

/* Expected client_initial_secret (32 bytes) */
static const uint8_t RFC_A1_CLIENT_SECRET[]
    = { 0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75, 0xed, 0x0e, 0xbf,
        0xb5, 0xc8, 0x03, 0x23, 0xc4, 0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81,
        0x28, 0x9a, 0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea };

/* Expected server_initial_secret (32 bytes) */
static const uint8_t RFC_A1_SERVER_SECRET[]
    = { 0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xfd, 0x21, 0x6c, 0x15,
        0x5a, 0xd8, 0x44, 0xcc, 0x81, 0xfb, 0x82, 0xfa, 0x8d, 0x74, 0x46,
        0xfa, 0x7d, 0x78, 0xbe, 0x80, 0x3a, 0xcd, 0xda, 0x95, 0x1b };

/* Expected client_key (16 bytes) */
static const uint8_t RFC_A1_CLIENT_KEY[]
    = { 0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46,
        0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d };

/* Expected client_iv (12 bytes) */
static const uint8_t RFC_A1_CLIENT_IV[] = {
  0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c
};

/* Expected client_hp (16 bytes) */
static const uint8_t RFC_A1_CLIENT_HP[]
    = { 0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
        0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2 };

/* Expected server_key (16 bytes) */
static const uint8_t RFC_A1_SERVER_KEY[]
    = { 0xcf, 0x3a, 0x53, 0x31, 0x65, 0x3c, 0x36, 0x4c,
        0x88, 0xf0, 0xf3, 0x79, 0xb6, 0x06, 0x7e, 0x37 };

/* Expected server_iv (12 bytes) */
static const uint8_t RFC_A1_SERVER_IV[] = {
  0x0a, 0xc1, 0x49, 0x3c, 0xa1, 0x90, 0x58, 0x53, 0xb0, 0xbb, 0xa0, 0x3e
};

/* Expected server_hp (16 bytes) */
static const uint8_t RFC_A1_SERVER_HP[]
    = { 0xc2, 0x06, 0xb8, 0xd9, 0xb9, 0xf0, 0xf3, 0x76,
        0x44, 0x43, 0x0b, 0x49, 0x0e, 0xea, 0xa3, 0x14 };

/* Unprotected header (22 bytes) - packet number 2, 4-byte encoding */
static const uint8_t RFC_A2_UNPROTECTED_HEADER[]
    = { 0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e,
        0x51, 0x57, 0x08, 0x00, 0x00, 0x44, 0x9e, 0x00, 0x00, 0x00, 0x02 };

/* Protected header (22 bytes) */
static const uint8_t RFC_A2_PROTECTED_HEADER[]
    = { 0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e,
        0x51, 0x57, 0x08, 0x00, 0x00, 0x44, 0x9e, 0x7b, 0x9a, 0xec, 0x34 };

/* Header protection sample (16 bytes) - from encrypted payload */
static const uint8_t RFC_A2_SAMPLE[]
    = { 0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68, 0x9f, 0xb8,
        0xec, 0x11, 0xd2, 0x42, 0xb1, 0x23, 0xdc, 0x9b };

/* Expected mask (5 bytes) */
static const uint8_t RFC_A2_MASK[] = { 0x43, 0x7b, 0x9a, 0xec, 0x36 };

/* CRYPTO frame payload (ClientHello) - 241 bytes */
static const uint8_t RFC_A2_CRYPTO_FRAME[] = {
  0x06, 0x00, 0x40, 0xf1, 0x01, 0x00, 0x00, 0xed, 0x03, 0x03, 0xeb, 0xf8, 0xfa,
  0x56, 0xf1, 0x29, 0x39, 0xb9, 0x58, 0x4a, 0x38, 0x96, 0x47, 0x2e, 0xc4, 0x0b,
  0xb8, 0x63, 0xcf, 0xd3, 0xe8, 0x68, 0x04, 0xfe, 0x3a, 0x47, 0xf0, 0x6a, 0x2b,
  0x69, 0x48, 0x4c, 0x00, 0x00, 0x04, 0x13, 0x01, 0x13, 0x02, 0x01, 0x00, 0x00,
  0xc0, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x00, 0x0b, 0x65, 0x78, 0x61,
  0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0xff, 0x01, 0x00, 0x01, 0x00,
  0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00,
  0x10, 0x00, 0x07, 0x00, 0x05, 0x04, 0x61, 0x6c, 0x70, 0x6e, 0x00, 0x05, 0x00,
  0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00,
  0x1d, 0x00, 0x20, 0x93, 0x70, 0xb2, 0xc9, 0xca, 0xa4, 0x7f, 0xba, 0xba, 0xf4,
  0x55, 0x9f, 0xed, 0xba, 0x75, 0x3d, 0xe1, 0x71, 0xfa, 0x71, 0xf5, 0x0f, 0x1c,
  0xe1, 0x5d, 0x43, 0xe9, 0x94, 0xec, 0x74, 0xd7, 0x48, 0x00, 0x2b, 0x00, 0x03,
  0x02, 0x03, 0x04, 0x00, 0x0d, 0x00, 0x10, 0x00, 0x0e, 0x04, 0x03, 0x05, 0x03,
  0x06, 0x03, 0x02, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x00, 0x2d, 0x00,
  0x02, 0x01, 0x01, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01, 0x00, 0x39, 0x00, 0x32,
  0x04, 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x05, 0x04, 0x80,
  0x00, 0xff, 0xff, 0x07, 0x04, 0x80, 0x00, 0xff, 0xff, 0x08, 0x01, 0x10, 0x01,
  0x04, 0x80, 0x00, 0x75, 0x30, 0x09, 0x01, 0x10, 0x0f, 0x08, 0x83, 0x94, 0xc8,
  0xf0, 0x3e, 0x51, 0x57, 0x08, 0x06, 0x04, 0x80, 0x00, 0xff, 0xff
};

/* First 64 bytes of complete protected packet (for verification) */
static const uint8_t RFC_A2_PROTECTED_PACKET_START[]
    = { 0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e,
        0x51, 0x57, 0x08, 0x00, 0x00, 0x44, 0x9e, 0x7b, 0x9a, 0xec, 0x34,
        0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68, 0x9f, 0xb8, 0xec, 0x11, 0xd2,
        0x42, 0xb1, 0x23, 0xdc, 0x9b, 0xd8, 0xba, 0xb9, 0x36, 0xb4, 0x7d,
        0x92, 0xec, 0x35, 0x6c, 0x0b, 0xab, 0x7d, 0xf5, 0x97, 0x6d, 0x27,
        0xcd, 0x44, 0x9f, 0x63, 0x30, 0x00, 0x99, 0xf3, 0x99 };

/* Unprotected header (20 bytes) - packet number 1, 2-byte encoding */
static const uint8_t RFC_A3_UNPROTECTED_HEADER[]
    = { 0xc1, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5,
        0x50, 0x2a, 0x42, 0x62, 0xb5, 0x00, 0x40, 0x75, 0x00, 0x01 };

/* Protected header (20 bytes) */
static const uint8_t RFC_A3_PROTECTED_HEADER[]
    = { 0xcf, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5,
        0x50, 0x2a, 0x42, 0x62, 0xb5, 0x00, 0x40, 0x75, 0xc0, 0xd9 };

/* Header protection sample (16 bytes) */
static const uint8_t RFC_A3_SAMPLE[]
    = { 0x2c, 0xd0, 0x99, 0x1c, 0xd2, 0x5b, 0x0a, 0xac,
        0x40, 0x6a, 0x58, 0x16, 0xb6, 0x39, 0x41, 0x00 };

/* Expected mask (5 bytes) */
static const uint8_t RFC_A3_MASK[] = { 0x2e, 0xc0, 0xd8, 0x35, 0x6a };

/* Server payload (ACK + CRYPTO with ServerHello) - 90 bytes */
static const uint8_t RFC_A3_PAYLOAD[]
    = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x40, 0x5a, 0x02, 0x00,
        0x00, 0x56, 0x03, 0x03, 0xee, 0xfc, 0xe7, 0xf7, 0xb3, 0x7b, 0xa1,
        0xd1, 0x63, 0x2e, 0x96, 0x67, 0x78, 0x25, 0xdd, 0xf7, 0x39, 0x88,
        0xcf, 0xc7, 0x98, 0x25, 0xdf, 0x56, 0x6d, 0xc5, 0x43, 0x0b, 0x9a,
        0x04, 0x5a, 0x12, 0x00, 0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x33,
        0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x9d, 0x3c, 0x94, 0x0d, 0x89,
        0x69, 0x0b, 0x84, 0xd0, 0x8a, 0x60, 0x99, 0x3c, 0x14, 0x4e, 0xca,
        0x68, 0x4d, 0x10, 0x81, 0x28, 0x7c, 0x83, 0x4d, 0x53, 0x11, 0xbc,
        0xf3, 0x2b, 0xb9, 0xda, 0x1a, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04 };

/* Complete protected packet (135 bytes) */
static const uint8_t RFC_A3_PROTECTED_PACKET[]
    = { 0xcf, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a,
        0x42, 0x62, 0xb5, 0x00, 0x40, 0x75, 0xc0, 0xd9, 0x5a, 0x48, 0x2c, 0xd0,
        0x99, 0x1c, 0xd2, 0x5b, 0x0a, 0xac, 0x40, 0x6a, 0x58, 0x16, 0xb6, 0x39,
        0x41, 0x00, 0xf3, 0x7a, 0x1c, 0x69, 0x79, 0x75, 0x54, 0x78, 0x0b, 0xb3,
        0x8c, 0xc5, 0xa9, 0x9f, 0x5e, 0xde, 0x4c, 0xf7, 0x3c, 0x3e, 0xc2, 0x49,
        0x3a, 0x18, 0x39, 0xb3, 0xdb, 0xcb, 0xa3, 0xf6, 0xea, 0x46, 0xc5, 0xb7,
        0x68, 0x4d, 0xf3, 0x54, 0x8e, 0x7d, 0xde, 0xb9, 0xc3, 0xbf, 0x9c, 0x73,
        0xcc, 0x3f, 0x3b, 0xde, 0xd7, 0x4b, 0x56, 0x2b, 0xfb, 0x19, 0xfb, 0x84,
        0x02, 0x2f, 0x8e, 0xf4, 0xcd, 0xd9, 0x37, 0x95, 0xd7, 0x7d, 0x06, 0xed,
        0xbb, 0x7a, 0xaf, 0x2f, 0x58, 0x89, 0x18, 0x50, 0xab, 0xbd, 0xca, 0x3d,
        0x20, 0x39, 0x8c, 0x27, 0x64, 0x56, 0xcb, 0xc4, 0x21, 0x58, 0x40, 0x7d,
        0xd0, 0x74, 0xee };

/* Complete Retry packet (36 bytes) */
static const uint8_t RFC_A4_RETRY_PACKET[] = { 0xff,
                                               0x00,
                                               0x00,
                                               0x00,
                                               0x01,
                                               0x00,
                                               0x08,
                                               0xf0,
                                               0x67,
                                               0xa5,
                                               0x50,
                                               0x2a,
                                               0x42,
                                               0x62,
                                               0xb5,
                                               0x74,
                                               0x6f,
                                               0x6b,
                                               0x65,
                                               0x6e, /* "token" */
                                               /* Integrity tag (16 bytes) */
                                               0x04,
                                               0xa2,
                                               0x65,
                                               0xba,
                                               0x2e,
                                               0xff,
                                               0x4d,
                                               0x82,
                                               0x90,
                                               0x58,
                                               0xfb,
                                               0x3f,
                                               0x0f,
                                               0x24,
                                               0x96,
                                               0xba };

/* Expected integrity tag */
static const uint8_t RFC_A4_INTEGRITY_TAG[]
    = { 0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82,
        0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24, 0x96, 0xba };

/* Retry packet without tag (20 bytes) */
static const uint8_t RFC_A4_RETRY_NO_TAG[]
    = { 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5,
        0x50, 0x2a, 0x42, 0x62, 0xb5, 0x74, 0x6f, 0x6b, 0x65, 0x6e };

/* Secret for ChaCha20-Poly1305 (32 bytes) */
static const uint8_t RFC_A5_SECRET[]
    = { 0x9a, 0xc3, 0x12, 0xa7, 0xf8, 0x77, 0x46, 0x8e, 0xbe, 0x69, 0x42,
        0x27, 0x48, 0xad, 0x00, 0xa1, 0x54, 0x43, 0xf1, 0x82, 0x03, 0xa0,
        0x7d, 0x60, 0x60, 0xf6, 0x88, 0xf3, 0x0f, 0x21, 0x63, 0x2b };

/* Expected key (32 bytes) */
static const uint8_t RFC_A5_KEY[]
    = { 0xc6, 0xd9, 0x8f, 0xf3, 0x44, 0x1c, 0x3f, 0xe1, 0xb2, 0x18, 0x20,
        0x94, 0xf6, 0x9c, 0xaa, 0x2e, 0xd4, 0xb7, 0x16, 0xb6, 0x54, 0x88,
        0x96, 0x0a, 0x7a, 0x98, 0x49, 0x79, 0xfb, 0x23, 0xe1, 0xc8 };

/* Expected IV (12 bytes) */
static const uint8_t RFC_A5_IV[] = { 0xe0, 0x45, 0x9b, 0x34, 0x74, 0xbd,
                                     0xd0, 0xe4, 0x4a, 0x41, 0xc1, 0x44 };

/* Expected HP key (32 bytes) */
static const uint8_t RFC_A5_HP[]
    = { 0x25, 0xa2, 0x82, 0xb9, 0xe8, 0x2f, 0x06, 0xf2, 0x1f, 0x48, 0x89,
        0x17, 0xa4, 0xfc, 0x8f, 0x1b, 0x73, 0x57, 0x36, 0x85, 0x60, 0x85,
        0x97, 0xd0, 0xef, 0xcb, 0x07, 0x6b, 0x0a, 0xb7, 0xa7, 0xa4 };

/* Expected KU (key update) secret (32 bytes) */
static const uint8_t RFC_A5_KU[]
    = { 0x12, 0x23, 0x50, 0x47, 0x55, 0x03, 0x6d, 0x55, 0x63, 0x42, 0xee,
        0x93, 0x61, 0xd2, 0x53, 0x42, 0x1a, 0x82, 0x6c, 0x9e, 0xcd, 0xf3,
        0xc7, 0x14, 0x86, 0x84, 0xb3, 0x6b, 0x71, 0x48, 0x81, 0xf9 };

/* Packet number (654360564 decimal = 0x2700bff4) */
#define RFC_A5_PACKET_NUMBER 654360564

/* Nonce (IV XOR packet number) */
static const uint8_t RFC_A5_NONCE[] = { 0xe0, 0x45, 0x9b, 0x34, 0x74, 0xbd,
                                        0xd0, 0xe4, 0x6d, 0x41, 0x7e, 0xb0 };

/* Unprotected header (4 bytes) - short header with 3-byte PN */
static const uint8_t RFC_A5_UNPROTECTED_HEADER[] = { 0x42, 0x00, 0xbf, 0xf4 };

/* Protected header (4 bytes) */
static const uint8_t RFC_A5_PROTECTED_HEADER[] = { 0x4c, 0xfe, 0x41, 0x89 };

/* Payload plaintext - single PING frame */
static const uint8_t RFC_A5_PLAINTEXT[] = { 0x01 };

/* Payload ciphertext (17 bytes) - 1 byte payload + 16 byte tag */
static const uint8_t RFC_A5_CIPHERTEXT[]
    = { 0x65, 0x5e, 0x5c, 0xd5, 0x5c, 0x41, 0xf6, 0x90, 0x80,
        0x57, 0x5d, 0x79, 0x99, 0xc2, 0x5a, 0x5b, 0xfb };

/* Header protection sample (16 bytes) */
static const uint8_t RFC_A5_SAMPLE[]
    = { 0x5e, 0x5c, 0xd5, 0x5c, 0x41, 0xf6, 0x90, 0x80,
        0x57, 0x5d, 0x79, 0x99, 0xc2, 0x5a, 0x5b, 0xfb };

/* Expected mask (5 bytes) */
static const uint8_t RFC_A5_MASK[] = { 0xae, 0xfe, 0xfe, 0x7d, 0x03 };

/* Complete protected packet (21 bytes) */
static const uint8_t RFC_A5_PROTECTED_PACKET[]
    = { 0x4c, 0xfe, 0x41, 0x89, 0x65, 0x5e, 0x5c, 0xd5, 0x5c, 0x41, 0xf6,
        0x90, 0x80, 0x57, 0x5d, 0x79, 0x99, 0xc2, 0x5a, 0x5b, 0xfb };

#ifdef SOCKET_HAS_TLS

/*
 * HKDF-Expand-Label encoded labels from RFC 9001 Appendix A.1.
 *
 * HkdfLabel structure (TLS 1.3):
 *   uint16 length;           // output length
 *   opaque label<7..255>;    // "tls13 " + label
 *   opaque context<0..255>;  // empty for QUIC
 *
 * These hex values document the expected inputs to HKDF-Expand-Label.
 */

/* "client in" → length=32, label="tls13 client in", context="" */
static const uint8_t RFC_HKDF_LABEL_CLIENT_IN[]
    = { 0x00, 0x20, 0x0f, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x63,
        0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x69, 0x6e, 0x00 };

/* "server in" → length=32, label="tls13 server in", context="" */
static const uint8_t RFC_HKDF_LABEL_SERVER_IN[]
    = { 0x00, 0x20, 0x0f, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x73,
        0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x69, 0x6e, 0x00 };

/* "quic key" → length=16, label="tls13 quic key", context="" */
static const uint8_t RFC_HKDF_LABEL_QUIC_KEY[]
    = { 0x00, 0x10, 0x0e, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20,
        0x71, 0x75, 0x69, 0x63, 0x20, 0x6b, 0x65, 0x79, 0x00 };

/* "quic iv" → length=12, label="tls13 quic iv", context="" */
static const uint8_t RFC_HKDF_LABEL_QUIC_IV[]
    = { 0x00, 0x0c, 0x0d, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20,
        0x71, 0x75, 0x69, 0x63, 0x20, 0x69, 0x76, 0x00 };

/* "quic hp" → length=16, label="tls13 quic hp", context="" */
static const uint8_t RFC_HKDF_LABEL_QUIC_HP[]
    = { 0x00, 0x10, 0x0d, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20,
        0x71, 0x75, 0x69, 0x63, 0x20, 0x68, 0x70, 0x00 };

TEST (rfc9001_a1_hkdf_label_format)
{
  /*
   * Verify HKDF label structure per RFC 8446 Section 7.1 and RFC 9001 A.1.
   * This test validates the documented label byte sequences.
   *
   * Format: length (2) || label_len (1) || "tls13 " || label || context_len (1)
   */

  /* "client in": output=32, label_len=15 ("tls13 client in") */
  ASSERT_EQ (0x00, RFC_HKDF_LABEL_CLIENT_IN[0]);  /* length high byte */
  ASSERT_EQ (0x20, RFC_HKDF_LABEL_CLIENT_IN[1]);  /* length low = 32 */
  ASSERT_EQ (0x0f, RFC_HKDF_LABEL_CLIENT_IN[2]);  /* label_len = 15 */
  ASSERT_EQ ('t', RFC_HKDF_LABEL_CLIENT_IN[3]);   /* "tls13 client in" */
  ASSERT_EQ (0x00, RFC_HKDF_LABEL_CLIENT_IN[18]); /* context_len = 0 */

  /* "server in": output=32, label_len=15 */
  ASSERT_EQ (0x20, RFC_HKDF_LABEL_SERVER_IN[1]); /* length = 32 */
  ASSERT_EQ (0x0f, RFC_HKDF_LABEL_SERVER_IN[2]); /* label_len = 15 */
  ASSERT_EQ ('s', RFC_HKDF_LABEL_SERVER_IN[9]);  /* "server" starts at idx 9 */

  /* "quic key": output=16, label_len=14 */
  ASSERT_EQ (0x10, RFC_HKDF_LABEL_QUIC_KEY[1]); /* length = 16 */
  ASSERT_EQ (0x0e, RFC_HKDF_LABEL_QUIC_KEY[2]); /* label_len = 14 */

  /* "quic iv": output=12, label_len=13 */
  ASSERT_EQ (0x0c, RFC_HKDF_LABEL_QUIC_IV[1]); /* length = 12 */
  ASSERT_EQ (0x0d, RFC_HKDF_LABEL_QUIC_IV[2]); /* label_len = 13 */

  /* "quic hp": output=16, label_len=13 */
  ASSERT_EQ (0x10, RFC_HKDF_LABEL_QUIC_HP[1]); /* length = 16 */
  ASSERT_EQ (0x0d, RFC_HKDF_LABEL_QUIC_HP[2]); /* label_len = 13 */
}

TEST (rfc9001_a1_initial_secret)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICCryptoSecrets_T secrets;
  SocketQUICInitialKeys_T keys;

  SocketQUICConnectionID_set (&dcid, RFC_DCID, sizeof (RFC_DCID));

  SocketQUICCrypto_Result result = SocketQUICCrypto_derive_initial_secrets (
      &dcid, QUIC_VERSION_1, &secrets, &keys);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT (memcmp (secrets.initial_secret,
                  RFC_A1_INITIAL_SECRET,
                  sizeof (RFC_A1_INITIAL_SECRET))
          == 0);

  SocketQUICCryptoSecrets_clear (&secrets);
  SocketQUICInitialKeys_clear (&keys);
}

TEST (rfc9001_a1_client_secret)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICCryptoSecrets_T secrets;
  SocketQUICInitialKeys_T keys;

  SocketQUICConnectionID_set (&dcid, RFC_DCID, sizeof (RFC_DCID));

  SocketQUICCrypto_Result result = SocketQUICCrypto_derive_initial_secrets (
      &dcid, QUIC_VERSION_1, &secrets, &keys);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT (memcmp (secrets.client_initial_secret,
                  RFC_A1_CLIENT_SECRET,
                  sizeof (RFC_A1_CLIENT_SECRET))
          == 0);

  SocketQUICCryptoSecrets_clear (&secrets);
  SocketQUICInitialKeys_clear (&keys);
}

TEST (rfc9001_a1_server_secret)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICCryptoSecrets_T secrets;
  SocketQUICInitialKeys_T keys;

  SocketQUICConnectionID_set (&dcid, RFC_DCID, sizeof (RFC_DCID));

  SocketQUICCrypto_Result result = SocketQUICCrypto_derive_initial_secrets (
      &dcid, QUIC_VERSION_1, &secrets, &keys);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT (memcmp (secrets.server_initial_secret,
                  RFC_A1_SERVER_SECRET,
                  sizeof (RFC_A1_SERVER_SECRET))
          == 0);

  SocketQUICCryptoSecrets_clear (&secrets);
  SocketQUICInitialKeys_clear (&keys);
}

TEST (rfc9001_a1_client_key)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICInitialKeys_T keys;

  SocketQUICConnectionID_set (&dcid, RFC_DCID, sizeof (RFC_DCID));

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_derive_initial_keys (&dcid, QUIC_VERSION_1, &keys);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT (
      memcmp (keys.client_key, RFC_A1_CLIENT_KEY, sizeof (RFC_A1_CLIENT_KEY))
      == 0);

  SocketQUICInitialKeys_clear (&keys);
}

TEST (rfc9001_a1_client_iv)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICInitialKeys_T keys;

  SocketQUICConnectionID_set (&dcid, RFC_DCID, sizeof (RFC_DCID));

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_derive_initial_keys (&dcid, QUIC_VERSION_1, &keys);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT (memcmp (keys.client_iv, RFC_A1_CLIENT_IV, sizeof (RFC_A1_CLIENT_IV))
          == 0);

  SocketQUICInitialKeys_clear (&keys);
}

TEST (rfc9001_a1_client_hp)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICInitialKeys_T keys;

  SocketQUICConnectionID_set (&dcid, RFC_DCID, sizeof (RFC_DCID));

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_derive_initial_keys (&dcid, QUIC_VERSION_1, &keys);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT (
      memcmp (keys.client_hp_key, RFC_A1_CLIENT_HP, sizeof (RFC_A1_CLIENT_HP))
      == 0);

  SocketQUICInitialKeys_clear (&keys);
}

TEST (rfc9001_a1_server_key)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICInitialKeys_T keys;

  SocketQUICConnectionID_set (&dcid, RFC_DCID, sizeof (RFC_DCID));

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_derive_initial_keys (&dcid, QUIC_VERSION_1, &keys);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT (
      memcmp (keys.server_key, RFC_A1_SERVER_KEY, sizeof (RFC_A1_SERVER_KEY))
      == 0);

  SocketQUICInitialKeys_clear (&keys);
}

TEST (rfc9001_a1_server_iv)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICInitialKeys_T keys;

  SocketQUICConnectionID_set (&dcid, RFC_DCID, sizeof (RFC_DCID));

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_derive_initial_keys (&dcid, QUIC_VERSION_1, &keys);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT (memcmp (keys.server_iv, RFC_A1_SERVER_IV, sizeof (RFC_A1_SERVER_IV))
          == 0);

  SocketQUICInitialKeys_clear (&keys);
}

TEST (rfc9001_a1_server_hp)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICInitialKeys_T keys;

  SocketQUICConnectionID_set (&dcid, RFC_DCID, sizeof (RFC_DCID));

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_derive_initial_keys (&dcid, QUIC_VERSION_1, &keys);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT (
      memcmp (keys.server_hp_key, RFC_A1_SERVER_HP, sizeof (RFC_A1_SERVER_HP))
      == 0);

  SocketQUICInitialKeys_clear (&keys);
}

TEST (rfc9001_a2_client_initial_header_protect)
{
  uint8_t header[sizeof (RFC_A2_UNPROTECTED_HEADER)];
  uint8_t packet[128];
  size_t pn_offset = 18; /* Offset to packet number in header */

  /* Build test packet: header + sample at pn_offset + 4 */
  memcpy (
      header, RFC_A2_UNPROTECTED_HEADER, sizeof (RFC_A2_UNPROTECTED_HEADER));
  memcpy (packet, header, sizeof (header));
  memcpy (packet + pn_offset + 4, RFC_A2_SAMPLE, sizeof (RFC_A2_SAMPLE));

  size_t packet_len = pn_offset + 4 + sizeof (RFC_A2_SAMPLE);

  /* Apply header protection */
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_protect_header (RFC_A1_CLIENT_HP,
                                         sizeof (RFC_A1_CLIENT_HP),
                                         QUIC_AEAD_AES_128_GCM,
                                         packet,
                                         packet_len,
                                         pn_offset);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Verify first byte */
  ASSERT_EQ (RFC_A2_PROTECTED_HEADER[0], packet[0]);

  /* Verify packet number bytes */
  ASSERT_EQ (RFC_A2_PROTECTED_HEADER[18], packet[18]);
  ASSERT_EQ (RFC_A2_PROTECTED_HEADER[19], packet[19]);
  ASSERT_EQ (RFC_A2_PROTECTED_HEADER[20], packet[20]);
  ASSERT_EQ (RFC_A2_PROTECTED_HEADER[21], packet[21]);
}

TEST (rfc9001_a2_client_initial_mask_verify)
{
  /*
   * Verify mask by computing XOR difference between protected/unprotected.
   * RFC 9001 A.2 mask = 437b9aec36
   *
   * For long header: first byte masked with mask[0] & 0x0F
   *   0xC3 ^ (0x43 & 0x0F) = 0xC3 ^ 0x03 = 0xC0 ✓
   * Packet number (4 bytes) XOR with mask[1..4]:
   *   0x00000002 ^ 0x7b9aec36 = 0x7b9aec34 ✓
   */
  uint8_t computed_mask[5];

  /* First byte: extract mask[0] & 0x0F from XOR */
  uint8_t first_byte_diff
      = RFC_A2_UNPROTECTED_HEADER[0] ^ RFC_A2_PROTECTED_HEADER[0];
  /* For long header, only lower 4 bits are masked */
  computed_mask[0] = (RFC_A2_MASK[0] & 0x0F);
  ASSERT_EQ (computed_mask[0], first_byte_diff);

  /* Packet number bytes (offset 18-21) */
  computed_mask[1]
      = RFC_A2_UNPROTECTED_HEADER[18] ^ RFC_A2_PROTECTED_HEADER[18];
  computed_mask[2]
      = RFC_A2_UNPROTECTED_HEADER[19] ^ RFC_A2_PROTECTED_HEADER[19];
  computed_mask[3]
      = RFC_A2_UNPROTECTED_HEADER[20] ^ RFC_A2_PROTECTED_HEADER[20];
  computed_mask[4]
      = RFC_A2_UNPROTECTED_HEADER[21] ^ RFC_A2_PROTECTED_HEADER[21];

  ASSERT_EQ (RFC_A2_MASK[1], computed_mask[1]);
  ASSERT_EQ (RFC_A2_MASK[2], computed_mask[2]);
  ASSERT_EQ (RFC_A2_MASK[3], computed_mask[3]);
  ASSERT_EQ (RFC_A2_MASK[4], computed_mask[4]);
}

TEST (rfc9001_a2_client_initial_encrypt_decrypt)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICInitialKeys_T keys;
  uint8_t plaintext[1200];
  uint8_t ciphertext[1216]; /* plaintext + 16 byte tag */
  uint8_t decrypted[1200];
  size_t ciphertext_len = sizeof (ciphertext);
  size_t decrypted_len = sizeof (decrypted);

  /* Build plaintext: CRYPTO frame + padding to 1162 bytes */
  memset (plaintext, 0, sizeof (plaintext));
  memcpy (plaintext, RFC_A2_CRYPTO_FRAME, sizeof (RFC_A2_CRYPTO_FRAME));
  size_t plaintext_len = 1162; /* RFC specifies 1162 byte payload */

  /* Derive keys */
  SocketQUICConnectionID_set (&dcid, RFC_DCID, sizeof (RFC_DCID));
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_derive_initial_keys (&dcid, QUIC_VERSION_1, &keys);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Build packet keys from initial keys */
  SocketQUICPacketKeys_T pkt_keys;
  SocketQUICPacketKeys_init (&pkt_keys);
  memcpy (pkt_keys.key, keys.client_key, QUIC_INITIAL_KEY_LEN);
  memcpy (pkt_keys.iv, keys.client_iv, QUIC_INITIAL_IV_LEN);
  pkt_keys.key_len = QUIC_INITIAL_KEY_LEN;
  pkt_keys.hp_len = QUIC_INITIAL_HP_KEY_LEN;
  pkt_keys.aead = QUIC_AEAD_AES_128_GCM;

  /* Encrypt with packet number 2 */
  result = SocketQUICCrypto_encrypt_payload (&pkt_keys,
                                             2, /* packet number */
                                             RFC_A2_UNPROTECTED_HEADER,
                                             sizeof (RFC_A2_UNPROTECTED_HEADER),
                                             plaintext,
                                             plaintext_len,
                                             ciphertext,
                                             &ciphertext_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (plaintext_len + 16, ciphertext_len); /* +16 for auth tag */

  /* Verify ciphertext sample matches RFC */
  ASSERT (memcmp (ciphertext, RFC_A2_SAMPLE, sizeof (RFC_A2_SAMPLE)) == 0);

  /* Decrypt and verify round-trip */
  result = SocketQUICCrypto_decrypt_payload (&pkt_keys,
                                             2,
                                             RFC_A2_UNPROTECTED_HEADER,
                                             sizeof (RFC_A2_UNPROTECTED_HEADER),
                                             ciphertext,
                                             ciphertext_len,
                                             decrypted,
                                             &decrypted_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (plaintext_len, decrypted_len);
  ASSERT (memcmp (decrypted, plaintext, plaintext_len) == 0);

  SocketQUICInitialKeys_clear (&keys);
  SocketQUICPacketKeys_clear (&pkt_keys);
}

TEST (rfc9001_a2_client_initial_full_packet_start)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICInitialKeys_T keys;
  uint8_t packet[1400];
  uint8_t plaintext[1200];
  size_t ciphertext_len;
  size_t pn_offset = 18;

  /* Build plaintext */
  memset (plaintext, 0, sizeof (plaintext));
  memcpy (plaintext, RFC_A2_CRYPTO_FRAME, sizeof (RFC_A2_CRYPTO_FRAME));
  size_t plaintext_len = 1162;

  /* Derive keys */
  SocketQUICConnectionID_set (&dcid, RFC_DCID, sizeof (RFC_DCID));
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_derive_initial_keys (&dcid, QUIC_VERSION_1, &keys);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Copy unprotected header */
  memcpy (
      packet, RFC_A2_UNPROTECTED_HEADER, sizeof (RFC_A2_UNPROTECTED_HEADER));

  /* Build packet keys */
  SocketQUICPacketKeys_T pkt_keys;
  SocketQUICPacketKeys_init (&pkt_keys);
  memcpy (pkt_keys.key, keys.client_key, QUIC_INITIAL_KEY_LEN);
  memcpy (pkt_keys.iv, keys.client_iv, QUIC_INITIAL_IV_LEN);
  memcpy (pkt_keys.hp_key, keys.client_hp_key, QUIC_INITIAL_HP_KEY_LEN);
  pkt_keys.key_len = QUIC_INITIAL_KEY_LEN;
  pkt_keys.hp_len = QUIC_INITIAL_HP_KEY_LEN;
  pkt_keys.aead = QUIC_AEAD_AES_128_GCM;

  /* Encrypt payload */
  ciphertext_len = sizeof (packet) - sizeof (RFC_A2_UNPROTECTED_HEADER);
  result = SocketQUICCrypto_encrypt_payload (
      &pkt_keys,
      2,
      RFC_A2_UNPROTECTED_HEADER,
      sizeof (RFC_A2_UNPROTECTED_HEADER),
      plaintext,
      plaintext_len,
      packet + sizeof (RFC_A2_UNPROTECTED_HEADER),
      &ciphertext_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  size_t packet_len = sizeof (RFC_A2_UNPROTECTED_HEADER) + ciphertext_len;

  /* Apply header protection */
  result = SocketQUICCrypto_protect_header (keys.client_hp_key,
                                            QUIC_INITIAL_HP_KEY_LEN,
                                            QUIC_AEAD_AES_128_GCM,
                                            packet,
                                            packet_len,
                                            pn_offset);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Verify first 64 bytes match RFC */
  ASSERT (memcmp (packet,
                  RFC_A2_PROTECTED_PACKET_START,
                  sizeof (RFC_A2_PROTECTED_PACKET_START))
          == 0);

  SocketQUICInitialKeys_clear (&keys);
  SocketQUICPacketKeys_clear (&pkt_keys);
}

TEST (rfc9001_a3_server_initial_header_protect)
{
  uint8_t packet[128];
  size_t pn_offset = 18;

  /* Build test packet: header + sample at pn_offset + 4 */
  memcpy (
      packet, RFC_A3_UNPROTECTED_HEADER, sizeof (RFC_A3_UNPROTECTED_HEADER));
  memcpy (packet + pn_offset + 4, RFC_A3_SAMPLE, sizeof (RFC_A3_SAMPLE));

  size_t packet_len = pn_offset + 4 + sizeof (RFC_A3_SAMPLE);

  /* Apply header protection */
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_protect_header (RFC_A1_SERVER_HP,
                                         sizeof (RFC_A1_SERVER_HP),
                                         QUIC_AEAD_AES_128_GCM,
                                         packet,
                                         packet_len,
                                         pn_offset);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Verify first byte: 0xc1 ^ (0x2e & 0x0f) = 0xcf */
  ASSERT_EQ (RFC_A3_PROTECTED_HEADER[0], packet[0]);

  /* Verify packet number bytes */
  ASSERT_EQ (RFC_A3_PROTECTED_HEADER[18], packet[18]);
  ASSERT_EQ (RFC_A3_PROTECTED_HEADER[19], packet[19]);
}

TEST (rfc9001_a3_server_initial_mask_verify)
{
  /*
   * Verify mask by computing XOR difference between protected/unprotected.
   * RFC 9001 A.3 mask = 2ec0d8356a
   *
   * For long header: first byte masked with mask[0] & 0x0F
   *   0xC1 ^ (0x2E & 0x0F) = 0xC1 ^ 0x0E = 0xCF ✓
   * Packet number (2 bytes) XOR with mask[1..2]:
   *   0x0001 ^ 0xc0d8 = 0xc0d9 ✓
   */

  /* First byte: extract mask[0] & 0x0F from XOR */
  uint8_t first_byte_diff
      = RFC_A3_UNPROTECTED_HEADER[0] ^ RFC_A3_PROTECTED_HEADER[0];
  uint8_t expected_mask_low = RFC_A3_MASK[0] & 0x0F;
  ASSERT_EQ (expected_mask_low, first_byte_diff);

  /* Packet number bytes (offset 18-19, 2-byte PN) */
  uint8_t pn_mask_1
      = RFC_A3_UNPROTECTED_HEADER[18] ^ RFC_A3_PROTECTED_HEADER[18];
  uint8_t pn_mask_2
      = RFC_A3_UNPROTECTED_HEADER[19] ^ RFC_A3_PROTECTED_HEADER[19];

  ASSERT_EQ (RFC_A3_MASK[1], pn_mask_1);
  ASSERT_EQ (RFC_A3_MASK[2], pn_mask_2);
}

TEST (rfc9001_a3_server_initial_full_packet)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICInitialKeys_T keys;
  uint8_t packet[256];
  size_t ciphertext_len;
  size_t pn_offset = 18;

  /* Derive keys */
  SocketQUICConnectionID_set (&dcid, RFC_DCID, sizeof (RFC_DCID));
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_derive_initial_keys (&dcid, QUIC_VERSION_1, &keys);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Copy unprotected header */
  memcpy (
      packet, RFC_A3_UNPROTECTED_HEADER, sizeof (RFC_A3_UNPROTECTED_HEADER));

  /* Build packet keys */
  SocketQUICPacketKeys_T pkt_keys;
  SocketQUICPacketKeys_init (&pkt_keys);
  memcpy (pkt_keys.key, keys.server_key, QUIC_INITIAL_KEY_LEN);
  memcpy (pkt_keys.iv, keys.server_iv, QUIC_INITIAL_IV_LEN);
  memcpy (pkt_keys.hp_key, keys.server_hp_key, QUIC_INITIAL_HP_KEY_LEN);
  pkt_keys.key_len = QUIC_INITIAL_KEY_LEN;
  pkt_keys.hp_len = QUIC_INITIAL_HP_KEY_LEN;
  pkt_keys.aead = QUIC_AEAD_AES_128_GCM;

  /* Encrypt payload with packet number 1 */
  ciphertext_len = sizeof (packet) - sizeof (RFC_A3_UNPROTECTED_HEADER);
  result = SocketQUICCrypto_encrypt_payload (
      &pkt_keys,
      1, /* packet number */
      RFC_A3_UNPROTECTED_HEADER,
      sizeof (RFC_A3_UNPROTECTED_HEADER),
      RFC_A3_PAYLOAD,
      sizeof (RFC_A3_PAYLOAD),
      packet + sizeof (RFC_A3_UNPROTECTED_HEADER),
      &ciphertext_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  size_t packet_len = sizeof (RFC_A3_UNPROTECTED_HEADER) + ciphertext_len;

  /* Apply header protection */
  result = SocketQUICCrypto_protect_header (keys.server_hp_key,
                                            QUIC_INITIAL_HP_KEY_LEN,
                                            QUIC_AEAD_AES_128_GCM,
                                            packet,
                                            packet_len,
                                            pn_offset);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Verify full packet matches RFC */
  ASSERT_EQ (sizeof (RFC_A3_PROTECTED_PACKET), packet_len);
  ASSERT (memcmp (packet, RFC_A3_PROTECTED_PACKET, packet_len) == 0);

  SocketQUICInitialKeys_clear (&keys);
  SocketQUICPacketKeys_clear (&pkt_keys);
}

TEST (rfc9001_a3_server_initial_decrypt)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICInitialKeys_T keys;
  uint8_t packet[256];
  uint8_t decrypted[256];
  size_t decrypted_len = sizeof (decrypted);
  size_t pn_offset = 18;

  /* Copy protected packet */
  memcpy (packet, RFC_A3_PROTECTED_PACKET, sizeof (RFC_A3_PROTECTED_PACKET));

  /* Derive keys */
  SocketQUICConnectionID_set (&dcid, RFC_DCID, sizeof (RFC_DCID));
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_derive_initial_keys (&dcid, QUIC_VERSION_1, &keys);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Remove header protection */
  result = SocketQUICCrypto_unprotect_header (keys.server_hp_key,
                                              QUIC_INITIAL_HP_KEY_LEN,
                                              QUIC_AEAD_AES_128_GCM,
                                              packet,
                                              sizeof (RFC_A3_PROTECTED_PACKET),
                                              pn_offset);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Verify header is unprotected */
  ASSERT (memcmp (packet,
                  RFC_A3_UNPROTECTED_HEADER,
                  sizeof (RFC_A3_UNPROTECTED_HEADER))
          == 0);

  /* Build packet keys */
  SocketQUICPacketKeys_T pkt_keys;
  SocketQUICPacketKeys_init (&pkt_keys);
  memcpy (pkt_keys.key, keys.server_key, QUIC_INITIAL_KEY_LEN);
  memcpy (pkt_keys.iv, keys.server_iv, QUIC_INITIAL_IV_LEN);
  pkt_keys.key_len = QUIC_INITIAL_KEY_LEN;
  pkt_keys.hp_len = QUIC_INITIAL_HP_KEY_LEN;
  pkt_keys.aead = QUIC_AEAD_AES_128_GCM;

  /* Decrypt */
  size_t ciphertext_len
      = sizeof (RFC_A3_PROTECTED_PACKET) - sizeof (RFC_A3_UNPROTECTED_HEADER);
  result = SocketQUICCrypto_decrypt_payload (
      &pkt_keys,
      1, /* packet number */
      RFC_A3_UNPROTECTED_HEADER,
      sizeof (RFC_A3_UNPROTECTED_HEADER),
      packet + sizeof (RFC_A3_UNPROTECTED_HEADER),
      ciphertext_len,
      decrypted,
      &decrypted_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Verify payload */
  ASSERT_EQ (sizeof (RFC_A3_PAYLOAD), decrypted_len);
  ASSERT (memcmp (decrypted, RFC_A3_PAYLOAD, decrypted_len) == 0);

  SocketQUICInitialKeys_clear (&keys);
  SocketQUICPacketKeys_clear (&pkt_keys);
}

TEST (rfc9001_a4_retry_tag_compute)
{
  SocketQUICConnectionID_T odcid;
  uint8_t computed_tag[QUIC_RETRY_INTEGRITY_TAG_LEN];

  SocketQUICConnectionID_init (&odcid);
  odcid.len = sizeof (RFC_DCID);
  memcpy (odcid.data, RFC_DCID, sizeof (RFC_DCID));

  SocketQUICPacket_Result result = SocketQUICPacket_compute_retry_tag (
      &odcid, RFC_A4_RETRY_NO_TAG, sizeof (RFC_A4_RETRY_NO_TAG), computed_tag);

  ASSERT_EQ (QUIC_PACKET_OK, result);
  ASSERT (
      memcmp (computed_tag, RFC_A4_INTEGRITY_TAG, QUIC_RETRY_INTEGRITY_TAG_LEN)
      == 0);
}

TEST (rfc9001_a4_retry_tag_verify)
{
  SocketQUICConnectionID_T odcid;

  SocketQUICConnectionID_init (&odcid);
  odcid.len = sizeof (RFC_DCID);
  memcpy (odcid.data, RFC_DCID, sizeof (RFC_DCID));

  SocketQUICPacket_Result result = SocketQUICPacket_verify_retry_tag (
      &odcid, RFC_A4_RETRY_PACKET, sizeof (RFC_A4_RETRY_PACKET));

  ASSERT_EQ (QUIC_PACKET_OK, result);
}

TEST (rfc9001_a4_retry_full_packet)
{
  SocketQUICConnectionID_T odcid;
  uint8_t packet[36];
  uint8_t tag[QUIC_RETRY_INTEGRITY_TAG_LEN];

  SocketQUICConnectionID_init (&odcid);
  odcid.len = sizeof (RFC_DCID);
  memcpy (odcid.data, RFC_DCID, sizeof (RFC_DCID));

  /* Build packet: copy packet without tag, then append computed tag */
  memcpy (packet, RFC_A4_RETRY_NO_TAG, sizeof (RFC_A4_RETRY_NO_TAG));

  SocketQUICPacket_Result result = SocketQUICPacket_compute_retry_tag (
      &odcid, RFC_A4_RETRY_NO_TAG, sizeof (RFC_A4_RETRY_NO_TAG), tag);
  ASSERT_EQ (QUIC_PACKET_OK, result);

  memcpy (packet + sizeof (RFC_A4_RETRY_NO_TAG), tag, sizeof (tag));

  /* Verify complete packet matches RFC */
  ASSERT (memcmp (packet, RFC_A4_RETRY_PACKET, sizeof (RFC_A4_RETRY_PACKET))
          == 0);
}

TEST (rfc9001_a5_chacha20_key_derivation)
{
  SocketQUICPacketKeys_T keys;

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_derive_packet_keys (RFC_A5_SECRET,
                                             sizeof (RFC_A5_SECRET),
                                             QUIC_AEAD_CHACHA20_POLY1305,
                                             &keys);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT (memcmp (keys.key, RFC_A5_KEY, sizeof (RFC_A5_KEY)) == 0);
  ASSERT (memcmp (keys.iv, RFC_A5_IV, sizeof (RFC_A5_IV)) == 0);
  ASSERT (memcmp (keys.hp_key, RFC_A5_HP, sizeof (RFC_A5_HP)) == 0);

  SocketQUICPacketKeys_clear (&keys);
}

TEST (rfc9001_a5_chacha20_encrypt)
{
  SocketQUICPacketKeys_T keys;
  uint8_t ciphertext[32];
  size_t ciphertext_len = sizeof (ciphertext);

  /* Setup keys */
  SocketQUICPacketKeys_init (&keys);
  memcpy (keys.key, RFC_A5_KEY, sizeof (RFC_A5_KEY));
  memcpy (keys.iv, RFC_A5_IV, sizeof (RFC_A5_IV));
  keys.key_len = sizeof (RFC_A5_KEY);
  keys.hp_len = sizeof (RFC_A5_HP);
  keys.aead = QUIC_AEAD_CHACHA20_POLY1305;

  /* Encrypt PING frame with packet number 654360564 */
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_encrypt_payload (&keys,
                                          RFC_A5_PACKET_NUMBER,
                                          RFC_A5_UNPROTECTED_HEADER,
                                          sizeof (RFC_A5_UNPROTECTED_HEADER),
                                          RFC_A5_PLAINTEXT,
                                          sizeof (RFC_A5_PLAINTEXT),
                                          ciphertext,
                                          &ciphertext_len);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (sizeof (RFC_A5_CIPHERTEXT), ciphertext_len);
  ASSERT (memcmp (ciphertext, RFC_A5_CIPHERTEXT, ciphertext_len) == 0);

  SocketQUICPacketKeys_clear (&keys);
}

TEST (rfc9001_a5_chacha20_header_protect)
{
  uint8_t packet[64];
  size_t pn_offset = 1; /* Short header: pn immediately after first byte */

  /* Build test packet: 4-byte header + ciphertext (sample at offset 1) */
  memcpy (
      packet, RFC_A5_UNPROTECTED_HEADER, sizeof (RFC_A5_UNPROTECTED_HEADER));
  memcpy (packet + sizeof (RFC_A5_UNPROTECTED_HEADER),
          RFC_A5_CIPHERTEXT,
          sizeof (RFC_A5_CIPHERTEXT));

  size_t packet_len
      = sizeof (RFC_A5_UNPROTECTED_HEADER) + sizeof (RFC_A5_CIPHERTEXT);

  /* Apply header protection */
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_protect_header (RFC_A5_HP,
                                         sizeof (RFC_A5_HP),
                                         QUIC_AEAD_CHACHA20_POLY1305,
                                         packet,
                                         packet_len,
                                         pn_offset);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Verify protected header */
  ASSERT (
      memcmp (packet, RFC_A5_PROTECTED_HEADER, sizeof (RFC_A5_PROTECTED_HEADER))
      == 0);
}

TEST (rfc9001_a5_chacha20_mask_verify)
{
  /*
   * Verify mask by computing XOR difference between protected/unprotected.
   * RFC 9001 A.5 mask = aefefe7d03
   *
   * For short header: first byte masked with mask[0] & 0x1F (5 bits)
   *   0x42 ^ (0xAE & 0x1F) = 0x42 ^ 0x0E = 0x4C ✓
   * Packet number (3 bytes) XOR with mask[1..3]:
   *   0x00bff4 ^ 0xfefe7d = 0xfe4189 ✓
   */

  /* First byte: for short header, lower 5 bits are masked */
  uint8_t first_byte_diff
      = RFC_A5_UNPROTECTED_HEADER[0] ^ RFC_A5_PROTECTED_HEADER[0];
  uint8_t expected_mask_low = RFC_A5_MASK[0] & 0x1F;
  ASSERT_EQ (expected_mask_low, first_byte_diff);

  /* Packet number bytes (offset 1-3, 3-byte PN) */
  uint8_t pn_mask_1 = RFC_A5_UNPROTECTED_HEADER[1] ^ RFC_A5_PROTECTED_HEADER[1];
  uint8_t pn_mask_2 = RFC_A5_UNPROTECTED_HEADER[2] ^ RFC_A5_PROTECTED_HEADER[2];
  uint8_t pn_mask_3 = RFC_A5_UNPROTECTED_HEADER[3] ^ RFC_A5_PROTECTED_HEADER[3];

  ASSERT_EQ (RFC_A5_MASK[1], pn_mask_1);
  ASSERT_EQ (RFC_A5_MASK[2], pn_mask_2);
  ASSERT_EQ (RFC_A5_MASK[3], pn_mask_3);
}

TEST (rfc9001_a5_chacha20_nonce_verify)
{
  /*
   * Verify nonce construction per RFC 9001 Section 5.3.
   * nonce = IV XOR packet_number (left-padded to IV length)
   *
   * IV:            e0459b3474bdd0e44a41c144
   * packet_number: 654360564 = 0x2700bff4
   * padded PN:     000000002700bff4 (as 12 bytes: 00000000 00000000 2700bff4)
   *
   * nonce = e0459b3474bdd0e46d417eb0
   */
  uint8_t computed_nonce[12];
  uint8_t pn_bytes[12] = { 0 };

  /* Encode packet number in big-endian, right-aligned in 12 bytes */
  pn_bytes[8] = (RFC_A5_PACKET_NUMBER >> 24) & 0xFF;
  pn_bytes[9] = (RFC_A5_PACKET_NUMBER >> 16) & 0xFF;
  pn_bytes[10] = (RFC_A5_PACKET_NUMBER >> 8) & 0xFF;
  pn_bytes[11] = RFC_A5_PACKET_NUMBER & 0xFF;

  /* XOR IV with packet number */
  for (size_t i = 0; i < 12; i++)
    computed_nonce[i] = RFC_A5_IV[i] ^ pn_bytes[i];

  /* Verify nonce matches RFC */
  ASSERT (memcmp (computed_nonce, RFC_A5_NONCE, sizeof (RFC_A5_NONCE)) == 0);
}

TEST (rfc9001_a5_chacha20_full_packet)
{
  SocketQUICPacketKeys_T keys;
  uint8_t packet[64];
  size_t ciphertext_len;
  size_t pn_offset = 1;

  /* Setup keys */
  SocketQUICPacketKeys_init (&keys);
  memcpy (keys.key, RFC_A5_KEY, sizeof (RFC_A5_KEY));
  memcpy (keys.iv, RFC_A5_IV, sizeof (RFC_A5_IV));
  memcpy (keys.hp_key, RFC_A5_HP, sizeof (RFC_A5_HP));
  keys.key_len = sizeof (RFC_A5_KEY);
  keys.hp_len = sizeof (RFC_A5_HP);
  keys.aead = QUIC_AEAD_CHACHA20_POLY1305;

  /* Copy unprotected header */
  memcpy (
      packet, RFC_A5_UNPROTECTED_HEADER, sizeof (RFC_A5_UNPROTECTED_HEADER));

  /* Encrypt payload */
  ciphertext_len = sizeof (packet) - sizeof (RFC_A5_UNPROTECTED_HEADER);
  SocketQUICCrypto_Result result = SocketQUICCrypto_encrypt_payload (
      &keys,
      RFC_A5_PACKET_NUMBER,
      RFC_A5_UNPROTECTED_HEADER,
      sizeof (RFC_A5_UNPROTECTED_HEADER),
      RFC_A5_PLAINTEXT,
      sizeof (RFC_A5_PLAINTEXT),
      packet + sizeof (RFC_A5_UNPROTECTED_HEADER),
      &ciphertext_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  size_t packet_len = sizeof (RFC_A5_UNPROTECTED_HEADER) + ciphertext_len;

  /* Apply header protection */
  result = SocketQUICCrypto_protect_header (
      keys.hp_key, keys.hp_len, keys.aead, packet, packet_len, pn_offset);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Verify complete protected packet */
  ASSERT_EQ (sizeof (RFC_A5_PROTECTED_PACKET), packet_len);
  ASSERT (memcmp (packet, RFC_A5_PROTECTED_PACKET, packet_len) == 0);

  SocketQUICPacketKeys_clear (&keys);
}

TEST (rfc9001_a5_chacha20_decrypt)
{
  SocketQUICPacketKeys_T keys;
  uint8_t packet[64];
  uint8_t decrypted[32];
  size_t decrypted_len = sizeof (decrypted);
  size_t pn_offset = 1;

  /* Copy protected packet */
  memcpy (packet, RFC_A5_PROTECTED_PACKET, sizeof (RFC_A5_PROTECTED_PACKET));

  /* Setup keys */
  SocketQUICPacketKeys_init (&keys);
  memcpy (keys.key, RFC_A5_KEY, sizeof (RFC_A5_KEY));
  memcpy (keys.iv, RFC_A5_IV, sizeof (RFC_A5_IV));
  memcpy (keys.hp_key, RFC_A5_HP, sizeof (RFC_A5_HP));
  keys.key_len = sizeof (RFC_A5_KEY);
  keys.hp_len = sizeof (RFC_A5_HP);
  keys.aead = QUIC_AEAD_CHACHA20_POLY1305;

  /* Remove header protection */
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_unprotect_header (keys.hp_key,
                                           keys.hp_len,
                                           keys.aead,
                                           packet,
                                           sizeof (RFC_A5_PROTECTED_PACKET),
                                           pn_offset);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Verify header is unprotected */
  ASSERT (memcmp (packet,
                  RFC_A5_UNPROTECTED_HEADER,
                  sizeof (RFC_A5_UNPROTECTED_HEADER))
          == 0);

  /* Decrypt */
  size_t ciphertext_len
      = sizeof (RFC_A5_PROTECTED_PACKET) - sizeof (RFC_A5_UNPROTECTED_HEADER);
  result = SocketQUICCrypto_decrypt_payload (
      &keys,
      RFC_A5_PACKET_NUMBER,
      RFC_A5_UNPROTECTED_HEADER,
      sizeof (RFC_A5_UNPROTECTED_HEADER),
      packet + sizeof (RFC_A5_UNPROTECTED_HEADER),
      ciphertext_len,
      decrypted,
      &decrypted_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Verify payload is PING frame */
  ASSERT_EQ (sizeof (RFC_A5_PLAINTEXT), decrypted_len);
  ASSERT (memcmp (decrypted, RFC_A5_PLAINTEXT, decrypted_len) == 0);

  SocketQUICPacketKeys_clear (&keys);
}

TEST (rfc9001_a5_chacha20_key_update_secret)
{
  uint8_t next_secret[32];

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_derive_next_secret (RFC_A5_SECRET,
                                             sizeof (RFC_A5_SECRET),
                                             QUIC_AEAD_CHACHA20_POLY1305,
                                             next_secret);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT (memcmp (next_secret, RFC_A5_KU, sizeof (RFC_A5_KU)) == 0);
}

#endif /* SOCKET_HAS_TLS */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}
