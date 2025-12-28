/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICConstants.h
 * @brief Shared constants for QUIC implementation.
 *
 * Consolidates common constants used across multiple QUIC modules to ensure
 * consistency and provide a single source of truth for protocol values.
 *
 * @defgroup quic_constants QUIC Shared Constants
 * @{
 */

#ifndef SOCKETQUICCONSTANTS_INCLUDED
#define SOCKETQUICCONSTANTS_INCLUDED

#include <stdint.h>

/* ============================================================================
 * Hash Constants (FNV-1a)
 * ============================================================================
 *
 * FNV-1a is used for connection ID hashing and address pair hashing.
 * These constants provide good distribution for hash tables.
 *
 * @see http://www.isthe.com/chongo/tech/comp/fnv/
 */

/**
 * @brief FNV-1a offset basis (32-bit).
 *
 * The initial hash value for FNV-1a algorithm.
 */
#define QUIC_HASH_FNV1A_OFFSET_BASIS 2166136261u

/**
 * @brief FNV-1a prime multiplier (32-bit).
 *
 * The prime used in each iteration of FNV-1a.
 */
#define QUIC_HASH_FNV1A_PRIME 16777619u

/* ============================================================================
 * HKDF Label Constants (RFC 8446)
 * ============================================================================
 */

/**
 * @brief Maximum size of HKDF label buffer.
 *
 * Per RFC 8446 Section 7.1, the HkdfLabel structure is:
 *   2 bytes: length (big-endian)
 *   1 byte: label length
 *   6 bytes: "tls13 " prefix
 *   variable: label (max 255 bytes)
 *   1 byte: context length
 *   variable: context (max 255 bytes)
 *
 * Maximum: 2 + 1 + 6 + 255 + 1 + 255 = 520 bytes
 */
#define QUIC_HKDF_LABEL_MAX_SIZE 520

/* ============================================================================
 * Congestion Control Constants (RFC 9002)
 * ============================================================================
 */

/**
 * @brief Maximum datagram size used for CWND calculations.
 *
 * RFC 9000 Section 14: Minimum supported datagram size is 1200 bytes.
 */
#define QUIC_MAX_DATAGRAM_SIZE 1200

/**
 * @brief Initial congestion window in datagrams (RFC 9002 Section 7.2).
 *
 * initial_window = min(10 * max_datagram_size, max(14720, 2 * max_datagram_size))
 * For 1200-byte datagrams: 10 * 1200 = 12000 bytes
 */
#define QUIC_INITIAL_CWND_PACKETS 10

/**
 * @brief Initial congestion window in bytes.
 */
#define QUIC_INITIAL_CWND (QUIC_INITIAL_CWND_PACKETS * QUIC_MAX_DATAGRAM_SIZE)

/**
 * @brief Maximum congestion window in bytes.
 *
 * Practical limit to prevent excessive buffering.
 */
#define QUIC_MAX_CWND (1024 * 1024)

/**
 * @brief Initial RTT estimate in microseconds (RFC 9002 Section 6.2.2).
 *
 * Before any RTT measurement, use 333ms as initial estimate.
 * Note: Some implementations use 500ms for more conservative behavior.
 */
#define QUIC_INITIAL_RTT_US 500000

/**
 * @brief RTT smoothing factor (RFC 6298).
 *
 * SRTT = (1 - alpha) * SRTT + alpha * RTT
 * Standard value: alpha = 1/8 = 0.125
 */
#define QUIC_RTT_ALPHA 0.125

/**
 * @brief RTT variance smoothing factor (RFC 6298).
 *
 * RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - RTT|
 * Standard value: beta = 1/4 = 0.25
 */
#define QUIC_RTT_BETA 0.25

/**
 * @brief RTT smoothing using integer arithmetic (RFC 6298/RFC 9002).
 *
 * Integer-based constants for EWMA smoothing without floating-point arithmetic:
 * - smoothed_rtt = (1 - 1/8) * smoothed_rtt + 1/8 * rtt_sample
 *                = (7 * smoothed_rtt + rtt_sample) / 8
 * - rtt_var = (1 - 1/4) * rtt_var + 1/4 * |smoothed_rtt - rtt_sample|
 *           = (3 * rtt_var + |smoothed_rtt - rtt_sample|) / 4
 *
 * These constants map to floating-point equivalents QUIC_RTT_ALPHA and QUIC_RTT_BETA.
 */

/**
 * @brief Numerator for smoothed RTT: (1 - alpha) = 7/8.
 */
#define QUIC_RTT_SMOOTH_WEIGHT 7

/**
 * @brief Denominator for smoothed RTT calculation.
 */
#define QUIC_RTT_SMOOTH_DENOM 8

/**
 * @brief Numerator for RTT variance: (1 - beta) = 3/4.
 */
#define QUIC_RTT_VAR_WEIGHT 3

/**
 * @brief Denominator for RTT variance calculation.
 */
#define QUIC_RTT_VAR_DENOM 4

/* ============================================================================
 * Loss Detection Constants (RFC 9002)
 * ============================================================================
 */

/**
 * @brief Default hash table size for sent packet tracking.
 *
 * Power of 2 for efficient modulo via bitmask.
 */
#define QUIC_SENT_PACKET_HASH_SIZE 128

/**
 * @brief Packet reordering threshold (RFC 9002 Section 6.1.1).
 *
 * Packets are declared lost after this many later packets are acknowledged.
 */
#define QUIC_PACKET_REORDER_THRESHOLD 3

/**
 * @brief Time reordering threshold numerator (RFC 9002 Section 6.1.2).
 *
 * time_threshold = max(kTimeThreshold * max(smoothed_rtt, latest_rtt), kGranularity)
 * kTimeThreshold = 9/8 = 1.125
 */
#define QUIC_TIME_THRESHOLD_NUM 9
#define QUIC_TIME_THRESHOLD_DEN 8

/**
 * @brief Timer granularity in microseconds (RFC 9002 Section 6.1.2).
 *
 * Minimum time threshold for loss detection.
 */
#define QUIC_TIMER_GRANULARITY_US 1000

/**
 * @brief PTO multiplier for closing/draining timeout.
 *
 * RFC 9000 Section 10.2: Closing period = 3 * PTO.
 */
#define QUIC_CLOSING_TIMEOUT_PTO_MULT 3

/* ============================================================================
 * Cryptographic Constants
 * ============================================================================
 */

/**
 * @brief AEAD authentication tag length in bytes.
 *
 * QUIC uses AES-GCM or ChaCha20-Poly1305, both with 16-byte tags.
 */
#define QUIC_AEAD_TAG_LEN 16

/**
 * @brief AEAD nonce/IV length in bytes.
 *
 * Both AES-GCM and ChaCha20-Poly1305 use 12-byte nonces.
 */
#define QUIC_AEAD_NONCE_LEN 12

/**
 * @brief Stateless reset token length in bytes (RFC 9000 Section 10.3).
 */
#define QUIC_STATELESS_RESET_TOKEN_LEN 16

/**
 * @brief Retry integrity tag length in bytes (RFC 9001 Section 5.8).
 */
#define QUIC_RETRY_INTEGRITY_TAG_LEN 16

/* ============================================================================
 * Header Protection Constants
 * ============================================================================
 */

/**
 * @brief Header protection sample offset from packet number.
 *
 * Sample starts 4 bytes after the start of the Packet Number field.
 */
#define QUIC_HP_SAMPLE_OFFSET 4

/**
 * @brief Header protection mask for long headers.
 *
 * Masks the lower 4 bits of the first byte (packet number length).
 */
#define QUIC_HP_LONG_HEADER_MASK 0x0F

/**
 * @brief Header protection mask for short headers.
 *
 * Masks the lower 5 bits of the first byte (key phase + packet number length).
 */
#define QUIC_HP_SHORT_HEADER_MASK 0x1F

/* ============================================================================
 * Address Validation Constants
 * ============================================================================
 */

/**
 * @brief Address validation token size in bytes.
 *
 * 8 (timestamp) + 16 (address hash) + 32 (HMAC) = 56 bytes
 */
#define QUIC_ADDR_VALIDATION_TOKEN_SIZE 56

/**
 * @brief Address hash size for tokens.
 */
#define QUIC_ADDR_HASH_SIZE 16

/**
 * @brief Minimum stateless reset packet size (RFC 9000 Section 10.3).
 *
 * 21 bytes minimum + 16-byte token + 1 byte unpredictable = 38 bytes minimum.
 */
#define QUIC_STATELESS_RESET_MIN_SIZE 38

/* ============================================================================
 * String Formatting Constants
 * ============================================================================
 */

/**
 * @brief Maximum length for formatted socket address string.
 *
 * Format: "[IPv6]:port"
 * - IPv6 address: up to INET6_ADDRSTRLEN (46 bytes including null)
 * - Brackets for IPv6: 2 characters '[' ']'
 * - Port separator: 1 character ':'
 * - Port number: up to 5 characters (65535)
 * - Null terminator: 1 character
 *
 * Total: 46 + 2 + 1 + 5 + 1 = 55 bytes minimum, rounded to 64 for alignment.
 */
#define QUIC_SOCKADDR_STRING_MAX 64

/* ============================================================================
 * Utility Macros
 * ============================================================================
 */

/**
 * @brief Compute FNV-1a hash step.
 *
 * @param hash Current hash value.
 * @param byte Byte to incorporate.
 * @return Updated hash value.
 */
#define QUIC_HASH_FNV1A_STEP(hash, byte) \
  (((hash) ^ (uint8_t)(byte)) * QUIC_HASH_FNV1A_PRIME)

/**
 * @brief Define result string lookup function from static array.
 *
 * Generates a standard result_string function that looks up error strings
 * from a static const array named `result_strings[]`.
 *
 * Usage:
 * @code
 * static const char *result_strings[] = {
 *   [QUIC_FOO_OK] = "OK",
 *   [QUIC_FOO_ERROR_NULL] = "NULL pointer",
 *   // ...
 * };
 * DEFINE_RESULT_STRING_FUNC(SocketQUICFoo, QUIC_FOO_ERROR_LAST)
 * @endcode
 *
 * @param prefix   Module prefix (e.g., SocketQUICAck)
 * @param max_val  Maximum valid result enum value
 */
#define DEFINE_RESULT_STRING_FUNC(prefix, max_val)                            \
  const char *prefix##_result_string (prefix##_Result result)                 \
  {                                                                           \
    if (result < 0 || result > (max_val))                                     \
      return "Unknown error";                                                 \
    return result_strings[result];                                            \
  }

/** @} */

#endif /* SOCKETQUICCONSTANTS_INCLUDED */
