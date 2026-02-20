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

/**
 * @brief MurmurHash3 64-bit finalizer mixing constant.
 *
 * Used in multiplicative hashing for avalanche effect in sequence number
 * hashing. This constant is part of the MurmurHash3 finalizer step and
 * ensures that similar input values produce well-distributed hash outputs.
 *
 * From MurmurHash3 by Austin Appleby (public domain).
 */
#define QUIC_HASH_MURMUR3_MIX 0xff51afd7ed558ccdULL

/**
 * @brief Knuth's multiplicative hash constant (32-bit).
 *
 * Used for integer hashing in hash tables. This is the 32-bit
 * golden ratio constant: 2^32 / φ where φ is the golden ratio.
 * Provides excellent distribution for sequential integer inputs.
 *
 * @see Donald Knuth, The Art of Computer Programming, Volume 3, Section 6.4
 */
#define QUIC_HASH_KNUTH_CONSTANT 2654435761ULL

/**
 * @brief TLS 1.3 label prefix length.
 *
 * Per RFC 8446 Section 7.1, all HKDF-Expand-Label operations use the
 * "tls13 " prefix (6 bytes including the space).
 */
#define QUIC_HKDF_TLS13_PREFIX_LEN 6

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

/**
 * @brief Stream ID increment value (RFC 9000 Section 2.1).
 *
 * Stream IDs increment by 4 to preserve the 2-bit type encoding
 * in bits 0-1. Same-type streams use IDs: 0, 4, 8, 12, ...
 *
 * The lower 2 bits of a stream ID encode:
 *   - Bit 0: Initiator (0=client, 1=server)
 *   - Bit 1: Directionality (0=bidirectional, 1=unidirectional)
 *
 * Incrementing by 4 preserves these bits, ensuring consecutive
 * stream IDs are of the same type.
 */
#define QUIC_STREAM_ID_INCREMENT 4

/**
 * @brief Maximum datagram size used for CWND calculations.
 *
 * RFC 9000 Section 14: Minimum supported datagram size is 1200 bytes.
 */
#define QUIC_MAX_DATAGRAM_SIZE 1200

/**
 * @brief Initial congestion window in datagrams (RFC 9002 Section 7.2).
 *
 * initial_window = min(10 * max_datagram_size, max(14720, 2 *
 * max_datagram_size)) For 1200-byte datagrams: 10 * 1200 = 12000 bytes
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
 * @brief Minimum congestion window in bytes (RFC 9002 Section 7.2).
 *
 * 2 * max_datagram_size = 2400 bytes.
 */
#define QUIC_MIN_CWND (2 * QUIC_MAX_DATAGRAM_SIZE)

/**
 * @brief Loss reduction factor numerator (RFC 9002 Section 7.3.2).
 *
 * NewReno halves the window on loss: factor = 1/2.
 */
#define QUIC_LOSS_REDUCTION_FACTOR_NUM 1
#define QUIC_LOSS_REDUCTION_FACTOR_DEN 2

/**
 * @brief Persistent congestion threshold (RFC 9002 Section 7.6).
 *
 * Duration = (smoothed_rtt + max(4*rttvar, granularity) + max_ack_delay) * 3.
 */
#define QUIC_PERSISTENT_CONGESTION_THRESHOLD 3

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
 * These constants map to floating-point equivalents QUIC_RTT_ALPHA and
 * QUIC_RTT_BETA.
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
 * time_threshold = max(kTimeThreshold * max(smoothed_rtt, latest_rtt),
 * kGranularity) kTimeThreshold = 9/8 = 1.125
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

/**
 * @brief Header Form bit (RFC 9000 §17.2).
 *
 * Bit 7 of the first byte: 1 = Long Header, 0 = Short Header.
 */
#define QUIC_HEADER_FORM_BIT 0x80

/**
 * @brief Packet Number Length mask (RFC 9000 §17.2, §17.3).
 *
 * Bottom 2 bits of the first byte encode (pn_length - 1).
 * Actual PN length = (first_byte & QUIC_PN_LENGTH_MASK) + 1.
 */
#define QUIC_PN_LENGTH_MASK 0x03

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

/**
 * @brief IPv4 address length in bytes.
 *
 * Standard IPv4 address size for preferred address encoding.
 */
#define QUIC_IPV4_ADDR_LEN 4

/**
 * @brief IPv6 address length in bytes.
 *
 * Standard IPv6 address size for preferred address encoding.
 */
#define QUIC_IPV6_ADDR_LEN 16

/**
 * @brief Port number length in bytes.
 *
 * Port encoded as big-endian uint16_t.
 */
#define QUIC_PORT_LEN 2

/**
 * @brief Minimum preferred address size in bytes.
 *
 * Minimum size when connection_id.len = 0:
 * IPv4 (4) + IPv4 port (2) + IPv6 (16) + IPv6 port (2) +
 * CID length (1) + CID (0) + Stateless Reset Token (16) = 41 bytes
 */
#define QUIC_PREFERRED_ADDR_MIN_SIZE 41

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

/**
 * @brief Typical idle timeout in milliseconds (30 seconds).
 *
 * RFC 9000 default is 0 (disabled), but 30 seconds is a reasonable
 * production value to detect dead connections while allowing for
 * temporary network issues.
 */
#define QUIC_TP_TYPICAL_IDLE_TIMEOUT_MS 30000

/**
 * @brief Typical initial max data (1 MB).
 *
 * RFC 9000 default is 0 (no data allowed), but 1 MB provides a
 * good starting point for connection-level flow control.
 */
#define QUIC_TP_TYPICAL_INITIAL_MAX_DATA (1024 * 1024)

/**
 * @brief Typical initial max stream data (256 KB).
 *
 * RFC 9000 default is 0 (no data allowed), but 256 KB allows
 * reasonable stream buffering for both bidirectional and
 * unidirectional streams.
 */
#define QUIC_TP_TYPICAL_INITIAL_MAX_STREAM_DATA (256 * 1024)

/**
 * @brief Typical initial max streams limit (100 streams).
 *
 * RFC 9000 default is 0 (no streams allowed), but 100 concurrent
 * streams is sufficient for most applications while preventing
 * resource exhaustion.
 */
#define QUIC_TP_TYPICAL_INITIAL_MAX_STREAMS 100

/**
 * @brief Typical active connection ID limit (8 CIDs).
 *
 * RFC 9000 default is 2 (minimum), but 8 provides flexibility for
 * connection migration and load balancing scenarios.
 */
#define QUIC_TP_TYPICAL_ACTIVE_CONNID_LIMIT 8

/**
 * @brief Maximum parameter ID trackable for duplicate detection.
 *
 * Limited to 63 because duplicate checking uses a 64-bit bitmap.
 * Parameters with ID >= 64 bypass duplicate detection, which is
 * acceptable per RFC 9000 Section 18.1 (ignore unknown parameters).
 *
 * Current known parameters (all < 64):
 *   0x00-0x10: Core parameters (RFC 9000)
 *   0x11: VERSION_INFO (RFC 9369)
 *   0x20: MAX_DATAGRAM_FRAME_SIZE (RFC 9221)
 */
#define QUIC_TP_DUPLICATE_CHECK_MAX_ID 63

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
#define DEFINE_RESULT_STRING_FUNC(prefix, max_val)            \
  const char *prefix##_result_string (prefix##_Result result) \
  {                                                           \
    if (result < 0 || result > (max_val))                     \
      return "Unknown error";                                 \
    return result_strings[result];                            \
  }

/** @} */

#endif /* SOCKETQUICCONSTANTS_INCLUDED */
