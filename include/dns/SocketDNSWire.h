/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETDNSWIRE_INCLUDED
#define SOCKETDNSWIRE_INCLUDED

/**
 * @file SocketDNSWire.h
 * @brief DNS wire format encoding/decoding (RFC 1035).
 * @ingroup dns
 *
 * Implements DNS message wire format as specified in RFC 1035 Section 4.1.
 * This module handles serialization and deserialization of DNS protocol
 * messages for network transmission.
 *
 * ## RFC References
 *
 * - RFC 1035 Section 4.1.1: Header format
 * - RFC 1035 Section 4.1.2: Question section format
 * - RFC 1035 Section 4.1.3: Resource record format
 *
 * @see SocketDNS.h for the async resolver API.
 */

#include "core/Except.h"
#include <stddef.h>
#include <stdint.h>

/**
 * @defgroup dns_wire DNS Wire Format
 * @brief DNS message encoding and decoding.
 * @ingroup dns
 * @{
 */

/** DNS message header size in bytes (RFC 1035 Section 4.1.1). */
#define DNS_HEADER_SIZE 12

/**
 * @brief DNS operation codes (RFC 1035 Section 4.1.1).
 *
 * OPCODE field values for DNS header. Specifies the kind of query.
 */
typedef enum
{
  DNS_OPCODE_QUERY = 0,  /**< Standard query (QUERY) */
  DNS_OPCODE_IQUERY = 1, /**< Inverse query (IQUERY, obsolete) */
  DNS_OPCODE_STATUS = 2, /**< Server status request (STATUS) */
  DNS_OPCODE_NOTIFY = 4, /**< Zone change notification (RFC 1996) */
  DNS_OPCODE_UPDATE = 5  /**< Dynamic update (RFC 2136) */
} SocketDNS_Opcode;

/**
 * @brief DNS response codes (RFC 1035 Section 4.1.1).
 *
 * RCODE field values indicating response status.
 */
typedef enum
{
  DNS_RCODE_NOERROR = 0,  /**< No error condition */
  DNS_RCODE_FORMERR = 1,  /**< Format error - server could not interpret */
  DNS_RCODE_SERVFAIL = 2, /**< Server failure - internal error */
  DNS_RCODE_NXDOMAIN = 3, /**< Name Error - domain does not exist */
  DNS_RCODE_NOTIMP = 4,   /**< Not Implemented - query type not supported */
  DNS_RCODE_REFUSED = 5,  /**< Refused - policy restriction */
  DNS_RCODE_YXDOMAIN = 6, /**< Name exists when it should not (RFC 2136) */
  DNS_RCODE_YXRRSET = 7,  /**< RR set exists when it should not (RFC 2136) */
  DNS_RCODE_NXRRSET = 8,  /**< RR set does not exist (RFC 2136) */
  DNS_RCODE_NOTAUTH = 9,  /**< Server not authoritative (RFC 2136) */
  DNS_RCODE_NOTZONE = 10  /**< Name not in zone (RFC 2136) */
} SocketDNS_Rcode;

/**
 * @brief DNS message header structure (unpacked representation).
 *
 * Represents the 12-byte DNS header in an easily accessible form.
 * Use SocketDNS_header_encode() to serialize to wire format and
 * SocketDNS_header_decode() to parse from wire format.
 *
 * ## Wire Format (RFC 1035 Section 4.1.1)
 *
 * ```
 *                                 1  1  1  1  1  1
 *   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                      ID                       |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    QDCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    ANCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    NSCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    ARCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * ```
 */
typedef struct
{
  uint16_t id; /**< Query identifier (matches responses to queries) */

  /* Flags - bits 15-0 of the second 16-bit word */
  uint8_t qr;     /**< Query (0) or Response (1) - bit 15 */
  uint8_t opcode; /**< Operation code (4 bits) - bits 14-11 */
  uint8_t aa;     /**< Authoritative Answer - bit 10 */
  uint8_t tc;     /**< TrunCation - bit 9 */
  uint8_t rd;     /**< Recursion Desired - bit 8 */
  uint8_t ra;     /**< Recursion Available - bit 7 */
  uint8_t z;      /**< Reserved, must be 0 (3 bits) - bits 6-4 */
  uint8_t rcode;  /**< Response code (4 bits) - bits 3-0 */

  /* Section counts */
  uint16_t qdcount; /**< Number of entries in Question section */
  uint16_t ancount; /**< Number of entries in Answer section */
  uint16_t nscount; /**< Number of entries in Authority section */
  uint16_t arcount; /**< Number of entries in Additional section */
} SocketDNS_Header;

/**
 * @brief DNS wire format operation failure exception.
 * @ingroup dns_wire
 *
 * Raised when DNS wire format encoding or decoding fails due to:
 * - Buffer too small
 * - Invalid field values
 * - Malformed input data
 */
extern const Except_T SocketDNS_WireError;

/**
 * @brief Encode DNS header to wire format.
 * @ingroup dns_wire
 *
 * Serializes a DNS header structure to the 12-byte network format
 * as specified in RFC 1035 Section 4.1.1. All multi-byte fields
 * are encoded in network byte order (big-endian).
 *
 * @param[in]  header  Header structure to encode.
 * @param[out] buf     Output buffer (must be at least DNS_HEADER_SIZE bytes).
 * @param[in]  buflen  Size of output buffer.
 * @return 0 on success, -1 on error (buffer too small or NULL pointers).
 *
 * @code{.c}
 * SocketDNS_Header header = {
 *     .id = 0x1234,
 *     .qr = 0,           // Query
 *     .opcode = DNS_OPCODE_QUERY,
 *     .rd = 1,           // Recursion desired
 *     .qdcount = 1       // One question
 * };
 * unsigned char buf[DNS_HEADER_SIZE];
 * if (SocketDNS_header_encode(&header, buf, sizeof(buf)) == 0) {
 *     // buf now contains wire format header
 * }
 * @endcode
 *
 * @see SocketDNS_header_decode() for parsing wire format.
 */
extern int SocketDNS_header_encode (const SocketDNS_Header *header,
                                    unsigned char *buf, size_t buflen);

/**
 * @brief Decode DNS header from wire format.
 * @ingroup dns_wire
 *
 * Parses a 12-byte DNS header from network format into a structure.
 * Multi-byte fields are converted from network byte order (big-endian).
 *
 * @param[in]  data    Input buffer containing wire format header.
 * @param[in]  datalen Size of input buffer (must be >= DNS_HEADER_SIZE).
 * @param[out] header  Output header structure.
 * @return 0 on success, -1 on error (buffer too small or NULL pointers).
 *
 * @code{.c}
 * unsigned char packet[512];
 * // ... receive packet from network ...
 * SocketDNS_Header header;
 * if (SocketDNS_header_decode(packet, packet_len, &header) == 0) {
 *     if (header.qr == 1 && header.rcode == DNS_RCODE_NOERROR) {
 *         // Process successful response
 *     }
 * }
 * @endcode
 *
 * @see SocketDNS_header_encode() for creating wire format.
 */
extern int SocketDNS_header_decode (const unsigned char *data, size_t datalen,
                                    SocketDNS_Header *header);

/**
 * @brief Initialize a DNS header for a standard query.
 * @ingroup dns_wire
 *
 * Convenience function to set up a header for a typical recursive query.
 * Sets RD (recursion desired) and clears all other flags.
 *
 * @param[out] header  Header structure to initialize.
 * @param[in]  id      Query identifier.
 * @param[in]  qdcount Number of questions (typically 1).
 *
 * @code{.c}
 * SocketDNS_Header header;
 * SocketDNS_header_init_query(&header, random_id(), 1);
 * // header is now ready to encode
 * @endcode
 */
extern void SocketDNS_header_init_query (SocketDNS_Header *header, uint16_t id,
                                         uint16_t qdcount);

/** @} */ /* End of dns_wire group */

#endif /* SOCKETDNSWIRE_INCLUDED */
