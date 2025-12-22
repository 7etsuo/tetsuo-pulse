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
#include <netinet/in.h>
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

/**
 * @defgroup dns_name DNS Domain Name Encoding
 * @brief Domain name wire format encoding and decoding.
 * @ingroup dns_wire
 * @{
 */

/** Maximum length of a single DNS label (RFC 1035 Section 2.3.4). */
#define DNS_MAX_LABEL_LEN 63

/** Maximum total length of a domain name in wire format (RFC 1035 Section 2.3.4). */
#define DNS_MAX_NAME_LEN 255

/** Compression pointer flag (high 2 bits = 11, RFC 1035 Section 4.1.4). */
#define DNS_COMPRESSION_FLAG 0xC0

/** Mask for compression pointer offset (14 bits). */
#define DNS_COMPRESSION_OFFSET_MASK 0x3FFF

/** Maximum depth for following compression pointers (prevents infinite loops). */
#define DNS_MAX_POINTER_HOPS 16

/**
 * @brief Encode a domain name to DNS wire format.
 * @ingroup dns_name
 *
 * Converts a human-readable domain name (e.g., "www.example.com") to the
 * wire format specified in RFC 1035 Section 4.1.2. Each label is encoded
 * as a length byte followed by the label data, terminated by a zero byte.
 *
 * @param[in]  name    NUL-terminated domain name string.
 * @param[out] buf     Output buffer for wire format.
 * @param[in]  buflen  Size of output buffer.
 * @param[out] written Number of bytes written (may be NULL).
 * @return 0 on success, -1 on error (invalid name, buffer too small).
 *
 * @code{.c}
 * unsigned char wire[DNS_MAX_NAME_LEN];
 * size_t len;
 * if (SocketDNS_name_encode("www.example.com", wire, sizeof(wire), &len) == 0) {
 *     // wire contains: [3]www[7]example[3]com[0]
 *     // len = 17
 * }
 * @endcode
 */
extern int SocketDNS_name_encode (const char *name, unsigned char *buf,
                                  size_t buflen, size_t *written);

/**
 * @brief Decode a domain name from DNS wire format (with compression support).
 * @ingroup dns_name
 *
 * Parses a domain name from wire format, handling both regular labels and
 * compression pointers as specified in RFC 1035 Sections 4.1.2 and 4.1.4.
 *
 * @param[in]  msg      Full DNS message buffer (needed for pointer resolution).
 * @param[in]  msglen   Total length of the DNS message.
 * @param[in]  offset   Offset within msg where the name starts.
 * @param[out] buf      Output buffer for decoded domain name.
 * @param[in]  buflen   Size of output buffer.
 * @param[out] consumed Bytes consumed from offset position (may be NULL).
 *                      This is the actual wire size, not the expanded size.
 * @return Length of decoded name on success, -1 on error.
 *
 * @code{.c}
 * char name[DNS_MAX_NAME_LEN];
 * size_t consumed;
 * int len = SocketDNS_name_decode(msg, msglen, 12, name, sizeof(name), &consumed);
 * if (len >= 0) {
 *     printf("Domain: %s (consumed %zu bytes)\n", name, consumed);
 * }
 * @endcode
 */
extern int SocketDNS_name_decode (const unsigned char *msg, size_t msglen,
                                  size_t offset, char *buf, size_t buflen,
                                  size_t *consumed);

/**
 * @brief Compare two domain names case-insensitively.
 * @ingroup dns_name
 *
 * Performs case-insensitive comparison as specified in RFC 1035 Section 2.3.3.
 * Non-alphabetic characters must match exactly. Trailing dots are normalized.
 *
 * @param[in] name1 First domain name.
 * @param[in] name2 Second domain name.
 * @return 1 if names are equal, 0 if different.
 */
extern int SocketDNS_name_equal (const char *name1, const char *name2);

/**
 * @brief Validate a domain name string.
 * @ingroup dns_name
 *
 * Checks that the domain name conforms to RFC 1035 constraints:
 * - Each label is 63 octets or less
 * - Total wire length is 255 octets or less
 * - No empty labels (except for root)
 *
 * @param[in] name Domain name to validate.
 * @return 1 if valid, 0 if invalid.
 */
extern int SocketDNS_name_valid (const char *name);

/**
 * @brief Calculate the wire format length of a domain name.
 * @ingroup dns_name
 *
 * Returns the number of bytes needed to encode the domain name in wire format.
 * This includes all length bytes and the terminating zero byte.
 *
 * @param[in] name Domain name string.
 * @return Wire format length, or 0 if name is invalid.
 */
extern size_t SocketDNS_name_wire_length (const char *name);

/** @} */ /* End of dns_name group */

/**
 * @defgroup dns_question DNS Question Section
 * @brief Question section encoding and decoding.
 * @ingroup dns_wire
 * @{
 */

/**
 * @brief DNS record types (RFC 1035 Section 3.2.2, RFC 3596).
 *
 * TYPE field values for resource records and QTYPE values for questions.
 */
typedef enum
{
  DNS_TYPE_A = 1,      /**< IPv4 host address (RFC 1035) */
  DNS_TYPE_NS = 2,     /**< Authoritative name server (RFC 1035) */
  DNS_TYPE_CNAME = 5,  /**< Canonical name for alias (RFC 1035) */
  DNS_TYPE_SOA = 6,    /**< Start of authority (RFC 1035) */
  DNS_TYPE_PTR = 12,   /**< Domain name pointer (RFC 1035) */
  DNS_TYPE_MX = 15,    /**< Mail exchange (RFC 1035) */
  DNS_TYPE_TXT = 16,   /**< Text strings (RFC 1035) */
  DNS_TYPE_AAAA = 28,  /**< IPv6 host address (RFC 3596) */
  DNS_TYPE_SRV = 33,   /**< Service locator (RFC 2782) */
  DNS_TYPE_OPT = 41,   /**< EDNS0 option (RFC 6891) */
  DNS_TYPE_ANY = 255   /**< Any type (QTYPE only, RFC 1035) */
} SocketDNS_Type;

/**
 * @brief DNS query classes (RFC 1035 Section 3.2.4).
 *
 * CLASS field values for resource records and QCLASS values for questions.
 */
typedef enum
{
  DNS_CLASS_IN = 1,   /**< Internet (RFC 1035) */
  DNS_CLASS_CH = 3,   /**< CHAOS (RFC 1035) */
  DNS_CLASS_HS = 4,   /**< Hesiod (RFC 1035) */
  DNS_CLASS_ANY = 255 /**< Any class (QCLASS only, RFC 1035) */
} SocketDNS_Class;

/**
 * @brief DNS question section structure.
 *
 * Represents a single question entry from the question section.
 *
 * ## Wire Format (RFC 1035 Section 4.1.2)
 *
 * ```
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     QNAME                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     QTYPE                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     QCLASS                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * ```
 */
typedef struct
{
  char qname[DNS_MAX_NAME_LEN]; /**< Query domain name */
  uint16_t qtype;               /**< Query type (SocketDNS_Type) */
  uint16_t qclass;              /**< Query class (SocketDNS_Class) */
} SocketDNS_Question;

/**
 * @brief Encode a DNS question to wire format.
 * @ingroup dns_question
 *
 * Serializes a question structure to the wire format as specified in
 * RFC 1035 Section 4.1.2. The QNAME is encoded as labels, followed by
 * QTYPE and QCLASS in network byte order (big-endian).
 *
 * @param[in]  question Question structure to encode.
 * @param[out] buf      Output buffer for wire format.
 * @param[in]  buflen   Size of output buffer.
 * @param[out] written  Number of bytes written (may be NULL).
 * @return 0 on success, -1 on error (invalid name, buffer too small).
 *
 * @code{.c}
 * SocketDNS_Question q;
 * SocketDNS_question_init(&q, "example.com", DNS_TYPE_A);
 * unsigned char buf[512];
 * size_t len;
 * if (SocketDNS_question_encode(&q, buf, sizeof(buf), &len) == 0) {
 *     // buf contains: [7]example[3]com[0] + QTYPE(2) + QCLASS(2)
 * }
 * @endcode
 */
extern int SocketDNS_question_encode (const SocketDNS_Question *question,
                                      unsigned char *buf, size_t buflen,
                                      size_t *written);

/**
 * @brief Decode a DNS question from wire format.
 * @ingroup dns_question
 *
 * Parses a question entry from wire format. Handles domain name
 * compression as specified in RFC 1035 Section 4.1.4.
 *
 * @param[in]  msg      Full DNS message buffer (for compression pointers).
 * @param[in]  msglen   Total length of the DNS message.
 * @param[in]  offset   Offset within msg where question starts.
 * @param[out] question Output question structure.
 * @param[out] consumed Bytes consumed from offset position (may be NULL).
 * @return 0 on success, -1 on error.
 *
 * @code{.c}
 * SocketDNS_Question q;
 * size_t consumed;
 * if (SocketDNS_question_decode(msg, msglen, 12, &q, &consumed) == 0) {
 *     printf("Query for %s type %d\n", q.qname, q.qtype);
 * }
 * @endcode
 */
extern int SocketDNS_question_decode (const unsigned char *msg, size_t msglen,
                                      size_t offset, SocketDNS_Question *question,
                                      size_t *consumed);

/**
 * @brief Initialize a DNS question for a standard query.
 * @ingroup dns_question
 *
 * Convenience function to set up a question with QCLASS=IN.
 *
 * @param[out] question Question structure to initialize.
 * @param[in]  name     Domain name to query.
 * @param[in]  qtype    Query type (e.g., DNS_TYPE_A, DNS_TYPE_AAAA).
 *
 * @code{.c}
 * SocketDNS_Question q;
 * SocketDNS_question_init(&q, "example.com", DNS_TYPE_AAAA);
 * // q.qname = "example.com", q.qtype = 28, q.qclass = 1
 * @endcode
 */
extern void SocketDNS_question_init (SocketDNS_Question *question,
                                     const char *name, uint16_t qtype);

/** @} */ /* End of dns_question group */

/**
 * @defgroup dns_rr DNS Resource Record Parsing
 * @brief Resource record parsing from DNS responses.
 * @ingroup dns_wire
 * @{
 */

/** Maximum RDATA size in bytes (16-bit RDLENGTH field limit). */
#define DNS_MAX_RDATA_LEN 65535

/**
 * @brief DNS resource record structure (parsed representation).
 *
 * Represents a single resource record from answer, authority, or
 * additional sections of a DNS response message.
 *
 * ## Wire Format (RFC 1035 Section 4.1.3)
 *
 * ```
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                      NAME                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                      TYPE                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     CLASS                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                      TTL                      |
 * |                                               |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                   RDLENGTH                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * /                     RDATA                     /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * ```
 *
 * @note The `rdata` field points into the original message buffer.
 *       Do not modify or free the message while the RR is in use.
 */
typedef struct
{
  char name[DNS_MAX_NAME_LEN]; /**< Owner domain name */
  uint16_t type;               /**< RR type (SocketDNS_Type) */
  uint16_t rclass;             /**< RR class (SocketDNS_Class) */
  uint32_t ttl;                /**< Time to live in seconds */
  uint16_t rdlength;           /**< Length of RDATA in bytes */
  const unsigned char *rdata;  /**< Pointer to RDATA within message */
} SocketDNS_RR;

/**
 * @brief Decode a resource record from wire format.
 * @ingroup dns_rr
 *
 * Parses a single resource record from the answer, authority, or additional
 * section of a DNS response. Handles domain name compression.
 *
 * @param[in]  msg      Full DNS message buffer (for compression pointers).
 * @param[in]  msglen   Total length of the DNS message.
 * @param[in]  offset   Offset within msg where RR starts.
 * @param[out] rr       Output resource record structure.
 * @param[out] consumed Bytes consumed from offset position (may be NULL).
 * @return 0 on success, -1 on error.
 *
 * @code{.c}
 * // After parsing header and question section...
 * size_t offset = header_size + question_size;
 * for (int i = 0; i < header.ancount; i++) {
 *     SocketDNS_RR rr;
 *     size_t consumed;
 *     if (SocketDNS_rr_decode(msg, msglen, offset, &rr, &consumed) == 0) {
 *         printf("RR: %s type=%d ttl=%u rdlen=%u\n",
 *                rr.name, rr.type, rr.ttl, rr.rdlength);
 *         offset += consumed;
 *     }
 * }
 * @endcode
 */
extern int SocketDNS_rr_decode (const unsigned char *msg, size_t msglen,
                                size_t offset, SocketDNS_RR *rr,
                                size_t *consumed);

/**
 * @brief Skip over a resource record without full parsing.
 * @ingroup dns_rr
 *
 * Efficiently skips an RR to reach subsequent records. Only parses
 * enough to determine the total wire size.
 *
 * @param[in]  msg      Full DNS message buffer.
 * @param[in]  msglen   Total length of the DNS message.
 * @param[in]  offset   Offset within msg where RR starts.
 * @param[out] consumed Bytes consumed from offset position (may be NULL).
 * @return 0 on success, -1 on error.
 *
 * @code{.c}
 * // Skip all answer records to reach authority section
 * size_t offset = header_size + question_size;
 * for (int i = 0; i < header.ancount; i++) {
 *     size_t consumed;
 *     if (SocketDNS_rr_skip(msg, msglen, offset, &consumed) != 0)
 *         break;
 *     offset += consumed;
 * }
 * // offset now points to authority section
 * @endcode
 */
extern int SocketDNS_rr_skip (const unsigned char *msg, size_t msglen,
                              size_t offset, size_t *consumed);

/** @} */ /* End of dns_rr group */

/**
 * @defgroup dns_rdata DNS RDATA Parsing
 * @brief Type-specific RDATA parsing functions.
 * @ingroup dns_wire
 * @{
 */

/** Size of A record RDATA in bytes (IPv4 address, RFC 1035 Section 3.4.1). */
#define DNS_RDATA_A_SIZE 4

/** Size of AAAA record RDATA in bytes (IPv6 address, RFC 3596). */
#define DNS_RDATA_AAAA_SIZE 16

/**
 * @brief Parse A record RDATA (IPv4 address).
 * @ingroup dns_rdata
 *
 * Extracts an IPv4 address from an A record's RDATA field.
 * The address is returned in network byte order.
 *
 * @param[in]  rr   Resource record with TYPE=A.
 * @param[out] addr Output IPv4 address (network byte order).
 * @return 0 on success, -1 on error (wrong type, wrong rdlength, or NULL).
 *
 * @code{.c}
 * SocketDNS_RR rr;
 * if (SocketDNS_rr_decode(msg, msglen, offset, &rr, NULL) == 0) {
 *     if (rr.type == DNS_TYPE_A) {
 *         struct in_addr addr;
 *         if (SocketDNS_rdata_parse_a(&rr, &addr) == 0) {
 *             char str[INET_ADDRSTRLEN];
 *             inet_ntop(AF_INET, &addr, str, sizeof(str));
 *             printf("IPv4: %s\n", str);
 *         }
 *     }
 * }
 * @endcode
 */
extern int SocketDNS_rdata_parse_a (const SocketDNS_RR *rr,
                                    struct in_addr *addr);

/**
 * @brief Parse AAAA record RDATA (IPv6 address).
 * @ingroup dns_rdata
 *
 * Extracts an IPv6 address from an AAAA record's RDATA field.
 * The address is returned in network byte order.
 *
 * @param[in]  rr   Resource record with TYPE=AAAA.
 * @param[out] addr Output IPv6 address (network byte order).
 * @return 0 on success, -1 on error (wrong type, wrong rdlength, or NULL).
 *
 * @code{.c}
 * SocketDNS_RR rr;
 * if (SocketDNS_rr_decode(msg, msglen, offset, &rr, NULL) == 0) {
 *     if (rr.type == DNS_TYPE_AAAA) {
 *         struct in6_addr addr;
 *         if (SocketDNS_rdata_parse_aaaa(&rr, &addr) == 0) {
 *             char str[INET6_ADDRSTRLEN];
 *             inet_ntop(AF_INET6, &addr, str, sizeof(str));
 *             printf("IPv6: %s\n", str);
 *         }
 *     }
 * }
 * @endcode
 */
extern int SocketDNS_rdata_parse_aaaa (const SocketDNS_RR *rr,
                                       struct in6_addr *addr);

/** @} */ /* End of dns_rdata group */

/** @} */ /* End of dns_wire group */

#endif /* SOCKETDNSWIRE_INCLUDED */
