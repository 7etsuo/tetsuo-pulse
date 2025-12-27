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
#include "core/SocketUtil.h"
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
  DNS_RCODE_NOTZONE = 10,  /**< Name not in zone (RFC 2136) */
  DNS_RCODE_BADCOOKIE = 23 /**< Bad/missing Server Cookie (RFC 7873) */
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

/** Fixed fields size in question section: QTYPE(2) + QCLASS(2) bytes (RFC 1035 Section 4.1.2). */
#define DNS_QUESTION_FIXED_SIZE 4

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
  DNS_TYPE_DS = 43,    /**< Delegation Signer (RFC 4034) */
  DNS_TYPE_RRSIG = 46, /**< RRSIG signature (RFC 4034) */
  DNS_TYPE_NSEC = 47,  /**< Next Secure (RFC 4034) */
  DNS_TYPE_DNSKEY = 48, /**< DNS Public Key (RFC 4034) */
  DNS_TYPE_NSEC3 = 50, /**< NSEC3 hashed denial (RFC 5155) */
  DNS_TYPE_NSEC3PARAM = 51, /**< NSEC3 parameters (RFC 5155) */
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

/**
 * @brief Parse CNAME record RDATA (canonical name).
 * @ingroup dns_rdata
 *
 * Extracts the canonical domain name from a CNAME record's RDATA field.
 * The domain name may use compression pointers, so the full message
 * context is required for pointer resolution.
 *
 * @param[in]  msg      Full DNS message buffer (for compression pointers).
 * @param[in]  msglen   Total length of the DNS message.
 * @param[in]  rr       Resource record with TYPE=CNAME.
 * @param[out] cname    Output buffer for canonical name.
 * @param[in]  cnamelen Size of output buffer.
 * @return Length of canonical name on success, -1 on error.
 *
 * @code{.c}
 * SocketDNS_RR rr;
 * if (SocketDNS_rr_decode(msg, msglen, offset, &rr, NULL) == 0) {
 *     if (rr.type == DNS_TYPE_CNAME) {
 *         char cname[DNS_MAX_NAME_LEN];
 *         int len = SocketDNS_rdata_parse_cname(msg, msglen, &rr,
 *                                                cname, sizeof(cname));
 *         if (len >= 0) {
 *             printf("Canonical name: %s\n", cname);
 *         }
 *     }
 * }
 * @endcode
 */
extern int SocketDNS_rdata_parse_cname (const unsigned char *msg, size_t msglen,
                                        const SocketDNS_RR *rr, char *cname,
                                        size_t cnamelen);

/** Size of SOA fixed fields in bytes (SERIAL + REFRESH + RETRY + EXPIRE + MINIMUM). */
#define DNS_SOA_FIXED_SIZE 20

/**
 * @brief SOA record RDATA structure (RFC 1035 Section 3.3.13).
 *
 * Represents the parsed contents of a Start of Authority record.
 * SOA records appear in zone apex and in authority section of
 * NXDOMAIN/NODATA responses for negative caching.
 *
 * ## Wire Format (RFC 1035 Section 3.3.13)
 *
 * ```
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * /                     MNAME                     /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * /                     RNAME                     /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    SERIAL                     |
 * |                                               |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    REFRESH                    |
 * |                                               |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     RETRY                     |
 * |                                               |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    EXPIRE                     |
 * |                                               |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    MINIMUM                    |
 * |                                               |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * ```
 */
typedef struct
{
  char mname[DNS_MAX_NAME_LEN]; /**< Primary nameserver domain name */
  char rname[DNS_MAX_NAME_LEN]; /**< Responsible person mailbox (@ as .) */
  uint32_t serial;              /**< Zone version number */
  uint32_t refresh;             /**< Refresh interval (seconds) */
  uint32_t retry;               /**< Retry interval (seconds) */
  uint32_t expire;              /**< Expire time (seconds) */
  uint32_t minimum;             /**< Negative cache TTL (seconds) */
} SocketDNS_SOA;

/**
 * @brief Parse SOA record RDATA (Start of Authority).
 * @ingroup dns_rdata
 *
 * Extracts SOA record data including primary nameserver, responsible
 * person mailbox, and zone timing parameters. MNAME and RNAME may use
 * compression pointers, so full message context is required.
 *
 * The MINIMUM field is particularly important for negative caching
 * as specified in RFC 2308 - it determines how long NXDOMAIN and
 * NODATA responses should be cached.
 *
 * @param[in]  msg    Full DNS message buffer (for compression pointers).
 * @param[in]  msglen Total length of the DNS message.
 * @param[in]  rr     Resource record with TYPE=SOA.
 * @param[out] soa    Output SOA structure.
 * @return 0 on success, -1 on error.
 *
 * @code{.c}
 * SocketDNS_RR rr;
 * if (SocketDNS_rr_decode(msg, msglen, offset, &rr, NULL) == 0) {
 *     if (rr.type == DNS_TYPE_SOA) {
 *         SocketDNS_SOA soa;
 *         if (SocketDNS_rdata_parse_soa(msg, msglen, &rr, &soa) == 0) {
 *             printf("Primary NS: %s\n", soa.mname);
 *             printf("Negative TTL: %u\n", soa.minimum);
 *         }
 *     }
 * }
 * @endcode
 */
extern int SocketDNS_rdata_parse_soa (const unsigned char *msg, size_t msglen,
                                      const SocketDNS_RR *rr, SocketDNS_SOA *soa);

/** @} */ /* End of dns_rdata group */

/**
 * @defgroup dns_edns0 EDNS0 Extension Mechanism
 * @brief EDNS0 OPT pseudo-RR encoding and decoding (RFC 6891).
 * @ingroup dns_wire
 * @{
 */

/** EDNS0 version number (RFC 6891 Section 6.1.3). */
#define DNS_EDNS0_VERSION 0

/** Default UDP payload size for EDNS0 (RFC 6891 Section 6.2.5). */
#define DNS_EDNS0_DEFAULT_UDPSIZE 4096

/** Minimum UDP payload size (values below treated as 512, RFC 6891 Section 6.2.3). */
#define DNS_EDNS0_MIN_UDPSIZE 512

/** Fixed size of OPT pseudo-RR in bytes (1 + 2 + 2 + 4 + 2 = 11). */
#define DNS_OPT_FIXED_SIZE 11

/**
 * @brief EDNS0 OPT pseudo-RR structure (RFC 6891).
 *
 * Represents the EDNS0 extension mechanism pseudo-RR. Unlike standard RRs,
 * the OPT record uses fields differently:
 * - NAME: Always root (0x00)
 * - TYPE: OPT (41)
 * - CLASS: Requestor's UDP payload size
 * - TTL: Extended RCODE, version, and flags
 * - RDATA: Zero or more options
 *
 * ## Wire Format (RFC 6891 Section 6.1.2)
 *
 * ```
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |0 |                 TYPE = 41                  |  1 + 2 bytes
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |              UDP Payload Size                |  2 bytes
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |  Extended RCODE   |  VERSION  | DO |    Z    |  4 bytes
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                 RDLENGTH                     |  2 bytes
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                   RDATA                      |  variable
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * ```
 */
typedef struct
{
  uint16_t udp_payload_size; /**< Max UDP payload size (CLASS field) */
  uint8_t extended_rcode;    /**< Upper 8 bits of 12-bit RCODE (TTL bits 24-31) */
  uint8_t version;           /**< EDNS version (TTL bits 16-23), 0 for EDNS0 */
  uint8_t do_bit;            /**< DNSSEC OK flag (TTL bit 15) */
  uint16_t z;                /**< Reserved, must be zero (TTL bits 0-14) */
  uint16_t rdlength;         /**< Length of RDATA in bytes */
  const unsigned char *rdata; /**< Pointer to RDATA (options), not owned */
} SocketDNS_OPT;

/**
 * @brief OPT pseudo-RR TTL field flags (RFC 6891 Section 6.1.3).
 *
 * Parsed representation of the 32-bit TTL field in OPT records.
 * The TTL field is repurposed to carry extended RCODE, version, and flags.
 *
 * ## TTL Field Structure (32 bits)
 *
 * ```
 *                +0 (MSB)                            +1 (LSB)
 *   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 * 0: |         EXTENDED-RCODE        |            VERSION            |
 *   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 * 2: | DO|                           Z                               |
 *   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 * ```
 */
typedef struct
{
  uint8_t extended_rcode; /**< Upper 8 bits of 12-bit RCODE */
  uint8_t version;        /**< EDNS version (0 for EDNS0) */
  uint8_t do_bit;         /**< DNSSEC OK flag */
  uint16_t z;             /**< Reserved, must be zero */
} SocketDNS_OPT_Flags;

/**
 * @brief Extended DNS response codes (12-bit, RFC 6891).
 *
 * Extended RCODEs combine the 4-bit header RCODE with the 8-bit
 * extended RCODE from the OPT record to form a 12-bit value.
 *
 * Values 0-15 are the same as SocketDNS_Rcode.
 * Values 16+ require EDNS0 OPT record for transport.
 */
typedef enum
{
  DNS_RCODE_EXT_BADVERS = 16,  /**< BADVERS - Server doesn't support EDNS version */
  DNS_RCODE_EXT_BADSIG = 16,   /**< BADSIG - TSIG signature failure (same as BADVERS) */
  DNS_RCODE_EXT_BADKEY = 17,   /**< BADKEY - Key not recognized */
  DNS_RCODE_EXT_BADTIME = 18,  /**< BADTIME - Signature out of time window */
  DNS_RCODE_EXT_BADMODE = 19,  /**< BADMODE - Bad TKEY mode */
  DNS_RCODE_EXT_BADNAME = 20,  /**< BADNAME - Duplicate key name */
  DNS_RCODE_EXT_BADALG = 21,   /**< BADALG - Algorithm not supported */
  DNS_RCODE_EXT_BADTRUNC = 22, /**< BADTRUNC - Bad truncation */
  DNS_RCODE_EXT_BADCOOKIE = 23 /**< BADCOOKIE - Bad/missing server cookie */
} SocketDNS_ExtendedRcode;

/**
 * @brief OPT record validation result (RFC 6891 Section 6.1.1).
 *
 * Used to report validation errors for incoming OPT records.
 * Per RFC 6891, malformed OPT records should trigger FORMERR.
 */
typedef enum
{
  DNS_OPT_VALID = 0,        /**< OPT record is well-formed */
  DNS_OPT_INVALID_NAME,     /**< NAME is not root (must be 0x00) */
  DNS_OPT_INVALID_TYPE,     /**< TYPE is not 41 */
  DNS_OPT_MULTIPLE,         /**< More than one OPT in message */
  DNS_OPT_TRUNCATED,        /**< RDLEN exceeds available data */
  DNS_OPT_MALFORMED_OPTION, /**< Option within RDATA is malformed */
  DNS_OPT_INVALID_RDATA     /**< RDATA structure is invalid */
} SocketDNS_OPT_ValidationResult;

/**
 * @brief Initialize an OPT record with default values.
 * @ingroup dns_edns0
 *
 * Sets up an OPT record for a standard EDNS0 query with:
 * - Specified UDP payload size (minimum 512)
 * - Version 0 (EDNS0)
 * - DO bit cleared (no DNSSEC)
 * - No options (RDLENGTH = 0)
 *
 * @param[out] opt      OPT structure to initialize.
 * @param[in]  udp_size Maximum UDP payload size to advertise.
 *                      Values below 512 are normalized to 512.
 *
 * @code{.c}
 * SocketDNS_OPT opt;
 * SocketDNS_opt_init(&opt, 4096);
 * // opt.udp_payload_size = 4096, opt.version = 0, opt.do_bit = 0
 * @endcode
 */
extern void SocketDNS_opt_init (SocketDNS_OPT *opt, uint16_t udp_size);

/**
 * @brief Encode an OPT record to wire format.
 * @ingroup dns_edns0
 *
 * Serializes an OPT pseudo-RR to wire format as specified in RFC 6891.
 * The encoded record can be appended to the additional section of a query.
 *
 * @param[in]  opt    OPT structure to encode.
 * @param[out] buf    Output buffer for wire format.
 * @param[in]  buflen Size of output buffer.
 * @return Number of bytes written on success, -1 on error (buffer too small).
 *
 * @code{.c}
 * SocketDNS_OPT opt;
 * SocketDNS_opt_init(&opt, 4096);
 * unsigned char buf[DNS_OPT_FIXED_SIZE];
 * int len = SocketDNS_opt_encode(&opt, buf, sizeof(buf));
 * if (len > 0) {
 *     // Append buf to query, increment ARCOUNT
 * }
 * @endcode
 */
extern int SocketDNS_opt_encode (const SocketDNS_OPT *opt, unsigned char *buf,
                                  size_t buflen);

/**
 * @brief Decode an OPT record from wire format.
 * @ingroup dns_edns0
 *
 * Parses an OPT pseudo-RR from the additional section of a DNS response.
 * Validates that NAME is root (0x00) and TYPE is OPT (41).
 *
 * @param[in]  buf    Buffer containing OPT record.
 * @param[in]  len    Length of buffer.
 * @param[out] opt    Output OPT structure.
 * @return Number of bytes consumed on success, -1 on error.
 *
 * @code{.c}
 * // Find OPT in additional section
 * SocketDNS_OPT opt;
 * int consumed = SocketDNS_opt_decode(additional_ptr, remaining, &opt);
 * if (consumed > 0) {
 *     printf("Server supports %u byte UDP\n", opt.udp_payload_size);
 * }
 * @endcode
 */
extern int SocketDNS_opt_decode (const unsigned char *buf, size_t len,
                                  SocketDNS_OPT *opt);

/**
 * @brief Validate an OPT record per RFC 6891 Section 6.1.1.
 * @ingroup dns_edns0
 *
 * Checks that an OPT record is well-formed:
 * - NAME must be root (0x00)
 * - TYPE must be 41 (already ensured by decode)
 * - RDLEN must not exceed available data
 * - Options in RDATA must be parseable
 *
 * @param[in] opt       OPT record to validate.
 * @param[in] rdata_len Actual length of RDATA buffer available.
 * @return DNS_OPT_VALID if valid, or specific error code.
 *
 * @code{.c}
 * SocketDNS_OPT opt;
 * if (SocketDNS_opt_decode(buf, len, &opt) > 0) {
 *     SocketDNS_OPT_ValidationResult result = SocketDNS_opt_validate(&opt, len);
 *     if (result != DNS_OPT_VALID) {
 *         // Return FORMERR
 *     }
 * }
 * @endcode
 */
extern SocketDNS_OPT_ValidationResult SocketDNS_opt_validate (
    const SocketDNS_OPT *opt, size_t rdata_len);

/**
 * @brief Check if OPT NAME is the root domain.
 * @ingroup dns_edns0
 *
 * Per RFC 6891 Section 6.1.1, the NAME field of an OPT record
 * MUST be 0 (the root domain). This is already validated during
 * decoding, but this function allows explicit checking.
 *
 * @param[in] name_byte First byte of NAME field in wire format.
 * @return 1 if valid (0x00), 0 if invalid.
 */
extern int SocketDNS_opt_is_valid_name (unsigned char name_byte);

/**
 * @brief Count OPT records in a DNS message's additional section.
 * @ingroup dns_edns0
 *
 * Per RFC 6891 Section 6.1.1, a DNS message MUST contain at most one
 * OPT record. This function counts OPT records to detect violations.
 *
 * @param[in] msg      Complete DNS message buffer.
 * @param[in] msg_len  Length of message buffer.
 * @param[in] hdr      Parsed DNS header (for ARCOUNT).
 * @return Number of OPT records found (0, 1, or more), or -1 on error.
 *
 * @code{.c}
 * int opt_count = SocketDNS_response_count_opt(msg, msg_len, &hdr);
 * if (opt_count > 1) {
 *     // RFC 6891 violation - FORMERR
 * }
 * @endcode
 */
extern int SocketDNS_response_count_opt (const unsigned char *msg, size_t msg_len,
                                          const SocketDNS_Header *hdr);

/**
 * @brief Get human-readable string for OPT validation result.
 * @ingroup dns_edns0
 *
 * @param[in] result Validation result code.
 * @return Static string describing the result.
 */
extern const char *SocketDNS_opt_validation_str (SocketDNS_OPT_ValidationResult result);

/**
 * @brief Calculate the 12-bit extended RCODE from header and OPT.
 * @ingroup dns_edns0
 *
 * Combines the 4-bit RCODE from the DNS header with the 8-bit extended
 * RCODE from the OPT record to form the full 12-bit extended RCODE
 * as specified in RFC 6891 Section 6.1.3.
 *
 * @param[in] hdr DNS header (contains lower 4 bits of RCODE).
 * @param[in] opt OPT record (contains upper 8 bits of RCODE), may be NULL.
 * @return 12-bit extended RCODE (0-4095).
 *
 * @code{.c}
 * SocketDNS_Header hdr;
 * SocketDNS_OPT opt;
 * // ... decode header and OPT ...
 * uint16_t rcode = SocketDNS_opt_extended_rcode(&hdr, &opt);
 * if (rcode == 16) {
 *     // BADVERS - server doesn't support this EDNS version
 * }
 * @endcode
 */
extern uint16_t SocketDNS_opt_extended_rcode (const SocketDNS_Header *hdr,
                                               const SocketDNS_OPT *opt);

/**
 * @brief Decode OPT TTL field into flags structure.
 * @ingroup dns_edns0
 *
 * Parses the 32-bit TTL field from an OPT record into its component parts:
 * extended RCODE, version, DO bit, and Z flags.
 *
 * @param[in]  ttl   32-bit TTL value from OPT record.
 * @param[out] flags Output flags structure.
 *
 * @code{.c}
 * SocketDNS_OPT_Flags flags;
 * SocketDNS_opt_ttl_decode(opt_rr.ttl, &flags);
 * if (flags.version != 0) {
 *     // Server uses different EDNS version
 * }
 * @endcode
 */
extern void SocketDNS_opt_ttl_decode (uint32_t ttl, SocketDNS_OPT_Flags *flags);

/**
 * @brief Encode flags structure into OPT TTL field.
 * @ingroup dns_edns0
 *
 * Packs extended RCODE, version, DO bit, and Z flags into a 32-bit TTL value
 * suitable for use in an OPT record.
 *
 * @param[in] flags Flags structure to encode.
 * @return 32-bit TTL value for OPT record.
 *
 * @code{.c}
 * SocketDNS_OPT_Flags flags = {
 *     .extended_rcode = 0,
 *     .version = 0,
 *     .do_bit = 1,  // Enable DNSSEC
 *     .z = 0
 * };
 * uint32_t ttl = SocketDNS_opt_ttl_encode(&flags);
 * @endcode
 */
extern uint32_t SocketDNS_opt_ttl_encode (const SocketDNS_OPT_Flags *flags);

/**
 * @brief Get EDNS version from OPT record.
 * @ingroup dns_edns0
 *
 * Convenience function to extract the VERSION field from an OPT record.
 * Per RFC 6891, version 0 indicates EDNS0 conformance.
 *
 * @param[in] opt OPT record structure.
 * @return EDNS version (0 for EDNS0), or -1 if opt is NULL.
 *
 * @code{.c}
 * int version = SocketDNS_opt_get_version(&opt);
 * if (version > DNS_EDNS0_VERSION) {
 *     // Server uses newer EDNS version
 * }
 * @endcode
 */
extern int SocketDNS_opt_get_version (const SocketDNS_OPT *opt);

/**
 * @brief Check if response indicates BADVERS (version negotiation failure).
 * @ingroup dns_edns0
 *
 * Detects BADVERS response (extended RCODE 16) which indicates the server
 * does not support the EDNS version in the request. Per RFC 6891 Section 6.1.3,
 * the client should retry with a lower version or fall back to non-EDNS.
 *
 * @param[in] hdr DNS response header.
 * @param[in] opt OPT record from response (may be NULL).
 * @return 1 if BADVERS, 0 otherwise.
 *
 * @code{.c}
 * if (SocketDNS_opt_is_badvers(&header, &opt)) {
 *     int server_version = SocketDNS_opt_get_version(&opt);
 *     // Retry with server_version or fall back to non-EDNS
 * }
 * @endcode
 */
extern int SocketDNS_opt_is_badvers (const SocketDNS_Header *hdr,
                                      const SocketDNS_OPT *opt);

/**
 * @defgroup dns_edns0_options EDNS0 Option Parsing
 * @brief EDNS0 option encoding and decoding (RFC 6891 Section 6.1.2).
 * @ingroup dns_edns0
 * @{
 */

/** Minimum size of an EDNS option (code + length, no data). */
#define DNS_EDNS_OPTION_HEADER_SIZE 4

/**
 * @brief Known EDNS option codes (IANA registry).
 *
 * Option codes assigned by IANA for EDNS options.
 * Unknown codes MUST be ignored per RFC 6891.
 */
typedef enum
{
  DNS_EDNS_OPT_RESERVED = 0,         /**< Reserved (RFC 6891) */
  DNS_EDNS_OPT_NSID = 3,             /**< Name Server Identifier (RFC 5001) */
  DNS_EDNS_OPT_CLIENT_SUBNET = 8,    /**< Client Subnet (RFC 7871) */
  DNS_EDNS_OPT_COOKIE = 10,          /**< DNS Cookie (RFC 7873) */
  DNS_EDNS_OPT_TCP_KEEPALIVE = 11,   /**< TCP Keepalive (RFC 7828) */
  DNS_EDNS_OPT_PADDING = 12,         /**< Padding (RFC 7830) */
  DNS_EDNS_OPT_EXTENDED_ERROR = 15,  /**< Extended DNS Error (RFC 8914) */
  DNS_EDNS_OPT_LOCAL_MIN = 65001,    /**< Local/Experimental minimum */
  DNS_EDNS_OPT_LOCAL_MAX = 65534,    /**< Local/Experimental maximum */
  DNS_EDNS_OPT_RESERVED_MAX = 65535  /**< Reserved (RFC 6891) */
} SocketDNS_EDNSOptionCode;

/**
 * @brief Single EDNS option structure (RFC 6891 Section 6.1.2).
 *
 * Represents a single option from the OPT record RDATA section.
 * Options are encoded as {OPTION-CODE, OPTION-LENGTH, OPTION-DATA}.
 *
 * ## Wire Format
 *
 * ```
 *                +0 (MSB)                            +1 (LSB)
 *   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 * 0: |                          OPTION-CODE                         |
 *   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 * 2: |                         OPTION-LENGTH                        |
 *   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 * 4: |                          OPTION-DATA                         |
 *   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 * ```
 *
 * @note The `data` field points into the original buffer and is not owned.
 */
typedef struct
{
  uint16_t code;               /**< Option code (IANA assigned) */
  uint16_t length;             /**< Length of option data in bytes */
  const unsigned char *data;   /**< Option data (not owned, may be NULL if length=0) */
} SocketDNS_EDNSOption;

/**
 * @brief Iterator for parsing EDNS options from OPT RDATA.
 *
 * Used to iterate over multiple options in an OPT record's RDATA section.
 * Initialize with SocketDNS_edns_option_iter_init() and retrieve options
 * with SocketDNS_edns_option_iter_next().
 */
typedef struct
{
  const unsigned char *pos;   /**< Current position in RDATA */
  const unsigned char *end;   /**< End of RDATA */
} SocketDNS_EDNSOptionIter;

/**
 * @brief Encode a single EDNS option to wire format.
 * @ingroup dns_edns0_options
 *
 * Serializes an EDNS option to the wire format as specified in
 * RFC 6891 Section 6.1.2.
 *
 * @param[in]  option  Option structure to encode.
 * @param[out] buf     Output buffer for wire format.
 * @param[in]  buflen  Size of output buffer.
 * @return Number of bytes written on success, -1 on error (buffer too small).
 *
 * @code{.c}
 * SocketDNS_EDNSOption opt = {
 *     .code = DNS_EDNS_OPT_PADDING,
 *     .length = 12,
 *     .data = padding_bytes
 * };
 * unsigned char buf[16];
 * int len = SocketDNS_edns_option_encode(&opt, buf, sizeof(buf));
 * @endcode
 */
extern int SocketDNS_edns_option_encode (const SocketDNS_EDNSOption *option,
                                          unsigned char *buf, size_t buflen);

/**
 * @brief Initialize an iterator for parsing EDNS options.
 * @ingroup dns_edns0_options
 *
 * Sets up an iterator to parse options from OPT record RDATA.
 * The iterator points into the provided buffer and does not copy data.
 *
 * @param[out] iter    Iterator to initialize.
 * @param[in]  rdata   OPT record RDATA buffer.
 * @param[in]  rdlen   Length of RDATA in bytes.
 *
 * @code{.c}
 * SocketDNS_EDNSOptionIter iter;
 * SocketDNS_edns_option_iter_init(&iter, opt.rdata, opt.rdlength);
 * @endcode
 */
extern void SocketDNS_edns_option_iter_init (SocketDNS_EDNSOptionIter *iter,
                                              const unsigned char *rdata,
                                              size_t rdlen);

/**
 * @brief Get next option from the iterator.
 * @ingroup dns_edns0_options
 *
 * Retrieves the next option from the RDATA and advances the iterator.
 * Returns 0 when no more options are available or on parse error.
 *
 * Per RFC 6891, unknown option codes MUST be ignored. This function
 * returns all options; the caller should ignore unknown codes.
 *
 * @param[in,out] iter   Iterator (advanced on success).
 * @param[out]    option Output option structure.
 * @return 1 if option retrieved, 0 if no more options or parse error.
 *
 * @code{.c}
 * SocketDNS_EDNSOptionIter iter;
 * SocketDNS_EDNSOption opt;
 * SocketDNS_edns_option_iter_init(&iter, rdata, rdlen);
 * while (SocketDNS_edns_option_iter_next(&iter, &opt)) {
 *     switch (opt.code) {
 *     case DNS_EDNS_OPT_COOKIE:
 *         // Process cookie option
 *         break;
 *     default:
 *         // Ignore unknown options per RFC 6891
 *         break;
 *     }
 * }
 * @endcode
 */
extern int SocketDNS_edns_option_iter_next (SocketDNS_EDNSOptionIter *iter,
                                             SocketDNS_EDNSOption *option);

/**
 * @brief Find an option by code in OPT RDATA.
 * @ingroup dns_edns0_options
 *
 * Searches for the first option with the specified code in the RDATA.
 * If multiple options with the same code exist, only the first is returned.
 *
 * @param[in]  rdata   OPT record RDATA buffer.
 * @param[in]  rdlen   Length of RDATA in bytes.
 * @param[in]  code    Option code to search for.
 * @param[out] option  Output option structure (filled if found).
 * @return 1 if option found, 0 if not found or parse error.
 *
 * @code{.c}
 * SocketDNS_EDNSOption cookie;
 * if (SocketDNS_edns_option_find(opt.rdata, opt.rdlength,
 *                                 DNS_EDNS_OPT_COOKIE, &cookie)) {
 *     // Process cookie
 * }
 * @endcode
 */
extern int SocketDNS_edns_option_find (const unsigned char *rdata, size_t rdlen,
                                        uint16_t code, SocketDNS_EDNSOption *option);

/**
 * @brief Encode an array of options to RDATA format.
 * @ingroup dns_edns0_options
 *
 * Serializes multiple EDNS options to a buffer suitable for use as
 * OPT record RDATA. Options are encoded consecutively.
 *
 * @param[in]  options Array of options to encode.
 * @param[in]  count   Number of options in array.
 * @param[out] buf     Output buffer for RDATA.
 * @param[in]  buflen  Size of output buffer.
 * @return Total bytes written on success, -1 on error (buffer too small).
 *
 * @code{.c}
 * SocketDNS_EDNSOption opts[] = {
 *     { .code = DNS_EDNS_OPT_COOKIE, .length = 8, .data = cookie },
 *     { .code = DNS_EDNS_OPT_PADDING, .length = 4, .data = padding }
 * };
 * unsigned char rdata[256];
 * int rdlen = SocketDNS_edns_options_encode(opts, 2, rdata, sizeof(rdata));
 * if (rdlen > 0) {
 *     opt.rdata = rdata;
 *     opt.rdlength = rdlen;
 * }
 * @endcode
 */
extern int SocketDNS_edns_options_encode (const SocketDNS_EDNSOption *options,
                                           size_t count, unsigned char *buf,
                                           size_t buflen);

/** @} */ /* End of dns_edns0_options group */

/**
 * @defgroup dns_edns0_payload EDNS0 UDP Payload Size Selection
 * @brief Intelligent UDP payload size fallback (RFC 6891 Section 6.2.5).
 * @ingroup dns_edns0
 * @{
 */

/** Initial/optimal UDP payload size (RFC 6891 Section 6.2.5). */
#define DNS_PAYLOAD_INITIAL 4096

/** First fallback size: safe for most paths (IPv6 min MTU area). */
#define DNS_PAYLOAD_FALLBACK1 1400

/** Last resort UDP size: RFC 1035 guaranteed minimum. */
#define DNS_PAYLOAD_FALLBACK2 512

/** Default timeout (seconds) before resetting to initial size. */
#define DNS_PAYLOAD_RESET_TIMEOUT 300

/**
 * @brief UDP payload size state for progressive fallback.
 *
 * Per RFC 6891 Section 6.2.5, implementations should start with a large
 * size (4096) and progressively fall back on failures:
 *
 * ```
 * PAYLOAD_4096 (start) → timeout/failure
 *        ↓
 * PAYLOAD_1400 (first fallback) → timeout/failure
 *        ↓
 * PAYLOAD_512 (last resort UDP) → timeout/failure
 *        ↓
 * PAYLOAD_TCP (give up on UDP)
 * ```
 */
typedef enum
{
  DNS_PAYLOAD_STATE_4096 = 0, /**< Start with 4096 bytes */
  DNS_PAYLOAD_STATE_1400,     /**< First fallback: ~1400 bytes */
  DNS_PAYLOAD_STATE_512,      /**< Last resort: 512 bytes (RFC 1035 min) */
  DNS_PAYLOAD_STATE_TCP       /**< UDP exhausted, must use TCP */
} SocketDNS_PayloadState;

/**
 * @brief Per-nameserver payload size tracking.
 *
 * Tracks the current payload state and history for a nameserver.
 * This allows learning which payload sizes work for each server.
 */
typedef struct
{
  SocketDNS_PayloadState state; /**< Current fallback state */
  uint16_t last_working_size;   /**< Cached size that last succeeded (0=none) */
  uint64_t last_failure_time;   /**< Unix timestamp of last failure (0=none) */
  uint64_t last_success_time;   /**< Unix timestamp of last success (0=none) */
  uint32_t failure_count;       /**< Consecutive failures at current state */
} SocketDNS_PayloadTracker;

/**
 * @brief Configuration for payload size selection.
 */
typedef struct
{
  uint16_t initial_size;     /**< Initial payload size (default: 4096) */
  uint16_t fallback1_size;   /**< First fallback size (default: 1400) */
  uint16_t fallback2_size;   /**< Second fallback size (default: 512) */
  uint32_t reset_timeout_sec; /**< Seconds before resetting to initial (default: 300) */
} SocketDNS_PayloadConfig;

/**
 * @brief Initialize a payload tracker with default state.
 * @ingroup dns_edns0_payload
 *
 * Sets tracker to initial state (4096 bytes, no history).
 *
 * @param[out] tracker Tracker to initialize.
 *
 * @code{.c}
 * SocketDNS_PayloadTracker tracker;
 * SocketDNS_payload_init(&tracker);
 * // tracker.state = DNS_PAYLOAD_STATE_4096
 * @endcode
 */
extern void SocketDNS_payload_init (SocketDNS_PayloadTracker *tracker);

/**
 * @brief Initialize payload configuration with defaults.
 * @ingroup dns_edns0_payload
 *
 * Sets config to RFC 6891 recommended values:
 * - initial_size: 4096
 * - fallback1_size: 1400
 * - fallback2_size: 512
 * - reset_timeout_sec: 300
 *
 * @param[out] config Configuration to initialize.
 */
extern void SocketDNS_payload_config_init (SocketDNS_PayloadConfig *config);

/**
 * @brief Get the current UDP payload size for a tracker.
 * @ingroup dns_edns0_payload
 *
 * Returns the appropriate payload size based on current state.
 * If a previous size worked, returns that cached value.
 * Values less than 512 are normalized to 512 per RFC 6891.
 *
 * @param[in] tracker Payload tracker.
 * @param[in] config  Configuration (NULL for defaults).
 * @return UDP payload size in bytes, or 0 if TCP required.
 *
 * @code{.c}
 * uint16_t size = SocketDNS_payload_get_size(&tracker, NULL);
 * if (size == 0) {
 *     // Must use TCP
 * } else {
 *     opt.udp_payload_size = size;
 * }
 * @endcode
 */
extern uint16_t SocketDNS_payload_get_size (const SocketDNS_PayloadTracker *tracker,
                                             const SocketDNS_PayloadConfig *config);

/**
 * @brief Record a payload-related failure and advance state.
 * @ingroup dns_edns0_payload
 *
 * Called when a query times out or fails in a way that suggests
 * payload size issues (e.g., consistent timeouts, fragmentation).
 * Advances to the next fallback state.
 *
 * @param[in,out] tracker Payload tracker to update.
 * @param[in]     now     Current Unix timestamp.
 *
 * @code{.c}
 * if (error == DNS_ERROR_TIMEOUT) {
 *     SocketDNS_payload_failed(&tracker, time(NULL));
 *     // Retry with smaller payload
 * }
 * @endcode
 */
extern void SocketDNS_payload_failed (SocketDNS_PayloadTracker *tracker,
                                       uint64_t now);

/**
 * @brief Record a successful query and cache the working size.
 * @ingroup dns_edns0_payload
 *
 * Called when a query succeeds. Caches the payload size that worked.
 * Resets failure count but does NOT change state (we want to remember
 * the minimum working size for this server).
 *
 * @param[in,out] tracker Payload tracker to update.
 * @param[in]     size    Payload size that succeeded.
 * @param[in]     now     Current Unix timestamp.
 *
 * @code{.c}
 * if (response_received) {
 *     SocketDNS_payload_succeeded(&tracker, opt.udp_payload_size, time(NULL));
 * }
 * @endcode
 */
extern void SocketDNS_payload_succeeded (SocketDNS_PayloadTracker *tracker,
                                          uint16_t size, uint64_t now);

/**
 * @brief Check if tracker should be reset to initial state.
 * @ingroup dns_edns0_payload
 *
 * After a period of time (reset_timeout_sec), it's worth retrying
 * larger payload sizes as network conditions may have changed.
 *
 * @param[in] tracker Payload tracker.
 * @param[in] config  Configuration (NULL for defaults).
 * @param[in] now     Current Unix timestamp.
 * @return 1 if should reset, 0 otherwise.
 */
extern int SocketDNS_payload_should_reset (const SocketDNS_PayloadTracker *tracker,
                                            const SocketDNS_PayloadConfig *config,
                                            uint64_t now);

/**
 * @brief Reset tracker to initial state.
 * @ingroup dns_edns0_payload
 *
 * Resets to 4096 bytes. Call periodically to retry larger sizes
 * after network conditions may have improved.
 *
 * @param[in,out] tracker Payload tracker to reset.
 *
 * @code{.c}
 * if (SocketDNS_payload_should_reset(&tracker, NULL, time(NULL))) {
 *     SocketDNS_payload_reset(&tracker);
 * }
 * @endcode
 */
extern void SocketDNS_payload_reset (SocketDNS_PayloadTracker *tracker);

/**
 * @brief Check if UDP is exhausted and TCP is required.
 * @ingroup dns_edns0_payload
 *
 * @param[in] tracker Payload tracker.
 * @return 1 if must use TCP, 0 if UDP still viable.
 */
extern int SocketDNS_payload_needs_tcp (const SocketDNS_PayloadTracker *tracker);

/**
 * @brief Get human-readable state name.
 * @ingroup dns_edns0_payload
 *
 * @param[in] state Payload state.
 * @return State name string.
 */
extern const char *SocketDNS_payload_state_name (SocketDNS_PayloadState state);

/** @} */ /* End of dns_edns0_payload group */

/** @} */ /* End of dns_edns0 group */

/**
 * @defgroup dns_security DNS Security Utilities
 * @brief Security-related validation functions (RFC 5452).
 * @ingroup dns
 * @{
 */

/**
 * @brief Check if a name is within the bailiwick of a zone (RFC 5452).
 * @ingroup dns_security
 *
 * A name is in-bailiwick if it equals the zone or is a subdomain of it.
 * For example, "www.example.com" is in-bailiwick of "example.com".
 * This prevents cache poisoning via out-of-zone answer injection.
 *
 * @param record_name Name from the answer record.
 * @param query_name  Original query name (defines the bailiwick).
 * @return 1 if in-bailiwick, 0 if out-of-bailiwick.
 *
 * @code{.c}
 * // Accept: subdomain of queried name
 * assert(SocketDNS_name_in_bailiwick("www.example.com", "example.com") == 1);
 *
 * // Reject: unrelated domain
 * assert(SocketDNS_name_in_bailiwick("attacker.com", "example.com") == 0);
 * @endcode
 */
extern int SocketDNS_name_in_bailiwick (const char *record_name,
                                        const char *query_name);

/** @} */ /* End of dns_security group */

/**
 * @defgroup dns_negative_cache DNS Negative Cache TTL
 * @brief Extract TTL for negative caching from DNS responses (RFC 2308).
 * @ingroup dns_wire
 * @{
 */

/** Default negative cache TTL when no SOA is present (seconds). */
#define DNS_NEGATIVE_TTL_DEFAULT 300

/** Maximum negative cache TTL (1 hour per RFC 2308 recommendation). */
#define DNS_NEGATIVE_TTL_MAX 3600

/**
 * @brief Extract negative cache TTL from a DNS response.
 * @ingroup dns_negative_cache
 *
 * Scans the authority section of a DNS response for an SOA record and
 * calculates the negative cache TTL as specified in RFC 2308 Section 5:
 *
 *     TTL = min(SOA_record_TTL, SOA.MINIMUM)
 *
 * This function is used to determine how long NXDOMAIN and NODATA
 * responses should be cached.
 *
 * ## RFC 2308 Compliance
 *
 * Per RFC 2308 Section 3, authoritative servers MUST include an SOA
 * record in the authority section when reporting NXDOMAIN or NODATA.
 * However, some servers may not comply. This function returns a
 * default TTL (300 seconds) if no SOA is found.
 *
 * ## TTL Calculation (RFC 2308 Section 5)
 *
 * The negative cache TTL is the minimum of:
 * - The TTL field of the SOA resource record
 * - The MINIMUM field in the SOA RDATA
 *
 * @param[in]  msg     Complete DNS response message.
 * @param[in]  msglen  Length of the DNS message.
 * @param[out] soa_out Optional output for the parsed SOA record (may be NULL).
 * @return Negative cache TTL in seconds, or DNS_NEGATIVE_TTL_DEFAULT if
 *         no SOA record is found in the authority section.
 *
 * @code{.c}
 * // After receiving NXDOMAIN or NODATA response
 * SocketDNS_SOA soa;
 * uint32_t neg_ttl = SocketDNS_extract_negative_ttl(response, len, &soa);
 *
 * // Cache the negative response with the extracted TTL
 * SocketDNSNegCache_insert_nxdomain(cache, qname, qclass, neg_ttl);
 * @endcode
 *
 * @see SocketDNS_rdata_parse_soa() for SOA record parsing.
 * @see RFC 2308 Section 5 for negative caching requirements.
 */
extern uint32_t SocketDNS_extract_negative_ttl (const unsigned char *msg,
                                                 size_t msglen,
                                                 SocketDNS_SOA *soa_out);

/** @} */ /* End of dns_negative_cache group */

/** @} */ /* End of dns_wire group */

#endif /* SOCKETDNSWIRE_INCLUDED */
