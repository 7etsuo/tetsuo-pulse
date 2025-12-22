/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/*
 * SocketDNSWire.c - DNS wire format encoding/decoding (RFC 1035)
 */

#include "dns/SocketDNSWire.h"

#include <string.h>

const Except_T SocketDNS_WireError
    = { &SocketDNS_WireError, "DNS wire format error" };

/*
 * Big-endian pack/unpack helpers.
 * Following the pattern from SocketHTTP2-frame.c for explicit byte
 * manipulation rather than relying on htons/ntohs macros.
 */

static inline uint16_t
dns_unpack_be16 (const unsigned char *p)
{
  return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}

static inline void
dns_pack_be16 (unsigned char *p, uint16_t v)
{
  p[0] = (unsigned char)((v >> 8) & 0xFF);
  p[1] = (unsigned char)(v & 0xFF);
}

/*
 * Flags word layout (16 bits):
 *
 *   Bit 15: QR (1 bit)      - Query/Response
 *   Bits 14-11: OPCODE (4)  - Operation code
 *   Bit 10: AA (1)          - Authoritative Answer
 *   Bit 9: TC (1)           - Truncation
 *   Bit 8: RD (1)           - Recursion Desired
 *   Bit 7: RA (1)           - Recursion Available
 *   Bits 6-4: Z (3)         - Reserved (must be 0)
 *   Bits 3-0: RCODE (4)     - Response code
 *
 * Bit positions from MSB (bit 15) to LSB (bit 0):
 *   QR: bit 15 (0x8000)
 *   OPCODE: bits 14-11 (0x7800), shift 11
 *   AA: bit 10 (0x0400)
 *   TC: bit 9 (0x0200)
 *   RD: bit 8 (0x0100)
 *   RA: bit 7 (0x0080)
 *   Z: bits 6-4 (0x0070), shift 4
 *   RCODE: bits 3-0 (0x000F)
 */

#define DNS_FLAG_QR_MASK     0x8000
#define DNS_FLAG_QR_SHIFT    15
#define DNS_FLAG_OPCODE_MASK 0x7800
#define DNS_FLAG_OPCODE_SHIFT 11
#define DNS_FLAG_AA_MASK     0x0400
#define DNS_FLAG_AA_SHIFT    10
#define DNS_FLAG_TC_MASK     0x0200
#define DNS_FLAG_TC_SHIFT    9
#define DNS_FLAG_RD_MASK     0x0100
#define DNS_FLAG_RD_SHIFT    8
#define DNS_FLAG_RA_MASK     0x0080
#define DNS_FLAG_RA_SHIFT    7
#define DNS_FLAG_Z_MASK      0x0070
#define DNS_FLAG_Z_SHIFT     4
#define DNS_FLAG_RCODE_MASK  0x000F
#define DNS_FLAG_RCODE_SHIFT 0

static inline uint16_t
dns_pack_flags (const SocketDNS_Header *h)
{
  uint16_t flags = 0;

  flags |= ((uint16_t)(h->qr & 0x01)) << DNS_FLAG_QR_SHIFT;
  flags |= ((uint16_t)(h->opcode & 0x0F)) << DNS_FLAG_OPCODE_SHIFT;
  flags |= ((uint16_t)(h->aa & 0x01)) << DNS_FLAG_AA_SHIFT;
  flags |= ((uint16_t)(h->tc & 0x01)) << DNS_FLAG_TC_SHIFT;
  flags |= ((uint16_t)(h->rd & 0x01)) << DNS_FLAG_RD_SHIFT;
  flags |= ((uint16_t)(h->ra & 0x01)) << DNS_FLAG_RA_SHIFT;
  flags |= ((uint16_t)(h->z & 0x07)) << DNS_FLAG_Z_SHIFT;
  flags |= ((uint16_t)(h->rcode & 0x0F)) << DNS_FLAG_RCODE_SHIFT;

  return flags;
}

static inline void
dns_unpack_flags (uint16_t flags, SocketDNS_Header *h)
{
  h->qr = (uint8_t)((flags & DNS_FLAG_QR_MASK) >> DNS_FLAG_QR_SHIFT);
  h->opcode = (uint8_t)((flags & DNS_FLAG_OPCODE_MASK) >> DNS_FLAG_OPCODE_SHIFT);
  h->aa = (uint8_t)((flags & DNS_FLAG_AA_MASK) >> DNS_FLAG_AA_SHIFT);
  h->tc = (uint8_t)((flags & DNS_FLAG_TC_MASK) >> DNS_FLAG_TC_SHIFT);
  h->rd = (uint8_t)((flags & DNS_FLAG_RD_MASK) >> DNS_FLAG_RD_SHIFT);
  h->ra = (uint8_t)((flags & DNS_FLAG_RA_MASK) >> DNS_FLAG_RA_SHIFT);
  h->z = (uint8_t)((flags & DNS_FLAG_Z_MASK) >> DNS_FLAG_Z_SHIFT);
  h->rcode = (uint8_t)((flags & DNS_FLAG_RCODE_MASK) >> DNS_FLAG_RCODE_SHIFT);
}

int
SocketDNS_header_encode (const SocketDNS_Header *header, unsigned char *buf,
                         size_t buflen)
{
  uint16_t flags;

  if (!header || !buf)
    return -1;

  if (buflen < DNS_HEADER_SIZE)
    return -1;

  /* Bytes 0-1: ID */
  dns_pack_be16 (buf + 0, header->id);

  /* Bytes 2-3: Flags */
  flags = dns_pack_flags (header);
  dns_pack_be16 (buf + 2, flags);

  /* Bytes 4-5: QDCOUNT */
  dns_pack_be16 (buf + 4, header->qdcount);

  /* Bytes 6-7: ANCOUNT */
  dns_pack_be16 (buf + 6, header->ancount);

  /* Bytes 8-9: NSCOUNT */
  dns_pack_be16 (buf + 8, header->nscount);

  /* Bytes 10-11: ARCOUNT */
  dns_pack_be16 (buf + 10, header->arcount);

  return 0;
}

int
SocketDNS_header_decode (const unsigned char *data, size_t datalen,
                         SocketDNS_Header *header)
{
  uint16_t flags;

  if (!data || !header)
    return -1;

  if (datalen < DNS_HEADER_SIZE)
    return -1;

  /* Bytes 0-1: ID */
  header->id = dns_unpack_be16 (data + 0);

  /* Bytes 2-3: Flags */
  flags = dns_unpack_be16 (data + 2);
  dns_unpack_flags (flags, header);

  /* Bytes 4-5: QDCOUNT */
  header->qdcount = dns_unpack_be16 (data + 4);

  /* Bytes 6-7: ANCOUNT */
  header->ancount = dns_unpack_be16 (data + 6);

  /* Bytes 8-9: NSCOUNT */
  header->nscount = dns_unpack_be16 (data + 8);

  /* Bytes 10-11: ARCOUNT */
  header->arcount = dns_unpack_be16 (data + 10);

  return 0;
}

void
SocketDNS_header_init_query (SocketDNS_Header *header, uint16_t id,
                             uint16_t qdcount)
{
  if (!header)
    return;

  memset (header, 0, sizeof (*header));
  header->id = id;
  header->qr = 0;                 /* Query */
  header->opcode = DNS_OPCODE_QUERY;
  header->rd = 1;                 /* Request recursion */
  header->qdcount = qdcount;
}
