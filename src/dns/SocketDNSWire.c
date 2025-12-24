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

static inline uint32_t
dns_unpack_be32 (const unsigned char *p)
{
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline void
dns_pack_be32 (unsigned char *p, uint32_t v)
{
  p[0] = (unsigned char)((v >> 24) & 0xFF);
  p[1] = (unsigned char)((v >> 16) & 0xFF);
  p[2] = (unsigned char)((v >> 8) & 0xFF);
  p[3] = (unsigned char)(v & 0xFF);
}

/* Silence compiler warning for unused static inline */
static inline void
dns_pack_be32_unused_check (void)
{
  (void)dns_pack_be32;
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

/*
 * Domain Name Encoding/Decoding (RFC 1035 Section 4.1.2, 4.1.4)
 *
 * Domain names are encoded as a sequence of labels:
 *   [length][label data][length][label data]...[0]
 *
 * Each label is preceded by a length byte (1-63).
 * The sequence ends with a zero-length byte.
 *
 * Compression pointers (RFC 1035 Section 4.1.4):
 *   [11xxxxxx][xxxxxxxx] - 14-bit offset from message start
 */

/* Case-insensitive character comparison for ASCII (RFC 1035 Section 2.3.3) */
static inline int
dns_char_equal_ci (unsigned char a, unsigned char b)
{
  if (a >= 'A' && a <= 'Z')
    a = (unsigned char)(a + 32);
  if (b >= 'A' && b <= 'Z')
    b = (unsigned char)(b + 32);
  return a == b;
}

int
SocketDNS_name_valid (const char *name)
{
  size_t wire_len;
  size_t label_len;
  const char *p;

  if (!name)
    return 0;

  /* Empty string or just "." = root domain, valid */
  if (name[0] == '\0' || (name[0] == '.' && name[1] == '\0'))
    return 1;

  wire_len = 0;
  label_len = 0;
  p = name;

  while (*p)
    {
      if (*p == '.')
        {
          /* Empty label (consecutive dots or leading dot) */
          if (label_len == 0)
            return 0;
          /* Label too long */
          if (label_len > DNS_MAX_LABEL_LEN)
            return 0;
          wire_len += 1 + label_len; /* length byte + label */
          label_len = 0;
        }
      else
        {
          label_len++;
        }
      p++;
    }

  /* Handle final label (unless trailing dot) */
  if (label_len > 0)
    {
      if (label_len > DNS_MAX_LABEL_LEN)
        return 0;
      wire_len += 1 + label_len;
    }

  /* Add terminating zero byte */
  wire_len += 1;

  /* Total length check */
  if (wire_len > DNS_MAX_NAME_LEN)
    return 0;

  return 1;
}

size_t
SocketDNS_name_wire_length (const char *name)
{
  size_t wire_len;
  size_t label_len;
  const char *p;

  if (!name)
    return 0;

  /* Empty string or root domain */
  if (name[0] == '\0' || (name[0] == '.' && name[1] == '\0'))
    return 1; /* Just the terminating zero byte */

  wire_len = 0;
  label_len = 0;
  p = name;

  while (*p)
    {
      if (*p == '.')
        {
          if (label_len == 0 || label_len > DNS_MAX_LABEL_LEN)
            return 0; /* Invalid */
          wire_len += 1 + label_len;
          label_len = 0;
        }
      else
        {
          label_len++;
        }
      p++;
    }

  /* Final label */
  if (label_len > 0)
    {
      if (label_len > DNS_MAX_LABEL_LEN)
        return 0;
      wire_len += 1 + label_len;
    }

  /* Terminating zero */
  wire_len += 1;

  if (wire_len > DNS_MAX_NAME_LEN)
    return 0;

  return wire_len;
}

int
SocketDNS_name_encode (const char *name, unsigned char *buf, size_t buflen,
                       size_t *written)
{
  const char *label_start;
  const char *p;
  size_t pos;
  size_t label_len;

  if (!name || !buf)
    return -1;

  /* Validate first */
  if (!SocketDNS_name_valid (name))
    return -1;

  pos = 0;

  /* Handle empty string (root domain) */
  if (name[0] == '\0' || (name[0] == '.' && name[1] == '\0'))
    {
      if (buflen < 1)
        return -1;
      buf[0] = 0;
      if (written)
        *written = 1;
      return 0;
    }

  label_start = name;
  p = name;

  while (*p)
    {
      if (*p == '.')
        {
          label_len = (size_t)(p - label_start);

          /* Need space for length byte + label data */
          if (pos + 1 + label_len > buflen)
            return -1;

          buf[pos++] = (unsigned char)label_len;
          memcpy (buf + pos, label_start, label_len);
          pos += label_len;

          label_start = p + 1;
        }
      p++;
    }

  /* Final label (if no trailing dot) */
  label_len = (size_t)(p - label_start);
  if (label_len > 0)
    {
      if (pos + 1 + label_len > buflen)
        return -1;
      buf[pos++] = (unsigned char)label_len;
      memcpy (buf + pos, label_start, label_len);
      pos += label_len;
    }

  /* Terminating zero byte */
  if (pos >= buflen)
    return -1;
  buf[pos++] = 0;

  if (written)
    *written = pos;

  return 0;
}

int
SocketDNS_name_decode (const unsigned char *msg, size_t msglen, size_t offset,
                       char *buf, size_t buflen, size_t *consumed)
{
  size_t out_pos;
  size_t wire_pos;
  size_t first_end;
  int hops;
  int jumped;

  if (!msg || !buf || buflen == 0)
    return -1;

  if (offset >= msglen)
    return -1;

  out_pos = 0;
  wire_pos = offset;
  first_end = 0;
  hops = 0;
  jumped = 0;

  while (1)
    {
      unsigned char len_byte;

      if (wire_pos >= msglen)
        return -1;

      len_byte = msg[wire_pos];

      /* Check for compression pointer */
      if ((len_byte & DNS_COMPRESSION_FLAG) == DNS_COMPRESSION_FLAG)
        {
          uint16_t ptr_offset;

          /* Need two bytes for pointer */
          if (wire_pos + 1 >= msglen)
            return -1;

          ptr_offset
              = ((uint16_t)(len_byte & 0x3F) << 8) | msg[wire_pos + 1];

          /* Pointer must be valid */
          if (ptr_offset >= msglen)
            return -1;

          /* Track first end position for consumed calculation */
          if (!jumped)
            {
              first_end = wire_pos + 2;
              jumped = 1;
            }

          /* Prevent infinite loops */
          if (++hops > DNS_MAX_POINTER_HOPS)
            return -1;

          wire_pos = ptr_offset;
          continue;
        }

      /* Check for reserved bits (10 or 01) - invalid */
      if ((len_byte & 0xC0) != 0 && (len_byte & DNS_COMPRESSION_FLAG) != DNS_COMPRESSION_FLAG)
        return -1;

      /* Zero length = end of name */
      if (len_byte == 0)
        {
          /* Move past the zero byte if not jumped */
          if (!jumped)
            first_end = wire_pos + 1;
          break;
        }

      /* Validate label length */
      if (len_byte > DNS_MAX_LABEL_LEN)
        return -1;

      /* Check there's enough data for the label */
      if (wire_pos + 1 + len_byte > msglen)
        return -1;

      /* Add dot separator (except for first label) */
      if (out_pos > 0)
        {
          if (out_pos >= buflen - 1)
            return -1;
          buf[out_pos++] = '.';
        }

      /* Check output buffer space */
      if (out_pos + len_byte >= buflen)
        return -1;

      /* Copy label data */
      memcpy (buf + out_pos, msg + wire_pos + 1, len_byte);
      out_pos += len_byte;
      wire_pos += 1 + len_byte;
    }

  /* Null terminate */
  buf[out_pos] = '\0';

  if (consumed)
    *consumed = first_end - offset;

  return (int)out_pos;
}

int
SocketDNS_name_equal (const char *name1, const char *name2)
{
  const char *p1, *p2;

  if (!name1 || !name2)
    return 0;

  p1 = name1;
  p2 = name2;

  while (*p1 && *p2)
    {
      if (!dns_char_equal_ci ((unsigned char)*p1, (unsigned char)*p2))
        return 0;
      p1++;
      p2++;
    }

  /* Handle trailing dots: "example.com" == "example.com." */
  while (*p1 == '.')
    p1++;
  while (*p2 == '.')
    p2++;

  return (*p1 == '\0' && *p2 == '\0');
}

/*
 * Question Section Encoding/Decoding (RFC 1035 Section 4.1.2)
 *
 * Each question has three fields:
 *   QNAME  - variable length domain name
 *   QTYPE  - 2 bytes, query type
 *   QCLASS - 2 bytes, query class
 */

int
SocketDNS_question_encode (const SocketDNS_Question *question,
                           unsigned char *buf, size_t buflen, size_t *written)
{
  size_t name_len;
  size_t pos;

  if (!question || !buf)
    return -1;

  /* Encode the domain name first */
  if (SocketDNS_name_encode (question->qname, buf, buflen, &name_len) != 0)
    return -1;

  pos = name_len;

  /* Need 4 more bytes for QTYPE and QCLASS */
  if (pos + 4 > buflen)
    return -1;

  /* QTYPE (2 bytes, big-endian) */
  dns_pack_be16 (buf + pos, question->qtype);
  pos += 2;

  /* QCLASS (2 bytes, big-endian) */
  dns_pack_be16 (buf + pos, question->qclass);
  pos += 2;

  if (written)
    *written = pos;

  return 0;
}

int
SocketDNS_question_decode (const unsigned char *msg, size_t msglen,
                           size_t offset, SocketDNS_Question *question,
                           size_t *consumed)
{
  size_t name_consumed;
  int name_len;
  size_t pos;

  if (!msg || !question)
    return -1;

  if (offset >= msglen)
    return -1;

  /* Decode the domain name */
  name_len = SocketDNS_name_decode (msg, msglen, offset, question->qname,
                                    sizeof (question->qname), &name_consumed);
  if (name_len < 0)
    return -1;

  pos = offset + name_consumed;

  /* Need 4 more bytes for QTYPE and QCLASS */
  if (pos + 4 > msglen)
    return -1;

  /* QTYPE (2 bytes, big-endian) */
  question->qtype = dns_unpack_be16 (msg + pos);
  pos += 2;

  /* QCLASS (2 bytes, big-endian) */
  question->qclass = dns_unpack_be16 (msg + pos);
  pos += 2;

  if (consumed)
    *consumed = pos - offset;

  return 0;
}

void
SocketDNS_question_init (SocketDNS_Question *question, const char *name,
                         uint16_t qtype)
{
  size_t name_len;

  if (!question)
    return;

  memset (question, 0, sizeof (*question));

  if (name)
    {
      name_len = strlen (name);
      if (name_len >= sizeof (question->qname))
        name_len = sizeof (question->qname) - 1;
      memcpy (question->qname, name, name_len);
      question->qname[name_len] = '\0';
    }

  question->qtype = qtype;
  question->qclass = DNS_CLASS_IN; /* Default to Internet class */
}

/*
 * Resource Record Decoding (RFC 1035 Section 4.1.3)
 *
 * RR Format:
 *   NAME     - variable length domain name (may be compressed)
 *   TYPE     - 2 bytes
 *   CLASS    - 2 bytes
 *   TTL      - 4 bytes
 *   RDLENGTH - 2 bytes
 *   RDATA    - variable length (RDLENGTH bytes)
 *
 * Fixed portion after NAME is 10 bytes (2+2+4+2).
 */

#define DNS_RR_FIXED_SIZE 10 /* TYPE + CLASS + TTL + RDLENGTH */

int
SocketDNS_rr_decode (const unsigned char *msg, size_t msglen, size_t offset,
                     SocketDNS_RR *rr, size_t *consumed)
{
  size_t name_consumed;
  int name_len;
  size_t pos;
  uint16_t rdlength;

  if (!msg || !rr)
    return -1;

  if (offset >= msglen)
    return -1;

  /* Decode the owner name */
  name_len = SocketDNS_name_decode (msg, msglen, offset, rr->name,
                                    sizeof (rr->name), &name_consumed);
  if (name_len < 0)
    return -1;

  pos = offset + name_consumed;

  /* Need 10 more bytes for TYPE, CLASS, TTL, RDLENGTH */
  if (pos + DNS_RR_FIXED_SIZE > msglen)
    return -1;

  /* TYPE (2 bytes) */
  rr->type = dns_unpack_be16 (msg + pos);
  pos += 2;

  /* CLASS (2 bytes) */
  rr->rclass = dns_unpack_be16 (msg + pos);
  pos += 2;

  /* TTL (4 bytes) */
  rr->ttl = dns_unpack_be32 (msg + pos);
  pos += 4;

  /* RDLENGTH (2 bytes) */
  rdlength = dns_unpack_be16 (msg + pos);
  pos += 2;

  /* Verify RDATA fits in message */
  if (pos + rdlength > msglen)
    return -1;

  rr->rdlength = rdlength;
  rr->rdata = (rdlength > 0) ? (msg + pos) : NULL;

  if (consumed)
    *consumed = name_consumed + DNS_RR_FIXED_SIZE + rdlength;

  return 0;
}

int
SocketDNS_rr_skip (const unsigned char *msg, size_t msglen, size_t offset,
                   size_t *consumed)
{
  char name_buf[DNS_MAX_NAME_LEN];
  size_t name_consumed;
  int name_len;
  size_t pos;
  uint16_t rdlength;

  if (!msg)
    return -1;

  if (offset >= msglen)
    return -1;

  /* Skip the name */
  name_len
      = SocketDNS_name_decode (msg, msglen, offset, name_buf, sizeof (name_buf),
                               &name_consumed);
  if (name_len < 0)
    return -1;

  pos = offset + name_consumed;

  /* Need 10 bytes for fixed fields */
  if (pos + DNS_RR_FIXED_SIZE > msglen)
    return -1;

  /* Skip TYPE, CLASS, TTL to get RDLENGTH at offset+6 */
  rdlength = dns_unpack_be16 (msg + pos + 8);

  /* Verify RDATA fits */
  if (pos + DNS_RR_FIXED_SIZE + rdlength > msglen)
    return -1;

  if (consumed)
    *consumed = name_consumed + DNS_RR_FIXED_SIZE + rdlength;

  return 0;
}

/*
 * A and AAAA RDATA Parsing (RFC 1035 Section 3.4.1, RFC 3596)
 *
 * A Record:
 *   4 bytes - 32-bit IPv4 address in network byte order
 *
 * AAAA Record:
 *   16 bytes - 128-bit IPv6 address in network byte order
 */

int
SocketDNS_rdata_parse_a (const SocketDNS_RR *rr, struct in_addr *addr)
{
  if (!rr || !addr)
    return -1;

  /* Validate RR type */
  if (rr->type != DNS_TYPE_A)
    return -1;

  /* A record RDATA must be exactly 4 bytes (RFC 1035 Section 3.4.1) */
  if (rr->rdlength != DNS_RDATA_A_SIZE)
    return -1;

  /* Ensure RDATA pointer is valid */
  if (!rr->rdata)
    return -1;

  /* Copy 4 bytes directly - already in network byte order */
  memcpy (&addr->s_addr, rr->rdata, DNS_RDATA_A_SIZE);

  return 0;
}

int
SocketDNS_rdata_parse_aaaa (const SocketDNS_RR *rr, struct in6_addr *addr)
{
  if (!rr || !addr)
    return -1;

  /* Validate RR type */
  if (rr->type != DNS_TYPE_AAAA)
    return -1;

  /* AAAA record RDATA must be exactly 16 bytes (RFC 3596) */
  if (rr->rdlength != DNS_RDATA_AAAA_SIZE)
    return -1;

  /* Ensure RDATA pointer is valid */
  if (!rr->rdata)
    return -1;

  /* Copy 16 bytes directly - already in network byte order */
  memcpy (addr->s6_addr, rr->rdata, DNS_RDATA_AAAA_SIZE);

  return 0;
}

/*
 * CNAME RDATA Parsing (RFC 1035 Section 3.3.1)
 *
 * CNAME Record:
 *   Variable length - domain name (may use compression pointers)
 *
 * The CNAME RDATA contains a single domain name that specifies the
 * canonical or primary name for the owner. Unlike A/AAAA which contain
 * raw address bytes, CNAME requires full message context for compression
 * pointer resolution.
 */

int
SocketDNS_rdata_parse_cname (const unsigned char *msg, size_t msglen,
                             const SocketDNS_RR *rr, char *cname,
                             size_t cnamelen)
{
  size_t rdata_offset;

  if (!msg || !rr || !cname || cnamelen == 0)
    return -1;

  /* Validate RR type */
  if (rr->type != DNS_TYPE_CNAME)
    return -1;

  /* RDATA must be present and non-empty */
  if (!rr->rdata || rr->rdlength == 0)
    return -1;

  /* Calculate offset of RDATA within message */
  rdata_offset = (size_t)(rr->rdata - msg);

  /* Validate offset is within message bounds */
  if (rdata_offset >= msglen || rdata_offset + rr->rdlength > msglen)
    return -1;

  /* Decode the domain name from RDATA (handles compression pointers) */
  return SocketDNS_name_decode (msg, msglen, rdata_offset, cname, cnamelen,
                                NULL);
}

/*
 * SOA RDATA Parsing (RFC 1035 Section 3.3.13)
 *
 * SOA Record (Start of Authority):
 *   MNAME   - domain name of primary nameserver
 *   RNAME   - domain name of responsible person mailbox
 *   SERIAL  - 32-bit zone version number
 *   REFRESH - 32-bit refresh interval (seconds)
 *   RETRY   - 32-bit retry interval (seconds)
 *   EXPIRE  - 32-bit expire time (seconds)
 *   MINIMUM - 32-bit negative cache TTL (seconds)
 *
 * Both MNAME and RNAME may use compression pointers, requiring
 * full message context for resolution.
 */

int
SocketDNS_rdata_parse_soa (const unsigned char *msg, size_t msglen,
                           const SocketDNS_RR *rr, SocketDNS_SOA *soa)
{
  size_t rdata_offset;
  size_t offset;
  size_t consumed;
  int name_len;

  if (!msg || !rr || !soa)
    return -1;

  /* Validate RR type */
  if (rr->type != DNS_TYPE_SOA)
    return -1;

  /* RDATA must be present and non-empty */
  if (!rr->rdata || rr->rdlength == 0)
    return -1;

  /* Calculate offset of RDATA within message */
  rdata_offset = (size_t)(rr->rdata - msg);

  /* Validate offset is within message bounds */
  if (rdata_offset >= msglen || rdata_offset + rr->rdlength > msglen)
    return -1;

  offset = rdata_offset;

  /* Decode MNAME (primary nameserver) */
  name_len = SocketDNS_name_decode (msg, msglen, offset, soa->mname,
                                    sizeof (soa->mname), &consumed);
  if (name_len < 0)
    return -1;
  offset += consumed;

  /* Decode RNAME (responsible person mailbox) */
  name_len = SocketDNS_name_decode (msg, msglen, offset, soa->rname,
                                    sizeof (soa->rname), &consumed);
  if (name_len < 0)
    return -1;
  offset += consumed;

  /* Verify enough bytes remain for fixed fields (20 bytes) */
  if (offset + DNS_SOA_FIXED_SIZE > rdata_offset + rr->rdlength)
    return -1;

  /* Also verify we don't read past message end */
  if (offset + DNS_SOA_FIXED_SIZE > msglen)
    return -1;

  /* Extract SERIAL (32-bit, network byte order) */
  soa->serial = ((uint32_t)msg[offset] << 24) |
                ((uint32_t)msg[offset + 1] << 16) |
                ((uint32_t)msg[offset + 2] << 8) |
                ((uint32_t)msg[offset + 3]);
  offset += 4;

  /* Extract REFRESH (32-bit, network byte order) */
  soa->refresh = ((uint32_t)msg[offset] << 24) |
                 ((uint32_t)msg[offset + 1] << 16) |
                 ((uint32_t)msg[offset + 2] << 8) |
                 ((uint32_t)msg[offset + 3]);
  offset += 4;

  /* Extract RETRY (32-bit, network byte order) */
  soa->retry = ((uint32_t)msg[offset] << 24) |
               ((uint32_t)msg[offset + 1] << 16) |
               ((uint32_t)msg[offset + 2] << 8) |
               ((uint32_t)msg[offset + 3]);
  offset += 4;

  /* Extract EXPIRE (32-bit, network byte order) */
  soa->expire = ((uint32_t)msg[offset] << 24) |
                ((uint32_t)msg[offset + 1] << 16) |
                ((uint32_t)msg[offset + 2] << 8) |
                ((uint32_t)msg[offset + 3]);
  offset += 4;

  /* Extract MINIMUM (32-bit, network byte order) */
  soa->minimum = ((uint32_t)msg[offset] << 24) |
                 ((uint32_t)msg[offset + 1] << 16) |
                 ((uint32_t)msg[offset + 2] << 8) |
                 ((uint32_t)msg[offset + 3]);

  return 0;
}

/*
 * EDNS0 OPT Pseudo-RR Encoding/Decoding (RFC 6891)
 *
 * The OPT record is a pseudo-RR with non-standard field usage:
 *   NAME     - Must be 0 (root domain, single zero byte)
 *   TYPE     - 41 (OPT)
 *   CLASS    - Requestor's UDP payload size
 *   TTL      - Extended RCODE (8 bits) | VERSION (8 bits) | DO (1 bit) | Z (15 bits)
 *   RDLENGTH - Length of options data
 *   RDATA    - Zero or more {option-code, option-length, option-data} tuples
 *
 * Wire format (11 bytes minimum without options):
 *   +--+--+--+--+--+--+--+--+--+--+--+
 *   |0 |  TYPE=41  |  UDP SIZE |  TTL (4 bytes)  | RDLEN |
 *   +--+--+--+--+--+--+--+--+--+--+--+
 */

void
SocketDNS_opt_init (SocketDNS_OPT *opt, uint16_t udp_size)
{
  if (!opt)
    return;

  memset (opt, 0, sizeof (*opt));

  /* Enforce minimum UDP payload size per RFC 6891 Section 6.2.3 */
  opt->udp_payload_size = (udp_size < DNS_EDNS0_MIN_UDPSIZE)
                              ? DNS_EDNS0_MIN_UDPSIZE
                              : udp_size;
  opt->version = DNS_EDNS0_VERSION;
  /* do_bit = 0, z = 0, rdlength = 0, rdata = NULL (already zeroed) */
}

int
SocketDNS_opt_encode (const SocketDNS_OPT *opt, unsigned char *buf,
                      size_t buflen)
{
  size_t total;
  uint32_t ttl;
  unsigned char *p;

  if (!opt || !buf)
    return -1;

  total = DNS_OPT_FIXED_SIZE + opt->rdlength;
  if (buflen < total)
    return -1;

  p = buf;

  /* NAME = root (single zero byte) */
  *p++ = 0x00;

  /* TYPE = OPT (41) */
  dns_pack_be16 (p, DNS_TYPE_OPT);
  p += 2;

  /* CLASS = UDP payload size */
  dns_pack_be16 (p, opt->udp_payload_size);
  p += 2;

  /* TTL = extended RCODE (8) | version (8) | DO (1) | Z (15) */
  ttl = ((uint32_t)opt->extended_rcode << 24)
        | ((uint32_t)opt->version << 16)
        | ((uint32_t)(opt->do_bit ? 0x8000 : 0))
        | ((uint32_t)(opt->z & 0x7FFF));
  dns_pack_be32 (p, ttl);
  p += 4;

  /* RDLENGTH */
  dns_pack_be16 (p, opt->rdlength);
  p += 2;

  /* RDATA (options) */
  if (opt->rdlength > 0 && opt->rdata != NULL)
    memcpy (p, opt->rdata, opt->rdlength);

  return (int)total;
}

int
SocketDNS_opt_decode (const unsigned char *buf, size_t len, SocketDNS_OPT *opt)
{
  const unsigned char *p;
  uint16_t type;
  uint32_t ttl;

  if (!buf || !opt)
    return -1;

  if (len < DNS_OPT_FIXED_SIZE)
    return -1;

  p = buf;

  /* NAME must be root (single zero byte) */
  if (*p++ != 0x00)
    return -1;

  /* TYPE must be OPT (41) */
  type = dns_unpack_be16 (p);
  p += 2;
  if (type != DNS_TYPE_OPT)
    return -1;

  /* CLASS = UDP payload size */
  opt->udp_payload_size = dns_unpack_be16 (p);
  p += 2;

  /* TTL = extended RCODE | version | flags */
  ttl = dns_unpack_be32 (p);
  p += 4;

  opt->extended_rcode = (uint8_t)((ttl >> 24) & 0xFF);
  opt->version = (uint8_t)((ttl >> 16) & 0xFF);
  opt->do_bit = (uint8_t)((ttl >> 15) & 0x01);
  opt->z = (uint16_t)(ttl & 0x7FFF);

  /* RDLENGTH */
  opt->rdlength = dns_unpack_be16 (p);
  p += 2;

  /* Validate RDLENGTH doesn't exceed available buffer */
  if (len < (size_t)DNS_OPT_FIXED_SIZE + opt->rdlength)
    return -1;

  /* RDATA pointer (not copied, points into buffer) */
  opt->rdata = (opt->rdlength > 0) ? p : NULL;

  return DNS_OPT_FIXED_SIZE + (int)opt->rdlength;
}

/*
 * OPT Record Validation (RFC 6891 Section 6.1.1)
 */

int
SocketDNS_opt_is_valid_name (unsigned char name_byte)
{
  /* Per RFC 6891, OPT NAME MUST be 0 (root domain) */
  return (name_byte == 0x00) ? 1 : 0;
}

SocketDNS_OPT_ValidationResult
SocketDNS_opt_validate (const SocketDNS_OPT *opt, size_t rdata_len)
{
  SocketDNS_EDNSOptionIter iter;
  SocketDNS_EDNSOption option;

  if (!opt)
    return DNS_OPT_INVALID_RDATA;

  /* Check RDLEN doesn't exceed available data */
  if (opt->rdlength > rdata_len)
    return DNS_OPT_TRUNCATED;

  /* Empty RDATA is valid */
  if (opt->rdlength == 0)
    return DNS_OPT_VALID;

  /* Validate all options in RDATA can be parsed */
  if (opt->rdata == NULL && opt->rdlength > 0)
    return DNS_OPT_INVALID_RDATA;

  SocketDNS_edns_option_iter_init (&iter, opt->rdata, opt->rdlength);

  /* Iterate through all options to verify they're well-formed */
  while (SocketDNS_edns_option_iter_next (&iter, &option))
    {
      /* Option parsed successfully, continue */
    }

  /* Check if we consumed all RDATA - if not, there's trailing garbage
   * or a malformed option that caused early termination */
  if (iter.pos != iter.end)
    return DNS_OPT_MALFORMED_OPTION;

  return DNS_OPT_VALID;
}

int
SocketDNS_response_count_opt (const unsigned char *msg, size_t msg_len,
                               const SocketDNS_Header *hdr)
{
  size_t offset;
  int opt_count;
  uint16_t i;
  uint16_t qdcount, ancount, nscount, arcount;
  SocketDNS_Question q;
  SocketDNS_RR rr;
  size_t consumed;

  if (!msg || !hdr || msg_len < DNS_HEADER_SIZE)
    return -1;

  qdcount = hdr->qdcount;
  ancount = hdr->ancount;
  nscount = hdr->nscount;
  arcount = hdr->arcount;

  offset = DNS_HEADER_SIZE;

  /* Skip question section */
  for (i = 0; i < qdcount; i++)
    {
      if (SocketDNS_question_decode (msg, msg_len, offset, &q, &consumed) < 0)
        return -1;
      offset += consumed;
    }

  /* Skip answer section */
  for (i = 0; i < ancount; i++)
    {
      if (SocketDNS_rr_decode (msg, msg_len, offset, &rr, &consumed) < 0)
        return -1;
      offset += consumed;
    }

  /* Skip authority section */
  for (i = 0; i < nscount; i++)
    {
      if (SocketDNS_rr_decode (msg, msg_len, offset, &rr, &consumed) < 0)
        return -1;
      offset += consumed;
    }

  /* Count OPT records in additional section */
  opt_count = 0;
  for (i = 0; i < arcount; i++)
    {
      if (SocketDNS_rr_decode (msg, msg_len, offset, &rr, &consumed) < 0)
        return -1;

      if (rr.type == DNS_TYPE_OPT)
        opt_count++;

      offset += consumed;
    }

  return opt_count;
}

const char *
SocketDNS_opt_validation_str (SocketDNS_OPT_ValidationResult result)
{
  switch (result)
    {
    case DNS_OPT_VALID:
      return "valid";
    case DNS_OPT_INVALID_NAME:
      return "invalid NAME (must be root)";
    case DNS_OPT_INVALID_TYPE:
      return "invalid TYPE (must be 41)";
    case DNS_OPT_MULTIPLE:
      return "multiple OPT records";
    case DNS_OPT_TRUNCATED:
      return "truncated RDATA";
    case DNS_OPT_MALFORMED_OPTION:
      return "malformed option in RDATA";
    case DNS_OPT_INVALID_RDATA:
      return "invalid RDATA";
    default:
      return "unknown error";
    }
}

uint16_t
SocketDNS_opt_extended_rcode (const SocketDNS_Header *hdr,
                              const SocketDNS_OPT *opt)
{
  uint16_t rcode;

  if (!hdr)
    return 0;

  /* Base 4-bit RCODE from header */
  rcode = (uint16_t)(hdr->rcode & 0x0F);

  /* Combine with upper 8 bits from OPT if present */
  if (opt != NULL)
    rcode |= ((uint16_t)opt->extended_rcode << 4);

  return rcode;
}

/*
 * OPT TTL Field Encoding/Decoding (RFC 6891 Section 6.1.3)
 *
 * The TTL field in OPT records is repurposed as follows:
 *
 *   Bits 31-24: EXTENDED-RCODE (8 bits) - Upper 8 bits of 12-bit RCODE
 *   Bits 23-16: VERSION (8 bits) - EDNS version (0 for EDNS0)
 *   Bit 15:     DO (1 bit) - DNSSEC OK flag
 *   Bits 14-0:  Z (15 bits) - Reserved, must be zero
 */

void
SocketDNS_opt_ttl_decode (uint32_t ttl, SocketDNS_OPT_Flags *flags)
{
  if (!flags)
    return;

  flags->extended_rcode = (uint8_t)((ttl >> 24) & 0xFF);
  flags->version = (uint8_t)((ttl >> 16) & 0xFF);
  flags->do_bit = (uint8_t)((ttl >> 15) & 0x01);
  flags->z = (uint16_t)(ttl & 0x7FFF);
}

uint32_t
SocketDNS_opt_ttl_encode (const SocketDNS_OPT_Flags *flags)
{
  if (!flags)
    return 0;

  return ((uint32_t)flags->extended_rcode << 24)
         | ((uint32_t)flags->version << 16)
         | ((uint32_t)(flags->do_bit ? 0x8000 : 0))
         | ((uint32_t)(flags->z & 0x7FFF));
}

int
SocketDNS_opt_get_version (const SocketDNS_OPT *opt)
{
  if (!opt)
    return -1;

  return (int)opt->version;
}

int
SocketDNS_opt_is_badvers (const SocketDNS_Header *hdr,
                          const SocketDNS_OPT *opt)
{
  uint16_t ext_rcode;

  if (!hdr)
    return 0;

  ext_rcode = SocketDNS_opt_extended_rcode (hdr, opt);

  return (ext_rcode == DNS_RCODE_EXT_BADVERS) ? 1 : 0;
}

/*
 * EDNS0 Option Parsing (RFC 6891 Section 6.1.2)
 *
 * Options are encoded as tuples in the OPT RDATA:
 *   OPTION-CODE   - 2 bytes (uint16_t, big-endian)
 *   OPTION-LENGTH - 2 bytes (uint16_t, big-endian)
 *   OPTION-DATA   - variable length (OPTION-LENGTH bytes)
 *
 * Multiple options can appear consecutively. Order is undefined.
 * Unknown option codes MUST be ignored per RFC 6891.
 */

int
SocketDNS_edns_option_encode (const SocketDNS_EDNSOption *option,
                              unsigned char *buf, size_t buflen)
{
  size_t total;

  if (!option || !buf)
    return -1;

  /* Calculate total size: 2 (code) + 2 (length) + data */
  total = DNS_EDNS_OPTION_HEADER_SIZE + option->length;

  if (buflen < total)
    return -1;

  /* OPTION-CODE (2 bytes, big-endian) */
  dns_pack_be16 (buf, option->code);

  /* OPTION-LENGTH (2 bytes, big-endian) */
  dns_pack_be16 (buf + 2, option->length);

  /* OPTION-DATA (variable length) */
  if (option->length > 0)
    {
      if (!option->data)
        return -1;
      memcpy (buf + 4, option->data, option->length);
    }

  return (int)total;
}

void
SocketDNS_edns_option_iter_init (SocketDNS_EDNSOptionIter *iter,
                                  const unsigned char *rdata, size_t rdlen)
{
  if (!iter)
    return;

  if (rdata && rdlen > 0)
    {
      iter->pos = rdata;
      iter->end = rdata + rdlen;
    }
  else
    {
      iter->pos = NULL;
      iter->end = NULL;
    }
}

int
SocketDNS_edns_option_iter_next (SocketDNS_EDNSOptionIter *iter,
                                  SocketDNS_EDNSOption *option)
{
  uint16_t code;
  uint16_t length;
  size_t remaining;

  if (!iter || !option)
    return 0;

  /* Check if we've reached the end or iterator is invalid */
  if (!iter->pos || !iter->end || iter->pos >= iter->end)
    return 0;

  remaining = (size_t)(iter->end - iter->pos);

  /* Need at least 4 bytes for option header (code + length) */
  if (remaining < DNS_EDNS_OPTION_HEADER_SIZE)
    return 0;

  /* Parse OPTION-CODE (2 bytes, big-endian) */
  code = dns_unpack_be16 (iter->pos);

  /* Parse OPTION-LENGTH (2 bytes, big-endian) */
  length = dns_unpack_be16 (iter->pos + 2);

  /* Validate that option data fits in remaining buffer */
  if (remaining < (size_t)DNS_EDNS_OPTION_HEADER_SIZE + (size_t)length)
    return 0;

  /* Fill in the option structure */
  option->code = code;
  option->length = length;
  option->data = (length > 0) ? (iter->pos + 4) : NULL;

  /* Advance iterator past this option */
  iter->pos += (size_t)DNS_EDNS_OPTION_HEADER_SIZE + (size_t)length;

  return 1;
}

int
SocketDNS_edns_option_find (const unsigned char *rdata, size_t rdlen,
                             uint16_t code, SocketDNS_EDNSOption *option)
{
  SocketDNS_EDNSOptionIter iter;
  SocketDNS_EDNSOption opt;

  if (!option)
    return 0;

  /* Initialize iterator */
  SocketDNS_edns_option_iter_init (&iter, rdata, rdlen);

  /* Iterate through all options looking for matching code */
  while (SocketDNS_edns_option_iter_next (&iter, &opt))
    {
      if (opt.code == code)
        {
          *option = opt;
          return 1;
        }
    }

  return 0;
}

int
SocketDNS_edns_options_encode (const SocketDNS_EDNSOption *options,
                                size_t count, unsigned char *buf, size_t buflen)
{
  size_t pos;
  size_t i;
  int encoded;

  if (!buf)
    return -1;

  /* Empty options array is valid - just returns 0 bytes */
  if (!options || count == 0)
    return 0;

  pos = 0;

  for (i = 0; i < count; i++)
    {
      encoded = SocketDNS_edns_option_encode (&options[i], buf + pos,
                                               buflen - pos);
      if (encoded < 0)
        return -1;

      pos += (size_t)encoded;
    }

  return (int)pos;
}

/*
 * EDNS0 UDP Payload Size Selection (RFC 6891 Section 6.2.5)
 *
 * Progressive fallback sequence:
 *   4096 (initial) → 1400 (safe for most paths) → 512 (guaranteed) → TCP
 */

void
SocketDNS_payload_init (SocketDNS_PayloadTracker *tracker)
{
  if (!tracker)
    return;

  tracker->state = DNS_PAYLOAD_STATE_4096;
  tracker->last_working_size = 0;
  tracker->last_failure_time = 0;
  tracker->last_success_time = 0;
  tracker->failure_count = 0;
}

void
SocketDNS_payload_config_init (SocketDNS_PayloadConfig *config)
{
  if (!config)
    return;

  config->initial_size = DNS_PAYLOAD_INITIAL;
  config->fallback1_size = DNS_PAYLOAD_FALLBACK1;
  config->fallback2_size = DNS_PAYLOAD_FALLBACK2;
  config->reset_timeout_sec = DNS_PAYLOAD_RESET_TIMEOUT;
}

uint16_t
SocketDNS_payload_get_size (const SocketDNS_PayloadTracker *tracker,
                             const SocketDNS_PayloadConfig *config)
{
  SocketDNS_PayloadConfig defaults;
  const SocketDNS_PayloadConfig *cfg;
  uint16_t size;

  if (!tracker)
    return DNS_PAYLOAD_INITIAL;

  /* Use provided config or defaults */
  if (config)
    {
      cfg = config;
    }
  else
    {
      SocketDNS_payload_config_init (&defaults);
      cfg = &defaults;
    }

  /* If we have a known working size, use it */
  if (tracker->last_working_size > 0)
    {
      /* Ensure minimum of 512 per RFC 6891 */
      size = tracker->last_working_size;
      if (size < DNS_EDNS0_MIN_UDPSIZE)
        size = DNS_EDNS0_MIN_UDPSIZE;
      return size;
    }

  /* Otherwise, return size based on current state */
  switch (tracker->state)
    {
    case DNS_PAYLOAD_STATE_4096:
      size = cfg->initial_size;
      break;
    case DNS_PAYLOAD_STATE_1400:
      size = cfg->fallback1_size;
      break;
    case DNS_PAYLOAD_STATE_512:
      size = cfg->fallback2_size;
      break;
    case DNS_PAYLOAD_STATE_TCP:
      return 0;  /* Signal that TCP is required */
    default:
      size = cfg->initial_size;
      break;
    }

  /* Enforce minimum per RFC 6891 Section 6.2.3 */
  if (size < DNS_EDNS0_MIN_UDPSIZE)
    size = DNS_EDNS0_MIN_UDPSIZE;

  return size;
}

void
SocketDNS_payload_failed (SocketDNS_PayloadTracker *tracker, uint64_t now)
{
  if (!tracker)
    return;

  tracker->last_failure_time = now;
  tracker->failure_count++;

  /* Clear cached working size - it's no longer reliable */
  tracker->last_working_size = 0;

  /* Advance to next fallback state */
  switch (tracker->state)
    {
    case DNS_PAYLOAD_STATE_4096:
      tracker->state = DNS_PAYLOAD_STATE_1400;
      tracker->failure_count = 0;  /* Reset count for new state */
      break;
    case DNS_PAYLOAD_STATE_1400:
      tracker->state = DNS_PAYLOAD_STATE_512;
      tracker->failure_count = 0;
      break;
    case DNS_PAYLOAD_STATE_512:
      tracker->state = DNS_PAYLOAD_STATE_TCP;
      tracker->failure_count = 0;
      break;
    case DNS_PAYLOAD_STATE_TCP:
      /* Already at TCP, can't fall back further */
      break;
    }
}

void
SocketDNS_payload_succeeded (SocketDNS_PayloadTracker *tracker,
                              uint16_t size, uint64_t now)
{
  if (!tracker)
    return;

  tracker->last_success_time = now;
  tracker->failure_count = 0;

  /* Cache the working size (normalized to minimum) */
  if (size < DNS_EDNS0_MIN_UDPSIZE)
    size = DNS_EDNS0_MIN_UDPSIZE;
  tracker->last_working_size = size;
}

int
SocketDNS_payload_should_reset (const SocketDNS_PayloadTracker *tracker,
                                 const SocketDNS_PayloadConfig *config,
                                 uint64_t now)
{
  SocketDNS_PayloadConfig defaults;
  const SocketDNS_PayloadConfig *cfg;
  uint64_t elapsed;

  if (!tracker)
    return 0;

  /* Already at initial state, no reset needed */
  if (tracker->state == DNS_PAYLOAD_STATE_4096
      && tracker->last_working_size == 0)
    return 0;

  /* Use provided config or defaults */
  if (config)
    {
      cfg = config;
    }
  else
    {
      SocketDNS_payload_config_init (&defaults);
      cfg = &defaults;
    }

  /* Check if enough time has passed since last success */
  if (tracker->last_success_time > 0)
    {
      elapsed = now - tracker->last_success_time;
      if (elapsed >= cfg->reset_timeout_sec)
        return 1;
    }

  /* Also reset if enough time since last failure and we're not at initial */
  if (tracker->last_failure_time > 0
      && tracker->state != DNS_PAYLOAD_STATE_4096)
    {
      elapsed = now - tracker->last_failure_time;
      if (elapsed >= cfg->reset_timeout_sec)
        return 1;
    }

  return 0;
}

void
SocketDNS_payload_reset (SocketDNS_PayloadTracker *tracker)
{
  if (!tracker)
    return;

  tracker->state = DNS_PAYLOAD_STATE_4096;
  tracker->last_working_size = 0;
  tracker->failure_count = 0;
  /* Preserve timestamps for debugging/metrics */
}

int
SocketDNS_payload_needs_tcp (const SocketDNS_PayloadTracker *tracker)
{
  if (!tracker)
    return 0;

  return (tracker->state == DNS_PAYLOAD_STATE_TCP) ? 1 : 0;
}

const char *
SocketDNS_payload_state_name (SocketDNS_PayloadState state)
{
  switch (state)
    {
    case DNS_PAYLOAD_STATE_4096:
      return "4096";
    case DNS_PAYLOAD_STATE_1400:
      return "1400";
    case DNS_PAYLOAD_STATE_512:
      return "512";
    case DNS_PAYLOAD_STATE_TCP:
      return "TCP";
    default:
      return "unknown";
    }
}

/*
 * Security Utilities (RFC 5452)
 */

int
SocketDNS_name_in_bailiwick (const char *record_name, const char *query_name)
{
  size_t rec_len, qry_len;

  if (!record_name || !query_name)
    return 0;

  /* Exact match is always in-bailiwick */
  if (SocketDNS_name_equal (record_name, query_name))
    return 1;

  rec_len = strlen (record_name);
  qry_len = strlen (query_name);

  /* Strip trailing dots for comparison */
  while (rec_len > 0 && record_name[rec_len - 1] == '.')
    rec_len--;
  while (qry_len > 0 && query_name[qry_len - 1] == '.')
    qry_len--;

  /* Record must be longer (subdomain check) */
  if (rec_len <= qry_len)
    return 0;

  /* Must have '.' separator before the suffix */
  if (record_name[rec_len - qry_len - 1] != '.')
    return 0;

  /* Compare suffix case-insensitively */
  const char *suffix = record_name + (rec_len - qry_len);
  for (size_t i = 0; i < qry_len; i++)
    {
      char a = suffix[i], b = query_name[i];
      if (a >= 'A' && a <= 'Z')
        a = (char)(a + 32);
      if (b >= 'A' && b <= 'Z')
        b = (char)(b + 32);
      if (a != b)
        return 0;
    }

  return 1;
}

/*
 * Negative Cache TTL Extraction (RFC 2308)
 *
 * Per RFC 2308 Section 5, the negative cache TTL is calculated as:
 *   TTL = min(SOA_record_TTL, SOA.MINIMUM)
 *
 * This function scans the authority section of a DNS response to find
 * an SOA record and extracts the appropriate TTL for negative caching.
 */

uint32_t
SocketDNS_extract_negative_ttl (const unsigned char *msg, size_t msglen,
                                 SocketDNS_SOA *soa_out)
{
  SocketDNS_Header header;
  SocketDNS_Question question;
  SocketDNS_RR rr;
  SocketDNS_SOA soa;
  size_t offset;
  size_t consumed;
  uint16_t i;
  uint32_t neg_ttl;

  if (!msg || msglen < DNS_HEADER_SIZE)
    return DNS_NEGATIVE_TTL_DEFAULT;

  /* Decode header */
  if (SocketDNS_header_decode (msg, msglen, &header) != 0)
    return DNS_NEGATIVE_TTL_DEFAULT;

  /* Skip question section */
  offset = DNS_HEADER_SIZE;
  for (i = 0; i < header.qdcount; i++)
    {
      if (SocketDNS_question_decode (msg, msglen, offset, &question, &consumed)
          != 0)
        return DNS_NEGATIVE_TTL_DEFAULT;
      offset += consumed;
    }

  /* Skip answer section */
  for (i = 0; i < header.ancount; i++)
    {
      if (SocketDNS_rr_skip (msg, msglen, offset, &consumed) != 0)
        return DNS_NEGATIVE_TTL_DEFAULT;
      offset += consumed;
    }

  /* Scan authority section for SOA record */
  for (i = 0; i < header.nscount; i++)
    {
      if (SocketDNS_rr_decode (msg, msglen, offset, &rr, &consumed) != 0)
        return DNS_NEGATIVE_TTL_DEFAULT;

      if (rr.type == DNS_TYPE_SOA)
        {
          /* Found SOA - parse RDATA */
          if (SocketDNS_rdata_parse_soa (msg, msglen, &rr, &soa) != 0)
            {
              /* SOA parsing failed, continue to next RR */
              offset += consumed;
              continue;
            }

          /* Copy SOA to output if requested */
          if (soa_out)
            *soa_out = soa;

          /* RFC 2308 Section 5: TTL = min(SOA_TTL, MINIMUM) */
          neg_ttl = (rr.ttl < soa.minimum) ? rr.ttl : soa.minimum;

          /* Cap at maximum recommended TTL */
          if (neg_ttl > DNS_NEGATIVE_TTL_MAX)
            neg_ttl = DNS_NEGATIVE_TTL_MAX;

          return neg_ttl;
        }

      offset += consumed;
    }

  /* No SOA found - return default */
  return DNS_NEGATIVE_TTL_DEFAULT;
}
