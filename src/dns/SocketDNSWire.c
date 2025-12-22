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
