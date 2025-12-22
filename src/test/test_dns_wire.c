/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/*
 * test_dns_wire.c - Unit tests for DNS wire format encoding/decoding
 *
 * Tests RFC 1035 Section 4.1.1 header format implementation.
 */

#include "dns/SocketDNSWire.h"
#include "test/Test.h"

#include <stdio.h>
#include <string.h>

/* Test basic header encoding and decoding round-trip */
TEST (dns_wire_header_roundtrip)
{
  SocketDNS_Header orig = { 0 };
  SocketDNS_Header decoded = { 0 };
  unsigned char buf[DNS_HEADER_SIZE];
  int ret;

  /* Set up a typical query header */
  orig.id = 0x1234;
  orig.qr = 0;                    /* Query */
  orig.opcode = DNS_OPCODE_QUERY;
  orig.aa = 0;
  orig.tc = 0;
  orig.rd = 1;                    /* Recursion desired */
  orig.ra = 0;
  orig.z = 0;
  orig.rcode = DNS_RCODE_NOERROR;
  orig.qdcount = 1;
  orig.ancount = 0;
  orig.nscount = 0;
  orig.arcount = 0;

  ret = SocketDNS_header_encode (&orig, buf, sizeof (buf));
  ASSERT_EQ (ret, 0);

  ret = SocketDNS_header_decode (buf, sizeof (buf), &decoded);
  ASSERT_EQ (ret, 0);

  /* Verify all fields match */
  ASSERT_EQ (decoded.id, orig.id);
  ASSERT_EQ (decoded.qr, orig.qr);
  ASSERT_EQ (decoded.opcode, orig.opcode);
  ASSERT_EQ (decoded.aa, orig.aa);
  ASSERT_EQ (decoded.tc, orig.tc);
  ASSERT_EQ (decoded.rd, orig.rd);
  ASSERT_EQ (decoded.ra, orig.ra);
  ASSERT_EQ (decoded.z, orig.z);
  ASSERT_EQ (decoded.rcode, orig.rcode);
  ASSERT_EQ (decoded.qdcount, orig.qdcount);
  ASSERT_EQ (decoded.ancount, orig.ancount);
  ASSERT_EQ (decoded.nscount, orig.nscount);
  ASSERT_EQ (decoded.arcount, orig.arcount);
}

/* Test response header with all flags set */
TEST (dns_wire_header_all_flags)
{
  SocketDNS_Header orig = { 0 };
  SocketDNS_Header decoded = { 0 };
  unsigned char buf[DNS_HEADER_SIZE];
  int ret;

  /* Response with all flags set */
  orig.id = 0xABCD;
  orig.qr = 1;                    /* Response */
  orig.opcode = DNS_OPCODE_STATUS;
  orig.aa = 1;                    /* Authoritative */
  orig.tc = 1;                    /* Truncated */
  orig.rd = 1;                    /* Recursion desired */
  orig.ra = 1;                    /* Recursion available */
  orig.z = 0;                     /* Reserved, must be 0 */
  orig.rcode = DNS_RCODE_REFUSED;
  orig.qdcount = 0xFFFF;
  orig.ancount = 0x1234;
  orig.nscount = 0x5678;
  orig.arcount = 0x9ABC;

  ret = SocketDNS_header_encode (&orig, buf, sizeof (buf));
  ASSERT_EQ (ret, 0);

  ret = SocketDNS_header_decode (buf, sizeof (buf), &decoded);
  ASSERT_EQ (ret, 0);

  ASSERT_EQ (decoded.id, 0xABCD);
  ASSERT_EQ (decoded.qr, 1);
  ASSERT_EQ (decoded.opcode, DNS_OPCODE_STATUS);
  ASSERT_EQ (decoded.aa, 1);
  ASSERT_EQ (decoded.tc, 1);
  ASSERT_EQ (decoded.rd, 1);
  ASSERT_EQ (decoded.ra, 1);
  ASSERT_EQ (decoded.z, 0);
  ASSERT_EQ (decoded.rcode, DNS_RCODE_REFUSED);
  ASSERT_EQ (decoded.qdcount, 0xFFFF);
  ASSERT_EQ (decoded.ancount, 0x1234);
  ASSERT_EQ (decoded.nscount, 0x5678);
  ASSERT_EQ (decoded.arcount, 0x9ABC);
}

/* Test decoding a known DNS query packet */
TEST (dns_wire_decode_known_query)
{
  /* DNS query for "example.com" A record
   * ID: 0x1234
   * Flags: 0x0100 (standard query, recursion desired)
   * Questions: 1
   * Answers: 0
   * Authority: 0
   * Additional: 0
   */
  unsigned char query[] = {
    0x12, 0x34,   /* ID */
    0x01, 0x00,   /* Flags: RD=1, rest 0 */
    0x00, 0x01,   /* QDCOUNT = 1 */
    0x00, 0x00,   /* ANCOUNT = 0 */
    0x00, 0x00,   /* NSCOUNT = 0 */
    0x00, 0x00    /* ARCOUNT = 0 */
  };

  SocketDNS_Header h;
  int ret = SocketDNS_header_decode (query, sizeof (query), &h);

  ASSERT_EQ (ret, 0);
  ASSERT_EQ (h.id, 0x1234);
  ASSERT_EQ (h.qr, 0);
  ASSERT_EQ (h.opcode, DNS_OPCODE_QUERY);
  ASSERT_EQ (h.rd, 1);
  ASSERT_EQ (h.aa, 0);
  ASSERT_EQ (h.tc, 0);
  ASSERT_EQ (h.ra, 0);
  ASSERT_EQ (h.qdcount, 1);
  ASSERT_EQ (h.ancount, 0);
}

/* Test decoding a known DNS response packet */
TEST (dns_wire_decode_known_response)
{
  /* DNS response for "example.com" A record
   * ID: 0x1234
   * Flags: 0x8180 (QR=1, RD=1, RA=1)
   * Questions: 1
   * Answers: 1
   * Authority: 0
   * Additional: 0
   */
  unsigned char response[] = {
    0x12, 0x34,   /* ID */
    0x81, 0x80,   /* Flags: QR=1, RD=1, RA=1 */
    0x00, 0x01,   /* QDCOUNT = 1 */
    0x00, 0x01,   /* ANCOUNT = 1 */
    0x00, 0x00,   /* NSCOUNT = 0 */
    0x00, 0x00    /* ARCOUNT = 0 */
  };

  SocketDNS_Header h;
  int ret = SocketDNS_header_decode (response, sizeof (response), &h);

  ASSERT_EQ (ret, 0);
  ASSERT_EQ (h.id, 0x1234);
  ASSERT_EQ (h.qr, 1);
  ASSERT_EQ (h.opcode, DNS_OPCODE_QUERY);
  ASSERT_EQ (h.aa, 0);
  ASSERT_EQ (h.tc, 0);
  ASSERT_EQ (h.rd, 1);
  ASSERT_EQ (h.ra, 1);
  ASSERT_EQ (h.rcode, DNS_RCODE_NOERROR);
  ASSERT_EQ (h.qdcount, 1);
  ASSERT_EQ (h.ancount, 1);
}

/* Test NXDOMAIN response */
TEST (dns_wire_decode_nxdomain)
{
  /* NXDOMAIN response
   * Flags: 0x8183 (QR=1, RD=1, RA=1, RCODE=3)
   */
  unsigned char nxdomain[] = {
    0x56, 0x78,   /* ID */
    0x81, 0x83,   /* Flags: QR=1, RD=1, RA=1, RCODE=NXDOMAIN(3) */
    0x00, 0x01,   /* QDCOUNT = 1 */
    0x00, 0x00,   /* ANCOUNT = 0 */
    0x00, 0x01,   /* NSCOUNT = 1 (SOA for negative caching) */
    0x00, 0x00    /* ARCOUNT = 0 */
  };

  SocketDNS_Header h;
  int ret = SocketDNS_header_decode (nxdomain, sizeof (nxdomain), &h);

  ASSERT_EQ (ret, 0);
  ASSERT_EQ (h.id, 0x5678);
  ASSERT_EQ (h.qr, 1);
  ASSERT_EQ (h.rcode, DNS_RCODE_NXDOMAIN);
  ASSERT_EQ (h.nscount, 1);
}

/* Test truncated response (TC bit) */
TEST (dns_wire_truncated_response)
{
  /* Truncated response - needs TCP retry
   * Flags: 0x8280 (QR=1, TC=1, RA=1)
   */
  unsigned char truncated[] = {
    0xAB, 0xCD,   /* ID */
    0x82, 0x80,   /* Flags: QR=1, TC=1, RA=1 */
    0x00, 0x01,   /* QDCOUNT = 1 */
    0x00, 0x05,   /* ANCOUNT = 5 (but truncated) */
    0x00, 0x00,   /* NSCOUNT = 0 */
    0x00, 0x00    /* ARCOUNT = 0 */
  };

  SocketDNS_Header h;
  int ret = SocketDNS_header_decode (truncated, sizeof (truncated), &h);

  ASSERT_EQ (ret, 0);
  ASSERT_EQ (h.tc, 1);
  ASSERT_EQ (h.qr, 1);
}

/* Test authoritative answer (AA bit) */
TEST (dns_wire_authoritative_answer)
{
  /* Authoritative answer
   * Flags: 0x8400 (QR=1, AA=1)
   */
  unsigned char auth[] = {
    0x11, 0x22,   /* ID */
    0x84, 0x00,   /* Flags: QR=1, AA=1 */
    0x00, 0x01,   /* QDCOUNT = 1 */
    0x00, 0x01,   /* ANCOUNT = 1 */
    0x00, 0x00,   /* NSCOUNT = 0 */
    0x00, 0x00    /* ARCOUNT = 0 */
  };

  SocketDNS_Header h;
  int ret = SocketDNS_header_decode (auth, sizeof (auth), &h);

  ASSERT_EQ (ret, 0);
  ASSERT_EQ (h.aa, 1);
  ASSERT_EQ (h.qr, 1);
}

/* Test buffer too small for encode */
TEST (dns_wire_encode_buffer_too_small)
{
  SocketDNS_Header h = { 0 };
  unsigned char buf[DNS_HEADER_SIZE - 1]; /* Too small */
  int ret;

  ret = SocketDNS_header_encode (&h, buf, sizeof (buf));
  ASSERT_EQ (ret, -1);
}

/* Test buffer too small for decode */
TEST (dns_wire_decode_buffer_too_small)
{
  unsigned char buf[DNS_HEADER_SIZE - 1] = { 0 }; /* Too small */
  SocketDNS_Header h;
  int ret;

  ret = SocketDNS_header_decode (buf, sizeof (buf), &h);
  ASSERT_EQ (ret, -1);
}

/* Test NULL pointer handling */
TEST (dns_wire_null_pointers)
{
  SocketDNS_Header h = { 0 };
  unsigned char buf[DNS_HEADER_SIZE] = { 0 };
  int ret;

  ret = SocketDNS_header_encode (NULL, buf, sizeof (buf));
  ASSERT_EQ (ret, -1);

  ret = SocketDNS_header_encode (&h, NULL, sizeof (buf));
  ASSERT_EQ (ret, -1);

  ret = SocketDNS_header_decode (buf, sizeof (buf), NULL);
  ASSERT_EQ (ret, -1);

  ret = SocketDNS_header_decode (NULL, sizeof (buf), &h);
  ASSERT_EQ (ret, -1);
}

/* Test init_query helper */
TEST (dns_wire_init_query)
{
  SocketDNS_Header h;
  unsigned char buf[DNS_HEADER_SIZE];
  SocketDNS_Header decoded;

  SocketDNS_header_init_query (&h, 0x4321, 1);

  ASSERT_EQ (h.id, 0x4321);
  ASSERT_EQ (h.qr, 0);
  ASSERT_EQ (h.opcode, DNS_OPCODE_QUERY);
  ASSERT_EQ (h.rd, 1);
  ASSERT_EQ (h.qdcount, 1);
  ASSERT_EQ (h.ancount, 0);
  ASSERT_EQ (h.nscount, 0);
  ASSERT_EQ (h.arcount, 0);

  /* Verify it encodes correctly */
  ASSERT_EQ (SocketDNS_header_encode (&h, buf, sizeof (buf)), 0);
  ASSERT_EQ (SocketDNS_header_decode (buf, sizeof (buf), &decoded), 0);
  ASSERT_EQ (decoded.id, 0x4321);
  ASSERT_EQ (decoded.rd, 1);
}

/* Test OPCODE values */
TEST (dns_wire_opcode_values)
{
  SocketDNS_Header h = { 0 };
  SocketDNS_Header decoded;
  unsigned char buf[DNS_HEADER_SIZE];
  uint8_t opcodes[] = { DNS_OPCODE_QUERY, DNS_OPCODE_IQUERY, DNS_OPCODE_STATUS,
                        DNS_OPCODE_NOTIFY, DNS_OPCODE_UPDATE };
  size_t i;

  for (i = 0; i < sizeof (opcodes) / sizeof (opcodes[0]); i++)
    {
      memset (&h, 0, sizeof (h));
      h.id = (uint16_t)(i + 1);
      h.opcode = opcodes[i];

      ASSERT_EQ (SocketDNS_header_encode (&h, buf, sizeof (buf)), 0);
      ASSERT_EQ (SocketDNS_header_decode (buf, sizeof (buf), &decoded), 0);
      ASSERT_EQ (decoded.opcode, opcodes[i]);
    }
}

/* Test RCODE values */
TEST (dns_wire_rcode_values)
{
  SocketDNS_Header h = { 0 };
  SocketDNS_Header decoded;
  unsigned char buf[DNS_HEADER_SIZE];
  uint8_t rcodes[] = { DNS_RCODE_NOERROR,  DNS_RCODE_FORMERR,
                       DNS_RCODE_SERVFAIL, DNS_RCODE_NXDOMAIN,
                       DNS_RCODE_NOTIMP,   DNS_RCODE_REFUSED };
  size_t i;

  for (i = 0; i < sizeof (rcodes) / sizeof (rcodes[0]); i++)
    {
      memset (&h, 0, sizeof (h));
      h.id = (uint16_t)(i + 1);
      h.qr = 1;
      h.rcode = rcodes[i];

      ASSERT_EQ (SocketDNS_header_encode (&h, buf, sizeof (buf)), 0);
      ASSERT_EQ (SocketDNS_header_decode (buf, sizeof (buf), &decoded), 0);
      ASSERT_EQ (decoded.rcode, rcodes[i]);
    }
}

/* Test byte order (big-endian) */
TEST (dns_wire_byte_order)
{
  SocketDNS_Header h = { 0 };
  unsigned char buf[DNS_HEADER_SIZE];

  h.id = 0x0102;        /* Should encode as 0x01, 0x02 */
  h.qdcount = 0x0304;   /* Should encode as 0x03, 0x04 */
  h.ancount = 0x0506;
  h.nscount = 0x0708;
  h.arcount = 0x090A;

  ASSERT_EQ (SocketDNS_header_encode (&h, buf, sizeof (buf)), 0);

  /* Verify byte order (big-endian / network order) */
  ASSERT (buf[0] == 0x01 && buf[1] == 0x02);
  ASSERT (buf[4] == 0x03 && buf[5] == 0x04);
  ASSERT (buf[6] == 0x05 && buf[7] == 0x06);
  ASSERT (buf[8] == 0x07 && buf[9] == 0x08);
  ASSERT (buf[10] == 0x09 && buf[11] == 0x0A);
}

/* Test boundary values */
TEST (dns_wire_boundary_values)
{
  SocketDNS_Header h = { 0 };
  SocketDNS_Header decoded;
  unsigned char buf[DNS_HEADER_SIZE];

  /* Test maximum values */
  h.id = 0xFFFF;
  h.qr = 1;
  h.opcode = 0x0F;      /* Max 4-bit value */
  h.aa = 1;
  h.tc = 1;
  h.rd = 1;
  h.ra = 1;
  h.z = 0x07;           /* Max 3-bit value (though should be 0) */
  h.rcode = 0x0F;       /* Max 4-bit value */
  h.qdcount = 0xFFFF;
  h.ancount = 0xFFFF;
  h.nscount = 0xFFFF;
  h.arcount = 0xFFFF;

  ASSERT_EQ (SocketDNS_header_encode (&h, buf, sizeof (buf)), 0);
  ASSERT_EQ (SocketDNS_header_decode (buf, sizeof (buf), &decoded), 0);

  ASSERT_EQ (decoded.id, 0xFFFF);
  ASSERT_EQ (decoded.opcode, 0x0F);
  ASSERT_EQ (decoded.rcode, 0x0F);
  ASSERT_EQ (decoded.qdcount, 0xFFFF);

  /* Test zero values */
  memset (&h, 0, sizeof (h));
  ASSERT_EQ (SocketDNS_header_encode (&h, buf, sizeof (buf)), 0);
  ASSERT_EQ (SocketDNS_header_decode (buf, sizeof (buf), &decoded), 0);

  ASSERT_EQ (decoded.id, 0);
  ASSERT_EQ (decoded.qr, 0);
  ASSERT_EQ (decoded.opcode, 0);
  ASSERT_EQ (decoded.rcode, 0);
  ASSERT_EQ (decoded.qdcount, 0);
}

/* Test wire format flags byte layout */
TEST (dns_wire_flags_byte_layout)
{
  unsigned char buf[DNS_HEADER_SIZE];
  SocketDNS_Header h = { 0 };

  /* Test QR bit (bit 15 = 0x80 in first flags byte) */
  h.qr = 1;
  SocketDNS_header_encode (&h, buf, sizeof (buf));
  ASSERT ((buf[2] & 0x80) == 0x80);

  /* Test OPCODE (bits 14-11 = 0x78 in first flags byte) */
  memset (&h, 0, sizeof (h));
  h.opcode = 0x0F;      /* All bits set */
  SocketDNS_header_encode (&h, buf, sizeof (buf));
  ASSERT ((buf[2] & 0x78) == 0x78);

  /* Test AA bit (bit 10 = 0x04 in first flags byte) */
  memset (&h, 0, sizeof (h));
  h.aa = 1;
  SocketDNS_header_encode (&h, buf, sizeof (buf));
  ASSERT ((buf[2] & 0x04) == 0x04);

  /* Test TC bit (bit 9 = 0x02 in first flags byte) */
  memset (&h, 0, sizeof (h));
  h.tc = 1;
  SocketDNS_header_encode (&h, buf, sizeof (buf));
  ASSERT ((buf[2] & 0x02) == 0x02);

  /* Test RD bit (bit 8 = 0x01 in first flags byte) */
  memset (&h, 0, sizeof (h));
  h.rd = 1;
  SocketDNS_header_encode (&h, buf, sizeof (buf));
  ASSERT ((buf[2] & 0x01) == 0x01);

  /* Test RA bit (bit 7 = 0x80 in second flags byte) */
  memset (&h, 0, sizeof (h));
  h.ra = 1;
  SocketDNS_header_encode (&h, buf, sizeof (buf));
  ASSERT ((buf[3] & 0x80) == 0x80);

  /* Test RCODE (bits 3-0 = 0x0F in second flags byte) */
  memset (&h, 0, sizeof (h));
  h.rcode = 0x0F;
  SocketDNS_header_encode (&h, buf, sizeof (buf));
  ASSERT ((buf[3] & 0x0F) == 0x0F);
}

/* ==================== Domain Name Tests ==================== */

/* Test basic domain name encoding */
TEST (dns_name_encode_basic)
{
  unsigned char buf[DNS_MAX_NAME_LEN];
  size_t written;
  int ret;

  ret = SocketDNS_name_encode ("www.example.com", buf, sizeof (buf), &written);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (written, 17);

  /* Verify wire format: [3]www[7]example[3]com[0] */
  ASSERT_EQ (buf[0], 3);
  ASSERT (memcmp (buf + 1, "www", 3) == 0);
  ASSERT_EQ (buf[4], 7);
  ASSERT (memcmp (buf + 5, "example", 7) == 0);
  ASSERT_EQ (buf[12], 3);
  ASSERT (memcmp (buf + 13, "com", 3) == 0);
  ASSERT_EQ (buf[16], 0);
}

/* Test encoding root domain */
TEST (dns_name_encode_root)
{
  unsigned char buf[DNS_MAX_NAME_LEN];
  size_t written;

  /* Empty string = root */
  ASSERT_EQ (SocketDNS_name_encode ("", buf, sizeof (buf), &written), 0);
  ASSERT_EQ (written, 1);
  ASSERT_EQ (buf[0], 0);

  /* Single dot = root */
  ASSERT_EQ (SocketDNS_name_encode (".", buf, sizeof (buf), &written), 0);
  ASSERT_EQ (written, 1);
  ASSERT_EQ (buf[0], 0);
}

/* Test encoding with trailing dot */
TEST (dns_name_encode_trailing_dot)
{
  unsigned char buf[DNS_MAX_NAME_LEN];
  size_t written1, written2;

  ASSERT_EQ (SocketDNS_name_encode ("example.com", buf, sizeof (buf), &written1), 0);
  ASSERT_EQ (SocketDNS_name_encode ("example.com.", buf, sizeof (buf), &written2), 0);
  ASSERT_EQ (written1, written2);
}

/* Test basic domain name decoding */
TEST (dns_name_decode_basic)
{
  /* Wire format for "www.example.com" */
  unsigned char wire[] = { 3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                           3, 'c', 'o', 'm', 0 };
  char name[DNS_MAX_NAME_LEN];
  size_t consumed;
  int len;

  len = SocketDNS_name_decode (wire, sizeof (wire), 0, name, sizeof (name),
                               &consumed);
  ASSERT_EQ (len, 15); /* "www.example.com" */
  ASSERT_EQ (consumed, 17);
  ASSERT (strcmp (name, "www.example.com") == 0);
}

/* Test decoding with compression pointer */
TEST (dns_name_decode_compression)
{
  /* Simulated DNS message:
   * Offset 0-11: Header (12 bytes)
   * Offset 12: "example.com" in wire format
   * Offset 24: "www" + pointer to offset 12
   */
  unsigned char msg[32];
  char name[DNS_MAX_NAME_LEN];
  size_t consumed;
  int len;

  /* Header (dummy) */
  memset (msg, 0, 12);

  /* "example.com" at offset 12 */
  msg[12] = 7;
  memcpy (msg + 13, "example", 7);
  msg[20] = 3;
  memcpy (msg + 21, "com", 3);
  msg[24] = 0;

  /* Decode "example.com" from offset 12 */
  len = SocketDNS_name_decode (msg, 25, 12, name, sizeof (name), &consumed);
  ASSERT_EQ (len, 11); /* "example.com" */
  ASSERT (strcmp (name, "example.com") == 0);

  /* Now add "www" + pointer at offset 25 */
  msg[25] = 3;
  memcpy (msg + 26, "www", 3);
  msg[29] = 0xC0;       /* Compression pointer */
  msg[30] = 12;         /* Points to offset 12 */

  len = SocketDNS_name_decode (msg, 31, 25, name, sizeof (name), &consumed);
  ASSERT_EQ (len, 15); /* "www.example.com" */
  ASSERT_EQ (consumed, 6); /* 1 + 3 + 2 (pointer) */
  ASSERT (strcmp (name, "www.example.com") == 0);
}

/* Test compression loop detection */
TEST (dns_name_decode_loop_detection)
{
  /* Create a message with a self-referential pointer */
  unsigned char msg[16];
  char name[DNS_MAX_NAME_LEN];

  memset (msg, 0, 12);
  /* Pointer at offset 12 pointing to offset 12 (infinite loop) */
  msg[12] = 0xC0;
  msg[13] = 12;

  ASSERT_EQ (SocketDNS_name_decode (msg, 14, 12, name, sizeof (name), NULL), -1);
}

/* Test valid domain names */
TEST (dns_name_valid_basic)
{
  ASSERT_EQ (SocketDNS_name_valid ("example.com"), 1);
  ASSERT_EQ (SocketDNS_name_valid ("www.example.com"), 1);
  ASSERT_EQ (SocketDNS_name_valid ("a.b.c.d.e.f"), 1);
  ASSERT_EQ (SocketDNS_name_valid (""), 1); /* Root */
  ASSERT_EQ (SocketDNS_name_valid ("."), 1); /* Root */
  ASSERT_EQ (SocketDNS_name_valid ("example.com."), 1); /* Trailing dot */
}

/* Test invalid domain names */
TEST (dns_name_valid_invalid)
{
  /* Empty label (consecutive dots) */
  ASSERT_EQ (SocketDNS_name_valid ("example..com"), 0);
  /* Leading dot (empty first label) */
  ASSERT_EQ (SocketDNS_name_valid (".example.com"), 0);
  /* NULL pointer */
  ASSERT_EQ (SocketDNS_name_valid (NULL), 0);
}

/* Test label length limit (63 bytes) */
TEST (dns_name_valid_label_length)
{
  char label64[65];
  char name[80];

  memset (label64, 'a', 64);
  label64[64] = '\0';

  /* 64 character label - invalid */
  snprintf (name, sizeof (name), "%s.com", label64);
  ASSERT_EQ (SocketDNS_name_valid (name), 0);

  /* 63 character label - valid */
  label64[63] = '\0';
  snprintf (name, sizeof (name), "%s.com", label64);
  ASSERT_EQ (SocketDNS_name_valid (name), 1);
}

/* Test case-insensitive domain name comparison */
TEST (dns_name_equal_basic)
{
  ASSERT_EQ (SocketDNS_name_equal ("example.com", "example.com"), 1);
  ASSERT_EQ (SocketDNS_name_equal ("Example.COM", "example.com"), 1);
  ASSERT_EQ (SocketDNS_name_equal ("EXAMPLE.COM", "example.com"), 1);
  ASSERT_EQ (SocketDNS_name_equal ("example.com", "EXAMPLE.COM"), 1);
}

/* Test comparison with trailing dots */
TEST (dns_name_equal_trailing_dot)
{
  ASSERT_EQ (SocketDNS_name_equal ("example.com", "example.com."), 1);
  ASSERT_EQ (SocketDNS_name_equal ("example.com.", "example.com"), 1);
  ASSERT_EQ (SocketDNS_name_equal ("example.com.", "example.com."), 1);
}

/* Test non-equal names */
TEST (dns_name_equal_different)
{
  ASSERT_EQ (SocketDNS_name_equal ("example.com", "example.org"), 0);
  ASSERT_EQ (SocketDNS_name_equal ("www.example.com", "example.com"), 0);
  ASSERT_EQ (SocketDNS_name_equal ("example.com", "examples.com"), 0);
}

/* Test buffer too small for encoding */
TEST (dns_name_encode_buffer_small)
{
  unsigned char buf[5]; /* Too small for "www.com" */
  ASSERT_EQ (SocketDNS_name_encode ("www.com", buf, sizeof (buf), NULL), -1);
}

/* Test NULL pointer handling for name functions */
TEST (dns_name_null_handling)
{
  unsigned char buf[32];
  char name[32];

  ASSERT_EQ (SocketDNS_name_encode (NULL, buf, sizeof (buf), NULL), -1);
  ASSERT_EQ (SocketDNS_name_encode ("test", NULL, sizeof (buf), NULL), -1);
  ASSERT_EQ (SocketDNS_name_decode (NULL, 32, 0, name, sizeof (name), NULL), -1);
  ASSERT_EQ (SocketDNS_name_decode (buf, 32, 0, NULL, sizeof (name), NULL), -1);
  ASSERT_EQ (SocketDNS_name_equal (NULL, "test"), 0);
  ASSERT_EQ (SocketDNS_name_equal ("test", NULL), 0);
}

/* Test wire length calculation */
TEST (dns_name_wire_length)
{
  ASSERT_EQ (SocketDNS_name_wire_length (""), 1);
  ASSERT_EQ (SocketDNS_name_wire_length ("."), 1);
  ASSERT_EQ (SocketDNS_name_wire_length ("com"), 5); /* 1+3+1 */
  ASSERT_EQ (SocketDNS_name_wire_length ("example.com"), 13); /* 1+7+1+3+1 */
  ASSERT_EQ (SocketDNS_name_wire_length ("www.example.com"), 17);
}

/* Test encode/decode roundtrip */
TEST (dns_name_roundtrip)
{
  const char *names[] = {
    "example.com",
    "www.example.com",
    "a.b.c.d.e.f.g",
    "test123.subdomain.domain.tld",
    ""  /* root */
  };
  size_t i;

  for (i = 0; i < sizeof (names) / sizeof (names[0]); i++)
    {
      unsigned char wire[DNS_MAX_NAME_LEN];
      char decoded[DNS_MAX_NAME_LEN];
      size_t written, consumed;
      int len;

      ASSERT_EQ (SocketDNS_name_encode (names[i], wire, sizeof (wire), &written), 0);
      len = SocketDNS_name_decode (wire, written, 0, decoded, sizeof (decoded),
                                   &consumed);
      ASSERT (len >= 0);
      ASSERT_EQ (consumed, written);

      /* For root, decoded will be empty string */
      if (names[i][0] == '\0')
        ASSERT_EQ (decoded[0], '\0');
      else
        ASSERT (SocketDNS_name_equal (names[i], decoded) == 1);
    }
}

/* Test decoding at various offsets */
TEST (dns_name_decode_offset)
{
  unsigned char msg[64];
  char name[DNS_MAX_NAME_LEN];
  size_t consumed;
  int len;

  memset (msg, 0, sizeof (msg));

  /* Put "test.com" at offset 20 */
  msg[20] = 4;
  memcpy (msg + 21, "test", 4);
  msg[25] = 3;
  memcpy (msg + 26, "com", 3);
  msg[29] = 0;

  len = SocketDNS_name_decode (msg, 30, 20, name, sizeof (name), &consumed);
  ASSERT_EQ (len, 8); /* "test.com" */
  ASSERT_EQ (consumed, 10);
  ASSERT (strcmp (name, "test.com") == 0);
}

/* Test invalid offset */
TEST (dns_name_decode_invalid_offset)
{
  unsigned char msg[32];
  char name[DNS_MAX_NAME_LEN];

  memset (msg, 0, sizeof (msg));

  /* Offset beyond message length */
  ASSERT_EQ (SocketDNS_name_decode (msg, 32, 100, name, sizeof (name), NULL), -1);
}

/* Test truncated label */
TEST (dns_name_decode_truncated_label)
{
  /* Label says 10 bytes but only 5 available */
  unsigned char msg[] = { 10, 'a', 'b', 'c', 'd', 'e' };
  char name[DNS_MAX_NAME_LEN];

  ASSERT_EQ (SocketDNS_name_decode (msg, sizeof (msg), 0, name, sizeof (name), NULL), -1);
}

/* Test nested compression pointers */
TEST (dns_name_decode_nested_pointers)
{
  unsigned char msg[64];
  char name[DNS_MAX_NAME_LEN];
  size_t consumed;
  int len;

  memset (msg, 0, 12); /* Header */

  /* "com" at offset 12 */
  msg[12] = 3;
  memcpy (msg + 13, "com", 3);
  msg[16] = 0;

  /* "example" + pointer to "com" at offset 17 */
  msg[17] = 7;
  memcpy (msg + 18, "example", 7);
  msg[25] = 0xC0;
  msg[26] = 12; /* Points to "com" */

  /* "www" + pointer to "example.com" at offset 27 */
  msg[27] = 3;
  memcpy (msg + 28, "www", 3);
  msg[31] = 0xC0;
  msg[32] = 17; /* Points to "example" + pointer */

  len = SocketDNS_name_decode (msg, 33, 27, name, sizeof (name), &consumed);
  ASSERT_EQ (len, 15); /* "www.example.com" */
  ASSERT_EQ (consumed, 6); /* 1+3+2 */
  ASSERT (strcmp (name, "www.example.com") == 0);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
