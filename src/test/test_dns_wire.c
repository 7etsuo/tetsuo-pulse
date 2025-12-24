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

#include <arpa/inet.h>
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

/* ==================== Question Section Tests ==================== */

/* Test type constant values (RFC 1035, RFC 3596) */
TEST (dns_question_type_constants)
{
  ASSERT_EQ (DNS_TYPE_A, 1);
  ASSERT_EQ (DNS_TYPE_NS, 2);
  ASSERT_EQ (DNS_TYPE_CNAME, 5);
  ASSERT_EQ (DNS_TYPE_SOA, 6);
  ASSERT_EQ (DNS_TYPE_PTR, 12);
  ASSERT_EQ (DNS_TYPE_MX, 15);
  ASSERT_EQ (DNS_TYPE_TXT, 16);
  ASSERT_EQ (DNS_TYPE_AAAA, 28);
  ASSERT_EQ (DNS_TYPE_SRV, 33);
  ASSERT_EQ (DNS_TYPE_OPT, 41);
  ASSERT_EQ (DNS_TYPE_ANY, 255);
}

/* Test class constant values (RFC 1035) */
TEST (dns_question_class_constants)
{
  ASSERT_EQ (DNS_CLASS_IN, 1);
  ASSERT_EQ (DNS_CLASS_CH, 3);
  ASSERT_EQ (DNS_CLASS_HS, 4);
  ASSERT_EQ (DNS_CLASS_ANY, 255);
}

/* Test question init helper */
TEST (dns_question_init_basic)
{
  SocketDNS_Question q;

  SocketDNS_question_init (&q, "example.com", DNS_TYPE_A);
  ASSERT (strcmp (q.qname, "example.com") == 0);
  ASSERT_EQ (q.qtype, DNS_TYPE_A);
  ASSERT_EQ (q.qclass, DNS_CLASS_IN);

  SocketDNS_question_init (&q, "ipv6.example.org", DNS_TYPE_AAAA);
  ASSERT (strcmp (q.qname, "ipv6.example.org") == 0);
  ASSERT_EQ (q.qtype, DNS_TYPE_AAAA);
  ASSERT_EQ (q.qclass, DNS_CLASS_IN);
}

/* Test basic question encoding */
TEST (dns_question_encode_basic)
{
  SocketDNS_Question q;
  unsigned char buf[128];
  size_t written;
  int ret;

  SocketDNS_question_init (&q, "example.com", DNS_TYPE_A);
  ret = SocketDNS_question_encode (&q, buf, sizeof (buf), &written);
  ASSERT_EQ (ret, 0);

  /* Wire format: [7]example[3]com[0] + QTYPE(2) + QCLASS(2) = 13 + 4 = 17 */
  ASSERT_EQ (written, 17);

  /* Verify name encoding */
  ASSERT_EQ (buf[0], 7);
  ASSERT (memcmp (buf + 1, "example", 7) == 0);
  ASSERT_EQ (buf[8], 3);
  ASSERT (memcmp (buf + 9, "com", 3) == 0);
  ASSERT_EQ (buf[12], 0);

  /* Verify QTYPE = 1 (A) big-endian */
  ASSERT_EQ (buf[13], 0);
  ASSERT_EQ (buf[14], 1);

  /* Verify QCLASS = 1 (IN) big-endian */
  ASSERT_EQ (buf[15], 0);
  ASSERT_EQ (buf[16], 1);
}

/* Test AAAA query encoding */
TEST (dns_question_encode_aaaa)
{
  SocketDNS_Question q;
  unsigned char buf[128];
  size_t written;
  int ret;

  SocketDNS_question_init (&q, "ipv6.test.com", DNS_TYPE_AAAA);
  ret = SocketDNS_question_encode (&q, buf, sizeof (buf), &written);
  ASSERT_EQ (ret, 0);

  /* QTYPE = 28 (AAAA) big-endian at end - 4 bytes */
  size_t qtype_offset = written - 4;
  ASSERT_EQ (buf[qtype_offset], 0);
  ASSERT_EQ (buf[qtype_offset + 1], 28);
}

/* Test question decoding */
TEST (dns_question_decode_basic)
{
  /* Wire format for "example.com" A IN query */
  unsigned char wire[] = {
    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    3, 'c', 'o', 'm',
    0,        /* Name terminator */
    0, 1,     /* QTYPE = A (1) */
    0, 1      /* QCLASS = IN (1) */
  };
  SocketDNS_Question q;
  size_t consumed;
  int ret;

  ret = SocketDNS_question_decode (wire, sizeof (wire), 0, &q, &consumed);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (consumed, sizeof (wire));
  ASSERT (strcmp (q.qname, "example.com") == 0);
  ASSERT_EQ (q.qtype, DNS_TYPE_A);
  ASSERT_EQ (q.qclass, DNS_CLASS_IN);
}

/* Test question decode with AAAA type */
TEST (dns_question_decode_aaaa)
{
  /* Wire format for "test.org" AAAA IN query */
  unsigned char wire[] = {
    4, 't', 'e', 's', 't',
    3, 'o', 'r', 'g',
    0,        /* Name terminator */
    0, 28,    /* QTYPE = AAAA (28) */
    0, 1      /* QCLASS = IN (1) */
  };
  SocketDNS_Question q;
  size_t consumed;
  int ret;

  ret = SocketDNS_question_decode (wire, sizeof (wire), 0, &q, &consumed);
  ASSERT_EQ (ret, 0);
  ASSERT (strcmp (q.qname, "test.org") == 0);
  ASSERT_EQ (q.qtype, DNS_TYPE_AAAA);
  ASSERT_EQ (q.qclass, DNS_CLASS_IN);
}

/* Test question encode/decode roundtrip */
TEST (dns_question_roundtrip)
{
  const struct {
    const char *name;
    uint16_t qtype;
  } tests[] = {
    { "example.com", DNS_TYPE_A },
    { "ipv6.example.org", DNS_TYPE_AAAA },
    { "mail.domain.net", DNS_TYPE_MX },
    { "ns1.provider.com", DNS_TYPE_NS },
    { "_srv._tcp.example.com", DNS_TYPE_SRV },
    { "", DNS_TYPE_A },  /* Root domain */
  };
  size_t i;

  for (i = 0; i < sizeof (tests) / sizeof (tests[0]); i++)
    {
      SocketDNS_Question orig, decoded;
      unsigned char wire[512];
      size_t written, consumed;

      SocketDNS_question_init (&orig, tests[i].name, tests[i].qtype);
      ASSERT_EQ (SocketDNS_question_encode (&orig, wire, sizeof (wire), &written), 0);
      ASSERT_EQ (SocketDNS_question_decode (wire, written, 0, &decoded, &consumed), 0);
      ASSERT_EQ (consumed, written);
      ASSERT (SocketDNS_name_equal (orig.qname, decoded.qname) == 1);
      ASSERT_EQ (decoded.qtype, orig.qtype);
      ASSERT_EQ (decoded.qclass, orig.qclass);
    }
}

/* Test question decoding at non-zero offset (after header) */
TEST (dns_question_decode_offset)
{
  unsigned char msg[64];
  SocketDNS_Question q;
  size_t consumed;

  memset (msg, 0, 12); /* Header */

  /* Question at offset 12: "test.com" A IN */
  msg[12] = 4;
  memcpy (msg + 13, "test", 4);
  msg[17] = 3;
  memcpy (msg + 18, "com", 3);
  msg[21] = 0;
  msg[22] = 0; msg[23] = 1;  /* QTYPE = A */
  msg[24] = 0; msg[25] = 1;  /* QCLASS = IN */

  ASSERT_EQ (SocketDNS_question_decode (msg, 26, 12, &q, &consumed), 0);
  ASSERT_EQ (consumed, 14); /* 10 (name) + 4 (type+class) */
  ASSERT (strcmp (q.qname, "test.com") == 0);
  ASSERT_EQ (q.qtype, DNS_TYPE_A);
}

/* Test question encode buffer too small */
TEST (dns_question_encode_buffer_small)
{
  SocketDNS_Question q;
  unsigned char buf[10]; /* Too small */

  SocketDNS_question_init (&q, "example.com", DNS_TYPE_A);
  ASSERT_EQ (SocketDNS_question_encode (&q, buf, sizeof (buf), NULL), -1);
}

/* Test question decode truncated */
TEST (dns_question_decode_truncated)
{
  /* Wire format missing QCLASS bytes */
  unsigned char wire[] = {
    3, 'c', 'o', 'm',
    0,        /* Name terminator */
    0, 1      /* QTYPE = A, but QCLASS missing */
  };
  SocketDNS_Question q;

  ASSERT_EQ (SocketDNS_question_decode (wire, sizeof (wire), 0, &q, NULL), -1);
}

/* Test question NULL pointer handling */
TEST (dns_question_null_handling)
{
  SocketDNS_Question q;
  unsigned char buf[64];

  ASSERT_EQ (SocketDNS_question_encode (NULL, buf, sizeof (buf), NULL), -1);
  ASSERT_EQ (SocketDNS_question_encode (&q, NULL, sizeof (buf), NULL), -1);
  ASSERT_EQ (SocketDNS_question_decode (NULL, 64, 0, &q, NULL), -1);
  ASSERT_EQ (SocketDNS_question_decode (buf, 64, 0, NULL, NULL), -1);

  /* Init with NULL should not crash */
  SocketDNS_question_init (NULL, "test", DNS_TYPE_A);
  SocketDNS_question_init (&q, NULL, DNS_TYPE_A);
  ASSERT_EQ (q.qname[0], '\0');
}

/* Test question with compression pointer in name */
TEST (dns_question_decode_compressed)
{
  unsigned char msg[64];
  SocketDNS_Question q;
  size_t consumed;

  memset (msg, 0, 12);

  /* "example.com" at offset 12 */
  msg[12] = 7;
  memcpy (msg + 13, "example", 7);
  msg[20] = 3;
  memcpy (msg + 21, "com", 3);
  msg[24] = 0;

  /* Question at offset 25: "www" + pointer to offset 12 */
  msg[25] = 3;
  memcpy (msg + 26, "www", 3);
  msg[29] = 0xC0;
  msg[30] = 12;  /* Pointer to "example.com" */
  msg[31] = 0; msg[32] = 1;  /* QTYPE = A */
  msg[33] = 0; msg[34] = 1;  /* QCLASS = IN */

  ASSERT_EQ (SocketDNS_question_decode (msg, 35, 25, &q, &consumed), 0);
  ASSERT_EQ (consumed, 10); /* 1+3+2 (name with pointer) + 4 (type+class) */
  ASSERT (strcmp (q.qname, "www.example.com") == 0);
  ASSERT_EQ (q.qtype, DNS_TYPE_A);
}

/* ==================== Resource Record Tests ==================== */

/* Test basic A record decoding */
TEST (dns_rr_decode_a_record)
{
  /* Wire format for "example.com" A record with IP 192.0.2.1 */
  unsigned char wire[] = {
    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    3, 'c', 'o', 'm',
    0,              /* Name terminator */
    0, 1,           /* TYPE = A (1) */
    0, 1,           /* CLASS = IN (1) */
    0, 0, 0x0E, 0x10, /* TTL = 3600 seconds */
    0, 4,           /* RDLENGTH = 4 */
    192, 0, 2, 1    /* RDATA = 192.0.2.1 */
  };
  SocketDNS_RR rr;
  size_t consumed;
  int ret;

  ret = SocketDNS_rr_decode (wire, sizeof (wire), 0, &rr, &consumed);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (consumed, sizeof (wire));
  ASSERT (strcmp (rr.name, "example.com") == 0);
  ASSERT_EQ (rr.type, DNS_TYPE_A);
  ASSERT_EQ (rr.rclass, DNS_CLASS_IN);
  ASSERT_EQ (rr.ttl, 3600);
  ASSERT_EQ (rr.rdlength, 4);
  ASSERT_NOT_NULL (rr.rdata);
  ASSERT_EQ (rr.rdata[0], 192);
  ASSERT_EQ (rr.rdata[1], 0);
  ASSERT_EQ (rr.rdata[2], 2);
  ASSERT_EQ (rr.rdata[3], 1);
}

/* Test AAAA record decoding */
TEST (dns_rr_decode_aaaa_record)
{
  /* Wire format for "ipv6.example.com" AAAA record with 2001:db8::1 */
  unsigned char wire[] = {
    4, 'i', 'p', 'v', '6',
    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    3, 'c', 'o', 'm',
    0,              /* Name terminator */
    0, 28,          /* TYPE = AAAA (28) */
    0, 1,           /* CLASS = IN (1) */
    0, 0, 0x1C, 0x20, /* TTL = 7200 seconds */
    0, 16,          /* RDLENGTH = 16 */
    0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01  /* 2001:db8::1 */
  };
  SocketDNS_RR rr;
  size_t consumed;
  int ret;

  ret = SocketDNS_rr_decode (wire, sizeof (wire), 0, &rr, &consumed);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (consumed, sizeof (wire));
  ASSERT (strcmp (rr.name, "ipv6.example.com") == 0);
  ASSERT_EQ (rr.type, DNS_TYPE_AAAA);
  ASSERT_EQ (rr.rclass, DNS_CLASS_IN);
  ASSERT_EQ (rr.ttl, 7200);
  ASSERT_EQ (rr.rdlength, 16);
  ASSERT_NOT_NULL (rr.rdata);
  ASSERT_EQ (rr.rdata[0], 0x20);
  ASSERT_EQ (rr.rdata[1], 0x01);
}

/* Test RR with compressed name */
TEST (dns_rr_decode_compressed_name)
{
  unsigned char msg[64];
  SocketDNS_RR rr;
  size_t consumed;

  memset (msg, 0, 12); /* Header */

  /* "example.com" at offset 12 */
  msg[12] = 7;
  memcpy (msg + 13, "example", 7);
  msg[20] = 3;
  memcpy (msg + 21, "com", 3);
  msg[24] = 0;

  /* RR at offset 25 with compressed name pointing to offset 12 */
  msg[25] = 0xC0;
  msg[26] = 12;       /* Pointer to "example.com" */
  msg[27] = 0; msg[28] = 1;   /* TYPE = A */
  msg[29] = 0; msg[30] = 1;   /* CLASS = IN */
  msg[31] = 0; msg[32] = 0; msg[33] = 0; msg[34] = 60;  /* TTL = 60 */
  msg[35] = 0; msg[36] = 4;   /* RDLENGTH = 4 */
  msg[37] = 10; msg[38] = 0; msg[39] = 0; msg[40] = 1;  /* 10.0.0.1 */

  ASSERT_EQ (SocketDNS_rr_decode (msg, 41, 25, &rr, &consumed), 0);
  ASSERT_EQ (consumed, 16); /* 2 (ptr) + 10 (fixed) + 4 (rdata) */
  ASSERT (strcmp (rr.name, "example.com") == 0);
  ASSERT_EQ (rr.type, DNS_TYPE_A);
  ASSERT_EQ (rr.ttl, 60);
  ASSERT_EQ (rr.rdlength, 4);
}

/* Test RR with zero TTL */
TEST (dns_rr_decode_zero_ttl)
{
  unsigned char wire[] = {
    3, 'f', 'o', 'o',
    0,              /* Name terminator */
    0, 1,           /* TYPE = A */
    0, 1,           /* CLASS = IN */
    0, 0, 0, 0,     /* TTL = 0 */
    0, 4,           /* RDLENGTH = 4 */
    127, 0, 0, 1    /* 127.0.0.1 */
  };
  SocketDNS_RR rr;

  ASSERT_EQ (SocketDNS_rr_decode (wire, sizeof (wire), 0, &rr, NULL), 0);
  ASSERT_EQ (rr.ttl, 0);
}

/* Test RR with maximum TTL */
TEST (dns_rr_decode_max_ttl)
{
  unsigned char wire[] = {
    3, 'f', 'o', 'o',
    0,              /* Name terminator */
    0, 1,           /* TYPE = A */
    0, 1,           /* CLASS = IN */
    0xFF, 0xFF, 0xFF, 0xFF, /* TTL = 0xFFFFFFFF (max) */
    0, 4,           /* RDLENGTH = 4 */
    1, 2, 3, 4
  };
  SocketDNS_RR rr;

  ASSERT_EQ (SocketDNS_rr_decode (wire, sizeof (wire), 0, &rr, NULL), 0);
  ASSERT_EQ (rr.ttl, 0xFFFFFFFF);
}

/* Test RR with zero RDLENGTH */
TEST (dns_rr_decode_zero_rdlength)
{
  unsigned char wire[] = {
    3, 'f', 'o', 'o',
    0,              /* Name terminator */
    0, 10,          /* TYPE = NULL (10) */
    0, 1,           /* CLASS = IN */
    0, 0, 0, 60,    /* TTL = 60 */
    0, 0            /* RDLENGTH = 0 */
  };
  SocketDNS_RR rr;
  size_t consumed;

  ASSERT_EQ (SocketDNS_rr_decode (wire, sizeof (wire), 0, &rr, &consumed), 0);
  ASSERT_EQ (consumed, sizeof (wire));
  ASSERT_EQ (rr.rdlength, 0);
  ASSERT_NULL (rr.rdata);  /* NULL when rdlength is 0 */
}

/* Test RR skip basic */
TEST (dns_rr_skip_basic)
{
  unsigned char wire[] = {
    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    3, 'c', 'o', 'm',
    0,              /* Name terminator */
    0, 1,           /* TYPE = A */
    0, 1,           /* CLASS = IN */
    0, 0, 0x0E, 0x10, /* TTL = 3600 */
    0, 4,           /* RDLENGTH = 4 */
    192, 0, 2, 1
  };
  size_t consumed;

  ASSERT_EQ (SocketDNS_rr_skip (wire, sizeof (wire), 0, &consumed), 0);
  ASSERT_EQ (consumed, sizeof (wire));
}

/* Test skipping multiple RRs */
TEST (dns_rr_skip_multiple)
{
  /* Two A records back to back */
  unsigned char wire[] = {
    /* First RR: "a.com" A 1.2.3.4 */
    1, 'a', 3, 'c', 'o', 'm', 0,
    0, 1, 0, 1,           /* TYPE=A, CLASS=IN */
    0, 0, 0, 60,          /* TTL=60 */
    0, 4, 1, 2, 3, 4,     /* RDLENGTH=4, RDATA */
    /* Second RR: "b.com" A 5.6.7.8 */
    1, 'b', 3, 'c', 'o', 'm', 0,
    0, 1, 0, 1,           /* TYPE=A, CLASS=IN */
    0, 0, 0, 60,          /* TTL=60 */
    0, 4, 5, 6, 7, 8      /* RDLENGTH=4, RDATA */
  };
  size_t consumed1, consumed2;
  size_t offset = 0;

  /* Skip first RR */
  ASSERT_EQ (SocketDNS_rr_skip (wire, sizeof (wire), offset, &consumed1), 0);
  ASSERT_EQ (consumed1, 21); /* 7 (name) + 10 (fixed) + 4 (rdata) */

  offset += consumed1;

  /* Skip second RR */
  ASSERT_EQ (SocketDNS_rr_skip (wire, sizeof (wire), offset, &consumed2), 0);
  ASSERT_EQ (consumed2, 21);

  /* Total should match */
  ASSERT_EQ (offset + consumed2, sizeof (wire));
}

/* Test RR decode after question (typical response parsing) */
TEST (dns_rr_decode_after_question)
{
  unsigned char msg[128];
  size_t offset;
  SocketDNS_Question q;
  SocketDNS_RR rr;
  size_t consumed;

  memset (msg, 0, sizeof (msg));

  /* Build a minimal response: header + question + answer */
  /* Header at offset 0: ID=0x1234, QR=1, QDCOUNT=1, ANCOUNT=1 */
  msg[0] = 0x12; msg[1] = 0x34;  /* ID */
  msg[2] = 0x80; msg[3] = 0x00;  /* QR=1, flags=0 */
  msg[4] = 0; msg[5] = 1;        /* QDCOUNT=1 */
  msg[6] = 0; msg[7] = 1;        /* ANCOUNT=1 */

  /* Question at offset 12: "test.com" A IN */
  offset = 12;
  msg[offset++] = 4;
  memcpy (msg + offset, "test", 4); offset += 4;
  msg[offset++] = 3;
  memcpy (msg + offset, "com", 3); offset += 3;
  msg[offset++] = 0;
  msg[offset++] = 0; msg[offset++] = 1;  /* QTYPE=A */
  msg[offset++] = 0; msg[offset++] = 1;  /* QCLASS=IN */

  /* Answer RR: compressed name + A record */
  msg[offset++] = 0xC0;
  msg[offset++] = 12;  /* Pointer to "test.com" */
  msg[offset++] = 0; msg[offset++] = 1;  /* TYPE=A */
  msg[offset++] = 0; msg[offset++] = 1;  /* CLASS=IN */
  msg[offset++] = 0; msg[offset++] = 0;
  msg[offset++] = 0; msg[offset++] = 120; /* TTL=120 */
  msg[offset++] = 0; msg[offset++] = 4;  /* RDLENGTH=4 */
  msg[offset++] = 93; msg[offset++] = 184;
  msg[offset++] = 216; msg[offset++] = 34; /* 93.184.216.34 */

  /* Parse question */
  ASSERT_EQ (SocketDNS_question_decode (msg, offset, 12, &q, &consumed), 0);
  ASSERT (strcmp (q.qname, "test.com") == 0);

  /* Parse answer RR */
  size_t rr_offset = 12 + consumed;
  ASSERT_EQ (SocketDNS_rr_decode (msg, offset, rr_offset, &rr, &consumed), 0);
  ASSERT (strcmp (rr.name, "test.com") == 0);
  ASSERT_EQ (rr.type, DNS_TYPE_A);
  ASSERT_EQ (rr.ttl, 120);
  ASSERT_EQ (rr.rdlength, 4);
  ASSERT_EQ (rr.rdata[0], 93);
}

/* Test RR decode truncated - missing RDATA */
TEST (dns_rr_decode_truncated_rdata)
{
  unsigned char wire[] = {
    3, 'f', 'o', 'o',
    0,              /* Name terminator */
    0, 1,           /* TYPE = A */
    0, 1,           /* CLASS = IN */
    0, 0, 0, 60,    /* TTL = 60 */
    0, 4            /* RDLENGTH = 4, but no RDATA follows */
  };
  SocketDNS_RR rr;

  ASSERT_EQ (SocketDNS_rr_decode (wire, sizeof (wire), 0, &rr, NULL), -1);
}

/* Test RR decode truncated - missing fixed fields */
TEST (dns_rr_decode_truncated_fixed)
{
  unsigned char wire[] = {
    3, 'f', 'o', 'o',
    0,              /* Name terminator */
    0, 1,           /* TYPE = A */
    0, 1,           /* CLASS = IN */
    0, 0            /* TTL incomplete */
  };
  SocketDNS_RR rr;

  ASSERT_EQ (SocketDNS_rr_decode (wire, sizeof (wire), 0, &rr, NULL), -1);
}

/* Test RR NULL pointer handling */
TEST (dns_rr_null_handling)
{
  unsigned char wire[] = {
    3, 'f', 'o', 'o', 0,
    0, 1, 0, 1,
    0, 0, 0, 60,
    0, 4, 1, 2, 3, 4
  };
  SocketDNS_RR rr;
  size_t consumed;

  ASSERT_EQ (SocketDNS_rr_decode (NULL, 64, 0, &rr, &consumed), -1);
  ASSERT_EQ (SocketDNS_rr_decode (wire, sizeof (wire), 0, NULL, &consumed), -1);
  ASSERT_EQ (SocketDNS_rr_skip (NULL, 64, 0, &consumed), -1);

  /* consumed=NULL should not crash */
  ASSERT_EQ (SocketDNS_rr_decode (wire, sizeof (wire), 0, &rr, NULL), 0);
  ASSERT_EQ (SocketDNS_rr_skip (wire, sizeof (wire), 0, NULL), 0);
}

/* Test RR decode invalid offset */
TEST (dns_rr_decode_invalid_offset)
{
  unsigned char wire[32];
  SocketDNS_RR rr;

  memset (wire, 0, sizeof (wire));
  ASSERT_EQ (SocketDNS_rr_decode (wire, sizeof (wire), 100, &rr, NULL), -1);
  ASSERT_EQ (SocketDNS_rr_skip (wire, sizeof (wire), 100, NULL), -1);
}

/* ==================== A/AAAA RDATA Parsing Tests ==================== */

/* Test A record RDATA parsing */
TEST (dns_rdata_parse_a_valid)
{
  unsigned char wire[] = {
    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    3, 'c', 'o', 'm',
    0,              /* Name terminator */
    0, 1,           /* TYPE = A */
    0, 1,           /* CLASS = IN */
    0, 0, 0x0E, 0x10, /* TTL = 3600 */
    0, 4,           /* RDLENGTH = 4 */
    93, 184, 216, 34  /* 93.184.216.34 (example.com) */
  };
  SocketDNS_RR rr;
  struct in_addr addr;
  char str[INET_ADDRSTRLEN];

  ASSERT_EQ (SocketDNS_rr_decode (wire, sizeof (wire), 0, &rr, NULL), 0);
  ASSERT_EQ (rr.type, DNS_TYPE_A);
  ASSERT_EQ (rr.rdlength, DNS_RDATA_A_SIZE);

  ASSERT_EQ (SocketDNS_rdata_parse_a (&rr, &addr), 0);
  inet_ntop (AF_INET, &addr, str, sizeof (str));
  ASSERT (strcmp (str, "93.184.216.34") == 0);
}

/* Test AAAA record RDATA parsing */
TEST (dns_rdata_parse_aaaa_valid)
{
  unsigned char wire[] = {
    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    3, 'c', 'o', 'm',
    0,              /* Name terminator */
    0, 28,          /* TYPE = AAAA (28) */
    0, 1,           /* CLASS = IN */
    0, 0, 0x0E, 0x10, /* TTL = 3600 */
    0, 16,          /* RDLENGTH = 16 */
    /* 2606:2800:0220:0001:0248:1893:25c8:1946 */
    0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01,
    0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46
  };
  SocketDNS_RR rr;
  struct in6_addr addr;
  char str[INET6_ADDRSTRLEN];

  ASSERT_EQ (SocketDNS_rr_decode (wire, sizeof (wire), 0, &rr, NULL), 0);
  ASSERT_EQ (rr.type, DNS_TYPE_AAAA);
  ASSERT_EQ (rr.rdlength, DNS_RDATA_AAAA_SIZE);

  ASSERT_EQ (SocketDNS_rdata_parse_aaaa (&rr, &addr), 0);
  inet_ntop (AF_INET6, &addr, str, sizeof (str));
  ASSERT (strcmp (str, "2606:2800:220:1:248:1893:25c8:1946") == 0);
}

/* Test A parser rejects wrong rdlength */
TEST (dns_rdata_parse_a_wrong_rdlength)
{
  SocketDNS_RR rr;
  struct in_addr addr;
  unsigned char fake_rdata[8] = {1, 2, 3, 4, 5, 6, 7, 8};

  memset (&rr, 0, sizeof (rr));
  rr.type = DNS_TYPE_A;
  rr.rdata = fake_rdata;

  /* rdlength = 3 (too short) */
  rr.rdlength = 3;
  ASSERT_EQ (SocketDNS_rdata_parse_a (&rr, &addr), -1);

  /* rdlength = 5 (too long) */
  rr.rdlength = 5;
  ASSERT_EQ (SocketDNS_rdata_parse_a (&rr, &addr), -1);
}

/* Test AAAA parser rejects wrong rdlength */
TEST (dns_rdata_parse_aaaa_wrong_rdlength)
{
  SocketDNS_RR rr;
  struct in6_addr addr;
  unsigned char fake_rdata[20];

  memset (&rr, 0, sizeof (rr));
  memset (fake_rdata, 0, sizeof (fake_rdata));
  rr.type = DNS_TYPE_AAAA;
  rr.rdata = fake_rdata;

  /* rdlength = 15 (too short) */
  rr.rdlength = 15;
  ASSERT_EQ (SocketDNS_rdata_parse_aaaa (&rr, &addr), -1);

  /* rdlength = 17 (too long) */
  rr.rdlength = 17;
  ASSERT_EQ (SocketDNS_rdata_parse_aaaa (&rr, &addr), -1);
}

/* Test A parser rejects AAAA record */
TEST (dns_rdata_parse_a_rejects_aaaa)
{
  SocketDNS_RR rr;
  struct in_addr addr;
  unsigned char fake_rdata[16];

  memset (&rr, 0, sizeof (rr));
  memset (fake_rdata, 0, sizeof (fake_rdata));
  rr.type = DNS_TYPE_AAAA;  /* Wrong type */
  rr.rdlength = 4;
  rr.rdata = fake_rdata;

  ASSERT_EQ (SocketDNS_rdata_parse_a (&rr, &addr), -1);
}

/* Test AAAA parser rejects A record */
TEST (dns_rdata_parse_aaaa_rejects_a)
{
  SocketDNS_RR rr;
  struct in6_addr addr;
  unsigned char fake_rdata[16];

  memset (&rr, 0, sizeof (rr));
  memset (fake_rdata, 0, sizeof (fake_rdata));
  rr.type = DNS_TYPE_A;  /* Wrong type */
  rr.rdlength = 16;
  rr.rdata = fake_rdata;

  ASSERT_EQ (SocketDNS_rdata_parse_aaaa (&rr, &addr), -1);
}

/* Test NULL pointer handling for A parser */
TEST (dns_rdata_parse_a_null_handling)
{
  SocketDNS_RR rr;
  struct in_addr addr;
  unsigned char fake_rdata[4] = {1, 2, 3, 4};

  memset (&rr, 0, sizeof (rr));
  rr.type = DNS_TYPE_A;
  rr.rdlength = 4;
  rr.rdata = fake_rdata;

  /* NULL rr */
  ASSERT_EQ (SocketDNS_rdata_parse_a (NULL, &addr), -1);

  /* NULL addr */
  ASSERT_EQ (SocketDNS_rdata_parse_a (&rr, NULL), -1);

  /* NULL rdata */
  rr.rdata = NULL;
  ASSERT_EQ (SocketDNS_rdata_parse_a (&rr, &addr), -1);
}

/* Test NULL pointer handling for AAAA parser */
TEST (dns_rdata_parse_aaaa_null_handling)
{
  SocketDNS_RR rr;
  struct in6_addr addr;
  unsigned char fake_rdata[16];

  memset (&rr, 0, sizeof (rr));
  memset (fake_rdata, 0, sizeof (fake_rdata));
  rr.type = DNS_TYPE_AAAA;
  rr.rdlength = 16;
  rr.rdata = fake_rdata;

  /* NULL rr */
  ASSERT_EQ (SocketDNS_rdata_parse_aaaa (NULL, &addr), -1);

  /* NULL addr */
  ASSERT_EQ (SocketDNS_rdata_parse_aaaa (&rr, NULL), -1);

  /* NULL rdata */
  rr.rdata = NULL;
  ASSERT_EQ (SocketDNS_rdata_parse_aaaa (&rr, &addr), -1);
}

/* Test A parser with loopback address */
TEST (dns_rdata_parse_a_loopback)
{
  SocketDNS_RR rr;
  struct in_addr addr;
  unsigned char rdata[4] = {127, 0, 0, 1};  /* 127.0.0.1 */
  char str[INET_ADDRSTRLEN];

  memset (&rr, 0, sizeof (rr));
  rr.type = DNS_TYPE_A;
  rr.rdlength = 4;
  rr.rdata = rdata;

  ASSERT_EQ (SocketDNS_rdata_parse_a (&rr, &addr), 0);
  inet_ntop (AF_INET, &addr, str, sizeof (str));
  ASSERT (strcmp (str, "127.0.0.1") == 0);
}

/* Test AAAA parser with loopback address */
TEST (dns_rdata_parse_aaaa_loopback)
{
  SocketDNS_RR rr;
  struct in6_addr addr;
  unsigned char rdata[16] = {0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 1};  /* ::1 */
  char str[INET6_ADDRSTRLEN];

  memset (&rr, 0, sizeof (rr));
  rr.type = DNS_TYPE_AAAA;
  rr.rdlength = 16;
  rr.rdata = rdata;

  ASSERT_EQ (SocketDNS_rdata_parse_aaaa (&rr, &addr), 0);
  inet_ntop (AF_INET6, &addr, str, sizeof (str));
  ASSERT (strcmp (str, "::1") == 0);
}

/* ==================== CNAME RDATA Parsing Tests ==================== */

/* Test valid CNAME record parsing */
TEST (dns_rdata_parse_cname_valid)
{
  /* Build a DNS response with CNAME record:
   * alias.example.com CNAME www.example.com
   */
  unsigned char msg[128];
  SocketDNS_RR rr;
  char cname[DNS_MAX_NAME_LEN];
  int len;
  size_t offset = 0;

  memset (msg, 0, 12); /* Header */
  offset = 12;

  /* Query name "alias.example.com" at offset 12 */
  msg[offset++] = 5;
  memcpy (msg + offset, "alias", 5); offset += 5;
  msg[offset++] = 7;
  memcpy (msg + offset, "example", 7); offset += 7;
  msg[offset++] = 3;
  memcpy (msg + offset, "com", 3); offset += 3;
  msg[offset++] = 0;

  /* CNAME RR header */
  size_t rr_start = offset;
  msg[offset++] = 0xC0; /* Compression pointer */
  msg[offset++] = 12;   /* Points back to "alias.example.com" */
  msg[offset++] = 0; msg[offset++] = 5;   /* TYPE = CNAME */
  msg[offset++] = 0; msg[offset++] = 1;   /* CLASS = IN */
  msg[offset++] = 0; msg[offset++] = 0;
  msg[offset++] = 0x0E; msg[offset++] = 0x10; /* TTL = 3600 */
  msg[offset++] = 0; msg[offset++] = 15;  /* RDLENGTH = 15 */

  /* CNAME RDATA: "www.example.com" */
  msg[offset++] = 3;
  memcpy (msg + offset, "www", 3); offset += 3;
  msg[offset++] = 7;
  memcpy (msg + offset, "example", 7); offset += 7;
  msg[offset++] = 3;
  memcpy (msg + offset, "com", 3); offset += 3;
  msg[offset++] = 0;

  ASSERT_EQ (SocketDNS_rr_decode (msg, offset, rr_start, &rr, NULL), 0);
  ASSERT_EQ (rr.type, DNS_TYPE_CNAME);

  len = SocketDNS_rdata_parse_cname (msg, offset, &rr, cname, sizeof (cname));
  ASSERT (len >= 0);
  ASSERT (strcmp (cname, "www.example.com") == 0);
}

/* Test CNAME with compression pointer in RDATA */
TEST (dns_rdata_parse_cname_compressed)
{
  unsigned char msg[128];
  SocketDNS_RR rr;
  char cname[DNS_MAX_NAME_LEN];
  int len;
  size_t offset = 0;

  memset (msg, 0, 12);
  offset = 12;

  /* "example.com" at offset 12 */
  msg[offset++] = 7;
  memcpy (msg + offset, "example", 7); offset += 7;
  msg[offset++] = 3;
  memcpy (msg + offset, "com", 3); offset += 3;
  msg[offset++] = 0;

  /* CNAME RR with "www" + pointer */
  size_t rr_start = offset;
  msg[offset++] = 3;
  memcpy (msg + offset, "foo", 3); offset += 3;
  msg[offset++] = 0xC0;
  msg[offset++] = 12; /* ptr to "example.com" */
  msg[offset++] = 0; msg[offset++] = 5;   /* TYPE = CNAME */
  msg[offset++] = 0; msg[offset++] = 1;   /* CLASS = IN */
  msg[offset++] = 0; msg[offset++] = 0;
  msg[offset++] = 0; msg[offset++] = 60;  /* TTL = 60 */
  msg[offset++] = 0; msg[offset++] = 6;   /* RDLENGTH = 6 (www + ptr) */

  /* CNAME RDATA: "www" + pointer to offset 12 */
  msg[offset++] = 3;
  memcpy (msg + offset, "www", 3); offset += 3;
  msg[offset++] = 0xC0;
  msg[offset++] = 12;

  ASSERT_EQ (SocketDNS_rr_decode (msg, offset, rr_start, &rr, NULL), 0);
  ASSERT_EQ (rr.type, DNS_TYPE_CNAME);

  len = SocketDNS_rdata_parse_cname (msg, offset, &rr, cname, sizeof (cname));
  ASSERT (len >= 0);
  ASSERT (strcmp (cname, "www.example.com") == 0);
}

/* Test CNAME parser rejects wrong type */
TEST (dns_rdata_parse_cname_wrong_type)
{
  unsigned char msg[64];
  SocketDNS_RR rr;
  char cname[DNS_MAX_NAME_LEN];
  unsigned char fake_rdata[4] = {1, 2, 3, 4};

  memset (msg, 0, sizeof (msg));
  memset (&rr, 0, sizeof (rr));
  rr.type = DNS_TYPE_A;  /* Wrong type - should be CNAME */
  rr.rdlength = 4;
  rr.rdata = fake_rdata;

  ASSERT_EQ (SocketDNS_rdata_parse_cname (msg, sizeof (msg), &rr,
                                           cname, sizeof (cname)), -1);
}

/* Test NULL pointer handling */
TEST (dns_rdata_parse_cname_null_handling)
{
  unsigned char msg[64];
  SocketDNS_RR rr;
  char cname[DNS_MAX_NAME_LEN];
  unsigned char fake_rdata[16];

  memset (msg, 0, sizeof (msg));
  memset (&rr, 0, sizeof (rr));
  memset (fake_rdata, 0, sizeof (fake_rdata));
  rr.type = DNS_TYPE_CNAME;
  rr.rdlength = 10;
  rr.rdata = msg + 20;  /* Point somewhere in msg */

  /* NULL msg */
  ASSERT_EQ (SocketDNS_rdata_parse_cname (NULL, sizeof (msg), &rr,
                                           cname, sizeof (cname)), -1);

  /* NULL rr */
  ASSERT_EQ (SocketDNS_rdata_parse_cname (msg, sizeof (msg), NULL,
                                           cname, sizeof (cname)), -1);

  /* NULL cname buffer */
  ASSERT_EQ (SocketDNS_rdata_parse_cname (msg, sizeof (msg), &rr,
                                           NULL, sizeof (cname)), -1);

  /* Zero cnamelen */
  ASSERT_EQ (SocketDNS_rdata_parse_cname (msg, sizeof (msg), &rr,
                                           cname, 0), -1);
}

/* Test CNAME with empty RDATA */
TEST (dns_rdata_parse_cname_empty_rdata)
{
  unsigned char msg[64];
  SocketDNS_RR rr;
  char cname[DNS_MAX_NAME_LEN];

  memset (msg, 0, sizeof (msg));
  memset (&rr, 0, sizeof (rr));
  rr.type = DNS_TYPE_CNAME;
  rr.rdlength = 0;  /* Empty */
  rr.rdata = NULL;

  ASSERT_EQ (SocketDNS_rdata_parse_cname (msg, sizeof (msg), &rr,
                                           cname, sizeof (cname)), -1);
}

/* Test full integration: header -> question -> CNAME RR -> parse */
TEST (dns_rdata_parse_cname_integration)
{
  unsigned char msg[256];
  SocketDNS_Header header;
  SocketDNS_Question question;
  SocketDNS_RR rr;
  char cname[DNS_MAX_NAME_LEN];
  size_t offset;
  size_t consumed;

  memset (msg, 0, sizeof (msg));

  /* Build header: QR=1, ANCOUNT=1 */
  header.id = 0x1234;
  header.qr = 1;
  header.opcode = DNS_OPCODE_QUERY;
  header.aa = 0;
  header.tc = 0;
  header.rd = 1;
  header.ra = 1;
  header.z = 0;
  header.rcode = DNS_RCODE_NOERROR;
  header.qdcount = 1;
  header.ancount = 1;
  header.nscount = 0;
  header.arcount = 0;

  ASSERT_EQ (SocketDNS_header_encode (&header, msg, sizeof (msg)), 0);

  /* Build question at offset 12: "alias.test.com" CNAME */
  offset = 12;
  msg[offset++] = 5;
  memcpy (msg + offset, "alias", 5); offset += 5;
  msg[offset++] = 4;
  memcpy (msg + offset, "test", 4); offset += 4;
  msg[offset++] = 3;
  memcpy (msg + offset, "com", 3); offset += 3;
  msg[offset++] = 0;
  msg[offset++] = 0; msg[offset++] = 5;  /* QTYPE = CNAME */
  msg[offset++] = 0; msg[offset++] = 1;  /* QCLASS = IN */

  /* Build answer RR with compressed name */
  size_t rr_start = offset;
  msg[offset++] = 0xC0;
  msg[offset++] = 12;   /* Pointer to "alias.test.com" */
  msg[offset++] = 0; msg[offset++] = 5;   /* TYPE = CNAME */
  msg[offset++] = 0; msg[offset++] = 1;   /* CLASS = IN */
  msg[offset++] = 0; msg[offset++] = 0;
  msg[offset++] = 0; msg[offset++] = 120; /* TTL = 120 */
  msg[offset++] = 0; msg[offset++] = 12;  /* RDLENGTH = 12 */

  /* CNAME RDATA: "real.test.com" */
  msg[offset++] = 4;
  memcpy (msg + offset, "real", 4); offset += 4;
  msg[offset++] = 4;
  memcpy (msg + offset, "test", 4); offset += 4;
  msg[offset++] = 3;
  memcpy (msg + offset, "com", 3); offset += 3;
  msg[offset++] = 0;

  /* Parse header */
  SocketDNS_Header decoded_header;
  ASSERT_EQ (SocketDNS_header_decode (msg, offset, &decoded_header), 0);
  ASSERT_EQ (decoded_header.ancount, 1);

  /* Parse question */
  ASSERT_EQ (SocketDNS_question_decode (msg, offset, 12, &question, &consumed), 0);
  ASSERT (strcmp (question.qname, "alias.test.com") == 0);

  /* Parse CNAME RR */
  ASSERT_EQ (SocketDNS_rr_decode (msg, offset, rr_start, &rr, NULL), 0);
  ASSERT_EQ (rr.type, DNS_TYPE_CNAME);
  ASSERT_EQ (rr.ttl, 120);

  /* Parse CNAME RDATA */
  int len = SocketDNS_rdata_parse_cname (msg, offset, &rr, cname, sizeof (cname));
  ASSERT (len >= 0);
  ASSERT (strcmp (cname, "real.test.com") == 0);
}

/* Test deeply nested compression in CNAME */
TEST (dns_rdata_parse_cname_deep_compression)
{
  unsigned char msg[128];
  SocketDNS_RR rr;
  char cname[DNS_MAX_NAME_LEN];
  int len;
  size_t offset = 0;

  memset (msg, 0, 12);
  offset = 12;

  /* "com" at offset 12 */
  msg[offset++] = 3;
  memcpy (msg + offset, "com", 3); offset += 3;
  msg[offset++] = 0;

  /* "example" + ptr to "com" at offset 17 */
  msg[offset++] = 7;
  memcpy (msg + offset, "example", 7); offset += 7;
  msg[offset++] = 0xC0;
  msg[offset++] = 12;

  /* RR with name "foo" + ptr to "example.com" */
  size_t rr_start = offset;
  msg[offset++] = 3;
  memcpy (msg + offset, "foo", 3); offset += 3;
  msg[offset++] = 0xC0;
  msg[offset++] = 17;
  msg[offset++] = 0; msg[offset++] = 5;   /* TYPE = CNAME */
  msg[offset++] = 0; msg[offset++] = 1;   /* CLASS = IN */
  msg[offset++] = 0; msg[offset++] = 0;
  msg[offset++] = 0; msg[offset++] = 60;  /* TTL */
  msg[offset++] = 0; msg[offset++] = 6;   /* RDLENGTH */

  /* CNAME RDATA: "bar" + ptr to "example.com" */
  msg[offset++] = 3;
  memcpy (msg + offset, "bar", 3); offset += 3;
  msg[offset++] = 0xC0;
  msg[offset++] = 17;

  ASSERT_EQ (SocketDNS_rr_decode (msg, offset, rr_start, &rr, NULL), 0);
  ASSERT_EQ (rr.type, DNS_TYPE_CNAME);

  len = SocketDNS_rdata_parse_cname (msg, offset, &rr, cname, sizeof (cname));
  ASSERT (len >= 0);
  ASSERT (strcmp (cname, "bar.example.com") == 0);
}

/* Test CNAME pointing to subdomain */
TEST (dns_rdata_parse_cname_subdomain)
{
  unsigned char msg[128];
  SocketDNS_RR rr;
  char cname[DNS_MAX_NAME_LEN];
  int len;
  size_t offset = 0;

  memset (msg, 0, 12);
  offset = 12;

  /* "short.io" at offset 12 */
  msg[offset++] = 5;
  memcpy (msg + offset, "short", 5); offset += 5;
  msg[offset++] = 2;
  memcpy (msg + offset, "io", 2); offset += 2;
  msg[offset++] = 0;

  /* CNAME RR */
  size_t rr_start = offset;
  msg[offset++] = 0xC0;
  msg[offset++] = 12;
  msg[offset++] = 0; msg[offset++] = 5;   /* TYPE = CNAME */
  msg[offset++] = 0; msg[offset++] = 1;   /* CLASS = IN */
  msg[offset++] = 0; msg[offset++] = 0;
  msg[offset++] = 0; msg[offset++] = 300 & 0xFF; /* TTL = 300 */
  msg[offset++] = 0; msg[offset++] = 22;  /* RDLENGTH */

  /* CNAME RDATA: "redirect.cdn.cloudflare.net" */
  msg[offset++] = 8;
  memcpy (msg + offset, "redirect", 8); offset += 8;
  msg[offset++] = 3;
  memcpy (msg + offset, "cdn", 3); offset += 3;
  msg[offset++] = 10;
  memcpy (msg + offset, "cloudflare", 10); offset += 10;
  msg[offset++] = 3;
  memcpy (msg + offset, "net", 3); offset += 3;
  msg[offset++] = 0;

  ASSERT_EQ (SocketDNS_rr_decode (msg, offset, rr_start, &rr, NULL), 0);
  ASSERT_EQ (rr.type, DNS_TYPE_CNAME);

  len = SocketDNS_rdata_parse_cname (msg, offset, &rr, cname, sizeof (cname));
  ASSERT (len >= 0);
  ASSERT (strcmp (cname, "redirect.cdn.cloudflare.net") == 0);
}

/*
 * SOA RDATA Parsing Tests (RFC 1035 Section 3.3.13)
 */

/* Test parsing valid SOA record with all fields */
TEST (dns_rdata_parse_soa_valid)
{
  unsigned char msg[256];
  SocketDNS_RR rr;
  SocketDNS_SOA soa;
  size_t offset = 0;

  /* Build minimal header */
  memset (msg, 0, 12);
  offset = 12;

  /* "example.com" at offset 12 */
  msg[offset++] = 7;
  memcpy (msg + offset, "example", 7); offset += 7;
  msg[offset++] = 3;
  memcpy (msg + offset, "com", 3); offset += 3;
  msg[offset++] = 0;

  /* SOA RR */
  size_t rr_start = offset;
  msg[offset++] = 0xC0;
  msg[offset++] = 12;  /* Name pointer to example.com */
  msg[offset++] = 0; msg[offset++] = 6;   /* TYPE = SOA */
  msg[offset++] = 0; msg[offset++] = 1;   /* CLASS = IN */
  msg[offset++] = 0; msg[offset++] = 0;
  msg[offset++] = 0x0E; msg[offset++] = 0x10; /* TTL = 3600 */

  /* RDLENGTH - calculated after building RDATA */
  size_t rdlen_offset = offset;
  msg[offset++] = 0; msg[offset++] = 0; /* placeholder */

  size_t rdata_start = offset;

  /* MNAME: "ns1.example.com" */
  msg[offset++] = 3;
  memcpy (msg + offset, "ns1", 3); offset += 3;
  msg[offset++] = 0xC0;
  msg[offset++] = 12; /* pointer to example.com */

  /* RNAME: "hostmaster.example.com" */
  msg[offset++] = 10;
  memcpy (msg + offset, "hostmaster", 10); offset += 10;
  msg[offset++] = 0xC0;
  msg[offset++] = 12; /* pointer to example.com */

  /* SERIAL = 2024010101 (0x78A3F175) */
  msg[offset++] = 0x78;
  msg[offset++] = 0xA3;
  msg[offset++] = 0xF1;
  msg[offset++] = 0x75;

  /* REFRESH = 7200 (0x1C20) */
  msg[offset++] = 0x00;
  msg[offset++] = 0x00;
  msg[offset++] = 0x1C;
  msg[offset++] = 0x20;

  /* RETRY = 1800 (0x0708) */
  msg[offset++] = 0x00;
  msg[offset++] = 0x00;
  msg[offset++] = 0x07;
  msg[offset++] = 0x08;

  /* EXPIRE = 604800 (0x00093A80) */
  msg[offset++] = 0x00;
  msg[offset++] = 0x09;
  msg[offset++] = 0x3A;
  msg[offset++] = 0x80;

  /* MINIMUM = 86400 (0x00015180) */
  msg[offset++] = 0x00;
  msg[offset++] = 0x01;
  msg[offset++] = 0x51;
  msg[offset++] = 0x80;

  /* Fill in RDLENGTH */
  size_t rdlen = offset - rdata_start;
  msg[rdlen_offset] = (rdlen >> 8) & 0xFF;
  msg[rdlen_offset + 1] = rdlen & 0xFF;

  ASSERT_EQ (SocketDNS_rr_decode (msg, offset, rr_start, &rr, NULL), 0);
  ASSERT_EQ (rr.type, DNS_TYPE_SOA);

  ASSERT_EQ (SocketDNS_rdata_parse_soa (msg, offset, &rr, &soa), 0);
  ASSERT (strcmp (soa.mname, "ns1.example.com") == 0);
  ASSERT (strcmp (soa.rname, "hostmaster.example.com") == 0);
  ASSERT_EQ (soa.serial, 2024010101U);
  ASSERT_EQ (soa.refresh, 7200U);
  ASSERT_EQ (soa.retry, 1800U);
  ASSERT_EQ (soa.expire, 604800U);
  ASSERT_EQ (soa.minimum, 86400U);
}

/* Test SOA with compressed MNAME */
TEST (dns_rdata_parse_soa_compressed_mname)
{
  unsigned char msg[256];
  SocketDNS_RR rr;
  SocketDNS_SOA soa;
  size_t offset = 0;

  memset (msg, 0, 12);
  offset = 12;

  /* "dns.google" at offset 12 */
  msg[offset++] = 3;
  memcpy (msg + offset, "dns", 3); offset += 3;
  msg[offset++] = 6;
  memcpy (msg + offset, "google", 6); offset += 6;
  msg[offset++] = 0;

  /* SOA RR */
  size_t rr_start = offset;
  msg[offset++] = 0xC0;
  msg[offset++] = 12;
  msg[offset++] = 0; msg[offset++] = 6;   /* TYPE = SOA */
  msg[offset++] = 0; msg[offset++] = 1;   /* CLASS = IN */
  msg[offset++] = 0; msg[offset++] = 0;
  msg[offset++] = 0; msg[offset++] = 60;  /* TTL = 60 */

  size_t rdlen_offset = offset;
  msg[offset++] = 0; msg[offset++] = 0;

  size_t rdata_start = offset;

  /* MNAME: pointer to dns.google (offset 12) */
  msg[offset++] = 0xC0;
  msg[offset++] = 12;

  /* RNAME: "admin.google" (uncompressed) */
  msg[offset++] = 5;
  memcpy (msg + offset, "admin", 5); offset += 5;
  msg[offset++] = 6;
  memcpy (msg + offset, "google", 6); offset += 6;
  msg[offset++] = 0;

  /* Fixed fields (20 bytes) */
  msg[offset++] = 0x00; msg[offset++] = 0x00; msg[offset++] = 0x00; msg[offset++] = 0x01; /* SERIAL */
  msg[offset++] = 0x00; msg[offset++] = 0x00; msg[offset++] = 0x03; msg[offset++] = 0x84; /* REFRESH */
  msg[offset++] = 0x00; msg[offset++] = 0x00; msg[offset++] = 0x00; msg[offset++] = 0x3C; /* RETRY */
  msg[offset++] = 0x00; msg[offset++] = 0x00; msg[offset++] = 0x07; msg[offset++] = 0x08; /* EXPIRE */
  msg[offset++] = 0x00; msg[offset++] = 0x00; msg[offset++] = 0x00; msg[offset++] = 0x3C; /* MINIMUM */

  size_t rdlen = offset - rdata_start;
  msg[rdlen_offset] = (rdlen >> 8) & 0xFF;
  msg[rdlen_offset + 1] = rdlen & 0xFF;

  ASSERT_EQ (SocketDNS_rr_decode (msg, offset, rr_start, &rr, NULL), 0);
  ASSERT_EQ (SocketDNS_rdata_parse_soa (msg, offset, &rr, &soa), 0);
  ASSERT (strcmp (soa.mname, "dns.google") == 0);
  ASSERT (strcmp (soa.rname, "admin.google") == 0);
}

/* Test SOA with compressed RNAME */
TEST (dns_rdata_parse_soa_compressed_rname)
{
  unsigned char msg[256];
  SocketDNS_RR rr;
  SocketDNS_SOA soa;
  size_t offset = 0;

  memset (msg, 0, 12);
  offset = 12;

  /* "example.org" at offset 12 */
  msg[offset++] = 7;
  memcpy (msg + offset, "example", 7); offset += 7;
  msg[offset++] = 3;
  memcpy (msg + offset, "org", 3); offset += 3;
  msg[offset++] = 0;

  /* SOA RR */
  size_t rr_start = offset;
  msg[offset++] = 0xC0;
  msg[offset++] = 12;
  msg[offset++] = 0; msg[offset++] = 6;   /* TYPE = SOA */
  msg[offset++] = 0; msg[offset++] = 1;   /* CLASS = IN */
  msg[offset++] = 0; msg[offset++] = 0;
  msg[offset++] = 0; msg[offset++] = 120; /* TTL */

  size_t rdlen_offset = offset;
  msg[offset++] = 0; msg[offset++] = 0;

  size_t rdata_start = offset;

  /* MNAME: "ns.example.org" (uncompressed) */
  msg[offset++] = 2;
  memcpy (msg + offset, "ns", 2); offset += 2;
  msg[offset++] = 7;
  memcpy (msg + offset, "example", 7); offset += 7;
  msg[offset++] = 3;
  memcpy (msg + offset, "org", 3); offset += 3;
  msg[offset++] = 0;

  /* RNAME: "admin" + pointer to example.org */
  msg[offset++] = 5;
  memcpy (msg + offset, "admin", 5); offset += 5;
  msg[offset++] = 0xC0;
  msg[offset++] = 12;

  /* Fixed fields */
  msg[offset++] = 0x00; msg[offset++] = 0x00; msg[offset++] = 0x00; msg[offset++] = 0x64; /* SERIAL = 100 */
  msg[offset++] = 0x00; msg[offset++] = 0x00; msg[offset++] = 0x01; msg[offset++] = 0x2C; /* REFRESH = 300 */
  msg[offset++] = 0x00; msg[offset++] = 0x00; msg[offset++] = 0x00; msg[offset++] = 0x64; /* RETRY = 100 */
  msg[offset++] = 0x00; msg[offset++] = 0x01; msg[offset++] = 0x51; msg[offset++] = 0x80; /* EXPIRE = 86400 */
  msg[offset++] = 0x00; msg[offset++] = 0x00; msg[offset++] = 0x01; msg[offset++] = 0x2C; /* MINIMUM = 300 */

  size_t rdlen = offset - rdata_start;
  msg[rdlen_offset] = (rdlen >> 8) & 0xFF;
  msg[rdlen_offset + 1] = rdlen & 0xFF;

  ASSERT_EQ (SocketDNS_rr_decode (msg, offset, rr_start, &rr, NULL), 0);
  ASSERT_EQ (SocketDNS_rdata_parse_soa (msg, offset, &rr, &soa), 0);
  ASSERT (strcmp (soa.mname, "ns.example.org") == 0);
  ASSERT (strcmp (soa.rname, "admin.example.org") == 0);
  ASSERT_EQ (soa.serial, 100U);
  ASSERT_EQ (soa.minimum, 300U);
}

/* Test SOA with both MNAME and RNAME compressed */
TEST (dns_rdata_parse_soa_both_compressed)
{
  unsigned char msg[128];
  SocketDNS_RR rr;
  SocketDNS_SOA soa;
  size_t offset = 0;

  memset (msg, 0, 12);
  offset = 12;

  /* "test.net" at offset 12 */
  msg[offset++] = 4;
  memcpy (msg + offset, "test", 4); offset += 4;
  msg[offset++] = 3;
  memcpy (msg + offset, "net", 3); offset += 3;
  msg[offset++] = 0;

  /* SOA RR */
  size_t rr_start = offset;
  msg[offset++] = 0xC0;
  msg[offset++] = 12;
  msg[offset++] = 0; msg[offset++] = 6;
  msg[offset++] = 0; msg[offset++] = 1;
  msg[offset++] = 0; msg[offset++] = 0;
  msg[offset++] = 0; msg[offset++] = 0;

  size_t rdlen_offset = offset;
  msg[offset++] = 0; msg[offset++] = 0;

  size_t rdata_start = offset;

  /* MNAME: pointer to test.net */
  msg[offset++] = 0xC0;
  msg[offset++] = 12;

  /* RNAME: pointer to test.net */
  msg[offset++] = 0xC0;
  msg[offset++] = 12;

  /* Fixed fields */
  msg[offset++] = 0x12; msg[offset++] = 0x34; msg[offset++] = 0x56; msg[offset++] = 0x78;
  msg[offset++] = 0x00; msg[offset++] = 0x00; msg[offset++] = 0x00; msg[offset++] = 0x01;
  msg[offset++] = 0x00; msg[offset++] = 0x00; msg[offset++] = 0x00; msg[offset++] = 0x02;
  msg[offset++] = 0x00; msg[offset++] = 0x00; msg[offset++] = 0x00; msg[offset++] = 0x03;
  msg[offset++] = 0x00; msg[offset++] = 0x00; msg[offset++] = 0x00; msg[offset++] = 0x04;

  size_t rdlen = offset - rdata_start;
  msg[rdlen_offset] = (rdlen >> 8) & 0xFF;
  msg[rdlen_offset + 1] = rdlen & 0xFF;

  ASSERT_EQ (SocketDNS_rr_decode (msg, offset, rr_start, &rr, NULL), 0);
  ASSERT_EQ (SocketDNS_rdata_parse_soa (msg, offset, &rr, &soa), 0);
  ASSERT (strcmp (soa.mname, "test.net") == 0);
  ASSERT (strcmp (soa.rname, "test.net") == 0);
  ASSERT_EQ (soa.serial, 0x12345678U);
  ASSERT_EQ (soa.refresh, 1U);
  ASSERT_EQ (soa.retry, 2U);
  ASSERT_EQ (soa.expire, 3U);
  ASSERT_EQ (soa.minimum, 4U);
}

/* Test SOA parsing rejects wrong RR type */
TEST (dns_rdata_parse_soa_wrong_type)
{
  SocketDNS_RR rr;
  SocketDNS_SOA soa;
  unsigned char msg[64];

  memset (msg, 0, sizeof (msg));
  memset (&rr, 0, sizeof (rr));

  rr.type = DNS_TYPE_A;  /* Wrong type */
  rr.rclass = DNS_CLASS_IN;
  rr.rdlength = 40;
  rr.rdata = msg + 12;

  ASSERT_EQ (SocketDNS_rdata_parse_soa (msg, sizeof (msg), &rr, &soa), -1);

  rr.type = DNS_TYPE_CNAME;
  ASSERT_EQ (SocketDNS_rdata_parse_soa (msg, sizeof (msg), &rr, &soa), -1);
}

/* Test SOA parsing handles NULL parameters */
TEST (dns_rdata_parse_soa_null_handling)
{
  unsigned char msg[64];
  SocketDNS_RR rr;
  SocketDNS_SOA soa;

  memset (msg, 0, sizeof (msg));
  memset (&rr, 0, sizeof (rr));
  rr.type = DNS_TYPE_SOA;
  rr.rdlength = 40;
  rr.rdata = msg + 12;

  /* NULL msg */
  ASSERT_EQ (SocketDNS_rdata_parse_soa (NULL, sizeof (msg), &rr, &soa), -1);

  /* NULL rr */
  ASSERT_EQ (SocketDNS_rdata_parse_soa (msg, sizeof (msg), NULL, &soa), -1);

  /* NULL soa */
  ASSERT_EQ (SocketDNS_rdata_parse_soa (msg, sizeof (msg), &rr, NULL), -1);
}

/* Test SOA parsing handles truncated fixed fields */
TEST (dns_rdata_parse_soa_truncated_fixed)
{
  unsigned char msg[128];
  SocketDNS_RR rr;
  SocketDNS_SOA soa;
  size_t offset = 0;

  memset (msg, 0, 12);
  offset = 12;

  /* "a.b" at offset 12 */
  msg[offset++] = 1;
  msg[offset++] = 'a';
  msg[offset++] = 1;
  msg[offset++] = 'b';
  msg[offset++] = 0;

  /* SOA RR */
  size_t rr_start = offset;
  msg[offset++] = 0xC0;
  msg[offset++] = 12;
  msg[offset++] = 0; msg[offset++] = 6;
  msg[offset++] = 0; msg[offset++] = 1;
  msg[offset++] = 0; msg[offset++] = 0;
  msg[offset++] = 0; msg[offset++] = 0;

  /* RDLENGTH = 10 (only enough for 2 pointers + partial fixed fields) */
  msg[offset++] = 0; msg[offset++] = 10;

  size_t rdata_start = offset;
  msg[offset++] = 0xC0; msg[offset++] = 12;  /* MNAME pointer */
  msg[offset++] = 0xC0; msg[offset++] = 12;  /* RNAME pointer */
  /* Only 6 bytes of fixed fields (need 20) */
  msg[offset++] = 0x00; msg[offset++] = 0x00;
  msg[offset++] = 0x00; msg[offset++] = 0x01;
  msg[offset++] = 0x00; msg[offset++] = 0x00;

  ASSERT_EQ (SocketDNS_rr_decode (msg, offset, rr_start, &rr, NULL), 0);
  ASSERT_EQ (rr.type, DNS_TYPE_SOA);

  /* Should fail - not enough bytes for fixed fields */
  ASSERT_EQ (SocketDNS_rdata_parse_soa (msg, offset, &rr, &soa), -1);
}

/* Test SOA parsing handles empty RDATA */
TEST (dns_rdata_parse_soa_empty_rdata)
{
  SocketDNS_RR rr;
  SocketDNS_SOA soa;
  unsigned char msg[64];

  memset (msg, 0, sizeof (msg));
  memset (&rr, 0, sizeof (rr));

  rr.type = DNS_TYPE_SOA;
  rr.rclass = DNS_CLASS_IN;
  rr.rdlength = 0;
  rr.rdata = msg + 12;

  ASSERT_EQ (SocketDNS_rdata_parse_soa (msg, sizeof (msg), &rr, &soa), -1);

  /* NULL rdata */
  rr.rdlength = 40;
  rr.rdata = NULL;
  ASSERT_EQ (SocketDNS_rdata_parse_soa (msg, sizeof (msg), &rr, &soa), -1);
}

/* Test SOA full integration: header -> question -> RR -> SOA */
TEST (dns_rdata_parse_soa_integration)
{
  unsigned char msg[256];
  SocketDNS_Header header;
  SocketDNS_Question question;
  SocketDNS_RR rr;
  SocketDNS_SOA soa;
  size_t offset = 0;
  size_t consumed;

  /* Build header */
  memset (&header, 0, sizeof (header));
  header.id = 0xABCD;
  header.qr = 1;
  header.aa = 1;
  header.rd = 1;
  header.ra = 1;
  header.qdcount = 1;
  header.ancount = 1;

  ASSERT_EQ (SocketDNS_header_encode (&header, msg, sizeof (msg)), 0);
  offset = DNS_HEADER_SIZE;

  /* Build question for "example.net" SOA */
  SocketDNS_question_init (&question, "example.net", DNS_TYPE_SOA);
  size_t qwritten;
  ASSERT_EQ (SocketDNS_question_encode (&question, msg + offset, sizeof (msg) - offset, &qwritten), 0);
  size_t name_offset = offset; /* Remember where name starts for compression */
  offset += qwritten;

  /* Build SOA answer RR */
  size_t rr_start = offset;

  /* Name: pointer to question */
  msg[offset++] = 0xC0;
  msg[offset++] = (unsigned char)name_offset;

  /* TYPE = SOA (6) */
  msg[offset++] = 0;
  msg[offset++] = 6;

  /* CLASS = IN (1) */
  msg[offset++] = 0;
  msg[offset++] = 1;

  /* TTL = 3600 */
  msg[offset++] = 0;
  msg[offset++] = 0;
  msg[offset++] = 0x0E;
  msg[offset++] = 0x10;

  /* RDLENGTH placeholder */
  size_t rdlen_offset = offset;
  msg[offset++] = 0;
  msg[offset++] = 0;

  size_t rdata_start = offset;

  /* MNAME: "ns1" + pointer to example.net */
  msg[offset++] = 3;
  memcpy (msg + offset, "ns1", 3);
  offset += 3;
  msg[offset++] = 0xC0;
  msg[offset++] = (unsigned char)name_offset;

  /* RNAME: "dns-admin" + pointer to example.net */
  msg[offset++] = 9;
  memcpy (msg + offset, "dns-admin", 9);
  offset += 9;
  msg[offset++] = 0xC0;
  msg[offset++] = (unsigned char)name_offset;

  /* SERIAL = 2025122201 (0x78B4E999) */
  msg[offset++] = 0x78;
  msg[offset++] = 0xB4;
  msg[offset++] = 0xE9;
  msg[offset++] = 0x99;

  /* REFRESH = 10800 (0x2A30) */
  msg[offset++] = 0x00;
  msg[offset++] = 0x00;
  msg[offset++] = 0x2A;
  msg[offset++] = 0x30;

  /* RETRY = 3600 (0x0E10) */
  msg[offset++] = 0x00;
  msg[offset++] = 0x00;
  msg[offset++] = 0x0E;
  msg[offset++] = 0x10;

  /* EXPIRE = 1209600 (0x00127500) */
  msg[offset++] = 0x00;
  msg[offset++] = 0x12;
  msg[offset++] = 0x75;
  msg[offset++] = 0x00;

  /* MINIMUM = 300 (0x012C) */
  msg[offset++] = 0x00;
  msg[offset++] = 0x00;
  msg[offset++] = 0x01;
  msg[offset++] = 0x2C;

  /* Fill in RDLENGTH */
  size_t rdlen = offset - rdata_start;
  msg[rdlen_offset] = (rdlen >> 8) & 0xFF;
  msg[rdlen_offset + 1] = rdlen & 0xFF;

  /* Decode and verify header */
  SocketDNS_Header decoded_header;
  ASSERT_EQ (SocketDNS_header_decode (msg, offset, &decoded_header), 0);
  ASSERT_EQ (decoded_header.id, 0xABCD);
  ASSERT_EQ (decoded_header.qdcount, 1);
  ASSERT_EQ (decoded_header.ancount, 1);

  /* Decode and verify question */
  SocketDNS_Question decoded_question;
  ASSERT_EQ (SocketDNS_question_decode (msg, offset, DNS_HEADER_SIZE, &decoded_question, &consumed), 0);
  ASSERT (strcmp (decoded_question.qname, "example.net") == 0);
  ASSERT_EQ (decoded_question.qtype, DNS_TYPE_SOA);

  /* Decode and verify RR */
  ASSERT_EQ (SocketDNS_rr_decode (msg, offset, rr_start, &rr, &consumed), 0);
  ASSERT (strcmp (rr.name, "example.net") == 0);
  ASSERT_EQ (rr.type, DNS_TYPE_SOA);
  ASSERT_EQ (rr.ttl, 3600U);

  /* Parse and verify SOA */
  ASSERT_EQ (SocketDNS_rdata_parse_soa (msg, offset, &rr, &soa), 0);
  ASSERT (strcmp (soa.mname, "ns1.example.net") == 0);
  ASSERT (strcmp (soa.rname, "dns-admin.example.net") == 0);
  ASSERT_EQ (soa.serial, 2025122201U);
  ASSERT_EQ (soa.refresh, 10800U);
  ASSERT_EQ (soa.retry, 3600U);
  ASSERT_EQ (soa.expire, 1209600U);
  ASSERT_EQ (soa.minimum, 300U);
}

/* Test SOA verifies all 5 integer fields are extracted correctly */
TEST (dns_rdata_parse_soa_verify_values)
{
  unsigned char msg[128];
  SocketDNS_RR rr;
  SocketDNS_SOA soa;
  size_t offset = 0;

  memset (msg, 0, 12);
  offset = 12;

  /* Root zone "." */
  msg[offset++] = 0;

  /* SOA RR for root */
  size_t rr_start = offset;
  msg[offset++] = 0;  /* Root name */
  msg[offset++] = 0; msg[offset++] = 6;
  msg[offset++] = 0; msg[offset++] = 1;
  msg[offset++] = 0; msg[offset++] = 0;
  msg[offset++] = 0; msg[offset++] = 0;

  size_t rdlen_offset = offset;
  msg[offset++] = 0; msg[offset++] = 0;

  size_t rdata_start = offset;

  /* MNAME: "a.root-servers.net" (simplified as just root for test) */
  msg[offset++] = 0;

  /* RNAME: root */
  msg[offset++] = 0;

  /* Test boundary values for 32-bit integers */

  /* SERIAL = 0xFFFFFFFF (max uint32) */
  msg[offset++] = 0xFF;
  msg[offset++] = 0xFF;
  msg[offset++] = 0xFF;
  msg[offset++] = 0xFF;

  /* REFRESH = 0x80000000 (high bit set) */
  msg[offset++] = 0x80;
  msg[offset++] = 0x00;
  msg[offset++] = 0x00;
  msg[offset++] = 0x00;

  /* RETRY = 0x00000000 (zero) */
  msg[offset++] = 0x00;
  msg[offset++] = 0x00;
  msg[offset++] = 0x00;
  msg[offset++] = 0x00;

  /* EXPIRE = 0x12345678 */
  msg[offset++] = 0x12;
  msg[offset++] = 0x34;
  msg[offset++] = 0x56;
  msg[offset++] = 0x78;

  /* MINIMUM = 0x00000001 */
  msg[offset++] = 0x00;
  msg[offset++] = 0x00;
  msg[offset++] = 0x00;
  msg[offset++] = 0x01;

  size_t rdlen = offset - rdata_start;
  msg[rdlen_offset] = (rdlen >> 8) & 0xFF;
  msg[rdlen_offset + 1] = rdlen & 0xFF;

  ASSERT_EQ (SocketDNS_rr_decode (msg, offset, rr_start, &rr, NULL), 0);
  ASSERT_EQ (SocketDNS_rdata_parse_soa (msg, offset, &rr, &soa), 0);

  /* Verify boundary values */
  ASSERT_EQ (soa.serial, 0xFFFFFFFFU);
  ASSERT_EQ (soa.refresh, 0x80000000U);
  ASSERT_EQ (soa.retry, 0x00000000U);
  ASSERT_EQ (soa.expire, 0x12345678U);
  ASSERT_EQ (soa.minimum, 0x00000001U);
}

/*
 * EDNS0 OPT Record Tests (RFC 6891)
 */

/* Test SocketDNS_opt_init() sets default values correctly */
TEST (dns_opt_init_defaults)
{
  SocketDNS_OPT opt;

  SocketDNS_opt_init (&opt, 4096);

  ASSERT_EQ (opt.udp_payload_size, 4096);
  ASSERT_EQ (opt.extended_rcode, 0);
  ASSERT_EQ (opt.version, DNS_EDNS0_VERSION);
  ASSERT_EQ (opt.do_bit, 0);
  ASSERT_EQ (opt.z, 0);
  ASSERT_EQ (opt.rdlength, 0);
  ASSERT (opt.rdata == NULL);
}

/* Test SocketDNS_opt_init() enforces minimum 512 bytes */
TEST (dns_opt_init_min_size)
{
  SocketDNS_OPT opt;

  /* Request 256, should get 512 */
  SocketDNS_opt_init (&opt, 256);
  ASSERT_EQ (opt.udp_payload_size, DNS_EDNS0_MIN_UDPSIZE);

  /* Request 0, should get 512 */
  SocketDNS_opt_init (&opt, 0);
  ASSERT_EQ (opt.udp_payload_size, DNS_EDNS0_MIN_UDPSIZE);

  /* Request 512, should get 512 */
  SocketDNS_opt_init (&opt, 512);
  ASSERT_EQ (opt.udp_payload_size, 512);

  /* Request 513, should get 513 */
  SocketDNS_opt_init (&opt, 513);
  ASSERT_EQ (opt.udp_payload_size, 513);
}

/* Test basic OPT encoding (minimal, no options) */
TEST (dns_opt_encode_basic)
{
  SocketDNS_OPT opt;
  unsigned char buf[DNS_OPT_FIXED_SIZE + 16];
  int len;

  SocketDNS_opt_init (&opt, 4096);

  len = SocketDNS_opt_encode (&opt, buf, sizeof (buf));
  ASSERT_EQ (len, DNS_OPT_FIXED_SIZE);

  /* Verify wire format */
  ASSERT_EQ (buf[0], 0x00);       /* NAME = root */
  ASSERT_EQ (buf[1], 0x00);       /* TYPE high byte */
  ASSERT_EQ (buf[2], 41);         /* TYPE = OPT (41) */
  ASSERT_EQ (buf[3], 0x10);       /* CLASS high byte (4096 >> 8 = 16) */
  ASSERT_EQ (buf[4], 0x00);       /* CLASS low byte */
  ASSERT_EQ (buf[5], 0x00);       /* TTL byte 0 (extended RCODE) */
  ASSERT_EQ (buf[6], 0x00);       /* TTL byte 1 (version) */
  ASSERT_EQ (buf[7], 0x00);       /* TTL byte 2 (flags high) */
  ASSERT_EQ (buf[8], 0x00);       /* TTL byte 3 (flags low) */
  ASSERT_EQ (buf[9], 0x00);       /* RDLENGTH high */
  ASSERT_EQ (buf[10], 0x00);      /* RDLENGTH low */
}

/* Test OPT encoding with DO bit set */
TEST (dns_opt_encode_with_do)
{
  SocketDNS_OPT opt;
  unsigned char buf[DNS_OPT_FIXED_SIZE + 16];
  int len;

  SocketDNS_opt_init (&opt, 1232);
  opt.do_bit = 1;

  len = SocketDNS_opt_encode (&opt, buf, sizeof (buf));
  ASSERT_EQ (len, DNS_OPT_FIXED_SIZE);

  /* CLASS = 1232 = 0x04D0 */
  ASSERT_EQ (buf[3], 0x04);
  ASSERT_EQ (buf[4], 0xD0);

  /* TTL byte 2 should have DO bit (0x80) */
  ASSERT_EQ (buf[7], 0x80);
}

/* Test encoding with extended RCODE and version */
TEST (dns_opt_encode_extended_rcode)
{
  SocketDNS_OPT opt;
  unsigned char buf[DNS_OPT_FIXED_SIZE + 16];
  int len;

  SocketDNS_opt_init (&opt, 4096);
  opt.extended_rcode = 0x01;  /* BADVERS upper bits */
  opt.version = 0;

  len = SocketDNS_opt_encode (&opt, buf, sizeof (buf));
  ASSERT_EQ (len, DNS_OPT_FIXED_SIZE);

  /* TTL byte 0 = extended RCODE = 0x01 */
  ASSERT_EQ (buf[5], 0x01);
  /* TTL byte 1 = version = 0 */
  ASSERT_EQ (buf[6], 0x00);
}

/* Test basic OPT decoding */
TEST (dns_opt_decode_basic)
{
  SocketDNS_OPT opt;
  unsigned char buf[DNS_OPT_FIXED_SIZE] = {
    0x00,             /* NAME = root */
    0x00, 0x29,       /* TYPE = 41 (OPT) */
    0x10, 0x00,       /* CLASS = 4096 */
    0x00, 0x00, 0x00, 0x00,  /* TTL = 0 */
    0x00, 0x00        /* RDLENGTH = 0 */
  };
  int consumed;

  consumed = SocketDNS_opt_decode (buf, sizeof (buf), &opt);
  ASSERT_EQ (consumed, DNS_OPT_FIXED_SIZE);

  ASSERT_EQ (opt.udp_payload_size, 4096);
  ASSERT_EQ (opt.extended_rcode, 0);
  ASSERT_EQ (opt.version, 0);
  ASSERT_EQ (opt.do_bit, 0);
  ASSERT_EQ (opt.z, 0);
  ASSERT_EQ (opt.rdlength, 0);
}

/* Test OPT decoding with options data */
TEST (dns_opt_decode_with_options)
{
  SocketDNS_OPT opt;
  unsigned char buf[] = {
    0x00,             /* NAME = root */
    0x00, 0x29,       /* TYPE = 41 (OPT) */
    0x04, 0xD0,       /* CLASS = 1232 */
    0x00, 0x00, 0x80, 0x00,  /* TTL: extended=0, ver=0, DO=1, Z=0 */
    0x00, 0x04,       /* RDLENGTH = 4 */
    0xDE, 0xAD, 0xBE, 0xEF  /* RDATA (dummy options) */
  };
  int consumed;

  consumed = SocketDNS_opt_decode (buf, sizeof (buf), &opt);
  ASSERT_EQ (consumed, DNS_OPT_FIXED_SIZE + 4);

  ASSERT_EQ (opt.udp_payload_size, 1232);
  ASSERT_EQ (opt.do_bit, 1);
  ASSERT_EQ (opt.rdlength, 4);
  ASSERT (opt.rdata != NULL);
  ASSERT_EQ (opt.rdata[0], 0xDE);
  ASSERT_EQ (opt.rdata[3], 0xEF);
}

/* Test OPT decode rejects non-root NAME */
TEST (dns_opt_decode_invalid_name)
{
  SocketDNS_OPT opt;
  unsigned char buf[] = {
    0x03, 'f', 'o', 'o', 0x00,  /* NAME = "foo" (not root) */
    0x00, 0x29,       /* TYPE = 41 */
    0x10, 0x00,       /* CLASS */
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00
  };
  int consumed;

  consumed = SocketDNS_opt_decode (buf, sizeof (buf), &opt);
  ASSERT_EQ (consumed, -1);  /* Should fail */
}

/* Test OPT decode rejects wrong TYPE */
TEST (dns_opt_decode_invalid_type)
{
  SocketDNS_OPT opt;
  unsigned char buf[] = {
    0x00,             /* NAME = root */
    0x00, 0x01,       /* TYPE = 1 (A, not OPT) */
    0x10, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00
  };
  int consumed;

  consumed = SocketDNS_opt_decode (buf, sizeof (buf), &opt);
  ASSERT_EQ (consumed, -1);  /* Should fail */
}

/* Test OPT decode handles truncated buffer */
TEST (dns_opt_decode_truncated)
{
  SocketDNS_OPT opt;
  unsigned char buf[5] = { 0x00, 0x00, 0x29, 0x10, 0x00 };
  int consumed;

  /* Buffer too short for full OPT */
  consumed = SocketDNS_opt_decode (buf, sizeof (buf), &opt);
  ASSERT_EQ (consumed, -1);

  /* Buffer too short for declared RDLENGTH */
  unsigned char buf2[] = {
    0x00, 0x00, 0x29, 0x10, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x10  /* RDLENGTH = 16, but no RDATA */
  };
  consumed = SocketDNS_opt_decode (buf2, sizeof (buf2), &opt);
  ASSERT_EQ (consumed, -1);
}

/* Test encode/decode roundtrip */
TEST (dns_opt_roundtrip)
{
  SocketDNS_OPT orig, decoded;
  unsigned char buf[DNS_OPT_FIXED_SIZE + 32];
  int encoded, consumed;

  /* Set up original with various values */
  SocketDNS_opt_init (&orig, 1280);
  orig.do_bit = 1;
  orig.extended_rcode = 0x02;
  orig.version = 0;

  encoded = SocketDNS_opt_encode (&orig, buf, sizeof (buf));
  ASSERT (encoded > 0);

  consumed = SocketDNS_opt_decode (buf, encoded, &decoded);
  ASSERT_EQ (consumed, encoded);

  /* Verify all fields match */
  ASSERT_EQ (decoded.udp_payload_size, orig.udp_payload_size);
  ASSERT_EQ (decoded.extended_rcode, orig.extended_rcode);
  ASSERT_EQ (decoded.version, orig.version);
  ASSERT_EQ (decoded.do_bit, orig.do_bit);
  ASSERT_EQ (decoded.z, orig.z);
  ASSERT_EQ (decoded.rdlength, orig.rdlength);
}

/* Test extended RCODE calculation */
TEST (dns_opt_extended_rcode_calc)
{
  SocketDNS_Header hdr;
  SocketDNS_OPT opt;
  uint16_t rcode;

  memset (&hdr, 0, sizeof (hdr));
  memset (&opt, 0, sizeof (opt));

  /* Standard RCODE (no extension) */
  hdr.rcode = 5;  /* REFUSED */
  rcode = SocketDNS_opt_extended_rcode (&hdr, NULL);
  ASSERT_EQ (rcode, 5);

  /* Extended RCODE = 16 (BADVERS) = (1 << 4) | 0 */
  hdr.rcode = 0;
  opt.extended_rcode = 1;
  rcode = SocketDNS_opt_extended_rcode (&hdr, &opt);
  ASSERT_EQ (rcode, 16);

  /* Extended RCODE with both parts set */
  hdr.rcode = 3;  /* NXDOMAIN in lower bits */
  opt.extended_rcode = 2;  /* 2 << 4 = 32 */
  rcode = SocketDNS_opt_extended_rcode (&hdr, &opt);
  ASSERT_EQ (rcode, 35);  /* (2 << 4) | 3 = 32 + 3 */
}

/* ==================== EDNS Option Tests (RFC 6891 §6.1.2) ==================== */

/* Test encode/decode single option */
TEST (dns_edns_option_encode_decode)
{
  SocketDNS_EDNSOption orig, decoded;
  SocketDNS_EDNSOptionIter iter;
  unsigned char data[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
  unsigned char buf[32];
  int encoded;

  /* Set up a COOKIE option (code 10) */
  orig.code = DNS_EDNS_OPT_COOKIE;
  orig.length = 8;
  orig.data = data;

  /* Encode */
  encoded = SocketDNS_edns_option_encode (&orig, buf, sizeof (buf));
  ASSERT_EQ (encoded, 12);  /* 4 (header) + 8 (data) */

  /* Verify wire format */
  ASSERT_EQ (buf[0], 0x00);  /* Code high byte */
  ASSERT_EQ (buf[1], 0x0A);  /* Code low byte (10) */
  ASSERT_EQ (buf[2], 0x00);  /* Length high byte */
  ASSERT_EQ (buf[3], 0x08);  /* Length low byte (8) */
  ASSERT_EQ (memcmp (buf + 4, data, 8), 0);

  /* Decode via iterator */
  SocketDNS_edns_option_iter_init (&iter, buf, (size_t)encoded);
  ASSERT (SocketDNS_edns_option_iter_next (&iter, &decoded) == 1);

  ASSERT_EQ (decoded.code, orig.code);
  ASSERT_EQ (decoded.length, orig.length);
  ASSERT_NOT_NULL (decoded.data);
  ASSERT_EQ (memcmp (decoded.data, data, 8), 0);

  /* No more options */
  ASSERT_EQ (SocketDNS_edns_option_iter_next (&iter, &decoded), 0);
}

/* Test encode/decode multiple options */
TEST (dns_edns_options_multiple)
{
  unsigned char cookie_data[] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 };
  unsigned char padding_data[] = { 0x00, 0x00, 0x00, 0x00 };
  SocketDNS_EDNSOption opts[] = {
    { DNS_EDNS_OPT_COOKIE, 8, cookie_data },
    { DNS_EDNS_OPT_PADDING, 4, padding_data }
  };
  SocketDNS_EDNSOption decoded;
  SocketDNS_EDNSOptionIter iter;
  unsigned char buf[64];
  int encoded;
  int count = 0;

  /* Encode multiple options */
  encoded = SocketDNS_edns_options_encode (opts, 2, buf, sizeof (buf));
  ASSERT_EQ (encoded, 20);  /* (4+8) + (4+4) = 12 + 8 = 20 */

  /* Decode and count options */
  SocketDNS_edns_option_iter_init (&iter, buf, (size_t)encoded);
  while (SocketDNS_edns_option_iter_next (&iter, &decoded))
    {
      if (count == 0)
        {
          ASSERT_EQ (decoded.code, DNS_EDNS_OPT_COOKIE);
          ASSERT_EQ (decoded.length, 8);
        }
      else if (count == 1)
        {
          ASSERT_EQ (decoded.code, DNS_EDNS_OPT_PADDING);
          ASSERT_EQ (decoded.length, 4);
        }
      count++;
    }
  ASSERT_EQ (count, 2);
}

/* Test zero-length option data */
TEST (dns_edns_option_zero_length)
{
  SocketDNS_EDNSOption orig, decoded;
  SocketDNS_EDNSOptionIter iter;
  unsigned char buf[16];
  int encoded;

  /* TCP Keepalive with no data (RFC 7828 - client query form) */
  orig.code = DNS_EDNS_OPT_TCP_KEEPALIVE;
  orig.length = 0;
  orig.data = NULL;

  encoded = SocketDNS_edns_option_encode (&orig, buf, sizeof (buf));
  ASSERT_EQ (encoded, 4);  /* Just header, no data */

  /* Verify wire format */
  ASSERT_EQ (buf[0], 0x00);
  ASSERT_EQ (buf[1], 0x0B);  /* Code 11 */
  ASSERT_EQ (buf[2], 0x00);
  ASSERT_EQ (buf[3], 0x00);  /* Length 0 */

  /* Decode */
  SocketDNS_edns_option_iter_init (&iter, buf, (size_t)encoded);
  ASSERT (SocketDNS_edns_option_iter_next (&iter, &decoded) == 1);
  ASSERT_EQ (decoded.code, DNS_EDNS_OPT_TCP_KEEPALIVE);
  ASSERT_EQ (decoded.length, 0);
  ASSERT_NULL (decoded.data);
}

/* Test find option by code (present) */
TEST (dns_edns_option_find_present)
{
  unsigned char cookie_data[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
  unsigned char nsid_data[] = { 'n', 's', '1' };
  SocketDNS_EDNSOption opts[] = {
    { DNS_EDNS_OPT_NSID, 3, nsid_data },
    { DNS_EDNS_OPT_COOKIE, 8, cookie_data }
  };
  SocketDNS_EDNSOption found;
  unsigned char buf[64];
  int encoded;

  encoded = SocketDNS_edns_options_encode (opts, 2, buf, sizeof (buf));
  ASSERT (encoded > 0);

  /* Find COOKIE (second option) */
  ASSERT (SocketDNS_edns_option_find (buf, (size_t)encoded, DNS_EDNS_OPT_COOKIE, &found) == 1);
  ASSERT_EQ (found.code, DNS_EDNS_OPT_COOKIE);
  ASSERT_EQ (found.length, 8);
  ASSERT_EQ (memcmp (found.data, cookie_data, 8), 0);

  /* Find NSID (first option) */
  ASSERT (SocketDNS_edns_option_find (buf, (size_t)encoded, DNS_EDNS_OPT_NSID, &found) == 1);
  ASSERT_EQ (found.code, DNS_EDNS_OPT_NSID);
  ASSERT_EQ (found.length, 3);
  ASSERT_EQ (memcmp (found.data, nsid_data, 3), 0);
}

/* Test find option by code (not present) */
TEST (dns_edns_option_find_not_present)
{
  unsigned char nsid_data[] = { 'n', 's', '1' };
  SocketDNS_EDNSOption opts[] = {
    { DNS_EDNS_OPT_NSID, 3, nsid_data }
  };
  SocketDNS_EDNSOption found;
  unsigned char buf[32];
  int encoded;

  encoded = SocketDNS_edns_options_encode (opts, 1, buf, sizeof (buf));
  ASSERT (encoded > 0);

  /* Try to find COOKIE (not present) */
  ASSERT_EQ (SocketDNS_edns_option_find (buf, (size_t)encoded, DNS_EDNS_OPT_COOKIE, &found), 0);

  /* Try to find Extended Error (not present) */
  ASSERT_EQ (SocketDNS_edns_option_find (buf, (size_t)encoded, DNS_EDNS_OPT_EXTENDED_ERROR, &found), 0);
}

/* Test iterate over empty RDATA */
TEST (dns_edns_option_iter_empty)
{
  SocketDNS_EDNSOptionIter iter;
  SocketDNS_EDNSOption opt;

  /* NULL RDATA */
  SocketDNS_edns_option_iter_init (&iter, NULL, 0);
  ASSERT_EQ (SocketDNS_edns_option_iter_next (&iter, &opt), 0);

  /* Zero-length RDATA */
  unsigned char buf[1] = { 0 };
  SocketDNS_edns_option_iter_init (&iter, buf, 0);
  ASSERT_EQ (SocketDNS_edns_option_iter_next (&iter, &opt), 0);
}

/* Test iterate over malformed RDATA (truncated header) */
TEST (dns_edns_option_iter_truncated_header)
{
  SocketDNS_EDNSOptionIter iter;
  SocketDNS_EDNSOption opt;
  unsigned char buf[] = { 0x00, 0x0A, 0x00 };  /* Only 3 bytes, need 4 for header */

  SocketDNS_edns_option_iter_init (&iter, buf, sizeof (buf));
  ASSERT_EQ (SocketDNS_edns_option_iter_next (&iter, &opt), 0);
}

/* Test iterate over malformed RDATA (truncated data) */
TEST (dns_edns_option_iter_truncated_data)
{
  SocketDNS_EDNSOptionIter iter;
  SocketDNS_EDNSOption opt;
  /* Header says 8 bytes of data, but only 4 provided */
  unsigned char buf[] = { 0x00, 0x0A, 0x00, 0x08, 0x11, 0x22, 0x33, 0x44 };

  SocketDNS_edns_option_iter_init (&iter, buf, sizeof (buf));
  ASSERT_EQ (SocketDNS_edns_option_iter_next (&iter, &opt), 0);
}

/* Test encode with buffer too small */
TEST (dns_edns_option_encode_buffer_small)
{
  SocketDNS_EDNSOption opt;
  unsigned char data[] = { 0x01, 0x02, 0x03, 0x04 };
  unsigned char buf[4];  /* Too small for 4-byte header + 4-byte data */

  opt.code = DNS_EDNS_OPT_PADDING;
  opt.length = 4;
  opt.data = data;

  ASSERT_EQ (SocketDNS_edns_option_encode (&opt, buf, sizeof (buf)), -1);
}

/* Test encode with data NULL but length > 0 */
TEST (dns_edns_option_encode_null_data)
{
  SocketDNS_EDNSOption opt;
  unsigned char buf[32];

  opt.code = DNS_EDNS_OPT_PADDING;
  opt.length = 4;  /* Says 4 bytes, but... */
  opt.data = NULL; /* No data pointer */

  ASSERT_EQ (SocketDNS_edns_option_encode (&opt, buf, sizeof (buf)), -1);
}

/* Test encode empty array */
TEST (dns_edns_options_encode_empty)
{
  unsigned char buf[32];
  int encoded;

  /* Empty array (NULL) */
  encoded = SocketDNS_edns_options_encode (NULL, 0, buf, sizeof (buf));
  ASSERT_EQ (encoded, 0);

  /* Count = 0 */
  SocketDNS_EDNSOption opts[1] = { { 0, 0, NULL } };
  encoded = SocketDNS_edns_options_encode (opts, 0, buf, sizeof (buf));
  ASSERT_EQ (encoded, 0);
}

/* Test NULL pointer handling */
TEST (dns_edns_option_null_handling)
{
  SocketDNS_EDNSOption opt;
  SocketDNS_EDNSOptionIter iter;
  unsigned char buf[32];

  memset (&opt, 0, sizeof (opt));
  memset (buf, 0, sizeof (buf));

  ASSERT_EQ (SocketDNS_edns_option_encode (NULL, buf, sizeof (buf)), -1);
  ASSERT_EQ (SocketDNS_edns_option_encode (&opt, NULL, 32), -1);

  /* iter_init with NULL should not crash */
  SocketDNS_edns_option_iter_init (NULL, buf, 32);
  SocketDNS_edns_option_iter_init (&iter, NULL, 32);

  /* iter_next with NULL should return 0 */
  ASSERT_EQ (SocketDNS_edns_option_iter_next (NULL, &opt), 0);
  ASSERT_EQ (SocketDNS_edns_option_iter_next (&iter, NULL), 0);

  /* find with NULL should return 0 */
  ASSERT_EQ (SocketDNS_edns_option_find (buf, 32, DNS_EDNS_OPT_COOKIE, NULL), 0);
}

/* Test option codes enum values */
TEST (dns_edns_option_codes)
{
  /* Verify known option codes match IANA registry */
  ASSERT_EQ (DNS_EDNS_OPT_RESERVED, 0);
  ASSERT_EQ (DNS_EDNS_OPT_NSID, 3);
  ASSERT_EQ (DNS_EDNS_OPT_CLIENT_SUBNET, 8);
  ASSERT_EQ (DNS_EDNS_OPT_COOKIE, 10);
  ASSERT_EQ (DNS_EDNS_OPT_TCP_KEEPALIVE, 11);
  ASSERT_EQ (DNS_EDNS_OPT_PADDING, 12);
  ASSERT_EQ (DNS_EDNS_OPT_EXTENDED_ERROR, 15);
  ASSERT_EQ (DNS_EDNS_OPT_LOCAL_MIN, 65001);
  ASSERT_EQ (DNS_EDNS_OPT_LOCAL_MAX, 65534);
  ASSERT_EQ (DNS_EDNS_OPT_RESERVED_MAX, 65535);
}

/* Test roundtrip with known wire data */
TEST (dns_edns_option_roundtrip_wire)
{
  /* Manually crafted EDNS options (two options):
   * Option 1: NSID (3), length 4, data "ns42"
   * Option 2: Padding (12), length 2, data 0x00 0x00
   */
  unsigned char wire[] = {
    0x00, 0x03,             /* Code: NSID (3) */
    0x00, 0x04,             /* Length: 4 */
    'n', 's', '4', '2',     /* Data: "ns42" */
    0x00, 0x0C,             /* Code: Padding (12) */
    0x00, 0x02,             /* Length: 2 */
    0x00, 0x00              /* Data: padding bytes */
  };
  SocketDNS_EDNSOption opt;
  SocketDNS_EDNSOptionIter iter;
  int count = 0;

  SocketDNS_edns_option_iter_init (&iter, wire, sizeof (wire));

  while (SocketDNS_edns_option_iter_next (&iter, &opt))
    {
      if (count == 0)
        {
          ASSERT_EQ (opt.code, DNS_EDNS_OPT_NSID);
          ASSERT_EQ (opt.length, 4);
          ASSERT_EQ (memcmp (opt.data, "ns42", 4), 0);
        }
      else if (count == 1)
        {
          ASSERT_EQ (opt.code, DNS_EDNS_OPT_PADDING);
          ASSERT_EQ (opt.length, 2);
        }
      count++;
    }

  ASSERT_EQ (count, 2);
}

/* Test large option encoding/decoding */
TEST (dns_edns_option_large_data)
{
  unsigned char data[256];
  unsigned char buf[300];
  SocketDNS_EDNSOption opt, decoded;
  SocketDNS_EDNSOptionIter iter;
  int encoded;
  size_t i;

  /* Fill with pattern */
  for (i = 0; i < sizeof (data); i++)
    data[i] = (unsigned char)(i & 0xFF);

  opt.code = DNS_EDNS_OPT_CLIENT_SUBNET;
  opt.length = 256;
  opt.data = data;

  encoded = SocketDNS_edns_option_encode (&opt, buf, sizeof (buf));
  ASSERT_EQ (encoded, 260);  /* 4 + 256 */

  SocketDNS_edns_option_iter_init (&iter, buf, (size_t)encoded);
  ASSERT (SocketDNS_edns_option_iter_next (&iter, &decoded) == 1);
  ASSERT_EQ (decoded.code, DNS_EDNS_OPT_CLIENT_SUBNET);
  ASSERT_EQ (decoded.length, 256);
  ASSERT_EQ (memcmp (decoded.data, data, 256), 0);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
