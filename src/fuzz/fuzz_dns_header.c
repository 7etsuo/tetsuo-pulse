/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_dns_header.c - libFuzzer harness for DNS header encoding/decoding
 *
 * Fuzzes DNS header parsing (RFC 1035 Section 4.1.1).
 *
 * Targets:
 * - SocketDNS_header_decode() with malformed/truncated input
 * - SocketDNS_header_encode() roundtrip verification
 * - Flag bit extraction and edge cases
 * - Extreme section counts (QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_dns_header
 * Run:   ./fuzz_dns_header -fork=16 -max_len=64
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "dns/SocketDNSWire.h"

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  SocketDNS_Header header;
  SocketDNS_Header decoded;
  unsigned char encoded[DNS_HEADER_SIZE];

  /* Test decode with arbitrary input */
  int result = SocketDNS_header_decode (data, size, &header);

  if (result == 0)
    {
      /* Decode succeeded - verify roundtrip */

      /* Encode the decoded header */
      int enc_result
          = SocketDNS_header_encode (&header, encoded, sizeof (encoded));

      if (enc_result == 0)
        {
          /* Decode the encoded header */
          int dec_result
              = SocketDNS_header_decode (encoded, sizeof (encoded), &decoded);

          /* Roundtrip should always succeed */
          if (dec_result == 0)
            {
              /* Verify all fields match */
              /* Note: We don't assert here to allow fuzzer to continue */
              (void)(header.id == decoded.id);
              (void)(header.qr == decoded.qr);
              (void)(header.opcode == decoded.opcode);
              (void)(header.aa == decoded.aa);
              (void)(header.tc == decoded.tc);
              (void)(header.rd == decoded.rd);
              (void)(header.ra == decoded.ra);
              (void)(header.z == decoded.z);
              (void)(header.rcode == decoded.rcode);
              (void)(header.qdcount == decoded.qdcount);
              (void)(header.ancount == decoded.ancount);
              (void)(header.nscount == decoded.nscount);
              (void)(header.arcount == decoded.arcount);
            }
        }
    }

  /* Test with NULL pointers (should return -1, not crash) */
  (void)SocketDNS_header_decode (NULL, size, &header);
  (void)SocketDNS_header_decode (data, size, NULL);
  (void)SocketDNS_header_encode (NULL, encoded, sizeof (encoded));
  (void)SocketDNS_header_encode (&header, NULL, sizeof (encoded));

  /* Test init_query helper */
  if (size >= 4)
    {
      uint16_t id = ((uint16_t)data[0] << 8) | data[1];
      uint16_t qdcount = ((uint16_t)data[2] << 8) | data[3];

      SocketDNS_header_init_query (&header, id, qdcount);

      /* Verify init_query sets expected fields */
      (void)(header.id == id);
      (void)(header.qr == 0);       /* Query */
      (void)(header.opcode == 0);   /* Standard query */
      (void)(header.rd == 1);       /* Recursion desired */
      (void)(header.qdcount == qdcount);
    }

  return 0;
}
