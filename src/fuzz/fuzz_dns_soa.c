/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_dns_soa.c - libFuzzer harness for DNS SOA record parsing
 *
 * Fuzzes SOA record parsing and negative TTL extraction (RFC 1035 §3.3.13,
 * RFC 2308).
 *
 * Targets:
 * - SocketDNS_rdata_parse_soa() - SOA record parsing
 * - SocketDNS_extract_negative_ttl() - Negative cache TTL extraction
 *
 * Critical test cases:
 * - Compression pointers in MNAME/RNAME
 * - Insufficient space after names for fixed fields (20 bytes)
 * - RDATA exactly at message boundary
 * - Pointer loops in MNAME or RNAME
 * - Large/small timing values (SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM)
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_dns_soa
 * Run:   ./fuzz_dns_soa -fork=16 -max_len=4096
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "dns/SocketDNSWire.h"

/* Maximum RRs to process */
#define MAX_RRS 64

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  SocketDNS_Header header;
  SocketDNS_Question question;
  SocketDNS_RR rr;
  SocketDNS_SOA soa;
  size_t offset;
  size_t consumed;

  /* Need at least a header */
  if (size < DNS_HEADER_SIZE)
    return 0;

  /* Parse header */
  if (SocketDNS_header_decode (data, size, &header) != 0)
    return 0;

  offset = DNS_HEADER_SIZE;

  /*
   * Skip question section
   */
  int qdcount = header.qdcount;
  if (qdcount > MAX_RRS)
    qdcount = MAX_RRS;

  for (int i = 0; i < qdcount && offset < size; i++)
    {
      consumed = 0;
      if (SocketDNS_question_decode (data, size, offset, &question, &consumed)
          != 0)
        break;
      offset += consumed;
    }

  /*
   * Parse RRs looking for SOA records.
   * SOA typically appears in:
   * - Answer section for SOA queries
   * - Authority section for NXDOMAIN/NODATA (negative responses)
   */
  int total_rrs = header.ancount + header.nscount + header.arcount;
  if (total_rrs > MAX_RRS)
    total_rrs = MAX_RRS;

  for (int i = 0; i < total_rrs && offset < size; i++)
    {
      consumed = 0;
      if (SocketDNS_rr_decode (data, size, offset, &rr, &consumed) != 0)
        break;

      if (rr.type == DNS_TYPE_SOA)
        {
          /* Parse SOA record */
          memset (&soa, 0, sizeof (soa));
          int result = SocketDNS_rdata_parse_soa (data, size, &rr, &soa);

          if (result == 0)
            {
              /* Verify parsed fields are accessible */
              (void)soa.mname[0];
              (void)soa.rname[0];
              (void)soa.serial;
              (void)soa.refresh;
              (void)soa.retry;
              (void)soa.expire;
              (void)soa.minimum;
            }
        }

      offset += consumed;
    }

  /*
   * Test negative TTL extraction directly.
   * This scans the authority section for SOA and calculates
   * TTL = min(SOA_RR_TTL, SOA.MINIMUM) per RFC 2308.
   */
  memset (&soa, 0, sizeof (soa));
  uint32_t neg_ttl = SocketDNS_extract_negative_ttl (data, size, &soa);
  (void)neg_ttl;

  /* Test with NULL soa_out parameter */
  neg_ttl = SocketDNS_extract_negative_ttl (data, size, NULL);
  (void)neg_ttl;

  /*
   * Test SOA parsing with synthetic RRs.
   * Construct an RR structure pointing into the fuzz input.
   */
  if (size >= DNS_HEADER_SIZE + 20)
    {
      /* Fake an SOA RR pointing to data after header */
      rr.type = DNS_TYPE_SOA;
      rr.rclass = DNS_CLASS_IN;
      rr.ttl = 3600;
      rr.rdlength = size - DNS_HEADER_SIZE;
      rr.rdata = data + DNS_HEADER_SIZE;

      memset (&soa, 0, sizeof (soa));
      int result = SocketDNS_rdata_parse_soa (data, size, &rr, &soa);
      (void)result;
    }

  /*
   * Test edge cases with various RDLENGTH values
   */
  if (size >= DNS_HEADER_SIZE + DNS_SOA_FIXED_SIZE)
    {
      for (size_t rdlen = 0; rdlen <= size - DNS_HEADER_SIZE && rdlen <= 512;
           rdlen += 7)
        {
          rr.type = DNS_TYPE_SOA;
          rr.rclass = DNS_CLASS_IN;
          rr.ttl = 3600;
          rr.rdlength = rdlen;
          rr.rdata = (rdlen > 0) ? (data + DNS_HEADER_SIZE) : NULL;

          memset (&soa, 0, sizeof (soa));
          int result = SocketDNS_rdata_parse_soa (data, size, &rr, &soa);
          (void)result;
        }
    }

  /*
   * Test with malformed RR structures
   */
  if (size >= 4)
    {
      /* RR with type not SOA (should be rejected) */
      rr.type = DNS_TYPE_A;
      rr.rdlength = size;
      rr.rdata = data;
      memset (&soa, 0, sizeof (soa));
      int result = SocketDNS_rdata_parse_soa (data, size, &rr, &soa);
      (void)result;

      /* RR with wrong class */
      rr.type = DNS_TYPE_SOA;
      rr.rclass = DNS_CLASS_CH;
      result = SocketDNS_rdata_parse_soa (data, size, &rr, &soa);
      (void)result;
    }

  /*
   * Test with NULL pointers
   */
  (void)SocketDNS_rdata_parse_soa (NULL, size, &rr, &soa);
  (void)SocketDNS_rdata_parse_soa (data, size, NULL, &soa);
  (void)SocketDNS_rdata_parse_soa (data, size, &rr, NULL);
  (void)SocketDNS_extract_negative_ttl (NULL, size, &soa);

  return 0;
}
