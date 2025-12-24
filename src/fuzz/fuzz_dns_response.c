/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_dns_response.c - libFuzzer harness for complete DNS response parsing
 *
 * Fuzzes the full DNS response parsing chain (RFC 1035).
 *
 * Targets:
 * - SocketDNS_header_decode()
 * - SocketDNS_question_decode()
 * - SocketDNS_rr_decode()
 * - SocketDNS_rdata_parse_a/aaaa/cname()
 * - SocketDNS_rr_skip()
 *
 * Test cases:
 * - Complete DNS response parsing
 * - Mismatched section counts
 * - Truncated RRs at various points
 * - RDATA type/length mismatches
 * - All RR types (A, AAAA, CNAME, SOA, OPT)
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_dns_response
 * Run:   ./fuzz_dns_response -fork=16 -max_len=4096
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "dns/SocketDNSWire.h"

/* Maximum message size to fuzz */
#define MAX_FUZZ_MSG_SIZE 65535

/* Maximum RRs to parse per section (prevent DoS from huge counts) */
#define MAX_RRS_PER_SECTION 256

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  SocketDNS_Header header;
  SocketDNS_Question question;
  SocketDNS_RR rr;
  size_t offset;
  size_t consumed;

  /* Need at least a header */
  if (size < DNS_HEADER_SIZE)
    return 0;

  /* Cap size */
  if (size > MAX_FUZZ_MSG_SIZE)
    size = MAX_FUZZ_MSG_SIZE;

  /* Parse header */
  if (SocketDNS_header_decode (data, size, &header) != 0)
    return 0;

  offset = DNS_HEADER_SIZE;

  /*
   * Parse question section
   * Cap to prevent DoS from huge qdcount
   */
  int qdcount = header.qdcount;
  if (qdcount > MAX_RRS_PER_SECTION)
    qdcount = MAX_RRS_PER_SECTION;

  for (int i = 0; i < qdcount && offset < size; i++)
    {
      consumed = 0;
      if (SocketDNS_question_decode (data, size, offset, &question, &consumed)
          != 0)
        break;
      offset += consumed;
    }

  /*
   * Parse answer section
   */
  int ancount = header.ancount;
  if (ancount > MAX_RRS_PER_SECTION)
    ancount = MAX_RRS_PER_SECTION;

  for (int i = 0; i < ancount && offset < size; i++)
    {
      consumed = 0;
      if (SocketDNS_rr_decode (data, size, offset, &rr, &consumed) != 0)
        break;

      /* Parse type-specific RDATA */
      switch (rr.type)
        {
        case DNS_TYPE_A:
          {
            struct in_addr addr;
            (void)SocketDNS_rdata_parse_a (&rr, &addr);
            break;
          }
        case DNS_TYPE_AAAA:
          {
            struct in6_addr addr;
            (void)SocketDNS_rdata_parse_aaaa (&rr, &addr);
            break;
          }
        case DNS_TYPE_CNAME:
          {
            char cname[DNS_MAX_NAME_LEN];
            (void)SocketDNS_rdata_parse_cname (data, size, &rr, cname,
                                               sizeof (cname));
            break;
          }
        case DNS_TYPE_SOA:
          {
            SocketDNS_SOA soa;
            (void)SocketDNS_rdata_parse_soa (data, size, &rr, &soa);
            break;
          }
        default:
          /* Skip unknown types */
          break;
        }

      offset += consumed;
    }

  /*
   * Parse authority section
   */
  int nscount = header.nscount;
  if (nscount > MAX_RRS_PER_SECTION)
    nscount = MAX_RRS_PER_SECTION;

  for (int i = 0; i < nscount && offset < size; i++)
    {
      consumed = 0;
      if (SocketDNS_rr_decode (data, size, offset, &rr, &consumed) != 0)
        break;

      /* SOA records commonly appear in authority section */
      if (rr.type == DNS_TYPE_SOA)
        {
          SocketDNS_SOA soa;
          (void)SocketDNS_rdata_parse_soa (data, size, &rr, &soa);
        }

      offset += consumed;
    }

  /*
   * Parse additional section
   * Look for OPT records (EDNS0)
   */
  int arcount = header.arcount;
  if (arcount > MAX_RRS_PER_SECTION)
    arcount = MAX_RRS_PER_SECTION;

  for (int i = 0; i < arcount && offset < size; i++)
    {
      consumed = 0;
      if (SocketDNS_rr_decode (data, size, offset, &rr, &consumed) != 0)
        break;

      /* OPT record has special parsing */
      if (rr.type == DNS_TYPE_OPT)
        {
          /* OPT record parsing is done separately via SocketDNS_opt_decode */
          /* Here we just verify the RR parsing doesn't crash */
        }

      offset += consumed;
    }

  /*
   * Test rr_skip function
   * Restart from beginning and skip all RRs
   */
  offset = DNS_HEADER_SIZE;

  /* Skip questions */
  for (int i = 0; i < qdcount && offset < size; i++)
    {
      consumed = 0;
      if (SocketDNS_question_decode (data, size, offset, &question, &consumed)
          != 0)
        break;
      offset += consumed;
    }

  /* Skip all RRs using rr_skip */
  int total_rrs = ancount + nscount + arcount;
  if (total_rrs > MAX_RRS_PER_SECTION * 3)
    total_rrs = MAX_RRS_PER_SECTION * 3;

  for (int i = 0; i < total_rrs && offset < size; i++)
    {
      consumed = 0;
      if (SocketDNS_rr_skip (data, size, offset, &consumed) != 0)
        break;
      offset += consumed;
    }

  /*
   * Test negative TTL extraction (RFC 2308)
   * This scans authority section for SOA
   */
  SocketDNS_SOA soa;
  uint32_t neg_ttl = SocketDNS_extract_negative_ttl (data, size, &soa);
  (void)neg_ttl;

  /* Test with NULL soa_out (should still work) */
  neg_ttl = SocketDNS_extract_negative_ttl (data, size, NULL);
  (void)neg_ttl;

  /*
   * Test OPT record counting
   */
  int opt_count = SocketDNS_response_count_opt (data, size, &header);
  (void)opt_count;

  return 0;
}
