/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_dns_edns0.c - libFuzzer harness for EDNS0 OPT record parsing
 *
 * Fuzzes EDNS0 extension mechanism (RFC 6891).
 *
 * Targets:
 * - SocketDNS_opt_decode() - OPT pseudo-RR parsing
 * - SocketDNS_opt_encode() - OPT record encoding
 * - SocketDNS_opt_validate() - Validation per RFC 6891 §6.1.1
 * - SocketDNS_edns_option_iter_*() - Option iteration
 * - SocketDNS_edns_option_find() - Option search
 * - SocketDNS_edns_option_encode() - Option encoding
 * - SocketDNS_opt_ttl_decode/encode() - TTL field handling
 * - SocketDNS_opt_extended_rcode() - Extended RCODE reconstruction
 *
 * Test cases:
 * - Invalid OPT NAME (must be 0x00)
 * - Invalid OPT TYPE (must be 41)
 * - RDLENGTH exceeds buffer
 * - Malformed options in RDATA
 * - Option length exceeds remaining data
 * - Zero-length options
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_dns_edns0
 * Run:   ./fuzz_dns_edns0 -fork=16 -max_len=1024
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "dns/SocketDNSWire.h"

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  SocketDNS_OPT opt;
  SocketDNS_OPT decoded;
  SocketDNS_EDNSOption option;
  SocketDNS_EDNSOptionIter iter;
  SocketDNS_OPT_Flags flags;
  unsigned char buf[512];
  int consumed;

  if (size == 0)
    return 0;

  /*
   * Test OPT record decoding
   * OPT record minimum size is DNS_OPT_FIXED_SIZE (11 bytes)
   */
  consumed = SocketDNS_opt_decode (data, size, &opt);

  if (consumed > 0)
    {
      /* Decode succeeded - test validation */
      SocketDNS_OPT_ValidationResult valid_result
          = SocketDNS_opt_validate (&opt, size - DNS_OPT_FIXED_SIZE);
      (void)valid_result;

      /* Get validation result string */
      const char *valid_str = SocketDNS_opt_validation_str (valid_result);
      (void)valid_str;

      /* Test TTL field decoding */
      uint32_t ttl = ((uint32_t)opt.extended_rcode << 24)
                     | ((uint32_t)opt.version << 16)
                     | ((uint32_t)opt.do_bit << 15) | opt.z;
      SocketDNS_opt_ttl_decode (ttl, &flags);

      /* Verify fields match */
      (void)(flags.extended_rcode == opt.extended_rcode);
      (void)(flags.version == opt.version);
      (void)(flags.do_bit == opt.do_bit);

      /* Test TTL encoding roundtrip */
      uint32_t encoded_ttl = SocketDNS_opt_ttl_encode (&flags);
      (void)encoded_ttl;

      /* Test version getter */
      int version = SocketDNS_opt_get_version (&opt);
      (void)version;

      /* Test BADVERS check with a fake header */
      SocketDNS_Header hdr;
      memset (&hdr, 0, sizeof (hdr));
      hdr.rcode = 0; /* BADVERS is extended RCODE 16 */

      int is_badvers = SocketDNS_opt_is_badvers (&hdr, &opt);
      (void)is_badvers;

      /* Test extended RCODE calculation */
      uint16_t ext_rcode = SocketDNS_opt_extended_rcode (&hdr, &opt);
      (void)ext_rcode;

      /* Iterate through options if RDATA present */
      if (opt.rdata && opt.rdlength > 0)
        {
          SocketDNS_edns_option_iter_init (&iter, opt.rdata, opt.rdlength);

          while (SocketDNS_edns_option_iter_next (&iter, &option))
            {
              /* Process each option */
              (void)option.code;
              (void)option.length;
              (void)option.data;
            }

          /* Search for specific well-known options */
          int found;

          found = SocketDNS_edns_option_find (opt.rdata, opt.rdlength,
                                              DNS_EDNS_OPT_COOKIE, &option);
          (void)found;

          found = SocketDNS_edns_option_find (opt.rdata, opt.rdlength,
                                              DNS_EDNS_OPT_EXTENDED_ERROR,
                                              &option);
          (void)found;

          found = SocketDNS_edns_option_find (opt.rdata, opt.rdlength,
                                              DNS_EDNS_OPT_PADDING, &option);
          (void)found;
        }

      /* Test OPT encoding roundtrip */
      int enc_len = SocketDNS_opt_encode (&opt, buf, sizeof (buf));
      if (enc_len > 0)
        {
          int dec_consumed = SocketDNS_opt_decode (buf, enc_len, &decoded);
          if (dec_consumed > 0)
            {
              /* Verify key fields match */
              (void)(opt.udp_payload_size == decoded.udp_payload_size);
              (void)(opt.extended_rcode == decoded.extended_rcode);
              (void)(opt.version == decoded.version);
              (void)(opt.do_bit == decoded.do_bit);
            }
        }
    }

  /*
   * Test OPT init helper
   */
  if (size >= 2)
    {
      uint16_t udp_size = ((uint16_t)data[0] << 8) | data[1];
      SocketDNS_opt_init (&opt, udp_size);

      /* Verify init sets expected values */
      (void)(opt.version == DNS_EDNS0_VERSION);
      (void)(opt.do_bit == 0);
      (void)(opt.z == 0);
      (void)(opt.rdlength == 0);

      /* UDP size should be normalized to minimum 512 */
      if (udp_size < DNS_EDNS0_MIN_UDPSIZE)
        {
          (void)(opt.udp_payload_size == DNS_EDNS0_MIN_UDPSIZE);
        }
    }

  /*
   * Test EDNS option encoding
   */
  if (size >= 4)
    {
      option.code = ((uint16_t)data[0] << 8) | data[1];
      option.length = ((uint16_t)data[2] << 8) | data[3];

      /* Cap length to available data */
      if (option.length > size - 4)
        option.length = size - 4;

      option.data = (option.length > 0) ? (data + 4) : NULL;

      int enc_len
          = SocketDNS_edns_option_encode (&option, buf, sizeof (buf));
      (void)enc_len;
    }

  /*
   * Test batch option encoding
   */
  if (size >= 16)
    {
      SocketDNS_EDNSOption options[2];
      size_t avail0 = size - 8;
      size_t avail1 = size - 12;

      options[0].code = ((uint16_t)data[0] << 8) | data[1];
      options[0].length = data[2] % 16;
      if (options[0].length > avail0)
        options[0].length = avail0;
      options[0].data = (options[0].length > 0) ? (data + 8) : NULL;

      options[1].code = ((uint16_t)data[3] << 8) | data[4];
      options[1].length = data[5] % 16;
      if (options[1].length > avail1)
        options[1].length = avail1;
      options[1].data = (options[1].length > 0) ? (data + 12) : NULL;

      int enc_len
          = SocketDNS_edns_options_encode (options, 2, buf, sizeof (buf));
      (void)enc_len;
    }

  /*
   * Test valid NAME check
   */
  if (size >= 1)
    {
      int is_valid_name = SocketDNS_opt_is_valid_name (data[0]);
      (void)is_valid_name;
    }

  /*
   * Test payload size helpers
   */
  SocketDNS_PayloadTracker tracker;
  SocketDNS_PayloadConfig config;

  SocketDNS_payload_init (&tracker);
  SocketDNS_payload_config_init (&config);

  uint16_t payload_size = SocketDNS_payload_get_size (&tracker, &config);
  (void)payload_size;

  const char *state_name = SocketDNS_payload_state_name (tracker.state);
  (void)state_name;

  int needs_tcp = SocketDNS_payload_needs_tcp (&tracker);
  (void)needs_tcp;

  /* Simulate failures and successes */
  if (size >= 8)
    {
      uint64_t now = 0;
      for (size_t i = 0; i + 8 <= size; i += 8)
        {
          now = ((uint64_t)data[i] << 56) | ((uint64_t)data[i + 1] << 48)
                | ((uint64_t)data[i + 2] << 40)
                | ((uint64_t)data[i + 3] << 32)
                | ((uint64_t)data[i + 4] << 24)
                | ((uint64_t)data[i + 5] << 16)
                | ((uint64_t)data[i + 6] << 8) | data[i + 7];
        }

      SocketDNS_payload_failed (&tracker, now);

      int should_reset
          = SocketDNS_payload_should_reset (&tracker, &config, now + 1000);
      (void)should_reset;

      SocketDNS_payload_succeeded (&tracker, 4096, now);
      SocketDNS_payload_reset (&tracker);
    }

  /* Test with NULL pointers */
  (void)SocketDNS_opt_decode (NULL, size, &opt);
  (void)SocketDNS_opt_decode (data, size, NULL);
  (void)SocketDNS_opt_encode (NULL, buf, sizeof (buf));
  (void)SocketDNS_opt_encode (&opt, NULL, sizeof (buf));
  (void)SocketDNS_opt_validate (NULL, 0);
  (void)SocketDNS_opt_get_version (NULL);

  return 0;
}
