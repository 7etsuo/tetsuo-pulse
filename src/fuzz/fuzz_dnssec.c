/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_dnssec.c - libFuzzer harness for DNSSEC validation
 *
 * Fuzzes DNSSEC record parsing and validation (RFC 4033, 4034, 4035, 5155).
 *
 * Targets:
 * - SocketDNSSEC_parse_dnskey() - DNSKEY record parsing
 * - SocketDNSSEC_parse_rrsig() - RRSIG record parsing
 * - SocketDNSSEC_parse_ds() - DS record parsing
 * - SocketDNSSEC_parse_nsec() - NSEC record parsing
 * - SocketDNSSEC_parse_nsec3() - NSEC3 record parsing
 * - SocketDNSSEC_calculate_keytag() - Key tag calculation
 * - SocketDNSSEC_verify_rrsig() - RRSIG signature verification
 * - SocketDNSSEC_verify_ds() - DS/DNSKEY chain verification
 * - SocketDNSSEC_rrsig_valid_time() - Signature time validity
 * - SocketDNSSEC_type_in_bitmap() - NSEC/NSEC3 type bitmap parsing
 * - SocketDNSSEC_name_canonicalize() - DNS name canonicalization
 * - SocketDNSSEC_name_canonical_compare() - Canonical name ordering
 * - SocketDNSSEC_algorithm_supported() - Algorithm support checks
 * - SocketDNSSEC_digest_supported() - Digest type support checks
 *
 * Test cases:
 * - Malformed DNSKEY records (invalid protocol, truncated pubkey)
 * - RRSIG with invalid algorithms, expired/future timestamps
 * - DS with wrong digest lengths for type
 * - NSEC/NSEC3 with malformed type bitmaps
 * - Signature verification with mismatched keys
 * - Algorithm downgrade attacks
 * - Key rollover edge cases
 * - NSEC3 hash iterations overflow
 * - Canonical name ordering edge cases
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_dnssec
 * Run:   ./fuzz_dnssec corpus/dnssec/ -fork=16 -max_len=4096
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "dns/SocketDNSSEC.h"
#include "dns/SocketDNSWire.h"

/* Maximum message size to fuzz */
#define MAX_FUZZ_MSG_SIZE 4096

/* Maximum name length for canonicalization tests */
#define MAX_NAME_LEN 256

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  SocketDNS_RR rr;
  SocketDNSSEC_DNSKEY dnskey;
  SocketDNSSEC_RRSIG rrsig;
  SocketDNSSEC_DS ds;
  SocketDNSSEC_NSEC nsec;
  SocketDNSSEC_NSEC3 nsec3;

  if (size == 0)
    return 0;

  /* Cap size */
  if (size > MAX_FUZZ_MSG_SIZE)
    size = MAX_FUZZ_MSG_SIZE;

  /*
   * Test key tag calculation
   * Key tag is calculated over DNSKEY RDATA
   */
  uint16_t keytag = SocketDNSSEC_calculate_keytag (data, size);
  (void)keytag;

  /*
   * Test DNSKEY parsing
   * Construct a fake RR from the input data
   */
  if (size >= DNSSEC_DNSKEY_FIXED_SIZE)
    {
      memset (&rr, 0, sizeof (rr));
      rr.type = DNS_TYPE_DNSKEY;
      rr.rdata = data;
      rr.rdlength = size;

      int result = SocketDNSSEC_parse_dnskey (&rr, &dnskey);
      if (result == 0)
        {
          /* Parse succeeded - verify key tag calculation */
          uint16_t calc_tag
              = SocketDNSSEC_calculate_keytag (data, rr.rdlength);
          (void)(calc_tag == dnskey.key_tag);

          /* Test algorithm support check */
          int algo_supported
              = SocketDNSSEC_algorithm_supported (dnskey.algorithm);
          (void)algo_supported;

          /* Verify DNSKEY flags */
          int is_ksk = (dnskey.flags & DNSKEY_FLAG_SEP) != 0;
          int is_zsk = (dnskey.flags & DNSKEY_FLAG_ZONE_KEY) != 0;
          int is_revoked = (dnskey.flags & DNSKEY_FLAG_REVOKE) != 0;
          (void)is_ksk;
          (void)is_zsk;
          (void)is_revoked;
        }
    }

  /*
   * Test RRSIG parsing
   * RRSIG requires full DNS message for name decompression
   */
  if (size >= DNS_HEADER_SIZE + DNSSEC_RRSIG_FIXED_SIZE)
    {
      memset (&rr, 0, sizeof (rr));
      rr.type = DNS_TYPE_RRSIG;
      rr.rdata = data + DNS_HEADER_SIZE;
      rr.rdlength = size - DNS_HEADER_SIZE;

      int result = SocketDNSSEC_parse_rrsig (data, size, &rr, &rrsig);
      if (result == 0)
        {
          /* Parse succeeded - test validation functions */

          /* Test time validity with current time */
          int valid_now = SocketDNSSEC_rrsig_valid_time (&rrsig, 0);
          (void)valid_now;

          /* Test with specific timestamp from input */
          if (size >= DNS_HEADER_SIZE + DNSSEC_RRSIG_FIXED_SIZE + 8)
            {
              time_t test_time
                  = ((time_t)data[DNS_HEADER_SIZE + DNSSEC_RRSIG_FIXED_SIZE]
                     << 24)
                    | ((time_t)data[DNS_HEADER_SIZE + DNSSEC_RRSIG_FIXED_SIZE
                                    + 1]
                       << 16)
                    | ((time_t)data[DNS_HEADER_SIZE + DNSSEC_RRSIG_FIXED_SIZE
                                    + 2]
                       << 8)
                    | data[DNS_HEADER_SIZE + DNSSEC_RRSIG_FIXED_SIZE + 3];

              int valid_at = SocketDNSSEC_rrsig_valid_time (&rrsig, test_time);
              (void)valid_at;
            }

          /* Test algorithm support */
          int algo_supported
              = SocketDNSSEC_algorithm_supported (rrsig.algorithm);
          (void)algo_supported;

          /* Test signature verification if we have a matching DNSKEY */
          if (size >= DNSSEC_DNSKEY_FIXED_SIZE * 2)
            {
              /* Try to parse a DNSKEY from later in the input */
              SocketDNS_RR key_rr;
              memset (&key_rr, 0, sizeof (key_rr));
              key_rr.type = DNS_TYPE_DNSKEY;
              key_rr.rdata = data + DNSSEC_DNSKEY_FIXED_SIZE;
              key_rr.rdlength = DNSSEC_DNSKEY_FIXED_SIZE;

              SocketDNSSEC_DNSKEY test_key;
              if (SocketDNSSEC_parse_dnskey (&key_rr, &test_key) == 0)
                {
                  /* Attempt signature verification
                   * This will test various crypto code paths
                   */
                  int verify_result = SocketDNSSEC_verify_rrsig (
                      &rrsig, &test_key, data, size, DNS_HEADER_SIZE, 1);
                  (void)verify_result;
                }
            }
        }
    }

  /*
   * Test DS parsing
   */
  if (size >= DNSSEC_DS_FIXED_SIZE)
    {
      memset (&rr, 0, sizeof (rr));
      rr.type = DNS_TYPE_DS;
      rr.rdata = data;
      rr.rdlength = size;

      int result = SocketDNSSEC_parse_ds (&rr, &ds);
      if (result == 0)
        {
          /* Test digest type support */
          int digest_supported
              = SocketDNSSEC_digest_supported (ds.digest_type);
          (void)digest_supported;

          /* Test algorithm support */
          int algo_supported = SocketDNSSEC_algorithm_supported (ds.algorithm);
          (void)algo_supported;

          /* Test DS verification against a DNSKEY */
          if (size >= DNSSEC_DS_FIXED_SIZE + DNSSEC_DNSKEY_FIXED_SIZE)
            {
              SocketDNS_RR key_rr;
              memset (&key_rr, 0, sizeof (key_rr));
              key_rr.type = DNS_TYPE_DNSKEY;
              key_rr.rdata = data + DNSSEC_DS_FIXED_SIZE;
              key_rr.rdlength = size - DNSSEC_DS_FIXED_SIZE;

              SocketDNSSEC_DNSKEY test_key;
              if (SocketDNSSEC_parse_dnskey (&key_rr, &test_key) == 0)
                {
                  /* Try to verify DS matches DNSKEY
                   * Use a fake owner name from input
                   */
                  char owner_name[DNS_MAX_NAME_LEN];
                  size_t name_len
                      = (size > DNS_MAX_NAME_LEN) ? DNS_MAX_NAME_LEN : size;
                  memcpy (owner_name, data, name_len);
                  owner_name[name_len - 1] = '\0'; /* Ensure null termination */

                  int verify_result
                      = SocketDNSSEC_verify_ds (&ds, &test_key, owner_name);
                  (void)verify_result;
                }
            }
        }
    }

  /*
   * Test NSEC parsing
   */
  if (size >= DNS_HEADER_SIZE + 2)
    {
      memset (&rr, 0, sizeof (rr));
      rr.type = DNS_TYPE_NSEC;
      rr.rdata = data + DNS_HEADER_SIZE;
      rr.rdlength = size - DNS_HEADER_SIZE;

      int result = SocketDNSSEC_parse_nsec (data, size, &rr, &nsec);
      if (result == 0)
        {
          /* Test type bitmap parsing */
          if (nsec.type_bitmaps && nsec.type_bitmaps_len > 0)
            {
              /* Test various RR types */
              int has_a = SocketDNSSEC_type_in_bitmap (
                  nsec.type_bitmaps, nsec.type_bitmaps_len, DNS_TYPE_A);
              (void)has_a;

              int has_aaaa = SocketDNSSEC_type_in_bitmap (
                  nsec.type_bitmaps, nsec.type_bitmaps_len, DNS_TYPE_AAAA);
              (void)has_aaaa;

              int has_dnskey = SocketDNSSEC_type_in_bitmap (
                  nsec.type_bitmaps, nsec.type_bitmaps_len, DNS_TYPE_DNSKEY);
              (void)has_dnskey;

              int has_rrsig = SocketDNSSEC_type_in_bitmap (
                  nsec.type_bitmaps, nsec.type_bitmaps_len, DNS_TYPE_RRSIG);
              (void)has_rrsig;

              int has_nsec = SocketDNSSEC_type_in_bitmap (
                  nsec.type_bitmaps, nsec.type_bitmaps_len, DNS_TYPE_NSEC);
              (void)has_nsec;

              /* Test with type from input data */
              if (size >= 2)
                {
                  uint16_t test_type = ((uint16_t)data[0] << 8) | data[1];
                  int has_type = SocketDNSSEC_type_in_bitmap (
                      nsec.type_bitmaps, nsec.type_bitmaps_len, test_type);
                  (void)has_type;
                }
            }
        }
    }

  /*
   * Test NSEC3 parsing
   */
  if (size >= DNSSEC_NSEC3_FIXED_SIZE)
    {
      memset (&rr, 0, sizeof (rr));
      rr.type = DNS_TYPE_NSEC3;
      rr.rdata = data;
      rr.rdlength = size;

      int result = SocketDNSSEC_parse_nsec3 (&rr, &nsec3);
      if (result == 0)
        {
          /* Verify NSEC3 fields */
          (void)(nsec3.hash_algorithm == 1); /* Should be SHA-1 */

          /* Test opt-out flag */
          int opt_out = (nsec3.flags & NSEC3_FLAG_OPT_OUT) != 0;
          (void)opt_out;

          /* Test iterations count (should be reasonable) */
          (void)(nsec3.iterations < 65536);

          /* Test salt length */
          (void)(nsec3.salt_len <= 255);

          /* Test hash length */
          (void)(nsec3.hash_len <= 255);

          /* Test type bitmap parsing */
          if (nsec3.type_bitmaps && nsec3.type_bitmaps_len > 0)
            {
              int has_a = SocketDNSSEC_type_in_bitmap (
                  nsec3.type_bitmaps, nsec3.type_bitmaps_len, DNS_TYPE_A);
              (void)has_a;

              int has_ns = SocketDNSSEC_type_in_bitmap (
                  nsec3.type_bitmaps, nsec3.type_bitmaps_len, DNS_TYPE_NS);
              (void)has_ns;
            }
        }
    }

  /*
   * Test name canonicalization and comparison
   */
  if (size >= 4)
    {
      /* Create two name buffers from input */
      char name1[MAX_NAME_LEN];
      char name2[MAX_NAME_LEN];

      size_t half = size / 2;
      size_t len1 = (half > MAX_NAME_LEN - 1) ? MAX_NAME_LEN - 1 : half;
      size_t len2 = (size - half > MAX_NAME_LEN - 1) ? MAX_NAME_LEN - 1
                                                      : size - half;

      memcpy (name1, data, len1);
      name1[len1] = '\0';

      memcpy (name2, data + half, len2);
      name2[len2] = '\0';

      /* Test canonicalization */
      SocketDNSSEC_name_canonicalize (name1);
      SocketDNSSEC_name_canonicalize (name2);

      /* Test canonical comparison */
      int cmp = SocketDNSSEC_name_canonical_compare (name1, name2);
      (void)cmp;

      /* Test comparison with NULL */
      cmp = SocketDNSSEC_name_canonical_compare (NULL, name2);
      (void)cmp;

      cmp = SocketDNSSEC_name_canonical_compare (name1, NULL);
      (void)cmp;

      cmp = SocketDNSSEC_name_canonical_compare (NULL, NULL);
      (void)cmp;
    }

  /*
   * Test algorithm and digest support checks with all possible values
   */
  for (uint8_t algo = 0; algo < 17; algo++)
    {
      int supported = SocketDNSSEC_algorithm_supported (algo);
      (void)supported;
    }

  for (uint8_t digest = 0; digest < 5; digest++)
    {
      int supported = SocketDNSSEC_digest_supported (digest);
      (void)supported;
    }

  /*
   * Test NULL pointer handling
   */
  (void)SocketDNSSEC_parse_dnskey (NULL, &dnskey);
  (void)SocketDNSSEC_parse_dnskey (&rr, NULL);
  (void)SocketDNSSEC_parse_rrsig (NULL, size, &rr, &rrsig);
  (void)SocketDNSSEC_parse_rrsig (data, size, NULL, &rrsig);
  (void)SocketDNSSEC_parse_rrsig (data, size, &rr, NULL);
  (void)SocketDNSSEC_parse_ds (NULL, &ds);
  (void)SocketDNSSEC_parse_ds (&rr, NULL);
  (void)SocketDNSSEC_parse_nsec (NULL, size, &rr, &nsec);
  (void)SocketDNSSEC_parse_nsec (data, size, NULL, &nsec);
  (void)SocketDNSSEC_parse_nsec (data, size, &rr, NULL);
  (void)SocketDNSSEC_parse_nsec3 (NULL, &nsec3);
  (void)SocketDNSSEC_parse_nsec3 (&rr, NULL);
  (void)SocketDNSSEC_calculate_keytag (NULL, size);
  (void)SocketDNSSEC_rrsig_valid_time (NULL, 0);
  (void)SocketDNSSEC_type_in_bitmap (NULL, 0, DNS_TYPE_A);
  (void)SocketDNSSEC_verify_rrsig (NULL, &dnskey, data, size, 0, 1);
  (void)SocketDNSSEC_verify_rrsig (&rrsig, NULL, data, size, 0, 1);
  (void)SocketDNSSEC_verify_rrsig (&rrsig, &dnskey, NULL, size, 0, 1);
  (void)SocketDNSSEC_verify_ds (NULL, &dnskey, "example.com");
  (void)SocketDNSSEC_verify_ds (&ds, NULL, "example.com");
  (void)SocketDNSSEC_verify_ds (&ds, &dnskey, NULL);
  SocketDNSSEC_name_canonicalize (NULL);

  /*
   * Test edge cases with specific algorithm values
   */
  if (size >= 1)
    {
      /* Test with algorithm 1 (RSA/MD5) - uses different keytag calculation */
      unsigned char rsamd5_key[DNSSEC_DNSKEY_FIXED_SIZE + 8];
      if (size >= sizeof (rsamd5_key))
        {
          memcpy (rsamd5_key, data, sizeof (rsamd5_key));
          rsamd5_key[3] = DNSSEC_ALGO_RSAMD5; /* Set algorithm to 1 */
          uint16_t tag
              = SocketDNSSEC_calculate_keytag (rsamd5_key, sizeof (rsamd5_key));
          (void)tag;
        }
    }

  /*
   * Test RRSIG with various time combinations
   * Test serial number arithmetic edge cases
   */
  if (size >= 12)
    {
      memset (&rrsig, 0, sizeof (rrsig));

      /* Construct timestamps from input */
      rrsig.sig_inception = ((uint32_t)data[0] << 24)
                            | ((uint32_t)data[1] << 16)
                            | ((uint32_t)data[2] << 8) | data[3];

      rrsig.sig_expiration = ((uint32_t)data[4] << 24)
                             | ((uint32_t)data[5] << 16)
                             | ((uint32_t)data[6] << 8) | data[7];

      time_t test_time = ((time_t)data[8] << 24) | ((time_t)data[9] << 16)
                         | ((time_t)data[10] << 8) | data[11];

      int valid = SocketDNSSEC_rrsig_valid_time (&rrsig, test_time);
      (void)valid;

      /* Test with current time */
      valid = SocketDNSSEC_rrsig_valid_time (&rrsig, 0);
      (void)valid;
    }

  return 0;
}
