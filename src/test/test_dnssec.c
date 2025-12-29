/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_dnssec.c
 * @brief Unit tests for DNSSEC validation (RFC 4033, 4034, 4035).
 */

#include "dns/SocketDNSSEC.h"
#include "dns/SocketDNSWire.h"
#include "test/Test.h"
#include <stdio.h>
#include <string.h>

/*
 * Test DNSKEY parsing
 */
TEST (dnskey_parse)
{
  unsigned char dnskey_rdata[] = {
      0x01, 0x01, /* Flags: 257 (KSK) */
      0x03,       /* Protocol: 3 */
      0x08,       /* Algorithm: 8 (RSA/SHA-256) */
      0x03, 0x01, 0x00, 0x01, /* Exponent: 65537 */
      0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,
      0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78};

  SocketDNS_RR rr = {.name = "example.com",
                     .type = DNS_TYPE_DNSKEY,
                     .rclass = DNS_CLASS_IN,
                     .ttl = 3600,
                     .rdlength = sizeof (dnskey_rdata),
                     .rdata = dnskey_rdata};

  SocketDNSSEC_DNSKEY dnskey;
  int ret = SocketDNSSEC_parse_dnskey (&rr, &dnskey);

  ASSERT (ret == 0);
  ASSERT (dnskey.flags == 257);
  ASSERT (dnskey.protocol == 3);
  ASSERT (dnskey.algorithm == DNSSEC_ALGO_RSASHA256);
  ASSERT (dnskey.pubkey_len == sizeof (dnskey_rdata) - 4);
  ASSERT (dnskey.key_tag != 0);
}

/*
 * Test DNSKEY flags parsing
 */
TEST (dnskey_flags)
{
  unsigned char zsk_rdata[] = {
      0x01, 0x00, /* Flags: 256 (ZONE) */
      0x03,       /* Protocol: 3 */
      0x08,       /* Algorithm: 8 */
      0x00, 0x00, 0x00, 0x01};

  SocketDNS_RR rr = {.type = DNS_TYPE_DNSKEY,
                     .rdlength = sizeof (zsk_rdata),
                     .rdata = zsk_rdata};

  SocketDNSSEC_DNSKEY dnskey;
  int ret = SocketDNSSEC_parse_dnskey (&rr, &dnskey);

  ASSERT (ret == 0);
  ASSERT ((dnskey.flags & DNSKEY_FLAG_ZONE_KEY) != 0);
  ASSERT ((dnskey.flags & DNSKEY_FLAG_SEP) == 0);
}

/*
 * Test DNSKEY with invalid protocol
 */
TEST (dnskey_invalid_protocol)
{
  unsigned char bad_proto[] = {
      0x01, 0x01, /* Flags: 257 */
      0x02,       /* Protocol: 2 (INVALID) */
      0x08,       /* Algorithm: 8 */
      0x00, 0x00, 0x00, 0x01};

  SocketDNS_RR rr = {.type = DNS_TYPE_DNSKEY,
                     .rdlength = sizeof (bad_proto),
                     .rdata = bad_proto};

  SocketDNSSEC_DNSKEY dnskey;
  int ret = SocketDNSSEC_parse_dnskey (&rr, &dnskey);

  ASSERT (ret == -1);
}

/*
 * Test DS record parsing
 */
TEST (ds_parse)
{
  unsigned char ds_rdata[] = {
      0x12, 0x34, /* Key Tag: 0x1234 */
      0x08,       /* Algorithm: 8 */
      0x02,       /* Digest Type: 2 (SHA-256) */
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
      0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
      0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};

  SocketDNS_RR rr = {.name = "example.com",
                     .type = DNS_TYPE_DS,
                     .rclass = DNS_CLASS_IN,
                     .ttl = 3600,
                     .rdlength = sizeof (ds_rdata),
                     .rdata = ds_rdata};

  SocketDNSSEC_DS ds;
  int ret = SocketDNSSEC_parse_ds (&rr, &ds);

  ASSERT (ret == 0);
  ASSERT (ds.key_tag == 0x1234);
  ASSERT (ds.algorithm == DNSSEC_ALGO_RSASHA256);
  ASSERT (ds.digest_type == DNSSEC_DIGEST_SHA256);
  ASSERT (ds.digest_len == 32);
}

/*
 * Test DS record with SHA-1 digest
 */
TEST (ds_sha1)
{
  unsigned char ds_rdata[] = {
      0x00, 0x01, /* Key Tag: 1 */
      0x05,       /* Algorithm: 5 (RSA/SHA-1) */
      0x01,       /* Digest Type: 1 (SHA-1) */
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14};

  SocketDNS_RR rr = {.type = DNS_TYPE_DS,
                     .rdlength = sizeof (ds_rdata),
                     .rdata = ds_rdata};

  SocketDNSSEC_DS ds;
  int ret = SocketDNSSEC_parse_ds (&rr, &ds);

  ASSERT (ret == 0);
  ASSERT (ds.digest_type == DNSSEC_DIGEST_SHA1);
  ASSERT (ds.digest_len == 20);
}

/*
 * Test DS record with invalid digest length
 */
TEST (ds_invalid_digest_len)
{
  unsigned char ds_rdata[] = {0x00, 0x01, 0x08, 0x02, /* SHA-256 type */
                              0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                              0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                              0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B};

  SocketDNS_RR rr = {.type = DNS_TYPE_DS,
                     .rdlength = sizeof (ds_rdata),
                     .rdata = ds_rdata};

  SocketDNSSEC_DS ds;
  int ret = SocketDNSSEC_parse_ds (&rr, &ds);

  ASSERT (ret == -1);
}

/*
 * Test key tag calculation
 */
TEST (keytag_calculation)
{
  unsigned char dnskey_rdata[] = {
      0x01, 0x01, /* Flags: 257 */
      0x03,       /* Protocol: 3 */
      0x08,       /* Algorithm: 8 */
      0x03, 0x01, 0x00, 0x01};

  uint16_t tag = SocketDNSSEC_calculate_keytag (dnskey_rdata,
                                                 sizeof (dnskey_rdata));

  ASSERT (tag != 0);
}

/*
 * Test NSEC type bitmap operations
 */
TEST (nsec_type_bitmap)
{
  unsigned char bitmap[] = {
      0x00, 0x06,             /* Window 0, bitmap length 6 */
      0x40, 0x00, 0x00, 0x08, /* Bit 1 (A) and bit 28 (AAAA) */
      0x00, 0x02              /* Bit 46 (RRSIG) */
  };

  ASSERT (SocketDNSSEC_type_in_bitmap (bitmap, sizeof (bitmap), DNS_TYPE_A) == 1);
  ASSERT (SocketDNSSEC_type_in_bitmap (bitmap, sizeof (bitmap), DNS_TYPE_AAAA) == 1);
  ASSERT (SocketDNSSEC_type_in_bitmap (bitmap, sizeof (bitmap), DNS_TYPE_RRSIG) == 1);
  ASSERT (SocketDNSSEC_type_in_bitmap (bitmap, sizeof (bitmap), DNS_TYPE_MX) == 0);
}

/*
 * Test canonical name comparison
 */
TEST (canonical_name_compare)
{
  ASSERT (SocketDNSSEC_name_canonical_compare ("Example.COM", "example.com") == 0);
  ASSERT (SocketDNSSEC_name_canonical_compare ("com", "example.com") < 0);
  ASSERT (SocketDNSSEC_name_canonical_compare ("aaa.com", "bbb.com") < 0);
  ASSERT (SocketDNSSEC_name_canonical_compare ("a.example.com", "aa.example.com") < 0);
}

/*
 * Test canonical name case folding
 */
TEST (canonical_name_fold)
{
  char name[] = "WWW.EXAMPLE.COM";
  SocketDNSSEC_name_canonicalize (name);
  ASSERT (strcmp (name, "www.example.com") == 0);
}

/*
 * Test RRSIG time validity
 */
TEST (rrsig_time_validity)
{
  SocketDNSSEC_RRSIG rrsig = {
      .sig_inception = 1700000000,
      .sig_expiration = 1800000000,
  };

  ASSERT (SocketDNSSEC_rrsig_valid_time (&rrsig, 1750000000) == 1);
  ASSERT (SocketDNSSEC_rrsig_valid_time (&rrsig, 1600000000) == 0);
  ASSERT (SocketDNSSEC_rrsig_valid_time (&rrsig, 1900000000) == 0);
}

/*
 * Test algorithm support
 */
TEST (algorithm_support)
{
#ifdef SOCKET_HAS_TLS
  ASSERT (SocketDNSSEC_algorithm_supported (DNSSEC_ALGO_RSASHA256) == 1);
  ASSERT (SocketDNSSEC_algorithm_supported (DNSSEC_ALGO_ECDSAP256SHA256) == 1);
  ASSERT (SocketDNSSEC_algorithm_supported (DNSSEC_ALGO_ED25519) == 1);
#endif
  ASSERT (SocketDNSSEC_algorithm_supported (DNSSEC_ALGO_RSAMD5) == 0);
}

/*
 * Test digest type support
 */
TEST (digest_support)
{
#ifdef SOCKET_HAS_TLS
  ASSERT (SocketDNSSEC_digest_supported (DNSSEC_DIGEST_SHA256) == 1);
  ASSERT (SocketDNSSEC_digest_supported (DNSSEC_DIGEST_SHA384) == 1);
#endif
  ASSERT (SocketDNSSEC_digest_supported (DNSSEC_DIGEST_GOST) == 0);
}

/*
 * Test NSEC3 parsing
 */
TEST (nsec3_parse)
{
  unsigned char nsec3_rdata[] = {
      0x01,       /* Hash Algorithm: 1 (SHA-1) */
      0x00,       /* Flags: 0 */
      0x00, 0x0A, /* Iterations: 10 */
      0x04,       /* Salt Length: 4 */
      0xAB, 0xCD, 0xEF, 0x12, /* Salt */
      0x14,                   /* Hash Length: 20 */
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
      0x00, 0x04, /* Window 0, length 4 */
      0x40, 0x00, 0x00, 0x08};

  SocketDNS_RR rr = {.type = DNS_TYPE_NSEC3,
                     .rdlength = sizeof (nsec3_rdata),
                     .rdata = nsec3_rdata};

  SocketDNSSEC_NSEC3 nsec3;
  int ret = SocketDNSSEC_parse_nsec3 (&rr, &nsec3);

  ASSERT (ret == 0);
  ASSERT (nsec3.hash_algorithm == 1);
  ASSERT (nsec3.flags == 0);
  ASSERT (nsec3.iterations == 10);
  ASSERT (nsec3.salt_len == 4);
  ASSERT (nsec3.hash_len == 20);
}

/*
 * Test RSA key parsing with malicious exponent length (overflow attack)
 * This tests the fix in SocketDNSSEC_verify_rrsig() at line 891-894
 */
TEST (dnskey_rsa_overflow_attack)
{
#ifdef SOCKET_HAS_TLS
  /* Create DNSKEY structure with malicious RSA public key */
  /* Public key blob has exp_len = 0xFFFF which would cause pointer overflow */
  unsigned char malicious_pubkey[] = {
      0x00,       /* Exponent length byte = 0 (means use next 2 bytes) */
      0xFF, 0xFF, /* Exponent length: 65535 (malicious - would cause overflow) */
      0x01, 0x02, 0x03, 0x04 /* Only 4 bytes of actual data */
  };

  SocketDNSSEC_DNSKEY dnskey = {
      .flags = 257,
      .protocol = 3,
      .algorithm = DNSSEC_ALGO_RSASHA256,
      .pubkey = malicious_pubkey,
      .pubkey_len = sizeof (malicious_pubkey),
      .key_tag = 0x1234
  };

  /* Create minimal RRSIG that passes initial checks */
  SocketDNSSEC_RRSIG rrsig = {
      .type_covered = 1, /* A record */
      .algorithm = DNSSEC_ALGO_RSASHA256,
      .labels = 2,
      .original_ttl = 3600,
      .sig_expiration = 0x7FFFFFFF, /* Far future */
      .sig_inception = 0, /* Epoch */
      .key_tag = 0x1234,
      .signature = (unsigned char *)"dummy",
      .signature_len = 8
  };

  /* Minimal DNS message with one RR */
  unsigned char msg[] = {
      /* DNS Header */
      0x00, 0x00, /* ID */
      0x00, 0x00, /* Flags */
      0x00, 0x00, /* QDCOUNT */
      0x00, 0x01, /* ANCOUNT = 1 */
      0x00, 0x00, /* NSCOUNT */
      0x00, 0x00, /* ARCOUNT */
      /* Answer RR: example.com A 1.2.3.4 */
      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
      0x00, 0x01, /* Type A */
      0x00, 0x01, /* Class IN */
      0x00, 0x00, 0x0e, 0x10, /* TTL 3600 */
      0x00, 0x04, /* RDLENGTH 4 */
      0x01, 0x02, 0x03, 0x04 /* 1.2.3.4 */
  };

  /* Attempt verification - should return DNSSEC_BOGUS due to overflow check */
  int result = SocketDNSSEC_verify_rrsig (&rrsig, &dnskey, msg, sizeof (msg), 12, 1);

  /* Should fail with DNSSEC_BOGUS (2) due to bounds check on exp_len */
  ASSERT (result == 2); /* DNSSEC_BOGUS */
#endif
}

/*
 * Test RSA key parsing with exponent length exceeding buffer
 */
TEST (dnskey_rsa_exponent_oob)
{
#ifdef SOCKET_HAS_TLS
  /* Public key where exponent length exceeds remaining buffer */
  unsigned char oob_pubkey[] = {
      0x10,       /* Exponent length: 16 bytes */
      0x01, 0x02, 0x03, 0x04, 0x05 /* Only 5 bytes left (needs 16 + modulus) */
  };

  SocketDNSSEC_DNSKEY dnskey = {
      .flags = 257,
      .protocol = 3,
      .algorithm = DNSSEC_ALGO_RSASHA256,
      .pubkey = oob_pubkey,
      .pubkey_len = sizeof (oob_pubkey),
      .key_tag = 0x1234
  };

  SocketDNSSEC_RRSIG rrsig = {
      .type_covered = 1,
      .algorithm = DNSSEC_ALGO_RSASHA256,
      .labels = 2,
      .original_ttl = 3600,
      .sig_expiration = 0x7FFFFFFF,
      .sig_inception = 0,
      .key_tag = 0x1234,
      .signature = (unsigned char *)"dummy",
      .signature_len = 8
  };

  unsigned char msg[] = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
      0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x04,
      0x01, 0x02, 0x03, 0x04
  };

  /* Attempt verification - should return DNSSEC_BOGUS */
  int result = SocketDNSSEC_verify_rrsig (&rrsig, &dnskey, msg, sizeof (msg), 12, 1);

  /* Should fail with DNSSEC_BOGUS (2) due to exp_len > remaining */
  ASSERT (result == 2); /* DNSSEC_BOGUS */
#endif
}

/*
 * Test validator lifecycle
 */
TEST (validator_lifecycle)
{
  SocketDNSSEC_Validator_T validator = SocketDNSSEC_validator_new (NULL);
  ASSERT_NOT_NULL (validator);

  SocketDNSSEC_validator_free (&validator);
  ASSERT_NULL (validator);
}

/*
 * Test BIND-format trust anchor file parsing
 */
TEST (load_anchors_bind_format)
{
  /* Create test trust anchor file */
  const char *test_file = "/tmp/test_trust_anchors.conf";
  FILE *fp = fopen (test_file, "w");
  ASSERT_NOT_NULL (fp);

  /* Write DNSKEY record (simplified base64 key) */
  fprintf (fp, "; Trust anchor for root zone\n");
  fprintf (fp, ". IN DNSKEY 257 3 8 "
               "AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF\n");
  fprintf (fp, "\n");

  /* Write DS record */
  fprintf (fp, "# Trust anchor as DS record\n");
  fprintf (
      fp,
      "example.com. IN DS 12345 8 2 "
      "49FD46E6C4B45C55D4AC69CBD3CD34AC1AFE51DE3D5A1D1E1E1F1E1F1E1F1E1F\n");

  /* Write entry with optional TTL field */
  fprintf (fp, "test.org. 3600 IN DNSKEY 256 3 13 "
               "AQPJ////4Q==\n");

  fclose (fp);

  /* Load anchors */
  SocketDNSSEC_Validator_T validator = SocketDNSSEC_validator_new (NULL);
  ASSERT_NOT_NULL (validator);

  int count = SocketDNSSEC_validator_load_anchors (validator, test_file);
  ASSERT (count >= 2); /* Should load at least DNSKEY and DS */

  /* Cleanup */
  SocketDNSSEC_validator_free (&validator);
  remove (test_file);
}

/*
 * Test trust anchor parsing with invalid file
 */
TEST (load_anchors_invalid_file)
{
  SocketDNSSEC_Validator_T validator = SocketDNSSEC_validator_new (NULL);
  ASSERT_NOT_NULL (validator);

  /* Try to load non-existent file */
  int count
      = SocketDNSSEC_validator_load_anchors (validator, "/nonexistent/file");
  ASSERT (count == -1);

  SocketDNSSEC_validator_free (&validator);
}

/*
 * Test trust anchor with KSK flags
 */
TEST (load_anchors_ksk_flags)
{
  const char *test_file = "/tmp/test_ksk_anchor.conf";
  FILE *fp = fopen (test_file, "w");
  ASSERT_NOT_NULL (fp);

  /* DNSKEY with KSK flags (257 = 0x0101 = ZONE + SEP) */
  fprintf (fp, ". IN DNSKEY 257 3 8 AQPJ////4Q==\n");

  fclose (fp);

  SocketDNSSEC_Validator_T validator = SocketDNSSEC_validator_new (NULL);
  ASSERT_NOT_NULL (validator);

  int count = SocketDNSSEC_validator_load_anchors (validator, test_file);
  ASSERT (count == 1);

  /* Verify anchor was loaded (basic check) */
  ASSERT (validator != NULL);

  SocketDNSSEC_validator_free (&validator);
  remove (test_file);
}

/*
 * Main test entry
 */
int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}
