/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/*
 * test_dnserror.c - Unit tests for Extended DNS Errors (RFC 8914)
 *
 * Tests EDE parsing, encoding, and helper functions.
 */

#include "dns/SocketDNSError.h"
#include "dns/SocketDNSWire.h"
#include "test/Test.h"

#include <stdio.h>
#include <string.h>

/* Test EDE initialization */
TEST (ede_init)
{
  SocketDNS_ExtendedError ede;

  /* Fill with garbage first */
  memset (&ede, 0xFF, sizeof (ede));

  SocketDNS_ede_init (&ede);

  ASSERT_EQ (ede.info_code, 0);
  ASSERT_EQ (ede.present, false);
  ASSERT_EQ (ede.extra_text_len, 0);
  ASSERT_EQ (ede.extra_text[0], '\0');
}

/* Test EDE init with NULL parameter */
TEST (ede_init_null)
{
  /* Should not crash */
  SocketDNS_ede_init (NULL);
}

/* Test basic EDE parsing without EXTRA-TEXT */
TEST (ede_parse_basic)
{
  /* INFO-CODE only: DNSSEC Bogus (6) */
  unsigned char data[] = { 0x00, 0x06 };
  SocketDNS_ExtendedError ede;

  int ret = SocketDNS_ede_parse (data, sizeof (data), &ede);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (ede.info_code, DNS_EDE_DNSSEC_BOGUS);
  ASSERT_EQ (ede.present, true);
  ASSERT_EQ (ede.extra_text_len, 0);
}

/* Test EDE parsing with EXTRA-TEXT */
TEST (ede_parse_with_text)
{
  /* INFO-CODE: Network Error (23) + EXTRA-TEXT */
  unsigned char data[] = {
    0x00, 0x17,                               /* INFO-CODE = 23 */
    'C', 'o', 'n', 'n', 'e', 'c', 't', 'i',   /* EXTRA-TEXT */
    'o', 'n', ' ', 'r', 'e', 'f', 'u', 's',
    'e', 'd'
  };
  SocketDNS_ExtendedError ede;

  int ret = SocketDNS_ede_parse (data, sizeof (data), &ede);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (ede.info_code, DNS_EDE_NETWORK_ERROR);
  ASSERT_EQ (ede.present, true);
  ASSERT_EQ (ede.extra_text_len, 18);
  ASSERT (strcmp (ede.extra_text, "Connection refused") == 0);
}

/* Test EDE parsing with UTF-8 EXTRA-TEXT */
TEST (ede_parse_utf8_text)
{
  /* INFO-CODE: Blocked (15) + UTF-8 EXTRA-TEXT with Euro sign */
  unsigned char data[] = {
    0x00, 0x0F,                     /* INFO-CODE = 15 */
    'C', 'o', 's', 't', ':', ' ',
    0xE2, 0x82, 0xAC,               /* Euro sign (U+20AC) */
    '1', '0'
  };
  SocketDNS_ExtendedError ede;

  int ret = SocketDNS_ede_parse (data, sizeof (data), &ede);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (ede.info_code, DNS_EDE_BLOCKED);
  ASSERT_EQ (ede.extra_text_len, 11);
}

/* Test EDE parsing with all defined codes */
TEST (ede_parse_all_codes)
{
  for (uint16_t code = 0; code <= DNS_EDE_MAX_DEFINED; code++)
    {
      unsigned char data[2] = { (code >> 8) & 0xFF, code & 0xFF };
      SocketDNS_ExtendedError ede;

      int ret = SocketDNS_ede_parse (data, sizeof (data), &ede);
      ASSERT_EQ (ret, 0);
      ASSERT_EQ (ede.info_code, code);
      ASSERT_EQ (ede.present, true);
    }
}

/* Test EDE parsing with high info codes (undefined) */
TEST (ede_parse_high_code)
{
  /* INFO-CODE 65535 (undefined) */
  unsigned char data[] = { 0xFF, 0xFF };
  SocketDNS_ExtendedError ede;

  int ret = SocketDNS_ede_parse (data, sizeof (data), &ede);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (ede.info_code, 65535);
  ASSERT_EQ (ede.present, true);
}

/* Test EDE parse with too short data */
TEST (ede_parse_too_short)
{
  unsigned char data[] = { 0x00 };
  SocketDNS_ExtendedError ede;

  int ret = SocketDNS_ede_parse (data, sizeof (data), &ede);
  ASSERT_EQ (ret, -1);
}

/* Test EDE parse with NULL parameters */
TEST (ede_parse_null)
{
  unsigned char data[] = { 0x00, 0x00 };
  SocketDNS_ExtendedError ede;

  ASSERT_EQ (SocketDNS_ede_parse (NULL, 2, &ede), -1);
  ASSERT_EQ (SocketDNS_ede_parse (data, 2, NULL), -1);
}

/* Test EDE encoding without EXTRA-TEXT */
TEST (ede_encode_basic)
{
  SocketDNS_ExtendedError ede;
  SocketDNS_ede_init (&ede);
  ede.info_code = DNS_EDE_DNSSEC_BOGUS;
  ede.present = true;

  unsigned char buf[64];
  int ret = SocketDNS_ede_encode (&ede, buf, sizeof (buf));
  ASSERT_EQ (ret, 2);
  ASSERT_EQ (buf[0], 0x00);
  ASSERT_EQ (buf[1], 0x06);
}

/* Test EDE encoding with EXTRA-TEXT */
TEST (ede_encode_with_text)
{
  SocketDNS_ExtendedError ede;
  SocketDNS_ede_init (&ede);
  ede.info_code = DNS_EDE_NETWORK_ERROR;
  ede.present = true;
  strcpy (ede.extra_text, "timeout");
  ede.extra_text_len = 7;

  unsigned char buf[64];
  int ret = SocketDNS_ede_encode (&ede, buf, sizeof (buf));
  ASSERT_EQ (ret, 9);  /* 2 + 7 */
  ASSERT_EQ (buf[0], 0x00);
  ASSERT_EQ (buf[1], 0x17);  /* 23 = Network Error */
  ASSERT (memcmp (buf + 2, "timeout", 7) == 0);
}

/* Test EDE encoding roundtrip */
TEST (ede_encode_roundtrip)
{
  SocketDNS_ExtendedError orig, decoded;
  SocketDNS_ede_init (&orig);
  orig.info_code = DNS_EDE_NO_REACHABLE_AUTHORITY;
  orig.present = true;
  strcpy (orig.extra_text, "All nameservers failed");
  orig.extra_text_len = strlen (orig.extra_text);

  unsigned char buf[256];
  int len = SocketDNS_ede_encode (&orig, buf, sizeof (buf));
  ASSERT (len > 0);

  int ret = SocketDNS_ede_parse (buf, (size_t)len, &decoded);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (decoded.info_code, orig.info_code);
  ASSERT_EQ (decoded.extra_text_len, orig.extra_text_len);
  ASSERT (strcmp (decoded.extra_text, orig.extra_text) == 0);
}

/* Test EDE encode with buffer too small */
TEST (ede_encode_buffer_too_small)
{
  SocketDNS_ExtendedError ede;
  SocketDNS_ede_init (&ede);
  ede.info_code = DNS_EDE_OTHER;
  ede.present = true;
  strcpy (ede.extra_text, "test");
  ede.extra_text_len = 4;

  unsigned char buf[4];  /* Too small for 2 + 4 = 6 bytes */
  int ret = SocketDNS_ede_encode (&ede, buf, sizeof (buf));
  ASSERT_EQ (ret, -1);
}

/* Test EDE code names */
TEST (ede_code_name)
{
  ASSERT (strcmp (SocketDNS_ede_code_name (DNS_EDE_OTHER), "Other Error") == 0);
  ASSERT (strcmp (SocketDNS_ede_code_name (DNS_EDE_DNSSEC_BOGUS), "DNSSEC Bogus") == 0);
  ASSERT (strcmp (SocketDNS_ede_code_name (DNS_EDE_NETWORK_ERROR), "Network Error") == 0);
  ASSERT (strcmp (SocketDNS_ede_code_name (DNS_EDE_INVALID_DATA), "Invalid Data") == 0);

  /* Unknown code */
  ASSERT (strcmp (SocketDNS_ede_code_name (100), "Unknown Error") == 0);
  ASSERT (strcmp (SocketDNS_ede_code_name (65535), "Unknown Error") == 0);
}

/* Test EDE code descriptions */
TEST (ede_code_description)
{
  const char *desc = SocketDNS_ede_code_description (DNS_EDE_DNSSEC_BOGUS);
  ASSERT_NOT_NULL (desc);
  ASSERT (strlen (desc) > 0);

  /* Unknown code */
  desc = SocketDNS_ede_code_description (999);
  ASSERT_NOT_NULL (desc);
  ASSERT (strstr (desc, "Unknown") != NULL || strstr (desc, "unknown") != NULL);
}

/* Test EDE categories */
TEST (ede_category)
{
  /* DNSSEC category */
  ASSERT_EQ (SocketDNS_ede_category (DNS_EDE_DNSSEC_BOGUS), DNS_EDE_CATEGORY_DNSSEC);
  ASSERT_EQ (SocketDNS_ede_category (DNS_EDE_SIGNATURE_EXPIRED), DNS_EDE_CATEGORY_DNSSEC);
  ASSERT_EQ (SocketDNS_ede_category (DNS_EDE_DNSKEY_MISSING), DNS_EDE_CATEGORY_DNSSEC);

  /* Stale category */
  ASSERT_EQ (SocketDNS_ede_category (DNS_EDE_STALE_ANSWER), DNS_EDE_CATEGORY_STALE);
  ASSERT_EQ (SocketDNS_ede_category (DNS_EDE_STALE_NXDOMAIN_ANSWER), DNS_EDE_CATEGORY_STALE);

  /* Policy category */
  ASSERT_EQ (SocketDNS_ede_category (DNS_EDE_BLOCKED), DNS_EDE_CATEGORY_POLICY);
  ASSERT_EQ (SocketDNS_ede_category (DNS_EDE_CENSORED), DNS_EDE_CATEGORY_POLICY);
  ASSERT_EQ (SocketDNS_ede_category (DNS_EDE_FILTERED), DNS_EDE_CATEGORY_POLICY);

  /* Server category */
  ASSERT_EQ (SocketDNS_ede_category (DNS_EDE_NOT_READY), DNS_EDE_CATEGORY_SERVER);
  ASSERT_EQ (SocketDNS_ede_category (DNS_EDE_NOT_SUPPORTED), DNS_EDE_CATEGORY_SERVER);

  /* Network category */
  ASSERT_EQ (SocketDNS_ede_category (DNS_EDE_NETWORK_ERROR), DNS_EDE_CATEGORY_NETWORK);
  ASSERT_EQ (SocketDNS_ede_category (DNS_EDE_NO_REACHABLE_AUTHORITY), DNS_EDE_CATEGORY_NETWORK);
}

/* Test EDE category names */
TEST (ede_category_name)
{
  ASSERT (strcmp (SocketDNS_ede_category_name (DNS_EDE_CATEGORY_GENERAL), "General") == 0);
  ASSERT (strcmp (SocketDNS_ede_category_name (DNS_EDE_CATEGORY_DNSSEC), "DNSSEC") == 0);
  ASSERT (strcmp (SocketDNS_ede_category_name (DNS_EDE_CATEGORY_STALE), "Stale Cache") == 0);
  ASSERT (strcmp (SocketDNS_ede_category_name (DNS_EDE_CATEGORY_POLICY), "Policy/Filter") == 0);
  ASSERT (strcmp (SocketDNS_ede_category_name (DNS_EDE_CATEGORY_SERVER), "Server State") == 0);
  ASSERT (strcmp (SocketDNS_ede_category_name (DNS_EDE_CATEGORY_NETWORK), "Network") == 0);
}

/* Test is_dnssec_error helper */
TEST (ede_is_dnssec_error)
{
  ASSERT_EQ (SocketDNS_ede_is_dnssec_error (DNS_EDE_DNSSEC_BOGUS), true);
  ASSERT_EQ (SocketDNS_ede_is_dnssec_error (DNS_EDE_SIGNATURE_EXPIRED), true);
  ASSERT_EQ (SocketDNS_ede_is_dnssec_error (DNS_EDE_DNSKEY_MISSING), true);
  ASSERT_EQ (SocketDNS_ede_is_dnssec_error (DNS_EDE_RRSIGS_MISSING), true);
  ASSERT_EQ (SocketDNS_ede_is_dnssec_error (DNS_EDE_NSEC_MISSING), true);
  ASSERT_EQ (SocketDNS_ede_is_dnssec_error (DNS_EDE_UNSUPPORTED_DNSKEY_ALGORITHM), true);

  /* Non-DNSSEC codes */
  ASSERT_EQ (SocketDNS_ede_is_dnssec_error (DNS_EDE_OTHER), false);
  ASSERT_EQ (SocketDNS_ede_is_dnssec_error (DNS_EDE_NETWORK_ERROR), false);
  ASSERT_EQ (SocketDNS_ede_is_dnssec_error (DNS_EDE_BLOCKED), false);
}

/* Test is_stale helper */
TEST (ede_is_stale)
{
  ASSERT_EQ (SocketDNS_ede_is_stale (DNS_EDE_STALE_ANSWER), true);
  ASSERT_EQ (SocketDNS_ede_is_stale (DNS_EDE_STALE_NXDOMAIN_ANSWER), true);

  ASSERT_EQ (SocketDNS_ede_is_stale (DNS_EDE_OTHER), false);
  ASSERT_EQ (SocketDNS_ede_is_stale (DNS_EDE_DNSSEC_BOGUS), false);
}

/* Test is_filtered helper */
TEST (ede_is_filtered)
{
  ASSERT_EQ (SocketDNS_ede_is_filtered (DNS_EDE_FORGED_ANSWER), true);
  ASSERT_EQ (SocketDNS_ede_is_filtered (DNS_EDE_BLOCKED), true);
  ASSERT_EQ (SocketDNS_ede_is_filtered (DNS_EDE_CENSORED), true);
  ASSERT_EQ (SocketDNS_ede_is_filtered (DNS_EDE_FILTERED), true);
  ASSERT_EQ (SocketDNS_ede_is_filtered (DNS_EDE_PROHIBITED), true);

  ASSERT_EQ (SocketDNS_ede_is_filtered (DNS_EDE_OTHER), false);
  ASSERT_EQ (SocketDNS_ede_is_filtered (DNS_EDE_NETWORK_ERROR), false);
}

/* Test is_retriable helper */
TEST (ede_is_retriable)
{
  /* Retriable errors */
  ASSERT_EQ (SocketDNS_ede_is_retriable (DNS_EDE_NOT_READY), true);
  ASSERT_EQ (SocketDNS_ede_is_retriable (DNS_EDE_NETWORK_ERROR), true);
  ASSERT_EQ (SocketDNS_ede_is_retriable (DNS_EDE_NO_REACHABLE_AUTHORITY), true);
  ASSERT_EQ (SocketDNS_ede_is_retriable (DNS_EDE_CACHED_ERROR), true);
  ASSERT_EQ (SocketDNS_ede_is_retriable (DNS_EDE_SIGNATURE_NOT_YET_VALID), true);
  ASSERT_EQ (SocketDNS_ede_is_retriable (DNS_EDE_STALE_ANSWER), true);

  /* Non-retriable errors */
  ASSERT_EQ (SocketDNS_ede_is_retriable (DNS_EDE_DNSSEC_BOGUS), false);
  ASSERT_EQ (SocketDNS_ede_is_retriable (DNS_EDE_BLOCKED), false);
  ASSERT_EQ (SocketDNS_ede_is_retriable (DNS_EDE_PROHIBITED), false);
  ASSERT_EQ (SocketDNS_ede_is_retriable (DNS_EDE_SIGNATURE_EXPIRED), false);
}

/* Test EDE format */
TEST (ede_format)
{
  SocketDNS_ExtendedError ede;
  char buf[256];

  /* Test with EXTRA-TEXT */
  SocketDNS_ede_init (&ede);
  ede.info_code = DNS_EDE_NETWORK_ERROR;
  ede.present = true;
  strcpy (ede.extra_text, "Connection timed out");
  ede.extra_text_len = strlen (ede.extra_text);

  int ret = SocketDNS_ede_format (&ede, buf, sizeof (buf));
  ASSERT (ret > 0);
  ASSERT (strstr (buf, "Network Error") != NULL);
  ASSERT (strstr (buf, "23") != NULL);
  ASSERT (strstr (buf, "Connection timed out") != NULL);

  /* Test without EXTRA-TEXT */
  SocketDNS_ede_init (&ede);
  ede.info_code = DNS_EDE_BLOCKED;
  ede.present = true;

  ret = SocketDNS_ede_format (&ede, buf, sizeof (buf));
  ASSERT (ret > 0);
  ASSERT (strstr (buf, "Blocked") != NULL);
  ASSERT (strstr (buf, "15") != NULL);

  /* Test with not present */
  SocketDNS_ede_init (&ede);
  ret = SocketDNS_ede_format (&ede, buf, sizeof (buf));
  ASSERT (ret > 0);
  ASSERT (strstr (buf, "no extended error") != NULL);
}

/* Test EDE format with NULL params */
TEST (ede_format_null)
{
  SocketDNS_ExtendedError ede;
  char buf[64];

  ASSERT_EQ (SocketDNS_ede_format (NULL, buf, sizeof (buf)), -1);
  ASSERT_EQ (SocketDNS_ede_format (&ede, NULL, sizeof (buf)), -1);
  ASSERT_EQ (SocketDNS_ede_format (&ede, buf, 0), -1);
}

/* Test EDE parse_all with multiple EDEs */
TEST (ede_parse_all_multiple)
{
  /* Construct RDATA with two EDE options */
  unsigned char rdata[64];
  size_t pos = 0;

  /* First EDE: DNSSEC Bogus (6) */
  rdata[pos++] = 0x00; rdata[pos++] = 0x0F;  /* Option code 15 */
  rdata[pos++] = 0x00; rdata[pos++] = 0x02;  /* Length 2 */
  rdata[pos++] = 0x00; rdata[pos++] = 0x06;  /* INFO-CODE 6 */

  /* Second EDE: Network Error (23) with text */
  rdata[pos++] = 0x00; rdata[pos++] = 0x0F;  /* Option code 15 */
  rdata[pos++] = 0x00; rdata[pos++] = 0x09;  /* Length 9 */
  rdata[pos++] = 0x00; rdata[pos++] = 0x17;  /* INFO-CODE 23 */
  memcpy (rdata + pos, "timeout", 7);
  pos += 7;

  SocketDNS_ExtendedError errors[4];
  int count = SocketDNS_ede_parse_all (rdata, pos, errors, 4);
  ASSERT_EQ (count, 2);
  ASSERT_EQ (errors[0].info_code, DNS_EDE_DNSSEC_BOGUS);
  ASSERT_EQ (errors[1].info_code, DNS_EDE_NETWORK_ERROR);
  ASSERT (strcmp (errors[1].extra_text, "timeout") == 0);
}

/* Test EDE parse_all with no EDEs */
TEST (ede_parse_all_empty)
{
  /* RDATA with only non-EDE options */
  unsigned char rdata[] = {
    0x00, 0x03,  /* Option code 3 (NSID) */
    0x00, 0x04,  /* Length 4 */
    't', 'e', 's', 't'
  };

  SocketDNS_ExtendedError errors[4];
  int count = SocketDNS_ede_parse_all (rdata, sizeof (rdata), errors, 4);
  ASSERT_EQ (count, 0);
}

/* Test EDE to EDNS option */
TEST (ede_to_edns_option)
{
  SocketDNS_ExtendedError ede;
  SocketDNS_ede_init (&ede);
  ede.info_code = DNS_EDE_BLOCKED;
  ede.present = true;
  strcpy (ede.extra_text, "policy");
  ede.extra_text_len = 6;

  SocketDNS_EDNSOption opt;
  unsigned char data[64];

  int ret = SocketDNS_ede_to_edns_option (&ede, &opt, data, sizeof (data));
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (opt.code, DNS_EDE_OPTION_CODE);
  ASSERT_EQ (opt.length, 8);  /* 2 + 6 */
  ASSERT_NOT_NULL (opt.data);
}

/* Test EDE option code constant */
TEST (ede_option_code)
{
  /* Verify option code matches RFC 8914 */
  ASSERT_EQ (DNS_EDE_OPTION_CODE, 15);
  ASSERT_EQ (DNS_EDE_OPTION_CODE, DNS_EDNS_OPT_EXTENDED_ERROR);
}

/* Main function */
int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}
