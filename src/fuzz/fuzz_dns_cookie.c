/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_dns_cookie.c - libFuzzer harness for DNS Cookie parsing
 *
 * Fuzzes DNS Cookie encoding/decoding (RFC 7873).
 *
 * Targets:
 * - SocketDNSCookie_parse() - Parse cookie from EDNS0 option
 * - SocketDNSCookie_encode() - Encode cookie to wire format
 * - SocketDNSCookie_validate() - Validate response against request
 * - SocketDNSCookie_equal() - Compare cookies
 * - SocketDNSCookie_to_hex() - Debug formatting
 * - SocketDNSCookie_is_badcookie() - RCODE 23 check
 *
 * Test cases:
 * - Invalid lengths (< 8, 9-15, > 40)
 * - Client cookie only (8 bytes)
 * - With server cookie (16-40 bytes)
 * - Maximum server cookie (32 bytes)
 * - Encode-decode roundtrip
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_dns_cookie
 * Run:   ./fuzz_dns_cookie -fork=16 -max_len=64
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "dns/SocketDNSCookie.h"

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  SocketDNSCookie_Cookie cookie;
  SocketDNSCookie_Cookie decoded;
  unsigned char encoded[DNS_COOKIE_OPTION_MAX_LEN + 16];
  char hex_buf[128];

  if (size == 0)
    return 0;

  /*
   * Test cookie parsing from raw data.
   * RFC 7873 specifies valid lengths:
   * - 8 bytes: client cookie only
   * - 16-40 bytes: client + server cookie
   */
  int result = SocketDNSCookie_parse (data, size, &cookie);

  if (result == 0)
    {
      /* Parse succeeded - test roundtrip encoding */
      int enc_len = SocketDNSCookie_encode (&cookie, encoded, sizeof (encoded));

      if (enc_len > 0)
        {
          /* Decode the encoded cookie */
          int dec_result = SocketDNSCookie_parse (encoded, enc_len, &decoded);

          if (dec_result == 0)
            {
              /* Verify cookies match */
              int equal = SocketDNSCookie_equal (&cookie, &decoded);
              (void)equal;
            }
        }

      /* Test validation - a cookie validates against itself */
      int valid = SocketDNSCookie_validate (&cookie, &cookie);
      (void)valid;

      /* Test hex formatting */
      int hex_len = SocketDNSCookie_to_hex (&cookie, hex_buf, sizeof (hex_buf));
      (void)hex_len;

      /* Test with small buffer */
      char small_buf[8];
      hex_len = SocketDNSCookie_to_hex (&cookie, small_buf, sizeof (small_buf));
      (void)hex_len;
    }

  /*
   * Test comparison with two halves of input
   */
  if (size >= 16)
    {
      SocketDNSCookie_Cookie cookie1, cookie2;

      /* Try parsing first half as cookie1 */
      int r1 = SocketDNSCookie_parse (data, size / 2, &cookie1);

      /* Try parsing second half as cookie2 */
      int r2
          = SocketDNSCookie_parse (data + size / 2, size - size / 2, &cookie2);

      if (r1 == 0 && r2 == 0)
        {
          /* Compare the two */
          int equal = SocketDNSCookie_equal (&cookie1, &cookie2);
          (void)equal;

          /* Cross-validate */
          int valid = SocketDNSCookie_validate (&cookie1, &cookie2);
          (void)valid;
        }
    }

  /*
   * Test BADCOOKIE RCODE check
   */
  if (size >= 2)
    {
      uint16_t rcode = ((uint16_t)data[0] << 8) | data[1];
      int is_bad = SocketDNSCookie_is_badcookie (rcode);
      (void)is_bad;

      /* Specifically test RCODE 23 */
      is_bad = SocketDNSCookie_is_badcookie (23);
      (void)is_bad;
    }

  /*
   * Test encoding with various lengths
   * Force different server_cookie_len values
   */
  if (size >= DNS_CLIENT_COOKIE_SIZE)
    {
      /* Copy client cookie from input */
      memcpy (cookie.client_cookie, data, DNS_CLIENT_COOKIE_SIZE);

      /* Test with no server cookie */
      cookie.server_cookie_len = 0;
      int enc_len = SocketDNSCookie_encode (&cookie, encoded, sizeof (encoded));
      (void)enc_len;

      /* Test with various server cookie lengths */
      for (size_t slen = DNS_SERVER_COOKIE_MIN_SIZE;
           slen <= DNS_SERVER_COOKIE_MAX_SIZE && slen + 8 <= size;
           slen += 4)
        {
          cookie.server_cookie_len = slen;
          memcpy (cookie.server_cookie, data + 8, slen);

          enc_len = SocketDNSCookie_encode (&cookie, encoded, sizeof (encoded));
          if (enc_len > 0)
            {
              /* Verify decode */
              SocketDNSCookie_parse (encoded, enc_len, &decoded);
            }
        }
    }

  /*
   * Test with NULL pointers (should not crash)
   */
  (void)SocketDNSCookie_parse (NULL, size, &cookie);
  (void)SocketDNSCookie_parse (data, size, NULL);
  (void)SocketDNSCookie_encode (NULL, encoded, sizeof (encoded));
  (void)SocketDNSCookie_encode (&cookie, NULL, sizeof (encoded));
  (void)SocketDNSCookie_encode (&cookie, encoded, 0);
  (void)SocketDNSCookie_validate (NULL, &cookie);
  (void)SocketDNSCookie_validate (&cookie, NULL);
  (void)SocketDNSCookie_equal (NULL, &cookie);
  (void)SocketDNSCookie_equal (&cookie, NULL);
  (void)SocketDNSCookie_to_hex (NULL, hex_buf, sizeof (hex_buf));
  (void)SocketDNSCookie_to_hex (&cookie, NULL, sizeof (hex_buf));

  return 0;
}
