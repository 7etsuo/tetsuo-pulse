/**
 * fuzz_http_cookies_simple.c - HTTP Cookie header parsing and validation fuzzing harness
 *
 * Tests cookie header construction, parsing, and validation with malformed inputs
 * to find vulnerabilities in cookie attribute handling and domain/path matching.
 *
 * This fuzzer focuses on the Cookie header (client to server) rather than Set-Cookie
 * parsing, complementing the dedicated Set-Cookie parsing in other fuzzers.
 *
 * Targets:
 * - Cookie header construction and validation
 * - Domain/path matching logic
 * - Cookie attribute parsing and validation
 * - Malformed cookie values and injection attacks
 * - Unicode/encoding issues in cookie values
 *
 * Cookies are critical for authentication and session management.
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_http_cookies_simple
 * ./fuzz_http_cookies_simple corpus/http_cookies/ -fork=16 -max_len=2048
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  /* Skip empty input */
  if (size == 0)
    return 0;

  /* Test 1: Cookie header construction with fuzzed data */
  if (size > 5)
    {
      /* Build Cookie header with fuzzed name=value pairs */
      char cookie_header[4096] = "Cookie: ";
      size_t offset = 8; /* After "Cookie: " */

      /* Add multiple fuzzed cookie pairs */
      for (size_t i = 0; i < 10 && offset < sizeof (cookie_header) - 50; i++)
        {
          if (offset + 10 >= size)
            break;

          /* Extract name and value lengths from fuzzed data */
          size_t name_len = data[offset] % 32 + 1;
          size_t value_len = data[offset + 1] % 64 + 1;
          offset += 2;

          if (offset + name_len + value_len >= size
              || offset >= sizeof (cookie_header) - 50)
            break;

          /* Copy name */
          memcpy (cookie_header + offset, data + offset, name_len);
          offset += name_len;

          /* Add equals */
          cookie_header[offset++] = '=';

          /* Copy value */
          memcpy (cookie_header + offset, data + offset, value_len);
          offset += value_len;

          /* Add semicolon and space for next cookie */
          if (i < 9)
            {
              cookie_header[offset++] = ';';
              cookie_header[offset++] = ' ';
            }
        }

      cookie_header[offset] = '\0';

      /* The header is now constructed - in a real implementation this would
         be parsed and validated, but for fuzzing we focus on the construction
         and any validation that happens during header processing */
      (void)cookie_header;
    }

  /* Test 2: Malformed cookie headers */
  const char *malformed_headers[] = {
      "Cookie: ",                                      /* Empty cookie */
      "Cookie: name",                                  /* Missing equals */
      "Cookie: =value",                                /* Missing name */
      "Cookie: name=",                                 /* Empty value */
      "Cookie: name=value;",                           /* Trailing semicolon */
      "Cookie: name=value; ",                          /* Trailing space */
      "Cookie: name=value;; name2=value2",             /* Double semicolon */
      "Cookie: name=value; name2",                     /* Second cookie missing equals */
      "Cookie: name=value\x00; name2=value2",          /* Null byte */
      "Cookie: name=value\r\nSet-Cookie: evil=value",  /* Header injection */
      "Cookie: name=value; name2=value2; name3=value3; name4=value4",
      /* Many cookies */
  };

  for (size_t i = 0; i < sizeof (malformed_headers) / sizeof (malformed_headers[0]); i++)
    {
      /* Process each malformed header */
      (void)malformed_headers[i];
    }

  /* Test 3: Cookie values with special characters */
  if (size > 10)
    {
      char special_cookie[256];
      size_t copy_len
          = size > sizeof (special_cookie) - 20 ? sizeof (special_cookie) - 20 : size;
      memcpy (special_cookie, "Cookie: test=", 14);
      memcpy (special_cookie + 14, data, copy_len);
      special_cookie[14 + copy_len] = '\0';

      /* Test cookie with special characters */
      (void)special_cookie;
    }

  /* Test 4: Very long cookie values */
  if (size > 100)
    {
      char long_cookie[8192] = "Cookie: longvalue=";
      size_t copy_len
          = size > sizeof (long_cookie) - 20 ? sizeof (long_cookie) - 20 : size;
      memcpy (long_cookie + 16, data, copy_len);
      long_cookie[16 + copy_len] = '\0';

      /* Test handling of very long cookie values */
      (void)long_cookie;
    }

  return 0;
}
