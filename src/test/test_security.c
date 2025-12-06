/**
 * test_security.c - Comprehensive Security Test Suite
 *
 * Part of the Socket Library
 *
 * Tests security measures across all components:
 * - Integer overflow protection
 * - Buffer overflow prevention
 * - Request smuggling rejection (HTTP/1.1)
 * - Header injection prevention
 * - Invalid UTF-8 handling
 * - Size limit enforcement
 * - Secure memory operations
 *
 * This test suite verifies that security measures implemented across
 * the library are functioning correctly.
 */

#include "test/Test.h"
#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "core/SocketCrypto.h"
#include "core/SocketSecurity.h"
#include "core/SocketUTF8.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"
#include "socket/SocketBuf.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Security Limits Query Tests
 * ============================================================================ */

TEST (security_limits_populated)
{
  SocketSecurityLimits limits;
  memset (&limits, 0, sizeof (limits));

  SocketSecurity_get_limits (&limits);

  /* Verify all limits are populated with non-zero values */
  ASSERT (limits.max_allocation > 0);
  ASSERT (limits.max_buffer_size > 0);
  ASSERT (limits.max_connections > 0);
  ASSERT (limits.http_max_uri_length > 0);
  ASSERT (limits.http_max_header_size > 0);
  ASSERT (limits.http_max_headers > 0);
  ASSERT (limits.http2_max_concurrent_streams > 0);
  ASSERT (limits.ws_max_frame_size > 0);
  ASSERT (limits.ws_max_message_size > 0);
  ASSERT (limits.timeout_connect_ms > 0);
  ASSERT (limits.timeout_dns_ms > 0);
}

TEST (security_limits_reasonable)
{
  SocketSecurityLimits limits;
  SocketSecurity_get_limits (&limits);

  /* Verify limits are reasonable (not impossibly large) */
  ASSERT (limits.max_allocation <= 1024 * 1024 * 1024); /* <= 1GB */
  ASSERT (limits.http_max_uri_length <= 64 * 1024);     /* <= 64KB */
  ASSERT (limits.http_max_headers <= 1000);             /* <= 1000 headers */
  ASSERT (limits.http2_max_concurrent_streams <= 1000); /* <= 1000 streams */
}

TEST (security_http_limits_query)
{
  size_t max_uri, max_header_size, max_headers, max_body;

  SocketSecurity_get_http_limits (&max_uri, &max_header_size, &max_headers,
                                  &max_body);

  ASSERT (max_uri > 0);
  ASSERT (max_header_size > 0);
  ASSERT (max_headers > 0);
  ASSERT (max_body > 0);

  /* Verify consistency with documented values */
  ASSERT_EQ (SOCKETHTTP_MAX_URI_LEN, max_uri);
  ASSERT_EQ (SOCKETHTTP_MAX_HEADER_SIZE, max_header_size);
  ASSERT_EQ (SOCKETHTTP_MAX_HEADERS, max_headers);
}

TEST (security_ws_limits_query)
{
  size_t max_frame, max_message;

  SocketSecurity_get_ws_limits (&max_frame, &max_message);

  ASSERT (max_frame > 0);
  ASSERT (max_message > 0);
  ASSERT (max_message >= max_frame); /* Message limit >= frame limit */
}

/* ============================================================================
 * Integer Overflow Protection Tests
 * ============================================================================ */

TEST (security_overflow_multiply_safe)
{
  size_t result;

  /* Normal multiplication should succeed */
  ASSERT (SocketSecurity_check_multiply (100, 200, &result));
  ASSERT_EQ (20000, result);

  /* Zero multiplication should succeed */
  ASSERT (SocketSecurity_check_multiply (0, 1000, &result));
  ASSERT_EQ (0, result);

  ASSERT (SocketSecurity_check_multiply (1000, 0, &result));
  ASSERT_EQ (0, result);
}

TEST (security_overflow_multiply_detects)
{
  size_t result = 12345; /* Set to non-zero to verify it's not modified */

  /* Multiplication that would overflow should fail */
  ASSERT (!SocketSecurity_check_multiply (SIZE_MAX, 2, &result));
  ASSERT_EQ (12345, result); /* Result unchanged on failure */

  ASSERT (!SocketSecurity_check_multiply (SIZE_MAX / 2 + 1, 2, &result));

  /* Large multiplication that would overflow */
  ASSERT (
      !SocketSecurity_check_multiply (SIZE_MAX / 1000 + 1, 1001, &result));
}

TEST (security_overflow_add_safe)
{
  size_t result;

  /* Normal addition should succeed */
  ASSERT (SocketSecurity_check_add (100, 200, &result));
  ASSERT_EQ (300, result);

  /* Zero addition should succeed */
  ASSERT (SocketSecurity_check_add (0, 1000, &result));
  ASSERT_EQ (1000, result);
}

TEST (security_overflow_add_detects)
{
  size_t result = 12345;

  /* Addition that would overflow should fail */
  ASSERT (!SocketSecurity_check_add (SIZE_MAX, 1, &result));
  ASSERT_EQ (12345, result);

  ASSERT (!SocketSecurity_check_add (SIZE_MAX - 100, 200, &result));
}

TEST (security_safe_multiply_inline)
{
  /* Normal case */
  ASSERT_EQ (20000, SocketSecurity_safe_multiply (100, 200));

  /* Zero cases */
  ASSERT_EQ (0, SocketSecurity_safe_multiply (0, 1000));
  ASSERT_EQ (0, SocketSecurity_safe_multiply (1000, 0));

  /* Overflow returns 0 */
  ASSERT_EQ (0, SocketSecurity_safe_multiply (SIZE_MAX, 2));
  ASSERT_EQ (0, SocketSecurity_safe_multiply (SIZE_MAX / 2 + 1, 2));
}

TEST (security_safe_add_inline)
{
  /* Normal case */
  ASSERT_EQ (300, SocketSecurity_safe_add (100, 200));

  /* Overflow returns SIZE_MAX */
  ASSERT_EQ (SIZE_MAX, SocketSecurity_safe_add (SIZE_MAX, 1));
  ASSERT_EQ (SIZE_MAX, SocketSecurity_safe_add (SIZE_MAX - 100, 200));
}

TEST (security_check_size_valid)
{
  /* Normal sizes should be valid */
  ASSERT (SocketSecurity_check_size (1));
  ASSERT (SocketSecurity_check_size (1024));
  ASSERT (SocketSecurity_check_size (1024 * 1024));
  ASSERT (SocketSecurity_check_size (SOCKET_SECURITY_MAX_ALLOCATION));
}

TEST (security_check_size_invalid)
{
  /* Zero size is invalid */
  ASSERT (!SocketSecurity_check_size (0));

  /* Sizes exceeding max allocation are invalid */
  ASSERT (!SocketSecurity_check_size (SOCKET_SECURITY_MAX_ALLOCATION + 1));

  /* Very large sizes (likely overflow) are invalid */
  ASSERT (!SocketSecurity_check_size (SIZE_MAX));
  ASSERT (!SocketSecurity_check_size (SIZE_MAX / 2 + 1));
}

TEST (security_validation_macros)
{
  /* SOCKET_SECURITY_VALID_SIZE */
  ASSERT (SOCKET_SECURITY_VALID_SIZE (1024));
  ASSERT (!SOCKET_SECURITY_VALID_SIZE (0));
  ASSERT (!SOCKET_SECURITY_VALID_SIZE (SOCKET_SECURITY_MAX_ALLOCATION + 1));

  /* SOCKET_SECURITY_CHECK_OVERFLOW_MUL */
  ASSERT (SOCKET_SECURITY_CHECK_OVERFLOW_MUL (100, 200));
  ASSERT (SOCKET_SECURITY_CHECK_OVERFLOW_MUL (SIZE_MAX, 0));
  ASSERT (!SOCKET_SECURITY_CHECK_OVERFLOW_MUL (SIZE_MAX, 2));

  /* SOCKET_SECURITY_CHECK_OVERFLOW_ADD */
  ASSERT (SOCKET_SECURITY_CHECK_OVERFLOW_ADD (100, 200));
  ASSERT (!SOCKET_SECURITY_CHECK_OVERFLOW_ADD (SIZE_MAX, 1));
}

/* ============================================================================
 * Arena Overflow Protection Tests
 * ============================================================================ */

TEST (security_arena_overflow_protection)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  volatile int exception_raised = 0;

  TRY
  {
    /* Try to allocate with values that would overflow */
    size_t huge_count = SIZE_MAX / sizeof (int) + 1;
    void *ptr = CALLOC (arena, huge_count, sizeof (int));
    (void)ptr;
    /* Should not reach here */
    ASSERT (0);
  }
  ELSE
  {
    /* Expected - overflow detected */
    exception_raised = 1;
  }
  END_TRY;

  ASSERT (exception_raised);
  Arena_dispose (&arena);
}

/* ============================================================================
 * Buffer Safety Tests
 * ============================================================================ */

TEST (security_buffer_bounds_checking)
{
  Arena_T arena = Arena_new ();
  SocketBuf_T buf = SocketBuf_new (arena, 1024);
  ASSERT_NOT_NULL (buf);

  /* Write exactly to capacity */
  char data[1024];
  memset (data, 'A', sizeof (data));
  size_t written = SocketBuf_write (buf, data, sizeof (data));
  ASSERT_EQ (1024, written);
  ASSERT_EQ (1024, SocketBuf_available (buf));

  /* Buffer should be full - additional writes should return 0 */
  written = SocketBuf_write (buf, "X", 1);
  ASSERT_EQ (0, written);

  /* Buffer should be full */
  ASSERT (SocketBuf_full (buf));
  ASSERT_EQ (0, SocketBuf_space (buf));

  SocketBuf_release (&buf);
  Arena_dispose (&arena);
}

TEST (security_buffer_read_bounds)
{
  Arena_T arena = Arena_new ();
  SocketBuf_T buf = SocketBuf_new (arena, 1024);
  ASSERT_NOT_NULL (buf);

  /* Write some data */
  const char *data = "Hello, World!";
  SocketBuf_write (buf, data, strlen (data));

  /* Read should not exceed available data */
  char readbuf[1024];
  size_t read_count = SocketBuf_read (buf, readbuf, sizeof (readbuf));
  ASSERT_EQ (strlen (data), read_count);

  /* Further reads should return 0 (no data) */
  read_count = SocketBuf_read (buf, readbuf, sizeof (readbuf));
  ASSERT_EQ (0, read_count);

  SocketBuf_release (&buf);
  Arena_dispose (&arena);
}

TEST (security_buffer_secure_clear)
{
  Arena_T arena = Arena_new ();
  SocketBuf_T buf = SocketBuf_new (arena, 256);
  ASSERT_NOT_NULL (buf);

  /* Write sensitive data */
  const char *secret = "super_secret_password_12345";
  SocketBuf_write (buf, secret, strlen (secret));
  ASSERT (SocketBuf_available (buf) > 0);

  /* Secure clear should zero the buffer */
  SocketBuf_secureclear (buf);
  ASSERT_EQ (0, SocketBuf_available (buf));

  SocketBuf_release (&buf);
  Arena_dispose (&arena);
}

/* ============================================================================
 * HTTP Security Tests - Request Smuggling Prevention
 * ============================================================================ */

TEST (security_http1_smuggling_cl_te_rejected)
{
  Arena_T arena = Arena_new ();
  SocketHTTP1_Parser_T parser
      = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);
  ASSERT_NOT_NULL (parser);

  /* Both Content-Length and Transfer-Encoding present = smuggling attempt */
  const char *request = "POST / HTTP/1.1\r\n"
                        "Host: test.com\r\n"
                        "Content-Length: 5\r\n"
                        "Transfer-Encoding: chunked\r\n"
                        "\r\n";

  size_t consumed;
  SocketHTTP1_Result result
      = SocketHTTP1_Parser_execute (parser, request, strlen (request),
                                    &consumed);

  /* Must be rejected as smuggling attempt */
  ASSERT_EQ (HTTP1_ERROR_SMUGGLING_DETECTED, result);

  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

TEST (security_http1_smuggling_te_cl_rejected)
{
  Arena_T arena = Arena_new ();
  SocketHTTP1_Parser_T parser
      = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);
  ASSERT_NOT_NULL (parser);

  /* Transfer-Encoding before Content-Length = also smuggling */
  const char *request = "POST / HTTP/1.1\r\n"
                        "Host: test.com\r\n"
                        "Transfer-Encoding: chunked\r\n"
                        "Content-Length: 5\r\n"
                        "\r\n";

  size_t consumed;
  SocketHTTP1_Result result
      = SocketHTTP1_Parser_execute (parser, request, strlen (request),
                                    &consumed);

  ASSERT_EQ (HTTP1_ERROR_SMUGGLING_DETECTED, result);

  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

/* ============================================================================
 * HTTP Security Tests - Header Injection Prevention
 * ============================================================================ */

TEST (security_http_header_name_injection_rejected)
{
  Arena_T arena = Arena_new ();
  SocketHTTP_Headers_T headers = SocketHTTP_Headers_new (arena);
  ASSERT_NOT_NULL (headers);

  /* Header name with CRLF injection attempt should be rejected */
  /* Returns -1 on invalid header name */
  int result = SocketHTTP_Headers_add (headers, "X-Injected\r\nEvil: Header",
                                       "value");
  ASSERT_EQ (-1, result);

  /* Headers freed when arena is disposed */
  Arena_dispose (&arena);
}

TEST (security_http_header_value_bare_cr_rejected)
{
  Arena_T arena = Arena_new ();
  SocketHTTP_Headers_T headers = SocketHTTP_Headers_new (arena);
  ASSERT_NOT_NULL (headers);

  /* Bare CR (not followed by LF) should be rejected per RFC 9110 */
  int result = SocketHTTP_Headers_add (headers, "X-Header", "value\rEvil");
  ASSERT_EQ (-1, result);

  /* Bare LF (not preceded by CR) should be rejected per RFC 9110 */
  result = SocketHTTP_Headers_add (headers, "X-Header", "value\nEvil");
  ASSERT_EQ (-1, result);

  /* Headers freed when arena is disposed */
  Arena_dispose (&arena);
}

TEST (security_http_header_name_invalid_chars_rejected)
{
  Arena_T arena = Arena_new ();
  SocketHTTP_Headers_T headers = SocketHTTP_Headers_new (arena);
  ASSERT_NOT_NULL (headers);

  /* Header name with space (invalid per RFC 9110) should be rejected */
  /* Returns -1 on invalid header name */
  int result = SocketHTTP_Headers_add (headers, "Invalid Header Name", "value");
  ASSERT_EQ (-1, result);

  /* Headers freed when arena is disposed */
  Arena_dispose (&arena);
}

/* ============================================================================
 * UTF-8 Security Tests
 * ============================================================================ */

TEST (security_utf8_overlong_rejected)
{
  /* Overlong encoding of ASCII character (security vulnerability) */

  /* Overlong NUL (U+0000 as 2 bytes instead of 1) */
  const unsigned char overlong_nul[] = { 0xC0, 0x80 };
  ASSERT_EQ (UTF8_OVERLONG,
             SocketUTF8_validate (overlong_nul, sizeof (overlong_nul)));

  /* Overlong '/' (U+002F as 2 bytes) - directory traversal attack vector */
  const unsigned char overlong_slash[] = { 0xC0, 0xAF };
  ASSERT_EQ (UTF8_OVERLONG,
             SocketUTF8_validate (overlong_slash, sizeof (overlong_slash)));
}

TEST (security_utf8_surrogate_rejected)
{
  /* Surrogate pairs are invalid in UTF-8 (security issue) */

  /* High surrogate U+D800 */
  const unsigned char high_surrogate[] = { 0xED, 0xA0, 0x80 };
  ASSERT_EQ (UTF8_SURROGATE,
             SocketUTF8_validate (high_surrogate, sizeof (high_surrogate)));

  /* Low surrogate U+DC00 */
  const unsigned char low_surrogate[] = { 0xED, 0xB0, 0x80 };
  ASSERT_EQ (UTF8_SURROGATE,
             SocketUTF8_validate (low_surrogate, sizeof (low_surrogate)));

  /* Maximum surrogate U+DFFF */
  const unsigned char max_surrogate[] = { 0xED, 0xBF, 0xBF };
  ASSERT_EQ (UTF8_SURROGATE,
             SocketUTF8_validate (max_surrogate, sizeof (max_surrogate)));
}

TEST (security_utf8_too_large_rejected)
{
  /* Code points > U+10FFFF are invalid */

  /* U+110000 (one past maximum) */
  const unsigned char too_large[] = { 0xF4, 0x90, 0x80, 0x80 };
  ASSERT_EQ (UTF8_TOO_LARGE,
             SocketUTF8_validate (too_large, sizeof (too_large)));
}

TEST (security_utf8_invalid_continuation_rejected)
{
  /* Invalid continuation byte */
  const unsigned char invalid[] = { 0xC2, 0x00 }; /* NUL instead of 0x80-0xBF */
  ASSERT_EQ (UTF8_INVALID, SocketUTF8_validate (invalid, sizeof (invalid)));

  /* Missing continuation */
  const unsigned char missing[] = { 0xE0, 0xA0 }; /* Need one more byte */
  ASSERT_EQ (UTF8_INCOMPLETE,
             SocketUTF8_validate (missing, sizeof (missing)));
}

/* ============================================================================
 * Cryptographic Security Tests
 * ============================================================================ */

TEST (security_secure_compare_constant_time)
{
  const char *secret1 = "secret_token_12345678";
  const char *secret2 = "secret_token_12345678";
  const char *different = "different_token_00000";

  /* Equal comparison should return 0 */
  ASSERT_EQ (0, SocketCrypto_secure_compare (secret1, secret2,
                                             strlen (secret1)));

  /* Different comparison should return non-zero */
  ASSERT_NE (0, SocketCrypto_secure_compare (secret1, different,
                                             strlen (secret1)));

  /* First byte difference should behave same as last byte difference */
  const char *diff_first = "Xecret_token_12345678";
  const char *diff_last = "secret_token_1234567X";

  /* Both should return non-zero (not equal) */
  ASSERT_NE (0, SocketCrypto_secure_compare (secret1, diff_first,
                                             strlen (secret1)));
  ASSERT_NE (0, SocketCrypto_secure_compare (secret1, diff_last,
                                             strlen (secret1)));
}

TEST (security_secure_clear)
{
  char buffer[64];

  /* Fill with recognizable pattern */
  memset (buffer, 0xAA, sizeof (buffer));

  /* Verify pattern is set */
  ASSERT_EQ (0xAA, (unsigned char)buffer[0]);
  ASSERT_EQ (0xAA, (unsigned char)buffer[63]);

  /* Secure clear */
  SocketCrypto_secure_clear (buffer, sizeof (buffer));

  /* Verify cleared (should be all zeros) */
  for (size_t i = 0; i < sizeof (buffer); i++)
    {
      ASSERT_EQ (0, buffer[i]);
    }
}

#ifdef SOCKET_HAS_TLS
TEST (security_random_bytes)
{
  unsigned char buf1[32];
  unsigned char buf2[32];

  /* Generate random bytes */
  int result1 = SocketCrypto_random_bytes (buf1, sizeof (buf1));
  int result2 = SocketCrypto_random_bytes (buf2, sizeof (buf2));

  ASSERT_EQ (0, result1);
  ASSERT_EQ (0, result2);

  /* Two random generations should be different (probabilistically) */
  ASSERT_NE (0, memcmp (buf1, buf2, sizeof (buf1)));
}
#endif

/* ============================================================================
 * Size Limit Enforcement Tests
 * ============================================================================ */

TEST (security_http1_line_limit_enforced)
{
  Arena_T arena = Arena_new ();

  /* Create parser with small line limit for testing */
  SocketHTTP1_Config config;
  SocketHTTP1_config_defaults (&config);
  config.max_request_line = 100; /* Very small limit */

  SocketHTTP1_Parser_T parser
      = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, &config, arena);
  ASSERT_NOT_NULL (parser);

  /* Request line exceeding limit */
  char long_request[256];
  memset (long_request, 0, sizeof (long_request));
  strcpy (long_request, "GET /");
  for (int i = 5; i < 150; i++)
    long_request[i] = 'a';
  strcat (long_request, " HTTP/1.1\r\n");

  size_t consumed;
  SocketHTTP1_Result result
      = SocketHTTP1_Parser_execute (parser, long_request, strlen (long_request),
                                    &consumed);

  /* Should be rejected as line too long */
  ASSERT_EQ (HTTP1_ERROR_LINE_TOO_LONG, result);

  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

TEST (security_http1_header_limit_enforced)
{
  Arena_T arena = Arena_new ();

  /* Create parser with small header limit for testing */
  SocketHTTP1_Config config;
  SocketHTTP1_config_defaults (&config);
  config.max_headers = 3; /* Very small limit */

  SocketHTTP1_Parser_T parser
      = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, &config, arena);
  ASSERT_NOT_NULL (parser);

  /* Request with too many headers */
  const char *request = "GET / HTTP/1.1\r\n"
                        "Header1: value1\r\n"
                        "Header2: value2\r\n"
                        "Header3: value3\r\n"
                        "Header4: value4\r\n" /* Exceeds limit */
                        "\r\n";

  size_t consumed;
  SocketHTTP1_Result result
      = SocketHTTP1_Parser_execute (parser, request, strlen (request),
                                    &consumed);

  /* Should be rejected as too many headers */
  ASSERT_EQ (HTTP1_ERROR_TOO_MANY_HEADERS, result);

  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

/* ============================================================================
 * Feature Detection Tests
 * ============================================================================ */

TEST (security_feature_detection)
{
  /* TLS detection */
  int has_tls = SocketSecurity_has_tls ();
#ifdef SOCKET_HAS_TLS
  ASSERT_EQ (1, has_tls);
#else
  ASSERT_EQ (0, has_tls);
#endif

  /* Compression detection */
  int has_compression = SocketSecurity_has_compression ();
  /* Just verify it returns a valid value */
  ASSERT (has_compression == 0 || has_compression == 1);
}

/* ============================================================================
 * Port Validation Tests
 * ============================================================================ */

TEST (security_port_validation)
{
  /* Valid ports */
  ASSERT (SOCKET_VALID_PORT (0));     /* Port 0 = any available port */
  ASSERT (SOCKET_VALID_PORT (1));
  ASSERT (SOCKET_VALID_PORT (80));
  ASSERT (SOCKET_VALID_PORT (443));
  ASSERT (SOCKET_VALID_PORT (8080));
  ASSERT (SOCKET_VALID_PORT (65535));

  /* Invalid ports */
  ASSERT (!SOCKET_VALID_PORT (-1));
  ASSERT (!SOCKET_VALID_PORT (65536));
  ASSERT (!SOCKET_VALID_PORT (100000));
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================ */

int
main (void)
{
  printf ("=== Socket Library Security Test Suite ===\n\n");

  Test_run_all ();

  printf ("\n=== Security Tests Complete ===\n");

  return Test_get_failures () > 0 ? 1 : 0;
}

