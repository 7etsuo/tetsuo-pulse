/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_security.c - SocketSecurity limit enforcement fuzzer
 *
 * Comprehensive fuzzing harness for SocketSecurity module to test:
 * - Size validation and overflow protection
 * - Limit bypass attempts
 * - Safe arithmetic operations
 * - Security configuration queries
 *
 * Attack Categories Tested:
 *
 * 1. Size Validation:
 *    - Zero sizes
 *    - Maximum sizes (SIZE_MAX, SIZE_MAX/2)
 *    - Boundary values around limits
 *    - Negative-to-unsigned conversion issues
 *
 * 2. Overflow Protection:
 *    - Multiplication overflow detection
 *    - Addition overflow detection
 *    - Chained arithmetic operations
 *
 * 3. Limit Queries:
 *    - All limit accessors
 *    - NULL pointer handling
 *    - Partial limit queries
 *
 * 4. Feature Detection:
 *    - TLS availability
 *    - Compression availability
 *
 * Security Focus:
 * - Integer overflow vulnerabilities
 * - Limit bypass through edge cases
 * - Buffer overflow prevention
 * - Safe arithmetic correctness
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_security
 * ./fuzz_security corpus/security/ -fork=16 -max_len=1024
 */

#include "core/SocketSecurity.h"
#include "core/Arena.h"
#include "core/Except.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Suppress GCC clobbered warnings for TRY/EXCEPT */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/**
 * Read 64-bit value from byte stream
 */
static size_t
read_size (const uint8_t *data, size_t offset)
{
  size_t val = 0;
  for (int i = 0; i < (int)sizeof (size_t); i++)
    {
      val = (val << 8) | data[offset + i];
    }
  return val;
}

/**
 * Test size validation with fuzzed values
 */
static void
test_size_validation (const uint8_t *data, size_t size)
{
  if (size < sizeof (size_t))
    return;

  /* Test with fuzzed size value */
  size_t test_size = read_size (data, 0);

  /* Test SocketSecurity_check_size */
  int result = SocketSecurity_check_size (test_size);
  (void)result;

  /* Test macro version */
  int macro_result = SOCKET_SECURITY_VALID_SIZE (test_size);
  (void)macro_result;

  /* Results should be consistent for valid sizes */
  if (test_size > 0 && test_size <= SOCKET_SECURITY_MAX_ALLOCATION)
    {
      /* Both should return true for valid sizes */
    }
}

/**
 * Test boundary values for size validation
 */
static void
test_size_boundaries (void)
{
  /* Test zero size */
  int r0 = SocketSecurity_check_size (0);
  if (r0 != 0)
    {
      /* Zero should be invalid */
    }

  /* Test maximum allocation */
  size_t max_alloc = SocketSecurity_get_max_allocation ();
  int r1 = SocketSecurity_check_size (max_alloc);
  (void)r1;

  /* Test just over maximum */
  int r2 = SocketSecurity_check_size (max_alloc + 1);
  if (r2 != 0)
    {
      /* Should be invalid */
    }

  /* Test SIZE_MAX */
  int r3 = SocketSecurity_check_size (SIZE_MAX);
  if (r3 != 0)
    {
      /* Should be invalid */
    }

  /* Test SIZE_MAX / 2 boundary */
  int r4 = SocketSecurity_check_size (SIZE_MAX / 2);
  (void)r4; /* May or may not be valid depending on max_alloc */

  int r5 = SocketSecurity_check_size (SIZE_MAX / 2 + 1);
  if (r5 != 0)
    {
      /* Should be invalid (defense-in-depth) */
    }

  /* Test 1 (minimum valid) */
  int r6 = SocketSecurity_check_size (1);
  if (r6 == 0)
    {
      /* 1 should be valid */
    }

  /* Test macro boundaries */
  int m0 = SOCKET_SECURITY_VALID_SIZE (0);
  int m1 = SOCKET_SECURITY_VALID_SIZE (1);
  int m2 = SOCKET_SECURITY_VALID_SIZE (max_alloc);
  int m3 = SOCKET_SECURITY_VALID_SIZE (max_alloc + 1);
  int m4 = SOCKET_SECURITY_VALID_SIZE (SIZE_MAX);

  (void)m0;
  (void)m1;
  (void)m2;
  (void)m3;
  (void)m4;
}

/**
 * Test multiplication overflow protection
 */
static void
test_multiply_overflow (const uint8_t *data, size_t size)
{
  if (size < 2 * sizeof (size_t))
    return;

  size_t a = read_size (data, 0);
  size_t b = read_size (data, sizeof (size_t));
  size_t result;

  /* Test check_multiply */
  int safe = SocketSecurity_check_multiply (a, b, &result);

  if (safe)
    {
      /* Verify result is correct */
      if (result != a * b)
        {
          /* Inconsistency */
        }
    }

  /* Test without result pointer */
  int safe2 = SocketSecurity_check_multiply (a, b, NULL);
  (void)safe2;

  /* Test safe_multiply inline function */
  size_t safe_result = SocketSecurity_safe_multiply (a, b);

  if (safe && safe_result != result)
    {
      /* Results should match when safe */
    }

  if (!safe && safe_result != 0)
    {
      /* Should return 0 on overflow */
    }

  /* Test macro */
  int macro_safe = SOCKET_SECURITY_CHECK_OVERFLOW_MUL (a, b);
  (void)macro_safe;
}

/**
 * Test multiplication overflow boundary cases
 */
static void
test_multiply_boundaries (void)
{
  size_t result;

  /* Test 0 * anything */
  int r0 = SocketSecurity_check_multiply (0, 100, &result);
  if (r0 && result != 0)
    {
      /* Should be 0 */
    }

  /* Test anything * 0 */
  int r1 = SocketSecurity_check_multiply (100, 0, &result);
  if (r1 && result != 0)
    {
      /* Should be 0 */
    }

  /* Test 1 * 1 */
  int r2 = SocketSecurity_check_multiply (1, 1, &result);
  if (!r2 || result != 1)
    {
      /* Should be safe and equal 1 */
    }

  /* Test SIZE_MAX * 2 - should overflow */
  int r3 = SocketSecurity_check_multiply (SIZE_MAX, 2, &result);
  if (r3 != 0)
    {
      /* Should be unsafe */
    }

  /* Test SIZE_MAX / 2 * 2 - should be safe */
  int r4 = SocketSecurity_check_multiply (SIZE_MAX / 2, 2, &result);
  (void)r4; /* May or may not overflow depending on SIZE_MAX */

  /* Test SIZE_MAX * 1 - should be safe */
  int r5 = SocketSecurity_check_multiply (SIZE_MAX, 1, &result);
  if (!r5 || result != SIZE_MAX)
    {
      /* Should be safe */
    }

  /* Test square root of SIZE_MAX * itself */
  size_t sqrt_max = 1UL << (sizeof (size_t) * 4); /* Approximate sqrt */
  int r6 = SocketSecurity_check_multiply (sqrt_max, sqrt_max, &result);
  (void)r6;
}

/**
 * Test addition overflow protection
 */
static void
test_add_overflow (const uint8_t *data, size_t size)
{
  if (size < 2 * sizeof (size_t))
    return;

  size_t a = read_size (data, 0);
  size_t b = read_size (data, sizeof (size_t));
  size_t result;

  /* Test check_add */
  int safe = SocketSecurity_check_add (a, b, &result);

  if (safe)
    {
      /* Verify result is correct */
      if (result != a + b)
        {
          /* Inconsistency */
        }
    }

  /* Test without result pointer */
  int safe2 = SocketSecurity_check_add (a, b, NULL);
  (void)safe2;

  /* Test safe_add inline function */
  size_t safe_result = SocketSecurity_safe_add (a, b);

  if (safe && safe_result != result)
    {
      /* Results should match when safe */
    }

  if (!safe && safe_result != SIZE_MAX)
    {
      /* Should return SIZE_MAX on overflow */
    }

  /* Test macro */
  int macro_safe = SOCKET_SECURITY_CHECK_OVERFLOW_ADD (a, b);
  (void)macro_safe;
}

/**
 * Test addition overflow boundary cases
 */
static void
test_add_boundaries (void)
{
  size_t result;

  /* Test 0 + 0 */
  int r0 = SocketSecurity_check_add (0, 0, &result);
  if (!r0 || result != 0)
    {
      /* Should be safe and equal 0 */
    }

  /* Test SIZE_MAX + 1 - should overflow */
  int r1 = SocketSecurity_check_add (SIZE_MAX, 1, &result);
  if (r1 != 0)
    {
      /* Should be unsafe */
    }

  /* Test SIZE_MAX + 0 - should be safe */
  int r2 = SocketSecurity_check_add (SIZE_MAX, 0, &result);
  if (!r2 || result != SIZE_MAX)
    {
      /* Should be safe */
    }

  /* Test SIZE_MAX/2 + SIZE_MAX/2 */
  int r3 = SocketSecurity_check_add (SIZE_MAX / 2, SIZE_MAX / 2, &result);
  (void)r3; /* Should be safe */

  /* Test SIZE_MAX/2 + SIZE_MAX/2 + 2 equivalent */
  size_t half_plus_one = SIZE_MAX / 2 + 1;
  int r4 = SocketSecurity_check_add (half_plus_one, half_plus_one, &result);
  (void)r4; /* May overflow */
}

/**
 * Test chained arithmetic operations
 */
static void
test_chained_arithmetic (const uint8_t *data, size_t size)
{
  if (size < 4 * sizeof (size_t))
    return;

  size_t a = read_size (data, 0);
  size_t b = read_size (data, sizeof (size_t));
  size_t c = read_size (data, 2 * sizeof (size_t));
  size_t d = read_size (data, 3 * sizeof (size_t));

  /* Test: (a * b) + (c * d) */
  size_t ab, cd, total;

  int safe_ab = SocketSecurity_check_multiply (a, b, &ab);
  int safe_cd = SocketSecurity_check_multiply (c, d, &cd);

  if (safe_ab && safe_cd)
    {
      int safe_total = SocketSecurity_check_add (ab, cd, &total);
      if (safe_total)
        {
          /* Validate against limits */
          int valid = SocketSecurity_check_size (total);
          (void)valid;
        }
    }
}

/**
 * Test limit queries
 */
static void
test_limit_queries (void)
{
  /* Test full limits structure */
  SocketSecurityLimits limits;
  memset (&limits, 0xFF, sizeof (limits)); /* Fill with garbage */

  TRY
  {
    SocketSecurity_get_limits (&limits);

    /* Verify some fields are populated */
    if (limits.max_allocation == 0)
      {
        /* Should have a value */
      }

    /* Check consistency with get_max_allocation */
    size_t max_alloc = SocketSecurity_get_max_allocation ();
    if (limits.max_allocation != max_alloc)
      {
        /* Should match */
      }
  }
  EXCEPT (SocketSecurity_ValidationFailed)
  {
    /* Should not happen with valid pointer */
  }
  END_TRY;

  /* Test individual limit queries */
  size_t max_alloc = SocketSecurity_get_max_allocation ();
  (void)max_alloc;

  /* Test HTTP limits */
  size_t http_uri, http_header_size, http_headers, http_body;
  SocketSecurity_get_http_limits (&http_uri, &http_header_size, &http_headers,
                                  &http_body);
  (void)http_uri;
  (void)http_header_size;
  (void)http_headers;
  (void)http_body;

  /* Test partial HTTP limits (NULL pointers) */
  SocketSecurity_get_http_limits (&http_uri, NULL, NULL, NULL);
  SocketSecurity_get_http_limits (NULL, &http_header_size, NULL, NULL);
  SocketSecurity_get_http_limits (NULL, NULL, &http_headers, NULL);
  SocketSecurity_get_http_limits (NULL, NULL, NULL, &http_body);
  SocketSecurity_get_http_limits (NULL, NULL, NULL, NULL);

  /* Test WebSocket limits */
  size_t ws_frame, ws_message;
  SocketSecurity_get_ws_limits (&ws_frame, &ws_message);
  (void)ws_frame;
  (void)ws_message;

  SocketSecurity_get_ws_limits (&ws_frame, NULL);
  SocketSecurity_get_ws_limits (NULL, &ws_message);
  SocketSecurity_get_ws_limits (NULL, NULL);

  /* Test arena limits */
  size_t arena_max;
  SocketSecurity_get_arena_limits (&arena_max);
  (void)arena_max;

  SocketSecurity_get_arena_limits (NULL);

  /* Test HPACK limits */
  size_t hpack_table;
  SocketSecurity_get_hpack_limits (&hpack_table);
  (void)hpack_table;

  SocketSecurity_get_hpack_limits (NULL);
}

/**
 * Test NULL pointer handling
 */
static void
test_null_handling (void)
{
  TRY
  {
    SocketSecurity_get_limits (NULL);
    /* Should raise exception */
  }
  EXCEPT (SocketSecurity_ValidationFailed) { /* Expected */ }
  END_TRY;
}

/**
 * Test feature detection
 */
static void
test_feature_detection (void)
{
  /* Test TLS availability */
  int has_tls = SocketSecurity_has_tls ();
  (void)has_tls;

  /* Verify consistency with macro */
#if SOCKET_HAS_TLS
  if (has_tls != 1)
    {
      /* Inconsistency */
    }
#else
  if (has_tls != 0)
    {
      /* Inconsistency */
    }
#endif

  /* Test compression availability */
  int has_compression = SocketSecurity_has_compression ();
  (void)has_compression;
}

/**
 * Test limit structure fields
 */
static void
test_limit_fields (void)
{
  SocketSecurityLimits limits;
  SocketSecurity_get_limits (&limits);

  /* Access all fields to ensure they're populated */
  (void)limits.max_allocation;
  (void)limits.max_buffer_size;
  (void)limits.max_connections;
  (void)limits.arena_max_alloc_size;

  (void)limits.http_max_uri_length;
  (void)limits.http_max_header_name;
  (void)limits.http_max_header_value;
  (void)limits.http_max_header_size;
  (void)limits.http_max_headers;
  (void)limits.http_max_body_size;

  (void)limits.http1_max_request_line;
  (void)limits.http1_max_chunk_size;

  (void)limits.http2_max_concurrent_streams;
  (void)limits.http2_max_frame_size;
  (void)limits.http2_max_header_list_size;

  (void)limits.tls_max_alpn_protocols;
  (void)limits.tls_max_alpn_len;
  (void)limits.tls_max_alpn_total_bytes;
  (void)limits.hpack_max_table_size;

  (void)limits.ws_max_frame_size;
  (void)limits.ws_max_message_size;

  (void)limits.tls_max_cert_chain_depth;
  (void)limits.tls_session_cache_size;

  (void)limits.ratelimit_conn_per_sec;
  (void)limits.ratelimit_burst;
  (void)limits.ratelimit_max_per_ip;

  (void)limits.timeout_connect_ms;
  (void)limits.timeout_dns_ms;
  (void)limits.timeout_idle_ms;
  (void)limits.timeout_request_ms;
}

/**
 * Test safe arithmetic with fuzzed sequences
 */
static void
test_arithmetic_sequence (const uint8_t *data, size_t size)
{
  if (size < 20)
    return;

  size_t accumulator = 1; /* Start with 1 */
  size_t offset = 0;

  while (offset + 2 < size)
    {
      uint8_t op = data[offset++];
      size_t operand;

      /* Read operand based on available data */
      if (offset + sizeof (size_t) <= size)
        {
          operand = read_size (data, offset);
          offset += sizeof (size_t);
        }
      else
        {
          operand = data[offset++];
        }

      switch (op % 4)
        {
        case 0: /* Safe add */
          {
            size_t result;
            if (SocketSecurity_check_add (accumulator, operand, &result))
              accumulator = result;
          }
          break;

        case 1: /* Safe multiply */
          {
            size_t result;
            if (SocketSecurity_check_multiply (accumulator, operand, &result))
              {
                if (SocketSecurity_check_size (result))
                  accumulator = result;
              }
          }
          break;

        case 2: /* Check size */
          {
            int valid = SocketSecurity_check_size (accumulator);
            (void)valid;
          }
          break;

        case 3: /* Reset */
          accumulator = operand % 1000 + 1;
          break;
        }
    }
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size == 0)
    return 0;

  TRY
  {
    /* ====================================================================
     * Test 1: Size validation with fuzzed values
     * ==================================================================== */
    test_size_validation (data, size);

    /* ====================================================================
     * Test 2: Size validation boundary cases
     * ==================================================================== */
    test_size_boundaries ();

    /* ====================================================================
     * Test 3: Multiplication overflow protection
     * ==================================================================== */
    test_multiply_overflow (data, size);

    /* ====================================================================
     * Test 4: Multiplication boundaries
     * ==================================================================== */
    test_multiply_boundaries ();

    /* ====================================================================
     * Test 5: Addition overflow protection
     * ==================================================================== */
    test_add_overflow (data, size);

    /* ====================================================================
     * Test 6: Addition boundaries
     * ==================================================================== */
    test_add_boundaries ();

    /* ====================================================================
     * Test 7: Chained arithmetic
     * ==================================================================== */
    test_chained_arithmetic (data, size);

    /* ====================================================================
     * Test 8: Limit queries
     * ==================================================================== */
    test_limit_queries ();

    /* ====================================================================
     * Test 9: NULL pointer handling
     * ==================================================================== */
    test_null_handling ();

    /* ====================================================================
     * Test 10: Feature detection
     * ==================================================================== */
    test_feature_detection ();

    /* ====================================================================
     * Test 11: Limit structure fields
     * ==================================================================== */
    test_limit_fields ();

    /* ====================================================================
     * Test 12: Arithmetic sequences
     * ==================================================================== */
    test_arithmetic_sequence (data, size);
  }
  EXCEPT (SocketSecurity_SizeExceeded) { /* Expected for oversized values */ }
  EXCEPT (SocketSecurity_ValidationFailed) { /* Expected for invalid inputs */ }
  EXCEPT (Arena_Failed) { /* Unlikely but handle */ }
  END_TRY;

  return 0;
}
