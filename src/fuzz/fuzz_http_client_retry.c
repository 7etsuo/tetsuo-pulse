/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_http_client_retry.c - HTTP Client Retry Logic Fuzzer
 *
 * Targets SocketHTTPClient-retry.c (0% coverage → goal: 80%+)
 *
 * Fuzzing strategy:
 * - Retry delay calculation with edge case attempt counts
 * - Retry decision logic for different error types
 * - Status code retry logic with various HTTP methods
 * - Idempotency checks (RFC 7231 compliance)
 * - Exponential backoff and jitter validation
 * - Configuration edge cases (timeouts, max retries)
 *
 * Key functions under test:
 * - httpclient_calculate_retry_delay()
 * - httpclient_should_retry_error()
 * - httpclient_should_retry_status()
 * - httpclient_should_retry_status_with_method()
 * - is_idempotent_method() [static, tested indirectly]
 *
 * Attack surfaces:
 * - Integer overflow in delay calculation
 * - Configuration mismatch (zero/negative delays)
 * - Non-idempotent method retry (SECURITY: could duplicate POST)
 * - Invalid method values
 * - Extreme retry counts
 *
 * Build: CC=clang cmake -B build -DENABLE_FUZZING=ON && cmake --build build
 * --target fuzz_http_client_retry Run: ./build/fuzz_http_client_retry
 * corpus/http_client_retry/ -fork=8 -max_len=256
 */

#include <stdlib.h>
#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHTTPClient.h"
#include "http/SocketHTTPClient-private.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

/* Suppress GCC clobbered warnings for TRY/EXCEPT */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/* Input format: configuration bytes followed by test data */
typedef struct
{
  uint8_t enable_retry;
  uint8_t max_retries;
  uint16_t initial_delay_ms;
  uint16_t max_delay_ms;
  uint8_t retry_on_connection_error;
  uint8_t retry_on_timeout;
  uint8_t retry_on_5xx;
  uint8_t attempt;      /* Retry attempt count */
  uint8_t error_type;   /* SocketHTTPClient_Error */
  uint16_t status_code; /* HTTP status code */
  uint8_t http_method;  /* SocketHTTP_Method */
} FuzzInput;

#define MIN_INPUT_SIZE sizeof (FuzzInput)

/**
 * Test retry delay calculation with various configurations
 */
static void
test_retry_delay_calculation (Arena_T arena, const FuzzInput *input)
{
  SocketHTTPClient_Config config;
  SocketHTTPClient_T client;
  volatile int delay = 0;

  (void)arena; /* Not used in this test */

  /* Initialize config with fuzzer input */
  SocketHTTPClient_config_defaults (&config);
  config.enable_retry = input->enable_retry;
  config.max_retries = input->max_retries;
  config.retry_initial_delay_ms = input->initial_delay_ms;
  config.retry_max_delay_ms = input->max_delay_ms;
  config.retry_on_connection_error = input->retry_on_connection_error;
  config.retry_on_timeout = input->retry_on_timeout;
  config.retry_on_5xx = input->retry_on_5xx;

  TRY
  {
    client = SocketHTTPClient_new (&config);
    if (client == NULL)
      RETURN;

    /* Test delay calculation with various attempt counts */
    delay = httpclient_calculate_retry_delay (client, input->attempt);

    /* Validate delay is within reasonable bounds */
    assert (delay >= 0);
    if (config.retry_max_delay_ms > 0)
      {
        /* Should not exceed configured max (with small jitter tolerance) */
        assert (delay <= config.retry_max_delay_ms * 2);
      }

    /* Test edge cases */
    (void)httpclient_calculate_retry_delay (client, 0);    /* Zero attempts */
    (void)httpclient_calculate_retry_delay (client, -1);   /* Negative */
    (void)httpclient_calculate_retry_delay (client, 255);  /* Very large */
    (void)httpclient_calculate_retry_delay (client, 1000); /* Excessive */

    /* Test with NULL client (should be safe) */
    (void)httpclient_calculate_retry_delay (NULL, input->attempt);

    SocketHTTPClient_free (&client);
  }
  EXCEPT (SocketHTTPClient_Failed)
  {
    /* Expected for some invalid configs */
  }
  END_TRY;
}

/**
 * Test error type retry decision logic
 */
static void
test_retry_error_decision (Arena_T arena, const FuzzInput *input)
{
  SocketHTTPClient_Config config;
  SocketHTTPClient_T client;
  volatile int should_retry = 0;

  (void)arena; /* Not used in this test */

  SocketHTTPClient_config_defaults (&config);
  config.enable_retry = input->enable_retry;
  config.retry_on_connection_error = input->retry_on_connection_error;
  config.retry_on_timeout = input->retry_on_timeout;

  TRY
  {
    client = SocketHTTPClient_new (&config);
    if (client == NULL)
      RETURN;

    /* Test with fuzzer-provided error type */
    SocketHTTPClient_Error error
        = (SocketHTTPClient_Error)(input->error_type % 11);
    should_retry = httpclient_should_retry_error (client, error);
    (void)should_retry; /* Use result to avoid warning */

    /* Test all error types systematically */
    (void)httpclient_should_retry_error (client, HTTPCLIENT_OK);
    (void)httpclient_should_retry_error (client, HTTPCLIENT_ERROR_DNS);
    (void)httpclient_should_retry_error (client, HTTPCLIENT_ERROR_CONNECT);
    (void)httpclient_should_retry_error (client, HTTPCLIENT_ERROR_TLS);
    (void)httpclient_should_retry_error (client, HTTPCLIENT_ERROR_TIMEOUT);
    (void)httpclient_should_retry_error (client, HTTPCLIENT_ERROR_PROTOCOL);
    (void)httpclient_should_retry_error (client,
                                         HTTPCLIENT_ERROR_TOO_MANY_REDIRECTS);
    (void)httpclient_should_retry_error (client,
                                         HTTPCLIENT_ERROR_RESPONSE_TOO_LARGE);
    (void)httpclient_should_retry_error (client, HTTPCLIENT_ERROR_CANCELLED);
    (void)httpclient_should_retry_error (client,
                                         HTTPCLIENT_ERROR_OUT_OF_MEMORY);
    (void)httpclient_should_retry_error (client,
                                         HTTPCLIENT_ERROR_LIMIT_EXCEEDED);

    /* Test with NULL client */
    should_retry = httpclient_should_retry_error (NULL, error);
    assert (should_retry == 0); /* NULL client should never retry */

    SocketHTTPClient_free (&client);
  }
  EXCEPT (SocketHTTPClient_Failed)
  {
    /* Expected for some configs */
  }
  END_TRY;
}

/**
 * Test status code retry with different HTTP methods (idempotency checks)
 *
 * SECURITY CRITICAL: Must never retry non-idempotent methods (POST, PATCH)
 * on 5xx errors, as this could duplicate mutations on the server.
 * RFC 7231 §4.2.2 defines idempotent methods.
 */
static void
test_retry_status_with_method (Arena_T arena, const FuzzInput *input)
{
  SocketHTTPClient_Config config;
  SocketHTTPClient_T client;
  volatile int should_retry = 0;

  (void)arena; /* Not used in this test */

  SocketHTTPClient_config_defaults (&config);
  config.enable_retry = input->enable_retry;
  config.retry_on_5xx = input->retry_on_5xx;

  TRY
  {
    client = SocketHTTPClient_new (&config);
    if (client == NULL)
      RETURN;

    /* Map fuzzer input to valid HTTP method */
    SocketHTTP_Method method = (SocketHTTP_Method)(input->http_method % 9);
    int status = input->status_code;

    /* Test with fuzzer inputs */
    should_retry
        = httpclient_should_retry_status_with_method (client, status, method);

    /* SECURITY: Verify non-idempotent methods are NEVER retried on 5xx */
    if (status >= 500 && status < 600)
      {
        int retry_post = httpclient_should_retry_status_with_method (
            client, status, HTTP_METHOD_POST);
        int retry_patch = httpclient_should_retry_status_with_method (
            client, status, HTTP_METHOD_PATCH);

        /* These must NEVER be retried even if retry_on_5xx is enabled */
        assert (retry_post == 0);
        assert (retry_patch == 0);
      }

    /* Test idempotent methods - should follow retry_on_5xx config */
    (void)httpclient_should_retry_status_with_method (
        client, 500, HTTP_METHOD_GET);
    (void)httpclient_should_retry_status_with_method (
        client, 503, HTTP_METHOD_HEAD);
    (void)httpclient_should_retry_status_with_method (
        client, 502, HTTP_METHOD_PUT);
    (void)httpclient_should_retry_status_with_method (
        client, 504, HTTP_METHOD_DELETE);
    (void)httpclient_should_retry_status_with_method (
        client, 500, HTTP_METHOD_OPTIONS);
    (void)httpclient_should_retry_status_with_method (
        client, 500, HTTP_METHOD_TRACE);

    /* Test non-5xx status codes (should not retry regardless of method) */
    (void)httpclient_should_retry_status_with_method (client, 200, method);
    (void)httpclient_should_retry_status_with_method (client, 404, method);
    (void)httpclient_should_retry_status_with_method (client, 301, method);

    /* Test edge cases */
    (void)httpclient_should_retry_status_with_method (client, 0, method);
    (void)httpclient_should_retry_status_with_method (client, -1, method);
    (void)httpclient_should_retry_status_with_method (client, 999, method);

    /* Test legacy wrapper (assumes GET) */
    should_retry = httpclient_should_retry_status (client, status);
    int retry_with_get = httpclient_should_retry_status_with_method (
        client, status, HTTP_METHOD_GET);
    /* Legacy wrapper should match GET behavior */
    assert (should_retry == retry_with_get);

    /* Test with NULL client */
    should_retry
        = httpclient_should_retry_status_with_method (NULL, status, method);
    assert (should_retry == 0);

    SocketHTTPClient_free (&client);
  }
  EXCEPT (SocketHTTPClient_Failed)
  {
    /* Expected */
  }
  END_TRY;
}

/**
 * Test comprehensive retry scenarios combining errors, statuses, and configs
 */
static void
test_retry_combinations (Arena_T arena, const FuzzInput *input)
{
  SocketHTTPClient_Config config;
  SocketHTTPClient_T client;

  (void)arena; /* Not used in this test */

  SocketHTTPClient_config_defaults (&config);
  config.enable_retry = input->enable_retry;
  config.max_retries = input->max_retries % 10; /* Limit to reasonable value */
  config.retry_initial_delay_ms = input->initial_delay_ms;
  config.retry_max_delay_ms = input->max_delay_ms;
  config.retry_on_connection_error = input->retry_on_connection_error;
  config.retry_on_timeout = input->retry_on_timeout;
  config.retry_on_5xx = input->retry_on_5xx;

  TRY
  {
    client = SocketHTTPClient_new (&config);
    if (client == NULL)
      RETURN;

    /* Simulate retry loop with different attempt counts */
    for (int attempt = 1; attempt <= 5; attempt++)
      {
        int delay = httpclient_calculate_retry_delay (client, attempt);

        /* Verify delay increases (exponential backoff) or stays bounded */
        if (config.retry_max_delay_ms > 0)
          {
            assert (delay >= 0);
            assert (delay <= config.retry_max_delay_ms * 2); /* Allow jitter */
          }

        /* Test error retry decisions at each attempt */
        (void)httpclient_should_retry_error (client, HTTPCLIENT_ERROR_CONNECT);
        (void)httpclient_should_retry_error (client, HTTPCLIENT_ERROR_TIMEOUT);
      }

    /* Test overflow protection with very large attempt counts */
    for (int attempt = 100; attempt <= 1000; attempt += 100)
      {
        int delay = httpclient_calculate_retry_delay (client, attempt);
        assert (delay >= 0); /* Should never overflow to negative */
      }

    SocketHTTPClient_free (&client);
  }
  EXCEPT (SocketHTTPClient_Failed)
  {
    /* Expected for invalid configs */
  }
  END_TRY;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  volatile Arena_T arena = NULL;

  /* Need minimum size for FuzzInput */
  if (size < MIN_INPUT_SIZE)
    return 0;

  /* Copy to aligned local storage to avoid UBSan misaligned access errors.
   * The fuzzer-provided data buffer may not be properly aligned for the
   * struct's uint16_t members. Zero-initialize first to ensure padding
   * bytes are deterministic. */
  FuzzInput input_storage = { 0 };
  memcpy (&input_storage, data, sizeof (FuzzInput));
  const FuzzInput *input = &input_storage;

  TRY
  {
    arena = Arena_new ();
    if (arena == NULL)
      RETURN 0;

    /* Test 1: Retry delay calculation */
    test_retry_delay_calculation ((Arena_T)arena, input);

    /* Test 2: Error retry decisions */
    test_retry_error_decision ((Arena_T)arena, input);

    /* Test 3: Status code + method retry (idempotency) */
    test_retry_status_with_method ((Arena_T)arena, input);

    /* Test 4: Combined scenarios */
    test_retry_combinations ((Arena_T)arena, input);

    Arena_dispose ((Arena_T *)&arena);
  }
  EXCEPT (Arena_Failed)
  {
    if (arena)
      Arena_dispose ((Arena_T *)&arena);
  }
  END_TRY;

  return 0;
}
