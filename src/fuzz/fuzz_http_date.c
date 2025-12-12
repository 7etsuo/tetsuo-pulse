/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_http_date.c - HTTP Date Parsing Fuzzing Harness
 *
 * Part of the Socket Library Fuzz Testing Suite
 *
 * Tests HTTP-date parsing with random/malformed input to find crashes,
 * memory safety issues, and unexpected behavior.
 */

#include "http/SocketHTTP.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/**
 * LibFuzzer entry point
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  /* Skip empty input */
  if (size == 0)
    return 0;

  /* Limit maximum size - HTTP dates are short */
  if (size > 128)
    return 0;

  time_t t;
  int result;

  /* Test date parsing */
  result = SocketHTTP_date_parse ((const char *)data, size, &t);

  /* If parse succeeded, test formatting back */
  if (result == 0)
    {
      char buf[SOCKETHTTP_DATE_BUFSIZE];
      int len = SocketHTTP_date_format (t, buf);
      (void)len;

      /* The formatted date should parse back successfully */
      time_t t2;
      result = SocketHTTP_date_parse (buf, 0, &t2);
      (void)result;
    }

  return 0;
}
