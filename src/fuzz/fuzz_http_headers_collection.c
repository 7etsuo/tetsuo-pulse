/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_http_headers_collection.c - HTTP Headers collection operations fuzzer
 *
 * Stress-tests SocketHTTP_Headers_T operations with fuzzed header names and
 * values:
 * - Headers_new, Headers_clear
 * - Headers_add, Headers_add_n, Headers_set
 * - Headers_get, Headers_get_all, Headers_get_int
 * - Headers_has, Headers_contains (token search)
 * - Headers_remove, Headers_remove_all
 * - Headers_count, Headers_at, Headers_iterate
 *
 * Tests boundary conditions, validation, and memory safety under stress.
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make
 * fuzz_http_headers_collection
 * ./fuzz_http_headers_collection corpus/http_headers/ -fork=16 -max_len=8192
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHTTP.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Callback for header iteration */
static int
header_callback (const char *name,
                 size_t name_len,
                 const char *value,
                 size_t value_len,
                 void *userdata)
{
  size_t *count = (size_t *)userdata;
  (*count)++;

  /* Access the data to ensure it's valid */
  (void)name;
  (void)name_len;
  (void)value;
  (void)value_len;

  /* Continue iteration */
  return 0;
}

/* Callback that stops early */
static int
header_callback_stop (const char *name,
                      size_t name_len,
                      const char *value,
                      size_t value_len,
                      void *userdata)
{
  size_t *count = (size_t *)userdata;
  (*count)++;

  (void)name;
  (void)name_len;
  (void)value;
  (void)value_len;

  /* Stop after 5 headers */
  return (*count >= 5) ? 1 : 0;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena = NULL;
  SocketHTTP_Headers_T headers = NULL;

  /* Skip empty input */
  if (size == 0)
    return 0;

  arena = Arena_new ();
  if (!arena)
    return 0;

  TRY
  {
    /* Create headers collection */
    headers = SocketHTTP_Headers_new (arena);
    if (!headers)
      {
        Arena_dispose (&arena);
        return 0;
      }

    /* ====================================================================
     * Test 1: Add headers with fuzzed names and values
     * ==================================================================== */
    {
      size_t offset = 0;

      /* Add multiple fuzzed headers */
      for (int i = 0; i < 50 && offset + 4 < size; i++)
        {
          /* Use fuzz data to determine name and value lengths */
          size_t name_len = (data[offset] % 64) + 1;       /* 1-64 chars */
          size_t value_len = (data[offset + 1] % 128) + 1; /* 1-128 chars */

          offset += 2;

          if (offset + name_len + value_len > size)
            break;

          /* Extract name and value from fuzz data */
          char name[256];
          char value[512];

          size_t actual_name_len
              = (name_len < sizeof (name) - 1) ? name_len : sizeof (name) - 1;
          size_t actual_value_len = (value_len < sizeof (value) - 1)
                                        ? value_len
                                        : sizeof (value) - 1;

          if (offset + actual_name_len + actual_value_len > size)
            break;

          memcpy (name, data + offset, actual_name_len);
          name[actual_name_len] = '\0';
          offset += actual_name_len;

          memcpy (value, data + offset, actual_value_len);
          value[actual_value_len] = '\0';
          offset += actual_value_len;

          /* Test add with null-terminated strings */
          int result = SocketHTTP_Headers_add (headers, name, value);
          (void)result;

          /* Test add_n with explicit lengths */
          result = SocketHTTP_Headers_add_n (
              headers, name, actual_name_len, value, actual_value_len);
          (void)result;
        }
    }

    /* ====================================================================
     * Test 2: Header retrieval operations
     * ==================================================================== */
    {
      /* Get count */
      size_t count = SocketHTTP_Headers_count (headers);
      (void)count;

      /* Try to get headers with fuzzed names */
      char search_name[128];
      size_t search_len
          = (size > sizeof (search_name) - 1) ? sizeof (search_name) - 1 : size;
      memcpy (search_name, data, search_len);
      search_name[search_len] = '\0';

      /* Test get */
      const char *value = SocketHTTP_Headers_get (headers, search_name);
      (void)value;

      /* Test has */
      int has = SocketHTTP_Headers_has (headers, search_name);
      (void)has;

      /* Test get_all */
      const char *values[16];
      size_t found
          = SocketHTTP_Headers_get_all (headers, search_name, values, 16);
      (void)found;

      /* Test get_int */
      int64_t int_value;
      int int_result
          = SocketHTTP_Headers_get_int (headers, search_name, &int_value);
      (void)int_result;

      /* Test contains (token search) */
      if (size > 2)
        {
          char token[64];
          size_t token_len = (data[0] % 32) + 1;
          if (1 + token_len < size)
            {
              memcpy (token, data + 1, token_len);
              token[token_len] = '\0';
              int contains
                  = SocketHTTP_Headers_contains (headers, search_name, token);
              (void)contains;
            }
        }
    }

    /* ====================================================================
     * Test 3: Header iteration
     * ==================================================================== */
    {
      /* Iterate all headers */
      size_t callback_count = 0;
      int iter_result = SocketHTTP_Headers_iterate (
          headers, header_callback, &callback_count);
      (void)iter_result;

      /* Iterate with early stop */
      callback_count = 0;
      iter_result = SocketHTTP_Headers_iterate (
          headers, header_callback_stop, &callback_count);
      (void)iter_result;

      /* Access by index */
      size_t count = SocketHTTP_Headers_count (headers);
      for (size_t i = 0; i < count && i < 100; i++)
        {
          const SocketHTTP_Header *header = SocketHTTP_Headers_at (headers, i);
          if (header)
            {
              (void)header->name;
              (void)header->name_len;
              (void)header->value;
              (void)header->value_len;
            }
        }

      /* Test out-of-bounds access */
      const SocketHTTP_Header *invalid
          = SocketHTTP_Headers_at (headers, count + 1);
      (void)invalid;
      invalid = SocketHTTP_Headers_at (headers, SIZE_MAX);
      (void)invalid;
    }

    /* ====================================================================
     * Test 4: Header set (replace) operations
     * ==================================================================== */
    {
      /* Set headers with fuzzed data */
      char name[64];
      char value[256];
      size_t name_len = (size > sizeof (name) - 1) ? sizeof (name) - 1 : size;
      memcpy (name, data, name_len);
      name[name_len] = '\0';

      size_t value_offset = name_len;
      size_t value_len = (size > value_offset)
                             ? ((size - value_offset > sizeof (value) - 1)
                                    ? sizeof (value) - 1
                                    : size - value_offset)
                             : 0;
      if (value_len > 0)
        {
          memcpy (value, data + value_offset, value_len);
          value[value_len] = '\0';

          /* Test set */
          int result = SocketHTTP_Headers_set (headers, name, value);
          (void)result;

          /* Set again to replace */
          result = SocketHTTP_Headers_set (headers, name, "replacement");
          (void)result;
        }
    }

    /* ====================================================================
     * Test 5: Header removal operations
     * ==================================================================== */
    {
      /* Remove with fuzzed name */
      char remove_name[64];
      size_t remove_len
          = (size > sizeof (remove_name) - 1) ? sizeof (remove_name) - 1 : size;
      memcpy (remove_name, data, remove_len);
      remove_name[remove_len] = '\0';

      /* Test remove (first match) */
      int removed = SocketHTTP_Headers_remove (headers, remove_name);
      (void)removed;

      /* Test remove_all */
      int removed_count = SocketHTTP_Headers_remove_all (headers, remove_name);
      (void)removed_count;
    }

    /* ====================================================================
     * Test 6: Add known headers with fuzzed values
     * ==================================================================== */
    {
      const char *known_headers[]
          = { "Content-Type",    "Content-Length", "Accept",
              "Accept-Encoding", "Authorization",  "Cache-Control",
              "Connection",      "Host",           "User-Agent",
              "X-Custom-Header", "Set-Cookie",     "Cookie" };

      char fuzz_value[512];
      size_t fuzz_len
          = (size > sizeof (fuzz_value) - 1) ? sizeof (fuzz_value) - 1 : size;
      memcpy (fuzz_value, data, fuzz_len);
      fuzz_value[fuzz_len] = '\0';

      for (size_t i = 0; i < sizeof (known_headers) / sizeof (known_headers[0]);
           i++)
        {
          SocketHTTP_Headers_add (headers, known_headers[i], fuzz_value);
          SocketHTTP_Headers_get (headers, known_headers[i]);
          SocketHTTP_Headers_has (headers, known_headers[i]);
        }
    }

    /* ====================================================================
     * Test 7: Integer header parsing
     * ==================================================================== */
    {
      /* Add Content-Length with various fuzzed values */
      char int_value[32];
      int int_len = snprintf (int_value,
                              sizeof (int_value),
                              "%.*s",
                              (int)(size > 20 ? 20 : size),
                              (const char *)data);
      if (int_len > 0 && (size_t)int_len < sizeof (int_value))
        {
          SocketHTTP_Headers_set (headers, "Content-Length", int_value);
          int64_t parsed;
          SocketHTTP_Headers_get_int (headers, "Content-Length", &parsed);
        }

      /* Test known integer values */
      const char *int_values[]
          = { "0",  "1",   "100",    "65535",   "2147483647",
              "-1", "abc", "123abc", "  456  ", "" };
      for (size_t i = 0; i < sizeof (int_values) / sizeof (int_values[0]); i++)
        {
          SocketHTTP_Headers_set (headers, "X-Int-Header", int_values[i]);
          int64_t parsed;
          SocketHTTP_Headers_get_int (headers, "X-Int-Header", &parsed);
        }
    }

    /* ====================================================================
     * Test 8: Token contains search
     * ==================================================================== */
    {
      /* Add Connection header with tokens */
      SocketHTTP_Headers_set (headers, "Connection", "keep-alive, upgrade");
      SocketHTTP_Headers_contains (headers, "Connection", "keep-alive");
      SocketHTTP_Headers_contains (headers, "Connection", "upgrade");
      SocketHTTP_Headers_contains (headers, "Connection", "close");

      /* Test with fuzzed token */
      char fuzz_token[64];
      size_t token_len
          = (size > sizeof (fuzz_token) - 1) ? sizeof (fuzz_token) - 1 : size;
      memcpy (fuzz_token, data, token_len);
      fuzz_token[token_len] = '\0';
      SocketHTTP_Headers_contains (headers, "Connection", fuzz_token);

      /* Add Accept-Encoding with fuzzed tokens */
      char encoding_header[256];
      int hlen = snprintf (encoding_header,
                           sizeof (encoding_header),
                           "gzip, deflate, %.*s",
                           (int)(size > 100 ? 100 : size),
                           (const char *)data);
      if (hlen > 0 && (size_t)hlen < sizeof (encoding_header))
        {
          SocketHTTP_Headers_set (headers, "Accept-Encoding", encoding_header);
          SocketHTTP_Headers_contains (headers, "Accept-Encoding", "gzip");
          SocketHTTP_Headers_contains (headers, "Accept-Encoding", fuzz_token);
        }
    }

    /* ====================================================================
     * Test 9: Clear and reuse
     * ==================================================================== */
    {
      /* Get count before clear */
      size_t before = SocketHTTP_Headers_count (headers);
      (void)before;

      /* Clear all headers */
      SocketHTTP_Headers_clear (headers);

      /* Get count after clear */
      size_t after = SocketHTTP_Headers_count (headers);
      (void)after;

      /* Add headers again */
      SocketHTTP_Headers_add (headers, "New-Header", "new-value");
      SocketHTTP_Headers_add (headers, "Another-Header", "another-value");

      /* Verify count */
      size_t final = SocketHTTP_Headers_count (headers);
      (void) final;
    }

    /* ====================================================================
     * Test 10: Duplicate headers
     * ==================================================================== */
    {
      /* Clear and add duplicate headers */
      SocketHTTP_Headers_clear (headers);

      /* Add multiple Set-Cookie headers (common use case) */
      SocketHTTP_Headers_add (headers, "Set-Cookie", "session=abc123");
      SocketHTTP_Headers_add (headers, "Set-Cookie", "user=john");
      SocketHTTP_Headers_add (headers, "Set-Cookie", "tracking=xyz");

      /* Get all values */
      const char *cookies[10];
      size_t cookie_count
          = SocketHTTP_Headers_get_all (headers, "Set-Cookie", cookies, 10);
      (void)cookie_count;

      /* Iterate and count Set-Cookie headers */
      size_t count = SocketHTTP_Headers_count (headers);
      for (size_t i = 0; i < count; i++)
        {
          const SocketHTTP_Header *h = SocketHTTP_Headers_at (headers, i);
          (void)h;
        }

      /* Remove first Set-Cookie */
      SocketHTTP_Headers_remove (headers, "Set-Cookie");

      /* Remove all remaining */
      SocketHTTP_Headers_remove_all (headers, "Set-Cookie");
    }
  }
  EXCEPT (SocketHTTP_Failed)
  {
    /* Expected on validation failures */
  }
  EXCEPT (SocketHTTP_InvalidHeader)
  {
    /* Expected on invalid header names/values */
  }
  EXCEPT (Arena_Failed)
  {
    /* Expected on memory exhaustion */
  }
  END_TRY;

  Arena_dispose (&arena);

  return 0;
}
