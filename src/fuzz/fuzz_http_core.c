/**
 * fuzz_http_core.c - Comprehensive SocketHTTP.h core utilities fuzzer
 *
 * Tests all core HTTP parsing and validation functions from SocketHTTP.h:
 * - HTTP method parsing and validation
 * - HTTP version parsing
 * - Header name/value validation
 * - Content coding parsing
 * - Accept header quality value parsing
 * - Media type parsing and matching
 * - Status code utilities
 *
 * These functions are foundational and used throughout the HTTP stack.
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_http_core
 * ./fuzz_http_core corpus/http_core/ -fork=16 -max_len=4096
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHTTP.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena = NULL;

  /* Skip empty input */
  if (size == 0)
    return 0;

  arena = Arena_new ();
  if (!arena)
    return 0;

  TRY
  {
    /* Null-terminate fuzzed data for string functions */
    char *fuzz_str = Arena_alloc (arena, size + 1, __FILE__, __LINE__);
    if (!fuzz_str)
      {
        Arena_dispose (&arena);
        return 0;
      }
    memcpy (fuzz_str, data, size);
    fuzz_str[size] = '\0';

    /* ====================================================================
     * Test 1: HTTP Method Parsing and Validation
     * ==================================================================== */
    {
      /* Parse method from fuzzed string */
      SocketHTTP_Method method = SocketHTTP_method_parse (fuzz_str, size);
      (void)method;

      /* Also test with 0 length to use strlen */
      method = SocketHTTP_method_parse (fuzz_str, 0);

      /* Get method properties */
      SocketHTTP_MethodProperties props = SocketHTTP_method_properties (method);
      (void)props;

      /* Validate method token */
      int valid = SocketHTTP_method_valid (fuzz_str, size);
      (void)valid;

      /* Get method name */
      const char *name = SocketHTTP_method_name (method);
      (void)name;

      /* Test known methods with fuzzed string appended */
      const char *methods[] = {"GET", "POST", "PUT", "DELETE", "HEAD",
                               "OPTIONS", "PATCH", "CONNECT", "TRACE"};
      for (size_t i = 0; i < sizeof (methods) / sizeof (methods[0]); i++)
        {
          char combined[256];
          int len = snprintf (combined, sizeof (combined), "%s%.*s",
                             methods[i], (int)(size > 100 ? 100 : size), fuzz_str);
          if (len > 0 && (size_t)len < sizeof (combined))
            {
              SocketHTTP_method_parse (combined, len);
              SocketHTTP_method_valid (combined, len);
            }
        }
    }

    /* ====================================================================
     * Test 2: HTTP Version Parsing
     * ==================================================================== */
    {
      /* Parse version from fuzzed string */
      SocketHTTP_Version version = SocketHTTP_version_parse (fuzz_str, size);
      (void)version;

      /* Also test with 0 length */
      version = SocketHTTP_version_parse (fuzz_str, 0);

      /* Get version string */
      const char *ver_str = SocketHTTP_version_string (version);
      (void)ver_str;

      /* Test version prefixes with fuzzed suffix */
      const char *prefixes[] = {"HTTP/", "HTTP/0", "HTTP/1", "HTTP/1.", "HTTP/2"};
      for (size_t i = 0; i < sizeof (prefixes) / sizeof (prefixes[0]); i++)
        {
          char combined[256];
          int len = snprintf (combined, sizeof (combined), "%s%.*s",
                             prefixes[i], (int)(size > 100 ? 100 : size), fuzz_str);
          if (len > 0 && (size_t)len < sizeof (combined))
            {
              SocketHTTP_version_parse (combined, len);
            }
        }
    }

    /* ====================================================================
     * Test 3: Header Name Validation
     * ==================================================================== */
    {
      /* Validate fuzzed data as header name */
      int valid = SocketHTTP_header_name_valid (fuzz_str, size);
      (void)valid;

      /* Test with various lengths */
      for (size_t len = 0; len < size && len < 256; len++)
        {
          SocketHTTP_header_name_valid (fuzz_str, len);
        }

      /* Test known valid names with fuzzed suffix */
      const char *valid_names[] = {"Content-Type", "Authorization", "Accept",
                                   "X-Custom-Header", "X-"};
      for (size_t i = 0; i < sizeof (valid_names) / sizeof (valid_names[0]); i++)
        {
          char combined[512];
          int len = snprintf (combined, sizeof (combined), "%s%.*s",
                             valid_names[i], (int)(size > 200 ? 200 : size), fuzz_str);
          if (len > 0 && (size_t)len < sizeof (combined))
            {
              SocketHTTP_header_name_valid (combined, len);
            }
        }
    }

    /* ====================================================================
     * Test 4: Header Value Validation
     * ==================================================================== */
    {
      /* Validate fuzzed data as header value */
      int valid = SocketHTTP_header_value_valid (fuzz_str, size);
      (void)valid;

      /* Test with various lengths */
      for (size_t len = 0; len < size && len < 1024; len += 10)
        {
          SocketHTTP_header_value_valid (fuzz_str, len);
        }

      /* Test header values with embedded control characters */
      char value_with_crlf[512];
      int vlen = snprintf (value_with_crlf, sizeof (value_with_crlf),
                          "prefix\r\n%.*s", (int)(size > 200 ? 200 : size), fuzz_str);
      if (vlen > 0 && (size_t)vlen < sizeof (value_with_crlf))
        {
          SocketHTTP_header_value_valid (value_with_crlf, vlen);
        }
    }

    /* ====================================================================
     * Test 5: Content Coding Parsing
     * ==================================================================== */
    {
      /* Parse coding from fuzzed string */
      SocketHTTP_Coding coding = SocketHTTP_coding_parse (fuzz_str, size);
      (void)coding;

      /* Also test with 0 length */
      coding = SocketHTTP_coding_parse (fuzz_str, 0);

      /* Get coding name */
      const char *coding_name = SocketHTTP_coding_name (coding);
      (void)coding_name;

      /* Test all standard codings */
      const char *codings[] = {"identity", "chunked", "gzip", "deflate",
                               "compress", "br", "x-gzip", "x-deflate"};
      for (size_t i = 0; i < sizeof (codings) / sizeof (codings[0]); i++)
        {
          SocketHTTP_Coding c = SocketHTTP_coding_parse (codings[i], 0);
          SocketHTTP_coding_name (c);

          /* Test with fuzzed suffix */
          char combined[256];
          int len = snprintf (combined, sizeof (combined), "%s%.*s",
                             codings[i], (int)(size > 100 ? 100 : size), fuzz_str);
          if (len > 0 && (size_t)len < sizeof (combined))
            {
              SocketHTTP_coding_parse (combined, len);
            }
        }
    }

    /* ====================================================================
     * Test 6: Accept Header Quality Value Parsing
     * ==================================================================== */
    {
      SocketHTTP_QualityValue results[32];

      /* Parse fuzzed string as Accept header */
      size_t count = SocketHTTP_parse_accept (fuzz_str, size, results, 32, arena);
      (void)count;

      /* Also test with 0 length */
      count = SocketHTTP_parse_accept (fuzz_str, 0, results, 32, arena);

      /* Test with various Accept header patterns */
      const char *accept_patterns[] = {
          "text/html",
          "text/html, application/json",
          "text/html; q=0.9, application/json; q=1.0",
          "*/*",
          "text/*; q=0.5",
          "application/json; q=0.9, text/html; q=0.8, */*; q=0.1",
          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      };

      for (size_t i = 0; i < sizeof (accept_patterns) / sizeof (accept_patterns[0]); i++)
        {
          SocketHTTP_parse_accept (accept_patterns[i], 0, results, 32, arena);

          /* Test pattern with fuzzed suffix */
          char combined[1024];
          int len = snprintf (combined, sizeof (combined), "%s, %.*s",
                             accept_patterns[i], (int)(size > 500 ? 500 : size), fuzz_str);
          if (len > 0 && (size_t)len < sizeof (combined))
            {
              SocketHTTP_parse_accept (combined, len, results, 32, arena);
            }
        }

      /* Test with fuzzed q values */
      if (size >= 4)
        {
          char qvalue_test[256];
          int len = snprintf (qvalue_test, sizeof (qvalue_test),
                             "text/html; q=%c.%c%c%c",
                             '0' + (data[0] % 2), '0' + (data[1] % 10),
                             '0' + (data[2] % 10), '0' + (data[3] % 10));
          if (len > 0 && (size_t)len < sizeof (qvalue_test))
            {
              SocketHTTP_parse_accept (qvalue_test, len, results, 32, arena);
            }
        }
    }

    /* ====================================================================
     * Test 7: Media Type Parsing
     * ==================================================================== */
    {
      SocketHTTP_MediaType media_type;

      /* Parse fuzzed string as media type */
      int result = SocketHTTP_MediaType_parse (fuzz_str, size, &media_type, arena);
      (void)result;

      /* Also test with 0 length */
      result = SocketHTTP_MediaType_parse (fuzz_str, 0, &media_type, arena);

      /* Test standard media types */
      const char *media_types[] = {
          "text/plain",
          "text/html; charset=utf-8",
          "application/json",
          "application/json; charset=utf-8",
          "multipart/form-data; boundary=----WebKitFormBoundary",
          "application/octet-stream",
          "image/png",
          "application/x-www-form-urlencoded",
      };

      for (size_t i = 0; i < sizeof (media_types) / sizeof (media_types[0]); i++)
        {
          SocketHTTP_MediaType_parse (media_types[i], 0, &media_type, arena);

          /* Test with fuzzed parameters */
          char combined[512];
          int len = snprintf (combined, sizeof (combined), "%s; %.*s",
                             media_types[i], (int)(size > 200 ? 200 : size), fuzz_str);
          if (len > 0 && (size_t)len < sizeof (combined))
            {
              SocketHTTP_MediaType_parse (combined, len, &media_type, arena);
            }
        }

      /* Test malformed media types */
      const char *malformed[] = {
          "",
          "/",
          "text/",
          "/html",
          "text",
          "text/plain/extra",
          "text/plain; charset",
          "text/plain; charset=",
          "text/plain; =value",
          "text/plain; ; charset=utf-8",
      };

      for (size_t i = 0; i < sizeof (malformed) / sizeof (malformed[0]); i++)
        {
          SocketHTTP_MediaType_parse (malformed[i], 0, &media_type, arena);
        }
    }

    /* ====================================================================
     * Test 8: Media Type Matching
     * ==================================================================== */
    {
      SocketHTTP_MediaType media_type;

      /* Parse a known good media type */
      SocketHTTP_MediaType_parse ("text/html; charset=utf-8", 0, &media_type, arena);

      /* Match against fuzzed pattern */
      int matches = SocketHTTP_MediaType_matches (&media_type, fuzz_str);
      (void)matches;

      /* Test with standard patterns */
      const char *patterns[] = {"text/html", "text/*", "*/*", "application/json"};
      for (size_t i = 0; i < sizeof (patterns) / sizeof (patterns[0]); i++)
        {
          SocketHTTP_MediaType_matches (&media_type, patterns[i]);
        }

      /* Parse fuzzed and match against patterns */
      if (SocketHTTP_MediaType_parse (fuzz_str, size, &media_type, arena) == 0)
        {
          for (size_t i = 0; i < sizeof (patterns) / sizeof (patterns[0]); i++)
            {
              SocketHTTP_MediaType_matches (&media_type, patterns[i]);
            }
        }
    }

    /* ====================================================================
     * Test 9: Status Code Utilities
     * ==================================================================== */
    {
      /* Test with fuzzed bytes as status codes */
      for (size_t i = 0; i < size && i < 100; i++)
        {
          int code;
          if (i + 1 < size)
            {
              code = ((int)data[i] << 8) | data[i + 1];
            }
          else
            {
              code = data[i];
            }

          /* Test status utilities */
          int valid = SocketHTTP_status_valid (code);
          (void)valid;

          SocketHTTP_StatusCategory cat = SocketHTTP_status_category (code);
          (void)cat;

          const char *reason = SocketHTTP_status_reason (code);
          (void)reason;
        }

      /* Test all valid status code categories */
      int codes[] = {100, 101, 200, 201, 204, 301, 302, 304, 400, 401, 403, 404, 500, 502, 503};
      for (size_t i = 0; i < sizeof (codes) / sizeof (codes[0]); i++)
        {
          SocketHTTP_status_valid (codes[i]);
          SocketHTTP_status_category (codes[i]);
          SocketHTTP_status_reason (codes[i]);
        }

      /* Test boundary cases */
      int edge_codes[] = {0, 99, 100, 199, 200, 299, 300, 399, 400, 499, 500, 599, 600, -1, 1000};
      for (size_t i = 0; i < sizeof (edge_codes) / sizeof (edge_codes[0]); i++)
        {
          SocketHTTP_status_valid (edge_codes[i]);
          SocketHTTP_status_category (edge_codes[i]);
          SocketHTTP_status_reason (edge_codes[i]);
        }
    }
  }
  EXCEPT (SocketHTTP_Failed)
  {
    /* Expected on malformed input */
  }
  EXCEPT (SocketHTTP_ParseError)
  {
    /* Expected on parse errors */
  }
  EXCEPT (Arena_Failed)
  {
    /* Expected on memory exhaustion */
  }
  END_TRY;

  Arena_dispose (&arena);

  return 0;
}
