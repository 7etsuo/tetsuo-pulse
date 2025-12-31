/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_http_cookies_simple.c - Enterprise-grade HTTP Cookie header fuzzer
 *
 * Comprehensive fuzzing harness for HTTP Cookie header parsing and validation.
 * Tests the Cookie header sent from client to server (as opposed to Set-Cookie
 * responses which are tested in fuzz_http_cookies.c).
 *
 * Targets:
 * - Cookie header construction and parsing
 * - Cookie name=value pair extraction
 * - Multiple cookies in single header
 * - Cookie name validation (token per RFC 6265)
 * - Cookie value validation
 * - Special characters handling
 * - Security attacks (injection, overflow)
 * - Integration with HTTP/1.1 parser
 *
 * Security Focus:
 * - Cookie injection prevention
 * - Value escaping and validation
 * - Buffer overflow prevention
 * - Integer overflow in counts
 * - Null byte handling
 * - CRLF injection
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make
 * fuzz_http_cookies_simple
 * ./fuzz_http_cookies_simple corpus/http_cookies/ -fork=16 -max_len=8192
 */

#include <stdio.h>
#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/**
 * Parse cookie pairs from Cookie header value
 * Format: name1=value1; name2=value2; ...
 */
static void
parse_cookie_header (const char *value, size_t len, Arena_T arena)
{
  if (!value || len == 0)
    return;

  /* Make working copy */
  char *copy = Arena_alloc (arena, len + 1, __FILE__, __LINE__);
  if (!copy)
    return;

  memcpy (copy, value, len);
  copy[len] = '\0';

  /* Parse cookie pairs */
  char *saveptr = NULL;
  char *pair = strtok_r (copy, ";", &saveptr);

  int cookie_count = 0;
  while (pair && cookie_count < 100)
    {
      /* Skip leading whitespace */
      while (*pair && (*pair == ' ' || *pair == '\t'))
        pair++;

      /* Find equals sign */
      char *equals = strchr (pair, '=');
      if (equals)
        {
          /* Extract name */
          size_t name_len = equals - pair;
          char *name = pair;

          /* Trim trailing whitespace from name */
          while (name_len > 0
                 && (name[name_len - 1] == ' ' || name[name_len - 1] == '\t'))
            name_len--;

          /* Extract value */
          char *value_start = equals + 1;
          size_t value_len = strlen (value_start);

          /* Trim trailing whitespace from value */
          while (value_len > 0
                 && (value_start[value_len - 1] == ' '
                     || value_start[value_len - 1] == '\t'))
            value_len--;

          /* Validate name (should be token per RFC 6265) */
          int valid_name = (name_len > 0);
          for (size_t i = 0; i < name_len && valid_name; i++)
            {
              char c = name[i];
              /* Token characters per RFC 7230 */
              if (c <= 0x20 || c >= 0x7F || c == '(' || c == ')' || c == '<'
                  || c == '>' || c == '@' || c == ',' || c == ';' || c == ':'
                  || c == '\\' || c == '"' || c == '/' || c == '[' || c == ']'
                  || c == '?' || c == '=' || c == '{' || c == '}')
                {
                  valid_name = 0;
                }
            }

          /* Validate value (cookie-octet per RFC 6265) */
          int valid_value = 1;
          int has_dquote = 0;

          if (value_len > 0 && value_start[0] == '"')
            {
              has_dquote = 1;
              value_start++;
              value_len--;

              if (value_len > 0 && value_start[value_len - 1] == '"')
                value_len--;
            }

          for (size_t i = 0; i < value_len && valid_value; i++)
            {
              unsigned char c = (unsigned char)value_start[i];
              /* cookie-octet: 0x21, 0x23-0x2B, 0x2D-0x3A, 0x3C-0x5B, 0x5D-0x7E
               */
              if (c < 0x21 || c > 0x7E || c == 0x22 || c == 0x2C || c == 0x3B
                  || c == 0x5C)
                {
                  if (!has_dquote) /* Quoted values allow more chars */
                    valid_value = 0;
                }
            }

          (void)valid_name;
          (void)valid_value;
          (void)name_len;
          (void)value_len;
        }

      pair = strtok_r (NULL, ";", &saveptr);
      cookie_count++;
    }
}

/**
 * Test Cookie header parsing through HTTP/1.1 parser
 */
static void
test_via_http1_parser (const char *cookie_value, size_t len, Arena_T arena)
{
  char request[8192];
  int req_len;

  /* Build HTTP request with Cookie header */
  req_len = snprintf (request,
                      sizeof (request),
                      "GET / HTTP/1.1\r\n"
                      "Host: example.com\r\n"
                      "Cookie: %.*s\r\n"
                      "\r\n",
                      (int)len,
                      cookie_value);

  if (req_len <= 0 || (size_t)req_len >= sizeof (request))
    return;

  SocketHTTP1_Config cfg;
  SocketHTTP1_config_defaults (&cfg);
  cfg.strict_mode = 1;

  SocketHTTP1_Parser_T parser
      = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, &cfg, arena);
  if (!parser)
    return;

  size_t consumed;
  SocketHTTP1_Result result
      = SocketHTTP1_Parser_execute (parser, request, req_len, &consumed);

  if (result == HTTP1_OK)
    {
      const SocketHTTP_Request *req = SocketHTTP1_Parser_get_request (parser);
      if (req && req->headers)
        {
          /* Get Cookie header */
          const char *cookie = SocketHTTP_Headers_get (req->headers, "Cookie");
          if (cookie)
            {
              parse_cookie_header (cookie, strlen (cookie), arena);
            }
        }
    }

  SocketHTTP1_Parser_free (&parser);
}

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
    /* ====================================================================
     * Test 1: Direct fuzzed cookie value parsing
     * ==================================================================== */
    {
      char *cookie_str = Arena_alloc (arena, size + 1, __FILE__, __LINE__);
      if (cookie_str)
        {
          memcpy (cookie_str, data, size);
          cookie_str[size] = '\0';

          parse_cookie_header (cookie_str, size, arena);
        }
    }

    /* ====================================================================
     * Test 2: Parse through HTTP/1.1 parser
     * ==================================================================== */
    {
      char *cookie_str = Arena_alloc (arena, size + 1, __FILE__, __LINE__);
      if (cookie_str)
        {
          memcpy (cookie_str, data, size);
          cookie_str[size] = '\0';

          /* Sanitize for HTTP header (remove CR/LF/NUL) */
          for (size_t i = 0; i < size; i++)
            {
              if (cookie_str[i] == '\0' || cookie_str[i] == '\r'
                  || cookie_str[i] == '\n')
                cookie_str[i] = 'X';
            }

          test_via_http1_parser (cookie_str, size, arena);
        }
    }

    /* ====================================================================
     * Test 3: Valid cookie formats
     * ==================================================================== */
    {
      const char *valid_cookies[] = {
        "session=abc123",
        "session=abc123; user=john",
        "session=abc123; user=john; tracking=xyz",
        "name=value",
        "a=b",
        "long_cookie_name=long_cookie_value_with_many_characters",
        "cookie1=value1; cookie2=value2; cookie3=value3; cookie4=value4",
        "session=\"quoted value\"",
        "empty=",
        "numeric=12345",
        "special=!#$%&'()*+-./:<=>?@[]^_`{|}~",
      };

      for (size_t i = 0; i < sizeof (valid_cookies) / sizeof (valid_cookies[0]);
           i++)
        {
          parse_cookie_header (
              valid_cookies[i], strlen (valid_cookies[i]), arena);
          test_via_http1_parser (
              valid_cookies[i], strlen (valid_cookies[i]), arena);
        }
    }

    /* ====================================================================
     * Test 4: Invalid/malformed cookie formats
     * ==================================================================== */
    {
      const char *malformed_cookies[] = {
        "",             /* Empty */
        ";",            /* Just separator */
        "=",            /* Just equals */
        "=value",       /* Missing name */
        "name",         /* Missing equals and value */
        "name=",        /* Empty value (actually valid per RFC 6265) */
        "name=value;",  /* Trailing semicolon */
        "name=value; ", /* Trailing space */
        "name=value;;name2=value2", /* Double semicolon */
        "name =value",              /* Space in name */
        "name= value",              /* Leading space in value */
        "name=va lue",              /* Space in value */
        "name=value\t",             /* Tab in value */
        "name\t=value",             /* Tab in name */
        "name=value\x00extra",      /* Null byte (should be sanitized) */
        "name=\"unclosed",          /* Unclosed quote */
        "name=value\"",             /* Trailing quote */
        "\"name\"=value",           /* Quoted name (invalid) */
        "na;me=value",              /* Semicolon in name */
        "name=val;ue",              /* Would split incorrectly */
        "name\\=value",             /* Escaped equals */
        "name=val\\;ue",            /* Escaped semicolon */
      };

      for (size_t i = 0;
           i < sizeof (malformed_cookies) / sizeof (malformed_cookies[0]);
           i++)
        {
          parse_cookie_header (
              malformed_cookies[i], strlen (malformed_cookies[i]), arena);
        }
    }

    /* ====================================================================
     * Test 5: Security attack vectors
     * ==================================================================== */
    {
      const char *attack_cookies[] = {
        /* CRLF injection (sanitized before passing) */
        "name=value\r\nX-Injected: header",
        "name=value\r\n\r\nHTTP/1.1 200 OK",

        /* Very long name */
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "=value",

        /* Very long value */
        "name=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",

        /* Many cookies */
        ("a=1; b=2; c=3; d=4; e=5; f=6; g=7; h=8; i=9; j=10; k=11; l=12; m=13; "
         "n=14; o=15"),

        /* Unicode in value */
        "name=\xc3\xa9\xc3\xa0\xc3\xb9", /* UTF-8 éàù */

        /* Control characters (should be rejected) */
        "name=\x01\x02\x03",

        /* DEL character */
        "name=\x7f",

        /* High bytes */
        "name=\x80\x90\xa0\xb0\xc0\xd0\xe0\xf0",
      };

      for (size_t i = 0;
           i < sizeof (attack_cookies) / sizeof (attack_cookies[0]);
           i++)
        {
          parse_cookie_header (
              attack_cookies[i], strlen (attack_cookies[i]), arena);
        }
    }

    /* ====================================================================
     * Test 6: Build cookies from fuzz data
     * ==================================================================== */
    if (size > 10)
      {
        char built_cookie[4096];
        size_t offset = 0;
        int cookie_count = 0;

        /* Build multiple name=value pairs from fuzz data */
        size_t fuzz_offset = 0;
        while (fuzz_offset + 4 < size && offset < sizeof (built_cookie) - 100
               && cookie_count < 20)
          {
            /* Get lengths from fuzz data */
            size_t name_len = (data[fuzz_offset] % 32) + 1;
            size_t value_len = (data[fuzz_offset + 1] % 64) + 1;
            fuzz_offset += 2;

            if (fuzz_offset + name_len + value_len > size)
              break;

            /* Add separator if not first */
            if (cookie_count > 0)
              {
                if (offset + 2 < sizeof (built_cookie))
                  {
                    built_cookie[offset++] = ';';
                    built_cookie[offset++] = ' ';
                  }
              }

            /* Copy name (sanitize to alphanum) */
            for (size_t i = 0;
                 i < name_len && offset < sizeof (built_cookie) - 10;
                 i++)
              {
                char c = data[fuzz_offset + i];
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '_' || c == '-')
                  built_cookie[offset++] = c;
                else
                  built_cookie[offset++] = 'x';
              }
            fuzz_offset += name_len;

            /* Add equals */
            if (offset < sizeof (built_cookie) - 5)
              built_cookie[offset++] = '=';

            /* Copy value (sanitize) */
            for (size_t i = 0;
                 i < value_len && offset < sizeof (built_cookie) - 2;
                 i++)
              {
                char c = data[fuzz_offset + i];
                if (c >= 0x21 && c <= 0x7E && c != ';' && c != '\\' && c != '"'
                    && c != ',')
                  built_cookie[offset++] = c;
                else
                  built_cookie[offset++] = 'y';
              }
            fuzz_offset += value_len;

            cookie_count++;
          }

        if (offset > 0)
          {
            built_cookie[offset] = '\0';
            parse_cookie_header (built_cookie, offset, arena);
            test_via_http1_parser (built_cookie, offset, arena);
          }
      }

    /* ====================================================================
     * Test 7: Edge cases
     * ==================================================================== */
    {
      /* Single character cookies */
      parse_cookie_header ("a=b", 3, arena);
      parse_cookie_header ("x=", 2, arena);
      parse_cookie_header ("=v", 2, arena);

      /* Maximum reasonable cookie count */
      char many_cookies[8192];
      size_t pos = 0;
      for (int i = 0; i < 100 && pos < sizeof (many_cookies) - 20; i++)
        {
          if (i > 0)
            {
              many_cookies[pos++] = ';';
              many_cookies[pos++] = ' ';
            }
          int len = snprintf (
              many_cookies + pos, sizeof (many_cookies) - pos, "c%d=v%d", i, i);
          if (len > 0)
            pos += len;
        }
      many_cookies[pos] = '\0';
      parse_cookie_header (many_cookies, pos, arena);
    }
  }
  EXCEPT (SocketHTTP1_ParseError)
  {
    /* Expected on malformed HTTP */
  }
  EXCEPT (Arena_Failed)
  {
    /* Expected on memory exhaustion */
  }
  END_TRY;

  Arena_dispose (&arena);

  return 0;
}
