/**
 * fuzz_http_client.c - Comprehensive HTTP Client fuzzing harness
 *
 * Tests SocketHTTPClient functionality with malformed inputs to find vulnerabilities
 * in request building, response parsing, cookie handling, authentication, and redirects.
 *
 * Targets:
 * - Custom request header validation and injection
 * - Cookie parsing and jar management
 * - Authentication header construction and validation
 * - Response parsing and validation (CRITICAL - malicious server responses)
 * - Redirect URL validation and loop detection
 * - Content-Type and Accept header handling
 * - Custom request body validation
 * - Timeout and configuration edge cases
 * - Set-Cookie header injection attacks
 * - Chunked response parsing edge cases
 * - Response body decompression (if enabled)
 * - Conflicting Content-Length/Transfer-Encoding
 *
 * HTTP clients are critical attack surfaces as they process untrusted server responses.
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_http_client
 * ./fuzz_http_client corpus/http_client/ -fork=16 -max_len=65536
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"
#include "http/SocketHTTPClient.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Suppress GCC clobbered warnings for TRY/EXCEPT */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/**
 * Test malicious server response parsing through HTTP/1.1 parser
 * This is the critical attack surface - a malicious server can send any response
 */
static void
test_response_parsing (Arena_T arena, const uint8_t *data, size_t size)
{
  SocketHTTP1_Parser_T parser = NULL;
  SocketHTTP1_Config cfg;
  size_t consumed;

  SocketHTTP1_config_defaults (&cfg);

  /* Test both strict and lenient modes */
  for (int strict = 0; strict <= 1; strict++)
    {
      cfg.strict_mode = strict;

      parser = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, &cfg, arena);
      if (!parser)
        continue;

      SocketHTTP1_Result result
          = SocketHTTP1_Parser_execute (parser, (const char *)data, size, &consumed);

      if (result == HTTP1_OK)
        {
          const SocketHTTP_Response *resp = SocketHTTP1_Parser_get_response (parser);
          if (resp)
            {
              /* Access all response fields */
              (void)resp->status_code;
              (void)resp->version;
              (void)resp->reason_phrase;

              if (resp->headers)
                {
                  /* Headers a client cares about */
                  SocketHTTP_Headers_get (resp->headers, "Content-Length");
                  SocketHTTP_Headers_get (resp->headers, "Transfer-Encoding");
                  SocketHTTP_Headers_get (resp->headers, "Content-Type");
                  SocketHTTP_Headers_get (resp->headers, "Content-Encoding");
                  SocketHTTP_Headers_get (resp->headers, "Set-Cookie");
                  SocketHTTP_Headers_get (resp->headers, "Location");
                  SocketHTTP_Headers_get (resp->headers, "Connection");
                  SocketHTTP_Headers_get (resp->headers, "WWW-Authenticate");

                  /* Get all Set-Cookie headers (multiple allowed) */
                  const char *cookies[20];
                  size_t cookie_count = SocketHTTP_Headers_get_all (
                      resp->headers, "Set-Cookie", cookies, 20);
                  (void)cookie_count;

                  /* Check for keep-alive */
                  int keepalive = SocketHTTP1_Parser_should_keepalive (parser);
                  (void)keepalive;
                }
            }

          /* Process body if present */
          if (consumed < size)
            {
              char body_buf[8192];
              size_t body_consumed, body_written;

              while (consumed < size && !SocketHTTP1_Parser_body_complete (parser))
                {
                  SocketHTTP1_Result body_result = SocketHTTP1_Parser_read_body (
                      parser, (const char *)data + consumed, size - consumed,
                      &body_consumed, body_buf, sizeof (body_buf), &body_written);

                  if (body_consumed == 0)
                    break;

                  consumed += body_consumed;

                  if (body_result != HTTP1_OK && body_result != HTTP1_INCOMPLETE)
                    break;
                }
            }
        }

      SocketHTTP1_Parser_free (&parser);
      parser = NULL;
    }
}

/**
 * Test malicious Set-Cookie header parsing
 */
static void
test_setcookie_parsing (Arena_T arena, const uint8_t *data, size_t size)
{
  if (size < 20)
    return;

  SocketHTTP1_Parser_T parser = NULL;
  SocketHTTP1_Config cfg;
  size_t consumed;

  SocketHTTP1_config_defaults (&cfg);

  /* Build response with fuzzed Set-Cookie */
  char response_buf[4096];
  char fuzzed_cookie[256];
  size_t cookie_len = (size > 200) ? 200 : size;
  memcpy (fuzzed_cookie, data, cookie_len);
  fuzzed_cookie[cookie_len] = '\0';

  /* Make it somewhat printable but allow attack chars */
  for (size_t i = 0; i < cookie_len; i++)
    {
      if (fuzzed_cookie[i] == '\0')
        fuzzed_cookie[i] = 'x';
      /* Allow dangerous chars: ; = \r \n for injection testing */
    }

  int len = snprintf (response_buf, sizeof (response_buf),
                      "HTTP/1.1 200 OK\r\n"
                      "Content-Length: 0\r\n"
                      "Set-Cookie: %s\r\n"
                      "\r\n",
                      fuzzed_cookie);

  if (len <= 0 || (size_t)len >= sizeof (response_buf))
    return;

  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, &cfg, arena);
  if (parser)
    {
      SocketHTTP1_Parser_execute (parser, response_buf, len, &consumed);

      if (SocketHTTP1_Parser_state (parser) >= HTTP1_STATE_BODY)
        {
          const SocketHTTP_Response *resp = SocketHTTP1_Parser_get_response (parser);
          if (resp && resp->headers)
            {
              const char *cookie = SocketHTTP_Headers_get (resp->headers, "Set-Cookie");
              (void)cookie;
            }
        }

      SocketHTTP1_Parser_free (&parser);
    }
}

/**
 * Test malicious redirect Location header
 */
static void
test_redirect_parsing (Arena_T arena, const uint8_t *data, size_t size)
{
  if (size < 10)
    return;

  SocketHTTP1_Parser_T parser = NULL;
  SocketHTTP1_Config cfg;
  size_t consumed;

  SocketHTTP1_config_defaults (&cfg);

  /* Build redirect response with fuzzed Location */
  char response_buf[4096];
  char fuzzed_location[512];
  size_t loc_len = (size > 400) ? 400 : size;
  memcpy (fuzzed_location, data, loc_len);
  fuzzed_location[loc_len] = '\0';

  /* Allow dangerous chars for SSRF testing */
  for (size_t i = 0; i < loc_len; i++)
    {
      if (fuzzed_location[i] == '\0')
        fuzzed_location[i] = 'x';
    }

  int status_codes[] = { 301, 302, 303, 307, 308 };
  int status = status_codes[data[0] % 5];

  int len = snprintf (response_buf, sizeof (response_buf),
                      "HTTP/1.1 %d Redirect\r\n"
                      "Location: %s\r\n"
                      "Content-Length: 0\r\n"
                      "\r\n",
                      status, fuzzed_location);

  if (len <= 0 || (size_t)len >= sizeof (response_buf))
    return;

  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, &cfg, arena);
  if (parser)
    {
      SocketHTTP1_Parser_execute (parser, response_buf, len, &consumed);

      if (SocketHTTP1_Parser_state (parser) >= HTTP1_STATE_BODY)
        {
          const SocketHTTP_Response *resp = SocketHTTP1_Parser_get_response (parser);
          if (resp && resp->headers)
            {
              const char *location = SocketHTTP_Headers_get (resp->headers, "Location");
              if (location)
                {
                  /* Parse the redirect URL */
                  SocketHTTP_URI uri;
                  SocketHTTP_URI_parse (location, strlen (location), &uri, arena);
                }
            }
        }

      SocketHTTP1_Parser_free (&parser);
    }
}

/**
 * Test chunked response parsing (malicious chunks)
 */
static void
test_chunked_response (Arena_T arena, const uint8_t *data, size_t size)
{
  if (size < 20)
    return;

  SocketHTTP1_Parser_T parser = NULL;
  SocketHTTP1_Config cfg;
  size_t consumed;

  SocketHTTP1_config_defaults (&cfg);

  /* Build chunked response */
  char response_buf[8192];
  int len = snprintf (response_buf, sizeof (response_buf),
                      "HTTP/1.1 200 OK\r\n"
                      "Transfer-Encoding: chunked\r\n"
                      "\r\n");

  if (len <= 0)
    return;

  /* Add fuzzed chunks */
  size_t resp_offset = len;
  size_t data_offset = 0;

  while (data_offset < size && resp_offset + 100 < sizeof (response_buf))
    {
      /* Fuzzed chunk size */
      char chunk_size[32];
      int chunk_len;

      if (data_offset + 2 <= size)
        {
          uint16_t raw_size = ((uint16_t)data[data_offset] << 8) | data[data_offset + 1];
          chunk_len = raw_size % 256; /* Keep chunks small for testing */
          data_offset += 2;
        }
      else
        {
          chunk_len = 0;
        }

      if (chunk_len == 0)
        {
          /* Final chunk */
          int added = snprintf (response_buf + resp_offset,
                                sizeof (response_buf) - resp_offset, "0\r\n\r\n");
          if (added > 0)
            resp_offset += added;
          break;
        }

      /* Add chunk header */
      int header_len = snprintf (chunk_size, sizeof (chunk_size), "%x\r\n", chunk_len);
      if (header_len <= 0 || resp_offset + header_len >= sizeof (response_buf))
        break;

      memcpy (response_buf + resp_offset, chunk_size, header_len);
      resp_offset += header_len;

      /* Add chunk data from fuzz input */
      size_t to_copy = chunk_len;
      if (data_offset + to_copy > size)
        to_copy = size - data_offset;
      if (resp_offset + to_copy >= sizeof (response_buf))
        to_copy = sizeof (response_buf) - resp_offset - 1;

      if (to_copy > 0)
        {
          memcpy (response_buf + resp_offset, data + data_offset, to_copy);
          resp_offset += to_copy;
          data_offset += to_copy;
        }

      /* Pad with 'x' if chunk_len > to_copy */
      for (size_t i = to_copy; i < (size_t)chunk_len && resp_offset < sizeof (response_buf) - 1;
           i++)
        {
          response_buf[resp_offset++] = 'x';
        }

      /* Add CRLF after chunk */
      if (resp_offset + 2 < sizeof (response_buf))
        {
          response_buf[resp_offset++] = '\r';
          response_buf[resp_offset++] = '\n';
        }
    }

  /* Parse the chunked response */
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, &cfg, arena);
  if (parser)
    {
      SocketHTTP1_Result result
          = SocketHTTP1_Parser_execute (parser, response_buf, resp_offset, &consumed);

      if (result == HTTP1_OK)
        {
          /* Read body chunks */
          char body_buf[4096];
          size_t body_consumed, body_written;
          size_t offset = consumed;

          while (offset < resp_offset && !SocketHTTP1_Parser_body_complete (parser))
            {
              SocketHTTP1_Result body_result = SocketHTTP1_Parser_read_body (
                  parser, response_buf + offset, resp_offset - offset, &body_consumed,
                  body_buf, sizeof (body_buf), &body_written);

              if (body_consumed == 0)
                break;

              offset += body_consumed;

              if (body_result != HTTP1_OK && body_result != HTTP1_INCOMPLETE)
                break;
            }
        }

      SocketHTTP1_Parser_free (&parser);
    }
}

/**
 * Test response smuggling vectors (malicious server trying to desync)
 */
static void
test_response_smuggling (Arena_T arena)
{
  SocketHTTP1_Parser_T parser = NULL;
  SocketHTTP1_Config cfg;
  size_t consumed;

  SocketHTTP1_config_defaults (&cfg);
  cfg.strict_mode = 1;

  const char *smuggling_responses[] = {
    /* Duplicate Content-Length */
    "HTTP/1.1 200 OK\r\n"
    "Content-Length: 10\r\n"
    "Content-Length: 5\r\n"
    "\r\n"
    "hello",

    /* CL + TE conflict */
    "HTTP/1.1 200 OK\r\n"
    "Content-Length: 10\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "5\r\nhello\r\n0\r\n\r\n",

    /* TE + CL conflict */
    "HTTP/1.1 200 OK\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Content-Length: 5\r\n"
    "\r\n"
    "5\r\nhello\r\n0\r\n\r\n",

    /* Multiple TE headers */
    "HTTP/1.1 200 OK\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Transfer-Encoding: identity\r\n"
    "\r\n"
    "5\r\nhello\r\n0\r\n\r\n",

    /* TE with obfuscation */
    "HTTP/1.1 200 OK\r\n"
    "Transfer-Encoding:  chunked\r\n"
    "\r\n"
    "5\r\nhello\r\n0\r\n\r\n",

    /* Negative Content-Length */
    "HTTP/1.1 200 OK\r\n"
    "Content-Length: -1\r\n"
    "\r\n",

    /* Huge Content-Length */
    "HTTP/1.1 200 OK\r\n"
    "Content-Length: 99999999999999999999\r\n"
    "\r\n",

    /* Invalid HTTP version */
    "HTTP/9.9 200 OK\r\n"
    "Content-Length: 5\r\n"
    "\r\n"
    "hello",

    /* No status code */
    "HTTP/1.1 OK\r\n"
    "Content-Length: 5\r\n"
    "\r\n"
    "hello",

    /* Empty status line */
    "\r\n"
    "Content-Length: 5\r\n"
    "\r\n"
    "hello",

    /* Header injection via obs-fold */
    "HTTP/1.1 200 OK\r\n"
    "Set-Cookie: session=abc\r\n"
    " ; Secure\r\n"
    "Content-Length: 0\r\n"
    "\r\n",

    /* Null byte in header */
    "HTTP/1.1 200 OK\r\n"
    "X-Header: val\x00ue\r\n"
    "Content-Length: 0\r\n"
    "\r\n",
  };

  for (size_t i = 0; i < sizeof (smuggling_responses) / sizeof (smuggling_responses[0]);
       i++)
    {
      parser = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, &cfg, arena);
      if (parser)
        {
          SocketHTTP1_Parser_execute (parser, smuggling_responses[i],
                                      strlen (smuggling_responses[i]), &consumed);
          SocketHTTP1_Parser_free (&parser);
        }
    }
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena = NULL;
  SocketHTTPClient_T client = NULL;
  SocketHTTPClient_Request_T request = NULL;
  SocketHTTPClient_CookieJar_T cookie_jar = NULL;

  /* Skip empty input */
  if (size == 0)
    return 0;

  arena = Arena_new ();
  if (!arena)
    return 0;

  TRY
  {
    /* Test 1: Cookie jar operations */
    cookie_jar = SocketHTTPClient_CookieJar_new ();
    if (cookie_jar)
      {
        /* Create test cookies with fuzzed data */
        if (size > 10)
          {
            SocketHTTPClient_Cookie cookie;
            memset (&cookie, 0, sizeof (cookie));

            /* Set fuzzed name and value */
            size_t name_len = data[0] % 32 + 1;
            size_t value_len = data[1] % 64 + 1;

            if (2 + name_len + value_len < size)
              {
                char name[33], value[65];
                memcpy (name, data + 2, name_len);
                name[name_len] = '\0';
                memcpy (value, data + 2 + name_len, value_len);
                value[value_len] = '\0';

                cookie.name = name;
                cookie.value = value;
                cookie.domain = "example.com";
                cookie.path = "/";

                SocketHTTPClient_CookieJar_set (cookie_jar, &cookie);
              }
          }

        /* Test getting cookies */
        const SocketHTTPClient_Cookie *retrieved = SocketHTTPClient_CookieJar_get (
            cookie_jar, "example.com", "/", "test");
        (void)retrieved;

        /* Test clearing operations */
        SocketHTTPClient_CookieJar_clear_expired (cookie_jar);
      }

    /* Test 2: Custom request building with fuzzed headers */
    client = SocketHTTPClient_new (NULL);
    if (client && size > 20)
      {
        /* Create custom request with fuzzed headers */
        request = SocketHTTPClient_Request_new (client, HTTP_METHOD_GET, "http://example.com/test");
        if (request)
          {
            /* Add multiple fuzzed headers */
            size_t offset = 0;
            for (int i = 0; i < 10 && offset + 10 < size; i++)
              {
                char header_name[256];
                char header_value[1024];
                size_t name_len = data[offset] % 32 + 1; /* 1-32 chars */
                size_t value_len = data[offset + 1] % 128 + 1; /* 1-128 chars */

                offset += 2;

                if (offset + name_len + value_len >= size)
                  break;

                memcpy (header_name, data + offset, name_len);
                header_name[name_len] = '\0';
                offset += name_len;

                memcpy (header_value, data + offset, value_len);
                header_value[value_len] = '\0';
                offset += value_len;

                /* Try to add the header */
                SocketHTTPClient_Request_header (request, header_name, header_value);
              }

            /* Set fuzzed timeout - use unsigned to avoid UB on left shift */
            if (offset + 4 < size)
              {
                int timeout_ms = (int)(((uint32_t)data[offset] << 24) |
                                       ((uint32_t)data[offset + 1] << 16) |
                                       ((uint32_t)data[offset + 2] << 8) |
                                       (uint32_t)data[offset + 3]);
                SocketHTTPClient_Request_timeout (request, timeout_ms);
              }

            /* Add fuzzed request body */
            if (offset + 100 < size)
              {
                size_t body_len = size - offset;
                if (body_len > 1024)
                  body_len = 1024;
                SocketHTTPClient_Request_body (request, data + offset, body_len);
              }
          }
      }

    /* Test 3: Authentication header construction */
    if (client && size > 10)
      {
        /* Create auth structures with fuzzed data - zero-init to avoid UB */
        SocketHTTPClient_Auth auth;
        memset (&auth, 0, sizeof (auth));

        /* Test Basic auth with fuzzed credentials */
        char username[256];
        char password[256];
        size_t user_len = data[0] % 64 + 1;
        size_t pass_len = data[1] % 64 + 1;

        if (2 + user_len + pass_len < size)
          {
            memcpy (username, data + 2, user_len);
            username[user_len] = '\0';
            memcpy (password, data + 2 + user_len, pass_len);
            password[pass_len] = '\0';

            auth.type = HTTP_AUTH_BASIC;
            auth.username = username;
            auth.password = password;

            if (request)
              SocketHTTPClient_Request_auth (request, &auth);
          }

        /* Test Bearer token auth */
        if (size > 100)
          {
            char token[512];
            size_t token_len = data[2] % 256 + 1;
            if (3 + token_len < size)
              {
                memcpy (token, data + 3, token_len);
                token[token_len] = '\0';

                auth.type = HTTP_AUTH_BEARER;
                auth.token = token;

                if (request)
                  SocketHTTPClient_Request_auth (request, &auth);
              }
          }
      }

    /* Test 4: Malicious server response parsing (CRITICAL) */
    test_response_parsing (arena, data, size);

    /* Test 5: Set-Cookie header injection */
    test_setcookie_parsing (arena, data, size);

    /* Test 6: Redirect Location header (SSRF vectors) */
    test_redirect_parsing (arena, data, size);

    /* Test 7: Chunked response parsing */
    test_chunked_response (arena, data, size);

    /* Test 8: Response smuggling vectors */
    test_response_smuggling (arena);

    /* Test 9: Configuration validation */
    /* NOTE: Cannot memcpy raw fuzz data into config struct as it contains
     * pointers that would be garbage values causing SEGV in strdup.
     * Instead, initialize defaults and fuzz numeric fields only. */
    if (size >= 8)
      {
        SocketHTTPClient_Config config;
        SocketHTTPClient_config_defaults (&config);

        /* Fuzz numeric configuration fields only */
        config.connect_timeout_ms = (int)(((uint32_t)data[0] << 8) | data[1]);
        config.request_timeout_ms = (int)(((uint32_t)data[2] << 8) | data[3]);
        config.follow_redirects = (int)(data[4] % 20);
        config.max_response_size = (size_t)(((uint32_t)data[5] << 16) |
                                            ((uint32_t)data[6] << 8) | data[7]);

        /* Validate config doesn't crash client creation */
        SocketHTTPClient_T test_client = SocketHTTPClient_new (&config);
        if (test_client)
          {
            SocketHTTPClient_free (&test_client);
          }
      }

    /* Cleanup */
    if (request)
      SocketHTTPClient_Request_free (&request);
    if (client)
      SocketHTTPClient_free (&client);
    if (cookie_jar)
      SocketHTTPClient_CookieJar_free (&cookie_jar);
  }
  EXCEPT (SocketHTTPClient_Failed)
  {
    /* Expected on malformed input */
  }
  EXCEPT (SocketHTTP1_ParseError)
  {
    /* Expected on malformed responses */
  }
  EXCEPT (Arena_Failed)
  {
    /* Expected on memory exhaustion */
  }
  END_TRY;

  Arena_dispose (&arena);

  return 0;
}
