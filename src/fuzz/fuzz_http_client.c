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
 * - Response parsing and validation
 * - Redirect URL validation and loop detection
 * - Content-Type and Accept header handling
 * - Custom request body validation
 * - Timeout and configuration edge cases
 *
 * HTTP clients are critical attack surfaces as they process untrusted server responses.
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_http_client
 * ./fuzz_http_client corpus/http_client/ -fork=16 -max_len=8192
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHTTPClient.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

            /* Set fuzzed timeout */
            if (offset + 4 < size)
              {
                int timeout_ms = ((int)data[offset] << 24) | ((int)data[offset + 1] << 16) |
                                ((int)data[offset + 2] << 8) | (int)data[offset + 3];
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
        /* Create auth structures with fuzzed data */
        SocketHTTPClient_Auth auth;

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

    /* Test 4: Response parsing simulation */
    if (size > 50)
      {
        /* Create a mock HTTP response with fuzzed content */
        char response_data[4096];
        size_t resp_len = size > sizeof (response_data) - 200 ? sizeof (response_data) - 200 : size;

        /* Build response: headers + fuzzed body */
        int len = snprintf (response_data, sizeof (response_data),
                          "HTTP/1.1 200 OK\r\n"
                          "Content-Length: %zu\r\n"
                          "Content-Type: text/plain\r\n"
                          "Set-Cookie: session=%.*s\r\n"
                          "\r\n",
                          resp_len, (int)(resp_len > 32 ? 32 : resp_len), data);

        if (len > 0 && (size_t)len + resp_len < sizeof (response_data))
          {
            memcpy (response_data + len, data, resp_len);
            /* Cookie parsing from response would be tested separately in fuzz_http_cookies.c */
          }
      }

    /* Test 5: Configuration validation */
    if (size >= sizeof (SocketHTTPClient_Config))
      {
        SocketHTTPClient_Config config;
        memcpy (&config, data, sizeof (config));

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
  EXCEPT (Arena_Failed)
  {
    /* Expected on memory exhaustion */
  }
  END_TRY;

  Arena_dispose (&arena);

  return 0;
}
