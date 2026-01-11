/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_http_auth.c - HTTP authentication header parsing fuzzer
 *
 * Tests HTTP authentication header parsing and validation with malformed inputs
 * to find vulnerabilities in Basic, Digest, Bearer, and other auth mechanisms.
 *
 * Targets:
 * - Authorization header parsing (Basic, Digest, Bearer, etc.)
 * - WWW-Authenticate header parsing
 * - Base64 decoding in Basic auth
 * - Digest auth parameter parsing
 * - Credential validation logic
 * - Buffer overflows in auth parsing
 * - Malformed auth schemes
 * - Injection attacks in credentials
 * - Unicode/encoding issues in usernames/passwords
 *
 * Security-Critical Functions (SocketHTTPClient-auth.c):
 * - httpclient_auth_digest_challenge() - Digest auth challenge parsing
 * - httpclient_auth_is_stale_nonce() - Stale nonce detection
 * - parse_http_auth_params() - Internal parameter parser with stack buffers:
 *   - char name[HTTPCLIENT_DIGEST_PARAM_NAME_MAX_LEN] (32 bytes)
 *   - char value[HTTPCLIENT_DIGEST_VALUE_MAX_LEN] (256 bytes)
 *
 * HTTP authentication is critical for security and can be exploited for
 * credential theft, authentication bypass, and injection attacks.
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_http_auth
 * ./fuzz_http_auth corpus/http_auth/ -fork=16 -max_len=4096
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketCrypto.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"
#include "http/SocketHTTPClient-private.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* HTTP request template with Authorization header */
static const char *auth_request_template = "GET /protected HTTP/1.1\r\n"
                                           "Host: example.com\r\n"
                                           "Authorization: %s\r\n"
                                           "\r\n";

/* HTTP response template with WWW-Authenticate header */
static const char *auth_response_template = "HTTP/1.1 401 Unauthorized\r\n"
                                            "WWW-Authenticate: %s\r\n"
                                            "Content-Length: 0\r\n"
                                            "\r\n";

/**
 * Parse Basic authentication credentials
 */
static void
parse_basic_auth (const char *auth_header, Arena_T arena)
{
  if (!auth_header || strncasecmp (auth_header, "Basic ", 6) != 0)
    return;

  const char *b64_start = auth_header + 6;
  size_t b64_len = strlen (b64_start);

  if (b64_len == 0)
    return;

  /* Decode base64 */
  size_t decoded_len = (b64_len * 3) / 4 + 1;
  char *decoded = Arena_alloc (arena, decoded_len, __FILE__, __LINE__);
  if (!decoded)
    return;

  int decode_result = SocketCrypto_base64_decode (
      b64_start, b64_len, (unsigned char *)decoded, decoded_len);
  if (decode_result > 0)
    {
      decoded[decode_result] = '\0';

      /* Parse username:password */
      char *colon = strchr (decoded, ':');
      if (colon)
        {
          *colon = '\0';
          const char *username = decoded;
          const char *password = colon + 1;

          /* Validate credentials (simplified) */
          size_t user_len = strlen (username);
          size_t pass_len = strlen (password);

          (void)user_len;
          (void)pass_len;
        }
    }
}

/**
 * Parse Digest authentication parameters
 */
static void
parse_digest_auth (const char *auth_header, Arena_T arena)
{
  if (!auth_header || strncasecmp (auth_header, "Digest ", 7) != 0)
    return;

  const char *params_start = auth_header + 7;
  char *params_copy
      = Arena_alloc (arena, strlen (params_start) + 1, __FILE__, __LINE__);
  if (!params_copy)
    return;

  strcpy (params_copy, params_start);

  /* Parse comma-separated parameters */
  char *token = strtok (params_copy, ",");
  while (token)
    {
      /* Skip whitespace */
      while (*token && (*token == ' ' || *token == '\t'))
        token++;

      /* Parse key="value" or key=value */
      char *equals = strchr (token, '=');
      if (equals)
        {
          *equals = '\0';
          char *key = token;
          char *value = equals + 1;

          /* Remove quotes if present */
          if (*value == '"')
            {
              value++;
              char *end_quote = strrchr (value, '"');
              if (end_quote)
                *end_quote = '\0';
            }

          /* Process known Digest parameters */
          if (strcasecmp (key, "username") == 0
              || strcasecmp (key, "realm") == 0
              || strcasecmp (key, "nonce") == 0 || strcasecmp (key, "uri") == 0
              || strcasecmp (key, "response") == 0
              || strcasecmp (key, "algorithm") == 0
              || strcasecmp (key, "cnonce") == 0
              || strcasecmp (key, "opaque") == 0 || strcasecmp (key, "qop") == 0
              || strcasecmp (key, "nc") == 0)
            {
              /* Validate parameter value */
              size_t value_len = strlen (value);
              (void)value_len;
            }
        }

      token = strtok (NULL, ",");
    }
}

/**
 * Parse WWW-Authenticate header
 */
static void
parse_www_authenticate (const char *auth_header, Arena_T arena)
{
  if (!auth_header)
    return;

  char *header_copy
      = Arena_alloc (arena, strlen (auth_header) + 1, __FILE__, __LINE__);
  if (!header_copy)
    return;

  strcpy (header_copy, auth_header);

  /* Parse challenge parameters */
  char *token = strtok (header_copy, " ");
  if (token)
    {
      /* First token is auth scheme */
      char *scheme = token;

      if (strcasecmp (scheme, "Basic") == 0)
        {
          /* Parse Basic challenge parameters */
          while ((token = strtok (NULL, ",")) != NULL)
            {
              char *equals = strchr (token, '=');
              if (equals)
                {
                  *equals = '\0';
                  char *key = token;
                  char *value = equals + 1;

                  while (*key && (*key == ' ' || *key == '\t'))
                    key++;
                  while (*value && (*value == ' ' || *value == '\t'))
                    value++;

                  if (*value == '"')
                    {
                      value++;
                      char *end_quote = strrchr (value, '"');
                      if (end_quote)
                        *end_quote = '\0';
                    }

                  if (strcasecmp (key, "realm") == 0)
                    {
                      size_t realm_len = strlen (value);
                      (void)realm_len;
                    }
                }
            }
        }
      else if (strcasecmp (scheme, "Digest") == 0)
        {
          /* Parse Digest challenge parameters - similar to Digest auth */
          parse_digest_auth (auth_header, arena);
        }
      else if (strcasecmp (scheme, "Bearer") == 0)
        {
          /* Parse Bearer challenge */
          while ((token = strtok (NULL, ",")) != NULL)
            {
              char *equals = strchr (token, '=');
              if (equals)
                {
                  *equals = '\0';
                  char *key = token;
                  char *value = equals + 1;

                  while (*key && (*key == ' ' || *key == '\t'))
                    key++;
                  while (*value && (*value == ' ' || *value == '\t'))
                    value++;

                  if (strcasecmp (key, "realm") == 0
                      || strcasecmp (key, "scope") == 0
                      || strcasecmp (key, "error") == 0
                      || strcasecmp (key, "error_description") == 0)
                    {
                      size_t param_len = strlen (value);
                      (void)param_len;
                    }
                }
            }
        }
    }
}

/* ============================================================================
 * HTTP Client Private API Fuzzing (SocketHTTPClient-auth.c)
 * ============================================================================
 *
 * These functions directly test the private auth parsing API that uses
 * stack-allocated buffers for parameter names and values.
 */

/* Test credentials - safe dummy values for fuzzing */
#define FUZZ_USERNAME "testuser"
#define FUZZ_PASSWORD "testpass"
#define FUZZ_METHOD "GET"
#define FUZZ_URI "/test/path"
#define FUZZ_NC "00000001"

/**
 * Fuzz httpclient_auth_is_stale_nonce - parses WWW-Authenticate for stale=true
 *
 * This function uses parse_http_auth_params() internally which has:
 * - char name[32] stack buffer
 * - char value[256] stack buffer
 *
 * No TLS required - pure parsing function.
 */
static void
fuzz_stale_nonce_detection (const char *input)
{
  if (!input)
    return;

  /* Test with raw input */
  int is_stale = httpclient_auth_is_stale_nonce (input);

  /* Result must be 0 or 1 */
  if (is_stale != 0 && is_stale != 1)
    __builtin_trap ();
}

#if SOCKET_HAS_TLS
/**
 * Fuzz httpclient_auth_digest_challenge - full digest auth parsing
 *
 * This requires TLS for random number generation (cnonce).
 * Tests parse_digest_challenge() -> parse_http_auth_params() path.
 */
static void
fuzz_digest_challenge_parsing (const char *input)
{
  char output[2048];

  if (!input)
    return;

  /* Test parsing with fuzz input */
  int result = httpclient_auth_digest_challenge (input,
                                                 FUZZ_USERNAME,
                                                 FUZZ_PASSWORD,
                                                 FUZZ_METHOD,
                                                 FUZZ_URI,
                                                 FUZZ_NC,
                                                 output,
                                                 sizeof (output));

  /* Result should be 0 (success) or -1 (parse failure) */
  if (result != 0 && result != -1)
    __builtin_trap ();

  /* On success, output should be null-terminated within bounds */
  if (result == 0)
    {
      size_t len = strnlen (output, sizeof (output));
      if (len >= sizeof (output))
        __builtin_trap (); /* Buffer overflow detected */
    }

  /* Test with minimal output buffer - should fail gracefully */
  char tiny_output[1];
  result = httpclient_auth_digest_challenge (input,
                                             FUZZ_USERNAME,
                                             FUZZ_PASSWORD,
                                             FUZZ_METHOD,
                                             FUZZ_URI,
                                             FUZZ_NC,
                                             tiny_output,
                                             sizeof (tiny_output));
  (void)result;

  /* Test with medium buffer (boundary condition) */
  char medium_output[64];
  result = httpclient_auth_digest_challenge (input,
                                             FUZZ_USERNAME,
                                             FUZZ_PASSWORD,
                                             FUZZ_METHOD,
                                             FUZZ_URI,
                                             FUZZ_NC,
                                             medium_output,
                                             sizeof (medium_output));
  (void)result;
}
#endif /* SOCKET_HAS_TLS */

/**
 * Test auth parsing with various prefixes and edge cases
 */
static void
fuzz_auth_edge_cases (const char *input, size_t input_len)
{
  char *test_input;
  size_t test_len;

  /* Test with "Digest " prefix */
  test_len = 7 + input_len + 1;
  test_input = malloc (test_len);
  if (test_input)
    {
      memcpy (test_input, "Digest ", 7);
      memcpy (test_input + 7, input, input_len);
      test_input[test_len - 1] = '\0';

      fuzz_stale_nonce_detection (test_input);
#if SOCKET_HAS_TLS
      fuzz_digest_challenge_parsing (test_input);
#endif
      free (test_input);
    }

  /* Test with embedded quotes (quoted string parsing) */
  test_len = 18 + input_len + 1;
  test_input = malloc (test_len);
  if (test_input)
    {
      snprintf (test_input, test_len, "Digest realm=\"%s\"", input);
      fuzz_stale_nonce_detection (test_input);
#if SOCKET_HAS_TLS
      fuzz_digest_challenge_parsing (test_input);
#endif
      free (test_input);
    }

  /* Test with stale parameter (target of is_stale_nonce) */
  test_len = 15 + input_len + 1;
  test_input = malloc (test_len);
  if (test_input)
    {
      snprintf (test_input, test_len, "Digest stale=%s", input);
      fuzz_stale_nonce_detection (test_input);
      free (test_input);
    }

  /* Test with many parameters (stress parse loop) */
  test_len = 50 + input_len + 1;
  test_input = malloc (test_len);
  if (test_input)
    {
      snprintf (
          test_input, test_len, "Digest realm=\"r\", nonce=\"n\", %s", input);
      fuzz_stale_nonce_detection (test_input);
#if SOCKET_HAS_TLS
      fuzz_digest_challenge_parsing (test_input);
#endif
      free (test_input);
    }
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena = NULL;
  SocketHTTP1_Parser_T parser = NULL;
  char request_buffer[8192];
  char response_buffer[8192];
  size_t consumed;

  /* Skip empty input */
  if (size == 0)
    return 0;

  /* Limit input size to prevent OOM */
  if (size > 4096)
    size = 4096;

  arena = Arena_new ();
  if (!arena)
    return 0;

  TRY
  {
    SocketHTTP1_Config cfg;
    SocketHTTP1_config_defaults (&cfg);
    cfg.strict_mode = 1;

    /* Test 1: Direct parsing of fuzzed Authorization header */
    parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, &cfg, arena);
    if (parser)
      {
        /* Build request with fuzzed Authorization header */
        char auth_value[4096];
        size_t auth_len
            = size > sizeof (auth_value) - 1 ? sizeof (auth_value) - 1 : size;
        memcpy (auth_value, data, auth_len);
        auth_value[auth_len] = '\0';

        int request_len = snprintf (request_buffer,
                                    sizeof (request_buffer),
                                    auth_request_template,
                                    auth_value);

        if (request_len > 0 && (size_t)request_len < sizeof (request_buffer))
          {
            SocketHTTP1_Parser_execute (
                parser, request_buffer, request_len, &consumed);

            if (SocketHTTP1_Parser_state (parser) >= HTTP1_STATE_BODY)
              {
                const SocketHTTP_Request *request
                    = SocketHTTP1_Parser_get_request (parser);
                if (request)
                  {
                    const char *auth_header = SocketHTTP_Headers_get (
                        request->headers, "Authorization");
                    if (auth_header)
                      {
                        /* Test auth parsing functions */
                        parse_basic_auth (auth_header, arena);
                        parse_digest_auth (auth_header, arena);
                      }
                  }
              }
          }

        SocketHTTP1_Parser_free (&parser);
        parser = NULL;
      }

    /* Test 2: Response parsing with fuzzed WWW-Authenticate header */
    parser = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, &cfg, arena);
    if (parser)
      {
        char auth_value[4096];
        size_t auth_len
            = size > sizeof (auth_value) - 1 ? sizeof (auth_value) - 1 : size;
        memcpy (auth_value, data, auth_len);
        auth_value[auth_len] = '\0';

        int response_len = snprintf (response_buffer,
                                     sizeof (response_buffer),
                                     auth_response_template,
                                     auth_value);

        if (response_len > 0 && (size_t)response_len < sizeof (response_buffer))
          {
            SocketHTTP1_Parser_execute (
                parser, response_buffer, response_len, &consumed);

            if (SocketHTTP1_Parser_state (parser) >= HTTP1_STATE_BODY)
              {
                const SocketHTTP_Response *response
                    = SocketHTTP1_Parser_get_response (parser);
                if (response)
                  {
                    const char *www_auth = SocketHTTP_Headers_get (
                        response->headers, "WWW-Authenticate");
                    if (www_auth)
                      {
                        parse_www_authenticate (www_auth, arena);
                      }
                  }
              }
          }

        SocketHTTP1_Parser_free (&parser);
        parser = NULL;
      }

    /* Test 3: Known valid authentication headers */
    const char *valid_auth_headers[] = {
      "Basic dXNlcjpwYXNz", /* user:pass */
      "Digest username=\"user\", realm=\"test\", nonce=\"abc123\", uri=\"/\", "
      "response=\"xyz789\"",
      "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9", /* JWT-like */
      "Negotiate TlRMTVNTUAADAAAAGAAYAIAAA",         /* NTLM */
      "AWS4-HMAC-SHA256 "
      "Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, "
      "SignedHeaders=host;range;x-amz-date, Signature=example",
    };

    for (size_t i = 0;
         i < sizeof (valid_auth_headers) / sizeof (valid_auth_headers[0]);
         i++)
      {
        parse_basic_auth (valid_auth_headers[i], arena);
        parse_digest_auth (valid_auth_headers[i], arena);
        parse_www_authenticate (valid_auth_headers[i], arena);
      }

    /* Test 4: Malformed authentication headers */
    const char *malformed_auth[] = {
      "Basic ",                            /* Empty Basic */
      "Basic invalid-base64!",             /* Invalid base64 */
      "Basic dXNlcg==",                    /* Missing password */
      "Digest ",                           /* Empty Digest */
      "Digest username=",                  /* Incomplete Digest */
      "Digest username=\"user",            /* Unclosed quote */
      "Digest username=\"user\", invalid", /* Invalid parameter */
      "Bearer ",                           /* Empty Bearer */
      "Unknown scheme",                    /* Unknown scheme */
      "Basic\r\nX-Injected: header",       /* Header injection */
      "Basic dXNlcjpwYXNz\r\n",            /* CRLF in auth */
      "",                                  /* Empty */
      "Basic \xff\xfe",                    /* Invalid UTF-8 */
    };

    for (size_t i = 0; i < sizeof (malformed_auth) / sizeof (malformed_auth[0]);
         i++)
      {
        parse_basic_auth (malformed_auth[i], arena);
        parse_digest_auth (malformed_auth[i], arena);
        parse_www_authenticate (malformed_auth[i], arena);
      }

    /* Test 5: HTTP Client Private API - Direct auth parsing */
    {
      char auth_value[4096];
      size_t auth_len
          = size > sizeof (auth_value) - 1 ? sizeof (auth_value) - 1 : size;
      memcpy (auth_value, data, auth_len);
      auth_value[auth_len] = '\0';

      /* Test stale nonce detection (no TLS required) */
      fuzz_stale_nonce_detection (auth_value);
      fuzz_stale_nonce_detection (NULL);
      fuzz_stale_nonce_detection ("");

#if SOCKET_HAS_TLS
      /* Test digest challenge parsing (requires TLS for cnonce) */
      fuzz_digest_challenge_parsing (auth_value);
#endif

      /* Test with various prefixes and edge cases */
      fuzz_auth_edge_cases (auth_value, auth_len);
    }

    /* Test 6: Edge cases in base64 decoding */
    if (size >= 4)
      {
        /* Test various base64 inputs for Basic auth */
        char b64_input[1024];
        size_t b64_len
            = size > sizeof (b64_input) - 1 ? sizeof (b64_input) - 1 : size;
        memcpy (b64_input, data, b64_len);
        b64_input[b64_len] = '\0';

        char *decoded
            = Arena_alloc (arena, (b64_len * 3) / 4 + 4, __FILE__, __LINE__);
        if (decoded)
          {
            int decode_result
                = SocketCrypto_base64_decode (b64_input,
                                              b64_len,
                                              (unsigned char *)decoded,
                                              (b64_len * 3) / 4 + 4);
            (void)decode_result;
          }
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

  if (parser)
    SocketHTTP1_Parser_free (&parser);

  Arena_dispose (&arena);

  return 0;
}
