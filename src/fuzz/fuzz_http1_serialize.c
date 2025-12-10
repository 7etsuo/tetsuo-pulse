/**
 * fuzz_http1_serialize.c - HTTP/1.1 serialization fuzzer
 *
 * Tests HTTP/1.1 request and response serialization with fuzzed data:
 * - SocketHTTP1_serialize_request with fuzzed SocketHTTP_Request structs
 * - SocketHTTP1_serialize_response with fuzzed SocketHTTP_Response structs
 * - Buffer boundary conditions
 * - Header serialization edge cases
 * - Status line formatting
 * - Request line formatting
 *
 * Serialization bugs can lead to malformed HTTP messages and security issues.
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_http1_serialize
 * ./fuzz_http1_serialize corpus/http1_serialize/ -fork=16 -max_len=4096
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena = NULL;
  char output_buffer[16384];

  /* Skip empty input */
  if (size == 0)
    return 0;

  arena = Arena_new ();
  if (!arena)
    return 0;

  TRY
  {
    /* ====================================================================
     * Test 1: Request serialization with fuzzed components
     * ==================================================================== */
    {
      SocketHTTP_Request request;
      memset (&request, 0, sizeof (request));

      /* Use fuzz data to select method */
      request.method = (SocketHTTP_Method)(data[0] % 10);
      request.version = HTTP_VERSION_1_1;

      /* Create path from fuzz data */
      char path[1024];
      size_t path_offset = 1;
      size_t path_len = (size > path_offset) ?
                        ((size - path_offset > sizeof (path) - 1) ?
                         sizeof (path) - 1 : size - path_offset) : 0;
      if (path_len > 0)
        {
          memcpy (path, data + path_offset, path_len);
          path[path_len] = '\0';
          request.path = path;
        }
      else
        {
          request.path = "/";
        }

      /* Create headers with fuzzed values */
      SocketHTTP_Headers_T headers = SocketHTTP_Headers_new (arena);
      if (headers)
        {
          request.headers = headers;

          /* Add Host header (required) */
          SocketHTTP_Headers_add (headers, "Host", "example.com");

          /* Add fuzzed headers */
          size_t offset = 1 + path_len;
          for (int i = 0; i < 10 && offset + 4 < size; i++)
            {
              size_t name_len = (data[offset] % 32) + 1;
              size_t value_len = (data[offset + 1] % 64) + 1;
              offset += 2;

              if (offset + name_len + value_len > size)
                break;

              char name[64], value[128];
              size_t actual_name = (name_len < sizeof (name) - 1) ? name_len : sizeof (name) - 1;
              size_t actual_value = (value_len < sizeof (value) - 1) ? value_len : sizeof (value) - 1;

              if (offset + actual_name + actual_value > size)
                break;

              memcpy (name, data + offset, actual_name);
              name[actual_name] = '\0';
              offset += actual_name;

              memcpy (value, data + offset, actual_value);
              value[actual_value] = '\0';
              offset += actual_value;

              SocketHTTP_Headers_add (headers, name, value);
            }

          /* Serialize request */
          ssize_t serialized = SocketHTTP1_serialize_request (&request, output_buffer,
                                                              sizeof (output_buffer));
          (void)serialized;

          /* Test with small buffer */
          char small_buffer[64];
          serialized = SocketHTTP1_serialize_request (&request, small_buffer,
                                                      sizeof (small_buffer));
          (void)serialized;

          /* Test with exact-size buffer */
          if (serialized > 0 && (size_t)serialized < sizeof (output_buffer))
            {
              char *exact_buffer = Arena_alloc (arena, serialized + 1, __FILE__, __LINE__);
              if (exact_buffer)
                {
                  ssize_t exact_result = SocketHTTP1_serialize_request (&request, exact_buffer,
                                                                        serialized + 1);
                  (void)exact_result;
                }
            }
        }
    }

    /* ====================================================================
     * Test 2: Response serialization with fuzzed components
     * ==================================================================== */
    {
      SocketHTTP_Response response;
      memset (&response, 0, sizeof (response));

      response.version = HTTP_VERSION_1_1;

      /* Use fuzz data for status code */
      if (size >= 3)
        {
          response.status_code = ((int)data[0] << 8) | data[1];
          /* Clamp to valid range for more meaningful testing */
          if (response.status_code < 100 || response.status_code > 599)
            {
              response.status_code = 100 + (response.status_code % 500);
            }
        }
      else
        {
          response.status_code = 200;
        }

      /* Fuzzed reason phrase */
      char reason[256];
      size_t reason_offset = 2;
      size_t reason_len = (size > reason_offset) ?
                          ((size - reason_offset > sizeof (reason) - 1) ?
                           sizeof (reason) - 1 : size - reason_offset) : 0;
      if (reason_len > 0)
        {
          memcpy (reason, data + reason_offset, reason_len);
          reason[reason_len] = '\0';
          response.reason_phrase = reason;
        }
      else
        {
          response.reason_phrase = "OK";
        }

      /* Create headers with fuzzed values */
      SocketHTTP_Headers_T headers = SocketHTTP_Headers_new (arena);
      if (headers)
        {
          response.headers = headers;

          /* Add standard headers */
          SocketHTTP_Headers_add (headers, "Content-Type", "text/plain");

          /* Add fuzzed headers */
          size_t offset = 2 + reason_len;
          for (int i = 0; i < 10 && offset + 4 < size; i++)
            {
              size_t name_len = (data[offset] % 32) + 1;
              size_t value_len = (data[offset + 1] % 64) + 1;
              offset += 2;

              if (offset + name_len + value_len > size)
                break;

              char name[64], value[128];
              size_t actual_name = (name_len < sizeof (name) - 1) ? name_len : sizeof (name) - 1;
              size_t actual_value = (value_len < sizeof (value) - 1) ? value_len : sizeof (value) - 1;

              if (offset + actual_name + actual_value > size)
                break;

              memcpy (name, data + offset, actual_name);
              name[actual_name] = '\0';
              offset += actual_name;

              memcpy (value, data + offset, actual_value);
              value[actual_value] = '\0';
              offset += actual_value;

              SocketHTTP_Headers_add (headers, name, value);
            }

          /* Serialize response */
          ssize_t serialized = SocketHTTP1_serialize_response (&response, output_buffer,
                                                               sizeof (output_buffer));
          (void)serialized;

          /* Test with small buffer */
          char small_buffer[64];
          serialized = SocketHTTP1_serialize_response (&response, small_buffer,
                                                       sizeof (small_buffer));
          (void)serialized;
        }
    }

    /* ====================================================================
     * Test 3: Roundtrip parsing of serialized requests
     * ==================================================================== */
    {
      SocketHTTP_Request request;
      memset (&request, 0, sizeof (request));
      request.method = HTTP_METHOD_GET;
      request.version = HTTP_VERSION_1_1;
      request.path = "/test";

      SocketHTTP_Headers_T headers = SocketHTTP_Headers_new (arena);
      if (headers)
        {
          request.headers = headers;
          SocketHTTP_Headers_add (headers, "Host", "example.com");
          SocketHTTP_Headers_add (headers, "Accept", "*/*");

          /* Serialize */
          ssize_t len = SocketHTTP1_serialize_request (&request, output_buffer,
                                                       sizeof (output_buffer));

          if (len > 0)
            {
              /* Parse the serialized request */
              SocketHTTP1_Config cfg;
              SocketHTTP1_config_defaults (&cfg);
              SocketHTTP1_Parser_T parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, &cfg, arena);
              if (parser)
                {
                  size_t consumed;
                  SocketHTTP1_Parser_execute (parser, output_buffer, len, &consumed);
                  SocketHTTP1_Parser_free (&parser);
                }
            }
        }
    }

    /* ====================================================================
     * Test 4: Roundtrip parsing of serialized responses
     * ==================================================================== */
    {
      SocketHTTP_Response response;
      memset (&response, 0, sizeof (response));
      response.version = HTTP_VERSION_1_1;
      response.status_code = 200;
      response.reason_phrase = "OK";

      SocketHTTP_Headers_T headers = SocketHTTP_Headers_new (arena);
      if (headers)
        {
          response.headers = headers;
          SocketHTTP_Headers_add (headers, "Content-Type", "text/html");
          SocketHTTP_Headers_add (headers, "Content-Length", "0");

          /* Serialize */
          ssize_t len = SocketHTTP1_serialize_response (&response, output_buffer,
                                                        sizeof (output_buffer));

          if (len > 0)
            {
              /* Parse the serialized response */
              SocketHTTP1_Config cfg;
              SocketHTTP1_config_defaults (&cfg);
              SocketHTTP1_Parser_T parser = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, &cfg, arena);
              if (parser)
                {
                  size_t consumed;
                  SocketHTTP1_Parser_execute (parser, output_buffer, len, &consumed);
                  SocketHTTP1_Parser_free (&parser);
                }
            }
        }
    }

    /* ====================================================================
     * Test 5: Edge cases in serialization
     * ==================================================================== */
    {
      /* Test with NULL path */
      SocketHTTP_Request null_path_req;
      memset (&null_path_req, 0, sizeof (null_path_req));
      null_path_req.method = HTTP_METHOD_GET;
      null_path_req.version = HTTP_VERSION_1_1;
      null_path_req.path = NULL;
      SocketHTTP_Headers_T h1 = SocketHTTP_Headers_new (arena);
      if (h1)
        {
          null_path_req.headers = h1;
          SocketHTTP_Headers_add (h1, "Host", "example.com");
          SocketHTTP1_serialize_request (&null_path_req, output_buffer, sizeof (output_buffer));
        }

      /* Test with empty path */
      SocketHTTP_Request empty_path_req;
      memset (&empty_path_req, 0, sizeof (empty_path_req));
      empty_path_req.method = HTTP_METHOD_GET;
      empty_path_req.version = HTTP_VERSION_1_1;
      empty_path_req.path = "";
      SocketHTTP_Headers_T h2 = SocketHTTP_Headers_new (arena);
      if (h2)
        {
          empty_path_req.headers = h2;
          SocketHTTP_Headers_add (h2, "Host", "example.com");
          SocketHTTP1_serialize_request (&empty_path_req, output_buffer, sizeof (output_buffer));
        }

      /* Test with NULL headers */
      SocketHTTP_Request no_headers_req;
      memset (&no_headers_req, 0, sizeof (no_headers_req));
      no_headers_req.method = HTTP_METHOD_GET;
      no_headers_req.version = HTTP_VERSION_1_1;
      no_headers_req.path = "/test";
      no_headers_req.headers = NULL;
      SocketHTTP1_serialize_request (&no_headers_req, output_buffer, sizeof (output_buffer));

      /* Test with all methods */
      SocketHTTP_Method methods[] = {
          HTTP_METHOD_GET, HTTP_METHOD_HEAD, HTTP_METHOD_POST, HTTP_METHOD_PUT,
          HTTP_METHOD_DELETE, HTTP_METHOD_CONNECT, HTTP_METHOD_OPTIONS,
          HTTP_METHOD_TRACE, HTTP_METHOD_PATCH, HTTP_METHOD_UNKNOWN
      };
      for (size_t i = 0; i < sizeof (methods) / sizeof (methods[0]); i++)
        {
          SocketHTTP_Request method_req;
          memset (&method_req, 0, sizeof (method_req));
          method_req.method = methods[i];
          method_req.version = HTTP_VERSION_1_1;
          method_req.path = "/";
          SocketHTTP_Headers_T h = SocketHTTP_Headers_new (arena);
          if (h)
            {
              method_req.headers = h;
              SocketHTTP_Headers_add (h, "Host", "example.com");
              SocketHTTP1_serialize_request (&method_req, output_buffer, sizeof (output_buffer));
            }
        }

      /* Test with all status code categories */
      int status_codes[] = {100, 101, 200, 201, 204, 301, 302, 304, 400, 401, 403, 404, 500, 502, 503};
      for (size_t i = 0; i < sizeof (status_codes) / sizeof (status_codes[0]); i++)
        {
          SocketHTTP_Response status_resp;
          memset (&status_resp, 0, sizeof (status_resp));
          status_resp.version = HTTP_VERSION_1_1;
          status_resp.status_code = status_codes[i];
          status_resp.reason_phrase = SocketHTTP_status_reason (status_codes[i]);
          SocketHTTP_Headers_T h = SocketHTTP_Headers_new (arena);
          if (h)
            {
              status_resp.headers = h;
              SocketHTTP_Headers_add (h, "Content-Length", "0");
              SocketHTTP1_serialize_response (&status_resp, output_buffer, sizeof (output_buffer));
            }
        }
    }

    /* ====================================================================
     * Test 6: Buffer size edge cases
     * ==================================================================== */
    {
      SocketHTTP_Response resp;
      memset (&resp, 0, sizeof (resp));
      resp.version = HTTP_VERSION_1_1;
      resp.status_code = 200;
      resp.reason_phrase = "OK";

      SocketHTTP_Headers_T headers = SocketHTTP_Headers_new (arena);
      if (headers)
        {
          resp.headers = headers;
          SocketHTTP_Headers_add (headers, "Content-Type", "text/plain");

          /* Test with various buffer sizes */
          for (size_t buf_size = 0; buf_size < 256; buf_size++)
            {
              char *test_buf = Arena_alloc (arena, buf_size + 1, __FILE__, __LINE__);
              if (test_buf)
                {
                  ssize_t result = SocketHTTP1_serialize_response (&resp, test_buf, buf_size);
                  (void)result;
                }
            }
        }
    }
  }
  EXCEPT (SocketHTTP1_SerializeError)
  {
    /* Expected on serialization errors */
  }
  EXCEPT (SocketHTTP1_ParseError)
  {
    /* Expected on parse errors in roundtrip */
  }
  EXCEPT (SocketHTTP_Failed)
  {
    /* Expected on HTTP failures */
  }
  EXCEPT (Arena_Failed)
  {
    /* Expected on memory exhaustion */
  }
  END_TRY;

  Arena_dispose (&arena);

  return 0;
}
