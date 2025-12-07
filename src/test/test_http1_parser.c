/**
 * test_http1_parser.c - HTTP/1.1 Parser Test Suite
 *
 * Part of the Socket Library
 *
 * Comprehensive tests for RFC 9112 HTTP/1.1 message parsing.
 */

#include "test/Test.h"
#include "core/Arena.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"

#include <stdio.h>
#include <string.h>

/* ============================================================================
 * Request Parsing Tests
 * ============================================================================ */

TEST (http1_simple_get_request)
{
  const char *request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
  size_t consumed;
  SocketHTTP1_Result result;
  const SocketHTTP_Request *req;
  Arena_T arena;
  SocketHTTP1_Parser_T parser;

  arena = Arena_new ();
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);

  result = SocketHTTP1_Parser_execute (parser, request, strlen (request),
                                       &consumed);
  ASSERT_EQ (HTTP1_OK, result);
  ASSERT_EQ (strlen (request), consumed);

  req = SocketHTTP1_Parser_get_request (parser);
  ASSERT_NOT_NULL (req);
  ASSERT_EQ (HTTP_METHOD_GET, req->method);
  ASSERT_EQ (HTTP_VERSION_1_1, req->version);
  ASSERT (strcmp (req->path, "/") == 0);
  ASSERT (strcmp (req->authority, "example.com") == 0);

  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

TEST (http1_get_with_query)
{
  const char *request
      = "GET /search?q=test&page=1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
  size_t consumed;
  SocketHTTP1_Result result;
  const SocketHTTP_Request *req;
  Arena_T arena;
  SocketHTTP1_Parser_T parser;

  arena = Arena_new ();
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);

  result = SocketHTTP1_Parser_execute (parser, request, strlen (request),
                                       &consumed);
  ASSERT_EQ (HTTP1_OK, result);

  req = SocketHTTP1_Parser_get_request (parser);
  ASSERT_NOT_NULL (req);
  ASSERT (strcmp (req->path, "/search?q=test&page=1") == 0);

  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

TEST (http1_post_with_body)
{
  const char *request = "POST /api/data HTTP/1.1\r\n"
                        "Host: api.example.com\r\n"
                        "Content-Type: application/json\r\n"
                        "Content-Length: 13\r\n"
                        "\r\n";
  size_t consumed;
  SocketHTTP1_Result result;
  const SocketHTTP_Request *req;
  Arena_T arena;
  SocketHTTP1_Parser_T parser;

  arena = Arena_new ();
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);

  result = SocketHTTP1_Parser_execute (parser, request, strlen (request),
                                       &consumed);
  ASSERT_EQ (HTTP1_OK, result);

  req = SocketHTTP1_Parser_get_request (parser);
  ASSERT_NOT_NULL (req);
  ASSERT_EQ (HTTP_METHOD_POST, req->method);
  ASSERT_EQ (1, req->has_body);
  ASSERT_EQ (13, req->content_length);
  ASSERT_EQ (HTTP1_BODY_CONTENT_LENGTH, SocketHTTP1_Parser_body_mode (parser));

  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

TEST (http1_chunked_request)
{
  const char *request = "POST /upload HTTP/1.1\r\n"
                        "Host: example.com\r\n"
                        "Transfer-Encoding: chunked\r\n"
                        "\r\n";
  size_t consumed;
  SocketHTTP1_Result result;
  const SocketHTTP_Request *req;
  Arena_T arena;
  SocketHTTP1_Parser_T parser;

  arena = Arena_new ();
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);

  result = SocketHTTP1_Parser_execute (parser, request, strlen (request),
                                       &consumed);
  ASSERT_EQ (HTTP1_OK, result);

  req = SocketHTTP1_Parser_get_request (parser);
  ASSERT_NOT_NULL (req);
  ASSERT_EQ (HTTP1_BODY_CHUNKED, SocketHTTP1_Parser_body_mode (parser));

  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

TEST (http1_keepalive_http11)
{
  const char *request = "GET / HTTP/1.1\r\nHost: test.com\r\n\r\n";
  size_t consumed;
  Arena_T arena;
  SocketHTTP1_Parser_T parser;

  arena = Arena_new ();
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);
  SocketHTTP1_Parser_execute (parser, request, strlen (request), &consumed);

  /* HTTP/1.1 keeps alive by default */
  ASSERT_EQ (1, SocketHTTP1_Parser_should_keepalive (parser));

  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

TEST (http1_close_connection)
{
  const char *request
      = "GET / HTTP/1.1\r\nHost: test.com\r\nConnection: close\r\n\r\n";
  size_t consumed;
  Arena_T arena;
  SocketHTTP1_Parser_T parser;

  arena = Arena_new ();
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);
  SocketHTTP1_Parser_execute (parser, request, strlen (request), &consumed);

  ASSERT_EQ (0, SocketHTTP1_Parser_should_keepalive (parser));

  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

TEST (http1_http10_default_close)
{
  const char *request = "GET / HTTP/1.0\r\nHost: test.com\r\n\r\n";
  size_t consumed;
  const SocketHTTP_Request *req;
  Arena_T arena;
  SocketHTTP1_Parser_T parser;

  arena = Arena_new ();
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);
  SocketHTTP1_Parser_execute (parser, request, strlen (request), &consumed);

  req = SocketHTTP1_Parser_get_request (parser);
  ASSERT_EQ (HTTP_VERSION_1_0, req->version);
  /* HTTP/1.0 closes by default */
  ASSERT_EQ (0, SocketHTTP1_Parser_should_keepalive (parser));

  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

TEST (http1_expect_continue)
{
  const char *request = "POST /upload HTTP/1.1\r\n"
                        "Host: test.com\r\n"
                        "Content-Length: 1000\r\n"
                        "Expect: 100-continue\r\n"
                        "\r\n";
  size_t consumed;
  Arena_T arena;
  SocketHTTP1_Parser_T parser;

  arena = Arena_new ();
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);
  SocketHTTP1_Parser_execute (parser, request, strlen (request), &consumed);

  ASSERT_EQ (1, SocketHTTP1_Parser_expects_continue (parser));

  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

TEST (http1_upgrade_websocket)
{
  const char *request = "GET /ws HTTP/1.1\r\n"
                        "Host: test.com\r\n"
                        "Upgrade: websocket\r\n"
                        "Connection: Upgrade\r\n"
                        "\r\n";
  size_t consumed;
  Arena_T arena;
  SocketHTTP1_Parser_T parser;

  arena = Arena_new ();
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);
  SocketHTTP1_Parser_execute (parser, request, strlen (request), &consumed);

  ASSERT_EQ (1, SocketHTTP1_Parser_is_upgrade (parser));
  ASSERT (strcmp (SocketHTTP1_Parser_upgrade_protocol (parser), "websocket")
          == 0);

  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

/* ============================================================================
 * Response Parsing Tests
 * ============================================================================ */

TEST (http1_simple_response)
{
  const char *response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
  size_t consumed;
  SocketHTTP1_Result result;
  const SocketHTTP_Response *resp;
  Arena_T arena;
  SocketHTTP1_Parser_T parser;

  arena = Arena_new ();
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, NULL, arena);

  result = SocketHTTP1_Parser_execute (parser, response, strlen (response),
                                       &consumed);
  ASSERT_EQ (HTTP1_OK, result);

  resp = SocketHTTP1_Parser_get_response (parser);
  ASSERT_NOT_NULL (resp);
  ASSERT_EQ (200, resp->status_code);
  ASSERT_EQ (HTTP_VERSION_1_1, resp->version);
  ASSERT_EQ (5, resp->content_length);

  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

TEST (http1_204_no_content)
{
  const char *response = "HTTP/1.1 204 No Content\r\n\r\n";
  size_t consumed;
  const SocketHTTP_Response *resp;
  Arena_T arena;
  SocketHTTP1_Parser_T parser;

  arena = Arena_new ();
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, NULL, arena);
  SocketHTTP1_Parser_execute (parser, response, strlen (response), &consumed);

  resp = SocketHTTP1_Parser_get_response (parser);
  ASSERT_NOT_NULL (resp);
  ASSERT_EQ (204, resp->status_code);
  ASSERT_EQ (0, resp->has_body);
  ASSERT_EQ (1, SocketHTTP1_Parser_body_complete (parser));

  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

TEST (http1_304_not_modified)
{
  const char *response = "HTTP/1.1 304 Not Modified\r\n\r\n";
  size_t consumed;
  const SocketHTTP_Response *resp;
  Arena_T arena;
  SocketHTTP1_Parser_T parser;

  arena = Arena_new ();
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, NULL, arena);
  SocketHTTP1_Parser_execute (parser, response, strlen (response), &consumed);

  resp = SocketHTTP1_Parser_get_response (parser);
  ASSERT_NOT_NULL (resp);
  ASSERT_EQ (304, resp->status_code);
  ASSERT_EQ (0, resp->has_body);

  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

TEST (http1_chunked_response)
{
  const char *response = "HTTP/1.1 200 OK\r\n"
                         "Transfer-Encoding: chunked\r\n"
                         "\r\n";
  size_t consumed;
  const SocketHTTP_Response *resp;
  Arena_T arena;
  SocketHTTP1_Parser_T parser;

  arena = Arena_new ();
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, NULL, arena);
  SocketHTTP1_Parser_execute (parser, response, strlen (response), &consumed);

  resp = SocketHTTP1_Parser_get_response (parser);
  ASSERT_NOT_NULL (resp);
  ASSERT_EQ (HTTP1_BODY_CHUNKED, SocketHTTP1_Parser_body_mode (parser));

  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

/* ============================================================================
 * Security Tests - Request Smuggling Prevention
 * ============================================================================ */

TEST (http1_smuggling_cl_te)
{
  /* Both Content-Length and Transfer-Encoding present */
  const char *request = "POST / HTTP/1.1\r\n"
                        "Host: test.com\r\n"
                        "Content-Length: 5\r\n"
                        "Transfer-Encoding: chunked\r\n"
                        "\r\n";
  size_t consumed;
  SocketHTTP1_Result result;
  Arena_T arena;
  SocketHTTP1_Parser_T parser;

  arena = Arena_new ();
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);

  result = SocketHTTP1_Parser_execute (parser, request, strlen (request),
                                       &consumed);
  ASSERT_EQ (HTTP1_ERROR_SMUGGLING_DETECTED, result);

  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

TEST (http1_invalid_content_length)
{
  const char *request = "POST / HTTP/1.1\r\n"
                        "Host: test.com\r\n"
                        "Content-Length: abc\r\n"
                        "\r\n";
  size_t consumed;
  SocketHTTP1_Result result;
  Arena_T arena;
  SocketHTTP1_Parser_T parser;

  arena = Arena_new ();
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);

  result = SocketHTTP1_Parser_execute (parser, request, strlen (request),
                                       &consumed);
  ASSERT_EQ (HTTP1_ERROR_INVALID_CONTENT_LENGTH, result);

  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

TEST (http1_negative_content_length)
{
  const char *request = "POST / HTTP/1.1\r\n"
                        "Host: test.com\r\n"
                        "Content-Length: -5\r\n"
                        "\r\n";
  size_t consumed;
  SocketHTTP1_Result result;
  Arena_T arena;
  SocketHTTP1_Parser_T parser;

  arena = Arena_new ();
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);

  result = SocketHTTP1_Parser_execute (parser, request, strlen (request),
                                       &consumed);
  ASSERT_EQ (HTTP1_ERROR_INVALID_CONTENT_LENGTH, result);

  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

/* ============================================================================
 * Header Parsing Tests
 * ============================================================================ */

TEST (http1_multiple_headers)
{
  const char *request = "GET / HTTP/1.1\r\n"
                        "Host: test.com\r\n"
                        "Accept: text/html\r\n"
                        "Accept-Language: en-US\r\n"
                        "User-Agent: TestClient/1.0\r\n"
                        "\r\n";
  size_t consumed;
  const SocketHTTP_Request *req;
  Arena_T arena;
  SocketHTTP1_Parser_T parser;

  arena = Arena_new ();
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);
  SocketHTTP1_Parser_execute (parser, request, strlen (request), &consumed);

  req = SocketHTTP1_Parser_get_request (parser);
  ASSERT_NOT_NULL (req);

  ASSERT (strcmp (SocketHTTP_Headers_get (req->headers, "Accept"), "text/html")
          == 0);
  ASSERT (strcmp (SocketHTTP_Headers_get (req->headers, "Accept-Language"),
                  "en-US")
          == 0);
  ASSERT (strcmp (SocketHTTP_Headers_get (req->headers, "User-Agent"),
                  "TestClient/1.0")
          == 0);

  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

TEST (http1_header_case_insensitive)
{
  const char *request = "GET / HTTP/1.1\r\n"
                        "host: test.com\r\n"
                        "CONTENT-TYPE: text/plain\r\n"
                        "\r\n";
  size_t consumed;
  const SocketHTTP_Request *req;
  Arena_T arena;
  SocketHTTP1_Parser_T parser;

  arena = Arena_new ();
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);
  SocketHTTP1_Parser_execute (parser, request, strlen (request), &consumed);

  req = SocketHTTP1_Parser_get_request (parser);

  /* Should find with any case */
  ASSERT (strcmp (SocketHTTP_Headers_get (req->headers, "Host"), "test.com")
          == 0);
  ASSERT (strcmp (SocketHTTP_Headers_get (req->headers, "HOST"), "test.com")
          == 0);
  ASSERT (strcmp (SocketHTTP_Headers_get (req->headers, "content-type"),
                  "text/plain")
          == 0);

  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

/* ============================================================================
 * Incremental Parsing Tests
 * ============================================================================ */

TEST (http1_incremental_parsing)
{
  const char *part1 = "GET / HTTP/1.1\r\n";
  const char *part2 = "Host: test.";
  const char *part3 = "com\r\n\r\n";
  size_t consumed;
  SocketHTTP1_Result result;
  Arena_T arena;
  SocketHTTP1_Parser_T parser;

  arena = Arena_new ();
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);

  result = SocketHTTP1_Parser_execute (parser, part1, strlen (part1),
                                       &consumed);
  ASSERT_EQ (HTTP1_INCOMPLETE, result);

  result = SocketHTTP1_Parser_execute (parser, part2, strlen (part2),
                                       &consumed);
  ASSERT_EQ (HTTP1_INCOMPLETE, result);

  result = SocketHTTP1_Parser_execute (parser, part3, strlen (part3),
                                       &consumed);
  ASSERT_EQ (HTTP1_OK, result);

  ASSERT_NOT_NULL (SocketHTTP1_Parser_get_request (parser));

  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

/* ============================================================================
 * Body Reading Tests
 * ============================================================================ */

TEST (http1_read_body_content_length)
{
  const char *request = "POST / HTTP/1.1\r\n"
                        "Host: test.com\r\n"
                        "Content-Length: 11\r\n"
                        "\r\n";
  const char *body = "Hello World";
  size_t consumed;
  char output[64];
  size_t written;
  SocketHTTP1_Result result;
  Arena_T arena;
  SocketHTTP1_Parser_T parser;

  arena = Arena_new ();
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);

  SocketHTTP1_Parser_execute (parser, request, strlen (request), &consumed);

  result = SocketHTTP1_Parser_read_body (parser, body, strlen (body), &consumed,
                                         output, sizeof (output), &written);
  ASSERT_EQ (HTTP1_OK, result);
  ASSERT_EQ (11, written);
  ASSERT (memcmp (output, "Hello World", 11) == 0);
  ASSERT_EQ (1, SocketHTTP1_Parser_body_complete (parser));

  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

TEST (http1_read_body_chunked)
{
  const char *request = "POST / HTTP/1.1\r\n"
                        "Host: test.com\r\n"
                        "Transfer-Encoding: chunked\r\n"
                        "\r\n";
  const char *body = "5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n";
  size_t consumed;
  char output[64];
  size_t written;
  SocketHTTP1_Result result;
  Arena_T arena;
  SocketHTTP1_Parser_T parser;

  arena = Arena_new ();
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);

  SocketHTTP1_Parser_execute (parser, request, strlen (request), &consumed);

  result = SocketHTTP1_Parser_read_body (parser, body, strlen (body), &consumed,
                                         output, sizeof (output), &written);
  ASSERT_EQ (HTTP1_OK, result);
  ASSERT_EQ (11, written);
  ASSERT (memcmp (output, "Hello World", 11) == 0);
  ASSERT_EQ (1, SocketHTTP1_Parser_body_complete (parser));

  /* Security tests - require config for small limits */
  SocketHTTP1_Config small_config = {0};
  SocketHTTP1_config_defaults (&small_config);
  small_config.max_trailer_size = 50;
  small_config.max_chunk_ext = 10;  /* Small for extension test */
  SocketHTTP1_Parser_T sec_parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, &small_config, arena);
  SocketHTTP1_Parser_execute (sec_parser, request, strlen (request), &consumed);

  /* Oversized trailer - parser is incremental, need to call until complete or error */
  const char *oversized = "0\r\nTrailer: this is a long value exceeding small limit\r\n\r\n";
  size_t total_consumed = 0;
  result = HTTP1_OK;
  while (result == HTTP1_OK && !SocketHTTP1_Parser_body_complete (sec_parser) && total_consumed < strlen (oversized))
    {
      result = SocketHTTP1_Parser_read_body (sec_parser, oversized + total_consumed, 
                                             strlen (oversized) - total_consumed, &consumed, 
                                             output, sizeof (output), &written);
      total_consumed += consumed;
    }
  ASSERT (result == HTTP1_ERROR_HEADER_TOO_LARGE);

  /* Forbidden trailer - incremental processing */
  const char *forbidden = "0\r\nTransfer-Encoding: chunked\r\n\r\n";
  SocketHTTP1_Parser_reset (sec_parser);
  SocketHTTP1_Parser_execute (sec_parser, request, strlen (request), &consumed);
  total_consumed = 0;
  result = HTTP1_OK;
  while (result == HTTP1_OK && !SocketHTTP1_Parser_body_complete (sec_parser) && total_consumed < strlen (forbidden))
    {
      result = SocketHTTP1_Parser_read_body (sec_parser, forbidden + total_consumed, 
                                             strlen (forbidden) - total_consumed, &consumed, 
                                             output, sizeof (output), &written);
      total_consumed += consumed;
    }
  ASSERT_EQ (HTTP1_ERROR_INVALID_TRAILER, result);

  /* Long chunk extension - note: requires long string, but for demo */
  const char *long_ext = "1;ext=" "1234567890123456789012345678901234567890" /* >1024 in full test */ "\r\na\r\n0\r\n\r\n";
  SocketHTTP1_Parser_reset (sec_parser);
  SocketHTTP1_Parser_execute (sec_parser, request, strlen (request), &consumed);
  total_consumed = 0;
  result = HTTP1_OK;
  while (result == HTTP1_OK && !SocketHTTP1_Parser_body_complete (sec_parser) && total_consumed < strlen (long_ext))
    {
      result = SocketHTTP1_Parser_read_body (sec_parser, long_ext + total_consumed, 
                                             strlen (long_ext) - total_consumed, &consumed, 
                                             output, sizeof (output), &written);
      total_consumed += consumed;
    }
  ASSERT_EQ (HTTP1_ERROR_INVALID_CHUNK_SIZE, result);  /* If ext too long */

  SocketHTTP1_Parser_free (&sec_parser);
  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

/* ============================================================================
 * Serialization Tests
 * ============================================================================ */

TEST (http1_serialize_request)
{
  SocketHTTP_Request req = { 0 };
  char output[512];
  ssize_t len;
  Arena_T arena;
  SocketHTTP_Headers_T headers;

  arena = Arena_new ();
  headers = SocketHTTP_Headers_new (arena);
  SocketHTTP_Headers_add (headers, "User-Agent", "Test/1.0");

  req.method = HTTP_METHOD_GET;
  req.version = HTTP_VERSION_1_1;
  req.path = "/api/test";
  req.authority = "api.example.com";
  req.headers = headers;
  req.has_body = 0;

  len = SocketHTTP1_serialize_request (&req, output, sizeof (output));
  ASSERT (len > 0);

  /* Check output contains expected parts */
  ASSERT (strstr (output, "GET /api/test HTTP/1.1\r\n") != NULL);
  ASSERT (strstr (output, "User-Agent: Test/1.0\r\n") != NULL);
  ASSERT (strstr (output, "Host: api.example.com\r\n") != NULL);

  Arena_dispose (&arena);
}

TEST (http1_serialize_response)
{
  SocketHTTP_Response resp = { 0 };
  char output[512];
  ssize_t len;
  Arena_T arena;
  SocketHTTP_Headers_T headers;

  arena = Arena_new ();
  headers = SocketHTTP_Headers_new (arena);
  SocketHTTP_Headers_add (headers, "Content-Type", "text/plain");

  resp.version = HTTP_VERSION_1_1;
  resp.status_code = 200;
  resp.reason_phrase = "OK";
  resp.headers = headers;
  resp.has_body = 1;
  resp.content_length = 5;

  len = SocketHTTP1_serialize_response (&resp, output, sizeof (output));
  ASSERT (len > 0);

  ASSERT (strstr (output, "HTTP/1.1 200 OK\r\n") != NULL);
  ASSERT (strstr (output, "Content-Type: text/plain\r\n") != NULL);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Chunk Encoding Tests
 * ============================================================================ */

TEST (http1_chunk_encode)
{
  const char *data = "Hello";
  char output[64];
  ssize_t len;
  const char *expected = "5\r\nHello\r\n";

  len = SocketHTTP1_chunk_encode (data, 5, output, sizeof (output));
  ASSERT_EQ (10, len);
  ASSERT (memcmp (output, expected, (size_t)len) == 0);
}

TEST (http1_chunk_final)
{
  char output[64];
  ssize_t len;
  const char *expected = "0\r\n\r\n";

  len = SocketHTTP1_chunk_final (output, sizeof (output), NULL);
  ASSERT_EQ (5, len);
  ASSERT (memcmp (output, expected, (size_t)len) == 0);
}

/* ============================================================================
 * Error Cases
 * ============================================================================ */

TEST (http1_invalid_method)
{
  const char *request = "INVALID_METHOD_TOO_LONG_12345678 / HTTP/1.1\r\n\r\n";
  size_t consumed;
  SocketHTTP1_Result result;
  Arena_T arena;
  SocketHTTP1_Parser_T parser;

  arena = Arena_new ();
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);

  result = SocketHTTP1_Parser_execute (parser, request, strlen (request),
                                       &consumed);
  ASSERT_EQ (HTTP1_ERROR_INVALID_METHOD, result);

  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

TEST (http1_result_strings)
{
  ASSERT (strcmp (SocketHTTP1_result_string (HTTP1_OK), "OK") == 0);
  ASSERT (strcmp (SocketHTTP1_result_string (HTTP1_INCOMPLETE),
                  "Incomplete - need more data")
          == 0);
  ASSERT (strcmp (SocketHTTP1_result_string (HTTP1_ERROR_SMUGGLING_DETECTED),
                  "Request smuggling attempt detected")
          == 0);
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================ */

int
main (void)
{
  printf ("HTTP/1.1 Parser Tests\n");
  printf ("=====================\n\n");

  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

TEST (http1_multi_cl_same)
{
  const char *request = "GET / HTTP/1.1\r\n"
                        "Host: test.com\r\n"
                        "Content-Length: 10\r\n"
                        "Content-Length: 10\r\n"
                        "\r\n";
  size_t consumed;
  SocketHTTP1_Result result;
  const SocketHTTP_Request *req;
  Arena_T arena;
  SocketHTTP1_Parser_T parser;

  arena = Arena_new ();
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);
  result = SocketHTTP1_Parser_execute (parser, request, strlen (request), &consumed);
  ASSERT_EQ (HTTP1_OK, result);
  ASSERT_EQ (strlen (request), consumed);
  req = SocketHTTP1_Parser_get_request (parser);
  ASSERT_NOT_NULL (req);
  ASSERT_EQ (10, req->content_length);
  ASSERT_EQ (HTTP1_BODY_CONTENT_LENGTH, SocketHTTP1_Parser_body_mode (parser));
  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

TEST (http1_multi_cl_differ_reject)
{
  const char *request = "GET / HTTP/1.1\r\n"
                        "Host: test.com\r\n"
                        "Content-Length: 10\r\n"
                        "Content-Length: 20\r\n"
                        "\r\n";
  size_t consumed;
  SocketHTTP1_Result result;
  Arena_T arena;
  SocketHTTP1_Parser_T parser;

  arena = Arena_new ();
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);
  result = SocketHTTP1_Parser_execute (parser, request, strlen (request), &consumed);
  ASSERT (result != HTTP1_OK);
  ASSERT_EQ (HTTP1_ERROR_INVALID_CONTENT_LENGTH, result); // mismatch validation
  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

TEST (http1_multi_te_chunked_hidden)
{
  const char *request = "GET / HTTP/1.1\r\n"
                        "Host: test.com\r\n"
                        "Transfer-Encoding: identity\r\n"
                        "Transfer-Encoding: chunked\r\n"
                        "\r\n";
  size_t consumed;
  SocketHTTP1_Result result;
  SocketHTTP1_Config config;
  Arena_T arena;
  SocketHTTP1_Parser_T parser;

  /* Use non-strict mode to allow multiple TE headers for smuggling detection test */
  SocketHTTP1_config_defaults (&config);
  config.strict_mode = 0;

  arena = Arena_new ();
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, &config, arena);
  result = SocketHTTP1_Parser_execute (parser, request, strlen (request), &consumed);
  ASSERT_EQ (HTTP1_OK, result);
  ASSERT_EQ (HTTP1_BODY_CHUNKED, SocketHTTP1_Parser_body_mode (parser)); // detects in second TE
  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

TEST (http1_te_unsupported_reject)
{
  const char *request = "GET / HTTP/1.1\r\n"
                        "Host: test.com\r\n"
                        "Transfer-Encoding: gzip\r\n"
                        "\r\n";
  size_t consumed;
  SocketHTTP1_Result result;
  SocketHTTP1_Config config;
  Arena_T arena;
  SocketHTTP1_Parser_T parser;

  SocketHTTP1_config_defaults (&config);
  config.strict_mode = 1;

  arena = Arena_new ();
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, &config, arena);
  result = SocketHTTP1_Parser_execute (parser, request, strlen (request), &consumed);
  ASSERT (result != HTTP1_OK);
  ASSERT_EQ (HTTP1_ERROR_UNSUPPORTED_TRANSFER_CODING, result);
  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

TEST (http1_te_chunked_with_extra_reject)
{
  const char *request = "GET / HTTP/1.1\r\n"
                        "Host: test.com\r\n"
                        "Transfer-Encoding: chunked,identity\r\n"
                        "\r\n";
  size_t consumed;
  SocketHTTP1_Result result;
  SocketHTTP1_Config config;
  Arena_T arena;
  SocketHTTP1_Parser_T parser;

  SocketHTTP1_config_defaults (&config);
  config.strict_mode = 1;

  arena = Arena_new ();
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, &config, arena);
  result = SocketHTTP1_Parser_execute (parser, request, strlen (request), &consumed);
  ASSERT (result != HTTP1_OK);
  ASSERT_EQ (HTTP1_ERROR_UNSUPPORTED_TRANSFER_CODING, result); // extra coding rejected
  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

TEST (http1_long_header_line_reject)
{
  SocketHTTP1_Config config;
  SocketHTTP1_config_defaults (&config);
  config.max_header_line = 50; // small for test

  char long_request[512];
  strncpy (long_request, "GET / HTTP/1.1\r\nHost: test.com\r\nX-Long: ", sizeof(long_request) - 1);
  long_request[sizeof(long_request) - 1] = '\0';
  // Fill with 100 'a' to exceed 50
  size_t curr_len = strlen (long_request);
  memset (long_request + curr_len, 'a', (100 < (sizeof(long_request) - curr_len - 6) ? 100 : (sizeof(long_request) - curr_len - 6)));
  strncat (long_request, "\r\n\r\n", sizeof(long_request) - curr_len - 1);

  size_t consumed;
  SocketHTTP1_Result result;
  Arena_T arena;
  SocketHTTP1_Parser_T parser;

  arena = Arena_new ();
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, &config, arena);
  result = SocketHTTP1_Parser_execute (parser, long_request, strlen (long_request), &consumed);
  ASSERT (result != HTTP1_OK);
  ASSERT_EQ (HTTP1_ERROR_HEADER_TOO_LARGE, result); // line too long
  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

TEST (http1_invalid_uri_reject)
{
  const char *invalid_uri = "GET /invalid%GG HTTP/1.1\r\nHost: test.com\r\n\r\n"; // invalid % encoding
  size_t consumed;
  SocketHTTP1_Result result;
  Arena_T arena;
  SocketHTTP1_Parser_T parser;

  arena = Arena_new ();
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);
  result = SocketHTTP1_Parser_execute (parser, invalid_uri, strlen (invalid_uri), &consumed);
  ASSERT (result != HTTP1_OK);
  ASSERT_EQ (HTTP1_ERROR_INVALID_URI, result); // URI parse fails on invalid encoding
  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);
}

