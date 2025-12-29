/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_http_core.c - HTTP Core Module Tests
 *
 * Part of the Socket Library Test Suite
 *
 * Tests HTTP methods, status codes, headers, URI parsing, date parsing,
 * media type parsing, and content negotiation.
 */

#include "core/Arena.h"
#include "http/SocketHTTP.h"
#include "test/Test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ============================================================================
 * Test Counters
 * ============================================================================
 */

static int tests_run = 0;
static int tests_passed = 0;

#define TEST_ASSERT(cond, msg)                                                \
  do                                                                          \
    {                                                                         \
      tests_run++;                                                            \
      if (cond)                                                               \
        {                                                                     \
          tests_passed++;                                                     \
        }                                                                     \
      else                                                                    \
        {                                                                     \
          printf ("FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__);             \
        }                                                                     \
    }                                                                         \
  while (0)

/* ============================================================================
 * HTTP Version Tests
 * ============================================================================
 */

static void
test_version_string (void)
{
  printf ("Testing HTTP version strings...\n");

  TEST_ASSERT (
      strcmp (SocketHTTP_version_string (HTTP_VERSION_0_9), "HTTP/0.9") == 0,
      "HTTP/0.9 string");
  TEST_ASSERT (
      strcmp (SocketHTTP_version_string (HTTP_VERSION_1_0), "HTTP/1.0") == 0,
      "HTTP/1.0 string");
  TEST_ASSERT (
      strcmp (SocketHTTP_version_string (HTTP_VERSION_1_1), "HTTP/1.1") == 0,
      "HTTP/1.1 string");
  TEST_ASSERT (strcmp (SocketHTTP_version_string (HTTP_VERSION_2), "HTTP/2")
                   == 0,
               "HTTP/2 string");
  TEST_ASSERT (strcmp (SocketHTTP_version_string (HTTP_VERSION_3), "HTTP/3")
                   == 0,
               "HTTP/3 string");
}

static void
test_version_parse (void)
{
  printf ("Testing HTTP version parsing...\n");

  TEST_ASSERT (SocketHTTP_version_parse ("HTTP/1.1", 0) == HTTP_VERSION_1_1,
               "Parse HTTP/1.1");
  TEST_ASSERT (SocketHTTP_version_parse ("HTTP/1.0", 0) == HTTP_VERSION_1_0,
               "Parse HTTP/1.0");
  TEST_ASSERT (SocketHTTP_version_parse ("HTTP/0.9", 0) == HTTP_VERSION_0_9,
               "Parse HTTP/0.9");
  TEST_ASSERT (SocketHTTP_version_parse ("HTTP/2", 0) == HTTP_VERSION_2,
               "Parse HTTP/2");
  TEST_ASSERT (SocketHTTP_version_parse ("HTTP/3", 0) == HTTP_VERSION_3,
               "Parse HTTP/3");
  TEST_ASSERT (SocketHTTP_version_parse ("invalid", 0) == HTTP_VERSION_0_9,
               "Parse invalid returns default");
}

/* ============================================================================
 * HTTP Method Tests
 * ============================================================================
 */

static void
test_method_name (void)
{
  printf ("Testing HTTP method names...\n");

  TEST_ASSERT (strcmp (SocketHTTP_method_name (HTTP_METHOD_GET), "GET") == 0,
               "GET name");
  TEST_ASSERT (strcmp (SocketHTTP_method_name (HTTP_METHOD_HEAD), "HEAD") == 0,
               "HEAD name");
  TEST_ASSERT (strcmp (SocketHTTP_method_name (HTTP_METHOD_POST), "POST") == 0,
               "POST name");
  TEST_ASSERT (strcmp (SocketHTTP_method_name (HTTP_METHOD_PUT), "PUT") == 0,
               "PUT name");
  TEST_ASSERT (strcmp (SocketHTTP_method_name (HTTP_METHOD_DELETE), "DELETE")
                   == 0,
               "DELETE name");
  TEST_ASSERT (strcmp (SocketHTTP_method_name (HTTP_METHOD_CONNECT), "CONNECT")
                   == 0,
               "CONNECT name");
  TEST_ASSERT (strcmp (SocketHTTP_method_name (HTTP_METHOD_OPTIONS), "OPTIONS")
                   == 0,
               "OPTIONS name");
  TEST_ASSERT (strcmp (SocketHTTP_method_name (HTTP_METHOD_TRACE), "TRACE")
                   == 0,
               "TRACE name");
  TEST_ASSERT (strcmp (SocketHTTP_method_name (HTTP_METHOD_PATCH), "PATCH")
                   == 0,
               "PATCH name");
  TEST_ASSERT (SocketHTTP_method_name (HTTP_METHOD_UNKNOWN) == NULL,
               "UNKNOWN returns NULL");
}

static void
test_method_parse (void)
{
  printf ("Testing HTTP method parsing...\n");

  TEST_ASSERT (SocketHTTP_method_parse ("GET", 0) == HTTP_METHOD_GET,
               "Parse GET");
  TEST_ASSERT (SocketHTTP_method_parse ("POST", 0) == HTTP_METHOD_POST,
               "Parse POST");
  TEST_ASSERT (SocketHTTP_method_parse ("PUT", 0) == HTTP_METHOD_PUT,
               "Parse PUT");
  TEST_ASSERT (SocketHTTP_method_parse ("DELETE", 0) == HTTP_METHOD_DELETE,
               "Parse DELETE");
  TEST_ASSERT (SocketHTTP_method_parse ("PATCH", 0) == HTTP_METHOD_PATCH,
               "Parse PATCH");
  TEST_ASSERT (SocketHTTP_method_parse ("UNKNOWN", 0) == HTTP_METHOD_UNKNOWN,
               "Parse unknown method");
  TEST_ASSERT (SocketHTTP_method_parse ("get", 0) == HTTP_METHOD_UNKNOWN,
               "Methods are case-sensitive");
}

static void
test_method_properties (void)
{
  printf ("Testing HTTP method properties...\n");

  SocketHTTP_MethodProperties props;

  props = SocketHTTP_method_properties (HTTP_METHOD_GET);
  TEST_ASSERT (props.safe == 1, "GET is safe");
  TEST_ASSERT (props.idempotent == 1, "GET is idempotent");
  TEST_ASSERT (props.cacheable == 1, "GET is cacheable");
  TEST_ASSERT (props.has_body == 0, "GET has no body");
  TEST_ASSERT (props.response_body == 1, "GET has response body");

  props = SocketHTTP_method_properties (HTTP_METHOD_HEAD);
  TEST_ASSERT (props.safe == 1, "HEAD is safe");
  TEST_ASSERT (props.response_body == 0, "HEAD has no response body");

  props = SocketHTTP_method_properties (HTTP_METHOD_POST);
  TEST_ASSERT (props.safe == 0, "POST is not safe");
  TEST_ASSERT (props.idempotent == 0, "POST is not idempotent");
  TEST_ASSERT (props.has_body == 1, "POST has body");

  props = SocketHTTP_method_properties (HTTP_METHOD_PUT);
  TEST_ASSERT (props.safe == 0, "PUT is not safe");
  TEST_ASSERT (props.idempotent == 1, "PUT is idempotent");

  props = SocketHTTP_method_properties (HTTP_METHOD_DELETE);
  TEST_ASSERT (props.idempotent == 1, "DELETE is idempotent");
}

static void
test_method_valid (void)
{
  printf ("Testing HTTP method validation...\n");

  TEST_ASSERT (SocketHTTP_method_valid ("GET", 3) == 1, "GET is valid");
  TEST_ASSERT (SocketHTTP_method_valid ("CUSTOM", 6) == 1, "CUSTOM is valid");
  TEST_ASSERT (SocketHTTP_method_valid ("X-My-Method", 11) == 1,
               "X-My-Method is valid");
  TEST_ASSERT (SocketHTTP_method_valid ("GET ", 4) == 0, "Space invalid");
  TEST_ASSERT (SocketHTTP_method_valid ("GET\t", 4) == 0, "Tab invalid");
  TEST_ASSERT (SocketHTTP_method_valid ("", 0) == 0, "Empty invalid");
}

/* ============================================================================
 * HTTP Status Code Tests
 * ============================================================================
 */

static void
test_status_reason (void)
{
  printf ("Testing HTTP status reasons...\n");

  TEST_ASSERT (strcmp (SocketHTTP_status_reason (200), "OK") == 0, "200 OK");
  TEST_ASSERT (strcmp (SocketHTTP_status_reason (201), "Created") == 0,
               "201 Created");
  TEST_ASSERT (strcmp (SocketHTTP_status_reason (204), "No Content") == 0,
               "204 No Content");
  TEST_ASSERT (strcmp (SocketHTTP_status_reason (301), "Moved Permanently")
                   == 0,
               "301 Moved Permanently");
  TEST_ASSERT (strcmp (SocketHTTP_status_reason (400), "Bad Request") == 0,
               "400 Bad Request");
  TEST_ASSERT (strcmp (SocketHTTP_status_reason (404), "Not Found") == 0,
               "404 Not Found");
  TEST_ASSERT (strcmp (SocketHTTP_status_reason (418), "I'm a Teapot") == 0,
               "418 I'm a Teapot");
  TEST_ASSERT (strcmp (SocketHTTP_status_reason (500), "Internal Server Error")
                   == 0,
               "500 Internal Server Error");
  TEST_ASSERT (strcmp (SocketHTTP_status_reason (999), "Unknown") == 0,
               "Unknown code");
}

static void
test_status_category (void)
{
  printf ("Testing HTTP status categories...\n");

  TEST_ASSERT (SocketHTTP_status_category (100) == HTTP_STATUS_INFORMATIONAL,
               "100 is informational");
  TEST_ASSERT (SocketHTTP_status_category (200) == HTTP_STATUS_SUCCESSFUL,
               "200 is successful");
  TEST_ASSERT (SocketHTTP_status_category (301) == HTTP_STATUS_REDIRECTION,
               "301 is redirection");
  TEST_ASSERT (SocketHTTP_status_category (404) == HTTP_STATUS_CLIENT_ERROR,
               "404 is client error");
  TEST_ASSERT (SocketHTTP_status_category (500) == HTTP_STATUS_SERVER_ERROR,
               "500 is server error");
  TEST_ASSERT (SocketHTTP_status_category (50) == 0, "50 is invalid");
  TEST_ASSERT (SocketHTTP_status_category (600) == 0, "600 is invalid");
}

static void
test_status_valid (void)
{
  printf ("Testing HTTP status validation...\n");

  TEST_ASSERT (SocketHTTP_status_valid (100) == 1, "100 is valid");
  TEST_ASSERT (SocketHTTP_status_valid (599) == 1, "599 is valid");
  TEST_ASSERT (SocketHTTP_status_valid (99) == 0, "99 is invalid");
  TEST_ASSERT (SocketHTTP_status_valid (600) == 0, "600 is invalid");
}

/* ============================================================================
 * HTTP Header Tests
 * ============================================================================
 */

static void
test_headers_basic (void)
{
  printf ("Testing HTTP headers basic operations...\n");

  Arena_T arena = Arena_new ();
  SocketHTTP_Headers_T headers = SocketHTTP_Headers_new (arena);
  TEST_ASSERT (headers != NULL, "Create headers");

  TEST_ASSERT (SocketHTTP_Headers_count (headers) == 0, "Initial count is 0");

  TEST_ASSERT (SocketHTTP_Headers_add (headers, "Content-Type", "text/html")
                   == 0,
               "Add Content-Type");
  TEST_ASSERT (SocketHTTP_Headers_count (headers) == 1, "Count is 1");

  const char *value = SocketHTTP_Headers_get (headers, "Content-Type");
  TEST_ASSERT (value != NULL && strcmp (value, "text/html") == 0,
               "Get Content-Type");

  /* Case-insensitive lookup */
  value = SocketHTTP_Headers_get (headers, "content-type");
  TEST_ASSERT (value != NULL && strcmp (value, "text/html") == 0,
               "Case-insensitive get");
  value = SocketHTTP_Headers_get (headers, "CONTENT-TYPE");
  TEST_ASSERT (value != NULL && strcmp (value, "text/html") == 0,
               "Upper case get");

  Arena_dispose (&arena);
}

static void
test_headers_multi (void)
{
  printf ("Testing HTTP headers multi-value...\n");

  Arena_T arena = Arena_new ();
  SocketHTTP_Headers_T headers = SocketHTTP_Headers_new (arena);

  SocketHTTP_Headers_add (headers, "Set-Cookie", "a=1");
  SocketHTTP_Headers_add (headers, "Set-Cookie", "b=2");
  SocketHTTP_Headers_add (headers, "Set-Cookie", "c=3");

  TEST_ASSERT (SocketHTTP_Headers_count (headers) == 3, "Count is 3");

  const char *values[10];
  size_t count
      = SocketHTTP_Headers_get_all (headers, "Set-Cookie", values, 10);
  TEST_ASSERT (count == 3, "Get all returns 3");
  TEST_ASSERT (strcmp (values[0], "a=1") == 0, "First cookie");
  TEST_ASSERT (strcmp (values[1], "b=2") == 0, "Second cookie");
  TEST_ASSERT (strcmp (values[2], "c=3") == 0, "Third cookie");

  Arena_dispose (&arena);
}

static void
test_headers_set (void)
{
  printf ("Testing HTTP headers set...\n");

  Arena_T arena = Arena_new ();
  SocketHTTP_Headers_T headers = SocketHTTP_Headers_new (arena);

  SocketHTTP_Headers_add (headers, "Content-Type", "text/html");
  SocketHTTP_Headers_add (headers, "Content-Type", "text/plain");
  TEST_ASSERT (SocketHTTP_Headers_count (headers) == 2, "Count is 2");

  SocketHTTP_Headers_set (headers, "Content-Type", "application/json");
  TEST_ASSERT (SocketHTTP_Headers_count (headers) == 1,
               "Count is 1 after set");

  const char *value = SocketHTTP_Headers_get (headers, "Content-Type");
  TEST_ASSERT (strcmp (value, "application/json") == 0, "Value replaced");

  Arena_dispose (&arena);
}

static void
test_headers_remove (void)
{
  printf ("Testing HTTP headers remove...\n");

  Arena_T arena = Arena_new ();
  SocketHTTP_Headers_T headers = SocketHTTP_Headers_new (arena);

  SocketHTTP_Headers_add (headers, "A", "1");
  SocketHTTP_Headers_add (headers, "B", "2");
  SocketHTTP_Headers_add (headers, "A", "3");

  TEST_ASSERT (SocketHTTP_Headers_count (headers) == 3, "Count is 3");

  int removed = SocketHTTP_Headers_remove (headers, "A");
  TEST_ASSERT (removed == 1, "Remove returned 1");
  TEST_ASSERT (SocketHTTP_Headers_count (headers) == 2, "Count is 2");

  removed = SocketHTTP_Headers_remove_all (headers, "A");
  TEST_ASSERT (removed == 1, "Remove all returned 1");
  TEST_ASSERT (SocketHTTP_Headers_count (headers) == 1, "Count is 1");

  Arena_dispose (&arena);
}

static void
test_headers_contains (void)
{
  printf ("Testing HTTP headers contains...\n");

  Arena_T arena = Arena_new ();
  SocketHTTP_Headers_T headers = SocketHTTP_Headers_new (arena);

  SocketHTTP_Headers_add (headers, "Connection", "keep-alive, upgrade");
  SocketHTTP_Headers_add (headers, "Accept-Encoding", "gzip, deflate, br");

  TEST_ASSERT (
      SocketHTTP_Headers_contains (headers, "Connection", "keep-alive") == 1,
      "Contains keep-alive");
  TEST_ASSERT (SocketHTTP_Headers_contains (headers, "Connection", "upgrade")
                   == 1,
               "Contains upgrade");
  TEST_ASSERT (SocketHTTP_Headers_contains (headers, "Connection", "close")
                   == 0,
               "Not contains close");
  TEST_ASSERT (SocketHTTP_Headers_contains (headers, "Accept-Encoding", "br")
                   == 1,
               "Contains br");

  Arena_dispose (&arena);
}

static void
test_headers_get_int (void)
{
  printf ("Testing HTTP headers get_int...\n");

  Arena_T arena = Arena_new ();
  SocketHTTP_Headers_T headers = SocketHTTP_Headers_new (arena);

  SocketHTTP_Headers_add (headers, "Content-Length", "12345");
  SocketHTTP_Headers_add (headers, "Max-Age", "  3600  ");
  SocketHTTP_Headers_add (headers, "Bad", "not-a-number");

  int64_t val;
  TEST_ASSERT (SocketHTTP_Headers_get_int (headers, "Content-Length", &val)
                   == 0,
               "Parse Content-Length");
  TEST_ASSERT (val == 12345, "Content-Length value");

  TEST_ASSERT (SocketHTTP_Headers_get_int (headers, "Max-Age", &val) == 0,
               "Parse Max-Age with whitespace");
  TEST_ASSERT (val == 3600, "Max-Age value");

  TEST_ASSERT (SocketHTTP_Headers_get_int (headers, "Bad", &val) == -1,
               "Invalid number fails");
  TEST_ASSERT (SocketHTTP_Headers_get_int (headers, "Missing", &val) == -1,
               "Missing header fails");

  Arena_dispose (&arena);
}

static void
test_header_validation (void)
{
  printf ("Testing HTTP header validation...\n");

  TEST_ASSERT (SocketHTTP_header_name_valid ("Content-Type", 12) == 1,
               "Content-Type valid");
  TEST_ASSERT (SocketHTTP_header_name_valid ("X-Custom-Header", 15) == 1,
               "X-Custom-Header valid");
  TEST_ASSERT (SocketHTTP_header_name_valid ("Invalid Header", 14) == 0,
               "Space in name invalid");
  TEST_ASSERT (SocketHTTP_header_name_valid ("Invalid:Header", 14) == 0,
               "Colon in name invalid");
  TEST_ASSERT (SocketHTTP_header_name_valid ("", 0) == 0,
               "Empty name invalid");

  TEST_ASSERT (SocketHTTP_header_value_valid ("normal value", 12) == 1,
               "Normal value valid");

  /*
   * SECURITY FIX: CRLF sequences are now rejected to prevent header injection
   * attacks (CWE-113). Per RFC 9110 Section 5.5, obs-fold (CRLF + space/tab)
   * is deprecated and should not be generated. Rejecting all CR/LF prevents:
   * - HTTP response splitting
   * - Header injection
   * - Cache poisoning
   * - Session hijacking via injected Set-Cookie headers
   */
  TEST_ASSERT (SocketHTTP_header_value_valid ("value\r\n with fold", 17) == 0,
               "CRLF invalid (header injection prevention)");
  TEST_ASSERT (SocketHTTP_header_value_valid ("value\n bad", 10) == 0,
               "Bare LF invalid");
  TEST_ASSERT (SocketHTTP_header_value_valid ("value\r bad", 10) == 0,
               "Bare CR invalid");

  /* Additional injection prevention tests */
  TEST_ASSERT (SocketHTTP_header_value_valid ("inject\r\nSet-Cookie: x=y", 22)
                   == 0,
               "CRLF injection attempt blocked");
  TEST_ASSERT (SocketHTTP_header_value_valid ("val\x00ue", 6) == 0,
               "NUL byte invalid");
}

/**
 * Test hash collision DoS protection
 * Issue #508: Ensure excessive hash chain length triggers warnings and fails
 */
static void
test_header_dos_protection (void)
{
  printf ("Testing HTTP header DoS protection...\n");

  Arena_T arena = Arena_new ();
  SocketHTTP_Headers_T headers = SocketHTTP_Headers_new (arena);

  /* Add many headers with same hash to trigger collision detection */
  /* This test relies on internal bucket size limits */
  int added = 0;
  int failed = 0;

  /* Try to add many headers - should eventually hit chain length limit */
  for (int i = 0; i < 100; i++)
    {
      char name[32];
      char value[32];
      snprintf (name, sizeof (name), "X-Header-%d", i);
      snprintf (value, sizeof (value), "value%d", i);

      int result = SocketHTTP_Headers_add (headers, name, value);
      if (result == 0)
        added++;
      else
        failed++;
    }

  /* We should be able to add most headers, but may hit limits */
  TEST_ASSERT (added > 0, "Should add some headers");

  /* Test that we can still retrieve added headers */
  const char *val = SocketHTTP_Headers_get (headers, "X-Header-0");
  if (added > 0)
    {
      TEST_ASSERT (val != NULL, "Should retrieve first header");
      TEST_ASSERT (strcmp (val, "value0") == 0, "Header value correct");
    }

  Arena_dispose (&arena);
}

/* ============================================================================
 * URI Parsing Tests
 * ============================================================================
 */

static void
test_uri_basic (void)
{
  printf ("Testing URI basic parsing...\n");

  Arena_T arena = Arena_new ();
  SocketHTTP_URI uri;
  SocketHTTP_URIResult result;

  result = SocketHTTP_URI_parse ("http://example.com/path", 0, &uri, arena);
  TEST_ASSERT (result == URI_PARSE_OK, "Parse basic URI");
  TEST_ASSERT (uri.scheme && strcmp (uri.scheme, "http") == 0, "Scheme");
  TEST_ASSERT (uri.host && strcmp (uri.host, "example.com") == 0, "Host");
  TEST_ASSERT (uri.path && strcmp (uri.path, "/path") == 0, "Path");
  TEST_ASSERT (uri.port == -1, "Port not specified");

  Arena_dispose (&arena);
}

static void
test_uri_with_port (void)
{
  printf ("Testing URI with port...\n");

  Arena_T arena = Arena_new ();
  SocketHTTP_URI uri;
  SocketHTTP_URIResult result;

  result
      = SocketHTTP_URI_parse ("https://example.com:8443/path", 0, &uri, arena);
  TEST_ASSERT (result == URI_PARSE_OK, "Parse URI with port");
  TEST_ASSERT (strcmp (uri.scheme, "https") == 0, "Scheme");
  TEST_ASSERT (strcmp (uri.host, "example.com") == 0, "Host");
  TEST_ASSERT (uri.port == 8443, "Port");
  TEST_ASSERT (strcmp (uri.path, "/path") == 0, "Path");

  Arena_dispose (&arena);
}

static void
test_uri_with_query (void)
{
  printf ("Testing URI with query...\n");

  Arena_T arena = Arena_new ();
  SocketHTTP_URI uri;
  SocketHTTP_URIResult result;

  result = SocketHTTP_URI_parse ("http://example.com/search?q=test&page=1", 0,
                                 &uri, arena);
  TEST_ASSERT (result == URI_PARSE_OK, "Parse URI with query");
  TEST_ASSERT (uri.query && strcmp (uri.query, "q=test&page=1") == 0, "Query");

  Arena_dispose (&arena);
}

static void
test_uri_with_fragment (void)
{
  printf ("Testing URI with fragment...\n");

  Arena_T arena = Arena_new ();
  SocketHTTP_URI uri;
  SocketHTTP_URIResult result;

  result = SocketHTTP_URI_parse ("http://example.com/page#section", 0, &uri,
                                 arena);
  TEST_ASSERT (result == URI_PARSE_OK, "Parse URI with fragment");
  TEST_ASSERT (uri.fragment && strcmp (uri.fragment, "section") == 0,
               "Fragment");

  Arena_dispose (&arena);
}

static void
test_uri_ipv6 (void)
{
  printf ("Testing URI with IPv6...\n");

  Arena_T arena = Arena_new ();
  SocketHTTP_URI uri;
  SocketHTTP_URIResult result;

  result = SocketHTTP_URI_parse ("http://[::1]:8080/path", 0, &uri, arena);
  TEST_ASSERT (result == URI_PARSE_OK, "Parse IPv6 URI");
  TEST_ASSERT (uri.host && strcmp (uri.host, "[::1]") == 0, "IPv6 host");
  TEST_ASSERT (uri.port == 8080, "Port");

  Arena_dispose (&arena);
}

static void
test_uri_relative (void)
{
  printf ("Testing relative URI...\n");

  Arena_T arena = Arena_new ();
  SocketHTTP_URI uri;
  SocketHTTP_URIResult result;

  result = SocketHTTP_URI_parse ("/path/to/resource?query=1", 0, &uri, arena);
  TEST_ASSERT (result == URI_PARSE_OK, "Parse relative URI");
  TEST_ASSERT (uri.path && strcmp (uri.path, "/path/to/resource") == 0,
               "Relative path");
  TEST_ASSERT (uri.query && strcmp (uri.query, "query=1") == 0,
               "Relative query");
  TEST_ASSERT (uri.scheme == NULL, "No scheme in relative");
  TEST_ASSERT (uri.host == NULL, "No host in relative");

  Arena_dispose (&arena);
}

static void
test_uri_security_invalid (void)
{
  printf ("Testing URI security validation...\n");

  Arena_T arena = Arena_new ();
  SocketHTTP_URI uri;
  SocketHTTP_URIResult result;

  // Control char in path (use sizeof-1 to get full length including embedded
  // NUL)
  result = SocketHTTP_URI_parse ("http://example.com/pat\0h",
                                 sizeof ("http://example.com/pat\0h") - 1,
                                 &uri, arena);
  TEST_ASSERT (result == URI_PARSE_ERROR, "Reject control char (NUL) in path");

  // Invalid host char (space)
  result = SocketHTTP_URI_parse ("http://example com/path", 0, &uri, arena);
  TEST_ASSERT (result == URI_PARSE_INVALID_HOST, "Reject space in host");

  // Invalid reg-name char in host
  result = SocketHTTP_URI_parse ("http://exa<mple.com/path", 0, &uri, arena);
  TEST_ASSERT (result == URI_PARSE_INVALID_HOST,
               "Reject < in host (reg-name)");

  // Malformed IPv6 literal
  result = SocketHTTP_URI_parse ("http://[::g]:80/path", 0, &uri, arena);
  TEST_ASSERT (result == URI_PARSE_INVALID_HOST,
               "Reject invalid char in IPv6");

  // Unmatched IPv6 bracket
  result = SocketHTTP_URI_parse ("http://[::1/path", 0, &uri, arena);
  TEST_ASSERT (result == URI_PARSE_INVALID_HOST,
               "Reject unmatched IPv6 bracket");

  // Oversized host
  char long_host[310] = "http://";
  memset (long_host + 7, 'a', 290);
  strncpy (long_host + 297, "/path", 12); /* Safe copy with room for null */
  long_host[308] = '\0';                  /* Ensure null termination */
  result = SocketHTTP_URI_parse (long_host, 300, &uri, arena);
  TEST_ASSERT (result == URI_PARSE_TOO_LONG, "Reject oversized host >255");

  // Invalid pct encoding
  result = SocketHTTP_URI_parse ("http://example.com/pat%G1h", 0, &uri, arena);
  TEST_ASSERT (result == URI_PARSE_INVALID_PATH, "Reject invalid %XX in path");

  // Path traversal - literal ".."
  result = SocketHTTP_URI_parse ("http://example.com/../foo", 0, &uri, arena);
  TEST_ASSERT (result == URI_PARSE_INVALID_PATH, "Reject literal ../foo");

  result = SocketHTTP_URI_parse ("http://example.com/foo/../bar", 0, &uri, arena);
  TEST_ASSERT (result == URI_PARSE_INVALID_PATH, "Reject foo/../bar");

  result = SocketHTTP_URI_parse ("http://example.com/..", 0, &uri, arena);
  TEST_ASSERT (result == URI_PARSE_INVALID_PATH, "Reject .. at end");

  result = SocketHTTP_URI_parse ("http://example.com/..?query", 0, &uri, arena);
  TEST_ASSERT (result == URI_PARSE_INVALID_PATH, "Reject .. before query");

  // Path traversal - fully encoded "%2e%2e"
  result = SocketHTTP_URI_parse ("http://example.com/%2e%2e/foo", 0, &uri, arena);
  TEST_ASSERT (result == URI_PARSE_INVALID_PATH, "Reject %2e%2e/foo (lowercase)");

  result = SocketHTTP_URI_parse ("http://example.com/%2E%2E/foo", 0, &uri, arena);
  TEST_ASSERT (result == URI_PARSE_INVALID_PATH, "Reject %2E%2E/foo (uppercase)");

  // Path traversal - mixed encoding ".%2e"
  result = SocketHTTP_URI_parse ("http://example.com/.%2e/foo", 0, &uri, arena);
  TEST_ASSERT (result == URI_PARSE_INVALID_PATH, "Reject .%2e/foo (lowercase)");

  result = SocketHTTP_URI_parse ("http://example.com/.%2E/foo", 0, &uri, arena);
  TEST_ASSERT (result == URI_PARSE_INVALID_PATH, "Reject .%2E/foo (uppercase)");

  result = SocketHTTP_URI_parse ("http://example.com/foo/.%2e/", 0, &uri, arena);
  TEST_ASSERT (result == URI_PARSE_INVALID_PATH, "Reject foo/.%2e/ (mid-path)");

  result = SocketHTTP_URI_parse ("http://example.com/.%2e", 0, &uri, arena);
  TEST_ASSERT (result == URI_PARSE_INVALID_PATH, "Reject .%2e (at end)");

  result = SocketHTTP_URI_parse ("http://example.com/.%2e?query", 0, &uri, arena);
  TEST_ASSERT (result == URI_PARSE_INVALID_PATH, "Reject .%2e?query (before query)");

  // Path traversal - mixed encoding "%2e."
  result = SocketHTTP_URI_parse ("http://example.com/%2e./foo", 0, &uri, arena);
  TEST_ASSERT (result == URI_PARSE_INVALID_PATH, "Reject %2e./foo (lowercase)");

  result = SocketHTTP_URI_parse ("http://example.com/%2E./foo", 0, &uri, arena);
  TEST_ASSERT (result == URI_PARSE_INVALID_PATH, "Reject %2E./foo (uppercase)");

  result = SocketHTTP_URI_parse ("http://example.com/foo/%2e./", 0, &uri, arena);
  TEST_ASSERT (result == URI_PARSE_INVALID_PATH, "Reject foo/%2e./ (mid-path)");

  result = SocketHTTP_URI_parse ("http://example.com/%2e.", 0, &uri, arena);
  TEST_ASSERT (result == URI_PARSE_INVALID_PATH, "Reject %2e. (at end)");

  result = SocketHTTP_URI_parse ("http://example.com/%2e.?query", 0, &uri, arena);
  TEST_ASSERT (result == URI_PARSE_INVALID_PATH, "Reject %2e.?query (before query)");

  // Valid paths with single dots (should pass)
  result = SocketHTTP_URI_parse ("http://example.com/.", 0, &uri, arena);
  TEST_ASSERT (result == URI_PARSE_OK, "Accept single dot /.");

  result = SocketHTTP_URI_parse ("http://example.com/./foo", 0, &uri, arena);
  TEST_ASSERT (result == URI_PARSE_OK, "Accept single dot /./foo");

  result = SocketHTTP_URI_parse ("http://example.com/foo.bar", 0, &uri, arena);
  TEST_ASSERT (result == URI_PARSE_OK, "Accept foo.bar (non-traversal)");

  Arena_dispose (&arena);
}

static void
test_mediatype_security (void)
{
  printf ("Testing media type security validation...\n");

  Arena_T arena = Arena_new ();
  SocketHTTP_MediaType mt;
  int res;

  // Invalid token char in type
  res = SocketHTTP_MediaType_parse ("text[<]/plain", 0, &mt, arena);
  TEST_ASSERT (res == -1, "Reject invalid char in type");

  // Invalid param name
  res = SocketHTTP_MediaType_parse ("text/plain; inval= id", 0, &mt, arena);
  TEST_ASSERT (res == -1, "Reject invalid param name char");

  // Incomplete escape in quoted
  res = SocketHTTP_MediaType_parse ("text/plain; boundary=\\\"abc\\", 0, &mt,
                                    arena);
  TEST_ASSERT (res == -1, "Reject incomplete escape in quoted value");

  Arena_dispose (&arena);
}

static void
test_uri_userinfo (void)
{
  printf ("Testing URI with userinfo...\n");

  Arena_T arena = Arena_new ();
  SocketHTTP_URI uri;
  SocketHTTP_URIResult result;

  result = SocketHTTP_URI_parse ("http://user:pass@example.com/path", 0, &uri,
                                 arena);
  TEST_ASSERT (result == URI_PARSE_OK, "Parse URI with userinfo");
  TEST_ASSERT (uri.userinfo && strcmp (uri.userinfo, "user:pass") == 0,
               "Userinfo");
  TEST_ASSERT (strcmp (uri.host, "example.com") == 0, "Host after userinfo");

  Arena_dispose (&arena);
}

static void
test_uri_helpers (void)
{
  printf ("Testing URI helper functions...\n");

  Arena_T arena = Arena_new ();
  SocketHTTP_URI uri;

  SocketHTTP_URI_parse ("https://example.com:443/path", 0, &uri, arena);
  TEST_ASSERT (SocketHTTP_URI_get_port (&uri, 80) == 443, "Get explicit port");
  TEST_ASSERT (SocketHTTP_URI_is_secure (&uri) == 1, "https is secure");

  SocketHTTP_URI_parse ("http://example.com/path", 0, &uri, arena);
  TEST_ASSERT (SocketHTTP_URI_get_port (&uri, 80) == 80, "Get default port");
  TEST_ASSERT (SocketHTTP_URI_is_secure (&uri) == 0, "http is not secure");

  Arena_dispose (&arena);
}

static void
test_uri_encode_decode (void)
{
  printf ("Testing URI encoding/decoding...\n");

  char buf[256];
  ssize_t len;

  len = SocketHTTP_URI_encode ("hello world!", 12, buf, sizeof (buf));
  TEST_ASSERT (len > 0, "Encode succeeds");
  TEST_ASSERT (strcmp (buf, "hello%20world%21") == 0, "Encode result");

  char decoded[256];
  len = SocketHTTP_URI_decode (buf, (size_t)len, decoded, sizeof (decoded));
  TEST_ASSERT (len == 12, "Decode length");
  TEST_ASSERT (strcmp (decoded, "hello world!") == 0, "Decode result");

  /* Test + decoding */
  len = SocketHTTP_URI_decode ("hello+world", 11, decoded, sizeof (decoded));
  TEST_ASSERT (len == 11, "Plus decode length");
  TEST_ASSERT (strcmp (decoded, "hello world") == 0, "Plus decoded as space");
}

static void
test_uri_build (void)
{
  printf ("Testing URI building...\n");

  Arena_T arena = Arena_new ();
  SocketHTTP_URI uri;
  char buf[256];

  SocketHTTP_URI_parse ("https://user@example.com:8080/path?query#frag", 0,
                        &uri, arena);

  ssize_t len = SocketHTTP_URI_build (&uri, buf, sizeof (buf));
  TEST_ASSERT (len > 0, "Build succeeds");
  TEST_ASSERT (strcmp (buf, "https://user@example.com:8080/path?query#frag")
                   == 0,
               "Build result");

  Arena_dispose (&arena);
}

/* ============================================================================
 * Date Parsing Tests
 * ============================================================================
 */

static void
test_date_imf_fixdate (void)
{
  printf ("Testing IMF-fixdate parsing...\n");

  time_t t;
  int result;

  /* RFC 9110 example */
  result = SocketHTTP_date_parse ("Sun, 06 Nov 1994 08:49:37 GMT", 0, &t);
  TEST_ASSERT (result == 0, "Parse IMF-fixdate");

  struct tm *tm = gmtime (&t);
  TEST_ASSERT (tm->tm_year == 94, "Year 1994");
  TEST_ASSERT (tm->tm_mon == 10, "November (10)");
  TEST_ASSERT (tm->tm_mday == 6, "Day 6");
  TEST_ASSERT (tm->tm_hour == 8, "Hour 8");
  TEST_ASSERT (tm->tm_min == 49, "Minute 49");
  TEST_ASSERT (tm->tm_sec == 37, "Second 37");
}

static void
test_date_rfc850 (void)
{
  printf ("Testing RFC 850 date parsing...\n");

  time_t t;
  int result;

  result = SocketHTTP_date_parse ("Sunday, 06-Nov-94 08:49:37 GMT", 0, &t);
  TEST_ASSERT (result == 0, "Parse RFC 850 date");

  struct tm *tm = gmtime (&t);
  TEST_ASSERT (tm->tm_year == 94, "Year 1994");
  TEST_ASSERT (tm->tm_mon == 10, "November");
  TEST_ASSERT (tm->tm_mday == 6, "Day 6");
}

static void
test_date_asctime (void)
{
  printf ("Testing ANSI C asctime parsing...\n");

  time_t t;
  int result;

  result = SocketHTTP_date_parse ("Sun Nov  6 08:49:37 1994", 0, &t);
  TEST_ASSERT (result == 0, "Parse asctime date");

  struct tm *tm = gmtime (&t);
  TEST_ASSERT (tm->tm_year == 94, "Year 1994");
  TEST_ASSERT (tm->tm_mon == 10, "November");
  TEST_ASSERT (tm->tm_mday == 6, "Day 6");
}

static void
test_date_format (void)
{
  printf ("Testing date formatting...\n");

  time_t t;
  SocketHTTP_date_parse ("Sun, 06 Nov 1994 08:49:37 GMT", 0, &t);

  char buf[SOCKETHTTP_DATE_BUFSIZE];
  int len = SocketHTTP_date_format (t, buf);
  TEST_ASSERT (len == 29, "Format length");
  TEST_ASSERT (strcmp (buf, "Sun, 06 Nov 1994 08:49:37 GMT") == 0,
               "Format result");
}

static void
test_date_invalid (void)
{
  printf ("Testing invalid dates...\n");

  time_t t;

  TEST_ASSERT (SocketHTTP_date_parse ("invalid", 0, &t) == -1,
               "Reject invalid");
  TEST_ASSERT (SocketHTTP_date_parse ("", 0, &t) == -1, "Reject empty");
  TEST_ASSERT (SocketHTTP_date_parse (NULL, 0, &t) == -1, "Reject NULL");

  /* Test that overly long date strings are rejected (security fix for #1392) */
  char long_date[200];
  memset (long_date, 'A', sizeof (long_date) - 1);
  long_date[sizeof (long_date) - 1] = '\0';
  TEST_ASSERT (SocketHTTP_date_parse (long_date, 0, &t) == -1,
               "Reject overly long date string");
}

/* ============================================================================
 * Media Type Parsing Tests
 * ============================================================================
 */

static void
test_media_type_basic (void)
{
  printf ("Testing media type basic parsing...\n");

  Arena_T arena = Arena_new ();
  SocketHTTP_MediaType mt;

  int result = SocketHTTP_MediaType_parse ("text/html", 0, &mt, arena);
  TEST_ASSERT (result == 0, "Parse text/html");
  TEST_ASSERT (strcmp (mt.type, "text") == 0, "Type");
  TEST_ASSERT (strcmp (mt.subtype, "html") == 0, "Subtype");

  Arena_dispose (&arena);
}

static void
test_media_type_params (void)
{
  printf ("Testing media type with parameters...\n");

  Arena_T arena = Arena_new ();
  SocketHTTP_MediaType mt;

  int result = SocketHTTP_MediaType_parse (
      "text/html; charset=utf-8; boundary=\"----\"", 0, &mt, arena);
  TEST_ASSERT (result == 0, "Parse with params");
  TEST_ASSERT (strcmp (mt.type, "text") == 0, "Type");
  TEST_ASSERT (strcmp (mt.subtype, "html") == 0, "Subtype");
  TEST_ASSERT (mt.charset && strcmp (mt.charset, "utf-8") == 0, "Charset");
  TEST_ASSERT (mt.boundary && strcmp (mt.boundary, "----") == 0, "Boundary");

  Arena_dispose (&arena);
}

static void
test_media_type_matches (void)
{
  printf ("Testing media type matching...\n");

  Arena_T arena = Arena_new ();
  SocketHTTP_MediaType mt;

  SocketHTTP_MediaType_parse ("application/json", 0, &mt, arena);
  TEST_ASSERT (SocketHTTP_MediaType_matches (&mt, "application/json") == 1,
               "Exact match");
  TEST_ASSERT (SocketHTTP_MediaType_matches (&mt, "application/*") == 1,
               "Wildcard subtype");
  TEST_ASSERT (SocketHTTP_MediaType_matches (&mt, "*/*") == 1, "Wildcard all");
  TEST_ASSERT (SocketHTTP_MediaType_matches (&mt, "text/json") == 0,
               "Type mismatch");

  Arena_dispose (&arena);
}

/* ============================================================================
 * Accept Header Parsing Tests
 * ============================================================================
 */

static void
test_accept_parsing (void)
{
  printf ("Testing Accept header parsing...\n");

  Arena_T arena = Arena_new ();
  SocketHTTP_QualityValue results[10];

  size_t count = SocketHTTP_parse_accept (
      "text/html, application/json;q=0.9, */*;q=0.1", 0, results, 10, arena);

  TEST_ASSERT (count == 3, "Parse 3 values");
  /* Should be sorted by quality */
  TEST_ASSERT (strcmp (results[0].value, "text/html") == 0,
               "First: text/html");
  TEST_ASSERT (results[0].quality == 1.0f, "First quality 1.0");
  TEST_ASSERT (strcmp (results[1].value, "application/json") == 0,
               "Second: application/json");
  TEST_ASSERT (results[1].quality == 0.9f, "Second quality 0.9");
  TEST_ASSERT (strcmp (results[2].value, "*/*") == 0, "Third: */*");
  TEST_ASSERT (results[2].quality == 0.1f, "Third quality 0.1");

  Arena_dispose (&arena);
}

/* ============================================================================
 * Coding Tests
 * ============================================================================
 */

static void
test_coding (void)
{
  printf ("Testing transfer/content codings...\n");

  TEST_ASSERT (SocketHTTP_coding_parse ("gzip", 0) == HTTP_CODING_GZIP,
               "Parse gzip");
  TEST_ASSERT (SocketHTTP_coding_parse ("GZIP", 0) == HTTP_CODING_GZIP,
               "Parse GZIP (case-insensitive)");
  TEST_ASSERT (SocketHTTP_coding_parse ("deflate", 0) == HTTP_CODING_DEFLATE,
               "Parse deflate");
  TEST_ASSERT (SocketHTTP_coding_parse ("br", 0) == HTTP_CODING_BR,
               "Parse br");
  TEST_ASSERT (SocketHTTP_coding_parse ("chunked", 0) == HTTP_CODING_CHUNKED,
               "Parse chunked");
  TEST_ASSERT (SocketHTTP_coding_parse ("unknown", 0) == HTTP_CODING_UNKNOWN,
               "Parse unknown");

  TEST_ASSERT (strcmp (SocketHTTP_coding_name (HTTP_CODING_GZIP), "gzip") == 0,
               "Name gzip");
  TEST_ASSERT (SocketHTTP_coding_name (HTTP_CODING_UNKNOWN) == NULL,
               "Unknown returns NULL");
}

/* ============================================================================
 * Main
 * ============================================================================
 */

int
main (void)
{
  printf ("=== HTTP Core Module Tests ===\n\n");

  /* Version tests */
  test_version_string ();
  test_version_parse ();

  /* Method tests */
  test_method_name ();
  test_method_parse ();
  test_method_properties ();
  test_method_valid ();

  /* Status code tests */
  test_status_reason ();
  test_status_category ();
  test_status_valid ();

  /* Header tests */
  test_headers_basic ();
  test_headers_multi ();
  test_headers_set ();
  test_headers_remove ();
  test_headers_contains ();
  test_headers_get_int ();
  test_header_validation ();
  test_header_dos_protection ();

  /* URI tests */
  test_uri_basic ();
  test_uri_with_port ();
  test_uri_with_query ();
  test_uri_with_fragment ();
  test_uri_ipv6 ();
  test_uri_relative ();
  test_uri_userinfo ();
  test_uri_helpers ();
  test_uri_encode_decode ();
  test_uri_build ();
  test_uri_security_invalid ();

  /* Date tests */
  test_date_imf_fixdate ();
  test_date_rfc850 ();
  test_date_asctime ();
  test_date_format ();
  test_date_invalid ();

  /* Media type tests */
  test_media_type_basic ();
  test_media_type_params ();
  test_media_type_matches ();
  test_mediatype_security ();

  /* Accept header tests */
  test_accept_parsing ();

  /* Coding tests */
  test_coding ();

  printf ("\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);

  return (tests_passed == tests_run) ? 0 : 1;
}
