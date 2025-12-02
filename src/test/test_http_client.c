/**
 * test_http_client.c - HTTP Client Test Suite
 *
 * Tests for the HTTP Client module covering:
 * - Client lifecycle (new/free)
 * - Configuration
 * - Request building
 * - Cookie jar
 * - Authentication
 * - Connection pool
 */

#include "http/SocketHTTPClient.h"
#include "http/SocketHTTP.h"
#include "core/Arena.h"
#include "core/Except.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

/* ============================================================================
 * Test Framework
 * ============================================================================ */

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_START(name)                                                       \
  do                                                                           \
    {                                                                          \
      printf ("  Testing: %s... ", name);                                      \
      fflush (stdout);                                                         \
      tests_run++;                                                             \
    }                                                                          \
  while (0)

#define TEST_PASS()                                                            \
  do                                                                           \
    {                                                                          \
      printf ("PASS\n");                                                       \
      tests_passed++;                                                          \
    }                                                                          \
  while (0)

#define TEST_FAIL(msg)                                                         \
  do                                                                           \
    {                                                                          \
      printf ("FAIL: %s\n", msg);                                              \
      tests_failed++;                                                          \
    }                                                                          \
  while (0)

#define ASSERT_TRUE(cond, msg)                                                 \
  do                                                                           \
    {                                                                          \
      if (!(cond))                                                             \
        {                                                                      \
          TEST_FAIL (msg);                                                     \
          return;                                                              \
        }                                                                      \
    }                                                                          \
  while (0)

#define ASSERT_EQ(a, b, msg) ASSERT_TRUE ((a) == (b), msg)
#define ASSERT_NE(a, b, msg) ASSERT_TRUE ((a) != (b), msg)
#define ASSERT_NULL(p, msg) ASSERT_TRUE ((p) == NULL, msg)
#define ASSERT_NOT_NULL(p, msg) ASSERT_TRUE ((p) != NULL, msg)
#define ASSERT_STR_EQ(a, b, msg) ASSERT_TRUE (strcmp ((a), (b)) == 0, msg)

/* ============================================================================
 * Configuration Tests
 * ============================================================================ */

static void
test_config_defaults (void)
{
  SocketHTTPClient_Config config;

  TEST_START ("config defaults");

  SocketHTTPClient_config_defaults (&config);

  ASSERT_EQ (config.max_version, HTTP_VERSION_2, "max_version should be HTTP/2");
  ASSERT_EQ (config.allow_http2_cleartext, 0, "h2c should be disabled by default");
  ASSERT_EQ (config.enable_connection_pool, 1, "pooling should be enabled");
  ASSERT_EQ (config.max_connections_per_host, HTTPCLIENT_DEFAULT_MAX_CONNS_PER_HOST,
             "max_connections_per_host");
  ASSERT_EQ (config.connect_timeout_ms, HTTPCLIENT_DEFAULT_CONNECT_TIMEOUT_MS,
             "connect_timeout_ms");
  ASSERT_EQ (config.follow_redirects, HTTPCLIENT_DEFAULT_MAX_REDIRECTS,
             "follow_redirects");
  ASSERT_EQ (config.auto_decompress, 1, "auto_decompress should be enabled");
  ASSERT_EQ (config.verify_ssl, 1, "verify_ssl should be enabled");
  ASSERT_NOT_NULL (config.user_agent, "user_agent should be set");

  TEST_PASS ();
}

/* ============================================================================
 * Client Lifecycle Tests
 * ============================================================================ */

static void
test_client_new_free (void)
{
  SocketHTTPClient_T client;

  TEST_START ("client new/free");

  client = SocketHTTPClient_new (NULL);
  ASSERT_NOT_NULL (client, "client should not be NULL");

  SocketHTTPClient_free (&client);
  ASSERT_NULL (client, "client should be NULL after free");

  TEST_PASS ();
}

static void
test_client_with_config (void)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_Config config;

  TEST_START ("client with custom config");

  SocketHTTPClient_config_defaults (&config);
  config.max_connections_per_host = 10;
  config.connect_timeout_ms = 5000;
  config.follow_redirects = 5;

  client = SocketHTTPClient_new (&config);
  ASSERT_NOT_NULL (client, "client should not be NULL");

  SocketHTTPClient_free (&client);
  TEST_PASS ();
}

/* ============================================================================
 * Request Builder Tests
 * ============================================================================ */

static void
test_request_new_free (void)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_Request_T req;

  TEST_START ("request new/free");

  client = SocketHTTPClient_new (NULL);
  ASSERT_NOT_NULL (client, "client should not be NULL");

  req = SocketHTTPClient_Request_new (client, HTTP_METHOD_GET,
                                      "http://example.com/path?query=value");
  ASSERT_NOT_NULL (req, "request should not be NULL");

  SocketHTTPClient_Request_free (&req);
  ASSERT_NULL (req, "request should be NULL after free");

  SocketHTTPClient_free (&client);
  TEST_PASS ();
}

static void
test_request_headers (void)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_Request_T req;
  int result;

  TEST_START ("request headers");

  client = SocketHTTPClient_new (NULL);
  req = SocketHTTPClient_Request_new (client, HTTP_METHOD_GET,
                                      "http://example.com/");

  result = SocketHTTPClient_Request_header (req, "X-Custom-Header", "test-value");
  ASSERT_EQ (result, 0, "header add should succeed");

  result = SocketHTTPClient_Request_header (req, "Accept", "application/json");
  ASSERT_EQ (result, 0, "header add should succeed");

  SocketHTTPClient_Request_free (&req);
  SocketHTTPClient_free (&client);
  TEST_PASS ();
}

static void
test_request_body (void)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_Request_T req;
  int result;
  const char *body = "{\"key\": \"value\"}";

  TEST_START ("request body");

  client = SocketHTTPClient_new (NULL);
  req = SocketHTTPClient_Request_new (client, HTTP_METHOD_POST,
                                      "http://example.com/api");

  result = SocketHTTPClient_Request_header (req, "Content-Type",
                                            "application/json");
  ASSERT_EQ (result, 0, "content-type header");

  result = SocketHTTPClient_Request_body (req, body, strlen (body));
  ASSERT_EQ (result, 0, "body set should succeed");

  SocketHTTPClient_Request_free (&req);
  SocketHTTPClient_free (&client);
  TEST_PASS ();
}

static void
test_request_timeout (void)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_Request_T req;

  TEST_START ("request timeout");

  client = SocketHTTPClient_new (NULL);
  req = SocketHTTPClient_Request_new (client, HTTP_METHOD_GET,
                                      "http://example.com/");

  SocketHTTPClient_Request_timeout (req, 5000);

  SocketHTTPClient_Request_free (&req);
  SocketHTTPClient_free (&client);
  TEST_PASS ();
}

/* ============================================================================
 * Cookie Jar Tests
 * ============================================================================ */

static void
test_cookie_jar_new_free (void)
{
  SocketHTTPClient_CookieJar_T jar;

  TEST_START ("cookie jar new/free");

  jar = SocketHTTPClient_CookieJar_new ();
  ASSERT_NOT_NULL (jar, "jar should not be NULL");

  SocketHTTPClient_CookieJar_free (&jar);
  ASSERT_NULL (jar, "jar should be NULL after free");

  TEST_PASS ();
}

static void
test_cookie_jar_set_get (void)
{
  SocketHTTPClient_CookieJar_T jar;
  SocketHTTPClient_Cookie cookie;
  const SocketHTTPClient_Cookie *result;
  int ret;

  TEST_START ("cookie jar set/get");

  jar = SocketHTTPClient_CookieJar_new ();

  memset (&cookie, 0, sizeof (cookie));
  cookie.name = "session";
  cookie.value = "abc123";
  cookie.domain = "example.com";
  cookie.path = "/";
  cookie.secure = 1;
  cookie.http_only = 1;

  ret = SocketHTTPClient_CookieJar_set (jar, &cookie);
  ASSERT_EQ (ret, 0, "cookie set should succeed");

  result = SocketHTTPClient_CookieJar_get (jar, "example.com", "/", "session");
  ASSERT_NOT_NULL (result, "cookie get should find cookie");
  ASSERT_STR_EQ (result->value, "abc123", "cookie value should match");
  ASSERT_EQ (result->secure, 1, "secure flag should match");

  SocketHTTPClient_CookieJar_free (&jar);
  TEST_PASS ();
}

static void
test_cookie_jar_update (void)
{
  SocketHTTPClient_CookieJar_T jar;
  SocketHTTPClient_Cookie cookie;
  const SocketHTTPClient_Cookie *result;

  TEST_START ("cookie jar update");

  jar = SocketHTTPClient_CookieJar_new ();

  /* Set initial cookie */
  memset (&cookie, 0, sizeof (cookie));
  cookie.name = "token";
  cookie.value = "old_value";
  cookie.domain = "test.com";
  cookie.path = "/";

  SocketHTTPClient_CookieJar_set (jar, &cookie);

  /* Update same cookie */
  cookie.value = "new_value";
  SocketHTTPClient_CookieJar_set (jar, &cookie);

  result = SocketHTTPClient_CookieJar_get (jar, "test.com", "/", "token");
  ASSERT_NOT_NULL (result, "cookie should exist");
  ASSERT_STR_EQ (result->value, "new_value", "cookie should be updated");

  SocketHTTPClient_CookieJar_free (&jar);
  TEST_PASS ();
}

static void
test_cookie_jar_clear (void)
{
  SocketHTTPClient_CookieJar_T jar;
  SocketHTTPClient_Cookie cookie;
  const SocketHTTPClient_Cookie *result;

  TEST_START ("cookie jar clear");

  jar = SocketHTTPClient_CookieJar_new ();

  memset (&cookie, 0, sizeof (cookie));
  cookie.name = "test";
  cookie.value = "value";
  cookie.domain = "example.com";
  cookie.path = "/";

  SocketHTTPClient_CookieJar_set (jar, &cookie);

  SocketHTTPClient_CookieJar_clear (jar);

  result = SocketHTTPClient_CookieJar_get (jar, "example.com", "/", "test");
  ASSERT_NULL (result, "cookie should be cleared");

  SocketHTTPClient_CookieJar_free (&jar);
  TEST_PASS ();
}

static void
test_cookie_jar_association (void)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_CookieJar_T jar;
  SocketHTTPClient_CookieJar_T retrieved;

  TEST_START ("cookie jar association");

  client = SocketHTTPClient_new (NULL);
  jar = SocketHTTPClient_CookieJar_new ();

  /* Associate jar with client */
  SocketHTTPClient_set_cookie_jar (client, jar);

  retrieved = SocketHTTPClient_get_cookie_jar (client);
  ASSERT_EQ (retrieved, jar, "retrieved jar should match");

  /* Remove association */
  SocketHTTPClient_set_cookie_jar (client, NULL);
  retrieved = SocketHTTPClient_get_cookie_jar (client);
  ASSERT_NULL (retrieved, "jar should be NULL after removal");

  SocketHTTPClient_CookieJar_free (&jar);
  SocketHTTPClient_free (&client);
  TEST_PASS ();
}

/* ============================================================================
 * Authentication Tests
 * ============================================================================ */

static void
test_auth_basic (void)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_Auth auth;

  TEST_START ("basic authentication");

  client = SocketHTTPClient_new (NULL);

  memset (&auth, 0, sizeof (auth));
  auth.type = HTTP_AUTH_BASIC;
  auth.username = "user";
  auth.password = "pass";

  SocketHTTPClient_set_auth (client, &auth);

  SocketHTTPClient_free (&client);
  TEST_PASS ();
}

static void
test_auth_bearer (void)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_Auth auth;

  TEST_START ("bearer authentication");

  client = SocketHTTPClient_new (NULL);

  memset (&auth, 0, sizeof (auth));
  auth.type = HTTP_AUTH_BEARER;
  auth.token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";

  SocketHTTPClient_set_auth (client, &auth);

  SocketHTTPClient_free (&client);
  TEST_PASS ();
}

static void
test_auth_per_request (void)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_Request_T req;
  SocketHTTPClient_Auth auth;

  TEST_START ("per-request authentication");

  client = SocketHTTPClient_new (NULL);
  req = SocketHTTPClient_Request_new (client, HTTP_METHOD_GET,
                                      "http://example.com/secure");

  memset (&auth, 0, sizeof (auth));
  auth.type = HTTP_AUTH_BEARER;
  auth.token = "request_specific_token";

  SocketHTTPClient_Request_auth (req, &auth);

  SocketHTTPClient_Request_free (&req);
  SocketHTTPClient_free (&client);
  TEST_PASS ();
}

/* ============================================================================
 * Pool Statistics Tests
 * ============================================================================ */

static void
test_pool_stats (void)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_PoolStats stats;

  TEST_START ("pool statistics");

  client = SocketHTTPClient_new (NULL);

  SocketHTTPClient_pool_stats (client, &stats);

  ASSERT_EQ (stats.active_connections, 0, "should have no active connections");
  ASSERT_EQ (stats.idle_connections, 0, "should have no idle connections");

  SocketHTTPClient_free (&client);
  TEST_PASS ();
}

static void
test_pool_clear (void)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_PoolStats stats;

  TEST_START ("pool clear");

  client = SocketHTTPClient_new (NULL);

  /* Clear pool (even though empty) */
  SocketHTTPClient_pool_clear (client);

  SocketHTTPClient_pool_stats (client, &stats);
  ASSERT_EQ (stats.active_connections, 0, "should have no connections after clear");

  SocketHTTPClient_free (&client);
  TEST_PASS ();
}

/* ============================================================================
 * Error Handling Tests
 * ============================================================================ */

static void
test_error_strings (void)
{
  const char *s;

  TEST_START ("error strings");

  s = SocketHTTPClient_error_string (HTTPCLIENT_OK);
  ASSERT_NOT_NULL (s, "OK should have string");

  s = SocketHTTPClient_error_string (HTTPCLIENT_ERROR_DNS);
  ASSERT_NOT_NULL (s, "DNS error should have string");

  s = SocketHTTPClient_error_string (HTTPCLIENT_ERROR_TIMEOUT);
  ASSERT_NOT_NULL (s, "timeout error should have string");

  s = SocketHTTPClient_error_string (HTTPCLIENT_ERROR_TOO_MANY_REDIRECTS);
  ASSERT_NOT_NULL (s, "redirects error should have string");

  TEST_PASS ();
}

static void
test_last_error (void)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_Error err;

  TEST_START ("last error");

  client = SocketHTTPClient_new (NULL);

  err = SocketHTTPClient_last_error (client);
  ASSERT_EQ (err, HTTPCLIENT_OK, "initial error should be OK");

  SocketHTTPClient_free (&client);
  TEST_PASS ();
}

/* ============================================================================
 * Response Free Test
 * ============================================================================ */

static void
test_response_free (void)
{
  SocketHTTPClient_Response response;

  TEST_START ("response free");

  memset (&response, 0, sizeof (response));
  response.arena = Arena_new ();
  response.status_code = 200;

  SocketHTTPClient_Response_free (&response);
  ASSERT_NULL (response.arena, "arena should be NULL after free");
  ASSERT_EQ (response.status_code, 0, "status should be cleared");

  TEST_PASS ();
}

/* ============================================================================
 * URL Parsing Tests
 * ============================================================================ */

static void
test_url_parsing_http (void)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_Request_T req;

  TEST_START ("URL parsing (http)");

  client = SocketHTTPClient_new (NULL);

  req = SocketHTTPClient_Request_new (client, HTTP_METHOD_GET,
                                      "http://example.com:8080/path/to/resource");
  ASSERT_NOT_NULL (req, "request should be created");

  SocketHTTPClient_Request_free (&req);
  SocketHTTPClient_free (&client);
  TEST_PASS ();
}

static void
test_url_parsing_https (void)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_Request_T req;

  TEST_START ("URL parsing (https)");

  client = SocketHTTPClient_new (NULL);

  req = SocketHTTPClient_Request_new (client, HTTP_METHOD_GET,
                                      "https://secure.example.com/api/v1/data");
  ASSERT_NOT_NULL (req, "request should be created");

  SocketHTTPClient_Request_free (&req);
  SocketHTTPClient_free (&client);
  TEST_PASS ();
}

static void
test_url_parsing_various (void)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_Request_T req;

  TEST_START ("URL parsing (various formats)");

  client = SocketHTTPClient_new (NULL);

  /* Valid URLs should work */
  req = SocketHTTPClient_Request_new (client, HTTP_METHOD_GET,
                                      "http://example.com/path");
  ASSERT_NOT_NULL (req, "http URL should create request");
  SocketHTTPClient_Request_free (&req);

  req = SocketHTTPClient_Request_new (client, HTTP_METHOD_GET,
                                      "https://secure.example.com/api");
  ASSERT_NOT_NULL (req, "https URL should create request");
  SocketHTTPClient_Request_free (&req);

  req = SocketHTTPClient_Request_new (client, HTTP_METHOD_GET,
                                      "http://localhost:3000/test");
  ASSERT_NOT_NULL (req, "localhost URL should create request");
  SocketHTTPClient_Request_free (&req);

  SocketHTTPClient_free (&client);
  TEST_PASS ();
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================ */

int
main (void)
{
  /* Ignore SIGPIPE */
  signal (SIGPIPE, SIG_IGN);

  printf ("\n");
  printf ("============================================================\n");
  printf ("HTTP Client Test Suite\n");
  printf ("============================================================\n\n");

  printf ("Configuration Tests:\n");
  test_config_defaults ();

  printf ("\nClient Lifecycle Tests:\n");
  test_client_new_free ();
  test_client_with_config ();

  printf ("\nRequest Builder Tests:\n");
  test_request_new_free ();
  test_request_headers ();
  test_request_body ();
  test_request_timeout ();

  printf ("\nCookie Jar Tests:\n");
  test_cookie_jar_new_free ();
  test_cookie_jar_set_get ();
  test_cookie_jar_update ();
  test_cookie_jar_clear ();
  test_cookie_jar_association ();

  printf ("\nAuthentication Tests:\n");
  test_auth_basic ();
  test_auth_bearer ();
  test_auth_per_request ();

  printf ("\nPool Tests:\n");
  test_pool_stats ();
  test_pool_clear ();

  printf ("\nError Handling Tests:\n");
  test_error_strings ();
  test_last_error ();

  printf ("\nResponse Tests:\n");
  test_response_free ();

  printf ("\nURL Parsing Tests:\n");
  test_url_parsing_http ();
  test_url_parsing_https ();
  test_url_parsing_various ();

  printf ("\n============================================================\n");
  printf ("Test Results: %d passed, %d failed, %d total\n", tests_passed,
          tests_failed, tests_run);
  printf ("============================================================\n\n");

  return tests_failed > 0 ? 1 : 0;
}

