/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

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

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h" /* For SOCKET_HAS_TLS */
#include "http/SocketHTTP.h"
#include "http/SocketHTTPClient-private.h" /* For auth helper testing */
#include "http/SocketHTTPClient.h"

#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ============================================================================
 * Test Framework
 * ============================================================================
 */

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_START(name)                                                      \
  do                                                                          \
    {                                                                         \
      printf ("  Testing: %s... ", name);                                     \
      fflush (stdout);                                                        \
      tests_run++;                                                            \
    }                                                                         \
  while (0)

#define TEST_PASS()                                                           \
  do                                                                          \
    {                                                                         \
      printf ("PASS\n");                                                      \
      tests_passed++;                                                         \
    }                                                                         \
  while (0)

#define TEST_FAIL(msg)                                                        \
  do                                                                          \
    {                                                                         \
      printf ("FAIL: %s\n", msg);                                             \
      tests_failed++;                                                         \
    }                                                                         \
  while (0)

#define ASSERT_TRUE(cond, msg)                                                \
  do                                                                          \
    {                                                                         \
      if (!(cond))                                                            \
        {                                                                     \
          TEST_FAIL (msg);                                                    \
          return;                                                             \
        }                                                                     \
    }                                                                         \
  while (0)

#define ASSERT_EQ(a, b, msg) ASSERT_TRUE ((a) == (b), msg)
#define ASSERT_NE(a, b, msg) ASSERT_TRUE ((a) != (b), msg)
#define ASSERT_NULL(p, msg) ASSERT_TRUE ((p) == NULL, msg)
#define ASSERT_NOT_NULL(p, msg) ASSERT_TRUE ((p) != NULL, msg)
#define ASSERT_STR_EQ(a, b, msg) ASSERT_TRUE (strcmp ((a), (b)) == 0, msg)

/* ============================================================================
 * Configuration Tests
 * ============================================================================
 */

static void
test_config_defaults (void)
{
  SocketHTTPClient_Config config;

  TEST_START ("config defaults");

  SocketHTTPClient_config_defaults (&config);

  ASSERT_EQ (config.max_version, HTTP_VERSION_2,
             "max_version should be HTTP/2");
  ASSERT_EQ (config.allow_http2_cleartext, 0,
             "h2c should be disabled by default");
  ASSERT_EQ (config.enable_connection_pool, 1, "pooling should be enabled");
  ASSERT_EQ (config.max_connections_per_host,
             HTTPCLIENT_DEFAULT_MAX_CONNS_PER_HOST,
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
 * ============================================================================
 */

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
 * ============================================================================
 */

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

  result
      = SocketHTTPClient_Request_header (req, "X-Custom-Header", "test-value");
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
 * ============================================================================
 */

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
 * ============================================================================
 */

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
 * Digest Authentication Tests
 * ============================================================================
 */

/**
 * Test Basic auth header generation
 */
static void
test_auth_basic_header (void)
{
  char output[256];
  int result;

  TEST_START ("basic auth header generation");

  result
      = httpclient_auth_basic_header ("user", "pass", output, sizeof (output));
  ASSERT_EQ (result, 0, "should generate basic auth header");

  /* Check that it starts with "Basic " */
  ASSERT_TRUE (strncmp (output, "Basic ", 6) == 0,
               "should start with 'Basic '");

  /* The value should be base64("user:pass") = "dXNlcjpwYXNz" */
  ASSERT_STR_EQ (output, "Basic dXNlcjpwYXNz",
                 "should have correct base64 encoding");

  TEST_PASS ();
}

#if SOCKET_HAS_TLS
/**
 * Test Digest auth response generation (MD5, no qop)
 * NOTE: Requires TLS for MD5 hashing
 */
static void
test_auth_digest_md5_no_qop (void)
{
  char output[1024];
  int result;

  TEST_START ("digest auth MD5 no qop");

  /* Test with RFC 2617 style (no qop) */
  result = httpclient_auth_digest_response (
      "user", "pass", "testrealm@host.com",
      "dcd98b7102dd2f0e8b11d0f600bfb0c093", "/dir/index.html", "GET",
      NULL, /* qop */
      NULL, /* nc */
      NULL, /* cnonce */
      0,    /* MD5 */
      output, sizeof (output));

  ASSERT_EQ (result, 0, "should generate digest response");

  /* Check it contains required fields */
  ASSERT_NOT_NULL (strstr (output, "Digest "), "should start with Digest");
  ASSERT_NOT_NULL (strstr (output, "username=\"user\""),
                   "should contain username");
  ASSERT_NOT_NULL (strstr (output, "realm=\"testrealm@host.com\""),
                   "should contain realm");
  ASSERT_NOT_NULL (strstr (output, "algorithm=MD5"),
                   "should contain algorithm");
  ASSERT_NOT_NULL (strstr (output, "response=\""), "should contain response");

  /* Should NOT contain qop fields since qop is NULL */
  ASSERT_NULL (strstr (output, "qop="), "should not contain qop");
  ASSERT_NULL (strstr (output, "nc="), "should not contain nc");
  ASSERT_NULL (strstr (output, "cnonce="), "should not contain cnonce");

  TEST_PASS ();
}
#endif /* SOCKET_HAS_TLS */

#if SOCKET_HAS_TLS
/**
 * Test Digest auth response generation (MD5, qop=auth)
 * NOTE: Requires TLS for MD5 hashing
 */
static void
test_auth_digest_md5_qop_auth (void)
{
  char output[1024];
  int result;

  TEST_START ("digest auth MD5 qop=auth");

  /* Test with RFC 7616 style (qop=auth) */
  result = httpclient_auth_digest_response (
      "testuser", "testpass", "Protected Area",
      "7f9f98d76b89c4d2e5a5a5d3e4f5a6b7", "/protected/resource", "GET", "auth",
      "00000001", "8fc1bc23d4e8f5a9", /* Fixed cnonce for reproducible test */
      0,                              /* MD5 */
      output, sizeof (output));

  ASSERT_EQ (result, 0, "should generate digest response");

  /* Check it contains all required fields */
  ASSERT_NOT_NULL (strstr (output, "Digest "), "should start with Digest");
  ASSERT_NOT_NULL (strstr (output, "qop=auth"), "should contain qop=auth");
  ASSERT_NOT_NULL (strstr (output, "nc=00000001"), "should contain nc");
  ASSERT_NOT_NULL (strstr (output, "cnonce=\"8fc1bc23d4e8f5a9\""),
                   "should contain cnonce");
  ASSERT_NOT_NULL (strstr (output, "algorithm=MD5"), "should use MD5");

  TEST_PASS ();
}

/**
 * Test Digest auth response generation (SHA-256)
 * NOTE: Requires TLS for SHA-256 hashing
 */
static void
test_auth_digest_sha256 (void)
{
  char output[1024];
  int result;

  TEST_START ("digest auth SHA-256");

  result = httpclient_auth_digest_response (
      "user", "secret", "api.example.com", "abc123def456", "/api/v1/data",
      "POST", "auth", "00000001", "randomcnonce", 1, /* SHA-256 */
      output, sizeof (output));

  ASSERT_EQ (result, 0, "should generate SHA-256 digest response");

  /* Check algorithm is SHA-256 */
  ASSERT_NOT_NULL (strstr (output, "algorithm=SHA-256"),
                   "should use SHA-256 algorithm");

  /* SHA-256 response should be 64 hex chars */
  const char *resp_start = strstr (output, "response=\"");
  ASSERT_NOT_NULL (resp_start, "should have response field");

  TEST_PASS ();
}
#endif /* SOCKET_HAS_TLS */

#if SOCKET_HAS_TLS
/**
 * Test Digest challenge parsing with full WWW-Authenticate header
 * NOTE: Requires TLS for MD5 hashing
 */
static void
test_auth_digest_challenge (void)
{
  char output[1024];
  int result;

  TEST_START ("digest auth challenge parsing");

  /* Realistic WWW-Authenticate header */
  const char *www_auth = "Digest realm=\"Protected Area\", "
                         "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", "
                         "qop=\"auth,auth-int\", "
                         "algorithm=MD5, "
                         "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";

  result = httpclient_auth_digest_challenge (www_auth, "user", "pass", "GET",
                                             "/dir/index.html", "00000001",
                                             output, sizeof (output));

  ASSERT_EQ (result, 0, "should parse challenge and generate response");

  /* Verify response contains required fields */
  ASSERT_NOT_NULL (strstr (output, "Digest "), "should be Digest response");
  ASSERT_NOT_NULL (strstr (output, "realm=\"Protected Area\""),
                   "should include realm");
  ASSERT_NOT_NULL (strstr (output, "qop=auth"),
                   "should select qop=auth (not auth-int)");

  /* Test qop with tab delimiter (word boundary bug fix) */
  const char *www_auth_tab = "Digest realm=\"test\", nonce=\"abc\", "
                             "qop=\"auth\t, auth-int\"";
  result = httpclient_auth_digest_challenge (www_auth_tab, "user", "pass",
                                             "GET", "/test", "00000001",
                                             output, sizeof (output));
  ASSERT_EQ (result, 0, "should parse qop with tab delimiter");
  ASSERT_NOT_NULL (strstr (output, "qop=auth"),
                   "should select auth with tab boundary");

  TEST_PASS ();
}
#endif /* SOCKET_HAS_TLS */

/**
 * Test stale nonce detection
 */
static void
test_auth_stale_nonce_detection (void)
{
  int is_stale;

  TEST_START ("stale nonce detection");

  /* Test with stale=true */
  is_stale = httpclient_auth_is_stale_nonce (
      "Digest realm=\"test\", nonce=\"abc\", stale=true");
  ASSERT_EQ (is_stale, 1, "should detect stale=true");

  /* Test with stale=TRUE (case insensitive) */
  is_stale = httpclient_auth_is_stale_nonce (
      "Digest realm=\"test\", nonce=\"abc\", stale=TRUE");
  ASSERT_EQ (is_stale, 1, "should detect stale=TRUE (case insensitive)");

  /* Test with quoted stale="true" */
  is_stale = httpclient_auth_is_stale_nonce (
      "Digest realm=\"test\", nonce=\"abc\", stale=\"true\"");
  ASSERT_EQ (is_stale, 1, "should detect stale=\"true\" (quoted)");

  /* Test with stale=false */
  is_stale = httpclient_auth_is_stale_nonce (
      "Digest realm=\"test\", nonce=\"abc\", stale=false");
  ASSERT_EQ (is_stale, 0, "should not detect stale=false");

  /* Test without stale parameter */
  is_stale = httpclient_auth_is_stale_nonce (
      "Digest realm=\"test\", nonce=\"abc\", qop=\"auth\"");
  ASSERT_EQ (is_stale, 0, "should not detect stale when absent");

  /* Test with NULL */
  is_stale = httpclient_auth_is_stale_nonce (NULL);
  ASSERT_EQ (is_stale, 0, "should handle NULL input");

  /* Test Basic auth (no stale concept) */
  is_stale = httpclient_auth_is_stale_nonce ("Basic realm=\"test\"");
  ASSERT_EQ (is_stale, 0, "should not find stale in Basic auth");

  /* Test word boundary: "stalex" should NOT match "stale" */
  is_stale = httpclient_auth_is_stale_nonce (
      "Digest realm=\"test\", nonce=\"abc\", stalex=true");
  ASSERT_EQ (is_stale, 0, "should not match stalex=true (word boundary)");

  /* Test with stale followed by tab before = */
  is_stale = httpclient_auth_is_stale_nonce (
      "Digest realm=\"test\", nonce=\"abc\", stale\t=true");
  ASSERT_EQ (is_stale, 1, "should detect stale with tab before =");

  TEST_PASS ();
}

/**
 * Test Digest auth client configuration
 */
static void
test_auth_digest_client_config (void)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_Auth auth;

  TEST_START ("digest auth client configuration");

  client = SocketHTTPClient_new (NULL);

  memset (&auth, 0, sizeof (auth));
  auth.type = HTTP_AUTH_DIGEST;
  auth.username = "digestuser";
  auth.password = "digestpass";

  SocketHTTPClient_set_auth (client, &auth);

  /* Verify auth was set (indirect check - client stores it) */
  ASSERT_NOT_NULL (client, "client should be valid");

  /* Set different auth */
  auth.username = "newuser";
  auth.password = "newpass";
  SocketHTTPClient_set_auth (client, &auth);

  /* Clear auth */
  SocketHTTPClient_set_auth (client, NULL);

  SocketHTTPClient_free (&client);
  TEST_PASS ();
}

/**
 * Test buffer too small for auth header
 */
static void
test_auth_buffer_overflow_protection (void)
{
  char small_buf[10]; /* Intentionally too small */
  int result;

  TEST_START ("auth buffer overflow protection");

  /* Basic auth with small buffer should fail */
  result = httpclient_auth_basic_header ("user", "password", small_buf,
                                         sizeof (small_buf));
  ASSERT_EQ (result, -1, "should fail with small buffer");

#if SOCKET_HAS_TLS
  /* Digest response with small buffer should fail (requires TLS for MD5) */
  result = httpclient_auth_digest_response ("user", "pass", "realm", "nonce",
                                            "/", "GET", NULL, NULL, NULL, 0,
                                            small_buf, sizeof (small_buf));
  ASSERT_EQ (result, -1, "should fail with small buffer for digest");
#else
  (void)result; /* Suppress unused warning when TLS disabled */
#endif

  TEST_PASS ();
}

/**
 * Test secure clearing of authentication headers (Issue #1868)
 */
static void
test_auth_secure_clear (void)
{
  char output[256];
  int result;
  size_t i;
  int all_cleared;

  TEST_START ("auth header secure clearing");

  /* Test Basic auth header clearing */
  result
      = httpclient_auth_basic_header ("user", "pass", output, sizeof (output));
  ASSERT_EQ (result, 0, "should generate basic auth header");
  ASSERT_STR_EQ (output, "Basic dXNlcjpwYXNz",
                 "should have correct base64 encoding");

  /* Clear the header */
  httpclient_auth_clear_header (output, sizeof (output));

  /* Verify all bytes are cleared (should be zeroed) */
  all_cleared = 1;
  for (i = 0; i < sizeof (output); i++)
    {
      if (output[i] != 0)
        {
          all_cleared = 0;
          break;
        }
    }
  ASSERT_TRUE (all_cleared, "basic auth header should be fully cleared");

  /* Test Bearer token header clearing */
  result = httpclient_auth_bearer_header ("secret_token_12345", output,
                                          sizeof (output));
  ASSERT_EQ (result, 0, "should generate bearer auth header");
  ASSERT_TRUE (strncmp (output, "Bearer ", 7) == 0,
               "should start with 'Bearer '");

  /* Clear the header */
  httpclient_auth_clear_header (output, sizeof (output));

  /* Verify all bytes are cleared */
  all_cleared = 1;
  for (i = 0; i < sizeof (output); i++)
    {
      if (output[i] != 0)
        {
          all_cleared = 0;
          break;
        }
    }
  ASSERT_TRUE (all_cleared, "bearer auth header should be fully cleared");

#if SOCKET_HAS_TLS
  /* Test Digest auth header clearing (requires TLS for hashing) */
  result = httpclient_auth_digest_response (
      "user", "pass", "testrealm@host.com",
      "dcd98b7102dd2f0e8b11d0f600bfb0c093", "/dir/index.html", "GET",
      NULL, /* qop */
      NULL, /* nc */
      NULL, /* cnonce */
      0,    /* MD5 */
      output, sizeof (output));
  ASSERT_EQ (result, 0, "should generate digest response");

  /* Clear the header */
  httpclient_auth_clear_header (output, sizeof (output));

  /* Verify all bytes are cleared */
  all_cleared = 1;
  for (i = 0; i < sizeof (output); i++)
    {
      if (output[i] != 0)
        {
          all_cleared = 0;
          break;
        }
    }
  ASSERT_TRUE (all_cleared, "digest auth header should be fully cleared");
#endif

  TEST_PASS ();
}

/* ============================================================================
 * Pool Statistics Tests
 * ============================================================================
 */

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
  ASSERT_EQ (stats.active_connections, 0,
             "should have no connections after clear");

  SocketHTTPClient_free (&client);
  TEST_PASS ();
}

/* ============================================================================
 * Error Handling Tests
 * ============================================================================
 */

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
 * ============================================================================
 */

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
 * ============================================================================
 */

static void
test_url_parsing_http (void)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_Request_T req;

  TEST_START ("URL parsing (http)");

  client = SocketHTTPClient_new (NULL);

  req = SocketHTTPClient_Request_new (
      client, HTTP_METHOD_GET, "http://example.com:8080/path/to/resource");
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

  req = SocketHTTPClient_Request_new (
      client, HTTP_METHOD_GET, "https://secure.example.com/api/v1/data");
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
 * Pool Statistics Extended Tests
 * ============================================================================
 */

static void
test_pool_stats_extended (void)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_PoolStats stats;
  SocketHTTPClient_Config config;

  TEST_START ("pool statistics (extended)");

  SocketHTTPClient_config_defaults (&config);
  config.max_connections_per_host = 2;
  config.max_total_connections = 10;
  config.max_connection_age_ms = 30000; /* 30 seconds */
  config.acquire_timeout_ms = 5000;     /* 5 seconds */

  client = SocketHTTPClient_new (&config);
  ASSERT_NOT_NULL (client, "client should not be NULL");

  SocketHTTPClient_pool_stats (client, &stats);

  /* All counters should start at zero */
  ASSERT_EQ (stats.active_connections, 0, "no active connections initially");
  ASSERT_EQ (stats.idle_connections, 0, "no idle connections initially");
  ASSERT_EQ (stats.total_requests, 0, "no requests initially");
  ASSERT_EQ (stats.reused_connections, 0, "no reused connections initially");
  ASSERT_EQ (stats.connections_created, 0, "no connections created initially");
  ASSERT_EQ (stats.connections_failed, 0, "no connections failed initially");
  ASSERT_EQ (stats.connections_timed_out, 0, "no timeouts initially");
  ASSERT_EQ (stats.stale_connections_removed, 0,
             "no stale removals initially");
  ASSERT_EQ (stats.pool_exhausted_waits, 0, "no waits initially");

  SocketHTTPClient_free (&client);
  TEST_PASS ();
}

/* ============================================================================
 * Connection Pool Configuration Tests
 * ============================================================================
 */

static void
test_pool_config_limits (void)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_Config config;

  TEST_START ("pool configuration limits");

  SocketHTTPClient_config_defaults (&config);
  config.max_connections_per_host = 4;
  config.max_total_connections = 50;
  config.idle_timeout_ms = 30000;
  config.max_connection_age_ms = 60000;
  config.acquire_timeout_ms = 10000;

  client = SocketHTTPClient_new (&config);
  ASSERT_NOT_NULL (client, "client should be created with custom limits");

  SocketHTTPClient_free (&client);
  TEST_PASS ();
}

static void
test_pool_no_pooling (void)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_Config config;
  SocketHTTPClient_PoolStats stats;

  TEST_START ("pool disabled");

  SocketHTTPClient_config_defaults (&config);
  config.enable_connection_pool = 0;

  client = SocketHTTPClient_new (&config);
  ASSERT_NOT_NULL (client, "client should be created with pooling disabled");

  /* Stats should still work but show zeros */
  SocketHTTPClient_pool_stats (client, &stats);
  ASSERT_EQ (stats.active_connections, 0, "no active connections");
  ASSERT_EQ (stats.idle_connections, 0, "no idle connections");

  SocketHTTPClient_free (&client);
  TEST_PASS ();
}

/* ============================================================================
 * Response Size Limit Tests
 * ============================================================================
 */

static void
test_max_response_size_config (void)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_Config config;

  TEST_START ("max response size configuration");

  SocketHTTPClient_config_defaults (&config);
  config.max_response_size = 1024 * 1024; /* 1 MB limit */

  client = SocketHTTPClient_new (&config);
  ASSERT_NOT_NULL (client, "client should be created with response limit");

  SocketHTTPClient_free (&client);
  TEST_PASS ();
}

/* ============================================================================
 * Async Request Tests
 * ============================================================================
 */

/* Dummy callback for async tests */
static void
dummy_async_callback (SocketHTTPClient_AsyncRequest_T req,
                      SocketHTTPClient_Response *response,
                      SocketHTTPClient_Error error, void *userdata)
{
  (void)req;
  (void)response;
  (void)error;
  (void)userdata;
}

static void
test_async_cancel (void)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_Request_T req;
  SocketHTTPClient_AsyncRequest_T async_req;

  TEST_START ("async request cancellation");

  client = SocketHTTPClient_new (NULL);
  req = SocketHTTPClient_Request_new (client, HTTP_METHOD_GET,
                                      "http://example.com/test");
  ASSERT_NOT_NULL (req, "request should be created");

  async_req = SocketHTTPClient_Request_async (req, dummy_async_callback, NULL);
  ASSERT_NOT_NULL (async_req, "async request should be created");

  SocketHTTPClient_AsyncRequest_cancel (async_req);
  SocketHTTPClient_AsyncRequest_cancel (async_req);

  SocketHTTPClient_AsyncRequest_free (&async_req);
  SocketHTTPClient_Request_free (&req);
  SocketHTTPClient_free (&client);
  TEST_PASS ();
}

/* ============================================================================
 * Concurrency Configuration Tests
 * ============================================================================
 */

static void
test_concurrency_config (void)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_Config config;
  SocketHTTPClient_PoolStats stats;

  TEST_START ("concurrency configuration");

  SocketHTTPClient_config_defaults (&config);
  config.max_connections_per_host = 4;
  config.max_total_connections = 20;
  config.acquire_timeout_ms = 5000;

  client = SocketHTTPClient_new (&config);
  ASSERT_NOT_NULL (client, "client should be created");

  /* Verify pool is properly configured */
  SocketHTTPClient_pool_stats (client, &stats);
  ASSERT_EQ (stats.active_connections, 0, "no active connections");
  ASSERT_EQ (stats.idle_connections, 0, "no idle connections");

  SocketHTTPClient_free (&client);
  TEST_PASS ();
}

static void
test_multiple_clients (void)
{
  SocketHTTPClient_T clients[5];
  SocketHTTPClient_Config config;
  int i;

  TEST_START ("multiple clients");

  SocketHTTPClient_config_defaults (&config);
  config.max_connections_per_host = 2;
  config.max_total_connections = 10;

  /* Create multiple independent clients */
  for (i = 0; i < 5; i++)
    {
      clients[i] = SocketHTTPClient_new (&config);
      ASSERT_NOT_NULL (clients[i], "client should be created");
    }

  /* Each client should have its own independent pool */
  for (i = 0; i < 5; i++)
    {
      SocketHTTPClient_PoolStats stats;
      SocketHTTPClient_pool_stats (clients[i], &stats);
      ASSERT_EQ (stats.active_connections, 0, "no active connections");
    }

  /* Free all clients */
  for (i = 0; i < 5; i++)
    {
      SocketHTTPClient_free (&clients[i]);
      ASSERT_NULL (clients[i], "client should be NULL after free");
    }

  TEST_PASS ();
}

/* ============================================================================
 * Timeout Configuration Tests
 * ============================================================================
 */

static void
test_timeout_configuration (void)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_Config config;
  SocketHTTPClient_Request_T req;

  TEST_START ("timeout configuration");

  SocketHTTPClient_config_defaults (&config);
  config.connect_timeout_ms = 5000;
  config.request_timeout_ms = 30000;
  config.dns_timeout_ms = 2000;

  client = SocketHTTPClient_new (&config);
  ASSERT_NOT_NULL (client, "client should be created");

  /* Create request with custom timeout */
  req = SocketHTTPClient_Request_new (client, HTTP_METHOD_GET,
                                      "http://example.com/");
  ASSERT_NOT_NULL (req, "request should be created");

  /* Set per-request timeout */
  SocketHTTPClient_Request_timeout (req, 10000);

  SocketHTTPClient_Request_free (&req);
  SocketHTTPClient_free (&client);
  TEST_PASS ();
}

/* ============================================================================
 * Prepared Request Tests (Issue #185)
 * ============================================================================
 */

static void
test_prepared_request_basic (void)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_PreparedRequest_T prep;

  TEST_START ("prepared request basic");

  client = SocketHTTPClient_new (NULL);
  ASSERT_NOT_NULL (client, "client should not be NULL");

  prep = SocketHTTPClient_prepare (client, HTTP_METHOD_GET,
                                   "http://example.com/path?query=value");
  ASSERT_NOT_NULL (prep, "prepared request should not be NULL");

  SocketHTTPClient_PreparedRequest_free (&prep);
  ASSERT_NULL (prep, "prepared request should be NULL after free");

  SocketHTTPClient_free (&client);
  TEST_PASS ();
}

static void
test_prepared_request_https (void)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_PreparedRequest_T prep;

  TEST_START ("prepared request https");

  client = SocketHTTPClient_new (NULL);

  prep = SocketHTTPClient_prepare (client, HTTP_METHOD_GET,
                                   "https://secure.example.com/api/v1/data");
  ASSERT_NOT_NULL (prep, "prepared https request should not be NULL");

  SocketHTTPClient_PreparedRequest_free (&prep);
  SocketHTTPClient_free (&client);
  TEST_PASS ();
}

static void
test_prepared_request_methods (void)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_PreparedRequest_T prep;

  TEST_START ("prepared request methods");

  client = SocketHTTPClient_new (NULL);

  /* Test GET */
  prep = SocketHTTPClient_prepare (client, HTTP_METHOD_GET,
                                   "http://example.com/get");
  ASSERT_NOT_NULL (prep, "GET prepared should succeed");
  SocketHTTPClient_PreparedRequest_free (&prep);

  /* Test POST */
  prep = SocketHTTPClient_prepare (client, HTTP_METHOD_POST,
                                   "http://example.com/post");
  ASSERT_NOT_NULL (prep, "POST prepared should succeed");
  SocketHTTPClient_PreparedRequest_free (&prep);

  /* Test PUT */
  prep = SocketHTTPClient_prepare (client, HTTP_METHOD_PUT,
                                   "http://example.com/put");
  ASSERT_NOT_NULL (prep, "PUT prepared should succeed");
  SocketHTTPClient_PreparedRequest_free (&prep);

  /* Test DELETE */
  prep = SocketHTTPClient_prepare (client, HTTP_METHOD_DELETE,
                                   "http://example.com/delete");
  ASSERT_NOT_NULL (prep, "DELETE prepared should succeed");
  SocketHTTPClient_PreparedRequest_free (&prep);

  SocketHTTPClient_free (&client);
  TEST_PASS ();
}

static void
test_prepared_request_with_port (void)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_PreparedRequest_T prep;

  TEST_START ("prepared request with custom port");

  client = SocketHTTPClient_new (NULL);

  /* Non-standard port */
  prep = SocketHTTPClient_prepare (client, HTTP_METHOD_GET,
                                   "http://example.com:8080/api");
  ASSERT_NOT_NULL (prep, "prepared with custom port should succeed");
  SocketHTTPClient_PreparedRequest_free (&prep);

  /* HTTPS with custom port */
  prep = SocketHTTPClient_prepare (client, HTTP_METHOD_GET,
                                   "https://example.com:8443/secure");
  ASSERT_NOT_NULL (prep, "prepared https with custom port should succeed");
  SocketHTTPClient_PreparedRequest_free (&prep);

  SocketHTTPClient_free (&client);
  TEST_PASS ();
}

static void
test_prepared_request_invalid (void)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_PreparedRequest_T prep;

  TEST_START ("prepared request invalid inputs");

  client = SocketHTTPClient_new (NULL);

  /* NULL client - must fail */
  prep = SocketHTTPClient_prepare (NULL, HTTP_METHOD_GET,
                                   "http://example.com/");
  ASSERT_NULL (prep, "NULL client should return NULL");

  /* NULL URL - must fail */
  prep = SocketHTTPClient_prepare (client, HTTP_METHOD_GET, NULL);
  ASSERT_NULL (prep, "NULL URL should return NULL");

  SocketHTTPClient_free (&client);
  TEST_PASS ();
}

static void
test_prepared_request_free_null (void)
{
  SocketHTTPClient_PreparedRequest_T prep = NULL;

  TEST_START ("prepared request free NULL");

  /* Should not crash */
  SocketHTTPClient_PreparedRequest_free (NULL);
  SocketHTTPClient_PreparedRequest_free (&prep);

  TEST_PASS ();
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================
 */

int
main (void)
{
  /* Ignore SIGPIPE - library handles this internally, but explicit for tests
   */
  if (Socket_ignore_sigpipe () != 0)
    {
      perror ("Socket_ignore_sigpipe");
      return 1;
    }

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

  printf ("\nDigest Authentication Tests:\n");
  test_auth_basic_header ();
#if SOCKET_HAS_TLS
  test_auth_digest_md5_no_qop ();
  test_auth_digest_md5_qop_auth ();
  test_auth_digest_sha256 ();
  test_auth_digest_challenge ();
#else
  printf ("  [SKIPPED] digest auth tests (require TLS)\n");
#endif
  test_auth_stale_nonce_detection ();
  test_auth_digest_client_config ();
  test_auth_buffer_overflow_protection ();
  test_auth_secure_clear ();

  printf ("\nPool Tests:\n");
  test_pool_stats ();
  test_pool_stats_extended ();
  test_pool_config_limits ();
  test_pool_no_pooling ();
  test_pool_clear ();

  printf ("\nResponse Limit Tests:\n");
  test_max_response_size_config ();

  printf ("\nAsync Request Tests:\n");
  test_async_cancel ();

  printf ("\nConcurrency Tests:\n");
  test_concurrency_config ();
  test_multiple_clients ();

  printf ("\nTimeout Tests:\n");
  test_timeout_configuration ();

  printf ("\nError Handling Tests:\n");
  test_error_strings ();
  test_last_error ();

  printf ("\nResponse Tests:\n");
  test_response_free ();

  printf ("\nURL Parsing Tests:\n");
  test_url_parsing_http ();
  test_url_parsing_https ();
  test_url_parsing_various ();

  printf ("\nPrepared Request Tests (Issue #185):\n");
  test_prepared_request_basic ();
  test_prepared_request_https ();
  test_prepared_request_methods ();
  test_prepared_request_with_port ();
  test_prepared_request_invalid ();
  test_prepared_request_free_null ();

  printf ("\n============================================================\n");
  printf ("Test Results: %d passed, %d failed, %d total\n", tests_passed,
          tests_failed, tests_run);
  printf ("============================================================\n\n");

  return tests_failed > 0 ? 1 : 0;
}
