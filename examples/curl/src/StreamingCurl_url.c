/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file StreamingCurl_url.c
 * @brief URL parsing implementation for streaming curl module.
 *
 * Wraps SocketHTTP_URI_parse() with curl-specific validation and
 * convenience functions.
 */

#include "curl/StreamingCurl-private.h"
#include "curl/StreamingCurl.h"
#include "http/SocketHTTP.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

/* URL parsing constants */
#define HTTP_SCHEME_LEN 4
#define HTTPS_SCHEME_LEN 5
#define HTTP_SCHEME_PREFIX_LEN 7  /* "http://" */
#define HTTPS_SCHEME_PREFIX_LEN 8 /* "https://" */
#define DEFAULT_PATH "/"
#define DEFAULT_PATH_LEN 1
#define QUERY_CHAR_LEN 1     /* '?' */
#define PATH_SEPARATOR_LEN 1 /* '/' */

/* Exception definitions - format: { &self, "reason" } */
const Except_T Curl_Failed = { &Curl_Failed, "Curl operation failed" };
const Except_T Curl_DNSFailed = { &Curl_DNSFailed, "DNS resolution failed" };
const Except_T Curl_ConnectFailed
    = { &Curl_ConnectFailed, "Connection failed" };
const Except_T Curl_TLSFailed = { &Curl_TLSFailed, "TLS handshake failed" };
const Except_T Curl_Timeout = { &Curl_Timeout, "Operation timed out" };
const Except_T Curl_ProtocolError
    = { &Curl_ProtocolError, "HTTP protocol error" };
const Except_T Curl_TooManyRedirects
    = { &Curl_TooManyRedirects, "Too many redirects" };
const Except_T Curl_InvalidURL = { &Curl_InvalidURL, "Invalid URL" };

/* Error message table */
static const char *error_strings[]
    = { [CURL_OK] = "Success",
        [CURL_ERROR_DNS] = "DNS resolution failed",
        [CURL_ERROR_CONNECT] = "Connection failed",
        [CURL_ERROR_TLS] = "TLS handshake failed",
        [CURL_ERROR_TIMEOUT] = "Operation timed out",
        [CURL_ERROR_PROTOCOL] = "HTTP protocol error",
        [CURL_ERROR_TOO_MANY_REDIRECTS] = "Too many redirects",
        [CURL_ERROR_INVALID_URL] = "Invalid URL",
        [CURL_ERROR_WRITE_CALLBACK] = "Write callback failed",
        [CURL_ERROR_READ_CALLBACK] = "Read callback failed",
        [CURL_ERROR_OUT_OF_MEMORY] = "Out of memory",
        [CURL_ERROR_ABORTED] = "Operation aborted" };

const char *
Curl_error_string (CurlError error)
{
  if (error >= 0 && error <= CURL_ERROR_ABORTED)
    return error_strings[error];
  return "Unknown error";
}

char *
curl_arena_strdup (Arena_T arena, const char *str, size_t len)
{
  if (!str || len == 0)
    return NULL;

  char *copy = ALLOC (arena, len + 1);
  memcpy (copy, str, len);
  copy[len] = '\0';
  return copy;
}

/**
 * @brief Check if scheme is http or https.
 */
static int
is_http_scheme (const char *scheme, size_t len)
{
  if (len == HTTP_SCHEME_LEN
      && strncasecmp (scheme, "http", HTTP_SCHEME_LEN) == 0)
    return 1;
  if (len == HTTPS_SCHEME_LEN
      && strncasecmp (scheme, "https", HTTPS_SCHEME_LEN) == 0)
    return 1;
  return 0;
}

CurlError
Curl_parse_url (const char *url,
                size_t len,
                CurlParsedURL *result,
                Arena_T arena)
{
  if (!url || !result || !arena)
    return CURL_ERROR_INVALID_URL;

  if (len == 0)
    len = strlen (url);

  /* Clear result */
  memset (result, 0, sizeof (*result));

  /* Use the existing URI parser */
  SocketHTTP_URI uri;
  SocketHTTP_URIResult parse_result
      = SocketHTTP_URI_parse (url, len, &uri, arena);

  if (parse_result != URI_PARSE_OK)
    return CURL_ERROR_INVALID_URL;

  /* Validate scheme is http or https */
  if (!uri.scheme || !is_http_scheme (uri.scheme, uri.scheme_len))
    return CURL_ERROR_INVALID_URL;

  /* Validate host is present */
  if (!uri.host || uri.host_len == 0)
    return CURL_ERROR_INVALID_URL;

  /* Copy components to result */
  result->scheme = curl_arena_strdup (arena, uri.scheme, uri.scheme_len);
  result->scheme_len = uri.scheme_len;

  if (uri.userinfo && uri.userinfo_len > 0)
    {
      result->userinfo
          = curl_arena_strdup (arena, uri.userinfo, uri.userinfo_len);
      result->userinfo_len = uri.userinfo_len;
    }

  result->host = curl_arena_strdup (arena, uri.host, uri.host_len);
  result->host_len = uri.host_len;

  /* Determine if secure */
  result->is_secure = SocketHTTP_URI_is_secure (&uri);

  /* Handle port */
  if (uri.port > 0)
    {
      result->port = uri.port;
    }
  else
    {
      result->port = result->is_secure ? CURL_HTTPS_DEFAULT_PORT
                                       : CURL_HTTP_DEFAULT_PORT;
    }

  /* Handle path - default to "/" if empty */
  if (uri.path && uri.path_len > 0)
    {
      result->path = curl_arena_strdup (arena, uri.path, uri.path_len);
      result->path_len = uri.path_len;
    }
  else
    {
      result->path = curl_arena_strdup (arena, DEFAULT_PATH, DEFAULT_PATH_LEN);
      result->path_len = DEFAULT_PATH_LEN;
    }

  /* Copy query string if present */
  if (uri.query && uri.query_len > 0)
    {
      result->query = curl_arena_strdup (arena, uri.query, uri.query_len);
      result->query_len = uri.query_len;
    }

  /* Copy fragment if present */
  if (uri.fragment && uri.fragment_len > 0)
    {
      result->fragment
          = curl_arena_strdup (arena, uri.fragment, uri.fragment_len);
      result->fragment_len = uri.fragment_len;
    }

  return CURL_OK;
}

int
Curl_url_get_port (const CurlParsedURL *url)
{
  if (!url)
    return CURL_HTTP_DEFAULT_PORT;

  if (url->port > 0)
    return url->port;

  return url->is_secure ? CURL_HTTPS_DEFAULT_PORT : CURL_HTTP_DEFAULT_PORT;
}

ssize_t
Curl_resolve_url (const CurlParsedURL *base,
                  const char *relative,
                  char *result,
                  size_t result_size)
{
  if (!base || !relative || !result || result_size == 0)
    return -1;

  size_t rel_len = strlen (relative);
  if (rel_len == 0)
    return -1;

  /* Check if relative is actually an absolute URL */
  if (rel_len > HTTP_SCHEME_PREFIX_LEN
      && (strncasecmp (relative, "http://", HTTP_SCHEME_PREFIX_LEN) == 0
          || strncasecmp (relative, "https://", HTTPS_SCHEME_PREFIX_LEN) == 0))
    {
      /* It's an absolute URL, just copy it */
      if (rel_len >= result_size)
        return -1;
      memcpy (result, relative, rel_len);
      result[rel_len] = '\0';
      return (ssize_t)rel_len;
    }

  /* Build the resolved URL */
  size_t written = 0;
  int n;

  /* Start with scheme and host */
  n = snprintf (result + written, result_size - written, "%s://", base->scheme);
  if (n < 0 || (size_t)n >= result_size - written)
    return -1;
  written += (size_t)n;

  /* Add host */
  if (base->host_len + written >= result_size)
    return -1;
  memcpy (result + written, base->host, base->host_len);
  written += base->host_len;

  /* Add port if non-default */
  int default_port
      = base->is_secure ? CURL_HTTPS_DEFAULT_PORT : CURL_HTTP_DEFAULT_PORT;
  if (base->port > 0 && base->port != default_port)
    {
      n = snprintf (result + written, result_size - written, ":%d", base->port);
      if (n < 0 || (size_t)n >= result_size - written)
        return -1;
      written += (size_t)n;
    }

  /* Handle different relative URL forms */
  if (relative[0] == '/')
    {
      /* Absolute path */
      if (rel_len + written >= result_size)
        return -1;
      memcpy (result + written, relative, rel_len);
      written += rel_len;
    }
  else if (relative[0] == '?')
    {
      /* Query string only - use base path */
      if (base->path_len + written >= result_size)
        return -1;
      memcpy (result + written, base->path, base->path_len);
      written += base->path_len;

      if (rel_len + written >= result_size)
        return -1;
      memcpy (result + written, relative, rel_len);
      written += rel_len;
    }
  else if (relative[0] == '#')
    {
      /* Fragment only - use base path and query */
      if (base->path_len + written >= result_size)
        return -1;
      memcpy (result + written, base->path, base->path_len);
      written += base->path_len;

      if (base->query && base->query_len > 0)
        {
          if (QUERY_CHAR_LEN + base->query_len + written >= result_size)
            return -1;
          result[written++] = '?';
          memcpy (result + written, base->query, base->query_len);
          written += base->query_len;
        }

      if (rel_len + written >= result_size)
        return -1;
      memcpy (result + written, relative, rel_len);
      written += rel_len;
    }
  else
    {
      /* Relative path - need to merge with base path */
      /* Find the last slash in base path */
      const char *last_slash = NULL;
      if (base->path)
        {
          for (size_t i = base->path_len; i > 0; i--)
            {
              if (base->path[i - 1] == '/')
                {
                  last_slash = base->path + i - 1;
                  break;
                }
            }
        }

      if (last_slash)
        {
          /* Copy base path up to and including last slash */
          size_t prefix_len = (size_t)(last_slash - base->path) + 1;
          if (prefix_len + written >= result_size)
            return -1;
          memcpy (result + written, base->path, prefix_len);
          written += prefix_len;
        }
      else
        {
          /* No slash in base path, start from root */
          if (PATH_SEPARATOR_LEN + written >= result_size)
            return -1;
          result[written++] = '/';
        }

      /* Append relative path */
      if (rel_len + written >= result_size)
        return -1;
      memcpy (result + written, relative, rel_len);
      written += rel_len;
    }

  result[written] = '\0';
  return (ssize_t)written;
}

/* Internal helper used by other modules */
CurlError
curl_internal_parse_url (const char *url,
                         size_t len,
                         CurlParsedURL *result,
                         Arena_T arena)
{
  return Curl_parse_url (url, len, result, arena);
}

int
curl_urls_same_origin (const CurlParsedURL *a, const CurlParsedURL *b)
{
  if (!a || !b)
    return 0;

  /* Compare scheme (case-insensitive) */
  if (a->scheme_len != b->scheme_len)
    return 0;
  if (strncasecmp (a->scheme, b->scheme, a->scheme_len) != 0)
    return 0;

  /* Compare host (case-insensitive) */
  if (a->host_len != b->host_len)
    return 0;
  if (strncasecmp (a->host, b->host, a->host_len) != 0)
    return 0;

  /* Compare port */
  int port_a = Curl_url_get_port (a);
  int port_b = Curl_url_get_port (b);
  if (port_a != port_b)
    return 0;

  return 1;
}

void
curl_url_copy (CurlParsedURL *dst, const CurlParsedURL *src, Arena_T arena)
{
  if (!dst || !src || !arena)
    return;

  memset (dst, 0, sizeof (*dst));

  if (src->scheme)
    {
      dst->scheme = curl_arena_strdup (arena, src->scheme, src->scheme_len);
      dst->scheme_len = src->scheme_len;
    }

  if (src->userinfo)
    {
      dst->userinfo
          = curl_arena_strdup (arena, src->userinfo, src->userinfo_len);
      dst->userinfo_len = src->userinfo_len;
    }

  if (src->host)
    {
      dst->host = curl_arena_strdup (arena, src->host, src->host_len);
      dst->host_len = src->host_len;
    }

  dst->port = src->port;

  if (src->path)
    {
      dst->path = curl_arena_strdup (arena, src->path, src->path_len);
      dst->path_len = src->path_len;
    }

  if (src->query)
    {
      dst->query = curl_arena_strdup (arena, src->query, src->query_len);
      dst->query_len = src->query_len;
    }

  if (src->fragment)
    {
      dst->fragment
          = curl_arena_strdup (arena, src->fragment, src->fragment_len);
      dst->fragment_len = src->fragment_len;
    }

  dst->is_secure = src->is_secure;
}

static void
init_protocol_settings (CurlOptions *options)
{
  options->max_version = HTTP_VERSION_2;
  options->allow_http2_cleartext = 0;
}

static void
init_timeout_settings (CurlOptions *options)
{
  options->connect_timeout_ms = CURL_DEFAULT_CONNECT_TIMEOUT_MS;
  options->request_timeout_ms = CURL_DEFAULT_REQUEST_TIMEOUT_MS; /* No limit */
  options->dns_timeout_ms = CURL_DEFAULT_DNS_TIMEOUT_MS;
}

static void
init_redirect_settings (CurlOptions *options)
{
  options->follow_redirects = 1;
  options->max_redirects = CURL_DEFAULT_MAX_REDIRECTS;
}

static void
init_tls_settings (CurlOptions *options)
{
  options->tls_context = NULL;
  options->verify_ssl = 1;
}

static void
init_proxy_settings (CurlOptions *options)
{
  options->proxy_url = NULL;
}

static void
init_request_settings (CurlOptions *options)
{
  options->user_agent = "tetsuo-curl/1.0";
  options->accept_encoding = 1;
  options->auto_decompress = 1;
}

static_void
init_callback_settings (CurlOptions *options)
{
  options->write_callback = NULL;
  options->write_userdata = NULL;
  options->read_callback = NULL;
  options->read_userdata = NULL;
  options->progress_callback = NULL;
  options->progress_userdata = NULL;
  options->header_callback = NULL;
  options->header_userdata = NULL;
}

static void
init_auth_settings (CurlOptions *options)
{
  options->auth.type = CURL_AUTH_NONE;
  options->auth.username = NULL;
  options->auth.password = NULL;
  options->auth.token = NULL;
}

static void
init_cookie_settings (CurlOptions *options)
{
  options->cookie_file = NULL;
}

static void
init_retry_settings (CurlOptions *options)
{
  options->enable_retry = 0;
  options->max_retries = CURL_DEFAULT_MAX_RETRIES;
  options->retry_on_connection_error = 1;
  options->retry_on_timeout = 1;
  options->retry_on_5xx = 0;
}

static void
init_debug_settings (CurlOptions *options)
{
  options->verbose = 0;
}

void
Curl_options_defaults (CurlOptions *options)
{
  if (!options)
    return;

  memset (options, 0, sizeof (*options));

  init_protocol_settings (options);
  init_timeout_settings (options);
  init_redirect_settings (options);
  init_tls_settings (options);
  init_proxy_settings (options);
  init_request_settings (options);
  init_callback_settings (options);
  init_auth_settings (options);
  init_cookie_settings (options);
  init_retry_settings (options);
  init_debug_settings (options);
}
