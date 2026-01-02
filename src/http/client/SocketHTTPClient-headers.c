/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTPClient-headers.c
 * @brief Request header building for HTTP client
 *
 * Constructs HTTP request headers:
 * - Host header with port handling (RFC 7230)
 * - Accept-Encoding for compression
 * - User-Agent from config
 * - Cookie header from jar
 * - Authorization for Basic/Bearer auth
 * - Content-Length for bodies
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "http/SocketHTTP-private.h"
#include "http/SocketHTTPClient-private.h"

/* hostname_safe is now inline in SocketHTTPClient-private.h */

void
httpclient_headers_add_host (SocketHTTPClient_Request_T req)
{
  char host_header[HTTPCLIENT_HOST_HEADER_SIZE];

  if (SocketHTTP_Headers_has (req->headers, "Host"))
    return;

  /* Validate host length before formatting */
  size_t host_len = strlen (req->uri.host);
  bool is_https = (strcmp (req->uri.scheme, "https") == 0);
  size_t needed_len
      = host_len + (is_default_http_port (req->uri.port, is_https) ? 1 : 10);
  /* +1 NUL, +port digits */
  if (needed_len > sizeof (host_header) - 1)
    {
      /* Truncate or raise error; here log and skip */
      HTTPCLIENT_ERROR_MSG ("Host header too long, skipping");
      return;
    }

  /* SECURITY: Validate hostname for control characters (injection prevention)
   */
  if (!hostname_safe (req->uri.host, host_len))
    {
      HTTPCLIENT_ERROR_MSG ("Invalid characters in hostname");
      return;
    }

  if (is_default_http_port (req->uri.port, is_https))
    {
      snprintf (host_header, sizeof (host_header), "%s", req->uri.host);
    }
  else
    {
      snprintf (host_header,
                sizeof (host_header),
                "%s:%d",
                req->uri.host,
                req->uri.port);
    }
  SocketHTTP_Headers_add (req->headers, "Host", host_header);
}

void
httpclient_headers_add_accept_encoding (SocketHTTPClient_T client,
                                        SocketHTTPClient_Request_T req)
{
  char encoding[HTTPCLIENT_ACCEPT_ENCODING_SIZE] = "";
  size_t len = 0;

  if (!client->config.auto_decompress)
    return;
  if (SocketHTTP_Headers_has (req->headers, "Accept-Encoding"))
    return;

  if (client->config.accept_encoding & HTTPCLIENT_ENCODING_GZIP)
    len = (size_t)snprintf (encoding, sizeof (encoding), "gzip");

  if (client->config.accept_encoding & HTTPCLIENT_ENCODING_DEFLATE)
    {
      if (len > 0 && len < sizeof (encoding) - 1)
        len += (size_t)snprintf (
            encoding + len, sizeof (encoding) - len, ", deflate");
      else if (len == 0)
        len = (size_t)snprintf (encoding, sizeof (encoding), "deflate");
    }

  if (encoding[0])
    SocketHTTP_Headers_add (req->headers, "Accept-Encoding", encoding);
}

void
httpclient_headers_add_standard (SocketHTTPClient_T client,
                                 SocketHTTPClient_Request_T req)
{
  httpclient_headers_add_host (req);

  if (!SocketHTTP_Headers_has (req->headers, "User-Agent")
      && client->config.user_agent != NULL)
    {
      SocketHTTP_Headers_add (
          req->headers, "User-Agent", client->config.user_agent);
    }

  httpclient_headers_add_accept_encoding (client, req);
}

void
httpclient_headers_add_cookie (SocketHTTPClient_T client,
                               SocketHTTPClient_Request_T req)
{
  char cookie_header[HTTPCLIENT_COOKIE_HEADER_SIZE];

  if (client->cookie_jar == NULL)
    return;

  if (httpclient_cookies_for_request (client->cookie_jar,
                                      &req->uri,
                                      cookie_header,
                                      sizeof (cookie_header),
                                      client->config.enforce_samesite)
      > 0)
    {
      SocketHTTP_Headers_add (req->headers, "Cookie", cookie_header);
    }
}

void
httpclient_headers_add_initial_auth (SocketHTTPClient_T client,
                                     SocketHTTPClient_Request_T req)
{
  SocketHTTPClient_Auth *auth;
  char auth_header[HTTPCLIENT_AUTH_HEADER_SIZE];

  auth = httpclient_get_effective_auth (client, req);
  if (auth == NULL)
    return;

  if (auth->type == HTTP_AUTH_BASIC)
    {
      if (httpclient_auth_basic_header (
              auth->username, auth->password, auth_header, sizeof (auth_header))
          == 0)
        {
          SocketHTTP_Headers_add (req->headers, "Authorization", auth_header);
        }
    }
  else if (auth->type == HTTP_AUTH_BEARER && auth->token != NULL)
    {
      snprintf (auth_header, sizeof (auth_header), "Bearer %s", auth->token);
      SocketHTTP_Headers_add (req->headers, "Authorization", auth_header);
    }
}

void
httpclient_headers_add_content_length (SocketHTTPClient_Request_T req)
{
  char cl_header[HTTPCLIENT_CONTENT_LENGTH_SIZE];

  if (req->body == NULL || req->body_len == 0)
    return;

  snprintf (cl_header, sizeof (cl_header), "%zu", req->body_len);
  SocketHTTP_Headers_set (req->headers, "Content-Length", cl_header);
}

void
httpclient_headers_prepare_request (SocketHTTPClient_T client,
                                    SocketHTTPClient_Request_T req)
{
  httpclient_headers_add_standard (client, req);
  httpclient_headers_add_cookie (client, req);
  httpclient_headers_add_initial_auth (client, req);
  httpclient_headers_add_content_length (req);
}

void
httpclient_store_response_cookies (SocketHTTPClient_T client,
                                   SocketHTTPClient_Request_T req,
                                   SocketHTTPClient_Response *response)
{
  const char *set_cookies[HTTPCLIENT_MAX_SET_COOKIES];
  size_t cookie_count;
  size_t i;

  if (client->cookie_jar == NULL)
    return;

  cookie_count = SocketHTTP_Headers_get_all (
      response->headers, "Set-Cookie", set_cookies, HTTPCLIENT_MAX_SET_COOKIES);

  for (i = 0; i < cookie_count; i++)
    {
      SocketHTTPClient_Cookie cookie;
      if (httpclient_parse_set_cookie (set_cookies[i],
                                       strlen (set_cookies[i]),
                                       &req->uri,
                                       &cookie,
                                       response->arena)
          == 0)
        {
          SocketHTTPClient_CookieJar_set (client->cookie_jar, &cookie);
        }
    }
}
