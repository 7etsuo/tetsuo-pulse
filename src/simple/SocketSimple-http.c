/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketSimple-http.c
 * @brief HTTP implementation for Simple API.
 *
 * Wraps the SocketHTTPClient module for return-code-based API.
 */

#include "SocketSimple-internal.h"

#include "socket/SocketCommon.h"

#include <pthread.h>

/* ============================================================================
 * Constants
 * ============================================================================
 */

#define SOCKET_SIMPLE_DEFAULT_MAX_REDIRECTS 5
#define SOCKET_SIMPLE_MAX_HEADER_NAME_LEN 256
#define SOCKET_SIMPLE_DEFAULT_CONNECT_TIMEOUT_MS 30000
#define SOCKET_SIMPLE_DEFAULT_REQUEST_TIMEOUT_MS 60000

/* Performance: Compile-time string length for header lookups */
#define STRLEN_LIT(s) (sizeof (s) - 1)

/* ============================================================================
 * Shared Global HTTP Client (Lazy Initialization)
 * ============================================================================
 */

static SocketHTTPClient_T g_http_client = NULL;
static pthread_once_t g_http_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_http_mutex = PTHREAD_MUTEX_INITIALIZER;

static void
init_global_http_client (void)
{
  SocketHTTPClient_Config config;

  /* Use HTTP/1.1 only for Simple API global client.
   * HTTP/2 requires more complex async processing that doesn't fit
   * the simple blocking API model well. Users who need HTTP/2 should
   * use the full SocketHTTPClient API with Socket_simple_http_new_ex(). */
  SocketHTTPClient_config_defaults (&config);
  config.max_version = HTTP_VERSION_1_1;

  TRY
  {
    g_http_client = SocketHTTPClient_new (&config);
  }
  EXCEPT (SocketHTTPClient_Failed)
  {
    g_http_client = NULL;
  }
  END_TRY;
}

static SocketHTTPClient_T
get_global_http_client (void)
{
  pthread_once (&g_http_once, init_global_http_client);
  return g_http_client;
}

/* ============================================================================
 * HTTP Options Init
 * ============================================================================
 */

void
Socket_simple_http_options_init (SocketSimple_HTTPOptions *opts)
{
  if (!opts)
    return;
  memset (opts, 0, sizeof (*opts));
  opts->connect_timeout_ms = SOCKET_SIMPLE_DEFAULT_CONNECT_TIMEOUT_MS;
  opts->request_timeout_ms = SOCKET_SIMPLE_DEFAULT_REQUEST_TIMEOUT_MS;
  opts->max_redirects = SOCKET_SIMPLE_DEFAULT_MAX_REDIRECTS;
  opts->verify_ssl = 1;
}

/* ============================================================================
 * Response Conversion Helper
 * ============================================================================
 */

static int
convert_response (const SocketHTTPClient_Response *src,
                  SocketSimple_HTTPResponse *dst)
{
  const char *ct;
  const char *loc;

  if (!dst)
    return -1;

  memset (dst, 0, sizeof (*dst));
  dst->status_code = src->status_code;

  /* Copy body */
  if (src->body && src->body_len > 0)
    {
      /* Check for integer overflow before malloc */
      if (src->body_len > SIZE_MAX - 1)
        {
          simple_set_error (SOCKET_SIMPLE_ERR_MEMORY,
                            "Response body too large");
          return -1;
        }
      dst->body = malloc (src->body_len + 1);
      if (!dst->body)
        {
          simple_set_error (SOCKET_SIMPLE_ERR_MEMORY,
                            "Memory allocation failed");
          return -1;
        }
      memcpy (dst->body, src->body, src->body_len);
      dst->body[src->body_len] = '\0';
      dst->body_len = src->body_len;
    }

  /* Extract Content-Type header */
  ct = SocketHTTP_Headers_get_n (
      src->headers, "Content-Type", STRLEN_LIT ("Content-Type"));
  if (ct)
    {
      dst->content_type = strdup (ct);
      if (!dst->content_type)
        {
          free (dst->body);
          simple_set_error (SOCKET_SIMPLE_ERR_MEMORY,
                            "Failed to copy Content-Type header");
          return -1;
        }
    }

  /* Extract Location header */
  loc = SocketHTTP_Headers_get_n (
      src->headers, "Location", STRLEN_LIT ("Location"));
  if (loc)
    {
      dst->location = strdup (loc);
      if (!dst->location)
        {
          free (dst->body);
          free (dst->content_type);
          simple_set_error (SOCKET_SIMPLE_ERR_MEMORY,
                            "Failed to copy Location header");
          return -1;
        }
    }

  return 0;
}

/* ============================================================================
 * Error Mapping Helper
 * ============================================================================
 */

static void
set_http_error_from_exception (void)
{
  /* Map the exception to a simple error code based on errno */
  int err = Socket_geterrno ();
  if (Socket_error_is_retryable (err) && (err == ETIMEDOUT || err == EAGAIN))
    {
      simple_set_error (SOCKET_SIMPLE_ERR_TIMEOUT, "HTTP request timed out");
    }
  else
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP request failed");
    }
}

/* ============================================================================
 * Exception Handling Macros
 * ============================================================================
 */

/**
 * @brief Common exception handling for HTTP client operations.
 *
 * This macro handles the standard set of exceptions thrown by
 * SocketHTTPClient operations and maps them to Simple API error codes.
 *
 * @param exception_var Name of volatile int variable to set on exception
 */
#define HANDLE_HTTP_EXCEPTIONS(exception_var)                               \
  EXCEPT (SocketHTTPClient_Timeout)                                         \
  {                                                                         \
    simple_set_error (SOCKET_SIMPLE_ERR_TIMEOUT, "HTTP request timed out"); \
    exception_var = 1;                                                      \
  }                                                                         \
  EXCEPT (SocketHTTPClient_DNSFailed)                                       \
  {                                                                         \
    simple_set_error (SOCKET_SIMPLE_ERR_DNS, "DNS resolution failed");      \
    exception_var = 1;                                                      \
  }                                                                         \
  EXCEPT (SocketHTTPClient_ConnectFailed)                                   \
  {                                                                         \
    simple_set_error (SOCKET_SIMPLE_ERR_CONNECT, "Connection failed");      \
    exception_var = 1;                                                      \
  }                                                                         \
  EXCEPT (SocketHTTPClient_TLSFailed)                                       \
  {                                                                         \
    simple_set_error (SOCKET_SIMPLE_ERR_TLS, "TLS error");                  \
    exception_var = 1;                                                      \
  }                                                                         \
  EXCEPT (SocketHTTPClient_ProtocolError)                                   \
  {                                                                         \
    simple_set_error (SOCKET_SIMPLE_ERR_HTTP_PARSE, "HTTP protocol error"); \
    exception_var = 1;                                                      \
  }                                                                         \
  EXCEPT (SocketHTTPClient_TooManyRedirects)                                \
  {                                                                         \
    simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "Too many redirects");        \
    exception_var = 1;                                                      \
  }                                                                         \
  EXCEPT (SocketHTTPClient_Failed)                                          \
  {                                                                         \
    set_http_error_from_exception ();                                       \
    exception_var = 1;                                                      \
  }

/**
 * @brief Minimal exception handling for basic HTTP operations.
 *
 * This macro provides a subset of exception handlers for simpler operations
 * that only need to handle timeout and general failure cases.
 *
 * @param exception_var Name of volatile int variable to set on exception
 */
#define HANDLE_HTTP_EXCEPTIONS_MINIMAL(exception_var)                       \
  EXCEPT (SocketHTTPClient_Timeout)                                         \
  {                                                                         \
    simple_set_error (SOCKET_SIMPLE_ERR_TIMEOUT, "HTTP request timed out"); \
    exception_var = 1;                                                      \
  }                                                                         \
  EXCEPT (SocketHTTPClient_Failed)                                          \
  {                                                                         \
    set_http_error_from_exception ();                                       \
    exception_var = 1;                                                      \
  }

/* ============================================================================
 * Header Parsing Helper
 * ============================================================================
 */

static void
add_custom_headers (SocketHTTPClient_Request_T req, const char **headers)
{
  if (!headers)
    return;

  for (const char **h = headers; *h != NULL; h++)
    {
      const char *colon = strchr (*h, ':');
      if (colon)
        {
          size_t name_len = (size_t)(colon - *h);
          if (name_len > 0 && name_len < SOCKET_SIMPLE_MAX_HEADER_NAME_LEN)
            {
              char name[SOCKET_SIMPLE_MAX_HEADER_NAME_LEN];
              memcpy (name, *h, name_len);
              name[name_len] = '\0';
              const char *value = colon + 1;
              while (*value == ' ')
                value++;
              SocketHTTPClient_Request_header (req, name, value);
            }
        }
    }
}

/* ============================================================================
 * One-liner HTTP Functions
 * ============================================================================
 */

int
Socket_simple_http_get (const char *url, SocketSimple_HTTPResponse *response)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_Response lib_response;
  volatile int ret = -1;
  volatile int exception_occurred = 0;

  Socket_simple_clear_error ();

  if (!url || !response)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  client = get_global_http_client ();
  if (!client)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP client not available");
      return -1;
    }

  memset (&lib_response, 0, sizeof (lib_response));

  pthread_mutex_lock (&g_http_mutex);
  TRY
  {
    ret = SocketHTTPClient_get (client, url, &lib_response);
  }
  HANDLE_HTTP_EXCEPTIONS (exception_occurred)
  FINALLY
  {
    pthread_mutex_unlock (&g_http_mutex);
  }
  END_TRY;

  if (exception_occurred)
    return -1;

  if (ret != 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP request failed");
      return -1;
    }

  ret = convert_response (&lib_response, response);
  SocketHTTPClient_Response_free (&lib_response);

  return ret;
}

int
Socket_simple_http_get_ex (const char *url,
                           const char **headers,
                           SocketSimple_HTTPResponse *response)
{
  SocketHTTPClient_T client;
  volatile SocketHTTPClient_Request_T req = NULL;
  SocketHTTPClient_Response lib_response;
  volatile int ret = -1;
  volatile int exception_occurred = 0;

  Socket_simple_clear_error ();

  if (!url || !response)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  client = get_global_http_client ();
  if (!client)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP client not available");
      return -1;
    }

  memset (&lib_response, 0, sizeof (lib_response));

  pthread_mutex_lock (&g_http_mutex);
  TRY
  {
    req = SocketHTTPClient_Request_new (client, HTTP_METHOD_GET, url);
    add_custom_headers ((SocketHTTPClient_Request_T)req, headers);
    ret = SocketHTTPClient_Request_execute ((SocketHTTPClient_Request_T)req,
                                            &lib_response);
  }
  HANDLE_HTTP_EXCEPTIONS_MINIMAL (exception_occurred)
  FINALLY
  {
    if (req)
      SocketHTTPClient_Request_free ((SocketHTTPClient_Request_T *)&req);
    pthread_mutex_unlock (&g_http_mutex);
  }
  END_TRY;

  if (exception_occurred)
    return -1;

  if (ret != 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP request failed");
      return -1;
    }

  ret = convert_response (&lib_response, response);
  SocketHTTPClient_Response_free (&lib_response);

  return ret;
}

int
Socket_simple_http_post (const char *url,
                         const char *content_type,
                         const void *body,
                         size_t body_len,
                         SocketSimple_HTTPResponse *response)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_Response lib_response;
  volatile int ret = -1;
  volatile int exception_occurred = 0;

  Socket_simple_clear_error ();

  if (!url || !response)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  client = get_global_http_client ();
  if (!client)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP client not available");
      return -1;
    }

  memset (&lib_response, 0, sizeof (lib_response));

  pthread_mutex_lock (&g_http_mutex);
  TRY
  {
    ret = SocketHTTPClient_post (
        client, url, content_type, body, body_len, &lib_response);
  }
  HANDLE_HTTP_EXCEPTIONS_MINIMAL (exception_occurred)
  FINALLY
  {
    pthread_mutex_unlock (&g_http_mutex);
  }
  END_TRY;

  if (exception_occurred)
    return -1;

  if (ret != 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP request failed");
      return -1;
    }

  ret = convert_response (&lib_response, response);
  SocketHTTPClient_Response_free (&lib_response);

  return ret;
}

int
Socket_simple_http_put (const char *url,
                        const char *content_type,
                        const void *body,
                        size_t body_len,
                        SocketSimple_HTTPResponse *response)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_Response lib_response;
  volatile int ret = -1;
  volatile int exception_occurred = 0;

  Socket_simple_clear_error ();

  if (!url || !response)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  client = get_global_http_client ();
  if (!client)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP client not available");
      return -1;
    }

  memset (&lib_response, 0, sizeof (lib_response));

  pthread_mutex_lock (&g_http_mutex);
  TRY
  {
    ret = SocketHTTPClient_put (
        client, url, content_type, body, body_len, &lib_response);
  }
  HANDLE_HTTP_EXCEPTIONS_MINIMAL (exception_occurred)
  FINALLY
  {
    pthread_mutex_unlock (&g_http_mutex);
  }
  END_TRY;

  if (exception_occurred)
    return -1;

  if (ret != 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP request failed");
      return -1;
    }

  ret = convert_response (&lib_response, response);
  SocketHTTPClient_Response_free (&lib_response);

  return ret;
}

int
Socket_simple_http_delete (const char *url, SocketSimple_HTTPResponse *response)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_Response lib_response;
  volatile int ret = -1;
  volatile int exception_occurred = 0;

  Socket_simple_clear_error ();

  if (!url || !response)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  client = get_global_http_client ();
  if (!client)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP client not available");
      return -1;
    }

  memset (&lib_response, 0, sizeof (lib_response));

  pthread_mutex_lock (&g_http_mutex);
  TRY
  {
    ret = SocketHTTPClient_delete (client, url, &lib_response);
  }
  HANDLE_HTTP_EXCEPTIONS_MINIMAL (exception_occurred)
  FINALLY
  {
    pthread_mutex_unlock (&g_http_mutex);
  }
  END_TRY;

  if (exception_occurred)
    return -1;

  if (ret != 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP request failed");
      return -1;
    }

  ret = convert_response (&lib_response, response);
  SocketHTTPClient_Response_free (&lib_response);

  return ret;
}

int
Socket_simple_http_head (const char *url, SocketSimple_HTTPResponse *response)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_Response lib_response;
  volatile int ret = -1;
  volatile int exception_occurred = 0;

  Socket_simple_clear_error ();

  if (!url || !response)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  client = get_global_http_client ();
  if (!client)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP client not available");
      return -1;
    }

  memset (&lib_response, 0, sizeof (lib_response));

  pthread_mutex_lock (&g_http_mutex);
  TRY
  {
    ret = SocketHTTPClient_head (client, url, &lib_response);
  }
  HANDLE_HTTP_EXCEPTIONS_MINIMAL (exception_occurred)
  FINALLY
  {
    pthread_mutex_unlock (&g_http_mutex);
  }
  END_TRY;

  if (exception_occurred)
    return -1;

  if (ret != 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP request failed");
      return -1;
    }

  ret = convert_response (&lib_response, response);
  SocketHTTPClient_Response_free (&lib_response);

  return ret;
}

int
Socket_simple_http_patch (const char *url,
                          const char *content_type,
                          const void *body,
                          size_t body_len,
                          SocketSimple_HTTPResponse *response)
{
  SocketHTTPClient_T client;
  volatile SocketHTTPClient_Request_T req = NULL;
  SocketHTTPClient_Response lib_response;
  volatile int ret = -1;
  volatile int exception_occurred = 0;

  Socket_simple_clear_error ();

  if (!url || !response)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  client = get_global_http_client ();
  if (!client)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP client not available");
      return -1;
    }

  memset (&lib_response, 0, sizeof (lib_response));

  pthread_mutex_lock (&g_http_mutex);
  TRY
  {
    req = SocketHTTPClient_Request_new (client, HTTP_METHOD_PATCH, url);
    if (content_type)
      SocketHTTPClient_Request_header (
          (SocketHTTPClient_Request_T)req, "Content-Type", content_type);
    if (body && body_len > 0)
      SocketHTTPClient_Request_body (
          (SocketHTTPClient_Request_T)req, body, body_len);
    ret = SocketHTTPClient_Request_execute ((SocketHTTPClient_Request_T)req,
                                            &lib_response);
  }
  HANDLE_HTTP_EXCEPTIONS_MINIMAL (exception_occurred)
  FINALLY
  {
    if (req)
      SocketHTTPClient_Request_free ((SocketHTTPClient_Request_T *)&req);
    pthread_mutex_unlock (&g_http_mutex);
  }
  END_TRY;

  if (exception_occurred)
    return -1;

  if (ret != 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP request failed");
      return -1;
    }

  ret = convert_response (&lib_response, response);
  SocketHTTPClient_Response_free (&lib_response);

  return ret;
}

int
Socket_simple_http_options (const char *url,
                            SocketSimple_HTTPResponse *response)
{
  SocketHTTPClient_T client;
  volatile SocketHTTPClient_Request_T req = NULL;
  SocketHTTPClient_Response lib_response;
  volatile int ret = -1;
  volatile int exception_occurred = 0;

  Socket_simple_clear_error ();

  if (!url || !response)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  client = get_global_http_client ();
  if (!client)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP client not available");
      return -1;
    }

  memset (&lib_response, 0, sizeof (lib_response));

  pthread_mutex_lock (&g_http_mutex);
  TRY
  {
    req = SocketHTTPClient_Request_new (client, HTTP_METHOD_OPTIONS, url);
    ret = SocketHTTPClient_Request_execute ((SocketHTTPClient_Request_T)req,
                                            &lib_response);
  }
  HANDLE_HTTP_EXCEPTIONS_MINIMAL (exception_occurred)
  FINALLY
  {
    if (req)
      SocketHTTPClient_Request_free ((SocketHTTPClient_Request_T *)&req);
    pthread_mutex_unlock (&g_http_mutex);
  }
  END_TRY;

  if (exception_occurred)
    return -1;

  if (ret != 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP request failed");
      return -1;
    }

  ret = convert_response (&lib_response, response);
  SocketHTTPClient_Response_free (&lib_response);

  return ret;
}

/* ============================================================================
 * Extended Functions with Custom Headers
 * ============================================================================
 */

int
Socket_simple_http_post_ex (const char *url,
                            const char **headers,
                            const char *content_type,
                            const void *body,
                            size_t body_len,
                            SocketSimple_HTTPResponse *response)
{
  SocketHTTPClient_T client;
  volatile SocketHTTPClient_Request_T req = NULL;
  SocketHTTPClient_Response lib_response;
  volatile int ret = -1;
  volatile int exception_occurred = 0;

  Socket_simple_clear_error ();

  if (!url || !response)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  client = get_global_http_client ();
  if (!client)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP client not available");
      return -1;
    }

  memset (&lib_response, 0, sizeof (lib_response));

  pthread_mutex_lock (&g_http_mutex);
  TRY
  {
    req = SocketHTTPClient_Request_new (client, HTTP_METHOD_POST, url);
    add_custom_headers ((SocketHTTPClient_Request_T)req, headers);
    if (content_type)
      SocketHTTPClient_Request_header (
          (SocketHTTPClient_Request_T)req, "Content-Type", content_type);
    if (body && body_len > 0)
      SocketHTTPClient_Request_body (
          (SocketHTTPClient_Request_T)req, body, body_len);
    ret = SocketHTTPClient_Request_execute ((SocketHTTPClient_Request_T)req,
                                            &lib_response);
  }
  HANDLE_HTTP_EXCEPTIONS_MINIMAL (exception_occurred)
  FINALLY
  {
    if (req)
      SocketHTTPClient_Request_free ((SocketHTTPClient_Request_T *)&req);
    pthread_mutex_unlock (&g_http_mutex);
  }
  END_TRY;

  if (exception_occurred)
    return -1;

  if (ret != 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP request failed");
      return -1;
    }

  ret = convert_response (&lib_response, response);
  SocketHTTPClient_Response_free (&lib_response);

  return ret;
}

int
Socket_simple_http_put_ex (const char *url,
                           const char **headers,
                           const char *content_type,
                           const void *body,
                           size_t body_len,
                           SocketSimple_HTTPResponse *response)
{
  SocketHTTPClient_T client;
  volatile SocketHTTPClient_Request_T req = NULL;
  SocketHTTPClient_Response lib_response;
  volatile int ret = -1;
  volatile int exception_occurred = 0;

  Socket_simple_clear_error ();

  if (!url || !response)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  client = get_global_http_client ();
  if (!client)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP client not available");
      return -1;
    }

  memset (&lib_response, 0, sizeof (lib_response));

  pthread_mutex_lock (&g_http_mutex);
  TRY
  {
    req = SocketHTTPClient_Request_new (client, HTTP_METHOD_PUT, url);
    add_custom_headers ((SocketHTTPClient_Request_T)req, headers);
    if (content_type)
      SocketHTTPClient_Request_header (
          (SocketHTTPClient_Request_T)req, "Content-Type", content_type);
    if (body && body_len > 0)
      SocketHTTPClient_Request_body (
          (SocketHTTPClient_Request_T)req, body, body_len);
    ret = SocketHTTPClient_Request_execute ((SocketHTTPClient_Request_T)req,
                                            &lib_response);
  }
  HANDLE_HTTP_EXCEPTIONS_MINIMAL (exception_occurred)
  FINALLY
  {
    if (req)
      SocketHTTPClient_Request_free ((SocketHTTPClient_Request_T *)&req);
    pthread_mutex_unlock (&g_http_mutex);
  }
  END_TRY;

  if (exception_occurred)
    return -1;

  if (ret != 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP request failed");
      return -1;
    }

  ret = convert_response (&lib_response, response);
  SocketHTTPClient_Response_free (&lib_response);

  return ret;
}

int
Socket_simple_http_delete_ex (const char *url,
                              const char **headers,
                              SocketSimple_HTTPResponse *response)
{
  SocketHTTPClient_T client;
  volatile SocketHTTPClient_Request_T req = NULL;
  SocketHTTPClient_Response lib_response;
  volatile int ret = -1;
  volatile int exception_occurred = 0;

  Socket_simple_clear_error ();

  if (!url || !response)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  client = get_global_http_client ();
  if (!client)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP client not available");
      return -1;
    }

  memset (&lib_response, 0, sizeof (lib_response));

  pthread_mutex_lock (&g_http_mutex);
  TRY
  {
    req = SocketHTTPClient_Request_new (client, HTTP_METHOD_DELETE, url);
    add_custom_headers ((SocketHTTPClient_Request_T)req, headers);
    ret = SocketHTTPClient_Request_execute ((SocketHTTPClient_Request_T)req,
                                            &lib_response);
  }
  HANDLE_HTTP_EXCEPTIONS_MINIMAL (exception_occurred)
  FINALLY
  {
    if (req)
      SocketHTTPClient_Request_free ((SocketHTTPClient_Request_T *)&req);
    pthread_mutex_unlock (&g_http_mutex);
  }
  END_TRY;

  if (exception_occurred)
    return -1;

  if (ret != 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP request failed");
      return -1;
    }

  ret = convert_response (&lib_response, response);
  SocketHTTPClient_Response_free (&lib_response);

  return ret;
}

int
Socket_simple_http_head_ex (const char *url,
                            const char **headers,
                            SocketSimple_HTTPResponse *response)
{
  SocketHTTPClient_T client;
  volatile SocketHTTPClient_Request_T req = NULL;
  SocketHTTPClient_Response lib_response;
  volatile int ret = -1;
  volatile int exception_occurred = 0;

  Socket_simple_clear_error ();

  if (!url || !response)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  client = get_global_http_client ();
  if (!client)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP client not available");
      return -1;
    }

  memset (&lib_response, 0, sizeof (lib_response));

  pthread_mutex_lock (&g_http_mutex);
  TRY
  {
    req = SocketHTTPClient_Request_new (client, HTTP_METHOD_HEAD, url);
    add_custom_headers ((SocketHTTPClient_Request_T)req, headers);
    ret = SocketHTTPClient_Request_execute ((SocketHTTPClient_Request_T)req,
                                            &lib_response);
  }
  HANDLE_HTTP_EXCEPTIONS_MINIMAL (exception_occurred)
  FINALLY
  {
    if (req)
      SocketHTTPClient_Request_free ((SocketHTTPClient_Request_T *)&req);
    pthread_mutex_unlock (&g_http_mutex);
  }
  END_TRY;

  if (exception_occurred)
    return -1;

  if (ret != 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP request failed");
      return -1;
    }

  ret = convert_response (&lib_response, response);
  SocketHTTPClient_Response_free (&lib_response);

  return ret;
}

int
Socket_simple_http_patch_ex (const char *url,
                             const char **headers,
                             const char *content_type,
                             const void *body,
                             size_t body_len,
                             SocketSimple_HTTPResponse *response)
{
  SocketHTTPClient_T client;
  volatile SocketHTTPClient_Request_T req = NULL;
  SocketHTTPClient_Response lib_response;
  volatile int ret = -1;
  volatile int exception_occurred = 0;

  Socket_simple_clear_error ();

  if (!url || !response)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  client = get_global_http_client ();
  if (!client)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP client not available");
      return -1;
    }

  memset (&lib_response, 0, sizeof (lib_response));

  pthread_mutex_lock (&g_http_mutex);
  TRY
  {
    req = SocketHTTPClient_Request_new (client, HTTP_METHOD_PATCH, url);
    add_custom_headers ((SocketHTTPClient_Request_T)req, headers);
    if (content_type)
      SocketHTTPClient_Request_header (
          (SocketHTTPClient_Request_T)req, "Content-Type", content_type);
    if (body && body_len > 0)
      SocketHTTPClient_Request_body (
          (SocketHTTPClient_Request_T)req, body, body_len);
    ret = SocketHTTPClient_Request_execute ((SocketHTTPClient_Request_T)req,
                                            &lib_response);
  }
  HANDLE_HTTP_EXCEPTIONS_MINIMAL (exception_occurred)
  FINALLY
  {
    if (req)
      SocketHTTPClient_Request_free ((SocketHTTPClient_Request_T *)&req);
    pthread_mutex_unlock (&g_http_mutex);
  }
  END_TRY;

  if (exception_occurred)
    return -1;

  if (ret != 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP request failed");
      return -1;
    }

  ret = convert_response (&lib_response, response);
  SocketHTTPClient_Response_free (&lib_response);

  return ret;
}

int
Socket_simple_http_options_ex (const char *url,
                               const char **headers,
                               SocketSimple_HTTPResponse *response)
{
  SocketHTTPClient_T client;
  volatile SocketHTTPClient_Request_T req = NULL;
  SocketHTTPClient_Response lib_response;
  volatile int ret = -1;
  volatile int exception_occurred = 0;

  Socket_simple_clear_error ();

  if (!url || !response)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  client = get_global_http_client ();
  if (!client)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP client not available");
      return -1;
    }

  memset (&lib_response, 0, sizeof (lib_response));

  pthread_mutex_lock (&g_http_mutex);
  TRY
  {
    req = SocketHTTPClient_Request_new (client, HTTP_METHOD_OPTIONS, url);
    add_custom_headers ((SocketHTTPClient_Request_T)req, headers);
    ret = SocketHTTPClient_Request_execute ((SocketHTTPClient_Request_T)req,
                                            &lib_response);
  }
  HANDLE_HTTP_EXCEPTIONS_MINIMAL (exception_occurred)
  FINALLY
  {
    if (req)
      SocketHTTPClient_Request_free ((SocketHTTPClient_Request_T *)&req);
    pthread_mutex_unlock (&g_http_mutex);
  }
  END_TRY;

  if (exception_occurred)
    return -1;

  if (ret != 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP request failed");
      return -1;
    }

  ret = convert_response (&lib_response, response);
  SocketHTTPClient_Response_free (&lib_response);

  return ret;
}

/* ============================================================================
 * Generic Request Function
 * ============================================================================
 */

static SocketHTTP_Method
simple_method_to_http_method (SocketSimple_HTTPMethod method)
{
  switch (method)
    {
    case SIMPLE_HTTP_GET:
      return HTTP_METHOD_GET;
    case SIMPLE_HTTP_POST:
      return HTTP_METHOD_POST;
    case SIMPLE_HTTP_PUT:
      return HTTP_METHOD_PUT;
    case SIMPLE_HTTP_DELETE:
      return HTTP_METHOD_DELETE;
    case SIMPLE_HTTP_HEAD:
      return HTTP_METHOD_HEAD;
    case SIMPLE_HTTP_PATCH:
      return HTTP_METHOD_PATCH;
    case SIMPLE_HTTP_OPTIONS:
      return HTTP_METHOD_OPTIONS;
    default:
      return HTTP_METHOD_GET;
    }
}

/**
 * @brief Build and execute an HTTP request with exception handling.
 *
 * This helper encapsulates the request building, header addition, body
 * attachment, and execution logic with comprehensive exception handling.
 *
 * @param client HTTP client instance
 * @param method HTTP method
 * @param url Request URL
 * @param headers Optional custom headers (NULL-terminated array)
 * @param body Optional request body
 * @param body_len Length of request body
 * @param lib_response Output response structure
 * @return 0 on success, -1 on failure (error already set)
 */
static int
build_and_execute_request (SocketHTTPClient_T client,
                           SocketHTTP_Method method,
                           const char *url,
                           const char **headers,
                           const void *body,
                           size_t body_len,
                           SocketHTTPClient_Response *lib_response)
{
  volatile SocketHTTPClient_Request_T req = NULL;
  volatile int ret = -1;
  volatile int exception_occurred = 0;

  TRY
  {
    req = SocketHTTPClient_Request_new (client, method, url);
    add_custom_headers ((SocketHTTPClient_Request_T)req, headers);
    if (body && body_len > 0)
      SocketHTTPClient_Request_body (
          (SocketHTTPClient_Request_T)req, body, body_len);
    ret = SocketHTTPClient_Request_execute ((SocketHTTPClient_Request_T)req,
                                            lib_response);
  }
  EXCEPT (SocketHTTPClient_Timeout)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_TIMEOUT, "HTTP request timed out");
    exception_occurred = 1;
  }
  EXCEPT (SocketHTTPClient_DNSFailed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_DNS, "DNS resolution failed");
    exception_occurred = 1;
  }
  EXCEPT (SocketHTTPClient_ConnectFailed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_CONNECT, "Connection failed");
    exception_occurred = 1;
  }
  EXCEPT (SocketHTTPClient_TLSFailed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_TLS, "TLS error");
    exception_occurred = 1;
  }
  EXCEPT (SocketHTTPClient_Failed)
  {
    set_http_error_from_exception ();
    exception_occurred = 1;
  }
  EXCEPT (Socket_Closed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_CONNECT, "Connection closed by peer");
    exception_occurred = 1;
  }
  EXCEPT (Socket_Failed)
  {
    set_http_error_from_exception ();
    exception_occurred = 1;
  }
  FINALLY
  {
    if (req)
      SocketHTTPClient_Request_free ((SocketHTTPClient_Request_T *)&req);
  }
  END_TRY;

  if (exception_occurred)
    return -1;

  if (ret != 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP request failed");
      return -1;
    }

  return 0;
}

int
Socket_simple_http_request (SocketSimple_HTTPMethod method,
                            const char *url,
                            const char **headers,
                            const void *body,
                            size_t body_len,
                            const SocketSimple_HTTPOptions *opts,
                            SocketSimple_HTTPResponse *response)
{
  SocketSimple_HTTP_T client = NULL;
  SocketHTTPClient_Response lib_response;
  int ret;

  Socket_simple_clear_error ();

  if (!url || !response)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  /* Create client with options if provided, otherwise use defaults */
  client = Socket_simple_http_new_ex (opts);
  if (!client)
    return -1; /* Error already set by new_ex */

  memset (&lib_response, 0, sizeof (lib_response));

  /* Build and execute request with exception handling */
  ret = build_and_execute_request (client->client,
                                   simple_method_to_http_method (method),
                                   url,
                                   headers,
                                   body,
                                   body_len,
                                   &lib_response);

  if (ret != 0)
    {
      Socket_simple_http_free (&client);
      return -1;
    }

  /* Convert response and cleanup */
  ret = convert_response (&lib_response, response);
  SocketHTTPClient_Response_free (&lib_response);
  Socket_simple_http_free (&client);

  return ret;
}

/* ============================================================================
 * JSON Convenience
 * ============================================================================
 */

int
Socket_simple_http_get_json (const char *url, char **json_out, size_t *json_len)
{
  SocketHTTPClient_T client;
  volatile int status = -1;
  volatile int exception_occurred = 0;

  Socket_simple_clear_error ();

  if (!url || !json_out || !json_len)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  *json_out = NULL;
  *json_len = 0;

  client = get_global_http_client ();
  if (!client)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP client not available");
      return -1;
    }

  pthread_mutex_lock (&g_http_mutex);
  TRY
  {
    status = SocketHTTPClient_json_get (client, url, json_out, json_len);
  }
  HANDLE_HTTP_EXCEPTIONS_MINIMAL (exception_occurred)
  FINALLY
  {
    pthread_mutex_unlock (&g_http_mutex);
  }
  END_TRY;

  if (exception_occurred)
    return -1;

  return status;
}

int
Socket_simple_http_post_json (const char *url,
                              const char *json_body,
                              char **json_out,
                              size_t *json_len)
{
  SocketHTTPClient_T client;
  volatile int status = -1;
  volatile int exception_occurred = 0;

  Socket_simple_clear_error ();

  if (!url || !json_body || !json_out || !json_len)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  *json_out = NULL;
  *json_len = 0;

  client = get_global_http_client ();
  if (!client)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP client not available");
      return -1;
    }

  pthread_mutex_lock (&g_http_mutex);
  TRY
  {
    status = SocketHTTPClient_json_post (
        client, url, json_body, json_out, json_len);
  }
  HANDLE_HTTP_EXCEPTIONS_MINIMAL (exception_occurred)
  FINALLY
  {
    pthread_mutex_unlock (&g_http_mutex);
  }
  END_TRY;

  if (exception_occurred)
    return -1;

  return status;
}

int
Socket_simple_http_put_json (const char *url,
                             const char *json_body,
                             char **json_out,
                             size_t *json_len)
{
  SocketHTTPClient_T client;
  volatile SocketHTTPClient_Request_T req = NULL;
  SocketHTTPClient_Response lib_response;
  volatile int ret = -1;
  volatile int exception_occurred = 0;
  int status;

  Socket_simple_clear_error ();

  if (!url || !json_body || !json_out || !json_len)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  *json_out = NULL;
  *json_len = 0;

  client = get_global_http_client ();
  if (!client)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP client not available");
      return -1;
    }

  memset (&lib_response, 0, sizeof (lib_response));

  pthread_mutex_lock (&g_http_mutex);
  TRY
  {
    req = SocketHTTPClient_Request_new (client, HTTP_METHOD_PUT, url);
    SocketHTTPClient_Request_header (
        (SocketHTTPClient_Request_T)req, "Content-Type", "application/json");
    SocketHTTPClient_Request_header (
        (SocketHTTPClient_Request_T)req, "Accept", "application/json");
    SocketHTTPClient_Request_body (
        (SocketHTTPClient_Request_T)req, json_body, strlen (json_body));
    ret = SocketHTTPClient_Request_execute ((SocketHTTPClient_Request_T)req,
                                            &lib_response);
  }
  HANDLE_HTTP_EXCEPTIONS_MINIMAL (exception_occurred)
  FINALLY
  {
    if (req)
      SocketHTTPClient_Request_free ((SocketHTTPClient_Request_T *)&req);
    pthread_mutex_unlock (&g_http_mutex);
  }
  END_TRY;

  if (exception_occurred)
    return -1;

  if (ret != 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP request failed");
      return -1;
    }

  status = lib_response.status_code;

  /* Copy JSON body */
  if (lib_response.body && lib_response.body_len > 0)
    {
      /* Check for integer overflow before malloc */
      if (lib_response.body_len > SIZE_MAX - 1)
        {
          simple_set_error (SOCKET_SIMPLE_ERR_MEMORY,
                            "Response body too large");
          SocketHTTPClient_Response_free (&lib_response);
          return -1;
        }
      *json_out = malloc (lib_response.body_len + 1);
      if (!*json_out)
        {
          simple_set_error (SOCKET_SIMPLE_ERR_MEMORY,
                            "Failed to allocate response buffer");
          SocketHTTPClient_Response_free (&lib_response);
          return -1;
        }
      memcpy (*json_out, lib_response.body, lib_response.body_len);
      (*json_out)[lib_response.body_len] = '\0';
      *json_len = lib_response.body_len;
    }

  SocketHTTPClient_Response_free (&lib_response);
  return status;
}

/* ============================================================================
 * File Operations
 * ============================================================================
 */

int
Socket_simple_http_download (const char *url, const char *filepath)
{
  SocketHTTPClient_T client;
  volatile int ret = -1;
  volatile int exception_occurred = 0;

  Socket_simple_clear_error ();

  if (!url || !filepath)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  client = get_global_http_client ();
  if (!client)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP client not available");
      return -1;
    }

  pthread_mutex_lock (&g_http_mutex);
  TRY
  {
    ret = SocketHTTPClient_download (client, url, filepath);
  }
  HANDLE_HTTP_EXCEPTIONS_MINIMAL (exception_occurred)
  FINALLY
  {
    pthread_mutex_unlock (&g_http_mutex);
  }
  END_TRY;

  if (exception_occurred)
    return -1;

  if (ret == -2)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_IO, "File I/O error");
    }
  else if (ret == -1)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP download failed");
    }

  return ret;
}

int
Socket_simple_http_upload (const char *url,
                           const char *filepath,
                           const char *content_type)
{
  SocketHTTPClient_T client;
  volatile int ret = -1;
  volatile int exception_occurred = 0;

  Socket_simple_clear_error ();

  if (!url || !filepath)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  client = get_global_http_client ();
  if (!client)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP client not available");
      return -1;
    }

  (void)content_type; /* Library uses application/octet-stream */

  pthread_mutex_lock (&g_http_mutex);
  TRY
  {
    ret = SocketHTTPClient_upload (client, url, filepath);
  }
  HANDLE_HTTP_EXCEPTIONS_MINIMAL (exception_occurred)
  FINALLY
  {
    pthread_mutex_unlock (&g_http_mutex);
  }
  END_TRY;

  if (exception_occurred)
    return -1;

  if (ret == -2)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_IO, "File I/O error");
    }
  else if (ret == -1)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP upload failed");
    }

  return ret;
}

/* ============================================================================
 * Reusable Client
 * ============================================================================
 */

SocketSimple_HTTP_T
Socket_simple_http_new (void)
{
  return Socket_simple_http_new_ex (NULL);
}

SocketSimple_HTTP_T
Socket_simple_http_new_ex (const SocketSimple_HTTPOptions *opts)
{
  struct SocketSimple_HTTP *handle;
  SocketHTTPClient_Config config;
  volatile int exception_occurred = 0;

  Socket_simple_clear_error ();

  handle = calloc (1, sizeof (*handle));
  if (!handle)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Memory allocation failed");
      return NULL;
    }

  SocketHTTPClient_config_defaults (&config);

  /* Apply options if provided */
  if (opts)
    {
      if (opts->connect_timeout_ms > 0)
        config.connect_timeout_ms = opts->connect_timeout_ms;
      if (opts->request_timeout_ms > 0)
        config.request_timeout_ms = opts->request_timeout_ms;
      if (opts->max_redirects >= 0)
        config.follow_redirects = opts->max_redirects;
      config.verify_ssl = opts->verify_ssl;
      if (opts->user_agent)
        config.user_agent = opts->user_agent;
    }

  TRY
  {
    handle->client = SocketHTTPClient_new (&config);
  }
  EXCEPT (SocketHTTPClient_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "Failed to create HTTP client");
    exception_occurred = 1;
  }
  END_TRY;

  /* Clean up if exception occurred or client creation failed */
  if (exception_occurred || !handle->client)
    {
      free (handle);
      if (!exception_occurred)
        simple_set_error (SOCKET_SIMPLE_ERR_HTTP,
                          "Failed to create HTTP client");
      return NULL;
    }

  /* Set authentication if provided */
  if (opts && (opts->auth_user || opts->bearer_token))
    {
      SocketHTTPClient_Auth auth = { 0 };
      if (opts->bearer_token)
        {
          auth.type = HTTP_AUTH_BEARER;
          auth.token = opts->bearer_token;
        }
      else if (opts->auth_user)
        {
          auth.type = HTTP_AUTH_BASIC;
          auth.username = opts->auth_user;
          auth.password = opts->auth_pass;
        }
      SocketHTTPClient_set_auth (handle->client, &auth);
    }

  return handle;
}

int
Socket_simple_http_client_get (SocketSimple_HTTP_T client,
                               const char *url,
                               SocketSimple_HTTPResponse *response)
{
  SocketHTTPClient_Response lib_response;
  volatile int ret;

  Socket_simple_clear_error ();

  if (!client || !client->client || !url || !response)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  memset (&lib_response, 0, sizeof (lib_response));

  volatile int exception_occurred = 0;
  TRY
  {
    ret = SocketHTTPClient_get (client->client, url, &lib_response);
  }
  HANDLE_HTTP_EXCEPTIONS (exception_occurred)
  END_TRY;

  if (exception_occurred)
    return -1;

  if (ret != 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP request failed");
      return -1;
    }

  ret = convert_response (&lib_response, response);
  SocketHTTPClient_Response_free (&lib_response);

  return ret;
}

int
Socket_simple_http_client_post (SocketSimple_HTTP_T client,
                                const char *url,
                                const char *content_type,
                                const void *body,
                                size_t body_len,
                                SocketSimple_HTTPResponse *response)
{
  SocketHTTPClient_Response lib_response;
  volatile int ret;

  Socket_simple_clear_error ();

  if (!client || !client->client || !url || !response)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  memset (&lib_response, 0, sizeof (lib_response));

  volatile int exception_occurred = 0;
  TRY
  {
    ret = SocketHTTPClient_post (
        client->client, url, content_type, body, body_len, &lib_response);
  }
  HANDLE_HTTP_EXCEPTIONS_MINIMAL (exception_occurred)
  END_TRY;

  if (exception_occurred)
    return -1;

  if (ret != 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_HTTP, "HTTP request failed");
      return -1;
    }

  ret = convert_response (&lib_response, response);
  SocketHTTPClient_Response_free (&lib_response);

  return ret;
}

void
Socket_simple_http_free (SocketSimple_HTTP_T *client)
{
  if (!client || !*client)
    return;

  struct SocketSimple_HTTP *h = *client;

  if (h->client)
    {
      SocketHTTPClient_free (&h->client);
    }

  free (h);
  *client = NULL;
}

void
Socket_simple_http_response_free (SocketSimple_HTTPResponse *response)
{
  if (!response)
    return;
  free (response->body);
  free (response->content_type);
  free (response->location);
  memset (response, 0, sizeof (*response));
}
