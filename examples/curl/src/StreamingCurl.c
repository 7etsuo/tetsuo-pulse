/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file StreamingCurl.c
 * @brief Main implementation of streaming curl module.
 *
 * Implements the public API for the streaming HTTP client:
 * - Session lifecycle (new, reset, free)
 * - Request methods (GET, POST, PUT, DELETE, HEAD)
 * - Convenience functions (fetch, download, upload)
 * - Exception-safe resource management
 * - Connection reuse for same-host requests
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "curl/StreamingCurl-private.h"
#include "curl/StreamingCurl.h"
#include "http/SocketHTTP.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* Curl_options_defaults is defined in StreamingCurl_url.c */

/* Constants */
#define URL_PARSE_FLAGS_NONE 0     /* No special flags for URL parsing */
#define FILE_MODE_WRITE_BINARY "wb" /* File mode for binary write */
#define FILE_MODE_READ_BINARY "rb"  /* File mode for binary read */
#define FREAD_ELEMENT_SIZE 1        /* Read 1-byte elements with fread */
#define NULL_TERMINATOR_SIZE 1      /* Extra byte for null terminator */

CurlSession_T
Curl_session_new (const CurlOptions *options)
{
  /* Create session arena */
  Arena_T arena = Arena_new ();
  if (!arena)
    {
      RAISE (Curl_Failed);
    }

  /* Allocate session structure */
  CurlSession_T session = CALLOC (arena, 1, sizeof (*session));
  session->arena = arena;

  /* Create per-request arena */
  session->request_arena = Arena_new ();
  if (!session->request_arena)
    {
      Arena_dispose (&arena);
      RAISE (Curl_Failed);
    }

  /* Copy options or use defaults */
  if (options)
    {
      session->options = *options;
    }
  else
    {
      Curl_options_defaults (&session->options);
    }

  /* Copy authentication credentials to session */
  session->auth = session->options.auth;

  /* Initialize state */
  session->state = CURL_STATE_IDLE;
  session->last_error = CURL_OK;

  /* Initialize cookie handling if enabled */
  if (session->options.cookie_file)
    {
      curl_session_init_cookies (session, session->options.cookie_file);
    }

  return session;
}

void
Curl_session_free (CurlSession_T *session_p)
{
  if (!session_p || !*session_p)
    return;

  CurlSession_T session = *session_p;

  /* Save cookies if needed */
  if (session->cookie_jar && session->cookie_jar->dirty)
    {
      curl_session_save_cookies (session);
    }

  /* Close connection if open */
  if (session->conn)
    {
      curl_connection_close (session->conn);
      session->conn = NULL;
    }

  /* Free per-request arena */
  if (session->request_arena)
    {
      Arena_dispose (&session->request_arena);
    }

  /* Free session arena (frees everything including session struct).
   * Save arena to local variable first because session itself is allocated
   * from this arena - after Arena_clear, session memory is freed. */
  Arena_T arena = session->arena;
  Arena_dispose (&arena);
  *session_p = NULL;
}

void
Curl_session_reset (CurlSession_T session)
{
  if (!session)
    return;

  /* Reset per-request arena */
  if (session->request_arena)
    {
      Arena_dispose (&session->request_arena);
      session->request_arena = Arena_new ();
      if (!session->request_arena)
        {
          RAISE (Curl_Failed);
        }
    }

  /* Reset state */
  session->state = CURL_STATE_IDLE;
  session->last_error = CURL_OK;

  /* Reset response (but keep headers from session arena) */
  memset (&session->response, 0, sizeof (session->response));

  /* Reset URL */
  memset (&session->current_url, 0, sizeof (session->current_url));

  /* Keep connection for reuse (if compatible with next request) */
  /* Keep cookie jar */
  /* Keep custom headers */

  /* Reset transfer state */
  session->upload_total = 0;
  session->upload_sent = 0;
  session->download_total = 0;
  session->download_received = 0;

  /* Reset retry count */
  session->retry_count = 0;
}

CurlState
Curl_session_state (CurlSession_T session)
{
  if (!session)
    return CURL_STATE_ERROR;

  return session->state;
}

CurlError
Curl_session_error (CurlSession_T session)
{
  if (!session)
    return CURL_ERROR_CONNECT;

  return session->last_error;
}

const CurlResponse *
Curl_session_response (CurlSession_T session)
{
  if (!session)
    return NULL;

  return &session->response;
}

int
Curl_session_set_header (CurlSession_T session, const char *name,
                         const char *value)
{
  if (!session || !name)
    return -1;

  /* Allocate new custom header */
  CurlCustomHeader *header = ALLOC (session->arena, sizeof (*header));
  header->name = curl_arena_strdup (session->arena, name, strlen (name));
  header->value
      = value ? curl_arena_strdup (session->arena, value, strlen (value))
              : NULL;

  /* Prepend to list */
  header->next = session->custom_headers;
  session->custom_headers = header;

  return 0;
}

void
Curl_session_set_auth (CurlSession_T session, const CurlAuth *auth)
{
  if (!session)
    return;

  if (auth)
    {
      session->auth = *auth;
    }
  else
    {
      session->auth.type = CURL_AUTH_NONE;
      session->auth.username = NULL;
      session->auth.password = NULL;
      session->auth.token = NULL;
    }
}

void
Curl_session_set_write_callback (CurlSession_T session,
                                 CurlWriteCallback write_cb,
                                 void *write_userdata)
{
  if (!session)
    return;

  session->options.write_callback = write_cb;
  session->options.write_userdata = write_userdata;
}

void
Curl_session_set_read_callback (CurlSession_T session,
                                CurlReadCallback read_cb, void *read_userdata)
{
  if (!session)
    return;

  session->options.read_callback = read_cb;
  session->options.read_userdata = read_userdata;
}

/**
 * @brief Raise an exception based on CurlError code.
 */
static void
curl_raise_for_error (CurlError error)
{
  switch (error)
    {
    case CURL_ERROR_DNS:
      RAISE (Curl_DNSFailed);
    case CURL_ERROR_CONNECT:
      RAISE (Curl_ConnectFailed);
    case CURL_ERROR_TLS:
      RAISE (Curl_TLSFailed);
    case CURL_ERROR_TIMEOUT:
      RAISE (Curl_Timeout);
    case CURL_ERROR_TOO_MANY_REDIRECTS:
      RAISE (Curl_TooManyRedirects);
    case CURL_ERROR_INVALID_URL:
      RAISE (Curl_InvalidURL);
    case CURL_ERROR_PROTOCOL:
      RAISE (Curl_ProtocolError);
    case CURL_OK:
    case CURL_ERROR_WRITE_CALLBACK:
    case CURL_ERROR_READ_CALLBACK:
    case CURL_ERROR_OUT_OF_MEMORY:
    case CURL_ERROR_ABORTED:
    default:
      RAISE (Curl_Failed);
    }
}

/**
 * @brief Prepare session for a new request.
 *
 * Validates inputs, resets session state, and parses the URL.
 *
 * @param session Session handle
 * @param url URL string to parse
 * @return CURL_OK on success, error code on failure (also sets session error state)
 */
static CurlError
curl_prepare_request (CurlSession_T session, const char *url)
{
  if (!session || !url)
    return CURL_ERROR_CONNECT;

  Curl_session_reset (session);

  CurlError err = curl_internal_parse_url (url, URL_PARSE_FLAGS_NONE,
                                           &session->current_url,
                                           session->request_arena);
  if (err != CURL_OK)
    {
      session->state = CURL_STATE_ERROR;
      session->last_error = err;
    }

  return err;
}

/**
 * @brief Initialize options from provided or defaults.
 */
static void
curl_init_options (CurlOptions *opts, const CurlOptions *provided)
{
  if (provided)
    *opts = *provided;
  else
    Curl_options_defaults (opts);
}

/**
 * @brief Set session error state.
 */
static void
curl_set_error (CurlSession_T session, CurlError error)
{
  session->state = CURL_STATE_ERROR;
  session->last_error = error;
}

/**
 * @brief Setup connection for the request.
 *
 * Checks if existing connection can be reused, otherwise establishes
 * a new connection to the target URL.
 *
 * @param session Session handle
 * @return CURL_OK on success, error code on failure
 */
static CurlError
setup_connection (CurlSession_T session)
{
  /* Check if existing connection can be reused */
  if (session->conn
      && !curl_connection_reusable (session->conn, &session->current_url))
    {
      curl_connection_close (session->conn);
      session->conn = NULL;
    }

  /* Establish connection if needed */
  if (!session->conn)
    {
      session->state = CURL_STATE_CONNECTING;
      session->conn = curl_connect (&session->current_url, &session->options,
                                     session->request_arena);
      if (!session->conn)
        {
          return CURL_ERROR_CONNECT;
        }
    }

  return CURL_OK;
}

/**
 * @brief Build and send HTTP request.
 *
 * Builds request headers (including auth and cookies), then sends
 * the request using the appropriate protocol (HTTP/1.1 or HTTP/2).
 *
 * @param session Session handle
 * @param method HTTP method
 * @param body Request body (NULL for none)
 * @param body_len Body length
 * @return CURL_OK on success, error code on failure
 */
static CurlError
send_request (CurlSession_T session, SocketHTTP_Method method,
              const void *body, size_t body_len)
{
  /* Build request headers */
  if (curl_build_request_headers (session, method, NULL, body_len) != 0)
    {
      return CURL_ERROR_OUT_OF_MEMORY;
    }

  /* Add authentication header */
  curl_auth_setup (session);

  /* Add cookies to request */
  if (session->cookie_jar)
    {
      curl_session_add_cookies (session);
    }

  /* Send request */
  session->state = CURL_STATE_SENDING_REQUEST;
  return curl_send_request (session, method, body, body_len);
}

/**
 * @brief Receive HTTP response.
 *
 * Receives response headers and body using the appropriate protocol
 * (HTTP/1.1 or HTTP/2).
 *
 * @param session Session handle
 * @return CURL_OK on success, error code on failure
 */
static CurlError
receive_response (CurlSession_T session)
{
  if (curl_connection_is_http2 (session->conn))
    {
      return curl_receive_h2_response (session);
    }
  else
    {
      return curl_receive_h1_response (session);
    }
}

/**
 * @brief Process cookies from response headers.
 *
 * Parses Set-Cookie headers from the response and adds them to
 * the session's cookie jar.
 *
 * @param session Session handle
 * @return CURL_OK (always succeeds)
 */
static CurlError
handle_cookies (CurlSession_T session)
{
  if (session->cookie_jar)
    {
      curl_session_process_cookies (session);
    }
  return CURL_OK;
}

/**
 * @brief Check and handle redirect response.
 *
 * Determines if the response is a redirect that should be followed,
 * updates the session URL and state for the next request.
 *
 * @param session Session handle
 * @param should_retry Output flag: 1 if redirect should be followed
 * @param body_ptr Pointer to body pointer (may be reset for GET redirects)
 * @param body_len_ptr Pointer to body length (may be reset for GET redirects)
 * @return CURL_OK on success, error code on failure
 */
static CurlError
check_redirect (CurlSession_T session, int *should_retry,
                const void **body_ptr, size_t *body_len_ptr)
{
  *should_retry = 0;

  if (!curl_should_follow_redirect (session))
    {
      return CURL_OK;
    }

  CurlError result = curl_handle_redirect (session);
  if (result != CURL_OK)
    {
      return result;
    }

  if (curl_is_redirect (session))
    {
      /* Continue loop for redirect */
      *should_retry = 1;

      /* Reset for next request - but keep connection if reusable */
      session->state = CURL_STATE_IDLE;

      /* Reset upload state - body may not be sent for GET redirect */
      if (session->request_method == HTTP_METHOD_GET)
        {
          *body_ptr = NULL;
          *body_len_ptr = 0;
          session->upload_total = 0;
        }
    }

  return CURL_OK;
}

/**
 * @brief Execute a request with the session's current configuration.
 *
 * Handles connection establishment, request sending, response receiving,
 * redirect following, and cookie processing.
 *
 * @param session Session handle
 * @param method HTTP method
 * @param body Request body (NULL for none)
 * @param body_len Body length
 * @return CURL_OK on success, error code on failure
 */
static CurlError curl_perform_internal (CurlSession_T session,
                                        SocketHTTP_Method method,
                                        const void *body, size_t body_len);

static CurlError
curl_perform (CurlSession_T session, SocketHTTP_Method method,
              const void *body, size_t body_len)
{
  if (!session)
    return CURL_ERROR_CONNECT;

  return curl_perform_internal (session, method, body, body_len);
}

/**
 * @brief Check result and raise exception on error.
 */
static void
curl_check_result (CurlError result)
{
  if (result != CURL_OK)
    curl_raise_for_error (result);
}

static CurlError
curl_perform_internal (CurlSession_T session, SocketHTTP_Method method,
                       const void *body_init, size_t body_len_init)
{
  volatile CurlError result = CURL_OK;
  volatile int should_retry = 0;
  const void *volatile body = body_init;
  volatile size_t body_len = body_len_init;

  session->state = CURL_STATE_CONNECTING;
  session->request_method = method;
  session->upload_total = (int64_t)body_len_init;
  session->upload_sent = 0;
  session->download_received = 0;

  TRY
  {
    do
      {
        should_retry = 0;
        curl_check_result (setup_connection (session));
        curl_check_result (send_request (session, method, body, (size_t)body_len));
        curl_check_result (receive_response (session));
        curl_check_result (handle_cookies (session));
        curl_check_result (check_redirect (session, (int *)&should_retry,
                                           (const void **)&body,
                                           (size_t *)&body_len));
      }
    while (should_retry);
    session->state = CURL_STATE_COMPLETE;
  }
  EXCEPT (Curl_DNSFailed) { curl_set_error (session, result = CURL_ERROR_DNS); }
  EXCEPT (Curl_ConnectFailed) { curl_set_error (session, result = CURL_ERROR_CONNECT); }
  EXCEPT (Curl_TLSFailed) { curl_set_error (session, result = CURL_ERROR_TLS); }
  EXCEPT (Curl_Timeout) { curl_set_error (session, result = CURL_ERROR_TIMEOUT); }
  EXCEPT (Curl_TooManyRedirects) { curl_set_error (session, result = CURL_ERROR_TOO_MANY_REDIRECTS); }
  EXCEPT (Curl_ProtocolError) { curl_set_error (session, result = CURL_ERROR_PROTOCOL); }
  FINALLY
  {
    if (session->cookie_jar && session->cookie_jar->dirty
        && session->options.cookie_file)
      curl_session_save_cookies (session);
  }
  END_TRY;

  return result;
}

CurlError
Curl_get (CurlSession_T session, const char *url)
{
  CurlError err = curl_prepare_request (session, url);
  if (err != CURL_OK)
    return err;

  return curl_perform (session, HTTP_METHOD_GET, NULL, 0);
}

CurlError
Curl_head (CurlSession_T session, const char *url)
{
  CurlError err = curl_prepare_request (session, url);
  if (err != CURL_OK)
    return err;

  return curl_perform (session, HTTP_METHOD_HEAD, NULL, 0);
}

CurlError
Curl_post (CurlSession_T session, const char *url, const char *content_type,
           const void *body, size_t body_len)
{
  CurlError err = curl_prepare_request (session, url);
  if (err != CURL_OK)
    return err;

  if (content_type)
    Curl_session_set_header (session, "Content-Type", content_type);

  return curl_perform (session, HTTP_METHOD_POST, body, body_len);
}

CurlError
Curl_put (CurlSession_T session, const char *url, const char *content_type,
          const void *body, size_t body_len)
{
  CurlError err = curl_prepare_request (session, url);
  if (err != CURL_OK)
    return err;

  if (content_type)
    Curl_session_set_header (session, "Content-Type", content_type);

  return curl_perform (session, HTTP_METHOD_PUT, body, body_len);
}

CurlError
Curl_delete (CurlSession_T session, const char *url)
{
  CurlError err = curl_prepare_request (session, url);
  if (err != CURL_OK)
    return err;

  return curl_perform (session, HTTP_METHOD_DELETE, NULL, 0);
}

/**
 * @brief Copy headers from SocketHTTP_Headers_T to session.
 */
static void
curl_copy_headers (CurlSession_T session, SocketHTTP_Headers_T headers)
{
  size_t count = SocketHTTP_Headers_count (headers);
  for (size_t i = 0; i < count; i++)
    {
      const SocketHTTP_Header *h = SocketHTTP_Headers_at (headers, i);
      if (!h || !h->name || !h->value)
        continue;

      char *name = ALLOC (session->request_arena, h->name_len + NULL_TERMINATOR_SIZE);
      if (!name)
        continue;
      memcpy (name, h->name, h->name_len);
      name[h->name_len] = '\0';

      char *value = ALLOC (session->request_arena, h->value_len + NULL_TERMINATOR_SIZE);
      if (!value)
        continue;
      memcpy (value, h->value, h->value_len);
      value[h->value_len] = '\0';

      Curl_session_set_header (session, name, value);
    }
}

CurlError
Curl_request (CurlSession_T session, SocketHTTP_Method method, const char *url,
              SocketHTTP_Headers_T headers, const void *body, size_t body_len)
{
  CurlError err = curl_prepare_request (session, url);
  if (err != CURL_OK)
    return err;

  if (headers)
    curl_copy_headers (session, headers);

  return curl_perform (session, method, body, body_len);
}

CurlError
Curl_fetch (const char *url, CurlWriteCallback write_cb, void *userdata,
            const CurlOptions *options)
{
  if (!url)
    return CURL_ERROR_INVALID_URL;

  CurlOptions opts;
  curl_init_options (&opts, options);
  opts.write_callback = write_cb;
  opts.write_userdata = userdata;

  CurlSession_T session = Curl_session_new (&opts);
  if (!session)
    return CURL_ERROR_OUT_OF_MEMORY;

  CurlError result = Curl_get (session, url);
  Curl_session_free (&session);

  return result;
}

/**
 * @brief Write callback for file download.
 */
static size_t
file_write_callback (void *data, size_t size, size_t nmemb, void *userdata)
{
  FILE *fp = (FILE *)userdata;
  if (!fp)
    return 0;

  return fwrite (data, size, nmemb, fp);
}

CurlError
Curl_download (const char *url, const char *filepath,
               const CurlOptions *options)
{
  if (!url || !filepath)
    return CURL_ERROR_INVALID_URL;

  FILE *fp = fopen (filepath, FILE_MODE_WRITE_BINARY);
  if (!fp)
    return CURL_ERROR_WRITE_CALLBACK;

  CurlOptions opts;
  curl_init_options (&opts, options);
  opts.write_callback = file_write_callback;
  opts.write_userdata = fp;

  CurlSession_T session = Curl_session_new (&opts);
  if (!session)
    {
      fclose (fp);
      return CURL_ERROR_OUT_OF_MEMORY;
    }

  volatile CurlError result = CURL_OK;
  TRY { result = Curl_get (session, url); }
  FINALLY
  {
    Curl_session_free (&session);
    fclose (fp);
  }
  END_TRY;

  return result;
}

/**
 * @brief File upload state.
 */
typedef struct
{
  FILE *fp;
  size_t size;
  size_t sent;
} FileUploadState;

/**
 * @brief Read callback for file upload.
 */
static size_t
file_read_callback (void *buffer, size_t size, size_t nmemb, void *userdata)
{
  FileUploadState *state = (FileUploadState *)userdata;
  if (!state || !state->fp)
    return 0;

  size_t remaining = state->size - state->sent;
  size_t to_read = size * nmemb;
  if (to_read > remaining)
    to_read = remaining;

  size_t nread = fread (buffer, FREAD_ELEMENT_SIZE, to_read, state->fp);
  state->sent += nread;

  return nread;
}

/**
 * @brief Get file size, returning -1 on error.
 */
static long
curl_get_file_size (FILE *fp)
{
  fseek (fp, 0, SEEK_END);
  long size = ftell (fp);
  fseek (fp, 0, SEEK_SET);
  return size;
}

/**
 * @brief Internal upload implementation to avoid clobbered parameter warnings.
 */
static CurlError
curl_upload_internal (const char *url, FILE *fp, long size, const char *ct,
                      const CurlOptions *options)
{
  FileUploadState state = { .fp = fp, .size = (size_t)size, .sent = 0 };

  CurlOptions opts;
  curl_init_options (&opts, options);
  opts.read_callback = file_read_callback;
  opts.read_userdata = &state;

  CurlSession_T session = Curl_session_new (&opts);
  if (!session)
    return CURL_ERROR_OUT_OF_MEMORY;

  volatile CurlError result = CURL_OK;
  TRY { result = Curl_put (session, url, ct, NULL, (size_t)size); }
  FINALLY { Curl_session_free (&session); }
  END_TRY;

  return result;
}

CurlError
Curl_upload (const char *url, const char *filepath, const char *content_type,
             const CurlOptions *options)
{
  if (!url || !filepath)
    return CURL_ERROR_INVALID_URL;

  FILE *fp = fopen (filepath, FILE_MODE_READ_BINARY);
  if (!fp)
    return CURL_ERROR_READ_CALLBACK;

  long size = curl_get_file_size (fp);
  if (size < 0)
    {
      fclose (fp);
      return CURL_ERROR_READ_CALLBACK;
    }

  const char *ct = content_type ? content_type : "application/octet-stream";
  CurlError result = curl_upload_internal (url, fp, size, ct, options);
  fclose (fp);

  return result;
}
