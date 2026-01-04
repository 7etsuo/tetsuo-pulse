/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file curl_main.c
 * @brief Main entry point for tcurl CLI tool.
 *
 * Provides a curl-compatible command-line interface for HTTP requests
 * using the StreamingCurl library.
 */

#include "core/Except.h"
#include "curl/StreamingCurl.h"
#include "curl/StreamingCurl-private.h"
#include "curl/curl_args.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Constants */
#define PERCENT_MULTIPLIER 100
#define ASCII_PRINTABLE_MIN 32
#define WRITEOUT_VAR_PREFIX_LEN 2
#define WRITEOUT_VAR_SUFFIX_LEN 1
#define ESCAPE_SEQUENCE_LEN 2
#define MILLISECONDS_PER_SECOND 1000
#define CONTENT_TYPE_HEADER_LEN 13
#define HTTP_CLIENT_ERROR_MIN 400

/* Exit codes (curl compatible) */
#define EXIT_SUCCESS_CODE 0
#define EXIT_UNSUPPORTED_PROTOCOL 1
#define EXIT_FAILED_INIT 2
#define EXIT_URL_MALFORMED 3
#define EXIT_COULD_NOT_RESOLVE_HOST 6
#define EXIT_COULDNT_CONNECT 7
#define EXIT_HTTP_ERROR 22
#define EXIT_WRITE_ERROR 23
#define EXIT_OPERATION_TIMEOUT 28
#define EXIT_SSL_CONNECT_ERROR 35
#define EXIT_TOO_MANY_REDIRECTS 47
#define EXIT_RECV_ERROR 56

/* Global state for signal handling */
static volatile sig_atomic_t g_interrupted = 0;

/* Progress state */
typedef struct
{
  TcurlOptions *opts;
  int64_t last_progress_time;
  int64_t last_dlnow;
  int64_t last_ulnow;
} ProgressState;

/* Write callback context */
typedef struct
{
  FILE *fp;
  TcurlOptions *opts;
  int64_t bytes_written;
} WriteContext;

/* Header callback context */
typedef struct
{
  TcurlOptions *opts;
  FILE *output;
} HeaderContext;

/* Main execution context - groups all state for the curl operation */
typedef struct
{
  TcurlOptions opts;
  WriteContext write_ctx;
  HeaderContext header_ctx;
  ProgressState progress_state;
  CurlAuth auth;
  char auth_username[CURL_MAX_CREDENTIAL_LEN];
  char auth_password[CURL_MAX_CREDENTIAL_LEN];
  CurlOptions curl_opts;
  volatile FILE *output;
  CurlSession_T session;
} MainContext;

/* Writeout variable handler context */
typedef struct
{
  const CurlResponse *response;
  int64_t bytes_written;
} WriteoutContext;

/* Writeout variable lookup entry */
typedef struct
{
  const char *name;
  void (*handler) (const WriteoutContext *ctx);
} WriteoutVar;

static void
signal_handler (int sig)
{
  (void)sig;
  g_interrupted = 1;
}

static void
setup_signals (void)
{
  struct sigaction sa;
  memset (&sa, 0, sizeof (sa));
  sa.sa_handler = signal_handler;
  sigemptyset (&sa.sa_mask);
  sa.sa_flags = 0;

  sigaction (SIGINT, &sa, NULL);
  sigaction (SIGTERM, &sa, NULL);
  signal (SIGPIPE, SIG_IGN);
}

static size_t
write_callback (void *data, size_t size, size_t nmemb, void *userdata)
{
  WriteContext *ctx = (WriteContext *)userdata;

  if (g_interrupted)
    return 0;

  size_t written = fwrite (data, size, nmemb, ctx->fp);
  ctx->bytes_written += written;
  return written;
}

static size_t
header_callback (void *data, size_t size, size_t nmemb, void *userdata)
{
  HeaderContext *ctx = (HeaderContext *)userdata;
  size_t total = size * nmemb;

  if (ctx->opts->verbose || ctx->opts->include_headers)
    {
      FILE *out = ctx->opts->verbose ? stderr : ctx->output;
      fwrite (data, size, nmemb, out);
    }

  return total;
}

static int
should_skip_progress (ProgressState *state, int64_t now, int64_t dlnow,
                      int64_t ulnow)
{
  return now == state->last_progress_time && dlnow == state->last_dlnow
         && ulnow == state->last_ulnow;
}

static void
show_download_progress (int64_t dltotal, int64_t dlnow)
{
  if (dltotal > 0)
    {
      int percent = (int)(dlnow * PERCENT_MULTIPLIER / dltotal);
      fprintf (stderr, "\r  %% Total    %% Received\n");
      fprintf (stderr, "\r%3d %8lld %3d %8lld", percent, (long long)dltotal,
               percent, (long long)dlnow);
    }
  else if (dlnow > 0)
    {
      fprintf (stderr, "\rReceived: %lld bytes", (long long)dlnow);
    }
}

static void
show_upload_progress (int64_t ultotal, int64_t ulnow)
{
  if (ultotal > 0)
    {
      int percent = (int)(ulnow * PERCENT_MULTIPLIER / ultotal);
      fprintf (stderr, "  Upload: %3d%% (%lld/%lld)", percent,
               (long long)ulnow, (long long)ultotal);
    }
}

static int
progress_callback (void *userdata, int64_t dltotal, int64_t dlnow,
                   int64_t ultotal, int64_t ulnow)
{
  ProgressState *state = (ProgressState *)userdata;

  if (g_interrupted)
    return 1;

  if (state->opts->silent)
    return 0;

  int64_t now = (int64_t)time (NULL);
  if (should_skip_progress (state, now, dlnow, ulnow))
    return 0;

  state->last_progress_time = now;
  state->last_dlnow = dlnow;
  state->last_ulnow = ulnow;

  show_download_progress (dltotal, dlnow);
  show_upload_progress (ultotal, ulnow);
  fflush (stderr);

  return 0;
}

static int
error_to_exit_code (CurlError error)
{
  switch (error)
    {
    case CURL_OK:
      return EXIT_SUCCESS_CODE;
    case CURL_ERROR_DNS:
      return EXIT_COULD_NOT_RESOLVE_HOST;
    case CURL_ERROR_CONNECT:
      return EXIT_COULDNT_CONNECT;
    case CURL_ERROR_TLS:
      return EXIT_SSL_CONNECT_ERROR;
    case CURL_ERROR_TIMEOUT:
      return EXIT_OPERATION_TIMEOUT;
    case CURL_ERROR_TOO_MANY_REDIRECTS:
      return EXIT_TOO_MANY_REDIRECTS;
    case CURL_ERROR_INVALID_URL:
      return EXIT_URL_MALFORMED;
    case CURL_ERROR_WRITE_CALLBACK:
      return EXIT_WRITE_ERROR;
    case CURL_ERROR_PROTOCOL:
      return EXIT_RECV_ERROR;
    default:
      return 1;
    }
}

static int
validate_header (const char *header)
{
  if (!header)
    return -1;

  for (const char *p = header; *p; p++)
    {
      if (*p == '\r' || *p == '\n' || (*p < ASCII_PRINTABLE_MIN && *p != '\t'))
        return -1;
    }

  return 0;
}

static void
parse_user_auth (const char *user_str, CurlAuth *auth, char *username_buf,
                 size_t username_size, char *password_buf, size_t password_size)
{
  if (!user_str)
    return;

  auth->type = CURL_AUTH_BASIC;
  const char *colon = strchr (user_str, ':');

  if (colon)
    {
      size_t user_len = (size_t)(colon - user_str);
      if (user_len >= username_size)
        user_len = username_size - 1;
      memcpy (username_buf, user_str, user_len);
      username_buf[user_len] = '\0';
      auth->username = username_buf;

      size_t pass_len = strlen (colon + 1);
      if (pass_len >= password_size)
        pass_len = password_size - 1;
      memcpy (password_buf, colon + 1, pass_len);
      password_buf[pass_len] = '\0';
      auth->password = password_buf;
    }
  else
    {
      auth->username = user_str;
      auth->password = "";
    }
}

static void
secure_clear (void *ptr, size_t len)
{
  volatile unsigned char *p = ptr;
  while (len--)
    *p++ = 0;
}

/* Writeout variable handlers */
static void
writeout_http_code (const WriteoutContext *ctx)
{
  printf ("%d", ctx->response ? ctx->response->status_code : 0);
}

static void
writeout_size_download (const WriteoutContext *ctx)
{
  printf ("%lld", (long long)ctx->bytes_written);
}

static void
writeout_content_type (const WriteoutContext *ctx)
{
  if (ctx->response && ctx->response->headers)
    {
      const char *ct
          = SocketHTTP_Headers_get (ctx->response->headers, "Content-Type");
      printf ("%s", ct ? ct : "");
    }
}

static const WriteoutVar writeout_vars[] = {
  { "http_code", writeout_http_code },
  { "size_download", writeout_size_download },
  { "content_type", writeout_content_type },
  { NULL, NULL }
};

static void
handle_writeout_var (const char *varname, const WriteoutContext *ctx)
{
  for (const WriteoutVar *v = writeout_vars; v->name; v++)
    {
      if (strcmp (varname, v->name) == 0)
        {
          v->handler (ctx);
          return;
        }
    }
}

static const char *
parse_writeout_var (const char *p, const WriteoutContext *ctx)
{
  const char *end = strchr (p + WRITEOUT_VAR_PREFIX_LEN, '}');
  if (!end)
    return NULL;

  size_t varlen = end - (p + WRITEOUT_VAR_PREFIX_LEN);
  char varname[CURL_MAX_QOP_LEN];

  if (varlen < sizeof (varname))
    {
      memcpy (varname, p + WRITEOUT_VAR_PREFIX_LEN, varlen);
      varname[varlen] = '\0';
      handle_writeout_var (varname, ctx);
    }

  return end + WRITEOUT_VAR_SUFFIX_LEN;
}

static void
process_write_out (const char *format, const CurlResponse *response,
                   int64_t bytes_written)
{
  if (!format)
    return;

  WriteoutContext ctx = { response, bytes_written };
  const char *p = format;

  while (*p)
    {
      if (*p == '%' && *(p + 1) == '{')
        {
          const char *next = parse_writeout_var (p, &ctx);
          if (next)
            {
              p = next;
              continue;
            }
        }
      else if (*p == '\\' && *(p + 1) == 'n')
        {
          printf ("\n");
          p += ESCAPE_SEQUENCE_LEN;
          continue;
        }
      else if (*p == '\\' && *(p + 1) == 't')
        {
          printf ("\t");
          p += ESCAPE_SEQUENCE_LEN;
          continue;
        }

      putchar (*p);
      p++;
    }
}

static void
configure_timeouts (CurlOptions *curl_opts, const TcurlOptions *opts)
{
  if (opts->connect_timeout > 0)
    curl_opts->connect_timeout_ms
        = opts->connect_timeout * MILLISECONDS_PER_SECOND;

  if (opts->max_time > 0)
    curl_opts->request_timeout_ms = opts->max_time * MILLISECONDS_PER_SECOND;
}

static void
configure_http_version (CurlOptions *curl_opts, const TcurlOptions *opts)
{
  if (opts->http_version == TCURL_HTTP_2)
    curl_opts->max_version = HTTP_VERSION_2;
  else if (opts->http_version == TCURL_HTTP_1_1)
    curl_opts->max_version = HTTP_VERSION_1_1;
}

static void
configure_compression (CurlOptions *curl_opts, const TcurlOptions *opts)
{
  if (opts->compressed)
    {
      curl_opts->accept_encoding = 1;
      curl_opts->auto_decompress = 1;
    }
}

static void
configure_optional_features (CurlOptions *curl_opts, const TcurlOptions *opts)
{
  if (opts->proxy)
    curl_opts->proxy_url = opts->proxy;

  if (opts->cookie_file || opts->cookie_jar)
    curl_opts->cookie_file
        = opts->cookie_file ? opts->cookie_file : opts->cookie_jar;

  if (opts->retry_count > 0)
    {
      curl_opts->enable_retry = 1;
      curl_opts->max_retries = opts->retry_count;
    }
}

static void
configure_callbacks (CurlOptions *curl_opts, WriteContext *write_ctx,
                     HeaderContext *header_ctx, ProgressState *progress_state,
                     int silent)
{
  curl_opts->write_callback = write_callback;
  curl_opts->write_userdata = write_ctx;
  curl_opts->header_callback = header_callback;
  curl_opts->header_userdata = header_ctx;

  if (!silent)
    {
      curl_opts->progress_callback = progress_callback;
      curl_opts->progress_userdata = progress_state;
    }
}

static void
configure_curl_options (CurlOptions *curl_opts, TcurlOptions *opts,
                        WriteContext *write_ctx, HeaderContext *header_ctx,
                        ProgressState *progress_state, CurlAuth *auth)
{
  Curl_options_defaults (curl_opts);

  curl_opts->follow_redirects = opts->follow_redirects;
  curl_opts->max_redirects = opts->max_redirects;
  curl_opts->verify_ssl = !opts->insecure;
  curl_opts->user_agent = opts->user_agent;
  curl_opts->verbose = opts->verbose;

  configure_timeouts (curl_opts, opts);
  configure_http_version (curl_opts, opts);
  configure_compression (curl_opts, opts);
  configure_optional_features (curl_opts, opts);
  configure_callbacks (curl_opts, write_ctx, header_ctx, progress_state,
                       opts->silent);

  if (auth)
    curl_opts->auth = *auth;
}

static int
add_single_header (CurlSession_T session, char *header)
{
  if (validate_header (header) < 0)
    {
      fprintf (stderr,
               "tcurl: Invalid header (contains control characters): %s\n",
               header);
      return -1;
    }

  char *colon = strchr (header, ':');
  if (colon)
    {
      *colon = '\0';
      const char *value = colon + 1;
      while (*value == ' ')
        value++;
      Curl_session_set_header (session, header, value);
      *colon = ':';
    }

  return 0;
}

static int
add_custom_headers (CurlSession_T session, TcurlOptions *opts)
{
  for (int i = 0; i < opts->header_count; i++)
    {
      if (add_single_header (session, opts->headers[i]) < 0)
        return -1;
    }
  return 0;
}

static int
add_referer_header (CurlSession_T session, const char *referer)
{
  if (!referer)
    return 0;

  if (validate_header (referer) < 0)
    {
      fprintf (stderr, "tcurl: Invalid referer (contains control characters)\n");
      return -1;
    }

  Curl_session_set_header (session, "Referer", referer);
  return 0;
}

static void
print_verbose_request (const TcurlOptions *opts)
{
  if (!opts->verbose)
    return;

  fprintf (stderr, "> %s %s\n", opts->method ? opts->method : "GET", opts->url);
  fprintf (stderr, "> User-Agent: %s\n", opts->user_agent);

  for (int i = 0; i < opts->header_count; i++)
    fprintf (stderr, "> %s\n", opts->headers[i]);

  fprintf (stderr, ">\n");
}

static int
setup_session (CurlSession_T *session, TcurlOptions *opts,
               CurlOptions *curl_opts)
{
  *session = Curl_session_new (curl_opts);

  if (add_custom_headers (*session, opts) < 0)
    RAISE (Curl_Failed);

  if (add_referer_header (*session, opts->referer) < 0)
    RAISE (Curl_Failed);

  print_verbose_request (opts);
  return 0;
}

static int
has_custom_content_type (const TcurlOptions *opts)
{
  for (int i = 0; i < opts->header_count; i++)
    {
      if (strncasecmp (opts->headers[i], "Content-Type:",
                       CONTENT_TYPE_HEADER_LEN)
          == 0)
        return 1;
    }
  return 0;
}

static CurlError
execute_with_data (CurlSession_T session, TcurlOptions *opts,
                   SocketHTTP_Method method)
{
  const char *content_type
      = has_custom_content_type (opts) ? NULL : "application/x-www-form-urlencoded";

  if (method == HTTP_METHOD_PUT)
    return Curl_put (session, opts->url, content_type, opts->data,
                     opts->data_len);

  return Curl_post (session, opts->url, content_type, opts->data,
                    opts->data_len);
}

static CurlError
execute_request (CurlSession_T session, TcurlOptions *opts)
{
  SocketHTTP_Method method = Tcurl_get_http_method (opts);

  if (opts->data && opts->data_len > 0)
    return execute_with_data (session, opts, method);

  if (opts->head_only)
    return Curl_head (session, opts->url);

  if (method == HTTP_METHOD_DELETE)
    return Curl_delete (session, opts->url);

  if (method == HTTP_METHOD_POST)
    return Curl_post (session, opts->url, NULL, NULL, 0);

  if (method == HTTP_METHOD_PUT)
    return Curl_put (session, opts->url, NULL, NULL, 0);

  return Curl_get (session, opts->url);
}

static void
handle_output (TcurlOptions *opts, const CurlResponse *response,
               int64_t bytes_written)
{
  if (opts->write_out)
    process_write_out (opts->write_out, response, bytes_written);

  if (opts->verbose && response)
    {
      fprintf (stderr, "\n< HTTP/%s %d\n",
               response->version == HTTP_VERSION_2 ? "2" : "1.1",
               response->status_code);
    }
}

static void
init_write_context (WriteContext *ctx, TcurlOptions *opts)
{
  ctx->fp = stdout;
  ctx->opts = opts;
  ctx->bytes_written = 0;
}

static void
init_header_context (HeaderContext *ctx, TcurlOptions *opts)
{
  ctx->opts = opts;
  ctx->output = stdout;
}

static void
init_progress_state (ProgressState *state, TcurlOptions *opts)
{
  state->opts = opts;
  state->last_progress_time = 0;
  state->last_dlnow = 0;
  state->last_ulnow = 0;
}

static void
initialize_contexts (TcurlOptions *opts, WriteContext *write_ctx,
                     HeaderContext *header_ctx, ProgressState *progress_state,
                     CurlAuth *auth, char *auth_username, char *auth_password)
{
  init_write_context (write_ctx, opts);
  init_header_context (header_ctx, opts);
  init_progress_state (progress_state, opts);

  if (opts->user)
    {
      parse_user_auth (opts->user, auth, auth_username, CURL_MAX_CREDENTIAL_LEN,
                       auth_password, CURL_MAX_CREDENTIAL_LEN);
    }
}

static int
validate_output_path (const char *filename)
{
  struct stat st;

  if (lstat (filename, &st) != 0)
    return 0;

  if (S_ISLNK (st.st_mode))
    {
      fprintf (stderr, "tcurl: Refusing to write to symbolic link: %s\n",
               filename);
      return -1;
    }

  if (!S_ISREG (st.st_mode))
    {
      fprintf (stderr, "tcurl: Refusing to write to non-regular file: %s\n",
               filename);
      return -1;
    }

  return 0;
}

static int
open_output_file (const char *filename, volatile FILE **output_ptr)
{
  if (!filename)
    {
      *output_ptr = stdout;
      return 0;
    }

  if (validate_output_path (filename) < 0)
    RAISE (Curl_Failed);

  *output_ptr = fopen (filename, "wb");
  if (!*output_ptr)
    {
      fprintf (stderr, "tcurl: Cannot open '%s' for writing: %s\n", filename,
               strerror (errno));
      RAISE (Curl_Failed);
    }

  return 0;
}

static void
report_error (const TcurlOptions *opts, CurlError result)
{
  if (!opts->silent || opts->show_error)
    fprintf (stderr, "\ntcurl: %s\n", Curl_error_string (result));
}

static CurlError
check_http_error (const TcurlOptions *opts, const CurlResponse *response)
{
  if (!opts->fail_on_error || !response)
    return CURL_OK;

  if (response->status_code >= HTTP_CLIENT_ERROR_MIN)
    {
      if (!opts->silent || opts->show_error)
        {
          fprintf (stderr, "\ntcurl: The requested URL returned error: %d\n",
                   response->status_code);
        }
      return CURL_ERROR_PROTOCOL;
    }

  return CURL_OK;
}

static CurlError
handle_request_result (TcurlOptions *opts, CurlSession_T session,
                       CurlError result, int64_t bytes_written)
{
  if (result != CURL_OK)
    {
      report_error (opts, result);
      return result;
    }

  const CurlResponse *response = Curl_session_response (session);
  CurlError http_error = check_http_error (opts, response);

  handle_output (opts, response, bytes_written);

  return http_error != CURL_OK ? http_error : result;
}

static CurlError
execute_curl_request (TcurlOptions *opts, CurlOptions *curl_opts,
                      WriteContext *write_ctx, HeaderContext *header_ctx,
                      volatile FILE **output)
{
  CurlSession_T session = NULL;

  open_output_file (opts->output_file, output);
  write_ctx->fp = (FILE *)*output;
  header_ctx->output = (FILE *)*output;

  setup_session (&session, opts, curl_opts);
  CurlError result = execute_request (session, opts);
  result = handle_request_result (opts, session, result, write_ctx->bytes_written);

  if (session)
    Curl_session_free (&session);

  return result;
}

static void
close_output_file (volatile FILE **output)
{
  if (*output != stdout && *output != NULL)
    {
      fclose ((FILE *)*output);
      *output = stdout;
    }
}

static void
cleanup_session (CurlSession_T *session, volatile FILE **output,
                 TcurlOptions *opts, char *auth_username, char *auth_password)
{
  close_output_file (output);

  if (*session)
    Curl_session_free (session);

  Tcurl_options_free (opts);
  secure_clear (auth_username, CURL_MAX_CREDENTIAL_LEN);
  secure_clear (auth_password, CURL_MAX_CREDENTIAL_LEN);
}

static int
parse_options (int argc, char **argv, TcurlOptions *opts)
{
  if (Tcurl_parse_args (argc, argv, opts) < 0)
    return -EXIT_FAILED_INIT;

  if (opts->show_help)
    {
      Tcurl_print_usage (argv[0]);
      return EXIT_SUCCESS_CODE + 1;
    }

  if (opts->show_version)
    {
      Tcurl_print_version ();
      return EXIT_SUCCESS_CODE + 1;
    }

  if (Tcurl_validate_args (opts) < 0)
    {
      Tcurl_print_usage (argv[0]);
      return -EXIT_FAILED_INIT;
    }

  return 0;
}

static void
print_error_message (const TcurlOptions *opts, const char *message)
{
  if (!opts->silent || opts->show_error)
    fprintf (stderr, "tcurl: %s\n", message);
}

static void
init_main_context (MainContext *ctx)
{
  memset (ctx, 0, sizeof (*ctx));
  ctx->output = stdout;
  ctx->session = NULL;
}

static void
setup_main_context (MainContext *ctx)
{
  initialize_contexts (&ctx->opts, &ctx->write_ctx, &ctx->header_ctx,
                       &ctx->progress_state, &ctx->auth, ctx->auth_username,
                       ctx->auth_password);

  configure_curl_options (&ctx->curl_opts, &ctx->opts, &ctx->write_ctx,
                          &ctx->header_ctx, &ctx->progress_state,
                          ctx->opts.user ? &ctx->auth : NULL);
}

static int
process_result (CurlError result, const TcurlOptions *opts)
{
  if (result == CURL_OK)
    return EXIT_SUCCESS_CODE;

  int exit_code = error_to_exit_code (result);
  if (result == CURL_ERROR_PROTOCOL && opts->fail_on_error)
    exit_code = EXIT_HTTP_ERROR;

  return exit_code;
}

/* Exception-to-exit-code mapping */
typedef struct
{
  const Except_T *exception;
  int exit_code;
  const char *message;
} ExceptionMapping;

static const ExceptionMapping exception_map[] = {
  { &Curl_DNSFailed, EXIT_COULD_NOT_RESOLVE_HOST, "Could not resolve host" },
  { &Curl_ConnectFailed, EXIT_COULDNT_CONNECT, "Failed to connect" },
  { &Curl_TLSFailed, EXIT_SSL_CONNECT_ERROR, "SSL/TLS handshake failed" },
  { &Curl_Timeout, EXIT_OPERATION_TIMEOUT, "Operation timed out" },
  { &Curl_TooManyRedirects, EXIT_TOO_MANY_REDIRECTS, "Maximum redirects exceeded" },
  { &Curl_InvalidURL, EXIT_URL_MALFORMED, "Invalid URL" },
  { &Curl_Failed, 1, "Request failed" },
  { NULL, 0, NULL }
};

static int
run_curl_main (MainContext *ctx)
{
  volatile int exit_code = EXIT_SUCCESS_CODE;
  volatile CurlError result;

  TRY
  {
    result = execute_curl_request (&ctx->opts, &ctx->curl_opts, &ctx->write_ctx,
                                   &ctx->header_ctx, &ctx->output);
    exit_code = process_result (result, &ctx->opts);
  }
  EXCEPT (Curl_DNSFailed)
  {
    exit_code = exception_map[0].exit_code;
    print_error_message (&ctx->opts, exception_map[0].message);
  }
  EXCEPT (Curl_ConnectFailed)
  {
    exit_code = exception_map[1].exit_code;
    print_error_message (&ctx->opts, exception_map[1].message);
  }
  EXCEPT (Curl_TLSFailed)
  {
    exit_code = exception_map[2].exit_code;
    print_error_message (&ctx->opts, exception_map[2].message);
  }
  EXCEPT (Curl_Timeout)
  {
    exit_code = exception_map[3].exit_code;
    print_error_message (&ctx->opts, exception_map[3].message);
  }
  EXCEPT (Curl_TooManyRedirects)
  {
    exit_code = exception_map[4].exit_code;
    print_error_message (&ctx->opts, exception_map[4].message);
  }
  EXCEPT (Curl_InvalidURL)
  {
    exit_code = exception_map[5].exit_code;
    print_error_message (&ctx->opts, exception_map[5].message);
  }
  EXCEPT (Curl_Failed)
  {
    exit_code = exception_map[6].exit_code;
    print_error_message (&ctx->opts, exception_map[6].message);
  }
  FINALLY
  {
    cleanup_session (&ctx->session, &ctx->output, &ctx->opts, ctx->auth_username,
                     ctx->auth_password);
  }
  END_TRY;

  return exit_code;
}

int
main (int argc, char **argv)
{
  MainContext ctx;
  init_main_context (&ctx);

  int parse_result = parse_options (argc, argv, &ctx.opts);
  if (parse_result < 0)
    return -parse_result;
  if (parse_result > 0)
    return EXIT_SUCCESS_CODE;

  setup_signals ();
  setup_main_context (&ctx);

  int exit_code = run_curl_main (&ctx);

  if (!ctx.opts.silent && !ctx.opts.verbose)
    fprintf (stderr, "\n");

  return exit_code;
}
