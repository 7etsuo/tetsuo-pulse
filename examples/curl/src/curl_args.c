/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file curl_args.c
 * @brief Command-line argument parsing for tcurl CLI tool.
 *
 * Parses curl-compatible command-line arguments and populates
 * a TcurlOptions structure for the main program.
 */

#include "curl/StreamingCurl-private.h"
#include "curl/curl_args.h"

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Default values */
#define DEFAULT_USER_AGENT "tcurl/1.0"
#define DEFAULT_CONNECT_TIMEOUT 30
#define DEFAULT_MAX_TIME 0

/* Option values for long-only options (no short equivalent) */
#define OPT_DATA_RAW 256
#define OPT_DATA_BINARY 257
#define OPT_HTTP2 258
#define OPT_HTTP11 259
#define OPT_HTTP10 260
#define OPT_CONNECT_TIMEOUT 261
#define OPT_COMPRESSED 262
#define OPT_FAIL_WITH_BODY 263
#define OPT_MAX_REDIRS 264
#define OPT_RETRY 265

/* Long options table */
static struct option long_options[]
    = { { "request", required_argument, NULL, 'X' },
        { "header", required_argument, NULL, 'H' },
        { "data", required_argument, NULL, 'd' },
        { "data-raw", required_argument, NULL, OPT_DATA_RAW },
        { "data-binary", required_argument, NULL, OPT_DATA_BINARY },
        { "form", required_argument, NULL, 'F' },
        { "output", required_argument, NULL, 'o' },
        { "remote-name", no_argument, NULL, 'O' },
        { "location", no_argument, NULL, 'L' },
        { "insecure", no_argument, NULL, 'k' },
        { "proxy", required_argument, NULL, 'x' },
        { "user", required_argument, NULL, 'u' },
        { "cookie", required_argument, NULL, 'b' },
        { "cookie-jar", required_argument, NULL, 'c' },
        { "user-agent", required_argument, NULL, 'A' },
        { "referer", required_argument, NULL, 'e' },
        { "verbose", no_argument, NULL, 'v' },
        { "silent", no_argument, NULL, 's' },
        { "show-error", no_argument, NULL, 'S' },
        { "include", no_argument, NULL, 'i' },
        { "head", no_argument, NULL, 'I' },
        { "write-out", required_argument, NULL, 'w' },
        { "http2", no_argument, NULL, OPT_HTTP2 },
        { "http1.1", no_argument, NULL, OPT_HTTP11 },
        { "http1.0", no_argument, NULL, OPT_HTTP10 },
        { "connect-timeout", required_argument, NULL, OPT_CONNECT_TIMEOUT },
        { "max-time", required_argument, NULL, 'm' },
        { "compressed", no_argument, NULL, OPT_COMPRESSED },
        { "fail", no_argument, NULL, 'f' },
        { "fail-with-body", no_argument, NULL, OPT_FAIL_WITH_BODY },
        { "max-redirs", required_argument, NULL, OPT_MAX_REDIRS },
        { "retry", required_argument, NULL, OPT_RETRY },
        { "help", no_argument, NULL, 'h' },
        { "version", no_argument, NULL, 'V' },
        { NULL, 0, NULL, 0 } };

/* Short options string */
static const char *short_options = "X:H:d:F:o:OLkx:u:b:c:A:e:vsSiIw:m:fhV";

/*
 * Data-driven option handling tables
 */

/* Boolean flag option: sets an int field to 1 */
typedef struct
{
  int opt_val;
  size_t offset;
} BoolOption;

/* String option: sets a const char* field to optarg */
typedef struct
{
  int opt_val;
  size_t offset;
} StringOption;

/* Integer option: parses optarg and sets an int field */
typedef struct
{
  int opt_val;
  size_t offset;
  const char *name;
} IntOption;

/* HTTP version option: sets http_version field to a specific value */
typedef struct
{
  int opt_val;
  TcurlHttpVersion version;
} HttpVersionOption;

/* HTTP method mapping for Tcurl_get_http_method */
typedef struct
{
  const char *name;
  SocketHTTP_Method method;
} HttpMethodEntry;

/* Boolean options table */
static const BoolOption bool_options[] = {
  { 'O', offsetof (TcurlOptions, remote_name) },
  { 'L', offsetof (TcurlOptions, follow_redirects) },
  { 'k', offsetof (TcurlOptions, insecure) },
  { 'v', offsetof (TcurlOptions, verbose) },
  { 's', offsetof (TcurlOptions, silent) },
  { 'S', offsetof (TcurlOptions, show_error) },
  { 'i', offsetof (TcurlOptions, include_headers) },
  { 'f', offsetof (TcurlOptions, fail_on_error) },
  { 'h', offsetof (TcurlOptions, show_help) },
  { 'V', offsetof (TcurlOptions, show_version) },
  { OPT_COMPRESSED, offsetof (TcurlOptions, compressed) },
  { 0, 0 }
};

/* String options table */
static const StringOption string_options[] = {
  { 'X', offsetof (TcurlOptions, method) },
  { 'o', offsetof (TcurlOptions, output_file) },
  { 'x', offsetof (TcurlOptions, proxy) },
  { 'u', offsetof (TcurlOptions, user) },
  { 'b', offsetof (TcurlOptions, cookie_file) },
  { 'c', offsetof (TcurlOptions, cookie_jar) },
  { 'A', offsetof (TcurlOptions, user_agent) },
  { 'e', offsetof (TcurlOptions, referer) },
  { 'w', offsetof (TcurlOptions, write_out) },
  { 0, 0 }
};

/* Integer options table */
static const IntOption int_options[] = {
  { OPT_CONNECT_TIMEOUT, offsetof (TcurlOptions, connect_timeout),
    "connect-timeout" },
  { 'm', offsetof (TcurlOptions, max_time), "max-time" },
  { OPT_MAX_REDIRS, offsetof (TcurlOptions, max_redirects), "max-redirs" },
  { OPT_RETRY, offsetof (TcurlOptions, retry_count), "retry count" },
  { 0, 0, NULL }
};

/* HTTP version options table */
static const HttpVersionOption http_version_options[] = {
  { OPT_HTTP2, TCURL_HTTP_2 },
  { OPT_HTTP11, TCURL_HTTP_1_1 },
  { OPT_HTTP10, TCURL_HTTP_1_0 },
  { 0, 0 }
};

/* HTTP method lookup table */
static const HttpMethodEntry http_methods[] = {
  { "GET", HTTP_METHOD_GET },       { "HEAD", HTTP_METHOD_HEAD },
  { "POST", HTTP_METHOD_POST },     { "PUT", HTTP_METHOD_PUT },
  { "DELETE", HTTP_METHOD_DELETE }, { "OPTIONS", HTTP_METHOD_OPTIONS },
  { "PATCH", HTTP_METHOD_PATCH },   { "TRACE", HTTP_METHOD_TRACE },
  { "CONNECT", HTTP_METHOD_CONNECT }, { NULL, HTTP_METHOD_GET }
};

/*
 * Generic option handlers
 */

static int
handle_bool_option (TcurlOptions *opts, int opt_val)
{
  for (const BoolOption *entry = bool_options; entry->opt_val; entry++)
    {
      if (entry->opt_val == opt_val)
        {
          *(int *)((char *)opts + entry->offset) = 1;
          return 1;
        }
    }
  return 0;
}

static int
handle_string_option (TcurlOptions *opts, int opt_val, const char *optarg)
{
  for (const StringOption *entry = string_options; entry->opt_val; entry++)
    {
      if (entry->opt_val == opt_val)
        {
          *(const char **)((char *)opts + entry->offset) = optarg;
          return 1;
        }
    }
  return 0;
}

static int
parse_positive_long (const char *str, const char *option_name, long *result)
{
  char *endptr;
  errno = 0;
  long val = strtol (str, &endptr, CURL_DECIMAL_BASE);
  if (errno != 0 || *endptr != '\0' || val < 0 || val > INT_MAX)
    {
      fprintf (stderr, "tcurl: Invalid %s: %s\n", option_name, str);
      return -1;
    }
  *result = val;
  return 0;
}

static int
handle_int_option (TcurlOptions *opts, int opt_val, const char *optarg)
{
  for (const IntOption *entry = int_options; entry->opt_val; entry++)
    {
      if (entry->opt_val == opt_val)
        {
          long val;
          if (parse_positive_long (optarg, entry->name, &val) != 0)
            return -1;
          *(int *)((char *)opts + entry->offset) = (int)val;
          return 1;
        }
    }
  return 0;
}

static int
handle_http_version_option (TcurlOptions *opts, int opt_val)
{
  for (const HttpVersionOption *entry = http_version_options; entry->opt_val;
       entry++)
    {
      if (entry->opt_val == opt_val)
        {
          opts->http_version = entry->version;
          return 1;
        }
    }
  return 0;
}

/*
 * Special-case option handlers (options with side effects)
 */

static int
handle_data_option (TcurlOptions *opts, const char *optarg)
{
  opts->data = optarg;
  opts->data_len = strlen (optarg);
  if (!opts->method)
    opts->method = "POST";
  return 0;
}

static int
handle_form_option (TcurlOptions *opts, const char *optarg)
{
  opts->form_data = optarg;
  if (!opts->method)
    opts->method = "POST";
  return 0;
}

static int
handle_header_option (TcurlOptions *opts, const char *optarg)
{
  if (Tcurl_add_header (opts, optarg) < 0)
    {
      fprintf (stderr, "tcurl: Failed to add header\n");
      return -1;
    }
  return 0;
}

static int
handle_head_option (TcurlOptions *opts)
{
  opts->head_only = 1;
  opts->method = "HEAD";
  return 0;
}

static int
handle_fail_with_body_option (TcurlOptions *opts)
{
  opts->fail_on_error = 1;
  opts->fail_with_body = 1;
  return 0;
}

/*
 * Main option dispatch
 */

static int
process_option (TcurlOptions *opts, int opt, const char *optarg)
{
  /* Try data-driven handlers first */
  if (handle_bool_option (opts, opt))
    return 0;
  if (handle_string_option (opts, opt, optarg))
    return 0;

  int int_result = handle_int_option (opts, opt, optarg);
  if (int_result != 0)
    return (int_result < 0) ? -1 : 0;

  if (handle_http_version_option (opts, opt))
    return 0;

  /* Special-case handlers */
  switch (opt)
    {
    case 'H':
      return handle_header_option (opts, optarg);
    case 'd':
    case OPT_DATA_RAW:
    case OPT_DATA_BINARY:
      return handle_data_option (opts, optarg);
    case 'F':
      return handle_form_option (opts, optarg);
    case 'I':
      return handle_head_option (opts);
    case OPT_FAIL_WITH_BODY:
      return handle_fail_with_body_option (opts);
    default:
      return 0;
    }
}

/*
 * Public API
 */

void
Tcurl_options_init (TcurlOptions *opts)
{
  if (!opts)
    return;

  memset (opts, 0, sizeof (*opts));

  opts->user_agent = DEFAULT_USER_AGENT;
  opts->connect_timeout = DEFAULT_CONNECT_TIMEOUT;
  opts->max_time = DEFAULT_MAX_TIME;
  opts->follow_redirects = 0;
  opts->max_redirects = CURL_DEFAULT_MAX_REDIRECTS;
  opts->http_version = TCURL_HTTP_DEFAULT;
  opts->compressed = 0;
  opts->fail_on_error = 0;
  opts->show_error = 0;
}

void
Tcurl_options_free (TcurlOptions *opts)
{
  if (!opts)
    return;

  for (int i = 0; i < opts->header_count; i++)
    free (opts->headers[i]);
  free (opts->headers);

  if (opts->data_allocated)
    free ((void *)opts->data);

  memset (opts, 0, sizeof (*opts));
}

int
Tcurl_add_header (TcurlOptions *opts, const char *header)
{
  if (!opts || !header)
    return -1;

  char **new_headers
      = realloc (opts->headers, (opts->header_count + 1) * sizeof (char *));
  if (!new_headers)
    return -1;

  opts->headers = new_headers;
  opts->headers[opts->header_count] = strdup (header);
  if (!opts->headers[opts->header_count])
    return -1;

  opts->header_count++;
  return 0;
}

static const char *
get_filename_from_url (const char *url, char *buf, size_t buf_size)
{
  if (!url || !buf || buf_size == 0)
    return NULL;

  const char *last_slash = strrchr (url, '/');
  if (!last_slash || last_slash[1] == '\0')
    return NULL;

  const char *filename = last_slash + 1;

  /* Security checks */
  if (filename[0] == '/' || strchr (filename, '%') || strstr (filename, ".."))
    return NULL;

  const char *query = strchr (filename, '?');
  if (query)
    {
      size_t len = query - filename;
      if (len >= buf_size)
        len = buf_size - 1;
      memcpy (buf, filename, len);
      buf[len] = '\0';

      if (strstr (buf, "..") || strchr (buf, '%'))
        return NULL;

      return buf;
    }

  return filename;
}

int
Tcurl_parse_args (int argc, char **argv, TcurlOptions *opts)
{
  if (!opts)
    return -1;

  Tcurl_options_init (opts);

  int opt;
  int option_index = 0;
  optind = 1;

  while ((opt = getopt_long (argc, argv, short_options, long_options,
                             &option_index))
         != -1)
    {
      if (opt == '?')
        return -1;

      int result = process_option (opts, opt, optarg);
      if (result != 0)
        return result;

      if (opts->show_help || opts->show_version)
        return 0;
    }

  if (optind < argc)
    {
      opts->url = argv[optind];

      if (opts->remote_name && !opts->output_file)
        {
          static _Thread_local char filename_buf[CURL_MAX_FILENAME_LEN];
          opts->output_file
              = get_filename_from_url (opts->url, filename_buf,
                                       sizeof (filename_buf));
          if (!opts->output_file)
            {
              fprintf (stderr, "tcurl: Cannot extract filename from URL\n");
              return -1;
            }
        }
    }

  return 0;
}

int
Tcurl_validate_args (const TcurlOptions *opts)
{
  if (!opts)
    return -1;

  if (!opts->show_help && !opts->show_version && !opts->url)
    {
      fprintf (stderr, "tcurl: No URL specified\n");
      return -1;
    }

  if (opts->method)
    {
      int valid = 0;
      for (const HttpMethodEntry *entry = http_methods; entry->name; entry++)
        {
          if (strcasecmp (opts->method, entry->name) == 0)
            {
              valid = 1;
              break;
            }
        }
      if (!valid)
        {
          fprintf (stderr, "tcurl: Unknown method: %s\n", opts->method);
          return -1;
        }
    }

  if (opts->connect_timeout < 0)
    {
      fprintf (stderr, "tcurl: Invalid connect-timeout\n");
      return -1;
    }

  if (opts->max_time < 0)
    {
      fprintf (stderr, "tcurl: Invalid max-time\n");
      return -1;
    }

  return 0;
}

void
Tcurl_print_usage (const char *progname)
{
  const char *name = progname ? progname : "tcurl";

  printf ("Usage: %s [options] <url>\n", name);
  printf ("\n");
  printf ("Transfer data from or to a server using HTTP/HTTPS.\n");
  printf ("\n");
  printf ("Options:\n");
  printf ("  -X, --request METHOD     HTTP method (GET, POST, PUT, DELETE, "
          "etc.)\n");
  printf ("  -H, --header HEADER      Add header (can be used multiple "
          "times)\n");
  printf ("  -d, --data DATA          POST data (implies -X POST)\n");
  printf ("  -F, --form DATA          Multipart form data\n");
  printf ("  -o, --output FILE        Write response body to file\n");
  printf ("  -O, --remote-name        Write to file named from URL\n");
  printf ("  -L, --location           Follow redirects\n");
  printf ("  -k, --insecure           Skip TLS certificate verification\n");
  printf ("  -x, --proxy URL          Use proxy (http://host:port, "
          "socks5://host:port)\n");
  printf ("  -u, --user USER:PASS     Authentication credentials\n");
  printf ("  -b, --cookie FILE        Read cookies from file\n");
  printf ("  -c, --cookie-jar FILE    Write cookies to file\n");
  printf ("  -A, --user-agent STRING  Set User-Agent header\n");
  printf ("  -e, --referer URL        Set Referer header\n");
  printf ("  -v, --verbose            Verbose output (show headers)\n");
  printf ("  -s, --silent             Silent mode (no progress)\n");
  printf ("  -S, --show-error         Show errors in silent mode\n");
  printf ("  -i, --include            Include response headers in output\n");
  printf ("  -I, --head               HEAD request (headers only)\n");
  printf ("  -w, --write-out FORMAT   Custom output format\n");
  printf ("  -f, --fail               Fail silently on HTTP errors\n");
  printf ("      --http2              Prefer HTTP/2\n");
  printf ("      --http1.1            Force HTTP/1.1\n");
  printf ("      --connect-timeout SEC  Connection timeout\n");
  printf ("  -m, --max-time SEC       Total timeout\n");
  printf ("      --compressed         Request compressed response\n");
  printf ("      --max-redirs NUM     Maximum number of redirects\n");
  printf ("      --retry NUM          Number of retries on failure\n");
  printf ("  -h, --help               Show this help\n");
  printf ("  -V, --version            Show version\n");
  printf ("\n");
  printf ("Examples:\n");
  printf ("  %s https://example.com\n", name);
  printf ("  %s -o file.txt https://example.com/file.txt\n", name);
  printf ("  %s -X POST -d 'key=value' https://api.example.com/data\n", name);
  printf ("  %s -H 'Authorization: Bearer token' https://api.example.com\n",
          name);
  printf ("\n");
}

void
Tcurl_print_version (void)
{
  printf ("tcurl 1.0.0\n");
  printf ("Built with tetsuo-curl socket library\n");
  printf ("Copyright (c) 2025 Tetsuo AI\n");
}

SocketHTTP_Method
Tcurl_get_http_method (const TcurlOptions *opts)
{
  if (!opts || !opts->method)
    return HTTP_METHOD_GET;

  for (const HttpMethodEntry *entry = http_methods; entry->name; entry++)
    {
      if (strcasecmp (opts->method, entry->name) == 0)
        return entry->method;
    }

  return HTTP_METHOD_GET;
}
