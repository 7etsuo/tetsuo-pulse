// clang-format off
/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 *
 * tetsuo_curl.c - A curl-like HTTP client using the Simple API
 *
 * Demonstrates the Simple HTTP API with all features working for all methods.
 *
 * Usage:
 *   ./tetsuo_curl [options] <url>
 *
 * Options:
 *   -X, --request METHOD   HTTP method (GET, POST, PUT, DELETE, HEAD, PATCH, OPTIONS)
 *   -d, --data DATA        Request body (implies POST if no -X)
 *   -H, --header HEADER    Add header (can be used multiple times)
 *   -o, --output FILE      Write output to file instead of stdout
 *   -i, --include          Include response headers in output
 *   -I, --head             HEAD request (headers only)
 *   -s, --silent           Silent mode (no progress/errors to stderr)
 *   -v, --verbose          Verbose output (show request details)
 *   -k, --insecure         Allow insecure TLS connections
 *   -A, --user-agent STR   Set User-Agent header
 *   -u, --user USER:PASS   Basic authentication
 *   --connect-timeout SEC  Connection timeout in seconds
 *   -h, --help             Show this help
 *
 * Examples:
 *   ./tetsuo_curl https://httpbin.org/get
 *   ./tetsuo_curl -H "Accept: application/json" https://httpbin.org/get
 *   ./tetsuo_curl -u user:pass https://httpbin.org/basic-auth/user/pass
 *   ./tetsuo_curl -X POST -d '{"key":"value"}' -H "Content-Type: application/json" https://httpbin.org/post
 *   ./tetsuo_curl -X PUT -H "X-Custom: value" -d "data" https://httpbin.org/put
 */
// clang-format on

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "simple/SocketSimple.h"

#define MAX_HEADERS 64
#define CREDENTIAL_SIZE 256
#define DEFAULT_TIMEOUT 30
#define MAX_TIMEOUT 3600
#define MIN_URL_LENGTH 8

typedef struct
{
  const char *method;
  const char *url;
  const char *data;
  const char *output_file;
  const char *user_agent;
  const char *auth_user;
  const char *auth_pass;
  const char *headers[MAX_HEADERS + 1]; /* +1 for NULL terminator */
  int header_count;
  int include_headers;
  int head_only;
  int silent;
  int verbose;
  int insecure;
  int connect_timeout;
  char user_buf[CREDENTIAL_SIZE];
  char pass_buf[CREDENTIAL_SIZE];
} Options;

static Options opts = { .method = "GET", .connect_timeout = DEFAULT_TIMEOUT };

static void print_usage (const char *progname);
static int parse_options (int argc, char **argv);
static void verbose_print (const char *fmt, ...);
static void error_print (const char *fmt, ...);
static int validate_method (const char *method);
static SocketSimple_HTTPMethod get_http_method (void);
static const char *get_status_text (int code);
static int perform_request (void);

int
main (int argc, char **argv)
{
  if (argc < 2)
    {
      print_usage (argv[0]);
      return 1;
    }

  if (parse_options (argc, argv) < 0)
    return 1;

  return perform_request () < 0 ? 1 : 0;
}

static void
print_usage (const char *progname)
{
  fprintf (stderr,
           "Usage: %s [options] <url>\n"
           "\n"
           "A curl-like HTTP client using the Simple API.\n"
           "\n"
           "Options:\n"
           "  -X, --request METHOD   HTTP method (default: GET)\n"
           "  -d, --data DATA        Request body (implies POST)\n"
           "  -H, --header HEADER    Add header (repeatable)\n"
           "  -o, --output FILE      Write to file\n"
           "  -i, --include          Include headers in output\n"
           "  -I, --head             HEAD request only\n"
           "  -s, --silent           Silent mode\n"
           "  -v, --verbose          Verbose output\n"
           "  -k, --insecure         Skip TLS verification\n"
           "  -A, --user-agent STR   User-Agent string\n"
           "  -u, --user USER:PASS   Basic authentication\n"
           "  --connect-timeout SEC  Timeout (default: %d)\n"
           "  -h, --help             Show help\n"
           "\n"
           "Examples:\n"
           "  %s https://httpbin.org/get\n"
           "  %s -H 'Accept: application/json' https://httpbin.org/get\n"
           "  %s -u user:pass https://httpbin.org/basic-auth/user/pass\n"
           "  %s -X POST -d '{\"x\":1}' -H 'Content-Type: application/json' "
           "https://httpbin.org/post\n"
           "\n",
           progname, DEFAULT_TIMEOUT, progname, progname, progname, progname);
}

static int
parse_auth (const char *auth)
{
  const char *colon = strchr (auth, ':');
  if (!colon)
    {
      fprintf (stderr, "Error: -u requires USER:PASS format\n");
      return -1;
    }

  size_t user_len = (size_t)(colon - auth);
  if (user_len >= CREDENTIAL_SIZE)
    user_len = CREDENTIAL_SIZE - 1;

  memcpy (opts.user_buf, auth, user_len);
  opts.user_buf[user_len] = '\0';

  size_t pass_len = strlen (colon + 1);
  if (pass_len >= CREDENTIAL_SIZE)
    pass_len = CREDENTIAL_SIZE - 1;

  memcpy (opts.pass_buf, colon + 1, pass_len);
  opts.pass_buf[pass_len] = '\0';

  opts.auth_user = opts.user_buf;
  opts.auth_pass = opts.pass_buf;
  return 0;
}

static int
parse_timeout (const char *str, int *out)
{
  if (!str || !*str)
    {
      fprintf (stderr, "Error: timeout value cannot be empty\n");
      return -1;
    }

  char *endptr;
  errno = 0;
  long val = strtol (str, &endptr, 10);

  if (errno == ERANGE || val < 0 || val > MAX_TIMEOUT)
    {
      fprintf (stderr, "Error: timeout must be 0-%d seconds\n", MAX_TIMEOUT);
      return -1;
    }

  if (*endptr != '\0')
    {
      fprintf (stderr, "Error: invalid timeout value '%s'\n", str);
      return -1;
    }

  *out = (int)val;
  return 0;
}

static int
validate_url (const char *url)
{
  if (!url || strlen (url) < MIN_URL_LENGTH)
    {
      fprintf (stderr, "Error: invalid URL\n");
      return -1;
    }

  if (strncmp (url, "http://", 7) != 0 && strncmp (url, "https://", 8) != 0)
    {
      fprintf (stderr, "Error: URL must start with http:// or https://\n");
      return -1;
    }

  return 0;
}

static int
parse_options (int argc, char **argv)
{
  static struct option long_options[]
      = { { "request", required_argument, 0, 'X' },
          { "data", required_argument, 0, 'd' },
          { "header", required_argument, 0, 'H' },
          { "output", required_argument, 0, 'o' },
          { "include", no_argument, 0, 'i' },
          { "head", no_argument, 0, 'I' },
          { "silent", no_argument, 0, 's' },
          { "verbose", no_argument, 0, 'v' },
          { "insecure", no_argument, 0, 'k' },
          { "user-agent", required_argument, 0, 'A' },
          { "user", required_argument, 0, 'u' },
          { "connect-timeout", required_argument, 0, 't' },
          { "help", no_argument, 0, 'h' },
          { 0, 0, 0, 0 } };

  int c;
  while ((c = getopt_long (argc, argv, "X:d:H:o:iIsvkA:u:t:h", long_options,
                           NULL))
         != -1)
    {
      switch (c)
        {
        case 'X':
          opts.method = optarg;
          break;
        case 'd':
          opts.data = optarg;
          if (strcasecmp (opts.method, "GET") == 0)
            opts.method = "POST";
          break;
        case 'H':
          if (opts.header_count < MAX_HEADERS)
            opts.headers[opts.header_count++] = optarg;
          else
            fprintf (stderr, "Warning: too many headers, ignoring: %s\n",
                     optarg);
          break;
        case 'o':
          opts.output_file = optarg;
          break;
        case 'i':
          opts.include_headers = 1;
          break;
        case 'I':
          opts.head_only = 1;
          opts.method = "HEAD";
          break;
        case 's':
          opts.silent = 1;
          break;
        case 'v':
          opts.verbose = 1;
          break;
        case 'k':
          opts.insecure = 1;
          break;
        case 'A':
          opts.user_agent = optarg;
          break;
        case 'u':
          if (parse_auth (optarg) < 0)
            return -1;
          break;
        case 't':
          if (parse_timeout (optarg, &opts.connect_timeout) < 0)
            return -1;
          break;
        case 'h':
          print_usage (argv[0]);
          exit (0);
        default:
          return -1;
        }
    }

  if (optind >= argc)
    {
      if (!opts.silent)
        {
          fprintf (stderr, "Error: URL required\n");
          print_usage (argv[0]);
        }
      return -1;
    }

  opts.url = argv[optind];
  opts.headers[opts.header_count] = NULL; /* NULL terminate for API */

  if (validate_method (opts.method) < 0)
    return -1;

  return validate_url (opts.url);
}

static int
validate_method (const char *method)
{
  if (strcasecmp (method, "GET") == 0 || strcasecmp (method, "POST") == 0
      || strcasecmp (method, "PUT") == 0 || strcasecmp (method, "DELETE") == 0
      || strcasecmp (method, "HEAD") == 0 || strcasecmp (method, "PATCH") == 0
      || strcasecmp (method, "OPTIONS") == 0)
    return 0;

  fprintf (stderr, "Error: unknown HTTP method '%s'\n", method);
  fprintf (stderr, "Supported: GET, POST, PUT, DELETE, HEAD, PATCH, OPTIONS\n");
  return -1;
}

static void
verbose_print (const char *fmt, ...)
{
  if (!opts.verbose)
    return;

  va_list ap;
  va_start (ap, fmt);
  fprintf (stderr, "> ");
  vfprintf (stderr, fmt, ap);
  va_end (ap);
}

static void
error_print (const char *fmt, ...)
{
  if (opts.silent)
    return;

  va_list ap;
  va_start (ap, fmt);
  fprintf (stderr, "tetsuo_curl: ");
  vfprintf (stderr, fmt, ap);
  va_end (ap);
}

static SocketSimple_HTTPMethod
get_http_method (void)
{
  if (strcasecmp (opts.method, "GET") == 0)
    return SIMPLE_HTTP_GET;
  if (strcasecmp (opts.method, "POST") == 0)
    return SIMPLE_HTTP_POST;
  if (strcasecmp (opts.method, "PUT") == 0)
    return SIMPLE_HTTP_PUT;
  if (strcasecmp (opts.method, "DELETE") == 0)
    return SIMPLE_HTTP_DELETE;
  if (strcasecmp (opts.method, "HEAD") == 0)
    return SIMPLE_HTTP_HEAD;
  if (strcasecmp (opts.method, "PATCH") == 0)
    return SIMPLE_HTTP_PATCH;
  if (strcasecmp (opts.method, "OPTIONS") == 0)
    return SIMPLE_HTTP_OPTIONS;
  return SIMPLE_HTTP_GET;
}

static const char *
get_status_text (int code)
{
  switch (code)
    {
    case 100:
      return "Continue";
    case 101:
      return "Switching Protocols";
    case 200:
      return "OK";
    case 201:
      return "Created";
    case 204:
      return "No Content";
    case 301:
      return "Moved Permanently";
    case 302:
      return "Found";
    case 304:
      return "Not Modified";
    case 307:
      return "Temporary Redirect";
    case 308:
      return "Permanent Redirect";
    case 400:
      return "Bad Request";
    case 401:
      return "Unauthorized";
    case 403:
      return "Forbidden";
    case 404:
      return "Not Found";
    case 405:
      return "Method Not Allowed";
    case 408:
      return "Request Timeout";
    case 429:
      return "Too Many Requests";
    case 500:
      return "Internal Server Error";
    case 502:
      return "Bad Gateway";
    case 503:
      return "Service Unavailable";
    case 504:
      return "Gateway Timeout";
    default:
      return "Unknown";
    }
}

static void
print_verbose_request (void)
{
  verbose_print ("%s %s\n", opts.method, opts.url);

  if (opts.user_agent)
    verbose_print ("User-Agent: %s\n", opts.user_agent);

  if (opts.auth_user)
    verbose_print ("Authorization: Basic <credentials>\n");

  for (int i = 0; i < opts.header_count; i++)
    verbose_print ("%s\n", opts.headers[i]);

  if (opts.data)
    {
      /* Show Content-Type if not already in headers */
      int has_content_type = 0;
      for (int i = 0; i < opts.header_count; i++)
        {
          if (strncasecmp (opts.headers[i], "Content-Type:", 13) == 0)
            {
              has_content_type = 1;
              break;
            }
        }
      if (!has_content_type)
        verbose_print ("Content-Type: application/x-www-form-urlencoded\n");

      verbose_print ("Content-Length: %zu\n", strlen (opts.data));
    }

  verbose_print ("\n");
}

static void
print_response_headers (const SocketSimple_HTTPResponse *resp, FILE *out)
{
  fprintf (out, "HTTP/1.1 %d %s\n", resp->status_code,
           get_status_text (resp->status_code));

  if (resp->content_type)
    fprintf (out, "Content-Type: %s\n", resp->content_type);

  if (resp->location)
    fprintf (out, "Location: %s\n", resp->location);

  if (resp->body_len > 0)
    fprintf (out, "Content-Length: %zu\n", resp->body_len);

  fprintf (out, "\n");
}

static int
perform_request (void)
{
  SocketSimple_HTTPResponse resp = { 0 };
  SocketSimple_HTTPOptions http_opts;
  FILE *out = NULL;
  int result = -1;

  /* Open output file */
  if (opts.output_file)
    {
      out = fopen (opts.output_file, "wb");
      if (!out)
        {
          error_print ("cannot open '%s': %s\n", opts.output_file,
                       strerror (errno));
          return -1;
        }
    }
  else
    {
      out = stdout;
    }

  /* Initialize options */
  Socket_simple_http_options_init (&http_opts);
  http_opts.connect_timeout_ms = opts.connect_timeout * 1000;
  http_opts.verify_ssl = opts.insecure ? 0 : 1;
  http_opts.auth_user = opts.auth_user;
  http_opts.auth_pass = opts.auth_pass;
  if (opts.user_agent)
    http_opts.user_agent = opts.user_agent;

  /* Print verbose request info */
  print_verbose_request ();

  /* Perform request using the generic function */
  if (Socket_simple_http_request (
          get_http_method (), opts.url,
          opts.header_count > 0 ? opts.headers : NULL, opts.data,
          opts.data ? strlen (opts.data) : 0, &http_opts, &resp)
      < 0)
    {
      error_print ("%s\n", Socket_simple_error ());
      goto cleanup;
    }

  /* Output response */
  if (opts.include_headers || opts.head_only)
    print_response_headers (&resp, out);

  if (!opts.head_only && resp.body && resp.body_len > 0)
    {
      if (fwrite (resp.body, 1, resp.body_len, out) != resp.body_len)
        {
          error_print ("write error: %s\n", strerror (errno));
          goto cleanup;
        }

      if (!opts.output_file && resp.body_len > 0)
        {
          if (resp.body[resp.body_len - 1] != '\n')
            fprintf (out, "\n");
        }
    }

  if (opts.verbose)
    {
      fprintf (stderr, "< HTTP %d %s\n", resp.status_code,
               get_status_text (resp.status_code));
      fprintf (stderr, "< Content-Length: %zu\n", resp.body_len);
    }

  result = 0;

cleanup:
  Socket_simple_http_response_free (&resp);
  if (opts.output_file && out)
    fclose (out);

  return result;
}
