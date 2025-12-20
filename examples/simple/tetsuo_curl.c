// clang-format off
/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 *
 * tetsuo_curl.c - A minimal curl-like HTTP client using the Simple API
 *
 * Demonstrates how little code is needed for a functional HTTP client.
 * Redirects are followed automatically (up to 10 hops).
 *
 * Usage:
 *   ./tetsuo_curl [options] <url>
 *
 * Options:
 *   -X, --request METHOD   HTTP method (GET, POST, PUT, DELETE, HEAD)
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
 *   ./tetsuo_curl -X POST -d '{"key":"value"}' -H "Content-Type: application/json" https://httpbin.org/post
 *   ./tetsuo_curl -o image.png https://example.com/image.png
 */
// clang-format on

#include <errno.h>
#include <getopt.h>
#include <simple/SocketSimple.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/** Maximum number of custom headers */
#define CURL_MAX_HEADERS 64

/** User-Agent header buffer size */
#define CURL_UA_HEADER_SIZE 512

/** Username/password buffer size */
#define CURL_CREDENTIAL_SIZE 256

/** Default connection timeout in seconds */
#define CURL_DEFAULT_TIMEOUT 30

/** Content-Type header prefix length ("Content-Type:") */
#define CONTENT_TYPE_PREFIX_LEN 13

/** Program version string */
#define CURL_VERSION "1.0"

/**
 * @brief Command-line options structure.
 */
typedef struct
{
  const char *method;
  const char *url;
  const char *data;
  const char *output_file;
  const char *user_agent;
  const char *auth_user;
  const char *auth_pass;
  const char *headers[CURL_MAX_HEADERS];
  int header_count;
  int include_headers;
  int head_only;
  int silent;
  int verbose;
  int insecure;
  int connect_timeout;
  char user_buf[CURL_CREDENTIAL_SIZE];
  char pass_buf[CURL_CREDENTIAL_SIZE];
} CurlOptions;

static CurlOptions opts
    = { .method = "GET", .connect_timeout = CURL_DEFAULT_TIMEOUT };

static void print_usage (const char *progname);
static int parse_auth (const char *auth);
static int parse_options (int argc, char **argv);
static void verbose_print (const char *fmt, ...);
static void error_print (const char *fmt, ...);
static const char *get_status_text (int code);
static int write_output (const void *data, size_t len, FILE *out);
static const char *find_content_type (void);

/* Request execution subroutines */
static FILE *open_output_file (void);
static int build_headers_array (const char **headers, char *ua_buf,
                                size_t ua_size);
static void print_verbose_request (const char *url, const char **headers,
                                   int header_count);
static int execute_http_method (const char *url, const char **headers,
                                int header_count,
                                SocketSimple_HTTPResponse *resp);
static void print_response_headers (const SocketSimple_HTTPResponse *resp,
                                    FILE *out);
static int print_response_body (const SocketSimple_HTTPResponse *resp,
                                FILE *out);
static void print_verbose_response (const SocketSimple_HTTPResponse *resp);
static int perform_request (void);

int
main (int argc, char **argv)
{
  int ret;

  if (argc < 2)
    {
      print_usage (argv[0]);
      return 1;
    }

  if (parse_options (argc, argv) < 0)
    {
      return 1;
    }

  ret = perform_request ();

  return ret < 0 ? 1 : 0;
}

/**
 * print_usage - Display program usage information
 * @progname: Program name for usage display
 */
static void
print_usage (const char *progname)
{
  fprintf (stderr,
           "Usage: %s [options] <url>\n"
           "\n"
           "A minimal curl-like HTTP client using the Simple API.\n"
           "Redirects are followed automatically (up to 10 hops).\n"
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
           "  %s -d '{\"x\":1}' -H 'Content-Type: application/json' "
           "https://httpbin.org/post\n"
           "  %s -o page.html https://example.com\n"
           "\n",
           progname, CURL_DEFAULT_TIMEOUT, progname, progname, progname);
}

/**
 * parse_auth - Parse USER:PASS authentication string
 * @auth: Authentication string in "user:pass" format
 *
 * Returns: 0 on success, -1 on error
 */
static int
parse_auth (const char *auth)
{
  const char *colon;
  size_t user_len;

  colon = strchr (auth, ':');
  if (!colon)
    {
      fprintf (stderr, "Error: -u requires USER:PASS format\n");
      return -1;
    }

  user_len = (size_t)(colon - auth);
  if (user_len >= CURL_CREDENTIAL_SIZE)
    {
      user_len = CURL_CREDENTIAL_SIZE - 1;
    }

  memcpy (opts.user_buf, auth, user_len);
  opts.user_buf[user_len] = '\0';

  /* Copy password with proper bounds checking */
  size_t pass_len = strlen (colon + 1);
  if (pass_len >= CURL_CREDENTIAL_SIZE)
    {
      pass_len = CURL_CREDENTIAL_SIZE - 1;
    }
  memcpy (opts.pass_buf, colon + 1, pass_len);
  opts.pass_buf[pass_len] = '\0';

  opts.auth_user = opts.user_buf;
  opts.auth_pass = opts.pass_buf;
  return 0;
}

/**
 * parse_options - Parse command-line options
 * @argc: Argument count
 * @argv: Argument vector
 *
 * Returns: 0 on success, -1 on error
 */
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
          if (strcmp (opts.method, "GET") == 0)
            {
              opts.method = "POST";
            }
          break;
        case 'H':
          if (opts.header_count < CURL_MAX_HEADERS)
            {
              opts.headers[opts.header_count++] = optarg;
            }
          else
            {
              fprintf (stderr, "Warning: too many headers, ignoring: %s\n",
                       optarg);
            }
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
            {
              return -1;
            }
          break;
        case 't':
          opts.connect_timeout = atoi (optarg);
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
  return 0;
}

/**
 * verbose_print - Print verbose output to stderr
 * @fmt: Format string
 * @...: Format arguments
 */
static void
verbose_print (const char *fmt, ...)
{
  va_list ap;

  if (!opts.verbose)
    {
      return;
    }

  va_start (ap, fmt);
  fprintf (stderr, "> ");
  vfprintf (stderr, fmt, ap);
  va_end (ap);
}

/**
 * error_print - Print error message to stderr
 * @fmt: Format string
 * @...: Format arguments
 */
static void
error_print (const char *fmt, ...)
{
  va_list ap;

  if (opts.silent)
    {
      return;
    }

  va_start (ap, fmt);
  fprintf (stderr, "tetsuo_curl: ");
  vfprintf (stderr, fmt, ap);
  va_end (ap);
}

/**
 * get_status_text - Get human-readable HTTP status text
 * @code: HTTP status code
 *
 * Returns: Status text string
 */
static const char *
get_status_text (int code)
{
  switch (code)
    {
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
    case 400:
      return "Bad Request";
    case 401:
      return "Unauthorized";
    case 403:
      return "Forbidden";
    case 404:
      return "Not Found";
    case 500:
      return "Internal Server Error";
    case 502:
      return "Bad Gateway";
    case 503:
      return "Service Unavailable";
    default:
      return "Unknown";
    }
}

/**
 * write_output - Write data to output file
 * @data: Data to write
 * @len: Data length
 * @out: Output file handle
 *
 * Returns: 0 on success, -1 on error
 */
static int
write_output (const void *data, size_t len, FILE *out)
{
  size_t written;

  written = fwrite (data, 1, len, out);
  if (written != len)
    {
      error_print ("write error: %s\n", strerror (errno));
      return -1;
    }
  return 0;
}

/**
 * find_content_type - Find Content-Type header in custom headers
 *
 * Returns: Content-Type value or NULL if not found
 */
static const char *
find_content_type (void)
{
  for (int i = 0; i < opts.header_count; i++)
    {
      if (strncasecmp (opts.headers[i],
                       "Content-Type:", CONTENT_TYPE_PREFIX_LEN)
          == 0)
        {
          const char *value = opts.headers[i] + CONTENT_TYPE_PREFIX_LEN;
          while (*value == ' ')
            {
              value++;
            }
          return value;
        }
    }
  return NULL;
}

/**
 * open_output_file - Open output file for writing response
 *
 * Returns: FILE pointer (stdout if no file specified), NULL on error
 */
static FILE *
open_output_file (void)
{
  if (!opts.output_file)
    return stdout;

  FILE *out = fopen (opts.output_file, "wb");
  if (!out)
    {
      error_print ("cannot open '%s': %s\n", opts.output_file,
                   strerror (errno));
    }
  return out;
}

/**
 * build_headers_array - Build NULL-terminated headers array
 * @headers: Output array for header pointers
 * @ua_buf: Buffer for User-Agent header string
 * @ua_size: Size of ua_buf
 *
 * Returns: Number of headers added
 */
static int
build_headers_array (const char **headers, char *ua_buf, size_t ua_size)
{
  int count = 0;

  if (opts.user_agent)
    {
      snprintf (ua_buf, ua_size, "User-Agent: %s", opts.user_agent);
      headers[count++] = ua_buf;
    }

  for (int i = 0; i < opts.header_count; i++)
    {
      headers[count++] = opts.headers[i];
    }

  headers[count] = NULL;
  return count;
}

/**
 * print_verbose_request - Print request details in verbose mode
 * @url: Request URL
 * @headers: Headers array
 * @header_count: Number of headers
 */
static void
print_verbose_request (const char *url, const char **headers, int header_count)
{
  verbose_print ("%s %s\n", opts.method, url);

  for (int i = 0; i < header_count; i++)
    {
      verbose_print ("%s\n", headers[i]);
    }

  if (opts.data)
    {
      verbose_print ("Content-Length: %zu\n", strlen (opts.data));
    }

  verbose_print ("\n");
}

/**
 * execute_http_method - Execute HTTP request based on method
 * @url: Request URL
 * @headers: Headers array (NULL-terminated)
 * @header_count: Number of headers
 * @resp: Output response structure
 *
 * Returns: 0 on success, -1 on error
 */
static int
execute_http_method (const char *url, const char **headers, int header_count,
                     SocketSimple_HTTPResponse *resp)
{
  const char *content_type;
  int result;

  if (strcmp (opts.method, "GET") == 0 || strcmp (opts.method, "HEAD") == 0)
    {
      if (header_count > 0)
        result = Socket_simple_http_get_ex (url, headers, resp);
      else
        result = Socket_simple_http_get (url, resp);
    }
  else if (strcmp (opts.method, "POST") == 0)
    {
      content_type = find_content_type ();
      if (!content_type)
        content_type = "application/x-www-form-urlencoded";

      result
          = Socket_simple_http_post (url, content_type, opts.data,
                                     opts.data ? strlen (opts.data) : 0, resp);
    }
  else if (strcmp (opts.method, "PUT") == 0)
    {
      content_type = find_content_type ();
      if (!content_type)
        content_type = "application/octet-stream";

      result
          = Socket_simple_http_put (url, content_type, opts.data,
                                    opts.data ? strlen (opts.data) : 0, resp);
    }
  else if (strcmp (opts.method, "DELETE") == 0)
    {
      result = Socket_simple_http_delete (url, resp);
    }
  else
    {
      error_print ("unsupported method: %s\n", opts.method);
      return -1;
    }

  if (result < 0)
    {
      error_print ("request failed: %s\n", Socket_simple_error ());
      return -1;
    }

  return 0;
}

/**
 * print_response_headers - Print HTTP response headers
 * @resp: Response containing headers
 * @out: Output file stream
 */
static void
print_response_headers (const SocketSimple_HTTPResponse *resp, FILE *out)
{
  if (!opts.include_headers && !opts.head_only)
    return;

  fprintf (out, "HTTP/1.1 %d %s\n", resp->status_code,
           get_status_text (resp->status_code));

  if (resp->content_type)
    fprintf (out, "Content-Type: %s\n", resp->content_type);

  if (resp->body_len > 0)
    fprintf (out, "Content-Length: %zu\n", resp->body_len);

  if (resp->location)
    fprintf (out, "Location: %s\n", resp->location);

  fprintf (out, "\n");
}

/**
 * print_response_body - Print HTTP response body
 * @resp: Response containing body
 * @out: Output file stream
 *
 * Returns: 0 on success, -1 on error
 */
static int
print_response_body (const SocketSimple_HTTPResponse *resp, FILE *out)
{
  if (opts.head_only || !resp->body || resp->body_len == 0)
    return 0;

  if (write_output (resp->body, resp->body_len, out) < 0)
    return -1;

  /* Add newline if output is terminal and body doesn't end with one */
  if (!opts.output_file && resp->body_len > 0
      && resp->body[resp->body_len - 1] != '\n')
    {
      fprintf (out, "\n");
    }

  return 0;
}

/**
 * print_verbose_response - Print response status in verbose mode
 * @resp: Response to display
 */
static void
print_verbose_response (const SocketSimple_HTTPResponse *resp)
{
  if (!opts.verbose)
    return;

  fprintf (stderr, "< HTTP %d %s\n", resp->status_code,
           get_status_text (resp->status_code));
  fprintf (stderr, "< Content-Length: %zu\n", resp->body_len);

  if (resp->content_type)
    fprintf (stderr, "< Content-Type: %s\n", resp->content_type);
}

/**
 * perform_request - Execute the HTTP request
 *
 * The Simple API automatically follows redirects (up to 10 hops).
 *
 * Returns: 0 on success, -1 on error
 */
static int
perform_request (void)
{
  SocketSimple_HTTPResponse resp = { 0 };
  const char *headers[CURL_MAX_HEADERS + 4];
  static char ua_header[CURL_UA_HEADER_SIZE];
  int header_count;
  int result = -1;
  FILE *out;

  /* Setup */
  out = open_output_file ();
  if (!out)
    return -1;

  header_count = build_headers_array (headers, ua_header, sizeof (ua_header));

  /* Show request in verbose mode */
  print_verbose_request (opts.url, headers, header_count);

  /* Execute request (redirects handled automatically by library) */
  if (execute_http_method (opts.url, headers, header_count, &resp) < 0)
    goto cleanup;

  /* Output response */
  print_response_headers (&resp, out);

  if (print_response_body (&resp, out) < 0)
    {
      result = -1;
      goto cleanup;
    }

  print_verbose_response (&resp);
  result = 0;

cleanup:
  Socket_simple_http_response_free (&resp);
  if (opts.output_file && out)
    fclose (out);

  return result;
}
