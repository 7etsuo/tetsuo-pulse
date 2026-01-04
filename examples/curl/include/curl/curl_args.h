/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file curl_args.h
 * @ingroup curl
 * @brief Command-line argument parsing for tcurl CLI tool.
 */

#ifndef CURL_ARGS_INCLUDED
#define CURL_ARGS_INCLUDED

#include "http/SocketHTTP.h"

/**
 * @brief HTTP version preference.
 */
typedef enum
{
  TCURL_HTTP_DEFAULT = 0,  /**< Auto-negotiate (prefer HTTP/2) */
  TCURL_HTTP_1_0,          /**< Force HTTP/1.0 */
  TCURL_HTTP_1_1,          /**< Force HTTP/1.1 */
  TCURL_HTTP_2             /**< Prefer HTTP/2 */
} TcurlHttpVersion;

/**
 * @brief Parsed command-line options.
 */
typedef struct
{
  /* URL and method */
  const char *url;           /**< Target URL */
  const char *method;        /**< HTTP method (NULL for GET) */

  /* Request data */
  const char *data;          /**< POST/PUT data */
  size_t data_len;           /**< Length of data */
  int data_allocated;        /**< Whether data was dynamically allocated */
  const char *form_data;     /**< Multipart form data */

  /* Headers */
  char **headers;            /**< Array of custom headers */
  int header_count;          /**< Number of headers */

  /* Output */
  const char *output_file;   /**< Output file path */
  int remote_name;           /**< Use remote filename (-O) */
  const char *write_out;     /**< Write-out format string */

  /* Behavior */
  int follow_redirects;      /**< Follow redirects (-L) */
  int max_redirects;         /**< Maximum redirects */
  int insecure;              /**< Skip TLS verification (-k) */
  int verbose;               /**< Verbose output (-v) */
  int silent;                /**< Silent mode (-s) */
  int show_error;            /**< Show errors in silent mode (-S) */
  int include_headers;       /**< Include headers in output (-i) */
  int head_only;             /**< HEAD request only (-I) */
  int compressed;            /**< Request compressed response */
  int fail_on_error;         /**< Fail on HTTP errors (-f) */
  int fail_with_body;        /**< Fail with body on HTTP errors */

  /* Timeouts */
  int connect_timeout;       /**< Connection timeout (seconds) */
  int max_time;              /**< Total timeout (seconds) */

  /* Protocol */
  TcurlHttpVersion http_version;  /**< HTTP version preference */

  /* Authentication */
  const char *user;          /**< user:password */

  /* Proxy */
  const char *proxy;         /**< Proxy URL */

  /* Cookies */
  const char *cookie_file;   /**< Cookie file to read */
  const char *cookie_jar;    /**< Cookie file to write */

  /* Other */
  const char *user_agent;    /**< User-Agent header */
  const char *referer;       /**< Referer header */
  int retry_count;           /**< Number of retries */

  /* Control flags */
  int show_help;             /**< Show help and exit */
  int show_version;          /**< Show version and exit */
} TcurlOptions;

/**
 * @brief Initialize options with defaults.
 * @param opts Options structure to initialize
 */
extern void Tcurl_options_init (TcurlOptions *opts);

/**
 * @brief Free resources in options structure.
 * @param opts Options structure to free
 */
extern void Tcurl_options_free (TcurlOptions *opts);

/**
 * @brief Add a header to the options.
 * @param opts Options structure
 * @param header Header string (will be copied)
 * @return 0 on success, -1 on failure
 */
extern int Tcurl_add_header (TcurlOptions *opts, const char *header);

/**
 * @brief Parse command-line arguments.
 * @param argc Argument count
 * @param argv Argument vector
 * @param opts Output options structure
 * @return 0 on success, -1 on failure
 */
extern int Tcurl_parse_args (int argc, char **argv, TcurlOptions *opts);

/**
 * @brief Validate parsed options.
 * @param opts Options to validate
 * @return 0 if valid, -1 if invalid
 */
extern int Tcurl_validate_args (const TcurlOptions *opts);

/**
 * @brief Print usage information.
 * @param progname Program name (argv[0])
 */
extern void Tcurl_print_usage (const char *progname);

/**
 * @brief Print version information.
 */
extern void Tcurl_print_version (void);

/**
 * @brief Convert method string to SocketHTTP_Method.
 * @param opts Options containing method string
 * @return HTTP method enum value
 */
extern SocketHTTP_Method Tcurl_get_http_method (const TcurlOptions *opts);

#endif /* CURL_ARGS_INCLUDED */
