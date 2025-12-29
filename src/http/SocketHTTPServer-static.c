/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTPServer-static.c
 * @brief Static file serving for HTTP server
 *
 * Implements static file serving with:
 * - Path traversal protection
 * - MIME type detection
 * - If-Modified-Since / 304 Not Modified
 * - Range requests / 206 Partial Content
 * - sendfile() for zero-copy transfer
 */

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <time.h>

#include "core/SocketError.h"
#include "core/SocketLog.h"
#include "core/SocketMetrics.h"
#include "core/SocketUtil.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"
#include "http/SocketHTTPServer-private.h"
#include "http/SocketHTTPServer.h"
#include "socket/Socket.h"

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "HTTPServer-Static"

/* Module exception handling */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketHTTPServer);

/* Maximum path length for static files */
#ifndef HTTPSERVER_STATIC_MAX_PATH
#define HTTPSERVER_STATIC_MAX_PATH 4096
#endif

/* MIME type mappings */
static const struct
{
  const char *extension;
  const char *mime_type;
} mime_types[] = {
  /* Text */
  { ".html", "text/html; charset=utf-8" },
  { ".htm", "text/html; charset=utf-8" },
  { ".css", "text/css; charset=utf-8" },
  { ".js", "text/javascript; charset=utf-8" },
  { ".mjs", "text/javascript; charset=utf-8" },
  { ".json", "application/json; charset=utf-8" },
  { ".xml", "application/xml; charset=utf-8" },
  { ".txt", "text/plain; charset=utf-8" },
  { ".csv", "text/csv; charset=utf-8" },
  { ".md", "text/markdown; charset=utf-8" },

  /* Images */
  { ".png", "image/png" },
  { ".jpg", "image/jpeg" },
  { ".jpeg", "image/jpeg" },
  { ".gif", "image/gif" },
  { ".webp", "image/webp" },
  { ".svg", "image/svg+xml" },
  { ".ico", "image/x-icon" },
  { ".bmp", "image/bmp" },
  { ".avif", "image/avif" },

  /* Fonts */
  { ".woff", "font/woff" },
  { ".woff2", "font/woff2" },
  { ".ttf", "font/ttf" },
  { ".otf", "font/otf" },
  { ".eot", "application/vnd.ms-fontobject" },

  /* Media */
  { ".mp3", "audio/mpeg" },
  { ".mp4", "video/mp4" },
  { ".webm", "video/webm" },
  { ".ogg", "audio/ogg" },
  { ".wav", "audio/wav" },

  /* Archives */
  { ".zip", "application/zip" },
  { ".gz", "application/gzip" },
  { ".tar", "application/x-tar" },

  /* Documents */
  { ".pdf", "application/pdf" },
  { ".wasm", "application/wasm" },

  { NULL, NULL }
};

/**
 * get_mime_type - Determine MIME type from file extension
 * @path: File path to check
 *
 * Returns: MIME type string or "application/octet-stream" for unknown
 */
static const char *
get_mime_type (const char *path)
{
  const char *ext;
  size_t path_len, ext_len;

  if (path == NULL)
    return "application/octet-stream";

  path_len = strlen (path);

  /* Find the last dot in the path */
  ext = strrchr (path, '.');
  if (ext == NULL)
    return "application/octet-stream";

  ext_len = path_len - (size_t)(ext - path);

  /* Check against known extensions (case-insensitive) */
  for (int i = 0; mime_types[i].extension != NULL; i++)
    {
      if (strlen (mime_types[i].extension) == ext_len
          && strcasecmp (ext, mime_types[i].extension) == 0)
        {
          return mime_types[i].mime_type;
        }
    }

  return "application/octet-stream";
}

/**
 * validate_static_path - Validate path for security (no traversal attacks)
 * @path: URL path component (after prefix removal)
 *
 * Returns: 1 if safe, 0 if potentially malicious
 */
static int
validate_static_path (const char *path)
{
  const char *p;

  if (path == NULL || path[0] == '\0')
    return 0;

  /* Reject absolute paths */
  if (path[0] == '/')
    return 0;

  /* Reject paths with null bytes (injection attack) */
  if (strchr (path, '\0') != path + strlen (path))
    return 0;

  /* Check for path traversal sequences */
  p = path;
  while (*p != '\0')
    {
      /* Check for ".." component */
      if (p[0] == '.')
        {
          if (p[1] == '.' && (p[2] == '/' || p[2] == '\0'))
            return 0; /* Found ".." */
          if (p[1] == '/' || p[1] == '\0')
            {
              /* Single "." is okay, skip */
              p += (p[1] == '/') ? 2 : 1;
              continue;
            }
        }

      /* Skip to next path component */
      while (*p != '\0' && *p != '/')
        p++;
      if (*p == '/')
        p++;
    }

  /* Reject hidden files (dotfiles) */
  p = path;
  while (*p != '\0')
    {
      if (*p == '.' && (p == path || *(p - 1) == '/'))
        {
          /* Hidden file/directory found */
          return 0;
        }
      p++;
    }

  return 1;
}

/**
 * format_http_date - Format time as HTTP-date (RFC 7231)
 * @t: Time to format
 * @buf: Output buffer (must be at least 30 bytes)
 *
 * Returns: Pointer to buf
 */
static char *
format_http_date (time_t t, char *buf)
{
  struct tm tm;
  gmtime_r (&t, &tm);
  strftime (buf, 30, "%a, %d %b %Y %H:%M:%S GMT", &tm);
  return buf;
}

/**
 * parse_http_date - Parse HTTP-date to time_t
 * @date_str: Date string in RFC 7231 format
 *
 * Returns: time_t value, or -1 on parse error
 */
static time_t
parse_http_date (const char *date_str)
{
  struct tm tm;
  memset (&tm, 0, sizeof (tm));

  if (date_str == NULL)
    return -1;

  /* Try RFC 7231 format: "Sun, 06 Nov 1994 08:49:37 GMT" */
  if (strptime (date_str, "%a, %d %b %Y %H:%M:%S GMT", &tm) != NULL)
    {
      return timegm (&tm);
    }

  /* Try RFC 850 format: "Sunday, 06-Nov-94 08:49:37 GMT" */
  if (strptime (date_str, "%A, %d-%b-%y %H:%M:%S GMT", &tm) != NULL)
    {
      return timegm (&tm);
    }

  /* Try ANSI C format: "Sun Nov  6 08:49:37 1994" */
  if (strptime (date_str, "%a %b %d %H:%M:%S %Y", &tm) != NULL)
    {
      return timegm (&tm);
    }

  return -1;
}

/**
 * parse_range_header - Parse Range header for partial content
 * @range_str: Range header value (e.g., "bytes=0-499")
 * @file_size: Total file size
 * @start: Output: start byte position
 * @end: Output: end byte position
 *
 * Returns: 1 if valid range parsed, 0 if invalid/unsatisfiable
 */
static int
parse_range_header (const char *range_str, off_t file_size, off_t *start,
                    off_t *end)
{
  const char *p;
  char *endptr;
  long long val;

  if (range_str == NULL || file_size <= 0)
    return 0;

  /* Must start with "bytes=" */
  if (strncmp (range_str, "bytes=", 6) != 0)
    return 0;

  p = range_str + 6;

  /* Skip whitespace */
  while (*p == ' ')
    p++;

  if (*p == '-')
    {
      /* Suffix range: "-500" means last 500 bytes */
      p++;
      val = strtoll (p, &endptr, 10);
      if (endptr == p || val <= 0)
        return 0;
      *start = (file_size > val) ? (file_size - val) : 0;
      *end = file_size - 1;
    }
  else
    {
      /* Normal range: "500-999" or "500-" */
      val = strtoll (p, &endptr, 10);
      if (endptr == p || val < 0)
        return 0;
      *start = (off_t)val;

      if (*endptr == '-')
        {
          p = endptr + 1;
          if (*p == '\0' || *p == ',')
            {
              /* Open-ended: "500-" means 500 to end */
              *end = file_size - 1;
            }
          else
            {
              val = strtoll (p, &endptr, 10);
              if (endptr == p)
                return 0;
              *end = (off_t)val;
            }
        }
      else
        {
          return 0;
        }
    }

  /* Validate range */
  if (*start >= file_size || *start > *end)
    return 0;

  /* Clamp end to file size */
  if (*end >= file_size)
    *end = file_size - 1;

  return 1;
}

/**
 * find_static_route - Find matching static route for request path
 * @server: HTTP server
 * @path: Request path
 *
 * Returns: Matching StaticRoute or NULL if no match
 */
StaticRoute *
server_find_static_route (SocketHTTPServer_T server, const char *path)
{
  StaticRoute *route;
  StaticRoute *best = NULL;
  size_t best_len = 0;

  if (path == NULL)
    return NULL;

  /* Find longest matching prefix */
  for (route = server->static_routes; route != NULL; route = route->next)
    {
      if (strncmp (path, route->prefix, route->prefix_len) == 0)
        {
          if (route->prefix_len > best_len)
            {
              best = route;
              best_len = route->prefix_len;
            }
        }
    }

  return best;
}

/**
 * serve_static_file - Serve a static file with full HTTP semantics
 * @server: HTTP server
 * @conn: Connection to serve on
 * @route: Static route that matched
 * @file_path: Path component after prefix
 *
 * Implements:
 * - Path traversal protection
 * - MIME type detection
 * - If-Modified-Since / 304 Not Modified
 * - Range requests / 206 Partial Content
 * - sendfile() for zero-copy transfer
 *
 * Returns: 1 if file served, 0 if file not found, -1 on error
 */
int
server_serve_static_file (SocketHTTPServer_T server, ServerConnection *conn,
                          StaticRoute *route, const char *file_path)
{
  char full_path[HTTPSERVER_STATIC_MAX_PATH];
  char resolved_path[HTTPSERVER_STATIC_MAX_PATH];
  char date_buf[32];
  char last_modified_buf[32];
  char content_length_buf[32];
  char content_range_buf[64];
  struct stat st;
  const char *mime_type;
  const char *if_modified_since;
  const char *range_header;
  time_t if_modified_time;
  off_t range_start = 0;
  off_t range_end = 0;
  int use_range = 0;
  int fd = -1;
  ssize_t sent;

  /* Validate the file path for security */
  if (!validate_static_path (file_path))
    {
      SOCKET_LOG_WARN_MSG ("Rejected suspicious static path: %.100s",
                           file_path);
      return 0; /* Treat as not found */
    }

  /* Build full path */
  int path_len = snprintf (full_path, sizeof (full_path), "%s/%s",
                           route->resolved_directory, file_path);
  if (path_len < 0 || (size_t)path_len >= sizeof (full_path))
    {
      return 0; /* Path too long */
    }

  /* Resolve the full path and verify it's within the allowed directory */
  if (realpath (full_path, resolved_path) == NULL)
    {
      return 0; /* File doesn't exist or can't be resolved */
    }

  /* Security: Ensure resolved path is within the allowed directory */
  if (strncmp (resolved_path, route->resolved_directory,
               route->resolved_dir_len)
      != 0)
    {
      SOCKET_LOG_WARN_MSG ("Path traversal attempt blocked: %.100s",
                           file_path);
      return 0;
    }

  /* Check file exists and is regular file */
  if (stat (resolved_path, &st) < 0)
    {
      return 0;
    }

  if (!S_ISREG (st.st_mode))
    {
      /* Not a regular file (directory, symlink target outside dir, etc.) */
      return 0;
    }

  /* Get MIME type */
  mime_type = get_mime_type (resolved_path);

  /* Check If-Modified-Since header */
  if_modified_since = SocketHTTP_Headers_get (conn->request->headers,
                                              "If-Modified-Since");
  if (if_modified_since != NULL)
    {
      if_modified_time = parse_http_date (if_modified_since);
      if (if_modified_time > 0 && st.st_mtime <= if_modified_time)
        {
          /* File not modified since - return 304 */
          conn->response_status = 304;
          conn->response_body = NULL;
          conn->response_body_len = 0;
          SocketHTTP_Headers_set (conn->response_headers, "Date",
                                  format_http_date (time (NULL), date_buf));
          SocketHTTP_Headers_set (
              conn->response_headers, "Last-Modified",
              format_http_date (st.st_mtime, last_modified_buf));
          return 1; /* Handled */
        }
    }

  /* Check Range header for partial content */
  range_header = SocketHTTP_Headers_get (conn->request->headers, "Range");
  if (range_header != NULL && conn->request->method == HTTP_METHOD_GET)
    {
      if (parse_range_header (range_header, st.st_size, &range_start,
                              &range_end))
        {
          use_range = 1;
        }
      else
        {
          /* Invalid range - send 416 Range Not Satisfiable */
          conn->response_status = 416;
          snprintf (content_range_buf, sizeof (content_range_buf),
                    "bytes */%ld", (long)st.st_size);
          SocketHTTP_Headers_set (conn->response_headers, "Content-Range",
                                  content_range_buf);
          conn->response_body = NULL;
          conn->response_body_len = 0;
          return 1;
        }
    }

  /* Open the file */
  fd = open (resolved_path, O_RDONLY);
  if (fd < 0)
    {
      return 0;
    }

  /* Set response headers */
  if (use_range)
    {
      conn->response_status = 206;
      snprintf (content_range_buf, sizeof (content_range_buf),
                "bytes %ld-%ld/%ld", (long)range_start, (long)range_end,
                (long)st.st_size);
      SocketHTTP_Headers_set (conn->response_headers, "Content-Range",
                              content_range_buf);
      snprintf (content_length_buf, sizeof (content_length_buf), "%ld",
                (long)(range_end - range_start + 1));
    }
  else
    {
      conn->response_status = 200;
      range_start = 0;
      range_end = st.st_size - 1;
      snprintf (content_length_buf, sizeof (content_length_buf), "%ld",
                (long)st.st_size);
    }

  SocketHTTP_Headers_set (conn->response_headers, "Content-Type", mime_type);
  SocketHTTP_Headers_set (conn->response_headers, "Content-Length",
                          content_length_buf);
  SocketHTTP_Headers_set (conn->response_headers, "Last-Modified",
                          format_http_date (st.st_mtime, last_modified_buf));
  SocketHTTP_Headers_set (conn->response_headers, "Date",
                          format_http_date (time (NULL), date_buf));
  SocketHTTP_Headers_set (conn->response_headers, "Accept-Ranges", "bytes");

  /* For HEAD requests, don't send body */
  if (conn->request->method == HTTP_METHOD_HEAD)
    {
      conn->response_body = NULL;
      conn->response_body_len = 0;
      close (fd);
      return 1;
    }

  /* Send response headers first */
  char header_buf[HTTPSERVER_RESPONSE_HEADER_BUFFER_SIZE];
  SocketHTTP_Response response;
  memset (&response, 0, sizeof (response));
  response.version = HTTP_VERSION_1_1;
  response.status_code = conn->response_status;
  response.headers = conn->response_headers;

  ssize_t header_len
      = SocketHTTP1_serialize_response (&response, header_buf, sizeof (header_buf));
  if (header_len < 0
      || connection_send_data (server, conn, header_buf, (size_t)header_len)
             < 0)
    {
      close (fd);
      return -1;
    }

  conn->response_headers_sent = 1;

  /* Use sendfile() for zero-copy file transfer */
  off_t offset = range_start;
  size_t remaining = (size_t)(range_end - range_start + 1);

  while (remaining > 0)
    {
      sent = sendfile (Socket_fd (conn->socket), fd, &offset, remaining);
      if (sent < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
              /* Would block - need to poll for write readiness */
              /* For simplicity, we'll continue trying */
              continue;
            }
          if (errno == EINTR)
            continue;
          close (fd);
          return -1;
        }
      if (sent == 0)
        break;

      remaining -= (size_t)sent;
      SocketMetrics_counter_add (SOCKET_CTR_HTTP_SERVER_BYTES_SENT,
                                 (uint64_t)sent);
    }

  close (fd);

  /* Mark response as finished */
  conn->response_finished = 1;
  conn->response_body = NULL;
  conn->response_body_len = 0;

  return 1;
}

int
SocketHTTPServer_add_static_dir (SocketHTTPServer_T server, const char *prefix,
                                 const char *directory)
{
  char resolved[HTTPSERVER_STATIC_MAX_PATH];
  struct stat st;
  StaticRoute *route;

  assert (server != NULL);
  assert (prefix != NULL);
  assert (directory != NULL);

  /* Validate prefix starts with '/' */
  if (prefix[0] != '/')
    {
      HTTPSERVER_ERROR_MSG ("Static prefix must start with '/': %s", prefix);
      RAISE_HTTPSERVER_ERROR (SocketHTTPServer_Failed);
      return -1;
    }

  /* Verify directory exists and is accessible */
  if (stat (directory, &st) < 0 || !S_ISDIR (st.st_mode))
    {
      HTTPSERVER_ERROR_FMT ("Static directory not accessible: %s", directory);
      RAISE_HTTPSERVER_ERROR (SocketHTTPServer_Failed);
      return -1;
    }

  /* Resolve the directory path for security validation */
  if (realpath (directory, resolved) == NULL)
    {
      HTTPSERVER_ERROR_FMT ("Cannot resolve static directory: %s", directory);
      RAISE_HTTPSERVER_ERROR (SocketHTTPServer_Failed);
      return -1;
    }

  /* Allocate and initialize the route */
  route = malloc (sizeof (*route));
  if (route == NULL)
    {
      HTTPSERVER_ERROR_MSG ("Failed to allocate static route");
      RAISE_HTTPSERVER_ERROR (SocketHTTPServer_Failed);
      return -1;
    }

  route->prefix = strdup (prefix);
  route->directory = strdup (directory);
  route->resolved_directory = strdup (resolved);

  if (route->prefix == NULL || route->directory == NULL
      || route->resolved_directory == NULL)
    {
      free (route->prefix);
      free (route->directory);
      free (route->resolved_directory);
      free (route);
      HTTPSERVER_ERROR_MSG ("Failed to allocate static route strings");
      RAISE_HTTPSERVER_ERROR (SocketHTTPServer_Failed);
      return -1;
    }

  route->prefix_len = strlen (prefix);
  route->resolved_dir_len = strlen (resolved);
  route->next = server->static_routes;
  server->static_routes = route;

  SOCKET_LOG_INFO_MSG ("Added static route: %s -> %s", prefix, directory);

  return 0;
}
