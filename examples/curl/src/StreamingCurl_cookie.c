/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file StreamingCurl_cookie.c
 * @brief Cookie jar implementation for curl module.
 *
 * Implements RFC 6265 cookie handling with:
 * - Netscape cookie file format for persistence
 * - Domain matching
 * - Path matching
 * - Secure/HttpOnly flags
 * - Expiration handling
 */

#include "curl/StreamingCurl-private.h"
#include "curl/StreamingCurl.h"
#include "http/SocketHTTP.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

/* Cookie parsing and formatting constants */
#define COOKIE_EXPIRED_IMMEDIATELY 1
#define COOKIE_DEFAULT_PATH_LEN 1
#define COOKIE_ROOT_PATH_ALLOC_SIZE 2
#define COOKIE_SEPARATOR_LEN 2         /* "; " */
#define COOKIE_NAME_VALUE_SEP_LEN 1    /* "=" */
#define SET_COOKIE_HEADER_LEN 10       /* "Set-Cookie" */

/* Netscape cookie file format field widths */
#define NETSCAPE_DOMAIN_FIELD_WIDTH 255
#define NETSCAPE_TAILMATCH_FIELD_WIDTH 15
#define NETSCAPE_PATH_FIELD_WIDTH 1023
#define NETSCAPE_SECURE_FIELD_WIDTH 15
#define NETSCAPE_NAME_FIELD_WIDTH 255
#define NETSCAPE_VALUE_FIELD_WIDTH 4094
#define NETSCAPE_MIN_FIELDS 6
#define NETSCAPE_FULL_FIELDS 7

/* Helper macros for sscanf format strings */
#define XSTR(s) STR(s)
#define STR(s) #s

CurlCookieJar *
curl_cookiejar_new (Arena_T arena)
{
  if (!arena)
    return NULL;

  CurlCookieJar *jar = CALLOC (arena, 1, sizeof (CurlCookieJar));
  jar->arena = arena;
  jar->cookies = NULL;
  jar->filename = NULL;
  jar->dirty = 0;

  return jar;
}

void
curl_cookiejar_free (CurlCookieJar **jar)
{
  if (!jar || !*jar)
    return;

  /* Cookies are arena-allocated, no need to free individually */
  *jar = NULL;
}

/**
 * @brief Skip whitespace.
 */
static const char *
skip_ws (const char *s)
{
  while (*s && (*s == ' ' || *s == '\t'))
    s++;
  return s;
}

/**
 * @brief Parse a quoted or unquoted value.
 */
static const char *
parse_value (const char *s, char *out, size_t out_size, size_t *out_len)
{
  s = skip_ws (s);

  if (*s == '"')
    {
      /* Quoted value */
      s++;
      size_t i = 0;
      while (*s && *s != '"' && i < out_size - 1)
        out[i++] = *s++;
      out[i] = '\0';
      *out_len = i;
      if (*s == '"')
        s++;
    }
  else
    {
      /* Unquoted value until ; or end */
      size_t i = 0;
      while (*s && *s != ';' && *s != ',' && i < out_size - 1)
        out[i++] = *s++;
      /* Trim trailing whitespace */
      while (i > 0 && (out[i - 1] == ' ' || out[i - 1] == '\t'))
        i--;
      out[i] = '\0';
      *out_len = i;
    }

  return s;
}

/**
 * @brief Parse a Set-Cookie attribute name.
 */
static const char *
parse_attr_name (const char *s, char *out, size_t out_size)
{
  s = skip_ws (s);
  size_t i = 0;
  while (*s && *s != '=' && *s != ';' && i < out_size - 1)
    out[i++] = *s++;
  /* Trim trailing whitespace */
  while (i > 0 && (out[i - 1] == ' ' || out[i - 1] == '\t'))
    i--;
  out[i] = '\0';

  if (*s == '=')
    s++;

  return s;
}

/**
 * @brief Parse cookie name=value pair.
 * @return 0 on success, -1 on failure.
 */
static int
parse_cookie_name_value (const char **p, CurlCookie *cookie, Arena_T arena)
{
  char name[CURL_MAX_COOKIE_NAME_LEN], value[CURL_MAX_COOKIE_VALUE_LEN];
  size_t name_len = 0, value_len = 0;

  /* Get cookie name */
  *p = skip_ws (*p);
  size_t i = 0;
  while (**p && **p != '=' && **p != ';' && i < sizeof (name) - 1)
    name[i++] = *(*p)++;
  /* Trim trailing whitespace from name */
  while (i > 0 && (name[i - 1] == ' ' || name[i - 1] == '\t'))
    i--;
  name[i] = '\0';
  name_len = i;

  if (**p != '=')
    return -1; /* No value - invalid cookie */

  (*p)++; /* Skip '=' */

  /* Get cookie value */
  *p = parse_value (*p, value, sizeof (value), &value_len);

  /* Store name and value */
  cookie->name = ALLOC (arena, name_len + 1);
  if (!cookie->name)
    return -1;
  memcpy (cookie->name, name, name_len);
  cookie->name[name_len] = '\0';

  cookie->value = ALLOC (arena, value_len + 1);
  if (!cookie->value)
    return -1;
  memcpy (cookie->value, value, value_len);
  cookie->value[value_len] = '\0';

  return 0;
}

/**
 * @brief Parse cookie Domain attribute.
 */
static void
parse_cookie_domain (const char *attr_value, size_t attr_val_len,
                     CurlCookie *cookie, Arena_T arena)
{
  if (attr_val_len == 0)
    return;

  /* Remove leading dot if present */
  const char *domain = attr_value;
  if (*domain == '.')
    domain++;
  size_t dlen = strlen (domain);
  cookie->domain = ALLOC (arena, dlen + 1);
  memcpy (cookie->domain, domain, dlen);
  cookie->domain[dlen] = '\0';
}

/**
 * @brief Parse cookie Path attribute.
 */
static void
parse_cookie_path (const char *attr_value, size_t attr_val_len,
                   CurlCookie *cookie, Arena_T arena)
{
  if (attr_val_len == 0)
    return;

  size_t plen = strlen (attr_value);
  cookie->path = ALLOC (arena, plen + 1);
  memcpy (cookie->path, attr_value, plen);
  cookie->path[plen] = '\0';
}

/**
 * @brief Parse cookie Expires and Max-Age attributes.
 */
static void
parse_cookie_expires (const char *attr_name, const char *attr_value,
                      size_t attr_val_len, CurlCookie *cookie)
{
  if (attr_val_len == 0)
    return;

  if (strcasecmp (attr_name, "Expires") == 0)
    {
      /* Parse HTTP date format */
      struct tm tm;
      memset (&tm, 0, sizeof (tm));
      if (strptime (attr_value, "%a, %d %b %Y %H:%M:%S", &tm) != NULL)
        {
          cookie->expires = timegm (&tm);
        }
    }
  else if (strcasecmp (attr_name, "Max-Age") == 0)
    {
      long max_age = strtol (attr_value, NULL, 10);
      if (max_age > 0)
        cookie->expires = time (NULL) + max_age;
      else if (max_age <= 0)
        cookie->expires = COOKIE_EXPIRED_IMMEDIATELY; /* Delete immediately */
    }
}

/**
 * @brief Parse cookie flags (Secure, HttpOnly, SameSite).
 */
static void
parse_cookie_flags (const char *attr_name, CurlCookie *cookie)
{
  if (strcasecmp (attr_name, "Secure") == 0)
    {
      cookie->secure = 1;
    }
  else if (strcasecmp (attr_name, "HttpOnly") == 0)
    {
      cookie->http_only = 1;
    }
  /* SameSite is parsed but not enforced in this implementation */
}

CurlCookie *
curl_cookie_parse (const char *set_cookie, const char *request_host,
                   const char *request_path, int request_secure, Arena_T arena)
{
  if (!set_cookie || !arena)
    return NULL;

  CurlCookie *cookie = CALLOC (arena, 1, sizeof (CurlCookie));

  /* Parse name=value pair first */
  const char *p = set_cookie;
  if (parse_cookie_name_value (&p, cookie, arena) != 0)
    return NULL;

  /* Set defaults */
  cookie->secure = 0;
  cookie->http_only = 0;
  cookie->expires = 0; /* Session cookie */

  /* Default domain to request host */
  if (request_host)
    {
      size_t host_len = strlen (request_host);
      cookie->domain = ALLOC (arena, host_len + 1);
      memcpy (cookie->domain, request_host, host_len);
      cookie->domain[host_len] = '\0';
    }

  /* Default path to request path */
  if (request_path)
    {
      /* Use directory part of path */
      const char *last_slash = strrchr (request_path, '/');
      size_t path_len
          = last_slash ? (size_t)(last_slash - request_path + 1) : COOKIE_DEFAULT_PATH_LEN;
      if (path_len == 0)
        path_len = COOKIE_DEFAULT_PATH_LEN;
      cookie->path = ALLOC (arena, path_len + 1);
      if (last_slash)
        memcpy (cookie->path, request_path, path_len);
      else
        cookie->path[0] = '/';
      cookie->path[path_len] = '\0';
    }
  else
    {
      cookie->path = ALLOC (arena, COOKIE_ROOT_PATH_ALLOC_SIZE);
      cookie->path[0] = '/';
      cookie->path[1] = '\0';
    }

  /* Parse attributes */
  char attr_name[CURL_MAX_QOP_LEN], attr_value[CURL_MAX_DOMAIN_LEN];

  while (*p)
    {
      /* Skip semicolon and whitespace */
      if (*p == ';')
        p++;
      p = skip_ws (p);

      if (*p == '\0')
        break;

      /* Parse attribute */
      p = parse_attr_name (p, attr_name, sizeof (attr_name));
      p = skip_ws (p);

      /* Get value if present */
      attr_value[0] = '\0';
      size_t attr_val_len = 0;
      if (*p && *p != ';')
        {
          p = parse_value (p, attr_value, sizeof (attr_value), &attr_val_len);
        }

      /* Process attribute */
      if (strcasecmp (attr_name, "Domain") == 0)
        {
          parse_cookie_domain (attr_value, attr_val_len, cookie, arena);
        }
      else if (strcasecmp (attr_name, "Path") == 0)
        {
          parse_cookie_path (attr_value, attr_val_len, cookie, arena);
        }
      else if (strcasecmp (attr_name, "Expires") == 0
               || strcasecmp (attr_name, "Max-Age") == 0)
        {
          parse_cookie_expires (attr_name, attr_value, attr_val_len, cookie);
        }
      else
        {
          parse_cookie_flags (attr_name, cookie);
        }
    }

  /* Validate secure cookie on secure request */
  (void)request_secure; /* May be used for validation in future */

  return cookie;
}

int
curl_cookie_domain_match (const char *cookie_domain, const char *request_host)
{
  if (!cookie_domain || !request_host)
    return 0;

  size_t cookie_len = strlen (cookie_domain);
  size_t host_len = strlen (request_host);

  /* Exact match */
  if (cookie_len == host_len && strcasecmp (cookie_domain, request_host) == 0)
    return 1;

  /* Domain suffix match */
  if (cookie_len < host_len)
    {
      const char *suffix = request_host + host_len - cookie_len;
      /* Check suffix match and that preceding char is a dot */
      if (strcasecmp (suffix, cookie_domain) == 0 && suffix[-1] == '.')
        return 1;
    }

  return 0;
}

int
curl_cookie_path_match (const char *cookie_path, const char *request_path)
{
  if (!cookie_path || !request_path)
    return 0;

  size_t cookie_len = strlen (cookie_path);
  size_t path_len = strlen (request_path);

  /* Cookie path must be prefix of request path */
  if (cookie_len > path_len)
    return 0;

  if (strncmp (cookie_path, request_path, cookie_len) != 0)
    return 0;

  /* Must be exact match or next char in request is '/' */
  if (cookie_len == path_len)
    return 1;

  if (cookie_path[cookie_len - 1] == '/')
    return 1;

  if (request_path[cookie_len] == '/')
    return 1;

  return 0;
}

int
curl_cookie_matches (const CurlCookie *cookie, const char *host,
                     const char *path, int is_secure)
{
  if (!cookie || !host || !path)
    return 0;

  /* Check domain */
  if (!curl_cookie_domain_match (cookie->domain, host))
    return 0;

  /* Check path */
  if (!curl_cookie_path_match (cookie->path, path))
    return 0;

  /* Check secure flag */
  if (cookie->secure && !is_secure)
    return 0;

  /* Check expiration */
  if (cookie->expires > 0 && cookie->expires <= time (NULL))
    return 0;

  return 1;
}

int
curl_cookie_is_expired (const CurlCookie *cookie)
{
  if (!cookie)
    return 1;

  /* Session cookie (expires == 0) never expires during session */
  if (cookie->expires == 0)
    return 0;

  return cookie->expires <= time (NULL);
}

int
curl_cookiejar_add (CurlCookieJar *jar, CurlCookie *cookie)
{
  if (!jar || !cookie)
    return -1;

  /* Remove existing cookie with same name, domain, path */
  curl_cookiejar_remove (jar, cookie->name, cookie->domain, cookie->path);

  /* Check if cookie has already expired (delete cookie) */
  if (cookie->expires > 0 && cookie->expires <= time (NULL))
    return 0; /* Don't add expired cookie */

  /* Add to front of list */
  cookie->next = jar->cookies;
  jar->cookies = cookie;
  jar->dirty = 1;

  return 0;
}

int
curl_cookiejar_remove (CurlCookieJar *jar, const char *name,
                       const char *domain, const char *path)
{
  if (!jar || !name)
    return -1;

  CurlCookie **pp = &jar->cookies;
  while (*pp)
    {
      CurlCookie *c = *pp;
      int match = (strcmp (c->name, name) == 0);

      if (match && domain)
        match = (strcasecmp (c->domain, domain) == 0);

      if (match && path)
        match = (strcmp (c->path, path) == 0);

      if (match)
        {
          *pp = c->next;
          jar->dirty = 1;
          /* Cookie memory is arena-managed */
          return 1; /* Removed */
        }

      pp = &c->next;
    }

  return 0; /* Not found */
}

void
curl_cookiejar_clear (CurlCookieJar *jar)
{
  if (!jar)
    return;

  jar->cookies = NULL;
  jar->dirty = 1;
}

void
curl_cookiejar_clear_expired (CurlCookieJar *jar)
{
  if (!jar)
    return;

  time_t now = time (NULL);
  CurlCookie **pp = &jar->cookies;

  while (*pp)
    {
      CurlCookie *c = *pp;
      if (c->expires > 0 && c->expires <= now)
        {
          *pp = c->next;
          jar->dirty = 1;
        }
      else
        {
          pp = &c->next;
        }
    }
}

int
curl_cookiejar_count (const CurlCookieJar *jar)
{
  if (!jar)
    return 0;

  int count = 0;
  for (const CurlCookie *c = jar->cookies; c; c = c->next)
    count++;

  return count;
}

ssize_t
curl_cookiejar_get_header (const CurlCookieJar *jar, const char *host,
                           const char *path, int is_secure, char *output,
                           size_t output_size)
{
  if (!jar || !host || !path || !output || output_size == 0)
    return -1;

  size_t written = 0;
  int first = 1;

  for (const CurlCookie *c = jar->cookies; c; c = c->next)
    {
      if (!curl_cookie_matches (c, host, path, is_secure))
        continue;

      /* Format: name=value; name2=value2 */
      size_t needed = strlen (c->name) + COOKIE_NAME_VALUE_SEP_LEN + strlen (c->value);
      if (!first)
        needed += COOKIE_SEPARATOR_LEN; /* "; " */

      if (written + needed >= output_size)
        break; /* Buffer full */

      if (!first)
        {
          output[written++] = ';';
          output[written++] = ' ';
        }

      size_t name_len = strlen (c->name);
      memcpy (output + written, c->name, name_len);
      written += name_len;

      output[written++] = '=';

      size_t value_len = strlen (c->value);
      memcpy (output + written, c->value, value_len);
      written += value_len;

      first = 0;
    }

  output[written] = '\0';
  return (ssize_t)written;
}

int
curl_cookiejar_process_response (CurlCookieJar *jar,
                                 SocketHTTP_Headers_T headers,
                                 const char *host, const char *path,
                                 int is_secure, Arena_T arena)
{
  if (!jar || !headers)
    return -1;

  int count = 0;
  size_t header_count = SocketHTTP_Headers_count (headers);

  for (size_t i = 0; i < header_count; i++)
    {
      const SocketHTTP_Header *h = SocketHTTP_Headers_at (headers, i);
      if (!h)
        continue;

      /* Check for Set-Cookie header (case-insensitive) */
      if (h->name_len == SET_COOKIE_HEADER_LEN && strncasecmp (h->name, "Set-Cookie", SET_COOKIE_HEADER_LEN) == 0)
        {
          /* Create null-terminated copy */
          char *value = ALLOC (arena, h->value_len + 1);
          memcpy (value, h->value, h->value_len);
          value[h->value_len] = '\0';

          CurlCookie *cookie
              = curl_cookie_parse (value, host, path, is_secure, arena);
          if (cookie)
            {
              curl_cookiejar_add (jar, cookie);
              count++;
            }
        }
    }

  return count;
}

int
curl_cookiejar_load (CurlCookieJar *jar, const char *filename)
{
  if (!jar || !filename)
    return -1;

  /* Use open() with O_NOFOLLOW to prevent symlink attacks */
  int fd = open (filename, O_RDONLY | O_NOFOLLOW);
  if (fd < 0)
    {
      if (errno == ENOENT)
        return 0; /* File doesn't exist yet - OK */
      return -1;
    }

  FILE *fp = fdopen (fd, "r");
  if (!fp)
    {
      close (fd);
      return -1;
    }

  char line[CURL_MAX_COOKIE_LINE_LEN];
  int count = 0;

  while (fgets (line, sizeof (line), fp))
    {
      /* Skip comments and blank lines */
      if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
        continue;

      /* Netscape format: domain TAB tailmatch TAB path TAB secure TAB expires
       * TAB name TAB value */
      char domain[CURL_MAX_DOMAIN_LEN], tailmatch[NETSCAPE_TAILMATCH_FIELD_WIDTH + 1], path[CURL_MAX_PATH_LEN],
          secure_str[NETSCAPE_SECURE_FIELD_WIDTH + 1];
      char name[CURL_MAX_COOKIE_NAME_LEN], value[CURL_MAX_COOKIE_VALUE_LEN];
      long expires;

      int n = sscanf (
          line, "%" XSTR(NETSCAPE_DOMAIN_FIELD_WIDTH) "s\t"
                "%" XSTR(NETSCAPE_TAILMATCH_FIELD_WIDTH) "s\t"
                "%" XSTR(NETSCAPE_PATH_FIELD_WIDTH) "s\t"
                "%" XSTR(NETSCAPE_SECURE_FIELD_WIDTH) "s\t%ld\t"
                "%" XSTR(NETSCAPE_NAME_FIELD_WIDTH) "s\t"
                "%" XSTR(NETSCAPE_VALUE_FIELD_WIDTH) "[^\r\n]",
          domain, tailmatch, path, secure_str, &expires, name, value);

      if (n < NETSCAPE_FULL_FIELDS)
        {
          /* Try without value (empty value) */
          n = sscanf (line, "%" XSTR(NETSCAPE_DOMAIN_FIELD_WIDTH) "s\t"
                            "%" XSTR(NETSCAPE_TAILMATCH_FIELD_WIDTH) "s\t"
                            "%" XSTR(NETSCAPE_PATH_FIELD_WIDTH) "s\t"
                            "%" XSTR(NETSCAPE_SECURE_FIELD_WIDTH) "s\t%ld\t"
                            "%" XSTR(NETSCAPE_NAME_FIELD_WIDTH) "s",
                      domain, tailmatch, path, secure_str, &expires, name);
          if (n >= NETSCAPE_MIN_FIELDS)
            value[0] = '\0';
          else
            continue;
        }

      /* Validate expires range before casting to time_t */
      if (expires < 0)
        continue;

      /* Create cookie */
      CurlCookie *cookie = CALLOC (jar->arena, 1, sizeof (CurlCookie));

      /* Remove leading dot from domain for storage */
      const char *d = domain;
      if (*d == '.')
        d++;
      size_t dlen = strlen (d);
      cookie->domain = ALLOC (jar->arena, dlen + 1);
      if (!cookie->domain)
        continue;
      memcpy (cookie->domain, d, dlen);
      cookie->domain[dlen] = '\0';

      size_t plen = strlen (path);
      cookie->path = ALLOC (jar->arena, plen + 1);
      if (!cookie->path)
        continue;
      memcpy (cookie->path, path, plen);
      cookie->path[plen] = '\0';

      size_t nlen = strlen (name);
      cookie->name = ALLOC (jar->arena, nlen + 1);
      if (!cookie->name)
        continue;
      memcpy (cookie->name, name, nlen);
      cookie->name[nlen] = '\0';

      size_t vlen = strlen (value);
      cookie->value = ALLOC (jar->arena, vlen + 1);
      if (!cookie->value)
        continue;
      memcpy (cookie->value, value, vlen);
      cookie->value[vlen] = '\0';

      cookie->secure = (strcasecmp (secure_str, "TRUE") == 0);
      cookie->http_only = 0; /* Not stored in Netscape format */
      cookie->expires = (time_t)expires;

      /* Add to jar */
      cookie->next = jar->cookies;
      jar->cookies = cookie;
      count++;
    }

  fclose (fp);

  /* Store filename for later save */
  size_t fname_len = strlen (filename);
  jar->filename = ALLOC (jar->arena, fname_len + 1);
  memcpy (jar->filename, filename, fname_len);
  jar->filename[fname_len] = '\0';
  jar->dirty = 0;

  return count;
}

int
curl_cookiejar_save (const CurlCookieJar *jar, const char *filename)
{
  if (!jar)
    return -1;

  const char *save_file = filename ? filename : jar->filename;
  if (!save_file)
    return -1;

  FILE *fp = fopen (save_file, "w");
  if (!fp)
    return -1;

  /* Write Netscape header */
  fprintf (fp, "# Netscape HTTP Cookie File\n");
  fprintf (fp, "# https://curl.se/docs/http-cookies.html\n");
  fprintf (fp, "# This file was generated by tetsuo-curl\n\n");

  time_t now = time (NULL);

  for (const CurlCookie *c = jar->cookies; c; c = c->next)
    {
      /* Skip expired cookies */
      if (c->expires > 0 && c->expires <= now)
        continue;

      /* Skip session cookies if expires is 0 */
      /* (We save them anyway, they'll be treated as session cookies on load)
       */

      /* Format: domain tailmatch path secure expires name value */
      fprintf (fp, ".%s\tTRUE\t%s\t%s\t%ld\t%s\t%s\n", c->domain, c->path,
               c->secure ? "TRUE" : "FALSE", (long)c->expires, c->name,
               c->value);
    }

  fclose (fp);
  return 0;
}

int
curl_session_add_cookies (CurlSession_T session)
{
  if (!session || !session->cookie_jar || !session->request_headers)
    return 0;

  char cookie_header[CURL_MAX_URL_BUFFER_LEN];
  ssize_t len = curl_cookiejar_get_header (
      session->cookie_jar, session->current_url.host,
      session->current_url.path ? session->current_url.path : "/",
      session->current_url.is_secure, cookie_header, sizeof (cookie_header));

  if (len <= 0)
    return 0;

  SocketHTTP_Headers_set (session->request_headers, "Cookie", cookie_header);
  return 1;
}

int
curl_session_process_cookies (CurlSession_T session)
{
  if (!session || !session->cookie_jar || !session->response.headers)
    return 0;

  return curl_cookiejar_process_response (
      session->cookie_jar, session->response.headers,
      session->current_url.host,
      session->current_url.path ? session->current_url.path : "/",
      session->current_url.is_secure, session->request_arena);
}

int
curl_session_init_cookies (CurlSession_T session, const char *cookie_file)
{
  if (!session)
    return -1;

  /* Create cookie jar if needed */
  if (!session->cookie_jar)
    {
      session->cookie_jar = curl_cookiejar_new (session->arena);
      if (!session->cookie_jar)
        return -1;
    }

  /* Load from file if specified */
  if (cookie_file)
    {
      int result = curl_cookiejar_load (session->cookie_jar, cookie_file);
      if (result < 0)
        return -1;
    }

  return 0;
}

int
curl_session_save_cookies (CurlSession_T session)
{
  if (!session || !session->cookie_jar)
    return 0;

  if (!session->cookie_jar->dirty)
    return 0; /* Nothing to save */

  if (!session->cookie_jar->filename && !session->options.cookie_file)
    return 0; /* No file configured */

  return curl_cookiejar_save (session->cookie_jar,
                              session->options.cookie_file);
}
