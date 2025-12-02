/**
 * SocketHTTPClient-cookie.c - HTTP Cookie Implementation (RFC 6265)
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Implements cookie storage and management:
 * - Cookie parsing from Set-Cookie headers
 * - Cookie storage with domain/path matching
 * - Cookie expiration handling
 * - Secure and HttpOnly flags
 * - SameSite attribute (Lax/Strict/None)
 * - File persistence (Netscape format)
 *
 * Leverages:
 * - SocketHTTP_date_parse() for Expires parsing
 * - Arena for memory management
 */

#include "http/SocketHTTPClient.h"
#include "http/SocketHTTPClient-private.h"
#include "http/SocketHTTP.h"
#include "core/Arena.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ============================================================================
 * Cookie Jar Configuration
 * ============================================================================ */

#define COOKIE_HASH_SIZE 127
#define COOKIE_MAX_NAME_LEN 256
#define COOKIE_MAX_VALUE_LEN 4096
#define COOKIE_MAX_DOMAIN_LEN 256
#define COOKIE_MAX_PATH_LEN 1024

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

/**
 * Hash function for cookie lookup (domain:path:name)
 */
static unsigned
cookie_hash (const char *domain, const char *path, const char *name,
             size_t table_size)
{
  unsigned hash = 5381;

  /* Hash domain (case-insensitive) */
  while (*domain)
    {
      unsigned char c = (unsigned char)*domain++;
      if (c >= 'A' && c <= 'Z')
        c = c + ('a' - 'A');
      hash = ((hash << 5) + hash) ^ c;
    }

  /* Hash path */
  while (*path)
    {
      hash = ((hash << 5) + hash) ^ (unsigned char)*path++;
    }

  /* Hash name (case-sensitive for cookies) */
  while (*name)
    {
      hash = ((hash << 5) + hash) ^ (unsigned char)*name++;
    }

  return hash % table_size;
}

/**
 * Check if domain matches cookie domain
 * RFC 6265 Section 5.1.3
 */
static int
domain_matches (const char *request_domain, const char *cookie_domain)
{
  size_t req_len, cookie_len;

  if (request_domain == NULL || cookie_domain == NULL)
    return 0;

  /* Handle leading dot in cookie domain */
  if (cookie_domain[0] == '.')
    cookie_domain++;

  req_len = strlen (request_domain);
  cookie_len = strlen (cookie_domain);

  /* Exact match */
  if (strcasecmp (request_domain, cookie_domain) == 0)
    return 1;

  /* Domain suffix match */
  if (req_len > cookie_len)
    {
      const char *suffix = request_domain + (req_len - cookie_len);
      if (strcasecmp (suffix, cookie_domain) == 0)
        {
          /* Must be preceded by a dot */
          if (suffix > request_domain && *(suffix - 1) == '.')
            return 1;
        }
    }

  return 0;
}

/**
 * Check if path matches cookie path
 * RFC 6265 Section 5.1.4
 */
static int
path_matches (const char *request_path, const char *cookie_path)
{
  size_t req_len, cookie_len;

  if (request_path == NULL)
    request_path = "/";
  if (cookie_path == NULL || cookie_path[0] == '\0')
    cookie_path = "/";

  req_len = strlen (request_path);
  cookie_len = strlen (cookie_path);

  /* Cookie path must be prefix of request path */
  if (strncmp (request_path, cookie_path, cookie_len) != 0)
    return 0;

  /* Either exact match or cookie path ends with / or next char is / */
  if (req_len == cookie_len)
    return 1;
  if (cookie_path[cookie_len - 1] == '/')
    return 1;
  if (request_path[cookie_len] == '/')
    return 1;

  return 0;
}

/**
 * Parse Max-Age attribute value
 */
static time_t
parse_max_age (const char *value)
{
  long age;
  char *endptr;

  if (value == NULL || *value == '\0')
    return 0;

  errno = 0;
  age = strtol (value, &endptr, 10);

  if (errno != 0 || endptr == value || *endptr != '\0')
    return 0;

  if (age <= 0)
    return 1; /* Expire immediately */

  return time (NULL) + age;
}

/**
 * Parse SameSite attribute value
 */
static SocketHTTPClient_SameSite
parse_same_site (const char *value)
{
  if (value == NULL)
    return COOKIE_SAMESITE_LAX; /* Default per RFC 6265bis */

  if (strcasecmp (value, "Strict") == 0)
    return COOKIE_SAMESITE_STRICT;
  if (strcasecmp (value, "Lax") == 0)
    return COOKIE_SAMESITE_LAX;
  if (strcasecmp (value, "None") == 0)
    return COOKIE_SAMESITE_NONE;

  return COOKIE_SAMESITE_LAX;
}

/**
 * Get default path from request URI
 * RFC 6265 Section 5.1.4
 */
static void
get_default_path (const char *request_path, char *output, size_t output_size)
{
  const char *last_slash;

  if (request_path == NULL || request_path[0] != '/'
      || (last_slash = strrchr (request_path, '/')) == request_path)
    {
      /* Default to "/" */
      strncpy (output, "/", output_size);
      return;
    }

  /* Copy path up to (not including) the last slash */
  size_t len = (size_t)(last_slash - request_path);
  if (len >= output_size)
    len = output_size - 1;

  memcpy (output, request_path, len);
  output[len] = '\0';
}

/**
 * Duplicate string into arena
 */
static char *
arena_strdup (Arena_T arena, const char *str)
{
  size_t len;
  char *copy;

  if (str == NULL)
    return NULL;

  len = strlen (str);
  copy = Arena_alloc (arena, len + 1, __FILE__, __LINE__);
  if (copy != NULL)
    memcpy (copy, str, len + 1);

  return copy;
}

/* ============================================================================
 * Cookie Jar Lifecycle
 * ============================================================================ */

SocketHTTPClient_CookieJar_T
SocketHTTPClient_CookieJar_new (void)
{
  SocketHTTPClient_CookieJar_T jar;
  Arena_T arena;

  arena = Arena_new ();
  if (arena == NULL)
    return NULL;

  jar = Arena_alloc (arena, sizeof (*jar), __FILE__, __LINE__);
  if (jar == NULL)
    {
      Arena_dispose (&arena);
      return NULL;
    }

  memset (jar, 0, sizeof (*jar));
  jar->arena = arena;
  jar->hash_size = COOKIE_HASH_SIZE;

  jar->hash_table
      = Arena_calloc (arena, COOKIE_HASH_SIZE, sizeof (CookieEntry *), __FILE__,
                      __LINE__);
  if (jar->hash_table == NULL)
    {
      Arena_dispose (&arena);
      return NULL;
    }

  if (pthread_mutex_init (&jar->mutex, NULL) != 0)
    {
      Arena_dispose (&arena);
      return NULL;
    }

  return jar;
}

void
SocketHTTPClient_CookieJar_free (SocketHTTPClient_CookieJar_T *jar)
{
  if (jar == NULL || *jar == NULL)
    return;

  SocketHTTPClient_CookieJar_T j = *jar;

  pthread_mutex_destroy (&j->mutex);

  if (j->arena != NULL)
    {
      Arena_dispose (&j->arena);
    }

  *jar = NULL;
}

/* ============================================================================
 * Cookie Storage Operations
 * ============================================================================ */

int
SocketHTTPClient_CookieJar_set (SocketHTTPClient_CookieJar_T jar,
                                const SocketHTTPClient_Cookie *cookie)
{
  unsigned hash;
  CookieEntry *entry;
  CookieEntry **pp;

  assert (jar != NULL);
  assert (cookie != NULL);
  assert (cookie->name != NULL);
  assert (cookie->value != NULL);
  assert (cookie->domain != NULL);

  pthread_mutex_lock (&jar->mutex);

  hash = cookie_hash (cookie->domain, cookie->path ? cookie->path : "/",
                      cookie->name, jar->hash_size);

  /* Look for existing cookie to replace */
  pp = &jar->hash_table[hash];
  while (*pp != NULL)
    {
      entry = *pp;
      if (strcmp (entry->cookie.name, cookie->name) == 0
          && strcasecmp (entry->cookie.domain, cookie->domain) == 0
          && strcmp (entry->cookie.path ? entry->cookie.path : "/",
                     cookie->path ? cookie->path : "/")
                 == 0)
        {
          /* Replace existing cookie */
          entry->cookie.value = arena_strdup (jar->arena, cookie->value);
          entry->cookie.expires = cookie->expires;
          entry->cookie.secure = cookie->secure;
          entry->cookie.http_only = cookie->http_only;
          entry->cookie.same_site = cookie->same_site;
          pthread_mutex_unlock (&jar->mutex);
          return 0;
        }
      pp = &entry->next;
    }

  /* Create new entry */
  entry = Arena_alloc (jar->arena, sizeof (*entry), __FILE__, __LINE__);
  if (entry == NULL)
    {
      pthread_mutex_unlock (&jar->mutex);
      return -1;
    }

  memset (entry, 0, sizeof (*entry));

  /* Copy cookie data */
  entry->cookie.name = arena_strdup (jar->arena, cookie->name);
  entry->cookie.value = arena_strdup (jar->arena, cookie->value);
  entry->cookie.domain = arena_strdup (jar->arena, cookie->domain);
  entry->cookie.path = arena_strdup (jar->arena,
                                     cookie->path ? cookie->path : "/");
  entry->cookie.expires = cookie->expires;
  entry->cookie.secure = cookie->secure;
  entry->cookie.http_only = cookie->http_only;
  entry->cookie.same_site = cookie->same_site;

  if (entry->cookie.name == NULL || entry->cookie.value == NULL
      || entry->cookie.domain == NULL)
    {
      pthread_mutex_unlock (&jar->mutex);
      return -1;
    }

  /* Add to hash table */
  entry->next = jar->hash_table[hash];
  jar->hash_table[hash] = entry;
  jar->count++;

  pthread_mutex_unlock (&jar->mutex);
  return 0;
}

const SocketHTTPClient_Cookie *
SocketHTTPClient_CookieJar_get (SocketHTTPClient_CookieJar_T jar,
                                const char *domain, const char *path,
                                const char *name)
{
  unsigned hash;
  CookieEntry *entry;

  assert (jar != NULL);
  assert (domain != NULL);
  assert (name != NULL);

  if (path == NULL)
    path = "/";

  pthread_mutex_lock (&jar->mutex);

  hash = cookie_hash (domain, path, name, jar->hash_size);

  entry = jar->hash_table[hash];
  while (entry != NULL)
    {
      if (strcmp (entry->cookie.name, name) == 0
          && strcasecmp (entry->cookie.domain, domain) == 0
          && strcmp (entry->cookie.path ? entry->cookie.path : "/", path) == 0)
        {
          pthread_mutex_unlock (&jar->mutex);
          return &entry->cookie;
        }
      entry = entry->next;
    }

  pthread_mutex_unlock (&jar->mutex);
  return NULL;
}

void
SocketHTTPClient_CookieJar_clear (SocketHTTPClient_CookieJar_T jar)
{
  assert (jar != NULL);

  pthread_mutex_lock (&jar->mutex);

  memset (jar->hash_table, 0, jar->hash_size * sizeof (CookieEntry *));
  jar->count = 0;

  /* Note: memory is still in arena, will be freed when jar is freed */

  pthread_mutex_unlock (&jar->mutex);
}

void
SocketHTTPClient_CookieJar_clear_expired (SocketHTTPClient_CookieJar_T jar)
{
  time_t now;
  size_t i;

  assert (jar != NULL);

  now = time (NULL);

  pthread_mutex_lock (&jar->mutex);

  for (i = 0; i < jar->hash_size; i++)
    {
      CookieEntry **pp = &jar->hash_table[i];
      while (*pp != NULL)
        {
          CookieEntry *entry = *pp;
          if (entry->cookie.expires > 0 && entry->cookie.expires < now)
            {
              /* Remove expired cookie */
              *pp = entry->next;
              jar->count--;
            }
          else
            {
              pp = &entry->next;
            }
        }
    }

  pthread_mutex_unlock (&jar->mutex);
}

/* ============================================================================
 * Cookie File Persistence
 * ============================================================================ */

int
SocketHTTPClient_CookieJar_load (SocketHTTPClient_CookieJar_T jar,
                                 const char *filename)
{
  FILE *f;
  char line[4096];

  assert (jar != NULL);
  assert (filename != NULL);

  f = fopen (filename, "r");
  if (f == NULL)
    return -1;

  while (fgets (line, sizeof (line), f) != NULL)
    {
      char *domain, *flag, *path, *secure, *expires, *name, *value;
      char *saveptr = NULL;
      SocketHTTPClient_Cookie cookie;

      /* Skip comments and empty lines */
      if (line[0] == '#' || line[0] == '\n')
        continue;

      /* Remove trailing newline */
      size_t len = strlen (line);
      if (len > 0 && line[len - 1] == '\n')
        line[len - 1] = '\0';

      /* Parse Netscape cookie format:
       * domain\tflag\tpath\tsecure\texpires\tname\tvalue */
      domain = strtok_r (line, "\t", &saveptr);
      flag = strtok_r (NULL, "\t", &saveptr);
      path = strtok_r (NULL, "\t", &saveptr);
      secure = strtok_r (NULL, "\t", &saveptr);
      expires = strtok_r (NULL, "\t", &saveptr);
      name = strtok_r (NULL, "\t", &saveptr);
      value = strtok_r (NULL, "\t", &saveptr);

      (void)flag; /* Unused - domain match flag */

      if (domain && path && secure && expires && name && value)
        {
          memset (&cookie, 0, sizeof (cookie));
          cookie.domain = domain;
          cookie.path = path;
          cookie.secure = (strcmp (secure, "TRUE") == 0);
          cookie.expires = (time_t)strtoll (expires, NULL, 10);
          cookie.name = name;
          cookie.value = value;

          SocketHTTPClient_CookieJar_set (jar, &cookie);
        }
    }

  fclose (f);
  return 0;
}

int
SocketHTTPClient_CookieJar_save (SocketHTTPClient_CookieJar_T jar,
                                 const char *filename)
{
  FILE *f;
  size_t i;

  assert (jar != NULL);
  assert (filename != NULL);

  f = fopen (filename, "w");
  if (f == NULL)
    return -1;

  /* Write header */
  fprintf (f, "# Netscape HTTP Cookie File\n");
  fprintf (f, "# http://curl.haxx.se/rfc/cookie_spec.html\n");
  fprintf (f, "# This file was generated by SocketHTTPClient.\n\n");

  pthread_mutex_lock (&jar->mutex);

  for (i = 0; i < jar->hash_size; i++)
    {
      CookieEntry *entry = jar->hash_table[i];
      while (entry != NULL)
        {
          const SocketHTTPClient_Cookie *c = &entry->cookie;

          /* Format: domain\tflag\tpath\tsecure\texpires\tname\tvalue */
          fprintf (f, "%s\t%s\t%s\t%s\t%lld\t%s\t%s\n",
                   c->domain,
                   (c->domain[0] == '.') ? "TRUE" : "FALSE",
                   c->path ? c->path : "/",
                   c->secure ? "TRUE" : "FALSE",
                   (long long)c->expires,
                   c->name,
                   c->value);

          entry = entry->next;
        }
    }

  pthread_mutex_unlock (&jar->mutex);

  fclose (f);
  return 0;
}

/* ============================================================================
 * Cookie Request/Response Integration
 * ============================================================================ */

int
httpclient_cookies_for_request (SocketHTTPClient_CookieJar_T jar,
                                const SocketHTTP_URI *uri, char *output,
                                size_t output_size)
{
  size_t i;
  size_t written = 0;
  time_t now;
  int is_secure;
  const char *request_path;

  assert (jar != NULL);
  assert (uri != NULL);
  assert (output != NULL);
  assert (output_size > 0);

  output[0] = '\0';
  now = time (NULL);
  is_secure = SocketHTTP_URI_is_secure (uri);
  request_path = uri->path ? uri->path : "/";

  pthread_mutex_lock (&jar->mutex);

  for (i = 0; i < jar->hash_size; i++)
    {
      CookieEntry *entry = jar->hash_table[i];
      while (entry != NULL)
        {
          const SocketHTTPClient_Cookie *c = &entry->cookie;

          /* Check expiration */
          if (c->expires > 0 && c->expires < now)
            {
              entry = entry->next;
              continue;
            }

          /* Check secure flag */
          if (c->secure && !is_secure)
            {
              entry = entry->next;
              continue;
            }

          /* Check domain match */
          if (!domain_matches (uri->host, c->domain))
            {
              entry = entry->next;
              continue;
            }

          /* Check path match */
          if (!path_matches (request_path, c->path))
            {
              entry = entry->next;
              continue;
            }

          /* Add cookie to output */
          size_t cookie_len = strlen (c->name) + strlen (c->value) + 1;
          if (written > 0)
            cookie_len += 2; /* "; " separator */

          if (written + cookie_len >= output_size)
            {
              /* Output buffer full */
              break;
            }

          if (written > 0)
            {
              memcpy (output + written, "; ", 2);
              written += 2;
            }

          written += (size_t)snprintf (output + written, output_size - written,
                                       "%s=%s", c->name, c->value);

          entry = entry->next;
        }
    }

  pthread_mutex_unlock (&jar->mutex);

  return (int)written;
}

int
httpclient_parse_set_cookie (const char *value, size_t len,
                             const SocketHTTP_URI *request_uri,
                             SocketHTTPClient_Cookie *cookie, Arena_T arena)
{
  const char *p = value;
  const char *end = value + (len > 0 ? len : strlen (value));
  const char *name_start, *name_end;
  const char *value_start, *value_end;
  char default_path[COOKIE_MAX_PATH_LEN];

  assert (value != NULL);
  assert (cookie != NULL);
  assert (arena != NULL);

  memset (cookie, 0, sizeof (*cookie));

  /* Skip leading whitespace */
  while (p < end && (*p == ' ' || *p == '\t'))
    p++;

  /* Parse name */
  name_start = p;
  while (p < end && *p != '=' && *p != ';')
    p++;
  name_end = p;

  /* Trim trailing whitespace from name */
  while (name_end > name_start
         && (*(name_end - 1) == ' ' || *(name_end - 1) == '\t'))
    name_end--;

  if (name_end == name_start || p >= end || *p != '=')
    return -1; /* Invalid cookie */

  p++; /* Skip '=' */

  /* Parse value */
  value_start = p;

  /* Handle quoted value */
  if (p < end && *p == '"')
    {
      value_start = ++p;
      while (p < end && *p != '"')
        p++;
      value_end = p;
      if (p < end)
        p++; /* Skip closing quote */
    }
  else
    {
      while (p < end && *p != ';')
        p++;
      value_end = p;
    }

  /* Trim trailing whitespace from value */
  while (value_end > value_start
         && (*(value_end - 1) == ' ' || *(value_end - 1) == '\t'))
    value_end--;

  /* Allocate name and value */
  {
    size_t name_len = (size_t)(name_end - name_start);
    size_t val_len = (size_t)(value_end - value_start);
    char *n = Arena_alloc (arena, name_len + 1, __FILE__, __LINE__);
    char *v = Arena_alloc (arena, val_len + 1, __FILE__, __LINE__);

    if (n == NULL || v == NULL)
      return -1;

    memcpy (n, name_start, name_len);
    n[name_len] = '\0';
    memcpy (v, value_start, val_len);
    v[val_len] = '\0';

    cookie->name = n;
    cookie->value = v;
  }

  /* Parse attributes */
  while (p < end)
    {
      const char *attr_start, *attr_end;
      const char *attr_value_start = NULL, *attr_value_end = NULL;

      /* Skip ';' and whitespace */
      while (p < end && (*p == ';' || *p == ' ' || *p == '\t'))
        p++;

      if (p >= end)
        break;

      /* Parse attribute name */
      attr_start = p;
      while (p < end && *p != '=' && *p != ';')
        p++;
      attr_end = p;

      /* Trim trailing whitespace */
      while (attr_end > attr_start
             && (*(attr_end - 1) == ' ' || *(attr_end - 1) == '\t'))
        attr_end--;

      /* Parse attribute value if present */
      if (p < end && *p == '=')
        {
          p++;
          while (p < end && (*p == ' ' || *p == '\t'))
            p++;
          attr_value_start = p;
          while (p < end && *p != ';')
            p++;
          attr_value_end = p;

          /* Trim trailing whitespace */
          while (attr_value_end > attr_value_start
                 && (*(attr_value_end - 1) == ' '
                     || *(attr_value_end - 1) == '\t'))
            attr_value_end--;
        }

      /* Process attribute */
      size_t attr_len = (size_t)(attr_end - attr_start);
      size_t attr_val_len
          = attr_value_start ? (size_t)(attr_value_end - attr_value_start) : 0;

      if (attr_len == 6 && strncasecmp (attr_start, "Secure", 6) == 0)
        {
          cookie->secure = 1;
        }
      else if (attr_len == 8 && strncasecmp (attr_start, "HttpOnly", 8) == 0)
        {
          cookie->http_only = 1;
        }
      else if (attr_len == 7 && strncasecmp (attr_start, "Expires", 7) == 0
               && attr_value_start != NULL)
        {
          /* Parse Expires using SocketHTTP_date_parse() */
          time_t expires;
          if (SocketHTTP_date_parse (attr_value_start, attr_val_len, &expires)
              == 0)
            {
              cookie->expires = expires;
            }
        }
      else if (attr_len == 7 && strncasecmp (attr_start, "Max-Age", 7) == 0
               && attr_value_start != NULL)
        {
          char max_age_str[32];
          if (attr_val_len < sizeof (max_age_str))
            {
              memcpy (max_age_str, attr_value_start, attr_val_len);
              max_age_str[attr_val_len] = '\0';
              cookie->expires = parse_max_age (max_age_str);
            }
        }
      else if (attr_len == 6 && strncasecmp (attr_start, "Domain", 6) == 0
               && attr_value_start != NULL)
        {
          char *d = Arena_alloc (arena, attr_val_len + 2, __FILE__, __LINE__);
          if (d != NULL)
            {
              /* Ensure leading dot for domain matching */
              if (attr_value_start[0] != '.')
                {
                  d[0] = '.';
                  memcpy (d + 1, attr_value_start, attr_val_len);
                  d[attr_val_len + 1] = '\0';
                }
              else
                {
                  memcpy (d, attr_value_start, attr_val_len);
                  d[attr_val_len] = '\0';
                }
              cookie->domain = d;
            }
        }
      else if (attr_len == 4 && strncasecmp (attr_start, "Path", 4) == 0
               && attr_value_start != NULL)
        {
          char *pt = Arena_alloc (arena, attr_val_len + 1, __FILE__, __LINE__);
          if (pt != NULL)
            {
              memcpy (pt, attr_value_start, attr_val_len);
              pt[attr_val_len] = '\0';
              cookie->path = pt;
            }
        }
      else if (attr_len == 8 && strncasecmp (attr_start, "SameSite", 8) == 0)
        {
          if (attr_value_start != NULL)
            {
              char ss[16];
              if (attr_val_len < sizeof (ss))
                {
                  memcpy (ss, attr_value_start, attr_val_len);
                  ss[attr_val_len] = '\0';
                  cookie->same_site = parse_same_site (ss);
                }
            }
        }
    }

  /* Set defaults from request URI */
  if (cookie->domain == NULL && request_uri != NULL && request_uri->host != NULL)
    {
      cookie->domain = arena_strdup (arena, request_uri->host);
    }

  if (cookie->path == NULL)
    {
      if (request_uri != NULL && request_uri->path != NULL)
        {
          get_default_path (request_uri->path, default_path,
                            sizeof (default_path));
          cookie->path = arena_strdup (arena, default_path);
        }
      else
        {
          cookie->path = arena_strdup (arena, "/");
        }
    }

  if (cookie->domain == NULL || cookie->name == NULL)
    return -1;

  return 0;
}

