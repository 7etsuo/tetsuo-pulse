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
 * - socket_util_arena_strdup() for string duplication
 */

#include "http/SocketHTTPClient.h"
#include "http/SocketHTTPClient-private.h"
#include "http/SocketHTTP.h"
#include "core/Arena.h"
#include "core/SocketUtil.h"

#include <assert.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Override log component for this module */
#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "HTTPClient-Cookie"

/* ============================================================================
 * Cookie Jar Configuration
 * ============================================================================
 * Cookie constants are defined in SocketHTTPClient-config.h:
 *   - HTTPCLIENT_COOKIE_HASH_SIZE (127) - hash table size
 *   - HTTPCLIENT_COOKIE_MAX_NAME_LEN (256) - max name length
 *   - HTTPCLIENT_COOKIE_MAX_VALUE_LEN (4096) - max value length
 *   - HTTPCLIENT_COOKIE_MAX_DOMAIN_LEN (256) - max domain length
 *   - HTTPCLIENT_COOKIE_MAX_PATH_LEN (1024) - max path length
 */

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

/**
 * cookie_hash - Hash function for cookie lookup (domain:path:name)
 * @domain: Cookie domain (case-insensitive)
 * @path: Cookie path (case-sensitive)
 * @name: Cookie name (case-sensitive)
 * @table_size: Hash table size
 *
 * Returns: Hash bucket index
 *
 * Uses DJB2 algorithm with additive variant for consistency with
 * socket_util_hash_djb2* functions. Domain is hashed case-insensitively
 * per RFC 6265, while path and name are case-sensitive.
 * Uses SOCKET_UTIL_DJB2_SEED from SocketUtil.h for consistency.
 */
static unsigned
cookie_hash (const char *domain, const char *path, const char *name,
             size_t table_size)
{
  unsigned h_domain = socket_util_hash_djb2_ci(domain, table_size);
  unsigned h_path = socket_util_hash_djb2(path, table_size);
  unsigned h_name = socket_util_hash_djb2(name, table_size);

  /* Combine hashes sequentially to approximate original behavior */
  unsigned hash = h_domain;
  hash = ((hash << 5) + hash + h_path) % table_size;
  hash = ((hash << 5) + hash + h_name) % table_size;

  return hash;
}

/**
 * domain_matches - Check if domain matches cookie domain
 * @request_domain: Domain from request URL
 * @cookie_domain: Domain from cookie
 *
 * Returns: 1 if matches, 0 otherwise
 *
 * Implements RFC 6265 Section 5.1.3 domain matching.
 * Handles leading dot in cookie domain for subdomain matching.
 */
static int
domain_matches (const char *request_domain, const char *cookie_domain)
{
  size_t req_len, cookie_len;
  const char *suffix;

  if (request_domain == NULL || cookie_domain == NULL)
    return 0;

  /* Handle leading dot in cookie domain */
  if (cookie_domain[0] == '.')
    cookie_domain++;

  /* Cache strlen results to avoid redundant calls */
  req_len = strlen (request_domain);
  cookie_len = strlen (cookie_domain);

  /* Exact match (case-insensitive) */
  if (req_len == cookie_len && strcasecmp (request_domain, cookie_domain) == 0)
    return 1;

  /* Domain suffix match - cookie domain must be suffix of request domain */
  if (req_len > cookie_len)
    {
      suffix = request_domain + (req_len - cookie_len);
      if (strcasecmp (suffix, cookie_domain) == 0)
        {
          /* Must be preceded by a dot for valid subdomain match */
          if (*(suffix - 1) == '.')
            return 1;
        }
    }

  return 0;
}

/**
 * path_matches - Check if path matches cookie path
 * @request_path: Path from request URL
 * @cookie_path: Path from cookie
 *
 * Returns: 1 if matches, 0 otherwise
 *
 * Implements RFC 6265 Section 5.1.4 path matching.
 * Cookie path must be a prefix of request path.
 */
static int
path_matches (const char *request_path, const char *cookie_path)
{
  size_t req_len, cookie_len;

  /* Apply defaults for NULL/empty paths */
  if (request_path == NULL)
    request_path = "/";
  if (cookie_path == NULL || cookie_path[0] == '\0')
    cookie_path = "/";

  /* Cache strlen results */
  req_len = strlen (request_path);
  cookie_len = strlen (cookie_path);

  /* Cookie path must be prefix of request path */
  if (strncmp (request_path, cookie_path, cookie_len) != 0)
    return 0;

  /* Match conditions per RFC 6265:
   * - Exact match (same length)
   * - Cookie path ends with '/'
   * - Request path has '/' after cookie path prefix */
  if (req_len == cookie_len)
    return 1;
  if (cookie_len > 0 && cookie_path[cookie_len - 1] == '/')
    return 1;
  if (request_path[cookie_len] == '/')
    return 1;

  return 0;
}

/**
 * Parse Max-Age attribute value
 */
/**
 * parse_max_age - Parse Max-Age attribute value from cookie
 * @value: String value of Max-Age (e.g. "3600")
 *
 * Returns: Unix timestamp of expiration, or 0 if invalid/session cookie
 * Note: Negative Max-Age treated as immediate expiration (time_t 1)
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
/**
 * parse_same_site - Parse SameSite attribute value
 * @value: String value ("Strict", "Lax", "None", case-insensitive)
 *
 * Returns: Parsed SameSite enum, defaults to LAX if unknown
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
 * get_default_path - Get default path from request URI
 * @request_path: Request URI path
 * @output: Output buffer for default path
 * @output_size: Size of output buffer
 *
 * Implements RFC 6265 Section 5.1.4 default-path algorithm.
 * Returns path up to (not including) the rightmost '/'.
 */
static void
get_default_path (const char *request_path, char *output, size_t output_size)
{
  const char *last_slash;
  size_t len;

  assert (output != NULL);
  assert (output_size > 0);

  /* Default to "/" for invalid/empty paths */
  if (request_path == NULL || request_path[0] != '/'
      || (last_slash = strrchr (request_path, '/')) == request_path)
    {
      snprintf (output, output_size, "/");
      return;
    }

  /* Copy path up to (not including) the last slash */
  len = (size_t)(last_slash - request_path);
  if (len >= output_size)
    len = output_size - 1;

  memcpy (output, request_path, len);
  output[len] = '\0';
}

/* NOTE: Uses socket_util_arena_strdup() from SocketUtil.h for string
 * duplication. This avoids code duplication and ensures consistent
 * allocation patterns across the codebase. */

/* ============================================================================
 * Cookie Jar Lifecycle
 * ============================================================================ */

SocketHTTPClient_CookieJar_T
SocketHTTPClient_CookieJar_new (void)
{
  SocketHTTPClient_CookieJar_T jar;
  Arena_T arena;

  arena = Arena_new ();
  if (arena == NULL) {
    SOCKET_ERROR_MSG("Arena_new failed");
    return NULL;
  }

  jar = Arena_alloc (arena, sizeof (*jar), __FILE__, __LINE__);
  if (jar == NULL) {
    SOCKET_ERROR_MSG("Arena_alloc failed for jar struct");
    Arena_dispose (&arena);
    return NULL;
  }

  memset (jar, 0, sizeof (*jar));
  jar->arena = arena;
  jar->hash_size = HTTPCLIENT_COOKIE_HASH_SIZE;

  jar->hash_table
      = Arena_calloc (arena, HTTPCLIENT_COOKIE_HASH_SIZE, sizeof (CookieEntry *), __FILE__,
                      __LINE__);
  if (jar->hash_table == NULL) {
    SOCKET_ERROR_MSG("Arena_calloc failed for hash table");
    Arena_dispose (&jar->arena);
    return NULL;
  }

  if (pthread_mutex_init (&jar->mutex, NULL) != 0) {
    SOCKET_ERROR_FMT("pthread_mutex_init failed for cookie jar");
    Arena_dispose (&jar->arena);
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

/**
 * cookie_entry_update_value_flags - Update cookie value and flags in existing entry
 * @entry: Cookie entry to update
 * @cookie: New cookie data for value and flags
 * @arena: Arena for strdup value
 *
 * Returns: 0 on success, -1 on alloc fail
 * Thread-safe: No (caller must hold mutex)
 */
static int
cookie_entry_update_value_flags (CookieEntry *entry,
                                 const SocketHTTPClient_Cookie *cookie,
                                 Arena_T arena)
{
  entry->cookie.value = socket_util_arena_strdup (arena, cookie->value);
  if (entry->cookie.value == NULL) {
    SOCKET_ERROR_MSG("socket_util_arena_strdup failed for cookie value update");
    return -1;
  }
  entry->cookie.expires = cookie->expires;
  entry->cookie.secure = cookie->secure;
  entry->cookie.http_only = cookie->http_only;
  entry->cookie.same_site = cookie->same_site;
  return 0;
}

/**
 * cookie_entry_init_full - Initialize new cookie entry with full data
 * @entry: Pre-allocated entry to initialize
 * @cookie: Source cookie data
 * @effective_path: Path to store (already resolved NULL to "/")
 * @arena: Arena for allocations
 *
 * Returns: 0 on success, -1 on alloc fail
 * Thread-safe: No (caller must hold mutex)
 */
static int
cookie_entry_init_full (CookieEntry *entry,
                        const SocketHTTPClient_Cookie *cookie,
                        const char *effective_path,
                        Arena_T arena)
{
  memset (entry, 0, sizeof (*entry));

  entry->cookie.name = socket_util_arena_strdup (arena, cookie->name);
  entry->cookie.value = socket_util_arena_strdup (arena, cookie->value);
  entry->cookie.domain = socket_util_arena_strdup (arena, cookie->domain);
  entry->cookie.path = socket_util_arena_strdup (arena, effective_path);
  entry->cookie.expires = cookie->expires;
  entry->cookie.secure = cookie->secure;
  entry->cookie.http_only = cookie->http_only;
  entry->cookie.same_site = cookie->same_site;

  if (entry->cookie.name == NULL || entry->cookie.value == NULL ||
      entry->cookie.domain == NULL || entry->cookie.path == NULL) {
    SOCKET_ERROR_MSG("socket_util_arena_strdup failed for new cookie fields");
    return -1;
  }
  return 0;
}

/**
 * cookie_jar_find_entry - Find cookie entry by domain, path, name
 * @jar: Cookie jar
 * @domain: Domain to match (case-insensitive)
 * @path: Path to match (case-sensitive, NULL defaults to "/")
 * @name: Name to match (case-sensitive)
 *
 * Returns: Matching entry or NULL
 * Thread-safe: No (caller must hold mutex)
 */
static CookieEntry *
cookie_jar_find_entry (SocketHTTPClient_CookieJar_T jar,
                       const char *domain, const char *path, const char *name)
{
  const char *effective_path = path ? path : "/";
  unsigned hash = cookie_hash (domain, effective_path, name, jar->hash_size);

  CookieEntry *entry = jar->hash_table[hash];
  while (entry != NULL)
    {
      const char *entry_path = entry->cookie.path ? entry->cookie.path : "/";
      if (strcmp (entry->cookie.name, name) == 0 &&
          strcasecmp (entry->cookie.domain, domain) == 0 &&
          strcmp (entry_path, effective_path) == 0)
        {
          return entry;
        }
      entry = entry->next;
    }
  return NULL;
}

/* ============================================================================
 * Cookie Storage Operations
 * ============================================================================ */

int
SocketHTTPClient_CookieJar_set (SocketHTTPClient_CookieJar_T jar,
                                const SocketHTTPClient_Cookie *cookie)
{
  assert (jar != NULL);
  assert (cookie != NULL);
  assert (cookie->name != NULL);
  assert (cookie->value != NULL);
  assert (cookie->domain != NULL);

  pthread_mutex_lock (&jar->mutex);

  const char *effective_path = cookie->path ? cookie->path : "/";
  unsigned hash = cookie_hash (cookie->domain, effective_path, cookie->name, jar->hash_size);

  CookieEntry *entry = cookie_jar_find_entry (jar, cookie->domain, effective_path, cookie->name);

  if (entry != NULL) {
    /* Replace existing cookie */
    if (cookie_entry_update_value_flags (entry, cookie, jar->arena) != 0) {
      pthread_mutex_unlock (&jar->mutex);
      return -1;
    }
    pthread_mutex_unlock (&jar->mutex);
    return 0;
  }

  /* Create new entry */
  entry = Arena_alloc (jar->arena, sizeof (*entry), __FILE__, __LINE__);
  if (entry == NULL) {
    SOCKET_ERROR_MSG("Arena_alloc failed for new cookie entry");
    pthread_mutex_unlock (&jar->mutex);
    return -1;
  }

  if (cookie_entry_init_full (entry, cookie, effective_path, jar->arena) != 0) {
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
  assert (jar != NULL);
  assert (domain != NULL);
  assert (name != NULL);

  const char *effective_path = path ? path : "/";

  pthread_mutex_lock (&jar->mutex);

  CookieEntry *entry = cookie_jar_find_entry (jar, domain, effective_path, name);

  pthread_mutex_unlock (&jar->mutex);

  return entry ? &entry->cookie : NULL;
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
  char line[HTTPCLIENT_COOKIE_FILE_LINE_SIZE];

  assert (jar != NULL);
  assert (filename != NULL);

  f = fopen (filename, "r");
  if (f == NULL) {
    SOCKET_ERROR_FMT("fopen(\"%s\", \"r\") failed", filename);
    return -1;
  }

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

          if (SocketHTTPClient_CookieJar_set (jar, &cookie) != 0) {
            SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT, "Failed to add cookie from file line (error: %s)", Socket_GetLastError ());
          }
        }
    }

  if (ferror (f)) {
    SOCKET_ERROR_MSG("Error reading cookie file %s", filename);
    fclose (f);
    return -1;
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
  if (f == NULL) {
    SOCKET_ERROR_FMT("fopen(\"%s\", \"w\") failed", filename);
    return -1;
  }

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

  if (ferror (f)) {
    SOCKET_ERROR_MSG("Error writing to cookie file %s", filename);
    fclose (f);
    return -1;
  }

  fclose (f);
  return 0;
}

/* ============================================================================
 * Cookie Request/Response Integration
 * ============================================================================ */

/**
 * cookie_matches_request - Check if cookie matches request
 * @cookie: Cookie to check
 * @host: Request hostname
 * @path: Request path
 * @is_secure: 1 if HTTPS, 0 if HTTP
 * @now: Current time for expiration check
 *
 * Returns: 1 if cookie should be sent, 0 otherwise
 */
static int
cookie_matches_request (const SocketHTTPClient_Cookie *cookie, const char *host,
                        const char *path, int is_secure, time_t now)
{
  /* Check expiration */
  if (cookie->expires > 0 && cookie->expires < now)
    return 0;

  /* Check secure flag */
  if (cookie->secure && !is_secure)
    return 0;

  /* Check domain match */
  if (!domain_matches (host, cookie->domain))
    return 0;

  /* Check path match */
  if (!path_matches (path, cookie->path))
    return 0;

  return 1;
}

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

          if (!cookie_matches_request (c, uri->host, request_path, is_secure,
                                       now))
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

/* ============================================================================
 * Set-Cookie Parsing Helpers
 * ============================================================================ */

/**
 * skip_whitespace - Skip leading whitespace characters
 * @p: Current position pointer
 * @end: End of string
 *
 * Returns: Pointer to first non-whitespace character
 */
/**
 * skip_whitespace - Skip leading whitespace characters in cookie attributes
 * @p: Current position pointer (updated)
 * @end: End of string
 *
 * Returns: Pointer to first non-whitespace character or end
 * Thread-safe: Yes (pure function)
 */
static const char *
skip_whitespace (const char *p, const char *end)
{
  while (p < end && (*p == ' ' || *p == '\t'))
    p++;
  return p;
}

/**
 * trim_trailing_whitespace - Find end after trimming trailing whitespace
 * @start: Start of string
 * @end: Current end position
 *
 * Returns: New end position after trimming
 */
/**
 * trim_trailing_whitespace - Trim trailing whitespace from string end
 * @start: Start of string (for bounds check)
 * @end: Current end position (updated)
 *
 * Returns: New end position after trimming trailing spaces/tabs
 * Thread-safe: Yes (pure function)
 */
static const char *
trim_trailing_whitespace (const char *start, const char *end)
{
  while (end > start && (*(end - 1) == ' ' || *(end - 1) == '\t'))
    end--;
  return end;
}

/**
 * parse_token - Parse a token (non-quoted name or attribute) 
 * @p: Current position (updated)
 * @end: End of string
 * @token_start: Output start of token
 * @token_end: Output end of token (trimmed)
 *
 * Returns: 0 on success, -1 if empty or invalid token
 * Thread-safe: Yes
 */
static int
parse_token (const char **p, const char *end, 
             const char **token_start, const char **token_end)
{
  *p = skip_whitespace (*p, end);
  const char *start = *p;
  if (start >= end)
    return -1;

  const char *tok_end = start;
  while (tok_end < end && *tok_end != '=' && *tok_end != ';')
    tok_end++;
  const char *trimmed_end = trim_trailing_whitespace (start, tok_end);

  if (trimmed_end == start)
    return -1; /* Empty token */

  *p = tok_end;
  *token_start = start;
  *token_end = trimmed_end;
  return 0;
}

/**
 * parse_value - Parse cookie value (quoted or unquoted)
 * @p: Current position (updated)
 * @end: End of string
 * @value_start: Output start of value
 * @value_end: Output end of value (trimmed)
 *
 * Handles quoted values with escape check? No, per RFC simple ".
 * Returns: 0 on success, -1 on invalid (unclosed quote)
 * Thread-safe: Yes
 */
static int
parse_value (const char **p, const char *end, 
             const char **value_start, const char **value_end)
{
  *p = skip_whitespace (*p, end);
  const char *start = *p;
  if (start >= end)
    return -1;

  if (*start == '"') {
    const char *s = ++ (*p);
    while (*p < end && **p != '"')
      (*p)++;
    const char *e = *p;
    if (*p >= end || **p != '"') {
      SOCKET_ERROR_MSG("Unclosed quoted cookie value in Set-Cookie header");
      return -1;
    }
    (*p)++; /* Skip closing quote */
    *value_end = trim_trailing_whitespace (s, e);
    *value_start = s;
  } else {
    const char *s = start;
    while (*p < end && **p != ';')
      (*p)++;
    *value_end = trim_trailing_whitespace (s, *p);
    *value_start = s;
  }
  return 0;
}

/**
 * parse_cookie_name_value - Parse name=value from Set-Cookie header
 * @p: Start of cookie string (modified to point past value)
 * @end: End of cookie string
 * @cookie: Cookie to populate with name and value
 * @arena: Arena for allocation
 *
 * Returns: 0 on success, -1 on failure
 */
static int
parse_cookie_name_value (const char **p, const char *end,
                         SocketHTTPClient_Cookie *cookie, Arena_T arena)
{
  const char *name_start, *name_end;
  const char *value_start, *value_end;
  const char *ptr;
  size_t name_len, val_len;
  char *n, *v;

  ptr = *p;

  /* Skip leading whitespace */
  ptr = skip_whitespace (ptr, end);

  /* Parse name */
  name_start = ptr;
  while (ptr < end && *ptr != '=' && *ptr != ';')
    ptr++;
  name_end = trim_trailing_whitespace (name_start, ptr);

  if (name_end == name_start || ptr >= end || *ptr != '=') {
    SOCKET_ERROR_MSG("Invalid cookie name in Set-Cookie header");
    return -1;
  }

  ptr++; /* Skip '=' */

  /* Parse value */
  value_start = ptr;

  /* Handle quoted value */
  if (ptr < end && *ptr == '"')
    {
      value_start = ++ptr;
      while (ptr < end && *ptr != '"')
        ptr++;
      value_end = ptr;
      if (ptr < end && *ptr == '"') {
        ptr++; /* Skip closing quote */
      } else {
        SOCKET_ERROR_MSG("Unclosed quoted cookie value in Set-Cookie header");
        return -1;
      }
    }
  else
    {
      while (ptr < end && *ptr != ';')
        ptr++;
      value_end = ptr;
    }

  value_end = trim_trailing_whitespace (value_start, value_end);

  /* Allocate name and value */
  name_len = (size_t)(name_end - name_start);
  val_len = (size_t)(value_end - value_start);

  n = Arena_alloc (arena, name_len + 1, __FILE__, __LINE__);
  v = Arena_alloc (arena, val_len + 1, __FILE__, __LINE__);

  if (n == NULL || v == NULL) {
    SOCKET_ERROR_MSG("Arena_alloc failed for cookie name or value strings");
    return -1;
  }

  memcpy (n, name_start, name_len);
  n[name_len] = '\0';
  memcpy (v, value_start, val_len);
  v[val_len] = '\0';

  cookie->name = n;
  cookie->value = v;
  *p = ptr;

  return 0;
}

/**
 * parse_cookie_attribute - Parse and apply a single cookie attribute
 * @attr_start: Start of attribute name
 * @attr_len: Length of attribute name
 * @attr_value_start: Start of attribute value (NULL if flag-only)
 * @attr_val_len: Length of attribute value
 * @cookie: Cookie to update
 * @arena: Arena for allocation
 */
static void
parse_cookie_attribute (const char *attr_start, size_t attr_len,
                        const char *attr_value_start, size_t attr_val_len,
                        SocketHTTPClient_Cookie *cookie, Arena_T arena)
{
  /* Boolean attributes */
  if (attr_len == 6 && strncasecmp (attr_start, "Secure", 6) == 0)
    {
      cookie->secure = 1;
      return;
    }

  if (attr_len == 8 && strncasecmp (attr_start, "HttpOnly", 8) == 0)
    {
      cookie->http_only = 1;
      return;
    }

  /* Value-required attributes */
  if (attr_value_start == NULL)
    return;

  if (attr_len == 7 && strncasecmp (attr_start, "Expires", 7) == 0)
    {
      time_t expires;
      if (SocketHTTP_date_parse (attr_value_start, attr_val_len, &expires) == 0)
        cookie->expires = expires;
    }
  else if (attr_len == 7 && strncasecmp (attr_start, "Max-Age", 7) == 0)
    {
      char max_age_str[HTTPCLIENT_COOKIE_MAX_AGE_SIZE];
      if (attr_val_len < sizeof (max_age_str))
        {
          memcpy (max_age_str, attr_value_start, attr_val_len);
          max_age_str[attr_val_len] = '\0';
          cookie->expires = parse_max_age (max_age_str);
        }
    }
  else if (attr_len == 6 && strncasecmp (attr_start, "Domain", 6) == 0)
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
  else if (attr_len == 4 && strncasecmp (attr_start, "Path", 4) == 0)
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
      char ss[HTTPCLIENT_COOKIE_SAMESITE_SIZE];
      if (attr_val_len < sizeof (ss))
        {
          memcpy (ss, attr_value_start, attr_val_len);
          ss[attr_val_len] = '\0';
          cookie->same_site = parse_same_site (ss);
        }
    }
}

/**
 * parse_cookie_attributes - Parse all attributes from Set-Cookie header
 * @p: Position after name=value (modified during parsing)
 * @end: End of cookie string
 * @cookie: Cookie to update with attributes
 * @arena: Arena for allocation
 */
static void
parse_cookie_attributes (const char **p, const char *end,
                         SocketHTTPClient_Cookie *cookie, Arena_T arena)
{
  const char *ptr = *p;

  while (ptr < end)
    {
      const char *attr_start, *attr_end;
      const char *attr_value_start = NULL, *attr_value_end = NULL;

      /* Skip ';' and whitespace */
      while (ptr < end && (*ptr == ';' || *ptr == ' ' || *ptr == '\t'))
        ptr++;

      if (ptr >= end)
        break;

      /* Parse attribute name */
      attr_start = ptr;
      while (ptr < end && *ptr != '=' && *ptr != ';')
        ptr++;
      attr_end = trim_trailing_whitespace (attr_start, ptr);

      /* Parse attribute value if present */
      if (ptr < end && *ptr == '=')
        {
          ptr++;
          ptr = skip_whitespace (ptr, end);
          attr_value_start = ptr;
          while (ptr < end && *ptr != ';')
            ptr++;
          attr_value_end = trim_trailing_whitespace (attr_value_start, ptr);
        }

      /* Process this attribute */
      parse_cookie_attribute (
          attr_start, (size_t)(attr_end - attr_start), attr_value_start,
          attr_value_start ? (size_t)(attr_value_end - attr_value_start) : 0,
          cookie, arena);
    }

  *p = ptr;
}

/**
 * apply_cookie_defaults - Apply default values from request URI
 * @cookie: Cookie to update
 * @request_uri: Request URI for defaults
 * @arena: Arena for allocation
 */
static void
apply_cookie_defaults (SocketHTTPClient_Cookie *cookie,
                       const SocketHTTP_URI *request_uri, Arena_T arena)
{
  char default_path[HTTPCLIENT_COOKIE_MAX_PATH_LEN];

  /* Set domain from request host if not specified */
  if (cookie->domain == NULL && request_uri != NULL
      && request_uri->host != NULL)
    {
      cookie->domain = socket_util_arena_strdup (arena, request_uri->host);
    }

  /* Set path from request path if not specified */
  if (cookie->path == NULL)
    {
      if (request_uri != NULL && request_uri->path != NULL)
        {
          get_default_path (request_uri->path, default_path,
                            sizeof (default_path));
          cookie->path = socket_util_arena_strdup (arena, default_path);
        }
      else
        {
          cookie->path = socket_util_arena_strdup (arena, "/");
        }
    }
}

/* ============================================================================
 * Set-Cookie Parsing Main Function
 * ============================================================================ */

/**
 * httpclient_parse_set_cookie - Parse Set-Cookie header value
 * @value: Set-Cookie header value
 * @len: Length of value (0 for strlen)
 * @request_uri: Request URI for defaults
 * @cookie: Output cookie structure
 * @arena: Arena for allocation
 *
 * Returns: 0 on success, -1 on failure
 *
 * Parses RFC 6265 Set-Cookie header into cookie structure.
 */
int
httpclient_parse_set_cookie (const char *value, size_t len,
                             const SocketHTTP_URI *request_uri,
                             SocketHTTPClient_Cookie *cookie, Arena_T arena)
{
  const char *p = value;
  const char *end = value + (len > 0 ? len : strlen (value));

  assert (value != NULL);
  assert (cookie != NULL);
  assert (arena != NULL);

  memset (cookie, 0, sizeof (*cookie));

  /* Parse name=value */
  if (parse_cookie_name_value (&p, end, cookie, arena) != 0) {
    SOCKET_ERROR_MSG("Invalid Set-Cookie: missing or malformed name=value");
    return -1;
  }

  /* Parse attributes */
  parse_cookie_attributes (&p, end, cookie, arena);

  /* Apply defaults from request URI */
  apply_cookie_defaults (cookie, request_uri, arena);

  /* Validate required fields */
  if (cookie->domain == NULL || cookie->name == NULL) {
    SOCKET_ERROR_MSG("Invalid Set-Cookie: missing required domain or name field after parsing");
    return -1;
  }

  return 0;
}

