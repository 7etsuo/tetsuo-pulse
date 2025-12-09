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

#include <assert.h>

#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/Except.h"
#include "core/SocketCrypto.h"
#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"

SOCKET_DECLARE_MODULE_EXCEPTION (SocketHTTPClient);

#include "core/Arena.h"
#include "core/SocketUtil.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTPClient-private.h"
#include "http/SocketHTTPClient.h"

/* Override log component for this module */
#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "HTTPClient-Cookie"

SOCKET_DECLARE_MODULE_EXCEPTION (SocketHTTPClient);

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
 * ============================================================================
 */

/**
 * is_valid_cookie_octet - Check if char is valid in cookie name/value
 * @c: Character to check
 *
 * Returns: 1 if valid, 0 if invalid
 *
 * Per RFC 6265 §3.1, cookie-octet excludes CTL chars (0-31, 127-159).
 * For unquoted strings, also excludes ; = , and space.
 * Since we parse quoted, allow " in quoted context, but for simplicity,
 * reject all CTL and key separators.
 */
static int
is_valid_cookie_octet (unsigned char c)
{
  /* Reject CTL chars */
  if (c <= 31 || (c >= 127 && c <= 159))
    return 0;

  /* Reject separators that would break parsing */
  if (c == ';' || c == '=' || c == ',' || c == ' ')
    return 0;

  return 1;
}

/**
 * cookie_hash - Hash function for cookie lookup (domain:path:name)
 * @domain: Cookie domain (case-insensitive)
 * @path: Cookie path (case-sensitive)
 * @name: Cookie name (case-sensitive)
 * @table_size: Hash table size
 * @seed: Random seed for collision resistance
 *
 * Returns: Hash bucket index
 *
 * Uses DJB2 algorithm with randomization for collision resistance.
 * Domain is hashed case-insensitively per RFC 6265.
 */
static unsigned
cookie_hash (const char *domain, const char *path, const char *name,
             size_t table_size, unsigned seed)
{
  unsigned h_domain = socket_util_hash_djb2_ci (domain, table_size);
  unsigned h_path = socket_util_hash_djb2 (path, table_size);
  unsigned h_name = socket_util_hash_djb2 (name, table_size);

  /* Mix with seed for collision resistance */
  unsigned hash = seed;
  hash ^= h_domain;
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
parse_max_age (const char *value, size_t len)
{
  if (value == NULL || len == 0)
    return 0;

  /* Skip leading whitespace (trimmed input, but for robustness) */
  const char *start = value;
  size_t remaining = len;
  while (remaining > 0 && (*start == ' ' || *start == '\t'))
    {
      start++;
      remaining--;
    }
  if (remaining == 0)
    return 0;

  /* Parse optional sign */
  int sign = 1;
  if (*start == '-')
    {
      sign = -1;
      start++;
      remaining--;
      if (remaining == 0)
        return 0;
    }

  /* Parse digits */
  long age = 0;
  int has_digit = 0;
  while (remaining > 0 && *start >= '0' && *start <= '9')
    {
      has_digit = 1;
      /* Check for overflow BEFORE multiplication to avoid undefined behavior.
       * The maximum we can safely add is 9 (a single digit), so check if
       * age * 10 + 9 would overflow. */
      if (age > (LONG_MAX - 9) / 10)
        return 0; /* Would overflow */
      age = age * 10 + (*start - '0');
      start++;
      remaining--;
    }

  if (!has_digit || remaining > 0)
    return 0; /* No digits or trailing non-digits */

  age *= sign;
  if (age <= 0)
    return 1; /* Expire immediately */

  /* Clamp age to maximum allowed */
  if (age > HTTPCLIENT_MAX_COOKIE_AGE_SEC)
    age = HTTPCLIENT_MAX_COOKIE_AGE_SEC;

  /* Safe addition to prevent overflow */
  time_t now = time (NULL);
  time_t expires;
  size_t temp;
  if (!SocketSecurity_check_add ((size_t)now, (size_t)age, &temp))
    return 1; /* On overflow, expire immediately */
  expires = (time_t)temp;

  return expires;
}

/* SameSite constants */
static const char COOKIE_SAMESITE_STRICT_STR[] = "Strict";
static const char COOKIE_SAMESITE_LAX_STR[] = "Lax";
static const char COOKIE_SAMESITE_NONE_STR[] = "None";

/**
 * parse_same_site - Parse SameSite attribute value
 * @value: String value ("Strict", "Lax", "None", case-insensitive)
 *
 * Returns: Parsed SameSite enum, defaults to LAX if unknown
 */
static SocketHTTPClient_SameSite
parse_same_site (const char *value, size_t len)
{
  if (value == NULL || len == 0)
    return COOKIE_SAMESITE_LAX; /* Default per RFC 6265bis */

  size_t strict_len = sizeof (COOKIE_SAMESITE_STRICT_STR) - 1;
  if (len == strict_len
      && strncasecmp (value, COOKIE_SAMESITE_STRICT_STR, strict_len) == 0)
    return COOKIE_SAMESITE_STRICT;
  size_t lax_len = sizeof (COOKIE_SAMESITE_LAX_STR) - 1;
  if (len == lax_len
      && strncasecmp (value, COOKIE_SAMESITE_LAX_STR, lax_len) == 0)
    return COOKIE_SAMESITE_LAX;
  size_t none_len = sizeof (COOKIE_SAMESITE_NONE_STR) - 1;
  if (len == none_len
      && strncasecmp (value, COOKIE_SAMESITE_NONE_STR, none_len) == 0)
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
 * ============================================================================
 */

SocketHTTPClient_CookieJar_T
SocketHTTPClient_CookieJar_new (void)
{
  SocketHTTPClient_CookieJar_T jar = NULL;
  Arena_T arena = NULL;

  TRY arena = Arena_new ();
  if (arena == NULL)
    RAISE_HTTPCLIENT_ERROR (SocketHTTPClient_Failed);

  jar = Arena_calloc (arena, 1, sizeof (*jar), __FILE__, __LINE__);
  if (jar == NULL)
    RAISE_HTTPCLIENT_ERROR (SocketHTTPClient_Failed);

  jar->arena = arena;
  jar->hash_size = HTTPCLIENT_COOKIE_HASH_SIZE;
  jar->max_cookies = HTTPCLIENT_MAX_COOKIES;
  SocketCrypto_random_bytes ((unsigned char *)&jar->hash_seed,
                             sizeof (jar->hash_seed));

  jar->hash_table = Arena_calloc (arena, HTTPCLIENT_COOKIE_HASH_SIZE,
                                  sizeof (CookieEntry *), __FILE__, __LINE__);
  if (jar->hash_table == NULL)
    RAISE_HTTPCLIENT_ERROR (SocketHTTPClient_Failed);

  if (pthread_mutex_init (&jar->mutex, NULL) != 0)
    RAISE_HTTPCLIENT_ERROR (SocketHTTPClient_Failed);

  return jar;
  EXCEPT (SocketHTTPClient_Failed)
  HTTPCLIENT_ERROR_MSG ("Failed to create cookie jar");
  if (arena != NULL)
    Arena_dispose (&arena);
  END_TRY;

  return NULL;
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
 * cookie_entry_update_value_flags - Update cookie value and flags in existing
 * entry
 * @entry: Cookie entry to update
 * @cookie: New cookie data for value and flags
 * @arena: Arena for strdup value
 *
 * Thread-safe: No (caller must hold mutex)
 * Raises: SocketHTTPClient_Failed on allocation failure
 */
static void
cookie_entry_update_value_flags (CookieEntry *entry,
                                 const SocketHTTPClient_Cookie *cookie,
                                 Arena_T arena)
{
  entry->cookie.value = socket_util_arena_strdup (arena, cookie->value);
  if (entry->cookie.value == NULL)
    RAISE_HTTPCLIENT_ERROR (SocketHTTPClient_Failed);
  entry->cookie.expires = cookie->expires;
  entry->cookie.secure = cookie->secure;
  entry->cookie.http_only = cookie->http_only;
  entry->cookie.same_site = cookie->same_site;
}

/**
 * evict_oldest_cookie - Remove the oldest cookie from jar
 * @jar: Cookie jar
 *
 * Finds and removes the cookie with the oldest creation time.
 * Thread-safe: No (caller must hold mutex)
 */
static void
evict_oldest_cookie (SocketHTTPClient_CookieJar_T jar)
{
  time_t oldest_time = (time_t)-1;
  CookieEntry **oldest_pp = NULL;
  size_t i;

  for (i = 0; i < jar->hash_size; i++)
    {
      CookieEntry **pp = &jar->hash_table[i];
      while (*pp != NULL)
        {
          CookieEntry *entry = *pp;
          if (entry->created < oldest_time)
            {
              oldest_time = entry->created;
              oldest_pp = pp;
            }
          pp = &entry->next;
        }
    }

  if (oldest_pp != NULL)
    {
      CookieEntry *entry = *oldest_pp;
      *oldest_pp = entry->next;
      jar->count--;
    }
}

/**
 * cookie_entry_init_full - Initialize new cookie entry with full data
 * @entry: Pre-allocated entry to initialize
 * @cookie: Source cookie data
 * @effective_path: Path to store (already resolved NULL to "/")
 * @arena: Arena for allocations
 *
 * Thread-safe: No (caller must hold mutex)
 * Raises: SocketHTTPClient_Failed on allocation failure
 */
static void
cookie_entry_init_full (CookieEntry *entry,
                        const SocketHTTPClient_Cookie *cookie,
                        const char *effective_path, Arena_T arena)
{
  /* entry zero-initialized by caller Arena_calloc */

  entry->cookie.name = socket_util_arena_strdup (arena, cookie->name);
  if (entry->cookie.name == NULL)
    RAISE_HTTPCLIENT_ERROR (SocketHTTPClient_Failed);

  entry->cookie.value = socket_util_arena_strdup (arena, cookie->value);
  if (entry->cookie.value == NULL)
    RAISE_HTTPCLIENT_ERROR (SocketHTTPClient_Failed);

  entry->cookie.domain = socket_util_arena_strdup (arena, cookie->domain);
  if (entry->cookie.domain == NULL)
    RAISE_HTTPCLIENT_ERROR (SocketHTTPClient_Failed);

  entry->cookie.path = socket_util_arena_strdup (arena, effective_path);
  if (entry->cookie.path == NULL)
    RAISE_HTTPCLIENT_ERROR (SocketHTTPClient_Failed);

  entry->cookie.expires = cookie->expires;
  entry->cookie.secure = cookie->secure;
  entry->cookie.http_only = cookie->http_only;
  entry->cookie.same_site = cookie->same_site;
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
cookie_jar_find_entry (SocketHTTPClient_CookieJar_T jar, const char *domain,
                       const char *path, const char *name)
{
  const char *effective_path = path ? path : "/";
  unsigned hash = cookie_hash (domain, effective_path, name, jar->hash_size,
                               jar->hash_seed);

  CookieEntry *entry = jar->hash_table[hash];
  int chain_len = 0;
  while (entry != NULL)
    {
      chain_len++;
      const char *entry_path = entry->cookie.path ? entry->cookie.path : "/";
      if (strcmp (entry->cookie.name, name) == 0
          && strcasecmp (entry->cookie.domain, domain) == 0
          && strcmp (entry_path, effective_path) == 0)
        {
          if (chain_len > HTTPCLIENT_COOKIE_MAX_CHAIN_LEN)
            {
              SocketLog_emitf (
                  SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                  "Hash collision chain too long (%d > %d), potential DoS",
                  chain_len, HTTPCLIENT_COOKIE_MAX_CHAIN_LEN);
            }
          return entry;
        }
      entry = entry->next;
    }
  if (chain_len > HTTPCLIENT_COOKIE_MAX_CHAIN_LEN)
    {
      SocketLog_emitf (
          SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
          "Hash collision chain too long (%d > %d), potential DoS", chain_len,
          HTTPCLIENT_COOKIE_MAX_CHAIN_LEN);
    }
  return NULL;
}

/* ============================================================================
 * Cookie Storage Operations
 * ============================================================================
 */

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

  int result = 0;

  TRY const char *effective_path = cookie->path ? cookie->path : "/";
  unsigned hash = cookie_hash (cookie->domain, effective_path, cookie->name,
                               jar->hash_size, jar->hash_seed);

  CookieEntry *entry = cookie_jar_find_entry (jar, cookie->domain,
                                              effective_path, cookie->name);

  if (entry != NULL)
    {
      /* Replace existing cookie */
      cookie_entry_update_value_flags (entry, cookie, jar->arena);
    }
  else
    {
      /* Check cookie limit */
      if (jar->count >= jar->max_cookies)
        {
          /* Try to clear expired first */
          SocketHTTPClient_CookieJar_clear_expired (jar);
          if (jar->count >= jar->max_cookies)
            {
              /* Still full, evict oldest */
              evict_oldest_cookie (jar);
              if (jar->count >= jar->max_cookies)
                {
                  /* Eviction failed or jar corrupted, reject */
                  SocketLog_emitf (
                      SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                      "Cookie jar at max capacity (%zu), rejecting new cookie",
                      jar->max_cookies);
                  result = -1;
                  goto unlock;
                }
            }
        }

      /* Create new entry (calloc to zero-initialize) */
      entry
          = Arena_calloc (jar->arena, 1, sizeof (*entry), __FILE__, __LINE__);
      if (entry == NULL)
        RAISE_HTTPCLIENT_ERROR (SocketHTTPClient_Failed);

      cookie_entry_init_full (entry, cookie, effective_path, jar->arena);
      entry->created = time (NULL);

      /* Add to hash table */
      entry->next = jar->hash_table[hash];
      jar->hash_table[hash] = entry;
      if (!SocketSecurity_check_add (jar->count, 1, &jar->count))
        {
          /* Overflow, but unlikely with max_cookies=10000 */
          jar->count++;
        }
    }
  EXCEPT (SocketHTTPClient_Failed)
  result = -1;
  HTTPCLIENT_ERROR_MSG ("Failed to set cookie");
  FINALLY
  /* No additional cleanup needed - arena retains memory on failure */
  END_TRY;
  ;

unlock:
  pthread_mutex_unlock (&jar->mutex);
  return result;
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

  CookieEntry *entry
      = cookie_jar_find_entry (jar, domain, effective_path, name);

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
 * ============================================================================
 */

/**
 * Thread-safety note: CookieJar_load is not thread-safe with concurrent
 * operations on the same jar. Caller must ensure exclusive access.
 */
int
SocketHTTPClient_CookieJar_load (SocketHTTPClient_CookieJar_T jar,
                                 const char *filename)
{
  FILE *f;
  char line[HTTPCLIENT_COOKIE_FILE_LINE_SIZE];

  assert (jar != NULL);
  assert (filename != NULL);

  f = fopen (filename, "r");
  if (f == NULL)
    {
      HTTPCLIENT_ERROR_FMT ("fopen(\"%s\", \"r\") failed", filename);
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
          /* Validate lengths */
          size_t domain_len = strlen (domain);
          size_t path_len = strlen (path);
          size_t name_len = strlen (name);
          size_t value_len = strlen (value);

          if (!SocketSecurity_check_size (domain_len)
              || !SocketSecurity_check_size (path_len)
              || !SocketSecurity_check_size (name_len)
              || !SocketSecurity_check_size (value_len)
              || domain_len > HTTPCLIENT_COOKIE_MAX_DOMAIN_LEN
              || path_len > HTTPCLIENT_COOKIE_MAX_PATH_LEN
              || name_len > HTTPCLIENT_COOKIE_MAX_NAME_LEN
              || value_len > HTTPCLIENT_COOKIE_MAX_VALUE_LEN)
            {
              SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                               "Cookie rejected: field too long (domain:%zu, "
                               "path:%zu, name:%zu, value:%zu)",
                               domain_len, path_len, name_len, value_len);
              continue;
            }

          /* Validate path starts with '/' */
          if (path[0] != '/')
            {
              SocketLog_emitf (
                  SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                  "Cookie rejected: invalid path '%s' (must start with '/')",
                  path);
              continue;
            }

          /* Validate secure is TRUE or FALSE */
          if (strcmp (secure, "TRUE") != 0 && strcmp (secure, "FALSE") != 0)
            {
              SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                               "Cookie rejected: invalid secure flag '%s'",
                               secure);
              continue;
            }

          /* Validate expires is reasonable */
          time_t expires_time = (time_t)strtoll (expires, NULL, 10);
          time_t now = time (NULL);
          if (expires_time != 0
              && (expires_time < now - 86400
                  || expires_time > now + 365 * 24 * 3600LL))
            {
              SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                               "Cookie rejected: unreasonable expires %lld",
                               (long long)expires_time);
              continue;
            }

          /* Validate name/value characters */
          int valid = 1;
          for (size_t i = 0; i < name_len && valid; i++)
            {
              if (!is_valid_cookie_octet ((unsigned char)name[i]))
                {
                  valid = 0;
                }
            }
          for (size_t i = 0; i < value_len && valid; i++)
            {
              if (!is_valid_cookie_octet ((unsigned char)value[i]))
                {
                  valid = 0;
                }
            }
          if (!valid)
            {
              SocketLog_emitf (
                  SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                  "Cookie rejected: invalid characters in name/value");
              continue;
            }

          memset (&cookie, 0, sizeof (cookie));
          cookie.domain = domain;
          cookie.path = path;
          cookie.secure = (strcmp (secure, "TRUE") == 0);
          cookie.expires = expires_time;
          cookie.name = name;
          cookie.value = value;

          if (SocketHTTPClient_CookieJar_set (jar, &cookie) != 0)
            {
              SocketLog_emitf (
                  SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                  "Failed to add cookie from file line (error: %s)",
                  Socket_GetLastError ());
            }
        }
    }

  if (ferror (f))
    {
      HTTPCLIENT_ERROR_MSG ("Error reading cookie file %s", filename);
      fclose (f);
      return -1;
    }

  fclose (f);

  /* Clean up any expired cookies loaded from file */
  SocketHTTPClient_CookieJar_clear_expired (jar);

  return 0;
}

/**
 * Thread-safety note: CookieJar_save is not thread-safe with concurrent
 * operations on the same jar. Caller must ensure exclusive access.
 */
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
    {
      HTTPCLIENT_ERROR_FMT ("fopen(\"%s\", \"w\") failed", filename);
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

          /* Validate no \r\n in name/value (breaks Netscape format) */
          if (strchr (c->name, '\r') || strchr (c->name, '\n')
              || strchr (c->value, '\r') || strchr (c->value, '\n'))
            {
              SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                               "Cookie '%s' contains \\r\\n, skipping save",
                               c->name);
              entry = entry->next;
              continue;
            }

          /* Format: domain\tflag\tpath\tsecure\texpires\tname\tvalue */
          fprintf (f, "%s\t%s\t%s\t%s\t%lld\t%s\t%s\n", c->domain,
                   (c->domain[0] == '.') ? "TRUE" : "FALSE",
                   c->path ? c->path : "/", c->secure ? "TRUE" : "FALSE",
                   (long long)c->expires, c->name, c->value);

          entry = entry->next;
        }
    }

  pthread_mutex_unlock (&jar->mutex);

  if (ferror (f))
    {
      HTTPCLIENT_ERROR_MSG ("Error writing to cookie file %s", filename);
      fclose (f);
      return -1;
    }

  fclose (f);
  return 0;
}

/* ============================================================================
 * Cookie Request/Response Integration
 * ============================================================================
 */

/**
 * cookie_matches_request - Check if cookie matches request
 * @cookie: Cookie to check
 * @host: Request hostname
 * @path: Request path
 * @is_secure: 1 if HTTPS, 0 if HTTP
 * @now: Current time for expiration check
 * @enforce_samesite: 1 if SameSite enforcement enabled
 * @is_cross_site: 1 if request is cross-site (default 0 for client)
 * @is_top_level_nav: 1 if top-level navigation (default 1 for client)
 * @is_safe_method: 1 if safe method (GET/HEAD/OPTIONS) (default 1 for client)
 *
 * Returns: 1 if cookie should be sent, 0 otherwise
 *
 * Enforces RFC 6265bis §5 SameSite attribute if enforce_samesite is set.
 */
static int
cookie_matches_request (const SocketHTTPClient_Cookie *cookie,
                        const char *host, const char *path, int is_secure,
                        time_t now, int enforce_samesite, int is_cross_site,
                        int is_top_level_nav, int is_safe_method)
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

  /* Enforce SameSite attribute per RFC 6265bis §5 */
  if (enforce_samesite)
    {
      if (cookie->same_site == COOKIE_SAMESITE_STRICT && is_cross_site)
        return 0;
      if (cookie->same_site == COOKIE_SAMESITE_LAX
          && !(is_top_level_nav && is_safe_method))
        return 0;
      if (cookie->same_site == COOKIE_SAMESITE_NONE && !is_secure)
        return 0;
    }

  return 1;
}

int
httpclient_cookies_for_request (SocketHTTPClient_CookieJar_T jar,
                                const SocketHTTP_URI *uri, char *output,
                                size_t output_size, int enforce_samesite)
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
      int chain_len = 0;
      while (entry != NULL)
        {
          chain_len++;
          const SocketHTTPClient_Cookie *c = &entry->cookie;

          if (!cookie_matches_request (c, uri->host, request_path, is_secure,
                                       now, enforce_samesite, 0, 1, 1))
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
      if (chain_len > HTTPCLIENT_COOKIE_MAX_CHAIN_LEN)
        {
          SocketLog_emitf (
              SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
              "Hash collision chain too long (%d > %d), potential DoS",
              chain_len, HTTPCLIENT_COOKIE_MAX_CHAIN_LEN);
        }
    }

  pthread_mutex_unlock (&jar->mutex);

  return (int)written;
}

/* ============================================================================
 * Set-Cookie Parsing Helpers
 * ============================================================================
 */

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
parse_token (const char **p, const char *end, const char **token_start,
             const char **token_end)
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
parse_value (const char **p, const char *end, const char **value_start,
             const char **value_end)
{
  *p = skip_whitespace (*p, end);
  const char *start = *p;
  if (start >= end)
    return -1;

  if (*start == '"')
    {
      const char *s = ++(*p);
      while (*p < end && **p != '"')
        (*p)++;
      const char *e = *p;
      if (*p >= end || **p != '"')
        {
          HTTPCLIENT_ERROR_MSG (
              "Unclosed quoted cookie value in Set-Cookie header");
          return -1;
        }
      (*p)++; /* Skip closing quote */
      *value_end = trim_trailing_whitespace (s, e);
      *value_start = s;
    }
  else
    {
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
  const char *ptr = *p;
  const char *name_start, *name_end;
  const char *value_start, *value_end;
  size_t name_len, val_len;
  char *n, *v;

  /* Parse name token (stops at '=' or ';') */
  if (parse_token (&ptr, end, &name_start, &name_end) != 0)
    {
      HTTPCLIENT_ERROR_MSG ("Invalid cookie name in Set-Cookie header");
      return -1;
    }
  name_len = name_end - name_start;

  if (ptr >= end || *ptr != '=')
    {
      HTTPCLIENT_ERROR_MSG (
          "Missing '=' after cookie name in Set-Cookie header");
      return -1;
    }
  ptr++; /* Skip '=' */

  /* Parse value (handles quoted or unquoted) */
  if (parse_value (&ptr, end, &value_start, &value_end) != 0)
    {
      HTTPCLIENT_ERROR_MSG ("Invalid cookie value in Set-Cookie header");
      return -1;
    }
  val_len = value_end - value_start;

  /* Allocate using utility function for consistency with codebase */
  cookie->name = socket_util_arena_strndup (arena, name_start, name_len);
  if (cookie->name == NULL)
    {
      HTTPCLIENT_ERROR_MSG (
          "socket_util_arena_strndup failed for cookie name");
      return -1;
    }

  /* Validate name characters */
  for (size_t i = 0; i < name_len; i++)
    {
      if (!is_valid_cookie_octet ((unsigned char)name_start[i]))
        {
          HTTPCLIENT_ERROR_MSG ("Invalid character in cookie name");
          return -1;
        }
    }

  cookie->value = socket_util_arena_strndup (arena, value_start, val_len);
  if (cookie->value == NULL)
    {
      HTTPCLIENT_ERROR_MSG (
          "socket_util_arena_strndup failed for cookie value");
      return -1;
    }

  /* Validate value characters */
  for (size_t i = 0; i < val_len; i++)
    {
      if (!is_valid_cookie_octet ((unsigned char)value_start[i]))
        {
          HTTPCLIENT_ERROR_MSG ("Invalid character in cookie value");
          return -1;
        }
    }

  *p = ptr;

  return 0;
}

/* Cookie attribute constants for avoiding magic numbers */
static const char COOKIE_ATTR_SECURE_STR[] = "Secure";
#define COOKIE_ATTR_SECURE_LEN (sizeof (COOKIE_ATTR_SECURE_STR) - 1)
static const char COOKIE_ATTR_HTTPONLY_STR[] = "HttpOnly";
#define COOKIE_ATTR_HTTPONLY_LEN (sizeof (COOKIE_ATTR_HTTPONLY_STR) - 1)
static const char COOKIE_ATTR_EXPIRES_STR[] = "Expires";
#define COOKIE_ATTR_EXPIRES_LEN (sizeof (COOKIE_ATTR_EXPIRES_STR) - 1)
static const char COOKIE_ATTR_MAXAGE_STR[] = "Max-Age";
#define COOKIE_ATTR_MAXAGE_LEN (sizeof (COOKIE_ATTR_MAXAGE_STR) - 1)
static const char COOKIE_ATTR_DOMAIN_STR[] = "Domain";
#define COOKIE_ATTR_DOMAIN_LEN (sizeof (COOKIE_ATTR_DOMAIN_STR) - 1)
static const char COOKIE_ATTR_PATH_STR[] = "Path";
#define COOKIE_ATTR_PATH_LEN (sizeof (COOKIE_ATTR_PATH_STR) - 1)
static const char COOKIE_ATTR_SAMESITE_STR[] = "SameSite";
#define COOKIE_ATTR_SAMESITE_LEN (sizeof (COOKIE_ATTR_SAMESITE_STR) - 1)

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
  if (attr_len == COOKIE_ATTR_SECURE_LEN
      && strncasecmp (attr_start, COOKIE_ATTR_SECURE_STR, attr_len) == 0)
    {
      cookie->secure = 1;
      return;
    }

  if (attr_len == COOKIE_ATTR_HTTPONLY_LEN
      && strncasecmp (attr_start, COOKIE_ATTR_HTTPONLY_STR, attr_len) == 0)
    {
      cookie->http_only = 1;
      return;
    }

  /* Value-required attributes */
  if (attr_value_start == NULL)
    return;

  if (attr_len == COOKIE_ATTR_EXPIRES_LEN
      && strncasecmp (attr_start, COOKIE_ATTR_EXPIRES_STR, attr_len) == 0)
    {
      time_t expires;
      if (SocketHTTP_date_parse (attr_value_start, attr_val_len, &expires)
          == 0)
        cookie->expires = expires;
    }
  else if (attr_len == COOKIE_ATTR_MAXAGE_LEN
           && strncasecmp (attr_start, COOKIE_ATTR_MAXAGE_STR, attr_len) == 0)
    {
      cookie->expires = parse_max_age (attr_value_start, attr_val_len);
    }
  else if (attr_len == COOKIE_ATTR_DOMAIN_LEN
           && strncasecmp (attr_start, COOKIE_ATTR_DOMAIN_STR, attr_len) == 0)
    {
      if (attr_val_len == 0)
        {
          return; /* Ignore empty Domain per RFC 6265 Section 5.2.3 */
        }
      cookie->domain
          = socket_util_arena_strndup (arena, attr_value_start, attr_val_len);
    }
  else if (attr_len == COOKIE_ATTR_PATH_LEN
           && strncasecmp (attr_start, COOKIE_ATTR_PATH_STR, attr_len) == 0)
    {
      if (attr_val_len == 0 || attr_value_start[0] != '/')
        {
          return; /* Ignore invalid Path per RFC 6265 Section 5.2.4 */
        }
      cookie->path
          = socket_util_arena_strndup (arena, attr_value_start, attr_val_len);
    }
  else if (attr_len == COOKIE_ATTR_SAMESITE_LEN
           && strncasecmp (attr_start, COOKIE_ATTR_SAMESITE_STR, attr_len)
                  == 0)
    {
      cookie->same_site = parse_same_site (attr_value_start, attr_val_len);
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

      /* Parse attribute name token (stops at '=' or ';') */
      if (parse_token (&ptr, end, &attr_start, &attr_end) != 0)
        {
          break; /* Invalid attribute name */
        }

      /* Parse attribute value if present, reusing parse_value logic for
       * consistency and bug fixes */
      attr_value_start = NULL;
      attr_value_end = NULL;
      if (ptr < end && *ptr == '=')
        {
          ptr++; /* Skip '=' */
          const char *val_start_temp, *val_end_temp;
          if (parse_value (&ptr, end, &val_start_temp, &val_end_temp) == 0)
            {
              attr_value_start = val_start_temp;
              attr_value_end
                  = val_end_temp; /* Already trimmed by parse_value */
            }
          else
            {
              /* Invalid value (e.g., unclosed quote), ignore this attribute
               * value */
            }
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
 * ============================================================================
 */

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
  if (parse_cookie_name_value (&p, end, cookie, arena) != 0)
    {
      HTTPCLIENT_ERROR_MSG (
          "Invalid Set-Cookie: missing or malformed name=value");
      return -1;
    }

  /* Parse attributes */
  parse_cookie_attributes (&p, end, cookie, arena);

  /* Apply defaults from request URI */
  apply_cookie_defaults (cookie, request_uri, arena);

  /* Validate required fields and attributes per RFC 6265 Sections 5.2.3
   * and 5.2 */
  if (cookie->name == NULL || cookie->value == NULL)
    {
      HTTPCLIENT_ERROR_MSG (
          "Invalid Set-Cookie: missing required name or value");
      return -1;
    }
  if (cookie->domain == NULL)
    {
      HTTPCLIENT_ERROR_MSG ("Invalid Set-Cookie: missing required domain "
                            "after applying defaults");
      return -1;
    }

  /* Length validation */
  size_t name_len = strlen (cookie->name);
  size_t value_len = strlen (cookie->value);
  size_t domain_len = strlen (cookie->domain);
  if (name_len > HTTPCLIENT_COOKIE_MAX_NAME_LEN
      || value_len > HTTPCLIENT_COOKIE_MAX_VALUE_LEN
      || domain_len > HTTPCLIENT_COOKIE_MAX_DOMAIN_LEN)
    {
      HTTPCLIENT_ERROR_MSG ("Set-Cookie rejected: field length exceeds limits "
                            "(name:%zu, value:%zu, domain:%zu)",
                            name_len, value_len, domain_len);
      return -1;
    }

  /* Validate Domain matches request host if provided (RFC 6265 Section 5.2.3)
   */
  if (request_uri != NULL && request_uri->host != NULL
      && !domain_matches (request_uri->host, cookie->domain))
    {
      HTTPCLIENT_ERROR_MSG ("Set-Cookie rejected: Domain '%s' does not "
                            "domain-match request host '%s'",
                            cookie->domain, request_uri->host);
      return -1;
    }

  return 0;
}
