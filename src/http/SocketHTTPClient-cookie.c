/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

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

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketCrypto.h"
#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTPClient-private.h"
#include "http/SocketHTTPClient.h"

/* Override log component for this module */
#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "HTTPClient-Cookie"

SOCKET_DECLARE_MODULE_EXCEPTION (SocketHTTPClient);

/* ============================================================================
 * Constants
 * ============================================================================
 */

/** Seconds per day for cookie expiry validation */
#define SECONDS_PER_DAY 86400

/** Maximum reasonable cookie expiry: 1 year in future */
#define MAX_COOKIE_EXPIRY_FUTURE (365LL * SECONDS_PER_DAY)

/* SameSite attribute string constants */
static const char COOKIE_SAMESITE_STRICT_STR[] = "Strict";
static const char COOKIE_SAMESITE_LAX_STR[] = "Lax";
static const char COOKIE_SAMESITE_NONE_STR[] = "None";

/* Cookie attribute string constants */
static const char COOKIE_ATTR_SECURE_STR[] = "Secure";
static const char COOKIE_ATTR_HTTPONLY_STR[] = "HttpOnly";
static const char COOKIE_ATTR_EXPIRES_STR[] = "Expires";
static const char COOKIE_ATTR_MAXAGE_STR[] = "Max-Age";
static const char COOKIE_ATTR_DOMAIN_STR[] = "Domain";
static const char COOKIE_ATTR_PATH_STR[] = "Path";
static const char COOKIE_ATTR_SAMESITE_STR[] = "SameSite";

#define COOKIE_ATTR_SECURE_LEN (sizeof (COOKIE_ATTR_SECURE_STR) - 1)
#define COOKIE_ATTR_HTTPONLY_LEN (sizeof (COOKIE_ATTR_HTTPONLY_STR) - 1)
#define COOKIE_ATTR_EXPIRES_LEN (sizeof (COOKIE_ATTR_EXPIRES_STR) - 1)
#define COOKIE_ATTR_MAXAGE_LEN (sizeof (COOKIE_ATTR_MAXAGE_STR) - 1)
#define COOKIE_ATTR_DOMAIN_LEN (sizeof (COOKIE_ATTR_DOMAIN_STR) - 1)
#define COOKIE_ATTR_PATH_LEN (sizeof (COOKIE_ATTR_PATH_STR) - 1)
#define COOKIE_ATTR_SAMESITE_LEN (sizeof (COOKIE_ATTR_SAMESITE_STR) - 1)

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
 */
static int
is_valid_cookie_octet (unsigned char c)
{
  if (c <= 31 || (c >= 127 && c <= 159))
    return 0;
  if (c == ';' || c == '=' || c == ',' || c == ' ')
    return 0;
  return 1;
}

/**
 * warn_long_hash_chain - Log warning for potential hash DoS
 * @chain_len: Current chain length
 *
 * Thread-safe: Yes
 */
static void
warn_long_hash_chain (int chain_len)
{
  if (chain_len > HTTPCLIENT_COOKIE_MAX_CHAIN_LEN)
    {
      SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                       "Hash collision chain too long (%d > %d), potential DoS",
                       chain_len, HTTPCLIENT_COOKIE_MAX_CHAIN_LEN);
    }
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
 */
static unsigned
cookie_hash (const char *domain, const char *path, const char *name,
             size_t table_size, unsigned seed)
{
  unsigned h_domain = socket_util_hash_djb2_ci (domain, table_size);
  unsigned h_path = socket_util_hash_djb2 (path, table_size);
  unsigned h_name = socket_util_hash_djb2 (name, table_size);

  unsigned hash = seed ^ h_domain;
  hash = ((hash << 5) + hash + h_path) % table_size;
  hash = ((hash << 5) + hash + h_name) % table_size;

  return hash;
}

/**
 * domain_matches - Check if domain matches cookie domain (RFC 6265 §5.1.3)
 * @request_domain: Domain from request URL
 * @cookie_domain: Domain from cookie
 *
 * Returns: 1 if matches, 0 otherwise
 */
static int
domain_matches (const char *request_domain, const char *cookie_domain)
{
  size_t req_len, cookie_len;
  const char *suffix;

  if (request_domain == NULL || cookie_domain == NULL)
    return 0;

  if (cookie_domain[0] == '.')
    cookie_domain++;

  req_len = strlen (request_domain);
  cookie_len = strlen (cookie_domain);

  if (req_len == cookie_len && strcasecmp (request_domain, cookie_domain) == 0)
    return 1;

  if (req_len > cookie_len)
    {
      suffix = request_domain + (req_len - cookie_len);
      if (strcasecmp (suffix, cookie_domain) == 0 && *(suffix - 1) == '.')
        return 1;
    }

  return 0;
}

/**
 * path_matches - Check if path matches cookie path (RFC 6265 §5.1.4)
 * @request_path: Path from request URL
 * @cookie_path: Path from cookie
 *
 * Returns: 1 if matches, 0 otherwise
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

  if (strncmp (request_path, cookie_path, cookie_len) != 0)
    return 0;

  if (req_len == cookie_len)
    return 1;
  if (cookie_len > 0 && cookie_path[cookie_len - 1] == '/')
    return 1;
  if (request_path[cookie_len] == '/')
    return 1;

  return 0;
}

/**
 * parse_max_age - Parse Max-Age attribute value from cookie
 * @value: String value of Max-Age (e.g. "3600")
 * @len: Length of value string
 *
 * Returns: Unix timestamp of expiration, or 0 if invalid/session cookie
 *
 * Per RFC 6265: Non-positive Max-Age means delete cookie (return 1 for
 * immediate expiry). Positive values are capped at HTTPCLIENT_MAX_COOKIE_AGE_SEC.
 */
static time_t
parse_max_age (const char *value, const size_t len)
{
  const char *start;
  size_t remaining;
  int sign = 1;
  long age = 0;
  int has_digit = 0;
  time_t now, expires;
  size_t temp;

  if (value == NULL || len == 0)
    return 0;

  start = value;
  remaining = len;

  while (remaining > 0 && (*start == ' ' || *start == '\t'))
    {
      start++;
      remaining--;
    }
  if (remaining == 0)
    return 0;

  if (*start == '-')
    {
      sign = -1;
      start++;
      remaining--;
      if (remaining == 0)
        return 0;
    }

  while (remaining > 0 && *start >= '0' && *start <= '9')
    {
      has_digit = 1;
      if (age > (LONG_MAX - 9) / 10)
        return 0;
      age = age * 10 + (*start - '0');
      start++;
      remaining--;
    }

  if (!has_digit || remaining > 0)
    return 0;

  age *= sign;
  if (age <= 0)
    return 1;

  if (age > HTTPCLIENT_MAX_COOKIE_AGE_SEC)
    age = HTTPCLIENT_MAX_COOKIE_AGE_SEC;

  now = time (NULL);
  if (!SocketSecurity_check_add ((size_t)now, (size_t)age, &temp))
    return 1;
  expires = (time_t)temp;

  return expires;
}

/**
 * parse_same_site - Parse SameSite attribute value
 * @value: String value ("Strict", "Lax", "None", case-insensitive)
 * @len: Length of value string
 *
 * Returns: Parsed SameSite enum, defaults to LAX if unknown per RFC 6265bis
 * Thread-safe: Yes (stateless)
 */
static SocketHTTPClient_SameSite
parse_same_site (const char *value, const size_t len)
{
  if (value == NULL || len == 0)
    return COOKIE_SAMESITE_LAX;

  if (len == sizeof (COOKIE_SAMESITE_STRICT_STR) - 1
      && strncasecmp (value, COOKIE_SAMESITE_STRICT_STR, len) == 0)
    return COOKIE_SAMESITE_STRICT;

  if (len == sizeof (COOKIE_SAMESITE_LAX_STR) - 1
      && strncasecmp (value, COOKIE_SAMESITE_LAX_STR, len) == 0)
    return COOKIE_SAMESITE_LAX;

  if (len == sizeof (COOKIE_SAMESITE_NONE_STR) - 1
      && strncasecmp (value, COOKIE_SAMESITE_NONE_STR, len) == 0)
    return COOKIE_SAMESITE_NONE;

  return COOKIE_SAMESITE_LAX;
}

/**
 * get_default_path - Get default path from request URI (RFC 6265 §5.1.4)
 * @request_path: Request URI path
 * @output: Output buffer for default path
 * @output_size: Size of output buffer
 */
static void
get_default_path (const char *request_path, char *output, size_t output_size)
{
  const char *last_slash;
  size_t len;

  assert (output != NULL);
  assert (output_size > 0);

  if (request_path == NULL || request_path[0] != '/'
      || (last_slash = strrchr (request_path, '/')) == request_path)
    {
      snprintf (output, output_size, "/");
      return;
    }

  len = (size_t)(last_slash - request_path);
  if (len >= output_size)
    len = output_size - 1;

  memcpy (output, request_path, len);
  output[len] = '\0';
}

/* ============================================================================
 * Cookie Entry Helpers
 * ============================================================================
 */

/**
 * cookie_entry_update_value_flags - Update cookie value and flags
 * @entry: Cookie entry to update
 * @cookie: New cookie data
 * @arena: Arena for strdup
 *
 * Thread-safe: No (caller must hold mutex)
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
 * evict_oldest_cookie - Remove the oldest cookie from jar by creation time
 * @jar: Cookie jar to evict from
 *
 * Scans all cookies to find oldest by creation timestamp and removes it.
 * Used when jar reaches max_cookies limit before adding new cookie.
 *
 * Thread-safe: No (caller must hold mutex)
 * Complexity: O(n) where n is total cookie count
 */
static void
evict_oldest_cookie (SocketHTTPClient_CookieJar_T jar)
{
  time_t oldest_time = (time_t)-1;
  CookieEntry **oldest_pp = NULL;

  for (size_t i = 0; i < jar->hash_size; i++)
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
 */
static void
cookie_entry_init_full (CookieEntry *entry,
                        const SocketHTTPClient_Cookie *cookie,
                        const char *effective_path, Arena_T arena)
{
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
          warn_long_hash_chain (chain_len);
          return entry;
        }
      entry = entry->next;
    }

  warn_long_hash_chain (chain_len);
  return NULL;
}

/* ============================================================================
 * Cookie Jar Lifecycle
 * ============================================================================
 */

SocketHTTPClient_CookieJar_T
SocketHTTPClient_CookieJar_new (void)
{
  volatile SocketHTTPClient_CookieJar_T jar = NULL;
  volatile Arena_T arena = NULL;

  TRY
  {
    arena = Arena_new ();
    if (arena == NULL)
      RAISE_HTTPCLIENT_ERROR (SocketHTTPClient_Failed);

    jar = Arena_calloc ((Arena_T)arena, 1, sizeof (*jar), __FILE__, __LINE__);
    if (jar == NULL)
      RAISE_HTTPCLIENT_ERROR (SocketHTTPClient_Failed);

    jar->arena = (Arena_T)arena;
    jar->hash_size = HTTPCLIENT_COOKIE_HASH_SIZE;
    jar->max_cookies = HTTPCLIENT_MAX_COOKIES;
    SocketCrypto_random_bytes ((unsigned char *)&jar->hash_seed,
                               sizeof (jar->hash_seed));

    jar->hash_table = Arena_calloc ((Arena_T)arena, HTTPCLIENT_COOKIE_HASH_SIZE,
                                    sizeof (CookieEntry *), __FILE__, __LINE__);
    if (jar->hash_table == NULL)
      RAISE_HTTPCLIENT_ERROR (SocketHTTPClient_Failed);

    if (pthread_mutex_init (&jar->mutex, NULL) != 0)
      RAISE_HTTPCLIENT_ERROR (SocketHTTPClient_Failed);
  }
  EXCEPT (SocketHTTPClient_Failed)
  {
    HTTPCLIENT_ERROR_MSG ("Failed to create cookie jar");
    if (arena != NULL)
      Arena_dispose ((Arena_T *)&arena);
    jar = NULL;
  }
  END_TRY;

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
    Arena_dispose (&j->arena);

  *jar = NULL;
}

/* ============================================================================
 * Cookie Storage Operations
 * ============================================================================
 */

int
SocketHTTPClient_CookieJar_set (SocketHTTPClient_CookieJar_T jar,
                                const SocketHTTPClient_Cookie *cookie)
{
  const char *effective_path;
  unsigned hash;
  CookieEntry *entry;
  volatile int result = 0;

  assert (jar != NULL);
  assert (cookie != NULL);
  assert (cookie->name != NULL);
  assert (cookie->value != NULL);
  assert (cookie->domain != NULL);

  pthread_mutex_lock (&jar->mutex);

  TRY
  {
    effective_path = cookie->path ? cookie->path : "/";
    hash = cookie_hash (cookie->domain, effective_path, cookie->name,
                        jar->hash_size, jar->hash_seed);

    entry = cookie_jar_find_entry (jar, cookie->domain, effective_path,
                                   cookie->name);

    if (entry != NULL)
      {
        cookie_entry_update_value_flags (entry, cookie, jar->arena);
      }
    else
      {
        if (jar->count >= jar->max_cookies)
          {
            SocketHTTPClient_CookieJar_clear_expired (jar);
            if (jar->count >= jar->max_cookies)
              {
                evict_oldest_cookie (jar);
                if (jar->count >= jar->max_cookies)
                  {
                    SocketLog_emitf (
                        SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                        "Cookie jar at max capacity (%zu), rejecting new cookie",
                        jar->max_cookies);
                    result = -1;
                    goto unlock;
                  }
              }
          }

        entry
            = Arena_calloc (jar->arena, 1, sizeof (*entry), __FILE__, __LINE__);
        if (entry == NULL)
          RAISE_HTTPCLIENT_ERROR (SocketHTTPClient_Failed);

        cookie_entry_init_full (entry, cookie, effective_path, jar->arena);
        entry->created = time (NULL);

        entry->next = jar->hash_table[hash];
        jar->hash_table[hash] = entry;
        jar->count++;
      }
  }
  EXCEPT (SocketHTTPClient_Failed)
  {
    result = -1;
    HTTPCLIENT_ERROR_MSG ("Failed to set cookie");
  }
  END_TRY;

unlock:
  pthread_mutex_unlock (&jar->mutex);
  return result;
}

const SocketHTTPClient_Cookie *
SocketHTTPClient_CookieJar_get (SocketHTTPClient_CookieJar_T jar,
                                const char *domain, const char *path,
                                const char *name)
{
  const char *effective_path;
  CookieEntry *entry;

  assert (jar != NULL);
  assert (domain != NULL);
  assert (name != NULL);

  effective_path = path ? path : "/";

  pthread_mutex_lock (&jar->mutex);
  entry = cookie_jar_find_entry (jar, domain, effective_path, name);
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
  pthread_mutex_unlock (&jar->mutex);
}

void
SocketHTTPClient_CookieJar_clear_expired (SocketHTTPClient_CookieJar_T jar)
{
  assert (jar != NULL);

  const time_t now = time (NULL);

  pthread_mutex_lock (&jar->mutex);

  for (size_t i = 0; i < jar->hash_size; i++)
    {
      CookieEntry **pp = &jar->hash_table[i];
      while (*pp != NULL)
        {
          CookieEntry *entry = *pp;
          if (entry->cookie.expires > 0 && entry->cookie.expires < now)
            {
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
 * Cookie File Persistence - Validation Helpers
 * ============================================================================
 */

/**
 * validate_cookie_field_lengths - Validate cookie field lengths from file
 * @domain_len: Length of domain field
 * @path_len: Length of path field
 * @name_len: Length of name field
 * @value_len: Length of value field
 *
 * Returns: 1 if valid, 0 if any field too long
 */
static int
validate_cookie_field_lengths (size_t domain_len, size_t path_len,
                               size_t name_len, size_t value_len)
{
  if (!SocketSecurity_check_size (domain_len)
      || !SocketSecurity_check_size (path_len)
      || !SocketSecurity_check_size (name_len)
      || !SocketSecurity_check_size (value_len))
    return 0;

  if (domain_len > HTTPCLIENT_COOKIE_MAX_DOMAIN_LEN
      || path_len > HTTPCLIENT_COOKIE_MAX_PATH_LEN
      || name_len > HTTPCLIENT_COOKIE_MAX_NAME_LEN
      || value_len > HTTPCLIENT_COOKIE_MAX_VALUE_LEN)
    {
      SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                       "Cookie rejected: field too long (domain:%zu, "
                       "path:%zu, name:%zu, value:%zu)",
                       domain_len, path_len, name_len, value_len);
      return 0;
    }

  return 1;
}

/**
 * validate_cookie_characters - Validate name/value characters
 * @name: Cookie name
 * @name_len: Length of name
 * @value: Cookie value
 * @value_len: Length of value
 *
 * Returns: 1 if valid, 0 if invalid characters found
 */
static int
validate_cookie_characters (const char *name, size_t name_len,
                            const char *value, size_t value_len)
{
  size_t i;

  for (i = 0; i < name_len; i++)
    {
      if (!is_valid_cookie_octet ((unsigned char)name[i]))
        {
          SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                           "Cookie rejected: invalid character in name");
          return 0;
        }
    }

  for (i = 0; i < value_len; i++)
    {
      if (!is_valid_cookie_octet ((unsigned char)value[i]))
        {
          SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                           "Cookie rejected: invalid character in value");
          return 0;
        }
    }

  return 1;
}

/**
 * validate_cookie_expiry - Validate cookie expiry time
 * @expires_time: Expiry timestamp from file
 * @now: Current time
 *
 * Returns: 1 if valid, 0 if unreasonable
 */
static int
validate_cookie_expiry (time_t expires_time, time_t now)
{
  if (expires_time != 0
      && (expires_time < now - SECONDS_PER_DAY
          || expires_time > now + MAX_COOKIE_EXPIRY_FUTURE))
    {
      SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                       "Cookie rejected: unreasonable expires %lld",
                       (long long)expires_time);
      return 0;
    }
  return 1;
}

/* ============================================================================
 * Cookie File Persistence
 * ============================================================================
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
      size_t len, domain_len, path_len, name_len, value_len;
      time_t expires_time, now;

      if (line[0] == '#' || line[0] == '\n')
        continue;

      len = strlen (line);
      if (len > 0 && line[len - 1] == '\n')
        line[len - 1] = '\0';

      domain = strtok_r (line, "\t", &saveptr);
      flag = strtok_r (NULL, "\t", &saveptr);
      path = strtok_r (NULL, "\t", &saveptr);
      secure = strtok_r (NULL, "\t", &saveptr);
      expires = strtok_r (NULL, "\t", &saveptr);
      name = strtok_r (NULL, "\t", &saveptr);
      value = strtok_r (NULL, "\t", &saveptr);

      (void)flag;

      if (!domain || !path || !secure || !expires || !name || !value)
        continue;

      domain_len = strlen (domain);
      path_len = strlen (path);
      name_len = strlen (name);
      value_len = strlen (value);

      if (!validate_cookie_field_lengths (domain_len, path_len, name_len,
                                          value_len))
        continue;

      if (path[0] != '/')
        {
          SocketLog_emitf (
              SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
              "Cookie rejected: invalid path '%s' (must start with '/')",
              path);
          continue;
        }

      if (strcmp (secure, "TRUE") != 0 && strcmp (secure, "FALSE") != 0)
        {
          SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                           "Cookie rejected: invalid secure flag '%s'",
                           secure);
          continue;
        }

      expires_time = (time_t)strtoll (expires, NULL, 10);
      now = time (NULL);

      if (!validate_cookie_expiry (expires_time, now))
        continue;

      if (!validate_cookie_characters (name, name_len, value, value_len))
        continue;

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

  if (ferror (f))
    {
      HTTPCLIENT_ERROR_FMT ("Error reading cookie file: %s", filename);
      fclose (f);
      return -1;
    }

  fclose (f);
  SocketHTTPClient_CookieJar_clear_expired (jar);

  return 0;
}

int
SocketHTTPClient_CookieJar_save (SocketHTTPClient_CookieJar_T jar,
                                 const char *filename)
{
  assert (jar != NULL);
  assert (filename != NULL);

  FILE *f = fopen (filename, "w");
  if (f == NULL)
    {
      HTTPCLIENT_ERROR_FMT ("fopen(\"%s\", \"w\") failed", filename);
      return -1;
    }

  fprintf (f, "# Netscape HTTP Cookie File\n");
  fprintf (f, "# http://curl.haxx.se/rfc/cookie_spec.html\n");
  fprintf (f, "# This file was generated by SocketHTTPClient.\n\n");

  pthread_mutex_lock (&jar->mutex);

  for (size_t i = 0; i < jar->hash_size; i++)
    {
      CookieEntry *entry = jar->hash_table[i];
      while (entry != NULL)
        {
          const SocketHTTPClient_Cookie *c = &entry->cookie;

          if (strchr (c->name, '\r') || strchr (c->name, '\n')
              || strchr (c->value, '\r') || strchr (c->value, '\n'))
            {
              SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                               "Cookie '%s' contains \\r\\n, skipping save",
                               c->name);
              entry = entry->next;
              continue;
            }

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
      HTTPCLIENT_ERROR_FMT ("Error writing to cookie file: %s", filename);
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
 * cookie_matches_request - Check if cookie matches request context
 * @cookie: Cookie to check (read-only)
 * @host: Request hostname for domain matching
 * @path: Request path for path matching
 * @is_secure: 1 if HTTPS connection, 0 if HTTP
 * @now: Current time for expiry check
 * @enforce_samesite: 1 to enforce SameSite policy
 * @is_cross_site: 1 if cross-site request context
 * @is_top_level_nav: 1 if top-level navigation (for Lax)
 * @is_safe_method: 1 if safe HTTP method (GET/HEAD/OPTIONS)
 *
 * Returns: 1 if cookie should be sent, 0 otherwise
 * Thread-safe: Yes (read-only access to cookie)
 */
static int
cookie_matches_request (const SocketHTTPClient_Cookie *cookie,
                        const char *host, const char *path, const int is_secure,
                        const time_t now, const int enforce_samesite,
                        const int is_cross_site, const int is_top_level_nav,
                        const int is_safe_method)
{
  if (cookie->expires > 0 && cookie->expires < now)
    return 0;

  if (cookie->secure && !is_secure)
    return 0;

  if (!domain_matches (host, cookie->domain))
    return 0;

  if (!path_matches (path, cookie->path))
    return 0;

  if (enforce_samesite && is_cross_site)
    {
      if (cookie->same_site == COOKIE_SAMESITE_STRICT)
        return 0;
      if (cookie->same_site == COOKIE_SAMESITE_LAX
          && (!is_top_level_nav || !is_safe_method))
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
          const SocketHTTPClient_Cookie *c = &entry->cookie;
          size_t name_len, value_len, cookie_len;

          chain_len++;

          if (!cookie_matches_request (c, uri->host, request_path, is_secure,
                                       now, enforce_samesite, 0, 1, 1))
            {
              entry = entry->next;
              continue;
            }

          name_len = strlen (c->name);
          value_len = strlen (c->value);
          cookie_len = name_len + value_len + 1;
          if (written > 0)
            cookie_len += 2;

          if (written + cookie_len >= output_size)
            break;

          if (written > 0)
            {
              memcpy (output + written, "; ", 2);
              written += 2;
            }

          written += (size_t)snprintf (output + written, output_size - written,
                                       "%s=%s", c->name, c->value);

          entry = entry->next;
        }

      warn_long_hash_chain (chain_len);
    }

  pthread_mutex_unlock (&jar->mutex);

  return (int)written;
}

/* ============================================================================
 * Set-Cookie Parsing Helpers
 * ============================================================================
 */

/**
 * skip_whitespace - Skip leading whitespace in cookie attributes
 * @p: Current position pointer
 * @end: End of string
 *
 * Returns: Pointer to first non-whitespace character
 */
static const char *
skip_whitespace (const char *p, const char *end)
{
  while (p < end && (*p == ' ' || *p == '\t'))
    p++;
  return p;
}

/**
 * trim_trailing_whitespace - Trim trailing whitespace from string
 * @start: Start of string
 * @end: Current end position
 *
 * Returns: New end position after trimming
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
 * @token_end: Output end of token
 *
 * Returns: 0 on success, -1 if empty or invalid
 */
static int
parse_token (const char **p, const char *end, const char **token_start,
             const char **token_end)
{
  const char *start, *tok_end, *trimmed_end;

  *p = skip_whitespace (*p, end);
  start = *p;
  if (start >= end)
    return -1;

  tok_end = start;
  while (tok_end < end && *tok_end != '=' && *tok_end != ';')
    tok_end++;
  trimmed_end = trim_trailing_whitespace (start, tok_end);

  if (trimmed_end == start)
    return -1;

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
 * @value_end: Output end of value
 *
 * Returns: 0 on success, -1 on invalid (unclosed quote)
 */
static int
parse_value (const char **p, const char *end, const char **value_start,
             const char **value_end)
{
  const char *start, *s, *e;

  *p = skip_whitespace (*p, end);
  start = *p;
  if (start >= end)
    return -1;

  if (*start == '"')
    {
      s = ++(*p);
      while (*p < end && **p != '"')
        (*p)++;
      e = *p;
      if (*p >= end || **p != '"')
        {
          HTTPCLIENT_ERROR_MSG (
              "Unclosed quoted cookie value in Set-Cookie header");
          return -1;
        }
      (*p)++;
      *value_end = trim_trailing_whitespace (s, e);
      *value_start = s;
    }
  else
    {
      s = start;
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
  size_t name_len, val_len, i;

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
  ptr++;

  if (parse_value (&ptr, end, &value_start, &value_end) != 0)
    {
      HTTPCLIENT_ERROR_MSG ("Invalid cookie value in Set-Cookie header");
      return -1;
    }
  val_len = value_end - value_start;

  cookie->name = socket_util_arena_strndup (arena, name_start, name_len);
  if (cookie->name == NULL)
    {
      HTTPCLIENT_ERROR_MSG (
          "socket_util_arena_strndup failed for cookie name");
      return -1;
    }

  for (i = 0; i < name_len; i++)
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

  for (i = 0; i < val_len; i++)
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
        return;
      cookie->domain
          = socket_util_arena_strndup (arena, attr_value_start, attr_val_len);
    }
  else if (attr_len == COOKIE_ATTR_PATH_LEN
           && strncasecmp (attr_start, COOKIE_ATTR_PATH_STR, attr_len) == 0)
    {
      if (attr_val_len == 0 || attr_value_start[0] != '/')
        return;
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

      while (ptr < end && (*ptr == ';' || *ptr == ' ' || *ptr == '\t'))
        ptr++;

      if (ptr >= end)
        break;

      if (parse_token (&ptr, end, &attr_start, &attr_end) != 0)
        break;

      if (ptr < end && *ptr == '=')
        {
          const char *val_start_temp, *val_end_temp;
          ptr++;
          if (parse_value (&ptr, end, &val_start_temp, &val_end_temp) == 0)
            {
              attr_value_start = val_start_temp;
              attr_value_end = val_end_temp;
            }
        }

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

  if (cookie->domain == NULL && request_uri != NULL
      && request_uri->host != NULL)
    {
      cookie->domain = socket_util_arena_strdup (arena, request_uri->host);
    }

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

int
httpclient_parse_set_cookie (const char *value, size_t len,
                             const SocketHTTP_URI *request_uri,
                             SocketHTTPClient_Cookie *cookie, Arena_T arena)
{
  const char *p = value;
  const char *end = value + (len > 0 ? len : strlen (value));
  size_t name_len, value_len, domain_len;

  assert (value != NULL);
  assert (cookie != NULL);
  assert (arena != NULL);

  memset (cookie, 0, sizeof (*cookie));

  if (parse_cookie_name_value (&p, end, cookie, arena) != 0)
    {
      HTTPCLIENT_ERROR_MSG (
          "Invalid Set-Cookie: missing or malformed name=value");
      return -1;
    }

  parse_cookie_attributes (&p, end, cookie, arena);
  apply_cookie_defaults (cookie, request_uri, arena);

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

  name_len = strlen (cookie->name);
  value_len = strlen (cookie->value);
  domain_len = strlen (cookie->domain);
  if (name_len > HTTPCLIENT_COOKIE_MAX_NAME_LEN
      || value_len > HTTPCLIENT_COOKIE_MAX_VALUE_LEN
      || domain_len > HTTPCLIENT_COOKIE_MAX_DOMAIN_LEN)
    {
      SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                       "Set-Cookie rejected: field length exceeds limits "
                       "(name:%zu, value:%zu, domain:%zu)",
                       name_len, value_len, domain_len);
      return -1;
    }

  if (request_uri != NULL && request_uri->host != NULL
      && !domain_matches (request_uri->host, cookie->domain))
    {
      SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                       "Set-Cookie rejected: Domain '%s' does not "
                       "domain-match request host '%s'",
                       cookie->domain, request_uri->host);
      return -1;
    }

  return 0;
}
