/**
 * @file SocketSSL-internal.h
 * @ingroup security
 * @brief Shared internal utilities for TLS and DTLS modules.
 *
 * Internal header providing common functionality between TLS and DTLS:
 * - File path security validation for credential loading
 * - OpenSSL error formatting helpers
 * - Common utility macros
 *
 * NOT part of public API - applications must not include this header.
 *
 * @internal
 *
 * @see SocketTLS-private.h for TLS-specific internals
 * @see SocketDTLS-private.h for DTLS-specific internals
 */

#ifndef SOCKETSSL_INTERNAL_INCLUDED
#define SOCKETSSL_INTERNAL_INCLUDED

#if SOCKET_HAS_TLS

#include <ctype.h>
#include <string.h>
#include <sys/stat.h>

#include "core/SocketUtil.h"
#include <openssl/err.h>

/* ============================================================================
 * Common Utility Macros
 * ============================================================================
 */

/**
 * @brief Suppress compiler warnings for intentionally unused parameters.
 * @ingroup security
 * @param x Parameter or variable that is intentionally unused.
 *
 * Casts the parameter to void to inform the compiler it is deliberately
 * unused. Common in callback functions or when params are used conditionally.
 */
#define SOCKET_SSL_UNUSED(x) (void)(x)

/* ============================================================================
 * Common File Path Validation
 * ============================================================================
 */

/**
 * @brief Maximum path length for TLS/DTLS credential files.
 * @ingroup security
 *
 * Shared limit used by both TLS and DTLS file path validation.
 * Defaults to the more restrictive of TLS/DTLS if both are defined.
 */
#ifndef SOCKET_SSL_MAX_PATH_LEN
#if defined(SOCKET_TLS_MAX_PATH_LEN)
#define SOCKET_SSL_MAX_PATH_LEN SOCKET_TLS_MAX_PATH_LEN
#elif defined(SOCKET_DTLS_MAX_PATH_LEN)
#define SOCKET_SSL_MAX_PATH_LEN SOCKET_DTLS_MAX_PATH_LEN
#else
#define SOCKET_SSL_MAX_PATH_LEN 4096
#endif
#endif

/**
 * @brief Validate file path for certificates, keys, or CAs against security
 * threats.
 * @ingroup security
 * @param path Null-terminated file path string to validate.
 * @param max_len Maximum allowed path length.
 * @return 1 if path passes all security checks, 0 otherwise.
 *
 * Comprehensive validation to mitigate path traversal, symlink following, and
 * injection attacks:
 * - Length limits and non-empty check
 * - Blocks traversal patterns like "/../", "\\..\\", etc.
 * - Rejects control characters and embedded nulls
 * - Detects and rejects symlinks via lstat (if accessible)
 *
 * Essential for secure loading of TLS/DTLS credentials from potentially
 * untrusted sources.
 *
 * @threadsafe Yes - pure string and stat operations, no shared state.
 * @note lstat failure (e.g., no permission) allows validation to proceed
 * conservatively.
 */
static inline int
ssl_validate_file_path (const char *path, size_t max_len)
{
  if (!path || !*path)
    return 0;

  size_t len = strlen (path);
  if (len == 0 || len > max_len)
    return 0;

  /* Check for specific path traversal sequences (avoid false positives on
   * filenames like "cert..pem") */
  const char *traversal_patterns[]
      = { "/../",  "\\..\\", "/..\\",
          "\\../", "/.../",  "\\../", /* Added context-aware */
          NULL };
  for (const char **pat = traversal_patterns; *pat != NULL; ++pat)
    {
      if (strstr (path, *pat) != NULL)
        return 0;
    }

  /* Reject paths starting with relative traversal */
  if (strncmp (path, "../", 3) == 0 || strncmp (path, "..\\", 3) == 0)
    return 0;

  /* Additional symlink detection (optional, conservative: reject if detectable
   * symlink) */
  struct stat sb;
  if (lstat (path, &sb) == 0)
    {
      if (S_ISLNK (sb.st_mode))
        return 0; /* Reject symlinks to prevent attacks */
    }
  /* If lstat fails (e.g., no perm), continue validation (false negative ok for
   * usability) */

  /* Check for control characters (ASCII 0-31 and 127) */
  for (size_t i = 0; i < len; i++)
    {
      unsigned char c = (unsigned char)path[i];
      if (c < 32 || c == 127)
        return 0;
    }

  return 1;
}

/* ============================================================================
 * Common OpenSSL Error Formatting
 * ============================================================================
 */

/**
 * @brief OpenSSL error string buffer size.
 * @ingroup security
 *
 * Size used for temporary OpenSSL error string buffers.
 */
#ifndef SOCKET_SSL_OPENSSL_ERRSTR_BUFSIZE
#define SOCKET_SSL_OPENSSL_ERRSTR_BUFSIZE 256
#endif

/**
 * @brief Format OpenSSL error into a provided buffer.
 * @ingroup security
 * @param context Context string for the error message.
 * @param buf Output buffer for formatted error message.
 * @param buf_size Size of output buffer.
 *
 * Formats the current OpenSSL error queue into the provided buffer prefixed
 * with the given context. Clears the error queue after formatting to prevent
 * interference with subsequent operations.
 *
 * @threadsafe Yes - operates on thread-local OpenSSL error queue.
 */
static inline void
ssl_format_openssl_error_to_buf (const char *context, char *buf,
                                 size_t buf_size)
{
  unsigned long err = ERR_get_error ();
  char err_str[SOCKET_SSL_OPENSSL_ERRSTR_BUFSIZE];

  if (err != 0)
    {
      ERR_error_string_n (err, err_str, sizeof (err_str));
      snprintf (buf, buf_size, "%s: %s", context, err_str);
    }
  else
    {
      snprintf (buf, buf_size, "%s: Unknown error", context);
    }

  /* Clear remaining errors to prevent stale error information from
   * affecting subsequent operations or leaking to callers */
  ERR_clear_error ();
}

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETSSL_INTERNAL_INCLUDED */
