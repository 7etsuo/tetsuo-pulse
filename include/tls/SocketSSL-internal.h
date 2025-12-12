/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

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
 * @brief Check if path contains any ".." traversal sequence
 * @ingroup security
 * @param path Path string to check
 * @param len Length of path
 * @return 1 if traversal found, 0 if safe
 *
 * Detects ".." in any context that could enable directory traversal:
 * - Standalone ".." (entire path)
 * - At path start: "../", "..\\"
 * - In path middle: "/../", "\\..\\", "/..\\", "\\../"
 * - At path end: "/..", "\\.."
 *
 * Uses robust detection rather than pattern matching to avoid bypasses.
 * Defense-in-depth: realpath() in higher layers provides additional protection.
 *
 * @threadsafe Yes - pure function, no side effects.
 */
static inline int
ssl_contains_path_traversal (const char *path, size_t len)
{
  /* Reject any path containing ".." - simple but comprehensive
   * This catches all traversal attempts including:
   * - /../ (Unix traversal)
   * - \..\ (Windows traversal)
   * - /.. or \.. at end
   * - ../ or ..\ at start
   * - Just ".." alone
   * - Mixed separators: /..\ or \../
   */
  if (strstr (path, "..") != NULL)
    return 1;

  (void)len; /* Reserved for future validation */
  return 0;
}

/**
 * @brief Check if path contains ASCII control characters
 * @ingroup security
 * @param path Path string to check
 * @param len Length of path
 * @return 1 if control characters found, 0 if safe
 *
 * Rejects bytes in ranges 0x00-0x1F (C0 controls) and 0x7F (DEL).
 * These can be used for:
 * - Null byte injection (truncation attacks)
 * - Terminal escape sequences
 * - Log injection
 * - Filename parsing confusion
 *
 * @threadsafe Yes - pure function, no side effects.
 */
static inline int
ssl_contains_control_chars (const char *path, size_t len)
{
  for (size_t i = 0; i < len; i++)
    {
      unsigned char c = (unsigned char)path[i];
      /* ASCII control: 0x00-0x1F (space-1) and 0x7F (DEL) */
      if (c < 0x20 || c == 0x7F)
        return 1;
    }
  return 0;
}

/**
 * @brief Validate file path for certificates, keys, or CAs against security
 * threats.
 * @ingroup security
 * @param path Null-terminated file path string to validate.
 * @param max_len Maximum allowed path length.
 * @return 1 if path passes all security checks, 0 otherwise.
 *
 * Comprehensive validation to mitigate path traversal, symlink following, and
 * injection attacks. Provides defense-in-depth for credential file loading.
 *
 * ## Security Checks Performed
 *
 * | Check | Attack Mitigated | Method |
 * |-------|------------------|--------|
 * | Empty/NULL | Null dereference | Pointer and length check |
 * | Length limit | Buffer overflow, DoS | Configurable max_len |
 * | Path traversal | Directory escape | Reject any ".." sequence |
 * | Control chars | Injection, truncation | Reject 0x00-0x1F, 0x7F |
 * | Symlinks | Symlink attacks | lstat() S_ISLNK check |
 *
 * ## Path Traversal Detection
 *
 * Rejects ANY path containing ".." to prevent:
 * - `/../` - Unix directory traversal
 * - `\..\\` - Windows directory traversal
 * - `..` at start, middle, or end of path
 * - Mixed separator attacks (`/..\\`, `\\../`)
 *
 * This is more restrictive than pattern-based detection but eliminates
 * bypass possibilities. Legitimate paths should use absolute paths or
 * avoid ".." in filenames entirely.
 *
 * ## Symlink Handling
 *
 * Uses lstat() to detect symlinks without following them. Symlinks are
 * rejected to prevent:
 * - Symlink-to-symlink chains escaping chroot
 * - TOCTOU (time-of-check-time-of-use) race conditions
 * - Privilege escalation via symlink pointing to sensitive files
 *
 * If lstat() fails (ENOENT, EACCES), validation continues but file
 * operations will fail later with appropriate errors.
 *
 * ## Usage Example
 *
 * @code{.c}
 * if (!ssl_validate_file_path(cert_path, SOCKET_TLS_MAX_PATH_LEN)) {
 *     RAISE_TLS_ERROR_MSG(SocketTLS_Failed, "Invalid certificate path");
 * }
 * // Path is safe to use with fopen(), SSL_CTX_use_certificate_file(), etc.
 * @endcode
 *
 * @threadsafe Yes - pure string and stat operations, no shared state.
 *
 * @note lstat failure (ENOENT, EACCES) allows validation to proceed;
 * the actual file operation will fail with appropriate error.
 *
 * @warning This does not validate that the file exists or is readable.
 * Use in combination with proper file access error handling.
 *
 * @see tls_validate_file_path() TLS-specific wrapper
 * @see dtls_validate_file_path() DTLS-specific wrapper
 * @see validate_crl_path_security() for CRL-specific validation with realpath
 */
static inline int
ssl_validate_file_path (const char *path, size_t max_len)
{
  /* NULL or empty path */
  if (!path || !*path)
    return 0;

  size_t len = strlen (path);

  /* Length validation (also catches empty after strlen) */
  if (len == 0 || len > max_len)
    return 0;

  /* Control character check (includes embedded nulls via strlen limitation)
   * Must check BEFORE any string operations that might be confused by special
   * chars */
  if (ssl_contains_control_chars (path, len))
    return 0;

  /* Path traversal detection - reject ANY ".." sequence
   * This is defense-in-depth; realpath() in callers provides additional
   * protection */
  if (ssl_contains_path_traversal (path, len))
    return 0;

  /* Symlink detection via lstat() - reject symlinks to prevent attacks
   * lstat() doesn't follow symlinks, so we can detect them directly */
  struct stat sb;
  if (lstat (path, &sb) == 0)
    {
      if (S_ISLNK (sb.st_mode))
        return 0; /* Reject symlinks */
    }
  /* lstat() failure (ENOENT, EACCES, etc.) is OK - validation passes,
   * but actual file operations will fail with appropriate errors */

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
 * Size used for temporary OpenSSL error string buffers when formatting
 * errors from the OpenSSL error queue.
 *
 * ## Buffer Size Rationale (256 bytes)
 *
 * OpenSSL error strings follow the format:
 *   `error:[hex error code]:[library name]:[function name]:[reason string]`
 *
 * - **Typical length**: ~80-120 characters for standard OpenSSL errors
 * - **Maximum observed**: ~200 characters for complex certificate errors
 * - **256 bytes**: Provides 2x safety margin for all known error formats
 *
 * This matches OpenSSL documentation recommendations and industry practice.
 * The ERR_error_string_n() function safely truncates if buffer is too small.
 *
 * ## Example Error Formats
 *
 * - `error:0A000086:SSL routines:tls_post_process_server_certificate:...`
 * - `error:16000069:STORE routines:ossl_store_get0_loader_int:...`
 *
 * @see ERR_error_string_n() for OpenSSL error string generation.
 * @see ssl_format_openssl_error_to_buf() for usage.
 */
#ifndef SOCKET_SSL_OPENSSL_ERRSTR_BUFSIZE
#define SOCKET_SSL_OPENSSL_ERRSTR_BUFSIZE 256
#endif

/**
 * @brief Format OpenSSL error into a provided buffer.
 * @ingroup security
 * @param[in] context Context string describing the operation that failed.
 * @param[out] buf Output buffer for the formatted error message.
 * @param[in] buf_size Size of output buffer in bytes.
 *
 * Reads the first (deepest) error from OpenSSL's thread-local error queue
 * and formats it into the provided buffer with the given context prefix.
 *
 * ## OpenSSL Error Queue Behavior
 *
 * OpenSSL pushes errors onto a per-thread queue in order of occurrence.
 * ERR_get_error() returns errors FIFO (first-in, first-out), meaning the
 * first error retrieved is typically the root cause. This function captures
 * that first error as it is usually the most specific and actionable.
 *
 * ## Error Queue Cleanup
 *
 * This function ALWAYS calls ERR_clear_error() after formatting to:
 * - Prevent stale errors from affecting subsequent operations
 * - Avoid error leakage between unrelated operations
 * - Follow OpenSSL best practice for error handling
 *
 * ## Format Specification
 *
 * Output format: `<context>: <openssl_error_string>`
 *
 * If no error is queued: `<context>: Unknown error`
 *
 * ## Usage Example
 *
 * @code{.c}
 * char errbuf[512];
 * if (SSL_connect(ssl) <= 0) {
 *     ssl_format_openssl_error_to_buf("SSL_connect failed", errbuf, sizeof(errbuf));
 *     // errbuf now contains: "SSL_connect failed: error:0A000..."
 * }
 * @endcode
 *
 * @threadsafe Yes - operates on thread-local OpenSSL error queue.
 *
 * @note Uses SOCKET_SSL_OPENSSL_ERRSTR_BUFSIZE (256) for internal formatting.
 * @note Always clears error queue even if buf is NULL or buf_size is 0.
 *
 * @see ERR_get_error() for OpenSSL error retrieval.
 * @see ERR_error_string_n() for safe error string formatting.
 * @see ERR_clear_error() for error queue cleanup.
 */
static inline void
ssl_format_openssl_error_to_buf (const char *context, char *buf,
                                 size_t buf_size)
{
  unsigned long err;
  char err_str[SOCKET_SSL_OPENSSL_ERRSTR_BUFSIZE];

  /* Validate output buffer parameters */
  if (!buf || buf_size == 0)
    {
      ERR_clear_error ();
      return;
    }

  /* ERR_get_error() returns 0 if no error is queued.
   * It removes the error from the queue as a side effect. */
  err = ERR_get_error ();

  if (err != 0)
    {
      /* ERR_error_string_n() safely formats into fixed-size buffer.
       * It null-terminates and truncates if necessary. */
      ERR_error_string_n (err, err_str, sizeof (err_str));

      /* Format with context prefix */
      if (context && *context)
        {
          snprintf (buf, buf_size, "%s: %s", context, err_str);
        }
      else
        {
          snprintf (buf, buf_size, "%s", err_str);
        }
    }
  else
    {
      /* No error in queue - provide meaningful fallback */
      if (context && *context)
        {
          snprintf (buf, buf_size, "%s: Unknown error (no OpenSSL error code)",
                    context);
        }
      else
        {
          snprintf (buf, buf_size, "Unknown error (no OpenSSL error code)");
        }
    }

  /* CRITICAL: Clear the entire error queue to prevent:
   * 1. Stale errors affecting subsequent unrelated operations
   * 2. Memory buildup from unread errors
   * 3. Error leakage between different logical operations
   *
   * Per OpenSSL documentation: "After handling an error, the error queue
   * should be cleared using ERR_clear_error()" */
  ERR_clear_error ();
}

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETSSL_INTERNAL_INCLUDED */
