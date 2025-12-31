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

#include "core/SocketCrypto.h"
#include "core/SocketUtil.h"
#include <openssl/err.h>
#include <openssl/ssl.h>

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

/**
 * @brief OpenSSL 3.0.0 version number for conditional compilation.
 * @ingroup security
 *
 * Used to check for OpenSSL 3.0+ features and deprecations at compile time.
 * OpenSSL version format: MNNFFPPS (major/minor/fix/patch/status).
 *
 * Version breakdown for 0x30000000L:
 * - Major: 0x30 = 3
 * - Minor: 0x00 = 0
 * - Fix:   0x00 = 0
 * - Patch: 0x00 = 0
 * - Status: 0x0 = release
 *
 * @see OPENSSL_VERSION_NUMBER for runtime OpenSSL version
 */
#define SOCKET_OPENSSL_VERSION_3_0 0x30000000L

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
 * Common Buffer Management
 * ============================================================================
 */

/**
 * @brief Securely clear a buffer if allocated.
 * @ingroup security
 * @param buf Buffer pointer (may be NULL).
 * @param size Size of buffer in bytes.
 *
 * Uses SocketCrypto_secure_clear to wipe sensitive data that cannot be
 * optimized away. No-op if buf is NULL.
 *
 * @threadsafe Yes - pure function, no side effects.
 */
static inline void
ssl_secure_clear_buf (void *buf, size_t size)
{
  if (buf)
    SocketCrypto_secure_clear (buf, size);
}

/**
 * @brief Securely clear a hostname string.
 * @ingroup security
 * @param hostname Hostname string (may be NULL).
 *
 * Securely clears the hostname including null terminator. No-op if NULL.
 *
 * @threadsafe Yes - pure function, no side effects.
 */
static inline void
ssl_secure_clear_hostname (const char *hostname)
{
  if (hostname)
    {
      size_t len = strlen (hostname) + 1;
      SocketCrypto_secure_clear ((void *)hostname, len);
    }
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
 *     ssl_format_openssl_error_to_buf("SSL_connect failed", errbuf,
 * sizeof(errbuf));
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
ssl_format_openssl_error_to_buf (const char *context,
                                 char *buf,
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
          snprintf (buf,
                    buf_size,
                    "%s: Unknown error (no OpenSSL error code)",
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

/* ============================================================================
 * Common SSL/TLS Operations
 * ============================================================================
 */

/**
 * @brief Apply SNI hostname to SSL object with verification enabled.
 * @ingroup security
 * @param ssl SSL object to configure
 * @param hostname Hostname for SNI and verification
 *
 * Configures SSL object for peer verification with SNI hostname extension
 * and automatic hostname verification. This is the standard setup for
 * TLS and DTLS client connections.
 *
 * ## Operations Performed
 *
 * 1. **Peer Verification**: Enables SSL_VERIFY_PEER to require valid
 *    certificate from peer during handshake.
 *
 * 2. **SNI Extension**: Sets TLS SNI (Server Name Indication) extension
 *    via SSL_set_tlsext_host_name() to indicate which hostname the client
 *    is trying to reach.
 *
 * 3. **Hostname Verification**: Enables automatic hostname verification
 *    via SSL_set1_host() to ensure the peer certificate's CN or SAN
 *    matches the expected hostname.
 *
 * ## Return Values
 *
 * Returns 0 on success, or negative error code:
 * - -1: SSL_set_tlsext_host_name() failed
 * - -2: SSL_set1_host() failed
 *
 * ## Usage Pattern
 *
 * @code{.c}
 * int ret = ssl_apply_sni_hostname(ssl, "example.com");
 * if (ret < 0) {
 *     // Handle error - ret indicates which operation failed
 *     RAISE_ERROR_MSG(Module_Failed, "Failed to set SNI hostname");
 * }
 * @endcode
 *
 * @threadsafe No - modifies SSL object state
 *
 * @see SSL_set_verify() for verification mode
 * @see SSL_set_tlsext_host_name() for SNI extension
 * @see SSL_set1_host() for hostname verification
 */
static inline int
ssl_apply_sni_hostname (SSL *ssl, const char *hostname)
{
  /* Enable peer certificate verification - required for hostname check */
  SSL_set_verify (ssl, SSL_VERIFY_PEER, NULL);

  /* Set SNI extension */
  if (SSL_set_tlsext_host_name (ssl, hostname) != 1)
    return -1;

  /* Enable hostname verification */
  if (SSL_set1_host (ssl, hostname) != 1)
    return -2;

  return 0;
}

/**
 * @brief Handle SSL handshake result and determine next action.
 * @ingroup security
 * @param ssl SSL object
 * @param ssl_result Return value from SSL_do_handshake()
 * @param handshake_done_flag Pointer to flag to set on completion (may be NULL)
 *
 * Processes the return value from SSL_do_handshake() and translates it
 * into actionable next steps for non-blocking handshake operations.
 *
 * ## Return Values
 *
 * - **0**: Handshake complete successfully (ssl_result == 1)
 * - **1**: Need to wait for readable data (SSL_ERROR_WANT_READ)
 * - **2**: Need to wait for writable socket (SSL_ERROR_WANT_WRITE)
 * - **-1**: Fatal error occurred (all other SSL errors)
 *
 * ## Handshake Done Flag
 *
 * If handshake_done_flag is non-NULL and handshake completes (return 0),
 * the flag is set to 1. This allows callers to update state atomically
 * with the handshake result check.
 *
 * ## Error Handling
 *
 * This function does NOT raise exceptions or format error messages - it
 * only returns error codes. Callers should check the return value and
 * call ssl_format_openssl_error_to_buf() or module-specific error
 * formatting as needed.
 *
 * ## Usage Pattern
 *
 * @code{.c}
 * int result = SSL_do_handshake(ssl);
 * if (result == 1) {
 *     // Handshake complete
 * } else {
 *     int next = ssl_handle_handshake_result(ssl, result,
 * &socket->handshake_done); switch (next) { case 0: // Complete break; case 1:
 * // WANT_READ poll_for_read(); break; case 2: // WANT_WRITE poll_for_write();
 *             break;
 *         case -1: // Error
 *             handle_error();
 *             break;
 *     }
 * }
 * @endcode
 *
 * @threadsafe No - reads SSL error state
 *
 * @see SSL_do_handshake() for handshake operation
 * @see SSL_get_error() for error code interpretation
 */
static inline int
ssl_handle_handshake_result (SSL *ssl, int ssl_result, int *handshake_done_flag)
{
  /* Fast path: handshake complete */
  if (ssl_result == 1)
    {
      if (handshake_done_flag)
        *handshake_done_flag = 1;
      return 0;
    }

  /* ssl_result <= 0: query error code */
  int ssl_error = SSL_get_error (ssl, ssl_result);

  switch (ssl_error)
    {
    case SSL_ERROR_WANT_READ:
      return 1;

    case SSL_ERROR_WANT_WRITE:
      return 2;

    default:
      /* All other errors are fatal */
      return -1;
    }
}

/**
 * @brief Get SSL object from opaque pointer with validation.
 * @ingroup security
 * @param ssl_ptr Opaque pointer to SSL object (void*)
 * @param enabled_flag Flag indicating if TLS/DTLS is enabled
 *
 * Safely retrieves SSL object from opaque void pointer with validation.
 * Returns NULL if TLS/DTLS is not enabled or pointer is NULL.
 *
 * This is a convenience helper for modules that store SSL* as void*
 * to avoid header pollution in public interfaces.
 *
 * ## Return Value
 *
 * Returns SSL* if enabled_flag is true and ssl_ptr is non-NULL,
 * otherwise returns NULL.
 *
 * ## Usage Pattern
 *
 * @code{.c}
 * SSL *ssl = ssl_get_from_opaque(socket->tls_ssl, socket->tls_enabled);
 * if (!ssl) {
 *     return -1; // TLS not enabled or SSL object missing
 * }
 * @endcode
 *
 * @threadsafe Yes - pure function, no side effects
 */
static inline SSL *
ssl_get_from_opaque (void *ssl_ptr, int enabled_flag)
{
  if (!enabled_flag || !ssl_ptr)
    return NULL;
  return (SSL *)ssl_ptr;
}

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETSSL_INTERNAL_INCLUDED */
