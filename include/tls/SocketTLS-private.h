/**
 * @file SocketTLS-private.h
 * @ingroup security
 * @brief Internal TLS module shared definitions, macros, and helper functions.
 *
 * Private header included by TLS .c files. Provides:
 * - Thread-local error handling and exception macros
 * - Security validation for files, hostnames, keys
 * - Internal structures for pinning, SNI, ALPN, CRL auto-refresh
 * - OpenSSL error formatting and SSL access utilities
 * - Ex_data index management for context association
 *
 * NOT part of public API - applications must not include this header.
 *
 *  Features
 *
 * - RAISE_TLS_ERROR* macros with thread-local detailed exceptions
 * - tls_validate_file_path() for secure credential loading
 * - tls_secure_free_pkey() for zeroized key cleanup
 * - tls_validate_hostname() for RFC-compliant SNI
 * - Certificate pinning with SPKI SHA256 and constant-time lookup
 * - ALPN temp buffer management to prevent UAF in callbacks
 * - CRL mutex-protected auto-refresh scheduling
 *
 *  Platform Requirements
 *
 * - OpenSSL/LibreSSL with TLS 1.2+ (1.3 recommended)
 * - POSIX pthreads for mutexes and thread-local storage (__thread)
 * - Unix stat/lstat for symlink detection in validation
 * - CLOCK_MONOTONIC for timing (CRL refresh, timeouts)
 * - _GNU_SOURCE enabled for extensions
 *
 *  Thread Safety
 *
 * - Macros: Thread-safe via thread-local storage
 * - Inline functions: Yes where noted (read-only or pure)
 * - Structs: Conditional; use mutexes for shared access
 *
 * @internal
 *
 * @warning Misuse can lead to security vulnerabilities (e.g., symlink attacks,
 * timing leaks)
 *
 * @see SocketTLS.h for public Socket TLS operations
 * @see SocketTLSContext.h for public context API
 * @see docs/SECURITY.md for TLS hardening guide
 */

#ifndef SOCKETTLS_PRIVATE_INCLUDED
#define SOCKETTLS_PRIVATE_INCLUDED

/**
 * @file SocketTLS-private.h
 * @ingroup security
 * @brief Internal TLS module shared definitions, macros, and helper functions.
 *
 * Private header included by TLS .c files. Provides:
 * - Thread-local error handling and exception macros
 * - Security validation for files, hostnames, keys
 * - Internal structures for pinning, SNI, ALPN, CRL auto-refresh
 * - OpenSSL error formatting and SSL access utilities
 * - Ex_data index management for context association
 *
 * NOT part of public API - applications must not include this header.
 *
 *  Features
 * - RAISE_TLS_ERROR* macros with thread-local detailed exceptions
 * - tls_validate_file_path() for secure credential loading
 * - tls_secure_free_pkey() for zeroized key cleanup
 * - tls_validate_hostname() for RFC-compliant SNI
 * - Certificate pinning with SPKI SHA256 and constant-time lookup
 * - ALPN temp buffer management to prevent UAF in callbacks
 * - CRL mutex-protected auto-refresh scheduling
 *
 *  Platform Requirements
 * - OpenSSL/LibreSSL with TLS 1.2+ (1.3 recommended)
 * - POSIX pthreads for mutexes and thread-local storage (__thread)
 * - Unix stat/lstat for symlink detection in validation
 * - CLOCK_MONOTONIC for timing (CRL refresh, timeouts)
 * - _GNU_SOURCE enabled for extensions
 *
 *  Thread Safety
 * - Macros: Thread-safe via thread-local storage
 * - Inline functions: Yes where noted (read-only or pure)
 * - Structs: Conditional; use mutexes for shared access
 *
 * @internal
 *
 * @warning Misuse can lead to security vulnerabilities (e.g., symlink attacks,
 * timing leaks)
 *
 * @see SocketTLS.h for public Socket TLS operations
 * @see SocketTLSContext.h for public context API
 * @see docs/SECURITY.md for TLS hardening guide
 * @see docs/ERROR_HANDLING.md for exception usage
 */

#if SOCKET_HAS_TLS

#include <ctype.h>
#include <pthread.h>
#include <string.h>
#include <sys/stat.h> /* For lstat and S_ISLNK */
#include <unistd.h>   /* For lstat portability */

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketCrypto.h" /* For SocketCrypto_secure_clear */
#include "core/SocketUtil.h"
#include "socket/Socket-private.h"
#include "tls/SocketTLS.h"
#include "tls/SocketTLSConfig.h"
#include "tls/SocketTLSContext.h"
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/stack.h> /* For STACK_OF and sk_* functions */
#include <openssl/x509.h>

/* ============================================================================
 * Thread-Local Error Handling for SocketTLS
 * ============================================================================
 */

/**
 * @brief tls_error_buf - Thread-local TLS error message buffer (see
 * SocketTLS.h for details).
 * @ingroup security
 *
 * Declared in SocketTLS.h. Used by all TLS macros for error reporting.
 */

/**
 * @brief SocketTLS_DetailedException - Thread-local exception for TLS module
 * errors.
 * @ingroup security
 *
 * Thread-local exception type for TLS module errors (declared in .c files via
 * SOCKET_DECLARE_MODULE_EXCEPTION(SocketTLS)). Prevents race conditions in
 * multi-threaded environments by providing per-thread exception storage
 * populated with tls_error_buf details.
 *
 * Used by RAISE_TLS_ERROR* macros for detailed reporting.
 *
 * @note Not a global var; thread-local instance.
 *
 * @see SOCKET_DECLARE_MODULE_EXCEPTION() in core/SocketUtil.h for declaration
 * pattern
 * @see tls_error_buf for error message buffer
 * @see core/Except.h for exception handling system
 */

/**
 * @brief RAISE_TLS_ERROR - Raise TLS exception with detailed error message
 * @ingroup security
 * @param exception Exception type to raise
 *
 * Creates thread-local copy of exception with reason from tls_error_buf.
 */
#define RAISE_TLS_ERROR(exception)                                            \
  SOCKET_RAISE_MODULE_ERROR (SocketTLS, exception)

/**
 * @brief RAISE_TLS_ERROR_MSG - Raise TLS exception with formatted message
 * @ingroup security
 * @param exception Exception type to raise
 * @param fmt Error message format string
 * @param ... Format arguments
 *
 * Raises TLS exception with formatted error message. Uses thread-local
 * exception storage to prevent race conditions. The message is formatted
 * into tls_error_buf and attached to the exception before raising.
 */
#define RAISE_TLS_ERROR_MSG(exception, fmt, ...)                              \
  SOCKET_RAISE_MSG (SocketTLS, exception, fmt, ##__VA_ARGS__)

/**
 * @brief REQUIRE_TLS_ENABLED - Validate TLS is enabled on socket
 * @ingroup security
 * @param socket Socket to validate
 * @param exception Exception to raise on failure
 *
 * Validates that TLS has been enabled on the specified socket. Raises
 * the provided exception with a descriptive message if TLS is not enabled.
 * Used throughout TLS operations to ensure proper initialization order.
 *
 * @see SocketTLS_enable() for enabling TLS on sockets
 */
#define REQUIRE_TLS_ENABLED(socket, exception)                                \
  do                                                                          \
    {                                                                         \
      if (!(socket)->tls_enabled)                                             \
        RAISE_TLS_ERROR_MSG (exception, "TLS not enabled on socket");         \
    }                                                                         \
  while (0)

/**
 * @brief TLS_ERROR_MSG - Format simple error message
 * @ingroup security
 * @param msg Message string
 *
 * Formats a simple error message into the thread-local error buffer.
 * Used for consistent error reporting across TLS operations.
 */
#define TLS_ERROR_MSG(msg) SOCKET_ERROR_MSG ("%s", msg)

/**
 * @brief TLS_ERROR_FMT - Format error message with arguments
 * @ingroup security
 * @param fmt Format string
 * @param ... Format arguments
 *
 * Formats an error message with arguments into the thread-local error buffer.
 * Includes errno information when available for system call diagnostics.
 */
#define TLS_ERROR_FMT(fmt, ...) SOCKET_ERROR_MSG (fmt, __VA_ARGS__)

/**
 * @brief VALIDATE_TLS_IO_READY - Validate socket is ready for TLS I/O
 * @ingroup security
 * @param socket Socket to validate
 * @param exception Exception to raise on failure
 *
 * Performs comprehensive validation before TLS I/O operations:
 * - Checks that TLS is enabled on the socket
 * - Verifies handshake is complete
 * - Ensures SSL object is available
 *
 * Returns SSL* pointer on success for immediate use, raises exception on
 * failure. Used by all TLS send/receive operations to ensure proper state.
 *
 * @return SSL* pointer for immediate use in TLS operations
 */
#define VALIDATE_TLS_IO_READY(socket, exception)                              \
  ({                                                                          \
    if (!(socket)->tls_enabled)                                               \
      {                                                                       \
        TLS_ERROR_MSG ("TLS not enabled on socket");                          \
        RAISE_TLS_ERROR (exception);                                          \
      }                                                                       \
    if (!(socket)->tls_handshake_done)                                        \
      {                                                                       \
        TLS_ERROR_MSG ("TLS handshake not complete");                         \
        RAISE_TLS_ERROR (exception);                                          \
      }                                                                       \
    SSL *_ssl = tls_socket_get_ssl (socket);                                  \
    if (!_ssl)                                                                \
      {                                                                       \
        TLS_ERROR_MSG ("SSL object not available");                           \
        RAISE_TLS_ERROR (exception);                                          \
      }                                                                       \
    _ssl;                                                                     \
  })

/* ============================================================================
 * SSL Object Access
 * ============================================================================
 */

/**
 * @brief tls_socket_get_ssl - Get SSL* from socket
 * @ingroup security
 * @param socket Socket instance
 * @return SSL* pointer or NULL if TLS not enabled/available
 *
 * Safely extracts the SSL object from a TLS-enabled socket. Performs
 * null checks and TLS enablement validation before returning the SSL pointer.
 * Returns NULL if socket is invalid, TLS is not enabled, or SSL object
 * is not available.
 *
 * @threadsafe Yes - read-only operation on socket state
 */
static inline SSL *
tls_socket_get_ssl (Socket_T socket)
{
  if (!socket || !socket->tls_enabled || !socket->tls_ssl)
    return NULL;
  return (SSL *)socket->tls_ssl;
}

/* ============================================================================
 * SSL Error Handling
 * ============================================================================
 */

/**
 * @brief tls_handle_ssl_error - Map OpenSSL errors to TLSHandshakeState
 * @ingroup security
 * @param socket Socket instance
 * @param ssl SSL object
 * @param ssl_result Result from SSL operation
 * @return TLSHandshakeState based on error type
 *
 * Maps OpenSSL error codes to TLS handshake states for event-driven I/O.
 * Handles the complex mapping between OpenSSL's error model and the socket
 * library's state machine. Critical for non-blocking TLS operations.
 *
 * Error handling:
 * - SSL_ERROR_NONE: Complete - handshake finished successfully
 * - SSL_ERROR_WANT_READ/WRITE: Non-blocking - need I/O, errno=EAGAIN
 * - SSL_ERROR_SYSCALL: System error - errno preserved for diagnostics
 * - SSL_ERROR_SSL: Protocol error - detailed in OpenSSL error queue
 * - SSL_ERROR_ZERO_RETURN: Clean peer shutdown
 *
 * @threadsafe Yes - operates on per-connection SSL state
 */
static inline TLSHandshakeState
tls_handle_ssl_error (Socket_T socket, SSL *ssl, int ssl_result)
{
  int ssl_error = SSL_get_error (ssl, ssl_result);

  switch (ssl_error)
    {
    case SSL_ERROR_NONE:
      socket->tls_handshake_done = 1;
      return TLS_HANDSHAKE_COMPLETE;

    case SSL_ERROR_WANT_READ:
      socket->tls_handshake_done = 0;
      errno = EAGAIN;
      return TLS_HANDSHAKE_WANT_READ;

    case SSL_ERROR_WANT_WRITE:
      socket->tls_handshake_done = 0;
      errno = EAGAIN;
      return TLS_HANDSHAKE_WANT_WRITE;

    case SSL_ERROR_ZERO_RETURN:
      /* Clean shutdown by peer - not an error per se, but connection is done
       */
      socket->tls_handshake_done = 0;
      return TLS_HANDSHAKE_ERROR;

    case SSL_ERROR_SYSCALL:
      /* System call error - errno contains the actual error.
       * If errno is 0, it typically means unexpected EOF (connection reset).
       * Do NOT overwrite errno here - preserve it for caller diagnostics. */
      socket->tls_handshake_done = 0;
      if (errno == 0)
        errno = ECONNRESET; /* Unexpected EOF treated as connection reset */
      return TLS_HANDSHAKE_ERROR;

    case SSL_ERROR_SSL:
      /* Protocol error - use ERR_get_error() for details.
       * Set errno to indicate protocol-level failure. */
      socket->tls_handshake_done = 0;
      errno = EPROTO;
      return TLS_HANDSHAKE_ERROR;

    default:
      /* Unknown error type - should not happen with current OpenSSL versions
       */
      socket->tls_handshake_done = 0;
      errno = EIO;
      return TLS_HANDSHAKE_ERROR;
    }
}

/**
 * @brief Format OpenSSL error into the thread-local error buffer.
 * @ingroup security
 * @param context Context string for the error message.
 *
 * Formats the current OpenSSL error queue into tls_error_buf prefixed with the
 * given context. Clears the error queue after formatting to prevent
 * interference with subsequent operations. Used internally for consistent
 * error reporting in TLS functions.
 *
 * @threadsafe Yes - operates on thread-local error buffer.
 * @see tls_handle_ssl_error() for SSL error state mapping.
 * @see ERR_clear_error() OpenSSL error queue management.
 */
static inline void
tls_format_openssl_error (const char *context)
{
  unsigned long err = ERR_get_error ();
  char err_str[SOCKET_TLS_OPENSSL_ERRSTR_BUFSIZE];

  if (err != 0)
    {
      ERR_error_string_n (err, err_str, sizeof (err_str));
      SOCKET_ERROR_MSG ("%s: %s", context, err_str);
    }
  else
    {
      SOCKET_ERROR_MSG ("%s: Unknown error", context);
    }

  /* Clear remaining errors to prevent stale error information from
   * affecting subsequent operations or leaking to callers */
  ERR_clear_error ();
}

/* ============================================================================
 * Input Validation
 * ============================================================================
 */

/**
 * @brief Validate file path for certificates, keys, or CAs against security
 * threats.
 * @ingroup security
 * @param path Null-terminated file path string to validate.
 * @return 1 if path passes all security checks, 0 otherwise.
 *
 * Comprehensive validation to mitigate path traversal, symlink following, and
 * injection attacks:
 * - Length limits and non-empty check
 * - Blocks traversal patterns like "/../", "\\..\\", etc.
 * - Rejects control characters and embedded nulls
 * - Detects and rejects symlinks via lstat (if accessible)
 * - Case-insensitive on Windows patterns if needed (platform-specific)
 *
 * Essential for secure loading of TLS credentials from potentially untrusted
 * sources.
 *
 * @threadsafe Yes - pure string and stat operations, no shared state.
 * @see tls_validate_hostname() for SNI name validation.
 * @see tls_secure_free_pkey() for secure key handling post-load.
 * @note lstat failure (e.g., no permission) allows validation to proceed
 * conservatively.
 */

/* ============================================================================
 * ALPN Temp Buffer Management (for UAF fix in selection callback)
 * ============================================================================
 *
 * ALPN (Application-Layer Protocol Negotiation) requires careful memory
 * management in OpenSSL callbacks. The callback receives protocol strings
 * that may have limited lifetime, so we create persistent copies in ex_data.
 * This prevents use-after-free bugs when callbacks return pointers to
 * temporary buffers.
 *
 * The ex_data index is lazily initialized once per process to store
 * the protocol string copy. Cleanup is performed before SSL_free to
 * prevent memory leaks.
 */

/**
 * @brief Get global ex_data index for ALPN temporary protocol buffers.
 * @ingroup security
 * @return Non-negative ex_data index for SSL/SSL_CTX ex_data storage.
 *
 * Lazily initializes and returns the process-global SSL ex_data index
 * used to store arena-allocated copies of ALPN protocol strings in callbacks.
 * Thread-safe initialization using atomic operations or mutex.
 * Prevents use-after-free by persisting short-lived protocol pointers.
 *
 * @see tls_cleanup_alpn_temp() for buffer cleanup on SSL free.
 * @see SSL_set_ex_data() / SSL_get_ex_data() OpenSSL ex_data API.
 * @threadsafe Yes - atomic initialization, read-only after init.
 */
extern int tls_get_alpn_ex_idx (void);

/**
 * @brief Clean up temporary ALPN protocol buffer from SSL ex_data.
 * @ingroup security
 * @param ssl OpenSSL SSL object to clean.
 *
 * Frees any arena-allocated ALPN protocol string stored in the SSL's ex_data
 * using tls_get_alpn_ex_idx and clears the ex_data slot to NULL.
 * Prevents memory leaks in ALPN callbacks; safe for repeated calls or non-ALPN
 * SSLs. Called internally before SSL_free in socket TLS cleanup.
 *
 * @see tls_get_alpn_ex_idx() for the ex_data index used.
 * @see Arena_dispose() indirect via buffer free.
 * @threadsafe Conditional - safe if no concurrent access to SSL ex_data.
 */
extern void tls_cleanup_alpn_temp (SSL *ssl);
static inline int
tls_validate_file_path (const char *path)
{
  if (!path || !*path)
    return 0;

  size_t len = strlen (path);
  if (len == 0 || len > SOCKET_TLS_MAX_PATH_LEN)
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

  /* Reject embedded null bytes (paranoia check).
     Note: memchr is intentional - we're checking WITHIN the valid strlen,
     not including the terminator. This detects strings with embedded nulls. */
  // NOLINTNEXTLINE(bugprone-not-null-terminated-result)
  if (memchr (path, '\0', len) != NULL)
    return 0;

  /* Check for control characters (ASCII 0-31 and 127) */
  for (size_t i = 0; i < len; i++)
    {
      unsigned char c = (unsigned char)path[i];
      if (c < 32 || c == 127)
        return 0;
    }

  return 1;
}

/**
 * @brief Securely free EVP_PKEY with key material zeroization.
 * @ingroup security
 * @param pkey EVP_PKEY private key to free (safe for NULL).
 *
 * Exports the private key to DER, securely wipes the key bytes using
 * SocketCrypto_secure_clear, then frees both DER buffer and EVP_PKEY.
 * Mitigates forensic recovery of keys from memory post-free.
 *
 * Best-effort: succeeds even if export fails; always calls EVP_PKEY_free.
 * OpenSSL may leave some metadata, but sensitive key bytes are overwritten.
 *
 * @threadsafe Conditional - safe if no concurrent use of pkey.
 * @see SocketCrypto_secure_clear() constant-time memory wipe.
 * @see i2d_PrivateKey() OpenSSL DER export.
 * @see tls_secure_free_pkey in context cleanup for usage.
 */
static inline void
tls_secure_free_pkey (EVP_PKEY *pkey)
{
  if (!pkey)
    return;

  /* Export private key to DER for clearing (best-effort) */
  unsigned char *der = NULL;
  int der_len = i2d_PrivateKey (pkey, &der);
  if (der_len > 0)
    {
      SocketCrypto_secure_clear (der, (size_t)der_len);
      OPENSSL_free (der);
    }

  EVP_PKEY_free (pkey);
}

/**
 * @brief Validate SNI hostname against RFC-compliant format rules.
 * @ingroup security
 * @param hostname Null-terminated hostname string for SNI.
 * @return 1 if valid SNI hostname, 0 if invalid or malformed.
 *
 * Enforces RFC 952/1123/1035/6066 rules for domain labels:
 * - Alphanumeric + hyphen only, no starting/ending hyphen per label
 * - Label length 1-63 chars, total <=255 chars for SNI
 * - No empty labels, proper dot separation
 * - Basic IDN support via punycode assumption (caller normalizes)
 *
 * Prevents invalid SNI attacks like label injection or buffer overflows in
 * virtual servers.
 *
 * @threadsafe Yes - pure string parsing, no side effects.
 * @see RFC 6066 for TLS SNI extension details.
 * @see RFC 1123 for domain name syntax updates.
 * @see tls_validate_file_path() companion for file path security.
 * @note Does not perform DNS resolution or existence check.
 */
static inline int
tls_validate_hostname (const char *hostname)
{
  if (!hostname)
    return 0;

  size_t len = strlen (hostname);
  if (len == 0 || len > SOCKET_TLS_MAX_SNI_LEN)
    return 0;

  const char *p = hostname;
  int label_len = 0;
  int prev_hyphen
      = 0; /* Track if previous char was hyphen (for end-of-label check) */

  while (*p)
    {
      if (*p == '.')
        {
          /* RFC 952/1123: Labels cannot be empty, exceed 63 chars, or end with
           * hyphen */
          if (label_len == 0 || label_len > 63 || prev_hyphen)
            return 0;
          label_len = 0;
          prev_hyphen = 0;
        }
      else
        {
          if (!(isalnum ((unsigned char)*p) || *p == '-'))
            return 0;
          /* RFC 952/1123: Labels cannot start with hyphen */
          if (*p == '-' && label_len == 0)
            return 0;
          prev_hyphen = (*p == '-');
          label_len++;
          if (label_len > 63)
            return 0;
        }
      p++;
    }

  /* Final label: must exist, not exceed 63 chars, and not end with hyphen */
  return (label_len > 0 && label_len <= 63 && !prev_hyphen);
}

/* ============================================================================
 * SocketTLSContext_T Structure and Internal Definitions
 * ============================================================================
 */

#define T SocketTLSContext_T

/**
 * @brief TLSCertPin - Single certificate pin entry (SPKI SHA256 hash)
 * @ingroup security
 *
 * Stores a 32-byte SHA256 digest of the SubjectPublicKeyInfo (SPKI) DER
 * encoding. SPKI pinning is OWASP-recommended as it survives certificate
 * renewal when the same key is reused.
 */
typedef struct
{
  unsigned char
      hash[SOCKET_TLS_PIN_HASH_LEN]; /**< SHA256 digest of the
                                        SubjectPublicKeyInfo (SPKI) DER
                                        encoding (32 bytes). OWASP-recommended
                                        for pinning as it targets key material.
                                      */
} TLSCertPin;

/**
 * @brief TLSContextPinning - Certificate pinning configuration
 * @ingroup security
 *
 * Maintains an array of SPKI SHA256 hashes with constant-time lookup.
 * Uses linear scan with SocketCrypto_secure_compare() to prevent timing
 * attacks. For typical deployments (1-5 pins), this is effectively O(1).
 *
 * Thread safety: Thread-safe with internal mutex protecting configuration and
 * verification.
 */
typedef struct
{
  TLSCertPin *pins; /**< Array of SHA256 hashes (arena-allocated). */
  size_t count;     /**< Number of pins in the array. */
  size_t capacity;  /**< Allocated capacity of the pins array. */
  int enforce; /**< 1 = fail on mismatch (strict), 0 = warn only (default: 1).
                */
  pthread_mutex_t lock; /**< Mutex protecting pinning configuration and
                           verification for thread safety. */
} TLSContextPinning;

/**
 * @brief Structure for managing SNI certificate mappings in TLS context.
 * @ingroup security
 *
 * Holds arrays mapping hostnames to certificate files, private keys, and
 * pre-loaded X509 chains and EVP_PKEY objects. Supports multiple mappings per
 * hostname and a default entry (NULL hostnames). Used for dynamic certificate
 * selection based on SNI during TLS handshakes.
 *
 * Memory is arena-allocated; chains are owned by STACK_OF(X509) (references
 * only). Thread-safe via context-level locking.
 *
 * @see SocketTLSContext_add_sni_cert() for adding mappings.
 * @see tls_validate_hostname() for SNI hostname validation.
 * @see SSL_CTX_set_tlsext_servername_callback() OpenSSL SNI integration.
 */
typedef struct
{
  char **hostnames;  /**< Array of hostname strings (arena-allocated, NULL for
                        default entry). */
  char **cert_files; /**< Array of certificate file paths (arena-allocated). */
  char **key_files;  /**< Array of private key file paths (arena-allocated). */
  STACK_OF (X509) * *chains; /**< Pre-loaded certificate chains for each entry
                                (sk_X509 owns cert refs; leaf at index 0,
                                followed by intermediates). */
  EVP_PKEY **pkeys; /**< Pre-loaded private key objects for each entry. */
  size_t count;     /**< Number of certificate mappings. */
  size_t capacity;  /**< Allocated capacity. */
} TLSContextSNICerts;

/**
 * @brief Configuration for ALPN protocol negotiation.
 * @ingroup security
 *
 * Manages the list of supported ALPN protocols, selection callback, and
 * storage for the negotiated protocol string. Used during TLS handshake for
 * protocol negotiation with peers.
 *
 * Protocols are null-terminated strings; callback allows custom selection
 * logic. Thread-safe via context mutex for modifications.
 *
 * @see SocketTLSContext_set_alpn_protocols() for configuring protocols.
 * @see SocketTLSContext_set_alpn_callback() for custom selection.
 * @see tls_get_alpn_ex_idx() for safe buffer management in callbacks.
 * @see SSL_set_alpn_protos() OpenSSL ALPN interface.
 */
typedef struct
{
  const char **protocols; /**< Array of supported ALPN protocol strings
                             (null-terminated). */
  size_t count;           /**< Number of protocols in the array. */
  const char *selected;   /**< Negotiated protocol string (for clients; set
                             during handshake). */
  SocketTLSAlpnCallback
      callback;             /**< Custom ALPN selection callback (if set). */
  void *callback_user_data; /**< Opaque user data passed to the callback. */
} TLSContextALPN;

/**
 * @brief TLS context structure for managing OpenSSL SSL_CTX with secure
 * defaults, certificates, verification, ALPN, and session caching.
 * @ingroup security
 *
 * Manages OpenSSL SSL_CTX with secure defaults, certificates, verification,
 * ALPN, and session caching.
 */
struct T
{
  SSL_CTX *ssl_ctx; /**< OpenSSL SSL_CTX object for TLS sessions. */
  Arena_T arena;    /**< Memory arena for internal allocations. */
  int is_server;    /**< 1 for server context, 0 for client context. */
  int session_cache_enabled; /**< Flag to enable session caching (default: 1).
                              */
  size_t session_cache_size; /**< Maximum number of sessions in cache (default:
                                1024). */
  size_t cache_hits;         /**< Number of session resumptions (hits). */
  size_t cache_misses; /**< Number of full handshakes due to cache misses. */
  size_t cache_stores; /**< Number of new sessions stored in cache. */
  pthread_mutex_t
      stats_mutex; /**< Mutex for thread-safe updates to cache statistics. */

  /* Session tickets */
  unsigned char
      ticket_key[SOCKET_TLS_TICKET_KEY_LEN]; /**< Session ticket encryption key
                                                (48 bytes). Used for stateless
                                                session resumption. */
  int tickets_enabled; /**< 1 if session tickets are enabled (servers by
                          default). */

  /* OCSP stapling */
  SocketTLSOcspGenCallback ocsp_gen_cb; /**< Dynamic OCSP response generation
                                           callback for stapling. */
  void *ocsp_gen_arg; /**< User argument passed to OCSP gen callback. */
  const unsigned char *ocsp_response; /**< Static OCSP response bytes for
                                         stapling (alternative to dynamic). */
  size_t ocsp_len; /**< Length of static OCSP response bytes. */

  /* SNI certificate mapping */
  TLSContextSNICerts sni_certs;

  /* ALPN configuration */
  TLSContextALPN alpn;

  /* Custom verification callback */
  SocketTLSVerifyCallback verify_callback; /**< Custom X509 verify callback for
                                              peer certificate validation. */
  void *verify_user_data; /**< Opaque user data passed to verify callback. */
  TLSVerifyMode verify_mode; /**< Stored verification mode (e.g.,
                                TLS_VERIFY_NONE, TLS_VERIFY_PEER). */

  /* Certificate pinning (SPKI SHA256) */
  TLSContextPinning pinning;

  /* Certificate Transparency (RFC 6962) */
  int ct_enabled;           /**< 1 if CT verification enabled */
  CTValidationMode ct_mode; /**< CT validation mode (strict/permissive) */

  /* CRL Auto-Refresh Configuration */
  char *crl_refresh_path;    /**< Path to CRL file for auto-refresh
                                (arena-allocated) */
  long crl_refresh_interval; /**< Refresh interval in seconds (0 = disabled) */
  int64_t crl_next_refresh_ms; /**< Next scheduled refresh time in monotonic
                                  milliseconds */
  void
      *crl_callback; /**< SocketTLSCrlCallback (cast to avoid circular deps) */
  void *crl_user_data; /**< User data for CRL callback */

  pthread_mutex_t
      crl_mutex; /**< Mutex protecting CRL refresh state and load operations */

  /* OCSP Stapling Client Mode */
  int ocsp_stapling_enabled; /**< 1 if client requests OCSP stapling */

  /* Custom Certificate Store Lookup */
  void *cert_lookup_callback;  /**< SocketTLSCertLookupCallback (cast) */
  void *cert_lookup_user_data; /**< User data for cert lookup callback */
};

/**
 * @brief Acquire lock on TLS context's CRL mutex.
 * @ingroup security
 * @param ctx SocketTLSContext_T instance.
 *
 * Thread-safe macro to lock the CRL refresh mutex. Logs error and raises
 * SocketTLS_Failed if pthread_mutex_lock fails (e.g., deadlock or invalid
 * mutex). Ensures exclusive access to CRL auto-refresh state and operations.
 *
 * @warning Not recursive; avoid calling from within locked sections.
 * @see CRL_UNLOCK(ctx) to release the lock.
 * @see pthread_mutex_lock() for POSIX mutex semantics.
 * @threadsafe Yes - standard mutex locking.
 */
#define CRL_LOCK(ctx)                                                         \
  do                                                                          \
    {                                                                         \
      int err = pthread_mutex_lock (&(ctx)->crl_mutex);                       \
      if (err != 0)                                                           \
        {                                                                     \
          SOCKET_LOG_ERROR_MSG ("CRL mutex lock failed: %d", err);            \
          RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "CRL mutex lock failed: %d", \
                               err);                                          \
        }                                                                     \
    }                                                                         \
  while (0)

/**
 * @brief Release lock on TLS context's CRL mutex.
 * @ingroup security
 * @param ctx SocketTLSContext_T instance.
 *
 * Thread-safe macro to unlock the CRL refresh mutex. Logs error and raises
 * SocketTLS_Failed if pthread_mutex_unlock fails (e.g., not locked by caller).
 * Balances CRL_LOCK for exclusive access control.
 *
 * @warning Undefined behavior if mutex not locked by calling thread.
 * @see CRL_LOCK(ctx) to acquire the lock.
 * @see pthread_mutex_unlock() for POSIX mutex release.
 * @threadsafe Yes - standard mutex unlocking.
 */
#define CRL_UNLOCK(ctx)                                                       \
  do                                                                          \
    {                                                                         \
      int err = pthread_mutex_unlock (&(ctx)->crl_mutex);                     \
      if (err != 0)                                                           \
        {                                                                     \
          SOCKET_LOG_ERROR_MSG ("CRL mutex unlock failed: %d", err);          \
          RAISE_CTX_ERROR_MSG (SocketTLS_Failed,                              \
                               "CRL mutex unlock failed: %d", err);           \
        }                                                                     \
    }                                                                         \
  while (0)

/* ============================================================================
 * Thread-Local Error Handling for SocketTLSContext
 * ============================================================================
 */

/**
 * @brief Raise a SocketTLSContext module exception using current error state.
 * @ingroup security
 * @param exception Specific SocketTLSContext exception type (e.g.,
 * SocketTLSContext_Failed).
 *
 * Uses the thread-local error buffer (tls_error_buf) populated by prior error
 * formatting macros like TLS_ERROR_MSG or tls_format_openssl_error. Creates a
 * detailed exception copy via SOCKET_RAISE_MODULE_ERROR to avoid races in
 * multi-threaded environments.
 *
 * Intended for context-level operations where OpenSSL or allocation errors
 * occur.
 *
 * @see RAISE_CTX_ERROR_MSG() for exceptions with custom formatted messages.
 * @see SocketTLS_DetailedException for thread-local exception details.
 * @see tls_error_buf for error message storage.
 */

#define RAISE_CTX_ERROR(exception)                                            \
  SOCKET_RAISE_MODULE_ERROR (SocketTLSContext, exception)

/**
 * @brief Raise a SocketTLSContext exception with formatted message.
 * @ingroup security
 * @param exception Specific SocketTLSContext exception type.
 * @param fmt printf-style format string for error message.
 * @param ... Arguments for format string.
 *
 * Formats the message into thread-local tls_error_buf using SOCKET_ERROR_MSG,
 * then raises the exception with details via SOCKET_RAISE_MSG.
 * Provides convenient error reporting for context operations.
 *
 * @throws SocketTLSContext exception variant with formatted message.
 * @see RAISE_CTX_ERROR() for using pre-formatted error buffer.
 * @see SOCKET_RAISE_MSG() underlying macro implementation.
 */
#define RAISE_CTX_ERROR_MSG(exception, fmt, ...)                              \
  SOCKET_RAISE_MSG (SocketTLSContext, exception, fmt, ##__VA_ARGS__)

/**
 * @brief Raise SocketTLSContext exception with variadic formatted message.
 * @ingroup security
 * @param exception Specific exception type to raise.
 * @param fmt printf-style format string.
 * @param ... Variable arguments for formatting.
 *
 * Similar to RAISE_CTX_ERROR_MSG but uses __VA_ARGS__ for better handling of
 * zero-argument cases in some compilers. Formats into tls_error_buf and
 * raises.
 *
 * @throws SocketTLSContext exception with formatted details.
 * @see RAISE_CTX_ERROR_MSG() primary formatted exception macro.
 */
#define RAISE_CTX_ERROR_FMT(exception, fmt, ...)                              \
  SOCKET_RAISE_MSG (SocketTLSContext, exception, fmt, __VA_ARGS__)

/* ============================================================================
 * Utility Macros
 * ============================================================================
 */

/**
 * @brief Suppress compiler warnings for intentionally unused parameters.
 * @ingroup security
 * @param x Parameter or variable that is intentionally unused (e.g., in
 * asserts only).
 *
 * Casts the parameter to void to inform the compiler it is deliberately
 * unused. Common in callback functions or when params are used conditionally.
 *
 * @note Use (void)param; style for single use; macro for readability.
 * @see socket_util_unused() if available in core utils.
 */
#define TLS_UNUSED(x) (void)(x)

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================
 */

/**
 * @brief Raise a SocketTLSContext exception from an OpenSSL error.
 * @ingroup security
 * @param context Descriptive context for the error (e.g., "SSL_CTX_new
 * failed").
 *
 * Formats the current OpenSSL error queue using tls_format_openssl_error and
 * raises SocketTLSContext_Failed with the details in the thread-local
 * exception. Clears the OpenSSL error queue after handling.
 *
 * @throws SocketTLSContext_Failed Always raised with formatted OpenSSL error
 * details.
 * @see tls_format_openssl_error() for error message formatting.
 * @see ERR_get_error() for accessing OpenSSL error queue.
 */
extern void ctx_raise_openssl_error (const char *context);

/**
 * @brief Duplicate a string into the TLS context's arena.
 * @ingroup security
 * @param ctx TLS context providing the memory arena.
 * @param str Null-terminated C string to duplicate.
 * @param error_msg Context message for allocation failure exception.
 * @return Pointer to the duplicated string in the arena.
 * @throws SocketTLS_Failed if Arena_alloc fails.
 *
 * Performs strlen + 1 allocation, copies the string, and handles allocation
 * failure by raising an exception with the provided error context. Used to
 * centralize arena-based string duplication in TLS context code.
 *
 * @see ctx_arena_alloc() for general-purpose allocation helper.
 * @see Arena_alloc() underlying memory allocation.
 * @threadsafe Conditional - safe if arena is not concurrently modified.
 */
static inline char *
ctx_arena_strdup (SocketTLSContext_T ctx, const char *str,
                  const char *error_msg)
{
  size_t len = strlen (str) + 1;
  char *copy = Arena_alloc (ctx->arena, len, __FILE__, __LINE__);
  if (!copy)
    {
      ctx_raise_openssl_error (error_msg);
    }
  memcpy (copy, str, len);
  return copy;
}

/**
 * @brief Allocate memory from the TLS context's arena with exception handling.
 * @ingroup security
 * @param ctx TLS context providing the memory arena.
 * @param size Number of bytes to allocate.
 * @param error_msg Context message for allocation failure exception.
 * @return Pointer to allocated memory block.
 * @throws SocketTLS_Failed if Arena_alloc returns NULL.
 *
 * Allocates memory using the context's arena and raises an exception on
 * failure with the specified error context. Centralizes allocation patterns in
 * TLS code.
 *
 * @see ctx_arena_strdup() for string-specific allocation.
 * @see Arena_alloc() underlying allocator with file/line tracking.
 * @threadsafe Conditional - safe if arena is thread-local or protected.
 */
static inline void *
ctx_arena_alloc (SocketTLSContext_T ctx, size_t size, const char *error_msg)
{
  void *ptr = Arena_alloc (ctx->arena, size, __FILE__, __LINE__);
  if (!ptr)
    {
      ctx_raise_openssl_error (error_msg);
    }
  return ptr;
}

/**
 * @brief Global ex_data index for storing SocketTLSContext_T in SSL_CTX.
 * @ingroup security
 *
 * Used to associate SocketTLSContext_T instances with their corresponding
 * OpenSSL SSL_CTX objects. Allows retrieving the library context from OpenSSL
 * callbacks and internal operations. Lazily initialized once per process.
 *
 * @see SSL_CTX_set_ex_data() for OpenSSL ex_data usage.
 */
extern int tls_context_exdata_idx;

/**
 * @brief Retrieve SocketTLSContext_T associated with an SSL object.
 * @ingroup security
 * @param ssl OpenSSL SSL object
 * @return Pointer to SocketTLSContext_T or NULL if not found
 *
 * Looks up the library TLS context stored in the SSL object's ex_data.
 * Used in OpenSSL callbacks to access configuration and state.
 *
 * @threadsafe Yes - read-only lookup
 * @see tls_context_get_from_ssl_ctx() for SSL_CTX lookup
 */
extern SocketTLSContext_T tls_context_get_from_ssl (const SSL *ssl);

/**
 * @brief Retrieve SocketTLSContext_T associated with an SSL_CTX object.
 * @ingroup security
 * @param ssl_ctx OpenSSL SSL_CTX object
 * @return Pointer to SocketTLSContext_T or NULL if not found
 *
 * Looks up the library TLS context stored in the SSL_CTX's ex_data.
 * Used during context initialization and OpenSSL callbacks.
 *
 * @threadsafe Yes - read-only lookup
 * @see tls_context_get_from_ssl() for SSL object lookup
 */
extern SocketTLSContext_T tls_context_get_from_ssl_ctx (SSL_CTX *ssl_ctx);

/**
 * @brief Allocate and initialize a new SocketTLSContext_T.
 * @ingroup security
 * @param method OpenSSL SSL_METHOD (e.g., TLS_server_method(),
 * TLS_client_method())
 * @param is_server 1 for server context, 0 for client context
 * @return New SocketTLSContext_T instance
 * @throws SocketTLS_Failed on allocation failure, OpenSSL errors, or invalid
 * params
 *
 * Creates arena, sets up SSL_CTX with secure defaults, initializes internal
 * state. Intended for internal use by SocketTLSContext_new*() functions.
 *
 * @see SocketTLSContext_new_server() for high-level server context creation
 * @see SocketTLSContext_new_client() for high-level client context creation
 */
extern SocketTLSContext_T ctx_alloc_and_init (const SSL_METHOD *method,
                                              int is_server);

/* ============================================================================
 * Certificate Pinning Internal Functions
 * ============================================================================
 */

/**
 * @brief Initialize TLS certificate pinning configuration.
 * @ingroup security
 * @param pinning Pointer to TLSContextPinning structure
 *
 * Sets up the pinning array and mutex for thread-safe operation.
 * Must be called before adding pins or using the pinning config.
 *
 * @see tls_pinning_add() to add pins after initialization
 */
static inline void
tls_pinning_init (TLSContextPinning *pinning)
{
  pinning->pins = NULL;
  pinning->count = 0;
  pinning->capacity = 0;
  pinning->enforce = 1; /* Default: strict enforcement */
  pthread_mutex_init (&pinning->lock, NULL);
}

/**
 * @brief Compute SPKI SHA256 hash from X509 certificate for pinning
 * verification.
 * @ingroup security
 * @param cert Input X509 certificate object.
 * @param out_hash Output buffer for the 32-byte SHA256 hash (must be at least
 * SOCKET_TLS_PIN_HASH_LEN).
 * @return 0 on success, -1 on failure (e.g., invalid certificate or DER
 * extraction error).
 *
 * Extracts the SubjectPublicKeyInfo (SPKI) DER from the certificate and
 * computes its SHA256 digest. This method is recommended by OWASP for
 * certificate pinning as it targets the public key material, surviving
 * certificate renewals with the same key.
 *
 * @see tls_pinning_check_chain() for verifying chain against pins.
 * @see tls_pinning_find() for constant-time hash matching.
 * @see RFC 7469 Certificate Transparency and Public Key Pinning Extension.
 * @threadsafe Yes - pure computation on input objects.
 */
extern int tls_pinning_extract_spki_hash (const X509 *cert,
                                          unsigned char *out_hash);

/**
 * @brief Verify if any certificate in the chain matches a configured pin.
 * @ingroup security
 * @param ctx TLS context with pinning configuration.
 * @param chain STACK_OF(X509) certificate chain (leaf first).
 * @return 1 if a matching pin is found, 0 if no match (or pinning disabled).
 *
 * Iterates through the certificate chain, extracts SPKI hashes for each cert,
 * and checks against configured pins using constant-time comparison.
 * Logs warnings or errors based on enforce mode; may raise exceptions in
 * strict mode.
 *
 * Called during TLS verification callback to enforce pinning policy.
 *
 * @see tls_pinning_extract_spki_hash() for hash extraction.
 * @see tls_pinning_find() for pin matching logic.
 * @see SocketTLSContext_add_pin() for configuring pins.
 * @threadsafe Yes - locks pinning mutex internally.
 */
extern int tls_pinning_check_chain (SocketTLSContext_T ctx,
                                    const STACK_OF (X509) * chain);

/**
 * @brief Perform constant-time search for a hash in pinning array.
 * @ingroup security
 * @param pins Array of TLSCertPin structures.
 * @param count Number of pins in the array.
 * @param hash 32-byte SHA256 hash to search for.
 * @return 1 if exact match found, 0 otherwise.
 *
 * Scans the entire pin array using SocketCrypto_secure_compare for each entry
 * to prevent timing side-channel attacks. Accumulates comparison results in
 * constant time regardless of position.
 *
 * Critical for secure certificate pinning verification.
 *
 * @see SocketCrypto_secure_compare() for constant-time memcmp.
 * @see tls_pinning_extract_spki_hash() for generating search hashes.
 * @threadsafe No - caller must hold pinning lock.
 */
extern int tls_pinning_find (const TLSCertPin *pins, size_t count,
                             const unsigned char *hash);

#undef T

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETTLS_PRIVATE_INCLUDED */
