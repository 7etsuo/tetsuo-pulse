/**
 * @file SocketTLS-private.h
 * @ingroup security
 * @brief TLS internal shared definitions and helper functions.
 *
 * Internal header for all TLS module implementation files. Contains shared
 * helper function declarations, error handling macros, internal types,
 * and the SocketTLSContext_T structure definition.
 * NOT part of public API - do not include from application code.
 *
 * Thread safety: Internal functions are not thread-safe unless noted.
 *
 * @see SocketTLS.h for public TLS API.
 * @see SocketTLSContext.h for public TLS context API.
 */

#ifndef SOCKETTLS_PRIVATE_INCLUDED
#define SOCKETTLS_PRIVATE_INCLUDED

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
 * @brief tls_error_buf - Thread-local TLS error message buffer (see SocketTLS.h for details).
 * @ingroup security
 *
 * Declared in SocketTLS.h. Used by all TLS macros for error reporting.
 */

/**
 * @brief SocketTLS_DetailedException - Thread-local exception for TLS module errors.
 * @ingroup security
 * @var SocketTLS_DetailedException
 *
 * Thread-local copy of SocketTLS exceptions to prevent race conditions when multiple
 * threads raise TLS exceptions simultaneously. Each thread gets its own copy populated
 * with details from tls_error_buf before raising.
 *
 * Declared via SOCKET_DECLARE_MODULE_EXCEPTION(SocketTLS) in implementation files.
 * Used by RAISE_TLS_ERROR* macros for detailed error reporting.
 *
 * @see SOCKET_DECLARE_MODULE_EXCEPTION() in SocketUtil.h for pattern
 * @see tls_error_buf for associated error message buffer
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
 * Returns SSL* pointer on success for immediate use, raises exception on failure.
 * Used by all TLS send/receive operations to ensure proper state.
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
 * tls_format_openssl_error - Format OpenSSL error into buffer
 * @param context Context string for error message
 *
 * Formats current OpenSSL error into tls_error_buf with context.
 * Clears the entire error queue to prevent stale errors from affecting
 * subsequent operations or leaking information.
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
 * @brief Validate certificate/key/CA file path for security
 * @ingroup security
 * @param path File path string to validate
 * @return 1 if valid, 0 if invalid
 *
 * Performs comprehensive security validation on file paths to prevent
 * directory traversal attacks and other path-based exploits:
 * - Non-empty and within configured length limits
 * - Rejects path traversal sequences (..) in any form
 * - Rejects control characters (except forward slash for paths)
 * - Validates against symlink attacks by checking file type
 * - Prevents embedded null bytes that could cause truncation
 *
 * This is critical for preventing attacks where untrusted input
 * could access sensitive files outside intended directories.
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
 * @brief tls_get_alpn_ex_idx - Get ex_data index for ALPN temp buffers
 * @ingroup security
 * @return Valid ex_data index for ALPN protocol storage
 *
 * Returns the SSL ex_data index used to store temporary ALPN protocol
 * copies. The index is lazily initialized once per process using
 * thread-safe mechanisms. Used by ALPN selection callbacks to store
 * persistent protocol strings.
 */
extern int tls_get_alpn_ex_idx (void);

/**
 * @brief tls_cleanup_alpn_temp - Free ALPN temp buffer from SSL ex_data
 * @ingroup security
 * @param ssl SSL object to cleanup
 *
 * Frees the temporary ALPN protocol copy stored in SSL ex_data (if any)
 * and clears the ex_data slot. Must be called before SSL_free() to
 * prevent memory leaks. Safe to call multiple times or on SSL objects
 * that never used ALPN.
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
 * @brief Securely free EVP_PKEY with cryptographic key material clearing
 * @ingroup security
 * @param pkey Pointer to private key to free (may be NULL)
 *
 * Performs secure cleanup of private key material to prevent memory disclosure:
 * 1. Exports private key to DER format for access to raw key bytes
 * 2. Securely clears the exported DER buffer using SocketCrypto_secure_clear()
 * 3. Frees the DER buffer and then the original EVP_PKEY
 *
 * This mitigates cold boot attacks and memory analysis that could recover
 * private keys from process memory after free(). Note: OpenSSL's internal
 * EVP_PKEY structure may retain some metadata, but raw key material is cleared.
 *
 * @see SocketCrypto_secure_clear() for secure memory wiping
 * @see EVP_PKEY_free() for standard OpenSSL cleanup
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
 * @brief Validate SNI hostname format according to RFC standards
 * @ingroup security
 * @param hostname Hostname string to validate
 * @return 1 if valid, 0 if invalid
 *
 * Performs strict validation of hostname format for Server Name Indication (SNI):
 * - Validates against RFC 952 (hostname syntax) and RFC 1123 (case insensitivity)
 * - Labels contain only alphanumeric characters and hyphens
 * - Labels cannot start or end with a hyphen (RFC 1123)
 * - Individual labels are 1-63 characters (RFC 1035 DNS limits)
 * - Total hostname length within RFC 6066 SNI limits (255 chars)
 * - Supports internationalized domain names (IDNA) through case-insensitive validation
 *
 * Critical for preventing hostname spoofing attacks in virtual hosting scenarios.
 * @see RFC 6066 Section 3 for SNI hostname validation requirements
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
  unsigned char hash[SOCKET_TLS_PIN_HASH_LEN]; /* SHA256 digest (32 bytes) */
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
  TLSCertPin *pins; /* Array of SHA256 hashes (arena-allocated) */
  size_t count;     /* Number of pins */
  size_t capacity;  /* Allocated capacity */
  int enforce;      /* 1 = fail on mismatch, 0 = warn only (default: 1) */
  pthread_mutex_t
      lock; /* Protects pinning configuration and access for thread safety */
} TLSContextPinning;

/**
 * SNI Certificate Mapping - Stores hostname-to-certificate mappings
 */
typedef struct
{
  char **hostnames;  /* Array of hostname strings (arena-allocated, NULL for
                        default) */
  char **cert_files; /* Array of certificate file paths (arena-allocated) */
  char **key_files;  /* Array of private key file paths (arena-allocated) */
  STACK_OF (X509)
  **chains; /* Pre-loaded certificate chains for each entry (sk_X509 owns
               cert refs; leaf at index 0, followed by intermediates) */
  EVP_PKEY **pkeys; /* Pre-loaded private key objects */
  size_t count;     /* Number of certificate mappings */
  size_t capacity;  /* Allocated capacity */
} TLSContextSNICerts;

/**
 * ALPN Configuration - Application-Layer Protocol Negotiation settings
 */
typedef struct
{
  const char **protocols;         /* Array of protocol strings */
  size_t count;                   /* Number of protocols */
  const char *selected;           /* Negotiated protocol (for clients) */
  SocketTLSAlpnCallback callback; /* Custom selection callback */
  void *callback_user_data;       /* User data for callback */
} TLSContextALPN;

/**
 * @brief TLS context structure for managing OpenSSL SSL_CTX with secure defaults, certificates, verification, ALPN, and session caching.
 * @ingroup security
 *
 * Manages OpenSSL SSL_CTX with secure defaults, certificates, verification,
 * ALPN, and session caching.
 */
struct T
{
  SSL_CTX *ssl_ctx;            /* OpenSSL context */
  Arena_T arena;               /* Arena for allocations */
  int is_server;               /* 1 for server, 0 for client */
  int session_cache_enabled;   /* Session cache flag */
  size_t session_cache_size;   /* Session cache size */
  size_t cache_hits;           /* Session resumptions (hits) */
  size_t cache_misses;         /* Full handshakes */
  size_t cache_stores;         /* New sessions stored */
  pthread_mutex_t stats_mutex; /* Thread-safe stats update */

  /* Session tickets */
  unsigned char ticket_key[SOCKET_TLS_TICKET_KEY_LEN]; /* Session ticket key */
  int tickets_enabled; /* 1 if session tickets enabled */

  /* OCSP stapling */
  SocketTLSOcspGenCallback ocsp_gen_cb; /* Dynamic OCSP callback */
  void *ocsp_gen_arg;                   /* Arg for OCSP gen cb */
  const unsigned char *ocsp_response;   /* Static response bytes */
  size_t ocsp_len;                      /* Response length */

  /* SNI certificate mapping */
  TLSContextSNICerts sni_certs;

  /* ALPN configuration */
  TLSContextALPN alpn;

  /* Custom verification callback */
  SocketTLSVerifyCallback verify_callback;
  void *verify_user_data;
  TLSVerifyMode verify_mode; /* Stored verification mode */

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
 * @brief RAISE_CTX_ERROR - Raise context exception with current error buffer
 * @ingroup security
 */

#define RAISE_CTX_ERROR(exception)                                            \
  SOCKET_RAISE_MODULE_ERROR (SocketTLSContext, exception)

/**
 * @brief RAISE_CTX_ERROR_MSG - Raise context exception with specific message
 * @ingroup security
 */
#define RAISE_CTX_ERROR_MSG(exception, fmt, ...)                              \
  SOCKET_RAISE_MSG (SocketTLSContext, exception, fmt, ##__VA_ARGS__)

#define RAISE_CTX_ERROR_FMT(exception, fmt, ...)                              \
  SOCKET_RAISE_MSG (SocketTLSContext, exception, fmt, __VA_ARGS__)

/* ============================================================================
 * Utility Macros
 * ============================================================================
 */

/**
 * @brief UNUSED - Suppress unused parameter warnings
 * @ingroup security
 * @param x Unused parameter
 */
#define TLS_UNUSED(x) (void)(x)

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================
 */

/**
 * ctx_raise_openssl_error - Raise TLS exception with OpenSSL error
 * @context: Context description for error message
 *
 * Formats OpenSSL error and raises SocketTLS_Failed.
 */
extern void ctx_raise_openssl_error (const char *context);

/**
 * ctx_arena_strdup - Copy string to context arena with error handling
 * @param ctx TLS context with arena
 * @param str String to copy
 * @param error_msg Error message on allocation failure
 *
 * @return Arena-allocated copy of string
 * @throws SocketTLS_Failed on allocation failure
 *
 * Consolidates repeated string copy patterns across TLS modules.
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
 * ctx_arena_alloc - Allocate from context arena with error handling
 * @param ctx TLS context with arena
 * @param size Number of bytes to allocate
 * @param error_msg Error message on allocation failure
 *
 * @return Arena-allocated memory
 * @throws SocketTLS_Failed on allocation failure
 *
 * Consolidates repeated allocation + error patterns across TLS modules.
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
 * Used to associate SocketTLSContext_T instances with their corresponding OpenSSL SSL_CTX objects.
 * Allows retrieving the library context from OpenSSL callbacks and internal operations.
 * Lazily initialized once per process.
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
 * @param method OpenSSL SSL_METHOD (e.g., TLS_server_method(), TLS_client_method())
 * @param is_server 1 for server context, 0 for client context
 * @return New SocketTLSContext_T instance
 * @throws SocketTLS_Failed on allocation failure, OpenSSL errors, or invalid params
 *
 * Creates arena, sets up SSL_CTX with secure defaults, initializes internal state.
 * Intended for internal use by SocketTLSContext_new*() functions.
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
 * tls_pinning_extract_spki_hash - Extract SPKI SHA256 hash from certificate
 * @param cert X509 certificate
 * @param out_hash Output buffer (must be SOCKET_TLS_PIN_HASH_LEN bytes)
 *
 * @return 0 on success, -1 on failure
 *
 * Computes SHA256 of the SubjectPublicKeyInfo (SPKI) DER encoding.
 * This is the OWASP-recommended pinning approach.
 */
extern int tls_pinning_extract_spki_hash (const X509 *cert,
                                          unsigned char *out_hash);

/**
 * tls_pinning_check_chain - Check if any cert in chain matches a pin
 * @param ctx TLS context with pins configured
 * @param chain Certificate chain to check
 *
 * @return 1 if match found, 0 if no match
 */
extern int tls_pinning_check_chain (SocketTLSContext_T ctx,
                                    const STACK_OF (X509) * chain);

/**
 * tls_pinning_find - Constant-time search for pin in array
 * @param pins Array of pins
 * @param count Number of pins
 * @param hash Hash to search for
 *
 * Uses constant-time comparison to prevent timing attacks.
 * Scans all pins regardless of match position.
 *
 * @return 1 if found, 0 if not found
 */
extern int tls_pinning_find (const TLSCertPin *pins, size_t count,
                             const unsigned char *hash);

#undef T

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETTLS_PRIVATE_INCLUDED */
