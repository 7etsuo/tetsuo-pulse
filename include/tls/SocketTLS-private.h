/**
 * SocketTLS-private.h - TLS Internal Shared Definitions
 *
 * Part of the Socket Library
 *
 * Internal header for all TLS module implementation files. Contains shared
 * helper function declarations, error handling macros, internal types,
 * and the SocketTLSContext_T structure definition.
 * NOT part of public API - do not include from application code.
 *
 * Thread safety: Internal functions are not thread-safe unless noted.
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
 * Thread-local error buffer for detailed TLS error messages.
 * Shared across all TLS implementation files.
 */
/**
 * Thread-local exception copy for detailed TLS error messages.
 * Prevents race conditions when multiple threads raise same exception.
 */

/**
 * RAISE_TLS_ERROR - Raise TLS exception with detailed error message
 * @exception: Exception type to raise
 *
 * Creates thread-local copy of exception with reason from tls_error_buf.
 */
#define RAISE_TLS_ERROR(exception)                                            \
  SOCKET_RAISE_MODULE_ERROR (SocketTLS, exception)

/**
 * RAISE_TLS_ERROR_MSG - Raise TLS exception with specific message
 * @exception: Exception type to raise
 * @msg: Error message string
 */
#define RAISE_TLS_ERROR_MSG(exception, fmt, ...)                              \
  SOCKET_RAISE_MSG (SocketTLS, exception, fmt, ##__VA_ARGS__)

/**
 * REQUIRE_TLS_ENABLED - Validate TLS is enabled on socket
 * @socket: Socket to validate
 * @exception: Exception to raise on failure
 */
#define REQUIRE_TLS_ENABLED(socket, exception)                                \
  do                                                                          \
    {                                                                         \
      if (!(socket)->tls_enabled)                                             \
        RAISE_TLS_ERROR_MSG (exception, "TLS not enabled on socket");         \
    }                                                                         \
  while (0)

/**
 * TLS_ERROR_MSG - Format simple error message
 * @msg: Message string
 */
#define TLS_ERROR_MSG(msg) SOCKET_ERROR_MSG ("%s", msg)

/**
 * TLS_ERROR_FMT - Format error message with arguments
 * @fmt: Format string
 * @...: Format arguments
 */
#define TLS_ERROR_FMT(fmt, ...) SOCKET_ERROR_MSG (fmt, __VA_ARGS__)

/**
 * VALIDATE_TLS_IO_READY - Validate socket is ready for TLS I/O
 * @socket: Socket to validate
 * @exception: Exception to raise on failure
 *
 * Checks tls_enabled, handshake_done, and SSL object availability.
 * Returns SSL* on success, raises exception on failure.
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
 * tls_socket_get_ssl - Get SSL* from socket
 * @socket: Socket instance
 *
 * Returns: SSL* pointer or NULL if TLS not enabled/available
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
 * tls_handle_ssl_error - Map OpenSSL errors to TLSHandshakeState
 * @socket: Socket instance
 * @ssl: SSL object
 * @ssl_result: Result from SSL operation
 *
 * Returns: TLSHandshakeState based on error type
 *
 * Sets errno to EAGAIN for WANT_READ/WRITE cases.
 * Preserves errno from SSL_ERROR_SYSCALL for diagnostics.
 *
 * Error type handling:
 * - SSL_ERROR_SYSCALL: System call error (check errno for details)
 * - SSL_ERROR_SSL: Protocol error (check ERR_get_error() for details)
 * - SSL_ERROR_ZERO_RETURN: Clean shutdown by peer
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
 * @context: Context string for error message
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
 * tls_validate_file_path - Validate certificate/key/CA file path
 * @path: File path string to validate
 *
 * Performs security checks:
 * - Non-empty and within length limits
 * - No path traversal sequences (..)
 * - No control characters (except forward slash)
 * - Path must be absolute or relative from current dir
 *
 * Returns: 1 if valid, 0 if invalid
 */

/* ============================================================================
 * ALPN Temp Buffer Management (for UAF fix in selection callback)
 * ============================================================================
 */
/**
 * tls_get_alpn_ex_idx - Get ex_data index for ALPN temp buffers
 *
 * Lazy initialization of SSL ex_data index for storing temp ALPN copies.
 * Called once per process.
 *
 * Returns: Valid ex_data index
 */
extern int tls_get_alpn_ex_idx (void);

/**
 * tls_cleanup_alpn_temp - Free ALPN temp buffer from SSL ex_data
 * @ssl: SSL object to cleanup
 *
 * Frees the temporary ALPN protocol copy stored in ex_data (if any)
 * and clears the slot. Call before SSL_free(ssl).
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
 * tls_secure_free_pkey - Securely free EVP_PKEY with best-effort key material
 * clearing
 * @pkey: Pointer to private key to free (may be NULL)
 *
 * Exports key to DER format, securely clears the exported buffer, then frees
 * the original PKEY. Mitigates memory disclosure of private keys in process
 * memory. Limitation: Original PKEY struct fields may not be fully zeroed
 * (OpenSSL internal).
 *
 * Requires: OpenSSL EVP functions.
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
 * tls_validate_hostname - Validate SNI hostname format
 * @hostname: Hostname string to validate
 *
 * Validates hostname according to DNS rules (RFC 952, RFC 1123):
 * - Labels contain only alphanumeric characters and hyphens
 * - Labels cannot start or end with a hyphen
 * - Labels are 1-63 characters
 * - Total length within RFC 6066 SNI limits
 *
 * Returns: 1 if valid, 0 if invalid
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
 * TLSCertPin - Single certificate pin entry (SPKI SHA256 hash)
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
 * TLSContextPinning - Certificate pinning configuration
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
      * *chains; /* Pre-loaded certificate chains for each entry (sk_X509 owns
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
 * SocketTLSContext_T - TLS Context Structure
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
 * RAISE_CTX_ERROR - Raise context exception with current error buffer
 */

#define RAISE_CTX_ERROR(exception)                                            \
  SOCKET_RAISE_MODULE_ERROR (SocketTLSContext, exception)

/**
 * RAISE_CTX_ERROR_MSG - Raise context exception with specific message
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
 * UNUSED - Suppress unused parameter warnings
 * @x: Unused parameter
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
 * @ctx: TLS context with arena
 * @str: String to copy
 * @error_msg: Error message on allocation failure
 *
 * Returns: Arena-allocated copy of string
 * Raises: SocketTLS_Failed on allocation failure
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
 * @ctx: TLS context with arena
 * @size: Number of bytes to allocate
 * @error_msg: Error message on allocation failure
 *
 * Returns: Arena-allocated memory
 * Raises: SocketTLS_Failed on allocation failure
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
 * tls_context_exdata_idx - Global SSL_CTX ex_data index for context lookup
 */
extern int tls_context_exdata_idx;

/**
 * tls_context_get_from_ssl - Get SocketTLSContext from SSL object
 * @ssl: SSL object
 *
 * Returns: Context pointer or NULL
 */
extern SocketTLSContext_T tls_context_get_from_ssl (const SSL *ssl);

/**
 * tls_context_get_from_ssl_ctx - Get SocketTLSContext from SSL_CTX
 * @ssl_ctx: OpenSSL context
 *
 * Returns: Context pointer or NULL
 */
extern SocketTLSContext_T tls_context_get_from_ssl_ctx (SSL_CTX *ssl_ctx);

/**
 * ctx_alloc_and_init - Create and initialize TLS context
 * @method: OpenSSL method (server or client)
 * @is_server: 1 for server, 0 for client
 *
 * Returns: New initialized context
 * Raises: SocketTLS_Failed on any failure
 */
extern SocketTLSContext_T ctx_alloc_and_init (const SSL_METHOD *method,
                                              int is_server);

/* ============================================================================
 * Certificate Pinning Internal Functions
 * ============================================================================
 */

/**
 * tls_pinning_init - Initialize pinning structure
 * @pinning: Pinning structure to initialize
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
 * @cert: X509 certificate
 * @out_hash: Output buffer (must be SOCKET_TLS_PIN_HASH_LEN bytes)
 *
 * Returns: 0 on success, -1 on failure
 *
 * Computes SHA256 of the SubjectPublicKeyInfo (SPKI) DER encoding.
 * This is the OWASP-recommended pinning approach.
 */
extern int tls_pinning_extract_spki_hash (const X509 *cert,
                                          unsigned char *out_hash);

/**
 * tls_pinning_check_chain - Check if any cert in chain matches a pin
 * @ctx: TLS context with pins configured
 * @chain: Certificate chain to check
 *
 * Returns: 1 if match found, 0 if no match
 */
extern int tls_pinning_check_chain (SocketTLSContext_T ctx,
                                    const STACK_OF (X509) * chain);

/**
 * tls_pinning_find - Constant-time search for pin in array
 * @pins: Array of pins
 * @count: Number of pins
 * @hash: Hash to search for
 *
 * Uses constant-time comparison to prevent timing attacks.
 * Scans all pins regardless of match position.
 *
 * Returns: 1 if found, 0 if not found
 */
extern int tls_pinning_find (const TLSCertPin *pins, size_t count,
                             const unsigned char *hash);

#undef T

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETTLS_PRIVATE_INCLUDED */
