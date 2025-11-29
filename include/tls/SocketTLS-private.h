/**
 * SocketTLS-private.h - TLS Internal Shared Definitions
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
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

#ifdef SOCKET_HAS_TLS

#include <ctype.h>
#include <pthread.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "socket/Socket-private.h"
#include "tls/SocketTLS.h"
#include "tls/SocketTLSConfig.h"
#include "tls/SocketTLSContext.h"
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

/* ============================================================================
 * Thread-Local Error Handling for SocketTLS
 * ============================================================================
 */

/**
 * Thread-local error buffer for detailed TLS error messages.
 * Shared across all TLS implementation files.
 */
#ifdef _WIN32
extern __declspec (thread) char tls_error_buf[];
#else
extern __thread char tls_error_buf[];
#endif

/**
 * Thread-local exception copy for detailed TLS error messages.
 * Prevents race conditions when multiple threads raise same exception.
 */
#ifdef _WIN32
extern __declspec (thread) Except_T SocketTLS_DetailedException;
#else
extern __thread Except_T SocketTLS_DetailedException;
#endif

/**
 * RAISE_TLS_ERROR - Raise TLS exception with detailed error message
 * @exception: Exception type to raise
 *
 * Creates thread-local copy of exception with reason from tls_error_buf.
 */
#define RAISE_TLS_ERROR(exception)                                            \
  do                                                                          \
    {                                                                         \
      SocketTLS_DetailedException = (exception);                              \
      SocketTLS_DetailedException.reason = tls_error_buf;                     \
      RAISE (SocketTLS_DetailedException);                                    \
    }                                                                         \
  while (0)

/**
 * RAISE_TLS_ERROR_MSG - Raise TLS exception with specific message
 * @exception: Exception type to raise
 * @msg: Error message string
 */
#define RAISE_TLS_ERROR_MSG(exception, msg)                                   \
  do                                                                          \
    {                                                                         \
      TLS_ERROR_MSG (msg);                                                    \
      RAISE_TLS_ERROR (exception);                                            \
    }                                                                         \
  while (0)

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
#define TLS_ERROR_MSG(msg)                                                    \
  snprintf (tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "%s", (msg))

/**
 * TLS_ERROR_FMT - Format error message with arguments
 * @fmt: Format string
 * @...: Format arguments
 */
#define TLS_ERROR_FMT(fmt, ...)                                               \
  snprintf (tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE, fmt, __VA_ARGS__)

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

    default:
      socket->tls_handshake_done = 0;
      return TLS_HANDSHAKE_ERROR;
    }
}

/**
 * tls_format_openssl_error - Format OpenSSL error into buffer
 * @context: Context string for error message
 *
 * Formats current OpenSSL error into tls_error_buf with context.
 */
static inline void
tls_format_openssl_error (const char *context)
{
  unsigned long err = ERR_get_error ();
  char err_str[SOCKET_TLS_OPENSSL_ERRSTR_BUFSIZE];

  if (err != 0)
    {
      ERR_error_string_n (err, err_str, sizeof (err_str));
      snprintf (tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "%s: %s", context,
                err_str);
    }
  else
    {
      snprintf (tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "%s: Unknown error",
                context);
    }
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
static inline int
tls_validate_file_path (const char *path)
{
  if (!path || !*path)
    return 0;

  size_t len = strlen (path);
  if (len == 0 || len > SOCKET_TLS_MAX_PATH_LEN)
    return 0;

  /* Check for path traversal */
  if (strstr (path, "..") != NULL)
    return 0;

  /* Check for control characters (ASCII 0-31 and 127, except don't allow any)
   * This prevents injection of special chars that might confuse filesystem */
  for (size_t i = 0; i < len; i++)
    {
      unsigned char c = (unsigned char)path[i];
      /* Reject control characters (0-31 and 127) */
      if (c < 32 || c == 127)
        return 0;
    }

  return 1;
}

/**
 * tls_validate_hostname - Validate SNI hostname format
 * @hostname: Hostname string to validate
 *
 * Validates hostname according to DNS rules: labels with alphanum/-,
 * length limits per RFC 6066.
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

  while (*p)
    {
      if (*p == '.')
        {
          if (label_len == 0 || label_len > 63)
            return 0;
          label_len = 0;
        }
      else
        {
          if (!(isalnum ((unsigned char)*p) || *p == '-'))
            return 0;
          if (*p == '-' && label_len == 0)
            return 0;
          label_len++;
          if (label_len > 63)
            return 0;
        }
      p++;
    }

  return (label_len > 0 && label_len <= 63);
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
 * Maintains a sorted array of SPKI SHA256 hashes for O(log n) lookup.
 * For typical deployments (1-5 pins), this is effectively O(1).
 *
 * Thread safety: Configuration is NOT thread-safe - perform before sharing.
 * Verification is read-only post-setup (thread-safe).
 */
typedef struct
{
  TLSCertPin *pins; /* Sorted array of SHA256 hashes (arena-allocated) */
  size_t count;     /* Number of pins */
  size_t capacity;  /* Allocated capacity */
  int enforce;      /* 1 = fail on mismatch, 0 = warn only (default: 1) */
} TLSContextPinning;

/**
 * SNI Certificate Mapping - Stores hostname-to-certificate mappings
 */
typedef struct
{
  char **hostnames;  /* Array of hostname strings */
  char **cert_files; /* Array of certificate file paths */
  char **key_files;  /* Array of private key file paths */
  X509 **certs;      /* Pre-loaded certificate objects */
  EVP_PKEY **pkeys;  /* Pre-loaded private key objects */
  size_t count;      /* Number of certificate mappings */
  size_t capacity;   /* Allocated capacity */
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
  SSL_CTX *ssl_ctx;          /* OpenSSL context */
  Arena_T arena;             /* Arena for allocations */
  int is_server;             /* 1 for server, 0 for client */
  int session_cache_enabled; /* Session cache flag */
  size_t session_cache_size; /* Session cache size */
  size_t cache_hits;         /* Session resumptions (hits) */
  size_t cache_misses;       /* Full handshakes */
  size_t cache_stores;       /* New sessions stored */
  pthread_mutex_t stats_mutex; /* Thread-safe stats update */

  /* Session tickets */
  unsigned char ticket_key[SOCKET_TLS_TICKET_KEY_LEN]; /* Session ticket key */
  int tickets_enabled;          /* 1 if session tickets enabled */

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
};

/* ============================================================================
 * Thread-Local Error Handling for SocketTLSContext
 * ============================================================================
 */

#ifdef _WIN32
extern __declspec (thread) char tls_context_error_buf[SOCKET_TLS_ERROR_BUFSIZE];
extern __declspec (thread) Except_T SocketTLSContext_DetailedException;
#else
extern __thread char tls_context_error_buf[SOCKET_TLS_ERROR_BUFSIZE];
extern __thread Except_T SocketTLSContext_DetailedException;
#endif

/**
 * RAISE_CTX_ERROR - Raise context exception with current error buffer
 */
#define RAISE_CTX_ERROR(exception)                                            \
  do                                                                          \
    {                                                                         \
      SocketTLSContext_DetailedException = (exception);                       \
      SocketTLSContext_DetailedException.reason = tls_context_error_buf;      \
      RAISE (SocketTLSContext_DetailedException);                             \
    }                                                                         \
  while (0)

/**
 * RAISE_CTX_ERROR_MSG - Raise context exception with specific message
 */
#define RAISE_CTX_ERROR_MSG(exception, msg)                                   \
  do                                                                          \
    {                                                                         \
      snprintf (tls_context_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "%s", msg);  \
      SocketTLSContext_DetailedException = (exception);                       \
      SocketTLSContext_DetailedException.reason = tls_context_error_buf;      \
      RAISE (SocketTLSContext_DetailedException);                             \
    }                                                                         \
  while (0)

#define RAISE_CTX_ERROR_FMT(exception, fmt, ...)                              \
  do                                                                          \
    {                                                                         \
      snprintf (tls_context_error_buf, SOCKET_TLS_ERROR_BUFSIZE, fmt,         \
                __VA_ARGS__);                                                 \
      SocketTLSContext_DetailedException = (exception);                       \
      SocketTLSContext_DetailedException.reason = tls_context_error_buf;      \
      RAISE (SocketTLSContext_DetailedException);                             \
    }                                                                         \
  while (0)

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
extern int tls_pinning_extract_spki_hash (X509 *cert, unsigned char *out_hash);

/**
 * tls_pinning_check_chain - Check if any cert in chain matches a pin
 * @ctx: TLS context with pins configured
 * @chain: Certificate chain to check
 *
 * Returns: 1 if match found, 0 if no match
 */
extern int tls_pinning_check_chain (SocketTLSContext_T ctx,
                                    STACK_OF (X509) * chain);

/**
 * tls_pinning_find - Binary search for pin in sorted array
 * @pins: Sorted array of pins
 * @count: Number of pins
 * @hash: Hash to search for
 *
 * Returns: 1 if found, 0 if not found
 */
extern int tls_pinning_find (const TLSCertPin *pins, size_t count,
                             const unsigned char *hash);

#undef T

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETTLS_PRIVATE_INCLUDED */
