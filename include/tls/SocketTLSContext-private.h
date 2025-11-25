/**
 * SocketTLSContext-private.h - TLS Context Internal Definitions
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Internal header shared between SocketTLSContext-*.c implementation files.
 * Contains the context structure definition and shared helper declarations.
 * NOT part of public API.
 *
 * Thread safety: Internal functions are not thread-safe unless noted.
 */

#ifndef SOCKETTLSCONTEXT_PRIVATE_INCLUDED
#define SOCKETTLSCONTEXT_PRIVATE_INCLUDED

#ifdef SOCKET_HAS_TLS

#include "core/Arena.h"
#include "tls/SocketTLS-private.h"
#include "tls/SocketTLSContext.h"
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <pthread.h>

#define T SocketTLSContext_T

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
};

/* ============================================================================
 * Thread-Local Error Handling (Context-specific)
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
 * RAISE_CTX_ERROR - Raise context exception with message
 */
#define RAISE_CTX_ERROR(exception)                                            \
  do                                                                          \
    {                                                                         \
      tls_context_error_buf[0] = '\0';                                        \
      SocketTLSContext_DetailedException = (exception);                       \
      SocketTLSContext_DetailedException.reason = tls_context_error_buf;      \
      RAISE (SocketTLSContext_DetailedException);                             \
    }                                                                         \
  while (0)

#define RAISE_CTX_ERROR_MSG(exception, msg)                                   \
  do                                                                          \
    {                                                                         \
      strncpy (tls_context_error_buf, msg, SOCKET_TLS_ERROR_BUFSIZE - 1);     \
      tls_context_error_buf[SOCKET_TLS_ERROR_BUFSIZE - 1] = '\0';             \
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
 * ctx_exdata_idx - Global SSL_CTX ex_data index for context lookup
 */
extern int tls_context_exdata_idx;

#undef T

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETTLSCONTEXT_PRIVATE_INCLUDED */

