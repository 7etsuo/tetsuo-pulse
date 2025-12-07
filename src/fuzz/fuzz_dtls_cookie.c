/**
 * fuzz_dtls_cookie.c - Fuzzer for DTLS cookie operations
 *
 * Tests DTLS cookie exchange functionality:
 * - Cookie secret configuration
 * - Cookie secret rotation
 * - Cookie exchange enable/disable
 *
 * NOTE: Avoids nested TRY/EXCEPT to prevent stack-use-after-scope with ASan.
 * Uses embedded test certificates for maximum fuzzing speed.
 */

#if SOCKET_HAS_TLS

#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "core/Except.h"
#include "fuzz_test_certs.h"

/* Ignore SIGPIPE */
__attribute__ ((constructor)) static void
ignore_sigpipe (void)
{
  signal (SIGPIPE, SIG_IGN);
}

#include "tls/SocketDTLS.h"
#include "tls/SocketDTLSConfig.h"
#include "tls/SocketDTLSContext.h"

/* Suppress GCC clobbered warnings */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/* Paths for temp cert files (written once at startup) */
static char g_cert_path[64];
static char g_key_path[64];
static int g_certs_ready = 0;

/**
 * Write embedded certs to temp files (once at startup)
 *
 * SocketDTLSContext_new_server() expects file paths, so we write
 * the embedded certs to temp files once. This is still much faster
 * than generating certs per-iteration.
 */
__attribute__ ((constructor)) static void
setup_test_certs (void)
{
  FILE *f;

  snprintf (g_cert_path, sizeof (g_cert_path), "/tmp/fuzz_dtls_cert_%d.pem",
            getpid ());
  snprintf (g_key_path, sizeof (g_key_path), "/tmp/fuzz_dtls_key_%d.pem",
            getpid ());

  /* Write certificate */
  f = fopen (g_cert_path, "w");
  if (f)
    {
      fputs (FUZZ_TEST_CERT, f);
      fclose (f);
    }
  else
    {
      return;
    }

  /* Write private key */
  f = fopen (g_key_path, "w");
  if (f)
    {
      fputs (FUZZ_TEST_KEY, f);
      fclose (f);
      g_certs_ready = 1;
    }
  else
    {
      unlink (g_cert_path);
    }
}

__attribute__ ((destructor)) static void
cleanup_test_certs (void)
{
  if (g_certs_ready)
    {
      unlink (g_cert_path);
      unlink (g_key_path);
    }
}

/* Operation types */
typedef enum
{
  OP_ENABLE_COOKIE = 0,
  OP_SET_SECRET,
  OP_ROTATE_SECRET,
  OP_HAS_COOKIE,
  OP_MULTIPLE_ROTATIONS
} DTLSCookieOp;

static uint8_t
get_op (const uint8_t *data, size_t size)
{
  return size > 0 ? data[0] % 5 : 0;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 2)
    return 0;

  if (!g_certs_ready)
    return 0; /* Skip if certs not available */

  volatile uint8_t op = get_op (data, size);
  SocketDTLSContext_T ctx = NULL;

  /* Single TRY block - no nesting */
  TRY
  {
    switch (op)
      {
      case OP_ENABLE_COOKIE:
        ctx = SocketDTLSContext_new_server (g_cert_path, g_key_path, NULL);
        SocketDTLSContext_enable_cookie_exchange (ctx);
        if (SocketDTLSContext_has_cookie_exchange (ctx) != 1)
          abort ();
        break;

      case OP_SET_SECRET:
        ctx = SocketDTLSContext_new_server (g_cert_path, g_key_path, NULL);
        SocketDTLSContext_enable_cookie_exchange (ctx);
        if (size >= SOCKET_DTLS_COOKIE_SECRET_LEN + 1)
          {
            SocketDTLSContext_set_cookie_secret (
                ctx, data + 1, SOCKET_DTLS_COOKIE_SECRET_LEN);
          }
        break;

      case OP_ROTATE_SECRET:
        ctx = SocketDTLSContext_new_server (g_cert_path, g_key_path, NULL);
        SocketDTLSContext_enable_cookie_exchange (ctx);
        SocketDTLSContext_rotate_cookie_secret (ctx);
        break;

      case OP_HAS_COOKIE:
        ctx = SocketDTLSContext_new_server (g_cert_path, g_key_path, NULL);
        /* Should be disabled initially */
        if (SocketDTLSContext_has_cookie_exchange (ctx) != 0)
          abort ();
        SocketDTLSContext_enable_cookie_exchange (ctx);
        if (SocketDTLSContext_has_cookie_exchange (ctx) != 1)
          abort ();
        break;

      case OP_MULTIPLE_ROTATIONS:
        ctx = SocketDTLSContext_new_server (g_cert_path, g_key_path, NULL);
        SocketDTLSContext_enable_cookie_exchange (ctx);
        /* Stress test rotations */
        for (int i = 0; i < 10; i++)
          {
            SocketDTLSContext_rotate_cookie_secret (ctx);
          }
        break;

      default:
        break;
      }
  }
  EXCEPT (SocketDTLS_Failed) { }
  EXCEPT (SocketDTLS_CookieFailed) { }
  ELSE { }
  END_TRY;

  /* Cleanup */
  if (ctx)
    SocketDTLSContext_free (&ctx);

  return 0;
}

#else /* !SOCKET_HAS_TLS */

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  (void)data;
  (void)size;
  return 0;
}

#endif /* SOCKET_HAS_TLS */
