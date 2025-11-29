/**
 * fuzz_dtls_cookie.c - Fuzzer for DTLS cookie operations
 *
 * Tests DTLS cookie exchange functionality:
 * - Cookie secret configuration
 * - Cookie secret rotation
 * - Cookie exchange enable/disable
 *
 * NOTE: Avoids nested TRY/EXCEPT to prevent stack-use-after-scope with ASan.
 */

#ifdef SOCKET_HAS_TLS

#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/Except.h"

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

/* Helper to generate test certs */
static int
generate_temp_certs (char *cert_path, char *key_path)
{
  snprintf (cert_path, 256, "/tmp/fuzz_dtls_cert_%d.pem", getpid ());
  snprintf (key_path, 256, "/tmp/fuzz_dtls_key_%d.pem", getpid ());

  char cmd[512];
  snprintf (cmd, sizeof (cmd),
            "openssl genrsa -out %s 2048 2>/dev/null && "
            "openssl req -new -x509 -key %s -out %s -days 1 -nodes "
            "-subj '/CN=fuzz' 2>/dev/null",
            key_path, key_path, cert_path);

  return system (cmd);
}

static void
cleanup_certs (const char *cert_path, const char *key_path)
{
  unlink (cert_path);
  unlink (key_path);
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

  volatile uint8_t op = get_op (data, size);
  SocketDTLSContext_T ctx = NULL;
  char cert_path[256], key_path[256];
  int have_certs = 0;

  /* Generate test certificates for server context */
  if (generate_temp_certs (cert_path, key_path) == 0)
    have_certs = 1;

  if (!have_certs)
    return 0; /* Skip if can't generate certs */

  /* Single TRY block - no nesting */
  TRY
  {
    switch (op)
      {
      case OP_ENABLE_COOKIE:
        ctx = SocketDTLSContext_new_server (cert_path, key_path, NULL);
        SocketDTLSContext_enable_cookie_exchange (ctx);
        if (SocketDTLSContext_has_cookie_exchange (ctx) != 1)
          abort ();
        break;

      case OP_SET_SECRET:
        ctx = SocketDTLSContext_new_server (cert_path, key_path, NULL);
        SocketDTLSContext_enable_cookie_exchange (ctx);
        if (size >= SOCKET_DTLS_COOKIE_SECRET_LEN + 1)
          {
            SocketDTLSContext_set_cookie_secret (
                ctx, data + 1, SOCKET_DTLS_COOKIE_SECRET_LEN);
          }
        break;

      case OP_ROTATE_SECRET:
        ctx = SocketDTLSContext_new_server (cert_path, key_path, NULL);
        SocketDTLSContext_enable_cookie_exchange (ctx);
        SocketDTLSContext_rotate_cookie_secret (ctx);
        break;

      case OP_HAS_COOKIE:
        ctx = SocketDTLSContext_new_server (cert_path, key_path, NULL);
        /* Should be disabled initially */
        if (SocketDTLSContext_has_cookie_exchange (ctx) != 0)
          abort ();
        SocketDTLSContext_enable_cookie_exchange (ctx);
        if (SocketDTLSContext_has_cookie_exchange (ctx) != 1)
          abort ();
        break;

      case OP_MULTIPLE_ROTATIONS:
        ctx = SocketDTLSContext_new_server (cert_path, key_path, NULL);
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
  if (have_certs)
    cleanup_certs (cert_path, key_path);

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

