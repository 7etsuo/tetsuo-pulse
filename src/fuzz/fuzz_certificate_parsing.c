/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_certificate_parsing.c - Fuzzer for X509 Certificate Parsing
 *
 * Part of the Socket Library Fuzzing Suite (Section 8.3)
 *
 * Targets:
 * - Certificate file loading
 * - Certificate chain parsing
 * - Certificate info extraction
 * - SPKI hash computation
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_certificate_parsing
 * Run:   ./fuzz_certificate_parsing corpus/certs/ -fork=16 -max_len=65536
 */

#if SOCKET_HAS_TLS

#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core/Except.h"
#include "tls/SocketTLSConfig.h"
#include "tls/SocketTLSContext.h"

#include <openssl/pem.h>
#include <openssl/x509.h>

/* Ignore SIGPIPE */
__attribute__ ((constructor)) static void
ignore_sigpipe (void)
{
  signal (SIGPIPE, SIG_IGN);
}

/* Suppress GCC clobbered warnings */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/* Operation types */
typedef enum
{
  OP_PARSE_DER = 0,
  OP_PARSE_PEM,
  OP_EXTRACT_INFO,
  OP_COMPUTE_SPKI_HASH,
  OP_VERIFY_CHAIN,
  OP_LOAD_CA,
  OP_ADD_PIN_FROM_DATA,
  OP_COUNT
} CertOp;

static uint8_t
get_op (const uint8_t *data, size_t size)
{
  return size > 0 ? data[0] % OP_COUNT : 0;
}

/* Helper to write fuzz data to temp file */
static int
write_temp_cert (const uint8_t *data, size_t size, char *path, size_t path_len)
{
  snprintf (path, path_len, "/tmp/fuzz_cert_XXXXXX");
  int fd = mkstemp (path);
  if (fd < 0)
    return -1;

  ssize_t written = write (fd, data, size);
  close (fd);

  if ((size_t)written != size)
    {
      unlink (path);
      return -1;
    }

  return 0;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 2)
    return 0;

  /* Limit input size to prevent OOM */
  if (size > 64 * 1024)
    return 0;

  volatile uint8_t op = get_op (data, size);
  const uint8_t *cert_data = data + 1;
  size_t cert_size = size - 1;

  SocketTLSContext_T ctx = NULL;
  char temp_path[256] = {0};

  TRY
  {
    switch (op)
      {
      case OP_PARSE_DER:
        {
          /* Try to parse as DER certificate */
          const unsigned char *p = cert_data;
          X509 *cert = d2i_X509 (NULL, &p, (long)cert_size);
          if (cert)
            {
              /* Extract some info to exercise parsing */
              (void)X509_get_subject_name (cert);
              (void)X509_get_issuer_name (cert);
              (void)X509_get_notAfter (cert);
              (void)X509_get_notBefore (cert);
              X509_free (cert);
            }
        }
        break;

      case OP_PARSE_PEM:
        {
          /* Try to parse as PEM certificate via temp file */
          if (write_temp_cert (cert_data, cert_size, temp_path,
                               sizeof (temp_path))
              == 0)
            {
              FILE *fp = fopen (temp_path, "r");
              if (fp)
                {
                  X509 *cert = PEM_read_X509 (fp, NULL, NULL, NULL);
                  fclose (fp);
                  if (cert)
                    X509_free (cert);
                }
              unlink (temp_path);
              temp_path[0] = '\0';
            }
        }
        break;

      case OP_EXTRACT_INFO:
        {
          /* Parse and extract detailed info */
          const unsigned char *p = cert_data;
          X509 *cert = d2i_X509 (NULL, &p, (long)cert_size);
          if (cert)
            {
              char buf[256];

              /* Subject */
              X509_NAME *subject = X509_get_subject_name (cert);
              if (subject)
                X509_NAME_oneline (subject, buf, sizeof (buf));

              /* Issuer */
              X509_NAME *issuer = X509_get_issuer_name (cert);
              if (issuer)
                X509_NAME_oneline (issuer, buf, sizeof (buf));

              /* Serial */
              ASN1_INTEGER *serial = X509_get_serialNumber (cert);
              if (serial)
                {
                  BIGNUM *bn = ASN1_INTEGER_to_BN (serial, NULL);
                  if (bn)
                    BN_free (bn);
                }

              /* Version */
              (void)X509_get_version (cert);

              X509_free (cert);
            }
        }
        break;

      case OP_COMPUTE_SPKI_HASH:
        {
          /* Parse cert and compute SPKI hash */
          const unsigned char *p = cert_data;
          X509 *cert = d2i_X509 (NULL, &p, (long)cert_size);
          if (cert)
            {
              X509_PUBKEY *pubkey = X509_get_X509_PUBKEY (cert);
              if (pubkey)
                {
                  unsigned char *spki_der = NULL;
                  int spki_len = i2d_X509_PUBKEY (pubkey, &spki_der);
                  if (spki_len > 0 && spki_der)
                    {
                      unsigned char hash[32];
                      SHA256 (spki_der, (size_t)spki_len, hash);
                      OPENSSL_free (spki_der);
                    }
                }
              X509_free (cert);
            }
        }
        break;

      case OP_VERIFY_CHAIN:
        {
          /* Create context and try to verify */
          ctx = SocketTLSContext_new_client (NULL);
          if (ctx)
            {
              /* Try adding as CA */
              if (write_temp_cert (cert_data, cert_size, temp_path,
                                   sizeof (temp_path))
                  == 0)
                {
                  TRY { SocketTLSContext_load_ca (ctx, temp_path); }
                  EXCEPT (SocketTLS_Failed) { /* Expected for invalid cert */ }
                  END_TRY;
                  unlink (temp_path);
                  temp_path[0] = '\0';
                }
            }
        }
        break;

      case OP_LOAD_CA:
        {
          /* Try loading as CA file */
          ctx = SocketTLSContext_new_client (NULL);
          if (ctx)
            {
              if (write_temp_cert (cert_data, cert_size, temp_path,
                                   sizeof (temp_path))
                  == 0)
                {
                  TRY { SocketTLSContext_load_ca (ctx, temp_path); }
                  EXCEPT (SocketTLS_Failed) {}
                  END_TRY;
                  unlink (temp_path);
                  temp_path[0] = '\0';
                }
            }
        }
        break;

      case OP_ADD_PIN_FROM_DATA:
        {
          /* Try adding pin from cert file */
          ctx = SocketTLSContext_new_client (NULL);
          if (ctx)
            {
              if (write_temp_cert (cert_data, cert_size, temp_path,
                                   sizeof (temp_path))
                  == 0)
                {
                  TRY { SocketTLSContext_add_pin_from_cert (ctx, temp_path); }
                  EXCEPT (SocketTLS_Failed) {}
                  END_TRY;
                  unlink (temp_path);
                  temp_path[0] = '\0';
                }
            }
        }
        break;
      }
  }
  EXCEPT (SocketTLS_Failed) {}
  ELSE {}
  END_TRY;

  if (ctx)
    SocketTLSContext_free (&ctx);

  if (temp_path[0])
    unlink (temp_path);

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
