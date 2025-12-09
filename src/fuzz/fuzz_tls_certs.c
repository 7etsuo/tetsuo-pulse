/**
 * fuzz_tls_certs.c - Fuzzer for TLS Certificate/Key PEM Parsing
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - PEM_read_bio_X509() - Certificate parsing
 * - PEM_read_bio_PrivateKey() - Private key parsing
 * - PEM_read_bio_X509_AUX() - Certificate chain parsing
 * - tls_validate_file_path() - Path validation
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON -DENABLE_TLS=ON && make
 * fuzz_tls_certs Run:   ./fuzz_tls_certs corpus/tls_certs/ -fork=16
 * -max_len=65536
 */

#if SOCKET_HAS_TLS

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "tls/SocketTLSContext.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

/* Operation codes */
enum CertOp
{
  CERT_PARSE_X509 = 0,
  CERT_PARSE_PRIVKEY,
  CERT_PARSE_CHAIN,
  CERT_VALIDATE_PATH,
  CERT_PARSE_X509_REQ,
  CERT_OP_COUNT
};

/* Maximum path length for validation testing */
#define MAX_TEST_PATH_LEN 4096

/**
 * tls_validate_file_path_fuzz - Local copy of path validation logic
 * @path: File path string to validate
 *
 * Validates path for security issues:
 * - Non-empty and within length limits
 * - No path traversal sequences (..)
 * - No control characters
 *
 * Returns: 1 if valid, 0 if invalid
 */
static int
tls_validate_file_path_fuzz (const char *path)
{
  if (!path || !*path)
    return 0;

  size_t len = strlen (path);
  if (len == 0 || len > MAX_TEST_PATH_LEN)
    return 0;

  /* Check for path traversal */
  if (strstr (path, "..") != NULL)
    return 0;

  /* Check for control characters */
  for (size_t i = 0; i < len; i++)
    {
      unsigned char c = (unsigned char)path[i];
      if (c < 32 || c == 127)
        return 0;
    }

  return 1;
}

/**
 * fuzz_parse_x509 - Parse fuzz data as X509 certificate
 * @data: PEM data
 * @size: Data size
 *
 * Returns: 1 if parsed successfully, 0 otherwise
 */
static int
fuzz_parse_x509 (const uint8_t *data, size_t size)
{
  BIO *bio = BIO_new_mem_buf (data, (int)size);
  if (!bio)
    return 0;

  X509 *cert = PEM_read_bio_X509 (bio, NULL, NULL, NULL);
  BIO_free (bio);

  if (cert)
    {
      /* Exercise some certificate accessors to catch memory issues */
      (void)X509_get_subject_name (cert);
      (void)X509_get_issuer_name (cert);
      (void)X509_get_serialNumber (cert);
      X509_free (cert);
      return 1;
    }

  return 0;
}

/**
 * fuzz_parse_privkey - Parse fuzz data as private key
 * @data: PEM data
 * @size: Data size
 *
 * Returns: 1 if parsed successfully, 0 otherwise
 */
static int
fuzz_parse_privkey (const uint8_t *data, size_t size)
{
  BIO *bio = BIO_new_mem_buf (data, (int)size);
  if (!bio)
    return 0;

  /* Try parsing with NULL password callback */
  EVP_PKEY *pkey = PEM_read_bio_PrivateKey (bio, NULL, NULL, NULL);
  BIO_free (bio);

  if (pkey)
    {
      /* Exercise key accessors */
      (void)EVP_PKEY_id (pkey);
      (void)EVP_PKEY_bits (pkey);
      EVP_PKEY_free (pkey);
      return 1;
    }

  return 0;
}

/**
 * fuzz_parse_chain - Parse fuzz data as certificate chain
 * @data: PEM data (may contain multiple certificates)
 * @size: Data size
 *
 * Returns: Number of certificates parsed
 */
static int
fuzz_parse_chain (const uint8_t *data, size_t size)
{
  BIO *bio = BIO_new_mem_buf (data, (int)size);
  if (!bio)
    return 0;

  int count = 0;
  X509 *cert;

  /* Read all certificates in the chain */
  while ((cert = PEM_read_bio_X509 (bio, NULL, NULL, NULL)) != NULL)
    {
      count++;
      X509_free (cert);

      /* Limit to prevent infinite loops on malformed data */
      if (count >= 100)
        break;
    }

  BIO_free (bio);
  return count;
}

/**
 * fuzz_parse_x509_req - Parse fuzz data as X509 certificate request (CSR)
 * @data: PEM data
 * @size: Data size
 *
 * Returns: 1 if parsed successfully, 0 otherwise
 */
static int
fuzz_parse_x509_req (const uint8_t *data, size_t size)
{
  BIO *bio = BIO_new_mem_buf (data, (int)size);
  if (!bio)
    return 0;

  X509_REQ *req = PEM_read_bio_X509_REQ (bio, NULL, NULL, NULL);
  BIO_free (bio);

  if (req)
    {
      /* Exercise CSR accessors */
      (void)X509_REQ_get_subject_name (req);
      X509_REQ_free (req);
      return 1;
    }

  return 0;
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 *
 * Input format:
 * - Byte 0: Operation selector
 * - Remaining: PEM data or path string
 *
 * Tests PEM parsing without actual file I/O.
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 2)
    return 0;

  uint8_t op = data[0];
  const uint8_t *pem_data = data + 1;
  size_t pem_size = size - 1;

  /* Clear any stale OpenSSL errors */
  ERR_clear_error ();

  switch (op % CERT_OP_COUNT)
    {
    case CERT_PARSE_X509:
      fuzz_parse_x509 (pem_data, pem_size);
      break;

    case CERT_PARSE_PRIVKEY:
      fuzz_parse_privkey (pem_data, pem_size);
      break;

    case CERT_PARSE_CHAIN:
      fuzz_parse_chain (pem_data, pem_size);
      break;

    case CERT_VALIDATE_PATH:
      {
        /* Null-terminate the path string safely */
        size_t path_len
            = pem_size < MAX_TEST_PATH_LEN ? pem_size : MAX_TEST_PATH_LEN - 1;
        char path_buf[MAX_TEST_PATH_LEN];
        memcpy (path_buf, pem_data, path_len);
        path_buf[path_len] = '\0';

        /* Test path validation */
        (void)tls_validate_file_path_fuzz (path_buf);
      }
      break;

    case CERT_PARSE_X509_REQ:
      fuzz_parse_x509_req (pem_data, pem_size);
      break;
    }

  /* Fuzz TLS context creation with generated malformed paths (tests path
   * validation, new_server error paths) */
  if (size > 64)
    { /* Enough data for plausible paths */
      const uint8_t *path_data
          = data + (size / 3); /* Offset to avoid overlapping PEM data */
      size_t path_size = size / 3;
      char cert_path[512] = { 0 };
      size_t cert_len = (path_size > 500) ? 500 : path_size;
      memcpy (cert_path, path_data, cert_len);
      cert_path[cert_len] = '\0';

      char key_path[512] = { 0 };
      size_t key_len = (path_size / 2 > 500) ? 500 : (path_size / 2);
      memcpy (key_path, path_data + (path_size / 2), key_len);
      key_path[key_len] = '\0';

      TRY
      {
        SocketTLSContext_T ctx
            = SocketTLSContext_new_server (cert_path, key_path, NULL);
        /* If succeeds (unlikely), free */
        SocketTLSContext_free (&ctx);
      }
      EXCEPT (SocketTLS_Failed)
      {
        /* Expected: malformed paths/files trigger validation/load errors
         * without crash */
      }
      END_TRY;
    }

  /* Clear errors generated during parsing and context fuzz */
  ERR_clear_error ();

  return 0;
}

#else /* !SOCKET_HAS_TLS */

/* Stub for non-TLS builds */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  (void)data;
  (void)size;
  return 0;
}

#endif /* SOCKET_HAS_TLS */
