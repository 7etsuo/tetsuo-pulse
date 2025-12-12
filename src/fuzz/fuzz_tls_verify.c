/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_tls_verify.c - Fuzzer for TLS Verification/Revocation Parsing
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - d2i_OCSP_RESPONSE() - OCSP response DER parsing
 * - d2i_X509_CRL() - CRL DER parsing
 * - OCSP_response_status() - Response status validation
 * - OCSP_response_get1_basic() - Basic response extraction
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON -DENABLE_TLS=ON && make
 * fuzz_tls_verify Run:   ./fuzz_tls_verify corpus/tls_verify/ -fork=16
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
#include <openssl/ocsp.h>
#include <openssl/x509.h>

/* Operation codes */
enum VerifyOp
{
  VERIFY_OCSP_RESPONSE = 0,
  VERIFY_CRL,
  VERIFY_OCSP_BASIC,
  VERIFY_CRL_ISSUER,
  VERIFY_OP_COUNT
};

/* Maximum OCSP response size (matches library limit) */
#ifndef SOCKET_TLS_MAX_OCSP_RESPONSE_LEN
#define SOCKET_TLS_MAX_OCSP_RESPONSE_LEN (1024 * 1024)
#endif

/**
 * read_u32 - Read a 32-bit value from byte stream (little-endian)
 */
static uint32_t
read_u32 (const uint8_t *p)
{
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

/**
 * fuzz_parse_ocsp_response - Parse fuzz data as OCSP response
 * @data: DER-encoded data
 * @size: Data size
 *
 * Returns: OCSP response status or -1 on parse failure
 */
static int
fuzz_parse_ocsp_response (const uint8_t *data, size_t size)
{
  /* Enforce size limit as library does */
  if (size > SOCKET_TLS_MAX_OCSP_RESPONSE_LEN)
    return -1;

  const unsigned char *p = data;
  OCSP_RESPONSE *resp = d2i_OCSP_RESPONSE (NULL, &p, (long)size);

  if (!resp)
    return -1;

  int status = OCSP_response_status (resp);
  OCSP_RESPONSE_free (resp);

  return status;
}

/**
 * fuzz_parse_ocsp_basic - Parse OCSP response and extract basic response
 * @data: DER-encoded data
 * @size: Data size
 *
 * Returns: 1 if basic response extracted, 0 otherwise
 */
static int
fuzz_parse_ocsp_basic (const uint8_t *data, size_t size)
{
  if (size > SOCKET_TLS_MAX_OCSP_RESPONSE_LEN)
    return 0;

  const unsigned char *p = data;
  OCSP_RESPONSE *resp = d2i_OCSP_RESPONSE (NULL, &p, (long)size);

  if (!resp)
    return 0;

  int status = OCSP_response_status (resp);
  if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL)
    {
      OCSP_RESPONSE_free (resp);
      return 0;
    }

  OCSP_BASICRESP *basic = OCSP_response_get1_basic (resp);
  OCSP_RESPONSE_free (resp);

  if (!basic)
    return 0;

  /* Exercise basic response accessors */
  (void)OCSP_resp_count (basic);

  OCSP_BASICRESP_free (basic);
  return 1;
}

/**
 * fuzz_parse_crl - Parse fuzz data as X509 CRL
 * @data: DER-encoded data
 * @size: Data size
 *
 * Returns: 1 if parsed successfully, 0 otherwise
 */
static int
fuzz_parse_crl (const uint8_t *data, size_t size)
{
  const unsigned char *p = data;
  X509_CRL *crl = d2i_X509_CRL (NULL, &p, (long)size);

  if (!crl)
    return 0;

  /* Exercise CRL accessors to catch memory issues */
  (void)X509_CRL_get_issuer (crl);
  (void)X509_CRL_get0_lastUpdate (crl);
  (void)X509_CRL_get0_nextUpdate (crl);

  X509_CRL_free (crl);
  return 1;
}

/**
 * fuzz_parse_crl_issuer - Parse CRL and verify issuer structure
 * @data: DER-encoded data
 * @size: Data size
 *
 * Returns: 1 if issuer extracted, 0 otherwise
 */
static int
fuzz_parse_crl_issuer (const uint8_t *data, size_t size)
{
  const unsigned char *p = data;
  X509_CRL *crl = d2i_X509_CRL (NULL, &p, (long)size);

  if (!crl)
    return 0;

  X509_NAME *issuer = X509_CRL_get_issuer (crl);
  int result = (issuer != NULL) ? 1 : 0;

  if (issuer)
    {
      /* Exercise issuer name accessors */
      char buf[256];
      X509_NAME_oneline (issuer, buf, sizeof (buf));
    }

  /* Get revoked certificates list */
  STACK_OF (X509_REVOKED) *revoked = X509_CRL_get_REVOKED (crl);
  if (revoked)
    {
      int count = sk_X509_REVOKED_num (revoked);
      /* Limit iteration to prevent DoS */
      for (int i = 0; i < count && i < 100; i++)
        {
          X509_REVOKED *rev = sk_X509_REVOKED_value (revoked, i);
          if (rev)
            {
              (void)X509_REVOKED_get0_serialNumber (rev);
              (void)X509_REVOKED_get0_revocationDate (rev);
            }
        }
    }

  X509_CRL_free (crl);
  return result;
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 *
 * Input format:
 * - Byte 0: Operation selector
 * - Bytes 1-4: Size hint (for split operations)
 * - Remaining: DER-encoded data
 *
 * Tests DER parsing for OCSP responses and CRLs.
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 5)
    return 0;

  uint8_t op = data[0];
  uint32_t size_hint = read_u32 (data + 1);
  const uint8_t *der_data = data + 5;
  size_t der_size = size - 5;

  /* Use size_hint to potentially truncate data for boundary testing */
  if (size_hint > 0 && size_hint < der_size)
    der_size = size_hint;

  /* Clear any stale OpenSSL errors */
  ERR_clear_error ();

  switch (op % VERIFY_OP_COUNT)
    {
    case VERIFY_OCSP_RESPONSE:
      fuzz_parse_ocsp_response (der_data, der_size);
      break;

    case VERIFY_CRL:
      fuzz_parse_crl (der_data, der_size);
      break;

    case VERIFY_OCSP_BASIC:
      fuzz_parse_ocsp_basic (der_data, der_size);
      break;

    case VERIFY_CRL_ISSUER:
      fuzz_parse_crl_issuer (der_data, der_size);
      break;
    }

  /* Clear errors generated during parsing */
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
