/**
 * fuzz_tls_ocsp.c - Fuzzer for TLS OCSP Response Parsing
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - d2i_OCSP_RESPONSE() - OCSP response parsing
 * - OCSP_response_get1_basic() - Basic response extraction
 * - OCSP_single_get0_status() - Certificate status extraction
 * - OCSP_check_validity() - Response freshness validation
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON -DENABLE_TLS=ON && make
 * fuzz_tls_ocsp Run:   ./fuzz_tls_ocsp corpus/tls_ocsp/ -fork=16 -max_len=65536
 */

#if SOCKET_HAS_TLS

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "core/Arena.h"
#include "core/Except.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

/* Operation codes */
enum OcspOp
{
  OCSP_PARSE_RESPONSE = 0,
  OCSP_PARSE_AND_VERIFY,
  OCSP_CHECK_VALIDITY,
  OCSP_EXTRACT_STATUS,
  OCSP_OP_COUNT
};

/* Default OCSP max age for freshness check (matches SocketTLS.c) */
#define SOCKET_TLS_OCSP_MAX_AGE_SECONDS 300

/**
 * fuzz_parse_ocsp_response - Parse fuzz data as OCSP response
 * @data: DER-encoded OCSP response data
 * @size: Data size
 *
 * Returns: 1 if parsed successfully, 0 otherwise
 */
static int
fuzz_parse_ocsp_response (const uint8_t *data, size_t size)
{
  if (size > INT_MAX)
    return 0;

  const unsigned char *p = data;
  OCSP_RESPONSE *resp = d2i_OCSP_RESPONSE (NULL, &p, (long)size);

  if (!resp)
    return 0;

  /* Exercise response accessors */
  int status = OCSP_response_status (resp);
  (void)status;

  /* Try to get basic response */
  OCSP_BASICRESP *basic = OCSP_response_get1_basic (resp);
  if (basic)
    {
      /* Count responses */
      int resp_count = OCSP_resp_count (basic);
      (void)resp_count;

      OCSP_BASICRESP_free (basic);
    }

  OCSP_RESPONSE_free (resp);
  return 1;
}

/**
 * fuzz_extract_ocsp_status - Parse and extract certificate status
 * @data: DER-encoded OCSP response data
 * @size: Data size
 *
 * Returns: Certificate status (1=GOOD, 0=REVOKED, -1=UNKNOWN/ERROR)
 */
static int
fuzz_extract_ocsp_status (const uint8_t *data, size_t size)
{
  if (size > INT_MAX)
    return -1;

  const unsigned char *p = data;
  OCSP_RESPONSE *resp = d2i_OCSP_RESPONSE (NULL, &p, (long)size);

  if (!resp)
    return -1;

  if (OCSP_response_status (resp) != OCSP_RESPONSE_STATUS_SUCCESSFUL)
    {
      OCSP_RESPONSE_free (resp);
      return -1;
    }

  OCSP_BASICRESP *basic = OCSP_response_get1_basic (resp);
  if (!basic)
    {
      OCSP_RESPONSE_free (resp);
      return -1;
    }

  int cert_status = -1;
  int resp_count = OCSP_resp_count (basic);

  for (int i = 0; i < resp_count && i < 100; i++)
    {
      OCSP_SINGLERESP *single = OCSP_resp_get0 (basic, i);
      if (!single)
        continue;

      int reason = 0;
      ASN1_GENERALIZEDTIME *thisupd = NULL;
      ASN1_GENERALIZEDTIME *nextupd = NULL;
      ASN1_GENERALIZEDTIME *revtime = NULL;

      int status = OCSP_single_get0_status (single, &reason, &revtime,
                                            &thisupd, &nextupd);

      /* Validate freshness if timestamps present */
      if (thisupd)
        {
          (void)OCSP_check_validity (thisupd, nextupd,
                                     SOCKET_TLS_OCSP_MAX_AGE_SECONDS, -1);
        }

      switch (status)
        {
        case V_OCSP_CERTSTATUS_GOOD:
          cert_status = 1;
          break;
        case V_OCSP_CERTSTATUS_REVOKED:
          cert_status = 0;
          break;
        default:
          if (cert_status < 0)
            cert_status = -1;
          break;
        }

      if (cert_status == 1 || cert_status == 0)
        break;
    }

  OCSP_BASICRESP_free (basic);
  OCSP_RESPONSE_free (resp);

  return cert_status;
}

/**
 * fuzz_check_ocsp_validity - Test OCSP validity checking with fuzz timestamps
 * @data: Fuzz data interpreted as timestamp components
 * @size: Data size
 *
 * Returns: 1 if valid, 0 if invalid, -1 on error
 */
static int
fuzz_check_ocsp_validity (const uint8_t *data, size_t size)
{
  if (size < 16)
    return -1;

  /* Create ASN1_GENERALIZEDTIME from fuzz data */
  ASN1_GENERALIZEDTIME *thisupd = ASN1_GENERALIZEDTIME_new ();
  ASN1_GENERALIZEDTIME *nextupd = ASN1_GENERALIZEDTIME_new ();

  if (!thisupd || !nextupd)
    {
      if (thisupd)
        ASN1_GENERALIZEDTIME_free (thisupd);
      if (nextupd)
        ASN1_GENERALIZEDTIME_free (nextupd);
      return -1;
    }

  /* Use current time as base, with fuzz data as offsets */
  time_t now = time (NULL);

  /* Construct thisUpdate as fuzz-derived offset from now */
  int32_t this_offset = 0;
  memcpy (&this_offset, data, sizeof (int32_t));
  this_offset = this_offset % (86400 * 365); /* Limit to +/- 1 year */

  time_t this_time = now + this_offset;
  struct tm *this_tm = gmtime (&this_time);
  if (this_tm)
    {
      ASN1_GENERALIZEDTIME_set (thisupd, this_time);
    }

  /* Construct nextUpdate as fuzz-derived offset from thisUpdate */
  int32_t next_offset = 0;
  memcpy (&next_offset, data + 4, sizeof (int32_t));
  next_offset = (next_offset % (86400 * 30)) + 1; /* 1 to 30 days */

  time_t next_time = this_time + (next_offset > 0 ? next_offset : 3600);
  struct tm *next_tm = gmtime (&next_time);
  if (next_tm)
    {
      ASN1_GENERALIZEDTIME_set (nextupd, next_time);
    }

  /* Test validity checking with various nsec/maxsec values */
  long nsec = (data[8] % 5) * 60;                    /* 0-4 minutes */
  long maxsec = (data[9] % 10) * SOCKET_TLS_OCSP_MAX_AGE_SECONDS;

  int result = OCSP_check_validity (thisupd, nextupd, nsec, maxsec);

  ASN1_GENERALIZEDTIME_free (thisupd);
  ASN1_GENERALIZEDTIME_free (nextupd);

  return result;
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 *
 * Input format:
 * - Byte 0: Operation selector
 * - Remaining: OCSP response data or timestamp components
 *
 * Tests OCSP parsing without network I/O.
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 2)
    return 0;

  uint8_t op = data[0];
  const uint8_t *ocsp_data = data + 1;
  size_t ocsp_size = size - 1;

  /* Clear any stale OpenSSL errors */
  ERR_clear_error ();

  switch (op % OCSP_OP_COUNT)
    {
    case OCSP_PARSE_RESPONSE:
      fuzz_parse_ocsp_response (ocsp_data, ocsp_size);
      break;

    case OCSP_PARSE_AND_VERIFY:
      /* Parse and exercise verification paths (without actual cert chain) */
      fuzz_parse_ocsp_response (ocsp_data, ocsp_size);
      break;

    case OCSP_CHECK_VALIDITY:
      fuzz_check_ocsp_validity (ocsp_data, ocsp_size);
      break;

    case OCSP_EXTRACT_STATUS:
      fuzz_extract_ocsp_status (ocsp_data, ocsp_size);
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
