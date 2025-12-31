/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketDNSSEC.c
 * @brief DNSSEC validation implementation (RFC 4033, 4034, 4035).
 */

#include "dns/SocketDNSSEC.h"
#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketCrypto.h"
#include "core/SocketUtil.h"
#include "dns/SocketDNSWire.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <string.h>
#include <time.h>

/*
 * DNSSEC digest and key size constants (RFC 4034, 5702, 6605, 8080)
 */

/** SHA-1 digest length (RFC 4034). */
#define DNSSEC_DIGEST_LEN_SHA1 20

/** SHA-256 digest length (RFC 4509). */
#define DNSSEC_DIGEST_LEN_SHA256 32

/** SHA-384 digest length (RFC 6605). */
#define DNSSEC_DIGEST_LEN_SHA384 48

/** GOST R 34.11-94 digest length (RFC 5933). */
#define DNSSEC_DIGEST_LEN_GOST 32

/** ECDSA P-256 coordinate size in bytes (RFC 6605). */
#define DNSSEC_ECDSA_P256_COORD_SIZE 32

/** ECDSA P-384 coordinate size in bytes (RFC 6605). */
#define DNSSEC_ECDSA_P384_COORD_SIZE 48

/** Ed25519 public key size in bytes (RFC 8080). */
#define DNSSEC_ED25519_PUBKEY_SIZE 32

/** Ed448 public key size in bytes (RFC 8080). */
#define DNSSEC_ED448_PUBKEY_SIZE 57

/** Minimum RSA public key RDATA size (exponent length byte + min exponent). */
#define DNSSEC_RSA_MIN_PUBKEY_SIZE 3

/** Maximum label count in domain name comparison. */
#define DNSSEC_MAX_LABELS 128

/** DNSSEC protocol field value (RFC 4034 Section 2.1.2). */
#define DNSSEC_PROTOCOL_VALUE 3

#ifdef SOCKET_HAS_TLS
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#endif


const Except_T SocketDNSSEC_Failed
    = { &SocketDNSSEC_Failed, "DNSSEC operation failed" };

/*
 * Key tag calculation (RFC 4034 Appendix B)
 *
 * The key tag is a 16-bit checksum computed over the DNSKEY RDATA.
 * It's used to efficiently identify which DNSKEY signed an RRset.
 */
uint16_t
SocketDNSSEC_calculate_keytag (const unsigned char *rdata, size_t rdlen)
{
  uint32_t ac = 0;

  if (rdata == NULL || rdlen < DNSSEC_DNSKEY_FIXED_SIZE)
    return 0;

  /*
   * RFC 4034 Appendix B.1: Algorithm 1 (RSA/MD5) uses different calculation.
   * For Algorithm 1, key tag = lower 16 bits of RSA public key modulus.
   * Algorithm 1 is deprecated but we maintain compatibility.
   */
  if (rdata[3] == DNSSEC_ALGO_RSAMD5)
    return socket_util_unpack_be16 (rdata + rdlen - 3);

  /* General key tag algorithm (RFC 4034 Appendix B) */
  for (size_t i = 0; i < rdlen; i++)
    {
      if (i & 1)
        ac += rdata[i];
      else
        ac += (uint32_t)rdata[i] << 8;
    }
  ac += (ac >> 16) & 0xFFFF;

  return (uint16_t)(ac & 0xFFFF);
}

/*
 * Parse DNSKEY record RDATA (RFC 4034 Section 2)
 */
int
SocketDNSSEC_parse_dnskey (const SocketDNS_RR *rr, SocketDNSSEC_DNSKEY *dnskey)
{
  if (rr == NULL || dnskey == NULL)
    return -1;

  if (rr->type != DNS_TYPE_DNSKEY)
    return -1;

  if (rr->rdlength < DNSSEC_DNSKEY_FIXED_SIZE)
    return -1;

  const unsigned char *p = rr->rdata;

  /* Flags: 2 bytes (network order) */
  dnskey->flags = socket_util_unpack_be16 (p);
  p += 2;

  /* Protocol: 1 byte (must be 3 for DNSSEC per RFC 4034 Section 2.1.2) */
  dnskey->protocol = *p++;
  if (dnskey->protocol != DNSSEC_PROTOCOL_VALUE)
    return -1;

  /* Algorithm: 1 byte */
  dnskey->algorithm = *p++;

  /* Public key: remainder */
  dnskey->pubkey = p;
  dnskey->pubkey_len = rr->rdlength - DNSSEC_DNSKEY_FIXED_SIZE;

  /* Calculate key tag */
  dnskey->key_tag = SocketDNSSEC_calculate_keytag (rr->rdata, rr->rdlength);

  return 0;
}

/*
 * Parse RRSIG record RDATA (RFC 4034 Section 3)
 */
int
SocketDNSSEC_parse_rrsig (const unsigned char *msg,
                          size_t msglen,
                          const SocketDNS_RR *rr,
                          SocketDNSSEC_RRSIG *rrsig)
{
  if (msg == NULL || rr == NULL || rrsig == NULL)
    return -1;

  if (rr->type != DNS_TYPE_RRSIG)
    return -1;

  if (rr->rdlength < DNSSEC_RRSIG_FIXED_SIZE)
    return -1;

  const unsigned char *p = rr->rdata;
  const unsigned char *end = rr->rdata + rr->rdlength;

  /* Type Covered: 2 bytes */
  rrsig->type_covered = socket_util_unpack_be16 (p);
  p += 2;

  /* Algorithm: 1 byte */
  rrsig->algorithm = *p++;

  /* Labels: 1 byte */
  rrsig->labels = *p++;

  /* Original TTL: 4 bytes */
  rrsig->original_ttl = socket_util_unpack_be32 (p);
  p += 4;

  /* Signature Expiration: 4 bytes */
  rrsig->sig_expiration = socket_util_unpack_be32 (p);
  p += 4;

  /* Signature Inception: 4 bytes */
  rrsig->sig_inception = socket_util_unpack_be32 (p);
  p += 4;

  /* Key Tag: 2 bytes */
  rrsig->key_tag = socket_util_unpack_be16 (p);
  p += 2;

  /* Signer's Name: variable length, may use compression */
  size_t offset = (size_t)(p - msg);
  size_t consumed;
  int len = SocketDNS_name_decode (msg,
                                   msglen,
                                   offset,
                                   rrsig->signer_name,
                                   sizeof (rrsig->signer_name),
                                   &consumed);
  if (len < 0)
    return -1;
  p += consumed;

  /* Signature: remainder */
  if (p > end)
    return -1;
  rrsig->signature = p;
  rrsig->signature_len = (uint16_t)(end - p);

  return 0;
}

/*
 * Parse DS record RDATA (RFC 4034 Section 5)
 */
int
SocketDNSSEC_parse_ds (const SocketDNS_RR *rr, SocketDNSSEC_DS *ds)
{
  if (rr == NULL || ds == NULL)
    return -1;

  if (rr->type != DNS_TYPE_DS)
    return -1;

  if (rr->rdlength < DNSSEC_DS_FIXED_SIZE)
    return -1;

  const unsigned char *p = rr->rdata;

  /* Key Tag: 2 bytes */
  ds->key_tag = socket_util_unpack_be16 (p);
  p += 2;

  /* Algorithm: 1 byte */
  ds->algorithm = *p++;

  /* Digest Type: 1 byte */
  ds->digest_type = *p++;

  /* Digest: remainder */
  ds->digest = p;
  ds->digest_len = rr->rdlength - DNSSEC_DS_FIXED_SIZE;

  /* Validate digest length based on type (RFC 4034, 4509, 5933, 6605) */
  switch (ds->digest_type)
    {
    case DNSSEC_DIGEST_SHA1:
      if (ds->digest_len != DNSSEC_DIGEST_LEN_SHA1)
        return -1;
      break;
    case DNSSEC_DIGEST_SHA256:
      if (ds->digest_len != DNSSEC_DIGEST_LEN_SHA256)
        return -1;
      break;
    case DNSSEC_DIGEST_SHA384:
      if (ds->digest_len != DNSSEC_DIGEST_LEN_SHA384)
        return -1;
      break;
    case DNSSEC_DIGEST_GOST:
      if (ds->digest_len != DNSSEC_DIGEST_LEN_GOST)
        return -1;
      break;
    default:
      /* Unknown digest type - accept but may fail validation */
      break;
    }

  return 0;
}

/*
 * Parse NSEC record RDATA (RFC 4034 Section 4)
 */
int
SocketDNSSEC_parse_nsec (const unsigned char *msg,
                         size_t msglen,
                         const SocketDNS_RR *rr,
                         SocketDNSSEC_NSEC *nsec)
{
  if (msg == NULL || rr == NULL || nsec == NULL)
    return -1;

  if (rr->type != DNS_TYPE_NSEC)
    return -1;

  if (rr->rdlength < 1)
    return -1;

  /* Next Domain Name: variable length, may use compression */
  size_t offset = (size_t)(rr->rdata - msg);
  size_t consumed;
  int len = SocketDNS_name_decode (msg,
                                   msglen,
                                   offset,
                                   nsec->next_domain,
                                   sizeof (nsec->next_domain),
                                   &consumed);
  if (len < 0)
    return -1;

  /* Type Bit Maps: remainder */
  if (consumed > rr->rdlength)
    return -1;
  nsec->type_bitmaps = rr->rdata + consumed;
  nsec->type_bitmaps_len = rr->rdlength - consumed;

  return 0;
}

/*
 * Parse NSEC3 record RDATA (RFC 5155)
 */
int
SocketDNSSEC_parse_nsec3 (const SocketDNS_RR *rr, SocketDNSSEC_NSEC3 *nsec3)
{
  if (rr == NULL || nsec3 == NULL)
    return -1;

  if (rr->type != DNS_TYPE_NSEC3)
    return -1;

  if (rr->rdlength < DNSSEC_NSEC3_FIXED_SIZE)
    return -1;

  const unsigned char *p = rr->rdata;
  const unsigned char *end = rr->rdata + rr->rdlength;

  /* Hash Algorithm: 1 byte */
  nsec3->hash_algorithm = *p++;

  /* Flags: 1 byte */
  nsec3->flags = *p++;

  /* Iterations: 2 bytes */
  nsec3->iterations = socket_util_unpack_be16 (p);
  p += 2;

  /* Salt Length: 1 byte */
  nsec3->salt_len = *p++;
  if (p + nsec3->salt_len > end)
    return -1;

  /* Salt: variable */
  nsec3->salt = (nsec3->salt_len > 0) ? p : NULL;
  p += nsec3->salt_len;

  /* Hash Length: 1 byte */
  if (p >= end)
    return -1;
  nsec3->hash_len = *p++;
  if (p + nsec3->hash_len > end)
    return -1;

  /* Next Hashed Owner Name: variable */
  nsec3->next_hashed = p;
  p += nsec3->hash_len;

  /* Type Bit Maps: remainder */
  nsec3->type_bitmaps = p;
  nsec3->type_bitmaps_len = (uint16_t)(end - p);

  return 0;
}

/*
 * Check if a type is present in NSEC/NSEC3 type bitmaps
 *
 * Type Bitmap format (RFC 4034 Section 4.1.2):
 *   Window Block # | Bitmap Length | Bitmap (variable)
 *   Each window covers 256 types (0-255, 256-511, etc.)
 */
int
SocketDNSSEC_type_in_bitmap (const unsigned char *bitmaps,
                             size_t bitmaps_len,
                             uint16_t rrtype)
{
  if (bitmaps == NULL || bitmaps_len == 0)
    return 0;

  uint8_t window = rrtype / 256;
  uint8_t bit_offset = rrtype % 256;
  uint8_t byte_offset = bit_offset / 8;
  uint8_t bit_mask = 0x80 >> (bit_offset % 8);

  const unsigned char *p = bitmaps;
  const unsigned char *end = bitmaps + bitmaps_len;

  while (p + 2 <= end)
    {
      uint8_t block_num = p[0];
      uint8_t bitmap_len = p[1];
      p += 2;

      if (bitmap_len == 0 || bitmap_len > 32)
        return -1; /* Invalid bitmap length */

      if (p + bitmap_len > end)
        return -1; /* Truncated */

      if (block_num == window)
        {
          if (byte_offset < bitmap_len)
            return (p[byte_offset] & bit_mask) ? 1 : 0;
          else
            return 0; /* Type not in this window's range */
        }

      p += bitmap_len;
    }

  return 0; /* Window not found */
}

/*
 * Canonicalize domain name (lowercase)
 */
void
SocketDNSSEC_name_canonicalize (char *name)
{
  if (name == NULL)
    return;

  for (char *p = name; *p; p++)
    {
      if (*p >= 'A' && *p <= 'Z')
        *p = *p + ('a' - 'A');
    }
}

/*
 * Parse domain name into labels
 *
 * Splits a domain name into labels separated by dots.
 * Returns the number of labels found.
 *
 * @param name Domain name to parse (e.g., "www.example.com")
 * @param labels Array to store pointers to each label
 * @param labellens Array to store length of each label
 * @return Number of labels parsed
 */
static int
parse_domain_labels (const char *name,
                     const char *labels[DNSSEC_MAX_LABELS],
                     size_t labellens[DNSSEC_MAX_LABELS])
{
  int count = 0;
  const char *p = name;

  while (*p && count < DNSSEC_MAX_LABELS)
    {
      labels[count] = p;
      const char *dot = strchr (p, '.');
      if (dot)
        {
          labellens[count] = dot - p;
          p = dot + 1;
        }
      else
        {
          labellens[count] = strlen (p);
          break;
        }
      count++;
    }
  if (*p && count < DNSSEC_MAX_LABELS)
    count++;

  return count;
}

/*
 * Compare domain names in canonical order (RFC 4034 Section 6.1)
 *
 * Canonical ordering is case-insensitive and compares labels
 * from right to left (parent before child).
 */
int
SocketDNSSEC_name_canonical_compare (const char *name1, const char *name2)
{
  if (name1 == NULL || name2 == NULL)
    return (name1 == name2) ? 0 : ((name1 == NULL) ? -1 : 1);

  /* Parse labels from both names */
  const char *label1[DNSSEC_MAX_LABELS], *label2[DNSSEC_MAX_LABELS];
  size_t labellen1[DNSSEC_MAX_LABELS], labellen2[DNSSEC_MAX_LABELS];

  int labels1 = parse_domain_labels (name1, label1, labellen1);
  int labels2 = parse_domain_labels (name2, label2, labellen2);

  /* Compare from rightmost label */
  int i1 = labels1 - 1, i2 = labels2 - 1;
  while (i1 >= 0 && i2 >= 0)
    {
      size_t len
          = (labellen1[i1] < labellen2[i2]) ? labellen1[i1] : labellen2[i2];
      for (size_t j = 0; j < len; j++)
        {
          unsigned char c1 = (unsigned char)label1[i1][j];
          unsigned char c2 = (unsigned char)label2[i2][j];
          if (c1 >= 'A' && c1 <= 'Z')
            c1 = c1 + ('a' - 'A');
          if (c2 >= 'A' && c2 <= 'Z')
            c2 = c2 + ('a' - 'A');
          if (c1 != c2)
            return (int)c1 - (int)c2;
        }
      if (labellen1[i1] != labellen2[i2])
        return (int)labellen1[i1] - (int)labellen2[i2];
      i1--;
      i2--;
    }

  /* Fewer labels = comes first */
  return labels1 - labels2;
}

/*
 * Check if RRSIG is within validity period
 */
int
SocketDNSSEC_rrsig_valid_time (const SocketDNSSEC_RRSIG *rrsig, time_t now)
{
  if (rrsig == NULL)
    return -1;

  if (now == 0)
    now = time (NULL);

  /*
   * RFC 4034 Section 3.1.5: Use serial number arithmetic
   * to handle wrap-around of 32-bit timestamps
   */
  uint32_t current = (uint32_t)now;

  /* Check inception: current >= inception */
  int32_t inception_diff = (int32_t)(current - rrsig->sig_inception);
  if (inception_diff < 0)
    return 0; /* Not yet valid */

  /* Check expiration: current < expiration */
  int32_t expiration_diff = (int32_t)(rrsig->sig_expiration - current);
  if (expiration_diff <= 0)
    return 0; /* Expired */

  return 1;
}

/*
 * Check if algorithm is supported
 */
int
SocketDNSSEC_algorithm_supported (uint8_t algorithm)
{
#ifdef SOCKET_HAS_TLS
  switch (algorithm)
    {
    case DNSSEC_ALGO_RSASHA1:
    case DNSSEC_ALGO_RSASHA1_NSEC3_SHA1:
    case DNSSEC_ALGO_RSASHA256:
    case DNSSEC_ALGO_RSASHA512:
    case DNSSEC_ALGO_ECDSAP256SHA256:
    case DNSSEC_ALGO_ECDSAP384SHA384:
    case DNSSEC_ALGO_ED25519:
    case DNSSEC_ALGO_ED448:
      return 1;
    default:
      return 0;
    }
#else
  (void)algorithm;
  return 0; /* No crypto support without TLS */
#endif
}

/*
 * Check if digest type is supported
 */
int
SocketDNSSEC_digest_supported (uint8_t digest_type)
{
#ifdef SOCKET_HAS_TLS
  switch (digest_type)
    {
    case DNSSEC_DIGEST_SHA1:
    case DNSSEC_DIGEST_SHA256:
    case DNSSEC_DIGEST_SHA384:
      return 1;
    case DNSSEC_DIGEST_GOST:
      return 0; /* GOST not commonly supported */
    default:
      return 0;
    }
#else
  (void)digest_type;
  return 0;
#endif
}

#ifdef SOCKET_HAS_TLS

/*
 * Encode domain name in canonical wire format for DNSSEC signing
 * Returns length written, or -1 on error
 */
static int
encode_canonical_name (const char *name, unsigned char *buf, size_t buflen)
{
  if (name == NULL || buf == NULL || buflen == 0)
    return -1;

  size_t total = 0;
  const char *p = name;

  while (*p)
    {
      /* Find end of label */
      const char *dot = strchr (p, '.');
      size_t label_len = dot ? (size_t)(dot - p) : strlen (p);

      if (label_len > DNS_MAX_LABEL_LEN)
        return -1;
      if (total + 1 + label_len > buflen)
        return -1;

      buf[total++] = (unsigned char)label_len;
      for (size_t i = 0; i < label_len; i++)
        {
          char c = p[i];
          if (c >= 'A' && c <= 'Z')
            c = c + ('a' - 'A');
          buf[total++] = (unsigned char)c;
        }

      if (dot)
        p = dot + 1;
      else
        break;
    }

  /* Root label */
  if (total + 1 > buflen)
    return -1;
  buf[total++] = 0;

  return (int)total;
}

/*
 * Compute DS digest from DNSKEY
 */
static int
compute_ds_digest (const char *owner_name,
                   const SocketDNSSEC_DNSKEY *dnskey __attribute__ ((unused)),
                   const unsigned char *rdata,
                   size_t rdlen,
                   uint8_t digest_type,
                   unsigned char *digest,
                   size_t *digest_len)
{
  const EVP_MD *md = NULL;

  switch (digest_type)
    {
    case DNSSEC_DIGEST_SHA1:
      md = EVP_sha1 ();
      break;
    case DNSSEC_DIGEST_SHA256:
      md = EVP_sha256 ();
      break;
    case DNSSEC_DIGEST_SHA384:
      md = EVP_sha384 ();
      break;
    default:
      return -1;
    }

  EVP_MD_CTX *ctx = EVP_MD_CTX_new ();
  if (ctx == NULL)
    return -1;

  if (EVP_DigestInit_ex (ctx, md, NULL) != 1)
    {
      EVP_MD_CTX_free (ctx);
      return -1;
    }

  /* Hash owner name in canonical wire format */
  unsigned char name_wire[DNS_MAX_NAME_LEN];
  int name_len
      = encode_canonical_name (owner_name, name_wire, sizeof (name_wire));
  if (name_len < 0)
    {
      EVP_MD_CTX_free (ctx);
      return -1;
    }

  if (EVP_DigestUpdate (ctx, name_wire, name_len) != 1)
    {
      EVP_MD_CTX_free (ctx);
      return -1;
    }

  /* Hash DNSKEY RDATA */
  if (EVP_DigestUpdate (ctx, rdata, rdlen) != 1)
    {
      EVP_MD_CTX_free (ctx);
      return -1;
    }

  unsigned int len;
  if (EVP_DigestFinal_ex (ctx, digest, &len) != 1)
    {
      EVP_MD_CTX_free (ctx);
      return -1;
    }

  *digest_len = len;
  EVP_MD_CTX_free (ctx);
  return 0;
}

#endif /* ENABLE_TLS */

/*
 * Verify DS matches DNSKEY
 */
int
SocketDNSSEC_verify_ds (const SocketDNSSEC_DS *ds,
                        const SocketDNSSEC_DNSKEY *dnskey,
                        const char *owner_name)
{
  if (ds == NULL || dnskey == NULL || owner_name == NULL)
    return -1;

  /* Check key tag matches */
  if (ds->key_tag != dnskey->key_tag)
    return 0;

  /* Check algorithm matches */
  if (ds->algorithm != dnskey->algorithm)
    return 0;

#ifdef SOCKET_HAS_TLS
  /* Reconstruct DNSKEY RDATA for hashing.
   * Note: pubkey_len is uint16_t (max 65535), so adding 4 bytes cannot
   * overflow. */
  size_t rdata_len = DNSSEC_DNSKEY_FIXED_SIZE + dnskey->pubkey_len;
  unsigned char *rdata = malloc (rdata_len);
  if (rdata == NULL)
    return -1;

  socket_util_pack_be16 (rdata, dnskey->flags);
  rdata[2] = dnskey->protocol;
  rdata[3] = dnskey->algorithm;
  memcpy (rdata + DNSSEC_DNSKEY_FIXED_SIZE, dnskey->pubkey, dnskey->pubkey_len);

  unsigned char computed_digest[DNSSEC_DS_MAX_DIGEST_LEN];
  size_t computed_len;

  int ret = compute_ds_digest (owner_name,
                               dnskey,
                               rdata,
                               rdata_len,
                               ds->digest_type,
                               computed_digest,
                               &computed_len);
  free (rdata);

  if (ret < 0)
    return -1;

  /* Compare digests */
  if (computed_len != ds->digest_len)
    return 0;

  /* Constant-time comparison to prevent timing attacks */
  return (SocketCrypto_secure_compare (
              computed_digest, ds->digest, computed_len)
          == 0)
             ? 1
             : 0;

#else
  /* No crypto support */
  return -1;
#endif
}

#ifdef SOCKET_HAS_TLS

/*
 * Create RSA public key from DNSKEY
 * Returns pkey on success, NULL on error
 * Sets *status to DNSSEC_BOGUS for malformed data, DNSSEC_INDETERMINATE for
 * system errors
 */
static EVP_PKEY *
create_rsa_pkey_from_dnskey (const SocketDNSSEC_DNSKEY *dnskey, int *status)
{
  /* RSA public key format: exponent length + exponent + modulus */
  if (dnskey->pubkey_len < 3)
    {
      *status = DNSSEC_BOGUS;
      return NULL;
    }

  const unsigned char *pk = dnskey->pubkey;
  size_t exp_len;
  if (pk[0] == 0)
    {
      if (dnskey->pubkey_len < 3)
        {
          *status = DNSSEC_BOGUS;
          return NULL;
        }
      exp_len = ((size_t)pk[1] << 8) | pk[2];
      pk += 3;
    }
  else
    {
      exp_len = pk[0];
      pk += 1;
    }

  /* Validate exp_len against remaining buffer to prevent overflow */
  size_t remaining = (dnskey->pubkey + dnskey->pubkey_len) - pk;
  if (exp_len > remaining)
    {
      *status = DNSSEC_BOGUS;
      return NULL;
    }

  const unsigned char *exp_data = pk;
  pk += exp_len;
  size_t mod_len = (dnskey->pubkey + dnskey->pubkey_len) - pk;

  /* Create RSA key */
  BIGNUM *n = BN_bin2bn (pk, mod_len, NULL);
  BIGNUM *e = BN_bin2bn (exp_data, exp_len, NULL);
  if (n == NULL || e == NULL)
    {
      BN_free (n);
      BN_free (e);
      *status = DNSSEC_INDETERMINATE;
      return NULL;
    }

  EVP_PKEY *pkey = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  /* OpenSSL 3.0+ uses EVP_PKEY_fromdata */
  OSSL_PARAM params[3];
  params[0] = OSSL_PARAM_construct_BN ("n", (unsigned char *)pk, mod_len);
  params[1] = OSSL_PARAM_construct_BN ("e", (unsigned char *)exp_data, exp_len);
  params[2] = OSSL_PARAM_construct_end ();

  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name (NULL, "RSA", NULL);
  if (pctx == NULL)
    {
      BN_free (n);
      BN_free (e);
      *status = DNSSEC_INDETERMINATE;
      return NULL;
    }

  if (EVP_PKEY_fromdata_init (pctx) <= 0
      || EVP_PKEY_fromdata (pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
    {
      EVP_PKEY_CTX_free (pctx);
      BN_free (n);
      BN_free (e);
      *status = DNSSEC_INDETERMINATE;
      return NULL;
    }
  EVP_PKEY_CTX_free (pctx);
  BN_free (n);
  BN_free (e);
#else
  RSA *rsa = RSA_new ();
  if (rsa == NULL)
    {
      BN_free (n);
      BN_free (e);
      *status = DNSSEC_INDETERMINATE;
      return NULL;
    }
  RSA_set0_key (rsa, n, e, NULL);
  pkey = EVP_PKEY_new ();
  if (pkey == NULL)
    {
      RSA_free (rsa);
      *status = DNSSEC_INDETERMINATE;
      return NULL;
    }
  EVP_PKEY_assign_RSA (pkey, rsa);
#endif

  *status = DNSSEC_SECURE;
  return pkey;
}

/*
 * Create ECDSA public key from DNSKEY
 * Returns pkey on success, NULL on error
 * Sets *status to DNSSEC_BOGUS for malformed data, DNSSEC_INDETERMINATE for
 * system errors
 */
static EVP_PKEY *
create_ecdsa_pkey_from_dnskey (const SocketDNSSEC_DNSKEY *dnskey, int *status)
{
  int nid = (dnskey->algorithm == DNSSEC_ALGO_ECDSAP256SHA256)
                ? NID_X9_62_prime256v1
                : NID_secp384r1;
  size_t coord_size = (dnskey->algorithm == DNSSEC_ALGO_ECDSAP256SHA256)
                          ? DNSSEC_ECDSA_P256_COORD_SIZE
                          : DNSSEC_ECDSA_P384_COORD_SIZE;

  if (dnskey->pubkey_len != 2 * coord_size)
    {
      *status = DNSSEC_BOGUS;
      return NULL;
    }

  EVP_PKEY *pkey = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  /* OpenSSL 3.0+ */
  unsigned char pubkey_uncompressed[1 + 2 * DNSSEC_ECDSA_P384_COORD_SIZE];
  pubkey_uncompressed[0] = 0x04; /* Uncompressed point */
  memcpy (pubkey_uncompressed + 1, dnskey->pubkey, 2 * coord_size);

  const char *group_name = (nid == NID_X9_62_prime256v1) ? "P-256" : "P-384";
  OSSL_PARAM params[3];
  params[0] = OSSL_PARAM_construct_utf8_string ("group", (char *)group_name, 0);
  params[1] = OSSL_PARAM_construct_octet_string (
      "pub", pubkey_uncompressed, 1 + 2 * coord_size);
  params[2] = OSSL_PARAM_construct_end ();

  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name (NULL, "EC", NULL);
  if (pctx == NULL)
    {
      *status = DNSSEC_INDETERMINATE;
      return NULL;
    }

  if (EVP_PKEY_fromdata_init (pctx) <= 0
      || EVP_PKEY_fromdata (pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
    {
      EVP_PKEY_CTX_free (pctx);
      *status = DNSSEC_INDETERMINATE;
      return NULL;
    }
  EVP_PKEY_CTX_free (pctx);
#else
  EC_KEY *ec = EC_KEY_new_by_curve_name (nid);
  if (ec == NULL)
    {
      *status = DNSSEC_INDETERMINATE;
      return NULL;
    }

  /* Create uncompressed public key point */
  unsigned char pubkey_uncompressed[1 + 2 * DNSSEC_ECDSA_P384_COORD_SIZE];
  pubkey_uncompressed[0] = 0x04; /* Uncompressed */
  memcpy (pubkey_uncompressed + 1, dnskey->pubkey, 2 * coord_size);

  const unsigned char *pp = pubkey_uncompressed;
  if (o2i_ECPublicKey (&ec, &pp, 1 + 2 * coord_size) == NULL)
    {
      EC_KEY_free (ec);
      *status = DNSSEC_BOGUS;
      return NULL;
    }

  pkey = EVP_PKEY_new ();
  if (pkey == NULL)
    {
      EC_KEY_free (ec);
      *status = DNSSEC_INDETERMINATE;
      return NULL;
    }
  EVP_PKEY_assign_EC_KEY (pkey, ec);
#endif

  *status = DNSSEC_SECURE;
  return pkey;
}

/*
 * Create EdDSA public key from DNSKEY
 * Returns pkey on success, NULL on error
 * Sets *status to DNSSEC_BOGUS for malformed data, DNSSEC_INDETERMINATE for
 * system errors
 */
static EVP_PKEY *
create_eddsa_pkey_from_dnskey (const SocketDNSSEC_DNSKEY *dnskey, int *status)
{
  int type = (dnskey->algorithm == DNSSEC_ALGO_ED25519) ? EVP_PKEY_ED25519
                                                        : EVP_PKEY_ED448;
  size_t key_len = (dnskey->algorithm == DNSSEC_ALGO_ED25519)
                       ? DNSSEC_ED25519_PUBKEY_SIZE
                       : DNSSEC_ED448_PUBKEY_SIZE;

  if (dnskey->pubkey_len != key_len)
    {
      *status = DNSSEC_BOGUS;
      return NULL;
    }

  EVP_PKEY *pkey
      = EVP_PKEY_new_raw_public_key (type, NULL, dnskey->pubkey, key_len);
  if (pkey == NULL)
    {
      *status = DNSSEC_INDETERMINATE;
      return NULL;
    }

  *status = DNSSEC_SECURE;
  return pkey;
}

/*
 * Construct RRSIG signed data into verification context
 */
static int
construct_rrsig_signed_data (EVP_MD_CTX *ctx,
                             const SocketDNSSEC_RRSIG *rrsig,
                             const unsigned char *msg,
                             size_t msglen,
                             size_t rrset_offset,
                             size_t rrset_count)
{
  /*
   * Feed signed data:
   * 1. RRSIG RDATA without signature (fixed fields + signer name)
   */
  unsigned char rrsig_rdata[DNSSEC_RRSIG_FIXED_SIZE + DNS_MAX_NAME_LEN];
  size_t rrsig_rdata_len = 0;

  /* Type Covered */
  socket_util_pack_be16 (rrsig_rdata + rrsig_rdata_len, rrsig->type_covered);
  rrsig_rdata_len += 2;

  /* Algorithm */
  rrsig_rdata[rrsig_rdata_len++] = rrsig->algorithm;

  /* Labels */
  rrsig_rdata[rrsig_rdata_len++] = rrsig->labels;

  /* Original TTL */
  socket_util_pack_be32 (rrsig_rdata + rrsig_rdata_len, rrsig->original_ttl);
  rrsig_rdata_len += 4;

  /* Signature Expiration */
  socket_util_pack_be32 (rrsig_rdata + rrsig_rdata_len, rrsig->sig_expiration);
  rrsig_rdata_len += 4;

  /* Signature Inception */
  socket_util_pack_be32 (rrsig_rdata + rrsig_rdata_len, rrsig->sig_inception);
  rrsig_rdata_len += 4;

  /* Key Tag */
  socket_util_pack_be16 (rrsig_rdata + rrsig_rdata_len, rrsig->key_tag);
  rrsig_rdata_len += 2;

  /* Signer's Name in canonical wire format */
  int name_len = encode_canonical_name (rrsig->signer_name,
                                        rrsig_rdata + rrsig_rdata_len,
                                        sizeof (rrsig_rdata) - rrsig_rdata_len);
  if (name_len < 0)
    return -1;
  rrsig_rdata_len += name_len;

  if (EVP_DigestVerifyUpdate (ctx, rrsig_rdata, rrsig_rdata_len) != 1)
    return -1;

  /*
   * 2. RRset in canonical form (RFC 4035 Section 5.3.2)
   * For each RR: owner name | type | class | TTL | RDLENGTH | RDATA
   */

  /* Iterate through RRset and add each RR to the signature data */
  size_t current_offset = rrset_offset;
  for (size_t i = 0; i < rrset_count; i++)
    {
      SocketDNS_RR rr;
      size_t consumed;

      /* Decode the resource record */
      if (SocketDNS_rr_decode (msg, msglen, current_offset, &rr, &consumed)
          != 0)
        return -1;

      /* Verify this RR is part of the covered RRset */
      if (rr.type != rrsig->type_covered)
        {
          /* Skip RRs not covered by this signature (e.g., RRSIG records) */
          current_offset += consumed;
          continue;
        }

      /* Build canonical RR data: owner | type | class | TTL | RDLENGTH | RDATA
       */
      unsigned char rr_canonical[DNS_MAX_NAME_LEN + 10 + DNS_MAX_RDATA_LEN];
      size_t rr_len = 0;

      /* Owner name in canonical (lowercase) wire format */
      int owner_len = encode_canonical_name (
          rr.name, rr_canonical, sizeof (rr_canonical));
      if (owner_len < 0)
        return -1;
      rr_len += owner_len;

      /* Check buffer space for fixed fields + RDATA */
      if (rr_len + 10 + rr.rdlength > sizeof (rr_canonical))
        return -1;

      /* Type (2 bytes, network order) */
      socket_util_pack_be16 (rr_canonical + rr_len, rr.type);
      rr_len += 2;

      /* Class (2 bytes, network order) */
      socket_util_pack_be16 (rr_canonical + rr_len, rr.rclass);
      rr_len += 2;

      /* TTL - use original TTL from RRSIG, not current RR TTL (RFC 4035 5.3.2)
       */
      socket_util_pack_be32 (rr_canonical + rr_len, rrsig->original_ttl);
      rr_len += 4;

      /* RDLENGTH (2 bytes, network order) */
      socket_util_pack_be16 (rr_canonical + rr_len, rr.rdlength);
      rr_len += 2;

      /* RDATA (raw bytes from wire format) */
      if (rr.rdata != NULL && rr.rdlength > 0)
        {
          memcpy (rr_canonical + rr_len, rr.rdata, rr.rdlength);
          rr_len += rr.rdlength;
        }

      /* Add this canonical RR to the signature verification data */
      if (EVP_DigestVerifyUpdate (ctx, rr_canonical, rr_len) != 1)
        return -1;

      current_offset += consumed;
    }

  return 0;
}

/*
 * Convert ECDSA signature from raw (r||s) to DER format
 */
static unsigned char *
convert_ecdsa_signature_to_der (const unsigned char *raw_sig,
                                size_t raw_sig_len,
                                uint8_t algorithm,
                                size_t *der_sig_len)
{
  size_t coord_size = (algorithm == DNSSEC_ALGO_ECDSAP256SHA256)
                          ? DNSSEC_ECDSA_P256_COORD_SIZE
                          : DNSSEC_ECDSA_P384_COORD_SIZE;

  if (raw_sig_len != 2 * coord_size)
    return NULL;

  ECDSA_SIG *ecdsa_sig = ECDSA_SIG_new ();
  if (ecdsa_sig == NULL)
    return NULL;

  BIGNUM *r = BN_bin2bn (raw_sig, coord_size, NULL);
  BIGNUM *s = BN_bin2bn (raw_sig + coord_size, coord_size, NULL);
  if (r == NULL || s == NULL)
    {
      BN_free (r);
      BN_free (s);
      ECDSA_SIG_free (ecdsa_sig);
      return NULL;
    }

  ECDSA_SIG_set0 (ecdsa_sig, r, s);

  unsigned char *der_sig = NULL;
  *der_sig_len = i2d_ECDSA_SIG (ecdsa_sig, &der_sig);
  ECDSA_SIG_free (ecdsa_sig);

  return der_sig;
}

#endif /* SOCKET_HAS_TLS */

/*
 * Verify RRSIG signature
 */
int
SocketDNSSEC_verify_rrsig (const SocketDNSSEC_RRSIG *rrsig,
                           const SocketDNSSEC_DNSKEY *dnskey,
                           const unsigned char *msg,
                           size_t msglen __attribute__ ((unused)),
                           size_t rrset_offset,
                           size_t rrset_count)
{
  if (rrsig == NULL || dnskey == NULL || msg == NULL)
    return -1;

  /* Check key tag matches */
  if (rrsig->key_tag != dnskey->key_tag)
    return DNSSEC_BOGUS;

  /* Check algorithm matches */
  if (rrsig->algorithm != dnskey->algorithm)
    return DNSSEC_BOGUS;

  /* Check validity period */
  if (!SocketDNSSEC_rrsig_valid_time (rrsig, 0))
    return DNSSEC_BOGUS;

  /* Check algorithm is supported */
  if (!SocketDNSSEC_algorithm_supported (rrsig->algorithm))
    return DNSSEC_INDETERMINATE;

#ifdef SOCKET_HAS_TLS
  /*
   * Construct signed data (RFC 4035 Section 5.3.2):
   * signed_data = RRSIG_RDATA | RR(1) | RR(2) | ...
   */

  /* Select hash algorithm based on DNSSEC algorithm */
  const EVP_MD *md = NULL;
  switch (rrsig->algorithm)
    {
    case DNSSEC_ALGO_RSASHA1:
    case DNSSEC_ALGO_RSASHA1_NSEC3_SHA1:
      md = EVP_sha1 ();
      break;
    case DNSSEC_ALGO_RSASHA256:
    case DNSSEC_ALGO_ECDSAP256SHA256:
      md = EVP_sha256 ();
      break;
    case DNSSEC_ALGO_RSASHA512:
      md = EVP_sha512 ();
      break;
    case DNSSEC_ALGO_ECDSAP384SHA384:
      md = EVP_sha384 ();
      break;
    case DNSSEC_ALGO_ED25519:
    case DNSSEC_ALGO_ED448:
      md = NULL; /* Ed25519/Ed448 don't use separate hash */
      break;
    default:
      return DNSSEC_INDETERMINATE;
    }

  /* Create public key from DNSKEY */
  EVP_PKEY *pkey = NULL;
  int pkey_status = DNSSEC_SECURE;

  switch (dnskey->algorithm)
    {
    case DNSSEC_ALGO_RSASHA1:
    case DNSSEC_ALGO_RSASHA1_NSEC3_SHA1:
    case DNSSEC_ALGO_RSASHA256:
    case DNSSEC_ALGO_RSASHA512:
      pkey = create_rsa_pkey_from_dnskey (dnskey, &pkey_status);
      break;

    case DNSSEC_ALGO_ECDSAP256SHA256:
    case DNSSEC_ALGO_ECDSAP384SHA384:
      pkey = create_ecdsa_pkey_from_dnskey (dnskey, &pkey_status);
      break;

    case DNSSEC_ALGO_ED25519:
    case DNSSEC_ALGO_ED448:
      pkey = create_eddsa_pkey_from_dnskey (dnskey, &pkey_status);
      break;

    default:
      return DNSSEC_INDETERMINATE;
    }

  if (pkey == NULL)
    return pkey_status;

  /* Create verification context */
  EVP_MD_CTX *ctx = EVP_MD_CTX_new ();
  if (ctx == NULL)
    {
      EVP_PKEY_free (pkey);
      return DNSSEC_INDETERMINATE;
    }

  if (EVP_DigestVerifyInit (ctx, NULL, md, NULL, pkey) != 1)
    {
      EVP_MD_CTX_free (ctx);
      EVP_PKEY_free (pkey);
      return DNSSEC_INDETERMINATE;
    }

  /* Build signature data */
  if (construct_rrsig_signed_data (
          ctx, rrsig, msg, msglen, rrset_offset, rrset_count)
      != 0)
    {
      EVP_MD_CTX_free (ctx);
      EVP_PKEY_free (pkey);
      return DNSSEC_INDETERMINATE;
    }

  /* Convert ECDSA signature if needed */
  const unsigned char *sig = rrsig->signature;
  size_t sig_len = rrsig->signature_len;
  unsigned char *der_sig = NULL;

  if (dnskey->algorithm == DNSSEC_ALGO_ECDSAP256SHA256
      || dnskey->algorithm == DNSSEC_ALGO_ECDSAP384SHA384)
    {
      der_sig = convert_ecdsa_signature_to_der (
          sig, sig_len, dnskey->algorithm, &sig_len);
      if (der_sig == NULL)
        {
          EVP_MD_CTX_free (ctx);
          EVP_PKEY_free (pkey);
          return DNSSEC_BOGUS;
        }
      sig = der_sig;
    }

  /* Verify signature */
  int verify_result = EVP_DigestVerifyFinal (ctx, sig, sig_len);

  if (der_sig)
    OPENSSL_free (der_sig);

  EVP_MD_CTX_free (ctx);
  EVP_PKEY_free (pkey);

  return (verify_result == 1) ? DNSSEC_SECURE : DNSSEC_BOGUS;

#else
  (void)rrset_offset;
  (void)rrset_count;
  return DNSSEC_INDETERMINATE; /* No crypto support */
#endif
}

/*
 * Validator implementation
 */

struct SocketDNSSEC_Validator
{
  Arena_T arena;
  SocketDNSSEC_TrustAnchor *anchors;
  int anchor_count;
};

SocketDNSSEC_Validator_T
SocketDNSSEC_validator_new (Arena_T arena)
{
  struct SocketDNSSEC_Validator *v;

  if (arena)
    v = Arena_alloc (arena, sizeof (*v), __FILE__, __LINE__);
  else
    v = malloc (sizeof (*v));

  if (v == NULL)
    return NULL;

  v->arena = arena;
  v->anchors = NULL;
  v->anchor_count = 0;

  return v;
}

void
SocketDNSSEC_validator_free (SocketDNSSEC_Validator_T *validator)
{
  if (validator == NULL || *validator == NULL)
    return;

  struct SocketDNSSEC_Validator *v = *validator;

  if (v->arena == NULL)
    {
      /* Free anchors if using heap */
      SocketDNSSEC_TrustAnchor *a = v->anchors;
      while (a)
        {
          SocketDNSSEC_TrustAnchor *next = a->next;

          /* Free embedded data pointers */
          if (a->type == TRUST_ANCHOR_DNSKEY && a->data.dnskey.pubkey != NULL)
            free ((void *)a->data.dnskey.pubkey);
          else if (a->type == TRUST_ANCHOR_DS && a->data.ds.digest != NULL)
            free ((void *)a->data.ds.digest);

          free (a);
          a = next;
        }
      free (v);
    }
  /* If using arena, memory is freed with arena */

  *validator = NULL;
}

int
SocketDNSSEC_validator_add_anchor (SocketDNSSEC_Validator_T validator,
                                   const SocketDNSSEC_TrustAnchor *anchor)
{
  if (validator == NULL || anchor == NULL)
    return -1;

  SocketDNSSEC_TrustAnchor *new_anchor;

  if (validator->arena)
    new_anchor = Arena_alloc (
        validator->arena, sizeof (*new_anchor), __FILE__, __LINE__);
  else
    new_anchor = malloc (sizeof (*new_anchor));

  if (new_anchor == NULL)
    return -1;

  memcpy (new_anchor, anchor, sizeof (*new_anchor));
  new_anchor->next = validator->anchors;
  validator->anchors = new_anchor;
  validator->anchor_count++;

  return 0;
}

/*
 * Base64 decoder for trust anchor parsing
 */
static int
base64_decode (const char *input,
               unsigned char *output,
               size_t *output_len,
               size_t max_output)
{
  static const unsigned char decode_table[256] = {
    ['A'] = 0,  ['B'] = 1,  ['C'] = 2,  ['D'] = 3,  ['E'] = 4,  ['F'] = 5,
    ['G'] = 6,  ['H'] = 7,  ['I'] = 8,  ['J'] = 9,  ['K'] = 10, ['L'] = 11,
    ['M'] = 12, ['N'] = 13, ['O'] = 14, ['P'] = 15, ['Q'] = 16, ['R'] = 17,
    ['S'] = 18, ['T'] = 19, ['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23,
    ['Y'] = 24, ['Z'] = 25, ['a'] = 26, ['b'] = 27, ['c'] = 28, ['d'] = 29,
    ['e'] = 30, ['f'] = 31, ['g'] = 32, ['h'] = 33, ['i'] = 34, ['j'] = 35,
    ['k'] = 36, ['l'] = 37, ['m'] = 38, ['n'] = 39, ['o'] = 40, ['p'] = 41,
    ['q'] = 42, ['r'] = 43, ['s'] = 44, ['t'] = 45, ['u'] = 46, ['v'] = 47,
    ['w'] = 48, ['x'] = 49, ['y'] = 50, ['z'] = 51, ['0'] = 52, ['1'] = 53,
    ['2'] = 54, ['3'] = 55, ['4'] = 56, ['5'] = 57, ['6'] = 58, ['7'] = 59,
    ['8'] = 60, ['9'] = 61, ['+'] = 62, ['/'] = 63,
  };

  size_t i = 0;
  size_t j = 0;
  size_t len = strlen (input);

  while (i < len)
    {
      /* Skip whitespace */
      if (isspace ((unsigned char)input[i]))
        {
          i++;
          continue;
        }

      /* Padding or end */
      if (input[i] == '=' || input[i] == '\0')
        break;

      /* Decode 4 input chars to 3 output bytes */
      if (i + 3 >= len)
        break;

      unsigned char a = decode_table[(unsigned char)input[i]];
      unsigned char b = decode_table[(unsigned char)input[i + 1]];
      unsigned char c = decode_table[(unsigned char)input[i + 2]];
      unsigned char d = decode_table[(unsigned char)input[i + 3]];

      if (j + 3 > max_output)
        return -1;

      output[j++] = (a << 2) | (b >> 4);
      output[j++] = (b << 4) | (c >> 2);
      output[j++] = (c << 6) | d;

      i += 4;
    }

  *output_len = j;
  return 0;
}

/*
 * Parse DNSKEY from BIND format: flags protocol algorithm base64key
 */
static int
parse_bind_dnskey (const char *zone,
                   const char *fields[],
                   int field_count,
                   SocketDNSSEC_TrustAnchor *anchor,
                   unsigned char *key_buffer,
                   size_t key_buffer_size)
{
  if (field_count < 7)
    return -1;

  /* fields[3] = flags, fields[4] = protocol, fields[5] = algorithm,
   * fields[6] = base64 key */
  unsigned long flags = strtoul (fields[3], NULL, 10);
  unsigned long protocol = strtoul (fields[4], NULL, 10);
  unsigned long algorithm = strtoul (fields[5], NULL, 10);

  if (flags > 65535 || protocol > 255 || algorithm > 255)
    return -1;

  /* Decode base64 public key */
  size_t pubkey_len = 0;
  if (base64_decode (fields[6], key_buffer, &pubkey_len, key_buffer_size) != 0)
    return -1;

  /* Build DNSKEY RDATA for key tag calculation */
  unsigned char rdata[4 + 2048];
  if (pubkey_len + 4 > sizeof (rdata))
    return -1;

  rdata[0] = (unsigned char)((flags >> 8) & 0xFF);
  rdata[1] = (unsigned char)(flags & 0xFF);
  rdata[2] = (unsigned char)protocol;
  rdata[3] = (unsigned char)algorithm;
  memcpy (rdata + 4, key_buffer, pubkey_len);

  /* Fill anchor structure */
  if (!socket_util_safe_strncpy (anchor->zone, zone, sizeof (anchor->zone)))
    return -1; /* Zone name truncated */
  anchor->type = TRUST_ANCHOR_DNSKEY;
  anchor->data.dnskey.flags = (uint16_t)flags;
  anchor->data.dnskey.protocol = (uint8_t)protocol;
  anchor->data.dnskey.algorithm = (uint8_t)algorithm;
  anchor->data.dnskey.pubkey = NULL; /* Will be allocated by caller */
  anchor->data.dnskey.pubkey_len = (uint16_t)pubkey_len;
  anchor->data.dnskey.key_tag
      = SocketDNSSEC_calculate_keytag (rdata, 4 + pubkey_len);

  return 0;
}

/*
 * Parse DS from BIND format: keytag algorithm digesttype digest
 */
static int
parse_bind_ds (const char *zone,
               const char *fields[],
               int field_count,
               SocketDNSSEC_TrustAnchor *anchor,
               unsigned char *digest_buffer,
               size_t digest_buffer_size)
{
  if (field_count < 7)
    return -1;

  /* fields[3] = keytag, fields[4] = algorithm, fields[5] = digesttype,
   * fields[6] = hex digest */
  unsigned long keytag = strtoul (fields[3], NULL, 10);
  unsigned long algorithm = strtoul (fields[4], NULL, 10);
  unsigned long digesttype = strtoul (fields[5], NULL, 10);

  if (keytag > 65535 || algorithm > 255 || digesttype > 255)
    return -1;

  /* Parse hex digest */
  const char *hex = fields[6];
  size_t hex_len = strlen (hex);
  size_t digest_len = hex_len / 2;

  if (digest_len > digest_buffer_size || digest_len > DNSSEC_DS_MAX_DIGEST_LEN)
    return -1;

  for (size_t i = 0; i < digest_len; i++)
    {
      int hi = hex[i * 2];
      int lo = hex[i * 2 + 1];

      if (!isxdigit (hi) || !isxdigit (lo))
        return -1;

      hi = isdigit (hi) ? hi - '0' : tolower (hi) - 'a' + 10;
      lo = isdigit (lo) ? lo - '0' : tolower (lo) - 'a' + 10;

      digest_buffer[i] = (unsigned char)((hi << 4) | lo);
    }

  /* Fill anchor structure */
  if (!socket_util_safe_strncpy (anchor->zone, zone, sizeof (anchor->zone)))
    return -1; /* Zone name truncated */
  anchor->type = TRUST_ANCHOR_DS;
  anchor->data.ds.key_tag = (uint16_t)keytag;
  anchor->data.ds.algorithm = (uint8_t)algorithm;
  anchor->data.ds.digest_type = (uint8_t)digesttype;
  anchor->data.ds.digest = NULL; /* Will be allocated by caller */
  anchor->data.ds.digest_len = (uint16_t)digest_len;

  return 0;
}

int
SocketDNSSEC_validator_load_anchors (SocketDNSSEC_Validator_T validator,
                                     const char *filename)
{
  if (validator == NULL || filename == NULL)
    return -1;

  FILE *fp = fopen (filename, "r");
  if (fp == NULL)
    return -1;

  char line[4096];
  int anchor_count = 0;

  while (fgets (line, sizeof (line), fp) != NULL)
    {
      /* Skip comments and blank lines */
      char *p = line;
      while (isspace ((unsigned char)*p))
        p++;

      if (*p == ';' || *p == '#' || *p == '\0')
        continue;

      /* Parse line into fields */
      const char *fields[16];
      int field_count = 0;
      char *token = strtok (line, " \t\n");

      while (token != NULL && field_count < 16)
        {
          /* Skip comments mid-line */
          if (token[0] == ';' || token[0] == '#')
            break;
          fields[field_count++] = token;
          token = strtok (NULL, " \t\n");
        }

      if (field_count < 5)
        continue;

      /* Extract zone name (fields[0]) */
      char zone[DNS_MAX_NAME_LEN];
      if (!socket_util_safe_strncpy (zone, fields[0], sizeof (zone)))
        continue; /* Skip entry if zone name truncated */

      /* Check for IN class (fields[1]) and record type (fields[2] or fields[3])
       */
      int type_idx = 2;
      if (strcasecmp (fields[1], "IN") == 0)
        type_idx = 2;
      else if (strcasecmp (fields[2], "IN") == 0)
        type_idx = 3;

      if (type_idx >= field_count)
        continue;

      const char *rrtype = fields[type_idx];
      SocketDNSSEC_TrustAnchor anchor;
      memset (&anchor, 0, sizeof (anchor));

      unsigned char data_buffer[2048];
      size_t data_len = 0;

      /* Parse DNSKEY or DS */
      if (strcasecmp (rrtype, "DNSKEY") == 0)
        {
          if (parse_bind_dnskey (zone,
                                 fields,
                                 field_count,
                                 &anchor,
                                 data_buffer,
                                 sizeof (data_buffer))
              != 0)
            continue;
          data_len = anchor.data.dnskey.pubkey_len;

          /* Allocate pubkey in validator's arena */
          unsigned char *pubkey;
          if (validator->arena)
            pubkey
                = Arena_alloc (validator->arena, data_len, __FILE__, __LINE__);
          else
            pubkey = malloc (data_len);

          if (pubkey == NULL)
            {
              fclose (fp);
              return -1;
            }

          memcpy (pubkey, data_buffer, data_len);
          anchor.data.dnskey.pubkey = pubkey;
        }
      else if (strcasecmp (rrtype, "DS") == 0)
        {
          if (parse_bind_ds (zone,
                             fields,
                             field_count,
                             &anchor,
                             data_buffer,
                             sizeof (data_buffer))
              != 0)
            continue;
          data_len = anchor.data.ds.digest_len;

          /* Allocate digest in validator's arena */
          unsigned char *digest;
          if (validator->arena)
            digest
                = Arena_alloc (validator->arena, data_len, __FILE__, __LINE__);
          else
            digest = malloc (data_len);

          if (digest == NULL)
            {
              fclose (fp);
              return -1;
            }

          memcpy (digest, data_buffer, data_len);
          anchor.data.ds.digest = digest;
        }
      else
        {
          /* Unknown record type */
          continue;
        }

      /* Add anchor to validator */
      if (SocketDNSSEC_validator_add_anchor (validator, &anchor) == 0)
        anchor_count++;
    }

  fclose (fp);
  return anchor_count;
}
