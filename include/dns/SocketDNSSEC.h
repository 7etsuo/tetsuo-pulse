/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETDNSSEC_INCLUDED
#define SOCKETDNSSEC_INCLUDED

/**
 * @file SocketDNSSEC.h
 * @brief DNSSEC validation (RFC 4033, 4034, 4035).
 * @ingroup dns
 *
 * Implements DNS Security Extensions for cryptographic verification of
 * DNS responses. Provides data origin authentication and data integrity
 * for DNS records.
 *
 * ## RFC References
 *
 * - RFC 4033: DNS Security Introduction and Requirements
 * - RFC 4034: Resource Records for DNS Security Extensions
 * - RFC 4035: Protocol Modifications for DNS Security Extensions
 * - RFC 5155: NSEC3 Hashed Authenticated Denial of Existence
 *
 * ## DNSSEC Overview
 *
 * DNSSEC provides:
 * - **Data origin authentication**: Verify response came from authoritative
 * source
 * - **Data integrity**: Detect tampering with DNS data
 * - **Authenticated denial of existence**: Prove a name/type doesn't exist
 *
 * DNSSEC does NOT provide:
 * - Confidentiality (use DoT/DoH for encryption)
 * - Protection against DDoS
 *
 * ## Validation States
 *
 * A DNSSEC-aware resolver determines one of four states for each RRset:
 * - **Secure**: Validated via chain of trust from trust anchor
 * - **Insecure**: Provably unsigned (no DS at parent)
 * - **Bogus**: Validation failed (bad signature, expired, etc.)
 * - **Indeterminate**: Cannot determine (network error, missing data)
 *
 * @see SocketDNS.h for the async resolver API.
 * @see SocketDNSWire.h for wire format encoding/decoding.
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "dns/SocketDNSWire.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

/**
 * @defgroup dnssec DNSSEC Validation
 * @brief DNS Security Extensions.
 * @ingroup dns
 * @{
 */

/**
 * @brief DNSSEC operation failure exception.
 * @ingroup dnssec
 *
 * Raised when DNSSEC operations fail:
 * - Invalid DNSSEC record format
 * - Cryptographic verification failure
 * - Trust chain validation failure
 * - Resource allocation failure
 */
extern const Except_T SocketDNSSEC_Failed;

/**
 * @defgroup dnssec_types DNSSEC Record Types
 * @brief DNSSEC resource record type constants.
 * @ingroup dnssec
 * @{
 */

/** DNSKEY resource record type (RFC 4034). Public keys for zone signing. */
#define DNS_TYPE_DNSKEY 48

/** RRSIG resource record type (RFC 4034). Signatures over RRsets. */
#define DNS_TYPE_RRSIG 46

/** DS resource record type (RFC 4034). Delegation Signer (parent hash). */
#define DNS_TYPE_DS 43

/** NSEC resource record type (RFC 4034). Authenticated denial of existence. */
#define DNS_TYPE_NSEC 47

/** NSEC3 resource record type (RFC 5155). Hashed denial of existence. */
#define DNS_TYPE_NSEC3 50

/** NSEC3PARAM resource record type (RFC 5155). NSEC3 parameters. */
#define DNS_TYPE_NSEC3PARAM 51

/** @} */ /* End of dnssec_types group */

/**
 * @defgroup dnssec_algorithms DNSSEC Algorithm Numbers
 * @brief Cryptographic algorithm identifiers (RFC 4034 Appendix A).
 * @ingroup dnssec
 * @{
 */

typedef enum
{
  DNSSEC_ALGO_DELETE = 0,         /**< Reserved for delete DS (RFC 8078) */
  DNSSEC_ALGO_RSAMD5 = 1,         /**< RSA/MD5 - NOT RECOMMENDED (RFC 3110) */
  DNSSEC_ALGO_DH = 2,             /**< Diffie-Hellman (RFC 2539) */
  DNSSEC_ALGO_DSA = 3,            /**< DSA/SHA-1 (RFC 2536) */
  DNSSEC_ALGO_RSASHA1 = 5,        /**< RSA/SHA-1 (RFC 3110) */
  DNSSEC_ALGO_DSA_NSEC3_SHA1 = 6, /**< DSA-NSEC3-SHA1 (RFC 5155) */
  DNSSEC_ALGO_RSASHA1_NSEC3_SHA1 = 7, /**< RSA/SHA-1-NSEC3-SHA1 (RFC 5155) */
  DNSSEC_ALGO_RSASHA256 = 8,        /**< RSA/SHA-256 (RFC 5702) - RECOMMENDED */
  DNSSEC_ALGO_RSASHA512 = 10,       /**< RSA/SHA-512 (RFC 5702) */
  DNSSEC_ALGO_ECC_GOST = 12,        /**< GOST R 34.10-2001 (RFC 5933) */
  DNSSEC_ALGO_ECDSAP256SHA256 = 13, /**< ECDSA P-256/SHA-256 (RFC 6605) */
  DNSSEC_ALGO_ECDSAP384SHA384 = 14, /**< ECDSA P-384/SHA-384 (RFC 6605) */
  DNSSEC_ALGO_ED25519 = 15,         /**< Ed25519 (RFC 8080) */
  DNSSEC_ALGO_ED448 = 16,           /**< Ed448 (RFC 8080) */
  DNSSEC_ALGO_INDIRECT = 252,       /**< Indirect (RFC 4034) */
  DNSSEC_ALGO_PRIVATEDNS = 253,     /**< Private DNS (RFC 4034) */
  DNSSEC_ALGO_PRIVATEOID = 254,     /**< Private OID (RFC 4034) */
} SocketDNSSEC_Algorithm;

/** @} */ /* End of dnssec_algorithms group */

/**
 * @defgroup dnssec_digest DNSSEC Digest Types
 * @brief DS record digest algorithm identifiers (RFC 4034 Appendix A.2).
 * @ingroup dnssec
 * @{
 */

typedef enum
{
  DNSSEC_DIGEST_SHA1 = 1,   /**< SHA-1 (RFC 4034) - 20 bytes */
  DNSSEC_DIGEST_SHA256 = 2, /**< SHA-256 (RFC 4509) - 32 bytes */
  DNSSEC_DIGEST_GOST = 3,   /**< GOST R 34.11-94 (RFC 5933) - 32 bytes */
  DNSSEC_DIGEST_SHA384 = 4, /**< SHA-384 (RFC 6605) - 48 bytes */
} SocketDNSSEC_DigestType;

/** @} */ /* End of dnssec_digest group */

/**
 * @defgroup dnssec_flags DNSSEC Key Flags
 * @brief DNSKEY flags field bits (RFC 4034 Section 2.1.1).
 * @ingroup dnssec
 * @{
 */

/** Zone Key flag - bit 7 (value 256). Key can sign zone data. */
#define DNSKEY_FLAG_ZONE_KEY 0x0100

/** Secure Entry Point flag - bit 15 (value 1). Key is a KSK. */
#define DNSKEY_FLAG_SEP 0x0001

/** Revoke flag - bit 8 (value 128). Key is revoked (RFC 5011). */
#define DNSKEY_FLAG_REVOKE 0x0080

/** @} */ /* End of dnssec_flags group */

/**
 * @defgroup dnssec_validation DNSSEC Validation Status
 * @brief Validation result states (RFC 4033 Section 5).
 * @ingroup dnssec
 * @{
 */

typedef enum
{
  DNSSEC_SECURE = 0,       /**< Validated successfully via chain of trust */
  DNSSEC_INSECURE = 1,     /**< Provably unsigned (no DS at parent) */
  DNSSEC_BOGUS = 2,        /**< Validation failed */
  DNSSEC_INDETERMINATE = 3 /**< Cannot determine (network error, etc.) */
} SocketDNSSEC_Status;

/** @} */ /* End of dnssec_validation group */

/**
 * @defgroup dnssec_records DNSSEC Record Structures
 * @brief Parsed DNSSEC resource record structures.
 * @ingroup dnssec
 * @{
 */

/**
 * @brief DNSKEY record RDATA (RFC 4034 Section 2).
 *
 * Public key used to verify RRSIG signatures.
 *
 * ## Wire Format
 *
 * ```
 *                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |              Flags            |    Protocol   |   Algorithm   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                                                               /
 * /                            Public Key                         /
 * /                                                               /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ```
 */
typedef struct
{
  uint16_t flags;              /**< Key flags (ZONE, SEP, REVOKE) */
  uint8_t protocol;            /**< Protocol field (must be 3) */
  uint8_t algorithm;           /**< Algorithm number (SocketDNSSEC_Algorithm) */
  const unsigned char *pubkey; /**< Public key data (points into message) */
  uint16_t pubkey_len;         /**< Length of public key in bytes */
  uint16_t key_tag;            /**< Calculated key tag (RFC 4034 Appendix B) */
} SocketDNSSEC_DNSKEY;

/** Minimum DNSKEY RDATA size (flags + protocol + algorithm = 4 bytes). */
#define DNSSEC_DNSKEY_FIXED_SIZE 4

/**
 * @brief RRSIG record RDATA (RFC 4034 Section 3).
 *
 * Digital signature over an RRset.
 *
 * ## Wire Format
 *
 * ```
 *                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |        Type Covered           |  Algorithm    |     Labels    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Original TTL                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      Signature Expiration                     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      Signature Inception                      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |            Key Tag            |                               /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         Signer's Name         /
 * /                                                               /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                                                               /
 * /                            Signature                          /
 * /                                                               /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ```
 */
typedef struct
{
  uint16_t type_covered;   /**< RR type covered by signature */
  uint8_t algorithm;       /**< Signing algorithm */
  uint8_t labels;          /**< Labels in original owner name */
  uint32_t original_ttl;   /**< Original TTL of covered RRset */
  uint32_t sig_expiration; /**< Signature expiration (Unix timestamp) */
  uint32_t sig_inception;  /**< Signature inception (Unix timestamp) */
  uint16_t key_tag;        /**< Key tag of signing DNSKEY */
  char signer_name[DNS_MAX_NAME_LEN]; /**< Signer's domain name */
  const unsigned char *signature; /**< Signature data (points into message) */
  uint16_t signature_len;         /**< Length of signature in bytes */
} SocketDNSSEC_RRSIG;

/** Minimum RRSIG RDATA fixed fields size (before signer name). */
#define DNSSEC_RRSIG_FIXED_SIZE 18

/**
 * @brief DS record RDATA (RFC 4034 Section 5).
 *
 * Delegation Signer - hash of child zone's DNSKEY.
 * Stored in parent zone to establish chain of trust.
 *
 * ## Wire Format
 *
 * ```
 *                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Key Tag             |  Algorithm    |  Digest Type  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                                                               /
 * /                            Digest                             /
 * /                                                               /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ```
 */
typedef struct
{
  uint16_t key_tag;    /**< Key tag of referenced DNSKEY */
  uint8_t algorithm;   /**< Algorithm of referenced DNSKEY */
  uint8_t digest_type; /**< Digest algorithm (SocketDNSSEC_DigestType) */
  const unsigned char *digest; /**< Digest data (points into message) */
  uint16_t digest_len;         /**< Length of digest in bytes */
} SocketDNSSEC_DS;

/** Minimum DS RDATA fixed fields size (before digest). */
#define DNSSEC_DS_FIXED_SIZE 4

/** Maximum DS digest size (SHA-384 = 48 bytes). */
#define DNSSEC_DS_MAX_DIGEST_LEN 48

/**
 * @brief NSEC record RDATA (RFC 4034 Section 4).
 *
 * Next Secure record - proves authenticated denial of existence.
 * Lists the next owner name and the RR types present at this name.
 *
 * ## Wire Format
 *
 * ```
 *                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                      Next Domain Name                         /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                       Type Bit Maps                           /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ```
 */
typedef struct
{
  char next_domain[DNS_MAX_NAME_LEN]; /**< Next owner name in canonical order */
  const unsigned char *type_bitmaps;  /**< Type bitmap data (points into msg) */
  uint16_t type_bitmaps_len;          /**< Length of type bitmaps in bytes */
} SocketDNSSEC_NSEC;

/**
 * @brief NSEC3 record RDATA (RFC 5155).
 *
 * Hashed authenticated denial of existence.
 * Uses hashed owner names to prevent zone enumeration.
 *
 * ## Wire Format
 *
 * ```
 *                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Hash Alg    |     Flags     |          Iterations           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Salt Length  |                     Salt                      /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Hash Length  |             Next Hashed Owner Name            /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                         Type Bit Maps                         /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ```
 */
typedef struct
{
  uint8_t hash_algorithm;            /**< Hash algorithm (1 = SHA-1) */
  uint8_t flags;                     /**< Flags (bit 0 = opt-out) */
  uint16_t iterations;               /**< Hash iterations */
  uint8_t salt_len;                  /**< Salt length */
  const unsigned char *salt;         /**< Salt data (points into message) */
  uint8_t hash_len;                  /**< Next hashed owner length */
  const unsigned char *next_hashed;  /**< Next hashed owner (points into msg) */
  const unsigned char *type_bitmaps; /**< Type bitmap data (points into msg) */
  uint16_t type_bitmaps_len;         /**< Length of type bitmaps in bytes */
} SocketDNSSEC_NSEC3;

/** NSEC3 minimum fixed fields size. */
#define DNSSEC_NSEC3_FIXED_SIZE 5

/** NSEC3 opt-out flag (bit 0). */
#define NSEC3_FLAG_OPT_OUT 0x01

/** @} */ /* End of dnssec_records group */

/**
 * @defgroup dnssec_parsing DNSSEC Record Parsing
 * @brief Functions to parse DNSSEC resource records.
 * @ingroup dnssec
 * @{
 */

/**
 * @brief Parse DNSKEY record RDATA.
 * @ingroup dnssec_parsing
 *
 * Parses DNSKEY RDATA from wire format and calculates the key tag.
 *
 * @param[in]  rr     Resource record with TYPE=DNSKEY.
 * @param[out] dnskey Output DNSKEY structure.
 * @return 0 on success, -1 on error (wrong type, too short, invalid).
 *
 * @code{.c}
 * SocketDNS_RR rr;
 * if (SocketDNS_rr_decode(msg, msglen, offset, &rr, NULL) == 0) {
 *     if (rr.type == DNS_TYPE_DNSKEY) {
 *         SocketDNSSEC_DNSKEY dnskey;
 *         if (SocketDNSSEC_parse_dnskey(&rr, &dnskey) == 0) {
 *             printf("DNSKEY: flags=%u algo=%u tag=%u\n",
 *                    dnskey.flags, dnskey.algorithm, dnskey.key_tag);
 *         }
 *     }
 * }
 * @endcode
 */
extern int
SocketDNSSEC_parse_dnskey (const SocketDNS_RR *rr, SocketDNSSEC_DNSKEY *dnskey);

/**
 * @brief Parse RRSIG record RDATA.
 * @ingroup dnssec_parsing
 *
 * Parses RRSIG RDATA from wire format, including the signer's name
 * which may use compression pointers.
 *
 * @param[in]  msg    Full DNS message buffer (for compression pointers).
 * @param[in]  msglen Total length of the DNS message.
 * @param[in]  rr     Resource record with TYPE=RRSIG.
 * @param[out] rrsig  Output RRSIG structure.
 * @return 0 on success, -1 on error.
 *
 * @code{.c}
 * SocketDNS_RR rr;
 * if (SocketDNS_rr_decode(msg, msglen, offset, &rr, NULL) == 0) {
 *     if (rr.type == DNS_TYPE_RRSIG) {
 *         SocketDNSSEC_RRSIG rrsig;
 *         if (SocketDNSSEC_parse_rrsig(msg, msglen, &rr, &rrsig) == 0) {
 *             printf("RRSIG: covers=%u signer=%s tag=%u\n",
 *                    rrsig.type_covered, rrsig.signer_name, rrsig.key_tag);
 *         }
 *     }
 * }
 * @endcode
 */
extern int SocketDNSSEC_parse_rrsig (const unsigned char *msg,
                                     size_t msglen,
                                     const SocketDNS_RR *rr,
                                     SocketDNSSEC_RRSIG *rrsig);

/**
 * @brief Parse DS record RDATA.
 * @ingroup dnssec_parsing
 *
 * Parses DS RDATA from wire format.
 *
 * @param[in]  rr Resource record with TYPE=DS.
 * @param[out] ds Output DS structure.
 * @return 0 on success, -1 on error.
 */
extern int SocketDNSSEC_parse_ds (const SocketDNS_RR *rr, SocketDNSSEC_DS *ds);

/**
 * @brief Parse NSEC record RDATA.
 * @ingroup dnssec_parsing
 *
 * Parses NSEC RDATA from wire format, including the next domain name
 * which may use compression pointers.
 *
 * @param[in]  msg    Full DNS message buffer (for compression pointers).
 * @param[in]  msglen Total length of the DNS message.
 * @param[in]  rr     Resource record with TYPE=NSEC.
 * @param[out] nsec   Output NSEC structure.
 * @return 0 on success, -1 on error.
 */
extern int SocketDNSSEC_parse_nsec (const unsigned char *msg,
                                    size_t msglen,
                                    const SocketDNS_RR *rr,
                                    SocketDNSSEC_NSEC *nsec);

/**
 * @brief Parse NSEC3 record RDATA.
 * @ingroup dnssec_parsing
 *
 * Parses NSEC3 RDATA from wire format.
 *
 * @param[in]  rr    Resource record with TYPE=NSEC3.
 * @param[out] nsec3 Output NSEC3 structure.
 * @return 0 on success, -1 on error.
 */
extern int
SocketDNSSEC_parse_nsec3 (const SocketDNS_RR *rr, SocketDNSSEC_NSEC3 *nsec3);

/**
 * @brief Check if a type is present in NSEC/NSEC3 type bitmaps.
 * @ingroup dnssec_parsing
 *
 * Searches the type bitmap for a specific RR type. Used to verify
 * authenticated denial of existence.
 *
 * @param[in] bitmaps    Type bitmap data from NSEC/NSEC3 record.
 * @param[in] bitmaps_len Length of bitmap data.
 * @param[in] rrtype     RR type to check for.
 * @return 1 if type is present, 0 if absent, -1 on error.
 *
 * @code{.c}
 * SocketDNSSEC_NSEC nsec;
 * // ... parse nsec ...
 * if (SocketDNSSEC_type_in_bitmap(nsec.type_bitmaps, nsec.type_bitmaps_len,
 *                                  DNS_TYPE_A)) {
 *     printf("A record exists at this name\n");
 * } else {
 *     printf("No A record at this name (authenticated denial)\n");
 * }
 * @endcode
 */
extern int SocketDNSSEC_type_in_bitmap (const unsigned char *bitmaps,
                                        size_t bitmaps_len,
                                        uint16_t rrtype);

/** @} */ /* End of dnssec_parsing group */

/**
 * @defgroup dnssec_keytag Key Tag Calculation
 * @brief Functions to calculate DNSKEY key tags.
 * @ingroup dnssec
 * @{
 */

/**
 * @brief Calculate key tag for a DNSKEY record (RFC 4034 Appendix B).
 * @ingroup dnssec_keytag
 *
 * Computes the key tag value used to identify DNSKEY records in RRSIG
 * and DS records. The key tag is a 16-bit checksum of the DNSKEY RDATA.
 *
 * @param[in] rdata   DNSKEY RDATA (flags + protocol + algorithm + pubkey).
 * @param[in] rdlen   Length of RDATA.
 * @return Key tag value (0-65535).
 *
 * @note Algorithm 1 (RSA/MD5) uses a different calculation - see RFC 4034 B.1.
 */
extern uint16_t
SocketDNSSEC_calculate_keytag (const unsigned char *rdata, size_t rdlen);

/** @} */ /* End of dnssec_keytag group */

/**
 * @defgroup dnssec_validation_funcs DNSSEC Validation Functions
 * @brief Functions to validate DNSSEC signatures and chains.
 * @ingroup dnssec
 * @{
 */

/**
 * @brief Check if an RRSIG is within its validity period.
 * @ingroup dnssec_validation_funcs
 *
 * Verifies that the current time is between the signature inception
 * and expiration times. Uses serial number arithmetic for wrap-around
 * handling as specified in RFC 4034 Section 3.1.5.
 *
 * @param[in] rrsig RRSIG record to check.
 * @param[in] now   Current time (Unix timestamp), or 0 to use current time.
 * @return 1 if valid, 0 if expired/not-yet-valid, -1 on error.
 */
extern int
SocketDNSSEC_rrsig_valid_time (const SocketDNSSEC_RRSIG *rrsig, time_t now);

/**
 * @brief Verify an RRSIG signature over an RRset.
 * @ingroup dnssec_validation_funcs
 *
 * Performs cryptographic verification of the signature using the provided
 * DNSKEY. Constructs the canonical signed data from the RRset and verifies
 * the signature.
 *
 * @param[in] rrsig  RRSIG record containing the signature.
 * @param[in] dnskey DNSKEY record containing the public key.
 * @param[in] msg    Full DNS message buffer.
 * @param[in] msglen Total length of the DNS message.
 * @param[in] rrset_offset Offset to start of RRset in message.
 * @param[in] rrset_count  Number of RRs in the RRset.
 * @return DNSSEC_SECURE on success, DNSSEC_BOGUS on failure, negative on error.
 *
 * @note Requires OpenSSL/LibreSSL for cryptographic operations.
 */
extern int SocketDNSSEC_verify_rrsig (const SocketDNSSEC_RRSIG *rrsig,
                                      const SocketDNSSEC_DNSKEY *dnskey,
                                      const unsigned char *msg,
                                      size_t msglen,
                                      size_t rrset_offset,
                                      size_t rrset_count);

/**
 * @brief Verify a DS record matches a DNSKEY.
 * @ingroup dnssec_validation_funcs
 *
 * Computes the digest of the DNSKEY owner name and RDATA, then compares
 * it to the digest in the DS record.
 *
 * @param[in] ds          DS record to verify.
 * @param[in] dnskey      DNSKEY record to check against.
 * @param[in] owner_name  Owner name of the DNSKEY (canonical form).
 * @return 1 if DS matches DNSKEY, 0 if no match, -1 on error.
 */
extern int SocketDNSSEC_verify_ds (const SocketDNSSEC_DS *ds,
                                   const SocketDNSSEC_DNSKEY *dnskey,
                                   const char *owner_name);

/**
 * @brief Check if an algorithm is supported for validation.
 * @ingroup dnssec_validation_funcs
 *
 * @param[in] algorithm DNSSEC algorithm number.
 * @return 1 if supported, 0 if not supported.
 */
extern int SocketDNSSEC_algorithm_supported (uint8_t algorithm);

/**
 * @brief Check if a digest type is supported for DS validation.
 * @ingroup dnssec_validation_funcs
 *
 * @param[in] digest_type DS digest type number.
 * @return 1 if supported, 0 if not supported.
 */
extern int SocketDNSSEC_digest_supported (uint8_t digest_type);

/** @} */ /* End of dnssec_validation_funcs group */

/**
 * @defgroup dnssec_trust Trust Anchor Management
 * @brief Functions to manage DNSSEC trust anchors.
 * @ingroup dnssec
 * @{
 */

/** Root DNSKEY key tag for KSK-2017 (id 20326). */
#define DNSSEC_ROOT_KSK_2017_KEYTAG 20326

/**
 * @brief DNSSEC trust anchor structure.
 *
 * Represents a configured trust anchor (DNSKEY or DS) for a zone.
 * Trust anchors are the starting points for building authentication chains.
 */
typedef struct SocketDNSSEC_TrustAnchor
{
  char zone[DNS_MAX_NAME_LEN]; /**< Zone name this anchor is for */
  enum
  {
    TRUST_ANCHOR_DNSKEY,
    TRUST_ANCHOR_DS
  } type;
  union
  {
    SocketDNSSEC_DNSKEY dnskey;
    SocketDNSSEC_DS ds;
  } data;
  struct SocketDNSSEC_TrustAnchor *next; /**< Next anchor in list */
} SocketDNSSEC_TrustAnchor;

/**
 * @brief DNSSEC validator context.
 *
 * Holds configuration and state for DNSSEC validation including
 * trust anchors and cached validated keys.
 */
typedef struct SocketDNSSEC_Validator *SocketDNSSEC_Validator_T;

/**
 * @brief Create a new DNSSEC validator.
 * @ingroup dnssec_trust
 *
 * Creates a validator context with the built-in root trust anchor.
 *
 * @param[in] arena Arena for memory allocation (NULL = global heap).
 * @return New validator, or NULL on failure.
 */
extern SocketDNSSEC_Validator_T SocketDNSSEC_validator_new (Arena_T arena);

/**
 * @brief Free a DNSSEC validator.
 * @ingroup dnssec_trust
 *
 * @param[in,out] validator Validator to free (set to NULL).
 */
extern void SocketDNSSEC_validator_free (SocketDNSSEC_Validator_T *validator);

/**
 * @brief Add a trust anchor to the validator.
 * @ingroup dnssec_trust
 *
 * @param[in] validator Validator context.
 * @param[in] anchor    Trust anchor to add (copied).
 * @return 0 on success, -1 on error.
 */
extern int
SocketDNSSEC_validator_add_anchor (SocketDNSSEC_Validator_T validator,
                                   const SocketDNSSEC_TrustAnchor *anchor);

/**
 * @brief Load trust anchors from a file.
 * @ingroup dnssec_trust
 *
 * Loads trust anchors in BIND format from a file.
 *
 * @param[in] validator Validator context.
 * @param[in] filename  Path to trust anchor file.
 * @return Number of anchors loaded, or -1 on error.
 */
extern int
SocketDNSSEC_validator_load_anchors (SocketDNSSEC_Validator_T validator,
                                     const char *filename);

/** @} */ /* End of dnssec_trust group */

/**
 * @defgroup dnssec_canonical Canonical Form Functions
 * @brief Functions for canonical DNS name and RR ordering.
 * @ingroup dnssec
 * @{
 */

/**
 * @brief Convert a domain name to canonical (lowercase) form.
 * @ingroup dnssec_canonical
 *
 * Converts uppercase ASCII letters to lowercase as required for
 * DNSSEC signature verification (RFC 4034 Section 6.2).
 *
 * @param[in,out] name Domain name to canonicalize (modified in place).
 */
extern void SocketDNSSEC_name_canonicalize (char *name);

/**
 * @brief Compare two domain names in canonical order.
 * @ingroup dnssec_canonical
 *
 * Compares names according to canonical DNS name ordering as specified
 * in RFC 4034 Section 6.1. Used for NSEC chain verification.
 *
 * @param[in] name1 First domain name.
 * @param[in] name2 Second domain name.
 * @return <0 if name1 < name2, 0 if equal, >0 if name1 > name2.
 */
extern int
SocketDNSSEC_name_canonical_compare (const char *name1, const char *name2);

/** @} */ /* End of dnssec_canonical group */

/** @} */ /* End of dnssec group */

#endif /* SOCKETDNSSEC_INCLUDED */
