/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETDNSERROR_INCLUDED
#define SOCKETDNSERROR_INCLUDED

/**
 * @file SocketDNSError.h
 * @brief Extended DNS Errors (RFC 8914).
 * @ingroup dns
 *
 * Implements Extended DNS Errors (EDE) as specified in RFC 8914.
 * EDE provides detailed error information beyond the traditional 4-bit
 * RCODE, transported via EDNS0 option code 15.
 *
 * ## RFC References
 *
 * - RFC 8914: Extended DNS Errors
 * - RFC 6891: EDNS0 (transport mechanism)
 *
 * ## Features
 *
 * - Parse EDE options from DNS responses
 * - Extract INFO-CODE and EXTRA-TEXT
 * - Support all 25 defined error codes (0-24)
 * - Human-readable error descriptions
 * - Integration with existing EDNS0 infrastructure
 *
 * @see SocketDNSWire.h for EDNS0 option parsing.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @defgroup dns_ede Extended DNS Errors
 * @brief RFC 8914 Extended DNS Error parsing and handling.
 * @ingroup dns
 * @{
 */

/** EDNS0 option code for Extended DNS Errors (RFC 8914). */
#define DNS_EDE_OPTION_CODE 15

/** Minimum EDE option size (INFO-CODE only, no EXTRA-TEXT). */
#define DNS_EDE_MIN_SIZE 2

/** Maximum EXTRA-TEXT length (practical limit). */
#define DNS_EDE_MAX_EXTRA_TEXT 256

/**
 * @brief Extended DNS Error INFO-CODE values (RFC 8914 Section 4).
 *
 * These codes provide detailed error information beyond RCODE.
 * Values 0-24 are defined by RFC 8914. Higher values are reserved
 * for future use and should be treated as "Other Error" (0).
 */
typedef enum
{
  /** Catchall for errors not matching other codes (INFO-CODE 0). */
  DNS_EDE_OTHER = 0,

  /** DNSKEY algorithm not supported by validator (INFO-CODE 1). */
  DNS_EDE_UNSUPPORTED_DNSKEY_ALGORITHM = 1,

  /** DS digest type not supported by validator (INFO-CODE 2). */
  DNS_EDE_UNSUPPORTED_DS_DIGEST_TYPE = 2,

  /** Answer served from stale cache (timeout, INFO-CODE 3). */
  DNS_EDE_STALE_ANSWER = 3,

  /** Answer was forged/modified by policy (INFO-CODE 4). */
  DNS_EDE_FORGED_ANSWER = 4,

  /** DNSSEC validation state indeterminate (INFO-CODE 5). */
  DNS_EDE_DNSSEC_INDETERMINATE = 5,

  /** DNSSEC validation failed (bogus) (INFO-CODE 6). */
  DNS_EDE_DNSSEC_BOGUS = 6,

  /** RRSIG validity period expired (INFO-CODE 7). */
  DNS_EDE_SIGNATURE_EXPIRED = 7,

  /** RRSIG not yet valid (INFO-CODE 8). */
  DNS_EDE_SIGNATURE_NOT_YET_VALID = 8,

  /** No matching DNSKEY for RRSIG (INFO-CODE 9). */
  DNS_EDE_DNSKEY_MISSING = 9,

  /** No RRSIGs found for RRset (INFO-CODE 10). */
  DNS_EDE_RRSIGS_MISSING = 10,

  /** DNSKEY has no zone flag set (INFO-CODE 11). */
  DNS_EDE_NO_ZONE_KEY_BIT_SET = 11,

  /** NSEC/NSEC3 missing for denial of existence (INFO-CODE 12). */
  DNS_EDE_NSEC_MISSING = 12,

  /** Previous SERVFAIL cached and returned (INFO-CODE 13). */
  DNS_EDE_CACHED_ERROR = 13,

  /** Server not ready to serve queries (INFO-CODE 14). */
  DNS_EDE_NOT_READY = 14,

  /** Query blocked by server policy (INFO-CODE 15). */
  DNS_EDE_BLOCKED = 15,

  /** Answer censored by external requirement (INFO-CODE 16). */
  DNS_EDE_CENSORED = 16,

  /** Answer filtered per client request (INFO-CODE 17). */
  DNS_EDE_FILTERED = 17,

  /** Client not authorized (INFO-CODE 18). */
  DNS_EDE_PROHIBITED = 18,

  /** Stale NXDOMAIN served (INFO-CODE 19). */
  DNS_EDE_STALE_NXDOMAIN_ANSWER = 19,

  /** Server not authoritative and recursion disabled (INFO-CODE 20). */
  DNS_EDE_NOT_AUTHORITATIVE = 20,

  /** Query type/operation not supported (INFO-CODE 21). */
  DNS_EDE_NOT_SUPPORTED = 21,

  /** Cannot reach authoritative servers (INFO-CODE 22). */
  DNS_EDE_NO_REACHABLE_AUTHORITY = 22,

  /** Network error reaching remote server (INFO-CODE 23). */
  DNS_EDE_NETWORK_ERROR = 23,

  /** Zone data too old or expired (INFO-CODE 24). */
  DNS_EDE_INVALID_DATA = 24,

  /** Maximum defined INFO-CODE value. */
  DNS_EDE_MAX_DEFINED = 24
} SocketDNS_EDECode;

/**
 * @brief Categorization of EDE codes.
 *
 * Groups related error codes for easier handling.
 */
typedef enum
{
  /** General/unspecified errors. */
  DNS_EDE_CATEGORY_GENERAL = 0,

  /** DNSSEC validation-related errors (codes 1-2, 5-12). */
  DNS_EDE_CATEGORY_DNSSEC = 1,

  /** Stale cache responses (codes 3, 19). */
  DNS_EDE_CATEGORY_STALE = 2,

  /** Policy/filtering errors (codes 4, 15-18). */
  DNS_EDE_CATEGORY_POLICY = 3,

  /** Server state errors (codes 13, 14, 20, 21). */
  DNS_EDE_CATEGORY_SERVER = 4,

  /** Network/reachability errors (codes 22, 23, 24). */
  DNS_EDE_CATEGORY_NETWORK = 5
} SocketDNS_EDECategory;

/**
 * @brief Extended DNS Error structure.
 *
 * Represents a parsed EDE option from a DNS response.
 * May contain optional UTF-8 EXTRA-TEXT for human consumption.
 */
typedef struct
{
  /** INFO-CODE from RFC 8914. */
  uint16_t info_code;

  /** Whether an EDE option was present in the response. */
  bool present;

  /** Length of extra_text in bytes (0 if none). */
  size_t extra_text_len;

  /** Optional UTF-8 extra text (NOT null-terminated in wire format). */
  char extra_text[DNS_EDE_MAX_EXTRA_TEXT + 1];
} SocketDNS_ExtendedError;

/**
 * @brief Initialize an Extended Error structure.
 * @ingroup dns_ede
 *
 * Sets all fields to default/empty values.
 *
 * @param[out] ede Structure to initialize.
 *
 * @code{.c}
 * SocketDNS_ExtendedError ede;
 * SocketDNS_ede_init(&ede);
 * // ede.present = false, ede.info_code = 0, ede.extra_text_len = 0
 * @endcode
 */
extern void SocketDNS_ede_init (SocketDNS_ExtendedError *ede);

/**
 * @brief Parse an EDE option from EDNS0 option data.
 * @ingroup dns_ede
 *
 * Extracts INFO-CODE and optional EXTRA-TEXT from an EDE option.
 * The EXTRA-TEXT is validated as UTF-8 and null-terminated in the output.
 *
 * @param[in]  data    EDE option data (after OPTION-CODE and OPTION-LENGTH).
 * @param[in]  len     Length of option data.
 * @param[out] ede     Output Extended Error structure.
 * @return 0 on success, -1 on error (NULL params, len < 2, or invalid UTF-8).
 *
 * @code{.c}
 * // Assuming we found EDE option in EDNS0 RDATA:
 * SocketDNS_EDNSOption opt;
 * if (SocketDNS_edns_option_find(rdata, rdlen, DNS_EDE_OPTION_CODE, &opt)) {
 *     SocketDNS_ExtendedError ede;
 *     if (SocketDNS_ede_parse(opt.data, opt.length, &ede) == 0) {
 *         printf("EDE: %s\n", SocketDNS_ede_code_name(ede.info_code));
 *         if (ede.extra_text_len > 0) {
 *             printf("  Extra: %s\n", ede.extra_text);
 *         }
 *     }
 * }
 * @endcode
 */
extern int SocketDNS_ede_parse (const unsigned char *data,
                                size_t len,
                                SocketDNS_ExtendedError *ede);

/**
 * @brief Encode an EDE option to wire format.
 * @ingroup dns_ede
 *
 * Serializes an Extended Error to wire format suitable for inclusion
 * in an EDNS0 OPT record RDATA section.
 *
 * @param[in]  ede     Extended Error to encode.
 * @param[out] buf     Output buffer.
 * @param[in]  buflen  Size of output buffer.
 * @return Bytes written on success, -1 on error (buffer too small).
 *
 * @code{.c}
 * SocketDNS_ExtendedError ede;
 * SocketDNS_ede_init(&ede);
 * ede.info_code = DNS_EDE_NETWORK_ERROR;
 * ede.present = true;
 * snprintf(ede.extra_text, sizeof(ede.extra_text), "Connection refused");
 * ede.extra_text_len = strlen(ede.extra_text);
 *
 * unsigned char buf[64];
 * int len = SocketDNS_ede_encode(&ede, buf, sizeof(buf));
 * // len = 2 + strlen("Connection refused")
 * @endcode
 */
extern int SocketDNS_ede_encode (const SocketDNS_ExtendedError *ede,
                                 unsigned char *buf,
                                 size_t buflen);

/**
 * @brief Get human-readable name for an EDE INFO-CODE.
 * @ingroup dns_ede
 *
 * Returns a static string describing the error code.
 * Unknown codes return "Unknown Error".
 *
 * @param[in] code INFO-CODE value.
 * @return Static string name (never NULL).
 *
 * @code{.c}
 * printf("Error: %s\n", SocketDNS_ede_code_name(DNS_EDE_DNSSEC_BOGUS));
 * // Output: "Error: DNSSEC Bogus"
 * @endcode
 */
extern const char *SocketDNS_ede_code_name (uint16_t code);

/**
 * @brief Get detailed description for an EDE INFO-CODE.
 * @ingroup dns_ede
 *
 * Returns a static string with detailed explanation of the error code.
 * Unknown codes return a generic message.
 *
 * @param[in] code INFO-CODE value.
 * @return Static description string (never NULL).
 *
 * @code{.c}
 * printf("Description: %s\n",
 *        SocketDNS_ede_code_description(DNS_EDE_DNSSEC_BOGUS));
 * // Output: "Description: DNSSEC validation failed (signature invalid, chain
 * broken, etc.)"
 * @endcode
 */
extern const char *SocketDNS_ede_code_description (uint16_t code);

/**
 * @brief Get category for an EDE INFO-CODE.
 * @ingroup dns_ede
 *
 * Categorizes the error code for easier handling/display.
 *
 * @param[in] code INFO-CODE value.
 * @return Error category.
 *
 * @code{.c}
 * if (SocketDNS_ede_category(ede.info_code) == DNS_EDE_CATEGORY_DNSSEC) {
 *     printf("DNSSEC validation issue\n");
 * }
 * @endcode
 */
extern SocketDNS_EDECategory SocketDNS_ede_category (uint16_t code);

/**
 * @brief Get category name as string.
 * @ingroup dns_ede
 *
 * @param[in] category Error category.
 * @return Static category name string.
 */
extern const char *SocketDNS_ede_category_name (SocketDNS_EDECategory category);

/**
 * @brief Check if EDE indicates a DNSSEC-related error.
 * @ingroup dns_ede
 *
 * Returns true for INFO-CODEs 1, 2, and 5-12.
 *
 * @param[in] code INFO-CODE value.
 * @return true if DNSSEC-related, false otherwise.
 */
extern bool SocketDNS_ede_is_dnssec_error (uint16_t code);

/**
 * @brief Check if EDE indicates a stale response.
 * @ingroup dns_ede
 *
 * Returns true for INFO-CODEs 3 and 19.
 *
 * @param[in] code INFO-CODE value.
 * @return true if stale response, false otherwise.
 */
extern bool SocketDNS_ede_is_stale (uint16_t code);

/**
 * @brief Check if EDE indicates a policy/filtering action.
 * @ingroup dns_ede
 *
 * Returns true for INFO-CODEs 4, 15, 16, 17, 18.
 *
 * @param[in] code INFO-CODE value.
 * @return true if policy/filter action, false otherwise.
 */
extern bool SocketDNS_ede_is_filtered (uint16_t code);

/**
 * @brief Check if EDE indicates the response may be retried.
 * @ingroup dns_ede
 *
 * Some errors are transient (network issues, server not ready).
 * Returns true if retrying the query might succeed.
 *
 * @param[in] code INFO-CODE value.
 * @return true if retry may help, false if permanent error.
 *
 * @code{.c}
 * if (SocketDNS_ede_is_retriable(ede.info_code)) {
 *     // Retry with exponential backoff
 * } else {
 *     // Don't retry - error is permanent
 * }
 * @endcode
 */
extern bool SocketDNS_ede_is_retriable (uint16_t code);

/**
 * @brief Format an EDE for logging/display.
 * @ingroup dns_ede
 *
 * Creates a formatted string representation of the Extended Error
 * suitable for logging or user display.
 *
 * @param[in]  ede     Extended Error to format.
 * @param[out] buf     Output buffer.
 * @param[in]  buflen  Size of output buffer.
 * @return Length of formatted string (excluding null terminator),
 *         or -1 on error.
 *
 * @code{.c}
 * char msg[256];
 * SocketDNS_ede_format(&ede, msg, sizeof(msg));
 * printf("DNS Error: %s\n", msg);
 * // Output: "DNS Error: DNSSEC Bogus (6): Signature verification failed"
 * @endcode
 */
extern int SocketDNS_ede_format (const SocketDNS_ExtendedError *ede,
                                 char *buf,
                                 size_t buflen);

/**
 * @brief Parse all EDE options from EDNS0 RDATA.
 * @ingroup dns_ede
 *
 * RFC 8914 allows multiple EDE options in a single response.
 * This function extracts all EDE options into an array.
 *
 * @param[in]  rdata     EDNS0 OPT RDATA.
 * @param[in]  rdlen     Length of RDATA.
 * @param[out] ede_array Array to fill with parsed EDE options.
 * @param[in]  max_count Maximum number of entries in array.
 * @return Number of EDE options found, or -1 on error.
 *
 * @code{.c}
 * SocketDNS_ExtendedError errors[4];
 * int count = SocketDNS_ede_parse_all(rdata, rdlen, errors, 4);
 * for (int i = 0; i < count; i++) {
 *     printf("EDE[%d]: %s\n", i, SocketDNS_ede_code_name(errors[i].info_code));
 * }
 * @endcode
 */
extern int SocketDNS_ede_parse_all (const unsigned char *rdata,
                                    size_t rdlen,
                                    SocketDNS_ExtendedError *ede_array,
                                    size_t max_count);

/**
 * @brief Create an EDNS0 option structure from an EDE.
 * @ingroup dns_ede
 *
 * Convenience function to create an EDNS0 option for transmission.
 * The caller must provide a buffer for the option data.
 *
 * @param[in]  ede        Extended Error to convert.
 * @param[out] opt        Output EDNS0 option structure.
 * @param[out] opt_data   Buffer for option data.
 * @param[in]  data_len   Size of opt_data buffer.
 * @return 0 on success, -1 on error.
 */
extern int SocketDNS_ede_to_edns_option (const SocketDNS_ExtendedError *ede,
                                         void *opt,
                                         unsigned char *opt_data,
                                         size_t data_len);

/** @} */ /* End of dns_ede group */

#endif /* SOCKETDNSERROR_INCLUDED */
