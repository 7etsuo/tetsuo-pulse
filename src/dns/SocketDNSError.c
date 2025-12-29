/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketDNSError.c
 * @brief Extended DNS Errors implementation (RFC 8914).
 */

#include "dns/SocketDNSError.h"
#include "dns/SocketDNSWire.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief Error code name table.
 */
static const char *ede_code_names[] = {
  "Other Error",                   /* 0 */
  "Unsupported DNSKEY Algorithm",  /* 1 */
  "Unsupported DS Digest Type",    /* 2 */
  "Stale Answer",                  /* 3 */
  "Forged Answer",                 /* 4 */
  "DNSSEC Indeterminate",          /* 5 */
  "DNSSEC Bogus",                  /* 6 */
  "Signature Expired",             /* 7 */
  "Signature Not Yet Valid",       /* 8 */
  "DNSKEY Missing",                /* 9 */
  "RRSIGs Missing",                /* 10 */
  "No Zone Key Bit Set",           /* 11 */
  "NSEC Missing",                  /* 12 */
  "Cached Error",                  /* 13 */
  "Not Ready",                     /* 14 */
  "Blocked",                       /* 15 */
  "Censored",                      /* 16 */
  "Filtered",                      /* 17 */
  "Prohibited",                    /* 18 */
  "Stale NXDOMAIN Answer",         /* 19 */
  "Not Authoritative",             /* 20 */
  "Not Supported",                 /* 21 */
  "No Reachable Authority",        /* 22 */
  "Network Error",                 /* 23 */
  "Invalid Data"                   /* 24 */
};

/**
 * @brief Error code description table.
 */
static const char *ede_code_descriptions[] = {
  /* 0 */ "Catchall for errors not matching other defined codes",
  /* 1 */ "DNSKEY algorithm not supported by the validator",
  /* 2 */ "DS digest type not supported by the validator",
  /* 3 */ "Answer served from stale cache due to timeout",
  /* 4 */ "Answer was forged or modified by policy",
  /* 5 */ "DNSSEC validation state could not be determined",
  /* 6 */ "DNSSEC validation failed (signature invalid, chain broken, etc.)",
  /* 7 */ "RRSIG validity period has expired",
  /* 8 */ "RRSIG inception time is in the future",
  /* 9 */ "No matching DNSKEY found for RRSIG verification",
  /* 10 */ "No RRSIGs found for the RRset requiring validation",
  /* 11 */ "DNSKEY record has no zone flag set (bit 7)",
  /* 12 */ "NSEC/NSEC3 record missing for denial of existence proof",
  /* 13 */ "Previous SERVFAIL response cached and returned",
  /* 14 */ "Server is not ready to serve queries",
  /* 15 */ "Query blocked by server operator policy",
  /* 16 */ "Answer censored due to external requirement",
  /* 17 */ "Answer filtered per client-requested policy",
  /* 18 */ "Client is not authorized for this query",
  /* 19 */ "Stale NXDOMAIN answer served from cache",
  /* 20 */ "Server is not authoritative and recursion is disabled",
  /* 21 */ "Requested query type or operation not supported",
  /* 22 */ "Cannot reach any authoritative nameservers",
  /* 23 */ "Network error communicating with remote server",
  /* 24 */ "Zone data is too old or has expired"
};

/**
 * @brief Category name table.
 */
static const char *ede_category_names[] = {
  "General",
  "DNSSEC",
  "Stale Cache",
  "Policy/Filter",
  "Server State",
  "Network"
};

/**
 * @brief Lookup table mapping EDE codes to categories.
 *
 * Uses designated initializers to map INFO-CODE to category.
 * Sparse array indexed by code - unmapped entries default to
 * DNS_EDE_CATEGORY_GENERAL (0).
 */
static const SocketDNS_EDECategory ede_code_to_category[] = {
  [DNS_EDE_OTHER]                       = DNS_EDE_CATEGORY_GENERAL,
  [DNS_EDE_UNSUPPORTED_DNSKEY_ALGORITHM] = DNS_EDE_CATEGORY_DNSSEC,
  [DNS_EDE_UNSUPPORTED_DS_DIGEST_TYPE]  = DNS_EDE_CATEGORY_DNSSEC,
  [DNS_EDE_STALE_ANSWER]                = DNS_EDE_CATEGORY_STALE,
  [DNS_EDE_FORGED_ANSWER]               = DNS_EDE_CATEGORY_POLICY,
  [DNS_EDE_DNSSEC_INDETERMINATE]        = DNS_EDE_CATEGORY_DNSSEC,
  [DNS_EDE_DNSSEC_BOGUS]                = DNS_EDE_CATEGORY_DNSSEC,
  [DNS_EDE_SIGNATURE_EXPIRED]           = DNS_EDE_CATEGORY_DNSSEC,
  [DNS_EDE_SIGNATURE_NOT_YET_VALID]     = DNS_EDE_CATEGORY_DNSSEC,
  [DNS_EDE_DNSKEY_MISSING]              = DNS_EDE_CATEGORY_DNSSEC,
  [DNS_EDE_RRSIGS_MISSING]              = DNS_EDE_CATEGORY_DNSSEC,
  [DNS_EDE_NO_ZONE_KEY_BIT_SET]         = DNS_EDE_CATEGORY_DNSSEC,
  [DNS_EDE_NSEC_MISSING]                = DNS_EDE_CATEGORY_DNSSEC,
  [DNS_EDE_CACHED_ERROR]                = DNS_EDE_CATEGORY_SERVER,
  [DNS_EDE_NOT_READY]                   = DNS_EDE_CATEGORY_SERVER,
  [DNS_EDE_BLOCKED]                     = DNS_EDE_CATEGORY_POLICY,
  [DNS_EDE_CENSORED]                    = DNS_EDE_CATEGORY_POLICY,
  [DNS_EDE_FILTERED]                    = DNS_EDE_CATEGORY_POLICY,
  [DNS_EDE_PROHIBITED]                  = DNS_EDE_CATEGORY_POLICY,
  [DNS_EDE_STALE_NXDOMAIN_ANSWER]       = DNS_EDE_CATEGORY_STALE,
  [DNS_EDE_NOT_AUTHORITATIVE]           = DNS_EDE_CATEGORY_SERVER,
  [DNS_EDE_NOT_SUPPORTED]               = DNS_EDE_CATEGORY_SERVER,
  [DNS_EDE_NO_REACHABLE_AUTHORITY]      = DNS_EDE_CATEGORY_NETWORK,
  [DNS_EDE_NETWORK_ERROR]               = DNS_EDE_CATEGORY_NETWORK,
  [DNS_EDE_INVALID_DATA]                = DNS_EDE_CATEGORY_NETWORK
};

/**
 * @brief Validate UTF-8 byte sequence.
 *
 * Simple UTF-8 validation - checks for valid byte sequences.
 *
 * @param data Data to validate.
 * @param len  Length of data.
 * @return true if valid UTF-8, false otherwise.
 */
static bool
validate_utf8 (const unsigned char *data, size_t len)
{
  size_t i = 0;

  while (i < len)
    {
      unsigned char c = data[i];

      if (c < 0x80)
        {
          /* ASCII character */
          i++;
        }
      else if ((c & 0xE0) == 0xC0)
        {
          /* 2-byte sequence */
          if (i + 1 >= len)
            return false;
          if ((data[i + 1] & 0xC0) != 0x80)
            return false;
          /* Check for overlong encoding */
          if (c < 0xC2)
            return false;
          i += 2;
        }
      else if ((c & 0xF0) == 0xE0)
        {
          /* 3-byte sequence */
          if (i + 2 >= len)
            return false;
          if ((data[i + 1] & 0xC0) != 0x80)
            return false;
          if ((data[i + 2] & 0xC0) != 0x80)
            return false;
          /* Check for overlong encoding and surrogates */
          if (c == 0xE0 && data[i + 1] < 0xA0)
            return false;
          if (c == 0xED && data[i + 1] >= 0xA0)
            return false; /* Surrogates */
          i += 3;
        }
      else if ((c & 0xF8) == 0xF0)
        {
          /* 4-byte sequence */
          if (i + 3 >= len)
            return false;
          if ((data[i + 1] & 0xC0) != 0x80)
            return false;
          if ((data[i + 2] & 0xC0) != 0x80)
            return false;
          if ((data[i + 3] & 0xC0) != 0x80)
            return false;
          /* Check for overlong encoding and valid range */
          if (c == 0xF0 && data[i + 1] < 0x90)
            return false;
          if (c == 0xF4 && data[i + 1] >= 0x90)
            return false;
          if (c > 0xF4)
            return false;
          i += 4;
        }
      else
        {
          /* Invalid leading byte */
          return false;
        }
    }

  return true;
}

void
SocketDNS_ede_init (SocketDNS_ExtendedError *ede)
{
  if (ede == NULL)
    return;

  ede->info_code = 0;
  ede->present = false;
  ede->extra_text_len = 0;
  ede->extra_text[0] = '\0';
}

int
SocketDNS_ede_parse (const unsigned char *data, size_t len,
                     SocketDNS_ExtendedError *ede)
{
  if (data == NULL || ede == NULL)
    return -1;

  /* Minimum size is 2 bytes (INFO-CODE only) */
  if (len < DNS_EDE_MIN_SIZE)
    return -1;

  SocketDNS_ede_init (ede);

  /* Parse INFO-CODE (network byte order) */
  ede->info_code = ((uint16_t)data[0] << 8) | data[1];
  ede->present = true;

  /* Parse optional EXTRA-TEXT */
  if (len > DNS_EDE_MIN_SIZE)
    {
      size_t text_len = len - DNS_EDE_MIN_SIZE;
      const unsigned char *text_data = data + DNS_EDE_MIN_SIZE;

      /* Validate UTF-8 */
      if (!validate_utf8 (text_data, text_len))
        {
          /* RFC 8914: EXTRA-TEXT must be valid UTF-8 */
          /* We'll accept the EDE but truncate invalid text */
          ede->extra_text_len = 0;
          ede->extra_text[0] = '\0';
        }
      else
        {
          /* Truncate if too long */
          if (text_len > DNS_EDE_MAX_EXTRA_TEXT)
            text_len = DNS_EDE_MAX_EXTRA_TEXT;

          memcpy (ede->extra_text, text_data, text_len);
          ede->extra_text[text_len] = '\0';
          ede->extra_text_len = text_len;
        }
    }

  return 0;
}

int
SocketDNS_ede_encode (const SocketDNS_ExtendedError *ede, unsigned char *buf,
                      size_t buflen)
{
  if (ede == NULL || buf == NULL)
    return -1;

  /* Validate extra_text_len to prevent overflow */
  if (ede->extra_text_len > DNS_EDE_MAX_EXTRA_TEXT)
    return -1;

  /* Check for size_t overflow before addition */
  if (ede->extra_text_len > SIZE_MAX - DNS_EDE_MIN_SIZE)
    return -1;

  size_t required = DNS_EDE_MIN_SIZE + ede->extra_text_len;

  /* Ensure result fits in uint16_t for EDNS option length field */
  if (required > UINT16_MAX)
    return -1;

  if (buflen < required)
    return -1;

  /* Encode INFO-CODE (network byte order) */
  buf[0] = (ede->info_code >> 8) & 0xFF;
  buf[1] = ede->info_code & 0xFF;

  /* Encode EXTRA-TEXT if present */
  if (ede->extra_text_len > 0)
    memcpy (buf + DNS_EDE_MIN_SIZE, ede->extra_text, ede->extra_text_len);

  return (int)required;
}

const char *
SocketDNS_ede_code_name (uint16_t code)
{
  if (code <= DNS_EDE_MAX_DEFINED)
    return ede_code_names[code];
  return "Unknown Error";
}

const char *
SocketDNS_ede_code_description (uint16_t code)
{
  if (code <= DNS_EDE_MAX_DEFINED)
    return ede_code_descriptions[code];
  return "Unknown extended DNS error code";
}

SocketDNS_EDECategory
SocketDNS_ede_category (uint16_t code)
{
  if (code <= DNS_EDE_MAX_DEFINED)
    return ede_code_to_category[code];
  return DNS_EDE_CATEGORY_GENERAL;
}

const char *
SocketDNS_ede_category_name (SocketDNS_EDECategory category)
{
  if (category <= DNS_EDE_CATEGORY_NETWORK)
    return ede_category_names[category];
  return "Unknown";
}

bool
SocketDNS_ede_is_dnssec_error (uint16_t code)
{
  switch (code)
    {
    case DNS_EDE_UNSUPPORTED_DNSKEY_ALGORITHM:
    case DNS_EDE_UNSUPPORTED_DS_DIGEST_TYPE:
    case DNS_EDE_DNSSEC_INDETERMINATE:
    case DNS_EDE_DNSSEC_BOGUS:
    case DNS_EDE_SIGNATURE_EXPIRED:
    case DNS_EDE_SIGNATURE_NOT_YET_VALID:
    case DNS_EDE_DNSKEY_MISSING:
    case DNS_EDE_RRSIGS_MISSING:
    case DNS_EDE_NO_ZONE_KEY_BIT_SET:
    case DNS_EDE_NSEC_MISSING:
      return true;
    default:
      return false;
    }
}

bool
SocketDNS_ede_is_stale (uint16_t code)
{
  return code == DNS_EDE_STALE_ANSWER || code == DNS_EDE_STALE_NXDOMAIN_ANSWER;
}

bool
SocketDNS_ede_is_filtered (uint16_t code)
{
  switch (code)
    {
    case DNS_EDE_FORGED_ANSWER:
    case DNS_EDE_BLOCKED:
    case DNS_EDE_CENSORED:
    case DNS_EDE_FILTERED:
    case DNS_EDE_PROHIBITED:
      return true;
    default:
      return false;
    }
}

bool
SocketDNS_ede_is_retriable (uint16_t code)
{
  switch (code)
    {
    /* Transient errors - retry may help */
    case DNS_EDE_NOT_READY:
    case DNS_EDE_NO_REACHABLE_AUTHORITY:
    case DNS_EDE_NETWORK_ERROR:
    case DNS_EDE_CACHED_ERROR:
      return true;

    /* Stale answers - server might have fresher data on retry */
    case DNS_EDE_STALE_ANSWER:
    case DNS_EDE_STALE_NXDOMAIN_ANSWER:
      return true;

    /* DNSSEC errors - signature may become valid */
    case DNS_EDE_SIGNATURE_NOT_YET_VALID:
      return true;

    /* All other errors are likely permanent */
    default:
      return false;
    }
}

int
SocketDNS_ede_format (const SocketDNS_ExtendedError *ede, char *buf,
                      size_t buflen)
{
  if (ede == NULL || buf == NULL || buflen == 0)
    return -1;

  if (!ede->present)
    {
      int ret = snprintf (buf, buflen, "(no extended error)");
      return (ret < 0 || (size_t)ret >= buflen) ? -1 : ret;
    }

  const char *name = SocketDNS_ede_code_name (ede->info_code);
  int ret;

  if (ede->extra_text_len > 0)
    ret = snprintf (buf, buflen, "%s (%u): %s", name, ede->info_code,
                    ede->extra_text);
  else
    ret = snprintf (buf, buflen, "%s (%u)", name, ede->info_code);

  return (ret < 0 || (size_t)ret >= buflen) ? -1 : ret;
}

int
SocketDNS_ede_parse_all (const unsigned char *rdata, size_t rdlen,
                         SocketDNS_ExtendedError *ede_array, size_t max_count)
{
  if (rdata == NULL || ede_array == NULL || max_count == 0)
    return -1;

  SocketDNS_EDNSOptionIter iter;
  SocketDNS_EDNSOption opt;
  int count = 0;

  SocketDNS_edns_option_iter_init (&iter, rdata, rdlen);

  while (SocketDNS_edns_option_iter_next (&iter, &opt))
    {
      if (opt.code == DNS_EDE_OPTION_CODE)
        {
          if ((size_t)count >= max_count)
            break;

          if (SocketDNS_ede_parse (opt.data, opt.length,
                                   &ede_array[count]) == 0)
            count++;
        }
    }

  return count;
}

int
SocketDNS_ede_to_edns_option (const SocketDNS_ExtendedError *ede, void *opt,
                              unsigned char *opt_data, size_t data_len)
{
  if (ede == NULL || opt == NULL || opt_data == NULL)
    return -1;

  /* Encode the EDE into the data buffer */
  int encoded_len = SocketDNS_ede_encode (ede, opt_data, data_len);
  if (encoded_len < 0)
    return -1;

  /* Fill in the EDNS option structure */
  SocketDNS_EDNSOption *edns_opt = (SocketDNS_EDNSOption *)opt;
  edns_opt->code = DNS_EDE_OPTION_CODE;
  edns_opt->length = (uint16_t)encoded_len;
  edns_opt->data = opt_data;

  return 0;
}
