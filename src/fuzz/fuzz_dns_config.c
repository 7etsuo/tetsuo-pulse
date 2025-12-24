/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_dns_config.c - libFuzzer harness for DNS config parsing (RFC 1035)
 *
 * Targets resolv.conf parsing (resolv.conf(5) manpage specification):
 * - SocketDNSConfig_parse()
 * - parse_line()
 * - parse_options()
 * - next_token()
 * - SocketDNSConfig_add_nameserver()
 * - SocketDNSConfig_add_search()
 * - detect_address_family()
 *
 * Also targets Extended DNS Errors (RFC 8914):
 * - SocketDNSError_from_ede()
 * - SocketDNSError_get_info_code()
 * - SocketDNSError_get_extra_text()
 * - SocketDNSError_format_error()
 *
 * Attack surface:
 * 1. Malformed resolv.conf directives (nameserver, search, domain, options)
 * 2. Invalid IP addresses (IPv4/IPv6 format errors, overflow, underflow)
 * 3. Oversized search domains (>255 chars, >6 domains, >256 total)
 * 4. Option parsing edge cases (invalid values, overflow, malformed key:value)
 * 5. Buffer handling (strncpy, fgets line buffer, token parsing)
 * 6. Extended DNS Error codes (0-65535 range, UTF-8 EXTRA-TEXT validation)
 * 7. Comment and whitespace handling (#, ;, tabs, spaces)
 * 8. Line truncation and continuation
 *
 * Test cases:
 * - Complete resolv.conf content
 * - Malformed nameserver lines (garbage, non-IP, mixed IPv4/IPv6)
 * - Invalid IP addresses (overflow, trailing garbage, partial)
 * - Buffer overflows in option parsing (timeout:999999, attempts:999999)
 * - Search domain edge cases (empty, too long, too many, special chars)
 * - All RFC 8914 EDE codes (0-24 + undefined 25-65535)
 * - UTF-8 validation in EXTRA-TEXT (valid, invalid, overlong, truncated)
 * - Mixed valid/invalid directives
 * - Boundary conditions (max nameservers, max search domains)
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_dns_config
 * Run:   ./fuzz_dns_config corpus/dns_config/ -fork=16 -max_len=8192
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "dns/SocketDNSConfig.h"
#include "dns/SocketDNSError.h"
#include "dns/SocketDNSWire.h"

/* Maximum resolv.conf size to fuzz (realistic limit) */
#define MAX_FUZZ_CONFIG_SIZE 8192

/* Maximum EDE EXTRA-TEXT length to test */
#define MAX_EDE_EXTRA_TEXT 512

/**
 * @brief Test resolv.conf parsing with fuzzer input.
 *
 * Parses the input as resolv.conf content and exercises all parsing paths.
 */
static void
fuzz_resolv_conf_parsing (const uint8_t *data, size_t size)
{
  SocketDNSConfig_T config;
  char *content;

  if (size == 0 || size > MAX_FUZZ_CONFIG_SIZE)
    return;

  /* Null-terminate input for parsing */
  content = (char *)malloc (size + 1);
  if (content == NULL)
    return;

  memcpy (content, data, size);
  content[size] = '\0';

  /* Parse configuration */
  (void)SocketDNSConfig_parse (&config, content);

  free (content);

  /* Test accessors with parsed config */
  (void)SocketDNSConfig_has_rotate (&config);
  (void)SocketDNSConfig_has_edns0 (&config);
  (void)SocketDNSConfig_use_tcp (&config);
  (void)SocketDNSConfig_local_domain (&config);
}

/**
 * @brief Test nameserver addition with fuzzer input.
 *
 * Exercises IP address validation (IPv4/IPv6) and nameserver limits.
 */
static void
fuzz_nameserver_addition (const uint8_t *data, size_t size)
{
  SocketDNSConfig_T config;
  char *address;

  if (size == 0 || size > 256)
    return;

  address = (char *)malloc (size + 1);
  if (address == NULL)
    return;

  memcpy (address, data, size);
  address[size] = '\0';

  SocketDNSConfig_init (&config);

  /* Try adding as nameserver (tests IP validation) */
  (void)SocketDNSConfig_add_nameserver (&config, address);

  /* Try adding multiple times to test limits */
  for (int i = 0; i < DNS_CONFIG_MAX_NAMESERVERS + 2; i++)
    {
      (void)SocketDNSConfig_add_nameserver (&config, address);
    }

  free (address);
}

/**
 * @brief Test search domain addition with fuzzer input.
 *
 * Exercises domain length validation and search domain limits.
 */
static void
fuzz_search_domain_addition (const uint8_t *data, size_t size)
{
  SocketDNSConfig_T config;
  char *domain;

  if (size == 0 || size > DNS_CONFIG_MAX_DOMAIN_LEN + 100)
    return;

  domain = (char *)malloc (size + 1);
  if (domain == NULL)
    return;

  memcpy (domain, data, size);
  domain[size] = '\0';

  SocketDNSConfig_init (&config);

  /* Try adding as search domain */
  (void)SocketDNSConfig_add_search (&config, domain);

  /* Try adding multiple times to test limits */
  for (int i = 0; i < DNS_CONFIG_MAX_SEARCH_DOMAINS + 2; i++)
    {
      (void)SocketDNSConfig_add_search (&config, domain);
    }

  free (domain);
}

/**
 * @brief Test Extended DNS Error parsing with fuzzer input.
 *
 * Exercises RFC 8914 EDE option parsing and validation.
 */
static void
fuzz_ede_parsing (const uint8_t *data, size_t size)
{
  SocketDNS_ExtendedError ede;

  if (size < 2)
    return;

  /* Parse EDE option using correct API */
  if (SocketDNS_ede_parse (data, size, &ede) == 0)
    {
      /* Test accessors via struct fields */
      (void)ede.info_code;
      (void)ede.extra_text;
      (void)ede.extra_text_len;
      (void)ede.present;

      /* Test category and type checks */
      (void)SocketDNS_ede_category (ede.info_code);
      (void)SocketDNS_ede_is_dnssec_error (ede.info_code);
      (void)SocketDNS_ede_is_stale (ede.info_code);
      (void)SocketDNS_ede_is_filtered (ede.info_code);
      (void)SocketDNS_ede_is_retriable (ede.info_code);

      /* Test formatting */
      char error_buf[512];
      (void)SocketDNS_ede_format (&ede, error_buf, sizeof (error_buf));

      /* Test name and description */
      (void)SocketDNS_ede_code_name (ede.info_code);
      (void)SocketDNS_ede_code_description (ede.info_code);
    }

  /* Test all defined EDE codes (0-24) */
  for (int code = 0; code <= DNS_EDE_MAX_DEFINED; code++)
    {
      (void)SocketDNS_ede_code_name (code);
      (void)SocketDNS_ede_code_description (code);
      (void)SocketDNS_ede_category (code);
      (void)SocketDNS_ede_category_name (SocketDNS_ede_category (code));
    }
}

/**
 * @brief Test configuration limits and boundary conditions.
 *
 * Exercises edge cases like maximum counts, empty values, etc.
 */
static void
fuzz_config_limits (const uint8_t *data, size_t size)
{
  SocketDNSConfig_T config;
  char content[1024];
  size_t offset = 0;

  if (size == 0)
    return;

  SocketDNSConfig_init (&config);

  /* Build pathological resolv.conf content */
  memset (content, 0, sizeof (content));

  /* Add too many nameservers */
  for (int i = 0; i < DNS_CONFIG_MAX_NAMESERVERS + 2 && offset < sizeof (content) - 50; i++)
    {
      /* Use fuzzer data for IP addresses */
      if (size >= 4)
        {
          offset += snprintf (content + offset, sizeof (content) - offset,
                              "nameserver %u.%u.%u.%u\n",
                              data[i % size], data[(i + 1) % size],
                              data[(i + 2) % size], data[(i + 3) % size]);
        }
    }

  /* Add too many search domains */
  for (int i = 0; i < DNS_CONFIG_MAX_SEARCH_DOMAINS + 2 && offset < sizeof (content) - 50; i++)
    {
      offset
          += snprintf (content + offset, sizeof (content) - offset,
                       "search domain%d.example.com\n", i);
    }

  /* Add options with extreme values */
  if (size >= 4 && offset < sizeof (content) - 100)
    {
      uint32_t timeout = (data[0] << 24) | (data[1] << 16) | (data[2] << 8)
                         | data[3];
      offset += snprintf (content + offset, sizeof (content) - offset,
                          "options timeout:%u attempts:%u ndots:%u\n", timeout,
                          timeout, timeout);
    }

  /* Parse the pathological config */
  (void)SocketDNSConfig_parse (&config, content);
}

/**
 * @brief Main fuzzer entry point.
 *
 * Distributes fuzzer input across different test scenarios based on input size
 * and first byte.
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size == 0)
    return 0;

  /* Distribute test scenarios based on first byte */
  uint8_t scenario = data[0] % 5;

  switch (scenario)
    {
    case 0:
      /* Full resolv.conf parsing */
      fuzz_resolv_conf_parsing (data + 1, size - 1);
      break;

    case 1:
      /* Nameserver addition (IP validation) */
      fuzz_nameserver_addition (data + 1, size - 1);
      break;

    case 2:
      /* Search domain addition (length validation) */
      fuzz_search_domain_addition (data + 1, size - 1);
      break;

    case 3:
      /* Extended DNS Error parsing */
      fuzz_ede_parsing (data + 1, size - 1);
      break;

    case 4:
      /* Configuration limits and boundary conditions */
      fuzz_config_limits (data + 1, size - 1);
      break;
    }

  /*
   * Additional universal tests (run on all inputs)
   */

  /* Test config initialization */
  SocketDNSConfig_T config;
  SocketDNSConfig_init (&config);

  /* Test with very small inputs */
  if (size >= 2)
    {
      char small[3] = { 0 };
      memcpy (small, data, 2);
      (void)SocketDNSConfig_parse (&config, small);
    }

  return 0;
}
