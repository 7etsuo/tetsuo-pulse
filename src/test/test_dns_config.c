/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/*
 * test_dns_config.c - Unit tests for resolv.conf parsing
 *
 * Tests parsing of /etc/resolv.conf format per resolv.conf(5) manpage.
 */

#include "dns/SocketDNSConfig.h"
#include "test/Test.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

/* Test basic initialization with defaults */
TEST (dns_config_init_defaults)
{
  SocketDNSConfig_T config;

  SocketDNSConfig_init (&config);

  ASSERT_EQ (config.nameserver_count, 0);
  ASSERT_EQ (config.search_count, 0);
  ASSERT_EQ (config.timeout_secs, DNS_CONFIG_DEFAULT_TIMEOUT);
  ASSERT_EQ (config.attempts, DNS_CONFIG_DEFAULT_ATTEMPTS);
  ASSERT_EQ (config.ndots, DNS_CONFIG_DEFAULT_NDOTS);
  ASSERT_EQ (config.opts, 0);
}

/* Test parsing a simple resolv.conf with one nameserver */
TEST (dns_config_parse_single_nameserver)
{
  SocketDNSConfig_T config;
  const char *content = "nameserver 8.8.8.8\n";
  int ret;

  ret = SocketDNSConfig_parse (&config, content);

  ASSERT_EQ (ret, 0);
  ASSERT_EQ (config.nameserver_count, 1);
  ASSERT (strcmp (config.nameservers[0].address, "8.8.8.8") == 0);
  ASSERT_EQ (config.nameservers[0].family, AF_INET);
}

/* Test parsing multiple nameservers */
TEST (dns_config_parse_multiple_nameservers)
{
  SocketDNSConfig_T config;
  const char *content = "nameserver 8.8.8.8\n"
                        "nameserver 8.8.4.4\n"
                        "nameserver 1.1.1.1\n";
  int ret;

  ret = SocketDNSConfig_parse (&config, content);

  ASSERT_EQ (ret, 0);
  ASSERT_EQ (config.nameserver_count, 3);
  ASSERT (strcmp (config.nameservers[0].address, "8.8.8.8") == 0);
  ASSERT (strcmp (config.nameservers[1].address, "8.8.4.4") == 0);
  ASSERT (strcmp (config.nameservers[2].address, "1.1.1.1") == 0);
}

/* Test max nameservers limit (3) */
TEST (dns_config_max_nameservers)
{
  SocketDNSConfig_T config;
  const char *content = "nameserver 8.8.8.8\n"
                        "nameserver 8.8.4.4\n"
                        "nameserver 1.1.1.1\n"
                        "nameserver 9.9.9.9\n";
  int ret;

  ret = SocketDNSConfig_parse (&config, content);

  ASSERT_EQ (ret, 0);
  ASSERT_EQ (config.nameserver_count, DNS_CONFIG_MAX_NAMESERVERS);
}

/* Test parsing IPv6 nameserver */
TEST (dns_config_parse_ipv6_nameserver)
{
  SocketDNSConfig_T config;
  const char *content = "nameserver 2001:4860:4860::8888\n";
  int ret;

  ret = SocketDNSConfig_parse (&config, content);

  ASSERT_EQ (ret, 0);
  ASSERT_EQ (config.nameserver_count, 1);
  ASSERT (strcmp (config.nameservers[0].address, "2001:4860:4860::8888") == 0);
  ASSERT_EQ (config.nameservers[0].family, AF_INET6);
}

/* Test parsing search domains */
TEST (dns_config_parse_search_domains)
{
  SocketDNSConfig_T config;
  const char *content = "search example.com local corp.internal\n";
  int ret;

  ret = SocketDNSConfig_parse (&config, content);

  ASSERT_EQ (ret, 0);
  ASSERT_EQ (config.search_count, 3);
  ASSERT (strcmp (config.search[0], "example.com") == 0);
  ASSERT (strcmp (config.search[1], "local") == 0);
  ASSERT (strcmp (config.search[2], "corp.internal") == 0);
}

/* Test parsing domain directive (obsolete, single search entry) */
TEST (dns_config_parse_domain)
{
  SocketDNSConfig_T config;
  const char *content = "domain example.com\n";
  int ret;

  ret = SocketDNSConfig_parse (&config, content);

  ASSERT_EQ (ret, 0);
  ASSERT_EQ (config.search_count, 1);
  ASSERT (strcmp (config.search[0], "example.com") == 0);
  ASSERT (strcmp (config.local_domain, "example.com") == 0);
}

/* Test last search directive wins */
TEST (dns_config_last_search_wins)
{
  SocketDNSConfig_T config;
  const char *content = "search first.com second.com\n"
                        "search third.com\n";
  int ret;

  ret = SocketDNSConfig_parse (&config, content);

  ASSERT_EQ (ret, 0);
  ASSERT_EQ (config.search_count, 1);
  ASSERT (strcmp (config.search[0], "third.com") == 0);
}

/* Test parsing timeout option */
TEST (dns_config_parse_options_timeout)
{
  SocketDNSConfig_T config;
  const char *content = "options timeout:10\n";
  int ret;

  ret = SocketDNSConfig_parse (&config, content);

  ASSERT_EQ (ret, 0);
  ASSERT_EQ (config.timeout_secs, 10);
}

/* Test timeout option is capped at 30 */
TEST (dns_config_timeout_capped)
{
  SocketDNSConfig_T config;
  const char *content = "options timeout:100\n";
  int ret;

  ret = SocketDNSConfig_parse (&config, content);

  ASSERT_EQ (ret, 0);
  ASSERT_EQ (config.timeout_secs, DNS_CONFIG_MAX_TIMEOUT);
}

/* Test parsing attempts option */
TEST (dns_config_parse_options_attempts)
{
  SocketDNSConfig_T config;
  const char *content = "options attempts:4\n";
  int ret;

  ret = SocketDNSConfig_parse (&config, content);

  ASSERT_EQ (ret, 0);
  ASSERT_EQ (config.attempts, 4);
}

/* Test attempts option is capped at 5 */
TEST (dns_config_attempts_capped)
{
  SocketDNSConfig_T config;
  const char *content = "options attempts:10\n";
  int ret;

  ret = SocketDNSConfig_parse (&config, content);

  ASSERT_EQ (ret, 0);
  ASSERT_EQ (config.attempts, DNS_CONFIG_MAX_ATTEMPTS);
}

/* Test parsing ndots option */
TEST (dns_config_parse_options_ndots)
{
  SocketDNSConfig_T config;
  const char *content = "options ndots:5\n";
  int ret;

  ret = SocketDNSConfig_parse (&config, content);

  ASSERT_EQ (ret, 0);
  ASSERT_EQ (config.ndots, 5);
}

/* Test ndots option is capped at 15 */
TEST (dns_config_ndots_capped)
{
  SocketDNSConfig_T config;
  const char *content = "options ndots:20\n";
  int ret;

  ret = SocketDNSConfig_parse (&config, content);

  ASSERT_EQ (ret, 0);
  ASSERT_EQ (config.ndots, DNS_CONFIG_MAX_NDOTS);
}

/* Test parsing rotate option */
TEST (dns_config_parse_options_rotate)
{
  SocketDNSConfig_T config;
  const char *content = "options rotate\n";
  int ret;

  ret = SocketDNSConfig_parse (&config, content);

  ASSERT_EQ (ret, 0);
  ASSERT (SocketDNSConfig_has_rotate (&config));
}

/* Test parsing edns0 option */
TEST (dns_config_parse_options_edns0)
{
  SocketDNSConfig_T config;
  const char *content = "options edns0\n";
  int ret;

  ret = SocketDNSConfig_parse (&config, content);

  ASSERT_EQ (ret, 0);
  ASSERT (SocketDNSConfig_has_edns0 (&config));
}

/* Test parsing use-vc option */
TEST (dns_config_parse_options_use_vc)
{
  SocketDNSConfig_T config;
  const char *content = "options use-vc\n";
  int ret;

  ret = SocketDNSConfig_parse (&config, content);

  ASSERT_EQ (ret, 0);
  ASSERT (SocketDNSConfig_use_tcp (&config));
}

/* Test parsing multiple options */
TEST (dns_config_parse_multiple_options)
{
  SocketDNSConfig_T config;
  const char *content = "options timeout:3 attempts:4 ndots:2 rotate edns0\n";
  int ret;

  ret = SocketDNSConfig_parse (&config, content);

  ASSERT_EQ (ret, 0);
  ASSERT_EQ (config.timeout_secs, 3);
  ASSERT_EQ (config.attempts, 4);
  ASSERT_EQ (config.ndots, 2);
  ASSERT (SocketDNSConfig_has_rotate (&config));
  ASSERT (SocketDNSConfig_has_edns0 (&config));
}

/* Test comments are ignored (# style) */
TEST (dns_config_ignore_hash_comments)
{
  SocketDNSConfig_T config;
  const char *content = "# This is a comment\n"
                        "nameserver 8.8.8.8\n"
                        "# Another comment\n";
  int ret;

  ret = SocketDNSConfig_parse (&config, content);

  ASSERT_EQ (ret, 0);
  ASSERT_EQ (config.nameserver_count, 1);
}

/* Test comments are ignored (; style) */
TEST (dns_config_ignore_semicolon_comments)
{
  SocketDNSConfig_T config;
  const char *content = "; This is a comment\n"
                        "nameserver 8.8.8.8\n";
  int ret;

  ret = SocketDNSConfig_parse (&config, content);

  ASSERT_EQ (ret, 0);
  ASSERT_EQ (config.nameserver_count, 1);
}

/* Test inline comments are handled */
TEST (dns_config_inline_comments)
{
  SocketDNSConfig_T config;
  const char *content = "nameserver 8.8.8.8 # Google DNS\n";
  int ret;

  ret = SocketDNSConfig_parse (&config, content);

  ASSERT_EQ (ret, 0);
  ASSERT_EQ (config.nameserver_count, 1);
  ASSERT (strcmp (config.nameservers[0].address, "8.8.8.8") == 0);
}

/* Test empty file gives fallback nameserver */
TEST (dns_config_empty_file_fallback)
{
  SocketDNSConfig_T config;
  const char *content = "\n";
  int ret;

  ret = SocketDNSConfig_parse (&config, content);

  ASSERT_EQ (ret, 0);
  ASSERT_EQ (config.nameserver_count, 1);
  ASSERT (strcmp (config.nameservers[0].address,
                  DNS_CONFIG_FALLBACK_NAMESERVER)
          == 0);
}

/* Test invalid nameserver address is skipped */
TEST (dns_config_invalid_nameserver_skipped)
{
  SocketDNSConfig_T config;
  const char *content = "nameserver not-an-ip\n"
                        "nameserver 8.8.8.8\n";
  int ret;

  ret = SocketDNSConfig_parse (&config, content);

  ASSERT_EQ (ret, 0);
  ASSERT_EQ (config.nameserver_count, 1);
  ASSERT (strcmp (config.nameservers[0].address, "8.8.8.8") == 0);
}

/* Test add_nameserver function */
TEST (dns_config_add_nameserver)
{
  SocketDNSConfig_T config;
  int ret;

  SocketDNSConfig_init (&config);

  ret = SocketDNSConfig_add_nameserver (&config, "8.8.8.8");
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (config.nameserver_count, 1);

  ret = SocketDNSConfig_add_nameserver (&config, "8.8.4.4");
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (config.nameserver_count, 2);
}

/* Test add_nameserver rejects invalid address */
TEST (dns_config_add_nameserver_invalid)
{
  SocketDNSConfig_T config;
  int ret;

  SocketDNSConfig_init (&config);

  ret = SocketDNSConfig_add_nameserver (&config, "not-valid");
  ASSERT_EQ (ret, -1);
  ASSERT_EQ (config.nameserver_count, 0);
}

/* Test add_search function */
TEST (dns_config_add_search)
{
  SocketDNSConfig_T config;
  int ret;

  SocketDNSConfig_init (&config);

  ret = SocketDNSConfig_add_search (&config, "example.com");
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (config.search_count, 1);

  ret = SocketDNSConfig_add_search (&config, "local");
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (config.search_count, 2);
}

/* Test local_domain returns search domain if not explicitly set */
TEST (dns_config_local_domain_from_search)
{
  SocketDNSConfig_T config;
  const char *content = "search example.com local\n";
  const char *domain;

  SocketDNSConfig_parse (&config, content);
  domain = SocketDNSConfig_local_domain (&config);

  ASSERT (strcmp (domain, "example.com") == 0);
}

/* Test local_domain returns explicit domain */
TEST (dns_config_local_domain_explicit)
{
  SocketDNSConfig_T config;
  const char *content = "domain mylocal.lan\n"
                        "search example.com\n";
  const char *domain;

  SocketDNSConfig_parse (&config, content);
  domain = SocketDNSConfig_local_domain (&config);

  ASSERT (strcmp (domain, "mylocal.lan") == 0);
}

/* Test comprehensive resolv.conf */
TEST (dns_config_comprehensive)
{
  SocketDNSConfig_T config;
  const char *content = "# /etc/resolv.conf\n"
                        "nameserver 8.8.8.8\n"
                        "nameserver 2001:4860:4860::8888\n"
                        "search example.com corp.internal\n"
                        "options timeout:3 attempts:4 ndots:2 rotate\n";
  int ret;

  ret = SocketDNSConfig_parse (&config, content);

  ASSERT_EQ (ret, 0);
  ASSERT_EQ (config.nameserver_count, 2);
  ASSERT_EQ (config.nameservers[0].family, AF_INET);
  ASSERT_EQ (config.nameservers[1].family, AF_INET6);
  ASSERT_EQ (config.search_count, 2);
  ASSERT_EQ (config.timeout_secs, 3);
  ASSERT_EQ (config.attempts, 4);
  ASSERT_EQ (config.ndots, 2);
  ASSERT (SocketDNSConfig_has_rotate (&config));
}

/* Main function - run all tests */
int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}
