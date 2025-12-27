/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketDNSConfig.c
 * @brief Implementation of resolv.conf parsing.
 * @ingroup dns_config
 *
 * Parses /etc/resolv.conf per resolv.conf(5) manpage specification.
 */

#include "dns/SocketDNSConfig.h"
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

/**
 * @brief Maximum size for config content.
 *
 * 1MB is a reasonable upper bound for resolv.conf content.
 */
#define MAX_CONFIG_SIZE (1024 * 1024)

/**
 * @brief Skip whitespace in a string.
 */
static const char *
skip_whitespace (const char *s)
{
  while (*s && (*s == ' ' || *s == '\t'))
    s++;
  return s;
}

/**
 * @brief Get next token from string, updating pointer.
 *
 * Tokens are separated by whitespace. Returns pointer to start of token
 * and null-terminates it.
 */
static char *
next_token (char **line)
{
  char *start;
  char *p;

  p = (char *)skip_whitespace (*line);
  if (*p == '\0' || *p == '#' || *p == ';')
    return NULL;

  start = p;

  while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '#' && *p != ';')
    p++;

  if (*p)
    {
      *p = '\0';
      p++;
    }

  *line = p;
  return start;
}

/**
 * @brief Detect address family from string.
 *
 * @param address IPv4 or IPv6 address string.
 * @return AF_INET, AF_INET6, or 0 if invalid.
 */
static int
detect_address_family (const char *address)
{
  struct in_addr addr4;
  struct in6_addr addr6;

  if (inet_pton (AF_INET, address, &addr4) == 1)
    return AF_INET;
  if (inet_pton (AF_INET6, address, &addr6) == 1)
    return AF_INET6;
  return 0;
}

/**
 * @brief Parse options from options line.
 *
 * @param config Configuration to update.
 * @param line Rest of line after "options" keyword.
 */
static void
parse_options (SocketDNSConfig_T *config, char *line)
{
  char *token;
  char *colon;
  char *endptr;
  long value;

  while ((token = next_token (&line)) != NULL)
    {
      colon = strchr (token, ':');

      if (colon)
        {
          *colon = '\0';
          errno = 0;
          value = strtol (colon + 1, &endptr, 10);

          /* Validate parsing: check for conversion errors and range */
          if (errno != 0 || endptr == colon + 1 || *endptr != '\0'
              || value < INT_MIN || value > INT_MAX)
            {
              /* Invalid integer, skip this option */
              continue;
            }

          if (strcmp (token, "timeout") == 0)
            {
              if (value < 1)
                value = 1;
              if (value > DNS_CONFIG_MAX_TIMEOUT)
                value = DNS_CONFIG_MAX_TIMEOUT;
              config->timeout_secs = (int)value;
            }
          else if (strcmp (token, "attempts") == 0)
            {
              if (value < 1)
                value = 1;
              if (value > DNS_CONFIG_MAX_ATTEMPTS)
                value = DNS_CONFIG_MAX_ATTEMPTS;
              config->attempts = (int)value;
            }
          else if (strcmp (token, "ndots") == 0)
            {
              if (value < 0)
                value = 0;
              if (value > DNS_CONFIG_MAX_NDOTS)
                value = DNS_CONFIG_MAX_NDOTS;
              config->ndots = (int)value;
            }
        }
      else
        {
          if (strcmp (token, "rotate") == 0)
            config->opts |= DNS_CONFIG_OPT_ROTATE;
          else if (strcmp (token, "edns0") == 0)
            config->opts |= DNS_CONFIG_OPT_EDNS0;
          else if (strcmp (token, "use-vc") == 0)
            config->opts |= DNS_CONFIG_OPT_USE_VC;
          else if (strcmp (token, "trust-ad") == 0)
            config->opts |= DNS_CONFIG_OPT_TRUST_AD;
          else if (strcmp (token, "no-aaaa") == 0)
            config->opts |= DNS_CONFIG_OPT_NO_AAAA;
        }
    }
}

/**
 * @brief Parse a single line from resolv.conf.
 *
 * @param config Configuration to update.
 * @param line Line to parse (will be modified).
 */
static void
parse_line (SocketDNSConfig_T *config, char *line)
{
  char *keyword;
  char *token;
  size_t len;

  len = strlen (line);
  if (len > 0 && line[len - 1] == '\n')
    line[len - 1] = '\0';

  keyword = next_token (&line);
  if (keyword == NULL)
    return;

  if (strcmp (keyword, "nameserver") == 0)
    {
      token = next_token (&line);
      if (token)
        SocketDNSConfig_add_nameserver (config, token);
    }
  else if (strcmp (keyword, "search") == 0)
    {
      config->search_count = 0;
      while ((token = next_token (&line)) != NULL)
        {
          SocketDNSConfig_add_search (config, token);
        }
    }
  else if (strcmp (keyword, "domain") == 0)
    {
      token = next_token (&line);
      if (token)
        {
          config->search_count = 0;
          SocketDNSConfig_add_search (config, token);
          strncpy (config->local_domain, token, DNS_CONFIG_MAX_DOMAIN_LEN);
          config->local_domain[DNS_CONFIG_MAX_DOMAIN_LEN] = '\0';
        }
    }
  else if (strcmp (keyword, "options") == 0)
    {
      parse_options (config, line);
    }
}

void
SocketDNSConfig_init (SocketDNSConfig_T *config)
{
  assert (config != NULL);

  memset (config, 0, sizeof (*config));
  config->timeout_secs = DNS_CONFIG_DEFAULT_TIMEOUT;
  config->attempts = DNS_CONFIG_DEFAULT_ATTEMPTS;
  config->ndots = DNS_CONFIG_DEFAULT_NDOTS;
}

int
SocketDNSConfig_load (SocketDNSConfig_T *config)
{
  return SocketDNSConfig_load_file (config, DNS_CONFIG_DEFAULT_PATH);
}

int
SocketDNSConfig_load_file (SocketDNSConfig_T *config, const char *path)
{
  FILE *fp;
  char line[1024];

  assert (config != NULL);
  assert (path != NULL);

  SocketDNSConfig_init (config);

  fp = fopen (path, "r");
  if (fp == NULL)
    {
      SocketDNSConfig_add_nameserver (config, DNS_CONFIG_FALLBACK_NAMESERVER);
      return -1;
    }

  while (fgets (line, sizeof (line), fp) != NULL)
    {
      parse_line (config, line);
    }

  fclose (fp);

  if (config->nameserver_count == 0)
    {
      SocketDNSConfig_add_nameserver (config, DNS_CONFIG_FALLBACK_NAMESERVER);
    }

  return 0;
}

int
SocketDNSConfig_parse (SocketDNSConfig_T *config, const char *content)
{
  char *copy;
  char *line;
  char *saveptr;
  size_t len;

  assert (config != NULL);
  assert (content != NULL);

  SocketDNSConfig_init (config);

  len = strlen (content);

  /* Check for reasonable size limit */
  if (len > MAX_CONFIG_SIZE)
    return -1;

  copy = malloc (len + 1);
  if (copy == NULL)
    return -1;

  memcpy (copy, content, len + 1);

  line = strtok_r (copy, "\n", &saveptr);
  while (line != NULL)
    {
      parse_line (config, line);
      line = strtok_r (NULL, "\n", &saveptr);
    }

  free (copy);

  if (config->nameserver_count == 0)
    {
      SocketDNSConfig_add_nameserver (config, DNS_CONFIG_FALLBACK_NAMESERVER);
    }

  return 0;
}

int
SocketDNSConfig_add_nameserver (SocketDNSConfig_T *config, const char *address)
{
  int family;
  size_t len;

  assert (config != NULL);
  assert (address != NULL);

  if (config->nameserver_count >= DNS_CONFIG_MAX_NAMESERVERS)
    return -1;

  family = detect_address_family (address);
  if (family == 0)
    return -1;

  len = strlen (address);
  if (len >= sizeof (config->nameservers[0].address))
    return -1;

  strncpy (config->nameservers[config->nameserver_count].address, address,
           sizeof (config->nameservers[0].address) - 1);
  config->nameservers[config->nameserver_count]
      .address[sizeof (config->nameservers[0].address) - 1]
      = '\0';
  config->nameservers[config->nameserver_count].family = family;
  config->nameserver_count++;

  return 0;
}

/**
 * @brief Validate domain name against RFC 1035 character set.
 *
 * Valid DNS domain names contain only:
 * - Letters (a-z, A-Z)
 * - Digits (0-9)
 * - Hyphens (-)
 * - Dots (.)
 *
 * This prevents shell metacharacters and control characters from being
 * injected into search domains.
 *
 * @param domain Domain name to validate.
 * @return 1 if valid, 0 if invalid.
 */
static int
is_valid_domain_name (const char *domain)
{
  const char *p;

  if (domain == NULL || *domain == '\0')
    return 0;

  for (p = domain; *p != '\0'; p++)
    {
      /* Allow alphanumeric, hyphen, and dot only (RFC 1035) */
      if (!isalnum ((unsigned char)*p) && *p != '-' && *p != '.')
        return 0;

      /* Reject control characters explicitly */
      if (iscntrl ((unsigned char)*p))
        return 0;
    }

  /* Additional checks: no leading/trailing dots or hyphens */
  if (domain[0] == '.' || domain[0] == '-')
    return 0;

  /* p now points to '\0', so p-1 is the last character */
  if (p > domain && (*(p - 1) == '.' || *(p - 1) == '-'))
    return 0;

  return 1;
}

int
SocketDNSConfig_add_search (SocketDNSConfig_T *config, const char *domain)
{
  size_t len;

  assert (config != NULL);
  assert (domain != NULL);

  if (config->search_count >= DNS_CONFIG_MAX_SEARCH_DOMAINS)
    return -1;

  len = strlen (domain);
  if (len == 0 || len > DNS_CONFIG_MAX_DOMAIN_LEN)
    return -1;

  /* Validate domain name against RFC 1035 character set */
  if (!is_valid_domain_name (domain))
    return -1;

  strncpy (config->search[config->search_count], domain,
           DNS_CONFIG_MAX_DOMAIN_LEN);
  config->search[config->search_count][DNS_CONFIG_MAX_DOMAIN_LEN] = '\0';
  config->search_count++;

  return 0;
}

int
SocketDNSConfig_has_rotate (const SocketDNSConfig_T *config)
{
  assert (config != NULL);
  return (config->opts & DNS_CONFIG_OPT_ROTATE) != 0;
}

int
SocketDNSConfig_has_edns0 (const SocketDNSConfig_T *config)
{
  assert (config != NULL);
  return (config->opts & DNS_CONFIG_OPT_EDNS0) != 0;
}

int
SocketDNSConfig_use_tcp (const SocketDNSConfig_T *config)
{
  assert (config != NULL);
  return (config->opts & DNS_CONFIG_OPT_USE_VC) != 0;
}

const char *
SocketDNSConfig_local_domain (const SocketDNSConfig_T *config)
{
  assert (config != NULL);

  if (config->local_domain[0] != '\0')
    return config->local_domain;

  if (config->search_count > 0)
    return config->search[0];

  return "";
}

void
SocketDNSConfig_dump (const SocketDNSConfig_T *config)
{
  int i;

  assert (config != NULL);

  fprintf (stderr, "DNS Configuration:\n");
  fprintf (stderr, "  Nameservers (%d):\n", config->nameserver_count);
  for (i = 0; i < config->nameserver_count; i++)
    {
      fprintf (stderr, "    [%d] %s (IPv%d)\n", i,
               config->nameservers[i].address,
               config->nameservers[i].family == AF_INET6 ? 6 : 4);
    }

  fprintf (stderr, "  Search domains (%d):\n", config->search_count);
  for (i = 0; i < config->search_count; i++)
    {
      fprintf (stderr, "    [%d] %s\n", i, config->search[i]);
    }

  fprintf (stderr, "  Options:\n");
  fprintf (stderr, "    timeout: %d seconds\n", config->timeout_secs);
  fprintf (stderr, "    attempts: %d\n", config->attempts);
  fprintf (stderr, "    ndots: %d\n", config->ndots);
  fprintf (stderr, "    rotate: %s\n",
           SocketDNSConfig_has_rotate (config) ? "yes" : "no");
  fprintf (stderr, "    edns0: %s\n",
           SocketDNSConfig_has_edns0 (config) ? "yes" : "no");
  fprintf (stderr, "    use-vc (TCP): %s\n",
           SocketDNSConfig_use_tcp (config) ? "yes" : "no");

  if (config->local_domain[0] != '\0')
    fprintf (stderr, "  Local domain: %s\n", config->local_domain);
}
