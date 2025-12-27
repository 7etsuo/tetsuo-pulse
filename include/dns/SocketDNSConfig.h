/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETDNSCONFIG_INCLUDED
#define SOCKETDNSCONFIG_INCLUDED

/**
 * @file SocketDNSConfig.h
 * @brief System DNS configuration parsing (/etc/resolv.conf).
 * @ingroup dns
 *
 * Parses resolver configuration from /etc/resolv.conf per the resolv.conf(5)
 * manpage. Provides access to nameservers, search domains, and resolver options.
 *
 * ## Supported Directives
 *
 * - `nameserver <IP>` - DNS server address (up to 3 per MAXNS)
 * - `search <domain>...` - Search list for short names
 * - `domain <domain>` - Local domain (obsolete, single search entry)
 * - `options` - Resolver options
 *
 * ## Supported Options
 *
 * - `timeout:N` - Query timeout in seconds (default: 5, max: 30)
 * - `attempts:N` - Retry attempts (default: 2, max: 5)
 * - `ndots:N` - Min dots before absolute lookup (default: 1, max: 15)
 * - `rotate` - Round-robin nameserver selection
 * - `edns0` - Enable EDNS0 (RFC 6891)
 * - `use-vc` - Force TCP for queries
 *
 * ## Platform Notes
 *
 * - Linux/BSD/macOS: Reads /etc/resolv.conf
 * - If file missing: Falls back to 127.0.0.53 or 127.0.0.1
 *
 * @see SocketDNSTransport.h for transport layer.
 * @see SocketDNS.h for the async resolver API.
 */

#include "core/Arena.h"
#include "dns/SocketDNSDeadServer.h"
#include <stddef.h>

/**
 * @defgroup dns_config DNS Configuration
 * @brief System resolver configuration parsing.
 * @ingroup dns
 * @{
 */

/** Maximum nameservers in resolv.conf (MAXNS from <resolv.h>). */
#define DNS_CONFIG_MAX_NAMESERVERS 3

/** Maximum search domains (glibc <= 2.25 limit). */
#define DNS_CONFIG_MAX_SEARCH_DOMAINS 6

/** Maximum length of a single search domain. */
#define DNS_CONFIG_MAX_DOMAIN_LEN 255

/** Maximum total search list length (glibc <= 2.25 limit). */
#define DNS_CONFIG_MAX_SEARCH_LEN 256

/** Maximum line length when reading resolv.conf. */
#define DNS_CONFIG_MAX_LINE_LEN 1024

/** Default query timeout in seconds (RES_TIMEOUT). */
#define DNS_CONFIG_DEFAULT_TIMEOUT 5

/** Maximum query timeout in seconds (resolv.conf cap). */
#define DNS_CONFIG_MAX_TIMEOUT 30

/** Default retry attempts (RES_DFLRETRY). */
#define DNS_CONFIG_DEFAULT_ATTEMPTS 2

/** Maximum retry attempts (resolv.conf cap). */
#define DNS_CONFIG_MAX_ATTEMPTS 5

/** Default ndots threshold. */
#define DNS_CONFIG_DEFAULT_NDOTS 1

/** Maximum ndots value (resolv.conf cap). */
#define DNS_CONFIG_MAX_NDOTS 15

/** Maximum line length in resolv.conf (typical limit is 256-1024 bytes). */
#define DNS_CONFIG_MAX_LINE_LEN 1024

/** Default resolv.conf path. */
#define DNS_CONFIG_DEFAULT_PATH "/etc/resolv.conf"

/** Fallback nameserver (systemd-resolved). */
#define DNS_CONFIG_FALLBACK_NAMESERVER "127.0.0.53"

/** Alternative fallback nameserver. */
#define DNS_CONFIG_FALLBACK_NAMESERVER_ALT "127.0.0.1"

/**
 * Maximum length of IP address string buffer.
 * Sized to accommodate IPv6 addresses with null terminator.
 * (INET6_ADDRSTRLEN is 46, we use 64 for alignment and future-proofing)
 */
#define DNS_CONFIG_MAX_ADDRESS_LEN 64

/**
 * @brief Resolver option flags.
 * @ingroup dns_config
 */
typedef enum
{
  DNS_CONFIG_OPT_NONE = 0,     /**< No options set */
  DNS_CONFIG_OPT_ROTATE = 1,   /**< Round-robin nameserver selection */
  DNS_CONFIG_OPT_EDNS0 = 2,    /**< Enable EDNS0 (RFC 6891) */
  DNS_CONFIG_OPT_USE_VC = 4,   /**< Force TCP for queries */
  DNS_CONFIG_OPT_TRUST_AD = 8, /**< Trust AD bit in responses */
  DNS_CONFIG_OPT_NO_AAAA = 16  /**< Suppress AAAA queries */
} SocketDNSConfig_Options;

/**
 * @brief Nameserver entry structure.
 * @ingroup dns_config
 */
typedef struct
{
  char address[DNS_ADDR_STR_MAX]; /**< IPv4 or IPv6 address string */
  int family;                     /**< AF_INET or AF_INET6 (0 if not detected) */
} SocketDNSConfig_Nameserver;

/**
 * @brief DNS resolver configuration.
 * @ingroup dns_config
 *
 * Contains parsed resolv.conf data. Use SocketDNSConfig_load() to populate.
 */
typedef struct
{
  SocketDNSConfig_Nameserver nameservers[DNS_CONFIG_MAX_NAMESERVERS];
  int nameserver_count; /**< Number of configured nameservers */

  char search[DNS_CONFIG_MAX_SEARCH_DOMAINS][DNS_CONFIG_MAX_DOMAIN_LEN + 1];
  int search_count; /**< Number of search domains */

  int timeout_secs;  /**< Query timeout in seconds */
  int attempts;      /**< Number of retry attempts */
  int ndots;         /**< Min dots before absolute lookup */
  unsigned int opts; /**< Option flags (SocketDNSConfig_Options) */

  char local_domain[DNS_CONFIG_MAX_DOMAIN_LEN + 1]; /**< Local domain name */
} SocketDNSConfig_T;

/**
 * @brief Initialize configuration with defaults.
 * @ingroup dns_config
 *
 * Sets default values:
 * - timeout: 5 seconds
 * - attempts: 2
 * - ndots: 1
 * - No nameservers or search domains
 *
 * @param config Configuration structure to initialize.
 */
extern void SocketDNSConfig_init (SocketDNSConfig_T *config);

/**
 * @brief Load configuration from /etc/resolv.conf.
 * @ingroup dns_config
 *
 * Parses the system resolver configuration file. If the file cannot be
 * opened or parsed, returns default configuration with fallback nameserver.
 *
 * @param config Configuration structure to populate.
 * @return 0 on success, -1 if file couldn't be opened (defaults applied).
 *
 * @code{.c}
 * SocketDNSConfig_T config;
 * SocketDNSConfig_load(&config);
 * // Use config.nameservers, config.search, etc.
 * @endcode
 */
extern int SocketDNSConfig_load (SocketDNSConfig_T *config);

/**
 * @brief Load configuration from a specific file path.
 * @ingroup dns_config
 *
 * @param config Configuration structure to populate.
 * @param path Path to resolv.conf-format file.
 * @return 0 on success, -1 if file couldn't be opened (defaults applied).
 */
extern int SocketDNSConfig_load_file (SocketDNSConfig_T *config,
                                      const char *path);

/**
 * @brief Parse configuration from a string buffer.
 * @ingroup dns_config
 *
 * Parses resolv.conf-format content from memory. Useful for testing
 * or when configuration comes from non-file sources.
 *
 * @param config Configuration structure to populate.
 * @param content Null-terminated resolv.conf content.
 * @return 0 on success.
 */
extern int SocketDNSConfig_parse (SocketDNSConfig_T *config,
                                  const char *content);

/**
 * @brief Add a nameserver to the configuration.
 * @ingroup dns_config
 *
 * @param config Configuration structure.
 * @param address IPv4 or IPv6 address string.
 * @return 0 on success, -1 if max nameservers reached or invalid address.
 */
extern int SocketDNSConfig_add_nameserver (SocketDNSConfig_T *config,
                                           const char *address);

/**
 * @brief Add a search domain to the configuration.
 * @ingroup dns_config
 *
 * @param config Configuration structure.
 * @param domain Search domain to add.
 * @return 0 on success, -1 if max search domains reached or invalid.
 */
extern int SocketDNSConfig_add_search (SocketDNSConfig_T *config,
                                       const char *domain);

/**
 * @brief Check if configuration has the rotate option.
 * @ingroup dns_config
 *
 * @param config Configuration structure.
 * @return 1 if rotate enabled, 0 otherwise.
 */
extern int SocketDNSConfig_has_rotate (const SocketDNSConfig_T *config);

/**
 * @brief Check if configuration has the edns0 option.
 * @ingroup dns_config
 *
 * @param config Configuration structure.
 * @return 1 if edns0 enabled, 0 otherwise.
 */
extern int SocketDNSConfig_has_edns0 (const SocketDNSConfig_T *config);

/**
 * @brief Check if configuration forces TCP (use-vc option).
 * @ingroup dns_config
 *
 * @param config Configuration structure.
 * @return 1 if TCP forced, 0 otherwise.
 */
extern int SocketDNSConfig_use_tcp (const SocketDNSConfig_T *config);

/**
 * @brief Get the local domain name.
 * @ingroup dns_config
 *
 * Returns the local domain name for unqualified hostname resolution.
 * If not explicitly set, may be derived from search domains or hostname.
 *
 * @param config Configuration structure.
 * @return Local domain name or empty string if not set.
 */
extern const char *SocketDNSConfig_local_domain (
    const SocketDNSConfig_T *config);

/**
 * @brief Print configuration for debugging.
 * @ingroup dns_config
 *
 * Outputs configuration to stderr in human-readable format.
 *
 * @param config Configuration structure.
 */
extern void SocketDNSConfig_dump (const SocketDNSConfig_T *config);

/** @} */ /* End of dns_config group */

#endif /* SOCKETDNSCONFIG_INCLUDED */
