/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETDNSCOOKIE_INCLUDED
#define SOCKETDNSCOOKIE_INCLUDED

/**
 * @file SocketDNSCookie.h
 * @brief DNS Cookies for spoofing and amplification protection (RFC 7873).
 * @ingroup dns
 *
 * Implements DNS Cookies as defined in RFC 7873 to provide lightweight
 * protection against off-path DNS spoofing and amplification attacks.
 * Cookies are transported via EDNS0 option (code 10).
 *
 * ## RFC References
 *
 * - RFC 7873: Domain Name System (DNS) Cookies
 * - RFC 6891: EDNS0 (Extension Mechanisms for DNS)
 *
 * ## How It Works
 *
 * 1. Client generates an 8-byte Client Cookie per server IP
 * 2. Client sends query with Client Cookie in EDNS0 option
 * 3. Server responds with Client Cookie + Server Cookie (8-32 bytes)
 * 4. Client caches Server Cookie for future queries to same server
 * 5. Future queries include both cookies
 * 6. Server verifies cookies before responding
 *
 * ## Cookie Format (EDNS0 Option Code 10)
 *
 * ```
 * +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 * |                    OPTION-CODE = 10                          |
 * +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 * |                    OPTION-LENGTH                             |
 * +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 * |                Client Cookie (8 bytes)                       |
 * +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 * |           Server Cookie (8-32 bytes, optional)               |
 * +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 * ```
 *
 * ## Security Notes
 *
 * - Cookies provide protection against **off-path** attackers only
 * - No protection against on-path adversaries who can observe traffic
 * - Client secret should have at least 64 bits of entropy
 * - Secret rotation recommended every 24 hours (max 36 days per RFC)
 *
 * @see SocketDNSWire.h for EDNS0 option encoding/decoding.
 * @see SocketDNSTransport.h for transport integration.
 */

#include "core/Arena.h"
#include "core/Except.h"
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

/**
 * @defgroup dns_cookie DNS Cookies
 * @brief DNS Cookie generation, caching, and validation.
 * @ingroup dns
 * @{
 */

/** EDNS0 option code for DNS Cookies (RFC 7873). */
#define DNS_COOKIE_OPTION_CODE 10

/** Client Cookie size in bytes (fixed per RFC 7873). */
#define DNS_CLIENT_COOKIE_SIZE 8

/** Minimum Server Cookie size in bytes. */
#define DNS_SERVER_COOKIE_MIN_SIZE 8

/** Maximum Server Cookie size in bytes. */
#define DNS_SERVER_COOKIE_MAX_SIZE 32

/** Minimum valid COOKIE option length (client cookie only). */
#define DNS_COOKIE_OPTION_MIN_LEN 8

/** Maximum valid COOKIE option length (client + max server). */
#define DNS_COOKIE_OPTION_MAX_LEN 40

/** Default client secret lifetime in seconds (1 day per RFC 7873). */
#define DNS_COOKIE_SECRET_LIFETIME_DEFAULT 86400

/** Maximum client secret lifetime in seconds (36 days per RFC 7873). */
#define DNS_COOKIE_SECRET_LIFETIME_MAX 3110400

/** Default cache size (number of server cookie entries). */
#define DNS_COOKIE_CACHE_DEFAULT_SIZE 64

/** Maximum cache size. */
#define DNS_COOKIE_CACHE_MAX_SIZE 1024

/** Server cookie expiry time in seconds (default: 1 hour). */
#define DNS_COOKIE_SERVER_TTL_DEFAULT 3600

/**
 * @brief DNS Cookie operation failure exception.
 * @ingroup dns_cookie
 *
 * Raised for cookie generation failures, invalid parameters,
 * or resource exhaustion.
 */
extern const Except_T SocketDNSCookie_Failed;

/**
 * @brief Opaque handle for DNS Cookie cache.
 * @ingroup dns_cookie
 *
 * Manages client secrets and cached server cookies per nameserver.
 */
#define T SocketDNSCookie_T
typedef struct T *T;

/**
 * @brief Parsed DNS Cookie from EDNS0 option.
 * @ingroup dns_cookie
 *
 * Contains client cookie and optional server cookie extracted
 * from a DNS COOKIE EDNS0 option.
 */
typedef struct
{
  uint8_t client_cookie[DNS_CLIENT_COOKIE_SIZE]; /**< Client cookie (8 bytes) */
  uint8_t server_cookie[DNS_SERVER_COOKIE_MAX_SIZE]; /**< Server cookie */
  size_t server_cookie_len; /**< Server cookie length (0 if absent) */
} SocketDNSCookie_Cookie;

/**
 * @brief Cached server cookie entry.
 * @ingroup dns_cookie
 *
 * Stores a server cookie associated with a specific nameserver address.
 */
typedef struct
{
  struct sockaddr_storage server_addr; /**< Nameserver address */
  socklen_t addr_len;                  /**< Address length */
  uint8_t client_cookie[DNS_CLIENT_COOKIE_SIZE]; /**< Client cookie used */
  uint8_t server_cookie[DNS_SERVER_COOKIE_MAX_SIZE]; /**< Cached server cookie */
  size_t server_cookie_len;            /**< Server cookie length */
  time_t received_at;                  /**< When cookie was received */
  time_t expires_at;                   /**< Expiration time */
} SocketDNSCookie_Entry;

/**
 * @brief Cookie cache statistics.
 * @ingroup dns_cookie
 */
typedef struct
{
  uint64_t client_cookies_generated; /**< Total client cookies generated */
  uint64_t server_cookies_cached;    /**< Server cookies added to cache */
  uint64_t cache_hits;               /**< Successful cache lookups */
  uint64_t cache_misses;             /**< Failed cache lookups */
  uint64_t cache_evictions;          /**< LRU evictions */
  uint64_t badcookie_responses;      /**< BADCOOKIE responses received */
  uint64_t secret_rotations;         /**< Client secret rotations */
  size_t current_entries;            /**< Current cached entries */
  size_t max_entries;                /**< Maximum cache capacity */
  time_t secret_expires_at;          /**< Current secret expiration */
} SocketDNSCookie_Stats;

/* Lifecycle functions */

/**
 * @brief Create a new DNS Cookie cache.
 * @ingroup dns_cookie
 *
 * Creates a cookie cache with a randomly generated client secret.
 * The secret is automatically rotated based on the configured lifetime.
 *
 * @param arena Arena for memory allocation (must outlive cache).
 * @return New cookie cache instance.
 * @throws SocketDNSCookie_Failed on allocation or entropy failure.
 *
 * @code{.c}
 * Arena_T arena = Arena_new();
 * SocketDNSCookie_T cache = SocketDNSCookie_new(arena);
 * // Use cache with DNS queries...
 * Arena_dispose(&arena);
 * @endcode
 */
extern T SocketDNSCookie_new (Arena_T arena);

/**
 * @brief Dispose of a DNS Cookie cache.
 * @ingroup dns_cookie
 *
 * Releases all resources and clears sensitive data (secrets).
 * The cache pointer is set to NULL.
 *
 * @param cache Pointer to cache instance.
 */
extern void SocketDNSCookie_free (T *cache);

/* Configuration functions */

/**
 * @brief Set the client secret lifetime.
 * @ingroup dns_cookie
 *
 * Controls how often the client secret is rotated.
 * Per RFC 7873, SHOULD NOT exceed 26 hours, MUST NOT exceed 36 days.
 *
 * @param cache           Cookie cache instance.
 * @param lifetime_seconds Secret lifetime in seconds.
 *                         Clamped to [60, DNS_COOKIE_SECRET_LIFETIME_MAX].
 *
 * @code{.c}
 * // Rotate secret every 12 hours
 * SocketDNSCookie_set_secret_lifetime(cache, 43200);
 * @endcode
 */
extern void SocketDNSCookie_set_secret_lifetime (T cache, int lifetime_seconds);

/**
 * @brief Set maximum cache entries.
 * @ingroup dns_cookie
 *
 * When the cache is full, least-recently-used entries are evicted.
 *
 * @param cache       Cookie cache instance.
 * @param max_entries Maximum entries (clamped to [1, DNS_COOKIE_CACHE_MAX_SIZE]).
 */
extern void SocketDNSCookie_set_cache_size (T cache, size_t max_entries);

/**
 * @brief Set server cookie TTL.
 * @ingroup dns_cookie
 *
 * Cached server cookies expire after this duration and must be refreshed.
 *
 * @param cache       Cookie cache instance.
 * @param ttl_seconds TTL in seconds (default: 3600).
 */
extern void SocketDNSCookie_set_server_ttl (T cache, int ttl_seconds);

/**
 * @brief Force immediate rotation of the client secret.
 * @ingroup dns_cookie
 *
 * Generates a new random client secret. Use after security events
 * or when the secret may have been compromised.
 *
 * @param cache Cookie cache instance.
 * @return 0 on success, -1 on entropy failure.
 */
extern int SocketDNSCookie_rotate_secret (T cache);

/* Cookie generation and parsing */

/**
 * @brief Generate a client cookie for a server address.
 * @ingroup dns_cookie
 *
 * Creates an 8-byte client cookie using HMAC-SHA256 over the
 * client IP, server IP, and client secret, truncated to 64 bits.
 *
 * If a valid server cookie exists in the cache, it is also returned.
 *
 * @param cache       Cookie cache instance.
 * @param server_addr Server address (IPv4 or IPv6).
 * @param addr_len    Server address length.
 * @param client_addr Client address (may be NULL for default).
 * @param client_len  Client address length.
 * @param[out] cookie Output cookie structure.
 * @return 0 on success, -1 on error.
 *
 * @code{.c}
 * struct sockaddr_in server;
 * server.sin_family = AF_INET;
 * inet_pton(AF_INET, "8.8.8.8", &server.sin_addr);
 *
 * SocketDNSCookie_Cookie cookie;
 * if (SocketDNSCookie_generate(cache, (struct sockaddr*)&server,
 *                               sizeof(server), NULL, 0, &cookie) == 0) {
 *     // cookie.client_cookie is ready
 *     // cookie.server_cookie_len > 0 if cached server cookie exists
 * }
 * @endcode
 */
extern int SocketDNSCookie_generate (T cache,
                                     const struct sockaddr *server_addr,
                                     socklen_t addr_len,
                                     const struct sockaddr *client_addr,
                                     socklen_t client_len,
                                     SocketDNSCookie_Cookie *cookie);

/**
 * @brief Parse a cookie from EDNS0 option data.
 * @ingroup dns_cookie
 *
 * Extracts client and server cookies from COOKIE option RDATA.
 * Validates that the option length is valid per RFC 7873:
 * - 8 bytes: client cookie only
 * - 16-40 bytes: client + server cookie
 * - Other lengths: FORMERR
 *
 * @param data     COOKIE option data (after OPTION-CODE and OPTION-LENGTH).
 * @param len      Length of option data.
 * @param[out] cookie Output cookie structure.
 * @return 0 on success, -1 on invalid format.
 *
 * @code{.c}
 * SocketDNS_EDNSOption opt;
 * if (SocketDNS_edns_option_find(rdata, rdlen, DNS_EDNS_OPT_COOKIE, &opt)) {
 *     SocketDNSCookie_Cookie cookie;
 *     if (SocketDNSCookie_parse(opt.data, opt.length, &cookie) == 0) {
 *         // Process cookie
 *     }
 * }
 * @endcode
 */
extern int SocketDNSCookie_parse (const unsigned char *data, size_t len,
                                  SocketDNSCookie_Cookie *cookie);

/**
 * @brief Encode a cookie to EDNS0 option format.
 * @ingroup dns_cookie
 *
 * Serializes a cookie structure to wire format suitable for
 * inclusion in an OPT record RDATA.
 *
 * @param cookie  Cookie to encode.
 * @param[out] buf Output buffer.
 * @param buflen  Buffer size.
 * @return Number of bytes written on success, -1 on error.
 *
 * @code{.c}
 * SocketDNSCookie_Cookie cookie;
 * SocketDNSCookie_generate(cache, server, slen, NULL, 0, &cookie);
 *
 * unsigned char opt_data[DNS_COOKIE_OPTION_MAX_LEN];
 * int opt_len = SocketDNSCookie_encode(&cookie, opt_data, sizeof(opt_data));
 * if (opt_len > 0) {
 *     SocketDNS_EDNSOption edns_opt = {
 *         .code = DNS_EDNS_OPT_COOKIE,
 *         .length = opt_len,
 *         .data = opt_data
 *     };
 *     // Add to OPT record
 * }
 * @endcode
 */
extern int SocketDNSCookie_encode (const SocketDNSCookie_Cookie *cookie,
                                   unsigned char *buf, size_t buflen);

/* Cache operations */

/**
 * @brief Store a server cookie in the cache.
 * @ingroup dns_cookie
 *
 * Caches a server cookie received in a DNS response. The cookie
 * is associated with the server address and will be used in
 * subsequent queries to the same server.
 *
 * @param cache         Cookie cache instance.
 * @param server_addr   Server address.
 * @param addr_len      Server address length.
 * @param client_cookie Client cookie that was sent (for validation).
 * @param server_cookie Server cookie received.
 * @param server_len    Server cookie length.
 * @return 0 on success, -1 on error.
 *
 * @note Server cookie length must be 8-32 bytes per RFC 7873.
 */
extern int SocketDNSCookie_cache_store (T cache,
                                        const struct sockaddr *server_addr,
                                        socklen_t addr_len,
                                        const uint8_t *client_cookie,
                                        const uint8_t *server_cookie,
                                        size_t server_len);

/**
 * @brief Look up a cached server cookie.
 * @ingroup dns_cookie
 *
 * Retrieves a previously cached server cookie for the given server.
 * Returns the associated client cookie that should be used with it.
 *
 * @param cache       Cookie cache instance.
 * @param server_addr Server address to look up.
 * @param addr_len    Server address length.
 * @param[out] entry  Output cache entry (may be NULL to just check existence).
 * @return 1 if found and valid, 0 if not found or expired.
 */
extern int SocketDNSCookie_cache_lookup (T cache,
                                         const struct sockaddr *server_addr,
                                         socklen_t addr_len,
                                         SocketDNSCookie_Entry *entry);

/**
 * @brief Invalidate cached cookie for a server.
 * @ingroup dns_cookie
 *
 * Removes the cached server cookie for the given address.
 * Use when receiving BADCOOKIE response to force cookie refresh.
 *
 * @param cache       Cookie cache instance.
 * @param server_addr Server address to invalidate.
 * @param addr_len    Server address length.
 * @return 1 if entry was removed, 0 if not found.
 */
extern int SocketDNSCookie_cache_invalidate (T cache,
                                             const struct sockaddr *server_addr,
                                             socklen_t addr_len);

/**
 * @brief Clear all cached server cookies.
 * @ingroup dns_cookie
 *
 * Removes all entries from the cache without rotating the client secret.
 *
 * @param cache Cookie cache instance.
 */
extern void SocketDNSCookie_cache_clear (T cache);

/**
 * @brief Remove expired entries from the cache.
 * @ingroup dns_cookie
 *
 * Scans the cache and removes entries whose TTL has expired.
 * Called automatically during cache operations.
 *
 * @param cache Cookie cache instance.
 * @return Number of entries removed.
 */
extern int SocketDNSCookie_cache_expire (T cache);

/* Validation */

/**
 * @brief Validate a response cookie against the request.
 * @ingroup dns_cookie
 *
 * Verifies that the client cookie in the response matches what was sent.
 * Per RFC 7873, responses with mismatched client cookies MUST be discarded.
 *
 * @param sent_cookie    Client cookie that was sent in the request.
 * @param response       Cookie parsed from the response.
 * @return 1 if valid, 0 if invalid (client cookie mismatch).
 *
 * @code{.c}
 * SocketDNSCookie_Cookie sent, received;
 * // ... generate sent, parse received ...
 * if (!SocketDNSCookie_validate(&sent, &received)) {
 *     // Discard response - possible spoofing attempt
 *     return;
 * }
 * // Process valid response
 * @endcode
 */
extern int SocketDNSCookie_validate (const SocketDNSCookie_Cookie *sent_cookie,
                                     const SocketDNSCookie_Cookie *response);

/**
 * @brief Check if an RCODE indicates BADCOOKIE.
 * @ingroup dns_cookie
 *
 * Convenience function to check for RCODE 23.
 *
 * @param rcode DNS response code (4-bit or extended 12-bit).
 * @return 1 if BADCOOKIE, 0 otherwise.
 */
extern int SocketDNSCookie_is_badcookie (uint16_t rcode);

/* Statistics */

/**
 * @brief Get cookie cache statistics.
 * @ingroup dns_cookie
 *
 * @param cache  Cookie cache instance.
 * @param[out] stats Output statistics structure.
 */
extern void SocketDNSCookie_stats (T cache, SocketDNSCookie_Stats *stats);

/**
 * @brief Reset statistics counters.
 * @ingroup dns_cookie
 *
 * @param cache Cookie cache instance.
 */
extern void SocketDNSCookie_stats_reset (T cache);

/* Utility functions */

/**
 * @brief Compare two cookies for equality.
 * @ingroup dns_cookie
 *
 * Compares client and server cookies using constant-time comparison.
 *
 * @param a First cookie.
 * @param b Second cookie.
 * @return 1 if equal, 0 if different.
 */
extern int SocketDNSCookie_equal (const SocketDNSCookie_Cookie *a,
                                  const SocketDNSCookie_Cookie *b);

/**
 * @brief Format a cookie as a hex string for debugging.
 * @ingroup dns_cookie
 *
 * @param cookie Cookie to format.
 * @param[out] buf Output buffer (must be at least 81 bytes for max cookie).
 * @param buflen Buffer size.
 * @return Length of formatted string, or -1 on error.
 *
 * @code{.c}
 * char hex[81];
 * SocketDNSCookie_to_hex(&cookie, hex, sizeof(hex));
 * printf("Cookie: %s\n", hex);
 * // Output: "0123456789abcdef:0011223344556677889900aabbccddeeff"
 * @endcode
 */
extern int SocketDNSCookie_to_hex (const SocketDNSCookie_Cookie *cookie,
                                   char *buf, size_t buflen);

/** @} */ /* End of dns_cookie group */

#undef T

#endif /* SOCKETDNSCOOKIE_INCLUDED */
