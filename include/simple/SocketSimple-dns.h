/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETSIMPLE_DNS_INCLUDED
#define SOCKETSIMPLE_DNS_INCLUDED

/**
 * @file SocketSimple-dns.h
 * @brief Simple DNS resolution operations.
 */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Types
 *============================================================================*/

/**
 * @brief DNS resolution result.
 */
typedef struct {
    char **addresses;  /**< NULL-terminated array of IP strings (caller must free) */
    int count;         /**< Number of addresses */
    int family;        /**< Address family (AF_INET or AF_INET6) */
} SocketSimple_DNSResult;

/*============================================================================
 * Resolution Functions
 *============================================================================*/

/**
 * @brief Resolve hostname to IP addresses (blocking).
 *
 * Returns all addresses (both IPv4 and IPv6 if available).
 *
 * @param hostname Hostname to resolve.
 * @param result Output result structure.
 * @return 0 on success, -1 on error.
 *
 * Example:
 * @code
 * SocketSimple_DNSResult result;
 * if (Socket_simple_dns_resolve("example.com", &result) == 0) {
 *     for (int i = 0; i < result.count; i++) {
 *         printf("IP: %s\n", result.addresses[i]);
 *     }
 *     Socket_simple_dns_result_free(&result);
 * }
 * @endcode
 */
extern int Socket_simple_dns_resolve(const char *hostname,
                                      SocketSimple_DNSResult *result);

/**
 * @brief Resolve with timeout.
 *
 * @param hostname Hostname to resolve.
 * @param result Output result structure.
 * @param timeout_ms Timeout in milliseconds.
 * @return 0 on success, -1 on error/timeout.
 */
extern int Socket_simple_dns_resolve_timeout(const char *hostname,
                                              SocketSimple_DNSResult *result,
                                              int timeout_ms);

/**
 * @brief Resolve to single IPv4 address.
 *
 * Convenience function for simple use cases.
 *
 * @param hostname Hostname to resolve.
 * @param buf Output buffer for IP string.
 * @param len Buffer length (at least 16 bytes for IPv4).
 * @return 0 on success, -1 on error.
 *
 * Example:
 * @code
 * char ip[46];
 * if (Socket_simple_dns_lookup("example.com", ip, sizeof(ip)) == 0) {
 *     printf("IP: %s\n", ip);
 * }
 * @endcode
 */
extern int Socket_simple_dns_lookup(const char *hostname,
                                     char *buf,
                                     size_t len);

/**
 * @brief Resolve to single IPv4 address (prefer IPv4).
 *
 * @param hostname Hostname to resolve.
 * @param buf Output buffer.
 * @param len Buffer length.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_dns_lookup4(const char *hostname,
                                      char *buf,
                                      size_t len);

/**
 * @brief Resolve to single IPv6 address (prefer IPv6).
 *
 * @param hostname Hostname to resolve.
 * @param buf Output buffer (at least 46 bytes).
 * @param len Buffer length.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_dns_lookup6(const char *hostname,
                                      char *buf,
                                      size_t len);

/**
 * @brief Reverse DNS lookup.
 *
 * @param ip IP address string (IPv4 or IPv6).
 * @param hostname Output buffer for hostname.
 * @param len Buffer length.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_dns_reverse(const char *ip,
                                      char *hostname,
                                      size_t len);

/*============================================================================
 * Cleanup
 *============================================================================*/

/**
 * @brief Free DNS result resources.
 *
 * @param result Result structure to free.
 */
extern void Socket_simple_dns_result_free(SocketSimple_DNSResult *result);

#ifdef __cplusplus
}
#endif

#endif /* SOCKETSIMPLE_DNS_INCLUDED */
