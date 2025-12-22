/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETSIMPLE_HAPPYEYEBALLS_INCLUDED
#define SOCKETSIMPLE_HAPPYEYEBALLS_INCLUDED

/**
 * @file SocketSimple-happyeyeballs.h
 * @brief RFC 8305 Happy Eyeballs v2 dual-stack connection racing.
 *
 * Provides fast dual-stack connection establishment by racing IPv4 and IPv6
 * connections. Uses the winning connection and cancels the other.
 *
 * ## Quick Start
 *
 * ```c
 * #include <simple/SocketSimple.h>
 *
 * // Simple dual-stack connect (uses best available connection)
 * SocketSimple_Socket_T sock = Socket_simple_happyeyeballs_connect(
 *     "example.com", 443, 5000);
 * if (!sock) {
 *     fprintf(stderr, "Error: %s\n", Socket_simple_error());
 *     return 1;
 * }
 *
 * // Use socket normally
 * Socket_simple_send(sock, "GET / HTTP/1.1\r\n", 16);
 * Socket_simple_close(&sock);
 * ```
 *
 * ## Algorithm (RFC 8305)
 *
 * 1. Resolve hostname to both IPv6 and IPv4 addresses
 * 2. Start IPv6 connection first (preferred)
 * 3. If IPv6 doesn't complete within delay (250ms default), start IPv4
 * 4. Return the first successful connection
 * 5. Cancel any pending connections
 */

#include "SocketSimple-tcp.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Configuration
 *============================================================================*/

/**
 * @brief Happy Eyeballs connection configuration.
 */
typedef struct SocketSimple_HappyEyeballs_Config {
    int resolution_delay_ms;  /**< Delay before starting parallel resolution (default: 50) */
    int connection_delay_ms;  /**< Delay before starting IPv4 after IPv6 (default: 250) */
    int prefer_ipv6;          /**< 1 to prefer IPv6, 0 to prefer IPv4 (default: 1) */
    int max_attempts;         /**< Max addresses to try per family (0=unlimited, default: 0) */
} SocketSimple_HappyEyeballs_Config;

/*============================================================================
 * Connection Functions
 *============================================================================*/

/**
 * @brief Connect using Happy Eyeballs algorithm (RFC 8305).
 *
 * Races IPv4 and IPv6 connections to minimize connection time on
 * dual-stack networks.
 *
 * @param host Hostname or IP address.
 * @param port Port number (1-65535).
 * @param timeout_ms Overall timeout in milliseconds.
 * @return Socket handle on success, NULL on error.
 *
 * Example:
 * @code
 * SocketSimple_Socket_T sock = Socket_simple_happyeyeballs_connect(
 *     "www.google.com", 443, 10000);
 * if (!sock) {
 *     fprintf(stderr, "Connect failed: %s\n", Socket_simple_error());
 * }
 * @endcode
 */
extern SocketSimple_Socket_T Socket_simple_happyeyeballs_connect(
    const char *host,
    int port,
    int timeout_ms);

/**
 * @brief Connect using Happy Eyeballs with custom configuration.
 *
 * @param host Hostname or IP address.
 * @param port Port number.
 * @param timeout_ms Overall timeout.
 * @param config Custom configuration (NULL for defaults).
 * @return Socket handle on success, NULL on error.
 */
extern SocketSimple_Socket_T Socket_simple_happyeyeballs_connect_config(
    const char *host,
    int port,
    int timeout_ms,
    const SocketSimple_HappyEyeballs_Config *config);

/*============================================================================
 * Configuration Helpers
 *============================================================================*/

/**
 * @brief Initialize configuration with default values.
 *
 * Default values per RFC 8305:
 * - resolution_delay_ms: 50
 * - connection_delay_ms: 250
 * - prefer_ipv6: 1
 * - max_attempts: 0 (unlimited)
 *
 * @param config Configuration structure to initialize.
 */
extern void Socket_simple_happyeyeballs_config_defaults(
    SocketSimple_HappyEyeballs_Config *config);

/*============================================================================
 * Query Functions
 *============================================================================*/

/**
 * @brief Get address family of connected socket.
 *
 * @param sock Socket handle.
 * @return AF_INET (2) for IPv4, AF_INET6 (10) for IPv6, -1 on error.
 */
extern int Socket_simple_get_family(SocketSimple_Socket_T sock);

/**
 * @brief Check if socket is using IPv6.
 *
 * @param sock Socket handle.
 * @return 1 if IPv6, 0 if IPv4, -1 on error.
 */
extern int Socket_simple_is_ipv6(SocketSimple_Socket_T sock);

/**
 * @brief Check if socket is using IPv4.
 *
 * @param sock Socket handle.
 * @return 1 if IPv4, 0 if IPv6, -1 on error.
 */
extern int Socket_simple_is_ipv4(SocketSimple_Socket_T sock);

#ifdef __cplusplus
}
#endif

#endif /* SOCKETSIMPLE_HAPPYEYEBALLS_INCLUDED */
