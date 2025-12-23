/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETDNSOVERTLS_INCLUDED
#define SOCKETDNSOVERTLS_INCLUDED

/**
 * @file SocketDNSoverTLS.h
 * @brief DNS-over-TLS transport (RFC 7858, RFC 8310).
 * @ingroup dns
 *
 * Provides encrypted DNS transport using TLS on port 853. Wraps the existing
 * TCP transport with TLS for privacy protection against eavesdropping and
 * tampering.
 *
 * ## RFC References
 *
 * - RFC 7858: Specification for DNS over TLS
 * - RFC 8310: Usage Profiles for DNS over TLS and DNS over DTLS
 *
 * ## Features
 *
 * - TLS 1.2+ encryption on port 853
 * - Same 2-byte length prefix framing as DNS-over-TCP (RFC 1035 Section 4.2.2)
 * - TLS session resumption for connection reuse
 * - Opportunistic privacy mode (encryption without authentication)
 * - Strict privacy mode (require certificate validation)
 * - SPKI pinning for known resolvers (RFC 7858 Section 4.2)
 * - Non-blocking async operation
 * - Connection pooling per nameserver
 *
 * ## Usage Profiles (RFC 8310)
 *
 * ### Opportunistic Privacy (Section 5)
 * Encrypts traffic but does not require server authentication.
 * Protects against passive eavesdropping.
 *
 * ### Strict Privacy (Section 5)
 * Requires TLS and valid server certificate.
 * Fails if server cannot be authenticated.
 *
 * ## Usage Example
 *
 * @code{.c}
 * Arena_T arena = Arena_new();
 * SocketDNSoverTLS_T dot = SocketDNSoverTLS_new(arena);
 *
 * // Configure server
 * SocketDNSoverTLS_Config config = {
 *     .server_address = "8.8.8.8",
 *     .port = 853,
 *     .server_name = "dns.google",
 *     .mode = DOT_MODE_STRICT,
 *     .spki_pin = NULL  // Optional SPKI pin
 * };
 * SocketDNSoverTLS_configure(dot, &config);
 *
 * // Send query
 * SocketDNSoverTLS_query(dot, query_buf, query_len, callback, userdata);
 *
 * // Event loop
 * while (SocketDNSoverTLS_pending_count(dot) > 0) {
 *     SocketDNSoverTLS_process(dot, 100);
 * }
 *
 * SocketDNSoverTLS_free(&dot);
 * @endcode
 *
 * @see SocketDNSTransport.h for plaintext UDP/TCP transport.
 * @see SocketTLS.h for TLS socket operations.
 */

#include "core/Arena.h"
#include "core/Except.h"
#include <stddef.h>
#include <stdint.h>

#if SOCKET_HAS_TLS

/**
 * @defgroup dns_dot DNS-over-TLS
 * @brief Encrypted DNS transport using TLS.
 * @ingroup dns
 * @{
 */

/** Default DNS-over-TLS port (RFC 7858). */
#define DOT_PORT 853

/** TLS handshake timeout in milliseconds. */
#define DOT_HANDSHAKE_TIMEOUT_MS 5000

/** Connection idle timeout before closing (per RFC 7858 Section 3.4). */
#define DOT_IDLE_TIMEOUT_MS 120000

/** Maximum cached TLS connections per transport. */
#define DOT_MAX_CONNECTIONS 8

/** Maximum pending queries per transport. */
#define DOT_MAX_PENDING_QUERIES 100

/* Error codes for callback */
#define DOT_ERROR_SUCCESS 0        /**< Query completed successfully */
#define DOT_ERROR_TIMEOUT -1       /**< Query timeout */
#define DOT_ERROR_CANCELLED -2     /**< Query cancelled */
#define DOT_ERROR_NETWORK -3       /**< Network/socket error */
#define DOT_ERROR_TLS_HANDSHAKE -4 /**< TLS handshake failed */
#define DOT_ERROR_TLS_VERIFY -5    /**< Certificate verification failed */
#define DOT_ERROR_TLS_IO -6        /**< TLS I/O error */
#define DOT_ERROR_INVALID -7       /**< Invalid response */
#define DOT_ERROR_NO_SERVER -8     /**< No server configured */
#define DOT_ERROR_FORMERR -9       /**< Server returned FORMERR */
#define DOT_ERROR_SERVFAIL -10     /**< Server returned SERVFAIL */
#define DOT_ERROR_NXDOMAIN -11     /**< Domain does not exist */
#define DOT_ERROR_REFUSED -12      /**< Server refused query */
#define DOT_ERROR_SPKI_MISMATCH -13 /**< SPKI pin mismatch (RFC 7858 Section 4.2) */

/**
 * @brief DNS-over-TLS privacy modes (RFC 8310 Section 5).
 * @ingroup dns_dot
 */
typedef enum
{
  /**
   * Opportunistic privacy: Use TLS if available, allow any certificate.
   * Protects against passive eavesdropping but not active attacks.
   */
  DOT_MODE_OPPORTUNISTIC = 0,

  /**
   * Strict privacy: Require valid TLS and authenticated server.
   * Fail if server certificate cannot be validated.
   */
  DOT_MODE_STRICT = 1

} SocketDNSoverTLS_Mode;

/**
 * @brief DNS-over-TLS transport operation failure exception.
 * @ingroup dns_dot
 *
 * Raised for initialization failures, invalid parameters, or resource
 * exhaustion.
 */
extern const Except_T SocketDNSoverTLS_Failed;

#define T SocketDNSoverTLS_T
typedef struct T *T;

/**
 * @brief Opaque handle for a pending DoT query.
 * @ingroup dns_dot
 */
typedef struct SocketDNSoverTLS_Query *SocketDNSoverTLS_Query_T;

/**
 * @brief Query completion callback function type.
 * @ingroup dns_dot
 *
 * Invoked when a DNS-over-TLS query completes (success or error).
 *
 * @param query    Query handle that completed.
 * @param response Response buffer (NULL on error).
 * @param len      Response length in bytes.
 * @param error    Error code (DOT_ERROR_*).
 * @param userdata User data passed to query function.
 *
 * @note Response buffer is only valid during callback; copy if needed.
 */
typedef void (*SocketDNSoverTLS_Callback) (SocketDNSoverTLS_Query_T query,
                                           const unsigned char *response,
                                           size_t len, int error,
                                           void *userdata);

/**
 * @brief DNS-over-TLS server configuration.
 * @ingroup dns_dot
 *
 * Configuration for a DoT server connection.
 */
typedef struct
{
  const char *server_address;  /**< Server IPv4 or IPv6 address */
  int port;                    /**< Port number (default: 853) */
  const char *server_name;     /**< TLS SNI hostname (e.g., "dns.google") */
  SocketDNSoverTLS_Mode mode;  /**< Privacy mode */

  /**
   * Optional SPKI pin for Out-of-Band Key-Pinned Privacy (RFC 7858 Section 4.2).
   * Base64-encoded SHA-256 hash of the server's SPKI.
   * If NULL, SPKI pinning is disabled.
   */
  const char *spki_pin;

  /**
   * Optional backup SPKI pin for key rollover (RFC 7858 Section 4.2).
   * If primary pin fails, try this one.
   */
  const char *spki_pin_backup;

} SocketDNSoverTLS_Config;

/**
 * @brief Connection statistics.
 * @ingroup dns_dot
 */
typedef struct
{
  uint64_t queries_sent;       /**< Total queries sent */
  uint64_t queries_completed;  /**< Queries completed successfully */
  uint64_t queries_failed;     /**< Queries that failed */
  uint64_t connections_opened; /**< TLS connections opened */
  uint64_t connections_reused; /**< Connections reused via session resumption */
  uint64_t handshake_failures; /**< TLS handshake failures */
  uint64_t verify_failures;    /**< Certificate verification failures */
  uint64_t bytes_sent;         /**< Total bytes sent (encrypted) */
  uint64_t bytes_received;     /**< Total bytes received (encrypted) */
} SocketDNSoverTLS_Stats;

/* Lifecycle functions */

/**
 * @brief Create a new DNS-over-TLS transport instance.
 * @ingroup dns_dot
 *
 * @param arena Arena for memory allocation (must outlive transport).
 * @return New transport instance.
 * @throws SocketDNSoverTLS_Failed on allocation failure.
 */
extern T SocketDNSoverTLS_new (Arena_T arena);

/**
 * @brief Dispose of a DNS-over-TLS transport instance.
 * @ingroup dns_dot
 *
 * Cancels all pending queries and closes TLS connections.
 *
 * @param transport Pointer to transport instance.
 */
extern void SocketDNSoverTLS_free (T *transport);

/* Configuration */

/**
 * @brief Configure a DoT server.
 * @ingroup dns_dot
 *
 * @param transport Transport instance.
 * @param config    Server configuration.
 * @return 0 on success, -1 on error.
 */
extern int SocketDNSoverTLS_configure (T transport,
                                       const SocketDNSoverTLS_Config *config);

/**
 * @brief Add a preconfigured DoT server by name.
 * @ingroup dns_dot
 *
 * Convenience function to add well-known DoT servers.
 *
 * Supported names:
 * - "google": 8.8.8.8:853, dns.google
 * - "google-v6": 2001:4860:4860::8888:853, dns.google
 * - "cloudflare": 1.1.1.1:853, cloudflare-dns.com
 * - "cloudflare-v6": 2606:4700:4700::1111:853, cloudflare-dns.com
 * - "quad9": 9.9.9.9:853, dns.quad9.net
 * - "quad9-v6": 2620:fe::fe:853, dns.quad9.net
 *
 * @param transport   Transport instance.
 * @param server_name Name of well-known server.
 * @param mode        Privacy mode to use.
 * @return 0 on success, -1 if name unknown.
 */
extern int SocketDNSoverTLS_add_server (T transport, const char *server_name,
                                        SocketDNSoverTLS_Mode mode);

/**
 * @brief Clear all configured servers.
 * @ingroup dns_dot
 *
 * @param transport Transport instance.
 */
extern void SocketDNSoverTLS_clear_servers (T transport);

/**
 * @brief Get number of configured servers.
 * @ingroup dns_dot
 *
 * @param transport Transport instance.
 * @return Number of configured servers.
 */
extern int SocketDNSoverTLS_server_count (T transport);

/* Query functions */

/**
 * @brief Send a DNS query via DoT.
 * @ingroup dns_dot
 *
 * Sends the query over TLS. If no connection exists, establishes one
 * (with TLS handshake). Supports session resumption for fast reconnects.
 *
 * @param transport Transport instance.
 * @param query     Encoded DNS query message.
 * @param len       Query length in bytes.
 * @param callback  Completion callback (required).
 * @param userdata  User data passed to callback.
 * @return Query handle on success, NULL on error.
 *
 * @note The 2-byte length prefix is added automatically.
 */
extern SocketDNSoverTLS_Query_T SocketDNSoverTLS_query (
    T transport, const unsigned char *query, size_t len,
    SocketDNSoverTLS_Callback callback, void *userdata);

/**
 * @brief Cancel a pending query.
 * @ingroup dns_dot
 *
 * @param transport Transport instance.
 * @param query     Query handle to cancel.
 * @return 0 on success, -1 if query not found.
 */
extern int SocketDNSoverTLS_cancel (T transport, SocketDNSoverTLS_Query_T query);

/**
 * @brief Get query ID from query handle.
 * @ingroup dns_dot
 *
 * @param query Query handle.
 * @return DNS message ID (uint16_t).
 */
extern uint16_t SocketDNSoverTLS_query_id (SocketDNSoverTLS_Query_T query);

/* Event loop integration */

/**
 * @brief Process pending queries and connections.
 * @ingroup dns_dot
 *
 * Handles TLS handshakes, sends/receives data, manages timeouts.
 * Must be called regularly in the event loop.
 *
 * @param transport  Transport instance.
 * @param timeout_ms Maximum time to wait for events (0 = non-blocking).
 * @return Number of queries completed, or -1 on error.
 */
extern int SocketDNSoverTLS_process (T transport, int timeout_ms);

/**
 * @brief Get the socket file descriptor for poll integration.
 * @ingroup dns_dot
 *
 * Returns the current active connection's socket fd for external poll.
 * May return -1 if no connection is established.
 *
 * @param transport Transport instance.
 * @return File descriptor or -1.
 */
extern int SocketDNSoverTLS_fd (T transport);

/**
 * @brief Get number of pending queries.
 * @ingroup dns_dot
 *
 * @param transport Transport instance.
 * @return Number of queries awaiting response.
 */
extern int SocketDNSoverTLS_pending_count (T transport);

/* Connection management */

/**
 * @brief Close all TLS connections.
 * @ingroup dns_dot
 *
 * Performs graceful TLS shutdown on all connections. Pending queries
 * are cancelled with DOT_ERROR_CANCELLED.
 *
 * @param transport Transport instance.
 */
extern void SocketDNSoverTLS_close_all (T transport);

/**
 * @brief Check if a connection is established.
 * @ingroup dns_dot
 *
 * @param transport Transport instance.
 * @return 1 if connected, 0 otherwise.
 */
extern int SocketDNSoverTLS_is_connected (T transport);

/**
 * @brief Get connection statistics.
 * @ingroup dns_dot
 *
 * @param transport Transport instance.
 * @param stats     Output statistics structure.
 */
extern void SocketDNSoverTLS_stats (T transport, SocketDNSoverTLS_Stats *stats);

/* Utility functions */

/**
 * @brief Convert DoT error code to string.
 * @ingroup dns_dot
 *
 * @param error Error code (DOT_ERROR_*).
 * @return Human-readable error string.
 */
extern const char *SocketDNSoverTLS_strerror (int error);

/** @} */ /* End of dns_dot group */

#undef T

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETDNSOVERTLS_INCLUDED */
