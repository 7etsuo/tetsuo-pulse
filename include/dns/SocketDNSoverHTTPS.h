/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETDNSOVERHTTPS_INCLUDED
#define SOCKETDNSOVERHTTPS_INCLUDED

/**
 * @file SocketDNSoverHTTPS.h
 * @brief DNS-over-HTTPS transport (RFC 8484).
 * @ingroup dns
 *
 * Provides encrypted DNS transport using HTTPS on port 443. Uses the existing
 * HTTP client for transport with HTTP/2 multiplexing support.
 *
 * ## RFC References
 *
 * - RFC 8484: DNS Queries over HTTPS (DoH)
 *
 * ## Features
 *
 * - POST method with application/dns-message content type (default)
 * - GET method with base64url-encoded DNS query parameter
 * - HTTP/2 multiplexing for concurrent queries
 * - Cache-Control header integration
 * - Non-blocking async operation
 * - Well-known server presets (Google, Cloudflare, Quad9)
 *
 * ## Usage Example
 *
 * @code{.c}
 * Arena_T arena = Arena_new();
 * SocketDNSoverHTTPS_T doh = SocketDNSoverHTTPS_new(arena);
 *
 * // Add well-known server
 * SocketDNSoverHTTPS_add_server(doh, "cloudflare");
 *
 * // Send query
 * SocketDNSoverHTTPS_query(doh, query_buf, query_len, callback, userdata);
 *
 * // Event loop
 * while (SocketDNSoverHTTPS_pending_count(doh) > 0) {
 *     SocketDNSoverHTTPS_process(doh, 100);
 * }
 *
 * SocketDNSoverHTTPS_free(&doh);
 * @endcode
 *
 * @see SocketDNSoverTLS.h for DNS-over-TLS transport.
 * @see SocketHTTPClient.h for HTTP client operations.
 */

#include "core/Arena.h"
#include "core/Except.h"
#include <stddef.h>
#include <stdint.h>

#if SOCKET_HAS_TLS

/**
 * @defgroup dns_doh DNS-over-HTTPS
 * @brief Encrypted DNS transport using HTTPS.
 * @ingroup dns
 * @{
 */

/** Default DoH path (RFC 8484). */
#define DOH_DEFAULT_PATH "/dns-query"

/** Query timeout in milliseconds. */
#define DOH_QUERY_TIMEOUT_MS 5000

/** Connection timeout in milliseconds. */
#define DOH_CONNECT_TIMEOUT_MS 10000

/** Maximum configured servers per transport. */
#define DOH_MAX_SERVERS 8

/** Maximum pending queries per transport. */
#define DOH_MAX_PENDING_QUERIES 100

/** Maximum server URL length in ServerConfig. */
#define DOH_MAX_SERVER_URL_LENGTH 512

/* Error codes for callback */
#define DOH_ERROR_SUCCESS 0         /**< Query completed successfully */
#define DOH_ERROR_TIMEOUT -1        /**< Query timeout */
#define DOH_ERROR_CANCELLED -2      /**< Query cancelled */
#define DOH_ERROR_NETWORK -3        /**< Network/socket error */
#define DOH_ERROR_TLS -4            /**< TLS error */
#define DOH_ERROR_HTTP -5           /**< HTTP error (non-2xx status) */
#define DOH_ERROR_INVALID -6        /**< Invalid DNS response */
#define DOH_ERROR_NO_SERVER -7      /**< No server configured */
#define DOH_ERROR_CONTENT_TYPE -8   /**< Wrong Content-Type in response */
#define DOH_ERROR_FORMERR -9        /**< Server returned FORMERR */
#define DOH_ERROR_SERVFAIL -10      /**< Server returned SERVFAIL */
#define DOH_ERROR_NXDOMAIN -11      /**< Domain does not exist */
#define DOH_ERROR_REFUSED -12       /**< Server refused query */

/**
 * @brief DNS-over-HTTPS HTTP method preference.
 * @ingroup dns_doh
 */
typedef enum
{
  /**
   * POST method (default, recommended).
   * Smaller request size, binary DNS message in body.
   */
  DOH_METHOD_POST = 0,

  /**
   * GET method.
   * Base64URL-encoded DNS query in ?dns= parameter.
   * May be cacheable by HTTP proxies.
   */
  DOH_METHOD_GET = 1

} SocketDNSoverHTTPS_Method;

/**
 * @brief DNS-over-HTTPS transport operation failure exception.
 * @ingroup dns_doh
 *
 * Raised for initialization failures, invalid parameters, or resource
 * exhaustion.
 */
extern const Except_T SocketDNSoverHTTPS_Failed;

#define T SocketDNSoverHTTPS_T
typedef struct T *T;

/**
 * @brief Opaque handle for a pending DoH query.
 * @ingroup dns_doh
 */
typedef struct SocketDNSoverHTTPS_Query *SocketDNSoverHTTPS_Query_T;

/**
 * @brief Query completion callback function type.
 * @ingroup dns_doh
 *
 * Invoked when a DNS-over-HTTPS query completes (success or error).
 *
 * @param query    Query handle that completed.
 * @param response Response buffer (NULL on error).
 * @param len      Response length in bytes.
 * @param error    Error code (DOH_ERROR_*).
 * @param userdata User data passed to query function.
 *
 * @note Response buffer is only valid during callback; copy if needed.
 */
typedef void (*SocketDNSoverHTTPS_Callback) (SocketDNSoverHTTPS_Query_T query,
                                              const unsigned char *response,
                                              size_t len, int error,
                                              void *userdata);

/**
 * @brief DNS-over-HTTPS server configuration.
 * @ingroup dns_doh
 *
 * Configuration for a DoH server connection.
 */
typedef struct
{
  const char *url; /**< Full DoH URL (e.g., "https://dns.google/dns-query") */
  SocketDNSoverHTTPS_Method method; /**< HTTP method preference */
  int prefer_http2;                 /**< Prefer HTTP/2 (default: 1) */
  int timeout_ms;                   /**< Query timeout in milliseconds */

} SocketDNSoverHTTPS_Config;

/**
 * @brief Connection statistics.
 * @ingroup dns_doh
 */
typedef struct
{
  uint64_t queries_sent;      /**< Total queries sent */
  uint64_t queries_completed; /**< Queries completed successfully */
  uint64_t queries_failed;    /**< Queries that failed */
  uint64_t http2_requests;    /**< Requests sent via HTTP/2 */
  uint64_t http1_requests;    /**< Requests sent via HTTP/1.1 */
  uint64_t bytes_sent;        /**< Total bytes sent */
  uint64_t bytes_received;    /**< Total bytes received */
} SocketDNSoverHTTPS_Stats;

/* Lifecycle functions */

/**
 * @brief Create a new DNS-over-HTTPS transport instance.
 * @ingroup dns_doh
 *
 * @param arena Arena for memory allocation (must outlive transport).
 * @return New transport instance.
 * @throws SocketDNSoverHTTPS_Failed on allocation failure.
 */
extern T SocketDNSoverHTTPS_new (Arena_T arena);

/**
 * @brief Dispose of a DNS-over-HTTPS transport instance.
 * @ingroup dns_doh
 *
 * Cancels all pending queries and closes HTTP connections.
 *
 * @param transport Pointer to transport instance.
 */
extern void SocketDNSoverHTTPS_free (T *transport);

/* Configuration */

/**
 * @brief Configure a DoH server.
 * @ingroup dns_doh
 *
 * @param transport Transport instance.
 * @param config    Server configuration.
 * @return 0 on success, -1 on error.
 */
extern int SocketDNSoverHTTPS_configure (T transport,
                                          const SocketDNSoverHTTPS_Config *config);

/**
 * @brief Add a preconfigured DoH server by name.
 * @ingroup dns_doh
 *
 * Convenience function to add well-known DoH servers.
 *
 * Supported names:
 * - "google": https://dns.google/dns-query
 * - "cloudflare": https://cloudflare-dns.com/dns-query
 * - "quad9": https://dns.quad9.net/dns-query
 * - "nextdns": https://dns.nextdns.io
 *
 * @param transport   Transport instance.
 * @param server_name Name of well-known server.
 * @return 0 on success, -1 if name unknown.
 */
extern int SocketDNSoverHTTPS_add_server (T transport, const char *server_name);

/**
 * @brief Clear all configured servers.
 * @ingroup dns_doh
 *
 * @param transport Transport instance.
 */
extern void SocketDNSoverHTTPS_clear_servers (T transport);

/**
 * @brief Get number of configured servers.
 * @ingroup dns_doh
 *
 * @param transport Transport instance.
 * @return Number of configured servers.
 */
extern int SocketDNSoverHTTPS_server_count (T transport);

/* Query functions */

/**
 * @brief Send a DNS query via DoH.
 * @ingroup dns_doh
 *
 * Sends the query over HTTPS. Uses POST (default) or GET method
 * depending on server configuration.
 *
 * @param transport Transport instance.
 * @param query     Encoded DNS query message.
 * @param len       Query length in bytes.
 * @param callback  Completion callback (required).
 * @param userdata  User data passed to callback.
 * @return Query handle on success, NULL on error.
 */
extern SocketDNSoverHTTPS_Query_T SocketDNSoverHTTPS_query (
    T transport, const unsigned char *query, size_t len,
    SocketDNSoverHTTPS_Callback callback, void *userdata);

/**
 * @brief Cancel a pending query.
 * @ingroup dns_doh
 *
 * @param transport Transport instance.
 * @param query     Query handle to cancel.
 * @return 0 on success, -1 if query not found.
 */
extern int SocketDNSoverHTTPS_cancel (T transport,
                                       SocketDNSoverHTTPS_Query_T query);

/**
 * @brief Get query ID from query handle.
 * @ingroup dns_doh
 *
 * @param query Query handle.
 * @return DNS message ID (uint16_t).
 */
extern uint16_t SocketDNSoverHTTPS_query_id (SocketDNSoverHTTPS_Query_T query);

/* Event loop integration */

/**
 * @brief Process pending queries and HTTP requests.
 * @ingroup dns_doh
 *
 * Handles HTTP request/response processing, manages timeouts.
 * Must be called regularly in the event loop.
 *
 * @param transport  Transport instance.
 * @param timeout_ms Maximum time to wait for events (0 = non-blocking).
 * @return Number of queries completed, or -1 on error.
 */
extern int SocketDNSoverHTTPS_process (T transport, int timeout_ms);

/**
 * @brief Get number of pending queries.
 * @ingroup dns_doh
 *
 * @param transport Transport instance.
 * @return Number of queries awaiting response.
 */
extern int SocketDNSoverHTTPS_pending_count (T transport);

/* Statistics */

/**
 * @brief Get connection statistics.
 * @ingroup dns_doh
 *
 * @param transport Transport instance.
 * @param stats     Output statistics structure.
 */
extern void SocketDNSoverHTTPS_stats (T transport,
                                       SocketDNSoverHTTPS_Stats *stats);

/* Utility functions */

/**
 * @brief Convert DoH error code to string.
 * @ingroup dns_doh
 *
 * @param error Error code (DOH_ERROR_*).
 * @return Human-readable error string.
 */
extern const char *SocketDNSoverHTTPS_strerror (int error);

/** @} */ /* End of dns_doh group */

#undef T

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETDNSOVERHTTPS_INCLUDED */
