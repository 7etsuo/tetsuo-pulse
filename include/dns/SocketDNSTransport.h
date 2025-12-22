/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETDNSTRANSPORT_INCLUDED
#define SOCKETDNSTRANSPORT_INCLUDED

/**
 * @file SocketDNSTransport.h
 * @brief DNS UDP transport layer (RFC 1035 Section 4.2.1).
 * @ingroup dns
 *
 * Provides async UDP transport for DNS queries with automatic retry,
 * timeout handling, and nameserver rotation. Integrates with SocketPoll
 * for event-driven operation.
 *
 * ## RFC References
 *
 * - RFC 1035 Section 4.2.1: UDP usage (port 53, 512 byte limit)
 * - RFC 1035 Section 4.2.2: TCP usage (for truncated responses)
 *
 * ## Features
 *
 * - Non-blocking async queries with callbacks
 * - Automatic retry with exponential backoff
 * - Nameserver rotation on failure
 * - Truncation detection (TC bit)
 * - IPv4 and IPv6 nameserver support
 *
 * @see SocketDNSWire.h for message encoding/decoding.
 * @see SocketDNS.h for the high-level resolver API.
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "dns/SocketDNSWire.h"
#include "poll/SocketPoll.h"
#include <stddef.h>
#include <stdint.h>

/**
 * @defgroup dns_transport DNS Transport Layer
 * @brief UDP and TCP transport for DNS queries.
 * @ingroup dns
 * @{
 */

/** Maximum UDP message size per RFC 1035 Section 4.2.1 (512 bytes). */
#define DNS_UDP_MAX_SIZE 512

/** Default DNS port (RFC 1035). */
#define DNS_PORT 53

/** Default initial retry timeout in milliseconds (RFC 1035 recommends 2-5s). */
#define DNS_RETRY_INITIAL_MS 2000

/** Maximum retry timeout in milliseconds. */
#define DNS_RETRY_MAX_MS 5000

/** Default maximum retry attempts. */
#define DNS_RETRY_MAX_ATTEMPTS 3

/** Maximum configurable nameservers. */
#define DNS_MAX_NAMESERVERS 8

/** Maximum pending queries (resource limit). */
#define DNS_MAX_PENDING_QUERIES 1000

/* Error codes for callback */
#define DNS_ERROR_SUCCESS 0    /**< Query completed successfully */
#define DNS_ERROR_TIMEOUT -1   /**< All retries exhausted */
#define DNS_ERROR_TRUNCATED -2 /**< Response TC bit set (use TCP) */
#define DNS_ERROR_CANCELLED -3 /**< Query cancelled by user */
#define DNS_ERROR_NETWORK -4   /**< Network/socket error */
#define DNS_ERROR_INVALID -5   /**< Invalid response (bad ID, etc.) */
#define DNS_ERROR_FORMERR -6   /**< Server returned FORMERR */
#define DNS_ERROR_SERVFAIL -7  /**< Server returned SERVFAIL */
#define DNS_ERROR_NXDOMAIN -8  /**< Domain does not exist */
#define DNS_ERROR_REFUSED -9   /**< Server refused query */
#define DNS_ERROR_NONS -10     /**< No nameservers configured */

/**
 * @brief DNS transport operation failure exception.
 * @ingroup dns_transport
 *
 * Raised for transport initialization failures, invalid parameters,
 * or resource exhaustion.
 */
extern const Except_T SocketDNSTransport_Failed;

#define T SocketDNSTransport_T
typedef struct T *T;

/**
 * @brief Opaque handle for a pending DNS query.
 * @ingroup dns_transport
 */
typedef struct SocketDNSQuery *SocketDNSQuery_T;

/**
 * @brief Query completion callback function type.
 * @ingroup dns_transport
 *
 * Invoked when a DNS query completes (success, error, or timeout).
 * The callback is invoked during SocketDNSTransport_process().
 *
 * @param query    Query handle that completed.
 * @param response Response buffer (NULL on error/timeout).
 * @param len      Response length in bytes.
 * @param error    Error code (0=success, negative=error).
 * @param userdata User data passed to query function.
 *
 * @note Response buffer is only valid during callback; copy if needed.
 * @note Do not call SocketDNSTransport_free() from within callback.
 */
typedef void (*SocketDNSTransport_Callback) (SocketDNSQuery_T query,
                                             const unsigned char *response,
                                             size_t len, int error,
                                             void *userdata);

/**
 * @brief Nameserver address information.
 * @ingroup dns_transport
 */
typedef struct
{
  char address[64]; /**< IPv4 or IPv6 address string */
  int port;         /**< Port number (default: 53) */
  int family;       /**< AF_INET or AF_INET6 (0 for auto-detect) */
} SocketDNS_Nameserver;

/**
 * @brief Transport configuration options.
 * @ingroup dns_transport
 */
typedef struct
{
  int initial_timeout_ms; /**< Initial retry timeout (default: 2000ms) */
  int max_timeout_ms;     /**< Maximum retry timeout (default: 5000ms) */
  int max_retries;        /**< Maximum retry attempts (default: 3) */
  int rotate_nameservers; /**< Rotate through nameservers on retry (default: 1) */
} SocketDNSTransport_Config;

/**
 * @brief Create a new DNS UDP transport instance.
 * @ingroup dns_transport
 *
 * Creates transport with UDP sockets for both IPv4 and IPv6.
 * Sockets are configured non-blocking for async operation.
 *
 * @param arena Arena for memory allocation (must outlive transport).
 * @param poll  Poll instance for timer integration (may be NULL for sync mode).
 * @return New transport instance.
 * @throws SocketDNSTransport_Failed on allocation or socket creation failure.
 *
 * @code{.c}
 * Arena_T arena = Arena_new();
 * SocketPoll_T poll = SocketPoll_new(64);
 * SocketDNSTransport_T transport = SocketDNSTransport_new(arena, poll);
 * SocketDNSTransport_add_nameserver(transport, "8.8.8.8", DNS_PORT);
 * @endcode
 */
extern T SocketDNSTransport_new (Arena_T arena, SocketPoll_T poll);

/**
 * @brief Dispose of a DNS transport instance.
 * @ingroup dns_transport
 *
 * Cancels all pending queries (callbacks invoked with DNS_ERROR_CANCELLED)
 * and releases resources. The transport pointer is set to NULL.
 *
 * @param transport Pointer to transport instance.
 */
extern void SocketDNSTransport_free (T *transport);

/**
 * @brief Add a nameserver to the transport.
 * @ingroup dns_transport
 *
 * @param transport Transport instance.
 * @param address   IPv4 or IPv6 address string.
 * @param port      Port number (use DNS_PORT for default).
 * @return 0 on success, -1 if max nameservers reached or invalid address.
 *
 * @code{.c}
 * SocketDNSTransport_add_nameserver(transport, "8.8.8.8", DNS_PORT);
 * SocketDNSTransport_add_nameserver(transport, "8.8.4.4", DNS_PORT);
 * SocketDNSTransport_add_nameserver(transport, "2001:4860:4860::8888", DNS_PORT);
 * @endcode
 */
extern int SocketDNSTransport_add_nameserver (T transport, const char *address,
                                              int port);

/**
 * @brief Remove all configured nameservers.
 * @ingroup dns_transport
 *
 * @param transport Transport instance.
 */
extern void SocketDNSTransport_clear_nameservers (T transport);

/**
 * @brief Get configured nameserver count.
 * @ingroup dns_transport
 *
 * @param transport Transport instance.
 * @return Number of configured nameservers.
 */
extern int SocketDNSTransport_nameserver_count (T transport);

/**
 * @brief Configure transport options.
 * @ingroup dns_transport
 *
 * @param transport Transport instance.
 * @param config    Configuration options (NULL members use defaults).
 */
extern void SocketDNSTransport_configure (T transport,
                                          const SocketDNSTransport_Config *config);

/**
 * @brief Send a DNS query asynchronously via UDP.
 * @ingroup dns_transport
 *
 * Sends the query to the current nameserver. On timeout or failure,
 * automatically retries with exponential backoff per RFC 1035.
 *
 * @param transport Transport instance.
 * @param query     Encoded DNS query message (header + question).
 * @param len       Query length in bytes (must be <= DNS_UDP_MAX_SIZE).
 * @param callback  Completion callback (required).
 * @param userdata  User data passed to callback.
 * @return Query handle on success, NULL on error.
 * @throws SocketDNSTransport_Failed on invalid parameters or resource exhaustion.
 *
 * @note If response TC (truncation) bit is set, callback receives
 *       DNS_ERROR_TRUNCATED. Caller should retry via TCP (issue #135).
 *
 * @code{.c}
 * unsigned char query[512];
 * size_t len;
 * SocketDNS_Header hdr;
 * SocketDNS_header_init_query(&hdr, 0x1234, 1);
 * SocketDNS_header_encode(&hdr, query, sizeof(query));
 * // ... encode question ...
 *
 * SocketDNSQuery_T q = SocketDNSTransport_query_udp(transport, query, len,
 *                                                   my_callback, my_data);
 * @endcode
 */
extern SocketDNSQuery_T SocketDNSTransport_query_udp (
    T transport, const unsigned char *query, size_t len,
    SocketDNSTransport_Callback callback, void *userdata);

/**
 * @brief Cancel a pending query.
 * @ingroup dns_transport
 *
 * The callback will be invoked with DNS_ERROR_CANCELLED during the
 * next SocketDNSTransport_process() call.
 *
 * @param transport Transport instance.
 * @param query     Query handle to cancel.
 * @return 0 on success, -1 if query not found or already completed.
 */
extern int SocketDNSTransport_cancel (T transport, SocketDNSQuery_T query);

/**
 * @brief Process pending queries (receive responses, handle timeouts).
 * @ingroup dns_transport
 *
 * This function must be called regularly to:
 * - Receive and process DNS responses
 * - Fire timeout callbacks
 * - Handle retries
 *
 * In async mode with SocketPoll, call this when the UDP socket FDs
 * are readable or when timers expire.
 *
 * @param transport Transport instance.
 * @param timeout_ms Maximum time to wait for events (0 = non-blocking).
 * @return Number of queries completed, or -1 on error.
 *
 * @code{.c}
 * // Event loop
 * while (running) {
 *     SocketDNSTransport_process(transport, 100);  // 100ms timeout
 * }
 * @endcode
 */
extern int SocketDNSTransport_process (T transport, int timeout_ms);

/**
 * @brief Get query ID from query handle.
 * @ingroup dns_transport
 *
 * @param query Query handle.
 * @return DNS message ID (uint16_t).
 */
extern uint16_t SocketDNSQuery_get_id (SocketDNSQuery_T query);

/**
 * @brief Get current retry count for a query.
 * @ingroup dns_transport
 *
 * @param query Query handle.
 * @return Number of retries so far (0 = first attempt).
 */
extern int SocketDNSQuery_get_retry_count (SocketDNSQuery_T query);

/**
 * @brief Check if a query is still pending.
 * @ingroup dns_transport
 *
 * @param transport Transport instance.
 * @param query     Query handle.
 * @return 1 if pending, 0 if completed or cancelled.
 */
extern int SocketDNSTransport_is_pending (T transport, SocketDNSQuery_T query);

/**
 * @brief Get the IPv4 socket file descriptor.
 * @ingroup dns_transport
 *
 * For external poll integration.
 *
 * @param transport Transport instance.
 * @return File descriptor (>= 0) or -1 if not initialized.
 */
extern int SocketDNSTransport_fd_v4 (T transport);

/**
 * @brief Get the IPv6 socket file descriptor.
 * @ingroup dns_transport
 *
 * For external poll integration.
 *
 * @param transport Transport instance.
 * @return File descriptor (>= 0) or -1 if not initialized.
 */
extern int SocketDNSTransport_fd_v6 (T transport);

/**
 * @brief Get number of pending queries.
 * @ingroup dns_transport
 *
 * @param transport Transport instance.
 * @return Number of queries awaiting response.
 */
extern int SocketDNSTransport_pending_count (T transport);

/**
 * @brief Convert DNS error code to string.
 * @ingroup dns_transport
 *
 * @param error Error code (DNS_ERROR_*).
 * @return Human-readable error string.
 */
extern const char *SocketDNSTransport_strerror (int error);

/** @} */ /* End of dns_transport group */

#undef T

#endif /* SOCKETDNSTRANSPORT_INCLUDED */
