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
extern "C"
{
#endif

  /**
   * @brief DNS resolution result.
   */
  typedef struct
  {
    char **addresses; /**< NULL-terminated array of IP strings (caller must
                         free) */
    int count;        /**< Number of addresses */
    int family;       /**< Address family (AF_INET or AF_INET6) */
  } SocketSimple_DNSResult;

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
  extern int Socket_simple_dns_resolve (const char *hostname,
                                        SocketSimple_DNSResult *result);

  /**
   * @brief Resolve with timeout.
   *
   * @param hostname Hostname to resolve.
   * @param result Output result structure.
   * @param timeout_ms Timeout in milliseconds.
   * @return 0 on success, -1 on error/timeout.
   */
  extern int Socket_simple_dns_resolve_timeout (const char *hostname,
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
  extern int
  Socket_simple_dns_lookup (const char *hostname, char *buf, size_t len);

  /**
   * @brief Resolve to single IPv4 address (prefer IPv4).
   *
   * @param hostname Hostname to resolve.
   * @param buf Output buffer.
   * @param len Buffer length.
   * @return 0 on success, -1 on error.
   */
  extern int
  Socket_simple_dns_lookup4 (const char *hostname, char *buf, size_t len);

  /**
   * @brief Resolve to single IPv6 address (prefer IPv6).
   *
   * @param hostname Hostname to resolve.
   * @param buf Output buffer (at least 46 bytes).
   * @param len Buffer length.
   * @return 0 on success, -1 on error.
   */
  extern int
  Socket_simple_dns_lookup6 (const char *hostname, char *buf, size_t len);

  /**
   * @brief Reverse DNS lookup.
   *
   * @param ip IP address string (IPv4 or IPv6).
   * @param hostname Output buffer for hostname.
   * @param len Buffer length.
   * @return 0 on success, -1 on error.
   */
  extern int
  Socket_simple_dns_reverse (const char *ip, char *hostname, size_t len);

  /**
   * @brief Free DNS result resources.
   *
   * @param result Result structure to free.
   */
  extern void Socket_simple_dns_result_free (SocketSimple_DNSResult *result);

  /**
   * @brief Opaque async DNS resolver handle.
   */
  typedef struct SocketSimple_DNS *SocketSimple_DNS_T;

  /**
   * @brief Opaque async DNS request handle.
   */
  typedef struct SocketSimple_DNSRequest *SocketSimple_DNSRequest_T;

  /**
   * @brief Async DNS completion callback.
   *
   * Called when an async resolution completes. The result structure is
   * automatically freed after the callback returns.
   *
   * @param result DNS result (NULL on error).
   * @param error Error code (0 on success).
   * @param userdata User data passed to resolve function.
   *
   * @warning Callbacks execute from a worker thread, NOT the main thread.
   * Ensure thread-safety when accessing shared data.
   */
  typedef void (*SocketSimple_DNSCallback) (SocketSimple_DNSResult *result,
                                            int error,
                                            void *userdata);

  /**
   * @brief Create async DNS resolver.
   *
   * @return Resolver handle on success, NULL on error.
   *
   * Example:
   * @code
   * SocketSimple_DNS_T dns = Socket_simple_dns_new();
   * if (!dns) {
   *     fprintf(stderr, "Failed: %s\n", Socket_simple_error());
   *     return 1;
   * }
   *
   * // Async resolution with callback
   * Socket_simple_dns_resolve_async(dns, "example.com", my_callback, ctx);
   *
   * // Or polling mode
   * SocketSimple_DNSRequest_T req = Socket_simple_dns_resolve_start(
   *     dns, "example.com");
   *
   * // Poll for completion
   * int fd = Socket_simple_dns_pollfd(dns);
   * // ... add fd to your poll/select loop ...
   *
   * // When fd is readable
   * Socket_simple_dns_check(dns);
   * if (Socket_simple_dns_request_done(req)) {
   *     SocketSimple_DNSResult result;
   *     if (Socket_simple_dns_request_result(req, &result) == 0) {
   *         // Use result
   *         Socket_simple_dns_result_free(&result);
   *     }
   *     Socket_simple_dns_request_free(&req);
   * }
   *
   * Socket_simple_dns_free(&dns);
   * @endcode
   */
  extern SocketSimple_DNS_T Socket_simple_dns_new (void);

  /**
   * @brief Free async DNS resolver.
   *
   * Cancels all pending requests and releases resources.
   *
   * @param dns Pointer to resolver handle.
   */
  extern void Socket_simple_dns_free (SocketSimple_DNS_T *dns);

  /**
   * @brief Set default timeout for async resolutions.
   *
   * @param dns Resolver handle.
   * @param timeout_ms Timeout in milliseconds (0 = no timeout).
   */
  extern void
  Socket_simple_dns_set_timeout (SocketSimple_DNS_T dns, int timeout_ms);

  /**
   * @brief Get default timeout.
   *
   * @param dns Resolver handle.
   * @return Timeout in milliseconds.
   */
  extern int Socket_simple_dns_get_timeout (SocketSimple_DNS_T dns);

  /**
   * @brief Set maximum pending requests.
   *
   * @param dns Resolver handle.
   * @param max_pending Maximum pending requests (DoS protection).
   */
  extern void Socket_simple_dns_set_max_pending (SocketSimple_DNS_T dns,
                                                 size_t max_pending);

  /**
   * @brief Set IPv6 preference.
   *
   * @param dns Resolver handle.
   * @param prefer_ipv6 1 to prefer IPv6, 0 to prefer IPv4.
   */
  extern void
  Socket_simple_dns_prefer_ipv6 (SocketSimple_DNS_T dns, int prefer_ipv6);

  /**
   * @brief Start async DNS resolution with callback.
   *
   * When resolution completes, the callback is invoked from a worker thread.
   *
   * @param dns Resolver handle.
   * @param hostname Hostname to resolve.
   * @param callback Completion callback.
   * @param userdata User data passed to callback.
   * @return 0 on success, -1 on error.
   */
  extern int Socket_simple_dns_resolve_async (SocketSimple_DNS_T dns,
                                              const char *hostname,
                                              SocketSimple_DNSCallback callback,
                                              void *userdata);

  /**
   * @brief Start async DNS resolution (polling mode).
   *
   * Returns a request handle. Monitor the resolver's pollfd and call
   * Socket_simple_dns_check() when readable, then check if the request
   * is done.
   *
   * @param dns Resolver handle.
   * @param hostname Hostname to resolve.
   * @return Request handle on success, NULL on error.
   */
  extern SocketSimple_DNSRequest_T
  Socket_simple_dns_resolve_start (SocketSimple_DNS_T dns,
                                   const char *hostname);

  /**
   * @brief Get file descriptor for poll/select integration.
   *
   * Monitor this fd for readability. When readable, call
   * Socket_simple_dns_check() to process completions.
   *
   * @param dns Resolver handle.
   * @return File descriptor, or -1 on error.
   */
  extern int Socket_simple_dns_pollfd (SocketSimple_DNS_T dns);

  /**
   * @brief Check for completed async requests.
   *
   * Call when pollfd is readable to process completion signals.
   *
   * @param dns Resolver handle.
   * @return Number of completions processed.
   */
  extern int Socket_simple_dns_check (SocketSimple_DNS_T dns);

  /**
   * @brief Check if async request is complete.
   *
   * @param req Request handle.
   * @return 1 if complete, 0 if pending.
   */
  extern int Socket_simple_dns_request_done (SocketSimple_DNSRequest_T req);

  /**
   * @brief Get result from completed async request.
   *
   * @param req Request handle (must be complete).
   * @param result Output result structure.
   * @return 0 on success, -1 on error (check Socket_simple_error()).
   */
  extern int Socket_simple_dns_request_result (SocketSimple_DNSRequest_T req,
                                               SocketSimple_DNSResult *result);

  /**
   * @brief Get error code from async request.
   *
   * @param req Request handle.
   * @return Error code (0 on success).
   */
  extern int Socket_simple_dns_request_error (SocketSimple_DNSRequest_T req);

  /**
   * @brief Cancel pending async request.
   *
   * @param dns Resolver handle.
   * @param req Request to cancel.
   */
  extern void Socket_simple_dns_request_cancel (SocketSimple_DNS_T dns,
                                                SocketSimple_DNSRequest_T req);

  /**
   * @brief Free async request handle.
   *
   * Call after retrieving result or cancelling.
   *
   * @param req Pointer to request handle.
   */
  extern void Socket_simple_dns_request_free (SocketSimple_DNSRequest_T *req);

  /**
   * @brief Clear DNS cache.
   *
   * @param dns Resolver handle.
   */
  extern void Socket_simple_dns_cache_clear (SocketSimple_DNS_T dns);

  /**
   * @brief Set DNS cache TTL.
   *
   * @param dns Resolver handle.
   * @param ttl_seconds Cache TTL in seconds (0 disables caching).
   */
  extern void
  Socket_simple_dns_cache_set_ttl (SocketSimple_DNS_T dns, int ttl_seconds);

#ifdef __cplusplus
}
#endif

#endif /* SOCKETSIMPLE_DNS_INCLUDED */
