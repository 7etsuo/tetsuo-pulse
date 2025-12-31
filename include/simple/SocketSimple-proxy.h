/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETSIMPLE_PROXY_INCLUDED
#define SOCKETSIMPLE_PROXY_INCLUDED

/**
 * @file SocketSimple-proxy.h
 * @brief Simple proxy tunneling support.
 *
 * Supports SOCKS4, SOCKS4a, SOCKS5, and HTTP CONNECT proxies.
 *
 * Example:
 * @code
 * // Parse proxy URL
 * SocketSimple_ProxyConfig config;
 * Socket_simple_proxy_config_init(&config);
 * if (Socket_simple_proxy_parse_url("socks5://user:pass@proxy:1080", &config) <
 * 0) { fprintf(stderr, "Invalid proxy URL: %s\n", Socket_simple_error());
 *     return 1;
 * }
 *
 * // Connect through proxy
 * SocketSimple_Socket_T sock = Socket_simple_proxy_connect(&config,
 * "example.com", 443); if (!sock) { fprintf(stderr, "Proxy error: %s\n",
 * Socket_simple_error()); return 1;
 * }
 *
 * // Upgrade to TLS (for HTTPS)
 * if (Socket_simple_tls_upgrade(sock, "example.com") < 0) {
 *     fprintf(stderr, "TLS error: %s\n", Socket_simple_error());
 *     Socket_simple_close(&sock);
 *     return 1;
 * }
 *
 * // Use the tunneled connection...
 * Socket_simple_close(&sock);
 * @endcode
 */

#include "SocketSimple-tcp.h"

#ifdef __cplusplus
extern "C"
{
#endif

  /*============================================================================
   * Proxy Type Enum
   *============================================================================*/

  /**
   * @brief Supported proxy types.
   */
  typedef enum
  {
    SOCKET_SIMPLE_PROXY_NONE,    /**< Direct connection (no proxy) */
    SOCKET_SIMPLE_PROXY_HTTP,    /**< HTTP CONNECT proxy */
    SOCKET_SIMPLE_PROXY_HTTPS,   /**< HTTP CONNECT over TLS */
    SOCKET_SIMPLE_PROXY_SOCKS4,  /**< SOCKS4 (IP address only) */
    SOCKET_SIMPLE_PROXY_SOCKS4A, /**< SOCKS4a (hostname support) */
    SOCKET_SIMPLE_PROXY_SOCKS5,  /**< SOCKS5 (full featured) */
    SOCKET_SIMPLE_PROXY_SOCKS5H  /**< SOCKS5 with remote DNS */
  } SocketSimple_ProxyType;

  /*============================================================================
   * Configuration Structure
   *============================================================================*/

  /**
   * @brief Proxy configuration.
   */
  typedef struct SocketSimple_ProxyConfig
  {
    SocketSimple_ProxyType type; /**< Proxy protocol type */
    char host[256];              /**< Proxy hostname or IP */
    int port;                    /**< Proxy port */
    char username[128];          /**< Auth username (empty if none) */
    char password[128];          /**< Auth password (empty if none) */
    int connect_timeout_ms;      /**< Proxy connect timeout (0=default) */
    int handshake_timeout_ms;    /**< Protocol handshake timeout (0=default) */
  } SocketSimple_ProxyConfig;

  /*============================================================================
   * Configuration Functions
   *============================================================================*/

  /**
   * @brief Initialize proxy config with defaults.
   *
   * @param config Config struct to initialize.
   */
  extern void
  Socket_simple_proxy_config_init (SocketSimple_ProxyConfig *config);

  /**
   * @brief Parse proxy URL into config.
   *
   * Supported formats:
   * - socks5://host:port
   * - socks5://user:pass@host:port
   * - http://host:port
   * - https://host:port
   *
   * @param url Proxy URL string.
   * @param config Output config struct.
   * @return 0 on success, -1 on parse error.
   */
  extern int Socket_simple_proxy_parse_url (const char *url,
                                            SocketSimple_ProxyConfig *config);

  /**
   * @brief Get string name for proxy type.
   *
   * @param type Proxy type enum.
   * @return Static string like "SOCKS5", "HTTP", etc.
   */
  extern const char *
  Socket_simple_proxy_type_name (SocketSimple_ProxyType type);

  /*============================================================================
   * Synchronous Connection
   *============================================================================*/

  /**
   * @brief Connect to target through proxy.
   *
   * Establishes connection to proxy, performs handshake, and tunnels
   * to the target host:port. Returns a plain TCP socket (not TLS).
   *
   * @param config Proxy configuration.
   * @param target_host Target hostname or IP.
   * @param target_port Target port.
   * @return Socket handle on success, NULL on error.
   */
  extern SocketSimple_Socket_T
  Socket_simple_proxy_connect (const SocketSimple_ProxyConfig *config,
                               const char *target_host,
                               int target_port);

  /**
   * @brief Connect to target through proxy with timeout.
   *
   * @param config Proxy configuration.
   * @param target_host Target hostname or IP.
   * @param target_port Target port.
   * @param timeout_ms Total timeout for connect+handshake.
   * @return Socket handle on success, NULL on error.
   */
  extern SocketSimple_Socket_T
  Socket_simple_proxy_connect_timeout (const SocketSimple_ProxyConfig *config,
                                       const char *target_host,
                                       int target_port,
                                       int timeout_ms);

  /**
   * @brief Connect through proxy and upgrade to TLS.
   *
   * Convenience function that connects through proxy and then
   * performs TLS handshake with the target.
   *
   * @param config Proxy configuration.
   * @param target_host Target hostname (used for TLS SNI).
   * @param target_port Target port.
   * @return TLS socket handle on success, NULL on error.
   */
  extern SocketSimple_Socket_T
  Socket_simple_proxy_connect_tls (const SocketSimple_ProxyConfig *config,
                                   const char *target_host,
                                   int target_port);

  /*============================================================================
   * Tunnel on Existing Socket
   *============================================================================*/

  /**
   * @brief Perform proxy handshake on pre-connected socket.
   *
   * Use this when you've already connected to the proxy and want
   * to establish the tunnel.
   *
   * @param sock Socket connected to proxy.
   * @param config Proxy configuration (type, auth).
   * @param target_host Target hostname.
   * @param target_port Target port.
   * @return 0 on success, -1 on error.
   */
  extern int Socket_simple_proxy_tunnel (SocketSimple_Socket_T sock,
                                         const SocketSimple_ProxyConfig *config,
                                         const char *target_host,
                                         int target_port);

#ifdef __cplusplus
}
#endif

#endif /* SOCKETSIMPLE_PROXY_INCLUDED */
