/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketWSH2.h
 * @brief WebSocket over HTTP/2 (RFC 8441)
 * @ingroup websocket
 *
 * This module implements WebSocket connections over HTTP/2 streams using
 * the Extended CONNECT method defined in RFC 8441.
 *
 * Key features:
 * - Multiplexed WebSocket connections over single HTTP/2 connection
 * - No masking required (HTTP/2 provides transport-layer security)
 * - No Sec-WebSocket-Key/Accept exchange (uses :protocol pseudo-header)
 * - Full WebSocket framing API (same as RFC 6455)
 *
 * Usage (Server):
 * @code{.c}
 * // In HTTP/2 request handler, check for WebSocket upgrade
 * if (SocketWSH2_is_websocket_request(stream)) {
 *     SocketWS_T ws = SocketWSH2_server_accept(stream, &ws_config);
 *     if (ws) {
 *         // WebSocket is now open - use SocketWS_send/recv APIs
 *         SocketWS_send_text(ws, "Hello from server", 17);
 *     }
 * }
 * @endcode
 *
 * Usage (Client):
 * @code{.c}
 * // Check if peer supports Extended CONNECT
 * if (SocketWSH2_is_supported(conn)) {
 *     SocketWS_T ws = SocketWSH2_client_connect(conn, "/chat", &ws_config);
 *     if (ws) {
 *         // WebSocket is now open
 *         SocketWS_send_text(ws, "Hello from client", 17);
 *     }
 * }
 * @endcode
 *
 * @see RFC 8441 - Bootstrapping WebSockets with HTTP/2
 * @see RFC 6455 - The WebSocket Protocol
 * @see SocketWS.h - WebSocket framing API
 * @see SocketHTTP2.h - HTTP/2 connection and stream API
 */

#ifndef SOCKETWSH2_INCLUDED
#define SOCKETWSH2_INCLUDED

#include "http/SocketHTTP2.h"
#include "socket/SocketWS.h"

#ifdef __cplusplus
extern "C"
{
#endif

  /* ==========================================================================
   * Server API
   * ==========================================================================
   */

  /**
   * @brief Check if HTTP/2 stream is a WebSocket upgrade request
   * @ingroup websocket
   *
   * Validates that the stream uses Extended CONNECT with :protocol=websocket.
   * Call this when processing incoming requests to detect WebSocket upgrades.
   *
   * @param stream  HTTP/2 stream to check
   *
   * @return 1 if this is a WebSocket upgrade request, 0 otherwise
   * @threadsafe No - stream operations are not thread-safe
   */
  extern int SocketWSH2_is_websocket_request (SocketHTTP2_Stream_T stream);

  /**
   * @brief Accept WebSocket connection on HTTP/2 stream (server)
   * @ingroup websocket
   *
   * Creates a WebSocket context for an incoming Extended CONNECT request.
   * Sends 200 response (not 101 as in RFC 6455) and sets up transport.
   *
   * Prerequisites:
   * - Stream must be a valid WebSocket request (check with
   * is_websocket_request)
   * - Connection must have SETTINGS_ENABLE_CONNECT_PROTOCOL enabled
   *
   * @param stream   HTTP/2 stream with WebSocket request
   * @param config   WebSocket configuration (may be NULL for defaults)
   *
   * @return WebSocket context on success, NULL on failure
   * @threadsafe No
   *
   * @note The returned SocketWS_T is already in OPEN state - no handshake
   * needed
   * @note Memory is allocated from the stream's connection arena
   */
  extern SocketWS_T SocketWSH2_server_accept (SocketHTTP2_Stream_T stream,
                                              const SocketWS_Config *config);

  /* ==========================================================================
   * Client API
   * ==========================================================================
   */

  /**
   * @brief Check if peer supports WebSocket over HTTP/2
   * @ingroup websocket
   *
   * Verifies that the peer has sent SETTINGS_ENABLE_CONNECT_PROTOCOL=1.
   * Call this before attempting to create WebSocket connections.
   *
   * @param conn  HTTP/2 connection to check
   *
   * @return 1 if Extended CONNECT is supported, 0 otherwise
   * @threadsafe No
   */
  extern int SocketWSH2_is_supported (SocketHTTP2_Conn_T conn);

  /**
   * @brief Initiate WebSocket connection over HTTP/2 (client)
   * @ingroup websocket
   *
   * Creates a new stream with Extended CONNECT request and establishes
   * a WebSocket connection. Blocks until handshake completes or fails.
   *
   * The request uses these pseudo-headers:
   * - :method = CONNECT
   * - :protocol = websocket
   * - :scheme = https (from connection)
   * - :path = provided path
   * - :authority = connection authority
   *
   * @param conn     HTTP/2 connection
   * @param path     Request path (e.g., "/chat")
   * @param config   WebSocket configuration (may be NULL for defaults)
   *
   * @return WebSocket context on success (state=OPEN), NULL on failure
   * @threadsafe No
   *
   * @note Caller must ensure peer supports Extended CONNECT first
   * @note Memory is allocated from the connection's arena
   */
  extern SocketWS_T SocketWSH2_client_connect (SocketHTTP2_Conn_T conn,
                                               const char *path,
                                               const SocketWS_Config *config);

  /* ==========================================================================
   * Accessor Functions
   * ==========================================================================
   */

  /**
   * @brief Get HTTP/2 stream underlying a WebSocket connection
   * @ingroup websocket
   *
   * Returns the HTTP/2 stream used for this WebSocket connection.
   * Only valid for WebSocket-over-HTTP/2 connections; returns NULL for
   * regular TCP/TLS WebSocket connections.
   *
   * @param ws  WebSocket context
   *
   * @return HTTP/2 stream or NULL if not using HTTP/2 transport
   * @threadsafe No
   */
  extern SocketHTTP2_Stream_T SocketWSH2_get_stream (SocketWS_T ws);

  /**
   * @brief Get HTTP/2 connection for a WebSocket
   * @ingroup websocket
   *
   * Returns the HTTP/2 connection containing this WebSocket's stream.
   * Only valid for WebSocket-over-HTTP/2 connections.
   *
   * @param ws  WebSocket context
   *
   * @return HTTP/2 connection or NULL if not using HTTP/2 transport
   * @threadsafe No
   */
  extern SocketHTTP2_Conn_T SocketWSH2_get_connection (SocketWS_T ws);

#ifdef __cplusplus
}
#endif

#endif /* SOCKETWSH2_INCLUDED */
