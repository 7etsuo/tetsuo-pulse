/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICServer.h
 * @brief QUIC server transport over UDP (RFC 9000).
 *
 * Multiplexes N QUIC connections over a single bound UDP socket.
 * Incoming packets are demuxed by DCID; Initial packets from unknown
 * clients create new connections with a full TLS handshake.
 *
 * V1 Simplifications (same as client transport):
 * - No Retry/Version Negotiation
 * - No congestion control, retransmission, 0-RTT, migration
 * - Fixed 4-byte packet numbers, immediate ACK
 */

#ifndef SOCKETQUICSERVER_INCLUDED
#define SOCKETQUICSERVER_INCLUDED

#ifdef SOCKET_HAS_TLS

#include <stddef.h>
#include <stdint.h>

#include "core/Arena.h"

/**
 * @brief QUIC server configuration.
 */
typedef struct
{
  const char *bind_addr;             /**< default: "0.0.0.0" */
  int port;                          /**< default: 443 */
  uint64_t idle_timeout_ms;          /**< default: 30000 */
  uint64_t max_stream_data;          /**< default: 262144 */
  uint64_t initial_max_data;         /**< default: 1048576 */
  uint64_t initial_max_streams_bidi; /**< default: 100 */
  const char *cert_file;             /**< required */
  const char *key_file;              /**< required */
  const char *alpn;                  /**< default: "h3" */
  size_t max_connections;            /**< default: 256 */
} SocketQUICServerConfig;

/** Opaque server handle. */
typedef struct SocketQUICServer *SocketQUICServer_T;

/** Opaque per-connection handle. */
typedef struct QUICServerConn *QUICServerConn_T;

/**
 * @brief Callback for new QUIC connections.
 *
 * @param conn      New connection handle.
 * @param userdata  User-supplied context pointer.
 */
typedef void (*SocketQUICServer_ConnCB) (QUICServerConn_T conn, void *userdata);

/**
 * @brief Callback for received stream data.
 *
 * @param conn       Connection handle.
 * @param stream_id  QUIC stream ID.
 * @param data       Received data.
 * @param len        Data length.
 * @param fin        1 if this is the final data on the stream.
 * @param userdata   User-supplied context pointer.
 */
typedef void (*SocketQUICServer_StreamCB) (QUICServerConn_T conn,
                                           uint64_t stream_id,
                                           const uint8_t *data,
                                           size_t len,
                                           int fin,
                                           void *userdata);

/**
 * @brief Initialize config to defaults.
 *
 * @param config  Output config structure.
 */
void SocketQUICServerConfig_defaults (SocketQUICServerConfig *config);

/**
 * @brief Create a new QUIC server.
 *
 * @param arena   Memory arena for server-level allocations.
 * @param config  Server configuration.
 * @return New server, or NULL on error.
 */
SocketQUICServer_T
SocketQUICServer_new (Arena_T arena, const SocketQUICServerConfig *config);

/**
 * @brief Bind and start listening for QUIC connections.
 *
 * @param server  Server handle.
 * @return 0 on success, -1 on error.
 */
int SocketQUICServer_listen (SocketQUICServer_T server);

/**
 * @brief Poll for incoming packets (blocking with timeout).
 *
 * Receives a UDP datagram, demuxes by DCID, dispatches to the
 * appropriate connection. Creates new connections for Initial packets.
 *
 * @param server      Server handle.
 * @param timeout_ms  Poll timeout in milliseconds (-1 for infinite).
 * @return Number of events processed (>=0), or -1 on error.
 */
int SocketQUICServer_poll (SocketQUICServer_T server, int timeout_ms);

/**
 * @brief Close the server and all connections.
 *
 * @param server  Server handle.
 */
void SocketQUICServer_close (SocketQUICServer_T server);

/**
 * @brief Register connection and stream callbacks.
 *
 * @param server     Server handle.
 * @param conn_cb    Called when a new connection is established.
 * @param stream_cb  Called when stream data is received.
 * @param userdata   User context passed to both callbacks.
 */
void SocketQUICServer_set_callbacks (SocketQUICServer_T server,
                                     SocketQUICServer_ConnCB conn_cb,
                                     SocketQUICServer_StreamCB stream_cb,
                                     void *userdata);

/**
 * @brief Send data on a QUIC stream.
 *
 * @param conn       Connection handle.
 * @param stream_id  QUIC stream ID.
 * @param data       Payload data.
 * @param len        Payload length.
 * @param fin        1 to signal end-of-stream.
 * @return 0 on success, -1 on error.
 */
int SocketQUICServer_send_stream (QUICServerConn_T conn,
                                  uint64_t stream_id,
                                  const uint8_t *data,
                                  size_t len,
                                  int fin);

/**
 * @brief Close a specific connection.
 *
 * @param conn        Connection handle.
 * @param error_code  Application error code for CONNECTION_CLOSE.
 * @return 0 on success, -1 on error.
 */
int SocketQUICServer_close_conn (QUICServerConn_T conn, uint64_t error_code);

/**
 * @brief Get the number of active connections.
 *
 * @param server  Server handle.
 * @return Number of active connections.
 */
size_t SocketQUICServer_active_connections (SocketQUICServer_T server);

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETQUICSERVER_INCLUDED */
