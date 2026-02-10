/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTP3-server.h
 * @brief HTTP/3 server API (RFC 9114).
 *
 * High-level HTTP/3 server that wraps the QUIC server transport and
 * HTTP/3 connection layer. Accepts QUIC connections, processes request
 * streams, and dispatches to user-defined handlers.
 *
 * Architecture: SocketHTTP3_Server_T owns a SocketQUICServer_T
 * (QUIC/UDP, multiplexing N connections) and manages a per-connection
 * SocketHTTP3_Conn_T (HTTP/3 framing). The output queue model bridges
 * them: H3 generates wire data, server flushes it through the QUIC
 * transport, transport delivers received data back to H3 via callbacks.
 */

#ifndef SOCKETHTTP3_SERVER_INCLUDED
#define SOCKETHTTP3_SERVER_INCLUDED

#ifdef SOCKET_HAS_TLS

#include <stddef.h>
#include <stdint.h>

#include "core/Arena.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP3.h"
#include "http/SocketHTTP3-frame.h"
#include "http/SocketHTTP3-request.h"

/**
 * @brief HTTP/3 server configuration.
 */
typedef struct
{
  const char *bind_addr;             /**< default: "0.0.0.0" */
  int port;                          /**< default: 443 */
  uint64_t idle_timeout_ms;          /**< default: 30000 */
  uint64_t initial_max_streams_bidi; /**< default: 100 */
  uint64_t max_stream_data;          /**< default: 262144 (256KB) */
  SocketHTTP3_Settings h3_settings;
  const char *cert_file;  /**< required */
  const char *key_file;   /**< required */
  size_t max_connections; /**< default: 256 */
  size_t max_header_size; /**< default: 65536 */
} SocketHTTP3_ServerConfig;

/** Opaque server handle. */
typedef struct SocketHTTP3_Server *SocketHTTP3_Server_T;

/**
 * @brief Request handler callback.
 *
 * Invoked when a client request's headers are fully received.
 * The handler should use SocketHTTP3_Request_recv_headers() to read
 * the request and SocketHTTP3_Request_send_headers/send_data to respond.
 *
 * @param req       Request handle with decoded headers available.
 * @param headers   Decoded request headers (convenience — same as
 *                  calling recv_headers on req).
 * @param userdata  User-supplied context pointer.
 */
typedef void (*SocketHTTP3_RequestHandler) (SocketHTTP3_Request_T req,
                                            const SocketHTTP_Headers_T headers,
                                            void *userdata);

/**
 * @brief Initialize config to defaults.
 *
 * @param config  Output config structure.
 */
void SocketHTTP3_ServerConfig_defaults (SocketHTTP3_ServerConfig *config);

/**
 * @brief Create a new HTTP/3 server.
 *
 * @param arena   Memory arena for server-level allocations.
 * @param config  Server configuration.
 * @return New server, or NULL on error.
 */
SocketHTTP3_Server_T
SocketHTTP3_Server_new (Arena_T arena, const SocketHTTP3_ServerConfig *config);

/**
 * @brief Register a request handler.
 *
 * @param server   Server handle.
 * @param handler  Callback invoked for each complete request.
 * @param userdata User context passed to handler.
 */
void SocketHTTP3_Server_on_request (SocketHTTP3_Server_T server,
                                    SocketHTTP3_RequestHandler handler,
                                    void *userdata);

/**
 * @brief Start the server (bind + listen).
 *
 * @param server  Server handle.
 * @return 0 on success, -1 on error.
 */
int SocketHTTP3_Server_start (SocketHTTP3_Server_T server);

/**
 * @brief Poll for incoming data (blocking with timeout).
 *
 * Receives QUIC packets, dispatches to connections, processes H3
 * framing, and invokes the request handler for complete requests.
 *
 * @param server      Server handle.
 * @param timeout_ms  Poll timeout in milliseconds (-1 for infinite).
 * @return Number of events processed (>=0), or -1 on error.
 */
int SocketHTTP3_Server_poll (SocketHTTP3_Server_T server, int timeout_ms);

/**
 * @brief Initiate graceful shutdown (send GOAWAY on all connections).
 *
 * @param server  Server handle.
 * @return 0 on success, -1 on error.
 */
int SocketHTTP3_Server_shutdown (SocketHTTP3_Server_T server);

/**
 * @brief Close the server and all connections.
 *
 * @param server  Server handle.
 */
void SocketHTTP3_Server_close (SocketHTTP3_Server_T server);

/**
 * @brief Get the number of active connections.
 *
 * @param server  Server handle.
 * @return Number of active connections.
 */
size_t SocketHTTP3_Server_active_connections (SocketHTTP3_Server_T server);

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETHTTP3_SERVER_INCLUDED */
