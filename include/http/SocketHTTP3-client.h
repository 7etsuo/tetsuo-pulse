/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTP3-client.h
 * @brief HTTP/3 client API (RFC 9114).
 *
 * High-level HTTP/3 client that wraps the QUIC transport and HTTP/3
 * connection layer. Provides both synchronous request/response and
 * streaming APIs.
 *
 * Architecture: SocketHTTP3_Client_T owns a SocketQUICTransport_T
 * (QUIC/UDP) and a SocketHTTP3_Conn_T (HTTP/3 framing). The output
 * queue model bridges them: H3 generates wire data, client flushes
 * it through the transport, transport delivers received data back
 * to H3 via stream callback.
 */

#ifndef SOCKETHTTP3_CLIENT_INCLUDED
#define SOCKETHTTP3_CLIENT_INCLUDED

#ifdef SOCKET_HAS_TLS

#include <stddef.h>
#include <stdint.h>

#include "core/Arena.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP3.h"
#include "http/SocketHTTP3-frame.h"
#include "http/SocketHTTP3-request.h"

/**
 * @brief HTTP/3 client configuration.
 */
typedef struct
{
  /* QUIC transport settings */
  uint64_t idle_timeout_ms;          /**< default: 30000 */
  uint64_t max_stream_data;          /**< default: 262144 (256KB) */
  uint64_t initial_max_streams_bidi; /**< default: 100 */

  /* HTTP/3 settings */
  SocketHTTP3_Settings h3_settings;

  /* TLS */
  const char *ca_file; /**< NULL for system CAs */
  int verify_peer;     /**< default: 1 */

  /* Timeouts */
  uint32_t connect_timeout_ms; /**< default: 5000 */
  uint32_t request_timeout_ms; /**< default: 30000 */
} SocketHTTP3_ClientConfig;

/** Opaque client handle. */
typedef struct SocketHTTP3_Client *SocketHTTP3_Client_T;

/**
 * @brief Initialize config to defaults.
 *
 * @param config  Output config structure.
 */
void SocketHTTP3_ClientConfig_defaults (SocketHTTP3_ClientConfig *config);

/**
 * @brief Create a new HTTP/3 client.
 *
 * @param arena   Memory arena for all allocations.
 * @param config  Client configuration (NULL for defaults).
 * @return New client, or NULL on error.
 */
SocketHTTP3_Client_T
SocketHTTP3_Client_new (Arena_T arena, const SocketHTTP3_ClientConfig *config);

/**
 * @brief Connect to a remote HTTP/3 server (blocking).
 *
 * Performs the full QUIC handshake, then opens H3 critical streams
 * and sends SETTINGS.
 *
 * @param client  Client handle.
 * @param host    Remote hostname or IP.
 * @param port    Remote port.
 * @return 0 on success, -1 on error.
 */
int SocketHTTP3_Client_connect (SocketHTTP3_Client_T client,
                                const char *host,
                                int port);

/**
 * @brief Close the client (send GOAWAY + CONNECTION_CLOSE).
 *
 * @param client  Client handle.
 * @return 0 on success, -1 on error.
 */
int SocketHTTP3_Client_close (SocketHTTP3_Client_T client);

/**
 * @brief Synchronous HTTP request/response.
 *
 * Sends request headers + optional body, then polls for the complete
 * response. All output memory is arena-owned.
 *
 * @param client         Client handle.
 * @param method         HTTP method (e.g., HTTP_METHOD_GET).
 * @param path           Request path (e.g., "/index.html").
 * @param headers        Additional request headers (may be NULL).
 * @param body           Request body (may be NULL).
 * @param body_len       Body length.
 * @param[out] resp_headers  Output: response headers.
 * @param[out] status_code   Output: HTTP status code (may be NULL).
 * @param[out] resp_body     Output: response body (may be NULL).
 * @param[out] resp_body_len Output: response body length (may be NULL).
 * @return 0 on success, -1 on error or timeout.
 */
int SocketHTTP3_Client_request (SocketHTTP3_Client_T client,
                                SocketHTTP_Method method,
                                const char *path,
                                const SocketHTTP_Headers_T headers,
                                const void *body,
                                size_t body_len,
                                SocketHTTP_Headers_T *resp_headers,
                                int *status_code,
                                void **resp_body,
                                size_t *resp_body_len);

/**
 * @brief Create a new streaming request on the connection.
 *
 * For callers who need fine-grained control over send/recv.
 *
 * @param client  Client handle.
 * @return New request, or NULL on error.
 */
SocketHTTP3_Request_T
SocketHTTP3_Client_new_request (SocketHTTP3_Client_T client);

/**
 * @brief Flush H3 output queue through the transport.
 *
 * Sends all pending H3 output entries via the QUIC transport.
 * Called automatically during request(), but available for
 * manual use with the streaming API.
 *
 * @param client  Client handle.
 * @return 0 on success, -1 on error.
 */
int SocketHTTP3_Client_flush (SocketHTTP3_Client_T client);

/**
 * @brief Poll for incoming data (blocking with timeout).
 *
 * Receives QUIC data and delivers it to the H3 connection layer.
 *
 * @param client      Client handle.
 * @param timeout_ms  Poll timeout in milliseconds (-1 for infinite).
 * @return Number of events processed (>=0), or -1 on error.
 */
int SocketHTTP3_Client_poll (SocketHTTP3_Client_T client, int timeout_ms);

/**
 * @brief Get the underlying H3 connection handle.
 *
 * @param client  Client handle.
 * @return H3 connection, or NULL.
 */
SocketHTTP3_Conn_T SocketHTTP3_Client_conn (SocketHTTP3_Client_T client);

/**
 * @brief Check if connected.
 *
 * @param client  Client handle.
 * @return 1 if connected, 0 otherwise.
 */
int SocketHTTP3_Client_is_connected (SocketHTTP3_Client_T client);

/**
 * @brief Parse Alt-Svc header for h3 support (RFC 7838).
 *
 * Extracts the port for "h3" protocol from an Alt-Svc header value.
 * Optionally extracts the alternate host.
 *
 * @param alt_svc_value  Alt-Svc header value string.
 * @param host_out       Output buffer for alternate host (may be NULL).
 * @param host_len       Size of host_out buffer.
 * @return Port number if h3 found, 0 otherwise.
 */
uint16_t SocketHTTP3_parse_alt_svc (const char *alt_svc_value,
                                    char *host_out,
                                    size_t host_len);

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETHTTP3_CLIENT_INCLUDED */
