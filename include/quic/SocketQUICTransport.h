/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICTransport.h
 * @brief QUIC transport layer over UDP (RFC 9000).
 *
 * Drives the QUIC handshake and stream I/O over a UDP socket, integrating
 * the existing packet protection, frame encoding, handshake state machine,
 * ACK generation, and loss detection modules.
 *
 * Output model: send_stream() builds STREAM frames into 1-RTT packets and
 * sends them immediately. poll() receives UDP datagrams, decrypts, parses
 * frames, and delivers stream data via callback.
 *
 * V1 Simplifications:
 * - No congestion control (send immediately)
 * - No retransmission (detect losses but don't retransmit)
 * - No 0-RTT (always full handshake)
 * - No connection migration (fixed path)
 * - No PMTU discovery (assume 1200-byte minimum)
 * - Fixed 4-byte packet numbers
 * - Immediate ACK (no delayed ACK)
 * - No coalesced packets (one QUIC packet per UDP datagram)
 * - No CID rotation
 */

#ifndef SOCKETQUICTRANSPORT_INCLUDED
#define SOCKETQUICTRANSPORT_INCLUDED

#ifdef SOCKET_HAS_TLS

#include <stddef.h>
#include <stdint.h>

#include "core/Arena.h"

/**
 * @brief QUIC transport configuration.
 */
typedef struct
{
  uint64_t idle_timeout_ms;          /**< default: 30000 */
  uint64_t max_stream_data;          /**< default: 262144 (256KB) */
  uint64_t initial_max_data;         /**< default: 1048576 (1MB) */
  uint64_t initial_max_streams_bidi; /**< default: 100 */
  uint32_t connect_timeout_ms;       /**< default: 5000 */
  const char *alpn;                  /**< default: "h3" */
  const char *ca_file;               /**< NULL for system CAs */
  int verify_peer;                   /**< default: 1 */
} SocketQUICTransportConfig;

/** Opaque transport handle. */
typedef struct SocketQUICTransport *SocketQUICTransport_T;

/**
 * @brief Callback for received stream data during poll().
 *
 * @param stream_id  QUIC stream ID.
 * @param data       Received data.
 * @param len        Data length.
 * @param fin        1 if this is the final data on the stream.
 * @param userdata   User-supplied context pointer.
 */
typedef void (*SocketQUICTransport_StreamCB) (uint64_t stream_id,
                                              const uint8_t *data,
                                              size_t len,
                                              int fin,
                                              void *userdata);

/**
 * @brief Initialize config to defaults.
 *
 * @param config  Output config structure.
 */
void SocketQUICTransportConfig_defaults (SocketQUICTransportConfig *config);

/**
 * @brief Create a new QUIC transport.
 *
 * @param arena   Memory arena for all allocations.
 * @param config  Transport configuration (NULL for defaults).
 * @return New transport, or NULL on error.
 */
SocketQUICTransport_T
SocketQUICTransport_new (Arena_T arena,
                         const SocketQUICTransportConfig *config);

/**
 * @brief Connect to a remote QUIC server (blocking).
 *
 * Performs the full QUIC handshake over UDP:
 * 1. Creates and connects UDP socket
 * 2. Derives Initial keys, sends ClientHello
 * 3. Processes server responses, derives Handshake/1-RTT keys
 * 4. Completes TLS handshake
 *
 * @param t     Transport handle.
 * @param host  Remote hostname or IP.
 * @param port  Remote port.
 * @return 0 on success, -1 on error.
 */
int SocketQUICTransport_connect (SocketQUICTransport_T t,
                                 const char *host,
                                 int port);

/**
 * @brief Close the transport (send CONNECTION_CLOSE).
 *
 * @param t  Transport handle.
 * @return 0 on success, -1 on error.
 */
int SocketQUICTransport_close (SocketQUICTransport_T t);

/**
 * @brief Send data on a QUIC stream.
 *
 * Builds a STREAM frame, wraps in a 1-RTT packet, encrypts, and sends.
 *
 * @param t          Transport handle.
 * @param stream_id  QUIC stream ID.
 * @param data       Payload data.
 * @param len        Payload length.
 * @param fin        1 to signal end-of-stream.
 * @return 0 on success, -1 on error.
 */
int SocketQUICTransport_send_stream (SocketQUICTransport_T t,
                                     uint64_t stream_id,
                                     const uint8_t *data,
                                     size_t len,
                                     int fin);

/**
 * @brief Poll for incoming data (blocking with timeout).
 *
 * Receives a UDP datagram, decrypts, parses frames, and delivers
 * stream data via the registered callback. Also handles ACK generation.
 *
 * @param t           Transport handle.
 * @param timeout_ms  Poll timeout in milliseconds (-1 for infinite).
 * @return Number of events processed (>=0), or -1 on error.
 */
int SocketQUICTransport_poll (SocketQUICTransport_T t, int timeout_ms);

/**
 * @brief Set stream data receive callback.
 *
 * @param t         Transport handle.
 * @param cb        Callback function.
 * @param userdata  User context passed to callback.
 */
void SocketQUICTransport_set_stream_callback (SocketQUICTransport_T t,
                                              SocketQUICTransport_StreamCB cb,
                                              void *userdata);

/**
 * @brief Check if connected.
 *
 * @param t  Transport handle.
 * @return 1 if connected, 0 otherwise.
 */
int SocketQUICTransport_is_connected (SocketQUICTransport_T t);

/**
 * @brief Allocate the next client bidirectional stream ID.
 *
 * Client bidi stream IDs: 0, 4, 8, 12, ...
 *
 * @param t  Transport handle.
 * @return Stream ID, or UINT64_MAX on error.
 */
uint64_t SocketQUICTransport_open_bidi_stream (SocketQUICTransport_T t);

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETQUICTRANSPORT_INCLUDED */
