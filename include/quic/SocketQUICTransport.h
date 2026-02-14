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
 * - No retransmission (detect losses but don't retransmit)
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
#include "quic/SocketQUICTransportParams.h"

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
 * @brief Begin connecting to a remote QUIC server (non-blocking start).
 *
 * Sets up the UDP socket, initializes QUIC+TLS state, and sends the first
 * Initial packet (ClientHello). The handshake is then advanced by calling
 * SocketQUICTransport_poll() until SocketQUICTransport_is_connected() returns
 * 1 (or an error occurs).
 *
 * If a resumption ticket is configured via
 * SocketQUICTransport_set_resumption_ticket(), this will attempt QUIC 0-RTT
 * (early data). Early stream data can be sent during the handshake using
 * SocketQUICTransport_send_stream_0rtt().
 *
 * @param t     Transport handle.
 * @param host  Remote hostname or IP.
 * @param port  Remote port.
 * @return 0 on success, -1 on error.
 */
int SocketQUICTransport_connect_start (SocketQUICTransport_T t,
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
 * @brief Send 0-RTT early data on a QUIC stream (client only).
 *
 * Builds a STREAM frame, wraps in a 0-RTT packet, encrypts, and sends.
 * Only usable after SocketQUICTransport_connect_start() and before the
 * connection is established.
 *
 * If the server rejects 0-RTT, the transport will automatically resend all
 * buffered 0-RTT stream data as 1-RTT once the handshake completes.
 *
 * @param t          Transport handle.
 * @param stream_id  QUIC stream ID.
 * @param data       Payload data.
 * @param len        Payload length.
 * @param fin        1 to signal end-of-stream.
 * @return 0 on success, -1 on error.
 */
int SocketQUICTransport_send_stream_0rtt (SocketQUICTransport_T t,
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
 * @brief Configure a TLS session ticket for resumption and QUIC 0-RTT.
 *
 * Call before SocketQUICTransport_connect_start() / connect().
 *
 * @param t                Transport handle.
 * @param ticket           Serialized TLS session ticket.
 * @param ticket_len       Ticket length.
 * @param saved_peer_params Peer transport parameters from the original
 *                         connection (RFC 9001 §4.6.3 validation).
 * @param alpn             ALPN negotiated on the original connection.
 * @param alpn_len         ALPN length in bytes.
 * @return 0 on success, -1 on error.
 */
int SocketQUICTransport_set_resumption_ticket (
    SocketQUICTransport_T t,
    const uint8_t *ticket,
    size_t ticket_len,
    const SocketQUICTransportParams_T *saved_peer_params,
    const char *alpn,
    size_t alpn_len);

/**
 * @brief Export resumption state for future 0-RTT connections.
 *
 * On success, writes:\n
 * - a serialized TLS session ticket into @p ticket\n
 * - the peer transport parameters into @p peer_params\n
 * - the negotiated ALPN into @p alpn (not NUL-terminated)\n
 *
 * If @p ticket is NULL, the required ticket length is returned in
 * @p ticket_len and the function returns 0.\n
 * If @p alpn is NULL, the required ALPN length is returned in @p alpn_len and
 * the function returns 0.\n
 *
 * @param t          Transport handle.
 * @param ticket     Output ticket buffer (or NULL for size query).
 * @param ticket_len In/out: buffer size / bytes written.
 * @param peer_params Output: peer transport parameters (optional, may be NULL).
 * @param alpn       Output ALPN buffer (or NULL for size query).
 * @param alpn_len   In/out: buffer size / bytes written.
 * @return 0 on success, -1 on error.
 */
int
SocketQUICTransport_export_resumption (SocketQUICTransport_T t,
                                       uint8_t *ticket,
                                       size_t *ticket_len,
                                       SocketQUICTransportParams_T *peer_params,
                                       char *alpn,
                                       size_t *alpn_len);

/**
 * @brief Allocate the next client bidirectional stream ID.
 *
 * Client bidi stream IDs: 0, 4, 8, 12, ...
 *
 * @param t  Transport handle.
 * @return Stream ID, or UINT64_MAX on error.
 */
uint64_t SocketQUICTransport_open_bidi_stream (SocketQUICTransport_T t);

/**
 * @brief Check whether the peer sent a CONNECTION_CLOSE frame.
 *
 * @param t  Transport handle.
 * @return 1 if a peer CONNECTION_CLOSE was received, 0 otherwise.
 */
int SocketQUICTransport_peer_close_received (SocketQUICTransport_T t);

/**
 * @brief Get the error code from the peer's CONNECTION_CLOSE frame.
 *
 * Only meaningful when SocketQUICTransport_peer_close_received() returns 1.
 *
 * @param t  Transport handle.
 * @return Error code (transport or application), or 0 if no close received.
 */
uint64_t SocketQUICTransport_peer_close_error (SocketQUICTransport_T t);

/**
 * @brief Check whether the peer's CONNECTION_CLOSE was application-level.
 *
 * @param t  Transport handle.
 * @return 1 if application-level (frame type 0x1d), 0 if transport-level.
 */
int SocketQUICTransport_peer_close_is_app (SocketQUICTransport_T t);

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETQUICTRANSPORT_INCLUDED */
