/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTP3.h
 * @brief HTTP/3 connection lifecycle management (RFC 9114).
 *
 * Manages the HTTP/3 connection layer between QUIC transport and
 * request/response processing: critical stream setup, SETTINGS
 * exchange, GOAWAY, and error handling.
 *
 * Output model: Functions that generate wire data (init, shutdown)
 * enqueue entries into an output queue. The caller retrieves entries
 * via get_output/output_count and sends them on the appropriate QUIC
 * streams, then calls drain_output to clear the queue.
 */

#ifndef SOCKETHTTP3_INCLUDED
#define SOCKETHTTP3_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include "core/Arena.h"
#include "http/SocketHTTP3-frame.h"

/**
 * @brief HTTP/3 connection states.
 */
typedef enum
{
  H3_CONN_STATE_IDLE,        /**< Created but not initialized */
  H3_CONN_STATE_OPEN,        /**< Critical streams opened, SETTINGS sent */
  H3_CONN_STATE_GOAWAY_SENT, /**< Local GOAWAY sent */
  H3_CONN_STATE_GOAWAY_RECV, /**< Peer GOAWAY received */
  H3_CONN_STATE_CLOSING,     /**< Both GOAWAYs exchanged */
  H3_CONN_STATE_CLOSED       /**< Connection closed */
} SocketHTTP3_ConnState;

/**
 * @brief HTTP/3 endpoint role.
 */
typedef enum
{
  H3_ROLE_CLIENT,
  H3_ROLE_SERVER
} SocketHTTP3_Role;

/**
 * @brief Configuration for creating an HTTP/3 connection.
 */
typedef struct
{
  SocketHTTP3_Role role;
  SocketHTTP3_Settings local_settings;
} SocketHTTP3_ConnConfig;

/**
 * @brief Per-stream output entry: pairs data with its destination stream.
 *
 * The data pointer is valid until drain_output is called.
 */
typedef struct
{
  uint64_t stream_id;
  const uint8_t *data;
  size_t len;
} SocketHTTP3_Output;

/** Opaque connection handle. */
typedef struct SocketHTTP3_Conn *SocketHTTP3_Conn_T;

/**
 * @brief Initialize config to RFC defaults with the given role.
 *
 * @param config  Output config structure.
 * @param role    Endpoint role (client or server).
 */
void SocketHTTP3_ConnConfig_defaults (SocketHTTP3_ConnConfig *config,
                                      SocketHTTP3_Role role);

/**
 * @brief Create a new HTTP/3 connection.
 *
 * @param arena   Memory arena for all allocations.
 * @param quic    QUIC connection handle (stored but not called; may be NULL
 *                for testing).
 * @param config  Connection configuration.
 * @return New connection in IDLE state, or NULL on error.
 */
SocketHTTP3_Conn_T SocketHTTP3_Conn_new (Arena_T arena,
                                         void *quic,
                                         const SocketHTTP3_ConnConfig *config);

/**
 * @brief Initialize the connection: open critical streams and send SETTINGS.
 *
 * Assigns local stream IDs, builds type bytes and SETTINGS frame,
 * queues output entries, and transitions state to OPEN.
 *
 * @param conn  Connection handle.
 * @return 0 on success, negative error code on failure.
 */
int SocketHTTP3_Conn_init (SocketHTTP3_Conn_T conn);

/**
 * @brief Process incoming data on a QUIC stream.
 *
 * Classifies the stream, handles unidirectional stream type detection,
 * and dispatches to the appropriate handler (control, QPACK, request).
 *
 * @param conn       Connection handle.
 * @param stream_id  QUIC stream ID.
 * @param data       Incoming data buffer.
 * @param len        Data length.
 * @param fin        1 if this is the final data on the stream.
 * @return 0 on success, negative H3 error code on protocol violation.
 */
int SocketHTTP3_Conn_feed_stream (SocketHTTP3_Conn_T conn,
                                  uint64_t stream_id,
                                  const uint8_t *data,
                                  size_t len,
                                  int fin);

/**
 * @brief Send GOAWAY for graceful shutdown.
 *
 * Builds a GOAWAY frame on the control stream and queues output.
 * The last_id indicates the last stream/push ID the peer should consider.
 *
 * @param conn     Connection handle.
 * @param last_id  Last accepted stream ID (client bidi) or push ID.
 * @return 0 on success, negative error code on failure.
 */
int SocketHTTP3_Conn_shutdown (SocketHTTP3_Conn_T conn, uint64_t last_id);

/**
 * @brief Immediately close the connection.
 *
 * Sets state to CLOSED. The caller should send a QUIC CONNECTION_CLOSE
 * with the returned error code.
 *
 * @param conn        Connection handle.
 * @param error_code  H3 error code for the close reason.
 * @return The error code for use in QUIC CONNECTION_CLOSE.
 */
int SocketHTTP3_Conn_close (SocketHTTP3_Conn_T conn, uint64_t error_code);

/**
 * @brief Get current connection state.
 */
SocketHTTP3_ConnState SocketHTTP3_Conn_state (SocketHTTP3_Conn_T conn);

/**
 * @brief Get peer's SETTINGS (valid after SETTINGS frame received).
 */
const SocketHTTP3_Settings *
SocketHTTP3_Conn_peer_settings (SocketHTTP3_Conn_T conn);

/**
 * @brief Get output entry at index.
 *
 * @param conn   Connection handle.
 * @param index  Entry index (0-based).
 * @return Pointer to output entry, or NULL if index out of range.
 */
const SocketHTTP3_Output *
SocketHTTP3_Conn_get_output (SocketHTTP3_Conn_T conn, size_t index);

/**
 * @brief Get number of pending output entries.
 */
size_t SocketHTTP3_Conn_output_count (SocketHTTP3_Conn_T conn);

/**
 * @brief Clear all output entries after caller has sent them.
 */
void SocketHTTP3_Conn_drain_output (SocketHTTP3_Conn_T conn);

/**
 * @brief Return human-readable name for a connection state.
 */
const char *SocketHTTP3_Conn_state_name (SocketHTTP3_ConnState state);

#endif /* SOCKETHTTP3_INCLUDED */
