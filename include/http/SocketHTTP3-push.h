/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTP3-push.h
 * @brief HTTP/3 server push support (RFC 9114 Section 4.6).
 *
 * Server push allows a server to pre-emptively send responses to a client.
 * The server sends a PUSH_PROMISE on an existing request stream, then
 * opens a unidirectional push stream to deliver the promised response.
 *
 * Build with -DENABLE_H3_PUSH=ON to enable. Disabled by default since
 * server push is rarely used in practice.
 *
 * Output model: Same as connection — push operations enqueue entries into
 * the connection's output queue. Caller must drain_output() between
 * push operations to avoid exhausting the output queue.
 */

#ifndef SOCKETHTTP3_PUSH_INCLUDED
#define SOCKETHTTP3_PUSH_INCLUDED

#ifdef SOCKET_HAS_H3_PUSH

#include <stddef.h>
#include <stdint.h>

#include "http/SocketHTTP.h"
#include "http/SocketHTTP3.h"
#include "http/SocketHTTP3-request.h"

/**
 * @brief Callback invoked when a client receives a PUSH_PROMISE.
 */
typedef void (*SocketHTTP3_PushCallback) (SocketHTTP3_Conn_T conn,
                                          uint64_t push_id,
                                          SocketHTTP_Headers_T promised_headers,
                                          void *userdata);

/**
 * @brief Allocate the next push ID.
 *
 * Monotonically increments the server's push ID counter. Fails if the
 * client hasn't sent MAX_PUSH_ID or the allocated ID would exceed it.
 *
 * @param conn          Server connection handle.
 * @param[out] out_push_id  Output: allocated push ID.
 * @return 0 on success, negative H3 error code on failure.
 */
int SocketHTTP3_Conn_allocate_push_id (SocketHTTP3_Conn_T conn,
                                       uint64_t *out_push_id);

/**
 * @brief Send PUSH_PROMISE on a request stream.
 *
 * QPACK-encodes the promised request headers and sends a PUSH_PROMISE
 * frame on the specified request stream. The push entry transitions to
 * PROMISED state.
 *
 * @param conn              Server connection handle.
 * @param request_stream_id Bidirectional stream to send promise on.
 * @param push_id           Previously allocated push ID.
 * @param headers           Promised request headers.
 * @return 0 on success, negative H3 error code on failure.
 */
int SocketHTTP3_Conn_send_push_promise (SocketHTTP3_Conn_T conn,
                                        uint64_t request_stream_id,
                                        uint64_t push_id,
                                        const SocketHTTP_Headers_T headers);

/**
 * @brief Open a push stream for a previously promised push ID.
 *
 * Allocates a server-initiated unidirectional stream, writes the push
 * stream header (type byte + push ID), and returns a request handle.
 * The caller uses send_headers + send_data on the returned handle to
 * deliver the pushed response.
 *
 * @param conn     Server connection handle.
 * @param push_id  Previously promised push ID (must be in PROMISED state).
 * @return Request handle for the push stream, or NULL on error.
 */
SocketHTTP3_Request_T
SocketHTTP3_Conn_open_push_stream (SocketHTTP3_Conn_T conn, uint64_t push_id);

/**
 * @brief Register a push promise callback (client only).
 *
 * The callback is invoked when the client receives a PUSH_PROMISE frame.
 *
 * @param conn      Client connection handle.
 * @param cb        Callback function (NULL to clear).
 * @param userdata  User context passed to callback.
 */
void SocketHTTP3_Conn_on_push (SocketHTTP3_Conn_T conn,
                                SocketHTTP3_PushCallback cb,
                                void *userdata);

/**
 * @brief Send MAX_PUSH_ID on the control stream (client only).
 *
 * Tells the server the maximum push ID it may use. The value must not
 * decrease from previously sent values.
 *
 * @param conn         Client connection handle.
 * @param max_push_id  Maximum push ID the server may use.
 * @return 0 on success, negative H3 error code on failure.
 */
int SocketHTTP3_Conn_send_max_push_id (SocketHTTP3_Conn_T conn,
                                       uint64_t max_push_id);

/**
 * @brief Cancel a push (both roles).
 *
 * Sends a CANCEL_PUSH frame on the control stream. Server: cancels a
 * promised or open push. Client: rejects a promised push.
 *
 * @param conn     Connection handle.
 * @param push_id  Push ID to cancel.
 * @return 0 on success, negative H3 error code on failure.
 */
int SocketHTTP3_Conn_cancel_push (SocketHTTP3_Conn_T conn, uint64_t push_id);

#endif /* SOCKET_HAS_H3_PUSH */

#endif /* SOCKETHTTP3_PUSH_INCLUDED */
