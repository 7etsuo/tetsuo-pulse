/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTP3-request.h
 * @brief HTTP/3 request/response exchange (RFC 9114 Section 4).
 *
 * Encodes HTTP requests into HEADERS+DATA frames with QPACK-compressed
 * headers, and decodes responses. Builds on the connection lifecycle
 * (SocketHTTP3.h) and uses the QPACK static table for header compression.
 *
 * Output model: Same as connection — send operations enqueue entries into
 * the connection's output queue. Caller retrieves via get_output/drain_output.
 */

#ifndef SOCKETHTTP3_REQUEST_INCLUDED
#define SOCKETHTTP3_REQUEST_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "http/SocketHTTP.h"
#include "http/SocketHTTP3.h"

/**
 * @brief Request send-side state machine.
 */
typedef enum
{
  H3_REQ_SEND_IDLE,          /**< No headers sent yet */
  H3_REQ_SEND_HEADERS_SENT,  /**< Initial HEADERS sent */
  H3_REQ_SEND_BODY_SENT,     /**< At least one DATA frame sent */
  H3_REQ_SEND_TRAILERS_SENT, /**< Trailing HEADERS sent (implies end_stream) */
  H3_REQ_SEND_DONE           /**< Send side closed (end_stream sent) */
} SocketHTTP3_ReqSendState;

/**
 * @brief Request receive-side state machine.
 */
typedef enum
{
  H3_REQ_RECV_IDLE,             /**< No data received yet */
  H3_REQ_RECV_HEADERS_RECEIVED, /**< Initial HEADERS decoded */
  H3_REQ_RECV_BODY_RECEIVING,   /**< Receiving DATA frames */
  H3_REQ_RECV_COMPLETE          /**< FIN received, request complete */
} SocketHTTP3_ReqRecvState;

/** Opaque request handle. */
typedef struct SocketHTTP3_Request *SocketHTTP3_Request_T;

/**
 * @brief Create a new request on the connection.
 *
 * Allocates a bidi stream ID from the connection and registers the
 * request for output queue and feed_stream dispatch.
 *
 * @param conn  Connection handle (must be in OPEN state).
 * @return New request, or NULL on error (connection full or wrong state).
 */
SocketHTTP3_Request_T SocketHTTP3_Request_new (SocketHTTP3_Conn_T conn);

/**
 * @brief Create a request for a peer-initiated bidirectional stream.
 *
 * Used by the server connection layer when a client opens a new bidi
 * stream. Does not allocate a new stream ID — uses the provided one.
 * Validates that stream_id is client-initiated bidirectional.
 *
 * @param conn       Connection handle (must be in OPEN state).
 * @param stream_id  Peer-initiated bidi stream ID (must be divisible by 4).
 * @return New request, or NULL on error.
 */
SocketHTTP3_Request_T
SocketHTTP3_Request_new_incoming (SocketHTTP3_Conn_T conn, uint64_t stream_id);

/**
 * @brief Send HEADERS frame (initial or informational).
 *
 * QPACK-encodes the headers using static table only, wraps in a HEADERS
 * frame, and queues the output. If end_stream is set, the send side is
 * closed (e.g., for GET requests with no body).
 *
 * @param req         Request handle.
 * @param headers     HTTP headers (must include required pseudo-headers).
 * @param end_stream  1 to close the send side after this frame.
 * @return 0 on success, negative H3 error code on failure.
 */
int SocketHTTP3_Request_send_headers (SocketHTTP3_Request_T req,
                                      const SocketHTTP_Headers_T headers,
                                      int end_stream);

/**
 * @brief Send DATA frame.
 *
 * Wraps the data in a DATA frame and queues the output.
 *
 * @param req         Request handle.
 * @param data        Payload data.
 * @param len         Payload length.
 * @param end_stream  1 to close the send side after this frame.
 * @return 0 on success, negative error code on failure.
 */
int SocketHTTP3_Request_send_data (SocketHTTP3_Request_T req,
                                   const void *data,
                                   size_t len,
                                   int end_stream);

/**
 * @brief Send trailing HEADERS frame.
 *
 * Implicitly sets end_stream.
 *
 * @param req       Request handle.
 * @param trailers  Trailing headers (no pseudo-headers allowed).
 * @return 0 on success, negative error code on failure.
 */
int SocketHTTP3_Request_send_trailers (SocketHTTP3_Request_T req,
                                       const SocketHTTP_Headers_T trailers);

/**
 * @brief Get received response headers.
 *
 * Returns the decoded response headers after feed_stream has delivered
 * a HEADERS frame. For informational responses (1xx), call again after
 * the next HEADERS frame arrives.
 *
 * @param req          Request handle.
 * @param[out] headers Output: header collection (arena-owned, valid until
 *                     connection arena is disposed).
 * @param[out] status_code Output: HTTP status code (may be NULL).
 * @return 0 on success, -1 if headers not yet available.
 */
int SocketHTTP3_Request_recv_headers (SocketHTTP3_Request_T req,
                                      SocketHTTP_Headers_T *headers,
                                      int *status_code);

/**
 * @brief Get decoded trailing HEADERS, when present.
 *
 * @param req            Request handle.
 * @param[out] trailers  Output trailer headers (may be NULL).
 * @return 0 on success, -1 if trailers not available.
 */
int SocketHTTP3_Request_recv_trailers (SocketHTTP3_Request_T req,
                                       SocketHTTP_Headers_T *trailers);

/**
 * @brief Read received DATA payload.
 *
 * Copies buffered DATA payload into the caller's buffer.
 *
 * @param req          Request handle.
 * @param buf          Output buffer.
 * @param buflen       Buffer size.
 * @param[out] end_stream  Set to 1 if all data received (may be NULL).
 * @return Bytes copied (>=0), or negative error code.
 */
ssize_t SocketHTTP3_Request_recv_data (SocketHTTP3_Request_T req,
                                       void *buf,
                                       size_t buflen,
                                       int *end_stream);

/**
 * @brief Cancel the request (client-side RST_STREAM equivalent).
 *
 * Marks the request as cancelled. No more send/recv operations will succeed.
 *
 * @param req  Request handle.
 * @return 0 on success, -1 if already cancelled or NULL.
 */
int SocketHTTP3_Request_cancel (SocketHTTP3_Request_T req);

/**
 * @brief Get the QUIC stream ID for this request.
 */
uint64_t SocketHTTP3_Request_stream_id (SocketHTTP3_Request_T req);

/**
 * @brief Get the send-side state.
 */
SocketHTTP3_ReqSendState
SocketHTTP3_Request_send_state (SocketHTTP3_Request_T req);

/**
 * @brief Get the receive-side state.
 */
SocketHTTP3_ReqRecvState
SocketHTTP3_Request_recv_state (SocketHTTP3_Request_T req);

/**
 * @brief Validate request headers per RFC 9114 Section 4.3.1.
 *
 * Checks pseudo-header requirements, forbidden connection headers,
 * field name case, and CONNECT method rules.
 *
 * @param headers  Headers to validate.
 * @return 0 if valid, negative H3 error code on violation.
 */
int SocketHTTP3_validate_request_headers (const SocketHTTP_Headers_T headers);

/**
 * @brief Validate response headers per RFC 9114 Section 4.3.2.
 *
 * Checks :status presence, forbidden headers, status 101 prohibition.
 *
 * @param headers  Headers to validate.
 * @return 0 if valid, negative H3 error code on violation.
 */
int SocketHTTP3_validate_response_headers (const SocketHTTP_Headers_T headers);

/**
 * @brief Feed incoming stream data to a request.
 *
 * Called by the connection layer when data arrives on a request stream.
 * Parses HEADERS/DATA frames and updates the request state machine.
 *
 * @param req   Request handle.
 * @param data  Incoming data.
 * @param len   Data length.
 * @param fin   1 if this is the final data on the stream.
 * @return 0 on success, negative H3 error code on protocol violation.
 */
int SocketHTTP3_Request_feed (SocketHTTP3_Request_T req,
                              const uint8_t *data,
                              size_t len,
                              int fin);

#ifdef SOCKET_HAS_H3_PUSH
/**
 * @brief Create a request for a server push stream.
 *
 * Used internally by the push module. Does not register in conn->requests[]
 * since push streams use a separate tracking array.
 *
 * @param conn       Connection handle (must be in OPEN state).
 * @param stream_id  Server-initiated unidirectional stream ID.
 * @param push_id    Push ID for this push stream.
 * @return New request, or NULL on error.
 */
SocketHTTP3_Request_T SocketHTTP3_Request_new_push (SocketHTTP3_Conn_T conn,
                                                    uint64_t stream_id,
                                                    uint64_t push_id);
#endif /* SOCKET_HAS_H3_PUSH */

#endif /* SOCKETHTTP3_REQUEST_INCLUDED */
