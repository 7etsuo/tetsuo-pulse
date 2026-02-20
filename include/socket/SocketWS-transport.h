/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketWS-transport.h
 * @ingroup websocket
 * @brief Transport abstraction layer for WebSocket I/O.
 *
 * Provides a pluggable transport interface for WebSocket connections,
 * enabling support for multiple underlying transports:
 * - TCP sockets (RFC 6455 - standard WebSocket)
 * - HTTP/2 streams (RFC 8441 - WebSocket over HTTP/2)
 *
 * The transport abstraction allows SocketWS to be transport-agnostic,
 * delegating actual I/O operations to the appropriate backend.
 *
 * Key Design:
 * - Function pointer vtable for transport operations
 * - Opaque context pointer for transport-specific state
 * - Arena-based memory management following library patterns
 *
 * Thread Safety:
 * - SocketWS_Transport_T instances are NOT thread-safe
 * - Each transport instance should be used from a single thread
 *
 * @see SocketWS.h for WebSocket API.
 * @see RFC 6455 for WebSocket Protocol.
 * @see RFC 8441 for WebSocket over HTTP/2.
 */

#ifndef SOCKETWS_TRANSPORT_INCLUDED
#define SOCKETWS_TRANSPORT_INCLUDED

#include <stddef.h>
#include <sys/types.h>

#include "core/Arena.h"
#include "socket/Socket.h"

/* Forward declarations for HTTP/2 types */
struct SocketHTTP2_Stream;
typedef struct SocketHTTP2_Stream *SocketHTTP2_Stream_T;

struct SocketHTTP2_Conn;
typedef struct SocketHTTP2_Conn *SocketHTTP2_Conn_T;

/**
 * @brief Opaque handle for a WebSocket transport.
 * @ingroup websocket
 */
typedef struct SocketWS_Transport *SocketWS_Transport_T;

/**
 * @brief Transport type identifier for runtime checks.
 * @ingroup websocket
 */
typedef enum
{
  SOCKETWS_TRANSPORT_SOCKET,  /**< TCP/TLS socket transport (RFC 6455) */
  SOCKETWS_TRANSPORT_H2STREAM /**< HTTP/2 stream transport (RFC 8441) */
} SocketWS_TransportType;

/**
 * @brief Function pointer type for transport send operation.
 * @ingroup websocket
 *
 * Sends data through the transport. Semantics match POSIX send().
 *
 * @param ctx Transport-specific context (e.g., Socket_T, HTTP2 stream).
 * @param data Data buffer to send.
 * @param len Number of bytes to send.
 * @return Bytes sent on success, -1 on error (sets errno).
 *
 * @note For non-blocking transports, may return partial send or EAGAIN.
 */
typedef ssize_t (*SocketWS_TransportSend) (void *ctx,
                                           const void *data,
                                           size_t len);

/**
 * @brief Function pointer type for transport receive operation.
 * @ingroup websocket
 *
 * Receives data from the transport. Semantics match POSIX recv().
 *
 * @param ctx Transport-specific context.
 * @param buf Buffer to receive into.
 * @param len Maximum bytes to receive.
 * @return Bytes received on success, 0 on EOF, -1 on error.
 *
 * @note For non-blocking transports, may return EAGAIN.
 */
typedef ssize_t (*SocketWS_TransportRecv) (void *ctx, void *buf, size_t len);

/**
 * @brief Function pointer type for transport close operation.
 * @ingroup websocket
 *
 * Initiates orderly shutdown of the transport.
 *
 * @param ctx Transport-specific context.
 * @param orderly Non-zero for graceful close, 0 for immediate.
 * @return 0 on success, -1 on error.
 *
 * @note For HTTP/2: orderly=1 sends END_STREAM, orderly=0 sends RST_STREAM.
 */
typedef int (*SocketWS_TransportClose) (void *ctx, int orderly);

/**
 * @brief Function pointer type for getting transport file descriptor.
 * @ingroup websocket
 *
 * Returns the file descriptor for poll/epoll integration.
 *
 * @param ctx Transport-specific context.
 * @return File descriptor >= 0, or -1 if not applicable.
 *
 * @note HTTP/2 streams return -1; poll the connection instead.
 */
typedef int (*SocketWS_TransportGetFd) (void *ctx);

/**
 * @brief Function pointer type for transport cleanup.
 * @ingroup websocket
 *
 * Releases transport-specific resources. Called when WebSocket is freed.
 *
 * @param ctx Transport-specific context.
 *
 * @note Should NOT free arena-allocated memory (managed by arena lifecycle).
 */
typedef void (*SocketWS_TransportFree) (void *ctx);

/**
 * @brief Operations table for WebSocket transport backends.
 * @ingroup websocket
 *
 * Implements the strategy pattern for transport-agnostic I/O.
 * Each transport type (socket, HTTP/2 stream) provides its own vtable.
 *
 * @see SocketWS_Transport_socket() for socket transport vtable.
 * @see SocketWS_Transport_h2stream() for HTTP/2 transport vtable.
 */
typedef struct
{
  SocketWS_TransportSend send;    /**< Send data through transport */
  SocketWS_TransportRecv recv;    /**< Receive data from transport */
  SocketWS_TransportClose close;  /**< Close the transport */
  SocketWS_TransportGetFd get_fd; /**< Get file descriptor for polling */
  SocketWS_TransportFree free;    /**< Release transport resources */
} SocketWS_TransportOps;

/**
 * @brief Internal structure for WebSocket transport.
 * @ingroup websocket
 * @internal
 *
 * Encapsulates transport type, operations vtable, and context pointer.
 * Users should access only through SocketWS_Transport_T functions.
 */
struct SocketWS_Transport
{
  SocketWS_TransportType type;      /**< Transport type identifier */
  const SocketWS_TransportOps *ops; /**< Operations vtable */
  void *ctx;                        /**< Transport-specific context */
  Arena_T arena;                    /**< Memory arena for allocations */
  int requires_masking; /**< 1 if client masking required (RFC 6455),
                             0 for HTTP/2 (RFC 8441) */
};

/**
 * @brief Create a socket-based transport (RFC 6455).
 * @ingroup websocket
 *
 * Wraps an existing TCP/TLS socket as a WebSocket transport.
 * Used for standard WebSocket connections over TCP.
 *
 * @param arena Memory arena for allocations.
 * @param socket Connected TCP socket (ownership transferred).
 * @param is_client Non-zero if client role (enables masking).
 * @return Transport handle, or NULL on failure.
 *
 * @note The socket is owned by the transport after creation.
 * @see SocketWS_Transport_free() to release.
 */
extern SocketWS_Transport_T
SocketWS_Transport_socket (Arena_T arena, Socket_T socket, int is_client);

/**
 * @brief Create an HTTP/2 stream transport (RFC 8441).
 * @ingroup websocket
 *
 * Wraps an HTTP/2 stream as a WebSocket transport.
 * Used for WebSocket-over-HTTP/2 (Extended CONNECT).
 *
 * @param arena Memory arena for allocations.
 * @param stream HTTP/2 stream from Extended CONNECT.
 * @return Transport handle, or NULL on failure.
 *
 * @note HTTP/2 WebSockets do not use masking (RFC 8441).
 * @note The stream must be in an appropriate state (post-HEADERS exchange).
 * @see SocketWS_Transport_free() to release.
 */
extern SocketWS_Transport_T
SocketWS_Transport_h2stream (Arena_T arena, SocketHTTP2_Stream_T stream);

/**
 * @brief Get the transport type.
 * @ingroup websocket
 *
 * @param transport Transport handle.
 * @return Transport type (socket or HTTP/2 stream).
 */
extern SocketWS_TransportType
SocketWS_Transport_type (SocketWS_Transport_T transport);

/**
 * @brief Check if transport requires client masking.
 * @ingroup websocket
 *
 * Per RFC 6455, TCP WebSocket clients must mask frames.
 * Per RFC 8441, HTTP/2 WebSockets do not use masking.
 *
 * @param transport Transport handle.
 * @return Non-zero if masking required, 0 otherwise.
 */
extern int SocketWS_Transport_requires_masking (SocketWS_Transport_T transport);

/**
 * @brief Send data through the transport.
 * @ingroup websocket
 *
 * @param transport Transport handle.
 * @param data Data to send.
 * @param len Length of data.
 * @return Bytes sent, or -1 on error.
 */
extern ssize_t SocketWS_Transport_send (SocketWS_Transport_T transport,
                                        const void *data,
                                        size_t len);

/**
 * @brief Receive data from the transport.
 * @ingroup websocket
 *
 * @param transport Transport handle.
 * @param buf Buffer to receive into.
 * @param len Maximum bytes to receive.
 * @return Bytes received, 0 on EOF, -1 on error.
 */
extern ssize_t
SocketWS_Transport_recv (SocketWS_Transport_T transport, void *buf, size_t len);

/**
 * @brief Close the transport.
 * @ingroup websocket
 *
 * @param transport Transport handle.
 * @param orderly Non-zero for graceful close.
 * @return 0 on success, -1 on error.
 */
extern int
SocketWS_Transport_close (SocketWS_Transport_T transport, int orderly);

/**
 * @brief Get file descriptor for poll integration.
 * @ingroup websocket
 *
 * @param transport Transport handle.
 * @return File descriptor, or -1 if not available.
 */
extern int SocketWS_Transport_get_fd (SocketWS_Transport_T transport);

/**
 * @brief Free transport resources.
 * @ingroup websocket
 *
 * Releases transport-specific resources. The transport handle
 * becomes invalid after this call.
 *
 * @param transport Pointer to transport handle (set to NULL).
 */
extern void SocketWS_Transport_free (SocketWS_Transport_T *transport);

/**
 * @brief Get the underlying socket (for socket transports only).
 * @ingroup websocket
 *
 * @param transport Transport handle.
 * @return Socket_T if socket transport, NULL otherwise.
 *
 * @note Returns NULL for HTTP/2 stream transports.
 */
extern Socket_T SocketWS_Transport_get_socket (SocketWS_Transport_T transport);

/**
 * @brief Get the underlying HTTP/2 stream (for H2 transports only).
 * @ingroup websocket
 *
 * @param transport Transport handle.
 * @return SocketHTTP2_Stream_T if H2 transport, NULL otherwise.
 *
 * @note Returns NULL for socket transports.
 */
extern SocketHTTP2_Stream_T
SocketWS_Transport_get_h2stream (SocketWS_Transport_T transport);

#endif /* SOCKETWS_TRANSPORT_INCLUDED */
