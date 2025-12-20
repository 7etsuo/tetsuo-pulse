/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETSIMPLE_WS_INCLUDED
#define SOCKETSIMPLE_WS_INCLUDED

/**
 * @file SocketSimple-ws.h
 * @brief Simple WebSocket client operations.
 */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Types
 *============================================================================*/

/**
 * @brief Opaque WebSocket handle.
 */
typedef struct SocketSimple_WS *SocketSimple_WS_T;

/**
 * @brief WebSocket message types.
 */
typedef enum {
    SOCKET_SIMPLE_WS_TEXT = 1,   /**< Text message (UTF-8) */
    SOCKET_SIMPLE_WS_BINARY = 2, /**< Binary message */
    SOCKET_SIMPLE_WS_PING = 9,   /**< Ping frame */
    SOCKET_SIMPLE_WS_PONG = 10,  /**< Pong frame */
    SOCKET_SIMPLE_WS_CLOSE = 8   /**< Close frame */
} SocketSimple_WSMessageType;

/**
 * @brief WebSocket message structure.
 */
typedef struct {
    SocketSimple_WSMessageType type; /**< Message type */
    void *data;                       /**< Message data (caller must free) */
    size_t len;                       /**< Data length */
    int close_code;                   /**< Close code (for CLOSE type) */
    char *close_reason;               /**< Close reason (for CLOSE type, caller frees) */
} SocketSimple_WSMessage;

/**
 * @brief WebSocket connection options.
 */
typedef struct {
    int connect_timeout_ms;   /**< Connection timeout (0 = default 30s) */
    int ping_interval_ms;     /**< Auto-ping interval (0 = disabled) */
    const char *subprotocols; /**< Subprotocols, comma-separated (NULL = none) */
    const char *origin;       /**< Origin header (NULL = none) */
    const char **headers;     /**< Extra headers, NULL-terminated (NULL = none) */
} SocketSimple_WSOptions;

/**
 * @brief Initialize WebSocket options to defaults.
 *
 * @param opts Options structure to initialize.
 */
extern void Socket_simple_ws_options_init(SocketSimple_WSOptions *opts);

/*============================================================================
 * Connection Functions
 *============================================================================*/

/**
 * @brief Connect to WebSocket server.
 *
 * Automatically handles ws:// and wss:// URLs.
 * Performs TCP connect, TLS handshake (if wss), and WebSocket upgrade.
 *
 * @param url WebSocket URL (e.g., "wss://echo.websocket.org").
 * @return WebSocket handle on success, NULL on error.
 *
 * Example:
 * @code
 * SocketSimple_WS_T ws = Socket_simple_ws_connect("wss://echo.websocket.org");
 * if (!ws) {
 *     fprintf(stderr, "Error: %s\n", Socket_simple_error());
 *     return 1;
 * }
 *
 * Socket_simple_ws_send_text(ws, "Hello!", 6);
 *
 * SocketSimple_WSMessage msg;
 * if (Socket_simple_ws_recv(ws, &msg) == 0) {
 *     printf("Received: %.*s\n", (int)msg.len, (char*)msg.data);
 *     Socket_simple_ws_message_free(&msg);
 * }
 *
 * Socket_simple_ws_close(ws, 1000, NULL);
 * Socket_simple_ws_free(&ws);
 * @endcode
 */
extern SocketSimple_WS_T Socket_simple_ws_connect(const char *url);

/**
 * @brief Connect to WebSocket server with options.
 *
 * @param url WebSocket URL.
 * @param opts Connection options (NULL for defaults).
 * @return WebSocket handle on success, NULL on error.
 */
extern SocketSimple_WS_T Socket_simple_ws_connect_ex(
    const char *url, const SocketSimple_WSOptions *opts);

/*============================================================================
 * Send Functions
 *============================================================================*/

/**
 * @brief Send text message.
 *
 * @param ws WebSocket handle.
 * @param text UTF-8 text to send.
 * @param len Text length (use strlen() for C strings).
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_ws_send_text(SocketSimple_WS_T ws,
                                       const char *text,
                                       size_t len);

/**
 * @brief Send binary message.
 *
 * @param ws WebSocket handle.
 * @param data Binary data to send.
 * @param len Data length.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_ws_send_binary(SocketSimple_WS_T ws,
                                         const void *data,
                                         size_t len);

/**
 * @brief Send JSON message (as text).
 *
 * @param ws WebSocket handle.
 * @param json JSON string.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_ws_send_json(SocketSimple_WS_T ws, const char *json);

/**
 * @brief Send ping frame.
 *
 * @param ws WebSocket handle.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_ws_ping(SocketSimple_WS_T ws);

/*============================================================================
 * Receive Functions
 *============================================================================*/

/**
 * @brief Receive message (blocking).
 *
 * Automatically responds to PING with PONG.
 *
 * @param ws WebSocket handle.
 * @param msg Output message structure.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_ws_recv(SocketSimple_WS_T ws,
                                  SocketSimple_WSMessage *msg);

/**
 * @brief Receive message with timeout.
 *
 * @param ws WebSocket handle.
 * @param msg Output message structure.
 * @param timeout_ms Timeout in milliseconds.
 * @return 0 on success, 1 on timeout, -1 on error.
 */
extern int Socket_simple_ws_recv_timeout(SocketSimple_WS_T ws,
                                          SocketSimple_WSMessage *msg,
                                          int timeout_ms);

/*============================================================================
 * Close Functions
 *============================================================================*/

/**
 * @brief Initiate graceful close.
 *
 * Sends close frame and waits for server response.
 *
 * @param ws WebSocket handle.
 * @param code Close code (1000 = normal, see RFC 6455).
 * @param reason Close reason (NULL for none).
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_ws_close(SocketSimple_WS_T ws,
                                   int code,
                                   const char *reason);

/**
 * @brief Free WebSocket resources.
 *
 * Also closes connection if still open.
 *
 * @param ws Pointer to WebSocket handle.
 */
extern void Socket_simple_ws_free(SocketSimple_WS_T *ws);

/**
 * @brief Free message data.
 *
 * @param msg Message structure to free.
 */
extern void Socket_simple_ws_message_free(SocketSimple_WSMessage *msg);

/*============================================================================
 * Status Functions
 *============================================================================*/

/**
 * @brief Check if WebSocket is open.
 *
 * @param ws WebSocket handle.
 * @return 1 if open, 0 if closed or closing.
 */
extern int Socket_simple_ws_is_open(SocketSimple_WS_T ws);

/**
 * @brief Get selected subprotocol.
 *
 * @param ws WebSocket handle.
 * @return Protocol string, or NULL if none selected.
 */
extern const char *Socket_simple_ws_protocol(SocketSimple_WS_T ws);

/**
 * @brief Get underlying file descriptor.
 *
 * Useful for poll/select integration.
 *
 * @param ws WebSocket handle.
 * @return File descriptor, or -1 if invalid.
 */
extern int Socket_simple_ws_fd(SocketSimple_WS_T ws);

#ifdef __cplusplus
}
#endif

#endif /* SOCKETSIMPLE_WS_INCLUDED */
