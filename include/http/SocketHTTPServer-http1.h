/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTPServer-http1.h
 * @brief HTTP/1.1 protocol handling for HTTP server
 * @internal
 *
 * HTTP/1.1 message processing, h2c upgrade (RFC 9113 §3.2), and streaming.
 * Used internally by SocketHTTPServer implementation.
 */

#ifndef SOCKETHTTPSERVER_HTTP1_INCLUDED
#define SOCKETHTTPSERVER_HTTP1_INCLUDED

#include "core/Arena.h"
#include "http/SocketHTTPServer.h"

/* Forward declarations from private header */
typedef struct ServerConnection ServerConnection;

/**
 * server_handle_parsed_request - Handle a fully parsed HTTP request
 * @server: HTTP server
 * @conn: Connection with parsed request
 *
 * Returns: 1 if request processed, 0 if rejected/skipped
 *
 * Orchestrates rate limiting, validation, handler invocation, and response.
 * This is the main HTTP/1.1 request dispatcher.
 */
int server_handle_parsed_request (SocketHTTPServer_T server,
                                  ServerConnection *conn);

/**
 * server_try_h2c_upgrade - Attempt HTTP/2 connection upgrade (RFC 9113 §3.2)
 * @server: HTTP server
 * @conn: Connection with upgrade request
 *
 * Returns: 1 if upgrade performed, 0 if not applicable/invalid, -1 on error
 *
 * Validates Upgrade header, decodes HTTP2-Settings, sends 101 response,
 * and transitions connection to HTTP/2 protocol.
 */
int server_try_h2c_upgrade (SocketHTTPServer_T server, ServerConnection *conn);

/**
 * server_header_has_token_ci - Check if header contains token (case-insensitive)
 * @value: Header value string (e.g., "Upgrade, HTTP2-Settings")
 * @token: Token to search for (e.g., "upgrade")
 *
 * Returns: 1 if token found, 0 otherwise
 *
 * Implements RFC 9110 §5.1.5 comma-separated token parsing with
 * case-insensitive matching and whitespace handling.
 */
int server_header_has_token_ci (const char *value, const char *token);

/**
 * server_decode_http2_settings - Decode HTTP2-Settings header value
 * @arena: Memory arena for allocation
 * @b64url: Base64url-encoded settings (RFC 4648 §5)
 * @out: Output buffer for decoded settings frame
 * @out_len: Length of decoded settings frame
 *
 * Returns: 0 on success, -1 on error
 *
 * Decodes HTTP2-Settings header value from base64url to settings frame bytes.
 */
int server_decode_http2_settings (Arena_T arena,
                                  const char *b64url,
                                  unsigned char **out,
                                  size_t *out_len);

/**
 * should_copy_header_to_h2 - Check if header should be copied during h2c upgrade
 * @name: Header name
 * @value: Header value
 *
 * Returns: 1 if header should be copied, 0 if filtered
 *
 * Implements RFC 9113 §3.2.1 header filtering rules for h2c upgrade.
 * Filters connection-specific headers (Connection, Upgrade, etc.).
 */
int should_copy_header_to_h2 (const char *name, const char *value);

/**
 * server_process_streaming_body - Handle streaming body callback
 * @server: HTTP server
 * @conn: Connection with streaming body
 * @input: Input buffer pointer
 * @input_len: Input buffer length
 *
 * Returns: Number of requests processed (0 or 1), or -1 on error/close
 *
 * Processes request body in streaming mode, invoking the body callback
 * for each chunk. Returns early if callback aborts or parser fails.
 */
int server_process_streaming_body (SocketHTTPServer_T server,
                                   ServerConnection *conn,
                                   const void *input,
                                   size_t input_len);

/**
 * server_process_body_reading - Process HTTP/1.1 request body reading
 * @server: HTTP server
 * @conn: Connection in CONN_STATE_READING_BODY state
 *
 * Returns: Number of requests processed (0 or 1)
 *
 * Handles both streaming and buffering modes for HTTP/1.1 request bodies:
 * - Streaming mode: Invokes callback for each chunk via server_process_streaming_body
 * - Chunked/until-close: Uses dynamic SocketBuf_T with size limit enforcement
 * - Content-Length: Uses fixed buffer with DoS prevention
 *
 * Enforces max_body_size limit and sends 413 Payload Too Large if exceeded.
 * Transitions to CONN_STATE_HANDLING when body is complete.
 */
int server_process_body_reading (SocketHTTPServer_T server,
                                 ServerConnection *conn);

#endif /* SOCKETHTTPSERVER_HTTP1_INCLUDED */
