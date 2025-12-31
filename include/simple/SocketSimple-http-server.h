/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETSIMPLE_HTTP_SERVER_INCLUDED
#define SOCKETSIMPLE_HTTP_SERVER_INCLUDED

/**
 * @file SocketSimple-http-server.h
 * @brief Simple HTTP server wrapper (return-code based).
 *
 * Provides a high-level HTTP server with request/response handling
 * and graceful shutdown support.
 *
 * ## Quick Start
 *
 * ```c
 * #include <simple/SocketSimple.h>
 *
 * void handle_request(SocketSimple_HTTPServerRequest_T req, void *arg) {
 *     const char *path = Socket_simple_http_server_request_path(req);
 *
 *     Socket_simple_http_server_response_status(req, 200);
 *     Socket_simple_http_server_response_header(req, "Content-Type",
 * "text/plain"); Socket_simple_http_server_response_body(req, "Hello, World!",
 * 13); Socket_simple_http_server_response_finish(req);
 * }
 *
 * int main(void) {
 *     SocketSimple_HTTPServer_T server =
 * Socket_simple_http_server_new("0.0.0.0", 8080); if (!server) {
 *         fprintf(stderr, "Error: %s\n", Socket_simple_error());
 *         return 1;
 *     }
 *
 *     Socket_simple_http_server_set_handler(server, handle_request, NULL);
 *
 *     if (Socket_simple_http_server_start(server) != 0) {
 *         fprintf(stderr, "Error: %s\n", Socket_simple_error());
 *         Socket_simple_http_server_free(&server);
 *         return 1;
 *     }
 *
 *     // Event loop
 *     while (Socket_simple_http_server_poll(server, 1000) >= 0) {
 *         // Handle other tasks...
 *     }
 *
 *     Socket_simple_http_server_free(&server);
 *     return 0;
 * }
 * ```
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

  /* ==========================================================================
   * Types
   * ==========================================================================
   */

  /**
   * @brief Opaque HTTP server handle.
   */
  typedef struct SocketSimple_HTTPServer *SocketSimple_HTTPServer_T;

  /**
   * @brief Opaque request context handle.
   *
   * Valid only during handler callback execution. Provides access to both
   * request data and response building.
   */
  typedef struct SocketSimple_HTTPServerRequest
      *SocketSimple_HTTPServerRequest_T;

  /**
   * @brief HTTP server lifecycle states.
   */
  typedef enum
  {
    SOCKET_SIMPLE_SERVER_RUNNING,  /**< Normal operation */
    SOCKET_SIMPLE_SERVER_DRAINING, /**< Draining - finishing existing requests
                                    */
    SOCKET_SIMPLE_SERVER_STOPPED   /**< Stopped - all requests complete */
  } SocketSimple_HTTPServerState;

  /**
   * @brief HTTP server configuration.
   *
   * Use Socket_simple_http_server_config_init() to initialize with defaults.
   */
  typedef struct
  {
    int port;                       /**< Listen port (default: 8080) */
    const char *bind_address;       /**< Bind address (NULL = all interfaces) */
    int backlog;                    /**< Listen backlog (default: 128) */
    size_t max_header_size;         /**< Max header size (default: 64KB) */
    size_t max_body_size;           /**< Max body size (default: 10MB) */
    int request_timeout_ms;         /**< Request timeout (default: 30000) */
    int keepalive_timeout_ms;       /**< Keep-alive timeout (default: 60000) */
    size_t max_connections;         /**< Max connections (default: 1000) */
    int max_connections_per_client; /**< Per-IP limit (default: 100) */
    int enable_tls;                 /**< Enable TLS (requires cert/key) */
    const char *tls_cert_file;      /**< TLS certificate file path */
    const char *tls_key_file;       /**< TLS private key file path */
  } SocketSimple_HTTPServerConfig;

  /**
   * @brief HTTP server statistics.
   */
  typedef struct
  {
    size_t active_connections;   /**< Current active connections */
    size_t total_connections;    /**< Total connections accepted */
    size_t connections_rejected; /**< Connections rejected (limits) */
    size_t total_requests;       /**< Total HTTP requests processed */
    size_t total_bytes_sent;     /**< Total response bytes sent */
    size_t total_bytes_received; /**< Total request bytes received */
    size_t errors_4xx;           /**< Client error count */
    size_t errors_5xx;           /**< Server error count */
    size_t timeouts;             /**< Timeout count */
    size_t rate_limited;         /**< Rate limit rejections */
    int64_t avg_request_time_us; /**< Average request time (us) */
    int64_t max_request_time_us; /**< Max request time (us) */
  } SocketSimple_HTTPServerStats;

  /* ==========================================================================
   * Callback Types
   * ==========================================================================
   */

  /**
   * @brief Request handler callback.
   *
   * Called for each incoming HTTP request. The handler is responsible for:
   * 1. Inspecting the request (method, path, headers, body)
   * 2. Setting response status, headers, and body
   * 3. Calling Socket_simple_http_server_response_finish()
   *
   * @param req Request context (valid only during callback).
   * @param userdata User data passed to set_handler().
   */
  typedef void (*SocketSimple_HTTPServerHandler) (
      SocketSimple_HTTPServerRequest_T req, void *userdata);

  /**
   * @brief Request validator callback (middleware).
   *
   * Called before the main handler. Can reject requests early.
   *
   * @param req Request context.
   * @param reject_status Output: HTTP status for rejection (e.g., 401).
   * @param userdata User data passed to set_validator().
   * @return Non-zero to allow request, 0 to reject with reject_status.
   */
  typedef int (*SocketSimple_HTTPServerValidator) (
      SocketSimple_HTTPServerRequest_T req, int *reject_status, void *userdata);

  /**
   * @brief Drain completion callback.
   *
   * Called when graceful shutdown completes.
   *
   * @param server The server instance.
   * @param timed_out Non-zero if drain timed out.
   * @param userdata User data passed to set_drain_callback().
   */
  typedef void (*SocketSimple_HTTPServerDrainCallback) (
      SocketSimple_HTTPServer_T server, int timed_out, void *userdata);

  /* ==========================================================================
   * Configuration
   * ==========================================================================
   */

  /**
   * @brief Initialize server config with defaults.
   *
   * @param config Config structure to initialize.
   */
  extern void
  Socket_simple_http_server_config_init (SocketSimple_HTTPServerConfig *config);

  /* ==========================================================================
   * Server Lifecycle
   * ==========================================================================
   */

  /**
   * @brief Create a new HTTP server with simple configuration.
   *
   * @param host Bind address (NULL for "0.0.0.0").
   * @param port Listen port.
   * @return Server handle, or NULL on error.
   */
  extern SocketSimple_HTTPServer_T
  Socket_simple_http_server_new (const char *host, int port);

  /**
   * @brief Create HTTP server with full configuration.
   *
   * @param config Server configuration.
   * @return Server handle, or NULL on error.
   */
  extern SocketSimple_HTTPServer_T Socket_simple_http_server_new_ex (
      const SocketSimple_HTTPServerConfig *config);

  /**
   * @brief Free HTTP server and all resources.
   *
   * @param server Pointer to server handle (set to NULL).
   */
  extern void
  Socket_simple_http_server_free (SocketSimple_HTTPServer_T *server);

  /**
   * @brief Start listening for connections.
   *
   * @param server Server handle.
   * @return 0 on success, -1 on error.
   */
  extern int Socket_simple_http_server_start (SocketSimple_HTTPServer_T server);

  /**
   * @brief Stop accepting new connections.
   *
   * Existing connections continue processing.
   *
   * @param server Server handle.
   */
  extern void Socket_simple_http_server_stop (SocketSimple_HTTPServer_T server);

  /* ==========================================================================
   * Handler Registration
   * ==========================================================================
   */

  /**
   * @brief Set the request handler callback.
   *
   * @param server Server handle.
   * @param handler Request handler callback.
   * @param userdata User data passed to handler.
   */
  extern void
  Socket_simple_http_server_set_handler (SocketSimple_HTTPServer_T server,
                                         SocketSimple_HTTPServerHandler handler,
                                         void *userdata);

  /**
   * @brief Set request validator middleware.
   *
   * @param server Server handle.
   * @param validator Validator callback.
   * @param userdata User data passed to validator.
   */
  extern void Socket_simple_http_server_set_validator (
      SocketSimple_HTTPServer_T server,
      SocketSimple_HTTPServerValidator validator,
      void *userdata);

  /* ==========================================================================
   * Event Loop
   * ==========================================================================
   */

  /**
   * @brief Process server events (accept, read, write).
   *
   * Call this in a loop to handle incoming requests.
   *
   * @param server Server handle.
   * @param timeout_ms Timeout in ms (-1 = infinite, 0 = non-blocking).
   * @return Number of requests processed, or -1 on error.
   */
  extern int Socket_simple_http_server_poll (SocketSimple_HTTPServer_T server,
                                             int timeout_ms);

  /**
   * @brief Get the listening socket file descriptor.
   *
   * Useful for integrating with external event loops.
   *
   * @param server Server handle.
   * @return File descriptor, or -1 if not listening.
   */
  extern int Socket_simple_http_server_fd (SocketSimple_HTTPServer_T server);

  /* ==========================================================================
   * Request Accessors
   * ==========================================================================
   */

  /**
   * @brief Get HTTP method string (e.g., "GET", "POST").
   *
   * @param req Request context.
   * @return Method string (do not free).
   */
  extern const char *Socket_simple_http_server_request_method (
      SocketSimple_HTTPServerRequest_T req);

  /**
   * @brief Get request path (e.g., "/api/users").
   *
   * @param req Request context.
   * @return Path string (do not free).
   */
  extern const char *
  Socket_simple_http_server_request_path (SocketSimple_HTTPServerRequest_T req);

  /**
   * @brief Get query string (e.g., "id=123&name=foo").
   *
   * @param req Request context.
   * @return Query string (may be empty), or NULL if none.
   */
  extern const char *Socket_simple_http_server_request_query (
      SocketSimple_HTTPServerRequest_T req);

  /**
   * @brief Get request header value.
   *
   * @param req Request context.
   * @param name Header name (case-insensitive).
   * @return Header value (do not free), or NULL if not found.
   */
  extern const char *Socket_simple_http_server_request_header (
      SocketSimple_HTTPServerRequest_T req, const char *name);

  /**
   * @brief Get request body data.
   *
   * @param req Request context.
   * @param len Output: body length.
   * @return Body data pointer, or NULL if no body.
   */
  extern const void *
  Socket_simple_http_server_request_body (SocketSimple_HTTPServerRequest_T req,
                                          size_t *len);

  /**
   * @brief Get client IP address.
   *
   * @param req Request context.
   * @return Client IP string (do not free), or NULL.
   */
  extern const char *Socket_simple_http_server_request_client_addr (
      SocketSimple_HTTPServerRequest_T req);

  /**
   * @brief Check if request is HTTP/2.
   *
   * @param req Request context.
   * @return 1 if HTTP/2, 0 if HTTP/1.x.
   */
  extern int Socket_simple_http_server_request_is_http2 (
      SocketSimple_HTTPServerRequest_T req);

  /* ==========================================================================
   * Response Building
   * ==========================================================================
   */

  /**
   * @brief Set response HTTP status code.
   *
   * @param req Request context.
   * @param code HTTP status code (e.g., 200, 404, 500).
   */
  extern void Socket_simple_http_server_response_status (
      SocketSimple_HTTPServerRequest_T req, int code);

  /**
   * @brief Add response header.
   *
   * @param req Request context.
   * @param name Header name.
   * @param value Header value.
   */
  extern void Socket_simple_http_server_response_header (
      SocketSimple_HTTPServerRequest_T req,
      const char *name,
      const char *value);

  /**
   * @brief Set response body from data buffer.
   *
   * @param req Request context.
   * @param data Body data.
   * @param len Body length.
   */
  extern void
  Socket_simple_http_server_response_body (SocketSimple_HTTPServerRequest_T req,
                                           const void *data,
                                           size_t len);

  /**
   * @brief Set response body from null-terminated string.
   *
   * @param req Request context.
   * @param str Body string.
   */
  extern void Socket_simple_http_server_response_body_string (
      SocketSimple_HTTPServerRequest_T req, const char *str);

  /**
   * @brief Finalize and send the response.
   *
   * Must be called to complete the response.
   *
   * @param req Request context.
   */
  extern void Socket_simple_http_server_response_finish (
      SocketSimple_HTTPServerRequest_T req);

  /* ==========================================================================
   * JSON Convenience
   * ==========================================================================
   */

  /**
   * @brief Send JSON response.
   *
   * Sets Content-Type: application/json and sends response.
   *
   * @param req Request context.
   * @param status HTTP status code.
   * @param json JSON string.
   */
  extern void
  Socket_simple_http_server_response_json (SocketSimple_HTTPServerRequest_T req,
                                           int status,
                                           const char *json);

  /**
   * @brief Send error response with JSON body.
   *
   * @param req Request context.
   * @param status HTTP status code.
   * @param message Error message.
   */
  extern void Socket_simple_http_server_response_error (
      SocketSimple_HTTPServerRequest_T req, int status, const char *message);

  /* ==========================================================================
   * Streaming Responses
   * ==========================================================================
   */

  /**
   * @brief Begin streaming response.
   *
   * Sends headers with Transfer-Encoding: chunked.
   *
   * @param req Request context.
   * @return 0 on success, -1 on error.
   */
  extern int Socket_simple_http_server_response_begin_stream (
      SocketSimple_HTTPServerRequest_T req);

  /**
   * @brief Send response chunk.
   *
   * @param req Request context.
   * @param data Chunk data.
   * @param len Chunk length.
   * @return 0 on success, -1 on error.
   */
  extern int Socket_simple_http_server_response_send_chunk (
      SocketSimple_HTTPServerRequest_T req, const void *data, size_t len);

  /**
   * @brief End streaming response.
   *
   * @param req Request context.
   * @return 0 on success, -1 on error.
   */
  extern int Socket_simple_http_server_response_end_stream (
      SocketSimple_HTTPServerRequest_T req);

  /* ==========================================================================
   * Graceful Shutdown
   * ==========================================================================
   */

  /**
   * @brief Initiate graceful shutdown.
   *
   * @param server Server handle.
   * @param timeout_ms Drain timeout (-1 = infinite).
   * @return 0 on success, -1 on error.
   */
  extern int Socket_simple_http_server_drain (SocketSimple_HTTPServer_T server,
                                              int timeout_ms);

  /**
   * @brief Check drain progress (non-blocking).
   *
   * @param server Server handle.
   * @return >0 active connections, 0 drained, -1 timed out.
   */
  extern int
  Socket_simple_http_server_drain_poll (SocketSimple_HTTPServer_T server);

  /**
   * @brief Block until drain completes.
   *
   * @param server Server handle.
   * @param timeout_ms Additional timeout (-1 = use drain timeout).
   * @return 0 if drained gracefully, -1 if timed out.
   */
  extern int
  Socket_simple_http_server_drain_wait (SocketSimple_HTTPServer_T server,
                                        int timeout_ms);

  /**
   * @brief Set drain completion callback.
   *
   * @param server Server handle.
   * @param callback Drain callback.
   * @param userdata User data.
   */
  extern void Socket_simple_http_server_set_drain_callback (
      SocketSimple_HTTPServer_T server,
      SocketSimple_HTTPServerDrainCallback callback,
      void *userdata);

  /**
   * @brief Get current server state.
   *
   * @param server Server handle.
   * @return Server state enum.
   */
  extern SocketSimple_HTTPServerState
  Socket_simple_http_server_state (SocketSimple_HTTPServer_T server);

  /* ==========================================================================
   * Statistics
   * ==========================================================================
   */

  /**
   * @brief Get server statistics.
   *
   * @param server Server handle.
   * @param stats Output statistics structure.
   * @return 0 on success, -1 on error.
   */
  extern int
  Socket_simple_http_server_get_stats (SocketSimple_HTTPServer_T server,
                                       SocketSimple_HTTPServerStats *stats);

  /**
   * @brief Get current connection count.
   *
   * @param server Server handle.
   * @return Number of active connections, or -1 on error.
   */
  extern int
  Socket_simple_http_server_connection_count (SocketSimple_HTTPServer_T server);

#ifdef __cplusplus
}
#endif

#endif /* SOCKETSIMPLE_HTTP_SERVER_INCLUDED */
