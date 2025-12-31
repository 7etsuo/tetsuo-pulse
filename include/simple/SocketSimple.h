/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETSIMPLE_INCLUDED
#define SOCKETSIMPLE_INCLUDED

/**
 * @file SocketSimple.h
 * @brief Simple, return-code-based socket API.
 *
 * This header provides a convenience layer over the exception-based socket
 * library. All functions return error codes instead of raising exceptions,
 * making it easier to use for simple applications.
 *
 * ## Quick Start
 *
 * ```c
 * #include <simple/SocketSimple.h>
 *
 * // TCP client
 * SocketSimple_Socket_T sock = Socket_simple_connect("example.com", 80);
 * if (!sock) {
 *     fprintf(stderr, "Error: %s\n", Socket_simple_error());
 *     return 1;
 * }
 * Socket_simple_send(sock, "GET / HTTP/1.0\r\n\r\n", 18);
 * char buf[4096];
 * ssize_t n = Socket_simple_recv(sock, buf, sizeof(buf));
 * Socket_simple_close(&sock);
 *
 * // HTTP GET
 * SocketSimple_HTTPResponse resp;
 * if (Socket_simple_http_get("https://api.example.com/data", &resp) == 0) {
 *     printf("Status: %d\n", resp.status_code);
 *     Socket_simple_http_response_free(&resp);
 * }
 * ```
 *
 * ## Error Handling
 *
 * All functions return:
 * - NULL or -1 on error
 * - Valid pointer or >= 0 on success
 *
 * Use Socket_simple_error() to get human-readable error message.
 * Use Socket_simple_code() to get error code for programmatic handling.
 */

#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C"
{
#endif

  /*============================================================================
   * Error Codes
   *============================================================================*/

  /**
   * @brief Error codes returned by Socket_simple_code()
   */
  typedef enum
  {
    SOCKET_SIMPLE_OK = 0,

    /* Socket/Network errors */
    SOCKET_SIMPLE_ERR_SOCKET,  /**< General socket failure */
    SOCKET_SIMPLE_ERR_CONNECT, /**< Connection failed */
    SOCKET_SIMPLE_ERR_BIND,    /**< Bind failed */
    SOCKET_SIMPLE_ERR_LISTEN,  /**< Listen failed */
    SOCKET_SIMPLE_ERR_ACCEPT,  /**< Accept failed */
    SOCKET_SIMPLE_ERR_SEND,    /**< Send failed */
    SOCKET_SIMPLE_ERR_RECV,    /**< Receive failed */
    SOCKET_SIMPLE_ERR_CLOSED,  /**< Connection closed by peer */
    SOCKET_SIMPLE_ERR_TIMEOUT, /**< Operation timed out */

    /* DNS errors */
    SOCKET_SIMPLE_ERR_DNS, /**< DNS resolution failed */

    /* TLS errors */
    SOCKET_SIMPLE_ERR_TLS,           /**< General TLS error */
    SOCKET_SIMPLE_ERR_TLS_HANDSHAKE, /**< TLS handshake failed */
    SOCKET_SIMPLE_ERR_TLS_VERIFY,    /**< Certificate verification failed */

    /* HTTP errors */
    SOCKET_SIMPLE_ERR_HTTP,       /**< HTTP protocol error */
    SOCKET_SIMPLE_ERR_HTTP_PARSE, /**< HTTP response parse error */

    /* WebSocket errors */
    SOCKET_SIMPLE_ERR_WS,          /**< WebSocket error */
    SOCKET_SIMPLE_ERR_WS_PROTOCOL, /**< WebSocket protocol violation */
    SOCKET_SIMPLE_ERR_WS_CLOSED,   /**< WebSocket closed */

    /* Resource errors */
    SOCKET_SIMPLE_ERR_MEMORY,      /**< Memory allocation failed */
    SOCKET_SIMPLE_ERR_INVALID_ARG, /**< Invalid argument */
    SOCKET_SIMPLE_ERR_UNSUPPORTED, /**< Feature not supported */
    SOCKET_SIMPLE_ERR_IO,          /**< File I/O error */

    /* Pool/Poll errors */
    SOCKET_SIMPLE_ERR_POOL,          /**< Connection pool error */
    SOCKET_SIMPLE_ERR_POLL,          /**< Poll/event error */
    SOCKET_SIMPLE_ERR_POOL_FULL,     /**< Pool at capacity */
    SOCKET_SIMPLE_ERR_POOL_DRAINING, /**< Pool is draining */

    /* Proxy errors */
    SOCKET_SIMPLE_ERR_PROXY,        /**< Proxy connection failed */
    SOCKET_SIMPLE_ERR_PROXY_AUTH,   /**< Proxy authentication failed */
    SOCKET_SIMPLE_ERR_PROXY_DENIED, /**< Proxy denied connection */

    /* Server errors */
    SOCKET_SIMPLE_ERR_SERVER, /**< HTTP server error */

    /* Rate limiting */
    SOCKET_SIMPLE_ERR_RATELIMIT, /**< Rate limit exceeded */

    /* Security */
    SOCKET_SIMPLE_ERR_SECURITY, /**< Security/protection error */

    /* Async I/O */
    SOCKET_SIMPLE_ERR_ASYNC /**< Async I/O operation failed */
  } SocketSimple_ErrorCode;

  /*============================================================================
   * Error Access Functions
   *============================================================================*/

  /**
   * @brief Get human-readable error message for last error.
   * @return Thread-local error string, or NULL if no error.
   */
  extern const char *Socket_simple_error (void);

  /**
   * @brief Get preserved errno from last error.
   * @return errno value at time of error.
   */
  extern int Socket_simple_errno (void);

  /**
   * @brief Get error code for programmatic handling.
   * @return Error code enum value.
   */
  extern SocketSimple_ErrorCode Socket_simple_code (void);

  /**
   * @brief Check if last error is retryable.
   * @return 1 if retryable (EAGAIN, EINTR, etc.), 0 otherwise.
   */
  extern int Socket_simple_is_retryable (void);

  /**
   * @brief Clear error state.
   */
  extern void Socket_simple_clear_error (void);

/*============================================================================
 * Include Sub-modules
 *============================================================================*/

/* Core socket operations */
#include "SocketSimple-tcp.h"
#include "SocketSimple-tls.h"
#include "SocketSimple-dtls.h"
#include "SocketSimple-dns.h"

/* Higher-level protocols */
#include "SocketSimple-http.h"
#include "SocketSimple-ws.h"

/* Infrastructure */
#include "SocketSimple-pool.h"
#include "SocketSimple-poll.h"
#include "SocketSimple-timer.h"
#include "SocketSimple-proxy.h"
#include "SocketSimple-ratelimit.h"
#include "SocketSimple-buf.h"

/* Connection Management */
#include "SocketSimple-happyeyeballs.h"
#include "SocketSimple-reconnect.h"

/* Servers */
#include "SocketSimple-http-server.h"

/* Security */
#include "SocketSimple-security.h"

/* Async I/O */
#include "SocketSimple-async.h"

#ifdef __cplusplus
}
#endif

#endif /* SOCKETSIMPLE_INCLUDED */
