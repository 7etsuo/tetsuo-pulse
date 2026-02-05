/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETSIMPLE_INTERNAL_H
#define SOCKETSIMPLE_INTERNAL_H

/**
 * @file SocketSimple-internal.h
 * @brief Internal shared definitions for Simple API implementation.
 */

#include "simple/SocketSimple.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Except.h"
#include "core/SocketError.h"
#include "core/SocketUtil.h"
#include "dns/SocketDNS.h"
#include "http/SocketHTTPClient.h"
#include "socket/Socket.h"
#include "socket/SocketDgram.h"
#include "socket/SocketWS.h"

#ifdef SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#include "tls/SocketTLSContext.h"
#endif

/* Forward declarations for cross-module access */
#include "http/SocketHTTPServer.h"

/* ============================================================================
 * Internal Handle Structures
 * ============================================================================
 */

/**
 * @brief Internal HTTP server request wrapper.
 *
 * Shared definition for use by WebSocket upgrade functionality.
 */
struct SocketSimple_HTTPServerRequest
{
  SocketHTTPServer_Request_T core_req;
};

struct SocketSimple_Socket
{
  Socket_T socket;     /* TCP socket (NULL for UDP) */
  SocketDgram_T dgram; /* UDP socket (NULL for TCP) */
#ifdef SOCKET_HAS_TLS
  SocketTLSContext_T tls_ctx;
#endif
  int is_tls;
  int is_server;
  int is_connected;
  int is_udp; /* Flag to distinguish TCP vs UDP */
};

struct SocketSimple_HTTP
{
  SocketHTTPClient_T client;
};

struct SocketSimple_WS
{
  SocketWS_T ws;
};

/* ============================================================================
 * Constants
 * ============================================================================
 */

/**
 * @brief Default backlog for listen() calls when user doesn't specify one.
 *
 * Used by Socket_simple_listen() and Socket_simple_listen_unix() when
 * backlog parameter is <= 0. Value of 128 is typical for most systems.
 */
#define SOCKET_SIMPLE_DEFAULT_BACKLOG 128

/**
 * @brief Default maximum WebSocket frame size (16MB).
 *
 * Used by Socket_simple_ws_server_config_init() to initialize the default
 * max_frame_size in SocketSimple_WSServerConfig.
 */
#define SOCKET_SIMPLE_WS_DEFAULT_MAX_FRAME_SIZE (16 * 1024 * 1024)

/**
 * @brief Default maximum WebSocket message size (64MB).
 *
 * Used by Socket_simple_ws_server_config_init() to initialize the default
 * max_message_size in SocketSimple_WSServerConfig.
 */
#define SOCKET_SIMPLE_WS_DEFAULT_MAX_MESSAGE_SIZE (64 * 1024 * 1024)

/* ============================================================================
 * Thread-Local Error State
 * ============================================================================
 */

typedef struct
{
  SocketSimple_ErrorCode code;
  int errno_value;
  char message[512];
} SimpleError;

extern __thread SimpleError simple_error;

/* ============================================================================
 * Error Helper Functions
 * ============================================================================
 */

void simple_set_error (SocketSimple_ErrorCode code, const char *msg);
void simple_set_error_errno (SocketSimple_ErrorCode code, const char *prefix);

/* ============================================================================
 * Handle Helper Functions
 * ============================================================================
 */

SocketSimple_Socket_T
simple_create_handle (Socket_T sock, int is_server, int is_tls);

SocketSimple_Socket_T simple_create_udp_handle (SocketDgram_T dgram);

/* ============================================================================
 * Cleanup Macros
 * ============================================================================
 */

#define SIMPLE_CLEANUP_SOCKET(sock_ptr)       \
  do                                          \
    {                                         \
      if ((sock_ptr) && *(sock_ptr))          \
        Socket_free ((Socket_T *)(sock_ptr)); \
    }                                         \
  while (0)

#define SIMPLE_CLEANUP_DGRAM(dgram_ptr)                  \
  do                                                     \
    {                                                    \
      if ((dgram_ptr) && *(dgram_ptr))                   \
        SocketDgram_free ((SocketDgram_T *)(dgram_ptr)); \
    }                                                    \
  while (0)

#ifdef SOCKET_HAS_TLS
#define SIMPLE_CLEANUP_TLS_CTX(ctx_ptr)                          \
  do                                                             \
    {                                                            \
      if ((ctx_ptr) && *(ctx_ptr))                               \
        SocketTLSContext_free ((SocketTLSContext_T *)(ctx_ptr)); \
    }                                                            \
  while (0)

#define SIMPLE_CLEANUP_TLS_CLIENT(client_ptr)     \
  do                                              \
    {                                             \
      if ((client_ptr) && *(client_ptr))          \
        {                                         \
          SocketTLS_disable (*(client_ptr));      \
          Socket_free ((Socket_T *)(client_ptr)); \
        }                                         \
    }                                             \
  while (0)
#endif

/* ============================================================================
 * Constants
 * ============================================================================
 */

/**
 * @brief Default timeout for Socket_simple_connect (milliseconds).
 */
#define SOCKET_SIMPLE_DEFAULT_TIMEOUT_MS 30000

#endif /* SOCKETSIMPLE_INTERNAL_H */
