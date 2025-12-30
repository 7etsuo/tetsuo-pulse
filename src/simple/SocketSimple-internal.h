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

SocketSimple_Socket_T simple_create_handle (Socket_T sock, int is_server,
                                            int is_tls);

SocketSimple_Socket_T simple_create_udp_handle (SocketDgram_T dgram);

/* ============================================================================
 * Constants
 * ============================================================================
 */

/**
 * @brief Default timeout for Socket_simple_connect (milliseconds).
 */
#define SOCKET_SIMPLE_DEFAULT_TIMEOUT_MS 30000

#endif /* SOCKETSIMPLE_INTERNAL_H */
