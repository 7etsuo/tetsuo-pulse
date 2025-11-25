/**
 * SocketCommon-cache.c - Endpoint caching operations
 *
 * Implements endpoint address and port caching for socket operations.
 * Provides efficient storage and retrieval of resolved network endpoints
 * with proper memory management using Arena allocation.
 *
 * Features:
 * - Endpoint caching with address and port storage
 * - Deep copying of addrinfo structures
 * - Thread-safe cache operations
 * - Memory management using Arena allocation
 * - Efficient cache lookup and storage
 */

#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "core/Arena.h"
#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "socket/Socket.h"
#include "socket/SocketCommon-private.h"
#include "socket/SocketCommon.h"

#define T Socket_T

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION(SocketCommon);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(SocketCommon, e)

/* ==================== Endpoint Caching ==================== */

#undef T
