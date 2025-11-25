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

/* Thread-local exception for detailed error messages */
#ifdef _WIN32
static __declspec (thread) Except_T SocketCommon_DetailedException;
#else
static __thread Except_T SocketCommon_DetailedException;
#endif

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e)                                                 \
  do                                                                          \
    {                                                                         \
      SocketCommon_DetailedException = (e);                                   \
      SocketCommon_DetailedException.reason = socket_error_buf;              \
      RAISE (SocketCommon_DetailedException);                                \
    }                                                                         \
  while (0)

/* ==================== Endpoint Caching ==================== */

#undef T
