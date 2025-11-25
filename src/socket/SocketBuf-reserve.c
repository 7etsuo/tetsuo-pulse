/**
 * SocketBuf-reserve.c - Socket buffer reserve and resize operations
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * This file contains buffer reserve/resize functionality separated from
 * SocketBuf.c to keep files under 400 lines.
 *
 * Features:
 * - Dynamic buffer resizing
 * - Safe capacity calculation with overflow protection
 * - Data migration during resize
 * - Secure memory clearing on resize
 */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "socket/SocketBuf.h"

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketBuf"

/* Forward declaration for exception */
extern const Except_T SocketBuf_Failed;

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketBuf_Reserve);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketBuf_Reserve, e)

#define T SocketBuf_T

/* Define struct locally since it's opaque in header */
struct T
{
  char *data;
  size_t capacity;
  size_t head;
  size_t tail;
  size_t size;
  Arena_T arena;
};

/* Forward declaration for invariant check */
extern bool SocketBuf_check_invariants (T buf);

#define SOCKETBUF_INVARIANTS(buf)                                             \
  do                                                                          \
    {                                                                         \
      if (!SocketBuf_check_invariants (buf))                                  \
        {                                                                     \
          SOCKET_ERROR_MSG ("SocketBuf invariants violated");                 \
          RAISE_MODULE_ERROR (SocketBuf_Failed);                              \
        }                                                                     \
    }                                                                         \
  while (0)

/**
 * reserve_calc_new_capacity - Calculate new capacity for reserve
 * @current_cap: Current capacity
 * @min_space: Minimum space required
 *
 * Returns: New capacity or 0 on overflow
 * Thread-safe: Yes (pure function)
 *
 * Uses SOCKETBUF_INITIAL_CAPACITY for initial allocation when growing
 * from zero, otherwise doubles current capacity.
 */
static size_t
reserve_calc_new_capacity (size_t current_cap, size_t min_space)
{
  size_t new_cap = current_cap ? current_cap * 2 : SOCKETBUF_INITIAL_CAPACITY;
  if (new_cap < min_space || new_cap > SIZE_MAX - SOCKETBUF_ALLOC_OVERHEAD)
    return 0;
  return new_cap > min_space ? new_cap : min_space;
}

/**
 * reserve_migrate_data - Migrate data to new buffer and cleanup old
 * @buf: Buffer to update
 * @new_data: New buffer data pointer
 * @new_cap: New buffer capacity
 *
 * Thread-safe: No (modifies buffer)
 */
static void
reserve_migrate_data (T buf, char *new_data, size_t new_cap)
{
  char *old_data = buf->data;
  size_t old_cap = buf->capacity;

  if (buf->size > 0)
    memcpy (new_data, old_data + buf->head, buf->size);
  if (old_data && old_cap > 0)
    memset (old_data, 0, old_cap);

  buf->data = new_data;
  buf->capacity = new_cap;
  buf->head = 0;
  buf->tail = buf->size;
}

/**
 * SocketBuf_reserve - Resize buffer to ensure min_space available
 * @buf: Buffer to resize
 * @min_space: Minimum additional space required
 *
 * Raises: SocketBuf_Failed on overflow or allocation failure
 * Thread-safe: No (modifies buffer)
 */
void
SocketBuf_reserve (T buf, size_t min_space)
{
  if (buf->size + min_space <= buf->capacity)
    return;

  size_t new_cap = reserve_calc_new_capacity (buf->capacity, min_space);
  if (new_cap == 0)
    {
      SOCKET_ERROR_MSG ("SocketBuf reserve overflow");
      RAISE_MODULE_ERROR (SocketBuf_Failed);
    }

  char *new_data = Arena_calloc (buf->arena, 1, new_cap, __FILE__, __LINE__);
  if (!new_data)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Failed to calloc SocketBuf");
      RAISE_MODULE_ERROR (SocketBuf_Failed);
    }

  reserve_migrate_data (buf, new_data, new_cap);
  SOCKETBUF_INVARIANTS (buf);
}

#undef T

