/**
 * SocketBuf.c - Circular buffer for socket I/O
 */

#include <assert.h>
#include <stdbool.h>
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

const Except_T SocketBuf_Failed
    = { &SocketBuf_Failed, "SocketBuf operation failed" };

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION(SocketBuf);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(SocketBuf, e)

#define T SocketBuf_T

/* Minimum buffer capacity for practical network I/O
 * Matches SOCKET_MIN_BUFFER_SIZE from SocketConfig.h for consistency */

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

struct T
{
  char *data;
  size_t capacity;
  size_t head;
  size_t tail;
  size_t size;
  Arena_T arena;
};

/**
 * SocketBuf_check_invariants - Validate buffer invariants
 * @buf: Buffer to check
 *
 * Returns: true if all invariants hold, false otherwise
 * Thread-safe: No (caller must ensure exclusive access)
 */
bool
SocketBuf_check_invariants (T buf)
{
  if (!buf || !buf->data || buf->capacity == 0)
    return false;
  if (buf->size > buf->capacity)
    return false;
  if (buf->tail >= buf->capacity || buf->head >= buf->capacity)
    return false;
  return true;
}

/* SocketBuf_reserve is implemented in SocketBuf-reserve.c */

/**
 * new_validate_capacity - Validate capacity for new buffer
 * @capacity: Requested capacity
 *
 * Raises: SocketBuf_Failed if capacity exceeds SOCKETBUF_MAX_CAPACITY
 *
 * The maximum capacity limit prevents integer overflow in buffer
 * arithmetic operations. See SocketConfig-limits.h for details.
 */
static void
new_validate_capacity (size_t capacity)
{
  if (capacity > SOCKETBUF_MAX_CAPACITY)
    {
      SOCKET_ERROR_MSG ("SocketBuf_new: capacity exceeds SOCKETBUF_MAX_CAPACITY");
      RAISE_MODULE_ERROR (SocketBuf_Failed);
    }
}

/**
 * new_alloc_struct - Allocate buffer structure
 * @arena: Memory arena
 * Returns: Allocated buffer or raises on failure
 */
static T
new_alloc_struct (Arena_T arena)
{
  T buf = ALLOC (arena, sizeof (*buf));
  if (!buf)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Failed to ALLOC SocketBuf struct");
      RAISE_MODULE_ERROR (SocketBuf_Failed);
    }
  return buf;
}

/**
 * new_alloc_data - Allocate buffer data
 * @arena: Memory arena
 * @capacity: Buffer capacity
 * Returns: Allocated data or raises on failure
 */
static char *
new_alloc_data (Arena_T arena, size_t capacity)
{
  char *data = CALLOC (arena, capacity, 1);
  if (!data)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Failed to CALLOC SocketBuf data");
      RAISE_MODULE_ERROR (SocketBuf_Failed);
    }
  return data;
}

/**
 * SocketBuf_new - Create new circular buffer
 * @arena: Memory arena for allocations
 * @capacity: Buffer capacity in bytes
 * Returns: New buffer instance
 * Raises: SocketBuf_Failed on allocation failure or invalid capacity
 */
T
SocketBuf_new (Arena_T arena, size_t capacity)
{
  assert (arena);
  assert (capacity > 0);

  new_validate_capacity (capacity);

  T buf = new_alloc_struct (arena);
  buf->data = new_alloc_data (arena, capacity);
  buf->capacity = capacity;
  buf->head = 0;
  buf->tail = 0;
  buf->size = 0;
  buf->arena = arena;

  return buf;
}

void
SocketBuf_release (T *buf)
{
  assert (buf && *buf);
  *buf = NULL;
}

/**
 * circular_calc_chunk - Calculate chunk size for circular buffer transfer
 * @capacity: Buffer capacity
 * @pos: Current position in buffer
 * @remaining: Remaining bytes to transfer
 * Returns: Chunk size for this iteration
 */
static size_t
circular_calc_chunk (size_t capacity, size_t pos, size_t remaining)
{
  size_t chunk = capacity - pos;
  return chunk > remaining ? remaining : chunk;
}

/**
 * circular_copy_to_buffer - Copy data to circular buffer at position
 * @buf: Target buffer
 * @src: Source data
 * @pos: Position in buffer
 * @len: Length to copy
 */
static void
circular_copy_to_buffer (T buf, const char *src, size_t pos, size_t len)
{
  assert (pos + len <= buf->capacity);
  memcpy (buf->data + pos, src, len);
}

/**
 * SocketBuf_write - Write data to circular buffer
 * @buf: Buffer to write to
 * @data: Source data
 * @len: Maximum bytes to write
 * Returns: Bytes actually written
 */
size_t
SocketBuf_write (T buf, const void *data, size_t len)
{
  assert (buf && buf->data);
  assert (data || len == 0);
  SOCKETBUF_INVARIANTS (buf);

  size_t space = buf->capacity - buf->size;
  if (len > space)
    len = space;

  const char *src = data;
  size_t written = 0;

  while (written < len)
    {
      size_t chunk = circular_calc_chunk (buf->capacity, buf->tail,
                                          len - written);
      if (chunk == 0)
        break;
      circular_copy_to_buffer (buf, src + written, buf->tail, chunk);
      buf->tail = (buf->tail + chunk) % buf->capacity;
      written += chunk;
    }

  buf->size += written;
  SOCKETBUF_INVARIANTS (buf);
  return written;
}

/**
 * circular_copy_from_buffer - Copy data from circular buffer at position
 * @buf: Source buffer
 * @dst: Destination data
 * @pos: Position in buffer
 * @len: Length to copy
 */
static void
circular_copy_from_buffer (T buf, char *dst, size_t pos, size_t len)
{
  assert (pos + len <= buf->capacity);
  memcpy (dst, buf->data + pos, len);
}

/**
 * SocketBuf_read - Read data from circular buffer (destructive)
 * @buf: Buffer to read from
 * @data: Destination buffer
 * @len: Maximum bytes to read
 * Returns: Bytes actually read
 */
size_t
SocketBuf_read (T buf, void *data, size_t len)
{
  assert (buf && buf->data);
  assert (data || len == 0);
  SOCKETBUF_INVARIANTS (buf);

  if (len > buf->size)
    len = buf->size;

  char *dst = data;
  size_t bytes_read = 0;

  while (bytes_read < len)
    {
      size_t chunk = circular_calc_chunk (buf->capacity, buf->head,
                                          len - bytes_read);
      if (chunk == 0)
        break;
      circular_copy_from_buffer (buf, dst + bytes_read, buf->head, chunk);
      buf->head = (buf->head + chunk) % buf->capacity;
      bytes_read += chunk;
    }

  buf->size -= bytes_read;
  SOCKETBUF_INVARIANTS (buf);
  return bytes_read;
}

/**
 * SocketBuf_peek - Peek data from circular buffer (non-destructive)
 * @buf: Buffer to peek from
 * @data: Destination buffer
 * @len: Maximum bytes to peek
 * Returns: Bytes actually peeked
 */
size_t
SocketBuf_peek (T buf, void *data, size_t len)
{
  assert (buf && buf->data);
  assert (data || len == 0);
  SOCKETBUF_INVARIANTS (buf);

  if (len > buf->size)
    len = buf->size;

  char *dst = data;
  size_t head = buf->head;
  size_t bytes_peeked = 0;

  while (bytes_peeked < len)
    {
      size_t chunk = circular_calc_chunk (buf->capacity, head,
                                          len - bytes_peeked);
      if (chunk == 0)
        break;
      circular_copy_from_buffer (buf, dst + bytes_peeked, head, chunk);
      head = (head + chunk) % buf->capacity;
      bytes_peeked += chunk;
    }

  return bytes_peeked;
}

void
SocketBuf_consume (T buf, size_t len)
{
  assert (buf);
  SOCKETBUF_INVARIANTS (buf);
  assert (len <= buf->size);

  /* Prevent overflow in modulo operation */
  assert (len <= buf->capacity);
  assert (buf->head <= buf->capacity - 1);

  buf->head = (buf->head + len) % buf->capacity;
  buf->size -= len;

  SOCKETBUF_INVARIANTS (buf);
}

size_t
SocketBuf_available (const T buf)
{
  assert (buf);
  return buf->size;
}

size_t
SocketBuf_space (const T buf)
{
  assert (buf);
  return buf->capacity - buf->size;
}

int
SocketBuf_empty (const T buf)
{
  assert (buf);
  return buf->size == 0;
}

int
SocketBuf_full (const T buf)
{
  assert (buf);
  return buf->size == buf->capacity;
}

void
SocketBuf_clear (T buf)
{
  assert (buf);

  /* Fast clear - just reset pointers without zeroing memory */
  buf->head = 0;
  buf->tail = 0;
  buf->size = 0;
}

/**
 * secure_zero_memory - Zero memory with volatile to prevent optimization
 * @data: Memory to zero
 * @len: Length to zero
 */
static void
secure_zero_memory (char *data, size_t len)
{
  volatile char *vdata = (volatile char *)data;
  for (size_t i = 0; i < len; i++)
    vdata[i] = 0;
}

/**
 * SocketBuf_secureclear - Securely clear buffer (for sensitive data)
 * @buf: Buffer to clear
 *
 * Zeros memory contents before resetting pointers. Uses volatile
 * to prevent compiler optimization removal. Use for sensitive data
 * (passwords, keys, tokens).
 */
void
SocketBuf_secureclear (T buf)
{
  assert (buf && buf->data);

  /* buf->data and buf->capacity guaranteed by assert and invariants */
  secure_zero_memory (buf->data, buf->capacity);

  buf->head = 0;
  buf->tail = 0;
  buf->size = 0;
}


#undef T
