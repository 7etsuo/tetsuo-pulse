/**
 * SocketBuf.c - Circular buffer for socket I/O
 *
 * Implements a circular buffer for efficient socket I/O operations.
 *
 * Features:
 * - Circular buffer implementation
 * - Read/write/peek operations
 * - Dynamic buffer resizing
 * - Zero-copy pointer access
 * - Secure memory clearing
 */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "core/SocketCrypto.h"
#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"
#include "socket/SocketBuf.h"

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketBuf"

const Except_T SocketBuf_Failed
    = { &SocketBuf_Failed, "SocketBuf operation failed" };

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketBuf);

/* Module-local convenience macros for error handling */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketBuf, e)
#define RAISE_MSG(e, fmt, ...)                                                \
  SOCKET_RAISE_MSG (SocketBuf, e, fmt, ##__VA_ARGS__)

/* Validation macros for defensive programming */
#define VALIDATE_BUF(buf)                                                     \
  do                                                                          \
    {                                                                         \
      if (!buf)                                                               \
        RAISE_MODULE_ERROR (SocketBuf_Failed);                                \
      SOCKETBUF_INVARIANTS (buf);                                             \
    }                                                                         \
  while (0)

#define VALIDATE_BUF_CONST(buf, retval)                                       \
  do                                                                          \
    {                                                                         \
      if (!buf)                                                               \
        return (retval);                                                      \
      if (!SocketBuf_check_invariants (buf))                                  \
        return (retval);                                                      \
    }                                                                         \
  while (0)

#define T SocketBuf_T

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
 * @buf: Buffer to check (read-only)
 *
 * Returns: true if all invariants hold, false otherwise
 * Thread-safe: No (caller must ensure exclusive access)
 */
bool
SocketBuf_check_invariants (const T buf)
{
  if (!buf || !buf->data || buf->capacity == 0)
    return false;
  if (buf->size > buf->capacity)
    return false;
  if (buf->tail >= buf->capacity || buf->head >= buf->capacity)
    return false;
  return true;
}

/**
 * new_validate_capacity - Validate capacity for new buffer
 * @capacity: Requested capacity
 *
 * Raises: SocketBuf_Failed if capacity exceeds SOCKETBUF_MAX_CAPACITY
 */
static void
new_validate_capacity (size_t capacity)
{
  if (capacity == 0 || !SOCKET_VALID_BUFFER_SIZE (capacity)
      || !SOCKET_SECURITY_VALID_SIZE (capacity))
    RAISE_MSG (SocketBuf_Failed,
               "SocketBuf_new: invalid capacity (0 < size <= %u bytes and "
               "valid allocation)",
               SOCKET_MAX_BUFFER_SIZE);
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
    RAISE_MSG (SocketBuf_Failed,
               SOCKET_ENOMEM ": Failed to ALLOC SocketBuf struct");
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
    RAISE_MSG (SocketBuf_Failed,
               SOCKET_ENOMEM ": Failed to CALLOC SocketBuf data");
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
  if (!arena)
    RAISE_MODULE_ERROR (SocketBuf_Failed);

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
SocketBuf_release (T *bufp)
{
  if (!bufp)
    return;
  T buf = *bufp;
  if (!buf)
    return;
  *bufp = NULL;
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
  VALIDATE_BUF (buf);

  if (len > 0 && !data)
    RAISE_MSG (SocketBuf_Failed, "NULL data with positive length");

  size_t space = buf->capacity - buf->size;
  if (len > space)
    len = space;

  const char *src = data;
  size_t written = 0;

  while (written < len)
    {
      size_t chunk
          = circular_calc_chunk (buf->capacity, buf->tail, len - written);
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
 * @buf: Source buffer (read-only)
 * @dst: Destination data
 * @pos: Position in buffer
 * @len: Length to copy
 */
static void
circular_copy_from_buffer (const T buf, char *dst, size_t pos, size_t len)
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
  VALIDATE_BUF (buf);

  if (len > 0 && !data)
    RAISE_MSG (SocketBuf_Failed, "NULL data with positive length");

  if (len > buf->size)
    len = buf->size;

  char *dst = data;
  size_t bytes_read = 0;

  while (bytes_read < len)
    {
      size_t chunk
          = circular_calc_chunk (buf->capacity, buf->head, len - bytes_read);
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
  VALIDATE_BUF (buf);

  if (len > 0 && !data)
    RAISE_MSG (SocketBuf_Failed, "NULL data with positive length");

  if (len > buf->size)
    len = buf->size;

  char *dst = data;
  size_t head = buf->head;
  size_t bytes_peeked = 0;

  while (bytes_peeked < len)
    {
      size_t chunk
          = circular_calc_chunk (buf->capacity, head, len - bytes_peeked);
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
  VALIDATE_BUF (buf);

  if (len > buf->size)
    RAISE_MSG (SocketBuf_Failed, "consume len %zu exceeds available data %zu",
               len, buf->size);

  buf->head = (buf->head + len) % buf->capacity;
  buf->size -= len;

  SOCKETBUF_INVARIANTS (buf);
}

size_t
SocketBuf_available (const T buf)
{
  VALIDATE_BUF_CONST (buf, 0);
  return buf->size;
}

size_t
SocketBuf_space (const T buf)
{
  VALIDATE_BUF_CONST (buf, 0);
  return buf->capacity - buf->size;
}

int
SocketBuf_empty (const T buf)
{
  VALIDATE_BUF_CONST (buf, 1);
  return buf->size == 0;
}

int
SocketBuf_full (const T buf)
{
  VALIDATE_BUF_CONST (buf, 0);
  return buf->size == buf->capacity;
}

void
SocketBuf_clear (T buf)
{
  VALIDATE_BUF (buf);

  buf->head = 0;
  buf->tail = 0;
  buf->size = 0;
}

/**
 * SocketBuf_secureclear - Securely clear buffer (for sensitive data)
 * @buf: Buffer to clear
 *
 * Zeros memory contents before resetting pointers. Uses SocketCrypto
 * secure clear to prevent compiler optimization removal. Use for
 * sensitive data (passwords, keys, tokens).
 */
void
SocketBuf_secureclear (T buf)
{
  VALIDATE_BUF (buf);

  SocketCrypto_secure_clear (buf->data, buf->capacity);

  buf->head = 0;
  buf->tail = 0;
  buf->size = 0;
}

/* ==================== Reserve Operations ==================== */

/**
 * reserve_calc_new_capacity - Calculate new capacity for reserve
 * @current_cap: Current capacity
 * @total_needed: Total capacity needed (current size + min_space)
 *
 * Returns: New capacity or 0 on overflow/invalid
 * Thread-safe: Yes (pure function)
 */
static size_t
reserve_calc_new_capacity (size_t current_cap, size_t total_needed)
{
  if (!SOCKET_SECURITY_VALID_SIZE (total_needed)
      || !SOCKET_VALID_BUFFER_SIZE (total_needed))
    return 0;

  size_t doubled;
  if (current_cap == 0)
    {
      doubled = SOCKETBUF_INITIAL_CAPACITY;
    }
  else
    {
      if (SocketSecurity_check_multiply (current_cap, 2, &doubled) != 1)
        return 0;
    }

  size_t new_cap = (doubled > total_needed) ? doubled : total_needed;

  if (new_cap > SIZE_MAX - SOCKETBUF_ALLOC_OVERHEAD)
    return 0;

  return new_cap;
}

/**
 * reserve_migrate_data - Migrate data to new buffer and cleanup old
 * @buf: Buffer to update
 * @new_data: New buffer data pointer
 * @new_cap: New buffer capacity
 *
 * Thread-safe: No (modifies buffer)
 *
 * Note: Uses memmove instead of memcpy because arena allocation may place
 * new_data adjacent to old_data in the same chunk, causing memory regions
 * to overlap when old_data + head extends into new_data's region.
 *
 * Handles circular buffer wraparound: when head + size > capacity, data
 * wraps from end of buffer back to beginning, requiring two-part copy.
 */
static void
reserve_migrate_data (T buf, char *new_data, size_t new_cap)
{
  char *old_data = buf->data;
  size_t old_cap = buf->capacity;

  if (buf->size > 0)
    {
      /* Calculate contiguous bytes from head to end of buffer */
      size_t first_part = old_cap - buf->head;

      if (first_part >= buf->size)
        {
          /* No wrap - all data is contiguous from head */
          memmove (new_data, old_data + buf->head, buf->size);
        }
      else
        {
          /* Data wraps around - copy in two parts */
          memmove (new_data, old_data + buf->head, first_part);
          memmove (new_data + first_part, old_data, buf->size - first_part);
        }
    }

  if (old_data && old_cap > 0)
    SocketCrypto_secure_clear (old_data, old_cap);

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
 *
 * Memory note: This function allocates a new buffer from the arena and
 * abandons the old buffer. Since arenas don't support individual frees,
 * the old allocation remains until Arena_dispose(). This is acceptable
 * because:
 * - Buffer resizing is expected to be rare (exponential growth strategy)
 * - Arena disposal reclaims all allocations together
 * - Alternative (malloc/free) would complicate memory ownership
 *
 * For applications with frequent buffer resizing, consider using a larger
 * initial capacity or a dedicated arena per buffer.
 */
void
SocketBuf_reserve (T buf, size_t min_space)
{
  if (!buf)
    RAISE_MODULE_ERROR (SocketBuf_Failed);

  SOCKETBUF_INVARIANTS (buf);

  if (!SOCKET_SECURITY_VALID_SIZE (min_space))
    RAISE_MSG (SocketBuf_Failed,
               "min_space exceeds security allocation limit");

  size_t total_needed;
  if (SocketSecurity_check_add (buf->size, min_space, &total_needed) != 1)
    RAISE_MSG (SocketBuf_Failed,
               "Overflow calculating total capacity needed in reserve");

  if (total_needed <= buf->capacity)
    return;

  size_t new_cap = reserve_calc_new_capacity (buf->capacity, total_needed);
  if (new_cap == 0)
    RAISE_MSG (SocketBuf_Failed, "SocketBuf reserve: new capacity invalid "
                                 "(overflow or exceeds limits)");

  /* Arena allocation - old buffer remains allocated until arena disposal.
   * See function doc for rationale on this acceptable memory behavior. */
  char *new_data = Arena_calloc (buf->arena, 1, new_cap, __FILE__, __LINE__);
  if (!new_data)
    RAISE_MSG (SocketBuf_Failed, SOCKET_ENOMEM ": Failed to calloc SocketBuf");

  reserve_migrate_data (buf, new_data, new_cap);
  SOCKETBUF_INVARIANTS (buf);
}

/* ==================== Zero-Copy Pointer Access ==================== */

const void *
SocketBuf_readptr (T buf, size_t *len)
{
  if (!buf || !len)
    {
      if (len)
        *len = 0;
      return NULL;
    }

  if (!SocketBuf_check_invariants (buf))
    {
      *len = 0;
      return NULL;
    }

  if (buf->size == 0)
    {
      *len = 0;
      return NULL;
    }

  size_t contiguous = buf->capacity - buf->head;
  if (contiguous > buf->size)
    contiguous = buf->size;

  assert (contiguous > 0);
  assert (contiguous <= buf->capacity);
  assert (buf->head + contiguous <= buf->capacity);

  *len = contiguous;
  return buf->data + buf->head;
}

void *
SocketBuf_writeptr (T buf, size_t *len)
{
  if (!buf || !len)
    {
      if (len)
        *len = 0;
      return NULL;
    }

  if (!SocketBuf_check_invariants (buf))
    {
      *len = 0;
      return NULL;
    }

  size_t space = buf->capacity - buf->size;
  if (space == 0)
    {
      *len = 0;
      return NULL;
    }

  size_t contiguous = buf->capacity - buf->tail;
  if (contiguous > space)
    contiguous = space;

  assert (contiguous > 0);
  assert (contiguous <= buf->capacity);
  assert (buf->tail + contiguous <= buf->capacity);

  *len = contiguous;
  return buf->data + buf->tail;
}

void
SocketBuf_written (T buf, size_t len)
{
  VALIDATE_BUF (buf);

  if (len > buf->capacity - buf->size)
    RAISE_MSG (SocketBuf_Failed, "written len %zu exceeds available space %zu",
               len, buf->capacity - buf->size);

  buf->tail = (buf->tail + len) % buf->capacity;
  buf->size += len;

  SOCKETBUF_INVARIANTS (buf);
}

/* ==================== Buffer Management Operations ==================== */

void
SocketBuf_compact (T buf)
{
  VALIDATE_BUF (buf);

  /* Nothing to do if empty or already compacted */
  if (buf->size == 0 || buf->head == 0)
    return;

  /* Calculate contiguous bytes from head to end of buffer */
  size_t first_part = buf->capacity - buf->head;

  if (first_part >= buf->size)
    {
      /* No wrap - all data is contiguous, just memmove */
      memmove (buf->data, buf->data + buf->head, buf->size);
    }
  else
    {
      /* Data wraps around - need temporary or two-part move */
      /* Use a simple approach: copy wrapped part first */
      size_t second_part = buf->size - first_part;

      /* If there's room at the end, shift first part up temporarily */
      if (first_part <= buf->head)
        {
          /* Can move directly: second part fits before first moves */
          memmove (buf->data + first_part, buf->data, second_part);
          memmove (buf->data, buf->data + buf->head, first_part);
        }
      else
        {
          /* Need to be careful - use arena temp buffer */
          char *temp = Arena_alloc (buf->arena, buf->size, __FILE__, __LINE__);
          if (temp)
            {
              memcpy (temp, buf->data + buf->head, first_part);
              memcpy (temp + first_part, buf->data, second_part);
              memcpy (buf->data, temp, buf->size);
              /* Arena temp will be freed with arena */
            }
          else
            {
              /* Fall back to byte-by-byte rotation if no memory */
              for (size_t i = 0; i < buf->size; i++)
                {
                  buf->data[i]
                      = buf->data[(buf->head + i) % buf->capacity];
                }
            }
        }
    }

  buf->head = 0;
  buf->tail = buf->size;

  SOCKETBUF_INVARIANTS (buf);
}

int
SocketBuf_ensure (T buf, size_t min_space)
{
  VALIDATE_BUF (buf);

  /* Check if already have enough space */
  if (SocketBuf_space (buf) >= min_space)
    return 1;

  /* Try compacting first - might free up contiguous space */
  SocketBuf_compact (buf);

  /* Check again after compacting */
  if (SocketBuf_space (buf) >= min_space)
    return 1;

  /* Need to resize */
  TRY { SocketBuf_reserve (buf, min_space); }
  EXCEPT (SocketBuf_Failed) { return 0; }
  END_TRY;

  return 1;
}

/**
 * get_byte_at_offset - Get byte at offset from head (handles wraparound)
 * @buf: Buffer to read from
 * @offset: Offset from head
 * Returns: Byte value at offset
 */
static unsigned char
get_byte_at_offset (const T buf, size_t offset)
{
  return (unsigned char)buf->data[(buf->head + offset) % buf->capacity];
}

ssize_t
SocketBuf_find (T buf, const void *needle, size_t needle_len)
{
  if (!buf || !SocketBuf_check_invariants (buf))
    return -1;

  if (needle_len == 0)
    return 0;

  if (!needle)
    {
      SOCKET_ERROR_MSG ("NULL needle with positive length");
      RAISE_MODULE_ERROR (SocketBuf_Failed);
      return -1;
    }

  if (needle_len > buf->size)
    return -1;

  const unsigned char *pattern = needle;
  size_t search_limit = buf->size - needle_len + 1;

  /* Simple search - handles circular buffer transparently */
  for (size_t i = 0; i < search_limit; i++)
    {
      int found = 1;
      for (size_t j = 0; j < needle_len; j++)
        {
          if (get_byte_at_offset (buf, i + j) != pattern[j])
            {
              found = 0;
              break;
            }
        }
      if (found)
        return (ssize_t)i;
    }

  return -1;
}

ssize_t
SocketBuf_readline (T buf, char *line, size_t max_len)
{
  VALIDATE_BUF (buf);

  if (!line)
    {
      SOCKET_ERROR_MSG ("NULL line buffer");
      RAISE_MODULE_ERROR (SocketBuf_Failed);
      return -1;
    }

  if (max_len == 0)
    return -1;

  /* Search for newline */
  ssize_t newline_pos = SocketBuf_find (buf, "\n", 1);
  if (newline_pos < 0)
    return -1; /* No complete line yet */

  /* Calculate line length excluding newline */
  size_t line_len = (size_t)newline_pos;

  /* Limit to max_len - 1 (reserve space for null) */
  if (line_len > max_len - 1)
    line_len = max_len - 1;

  /* Read the line data (consumes from buffer) */
  size_t bytes_read = SocketBuf_read (buf, line, line_len);
  line[bytes_read] = '\0';

  /* Consume the newline if present */
  if (SocketBuf_available(buf) > 0) {
    char dummy;
    SocketBuf_read(buf, &dummy, 1); /* Consume the \n */
  }

  return (ssize_t)bytes_read;
}

/* ==================== Scatter-Gather I/O ==================== */

#include <sys/uio.h>

ssize_t
SocketBuf_readv (T buf, const struct iovec *iov, int iovcnt)
{
  VALIDATE_BUF (buf);

  if (iovcnt < 0)
    return -1;

  if (iovcnt == 0)
    return 0;

  if (!iov)
    {
      SOCKET_ERROR_MSG ("NULL iov with positive iovcnt");
      RAISE_MODULE_ERROR (SocketBuf_Failed);
      return -1;
    }

  size_t total_read = 0;

  for (int i = 0; i < iovcnt && buf->size > 0; i++)
    {
      if (iov[i].iov_base == NULL || iov[i].iov_len == 0)
        continue;

      size_t n = SocketBuf_read (buf, iov[i].iov_base, iov[i].iov_len);
      total_read += n;

      /* If we read less than requested, buffer is empty */
      if (n < iov[i].iov_len)
        break;
    }

  return (ssize_t)total_read;
}

ssize_t
SocketBuf_writev (T buf, const struct iovec *iov, int iovcnt)
{
  VALIDATE_BUF (buf);

  if (iovcnt < 0)
    return -1;

  if (iovcnt == 0)
    return 0;

  if (!iov)
    {
      SOCKET_ERROR_MSG ("NULL iov with positive iovcnt");
      RAISE_MODULE_ERROR (SocketBuf_Failed);
      return -1;
    }

  size_t total_written = 0;

  for (int i = 0; i < iovcnt && SocketBuf_space (buf) > 0; i++)
    {
      if (iov[i].iov_base == NULL || iov[i].iov_len == 0)
        continue;

      size_t n = SocketBuf_write (buf, iov[i].iov_base, iov[i].iov_len);
      total_written += n;

      /* If we wrote less than requested, buffer is full */
      if (n < iov[i].iov_len)
        break;
    }

  return (ssize_t)total_written;
}

#undef T
