/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
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

SOCKET_DECLARE_MODULE_EXCEPTION (SocketBuf);

#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketBuf, e)
#define RAISE_MSG(e, fmt, ...)                                                \
  SOCKET_RAISE_MSG (SocketBuf, e, fmt, ##__VA_ARGS__)

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
  /* Async I/O support (optional) */
  struct SocketAsync_T *async;
  struct Socket_T *socket;
};


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


static T
new_alloc_struct (Arena_T arena)
{
  T buf = ALLOC (arena, sizeof (*buf));
  if (!buf)
    RAISE_MSG (SocketBuf_Failed,
               SOCKET_ENOMEM ": Failed to ALLOC SocketBuf struct");
  return buf;
}


static char *
new_alloc_data (Arena_T arena, size_t capacity)
{
  char *data = CALLOC (arena, capacity, 1);
  if (!data)
    RAISE_MSG (SocketBuf_Failed,
               SOCKET_ENOMEM ": Failed to CALLOC SocketBuf data");
  return data;
}


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
  buf->async = NULL;
  buf->socket = NULL;

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


static size_t
circular_calc_chunk (size_t capacity, size_t pos, size_t remaining)
{
  size_t chunk = capacity - pos;
  return chunk > remaining ? remaining : chunk;
}


static void
circular_copy_to_buffer (T buf, const char *src, size_t pos, size_t len)
{
  assert (pos + len <= buf->capacity);
  memcpy (buf->data + pos, src, len);
}


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


static void
circular_copy_from_buffer (const T buf, char *dst, size_t pos, size_t len)
{
  assert (pos + len <= buf->capacity);
  memcpy (dst, buf->data + pos, len);
}


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

/* Zeros memory contents before resetting pointers. Uses SocketCrypto
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

/* Note: Uses memmove instead of memcpy because arena allocation may place
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
      size_t first_part = old_cap - buf->head;

      if (first_part >= buf->size)
        {
          memmove (new_data, old_data + buf->head, buf->size);
        }
      else
        {
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

/* Memory note: This function allocates a new buffer from the arena and
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

  char *new_data = Arena_calloc (buf->arena, 1, new_cap, __FILE__, __LINE__);
  if (!new_data)
    RAISE_MSG (SocketBuf_Failed, SOCKET_ENOMEM ": Failed to calloc SocketBuf");

  reserve_migrate_data (buf, new_data, new_cap);
  SOCKETBUF_INVARIANTS (buf);
}

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

/* Uses the "three reversals" algorithm to rotate data in place:
 * 1. Reverse [head, capacity)
 * 2. Reverse [0, head)
 * 3. Reverse [0, size)
 *
 * This is O(n) and requires no additional memory.
 */
static void
compact_rotate_in_place (char *data, size_t capacity, size_t head, size_t size)
{
#define SWAP_BYTES(a, b)                                                      \
  do                                                                          \
    {                                                                         \
      char tmp = (a);                                                         \
      (a) = (b);                                                              \
      (b) = tmp;                                                              \
    }                                                                         \
  while (0)

  size_t first_part = capacity - head;
  size_t second_part = size - first_part;

  for (size_t i = 0; i < first_part / 2; i++)
    SWAP_BYTES (data[head + i], data[capacity - 1 - i]);

  for (size_t i = 0; i < second_part / 2; i++)
    SWAP_BYTES (data[i], data[second_part - 1 - i]);

  for (size_t i = 0; i < size / 2; i++)
    SWAP_BYTES (data[i], data[size - 1 - i]);

#undef SWAP_BYTES
}

void
SocketBuf_compact (T buf)
{
  VALIDATE_BUF (buf);

  if (buf->size == 0 || buf->head == 0)
    return;

  size_t first_part = buf->capacity - buf->head;

  if (first_part >= buf->size)
    {
      memmove (buf->data, buf->data + buf->head, buf->size);
    }
  else
    {
      size_t second_part = buf->size - first_part;

      if (first_part <= buf->head)
        {
          memmove (buf->data + first_part, buf->data, second_part);
          memmove (buf->data, buf->data + buf->head, first_part);
        }
      else
        {
          char *temp = Arena_alloc (buf->arena, buf->size, __FILE__, __LINE__);
          if (temp)
            {
              memmove (temp, buf->data + buf->head, first_part);
              memmove (temp + first_part, buf->data, second_part);
              memmove (buf->data, temp, buf->size);
            }
          else
            {
              compact_rotate_in_place (buf->data, buf->capacity, buf->head,
                                       buf->size);
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

  if (SocketBuf_space (buf) >= min_space)
    return 1;

  SocketBuf_compact (buf);

  if (SocketBuf_space (buf) >= min_space)
    return 1;

  TRY { SocketBuf_reserve (buf, min_space); }
  EXCEPT (SocketBuf_Failed) { return 0; }
  END_TRY;

  return 1;
}


static unsigned char
get_byte_at_offset (const T buf, size_t offset)
{
  return (unsigned char)buf->data[(buf->head + offset) % buf->capacity];
}


static int
match_pattern_at_offset (const T buf, size_t offset,
                         const unsigned char *pattern, size_t pattern_len)
{
  for (size_t j = 0; j < pattern_len; j++)
    {
      if (get_byte_at_offset (buf, offset + j) != pattern[j])
        return 0;
    }
  return 1;
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

  for (size_t i = 0; i < search_limit; i++)
    {
      if (match_pattern_at_offset (buf, i, pattern, needle_len))
        return (ssize_t)i;
    }

  return -1;
}


static size_t
readline_copy_and_strip (const char *src, size_t src_len, char *dst,
                         ssize_t newline_pos)
{
  size_t line_bytes;

  if (newline_pos >= 0)
    line_bytes = (size_t)newline_pos;
  else
    line_bytes = src_len;

  if (line_bytes > 0 && src[line_bytes - 1] == '\r')
    line_bytes--;

  memcpy (dst, src, line_bytes);
  dst[line_bytes] = '\0';

  return line_bytes;
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

  ssize_t nl_pos = SocketBuf_find (buf, "\n", 1);
  if (nl_pos < 0)
    return -1;

  size_t line_len = (size_t)nl_pos;

  if (line_len > max_len - 1)
    line_len = max_len - 1;

  size_t total_to_read = line_len + 1;
  if (total_to_read > max_len)
    total_to_read = max_len;

  char temp[SOCKETBUF_MAX_LINE_LENGTH + 1];
  if (total_to_read > SOCKETBUF_MAX_LINE_LENGTH)
    total_to_read = SOCKETBUF_MAX_LINE_LENGTH;

  size_t bytes_read = SocketBuf_read (buf, temp, total_to_read);

  char *nl_ptr = memchr (temp, '\n', bytes_read);
  ssize_t newline_offset = nl_ptr ? (nl_ptr - temp) : -1;

  size_t line_bytes
      = readline_copy_and_strip (temp, bytes_read, line, newline_offset);

  return (ssize_t)line_bytes;
}

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

      if (n < iov[i].iov_len)
        break;
    }

  return (ssize_t)total_written;
}

/* ============================================================================
 * Async I/O Operations
 * ============================================================================
 */

/* Undef T before including SocketAsync.h to avoid macro conflicts */
#undef T
#include "socket/SocketAsync.h"

void
SocketBuf_set_async (SocketBuf_T buf, SocketAsync_T async)
{
  VALIDATE_BUF (buf);
  buf->async = async;
}

SocketAsync_T
SocketBuf_get_async (const SocketBuf_T buf)
{
  VALIDATE_BUF_CONST (buf, NULL);
  return buf->async;
}

void
SocketBuf_set_socket (SocketBuf_T buf, Socket_T socket)
{
  VALIDATE_BUF (buf);
  buf->socket = socket;
}

Socket_T
SocketBuf_get_socket (const SocketBuf_T buf)
{
  VALIDATE_BUF_CONST (buf, NULL);
  return buf->socket;
}

int
SocketBuf_async_available (const SocketBuf_T buf)
{
  if (!buf || !buf->async)
    return 0;
  return SocketAsync_is_available (buf->async);
}

/**
 * Internal state for async callback bridging.
 * Bridges SocketAsync_Callback to SocketBuf_AsyncCallback.
 */
typedef struct AsyncBufState
{
  SocketBuf_T buf;
  SocketBuf_AsyncCallback user_cb;
  void *user_data;
  int is_fill; /* 1 = fill operation, 0 = flush operation */
} AsyncBufState;

/**
 * Internal callback that bridges SocketAsync completion to SocketBuf callback.
 */
static void
async_buf_callback (Socket_T socket, ssize_t bytes, int err, void *user_data)
{
  (void)socket; /* Unused - we have buf->socket */

  AsyncBufState *state = (AsyncBufState *)user_data;
  if (!state)
    return;

  SocketBuf_T buf = state->buf;
  SocketBuf_AsyncCallback cb = state->user_cb;
  void *ud = state->user_data;

  /* For fill operations, commit the received bytes to the buffer */
  if (state->is_fill && bytes > 0 && err == 0)
    {
      /* Commit received data by advancing tail */
      SocketBuf_written (buf, (size_t)bytes);
    }

  /* Invoke user callback */
  if (cb)
    cb (buf, bytes, err, ud);

  /* State was arena-allocated - no explicit free needed */
}

unsigned
SocketBuf_flush_async (SocketBuf_T buf, SocketBuf_AsyncCallback cb,
                       void *user_data, int flags)
{
  VALIDATE_BUF (buf);

  if (!buf->async)
    RAISE_MSG (SocketBuf_Failed,
               "SocketBuf_flush_async: async context not set");

  if (!buf->socket)
    RAISE_MSG (SocketBuf_Failed, "SocketBuf_flush_async: socket not set");

  if (!cb)
    RAISE_MSG (SocketBuf_Failed, "SocketBuf_flush_async: callback required");

  /* Get readable data from buffer */
  size_t avail;
  const void *data = SocketBuf_readptr (buf, &avail);

  if (!data || avail == 0)
    {
      /* Nothing to flush - invoke callback immediately with 0 bytes */
      cb (buf, 0, 0, user_data);
      return 0;
    }

  /* Allocate state for callback bridging */
  AsyncBufState *state = Arena_alloc (buf->arena, sizeof (*state), __FILE__,
                                      __LINE__);
  if (!state)
    RAISE_MSG (SocketBuf_Failed, SOCKET_ENOMEM ": Failed to allocate async state");

  state->buf = buf;
  state->user_cb = cb;
  state->user_data = user_data;
  state->is_fill = 0;

  /* Submit async send */
  unsigned req_id = SocketAsync_send (buf->async, buf->socket, data, avail,
                                      async_buf_callback, state,
                                      (SocketAsync_Flags)flags);

  return req_id;
}

unsigned
SocketBuf_fill_async (SocketBuf_T buf, size_t max_fill,
                      SocketBuf_AsyncCallback cb, void *user_data, int flags)
{
  VALIDATE_BUF (buf);

  if (!buf->async)
    RAISE_MSG (SocketBuf_Failed, "SocketBuf_fill_async: async context not set");

  if (!buf->socket)
    RAISE_MSG (SocketBuf_Failed, "SocketBuf_fill_async: socket not set");

  if (!cb)
    RAISE_MSG (SocketBuf_Failed, "SocketBuf_fill_async: callback required");

  /* Get writable space in buffer */
  size_t space;
  void *write_ptr = SocketBuf_writeptr (buf, &space);

  if (!write_ptr || space == 0)
    {
      /* No space to fill */
      SOCKET_LOG_DEBUG_MSG ("SocketBuf_fill_async: no write space available");
      return 0;
    }

  /* Limit to max_fill if specified */
  if (max_fill > 0 && max_fill < space)
    space = max_fill;

  /* Allocate state for callback bridging */
  AsyncBufState *state = Arena_alloc (buf->arena, sizeof (*state), __FILE__,
                                      __LINE__);
  if (!state)
    RAISE_MSG (SocketBuf_Failed, SOCKET_ENOMEM ": Failed to allocate async state");

  state->buf = buf;
  state->user_cb = cb;
  state->user_data = user_data;
  state->is_fill = 1;

  /* Submit async recv */
  unsigned req_id = SocketAsync_recv (buf->async, buf->socket, write_ptr, space,
                                      async_buf_callback, state,
                                      (SocketAsync_Flags)flags);

  return req_id;
}
