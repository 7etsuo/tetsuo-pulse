/**
 * SocketBuf-ptr.c - Socket buffer pointer access functions
 *
 * Functions for zero-copy buffer access using direct pointers.
 */

#include <assert.h>

#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "core/Except.h"
#include "socket/SocketBuf.h"

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

/* Forward declaration for exception */
extern const Except_T SocketBuf_Failed;

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION(SocketBuf_Ptr);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(SocketBuf_Ptr, e)

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

const void *
SocketBuf_readptr (T buf, size_t *len)
{
  size_t contiguous;

  assert (buf);
  assert (len);
  assert (buf->data);
  SOCKETBUF_INVARIANTS (buf);

  if (buf->size == 0)
    {
      *len = 0;
      return NULL;
    }

  contiguous = buf->capacity - buf->head;
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
  size_t space;
  size_t contiguous;

  assert (buf);
  assert (len);
  assert (buf->data);
  SOCKETBUF_INVARIANTS (buf);

  space = buf->capacity - buf->size;
  if (space == 0)
    {
      *len = 0;
      return NULL;
    }

  contiguous = buf->capacity - buf->tail;
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
  assert (buf);
  SOCKETBUF_INVARIANTS (buf);

  /* Validate len fits in available space */
  assert (len <= buf->capacity - buf->size);

  /* Prevent overflow in modulo operation */
  assert (len <= buf->capacity);

  buf->tail = (buf->tail + len) % buf->capacity;
  buf->size += len;

  SOCKETBUF_INVARIANTS (buf);
}

#undef T
