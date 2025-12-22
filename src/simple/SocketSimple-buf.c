/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketSimple-buf.c
 * @brief Circular buffer implementation for Simple API.
 */

#include "SocketSimple-internal.h"

#include "core/Arena.h"
#include "socket/SocketBuf.h"

/*============================================================================
 * Internal Buffer Handle Structure
 *============================================================================*/

struct SocketSimple_Buf
{
  Arena_T arena;
  SocketBuf_T buf;
  size_t initial_capacity;
};

/*============================================================================
 * Buffer Creation and Destruction
 *============================================================================*/

SocketSimple_Buf_T
Socket_simple_buf_new (size_t capacity)
{
  Socket_simple_clear_error ();

  if (capacity == 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Buffer capacity must be > 0");
      return NULL;
    }

  struct SocketSimple_Buf *handle = calloc (1, sizeof (*handle));
  if (!handle)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Memory allocation failed");
      return NULL;
    }

  TRY
  {
    handle->arena = Arena_new ();
    handle->buf = SocketBuf_new (handle->arena, capacity);
    handle->initial_capacity = capacity;
  }
  EXCEPT (Arena_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Arena allocation failed");
    free (handle);
    return NULL;
  }
  EXCEPT (SocketBuf_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Buffer allocation failed");
    if (handle->arena)
      Arena_dispose (&handle->arena);
    free (handle);
    return NULL;
  }
  END_TRY;

  return handle;
}

void
Socket_simple_buf_free (SocketSimple_Buf_T *buf)
{
  if (!buf || !*buf)
    return;

  struct SocketSimple_Buf *b = *buf;

  if (b->buf)
    {
      SocketBuf_release (&b->buf);
    }

  if (b->arena)
    {
      Arena_dispose (&b->arena);
    }

  free (b);
  *buf = NULL;
}

/*============================================================================
 * Write Operations
 *============================================================================*/

ssize_t
Socket_simple_buf_write (SocketSimple_Buf_T buf, const void *data, size_t len)
{
  volatile size_t written = 0;

  Socket_simple_clear_error ();

  if (!buf || !buf->buf)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid buffer");
      return -1;
    }

  if (!data && len > 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid data pointer");
      return -1;
    }

  if (len == 0)
    return 0;

  TRY { written = SocketBuf_write (buf->buf, data, len); }
  EXCEPT (SocketBuf_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_IO, "Buffer write failed");
    return -1;
  }
  END_TRY;

  return (ssize_t)written;
}

void *
Socket_simple_buf_writeptr (SocketSimple_Buf_T buf, size_t *len)
{
  Socket_simple_clear_error ();

  if (!buf || !buf->buf || !len)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return NULL;
    }

  return SocketBuf_writeptr (buf->buf, len);
}

int
Socket_simple_buf_commit (SocketSimple_Buf_T buf, size_t len)
{
  Socket_simple_clear_error ();

  if (!buf || !buf->buf)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid buffer");
      return -1;
    }

  TRY { SocketBuf_written (buf->buf, len); }
  EXCEPT (SocketBuf_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_IO, "Buffer commit failed");
    return -1;
  }
  END_TRY;

  return 0;
}

/*============================================================================
 * Read Operations
 *============================================================================*/

ssize_t
Socket_simple_buf_read (SocketSimple_Buf_T buf, void *data, size_t len)
{
  volatile size_t n = 0;

  Socket_simple_clear_error ();

  if (!buf || !buf->buf)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid buffer");
      return -1;
    }

  if (!data && len > 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid data pointer");
      return -1;
    }

  if (len == 0)
    return 0;

  TRY { n = SocketBuf_read (buf->buf, data, len); }
  EXCEPT (SocketBuf_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_IO, "Buffer read failed");
    return -1;
  }
  END_TRY;

  return (ssize_t)n;
}

ssize_t
Socket_simple_buf_peek (SocketSimple_Buf_T buf, void *data, size_t len)
{
  volatile size_t n = 0;

  Socket_simple_clear_error ();

  if (!buf || !buf->buf)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid buffer");
      return -1;
    }

  if (!data && len > 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid data pointer");
      return -1;
    }

  if (len == 0)
    return 0;

  TRY { n = SocketBuf_peek (buf->buf, data, len); }
  EXCEPT (SocketBuf_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_IO, "Buffer peek failed");
    return -1;
  }
  END_TRY;

  return (ssize_t)n;
}

const void *
Socket_simple_buf_readptr (SocketSimple_Buf_T buf, size_t *len)
{
  Socket_simple_clear_error ();

  if (!buf || !buf->buf || !len)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return NULL;
    }

  return SocketBuf_readptr (buf->buf, len);
}

int
Socket_simple_buf_consume (SocketSimple_Buf_T buf, size_t len)
{
  Socket_simple_clear_error ();

  if (!buf || !buf->buf)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid buffer");
      return -1;
    }

  if (len > SocketBuf_available (buf->buf))
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Cannot consume more than available");
      return -1;
    }

  TRY { SocketBuf_consume (buf->buf, len); }
  EXCEPT (SocketBuf_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_IO, "Buffer consume failed");
    return -1;
  }
  END_TRY;

  return 0;
}

ssize_t
Socket_simple_buf_readline (SocketSimple_Buf_T buf, char *line, size_t maxlen)
{
  volatile ssize_t n = 0;

  Socket_simple_clear_error ();

  if (!buf || !buf->buf)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid buffer");
      return -1;
    }

  if (!line || maxlen == 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid line buffer");
      return -1;
    }

  TRY { n = SocketBuf_readline (buf->buf, line, maxlen); }
  EXCEPT (SocketBuf_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_IO, "Buffer readline failed");
    return -1;
  }
  END_TRY;

  return n;
}

/*============================================================================
 * Buffer State Query
 *============================================================================*/

size_t
Socket_simple_buf_available (SocketSimple_Buf_T buf)
{
  if (!buf || !buf->buf)
    return 0;
  return SocketBuf_available (buf->buf);
}

size_t
Socket_simple_buf_space (SocketSimple_Buf_T buf)
{
  if (!buf || !buf->buf)
    return 0;
  return SocketBuf_space (buf->buf);
}

size_t
Socket_simple_buf_capacity (SocketSimple_Buf_T buf)
{
  if (!buf || !buf->buf)
    return 0;
  return SocketBuf_available (buf->buf) + SocketBuf_space (buf->buf);
}

int
Socket_simple_buf_empty (SocketSimple_Buf_T buf)
{
  if (!buf || !buf->buf)
    return 1;
  return SocketBuf_empty (buf->buf);
}

int
Socket_simple_buf_full (SocketSimple_Buf_T buf)
{
  if (!buf || !buf->buf)
    return 0;
  return SocketBuf_full (buf->buf);
}

/*============================================================================
 * Buffer Management
 *============================================================================*/

void
Socket_simple_buf_clear (SocketSimple_Buf_T buf)
{
  if (!buf || !buf->buf)
    return;

  TRY { SocketBuf_clear (buf->buf); }
  EXCEPT (SocketBuf_Failed)
  {
    /* Silently ignore errors on clear */
  }
  END_TRY;
}

void
Socket_simple_buf_clear_secure (SocketSimple_Buf_T buf)
{
  if (!buf || !buf->buf)
    return;

  TRY { SocketBuf_secureclear (buf->buf); }
  EXCEPT (SocketBuf_Failed)
  {
    /* Silently ignore errors on secure clear */
  }
  END_TRY;
}

int
Socket_simple_buf_reserve (SocketSimple_Buf_T buf, size_t min_space)
{
  Socket_simple_clear_error ();

  if (!buf || !buf->buf)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid buffer");
      return -1;
    }

  TRY { SocketBuf_reserve (buf->buf, min_space); }
  EXCEPT (SocketBuf_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Buffer reserve failed");
    return -1;
  }
  END_TRY;

  return 0;
}

int
Socket_simple_buf_compact (SocketSimple_Buf_T buf)
{
  Socket_simple_clear_error ();

  if (!buf || !buf->buf)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid buffer");
      return -1;
    }

  TRY { SocketBuf_compact (buf->buf); }
  EXCEPT (SocketBuf_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_IO, "Buffer compact failed");
    return -1;
  }
  END_TRY;

  return 0;
}

/*============================================================================
 * Search Operations
 *============================================================================*/

ssize_t
Socket_simple_buf_find (SocketSimple_Buf_T buf, const void *needle,
                         size_t needle_len)
{
  volatile ssize_t pos = -1;

  Socket_simple_clear_error ();

  if (!buf || !buf->buf)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid buffer");
      return -1;
    }

  if (!needle && needle_len > 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid needle");
      return -1;
    }

  TRY { pos = SocketBuf_find (buf->buf, needle, needle_len); }
  EXCEPT (SocketBuf_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_IO, "Buffer find failed");
    return -1;
  }
  END_TRY;

  return pos;
}

/*============================================================================
 * Scatter-Gather I/O
 *============================================================================*/

ssize_t
Socket_simple_buf_readv (SocketSimple_Buf_T buf, const struct iovec *iov,
                          int iovcnt)
{
  volatile ssize_t n = 0;

  Socket_simple_clear_error ();

  if (!buf || !buf->buf)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid buffer");
      return -1;
    }

  if (!iov && iovcnt > 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid iovec");
      return -1;
    }

  TRY { n = SocketBuf_readv (buf->buf, iov, iovcnt); }
  EXCEPT (SocketBuf_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_IO, "Buffer readv failed");
    return -1;
  }
  END_TRY;

  return n;
}

ssize_t
Socket_simple_buf_writev (SocketSimple_Buf_T buf, const struct iovec *iov,
                           int iovcnt)
{
  volatile ssize_t n = 0;

  Socket_simple_clear_error ();

  if (!buf || !buf->buf)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid buffer");
      return -1;
    }

  if (!iov && iovcnt > 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid iovec");
      return -1;
    }

  TRY { n = SocketBuf_writev (buf->buf, iov, iovcnt); }
  EXCEPT (SocketBuf_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_IO, "Buffer writev failed");
    return -1;
  }
  END_TRY;

  return n;
}
