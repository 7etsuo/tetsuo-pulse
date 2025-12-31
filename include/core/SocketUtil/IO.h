/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETUTIL_IO_H
#define SOCKETUTIL_IO_H

/**
 * @file SocketUtil/IO.h
 * @ingroup foundation
 * @brief EINTR-safe I/O utilities for robust read/write operations.
 *
 * Provides I/O wrappers that automatically retry on EINTR (interrupted
 * system call), the standard pattern for signal-safe I/O operations.
 */

#include <errno.h>
#include <stddef.h>
#include <unistd.h>

/**
 * @brief Write all data to file descriptor with EINTR retry.
 * @ingroup foundation
 * @param fd File descriptor to write to.
 * @param buf Buffer to write from.
 * @param len Number of bytes to write.
 * @return 0 on success, -1 on error.
 * @threadsafe Yes (pure function, no shared state)
 *
 * Writes all requested bytes to the file descriptor, automatically retrying
 * on EINTR (interrupted system call). Partial writes are handled by advancing
 * the buffer pointer and reducing the remaining count.
 *
 * @note Does not handle SIGPIPE - caller should set SO_NOSIGPIPE or ignore
 * SIGPIPE.
 */
static inline int
socket_util_write_all_eintr (int fd, const void *buf, size_t len)
{
  const char *data = buf;
  size_t remaining = len;

  while (remaining > 0)
    {
      ssize_t n = write (fd, data, remaining);
      if (n <= 0)
        {
          if (n < 0 && errno == EINTR)
            continue;
          return -1;
        }
      data += n;
      remaining -= (size_t)n;
    }
  return 0;
}

/**
 * @brief Read all data from file descriptor with EINTR retry.
 * @ingroup foundation
 * @param fd File descriptor to read from.
 * @param buf Buffer to read into.
 * @param len Number of bytes to read.
 * @return 0 on success, -1 on error or EOF.
 * @threadsafe Yes (pure function, no shared state)
 *
 * Reads exactly the requested number of bytes from the file descriptor,
 * automatically retrying on EINTR (interrupted system call). Partial reads
 * are handled by advancing the buffer pointer and reducing the remaining
 * count.
 *
 * @note Returns -1 on EOF before len bytes are read (short read).
 */
static inline int
socket_util_read_all_eintr (int fd, void *buf, size_t len)
{
  char *data = buf;
  size_t remaining = len;

  while (remaining > 0)
    {
      ssize_t n = read (fd, data, remaining);
      if (n <= 0)
        {
          if (n < 0 && errno == EINTR)
            continue;
          return -1;
        }
      data += n;
      remaining -= (size_t)n;
    }
  return 0;
}

#endif /* SOCKETUTIL_IO_H */
