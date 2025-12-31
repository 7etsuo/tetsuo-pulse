/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETSIMPLE_BUF_INCLUDED
#define SOCKETSIMPLE_BUF_INCLUDED

/**
 * @file SocketSimple-buf.h
 * @brief Simple circular buffer API for socket I/O operations.
 *
 * Provides a return-code based wrapper around SocketBuf_T for efficient
 * buffering without exception handling. Useful for protocol parsing,
 * message framing, and zero-copy I/O operations.
 *
 * ## Quick Start
 *
 * ```c
 * #include <simple/SocketSimple.h>
 *
 * // Create a 4KB buffer
 * SocketSimple_Buf_T buf = Socket_simple_buf_new(4096);
 * if (!buf) {
 *     fprintf(stderr, "Error: %s\n", Socket_simple_error());
 *     return 1;
 * }
 *
 * // Write data
 * if (Socket_simple_buf_write(buf, "Hello", 5) != 5) {
 *     fprintf(stderr, "Write failed\n");
 * }
 *
 * // Read data
 * char data[64];
 * ssize_t n = Socket_simple_buf_read(buf, data, sizeof(data));
 *
 * // Clean up
 * Socket_simple_buf_free(&buf);
 * ```
 */

#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C"
{
#endif

  /*============================================================================
   * Opaque Handle Type
   *============================================================================*/

  /**
   * @brief Opaque circular buffer handle.
   */
  typedef struct SocketSimple_Buf *SocketSimple_Buf_T;

  /*============================================================================
   * Buffer Creation and Destruction
   *============================================================================*/

  /**
   * @brief Create a new circular buffer.
   *
   * @param capacity Initial buffer size in bytes (must be > 0).
   * @return Buffer handle on success, NULL on error.
   *
   * Example:
   * @code
   * SocketSimple_Buf_T buf = Socket_simple_buf_new(4096);
   * if (!buf) {
   *     fprintf(stderr, "Error: %s\n", Socket_simple_error());
   *     return 1;
   * }
   * @endcode
   */
  extern SocketSimple_Buf_T Socket_simple_buf_new (size_t capacity);

  /**
   * @brief Free a buffer and release resources.
   *
   * Sets *buf to NULL after freeing.
   *
   * @param buf Pointer to buffer handle.
   */
  extern void Socket_simple_buf_free (SocketSimple_Buf_T *buf);

  /*============================================================================
   * Write Operations
   *============================================================================*/

  /**
   * @brief Write data into the buffer.
   *
   * @param buf Buffer handle.
   * @param data Data to write.
   * @param len Number of bytes to write.
   * @return Number of bytes written (may be less than len if full), -1 on
   * error.
   */
  extern ssize_t Socket_simple_buf_write (SocketSimple_Buf_T buf,
                                          const void *data,
                                          size_t len);

  /**
   * @brief Get direct write pointer for zero-copy writes.
   *
   * After writing to the returned pointer, call Socket_simple_buf_commit()
   * to mark the bytes as written.
   *
   * @param buf Buffer handle.
   * @param len Output: maximum contiguous bytes available for writing.
   * @return Pointer to write location, or NULL if no space or error.
   *
   * Example:
   * @code
   * size_t avail;
   * void *ptr = Socket_simple_buf_writeptr(buf, &avail);
   * if (ptr) {
   *     ssize_t n = recv(fd, ptr, avail, 0);
   *     if (n > 0) Socket_simple_buf_commit(buf, n);
   * }
   * @endcode
   */
  extern void *Socket_simple_buf_writeptr (SocketSimple_Buf_T buf, size_t *len);

  /**
   * @brief Commit bytes written via direct write pointer.
   *
   * @param buf Buffer handle.
   * @param len Number of bytes written.
   * @return 0 on success, -1 on error.
   */
  extern int Socket_simple_buf_commit (SocketSimple_Buf_T buf, size_t len);

  /*============================================================================
   * Read Operations
   *============================================================================*/

  /**
   * @brief Read and remove data from the buffer.
   *
   * @param buf Buffer handle.
   * @param data Destination buffer.
   * @param len Maximum bytes to read.
   * @return Number of bytes read, 0 if empty, -1 on error.
   */
  extern ssize_t
  Socket_simple_buf_read (SocketSimple_Buf_T buf, void *data, size_t len);

  /**
   * @brief Peek at data without removing it.
   *
   * @param buf Buffer handle.
   * @param data Destination buffer.
   * @param len Maximum bytes to peek.
   * @return Number of bytes copied, 0 if empty, -1 on error.
   */
  extern ssize_t
  Socket_simple_buf_peek (SocketSimple_Buf_T buf, void *data, size_t len);

  /**
   * @brief Get direct read pointer for zero-copy reads.
   *
   * After consuming data, call Socket_simple_buf_consume() to remove it.
   *
   * @param buf Buffer handle.
   * @param len Output: contiguous bytes available for reading.
   * @return Pointer to readable data, or NULL if empty or error.
   *
   * Example:
   * @code
   * size_t avail;
   * const void *ptr = Socket_simple_buf_readptr(buf, &avail);
   * if (ptr) {
   *     ssize_t n = send(fd, ptr, avail, 0);
   *     if (n > 0) Socket_simple_buf_consume(buf, n);
   * }
   * @endcode
   */
  extern const void *
  Socket_simple_buf_readptr (SocketSimple_Buf_T buf, size_t *len);

  /**
   * @brief Discard data from the front of the buffer.
   *
   * @param buf Buffer handle.
   * @param len Number of bytes to discard.
   * @return 0 on success, -1 on error (e.g., len > available).
   */
  extern int Socket_simple_buf_consume (SocketSimple_Buf_T buf, size_t len);

  /**
   * @brief Read a line (up to and including newline).
   *
   * @param buf Buffer handle.
   * @param line Destination buffer.
   * @param maxlen Maximum bytes to read (including null terminator).
   * @return Line length (excluding null), or -1 if no newline found or error.
   */
  extern ssize_t Socket_simple_buf_readline (SocketSimple_Buf_T buf,
                                             char *line,
                                             size_t maxlen);

  /*============================================================================
   * Buffer State Query
   *============================================================================*/

  /**
   * @brief Get number of bytes available for reading.
   *
   * @param buf Buffer handle.
   * @return Bytes in buffer, or 0 if invalid/empty.
   */
  extern size_t Socket_simple_buf_available (SocketSimple_Buf_T buf);

  /**
   * @brief Get free space available for writing.
   *
   * @param buf Buffer handle.
   * @return Free space in bytes, or 0 if invalid/full.
   */
  extern size_t Socket_simple_buf_space (SocketSimple_Buf_T buf);

  /**
   * @brief Get total buffer capacity.
   *
   * @param buf Buffer handle.
   * @return Capacity in bytes, or 0 if invalid.
   */
  extern size_t Socket_simple_buf_capacity (SocketSimple_Buf_T buf);

  /**
   * @brief Check if buffer is empty.
   *
   * @param buf Buffer handle.
   * @return 1 if empty, 0 if not empty or invalid.
   */
  extern int Socket_simple_buf_empty (SocketSimple_Buf_T buf);

  /**
   * @brief Check if buffer is full.
   *
   * @param buf Buffer handle.
   * @return 1 if full, 0 if not full or invalid.
   */
  extern int Socket_simple_buf_full (SocketSimple_Buf_T buf);

  /*============================================================================
   * Buffer Management
   *============================================================================*/

  /**
   * @brief Clear the buffer (reset to empty).
   *
   * @param buf Buffer handle.
   */
  extern void Socket_simple_buf_clear (SocketSimple_Buf_T buf);

  /**
   * @brief Securely clear buffer contents (overwrites with zeros).
   *
   * Use for sensitive data (passwords, keys, etc.).
   *
   * @param buf Buffer handle.
   */
  extern void Socket_simple_buf_clear_secure (SocketSimple_Buf_T buf);

  /**
   * @brief Ensure minimum write space is available.
   *
   * May resize the buffer if necessary.
   *
   * @param buf Buffer handle.
   * @param min_space Required minimum free space.
   * @return 0 on success (space available), -1 on error.
   */
  extern int
  Socket_simple_buf_reserve (SocketSimple_Buf_T buf, size_t min_space);

  /**
   * @brief Compact buffer (move data to front).
   *
   * Maximizes contiguous write space.
   *
   * @param buf Buffer handle.
   * @return 0 on success, -1 on error.
   */
  extern int Socket_simple_buf_compact (SocketSimple_Buf_T buf);

  /*============================================================================
   * Search Operations
   *============================================================================*/

  /**
   * @brief Search for a byte sequence in the buffer.
   *
   * @param buf Buffer handle.
   * @param needle Sequence to find.
   * @param needle_len Length of needle.
   * @return Offset from start where needle found, or -1 if not found.
   *
   * Example:
   * @code
   * // Find HTTP header end
   * ssize_t pos = Socket_simple_buf_find(buf, "\r\n\r\n", 4);
   * if (pos >= 0) {
   *     // Headers end at pos + 4
   * }
   * @endcode
   */
  extern ssize_t Socket_simple_buf_find (SocketSimple_Buf_T buf,
                                         const void *needle,
                                         size_t needle_len);

  /*============================================================================
   * Scatter-Gather I/O
   *============================================================================*/

#include <sys/uio.h>

  /**
   * @brief Scatter read from buffer into multiple iovecs.
   *
   * @param buf Buffer handle.
   * @param iov Array of iovec structures.
   * @param iovcnt Number of iovec entries.
   * @return Total bytes read, -1 on error.
   */
  extern ssize_t Socket_simple_buf_readv (SocketSimple_Buf_T buf,
                                          const struct iovec *iov,
                                          int iovcnt);

  /**
   * @brief Gather write from multiple iovecs into buffer.
   *
   * @param buf Buffer handle.
   * @param iov Array of iovec structures.
   * @param iovcnt Number of iovec entries.
   * @return Total bytes written, -1 on error.
   */
  extern ssize_t Socket_simple_buf_writev (SocketSimple_Buf_T buf,
                                           const struct iovec *iov,
                                           int iovcnt);

#ifdef __cplusplus
}
#endif

#endif /* SOCKETSIMPLE_BUF_INCLUDED */
