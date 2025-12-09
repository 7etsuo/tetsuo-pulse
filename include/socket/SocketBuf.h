#ifndef SOCKETBUF_INCLUDED
#define SOCKETBUF_INCLUDED

#include "core/Arena.h"
#include <stddef.h>
#include <stdbool.h>

/**
 * @file SocketBuf.h
 * @ingroup core_io
 * @brief Circular buffer for efficient socket I/O operations.
 *
 * Provides efficient buffering for network I/O operations using a
 * circular buffer implementation. This minimizes memory copies and
 * provides O(1) operations for all buffer operations.
 *
 * Features:
 * - Zero-copy read/write operations where possible
 * - Thread-safe design (when used with proper synchronization)
 * - Automatic wraparound handling
 * - Memory managed by Arena allocator
 *
 * The buffer automatically handles wraparound, so users don't need
 * to worry about circular buffer complexities.
 *
 * @see SocketBuf_new() for buffer creation.
 * @see SocketBuf_write() and SocketBuf_read() for I/O operations.
 */

#include "core/Except.h"

#define T SocketBuf_T
typedef struct T *T;

/**
 * @brief Exception thrown on buffer operation failure.
 * @ingroup core_io
 * @see SocketBuf_new() for operations that may raise this.
 */
extern const Except_T SocketBuf_Failed;

/**
 * @brief Create a new circular buffer.
 * @ingroup core_io
 * @param arena Arena for memory allocation.
 * @param capacity Buffer capacity in bytes.
 * @return New buffer instance.
 * @throws SocketBuf_Failed if allocation fails.
 * @see Arena_T for arena-based memory management.
 * @see SocketBuf_release() for cleanup.
 */
extern T SocketBuf_new (Arena_T arena, size_t capacity);

/**
 * SocketBuf_release - Release a buffer reference
 * @buf: Pointer to buffer (will be set to NULL)
 * Arena-based allocation means buffer memory persists until the arena is
 * disposed - individual buffers cannot be freed separately. This function
 * invalidates the buffer pointer to prevent accidental access through stale
 * pointers.
 * The buffer memory will be automatically freed when the arena is disposed.
 * This is the fundamental arena allocation pattern, not a limitation to work
 * around.
 */
extern void SocketBuf_release (T *buf);

/**
 * SocketBuf_write - Write data to buffer
 * @buf: Buffer instance
 * @data: Data to write
 * @len: Length of data
 * Returns: Bytes actually written (may be less if buffer fills)
 * Performance: O(n) where n is bytes written
 */
extern size_t SocketBuf_write (T buf, const void *data, size_t len);

/**
 * SocketBuf_read - Read and remove data from buffer
 * @buf: Buffer instance
 * @data: Destination buffer
 * @len: Maximum bytes to read
 * Returns: Bytes actually read
 * Performance: O(n) where n is bytes read
 */
extern size_t SocketBuf_read (T buf, void *data, size_t len);

/**
 * SocketBuf_peek - Read data without removing it
 * @buf: Buffer instance
 * @data: Destination buffer
 * @len: Maximum bytes to peek
 * Returns: Bytes actually read
 * Performance: O(n) where n is bytes peeked
 */
extern size_t SocketBuf_peek (T buf, void *data, size_t len);

/**
 * SocketBuf_consume - Remove data without reading
 * @buf: Buffer instance
 * @len: Bytes to remove
 * Asserts if len > available data
 * Performance: O(1)
 */
extern void SocketBuf_consume (T buf, size_t len);

/**
 * SocketBuf_available - Get available data size
 * @buf: Buffer instance
 * Returns: Bytes available for reading
 * Performance: O(1)
 */
extern size_t SocketBuf_available (const T buf);

/**
 * SocketBuf_space - Get available space
 * @buf: Buffer instance
 * Returns: Bytes available for writing
 * Performance: O(1)
 */
extern size_t SocketBuf_space (const T buf);

/**
 * SocketBuf_empty - Check if buffer is empty
 * @buf: Buffer instance
 * Returns: Non-zero if empty
 */
extern int SocketBuf_empty (const T buf);

/**
 * SocketBuf_full - Check if buffer is full
 * @buf: Buffer instance
 * Returns: Non-zero if full
 */
extern int SocketBuf_full (const T buf);

/**
 * SocketBuf_clear - Clear all data
 * @buf: Buffer instance
 * Resets buffer pointers without clearing memory contents.
 * Fast operation suitable for non-sensitive data.
 * For security-sensitive data, use SocketBuf_secureclear() instead.
 * Performance: O(1)
 */
extern void SocketBuf_clear (T buf);

/**
 * SocketBuf_secureclear - Securely clear all data
 * @buf: Buffer instance
 * Zeros memory contents before resetting buffer pointers.
 * Use this for buffers containing sensitive data (passwords, keys, etc.)
 * Performance: O(n) where n is buffer capacity
 * Note: Always use secureclear when removing connections that may have
 * handled sensitive data to prevent information disclosure.
 */
extern void SocketBuf_secureclear (T buf);

/**
 * SocketBuf_reserve - Ensure minimum available space (dynamic resize)
 * @buf: Buffer to resize
 * @min_space: Minimum space needed after resize
 * Raises: SocketBuf_Failed on realloc fail or overflow
 * Doubles capacity or sets to min_space, rebase circular data if needed
 * Runtime invariants checked before/after
 */
extern void SocketBuf_reserve (T buf, size_t min_space);

/**
 * SocketBuf_check_invariants - Runtime validation (no asserts)
 * @buf: Buffer to check (read-only)
 * Returns: true if valid invariants hold
 * Used for runtime security checks in production (rules preference)
 */
extern bool SocketBuf_check_invariants (const T buf);

/**
 * SocketBuf_readptr - Get direct read pointer
 * @buf: Buffer instance
 * @len: Output - contiguous bytes available
 * Returns: Pointer to data or NULL if empty
 * Performance: O(1)
 * For zero-copy reads. Data remains in buffer until consumed.
 */
extern const void *SocketBuf_readptr (T buf, size_t *len);

/**
 * SocketBuf_writeptr - Get direct write pointer
 * @buf: Buffer instance
 * @len: Output - contiguous space available
 * Returns: Pointer to write location or NULL if full
 * Performance: O(1)
 * For zero-copy writes. Call SocketBuf_written() after writing.
 */
extern void *SocketBuf_writeptr (T buf, size_t *len);

/**
 * SocketBuf_written - Commit written data
 * @buf: Buffer instance
 * @len: Bytes written to writeptr
 * Asserts if len > space available
 * Performance: O(1)
 */
extern void SocketBuf_written (T buf, size_t len);

#undef T
#endif
