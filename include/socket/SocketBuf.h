#ifndef SOCKETBUF_INCLUDED
#define SOCKETBUF_INCLUDED

#include "core/Arena.h"
#include <stdbool.h>
#include <stddef.h>

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
 * @brief Release a buffer reference.
 * @ingroup core_io
 * @param buf Pointer to buffer (will be set to NULL).
 * @note Arena-based allocation means buffer memory persists until the arena is disposed.
 * @note Individual buffers cannot be freed separately.
 * @note This function invalidates the buffer pointer to prevent accidental access through stale pointers.
 * @note The buffer memory will be automatically freed when the arena is disposed.
 * @note This is the fundamental arena allocation pattern, not a limitation to work around.
 * @see SocketBuf_new() for buffer creation.
 * @see Arena_dispose() for arena cleanup.
 */
extern void SocketBuf_release (T *buf);

/**
 * @brief Write data to buffer.
 * @ingroup core_io
 * @param buf Buffer instance.
 * @param data Data to write.
 * @param len Length of data.
 * @return Bytes actually written (may be less if buffer fills).
 * @note Performance: O(n) where n is bytes written.
 * @see SocketBuf_read() for reading data.
 * @see SocketBuf_available() for checking available space.
 */
extern size_t SocketBuf_write (T buf, const void *data, size_t len);

/**
 * @brief Read and remove data from buffer.
 * @ingroup core_io
 * @param buf Buffer instance.
 * @param data Destination buffer.
 * @param len Maximum bytes to read.
 * @return Bytes actually read.
 * @note Performance: O(n) where n is bytes read.
 * @see SocketBuf_peek() for reading without removing.
 * @see SocketBuf_available() for checking available data.
 */
extern size_t SocketBuf_read (T buf, void *data, size_t len);

/**
 * @brief Read data without removing it.
 * @ingroup core_io
 * @param buf Buffer instance.
 * @param data Destination buffer.
 * @param len Maximum bytes to peek.
 * @return Bytes actually read.
 * @note Performance: O(n) where n is bytes peeked.
 * @see SocketBuf_read() for reading and removing data.
 * @see SocketBuf_available() for checking available data.
 */
extern size_t SocketBuf_peek (T buf, void *data, size_t len);

/**
 * @brief Remove data without reading.
 * @ingroup core_io
 * @param buf Buffer instance.
 * @param len Bytes to remove.
 * @note Asserts if len > available data.
 * @note Performance: O(1).
 * @see SocketBuf_read() for reading and removing data.
 * @see SocketBuf_available() for checking available data.
 */
extern void SocketBuf_consume (T buf, size_t len);

/**
 * @brief Get available data size.
 * @ingroup core_io
 * @param buf Buffer instance.
 * @return Bytes available for reading.
 * @note Performance: O(1).
 * @see SocketBuf_space() for write space.
 * @see SocketBuf_empty() for emptiness check.
 */
extern size_t SocketBuf_available (const T buf);

/**
 * @brief Get available space.
 * @ingroup core_io
 * @param buf Buffer instance.
 * @return Bytes available for writing.
 * @note Performance: O(1).
 * @see SocketBuf_available() for readable data.
 * @see SocketBuf_full() for fullness check.
 */
extern size_t SocketBuf_space (const T buf);

/**
 * @brief Check if buffer is empty.
 * @ingroup core_io
 * @param buf Buffer instance.
 * @return Non-zero if empty.
 * @note Performance: O(1).
 * @see SocketBuf_available() for available data count.
 * @see SocketBuf_full() for opposite check.
 */
extern int SocketBuf_empty (const T buf);

/**
 * @brief Check if buffer is full.
 * @ingroup core_io
 * @param buf Buffer instance.
 * @return Non-zero if full.
 * @note Performance: O(1).
 * @see SocketBuf_space() for available space count.
 * @see SocketBuf_empty() for opposite check.
 */
extern int SocketBuf_full (const T buf);

/**
 * @brief Clear all data.
 * @ingroup core_io
 * @param buf Buffer instance.
 * @note Resets buffer pointers without clearing memory contents.
 * @note Fast operation suitable for non-sensitive data.
 * @note For security-sensitive data, use SocketBuf_secureclear() instead.
 * @note Performance: O(1).
 * @see SocketBuf_secureclear() for secure clearing.
 * @see SocketBuf_write() for adding new data.
 */
extern void SocketBuf_clear (T buf);

/**
 * @brief Securely clear all data.
 * @ingroup core_io
 * @param buf Buffer instance.
 * @note Zeros memory contents before resetting buffer pointers.
 * @note Use this for buffers containing sensitive data (passwords, keys, etc.).
 * @note Performance: O(n) where n is buffer capacity.
 * @note Always use secureclear when removing connections that may have handled sensitive data to prevent information disclosure.
 * @see SocketBuf_clear() for fast non-secure clearing.
 * @see SocketBuf_write() for adding new sensitive data.
 */
extern void SocketBuf_secureclear (T buf);

/**
 * @brief Ensure minimum available space (dynamic resize).
 * @ingroup core_io
 * @param buf Buffer to resize.
 * @param min_space Minimum space needed after resize.
 * @throws SocketBuf_Failed on realloc fail or overflow.
 * @note Doubles capacity or sets to min_space, rebase circular data if needed.
 * @note Runtime invariants checked before/after.
 * @see SocketBuf_space() for checking current space.
 * @see SocketBuf_write() for operations that may trigger resizing.
 */
extern void SocketBuf_reserve (T buf, size_t min_space);

/**
 * @brief Runtime validation (no asserts).
 * @ingroup core_io
 * @param buf Buffer to check (read-only).
 * @return true if valid invariants hold.
 * @note Used for runtime security checks in production (rules preference).
 * @see SocketBuf_reserve() for operations that check invariants.
 */
extern bool SocketBuf_check_invariants (const T buf);

/**
 * @brief Get direct read pointer.
 * @ingroup core_io
 * @param buf Buffer instance.
 * @param len Output - contiguous bytes available.
 * @return Pointer to data or NULL if empty.
 * @note Performance: O(1).
 * @note For zero-copy reads. Data remains in buffer until consumed.
 * @see SocketBuf_read() for consuming data.
 * @see SocketBuf_consume() for removing data without reading.
 */
extern const void *SocketBuf_readptr (T buf, size_t *len);

/**
 * @brief Get direct write pointer.
 * @ingroup core_io
 * @param buf Buffer instance.
 * @param len Output - contiguous space available.
 * @return Pointer to write location or NULL if full.
 * @note Performance: O(1).
 * @note For zero-copy writes. Call SocketBuf_written() after writing.
 * @see SocketBuf_written() for committing written data.
 * @see SocketBuf_write() for regular writing.
 */
extern void *SocketBuf_writeptr (T buf, size_t *len);

/**
 * @brief Commit written data.
 * @ingroup core_io
 * @param buf Buffer instance.
 * @param len Bytes written to writeptr.
 * @note Asserts if len > space available.
 * @note Performance: O(1).
 * @see SocketBuf_writeptr() for getting the write pointer.
 * @see SocketBuf_write() for regular writing.
 */
extern void SocketBuf_written (T buf, size_t len);

#undef T
#endif
