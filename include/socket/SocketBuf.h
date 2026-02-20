/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETBUF_INCLUDED
#define SOCKETBUF_INCLUDED

#include "core/Arena.h"
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h> /* For ssize_t */

/**
 * @file SocketBuf.h
 * @ingroup core_io
 * @brief Circular buffer for efficient socket I/O operations.
 *
 * Provides efficient buffering for network I/O operations using a
 * circular buffer implementation. This minimizes memory copies and
 * provides O(1) operations for most buffer operations (O(n) for data copies).
 *
 * Features:
 * - Zero-copy read/write pointers for integration with system calls like
 * send/recv
 * - Dynamic resizing with SocketBuf_reserve()
 * - Secure clearing for sensitive data (e.g., keys, credentials)
 * - Thread-conditional safety with external synchronization
 * - Automatic wraparound handling - no manual offset management needed
 * - Arena-based memory management for efficient allocation/deallocation
 *
 * ## Basic Usage
 *
 * @code{.c}
 * #include "socket/SocketBuf.h"
 * #include "core/Arena.h"
 * #include <string.h>
 * #include <assert.h>
 *
 * Arena_T arena = Arena_new();
 * TRY {
 *     SocketBuf_T buf = SocketBuf_new(arena, 4096);
 *
 *     // Write data
 *     const char *msg = "Hello, SocketBuf!";
 *     size_t written = SocketBuf_write(buf, msg, strlen(msg));
 *     assert(written == strlen(msg));
 *     assert(SocketBuf_available(buf) == strlen(msg));
 *
 *     // Read data (copy)
 *     char readbuf[1024] = {0};
 *     size_t read_len = SocketBuf_read(buf, readbuf, sizeof(readbuf));
 *     assert(read_len == strlen(msg));
 *     assert(strcmp(readbuf, msg) == 0);
 *
 *     // Zero-copy read for transmission
 *     size_t len;
 *     const void *data_ptr = SocketBuf_readptr(buf, &len);
 *     if (data_ptr) {
 *         // e.g., send(socket, data_ptr, len, 0);
 *         SocketBuf_consume(buf, len);  // Remove after use
 *     }
 *
 *     SocketBuf_release(&buf);
 * } EXCEPT(SocketBuf_Failed) {
 *     // Handle errors: allocation failure, invalid ops
 *     fprintf(stderr, "Buffer error: %s\n", Except_message(Except_stack));
 * } FINALLY {
 *     // Release already called in TRY
 * } END_TRY;
 * Arena_dispose(&arena);
 * @endcode
 *
 * ## Security Considerations
 *
 * For buffers holding sensitive data (e.g., TLS keys, passwords):
 *
 * @code{.c}
 * // Before reuse or disposal
 * SocketBuf_secureclear(buf);  // Overwrites with zeros
 *
 * // Or clear non-sensitive
 * SocketBuf_clear(buf);  // Faster, but leaves remnants
 * @endcode
 *
 * @note Integrate with SocketPool_T for per-connection buffers in servers.
 * @warning Never retain pointers from readptr/writeptr across mutating calls.
 * @complexity Most ops O(1); data ops O(n) where n=bytes transferred.
 *
 * @see SocketBuf_new() for creation.
 * @see SocketBuf_write() / SocketBuf_read() for basic I/O.
 * @see Socket_readptr() / Socket_writeptr() for zero-copy patterns.
 * @see @ref connection_mgmt::SocketPool_T "SocketPool_T" for pool usage.
 * @see docs/ASYNC_IO.md for advanced I/O integration.
 */

#include "core/Except.h"

#define T SocketBuf_T
/**
 * @brief Opaque handle to a circular buffer instance.
 * @ingroup core_io
 *
 * This type represents a circular buffer used for efficient buffering in
 * socket I/O operations. It supports zero-copy read/write, dynamic resizing,
 * and secure clearing for sensitive data.
 *
 * Memory is managed via an associated Arena_T, allowing batch deallocation.
 * The buffer automatically handles wraparound logic internally.
 *
 * @threadsafe Conditional - individual operations are atomic, but concurrent
 * access requires external synchronization for multi-threaded use.
 *
 * @see SocketBuf_new() to create an instance.
 * @see SocketBuf_release() to release the handle (sets pointer to NULL).
 * @see @ref foundation::Arena_T "Arena_T" for memory management.
 * @see SocketPool_T in @ref connection_mgmt for pool-integrated buffers.
 * @see SocketHTTP1_Parser_T in @ref http for HTTP parsing usage.
 */
typedef struct T *T;

/**
 * @brief Exception indicating failure in buffer operations such as allocation
 * or resize errors.
 * @ingroup core_io
 *
 * Raised when internal buffer operations fail due to memory exhaustion,
 * invalid parameters, or other runtime errors.
 *
 * @see SocketBuf_new() for allocation failure cases.
 * @see SocketBuf_reserve() for resize failure cases.
 * @see @ref foundation::Except_T "Except_T" for exception handling framework.
 * @see docs/ERROR_HANDLING.md for TRY/EXCEPT usage patterns.
 */
extern const Except_T SocketBuf_Failed;

/**
 * @brief Initial capacity for dynamic buffer growth when current capacity is 0.
 * @ingroup core_io
 *
 * This constant defines the default initial capacity used by the buffer
 * reserve logic when growing from zero capacity. Set to 4096 bytes (4KB)
 * for efficient initial allocation without excessive memory waste.
 *
 * @see reserve_calc_new_capacity() in SocketBuf.c
 */
#define SOCKETBUF_INITIAL_CAPACITY 4096

/**
 * @brief Create a new circular buffer with specified initial capacity.
 * @ingroup core_io
 *
 * Allocates and initializes a circular buffer instance using the provided
 * arena. The buffer starts empty with the given capacity. Capacity can grow
 * dynamically via SocketBuf_reserve() if needed.
 *
 * @param[in] arena Arena for all buffer memory allocations (must not be NULL).
 * @param[in] capacity Initial buffer size in bytes (must be > 0; power-of-2
 * recommended for alignment).
 *
 * @return Newly created buffer instance.
 *
 * @throws SocketBuf_Failed If arena allocation fails (ENOMEM), capacity <= 0,
 * or arena NULL.
 *
 * @threadsafe Yes - safe to call from any thread; returns independent
 * instance.
 *
 * @complexity O(1) - single allocation via arena; O(capacity) for initial
 * zeroing if implemented.
 *
 * ## Basic Usage
 *
 * @code{.c}
 * Arena_T arena = Arena_new();
 * SocketBuf_T buf = NULL;
 * TRY {
 *     buf = SocketBuf_new(arena, 4096);  // 4KB buffer
 *     // Use buf...
 * } EXCEPT(SocketBuf_Failed) {
 *     // Allocation failed - handle error
 *     fprintf(stderr, "Failed to create buffer: %s\n",
 * Except_message(Except_stack));
 *     // buf remains NULL
 * } FINALLY {
 *     if (buf) SocketBuf_release(&buf);
 * } END_TRY;
 * Arena_dispose(&arena);
 * @endcode
 *
 * ## In Connection Pools
 *
 * Buffers are commonly created per-connection in SocketPool_T:
 *
 * @code{.c}
 * Connection_T conn = SocketPool_add(pool, socket);
 * SocketBuf_T inbuf = Connection_inbuf(conn);  // Pool-managed buffer
 * @endcode
 *
 * @note Buffer lifecycle tied to arena - dispose arena to free all buffers at
 * once.
 * @warning Capacity=0 or very small may lead to frequent resizes; choose
 * appropriately.
 * @see SocketBuf_reserve() for dynamic growth.
 * @see SocketBuf_release() for handle invalidation (not memory free).
 * @see Arena_new() / Arena_dispose() in @ref foundation for arena lifecycle.
 * @see @ref connection_mgmt::SocketPool_T "SocketPool_T" for integrated usage.
 */
extern T SocketBuf_new (Arena_T arena, size_t capacity);

/**
 * @brief Release the buffer handle and invalidate the pointer.
 * @ingroup core_io
 * @param buf Pointer to the buffer handle (set to NULL on success).
 *
 * This function nullifies the buffer pointer but does not free the underlying
 * memory, as it is managed by the arena. It prevents use-after-free or
 * dangling pointer issues.
 *
 * @note Arena-managed memory persists until Arena_dispose() or Arena_clear().
 * @note No exception thrown; idempotent if *buf is already NULL.
 * @threadsafe Yes - safe to call concurrently if no overlapping access to
 * *buf.
 *
 * @see SocketBuf_new() for buffer creation.
 * @see Arena_dispose() in @ref foundation for full memory cleanup.
 * @see @ref foundation "Foundation" group for memory management principles.
 */
extern void SocketBuf_release (T *buf);

/**
 * @brief Write data into the buffer.
 * @ingroup core_io
 * @param buf The target buffer.
 * @param data Pointer to data to append.
 * @param len Number of bytes to write.
 * @return Number of bytes successfully written (<= len); 0 if full.
 * @throws SocketBuf_Failed if buffer is invalid or data is NULL with len > 0.
 * @note Writes as much as possible; partial writes possible if space limited.
 * @note Handles internal wraparound transparently.
 * @note Performance: O(n) time where n = bytes written, due to potential
 * memcpy.
 * @threadsafe No - concurrent writes may corrupt buffer; use locks externally.
 *
 * @see SocketBuf_space() to check available write space before writing.
 * @see SocketBuf_writeptr() for zero-copy alternative.
 * @see SocketBuf_read() for symmetric read operation.
 * @see SocketBuf_full() to check if buffer is full.
 */
extern size_t SocketBuf_write (T buf, const void *data, size_t len);

/**
 * @brief Read and remove data from the buffer.
 * @ingroup core_io
 * @param buf The source buffer.
 * @param data Destination buffer for read data.
 * @param len Maximum bytes to read into data.
 * @return Number of bytes read and removed (<= len); 0 if empty.
 * @throws SocketBuf_Failed if buffer is invalid or data is NULL with len > 0.
 * @note Partial reads possible if less data available.
 * @note Data is removed from buffer after successful read.
 * @note Performance: O(n) time where n = bytes read.
 * @threadsafe No - concurrent reads/writes require external synchronization.
 *
 * @see SocketBuf_peek() for non-destructive read.
 * @see SocketBuf_readptr() for zero-copy read access.
 * @see SocketBuf_consume() to remove data without copying.
 * @see SocketBuf_available() to check readable bytes.
 * @see SocketBuf_empty() to check if no data available.
 */
extern size_t SocketBuf_read (T buf, void *data, size_t len);

/**
 * @brief Peek at data without removing it from the buffer.
 * @ingroup core_io
 * @param buf The source buffer.
 * @param data Destination for peeked data.
 * @param len Maximum bytes to peek.
 * @return Number of bytes copied to data (<= len); 0 if empty.
 * @throws SocketBuf_Failed if buffer is invalid or data is NULL with len > 0.
 * @note Non-destructive: data remains available for subsequent reads.
 * @note Useful for protocol parsing without consuming stream.
 * @note Performance: O(n) time where n = bytes peeked.
 * @threadsafe Conditional - safe if no concurrent modifications.
 *
 * @see SocketBuf_read() for consuming data after peeking.
 * @see SocketBuf_readptr() for zero-copy peeking.
 * @see SocketBuf_available() to query readable data length.
 */
extern size_t SocketBuf_peek (T buf, void *data, size_t len);

/**
 * @brief Discard data from the front of the buffer without reading it.
 * @ingroup core_io
 * @param buf The buffer to modify.
 * @param len Number of bytes to discard.
 * @throws SocketBuf_Failed if buffer is invalid or len > available data.
 * @note Behavior undefined (assert in debug) if len >
 * SocketBuf_available(buf).
 * @note Efficient for skipping known-length headers or invalid data.
 * @note Performance: O(1) - only updates internal pointers.
 * @threadsafe No - modifies shared state; requires locking for concurrency.
 *
 * @see SocketBuf_available() to verify sufficient data before consuming.
 * @see SocketBuf_read() for read-and-discard operation.
 * @see SocketBuf_clear() for discarding all data.
 */
extern void SocketBuf_consume (T buf, size_t len);

/**
 * @brief Query the number of bytes available for reading.
 * @ingroup core_io
 * @param buf The buffer to query.
 * @return Number of bytes currently stored in the buffer (0 if empty).
 * @note Constant time query; no side effects.
 * @note Performance: O(1).
 * @threadsafe Yes - read-only query, safe concurrently.
 *
 * @see SocketBuf_space() for available write space.
 * @see SocketBuf_empty() for boolean emptiness check.
 * @see SocketBuf_read() or SocketBuf_peek() to access data.
 */
extern size_t SocketBuf_available (const T buf);

/**
 * @brief Query the number of bytes available for writing.
 * @ingroup core_io
 * @param buf The buffer to query.
 * @return Free space in bytes (capacity - available data; 0 if full).
 * @note Constant time; no modification to buffer state.
 * @note Performance: O(1).
 * @threadsafe Yes - read-only, concurrent safe.
 *
 * @see SocketBuf_available() for symmetric read query.
 * @see SocketBuf_full() for boolean full check.
 * @see SocketBuf_write() to add data if space > 0.
 * @see SocketBuf_reserve() to ensure minimum space.
 */
extern size_t SocketBuf_space (const T buf);

/**
 * @brief Check if the buffer contains no data.
 * @ingroup core_io
 * @param buf The buffer to check.
 * @return Non-zero (true) if empty, zero (false) otherwise.
 * @note Equivalent to SocketBuf_available(buf) == 0.
 * @note Performance: O(1).
 * @threadsafe Yes - read-only query.
 *
 * @see SocketBuf_available() for exact count.
 * @see SocketBuf_full() for full buffer check.
 * @see SocketBuf_clear() to make buffer empty.
 */
extern int SocketBuf_empty (const T buf);

/**
 * @brief Check if the buffer has no space for writing.
 * @ingroup core_io
 * @param buf The buffer to check.
 * @return Non-zero (true) if full, zero (false) otherwise.
 * @note Equivalent to SocketBuf_space(buf) == 0.
 * @note Performance: O(1).
 * @threadsafe Yes - read-only.
 *
 * @see SocketBuf_space() for exact free space.
 * @see SocketBuf_empty() for empty check.
 * @see SocketBuf_reserve() to expand capacity if full.
 */
extern int SocketBuf_full (const T buf);

/**
 * @brief Reset buffer to empty state without zeroing memory.
 * @ingroup core_io
 * @param buf The buffer to clear.
 * @throws SocketBuf_Failed if buffer is invalid.
 * @note Only updates read/write pointers; memory contents may remain until
 * overwritten.
 * @warning Not suitable for sensitive data - use SocketBuf_secureclear() to
 * prevent leakage.
 * @note Performance: O(1) - no memory operations.
 * @threadsafe No - modifies buffer state.
 *
 * @see SocketBuf_secureclear() for zeroing sensitive data.
 * @see SocketBuf_consume() for partial discard.
 * @see SocketBuf_write() to repopulate after clear.
 * @see @ref security for security best practices with buffers.
 */
extern void SocketBuf_clear (T buf);

/**
 * @brief Securely erase all data by zeroing memory contents.
 * @ingroup core_io
 * @param buf The buffer containing potentially sensitive data.
 * @throws SocketBuf_Failed if buffer is invalid.
 * @note Overwrites entire buffer capacity with zeros before resetting
 * pointers.
 * @note Essential for cryptographic keys, credentials, or PII to mitigate
 * timing attacks or memory dumps.
 * @warning Performance: O(n) where n = current capacity; slower than clear().
 * @threadsafe No - writes to shared memory; lock before use in multi-thread.
 *
 * @see SocketBuf_clear() for non-secure fast reset.
 * @see @ref security "Security Module" for TLS/crypto integration.
 * @see SocketPool_T in @ref connection_mgmt for connection buffer secure
 * cleanup.
 * @see SocketTLS_send() in @ref security for secure I/O patterns.
 */
extern void SocketBuf_secureclear (T buf);

/**
 * @brief Dynamically resize buffer to ensure at least min_space available.
 * @ingroup core_io
 * @param buf The buffer to potentially resize.
 * @param min_space Required minimum free space after operation.
 * @throws SocketBuf_Failed if reallocation fails or arithmetic overflow
 * occurs.
 * @note Strategy: doubles capacity or sets to max(current, min_space); copies
 * data.
 * @note May trigger on write if space insufficient (configurable?).
 * @note Validates internal invariants post-resize.
 * @threadsafe No - concurrent resize undefined; serialize access.
 *
 * @see SocketBuf_space() to check current space without resize.
 * @see SocketBuf_new() specify initial capacity to avoid frequent resizes.
 * @see @ref foundation::Arena_T "Arena" for underlying memory source.
 */
extern void SocketBuf_reserve (T buf, size_t min_space);

/**
 * @brief Validate internal buffer consistency without assertions.
 * @ingroup core_io
 * @param buf The buffer to validate (const, read-only access).
 * @return true if all invariants hold (e.g., pointers valid, no overflow),
 * false otherwise.
 * @note Intended for debugging, fuzzing, or production integrity checks.
 * @note Does not modify buffer; suitable for periodic health checks.
 * @note Performance: O(1) typically, may scan in debug modes.
 * @threadsafe Yes - const inspection only.
 *
 * @see SocketBuf_reserve() which internally validates invariants.
 * @see @ref utilities "Utilities" for metrics and monitoring integration.
 */
extern bool SocketBuf_check_invariants (const T buf);

/**
 * @brief Obtain a direct pointer to readable data for zero-copy access.
 * @ingroup core_io
 * @param buf The buffer.
 * @param len Output parameter: number of contiguous bytes available at
 * *return.
 * @return Pointer to start of readable data, or NULL if buffer empty.
 *            The pointed data is valid until next write/consume operation.
 * @note Guarantees contiguous block; may be less than available() due to
 * wraparound.
 * @note Caller must not retain pointer across mutating calls (write, consume,
 * etc.).
 * @note Performance: O(1).
 * @threadsafe Conditional - pointer invalidates on concurrent mutation.
 *
 * @see SocketBuf_consume() to advance past the read data.
 * @see SocketBuf_read() for copying alternative.
 * @see SocketBuf_peek() for size-limited copy-based peek.
 * @see send() system call for zero-copy socket transmission.
 */
extern const void *SocketBuf_readptr (T buf, size_t *len);

/**
 * @brief Obtain a direct pointer for zero-copy writing into the buffer.
 * @ingroup core_io
 * @param buf The buffer.
 * @param len Output: maximum contiguous bytes that can be written at *return.
 * @return Pointer to write location, or NULL if no space available.
 * @note After writing up to *len bytes, call SocketBuf_written(actual_len).
 * @note May return less than space() due to wraparound; buffer handles it.
 * @note Pointer invalid after any other buffer operation.
 * @note Performance: O(1).
 * @threadsafe No - concurrent writes corrupt buffer.
 *
 * @see SocketBuf_written() to commit the written bytes.
 * @see SocketBuf_write() for safe copying alternative.
 * @see recv() system call integration for zero-copy receive.
 */
extern void *SocketBuf_writeptr (T buf, size_t *len);

/**
 * @brief Commit bytes written via direct write pointer.
 * @ingroup core_io
 * @param buf The buffer where data was written.
 * @param len Exact number of bytes written at the pointer from writeptr().
 * @throws SocketBuf_Failed if buffer is invalid or len > available space.
 * @note Must match or be <= the len from corresponding SocketBuf_writeptr()
 * call.
 * @note Behavior undefined (assert in debug) if len exceeds available space.
 * @note Updates internal write position and available space.
 * @note Performance: O(1).
 * @threadsafe No - must be called by same thread/lock holder as writeptr().
 *
 * @see SocketBuf_writeptr() to obtain write location and space.
 * @see SocketBuf_write() for alternative non-zero-copy write.
 * @see @ref core_io "Core I/O" for zero-copy patterns with sockets.
 */
extern void SocketBuf_written (T buf, size_t len);

/**
 * @brief Move data to front of buffer, maximizing contiguous write space.
 * @ingroup core_io
 * @param buf The buffer to compact.
 *
 * Moves all readable data to the beginning of the buffer (head=0).
 * This maximizes contiguous write space for zero-copy operations.
 * Useful before large writes or when writeptr() returns less than space().
 *
 * @throws SocketBuf_Failed if buffer is invalid.
 * @note Performance: O(n) where n = bytes in buffer (memmove).
 * @note No-op if buffer is empty or already compacted.
 * @threadsafe No - modifies buffer internals.
 *
 * ## Example
 *
 * @code{.c}
 * size_t space;
 * void *ptr = SocketBuf_writeptr(buf, &space);
 * if (space < needed) {
 *     SocketBuf_compact(buf);  // Make space contiguous
 *     ptr = SocketBuf_writeptr(buf, &space);
 * }
 * @endcode
 *
 * @see SocketBuf_writeptr() for zero-copy writes.
 * @see SocketBuf_space() to check total available space.
 */
extern void SocketBuf_compact (T buf);

/**
 * @brief Ensure minimum write space is available, resizing if necessary.
 * @ingroup core_io
 * @param buf The buffer to ensure space in.
 * @param min_space Minimum required write space in bytes.
 * @return 1 if space is available, 0 on failure.
 *
 * Combines compact and reserve operations. First attempts to compact
 * (move data to front), then resizes if still insufficient.
 *
 * @throws SocketBuf_Failed if resize fails.
 * @note Performance: O(n) for compact or resize, O(1) if already sufficient.
 * @threadsafe No - may modify buffer.
 *
 * ## Example
 *
 * @code{.c}
 * if (SocketBuf_ensure(buf, 1024)) {
 *     // Guaranteed at least 1024 bytes of write space
 *     SocketBuf_write(buf, data, 1024);
 * }
 * @endcode
 *
 * @see SocketBuf_reserve() for resize without compact.
 * @see SocketBuf_compact() for compact without resize.
 * @see SocketBuf_space() to check current space.
 */
extern int SocketBuf_ensure (T buf, size_t min_space);

/**
 * @brief Search for a byte sequence in the buffer.
 * @ingroup core_io
 * @param buf The buffer to search.
 * @param needle Pointer to byte sequence to find.
 * @param needle_len Length of needle in bytes.
 * @return Offset from head where needle starts, or -1 if not found.
 *
 * Searches the readable portion of the buffer for the needle sequence.
 * Handles circular buffer wraparound transparently.
 *
 * @throws SocketBuf_Failed if buffer invalid or needle NULL with len > 0.
 * @note Performance: O(n*m) worst case (n=buffer size, m=needle length).
 * @note Empty needle (len=0) returns 0.
 * @threadsafe Conditional - safe if buffer not mutated during search.
 *
 * ## Example
 *
 * @code{.c}
 * // Find end of HTTP headers
 * ssize_t pos = SocketBuf_find(buf, "\r\n\r\n", 4);
 * if (pos >= 0) {
 *     size_t header_len = pos + 4;
 *     char headers[8192];
 *     SocketBuf_read(buf, headers, header_len);
 * }
 * @endcode
 *
 * @see SocketBuf_readline() for line-oriented reading.
 * @see SocketBuf_peek() to examine data without searching.
 */
extern ssize_t SocketBuf_find (T buf, const void *needle, size_t needle_len);

/**
 * @brief Read a line (up to and including newline) from the buffer.
 * @ingroup core_io
 * @param buf The buffer to read from.
 * @param line Destination buffer for the line.
 * @param max_len Maximum bytes to read (including null terminator).
 * @return Number of bytes read (excluding null), or -1 if no newline found.
 *
 * Reads up to and including the first newline ('\n') or until max_len-1.
 * The output is null-terminated. Handles both LF and CRLF line endings.
 * Does NOT consume data if no complete line found (returns -1).
 *
 * @throws SocketBuf_Failed if buffer invalid or line NULL.
 * @note Performance: O(n) where n = line length.
 * @note Returns -1 if no '\n' found in available data.
 * @threadsafe No - reads and consumes data.
 *
 * ## Example
 *
 * @code{.c}
 * char line[256];
 * ssize_t len;
 * while ((len = SocketBuf_readline(buf, line, sizeof(line))) > 0) {
 *     printf("Line: %s", line);  // line includes '\n'
 * }
 * @endcode
 *
 * @see SocketBuf_find() for searching without reading.
 * @see SocketBuf_read() for length-based reading.
 */
extern ssize_t SocketBuf_readline (T buf, char *line, size_t max_len);

#include <sys/uio.h>

/**
 * @brief Scatter read from buffer into multiple iovecs.
 * @ingroup core_io
 * @param buf The buffer to read from.
 * @param iov Array of iovec structures to scatter data into.
 * @param iovcnt Number of iovec entries.
 * @return Total bytes read, or -1 on error.
 *
 * Reads data from the buffer and scatters it across multiple memory regions.
 * Consumes data from buffer after successful read. Handles wraparound.
 *
 * @throws SocketBuf_Failed if buffer invalid or iov NULL with iovcnt > 0.
 * @note Performance: O(n) where n = total bytes read.
 * @note Partial fills possible if buffer has less data than iov capacity.
 * @threadsafe No - modifies buffer state.
 *
 * ## Example
 *
 * @code{.c}
 * struct header hdr;
 * char body[1024];
 * struct iovec iov[2] = {
 *     {.iov_base = &hdr, .iov_len = sizeof(hdr)},
 *     {.iov_base = body, .iov_len = sizeof(body)}
 * };
 * ssize_t n = SocketBuf_readv(buf, iov, 2);
 * @endcode
 *
 * @see SocketBuf_writev() for gather write.
 * @see SocketBuf_read() for single-buffer read.
 * @see readv(2) system call for analogous operation.
 */
extern ssize_t SocketBuf_readv (T buf, const struct iovec *iov, int iovcnt);

/**
 * @brief Gather write from multiple iovecs into buffer.
 * @ingroup core_io
 * @param buf The buffer to write to.
 * @param iov Array of iovec structures containing data to gather.
 * @param iovcnt Number of iovec entries.
 * @return Total bytes written, or -1 on error.
 *
 * Gathers data from multiple memory regions and writes into the buffer.
 * Handles circular buffer wraparound transparently.
 *
 * @throws SocketBuf_Failed if buffer invalid or iov NULL with iovcnt > 0.
 * @note Performance: O(n) where n = total bytes written.
 * @note Partial writes possible if buffer space insufficient.
 * @threadsafe No - modifies buffer state.
 *
 * ## Example
 *
 * @code{.c}
 * struct header hdr = {...};
 * char body[] = "Hello, World!";
 * struct iovec iov[2] = {
 *     {.iov_base = &hdr, .iov_len = sizeof(hdr)},
 *     {.iov_base = body, .iov_len = strlen(body)}
 * };
 * ssize_t n = SocketBuf_writev(buf, iov, 2);
 * @endcode
 *
 * @see SocketBuf_readv() for scatter read.
 * @see SocketBuf_write() for single-buffer write.
 * @see writev(2) system call for analogous operation.
 */
extern ssize_t SocketBuf_writev (T buf, const struct iovec *iov, int iovcnt);

/* Forward declarations for async types - use actual struct names */
#ifndef SOCKET_INCLUDED
struct Socket_T;
typedef struct Socket_T *Socket_T;
#endif

#ifndef SOCKETASYNC_INCLUDED
struct SocketAsync_T;
typedef struct SocketAsync_T *SocketAsync_T;
#endif

/**
 * @brief Callback invoked when async buffer I/O operation completes.
 * @ingroup core_io
 *
 * This callback is invoked from the event loop context when an async
 * flush or fill operation completes.
 *
 * @param[in] buf The buffer that completed the operation.
 * @param[in] bytes Number of bytes transferred (>0 success, 0 EOF, <0 error).
 * @param[in] err 0 on success, errno value on failure.
 * @param[in] user_data User-provided context from the original call.
 *
 * @threadsafe Invoked serially from event loop thread.
 */
typedef void (*SocketBuf_AsyncCallback) (T buf,
                                         ssize_t bytes,
                                         int err,
                                         void *user_data);

/**
 * @brief Associate an async I/O context with this buffer.
 * @ingroup core_io
 * @param[in] buf The buffer to configure.
 * @param[in] async The async context (may be NULL to disable async).
 *
 * Required before using SocketBuf_flush_async() or SocketBuf_fill_async().
 * The async context must outlive the buffer.
 *
 * @throws SocketBuf_Failed if buffer is invalid.
 * @threadsafe No - configure before concurrent use.
 *
 * @see SocketBuf_get_async() to query current context.
 * @see SocketAsync_new() or SocketPoll_get_async() to obtain context.
 */
extern void SocketBuf_set_async (T buf, SocketAsync_T async);

/**
 * @brief Get the associated async I/O context.
 * @ingroup core_io
 * @param[in] buf The buffer to query.
 * @return The async context, or NULL if not set.
 *
 * @threadsafe Yes - read-only.
 */
extern SocketAsync_T SocketBuf_get_async (const T buf);

/**
 * @brief Associate a socket with this buffer for I/O operations.
 * @ingroup core_io
 * @param[in] buf The buffer to configure.
 * @param[in] socket The socket for read/write operations.
 *
 * Required before using SocketBuf_flush_async() or SocketBuf_fill_async().
 * The socket must be non-blocking and outlive the buffer.
 *
 * @throws SocketBuf_Failed if buffer is invalid.
 * @threadsafe No - configure before concurrent use.
 *
 * @see SocketBuf_get_socket() to query current socket.
 */
extern void SocketBuf_set_socket (T buf, Socket_T socket);

/**
 * @brief Get the associated socket.
 * @ingroup core_io
 * @param[in] buf The buffer to query.
 * @return The associated socket, or NULL if not set.
 *
 * @threadsafe Yes - read-only.
 */
extern Socket_T SocketBuf_get_socket (const T buf);

/**
 * @brief Asynchronously flush buffer data to the associated socket.
 * @ingroup core_io
 * @param[in] buf The buffer containing data to send.
 * @param[in] cb Completion callback (required).
 * @param[in] user_data User context passed to callback.
 * @param[in] flags Async operation flags (e.g., ASYNC_FLAG_ZERO_COPY).
 * @return Request ID (>0) on success, 0 on failure.
 *
 * Submits the buffer's readable data for async transmission to the socket.
 * On completion, the callback receives the number of bytes sent. The caller
 * must call SocketBuf_consume() in the callback to remove sent data.
 *
 * Requires prior calls to SocketBuf_set_async() and SocketBuf_set_socket().
 *
 * @throws SocketBuf_Failed if buffer/socket/async not configured.
 * @threadsafe No - caller must synchronize buffer access.
 *
 * ## Example
 *
 * @code{.c}
 * void flush_complete(SocketBuf_T buf, ssize_t bytes, int err, void *ud) {
 *     if (err != 0) {
 *         fprintf(stderr, "Flush error: %s\n", strerror(err));
 *         return;
 *     }
 *     if (bytes > 0) {
 *         SocketBuf_consume(buf, (size_t)bytes);  // Remove sent data
 *     }
 * }
 *
 * // Submit async flush
 * unsigned req = SocketBuf_flush_async(buf, flush_complete, NULL, 0);
 * @endcode
 *
 * @see SocketBuf_fill_async() for async receive.
 * @see SocketAsync_Flags for available flags.
 */
extern unsigned SocketBuf_flush_async (T buf,
                                       SocketBuf_AsyncCallback cb,
                                       void *user_data,
                                       int flags);

/**
 * @brief Asynchronously fill buffer from the associated socket.
 * @ingroup core_io
 * @param[in] buf The buffer to receive data into.
 * @param[in] max_fill Maximum bytes to receive (0 = fill available space).
 * @param[in] cb Completion callback (required).
 * @param[in] user_data User context passed to callback.
 * @param[in] flags Async operation flags.
 * @return Request ID (>0) on success, 0 on failure.
 *
 * Submits an async receive request to fill the buffer's writable space.
 * On completion, the callback receives the number of bytes received.
 * The received data is automatically committed to the buffer (no action needed
 * in callback for data commitment, but buffer is ready for reading).
 *
 * Returns 0 (failure) if buffer has no write space - call SocketBuf_ensure()
 * first if needed.
 *
 * Requires prior calls to SocketBuf_set_async() and SocketBuf_set_socket().
 *
 * @throws SocketBuf_Failed if buffer/socket/async not configured.
 * @threadsafe No - caller must synchronize buffer access.
 *
 * ## Example
 *
 * @code{.c}
 * void fill_complete(SocketBuf_T buf, ssize_t bytes, int err, void *ud) {
 *     if (err != 0) {
 *         fprintf(stderr, "Fill error: %s\n", strerror(err));
 *         return;
 *     }
 *     if (bytes == 0) {
 *         printf("EOF - connection closed\n");
 *         return;
 *     }
 *     // Data already committed - read it
 *     char line[256];
 *     if (SocketBuf_readline(buf, line, sizeof(line)) > 0) {
 *         printf("Received: %s\n", line);
 *     }
 * }
 *
 * // Submit async fill (up to buffer capacity)
 * unsigned req = SocketBuf_fill_async(buf, 0, fill_complete, NULL, 0);
 * @endcode
 *
 * @see SocketBuf_flush_async() for async send.
 * @see SocketBuf_ensure() to guarantee write space.
 */
extern unsigned SocketBuf_fill_async (T buf,
                                      size_t max_fill,
                                      SocketBuf_AsyncCallback cb,
                                      void *user_data,
                                      int flags);

/**
 * @brief Check if async I/O is available and configured for this buffer.
 * @ingroup core_io
 * @param[in] buf The buffer to check.
 * @return 1 if async I/O is available (async context set and functional),
 *         0 otherwise.
 *
 * Use this to determine whether to use async or synchronous I/O paths.
 *
 * @threadsafe Yes - read-only.
 *
 * @see SocketBuf_set_async() to configure async context.
 * @see SocketAsync_is_available() for backend availability.
 */
extern int SocketBuf_async_available (const T buf);

#undef T
#endif /* SOCKETBUF_INCLUDED */
