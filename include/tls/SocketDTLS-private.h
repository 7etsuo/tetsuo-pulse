/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketDTLS-private.h
 * @ingroup security
 * @brief DTLS internal shared definitions and helper functions.
 *
 * Internal header for all DTLS module implementation files. Contains shared
 * helper function declarations, error handling macros, internal types,
 * and the SocketDTLSContext_T structure definition.
 * NOT part of public API - do not include from application code.
 *
 * Thread safety: Internal functions are not thread-safe unless noted.
 *
 * @see SocketDTLS.h for public DTLS API.
 * @see SocketDTLSContext.h for public DTLS context API.
 */

#ifndef SOCKETDTLS_PRIVATE_INCLUDED
#define SOCKETDTLS_PRIVATE_INCLUDED

#if SOCKET_HAS_TLS

#include <pthread.h>
#include <stdatomic.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketUtil.h"
#include "socket/SocketDgram-private.h"
#include "tls/SocketDTLS.h"
#include "tls/SocketDTLSConfig.h"
#include "tls/SocketDTLSContext.h"
#include "tls/SocketSSL-internal.h" /* Shared TLS/DTLS utilities */
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

/* ============================================================================
 * Thread-Local Error Handling for SocketDTLS
 * ============================================================================
 */

/**
 * @brief Raise a SocketDTLS module exception with automatically populated
 * error details.
 * @ingroup security
 *
 * Specialized exception-raising macro for the DTLS module. It leverages the
 * library's detailed exception pattern to attach a thread-local reason string
 * (from socket_error_buf) to the exception before raising. This ensures
 * multi-threaded safety by avoiding shared exception instances and provides
 * rich diagnostics including OpenSSL errors when used with
 * dtls_format_openssl_error().
 *
 * The macro expands to code that copies the base exception, sets its .reason
 * field, and invokes RAISE(). Requires prior population of socket_error_buf
 * (e.g., via DTLS_ERROR_MSG() or dtls_format_openssl_error()) for meaningful
 * details.
 *
 * @param[in] exception The SocketDTLS exception type to raise (e.g.,
 * SocketDTLS_Failed, SocketDTLS_HandshakeFailed). Must be a valid module
 * exception.
 *
 * @note
 * - Thread-local implementation prevents races; each thread gets its own
 * exception copy.
 * - socket_error_buf must be formatted before calling (use DTLS_ERROR_MSG() or
 * similar).
 * - If buffer empty, exception raises with empty reason (fallback to default
 * message).
 * - Defined only when SOCKET_HAS_TLS; otherwise expands harmlessly or errors
 * at compile.
 * - Part of internal error handling; public API uses higher-level exceptions
 * via SocketDTLS_* funcs.
 *
 * @threadsafe Yes - Uses __thread or TLS storage for exception and buffer.
 * Safe in multi-threaded contexts without external synchronization.
 *
 *  Usage Example
 *
 * @code{.c}
 * // Simple failure with message
 * DTLS_ERROR_MSG("Invalid certificate file: %s", path);
 * RAISE_DTLS_ERROR(SocketDTLSConfig_InvalidCert);
 *
 * // After OpenSSL failure
 * if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
 *     dtls_format_openssl_error("Failed to load certificate");
 *     RAISE_DTLS_ERROR(SocketDTLSConfig_InvalidCert);
 * }
 *
 * // In TRY/EXCEPT blocks
 * TRY {
 *     // DTLS operation that may fail
 * } EXCEPT(SocketDTLS_Failed) {
 *     // Handler receives exception with .reason populated by RAISE_DTLS_ERROR
 *     fprintf(stderr, "DTLS error: %s\n", Except_reason(Except_frame()));
 * } END_TRY;
 * @endcode
 *
 *  Related Macros
 *
 * | Macro | Purpose | Pre-formats message? |
 * |-------|---------|----------------------|
 * | RAISE_DTLS_ERROR | Raise with existing buffer | No |
 * | RAISE_DTLS_ERROR_MSG | Raise + format simple msg | Yes |
 * | DTLS_ERROR_MSG | Format only (no raise) | Yes |
 * | DTLS_ERROR_FMT | Format with args (no raise) | Yes |
 *
 * @warning Always format error details before raising to avoid empty reasons.
 * Unformatted raises still succeed but provide poor diagnostics.
 *
 * @complexity O(1) - Simple copy and raise; no allocations or loops.
 *
 * @see RAISE_DTLS_ERROR_MSG() for convenient message formatting + raise
 * @see DTLS_ERROR_MSG() and DTLS_ERROR_FMT() for buffer population
 * @see dtls_format_openssl_error() for OpenSSL-specific error handling
 * @see core/Except.h for base exception handling framework
 * @see SocketUtil.h#SOCKET_RAISE_MODULE_ERROR for generic module exception
 * macro
 * @see docs/ERROR_HANDLING.md for comprehensive exception patterns
 * @see SocketDTLS_DetailedException thread-local instance definition
 */
#define RAISE_DTLS_ERROR(exception)                                           \
  SOCKET_RAISE_MODULE_ERROR (SocketDTLS, exception)

/**
 * @brief Raise a SocketDTLS exception with formatted error message and
 * arguments.
 * @ingroup security
 *
 * Convenience macro combining error message formatting and exception raising
 * in one step. First populates the thread-local socket_error_buf using
 * SOCKET_ERROR_MSG() with the provided format string and arguments (including
 * errno if applicable), then invokes RAISE_DTLS_ERROR() to raise the exception
 * with the formatted details attached. Ideal for quick error reporting in DTLS
 * functions without separate formatting calls.
 *
 * Supports printf-style formatting for rich diagnostics, e.g., including file
 * paths, error codes, or numeric values. Automatically thread-safe via
 * per-thread buffers.
 *
 * @param[in] exception The SocketDTLS exception type (e.g., SocketDTLS_Failed)
 * @param[in] msg Format string for the error message (printf-style)
 * @param[in] ... Variable arguments matching the format string (e.g., const
 * char *path, int err)
 *
 * @note
 * - Equivalent to: DTLS_ERROR_MSG(msg, ...); RAISE_DTLS_ERROR(exception);
 * - Appends errno details if available (via SOCKET_ERROR_MSG behavior).
 * - Format string must be compile-time constant or literal for security
 * (avoids format attacks).
 * - Maximum buffer size SOCKET_DTLS_ERROR_BUFSIZE; truncation possible on
 * overflow (rare).
 * - Use for non-OpenSSL errors; pair with dtls_format_openssl_error() for SSL
 * failures.
 *
 * @threadsafe Yes - All operations use thread-local storage for buffer and
 * exception. No synchronization needed.
 *
 *  Usage Example
 *
 * @code{.c}
 * // Format with string and int
 * if (!dtls_validate_file_path(cert_path)) {
 *     RAISE_DTLS_ERROR_MSG(SocketDTLSConfig_InvalidCert,
 *                          "Invalid certificate path: '%s' (length %zu)",
 *                          cert_path, strlen(cert_path));
 * }
 *
 * // With errno after system call
 * FILE *f = fopen(key_path, "r");
 * if (!f) {
 *     RAISE_DTLS_ERROR_MSG(SocketDTLSConfig_Failed,
 *                          "Failed to open private key file: %s", key_path);
 *     // Exception includes strerror(errno) automatically
 * }
 * @endcode
 *
 *  Formatting vs Other Macros
 *
 * | Macro | Formats Msg? | Raises Exc? | Includes errno? | Best For |
 * |-------|--------------|-------------|-----------------|----------|
 * | RAISE_DTLS_ERROR_MSG | Yes (printf) | Yes | Yes | Quick errors with vars |
 * | RAISE_DTLS_ERROR | No | Yes | No | After manual formatting |
 * | DTLS_ERROR_FMT | Yes (printf) | No | Yes | Log without raising |
 * | DTLS_ERROR_MSG | Yes (simple) | No | Yes | Basic messages |
 *
 * @warning Format strings with user input can enable attacks;
 * validate/sanitize inputs. Excessive arguments may truncate; keep messages
 * concise (< SOCKET_DTLS_ERROR_BUFSIZE).
 *
 * @complexity O(n) where n=formatted string length - snprintf time,
 * negligible.
 *
 * @see DTLS_ERROR_FMT() for formatting without raising
 * @see RAISE_DTLS_ERROR() underlying raise mechanism
 * @see SOCKET_ERROR_MSG() base formatting macro in SocketUtil.h
 * @see core/Except.h for exception handling TRY/EXCEPT patterns
 * @see docs/ERROR_HANDLING.md#detailed-exceptions for best practices
 */
#define RAISE_DTLS_ERROR_MSG(exception, msg)                                  \
  do                                                                          \
    {                                                                         \
      SOCKET_ERROR_MSG (msg);                                                 \
      RAISE_DTLS_ERROR (exception);                                           \
    }                                                                         \
  while (0)

/**
 * @brief Validate that DTLS is enabled on a socket, raising exception if not.
 * @ingroup security
 *
 * Defensive programming macro used internally to enforce prerequisite that
 * DTLS has been enabled on the socket before performing any DTLS-specific
 * operations. Checks socket->dtls_enabled flag and raises the specified
 * exception with a standardized message if false. Prevents subtle bugs from
 * uninitialized sockets and clarifies error context for debugging.
 *
 * Expands to an if-statement that performs the check and
 * RAISE_DTLS_ERROR_MSG() on failure. No-op on success (continues execution).
 *
 * @param[in] socket The socket instance to validate (must not be NULL)
 * @param[in] exception The SocketDTLS exception type to raise on validation
 * failure (e.g., SocketDTLS_Failed, SocketDTLS_InvalidState)
 *
 * @note
 * - Assumes socket != NULL; add explicit NULL check if needed before this
 * macro.
 * - Message is fixed: "DTLS not enabled on socket" for consistency.
 * - Placed early in functions requiring DTLS state to fail-fast with clear
 * errors.
 * - Complements VALIDATE_DTLS_IO_READY() which adds more checks (handshake,
 * SSL*).
 *
 * @threadsafe Conditional - Safe if socket access is synchronized externally.
 * The check is read-only, but exception raising uses thread-local storage.
 *
 *  Usage Example
 *
 * @code{.c}
 * static ssize_t
 * dtls_internal_send(SocketDgram_T socket, const void *buf, size_t len) {
 *     REQUIRE_DTLS_ENABLED(socket, SocketDTLS_InvalidState);
 *     // Now safe to access DTLS state
 *     SSL *ssl = dtls_socket_get_ssl(socket);
 *     // Proceed with SSL_write(ssl, buf, len)
 * }
 * @endcode
 *
 * @warning Misuse (e.g., on non-DTLS sockets) always raises; use judiciously.
 * For runtime-disable scenarios, check flag manually without raising.
 *
 * @complexity O(1) - Single flag check and potential exception raise.
 *
 * @see VALIDATE_DTLS_IO_READY() for comprehensive I/O readiness validation
 * @see SocketDTLS_enable() public function to enable DTLS on sockets
 * @see RAISE_DTLS_ERROR_MSG() underlying raise mechanism
 * @see SocketDgram-private.h for socket internal state (dtls_enabled flag)
 * @see docs/SECURITY.md#dtls-validation for best practices
 */
#define REQUIRE_DTLS_ENABLED(socket, exception)                               \
  do                                                                          \
    {                                                                         \
      if (!(socket)->dtls_enabled)                                            \
        RAISE_DTLS_ERROR_MSG (exception, "DTLS not enabled on socket");       \
    }                                                                         \
  while (0)

/**
 * @brief Format a simple static error message into the thread-local error
 * buffer.
 * @ingroup security
 *
 * Thin wrapper over SOCKET_ERROR_MSG() for DTLS module consistency. Populates
 * the per-thread socket_error_buf with the given message string, optionally
 * appending strerror(errno) details if errno indicates a system error.
 * Used before raising exceptions or logging to provide context without printf
 * overhead.
 *
 * Does not raise exceptions or perform I/O; purely for buffer preparation.
 * Message should be compile-time literal for security and performance.
 *
 * @param[in] msg Compile-time constant string literal describing the error
 *
 * @note
 * - Automatically includes errno info if set (e.g., after failed open/read).
 * - Thread-local buffer; concurrent threads unaffected.
 * - Buffer size limited to SOCKET_DTLS_ERROR_BUFSIZE; long messages truncate.
 * - Follow with RAISE_DTLS_ERROR() to attach to exception or logging macros.
 *
 * @threadsafe Yes - Thread-local buffer, no shared state.
 *
 *  Usage Example
 *
 * @code{.c}
 * if (some_condition_fails) {
 *     DTLS_ERROR_MSG("DTLS configuration missing required field");
 *     RAISE_DTLS_ERROR(SocketDTLSConfig_Failed);
 * }
 *
 * // With system error
 * if (bind(fd, addr, addrlen) < 0) {
 *     DTLS_ERROR_MSG("Failed to bind DTLS socket");
 *     // Buffer now contains "Failed to bind DTLS socket: <strerror(errno)>"
 * }
 * @endcode
 *
 * @see DTLS_ERROR_FMT() for formatted messages with arguments
 * @see SOCKET_ERROR_MSG() underlying implementation
 * @see Socket_GetLastError() to retrieve formatted buffer
 * @see docs/ERROR_HANDLING.md for formatting best practices
 *
 * @complexity O(1) - String copy and potential strerror() call (bounded).
 *
 * @warning Avoid format strings here; use DTLS_ERROR_FMT() for %s/%d etc.
 * Static strings only to prevent runtime format attacks.
 */
#define DTLS_ERROR_MSG(msg) SOCKET_ERROR_MSG (msg)

/**
 * @brief Format error message with printf-style arguments into thread-local
 * buffer.
 * @ingroup security
 *
 * Advanced formatting macro for DTLS errors, wrapping SOCKET_ERROR_FMT() to
 * populate socket_error_buf with formatted message + optional errno details.
 * Supports full printf specifiers (%s, %d, %zu, etc.) for dynamic error
 * reporting, e.g., including numeric codes, paths, or counts. Automatically
 * appends system error description if errno is set post-system calls.
 *
 * Use when static strings insufficient; provides flexibility for parameterized
 * diagnostics while maintaining thread-safety and integration with exception
 * raising.
 *
 * @param[in] fmt printf-style format string (compile-time literal recommended)
 * @param[in] ... Variable arguments corresponding to format specifiers
 *
 * @note
 * - Expands to snprintf-like formatting into fixed-size buffer.
 * - Includes errno suffix if non-zero (e.g., ": No such file (ENOENT)").
 * - Truncates if output > SOCKET_DTLS_ERROR_BUFSIZE; prefer concise formats.
 * - For OpenSSL errors, prefer dtls_format_openssl_error() instead.
 * - Safe with NULL pointers in %s (prints "(null)"); validate args to avoid
 * crashes.
 *
 * @threadsafe Yes - Thread-local buffer; formatting reentrant.
 *
 *  Usage Example
 *
 * @code{.c}
 * // Dynamic path errors
 * size_t len = strlen(provided_path);
 * if (len > SOCKET_DTLS_MAX_PATH_LEN) {
 *     DTLS_ERROR_FMT("Path too long: %zu bytes exceeds %d limit", len,
 *                    SOCKET_DTLS_MAX_PATH_LEN);
 *     RAISE_DTLS_ERROR(SocketDTLSConfig_InvalidPath);
 * }
 *
 * // System call failure
 * if (stat(file_path, &st) < 0) {
 *     DTLS_ERROR_FMT("stat() failed for %s: errno=%d", file_path, errno);
 *     // Buffer: "stat() failed for cert.pem: errno=2: No such file or
 * directory"
 * }
 * @endcode
 *
 *  Specifier Support
 *
 * Standard printf specifiers supported via vsnprintf():
 * - %s: strings (handles NULL)
 * - %d/%i: signed ints
 * - %u/%zu: unsigned/size_t
 * - %x/%X: hex
 * - %%: literal %
 *
 * @warning
 * - Format string vulnerabilities: Use trusted sources; untrusted input to fmt
 * enables crashes/exploits.
 * - Buffer overflow truncation silent; check strlen(Socket_GetLastError()) if
 * critical.
 * - Performance: Avoid in hot paths; formatting slower than static
 * DTLS_ERROR_MSG().
 *
 * @complexity O(n) - Formatting time proportional to output length.
 *
 * @see DTLS_ERROR_MSG() for static string variant (faster, no args)
 * @see SOCKET_ERROR_FMT() base macro in SocketUtil.h
 * @see RAISE_DTLS_ERROR_MSG() for format + raise in one step
 * @see docs/ERROR_HANDLING.md#formatted-errors guidelines
 */
#define DTLS_ERROR_FMT(fmt, ...) SOCKET_ERROR_FMT (fmt, ##__VA_ARGS__)

/**
 * @brief Comprehensive validation macro for DTLS socket readiness before I/O
 * operations.
 * @ingroup security
 *
 * All-in-one validation macro ensuring a socket is fully prepared for DTLS
 * encrypted I/O. Combines multiple checks into a single statement expression
 * that either returns the SSL* pointer for immediate use or raises a detailed
 * exception on any failure. Essential guard for public DTLS send/recv
 * functions to prevent crashes or security issues from operating on
 * uninitialized or incomplete DTLS state.
 *
 * Checks in order:
 * 1. socket->dtls_enabled == true
 * 2. socket->dtls_handshake_done == true
 * 3. ssl = dtls_socket_get_ssl(socket) != NULL
 *
 * On any failure, formats specific error message into thread-local buffer and
 * raises the provided exception via RAISE_DTLS_ERROR(). Success returns the
 * validated SSL*.
 *
 * @param[in] socket The DTLS socket to validate for I/O readiness
 * @param[in] exception Exception type to raise on validation failure (e.g.,
 * SocketDTLS_InvalidState)
 *
 * @return SSL* pointer to validated SSL object (caller must not free)
 *
 * @note
 * - Macro expands to GCC statement expression ({ ... }) returning SSL* or
 * raising.
 * - Uses dtls_socket_get_ssl() internally for SSL* retrieval and validation.
 * - Error messages are specific: "DTLS not enabled...", "handshake not
 * complete", "SSL not available".
 * - Intended for use right before SSL_read()/SSL_write() calls in DTLS
 * wrappers.
 * - Does not check socket validity (non-NULL); add if (socket) before if
 * needed.
 *
 * @threadsafe Yes - Relies on thread-safe helpers (dtls_socket_get_ssl
 * read-only, exception raising thread-local). Safe concurrent use per-socket.
 *
 *  Usage Example
 *
 * @code{.c}
 * ssize_t
 * SocketDTLS_send(SocketDgram_T socket, const void *buf, size_t len) {
 *     SSL *ssl = VALIDATE_DTLS_IO_READY(socket, SocketDTLS_InvalidState);
 *     // ssl guaranteed valid; proceed to encrypted send
 *     return SSL_write(ssl, buf, len);
 * }
 *
 * // In recv with different exception
 * void dtls_process_packet(SocketDgram_T socket, const uint8_t *pkt, size_t
 * pkt_len) { SSL *ssl = VALIDATE_DTLS_IO_READY(socket, SocketDTLS_Failed);
 *     // Safe to use ssl for decryption
 * }
 * @endcode
 *
 *  Validation Checklist
 *
 * - [ ] DTLS enabled via SocketDTLS_enable()
 * - [ ] Handshake completed (DTLS_HANDSHAKE_COMPLETE)
 * - [ ] SSL* available and valid
 *
 * @warning Failure to use this macro before I/O can cause segfaults (null
 * SSL*), protocol errors (incomplete handshake), or security leaks (plaintext
 * on DTLS socket). Always validate in production code paths.
 *
 * @complexity O(1) - Sequential checks, no loops or dynamic ops.
 *
 * @see REQUIRE_DTLS_ENABLED() for basic enablement check only
 * @see dtls_socket_get_ssl() underlying SSL* accessor
 * @see dtls_handle_ssl_error() for handshake state management
 * @see SocketDTLS.h#SocketDTLS_send for public API using this internally
 * @see docs/TLS.md#dtls-io-validation for security rationale
 */
#define VALIDATE_DTLS_IO_READY(socket, exception)                             \
  ({                                                                          \
    if (!(socket)->dtls_enabled)                                              \
      {                                                                       \
        DTLS_ERROR_MSG ("DTLS not enabled on socket");                        \
        RAISE_DTLS_ERROR (exception);                                         \
      }                                                                       \
    if (!(socket)->dtls_handshake_done)                                       \
      {                                                                       \
        DTLS_ERROR_MSG ("DTLS handshake not complete");                       \
        RAISE_DTLS_ERROR (exception);                                         \
      }                                                                       \
    SSL *_ssl = dtls_socket_get_ssl (socket);                                 \
    if (!_ssl)                                                                \
      {                                                                       \
        DTLS_ERROR_MSG ("SSL object not available");                          \
        RAISE_DTLS_ERROR (exception);                                         \
      }                                                                       \
    _ssl;                                                                     \
  })

/* ============================================================================
 * SSL Object Access
 * ============================================================================
 */

/**
 * @brief Retrieve the SSL object pointer associated with a DTLS-enabled
 * socket.
 * @ingroup security
 *
 * Provides safe access to the underlying OpenSSL SSL structure for DTLS
 * operations. Performs validation checks before returning the pointer,
 * ensuring DTLS is enabled and the SSL object exists. This helper is used
 * extensively in DTLS I/O and handshake functions to avoid repeated null
 * checks and enablement verifications.
 *
 * @param[in] socket The socket instance to query (may be NULL or non-DTLS)
 *
 * @return SSL* pointer to the DTLS SSL context if available and valid; NULL
 * otherwise. Returns NULL in cases:
 * - socket == NULL
 * - !socket->dtls_enabled
 * - socket->dtls_ssl == NULL
 *
 * @note This is a read-only accessor; does not perform any I/O or state
 * changes. No exceptions raised; simply returns NULL on invalid state. Callers
 * should check return value before using SSL APIs. The returned SSL* remains
 * owned by the socket; do not free it directly.
 *
 * @threadsafe Yes - purely read-only access to socket fields. No locks or
 * modifications. Safe to call from any thread holding a reference to the
 * socket.
 *
 *  Usage Example
 *
 * @code{.c}
 * // Safe SSL access for DTLS operations
 * SSL *ssl = dtls_socket_get_ssl(dtls_socket);
 * if (ssl) {
 *     // Perform SSL operations, e.g., SSL_pending(ssl)
 *     int pending = SSL_pending(ssl);
 *     // Or use in error handling
 * } else {
 *     RAISE_DTLS_ERROR(SocketDTLS_Failed, "No SSL context available");
 * }
 * @endcode
 *
 *  Validation Performed
 *
 * - Null pointer check on socket
 * - Check socket->dtls_enabled flag
 * - Check socket->dtls_ssl pointer validity
 *
 * @complexity O(1) - Simple pointer and flag checks, no loops or allocations.
 *
 * @warning Never assume returned SSL* is valid without checking; invalid
 * access leads to crashes or security vulnerabilities. Always pair with if
 * (ssl) { ... }
 *
 * @see VALIDATE_DTLS_IO_READY() macro which uses this helper plus additional
 * checks
 * @see SocketDTLS_enable() to initialize DTLS on socket and create SSL*
 * @see dtls_handle_ssl_error() for handling operations on the SSL*
 * @see docs/TLS.md for DTLS socket lifecycle
 */
static inline SSL *
dtls_socket_get_ssl (SocketDgram_T socket)
{
  if (!socket || !socket->dtls_enabled || !socket->dtls_ssl)
    return NULL;
  return (SSL *)socket->dtls_ssl;
}

/* ============================================================================
 * SSL Error Handling
 * ============================================================================
 */

/**
 * @brief Map OpenSSL error codes to DTLS handshake states for non-blocking
 * I/O.
 * @ingroup security
 *
 * Handles the mapping between OpenSSL's error model and the library's DTLS
 * state machine. This function is essential for event-driven DTLS handshakes,
 * translating SSL_get_error() results into actionable states that drive
 * polling behavior. It also updates the socket's handshake completion flag and
 * sets errno appropriately for WANT_READ/WANT_WRITE cases.
 *
 * @param[in] socket The DTLS-enabled socket instance to update state on
 * @param[in] ssl The SSL object on which the operation was performed
 * @param[in] ssl_result The return value from the SSL API call (e.g.,
 * SSL_do_handshake(), SSL_read())
 *
 * @return DTLSHandshakeState enum value indicating the next required action:
 * - DTLS_HANDSHAKE_COMPLETE: Success, handshake finished
 * - DTLS_HANDSHAKE_WANT_READ: Poll for readability (errno set to EAGAIN)
 * - DTLS_HANDSHAKE_WANT_WRITE: Poll for writability (errno set to EAGAIN)
 * - DTLS_HANDSHAKE_ERROR: Fatal error occurred (errno or OpenSSL queue for
 * details)
 * - Other states unchanged
 *
 * @note This is an internal helper called after every SSL operation during
 * handshake. It does not clear OpenSSL error queue; caller may need to handle
 * persistent errors. Updates socket->dtls_handshake_done = 1 only on
 * SSL_ERROR_NONE.
 *
 * @threadsafe Yes - modifies only per-socket state
 * (socket->dtls_handshake_done) and sets errno (thread-local). No shared
 * resources or locks required.
 *
 *  Usage Example
 *
 * @code{.c}
 * // Typical usage in non-blocking DTLS handshake loop
 * SSL *ssl = dtls_socket_get_ssl(socket);
 * if (!ssl) {
 *     // Handle invalid socket
 *     return DTLS_HANDSHAKE_ERROR;
 * }
 *
 * int ret = SSL_do_handshake(ssl);
 * DTLSHandshakeState state = dtls_handle_ssl_error(socket, ssl, ret);
 *
 * switch (state) {
 *   case DTLS_HANDSHAKE_COMPLETE:
 *       SOCKET_LOG_DEBUG("DTLS handshake completed");
 *       break;
 *   case DTLS_HANDSHAKE_WANT_READ:
 *       // Add socket to read events in SocketPoll
 *       SocketPoll_add(poll, Socket_fd(socket), POLL_READ, userdata);
 *       break;
 *   case DTLS_HANDSHAKE_WANT_WRITE:
 *       SocketPoll_add(poll, Socket_fd(socket), POLL_WRITE, userdata);
 *       break;
 *   case DTLS_HANDSHAKE_ERROR:
 *       dtls_format_openssl_error("DTLS handshake failed");
 *       // Raise exception or close socket
 *       break;
 * }
 * @endcode
 *
 *  Error Mapping Details
 *
 * | SSL_get_error() Value | Mapped State | errno | Notes |
 * |-----------------------|--------------|-------|-------|
 * | SSL_ERROR_NONE        | COMPLETE     | None  | Success |
 * | SSL_ERROR_WANT_READ   | WANT_READ    | EAGAIN| Continue polling |
 * | SSL_ERROR_WANT_WRITE  | WANT_WRITE   | EAGAIN| Continue polling |
 * | SSL_ERROR_ZERO_RETURN | ERROR        | None  | Peer closed |
 * | SSL_ERROR_WANT_CONNECT| ERROR        | None  | Unsupported in DTLS |
 * | SSL_ERROR_WANT_ACCEPT | ERROR        | None  | Unsupported in DTLS |
 * | SSL_ERROR_WANT_X509_METHOD | ERROR | None | Cert verify issue |
 * | SSL_ERROR_SYSCALL     | ERROR        | Preserved | System error |
 * | SSL_ERROR_SSL         | ERROR        | None  | Protocol violation |
 *
 * @warning In non-blocking mode, always pair SSL calls with this handler to
 * avoid infinite loops or missed errors. Ignoring WANT_READ/WRITE leads to
 * stalled handshakes.
 *
 * @complexity O(1) - Single switch statement on error code, constant time.
 *
 * @see SocketDTLS.h for DTLSHandshakeState enum definition
 * @see SSL_get_error() - Called internally to determine state
 * @see dtls_socket_get_ssl() - To obtain SSL* from socket
 * @see dtls_format_openssl_error() - For formatting persistent errors
 * @see docs/SECURITY.md#dtls for DTLS implementation details
 * @see RFC 6347 Section 4 - DTLS Handshake Protocol
 */
static inline DTLSHandshakeState
dtls_handle_ssl_error (SocketDgram_T socket, SSL *ssl, int ssl_result)
{
  int ssl_error = SSL_get_error (ssl, ssl_result);

  switch (ssl_error)
    {
    case SSL_ERROR_NONE:
      socket->dtls_handshake_done = 1;
      return DTLS_HANDSHAKE_COMPLETE;

    case SSL_ERROR_WANT_READ:
      socket->dtls_handshake_done = 0;
      errno = EAGAIN;
      return DTLS_HANDSHAKE_WANT_READ;

    case SSL_ERROR_WANT_WRITE:
      socket->dtls_handshake_done = 0;
      errno = EAGAIN;
      return DTLS_HANDSHAKE_WANT_WRITE;

    default:
      socket->dtls_handshake_done = 0;
      return DTLS_HANDSHAKE_ERROR;
    }
}

/**
 * @brief Format OpenSSL error into the thread-local error buffer.
 * @ingroup security
 * @param context Context string for the error message.
 *
 * Formats the current OpenSSL error queue into socket_error_buf prefixed with
 * the given context. Clears the error queue after formatting to prevent
 * interference with subsequent operations. Used internally for consistent
 * error reporting in DTLS functions.
 *
 * @threadsafe Yes - operates on thread-local error buffer.
 * @see dtls_handle_ssl_error() for SSL error state mapping.
 * @see ssl_format_openssl_error_to_buf() shared implementation.
 */
static inline void
dtls_format_openssl_error (const char *context)
{
  ssl_format_openssl_error_to_buf (context, socket_error_buf,
                                   SOCKET_ERROR_BUFSIZE);
}

/* ============================================================================
 * Input Validation
 * ============================================================================
 */

/**
 * @brief Validate file path for certificates, keys, or CAs against security
 * threats.
 * @ingroup security
 * @param path Null-terminated file path string to validate.
 * @return 1 if path passes all security checks, 0 otherwise.
 *
 * Thin wrapper around ssl_validate_file_path() using DTLS-specific max length.
 *
 * @threadsafe Yes - pure string and stat operations, no shared state.
 * @see ssl_validate_file_path() for implementation details.
 */
static inline int
dtls_validate_file_path (const char *path)
{
  return ssl_validate_file_path (path, SOCKET_DTLS_MAX_PATH_LEN);
}

/* ============================================================================
 * SocketDTLSContext_T Structure Definition
 * ============================================================================
 */

#define T SocketDTLSContext_T

/**
 * @brief Cookie state structure for server-side DTLS cookie exchange.
 * @ingroup security
 *
 * Manages HMAC secrets for generating and verifying stateless cookies during
 * DTLS handshake to prevent DoS attacks (RFC 6347 Section 4.2.1). Supports
 * secret rotation for replay protection and forward secrecy.
 *
 * @threadsafe Conditional - mutex protects secret updates; read access
 * thread-safe.
 *
 * @see dtls_cookie_generate_cb()
 * @see dtls_cookie_verify_cb()
 * @see SocketDTLSContext_enable_cookie_exchange()
 * @see RFC 6347 for cookie exchange protocol.
 */
typedef struct
{
  unsigned char secret[SOCKET_DTLS_COOKIE_SECRET_LEN]; /**< HMAC secret */
  unsigned char
      prev_secret[SOCKET_DTLS_COOKIE_SECRET_LEN]; /**< Previous secret for
                                                     rotation */
  int cookie_enabled;           /**< Cookie exchange enabled */
  pthread_mutex_t secret_mutex; /**< Protects secret rotation */
} DTLSContextCookie;

/**
 * @brief ALPN configuration structure for DTLS contexts.
 * @ingroup security
 *
 * Stores supported application protocols for negotiation during handshake
 * (RFC 7301). Enables protocol selection for HTTP/2 over DTLS or other
 * services.
 *
 * @see SocketDTLSContext_set_alpn_protos()
 * @see SSL_get0_alpn_selected() for retrieval
 */
typedef struct
{
  const char **protocols; /**< Array of protocol strings */
  size_t *lens;           /**< Precomputed lengths of protocols[i] for O(1) access */
  size_t count;           /**< Number of protocols */
  const char
      *selected; /**< Negotiated protocol (set by server, read by client) */
} DTLSContextALPN;

/**
 * @brief SocketDTLSContext_T - DTLS Context Structure
 * @ingroup security
 *
 * Manages OpenSSL SSL_CTX for DTLS with secure defaults, certificates,
 * cookie exchange, and session caching. Provides DTLS 1.2+ support with
 * cookie-based DoS protection and session resumption for performance.
 *
 * Thread safety: Contexts are not thread-safe for modification after creation.
 * Share read-only after full setup, or use per-thread contexts.
 * SSL objects created from context are per-connection and thread-safe.
 */
struct T
{
  SSL_CTX *ssl_ctx;            /**< OpenSSL context */
  Arena_T arena;               /**< Arena for allocations */
  atomic_int refcount;         /**< Reference count for shared ownership */
  int is_server;               /**< 1 for server, 0 for client */
  size_t mtu;                  /**< Configured MTU */
  int session_cache_enabled;   /**< Session cache flag */
  size_t session_cache_size;   /**< Session cache size */
  size_t cache_hits;           /**< Session resumptions */
  size_t cache_misses;         /**< Full handshakes */
  size_t cache_stores;         /**< New sessions stored */
  pthread_mutex_t stats_mutex; /**< Thread-safe stats update */

  /* Cookie exchange (DTLS-specific DoS protection) */
  DTLSContextCookie cookie;

  /* ALPN configuration */
  DTLSContextALPN alpn;

  /* Timeout configuration */
  int initial_timeout_ms;
  int max_timeout_ms;
};

/**
 * @brief Context-specific raise macros using centralized SocketUtil infrastructure
 * @ingroup security
 *
 * These macros provide module-prefixed exception raising for SocketDTLSContext
 * using the shared socket_error_buf and SOCKET_RAISE_* family of macros.
 * No separate thread-local storage needed.
 *
 * @see SOCKET_RAISE_MODULE_ERROR() base macro
 * @see core/SocketUtil.h for implementation details
 */
#define RAISE_DTLS_CTX_ERROR(exception) \
  SOCKET_RAISE_MODULE_ERROR(SocketDTLSContext, exception)

#define RAISE_DTLS_CTX_ERROR_MSG(exception, msg) \
  SOCKET_RAISE_MSG(SocketDTLSContext, exception, msg)

#define RAISE_DTLS_CTX_ERROR_FMT(exception, fmt, ...) \
  SOCKET_RAISE_FMT(SocketDTLSContext, exception, fmt, ##__VA_ARGS__)

/* ============================================================================
 * Utility Macros
 * ============================================================================
 */

/**
 * @brief Suppress compiler warnings for intentionally unused parameters.
 * @ingroup security
 * @param x Parameter or variable that is intentionally unused.
 *
 * Alias for SOCKET_SSL_UNUSED for DTLS module compatibility.
 * @see SOCKET_SSL_UNUSED in SocketSSL-internal.h
 */
#define DTLS_UNUSED(x) SOCKET_SSL_UNUSED (x)

/**
 * @brief Validate DTLS enabled and retrieve SSL object, raising on failure.
 * @ingroup security
 *
 * Combined validation macro that checks DTLS is enabled and retrieves the SSL
 * object pointer. Raises the specified exception with a descriptive message if
 * either check fails. Returns the SSL* for immediate use.
 *
 * @param[in] socket The socket to validate
 * @param[in] exception Exception type to raise on failure
 *
 * @return SSL* pointer if validation passes
 * @threadsafe No - modifies thread-local error buffer
 */
#define REQUIRE_DTLS_SSL(socket, exception)                                   \
  ({                                                                          \
    if (!(socket)->dtls_enabled)                                              \
      RAISE_DTLS_ERROR_MSG (exception, "DTLS not enabled on socket");         \
    SSL *_ssl = dtls_socket_get_ssl (socket);                                 \
    if (!_ssl)                                                                \
      RAISE_DTLS_ERROR_MSG (exception, "SSL object not available");           \
    _ssl;                                                                     \
  })

/* ============================================================================
 * Cookie Exchange Internal Functions
 * ============================================================================
 */

/**
 * @brief OpenSSL callback for generating DTLS anti-DoS cookies during server
 * handshake.
 * @ingroup security
 *
 * Implements the server-side cookie generation logic for DTLS cookie exchange
 * protocol (RFC 6347 Section 4.2.1). Generates cryptographically secure,
 * stateless cookies that bind to client IP/port, proving address ownership and
 * mitigating resource exhaustion DoS attacks. Cookies force clients to
 * demonstrate reachability before server allocates full handshake state.
 *
 * Cookie computation: HMAC-SHA256(server_secret, peer_addr || peer_port ||
 * timestamp) truncated to SOCKET_DTLS_COOKIE_LEN (typically 32-64 bytes).
 * Secret rotated periodically via context for forward secrecy and replay
 * resistance. Timestamp ensures expiration.
 *
 * This callback is registered with OpenSSL via
 * SSL_CTX_set_cookie_generate_cb() and invoked automatically during
 * ClientHello processing when cookies enabled.
 *
 * @param[in] ssl Server SSL object in server context (DTLS role)
 * @param[out] cookie Buffer to write generated cookie bytes (size
 * SOCKET_DTLS_COOKIE_LEN)
 * @param[out] cookie_len Set to actual bytes written (0-255 per OpenSSL spec)
 *
 * @return 1 on successful generation (cookie written, *cookie_len set); 0 on
 * failure (e.g., RAND_bytes failure for nonce, HMAC error). On 0, OpenSSL
 * aborts handshake.
 *
 * @note
 * - Server-only; clients ignore (OpenSSL calls only on server ctx with
 * cookies).
 * - Buffer cookie must be at least 255 bytes (OpenSSL max); uses exactly
 * SOCKET_DTLS_COOKIE_LEN.
 * - Fails silently if secret unavailable or crypto ops fail; logs via
 * SocketLog if enabled.
 * - Timestamp in cookie prevents replays beyond window; config via context
 * timeouts.
 * - Do not call directly; set via internal SocketDTLSContext setup.
 *
 * @threadsafe Conditional - Accesses shared context cookie secret under mutex
 * lock. Safe for concurrent handshakes; internal locking prevents races on
 * secret rotation.
 *
 *  Usage Example
 *
 * @code{.c}
 * // Internal setup in SocketDTLSContext_new_server() or enable_cookies()
 * SSL_CTX_set_cookie_generate_cb(ctx, dtls_cookie_generate_cb);
 * // Callback auto-invoked on ClientHello with cookies enabled
 *
 * // Custom verification pairing
 * SSL_CTX_set_cookie_verify_cb(ctx, dtls_cookie_verify_cb);
 * @endcode
 *
 *  Cookie Security Properties
 *
 * - **Stateless**: No per-client memory; scales to millions of SYNs
 * - **Unforgeable**: HMAC binds to secret unknown to attacker
 * - **Address-bound**: Proves client IP/port ownership via round-trip
 * - **Time-limited**: Timestamp expiration (configurable window)
 * - **Replay-resistant**: Secret rotation + timestamp
 *
 * | Attack | Mitigated? | Mechanism |
 * |--------|------------|-----------|
 * | SYN Flood | Yes | Stateless verification |
 * | IP Spoofing | Yes | Address binding in HMAC |
 * | Replay | Yes | Timestamp + rotation |
 * | DoS Amplification | Partial | Limited cookie size |
 *
 * @warning Disable cookies in trusted networks to reduce latency (extra RTT).
 * Ensure server secret strong (min 32 bytes random); rotate periodically.
 * Monitor crypto failure rates (RAND_bytes/HMAC) for system resource issues.
 *
 * @complexity O(1) - Fixed HMAC computation, constant time crypto primitives.
 *
 * @see dtls_cookie_verify_cb() paired verification callback
 * @see dtls_generate_cookie_hmac() low-level HMAC implementation
 * @see SocketDTLSContext_enable_cookie_exchange() public enable function
 * @see SSL_CTX_set_cookie_generate_cb() OpenSSL registration
 * @see docs/SYN-PROTECT.md for DoS protection integration
 * @see RFC 6347#section-4.2.1 DTLS cookie exchange specification
 * @see RFC 2104 HMAC algorithm used
 */

/**
 * @brief OpenSSL callback for verifying client-provided DTLS cookies in server
 * handshake.
 * @ingroup security
 *
 * Server-side verification of DTLS cookies sent by clients in response to
 * HelloVerifyRequest (RFC 6347 Section 4.2.1). Recomputes expected cookie
 * using current/previous server secrets and compares in constant time against
 * provided cookie. Validates binding to client IP/port and checks timestamp
 * for expiration. Supports secret rotation by trying active and previous
 * secrets.
 *
 * Constant-time HMAC comparison (via HMAC_CTX) prevents side-channel timing
 * attacks that could reveal valid cookie patterns to attackers. On success,
 * allows handshake progression; on failure, rejects with stateless error (no
 * state allocated).
 *
 * Registered via SSL_CTX_set_cookie_verify_cb(); invoked by OpenSSL on cookie
 * receipt.
 *
 * @param[in] ssl Server SSL object receiving the ClientHello with cookie
 * @param[in] cookie Client-provided cookie bytes to verify
 * @param[in] cookie_len Length of cookie data (must match expected
 * SOCKET_DTLS_COOKIE_LEN)
 *
 * @return 1 if cookie valid (matches recomputed value, current/prev secret,
 * not expired, address bound); 0 if invalid (reject handshake, send new
 * HelloVerifyRequest)
 *
 * @note
 * - Server-only callback; checks peer address via SSL_get_peer_addr() or
 * equivalent.
 * - Tries both current and previous secrets for rotation window tolerance.
 * - Expiration based on timestamp in cookie vs current time (CLOCK_MONOTONIC).
 * - On mismatch/expiry, client auto-retries with fresh cookie from
 * generate_cb.
 * - Logs verification stats/failures via SocketMetrics if enabled.
 *
 * @threadsafe Conditional - Reads shared context secrets under mutex;
 * constant-time ops safe. Concurrent verifications protected by lock on secret
 * access.
 *
 *  Usage Example
 *
 * @code{.c}
 * // Setup in context initialization
 * SSL_CTX_set_cookie_verify_cb(ctx, dtls_cookie_verify_cb);
 *
 * // Auto-called by OpenSSL:
 * // 1. Client sends ClientHello with cookie
 * // 2. OpenSSL calls this cb
 * // 3. On 1: Proceed to full handshake
 * //   On 0: Send HelloVerifyRequest + new cookie via generate_cb
 * @endcode
 *
 *  Verification Steps
 *
 * 1. Extract addr/port/timestamp from cookie structure
 * 2. Verify current peer addr matches embedded addr
 * 3. Check timestamp not expired (context window)
 * 4. Recompute HMAC with current secret; const-time compare
 * 5. If fail, retry with previous secret
 * 6. Success: return 1; fail: return 0
 *
 * @warning Weak secrets or clock skew can weaken protection; use strong
 * RAND_bytes(). Monitor reject rates for potential attacks or config issues.
 * IPv6 support requires careful addr serialization in generate_cb.
 *
 * @complexity O(1) - Dual HMAC computations, constant-time compare regardless
 * of input.
 *
 * @see dtls_cookie_generate_cb() paired generation callback
 * @see dtls_generate_cookie_hmac() core verification primitive
 * @see SocketDTLSContext_enable_cookie_exchange() to activate this mechanism
 * @see SSL_CTX_set_cookie_verify_cb() OpenSSL setup
 * @see docs/SECURITY.md#dtls-cookies for deployment guide
 * @see RFC 6347#section-4.2.1 cookie verification protocol
 */

/**
 * @brief Generate HMAC-SHA256 based DTLS cookie for address verification
 * @ingroup security
 * @param secret Server secret key for HMAC (SOCKET_DTLS_COOKIE_SECRET_LEN
 * bytes)
 * @param peer_addr Client socket address (struct sockaddr)
 * @param peer_len Length of peer address structure
 * @param out_cookie Output buffer for cookie (SOCKET_DTLS_COOKIE_LEN bytes)
 * @return 0 on success, -1 on failure
 *
 * Creates a cryptographically secure cookie using HMAC-SHA256:
 * HMAC-SHA256(secret, client_addr || client_port || timestamp)
 *
 * The cookie proves client address ownership and prevents spoofing attacks.
 * Truncated to SOCKET_DTLS_COOKIE_LEN bytes for efficiency while maintaining
 * security. Cookies have limited lifetime to prevent replay attacks.
 *
 * Used internally by dtls_cookie_generate_cb() and exposed for testing.
 * @see RFC 6347 Section 4.2.1 for cookie exchange specification
 */

/**
 * @brief Get SocketDTLSContext from SSL object.
 * @ingroup security
 * @param ssl SSL object
 * @return Context pointer or NULL
 */

/**
 * dtls_cookie_generate_cb - OpenSSL cookie generation callback
 * @ssl: SSL object
 * @cookie: Output buffer for cookie
 * @cookie_len: Output for cookie length
 *
 * @return 1 on success, 0 on failure
 */
extern int dtls_cookie_generate_cb (SSL *ssl, unsigned char *cookie,
                                    unsigned int *cookie_len);

/**
 * dtls_cookie_verify_cb - OpenSSL cookie verification callback
 * @ssl: SSL object
 * @cookie: Cookie to verify
 * @cookie_len: Cookie length
 *
 * @return 1 if valid, 0 if invalid
 */
extern int dtls_cookie_verify_cb (SSL *ssl, const unsigned char *cookie,
                                  unsigned int cookie_len);

/**
 * dtls_generate_cookie_hmac - Generate HMAC-based cookie
 * @secret: Secret key
 * @peer_addr: Peer socket address
 * @peer_len: Peer address length
 * @out_cookie: Output buffer (SOCKET_DTLS_COOKIE_LEN bytes)
 *
 * @return 0 on success, -1 on failure
 */
extern int dtls_generate_cookie_hmac (const unsigned char *secret,
                                      const struct sockaddr *peer_addr,
                                      socklen_t peer_len,
                                      unsigned char *out_cookie);

/**
 * @brief dtls_context_get_from_ssl - Get SocketDTLSContext from SSL object
 * @ingroup security
 * @param ssl SSL object
 * @return Context pointer or NULL
 *
 * Retrieves the SocketDTLSContext associated with an SSL object.
 * Used internally by DTLS callbacks to access context-specific data.
 */
extern SocketDTLSContext_T dtls_context_get_from_ssl (const SSL *ssl);

#undef T

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETDTLS_PRIVATE_INCLUDED */
