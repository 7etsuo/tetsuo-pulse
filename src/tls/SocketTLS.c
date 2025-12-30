/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketTLS.c - TLS Socket Integration
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Implements TLS/SSL integration for sockets using OpenSSL. Provides:
 * - Transparent encryption/decryption via wrapper functions
 * - Non-blocking handshake management
 * - SNI support and hostname verification
 * - Connection info queries (cipher, version, ALPN, etc.)
 * - TLS I/O operations (send/recv)
 *
 * Thread safety: Functions are not thread-safe; each socket is
 * single-threaded. Uses thread-local error buffers for exception details.
 */

#if SOCKET_HAS_TLS

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <openssl/bn.h>
#include <openssl/ocsp.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "core/SocketCrypto.h"
#include "core/SocketMetrics.h"
#include "core/SocketUtil.h"
#include "poll/SocketPoll.h"
#include "tls/SocketSSL-internal.h"
#include "tls/SocketTLS-private.h"
#include "tls/SocketTLSContext.h"

/**
 * @brief Small poll capacity for single-FD handshake polling.
 * @ingroup security
 *
 * Used internally by do_handshake_poll() for temporary SocketPoll instances.
 * 16 events is more than sufficient for single-socket handshake operations.
 */
#define TLS_HANDSHAKE_POLL_CAPACITY 16

#define T SocketTLS_T

const Except_T SocketTLS_Failed
    = { &SocketTLS_Failed, "TLS operation failed" };
const Except_T SocketTLS_HandshakeFailed
    = { &SocketTLS_HandshakeFailed, "TLS handshake failed" };
const Except_T SocketTLS_VerifyFailed
    = { &SocketTLS_VerifyFailed, "TLS certificate verification failed" };
const Except_T SocketTLS_ProtocolError
    = { &SocketTLS_ProtocolError, "TLS protocol error" };
const Except_T SocketTLS_ShutdownFailed
    = { &SocketTLS_ShutdownFailed, "TLS shutdown failed" };

SOCKET_DECLARE_MODULE_EXCEPTION (SocketTLS);

/**
 * tls_alloc_buf - Allocate a TLS buffer from socket arena
 * @socket: Socket instance
 * @purpose: Buffer purpose string ("read" or "write") for error messages
 *
 * Allocates a buffer of SOCKET_TLS_BUFFER_SIZE bytes from the socket's arena.
 * Initializes length to 0 implicitly via allocation (assuming zeroed).
 *
 * Returns: Allocated buffer pointer
 * Raises: SocketTLS_Failed on allocation failure
 * Thread-safe: No
 */
static void *
tls_alloc_buf (Socket_T socket, const char *purpose)
{
  Arena_T arena = SocketBase_arena (socket->base);
  void *buf = Arena_alloc (arena, SOCKET_TLS_BUFFER_SIZE, __FILE__, __LINE__);
  if (!buf)
    RAISE_TLS_ERROR_MSG (SocketTLS_Failed, "Failed to allocate TLS %s buffer",
                         purpose);
  return buf;
}

/**
 * allocate_tls_buffers - Allocate TLS read/write buffers
 * @socket: Socket instance
 *
 * Raises: SocketTLS_Failed if arena allocation fails
 */
static void
allocate_tls_buffers (Socket_T socket)
{
  assert (socket);
  assert (SocketBase_arena (socket->base));

  if (!socket->tls_read_buf)
    {
      socket->tls_read_buf = tls_alloc_buf (socket, "read");
      socket->tls_read_buf_len = 0;
    }

  if (!socket->tls_write_buf)
    {
      socket->tls_write_buf = tls_alloc_buf (socket, "write");
      socket->tls_write_buf_len = 0;
    }
}

/* tls_secure_clear_buf is now provided by ssl_secure_clear_buf() in
 * SocketSSL-internal.h - use that shared implementation instead */

/**
 * free_tls_resources - Cleanup TLS resources
 * @socket: Socket instance
 *
 * Securely clears sensitive TLS buffers using SocketCrypto_secure_clear before
 * releasing them. This prevents potential exposure of decrypted application
 * data through memory disclosure attacks (core dumps, cold boot, etc.).
 * Thread-safe: No
 */
static void
free_tls_resources (Socket_T socket)
{
  assert (socket);

  if (socket->tls_ssl)
    {
      SSL *ssl = (SSL *)socket->tls_ssl;
      SSL_set_app_data (ssl, NULL);
      tls_cleanup_alpn_temp (ssl); /* Free ALPN temp buffer if stored */
      SSL_free (ssl);
      socket->tls_ssl = NULL;
      socket->tls_ctx = NULL;
    }

  /* Securely clear TLS buffers that may contain sensitive decrypted data */
  ssl_secure_clear_buf (socket->tls_read_buf, SOCKET_TLS_BUFFER_SIZE);
  ssl_secure_clear_buf (socket->tls_write_buf, SOCKET_TLS_BUFFER_SIZE);

  /* Clear SNI hostname (may contain sensitive connection info) */
  ssl_secure_clear_hostname (socket->tls_sni_hostname);
  socket->tls_sni_hostname = NULL;

  socket->tls_enabled = 0;
  socket->tls_handshake_done = 0;
  socket->tls_shutdown_done = 0;
  socket->tls_read_buf = NULL;
  socket->tls_write_buf = NULL;
  socket->tls_read_buf_len = 0;
  socket->tls_write_buf_len = 0;
}

/**
 * validate_tls_enable_preconditions - Validate socket is ready for TLS
 * @socket: Socket to validate
 *
 * Raises: SocketTLS_Failed if TLS already enabled or fd invalid
 */
static void
validate_tls_enable_preconditions (Socket_T socket)
{
  if (socket->tls_enabled)
    RAISE_TLS_ERROR_MSG (SocketTLS_Failed, "TLS already enabled on socket");

  int fd = SocketBase_fd (socket->base);
  if (fd < 0)
    RAISE_TLS_ERROR_MSG (SocketTLS_Failed,
                         "Socket not connected (invalid fd)");
}

/**
 * create_ssl_object - Create and configure SSL object from context
 * @ctx: TLS context
 *
 * Returns: Configured SSL object
 * Raises: SocketTLS_Failed on creation failure
 */
static SSL *
create_ssl_object (SocketTLSContext_T ctx)
{
  SSL *ssl = SSL_new ((SSL_CTX *)SocketTLSContext_get_ssl_ctx (ctx));
  if (!ssl)
    RAISE_TLS_ERROR_MSG (SocketTLS_Failed, "Failed to create SSL object");

  if (SocketTLSContext_is_server (ctx))
    SSL_set_accept_state (ssl);
  else
    SSL_set_connect_state (ssl);

  /* Enable non-blocking modes for proper partial write handling */
  long mode = SSL_get_mode (ssl);
  SSL_set_mode (ssl, mode | SSL_MODE_ENABLE_PARTIAL_WRITE
                         | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
#ifdef SSL_MODE_AUTO_RETRY
                         SSL_MODE_AUTO_RETRY
#endif
  );

  return ssl;
}

/**
 * associate_ssl_with_fd - Associate SSL object with socket file descriptor
 * @ssl: SSL object
 * @fd: File descriptor
 *
 * Raises: SocketTLS_Failed on failure (frees SSL on error)
 */
static void
associate_ssl_with_fd (SSL *ssl, int fd)
{
  if (SSL_set_fd (ssl, fd) != 1)
    {
      tls_cleanup_alpn_temp (
          ssl); /* Cleanup any ex_data before free on error */
      SSL_free (ssl);
      RAISE_TLS_ERROR_MSG (SocketTLS_Failed,
                           "Failed to associate SSL with fd");
    }
}

/**
 * finalize_tls_state - Set final TLS state on socket
 * @socket: Socket to configure
 * @ssl: SSL object to associate
 * @ctx: TLS context
 */
static void
finalize_tls_state (Socket_T socket, SSL *ssl, SocketTLSContext_T ctx)
{
  socket->tls_ssl = (void *)ssl;
  socket->tls_ctx = (void *)ctx;
  SSL_set_app_data (ssl, socket);
  allocate_tls_buffers (socket);

  socket->tls_enabled = 1;
  socket->tls_handshake_done = 0;
  socket->tls_shutdown_done = 0;
}

void
SocketTLS_enable (Socket_T socket, SocketTLSContext_T ctx)
{
  if (!socket)
    RAISE_TLS_ERROR_MSG (SocketTLS_Failed, "Socket cannot be NULL");
  if (!ctx)
    RAISE_TLS_ERROR_MSG (SocketTLS_Failed, "TLS context cannot be NULL");
  if (!SocketTLSContext_get_ssl_ctx (ctx))
    RAISE_TLS_ERROR_MSG (SocketTLS_Failed, "TLS context has no SSL_CTX");

  validate_tls_enable_preconditions (socket);

  SSL *ssl = create_ssl_object (ctx);
  associate_ssl_with_fd (ssl, SocketBase_fd (socket->base));
  finalize_tls_state (socket, ssl, ctx);
}

/**
 * validate_hostname_nonempty - Validate hostname is non-empty
 * @hostname: Hostname to validate
 * @len: Length of hostname
 *
 * Raises: SocketTLS_Failed if empty
 *
 * Note: tls_validate_hostname() performs full RFC 6066 validation including
 * length limits. This check provides early exit for empty strings.
 */
static void
validate_hostname_nonempty (const char *hostname, size_t len)
{
  TLS_UNUSED (hostname);
  if (len == 0)
    RAISE_TLS_ERROR_MSG (SocketTLS_Failed, "Hostname cannot be empty");
}

/**
 * copy_hostname_to_socket - Copy hostname to socket arena
 * @socket: Socket instance
 * @hostname: Hostname to copy
 * @len: Length of hostname
 */
static void
copy_hostname_to_socket (Socket_T socket, const char *hostname, size_t len)
{
  socket->tls_sni_hostname = Arena_alloc (SocketBase_arena (socket->base),
                                          len + 1, __FILE__, __LINE__);
  if (!socket->tls_sni_hostname)
    RAISE_TLS_ERROR_MSG (SocketTLS_Failed,
                         "Failed to allocate hostname buffer");

  memcpy ((char *)socket->tls_sni_hostname, hostname, len + 1);
}

/**
 * apply_sni_to_ssl - Apply SNI hostname to SSL connection
 * @ssl: SSL object
 * @hostname: Hostname for SNI
 *
 * Wrapper around shared ssl_apply_sni_hostname() helper with TLS-specific
 * error handling. Enables peer certificate verification and hostname checking.
 *
 * Raises: SocketTLS_Failed on OpenSSL error
 */
static void
apply_sni_to_ssl (SSL *ssl, const char *hostname)
{
  int ret = ssl_apply_sni_hostname (ssl, hostname);
  if (ret == -1)
    RAISE_TLS_ERROR_MSG (SocketTLS_Failed, "Failed to set SNI hostname");
  if (ret == -2)
    RAISE_TLS_ERROR_MSG (SocketTLS_Failed,
                         "Failed to enable hostname verification");
}

void
SocketTLS_set_hostname (Socket_T socket, const char *hostname)
{
  assert (socket);

  if (!hostname)
    RAISE_TLS_ERROR_MSG (SocketTLS_Failed, "Hostname cannot be NULL");

  REQUIRE_TLS_ENABLED (socket, SocketTLS_Failed);

  size_t hostname_len = strlen (hostname);
  validate_hostname_nonempty (hostname, hostname_len);

  /* Explicit SNI length check (RFC 6066 limit) before format validation */
  if (hostname_len > SOCKET_TLS_MAX_SNI_LEN)
    {
      TLS_ERROR_FMT ("Hostname too long for SNI (%zu > %d max)", hostname_len,
                     SOCKET_TLS_MAX_SNI_LEN);
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }

  if (!tls_validate_hostname (hostname))
    RAISE_TLS_ERROR_MSG (SocketTLS_Failed, "Invalid hostname format");

  copy_hostname_to_socket (socket, hostname, hostname_len);

  SSL *ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    RAISE_TLS_ERROR_MSG (SocketTLS_Failed, "SSL object not available");

  apply_sni_to_ssl (ssl, hostname);
}

TLSHandshakeState
SocketTLS_handshake (Socket_T socket)
{
  if (!socket)
    RAISE_TLS_ERROR_MSG (SocketTLS_HandshakeFailed, "Socket cannot be NULL");

  REQUIRE_TLS_ENABLED (socket, SocketTLS_HandshakeFailed);

  if (socket->tls_handshake_done)
    return TLS_HANDSHAKE_COMPLETE;

  SSL *ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    {
      SocketMetrics_counter_inc (SOCKET_CTR_TLS_HANDSHAKES_FAILED);
      RAISE_TLS_ERROR_MSG (SocketTLS_HandshakeFailed,
                           "SSL object not available");
    }

  int result = SSL_do_handshake (ssl);
  if (result == 1)
    {
      socket->tls_handshake_done = 1;
      socket->tls_last_handshake_state = TLS_HANDSHAKE_COMPLETE;
      SocketMetrics_counter_inc (SOCKET_CTR_TLS_HANDSHAKES_TOTAL);

      /* Update kTLS offload status after successful handshake */
      ktls_on_handshake_complete (socket);

      return TLS_HANDSHAKE_COMPLETE;
    }

  TLSHandshakeState state = tls_handle_ssl_error (socket, ssl, result);
  if (state == TLS_HANDSHAKE_ERROR)
    {
      SocketMetrics_counter_inc (SOCKET_CTR_TLS_HANDSHAKES_TOTAL);
      SocketMetrics_counter_inc (SOCKET_CTR_TLS_HANDSHAKES_FAILED);
      tls_format_openssl_error ("Handshake failed");
      RAISE_TLS_ERROR (SocketTLS_HandshakeFailed);
    }

  socket->tls_last_handshake_state = state;
  return state;
}

/**
 * state_to_poll_events - Map TLS handshake state to poll events
 * @state: Current handshake state
 *
 * Returns: Poll event flags (POLLIN, POLLOUT, or both)
 */
static unsigned
state_to_poll_events (TLSHandshakeState state)
{
  switch (state)
    {
    case TLS_HANDSHAKE_WANT_READ:
      return POLL_READ;
    case TLS_HANDSHAKE_WANT_WRITE:
      return POLL_WRITE;
    default:
      return POLL_READ | POLL_WRITE;
    }
}

/**
 * do_handshake_poll_safe - Perform poll wait without raising exceptions
 * @socket: Socket instance
 * @events: Poll events to wait for (SocketPoll_Events bitmask)
 * @timeout_ms: Poll timeout in milliseconds
 * @error_out: Output for error message (if any, set to NULL on success)
 *
 * Exception-safe poll function that returns error codes instead of raising.
 * This prevents exception stack corruption when called repeatedly in a loop.
 *
 * Returns: 1 if socket is ready, 0 on timeout or EINTR (retry), -1 on error
 * Thread-safe: No
 */
static int
do_handshake_poll_safe (Socket_T socket, unsigned events, int timeout_ms,
                        const char **error_out)
{
  SocketPoll_T poll = NULL;
  int result = 1;
  int saved_errno;

  *error_out = NULL;

  /* Try to create poll without exceptions - use TRY but catch and convert */
  volatile int alloc_failed = 0;
  TRY
  {
    poll = SocketPoll_new (TLS_HANDSHAKE_POLL_CAPACITY);
  }
  ELSE
  {
    alloc_failed = 1;
  }
  END_TRY;

  if (alloc_failed || !poll)
    {
      *error_out = "Failed to create temporary poll instance";
      return -1;
    }

  /* Try to add socket to poll */
  volatile int add_failed = 0;
  TRY
  {
    SocketPoll_add (poll, socket, events, NULL);
  }
  ELSE
  {
    add_failed = 1;
  }
  END_TRY;

  if (add_failed)
    {
      SocketPoll_free (&poll);
      *error_out = "Failed to add socket to poll";
      return -1;
    }

  /* Perform poll wait */
  SocketEvent_T evs[TLS_HANDSHAKE_POLL_CAPACITY];
  SocketEvent_T *events_out = evs;
  int rc = SocketPoll_wait (poll, &events_out, timeout_ms);
  saved_errno = errno;

  /* Clean up poll before returning */
  SocketPoll_free (&poll);

  if (rc < 0)
    {
      if (saved_errno == EINTR)
        return 0; /* Caller should retry */
      *error_out = strerror (saved_errno);
      return -1;
    }

  /* rc >= 0: success (0=timeout, >0=ready) */
  return result;
}

/**
 * do_handshake_poll - Perform poll wait for handshake I/O using SocketPoll
 * @socket: Socket instance
 * @events: Poll events to wait for (SocketPoll_Events bitmask)
 * @timeout_ms: Poll timeout in milliseconds
 *
 * Wrapper around do_handshake_poll_safe that raises exceptions on error.
 * Used by shutdown code path where exception handling is appropriate.
 *
 * Returns: 1 if socket is ready (events occurred), 0 on timeout or EINTR
 * Raises: SocketTLS_HandshakeFailed on poll error
 * Thread-safe: No
 */
static int
do_handshake_poll (Socket_T socket, unsigned events, int timeout_ms)
{
  const char *error_msg = NULL;
  int result = do_handshake_poll_safe (socket, events, timeout_ms, &error_msg);

  if (result < 0)
    {
      TLS_ERROR_FMT ("SocketPoll failed: %s",
                     error_msg ? error_msg : "unknown error");
      RAISE_TLS_ERROR (SocketTLS_HandshakeFailed);
    }

  return result;
}

/**
 * disable_compute_shutdown_timeout - Calculate timeout for best-effort shutdown
 *
 * Returns: Timeout in milliseconds (minimum 1 second)
 * Thread-safe: Yes
 */
static int
disable_compute_shutdown_timeout (void)
{
  int timeout_ms = SOCKET_TLS_DEFAULT_SHUTDOWN_TIMEOUT_MS / 4;
  if (timeout_ms < 1000)
    timeout_ms = 1000; /* Minimum 1 second for disable */
  return timeout_ms;
}

/**
 * disable_handle_shutdown_result - Process SSL_shutdown() result for disable
 * @socket: Socket instance
 * @result: Return value from SSL_shutdown()
 * @clean_shutdown_out: Output for clean shutdown flag
 *
 * Handles the three SSL_shutdown() return values:
 * - 1: Clean bidirectional shutdown (set flag, done)
 * - 0: Unidirectional shutdown (retry once)
 * - <0: Error (will be handled by caller)
 *
 * Returns: 1 to continue loop, 0 to break
 * Thread-safe: No
 */
static int
disable_handle_shutdown_result (Socket_T socket, int result,
                                 int *clean_shutdown_out)
{
  SSL *ssl = tls_socket_get_ssl (socket);

  if (result == 1)
    {
      /* Clean bidirectional shutdown */
      *clean_shutdown_out = 1;
      socket->tls_shutdown_done = 1;
      return 0; /* Break loop */
    }
  else if (result == 0)
    {
      /* Unidirectional shutdown sent, need peer response */
      /* Try once more then accept partial shutdown */
      result = SSL_shutdown (ssl);
      if (result == 1)
        {
          *clean_shutdown_out = 1;
          socket->tls_shutdown_done = 1;
        }
      return 0; /* Break loop */
    }

  return 1; /* Continue loop (error case handled by caller) */
}

/**
 * disable_handle_io_wait - Handle I/O wait for SSL_shutdown retry
 * @socket: Socket instance
 * @ssl: SSL object
 * @result: SSL_shutdown() result (negative value)
 * @deadline: Shutdown deadline timestamp
 *
 * Checks if SSL_shutdown needs I/O wait (WANT_READ/WANT_WRITE) and performs
 * brief poll if needed. Best-effort operation - ignores poll errors.
 *
 * Returns: 1 to continue retry loop, 0 to break
 * Thread-safe: No
 */
static int
disable_handle_io_wait (Socket_T socket, SSL *ssl, int result, int64_t deadline)
{
  int err = SSL_get_error (ssl, result);

  if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
    {
      /* Brief poll then retry */
      unsigned events = (err == SSL_ERROR_WANT_READ) ? POLL_READ : POLL_WRITE;
      int poll_timeout = SocketTimeout_poll_timeout (100, deadline);

      if (poll_timeout > 0)
        {
          /* Simple poll - ignore errors, best-effort */
          (void)do_handshake_poll (socket, events, poll_timeout);
          return 1; /* Continue retry */
        }
    }

  /* Other error or timeout - accept incomplete shutdown */
  return 0;
}

/**
 * disable_perform_shutdown_loop - Attempt SSL shutdown with retry loop
 * @socket: Socket instance
 * @ssl: SSL object
 * @timeout_ms: Timeout in milliseconds
 *
 * Best-effort SSL shutdown with limited retries. Handles:
 * - Bidirectional shutdown (complete)
 * - Unidirectional shutdown (partial, one retry)
 * - I/O blocking (brief poll then retry)
 * - Timeout (accept incomplete)
 *
 * Returns: 1 if clean shutdown, 0 if partial/failed
 * Thread-safe: No
 */
static int
disable_perform_shutdown_loop (Socket_T socket, SSL *ssl, int timeout_ms)
{
  int clean_shutdown = 0;
  int64_t deadline = SocketTimeout_deadline_ms (timeout_ms);

  while (!SocketTimeout_expired (deadline))
    {
      int result = SSL_shutdown (ssl);

      /* Handle successful or partial shutdown */
      if (!disable_handle_shutdown_result (socket, result, &clean_shutdown))
        break;

      /* result < 0: check if we need to wait for I/O */
      if (!disable_handle_io_wait (socket, ssl, result, deadline))
        break;
    }

  return clean_shutdown;
}

int
SocketTLS_disable (Socket_T socket)
{
  if (!socket)
    RAISE_TLS_ERROR_MSG (SocketTLS_Failed, "Socket cannot be NULL");

  /* Check if TLS is even enabled - no-op if not */
  if (!socket->tls_enabled)
    return 0;

  int clean_shutdown = 0;

  /* Check if already shutdown */
  if (socket->tls_shutdown_done)
    {
      clean_shutdown = 1;
    }
  else
    {
      /* Attempt graceful SSL shutdown (best-effort, no exceptions) */
      SSL *ssl = tls_socket_get_ssl (socket);
      if (ssl)
        {
          int timeout_ms = disable_compute_shutdown_timeout ();
          clean_shutdown = disable_perform_shutdown_loop (socket, ssl, timeout_ms);
        }
    }

  /* Always clean up TLS resources regardless of shutdown result */
  free_tls_resources (socket);

  /* Socket is now in plain mode - return status */
  return clean_shutdown ? 1 : 0;
}

/**
 * validate_handshake_preconditions - Check socket is ready for handshake loop
 * @socket: Socket to validate
 *
 * Raises: SocketTLS_HandshakeFailed on error
 * Thread-safe: No
 */
static void
validate_handshake_preconditions (Socket_T socket)
{
  REQUIRE_TLS_ENABLED (socket, SocketTLS_HandshakeFailed);

  int fd = SocketBase_fd (socket->base);
  if (fd < 0)
    RAISE_TLS_ERROR_MSG (SocketTLS_HandshakeFailed, "Invalid socket fd");
}

/**
 * handshake_record_duration - Record handshake timing metrics
 * @start_time_ms: Start time in milliseconds (0 to skip recording)
 *
 * Records successful handshake duration in histogram if timing is enabled.
 *
 * Thread-safe: No
 */
static void
handshake_record_duration (int64_t start_time_ms)
{
  if (start_time_ms > 0)
    {
      int64_t elapsed_ms = SocketTimeout_elapsed_ms (start_time_ms);
      SocketMetrics_histogram_observe (SOCKET_HIST_TLS_HANDSHAKE_TIME_MS,
                                        (double)elapsed_ms);
    }
}

/**
 * handshake_check_timeout - Check for timeout and raise exception if expired
 * @deadline: Deadline timestamp (0 if no timeout)
 * @timeout_ms: Original timeout value in milliseconds
 * @start_time_ms: Start time for elapsed calculation (0 to use timeout_ms)
 *
 * Raises: SocketTLS_HandshakeFailed if timeout expired
 * Thread-safe: No
 */
static void
handshake_check_timeout (int64_t deadline, int timeout_ms,
                         int64_t start_time_ms)
{
  if (!SocketTimeout_expired (deadline))
    return;

  int64_t elapsed_ms = (start_time_ms > 0)
                           ? SocketTimeout_elapsed_ms (start_time_ms)
                           : (int64_t)timeout_ms;

  SocketMetrics_counter_inc (SOCKET_CTR_TLS_HANDSHAKES_TOTAL);
  SocketMetrics_counter_inc (SOCKET_CTR_TLS_HANDSHAKES_FAILED);
  tls_format_openssl_error ("TLS handshake timeout");
  RAISE_TLS_ERROR_MSG (SocketTLS_HandshakeFailed,
                       "TLS handshake timeout after %lld ms (timeout: %d ms)",
                       (long long)elapsed_ms, timeout_ms);
}

/**
 * handshake_wait_for_io - Wait for I/O readiness during handshake
 * @socket: Socket instance
 * @state: Current handshake state
 * @poll_interval_ms: Poll interval in milliseconds
 * @deadline: Deadline timestamp (0 if no timeout)
 *
 * Performs exception-safe polling and raises on error.
 *
 * Returns: 1 if socket ready, 0 on timeout/EINTR (retry)
 * Raises: SocketTLS_HandshakeFailed on poll error
 * Thread-safe: No
 */
static int
handshake_wait_for_io (Socket_T socket, TLSHandshakeState state,
                       int poll_interval_ms, int64_t deadline)
{
  unsigned events = state_to_poll_events (state);
  int poll_timeout = SocketTimeout_poll_timeout (poll_interval_ms, deadline);

  const char *error_msg = NULL;
  int poll_result
      = do_handshake_poll_safe (socket, events, poll_timeout, &error_msg);

  if (poll_result < 0)
    {
      SocketMetrics_counter_inc (SOCKET_CTR_TLS_HANDSHAKES_TOTAL);
      SocketMetrics_counter_inc (SOCKET_CTR_TLS_HANDSHAKES_FAILED);
      TLS_ERROR_FMT ("SocketPoll_wait failed: %s",
                     error_msg ? error_msg : "unknown");
      RAISE_TLS_ERROR (SocketTLS_HandshakeFailed);
    }

  return poll_result;
}

/**
 * handshake_loop_internal - Internal handshake loop with configurable poll
 * interval
 * @socket: Socket to handshake
 * @timeout_ms: Total timeout in milliseconds (0 for non-blocking)
 * @poll_interval_ms: Poll interval in milliseconds between handshake attempts
 * @start_time_ms: Start time for elapsed time tracking (0 to not track)
 *
 * Uses single top-level TRY block to prevent exception stack corruption.
 * Internal poll operations use do_handshake_poll_safe() which returns error
 * codes instead of raising exceptions. Exceptions from SocketTLS_handshake()
 * are caught and converted to error state.
 *
 * Returns: TLSHandshakeState
 * Raises: SocketTLS_HandshakeFailed on timeout or error
 */
static TLSHandshakeState
handshake_loop_internal (Socket_T socket, int timeout_ms, int poll_interval_ms,
                         int64_t start_time_ms)
{
  volatile int64_t deadline
      = (timeout_ms > 0) ? SocketTimeout_deadline_ms (timeout_ms) : 0LL;

  volatile TLSHandshakeState final_state = TLS_HANDSHAKE_ERROR;

  /* Single TRY block at top level - exceptions from handshake are caught */
  TRY
  {
    while (1)
      {
        TLSHandshakeState state = SocketTLS_handshake (socket);

        if (state == TLS_HANDSHAKE_COMPLETE)
          {
            handshake_record_duration (start_time_ms);
            final_state = state;
            break; /* Success - exit loop */
          }

        if (state == TLS_HANDSHAKE_ERROR)
          {
            final_state = state;
            break; /* Error already handled by SocketTLS_handshake */
          }

        /* Non-blocking mode: return current state immediately */
        if (timeout_ms == 0)
          {
            final_state = state;
            break;
          }

        /* Check timeout and raise if expired */
        handshake_check_timeout (deadline, timeout_ms, start_time_ms);

        /* Wait for I/O - raises on error, returns 0/1 on success */
        int poll_result
            = handshake_wait_for_io (socket, state, poll_interval_ms, deadline);

        /* poll_result == 0: EINTR or partial timeout, continue loop */
        /* poll_result == 1: socket ready, retry handshake */
        (void)poll_result;
      }
  }
  EXCEPT (SocketTLS_HandshakeFailed)
  {
    /* Handshake raised exception - metrics already updated by handshake */
    final_state = TLS_HANDSHAKE_ERROR;
  }
  END_TRY;

  return final_state;
}

/**
 * handshake_loop_with_defaults - Common handshake loop with preconditions
 * @socket: Socket to handshake
 * @timeout_ms: Total timeout in milliseconds (0 for non-blocking)
 * @poll_interval_ms: Poll interval in milliseconds between attempts
 *
 * Handles common preconditions and delegates to handshake_loop_internal.
 * Checks if handshake is already complete, validates preconditions,
 * and tracks timing for metrics.
 *
 * Returns: TLSHandshakeState
 * Raises: SocketTLS_HandshakeFailed on timeout or error
 * Thread-safe: No
 */
static TLSHandshakeState
handshake_loop_with_defaults (Socket_T socket, int timeout_ms,
                               int poll_interval_ms)
{
  assert (socket);

  if (socket->tls_handshake_done)
    return TLS_HANDSHAKE_COMPLETE;

  validate_handshake_preconditions (socket);

  int64_t start_time_ms = Socket_get_monotonic_ms ();
  return handshake_loop_internal (socket, timeout_ms, poll_interval_ms,
                                  start_time_ms);
}

TLSHandshakeState
SocketTLS_handshake_loop (Socket_T socket, int timeout_ms)
{
  return handshake_loop_with_defaults (socket, timeout_ms,
                                       SOCKET_TLS_POLL_INTERVAL_MS);
}

TLSHandshakeState
SocketTLS_handshake_loop_ex (Socket_T socket, int timeout_ms,
                             int poll_interval_ms)
{
  /* Validate poll interval - use default if invalid */
  if (poll_interval_ms <= 0)
    poll_interval_ms = SOCKET_TLS_POLL_INTERVAL_MS;

  return handshake_loop_with_defaults (socket, timeout_ms, poll_interval_ms);
}

TLSHandshakeState
SocketTLS_handshake_auto (Socket_T socket)
{
  int timeout_ms;

  assert (socket);

  /* Use socket's operation timeout, falling back to TLS default */
  timeout_ms = socket->base->timeouts.operation_timeout_ms;
  if (timeout_ms <= 0)
    timeout_ms = SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS;

  return SocketTLS_handshake_loop (socket, timeout_ms);
}

/**
 * shutdown_handle_ssl_error - Handle SSL_shutdown errors in non-blocking mode
 * @socket: Socket instance
 * @ssl: SSL object
 * @result: SSL_shutdown() return value
 * @want_events_out: Output for poll events needed (POLL_READ/POLL_WRITE)
 *
 * Returns: 1 if should continue polling, 0 if fatal error occurred
 * Thread-safe: No
 *
 * Unlike handshake error handling, shutdown treats EAGAIN/WANT_* as
 * non-fatal - we continue polling. Only protocol errors are fatal.
 */
static int
shutdown_handle_ssl_error (Socket_T socket, SSL *ssl, int result,
                           unsigned *want_events_out)
{
  int ssl_error = SSL_get_error (ssl, result);

  *want_events_out = 0;

  switch (ssl_error)
    {
    case SSL_ERROR_WANT_READ:
      *want_events_out = POLL_READ;
      errno = EAGAIN;
      return 1; /* Continue polling */

    case SSL_ERROR_WANT_WRITE:
      *want_events_out = POLL_WRITE;
      errno = EAGAIN;
      return 1; /* Continue polling */

    case SSL_ERROR_SYSCALL:
      /* System call error during shutdown.
       * If errno is EAGAIN/EWOULDBLOCK, the operation just needs to be
       * retried. If errno is 0 with result 0, peer closed unexpectedly. Other
       * errors (ECONNRESET, EPIPE, etc.) indicate connection lost - not fatal
       * for shutdown since we're closing anyway. */
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
          *want_events_out = POLL_READ | POLL_WRITE;
          return 1; /* Continue polling */
        }
      if (errno == 0)
        errno = ECONNRESET;
      /* Connection lost during shutdown - mark as done (partial) */
      socket->tls_shutdown_done = 0; /* Partial/failed shutdown */
      return 0;                       /* Stop, but don't raise exception */

    case SSL_ERROR_ZERO_RETURN:
      /* Peer already sent close_notify - we're done */
      socket->tls_shutdown_done = 1;
      return 0; /* Complete - stop looping */

    case SSL_ERROR_SSL:
      /* Protocol error - this is a real failure */
      errno = EPROTO;
      tls_format_openssl_error ("TLS shutdown protocol error");
      return -1; /* Fatal error */

    default:
      /* Unknown error */
      errno = EIO;
      tls_format_openssl_error ("TLS shutdown unknown error");
      return -1; /* Fatal error */
    }
}

/**
 * shutdown_handle_result - Process SSL_shutdown return value
 * @socket: Socket instance
 * @ssl: SSL object
 * @result: Return value from SSL_shutdown()
 *
 * Returns: 0 if complete, 1 if need to continue, -1 if error (raises exception)
 * Thread-safe: No
 *
 * Handles the three possible SSL_shutdown() return values:
 * - 1: Complete bidirectional shutdown
 * - 0: Unidirectional shutdown (continue polling)
 * - <0: Error condition (uses shutdown_handle_ssl_error)
 */
static int
shutdown_handle_result (Socket_T socket, SSL *ssl, int result)
{
  if (result == 1)
    {
      /* Complete bidirectional shutdown: both close_notify sent and received */
      socket->tls_shutdown_done = 1;
      free_tls_resources (socket);
      return 0;
    }
  else if (result == 0)
    {
      /* Unidirectional shutdown: our close_notify sent, waiting for peer.
       * Per SSL_shutdown(3): "A second call is needed to complete the
       * bidirectional shutdown." Continue looping after poll. */
      return 1;
    }
  else /* result < 0 */
    {
      unsigned want_events = 0;
      int cont = shutdown_handle_ssl_error (socket, ssl, result, &want_events);
      if (cont < 0)
        {
          /* Fatal protocol error - raise exception */
          free_tls_resources (socket);
          RAISE_TLS_ERROR (SocketTLS_ShutdownFailed);
        }
      if (cont == 0)
        {
          /* Shutdown complete or connection lost - clean up and return */
          free_tls_resources (socket);
          return 0;
        }
      /* cont == 1: WANT_READ/WRITE - poll and retry */
      return 1;
    }
}

/**
 * shutdown_wait_for_io - Wait for I/O readiness during shutdown
 * @socket: Socket instance
 * @deadline: Deadline timestamp in milliseconds
 *
 * Returns: 1 to continue, 0 to stop (timeout or EINTR)
 * Thread-safe: No
 *
 * Polls for I/O events needed for shutdown to progress. Uses a timeout
 * slice to check deadline periodically.
 */
static int
shutdown_wait_for_io (Socket_T socket, int64_t deadline)
{
  unsigned events = POLL_READ | POLL_WRITE; /* Shutdown may need both */
  int poll_timeout
      = SocketTimeout_poll_timeout (SOCKET_TLS_POLL_INTERVAL_MS, deadline);
  if (poll_timeout < 0)
    return 0; /* Timeout expired */
  if (!do_handshake_poll (socket, events, poll_timeout))
    return 1; /* EINTR or timeout slice, check deadline again */
  return 1;
}

/**
 * shutdown_finalize - Finalize shutdown on timeout
 * @socket: Socket instance
 * @timeout_ms: Timeout value in milliseconds (for error message)
 *
 * Raises: SocketTLS_ShutdownFailed exception
 * Thread-safe: No
 *
 * Performs partial shutdown attempt and raises timeout exception.
 * Called when shutdown loop times out.
 */
static void
shutdown_finalize (Socket_T socket, int timeout_ms)
{
  /* Timeout - perform partial shutdown (send our close_notify if possible) */
  SSL *ssl = tls_socket_get_ssl (socket);
  if (ssl)
    {
      /* Try one more non-blocking SSL_shutdown to send close_notify */
      (void)SSL_shutdown (ssl);
    }

  /* Mark as partial shutdown and clean up without raising exception for
   * timeout. Timeout during shutdown is not critical - we sent our
   * close_notify (or tried to), and the socket will be closed anyway. */
  socket->tls_shutdown_done = 0; /* Partial shutdown */
  free_tls_resources (socket);

  /* For strict mode, raise exception on timeout. Most applications don't need
   * this level of strictness since the connection is being closed anyway. */
  TLS_ERROR_FMT ("TLS shutdown timeout after %d ms", timeout_ms);
  RAISE_TLS_ERROR (SocketTLS_ShutdownFailed);
}

void
SocketTLS_shutdown (Socket_T socket)
{
  assert (socket);

  REQUIRE_TLS_ENABLED (socket, SocketTLS_ShutdownFailed);

  if (socket->tls_shutdown_done)
    return;

  /* Use socket operation timeout or default shutdown timeout */
  int timeout_ms = socket->base->timeouts.operation_timeout_ms;
  if (timeout_ms <= 0)
    timeout_ms = SOCKET_TLS_DEFAULT_SHUTDOWN_TIMEOUT_MS;

  int64_t deadline = SocketTimeout_deadline_ms (timeout_ms);

  while (!SocketTimeout_expired (deadline))
    {
      SSL *ssl = tls_socket_get_ssl (socket);
      if (!ssl)
        {
          tls_format_openssl_error (
              "SSL object not available during shutdown");
          free_tls_resources (socket);
          RAISE_TLS_ERROR_MSG (SocketTLS_ShutdownFailed,
                               "SSL object lost during shutdown");
        }

      int result = SSL_shutdown (ssl);
      int cont = shutdown_handle_result (socket, ssl, result);
      if (cont == 0)
        return; /* Shutdown complete */

      /* Need I/O for remaining shutdown steps */
      if (!shutdown_wait_for_io (socket, deadline))
        break; /* Timeout expired */
    }

  shutdown_finalize (socket, timeout_ms);
}

/**
 * SocketTLS_shutdown_send - Send close_notify without waiting for peer
 * response
 * @socket: Socket with TLS enabled
 *
 * Performs a unidirectional (half-close) TLS shutdown by sending the
 * close_notify alert without waiting for the peer's response. This is
 * useful when:
 * - You want faster connection teardown
 * - You don't need to verify peer received the alert
 * - The underlying socket will be closed immediately after
 *
 * For non-blocking sockets, this function will attempt to send the
 * close_notify immediately. If it would block, it returns 0 with
 * errno=EAGAIN, and the caller should poll for POLL_WRITE and retry.
 *
 * Returns: 1 on success (close_notify sent),
 *          0 if would block (errno=EAGAIN) - retry after poll,
 *          -1 if TLS not enabled or already shutdown
 *
 * Raises: SocketTLS_ShutdownFailed on protocol error
 * Thread-safe: No
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Quick shutdown - don't wait for peer
 * int ret = SocketTLS_shutdown_send(sock);
 * if (ret == 0 && errno == EAGAIN) {
 *     // For non-blocking, poll and retry if needed
 *     // Or just proceed to close - best effort
 * }
 * Socket_close(sock);
 * @endcode
 *
 * @see SocketTLS_shutdown() for bidirectional shutdown
 */
int
SocketTLS_shutdown_send (Socket_T socket)
{
  assert (socket);

  if (!socket->tls_enabled)
    return -1;

  if (socket->tls_shutdown_done)
    return 1; /* Already done */

  SSL *ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    return -1;

  /* Set quiet shutdown mode to skip waiting for peer's close_notify */
  SSL_set_quiet_shutdown (ssl, 1);

  int result = SSL_shutdown (ssl);

  if (result >= 0)
    {
      /* result == 0: close_notify sent (unidirectional shutdown complete)
       * result == 1: full shutdown (shouldn't happen with quiet mode, but ok)
       */
      socket->tls_shutdown_done = 1;
      return 1;
    }

  /* result < 0: check error */
  int ssl_error = SSL_get_error (ssl, result);

  switch (ssl_error)
    {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      errno = EAGAIN;
      return 0; /* Would block - caller should retry */

    case SSL_ERROR_SYSCALL:
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return 0; /* Would block */
      /* Connection error - treat as partial success (we tried) */
      socket->tls_shutdown_done = 0;
      return 1;

    case SSL_ERROR_SSL:
      /* Protocol error */
      tls_format_openssl_error ("TLS shutdown_send protocol error");
      RAISE_TLS_ERROR (SocketTLS_ShutdownFailed);
      __builtin_unreachable (); /* RAISE never returns */

    default:
      /* Unknown or zero return - treat as success */
      socket->tls_shutdown_done = 1;
      return 1;
    }
}

/**
 * SocketTLS_send - Send data over a TLS-encrypted connection
 * @socket: Socket with completed TLS handshake
 * @buf: Buffer containing data to send
 * @len: Number of bytes to send
 *
 * Sends data using SSL_write() with proper partial write handling when
 * SSL_MODE_ENABLE_PARTIAL_WRITE is enabled. For non-blocking sockets,
 * returns 0 with errno=EAGAIN when the operation would block.
 *
 * ## Partial Write Handling
 *
 * With SSL_MODE_ENABLE_PARTIAL_WRITE (enabled by default), SSL_write() may
 * return a value less than len. The caller should retry with the remaining
 * data. This differs from blocking mode where SSL_write() waits until all
 * bytes are sent or an error occurs.
 *
 * ## Zero-Length Operations
 *
 * Sending zero bytes returns 0 immediately without invoking SSL_write().
 * This prevents undefined behavior in OpenSSL and provides consistent
 * semantics with POSIX send().
 *
 * ## Large Buffer Handling
 *
 * Buffers larger than INT_MAX are capped to INT_MAX per call since OpenSSL
 * uses int for lengths. Caller should loop to send all data if needed.
 *
 * Returns: Number of bytes sent (may be < len with partial writes),
 *          0 if would block (errno=EAGAIN)
 * Raises: SocketTLS_Failed on TLS error
 * Thread-safe: No - operates on per-connection SSL state
 */
ssize_t
SocketTLS_send (Socket_T socket, const void *buf, size_t len)
{
  assert (socket);
  assert (buf || len == 0);

  /* Handle zero-length send: return 0 immediately (POSIX semantics) */
  if (len == 0)
    return 0;

  SSL *ssl = VALIDATE_TLS_IO_READY (socket, SocketTLS_Failed);

  /* Cap length to INT_MAX to prevent truncation on 64-bit systems.
   * SSL_write uses int for length, so we must stay within INT_MAX. */
  int write_len = (len > (size_t)INT_MAX) ? INT_MAX : (int)len;
  int result = SSL_write (ssl, buf, write_len);

  if (result > 0)
    {
      /* Partial write success: SSL_MODE_ENABLE_PARTIAL_WRITE allows
       * result < write_len. Caller should loop for remaining data. */
      return (ssize_t)result;
    }

  ssize_t handled = tls_handle_ssl_write_result (ssl, result, "TLS send");
  if (handled < -1)
    {
      RAISE (Socket_Closed);
    }
  else if (handled < 0)
    {
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }
  return handled;

  /* Unreachable - all cases either return or raise */
  return -1;
}

/**
 * handle_ssl_read_error - Handle SSL_read error conditions
 * @ssl: SSL connection object
 * @result: Raw result from SSL_read
 * @ssl_error: Error code from SSL_get_error
 *
 * Processes SSL_read error conditions and takes appropriate action.
 * Returns 0 for EAGAIN (caller should retry), or raises exceptions
 * for fatal errors and connection close events.
 *
 * Error handling:
 * - SSL_ERROR_ZERO_RETURN: Clean shutdown (raises Socket_Closed)
 * - SSL_ERROR_WANT_READ/WRITE: Non-blocking would-block (returns 0, errno=EAGAIN)
 * - SSL_ERROR_SYSCALL: System error or abrupt close (raises exception)
 * - SSL_ERROR_SSL: Protocol error (raises SocketTLS_Failed)
 * - Default: Unknown error (raises SocketTLS_Failed)
 *
 * Returns: 0 for would-block (EAGAIN)
 * Raises: Socket_Closed on clean/abrupt shutdown,
 *         SocketTLS_Failed on protocol or syscall errors
 * Thread-safe: Yes - operates on per-connection SSL state
 */
static ssize_t
handle_ssl_read_error (SSL *ssl, int result, int ssl_error)
{
  (void)ssl; /* Unused - reserved for future use */

  switch (ssl_error)
    {
    case SSL_ERROR_ZERO_RETURN:
      /* Clean shutdown: peer sent close_notify alert.
       * This is a graceful connection termination - no data lost.
       * Set errno to 0 to indicate clean shutdown, then raise. */
      errno = 0;
      RAISE (Socket_Closed);
      __builtin_unreachable (); /* RAISE never returns */

    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      /* Non-blocking: would block, set errno and return 0.
       * Note: WANT_WRITE can occur during renegotiation even on recv.
       * Caller should poll for appropriate events and retry. */
      errno = EAGAIN;
      return 0;

    case SSL_ERROR_SYSCALL:
      /* System call error - check errno for details.
       * errno = 0 with result = 0: Unexpected EOF (peer closed abruptly).
       * This differs from SSL_ERROR_ZERO_RETURN which is a clean shutdown.
       *
       * Per OpenSSL docs: "Some I/O error occurred. The retrying may be
       * possible but the caller must ensure that the error wasn't fatal."
       * With errno = 0 and result = 0, it means unexpected EOF. */
      if (result == 0 && errno == 0)
        {
          /* Abrupt close: peer disconnected without close_notify.
           * This could indicate a truncation attack or network failure.
           * Set ECONNRESET to distinguish from clean shutdown. */
          errno = ECONNRESET;
          RAISE (Socket_Closed);
          __builtin_unreachable (); /* RAISE never returns */
        }
      /* Other syscall error - errno is already set appropriately */
      tls_format_openssl_error ("TLS recv failed (syscall)");
      RAISE_TLS_ERROR (SocketTLS_Failed);
      __builtin_unreachable (); /* RAISE never returns */

    case SSL_ERROR_SSL:
      /* Protocol error - fatal TLS failure (e.g., bad record MAC,
       * decompression failure, handshake failure during renegotiation). */
      errno = EPROTO;
      tls_format_openssl_error ("TLS recv failed (protocol)");
      RAISE_TLS_ERROR (SocketTLS_Failed);
      __builtin_unreachable (); /* RAISE never returns */

    default:
      /* Unknown error type - should not happen with current OpenSSL */
      errno = EIO;
      tls_format_openssl_error ("TLS recv failed (unknown)");
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }

  /* Unreachable - all cases either return or raise */
  return -1;
}

/**
 * SocketTLS_recv - Receive data from a TLS-encrypted connection
 * @socket: Socket with completed TLS handshake
 * @buf: Buffer to receive data into
 * @len: Maximum bytes to receive
 *
 * Receives data using SSL_read() with proper handling of all error cases.
 * Distinguishes between clean peer shutdown (SSL_ERROR_ZERO_RETURN) and
 * abrupt connection close (SSL_ERROR_SYSCALL with EOF).
 *
 * ## Shutdown Handling
 *
 * - **Clean shutdown (SSL_ERROR_ZERO_RETURN)**: Peer sent close_notify alert.
 *   This raises Socket_Closed to indicate graceful connection termination.
 *   The TLS session ended properly without data loss.
 *
 * - **Abrupt close (SSL_ERROR_SYSCALL with errno=0)**: Connection reset or
 *   closed without close_notify. This also raises Socket_Closed but with
 *   errno=ECONNRESET to indicate potential data truncation.
 *
 * ## Non-blocking Operation
 *
 * For non-blocking sockets, returns 0 with errno=EAGAIN when the operation
 * would block. Caller should poll for POLL_READ and retry.
 *
 * ## Zero-Length Operations
 *
 * Receiving into a zero-length buffer returns 0 immediately without invoking
 * SSL_read(). This prevents undefined behavior and matches POSIX recv().
 *
 * ## Large Buffer Handling
 *
 * Buffers larger than INT_MAX are capped to INT_MAX per call since OpenSSL
 * uses int for lengths. This is typically not an issue since TLS records
 * are limited to 16KB.
 *
 * Returns: Number of bytes received (> 0 on success),
 *          0 if would block (errno=EAGAIN)
 * Raises: Socket_Closed on clean shutdown or peer disconnect,
 *         SocketTLS_Failed on TLS protocol error
 * Thread-safe: No - operates on per-connection SSL state
 */
ssize_t
SocketTLS_recv (Socket_T socket, void *buf, size_t len)
{
  assert (socket);
  assert (buf || len == 0);

  /* Handle zero-length recv: return 0 immediately (POSIX semantics) */
  if (len == 0)
    return 0;

  SSL *ssl = VALIDATE_TLS_IO_READY (socket, SocketTLS_Failed);

  /* Cap length to INT_MAX to prevent truncation on 64-bit systems.
   * SSL_read uses int for length, so we must stay within INT_MAX. */
  int read_len = (len > (size_t)INT_MAX) ? INT_MAX : (int)len;
  int result = SSL_read (ssl, buf, read_len);

  if (result > 0)
    return (ssize_t)result;

  /* result <= 0: Must call SSL_get_error to determine the actual error.
   * Note: SSL_read returning 0 does NOT always mean clean shutdown;
   * SSL_get_error must be consulted for the definitive error code. */
  int ssl_error = SSL_get_error (ssl, result);

  return handle_ssl_read_error (ssl, result, ssl_error);
}

const char *
SocketTLS_get_cipher (Socket_T socket)
{
  assert (socket);

  SSL *ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    return NULL;

  const SSL_CIPHER *cipher = SSL_get_current_cipher (ssl);
  return cipher ? SSL_CIPHER_get_name (cipher) : NULL;
}

const char *
SocketTLS_get_version (Socket_T socket)
{
  assert (socket);

  SSL *ssl = tls_socket_get_ssl (socket);
  return ssl ? SSL_get_version (ssl) : NULL;
}

int
SocketTLS_get_protocol_version (Socket_T socket)
{
  assert (socket);

  SSL *ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    return 0;

  /* SSL_version() returns the protocol version:
   * TLS1_VERSION (0x0301), TLS1_1_VERSION (0x0302),
   * TLS1_2_VERSION (0x0303), TLS1_3_VERSION (0x0304) */
  return SSL_version (ssl);
}

long
SocketTLS_get_verify_result (Socket_T socket)
{
  SSL *ssl;

  if (!socket || !socket->tls_enabled || !socket->tls_ssl
      || !socket->tls_handshake_done)
    {
      return X509_V_ERR_INVALID_CALL;
    }

  ssl = (SSL *)socket->tls_ssl;
  return SSL_get_verify_result (ssl);
}

const char *
SocketTLS_get_verify_error_string (Socket_T socket, char *buf, size_t size)
{
  if (!socket || !buf || size == 0)
    return NULL;

  long code = SocketTLS_get_verify_result (socket);
  if (code == X509_V_OK)
    return NULL;

  const char *code_str = X509_verify_cert_error_string (code);
  if (code_str)
    {
      socket_util_safe_strncpy (buf, code_str, size);
      return buf;
    }

  unsigned long err = ERR_get_error ();
  if (err)
    {
      ERR_error_string_n (err, buf, size);
      ERR_clear_error (); /* Clear the error queue after reading */
      return buf;
    }

  socket_util_safe_strncpy (buf, "TLS verification failed (unknown error)", size);
  return buf;
}

int
SocketTLS_is_session_reused (Socket_T socket)
{
  assert (socket);

  /* Validate preconditions */
  if (!socket->tls_enabled)
    return -1;

  if (!socket->tls_handshake_done)
    return -1; /* Must complete handshake first */

  SSL *ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    return -1;

  /* SSL_session_reused() returns 1 if a session was reused, 0 otherwise.
   * For TLS 1.3, this indicates PSK resumption was used. */
  return SSL_session_reused (ssl) ? 1 : 0;
}

const char *
SocketTLS_get_alpn_selected (Socket_T socket)
{
  assert (socket);

  SSL *ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    return NULL;

  const unsigned char *alpn_data;
  unsigned int alpn_len;
  SSL_get0_alpn_selected (ssl, &alpn_data, &alpn_len);

  if (!alpn_data || alpn_len == 0 || alpn_len > SOCKET_TLS_MAX_ALPN_LEN)
    return NULL;

  char *proto_copy = Arena_alloc (SocketBase_arena (socket->base),
                                  alpn_len + 1, __FILE__, __LINE__);
  if (!proto_copy)
    return NULL;

  memcpy (proto_copy, alpn_data, alpn_len);
  proto_copy[alpn_len] = '\0';
  return proto_copy;
}

/**
 * SocketTLS_session_save - Export TLS session for later resumption
 * @socket: Socket with completed TLS handshake
 * @buffer: Buffer to store serialized session (NULL to query size only)
 * @len: On input: buffer size; On output: actual/required session size
 *
 * Exports the current TLS session data in DER format for persistent storage
 * or transfer. The session can be restored with SocketTLS_session_restore()
 * for abbreviated handshakes (session resumption).
 *
 * ## TLS 1.3 Considerations
 *
 * TLS 1.3 uses session tickets delivered asynchronously via NewSessionTicket
 * messages AFTER the handshake completes. Key points:
 *
 * 1. **Timing**: For TLS 1.3, this function may return -1 if called
 *    immediately after handshake. Session tickets are typically sent by the
 *    server shortly after handshake. Wait for I/O activity or use a callback.
 *
 * 2. **Multiple tickets**: TLS 1.3 servers may send multiple session tickets.
 *    Only the most recent is captured by SSL_get1_session().
 *
 * 3. **Ticket lifetime**: TLS 1.3 sessions have limited validity set by the
 *    server. Check the session's lifetime before storage.
 *
 * ## Buffer Sizing
 *
 * To determine required buffer size, call with buffer=NULL or with a buffer:
 * - If buffer is too small, returns 0 and sets *len to required size
 * - If buffer is NULL, returns 0 and sets *len to required size
 *
 * Returns: 1 on success (session saved),
 *          0 if buffer too small (len updated with required size),
 *          -1 on error (no session, TLS not enabled, handshake incomplete)
 *
 * Thread-safe: No
 *
 * @note Session data is sensitive - store securely (encrypted at rest)
 * @warning For TLS 1.3, call after some I/O to ensure ticket receipt
 */
int
SocketTLS_session_save (Socket_T socket, unsigned char *buffer, size_t *len)
{
  assert (socket);
  assert (len);

  /* Validate preconditions */
  if (!socket->tls_enabled)
    return -1;

  if (!socket->tls_handshake_done)
    return -1; /* Must complete handshake first */

  SSL *ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    return -1;

  /* Get session - for TLS 1.3, this returns the most recent ticket.
   * SSL_get1_session() increments reference count, we must free it. */
  SSL_SESSION *session = SSL_get1_session (ssl);
  if (!session)
    {
      /* No session available. For TLS 1.3, this might mean:
       * - Server hasn't sent NewSessionTicket yet (call later)
       * - Server disabled session tickets
       * - Session already expired */
      return -1;
    }

  /* Check if session is still valid (TLS 1.3 sessions can expire quickly) */
  time_t session_timeout = SSL_SESSION_get_timeout (session);
  time_t session_time = SSL_SESSION_get_time (session);
  time_t now = time (NULL);

  if (session_time + session_timeout < now)
    {
      /* Session already expired */
      SSL_SESSION_free (session);
      return -1;
    }

  /* Get required length first */
  int session_len = i2d_SSL_SESSION (session, NULL);
  if (session_len <= 0)
    {
      SSL_SESSION_free (session);
      return -1;
    }

  /* Check if just querying size or if buffer is too small */
  if (buffer == NULL || (size_t)session_len > *len)
    {
      *len = (size_t)session_len;
      SSL_SESSION_free (session);
      return 0; /* Buffer too small or size query */
    }

  /* Serialize session to buffer */
  unsigned char *p = buffer;
  int written = i2d_SSL_SESSION (session, &p);
  SSL_SESSION_free (session);

  if (written <= 0)
    return -1;

  *len = (size_t)written;
  return 1;
}

/**
 * SocketTLS_session_restore - Import saved TLS session for resumption
 * @socket: Socket with TLS enabled but BEFORE handshake
 * @buffer: Buffer containing serialized session
 * @len: Length of session data
 *
 * Restores a previously exported TLS session to enable session resumption.
 * When the handshake is performed, OpenSSL will attempt to resume the session.
 *
 * ## Critical Timing
 *
 * This function MUST be called:
 * - AFTER SocketTLS_enable()
 * - BEFORE SocketTLS_handshake()
 *
 * Calling after handshake has no effect.
 *
 * ## Failure Modes
 *
 * Session restoration may fail gracefully if:
 * - Session data is corrupted or invalid
 * - Session has expired (server-enforced lifetime)
 * - Server no longer accepts the session (rotated keys, etc.)
 *
 * In all cases, the handshake falls back to a full handshake automatically.
 * Use SocketTLS_is_session_reused() after handshake to check if resumption
 * occurred.
 *
 * Returns: 1 on success (session set for resumption),
 *          0 on invalid/expired session data (will do full handshake),
 *          -1 on error (TLS not enabled, handshake already done)
 *
 * Thread-safe: No
 *
 * @note Server may still reject resumption; always check is_session_reused()
 */
int
SocketTLS_session_restore (Socket_T socket, const unsigned char *buffer,
                           size_t len)
{
  assert (socket);
  assert (buffer);

  /* Validate preconditions */
  if (!socket->tls_enabled)
    return -1;

  /* Must be called BEFORE handshake - check state */
  if (socket->tls_handshake_done)
    {
      /* Already handshaked - too late to restore session.
       * This is a programming error, but we return gracefully. */
      return -1;
    }

  SSL *ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    return -1;

  /* Validate length bounds for d2i_SSL_SESSION (takes long parameter).
   * Use INT_MAX for portability - it's safe on all platforms including
   * 64-bit Windows (LLP64) where sizeof(long)=4 but sizeof(size_t)=8.
   * This conservative check prevents both overflow and platform-specific
   * edge cases while still allowing session data up to ~2GB. */
  if (len == 0 || len > INT_MAX)
    return 0; /* Invalid data */

  /* Deserialize session from DER format */
  const unsigned char *p = buffer;
  SSL_SESSION *session = d2i_SSL_SESSION (NULL, &p, (long)len);
  if (!session)
    {
      /* Invalid or corrupted session data.
       * This is not an error - handshake will proceed without resumption. */
      return 0;
    }

  /* Check if session has expired */
  time_t session_timeout = SSL_SESSION_get_timeout (session);
  time_t session_time = SSL_SESSION_get_time (session);
  time_t now = time (NULL);

  if (session_time + session_timeout < now)
    {
      /* Session expired - free and return gracefully.
       * Handshake will proceed with full negotiation. */
      SSL_SESSION_free (session);
      return 0;
    }

  /* Set session for resumption attempt.
   * SSL_set_session() does NOT take ownership - it copies/refs the session.
   * We still need to free our reference. */
  int ret = SSL_set_session (ssl, session);
  SSL_SESSION_free (session);

  if (!ret)
    {
      /* OpenSSL rejected the session - rare but possible.
       * Handshake will proceed with full negotiation. */
      return 0;
    }

  return 1; /* Session set successfully - resumption will be attempted */
}

/**
 * SocketTLS_is_session_reused - Check if session resumption occurred
 * @socket: Socket with completed TLS handshake
 *
 * After a successful handshake, this function checks whether the connection
 * used session resumption (abbreviated handshake) or a full handshake.
 *
 * ## TLS 1.3 Session Resumption
 *
 * In TLS 1.3, session resumption works via Pre-Shared Keys (PSK):
 * - If a valid session was restored and accepted, this returns 1
 * - The resumed session provides the same security as a full handshake
 * - 0-RTT early data (if enabled) is a separate feature
 *
 * Returns: 1 if session was reused (abbreviated handshake),
 *          0 if full handshake was performed,
 *          -1 if TLS not enabled or handshake not complete
 *
 * Thread-safe: Yes - reads immutable post-handshake state
 */

/* SOCKET_TLS_MAX_RENEGOTIATIONS is now defined in SocketTLSConfig.h
 * with comprehensive documentation about DoS protection rationale. */

int
SocketTLS_check_renegotiation (Socket_T socket)
{
  assert (socket);

  if (!socket->tls_enabled)
    return -1;

  SSL *ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    return -1;

  /* TLS 1.3 doesn't support renegotiation - uses KeyUpdate instead.
   * Return 0 to indicate no renegotiation is pending (correct behavior). */
  if (SSL_version (ssl) >= TLS1_3_VERSION)
    return 0;

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
  /* Check if renegotiation is pending */
  if (SSL_renegotiate_pending (ssl))
    {
      /* DoS protection: Enforce renegotiation limit */
      if (socket->tls_renegotiation_count >= SOCKET_TLS_MAX_RENEGOTIATIONS)
        {
          SocketMetrics_counter_inc (SOCKET_CTR_TLS_RENEGOTIATIONS);
          TLS_ERROR_FMT ("Renegotiation limit exceeded (%d max)",
                         SOCKET_TLS_MAX_RENEGOTIATIONS);
          return -1; /* Reject: limit exceeded */
        }

      /* Check if secure renegotiation is supported (RFC 5746) */
      if (!SSL_get_secure_renegotiation_support (ssl))
        {
          SocketMetrics_counter_inc (SOCKET_CTR_TLS_RENEGOTIATIONS);
          TLS_ERROR_MSG ("Insecure renegotiation not supported");
          return -1; /* Reject: insecure renegotiation */
        }

      /* Process the renegotiation */
      int ret = SSL_do_handshake (ssl);
      if (ret == 1)
        {
          socket->tls_renegotiation_count++;
          SocketMetrics_counter_inc (SOCKET_CTR_TLS_RENEGOTIATIONS);
          return 1; /* Renegotiation completed successfully */
        }

      /* Check for WANT_READ/WANT_WRITE (non-blocking) */
      int ssl_error = SSL_get_error (ssl, ret);
      if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
        {
          errno = EAGAIN;
          return 0; /* In progress, retry later */
        }

      /* Renegotiation failed */
      tls_format_openssl_error ("Renegotiation handshake failed");
      RAISE_TLS_ERROR (SocketTLS_ProtocolError);
    }
#else
  /* Older OpenSSL - renegotiation not fully controllable */
  (void)socket; /* Suppress unused warning */
#endif

  return 0; /* No renegotiation pending */
}

int
SocketTLS_disable_renegotiation (Socket_T socket)
{
  assert (socket);

  if (!socket->tls_enabled)
    return -1;

  SSL *ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    return -1;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  /* Disable client-initiated renegotiation via SSL_OP_NO_RENEGOTIATION.
   * This option was added in OpenSSL 1.1.0h and prevents the peer from
   * initiating renegotiation. It's a security best practice as
   * renegotiation can be exploited for DoS (CVE-2011-1473) and has had
   * protocol vulnerabilities (CVE-2009-3555). */
  SSL_set_options (ssl, SSL_OP_NO_RENEGOTIATION);
#endif

  /* Also reset the count since renegotiation is now disabled */
  socket->tls_renegotiation_count = 0;

  return 0;
}

int
SocketTLS_get_renegotiation_count (Socket_T socket)
{
  assert (socket);

  if (!socket->tls_enabled)
    return -1;

  return socket->tls_renegotiation_count;
}

/**
 * asn1_time_to_time_t - Convert ASN1_TIME to time_t
 * @asn1: ASN1_TIME value
 *
 * Returns: time_t value, or (time_t)-1 on error
 */
static time_t
asn1_time_to_time_t (const ASN1_TIME *asn1)
{
  if (!asn1)
    return (time_t)-1;

  struct tm tm_time = { 0 };
  int ret = ASN1_TIME_to_tm (asn1, &tm_time);
  if (ret != 1)
    return (time_t)-1;

  return timegm (&tm_time);
}

/**
 * @brief Extract certificate subject name
 *
 * @param cert X509 certificate
 * @param buf Output buffer
 * @param size Buffer size
 */
static void
extract_cert_subject (X509 *cert, char *buf, size_t size)
{
  assert (cert);
  assert (buf);
  assert (size > 0);

  X509_NAME *subject_name = X509_get_subject_name (cert);
  if (subject_name)
    X509_NAME_oneline (subject_name, buf, (int)size);
}

/**
 * @brief Extract certificate issuer name
 *
 * @param cert X509 certificate
 * @param buf Output buffer
 * @param size Buffer size
 */
static void
extract_cert_issuer (X509 *cert, char *buf, size_t size)
{
  assert (cert);
  assert (buf);
  assert (size > 0);

  X509_NAME *issuer_name = X509_get_issuer_name (cert);
  if (issuer_name)
    X509_NAME_oneline (issuer_name, buf, (int)size);
}

/**
 * @brief Extract certificate serial number as hex string
 *
 * @param cert X509 certificate
 * @param buf Output buffer
 * @param size Buffer size
 */
static void
extract_cert_serial (X509 *cert, char *buf, size_t size)
{
  assert (cert);
  assert (buf);
  assert (size > 0);

  ASN1_INTEGER *serial = X509_get_serialNumber (cert);
  if (!serial)
    return;

  BIGNUM *bn = ASN1_INTEGER_to_BN (serial, NULL);
  if (!bn)
    return;

  char *hex = BN_bn2hex (bn);
  if (hex)
    {
      socket_util_safe_strncpy (buf, hex, size);
      OPENSSL_free (hex);
    }
  BN_free (bn);
}

/**
 * @brief Extract certificate SHA256 fingerprint
 *
 * @param cert X509 certificate
 * @param buf Output buffer
 * @param size Buffer size
 */
static void
extract_cert_fingerprint (X509 *cert, char *buf, size_t size)
{
  assert (cert);
  assert (buf);
  assert (size > 0);

  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int md_len = 0;

  if (!X509_digest (cert, EVP_sha256 (), md, &md_len))
    return;

  /* Limit to SHA256 digest size (32 bytes = 64 hex chars) */
  int expected_size = EVP_MD_size (EVP_sha256 ());
  size_t hash_len
      = (md_len > (unsigned)expected_size) ? (size_t)expected_size : md_len;
  SocketCrypto_hex_encode (md, hash_len, buf, size);
}

int
SocketTLS_get_peer_cert_info (Socket_T socket, SocketTLS_CertInfo *info)
{
  assert (socket);
  assert (info);

  memset (info, 0, sizeof (*info));

  SSL *ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    return -1;

  X509 *cert = SSL_get_peer_certificate (ssl);
  if (!cert)
    return 0; /* No peer certificate */

  extract_cert_subject (cert, info->subject, sizeof (info->subject));
  extract_cert_issuer (cert, info->issuer, sizeof (info->issuer));
  extract_cert_serial (cert, info->serial, sizeof (info->serial));
  extract_cert_fingerprint (cert, info->fingerprint, sizeof (info->fingerprint));

  /* Validity period */
  info->not_before = asn1_time_to_time_t (X509_get0_notBefore (cert));
  info->not_after = asn1_time_to_time_t (X509_get0_notAfter (cert));

  /* Version (0-indexed in X509, add 1 for standard numbering) */
  info->version = (int)X509_get_version (cert) + 1;

  X509_free (cert);
  return 1;
}

time_t
SocketTLS_get_cert_expiry (Socket_T socket)
{
  assert (socket);

  SSL *ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    return (time_t)-1;

  X509 *cert = SSL_get_peer_certificate (ssl);
  if (!cert)
    return (time_t)-1;

  time_t expiry = asn1_time_to_time_t (X509_get0_notAfter (cert));
  X509_free (cert);
  return expiry;
}

int
SocketTLS_get_cert_subject (Socket_T socket, char *buf, size_t len)
{
  assert (socket);
  assert (buf);
  assert (len > 0);

  buf[0] = '\0';

  SSL *ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    return -1;

  X509 *cert = SSL_get_peer_certificate (ssl);
  if (!cert)
    return 0;

  X509_NAME *subject_name = X509_get_subject_name (cert);
  if (!subject_name)
    {
      X509_free (cert);
      return 0;
    }

  char *result = X509_NAME_oneline (subject_name, buf, (int)len);
  X509_free (cert);

  if (!result)
    return -1;

  return (int)strlen (buf);
}

int
SocketTLS_get_peer_cert_chain (Socket_T socket, X509 ***chain_out,
                               int *chain_len)
{
  assert (socket);
  assert (chain_out);
  assert (chain_len);

  *chain_out = NULL;
  *chain_len = 0;

  SSL *ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    return -1;

  /* Get the certificate chain (does NOT include peer cert for clients) */
  STACK_OF (X509) *chain = SSL_get_peer_cert_chain (ssl);
  if (!chain)
    return 0; /* No chain available */

  int num = sk_X509_num (chain);
  if (num <= 0)
    return 0;

  /* Allocate array from socket's arena */
  Arena_T arena = SocketBase_arena (socket->base);
  X509 **certs = Arena_alloc (arena, (size_t)num * sizeof (X509 *), __FILE__,
                              __LINE__);
  if (!certs)
    return -1;

  /* Copy certificate references (caller must NOT free individual certs) */
  for (int i = 0; i < num; i++)
    {
      certs[i] = sk_X509_value (chain, i);
    }

  *chain_out = certs;
  *chain_len = num;
  return 1;
}

/* SOCKET_TLS_OCSP_MAX_AGE_SECONDS is now defined in SocketTLSConfig.h
 * with comprehensive documentation about replay prevention rationale. */

#if !defined(OPENSSL_NO_OCSP)
/**
 * ocsp_parse_response - Parse and validate OCSP response structure
 * @ssl: SSL connection object
 *
 * Retrieves the stapled OCSP response from the SSL connection and validates
 * its basic structure and status.
 *
 * Returns: Basic OCSP response on success, NULL on failure
 * Thread-safe: No (operates on SSL connection state)
 */
static OCSP_BASICRESP *
ocsp_parse_response (SSL *ssl)
{
  const unsigned char *ocsp_resp;
  long ocsp_len = SSL_get_tlsext_status_ocsp_resp (ssl, &ocsp_resp);

  if (ocsp_len <= 0 || !ocsp_resp)
    return NULL; /* No OCSP response stapled */

  /* Parse the OCSP response */
  OCSP_RESPONSE *resp = d2i_OCSP_RESPONSE (NULL, &ocsp_resp, ocsp_len);
  if (!resp)
    return NULL; /* Invalid OCSP response format */

  /* Check overall response status */
  int response_status = OCSP_response_status (resp);
  if (response_status != OCSP_RESPONSE_STATUS_SUCCESSFUL)
    {
      OCSP_RESPONSE_free (resp);
      return NULL; /* OCSP responder error */
    }

  /* Extract basic response for signature verification */
  OCSP_BASICRESP *basic = OCSP_response_get1_basic (resp);
  OCSP_RESPONSE_free (resp);

  return basic; /* May be NULL if extraction failed */
}

/**
 * ocsp_verify_signature - Verify OCSP response signature against chain
 * @basic: Basic OCSP response to verify
 * @ssl: SSL connection object (provides chain and trust store)
 *
 * Performs full OCSP signature verification:
 * 1. Verifies the OCSP response signature
 * 2. Checks the responder certificate against the trust store
 * 3. Validates responder certificate is authorized (CA or delegated)
 *
 * Returns: 0 on success, -1 on verification failure
 * Thread-safe: No (operates on SSL connection state)
 */
static int
ocsp_verify_signature (OCSP_BASICRESP *basic, SSL *ssl)
{
  STACK_OF (X509) *chain = SSL_get_peer_cert_chain (ssl);
  SSL_CTX *ssl_ctx = SSL_get_SSL_CTX (ssl);
  X509_STORE *store = ssl_ctx ? SSL_CTX_get_cert_store (ssl_ctx) : NULL;

  if (!store)
    return -1; /* No trust store available */

  /* Trust certificates in chain for OCSP responder verification */
  int verify_flags = OCSP_TRUSTOTHER;

  if (OCSP_basic_verify (basic, chain, store, verify_flags) != 1)
    return -1; /* Signature verification failed */

  return 0;
}

/**
 * ocsp_check_cert_status - Check certificate status in OCSP response
 * @basic: Basic OCSP response containing status information
 *
 * Iterates through OCSP single responses to find valid certificate status.
 * Validates response freshness (thisUpdate/nextUpdate timestamps) and maps
 * OCSP status codes to return values.
 *
 * Returns: 1 (GOOD), 0 (REVOKED), or -1 (UNKNOWN/not found)
 * Thread-safe: Yes (read-only operation on OCSP response)
 */
static int
ocsp_check_cert_status (OCSP_BASICRESP *basic)
{
  int cert_status = -1;
  int resp_count = OCSP_resp_count (basic);

  for (int i = 0; i < resp_count; i++)
    {
      OCSP_SINGLERESP *single = OCSP_resp_get0 (basic, i);
      if (!single)
        continue;

      int reason = 0;
      ASN1_GENERALIZEDTIME *thisupd = NULL;
      ASN1_GENERALIZEDTIME *nextupd = NULL;
      ASN1_GENERALIZEDTIME *revtime = NULL;

      int status = OCSP_single_get0_status (single, &reason, &revtime,
                                            &thisupd, &nextupd);

      /* Validate response freshness */
      if (!OCSP_check_validity (thisupd, nextupd,
                                SOCKET_TLS_OCSP_MAX_AGE_SECONDS, -1))
        continue; /* Response is stale or not yet valid */

      /* Map OCSP status to return value */
      switch (status)
        {
        case V_OCSP_CERTSTATUS_GOOD:
          cert_status = 1;
          break;
        case V_OCSP_CERTSTATUS_REVOKED:
          cert_status = 0;
          break;
        case V_OCSP_CERTSTATUS_UNKNOWN:
        default:
          /* Unknown status - continue checking other responses */
          if (cert_status < 0)
            cert_status = -1;
          break;
        }

      /* Stop at first definitive result (GOOD or REVOKED) */
      if (cert_status == 1 || cert_status == 0)
        break;
    }

  return cert_status;
}
#endif /* !defined(OPENSSL_NO_OCSP) */

int
 SocketTLS_get_ocsp_response_status (Socket_T socket)
{
  assert (socket);

  SSL *ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    return -1;

#if !defined(OPENSSL_NO_OCSP)
  /* Check if OCSP response is present first */
  const unsigned char *ocsp_resp_check;
  long ocsp_len_check = SSL_get_tlsext_status_ocsp_resp (ssl, &ocsp_resp_check);
  if (ocsp_len_check <= 0 || !ocsp_resp_check)
    return -1; /* No OCSP response stapled */

  /* Parse and validate OCSP response structure */
  OCSP_BASICRESP *basic = ocsp_parse_response (ssl);
  if (!basic)
    return -2; /* Invalid OCSP response */

  /* Verify peer certificate is available */
  X509 *peer_cert = SSL_get_peer_certificate (ssl);
  if (!peer_cert)
    {
      OCSP_BASICRESP_free (basic);
      return -2; /* No peer certificate for verification */
    }

  /* Verify OCSP response signature against certificate chain */
  if (ocsp_verify_signature (basic, ssl) != 0)
    {
      X509_free (peer_cert);
      OCSP_BASICRESP_free (basic);
      return -2; /* Signature verification failed */
    }

  /* Check certificate status in OCSP response */
  int cert_status = ocsp_check_cert_status (basic);

  X509_free (peer_cert);
  OCSP_BASICRESP_free (basic);

  return cert_status;
#else
  (void)socket;
  return -1; /* OCSP not compiled in */
#endif
}

int
SocketTLS_get_ocsp_next_update (Socket_T socket, time_t *next_update)
{
  assert (socket);
  assert (next_update);

  *next_update = (time_t)-1;

  SSL *ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    return -1;

#if !defined(OPENSSL_NO_OCSP)
  const unsigned char *ocsp_resp;
  long ocsp_len = SSL_get_tlsext_status_ocsp_resp (ssl, &ocsp_resp);

  if (ocsp_len <= 0 || !ocsp_resp)
    return -1;

  OCSP_RESPONSE *resp = d2i_OCSP_RESPONSE (NULL, &ocsp_resp, ocsp_len);
  if (!resp)
    return -1;

  if (OCSP_response_status (resp) != OCSP_RESPONSE_STATUS_SUCCESSFUL)
    {
      OCSP_RESPONSE_free (resp);
      return -1;
    }

  OCSP_BASICRESP *basic = OCSP_response_get1_basic (resp);
  if (!basic)
    {
      OCSP_RESPONSE_free (resp);
      return -1;
    }

  int result = -1;
  int resp_count = OCSP_resp_count (basic);

  for (int i = 0; i < resp_count; i++)
    {
      OCSP_SINGLERESP *single = OCSP_resp_get0 (basic, i);
      if (!single)
        continue;

      ASN1_GENERALIZEDTIME *nextupd = NULL;
      (void)OCSP_single_get0_status (single, NULL, NULL, NULL, &nextupd);

      if (nextupd)
        {
          struct tm tm_time = { 0 };
          if (ASN1_TIME_to_tm (nextupd, &tm_time) == 1)
            {
              *next_update = timegm (&tm_time);
              result = 1;
              break;
            }
        }
    }

  OCSP_BASICRESP_free (basic);
  OCSP_RESPONSE_free (resp);

  return result;
#else
  (void)socket;
  return -1;
#endif
}

#undef T

#endif /* SOCKET_HAS_TLS */
