/**
 * SocketTLS.c - TLS Socket Integration
 *
 * Part of the Socket Library
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

#include "tls/SocketTLS-private.h"
#include "tls/SocketTLSContext.h"
#include "core/SocketCrypto.h"
#include "core/SocketUtil.h"
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <openssl/x509_vfy.h>
#include "poll/SocketPoll.h"
#include <string.h>
#include <stdint.h>

#define T SocketTLS_T

/* ============================================================================
 * Exception Definitions
 * ============================================================================
 */

const Except_T SocketTLS_Failed = { &SocketTLS_Failed, "TLS operation failed" };
const Except_T SocketTLS_HandshakeFailed
    = { &SocketTLS_HandshakeFailed, "TLS handshake failed" };
const Except_T SocketTLS_VerifyFailed
    = { &SocketTLS_VerifyFailed, "TLS certificate verification failed" };
const Except_T SocketTLS_ProtocolError
    = { &SocketTLS_ProtocolError, "TLS protocol error" };
const Except_T SocketTLS_ShutdownFailed
    = { &SocketTLS_ShutdownFailed, "TLS shutdown failed" };

/* ============================================================================
 * Thread-Local Error Buffers
 * ============================================================================
 */
SOCKET_DECLARE_MODULE_EXCEPTION(SocketTLS);
/* ============================================================================
 * Internal Helper Functions
 * ============================================================================
 */

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
    RAISE_TLS_ERROR_MSG (SocketTLS_Failed, "Failed to allocate TLS %s buffer", purpose);
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

/**
 * tls_secure_clear_buf - Securely clear a TLS buffer if allocated
 * @buf: Buffer pointer
 * @size: Buffer size
 *
 * Uses SocketCrypto_secure_clear to wipe sensitive data that cannot be optimized away.
 * No-op if buf is NULL.
 * Thread-safe: Yes
 */
static void
tls_secure_clear_buf (void *buf, size_t size)
{
  if (buf)
    SocketCrypto_secure_clear (buf, size);
}

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
      tls_cleanup_alpn_temp (ssl);  /* Free ALPN temp buffer if stored */
      SSL_free (ssl);
      socket->tls_ssl = NULL;
      socket->tls_ctx = NULL;
    }

  /* Securely clear TLS buffers that may contain sensitive decrypted data */
  tls_secure_clear_buf (socket->tls_read_buf, SOCKET_TLS_BUFFER_SIZE);
  tls_secure_clear_buf (socket->tls_write_buf, SOCKET_TLS_BUFFER_SIZE);

  /* Clear SNI hostname (may contain sensitive connection info) */
  if (socket->tls_sni_hostname)
    {
      size_t hostname_len = strlen (socket->tls_sni_hostname) + 1;
      SocketCrypto_secure_clear ((void *)socket->tls_sni_hostname, hostname_len);
      socket->tls_sni_hostname = NULL;
    }

  socket->tls_enabled = 0;
  socket->tls_handshake_done = 0;
  socket->tls_shutdown_done = 0;
  socket->tls_read_buf = NULL;
  socket->tls_write_buf = NULL;
  socket->tls_read_buf_len = 0;
  socket->tls_write_buf_len = 0;
}

/* ============================================================================
 * TLS Enable and Configuration
 * ============================================================================
 */

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
    RAISE_TLS_ERROR_MSG (SocketTLS_Failed, "Socket not connected (invalid fd)");
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
      tls_cleanup_alpn_temp (ssl);  /* Cleanup any ex_data before free on error */
      SSL_free (ssl);
      RAISE_TLS_ERROR_MSG (SocketTLS_Failed, "Failed to associate SSL with fd");
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
  assert (socket);
  assert (ctx);
  assert (SocketTLSContext_get_ssl_ctx (ctx));

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
    RAISE_TLS_ERROR_MSG (SocketTLS_Failed, "Failed to allocate hostname buffer");

  memcpy ((char *)socket->tls_sni_hostname, hostname, len + 1);
}

/**
 * apply_sni_to_ssl - Apply SNI hostname to SSL connection
 * @ssl: SSL object
 * @hostname: Hostname for SNI
 *
 * Enables peer certificate verification and hostname checking.
 * SSL_set_verify() with SSL_VERIFY_PEER ensures the handshake fails
 * if the server certificate is invalid or hostname doesn't match.
 *
 * Raises: SocketTLS_Failed on OpenSSL error
 */
static void
apply_sni_to_ssl (SSL *ssl, const char *hostname)
{
  /* Enable peer certificate verification - required for hostname check to work */
  SSL_set_verify (ssl, SSL_VERIFY_PEER, NULL);

  if (SSL_set_tlsext_host_name (ssl, hostname) != 1)
    RAISE_TLS_ERROR_MSG (SocketTLS_Failed, "Failed to set SNI hostname");

  if (SSL_set1_host (ssl, hostname) != 1)
    RAISE_TLS_ERROR_MSG (SocketTLS_Failed, "Failed to enable hostname verification");
}

void
SocketTLS_set_hostname (Socket_T socket, const char *hostname)
{
  assert (socket);
  assert (hostname);

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

/* ============================================================================
 * TLS Handshake and Shutdown
 * ============================================================================
 */

TLSHandshakeState
SocketTLS_handshake (Socket_T socket)
{
  assert (socket);

  REQUIRE_TLS_ENABLED (socket, SocketTLS_HandshakeFailed);

  if (socket->tls_handshake_done)
    return TLS_HANDSHAKE_COMPLETE;

  SSL *ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    RAISE_TLS_ERROR_MSG (SocketTLS_HandshakeFailed, "SSL object not available");

  int result = SSL_do_handshake (ssl);
  if (result == 1)
    {
      socket->tls_handshake_done = 1;
      socket->tls_last_handshake_state = TLS_HANDSHAKE_COMPLETE;
      return TLS_HANDSHAKE_COMPLETE;
    }

  TLSHandshakeState state = tls_handle_ssl_error (socket, ssl, result);
  if (state == TLS_HANDSHAKE_ERROR)
    {
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
 * do_handshake_poll - Perform poll wait for handshake I/O using SocketPoll
 * @socket: Socket instance
 * @events: Poll events to wait for (SocketPoll_Events bitmask)
 * @timeout_ms: Poll timeout in milliseconds
 *
 * Returns: 1 if socket is ready (events occurred), 0 on timeout or EINTR (retry)
 * Raises: SocketTLS_HandshakeFailed on poll error
 * Thread-safe: No
 */
static int
do_handshake_poll (Socket_T socket, unsigned events, int timeout_ms)
{
  SocketPoll_T poll = NULL;
  int rc;

  TRY
    {
      poll = SocketPoll_new (16); /* Small capacity for single FD poll */
      if (!poll)
        RAISE_TLS_ERROR_MSG (SocketTLS_HandshakeFailed, "Failed to create temporary poll instance");

      SocketPoll_add (poll, socket, events, NULL);

      SocketEvent_T evs[16];
      SocketEvent_T *events = evs;
      rc = SocketPoll_wait (poll, &events, timeout_ms);
      if (rc < 0)
        {
          if (errno == EINTR)
            return 0; /* Caller should retry */
          TLS_ERROR_FMT ("SocketPoll_wait failed: %s", strerror (errno));
          RAISE_TLS_ERROR (SocketTLS_HandshakeFailed);
        }
      /* rc >= 0: success (0=timeout, >0=ready) */
    }
  FINALLY
    {
      if (poll)
        SocketPoll_free (&poll);
    }
  END_TRY;

  return 1; /* Success (ready or timeout) */
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

TLSHandshakeState
SocketTLS_handshake_loop (Socket_T socket, int timeout_ms)
{
  assert (socket);

  if (socket->tls_handshake_done)
    return TLS_HANDSHAKE_COMPLETE;

  validate_handshake_preconditions (socket);

  int64_t deadline = (timeout_ms > 0) ? SocketTimeout_deadline_ms (timeout_ms) : 0LL;

  while (true)
    {
      TLSHandshakeState state = SocketTLS_handshake (socket);

      if (state == TLS_HANDSHAKE_COMPLETE || state == TLS_HANDSHAKE_ERROR)
        return state;

      /* Non-blocking mode: return current state immediately */
      if (timeout_ms == 0)
        return state;

      if (SocketTimeout_expired (deadline))
        {
          tls_format_openssl_error ("TLS handshake timeout");
          RAISE_TLS_ERROR (SocketTLS_HandshakeFailed);
        }

      unsigned events = state_to_poll_events (state);
      int poll_timeout = SocketTimeout_poll_timeout (SOCKET_TLS_POLL_INTERVAL_MS, deadline);
      if (!do_handshake_poll (socket, events, poll_timeout))
        continue; /* EINTR or partial timeout, check deadline again */

      /* Socket ready, retry handshake */
    }

  return TLS_HANDSHAKE_ERROR; /* Unreachable */
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
          tls_format_openssl_error ("SSL object not available during shutdown");
          free_tls_resources (socket);
          RAISE_TLS_ERROR_MSG (SocketTLS_ShutdownFailed, "SSL object lost during shutdown");
        }

      int result = SSL_shutdown (ssl);
      if (result == 1)
        {
          socket->tls_shutdown_done = 1;
          free_tls_resources (socket);
          return; /* Complete */
        }
      else if (result < 0)
        {
          TLSHandshakeState state = tls_handle_ssl_error (socket, ssl, result);
          if (state == TLS_HANDSHAKE_ERROR)
            {
              tls_format_openssl_error ("Shutdown failed");
              free_tls_resources (socket);
              RAISE_TLS_ERROR (SocketTLS_ShutdownFailed);
            }
          /* WANT_READ/WRITE: continue loop with poll */
        }
      else /* result == 0: partial shutdown, need to retry after I/O */
        {
          /* Continue to poll loop below */
        }

      /* Need I/O for remaining shutdown steps */
      unsigned events = POLL_READ | POLL_WRITE; /* Shutdown may need both */
      int poll_timeout = SocketTimeout_poll_timeout (SOCKET_TLS_POLL_INTERVAL_MS, deadline);
      if (!do_handshake_poll (socket, events, poll_timeout))
        continue; /* EINTR or timeout slice, retry */
    }

  /* Timeout */
  tls_format_openssl_error ("Shutdown timeout");
  free_tls_resources (socket);
  RAISE_TLS_ERROR_MSG (SocketTLS_ShutdownFailed, "TLS shutdown timeout after %d ms", timeout_ms);
}

/* ============================================================================
 * TLS I/O Operations
 * ============================================================================
 */

ssize_t
SocketTLS_send (Socket_T socket, const void *buf, size_t len)
{
  assert (socket);
  assert (buf);
  assert (len > 0);

  SSL *ssl = VALIDATE_TLS_IO_READY (socket, SocketTLS_Failed);
  /* Cap length to INT_MAX to prevent truncation on 64-bit systems */
  int write_len = (len > (size_t)INT_MAX) ? INT_MAX : (int)len;
  int result = SSL_write (ssl, buf, write_len);

  if (result > 0)
    return (ssize_t)result;

  TLSHandshakeState state = tls_handle_ssl_error (socket, ssl, result);
  if (state == TLS_HANDSHAKE_ERROR)
    {
      tls_format_openssl_error ("TLS send failed");
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }
  errno = EAGAIN;
  return 0;
}

ssize_t
SocketTLS_recv (Socket_T socket, void *buf, size_t len)
{
  assert (socket);
  assert (buf);
  assert (len > 0);

  SSL *ssl = VALIDATE_TLS_IO_READY (socket, SocketTLS_Failed);
  /* Cap length to INT_MAX to prevent truncation on 64-bit systems */
  int read_len = (len > (size_t)INT_MAX) ? INT_MAX : (int)len;
  int result = SSL_read (ssl, buf, read_len);

  if (result > 0)
    return (ssize_t)result;

  if (result == 0)
    RAISE (Socket_Closed); /* longjmp - does not return */

  TLSHandshakeState state = tls_handle_ssl_error (socket, ssl, result);
  if (state == TLS_HANDSHAKE_ERROR)
    {
      tls_format_openssl_error ("TLS recv failed");
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }
  errno = EAGAIN;
  return 0;
}

/* ============================================================================
 * TLS Connection Information
 * ============================================================================
 */

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
      strncpy (buf, code_str, size - 1);
      buf[size - 1] = '\0';
      return buf;
    }

  unsigned long err = ERR_get_error ();
  if (err)
    {
      ERR_error_string_n (err, buf, size);
      ERR_clear_error (); /* Clear the error queue after reading */
      return buf;
    }

  strncpy (buf, "TLS verification failed (unknown error)", size - 1);
  buf[size - 1] = '\0';
  return buf;
}

int
SocketTLS_is_session_reused (Socket_T socket)
{
  assert (socket);

  SSL *ssl = tls_socket_get_ssl (socket);
  return ssl ? (SSL_session_reused (ssl) ? 1 : 0) : -1;
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

#undef T

#endif /* SOCKET_HAS_TLS */

