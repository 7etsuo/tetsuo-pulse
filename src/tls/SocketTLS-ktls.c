/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketTLS-ktls.c - Kernel TLS (kTLS) Offload Support
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Implements kTLS (Kernel TLS) offload for high-performance TLS operations.
 * When kTLS is enabled, the Linux kernel handles TLS record encryption and
 * decryption, reducing context switches and enabling zero-copy operations.
 *
 * Requirements:
 * - OpenSSL 3.0+ compiled with enable-ktls (not OPENSSL_NO_KTLS)
 * - Linux 4.13+ for TX offload, 4.17+ for RX offload
 * - Kernel CONFIG_TLS=y or CONFIG_TLS=m
 * - Supported cipher: AES-GCM-128/256 or ChaCha20-Poly1305 (5.11+)
 *
 * Thread safety: Functions are not thread-safe; each socket is single-threaded.
 */

#if SOCKET_HAS_TLS

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tls/SocketTLS-private.h"
#include "tls/SocketTLSConfig.h"

/* Thread-local exception for this translation unit - declared early for inline helpers */
#include "core/Except.h"  /* For Except_T and module exception macros */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketTLS);

/* Linux kTLS headers - only available on Linux with kTLS support */
#ifdef __linux__
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION (4, 13, 0)
#define SOCKET_HAS_KERNEL_TLS 1
#else
#define SOCKET_HAS_KERNEL_TLS 0
#endif
#else
#define SOCKET_HAS_KERNEL_TLS 0
#endif

/* OpenSSL 3.0+ kTLS support detection */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(OPENSSL_NO_KTLS)
#define SOCKET_HAS_OPENSSL_KTLS 1
#include <openssl/bio.h>
#else
#define SOCKET_HAS_OPENSSL_KTLS 0
#endif

/**
 * ktls_check_kernel_support - Check if kernel TLS module is available
 *
 * Attempts to verify kernel TLS support by checking:
 * 1. Compile-time: Linux kernel version >= 4.13
 * 2. Runtime: /sys/module/tls exists (module loaded)
 * 3. Runtime: /proc/net/tls_stat exists (built into kernel)
 *
 * Returns: 1 if kernel TLS is available, 0 otherwise
 * Thread-safe: Yes
 *
 * Note: This function performs a conservative check. If neither runtime
 * check succeeds, it returns 0. If the module can auto-load, the actual
 * kTLS activation during SSL handshake will still succeed. This ensures
 * accurate diagnostic reporting via SocketTLS_ktls_available().
 */
static int
ktls_check_kernel_support (void)
{
#if !SOCKET_HAS_KERNEL_TLS
  return 0;
#else
  /* Runtime check: verify TLS kernel module is loaded or built-in */
  struct stat st;

  /* Check if tls module is loaded */
  if (stat ("/sys/module/tls", &st) == 0)
    return 1;

  /* Check if TLS is built into the kernel (proc interface) */
  if (stat ("/proc/net/tls_stat", &st) == 0)
    return 1;

  /* If neither check succeeded, kTLS is not currently available.
   * Conservative approach: report unavailable rather than assume auto-load.
   * Actual kTLS availability is still determined during SSL_set_options(). */
  return 0;
#endif
}

/**
 * ktls_check_openssl_support - Check if OpenSSL has kTLS support
 *
 * Verifies that OpenSSL was compiled with kTLS support (enable-ktls)
 * and the SSL_OP_ENABLE_KTLS option is available.
 *
 * Returns: 1 if OpenSSL kTLS is available, 0 otherwise
 * Thread-safe: Yes
 */
static int
ktls_check_openssl_support (void)
{
#if !SOCKET_HAS_OPENSSL_KTLS
  return 0;
#else
  /* OpenSSL 3.0+ with kTLS compiled in */
  return 1;
#endif
}

/**
 * ktls_update_offload_status - Update kTLS TX/RX active flags after handshake
 * @socket: Socket with completed TLS handshake
 *
 * Called after successful handshake to check if kTLS offload was activated.
 * Uses BIO_get_ktls_send() and BIO_get_ktls_recv() to query OpenSSL's
 * internal kTLS state.
 *
 * Thread-safe: No - modifies socket state
 */
static void
ktls_update_offload_status (Socket_T socket)
{
  assert (socket);

  /* Reset flags first */
  socket->tls_ktls_tx_active = 0;
  socket->tls_ktls_rx_active = 0;

  if (!socket->tls_ktls_enabled || !socket->tls_ssl)
    return;

#if SOCKET_HAS_OPENSSL_KTLS
  SSL *ssl = (SSL *)socket->tls_ssl;
  BIO *wbio = SSL_get_wbio (ssl);
  BIO *rbio = SSL_get_rbio (ssl);

  if (wbio && BIO_get_ktls_send (wbio))
    {
      socket->tls_ktls_tx_active = 1;
      SOCKET_LOG_DEBUG_MSG ("kTLS TX offload activated for fd=%d",
                            Socket_fd (socket));
    }

  if (rbio && BIO_get_ktls_recv (rbio))
    {
      socket->tls_ktls_rx_active = 1;
      SOCKET_LOG_DEBUG_MSG ("kTLS RX offload activated for fd=%d",
                            Socket_fd (socket));
    }
#endif
}

/**
 * SocketTLS_ktls_available - Check if kTLS support is available
 *
 * See SocketTLS.h for full documentation.
 */
int
SocketTLS_ktls_available (void)
{
  return ktls_check_kernel_support () && ktls_check_openssl_support ();
}

/**
 * SocketTLS_enable_ktls - Enable kTLS offload for a socket
 *
 * See SocketTLS.h for full documentation.
 */
void
SocketTLS_enable_ktls (Socket_T socket)
{
  assert (socket);

  /* Validate TLS is enabled */
  if (!socket->tls_enabled)
    {
      RAISE_TLS_ERROR_MSG (SocketTLS_Failed,
                           "Cannot enable kTLS: TLS not enabled on socket");
    }

  /* Check if handshake already done - too late to enable */
  if (socket->tls_handshake_done)
    {
      SOCKET_LOG_WARN_MSG (
          "kTLS enable called after handshake - no effect for fd=%d",
          Socket_fd (socket));
      return;
    }

  /* Mark kTLS as requested */
  socket->tls_ktls_enabled = 1;

#if SOCKET_HAS_OPENSSL_KTLS
  SSL *ssl = (SSL *)socket->tls_ssl;
  if (ssl)
    {
      /* Set SSL_OP_ENABLE_KTLS - OpenSSL handles the rest automatically */
      SSL_set_options (ssl, SSL_OP_ENABLE_KTLS);
      SOCKET_LOG_DEBUG_MSG ("kTLS enabled via SSL_OP_ENABLE_KTLS for fd=%d",
                            Socket_fd (socket));
    }
#else
  /* kTLS not available at compile time - will fall back to userspace */
  SOCKET_LOG_DEBUG_MSG ("kTLS requested but not available at compile time");
#endif
}

/**
 * SocketTLS_is_ktls_tx_active - Check if kTLS TX offload is active
 *
 * See SocketTLS.h for full documentation.
 */
int
SocketTLS_is_ktls_tx_active (Socket_T socket)
{
  if (!socket)
    return -1;

  if (!socket->tls_enabled || !socket->tls_handshake_done)
    return -1;

  return socket->tls_ktls_tx_active ? 1 : 0;
}

/**
 * SocketTLS_is_ktls_rx_active - Check if kTLS RX offload is active
 *
 * See SocketTLS.h for full documentation.
 */
int
SocketTLS_is_ktls_rx_active (Socket_T socket)
{
  if (!socket)
    return -1;

  if (!socket->tls_enabled || !socket->tls_handshake_done)
    return -1;

  return socket->tls_ktls_rx_active ? 1 : 0;
}

/**
 * SocketTLS_sendfile - Send file data over TLS with zero-copy when possible
 *
 * See SocketTLS.h for full documentation.
 */
ssize_t
SocketTLS_sendfile (Socket_T socket, int file_fd, off_t offset, size_t size)
{
  assert (socket);

  /* Validate TLS I/O ready */
  SSL *ssl = VALIDATE_TLS_IO_READY (socket, SocketTLS_Failed);

  if (file_fd < 0)
    {
      errno = EBADF;
      return -1;
    }

  if (size == 0)
    return 0;

#if SOCKET_HAS_OPENSSL_KTLS
  /* Check if kTLS TX is active - use SSL_sendfile for zero-copy */
  if (socket->tls_ktls_tx_active)
    {
      ossl_ssize_t sent_raw = SSL_sendfile (ssl, file_fd, offset, size, 0);
      ssize_t sent = tls_handle_ssl_write_result (ssl, sent_raw, "SSL_sendfile");
      if (sent < -1)
        {
          RAISE (Socket_Closed);
        }
      else if (sent < 0)
        {
          RAISE_TLS_ERROR (SocketTLS_Failed);
        }
      return sent;
    }
#endif

  /* Fallback: read from file and send via SSL_write */
  unsigned char buf[SOCKET_TLS_KTLS_SENDFILE_BUFSIZE];
  ssize_t total_sent = 0;

  /* Seek to offset if non-zero */
  if (offset != 0)
    {
      if (lseek (file_fd, offset, SEEK_SET) == (off_t)-1)
        {
          return -1;
        }
    }

  while ((size_t)total_sent < size)
    {
      size_t to_read = size - (size_t)total_sent;
      if (to_read > sizeof (buf))
        to_read = sizeof (buf);

      ssize_t nread = read (file_fd, buf, to_read);
      if (nread < 0)
        {
          if (errno == EINTR)
            continue;
          return total_sent > 0 ? total_sent : -1;
        }
      if (nread == 0)
        break; /* EOF */

      /* Send via SSL_write with partial handling */
      size_t sent_chunk = 0;
      while (sent_chunk < (size_t)nread)
        {
          int to_send = (int)(nread - sent_chunk);
          if (to_send > INT_MAX)
            to_send = INT_MAX;

          int ret_raw = SSL_write (ssl, buf + sent_chunk, to_send);
          ssize_t ret = tls_handle_ssl_write_result (ssl, ret_raw, "SSL_write in sendfile fallback");
          if (ret < -1)
            {
              RAISE (Socket_Closed);
            }
          else if (ret < 0)
            {
              RAISE_TLS_ERROR (SocketTLS_Failed);
            }
          sent_chunk += (size_t)ret;
          if (ret == 0)
            {
              /* Would block - return partial progress including this chunk's sent */
              return total_sent + sent_chunk;
            }
        }
      /* Full chunk sent */
      total_sent += nread;
    }

  return total_sent;
}

/**
 * ktls_on_handshake_complete - Called when TLS handshake completes
 * @socket: Socket with completed handshake
 *
 * This function should be called from SocketTLS_handshake() after
 * a successful handshake to update kTLS offload status.
 *
 * Exposed via extern declaration for use by SocketTLS.c
 */
void
ktls_on_handshake_complete (Socket_T socket)
{
  if (socket && socket->tls_ktls_enabled)
    {
      ktls_update_offload_status (socket);
    }
}

#endif /* SOCKET_HAS_TLS */
