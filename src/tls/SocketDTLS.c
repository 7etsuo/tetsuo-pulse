/**
 * SocketDTLS.c - DTLS Socket Integration Implementation
 *
 * Part of the Socket Library
 *
 * Implements DTLS/SSL integration for datagram sockets using OpenSSL.
 * Provides:
 * - Transparent encryption/decryption via wrapper functions
 * - Non-blocking handshake management
 * - SNI support and hostname verification
 * - Connection info queries (cipher, version, ALPN, etc.)
 * - DTLS I/O operations (send/recv)
 *
 * Thread safety: Functions are not thread-safe; each socket is
 * single-threaded. Uses thread-local error buffers for exception details.
 */

#if SOCKET_HAS_TLS

#include "tls/SocketDTLS-private.h"
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h> /* for struct addrinfo, freeaddrinfo */
#include <poll.h>
#include <string.h>

/* ============================================================================
 * Module Exception Declaration
 * ============================================================================
 */

#include "core/SocketCrypto.h"
#include "core/SocketMetrics.h"
#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"
#include "socket/SocketCommon.h"

#ifndef SOCKET_DTLS_DEFAULT_SHUTDOWN_TIMEOUT_MS
#define SOCKET_DTLS_DEFAULT_SHUTDOWN_TIMEOUT_MS                               \
  5000 /* ms, configurable via compile-time override */
#endif

SOCKET_DECLARE_MODULE_EXCEPTION (SocketDTLS);

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================
 */

/**
 * allocate_dtls_buffers - Allocate DTLS read/write buffers
 * @socket: Socket instance
 *
 * Raises: SocketDTLS_Failed if arena allocation fails
 */
static void
allocate_dtls_buffers (SocketDgram_T socket)
{
  assert (socket);
  Arena_T arena = SocketBase_arena (socket->base);
  assert (arena);

  if (!socket->dtls_read_buf)
    {
      socket->dtls_read_buf = ALLOC (arena, SOCKET_DTLS_MAX_RECORD_SIZE);
      if (!socket->dtls_read_buf)
        SOCKET_RAISE_MSG (SocketDTLS, SocketDTLS_Failed,
                          "Failed to allocate DTLS read buffer");
      socket->dtls_read_buf_len = 0;
    }

  if (!socket->dtls_write_buf)
    {
      socket->dtls_write_buf = ALLOC (arena, SOCKET_DTLS_MAX_RECORD_SIZE);
      if (!socket->dtls_write_buf)
        SOCKET_RAISE_MSG (SocketDTLS, SocketDTLS_Failed,
                          "Failed to allocate DTLS write buffer");
      socket->dtls_write_buf_len = 0;
    }
}

/**
 * free_dtls_resources - Cleanup DTLS resources
 * @socket: Socket instance
 *
 * Securely clears sensitive DTLS buffers before releasing.
 */
static void
free_dtls_resources (SocketDgram_T socket)
{
  assert (socket);

  if (socket->dtls_ssl)
    {
      SSL_set_app_data ((SSL *)socket->dtls_ssl, NULL);
      SSL_free ((SSL *)socket->dtls_ssl);
      socket->dtls_ssl = NULL;
      socket->dtls_ctx = NULL;
    }

  /* Securely clear DTLS buffers */
  if (socket->dtls_read_buf)
    {
      SocketCrypto_secure_clear (socket->dtls_read_buf,
                                 SOCKET_DTLS_MAX_RECORD_SIZE);
    }
  if (socket->dtls_write_buf)
    {
      SocketCrypto_secure_clear (socket->dtls_write_buf,
                                 SOCKET_DTLS_MAX_RECORD_SIZE);
    }

  /* Clear SNI hostname */
  if (socket->dtls_sni_hostname)
    {
      size_t hostname_len = strlen (socket->dtls_sni_hostname)
                            + 1; /* include null terminator */
      SocketCrypto_secure_clear ((void *)socket->dtls_sni_hostname,
                                 hostname_len);
    }

  /* Invalidate peer cache */
  if (socket->dtls_peer_res)
    {
      freeaddrinfo (socket->dtls_peer_res);
      socket->dtls_peer_res = NULL;
    }
  socket->dtls_peer_host = NULL;
  socket->dtls_peer_port = 0;
  socket->dtls_peer_cache_ts = 0;

  socket->dtls_enabled = 0;
  socket->dtls_handshake_done = 0;
  socket->dtls_shutdown_done = 0;
  socket->dtls_sni_hostname = NULL;
  socket->dtls_read_buf = NULL;
  socket->dtls_write_buf = NULL;
  socket->dtls_read_buf_len = 0;
  socket->dtls_write_buf_len = 0;
}

/**
 * validate_dtls_enable_preconditions - Validate socket is ready for DTLS
 * @socket: Socket to validate
 *
 * Raises: SocketDTLS_Failed if DTLS already enabled or fd invalid
 */
static void
validate_dtls_enable_preconditions (SocketDgram_T socket)
{
  if (socket->dtls_enabled)
    SOCKET_RAISE_MSG (SocketDTLS, SocketDTLS_Failed,
                      "DTLS already enabled on socket");

  int fd = SocketBase_fd (socket->base);
  if (fd < 0)
    SOCKET_RAISE_MSG (SocketDTLS, SocketDTLS_Failed,
                      "Socket not valid (invalid fd)");

  /* Validate socket type is datagram */
  int type;
  socklen_t optlen = sizeof (type);
  if (getsockopt (fd, SOL_SOCKET, SO_TYPE, &type, &optlen) != 0
      || type != SOCK_DGRAM)
    SOCKET_RAISE_MSG (SocketDTLS, SocketDTLS_Failed,
                      "DTLS requires a datagram socket (SOCK_DGRAM)");
}

/**
 * create_dtls_ssl_object - Create and configure SSL object from context
 * @ctx: DTLS context
 *
 * Returns: Configured SSL object
 * Raises: SocketDTLS_Failed on creation failure
 */
static SSL *
create_dtls_ssl_object (SocketDTLSContext_T ctx)
{
  SSL *ssl = SSL_new ((SSL_CTX *)SocketDTLSContext_get_ssl_ctx (ctx));
  if (!ssl)
    {
      SocketMetrics_counter_inc (SOCKET_CTR_DTLS_HANDSHAKES_FAILED);
      SOCKET_RAISE_MSG (SocketDTLS, SocketDTLS_Failed,
                        "Failed to create DTLS SSL object");
    }

  if (SocketDTLSContext_is_server (ctx))
    SSL_set_accept_state (ssl);
  else
    SSL_set_connect_state (ssl);

  return ssl;
}

/**
 * create_dgram_bio - Create datagram BIO for socket
 * @fd: Socket file descriptor
 *
 * Returns: BIO pointer
 * Raises: SocketDTLS_Failed on failure
 */
static BIO *
create_dgram_bio (int fd)
{
  BIO *bio = BIO_new_dgram (fd, BIO_NOCLOSE);
  if (!bio)
    SOCKET_RAISE_MSG (SocketDTLS, SocketDTLS_Failed,
                      "Failed to create datagram BIO");

  return bio;
}

/**
 * finalize_dtls_state - Set final DTLS state on socket
 * @socket: Socket to configure
 * @ssl: SSL object to associate
 * @ctx: DTLS context
 */
static void
finalize_dtls_state (SocketDgram_T socket, SSL *ssl, SocketDTLSContext_T ctx)
{
  socket->dtls_ssl = (void *)ssl;
  socket->dtls_ctx = (void *)ctx;
  SSL_set_app_data (ssl, socket);
  allocate_dtls_buffers (socket);

  /* Initialize peer cache */
  socket->dtls_peer_host = NULL;
  socket->dtls_peer_port = 0;
  socket->dtls_peer_res = NULL;
  socket->dtls_peer_cache_ts = 0;

  socket->dtls_enabled = 1;
  socket->dtls_handshake_done = 0;
  socket->dtls_shutdown_done = 0;
  socket->dtls_mtu = SocketDTLSContext_get_mtu (ctx);
}

/* ============================================================================
 * DTLS Peer Resolution Helper
 * ============================================================================
 */

/**
 * dtls_resolve_peer - Resolve peer hostname/port for DTLS BIO
 * @host: Hostname or IP
 * @port: Port number
 *
 * Returns: Resolved addrinfo list (caller must freeaddrinfo)
 * Raises: SocketDTLS_Failed on resolution failure
 * Thread-safe: Yes
 */
static struct addrinfo *
dtls_resolve_peer (const char *host, int port)
{
  struct addrinfo hints = { 0 };
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  struct addrinfo *result;
  SocketCommon_resolve_address (host, port, &hints, &result, SocketDTLS_Failed,
                                AF_UNSPEC, 1 /* use exceptions */);
  return result;
}

/**
 * dtls_set_ssl_hostname - Apply SNI hostname to SSL object
 * @socket: Socket with DTLS enabled
 * @hostname: Hostname string
 *
 * Sets SNI and hostname verification on SSL object.
 * Raises: SocketDTLS_Failed on failure
 * Thread-safe: No (single-threaded SSL)
 */
static void
dtls_set_ssl_hostname (SocketDgram_T socket, const char *hostname)
{
  SSL *ssl = dtls_socket_get_ssl (socket);
  if (!ssl)
    SOCKET_RAISE_MSG (SocketDTLS, SocketDTLS_Failed,
                      "SSL object not available");

  SSL_set_verify (ssl, SSL_VERIFY_PEER, NULL);

  if (SSL_set_tlsext_host_name (ssl, hostname) != 1)
    SOCKET_RAISE_MSG (SocketDTLS, SocketDTLS_Failed,
                      "Failed to set SNI hostname");

  if (SSL_set1_host (ssl, hostname) != 1)
    SOCKET_RAISE_MSG (SocketDTLS, SocketDTLS_Failed,
                      "Failed to enable hostname verification");
}

/* ============================================================================
 * DTLS Enable and Configuration
 * ============================================================================
 */

void
SocketDTLS_enable (SocketDgram_T socket, SocketDTLSContext_T ctx)
{
  assert (socket);
  assert (ctx);
  assert (SocketDTLSContext_get_ssl_ctx (ctx));

  validate_dtls_enable_preconditions (socket);

  SocketMetrics_counter_inc (SOCKET_CTR_DTLS_HANDSHAKES_TOTAL);

  SSL *ssl = create_dtls_ssl_object (ctx);
  int fd = SocketBase_fd (socket->base);

  /* Create datagram BIO and attach to SSL */
  BIO *bio = create_dgram_bio (fd);
  SSL_set_bio (ssl, bio, bio);

  /* Set MTU hint */
  SSL_set_mtu (ssl, (long)SocketDTLSContext_get_mtu (ctx));
  SSL_set_options (ssl, SSL_OP_NO_QUERY_MTU | SSL_OP_NO_RENEGOTIATION
                            | SSL_OP_NO_COMPRESSION);
  DTLS_set_link_mtu (ssl, (long)SocketDTLSContext_get_mtu (ctx));

  /* Enable read-ahead for efficient DTLS record reassembly */
  SSL_set_read_ahead (ssl, 1);

  /* Enable timer-based retransmission for DTLS */
  const struct timeval DTLS_INITIAL_RETRANS_TIMEOUT
      = { .tv_sec = 1, .tv_usec = 0 };
  BIO_ctrl (bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0,
            (void *)&DTLS_INITIAL_RETRANS_TIMEOUT);

  finalize_dtls_state (socket, ssl, ctx);
}

void
SocketDTLS_set_peer (SocketDgram_T socket, const char *host, int port)
{
  assert (socket);
  assert (host);

  REQUIRE_DTLS_ENABLED (socket, SocketDTLS_Failed);

  SSL *ssl = dtls_socket_get_ssl (socket);
  if (!ssl)
    SOCKET_RAISE_MSG (SocketDTLS, SocketDTLS_Failed,
                      "SSL object not available");

  BIO *bio = SSL_get_rbio (ssl);
  if (!bio)
    RAISE_DTLS_ERROR_MSG (SocketDTLS_Failed, "BIO not available");

  Arena_T arena = SocketBase_arena (socket->base);
  int64_t now_ms = Socket_get_monotonic_ms ();
  static const int64_t PEER_CACHE_TTL_MS
      = 30000; /* 30 seconds TTL for cached resolution */

  /* Check cache validity */
  bool cache_valid
      = socket->dtls_peer_host != NULL && socket->dtls_peer_port == port
        && strcmp (socket->dtls_peer_host, host) == 0
        && (now_ms - socket->dtls_peer_cache_ts) < PEER_CACHE_TTL_MS;

  struct addrinfo *result;
  if (cache_valid)
    {
      result = socket->dtls_peer_res; /* Reuse cached */
      SOCKET_LOG_DEBUG_MSG ("DTLS: Using cached peer resolution");
    }
  else
    {
      /* Invalidate old cache */
      if (socket->dtls_peer_res)
        {
          freeaddrinfo (socket->dtls_peer_res);
          socket->dtls_peer_res = NULL;
        }
      if (socket->dtls_peer_host)
        {
          socket->dtls_peer_host = NULL; /* Arena will free on dispose */
        }

      /* Resolve fresh */
      result = dtls_resolve_peer (host, port);

      /* Cache new resolution */
      socket->dtls_peer_host = socket_util_arena_strdup (arena, host);
      if (!socket->dtls_peer_host)
        {
          freeaddrinfo (result);
          RAISE_DTLS_ERROR_MSG (SocketDTLS_Failed,
                                "Failed to cache peer hostname");
        }
      socket->dtls_peer_port = port;
      socket->dtls_peer_res = result; /* Transfer ownership to cache */
      socket->dtls_peer_cache_ts = now_ms;
      SOCKET_LOG_DEBUG_MSG ("DTLS: Cached new peer resolution");
    }

  /* Set peer address in BIO (always use first resolved addr) */
  BIO_ADDR *bio_addr = BIO_ADDR_new ();
  if (!bio_addr)
    {
      if (!cache_valid)
        {
          freeaddrinfo (result); /* Only if not cached */
        }
      RAISE_DTLS_ERROR_MSG (SocketDTLS_Failed,
                            "Failed to allocate BIO address");
    }

  if (result->ai_family == AF_INET)
    {
      struct sockaddr_in *sin = (struct sockaddr_in *)result->ai_addr;
      BIO_ADDR_rawmake (bio_addr, AF_INET, &sin->sin_addr,
                        sizeof (sin->sin_addr), sin->sin_port);
    }
  else if (result->ai_family == AF_INET6)
    {
      struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)result->ai_addr;
      BIO_ADDR_rawmake (bio_addr, AF_INET6, &sin6->sin6_addr,
                        sizeof (sin6->sin6_addr), sin6->sin6_port);
    }
  else
    {
      BIO_ADDR_free (bio_addr);
      if (!cache_valid)
        {
          freeaddrinfo (result);
        }
      RAISE_DTLS_ERROR_MSG (SocketDTLS_Failed,
                            "Unsupported address family in resolution");
    }

  BIO_dgram_set_peer (bio, bio_addr);
  BIO_ADDR_free (bio_addr);
  /* Note: Do not freeaddrinfo(result) here if cached; handled on invalidate */
}

void
SocketDTLS_set_hostname (SocketDgram_T socket, const char *hostname)
{
  assert (socket);
  assert (hostname);

  REQUIRE_DTLS_ENABLED (socket, SocketDTLS_Failed);

  size_t hostname_len = strlen (hostname);
  if (hostname_len == 0)
    RAISE_DTLS_ERROR_MSG (SocketDTLS_Failed, "Hostname cannot be empty");

  if (hostname_len > SOCKET_DTLS_MAX_SNI_LEN)
    SOCKET_RAISE_FMT (SocketDTLS, SocketDTLS_Failed,
                      "Hostname too long for SNI (%zu > %d max)", hostname_len,
                      SOCKET_DTLS_MAX_SNI_LEN);

  SocketCommon_validate_hostname (hostname, SocketDTLS_Failed);

  /* Copy hostname to arena with overflow protection */
  Arena_T arena = SocketBase_arena (socket->base);
  size_t total_size;
  if (!SocketSecurity_check_add (hostname_len, 1, &total_size)
      || !SocketSecurity_check_size (total_size))
    {
      RAISE_DTLS_ERROR_MSG (SocketDTLS_Failed,
                            "Hostname too long for secure allocation");
    }
  socket->dtls_sni_hostname
      = Arena_alloc (arena, total_size, __FILE__, __LINE__);
  if (!socket->dtls_sni_hostname)
    RAISE_DTLS_ERROR_MSG (SocketDTLS_Failed,
                          "Failed to allocate hostname buffer");

  memcpy ((char *)socket->dtls_sni_hostname, hostname, hostname_len + 1);

  dtls_set_ssl_hostname (socket, socket->dtls_sni_hostname);
}

void
SocketDTLS_set_mtu (SocketDgram_T socket, size_t mtu)
{
  assert (socket);

  REQUIRE_DTLS_ENABLED (socket, SocketDTLS_Failed);

  if (!SocketSecurity_check_size (mtu))
    {
      SOCKET_RAISE_MSG (SocketDTLS, SocketDTLS_Failed,
                        "MTU exceeds security allocation limit");
    }

  if (!SOCKET_DTLS_VALID_MTU (mtu))
    {
      SOCKET_RAISE_FMT (SocketDTLS, SocketDTLS_Failed,
                        "Invalid MTU: %zu (must be %d-%d)", mtu,
                        SOCKET_DTLS_MIN_MTU, SOCKET_DTLS_MAX_MTU);
    }

  SSL *ssl = dtls_socket_get_ssl (socket);
  if (!ssl)
    SOCKET_RAISE_MSG (SocketDTLS, SocketDTLS_Failed,
                      "SSL object not available");

  SSL_set_mtu (ssl, (long)mtu);
  DTLS_set_link_mtu (ssl, (long)mtu);
  socket->dtls_mtu = mtu;
}

/* ============================================================================
 * DTLS Handshake
 * ============================================================================
 */

DTLSHandshakeState
SocketDTLS_handshake (SocketDgram_T socket)
{
  assert (socket);

  REQUIRE_DTLS_ENABLED (socket, SocketDTLS_HandshakeFailed);

  if (socket->dtls_handshake_done)
    return DTLS_HANDSHAKE_COMPLETE;

  SSL *ssl = dtls_socket_get_ssl (socket);
  if (!ssl)
    RAISE_DTLS_ERROR_MSG (SocketDTLS_HandshakeFailed,
                          "SSL object not available");

  /* Handle DTLS timer */
  if (DTLSv1_handle_timeout (ssl) < 0)
    {
      dtls_format_openssl_error ("DTLS timeout handling failed");
      socket->dtls_last_handshake_state = DTLS_HANDSHAKE_ERROR;
      return DTLS_HANDSHAKE_ERROR;
    }

  int result = SSL_do_handshake (ssl);
  if (result == 1)
    {
      socket->dtls_handshake_done = 1;
      socket->dtls_last_handshake_state = DTLS_HANDSHAKE_COMPLETE;
      return DTLS_HANDSHAKE_COMPLETE;
    }

  DTLSHandshakeState state = dtls_handle_ssl_error (socket, ssl, result);
  if (state == DTLS_HANDSHAKE_ERROR)
    {
      dtls_format_openssl_error ("DTLS handshake failed");
      SocketMetrics_counter_inc (SOCKET_CTR_DTLS_HANDSHAKES_FAILED);
      RAISE_DTLS_ERROR (SocketDTLS_HandshakeFailed);
    }

  socket->dtls_last_handshake_state = state;
  return state;
}

DTLSHandshakeState
SocketDTLS_handshake_loop (SocketDgram_T socket, int timeout_ms)
{
  assert (socket);

  REQUIRE_DTLS_ENABLED (socket, SocketDTLS_HandshakeFailed);

  if (socket->dtls_handshake_done)
    return DTLS_HANDSHAKE_COMPLETE;

  int fd = SocketBase_fd (socket->base);
  struct pollfd pfd;
  pfd.fd = fd;
  pfd.events = POLLIN | POLLOUT;

  int64_t deadline_ms
      = (timeout_ms > 0) ? SocketTimeout_deadline_ms (timeout_ms) : 0LL;

  while (timeout_ms == 0 || !SocketTimeout_expired (deadline_ms))
    {
      DTLSHandshakeState state = SocketDTLS_handshake (socket);

      switch (state)
        {
        case DTLS_HANDSHAKE_COMPLETE:
          return DTLS_HANDSHAKE_COMPLETE;

        case DTLS_HANDSHAKE_ERROR:
          return DTLS_HANDSHAKE_ERROR;

        case DTLS_HANDSHAKE_WANT_READ:
          pfd.events = POLLIN;
          break;

        case DTLS_HANDSHAKE_WANT_WRITE:
          pfd.events = POLLOUT;
          break;

        default:
          pfd.events = POLLIN | POLLOUT;
          break;
        }

      if (timeout_ms == 0)
        return state; /* Non-blocking, return current state */

      int poll_tmo = SocketTimeout_poll_timeout (
          -1, deadline_ms); /* -1: compute from deadline */

      int rc = poll (&pfd, 1, poll_tmo);
      if (rc < 0)
        {
          if (errno == EINTR)
            continue;
          SOCKET_RAISE_FMT (SocketDTLS, SocketDTLS_HandshakeFailed,
                            "poll failed: %s", Socket_safe_strerror (errno));
        }
    }

  /* Timeout expired */
  DTLS_ERROR_MSG ("DTLS handshake timeout");
  socket->dtls_last_handshake_state = DTLS_HANDSHAKE_ERROR;
  RAISE_DTLS_ERROR (SocketDTLS_TimeoutExpired);

  return DTLS_HANDSHAKE_ERROR; /* Unreachable */
}

DTLSHandshakeState
SocketDTLS_listen (SocketDgram_T socket)
{
  assert (socket);

  REQUIRE_DTLS_ENABLED (socket, SocketDTLS_Failed);

  SSL *ssl = dtls_socket_get_ssl (socket);
  if (!ssl)
    SOCKET_RAISE_MSG (SocketDTLS, SocketDTLS_Failed,
                      "SSL object not available");

  /* For DTLS server, we need to call DTLSv1_listen first if cookie enabled */
  SocketDTLSContext_T ctx_local = (SocketDTLSContext_T)socket->dtls_ctx;
  if (ctx_local && SocketDTLSContext_has_cookie_exchange (ctx_local))
    {
      BIO_ADDR *client_addr = BIO_ADDR_new ();
      if (!client_addr)
        RAISE_DTLS_ERROR_MSG (SocketDTLS_Failed,
                              "Failed to allocate client address");

      int listen_result = DTLSv1_listen (ssl, client_addr);
      if (listen_result < 0)
        {
          dtls_format_openssl_error ("DTLS listen failed");
          BIO_ADDR_free (client_addr);
          return DTLS_HANDSHAKE_ERROR;
        }
      else if (listen_result == 0)
        {
          /* Need more data - waiting for ClientHello */
          socket->dtls_last_handshake_state = DTLS_HANDSHAKE_WANT_READ;
          BIO_ADDR_free (client_addr);
          return DTLS_HANDSHAKE_WANT_READ;
        }
      /* listen_result > 0 means cookie verified, ready to handshake */
      /* Set peer address in BIO for subsequent operations */
      BIO *bio = SSL_get_rbio (ssl);
      if (bio)
        {
          BIO_dgram_set_peer (bio, client_addr);
        }
      BIO_ADDR_free (client_addr);
    }

  socket->dtls_last_handshake_state = DTLS_HANDSHAKE_IN_PROGRESS;
  return DTLS_HANDSHAKE_IN_PROGRESS;
}

/* ============================================================================
 * DTLS I/O Operations
 * ============================================================================
 */

ssize_t
SocketDTLS_send (SocketDgram_T socket, const void *buf, size_t len)
{
  assert (socket);
  assert (buf);
  assert (len > 0);

  SSL *ssl = VALIDATE_DTLS_IO_READY (socket, SocketDTLS_Failed);

  /* Cap length to INT_MAX */
  int write_len = (len > (size_t)INT_MAX) ? INT_MAX : (int)len;
  int result = SSL_write (ssl, buf, write_len);

  if (result > 0)
    return (ssize_t)result;

  DTLSHandshakeState state = dtls_handle_ssl_error (socket, ssl, result);
  if (state == DTLS_HANDSHAKE_ERROR)
    {
      dtls_format_openssl_error ("DTLS send failed");
      RAISE_DTLS_ERROR (SocketDTLS_Failed);
    }
  errno = EAGAIN;
  return 0;
}

ssize_t
SocketDTLS_recv (SocketDgram_T socket, void *buf, size_t len)
{
  assert (socket);
  assert (buf);
  assert (len > 0);

  SSL *ssl = VALIDATE_DTLS_IO_READY (socket, SocketDTLS_Failed);

  /* Handle any pending timeout retransmissions */
  DTLSv1_handle_timeout (ssl);

  /* Cap length to INT_MAX */
  int read_len = (len > (size_t)INT_MAX) ? INT_MAX : (int)len;
  int result = SSL_read (ssl, buf, read_len);

  if (result > 0)
    return (ssize_t)result;

  if (result == 0)
    RAISE (Socket_Closed);

  DTLSHandshakeState state = dtls_handle_ssl_error (socket, ssl, result);
  if (state == DTLS_HANDSHAKE_ERROR)
    {
      dtls_format_openssl_error ("DTLS recv failed");
      RAISE_DTLS_ERROR (SocketDTLS_Failed);
    }
  errno = EAGAIN;
  return 0;
}

ssize_t
SocketDTLS_sendto (SocketDgram_T socket, const void *buf, size_t len,
                   const char *host, int port)
{
  assert (socket);
  assert (buf);
  assert (host);

  /* Set peer address then send */
  SocketDTLS_set_peer (socket, host, port);
  return SocketDTLS_send (socket, buf, len);
}

ssize_t
SocketDTLS_recvfrom (SocketDgram_T socket, void *buf, size_t len, char *host,
                     size_t host_len, int *port)
{
  assert (socket);
  assert (buf);

  SSL *ssl = VALIDATE_DTLS_IO_READY (socket, SocketDTLS_Failed);

  ssize_t n = SocketDTLS_recv (socket, buf, len);

  /* Get peer address from BIO */
  if (n > 0 && (host || port))
    {
      bool peer_set = false;
      BIO *bio = SSL_get_rbio (ssl);
      if (bio)
        {
          BIO_ADDR *peer_addr = BIO_ADDR_new ();
          if (peer_addr && BIO_dgram_get_peer (bio, peer_addr))
            {
              peer_set = true;
              if (host && host_len > 0)
                {
                  char *addr_str = BIO_ADDR_hostname_string (peer_addr, 1);
                  if (addr_str)
                    {
                      strncpy (host, addr_str, host_len - 1);
                      host[host_len - 1] = '\0';
                      OPENSSL_free (addr_str);
                    }
                }
              if (port)
                {
                  char *port_str = BIO_ADDR_service_string (peer_addr, 1);
                  if (port_str)
                    {
                      {
                        char *endptr;
                        long p = strtol (port_str, &endptr, 10);
                        if (endptr > port_str && *endptr == '\0' && p >= 1
                            && p <= 65535)
                          {
                            *port = (int)p;
                          }
                        else
                          {
                            *port = 0; /* Invalid - default */
                          }
                      }
                      OPENSSL_free (port_str);
                    }
                }
            }
          if (peer_addr)
            BIO_ADDR_free (peer_addr);
        }
      if (!peer_set && (host || port))
        {
          /* Failed to retrieve peer info (e.g., OOM or BIO error); clear
           * outputs */
          if (host && host_len > 0)
            host[0] = '\0';
          if (port)
            *port = 0;
        }
    }

  return n;
}

/* ============================================================================
 * DTLS Connection Information
 * ============================================================================
 */

const char *
SocketDTLS_get_cipher (SocketDgram_T socket)
{
  assert (socket);

  SSL *ssl = dtls_socket_get_ssl (socket);
  if (!ssl)
    return NULL;

  const SSL_CIPHER *cipher = SSL_get_current_cipher (ssl);
  return cipher ? SSL_CIPHER_get_name (cipher) : NULL;
}

const char *
SocketDTLS_get_version (SocketDgram_T socket)
{
  assert (socket);

  SSL *ssl = dtls_socket_get_ssl (socket);
  return ssl ? SSL_get_version (ssl) : NULL;
}

long
SocketDTLS_get_verify_result (SocketDgram_T socket)
{
  if (!socket || !socket->dtls_enabled || !socket->dtls_ssl
      || !socket->dtls_handshake_done)
    {
      return X509_V_ERR_INVALID_CALL;
    }

  SSL *ssl = (SSL *)socket->dtls_ssl;
  return SSL_get_verify_result (ssl);
}

int
SocketDTLS_is_session_reused (SocketDgram_T socket)
{
  assert (socket);

  SSL *ssl = dtls_socket_get_ssl (socket);
  return ssl ? (SSL_session_reused (ssl) ? 1 : 0) : -1;
}

const char *
SocketDTLS_get_alpn_selected (SocketDgram_T socket)
{
  assert (socket);

  SSL *ssl = dtls_socket_get_ssl (socket);
  if (!ssl)
    return NULL;

  const unsigned char *alpn_data;
  unsigned int alpn_len;
  SSL_get0_alpn_selected (ssl, &alpn_data, &alpn_len);

  if (!alpn_data || alpn_len == 0 || alpn_len > SOCKET_DTLS_MAX_ALPN_LEN)
    return NULL;

  Arena_T arena = SocketBase_arena (socket->base);
  char *proto_copy = ALLOC (arena, alpn_len + 1);
  if (!proto_copy)
    return NULL;

  memcpy (proto_copy, alpn_data, alpn_len);
  proto_copy[alpn_len] = '\0';
  return proto_copy;
}

size_t
SocketDTLS_get_mtu (SocketDgram_T socket)
{
  return socket ? socket->dtls_mtu : SOCKET_DTLS_DEFAULT_MTU;
}

/* ============================================================================
 * DTLS Shutdown
 * ============================================================================
 */

void
SocketDTLS_shutdown (SocketDgram_T socket)
{
  assert (socket);

  REQUIRE_DTLS_ENABLED (socket, SocketDTLS_ShutdownFailed);

  if (socket->dtls_shutdown_done)
    return;

  SSL *ssl = dtls_socket_get_ssl (socket);
  if (!ssl)
    RAISE_DTLS_ERROR_MSG (SocketDTLS_ShutdownFailed,
                          "SSL object not available");

  int fd = SocketBase_fd (socket->base);
  if (fd < 0)
    RAISE_DTLS_ERROR_MSG (SocketDTLS_ShutdownFailed,
                          "Invalid socket fd during shutdown");

  struct pollfd pfd = { .fd = fd, .events = POLLIN | POLLOUT };
  int64_t deadline_ms = SocketTimeout_deadline_ms (
      SOCKET_DTLS_DEFAULT_SHUTDOWN_TIMEOUT_MS); /* Default 5s timeout for
                                                   shutdown */

  while (!SocketTimeout_expired (deadline_ms))
    {
      /* Handle any pending DTLS timeouts/retransmissions */
      if (DTLSv1_handle_timeout (ssl) < 0)
        {
          dtls_format_openssl_error ("DTLS timeout handling during shutdown");
          break; /* Continue but log */
        }

      int result = SSL_shutdown (ssl);
      if (result == 1)
        {
          socket->dtls_shutdown_done = 1;
          free_dtls_resources (socket);
          return;
        }
      else if (result < 0)
        {
          DTLSHandshakeState state
              = dtls_handle_ssl_error (socket, ssl, result);
          if (state == DTLS_HANDSHAKE_ERROR)
            {
              dtls_format_openssl_error ("DTLS shutdown error");
              RAISE_DTLS_ERROR (SocketDTLS_ShutdownFailed);
            }
          /* For other errors or WANT IO, continue polling */
        }

      /* Poll for required I/O (read peer close_notify or write) */
      int poll_tmo = SocketTimeout_poll_timeout (
          1000, deadline_ms); /* Max 1s per iteration */
      int pr = poll (&pfd, 1, poll_tmo);
      if (pr < 0)
        {
          if (errno == EINTR)
            continue;
          SOCKET_RAISE_FMT (SocketDTLS, SocketDTLS_ShutdownFailed,
                            "poll failed during shutdown: %s",
                            Socket_safe_strerror (errno));
        }
      /* No adjustment to pfd.events; both IN/OUT sufficient for shutdown phase
       */
    }

  /* Timeout or persistent error */
  dtls_format_openssl_error ("DTLS shutdown timeout or incomplete");
  RAISE_DTLS_ERROR (SocketDTLS_ShutdownFailed);
}

int
SocketDTLS_is_shutdown (SocketDgram_T socket)
{
  return socket ? socket->dtls_shutdown_done : 0;
}

/* ============================================================================
 * DTLS State Queries
 * ============================================================================
 */

int
SocketDTLS_is_enabled (SocketDgram_T socket)
{
  return socket ? socket->dtls_enabled : 0;
}

int
SocketDTLS_is_handshake_done (SocketDgram_T socket)
{
  return socket ? socket->dtls_handshake_done : 0;
}

DTLSHandshakeState
SocketDTLS_get_last_state (SocketDgram_T socket)
{
  return socket ? (DTLSHandshakeState)socket->dtls_last_handshake_state
                : DTLS_HANDSHAKE_NOT_STARTED;
}

#endif /* SOCKET_HAS_TLS */
