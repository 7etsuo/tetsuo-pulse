/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

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

#include "core/SocketCrypto.h"
#include "core/SocketMetrics.h"
#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"
#include "socket/SocketCommon.h"
#include "tls/SocketSSL-internal.h"

const Except_T SocketDTLS_Failed
    = { .type = &SocketDTLS_Failed, .reason = "DTLS operation failed" };
const Except_T SocketDTLS_HandshakeFailed
    = { .type = &SocketDTLS_HandshakeFailed,
        .reason = "DTLS handshake failed" };
const Except_T SocketDTLS_VerifyFailed
    = { .type = &SocketDTLS_VerifyFailed,
        .reason = "DTLS certificate verification failed" };
const Except_T SocketDTLS_CookieFailed
    = { .type = &SocketDTLS_CookieFailed,
        .reason = "DTLS cookie exchange failed" };
const Except_T SocketDTLS_TimeoutExpired
    = { .type = &SocketDTLS_TimeoutExpired,
        .reason = "DTLS handshake timeout expired" };
const Except_T SocketDTLS_ShutdownFailed
    = { .type = &SocketDTLS_ShutdownFailed, .reason = "DTLS shutdown failed" };

SOCKET_DECLARE_MODULE_EXCEPTION (SocketDTLS);

/**
 * allocate_single_dtls_buffer - Allocate a single DTLS buffer if needed
 * @arena: Arena for allocation
 * @buf_ptr: Pointer to buffer pointer
 * @len_ptr: Pointer to buffer length
 * @name: Buffer name for error messages
 *
 * Raises: SocketDTLS_Failed if arena allocation fails
 */
static void
allocate_single_dtls_buffer (Arena_T arena,
                             unsigned char **buf_ptr,
                             size_t *len_ptr,
                             const char *name)
{
  if (!*buf_ptr)
    {
      *buf_ptr = ALLOC (arena, SOCKET_DTLS_MAX_RECORD_SIZE);
      if (!*buf_ptr)
        SOCKET_RAISE_FMT (SocketDTLS,
                          SocketDTLS_Failed,
                          "Failed to allocate DTLS %s buffer",
                          name);
      *len_ptr = 0;
    }
}

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

  allocate_single_dtls_buffer (arena,
                               (unsigned char **)&socket->dtls_read_buf,
                               &socket->dtls_read_buf_len,
                               "read");
  allocate_single_dtls_buffer (arena,
                               (unsigned char **)&socket->dtls_write_buf,
                               &socket->dtls_write_buf_len,
                               "write");
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

  /* Securely clear DTLS buffers using shared helper */
  ssl_secure_clear_buf (socket->dtls_read_buf, SOCKET_DTLS_MAX_RECORD_SIZE);
  ssl_secure_clear_buf (socket->dtls_write_buf, SOCKET_DTLS_MAX_RECORD_SIZE);

  /* Clear SNI hostname using shared helper */
  ssl_secure_clear_hostname (socket->dtls_sni_hostname);

  /* Invalidate peer cache */
  if (socket->dtls_peer_res)
    {
      SocketCommon_free_addrinfo (socket->dtls_peer_res);
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
    SOCKET_RAISE_MSG (
        SocketDTLS, SocketDTLS_Failed, "DTLS already enabled on socket");

  int fd = SocketBase_fd (socket->base);
  if (fd < 0)
    SOCKET_RAISE_MSG (
        SocketDTLS, SocketDTLS_Failed, "Socket not valid (invalid fd)");

  /* Validate socket type is datagram */
  int type;
  socklen_t optlen = sizeof (type);
  if (getsockopt (fd, SOL_SOCKET, SO_TYPE, &type, &optlen) != 0
      || type != SOCK_DGRAM)
    SOCKET_RAISE_MSG (SocketDTLS,
                      SocketDTLS_Failed,
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
      SOCKET_RAISE_MSG (
          SocketDTLS, SocketDTLS_Failed, "Failed to create DTLS SSL object");
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
    SOCKET_RAISE_MSG (
        SocketDTLS, SocketDTLS_Failed, "Failed to create datagram BIO");

  return bio;
}

/**
 * finalize_dtls_state - Set final DTLS state on socket
 * @socket: Socket to configure
 * @ssl: SSL object to associate
 * @ctx: DTLS context
 *
 * Increments the context refcount so the context remains valid while the
 * socket is in use. The refcount is decremented when the socket is freed.
 */
static void
finalize_dtls_state (SocketDgram_T socket, SSL *ssl, SocketDTLSContext_T ctx)
{
  volatile int ref_added = 0;

  TRY
  {
    socket->dtls_ssl = (void *)ssl;
    socket->dtls_ctx = (void *)ctx;
    SocketDTLSContext_ref (ctx); /* Retain context for this socket */
    ref_added = 1;

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
    socket->dtls_last_handshake_state = DTLS_HANDSHAKE_NOT_STARTED;
    socket->dtls_retransmit_count = 0;

    ref_added = 0; /* Success - keep the reference */
  }
  ELSE
  {
    if (ref_added)
      {
        SocketDTLSContext_T ctx_temp = ctx;
        SocketDTLSContext_free (&ctx_temp);
      }
    RERAISE;
  }
  END_TRY;
}

/**
 * dtls_resolve_peer - Resolve peer hostname/port for DTLS BIO
 * @host: Hostname or IP
 * @port: Port number
 *
 * Returns: Resolved addrinfo list (caller must SocketCommon_free_addrinfo)
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
  SocketCommon_resolve_address (host,
                                port,
                                &hints,
                                &result,
                                SocketDTLS_Failed,
                                AF_UNSPEC,
                                1 /* use exceptions */);
  return result;
}

/**
 * dtls_peer_cache_valid - Check if peer resolution cache is valid
 * @socket: Socket to check
 * @host: Expected hostname
 * @port: Expected port
 * @now_ms: Current monotonic time in milliseconds
 *
 * Returns: 1 if cache is valid and matches, 0 otherwise
 */
static int
dtls_peer_cache_valid (SocketDgram_T socket,
                       const char *host,
                       int port,
                       int64_t now_ms)
{
  return socket->dtls_peer_host != NULL && socket->dtls_peer_port == port
         && strcmp (socket->dtls_peer_host, host) == 0
         && (now_ms - socket->dtls_peer_cache_ts)
                < SOCKET_DTLS_PEER_CACHE_TTL_MS;
}

/**
 * dtls_invalidate_peer_cache - Clear the peer resolution cache
 * @socket: Socket to clear cache for
 */
static void
dtls_invalidate_peer_cache (SocketDgram_T socket)
{
  if (socket->dtls_peer_res)
    {
      SocketCommon_free_addrinfo (socket->dtls_peer_res);
      socket->dtls_peer_res = NULL;
    }
  socket->dtls_peer_host = NULL;
}

/**
 * dtls_cache_peer_resolution - Store peer resolution in cache
 * @socket: Socket to cache for
 * @host: Hostname to cache
 * @port: Port to cache
 * @result: Resolved addrinfo (ownership transferred to cache)
 * @now_ms: Current monotonic time
 *
 * Raises: SocketDTLS_Failed on allocation failure
 */
static void
dtls_cache_peer_resolution (SocketDgram_T socket,
                            const char *host,
                            int port,
                            struct addrinfo *result,
                            int64_t now_ms)
{
  Arena_T arena = SocketBase_arena (socket->base);

  socket->dtls_peer_host = socket_util_arena_strdup (arena, host);
  if (!socket->dtls_peer_host)
    {
      SocketCommon_free_addrinfo (result);
      RAISE_DTLS_ERROR_MSG (SocketDTLS_Failed, "Failed to cache peer hostname");
    }
  socket->dtls_peer_port = port;
  socket->dtls_peer_res = result;
  socket->dtls_peer_cache_ts = now_ms;
  SOCKET_LOG_DEBUG_MSG ("DTLS: Cached new peer resolution");
}

/**
 * dtls_set_bio_peer_address - Set peer address in BIO from addrinfo
 * @bio: BIO to configure
 * @result: Resolved address info
 *
 * Raises: SocketDTLS_Failed on unsupported family or allocation failure
 */
static void
dtls_set_bio_peer_address (BIO *bio, struct addrinfo *result)
{
  BIO_ADDR *bio_addr = BIO_ADDR_new ();
  if (!bio_addr)
    RAISE_DTLS_ERROR_MSG (SocketDTLS_Failed, "Failed to allocate BIO address");

  int success = 0;
  if (result->ai_family == AF_INET)
    {
      struct sockaddr_in *sin = (struct sockaddr_in *)result->ai_addr;
      BIO_ADDR_rawmake (bio_addr,
                        AF_INET,
                        &sin->sin_addr,
                        sizeof (sin->sin_addr),
                        sin->sin_port);
      success = 1;
    }
  else if (result->ai_family == AF_INET6)
    {
      struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)result->ai_addr;
      BIO_ADDR_rawmake (bio_addr,
                        AF_INET6,
                        &sin6->sin6_addr,
                        sizeof (sin6->sin6_addr),
                        sin6->sin6_port);
      success = 1;
    }

  if (!success)
    {
      BIO_ADDR_free (bio_addr);
      RAISE_DTLS_ERROR_MSG (SocketDTLS_Failed,
                            "Unsupported address family in resolution");
    }

  BIO_dgram_set_peer (bio, bio_addr);
  BIO_ADDR_free (bio_addr);
}

/**
 * dtls_set_ssl_hostname - Apply SNI hostname to SSL object
 * @socket: Socket with DTLS enabled
 * @hostname: Hostname string
 *
 * Wrapper around shared ssl_apply_sni_hostname() helper with DTLS-specific
 * error handling. Sets SNI and hostname verification on SSL object.
 *
 * Raises: SocketDTLS_Failed on failure
 * Thread-safe: No (single-threaded SSL)
 */
static void
dtls_set_ssl_hostname (SocketDgram_T socket, const char *hostname)
{
  SSL *ssl = REQUIRE_DTLS_SSL (socket, SocketDTLS_Failed);

  int ret = ssl_apply_sni_hostname (ssl, hostname);
  if (ret == -1)
    RAISE_DTLS_ERROR_MSG (SocketDTLS_Failed, "Failed to set SNI hostname");
  if (ret == -2)
    RAISE_DTLS_ERROR_MSG (SocketDTLS_Failed,
                          "Failed to enable hostname verification");
}

/**
 * configure_dtls_mtu - Configure MTU settings on SSL object
 * @ssl: SSL object
 * @mtu: MTU value from context
 */
static void
configure_dtls_mtu (SSL *ssl, size_t mtu)
{
  SSL_set_mtu (ssl, (long)mtu);
  SSL_set_options (ssl,
                   SSL_OP_NO_QUERY_MTU | SSL_OP_NO_RENEGOTIATION
                       | SSL_OP_NO_COMPRESSION);
  DTLS_set_link_mtu (ssl, (long)mtu);
  SSL_set_read_ahead (ssl, 1);
}

/**
 * configure_dtls_retransmit_timeout - Set initial retransmission timeout
 * @ssl: SSL object
 *
 * Non-fatal if it fails - handshake works with default timing.
 */
static void
configure_dtls_retransmit_timeout (SSL *ssl)
{
  static const struct timeval DTLS_INITIAL_TIMEOUT
      = { .tv_sec = 1, .tv_usec = 0 };
  BIO *rbio = SSL_get_rbio (ssl);
  if (rbio)
    BIO_ctrl (rbio,
              BIO_CTRL_DGRAM_SET_RECV_TIMEOUT,
              0,
              (void *)&DTLS_INITIAL_TIMEOUT);
}

void
SocketDTLS_enable (SocketDgram_T socket, SocketDTLSContext_T ctx)
{
  if (!socket)
    RAISE (SocketDTLS_Failed);
  if (!ctx)
    RAISE (SocketDTLS_Failed);
  if (!SocketDTLSContext_get_ssl_ctx (ctx))
    RAISE (SocketDTLS_Failed);

  validate_dtls_enable_preconditions (socket);
  SocketMetrics_counter_inc (SOCKET_CTR_DTLS_HANDSHAKES_TOTAL);

  volatile SSL *ssl = NULL;
  volatile BIO *bio = NULL;

  TRY
  {
    ssl = create_dtls_ssl_object (ctx);
    int fd = SocketBase_fd (socket->base);

    bio = create_dgram_bio (fd);
    SSL_set_bio ((SSL *)ssl, (BIO *)bio, (BIO *)bio);
    bio = NULL; /* Ownership transferred to SSL */

    configure_dtls_mtu ((SSL *)ssl, SocketDTLSContext_get_mtu (ctx));
    configure_dtls_retransmit_timeout ((SSL *)ssl);
    finalize_dtls_state (socket, (SSL *)ssl, ctx);

    ssl = NULL; /* Success - ownership transferred */
  }
  ELSE
  {
    if (ssl)
      SSL_free ((SSL *)ssl);
    if (bio)
      BIO_free ((BIO *)bio);
    RERAISE;
  }
  END_TRY;
}

void
SocketDTLS_set_peer (SocketDgram_T socket, const char *host, int port)
{
  if (!socket)
    RAISE (SocketDTLS_Failed);
  if (!host)
    RAISE (SocketDTLS_Failed);

  SSL *ssl = REQUIRE_DTLS_SSL (socket, SocketDTLS_Failed);

  BIO *bio = SSL_get_rbio (ssl);
  if (!bio)
    RAISE_DTLS_ERROR_MSG (SocketDTLS_Failed, "BIO not available");

  int64_t now_ms = Socket_get_monotonic_ms ();
  int cache_valid = dtls_peer_cache_valid (socket, host, port, now_ms);

  struct addrinfo *result;
  if (cache_valid)
    {
      result = socket->dtls_peer_res;
      SOCKET_LOG_DEBUG_MSG ("DTLS: Using cached peer resolution");
    }
  else
    {
      dtls_invalidate_peer_cache (socket);
      result = dtls_resolve_peer (host, port);
      dtls_cache_peer_resolution (socket, host, port, result, now_ms);
    }

  dtls_set_bio_peer_address (bio, result);
}

void
SocketDTLS_set_hostname (SocketDgram_T socket, const char *hostname)
{
  if (!socket)
    RAISE (SocketDTLS_Failed);
  if (!hostname)
    RAISE (SocketDTLS_Failed);

  REQUIRE_DTLS_ENABLED (socket, SocketDTLS_Failed);

  size_t hostname_len = strlen (hostname);
  if (hostname_len == 0)
    RAISE_DTLS_ERROR_MSG (SocketDTLS_Failed, "Hostname cannot be empty");

  if (hostname_len > SOCKET_DTLS_MAX_SNI_LEN)
    SOCKET_RAISE_FMT (SocketDTLS,
                      SocketDTLS_Failed,
                      "Hostname too long for SNI (%zu > %d max)",
                      hostname_len,
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

  if (!SocketSecurity_check_size (mtu))
    RAISE_DTLS_ERROR_MSG (SocketDTLS_Failed,
                          "MTU exceeds security allocation limit");

  if (!SOCKET_DTLS_VALID_MTU (mtu))
    SOCKET_RAISE_FMT (SocketDTLS,
                      SocketDTLS_Failed,
                      "Invalid MTU: %zu (must be %d-%d)",
                      mtu,
                      SOCKET_DTLS_MIN_MTU,
                      SOCKET_DTLS_MAX_MTU);

  SSL *ssl = REQUIRE_DTLS_SSL (socket, SocketDTLS_Failed);

  SSL_set_mtu (ssl, (long)mtu);
  DTLS_set_link_mtu (ssl, (long)mtu);
  socket->dtls_mtu = mtu;
}

/**
 * dtls_check_cookie_exchange_state - Check if SSL is in cookie exchange
 * @ssl: SSL object
 *
 * Determines if the DTLS server is currently in the cookie exchange phase
 * by checking the OpenSSL internal state. During cookie exchange, the server
 * has sent HelloVerifyRequest and is waiting for client's cookie response.
 *
 * Returns: 1 if in cookie exchange state, 0 otherwise
 */
static int
dtls_check_cookie_exchange_state (SSL *ssl)
{
  if (!ssl)
    return 0;

  /* Check if we're on server side and in early handshake state */
  if (!SSL_is_server (ssl))
    return 0;

  /* During cookie exchange, SSL_in_init() is true and we haven't received
   * a valid ClientHello with cookie yet. The OSSL_HANDSHAKE_STATE tells us
   * if we're waiting for client response after sending HelloVerifyRequest. */
  OSSL_HANDSHAKE_STATE hs_state = SSL_get_state (ssl);

  /* DTLS_ST_SW_HELLO_VERIFY_REQUEST means we just sent HelloVerifyRequest */
  /* TLS_ST_BEFORE with SSL_in_init means we're in early handshake state */
  if (hs_state == DTLS_ST_SW_HELLO_VERIFY_REQUEST
      || (hs_state == TLS_ST_BEFORE && SSL_in_init (ssl)))
    {
      return 1;
    }

  return 0;
}

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

  /* Handle DTLS timer - OpenSSL handles retransmission internally */
  int timeout_result = DTLSv1_handle_timeout (ssl);
  if (timeout_result < 0)
    {
      dtls_format_openssl_error ("DTLS timeout handling failed");
      socket->dtls_last_handshake_state = DTLS_HANDSHAKE_ERROR;
      return DTLS_HANDSHAKE_ERROR;
    }
  if (timeout_result > 0)
    {
      socket->dtls_retransmit_count++;
      if (socket->dtls_retransmit_count > SOCKET_DTLS_MAX_RETRANSMITS)
        {
          DTLS_ERROR_FMT ("DTLS retransmit limit exceeded (%d max)",
                          SOCKET_DTLS_MAX_RETRANSMITS);
          socket->dtls_last_handshake_state = DTLS_HANDSHAKE_ERROR;
          SocketMetrics_counter_inc (SOCKET_CTR_DTLS_HANDSHAKES_FAILED);
          RAISE_DTLS_ERROR (SocketDTLS_HandshakeFailed);
        }
    }

  int result = SSL_do_handshake (ssl);
  if (result == 1)
    {
      socket->dtls_handshake_done = 1;
      socket->dtls_retransmit_count = 0;
      socket->dtls_last_handshake_state = DTLS_HANDSHAKE_COMPLETE;
      SocketMetrics_counter_inc (SOCKET_CTR_DTLS_HANDSHAKES_COMPLETE);
      return DTLS_HANDSHAKE_COMPLETE;
    }

  DTLSHandshakeState state = dtls_handle_ssl_error (socket, ssl, result);

  /* Check for cookie exchange state on server side */
  if (state == DTLS_HANDSHAKE_WANT_READ || state == DTLS_HANDSHAKE_IN_PROGRESS)
    {
      if (dtls_check_cookie_exchange_state (ssl))
        {
          socket->dtls_last_handshake_state = DTLS_HANDSHAKE_COOKIE_EXCHANGE;
          return DTLS_HANDSHAKE_COOKIE_EXCHANGE;
        }
    }

  if (state == DTLS_HANDSHAKE_ERROR)
    {
      dtls_format_openssl_error ("DTLS handshake failed");
      SocketMetrics_counter_inc (SOCKET_CTR_DTLS_HANDSHAKES_FAILED);
      RAISE_DTLS_ERROR (SocketDTLS_HandshakeFailed);
    }

  socket->dtls_last_handshake_state = state;
  return state;
}

/**
 * calculate_handshake_poll_timeout - Compute poll timeout for DTLS handshake
 * @timeout_ms: User-specified timeout (-1 for infinite, 0 for non-blocking, >0
 * for deadline)
 * @infinite_timeout: 1 if infinite wait mode, 0 otherwise
 * @deadline_ms: Absolute deadline in milliseconds (ignored if infinite_timeout)
 *
 * Calculates appropriate poll(2) timeout value based on handshake timeout mode:
 * - Infinite wait: Returns reasonable default (1000ms) to handle DTLS timers
 * - Finite deadline: Returns remaining milliseconds until deadline
 *
 * Returns: poll timeout in milliseconds, or 0 if deadline expired
 */
static int
calculate_handshake_poll_timeout (int timeout_ms,
                                  int infinite_timeout,
                                  int64_t deadline_ms)
{
  DTLS_UNUSED (timeout_ms); /* Only used for mode detection */

  if (infinite_timeout)
    {
      /* Infinite wait: Use default DTLS timeout for timer handling */
      return SOCKET_DTLS_INITIAL_TIMEOUT_MS;
    }

  /* Compute remaining time from deadline */
  int poll_tmo = SocketTimeout_poll_timeout (-1, deadline_ms);
  if (poll_tmo <= 0)
    return 0; /* Deadline expired */

  return poll_tmo;
}

/**
 * get_poll_events_for_handshake_state - Map handshake state to poll events
 * @state: Current DTLS handshake state
 *
 * Determines which poll events (POLLIN/POLLOUT) to wait for based on the
 * handshake state machine's current position. Optimizes event mask to avoid
 * spurious wakeups during non-blocking handshake progression.
 *
 * Returns: poll event mask (POLLIN, POLLOUT, or POLLIN|POLLOUT)
 */
static short
get_poll_events_for_handshake_state (DTLSHandshakeState state)
{
  switch (state)
    {
    case DTLS_HANDSHAKE_WANT_READ:
    case DTLS_HANDSHAKE_COOKIE_EXCHANGE:
      /* Wait for incoming data */
      return POLLIN;

    case DTLS_HANDSHAKE_WANT_WRITE:
      /* Wait for socket writability */
      return POLLOUT;

    default:
      /* Unknown state or IN_PROGRESS: wait for both */
      return POLLIN | POLLOUT;
    }
}

/**
 * is_handshake_timeout_expired - Check if deadline has passed
 * @timeout_ms: Original timeout value
 * @deadline_ms: Deadline timestamp
 *
 * Returns: true if expired, false otherwise
 */
static int
is_handshake_timeout_expired (int timeout_ms, int64_t deadline_ms)
{
  if (timeout_ms <= 0)
    return 0; /* Infinite or non-blocking mode */
  return SocketTimeout_expired (deadline_ms);
}

/**
 * wait_for_handshake_io - Wait for I/O readiness with poll
 * @fd: File descriptor
 * @state: Current handshake state
 * @timeout_ms: Original timeout value
 * @deadline_ms: Deadline timestamp
 *
 * Returns: 1 if ready, 0 if timeout, raises on error
 */
static int
wait_for_handshake_io (int fd,
                       DTLSHandshakeState state,
                       int timeout_ms,
                       int64_t deadline_ms)
{
  struct pollfd pfd = { .fd = fd,
                        .events = get_poll_events_for_handshake_state (state),
                        .revents = 0 };

  int infinite = (timeout_ms < 0);
  int poll_tmo
      = calculate_handshake_poll_timeout (timeout_ms, infinite, deadline_ms);
  if (poll_tmo == 0)
    return 0; /* Deadline expired */

  int rc = poll (&pfd, 1, poll_tmo);
  if (rc < 0 && errno != EINTR)
    SOCKET_RAISE_FMT (SocketDTLS,
                      SocketDTLS_HandshakeFailed,
                      "poll failed: %s",
                      Socket_safe_strerror (errno));

  return 1; /* Ready or EINTR - continue loop */
}

/**
 * raise_handshake_timeout - Raise timeout exception
 * @socket: Socket instance
 *
 * Does not return.
 */
static void
raise_handshake_timeout (SocketDgram_T socket)
{
  DTLS_ERROR_MSG ("DTLS handshake timeout");
  socket->dtls_last_handshake_state = DTLS_HANDSHAKE_ERROR;
  RAISE_DTLS_ERROR (SocketDTLS_TimeoutExpired);
}

DTLSHandshakeState
SocketDTLS_handshake_loop (SocketDgram_T socket, int timeout_ms)
{
  assert (socket);
  REQUIRE_DTLS_ENABLED (socket, SocketDTLS_HandshakeFailed);

  if (socket->dtls_handshake_done)
    return DTLS_HANDSHAKE_COMPLETE;

  int fd = SocketBase_fd (socket->base);
  int64_t deadline_ms
      = (timeout_ms > 0) ? SocketTimeout_deadline_ms (timeout_ms) : 0;

  for (;;)
    {
      if (is_handshake_timeout_expired (timeout_ms, deadline_ms))
        break;

      DTLSHandshakeState state = SocketDTLS_handshake (socket);

      if (state == DTLS_HANDSHAKE_COMPLETE || state == DTLS_HANDSHAKE_ERROR)
        return state;

      if (timeout_ms == 0)
        return state; /* Non-blocking: single step only */

      if (!wait_for_handshake_io (fd, state, timeout_ms, deadline_ms))
        break; /* Deadline expired */
    }

  raise_handshake_timeout (socket);
  return DTLS_HANDSHAKE_ERROR; /* Unreachable */
}

/**
 * dtls_handle_listen_with_cookies - Process DTLSv1_listen with cookie exchange
 * @socket: Socket instance
 * @ssl: SSL object
 *
 * Handles the server-side DTLS listen operation with cookie exchange enabled.
 * DTLSv1_listen() performs stateless cookie verification:
 *
 * Returns:
 *   - DTLS_HANDSHAKE_COOKIE_EXCHANGE: Cookie sent, waiting for client response
 *   - DTLS_HANDSHAKE_IN_PROGRESS: Cookie verified, proceed to full handshake
 *   - DTLS_HANDSHAKE_WANT_READ: No data available (non-blocking)
 *   - DTLS_HANDSHAKE_ERROR: Fatal error during listen
 *
 * Note: DTLSv1_listen() return values:
 *   0: No ClientHello or HelloVerifyRequest sent, try again
 *   1: Cookie verified, ready for SSL_accept/handshake
 *  <0: Fatal error
 */
/**
 * handle_dtls_listen_error - Handle errors from DTLSv1_listen
 * @socket: Socket instance
 * @ssl: SSL object
 * @listen_result: Return value from DTLSv1_listen
 * @client_addr: BIO_ADDR to free on error
 *
 * Classifies and handles SSL errors from DTLSv1_listen, updating socket state
 * and freeing client_addr as needed. Returns appropriate handshake state.
 *
 * Returns: Handshake state (COOKIE_EXCHANGE, WANT_WRITE, or ERROR)
 */
static DTLSHandshakeState
handle_dtls_listen_error (SocketDgram_T socket,
                          SSL *ssl,
                          int listen_result,
                          BIO_ADDR *client_addr)
{
  int ssl_error = SSL_get_error (ssl, listen_result);

  /* Check if it's a retriable error (non-blocking) */
  if (ssl_error == SSL_ERROR_WANT_READ)
    {
      BIO_ADDR_free (client_addr);
      socket->dtls_last_handshake_state = DTLS_HANDSHAKE_COOKIE_EXCHANGE;
      return DTLS_HANDSHAKE_COOKIE_EXCHANGE;
    }

  if (ssl_error == SSL_ERROR_WANT_WRITE)
    {
      BIO_ADDR_free (client_addr);
      socket->dtls_last_handshake_state = DTLS_HANDSHAKE_WANT_WRITE;
      return DTLS_HANDSHAKE_WANT_WRITE;
    }

  /* Fatal error */
  dtls_format_openssl_error ("DTLS listen failed");
  BIO_ADDR_free (client_addr);
  socket->dtls_last_handshake_state = DTLS_HANDSHAKE_ERROR;
  return DTLS_HANDSHAKE_ERROR;
}

static DTLSHandshakeState
dtls_handle_listen_with_cookies (SocketDgram_T socket, SSL *ssl)
{
  BIO_ADDR *client_addr = BIO_ADDR_new ();
  if (!client_addr)
    RAISE_DTLS_ERROR_MSG (SocketDTLS_Failed,
                          "Failed to allocate client address");

  int listen_result = DTLSv1_listen (ssl, client_addr);

  if (listen_result < 0)
    return handle_dtls_listen_error (socket, ssl, listen_result, client_addr);

  if (listen_result == 0)
    {
      /* HelloVerifyRequest sent or waiting for data - cookie exchange phase */
      socket->dtls_last_handshake_state = DTLS_HANDSHAKE_COOKIE_EXCHANGE;
      BIO_ADDR_free (client_addr);
      return DTLS_HANDSHAKE_COOKIE_EXCHANGE;
    }

  /* listen_result > 0: Cookie verified successfully!
   * Set peer address for subsequent handshake operations */
  BIO *bio = SSL_get_rbio (ssl);
  if (bio)
    BIO_dgram_set_peer (bio, client_addr);

  BIO_ADDR_free (client_addr);
  socket->dtls_last_handshake_state = DTLS_HANDSHAKE_IN_PROGRESS;
  SocketMetrics_counter_inc (SOCKET_CTR_DTLS_COOKIES_VERIFIED);
  return DTLS_HANDSHAKE_IN_PROGRESS;
}

/**
 * dtls_handle_listen_no_cookies - Process listen without cookie exchange
 * @socket: Socket instance
 * @ssl: SSL object
 *
 * For servers without cookie exchange, just check for incoming ClientHello.
 *
 * Returns: Handshake state
 */
static DTLSHandshakeState
dtls_handle_listen_no_cookies (SocketDgram_T socket, SSL *ssl)
{
  DTLS_UNUSED (ssl);

  /* Without cookies, we skip DTLSv1_listen and go straight to handshake.
   * Just mark as in progress and let SocketDTLS_handshake() handle it. */
  socket->dtls_last_handshake_state = DTLS_HANDSHAKE_IN_PROGRESS;
  return DTLS_HANDSHAKE_IN_PROGRESS;
}

DTLSHandshakeState
SocketDTLS_listen (SocketDgram_T socket)
{
  assert (socket);

  SSL *ssl = REQUIRE_DTLS_SSL (socket, SocketDTLS_Failed);

  SocketDTLSContext_T ctx_local = (SocketDTLSContext_T)socket->dtls_ctx;

  if (ctx_local && SocketDTLSContext_has_cookie_exchange (ctx_local))
    return dtls_handle_listen_with_cookies (socket, ssl);

  return dtls_handle_listen_no_cookies (socket, ssl);
}

ssize_t
SocketDTLS_send (SocketDgram_T socket, const void *buf, size_t len)
{
  if (!socket)
    RAISE (SocketDTLS_Failed);
  if (!buf)
    RAISE (SocketDTLS_Failed);
  if (len == 0)
    RAISE (SocketDTLS_Failed);

  SSL *ssl = VALIDATE_DTLS_IO_READY (socket, SocketDTLS_Failed);

  /* Cap length to INT_MAX for OpenSSL API */
  int write_len = SocketSecurity_size_to_int (len);
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
  if (!socket)
    RAISE (SocketDTLS_Failed);
  if (!buf)
    RAISE (SocketDTLS_Failed);
  if (len == 0)
    RAISE (SocketDTLS_Failed);

  SSL *ssl = VALIDATE_DTLS_IO_READY (socket, SocketDTLS_Failed);

  /* Handle any pending timeout retransmissions */
  DTLSv1_handle_timeout (ssl);

  /* Cap length to INT_MAX for OpenSSL API */
  int read_len = SocketSecurity_size_to_int (len);
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
SocketDTLS_sendto (SocketDgram_T socket,
                   const void *buf,
                   size_t len,
                   const char *host,
                   int port)
{
  if (!socket)
    RAISE (SocketDTLS_Failed);
  if (!buf)
    RAISE (SocketDTLS_Failed);
  if (!host)
    RAISE (SocketDTLS_Failed);

  /* Set peer address then send */
  SocketDTLS_set_peer (socket, host, port);
  return SocketDTLS_send (socket, buf, len);
}

/**
 * dtls_parse_port_string - Parse port number from string
 * @port_str: Port string to parse
 *
 * Returns: Port number (1-65535) or 0 on invalid input
 */
static int
dtls_parse_port_string (const char *port_str)
{
  if (!port_str || !*port_str)
    return 0;

  char *endptr;
  errno = 0; /* Clear errno before call (CERT C: ERR07-C) */
  long p = strtol (port_str, &endptr, 10);
  if (errno == ERANGE || endptr == port_str || *endptr != '\0')
    return 0;
  if (p >= 1 && p <= 65535)
    return (int)p;
  return 0;
}

/**
 * dtls_extract_peer_address - Extract peer address from BIO
 * @bio: BIO to query
 * @host: Output buffer for hostname (may be NULL)
 * @host_len: Size of host buffer
 * @port: Output for port (may be NULL)
 *
 * Returns: 1 on success, 0 on failure
 */
static int
dtls_extract_peer_address (BIO *bio, char *host, size_t host_len, int *port)
{
  if (!bio)
    return 0;

  BIO_ADDR *peer_addr = BIO_ADDR_new ();
  if (!peer_addr)
    return 0;

  int success = 0;
  if (BIO_dgram_get_peer (bio, peer_addr))
    {
      success = 1;
      if (host && host_len > 0)
        {
          memset (host, 0, host_len);
          char *addr_str = BIO_ADDR_hostname_string (peer_addr, 1);
          if (addr_str)
            {
              strncpy (host, addr_str, host_len - 1);
              OPENSSL_free (addr_str);
            }
          else
            {
              host[0] = '\0';
            }
        }
      if (port)
        {
          char *port_str = BIO_ADDR_service_string (peer_addr, 1);
          if (port_str)
            {
              *port = dtls_parse_port_string (port_str);
              OPENSSL_free (port_str);
            }
          else
            {
              *port = 0;
            }
        }
    }

  BIO_ADDR_free (peer_addr);
  return success;
}

ssize_t
SocketDTLS_recvfrom (SocketDgram_T socket,
                     void *buf,
                     size_t len,
                     char *host,
                     size_t host_len,
                     int *port)
{
  if (!socket)
    RAISE (SocketDTLS_Failed);
  if (!buf)
    RAISE (SocketDTLS_Failed);

  SSL *ssl = VALIDATE_DTLS_IO_READY (socket, SocketDTLS_Failed);

  ssize_t n = SocketDTLS_recv (socket, buf, len);

  if (n > 0 && (host || port))
    {
      BIO *bio = SSL_get_rbio (ssl);
      if (!dtls_extract_peer_address (bio, host, host_len, port))
        {
          if (host && host_len > 0)
            host[0] = '\0';
          if (port)
            *port = 0;
        }
    }

  return n;
}

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

/**
 * dtls_shutdown_single_attempt - Perform single SSL_shutdown attempt
 * @socket: Socket instance
 * @ssl: SSL object
 *
 * Returns: 1 if complete, 0 to continue, -1 on fatal error
 */
static int
dtls_shutdown_single_attempt (SocketDgram_T socket, SSL *ssl)
{
  if (DTLSv1_handle_timeout (ssl) < 0)
    {
      dtls_format_openssl_error ("DTLS timeout handling during shutdown");
      return 0; /* Continue despite timeout issue */
    }

  int result = SSL_shutdown (ssl);
  if (result == 1)
    {
      socket->dtls_shutdown_done = 1;
      free_dtls_resources (socket);
      return 1;
    }

  if (result < 0)
    {
      DTLSHandshakeState state = dtls_handle_ssl_error (socket, ssl, result);
      if (state == DTLS_HANDSHAKE_ERROR)
        {
          dtls_format_openssl_error ("DTLS shutdown error");
          return -1;
        }
    }

  return 0;
}

/**
 * dtls_shutdown_poll_wait - Wait for I/O events during shutdown
 * @fd: File descriptor to poll
 * @deadline_ms: Deadline in monotonic milliseconds
 *
 * Returns: 0 on success/timeout, -1 on fatal poll error
 * Raises: SocketDTLS_ShutdownFailed on poll error
 */
static int
dtls_shutdown_poll_wait (int fd, int64_t deadline_ms)
{
  struct pollfd pfd = { .fd = fd, .events = POLLIN | POLLOUT };
  int poll_tmo = SocketTimeout_poll_timeout (
      SOCKET_DTLS_SHUTDOWN_POLL_INTERVAL_MS, deadline_ms);
  int pr = poll (&pfd, 1, poll_tmo);

  if (pr < 0 && errno != EINTR)
    SOCKET_RAISE_FMT (SocketDTLS,
                      SocketDTLS_ShutdownFailed,
                      "poll failed during shutdown: %s",
                      Socket_safe_strerror (errno));
  return 0;
}

void
SocketDTLS_shutdown (SocketDgram_T socket)
{
  assert (socket);

  REQUIRE_DTLS_ENABLED (socket, SocketDTLS_ShutdownFailed);

  if (socket->dtls_shutdown_done)
    return;

  SSL *ssl = REQUIRE_DTLS_SSL (socket, SocketDTLS_ShutdownFailed);

  int fd = SocketBase_fd (socket->base);
  if (fd < 0)
    RAISE_DTLS_ERROR_MSG (SocketDTLS_ShutdownFailed,
                          "Invalid socket fd during shutdown");

  int64_t deadline_ms
      = SocketTimeout_deadline_ms (SOCKET_DTLS_DEFAULT_SHUTDOWN_TIMEOUT_MS);

  while (!SocketTimeout_expired (deadline_ms))
    {
      int result = dtls_shutdown_single_attempt (socket, ssl);
      if (result == 1)
        return;
      if (result < 0)
        RAISE_DTLS_ERROR (SocketDTLS_ShutdownFailed);

      dtls_shutdown_poll_wait (fd, deadline_ms);
    }

  dtls_format_openssl_error ("DTLS shutdown timeout or incomplete");
  RAISE_DTLS_ERROR (SocketDTLS_ShutdownFailed);
}

int
SocketDTLS_is_shutdown (SocketDgram_T socket)
{
  return socket ? socket->dtls_shutdown_done : 0;
}

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
