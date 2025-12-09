/**
 * SocketDTLS-cookie.c - DTLS Cookie Exchange Implementation
 *
 * Part of the Socket Library
 *
 * Implements RFC 6347 stateless cookie exchange for DoS protection.
 * Server sends HelloVerifyRequest with cookie before allocating state.
 * Client must echo cookie to prove address ownership.
 *
 * Cookie = HMAC-SHA256(server_secret, client_addr || client_port || timestamp)
 *
 * Thread safety: Cookie verification is thread-safe. Secret rotation
 * requires locking and should be done atomically.
 */

#if SOCKET_HAS_TLS

#include "core/Except.h"
#include "core/SocketCrypto.h"
#include "core/SocketMetrics.h"
#include "tls/SocketDTLS-private.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <time.h>

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================
 */

/**
 * get_time_bucket - Get current monotonic time bucket
 *
 * Returns monotonic time truncated to SOCKET_DTLS_COOKIE_LIFETIME_SEC
 * intervals. Uses Socket_get_monotonic_ms() to prevent clock manipulation
 * attacks. This allows cookies to be valid for approximately the lifetime
 * period without needing to embed exact timestamp in cookie.
 */
static uint32_t
get_time_bucket (void)
{
  int64_t now_ms = Socket_get_monotonic_ms ();
  int64_t lifetime_ms = (int64_t)SOCKET_DTLS_COOKIE_LIFETIME_SEC * 1000LL;
  return (uint32_t)(now_ms / lifetime_ms);
}

/**
 * get_peer_address_from_ssl - Extract peer address from SSL connection
 * @ssl: SSL object
 * @peer_addr: Output buffer for peer address
 * @peer_len: Output for address length
 *
 * Tries getpeername() via underlying socket fd first, falls back to
 * BIO_dgram_get_peer() for DTLS/UDP peer tracking.
 *
 * Returns: 0 on success, -1 on failure (unknown address family or extraction
 * failed)
 */
static int
get_peer_address_from_ssl (SSL *ssl, struct sockaddr_storage *peer_addr,
                           socklen_t *peer_len)
{
  /* Try getpeername first */
  BIO *bio = SSL_get_rbio (ssl);
  if (bio)
    {
      int fd = BIO_get_fd (bio, NULL);
      if (fd >= 0)
        {
          *peer_len = sizeof (*peer_addr);
          if (getpeername (fd, (struct sockaddr *)peer_addr, peer_len) == 0)
            return 0;
        }
    }

  /* Fallback: Extract from BIO dgram peer address */
  BIO_ADDR *bio_addr = BIO_ADDR_new ();
  if (!bio_addr)
    return -1;

  if (bio && BIO_dgram_get_peer (bio, bio_addr))
    {
      int family = BIO_ADDR_family (bio_addr);
      if (family == AF_INET)
        {
          *peer_len = sizeof (struct sockaddr_in);
          memset (peer_addr, 0, *peer_len);
          struct sockaddr_in *sin = (struct sockaddr_in *)peer_addr;
          sin->sin_family = AF_INET;
          sin->sin_port = BIO_ADDR_rawport (bio_addr);
          size_t addr_len = sizeof (sin->sin_addr);
          BIO_ADDR_rawaddress (bio_addr, &sin->sin_addr, &addr_len);
          BIO_ADDR_free (bio_addr);
          return 0;
        }
      else if (family == AF_INET6)
        {
          *peer_len = sizeof (struct sockaddr_in6);
          memset (peer_addr, 0, *peer_len);
          struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)peer_addr;
          sin6->sin6_family = AF_INET6;
          sin6->sin6_port = BIO_ADDR_rawport (bio_addr);
          sin6->sin6_flowinfo = 0;
          sin6->sin6_scope_id = 0;
          size_t addr_len = sizeof (sin6->sin6_addr);
          BIO_ADDR_rawaddress (bio_addr, &sin6->sin6_addr, &addr_len);
          BIO_ADDR_free (bio_addr);
          return 0;
        }
    }
  BIO_ADDR_free (bio_addr);
  return -1;
}

/**
 * compute_cookie_hmac - Compute HMAC-SHA256 cookie
 * @secret: Secret key (SOCKET_DTLS_COOKIE_SECRET_LEN bytes)
 * @peer_addr: Peer socket address
 * @peer_len: Peer address length
 * @timestamp: Timestamp bucket
 * @out_cookie: Output buffer (SOCKET_DTLS_COOKIE_LEN bytes)
 *
 * Returns: 0 on success, -1 on failure
 *
 * Note: This function is called from OpenSSL callbacks which expect return
 * codes, not exceptions. We catch any exceptions from SocketCrypto and
 * convert them to return codes.
 */
static int
compute_cookie_hmac (const unsigned char *secret,
                     const struct sockaddr *peer_addr, socklen_t peer_len,
                     uint32_t timestamp, unsigned char *out_cookie)
{
  /* Build input: peer_addr || timestamp */
  unsigned char input[sizeof (struct sockaddr_storage) + sizeof (uint32_t)];
  size_t input_len = 0;
  volatile int result = -1;

  if (peer_len > sizeof (struct sockaddr_storage))
    return -1;

  memcpy (input, peer_addr, peer_len);
  input_len += peer_len;

  uint32_t ts_net = htonl (timestamp);
  memcpy (input + input_len, &ts_net, sizeof (ts_net));
  input_len += sizeof (ts_net);

  /* Compute HMAC-SHA256 using SocketCrypto.
   * Catch exceptions since this is called from OpenSSL callbacks
   * that expect return codes, not exceptions. */
  TRY
  {
    SocketCrypto_hmac_sha256 (secret, SOCKET_DTLS_COOKIE_SECRET_LEN, input,
                              input_len, out_cookie);
    result = 0;
  }
  EXCEPT (SocketCrypto_Failed) { result = -1; }
  END_TRY;

  return result;
}

/* ============================================================================
 * Public Cookie Functions (called by SocketDTLSContext.c)
 * ============================================================================
 */

/**
 * dtls_generate_cookie_hmac - Generate HMAC-based cookie
 * @secret: Secret key
 * @peer_addr: Peer socket address
 * @peer_len: Peer address length
 * @out_cookie: Output buffer (SOCKET_DTLS_COOKIE_LEN bytes)
 *
 * Returns: 0 on success, -1 on failure
 */
int
dtls_generate_cookie_hmac (const unsigned char *secret,
                           const struct sockaddr *peer_addr,
                           socklen_t peer_len, unsigned char *out_cookie)
{
  if (!secret || !peer_addr || !out_cookie)
    return -1;

  uint32_t timestamp = get_time_bucket ();
  return compute_cookie_hmac (secret, peer_addr, peer_len, timestamp,
                              out_cookie);
}

/* ============================================================================
 * OpenSSL Cookie Callbacks
 * ============================================================================
 */

/**
 * dtls_cookie_generate_cb - OpenSSL cookie generation callback
 * @ssl: SSL object
 * @cookie: Output buffer for cookie
 * @cookie_len: Output for cookie length
 *
 * Called by OpenSSL during DTLS handshake when server sends
 * HelloVerifyRequest.
 *
 * Returns: 1 on success, 0 on failure
 */
int
dtls_cookie_generate_cb (SSL *ssl, unsigned char *cookie,
                         unsigned int *cookie_len)
{
  SocketDTLSContext_T ctx = dtls_context_get_from_ssl (ssl);
  if (!ctx || !ctx->cookie.cookie_enabled)
    return 0;

  /* Get peer address */
  struct sockaddr_storage peer_addr;
  socklen_t peer_len;

  if (get_peer_address_from_ssl (ssl, &peer_addr, &peer_len) != 0)
    return 0;

  /* Generate cookie with current secret */
  pthread_mutex_lock (&ctx->cookie.secret_mutex);
  int result = dtls_generate_cookie_hmac (
      ctx->cookie.secret, (struct sockaddr *)&peer_addr, peer_len, cookie);
  pthread_mutex_unlock (&ctx->cookie.secret_mutex);

  if (result != 0)
    return 0;

  *cookie_len = SOCKET_DTLS_COOKIE_LEN;
  SocketMetrics_counter_inc (SOCKET_CTR_DTLS_COOKIES_GENERATED);
  return 1;
}

/**
 * dtls_cookie_verify_cb - OpenSSL cookie verification callback
 * @ssl: SSL object
 * @cookie: Cookie to verify
 * @cookie_len: Cookie length
 *
 * Called by OpenSSL to verify cookie echoed by client in ClientHello.
 *
 * Returns: 1 if valid, 0 if invalid
 */
int
dtls_cookie_verify_cb (SSL *ssl, const unsigned char *cookie,
                       unsigned int cookie_len)
{
  SocketDTLSContext_T ctx = dtls_context_get_from_ssl (ssl);
  if (!ctx || !ctx->cookie.cookie_enabled)
    return 0;

  if (cookie_len != SOCKET_DTLS_COOKIE_LEN)
    return 0;

  /* Get peer address */
  struct sockaddr_storage peer_addr;
  socklen_t peer_len;

  if (get_peer_address_from_ssl (ssl, &peer_addr, &peer_len) != 0)
    return 0;

  pthread_mutex_lock (&ctx->cookie.secret_mutex);

  /* Try current timestamp bucket */
  uint32_t timestamp = get_time_bucket ();
  unsigned char expected_cookie[SOCKET_DTLS_COOKIE_LEN];

  /* Verify with current secret */
  if (compute_cookie_hmac (ctx->cookie.secret, (struct sockaddr *)&peer_addr,
                           peer_len, timestamp, expected_cookie)
      == 0)
    {
      if (SocketCrypto_secure_compare (cookie, expected_cookie,
                                       SOCKET_DTLS_COOKIE_LEN)
          == 0)
        {
          SocketCrypto_secure_clear (expected_cookie,
                                     sizeof (expected_cookie));
          pthread_mutex_unlock (&ctx->cookie.secret_mutex);
          return 1;
        }
    }

  /* Try previous timestamp bucket (for edge cases near bucket boundary) */
  if (compute_cookie_hmac (ctx->cookie.secret, (struct sockaddr *)&peer_addr,
                           peer_len, timestamp - 1, expected_cookie)
      == 0)
    {
      if (SocketCrypto_secure_compare (cookie, expected_cookie,
                                       SOCKET_DTLS_COOKIE_LEN)
          == 0)
        {
          SocketCrypto_secure_clear (expected_cookie,
                                     sizeof (expected_cookie));
          pthread_mutex_unlock (&ctx->cookie.secret_mutex);
          return 1;
        }
    }

  /* Try with previous secret (for rotation) */
  unsigned char zero_secret[SOCKET_DTLS_COOKIE_SECRET_LEN] = { 0 };
  SocketCrypto_secure_clear (zero_secret, sizeof (zero_secret));
  if (SocketCrypto_secure_compare (ctx->cookie.prev_secret, zero_secret,
                                   SOCKET_DTLS_COOKIE_SECRET_LEN)
      != 0)
    {
      /* Previous secret is set */
      if (compute_cookie_hmac (ctx->cookie.prev_secret,
                               (struct sockaddr *)&peer_addr, peer_len,
                               timestamp, expected_cookie)
          == 0)
        {
          if (SocketCrypto_secure_compare (cookie, expected_cookie,
                                           SOCKET_DTLS_COOKIE_LEN)
              == 0)
            {
              pthread_mutex_unlock (&ctx->cookie.secret_mutex);
              return 1;
            }
        }

      if (compute_cookie_hmac (ctx->cookie.prev_secret,
                               (struct sockaddr *)&peer_addr, peer_len,
                               timestamp - 1, expected_cookie)
          == 0)
        {
          if (SocketCrypto_secure_compare (cookie, expected_cookie,
                                           SOCKET_DTLS_COOKIE_LEN)
              == 0)
            {
              pthread_mutex_unlock (&ctx->cookie.secret_mutex);
              return 1;
            }
        }
    }
  SocketCrypto_secure_clear (zero_secret, sizeof (zero_secret));

  pthread_mutex_unlock (&ctx->cookie.secret_mutex);

  /* Clear expected cookie from stack using SocketCrypto */
  SocketCrypto_secure_clear (expected_cookie, sizeof (expected_cookie));

  SocketMetrics_counter_inc (SOCKET_CTR_DTLS_COOKIE_VERIFICATION_FAILURES);

  return 0;
}

#endif /* SOCKET_HAS_TLS */
