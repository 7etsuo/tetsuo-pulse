/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

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
#include <string.h>
#include <time.h>

/* ============================================================================
 * Constants
 * ============================================================================
 */

/** Number of timestamp buckets to check (current + previous for edge cases) */
#define COOKIE_TIMESTAMP_WINDOW 2

/** Number of secrets to try (current + previous for rotation) */
#define COOKIE_SECRET_COUNT 2

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================
 */

/**
 * get_time_bucket - Get current monotonic time bucket
 *
 * Returns monotonic time truncated to SOCKET_DTLS_COOKIE_LIFETIME_SEC
 * intervals. Uses Socket_get_monotonic_ms() to prevent clock manipulation
 * attacks.
 *
 * Returns: Current time bucket as uint32_t
 */
static uint32_t
get_time_bucket (void)
{
  int64_t now_ms = Socket_get_monotonic_ms ();
  int64_t lifetime_ms = (int64_t)SOCKET_DTLS_COOKIE_LIFETIME_SEC * 1000LL;
  return (uint32_t)(now_ms / lifetime_ms);
}

/**
 * extract_ipv4_address - Extract IPv4 address from BIO_ADDR
 * @bio_addr: Source BIO address
 * @peer_addr: Output sockaddr_storage
 * @peer_len: Output address length
 *
 * Returns: 0 on success, -1 on failure
 */
static int
extract_ipv4_address (BIO_ADDR *bio_addr, struct sockaddr_storage *peer_addr,
                      socklen_t *peer_len)
{
  struct sockaddr_in *sin = (struct sockaddr_in *)peer_addr;
  size_t addr_len = sizeof (sin->sin_addr);

  *peer_len = sizeof (struct sockaddr_in);
  memset (peer_addr, 0, *peer_len);

  sin->sin_family = AF_INET;
  sin->sin_port = BIO_ADDR_rawport (bio_addr);
  BIO_ADDR_rawaddress (bio_addr, &sin->sin_addr, &addr_len);

  return 0;
}

/**
 * extract_ipv6_address - Extract IPv6 address from BIO_ADDR
 * @bio_addr: Source BIO address
 * @peer_addr: Output sockaddr_storage
 * @peer_len: Output address length
 *
 * Returns: 0 on success, -1 on failure
 */
static int
extract_ipv6_address (BIO_ADDR *bio_addr, struct sockaddr_storage *peer_addr,
                      socklen_t *peer_len)
{
  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)peer_addr;
  size_t addr_len = sizeof (sin6->sin6_addr);

  *peer_len = sizeof (struct sockaddr_in6);
  memset (peer_addr, 0, *peer_len);

  sin6->sin6_family = AF_INET6;
  sin6->sin6_port = BIO_ADDR_rawport (bio_addr);
  sin6->sin6_flowinfo = 0;
  sin6->sin6_scope_id = 0;
  BIO_ADDR_rawaddress (bio_addr, &sin6->sin6_addr, &addr_len);

  return 0;
}

/**
 * get_peer_from_bio_dgram - Extract peer address from DTLS BIO
 * @bio: SSL read BIO
 * @peer_addr: Output sockaddr_storage
 * @peer_len: Output address length
 *
 * Returns: 0 on success, -1 on failure
 */
static int
get_peer_from_bio_dgram (BIO *bio, struct sockaddr_storage *peer_addr,
                         socklen_t *peer_len)
{
  BIO_ADDR *bio_addr;
  int family;
  int result = -1;

  bio_addr = BIO_ADDR_new ();
  if (!bio_addr)
    return -1;

  if (!BIO_dgram_get_peer (bio, bio_addr))
    goto cleanup;

  family = BIO_ADDR_family (bio_addr);

  if (family == AF_INET)
    result = extract_ipv4_address (bio_addr, peer_addr, peer_len);
  else if (family == AF_INET6)
    result = extract_ipv6_address (bio_addr, peer_addr, peer_len);

cleanup:
  BIO_ADDR_free (bio_addr);
  return result;
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
 * Returns: 0 on success, -1 on failure
 */
static int
get_peer_address_from_ssl (SSL *ssl, struct sockaddr_storage *peer_addr,
                           socklen_t *peer_len)
{
  BIO *bio;
  int fd;

  bio = SSL_get_rbio (ssl);
  if (!bio)
    return -1;

  /* Try getpeername first via underlying fd */
  fd = BIO_get_fd (bio, NULL);
  if (fd >= 0)
    {
      *peer_len = sizeof (*peer_addr);
      if (getpeername (fd, (struct sockaddr *)peer_addr, peer_len) == 0)
        return 0;
    }

  /* Fallback: Extract from BIO dgram peer address */
  return get_peer_from_bio_dgram (bio, peer_addr, peer_len);
}

/**
 * compute_cookie_hmac - Compute HMAC-SHA256 cookie
 * @secret: Secret key (SOCKET_DTLS_COOKIE_SECRET_LEN bytes)
 * @peer_addr: Peer socket address
 * @peer_len: Peer address length
 * @timestamp: Timestamp bucket
 * @out_cookie: Output buffer (SOCKET_DTLS_COOKIE_LEN bytes)
 *
 * Note: Called from OpenSSL callbacks which expect return codes, not
 * exceptions. Catches SocketCrypto_Failed and converts to return code.
 *
 * Returns: 0 on success, -1 on failure
 */
static int
compute_cookie_hmac (const unsigned char *secret,
                     const struct sockaddr *peer_addr, socklen_t peer_len,
                     uint32_t timestamp, unsigned char *out_cookie)
{
  unsigned char input[sizeof (struct sockaddr_storage) + sizeof (uint32_t)];
  size_t input_len = 0;
  uint32_t ts_net;
  volatile int result = -1;

  if (peer_len > sizeof (struct sockaddr_storage))
    return -1;

  /* Build HMAC input: peer_addr || timestamp (network byte order) */
  memcpy (input, peer_addr, peer_len);
  input_len = peer_len;

  ts_net = htonl (timestamp);
  memcpy (input + input_len, &ts_net, sizeof (ts_net));
  input_len += sizeof (ts_net);

  /* Compute HMAC-SHA256 - catch exceptions for OpenSSL callback context */
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

/**
 * try_verify_cookie - Attempt to verify cookie against one secret/timestamp
 * @cookie: Cookie to verify
 * @secret: Secret key to try
 * @peer_addr: Peer socket address
 * @peer_len: Peer address length
 * @timestamp: Timestamp bucket to try
 * @expected: Buffer for computed expected cookie (SOCKET_DTLS_COOKIE_LEN)
 *
 * Computes expected cookie and performs constant-time comparison.
 *
 * Returns: 1 if cookie matches, 0 otherwise
 */
static int
try_verify_cookie (const unsigned char *cookie, const unsigned char *secret,
                   const struct sockaddr *peer_addr, socklen_t peer_len,
                   uint32_t timestamp, unsigned char *expected)
{
  if (compute_cookie_hmac (secret, peer_addr, peer_len, timestamp, expected)
      != 0)
    return 0;

  return SocketCrypto_secure_compare (cookie, expected, SOCKET_DTLS_COOKIE_LEN)
         == 0;
}

/**
 * is_secret_set - Check if a secret buffer contains non-zero data
 * @secret: Secret buffer to check
 *
 * Uses constant-time comparison against zeros to avoid timing attacks.
 *
 * Returns: 1 if secret is set (non-zero), 0 if all zeros
 */
static int
is_secret_set (const unsigned char *secret)
{
  static const unsigned char zeros[SOCKET_DTLS_COOKIE_SECRET_LEN] = { 0 };
  return SocketCrypto_secure_compare (secret, zeros,
                                      SOCKET_DTLS_COOKIE_SECRET_LEN)
         != 0;
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

  return compute_cookie_hmac (secret, peer_addr, peer_len, get_time_bucket (),
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
  SocketDTLSContext_T ctx;
  struct sockaddr_storage peer_addr;
  socklen_t peer_len;
  int result;

  ctx = dtls_context_get_from_ssl (ssl);
  if (!ctx || !ctx->cookie.cookie_enabled)
    return 0;

  if (get_peer_address_from_ssl (ssl, &peer_addr, &peer_len) != 0)
    return 0;

  pthread_mutex_lock (&ctx->cookie.secret_mutex);
  result = dtls_generate_cookie_hmac (ctx->cookie.secret,
                                      (struct sockaddr *)&peer_addr, peer_len,
                                      cookie);
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
 * Tries current and previous secrets with current and previous timestamp
 * buckets to handle rotation and edge cases near bucket boundaries.
 *
 * Returns: 1 if valid, 0 if invalid
 */
int
dtls_cookie_verify_cb (SSL *ssl, const unsigned char *cookie,
                       unsigned int cookie_len)
{
  SocketDTLSContext_T ctx;
  struct sockaddr_storage peer_addr;
  socklen_t peer_len;
  unsigned char expected[SOCKET_DTLS_COOKIE_LEN];
  const struct sockaddr *addr;
  uint32_t timestamp;
  int verified = 0;

  /* Validate context and cookie length */
  ctx = dtls_context_get_from_ssl (ssl);
  if (!ctx || !ctx->cookie.cookie_enabled)
    return 0;

  if (cookie_len != SOCKET_DTLS_COOKIE_LEN)
    return 0;

  if (get_peer_address_from_ssl (ssl, &peer_addr, &peer_len) != 0)
    return 0;

  addr = (const struct sockaddr *)&peer_addr;
  timestamp = get_time_bucket ();

  pthread_mutex_lock (&ctx->cookie.secret_mutex);

  /* Try current secret with current and previous timestamp buckets */
  if (try_verify_cookie (cookie, ctx->cookie.secret, addr, peer_len, timestamp,
                         expected)
      || try_verify_cookie (cookie, ctx->cookie.secret, addr, peer_len,
                            timestamp - 1, expected))
    {
      verified = 1;
      goto cleanup;
    }

  /* Try previous secret if set (for rotation window) */
  if (is_secret_set (ctx->cookie.prev_secret))
    {
      if (try_verify_cookie (cookie, ctx->cookie.prev_secret, addr, peer_len,
                             timestamp, expected)
          || try_verify_cookie (cookie, ctx->cookie.prev_secret, addr,
                                peer_len, timestamp - 1, expected))
        {
          verified = 1;
          goto cleanup;
        }
    }

cleanup:
  pthread_mutex_unlock (&ctx->cookie.secret_mutex);

  /* Always clear expected cookie from stack - security critical */
  SocketCrypto_secure_clear (expected, sizeof (expected));

  if (!verified)
    SocketMetrics_counter_inc (SOCKET_CTR_DTLS_COOKIE_VERIFICATION_FAILURES);

  return verified;
}

#endif /* SOCKET_HAS_TLS */
