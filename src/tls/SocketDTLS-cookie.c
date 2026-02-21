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
 * Cookie format (SOCKET_DTLS_COOKIE_LEN bytes):
 *   [ timestamp_u32_be ][ hmac_tag... ]
 *
 * Where:
 * - timestamp is monotonic seconds at generation time (32-bit, big-endian)
 * - hmac_tag is a truncated HMAC-SHA256 over (peer_addr || timestamp)
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

/** Timestamp prefix in cookie (monotonic seconds, big-endian) */
#define COOKIE_TIMESTAMP_LEN 4

/** Number of secrets to try (current + previous for rotation) */
#define COOKIE_SECRET_COUNT 2

_Static_assert (SOCKET_DTLS_COOKIE_LEN > COOKIE_TIMESTAMP_LEN,
                "DTLS cookie must be large enough to store timestamp + tag");

static uint32_t
dtls_cookie_time_seconds (void)
{
  int64_t now_ms = Socket_get_monotonic_ms ();
  if (now_ms < 0)
    now_ms = 0;
  return (uint32_t)(now_ms / 1000);
}


static int
bio_addr_to_sockaddr_storage (BIO_ADDR *bio_addr,
                              struct sockaddr_storage *peer_addr,
                              socklen_t *peer_len)
{
  int family = BIO_ADDR_family (bio_addr);
  if (family == AF_INET)
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
  else if (family == AF_INET6)
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
  return -1;
}

static int
get_peer_from_bio_dgram (BIO *bio,
                         struct sockaddr_storage *peer_addr,
                         socklen_t *peer_len)
{
  BIO_ADDR *bio_addr;
  int result = -1;

  bio_addr = BIO_ADDR_new ();
  if (!bio_addr)
    return -1;

  if (!BIO_dgram_get_peer (bio, bio_addr))
    goto cleanup;

  result = bio_addr_to_sockaddr_storage (bio_addr, peer_addr, peer_len);

cleanup:
  BIO_ADDR_free (bio_addr);
  return result;
}

static int
get_peer_address_from_ssl (SSL *ssl,
                           struct sockaddr_storage *peer_addr,
                           socklen_t *peer_len)
{
  BIO *bio;
  int fd;

  bio = SSL_get_rbio (ssl);
  if (!bio)
    return -1;

  fd = BIO_get_fd (bio, NULL);
  if (fd >= 0)
    {
      *peer_len = sizeof (*peer_addr);
      if (getpeername (fd, (struct sockaddr *)peer_addr, peer_len) == 0)
        return 0;
    }

  return get_peer_from_bio_dgram (bio, peer_addr, peer_len);
}

static int
compute_cookie_hmac (const unsigned char *secret,
                     const struct sockaddr *peer_addr,
                     socklen_t peer_len,
                     uint32_t timestamp,
                     unsigned char *out_cookie)
{
  unsigned char input[sizeof (struct sockaddr_storage) + sizeof (uint32_t)];
  size_t input_len = 0;
  uint32_t ts_net;
  volatile int result = -1;

  if (peer_len == 0 || peer_len > sizeof (struct sockaddr_storage))
    return -1;

  memcpy (input, peer_addr, peer_len);
  input_len = peer_len;

  ts_net = htonl (timestamp);
  memcpy (input + input_len, &ts_net, sizeof (ts_net));
  input_len += sizeof (ts_net);

  TRY
  {
    SocketCrypto_hmac_sha256 (
        secret, SOCKET_DTLS_COOKIE_SECRET_LEN, input, input_len, out_cookie);
    result = 0;
  }
  EXCEPT (SocketCrypto_Failed)
  {
    result = -1;
  }
  END_TRY;

  return result;
}

static int
try_verify_cookie (const unsigned char *cookie,
                   const unsigned char *secret,
                   const struct sockaddr *peer_addr,
                   socklen_t peer_len,
                   uint32_t timestamp,
                   unsigned char *expected)
{
  if (compute_cookie_hmac (secret, peer_addr, peer_len, timestamp, expected)
      != 0)
    return 0;

  size_t tag_len = SOCKET_DTLS_COOKIE_LEN - COOKIE_TIMESTAMP_LEN;
  return SocketCrypto_secure_compare (
             cookie + COOKIE_TIMESTAMP_LEN, expected, tag_len)
         == 0;
}

static int
is_secret_set (const unsigned char *secret)
{
  static const unsigned char zeros[SOCKET_DTLS_COOKIE_SECRET_LEN] = { 0 };
  return SocketCrypto_secure_compare (
             secret, zeros, SOCKET_DTLS_COOKIE_SECRET_LEN)
         != 0;
}

int
dtls_generate_cookie_hmac (const unsigned char *secret,
                           const struct sockaddr *peer_addr,
                           socklen_t peer_len,
                           unsigned char *out_cookie)
{
  if (!secret || !peer_addr || !out_cookie)
    return -1;

  uint32_t ts = dtls_cookie_time_seconds ();
  uint32_t ts_net = htonl (ts);
  memcpy (out_cookie, &ts_net, sizeof (ts_net));

  unsigned char tag[SOCKET_DTLS_COOKIE_LEN];
  if (compute_cookie_hmac (secret, peer_addr, peer_len, ts, tag) != 0)
    {
      SocketCrypto_secure_clear (tag, sizeof (tag));
      return -1;
    }

  size_t tag_len = SOCKET_DTLS_COOKIE_LEN - COOKIE_TIMESTAMP_LEN;
  memcpy (out_cookie + COOKIE_TIMESTAMP_LEN, tag, tag_len);
  SocketCrypto_secure_clear (tag, sizeof (tag));

  return 0;
}

int
dtls_cookie_generate_cb (SSL *ssl,
                         unsigned char *cookie,
                         unsigned int *cookie_len)
{
  SocketDTLSContext_T ctx;
  struct sockaddr_storage peer_addr;
  socklen_t peer_len;
  unsigned char local_secret[SOCKET_DTLS_COOKIE_SECRET_LEN];

  ctx = dtls_context_get_from_ssl (ssl);
  if (!ctx || !ctx->cookie.cookie_enabled)
    return 0;

  if (get_peer_address_from_ssl (ssl, &peer_addr, &peer_len) != 0)
    return 0;

  if (pthread_mutex_lock (&ctx->cookie.secret_mutex) != 0)
    return 0;

  memcpy (local_secret, ctx->cookie.secret, sizeof (local_secret));
  pthread_mutex_unlock (&ctx->cookie.secret_mutex);

  int result = dtls_generate_cookie_hmac (
      local_secret, (struct sockaddr *)&peer_addr, peer_len, cookie);
  SocketCrypto_secure_clear (local_secret, sizeof (local_secret));

  if (result != 0)
    return 0;

  *cookie_len = SOCKET_DTLS_COOKIE_LEN;
  SocketMetrics_counter_inc (SOCKET_CTR_DTLS_COOKIES_GENERATED);
  return 1;
}

int
dtls_cookie_verify_cb (SSL *ssl,
                       const unsigned char *cookie,
                       unsigned int cookie_len)
{
  SocketDTLSContext_T ctx;
  struct sockaddr_storage peer_addr;
  socklen_t peer_len;
  const struct sockaddr *addr;
  int verified = 0;

  ctx = dtls_context_get_from_ssl (ssl);
  if (!ctx || !ctx->cookie.cookie_enabled)
    return 0;

  if (cookie_len != SOCKET_DTLS_COOKIE_LEN)
    return 0;

  if (get_peer_address_from_ssl (ssl, &peer_addr, &peer_len) != 0)
    return 0;

  addr = (const struct sockaddr *)&peer_addr;

  uint32_t ts_net = 0;
  memcpy (&ts_net, cookie, sizeof (ts_net));
  uint32_t timestamp = ntohl (ts_net);

  uint32_t now = dtls_cookie_time_seconds ();
  if (timestamp > now || (now - timestamp) > SOCKET_DTLS_COOKIE_LIFETIME_SEC)
    return 0;

  unsigned char secret[SOCKET_DTLS_COOKIE_SECRET_LEN];
  unsigned char prev_secret[SOCKET_DTLS_COOKIE_SECRET_LEN];
  int has_prev = 0;

  if (pthread_mutex_lock (&ctx->cookie.secret_mutex) != 0)
    return 0;

  memcpy (secret, ctx->cookie.secret, sizeof (secret));
  memcpy (prev_secret, ctx->cookie.prev_secret, sizeof (prev_secret));
  pthread_mutex_unlock (&ctx->cookie.secret_mutex);

  has_prev = is_secret_set (prev_secret);

  unsigned char expected[SOCKET_DTLS_COOKIE_LEN];

  if (try_verify_cookie (cookie, secret, addr, peer_len, timestamp, expected))
    {
      verified = 1;
    }
  else if (has_prev
           && try_verify_cookie (
               cookie, prev_secret, addr, peer_len, timestamp, expected))
    {
      verified = 1;
    }

  SocketCrypto_secure_clear (secret, sizeof (secret));
  SocketCrypto_secure_clear (prev_secret, sizeof (prev_secret));
  SocketCrypto_secure_clear (expected, sizeof (expected));

  if (!verified)
    SocketMetrics_counter_inc (SOCKET_CTR_DTLS_COOKIE_VERIFICATION_FAILURES);

  return verified;
}

#endif /* SOCKET_HAS_TLS */
