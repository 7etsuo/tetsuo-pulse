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

/** Number of timestamp buckets to check (current + previous for edge cases) */
#define COOKIE_TIMESTAMP_WINDOW 2

/** Number of secrets to try (current + previous for rotation) */
#define COOKIE_SECRET_COUNT 2

/* Security: Random offset for bucket boundaries, initialized once per process.
 * This makes bucket boundaries unpredictable to attackers, preventing them
 * from timing replay attacks around known bucket transitions. */
static uint32_t bucket_offset = 0;
static pthread_once_t bucket_offset_once = PTHREAD_ONCE_INIT;

static void
init_bucket_offset (void)
{
  unsigned char rand_bytes[4];
  /* SECURITY: Fail on RNG failure instead of using predictable offset */
  if (SocketCrypto_random_bytes (rand_bytes, sizeof (rand_bytes)) != 0)
    {
      /* RNG failure - this is a critical security issue */
      RAISE (SocketCrypto_Failed);
    }
  uint32_t rand_val = ((uint32_t)rand_bytes[0] << 24)
                      | ((uint32_t)rand_bytes[1] << 16)
                      | ((uint32_t)rand_bytes[2] << 8)
                      | (uint32_t)rand_bytes[3];
  bucket_offset = rand_val % (SOCKET_DTLS_COOKIE_LIFETIME_SEC * 1000);
}

static uint32_t
get_time_bucket (void)
{
  pthread_once (&bucket_offset_once, init_bucket_offset);

  int64_t now_ms = Socket_get_monotonic_ms ();
  int64_t lifetime_ms = (int64_t)SOCKET_DTLS_COOKIE_LIFETIME_SEC * 1000LL;
  int64_t offset_now_ms = now_ms + bucket_offset;
  return (uint32_t)(offset_now_ms / lifetime_ms);
}



static int
bio_addr_to_sockaddr_storage (BIO_ADDR *bio_addr, struct sockaddr_storage *peer_addr,
                              socklen_t *peer_len)
{
  int family = BIO_ADDR_family (bio_addr);
  if (family == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in *)peer_addr;
    size_t addr_len = sizeof (sin->sin_addr);
    *peer_len = sizeof (struct sockaddr_in);
    memset (peer_addr, 0, *peer_len);
    sin->sin_family = AF_INET;
    sin->sin_port = BIO_ADDR_rawport (bio_addr);
    BIO_ADDR_rawaddress (bio_addr, &sin->sin_addr, &addr_len);
    return 0;
  } else if (family == AF_INET6) {
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
get_peer_from_bio_dgram (BIO *bio, struct sockaddr_storage *peer_addr,
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
get_peer_address_from_ssl (SSL *ssl, struct sockaddr_storage *peer_addr,
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
                     const struct sockaddr *peer_addr, socklen_t peer_len,
                     uint32_t timestamp, unsigned char *out_cookie)
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
    SocketCrypto_hmac_sha256 (secret, SOCKET_DTLS_COOKIE_SECRET_LEN, input,
                              input_len, out_cookie);
    result = 0;
  }
  EXCEPT (SocketCrypto_Failed) { result = -1; }
  END_TRY;

  return result;
}

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

static int
is_secret_set (const unsigned char *secret)
{
  static const unsigned char zeros[SOCKET_DTLS_COOKIE_SECRET_LEN] = { 0 };
  return SocketCrypto_secure_compare (secret, zeros,
                                      SOCKET_DTLS_COOKIE_SECRET_LEN)
         != 0;
}

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

  if (pthread_mutex_lock (&ctx->cookie.secret_mutex) != 0)
    return 0;

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

  ctx = dtls_context_get_from_ssl (ssl);
  if (!ctx || !ctx->cookie.cookie_enabled)
    return 0;

  if (cookie_len != SOCKET_DTLS_COOKIE_LEN)
    return 0;

  if (get_peer_address_from_ssl (ssl, &peer_addr, &peer_len) != 0)
    return 0;

  addr = (const struct sockaddr *)&peer_addr;
  timestamp = get_time_bucket ();

  if (pthread_mutex_lock (&ctx->cookie.secret_mutex) != 0)
    return 0;


  const unsigned char *secrets[COOKIE_SECRET_COUNT] = {
    ctx->cookie.secret,
    ctx->cookie.prev_secret
  };
  int num_secrets = 1;
  if (is_secret_set (secrets[1])) {
    num_secrets = COOKIE_SECRET_COUNT;
  }

  verified = 0;
  for (int s = 0; s < num_secrets; s++) {
    for (int t = 0; t < COOKIE_TIMESTAMP_WINDOW; t++) {
      /* Prevent underflow: only subtract if t <= timestamp */
      if ((uint32_t)t > timestamp)
        continue;
      uint32_t ts = timestamp - (uint32_t)t;
      if (try_verify_cookie (cookie, secrets[s], addr, peer_len, ts, expected)) {
        verified = 1;
        goto cleanup;
      }
    }
  }

cleanup:
  pthread_mutex_unlock (&ctx->cookie.secret_mutex);
  SocketCrypto_secure_clear (expected, sizeof (expected));

  if (!verified)
    SocketMetrics_counter_inc (SOCKET_CTR_DTLS_COOKIE_VERIFICATION_FAILURES);

  return verified;
}

#endif /* SOCKET_HAS_TLS */
