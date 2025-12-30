/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* SocketHTTPClient-auth.c - HTTP Authentication (RFC 7617 Basic, RFC 7616 Digest, RFC 6750 Bearer) */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "core/SocketCrypto.h"
#include "core/SocketUtil.h"
#include "http/SocketHTTP-private.h"
#include "http/SocketHTTPClient-private.h"

typedef struct
{
  char realm[HTTPCLIENT_DIGEST_REALM_MAX_LEN];
  char nonce[HTTPCLIENT_DIGEST_NONCE_MAX_LEN];
  char opaque[HTTPCLIENT_DIGEST_OPAQUE_MAX_LEN];
  char qop[HTTPCLIENT_DIGEST_QOP_MAX_LEN];
  char algorithm[HTTPCLIENT_DIGEST_ALGORITHM_MAX_LEN];
  int stale;
} DigestChallenge;

typedef void (*HttpAuthParamCallback)(const char *name, const char *value, void *userdata);

static const char *parse_quoted_string (const char *p, char *out,
                                        size_t out_size);
static const char *parse_token_value (const char *p, char *out,
                                      size_t out_size);
static const char *skip_quoted_value (const char *p);
static const char *parse_parameter_name (const char *p, char *name,
                                         size_t name_size);
static void store_challenge_field (DigestChallenge *ch, const char *name,
                                   const char *value);
static int check_stale_value(const char *value);
static int parse_http_auth_params(const char *header, int require_prefix,
                                  HttpAuthParamCallback cb, void *userdata);
static const char *skip_to_next_param(const char *p);

#define skip_delimiters sockethttp_skip_delimiters
#define skip_whitespace sockethttp_skip_whitespace
#define is_token_boundary sockethttp_is_token_boundary
static const char *
advance_quoted_content (const char *p, char *out, size_t out_size)
{
  size_t i = 0;
  size_t max_copy = out ? (out_size - 1) : SIZE_MAX;

  while (*p && *p != '"' && i < max_copy)
    {
      char ch;
      if (*p == '\\' && *(p + 1) != '\0')
        {
          p++;
          ch = *p++;
        }
      else
        {
          ch = *p++;
        }

      if (out)
        out[i++] = ch;
    }

  if (out)
    out[i] = '\0';

  return p;
}

static const char *
parse_quoted_string (const char *p, char *out, size_t out_size)
{
  if (*p != '"')
    return NULL;

  p++;
  p = advance_quoted_content (p, out, out_size);

  if (*p != '"')
    return NULL;

  return p + 1;
}

static const char *
parse_token_value (const char *p, char *out, size_t out_size)
{
  size_t i = 0;

  while (!is_token_boundary (*p) && i < out_size - 1)
    out[i++] = *p++;

  out[i] = '\0';
  return p;
}

static const char *
skip_quoted_value (const char *p)
{
  if (*p != '"')
    return p;

  p++;
  p = advance_quoted_content (p, NULL, 0);

  if (*p == '"')
    p++;

  return p;
}

static const char *
parse_param_value (const char *p, char *out, size_t out_size)
{
  p = skip_whitespace (p);
  return (*p == '"') ? parse_quoted_string (p, out, out_size)
                     : parse_token_value (p, out, out_size);
}

static const char *
parse_parameter_name (const char *p, char *name, size_t name_size)
{
  size_t i = 0;

  while (*p && *p != '=' && !is_token_boundary (*p) && i < name_size - 1)
    name[i++] = *p++;

  name[i] = '\0';
  p = skip_whitespace (p);

  return (*p == '=') ? p : NULL;
}

static void
store_challenge_field (DigestChallenge *ch, const char *name,
                       const char *value)
{
  if (strcasecmp (name, "realm") == 0)
    socket_util_safe_strncpy (ch->realm, value, sizeof (ch->realm));
  else if (strcasecmp (name, "nonce") == 0)
    socket_util_safe_strncpy (ch->nonce, value, sizeof (ch->nonce));
  else if (strcasecmp (name, "opaque") == 0)
    socket_util_safe_strncpy (ch->opaque, value, sizeof (ch->opaque));
  else if (strcasecmp (name, "qop") == 0)
    socket_util_safe_strncpy (ch->qop, value, sizeof (ch->qop));
  else if (strcasecmp (name, "algorithm") == 0)
    socket_util_safe_strncpy (ch->algorithm, value, sizeof (ch->algorithm));
  else if (strcasecmp (name, "stale") == 0)
    ch->stale = check_stale_value(value);
}

static void
store_param_cb(const char *name, const char *value, void *userdata) {
    DigestChallenge *ch = (DigestChallenge *)userdata;
    store_challenge_field(ch, name, value);
}

static void
check_stale_cb(const char *name, const char *value, void *userdata) {
    int *is_stale = (int *)userdata;
    if (strcasecmp(name, "stale") == 0) {
        *is_stale |= check_stale_value(value);
    }
}

static void
digest_hash (const void *data, size_t len, int use_sha256, char *hex_output)
{
  if (use_sha256)
    {
      unsigned char hash[SOCKET_CRYPTO_SHA256_SIZE];
      SocketCrypto_sha256 (data, len, hash);
      SocketCrypto_hex_encode (hash, sizeof (hash), hex_output, 1);
    }
  else
    {
      unsigned char hash[SOCKET_CRYPTO_MD5_SIZE];
      SocketCrypto_md5 (data, len, hash);
      SocketCrypto_hex_encode (hash, sizeof (hash), hex_output, 1);
    }
}

static int
compute_digest_a (const char *arg1, const char *arg2, const char *arg3,
                  int use_sha256, int secure_clear, char *ha_hex)
{
  char buffer[HTTPCLIENT_DIGEST_A_BUFFER_SIZE];
  int len;

  if (arg3 != NULL)
    len = snprintf (buffer, sizeof (buffer), "%s:%s:%s", arg1, arg2, arg3);
  else
    len = snprintf (buffer, sizeof (buffer), "%s:%s", arg1, arg2);

  if (len < 0 || (size_t)len >= sizeof (buffer))
    return -1;

  digest_hash (buffer, (size_t)len, use_sha256, ha_hex);

  if (secure_clear)
    SocketCrypto_secure_clear (buffer, sizeof (buffer));

  return 0;
}

static int
compute_ha1 (const char *username, const char *realm, const char *password,
             int use_sha256, char *ha1_hex)
{
  return compute_digest_a (username, realm, password, use_sha256, 1, ha1_hex);
}

static int
compute_ha2 (const char *method, const char *uri, int use_sha256,
             char *ha2_hex)
{
  return compute_digest_a (method, uri, NULL, use_sha256, 0, ha2_hex);
}

/* Compute response hash with or without qop (RFC 2617/7616) */
static int
compute_response_hash (const char *ha1_hex, const char *nonce, const char *nc,
                       const char *cnonce, const char *qop,
                       const char *ha2_hex, int use_sha256, char *response_hex)
{
  char buf[HTTPCLIENT_DIGEST_A_BUFFER_SIZE];
  int len;

  if (qop != NULL && strcmp (qop, HTTPCLIENT_DIGEST_TOKEN_AUTH) == 0)
    {
      if (nc == NULL || cnonce == NULL)
        return -1;

      len = snprintf (buf, sizeof (buf), "%s:%s:%s:%s:%s:%s", ha1_hex, nonce,
                      nc, cnonce, qop, ha2_hex);
    }
  else
    {
      len = snprintf (buf, sizeof (buf), "%s:%s:%s", ha1_hex, nonce, ha2_hex);
    }

  if (len < 0 || (size_t)len >= sizeof (buf))
    return -1;

  digest_hash (buf, (size_t)len, use_sha256, response_hex);
  return 0;
}

int
httpclient_auth_basic_header (const char *username, const char *password,
                              char *output, size_t output_size)
{
  char credentials[HTTPCLIENT_AUTH_CREDENTIALS_SIZE];
  int cred_len;
  ssize_t encoded_len;
  size_t base64_size;

  assert (username != NULL);
  assert (password != NULL);
  assert (output != NULL);
  assert (output_size > 0);

  cred_len = snprintf (credentials, sizeof (credentials), "%s:%s", username,
                       password);
  if (cred_len < 0 || (size_t)cred_len >= sizeof (credentials))
    {
      SOCKET_LOG_WARN_MSG (
          "Basic auth credentials too long: username='%.*s' password_len=%zu",
          (int)strnlen (username, 32), username, strlen (password));
      return -1;
    }

  base64_size = SocketCrypto_base64_encoded_size ((size_t)cred_len);
  if (HTTPCLIENT_BASIC_PREFIX_LEN + base64_size > output_size)
    return -1;

  /* Write prefix followed by base64-encoded credentials */
  memcpy (output, HTTPCLIENT_BASIC_PREFIX, HTTPCLIENT_BASIC_PREFIX_LEN);
  output[HTTPCLIENT_BASIC_PREFIX_LEN] = '\0';  /* Temporary termination */
  encoded_len
      = SocketCrypto_base64_encode (credentials, (size_t)cred_len,
                                    output + HTTPCLIENT_BASIC_PREFIX_LEN,
                                    output_size - HTTPCLIENT_BASIC_PREFIX_LEN);
  SocketCrypto_secure_clear (credentials, sizeof (credentials));

  return (encoded_len < 0) ? -1 : 0;
}

int
httpclient_auth_bearer_header (const char *token, char *output,
                               size_t output_size)
{
  size_t token_len;
  size_t needed;

  assert (token != NULL);
  assert (output != NULL);
  assert (output_size > 0);

  token_len = strlen (token);
  needed = HTTPCLIENT_BEARER_PREFIX_LEN + token_len + 1;

  if (needed > output_size)
    {
      SOCKET_LOG_WARN_MSG ("Bearer token too long for output buffer: "
                           "token_len=%zu needed=%zu available=%zu",
                           token_len, needed, output_size);
      return -1;
    }

  memcpy (output, HTTPCLIENT_BEARER_PREFIX, HTTPCLIENT_BEARER_PREFIX_LEN);
  memcpy (output + HTTPCLIENT_BEARER_PREFIX_LEN, token, token_len);
  output[HTTPCLIENT_BEARER_PREFIX_LEN + token_len] = '\0';

  return 0;
}

static int
format_digest_header (const char *username, const char *realm,
                      const char *nonce, const char *uri, int use_sha256,
                      const char *qop, const char *nc, const char *cnonce,
                      const char *response_hex, char *output,
                      size_t output_size)
{
  int written;

  if (qop != NULL && nc != NULL && cnonce != NULL)
    {
      written = snprintf (output, output_size,
                          "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", "
                          "uri=\"%s\", algorithm=%s, qop=%s, nc=%s, "
                          "cnonce=\"%s\", response=\"%s\"",
                          username, realm, nonce, uri,
                          use_sha256 ? "SHA-256" : "MD5", qop, nc, cnonce,
                          response_hex);
    }
  else
    {
      written = snprintf (output, output_size,
                          "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", "
                          "uri=\"%s\", algorithm=%s, response=\"%s\"",
                          username, realm, nonce, uri,
                          use_sha256 ? "SHA-256" : "MD5", response_hex);
    }

  return (written < 0 || (size_t)written >= output_size) ? -1 : 0;
}

int
httpclient_auth_digest_response (const char *username, const char *password,
                                 const char *realm, const char *nonce,
                                 const char *uri, const char *method,
                                 const char *qop, const char *nc,
                                 const char *cnonce, int use_sha256,
                                 char *output, size_t output_size)
{
  char ha1_hex[HTTPCLIENT_DIGEST_HEX_SIZE];
  char ha2_hex[HTTPCLIENT_DIGEST_HEX_SIZE];
  char response_hex[HTTPCLIENT_DIGEST_HEX_SIZE];

  assert (username != NULL);
  assert (password != NULL);
  assert (realm != NULL);
  assert (nonce != NULL);
  assert (uri != NULL);
  assert (method != NULL);
  assert (output != NULL);
  assert (output_size > 0);

  if (compute_ha1 (username, realm, password, use_sha256, ha1_hex) != 0)
    return -1;

  if (compute_ha2 (method, uri, use_sha256, ha2_hex) != 0)
    return -1;

  if (compute_response_hash (ha1_hex, nonce, nc, cnonce, qop, ha2_hex,
                             use_sha256, response_hex)
      != 0)
    return -1;

  return format_digest_header (username, realm, nonce, uri, use_sha256,
                               (qop != NULL
                                && strcmp (qop, HTTPCLIENT_DIGEST_TOKEN_AUTH)
                                       == 0)
                                   ? qop
                                   : NULL,
                               nc, cnonce, response_hex, output, output_size);
}

static const char *
skip_digest_prefix (const char *header, int strict)
{
  if (strncasecmp (header, HTTPCLIENT_DIGEST_PREFIX,
                   HTTPCLIENT_DIGEST_PREFIX_LEN)
      == 0)
    return header + HTTPCLIENT_DIGEST_PREFIX_LEN;

  return strict ? NULL : header;
}

static int
validate_challenge (const DigestChallenge *ch)
{
  if (ch->realm[0] == '\0' || ch->nonce[0] == '\0')
    {
      SOCKET_LOG_WARN_MSG (
          "Digest challenge missing required field: realm='%s' nonce='%s'",
          ch->realm, ch->nonce);
      return -1;
    }
  return 0;
}

static int
parse_digest_challenge (const char *header, DigestChallenge *ch)
{
  memset (ch, 0, sizeof (*ch));
  int res = parse_http_auth_params(header, 1, store_param_cb, ch);
  if (res != 0)
    return -1;
  if (validate_challenge (ch) != 0)
    return -1;

  if (ch->algorithm[0] == '\0')
    socket_util_safe_strncpy (ch->algorithm, "MD5", sizeof (ch->algorithm));

  return 0;
}

static int
parse_http_auth_params(const char *header, int require_prefix,
                       HttpAuthParamCallback cb, void *userdata) {
  const char *p = skip_digest_prefix(header, require_prefix);
  if (require_prefix && p == NULL) {
    SOCKET_LOG_WARN_MSG("Missing Digest prefix in auth header");
    return -1;
  }

  while (*p) {
    p = skip_delimiters(p);
    if (*p == '\0') break;

    char name[HTTPCLIENT_DIGEST_PARAM_NAME_MAX_LEN];
    const char *eq_pos = parse_parameter_name(p, name, sizeof(name));
    if (eq_pos == NULL || *eq_pos != '=') {
      p = skip_to_next_param(p);
      continue;
    }

    p = eq_pos + 1;
    p = skip_whitespace(p);

    char value[HTTPCLIENT_DIGEST_VALUE_MAX_LEN];
    const char *next_p = parse_param_value(p, value, sizeof(value));
    if (next_p == NULL) {
      p = skip_to_next_param(p);
      continue;
    }

    cb(name, value, userdata);
    p = next_p;
  }

  return 0;
}

static void
generate_cnonce (char *cnonce, size_t size)
{
  unsigned char random_bytes[HTTPCLIENT_DIGEST_CNONCE_SIZE];

  assert (cnonce != NULL);
  assert (size >= HTTPCLIENT_DIGEST_CNONCE_HEX_SIZE);
  (void)size;

  if (SocketCrypto_random_bytes (random_bytes, sizeof (random_bytes)) != 0)
    {
      uint64_t t = (uint64_t)time (NULL);
      memcpy (random_bytes, &t, sizeof (t));
      memset (random_bytes + sizeof (t), 0,
              sizeof (random_bytes) - sizeof (t));
    }

  SocketCrypto_hex_encode (random_bytes, sizeof (random_bytes), cnonce, 1);
  SocketCrypto_secure_clear (random_bytes, sizeof (random_bytes));
}

/* Find "auth" token in qop list (qop=auth-int not supported) */
static const char *
find_auth_qop (const char *qop_list)
{
  const char *p = qop_list;

  while (*p)
    {
      p = skip_delimiters (p);
      if (*p == '\0')
        break;

      if (strncmp (p, HTTPCLIENT_DIGEST_TOKEN_AUTH,
                   HTTPCLIENT_DIGEST_TOKEN_AUTH_LEN)
              == 0
          && is_token_boundary (p[HTTPCLIENT_DIGEST_TOKEN_AUTH_LEN]))
        return HTTPCLIENT_DIGEST_TOKEN_AUTH;

      while (*p && *p != ',')
        p++;
    }

  return NULL;
}

int
httpclient_auth_digest_challenge (const char *www_authenticate,
                                  const char *username, const char *password,
                                  const char *method, const char *uri,
                                  const char *nc_value, char *output,
                                  size_t output_size)
{
  DigestChallenge ch;
  char cnonce[HTTPCLIENT_DIGEST_CNONCE_HEX_SIZE];
  int use_sha256;
  const char *qop = NULL;

  assert (www_authenticate != NULL);
  assert (username != NULL);
  assert (password != NULL);
  assert (method != NULL);
  assert (uri != NULL);
  assert (output != NULL);

  if (parse_digest_challenge (www_authenticate, &ch) != 0)
    return -1;

  use_sha256 = (strcasecmp (ch.algorithm, "SHA-256") == 0
                || strcasecmp (ch.algorithm, "SHA-256-sess") == 0);

  generate_cnonce (cnonce, sizeof (cnonce));

  if (ch.qop[0] != '\0')
    qop = find_auth_qop (ch.qop);

  return httpclient_auth_digest_response (
      username, password, ch.realm, ch.nonce, uri, method, qop, nc_value,
      cnonce, use_sha256, output, output_size);
}

static int
check_stale_value (const char *value)
{
  return strcasecmp (value, HTTPCLIENT_DIGEST_TOKEN_TRUE) == 0;
}

static const char *
skip_to_next_param (const char *p)
{
  while (*p && *p != ',')
    {
      if (*p == '"')
        p = skip_quoted_value (p);
      else
        p++;
    }
  return p;
}

int
httpclient_auth_is_stale_nonce (const char *www_authenticate)
{
  if (www_authenticate == NULL)
    return 0;

  int is_stale = 0;
  parse_http_auth_params(www_authenticate, 0, check_stale_cb, &is_stale);
  return is_stale;
}
