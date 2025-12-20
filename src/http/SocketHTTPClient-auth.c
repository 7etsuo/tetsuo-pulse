/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketHTTPClient-auth.c - HTTP Authentication Implementation
 *
 * Part of the Socket Library
 *
 * Implements HTTP authentication schemes:
 * - Basic Authentication (RFC 7617) - Uses SocketCrypto_base64_encode()
 * - Digest Authentication (RFC 7616) - Uses SocketCrypto_md5(),
 * SocketCrypto_sha256()
 * - Bearer Token (RFC 6750) - Simple token header
 *
 * Leverages SocketCrypto for all cryptographic operations to avoid
 * duplication.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "core/SocketCrypto.h"
#include "core/SocketUtil.h"
#include "http/SocketHTTP-private.h"
#include "http/SocketHTTPClient-private.h"

/* ============================================================================
 * Digest Challenge Structure
 * ============================================================================
 */

/**
 * Parsed Digest authentication challenge
 */
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

/* ============================================================================
 * Forward Declarations
 * ============================================================================
 */

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

/* ============================================================================
 * String Utility Helpers
 * ============================================================================
 */

/**
 * safe_strcpy - Copy string with truncation
 * @dst: Destination buffer
 * @dst_size: Size of destination buffer
 * @src: Source string
 *
 * Copies at most dst_size-1 characters and always null-terminates.
 */
static void
safe_strcpy (char *dst, size_t dst_size, const char *src)
{
  size_t copy_len;

  if (dst_size == 0)
    return;

  copy_len = strlen (src);
  if (copy_len >= dst_size)
    copy_len = dst_size - 1;

  memcpy (dst, src, copy_len);
  dst[copy_len] = '\0';
}

/* Use shared utilities from SocketHTTP-private.h */
#define skip_delimiters sockethttp_skip_delimiters
#define skip_whitespace sockethttp_skip_whitespace
#define is_token_boundary sockethttp_is_token_boundary

/* ============================================================================
 * Quoted String Parsing
 * ============================================================================
 */

/**
 * advance_quoted_content - Advance past quoted string content handling escapes
 * @p: Pointer after opening quote
 * @out: Output buffer (NULL to skip without copying)
 * @out_size: Output buffer size
 *
 * Returns: Pointer at closing quote or end of input
 */
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

/**
 * parse_quoted_string - Parse a quoted string value
 * @p: Pointer starting at opening quote
 * @out: Output buffer
 * @out_size: Output buffer size
 *
 * Returns: Pointer past closing quote, or NULL on error
 */
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

/**
 * parse_token_value - Parse unquoted token value
 * @p: Pointer to start of value
 * @out: Output buffer
 * @out_size: Output buffer size
 *
 * Returns: Pointer past value
 */
static const char *
parse_token_value (const char *p, char *out, size_t out_size)
{
  size_t i = 0;

  while (*p && *p != ',' && *p != ' ' && *p != '\t' && i < out_size - 1)
    out[i++] = *p++;

  out[i] = '\0';
  return p;
}

/**
 * skip_quoted_value - Skip past a quoted value including escapes
 * @p: Pointer starting at opening quote
 *
 * Returns: Pointer past closing quote
 */
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

/**
 * parse_param_value - Parse parameter value after '='
 * @p: Pointer after '='
 * @out: Output buffer
 * @out_size: Output buffer size
 *
 * Returns: Pointer past value, or NULL on error
 */
static const char *
parse_param_value (const char *p, char *out, size_t out_size)
{
  p = skip_whitespace (p);
  return (*p == '"') ? parse_quoted_string (p, out, out_size)
                     : parse_token_value (p, out, out_size);
}

/* ============================================================================
 * Parameter Name Parsing
 * ============================================================================
 */

/**
 * parse_parameter_name - Parse parameter name up to '='
 * @p: Pointer to start of parameter
 * @name: Output buffer for name
 * @name_size: Name buffer size
 *
 * Returns: Pointer at '=', or NULL on error
 */
static const char *
parse_parameter_name (const char *p, char *name, size_t name_size)
{
  size_t i = 0;

  while (*p && *p != '=' && *p != ',' && *p != ' ' && *p != '\t'
         && i < name_size - 1)
    name[i++] = *p++;

  name[i] = '\0';
  p = skip_whitespace (p);

  return (*p == '=') ? p : NULL;
}

/* ============================================================================
 * Challenge Field Storage
 * ============================================================================
 */

/**
 * store_challenge_field - Store parsed field in challenge structure
 * @ch: Challenge structure (output)
 * @name: Field name (read-only)
 * @value: Field value (read-only)
 */
static void
store_challenge_field (DigestChallenge *ch, const char *name,
                       const char *value)
{
  if (strcasecmp (name, "realm") == 0)
    safe_strcpy (ch->realm, sizeof (ch->realm), value);
  else if (strcasecmp (name, "nonce") == 0)
    safe_strcpy (ch->nonce, sizeof (ch->nonce), value);
  else if (strcasecmp (name, "opaque") == 0)
    safe_strcpy (ch->opaque, sizeof (ch->opaque), value);
  else if (strcasecmp (name, "qop") == 0)
    safe_strcpy (ch->qop, sizeof (ch->qop), value);
  else if (strcasecmp (name, "algorithm") == 0)
    safe_strcpy (ch->algorithm, sizeof (ch->algorithm), value);
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

/* ============================================================================
 * Digest Hash Computation
 * ============================================================================
 */

/**
 * digest_hash - Compute hash and format as lowercase hex string
 * @data: Input data
 * @len: Input length
 * @use_sha256: Use SHA-256 (1) or MD5 (0)
 * @hex_output: Output buffer (must be HTTPCLIENT_DIGEST_HEX_SIZE)
 */
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

/**
 * compute_ha1 - Compute H(A1) = H(username:realm:password)
 * @username: Username
 * @realm: Realm from challenge
 * @password: Password
 * @use_sha256: Use SHA-256 (1) or MD5 (0)
 * @ha1_hex: Output buffer (must be HTTPCLIENT_DIGEST_HEX_SIZE)
 *
 * Returns: 0 on success, -1 on error
 */
static int
compute_ha1 (const char *username, const char *realm, const char *password,
             int use_sha256, char *ha1_hex)
{
  char a1[HTTPCLIENT_DIGEST_A_BUFFER_SIZE];
  int len;

  len = snprintf (a1, sizeof (a1), "%s:%s:%s", username, realm, password);
  if (len < 0 || (size_t)len >= sizeof (a1))
    return -1;

  digest_hash (a1, (size_t)len, use_sha256, ha1_hex);
  SocketCrypto_secure_clear (a1, sizeof (a1));

  return 0;
}

/**
 * compute_ha2 - Compute H(A2) = H(method:uri)
 * @method: HTTP method
 * @uri: Request URI
 * @use_sha256: Use SHA-256 (1) or MD5 (0)
 * @ha2_hex: Output buffer (must be HTTPCLIENT_DIGEST_HEX_SIZE)
 *
 * Returns: 0 on success, -1 on error
 */
static int
compute_ha2 (const char *method, const char *uri, int use_sha256,
             char *ha2_hex)
{
  char a2[HTTPCLIENT_DIGEST_A_BUFFER_SIZE];
  int len;

  len = snprintf (a2, sizeof (a2), "%s:%s", method, uri);
  if (len < 0 || (size_t)len >= sizeof (a2))
    return -1;

  digest_hash (a2, (size_t)len, use_sha256, ha2_hex);
  return 0;
}

/**
 * compute_response_with_qop - Compute response with qop=auth
 * @ha1_hex: H(A1) as hex
 * @nonce: Server nonce
 * @nc: Nonce count
 * @cnonce: Client nonce
 * @qop: QoP value
 * @ha2_hex: H(A2) as hex
 * @use_sha256: Use SHA-256 or MD5
 * @response_hex: Output buffer
 *
 * Returns: 0 on success, -1 on error
 */
static int
compute_response_with_qop (const char *ha1_hex, const char *nonce,
                           const char *nc, const char *cnonce, const char *qop,
                           const char *ha2_hex, int use_sha256,
                           char *response_hex)
{
  char buf[HTTPCLIENT_DIGEST_A_BUFFER_SIZE];
  int len;

  if (nc == NULL || cnonce == NULL)
    return -1;

  len = snprintf (buf, sizeof (buf), "%s:%s:%s:%s:%s:%s", ha1_hex, nonce, nc,
                  cnonce, qop, ha2_hex);
  if (len < 0 || (size_t)len >= sizeof (buf))
    return -1;

  digest_hash (buf, (size_t)len, use_sha256, response_hex);
  return 0;
}

/**
 * compute_response_no_qop - Compute response without qop (RFC 2617 compat)
 * @ha1_hex: H(A1) as hex
 * @nonce: Server nonce
 * @ha2_hex: H(A2) as hex
 * @use_sha256: Use SHA-256 or MD5
 * @response_hex: Output buffer
 *
 * Returns: 0 on success, -1 on error
 */
static int
compute_response_no_qop (const char *ha1_hex, const char *nonce,
                         const char *ha2_hex, int use_sha256,
                         char *response_hex)
{
  char buf[HTTPCLIENT_DIGEST_A_BUFFER_SIZE];
  int len;

  len = snprintf (buf, sizeof (buf), "%s:%s:%s", ha1_hex, nonce, ha2_hex);
  if (len < 0 || (size_t)len >= sizeof (buf))
    return -1;

  digest_hash (buf, (size_t)len, use_sha256, response_hex);
  return 0;
}

/**
 * compute_response_hash - Compute final Digest response hash
 * @ha1_hex: H(A1) as hex string
 * @nonce: Server nonce
 * @nc: Nonce count (may be NULL)
 * @cnonce: Client nonce (may be NULL)
 * @qop: QoP value (may be NULL)
 * @ha2_hex: H(A2) as hex string
 * @use_sha256: Use SHA-256 (1) or MD5 (0)
 * @response_hex: Output buffer
 *
 * Returns: 0 on success, -1 on error
 */
static int
compute_response_hash (const char *ha1_hex, const char *nonce, const char *nc,
                       const char *cnonce, const char *qop,
                       const char *ha2_hex, int use_sha256, char *response_hex)
{
  if (qop != NULL && strcmp (qop, HTTPCLIENT_DIGEST_TOKEN_AUTH) == 0)
    return compute_response_with_qop (ha1_hex, nonce, nc, cnonce, qop, ha2_hex,
                                      use_sha256, response_hex);
  else
    return compute_response_no_qop (ha1_hex, nonce, ha2_hex, use_sha256,
                                    response_hex);
}

/* ============================================================================
 * Basic Authentication (RFC 7617)
 * ============================================================================
 */

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

/* ============================================================================
 * Bearer Authentication (RFC 6750)
 * ============================================================================
 */

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

/* ============================================================================
 * Digest Response Header Formatting
 * ============================================================================
 */

/**
 * format_digest_header_with_qop - Format header with qop parameters
 */
static int
format_digest_header_with_qop (const char *username, const char *realm,
                               const char *nonce, const char *uri,
                               int use_sha256, const char *qop, const char *nc,
                               const char *cnonce, const char *response_hex,
                               char *output, size_t output_size)
{
  int written
      = snprintf (output, output_size,
                  "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", "
                  "uri=\"%s\", algorithm=%s, qop=%s, nc=%s, "
                  "cnonce=\"%s\", response=\"%s\"",
                  username, realm, nonce, uri, use_sha256 ? "SHA-256" : "MD5",
                  qop, nc, cnonce, response_hex);

  return (written < 0 || (size_t)written >= output_size) ? -1 : 0;
}

/**
 * format_digest_header_no_qop - Format header without qop parameters
 */
static int
format_digest_header_no_qop (const char *username, const char *realm,
                             const char *nonce, const char *uri,
                             int use_sha256, const char *response_hex,
                             char *output, size_t output_size)
{
  int written
      = snprintf (output, output_size,
                  "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", "
                  "uri=\"%s\", algorithm=%s, response=\"%s\"",
                  username, realm, nonce, uri, use_sha256 ? "SHA-256" : "MD5",
                  response_hex);

  return (written < 0 || (size_t)written >= output_size) ? -1 : 0;
}

/* ============================================================================
 * Digest Authentication Response Generation
 * ============================================================================
 */

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

  if (qop != NULL && strcmp (qop, HTTPCLIENT_DIGEST_TOKEN_AUTH) == 0)
    return format_digest_header_with_qop (username, realm, nonce, uri,
                                          use_sha256, qop, nc, cnonce,
                                          response_hex, output, output_size);
  else
    return format_digest_header_no_qop (username, realm, nonce, uri,
                                        use_sha256, response_hex, output,
                                        output_size);
}

/* ============================================================================
 * Digest Challenge Parsing
 * ============================================================================
 */

/**
 * skip_digest_prefix - Skip "Digest " prefix if present
 * @header: Header value
 * @strict: Require prefix
 *
 * Returns: Pointer after prefix, or NULL if strict and missing
 */
static const char *
skip_digest_prefix (const char *header, int strict)
{
  if (strncasecmp (header, HTTPCLIENT_DIGEST_PREFIX,
                   HTTPCLIENT_DIGEST_PREFIX_LEN)
      == 0)
    return header + HTTPCLIENT_DIGEST_PREFIX_LEN;

  return strict ? NULL : header;
}



/**
 * validate_challenge - Ensure required fields present
 * @ch: Challenge to validate
 *
 * Returns: 0 if valid, -1 if missing required fields
 */
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

/**
 * parse_digest_challenge - Parse Digest WWW-Authenticate header
 * @header: WWW-Authenticate header value
 * @ch: Output challenge structure
 *
 * Returns: 0 on success, -1 on error
 */
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
    safe_strcpy (ch->algorithm, sizeof (ch->algorithm), "MD5");

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

/* ============================================================================
 * Client Nonce Generation
 * ============================================================================
 */

/**
 * generate_cnonce - Generate client nonce for Digest auth
 * @cnonce: Output buffer
 * @size: Buffer size (must be >= HTTPCLIENT_DIGEST_CNONCE_HEX_SIZE)
 */
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

/* ============================================================================
 * QoP Selection
 * ============================================================================
 */

/**
 * find_auth_qop - Find "auth" token in qop list
 * @qop_list: Comma-separated qop values
 *
 * Returns: "auth" if found, NULL otherwise
 *
 * NOTE: qop=auth-int is NOT supported (requires request body hash).
 */
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

/* ============================================================================
 * Public Digest Auth Helper
 * ============================================================================
 */

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

/* ============================================================================
 * Stale Nonce Detection
 * ============================================================================
 */

/**
 * check_stale_value - Check if parsed value indicates stale=true
 * @value: Parsed parameter value
 *
 * Returns: 1 if stale=true, 0 otherwise
 */
static int
check_stale_value (const char *value)
{
  return strcasecmp (value, HTTPCLIENT_DIGEST_TOKEN_TRUE) == 0;
}

/**
 * skip_to_next_param - Skip past current parameter value
 * @p: Current position in header
 *
 * Returns: Position at next parameter or end
 */
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
