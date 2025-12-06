/**
 * SocketHTTPClient-auth.c - HTTP Authentication Implementation
 *
 * Part of the Socket Library
 *
 * Implements HTTP authentication schemes:
 * - Basic Authentication (RFC 7617) - Uses SocketCrypto_base64_encode()
 * - Digest Authentication (RFC 7616) - Uses SocketCrypto_md5(), SocketCrypto_sha256()
 * - Bearer Token (RFC 6750) - Simple token header
 *
 * Leverages SocketCrypto for all cryptographic operations to avoid duplication.
 */

#include "http/SocketHTTPClient.h"
#include "http/SocketHTTPClient-private.h"
#include "core/SocketCrypto.h"
#include "core/SocketUtil.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

/* Constants moved to SocketHTTPClient-private.h */

/* ============================================================================
 * Digest Challenge Structure
 * ============================================================================ */

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

/* Forward declarations for parsing helpers to allow re-use */
static const char *
parse_quoted_string (const char *p, char *out, size_t out_size);

static const char *
parse_token_value (const char *p, char *out, size_t out_size);

static const char *
skip_quoted_value (const char *p);

static const char *
parse_parameter_name (const char *p, char *name, size_t name_size);

static void
store_challenge_field (DigestChallenge *ch, const char *name, const char *value);

/* ============================================================================
 * Helper Functions - String Utilities
 * ============================================================================ */

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
  size_t src_len;
  size_t copy_len;

  if (dst_size == 0)
    return;

  src_len = strlen (src);
  copy_len = (src_len < dst_size - 1) ? src_len : (dst_size - 1);
  memcpy (dst, src, copy_len);
  dst[copy_len] = '\0';
}

/**
 * skip_delimiters - Skip whitespace and commas
 * @p: Pointer to current position
 *
 * Returns: Pointer past any whitespace, tabs, or commas
 */
static const char *
skip_delimiters (const char *p)
{
  while (*p == ' ' || *p == '\t' || *p == ',')
    p++;
  return p;
}

/**
 * skip_whitespace - Skip whitespace only (not commas)
 * @p: Pointer to current position
 *
 * Returns: Pointer past any whitespace or tabs
 */
static const char *
skip_whitespace (const char *p)
{
  while (*p == ' ' || *p == '\t')
    p++;
  return p;
}

/**
 * is_token_boundary - Check if character is a token boundary
 * @c: Character to check
 *
 * Returns: 1 if boundary, 0 otherwise
 */
static int
is_token_boundary (char c)
{
  return c == '\0' || c == ',' || c == ' ' || c == '\t';
}

/* ============================================================================
 * Helper Functions - Digest Parsing
 * ============================================================================ */

/**
 * parse_param_value - Parse parameter value after '='
 * @p: Pointer after '=' (may have whitespace)
 * @out: Output buffer for value
 * @out_size: Size of output buffer
 *
 * Handles both quoted strings (with escapes) and unquoted tokens.
 * Advances @p past the value.
 *
 * Returns: Pointer past value on success, NULL on parse error (unterminated quote)
 * Thread-safe: Yes
 */
static const char *
parse_param_value (const char *p, char *out, size_t out_size)
{
  p = skip_whitespace (p);

  if (*p == '"')
    return parse_quoted_string (p, out, out_size);
  else
    return parse_token_value (p, out, out_size);
}

/**
 * skip_to_next_param - Skip to next parameter after processing current
 * @p: Pointer after current parameter value
 *
 * Skips until ',' or end, handling quoted strings.
 * Does not skip delimiters after ','.
 *
 * Thread-safe: Yes
 */
static void
skip_to_next_param (const char **p)
{
  while (**p && **p != ',')
    {
      if (**p == '"')
        *p = skip_quoted_value (*p);
      else
        (*p)++;
    }
}

/**
 * is_stale_param - Check if current parameter is stale=true
 * @p: Pointer at start of parameter name
 *
 * Parses name and value using shared helpers. Handles quoted/unquoted values.
 *
 * Returns: 1 if parameter is "stale=true" (case-insensitive), 0 otherwise
 * Thread-safe: Yes
 */
static int
is_stale_param (const char *p)
{
  char name[HTTPCLIENT_DIGEST_PARAM_NAME_MAX_LEN];
  char value[HTTPCLIENT_DIGEST_VALUE_MAX_LEN];

  const char *eq_pos = parse_parameter_name (p, name, sizeof (name));
  if (eq_pos == NULL || strcasecmp (name, HTTPCLIENT_DIGEST_TOKEN_STALE) != 0)
    return 0;

  const char *val_start = eq_pos + 1;
  const char *after_val = parse_param_value (val_start, value, sizeof (value));
  if (after_val == NULL)
    return 0;

  return (strcasecmp (value, HTTPCLIENT_DIGEST_TOKEN_TRUE) == 0);
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
  size_t i = 0;

  if (*p != '"')
    return NULL;
  p++;

  while (*p && *p != '"' && i < out_size - 1)
    {
      if (*p == '\\' && *(p + 1))
        {
          p++;
          out[i++] = *p++;
        }
      else
        {
          out[i++] = *p++;
        }
    }

  out[i] = '\0';

  if (*p == '"')
    return p + 1;

  return NULL;
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

  while (*p && *p != ',' && *p != ' ' && i < out_size - 1)
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
  while (*p && *p != '"')
    {
      if (*p == '\\' && *(p + 1))
        p++;
      p++;
    }

  if (*p == '"')
    p++;

  return p;
}

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

  while (*p && *p != '=' && i < name_size - 1)
    name[i++] = *p++;

  name[i] = '\0';

  if (*p != '=')
    return NULL;

  return p;
}

/**
 * store_challenge_field - Store parsed field in challenge structure
 * @ch: Challenge structure
 * @name: Field name
 * @value: Field value
 */
static void
store_challenge_field (DigestChallenge *ch, const char *name, const char *value)
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
    ch->stale = (strcasecmp (value, HTTPCLIENT_DIGEST_TOKEN_TRUE) == 0);
}

/* ============================================================================
 * Helper Functions - Digest Hashing
 * ============================================================================ */

/**
 * digest_hash - Compute hash and format as hex string
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
 * Returns: 0 on success, -1 on error (buffer overflow)
 */
static int
compute_ha1 (const char *username, const char *realm, const char *password,
             int use_sha256, char *ha1_hex)
{
  char a1[HTTPCLIENT_DIGEST_A_BUFFER_SIZE];
  size_t len;

  len = (size_t)snprintf (a1, sizeof (a1), "%s:%s:%s", username, realm,
                          password);
  if (len >= sizeof (a1))
    return -1;

  digest_hash (a1, len, use_sha256, ha1_hex);

  /* Clear sensitive A1 data immediately */
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
 * Returns: 0 on success, -1 on error (buffer overflow)
 */
static int
compute_ha2 (const char *method, const char *uri, int use_sha256,
             char *ha2_hex)
{
  char a2[HTTPCLIENT_DIGEST_A_BUFFER_SIZE];
  size_t len;

  len = (size_t)snprintf (a2, sizeof (a2), "%s:%s", method, uri);
  if (len >= sizeof (a2))
    return -1;

  digest_hash (a2, len, use_sha256, ha2_hex);

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
 * @response_hex: Output buffer (must be HTTPCLIENT_DIGEST_HEX_SIZE)
 *
 * Returns: 0 on success, -1 on error (buffer overflow)
 */
static int
compute_response_hash (const char *ha1_hex, const char *nonce, const char *nc,
                       const char *cnonce, const char *qop,
                       const char *ha2_hex, int use_sha256, char *response_hex)
{
  char response_input[HTTPCLIENT_DIGEST_A_BUFFER_SIZE];
  size_t len;

  if (qop != NULL && strcmp (qop, HTTPCLIENT_DIGEST_TOKEN_AUTH) == 0)
    {
      /* RFC 7616 with qop: response = H(H(A1):nonce:nc:cnonce:qop:H(A2)) */
      if (nc == NULL || cnonce == NULL)
        return -1;

      len = (size_t)snprintf (response_input, sizeof (response_input),
                              "%s:%s:%s:%s:%s:%s", ha1_hex, nonce, nc, cnonce,
                              qop, ha2_hex);
    }
  else
    {
      /* RFC 2617 compatibility: response = H(H(A1):nonce:H(A2)) */
      len = (size_t)snprintf (response_input, sizeof (response_input),
                              "%s:%s:%s", ha1_hex, nonce, ha2_hex);
    }

  if (len >= sizeof (response_input))
    return -1;

  digest_hash (response_input, len, use_sha256, response_hex);

  return 0;
}

/* ============================================================================
 * Basic Authentication (RFC 7617)
 * ============================================================================ */

int
httpclient_auth_basic_header (const char *username, const char *password,
                              char *output, size_t output_size)
{
  char credentials[HTTPCLIENT_AUTH_CREDENTIALS_SIZE];
  size_t cred_len;
  ssize_t encoded_len;
  size_t base64_size;

  assert (username != NULL);
  assert (password != NULL);
  assert (output != NULL);
  assert (output_size > 0);

  /* Format: "username:password" */
  cred_len = (size_t)snprintf (credentials, sizeof (credentials), "%s:%s",
                               username, password);
  if (cred_len >= sizeof (credentials))
    {
      SOCKET_LOG_WARN_MSG ("Basic auth credentials too long: username='%.*s' password_len=%zu",
                           (int)strnlen (username, 32), username, strlen (password));
      return -1;
    }

  /* Calculate required size: "Basic " + base64 + null */
  base64_size = SocketCrypto_base64_encoded_size (cred_len);

  if (HTTPCLIENT_DIGEST_BASIC_PREFIX_LEN + base64_size > output_size)
    return -1;

  /* Write prefix */
  memcpy (output, "Basic ", HTTPCLIENT_DIGEST_BASIC_PREFIX_LEN);

  /* Encode credentials using SocketCrypto */
  encoded_len = SocketCrypto_base64_encode (credentials, cred_len,
                                            output + HTTPCLIENT_DIGEST_BASIC_PREFIX_LEN,
                                            output_size - HTTPCLIENT_DIGEST_BASIC_PREFIX_LEN);
  if (encoded_len < 0)
    {
      SocketCrypto_secure_clear (credentials, sizeof (credentials));
      return -1;
    }

  /* Clear sensitive credential data */
  SocketCrypto_secure_clear (credentials, sizeof (credentials));

  return 0;
}

/* ============================================================================
 * Bearer Authentication (RFC 6750)
 * ============================================================================ */

/**
 * httpclient_auth_bearer_header - Generate Bearer token Authorization header
 * @token: Bearer token string
 * @output: Output buffer for "Bearer <token>"
 * @output_size: Size of output buffer
 *
 * Returns: 0 on success, -1 if buffer too small
 * Thread-safe: Yes
 *
 * Format per RFC 6750: Authorization: Bearer <token>
 * Token is copied as-is, no validation or encoding.
 * Token length limited by output_size - 7 (for "Bearer ").
 * No sensitive data clearing (token already transmitted in header).
 */
int
httpclient_auth_bearer_header (const char *token, char *output, size_t output_size)
{
  size_t token_len;
  size_t needed;

  assert (token != NULL);
  assert (output != NULL);
  assert (output_size > 0);

  token_len = strlen (token);
  needed = 7 + token_len + 1;  /* "Bearer " + token + \0 */

  if (needed > output_size)
    {
      SOCKET_LOG_WARN_MSG ("Bearer token too long for output buffer: token_len=%zu needed=%zu available=%zu",
                           token_len, needed, output_size);
      return -1;
    }

  memcpy (output, "Bearer ", 7);
  memcpy (output + 7, token, token_len);
  output[7 + token_len] = '\0';

  return 0;
}

/* ============================================================================
 * Digest Authentication Response Generation
 * ============================================================================ */

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
  int written;

  assert (username != NULL);
  assert (password != NULL);
  assert (realm != NULL);
  assert (nonce != NULL);
  assert (uri != NULL);
  assert (method != NULL);
  assert (output != NULL);
  assert (output_size > 0);

  /* Compute H(A1) */
  if (compute_ha1 (username, realm, password, use_sha256, ha1_hex) != 0)
    return -1;

  /* Compute H(A2) */
  if (compute_ha2 (method, uri, use_sha256, ha2_hex) != 0)
    return -1;

  /* Compute response hash */
  if (compute_response_hash (ha1_hex, nonce, nc, cnonce, qop, ha2_hex,
                             use_sha256, response_hex)
      != 0)
    return -1;

  /* Build Authorization header value */
  if (qop != NULL && strcmp (qop, HTTPCLIENT_DIGEST_TOKEN_AUTH) == 0)
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

  if (written < 0 || (size_t)written >= output_size)
    return -1;

  return 0;
}

/* ============================================================================
 * Digest Challenge Parsing
 * ============================================================================ */

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
  const char *p;
  char name[HTTPCLIENT_DIGEST_PARAM_NAME_MAX_LEN];
  char value[HTTPCLIENT_DIGEST_VALUE_MAX_LEN];

  memset (ch, 0, sizeof (*ch));

  /* Skip "Digest " prefix */
  if (strncasecmp (header, HTTPCLIENT_DIGEST_PREFIX, HTTPCLIENT_DIGEST_PREFIX_LEN) != 0)
    return -1;

  p = header + HTTPCLIENT_DIGEST_PREFIX_LEN;

  while (*p)
    {
      p = skip_delimiters (p);

      if (!*p)
        break;

      /* Parse name */
      p = parse_parameter_name (p, name, sizeof (name));
      if (p == NULL)
        return -1;
      p++; /* Skip '=' */

      p = parse_param_value (p, value, sizeof (value));
      if (p == NULL)
        return -1;

      /* Store parsed field */
      store_challenge_field (ch, name, value);
    }

  /* realm and nonce are required */
  if (ch->realm[0] == '\0' || ch->nonce[0] == '\0')
    {
      SOCKET_LOG_WARN_MSG ("Digest challenge missing required field: realm='%s' nonce='%s'",
                           ch->realm, ch->nonce);
      return -1;
    }

  /* Default algorithm is MD5 */
  if (ch->algorithm[0] == '\0')
    safe_strcpy (ch->algorithm, sizeof (ch->algorithm), "MD5");

  return 0;
}

/* ============================================================================
 * Client Nonce Generation
 * ============================================================================ */

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

  /* Generate random bytes using SocketCrypto */
  if (SocketCrypto_random_bytes (random_bytes, sizeof (random_bytes)) != 0)
    {
      /* Fallback to time-based if random fails */
      uint64_t t = (uint64_t)time (NULL);
      memcpy (random_bytes, &t, sizeof (t));
      memset (random_bytes + sizeof (t), 0, sizeof (random_bytes) - sizeof (t));
    }

  /* Convert to hex (SocketCrypto_hex_encode null-terminates) */
  SocketCrypto_hex_encode (random_bytes, sizeof (random_bytes), cnonce, 1);

  /* Clear sensitive random data */
  SocketCrypto_secure_clear (random_bytes, sizeof (random_bytes));
}

/* ============================================================================
 * QoP Selection
 * ============================================================================ */

/**
 * find_auth_qop - Find "auth" token in qop list
 * @qop_list: Comma-separated qop values
 *
 * Returns: "auth" if found, NULL otherwise
 *
 * NOTE: qop=auth-int is NOT supported because it requires:
 *   A2 = method:uri:H(entity-body)
 * We don't have access to the request body in this function.
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

      /* Check if this token is exactly "auth" */
      if (strncmp (p, HTTPCLIENT_DIGEST_TOKEN_AUTH, HTTPCLIENT_DIGEST_TOKEN_AUTH_LEN) == 0
          && is_token_boundary (p[HTTPCLIENT_DIGEST_TOKEN_AUTH_LEN]))
        return HTTPCLIENT_DIGEST_TOKEN_AUTH;

      /* Skip to next token */
      while (*p && *p != ',')
        p++;
    }

  return NULL;
}

/* ============================================================================
 * Public Digest Auth Helper
 * ============================================================================ */

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

  /* Parse challenge */
  if (parse_digest_challenge (www_authenticate, &ch) != 0)
    return -1;

  /* Determine algorithm */
  use_sha256 = (strcasecmp (ch.algorithm, "SHA-256") == 0
                || strcasecmp (ch.algorithm, "SHA-256-sess") == 0);

  /* Generate cnonce */
  generate_cnonce (cnonce, sizeof (cnonce));

  /* Select qop if available */
  if (ch.qop[0] != '\0')
    qop = find_auth_qop (ch.qop);

  /* Generate response */
  return httpclient_auth_digest_response (username, password, ch.realm,
                                          ch.nonce, uri, method, qop, nc_value,
                                          cnonce, use_sha256, output,
                                          output_size);
}

/* ============================================================================
 * Stale Nonce Detection
 * ============================================================================ */

/**
 * find_stale_parameter - Search for stale=true in header
 * @p: Pointer past "Digest " prefix
 *
 * Returns: 1 if stale=true found, 0 otherwise
 */
static int
find_stale_parameter (const char *p)
{
  while (*p)
    {
      p = skip_delimiters (p);
      if (*p == '\0')
        break;

      /* Check for "stale" parameter */
      if (strncasecmp (p, HTTPCLIENT_DIGEST_TOKEN_STALE, HTTPCLIENT_DIGEST_TOKEN_STALE_LEN) == 0
          && (p[HTTPCLIENT_DIGEST_TOKEN_STALE_LEN] == '=' || p[HTTPCLIENT_DIGEST_TOKEN_STALE_LEN] == ' '
              || p[HTTPCLIENT_DIGEST_TOKEN_STALE_LEN] == '\t'))
        {
          p += HTTPCLIENT_DIGEST_TOKEN_STALE_LEN;
          p = skip_whitespace (p);

          if (*p != '=')
            goto next_param;

          p++;
          p = skip_whitespace (p);

          /* Check for true (unquoted or quoted) */
          if (strncasecmp (p, HTTPCLIENT_DIGEST_TOKEN_TRUE, HTTPCLIENT_DIGEST_TOKEN_TRUE_LEN) == 0
              && is_token_boundary (p[HTTPCLIENT_DIGEST_TOKEN_TRUE_LEN]))
            return 1;

          if (*p == '"' && strncasecmp (p + 1, HTTPCLIENT_DIGEST_TOKEN_TRUE, HTTPCLIENT_DIGEST_TOKEN_TRUE_LEN) == 0
              && p[1 + HTTPCLIENT_DIGEST_TOKEN_TRUE_LEN] == '"')
            return 1;
        }

    next_param:
      /* Skip to next parameter */
      while (*p && *p != ',')
        {
          if (*p == '"')
            p = skip_quoted_value (p);
          else
            p++;
        }
    }

  return 0;
}

int
httpclient_auth_is_stale_nonce (const char *www_authenticate)
{
  const char *p;

  if (www_authenticate == NULL)
    return 0;

  /* Skip "Digest " prefix if present */
  if (strncasecmp (www_authenticate, HTTPCLIENT_DIGEST_PREFIX, HTTPCLIENT_DIGEST_PREFIX_LEN) == 0)
    p = www_authenticate + HTTPCLIENT_DIGEST_PREFIX_LEN;
  else
    p = www_authenticate;

  return find_stale_parameter (p);
}
