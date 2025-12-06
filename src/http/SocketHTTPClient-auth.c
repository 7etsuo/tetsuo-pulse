/**
 * SocketHTTPClient-auth.c - HTTP Authentication Implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
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

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

/**
 * safe_strcpy - Copy string with truncation (avoids GCC stringop-truncation)
 * @dst: Destination buffer
 * @dst_size: Size of destination buffer
 * @src: Source string
 *
 * Copies at most dst_size-1 characters and always null-terminates.
 * Uses memcpy to avoid GCC stringop-truncation and format-truncation warnings.
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

/* ============================================================================
 * Basic Authentication (RFC 7617)
 * ============================================================================
 *
 * Basic authentication is simple: base64(username:password)
 * Uses SocketCrypto_base64_encode() directly.
 */

int
httpclient_auth_basic_header (const char *username, const char *password,
                              char *output, size_t output_size)
{
  char credentials[HTTPCLIENT_AUTH_CREDENTIALS_SIZE];
  size_t cred_len;
  ssize_t encoded_len;
  size_t prefix_len;

  assert (username != NULL);
  assert (password != NULL);
  assert (output != NULL);
  assert (output_size > 0);

  /* Format: "username:password" */
  cred_len = (size_t)snprintf (credentials, sizeof (credentials), "%s:%s",
                               username, password);
  if (cred_len >= sizeof (credentials))
    return -1; /* Credentials too long */

  /* Calculate required size: "Basic " + base64 + null */
  prefix_len = 6; /* strlen("Basic ") */
  size_t base64_size = SocketCrypto_base64_encoded_size (cred_len);

  if (prefix_len + base64_size > output_size)
    return -1; /* Output buffer too small */

  /* Write prefix */
  memcpy (output, "Basic ", prefix_len);

  /* Encode credentials using SocketCrypto */
  encoded_len = SocketCrypto_base64_encode (credentials, cred_len,
                                            output + prefix_len,
                                            output_size - prefix_len);
  if (encoded_len < 0)
    {
      /* Clear sensitive data on error */
      SocketCrypto_secure_clear (credentials, sizeof (credentials));
      return -1;
    }

  /* Clear sensitive credential data */
  SocketCrypto_secure_clear (credentials, sizeof (credentials));

  return 0;
}

/* ============================================================================
 * Digest Authentication (RFC 7616)
 * ============================================================================
 *
 * Digest authentication uses MD5 or SHA-256 hashes:
 *
 * H(data) = MD5(data) or SHA-256(data) depending on algorithm
 * A1 = username:realm:password
 * A2 = method:uri (or method:uri:H(entity-body) for qop=auth-int)
 *
 * response = H(H(A1):nonce:H(A2)) for basic
 * response = H(H(A1):nonce:nc:cnonce:qop:H(A2)) for qop=auth
 *
 * Uses SocketCrypto_md5() and SocketCrypto_sha256() directly.
 */

/**
 * Compute hash and format as hex string
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
 * Compute Digest auth response
 */
int
httpclient_auth_digest_response (const char *username, const char *password,
                                 const char *realm, const char *nonce,
                                 const char *uri, const char *method,
                                 const char *qop, const char *nc,
                                 const char *cnonce, int use_sha256,
                                 char *output, size_t output_size)
{
  char a1[HTTPCLIENT_DIGEST_A_BUFFER_SIZE];
  char a2[HTTPCLIENT_DIGEST_A_BUFFER_SIZE];
  char ha1_hex[65]; /* 64 chars for SHA-256 hex + null */
  char ha2_hex[65];
  char response_input[HTTPCLIENT_DIGEST_A_BUFFER_SIZE];
  char response_hex[65];
  size_t len;

  assert (username != NULL);
  assert (password != NULL);
  assert (realm != NULL);
  assert (nonce != NULL);
  assert (uri != NULL);
  assert (method != NULL);
  assert (output != NULL);
  assert (output_size > 0);

  /* Compute H(A1) = H(username:realm:password) */
  len = (size_t)snprintf (a1, sizeof (a1), "%s:%s:%s", username, realm,
                          password);
  if (len >= sizeof (a1))
    return -1;

  digest_hash (a1, len, use_sha256, ha1_hex);

  /* Clear sensitive A1 data immediately */
  SocketCrypto_secure_clear (a1, sizeof (a1));

  /* Compute H(A2) = H(method:uri)
   *
   * NOTE: For qop=auth-int, A2 would be method:uri:H(entity-body)
   * but we only support qop=auth, so A2 is always method:uri.
   */
  len = (size_t)snprintf (a2, sizeof (a2), "%s:%s", method, uri);
  if (len >= sizeof (a2))
    return -1;

  digest_hash (a2, len, use_sha256, ha2_hex);

  /* Compute response */
  if (qop != NULL && strcmp (qop, "auth") == 0)
    {
      /* RFC 7616 with qop */
      /* response = H(H(A1):nonce:nc:cnonce:qop:H(A2)) */
      if (nc == NULL || cnonce == NULL)
        return -1;

      len = (size_t)snprintf (response_input, sizeof (response_input),
                              "%s:%s:%s:%s:%s:%s", ha1_hex, nonce, nc, cnonce,
                              qop, ha2_hex);
    }
  else
    {
      /* RFC 2617 compatibility (no qop) */
      /* response = H(H(A1):nonce:H(A2)) */
      len = (size_t)snprintf (response_input, sizeof (response_input),
                              "%s:%s:%s", ha1_hex, nonce, ha2_hex);
    }

  if (len >= sizeof (response_input))
    return -1;

  digest_hash (response_input, len, use_sha256, response_hex);

  /* Build Authorization header value */
  int written;
  if (qop != NULL && strcmp (qop, "auth") == 0)
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
 * Parse a quoted string from Digest challenge
 * Returns pointer past the closing quote, or NULL on error
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
 * Parse Digest authentication challenge from WWW-Authenticate header
 */
typedef struct
{
  char realm[128];
  char nonce[128];
  char opaque[128];
  char qop[64];
  char algorithm[32];
  int stale;
} DigestChallenge;

static int
parse_digest_challenge (const char *header, DigestChallenge *ch)
{
  const char *p;
  char name[32];
  char value[256];

  memset (ch, 0, sizeof (*ch));

  /* Skip "Digest " prefix */
  if (strncasecmp (header, "Digest ", 7) != 0)
    return -1;

  p = header + 7;

  while (*p)
    {
      /* Skip whitespace and commas */
      while (*p == ' ' || *p == '\t' || *p == ',')
        p++;

      if (!*p)
        break;

      /* Parse name */
      size_t i = 0;
      while (*p && *p != '=' && i < sizeof (name) - 1)
        {
          name[i++] = *p++;
        }
      name[i] = '\0';

      if (*p != '=')
        return -1;
      p++;

      /* Parse value (quoted or token) */
      if (*p == '"')
        {
          p = parse_quoted_string (p, value, sizeof (value));
          if (p == NULL)
            return -1;
        }
      else
        {
          i = 0;
          while (*p && *p != ',' && *p != ' ' && i < sizeof (value) - 1)
            {
              value[i++] = *p++;
            }
          value[i] = '\0';
        }

      /* Store parsed values - use safe_strcpy to avoid GCC truncation warnings */
      if (strcasecmp (name, "realm") == 0)
        {
          safe_strcpy (ch->realm, sizeof (ch->realm), value);
        }
      else if (strcasecmp (name, "nonce") == 0)
        {
          safe_strcpy (ch->nonce, sizeof (ch->nonce), value);
        }
      else if (strcasecmp (name, "opaque") == 0)
        {
          safe_strcpy (ch->opaque, sizeof (ch->opaque), value);
        }
      else if (strcasecmp (name, "qop") == 0)
        {
          safe_strcpy (ch->qop, sizeof (ch->qop), value);
        }
      else if (strcasecmp (name, "algorithm") == 0)
        {
          safe_strcpy (ch->algorithm, sizeof (ch->algorithm), value);
        }
      else if (strcasecmp (name, "stale") == 0)
        {
          ch->stale = (strcasecmp (value, "true") == 0);
        }
    }

  /* realm and nonce are required */
  if (ch->realm[0] == '\0' || ch->nonce[0] == '\0')
    return -1;

  /* Default algorithm is MD5 */
  if (ch->algorithm[0] == '\0')
    safe_strcpy (ch->algorithm, sizeof (ch->algorithm), "MD5");

  return 0;
}

/* ============================================================================
 * Generate Client Nonce
 * ============================================================================
 *
 * Uses SocketCrypto_random_bytes() for cryptographically secure random data.
 */

static void
generate_cnonce (char *cnonce, size_t size)
{
  unsigned char random_bytes[HTTPCLIENT_DIGEST_CNONCE_SIZE];
  size_t hex_len;

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

  /* Convert to hex */
  hex_len = sizeof (random_bytes) * 2;
  if (hex_len >= size)
    hex_len = size - 1;

  SocketCrypto_hex_encode (random_bytes, hex_len / 2, cnonce, 1);
  cnonce[hex_len] = '\0';

  /* Clear sensitive random data */
  SocketCrypto_secure_clear (random_bytes, sizeof (random_bytes));
}

/* ============================================================================
 * Public Digest Auth Helper (handles full challenge-response)
 * ============================================================================ */

/**
 * Handle Digest authentication challenge
 *
 * This function parses a WWW-Authenticate header and generates the
 * appropriate Authorization header value.
 *
 * @param www_authenticate: WWW-Authenticate header value
 * @param username: User's username
 * @param password: User's password
 * @param method: HTTP method (GET, POST, etc.)
 * @param uri: Request URI
 * @param nc_value: Nonce count (00000001 for first request)
 * @param output: Output buffer for Authorization header value
 * @param output_size: Size of output buffer
 *
 * Returns: 0 on success, -1 on error
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

  /* Parse challenge */
  if (parse_digest_challenge (www_authenticate, &ch) != 0)
    return -1;

  /* Determine algorithm */
  use_sha256
      = (strcasecmp (ch.algorithm, "SHA-256") == 0
         || strcasecmp (ch.algorithm, "SHA-256-sess") == 0);

  /* Generate cnonce */
  generate_cnonce (cnonce, sizeof (cnonce));

  /* Select qop if available (only "auth" is supported)
   *
   * NOTE: qop=auth-int is NOT supported because it requires:
   *   A2 = method:uri:H(entity-body)
   * We don't have access to the request body in this function.
   * Most servers support qop=auth which is sufficient for auth protection.
   *
   * If server only offers auth-int, we fall back to no-qop mode (RFC 2617).
   */
  if (ch.qop[0] != '\0')
    {
      /* Check for "auth" token (not just substring to avoid "auth-int" match) */
      const char *p = ch.qop;
      while (*p)
        {
          /* Skip whitespace and commas */
          while (*p == ' ' || *p == ',' || *p == '\t')
            p++;
          if (*p == '\0')
            break;

          /* Check if this token is exactly "auth" (with word boundary) */
          if (strncmp (p, "auth", 4) == 0
              && (p[4] == '\0' || p[4] == ',' || p[4] == ' ' || p[4] == '\t'))
            {
              qop = "auth";
              break;
            }

          /* Skip to next token */
          while (*p && *p != ',')
            p++;
        }
    }

  /* Generate response */
  return httpclient_auth_digest_response (username, password, ch.realm, ch.nonce,
                                          uri, method, qop, nc_value, cnonce,
                                          use_sha256, output, output_size);
}

/* ============================================================================
 * Stale Nonce Detection
 * ============================================================================ */

/**
 * Check if WWW-Authenticate header contains stale=true
 *
 * This indicates the server nonce has expired and the client should
 * retry with a new nonce, not that credentials are invalid.
 */
int
httpclient_auth_is_stale_nonce (const char *www_authenticate)
{
  const char *p;

  if (www_authenticate == NULL)
    return 0;

  /* Skip "Digest " prefix if present */
  if (strncasecmp (www_authenticate, "Digest ", 7) == 0)
    p = www_authenticate + 7;
  else
    p = www_authenticate;

  /* Search for stale=true (case-insensitive) */
  while (*p)
    {
      /* Skip whitespace and commas */
      while (*p == ' ' || *p == '\t' || *p == ',')
        p++;

      if (*p == '\0')
        break;

      /* Check for "stale" with word boundary (must be followed by '=', space,
       * or tab, not another alphanumeric char like "stalex") */
      if (strncasecmp (p, "stale", 5) == 0
          && (p[5] == '=' || p[5] == ' ' || p[5] == '\t'))
        {
          p += 5;
          /* Skip optional whitespace around '=' */
          while (*p == ' ' || *p == '\t')
            p++;
          if (*p != '=')
            continue;
          p++;
          while (*p == ' ' || *p == '\t')
            p++;

          /* Check for true (unquoted or quoted) */
          if (strncasecmp (p, "true", 4) == 0)
            {
              char next = p[4];
              if (next == '\0' || next == ',' || next == ' ' || next == '\t')
                return 1;
            }
          else if (*p == '"' && strncasecmp (p + 1, "true", 4) == 0
                   && p[5] == '"')
            {
              return 1;
            }
        }

      /* Skip to next parameter */
      while (*p && *p != ',')
        {
          if (*p == '"')
            {
              p++;
              /* Skip quoted value */
              while (*p && *p != '"')
                {
                  if (*p == '\\' && *(p + 1))
                    p++;
                  p++;
                }
              if (*p == '"')
                p++;
            }
          else
            {
              p++;
            }
        }
    }

  return 0;
}

