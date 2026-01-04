/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file StreamingCurl_auth.c
 * @brief Authentication support for streaming curl module.
 *
 * Implements HTTP authentication methods:
 * - Basic authentication (RFC 7617)
 * - Bearer token authentication (RFC 6750)
 * - Digest authentication (RFC 7616) - basic support
 */

#include "curl/StreamingCurl-private.h"
#include "curl/StreamingCurl.h"

#include "core/SocketCrypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Authentication header prefixes */
#define BASIC_PREFIX "Basic "
#define BASIC_PREFIX_LEN 6
#define BEARER_PREFIX "Bearer "
#define BEARER_PREFIX_LEN 7

/* Base64 encoding constants */
#define BASE64_BYTES_PER_GROUP 3
#define BASE64_CHARS_PER_GROUP 4
#define BASE64_OCTET_SHIFT_HIGH 16
#define BASE64_OCTET_SHIFT_MID 8
#define BASE64_SEXTET_SHIFT_1 18
#define BASE64_SEXTET_SHIFT_2 12
#define BASE64_SEXTET_SHIFT_3 6
#define BASE64_SEXTET_MASK 0x3F
#define BASE64_PADDING_CHAR '='
#define BASE64_MODULO_1_REMAINING 1
#define BASE64_MODULO_2_REMAINING 2

/* MD5 hash constants */
#define MD5_HEX_STRING_SIZE 33

/* Digest authentication constants */
#define DIGEST_PREFIX "Digest "
#define DIGEST_PREFIX_LEN 7
#define DIGEST_REALM_KEY_LEN 5
#define DIGEST_NONCE_KEY_LEN 5
#define DIGEST_OPAQUE_KEY_LEN 6
#define DIGEST_QOP_KEY_LEN 3
#define DIGEST_CNONCE_SIZE 17
#define DIGEST_CNONCE_FORMAT "%08x%08x"
#define DIGEST_NC_INITIAL "00000001"

/* String length constants */
#define COLON_SEPARATOR_LEN 1
#define NULL_TERMINATOR_LEN 1

/* Base64 encoding table */
static const char base64_table[]
    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * @brief Calculate base64 encoded length.
 *
 * @param input_len Input data length
 * @return Required output buffer size (including null terminator)
 */
static size_t
base64_encoded_len (size_t input_len)
{
  return ((input_len + BASE64_MODULO_2_REMAINING) / BASE64_BYTES_PER_GROUP) * BASE64_CHARS_PER_GROUP + NULL_TERMINATOR_LEN;
}

/**
 * @brief Encode data to base64.
 *
 * @param input Input data
 * @param input_len Input length
 * @param output Output buffer
 * @param output_size Output buffer size
 * @return Encoded length (excluding null), or -1 on error
 */
static ssize_t
base64_encode (const unsigned char *input, size_t input_len, char *output,
               size_t output_size)
{
  if (!input || !output)
    return -1;

  size_t needed = base64_encoded_len (input_len);
  if (output_size < needed)
    return -1;

  size_t i, j;
  /* Process complete 3-byte groups */
  for (i = 0, j = 0; i + BASE64_MODULO_2_REMAINING < input_len; i += BASE64_BYTES_PER_GROUP)
    {
      uint32_t octet_a = input[i];
      uint32_t octet_b = input[i + 1];
      uint32_t octet_c = input[i + 2];

      uint32_t triple = (octet_a << BASE64_OCTET_SHIFT_HIGH) | (octet_b << BASE64_OCTET_SHIFT_MID) | octet_c;

      output[j++] = base64_table[(triple >> BASE64_SEXTET_SHIFT_1) & BASE64_SEXTET_MASK];
      output[j++] = base64_table[(triple >> BASE64_SEXTET_SHIFT_2) & BASE64_SEXTET_MASK];
      output[j++] = base64_table[(triple >> BASE64_SEXTET_SHIFT_3) & BASE64_SEXTET_MASK];
      output[j++] = base64_table[triple & BASE64_SEXTET_MASK];
    }

  /* Handle remaining 1 or 2 bytes */
  if (i < input_len)
    {
      uint32_t octet_a = input[i];
      uint32_t octet_b = (i + BASE64_MODULO_1_REMAINING < input_len) ? input[i + 1] : 0;
      uint32_t octet_c = 0;

      uint32_t triple = (octet_a << BASE64_OCTET_SHIFT_HIGH) | (octet_b << BASE64_OCTET_SHIFT_MID) | octet_c;

      output[j++] = base64_table[(triple >> BASE64_SEXTET_SHIFT_1) & BASE64_SEXTET_MASK];
      output[j++] = base64_table[(triple >> BASE64_SEXTET_SHIFT_2) & BASE64_SEXTET_MASK];
      output[j++] = base64_table[(triple >> BASE64_SEXTET_SHIFT_3) & BASE64_SEXTET_MASK];
      output[j++] = base64_table[triple & BASE64_SEXTET_MASK];
    }

  /* Add padding */
  size_t mod = input_len % BASE64_BYTES_PER_GROUP;
  if (mod == BASE64_MODULO_1_REMAINING)
    {
      output[j - 2] = BASE64_PADDING_CHAR;
      output[j - 1] = BASE64_PADDING_CHAR;
    }
  else if (mod == BASE64_MODULO_2_REMAINING)
    {
      output[j - 1] = BASE64_PADDING_CHAR;
    }

  output[j] = '\0';
  return (ssize_t)j;
}

/**
 * @brief Build Basic authentication header value.
 *
 * Format: "Basic base64(username:password)"
 *
 * @param username Username
 * @param password Password
 * @param output Output buffer
 * @param output_size Output buffer size
 * @return Header value length, or -1 on error
 */
ssize_t
curl_auth_basic (const char *username, const char *password, char *output,
                 size_t output_size)
{
  if (!username || !password || !output || output_size == 0)
    return -1;

  /* Build "username:password" string */
  size_t user_len = strlen (username);
  size_t pass_len = strlen (password);
  size_t cred_len = user_len + COLON_SEPARATOR_LEN + pass_len;

  /* Allocate on stack for small credentials */
  char credentials[CURL_MAX_CREDENTIAL_LEN];
  if (cred_len >= sizeof (credentials))
    return -1;

  snprintf (credentials, sizeof (credentials), "%s:%s", username, password);

  /* Calculate output size needed */
  size_t b64_len = base64_encoded_len (cred_len);
  size_t total_len = BASIC_PREFIX_LEN + b64_len; /* "Basic " + base64 */

  if (output_size < total_len)
    return -1;

  /* Build header value */
  memcpy (output, BASIC_PREFIX, BASIC_PREFIX_LEN);

  ssize_t encoded = base64_encode ((const unsigned char *)credentials,
                                   cred_len, output + BASIC_PREFIX_LEN, output_size - BASIC_PREFIX_LEN);
  if (encoded < 0)
    return -1;

  return BASIC_PREFIX_LEN + encoded;
}

/**
 * @brief Build Bearer token authentication header value.
 *
 * Format: "Bearer <token>"
 *
 * @param token Bearer token
 * @param output Output buffer
 * @param output_size Output buffer size
 * @return Header value length, or -1 on error
 */
ssize_t
curl_auth_bearer (const char *token, char *output, size_t output_size)
{
  if (!token || !output || output_size == 0)
    return -1;

  size_t token_len = strlen (token);
  size_t total_len = BEARER_PREFIX_LEN + token_len; /* "Bearer " + token */

  if (output_size < total_len + NULL_TERMINATOR_LEN)
    return -1;

  int len = snprintf (output, output_size, BEARER_PREFIX "%s", token);
  if (len < 0 || (size_t)len >= output_size)
    return -1;

  return (ssize_t)len;
}

/**
 * @brief Compute MD5 hash and return as hex string.
 *
 * Uses SocketCrypto_md5 for proper RFC 1321 implementation.
 *
 * @param input Input data to hash
 * @param input_len Length of input data
 * @param output Output buffer (must be at least 33 bytes for hex + null)
 * @return 0 on success
 */
static int
md5_hex (const char *input, size_t input_len, char *output)
{
  unsigned char digest[SOCKET_CRYPTO_MD5_SIZE];

  SocketCrypto_md5 (input, input_len, digest);
  SocketCrypto_hex_encode (digest, SOCKET_CRYPTO_MD5_SIZE, output, 1);

  return 0;
}

/**
 * @brief Parse WWW-Authenticate header for Digest parameters.
 *
 * @param header WWW-Authenticate header value
 * @param realm Output realm
 * @param nonce Output nonce
 * @param opaque Output opaque (may be NULL)
 * @param qop Output qop (may be NULL)
 * @return 0 on success, -1 on error
 */
int
curl_auth_parse_digest_challenge (const char *header, char *realm,
                                  size_t realm_size, char *nonce,
                                  size_t nonce_size, char *opaque,
                                  size_t opaque_size, char *qop,
                                  size_t qop_size)
{
  if (!header || !realm || !nonce)
    return -1;

  /* Skip "Digest " prefix */
  if (strncasecmp (header, DIGEST_PREFIX, DIGEST_PREFIX_LEN) != 0)
    return -1;

  const char *ptr = header + DIGEST_PREFIX_LEN;

  realm[0] = '\0';
  nonce[0] = '\0';
  if (opaque)
    opaque[0] = '\0';
  if (qop)
    qop[0] = '\0';

  /* Simple parser for key="value" pairs */
  while (*ptr)
    {
      /* Skip whitespace and commas */
      while (*ptr == ' ' || *ptr == ',' || *ptr == '\t')
        ptr++;

      if (*ptr == '\0')
        break;

      /* Find key */
      const char *key_start = ptr;
      while (*ptr && *ptr != '=' && *ptr != ' ')
        ptr++;

      size_t key_len = (size_t)(ptr - key_start);

      if (*ptr != '=')
        continue;
      ptr++; /* Skip '=' */

      /* Find value */
      const char *value_start;
      const char *value_end;

      if (*ptr == '"')
        {
          ptr++;
          value_start = ptr;
          while (*ptr && *ptr != '"')
            ptr++;
          value_end = ptr;
          if (*ptr == '"')
            ptr++;
        }
      else
        {
          value_start = ptr;
          while (*ptr && *ptr != ',' && *ptr != ' ')
            ptr++;
          value_end = ptr;
        }

      size_t value_len = (size_t)(value_end - value_start);

      /* Match key */
      if (key_len == DIGEST_REALM_KEY_LEN && strncasecmp (key_start, "realm", DIGEST_REALM_KEY_LEN) == 0)
        {
          if (value_len < realm_size)
            {
              memcpy (realm, value_start, value_len);
              realm[value_len] = '\0';
            }
        }
      else if (key_len == DIGEST_NONCE_KEY_LEN && strncasecmp (key_start, "nonce", DIGEST_NONCE_KEY_LEN) == 0)
        {
          if (value_len < nonce_size)
            {
              memcpy (nonce, value_start, value_len);
              nonce[value_len] = '\0';
            }
        }
      else if (key_len == DIGEST_OPAQUE_KEY_LEN && strncasecmp (key_start, "opaque", DIGEST_OPAQUE_KEY_LEN) == 0
               && opaque)
        {
          if (value_len < opaque_size)
            {
              memcpy (opaque, value_start, value_len);
              opaque[value_len] = '\0';
            }
        }
      else if (key_len == DIGEST_QOP_KEY_LEN && strncasecmp (key_start, "qop", DIGEST_QOP_KEY_LEN) == 0 && qop)
        {
          if (value_len < qop_size)
            {
              memcpy (qop, value_start, value_len);
              qop[value_len] = '\0';
            }
        }
    }

  /* Validate required fields */
  if (realm[0] == '\0' || nonce[0] == '\0')
    return -1;

  return 0;
}

/**
 * @brief Build Digest authentication header value.
 *
 * @param params Digest authentication parameters
 * @return Header value length, or -1 on error
 */
ssize_t
curl_auth_digest (const CurlDigestParams *params)
{
  if (!params || !params->username || !params->password || !params->realm
      || !params->nonce || !params->uri || !params->method || !params->output)
    return -1;

  char ha1[MD5_HEX_STRING_SIZE], ha2[MD5_HEX_STRING_SIZE], response[MD5_HEX_STRING_SIZE];
  char buf[CURL_MAX_AUTH_BUFFER_LEN];
  int len;
  ssize_t result = -1;

  /* HA1 = MD5(username:realm:password) */
  len = snprintf (buf, sizeof (buf), "%s:%s:%s", params->username, params->realm, params->password);
  if (len < 0 || (size_t)len >= sizeof (buf))
    goto cleanup;
  md5_hex (buf, (size_t)len, ha1);

  /* HA2 = MD5(method:uri) */
  len = snprintf (buf, sizeof (buf), "%s:%s", params->method, params->uri);
  if (len < 0 || (size_t)len >= sizeof (buf))
    goto cleanup;
  md5_hex (buf, (size_t)len, ha2);

  /* Response calculation depends on qop */
  if (params->qop && (strcmp (params->qop, "auth") == 0 || strcmp (params->qop, "auth-int") == 0))
    {
      /* response = MD5(HA1:nonce:nc:cnonce:qop:HA2) */
      if (!params->nc || !params->cnonce)
        goto cleanup;

      len = snprintf (buf, sizeof (buf), "%s:%s:%s:%s:%s:%s", ha1, params->nonce, params->nc,
                      params->cnonce, params->qop, ha2);
      if (len < 0 || (size_t)len >= sizeof (buf))
        goto cleanup;
      md5_hex (buf, (size_t)len, response);

      /* Build header with qop */
      len = snprintf (
          params->output, params->output_size,
          "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", "
          "qop=%s, nc=%s, cnonce=\"%s\", response=\"%s\"",
          params->username, params->realm, params->nonce, params->uri, params->qop, params->nc, params->cnonce, response);
    }
  else
    {
      /* response = MD5(HA1:nonce:HA2) */
      len = snprintf (buf, sizeof (buf), "%s:%s:%s", ha1, params->nonce, ha2);
      if (len < 0 || (size_t)len >= sizeof (buf))
        goto cleanup;
      md5_hex (buf, (size_t)len, response);

      /* Build header without qop */
      len = snprintf (params->output, params->output_size,
                      "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", "
                      "uri=\"%s\", response=\"%s\"",
                      params->username, params->realm, params->nonce, params->uri, response);
    }

  if (len < 0 || (size_t)len >= params->output_size)
    goto cleanup;

  /* Add opaque if present */
  if (params->opaque && params->opaque[0] != '\0')
    {
      size_t current_len = (size_t)len;
      int added = snprintf (params->output + current_len, params->output_size - current_len,
                            ", opaque=\"%s\"", params->opaque);
      if (added > 0 && current_len + (size_t)added < params->output_size)
        len += added;
    }

  result = (ssize_t)len;

cleanup:
  /* Clear sensitive data before returning */
  explicit_bzero (ha1, sizeof (ha1));
  explicit_bzero (ha2, sizeof (ha2));
  explicit_bzero (response, sizeof (response));
  explicit_bzero (buf, sizeof (buf));

  return result;
}

/**
 * @brief Set up authentication header for session.
 *
 * Pre-computes the authentication header based on session auth settings.
 *
 * @param session Session
 * @return 0 on success, -1 on error
 */
int
curl_auth_setup (CurlSession_T session)
{
  if (!session)
    return -1;

  /* Clear existing auth header */
  session->auth_header = NULL;

  const CurlAuth *auth = &session->auth;

  if (auth->type == CURL_AUTH_NONE)
    return 0;

  Arena_T arena = session->arena;
  char buf[CURL_MAX_AUTH_BUFFER_LEN];
  ssize_t len;

  switch (auth->type)
    {
    case CURL_AUTH_BASIC:
      if (!auth->username || !auth->password)
        return -1;

      len = curl_auth_basic (auth->username, auth->password, buf,
                             sizeof (buf));
      if (len < 0)
        return -1;

      session->auth_header = ALLOC (arena, (size_t)len + 1);
      memcpy (session->auth_header, buf, (size_t)len);
      session->auth_header[len] = '\0';
      break;

    case CURL_AUTH_BEARER:
      if (!auth->token)
        return -1;

      len = curl_auth_bearer (auth->token, buf, sizeof (buf));
      if (len < 0)
        return -1;

      session->auth_header = ALLOC (arena, (size_t)len + 1);
      memcpy (session->auth_header, buf, (size_t)len);
      session->auth_header[len] = '\0';
      break;

    case CURL_AUTH_DIGEST:
      /* Digest auth requires a challenge from server first */
      /* Set up will be done after receiving 401 response */
      break;

    default:
      return -1;
    }

  return 0;
}

/**
 * @brief Handle 401 Unauthorized response for Digest auth.
 *
 * Parses WWW-Authenticate header and generates Digest response.
 *
 * @param session Session
 * @param www_auth WWW-Authenticate header value
 * @param method HTTP method
 * @param uri Request URI
 * @return 0 on success (auth_header updated), -1 on error
 */
int
curl_auth_handle_challenge (CurlSession_T session, const char *www_auth,
                            const char *method, const char *uri)
{
  if (!session || !www_auth || !method || !uri)
    return -1;

  const CurlAuth *auth = &session->auth;
  if (auth->type != CURL_AUTH_DIGEST)
    return -1;

  if (!auth->username || !auth->password)
    return -1;

  /* Parse challenge */
  char realm[CURL_MAX_REALM_LEN], nonce[CURL_MAX_NONCE_LEN],
      opaque[CURL_MAX_OPAQUE_LEN], qop[CURL_MAX_QOP_LEN];
  if (curl_auth_parse_digest_challenge (www_auth, realm, sizeof (realm), nonce,
                                        sizeof (nonce), opaque,
                                        sizeof (opaque), qop, sizeof (qop))
      != 0)
    return -1;

  /* Generate client nonce using cryptographically secure random */
  char cnonce[DIGEST_CNONCE_SIZE];
  snprintf (cnonce, sizeof (cnonce), DIGEST_CNONCE_FORMAT, SocketCrypto_random_uint32 (),
            SocketCrypto_random_uint32 ());

  /* Build response */
  char buf[CURL_MAX_AUTH_BUFFER_LEN];
  CurlDigestParams digest_params = {
      .username = auth->username,
      .password = auth->password,
      .realm = realm,
      .nonce = nonce,
      .opaque = opaque[0] ? opaque : NULL,
      .qop = qop[0] ? qop : NULL,
      .uri = uri,
      .method = method,
      .nc = DIGEST_NC_INITIAL,
      .cnonce = cnonce,
      .output = buf,
      .output_size = sizeof (buf)};
  ssize_t len = curl_auth_digest (&digest_params);
  if (len < 0)
    return -1;

  /* Store in session */
  Arena_T arena = session->arena;
  session->auth_header = ALLOC (arena, (size_t)len + 1);
  memcpy (session->auth_header, buf, (size_t)len);
  session->auth_header[len] = '\0';

  return 0;
}
