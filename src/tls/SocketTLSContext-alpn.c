/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketTLSContext-alpn.c - ALPN Protocol Negotiation
 *
 * Part of the Socket Library
 *
 * Application-Layer Protocol Negotiation (ALPN) support for TLS connections.
 * Handles protocol list configuration, wire format conversion, server-side
 * protocol selection, and custom selection callbacks.
 *
 * Thread safety: ALPN configuration is NOT thread-safe.
 * Perform all setup before sharing context. Callbacks must be thread-safe
 * if context is shared.
 */

#if SOCKET_HAS_TLS

#include "tls/SocketTLS-private.h"
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "core/SocketSecurity.h"

#define T SocketTLSContext_T

/** Initial capacity for dynamically-grown protocol arrays */
#define ALPN_INITIAL_CAPACITY 4

/** RFC 7301 Section 3.2: Minimum printable ASCII character (!) */
#define ALPN_PRINTABLE_ASCII_MIN 0x21u

/** RFC 7301 Section 3.2: Maximum printable ASCII character (~) */
#define ALPN_PRINTABLE_ASCII_MAX 0x7Eu

/**
 * validate_alpn_protocol_chars - Validate ALPN protocol name characters
 * @data: Protocol name bytes
 * @len: Length of protocol name
 *
 * RFC 7301 Section 3.2: Protocol identifiers must consist of printable
 * ASCII characters only (0x21-0x7E). Control characters, spaces, and
 * non-ASCII bytes are rejected to prevent injection attacks.
 *
 * Returns: true if valid, false if any invalid character found
 */
static bool
validate_alpn_protocol_chars (const unsigned char *data, size_t len)
{
  for (size_t i = 0; i < len; i++)
    {
      unsigned char c = data[i];
      if (c < ALPN_PRINTABLE_ASCII_MIN || c > ALPN_PRINTABLE_ASCII_MAX)
        return false;
    }
  return true;
}

/**
 * free_client_protos - Free parsed client protocols array
 * @protos: Protocol array to free (may be NULL)
 * @count: Number of protocols
 */
static void
free_client_protos (const char **protos, size_t count)
{
  if (!protos)
    return;

  for (size_t i = 0; i < count; i++)
    free ((void *)protos[i]);
  free (protos);
}

/**
 * parse_single_protocol - Parse and validate one protocol from wire format
 * @in: Wire format input buffer
 * @inlen: Total input length
 * @offset: Current offset (updated on success)
 * @total_bytes: Running total bytes (updated on success)
 * @limits: Security limits for validation
 * @proto_out: Output: allocated protocol string (caller owns)
 *
 * Parses one length-prefixed protocol, validates RFC 7301 compliance,
 * checks against DoS limits, and allocates a null-terminated copy.
 *
 * Returns: 1 on success, 0 on error/malformed, -1 on allocation failure
 */
static int
parse_single_protocol (const unsigned char *in, unsigned int inlen,
                       size_t *offset, size_t *total_bytes,
                       const SocketSecurityLimits *limits, char **proto_out)
{
  *proto_out = NULL;

  if (*offset >= inlen)
    return 0;

  /* Read protocol length byte */
  unsigned char plen = in[*offset];
  (*offset)++;

  /* RFC 7301: Protocol names must be 1-N bytes (0 is invalid) */
  if (plen == 0 || plen > limits->tls_max_alpn_len)
    return 0;

  if (*offset + plen > inlen)
    return 0; /* Malformed: length exceeds remaining data */

  /* Check total size limit to prevent DoS */
  size_t new_total;
  if (!SocketSecurity_check_add (*total_bytes, plen + 1, &new_total)
      || new_total > limits->tls_max_alpn_total_bytes)
    return 0;

  /* Validate protocol name contents per RFC 7301 Section 3.2 */
  if (!validate_alpn_protocol_chars (&in[*offset], plen))
    return 0;

  /* Allocate and copy protocol string */
  char *proto = malloc (plen + 1);
  if (!proto)
    return -1;

  memcpy (proto, &in[*offset], plen);
  proto[plen] = '\0';

  *offset += plen;
  *total_bytes = new_total;
  *proto_out = proto;
  return 1;
}

/**
 * grow_protocol_array - Grow protocol array with overflow protection
 * @protos: Current array
 * @capacity: Current capacity (updated on success)
 *
 * Doubles the array capacity with overflow checking. On allocation failure,
 * the old array is NOT freed (caller handles cleanup).
 *
 * Returns: New array or NULL on failure (overflow or allocation failure)
 */
static const char **
grow_protocol_array (const char **protos, size_t *capacity)
{
  size_t new_capacity;
  size_t alloc_size;

  /* Check for capacity doubling overflow */
  if (!SocketSecurity_check_multiply (*capacity, 2, &new_capacity))
    return NULL;

  /* Check for allocation size overflow */
  if (!SocketSecurity_check_multiply (new_capacity, sizeof (char *),
                                      &alloc_size))
    return NULL;

  const char **new_protos = realloc (protos, alloc_size);
  if (!new_protos)
    return NULL;

  *capacity = new_capacity;
  return new_protos;
}

/**
 * parse_client_protos - Parse client protocols from ALPN wire format
 * @in: Wire format input (length-prefixed strings)
 * @inlen: Input length
 * @count_out: Output: number of protocols parsed
 *
 * Parses wire format in a single pass, growing array as needed.
 * Wire format: [len1][proto1][len2][proto2]...
 *
 * Returns: Array of null-terminated protocol strings (caller frees via
 *          free_client_protos), or NULL on error/empty
 */
static const char **
parse_client_protos (const unsigned char *in, unsigned int inlen,
                     size_t *count_out)
{
  *count_out = 0;

  if (!in || inlen == 0)
    return NULL;

  /* Get runtime security limits */
  SocketSecurityLimits limits;
  SocketSecurity_get_limits (&limits);

  /* Start with small capacity, grow as needed */
  size_t capacity = ALPN_INITIAL_CAPACITY;
  const char **protos = calloc (capacity, sizeof (const char *));
  if (!protos)
    return NULL;

  size_t count = 0;
  size_t offset = 0;
  size_t total_bytes = 0;

  while (offset < inlen)
    {
      /* Check protocol count limit */
      if (count >= limits.tls_max_alpn_protocols)
        {
          free_client_protos (protos, count);
          return NULL;
        }

      /* Grow array if needed */
      if (count >= capacity)
        {
          const char **new_protos = grow_protocol_array (protos, &capacity);
          if (!new_protos)
            {
              free_client_protos (protos, count);
              return NULL;
            }
          protos = new_protos;
        }

      /* Parse one protocol */
      char *proto = NULL;
      int result
          = parse_single_protocol (in, inlen, &offset, &total_bytes, &limits,
                                   &proto);
      if (result < 0)
        {
          /* Allocation failure */
          free_client_protos (protos, count);
          return NULL;
        }
      if (result == 0)
        {
          /* Malformed protocol - reject entire list */
          free_client_protos (protos, count);
          return NULL;
        }

      protos[count++] = proto;
    }

  if (count == 0)
    {
      free (protos);
      return NULL;
    }

  *count_out = count;
  return protos;
}

/**
 * find_matching_proto - Find first matching protocol (server preference order)
 * @server_protos: Server's protocol list (preference order)
 * @server_count: Number of server protocols
 * @client_protos: Client's offered protocols
 * @client_count: Number of client protocols
 *
 * Returns: Selected protocol string or NULL if no match
 */
static const char *
find_matching_proto (const char *const *server_protos, size_t server_count,
                     const char *const *client_protos, size_t client_count)
{
  for (size_t i = 0; i < server_count; i++)
    {
      for (size_t j = 0; j < client_count; j++)
        {
          if (strcmp (server_protos[i], client_protos[j]) == 0)
            return server_protos[i];
        }
    }
  return NULL;
}

/**
 * find_in_client_list - Check if protocol exists in client's offered list
 * @proto: Protocol to find
 * @client_protos: Client's offered protocols
 * @client_count: Number of client protocols
 *
 * Returns: true if found, false otherwise
 */
static bool
find_in_client_list (const char *proto, const char *const *client_protos,
                     size_t client_count)
{
  for (size_t i = 0; i < client_count; i++)
    {
      if (strcmp (proto, client_protos[i]) == 0)
        return true;
    }
  return false;
}

/**
 * validate_selected_protocol - Validate callback-selected protocol
 * @selected: Protocol string from callback
 * @client_protos: Client's offered protocols (already validated)
 * @client_count: Number of client protocols
 * @validated_len: Output: validated length of protocol
 *
 * Ensures the selected protocol:
 * - Has valid length (1 to SOCKET_TLS_MAX_ALPN_LEN)
 * - Exists in the client's offered list
 * - Contains only RFC 7301 compliant characters
 *
 * Returns: true if valid, false if invalid (sets *validated_len to 0)
 */
static bool
validate_selected_protocol (const char *selected,
                            const char *const *client_protos,
                            size_t client_count, size_t *validated_len)
{
  *validated_len = 0;

  if (!selected)
    return false;

  size_t len = strlen (selected);
  if (len == 0 || len > SOCKET_TLS_MAX_ALPN_LEN)
    return false;

  /* Must be in client's offered list */
  if (!find_in_client_list (selected, client_protos, client_count))
    return false;

  /* Validate characters (defense in depth for custom callbacks) */
  if (!validate_alpn_protocol_chars ((const unsigned char *)selected, len))
    return false;

  *validated_len = len;
  return true;
}

/**
 * alpn_select_cb - OpenSSL ALPN selection callback
 * @ssl: SSL connection (for ex_data storage)
 * @out: Output: selected protocol
 * @outlen: Output: selected protocol length
 * @in: Client protocol list (wire format)
 * @inlen: Client protocol list length
 * @arg: Context pointer
 *
 * Returns: SSL_TLSEXT_ERR_OK or SSL_TLSEXT_ERR_NOACK
 */
static int
alpn_select_cb (SSL *ssl, const unsigned char **out, unsigned char *outlen,
                const unsigned char *in, unsigned int inlen, void *arg)
{
  TLS_UNUSED (ssl);
  T ctx = (T)arg;

  if (!ctx || !ctx->alpn.protocols || ctx->alpn.count == 0)
    return SSL_TLSEXT_ERR_NOACK;

  /* Parse client protocols from wire format */
  size_t client_count;
  const char **client_protos = parse_client_protos (in, inlen, &client_count);
  if (!client_protos)
    return SSL_TLSEXT_ERR_NOACK;

  /* Select protocol via callback or default matching */
  const char *selected = NULL;
  if (ctx->alpn.callback)
    {
      selected = ctx->alpn.callback (client_protos, client_count,
                                     ctx->alpn.callback_user_data);
    }
  else
    {
      selected = find_matching_proto (ctx->alpn.protocols, ctx->alpn.count,
                                      client_protos, client_count);
    }

  /* Validate selected protocol */
  size_t validated_len = 0;
  if (!validate_selected_protocol (selected, client_protos, client_count,
                                   &validated_len))
    {
      free_client_protos (client_protos, client_count);
      return SSL_TLSEXT_ERR_NOACK;
    }

  /* Allocate persistent copy to prevent UAF.
   * Store in SSL ex_data for cleanup in tls_cleanup_alpn_temp(). */
  unsigned char *selected_copy = (unsigned char *)malloc (validated_len);
  if (!selected_copy)
    {
      free_client_protos (client_protos, client_count);
      return SSL_TLSEXT_ERR_NOACK;
    }

  memcpy (selected_copy, selected, validated_len);

  /* Store for cleanup; prevents leak */
  int idx = tls_get_alpn_ex_idx ();
  if (idx != -1)
    {
      if (SSL_set_ex_data (ssl, idx, (void *)selected_copy) != 1)
        {
          SOCKET_LOG_WARN_MSG ("Failed to set SSL ex_data for ALPN selected protocol");
          /* Cleanup allocated memory on failure to prevent leak */
          free (selected_copy);
          free_client_protos (client_protos, client_count);
          return SSL_TLSEXT_ERR_NOACK;
        }
    }

  free_client_protos (client_protos, client_count);

  *out = selected_copy;
  *outlen = (unsigned char)validated_len;
  return SSL_TLSEXT_ERR_OK;
}

/**
 * build_wire_format - Build ALPN wire format from protocol list
 * @ctx: Context with arena
 * @protos: Protocol strings (read-only)
 * @count: Number of protocols
 * @len_out: Output: wire format length
 *
 * Wire format: [len1][proto1][len2][proto2]... (length-prefixed strings)
 *
 * Returns: Wire format buffer (arena-allocated)
 * Raises: SocketTLS_Failed on allocation failure or overflow
 */
static unsigned char *
build_wire_format (T ctx, const char *const *protos, size_t count,
                   size_t *len_out)
{
  /* Cache protocol lengths to avoid redundant strlen calls */
  size_t lengths_size;
  if (!SocketSecurity_check_multiply (count, sizeof (size_t), &lengths_size)
      || !SocketSecurity_check_size (lengths_size))
    ctx_raise_openssl_error ("ALPN lengths array size overflow or too large");

  size_t *lengths
      = ctx_arena_alloc (ctx, lengths_size, "Failed to allocate ALPN length cache");

  /* Calculate total wire format size with overflow protection */
  size_t total = 0;
  for (size_t i = 0; i < count; i++)
    {
      lengths[i] = strlen (protos[i]);
      size_t to_add = 1 + lengths[i];
      size_t new_total;
      if (!SocketSecurity_check_add (total, to_add, &new_total))
        ctx_raise_openssl_error ("ALPN wire format size overflow");
      total = new_total;
    }

  if (!SocketSecurity_check_size (total))
    ctx_raise_openssl_error ("ALPN buffer size too large or invalid");

  unsigned char *buf
      = ctx_arena_alloc (ctx, total, "Failed to allocate ALPN buffer");

  /* Build wire format: [len][data]... */
  size_t offset = 0;
  for (size_t i = 0; i < count; i++)
    {
      buf[offset++] = (unsigned char)lengths[i];
      memcpy (buf + offset, protos[i], lengths[i]);
      offset += lengths[i];
    }

  *len_out = total;
  return buf;
}

/**
 * validate_alpn_count - Validate ALPN protocol count against runtime limit
 * @count: Number of protocols
 *
 * Raises: SocketTLS_Failed if count exceeds maximum
 */
static void
validate_alpn_count (size_t count)
{
  SocketSecurityLimits limits;
  SocketSecurity_get_limits (&limits);
  if (count > limits.tls_max_alpn_protocols)
    ctx_raise_openssl_error ("Too many ALPN protocols (exceeds runtime limit)");
}

/**
 * alloc_alpn_array - Allocate ALPN protocols array in context arena
 * @ctx: TLS context
 * @count: Number of protocols
 *
 * Returns: Allocated array
 * Raises: SocketTLS_Failed on allocation failure
 */
static const char **
alloc_alpn_array (T ctx, size_t count)
{
  size_t arr_size;
  if (!SocketSecurity_check_multiply (count, sizeof (const char *), &arr_size)
      || !SocketSecurity_check_size (arr_size))
    ctx_raise_openssl_error ("ALPN protocols array size overflow or too large");

  return ctx_arena_alloc (ctx, arr_size, "Failed to allocate ALPN protocols array");
}

/**
 * copy_alpn_protocols - Validate and copy protocols to context
 * @ctx: TLS context
 * @protos: Source protocol strings (read-only)
 * @count: Number of protocols
 *
 * Validates each protocol length and characters per RFC 7301,
 * then copies to context arena.
 *
 * Raises: SocketTLS_Failed on invalid protocol or allocation failure
 */
static void
copy_alpn_protocols (T ctx, const char *const *protos, size_t count)
{
  SocketSecurityLimits limits;
  SocketSecurity_get_limits (&limits);

  for (size_t i = 0; i < count; i++)
    {
      assert (protos[i]);

      size_t len = strlen (protos[i]);
      if (len == 0 || len > limits.tls_max_alpn_len)
        ctx_raise_openssl_error (
            "Invalid ALPN protocol length (exceeds runtime limit)");

      /* Validate RFC 7301 Section 3.2 compliance */
      if (!validate_alpn_protocol_chars ((const unsigned char *)protos[i], len))
        ctx_raise_openssl_error (
            "Invalid characters in ALPN protocol name (RFC 7301)");

      ctx->alpn.protocols[i]
          = ctx_arena_strdup (ctx, protos[i], "Failed to allocate ALPN buffer");
    }
}

/**
 * apply_alpn_to_ssl_ctx - Apply ALPN configuration to OpenSSL context
 * @ctx: TLS context
 * @protos: Protocol strings (read-only)
 * @count: Number of protocols
 *
 * Builds wire format, sets ALPN protos on SSL_CTX, and registers
 * server-side selection callback.
 *
 * Raises: SocketTLS_Failed on OpenSSL error
 */
static void
apply_alpn_to_ssl_ctx (T ctx, const char *const *protos, size_t count)
{
  size_t wire_len;
  unsigned char *wire = build_wire_format (ctx, protos, count, &wire_len);

  if (SSL_CTX_set_alpn_protos (ctx->ssl_ctx, wire, (unsigned int)wire_len) != 0)
    ctx_raise_openssl_error ("Failed to set ALPN protocols");

  SSL_CTX_set_alpn_select_cb (ctx->ssl_ctx, alpn_select_cb, ctx);
}

void
SocketTLSContext_set_alpn_protos (T ctx, const char **protos, size_t count)
{
  assert (ctx);
  assert (ctx->ssl_ctx);
  assert (protos || count == 0);

  if (count == 0)
    return;

  validate_alpn_count (count);
  ctx->alpn.protocols = alloc_alpn_array (ctx, count);
  copy_alpn_protocols (ctx, protos, count);
  ctx->alpn.count = count;
  apply_alpn_to_ssl_ctx (ctx, protos, count);
}

void
SocketTLSContext_set_alpn_callback (T ctx, SocketTLSAlpnCallback callback,
                                    void *user_data)
{
  assert (ctx);

  ctx->alpn.callback = callback;
  ctx->alpn.callback_user_data = user_data;
}

/** Static process-wide ex_data index for ALPN temp buffers.
 * Thread-safe initialization using pthread_once to prevent race conditions
 * when multiple threads create SSL objects concurrently. */
static int tls_alpn_ex_idx = -1;
static pthread_once_t tls_alpn_ex_once = PTHREAD_ONCE_INIT;

/**
 * init_alpn_ex_idx - One-time initialization of ALPN ex-data index
 *
 * Called via pthread_once to ensure thread-safe single initialization.
 * This prevents race conditions where multiple threads could call
 * SSL_get_ex_new_index() simultaneously and get different indices.
 */
static void
init_alpn_ex_idx (void)
{
  tls_alpn_ex_idx
      = SSL_get_ex_new_index (0, "tls alpn temp buf", NULL, NULL, NULL);
}

/**
 * tls_get_alpn_ex_idx - Get ex_data index for ALPN temps (thread-safe)
 *
 * Uses pthread_once for guaranteed single initialization across all threads.
 *
 * Returns: Index or -1 on failure (rare, fallback leak)
 */
int
tls_get_alpn_ex_idx (void)
{
  pthread_once (&tls_alpn_ex_once, init_alpn_ex_idx);
  return tls_alpn_ex_idx;
}

/**
 * tls_cleanup_alpn_temp - Free ALPN temp from SSL ex_data
 * @ssl: SSL* to clean
 *
 * Frees stored malloc'ed copy if present; clears slot.
 * Call before SSL_free(ssl) in all TLS impl files.
 */
void
tls_cleanup_alpn_temp (SSL *ssl)
{
  if (!ssl)
    return;

  int idx = tls_get_alpn_ex_idx ();
  if (idx != -1)
    {
      void *ptr = SSL_get_ex_data (ssl, idx);
      if (ptr)
        {
          free (ptr);
          SSL_set_ex_data (ssl, idx, NULL);
        }
    }
}

#undef T

#endif /* SOCKET_HAS_TLS */
