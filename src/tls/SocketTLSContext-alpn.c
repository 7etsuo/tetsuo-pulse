/**
 * SocketTLSContext-alpn.c - ALPN Protocol Negotiation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Application-Layer Protocol Negotiation (ALPN) support for TLS connections.
 * Handles protocol list configuration, wire format conversion, server-side
 * protocol selection, and custom selection callbacks.
 *
 * Thread safety: ALPN configuration is NOT thread-safe.
 * Perform all setup before sharing context. Callbacks must be thread-safe
 * if context is shared.
 */

#ifdef SOCKET_HAS_TLS

#include "tls/SocketTLS-private.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define T SocketTLSContext_T

/* ============================================================================
 * Wire Format Parsing Helpers
 * ============================================================================
 */

/* Forward declaration for free_client_protos (used by parse_client_protos) */
static void free_client_protos (const char **protos, size_t count);

/**
 * parse_client_protos - Parse client protocols from ALPN wire format (single pass)
 * @in: Wire format input (length-prefixed strings)
 * @inlen: Input length
 * @count_out: Output: number of protocols parsed
 *
 * Parses wire format in a single pass, growing array as needed.
 * Wire format: [len1][proto1][len2][proto2]...
 *
 * Returns: Array of null-terminated protocol strings (caller frees)
 */
static const char **
parse_client_protos (const unsigned char *in, unsigned int inlen,
                     size_t *count_out)
{
  *count_out = 0;

  if (!in || inlen == 0)
    return NULL;

  /* Start with small capacity, grow as needed */
  size_t capacity = 4;
  const char **protos = calloc (capacity, sizeof (const char *));
  if (!protos)
    return NULL;

  size_t count = 0;
  size_t offset = 0;

  while (offset < inlen)
    {
      /* Read protocol length byte */
      unsigned char len = in[offset++];
      if (offset + len > inlen)
        break; /* Malformed: length exceeds remaining data */

      /* Grow array if needed */
      if (count >= capacity)
        {
          capacity *= 2;
          const char **new_protos = realloc (protos, capacity * sizeof (char *));
          if (!new_protos)
            {
              free_client_protos (protos, count);
              return NULL;
            }
          protos = new_protos;
        }

      /* Allocate and copy protocol string */
      char *proto = malloc (len + 1);
      if (!proto)
        {
          free_client_protos (protos, count);
          return NULL;
        }
      memcpy (proto, &in[offset], len);
      proto[len] = '\0';

      protos[count++] = proto;
      offset += len;
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
 * free_client_protos - Free parsed client protocols array
 * @protos: Protocol array to free
 * @count: Number of protocols
 */
static void
free_client_protos (const char **protos, size_t count)
{
  if (!protos)
    return;

  for (size_t i = 0; i < count; i++)
    {
      free ((void *)protos[i]);
    }
  free (protos);
}

/* ============================================================================
 * Protocol Selection
 * ============================================================================
 */

/**
 * find_matching_proto - Find first matching protocol
 * @server_protos: Server's protocol list (preference order)
 * @server_count: Number of server protocols
 * @client_protos: Client's offered protocols
 * @client_count: Number of client protocols
 *
 * Returns: Selected protocol string or NULL
 */
static const char *
find_matching_proto (const char **server_protos, size_t server_count,
                     const char **client_protos, size_t client_count)
{
  for (size_t i = 0; i < server_count; i++)
    {
      for (size_t j = 0; j < client_count; j++)
        {
          if (strcmp (server_protos[i], client_protos[j]) == 0)
            {
              return server_protos[i];
            }
        }
    }
  return NULL;
}

/**
 * alpn_select_cb - OpenSSL ALPN selection callback
 * @ssl: SSL connection (unused)
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

  size_t client_count;
  const char **client_protos = parse_client_protos (in, inlen, &client_count);
  if (!client_protos)
    return SSL_TLSEXT_ERR_NOACK;

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

  free_client_protos (client_protos, client_count);

  if (selected)
    {
      size_t selected_len = strlen (selected);
      /* Validate protocol length fits in unsigned char (ALPN max is 255) */
      if (selected_len == 0 || selected_len > SOCKET_TLS_MAX_ALPN_LEN)
        return SSL_TLSEXT_ERR_NOACK;
      *out = (const unsigned char *)selected;
      *outlen = (unsigned char)selected_len;
      return SSL_TLSEXT_ERR_OK;
    }

  return SSL_TLSEXT_ERR_NOACK;
}

/* ============================================================================
 * Wire Format Building
 * ============================================================================
 */

/**
 * build_wire_format - Build ALPN wire format from protocol list
 * @ctx: Context with arena
 * @protos: Protocol strings
 * @count: Number of protocols
 * @len_out: Output: wire format length
 *
 * Returns: Wire format buffer (arena-allocated)
 * Raises: SocketTLS_Failed on allocation failure
 */
static unsigned char *
build_wire_format (T ctx, const char **protos, size_t count, size_t *len_out)
{
  /* Cache protocol lengths to avoid redundant strlen calls */
  size_t *lengths = ctx_arena_alloc (ctx, count * sizeof (size_t),
                                     "Failed to allocate ALPN length cache");

  size_t total = 0;
  for (size_t i = 0; i < count; i++)
    {
      lengths[i] = strlen (protos[i]);
      /* Check for integer overflow before accumulation */
      if (total > SIZE_MAX - 1 - lengths[i])
        ctx_raise_openssl_error ("ALPN wire format size overflow");
      total += 1 + lengths[i];
    }

  unsigned char *buf = ctx_arena_alloc (ctx, total,
                                        "Failed to allocate ALPN buffer");

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

/* ============================================================================
 * Validation and Setup Helpers
 * ============================================================================
 */

/**
 * validate_alpn_count - Validate ALPN protocol count
 * @count: Number of protocols
 *
 * Raises: SocketTLS_Failed if count exceeds maximum
 */
static void
validate_alpn_count (size_t count)
{
  if (count > SOCKET_TLS_MAX_ALPN_PROTOCOLS)
    ctx_raise_openssl_error ("Too many ALPN protocols");
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
  return ctx_arena_alloc (ctx, count * sizeof (const char *),
                          "Failed to allocate ALPN protocols array");
}

/**
 * copy_alpn_protocols - Validate and copy protocols to context
 * @ctx: TLS context
 * @protos: Source protocol strings
 * @count: Number of protocols
 */
static void
copy_alpn_protocols (T ctx, const char **protos, size_t count)
{
  for (size_t i = 0; i < count; i++)
    {
      assert (protos[i]);
      size_t len = strlen (protos[i]);
      if (len == 0 || len > SOCKET_TLS_MAX_ALPN_LEN)
        ctx_raise_openssl_error ("Invalid ALPN protocol length");
      ctx->alpn.protocols[i]
          = ctx_arena_strdup (ctx, protos[i], "Failed to allocate ALPN buffer");
    }
}

/**
 * apply_alpn_to_ssl_ctx - Apply ALPN configuration to OpenSSL context
 * @ctx: TLS context
 * @protos: Protocol strings
 * @count: Number of protocols
 */
static void
apply_alpn_to_ssl_ctx (T ctx, const char **protos, size_t count)
{
  size_t wire_len;
  unsigned char *wire = build_wire_format (ctx, protos, count, &wire_len);

  if (SSL_CTX_set_alpn_protos (ctx->ssl_ctx, wire, (unsigned int)wire_len)
      != 0)
    ctx_raise_openssl_error ("Failed to set ALPN protocols");

  SSL_CTX_set_alpn_select_cb (ctx->ssl_ctx, alpn_select_cb, ctx);
}

/* ============================================================================
 * Public ALPN API
 * ============================================================================
 */

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

#undef T

#endif /* SOCKET_HAS_TLS */

