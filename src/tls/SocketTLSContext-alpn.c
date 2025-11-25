/**
 * SocketTLSContext-alpn.c - ALPN Protocol Negotiation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Handles ALPN (Application-Layer Protocol Negotiation) configuration.
 * Provides protocol list setup, wire format conversion, and custom
 * selection callback support.
 *
 * Thread safety: Not thread-safe (modifies shared context).
 */

#ifdef SOCKET_HAS_TLS

#include "tls/SocketTLSContext-private.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define T SocketTLSContext_T

/**
 * parse_client_protos - Parse client protocols from wire format
 * @in: Wire format input (length-prefixed strings)
 * @inlen: Input length
 * @count_out: Output: number of protocols parsed
 *
 * Returns: Array of null-terminated protocol strings (caller frees)
 */
static const char **
parse_client_protos (const unsigned char *in, unsigned int inlen,
                     size_t *count_out)
{
  size_t count = 0;
  size_t offset = 0;

  while (offset < inlen)
    {
      if (offset + 1 > inlen)
        break;
      unsigned char len = in[offset++];
      if (offset + len > inlen)
        break;
      count++;
      offset += len;
    }

  if (count == 0)
    {
      *count_out = 0;
      return NULL;
    }

  const char **protos = calloc (count, sizeof (const char *));
  if (!protos)
    {
      *count_out = 0;
      return NULL;
    }

  offset = 0;
  size_t idx = 0;
  while (offset < inlen && idx < count)
    {
      unsigned char len = in[offset++];
      if (offset + len > inlen)
        break;

      char *proto = malloc (len + 1);
      if (!proto)
        {
          for (size_t j = 0; j < idx; j++)
            free ((void *)protos[j]);
          free (protos);
          *count_out = 0;
          return NULL;
        }

      memcpy (proto, &in[offset], len);
      proto[len] = '\0';
      protos[idx++] = proto;
      offset += len;
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
  (void)ssl;
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
      *out = (const unsigned char *)selected;
      *outlen = (unsigned char)strlen (selected);
      return SSL_TLSEXT_ERR_OK;
    }

  return SSL_TLSEXT_ERR_NOACK;
}

/**
 * copy_protocol_to_arena - Copy protocol string to context arena
 * @ctx: Context with arena
 * @proto: Protocol string to copy
 *
 * Returns: Arena-allocated copy
 * Raises: SocketTLS_Failed on allocation failure
 */
static char *
copy_protocol_to_arena (T ctx, const char *proto)
{
  size_t len = strlen (proto);
  char *copy = Arena_alloc (ctx->arena, len + 1, __FILE__, __LINE__);
  if (!copy)
    {
      ctx_raise_openssl_error ("Failed to allocate ALPN protocol buffer");
    }
  memcpy (copy, proto, len + 1);
  return copy;
}

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
  size_t total = 0;
  for (size_t i = 0; i < count; i++)
    {
      total += 1 + strlen (protos[i]);
    }

  unsigned char *buf = Arena_alloc (ctx->arena, total, __FILE__, __LINE__);
  if (!buf)
    {
      ctx_raise_openssl_error ("Failed to allocate ALPN buffer");
    }

  size_t offset = 0;
  for (size_t i = 0; i < count; i++)
    {
      size_t len = strlen (protos[i]);
      buf[offset++] = (unsigned char)len;
      memcpy (buf + offset, protos[i], len);
      offset += len;
    }

  *len_out = total;
  return buf;
}

void
SocketTLSContext_set_alpn_protos (T ctx, const char **protos, size_t count)
{
  assert (ctx);
  assert (ctx->ssl_ctx);
  assert (protos || count == 0);

  if (count == 0)
    return;

  if (count > SOCKET_TLS_MAX_ALPN_PROTOCOLS)
    {
      ctx_raise_openssl_error ("Too many ALPN protocols");
    }

  ctx->alpn.protocols
      = Arena_alloc (ctx->arena, count * sizeof (const char *), __FILE__, __LINE__);
  if (!ctx->alpn.protocols)
    {
      ctx_raise_openssl_error ("Failed to allocate ALPN protocols array");
    }

  for (size_t i = 0; i < count; i++)
    {
      assert (protos[i]);
      size_t len = strlen (protos[i]);
      if (len == 0 || len > SOCKET_TLS_MAX_ALPN_LEN)
        {
          ctx_raise_openssl_error ("Invalid ALPN protocol length");
        }
      ctx->alpn.protocols[i] = copy_protocol_to_arena (ctx, protos[i]);
    }
  ctx->alpn.count = count;

  size_t wire_len;
  unsigned char *wire = build_wire_format (ctx, protos, count, &wire_len);

  if (SSL_CTX_set_alpn_protos (ctx->ssl_ctx, wire, (unsigned int)wire_len)
      != 0)
    {
      ctx_raise_openssl_error ("Failed to set ALPN protocols");
    }

  SSL_CTX_set_alpn_select_cb (ctx->ssl_ctx, alpn_select_cb, ctx);
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

