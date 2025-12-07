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
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "core/SocketSecurity.h"

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
  size_t total_bytes = 0;

  /* Use runtime security limits for DoS protection and flexibility */
  SocketSecurityLimits sec_limits;
  SocketSecurity_get_limits (&sec_limits);
  const size_t MAX_ALPN_TOTAL_BYTES = sec_limits.tls_max_alpn_total_bytes;
  const size_t MAX_ALPN_PROTOCOLS = sec_limits.tls_max_alpn_protocols;

  bool malformed = false;

  while (offset < inlen && !malformed)
    {
      /* Read protocol length byte */
      unsigned char plen = in[offset++];

      /* RFC 7301: Protocol names must be 1-%zu bytes (0 is invalid) */
      if (plen == 0 || plen > sec_limits.tls_max_alpn_len)
        {
          malformed = true;
          break;
        }

      if (offset + plen > inlen)
        {
          /* Malformed: length exceeds remaining data */
          malformed = true;
          break;
        }

      /* Check total size limit to prevent DoS using secure arithmetic */
      size_t new_total;
      if (!SocketSecurity_check_add(total_bytes, plen + 1, &new_total) ||
          new_total > MAX_ALPN_TOTAL_BYTES)
        {
          malformed = true;
          break; /* Exceeds safe total size or overflow */
        }
      total_bytes = new_total;

      /* Grow array if needed, but limit count using runtime limit */
      if (count >= capacity || count >= MAX_ALPN_PROTOCOLS)
        {
          if (count >= MAX_ALPN_PROTOCOLS)
            {
              free_client_protos (protos, count);
              return NULL; /* Reject lists with too many protocols */
            }
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
      char *proto = malloc (plen + 1);
      if (!proto)
        {
          free_client_protos (protos, count);
          return NULL;
        }
      memcpy (proto, &in[offset], plen);
      proto[plen] = '\0';

      /* Validate protocol name contents per RFC 7301 Section 3.2:
       * Printable ASCII only (0x21-0x7E), no controls or non-ASCII. */
      bool valid = true;
      for (size_t k = 0; k < plen; k++)
        {
          unsigned char c = (unsigned char)proto[k];
          if (c < 0x21u || c > 0x7Eu)
            {
              valid = false;
              break;
            }
        }
      if (!valid)
        {
          free (proto);
          malformed = true;
          break; /* Reject entire list on invalid protocol */
        }

      protos[count++] = proto;
      total_bytes += plen + 1;
      offset += plen;
    }

  if (malformed)
    {
      free_client_protos (protos, count);
      return NULL;
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
 *
 * Server-preference ordering: iterates server protos first, returns
 * the first match found in client list.
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

  /* Validate selected protocol is in client list, valid length, and contents.
   * Hoist length computation for reuse in copy. */
  size_t validated_len = 0;
  if (selected)
    {
      validated_len = strlen (selected);
      if (validated_len == 0 || validated_len > SOCKET_TLS_MAX_ALPN_LEN)
        {
          selected = NULL;
        }
      else
        {
          bool found = false;
          for (size_t j = 0; j < client_count; j++)
            {
              if (strcmp (selected, client_protos[j]) == 0)
                {
                  found = true;
                  break;
                }
            }
          if (!found)
            {
              selected = NULL;
            }
          else
            {
              /* Validate protocol name contents per RFC 7301 Section 3.2:
               * Printable ASCII only (0x21-0x7E), no controls or non-ASCII. */
              bool valid_chars = true;
              for (size_t k = 0; k < validated_len; k++)
                {
                  unsigned char c = (unsigned char)selected[k];
                  if (c < 0x21u || c > 0x7Eu)
                    {
                      valid_chars = false;
                      break;
                    }
                }
              if (!valid_chars)
                {
                  selected = NULL;
                }
            }
        }
    }

  /* Fixed UAF: Allocate copy, store in SSL ex_data for cleanup in tls_cleanup_alpn_temp().
   * OpenSSL memdups *out after callback; we free later via ex_data. */
  if (selected)
    {
      unsigned char *selected_copy = (unsigned char *) malloc (validated_len);
      if (selected_copy == NULL)
        {
          /* Alloc failure: fallback to no protocol (safe) */
          free_client_protos (client_protos, client_count);
          return SSL_TLSEXT_ERR_NOACK;
        }
      memcpy (selected_copy, selected, validated_len);
      /* Store for later cleanup; prevents leak */
      int idx = tls_get_alpn_ex_idx ();
      if (idx != -1)
        SSL_set_ex_data (ssl, idx, (void *) selected_copy);
      /* else rare failure: leak small buffer */
      free_client_protos (client_protos, client_count);
      *out = selected_copy;
      *outlen = (unsigned char) validated_len;
      return SSL_TLSEXT_ERR_OK;
    }
  else
    {
      free_client_protos (client_protos, client_count);
      return SSL_TLSEXT_ERR_NOACK;
    }
}

/* ============================================================================
 * Wire Format Building
 * ============================================================================
 */

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
  if (!SocketSecurity_check_multiply (count, sizeof (size_t), &lengths_size) ||
      !SocketSecurity_check_size (lengths_size))
    ctx_raise_openssl_error ("ALPN lengths array size overflow or too large");
  size_t *lengths = ctx_arena_alloc (ctx, lengths_size,
                                     "Failed to allocate ALPN length cache");

  size_t total = 0;
  for (size_t i = 0; i < count; i++)
    {
      lengths[i] = strlen (protos[i]);
      size_t to_add = 1 + lengths[i];
      size_t new_total;
      /* Check for integer overflow using library primitive */
      if (!SocketSecurity_check_add (total, to_add, &new_total))
        ctx_raise_openssl_error ("ALPN wire format size overflow");
      total = new_total;
    }

  if (!SocketSecurity_check_size (total))
    ctx_raise_openssl_error ("ALPN buffer size too large or invalid");
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
  if (!SocketSecurity_check_multiply (count, sizeof (const char *), &arr_size) ||
      !SocketSecurity_check_size (arr_size))
    ctx_raise_openssl_error ("ALPN protocols array size overflow or too large");
  return ctx_arena_alloc (ctx, arr_size,
                          "Failed to allocate ALPN protocols array");
}

/**
 * copy_alpn_protocols - Validate and copy protocols to context
 * @ctx: TLS context
 * @protos: Source protocol strings (read-only)
 * @count: Number of protocols
 *
 * Validates each protocol length (0 < len <= SOCKET_TLS_MAX_ALPN_LEN)
 * and copies to context arena.
 *
 * Raises: SocketTLS_Failed on invalid protocol length or allocation failure
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
        ctx_raise_openssl_error ("Invalid ALPN protocol length (exceeds runtime limit)");

      /* Validate protocol name contents per RFC 7301 Section 3.2:
       * Printable ASCII only (0x21-0x7E), no controls or non-ASCII. */
      bool valid = true;
      const char *s = protos[i];
      for (size_t k = 0; k < len; k++)
        {
          unsigned char c = (unsigned char)s[k];
          if (c < 0x21u || c > 0x7Eu)
            {
              valid = false;
              break;
            }
        }
      if (!valid)
        ctx_raise_openssl_error ("Invalid characters in ALPN protocol name (RFC 7301)");

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

/* ============================================================================
 * ALPN Temp Buffer Cleanup (for UAF fix)
 * ============================================================================ */

/* Static process-wide ex_data index for ALPN temp buffers */
static int tls_alpn_ex_idx = -1;

/**
 * tls_get_alpn_ex_idx - Get or create ex_data index for ALPN temps
 *
 * Lazy init; called once.
 * Returns: Index or -1 on failure (rare, fallback leak)
 */
int
tls_get_alpn_ex_idx (void)
{
  if (tls_alpn_ex_idx == -1)
    {
      tls_alpn_ex_idx = SSL_get_ex_new_index (0, "tls alpn temp buf", NULL, NULL, NULL);
    }
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

