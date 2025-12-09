/**
 * SocketTLSConfig.c - TLS Configuration Defaults and Helpers
 *
 * Implements SocketTLS_config_defaults and related helpers.
 * Stub for now; expand with full struct fields as needed.
 */

#if SOCKET_HAS_TLS

#include "tls/SocketTLS-private.h"
#include "tls/SocketTLSConfig.h"
#include "tls/SocketTLSContext.h"

SOCKET_DECLARE_MODULE_EXCEPTION (SocketTLSConfig);

void
SocketTLS_config_defaults (struct SocketTLSConfig_T *config)
{
  if (!config)
    return;

  /* Zero structure and set secure defaults */
  memset (config, 0, sizeof (*config));

  /* Reference constants from header */
  config->min_version = SOCKET_TLS_MIN_VERSION;
  config->max_version = SOCKET_TLS_MAX_VERSION;
  /* Add more fields as struct expands (ciphers, timeouts, etc.) */
  /* config->ciphersuites = SOCKET_TLS13_CIPHERSUITES; etc. */
}

SocketTLSContext_T
SocketTLSContext_new (const struct SocketTLSConfig_T *config)
{
  /* Stub impl: delegate to new_client with defaults if config NULL */
  SocketTLSContext_T ctx;
  struct SocketTLSConfig_T defaults;

  if (config == NULL)
    {
      SocketTLS_config_defaults (&defaults);
      config = &defaults;
    }

  /* Full impl would create context with config applied
   * For now, map to new_client (no CA) and apply config via setters */
  ctx = SocketTLSContext_new_client (NULL);

  /* Apply config */
  SocketTLSContext_set_min_protocol (ctx, config->min_version);
  SocketTLSContext_set_max_protocol (ctx, config->max_version);
  /* SocketTLSContext_set_cipher_list (ctx, config->ciphersuites); etc. */

  return ctx;
}

#else /* !SOCKET_HAS_TLS */

void
SocketTLS_config_defaults (struct SocketTLSConfig_T *config)
{
  (void)config;
}

SocketTLSContext_T
SocketTLSContext_new (const struct SocketTLSConfig_T *config)
{
  (void)config;
  return NULL; /* Stub */
}

#endif /* SOCKET_HAS_TLS */
