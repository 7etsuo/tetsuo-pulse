/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketTLSConfig.c - TLS Configuration Defaults
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Implements SocketTLS_config_defaults() for initializing TLS configuration
 * structures with secure defaults. This file focuses solely on configuration
 * initialization; context creation is handled by SocketTLSContext-core.c.
 *
 * Thread safety: Pure function with no shared state - fully thread-safe.
 */

#if SOCKET_HAS_TLS

#include "tls/SocketTLSConfig.h"

#include <string.h>

void
SocketTLS_config_defaults (SocketTLSConfig_T *config)
{
  if (!config)
    return;

  memset (config, 0, sizeof (*config));
  config->min_version = SOCKET_TLS_MIN_VERSION;
  config->max_version = SOCKET_TLS_MAX_VERSION;
  config->handshake_timeout_ms = SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS;
  config->shutdown_timeout_ms = SOCKET_TLS_DEFAULT_SHUTDOWN_TIMEOUT_MS;
  config->poll_interval_ms = SOCKET_TLS_POLL_INTERVAL_MS;
}

#else /* !SOCKET_HAS_TLS */

#include <stddef.h>

void
SocketTLS_config_defaults (SocketTLSConfig_T *config)
{
  (void)config;
}

#endif /* SOCKET_HAS_TLS */
