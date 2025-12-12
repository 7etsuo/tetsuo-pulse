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

/**
 * SocketTLS_config_defaults - Initialize TLS config with secure defaults
 * @config: Pointer to configuration structure to initialize
 *
 * Populates the structure with secure library defaults:
 * - min_version: TLS 1.3 (SOCKET_TLS_MIN_VERSION)
 * - max_version: TLS 1.3 (SOCKET_TLS_MAX_VERSION)
 * - All other fields: zero-initialized
 *
 * This enforces a strict TLS 1.3-only policy by default, disabling legacy
 * protocols for enhanced security against downgrade attacks.
 *
 * No-op if config is NULL (no exception raised).
 *
 * Thread-safe: Yes - pure function with no shared state.
 */
void
SocketTLS_config_defaults (SocketTLSConfig_T *config)
{
  if (!config)
    return;

  /* Zero structure and set secure defaults */
  memset (config, 0, sizeof (*config));

  /* Apply TLS 1.3-only policy from header constants */
  config->min_version = SOCKET_TLS_MIN_VERSION;
  config->max_version = SOCKET_TLS_MAX_VERSION;

  /* Future expansion: add ciphers, timeouts, verification settings as
   * SocketTLSConfig_T gains fields. All new fields should be documented
   * in SocketTLSConfig.h with secure defaults. */
}

#else /* !SOCKET_HAS_TLS */

#include <stddef.h>

/**
 * SocketTLS_config_defaults - No-op when TLS disabled
 * @config: Ignored
 *
 * Provides API compatibility when TLS support is not compiled in.
 */
void
SocketTLS_config_defaults (SocketTLSConfig_T *config)
{
  (void)config;
}

#endif /* SOCKET_HAS_TLS */
