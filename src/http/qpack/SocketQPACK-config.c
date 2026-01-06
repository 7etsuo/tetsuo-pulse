/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK-config.c
 * @brief QPACK Configuration implementation (RFC 9204 Section 5).
 *
 * Implements QPACK settings handling including:
 * - SETTINGS_QPACK_MAX_TABLE_CAPACITY (0x01)
 * - SETTINGS_QPACK_BLOCKED_STREAMS (0x07)
 * - 0-RTT early data settings handling (Section 3.2.3)
 *
 * @see https://www.rfc-editor.org/rfc/rfc9204#section-5
 */

#include "http/SocketQPACK.h"

#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketLog.h"

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "QPACK"

/* ============================================================================
 * Exception Definition
 * ============================================================================
 */

const Except_T SocketQPACK_ConfigError
    = { &SocketQPACK_ConfigError, "QPACK configuration error" };

/* ============================================================================
 * Result String Table
 * ============================================================================
 */

static const char *config_result_strings[] = {
  [QPACK_CONFIG_OK] = "OK",
  [QPACK_CONFIG_ERROR_INVALID_VALUE] = "Invalid settings value",
  [QPACK_CONFIG_ERROR_NULL_PARAM] = "NULL parameter",
  [QPACK_CONFIG_ERROR_ALREADY_APPLIED] = "Settings already applied",
  [QPACK_CONFIG_ERROR_ALLOC] = "Allocation failed",
  [QPACK_CONFIG_ERROR_NOT_READY] = "Configuration not ready",
};

const char *
SocketQPACK_config_result_string (SocketQPACK_ConfigResult result)
{
  if (result < 0
      || result >= (int)(sizeof (config_result_strings)
                         / sizeof (config_result_strings[0])))
    return "Unknown error";

  const char *str = config_result_strings[result];
  return str ? str : "Unknown error";
}

/* ============================================================================
 * Settings Functions (RFC 9204 Section 5)
 * ============================================================================
 */

SocketQPACK_ConfigResult
SocketQPACK_settings_defaults (SocketQPACK_Settings *settings)
{
  if (settings == NULL)
    {
      SOCKET_LOG_DEBUG_MSG (
          "SocketQPACK_settings_defaults: NULL settings pointer");
      return QPACK_CONFIG_ERROR_NULL_PARAM;
    }

  /* RFC 9204 Section 5: "The default value is zero." */
  settings->max_table_capacity = 0;
  settings->blocked_streams = 0;

  SOCKET_LOG_DEBUG_MSG ("SocketQPACK: initialized settings to RFC defaults "
                        "(capacity=0, blocked=0)");

  return QPACK_CONFIG_OK;
}

SocketQPACK_ConfigResult
SocketQPACK_settings_validate (const SocketQPACK_Settings *settings)
{
  if (settings == NULL)
    {
      SOCKET_LOG_DEBUG_MSG (
          "SocketQPACK_settings_validate: NULL settings pointer");
      return QPACK_CONFIG_ERROR_NULL_PARAM;
    }

  /* RFC 9204 Section 5: max_table_capacity max is 2^30 - 1 */
  if (settings->max_table_capacity > QPACK_MAX_TABLE_CAPACITY_LIMIT)
    {
      SOCKET_LOG_WARN_MSG (
          "SocketQPACK: max_table_capacity (%zu) exceeds limit (%zu)",
          settings->max_table_capacity,
          QPACK_MAX_TABLE_CAPACITY_LIMIT);
      return QPACK_CONFIG_ERROR_INVALID_VALUE;
    }

  /* RFC 9204 Section 5: blocked_streams max is 2^16 - 1 */
  if (settings->blocked_streams > QPACK_MAX_BLOCKED_STREAMS_LIMIT)
    {
      SOCKET_LOG_WARN_MSG (
          "SocketQPACK: blocked_streams (%zu) exceeds limit (%zu)",
          settings->blocked_streams,
          QPACK_MAX_BLOCKED_STREAMS_LIMIT);
      return QPACK_CONFIG_ERROR_INVALID_VALUE;
    }

  /* Warn on very large capacity values (potential resource exhaustion) */
  if (settings->max_table_capacity > QPACK_CAPACITY_WARNING_THRESHOLD)
    {
      SOCKET_LOG_WARN_MSG (
          "SocketQPACK: max_table_capacity (%zu) exceeds 100 MB warning "
          "threshold - ensure sufficient memory available",
          settings->max_table_capacity);
    }

  SOCKET_LOG_DEBUG_MSG ("SocketQPACK: settings validated (capacity=%zu, "
                        "blocked=%zu)",
                        settings->max_table_capacity,
                        settings->blocked_streams);

  return QPACK_CONFIG_OK;
}

int
SocketQPACK_settings_has_dynamic_table (const SocketQPACK_Settings *settings)
{
  if (settings == NULL)
    return 0;

  /* RFC 9204 Section 5: 0 capacity means no dynamic table */
  return settings->max_table_capacity > 0;
}

int
SocketQPACK_settings_allows_blocking (const SocketQPACK_Settings *settings)
{
  if (settings == NULL)
    return 0;

  /* RFC 9204 Section 5: 0 blocked_streams means no blocking allowed */
  return settings->blocked_streams > 0;
}

/* ============================================================================
 * Configuration Functions
 * ============================================================================
 */

SocketQPACK_Config_T
SocketQPACK_config_new (Arena_T arena)
{
  SocketQPACK_Config_T config;

  if (arena == NULL)
    {
      SOCKET_LOG_ERROR_MSG ("SocketQPACK_config_new: NULL arena");
      RAISE (SocketQPACK_ConfigError);
    }

  config = ALLOC (arena, sizeof (*config));
  if (config == NULL)
    {
      SOCKET_LOG_ERROR_MSG (
          "SocketQPACK_config_new: failed to allocate config");
      RAISE (SocketQPACK_ConfigError);
    }

  /* Initialize both local and peer settings to RFC defaults */
  SocketQPACK_settings_defaults (&config->local);
  SocketQPACK_settings_defaults (&config->peer);

  config->previous = NULL;
  config->validated = 0;
  config->peer_received = 0;
  config->using_0rtt = 0;

  SOCKET_LOG_DEBUG_MSG ("SocketQPACK: created new configuration");

  return config;
}

SocketQPACK_ConfigResult
SocketQPACK_config_set_local (SocketQPACK_Config_T config,
                               const SocketQPACK_Settings *settings)
{
  SocketQPACK_ConfigResult result;

  if (config == NULL || settings == NULL)
    {
      SOCKET_LOG_DEBUG_MSG ("SocketQPACK_config_set_local: NULL parameter");
      return QPACK_CONFIG_ERROR_NULL_PARAM;
    }

  /* Validate settings before applying */
  result = SocketQPACK_settings_validate (settings);
  if (result != QPACK_CONFIG_OK)
    return result;

  /* Copy settings */
  config->local.max_table_capacity = settings->max_table_capacity;
  config->local.blocked_streams = settings->blocked_streams;

  SOCKET_LOG_DEBUG_MSG ("SocketQPACK: set local settings (capacity=%zu, "
                        "blocked=%zu)",
                        config->local.max_table_capacity,
                        config->local.blocked_streams);

  return QPACK_CONFIG_OK;
}

SocketQPACK_ConfigResult
SocketQPACK_config_apply_peer (SocketQPACK_Config_T config,
                                const SocketQPACK_Settings *settings)
{
  SocketQPACK_ConfigResult result;

  if (config == NULL || settings == NULL)
    {
      SOCKET_LOG_DEBUG_MSG ("SocketQPACK_config_apply_peer: NULL parameter");
      return QPACK_CONFIG_ERROR_NULL_PARAM;
    }

  /* Validate settings before applying */
  result = SocketQPACK_settings_validate (settings);
  if (result != QPACK_CONFIG_OK)
    {
      SOCKET_LOG_WARN_MSG (
          "SocketQPACK: rejecting invalid peer settings: %s",
          SocketQPACK_config_result_string (result));
      return result;
    }

  /* Copy settings */
  config->peer.max_table_capacity = settings->max_table_capacity;
  config->peer.blocked_streams = settings->blocked_streams;
  config->peer_received = 1;
  config->validated = 1;

  SOCKET_LOG_DEBUG_MSG (
      "SocketQPACK: applied peer settings (capacity=%zu, blocked=%zu)",
      config->peer.max_table_capacity,
      config->peer.blocked_streams);

  /* Log dynamic table status */
  if (config->peer.max_table_capacity == 0)
    {
      SOCKET_LOG_DEBUG_MSG (
          "SocketQPACK: peer disabled dynamic table - using literal encoding");
    }

  if (config->peer.blocked_streams == 0)
    {
      SOCKET_LOG_DEBUG_MSG (
          "SocketQPACK: peer disabled blocking - encoder cannot block decoder");
    }

  return QPACK_CONFIG_OK;
}

const SocketQPACK_Settings *
SocketQPACK_config_encoder_settings (const SocketQPACK_Config_T config)
{
  if (config == NULL)
    return NULL;

  /* If using 0-RTT and handshake not complete, use previous settings */
  if (config->using_0rtt && config->previous != NULL)
    return config->previous;

  /* Encoder uses peer's settings (what the decoder can handle) */
  if (!config->peer_received)
    {
      SOCKET_LOG_DEBUG_MSG (
          "SocketQPACK: encoder settings requested but peer not received");
      return NULL;
    }

  return &config->peer;
}

const SocketQPACK_Settings *
SocketQPACK_config_decoder_settings (const SocketQPACK_Config_T config)
{
  if (config == NULL)
    return NULL;

  /* Decoder uses local settings (what we advertised) */
  return &config->local;
}

int
SocketQPACK_config_is_ready (const SocketQPACK_Config_T config)
{
  if (config == NULL)
    return 0;

  /* Ready when peer settings received and validated */
  return config->validated && config->peer_received;
}

/* ============================================================================
 * 0-RTT Support (RFC 9204 Section 3.2.3)
 * ============================================================================
 */

SocketQPACK_ConfigResult
SocketQPACK_config_set_0rtt (SocketQPACK_Config_T config,
                              const SocketQPACK_Settings *previous,
                              Arena_T arena)
{
  SocketQPACK_ConfigResult result;

  if (config == NULL || previous == NULL || arena == NULL)
    {
      SOCKET_LOG_DEBUG_MSG ("SocketQPACK_config_set_0rtt: NULL parameter");
      return QPACK_CONFIG_ERROR_NULL_PARAM;
    }

  /* Validate previous settings */
  result = SocketQPACK_settings_validate (previous);
  if (result != QPACK_CONFIG_OK)
    {
      SOCKET_LOG_WARN_MSG ("SocketQPACK: invalid 0-RTT settings: %s",
                           SocketQPACK_config_result_string (result));
      return result;
    }

  /* Allocate and copy previous settings */
  config->previous = ALLOC (arena, sizeof (*config->previous));
  if (config->previous == NULL)
    {
      SOCKET_LOG_ERROR_MSG (
          "SocketQPACK: failed to allocate 0-RTT settings");
      return QPACK_CONFIG_ERROR_ALLOC;
    }

  config->previous->max_table_capacity = previous->max_table_capacity;
  config->previous->blocked_streams = previous->blocked_streams;
  config->using_0rtt = 1;

  SOCKET_LOG_DEBUG_MSG (
      "SocketQPACK: set 0-RTT settings (capacity=%zu, blocked=%zu)",
      previous->max_table_capacity,
      previous->blocked_streams);

  return QPACK_CONFIG_OK;
}

SocketQPACK_ConfigResult
SocketQPACK_config_complete_0rtt (SocketQPACK_Config_T config)
{
  if (config == NULL)
    {
      SOCKET_LOG_DEBUG_MSG ("SocketQPACK_config_complete_0rtt: NULL config");
      return QPACK_CONFIG_ERROR_NULL_PARAM;
    }

  if (!config->using_0rtt)
    {
      SOCKET_LOG_DEBUG_MSG ("SocketQPACK: complete_0rtt called but not using "
                            "0-RTT - no action needed");
      return QPACK_CONFIG_OK;
    }

  if (!config->peer_received)
    {
      SOCKET_LOG_WARN_MSG (
          "SocketQPACK: complete_0rtt called but peer settings not received");
      return QPACK_CONFIG_ERROR_NOT_READY;
    }

  /* Switch from 0-RTT to negotiated settings */
  config->using_0rtt = 0;

  SOCKET_LOG_DEBUG_MSG (
      "SocketQPACK: completed 0-RTT, now using negotiated settings "
      "(capacity=%zu, blocked=%zu)",
      config->peer.max_table_capacity,
      config->peer.blocked_streams);

  return QPACK_CONFIG_OK;
}

int
SocketQPACK_config_is_0rtt (const SocketQPACK_Config_T config)
{
  if (config == NULL)
    return 0;

  return config->using_0rtt;
}
