/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK-config.c
 * @brief QPACK Configuration (RFC 9204 Section 5)
 *
 * Implements QPACK settings management for HTTP/3 integration.
 * Handles local/peer settings negotiation and 0-RTT resumption.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9204#section-5
 */

#include "http/qpack/SocketQPACK.h"

#include <string.h>

/**
 * @brief QPACK configuration internal structure.
 */
struct SocketQPACK_Config
{
  Arena_T arena;                    /**< Memory arena for allocations */
  SocketQPACK_Settings local;       /**< Our settings (sent to peer) */
  SocketQPACK_Settings peer;        /**< Peer's settings (received) */
  SocketQPACK_Settings stored_0rtt; /**< Settings stored for 0-RTT resumption */
  bool peer_received;               /**< True if apply_peer has been called */
  bool has_0rtt;                    /**< True if 0-RTT settings stored */
};

SocketQPACK_Result
SocketQPACK_settings_defaults (SocketQPACK_Settings *settings)
{
  if (settings == NULL)
    return QPACK_ERR_NULL_PARAM;

  /* RFC 9204 Section 5: Both settings default to 0 */
  settings->max_table_capacity = 0;
  settings->blocked_streams = 0;

  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_settings_validate (const SocketQPACK_Settings *settings)
{
  if (settings == NULL)
    return QPACK_ERR_NULL_PARAM;

  /*
   * RFC 9204 Section 5 does not specify upper limits for these settings.
   * All uint64_t values are valid. The encoder/decoder will apply
   * internal limits when using these values.
   */

  return QPACK_OK;
}

SocketQPACK_Config_T
SocketQPACK_Config_new (Arena_T arena)
{
  SocketQPACK_Config_T config;

  if (arena == NULL)
    return NULL;

  config = ALLOC (arena, sizeof (*config));
  if (config == NULL)
    return NULL;

  config->arena = arena;

  /* Initialize local settings to RFC defaults */
  config->local.max_table_capacity = 0;
  config->local.blocked_streams = 0;

  /* Peer settings not yet received */
  config->peer.max_table_capacity = 0;
  config->peer.blocked_streams = 0;
  config->peer_received = false;

  /* No 0-RTT settings stored yet */
  config->stored_0rtt.max_table_capacity = 0;
  config->stored_0rtt.blocked_streams = 0;
  config->has_0rtt = false;

  return config;
}

SocketQPACK_Result
SocketQPACK_Config_set_local (SocketQPACK_Config_T config,
                              const SocketQPACK_Settings *settings)
{
  if (config == NULL || settings == NULL)
    return QPACK_ERR_NULL_PARAM;

  config->local = *settings;

  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_Config_get_local (SocketQPACK_Config_T config,
                              SocketQPACK_Settings *settings)
{
  if (config == NULL || settings == NULL)
    return QPACK_ERR_NULL_PARAM;

  *settings = config->local;

  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_Config_apply_peer (SocketQPACK_Config_T config,
                               const SocketQPACK_Settings *settings)
{
  SocketQPACK_Result result;

  if (config == NULL || settings == NULL)
    return QPACK_ERR_NULL_PARAM;

  /* Validate the settings first */
  result = SocketQPACK_settings_validate (settings);
  if (result != QPACK_OK)
    return result;

  config->peer = *settings;
  config->peer_received = true;

  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_Config_get_peer (SocketQPACK_Config_T config,
                             SocketQPACK_Settings *settings)
{
  if (config == NULL || settings == NULL)
    return QPACK_ERR_NULL_PARAM;

  if (!config->peer_received)
    return QPACK_ERR_INTERNAL;

  *settings = config->peer;

  return QPACK_OK;
}

bool
SocketQPACK_Config_has_peer_settings (SocketQPACK_Config_T config)
{
  if (config == NULL)
    return false;

  return config->peer_received;
}

SocketQPACK_Result
SocketQPACK_Config_store_for_0rtt (SocketQPACK_Config_T config,
                                   const SocketQPACK_Settings *settings)
{
  if (config == NULL || settings == NULL)
    return QPACK_ERR_NULL_PARAM;

  config->stored_0rtt = *settings;
  config->has_0rtt = true;

  return QPACK_OK;
}

bool
SocketQPACK_Config_has_0rtt_settings (SocketQPACK_Config_T config)
{
  if (config == NULL)
    return false;

  return config->has_0rtt;
}

SocketQPACK_Result
SocketQPACK_Config_get_0rtt (SocketQPACK_Config_T config,
                             SocketQPACK_Settings *settings)
{
  if (config == NULL || settings == NULL)
    return QPACK_ERR_NULL_PARAM;

  if (!config->has_0rtt)
    return QPACK_ERR_INTERNAL;

  *settings = config->stored_0rtt;

  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_Config_validate_0rtt (SocketQPACK_Config_T config,
                                  const SocketQPACK_Settings *peer_settings)
{
  if (config == NULL || peer_settings == NULL)
    return QPACK_ERR_NULL_PARAM;

  /* If no 0-RTT settings stored, nothing to validate */
  if (!config->has_0rtt)
    return QPACK_OK;

  /*
   * RFC 9204 Section 3.2.3:
   * "When client's 0-RTT setting is non-zero: the server MUST send the
   * same non-zero value in its SETTINGS frame."
   *
   * If stored max_table_capacity > 0 and peer sends a different value,
   * this is a connection error of type QPACK_DECODER_STREAM_ERROR.
   */
  if (config->stored_0rtt.max_table_capacity > 0)
    {
      if (peer_settings->max_table_capacity
          != config->stored_0rtt.max_table_capacity)
        {
          return QPACK_ERR_0RTT_MISMATCH;
        }
    }

  /*
   * Note: RFC 9204 Section 3.2.3 specifically mentions max_table_capacity.
   * For blocked_streams, the RFC is less explicit, so we only enforce
   * the max_table_capacity requirement.
   */

  return QPACK_OK;
}

const char *
SocketQPACK_settings_id_string (uint64_t setting_id)
{
  switch (setting_id)
    {
    case SETTINGS_QPACK_MAX_TABLE_CAPACITY:
      return "SETTINGS_QPACK_MAX_TABLE_CAPACITY";
    case SETTINGS_QPACK_BLOCKED_STREAMS:
      return "SETTINGS_QPACK_BLOCKED_STREAMS";
    default:
      return "UNKNOWN";
    }
}
