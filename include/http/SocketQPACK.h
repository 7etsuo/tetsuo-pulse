/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK.h
 * @brief QPACK header compression configuration for HTTP/3 (RFC 9204).
 *
 * Implements RFC 9204 Section 5 - Configuration. QPACK is the header
 * compression format used by HTTP/3, evolved from HPACK (RFC 7541) to work
 * with QUIC's out-of-order delivery.
 *
 * Configuration Settings (RFC 9204 Section 5):
 *   - SETTINGS_QPACK_MAX_TABLE_CAPACITY (0x01): Maximum dynamic table size
 *   - SETTINGS_QPACK_BLOCKED_STREAMS (0x07): Maximum blocked streams
 *
 * Both settings default to 0 per RFC 9204:
 *   - 0 capacity means no dynamic table entries allowed
 *   - 0 blocked streams means decoder cannot block waiting for table updates
 *
 * Thread Safety: Configuration instances are NOT thread-safe. One instance
 * per connection/thread recommended. Static functions are thread-safe.
 *
 * @defgroup qpack QPACK Header Compression Module
 * @{
 * @see https://www.rfc-editor.org/rfc/rfc9204
 */

#ifndef SOCKETQPACK_INCLUDED
#define SOCKETQPACK_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include "core/Arena.h"
#include "core/Except.h"

/* ============================================================================
 * QPACK SETTINGS IDENTIFIERS (RFC 9204 Section 5)
 * ============================================================================
 */

/**
 * @brief SETTINGS_QPACK_MAX_TABLE_CAPACITY identifier (0x01).
 *
 * RFC 9204 Section 5: "An integer with a maximum value of 2^30 - 1.
 * The default value is zero."
 *
 * This setting specifies the maximum size (in bytes) of the dynamic table
 * that the encoder can use. The decoder MUST NOT allocate more than this
 * amount of memory for the dynamic table.
 */
#define SETTINGS_QPACK_MAX_TABLE_CAPACITY 0x01

/**
 * @brief SETTINGS_QPACK_BLOCKED_STREAMS identifier (0x07).
 *
 * RFC 9204 Section 5: "An integer with a maximum value of 2^16 - 1.
 * The default value is zero."
 *
 * This setting specifies the maximum number of streams that can be blocked
 * waiting for dynamic table entries. If the decoder has this many streams
 * blocked, it MUST NOT reference any new dynamic table entries.
 */
#define SETTINGS_QPACK_BLOCKED_STREAMS 0x07

/* ============================================================================
 * QPACK LIMITS (RFC 9204 Section 5)
 * ============================================================================
 */

/**
 * @brief Maximum value for SETTINGS_QPACK_MAX_TABLE_CAPACITY.
 *
 * RFC 9204 Section 5: "An integer with a maximum value of 2^30 - 1."
 */
#define QPACK_MAX_TABLE_CAPACITY_LIMIT ((size_t)(1U << 30) - 1)

/**
 * @brief Maximum value for SETTINGS_QPACK_BLOCKED_STREAMS.
 *
 * RFC 9204 Section 5: "An integer with a maximum value of 2^16 - 1."
 */
#define QPACK_MAX_BLOCKED_STREAMS_LIMIT ((size_t)(1U << 16) - 1)

/**
 * @brief Warning threshold for table capacity (100 MB).
 *
 * Settings exceeding this value trigger a log warning but are still valid.
 */
#define QPACK_CAPACITY_WARNING_THRESHOLD (100 * 1024 * 1024)

/* ============================================================================
 * QPACK RESULT CODES
 * ============================================================================
 */

/**
 * @brief QPACK configuration operation result codes.
 *
 * These codes indicate the success or failure of configuration operations.
 */
typedef enum
{
  /** Operation completed successfully. */
  QPACK_CONFIG_OK = 0,

  /** Settings validation failed - value exceeds protocol limit. */
  QPACK_CONFIG_ERROR_INVALID_VALUE,

  /** Null parameter passed to function. */
  QPACK_CONFIG_ERROR_NULL_PARAM,

  /** Configuration already applied - cannot modify. */
  QPACK_CONFIG_ERROR_ALREADY_APPLIED,

  /** Memory allocation failed. */
  QPACK_CONFIG_ERROR_ALLOC,

  /** Configuration is not yet ready (waiting for peer settings). */
  QPACK_CONFIG_ERROR_NOT_READY

} SocketQPACK_ConfigResult;

/* ============================================================================
 * QPACK SETTINGS STRUCTURE (RFC 9204 Section 5)
 * ============================================================================
 */

/**
 * @brief QPACK settings from HTTP/3 SETTINGS frame.
 *
 * Represents the QPACK-specific settings exchanged between peers during
 * HTTP/3 connection establishment. Both values default to 0 per RFC 9204.
 *
 * When max_table_capacity is 0:
 *   - Encoder MUST NOT insert entries into dynamic table
 *   - Encoder MUST use literal encoding for all headers
 *
 * When blocked_streams is 0:
 *   - Decoder MUST NOT block waiting for dynamic table entries
 *   - Encoder MUST NOT reference entries the decoder doesn't have
 */
typedef struct
{
  /**
   * Maximum dynamic table capacity in bytes.
   * RFC 9204 Section 5: "The default value is zero."
   * Maximum: 2^30 - 1 (QPACK_MAX_TABLE_CAPACITY_LIMIT)
   */
  size_t max_table_capacity;

  /**
   * Maximum number of blocked streams.
   * RFC 9204 Section 5: "The default value is zero."
   * Maximum: 2^16 - 1 (QPACK_MAX_BLOCKED_STREAMS_LIMIT)
   */
  size_t blocked_streams;

} SocketQPACK_Settings;

/* ============================================================================
 * QPACK CONFIGURATION STRUCTURE
 * ============================================================================
 */

/**
 * @brief QPACK connection configuration.
 *
 * Tracks both local and peer settings for a QPACK connection. The effective
 * configuration depends on both sides:
 *
 *   - Encoder uses peer's settings to know what the decoder can handle
 *   - Decoder uses local settings to allocate resources
 *
 * For 0-RTT (RFC 9204 Section 3.2.3):
 *   - Encoder uses previous connection's settings for early data
 *   - After handshake, switches to newly negotiated settings
 */
struct SocketQPACK_Config
{
  /** Our settings (sent to peer). */
  SocketQPACK_Settings local;

  /** Peer's settings (received from peer). */
  SocketQPACK_Settings peer;

  /** Previous settings for 0-RTT resumption (NULL if not resuming). */
  SocketQPACK_Settings *previous;

  /** Settings have been validated and applied. */
  int validated;

  /** Peer settings have been received. */
  int peer_received;

  /** Currently using 0-RTT settings. */
  int using_0rtt;
};

/** Opaque type for QPACK configuration. */
typedef struct SocketQPACK_Config *SocketQPACK_Config_T;

/* ============================================================================
 * EXCEPTION TYPE
 * ============================================================================
 */

/**
 * @brief Exception raised on QPACK configuration errors.
 *
 * This exception is raised when QPACK configuration operations encounter
 * fatal errors that cannot be recovered.
 */
extern const Except_T SocketQPACK_ConfigError;

/* ============================================================================
 * SETTINGS FUNCTIONS (RFC 9204 Section 5)
 * ============================================================================
 */

/**
 * @brief Initialize settings to RFC 9204 defaults.
 *
 * Sets both max_table_capacity and blocked_streams to 0 per RFC 9204 Section 5:
 * "The default value is zero."
 *
 * @param settings Settings structure to initialize (must not be NULL).
 * @return QPACK_CONFIG_OK on success, QPACK_CONFIG_ERROR_NULL_PARAM if NULL.
 *
 * @note Thread-safe: Does not access global state.
 */
extern SocketQPACK_ConfigResult
SocketQPACK_settings_defaults (SocketQPACK_Settings *settings);

/**
 * @brief Validate settings against RFC 9204 limits.
 *
 * Checks that:
 *   - max_table_capacity <= 2^30 - 1 (QPACK_MAX_TABLE_CAPACITY_LIMIT)
 *   - blocked_streams <= 2^16 - 1 (QPACK_MAX_BLOCKED_STREAMS_LIMIT)
 *
 * Values exceeding QPACK_CAPACITY_WARNING_THRESHOLD trigger a log warning
 * but are still considered valid if within protocol limits.
 *
 * @param settings Settings to validate (must not be NULL).
 * @return QPACK_CONFIG_OK if valid, error code otherwise.
 *
 * @note Thread-safe: Does not modify settings.
 */
extern SocketQPACK_ConfigResult
SocketQPACK_settings_validate (const SocketQPACK_Settings *settings);

/**
 * @brief Check if settings enable dynamic table usage.
 *
 * RFC 9204 Section 5: When max_table_capacity is 0, the dynamic table
 * cannot be used and all headers must be encoded as literals.
 *
 * @param settings Settings to check (must not be NULL).
 * @return Non-zero if dynamic table is enabled, 0 if disabled or NULL.
 */
extern int
SocketQPACK_settings_has_dynamic_table (const SocketQPACK_Settings *settings);

/**
 * @brief Check if settings allow blocking.
 *
 * RFC 9204 Section 5: When blocked_streams is 0, the decoder cannot block
 * waiting for dynamic table entries.
 *
 * @param settings Settings to check (must not be NULL).
 * @return Non-zero if blocking is allowed, 0 if not or NULL.
 */
extern int
SocketQPACK_settings_allows_blocking (const SocketQPACK_Settings *settings);

/* ============================================================================
 * CONFIGURATION FUNCTIONS
 * ============================================================================
 */

/**
 * @brief Create new QPACK configuration with defaults.
 *
 * Allocates a new configuration with both local and peer settings
 * initialized to RFC 9204 defaults (0, 0).
 *
 * @param arena Memory arena for allocations.
 * @return New configuration, or NULL on allocation failure.
 *
 * @throws SocketQPACK_ConfigError on allocation failure.
 */
extern SocketQPACK_Config_T SocketQPACK_config_new (Arena_T arena);

/**
 * @brief Set local settings (to be sent to peer).
 *
 * The local settings are advertised to the peer in the HTTP/3 SETTINGS frame.
 * They specify our capabilities (how much memory we can allocate for the
 * dynamic table, how many blocked streams we allow).
 *
 * @param config Configuration to modify.
 * @param settings Settings to copy as local settings.
 * @return QPACK_CONFIG_OK on success, error code on failure.
 */
extern SocketQPACK_ConfigResult
SocketQPACK_config_set_local (SocketQPACK_Config_T config,
                               const SocketQPACK_Settings *settings);

/**
 * @brief Apply peer settings (received from peer).
 *
 * Called when we receive the peer's SETTINGS frame containing
 * SETTINGS_QPACK_MAX_TABLE_CAPACITY and SETTINGS_QPACK_BLOCKED_STREAMS.
 *
 * RFC 9204 Section 5.2: "QPACK implementations MUST handle SETTINGS
 * received after the first SETTINGS frame."
 *
 * @param config Configuration to modify.
 * @param settings Peer's settings from SETTINGS frame.
 * @return QPACK_CONFIG_OK on success, error code on failure.
 */
extern SocketQPACK_ConfigResult
SocketQPACK_config_apply_peer (SocketQPACK_Config_T config,
                                const SocketQPACK_Settings *settings);

/**
 * @brief Get effective encoder settings.
 *
 * Returns the settings the encoder should use. The encoder is constrained
 * by the peer's advertised settings (what the decoder can handle).
 *
 * @param config Configuration to query.
 * @return Pointer to peer settings, or NULL if peer settings not received.
 */
extern const SocketQPACK_Settings *
SocketQPACK_config_encoder_settings (const SocketQPACK_Config_T config);

/**
 * @brief Get effective decoder settings.
 *
 * Returns the settings the decoder should use. The decoder uses local
 * settings (what we advertised we can handle).
 *
 * @param config Configuration to query.
 * @return Pointer to local settings, or NULL if config is NULL.
 */
extern const SocketQPACK_Settings *
SocketQPACK_config_decoder_settings (const SocketQPACK_Config_T config);

/**
 * @brief Check if configuration is ready for use.
 *
 * Returns true when both local settings are configured and peer settings
 * have been received and validated.
 *
 * @param config Configuration to check.
 * @return Non-zero if ready, 0 if not ready or NULL.
 */
extern int SocketQPACK_config_is_ready (const SocketQPACK_Config_T config);

/* ============================================================================
 * 0-RTT SUPPORT (RFC 9204 Section 3.2.3)
 * ============================================================================
 */

/**
 * @brief Set previous settings for 0-RTT resumption.
 *
 * RFC 9204 Section 3.2.3: "When 0-RTT is used, the encoder and decoder
 * MUST use the settings from the previous connection."
 *
 * Call this before encoding early data to restore the previous connection's
 * settings. The encoder will use these settings until the handshake completes
 * and new settings are negotiated.
 *
 * @param config Configuration to modify.
 * @param previous Previous connection's settings.
 * @param arena Arena for allocating copy of settings.
 * @return QPACK_CONFIG_OK on success, error code on failure.
 */
extern SocketQPACK_ConfigResult
SocketQPACK_config_set_0rtt (SocketQPACK_Config_T config,
                              const SocketQPACK_Settings *previous,
                              Arena_T arena);

/**
 * @brief Switch from 0-RTT settings to negotiated settings.
 *
 * Called after the TLS handshake completes to transition from using
 * the previous connection's settings to the newly negotiated settings.
 *
 * @param config Configuration to modify.
 * @return QPACK_CONFIG_OK on success, error code on failure.
 */
extern SocketQPACK_ConfigResult
SocketQPACK_config_complete_0rtt (SocketQPACK_Config_T config);

/**
 * @brief Check if using 0-RTT settings.
 *
 * @param config Configuration to check.
 * @return Non-zero if using 0-RTT settings, 0 otherwise.
 */
extern int SocketQPACK_config_is_0rtt (const SocketQPACK_Config_T config);

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================
 */

/**
 * @brief Get human-readable string for configuration result code.
 *
 * @param result Result code to describe.
 * @return Static string describing the result (never NULL).
 *
 * @note Thread-safe: Returns pointer to static read-only string.
 */
extern const char *
SocketQPACK_config_result_string (SocketQPACK_ConfigResult result);

/** @} */

#endif /* SOCKETQPACK_INCLUDED */
