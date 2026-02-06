/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTP3-constants.h
 * @brief HTTP/3 constants: frame types, error codes, settings, stream types
 *        (RFC 9114).
 *
 * This header defines the protocol constants needed for HTTP/3 framing,
 * error reporting, settings negotiation, and unidirectional stream typing.
 * QUIC varint encoding applies to all wire values (62-bit space), but named
 * constants fit in standard C enums.
 */

#ifndef SOCKETHTTP3_CONSTANTS_INCLUDED
#define SOCKETHTTP3_CONSTANTS_INCLUDED

#include <stdint.h>

/* ============================================================================
 * FRAME TYPES (RFC 9114 Section 7.2)
 * ============================================================================
 */

/** HTTP/3 frame types (RFC 9114 Section 7.2) */
typedef enum
{
  HTTP3_FRAME_DATA = 0x00,         /**< §7.2.1 DATA */
  HTTP3_FRAME_HEADERS = 0x01,      /**< §7.2.2 HEADERS */
  HTTP3_FRAME_CANCEL_PUSH = 0x03,  /**< §7.2.3 CANCEL_PUSH */
  HTTP3_FRAME_SETTINGS = 0x04,     /**< §7.2.4 SETTINGS */
  HTTP3_FRAME_PUSH_PROMISE = 0x05, /**< §7.2.5 PUSH_PROMISE */
  HTTP3_FRAME_GOAWAY = 0x07,       /**< §7.2.6 GOAWAY */
  HTTP3_FRAME_MAX_PUSH_ID = 0x0d   /**< §7.2.7 MAX_PUSH_ID */
} SocketHTTP3_FrameType;

/* ============================================================================
 * RESERVED HTTP/2 FRAME TYPES (RFC 9114 Section 11.2.1)
 *
 * These HTTP/2 frame types MUST NOT appear on the wire in HTTP/3.
 * Receipt MUST be treated as H3_FRAME_UNEXPECTED.
 * ============================================================================
 */

#define HTTP3_H2_FRAME_PRIORITY 0x02 /**< HTTP/2 PRIORITY — reserved */
#define HTTP3_H2_FRAME_PING 0x06     /**< HTTP/2 PING — reserved */
#define HTTP3_H2_FRAME_WINDOW_UPDATE \
  0x08 /**< HTTP/2 WINDOW_UPDATE — reserved */
#define HTTP3_H2_FRAME_CONTINUATION 0x09 /**< HTTP/2 CONTINUATION — reserved \
                                          */

/**
 * @brief Check whether a frame type is a reserved HTTP/2 type.
 *
 * RFC 9114 §11.2.1: These frame types MUST NOT be sent in HTTP/3.
 */
#define HTTP3_IS_RESERVED_H2_FRAME(type)                              \
  ((type) == HTTP3_H2_FRAME_PRIORITY || (type) == HTTP3_H2_FRAME_PING \
   || (type) == HTTP3_H2_FRAME_WINDOW_UPDATE                          \
   || (type) == HTTP3_H2_FRAME_CONTINUATION)

/* ============================================================================
 * ERROR CODES (RFC 9114 Section 8.1)
 * ============================================================================
 */

/** HTTP/3 error codes (RFC 9114 Section 8.1) */
typedef enum
{
  H3_NO_ERROR = 0x0100,
  H3_GENERAL_PROTOCOL_ERROR = 0x0101,
  H3_INTERNAL_ERROR = 0x0102,
  H3_STREAM_CREATION_ERROR = 0x0103,
  H3_CLOSED_CRITICAL_STREAM = 0x0104,
  H3_FRAME_UNEXPECTED = 0x0105,
  H3_FRAME_ERROR = 0x0106,
  H3_EXCESSIVE_LOAD = 0x0107,
  H3_ID_ERROR = 0x0108,
  H3_SETTINGS_ERROR = 0x0109,
  H3_MISSING_SETTINGS = 0x010a,
  H3_REQUEST_REJECTED = 0x010b,
  H3_REQUEST_CANCELLED = 0x010c,
  H3_REQUEST_INCOMPLETE = 0x010d,
  H3_MESSAGE_ERROR = 0x010e,
  H3_CONNECT_ERROR = 0x010f,
  H3_VERSION_FALLBACK = 0x0110
} SocketHTTP3_ErrorCode;

/* ============================================================================
 * SETTINGS IDENTIFIERS (RFC 9114 Section 7.2.4.1)
 * ============================================================================
 */

/** HTTP/3 settings identifiers (RFC 9114 Section 7.2.4.1) */
typedef enum
{
  H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0x01,
  H3_SETTINGS_MAX_FIELD_SECTION_SIZE = 0x06,
  H3_SETTINGS_QPACK_BLOCKED_STREAMS = 0x07
} SocketHTTP3_SettingsId;

/* ============================================================================
 * RESERVED HTTP/2 SETTINGS (RFC 9114 Section 11.2.2)
 *
 * These HTTP/2 settings identifiers MUST NOT be sent in HTTP/3.
 * Receipt MUST be treated as H3_SETTINGS_ERROR.
 * ============================================================================
 */

#define HTTP3_H2_SETTINGS_HEADER_TABLE_SIZE                                   \
  0x01                                                /**< Overloaded — but \
                                                         H3 uses 0x01 for     \
                                                         QPACK_MAX_TABLE_CAPACITY */
#define HTTP3_H2_SETTINGS_ENABLE_PUSH 0x02            /**< Reserved */
#define HTTP3_H2_SETTINGS_MAX_CONCURRENT_STREAMS 0x03 /**< Reserved */
#define HTTP3_H2_SETTINGS_INITIAL_WINDOW_SIZE 0x04    /**< Reserved */
#define HTTP3_H2_SETTINGS_MAX_FRAME_SIZE 0x05         /**< Reserved */

/**
 * @brief Check whether a settings identifier is a reserved HTTP/2 setting.
 *
 * RFC 9114 §11.2.2: Identifiers 0x02, 0x03, 0x04, 0x05 MUST NOT be sent.
 * Note: 0x01 is reused by H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY and is valid.
 */
#define HTTP3_IS_RESERVED_H2_SETTING(id)               \
  ((id) == HTTP3_H2_SETTINGS_ENABLE_PUSH               \
   || (id) == HTTP3_H2_SETTINGS_MAX_CONCURRENT_STREAMS \
   || (id) == HTTP3_H2_SETTINGS_INITIAL_WINDOW_SIZE    \
   || (id) == HTTP3_H2_SETTINGS_MAX_FRAME_SIZE)

/* ============================================================================
 * UNIDIRECTIONAL STREAM TYPES (RFC 9114 Section 6.2)
 * ============================================================================
 */

/** HTTP/3 unidirectional stream types (RFC 9114 Section 6.2) */
typedef enum
{
  H3_STREAM_TYPE_CONTROL = 0x00,       /**< §6.2.1 Control stream */
  H3_STREAM_TYPE_PUSH = 0x01,          /**< §6.2.2 Push stream */
  H3_STREAM_TYPE_QPACK_ENCODER = 0x02, /**< §6.2.3 QPACK encoder */
  H3_STREAM_TYPE_QPACK_DECODER = 0x03  /**< §6.2.3 QPACK decoder */
} SocketHTTP3_StreamType;

/* ============================================================================
 * GREASE (RFC 9114 Section 7.2.8 / 6.2.3 / 8.1)
 * ============================================================================
 */

/**
 * @brief Check whether a value is a GREASE value.
 *
 * GREASE values follow the formula 0x1f * N + 0x21 for non-negative integer N.
 * Used to exercise extensibility for frame types (§7.2.8), stream types
 * (§6.2.3), and error codes (§8.1).
 */
#define H3_IS_GREASE(val) \
  (((uint64_t)(val) >= 0x21) && (((uint64_t)(val) - 0x21) % 0x1f == 0))

/* ============================================================================
 * NAME LOOKUP FUNCTIONS
 * ============================================================================
 */

/**
 * @brief Return human-readable name for an HTTP/3 frame type.
 * @param type  Frame type value.
 * @return Static string, or "UNKNOWN" for unrecognised types.
 */
const char *SocketHTTP3_frame_type_name (uint64_t type);

/**
 * @brief Return human-readable name for an HTTP/3 error code.
 * @param code  Error code value.
 * @return Static string, or "UNKNOWN" for unrecognised codes.
 */
const char *SocketHTTP3_error_code_name (uint64_t code);

/**
 * @brief Return human-readable name for an HTTP/3 stream type.
 * @param type  Stream type value.
 * @return Static string, or "UNKNOWN" for unrecognised types.
 */
const char *SocketHTTP3_stream_type_name (uint64_t type);

/**
 * @brief Return human-readable name for an HTTP/3 settings identifier.
 * @param id  Settings identifier value.
 * @return Static string, or "UNKNOWN" for unrecognised identifiers.
 */
const char *SocketHTTP3_settings_name (uint64_t id);

#endif /* SOCKETHTTP3_CONSTANTS_INCLUDED */
