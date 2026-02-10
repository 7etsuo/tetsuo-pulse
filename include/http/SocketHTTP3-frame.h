/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTP3-frame.h
 * @brief HTTP/3 frame parser/serializer (RFC 9114 Section 7).
 *
 * Provides parsing and serialization for all HTTP/3 frame types:
 *   - DATA (0x00), HEADERS (0x01): header-only parse (payload is opaque)
 *   - CANCEL_PUSH (0x03): single push ID varint
 *   - SETTINGS (0x04): key-value varint pairs with duplicate detection
 *   - PUSH_PROMISE (0x05): push ID + encoded field section
 *   - GOAWAY (0x07): stream/push ID varint
 *   - MAX_PUSH_ID (0x0D): push ID varint
 *
 * Frame validation checks stream context (control/request/push) per RFC 9114.
 *
 * Wire format: Type(varint) + Length(varint) + Payload[Length]
 */

#ifndef SOCKETHTTP3_FRAME_INCLUDED
#define SOCKETHTTP3_FRAME_INCLUDED

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Parse result codes for frame header parsing.
 */
typedef enum
{
  HTTP3_PARSE_OK = 0,     /**< Parse succeeded */
  HTTP3_PARSE_INCOMPLETE, /**< Need more data */
  HTTP3_PARSE_ERROR       /**< Protocol violation */
} SocketHTTP3_ParseResult;

/**
 * @brief Logical stream context for frame validation.
 *
 * Distinct from SocketHTTP3_StreamType (wire-level unidirectional stream type
 * bytes). This classifies the logical stream for frame-level validation per
 * RFC 9114 Section 7.2.
 */
typedef enum
{
  HTTP3_STREAM_CONTROL, /**< Control stream */
  HTTP3_STREAM_REQUEST, /**< Request stream (bidirectional) */
  HTTP3_STREAM_PUSH     /**< Push stream (server-initiated) */
} SocketHTTP3_StreamContext;

/**
 * @brief Decoded frame header (type + length).
 *
 * On the wire, both fields are QUIC variable-length integers.
 */
typedef struct
{
  uint64_t type;   /**< Frame type */
  uint64_t length; /**< Payload length in bytes */
} SocketHTTP3_FrameHeader;

/**
 * @brief HTTP/3 SETTINGS parameters (RFC 9114 Section 7.2.4).
 */
typedef struct
{
  uint64_t max_field_section_size;   /**< 0x06, default: UINT64_MAX */
  uint64_t qpack_max_table_capacity; /**< 0x01, default: 0 */
  uint64_t qpack_blocked_streams;    /**< 0x07, default: 0 */
} SocketHTTP3_Settings;

/** Max buffer size for Settings_write output (3 settings * (8+8) varint pairs)
 */
#define HTTP3_SETTINGS_MAX_WRITE_SIZE 48

/* ============================================================================
 * Frame Header Parse/Write
 * ============================================================================
 */

/**
 * @brief Parse a frame header from buffer.
 *
 * Decodes two sequential QUIC varints (type + length). DATA and HEADERS
 * frames have no dedicated parse functions -- the caller reads header.length
 * bytes of opaque payload after parsing the header.
 *
 * @param buf       Input buffer.
 * @param buflen    Input buffer length.
 * @param header    Output: decoded frame header.
 * @param consumed  Output: bytes consumed from input.
 * @return HTTP3_PARSE_OK on success, HTTP3_PARSE_INCOMPLETE if buffer too
 * short.
 */
SocketHTTP3_ParseResult
SocketHTTP3_Frame_parse_header (const uint8_t *buf,
                                size_t buflen,
                                SocketHTTP3_FrameHeader *header,
                                size_t *consumed);

/**
 * @brief Write a frame header to buffer.
 *
 * @param type    Frame type.
 * @param length  Payload length.
 * @param buf     Output buffer.
 * @param buflen  Output buffer size.
 * @return Bytes written on success, -1 if buffer too small or value overflow.
 */
int SocketHTTP3_Frame_write_header (uint64_t type,
                                    uint64_t length,
                                    uint8_t *buf,
                                    size_t buflen);

/* ============================================================================
 * SETTINGS (RFC 9114 Section 7.2.4)
 * ============================================================================
 */

/**
 * @brief Initialize settings to RFC defaults.
 *
 * max_field_section_size = UINT64_MAX, qpack_max_table_capacity = 0,
 * qpack_blocked_streams = 0.
 */
void SocketHTTP3_Settings_init (SocketHTTP3_Settings *settings);

/**
 * @brief Parse SETTINGS payload.
 *
 * Processes varint pairs (id, value). Rejects reserved HTTP/2 settings
 * (0x02-0x05), detects duplicate identifiers (all IDs, not just known),
 * and silently ignores GREASE and unknown identifiers.
 *
 * @param buf       SETTINGS payload (after frame header).
 * @param len       Payload length.
 * @param settings  Output: parsed settings (must be pre-initialized).
 * @return 0 on success, 1 if incomplete, negative H3 error code on violation.
 */
int SocketHTTP3_Settings_parse (const uint8_t *buf,
                                size_t len,
                                SocketHTTP3_Settings *settings);

/**
 * @brief Write SETTINGS payload.
 *
 * Only writes non-default settings to minimize wire size.
 *
 * @param settings  Settings to serialize.
 * @param buf       Output buffer.
 * @param buflen    Output buffer size.
 * @return Bytes written on success, -1 on error.
 */
int SocketHTTP3_Settings_write (const SocketHTTP3_Settings *settings,
                                uint8_t *buf,
                                size_t buflen);

/* ============================================================================
 * Single-Varint Payload Frames
 * ============================================================================
 */

/**
 * @brief Parse GOAWAY payload (RFC 9114 Section 7.2.6).
 * @return 0 on success, 1 if incomplete, -1 on error.
 */
int SocketHTTP3_Goaway_parse (const uint8_t *buf, size_t len, uint64_t *id);

/**
 * @brief Write GOAWAY payload.
 * @return Bytes written on success, -1 on error.
 */
int SocketHTTP3_Goaway_write (uint64_t id, uint8_t *buf, size_t buflen);

/**
 * @brief Parse MAX_PUSH_ID payload (RFC 9114 Section 7.2.7).
 * @return 0 on success, 1 if incomplete, -1 on error.
 */
int SocketHTTP3_MaxPushId_parse (const uint8_t *buf, size_t len, uint64_t *id);

/**
 * @brief Write MAX_PUSH_ID payload.
 * @return Bytes written on success, -1 on error.
 */
int SocketHTTP3_MaxPushId_write (uint64_t id, uint8_t *buf, size_t buflen);

/**
 * @brief Parse CANCEL_PUSH payload (RFC 9114 Section 7.2.3).
 * @return 0 on success, 1 if incomplete, -1 on error.
 */
int SocketHTTP3_CancelPush_parse (const uint8_t *buf,
                                  size_t len,
                                  uint64_t *push_id);

/**
 * @brief Write CANCEL_PUSH payload.
 * @return Bytes written on success, -1 on error.
 */
int
SocketHTTP3_CancelPush_write (uint64_t push_id, uint8_t *buf, size_t buflen);

/* ============================================================================
 * PUSH_PROMISE (RFC 9114 Section 7.2.5)
 * ============================================================================
 */

/**
 * @brief Extract push ID from PUSH_PROMISE payload.
 *
 * Decodes the push_id varint at the start of the payload and sets
 * payload_offset to the start of the encoded field section.
 *
 * @param buf             PUSH_PROMISE payload.
 * @param len             Payload length.
 * @param push_id         Output: decoded push ID.
 * @param payload_offset  Output: byte offset to encoded field section.
 * @return 0 on success, 1 if incomplete, -1 on error.
 */
int SocketHTTP3_PushPromise_parse_id (const uint8_t *buf,
                                      size_t len,
                                      uint64_t *push_id,
                                      size_t *payload_offset);

/* ============================================================================
 * Frame Validation
 * ============================================================================
 */

/**
 * @brief Validate a frame type on a given stream context.
 *
 * Checks whether the frame type is permitted on the stream type per
 * RFC 9114 Section 7.2. The is_first_frame flag is caller-managed state
 * for enforcing SETTINGS as the first frame on a control stream.
 *
 * @param frame_type    Frame type to validate.
 * @param stream_type   Logical stream context.
 * @param is_first_frame  1 if this is the first frame on a control stream.
 * @return 0 if allowed, H3 error code otherwise.
 */
uint64_t SocketHTTP3_Frame_validate (uint64_t frame_type,
                                     SocketHTTP3_StreamContext stream_type,
                                     int is_first_frame);

#endif /* SOCKETHTTP3_FRAME_INCLUDED */
