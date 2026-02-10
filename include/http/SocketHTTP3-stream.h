/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTP3-stream.h
 * @brief HTTP/3 stream mapping and classification (RFC 9114 Section 6).
 *
 * Maps QUIC stream IDs to HTTP/3 roles and manages unidirectional stream
 * registration. Enforces critical stream uniqueness: exactly one control
 * stream, one QPACK encoder stream, and one QPACK decoder stream per
 * connection direction.
 *
 * Bidirectional streams are classified as request streams via O(1) bitmask
 * check. Push streams are tracked in a dynamic array.
 */

#ifndef SOCKETHTTP3_STREAM_INCLUDED
#define SOCKETHTTP3_STREAM_INCLUDED

#include <stdint.h>

#include "core/Arena.h"

/**
 * @brief HTTP/3 stream roles.
 *
 * Classifies a QUIC stream by its HTTP/3 function.
 */
typedef enum
{
  H3_STREAM_ROLE_REQUEST,       /**< Bidirectional request stream */
  H3_STREAM_ROLE_CONTROL,       /**< Control stream (type 0x00) */
  H3_STREAM_ROLE_PUSH,          /**< Push stream (type 0x01) */
  H3_STREAM_ROLE_QPACK_ENCODER, /**< QPACK encoder stream (type 0x02) */
  H3_STREAM_ROLE_QPACK_DECODER, /**< QPACK decoder stream (type 0x03) */
  H3_STREAM_ROLE_UNKNOWN        /**< Unknown or unregistered unidi stream */
} SocketHTTP3_StreamRole;

/** Sentinel value indicating no stream ID assigned. */
#define H3_STREAM_ID_NONE ((int64_t) - 1)

/** Opaque stream map handle. */
typedef struct SocketHTTP3_StreamMap *SocketHTTP3_StreamMap_T;

/**
 * @brief Create a new stream map.
 *
 * All critical stream slots are initialized to H3_STREAM_ID_NONE.
 *
 * @param arena  Memory arena for allocations.
 * @return New stream map, or NULL if arena is NULL.
 */
SocketHTTP3_StreamMap_T SocketHTTP3_StreamMap_new (Arena_T arena);

/**
 * @brief Register a peer-initiated unidirectional stream.
 *
 * Called after reading the stream type byte from a peer-initiated
 * unidirectional stream. Validates stream ID directionality, enforces
 * critical stream uniqueness, and stores the mapping.
 *
 * @param map         Stream map.
 * @param stream_id   QUIC stream ID (must be unidirectional).
 * @param stream_type HTTP/3 stream type byte (0x00-0x03, GREASE, etc.).
 * @return 0 on success, H3 error code on violation.
 */
uint64_t SocketHTTP3_StreamMap_register (SocketHTTP3_StreamMap_T map,
                                         uint64_t stream_id,
                                         uint64_t stream_type);

/**
 * @brief Classify a stream by its HTTP/3 role.
 *
 * Bidirectional streams return H3_STREAM_ROLE_REQUEST (O(1) bitmask).
 * Registered unidirectional streams return their assigned role.
 * Unregistered unidirectional streams return H3_STREAM_ROLE_UNKNOWN.
 *
 * @param map        Stream map.
 * @param stream_id  QUIC stream ID.
 * @return Stream role.
 */
SocketHTTP3_StreamRole
SocketHTTP3_StreamMap_role (SocketHTTP3_StreamMap_T map, uint64_t stream_id);

/**
 * @brief Check if all three peer critical streams have been opened.
 *
 * @param map  Stream map.
 * @return 1 if control, QPACK encoder, and QPACK decoder are all registered.
 */
int SocketHTTP3_StreamMap_critical_streams_ready (SocketHTTP3_StreamMap_T map);

/**
 * @brief Get the peer control stream ID.
 * @return Stream ID, or H3_STREAM_ID_NONE if not yet opened.
 */
int64_t SocketHTTP3_StreamMap_get_control (SocketHTTP3_StreamMap_T map);

/**
 * @brief Get the peer QPACK encoder stream ID.
 * @return Stream ID, or H3_STREAM_ID_NONE if not yet opened.
 */
int64_t SocketHTTP3_StreamMap_get_qpack_encoder (SocketHTTP3_StreamMap_T map);

/**
 * @brief Get the peer QPACK decoder stream ID.
 * @return Stream ID, or H3_STREAM_ID_NONE if not yet opened.
 */
int64_t SocketHTTP3_StreamMap_get_qpack_decoder (SocketHTTP3_StreamMap_T map);

/**
 * @brief Set the locally-opened control stream ID.
 * @param map  Stream map.
 * @param id   Stream ID.
 */
void SocketHTTP3_StreamMap_set_local_control (SocketHTTP3_StreamMap_T map,
                                              uint64_t id);

/**
 * @brief Set the locally-opened QPACK encoder stream ID.
 * @param map  Stream map.
 * @param id   Stream ID.
 */
void SocketHTTP3_StreamMap_set_local_qpack_encoder (SocketHTTP3_StreamMap_T map,
                                                    uint64_t id);

/**
 * @brief Set the locally-opened QPACK decoder stream ID.
 * @param map  Stream map.
 * @param id   Stream ID.
 */
void SocketHTTP3_StreamMap_set_local_qpack_decoder (SocketHTTP3_StreamMap_T map,
                                                    uint64_t id);

/**
 * @brief Return human-readable name for a stream role.
 * @param role  Stream role.
 * @return Static string.
 */
const char *SocketHTTP3_StreamRole_name (SocketHTTP3_StreamRole role);

#endif /* SOCKETHTTP3_STREAM_INCLUDED */
