/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTP3-stream.c
 * @brief HTTP/3 stream mapping implementation (RFC 9114 Section 6).
 */

#include "http/SocketHTTP3-stream.h"
#include "http/SocketHTTP3-constants.h"
#include "quic/SocketQUICStream.h"

#include <string.h>

#define H3_PUSH_STREAMS_INITIAL_CAP 8
#define H3_MAX_PUSH_STREAMS 256

struct SocketHTTP3_StreamMap
{
  Arena_T arena;

  /* Peer-initiated critical streams (exactly 1 each, or -1) */
  int64_t peer_control_id;
  int64_t peer_qpack_encoder_id;
  int64_t peer_qpack_decoder_id;

  /* Locally-opened critical streams (set by connection layer) */
  int64_t local_control_id;
  int64_t local_qpack_encoder_id;
  int64_t local_qpack_decoder_id;

  /* Push streams (server-initiated unidi type 0x01) */
  uint64_t *push_ids;
  size_t push_count;
  size_t push_capacity;
};

SocketHTTP3_StreamMap_T
SocketHTTP3_StreamMap_new (Arena_T arena)
{
  if (arena == NULL)
    return NULL;

  SocketHTTP3_StreamMap_T map
      = CALLOC (arena, 1, sizeof (struct SocketHTTP3_StreamMap));
  map->arena = arena;

  map->peer_control_id = H3_STREAM_ID_NONE;
  map->peer_qpack_encoder_id = H3_STREAM_ID_NONE;
  map->peer_qpack_decoder_id = H3_STREAM_ID_NONE;

  map->local_control_id = H3_STREAM_ID_NONE;
  map->local_qpack_encoder_id = H3_STREAM_ID_NONE;
  map->local_qpack_decoder_id = H3_STREAM_ID_NONE;

  map->push_ids
      = CALLOC (arena, H3_PUSH_STREAMS_INITIAL_CAP, sizeof (uint64_t));
  map->push_count = 0;
  map->push_capacity = H3_PUSH_STREAMS_INITIAL_CAP;

  return map;
}

/**
 * @brief Grow the push stream array by doubling capacity.
 */
static int
push_array_grow (SocketHTTP3_StreamMap_T map)
{
  size_t new_cap = map->push_capacity * 2;
  if (new_cap > H3_MAX_PUSH_STREAMS)
    new_cap = H3_MAX_PUSH_STREAMS;

  if (new_cap <= map->push_capacity)
    return -1;

  uint64_t *new_ids = CALLOC (map->arena, new_cap, sizeof (uint64_t));
  memcpy (new_ids, map->push_ids, map->push_count * sizeof (uint64_t));
  map->push_ids = new_ids;
  map->push_capacity = new_cap;
  return 0;
}

uint64_t
SocketHTTP3_StreamMap_register (SocketHTTP3_StreamMap_T map,
                                uint64_t stream_id,
                                uint64_t stream_type)
{
  if (map == NULL)
    return H3_STREAM_CREATION_ERROR;

  /* Only unidirectional streams carry a type byte */
  if (SocketQUICStream_is_bidirectional (stream_id))
    return H3_STREAM_CREATION_ERROR;

  /* GREASE stream types: silently ignore */
  if (H3_IS_GREASE (stream_type))
    return 0;

  switch (stream_type)
    {
    case H3_STREAM_TYPE_CONTROL:
      if (map->peer_control_id != H3_STREAM_ID_NONE)
        return H3_STREAM_CREATION_ERROR;
      map->peer_control_id = (int64_t)stream_id;
      return 0;

    case H3_STREAM_TYPE_QPACK_ENCODER:
      if (map->peer_qpack_encoder_id != H3_STREAM_ID_NONE)
        return H3_STREAM_CREATION_ERROR;
      map->peer_qpack_encoder_id = (int64_t)stream_id;
      return 0;

    case H3_STREAM_TYPE_QPACK_DECODER:
      if (map->peer_qpack_decoder_id != H3_STREAM_ID_NONE)
        return H3_STREAM_CREATION_ERROR;
      map->peer_qpack_decoder_id = (int64_t)stream_id;
      return 0;

    case H3_STREAM_TYPE_PUSH:
      /* Push streams must be server-initiated */
      if (SocketQUICStream_is_client_initiated (stream_id))
        return H3_STREAM_CREATION_ERROR;

      if (map->push_count >= map->push_capacity)
        {
          if (push_array_grow (map) < 0)
            return H3_STREAM_CREATION_ERROR;
        }
      map->push_ids[map->push_count++] = stream_id;
      return 0;

    default:
      /* Unknown non-GREASE type: RFC §6.2.3 requires ignore */
      return 0;
    }
}

SocketHTTP3_StreamRole
SocketHTTP3_StreamMap_role (SocketHTTP3_StreamMap_T map, uint64_t stream_id)
{
  if (map == NULL)
    return H3_STREAM_ROLE_UNKNOWN;

  /* Bidirectional streams are always request streams */
  if (SocketQUICStream_is_bidirectional (stream_id))
    return H3_STREAM_ROLE_REQUEST;

  /* Check peer critical streams */
  if (map->peer_control_id != H3_STREAM_ID_NONE
      && (uint64_t)map->peer_control_id == stream_id)
    return H3_STREAM_ROLE_CONTROL;

  if (map->peer_qpack_encoder_id != H3_STREAM_ID_NONE
      && (uint64_t)map->peer_qpack_encoder_id == stream_id)
    return H3_STREAM_ROLE_QPACK_ENCODER;

  if (map->peer_qpack_decoder_id != H3_STREAM_ID_NONE
      && (uint64_t)map->peer_qpack_decoder_id == stream_id)
    return H3_STREAM_ROLE_QPACK_DECODER;

  /* Check local critical streams */
  if (map->local_control_id != H3_STREAM_ID_NONE
      && (uint64_t)map->local_control_id == stream_id)
    return H3_STREAM_ROLE_CONTROL;

  if (map->local_qpack_encoder_id != H3_STREAM_ID_NONE
      && (uint64_t)map->local_qpack_encoder_id == stream_id)
    return H3_STREAM_ROLE_QPACK_ENCODER;

  if (map->local_qpack_decoder_id != H3_STREAM_ID_NONE
      && (uint64_t)map->local_qpack_decoder_id == stream_id)
    return H3_STREAM_ROLE_QPACK_DECODER;

  /* Check push streams */
  for (size_t i = 0; i < map->push_count; i++)
    {
      if (map->push_ids[i] == stream_id)
        return H3_STREAM_ROLE_PUSH;
    }

  return H3_STREAM_ROLE_UNKNOWN;
}

int
SocketHTTP3_StreamMap_critical_streams_ready (SocketHTTP3_StreamMap_T map)
{
  if (map == NULL)
    return 0;

  return map->peer_control_id != H3_STREAM_ID_NONE
         && map->peer_qpack_encoder_id != H3_STREAM_ID_NONE
         && map->peer_qpack_decoder_id != H3_STREAM_ID_NONE;
}

int64_t
SocketHTTP3_StreamMap_get_control (SocketHTTP3_StreamMap_T map)
{
  if (map == NULL)
    return H3_STREAM_ID_NONE;
  return map->peer_control_id;
}

int64_t
SocketHTTP3_StreamMap_get_qpack_encoder (SocketHTTP3_StreamMap_T map)
{
  if (map == NULL)
    return H3_STREAM_ID_NONE;
  return map->peer_qpack_encoder_id;
}

int64_t
SocketHTTP3_StreamMap_get_qpack_decoder (SocketHTTP3_StreamMap_T map)
{
  if (map == NULL)
    return H3_STREAM_ID_NONE;
  return map->peer_qpack_decoder_id;
}

void
SocketHTTP3_StreamMap_set_local_control (SocketHTTP3_StreamMap_T map,
                                         uint64_t id)
{
  if (map != NULL)
    map->local_control_id = (int64_t)id;
}

void
SocketHTTP3_StreamMap_set_local_qpack_encoder (SocketHTTP3_StreamMap_T map,
                                               uint64_t id)
{
  if (map != NULL)
    map->local_qpack_encoder_id = (int64_t)id;
}

void
SocketHTTP3_StreamMap_set_local_qpack_decoder (SocketHTTP3_StreamMap_T map,
                                               uint64_t id)
{
  if (map != NULL)
    map->local_qpack_decoder_id = (int64_t)id;
}

const char *
SocketHTTP3_StreamRole_name (SocketHTTP3_StreamRole role)
{
  switch (role)
    {
    case H3_STREAM_ROLE_REQUEST:
      return "REQUEST";
    case H3_STREAM_ROLE_CONTROL:
      return "CONTROL";
    case H3_STREAM_ROLE_PUSH:
      return "PUSH";
    case H3_STREAM_ROLE_QPACK_ENCODER:
      return "QPACK_ENCODER";
    case H3_STREAM_ROLE_QPACK_DECODER:
      return "QPACK_DECODER";
    case H3_STREAM_ROLE_UNKNOWN:
      return "UNKNOWN";
    default:
      return "UNKNOWN";
    }
}
