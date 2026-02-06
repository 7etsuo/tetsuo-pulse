/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTP3-constants.c
 * @brief Name-lookup functions for HTTP/3 constants (RFC 9114).
 */

#include "http/SocketHTTP3-constants.h"

const char *
SocketHTTP3_frame_type_name (uint64_t type)
{
  switch (type)
    {
    case HTTP3_FRAME_DATA:
      return "DATA";
    case HTTP3_FRAME_HEADERS:
      return "HEADERS";
    case HTTP3_FRAME_CANCEL_PUSH:
      return "CANCEL_PUSH";
    case HTTP3_FRAME_SETTINGS:
      return "SETTINGS";
    case HTTP3_FRAME_PUSH_PROMISE:
      return "PUSH_PROMISE";
    case HTTP3_FRAME_GOAWAY:
      return "GOAWAY";
    case HTTP3_FRAME_MAX_PUSH_ID:
      return "MAX_PUSH_ID";
    case HTTP3_H2_FRAME_PRIORITY:
      return "PRIORITY (reserved H2)";
    case HTTP3_H2_FRAME_PING:
      return "PING (reserved H2)";
    case HTTP3_H2_FRAME_WINDOW_UPDATE:
      return "WINDOW_UPDATE (reserved H2)";
    case HTTP3_H2_FRAME_CONTINUATION:
      return "CONTINUATION (reserved H2)";
    default:
      return "UNKNOWN";
    }
}

const char *
SocketHTTP3_error_code_name (uint64_t code)
{
  switch (code)
    {
    case H3_NO_ERROR:
      return "H3_NO_ERROR";
    case H3_GENERAL_PROTOCOL_ERROR:
      return "H3_GENERAL_PROTOCOL_ERROR";
    case H3_INTERNAL_ERROR:
      return "H3_INTERNAL_ERROR";
    case H3_STREAM_CREATION_ERROR:
      return "H3_STREAM_CREATION_ERROR";
    case H3_CLOSED_CRITICAL_STREAM:
      return "H3_CLOSED_CRITICAL_STREAM";
    case H3_FRAME_UNEXPECTED:
      return "H3_FRAME_UNEXPECTED";
    case H3_FRAME_ERROR:
      return "H3_FRAME_ERROR";
    case H3_EXCESSIVE_LOAD:
      return "H3_EXCESSIVE_LOAD";
    case H3_ID_ERROR:
      return "H3_ID_ERROR";
    case H3_SETTINGS_ERROR:
      return "H3_SETTINGS_ERROR";
    case H3_MISSING_SETTINGS:
      return "H3_MISSING_SETTINGS";
    case H3_REQUEST_REJECTED:
      return "H3_REQUEST_REJECTED";
    case H3_REQUEST_CANCELLED:
      return "H3_REQUEST_CANCELLED";
    case H3_REQUEST_INCOMPLETE:
      return "H3_REQUEST_INCOMPLETE";
    case H3_MESSAGE_ERROR:
      return "H3_MESSAGE_ERROR";
    case H3_CONNECT_ERROR:
      return "H3_CONNECT_ERROR";
    case H3_VERSION_FALLBACK:
      return "H3_VERSION_FALLBACK";
    default:
      return "UNKNOWN";
    }
}

const char *
SocketHTTP3_stream_type_name (uint64_t type)
{
  switch (type)
    {
    case H3_STREAM_TYPE_CONTROL:
      return "CONTROL";
    case H3_STREAM_TYPE_PUSH:
      return "PUSH";
    case H3_STREAM_TYPE_QPACK_ENCODER:
      return "QPACK_ENCODER";
    case H3_STREAM_TYPE_QPACK_DECODER:
      return "QPACK_DECODER";
    default:
      return "UNKNOWN";
    }
}

const char *
SocketHTTP3_settings_name (uint64_t id)
{
  switch (id)
    {
    case H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY:
      return "QPACK_MAX_TABLE_CAPACITY";
    case H3_SETTINGS_MAX_FIELD_SECTION_SIZE:
      return "MAX_FIELD_SECTION_SIZE";
    case H3_SETTINGS_QPACK_BLOCKED_STREAMS:
      return "QPACK_BLOCKED_STREAMS";
    default:
      return "UNKNOWN";
    }
}
