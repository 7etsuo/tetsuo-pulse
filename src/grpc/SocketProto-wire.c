/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketProto-wire.c
 * @brief Protobuf wire-level field parsing and encoding.
 */

#include "grpc/SocketProto-private.h"

SocketProto_Result
SocketProto_wire_make_tag (uint32_t field_number, uint8_t wire_type, uint64_t *tag)
{
  if (tag == NULL)
    return SOCKET_PROTO_INVALID_ARGUMENT;

  if (field_number == 0 || field_number > SOCKET_PROTO_MAX_FIELD_NUMBER)
    return SOCKET_PROTO_INVALID_TAG;

  if (wire_type > SOCKET_PROTO_WIRE_FIXED32 || wire_type == SOCKET_PROTO_WIRE_START_GROUP
      || wire_type == SOCKET_PROTO_WIRE_END_GROUP)
    return SOCKET_PROTO_INVALID_WIRE_TYPE;

  *tag = ((uint64_t)field_number << 3U) | (uint64_t)wire_type;
  return SOCKET_PROTO_OK;
}

SocketProto_Result
SocketProto_wire_write_tag (uint32_t field_number,
                            uint8_t wire_type,
                            uint8_t *out,
                            size_t out_len,
                            size_t *written)
{
  uint64_t tag = 0;
  SocketProto_Result rc
      = SocketProto_wire_make_tag (field_number, wire_type, &tag);
  if (rc != SOCKET_PROTO_OK)
    return rc;
  return SocketProto_varint_encode_u64 (tag, out, out_len, written);
}

SocketProto_Result
SocketProto_wire_write_length_delimited (uint32_t field_number,
                                         const uint8_t *value,
                                         size_t value_len,
                                         uint8_t *out,
                                         size_t out_len,
                                         size_t *written)
{
  uint8_t tag_buf[SOCKET_PROTO_MAX_VARINT_LEN];
  uint8_t len_buf[SOCKET_PROTO_MAX_VARINT_LEN];
  size_t tag_len = 0;
  size_t len_len = 0;
  size_t offset = 0;
  size_t total = 0;
  SocketProto_Result rc;

  if (out == NULL || written == NULL || (value_len > 0 && value == NULL))
    return SOCKET_PROTO_INVALID_ARGUMENT;

  rc = SocketProto_wire_write_tag (field_number,
                                   SOCKET_PROTO_WIRE_LENGTH_DELIMITED,
                                   tag_buf,
                                   sizeof (tag_buf),
                                   &tag_len);
  if (rc != SOCKET_PROTO_OK)
    return rc;

  rc = SocketProto_varint_encode_u64 (
      (uint64_t)value_len, len_buf, sizeof (len_buf), &len_len);
  if (rc != SOCKET_PROTO_OK)
    return rc;

  if (socketproto_size_add (tag_len, len_len, &total)
      || socketproto_size_add (total, value_len, &total))
    return SOCKET_PROTO_OVERFLOW;

  if (out_len < total)
    return SOCKET_PROTO_BUFFER_TOO_SMALL;

  for (size_t i = 0; i < tag_len; i++)
    out[offset++] = tag_buf[i];
  for (size_t i = 0; i < len_len; i++)
    out[offset++] = len_buf[i];
  for (size_t i = 0; i < value_len; i++)
    out[offset++] = value[i];

  *written = total;
  return SOCKET_PROTO_OK;
}

SocketProto_Result
SocketProto_wire_read_field (const uint8_t *data,
                             size_t len,
                             SocketProto_Field *field,
                             size_t *consumed)
{
  uint64_t tag = 0;
  size_t tag_len = 0;
  size_t offset = 0;
  uint8_t wire_type;
  uint32_t field_number;
  SocketProto_Result rc;

  if (data == NULL || field == NULL || consumed == NULL)
    return SOCKET_PROTO_INVALID_ARGUMENT;

  rc = SocketProto_varint_decode_u64 (data, len, &tag, &tag_len);
  if (rc != SOCKET_PROTO_OK)
    return rc;

  wire_type = (uint8_t)(tag & 0x07U);
  field_number = (uint32_t)(tag >> 3U);

  if (field_number == 0 || field_number > SOCKET_PROTO_MAX_FIELD_NUMBER)
    return SOCKET_PROTO_INVALID_TAG;

  if (wire_type > SOCKET_PROTO_WIRE_FIXED32
      || wire_type == SOCKET_PROTO_WIRE_START_GROUP
      || wire_type == SOCKET_PROTO_WIRE_END_GROUP)
    return SOCKET_PROTO_INVALID_WIRE_TYPE;

  offset = tag_len;
  field->field_number = field_number;
  field->wire_type = wire_type;
  field->encoded = data;
  field->known = 0;

  switch (wire_type)
    {
    case SOCKET_PROTO_WIRE_VARINT:
      {
        uint64_t ignored_value = 0;
        size_t value_len = 0;
        rc = SocketProto_varint_decode_u64 (
            data + offset, len - offset, &ignored_value, &value_len);
        if (rc != SOCKET_PROTO_OK)
          return rc;

        field->value = data + offset;
        field->value_len = value_len;
        if (socketproto_size_add (offset, value_len, &field->encoded_len))
          return SOCKET_PROTO_OVERFLOW;
      }
      break;

    case SOCKET_PROTO_WIRE_FIXED64:
      if (len - offset < 8)
        return SOCKET_PROTO_INCOMPLETE;
      field->value = data + offset;
      field->value_len = 8;
      if (socketproto_size_add (offset, 8, &field->encoded_len))
        return SOCKET_PROTO_OVERFLOW;
      break;

    case SOCKET_PROTO_WIRE_LENGTH_DELIMITED:
      {
        uint64_t length_u64 = 0;
        size_t length_len = 0;
        size_t payload_offset = 0;
        size_t payload_end = 0;

        rc = SocketProto_varint_decode_u64 (
            data + offset, len - offset, &length_u64, &length_len);
        if (rc != SOCKET_PROTO_OK)
          return rc;

        if (length_u64 > SIZE_MAX)
          return SOCKET_PROTO_OVERFLOW;

        if (socketproto_size_add (offset, length_len, &payload_offset))
          return SOCKET_PROTO_OVERFLOW;
        if (socketproto_size_add (payload_offset, (size_t)length_u64, &payload_end))
          return SOCKET_PROTO_OVERFLOW;

        if (payload_end > len)
          return SOCKET_PROTO_INCOMPLETE;

        field->value = data + payload_offset;
        field->value_len = (size_t)length_u64;
        field->encoded_len = payload_end;
      }
      break;

    case SOCKET_PROTO_WIRE_FIXED32:
      if (len - offset < 4)
        return SOCKET_PROTO_INCOMPLETE;
      field->value = data + offset;
      field->value_len = 4;
      if (socketproto_size_add (offset, 4, &field->encoded_len))
        return SOCKET_PROTO_OVERFLOW;
      break;

    default:
      return SOCKET_PROTO_INVALID_WIRE_TYPE;
    }

  *consumed = field->encoded_len;
  return SOCKET_PROTO_OK;
}
