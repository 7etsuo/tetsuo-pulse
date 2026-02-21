/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketProto-message.c
 * @brief Protobuf message parsing/encoding with unknown-field preservation.
 */

#include "grpc/SocketProto-private.h"

#include <stdlib.h>
#include <string.h>

static uint8_t
socketproto_kind_wire_type (SocketProto_FieldKind kind)
{
  switch (kind)
    {
    case SOCKET_PROTO_KIND_VARINT:
      return SOCKET_PROTO_WIRE_VARINT;
    case SOCKET_PROTO_KIND_FIXED64:
      return SOCKET_PROTO_WIRE_FIXED64;
    case SOCKET_PROTO_KIND_LENGTH_DELIMITED:
      return SOCKET_PROTO_WIRE_LENGTH_DELIMITED;
    case SOCKET_PROTO_KIND_FIXED32:
      return SOCKET_PROTO_WIRE_FIXED32;
    case SOCKET_PROTO_KIND_MESSAGE:
      return SOCKET_PROTO_WIRE_LENGTH_DELIMITED;
    }

  return 0xFFU;
}

const SocketProto_SchemaField *
SocketProto_Schema_find_field (const SocketProto_Schema *schema,
                               uint32_t field_number)
{
  if (schema == NULL || schema->fields == NULL || schema->field_count == 0)
    return NULL;

  for (size_t i = 0; i < schema->field_count; i++)
    {
      if (schema->fields[i].field_number == field_number)
        return &schema->fields[i];
    }

  return NULL;
}

void
SocketProto_limits_defaults (SocketProto_Limits *limits)
{
  if (limits == NULL)
    return;

  limits->max_message_size = SOCKET_PROTO_DEFAULT_MAX_MESSAGE_SIZE;
  limits->max_fields = SOCKET_PROTO_DEFAULT_MAX_FIELDS;
  limits->max_nesting_depth = SOCKET_PROTO_DEFAULT_MAX_NESTING_DEPTH;
}

static void
socketproto_limits_apply (SocketProto_Limits *out, const SocketProto_Limits *in)
{
  SocketProto_limits_defaults (out);
  if (in == NULL)
    return;

  if (in->max_message_size != 0)
    out->max_message_size = in->max_message_size;
  if (in->max_fields != 0)
    out->max_fields = in->max_fields;
  if (in->max_nesting_depth != 0)
    out->max_nesting_depth = in->max_nesting_depth;
}

SocketProto_Message_T
SocketProto_Message_new (Arena_T arena,
                         const SocketProto_Limits *limits,
                         const SocketProto_Schema *schema)
{
  SocketProto_Message_T message
      = calloc (1, sizeof (struct SocketProto_Message));
  if (message == NULL)
    return NULL;

  if (arena != NULL)
    {
      message->arena = arena;
      message->owns_arena = 0;
    }
  else
    {
      message->arena = Arena_new ();
      message->owns_arena = 1;
    }

  socketproto_limits_apply (&message->limits, limits);
  message->schema = schema;
  return message;
}

void
SocketProto_Message_free (SocketProto_Message_T *message)
{
  if (message == NULL || *message == NULL)
    return;

  if ((*message)->owns_arena)
    {
      Arena_dispose (&(*message)->arena);
    }

  free (*message);
  *message = NULL;
}

void
SocketProto_Message_clear (SocketProto_Message_T message)
{
  if (message == NULL)
    return;
  message->field_count = 0;
  message->unknown_count = 0;
}

static SocketProto_Result
socketproto_message_reserve_fields (SocketProto_Message_T message,
                                    size_t needed)
{
  size_t new_capacity;
  size_t bytes;
  SocketProto_Field *new_fields;

  if (message->field_capacity >= needed)
    return SOCKET_PROTO_OK;

  new_capacity = message->field_capacity ? message->field_capacity : 8U;
  while (new_capacity < needed)
    {
      size_t doubled;
      if (socketproto_size_mul (new_capacity, 2U, &doubled))
        return SOCKET_PROTO_OVERFLOW;
      if (doubled > message->limits.max_fields)
        {
          new_capacity = message->limits.max_fields;
          break;
        }
      new_capacity = doubled;
    }

  if (new_capacity < needed)
    return SOCKET_PROTO_LIMIT_FIELD_COUNT;

  if (socketproto_size_mul (new_capacity, sizeof (SocketProto_Field), &bytes))
    return SOCKET_PROTO_OVERFLOW;

  (void)bytes;
  new_fields
      = CALLOC (message->arena, new_capacity, sizeof (SocketProto_Field));
  if (message->fields != NULL && message->field_count > 0)
    {
      memcpy (new_fields,
              message->fields,
              message->field_count * sizeof (SocketProto_Field));
    }

  message->fields = new_fields;
  message->field_capacity = new_capacity;
  return SOCKET_PROTO_OK;
}

static SocketProto_Result
socketproto_validate_message_internal (const uint8_t *data,
                                       size_t len,
                                       const SocketProto_Schema *schema,
                                       const SocketProto_Limits *limits,
                                       size_t depth)
{
  size_t offset = 0;
  size_t field_count = 0;

  if ((data == NULL && len != 0) || limits == NULL)
    return SOCKET_PROTO_INVALID_ARGUMENT;

  if (len > limits->max_message_size)
    return SOCKET_PROTO_LIMIT_MESSAGE_SIZE;

  if (depth > limits->max_nesting_depth)
    return SOCKET_PROTO_LIMIT_NESTING_DEPTH;

  while (offset < len)
    {
      SocketProto_Field field;
      size_t consumed = 0;
      SocketProto_Result rc = SocketProto_wire_read_field (
          data + offset, len - offset, &field, &consumed);
      if (rc != SOCKET_PROTO_OK)
        return rc;
      if (consumed == 0)
        return SOCKET_PROTO_MALFORMED;

      field_count++;
      if (field_count > limits->max_fields)
        return SOCKET_PROTO_LIMIT_FIELD_COUNT;

      if (schema != NULL)
        {
          const SocketProto_SchemaField *decl
              = SocketProto_Schema_find_field (schema, field.field_number);
          if (decl != NULL)
            {
              uint8_t expected_wire = socketproto_kind_wire_type (decl->kind);
              if (expected_wire != field.wire_type)
                return SOCKET_PROTO_TYPE_MISMATCH;

              if (decl->kind == SOCKET_PROTO_KIND_MESSAGE
                  && decl->message_schema != NULL)
                {
                  if (depth + 1 > limits->max_nesting_depth)
                    return SOCKET_PROTO_LIMIT_NESTING_DEPTH;

                  rc = socketproto_validate_message_internal (
                      field.value,
                      field.value_len,
                      decl->message_schema,
                      limits,
                      depth + 1);
                  if (rc != SOCKET_PROTO_OK)
                    return rc;
                }
            }
        }

      if (socketproto_size_add (offset, consumed, &offset))
        return SOCKET_PROTO_OVERFLOW;
    }

  return SOCKET_PROTO_OK;
}

SocketProto_Result
SocketProto_Message_validate (const uint8_t *data,
                              size_t len,
                              const SocketProto_Schema *schema,
                              const SocketProto_Limits *limits)
{
  SocketProto_Limits effective_limits;
  socketproto_limits_apply (&effective_limits, limits);
  return socketproto_validate_message_internal (
      data, len, schema, &effective_limits, 0);
}

static SocketProto_Result
socketproto_message_store_encoded (SocketProto_Message_T message,
                                   uint32_t field_number,
                                   uint8_t wire_type,
                                   uint8_t *encoded,
                                   size_t encoded_len,
                                   size_t value_offset,
                                   size_t value_len,
                                   int known)
{
  SocketProto_Result rc;
  SocketProto_Field *dst;
  size_t total_size = 0;

  if (message == NULL || encoded == NULL)
    return SOCKET_PROTO_INVALID_ARGUMENT;
  if (value_offset > encoded_len)
    return SOCKET_PROTO_MALFORMED;
  if (value_len > encoded_len - value_offset)
    return SOCKET_PROTO_MALFORMED;
  if (message->field_count >= message->limits.max_fields)
    return SOCKET_PROTO_LIMIT_FIELD_COUNT;

  for (size_t i = 0; i < message->field_count; i++)
    {
      if (socketproto_size_add (
              total_size, message->fields[i].encoded_len, &total_size))
        return SOCKET_PROTO_OVERFLOW;
    }
  if (socketproto_size_add (total_size, encoded_len, &total_size))
    return SOCKET_PROTO_OVERFLOW;
  if (total_size > message->limits.max_message_size)
    return SOCKET_PROTO_LIMIT_MESSAGE_SIZE;

  rc = socketproto_message_reserve_fields (message, message->field_count + 1);
  if (rc != SOCKET_PROTO_OK)
    return rc;

  dst = &message->fields[message->field_count++];
  dst->field_number = field_number;
  dst->wire_type = wire_type;
  dst->encoded = encoded;
  dst->encoded_len = encoded_len;
  dst->value = encoded + value_offset;
  dst->value_len = value_len;
  dst->known = known ? 1 : 0;
  if (!dst->known)
    message->unknown_count++;

  return SOCKET_PROTO_OK;
}

static SocketProto_Result
socketproto_message_store_from_view (SocketProto_Message_T message,
                                     const SocketProto_Field *view,
                                     int known)
{
  ptrdiff_t offset;
  size_t value_offset;
  uint8_t *encoded_copy;

  if (message == NULL || view == NULL || view->encoded == NULL)
    return SOCKET_PROTO_INVALID_ARGUMENT;

  offset = view->value - view->encoded;
  if (offset < 0)
    return SOCKET_PROTO_MALFORMED;
  value_offset = (size_t)offset;

  encoded_copy = ALLOC (message->arena, view->encoded_len);
  memcpy (encoded_copy, view->encoded, view->encoded_len);

  return socketproto_message_store_encoded (message,
                                            view->field_number,
                                            view->wire_type,
                                            encoded_copy,
                                            view->encoded_len,
                                            value_offset,
                                            view->value_len,
                                            known);
}

SocketProto_Result
SocketProto_Message_parse (SocketProto_Message_T message,
                           const uint8_t *data,
                           size_t len)
{
  size_t offset = 0;

  if (message == NULL || (data == NULL && len != 0))
    return SOCKET_PROTO_INVALID_ARGUMENT;

  SocketProto_Message_clear (message);

  if (len > message->limits.max_message_size)
    return SOCKET_PROTO_LIMIT_MESSAGE_SIZE;

  while (offset < len)
    {
      SocketProto_Field field;
      size_t consumed = 0;
      int known = 0;
      const SocketProto_SchemaField *decl = NULL;
      SocketProto_Result rc = SocketProto_wire_read_field (
          data + offset, len - offset, &field, &consumed);
      if (rc != SOCKET_PROTO_OK)
        return rc;
      if (consumed == 0)
        return SOCKET_PROTO_MALFORMED;

      if (message->schema != NULL)
        {
          decl = SocketProto_Schema_find_field (message->schema,
                                                field.field_number);
          if (decl != NULL)
            {
              uint8_t expected_wire = socketproto_kind_wire_type (decl->kind);
              if (expected_wire != field.wire_type)
                return SOCKET_PROTO_TYPE_MISMATCH;
              known = 1;
            }
        }

      if (decl != NULL && decl->kind == SOCKET_PROTO_KIND_MESSAGE
          && decl->message_schema != NULL)
        {
          SocketProto_Result nested_rc
              = socketproto_validate_message_internal (field.value,
                                                       field.value_len,
                                                       decl->message_schema,
                                                       &message->limits,
                                                       1);
          if (nested_rc != SOCKET_PROTO_OK)
            return nested_rc;
        }

      rc = socketproto_message_store_from_view (message, &field, known);
      if (rc != SOCKET_PROTO_OK)
        return rc;

      if (socketproto_size_add (offset, consumed, &offset))
        return SOCKET_PROTO_OVERFLOW;
    }

  return SOCKET_PROTO_OK;
}

SocketProto_Result
SocketProto_Message_encode (const SocketProto_Message_T message,
                            uint8_t *out,
                            size_t out_len,
                            size_t *written)
{
  size_t total = 0;
  size_t pos = 0;

  if (message == NULL || out == NULL || written == NULL)
    return SOCKET_PROTO_INVALID_ARGUMENT;

  for (size_t i = 0; i < message->field_count; i++)
    {
      if (socketproto_size_add (total, message->fields[i].encoded_len, &total))
        return SOCKET_PROTO_OVERFLOW;
    }

  if (out_len < total)
    return SOCKET_PROTO_BUFFER_TOO_SMALL;

  for (size_t i = 0; i < message->field_count; i++)
    {
      memcpy (out + pos,
              message->fields[i].encoded,
              message->fields[i].encoded_len);
      pos += message->fields[i].encoded_len;
    }

  *written = total;
  return SOCKET_PROTO_OK;
}

size_t
SocketProto_Message_field_count (const SocketProto_Message_T message)
{
  return message ? message->field_count : 0;
}

const SocketProto_Field *
SocketProto_Message_field_at (const SocketProto_Message_T message, size_t index)
{
  if (message == NULL || index >= message->field_count)
    return NULL;
  return &message->fields[index];
}

size_t
SocketProto_Message_unknown_count (const SocketProto_Message_T message)
{
  return message ? message->unknown_count : 0;
}

const SocketProto_Field *
SocketProto_Message_unknown_at (const SocketProto_Message_T message,
                                size_t index)
{
  size_t seen = 0;

  if (message == NULL)
    return NULL;

  for (size_t i = 0; i < message->field_count; i++)
    {
      if (!message->fields[i].known)
        {
          if (seen == index)
            return &message->fields[i];
          seen++;
        }
    }

  return NULL;
}

static SocketProto_Result
socketproto_message_schema_classify (const SocketProto_Message_T message,
                                     uint32_t field_number,
                                     uint8_t wire_type,
                                     int *known,
                                     const SocketProto_SchemaField **decl_out)
{
  if (known == NULL)
    return SOCKET_PROTO_INVALID_ARGUMENT;

  *known = 0;
  if (decl_out != NULL)
    *decl_out = NULL;

  if (message == NULL || message->schema == NULL)
    return SOCKET_PROTO_OK;

  const SocketProto_SchemaField *decl
      = SocketProto_Schema_find_field (message->schema, field_number);
  if (decl == NULL)
    return SOCKET_PROTO_OK;

  if (socketproto_kind_wire_type (decl->kind) != wire_type)
    return SOCKET_PROTO_TYPE_MISMATCH;

  *known = 1;
  if (decl_out != NULL)
    *decl_out = decl;
  return SOCKET_PROTO_OK;
}

SocketProto_Result
SocketProto_Message_append_varint (SocketProto_Message_T message,
                                   uint32_t field_number,
                                   uint64_t value)
{
  uint8_t tag_buf[SOCKET_PROTO_MAX_VARINT_LEN];
  uint8_t val_buf[SOCKET_PROTO_MAX_VARINT_LEN];
  uint8_t *encoded;
  size_t tag_len = 0;
  size_t val_len = 0;
  size_t total = 0;
  int known = 0;
  SocketProto_Result rc;

  if (message == NULL)
    return SOCKET_PROTO_INVALID_ARGUMENT;

  rc = socketproto_message_schema_classify (
      message, field_number, SOCKET_PROTO_WIRE_VARINT, &known, NULL);
  if (rc != SOCKET_PROTO_OK)
    return rc;

  rc = SocketProto_wire_write_tag (field_number,
                                   SOCKET_PROTO_WIRE_VARINT,
                                   tag_buf,
                                   sizeof (tag_buf),
                                   &tag_len);
  if (rc != SOCKET_PROTO_OK)
    return rc;

  rc = SocketProto_varint_encode_u64 (
      value, val_buf, sizeof (val_buf), &val_len);
  if (rc != SOCKET_PROTO_OK)
    return rc;

  if (socketproto_size_add (tag_len, val_len, &total))
    return SOCKET_PROTO_OVERFLOW;

  encoded = ALLOC (message->arena, total);
  memcpy (encoded, tag_buf, tag_len);
  memcpy (encoded + tag_len, val_buf, val_len);

  return socketproto_message_store_encoded (message,
                                            field_number,
                                            SOCKET_PROTO_WIRE_VARINT,
                                            encoded,
                                            total,
                                            tag_len,
                                            val_len,
                                            known);
}

SocketProto_Result
SocketProto_Message_append_sint64 (SocketProto_Message_T message,
                                   uint32_t field_number,
                                   int64_t value)
{
  return SocketProto_Message_append_varint (
      message, field_number, SocketProto_zigzag_encode_s64 (value));
}

SocketProto_Result
SocketProto_Message_append_fixed32 (SocketProto_Message_T message,
                                    uint32_t field_number,
                                    uint32_t value)
{
  uint8_t tag_buf[SOCKET_PROTO_MAX_VARINT_LEN];
  uint8_t fixed_buf[4];
  uint8_t *encoded;
  size_t tag_len = 0;
  size_t total = 0;
  int known = 0;
  SocketProto_Result rc;

  if (message == NULL)
    return SOCKET_PROTO_INVALID_ARGUMENT;

  rc = socketproto_message_schema_classify (
      message, field_number, SOCKET_PROTO_WIRE_FIXED32, &known, NULL);
  if (rc != SOCKET_PROTO_OK)
    return rc;

  rc = SocketProto_wire_write_tag (field_number,
                                   SOCKET_PROTO_WIRE_FIXED32,
                                   tag_buf,
                                   sizeof (tag_buf),
                                   &tag_len);
  if (rc != SOCKET_PROTO_OK)
    return rc;

  rc = SocketProto_fixed32_encode (value, fixed_buf, sizeof (fixed_buf));
  if (rc != SOCKET_PROTO_OK)
    return rc;

  if (socketproto_size_add (tag_len, sizeof (fixed_buf), &total))
    return SOCKET_PROTO_OVERFLOW;

  encoded = ALLOC (message->arena, total);
  memcpy (encoded, tag_buf, tag_len);
  memcpy (encoded + tag_len, fixed_buf, sizeof (fixed_buf));

  return socketproto_message_store_encoded (message,
                                            field_number,
                                            SOCKET_PROTO_WIRE_FIXED32,
                                            encoded,
                                            total,
                                            tag_len,
                                            sizeof (fixed_buf),
                                            known);
}

SocketProto_Result
SocketProto_Message_append_fixed64 (SocketProto_Message_T message,
                                    uint32_t field_number,
                                    uint64_t value)
{
  uint8_t tag_buf[SOCKET_PROTO_MAX_VARINT_LEN];
  uint8_t fixed_buf[8];
  uint8_t *encoded;
  size_t tag_len = 0;
  size_t total = 0;
  int known = 0;
  SocketProto_Result rc;

  if (message == NULL)
    return SOCKET_PROTO_INVALID_ARGUMENT;

  rc = socketproto_message_schema_classify (
      message, field_number, SOCKET_PROTO_WIRE_FIXED64, &known, NULL);
  if (rc != SOCKET_PROTO_OK)
    return rc;

  rc = SocketProto_wire_write_tag (field_number,
                                   SOCKET_PROTO_WIRE_FIXED64,
                                   tag_buf,
                                   sizeof (tag_buf),
                                   &tag_len);
  if (rc != SOCKET_PROTO_OK)
    return rc;

  rc = SocketProto_fixed64_encode (value, fixed_buf, sizeof (fixed_buf));
  if (rc != SOCKET_PROTO_OK)
    return rc;

  if (socketproto_size_add (tag_len, sizeof (fixed_buf), &total))
    return SOCKET_PROTO_OVERFLOW;

  encoded = ALLOC (message->arena, total);
  memcpy (encoded, tag_buf, tag_len);
  memcpy (encoded + tag_len, fixed_buf, sizeof (fixed_buf));

  return socketproto_message_store_encoded (message,
                                            field_number,
                                            SOCKET_PROTO_WIRE_FIXED64,
                                            encoded,
                                            total,
                                            tag_len,
                                            sizeof (fixed_buf),
                                            known);
}

SocketProto_Result
SocketProto_Message_append_bytes (SocketProto_Message_T message,
                                  uint32_t field_number,
                                  const uint8_t *value,
                                  size_t value_len)
{
  uint8_t tag_buf[SOCKET_PROTO_MAX_VARINT_LEN];
  uint8_t len_buf[SOCKET_PROTO_MAX_VARINT_LEN];
  size_t tag_len = 0;
  size_t len_len = 0;
  size_t prefix_len = 0;
  size_t total = 0;
  uint8_t *encoded;
  int known = 0;
  const SocketProto_SchemaField *decl = NULL;
  SocketProto_Result rc;

  if (message == NULL || (value_len > 0 && value == NULL))
    return SOCKET_PROTO_INVALID_ARGUMENT;

  rc = socketproto_message_schema_classify (
      message, field_number, SOCKET_PROTO_WIRE_LENGTH_DELIMITED, &known, &decl);
  if (rc != SOCKET_PROTO_OK)
    return rc;

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

  if (socketproto_size_add (tag_len, len_len, &prefix_len))
    return SOCKET_PROTO_OVERFLOW;
  if (socketproto_size_add (prefix_len, value_len, &total))
    return SOCKET_PROTO_OVERFLOW;
  if (total > message->limits.max_message_size)
    return SOCKET_PROTO_LIMIT_MESSAGE_SIZE;

  encoded = ALLOC (message->arena, total);
  memcpy (encoded, tag_buf, tag_len);
  memcpy (encoded + tag_len, len_buf, len_len);
  if (value_len > 0)
    memcpy (encoded + prefix_len, value, value_len);

  if (decl != NULL && decl->kind == SOCKET_PROTO_KIND_MESSAGE
      && decl->message_schema != NULL)
    {
      SocketProto_Result nested_rc = socketproto_validate_message_internal (
          value, value_len, decl->message_schema, &message->limits, 1);
      if (nested_rc != SOCKET_PROTO_OK)
        return nested_rc;
    }

  return socketproto_message_store_encoded (message,
                                            field_number,
                                            SOCKET_PROTO_WIRE_LENGTH_DELIMITED,
                                            encoded,
                                            total,
                                            prefix_len,
                                            value_len,
                                            known);
}

SocketProto_Result
SocketProto_Message_append_embedded (SocketProto_Message_T message,
                                     uint32_t field_number,
                                     const uint8_t *encoded_message,
                                     size_t encoded_len)
{
  return SocketProto_Message_append_bytes (
      message, field_number, encoded_message, encoded_len);
}

SocketProto_Result
SocketProto_Field_decode_u64 (const SocketProto_Field *field, uint64_t *value)
{
  size_t consumed = 0;
  SocketProto_Result rc;

  if (field == NULL || value == NULL)
    return SOCKET_PROTO_INVALID_ARGUMENT;
  if (field->wire_type != SOCKET_PROTO_WIRE_VARINT)
    return SOCKET_PROTO_TYPE_MISMATCH;

  rc = SocketProto_varint_decode_u64 (
      field->value, field->value_len, value, &consumed);
  if (rc != SOCKET_PROTO_OK)
    return rc;
  if (consumed != field->value_len)
    return SOCKET_PROTO_MALFORMED;
  return SOCKET_PROTO_OK;
}

SocketProto_Result
SocketProto_Field_decode_s64 (const SocketProto_Field *field, int64_t *value)
{
  uint64_t encoded = 0;
  SocketProto_Result rc;

  if (field == NULL || value == NULL)
    return SOCKET_PROTO_INVALID_ARGUMENT;

  rc = SocketProto_Field_decode_u64 (field, &encoded);
  if (rc != SOCKET_PROTO_OK)
    return rc;

  *value = SocketProto_zigzag_decode_s64 (encoded);
  return SOCKET_PROTO_OK;
}

SocketProto_Result
SocketProto_Field_decode_fixed32 (const SocketProto_Field *field,
                                  uint32_t *value)
{
  if (field == NULL || value == NULL)
    return SOCKET_PROTO_INVALID_ARGUMENT;
  if (field->wire_type != SOCKET_PROTO_WIRE_FIXED32)
    return SOCKET_PROTO_TYPE_MISMATCH;
  return SocketProto_fixed32_decode (field->value, field->value_len, value);
}

SocketProto_Result
SocketProto_Field_decode_fixed64 (const SocketProto_Field *field,
                                  uint64_t *value)
{
  if (field == NULL || value == NULL)
    return SOCKET_PROTO_INVALID_ARGUMENT;
  if (field->wire_type != SOCKET_PROTO_WIRE_FIXED64)
    return SOCKET_PROTO_TYPE_MISMATCH;
  return SocketProto_fixed64_decode (field->value, field->value_len, value);
}
