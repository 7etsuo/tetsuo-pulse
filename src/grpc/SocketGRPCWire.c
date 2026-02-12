/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#include "grpc/SocketGRPCWire.h"

#include "core/SocketCrypto.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct SocketGRPC_Metadata
{
  Arena_T arena;
  int uses_arena;
  SocketGRPC_MetadataEntry *entries;
  size_t count;
  size_t capacity;
};

struct SocketGRPC_Trailers
{
  Arena_T arena;
  int uses_arena;
  int has_status;
  int grpc_status;
  char *grpc_message;
  uint8_t *grpc_status_details_bin;
  size_t grpc_status_details_bin_len;
  SocketGRPC_Metadata_T metadata;
};

static void *
wire_alloc (Arena_T arena, size_t size)
{
  if (size == 0)
    return NULL;
  return (arena != NULL) ? ALLOC (arena, size) : malloc (size);
}

static void
wire_free (Arena_T arena, void *ptr)
{
  if (arena != NULL || ptr == NULL)
    return;
  free (ptr);
}

static uint32_t
read_u32_be (const uint8_t *in)
{
  return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16)
         | ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

static void
write_u32_be (uint8_t *out, uint32_t value)
{
  out[0] = (uint8_t)((value >> 24) & 0xFFU);
  out[1] = (uint8_t)((value >> 16) & 0xFFU);
  out[2] = (uint8_t)((value >> 8) & 0xFFU);
  out[3] = (uint8_t)(value & 0xFFU);
}

static int
metadata_key_char_valid (unsigned char c)
{
  if (c >= 'a' && c <= 'z')
    return 1;
  if (c >= '0' && c <= '9')
    return 1;
  return c == '-' || c == '_' || c == '.';
}

static int
metadata_is_bin_key (const char *key, size_t key_len)
{
  return key_len >= 4 && memcmp (key + (key_len - 4), "-bin", 4) == 0;
}

static int
metadata_ascii_value_valid (const uint8_t *value, size_t value_len)
{
  size_t i;
  for (i = 0; i < value_len; i++)
    {
      unsigned char c = value[i];
      if (c < 0x20 || c > 0x7EU)
        return 0;
    }
  return 1;
}

static SocketGRPC_WireResult
metadata_reserve (SocketGRPC_Metadata_T metadata, size_t needed)
{
  size_t new_capacity;
  SocketGRPC_MetadataEntry *new_entries;

  if (metadata == NULL)
    return SOCKET_GRPC_WIRE_INVALID_ARGUMENT;
  if (needed <= metadata->capacity)
    return SOCKET_GRPC_WIRE_OK;

  new_capacity = (metadata->capacity == 0) ? 8U : metadata->capacity * 2U;
  while (new_capacity < needed)
    {
      if (new_capacity > (SIZE_MAX / 2U))
        return SOCKET_GRPC_WIRE_OUT_OF_MEMORY;
      new_capacity *= 2U;
    }

  new_entries = (SocketGRPC_MetadataEntry *)wire_alloc (
      metadata->arena, new_capacity * sizeof (*new_entries));
  if (new_entries == NULL)
    return SOCKET_GRPC_WIRE_OUT_OF_MEMORY;
  if (metadata->entries != NULL && metadata->count > 0)
    memcpy (new_entries,
            metadata->entries,
            metadata->count * sizeof (*new_entries));

  wire_free (metadata->arena, metadata->entries);
  metadata->entries = new_entries;
  metadata->capacity = new_capacity;
  return SOCKET_GRPC_WIRE_OK;
}

static SocketGRPC_WireResult
metadata_canonicalize_key (Arena_T arena,
                           const char *key,
                           size_t key_len,
                           char **canonical_out)
{
  char *canonical;
  size_t i;

  if (key == NULL || key_len == 0 || canonical_out == NULL)
    return SOCKET_GRPC_WIRE_INVALID_METADATA_KEY;

  canonical = (char *)wire_alloc (arena, key_len + 1U);
  if (canonical == NULL)
    return SOCKET_GRPC_WIRE_OUT_OF_MEMORY;

  for (i = 0; i < key_len; i++)
    {
      unsigned char c = (unsigned char)key[i];
      if (c >= 'A' && c <= 'Z')
        c = (unsigned char)(c - 'A' + 'a');
      if (!metadata_key_char_valid (c))
        {
          wire_free (arena, canonical);
          return SOCKET_GRPC_WIRE_INVALID_METADATA_KEY;
        }
      canonical[i] = (char)c;
    }
  canonical[key_len] = '\0';

  *canonical_out = canonical;
  return SOCKET_GRPC_WIRE_OK;
}

static SocketGRPC_WireResult
metadata_copy_value (Arena_T arena,
                     const uint8_t *value,
                     size_t value_len,
                     uint8_t **copied_out)
{
  uint8_t *copy;

  if (copied_out == NULL)
    return SOCKET_GRPC_WIRE_INVALID_ARGUMENT;
  if (value_len == 0)
    {
      *copied_out = NULL;
      return SOCKET_GRPC_WIRE_OK;
    }
  if (value == NULL)
    return SOCKET_GRPC_WIRE_INVALID_ARGUMENT;

  copy = (uint8_t *)wire_alloc (arena, value_len);
  if (copy == NULL)
    return SOCKET_GRPC_WIRE_OUT_OF_MEMORY;
  memcpy (copy, value, value_len);
  *copied_out = copy;
  return SOCKET_GRPC_WIRE_OK;
}

static SocketGRPC_WireResult
metadata_append_entry (SocketGRPC_Metadata_T metadata,
                       char *canonical_key,
                       uint8_t *copied_value,
                       size_t value_len,
                       int is_binary)
{
  SocketGRPC_WireResult rc;

  rc = metadata_reserve (metadata, metadata->count + 1U);
  if (rc != SOCKET_GRPC_WIRE_OK)
    {
      wire_free (metadata->arena, canonical_key);
      wire_free (metadata->arena, copied_value);
      return rc;
    }

  metadata->entries[metadata->count].key = canonical_key;
  metadata->entries[metadata->count].value = copied_value;
  metadata->entries[metadata->count].value_len = value_len;
  metadata->entries[metadata->count].is_binary = is_binary;
  metadata->count++;
  return SOCKET_GRPC_WIRE_OK;
}

static SocketGRPC_WireResult
metadata_add_value (SocketGRPC_Metadata_T metadata,
                    const char *key,
                    size_t key_len,
                    const uint8_t *value,
                    size_t value_len,
                    int is_binary)
{
  SocketGRPC_WireResult rc;
  char *canonical = NULL;
  uint8_t *copied_value = NULL;
  int key_is_bin;

  if (metadata == NULL || key == NULL || (value == NULL && value_len != 0))
    return SOCKET_GRPC_WIRE_INVALID_ARGUMENT;

  rc = metadata_canonicalize_key (metadata->arena, key, key_len, &canonical);
  if (rc != SOCKET_GRPC_WIRE_OK)
    return rc;

  key_is_bin = metadata_is_bin_key (canonical, strlen (canonical));
  if (is_binary && !key_is_bin)
    {
      wire_free (metadata->arena, canonical);
      return SOCKET_GRPC_WIRE_INVALID_METADATA_KEY;
    }
  if (!is_binary && key_is_bin)
    {
      wire_free (metadata->arena, canonical);
      return SOCKET_GRPC_WIRE_INVALID_METADATA_KEY;
    }

  if (!is_binary && !metadata_ascii_value_valid (value, value_len))
    {
      wire_free (metadata->arena, canonical);
      return SOCKET_GRPC_WIRE_INVALID_METADATA_VALUE;
    }

  rc = metadata_copy_value (metadata->arena, value, value_len, &copied_value);
  if (rc != SOCKET_GRPC_WIRE_OK)
    {
      wire_free (metadata->arena, canonical);
      return rc;
    }

  return metadata_append_entry (
      metadata, canonical, copied_value, value_len, is_binary);
}

static SocketGRPC_WireResult
buffer_append (uint8_t *out,
               size_t out_len,
               size_t *cursor,
               const uint8_t *data,
               size_t data_len)
{
  if (out == NULL || cursor == NULL || (data == NULL && data_len != 0))
    return SOCKET_GRPC_WIRE_INVALID_ARGUMENT;
  if (data_len > out_len || *cursor > (out_len - data_len))
    return SOCKET_GRPC_WIRE_BUFFER_TOO_SMALL;

  memcpy (out + *cursor, data, data_len);
  *cursor += data_len;
  return SOCKET_GRPC_WIRE_OK;
}

static int
is_reserved_trailer_key (const char *key)
{
  return strcmp (key, "grpc-status") == 0 || strcmp (key, "grpc-message") == 0
         || strcmp (key, "grpc-status-details-bin") == 0;
}

const char *
SocketGRPC_Wire_result_string (SocketGRPC_WireResult result)
{
  switch (result)
    {
    case SOCKET_GRPC_WIRE_OK:
      return "OK";
    case SOCKET_GRPC_WIRE_INCOMPLETE:
      return "INCOMPLETE";
    case SOCKET_GRPC_WIRE_BUFFER_TOO_SMALL:
      return "BUFFER_TOO_SMALL";
    case SOCKET_GRPC_WIRE_INVALID_ARGUMENT:
      return "INVALID_ARGUMENT";
    case SOCKET_GRPC_WIRE_INVALID_FRAME:
      return "INVALID_FRAME";
    case SOCKET_GRPC_WIRE_LENGTH_EXCEEDED:
      return "LENGTH_EXCEEDED";
    case SOCKET_GRPC_WIRE_INVALID_METADATA_KEY:
      return "INVALID_METADATA_KEY";
    case SOCKET_GRPC_WIRE_INVALID_METADATA_VALUE:
      return "INVALID_METADATA_VALUE";
    case SOCKET_GRPC_WIRE_INVALID_TRAILER:
      return "INVALID_TRAILER";
    case SOCKET_GRPC_WIRE_OUT_OF_MEMORY:
      return "OUT_OF_MEMORY";
    default:
      return "UNKNOWN";
    }
}

SocketGRPC_WireResult
SocketGRPC_Frame_encode (int compressed,
                         const uint8_t *payload,
                         uint32_t payload_len,
                         uint8_t *out,
                         size_t out_len,
                         size_t *written)
{
  size_t required = SOCKET_GRPC_WIRE_FRAME_PREFIX_SIZE + (size_t)payload_len;

  if (out == NULL || written == NULL || (payload == NULL && payload_len != 0))
    return SOCKET_GRPC_WIRE_INVALID_ARGUMENT;
  if (compressed != 0 && compressed != 1)
    return SOCKET_GRPC_WIRE_INVALID_FRAME;
  if (required > out_len)
    return SOCKET_GRPC_WIRE_BUFFER_TOO_SMALL;

  out[0] = (uint8_t)compressed;
  write_u32_be (out + 1, payload_len);
  if (payload_len > 0)
    memcpy (out + SOCKET_GRPC_WIRE_FRAME_PREFIX_SIZE, payload, payload_len);
  *written = required;
  return SOCKET_GRPC_WIRE_OK;
}

SocketGRPC_WireResult
SocketGRPC_Frame_parse (const uint8_t *data,
                        size_t len,
                        size_t max_message_size,
                        SocketGRPC_FrameView *frame,
                        size_t *consumed)
{
  uint32_t payload_len;
  size_t frame_len;

  if (data == NULL || frame == NULL || consumed == NULL)
    return SOCKET_GRPC_WIRE_INVALID_ARGUMENT;
  if (len < SOCKET_GRPC_WIRE_FRAME_PREFIX_SIZE)
    return SOCKET_GRPC_WIRE_INCOMPLETE;

  if (data[0] != 0U && data[0] != 1U)
    return SOCKET_GRPC_WIRE_INVALID_FRAME;

  payload_len = read_u32_be (data + 1);
  if (max_message_size == 0)
    max_message_size = SOCKET_GRPC_WIRE_DEFAULT_MAX_MESSAGE_SIZE;
  if ((size_t)payload_len > max_message_size)
    return SOCKET_GRPC_WIRE_LENGTH_EXCEEDED;

  frame_len = SOCKET_GRPC_WIRE_FRAME_PREFIX_SIZE + (size_t)payload_len;
  if (len < frame_len)
    return SOCKET_GRPC_WIRE_INCOMPLETE;

  frame->compressed = (int)data[0];
  frame->payload = data + SOCKET_GRPC_WIRE_FRAME_PREFIX_SIZE;
  frame->payload_len = payload_len;
  *consumed = frame_len;
  return SOCKET_GRPC_WIRE_OK;
}

SocketGRPC_Metadata_T
SocketGRPC_Metadata_new (Arena_T arena)
{
  SocketGRPC_Metadata_T metadata;

  if (arena != NULL)
    metadata = (SocketGRPC_Metadata_T)ALLOC (arena, sizeof (*metadata));
  else
    metadata = (SocketGRPC_Metadata_T)calloc (1, sizeof (*metadata));

  if (metadata == NULL)
    return NULL;
  if (arena != NULL)
    memset (metadata, 0, sizeof (*metadata));

  metadata->arena = arena;
  metadata->uses_arena = arena != NULL;
  return metadata;
}

void
SocketGRPC_Metadata_free (SocketGRPC_Metadata_T *metadata)
{
  size_t i;
  if (metadata == NULL || *metadata == NULL)
    return;

  if (!(*metadata)->uses_arena)
    {
      for (i = 0; i < (*metadata)->count; i++)
        {
          free ((*metadata)->entries[i].key);
          free ((*metadata)->entries[i].value);
        }
      free ((*metadata)->entries);
      free (*metadata);
    }

  *metadata = NULL;
}

void
SocketGRPC_Metadata_clear (SocketGRPC_Metadata_T metadata)
{
  size_t i;
  if (metadata == NULL)
    return;

  if (!metadata->uses_arena)
    {
      for (i = 0; i < metadata->count; i++)
        {
          free (metadata->entries[i].key);
          free (metadata->entries[i].value);
        }
    }
  metadata->count = 0;
}

size_t
SocketGRPC_Metadata_count (const SocketGRPC_Metadata_T metadata)
{
  return metadata != NULL ? metadata->count : 0U;
}

const SocketGRPC_MetadataEntry *
SocketGRPC_Metadata_at (const SocketGRPC_Metadata_T metadata, size_t index)
{
  if (metadata == NULL || index >= metadata->count)
    return NULL;
  return &metadata->entries[index];
}

SocketGRPC_WireResult
SocketGRPC_Metadata_add_ascii (SocketGRPC_Metadata_T metadata,
                               const char *key,
                               const char *value)
{
  if (value == NULL)
    return SOCKET_GRPC_WIRE_INVALID_ARGUMENT;
  return metadata_add_value (metadata,
                             key,
                             strlen (key),
                             (const uint8_t *)value,
                             strlen (value),
                             0);
}

SocketGRPC_WireResult
SocketGRPC_Metadata_add_binary (SocketGRPC_Metadata_T metadata,
                                const char *key,
                                const uint8_t *value,
                                size_t value_len)
{
  if (value == NULL && value_len != 0)
    return SOCKET_GRPC_WIRE_INVALID_ARGUMENT;
  return metadata_add_value (
      metadata, key, strlen (key), value, value_len, 1);
}

SocketGRPC_WireResult
SocketGRPC_Metadata_serialize (const SocketGRPC_Metadata_T metadata,
                               uint8_t *out,
                               size_t out_len,
                               size_t *written)
{
  size_t i;
  size_t cursor = 0;

  if (metadata == NULL || out == NULL || written == NULL)
    return SOCKET_GRPC_WIRE_INVALID_ARGUMENT;

  for (i = 0; i < metadata->count; i++)
    {
      const SocketGRPC_MetadataEntry *entry = &metadata->entries[i];
      const uint8_t sep[] = { ':', ' ' };
      const uint8_t crlf[] = { '\r', '\n' };
      SocketGRPC_WireResult rc;

      rc = buffer_append (
          out, out_len, &cursor, (const uint8_t *)entry->key, strlen (entry->key));
      if (rc != SOCKET_GRPC_WIRE_OK)
        return rc;
      rc = buffer_append (out, out_len, &cursor, sep, sizeof (sep));
      if (rc != SOCKET_GRPC_WIRE_OK)
        return rc;

      if (entry->is_binary)
        {
          size_t encoded_cap
              = SocketCrypto_base64_encoded_size (entry->value_len);
          char *encoded = (char *)malloc (encoded_cap);
          ssize_t encoded_len;
          if (encoded == NULL)
            return SOCKET_GRPC_WIRE_OUT_OF_MEMORY;
          encoded_len = SocketCrypto_base64_encode (
              entry->value, entry->value_len, encoded, encoded_cap);
          if (encoded_len < 0)
            {
              free (encoded);
              return SOCKET_GRPC_WIRE_INVALID_METADATA_VALUE;
            }
          rc = buffer_append (out,
                              out_len,
                              &cursor,
                              (const uint8_t *)encoded,
                              (size_t)encoded_len);
          free (encoded);
          if (rc != SOCKET_GRPC_WIRE_OK)
            return rc;
        }
      else
        {
          rc = buffer_append (
              out, out_len, &cursor, entry->value, entry->value_len);
          if (rc != SOCKET_GRPC_WIRE_OK)
            return rc;
        }

      rc = buffer_append (out, out_len, &cursor, crlf, sizeof (crlf));
      if (rc != SOCKET_GRPC_WIRE_OK)
        return rc;
    }

  {
    const uint8_t terminal_crlf[] = { '\r', '\n' };
    SocketGRPC_WireResult rc
        = buffer_append (
            out, out_len, &cursor, terminal_crlf, sizeof (terminal_crlf));
    if (rc != SOCKET_GRPC_WIRE_OK)
      return rc;
  }

  *written = cursor;
  return SOCKET_GRPC_WIRE_OK;
}

static SocketGRPC_WireResult
metadata_parse_line (SocketGRPC_Metadata_T metadata,
                     const uint8_t *line,
                     size_t line_len)
{
  const uint8_t *colon;
  size_t key_len;
  const uint8_t *value;
  size_t value_len;
  SocketGRPC_WireResult rc;
  char *key_buf;
  int is_binary;

  if (line == NULL || line_len == 0)
    return SOCKET_GRPC_WIRE_OK;

  colon = (const uint8_t *)memchr (line, ':', line_len);
  if (colon == NULL)
    return SOCKET_GRPC_WIRE_INVALID_METADATA_VALUE;

  key_len = (size_t)(colon - line);
  if (key_len == 0)
    return SOCKET_GRPC_WIRE_INVALID_METADATA_KEY;

  value = colon + 1;
  value_len = line_len - (key_len + 1U);
  while (value_len > 0 && (*value == ' ' || *value == '\t'))
    {
      value++;
      value_len--;
    }
  while (value_len > 0
         && (value[value_len - 1U] == ' ' || value[value_len - 1U] == '\t'))
    value_len--;

  key_buf = (char *)malloc (key_len + 1U);
  if (key_buf == NULL)
    return SOCKET_GRPC_WIRE_OUT_OF_MEMORY;
  memcpy (key_buf, line, key_len);
  key_buf[key_len] = '\0';

  is_binary = metadata_is_bin_key (key_buf, key_len);
  if (is_binary)
    {
      size_t decoded_cap = SocketCrypto_base64_decoded_size (value_len);
      uint8_t *decoded;
      ssize_t decoded_len;
      decoded = (uint8_t *)malloc (decoded_cap > 0 ? decoded_cap : 1U);
      if (decoded == NULL)
        {
          free (key_buf);
          return SOCKET_GRPC_WIRE_OUT_OF_MEMORY;
        }
      decoded_len = SocketCrypto_base64_decode (
          (const char *)value, value_len, decoded, decoded_cap > 0 ? decoded_cap : 1U);
      if (decoded_len < 0)
        {
          free (decoded);
          free (key_buf);
          return SOCKET_GRPC_WIRE_INVALID_METADATA_VALUE;
        }
      rc = metadata_add_value (
          metadata, key_buf, key_len, decoded, (size_t)decoded_len, 1);
      free (decoded);
    }
  else
    {
      rc = metadata_add_value (metadata, key_buf, key_len, value, value_len, 0);
    }

  free (key_buf);
  return rc;
}

SocketGRPC_WireResult
SocketGRPC_Metadata_parse (SocketGRPC_Metadata_T metadata,
                           const uint8_t *data,
                           size_t len)
{
  size_t pos = 0;

  if (metadata == NULL || (data == NULL && len != 0))
    return SOCKET_GRPC_WIRE_INVALID_ARGUMENT;

  SocketGRPC_Metadata_clear (metadata);

  while (pos < len)
    {
      size_t line_start = pos;
      size_t line_end;
      size_t line_len;
      SocketGRPC_WireResult rc;

      while (pos < len && data[pos] != '\n')
        pos++;
      line_end = pos;
      if (pos < len && data[pos] == '\n')
        pos++;

      if (line_end > line_start && data[line_end - 1U] == '\r')
        line_end--;
      line_len = line_end - line_start;
      if (line_len == 0)
        continue;

      rc = metadata_parse_line (metadata, data + line_start, line_len);
      if (rc != SOCKET_GRPC_WIRE_OK)
        {
          SocketGRPC_Metadata_clear (metadata);
          return rc;
        }
    }

  return SOCKET_GRPC_WIRE_OK;
}

SocketGRPC_Trailers_T
SocketGRPC_Trailers_new (Arena_T arena)
{
  SocketGRPC_Trailers_T trailers;

  if (arena != NULL)
    trailers = (SocketGRPC_Trailers_T)ALLOC (arena, sizeof (*trailers));
  else
    trailers = (SocketGRPC_Trailers_T)calloc (1, sizeof (*trailers));
  if (trailers == NULL)
    return NULL;
  if (arena != NULL)
    memset (trailers, 0, sizeof (*trailers));

  trailers->arena = arena;
  trailers->uses_arena = arena != NULL;
  trailers->metadata = SocketGRPC_Metadata_new (arena);
  if (trailers->metadata == NULL)
    {
      if (!trailers->uses_arena)
        free (trailers);
      return NULL;
    }

  return trailers;
}

void
SocketGRPC_Trailers_free (SocketGRPC_Trailers_T *trailers)
{
  if (trailers == NULL || *trailers == NULL)
    return;
  if (!(*trailers)->uses_arena)
    {
      SocketGRPC_Metadata_free (&(*trailers)->metadata);
      free ((*trailers)->grpc_message);
      free ((*trailers)->grpc_status_details_bin);
      free (*trailers);
    }
  *trailers = NULL;
}

void
SocketGRPC_Trailers_clear (SocketGRPC_Trailers_T trailers)
{
  if (trailers == NULL)
    return;

  trailers->has_status = 0;
  trailers->grpc_status = SOCKET_GRPC_STATUS_UNKNOWN;
  if (!trailers->uses_arena)
    {
      free (trailers->grpc_message);
      free (trailers->grpc_status_details_bin);
    }
  trailers->grpc_message = NULL;
  trailers->grpc_status_details_bin = NULL;
  trailers->grpc_status_details_bin_len = 0;
  SocketGRPC_Metadata_clear (trailers->metadata);
}

SocketGRPC_WireResult
SocketGRPC_Trailers_set_status (SocketGRPC_Trailers_T trailers, int grpc_status)
{
  if (trailers == NULL)
    return SOCKET_GRPC_WIRE_INVALID_ARGUMENT;
  if (grpc_status < SOCKET_GRPC_STATUS_OK
      || grpc_status > SOCKET_GRPC_STATUS_UNAUTHENTICATED)
    return SOCKET_GRPC_WIRE_INVALID_TRAILER;
  trailers->grpc_status = grpc_status;
  trailers->has_status = 1;
  return SOCKET_GRPC_WIRE_OK;
}

SocketGRPC_WireResult
SocketGRPC_Trailers_set_message (SocketGRPC_Trailers_T trailers,
                                 const char *grpc_message)
{
  char *copy;
  size_t len;

  if (trailers == NULL || grpc_message == NULL)
    return SOCKET_GRPC_WIRE_INVALID_ARGUMENT;
  len = strlen (grpc_message);
  if (!metadata_ascii_value_valid ((const uint8_t *)grpc_message, len))
    return SOCKET_GRPC_WIRE_INVALID_TRAILER;

  copy = (char *)wire_alloc (trailers->arena, len + 1U);
  if (copy == NULL)
    return SOCKET_GRPC_WIRE_OUT_OF_MEMORY;
  memcpy (copy, grpc_message, len + 1U);

  if (!trailers->uses_arena)
    free (trailers->grpc_message);
  trailers->grpc_message = copy;
  return SOCKET_GRPC_WIRE_OK;
}

SocketGRPC_WireResult
SocketGRPC_Trailers_set_status_details_bin (SocketGRPC_Trailers_T trailers,
                                            const uint8_t *data,
                                            size_t len)
{
  uint8_t *copy = NULL;

  if (trailers == NULL || (data == NULL && len != 0))
    return SOCKET_GRPC_WIRE_INVALID_ARGUMENT;
  if (len > 0)
    {
      copy = (uint8_t *)wire_alloc (trailers->arena, len);
      if (copy == NULL)
        return SOCKET_GRPC_WIRE_OUT_OF_MEMORY;
      memcpy (copy, data, len);
    }

  if (!trailers->uses_arena)
    free (trailers->grpc_status_details_bin);
  trailers->grpc_status_details_bin = copy;
  trailers->grpc_status_details_bin_len = len;
  return SOCKET_GRPC_WIRE_OK;
}

int
SocketGRPC_Trailers_has_status (const SocketGRPC_Trailers_T trailers)
{
  return trailers != NULL ? trailers->has_status : 0;
}

int
SocketGRPC_Trailers_status (const SocketGRPC_Trailers_T trailers)
{
  if (trailers == NULL || !trailers->has_status)
    return SOCKET_GRPC_STATUS_UNKNOWN;
  return trailers->grpc_status;
}

const char *
SocketGRPC_Trailers_message (const SocketGRPC_Trailers_T trailers)
{
  return trailers != NULL ? trailers->grpc_message : NULL;
}

const uint8_t *
SocketGRPC_Trailers_status_details_bin (const SocketGRPC_Trailers_T trailers,
                                        size_t *len)
{
  if (len != NULL)
    *len = trailers != NULL ? trailers->grpc_status_details_bin_len : 0U;
  return trailers != NULL ? trailers->grpc_status_details_bin : NULL;
}

SocketGRPC_Metadata_T
SocketGRPC_Trailers_metadata (const SocketGRPC_Trailers_T trailers)
{
  return trailers != NULL ? trailers->metadata : NULL;
}

SocketGRPC_WireResult
SocketGRPC_Trailers_serialize (const SocketGRPC_Trailers_T trailers,
                               uint8_t *out,
                               size_t out_len,
                               size_t *written)
{
  SocketGRPC_Metadata_T metadata;
  char status_buf[16];
  int status_len;
  SocketGRPC_WireResult rc;
  size_t i;
  size_t cursor = 0;
  const uint8_t sep[] = { ':', ' ' };
  const uint8_t crlf[] = { '\r', '\n' };

  if (trailers == NULL || out == NULL || written == NULL)
    return SOCKET_GRPC_WIRE_INVALID_ARGUMENT;
  if (!trailers->has_status)
    return SOCKET_GRPC_WIRE_INVALID_TRAILER;

  status_len = snprintf (
      status_buf, sizeof (status_buf), "%d", trailers->grpc_status);
  if (status_len <= 0 || (size_t)status_len >= sizeof (status_buf))
    return SOCKET_GRPC_WIRE_INVALID_TRAILER;

  rc = buffer_append (
      out, out_len, &cursor, (const uint8_t *)"grpc-status", 11U);
  if (rc != SOCKET_GRPC_WIRE_OK)
    return rc;
  rc = buffer_append (out, out_len, &cursor, sep, sizeof (sep));
  if (rc != SOCKET_GRPC_WIRE_OK)
    return rc;
  rc = buffer_append (
      out, out_len, &cursor, (const uint8_t *)status_buf, (size_t)status_len);
  if (rc != SOCKET_GRPC_WIRE_OK)
    return rc;
  rc = buffer_append (out, out_len, &cursor, crlf, sizeof (crlf));
  if (rc != SOCKET_GRPC_WIRE_OK)
    return rc;

  if (trailers->grpc_message != NULL)
    {
      size_t message_len = strlen (trailers->grpc_message);
      if (!metadata_ascii_value_valid (
              (const uint8_t *)trailers->grpc_message, message_len))
        return SOCKET_GRPC_WIRE_INVALID_TRAILER;

      rc = buffer_append (
          out, out_len, &cursor, (const uint8_t *)"grpc-message", 12U);
      if (rc != SOCKET_GRPC_WIRE_OK)
        return rc;
      rc = buffer_append (out, out_len, &cursor, sep, sizeof (sep));
      if (rc != SOCKET_GRPC_WIRE_OK)
        return rc;
      rc = buffer_append (out,
                          out_len,
                          &cursor,
                          (const uint8_t *)trailers->grpc_message,
                          message_len);
      if (rc != SOCKET_GRPC_WIRE_OK)
        return rc;
      rc = buffer_append (out, out_len, &cursor, crlf, sizeof (crlf));
      if (rc != SOCKET_GRPC_WIRE_OK)
        return rc;
    }

  if (trailers->grpc_status_details_bin != NULL
      && trailers->grpc_status_details_bin_len > 0)
    {
      size_t encoded_cap
          = SocketCrypto_base64_encoded_size (
              trailers->grpc_status_details_bin_len);
      char *encoded = (char *)malloc (encoded_cap);
      ssize_t encoded_len;
      if (encoded == NULL)
        return SOCKET_GRPC_WIRE_OUT_OF_MEMORY;

      encoded_len = SocketCrypto_base64_encode (trailers->grpc_status_details_bin,
                                                trailers->grpc_status_details_bin_len,
                                                encoded,
                                                encoded_cap);
      if (encoded_len < 0)
        {
          free (encoded);
          return SOCKET_GRPC_WIRE_INVALID_TRAILER;
        }

      rc = buffer_append (out,
                          out_len,
                          &cursor,
                          (const uint8_t *)"grpc-status-details-bin",
                          23U);
      if (rc == SOCKET_GRPC_WIRE_OK)
        rc = buffer_append (out, out_len, &cursor, sep, sizeof (sep));
      if (rc == SOCKET_GRPC_WIRE_OK)
        rc = buffer_append (
            out, out_len, &cursor, (const uint8_t *)encoded, (size_t)encoded_len);
      if (rc == SOCKET_GRPC_WIRE_OK)
        rc = buffer_append (out, out_len, &cursor, crlf, sizeof (crlf));
      free (encoded);
      if (rc != SOCKET_GRPC_WIRE_OK)
        return rc;
    }

  metadata = trailers->metadata;
  if (metadata == NULL)
    return SOCKET_GRPC_WIRE_INVALID_TRAILER;

  for (i = 0; i < metadata->count; i++)
    {
      const SocketGRPC_MetadataEntry *entry = &metadata->entries[i];
      if (is_reserved_trailer_key (entry->key))
        return SOCKET_GRPC_WIRE_INVALID_TRAILER;

      rc = buffer_append (out,
                          out_len,
                          &cursor,
                          (const uint8_t *)entry->key,
                          strlen (entry->key));
      if (rc != SOCKET_GRPC_WIRE_OK)
        return rc;
      rc = buffer_append (out, out_len, &cursor, sep, sizeof (sep));
      if (rc != SOCKET_GRPC_WIRE_OK)
        return rc;

      if (entry->is_binary)
        {
          size_t encoded_cap = SocketCrypto_base64_encoded_size (entry->value_len);
          char *encoded = (char *)malloc (encoded_cap);
          ssize_t encoded_len;
          if (encoded == NULL)
            return SOCKET_GRPC_WIRE_OUT_OF_MEMORY;
          encoded_len = SocketCrypto_base64_encode (
              entry->value, entry->value_len, encoded, encoded_cap);
          if (encoded_len < 0)
            {
              free (encoded);
              return SOCKET_GRPC_WIRE_INVALID_TRAILER;
            }
          rc = buffer_append (out,
                              out_len,
                              &cursor,
                              (const uint8_t *)encoded,
                              (size_t)encoded_len);
          free (encoded);
          if (rc != SOCKET_GRPC_WIRE_OK)
            return rc;
        }
      else
        {
          rc = buffer_append (
              out, out_len, &cursor, entry->value, entry->value_len);
          if (rc != SOCKET_GRPC_WIRE_OK)
            return rc;
        }

      rc = buffer_append (out, out_len, &cursor, crlf, sizeof (crlf));
      if (rc != SOCKET_GRPC_WIRE_OK)
        return rc;
    }

  {
    const uint8_t terminal_crlf[] = { '\r', '\n' };
    rc = buffer_append (
        out, out_len, &cursor, terminal_crlf, sizeof (terminal_crlf));
    if (rc != SOCKET_GRPC_WIRE_OK)
      return rc;
  }

  *written = cursor;
  return SOCKET_GRPC_WIRE_OK;
}

static SocketGRPC_WireResult
parse_status_value (const uint8_t *value, size_t value_len, int *status_out)
{
  int status = 0;
  size_t i;

  if (value == NULL || value_len == 0 || status_out == NULL)
    return SOCKET_GRPC_WIRE_INVALID_TRAILER;

  for (i = 0; i < value_len; i++)
    {
      if (!isdigit (value[i]))
        return SOCKET_GRPC_WIRE_INVALID_TRAILER;
      status = (status * 10) + (int)(value[i] - '0');
      if (status > SOCKET_GRPC_STATUS_UNAUTHENTICATED)
        return SOCKET_GRPC_WIRE_INVALID_TRAILER;
    }

  *status_out = status;
  return SOCKET_GRPC_WIRE_OK;
}

SocketGRPC_WireResult
SocketGRPC_Trailers_parse (SocketGRPC_Trailers_T trailers,
                           const uint8_t *data,
                           size_t len)
{
  SocketGRPC_Metadata_T parsed;
  size_t i;
  int saw_message = 0;
  int saw_details = 0;
  SocketGRPC_WireResult rc = SOCKET_GRPC_WIRE_OK;

  if (trailers == NULL || (data == NULL && len != 0))
    return SOCKET_GRPC_WIRE_INVALID_ARGUMENT;

  SocketGRPC_Trailers_clear (trailers);

  parsed = SocketGRPC_Metadata_new (NULL);
  if (parsed == NULL)
    return SOCKET_GRPC_WIRE_OUT_OF_MEMORY;

  rc = SocketGRPC_Metadata_parse (parsed, data, len);
  if (rc != SOCKET_GRPC_WIRE_OK)
    {
      rc = SOCKET_GRPC_WIRE_INVALID_TRAILER;
      goto fail;
    }

  for (i = 0; i < SocketGRPC_Metadata_count (parsed); i++)
    {
      const SocketGRPC_MetadataEntry *entry = SocketGRPC_Metadata_at (parsed, i);
      if (entry == NULL)
        continue;

      if (strcmp (entry->key, "grpc-status") == 0)
        {
          int status;
          if (trailers->has_status)
            {
              rc = SOCKET_GRPC_WIRE_INVALID_TRAILER;
              goto fail;
            }
          rc = parse_status_value (entry->value, entry->value_len, &status);
          if (rc != SOCKET_GRPC_WIRE_OK)
            goto fail;
          rc = SocketGRPC_Trailers_set_status (trailers, status);
          if (rc != SOCKET_GRPC_WIRE_OK)
            goto fail;
        }
      else if (strcmp (entry->key, "grpc-message") == 0)
        {
          char *tmp;
          if (saw_message)
            {
              rc = SOCKET_GRPC_WIRE_INVALID_TRAILER;
              goto fail;
            }
          tmp = (char *)malloc (entry->value_len + 1U);
          if (tmp == NULL)
            {
              rc = SOCKET_GRPC_WIRE_OUT_OF_MEMORY;
              goto fail;
            }
          memcpy (tmp, entry->value, entry->value_len);
          tmp[entry->value_len] = '\0';
          rc = SocketGRPC_Trailers_set_message (trailers, tmp);
          free (tmp);
          if (rc != SOCKET_GRPC_WIRE_OK)
            goto fail;
          saw_message = 1;
        }
      else if (strcmp (entry->key, "grpc-status-details-bin") == 0)
        {
          if (saw_details)
            {
              rc = SOCKET_GRPC_WIRE_INVALID_TRAILER;
              goto fail;
            }
          rc = SocketGRPC_Trailers_set_status_details_bin (
              trailers, entry->value, entry->value_len);
          if (rc != SOCKET_GRPC_WIRE_OK)
            goto fail;
          saw_details = 1;
        }
      else
        {
          if (entry->is_binary)
            rc = SocketGRPC_Metadata_add_binary (
                trailers->metadata, entry->key, entry->value, entry->value_len);
          else
            {
              char *tmp = (char *)malloc (entry->value_len + 1U);
              if (tmp == NULL)
                {
                  rc = SOCKET_GRPC_WIRE_OUT_OF_MEMORY;
                  goto fail;
                }
              memcpy (tmp, entry->value, entry->value_len);
              tmp[entry->value_len] = '\0';
              rc = SocketGRPC_Metadata_add_ascii (trailers->metadata, entry->key, tmp);
              free (tmp);
            }
          if (rc != SOCKET_GRPC_WIRE_OK)
            goto fail;
        }
    }
  if (!trailers->has_status)
    {
      rc = SOCKET_GRPC_WIRE_INVALID_TRAILER;
      goto fail;
    }

  SocketGRPC_Metadata_free (&parsed);
  return rc;

fail:
  SocketGRPC_Metadata_free (&parsed);
  SocketGRPC_Trailers_clear (trailers);
  return rc;
}

SocketGRPC_StatusCode
SocketGRPC_http_status_to_grpc (int http_status)
{
  switch (http_status)
    {
    case 200:
      return SOCKET_GRPC_STATUS_OK;
    case 400:
      return SOCKET_GRPC_STATUS_INTERNAL;
    case 401:
      return SOCKET_GRPC_STATUS_UNAUTHENTICATED;
    case 403:
      return SOCKET_GRPC_STATUS_PERMISSION_DENIED;
    case 404:
      return SOCKET_GRPC_STATUS_UNIMPLEMENTED;
    case 429:
    case 502:
    case 503:
    case 504:
      return SOCKET_GRPC_STATUS_UNAVAILABLE;
    default:
      return SOCKET_GRPC_STATUS_UNKNOWN;
    }
}
