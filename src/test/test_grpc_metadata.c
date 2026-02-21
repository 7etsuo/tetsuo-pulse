/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#include "grpc/SocketGRPCWire.h"
#include "test/Test.h"

#include <string.h>

TEST (grpc_metadata_ascii_and_binary_roundtrip)
{
  SocketGRPC_Metadata_T metadata = SocketGRPC_Metadata_new (NULL);
  SocketGRPC_Metadata_T parsed = SocketGRPC_Metadata_new (NULL);
  uint8_t wire[512];
  uint8_t trace_id[] = { 0xDE, 0xAD, 0xBE, 0xEF };
  size_t written = 0;
  const SocketGRPC_MetadataEntry *entry0;
  const SocketGRPC_MetadataEntry *entry1;

  ASSERT_NOT_NULL (metadata);
  ASSERT_NOT_NULL (parsed);

  ASSERT_EQ (
      SOCKET_GRPC_WIRE_OK,
      SocketGRPC_Metadata_add_ascii (metadata, "X-Request-Id", "request-123"));
  ASSERT_EQ (SOCKET_GRPC_WIRE_OK,
             SocketGRPC_Metadata_add_binary (
                 metadata, "trace-bin", trace_id, sizeof (trace_id)));

  ASSERT_EQ (
      SOCKET_GRPC_WIRE_OK,
      SocketGRPC_Metadata_serialize (metadata, wire, sizeof (wire), &written));
  ASSERT_NE (0U, written);
  ASSERT_EQ (SOCKET_GRPC_WIRE_OK,
             SocketGRPC_Metadata_parse (parsed, wire, written));
  ASSERT_EQ (2U, SocketGRPC_Metadata_count (parsed));

  entry0 = SocketGRPC_Metadata_at (parsed, 0);
  entry1 = SocketGRPC_Metadata_at (parsed, 1);
  ASSERT_NOT_NULL (entry0);
  ASSERT_NOT_NULL (entry1);

  ASSERT_EQ (0, strcmp (entry0->key, "x-request-id"));
  ASSERT_EQ (0, entry0->is_binary);
  ASSERT_EQ (11U, entry0->value_len);
  ASSERT_EQ (0, memcmp (entry0->value, "request-123", entry0->value_len));

  ASSERT_EQ (0, strcmp (entry1->key, "trace-bin"));
  ASSERT_EQ (1, entry1->is_binary);
  ASSERT_EQ (sizeof (trace_id), entry1->value_len);
  ASSERT_EQ (0, memcmp (entry1->value, trace_id, sizeof (trace_id)));

  SocketGRPC_Metadata_free (&parsed);
  SocketGRPC_Metadata_free (&metadata);
}

TEST (grpc_metadata_rejects_injection_and_invalid_keys)
{
  SocketGRPC_Metadata_T metadata = SocketGRPC_Metadata_new (NULL);
  uint8_t wire_no_colon[] = "broken-header\r\n\r\n";
  uint8_t wire_bad_bin[] = "trace-bin: !!!\r\n\r\n";

  ASSERT_NOT_NULL (metadata);

  ASSERT_EQ (SOCKET_GRPC_WIRE_INVALID_METADATA_KEY,
             SocketGRPC_Metadata_add_ascii (metadata, "Bad:Key", "value"));
  ASSERT_EQ (SOCKET_GRPC_WIRE_INVALID_METADATA_VALUE,
             SocketGRPC_Metadata_add_ascii (metadata, "x-ok", "line\nbreak"));
  ASSERT_EQ (SOCKET_GRPC_WIRE_INVALID_METADATA_KEY,
             SocketGRPC_Metadata_add_binary (
                 metadata, "trace", (const uint8_t *)"x", 1));

  ASSERT_EQ (SOCKET_GRPC_WIRE_INVALID_METADATA_VALUE,
             SocketGRPC_Metadata_parse (
                 metadata, wire_no_colon, sizeof (wire_no_colon) - 1U));
  ASSERT_EQ (SOCKET_GRPC_WIRE_INVALID_METADATA_VALUE,
             SocketGRPC_Metadata_parse (
                 metadata, wire_bad_bin, sizeof (wire_bad_bin) - 1U));

  SocketGRPC_Metadata_free (&metadata);
}

TEST (grpc_trailers_roundtrip_and_extra_metadata)
{
  SocketGRPC_Trailers_T trailers = SocketGRPC_Trailers_new (NULL);
  SocketGRPC_Trailers_T parsed = SocketGRPC_Trailers_new (NULL);
  uint8_t details[] = { 0x01, 0x02, 0x03, 0x04 };
  uint8_t binary_meta[] = { 0xAA, 0xBB };
  uint8_t wire[1024];
  size_t written = 0;
  size_t details_len = 0;
  const uint8_t *parsed_details;
  const SocketGRPC_MetadataEntry *m0;
  const SocketGRPC_MetadataEntry *m1;

  ASSERT_NOT_NULL (trailers);
  ASSERT_NOT_NULL (parsed);

  ASSERT_EQ (SOCKET_GRPC_WIRE_OK,
             SocketGRPC_Trailers_set_status (
                 trailers, SOCKET_GRPC_STATUS_INVALID_ARGUMENT));
  ASSERT_EQ (
      SOCKET_GRPC_WIRE_OK,
      SocketGRPC_Trailers_set_message (trailers, "invalid request payload"));
  ASSERT_EQ (SOCKET_GRPC_WIRE_OK,
             SocketGRPC_Trailers_set_status_details_bin (
                 trailers, details, sizeof (details)));

  ASSERT_EQ (
      SOCKET_GRPC_WIRE_OK,
      SocketGRPC_Metadata_add_ascii (
          SocketGRPC_Trailers_metadata (trailers), "x-trace-id", "abc-42"));
  ASSERT_EQ (
      SOCKET_GRPC_WIRE_OK,
      SocketGRPC_Metadata_add_binary (SocketGRPC_Trailers_metadata (trailers),
                                      "debug-bin",
                                      binary_meta,
                                      sizeof (binary_meta)));

  ASSERT_EQ (
      SOCKET_GRPC_WIRE_OK,
      SocketGRPC_Trailers_serialize (trailers, wire, sizeof (wire), &written));
  ASSERT_NE (0U, written);

  ASSERT_EQ (SOCKET_GRPC_WIRE_OK,
             SocketGRPC_Trailers_parse (parsed, wire, written));
  ASSERT (SocketGRPC_Trailers_has_status (parsed));
  ASSERT_EQ (SOCKET_GRPC_STATUS_INVALID_ARGUMENT,
             SocketGRPC_Trailers_status (parsed));
  ASSERT_EQ (
      0,
      strcmp (SocketGRPC_Trailers_message (parsed), "invalid request payload"));

  parsed_details
      = SocketGRPC_Trailers_status_details_bin (parsed, &details_len);
  ASSERT_EQ (sizeof (details), details_len);
  ASSERT_EQ (0, memcmp (parsed_details, details, sizeof (details)));

  ASSERT_EQ (2U,
             SocketGRPC_Metadata_count (SocketGRPC_Trailers_metadata (parsed)));
  m0 = SocketGRPC_Metadata_at (SocketGRPC_Trailers_metadata (parsed), 0);
  m1 = SocketGRPC_Metadata_at (SocketGRPC_Trailers_metadata (parsed), 1);
  ASSERT_NOT_NULL (m0);
  ASSERT_NOT_NULL (m1);
  ASSERT_EQ (0, strcmp (m0->key, "x-trace-id"));
  ASSERT_EQ (0, m0->is_binary);
  ASSERT_EQ (0, memcmp (m0->value, "abc-42", m0->value_len));
  ASSERT_EQ (0, strcmp (m1->key, "debug-bin"));
  ASSERT_EQ (1, m1->is_binary);
  ASSERT_EQ (sizeof (binary_meta), m1->value_len);
  ASSERT_EQ (0, memcmp (m1->value, binary_meta, sizeof (binary_meta)));

  SocketGRPC_Trailers_free (&parsed);
  SocketGRPC_Trailers_free (&trailers);
}

TEST (grpc_trailers_malformed_corpus_fails_deterministically)
{
  static const char *corpus[] = {
    "grpc-status: nope\r\n\r\n",
    "grpc-message: missing-status\r\n\r\n",
    "grpc-status: 0\r\ngrpc-status: 1\r\n\r\n",
    "grpc-status: 42\r\n\r\n",
    "grpc-status: 0\r\nbroken-line\r\n\r\n",
    "grpc-status: 0\r\ngrpc-status-details-bin: ###\r\n\r\n",
  };
  SocketGRPC_Trailers_T trailers = SocketGRPC_Trailers_new (NULL);
  size_t i;

  ASSERT_NOT_NULL (trailers);

  for (i = 0; i < (sizeof (corpus) / sizeof (corpus[0])); i++)
    {
      const uint8_t *wire = (const uint8_t *)corpus[i];
      size_t wire_len = strlen (corpus[i]);
      ASSERT_EQ (SOCKET_GRPC_WIRE_INVALID_TRAILER,
                 SocketGRPC_Trailers_parse (trailers, wire, wire_len));
      ASSERT_EQ (0, SocketGRPC_Trailers_has_status (trailers));
    }

  SocketGRPC_Trailers_free (&trailers);
}

TEST (grpc_trailers_reject_reserved_metadata_keys_on_serialize)
{
  SocketGRPC_Trailers_T trailers = SocketGRPC_Trailers_new (NULL);
  uint8_t wire[256];
  size_t written = 0;

  ASSERT_NOT_NULL (trailers);
  ASSERT_EQ (SOCKET_GRPC_WIRE_OK,
             SocketGRPC_Trailers_set_status (trailers, SOCKET_GRPC_STATUS_OK));
  ASSERT_EQ (SOCKET_GRPC_WIRE_OK,
             SocketGRPC_Metadata_add_ascii (
                 SocketGRPC_Trailers_metadata (trailers), "grpc-status", "7"));
  ASSERT_EQ (
      SOCKET_GRPC_WIRE_INVALID_TRAILER,
      SocketGRPC_Trailers_serialize (trailers, wire, sizeof (wire), &written));

  SocketGRPC_Trailers_free (&trailers);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
