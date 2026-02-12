/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#include "complex.socketgrpc.h"
#include "core/Arena.h"
#include "grpc/SocketGRPC.h"
#include "test/Test.h"

#include <string.h>

static int
handle_process (const test_complex_ComplexRequest *request,
                test_complex_ComplexResponse *response,
                void *userdata,
                Arena_T arena)
{
  (void)userdata;
  (void)arena;
  if (request == NULL || response == NULL || !request->has_envelope)
    return SOCKET_GRPC_STATUS_INVALID_ARGUMENT;

  response->accepted = 1;
  response->reason = "processed";
  return SOCKET_GRPC_STATUS_OK;
}

TEST (grpc_codegen_complex_message_roundtrip)
{
  test_complex_ComplexRequest request;
  test_complex_ComplexRequest decoded;
  uint8_t wire[4096];
  size_t written = 0;
  char *tags[] = { "alpha", "beta" };
  uint32_t scores[] = { 10, 20, 30 };
  uint8_t attachment_a[] = { 0x01, 0x02 };
  uint8_t attachment_b[] = { 0x03, 0x04, 0x05 };
  uint8_t *attachments[] = { attachment_a, attachment_b };
  size_t attachment_lens[] = { sizeof (attachment_a), sizeof (attachment_b) };
  char *notes[] = { "n1", "n2" };
  uint32_t codes[] = { 7, 8, 9 };
  Arena_T arena = Arena_new ();

  test_complex_ComplexRequest_init (&request);
  test_complex_ComplexRequest_init (&decoded);

  request.has_envelope = 1;
  request.envelope.has_meta = 1;
  request.envelope.meta.timestamp = 123456U;
  request.envelope.meta.source = "sensor-a";
  request.envelope.tags = tags;
  request.envelope.tags_count = sizeof (tags) / sizeof (tags[0]);
  request.envelope.scores = scores;
  request.envelope.scores_count = sizeof (scores) / sizeof (scores[0]);
  request.envelope.attachments = attachments;
  request.envelope.attachments_len = attachment_lens;
  request.envelope.attachments_count
      = sizeof (attachments) / sizeof (attachments[0]);
  request.envelope.payload_case = TEST_COMPLEX_ENVELOPE_PAYLOADCASE_TEXT;
  request.envelope.payload.text = "payload";
  request.notes = notes;
  request.notes_count = sizeof (notes) / sizeof (notes[0]);
  request.codes = codes;
  request.codes_count = sizeof (codes) / sizeof (codes[0]);

  ASSERT_EQ (0, test_complex_ComplexRequest_encode (
                    &request, wire, sizeof (wire), &written));
  ASSERT_NE (0U, written);
  ASSERT_EQ (0, test_complex_ComplexRequest_decode (&decoded, wire, written, arena));

  ASSERT (decoded.has_envelope);
  ASSERT (decoded.envelope.has_meta);
  ASSERT_EQ (123456U, decoded.envelope.meta.timestamp);
  ASSERT_NOT_NULL (decoded.envelope.meta.source);
  ASSERT_EQ (0, strcmp (decoded.envelope.meta.source, "sensor-a"));
  ASSERT_EQ (2U, decoded.envelope.tags_count);
  ASSERT_EQ (0, strcmp (decoded.envelope.tags[0], "alpha"));
  ASSERT_EQ (0, strcmp (decoded.envelope.tags[1], "beta"));
  ASSERT_EQ (3U, decoded.envelope.scores_count);
  ASSERT_EQ (10U, decoded.envelope.scores[0]);
  ASSERT_EQ (20U, decoded.envelope.scores[1]);
  ASSERT_EQ (30U, decoded.envelope.scores[2]);
  ASSERT_EQ (2U, decoded.envelope.attachments_count);
  ASSERT_EQ (sizeof (attachment_a), decoded.envelope.attachments_len[0]);
  ASSERT_EQ (sizeof (attachment_b), decoded.envelope.attachments_len[1]);
  ASSERT_EQ (0,
             memcmp (decoded.envelope.attachments[0], attachment_a,
                     sizeof (attachment_a)));
  ASSERT_EQ (0,
             memcmp (decoded.envelope.attachments[1], attachment_b,
                     sizeof (attachment_b)));
  ASSERT_EQ (TEST_COMPLEX_ENVELOPE_PAYLOADCASE_TEXT,
             decoded.envelope.payload_case);
  ASSERT_EQ (0, strcmp (decoded.envelope.payload.text, "payload"));
  ASSERT_EQ (2U, decoded.notes_count);
  ASSERT_EQ (0, strcmp (decoded.notes[0], "n1"));
  ASSERT_EQ (0, strcmp (decoded.notes[1], "n2"));
  ASSERT_EQ (3U, decoded.codes_count);
  ASSERT_EQ (7U, decoded.codes[0]);
  ASSERT_EQ (8U, decoded.codes[1]);
  ASSERT_EQ (9U, decoded.codes[2]);

  test_complex_ComplexRequest_free (&decoded);
  test_complex_ComplexRequest_free (&request);
  Arena_dispose (&arena);
}

TEST (grpc_codegen_complex_oneof_numeric_roundtrip)
{
  test_complex_Envelope envelope;
  test_complex_Envelope decoded;
  uint8_t wire[512];
  size_t written = 0;
  Arena_T arena = Arena_new ();

  test_complex_Envelope_init (&envelope);
  test_complex_Envelope_init (&decoded);

  envelope.payload_case = TEST_COMPLEX_ENVELOPE_PAYLOADCASE_REF_ID;
  envelope.payload.ref_id = 987654321ULL;

  ASSERT_EQ (0,
             test_complex_Envelope_encode (&envelope, wire, sizeof (wire), &written));
  ASSERT_NE (0U, written);
  ASSERT_EQ (0, test_complex_Envelope_decode (&decoded, wire, written, arena));
  ASSERT_EQ (TEST_COMPLEX_ENVELOPE_PAYLOADCASE_REF_ID, decoded.payload_case);
  ASSERT_EQ (987654321ULL, decoded.payload.ref_id);

  test_complex_Envelope_free (&decoded);
  test_complex_Envelope_free (&envelope);
  Arena_dispose (&arena);
}

TEST (grpc_codegen_complex_service_local_handler)
{
  test_complex_ComplexService_Client client;
  test_complex_ComplexService_ServerHandlers handlers;
  test_complex_ComplexRequest request;
  test_complex_ComplexResponse response;
  Arena_T arena = Arena_new ();

  memset (&handlers, 0, sizeof (handlers));
  handlers.Process = handle_process;

  test_complex_ComplexService_Client_init (&client, NULL);
  test_complex_ComplexService_Client_bind_local (&client, &handlers);
  test_complex_ComplexRequest_init (&request);
  test_complex_ComplexResponse_init (&response);
  request.has_envelope = 1;

  ASSERT_EQ (SOCKET_GRPC_STATUS_OK,
             test_complex_ComplexService_Client_Process (
                 &client, &request, &response, arena));
  ASSERT_EQ (1, response.accepted);
  ASSERT_NOT_NULL (response.reason);
  ASSERT_EQ (0, strcmp (response.reason, "processed"));

  test_complex_ComplexResponse_free (&response);
  test_complex_ComplexRequest_free (&request);
  Arena_dispose (&arena);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
