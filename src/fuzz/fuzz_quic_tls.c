/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_quic_tls.c - libFuzzer for QUIC TLS Integration (RFC 9001)
 *
 * Fuzzes TLS-related functions and transport parameter handling:
 * - TLS result string functions
 * - Transport parameter encoding/decoding
 * - Transport parameter validation
 * - 0-RTT parameter validation
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_quic_tls
 * ./fuzz_quic_tls corpus/quic_tls/ -fork=16 -max_len=4096
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "quic/SocketQUICTLS.h"
#include "quic/SocketQUICTransportParams.h"

/* Operation types */
enum
{
  OP_TRANSPORT_PARAMS_ENCODE,
  OP_TRANSPORT_PARAMS_DECODE,
  OP_TRANSPORT_PARAMS_VALIDATE,
  OP_0RTT_VALIDATION,
  OP_STRING_FUNCTIONS,
  OP_MAX
};

/* Helper to read uint64_t from buffer */
static uint64_t
read_u64 (const uint8_t *data)
{
  uint64_t val = 0;
  for (int i = 0; i < 8; i++)
    val = (val << 8) | data[i];
  return val;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 50)
    return 0;

  volatile Arena_T arena = Arena_new ();
  if (!arena)
    return 0;

  TRY
  {
    uint8_t op = data[0] % OP_MAX;

    switch (op)
      {
      case OP_TRANSPORT_PARAMS_ENCODE:
        {
          /* Test transport parameter encoding */
          SocketQUICTransportParams_T params;
          SocketQUICTransportParams_init (&params);

          /* Fill params from fuzz data */
          params.max_idle_timeout = read_u64 (data + 1);
          params.max_udp_payload_size = (read_u64 (data + 9) % 65536) + 1200;
          params.initial_max_data = read_u64 (data + 17);
          params.initial_max_stream_data_bidi_local = read_u64 (data + 25);
          params.initial_max_stream_data_bidi_remote = read_u64 (data + 33);
          params.initial_max_stream_data_uni = read_u64 (data + 41);
          params.initial_max_streams_bidi = (data[49] % 100) + 1;

          /* Try to encode parameters as client and server */
          uint8_t encoded[1024];

          size_t encoded_len = SocketQUICTransportParams_encode (
              &params, QUIC_ROLE_CLIENT, encoded, sizeof (encoded));
          (void)encoded_len;

          encoded_len = SocketQUICTransportParams_encode (
              &params, QUIC_ROLE_SERVER, encoded, sizeof (encoded));
          (void)encoded_len;

          /* Test encoded size calculation */
          size_t calc_size = SocketQUICTransportParams_encoded_size (
              &params, QUIC_ROLE_CLIENT);
          (void)calc_size;

          /* Test NULL inputs */
          SocketQUICTransportParams_encode (NULL, QUIC_ROLE_CLIENT, encoded,
                                            sizeof (encoded));
          SocketQUICTransportParams_encode (&params, QUIC_ROLE_CLIENT, NULL,
                                            sizeof (encoded));
          SocketQUICTransportParams_encoded_size (NULL, QUIC_ROLE_CLIENT);
          break;
        }

      case OP_TRANSPORT_PARAMS_DECODE:
        {
          /* Test transport parameter decoding */
          SocketQUICTransportParams_T decoded;
          SocketQUICTransportParams_init (&decoded);
          size_t consumed = 0;

          /* Try to decode fuzzed data as transport params from client */
          SocketQUICTransportParams_Result result
              = SocketQUICTransportParams_decode (data + 1, size - 1,
                                                  QUIC_ROLE_CLIENT, &decoded,
                                                  &consumed);
          (void)result;

          /* Also try from server role */
          SocketQUICTransportParams_init (&decoded);
          consumed = 0;
          result = SocketQUICTransportParams_decode (
              data + 1, size - 1, QUIC_ROLE_SERVER, &decoded, &consumed);
          (void)result;

          /* Test NULL inputs */
          SocketQUICTransportParams_decode (NULL, 0, QUIC_ROLE_CLIENT, &decoded,
                                            &consumed);
          SocketQUICTransportParams_decode (data, size, QUIC_ROLE_CLIENT, NULL,
                                            &consumed);
          SocketQUICTransportParams_decode (data, size, QUIC_ROLE_CLIENT,
                                            &decoded, NULL);
          break;
        }

      case OP_TRANSPORT_PARAMS_VALIDATE:
        {
          /* Test transport parameter validation */
          SocketQUICTransportParams_T params;
          SocketQUICTransportParams_init (&params);

          /* Fill with fuzzed values */
          params.max_idle_timeout = read_u64 (data + 1);
          params.max_udp_payload_size = read_u64 (data + 9);
          params.initial_max_data = read_u64 (data + 17);
          params.ack_delay_exponent = data[25];
          params.max_ack_delay = read_u64 (data + 26);
          params.active_connection_id_limit = data[34];

          /* Validate as client and server */
          SocketQUICTransportParams_Result result
              = SocketQUICTransportParams_validate (&params, QUIC_ROLE_CLIENT);
          (void)result;

          result
              = SocketQUICTransportParams_validate (&params, QUIC_ROLE_SERVER);
          (void)result;

          /* Test required params validation */
          result = SocketQUICTransportParams_validate_required (
              &params, QUIC_ROLE_CLIENT);
          (void)result;

          result = SocketQUICTransportParams_validate_required (
              &params, QUIC_ROLE_SERVER);
          (void)result;

          /* Test NULL inputs */
          SocketQUICTransportParams_validate (NULL, QUIC_ROLE_CLIENT);
          SocketQUICTransportParams_validate_required (NULL, QUIC_ROLE_CLIENT);
          break;
        }

      case OP_0RTT_VALIDATION:
        {
          /* Test 0-RTT transport parameter validation */
          SocketQUICTransportParams_T original;
          SocketQUICTransportParams_T resumption;

          SocketQUICTransportParams_init (&original);
          SocketQUICTransportParams_init (&resumption);

          /* Set up original params */
          original.max_idle_timeout = read_u64 (data + 1);
          original.initial_max_data = read_u64 (data + 9);
          original.initial_max_stream_data_bidi_local = read_u64 (data + 17);
          original.initial_max_stream_data_bidi_remote = read_u64 (data + 25);
          original.initial_max_stream_data_uni = read_u64 (data + 33);
          original.initial_max_streams_bidi = data[41] % 100;
          original.initial_max_streams_uni = data[42] % 100;
          original.active_connection_id_limit = (data[43] % 8) + 2;

          /* Set up resumption params (may be same or different) */
          if (data[44] & 1)
            {
              /* Same as original */
              memcpy (&resumption, &original, sizeof (resumption));
            }
          else
            {
              /* Different values */
              resumption.max_idle_timeout
                  = read_u64 (data + 45 % (size > 52 ? size - 8 : 1));
              resumption.initial_max_data = original.initial_max_data * 2;
              resumption.initial_max_streams_bidi
                  = original.initial_max_streams_bidi + 10;
            }

          /* Validate 0-RTT params */
          SocketQUICTLS_Result result
              = SocketQUICTLS_validate_0rtt_params (&original, &resumption);
          (void)result;

          /* Test cases where resumption params are smaller (should fail) */
          resumption.initial_max_data = original.initial_max_data / 2;
          result = SocketQUICTLS_validate_0rtt_params (&original, &resumption);
          (void)result;

          resumption.initial_max_data = original.initial_max_data;
          resumption.initial_max_streams_bidi = 0;
          result = SocketQUICTLS_validate_0rtt_params (&original, &resumption);
          (void)result;

          /* Test NULL inputs */
          SocketQUICTLS_validate_0rtt_params (NULL, &resumption);
          SocketQUICTLS_validate_0rtt_params (&original, NULL);
          break;
        }

      case OP_STRING_FUNCTIONS:
        {
          /* Test all TLS-related string functions */

          /* TLS Result codes */
          SocketQUICTLS_Result tls_results[]
              = { QUIC_TLS_OK,          QUIC_TLS_ERROR_NULL,
                  QUIC_TLS_ERROR_INIT,  QUIC_TLS_ERROR_CERT,
                  QUIC_TLS_ERROR_KEY,   QUIC_TLS_ERROR_ALPN,
                  QUIC_TLS_ERROR_TRANSPORT, QUIC_TLS_ERROR_HANDSHAKE,
                  QUIC_TLS_ERROR_SECRETS, QUIC_TLS_ERROR_ALERT,
                  QUIC_TLS_ERROR_NO_TLS, QUIC_TLS_ERROR_WANT_READ,
                  QUIC_TLS_ERROR_WANT_WRITE, QUIC_TLS_ERROR_LEVEL };
          for (size_t i = 0;
               i < sizeof (tls_results) / sizeof (tls_results[0]); i++)
            {
              const char *str = SocketQUICTLS_result_string (tls_results[i]);
              (void)str;
            }
          /* Test with fuzzed value */
          SocketQUICTLS_result_string ((SocketQUICTLS_Result)data[1]);

          /* Transport params result codes */
          SocketQUICTransportParams_Result tp_results[]
              = { QUIC_TP_OK,
                  QUIC_TP_ERROR_NULL,
                  QUIC_TP_ERROR_BUFFER,
                  QUIC_TP_ERROR_INCOMPLETE,
                  QUIC_TP_ERROR_INVALID_VALUE,
                  QUIC_TP_ERROR_DUPLICATE,
                  QUIC_TP_ERROR_ROLE,
                  QUIC_TP_ERROR_REQUIRED,
                  QUIC_TP_ERROR_ENCODING };
          for (size_t i = 0; i < sizeof (tp_results) / sizeof (tp_results[0]);
               i++)
            {
              const char *str
                  = SocketQUICTransportParams_result_string (tp_results[i]);
              (void)str;
            }
          /* Test with fuzzed value */
          SocketQUICTransportParams_result_string (
              (SocketQUICTransportParams_Result)data[2]);

          /* Test transport param ID strings */
          SocketQUICTransportParamID ids[] = {
            QUIC_TP_ORIGINAL_DCID,
            QUIC_TP_MAX_IDLE_TIMEOUT,
            QUIC_TP_STATELESS_RESET_TOKEN,
            QUIC_TP_MAX_UDP_PAYLOAD_SIZE,
            QUIC_TP_INITIAL_MAX_DATA,
            QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI,
            QUIC_TP_INITIAL_MAX_STREAMS_BIDI,
            QUIC_TP_INITIAL_MAX_STREAMS_UNI,
            QUIC_TP_ACK_DELAY_EXPONENT,
            QUIC_TP_MAX_ACK_DELAY,
            QUIC_TP_DISABLE_ACTIVE_MIGRATION,
            QUIC_TP_PREFERRED_ADDRESS,
            QUIC_TP_ACTIVE_CONNID_LIMIT,
            QUIC_TP_INITIAL_SCID,
            QUIC_TP_RETRY_SCID
          };
          for (size_t i = 0; i < sizeof (ids) / sizeof (ids[0]); i++)
            {
              const char *str = SocketQUICTransportParams_id_string (ids[i]);
              (void)str;
            }
          /* Test with fuzzed value */
          SocketQUICTransportParams_id_string (
              (SocketQUICTransportParamID)data[3]);
          break;
        }
      }
  }
  EXCEPT (Arena_Failed)
  {
    /* Expected on allocation failure */
  }
  END_TRY;

  Arena_dispose ((Arena_T *)&arena);
  return 0;
}
