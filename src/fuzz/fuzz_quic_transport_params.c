/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_quic_transport_params.c - libFuzzer for QUIC Transport Parameters
 *
 * Fuzzes QUIC transport parameter encoding/decoding (RFC 9000 Section 18).
 * Tests TLV parsing, value validation, and role-specific parameter handling.
 *
 * Targets:
 * - TLV decoding with various parameter IDs
 * - Role-specific parameter validation (client vs server)
 * - Value range validation (ack_delay_exponent, max_ack_delay)
 * - Duplicate parameter detection
 * - Unknown parameter handling (GREASE)
 * - Preferred address parsing
 * - Roundtrip verification
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make
 * fuzz_quic_transport_params
 * ./fuzz_quic_transport_params -fork=16 -max_len=4096
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "quic/SocketQUICTransportParams.h"

/**
 * @brief Operations to fuzz
 */
enum FuzzOp
{
  OP_DECODE_CLIENT = 0,
  OP_DECODE_SERVER,
  OP_VALIDATE_CLIENT,
  OP_VALIDATE_SERVER,
  OP_VALIDATE_REQUIRED_CLIENT,
  OP_VALIDATE_REQUIRED_SERVER,
  OP_ROUNDTRIP_CLIENT,
  OP_ROUNDTRIP_SERVER,
  OP_ENCODED_SIZE,
  OP_SET_DEFAULTS,
  OP_COPY,
  OP_EFFECTIVE_TIMEOUT,
  OP_MAX
};

/**
 * @brief Read 64-bit value from byte array (little-endian)
 */
static uint64_t
read_u64 (const uint8_t *p)
{
  return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16)
         | ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32)
         | ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48)
         | ((uint64_t)p[7] << 56);
}

/**
 * @brief Read 16-bit value from byte array (little-endian)
 */
static uint16_t
read_u16 (const uint8_t *p)
{
  return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 1)
    return 0;

  uint8_t op = data[0] % OP_MAX;
  SocketQUICTransportParams_Result res;

  switch (op)
    {
    case OP_DECODE_CLIENT:
      {
        /* Decode as if received from client (parse server params) */
        if (size > 1)
          {
            SocketQUICTransportParams_T params;
            SocketQUICTransportParams_init (&params);
            size_t consumed = 0;
            res = SocketQUICTransportParams_decode (
                data + 1, size - 1, QUIC_ROLE_CLIENT, &params, &consumed);
            (void)res;
            (void)consumed;

            /* Access decoded values to ensure they're valid */
            (void)params.max_idle_timeout;
            (void)params.max_udp_payload_size;
            (void)params.initial_max_data;
            (void)params.ack_delay_exponent;
          }
      }
      break;

    case OP_DECODE_SERVER:
      {
        /* Decode as if received from server (parse client params) */
        if (size > 1)
          {
            SocketQUICTransportParams_T params;
            SocketQUICTransportParams_init (&params);
            size_t consumed = 0;
            res = SocketQUICTransportParams_decode (
                data + 1, size - 1, QUIC_ROLE_SERVER, &params, &consumed);
            (void)res;

            /* Check server-specific fields */
            (void)params.has_stateless_reset_token;
            (void)params.preferred_address.present;
          }
      }
      break;

    case OP_VALIDATE_CLIENT:
      {
        /* Create params with fuzz-derived values and validate */
        if (size >= 25)
          {
            SocketQUICTransportParams_T params;
            SocketQUICTransportParams_init (&params);

            params.max_idle_timeout = read_u64 (data + 1);
            params.max_udp_payload_size = read_u64 (data + 9);
            params.ack_delay_exponent = data[17] % 30; /* May exceed max */
            params.max_ack_delay = read_u16 (data + 18) % 20000;
            params.active_connection_id_limit = data[20] % 10;

            res = SocketQUICTransportParams_validate (&params,
                                                      QUIC_ROLE_CLIENT);
            (void)res;
          }
      }
      break;

    case OP_VALIDATE_SERVER:
      {
        /* Validate server parameters */
        if (size >= 25)
          {
            SocketQUICTransportParams_T params;
            SocketQUICTransportParams_init (&params);

            params.max_idle_timeout = read_u64 (data + 1);
            params.initial_max_data = read_u64 (data + 9);
            params.has_original_dcid = data[17] & 1;
            params.has_stateless_reset_token = data[17] & 2;
            params.disable_active_migration = data[17] & 4;

            res = SocketQUICTransportParams_validate (&params,
                                                      QUIC_ROLE_SERVER);
            (void)res;
          }
      }
      break;

    case OP_VALIDATE_REQUIRED_CLIENT:
      {
        SocketQUICTransportParams_T params;
        SocketQUICTransportParams_init (&params);

        /* Optionally set some required params based on fuzz data */
        if (size > 1)
          {
            params.has_initial_scid = data[1] & 1;
          }

        res = SocketQUICTransportParams_validate_required (&params,
                                                           QUIC_ROLE_CLIENT);
        (void)res;
      }
      break;

    case OP_VALIDATE_REQUIRED_SERVER:
      {
        SocketQUICTransportParams_T params;
        SocketQUICTransportParams_init (&params);

        /* Optionally set some required params based on fuzz data */
        if (size > 1)
          {
            params.has_initial_scid = data[1] & 1;
            params.has_original_dcid = data[1] & 2;
          }

        res = SocketQUICTransportParams_validate_required (&params,
                                                           QUIC_ROLE_SERVER);
        (void)res;
      }
      break;

    case OP_ROUNDTRIP_CLIENT:
      {
        /* Encode then decode client params */
        SocketQUICTransportParams_T params;
        SocketQUICTransportParams_set_defaults (&params, QUIC_ROLE_CLIENT);

        /* Modify some values with fuzz data */
        if (size >= 17)
          {
            params.max_idle_timeout = read_u64 (data + 1) % 100000;
            params.initial_max_data = read_u64 (data + 9) % 1000000;
          }

        uint8_t encoded[QUIC_TP_MAX_ENCODED_SIZE];
        size_t encoded_len = SocketQUICTransportParams_encode (
            &params, QUIC_ROLE_CLIENT, encoded, sizeof (encoded));

        if (encoded_len > 0)
          {
            SocketQUICTransportParams_T decoded;
            SocketQUICTransportParams_init (&decoded);
            size_t consumed = 0;
            res = SocketQUICTransportParams_decode (
                encoded, encoded_len, QUIC_ROLE_CLIENT, &decoded, &consumed);
            (void)res;
            (void)decoded.max_idle_timeout;
          }
      }
      break;

    case OP_ROUNDTRIP_SERVER:
      {
        /* Encode then decode server params */
        SocketQUICTransportParams_T params;
        SocketQUICTransportParams_set_defaults (&params, QUIC_ROLE_SERVER);

        /* Modify some values with fuzz data */
        if (size >= 17)
          {
            params.max_idle_timeout = read_u64 (data + 1) % 100000;
            params.initial_max_streams_bidi = read_u64 (data + 9) % 1000;
          }

        uint8_t encoded[QUIC_TP_MAX_ENCODED_SIZE];
        size_t encoded_len = SocketQUICTransportParams_encode (
            &params, QUIC_ROLE_SERVER, encoded, sizeof (encoded));

        if (encoded_len > 0)
          {
            SocketQUICTransportParams_T decoded;
            SocketQUICTransportParams_init (&decoded);
            size_t consumed = 0;
            res = SocketQUICTransportParams_decode (
                encoded, encoded_len, QUIC_ROLE_SERVER, &decoded, &consumed);
            (void)res;
          }
      }
      break;

    case OP_ENCODED_SIZE:
      {
        SocketQUICTransportParams_T params;
        SocketQUICTransportParams_init (&params);

        size_t client_size = SocketQUICTransportParams_encoded_size (
            &params, QUIC_ROLE_CLIENT);
        size_t server_size = SocketQUICTransportParams_encoded_size (
            &params, QUIC_ROLE_SERVER);
        (void)client_size;
        (void)server_size;

        /* With defaults set */
        SocketQUICTransportParams_set_defaults (&params, QUIC_ROLE_CLIENT);
        client_size = SocketQUICTransportParams_encoded_size (&params,
                                                              QUIC_ROLE_CLIENT);
        (void)client_size;
      }
      break;

    case OP_SET_DEFAULTS:
      {
        SocketQUICTransportParams_T client_params;
        SocketQUICTransportParams_T server_params;

        SocketQUICTransportParams_init (&client_params);
        SocketQUICTransportParams_init (&server_params);

        SocketQUICTransportParams_set_defaults (&client_params,
                                                QUIC_ROLE_CLIENT);
        SocketQUICTransportParams_set_defaults (&server_params,
                                                QUIC_ROLE_SERVER);

        /* Access values */
        (void)client_params.max_udp_payload_size;
        (void)server_params.active_connection_id_limit;
      }
      break;

    case OP_COPY:
      {
        SocketQUICTransportParams_T src;
        SocketQUICTransportParams_T dst;

        SocketQUICTransportParams_set_defaults (&src, QUIC_ROLE_CLIENT);

        res = SocketQUICTransportParams_copy (&dst, &src);
        (void)res;
        (void)dst.max_idle_timeout;

        /* Test NULL handling */
        res = SocketQUICTransportParams_copy (NULL, &src);
        (void)res;
        res = SocketQUICTransportParams_copy (&dst, NULL);
        (void)res;
      }
      break;

    case OP_EFFECTIVE_TIMEOUT:
      {
        SocketQUICTransportParams_T local;
        SocketQUICTransportParams_T remote;

        SocketQUICTransportParams_init (&local);
        SocketQUICTransportParams_init (&remote);

        if (size >= 17)
          {
            local.max_idle_timeout = read_u64 (data + 1);
            remote.max_idle_timeout = read_u64 (data + 9);
          }

        uint64_t effective = SocketQUICTransportParams_effective_idle_timeout (
            &local, &remote);
        (void)effective;
      }
      break;

    default:
      break;
    }

  /* Always test decoding raw fuzz data */
  if (size > 1)
    {
      SocketQUICTransportParams_T params;
      SocketQUICTransportParams_init (&params);
      size_t consumed = 0;

      /* Try both roles */
      res = SocketQUICTransportParams_decode (
          data + 1, size - 1, QUIC_ROLE_CLIENT, &params, &consumed);
      (void)res;

      SocketQUICTransportParams_init (&params);
      consumed = 0;
      res = SocketQUICTransportParams_decode (
          data + 1, size - 1, QUIC_ROLE_SERVER, &params, &consumed);
      (void)res;
    }

  /* Test string functions */
  {
    const char *s1 = SocketQUICTransportParams_result_string (QUIC_TP_OK);
    const char *s2
        = SocketQUICTransportParams_result_string (QUIC_TP_ERROR_INVALID_VALUE);
    const char *s3
        = SocketQUICTransportParams_id_string (QUIC_TP_MAX_IDLE_TIMEOUT);
    const char *s4 = SocketQUICTransportParams_id_string (
        (SocketQUICTransportParamID)0xFFFF);
    (void)s1;
    (void)s2;
    (void)s3;
    (void)s4;
  }

  return 0;
}
