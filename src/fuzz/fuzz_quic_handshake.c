/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_quic_handshake.c - libFuzzer for QUIC Handshake (RFC 9000 Section 7)
 *
 * Fuzzes handshake state machine and key management:
 * - Handshake state transitions
 * - Key availability checks
 * - Key discard triggers
 * - 0-RTT early data state machine
 * - Transport parameter handling
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_quic_handshake
 * ./fuzz_quic_handshake corpus/quic_handshake/ -fork=16 -max_len=4096
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "quic/SocketQUICConnection.h"
#include "quic/SocketQUICHandshake.h"
#include "quic/SocketQUICTransportParams.h"

/* Operation types */
enum
{
  OP_HANDSHAKE_LIFECYCLE,
  OP_KEY_MANAGEMENT,
  OP_KEY_DISCARD,
  OP_0RTT_STATE,
  OP_TRANSPORT_PARAMS,
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
      case OP_HANDSHAKE_LIFECYCLE:
        {
          /* Test handshake creation and state queries */
          SocketQUICConnection_Role role
              = (data[1] & 1) ? QUIC_CONN_ROLE_SERVER : QUIC_CONN_ROLE_CLIENT;

          SocketQUICConnection_T conn
              = SocketQUICConnection_new (arena, role);
          if (!conn)
            break;

          SocketQUICHandshake_T hs
              = SocketQUICHandshake_new (arena, conn, role);
          if (!hs)
            break;

          /* Query initial state */
          SocketQUICHandshakeState state = SocketQUICHandshake_get_state (hs);
          int is_complete = SocketQUICHandshake_is_complete (hs);
          int is_confirmed = SocketQUICHandshake_is_confirmed (hs);
          (void)state;
          (void)is_complete;
          (void)is_confirmed;

          /* Get peer params (should be NULL initially) */
          const SocketQUICTransportParams_T *peer_params
              = SocketQUICHandshake_get_peer_params (hs);
          (void)peer_params;

          /* Try process (may fail without TLS setup, but exercises code paths) */
          SocketQUICHandshake_Result result = SocketQUICHandshake_process (hs);
          (void)result;

          /* Test NULL inputs */
          SocketQUICHandshake_get_state (NULL);
          SocketQUICHandshake_is_complete (NULL);
          SocketQUICHandshake_is_confirmed (NULL);
          SocketQUICHandshake_get_peer_params (NULL);
          SocketQUICHandshake_process (NULL);

          /* Free */
          SocketQUICHandshake_free (&hs);
          break;
        }

      case OP_KEY_MANAGEMENT:
        {
          /* Test key availability and retrieval */
          SocketQUICConnection_Role role
              = (data[1] & 1) ? QUIC_CONN_ROLE_SERVER : QUIC_CONN_ROLE_CLIENT;

          SocketQUICConnection_T conn
              = SocketQUICConnection_new (arena, role);
          if (!conn)
            break;

          SocketQUICHandshake_T hs
              = SocketQUICHandshake_new (arena, conn, role);
          if (!hs)
            break;

          /* Check key availability for all levels */
          for (int level = 0; level < QUIC_CRYPTO_LEVEL_COUNT; level++)
            {
              int has_keys
                  = SocketQUICHandshake_has_keys (hs, (SocketQUICCryptoLevel)level);
              void *keys
                  = SocketQUICHandshake_get_keys (hs, (SocketQUICCryptoLevel)level);
              (void)has_keys;
              (void)keys;
            }

          /* Check send/receive availability */
          int can_send_init = SocketQUICHandshake_can_send_initial (hs);
          int can_recv_init = SocketQUICHandshake_can_receive_initial (hs);
          int can_send_hs = SocketQUICHandshake_can_send_handshake (hs);
          int can_recv_hs = SocketQUICHandshake_can_receive_handshake (hs);
          int can_send_0rtt = SocketQUICHandshake_can_send_0rtt (hs);
          int can_recv_0rtt = SocketQUICHandshake_can_receive_0rtt (hs);
          (void)can_send_init;
          (void)can_recv_init;
          (void)can_send_hs;
          (void)can_recv_hs;
          (void)can_send_0rtt;
          (void)can_recv_0rtt;

          /* Discard keys */
          for (int level = 0; level < QUIC_CRYPTO_LEVEL_COUNT; level++)
            {
              SocketQUICHandshake_discard_keys (hs, (SocketQUICCryptoLevel)level);
            }

          /* Test NULL inputs */
          SocketQUICHandshake_has_keys (NULL, QUIC_CRYPTO_LEVEL_INITIAL);
          SocketQUICHandshake_get_keys (NULL, QUIC_CRYPTO_LEVEL_INITIAL);
          SocketQUICHandshake_discard_keys (NULL, QUIC_CRYPTO_LEVEL_INITIAL);
          SocketQUICHandshake_can_send_initial (NULL);
          SocketQUICHandshake_can_receive_initial (NULL);
          SocketQUICHandshake_can_send_handshake (NULL);
          SocketQUICHandshake_can_receive_handshake (NULL);
          SocketQUICHandshake_can_send_0rtt (NULL);
          SocketQUICHandshake_can_receive_0rtt (NULL);

          SocketQUICHandshake_free (&hs);
          break;
        }

      case OP_KEY_DISCARD:
        {
          /* Test key discard trigger functions */
          SocketQUICConnection_Role role
              = (data[1] & 1) ? QUIC_CONN_ROLE_SERVER : QUIC_CONN_ROLE_CLIENT;

          SocketQUICConnection_T conn
              = SocketQUICConnection_new (arena, role);
          if (!conn)
            break;

          SocketQUICHandshake_T hs
              = SocketQUICHandshake_new (arena, conn, role);
          if (!hs)
            break;

          /* Test key discard triggers (order from RFC 9001) */

          /* §4.9.1: Initial keys discarded when first Handshake sent/received
           */
          if (role == QUIC_CONN_ROLE_CLIENT)
            {
              /* Client: first Handshake packet sent */
              SocketQUICHandshake_on_handshake_packet_sent (hs);
              /* Should be idempotent */
              SocketQUICHandshake_on_handshake_packet_sent (hs);
            }
          else
            {
              /* Server: first Handshake packet received */
              SocketQUICHandshake_on_handshake_packet_received (hs);
              SocketQUICHandshake_on_handshake_packet_received (hs);
            }

          /* Check Initial keys are discarded */
          int can_send = SocketQUICHandshake_can_send_initial (hs);
          int can_recv = SocketQUICHandshake_can_receive_initial (hs);
          (void)can_send;
          (void)can_recv;

          /* §4.9.2: Handshake keys discarded when confirmed */
          SocketQUICHandshake_on_confirmed (hs);
          SocketQUICHandshake_on_confirmed (hs); /* Idempotent */

          /* Check Handshake keys are discarded */
          can_send = SocketQUICHandshake_can_send_handshake (hs);
          can_recv = SocketQUICHandshake_can_receive_handshake (hs);
          (void)can_send;
          (void)can_recv;

          /* §4.9.3: 0-RTT keys discarded when 1-RTT keys installed */
          SocketQUICHandshake_on_1rtt_keys_installed (hs);
          SocketQUICHandshake_on_1rtt_keys_installed (hs);

          /* Server also discards on 1-RTT packet received */
          if (role == QUIC_CONN_ROLE_SERVER)
            {
              SocketQUICHandshake_on_1rtt_packet_received (hs);
              SocketQUICHandshake_on_1rtt_packet_received (hs);
            }

          /* Check 0-RTT keys are discarded */
          int can_send_0rtt = SocketQUICHandshake_can_send_0rtt (hs);
          int can_recv_0rtt = SocketQUICHandshake_can_receive_0rtt (hs);
          (void)can_send_0rtt;
          (void)can_recv_0rtt;

          /* Test NULL inputs */
          SocketQUICHandshake_on_handshake_packet_sent (NULL);
          SocketQUICHandshake_on_handshake_packet_received (NULL);
          SocketQUICHandshake_on_confirmed (NULL);
          SocketQUICHandshake_on_1rtt_keys_installed (NULL);
          SocketQUICHandshake_on_1rtt_packet_received (NULL);

          SocketQUICHandshake_free (&hs);
          break;
        }

      case OP_0RTT_STATE:
        {
          /* Test 0-RTT early data state machine */
          SocketQUICConnection_T conn
              = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
          if (!conn)
            break;

          SocketQUICHandshake_T hs
              = SocketQUICHandshake_new (arena, conn, QUIC_CONN_ROLE_CLIENT);
          if (!hs)
            break;

          /* Initialize 0-RTT state */
          SocketQUICHandshake_0rtt_init (hs);

          /* Check initial state */
          SocketQUIC0RTT_State state = SocketQUICHandshake_0rtt_get_state (hs);
          int available = SocketQUICHandshake_0rtt_available (hs);
          int accepted = SocketQUICHandshake_0rtt_accepted (hs);
          (void)state;
          (void)available;
          (void)accepted;

          /* Set a ticket (from fuzz data) */
          size_t ticket_len = (data[2] % 100) + 10;
          if (size >= 3 + ticket_len + 8)
            {
              SocketQUICTransportParams_T saved_params;
              SocketQUICTransportParams_init (&saved_params);
              saved_params.max_idle_timeout = read_u64 (data + 3 + ticket_len);

              const char *alpn = "h3";
              SocketQUICHandshake_Result result
                  = SocketQUICHandshake_0rtt_set_ticket (hs, data + 3,
                                                         ticket_len,
                                                         &saved_params, alpn,
                                                         strlen (alpn));
              (void)result;

              /* Check state after ticket set */
              state = SocketQUICHandshake_0rtt_get_state (hs);
              available = SocketQUICHandshake_0rtt_available (hs);
              (void)state;
              (void)available;
            }

          /* Test HelloRetryRequest (forces 0-RTT rejection) */
          SocketQUICHandshake_on_hello_retry_request (hs);
          available = SocketQUICHandshake_0rtt_available (hs);
          (void)available;

          /* Test rejection handling */
          SocketQUICHandshake_Result result
              = SocketQUICHandshake_0rtt_handle_rejection (hs);
          state = SocketQUICHandshake_0rtt_get_state (hs);
          (void)result;
          (void)state;

          /* Test NULL inputs */
          SocketQUICHandshake_0rtt_init (NULL);
          SocketQUICHandshake_0rtt_get_state (NULL);
          SocketQUICHandshake_0rtt_available (NULL);
          SocketQUICHandshake_0rtt_accepted (NULL);
          SocketQUICHandshake_0rtt_set_ticket (NULL, NULL, 0, NULL, NULL, 0);
          SocketQUICHandshake_0rtt_handle_rejection (NULL);
          SocketQUICHandshake_on_hello_retry_request (NULL);

          SocketQUICHandshake_free (&hs);
          break;
        }

      case OP_TRANSPORT_PARAMS:
        {
          /* Test transport parameter handling */
          SocketQUICConnection_Role role
              = (data[1] & 1) ? QUIC_CONN_ROLE_SERVER : QUIC_CONN_ROLE_CLIENT;

          SocketQUICConnection_T conn
              = SocketQUICConnection_new (arena, role);
          if (!conn)
            break;

          SocketQUICHandshake_T hs
              = SocketQUICHandshake_new (arena, conn, role);
          if (!hs)
            break;

          /* Create transport parameters from fuzz data */
          SocketQUICTransportParams_T params;
          SocketQUICTransportParams_init (&params);

          params.max_idle_timeout = read_u64 (data + 2);
          params.max_udp_payload_size = read_u64 (data + 10) % 65536;
          params.initial_max_data = read_u64 (data + 18);
          params.initial_max_stream_data_bidi_local = read_u64 (data + 26);
          params.initial_max_stream_data_bidi_remote = read_u64 (data + 34);
          params.initial_max_stream_data_uni = read_u64 (data + 42);

          /* Set transport parameters */
          SocketQUICHandshake_Result result
              = SocketQUICHandshake_set_transport_params (hs, &params);
          (void)result;

          /* Get peer params (not available yet) */
          const SocketQUICTransportParams_T *peer
              = SocketQUICHandshake_get_peer_params (hs);
          (void)peer;

          /* Test NULL inputs */
          SocketQUICHandshake_set_transport_params (NULL, &params);
          SocketQUICHandshake_set_transport_params (hs, NULL);

          SocketQUICHandshake_free (&hs);
          break;
        }

      case OP_STRING_FUNCTIONS:
        {
          /* Test all string conversion functions */

          /* Crypto levels */
          for (int level = 0; level <= QUIC_CRYPTO_LEVEL_COUNT; level++)
            {
              const char *str = SocketQUICHandshake_crypto_level_string (
                  (SocketQUICCryptoLevel)level);
              (void)str;
            }
          SocketQUICHandshake_crypto_level_string ((SocketQUICCryptoLevel)data[1]);

          /* Handshake states */
          SocketQUICHandshakeState states[]
              = { QUIC_HANDSHAKE_STATE_IDLE,     QUIC_HANDSHAKE_STATE_INITIAL,
                  QUIC_HANDSHAKE_STATE_HANDSHAKE, QUIC_HANDSHAKE_STATE_COMPLETE,
                  QUIC_HANDSHAKE_STATE_CONFIRMED, QUIC_HANDSHAKE_STATE_FAILED };
          for (size_t i = 0; i < sizeof (states) / sizeof (states[0]); i++)
            {
              const char *str = SocketQUICHandshake_state_string (states[i]);
              (void)str;
            }
          SocketQUICHandshake_state_string ((SocketQUICHandshakeState)data[2]);

          /* Result codes */
          SocketQUICHandshake_Result results[]
              = { QUIC_HANDSHAKE_OK,
                  QUIC_HANDSHAKE_ERROR_NULL,
                  QUIC_HANDSHAKE_ERROR_STATE,
                  QUIC_HANDSHAKE_ERROR_CRYPTO,
                  QUIC_HANDSHAKE_ERROR_TLS,
                  QUIC_HANDSHAKE_ERROR_BUFFER,
                  QUIC_HANDSHAKE_ERROR_OFFSET,
                  QUIC_HANDSHAKE_ERROR_DUPLICATE,
                  QUIC_HANDSHAKE_ERROR_TRANSPORT,
                  QUIC_HANDSHAKE_ERROR_MEMORY };
          for (size_t i = 0; i < sizeof (results) / sizeof (results[0]); i++)
            {
              const char *str = SocketQUICHandshake_result_string (results[i]);
              (void)str;
            }
          SocketQUICHandshake_result_string (
              (SocketQUICHandshake_Result)data[3]);
          break;
        }
      }
  }
  EXCEPT (SocketQUICHandshake_Failed)
  {
    /* Expected on handshake errors */
  }
  EXCEPT (Arena_Failed)
  {
    /* Expected on allocation failure */
  }
  END_TRY;

  Arena_dispose ((Arena_T *)&arena);
  return 0;
}
