/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_quic_stream.c - libFuzzer for QUIC Stream Management (RFC 9000 Section
 * 2-3)
 *
 * Fuzzes stream ID operations and state machine transitions:
 * - Stream ID type detection and validation
 * - Stream ID sequence calculations
 * - Send/receive state machine transitions
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_quic_stream
 * ./fuzz_quic_stream corpus/quic_stream/ -fork=16 -max_len=1024
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "quic/SocketQUICStream.h"

/* Operation types */
enum
{
  OP_STREAM_ID_FUNCTIONS,
  OP_STATE_TRANSITIONS,
  OP_STREAM_LIFECYCLE,
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
  if (size < 20)
    return 0;

  volatile Arena_T arena = Arena_new ();
  if (!arena)
    return 0;

  TRY
  {
    uint8_t op = data[0] % OP_MAX;

    switch (op)
      {
      case OP_STREAM_ID_FUNCTIONS:
        {
          /* Test stream ID utility functions */
          uint64_t stream_id = read_u64 (data + 1);

          /* Test type detection */
          int is_client = SocketQUICStream_is_client_initiated (stream_id);
          int is_server = SocketQUICStream_is_server_initiated (stream_id);
          int is_bidi = SocketQUICStream_is_bidirectional (stream_id);
          int is_uni = SocketQUICStream_is_unidirectional (stream_id);
          (void)is_client;
          (void)is_server;
          (void)is_bidi;
          (void)is_uni;

          /* These should be mutually exclusive */
          SocketQUICStreamType type = SocketQUICStream_type (stream_id);
          (void)type;

          /* Validate stream ID */
          int is_valid = SocketQUICStream_is_valid_id (stream_id);
          (void)is_valid;

          /* Get sequence number */
          uint64_t seq = SocketQUICStream_sequence (stream_id);
          (void)seq;

          /* Get next stream ID */
          uint64_t next = SocketQUICStream_next_id (stream_id);
          (void)next;

          /* Test with special values */
          stream_id = 0;
          type = SocketQUICStream_type (stream_id);
          is_valid = SocketQUICStream_is_valid_id (stream_id);
          next = SocketQUICStream_next_id (stream_id);
          (void)type;
          (void)is_valid;
          (void)next;

          stream_id = QUIC_STREAM_ID_MAX;
          type = SocketQUICStream_type (stream_id);
          is_valid = SocketQUICStream_is_valid_id (stream_id);
          next = SocketQUICStream_next_id (stream_id);
          (void)type;
          (void)is_valid;
          (void)next;

          stream_id = QUIC_STREAM_ID_MAX + 1;
          is_valid = SocketQUICStream_is_valid_id (stream_id);
          (void)is_valid;

          /* Test first_id for each type */
          uint64_t first_bidi_client
              = SocketQUICStream_first_id (QUIC_STREAM_BIDI_CLIENT);
          uint64_t first_bidi_server
              = SocketQUICStream_first_id (QUIC_STREAM_BIDI_SERVER);
          uint64_t first_uni_client
              = SocketQUICStream_first_id (QUIC_STREAM_UNI_CLIENT);
          uint64_t first_uni_server
              = SocketQUICStream_first_id (QUIC_STREAM_UNI_SERVER);
          (void)first_bidi_client;
          (void)first_bidi_server;
          (void)first_uni_client;
          (void)first_uni_server;

          /* Test stream ID iteration */
          stream_id = 0;
          for (int i = 0; i < 20 && stream_id != 0; i++)
            {
              next = SocketQUICStream_next_id (stream_id);
              if (next == 0)
                break; /* Overflow */
              stream_id = next;
            }
          break;
        }

      case OP_STATE_TRANSITIONS:
        {
          /* Test state machine transitions */
          uint64_t stream_id = read_u64 (data + 1);

          SocketQUICStream_T stream
              = SocketQUICStream_new (arena, stream_id % 1000);
          if (!stream)
            break;

          /* Test send-side transitions */
          SocketQUICStreamState send_state
              = SocketQUICStream_get_send_state (stream);
          (void)send_state;

          /* Try all send events */
          SocketQUICStreamEvent send_events[]
              = { QUIC_STREAM_EVENT_SEND_DATA,
                  QUIC_STREAM_EVENT_SEND_FIN,
                  QUIC_STREAM_EVENT_ALL_DATA_ACKED,
                  QUIC_STREAM_EVENT_SEND_RESET,
                  QUIC_STREAM_EVENT_RESET_ACKED };

          for (size_t i = 0; i < sizeof (send_events) / sizeof (send_events[0]);
               i++)
            {
              SocketQUICStream_Result result
                  = SocketQUICStream_transition_send (stream, send_events[i]);
              (void)result;
              send_state = SocketQUICStream_get_send_state (stream);
              (void)send_state;
            }

          /* Reset and test receive-side transitions */
          SocketQUICStream_reset (stream);

          SocketQUICStreamState recv_state
              = SocketQUICStream_get_recv_state (stream);
          (void)recv_state;

          SocketQUICStreamEvent recv_events[]
              = { QUIC_STREAM_EVENT_RECV_DATA,
                  QUIC_STREAM_EVENT_RECV_FIN,
                  QUIC_STREAM_EVENT_ALL_DATA_RECVD,
                  QUIC_STREAM_EVENT_APP_READ_DATA,
                  QUIC_STREAM_EVENT_RECV_RESET,
                  QUIC_STREAM_EVENT_APP_READ_RESET,
                  QUIC_STREAM_EVENT_RECV_STOP_SENDING };

          for (size_t i = 0; i < sizeof (recv_events) / sizeof (recv_events[0]);
               i++)
            {
              SocketQUICStream_Result result
                  = SocketQUICStream_transition_recv (stream, recv_events[i]);
              (void)result;
              recv_state = SocketQUICStream_get_recv_state (stream);
              (void)recv_state;
            }

          /* Test with fuzzed event sequence */
          SocketQUICStream_reset (stream);
          size_t offset = 9;
          while (offset < size)
            {
              uint8_t event_idx = data[offset] % QUIC_STREAM_EVENT_MAX;
              SocketQUICStreamEvent event = (SocketQUICStreamEvent)event_idx;

              /* Randomly choose send or receive transition */
              if (data[offset] & 0x80)
                {
                  SocketQUICStream_transition_send (stream, event);
                }
              else
                {
                  SocketQUICStream_transition_recv (stream, event);
                }
              offset++;
            }

          /* Test NULL inputs */
          SocketQUICStream_transition_send (NULL, QUIC_STREAM_EVENT_SEND_DATA);
          SocketQUICStream_transition_recv (NULL, QUIC_STREAM_EVENT_RECV_DATA);
          break;
        }

      case OP_STREAM_LIFECYCLE:
        {
          /* Test stream creation and access functions */
          uint64_t stream_id = read_u64 (data + 1);

          /* Create stream */
          SocketQUICStream_T stream = SocketQUICStream_new (arena, stream_id);
          if (!stream)
            break;

          /* Get properties */
          uint64_t id = SocketQUICStream_get_id (stream);
          SocketQUICStreamType type = SocketQUICStream_get_type (stream);
          SocketQUICStreamState state = SocketQUICStream_get_state (stream);
          int is_local = SocketQUICStream_is_local (stream);
          (void)id;
          (void)type;
          (void)state;
          (void)is_local;

          /* Test init with different IDs */
          SocketQUICStream_Result result
              = SocketQUICStream_init (stream, stream_id + 4);
          (void)result;

          /* Reset */
          result = SocketQUICStream_reset (stream);
          (void)result;

          /* Create multiple streams */
          for (uint64_t i = 0; i < 10; i++)
            {
              uint64_t sid = (stream_id + i * 4) % QUIC_STREAM_ID_MAX;
              SocketQUICStream_T s = SocketQUICStream_new (arena, sid);
              if (s)
                {
                  SocketQUICStream_get_id (s);
                  SocketQUICStream_get_type (s);
                }
            }

          /* Test NULL inputs */
          SocketQUICStream_get_id (NULL);
          SocketQUICStream_get_type (NULL);
          SocketQUICStream_get_state (NULL);
          SocketQUICStream_is_local (NULL);
          SocketQUICStream_get_send_state (NULL);
          SocketQUICStream_get_recv_state (NULL);
          SocketQUICStream_init (NULL, 0);
          SocketQUICStream_reset (NULL);
          break;
        }

      case OP_STRING_FUNCTIONS:
        {
          /* Test all string conversion functions */

          /* Stream types */
          SocketQUICStreamType types[] = { QUIC_STREAM_BIDI_CLIENT,
                                           QUIC_STREAM_BIDI_SERVER,
                                           QUIC_STREAM_UNI_CLIENT,
                                           QUIC_STREAM_UNI_SERVER };
          for (size_t i = 0; i < sizeof (types) / sizeof (types[0]); i++)
            {
              const char *str = SocketQUICStream_type_string (types[i]);
              (void)str;
            }
          SocketQUICStream_type_string ((SocketQUICStreamType)data[1]);

          /* Stream states */
          SocketQUICStreamState states[]
              = { QUIC_STREAM_STATE_READY,      QUIC_STREAM_STATE_SEND,
                  QUIC_STREAM_STATE_DATA_SENT,  QUIC_STREAM_STATE_RESET_SENT,
                  QUIC_STREAM_STATE_DATA_RECVD, QUIC_STREAM_STATE_RESET_RECVD,
                  QUIC_STREAM_STATE_RECV,       QUIC_STREAM_STATE_SIZE_KNOWN,
                  QUIC_STREAM_STATE_DATA_READ,  QUIC_STREAM_STATE_RESET_READ };
          for (size_t i = 0; i < sizeof (states) / sizeof (states[0]); i++)
            {
              const char *str = SocketQUICStream_state_string (states[i]);
              (void)str;
            }
          SocketQUICStream_state_string ((SocketQUICStreamState)data[2]);

          /* Result codes */
          SocketQUICStream_Result results[] = { QUIC_STREAM_OK,
                                                QUIC_STREAM_ERROR_NULL,
                                                QUIC_STREAM_ERROR_INVALID_ID,
                                                QUIC_STREAM_ERROR_INVALID_TYPE,
                                                QUIC_STREAM_ERROR_WRONG_ROLE,
                                                QUIC_STREAM_ERROR_STATE,
                                                QUIC_STREAM_ERROR_LIMIT };
          for (size_t i = 0; i < sizeof (results) / sizeof (results[0]); i++)
            {
              const char *str = SocketQUICStream_result_string (results[i]);
              (void)str;
            }
          SocketQUICStream_result_string ((SocketQUICStream_Result)data[3]);

          /* Events */
          for (int i = 0; i < QUIC_STREAM_EVENT_MAX; i++)
            {
              const char *str
                  = SocketQUICStream_event_string ((SocketQUICStreamEvent)i);
              (void)str;
            }
          SocketQUICStream_event_string ((SocketQUICStreamEvent)data[4]);
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
