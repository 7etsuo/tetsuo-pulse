/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICStream.h
 * @brief QUIC Stream Management (RFC 9000 Section 2).
 *
 * Implements QUIC stream abstraction for multiplexed bidirectional and
 * unidirectional byte streams. Each stream is an independent, ordered,
 * reliable sequence of bytes.
 *
 * Stream ID encoding (62-bit integers):
 *   - Bit 0: Initiator (0=client, 1=server)
 *   - Bit 1: Directionality (0=bidirectional, 1=unidirectional)
 *
 * Stream ID sequences:
 *   - Client-initiated bidirectional: 0x0, 0x4, 0x8, ...
 *   - Server-initiated bidirectional: 0x1, 0x5, 0x9, ...
 *   - Client-initiated unidirectional: 0x2, 0x6, 0xA, ...
 *   - Server-initiated unidirectional: 0x3, 0x7, 0xB, ...
 *
 * Thread Safety: Individual stream structures are not thread-safe.
 * Use external synchronization when sharing across threads.
 *
 * @defgroup quic_stream QUIC Stream Module
 * @{
 * @see https://www.rfc-editor.org/rfc/rfc9000#section-2
 */

#ifndef SOCKETQUICSTREAM_INCLUDED
#define SOCKETQUICSTREAM_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include "core/Arena.h"
#include "core/Except.h"

/* ============================================================================
 * Constants (RFC 9000 Section 2.1)
 * ============================================================================
 */

/**
 * @brief Bit mask for extracting stream initiator.
 *
 * Bit 0 of stream ID indicates initiator: 0=client, 1=server.
 */
#define QUIC_STREAM_INITIATOR_MASK 0x01

/**
 * @brief Bit mask for extracting stream directionality.
 *
 * Bit 1 of stream ID indicates direction: 0=bidirectional, 1=unidirectional.
 */
#define QUIC_STREAM_DIRECTION_MASK 0x02

/**
 * @brief Maximum valid stream ID (2^62 - 1).
 *
 * Stream IDs are encoded as 62-bit QUIC variable-length integers.
 */
#define QUIC_STREAM_ID_MAX ((uint64_t)4611686018427387903ULL)

/**
 * @brief Stream type mask for extracting the 2-bit type field.
 */
#define QUIC_STREAM_TYPE_MASK 0x03

/* ============================================================================
 * Data Structures
 * ============================================================================
 */

/**
 * @brief Stream types based on initiator and directionality.
 *
 * The two least significant bits of the stream ID determine the type:
 *   - 0x0: Client-initiated bidirectional
 *   - 0x1: Server-initiated bidirectional
 *   - 0x2: Client-initiated unidirectional
 *   - 0x3: Server-initiated unidirectional
 */
typedef enum
{
  QUIC_STREAM_BIDI_CLIENT = 0x0, /**< Client-initiated bidirectional */
  QUIC_STREAM_BIDI_SERVER = 0x1, /**< Server-initiated bidirectional */
  QUIC_STREAM_UNI_CLIENT = 0x2,  /**< Client-initiated unidirectional */
  QUIC_STREAM_UNI_SERVER = 0x3   /**< Server-initiated unidirectional */
} SocketQUICStreamType;

/**
 * @brief Stream state machine states (RFC 9000 Section 3).
 *
 * Sending states: Ready, Send, DataSent, ResetSent, DataRecvd, ResetRecvd
 * Receiving states: Recv, SizeKnown, DataRecvd, ResetRecvd, DataRead, ResetRead
 */
typedef enum
{
  /* Sending states */
  QUIC_STREAM_STATE_READY = 0,      /**< Initial state, no data sent */
  QUIC_STREAM_STATE_SEND,           /**< Application sending data */
  QUIC_STREAM_STATE_DATA_SENT,      /**< FIN sent, awaiting acknowledgment */
  QUIC_STREAM_STATE_RESET_SENT,     /**< RESET_STREAM sent */
  QUIC_STREAM_STATE_DATA_RECVD,     /**< All data acknowledged by peer */
  QUIC_STREAM_STATE_RESET_RECVD,    /**< Reset acknowledged by peer */

  /* Receiving states */
  QUIC_STREAM_STATE_RECV,           /**< Receiving data from peer */
  QUIC_STREAM_STATE_SIZE_KNOWN,     /**< FIN received, final size known */
  QUIC_STREAM_STATE_DATA_READ,      /**< All data delivered to application */
  QUIC_STREAM_STATE_RESET_READ      /**< Reset delivered to application */
} SocketQUICStreamState;

/**
 * @brief Result codes for stream operations.
 */
typedef enum
{
  QUIC_STREAM_OK = 0,              /**< Operation succeeded */
  QUIC_STREAM_ERROR_NULL,          /**< NULL pointer argument */
  QUIC_STREAM_ERROR_INVALID_ID,    /**< Stream ID exceeds maximum */
  QUIC_STREAM_ERROR_INVALID_TYPE,  /**< Invalid stream type */
  QUIC_STREAM_ERROR_WRONG_ROLE,    /**< Wrong role for stream operation */
  QUIC_STREAM_ERROR_STATE,         /**< Invalid state transition */
  QUIC_STREAM_ERROR_LIMIT          /**< Stream limit exceeded */
} SocketQUICStream_Result;

/**
 * @brief Stream state transition events (RFC 9000 Section 3).
 *
 * Events that trigger state transitions in the send and receive state machines.
 */
typedef enum
{
  /* Send-side events */
  QUIC_STREAM_EVENT_SEND_DATA,        /**< Application sends data on stream */
  QUIC_STREAM_EVENT_SEND_FIN,         /**< Application signals end of stream */
  QUIC_STREAM_EVENT_ALL_DATA_ACKED,   /**< All sent data acknowledged by peer */
  QUIC_STREAM_EVENT_SEND_RESET,       /**< Application resets sending part */
  QUIC_STREAM_EVENT_RESET_ACKED,      /**< Peer acknowledged RESET_STREAM */

  /* Receive-side events */
  QUIC_STREAM_EVENT_RECV_DATA,        /**< Received STREAM frame with data */
  QUIC_STREAM_EVENT_RECV_FIN,         /**< Received STREAM frame with FIN bit */
  QUIC_STREAM_EVENT_ALL_DATA_RECVD,   /**< All data up to FIN received */
  QUIC_STREAM_EVENT_APP_READ_DATA,    /**< Application consumed all data */
  QUIC_STREAM_EVENT_RECV_RESET,       /**< Received RESET_STREAM frame */
  QUIC_STREAM_EVENT_APP_READ_RESET,   /**< Application notified of reset */

  /* Bidirectional events */
  QUIC_STREAM_EVENT_RECV_STOP_SENDING, /**< Received STOP_SENDING frame */

  QUIC_STREAM_EVENT_MAX = QUIC_STREAM_EVENT_RECV_STOP_SENDING /**< Maximum event value for bounds checking */
} SocketQUICStreamEvent;

/**
 * @brief Opaque stream handle.
 */
typedef struct SocketQUICStream *SocketQUICStream_T;

/**
 * @brief QUIC Stream structure.
 *
 * Represents a single QUIC stream with its state and flow control data.
 * RFC 9000 Section 3 defines dual state machines: one for sending and
 * one for receiving.
 */
struct SocketQUICStream
{
  uint64_t id;                    /**< Stream ID (62-bit) */
  SocketQUICStreamType type;      /**< Stream type (derived from ID) */

  /* Dual state machines (RFC 9000 Section 3) */
  SocketQUICStreamState send_state; /**< Send-side state machine */
  SocketQUICStreamState recv_state; /**< Receive-side state machine */
  SocketQUICStreamState state;      /**< Legacy: combined state (deprecated) */

  /* Flow control */
  uint64_t max_data;              /**< Maximum data peer can send */
  uint64_t data_sent;             /**< Bytes sent on this stream */
  uint64_t data_received;         /**< Bytes received on this stream */
  uint64_t final_size;            /**< Final size (set when FIN received) */

  /* Flags */
  unsigned int is_local : 1;      /**< 1 if locally initiated, 0 if remote */
  unsigned int fin_sent : 1;      /**< FIN has been sent */
  unsigned int fin_received : 1;  /**< FIN has been received */
  unsigned int reset_sent : 1;    /**< RESET_STREAM sent */
  unsigned int reset_received : 1; /**< RESET_STREAM received */
};

/* ============================================================================
 * Stream ID Functions
 * ============================================================================
 */

/**
 * @brief Check if stream ID indicates client-initiated stream.
 *
 * Bit 0 of stream ID: 0=client-initiated, 1=server-initiated.
 *
 * @param stream_id Stream ID to check.
 *
 * @return 1 if client-initiated, 0 if server-initiated.
 */
extern int SocketQUICStream_is_client_initiated (uint64_t stream_id);

/**
 * @brief Check if stream ID indicates server-initiated stream.
 *
 * @param stream_id Stream ID to check.
 *
 * @return 1 if server-initiated, 0 if client-initiated.
 */
extern int SocketQUICStream_is_server_initiated (uint64_t stream_id);

/**
 * @brief Check if stream ID indicates bidirectional stream.
 *
 * Bit 1 of stream ID: 0=bidirectional, 1=unidirectional.
 *
 * @param stream_id Stream ID to check.
 *
 * @return 1 if bidirectional, 0 if unidirectional.
 */
extern int SocketQUICStream_is_bidirectional (uint64_t stream_id);

/**
 * @brief Check if stream ID indicates unidirectional stream.
 *
 * @param stream_id Stream ID to check.
 *
 * @return 1 if unidirectional, 0 if bidirectional.
 */
extern int SocketQUICStream_is_unidirectional (uint64_t stream_id);

/**
 * @brief Get the stream type from stream ID.
 *
 * Extracts the 2-bit type field from the stream ID.
 *
 * @param stream_id Stream ID to check.
 *
 * @return Stream type (QUIC_STREAM_BIDI_CLIENT, etc.)
 */
extern SocketQUICStreamType SocketQUICStream_type (uint64_t stream_id);

/**
 * @brief Check if stream ID is valid.
 *
 * Validates that stream ID does not exceed maximum (2^62-1).
 *
 * @param stream_id Stream ID to validate.
 *
 * @return 1 if valid, 0 if invalid.
 */
extern int SocketQUICStream_is_valid_id (uint64_t stream_id);

/**
 * @brief Calculate next stream ID for a given type.
 *
 * Given a current stream ID, computes the next valid stream ID
 * of the same type (increments by 4).
 *
 * @param stream_id Current stream ID.
 *
 * @return Next stream ID, or 0 if overflow would occur.
 */
extern uint64_t SocketQUICStream_next_id (uint64_t stream_id);

/**
 * @brief Get the first stream ID for a given type.
 *
 * Returns the initial stream ID for the specified type:
 *   - QUIC_STREAM_BIDI_CLIENT: 0
 *   - QUIC_STREAM_BIDI_SERVER: 1
 *   - QUIC_STREAM_UNI_CLIENT: 2
 *   - QUIC_STREAM_UNI_SERVER: 3
 *
 * @param type Stream type.
 *
 * @return First stream ID for the type.
 */
extern uint64_t SocketQUICStream_first_id (SocketQUICStreamType type);

/**
 * @brief Calculate stream sequence number from ID.
 *
 * The sequence number indicates how many streams of this type
 * were created before this one (stream_id / 4).
 *
 * @param stream_id Stream ID.
 *
 * @return Sequence number (0, 1, 2, ...).
 */
extern uint64_t SocketQUICStream_sequence (uint64_t stream_id);

/* ============================================================================
 * Stream Lifecycle Functions
 * ============================================================================
 */

/**
 * @brief Create a new stream structure.
 *
 * Allocates and initializes a stream structure from the given arena.
 * The stream type is derived automatically from the stream ID.
 *
 * @param arena     Memory arena for allocation.
 * @param stream_id Stream ID (determines type).
 *
 * @return New stream handle, or NULL on error.
 */
extern SocketQUICStream_T SocketQUICStream_new (Arena_T arena,
                                                 uint64_t stream_id);

/**
 * @brief Initialize a stream structure.
 *
 * Initializes an existing stream structure with the given ID.
 * Useful when embedding stream in larger structures.
 *
 * @param stream    Stream structure to initialize.
 * @param stream_id Stream ID.
 *
 * @return QUIC_STREAM_OK on success, error code otherwise.
 */
extern SocketQUICStream_Result
SocketQUICStream_init (SocketQUICStream_T stream, uint64_t stream_id);

/**
 * @brief Reset stream structure to initial state.
 *
 * Clears all fields while preserving the stream ID.
 *
 * @param stream Stream to reset.
 *
 * @return QUIC_STREAM_OK on success, error code otherwise.
 */
extern SocketQUICStream_Result SocketQUICStream_reset (SocketQUICStream_T stream);

/* ============================================================================
 * Stream Access Functions
 * ============================================================================
 */

/**
 * @brief Get stream ID.
 *
 * @param stream Stream handle.
 *
 * @return Stream ID, or 0 if stream is NULL.
 */
extern uint64_t SocketQUICStream_get_id (const SocketQUICStream_T stream);

/**
 * @brief Get stream type.
 *
 * @param stream Stream handle.
 *
 * @return Stream type, or QUIC_STREAM_BIDI_CLIENT if stream is NULL.
 */
extern SocketQUICStreamType
SocketQUICStream_get_type (const SocketQUICStream_T stream);

/**
 * @brief Get stream state.
 *
 * @param stream Stream handle.
 *
 * @return Stream state, or QUIC_STREAM_STATE_READY if stream is NULL.
 */
extern SocketQUICStreamState
SocketQUICStream_get_state (const SocketQUICStream_T stream);

/**
 * @brief Check if stream is locally initiated.
 *
 * @param stream Stream handle.
 *
 * @return 1 if locally initiated, 0 otherwise.
 */
extern int SocketQUICStream_is_local (const SocketQUICStream_T stream);

/**
 * @brief Get send-side state.
 *
 * @param stream Stream handle.
 *
 * @return Send state, or QUIC_STREAM_STATE_READY if stream is NULL.
 */
extern SocketQUICStreamState
SocketQUICStream_get_send_state (const SocketQUICStream_T stream);

/**
 * @brief Get receive-side state.
 *
 * @param stream Stream handle.
 *
 * @return Receive state, or QUIC_STREAM_STATE_RECV if stream is NULL.
 */
extern SocketQUICStreamState
SocketQUICStream_get_recv_state (const SocketQUICStream_T stream);

/* ============================================================================
 * State Transition Functions (RFC 9000 Section 3)
 * ============================================================================
 */

/**
 * @brief Transition the send-side state machine.
 *
 * Implements the sending part of the stream state machine (RFC 9000 Section 3.1).
 *
 * Send states:
 *   Ready -> Send (on SEND_DATA)
 *   Send -> DataSent (on SEND_FIN)
 *   Send -> ResetSent (on SEND_RESET or RECV_STOP_SENDING)
 *   DataSent -> DataRecvd (on ALL_DATA_ACKED)
 *   DataSent -> ResetSent (on SEND_RESET or RECV_STOP_SENDING)
 *   ResetSent -> ResetRecvd (on RESET_ACKED)
 *
 * @param stream Stream to transition.
 * @param event  Event triggering the transition.
 *
 * @return QUIC_STREAM_OK on success, QUIC_STREAM_ERROR_STATE on invalid transition.
 */
extern SocketQUICStream_Result
SocketQUICStream_transition_send (SocketQUICStream_T stream,
                                  SocketQUICStreamEvent event);

/**
 * @brief Transition the receive-side state machine.
 *
 * Implements the receiving part of the stream state machine (RFC 9000 Section 3.2).
 *
 * Receive states:
 *   Recv -> SizeKnown (on RECV_FIN)
 *   Recv -> ResetRecvd (on RECV_RESET)
 *   SizeKnown -> DataRecvd (on ALL_DATA_RECVD)
 *   SizeKnown -> ResetRecvd (on RECV_RESET)
 *   DataRecvd -> DataRead (on APP_READ_DATA)
 *   ResetRecvd -> ResetRead (on APP_READ_RESET)
 *
 * @param stream Stream to transition.
 * @param event  Event triggering the transition.
 *
 * @return QUIC_STREAM_OK on success, QUIC_STREAM_ERROR_STATE on invalid transition.
 */
extern SocketQUICStream_Result
SocketQUICStream_transition_recv (SocketQUICStream_T stream,
                                  SocketQUICStreamEvent event);

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

/**
 * @brief Get string representation of stream type.
 *
 * @param type Stream type.
 *
 * @return Human-readable string.
 */
extern const char *SocketQUICStream_type_string (SocketQUICStreamType type);

/**
 * @brief Get string representation of stream state.
 *
 * @param state Stream state.
 *
 * @return Human-readable string.
 */
extern const char *SocketQUICStream_state_string (SocketQUICStreamState state);

/**
 * @brief Get string representation of result code.
 *
 * @param result Result code.
 *
 * @return Human-readable string.
 */
extern const char *
SocketQUICStream_result_string (SocketQUICStream_Result result);

/**
 * @brief Get string representation of stream event.
 *
 * @param event Stream event.
 *
 * @return Human-readable string.
 */
extern const char *SocketQUICStream_event_string (SocketQUICStreamEvent event);

/** @} */

#endif /* SOCKETQUICSTREAM_INCLUDED */
