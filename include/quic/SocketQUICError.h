/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICError.h
 * @brief QUIC Transport and Application Error Codes (RFC 9000 Section 20).
 *
 * Defines error codes used in QUIC CONNECTION_CLOSE and RESET_STREAM frames.
 * Error codes are 62-bit unsigned integers (encoded as VarInt).
 *
 * Error code spaces:
 *   - 0x00-0x10:     Transport error codes (defined in RFC 9000)
 *   - 0x0100-0x01ff: Crypto/TLS error codes (TLS alerts)
 *   - 0x0200+:       Reserved for application protocols (e.g., HTTP/3)
 *
 * Thread Safety: All functions are thread-safe (pure computation, no state).
 *
 * @defgroup quic_error QUIC Error Codes Module
 * @{
 * @see https://www.rfc-editor.org/rfc/rfc9000#section-20
 */

#ifndef SOCKETQUICERROR_INCLUDED
#define SOCKETQUICERROR_INCLUDED

#include <stddef.h>
#include <stdint.h>

/* Forward declarations */
typedef struct SocketQUICConnection *SocketQUICConnection_T;
typedef struct SocketQUICStream *SocketQUICStream_T;

/* ============================================================================
 * Transport Error Codes (RFC 9000 Section 20.1)
 * ============================================================================
 */

/**
 * @brief QUIC transport error codes for CONNECTION_CLOSE frames.
 *
 * These errors apply to the entire connection and are sent in
 * CONNECTION_CLOSE frames with type 0x1c.
 */
typedef enum
{
  /**
   * No error. Used to signal that the connection is being closed
   * abruptly in the absence of any error.
   */
  QUIC_NO_ERROR = 0x00,

  /**
   * Internal error. The endpoint encountered an internal error
   * and cannot continue with the connection.
   */
  QUIC_INTERNAL_ERROR = 0x01,

  /**
   * Connection refused. The server refused to accept a new connection.
   */
  QUIC_CONNECTION_REFUSED = 0x02,

  /**
   * Flow control error. An endpoint received more data than it
   * permitted in its advertised data limits (Section 4).
   */
  QUIC_FLOW_CONTROL_ERROR = 0x03,

  /**
   * Stream limit error. An endpoint received a frame for a stream
   * identifier that exceeded its advertised stream limit.
   */
  QUIC_STREAM_LIMIT_ERROR = 0x04,

  /**
   * Stream state error. An endpoint received a frame for a stream
   * that was not in a state that permitted that frame (Section 3).
   */
  QUIC_STREAM_STATE_ERROR = 0x05,

  /**
   * Final size error. An endpoint received a STREAM frame containing
   * data that exceeded the previously established final size, or
   * conflicting final size values.
   */
  QUIC_FINAL_SIZE_ERROR = 0x06,

  /**
   * Frame encoding error. An endpoint received a frame that was
   * badly formatted (e.g., unknown type, invalid ACK ranges).
   */
  QUIC_FRAME_ENCODING_ERROR = 0x07,

  /**
   * Transport parameter error. An endpoint received transport
   * parameters that were badly formatted, invalid, or in error.
   */
  QUIC_TRANSPORT_PARAMETER_ERROR = 0x08,

  /**
   * Connection ID limit error. The number of connection IDs provided
   * by the peer exceeds the advertised active_connection_id_limit.
   */
  QUIC_CONNECTION_ID_LIMIT_ERROR = 0x09,

  /**
   * Protocol violation. An endpoint detected an error with protocol
   * compliance that was not covered by more specific error codes.
   */
  QUIC_PROTOCOL_VIOLATION = 0x0a,

  /**
   * Invalid token. A server received a client Initial that contained
   * an invalid Token field.
   */
  QUIC_INVALID_TOKEN = 0x0b,

  /**
   * Application error. The application or application protocol
   * caused the connection to be closed.
   */
  QUIC_APPLICATION_ERROR = 0x0c,

  /**
   * Crypto buffer exceeded. An endpoint has received more data in
   * CRYPTO frames than it can buffer.
   */
  QUIC_CRYPTO_BUFFER_EXCEEDED = 0x0d,

  /**
   * Key update error. An endpoint detected errors in performing
   * key updates (Section 6 of [QUIC-TLS]).
   */
  QUIC_KEY_UPDATE_ERROR = 0x0e,

  /**
   * AEAD limit reached. An endpoint has reached the confidentiality
   * or integrity limit for the AEAD algorithm used by the connection.
   */
  QUIC_AEAD_LIMIT_REACHED = 0x0f,

  /**
   * No viable path. An endpoint has determined that the network path
   * is incapable of supporting QUIC (e.g., MTU too small).
   */
  QUIC_NO_VIABLE_PATH = 0x10

} SocketQUIC_TransportError;

/* ============================================================================
 * Crypto Error Codes (RFC 9000 Section 20.1)
 * ============================================================================
 */

/**
 * @brief Base value for crypto (TLS) error codes.
 *
 * Crypto errors are in the range 0x0100-0x01ff.
 * The low 8 bits contain the TLS AlertDescription value.
 */
#define QUIC_CRYPTO_ERROR_BASE 0x0100

/**
 * @brief Maximum crypto error code value.
 */
#define QUIC_CRYPTO_ERROR_MAX 0x01ff

/**
 * @brief Convert TLS AlertDescription to QUIC crypto error code.
 *
 * @param alert TLS AlertDescription value (0-255).
 * @return QUIC crypto error code (0x0100-0x01ff).
 */
#define QUIC_CRYPTO_ERROR(alert) (QUIC_CRYPTO_ERROR_BASE | ((alert) & 0xff))

/**
 * @brief Check if an error code is a crypto error.
 *
 * @param code QUIC error code to check.
 * @return Non-zero if code is in crypto error range, zero otherwise.
 */
#define QUIC_IS_CRYPTO_ERROR(code)                                            \
  (((code) >= QUIC_CRYPTO_ERROR_BASE) && ((code) <= QUIC_CRYPTO_ERROR_MAX))

/**
 * @brief Extract TLS AlertDescription from crypto error code.
 *
 * @param code QUIC crypto error code.
 * @return TLS AlertDescription value (0-255).
 */
#define QUIC_CRYPTO_ALERT(code) ((code) & 0xff)

/* ============================================================================
 * Application Error Codes (RFC 9000 Section 20.2)
 * ============================================================================
 */

/**
 * @brief Base value for application protocol error codes.
 *
 * Application protocol error codes (e.g., HTTP/3) are defined
 * by the respective application protocol specifications.
 * They are used in RESET_STREAM, STOP_SENDING, and CONNECTION_CLOSE
 * frames with type 0x1d.
 */
#define QUIC_APPLICATION_ERROR_BASE 0x0200

/* ============================================================================
 * Error Code Limits
 * ============================================================================
 */

/**
 * @brief Maximum transport error code defined in RFC 9000.
 */
#define QUIC_TRANSPORT_ERROR_MAX QUIC_NO_VIABLE_PATH

/**
 * @brief Maximum value for any QUIC error code (62 bits).
 *
 * Error codes are VarInt encoded, so the maximum is 2^62-1.
 */
#define QUIC_ERROR_CODE_MAX ((uint64_t)0x3FFFFFFFFFFFFFFFULL)

/**
 * @brief Maximum length of reason phrase in CONNECTION_CLOSE frames.
 *
 * CONNECTION_CLOSE frames can include a variable-length reason phrase
 * to provide additional diagnostic information. The length field is
 * encoded as a VarInt, but practical implementations limit the size
 * to prevent excessive memory usage. This limit (65535 bytes) ensures
 * the reason phrase fits within reasonable network packet sizes while
 * still allowing detailed error messages.
 */
#define QUIC_MAX_REASON_LENGTH 0xFFFF

/* ============================================================================
 * Error Code Classification
 * ============================================================================
 */

/**
 * @brief Error code category.
 */
typedef enum
{
  QUIC_ERROR_CATEGORY_TRANSPORT,   /**< Transport layer error (0x00-0x10) */
  QUIC_ERROR_CATEGORY_CRYPTO,      /**< Crypto/TLS error (0x0100-0x01ff) */
  QUIC_ERROR_CATEGORY_APPLICATION, /**< Application protocol error */
  QUIC_ERROR_CATEGORY_UNKNOWN      /**< Reserved/unknown error code */
} SocketQUIC_ErrorCategory;

/**
 * @brief Classify a QUIC error code.
 *
 * @param code Error code to classify.
 * @return Category of the error code.
 */
static inline SocketQUIC_ErrorCategory
SocketQUIC_error_category (uint64_t code)
{
  if (code <= QUIC_TRANSPORT_ERROR_MAX)
    return QUIC_ERROR_CATEGORY_TRANSPORT;

  if (QUIC_IS_CRYPTO_ERROR (code))
    return QUIC_ERROR_CATEGORY_CRYPTO;

  if (code >= QUIC_APPLICATION_ERROR_BASE)
    return QUIC_ERROR_CATEGORY_APPLICATION;

  return QUIC_ERROR_CATEGORY_UNKNOWN;
}

/**
 * @brief Check if an error code is valid (within 62-bit range).
 *
 * @param code Error code to validate.
 * @return 1 if valid, 0 if exceeds maximum.
 */
static inline int
SocketQUIC_error_is_valid (uint64_t code)
{
  return code <= QUIC_ERROR_CODE_MAX;
}

/**
 * @brief Check if an error code is a known transport error.
 *
 * @param code Error code to check.
 * @return 1 if known transport error, 0 otherwise.
 */
static inline int
SocketQUIC_is_transport_error (uint64_t code)
{
  return code <= QUIC_TRANSPORT_ERROR_MAX;
}

/* ============================================================================
 * String Conversion
 * ============================================================================
 */

/**
 * @brief Maximum buffer size for crypto error string formatting.
 *
 * The buffer is used to format strings like "CRYPTO_ERROR(0x%02x)",
 * which requires at most 19 bytes plus null terminator. 32 bytes
 * provides adequate headroom.
 */
#define QUIC_CRYPTO_ERROR_STRING_MAX 32

/**
 * @brief Get human-readable string for a QUIC error code.
 *
 * Returns the RFC-defined name for transport errors, a formatted
 * string for crypto errors, or "APPLICATION_ERROR" for application
 * protocol errors.
 *
 * @param code Error code to convert.
 * @return Static string describing the error. Never returns NULL.
 *
 * @note Thread-safe: Uses thread-local storage for crypto error formatting.
 *       Each thread maintains its own buffer, so concurrent calls from
 *       different threads are safe. However, the returned pointer is only
 *       valid until the next call to this function in the same thread.
 *       Copy the result if you need to preserve it across multiple calls.
 */
extern const char *SocketQUIC_error_string (uint64_t code);

/**
 * @brief Get category name string.
 *
 * @param category Error category.
 * @return Static string for the category name.
 */
static inline const char *
SocketQUIC_error_category_string (SocketQUIC_ErrorCategory category)
{
  static const char *names[] = { "TRANSPORT", "CRYPTO", "APPLICATION",
                                 "UNKNOWN" };

  if (category > QUIC_ERROR_CATEGORY_UNKNOWN)
    return "UNKNOWN";

  return names[category];
}

/* ============================================================================
 * Error Handling (RFC 9000 Section 11)
 * ============================================================================
 */

/**
 * @brief Check if an error code causes connection-level termination.
 *
 * Transport errors and crypto errors are connection-fatal and require
 * sending a CONNECTION_CLOSE frame and closing the entire connection.
 * Application errors may be connection-fatal depending on the application
 * protocol.
 *
 * @param code Error code to check.
 * @return 1 if error is connection-fatal, 0 if stream-level only.
 *
 * @note Application errors (>= 0x0200) are treated as potentially
 *       connection-fatal. The application should escalate appropriately.
 */
extern int SocketQUIC_error_is_connection_fatal (uint64_t code);

/**
 * @brief Send CONNECTION_CLOSE frame and terminate connection.
 *
 * Constructs and sends a CONNECTION_CLOSE frame with the specified error
 * code and reason phrase. This closes the entire connection and all
 * associated streams.
 *
 * @param conn   Connection to close.
 * @param code   Error code (transport or application).
 * @param reason Human-readable reason phrase (may be NULL).
 * @param out    Output buffer for encoded frame.
 * @param out_len Size of output buffer.
 *
 * @return Number of bytes written to out, or 0 on error.
 *
 * @note The connection state should be set to CLOSING after calling this.
 *       Transport errors use frame type 0x1c, application errors use 0x1d.
 */
extern size_t SocketQUIC_send_connection_close (SocketQUICConnection_T conn,
                                                 uint64_t code,
                                                 const char *reason,
                                                 uint8_t *out,
                                                 size_t out_len);

/**
 * @brief Send RESET_STREAM frame to terminate a stream.
 *
 * Constructs and sends a RESET_STREAM frame with the specified error code
 * and final size. This abruptly terminates the sending side of the stream.
 * The connection continues to operate normally.
 *
 * @param stream     Stream to reset.
 * @param code       Application error code.
 * @param final_size Final size of the stream in bytes.
 * @param out        Output buffer for encoded frame.
 * @param out_len    Size of output buffer.
 *
 * @return Number of bytes written to out, or 0 on error.
 *
 * @note After sending RESET_STREAM, the stream state should transition
 *       to RESET_SENT. No further data can be sent on this stream.
 */
extern size_t SocketQUIC_send_stream_reset (SocketQUICStream_T stream,
                                             uint64_t code,
                                             uint64_t final_size,
                                             uint8_t *out,
                                             size_t out_len);

/**
 * @brief Send STOP_SENDING frame to request peer stop sending.
 *
 * Constructs and sends a STOP_SENDING frame requesting the peer to stop
 * sending on the specified stream. This is used when the receiver does
 * not want to receive more data.
 *
 * @param stream  Stream to stop receiving.
 * @param code    Application error code.
 * @param out     Output buffer for encoded frame.
 * @param out_len Size of output buffer.
 *
 * @return Number of bytes written to out, or 0 on error.
 */
extern size_t SocketQUIC_send_stop_sending (SocketQUICStream_T stream,
                                             uint64_t code,
                                             uint8_t *out,
                                             size_t out_len);

/** @} */

#endif /* SOCKETQUICERROR_INCLUDED */
