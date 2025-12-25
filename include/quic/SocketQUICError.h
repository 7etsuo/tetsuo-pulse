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

#include <stdint.h>

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
 * @brief Get human-readable string for a QUIC error code.
 *
 * Returns the RFC-defined name for transport errors, a formatted
 * string for crypto errors, or "APPLICATION_ERROR" for application
 * protocol errors.
 *
 * @param code Error code to convert.
 * @return Static string describing the error. Never returns NULL.
 *
 * @note For crypto errors, a static buffer is used. Not thread-safe
 *       for crypto errors if called concurrently with different codes.
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

/** @} */

#endif /* SOCKETQUICERROR_INCLUDED */
