/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICTransportParams.h
 * @brief QUIC Transport Parameters (RFC 9000 Section 18).
 *
 * Transport parameters are exchanged during the TLS handshake to negotiate
 * connection settings. Each endpoint declares its limits and preferences
 * for the connection.
 *
 * Key features:
 *   - Parameters encoded as TLV (Type-Length-Value) using QUIC varints
 *   - Some parameters are role-specific (client vs server)
 *   - Validation ensures compliance with RFC 9000 requirements
 *   - Default values follow RFC 9000 Section 18.2
 *
 * Thread Safety: Individual parameter structures are not thread-safe.
 * Use external synchronization when sharing across threads.
 *
 * @defgroup quic_transport_params QUIC Transport Parameters Module
 * @{
 * @see https://www.rfc-editor.org/rfc/rfc9000#section-18
 */

#ifndef SOCKETQUICTRANSPORTPARAMS_INCLUDED
#define SOCKETQUICTRANSPORTPARAMS_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include "quic/SocketQUICConnectionID.h"

/**
 * @brief Transport parameter identifiers.
 *
 * These values are used as the type field in the TLV encoding.
 * Reserved values and those with special semantics are noted.
 */
typedef enum
{
  QUIC_TP_ORIGINAL_DCID = 0x00, /**< Server only: original DCID from client */
  QUIC_TP_MAX_IDLE_TIMEOUT = 0x01,      /**< Max idle timeout (ms) */
  QUIC_TP_STATELESS_RESET_TOKEN = 0x02, /**< Server only: reset token */
  QUIC_TP_MAX_UDP_PAYLOAD_SIZE = 0x03,  /**< Max UDP payload size */
  QUIC_TP_INITIAL_MAX_DATA = 0x04,      /**< Initial connection flow ctrl */
  QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL = 0x05,  /**< Local bidi stream */
  QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = 0x06, /**< Remote bidi stream */
  QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI = 0x07, /**< Unidirectional stream */
  QUIC_TP_INITIAL_MAX_STREAMS_BIDI = 0x08,    /**< Max bidi streams */
  QUIC_TP_INITIAL_MAX_STREAMS_UNI = 0x09,     /**< Max uni streams */
  QUIC_TP_ACK_DELAY_EXPONENT = 0x0a,          /**< ACK delay scaling */
  QUIC_TP_MAX_ACK_DELAY = 0x0b,               /**< Max ACK delay (ms) */
  QUIC_TP_DISABLE_ACTIVE_MIGRATION = 0x0c,    /**< Disable migration */
  QUIC_TP_PREFERRED_ADDRESS = 0x0d,   /**< Server only: preferred addr */
  QUIC_TP_ACTIVE_CONNID_LIMIT = 0x0e, /**< Active CID limit */
  QUIC_TP_INITIAL_SCID = 0x0f,        /**< Initial source CID */
  QUIC_TP_RETRY_SCID = 0x10,          /**< Retry source CID (server) */

  /* QUIC v2 and extensions */
  QUIC_TP_VERSION_INFO = 0x11, /**< RFC 9369: Version Information */

  /* QUIC datagram extension (RFC 9221) */
  QUIC_TP_MAX_DATAGRAM_FRAME_SIZE = 0x20, /**< Max DATAGRAM frame size */

  /* Greasing values (RFC 9000 Section 18.1) */
  QUIC_TP_GREASE_MIN = 0x1b,  /**< First GREASE value pattern */
  QUIC_TP_GREASE_MAX = 0xff00 /**< Last common GREASE range */
} SocketQUICTransportParamID;

/**
 * @brief Minimum max_udp_payload_size value (RFC 9000 Section 18.2).
 *
 * Endpoints MUST support at least 1200 bytes.
 */
#define QUIC_TP_MIN_UDP_PAYLOAD_SIZE 1200

/**
 * @brief Default max_udp_payload_size value.
 *
 * 65527 = 65535 - 8 (UDP header size).
 */
#define QUIC_TP_DEFAULT_MAX_UDP_PAYLOAD_SIZE 65527

/**
 * @brief Default max_idle_timeout (0 = disabled).
 */
#define QUIC_TP_DEFAULT_MAX_IDLE_TIMEOUT 0

/**
 * @brief Default initial_max_data (0 = no data allowed).
 */
#define QUIC_TP_DEFAULT_INITIAL_MAX_DATA 0

/**
 * @brief Default initial_max_stream_data values (0 = no data allowed).
 */
#define QUIC_TP_DEFAULT_INITIAL_MAX_STREAM_DATA 0

/**
 * @brief Default initial_max_streams values (0 = no streams allowed).
 */
#define QUIC_TP_DEFAULT_INITIAL_MAX_STREAMS 0

/**
 * @brief Default ack_delay_exponent (3 = multiply by 8).
 */
#define QUIC_TP_DEFAULT_ACK_DELAY_EXPONENT 3

/**
 * @brief Maximum ack_delay_exponent value.
 */
#define QUIC_TP_MAX_ACK_DELAY_EXPONENT 20

/**
 * @brief Default max_ack_delay in milliseconds.
 */
#define QUIC_TP_DEFAULT_MAX_ACK_DELAY 25

/**
 * @brief Maximum max_ack_delay in milliseconds (2^14).
 */
#define QUIC_TP_MAX_MAX_ACK_DELAY 16384

/**
 * @brief Minimum active_connection_id_limit (RFC 9000 Section 18.2).
 */
#define QUIC_TP_MIN_ACTIVE_CONNID_LIMIT 2

/**
 * @brief Default active_connection_id_limit.
 */
#define QUIC_TP_DEFAULT_ACTIVE_CONNID_LIMIT 2

/**
 * @brief Maximum encoded transport parameters size (conservative).
 *
 * Generous buffer for all parameters with large preferred_address.
 */
#define QUIC_TP_MAX_ENCODED_SIZE 512

/**
 * @brief Preferred address transport parameter structure.
 *
 * Sent by servers to indicate an alternative address for the client
 * to migrate to after completing the handshake.
 */
typedef struct SocketQUICPreferredAddress
{
  uint8_t ipv4_address[4];                /**< IPv4 address */
  uint16_t ipv4_port;                     /**< IPv4 port */
  uint8_t ipv6_address[16];               /**< IPv6 address */
  uint16_t ipv6_port;                     /**< IPv6 port */
  SocketQUICConnectionID_T connection_id; /**< CID for migration */
  uint8_t stateless_reset_token[QUIC_STATELESS_RESET_TOKEN_LEN]; /**< Token */
  int present; /**< Non-zero if preferred address is set */
} SocketQUICPreferredAddress_T;

/**
 * @brief QUIC Transport Parameters structure.
 *
 * Contains all transport parameters exchanged during the handshake.
 * Use SocketQUICTransportParams_init() to initialize with defaults.
 */
typedef struct SocketQUICTransportParams
{
  /* Connection IDs */
  SocketQUICConnectionID_T original_dcid; /**< Original destination CID */
  SocketQUICConnectionID_T initial_scid;  /**< Initial source CID */
  SocketQUICConnectionID_T retry_scid;    /**< Retry source CID */

  /* Flags for presence of optional parameters */
  int has_original_dcid;         /**< original_dcid is set */
  int has_initial_scid;          /**< initial_scid is set */
  int has_retry_scid;            /**< retry_scid is set */
  int has_stateless_reset_token; /**< stateless_reset_token is set */

  /* Stateless reset token (server only) */
  uint8_t stateless_reset_token[QUIC_STATELESS_RESET_TOKEN_LEN];

  /* Connection limits */
  uint64_t max_idle_timeout;     /**< Max idle timeout in ms (0 = disabled) */
  uint64_t max_udp_payload_size; /**< Max UDP payload (min 1200) */

  /* Flow control limits */
  uint64_t initial_max_data; /**< Initial connection-level limit */
  uint64_t initial_max_stream_data_bidi_local;  /**< For locally-init bidi */
  uint64_t initial_max_stream_data_bidi_remote; /**< For peer-init bidi */
  uint64_t initial_max_stream_data_uni;         /**< For unidirectional */

  /* Stream limits */
  uint64_t initial_max_streams_bidi; /**< Max bidi streams peer can open */
  uint64_t initial_max_streams_uni;  /**< Max uni streams peer can open */

  /* ACK behavior */
  uint64_t ack_delay_exponent; /**< Exponent for ACK delay encoding */
  uint64_t max_ack_delay;      /**< Max ACK delay in ms */

  /* Migration control */
  int disable_active_migration; /**< Non-zero to disable migration */

  /* Connection ID management */
  uint64_t active_connection_id_limit; /**< Max active CIDs (min 2) */

  /* Server preferred address */
  SocketQUICPreferredAddress_T preferred_address;

  /* Extension parameters */
  uint64_t max_datagram_frame_size; /**< RFC 9221: Max DATAGRAM size (0=off) */
  int has_max_datagram_frame_size;  /**< max_datagram_frame_size is set */

} SocketQUICTransportParams_T;

/**
 * @brief Result codes for transport parameter operations.
 */
typedef enum
{
  QUIC_TP_OK = 0,              /**< Operation succeeded */
  QUIC_TP_ERROR_NULL,          /**< NULL pointer argument */
  QUIC_TP_ERROR_BUFFER,        /**< Buffer too small */
  QUIC_TP_ERROR_INCOMPLETE,    /**< Need more input data */
  QUIC_TP_ERROR_INVALID_VALUE, /**< Invalid parameter value */
  QUIC_TP_ERROR_DUPLICATE,     /**< Duplicate parameter */
  QUIC_TP_ERROR_ROLE,          /**< Parameter not allowed for role */
  QUIC_TP_ERROR_REQUIRED,      /**< Required parameter missing */
  QUIC_TP_ERROR_ENCODING       /**< Encoding error */
} SocketQUICTransportParams_Result;

/**
 * @brief QUIC endpoint role.
 */
typedef enum
{
  QUIC_ROLE_CLIENT = 0, /**< Client role */
  QUIC_ROLE_SERVER = 1  /**< Server role */
} SocketQUICRole;

/**
 * @brief Initialize transport parameters with RFC 9000 defaults.
 *
 * Sets all parameters to their default values per RFC 9000 Section 18.2.
 * Call this before setting specific parameter values.
 *
 * @param params Transport parameters structure to initialize.
 */
extern void
SocketQUICTransportParams_init (SocketQUICTransportParams_T *params);

/**
 * @brief Set transport parameters to sensible connection defaults.
 *
 * Unlike init() which sets RFC defaults (many zeros), this sets
 * reasonable values for a typical connection.
 *
 * @param params Transport parameters structure to configure.
 * @param role   Endpoint role (client or server).
 */
extern void
SocketQUICTransportParams_set_defaults (SocketQUICTransportParams_T *params,
                                        SocketQUICRole role);

/**
 * @brief Calculate encoded size of transport parameters.
 *
 * Returns the number of bytes needed to encode the parameters.
 * Use this to allocate an appropriately sized buffer before encoding.
 *
 * @param params Transport parameters to measure.
 * @param role   Endpoint role (affects which parameters are encoded).
 *
 * @return Number of bytes needed, or 0 on error.
 */
extern size_t SocketQUICTransportParams_encoded_size (
    const SocketQUICTransportParams_T *params, SocketQUICRole role);

/**
 * @brief Encode transport parameters to wire format.
 *
 * Encodes parameters as TLV format per RFC 9000 Section 18.
 * Role-specific parameters are included or excluded based on role.
 *
 * @param params      Transport parameters to encode.
 * @param role        Endpoint role.
 * @param output      Output buffer for encoded data.
 * @param output_size Size of output buffer.
 *
 * @return Number of bytes written, or 0 on error.
 */
extern size_t
SocketQUICTransportParams_encode (const SocketQUICTransportParams_T *params,
                                  SocketQUICRole role,
                                  uint8_t *output,
                                  size_t output_size);

/**
 * @brief Decode transport parameters from wire format.
 *
 * Parses TLV-encoded parameters. Unknown parameters are ignored
 * per RFC 9000 Section 18.1 to support future extensions.
 *
 * @param data     Input buffer containing encoded parameters.
 * @param len      Size of input buffer.
 * @param role     Role of the PEER that sent these parameters.
 * @param params   Output: decoded transport parameters.
 * @param consumed Output: number of bytes consumed.
 *
 * @return QUIC_TP_OK on success, error code otherwise.
 */
extern SocketQUICTransportParams_Result
SocketQUICTransportParams_decode (const uint8_t *data,
                                  size_t len,
                                  SocketQUICRole peer_role,
                                  SocketQUICTransportParams_T *params,
                                  size_t *consumed);

/**
 * @brief Validate transport parameters for correctness.
 *
 * Checks that all values are within RFC 9000 allowed ranges and
 * that role-specific requirements are met.
 *
 * @param params Transport parameters to validate.
 * @param role   Role of the endpoint that sent these parameters.
 *
 * @return QUIC_TP_OK if valid, error code describing first violation.
 */
extern SocketQUICTransportParams_Result
SocketQUICTransportParams_validate (const SocketQUICTransportParams_T *params,
                                    SocketQUICRole role);

/**
 * @brief Validate that required parameters are present.
 *
 * Checks that all mandatory parameters for the given role are set.
 *
 * @param params Transport parameters to check.
 * @param role   Role of the endpoint that sent these parameters.
 *
 * @return QUIC_TP_OK if all required params present, error code otherwise.
 */
extern SocketQUICTransportParams_Result
SocketQUICTransportParams_validate_required (
    const SocketQUICTransportParams_T *params, SocketQUICRole role);

/**
 * @brief Copy transport parameters.
 *
 * @param dst Destination structure.
 * @param src Source structure.
 *
 * @return QUIC_TP_OK on success, QUIC_TP_ERROR_NULL if either is NULL.
 */
extern SocketQUICTransportParams_Result
SocketQUICTransportParams_copy (SocketQUICTransportParams_T *dst,
                                const SocketQUICTransportParams_T *src);

/**
 * @brief Get string representation of result code.
 *
 * @param result Result code to convert.
 *
 * @return Human-readable string describing the result.
 */
extern const char *SocketQUICTransportParams_result_string (
    SocketQUICTransportParams_Result result);

/**
 * @brief Get string representation of transport parameter ID.
 *
 * @param id Transport parameter ID.
 *
 * @return Human-readable name, or "unknown" for unrecognized IDs.
 */
extern const char *
SocketQUICTransportParams_id_string (SocketQUICTransportParamID id);

/**
 * @brief Calculate effective idle timeout from both endpoints.
 *
 * The effective timeout is the minimum of the two endpoints' values,
 * or zero if either is zero (disabling idle timeout).
 *
 * @param local  Local transport parameters.
 * @param remote Remote transport parameters.
 *
 * @return Effective idle timeout in milliseconds, or 0 if disabled.
 */
extern uint64_t SocketQUICTransportParams_effective_idle_timeout (
    const SocketQUICTransportParams_T *local,
    const SocketQUICTransportParams_T *remote);

/** @} */

#endif /* SOCKETQUICTRANSPORTPARAMS_INCLUDED */
