/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketWS-private.h
 * @brief Internal implementation details for WebSocket module.
 * @internal
 * @ingroup websocket
 *
 * Contains private structures, constants, and helper functions for SocketWS.
 * Not for public use - API unstable and may change without notice.
 *
 * References:
 * - RFC 6455: The WebSocket Protocol
 * - RFC 7692: Compression Extensions for WebSocket (permessage-deflate)
 *
 * @see SocketWS.h for public API.
 * @see @ref websocket for module overview (if defined).
 */

#ifndef SOCKETWS_PRIVATE_INCLUDED
#define SOCKETWS_PRIVATE_INCLUDED

/* Include public header for type definitions */
#include "socket/SocketWS.h"

/* Additional internal headers */
#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketCrypto.h"
#include "core/SocketTimer.h"
#include "core/SocketUTF8.h"
#include "core/SocketUtil.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"
#include "socket/SocketWS-transport.h"

#include <stddef.h>
#include <stdint.h>

#ifdef SOCKETWS_HAS_DEFLATE
#include <zlib.h>
#endif

/**
 * @section config_constants Configuration Constants
 * @internal
 * @ingroup websocket
 *
 * Compile-time constants controlling WebSocket behavior, limits, and defaults.
 * Override via CMake or preprocessor before including headers.
 *
 * @see SocketWS_Config for runtime configuration.
 */

/** Maximum WebSocket frame size (default 16MB) */
#ifndef SOCKETWS_MAX_FRAME_SIZE
#define SOCKETWS_MAX_FRAME_SIZE (16 * 1024 * 1024)
#endif

/**
 * @section handshake_constants Handshake Constants
 * @internal
 * @ingroup websocket
 *
 * Constants for HTTP upgrade handshake (client request, server response).
 * Includes protocol version, header values, buffer sizes, key lengths.
 *
 * @see SocketWS_Handshake for runtime handshake state.
 * @see RFC 6455 Section 1.3 for version, Section 4 for handshake format.
 */

/** WebSocket protocol version per RFC 6455 */
#define SOCKETWS_PROTOCOL_VERSION "13"

/** Maximum size for HTTP upgrade request buffer */
#ifndef SOCKETWS_HANDSHAKE_REQUEST_SIZE
#define SOCKETWS_HANDSHAKE_REQUEST_SIZE 4096
#endif

/** Maximum size for HTTP upgrade response buffer */
#ifndef SOCKETWS_HANDSHAKE_RESPONSE_SIZE
#define SOCKETWS_HANDSHAKE_RESPONSE_SIZE 4096
#endif

/** Maximum size for reject response buffer */
#ifndef SOCKETWS_REJECT_RESPONSE_SIZE
#define SOCKETWS_REJECT_RESPONSE_SIZE 1024
#endif

/** Maximum size for reject response body */
#ifndef SOCKETWS_REJECT_BODY_MAX_SIZE
#define SOCKETWS_REJECT_BODY_MAX_SIZE 512
#endif

/** Maximum size for reject response status phrase */
#define SOCKETWS_REJECT_STATUS_PHRASE_SIZE 64

/** Value for Upgrade header in WebSocket handshake */
#define SOCKETWS_UPGRADE_VALUE "websocket"

/** Value for Connection header in WebSocket handshake */
#define SOCKETWS_CONNECTION_VALUE "Upgrade"

/** Default HTTP port (used to omit port from Host header) */
#define SOCKETWS_DEFAULT_HTTP_PORT 80

/** Default HTTPS port (used to omit port from Host header) */
#define SOCKETWS_DEFAULT_HTTPS_PORT 443

/** Expected length of Base64-encoded Sec-WebSocket-Key */
#define SOCKETWS_KEY_BASE64_LENGTH 24

/** Raw Sec-WebSocket-Key size in bytes (before Base64 encoding) */
#define SOCKETWS_KEY_RAW_SIZE 16

/** No port specified (for Host header logic) */
#define SOCKETWS_NO_PORT 0

/** Maximum size for URL path buffer in SocketWS_connect() */
#define SOCKETWS_MAX_PATH_SIZE 1024

/**
 * @section masking_constants XOR Masking Constants
 * @internal
 * @ingroup websocket
 *
 * Constants for client-to-server payload masking (4-byte key XOR).
 * Optimization: 64-bit aligned XOR loops, mask cycling.
 *
 * Masking required for client frames to prevent proxy attacks.
 * Server frames unmasked.
 *
 * @see ws_mask_payload() optimized masking function.
 * @see ws_mask_payload_offset() for incremental masking.
 * @see RFC 6455 Section 5.3 for masking rationale and algorithm.
 */

/** Alignment size for optimized 64-bit XOR masking */
#define SOCKETWS_XOR_ALIGN_SIZE 8

/** Mask for 8-byte alignment check: (ptr & MASK) gives misalignment */
#define SOCKETWS_XOR_ALIGN_MASK 7

/** RFC 6455: Mask key is always 4 bytes */
#define SOCKETWS_MASK_KEY_SIZE 4

/** Wrap mask for mask key indexing: (offset & MASK) cycles 0-3 */
#define SOCKETWS_MASK_KEY_INDEX_MASK 3

/**
 * @section frame_header_constants Frame Header Constants
 * @internal
 * @ingroup websocket
 *
 * Constants for WebSocket frame header format and lengths.
 * Header: 2-14 bytes (FIN/RSV/opcode + MASK/len + ext len + mask key).
 *
 * Length encoding: 7-bit direct, 126=16-bit, 127=64-bit.
 * Control frames: max 125 byte payload, no fragmentation.
 *
 * @see SocketWS_FrameParse for parsing.
 * @see ws_frame_build_header() for serialization.
 * @see RFC 6455 Section 5.2 for detailed format.
 */

/** Minimum frame header size: 1 byte (FIN+RSV+opcode) + 1 byte (MASK+len) */
#define SOCKETWS_BASE_HEADER_SIZE 2

/** Payload length value indicating 16-bit extended length follows */
#define SOCKETWS_EXTENDED_LEN_16 126

/** Payload length value indicating 64-bit extended length follows */
#define SOCKETWS_EXTENDED_LEN_64 127

/** Maximum payload length that fits in 7-bit field */
#define SOCKETWS_MAX_7BIT_PAYLOAD 125

/** Maximum payload length that fits in 16-bit extended field */
#define SOCKETWS_MAX_16BIT_PAYLOAD 65535

/** Size of 16-bit extended length field */
#define SOCKETWS_EXTENDED_LEN_16_SIZE 2

/** Size of 64-bit extended length field */
#define SOCKETWS_EXTENDED_LEN_64_SIZE 8

/**
 * @section frame_bitmasks Frame Header Bit Masks
 * @internal
 * @ingroup websocket
 *
 * Bit masks for extracting fields from frame header bytes.
 * First byte: FIN (7), RSV1-3 (6-4), Opcode (3-0)
 * Second byte: MASK (7), Payload len (6-0)
 *
 * Used in parsing (ws_frame_parse_header) and building
 * (ws_frame_build_header).
 *
 * @see RFC 6455 Section 5.2 Table 2-3 for bit positions.
 */

/** FIN bit: indicates final fragment of message */
#define SOCKETWS_FIN_BIT 0x80

/** RSV1 bit: used for permessage-deflate compression */
#define SOCKETWS_RSV1_BIT 0x40

/** RSV2 bit: reserved, must be 0 */
#define SOCKETWS_RSV2_BIT 0x20

/** RSV3 bit: reserved, must be 0 */
#define SOCKETWS_RSV3_BIT 0x10

/** Opcode mask: lower 4 bits of first byte */
#define SOCKETWS_OPCODE_MASK 0x0F

/** MASK bit: indicates payload is masked (second byte, bit 7) */
#define SOCKETWS_MASK_BIT 0x80

/** Payload length mask: lower 7 bits of second byte */
#define SOCKETWS_PAYLOAD_LEN_MASK 0x7F

/**
 * @section send_config Send Buffer Configuration
 * @internal
 * @ingroup websocket
 *
 * Runtime constants for send/recv buffering, message limits, control payloads.
 * Defaults suitable for most use cases; override via config or defines.
 *
 * Buffers sized for efficiency (64KB), chunks for partial sends.
 * Limits prevent DoS: max frame/message, fragments, close reason.
 *
 * @see SocketBuf_T for underlying buffer impl.
 * @see SocketWS_Config for user-configurable limits.
 */

/** Chunk size for data frame payload sending (8KB) */
#ifndef SOCKETWS_SEND_CHUNK_SIZE
#define SOCKETWS_SEND_CHUNK_SIZE 8192
#endif

/** Maximum reassembled message size (default 64MB) */
#ifndef SOCKETWS_MAX_MESSAGE_SIZE
#define SOCKETWS_MAX_MESSAGE_SIZE (64 * 1024 * 1024)
#endif

/** Maximum fragments per message */
#ifndef SOCKETWS_MAX_FRAGMENTS
#define SOCKETWS_MAX_FRAGMENTS 1000
#endif

/** Maximum control frame payload (RFC 6455 mandates 125) */
#define SOCKETWS_MAX_CONTROL_PAYLOAD 125

/** Maximum close reason length (125 - 2 bytes for code) */
#define SOCKETWS_MAX_CLOSE_REASON 123

/** Internal receive buffer size */
#ifndef SOCKETWS_RECV_BUFFER_SIZE
#define SOCKETWS_RECV_BUFFER_SIZE (64 * 1024)
#endif

/** Internal send buffer size */
#ifndef SOCKETWS_SEND_BUFFER_SIZE
#define SOCKETWS_SEND_BUFFER_SIZE (64 * 1024)
#endif

/** Error buffer size */
#define SOCKETWS_ERROR_BUFSIZE 256

/** Maximum frame header size (2 + 8 + 4 = 14 bytes) */
#define SOCKETWS_MAX_HEADER_SIZE 14

/** Default ping interval (0 = disabled) */
#define SOCKETWS_DEFAULT_PING_INTERVAL_MS 0

/** Default ping timeout */
#define SOCKETWS_DEFAULT_PING_TIMEOUT_MS 30000

/** Handshake timeout in milliseconds */
#define SOCKETWS_HANDSHAKE_TIMEOUT_MS 5000

/** Default deflate window bits */
#define SOCKETWS_DEFAULT_DEFLATE_WINDOW_BITS 15

/** Default deflate compression level (6 = balanced speed/ratio) */
#define SOCKETWS_DEFAULT_DEFLATE_COMPRESSION_LEVEL 6

/** Maximum iterations for message buffer growth (DoS protection) */
#define SOCKETWS_MAX_GROWTH_ITERATIONS 64

/* SocketWS_Config is defined in public header (SocketWS.h) */

/* ============================================================================
 * Frame Parsing State
 * ============================================================================
 */

/**
 * @internal
 * @ingroup websocket
 * @brief States for the frame parsing state machine.
 *
 * Tracks progress through frame header parsing, length extension, masking, and
 * payload. Used to handle incremental frame reception in non-blocking mode.
 *
 * @see ws_frame_parse_header() for state transitions.
 * @see SocketWS_FrameParse for full parse context.
 */
typedef enum
{
  WS_FRAME_STATE_HEADER, /**< Reading frame header (opcode, fin, rsv, mask,
                            len) */
  WS_FRAME_STATE_EXTENDED_LEN, /**< Reading extended payload length (16/64-bit)
                                */
  WS_FRAME_STATE_MASK_KEY, /**< Reading 4-byte mask key (client frames only) */
  WS_FRAME_STATE_PAYLOAD,  /**< Reading payload data */
  WS_FRAME_STATE_COMPLETE  /**< Frame fully parsed */
} SocketWS_FrameState;

/**
 * @internal
 * @ingroup websocket
 * @brief Context for parsing incoming WebSocket frames.
 *
 * Manages incremental parsing of frame headers and payloads.
 * Supports partial reads for non-blocking sockets.
 * Handles variable-length fields: opcode/fin/rsv, mask bit, 7/16/64-bit
 * length, optional mask key.
 *
 * Usage:
 * - Initialize: memset or ws_frame_reset()
 * - Parse: ws_frame_parse_header() advances state and parses bytes
 * - Payload: Read payload_received bytes after header complete
 * - Reset: ws_frame_reset() for next frame
 *
 * @see SocketWS_FrameState for parsing states.
 * @see ws_frame_parse_header() main entry point.
 * @see ws_frame_build_header() for sending frames.
 * @see RFC 6455 Section 5.2 for frame format details.
 */
typedef struct
{
  SocketWS_FrameState state; /**< Current parsing state */

  /* Parsed header fields */
  int fin;                /**< FIN bit: final fragment of message */
  int rsv1;               /**< RSV1: compression flag (permessage-deflate) */
  int rsv2;               /**< RSV2: reserved, must be 0 */
  int rsv3;               /**< RSV3: reserved, must be 0 */
  SocketWS_Opcode opcode; /**< Frame opcode (data/control) */
  int masked;             /**< MASK bit: payload masked (client->server) */
  unsigned char mask_key[4]; /**< 4-byte mask key if masked */

  /* Payload tracking */
  uint64_t payload_len;      /**< Total payload length */
  uint64_t payload_received; /**< Bytes of payload received so far */

  /* Header buffer for partial reads */
  unsigned char header_buf[SOCKETWS_MAX_HEADER_SIZE]; /**< Temp buffer for
                                                         header bytes */
  size_t header_len;    /**< Bytes accumulated in header_buf */
  size_t header_needed; /**< Remaining bytes needed for current field */

} SocketWS_FrameParse;

/* ============================================================================
 * Message Reassembly State
 * ============================================================================
 */

/**
 * @internal
 * @ingroup websocket
 * @brief State for reassembling fragmented WebSocket messages.
 *
 * Accumulates data from multiple CONTINUATION frames into a single message
 * buffer. Supports UTF-8 validation for text messages across fragments.
 * Handles compression flag from first frame (RSV1).
 *
 * Limits enforced via config: max_message_size, max_fragments.
 *
 * Usage:
 * - Reset: ws_message_reset() before first fragment
 * - Append: ws_message_append() for each data frame fragment
 * - Finalize: ws_message_finalize() on last fragment (FIN=1), validates and
 * delivers
 *
 * @see ws_message_append() for adding fragments.
 * @see ws_message_finalize() for completion and validation.
 * @see SocketWS_Message for public message interface.
 * @see RFC 6455 Section 5.4 for fragmentation rules.
 */
typedef struct
{
  SocketWS_Opcode
      type; /**< Message type: TEXT or BINARY (from first frame opcode) */
  unsigned char *data;   /**< Reassembled message buffer (Arena-allocated) */
  size_t len;            /**< Current assembled length */
  size_t capacity;       /**< Allocated buffer capacity */
  size_t fragment_count; /**< Number of fragments received so far */
  int compressed;        /**< RSV1 set on first fragment (compression used) */

  /* UTF-8 validation state (for TEXT messages) */
  SocketUTF8_State utf8_state; /**< Incremental UTF-8 decoder state */
  int utf8_initialized;        /**< Whether UTF-8 validation started */

} SocketWS_MessageAssembly;

/* ============================================================================
 * Handshake State
 * ============================================================================
 */

/**
 * @internal
 * @ingroup websocket
 * @brief States for WebSocket HTTP upgrade handshake.
 *
 * Tracks progress of client or server handshake over HTTP/1.1.
 * Client: INIT -> SEND_REQUEST -> READ_RESPONSE -> COMPLETE/FAILED
 * Server: INIT -> SEND_RESPONSE -> COMPLETE/FAILED (request already parsed)
 *
 * @see SocketWS_Handshake for full handshake context.
 * @see SocketWS_handshake() public function that drives state machine.
 * @see RFC 6455 Section 4 for handshake details.
 */
typedef enum
{
  WS_HANDSHAKE_INIT,             /**< Initial state, prepare handshake data */
  WS_HANDSHAKE_SENDING_REQUEST,  /**< Client: Sending HTTP GET upgrade request
                                  */
  WS_HANDSHAKE_READING_RESPONSE, /**< Client: Reading HTTP 101 response;
                                    Server: reading client request if needed */
  WS_HANDSHAKE_COMPLETE, /**< Handshake successful, transition to frame mode */
  WS_HANDSHAKE_FAILED    /**< Handshake failed, error set */
} SocketWS_HandshakeState;

/**
 * @internal
 * @ingroup websocket
 * @brief Context for WebSocket HTTP upgrade handshake.
 *
 * Manages client or server handshake state, key generation/validation,
 * header negotiation (subprotocols, compression), and HTTP
 * parsing/serialization.
 *
 * Client:
 * - Generates Sec-WebSocket-Key, builds GET request with Upgrade: websocket
 * - Parses server response, validates Sec-WebSocket-Accept
 *
 * Server:
 * - Parses client request, computes Accept from key
 * - Validates required headers, negotiates extensions/subprotocols
 * - Sends 101 Switching Protocols response
 *
 * @see SocketWS_HandshakeState for state enum.
 * @see ws_handshake_client_init() / ws_handshake_server_init() for init.
 * @see ws_handshake_client_process() / ws_handshake_server_process() for I/O
 * loop.
 * @see SocketCrypto_websocket_accept_compute() for key validation.
 * @see RFC 6455 Section 4.2 for client handshake, Section 4.1 for server.
 */
typedef struct
{
  SocketWS_HandshakeState state; /**< Current handshake state */

  /* Client key (generated, used to validate accept) */
  char client_key[SOCKET_CRYPTO_WEBSOCKET_KEY_SIZE]; /**< Base64
                                                        Sec-WebSocket-Key (24
                                                        chars) */

  /* Expected accept value */
  char
      expected_accept[SOCKET_CRYPTO_WEBSOCKET_ACCEPT_SIZE]; /**< SHA1(key +
                                                               magic) base64 */

  /* HTTP parser for response */
  SocketHTTP1_Parser_T http_parser; /**< Parser for HTTP response/request */

  /* Negotiated values */
  char *selected_subprotocol;     /**< Negotiated subprotocol (Arena alloc) */
  int compression_negotiated;     /**< permessage-deflate negotiated? */
  int server_no_context_takeover; /**< Server no context takeover */
  int client_no_context_takeover; /**< Client no context takeover */
  int server_max_window_bits;     /**< Server max window bits (8-15) */
  int client_max_window_bits;     /**< Client max window bits (8-15) */

  /* Request buffer (client: upgrade request; server: response) */
  char *request_buf;   /**< Buffer for HTTP request/response */
  size_t request_len;  /**< Total length of HTTP message */
  size_t request_sent; /**< Bytes already sent */

} SocketWS_Handshake;

/* ============================================================================
 * Compression State (RFC 7692)
 * ============================================================================
 */

#ifdef SOCKETWS_HAS_DEFLATE
/**
 * @internal
 * @ingroup websocket
 * @brief Compression context for permessage-deflate extension (RFC 7692).
 *
 * Manages zlib streams for per-message compression/decompression.
 * Supports context takeover negotiation (no-takeover flags).
 * Window bits configurable per client/server.
 *
 * Initialization: ws_compression_init() after handshake negotiation.
 * Per-message: Compress before framing (RSV1=1), decompress after unmasking.
 * Cleanup: ws_compression_free() on close.
 *
 * Buffers: deflate_buf/inflate_buf for zlib operations (zlib-managed? No,
 * manual).
 *
 * @note Requires zlib library (SOCKETWS_HAS_DEFLATE).
 * @note Separate streams for send (deflate) and recv (inflate).
 * @see ws_compress_message() / ws_decompress_message() for usage.
 * @see RFC 7692 for extension details, context takeover semantics.
 */
typedef struct
{
  z_stream deflate_stream; /**< zlib deflate stream for outgoing messages */
  z_stream inflate_stream; /**< zlib inflate stream for incoming messages */
  int deflate_initialized; /**< deflate stream initialized? */
  int inflate_initialized; /**< inflate stream initialized? */

  /* Context takeover settings (negotiated) */
  int server_no_context_takeover; /**< Server disables context reuse */
  int client_no_context_takeover; /**< Client disables context reuse */
  int server_max_window_bits;     /**< Server max LZ77 window (8-15) */
  int client_max_window_bits;     /**< Client max LZ77 window (8-15) */

  /* Temporary buffers for zlib operations */
  unsigned char *deflate_buf; /**< Temp buffer for deflate output */
  size_t deflate_buf_size;    /**< Size of deflate_buf */
  unsigned char *inflate_buf; /**< Temp buffer for inflate output */
  size_t inflate_buf_size;    /**< Size of inflate_buf */

} SocketWS_Compression;
#endif

/* ============================================================================
 * Main WebSocket Context Structure
 * ============================================================================
 */

/**
 * @internal
 * @ingroup websocket
 * @brief Opaque WebSocket connection context holding all protocol state.
 *
 * Central opaque structure managing full WebSocket connection lifecycle,
 * from HTTP upgrade handshake through framed data exchange to graceful
 * closure. Publicly accessed only via SocketWS_T pointer and API functions;
 * internal fields private and unstable.
 *
 *  Key Responsibilities
 *
 * - HTTP/1.1 upgrade handshake (client/server)
 * - Frame parsing/serialization with masking/compression
 * - Message fragmentation/reassembly with UTF-8 validation
 * - Control frame handling (PING/PONG/CLOSE)
 * - Auto-keepalive via periodic PINGs
 * - Integration with SocketPoll for non-blocking I/O
 * - Error tracking and diagnostics
 *
 *  Lifecycle Management
 *
 * 1. **Creation**: SocketWS_client_new() or SocketWS_server_accept() allocates
 * and inits
 * 2. **Handshake**: SocketWS_handshake() or internal ws_handshake_*()
 * completes upgrade
 * 3. **Data Exchange**: SocketWS_send(), SocketWS_recv(), SocketWS_process()
 * loop
 * 4. **Closure**: SocketWS_close() sends CLOSE frame, awaits response
 * 5. **Cleanup**: SocketWS_free() releases arena, buffers, timers
 *
 *  Resource Ownership
 *
 * | Field | Ownership | Notes |
 * |-------|-----------|-------|
 * | socket | Transferred | Caller retains? No, owned until free |
 * | arena | Owned | All sub-allocs freed on dispose |
 * | recv_buf/send_buf | Owned | Circular buffers for buffering |
 * | poll | Referenced | Shared event loop instance |
 *
 *  State Subsystems
 *
 * - **Handshake**: HTTP parser, keys, negotiated extensions/subprotocols
 * - **Frame Parser**: Incremental header/payload parse (SocketWS_FrameParse)
 * - **Message Assembly**: Fragment collection with decompression/UTF-8
 * (SocketWS_MessageAssembly)
 * - **Compression**: zlib streams for permessage-deflate (if enabled)
 * - **Timers**: Auto-ping via SocketTimer
 * - **Error**: last_error code + formatted message
 *
 * Thread Safety: Not thread-safe; single-threaded use only. No internal
 * mutexes; concurrent access may corrupt state. For multi-thread, use one ws
 * per thread or external locking (not recommended).
 *
 * Non-blocking I/O: All functions handle EAGAIN/partial; integrate with
 * SocketPoll via SocketWS_fd() and SocketWS_process().
 *
 * @threadsafe No - no internal synchronization; serialize all operations on ws
 *
 * @note Dynamic fields (strings, buffers) allocated from ws->arena
 * @note socket field may be NULL post-transfer to higher layers
 * @warning Direct field access undefined; use getters/setters where available
 * @complexity Varies by operation; generally O(1) state access, O(payload) I/O
 *
 *  Example Internal Access (for library code)
 *
 * @code{.c}
 * // Internal: accessing state (not for users)
 * if (ws->state == WS_OPEN && ws->role == WS_CLIENT) {
 *     ws->frame.state = WS_FRAME_STATE_HEADER;
 * }
 * @endcode
 *
 * @see SocketWS_T Public opaque typedef
 * @see SocketWS_new() Internal constructor
 * @see SocketWS_free() Destructor
 * @see docs/WEBSOCKET.md Detailed WebSocket guide
 */
struct SocketWS
{
  /* Underlying resources */
  Socket_T
      socket;    /**< TCP/TLS socket (may be NULL if ownership transferred) */
  Arena_T arena; /**< Memory arena for all dynamic allocations */
  SocketBuf_T recv_buf; /**< Receive circular buffer for incoming data */
  SocketBuf_T send_buf; /**< Send circular buffer for outgoing data */
  SocketWS_Transport_T transport; /**< Transport abstraction (NULL = use socket
                                       directly for backward compat) */

  /* Configuration (copied at creation) */
  SocketWS_Config config; /**< User-provided configuration */

  /* State machine */
  SocketWS_State state; /**< High-level connection state
                           (CONNECTING/OPEN/CLOSING/CLOSED) */
  SocketWS_Role role;   /**< Client or server role (affects masking) */

  /* Handshake state */
  SocketWS_Handshake handshake; /**< HTTP upgrade handshake context */

  /* Frame parsing state */
  SocketWS_FrameParse frame; /**< Incoming frame parser */

  /* Message reassembly state */
  SocketWS_MessageAssembly message; /**< Fragmented message assembler */

  /* Compression state (conditional) */
#ifdef SOCKETWS_HAS_DEFLATE
  int compression_enabled; /**< Compression negotiated and active? */
  SocketWS_Compression
      compression; /**< Deflate/inflate streams and settings */
#endif

  /* Close state */
  int close_sent;                /**< Flag: sent CLOSE frame? */
  int close_received;            /**< Flag: received CLOSE frame? */
  SocketWS_CloseCode close_code; /**< Received/sent close code */
  char close_reason[SOCKETWS_MAX_CLOSE_REASON + 1]; /**< Close reason string */

  /* Ping/pong tracking (monotonic time) */
  int64_t last_ping_sent_time;     /**< Time last PING sent */
  int64_t last_pong_received_time; /**< Time last PONG received */
  int64_t last_pong_sent_time;     /**< Time last PONG sent (response) */
  unsigned char
      pending_ping_payload[SOCKETWS_MAX_CONTROL_PAYLOAD]; /**< Pending PING
                                                             payload */
  size_t pending_ping_len; /**< Length of pending PING payload */
  int awaiting_pong;       /**< Expecting PONG response? */

  /* Auto-ping timer integration */
  SocketTimer_T ping_timer; /**< Internal timer for auto-pings */
  SocketPoll_T poll;        /**< Associated poll instance (for timers) */

  /* Error tracking */
  SocketWS_Error last_error;              /**< Last error code */
  char error_buf[SOCKETWS_ERROR_BUFSIZE]; /**< Human-readable error message */

  /* URL components (client connect info) */
  char *host;  /**< Target host (for client handshake) */
  char *path;  /**< Request path (for client handshake) */
  int port;    /**< Target port */
  int use_tls; /**< Using TLS? (wss://) */
};

/**
 * @internal
 * @ingroup websocket
 * @brief Opaque type for WebSocket connection (public interface).
 *
 * In public header (SocketWS.h), defined as #define T SocketWS_T \n typedef
 * struct SocketWS *T; Here, reveals the pointer to private struct SocketWS.
 * Users should use opaque T without knowledge of internal layout.
 *
 * @see SocketWS.h public header.
 * @see struct SocketWS private implementation.
 */
typedef struct SocketWS *SocketWS_T;

/**
 * @internal
 * @ingroup websocket
 * @brief Thread-local exception declarations for SocketWS module.
 *
 * Declares module exceptions using SOCKET_DECLARE_MODULE_EXCEPTION.
 * These are raised via TRY/EXCEPT or RAISE_WS_ERROR macro.
 *
 * Public exceptions exposed in SocketWS.h:
 * - SocketWS_Failed: General failures
 * - SocketWS_ProtocolError: RFC violations
 * - SocketWS_Closed: Connection closed
 *
 * Internal use: RAISE_WS_ERROR for quick error raising with module context.
 *
 * @see Except.h for exception framework.
 * @see docs/ERROR_HANDLING.md for patterns.
 */

/* Module exception declaration moved to SocketWS.c to avoid unused variable
 * warnings when this header is included by other modules (e.g., SocketSecurity)
 */

/* Macro to raise exception with detailed error message */
#define RAISE_WS_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketWS, e)

/**
 * @section memory_helpers Internal Memory Helpers
 * @internal
 * @ingroup websocket
 *
 * Utility functions for arena-based string duplication.
 * All allocations use provided Arena_T for lifecycle management.
 *
 * @see Arena.h for memory allocation framework.
 */

/**
 * @brief Arena-allocated duplicate of input string.
 * @internal
 * @ingroup websocket
 *
 * Provides safe string duplication using the library's arena allocator.
 * Handles NULL input gracefully. Used internally for handshake headers,
 * subprotocols, and other string handling. Preserves null-termination.
 *
 * Edge cases:
 * - NULL str returns NULL without error.
 * - Empty string "" allocates single null byte.
 * - Allocation failure raises Arena_Failed exception.
 *
 * @param[in] arena Memory arena for allocation (must be valid).
 * @param[in] str Input C string to duplicate (may be NULL).
 *
 * @return Pointer to arena-allocated copy of str, or NULL if str is NULL.
 *         Caller should not free(); managed by arena lifecycle.
 *
 * @throws Arena_Failed If Arena_alloc() fails due to insufficient space.
 *
 * @threadsafe Yes - atomic if arena is thread-local or externally locked.
 *             Concurrent calls safe if arena mutexed.
 *
 *  Basic Usage
 *
 * @code{.c}
 * Arena_T arena = Arena_new();
 * char *dup = ws_copy_string(arena, "ws://example.com/path");
 * assert(strcmp(dup, "ws://example.com/path") == 0);
 * // dup valid until Arena_clear/dispose
 * Arena_dispose(&arena);
 * @endcode
 *
 *  With Exception Handling
 *
 * @code{.c}
 * char *header_value;
 * TRY {
 *     header_value = ws_copy_string(arena, http_header);
 * } EXCEPT(Arena_Failed) {
 *     SOCKET_LOG_ERROR_MSG("Failed to duplicate header: %s", http_header);
 *     return -1;
 * } END_TRY;
 * @endcode
 *
 * @note Equivalent to socket_util_arena_strdup(arena, str) but internal.
 * @note Does not perform UTF-8 validation; assumes valid C string.
 * @warning Arena must outlive all allocated strings.
 *
 * @complexity O(n) time where n = strlen(str); single allocation.
 * @complexity O(n) space for duplicated string.
 *
 * @see socket_util_arena_strdup() Public equivalent in utilities.
 * @see Arena_alloc() Underlying allocation mechanism.
 * @see Arena_dispose() For freeing allocated strings.
 */
char *ws_copy_string (Arena_T arena, const char *str);

/* ============================================================================
 * Internal Helper Functions - Transport
 * ============================================================================
 */

/**
 * @brief Check if WebSocket frames require client masking.
 * @internal
 * @ingroup websocket
 *
 * Per RFC 6455, client frames over TCP must be masked to prevent proxy cache
 * poisoning attacks. Per RFC 8441, HTTP/2 WebSocket frames do not use masking
 * as the HTTP/2 stream provides sufficient framing security.
 *
 * Uses transport abstraction's masking flag if transport is set, otherwise
 * falls back to RFC 6455 rule (client frames masked).
 *
 * @param[in] ws WebSocket context
 * @return 1 if masking required, 0 otherwise
 */
int ws_requires_masking (SocketWS_T ws);

/* ============================================================================
 * Internal Helper Functions - Frame Sending
 * ============================================================================
 */

/**
 * @brief Sends WebSocket control frame: PING, PONG, or CLOSE.
 * @internal
 * @ingroup websocket
 *
 * Constructs and transmits a control frame over the WebSocket connection.
 * Control frames are processed immediately, cannot be fragmented, and have
 * payload limit of 125 bytes. Used for keepalive (PING/PONG) and graceful
 * closure (CLOSE). Automatically flushes to socket if possible; otherwise
 * queues.
 *
 * Behavior:
 * - Builds frame header with opcode, no RSV (unless extensions), masked if
 * client.
 * - Validates len <= 125, opcode control type.
 * - Applies masking to payload if client role.
 * - Appends to send_buf, calls ws_flush_send_buffer().
 *
 * Error conditions:
 * - Invalid opcode (not 8/9/A): SocketWS_Failed
 * - len > SOCKETWS_MAX_CONTROL_PAYLOAD: truncates or fails
 * - Socket send error or closed: sets last_error, returns -1
 *
 * @param[in] ws Active WebSocket context (state must be OPEN)
 * @param[in] opcode Control opcode: WS_OPCODE_CLOSE (8), WS_OPCODE_PING (9),
 * WS_OPCODE_PONG (10)
 * @param[in] payload Payload bytes; NULL=empty. For CLOSE:
 * code(2B)+reason(UTF8); PING/PONG: app data
 * @param[in] len Exact payload length (0-125 bytes)
 *
 * @return 0 Success: frame built and queued/flushed
 * @return -1 Failure: error code in ws->last_error, msg in error_buf
 *
 * @throws SocketWS_Failed Invalid params, build error, or I/O failure
 * @throws SocketWS_Closed Connection not in OPEN state
 * @throws SocketWS_ProtocolError Invalid control opcode
 *
 * @threadsafe No - modifies ws->send_buf and socket state; serialize calls
 *
 *  Sending PING for Keepalive
 *
 * @code{.c}
 * // Simple ping to check peer responsiveness
 * unsigned char ping_data[] = {'H', 'e', 'l', 'l', 'o'};
 * if (ws_send_control_frame(ws, WS_OPCODE_PING, ping_data, sizeof(ping_data))
 * != 0) { SOCKET_LOG_ERROR("PING failed: %s", SocketWS_get_error_msg(ws));
 *     // Consider closing connection
 * }
 * @endcode
 *
 *  Initiating Graceful Close
 *
 * @code{.c}
 * // Send CLOSE with normal code 1000
 * uint16_t code = htons(1000); // Big-endian
 * TRY {
 *     ws_send_control_frame(ws, WS_OPCODE_CLOSE, (unsigned char*)&code, 2);
 *     ws->state = WS_CLOSING;  // Update state
 * } EXCEPT(SocketWS_Failed) {
 *     // Fallback to hard close
 *     Socket_shutdown(ws->socket, SHUT_RDWR);
 * } END_TRY;
 * @endcode
 *
 *  Responding to PING
 *
 * @code{.c}
 * // In frame handler: echo payload back as PONG
 * if (opcode == WS_OPCODE_PING) {
 *     ws_send_control_frame(ws, WS_OPCODE_PONG, received_payload,
 * received_len);
 * }
 * @endcode
 *
 * @note Payload for CLOSE: first 2 bytes uint16 BE status code, rest UTF-8
 * reason (total <=125)
 * @warning Use only valid close codes; see ws_is_valid_close_code()
 * @note If ws->config.close_auto_respond enabled, CLOSE triggers peer response
 * @complexity O(1 + len) - constant time header + linear payload mask/copy
 *
 * @see ws_send_data_frame() For fragmented data messages
 * @see ws_handle_control_frame() Incoming control processing
 * @see ws_send_close() Higher-level CLOSE sender
 * @see ws_flush_send_buffer() Underlying flush mechanism
 * @see RFC 6455 Sec. 5.5 (Control Frames), 7.1 (Close), 5.5.2 (Ping), 5.5.3
 * (Pong)
 */
int ws_send_control_frame (SocketWS_T ws, SocketWS_Opcode opcode,
                           const unsigned char *payload, size_t len);

/**
 * @brief Sends a WebSocket data frame (TEXT or BINARY).
 * @internal
 * @ingroup websocket
 * @param ws The WebSocket connection context.
 * @param opcode The data frame opcode (WS_OPCODE_TEXT or WS_OPCODE_BINARY).
 * @param data The payload data to send.
 * @param len The length of the payload data.
 * @param fin Non-zero if this is the final fragment of the message.
 * @return 0 on success, -1 on error (sets last_error).
 * @throws SocketWS_Failed if send fails, invalid opcode, or exceeds limits.
 * @note Supports fragmentation (fin=0 for continuation frames).
 * @note Payload masked for client role, unmasked for server.
 * @see ws_send_control_frame() for control frames.
 * @see RFC 6455 Section 5.6 for data frame format and masking.
 */
int ws_send_data_frame (SocketWS_T ws, SocketWS_Opcode opcode,
                        const unsigned char *data, size_t len, int fin);

/* ============================================================================
 * Internal Helper Functions - Frame Processing
 * ============================================================================
 */

/**
 * @brief Reset frame parser to initial state for new incoming frame.
 * @internal
 * @ingroup websocket
 *
 * Prepares SocketWS_FrameParse for parsing a new WebSocket frame header.
 * Clears accumulated header bytes, resets state to HEADER, zeros parsed fields
 * (fin, rsv, opcode, masked, mask_key, payload_len, payload_received), resets
 * header_len and header_needed. Essential for incremental parsing in loops.
 *
 * Usage pattern: Call after successful frame parse or to recover from
 * partial/error. Does not allocate/deallocate; safe to call frequently.
 *
 * @param[in,out] frame Pointer to frame parse structure (fields reset)
 *
 * @return void
 *
 * @throws None
 *
 * @threadsafe Yes - self-contained, no shared state if frame local
 *
 *  Initialization and Reset
 *
 * @code{.c}
 * // Initial setup
 * SocketWS_FrameParse frame;
 * memset(&frame, 0, sizeof(frame));  // Or use ws_frame_reset(&frame);
 *
 * // In receive loop
 * size_t consumed;
 * SocketWS_Error err = ws_frame_parse_header(&frame, recv_data, recv_len,
 * &consumed); if (err == WS_OK) {
 *     // Header parsed, now read payload
 *     // ... process payload ...
 *     ws_frame_reset(&frame);  // Ready for next
 * } else if (err == WS_PROTOCOL_ERROR) {
 *     ws_frame_reset(&frame);  // Recover
 * }
 * @endcode
 *
 * @note Can be used interchangeably with memset(&frame, 0, sizeof(frame))
 * @warning Ensure frame struct is properly aligned for header_buf
 * @complexity O(1) - fixed field assignments and memset if used
 *
 * @see ws_frame_parse_header() Next step after reset
 * @see SocketWS_FrameParse Full structure documentation
 * @see ws_message_reset() Analogous for message reassembly
 */
void ws_frame_reset (SocketWS_FrameParse *frame);

/**
 * @brief Incrementally parses WebSocket frame header from input data.
 * @internal
 * @ingroup websocket
 * @param frame The frame parse state structure.
 * @param data Buffer containing incoming frame bytes.
 * @param len Length of data buffer.
 * @param[out] consumed Number of bytes consumed from data (updated on call).
 * @return SocketWS_Error: WS_OK if header fully parsed, WS_NEED_MORE_DATA if
 * incomplete, or error code (e.g., WS_PROTOCOL_ERROR for invalid header).
 * @note Advances frame->state based on bytes parsed.
 * @note Handles variable header length (2-14 bytes).
 * @see ws_frame_reset() before first call.
 * @see RFC 6455 Section 5.2 for frame header format.
 */
SocketWS_Error ws_frame_parse_header (SocketWS_FrameParse *frame,
                                      const unsigned char *data, size_t len,
                                      size_t *consumed);

/**
 * @brief Receives and processes a complete WebSocket frame.
 * @internal
 * @ingroup websocket
 * @param ws The WebSocket context.
 * @param[out] frame_out Frame parse structure to populate.
 * @return 1 if data message completed, 0 if control frame handled,
 *         -1 on error, -2 if would block / need more data.
 * @note Handles incremental frame reception for non-blocking I/O.
 * @note Processes control frames internally (PING/PONG/CLOSE).
 * @see ws_frame_parse_header() for header parsing details.
 * @see ws_process_frames() caller loop.
 */
int ws_recv_frame (SocketWS_T ws, SocketWS_FrameParse *frame_out);

/**
 * @brief Builds the binary WebSocket frame header into output buffer.
 * @internal
 * @ingroup websocket
 * @param header Output buffer for header bytes (must hold at least
 * SOCKETWS_MAX_HEADER_SIZE).
 * @param fin Non-zero if final fragment (sets FIN bit).
 * @param opcode The frame opcode.
 * @param masked Non-zero if payload is masked (client frames).
 * @param mask_key 4-byte mask key if masked, ignored otherwise.
 * @param payload_len The payload length (encodes as 7/16/64-bit).
 * @return Number of bytes written to header (2-14), or 0 on error (invalid
 * params).
 * @note Validates opcode and length; does not include payload or mask
 * application.
 * @see ws_mask_payload() to mask payload after header.
 * @see RFC 6455 Section 5.2 for header encoding details.
 */
size_t ws_frame_build_header (unsigned char *header, int fin,
                              SocketWS_Opcode opcode, int masked,
                              const unsigned char *mask_key,
                              uint64_t payload_len);

/**
 * @brief Applies XOR masking to WebSocket payload data in place.
 * @internal
 * @ingroup websocket
 * @param data The payload buffer to mask (modified in place).
 * @param len The length of the data to mask.
 * @param mask The 4-byte masking key (cycles every 4 bytes).
 * @note Required for client-to-server frames per RFC.
 * @note Optimized with 64-bit aligned loops for performance.
 * @note Server frames must not be masked.
 * @see ws_mask_payload_offset() for incremental masking.
 * @see RFC 6455 Section 5.3 for masking algorithm.
 */
void ws_mask_payload (unsigned char *data, size_t len,
                      const unsigned char mask[4]);

/**
 * @brief Applies XOR masking to payload starting from a given mask offset.
 * @internal
 * @ingroup websocket
 * @param data The payload buffer to mask (modified in place).
 * @param len The length of the data to mask.
 * @param mask The 4-byte masking key.
 * @param offset Initial offset into the mask cycle (0-3).
 * @return The updated offset for the next chunk ((offset + len) % 4).
 * @note Used for incremental masking in streaming scenarios.
 * @note Equivalent to ws_mask_payload() when offset=0.
 * @see ws_mask_payload() for full payload masking.
 * @see RFC 6455 Section 5.3 masking details.
 */
size_t ws_mask_payload_offset (unsigned char *data, size_t len,
                               const unsigned char mask[4], size_t offset);

/* ============================================================================
 * Internal Helper Functions - Handshake
 * ============================================================================
 */

/**
 * @brief Initializes the client-side WebSocket handshake.
 * @internal
 * @ingroup websocket
 * @param ws The WebSocket context.
 * @return 0 on success, -1 on error (sets last_error).
 * @note Generates random Sec-WebSocket-Key and constructs HTTP GET upgrade
 * request.
 * @note Sets handshake.state to WS_HANDSHAKE_SENDING_REQUEST.
 * @see ws_handshake_client_process() to send request and read response.
 * @see SocketCrypto for key generation.
 * @see RFC 6455 Section 4.1 for client handshake.
 */
int ws_handshake_client_init (SocketWS_T ws);

/**
 * @brief Processes client handshake I/O in non-blocking manner.
 * @internal
 * @ingroup websocket
 * @param ws The WebSocket context.
 * @return 0 if handshake complete (state=COMPLETE), 1 if in progress (need
 * more I/O), -1 on error (sets last_error, state=FAILED).
 * @note Handles sending request and receiving response incrementally.
 * @note Validates Sec-WebSocket-Accept header.
 * @see ws_handshake_client_init() to start.
 * @see ws_handshake_validate_accept() for validation.
 * @see RFC 6455 Section 1.3 for opening handshake.
 */
int ws_handshake_client_process (SocketWS_T ws);

/**
 * @brief Initializes the server-side WebSocket handshake from HTTP request.
 * @internal
 * @ingroup websocket
 * @param ws The WebSocket context.
 * @param request The parsed SocketHTTP_Request from client upgrade.
 * @return 0 on success, -1 on error (invalid request, sets last_error).
 * @note Validates required headers (Upgrade, Connection, Sec-WebSocket-Key).
 * @note Computes Sec-WebSocket-Accept from client key.
 * @note Negotiates subprotocols and extensions (e.g., permessage-deflate).
 * @see SocketHTTP1_Parser for request parsing.
 * @see ws_handshake_server_process() to send response.
 * @see RFC 6455 Section 4.2.2 for server validation.
 */
int ws_handshake_server_init (SocketWS_T ws,
                              const SocketHTTP_Request *request);

/**
 * @brief Processes server handshake I/O in non-blocking manner.
 * @internal
 * @ingroup websocket
 * @param ws The WebSocket context.
 * @return 0 if handshake complete, 1 if in progress, -1 on error.
 * @note Sends 101 response after validation.
 * @note Transitions to frame mode on success.
 * @see ws_handshake_server_init() prerequisite.
 * @see RFC 6455 Section 4.1 for server opening handshake.
 */
int ws_handshake_server_process (SocketWS_T ws);

/**
 * @brief Validates the server's Sec-WebSocket-Accept header value.
 * @internal
 * @ingroup websocket
 * @param ws The WebSocket context (contains expected_accept).
 * @param accept The received accept string from server response.
 * @return 0 if matches expected value, -1 if mismatch or invalid.
 * @note Computes expected as SHA1(key + magic) base64.
 * @see SocketCrypto_websocket_accept_compute() for computation.
 * @see RFC 6455 Section 4.2.2 for accept key derivation.
 */
int ws_handshake_validate_accept (SocketWS_T ws, const char *accept);

/* ============================================================================
 * Internal Helper Functions - Compression
 * ============================================================================
 */

#ifdef SOCKETWS_HAS_DEFLATE
/**
 * @brief Initializes zlib streams for permessage-deflate compression.
 * @internal
 * @ingroup websocket
 * @param ws The WebSocket context with negotiated compression params.
 * @return 0 on success, -1 on error (zlib init fail, sets last_error).
 * @note Called after handshake if compression negotiated.
 * @note Sets up deflate and inflate streams with window bits, no-takeover
 * flags.
 * @see ws_compression_free() for cleanup.
 * @see RFC 7692 for permessage-deflate parameters.
 */
int ws_compression_init (SocketWS_T ws);

/**
 * @brief Frees zlib streams and buffers for compression context.
 * @internal
 * @ingroup websocket
 * @param ws The WebSocket context.
 * @note Deflates/inflates end and frees temporary buffers.
 * @note Called on connection close if compression enabled.
 * @see ws_compression_init() counterpart.
 * @see zlib.h deflateEnd/inflateEnd.
 */
void ws_compression_free (SocketWS_T ws);

/**
 * @brief Compresses a message payload using permessage-deflate.
 * @internal
 * @ingroup websocket
 * @param ws The WebSocket context with compression config.
 * @param input Uncompressed input data.
 * @param input_len Length of input.
 * @param[out] output Pointer to compressed data (allocated by function using
 * arena).
 * @param[out] output_len Length of compressed output.
 * @return 0 on success, -1 on zlib error.
 * @note Per-message compression; reset context if no-takeover.
 * @note Sets RSV1 bit in frame header when used.
 * @see ws_decompress_message() counterpart.
 * @see RFC 7692 Section 7 for compression format.
 */
int ws_compress_message (SocketWS_T ws, const unsigned char *input,
                         size_t input_len, unsigned char **output,
                         size_t *output_len);

/**
 * @brief Decompresses a compressed message payload using permessage-deflate.
 * @internal
 * @ingroup websocket
 * @param ws The WebSocket context with compression config.
 * @param input Compressed input data (RSV1 set in frame).
 * @param input_len Length of input.
 * @param[out] output Pointer to decompressed data (arena allocated).
 * @param[out] output_len Length of decompressed output.
 * @return 0 on success, -1 on zlib error or invalid compressed data.
 * @note Handles per-message decompression.
 * @note Flushes stream if needed for complete message.
 * @see ws_compress_message() for compression.
 * @see RFC 7692 Section 7 for decompression rules.
 */
int ws_decompress_message (SocketWS_T ws, const unsigned char *input,
                           size_t input_len, unsigned char **output,
                           size_t *output_len);
#endif

/* ============================================================================
 * Internal Helper Functions - Control Frames
 * ============================================================================
 */

/**
 * @brief Sends a WebSocket CLOSE control frame to initiate graceful shutdown.
 * @internal
 * @ingroup websocket
 * @param ws The WebSocket context.
 * @param code The close status code (valid per RFC or 0 for no code).
 * @param reason Optional UTF-8 reason string (truncated to max length).
 * @return 0 on success, -1 on error (sets last_error).
 * @note Validates code with ws_is_valid_close_code().
 * @note Sets close_sent flag; peer should respond with CLOSE.
 * @note After mutual CLOSE, connection enters CLOSING state.
 * @see SocketWS_close() public API wrapper.
 * @see RFC 6455 Section 7.1 for close handshake.
 */
int ws_send_close (SocketWS_T ws, SocketWS_CloseCode code, const char *reason);

/**
 * @brief Sends a WebSocket PING control frame for keepalive.
 * @internal
 * @ingroup websocket
 * @param ws The WebSocket context.
 * @param payload Optional application data in ping (NULL for empty).
 * @param len Length of payload (0 to 125 bytes).
 * @return 0 on success, -1 on error.
 * @note Peer must respond with PONG containing same payload.
 * @note Used for heartbeat; auto-triggered by timer if configured.
 * @see ws_send_pong() for response.
 * @see ws_auto_ping_start() for automatic pings.
 * @see RFC 6455 Section 5.5.2 for PING/PONG.
 */
int ws_send_ping (SocketWS_T ws, const unsigned char *payload, size_t len);

/**
 * @brief Sends a WebSocket PONG control frame in response to PING.
 * @internal
 * @ingroup websocket
 * @param ws The WebSocket context.
 * @param payload The payload to echo from received PING (or arbitrary).
 * @param len Length of payload (0-125).
 * @return 0 on success, -1 on error.
 * @note Typically called automatically on PING receipt.
 * @see ws_handle_control_frame() for automatic response.
 * @see ws_send_ping() for initiating ping.
 * @see RFC 6455 Section 5.5.3 for PONG semantics.
 */
int ws_send_pong (SocketWS_T ws, const unsigned char *payload, size_t len);

/**
 * @brief Handles a received WebSocket control frame (CLOSE, PING, PONG).
 * @internal
 * @ingroup websocket
 * @param ws The WebSocket context.
 * @param opcode The control opcode received.
 * @param payload The unmasked payload data.
 * @param len The payload length.
 * @return 0 on success, -1 on error (e.g., invalid close code).
 * @note For PING: sends PONG response, clears timeout.
 * @note For CLOSE: sets close_received, may initiate response.
 * @note For PONG: updates last_pong_received_time.
 * @see ws_send_pong() for PING response.
 * @see ws_send_close() for CLOSE response.
 * @see RFC 6455 Section 5.5 for control frame processing.
 */
int ws_handle_control_frame (SocketWS_T ws, SocketWS_Opcode opcode,
                             const unsigned char *payload, size_t len);

/* ============================================================================
 * Internal Helper Functions - Message Handling
 * ============================================================================
 */

/**
 * @brief Resets the message reassembly state for a new message.
 * @internal
 * @ingroup websocket
 * @param message The message assembly structure to reset.
 * @note Clears data buffer, length, fragments, UTF-8 state.
 * @note Called before first fragment of new message.
 * @see ws_message_append() to start assembly.
 * @see SocketWS_MessageAssembly for fields.
 */
void ws_message_reset (SocketWS_MessageAssembly *message);

/**
 * @brief Appends a data frame fragment to the current message assembly.
 * @internal
 * @ingroup websocket
 * @param ws The WebSocket context.
 * @param data The fragment payload (unmasked).
 * @param len Length of fragment.
 * @param is_text Non-zero if text message (enables UTF-8 validation).
 * @return 0 on success, -1 on error (exceeds max size/fragments, UTF-8
 * invalid).
 * @note Updates message.len and fragment_count; checks limits.
 * @note Decompresses if RSV1 set on first fragment.
 * @see ws_message_finalize() called on FIN=1.
 * @see SocketWS_MessageAssembly for state.
 * @see RFC 6455 Section 5.4 for message fragmentation.
 */
int ws_message_append (SocketWS_T ws, const unsigned char *data, size_t len,
                       int is_text);

/**
 * @brief Finalizes message assembly on last fragment and delivers to user.
 * @internal
 * @ingroup websocket
 * @param ws The WebSocket context.
 * @return 0 on success, -1 on error (UTF-8 invalid for text, or other).
 * @note Called when FIN=1 on data frame.
 * @note Performs final UTF-8 validation for text messages.
 * @note Invokes user callback with complete SocketWS_Message.
 * @note Resets assembly state for next message.
 * @see SocketWS_MessageCallback for delivery.
 * @see SocketUTF8_State for validation.
 */
int ws_message_finalize (SocketWS_T ws);

/* ============================================================================
 * Internal Helper Functions - Auto-Ping
 * ============================================================================
 */

/**
 * @brief Starts the automatic PING timer for keepalive.
 * @internal
 * @ingroup websocket
 * @param ws The WebSocket context with config.ping_interval_ms.
 * @param poll The SocketPoll instance for timer integration.
 * @return 0 on success, -1 on error (timer add fail).
 * @note Schedules first ping after interval_ms from now.
 * @note Uses SocketTimer_add_repeating for periodic pings.
 * @see ws_auto_ping_callback() timer handler.
 * @see SocketTimer_T for timer management.
 */
int ws_auto_ping_start (SocketWS_T ws, SocketPoll_T poll);

/**
 * @brief Stops the automatic PING timer.
 * @internal
 * @ingroup websocket
 * @param ws The WebSocket context.
 * @note Cancels the repeating timer using SocketTimer_cancel.
 * @note Called on close or disable.
 * @see ws_auto_ping_start() to start.
 * @see SocketTimer_cancel() underlying call.
 */
void ws_auto_ping_stop (SocketWS_T ws);

/**
 * @brief Timer callback invoked to send periodic PING.
 * @internal
 * @ingroup websocket
 * @param userdata The WebSocket context (cast from void*).
 * @note Sends PING with empty payload or config payload.
 * @note Sets awaiting_pong and timeout check.
 * @note Reschedules next timer.
 * @see SocketTimerCallback typedef.
 * @see ws_send_ping() for sending.
 */
void ws_auto_ping_callback (void *userdata);

/* ============================================================================
 * Internal Helper Functions - I/O
 * ============================================================================
 */

/**
 * @brief Flushes pending data from send buffer to underlying socket.
 * @internal
 * @ingroup websocket
 * @param ws The WebSocket context.
 * @return Number of bytes sent (>0), 0 if would block (EAGAIN), -1 on error.
 * @note Uses Socket_send() or TLS send if enabled.
 * @note Continues until buffer empty or block.
 * @see SocketBuf_T for buffer management.
 * @see Socket_send() low-level send.
 */
ssize_t ws_flush_send_buffer (SocketWS_T ws);

/**
 * @brief Fills the receive buffer from the underlying socket.
 * @internal
 * @ingroup websocket
 * @param ws The WebSocket context.
 * @return Bytes received (>0), 0 on EOF or would block, -1 on error.
 * @note Uses Socket_recv() or TLS recv.
 * @note Fills until buffer full or block/EOF.
 * @note Handles partial reads for non-blocking.
 * @see SocketBuf_T recv_buf.
 * @see Socket_recv() low-level recv.
 */
ssize_t ws_fill_recv_buffer (SocketWS_T ws);

/**
 * @brief Sets the last error code and formats error message.
 * @internal
 * @ingroup websocket
 * @param ws The WebSocket context.
 * @param error The SocketWS_Error code to set.
 * @param fmt printf-style format string for error_buf.
 * @param ... Arguments for format string.
 * @note Truncates message to SOCKETWS_ERROR_BUFSIZE.
 * @note Used internally for all error paths.
 * @see SocketWS_get_last_error() public accessor.
 */
void ws_set_error (SocketWS_T ws, SocketWS_Error error, const char *fmt, ...);

/* ============================================================================
 * Validation Helpers
 * ============================================================================
 */

/**
 * @brief Check if opcode represents a control frame.
 * @internal
 * @ingroup websocket
 *
 * Control frames: CLOSE (8), PING (9), PONG (A) - high bit set.
 * Data frames: CONT (0), TEXT (1), BINARY (2) - low bits.
 *
 * Used for special handling: immediate processing, no fragmentation.
 *
 * @param opcode Frame opcode.
 * @return 1 if control frame, 0 otherwise.
 * @see ws_is_data_opcode() for data frames.
 * @see RFC 6455 Section 5.2 for opcode ranges.
 */
static inline int
ws_is_control_opcode (SocketWS_Opcode opcode)
{
  return (opcode & 0x08) != 0;
}

/**
 * @brief Check if opcode represents a data frame.
 * @internal
 * @ingroup websocket
 *
 * Data frames: CONTINUATION (0), TEXT (1), BINARY (2).
 * Can be fragmented (multiple frames per message).
 *
 * @param opcode Frame opcode.
 * @return 1 if data frame (text/binary/cont), 0 otherwise.
 * @see ws_is_control_opcode() for control frames.
 * @see RFC 6455 Section 5.2 for data opcodes.
 */
static inline int
ws_is_data_opcode (SocketWS_Opcode opcode)
{
  return opcode == WS_OPCODE_TEXT || opcode == WS_OPCODE_BINARY;
}

/**
 * @brief Checks if a WebSocket opcode is valid per RFC 6455.
 * @internal
 * @ingroup websocket
 * @param opcode The opcode to validate.
 * @return 1 if valid (0-2 data, 8-A control), 0 otherwise.
 * @note Data: 0 CONT, 1 TEXT, 2 BINARY; Control: 8 CLOSE, 9 PING, A PONG.
 * @see ws_is_control_opcode(), ws_is_data_opcode().
 * @see RFC 6455 Section 5.2 Table 1 for opcodes.
 */
static inline int
ws_is_valid_opcode (SocketWS_Opcode opcode)
{
  return opcode <= WS_OPCODE_BINARY
         || (opcode >= WS_OPCODE_CLOSE && opcode <= WS_OPCODE_PONG);
}

/**
 * @brief Validate close status code per RFC 6455.
 * @internal
 * @ingroup websocket
 *
 * Valid codes: 1000-1014 (excluding 1004-1006 sometimes internal),
 * or 3000-4999 (library-specific).
 * Invalid: <1000, 1004-1006 (internal), 1015 (TLS, internal), others.
 *
 * Used in CLOSE frame processing/sending to ensure compliance.
 *
 * @param code Close code from frame.
 * @return 1 if valid for transmission, 0 otherwise.
 * @note Some codes (1001-1014) valid only on close, not status.
 * @see RFC 6455 Section 7.4.1 for defined codes and ranges.
 * @see SocketWS_CloseCode enum for common codes.
 */
static inline int
ws_is_valid_close_code (int code)
{
  /* RFC 6455 Section 7.4.1 */
  if (code < 1000)
    return 0;
  /* code >= 1000 is implied here since we didn't return above */
  if (code <= 1003)
    return 1;
  if (code >= 1007 && code <= 1014)
    return 1;
  if (code >= 3000 && code <= 4999)
    return 1;
  return 0;
}

#endif /* SOCKETWS_PRIVATE_INCLUDED */
