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

/** No port specified (for Host header logic) */
#define SOCKETWS_NO_PORT 0

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
 * Used in parsing (ws_frame_parse_header) and building (ws_frame_build_header).
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

/** Default deflate window bits */
#define SOCKETWS_DEFAULT_DEFLATE_WINDOW_BITS 15

/* SocketWS_Config is defined in public header (SocketWS.h) */

/* ============================================================================
 * Frame Parsing State
 * ============================================================================
 */

/**
 * @internal
 * @ingroup websocket
 * @brief States for the frame parsing state machine.
 * @internal
 * @ingroup websocket
 *
 * Tracks progress through frame header parsing, length extension, masking, and payload.
 * Used to handle incremental frame reception in non-blocking mode.
 *
 * @see ws_frame_parse_header() for state transitions.
 * @see SocketWS_FrameParse for full parse context.
 */
typedef enum
{
  WS_FRAME_STATE_HEADER,       /**< Reading frame header (opcode, fin, rsv, mask, len) */
  WS_FRAME_STATE_EXTENDED_LEN, /**< Reading extended payload length (16/64-bit) */
  WS_FRAME_STATE_MASK_KEY,     /**< Reading 4-byte mask key (client frames only) */
  WS_FRAME_STATE_PAYLOAD,      /**< Reading payload data */
  WS_FRAME_STATE_COMPLETE      /**< Frame fully parsed */
} SocketWS_FrameState;

/**
 * @internal
 * @ingroup websocket
 * @brief Context for parsing incoming WebSocket frames.
 * @internal
 * @ingroup websocket
 *
 * Manages incremental parsing of frame headers and payloads.
 * Supports partial reads for non-blocking sockets.
 * Handles variable-length fields: opcode/fin/rsv, mask bit, 7/16/64-bit length, optional mask key.
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
  int fin;                   /**< FIN bit: final fragment of message */
  int rsv1;                  /**< RSV1: compression flag (permessage-deflate) */
  int rsv2;                  /**< RSV2: reserved, must be 0 */
  int rsv3;                  /**< RSV3: reserved, must be 0 */
  SocketWS_Opcode opcode;    /**< Frame opcode (data/control) */
  int masked;                /**< MASK bit: payload masked (client->server) */
  unsigned char mask_key[4]; /**< 4-byte mask key if masked */

  /* Payload tracking */
  uint64_t payload_len;      /**< Total payload length */
  uint64_t payload_received; /**< Bytes of payload received so far */

  /* Header buffer for partial reads */
  unsigned char header_buf[SOCKETWS_MAX_HEADER_SIZE]; /**< Temp buffer for header bytes */
  size_t header_len;     /**< Bytes accumulated in header_buf */
  size_t header_needed;  /**< Remaining bytes needed for current field */

} SocketWS_FrameParse;

/* ============================================================================
 * Message Reassembly State
 * ============================================================================
 */

/**
 * @internal
 * @ingroup websocket
 * @brief State for reassembling fragmented WebSocket messages.
 * @internal
 * @ingroup websocket
 *
 * Accumulates data from multiple CONTINUATION frames into a single message buffer.
 * Supports UTF-8 validation for text messages across fragments.
 * Handles compression flag from first frame (RSV1).
 *
 * Limits enforced via config: max_message_size, max_fragments.
 *
 * Usage:
 * - Reset: ws_message_reset() before first fragment
 * - Append: ws_message_append() for each data frame fragment
 * - Finalize: ws_message_finalize() on last fragment (FIN=1), validates and delivers
 *
 * @see ws_message_append() for adding fragments.
 * @see ws_message_finalize() for completion and validation.
 * @see SocketWS_Message for public message interface.
 * @see RFC 6455 Section 5.4 for fragmentation rules.
 */
typedef struct
{
  SocketWS_Opcode type;         /**< Message type: TEXT or BINARY (from first frame opcode) */
  unsigned char *data;          /**< Reassembled message buffer (Arena-allocated) */
  size_t len;                   /**< Current assembled length */
  size_t capacity;              /**< Allocated buffer capacity */
  size_t fragment_count;        /**< Number of fragments received so far */
  int compressed;               /**< RSV1 set on first fragment (compression used) */

  /* UTF-8 validation state (for TEXT messages) */
  SocketUTF8_State utf8_state;  /**< Incremental UTF-8 decoder state */
  int utf8_initialized;         /**< Whether UTF-8 validation started */

} SocketWS_MessageAssembly;

/* ============================================================================
 * Handshake State
 * ============================================================================
 */

/**
 * @internal
 * @ingroup websocket
 * @brief States for WebSocket HTTP upgrade handshake.
 * @internal
 * @ingroup websocket
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
  WS_HANDSHAKE_INIT,            /**< Initial state, prepare handshake data */
  WS_HANDSHAKE_SENDING_REQUEST, /**< Client: Sending HTTP GET upgrade request */
  WS_HANDSHAKE_READING_RESPONSE,/**< Client: Reading HTTP 101 response; Server: reading client request if needed */
  WS_HANDSHAKE_COMPLETE,        /**< Handshake successful, transition to frame mode */
  WS_HANDSHAKE_FAILED           /**< Handshake failed, error set */
} SocketWS_HandshakeState;

/**
 * @internal
 * @ingroup websocket
 * @brief Context for WebSocket HTTP upgrade handshake.
 * @internal
 * @ingroup websocket
 *
 * Manages client or server handshake state, key generation/validation,
 * header negotiation (subprotocols, compression), and HTTP parsing/serialization.
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
 * @see ws_handshake_client_process() / ws_handshake_server_process() for I/O loop.
 * @see SocketCrypto_websocket_accept_compute() for key validation.
 * @see RFC 6455 Section 4.2 for client handshake, Section 4.1 for server.
 */
typedef struct
{
  SocketWS_HandshakeState state; /**< Current handshake state */

  /* Client key (generated, used to validate accept) */
  char client_key[SOCKET_CRYPTO_WEBSOCKET_KEY_SIZE]; /**< Base64 Sec-WebSocket-Key (24 chars) */

  /* Expected accept value */
  char expected_accept[SOCKET_CRYPTO_WEBSOCKET_ACCEPT_SIZE]; /**< SHA1(key + magic) base64 */

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
  char *request_buf; /**< Buffer for HTTP request/response */
  size_t request_len;/**< Total length of HTTP message */
  size_t request_sent;/**< Bytes already sent */

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
 * @internal
 * @ingroup websocket
 *
 * Manages zlib streams for per-message compression/decompression.
 * Supports context takeover negotiation (no-takeover flags).
 * Window bits configurable per client/server.
 *
 * Initialization: ws_compression_init() after handshake negotiation.
 * Per-message: Compress before framing (RSV1=1), decompress after unmasking.
 * Cleanup: ws_compression_free() on close.
 *
 * Buffers: deflate_buf/inflate_buf for zlib operations (zlib-managed? No, manual).
 *
 * @note Requires zlib library (SOCKETWS_HAS_DEFLATE).
 * @note Separate streams for send (deflate) and recv (inflate).
 * @see ws_compress_message() / ws_decompress_message() for usage.
 * @see RFC 7692 for extension details, context takeover semantics.
 */
typedef struct
{
  z_stream deflate_stream;  /**< zlib deflate stream for outgoing messages */
  z_stream inflate_stream;  /**< zlib inflate stream for incoming messages */
  int deflate_initialized;  /**< deflate stream initialized? */
  int inflate_initialized;  /**< inflate stream initialized? */

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
 * @brief Main WebSocket connection context (opaque in public header).
 * @internal
 * @ingroup websocket
 *
 * Central structure holding all state for a WebSocket connection.
 * Opaque to public users; access via public API functions only.
 *
 * Lifecycle:
 * - Create: SocketWS_client_new() or SocketWS_server_accept() (allocates, initializes)
 * - Handshake: SocketWS_handshake() drives to OPEN or CLOSED
 * - I/O: SocketWS_process() on poll events, send/recv via public funcs
 * - Close: SocketWS_close() initiates graceful close
 * - Free: SocketWS_free() cleans up resources
 *
 * Resources:
 * - arena: All dynamic allocations (buffers, strings, etc.)
 * - socket: Underlying TCP/TLS socket (not owned after transfer)
 * - recv_buf/send_buf: Circular buffers for I/O buffering
 *
 * State Management:
 * - state: High-level connection state (publicly queryable)
 * - handshake: HTTP upgrade details
 * - frame: Current incoming frame parse state
 * - message: Fragment reassembly for multi-frame messages
 * - compression: Deflate context (if enabled)
 * - close_*: Close handshake tracking
 * - ping/pong: Keepalive timing and pending pings
 *
 * Error: last_error and error_buf for detailed diagnostics.
 *
 * Thread Safety: Not thread-safe; single-threaded use only.
 * Non-blocking: Designed for event loops with SocketPoll.
 *
 * @note All pointers (except fixed arrays) Arena-allocated.
 * @see SocketWS_T public opaque type.
 * @see SocketWS_new (internal, called by public constructors).
 */
struct SocketWS
{
  /* Underlying resources */
  Socket_T socket;      /**< TCP/TLS socket (may be NULL if ownership transferred) */
  Arena_T arena;        /**< Memory arena for all dynamic allocations */
  SocketBuf_T recv_buf; /**< Receive circular buffer for incoming data */
  SocketBuf_T send_buf; /**< Send circular buffer for outgoing data */

  /* Configuration (copied at creation) */
  SocketWS_Config config; /**< User-provided configuration */

  /* State machine */
  SocketWS_State state; /**< High-level connection state (CONNECTING/OPEN/CLOSING/CLOSED) */
  SocketWS_Role role;   /**< Client or server role (affects masking) */

  /* Handshake state */
  SocketWS_Handshake handshake; /**< HTTP upgrade handshake context */

  /* Frame parsing state */
  SocketWS_FrameParse frame; /**< Incoming frame parser */

  /* Message reassembly state */
  SocketWS_MessageAssembly message; /**< Fragmented message assembler */

  /* Compression state (conditional) */
#ifdef SOCKETWS_HAS_DEFLATE
  int compression_enabled;  /**< Compression negotiated and active? */
  SocketWS_Compression compression; /**< Deflate/inflate streams and settings */
#endif

  /* Close state */
  int close_sent;           /**< Flag: sent CLOSE frame? */
  int close_received;       /**< Flag: received CLOSE frame? */
  SocketWS_CloseCode close_code; /**< Received/sent close code */
  char close_reason[SOCKETWS_MAX_CLOSE_REASON + 1]; /**< Close reason string */

  /* Ping/pong tracking (monotonic time) */
  int64_t last_ping_sent_time;    /**< Time last PING sent */
  int64_t last_pong_received_time;/**< Time last PONG received */
  int64_t last_pong_sent_time;    /**< Time last PONG sent (response) */
  unsigned char pending_ping_payload[SOCKETWS_MAX_CONTROL_PAYLOAD]; /**< Pending PING payload */
  size_t pending_ping_len;        /**< Length of pending PING payload */
  int awaiting_pong;              /**< Expecting PONG response? */

  /* Auto-ping timer integration */
  SocketTimer_T ping_timer; /**< Internal timer for auto-pings */
  SocketPoll_T poll;        /**< Associated poll instance (for timers) */

  /* Error tracking */
  SocketWS_Error last_error; /**< Last error code */
  char error_buf[SOCKETWS_ERROR_BUFSIZE]; /**< Human-readable error message */

  /* URL components (client connect info) */
  char *host; /**< Target host (for client handshake) */
  char *path; /**< Request path (for client handshake) */
  int port;   /**< Target port */
  int use_tls;/**< Using TLS? (wss://) */

};

/**
 * @internal
 * @ingroup websocket
 * @brief Opaque type for WebSocket connection (public interface).
 * @internal
 * @ingroup websocket
 *
 * In public header (SocketWS.h), defined as #define T SocketWS_T \n typedef struct SocketWS *T;
 * Here, reveals the pointer to private struct SocketWS.
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
 * @internal
 * @ingroup websocket
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

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketWS);

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
 * ws_copy_string - Copy string to arena
 * @arena: Memory arena
 * @str: String to copy (may be NULL)
 *
 * Returns: Copied string or NULL
 */
char *ws_copy_string (Arena_T arena, const char *str);

/* ============================================================================
 * Internal Helper Functions - Frame Sending
 * ============================================================================
 */

/**
 * ws_send_control_frame - Send a control frame (PING/PONG/CLOSE)
 * @ws: WebSocket context
 * @opcode: Control frame opcode
 * @payload: Payload data (may be NULL)
 * @len: Payload length (max 125)
 *
 * Returns: 0 on success, -1 on error
 */
int ws_send_control_frame (SocketWS_T ws, SocketWS_Opcode opcode,
                           const unsigned char *payload, size_t len);

/**
 * ws_send_data_frame - Send a data frame (TEXT/BINARY)
 * @ws: WebSocket context
 * @opcode: Data frame opcode
 * @data: Payload data
 * @len: Payload length
 * @fin: Final fragment flag
 *
 * Returns: 0 on success, -1 on error
 */
int ws_send_data_frame (SocketWS_T ws, SocketWS_Opcode opcode,
                        const unsigned char *data, size_t len, int fin);

/* ============================================================================
 * Internal Helper Functions - Frame Processing
 * ============================================================================
 */

/**
 * ws_frame_reset - Reset frame parsing state for next frame
 * @frame: Frame parsing state
 */
void ws_frame_reset (SocketWS_FrameParse *frame);

/**
 * ws_frame_parse_header - Parse frame header bytes
 * @frame: Frame parsing state
 * @data: Input data
 * @len: Input length
 * @consumed: Output - bytes consumed
 *
 * Returns: WS_OK if header complete, WS_ERROR_WOULD_BLOCK if need more,
 *          or error code
 */
SocketWS_Error ws_frame_parse_header (SocketWS_FrameParse *frame,
                                      const unsigned char *data, size_t len,
                                      size_t *consumed);

/**
 * ws_frame_build_header - Build frame header
 * @header: Output buffer (at least SOCKETWS_MAX_HEADER_SIZE)
 * @fin: Final fragment flag
 * @opcode: Frame opcode
 * @masked: Whether to mask (client = yes, server = no)
 * @mask_key: 4-byte mask key (only if masked)
 * @payload_len: Payload length
 *
 * Returns: Header length written
 */
size_t ws_frame_build_header (unsigned char *header, int fin,
                              SocketWS_Opcode opcode, int masked,
                              const unsigned char *mask_key,
                              uint64_t payload_len);

/**
 * ws_mask_payload - Apply XOR mask to payload (optimized)
 * @data: Data buffer (modified in place)
 * @len: Data length
 * @mask: 4-byte mask key
 *
 * Uses 8-byte aligned XOR for performance.
 */
void ws_mask_payload (unsigned char *data, size_t len,
                      const unsigned char mask[4]);

/**
 * ws_mask_payload_offset - Apply XOR mask with offset
 * @data: Data buffer
 * @len: Data length
 * @mask: 4-byte mask key
 * @offset: Starting offset into mask (for continuation)
 *
 * Returns: New offset (for next call)
 */
size_t ws_mask_payload_offset (unsigned char *data, size_t len,
                               const unsigned char mask[4], size_t offset);

/* ============================================================================
 * Internal Helper Functions - Handshake
 * ============================================================================
 */

/**
 * ws_handshake_client_init - Initialize client handshake
 * @ws: WebSocket context
 *
 * Generates Sec-WebSocket-Key and builds HTTP upgrade request.
 * Returns: 0 on success, -1 on error
 */
int ws_handshake_client_init (SocketWS_T ws);

/**
 * ws_handshake_client_process - Process client handshake I/O
 * @ws: WebSocket context
 *
 * Returns: 0 if complete, 1 if in progress, -1 on error
 */
int ws_handshake_client_process (SocketWS_T ws);

/**
 * ws_handshake_server_init - Initialize server handshake
 * @ws: WebSocket context
 * @request: Parsed HTTP upgrade request
 *
 * Returns: 0 on success, -1 on error
 */
int ws_handshake_server_init (SocketWS_T ws,
                              const SocketHTTP_Request *request);

/**
 * ws_handshake_server_process - Process server handshake I/O
 * @ws: WebSocket context
 *
 * Returns: 0 if complete, 1 if in progress, -1 on error
 */
int ws_handshake_server_process (SocketWS_T ws);

/**
 * ws_handshake_validate_accept - Validate Sec-WebSocket-Accept
 * @ws: WebSocket context
 * @accept: Received accept value
 *
 * Returns: 0 if valid, -1 if invalid
 */
int ws_handshake_validate_accept (SocketWS_T ws, const char *accept);

/* ============================================================================
 * Internal Helper Functions - Compression
 * ============================================================================
 */

#ifdef SOCKETWS_HAS_DEFLATE
/**
 * ws_compression_init - Initialize compression context
 * @ws: WebSocket context
 *
 * Returns: 0 on success, -1 on error
 */
int ws_compression_init (SocketWS_T ws);

/**
 * ws_compression_free - Free compression context
 * @ws: WebSocket context
 */
void ws_compression_free (SocketWS_T ws);

/**
 * ws_compress_message - Compress message data
 * @ws: WebSocket context
 * @input: Input data
 * @input_len: Input length
 * @output: Output buffer (arena allocated)
 * @output_len: Output length
 *
 * Returns: 0 on success, -1 on error
 */
int ws_compress_message (SocketWS_T ws, const unsigned char *input,
                         size_t input_len, unsigned char **output,
                         size_t *output_len);

/**
 * ws_decompress_message - Decompress message data
 * @ws: WebSocket context
 * @input: Compressed input
 * @input_len: Input length
 * @output: Output buffer (arena allocated)
 * @output_len: Output length
 *
 * Returns: 0 on success, -1 on error
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
 * ws_send_close - Send CLOSE frame
 * @ws: WebSocket context
 * @code: Close code
 * @reason: Optional reason string (may be NULL)
 *
 * Returns: 0 on success, -1 on error
 */
int ws_send_close (SocketWS_T ws, SocketWS_CloseCode code, const char *reason);

/**
 * ws_send_ping - Send PING frame
 * @ws: WebSocket context
 * @payload: Optional payload (may be NULL)
 * @len: Payload length (max 125)
 *
 * Returns: 0 on success, -1 on error
 */
int ws_send_ping (SocketWS_T ws, const unsigned char *payload, size_t len);

/**
 * ws_send_pong - Send PONG frame
 * @ws: WebSocket context
 * @payload: Payload from PING (may be NULL)
 * @len: Payload length
 *
 * Returns: 0 on success, -1 on error
 */
int ws_send_pong (SocketWS_T ws, const unsigned char *payload, size_t len);

/**
 * ws_handle_control_frame - Process received control frame
 * @ws: WebSocket context
 * @opcode: Frame opcode
 * @payload: Frame payload
 * @len: Payload length
 *
 * Returns: 0 on success, -1 on error
 */
int ws_handle_control_frame (SocketWS_T ws, SocketWS_Opcode opcode,
                             const unsigned char *payload, size_t len);

/* ============================================================================
 * Internal Helper Functions - Message Handling
 * ============================================================================
 */

/**
 * ws_message_reset - Reset message assembly state
 * @message: Message assembly state
 */
void ws_message_reset (SocketWS_MessageAssembly *message);

/**
 * ws_message_append - Append fragment to message
 * @ws: WebSocket context
 * @data: Fragment data
 * @len: Fragment length
 * @is_text: Whether this is text data
 *
 * Returns: 0 on success, -1 on error
 */
int ws_message_append (SocketWS_T ws, const unsigned char *data, size_t len,
                       int is_text);

/**
 * ws_message_finalize - Finalize assembled message
 * @ws: WebSocket context
 *
 * Validates UTF-8 for text messages.
 * Returns: 0 on success, -1 on error
 */
int ws_message_finalize (SocketWS_T ws);

/* ============================================================================
 * Internal Helper Functions - Auto-Ping
 * ============================================================================
 */

/**
 * ws_auto_ping_start - Start auto-ping timer
 * @ws: WebSocket context
 * @poll: Poll instance for timer
 *
 * Returns: 0 on success, -1 on error
 */
int ws_auto_ping_start (SocketWS_T ws, SocketPoll_T poll);

/**
 * ws_auto_ping_stop - Stop auto-ping timer
 * @ws: WebSocket context
 */
void ws_auto_ping_stop (SocketWS_T ws);

/**
 * ws_auto_ping_callback - Timer callback for auto-ping
 * @userdata: WebSocket context
 */
void ws_auto_ping_callback (void *userdata);

/* ============================================================================
 * Internal Helper Functions - I/O
 * ============================================================================
 */

/**
 * ws_flush_send_buffer - Flush send buffer to socket
 * @ws: WebSocket context
 *
 * Returns: Bytes sent, 0 if would block, -1 on error
 */
ssize_t ws_flush_send_buffer (SocketWS_T ws);

/**
 * ws_fill_recv_buffer - Fill receive buffer from socket
 * @ws: WebSocket context
 *
 * Returns: Bytes received, 0 on EOF, -1 on error (EAGAIN = 0)
 */
ssize_t ws_fill_recv_buffer (SocketWS_T ws);

/**
 * ws_set_error - Set error state with message
 * @ws: WebSocket context
 * @error: Error code
 * @fmt: Format string
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
static inline int
ws_is_data_opcode (SocketWS_Opcode opcode)
{
  return opcode == WS_OPCODE_TEXT || opcode == WS_OPCODE_BINARY;
}

/**
 * ws_is_valid_opcode - Check if opcode is valid
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
