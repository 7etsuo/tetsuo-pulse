/**
 * SocketWS-private.h - Internal structures for WebSocket Support
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * This header contains internal implementation details for the SocketWS
 * module. Not for public use - structures may change without notice.
 *
 * RFC 6455: The WebSocket Protocol
 * RFC 7692: Compression Extensions for WebSocket (permessage-deflate)
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

/* ============================================================================
 * Configuration Constants
 * ============================================================================ */

/** Maximum WebSocket frame size (default 16MB) */
#ifndef SOCKETWS_MAX_FRAME_SIZE
#define SOCKETWS_MAX_FRAME_SIZE (16 * 1024 * 1024)
#endif

/* ============================================================================
 * Handshake Constants (RFC 6455 Section 4)
 * ============================================================================ */

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

/* ============================================================================
 * XOR Masking Constants (RFC 6455 Section 5.3)
 * ============================================================================ */

/** Alignment size for optimized 64-bit XOR masking */
#define SOCKETWS_XOR_ALIGN_SIZE 8

/** Mask for 8-byte alignment check: (ptr & MASK) gives misalignment */
#define SOCKETWS_XOR_ALIGN_MASK 7

/** RFC 6455: Mask key is always 4 bytes */
#define SOCKETWS_MASK_KEY_SIZE 4

/** Wrap mask for mask key indexing: (offset & MASK) cycles 0-3 */
#define SOCKETWS_MASK_KEY_INDEX_MASK 3

/* ============================================================================
 * Frame Header Constants (RFC 6455 Section 5.2)
 * ============================================================================ */

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

/* ============================================================================
 * Frame Header Bit Masks (RFC 6455 Section 5.2)
 * ============================================================================ */

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

/* ============================================================================
 * Send Buffer Configuration
 * ============================================================================ */

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
 * ============================================================================ */

typedef enum
{
  WS_FRAME_STATE_HEADER,        /* Reading frame header */
  WS_FRAME_STATE_EXTENDED_LEN,  /* Reading extended length */
  WS_FRAME_STATE_MASK_KEY,      /* Reading mask key */
  WS_FRAME_STATE_PAYLOAD,       /* Reading payload */
  WS_FRAME_STATE_COMPLETE       /* Frame complete */
} SocketWS_FrameState;

typedef struct
{
  SocketWS_FrameState state;

  /* Parsed header fields */
  int fin;
  int rsv1;                     /* RSV1 = compression flag */
  int rsv2;
  int rsv3;
  SocketWS_Opcode opcode;
  int masked;
  unsigned char mask_key[4];

  /* Payload tracking */
  uint64_t payload_len;
  uint64_t payload_received;

  /* Header buffer for partial reads */
  unsigned char header_buf[SOCKETWS_MAX_HEADER_SIZE];
  size_t header_len;
  size_t header_needed;

} SocketWS_FrameParse;

/* ============================================================================
 * Message Reassembly State
 * ============================================================================ */

typedef struct
{
  SocketWS_Opcode type;         /* TEXT or BINARY (from first frame) */
  unsigned char *data;          /* Reassembly buffer */
  size_t len;                   /* Current message length */
  size_t capacity;              /* Buffer capacity */
  size_t fragment_count;        /* Number of fragments received */
  int compressed;               /* RSV1 set on first fragment */

  /* UTF-8 validation state (for TEXT messages) */
  SocketUTF8_State utf8_state;
  int utf8_initialized;

} SocketWS_MessageAssembly;

/* ============================================================================
 * Handshake State
 * ============================================================================ */

typedef enum
{
  WS_HANDSHAKE_INIT,
  WS_HANDSHAKE_SENDING_REQUEST,
  WS_HANDSHAKE_READING_RESPONSE,
  WS_HANDSHAKE_COMPLETE,
  WS_HANDSHAKE_FAILED
} SocketWS_HandshakeState;

typedef struct
{
  SocketWS_HandshakeState state;

  /* Client key (generated, used to validate accept) */
  char client_key[SOCKET_CRYPTO_WEBSOCKET_KEY_SIZE];

  /* Expected accept value */
  char expected_accept[SOCKET_CRYPTO_WEBSOCKET_ACCEPT_SIZE];

  /* HTTP parser for response */
  SocketHTTP1_Parser_T http_parser;

  /* Negotiated values */
  char *selected_subprotocol;
  int compression_negotiated;
  int server_no_context_takeover;
  int client_no_context_takeover;
  int server_max_window_bits;
  int client_max_window_bits;

  /* Request buffer */
  char *request_buf;
  size_t request_len;
  size_t request_sent;

} SocketWS_Handshake;

/* ============================================================================
 * Compression State (RFC 7692)
 * ============================================================================ */

#ifdef SOCKETWS_HAS_DEFLATE
typedef struct
{
  z_stream deflate_stream;      /* For compression */
  z_stream inflate_stream;      /* For decompression */
  int deflate_initialized;
  int inflate_initialized;

  /* Context takeover settings */
  int server_no_context_takeover;
  int client_no_context_takeover;
  int server_max_window_bits;
  int client_max_window_bits;

  /* Temporary buffers */
  unsigned char *deflate_buf;
  size_t deflate_buf_size;
  unsigned char *inflate_buf;
  size_t inflate_buf_size;

} SocketWS_Compression;
#endif

/* ============================================================================
 * Main WebSocket Context Structure
 * ============================================================================ */

struct SocketWS
{
  /* Underlying resources */
  Socket_T socket;              /* TCP/TLS socket (may be NULL if transferred) */
  Arena_T arena;                /* Memory arena for all allocations */
  SocketBuf_T recv_buf;         /* Receive circular buffer */
  SocketBuf_T send_buf;         /* Send circular buffer */

  /* Configuration (copied on create) */
  SocketWS_Config config;

  /* State machine */
  SocketWS_State state;
  SocketWS_Role role;

  /* Handshake state */
  SocketWS_Handshake handshake;

  /* Frame parsing state */
  SocketWS_FrameParse frame;

  /* Message reassembly state */
  SocketWS_MessageAssembly message;

  /* Compression state */
#ifdef SOCKETWS_HAS_DEFLATE
  int compression_enabled;
  SocketWS_Compression compression;
#endif

  /* Close state */
  int close_sent;               /* We sent CLOSE frame */
  int close_received;           /* We received CLOSE frame */
  SocketWS_CloseCode close_code;
  char close_reason[SOCKETWS_MAX_CLOSE_REASON + 1];

  /* Ping/pong tracking (using Socket_get_monotonic_ms) */
  int64_t last_ping_sent_time;
  int64_t last_pong_received_time;
  int64_t last_pong_sent_time;
  unsigned char pending_ping_payload[SOCKETWS_MAX_CONTROL_PAYLOAD];
  size_t pending_ping_len;
  int awaiting_pong;

  /* Auto-ping timer (using SocketTimer) */
  SocketTimer_T ping_timer;
  SocketPoll_T poll;            /* For timer integration */

  /* Error tracking */
  SocketWS_Error last_error;
  char error_buf[SOCKETWS_ERROR_BUFSIZE];

  /* URL components (for connect) */
  char *host;
  char *path;
  int port;
  int use_tls;
};

/* Opaque type definition */
typedef struct SocketWS *SocketWS_T;

/* ============================================================================
 * Thread-Local Exception Support
 * ============================================================================ */

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketWS);

/* Macro to raise exception with detailed error message */
#define RAISE_WS_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketWS, e)

/* ============================================================================
 * Internal Helper Functions - Memory
 * ============================================================================ */

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
 * ============================================================================ */

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
 * ============================================================================ */

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
 * ============================================================================ */

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
 * ============================================================================ */

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
 * ============================================================================ */

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
 * ============================================================================ */

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
 * ============================================================================ */

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
 * ============================================================================ */

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
 * ============================================================================ */

/**
 * ws_is_control_opcode - Check if opcode is control frame
 */
static inline int
ws_is_control_opcode (SocketWS_Opcode opcode)
{
  return (opcode & 0x08) != 0;
}

/**
 * ws_is_data_opcode - Check if opcode is data frame
 */
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
 * ws_is_valid_close_code - Check if close code is valid
 */
static inline int
ws_is_valid_close_code (int code)
{
  /* RFC 6455 Section 7.4.1 */
  if (code < 1000)
    return 0;
  if (code >= 1000 && code <= 1003)
    return 1;
  if (code >= 1007 && code <= 1014)
    return 1;
  if (code >= 3000 && code <= 4999)
    return 1;
  return 0;
}

#endif /* SOCKETWS_PRIVATE_INCLUDED */

