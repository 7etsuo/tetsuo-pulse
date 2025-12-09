/**
 * @file SocketHTTP1.h
 * @ingroup http
 * @brief HTTP/1.1 message syntax parsing and serialization (RFC 9112).
 *
 * Provides HTTP/1.1 message parsing, serialization, and chunked encoding.
 * Builds on SocketHTTP.h for core types (methods, status codes, headers, URI).
 *
 * Features:
 * - DFA-based incremental parser (O(n) complexity)
 * - Request and response parsing
 * - All request-target forms (origin, absolute, authority, asterisk)
 * - Chunked transfer encoding with trailer support
 * - Request smuggling prevention (strict RFC 9112 Section 6.3)
 * - Optional content encoding (gzip/deflate/brotli)
 * - Configurable limits for security
 *
 * Thread safety: Parser instances are NOT thread-safe.
 * Use one parser per thread or external synchronization.
 *
 * Security notes:
 * - Rejects requests with both Content-Length and Transfer-Encoding
 * - Rejects multiple differing Content-Length values
 * - Validates all header names/values for injection attacks
 * - Enforces configurable size limits
 *
 * @see SocketHTTP1_Parser_new() for creating parsers.
 * @see SocketHTTP1_Parser_execute() for incremental parsing.
 * @see SocketHTTP1_serialize_request() for message serialization.
 */

#ifndef SOCKETHTTP1_INCLUDED
#define SOCKETHTTP1_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHTTP.h"

/* ============================================================================
 * Configuration Limits
 * ============================================================================
 *
 * CONFIGURABLE LIMITS SUMMARY
 *
 * All limits can be overridden at compile time with -D flags or at runtime
 * via SocketHTTP1_Config.
 *
 * MESSAGE STRUCTURE LIMITS:
 *   SOCKETHTTP1_MAX_REQUEST_LINE - 8KB - Max request/status line
 *   SOCKETHTTP1_MAX_URI_LEN - 8KB - Max URI length
 *   SOCKETHTTP1_MAX_HEADER_NAME - 256B - Max header name length
 *   SOCKETHTTP1_MAX_HEADER_VALUE - 8KB - Max header value length
 *   SOCKETHTTP1_MAX_HEADERS - 100 - Max number of headers
 *   SOCKETHTTP1_MAX_HEADER_SIZE - 64KB - Max total header size
 *
 * CHUNKED ENCODING LIMITS:
 *   SOCKETHTTP1_MAX_CHUNK_SIZE - 16MB - Max single chunk size
 *   SOCKETHTTP1_MAX_CHUNK_EXT - 1KB - Max chunk extension length
 *   SOCKETHTTP1_MAX_TRAILER_SIZE - 4KB - Max trailer headers size
 *
 * ENFORCEMENT:
 *   - All limits enforced during parsing
 *   - Returns HTTP1_ERROR_LINE_TOO_LONG, HTTP1_ERROR_HEADER_TOO_LARGE, etc.
 *   - Request smuggling prevention per RFC 9112 Section 6.3
 *
 * SECURITY:
 *   - Rejects both Content-Length AND Transfer-Encoding (smuggling prevention)
 *   - Rejects multiple differing Content-Length values
 *   - Validates all header names/values for injection attacks
 */

/** Maximum request/status line length */
#ifndef SOCKETHTTP1_MAX_REQUEST_LINE
#define SOCKETHTTP1_MAX_REQUEST_LINE (8 * 1024)
#endif

/** Maximum HTTP method length (longest standard: OPTIONS = 7) */
#ifndef SOCKETHTTP1_MAX_METHOD_LEN
#define SOCKETHTTP1_MAX_METHOD_LEN 16
#endif

/** Maximum URI length in request line */
#ifndef SOCKETHTTP1_MAX_URI_LEN
#define SOCKETHTTP1_MAX_URI_LEN (8 * 1024)
#endif

/** Maximum header name length */
#ifndef SOCKETHTTP1_MAX_HEADER_NAME
#define SOCKETHTTP1_MAX_HEADER_NAME 256
#endif

/** Maximum header value length */
#ifndef SOCKETHTTP1_MAX_HEADER_VALUE
#define SOCKETHTTP1_MAX_HEADER_VALUE (8 * 1024)
#endif

/** Maximum number of headers */
#ifndef SOCKETHTTP1_MAX_HEADERS
#define SOCKETHTTP1_MAX_HEADERS 100
#endif

/** Maximum total header size */
#ifndef SOCKETHTTP1_MAX_HEADER_SIZE
#define SOCKETHTTP1_MAX_HEADER_SIZE (64 * 1024)
#endif

/** Maximum chunk size */
#ifndef SOCKETHTTP1_MAX_CHUNK_SIZE
#define SOCKETHTTP1_MAX_CHUNK_SIZE (16 * 1024 * 1024)
#endif

/** Maximum chunk extension length */
#ifndef SOCKETHTTP1_MAX_CHUNK_EXT
#define SOCKETHTTP1_MAX_CHUNK_EXT 1024
#endif

/** Maximum trailer headers size */
#ifndef SOCKETHTTP1_MAX_TRAILER_SIZE
#define SOCKETHTTP1_MAX_TRAILER_SIZE (4 * 1024)
#endif

/** Maximum individual header line length (name + : + value + OWS + \r\n) */
#ifndef SOCKETHTTP1_MAX_HEADER_LINE
#define SOCKETHTTP1_MAX_HEADER_LINE (16 * 1024)
#endif

/* ============================================================================
 * Serialization Buffer Sizes
 * ============================================================================
 */

/** Buffer size for integer-to-string conversion (covers int64_t) */
#ifndef SOCKETHTTP1_INT_STRING_BUFSIZE
#define SOCKETHTTP1_INT_STRING_BUFSIZE 24
#endif

/** Buffer size for Content-Length header line ("Content-Length: " + value) */
#ifndef SOCKETHTTP1_CONTENT_LENGTH_BUFSIZE
#define SOCKETHTTP1_CONTENT_LENGTH_BUFSIZE 48
#endif

/* ============================================================================
 * Exception Types
 * ============================================================================
 */

/**
 * SocketHTTP1_ParseError - HTTP/1.1 message parse failure
 *
 * Raised when:
 * - Invalid request/status line syntax
 * - Invalid header syntax
 * - Request smuggling attempt detected
 * - Size limits exceeded
 */
extern const Except_T SocketHTTP1_ParseError;

/**
 * SocketHTTP1_SerializeError - HTTP/1.1 message serialization failure
 *
 * Raised when:
 * - Invalid input data (unknown method, invalid version, etc.)
 * - Required fields missing or malformed
 */
extern const Except_T SocketHTTP1_SerializeError;

/* ============================================================================
 * Parser Types
 * ============================================================================
 */

/**
 * Parser mode
 */
typedef enum
{
  HTTP1_PARSE_REQUEST, /**< Parse HTTP requests */
  HTTP1_PARSE_RESPONSE /**< Parse HTTP responses */
} SocketHTTP1_ParseMode;

/**
 * Parser state (high-level)
 */
typedef enum
{
  HTTP1_STATE_START,      /**< Waiting for first line */
  HTTP1_STATE_HEADERS,    /**< Parsing headers */
  HTTP1_STATE_BODY,       /**< Reading body */
  HTTP1_STATE_CHUNK_SIZE, /**< Reading chunk size line */
  HTTP1_STATE_CHUNK_DATA, /**< Reading chunk data */
  HTTP1_STATE_CHUNK_END,  /**< Reading chunk CRLF */
  HTTP1_STATE_TRAILERS,   /**< Reading trailers */
  HTTP1_STATE_COMPLETE,   /**< Message complete */
  HTTP1_STATE_ERROR       /**< Parse error */
} SocketHTTP1_State;

/**
 * Parse result codes
 */
typedef enum
{
  HTTP1_OK = 0,     /**< Complete message or chunk parsed */
  HTTP1_INCOMPLETE, /**< Need more data */
  HTTP1_ERROR,      /**< Generic error */

  /* Specific errors for diagnostics */
  HTTP1_ERROR_LINE_TOO_LONG,
  HTTP1_ERROR_INVALID_METHOD,
  HTTP1_ERROR_INVALID_URI,
  HTTP1_ERROR_INVALID_VERSION,
  HTTP1_ERROR_INVALID_STATUS,
  HTTP1_ERROR_INVALID_HEADER_NAME,
  HTTP1_ERROR_INVALID_HEADER_VALUE,
  HTTP1_ERROR_HEADER_TOO_LARGE,
  HTTP1_ERROR_TOO_MANY_HEADERS,
  HTTP1_ERROR_INVALID_CONTENT_LENGTH,
  HTTP1_ERROR_INVALID_CHUNK_SIZE,
  HTTP1_ERROR_CHUNK_TOO_LARGE,
  HTTP1_ERROR_BODY_TOO_LARGE, /**< Decompressed body exceeds limit */
  HTTP1_ERROR_INVALID_TRAILER,
  HTTP1_ERROR_UNSUPPORTED_TRANSFER_CODING, /**< Unsupported Transfer-Encoding
                                              coding */
  HTTP1_ERROR_UNEXPECTED_EOF,
  HTTP1_ERROR_SMUGGLING_DETECTED /**< Request smuggling attempt */
} SocketHTTP1_Result;

/**
 * Body transfer mode (determined from headers)
 */
typedef enum
{
  HTTP1_BODY_NONE,           /**< No body (GET, HEAD, 1xx, 204, 304) */
  HTTP1_BODY_CONTENT_LENGTH, /**< Fixed Content-Length */
  HTTP1_BODY_CHUNKED,        /**< Transfer-Encoding: chunked */
  HTTP1_BODY_UNTIL_CLOSE     /**< Read until connection close (HTTP/1.0) */
} SocketHTTP1_BodyMode;

/**
 * Parser runtime configuration
 */
typedef struct
{
  size_t max_request_line; /**< Maximum request/status line length */
  size_t max_header_name;  /**< Maximum header name length */
  size_t max_header_value; /**< Maximum header value length */
  size_t max_headers;      /**< Maximum header count */
  size_t max_header_size;  /**< Maximum total header size */
  size_t max_chunk_size;   /**< Maximum chunk size */
  size_t max_chunk_ext; /**< Maximum chunk extension length (default: 1024) */
  size_t max_trailer_size; /**< Maximum trailer size */
  size_t max_header_line;  /**< Maximum individual header line length (name +
                              value + OWS + \r\n) */
  int allow_obs_fold;      /**< Allow obsolete header folding (default: 0) */
  int strict_mode;         /**< Reject ambiguous input (default: 1) */
  size_t
      max_decompressed_size; /**< Maximum decompressed body size (0=unlimited,
                                default from SocketSecurity_MAX_BODY_SIZE) */
} SocketHTTP1_Config;

/**
 * Parser instance (opaque type)
 */
typedef struct SocketHTTP1_Parser *SocketHTTP1_Parser_T;

/* ============================================================================
 * Parser Configuration
 * ============================================================================
 */

/**
 * SocketHTTP1_config_defaults - Initialize config with defaults
 * @config: Configuration to initialize
 *
 * Sets all limits to compile-time defaults and strict_mode to 1.
 * Thread-safe: Yes
 */
extern void SocketHTTP1_config_defaults (SocketHTTP1_Config *config);

/* ============================================================================
 * Parser Lifecycle
 * ============================================================================
 */

/**
 * SocketHTTP1_Parser_new - Create new parser
 * @mode: Request or response parsing mode
 * @config: Configuration (NULL for defaults)
 * @arena: Memory arena for allocations
 *
 * Returns: New parser instance
 * Raises: SocketHTTP1_ParseError on allocation failure
 * Thread-safe: Yes (arena must be thread-safe or thread-local)
 */
extern SocketHTTP1_Parser_T
SocketHTTP1_Parser_new (SocketHTTP1_ParseMode mode,
                        const SocketHTTP1_Config *config, Arena_T arena);

/**
 * SocketHTTP1_Parser_free - Free parser
 * @parser: Pointer to parser (set to NULL after free)
 *
 * Note: Strings returned by get_request/get_response remain valid
 * until the arena is disposed.
 * Thread-safe: No
 */
extern void SocketHTTP1_Parser_free (SocketHTTP1_Parser_T *parser);

/**
 * SocketHTTP1_Parser_reset - Reset parser for next message
 * @parser: Parser instance
 *
 * Resets parser state for parsing another message on same connection.
 * Thread-safe: No
 */
extern void SocketHTTP1_Parser_reset (SocketHTTP1_Parser_T parser);

/* ============================================================================
 * Parsing API
 * ============================================================================
 */

/**
 * SocketHTTP1_Parser_execute - Parse data incrementally
 * @parser: Parser instance
 * @data: Input data buffer
 * @len: Data length
 * @consumed: Output - bytes consumed from input
 *
 * Feed data to the parser incrementally. Can be called multiple times
 * with partial data. Parsing stops at message boundary:
 * - After headers for HEAD responses, 1xx, 204, 304
 * - After body for other responses
 * - After headers for requests (body read separately)
 *
 * Returns: HTTP1_OK when headers complete, HTTP1_INCOMPLETE if need more,
 *          or error code
 * Thread-safe: No
 */
extern SocketHTTP1_Result
SocketHTTP1_Parser_execute (SocketHTTP1_Parser_T parser, const char *data,
                            size_t len, size_t *consumed);

/**
 * SocketHTTP1_Parser_state - Get current parser state
 * @parser: Parser instance
 *
 * Returns: Current high-level state
 * Thread-safe: No
 */
extern SocketHTTP1_State
SocketHTTP1_Parser_state (SocketHTTP1_Parser_T parser);

/**
 * SocketHTTP1_Parser_get_request - Get parsed request
 * @parser: Parser instance (must be in REQUEST mode)
 *
 * Call after headers are complete (state >= HTTP1_STATE_BODY).
 *
 * Returns: Pointer to request structure, or NULL if not ready
 * Thread-safe: No
 */
extern const SocketHTTP_Request *
SocketHTTP1_Parser_get_request (SocketHTTP1_Parser_T parser);

/**
 * SocketHTTP1_Parser_get_response - Get parsed response
 * @parser: Parser instance (must be in RESPONSE mode)
 *
 * Call after headers are complete.
 *
 * Returns: Pointer to response structure, or NULL if not ready
 * Thread-safe: No
 */
extern const SocketHTTP_Response *
SocketHTTP1_Parser_get_response (SocketHTTP1_Parser_T parser);

/* ============================================================================
 * Body Handling
 * ============================================================================
 */

/**
 * SocketHTTP1_Parser_body_mode - Get body transfer mode
 * @parser: Parser instance
 *
 * Determined from headers (Transfer-Encoding, Content-Length).
 * Call after headers complete.
 *
 * Returns: Body transfer mode
 * Thread-safe: No
 */
extern SocketHTTP1_BodyMode
SocketHTTP1_Parser_body_mode (SocketHTTP1_Parser_T parser);

/**
 * SocketHTTP1_Parser_content_length - Get Content-Length value
 * @parser: Parser instance
 *
 * Returns: Content-Length value, or -1 if not specified or chunked
 * Thread-safe: No
 */
extern int64_t SocketHTTP1_Parser_content_length (SocketHTTP1_Parser_T parser);

/**
 * SocketHTTP1_Parser_body_remaining - Get remaining body bytes
 * @parser: Parser instance
 *
 * Returns: Remaining bytes, or -1 if unknown (chunked/until-close)
 * Thread-safe: No
 */
extern int64_t SocketHTTP1_Parser_body_remaining (SocketHTTP1_Parser_T parser);

/**
 * SocketHTTP1_Parser_read_body - Read body data
 * @parser: Parser instance
 * @input: Input buffer (raw socket data)
 * @input_len: Input length
 * @consumed: Output - bytes consumed from input
 * @output: Output buffer for decoded body
 * @output_len: Output buffer size
 * @written: Output - bytes written to output
 *
 * Handles chunked decoding transparently. For Content-Length bodies,
 * copies directly. For chunked, decodes and outputs raw data.
 *
 * Returns: HTTP1_OK if complete, HTTP1_INCOMPLETE if more data needed,
 *          or error code
 * Thread-safe: No
 */
extern SocketHTTP1_Result
SocketHTTP1_Parser_read_body (SocketHTTP1_Parser_T parser, const char *input,
                              size_t input_len, size_t *consumed, char *output,
                              size_t output_len, size_t *written);

/**
 * SocketHTTP1_Parser_body_complete - Check if body fully received
 * @parser: Parser instance
 *
 * Returns: 1 if body complete, 0 otherwise
 * Thread-safe: No
 */
extern int SocketHTTP1_Parser_body_complete (SocketHTTP1_Parser_T parser);

/**
 * SocketHTTP1_Parser_get_trailers - Get trailer headers
 * @parser: Parser instance
 *
 * Only valid for chunked encoding with trailers.
 *
 * Returns: Trailer headers, or NULL if none/not chunked
 * Thread-safe: No
 */
extern SocketHTTP_Headers_T
SocketHTTP1_Parser_get_trailers (SocketHTTP1_Parser_T parser);

/* ============================================================================
 * Connection Management
 * ============================================================================
 */

/**
 * SocketHTTP1_Parser_should_keepalive - Check keep-alive status
 * @parser: Parser instance
 *
 * Based on HTTP version and Connection header:
 * - HTTP/1.0: Keep-alive only if "Connection: keep-alive"
 * - HTTP/1.1: Keep-alive unless "Connection: close"
 *
 * Returns: 1 if connection should be kept alive, 0 otherwise
 * Thread-safe: No
 */
extern int SocketHTTP1_Parser_should_keepalive (SocketHTTP1_Parser_T parser);

/**
 * SocketHTTP1_Parser_is_upgrade - Check if upgrade requested
 * @parser: Parser instance
 *
 * Returns: 1 if Upgrade header present and valid, 0 otherwise
 * Thread-safe: No
 */
extern int SocketHTTP1_Parser_is_upgrade (SocketHTTP1_Parser_T parser);

/**
 * SocketHTTP1_Parser_upgrade_protocol - Get requested upgrade protocol
 * @parser: Parser instance
 *
 * Returns: Protocol name (e.g., "websocket", "h2c"), or NULL
 * Thread-safe: No
 */
extern const char *
SocketHTTP1_Parser_upgrade_protocol (SocketHTTP1_Parser_T parser);

/**
 * SocketHTTP1_Parser_expects_continue - Check for Expect: 100-continue
 * @parser: Parser instance
 *
 * Returns: 1 if client expects 100-continue, 0 otherwise
 * Thread-safe: No
 */
extern int SocketHTTP1_Parser_expects_continue (SocketHTTP1_Parser_T parser);

/* ============================================================================
 * Serialization API
 * ============================================================================
 */

/**
 * SocketHTTP1_serialize_request - Serialize request to buffer
 * @request: Request to serialize
 * @output: Output buffer
 * @output_size: Buffer size
 *
 * Serializes request line and headers. Does NOT serialize body.
 * Automatically adds Host header if missing (from authority).
 * Terminates with CRLF CRLF.
 *
 * Returns: Bytes written (excluding null), or -1 on error (buffer too small)
 * Raises: SocketHTTP1_SerializeError on invalid input (unknown method/version)
 * Thread-safe: Yes
 */
extern ssize_t
SocketHTTP1_serialize_request (const SocketHTTP_Request *request, char *output,
                               size_t output_size);

/**
 * SocketHTTP1_serialize_response - Serialize response to buffer
 * @response: Response to serialize
 * @output: Output buffer
 * @output_size: Buffer size
 *
 * Serializes status line and headers. Does NOT serialize body.
 *
 * Returns: Bytes written (excluding null), or -1 on error (buffer too small)
 * Raises: SocketHTTP1_SerializeError on invalid input (invalid status/version)
 * Thread-safe: Yes
 */
extern ssize_t
SocketHTTP1_serialize_response (const SocketHTTP_Response *response,
                                char *output, size_t output_size);

/**
 * SocketHTTP1_serialize_headers - Serialize headers only
 * @headers: Headers to serialize
 * @output: Output buffer
 * @output_size: Buffer size
 *
 * Each header formatted as "Name: Value\r\n".
 * Does NOT add final CRLF.
 *
 * Returns: Bytes written (excluding null), or -1 on error (buffer too small)
 * Raises: SocketHTTP1_SerializeError on invalid headers
 * Thread-safe: Yes
 */
extern ssize_t SocketHTTP1_serialize_headers (SocketHTTP_Headers_T headers,
                                              char *output,
                                              size_t output_size);

/* ============================================================================
 * Chunked Encoding
 * ============================================================================
 */

/**
 * SocketHTTP1_chunk_encode - Encode data as single chunk
 * @data: Input data
 * @len: Data length
 * @output: Output buffer
 * @output_size: Buffer size
 *
 * Output format: HEX_SIZE\r\nDATA\r\n
 * Required output size: len + 20 (for size line and CRLF)
 *
 * Returns: Total bytes written, or -1 on error
 * Thread-safe: Yes
 */
extern ssize_t SocketHTTP1_chunk_encode (const void *data, size_t len,
                                         char *output, size_t output_size);

/**
 * SocketHTTP1_chunk_final - Write final (zero-length) chunk
 * @output: Output buffer
 * @output_size: Buffer size
 * @trailers: Optional trailer headers (NULL for none)
 *
 * Output format: 0\r\n[trailers]\r\n
 *
 * Returns: Bytes written, or -1 on error
 * Thread-safe: Yes
 */
extern ssize_t SocketHTTP1_chunk_final (char *output, size_t output_size,
                                        SocketHTTP_Headers_T trailers);

/**
 * SocketHTTP1_chunk_encode_size - Calculate encoded chunk size
 * @data_len: Data length to encode
 *
 * Returns: Required buffer size for chunk (including headers and CRLF)
 * Thread-safe: Yes
 */
extern size_t SocketHTTP1_chunk_encode_size (size_t data_len);

/* ============================================================================
 * Content Encoding (Optional - requires zlib/brotli)
 * ============================================================================
 */

#ifdef SOCKETHTTP1_HAS_COMPRESSION

/**
 * Content decoder (opaque type)
 */
typedef struct SocketHTTP1_Decoder *SocketHTTP1_Decoder_T;

/**
 * Content encoder (opaque type)
 */
typedef struct SocketHTTP1_Encoder *SocketHTTP1_Encoder_T;

/**
 * Compression level
 */
typedef enum
{
  HTTP1_COMPRESS_FAST = 1,
  HTTP1_COMPRESS_DEFAULT = 6,
  HTTP1_COMPRESS_BEST = 9
} SocketHTTP1_CompressLevel;

/**
 * SocketHTTP1_Decoder_new - Create content decoder
 * @coding: Content coding (GZIP, DEFLATE, BR)
 * @cfg: Configuration for limits (may be NULL for defaults)
 * @arena: Memory arena
 *
 * Returns: Decoder instance, or NULL on error
 * Thread-safe: Yes
 */
extern SocketHTTP1_Decoder_T
SocketHTTP1_Decoder_new (SocketHTTP_Coding coding,
                         const SocketHTTP1_Config *cfg, Arena_T arena);

/**
 * SocketHTTP1_Decoder_free - Free decoder
 * @decoder: Pointer to decoder
 */
extern void SocketHTTP1_Decoder_free (SocketHTTP1_Decoder_T *decoder);

/**
 * SocketHTTP1_Decoder_decode - Decode compressed data
 * @decoder: Decoder instance
 * @input: Compressed input
 * @input_len: Input length
 * @consumed: Output - bytes consumed
 * @output: Decompressed output buffer
 * @output_len: Output buffer size
 * @written: Output - bytes written
 *
 * Returns: HTTP1_OK, HTTP1_INCOMPLETE, or error
 */
extern SocketHTTP1_Result
SocketHTTP1_Decoder_decode (SocketHTTP1_Decoder_T decoder,
                            const unsigned char *input, size_t input_len,
                            size_t *consumed, unsigned char *output,
                            size_t output_len, size_t *written);

/**
 * SocketHTTP1_Decoder_finish - Finalize decoding
 * @decoder: Decoder instance
 * @output: Output buffer for remaining data
 * @output_len: Buffer size
 * @written: Output - bytes written
 */
extern SocketHTTP1_Result
SocketHTTP1_Decoder_finish (SocketHTTP1_Decoder_T decoder,
                            unsigned char *output, size_t output_len,
                            size_t *written);

/**
 * SocketHTTP1_Encoder_new - Create content encoder
 * @coding: Content coding (GZIP, DEFLATE, BR)
 * @level: Compression level
 * @cfg: Configuration for limits (may be NULL for defaults)
 * @arena: Memory arena
 */
extern SocketHTTP1_Encoder_T
SocketHTTP1_Encoder_new (SocketHTTP_Coding coding,
                         SocketHTTP1_CompressLevel level,
                         const SocketHTTP1_Config *cfg, Arena_T arena);

/**
 * SocketHTTP1_Encoder_free - Free encoder
 */
extern void SocketHTTP1_Encoder_free (SocketHTTP1_Encoder_T *encoder);

/**
 * SocketHTTP1_Encoder_encode - Encode data
 * @encoder: Encoder instance
 * @input: Input data
 * @input_len: Input length
 * @output: Output buffer
 * @output_len: Buffer size
 * @flush: Flush mode (0 = no flush, 1 = sync flush)
 *
 * Returns: Bytes written to output, or -1 on error
 */
extern ssize_t SocketHTTP1_Encoder_encode (SocketHTTP1_Encoder_T encoder,
                                           const unsigned char *input,
                                           size_t input_len,
                                           unsigned char *output,
                                           size_t output_len, int flush);

/**
 * SocketHTTP1_Encoder_finish - Finish encoding
 * @encoder: Encoder instance
 * @output: Output buffer
 * @output_len: Buffer size
 *
 * Returns: Bytes written, or -1 on error
 */
extern ssize_t SocketHTTP1_Encoder_finish (SocketHTTP1_Encoder_T encoder,
                                           unsigned char *output,
                                           size_t output_len);

#endif /* SOCKETHTTP1_HAS_COMPRESSION */

/* ============================================================================
 * Error Handling
 * ============================================================================
 */

/**
 * SocketHTTP1_result_string - Get human-readable error description
 * @result: Parse result code
 *
 * Returns: Static string describing the result
 * Thread-safe: Yes
 */
extern const char *SocketHTTP1_result_string (SocketHTTP1_Result result);

#endif /* SOCKETHTTP1_INCLUDED */
