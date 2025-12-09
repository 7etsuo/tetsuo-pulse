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
 * @see SocketHTTP_Headers_T for core HTTP types and utilities.
 * @see SocketHTTPClient_T for HTTP client functionality.
 * @see SocketHTTPServer_T for HTTP server functionality.
 */

/**
 * @defgroup http1 HTTP/1.1 Parser and Serializer Module
 * @ingroup http
 * @brief Comprehensive HTTP/1.1 parsing, serialization, and transfer encoding support.
 *
 * This module implements the HTTP/1.1 protocol (RFC 9112) with focus on security,
 * performance, and incremental processing. It handles message syntax validation,
 * header parsing, body transfer (content-length, chunked, until-close), and optional
 * content encoding/decoding.
 *
 * Security Features:
 * - Strict validation against request smuggling (ambiguous lengths)
 * - Configurable limits to prevent DoS (header count/size, line lengths)
 * - Rejection of invalid syntax and injection attempts
 * - Support for decompression limits to avoid "zip bombs"
 *
 * Usage Pattern:
 * - Create parser with SocketHTTP1_Parser_new()
 * - Feed data incrementally via SocketHTTP1_Parser_execute()
 * - Access parsed structures with get_request()/get_response()
 * - Handle body with read_body() or dedicated modes
 * - Serialize outgoing messages with serialize_request/response()
 *
 * Thread Safety: Functions are thread-safe unless noted; parser instances require
 * per-thread allocation due to internal state.
 *
 * Dependencies:
 * - @ref foundation (Arena for memory, Except for errors)
 * - @ref http (SocketHTTP types: Request, Response, Headers, URI)
 *
 * Related Modules:
 * - @ref http2 for HTTP/2 protocol
 * - @ref hpack for HTTP/2 header compression
 * - @ref websocket for WebSocket over HTTP
 *
 * Example:
 * @include examples/http_server.c (server-side parsing)
 * @include examples/http_get.c (client-side serialization)
 *
 * @{
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

/** @brief Maximum request/status line length. @ingroup http1 */
#ifndef SOCKETHTTP1_MAX_REQUEST_LINE
#define SOCKETHTTP1_MAX_REQUEST_LINE (8 * 1024)
#endif

/** @brief Maximum HTTP method length (longest standard: OPTIONS = 7). @ingroup http1 */
#ifndef SOCKETHTTP1_MAX_METHOD_LEN
#define SOCKETHTTP1_MAX_METHOD_LEN 16
#endif

/** @brief Maximum URI length in request line. @ingroup http1 */
#ifndef SOCKETHTTP1_MAX_URI_LEN
#define SOCKETHTTP1_MAX_URI_LEN (8 * 1024)
#endif

/** @brief Maximum header name length. @ingroup http1 */
#ifndef SOCKETHTTP1_MAX_HEADER_NAME
#define SOCKETHTTP1_MAX_HEADER_NAME 256
#endif

/** @brief Maximum header value length. @ingroup http1 */
#ifndef SOCKETHTTP1_MAX_HEADER_VALUE
#define SOCKETHTTP1_MAX_HEADER_VALUE (8 * 1024)
#endif

/** @brief Maximum number of headers. @ingroup http1 */
#ifndef SOCKETHTTP1_MAX_HEADERS
#define SOCKETHTTP1_MAX_HEADERS 100
#endif

/** @brief Maximum total header size. @ingroup http1 */
#ifndef SOCKETHTTP1_MAX_HEADER_SIZE
#define SOCKETHTTP1_MAX_HEADER_SIZE (64 * 1024)
#endif

/** @brief Maximum chunk size. @ingroup http1 */
#ifndef SOCKETHTTP1_MAX_CHUNK_SIZE
#define SOCKETHTTP1_MAX_CHUNK_SIZE (16 * 1024 * 1024)
#endif

/** @brief Maximum chunk extension length. @ingroup http1 */
#ifndef SOCKETHTTP1_MAX_CHUNK_EXT
#define SOCKETHTTP1_MAX_CHUNK_EXT 1024
#endif

/** @brief Maximum trailer headers size. @ingroup http1 */
#ifndef SOCKETHTTP1_MAX_TRAILER_SIZE
#define SOCKETHTTP1_MAX_TRAILER_SIZE (4 * 1024)
#endif

/** @brief Maximum individual header line length (name + : + value + OWS + \r\n). @ingroup http1 */
#ifndef SOCKETHTTP1_MAX_HEADER_LINE
#define SOCKETHTTP1_MAX_HEADER_LINE (16 * 1024)
#endif

/* ============================================================================
 * Serialization Buffer Sizes
 * ============================================================================
 */

/** @brief Buffer size for integer-to-string conversion (covers int64_t). @ingroup http1 */
#ifndef SOCKETHTTP1_INT_STRING_BUFSIZE
#define SOCKETHTTP1_INT_STRING_BUFSIZE 24
#endif

/** @brief Buffer size for Content-Length header line ("Content-Length: " + value). @ingroup http1 */
#ifndef SOCKETHTTP1_CONTENT_LENGTH_BUFSIZE
#define SOCKETHTTP1_CONTENT_LENGTH_BUFSIZE 48
#endif

/* ============================================================================
 * Exception Types
 * ============================================================================
 */

/**
 * @brief Exception for HTTP/1.1 parsing failures.
 * @ingroup http1
 *
 * Thrown by parser functions on syntax errors, security violations, or limit breaches.
 * Specific conditions:
 * - Malformed request line, status line, headers, or chunk directives
 * - Request smuggling detection (e.g., conflicting Content-Length/Transfer-Encoding)
 * - Exceeding configurable limits (line lengths, header counts/sizes, body size)
 * - Unexpected EOF or invalid transfer codings
 *
 * @see SocketHTTP1_Parser_execute() - primary throwing function
 * @see SocketHTTP1_Result for detailed error codes (non-exception path)
 * @see SocketHTTP1_Config for limit configuration to prevent exceptions
 * @see docs/ERROR_HANDLING.md for exception handling best practices
 */
extern const Except_T SocketHTTP1_ParseError;

/**
 * @brief Exception for HTTP/1.1 serialization failures.
 * @ingroup http1
 *
 * Thrown when input to serialization functions is invalid or malformed.
 * Common causes:
 * - Unknown or invalid HTTP method/status/version
 * - Missing required fields (e.g., Host header, valid URI)
 * - Headers violating HTTP syntax rules
 * - Buffer overflow during output generation
 *
 * @see SocketHTTP1_serialize_request()
 * @see SocketHTTP1_serialize_response()
 * @see SocketHTTP1_serialize_headers()
 * @see SocketHTTP_Request and SocketHTTP_Response for valid input structures
 */
extern const Except_T SocketHTTP1_SerializeError;

/* ============================================================================
 * Parser Types
 * ============================================================================
 */

/**
 * Parser mode
 */
/**
 * @brief Parser mode: request or response parsing.
 * @ingroup http1
 *
 * Selects whether the parser expects an HTTP request or response message.
 * @see SocketHTTP1_Parser_new()
 */
typedef enum
{
  HTTP1_PARSE_REQUEST, /**< Parse HTTP requests */
  HTTP1_PARSE_RESPONSE /**< Parse HTTP responses */
} SocketHTTP1_ParseMode;

/**
 * @brief High-level states of the HTTP/1.1 parser state machine.
 * @ingroup http1
 *
 * Indicates the current parsing phase: from start line to complete message or error.
 * Used for monitoring progress and handling partial parses.
 *
 * @see SocketHTTP1_Parser_state() to query current state.
 * @see SocketHTTP1_Parser_execute() for state transitions.
 */
typedef enum
{
  HTTP1_STATE_START,      /**< Waiting for first line (request or status) */
  HTTP1_STATE_HEADERS,    /**< Parsing HTTP headers */
  HTTP1_STATE_BODY,       /**< Reading message body (content-length or until close) */
  HTTP1_STATE_CHUNK_SIZE, /**< Reading chunk size line in chunked transfer */
  HTTP1_STATE_CHUNK_DATA, /**< Reading chunk data */
  HTTP1_STATE_CHUNK_END,  /**< Reading CRLF after chunk data */
  HTTP1_STATE_TRAILERS,   /**< Reading trailer headers (chunked only) */
  HTTP1_STATE_COMPLETE,   /**< Full message parsed successfully */
  HTTP1_STATE_ERROR       /**< Parse error occurred; check result code */
} SocketHTTP1_State;

/**
 * @brief Result codes from HTTP/1.1 parsing operations.
 * @ingroup http1
 *
 * Values indicate parsing success, continuation, or specific failure modes.
 * Error codes provide diagnostics for debugging and security logging.
 * Use SocketHTTP1_result_string() for human-readable descriptions.
 *
 * @see SocketHTTP1_Parser_execute()
 * @see SocketHTTP1_result_string()
 * @see SocketHTTP1_SerializeError for serialization failures
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
 * @brief Body transfer modes for HTTP messages.
 * @ingroup http1
 *
 * Determined from HTTP headers (Content-Length, Transfer-Encoding, method/status).
 * Guides how the parser consumes the message body after headers.
 *
 * @see SocketHTTP1_Parser_body_mode()
 * @see SocketHTTP1_Parser_content_length()
 * @see SocketHTTP1_Parser_read_body()
 */
typedef enum
{
  HTTP1_BODY_NONE,              /**< No body expected (e.g., GET/HEAD requests, 1xx/204/304 responses) */
  HTTP1_BODY_CONTENT_LENGTH,    /**< Body length specified by Content-Length header */
  HTTP1_BODY_CHUNKED,           /**< Chunked transfer encoding (Transfer-Encoding: chunked) */
  HTTP1_BODY_UNTIL_CLOSE        /**< Body delimited by connection close (HTTP/1.0 default, rare in 1.1) */
} SocketHTTP1_BodyMode;

/**
 * @brief Runtime configuration structure for the HTTP/1.1 parser.
 * @ingroup http1
 *
 * Customizes security limits, syntax tolerance, and decompression behavior.
 * Fields correspond to compile-time macros (e.g., SOCKETHTTP1_MAX_REQUEST_LINE)
 * and can be overridden for specific use cases like embedded systems or high-security.
 *
 * @note Defaults provide reasonable security; lowering limits improves DoS resistance.
 * @see SocketHTTP1_config_defaults() for initialization.
 * @see SocketHTTP1_Parser_new() passes config to parser.
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
 * @brief HTTP/1.1 parser instance (opaque type)
 * @ingroup http1
 */
typedef struct SocketHTTP1_Parser *SocketHTTP1_Parser_T;

/* ============================================================================
 * Parser Configuration
 * ============================================================================
 */

/**
 * @brief Initialize SocketHTTP1_Config with safe default values.
 * @ingroup http1
 * @param config [out] Configuration structure to populate
 * @threadsafe Yes - pure function, no side effects
 *
 * Populates all fields with compile-time defaults (e.g., SOCKETHTTP1_MAX_HEADERS=100)
 * and enables strict mode for RFC compliance and security.
 * Recommended starting point before custom tuning.
 *
 * @see SocketHTTP1_Config for field details and overrides
 * @see SocketHTTP1_Parser_new() which accepts this config
 * @see http1 for module overview
 */
extern void SocketHTTP1_config_defaults (SocketHTTP1_Config *config);

/* ============================================================================
 * Parser Lifecycle
 * ============================================================================
 */

/**
 * @brief Create new parser
 * @ingroup http1
 * @param mode Request or response parsing mode
 * @param config Configuration (NULL for defaults)
 * @param arena Memory arena for allocations
 * @return New parser instance
 * @throws SocketHTTP1_ParseError on allocation failure
 * @threadsafe Yes (arena must be thread-safe or thread-local)
 */
extern SocketHTTP1_Parser_T
SocketHTTP1_Parser_new (SocketHTTP1_ParseMode mode,
                        const SocketHTTP1_Config *config, Arena_T arena);

/**
 * @brief Free parser
 * @ingroup http1
 * @param parser Pointer to parser (set to NULL after free)
 * @threadsafe No
 *
 * Note: Strings returned by get_request/get_response remain valid
 * until the arena is disposed.
 */
extern void SocketHTTP1_Parser_free (SocketHTTP1_Parser_T *parser);

/**
 * @brief Reset parser for next message
 * @ingroup http1
 * @param parser Parser instance
 * @threadsafe No
 *
 * Resets parser state for parsing another message on same connection.
 */
extern void SocketHTTP1_Parser_reset (SocketHTTP1_Parser_T parser);

/* ============================================================================
 * Parsing API
 * ============================================================================
 */

/**
 * @brief Parse data incrementally
 * @ingroup http1
 * @param parser Parser instance
 * @param data Input data buffer
 * @param len Data length
 * @param consumed Output - bytes consumed from input
 * @return HTTP1_OK when headers complete, HTTP1_INCOMPLETE if need more, or error code
 * @threadsafe No
 *
 * Feed data to the parser incrementally. Can be called multiple times
 * with partial data. Parsing stops at message boundary:
 * - After headers for HEAD responses, 1xx, 204, 304
 * - After body for other responses
 * - After headers for requests (body read separately)
 */
extern SocketHTTP1_Result
SocketHTTP1_Parser_execute (SocketHTTP1_Parser_T parser, const char *data,
                            size_t len, size_t *consumed);

/**
 * @brief Get current parser state
 * @ingroup http1
 * @param parser Parser instance
 * @return Current high-level state
 * @threadsafe No
 */
extern SocketHTTP1_State
SocketHTTP1_Parser_state (SocketHTTP1_Parser_T parser);

/**
 * @brief Get parsed request
 * @ingroup http1
 * @param parser Parser instance (must be in REQUEST mode)
 * @return Pointer to request structure, or NULL if not ready
 * @threadsafe No
 *
 * Call after headers are complete (state >= HTTP1_STATE_BODY).
 */
extern const SocketHTTP_Request *
SocketHTTP1_Parser_get_request (SocketHTTP1_Parser_T parser);

/**
 * @brief Get parsed response
 * @ingroup http1
 * @param parser Parser instance (must be in RESPONSE mode)
 * @return Pointer to response structure, or NULL if not ready
 * @threadsafe No
 *
 * Call after headers are complete.
 */
extern const SocketHTTP_Response *
SocketHTTP1_Parser_get_response (SocketHTTP1_Parser_T parser);

/* ============================================================================
 * Body Handling
 * ============================================================================
 */

/**
 * @brief Get body transfer mode
 * @ingroup http1
 * @param parser Parser instance
 * @return Body transfer mode
 * @threadsafe No
 *
 * Determined from headers (Transfer-Encoding, Content-Length).
 * Call after headers complete.
 */
extern SocketHTTP1_BodyMode
SocketHTTP1_Parser_body_mode (SocketHTTP1_Parser_T parser);

/**
 * @brief Get Content-Length value
 * @ingroup http1
 * @param parser Parser instance
 * @return Content-Length value, or -1 if not specified or chunked
 * @threadsafe No
 */
extern int64_t SocketHTTP1_Parser_content_length (SocketHTTP1_Parser_T parser);

/**
 * @brief Get remaining body bytes
 * @ingroup http1
 * @param parser Parser instance
 * @return Remaining bytes, or -1 if unknown (chunked/until-close)
 * @threadsafe No
 */
extern int64_t SocketHTTP1_Parser_body_remaining (SocketHTTP1_Parser_T parser);

/**
 * @brief Read body data
 * @ingroup http1
 * @param parser Parser instance
 * @param input Input buffer (raw socket data)
 * @param input_len Input length
 * @param consumed Output - bytes consumed from input
 * @param output Output buffer for decoded body
 * @param output_len Output buffer size
 * @param written Output - bytes written to output
 * @return HTTP1_OK if complete, HTTP1_INCOMPLETE if more data needed, or error code
 * @threadsafe No
 *
 * Handles chunked decoding transparently. For Content-Length bodies,
 * copies directly. For chunked, decodes and outputs raw data.
 */
extern SocketHTTP1_Result
SocketHTTP1_Parser_read_body (SocketHTTP1_Parser_T parser, const char *input,
                              size_t input_len, size_t *consumed, char *output,
                              size_t output_len, size_t *written);

/**
 * @brief Check if body fully received
 * @ingroup http1
 * @param parser Parser instance
 * @return 1 if body complete, 0 otherwise
 * @threadsafe No
 */
extern int SocketHTTP1_Parser_body_complete (SocketHTTP1_Parser_T parser);

/**
 * @brief Get trailer headers
 * @ingroup http1
 * @param parser Parser instance
 * @return Trailer headers, or NULL if none/not chunked
 * @threadsafe No
 *
 * Only valid for chunked encoding with trailers.
 */
extern SocketHTTP_Headers_T
SocketHTTP1_Parser_get_trailers (SocketHTTP1_Parser_T parser);

/* ============================================================================
 * Connection Management
 * ============================================================================
 */

/**
 * @brief Check keep-alive status
 * @ingroup http1
 * @param parser Parser instance
 * @return 1 if connection should be kept alive, 0 otherwise
 * @threadsafe No
 *
 * Based on HTTP version and Connection header:
 * - HTTP/1.0: Keep-alive only if "Connection: keep-alive"
 * - HTTP/1.1: Keep-alive unless "Connection: close"
 */
extern int SocketHTTP1_Parser_should_keepalive (SocketHTTP1_Parser_T parser);

/**
 * @brief Check if upgrade requested
 * @ingroup http1
 * @param parser Parser instance
 * @return 1 if Upgrade header present and valid, 0 otherwise
 * @threadsafe No
 */
extern int SocketHTTP1_Parser_is_upgrade (SocketHTTP1_Parser_T parser);

/**
 * @brief Get requested upgrade protocol
 * @ingroup http1
 * @param parser Parser instance
 * @return Protocol name (e.g., "websocket", "h2c"), or NULL
 * @threadsafe No
 */
extern const char *
SocketHTTP1_Parser_upgrade_protocol (SocketHTTP1_Parser_T parser);

/**
 * @brief Check for Expect: 100-continue
 * @ingroup http1
 * @param parser Parser instance
 * @return 1 if client expects 100-continue, 0 otherwise
 * @threadsafe No
 */
extern int SocketHTTP1_Parser_expects_continue (SocketHTTP1_Parser_T parser);

/* ============================================================================
 * Serialization API
 * ============================================================================
 */

/**
 * @brief Serialize request to buffer
 * @ingroup http1
 * @param request Request to serialize
 * @param output Output buffer
 * @param output_size Buffer size
 * @return Bytes written (excluding null), or -1 on error (buffer too small)
 * @throws SocketHTTP1_SerializeError on invalid input (unknown method/version)
 * @threadsafe Yes
 *
 * Serializes request line and headers. Does NOT serialize body.
 * Automatically adds Host header if missing (from authority).
 * Terminates with CRLF CRLF.
 */
extern ssize_t
SocketHTTP1_serialize_request (const SocketHTTP_Request *request, char *output,
                               size_t output_size);

/**
 * @brief Serialize response to buffer
 * @ingroup http1
 * @param response Response to serialize
 * @param output Output buffer
 * @param output_size Buffer size
 * @return Bytes written (excluding null), or -1 on error (buffer too small)
 * @throws SocketHTTP1_SerializeError on invalid input (invalid status/version)
 * @threadsafe Yes
 *
 * Serializes status line and headers. Does NOT serialize body.
 */
extern ssize_t
SocketHTTP1_serialize_response (const SocketHTTP_Response *response,
                                char *output, size_t output_size);

/**
 * @brief Serialize headers only
 * @ingroup http1
 * @param headers Headers to serialize
 * @param output Output buffer
 * @param output_size Buffer size
 * @return Bytes written (excluding null), or -1 on error (buffer too small)
 * @throws SocketHTTP1_SerializeError on invalid headers
 * @threadsafe Yes
 *
 * Each header formatted as "Name: Value\r\n".
 * Does NOT add final CRLF.
 */
extern ssize_t SocketHTTP1_serialize_headers (SocketHTTP_Headers_T headers,
                                              char *output,
                                              size_t output_size);

/* ============================================================================
 * Chunked Encoding
 * ============================================================================
 */

/**
 * @brief Encode data as single chunk
 * @ingroup http1
 * @param data Input data
 * @param len Data length
 * @param output Output buffer
 * @param output_size Buffer size
 * @return Total bytes written, or -1 on error
 * @threadsafe Yes
 *
 * Output format: HEX_SIZE\r\nDATA\r\n
 * Required output size: len + 20 (for size line and CRLF)
 */
extern ssize_t SocketHTTP1_chunk_encode (const void *data, size_t len,
                                         char *output, size_t output_size);

/**
 * @brief Write final (zero-length) chunk
 * @ingroup http1
 * @param output Output buffer
 * @param output_size Buffer size
 * @param trailers Optional trailer headers (NULL for none)
 * @return Bytes written, or -1 on error
 * @threadsafe Yes
 *
 * Output format: 0\r\n[trailers]\r\n
 */
extern ssize_t SocketHTTP1_chunk_final (char *output, size_t output_size,
                                        SocketHTTP_Headers_T trailers);

/**
 * @brief Calculate encoded chunk size
 * @ingroup http1
 * @param data_len Data length to encode
 * @return Required buffer size for chunk (including headers and CRLF)
 * @threadsafe Yes
 */
extern size_t SocketHTTP1_chunk_encode_size (size_t data_len);

/* ============================================================================
 * Content Encoding (Optional - requires zlib/brotli)
 * ============================================================================
 */

#if SOCKETHTTP1_HAS_COMPRESSION

/**
 * @brief HTTP/1.1 content decoder (opaque type)
 * @ingroup http1
 */
typedef struct SocketHTTP1_Decoder *SocketHTTP1_Decoder_T;

/**
 * @brief HTTP/1.1 content encoder (opaque type)
 * @ingroup http1
 */
typedef struct SocketHTTP1_Encoder *SocketHTTP1_Encoder_T;

/**
 * @brief Compression levels for content encoders.
 * @ingroup http1
 *
 * Controls trade-off between speed and compression ratio.
 * Higher levels use more CPU but reduce output size.
 *
 * @see SocketHTTP1_Encoder_new()
 */
typedef enum
{
  HTTP1_COMPRESS_FAST = 1,     /**< Fastest compression (lowest ratio, least CPU) */
  HTTP1_COMPRESS_DEFAULT = 6,  /**< Balanced default (standard zlib/gzip level) */
  HTTP1_COMPRESS_BEST = 9      /**< Maximum compression (best ratio, most CPU) */
} SocketHTTP1_CompressLevel;

/**
 * @brief Create content decoder
 * @ingroup http1
 * @param coding Content coding (GZIP, DEFLATE, BR)
 * @param cfg Configuration for limits (may be NULL for defaults)
 * @param arena Memory arena
 * @return Decoder instance, or NULL on error
 * @threadsafe Yes
 */
extern SocketHTTP1_Decoder_T
SocketHTTP1_Decoder_new (SocketHTTP_Coding coding,
                         const SocketHTTP1_Config *cfg, Arena_T arena);

/**
 * @brief Free decoder
 * @ingroup http1
 * @param decoder Pointer to decoder
 */
extern void SocketHTTP1_Decoder_free (SocketHTTP1_Decoder_T *decoder);

/**
 * @brief Decode compressed data
 * @ingroup http1
 * @param decoder Decoder instance
 * @param input Compressed input
 * @param input_len Input length
 * @param consumed Output - bytes consumed
 * @param output Decompressed output buffer
 * @param output_len Output buffer size
 * @param written Output - bytes written
 * @return HTTP1_OK, HTTP1_INCOMPLETE, or error
 */
extern SocketHTTP1_Result
SocketHTTP1_Decoder_decode (SocketHTTP1_Decoder_T decoder,
                            const unsigned char *input, size_t input_len,
                            size_t *consumed, unsigned char *output,
                            size_t output_len, size_t *written);

/**
 * @brief Finalize decoding
 * @ingroup http1
 * @param decoder Decoder instance
 * @param output Output buffer for remaining data
 * @param output_len Buffer size
 * @param written Output - bytes written
 */
extern SocketHTTP1_Result
SocketHTTP1_Decoder_finish (SocketHTTP1_Decoder_T decoder,
                            unsigned char *output, size_t output_len,
                            size_t *written);

/**
 * @brief Create content encoder
 * @ingroup http1
 * @param coding Content coding (GZIP, DEFLATE, BR)
 * @param level Compression level
 * @param cfg Configuration for limits (may be NULL for defaults)
 * @param arena Memory arena
 */
extern SocketHTTP1_Encoder_T
SocketHTTP1_Encoder_new (SocketHTTP_Coding coding,
                         SocketHTTP1_CompressLevel level,
                         const SocketHTTP1_Config *cfg, Arena_T arena);

/**
 * @brief Free encoder
 * @ingroup http1
 * @param encoder Encoder instance
 */
extern void SocketHTTP1_Encoder_free (SocketHTTP1_Encoder_T *encoder);

/**
 * @brief Encode data
 * @ingroup http1
 * @param encoder Encoder instance
 * @param input Input data
 * @param input_len Input length
 * @param output Output buffer
 * @param output_len Buffer size
 * @param flush Flush mode (0 = no flush, 1 = sync flush)
 * @return Bytes written to output, or -1 on error
 */
extern ssize_t SocketHTTP1_Encoder_encode (SocketHTTP1_Encoder_T encoder,
                                           const unsigned char *input,
                                           size_t input_len,
                                           unsigned char *output,
                                           size_t output_len, int flush);

/**
 * @brief Finish encoding
 * @ingroup http1
 * @param encoder Encoder instance
 * @param output Output buffer
 * @param output_len Buffer size
 * @return Bytes written, or -1 on error
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
 * @brief Get human-readable error description
 * @ingroup http1
 * @param result Parse result code
 * @return Static string describing the result
 * @threadsafe Yes
 */
extern const char *SocketHTTP1_result_string (SocketHTTP1_Result result);

/** @} */ /* http1 */

/**
 * @ingroup http1
 * @page http1_page HTTP/1.1 Module Overview
 *
 * Additional module-specific page if needed.
 * This can include diagrams, examples, or advanced topics.
 */

/* No additional page for now */

#endif /* SOCKETHTTP1_INCLUDED */
