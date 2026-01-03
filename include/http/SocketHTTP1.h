/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTP1.h
 * @ingroup http
 * @brief HTTP/1.1 message syntax parsing and serialization (RFC 9112).
 *
 * Provides HTTP/1.1 message parsing, serialization, and chunked encoding.
 *
 * Features:
 * - DFA-based incremental parser (O(n) complexity)
 * - Request and response parsing
 * - Chunked transfer encoding with trailer support
 * - Request smuggling prevention (strict RFC 9112 Section 6.3)
 * - Optional content encoding (gzip/deflate/brotli)
 * - Configurable limits for security
 *
 * Security notes:
 * - Rejects requests with both Content-Length and Transfer-Encoding
 * - Rejects multiple differing Content-Length values
 * - Validates all header names/values for injection attacks
 * - Enforces configurable size limits
 */

/**
 * @defgroup http1 HTTP/1.1 Parser and Serializer Module
 * @ingroup http
 * @brief HTTP/1.1 parsing, serialization, and transfer encoding support.
 *
 * This module implements the HTTP/1.1 protocol (RFC 9112) with focus on
 * security, performance, and incremental processing.
 *
 * Security Features:
 * - Strict validation against request smuggling (ambiguous lengths)
 * - Configurable limits to prevent DoS
 * - Rejection of invalid syntax and injection attempts
 *
 * Thread Safety: Parser instances are NOT thread-safe.
 * Use one parser per thread or external synchronization.
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

/** @brief Maximum request/status line length (8KB) */
#ifndef SOCKETHTTP1_MAX_REQUEST_LINE
#define SOCKETHTTP1_MAX_REQUEST_LINE (8 * 1024)
#endif

/** @brief Maximum HTTP method length */
#ifndef SOCKETHTTP1_MAX_METHOD_LEN
#define SOCKETHTTP1_MAX_METHOD_LEN 16
#endif

/** @brief Maximum URI length (8KB) */
#ifndef SOCKETHTTP1_MAX_URI_LEN
#define SOCKETHTTP1_MAX_URI_LEN (8 * 1024)
#endif

/** @brief Maximum header name length (256B) */
#ifndef SOCKETHTTP1_MAX_HEADER_NAME
#define SOCKETHTTP1_MAX_HEADER_NAME 256
#endif

/** @brief Maximum header value length (8KB) */
#ifndef SOCKETHTTP1_MAX_HEADER_VALUE
#define SOCKETHTTP1_MAX_HEADER_VALUE (8 * 1024)
#endif

/** @brief Maximum number of headers (100) */
#ifndef SOCKETHTTP1_MAX_HEADERS
#define SOCKETHTTP1_MAX_HEADERS 100
#endif

/** @brief Maximum total header size (64KB) */
#ifndef SOCKETHTTP1_MAX_HEADER_SIZE
#define SOCKETHTTP1_MAX_HEADER_SIZE (64 * 1024)
#endif

/** @brief Maximum chunk size (16MB) */
#ifndef SOCKETHTTP1_MAX_CHUNK_SIZE
#define SOCKETHTTP1_MAX_CHUNK_SIZE (16 * 1024 * 1024)
#endif

/** @brief Maximum chunk extension length (1KB) */
#ifndef SOCKETHTTP1_MAX_CHUNK_EXT
#define SOCKETHTTP1_MAX_CHUNK_EXT 1024
#endif

/** @brief Maximum trailer headers size (4KB) */
#ifndef SOCKETHTTP1_MAX_TRAILER_SIZE
#define SOCKETHTTP1_MAX_TRAILER_SIZE (4 * 1024)
#endif

/** @brief Maximum individual header line length */
#ifndef SOCKETHTTP1_MAX_HEADER_LINE
#define SOCKETHTTP1_MAX_HEADER_LINE (16 * 1024)
#endif

/**
 * @brief Default overhead per trailer entry for memory accounting.
 *
 * This value represents an estimate of per-entry overhead for trailer headers,
 * including:
 * - HeaderEntry struct (64 bytes on 64-bit: 5 pointers + 2 size_t + 2 ints)
 * - String null terminators (2 bytes)
 * - Wire format delimiters (": " + "\r\n" = 4 bytes)
 *
 * The default value of 32 is a CONSERVATIVE UNDERESTIMATE of actual overhead
 * (~70 bytes total), providing a safety margin while preventing excessive
 * memory consumption from trailer headers. This can be tuned per use case
 * via SocketHTTP1_Config.trailer_entry_overhead if stricter or looser
 * accounting is needed.
 */
#ifndef SOCKETHTTP1_TRAILER_ENTRY_OVERHEAD
#define SOCKETHTTP1_TRAILER_ENTRY_OVERHEAD 32
#endif

/** @brief Buffer size for integer-to-string conversion */
#ifndef SOCKETHTTP1_INT_STRING_BUFSIZE
#define SOCKETHTTP1_INT_STRING_BUFSIZE 24
#endif

/** @brief Buffer size for Content-Length header line */
#ifndef SOCKETHTTP1_CONTENT_LENGTH_BUFSIZE
#define SOCKETHTTP1_CONTENT_LENGTH_BUFSIZE 48
#endif

/**
 * @brief Exception for HTTP/1.1 parsing failures.
 *
 * Thrown on syntax errors, security violations, or limit breaches.
 * Includes request smuggling detection and exceeded limits.
 */
extern const Except_T SocketHTTP1_ParseError;

/**
 * @brief Exception for HTTP/1.1 serialization failures.
 *
 * Thrown when input is invalid (e.g., unknown method, malformed URI,
 * missing required fields, or buffer overflow).
 */
extern const Except_T SocketHTTP1_SerializeError;

/**
 * @brief Parser mode: request or response parsing.
 */
typedef enum
{
  HTTP1_PARSE_REQUEST, /**< Parse HTTP requests */
  HTTP1_PARSE_RESPONSE /**< Parse HTTP responses */
} SocketHTTP1_ParseMode;

/**
 * @brief High-level states of the HTTP/1.1 parser state machine.
 */
typedef enum
{
  HTTP1_STATE_START,      /**< Waiting for first line (request or status) */
  HTTP1_STATE_HEADERS,    /**< Parsing HTTP headers */
  HTTP1_STATE_BODY,       /**< Reading message body */
  HTTP1_STATE_CHUNK_SIZE, /**< Reading chunk size line in chunked transfer */
  HTTP1_STATE_CHUNK_DATA, /**< Reading chunk data */
  HTTP1_STATE_CHUNK_END,  /**< Reading CRLF after chunk data */
  HTTP1_STATE_TRAILERS,   /**< Reading trailer headers (chunked only) */
  HTTP1_STATE_COMPLETE,   /**< Full message parsed successfully */
  HTTP1_STATE_ERROR       /**< Parse error occurred; check result code */
} SocketHTTP1_State;

/**
 * @brief Result codes from HTTP/1.1 parsing operations.
 */
typedef enum
{
  HTTP1_OK = 0,     /**< Complete message or chunk parsed */
  HTTP1_INCOMPLETE, /**< Need more data */
  HTTP1_CONTINUE,   /**< Internal: continue main parsing loop */
  HTTP1_ERROR,      /**< Generic error */

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
  HTTP1_ERROR_BODY_TOO_LARGE,
  HTTP1_ERROR_INVALID_TRAILER,
  HTTP1_ERROR_UNSUPPORTED_TRANSFER_CODING,
  HTTP1_ERROR_UNEXPECTED_EOF,
  HTTP1_ERROR_SMUGGLING_DETECTED /**< Request smuggling attempt (RFC 9112 Sec
                                    6.3) */
} SocketHTTP1_Result;

/**
 * @brief Body transfer modes for HTTP messages.
 *
 * Determined from HTTP headers (Content-Length, Transfer-Encoding).
 */
typedef enum
{
  HTTP1_BODY_NONE,           /**< No body expected */
  HTTP1_BODY_CONTENT_LENGTH, /**< Content-Length header specifies length */
  HTTP1_BODY_CHUNKED,        /**< Transfer-Encoding: chunked */
  HTTP1_BODY_UNTIL_CLOSE     /**< Body delimited by connection close */
} SocketHTTP1_BodyMode;

/**
 * @brief Runtime configuration structure for the HTTP/1.1 parser.
 *
 * Customizes security limits, syntax tolerance, and decompression behavior.
 */
typedef struct
{
  size_t max_request_line;       /**< Maximum request/status line length */
  size_t max_header_name;        /**< Maximum header name length */
  size_t max_header_value;       /**< Maximum header value length */
  size_t max_headers;            /**< Maximum header count */
  size_t max_header_size;        /**< Maximum total header size */
  size_t max_chunk_size;         /**< Maximum chunk size */
  size_t max_chunk_ext;          /**< Maximum chunk extension length */
  size_t max_trailer_size;       /**< Maximum trailer size */
  size_t max_header_line;        /**< Maximum individual header line length */
  size_t trailer_entry_overhead; /**< Per-entry overhead for trailer size
                                    accounting */
  int allow_obs_fold; /**< Allow obsolete header folding (default: 0) */
  int strict_mode;    /**< Reject ambiguous input (default: 1) */
  size_t max_decompressed_size; /**< Maximum decompressed body size
                                   (0=unlimited) */
} SocketHTTP1_Config;

/**
 * @brief HTTP/1.1 parser instance (opaque type)
 */
typedef struct SocketHTTP1_Parser *SocketHTTP1_Parser_T;

/**
 * @brief Initialize SocketHTTP1_Config structure with secure default values.
 *
 * Sets all configuration fields to compile-time constants and enables strict
 * parsing mode to prevent request smuggling and other attacks.
 *
 * @param[out] config Pointer to configuration structure to initialize
 * @threadsafe Yes
 */
extern void SocketHTTP1_config_defaults (SocketHTTP1_Config *config);

/**
 * @brief Create a new HTTP/1.1 parser instance.
 *
 * Initializes a DFA-based incremental parser with configurable limits.
 * All allocations use the provided arena for lifecycle management.
 *
 * @param[in] mode Parse mode: HTTP1_PARSE_REQUEST or HTTP1_PARSE_RESPONSE
 * @param[in] config Parser configuration, or NULL for defaults
 * @param[in] arena Arena for internal allocations
 * @return Opaque parser handle
 * @throws SocketHTTP1_ParseError If allocation fails or invalid config
 * @threadsafe Yes - each call creates independent instance
 *
 * @note Parser is NOT thread-safe; use one instance per connection/thread.
 */
extern SocketHTTP1_Parser_T
SocketHTTP1_Parser_new (SocketHTTP1_ParseMode mode,
                        const SocketHTTP1_Config *config,
                        Arena_T arena);

/**
 * @brief Dispose of HTTP/1.1 parser instance and release resources.
 *
 * Frees internal state allocated from arena. Sets *parser to NULL.
 * Safe to call on NULL (no-op).
 *
 * @param[in,out] parser Pointer to parser handle (set to NULL on success)
 * @threadsafe No
 */
extern void SocketHTTP1_Parser_free (SocketHTTP1_Parser_T *parser);

/**
 * @brief Reset parser for next message.
 *
 * @param parser Parser instance
 * @threadsafe No
 */
extern void SocketHTTP1_Parser_reset (SocketHTTP1_Parser_T parser);

/**
 * @brief Incrementally parse HTTP/1.1 message data using DFA state machine.
 *
 * Processes input buffer through a DFA for O(n) parsing efficiency.
 * Supports partial reads from non-blocking sockets. Enforces config limits
 * and rejects smuggling attempts (RFC 9112 Section 6.3).
 *
 * @param[in] parser Initialized parser instance
 * @param[in] data Raw input bytes from socket/network
 * @param[in] len Length of data buffer (may be partial message)
 * @param[out] consumed Number of bytes processed (always set, even on error)
 * @return HTTP1_OK (headers complete), HTTP1_INCOMPLETE (need more data), or
 * error
 * @threadsafe No
 */
extern SocketHTTP1_Result
SocketHTTP1_Parser_execute (SocketHTTP1_Parser_T parser,
                            const char *data,
                            size_t len,
                            size_t *consumed);

/**
 * @brief Get current parser state.
 *
 * @param parser Parser instance
 * @return Current high-level state
 * @threadsafe No
 */
extern SocketHTTP1_State SocketHTTP1_Parser_state (SocketHTTP1_Parser_T parser);

/**
 * @brief Get parsed request.
 *
 * @param parser Parser instance (must be in REQUEST mode)
 * @return Pointer to request structure, or NULL if not ready
 * @threadsafe No
 */
extern const SocketHTTP_Request *
SocketHTTP1_Parser_get_request (SocketHTTP1_Parser_T parser);

/**
 * @brief Get parsed response.
 *
 * @param parser Parser instance (must be in RESPONSE mode)
 * @return Pointer to response structure, or NULL if not ready
 * @threadsafe No
 */
extern const SocketHTTP_Response *
SocketHTTP1_Parser_get_response (SocketHTTP1_Parser_T parser);

/**
 * @brief Get body transfer mode.
 *
 * @param parser Parser instance
 * @return Body transfer mode
 * @threadsafe No
 */
extern SocketHTTP1_BodyMode
SocketHTTP1_Parser_body_mode (SocketHTTP1_Parser_T parser);

/**
 * @brief Get Content-Length value.
 *
 * @param parser Parser instance
 * @return Content-Length value, or -1 if not specified or chunked
 * @threadsafe No
 */
extern int64_t SocketHTTP1_Parser_content_length (SocketHTTP1_Parser_T parser);

/**
 * @brief Get remaining body bytes.
 *
 * @param parser Parser instance
 * @return Remaining bytes, or -1 if unknown (chunked/until-close)
 * @threadsafe No
 */
extern int64_t SocketHTTP1_Parser_body_remaining (SocketHTTP1_Parser_T parser);

/**
 * @brief Read body data.
 *
 * Handles chunked decoding transparently. For Content-Length bodies,
 * copies directly. For chunked, decodes and outputs raw data.
 *
 * @param parser Parser instance
 * @param input Input buffer (raw socket data)
 * @param input_len Input length
 * @param consumed Output - bytes consumed from input
 * @param output Output buffer for decoded body
 * @param output_len Output buffer size
 * @param written Output - bytes written to output
 * @return HTTP1_OK if complete, HTTP1_INCOMPLETE if more data needed, or error
 * @threadsafe No
 */
extern SocketHTTP1_Result
SocketHTTP1_Parser_read_body (SocketHTTP1_Parser_T parser,
                              const char *input,
                              size_t input_len,
                              size_t *consumed,
                              char *output,
                              size_t output_len,
                              size_t *written);

/**
 * @brief Check if body fully received.
 *
 * @param parser Parser instance
 * @return 1 if body complete, 0 otherwise
 * @threadsafe No
 */
extern int SocketHTTP1_Parser_body_complete (SocketHTTP1_Parser_T parser);

/**
 * @brief Get trailer headers (only valid for chunked encoding with trailers).
 *
 * @param parser Parser instance
 * @return Trailer headers, or NULL if none/not chunked
 * @threadsafe No
 */
extern SocketHTTP_Headers_T
SocketHTTP1_Parser_get_trailers (SocketHTTP1_Parser_T parser);

/**
 * @brief Check keep-alive status.
 *
 * Based on HTTP version and Connection header.
 *
 * @param parser Parser instance
 * @return 1 if connection should be kept alive, 0 otherwise
 * @threadsafe No
 */
extern int SocketHTTP1_Parser_should_keepalive (SocketHTTP1_Parser_T parser);

/**
 * @brief Check if upgrade requested.
 *
 * @param parser Parser instance
 * @return 1 if Upgrade header present and valid, 0 otherwise
 * @threadsafe No
 */
extern int SocketHTTP1_Parser_is_upgrade (SocketHTTP1_Parser_T parser);

/**
 * @brief Get requested upgrade protocol.
 *
 * @param parser Parser instance
 * @return Protocol name (e.g., "websocket", "h2c"), or NULL
 * @threadsafe No
 */
extern const char *
SocketHTTP1_Parser_upgrade_protocol (SocketHTTP1_Parser_T parser);

/**
 * @brief Check for Expect: 100-continue.
 *
 * @param parser Parser instance
 * @return 1 if client expects 100-continue, 0 otherwise
 * @threadsafe No
 */
extern int SocketHTTP1_Parser_expects_continue (SocketHTTP1_Parser_T parser);

/**
 * @brief Serialize HTTP request message (headers only) to wire format.
 *
 * Generates RFC 9112 compliant request line + headers, ending with double
 * CRLF. Validates input and adds missing Host from URI authority.
 * Does NOT serialize body.
 *
 * @param[in] request Valid SocketHTTP_Request structure
 * @param[out] output Pre-allocated buffer for serialized bytes
 * @param[in] output_size Size of output buffer
 * @return Number of bytes written, or -1 if buffer too small
 * @throws SocketHTTP1_SerializeError For invalid request fields
 * @threadsafe Yes
 */
extern ssize_t SocketHTTP1_serialize_request (const SocketHTTP_Request *request,
                                              char *output,
                                              size_t output_size);

/**
 * @brief Serialize response to buffer.
 *
 * Serializes status line and headers. Does NOT serialize body.
 *
 * @param response Response to serialize
 * @param output Output buffer
 * @param output_size Buffer size
 * @return Bytes written, or -1 on error (buffer too small)
 * @throws SocketHTTP1_SerializeError on invalid input
 * @threadsafe Yes
 */
extern ssize_t
SocketHTTP1_serialize_response (const SocketHTTP_Response *response,
                                char *output,
                                size_t output_size);

/**
 * @brief Serialize headers only.
 *
 * Each header formatted as "Name: Value\r\n". Does NOT add final CRLF.
 *
 * @param headers Headers to serialize
 * @param output Output buffer
 * @param output_size Buffer size
 * @return Bytes written, or -1 on error (buffer too small)
 * @throws SocketHTTP1_SerializeError on invalid headers
 * @threadsafe Yes
 */
extern ssize_t SocketHTTP1_serialize_headers (SocketHTTP_Headers_T headers,
                                              char *output,
                                              size_t output_size);

/**
 * @brief Encode data as single chunk.
 *
 * Output format: HEX_SIZE\r\nDATA\r\n
 *
 * @param data Input data
 * @param len Data length
 * @param output Output buffer
 * @param output_size Buffer size
 * @return Total bytes written, or -1 on error
 * @threadsafe Yes
 */
extern ssize_t SocketHTTP1_chunk_encode (const void *data,
                                         size_t len,
                                         char *output,
                                         size_t output_size);

/**
 * @brief Write final (zero-length) chunk.
 *
 * Output format: 0\r\n[trailers]\r\n
 *
 * @param output Output buffer
 * @param output_size Buffer size
 * @param trailers Optional trailer headers (NULL for none)
 * @return Bytes written, or -1 on error
 * @threadsafe Yes
 */
extern ssize_t SocketHTTP1_chunk_final (char *output,
                                        size_t output_size,
                                        SocketHTTP_Headers_T trailers);

/**
 * @brief Calculate encoded chunk size.
 *
 * @param data_len Data length to encode
 * @return Required buffer size for chunk (including headers and CRLF)
 * @threadsafe Yes
 */
extern size_t SocketHTTP1_chunk_encode_size (size_t data_len);

#if SOCKETHTTP1_HAS_COMPRESSION

/**
 * @brief HTTP/1.1 content decoder (opaque type)
 */
typedef struct SocketHTTP1_Decoder *SocketHTTP1_Decoder_T;

/**
 * @brief HTTP/1.1 content encoder (opaque type)
 */
typedef struct SocketHTTP1_Encoder *SocketHTTP1_Encoder_T;

/**
 * @brief Compression levels for content encoders.
 */
typedef enum
{
  HTTP1_COMPRESS_FAST = 1,    /**< Fastest compression */
  HTTP1_COMPRESS_DEFAULT = 6, /**< Balanced default */
  HTTP1_COMPRESS_BEST = 9     /**< Maximum compression */
} SocketHTTP1_CompressLevel;

/**
 * @brief Create content decoder.
 *
 * @param coding Content coding (GZIP, DEFLATE, BR)
 * @param cfg Configuration for limits (may be NULL for defaults)
 * @param arena Memory arena
 * @return Decoder instance, or NULL on error
 * @threadsafe Yes
 */
extern SocketHTTP1_Decoder_T
SocketHTTP1_Decoder_new (SocketHTTP_Coding coding,
                         const SocketHTTP1_Config *cfg,
                         Arena_T arena);

/**
 * @brief Free decoder.
 *
 * @param decoder Pointer to decoder
 */
extern void SocketHTTP1_Decoder_free (SocketHTTP1_Decoder_T *decoder);

/**
 * @brief Decode compressed data.
 *
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
                            const unsigned char *input,
                            size_t input_len,
                            size_t *consumed,
                            unsigned char *output,
                            size_t output_len,
                            size_t *written);

/**
 * @brief Finalize decoding.
 *
 * @param decoder Decoder instance
 * @param output Output buffer for remaining data
 * @param output_len Buffer size
 * @param written Output - bytes written
 */
extern SocketHTTP1_Result
SocketHTTP1_Decoder_finish (SocketHTTP1_Decoder_T decoder,
                            unsigned char *output,
                            size_t output_len,
                            size_t *written);

/**
 * @brief Create content encoder.
 *
 * @param coding Content coding (GZIP, DEFLATE, BR)
 * @param level Compression level
 * @param cfg Configuration for limits (may be NULL for defaults)
 * @param arena Memory arena
 */
extern SocketHTTP1_Encoder_T
SocketHTTP1_Encoder_new (SocketHTTP_Coding coding,
                         SocketHTTP1_CompressLevel level,
                         const SocketHTTP1_Config *cfg,
                         Arena_T arena);

/**
 * @brief Free encoder.
 *
 * @param encoder Encoder instance
 */
extern void SocketHTTP1_Encoder_free (SocketHTTP1_Encoder_T *encoder);

/**
 * @brief Encode data.
 *
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
                                           size_t output_len,
                                           int flush);

/**
 * @brief Finish encoding.
 *
 * @param encoder Encoder instance
 * @param output Output buffer
 * @param output_len Buffer size
 * @return Bytes written, or -1 on error
 */
extern ssize_t SocketHTTP1_Encoder_finish (SocketHTTP1_Encoder_T encoder,
                                           unsigned char *output,
                                           size_t output_len);

#endif /* SOCKETHTTP1_HAS_COMPRESSION */

/**
 * @brief Get human-readable error description.
 *
 * @param result Parse result code
 * @return Static string describing the result
 * @threadsafe Yes
 */
extern const char *SocketHTTP1_result_string (SocketHTTP1_Result result);

/** @} */

#endif /* SOCKETHTTP1_INCLUDED */
