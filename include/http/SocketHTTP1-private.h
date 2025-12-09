/**
 * @file SocketHTTP1-private.h
 * @brief Internal HTTP/1.1 parser structures and DFA state machine.
 * @ingroup http
 * @ingroup http1_private
 *
 * This header contains internal structures for the HTTP/1.1 parser
 * implementation. NOT for public consumption - use SocketHTTP1.h instead.
 *
 * Contains:
 * - Table-driven DFA character classification (following SocketUTF8 pattern)
 * - HTTP/1.1 state machine definitions and transition tables
 * - Parser internal structures and buffers
 * - Chunked encoding state machine
 * - Compression/decompression state (if enabled)
 *
 * The parser uses a deterministic finite automaton (DFA) for O(n) parsing
 * with single-pass validation and error detection.
 *
 * @see SocketHTTP1.h for public HTTP/1.1 API.
 * @see SocketUTF8.c for similar table-driven DFA pattern.
 * @see SocketHTTP-private.h for core HTTP internal structures.
 */

#ifndef SOCKETHTTP1_PRIVATE_INCLUDED
#define SOCKETHTTP1_PRIVATE_INCLUDED

#include <string.h>

#include "http/SocketHTTP-private.h"
#include "http/SocketHTTP1.h"

/**
 * @defgroup http1_private HTTP/1.1 Parser Internal Implementation
 * @ingroup http1
 * @internal
 *
 * Contains low-level DFA tables, token buffers, parser state machine, and
 * helpers for the HTTP/1.1 parser in SocketHTTP1.c. Enables efficient, secure
 * parsing of HTTP/1.1 messages with single-pass validation and limit
 * enforcement.
 *
 *  Core Components
 *
 * - **DFA Tables**: Char classification, state transitions, actions for O(n)
 * parsing
 * - **TokenBuf**: Resizable buffers for accumulating strings (methods, URIs,
 * etc.)
 * - **Parser Struct**: Manages state, buffers, headers, body tracking
 * - **Helpers**: Inline funcs for buffer management, validation macros
 *
 *  Architecture Diagram
 *
 * ```
 * Input Bytes --> Char Class [http1_char_class]
 *                --> State Transition [*_state tables]
 *                --> Execute Action [*_action tables]
 *                    --> Buffer Append [HTTP1_TokenBuf]
 *                    --> Field Complete --> Add to Headers/Request
 *                --> Error/Complete States
 * ```
 *
 * Thread Safety: Internal functions not thread-safe; use mutexes if shared.
 *
 * @note Opaque to public; changes don't affect SocketHTTP1.h API.
 * @see @ref http1 for public HTTP/1.1 module
 * @see SocketHTTP1_Parser_T for public opaque handle
 * @see docs/HTTP.md for HTTP module overview
 *
 * @{
 */

/* ============================================================================
 * Table-Driven DFA Character Classes
 * ============================================================================
 */

/**
 * Character classification for table-driven DFA
 * Following Hoehrmann pattern from SocketUTF8.c
 */
/**
 * @brief Character classes used in the table-driven DFA for HTTP/1.1 parsing.
 * @ingroup http
 * @ingroup http1_private
 * @internal
 *
 * These classes categorize every possible byte value (0-255) for fast lookup
 * in state transition tables. The classification determines valid transitions
 * and actions during parsing of request lines, status lines, headers, chunks,
 * etc.
 *
 * Key classes:
 * - Controls and whitespace for line endings and separators
 * - Specific chars like :, /, . for syntax elements
 * - Digits, hex, alpha for numbers and tokens
 * - Token chars (tchar) for methods, header names
 * - VCHAR and obs-text for values
 *
 * The http1_char_class[256] table maps bytes to these classes for O(1)
 * classification. Invalid classes trigger error actions.
 *
 *  Usage in DFA
 *
 * In SocketHTTP1_Parser_execute():
 * @code{.c}
 * HTTP1_CharClass cls = http1_char_class[(uint8_t)*p];
 * HTTP1_InternalState next = http1_req_state[state][cls];  // or resp
 * HTTP1_Action act = http1_req_action[state][cls];         // execute act
 * @endcode
 *
 * @see http1_char_class for the classification table
 * @see HTTP1_Action for actions triggered by classes
 * @see HTTP1_InternalState for DFA states
 * @see RFC 9112 Appendix B for ABNF grammar referenced in classes
 * @see SocketUTF8_CharClass for similar pattern in UTF-8 validation
 */
typedef enum
{
  HTTP1_CC_CTL = 0, /**< Control chars (0x00-0x1F except HTAB) - invalid */
  HTTP1_CC_SP,      /**< Space (0x20) */
  HTTP1_CC_HTAB,    /**< Horizontal tab (0x09) - OWS */
  HTTP1_CC_CR,      /**< Carriage return (0x0D) */
  HTTP1_CC_LF,      /**< Line feed (0x0A) */
  HTTP1_CC_COLON,   /**< Colon ':' - header separator */
  HTTP1_CC_SLASH,   /**< Slash '/' - version separator */
  HTTP1_CC_DOT,     /**< Dot '.' - version separator */
  HTTP1_CC_DIGIT,   /**< 0-9 */
  HTTP1_CC_HEX,     /**< a-f, A-F (hex only, not digit) */
  HTTP1_CC_ALPHA,   /**< A-Za-z (not H, T, P) */
  HTTP1_CC_H,       /**< 'H' - HTTP version start */
  HTTP1_CC_T,       /**< 'T' - HTTP version */
  HTTP1_CC_P,       /**< 'P' - HTTP version */
  HTTP1_CC_TCHAR,   /**< Other token chars: !#$%&'*+-.^_`|~ */
  HTTP1_CC_VCHAR,   /**< Other visible chars (0x21-0x7E not above) */
  HTTP1_CC_OBS,     /**< obs-text (0x80-0xFF) */
  HTTP1_CC_INVALID, /**< Invalid (NUL, DEL, etc.) */
  HTTP1_NUM_CLASSES /**< Number of character classes */
} HTTP1_CharClass;

/**
 * Actions to execute on state transitions
 */
/**
 * @brief Actions executed during DFA state transitions in HTTP/1.1 parser.
 * @ingroup http
 * @ingroup http1_private
 * @internal
 *
 * Side effects triggered by specific character class matches in state tables.
 * Enables efficient single-pass parsing with minimal conditional branching.
 * Actions handle token buffering, field completion, header addition, and
 * errors.
 *
 * Actions are indexed via http1_*_action[state][char_class] tables and
 * executed in the main parsing loop. Most actions update internal buffers or
 * flags.
 *
 *  Action Categories
 *
 * - **Storage Actions**: Append bytes to token buffers (method, URI, etc.)
 * - **Completion Actions**: Finalize tokens, add headers, complete lines
 * - **Digit Actions**: Accumulate numeric values (version, status, chunk size)
 * - **Control Actions**: None for transitions, Error for invalid input
 *
 * @see http1_req_action, http1_resp_action for action lookup tables
 * @see HTTP1_CharClass for input classifications triggering actions
 * @see HTTP1_InternalState for parser states where actions occur
 * @see SocketHTTP1_Parser_execute() for action execution in parsing loop
 * @see HTTP1_TokenBuf for buffering mechanism used by store actions
 */
typedef enum
{
  HTTP1_ACT_NONE = 0,     /**< Just transition, no side effect */
  HTTP1_ACT_STORE_METHOD, /**< Store byte in method buffer */
  HTTP1_ACT_STORE_URI,    /**< Store byte in URI buffer */
  HTTP1_ACT_STORE_REASON, /**< Store byte in reason buffer */
  HTTP1_ACT_STORE_NAME,   /**< Store byte in header name buffer */
  HTTP1_ACT_STORE_VALUE,  /**< Store byte in header value buffer */
  HTTP1_ACT_METHOD_END,   /**< Complete method token */
  HTTP1_ACT_URI_END,      /**< Complete URI */
  HTTP1_ACT_VERSION_MAJ,  /**< Store major version digit */
  HTTP1_ACT_VERSION_MIN,  /**< Store minor version digit */
  HTTP1_ACT_STATUS_DIGIT, /**< Store status code digit */
  HTTP1_ACT_REASON_END,   /**< Complete reason phrase */
  HTTP1_ACT_HEADER_END,   /**< Complete current header */
  HTTP1_ACT_HEADERS_DONE, /**< All headers complete */
  HTTP1_ACT_ERROR         /**< Transition to error state */
} HTTP1_Action;

/* ============================================================================
 * Internal Parser State Machine
 * ============================================================================
 */

/**
 * @brief Low-level internal parser states for the DFA-based HTTP/1.1 parser.
 * @ingroup http
 * @internal

 * These states drive the table-driven deterministic finite automaton (DFA) for
 * efficient, single-pass parsing of HTTP/1.1 messages including
 request/response
 * lines, headers, chunked bodies, and trailers.

 * Parsing flows:
 * - Request: HTTP1_PS_START → HTTP1_PS_METHOD → HTTP1_PS_SP_AFTER_METHOD →
 *   HTTP1_PS_URI → HTTP1_PS_SP_AFTER_URI → version states → HTTP1_PS_LINE_CR →
 HTTP1_PS_LINE_LF
 * - Response: HTTP1_PS_START → version states → HTTP1_PS_STATUS_CODE →
 *   HTTP1_PS_SP_AFTER_STATUS → HTTP1_PS_REASON → HTTP1_PS_LINE_CR →
 HTTP1_PS_LINE_LF
 * - Headers loop: HTTP1_PS_HEADER_START → HTTP1_PS_HEADER_NAME →
 HTTP1_PS_HEADER_COLON →
 *   HTTP1_PS_HEADER_VALUE → HTTP1_PS_HEADER_CR → HTTP1_PS_HEADER_LF (repeat
 until HTTP1_PS_HEADERS_END_LF)
 * - Chunked body: HTTP1_PS_CHUNK_SIZE states → HTTP1_PS_CHUNK_DATA →
 HTTP1_PS_CHUNK_DATA_CR → HTTP1_PS_CHUNK_DATA_LF
 * - Trailers: Similar to headers after final chunk.

 * Individual state descriptions provided in enum values.

 * @see http1_char_class for character classification used in transitions.
 * @see http1_req_state, http1_resp_state for state transition tables.
 * @see http1_req_action, http1_resp_action for actions triggered by
 transitions.
 * @see RFC 7230 sections 3 (message format) and 4 (request/response) for
 grammar.
 * @see SocketHTTP1_Parser_execute() for how states are advanced.
 * @see SocketHTTP1.h for public parser interface.
 * @see @ref http1 "HTTP/1.1 Module" for group documentation.
 */
typedef enum
{
  /* Initial state */
  HTTP1_PS_START = 0,

  /* Request line states */
  HTTP1_PS_METHOD,          /* Parsing method token */
  HTTP1_PS_SP_AFTER_METHOD, /* Single space after method */
  HTTP1_PS_URI,             /* Parsing request target */
  HTTP1_PS_SP_AFTER_URI,    /* Single space after URI */

  /* Status line states (response only) */
  HTTP1_PS_STATUS_CODE,     /* 3 digits */
  HTTP1_PS_SP_AFTER_STATUS, /* Space after status */
  HTTP1_PS_REASON,          /* Reason phrase (optional) */

  /* Version states (shared) */
  HTTP1_PS_VERSION_H,     /* Expecting 'H' */
  HTTP1_PS_VERSION_T1,    /* Expecting first 'T' */
  HTTP1_PS_VERSION_T2,    /* Expecting second 'T' */
  HTTP1_PS_VERSION_P,     /* Expecting 'P' */
  HTTP1_PS_VERSION_SLASH, /* Expecting '/' */
  HTTP1_PS_VERSION_MAJOR, /* Major version digit */
  HTTP1_PS_VERSION_DOT,   /* Expecting '.' */
  HTTP1_PS_VERSION_MINOR, /* Minor version digit */

  /* Line ending states */
  HTTP1_PS_LINE_CR, /* Expecting CR after request/status line */
  HTTP1_PS_LINE_LF, /* Expecting LF after CR */

  /* Header states */
  HTTP1_PS_HEADER_START,     /* Start of header or empty line */
  HTTP1_PS_HEADER_NAME,      /* Parsing header name */
  HTTP1_PS_HEADER_COLON,     /* After colon, skip OWS */
  HTTP1_PS_HEADER_VALUE,     /* Parsing header value */
  HTTP1_PS_HEADER_VALUE_OWS, /* Trailing OWS in value */
  HTTP1_PS_HEADER_CR,        /* CR after header value */
  HTTP1_PS_HEADER_LF,        /* LF after header CR */
  HTTP1_PS_HEADERS_END_LF,   /* Final LF (empty line) */

  /* Body states */
  HTTP1_PS_BODY_IDENTITY,    /* Reading fixed-length body */
  HTTP1_PS_BODY_UNTIL_CLOSE, /* Reading until EOF */

  /* Chunked encoding states */
  HTTP1_PS_CHUNK_SIZE,     /* Hex digits */
  HTTP1_PS_CHUNK_SIZE_EXT, /* Chunk extension (skip) */
  HTTP1_PS_CHUNK_SIZE_CR,  /* CR after size */
  HTTP1_PS_CHUNK_SIZE_LF,  /* LF after CR */
  HTTP1_PS_CHUNK_DATA,     /* Reading chunk data */
  HTTP1_PS_CHUNK_DATA_CR,  /* CR after chunk data */
  HTTP1_PS_CHUNK_DATA_LF,  /* LF after chunk CR */

  /* Trailer states (reuse header logic) */
  HTTP1_PS_TRAILER_START,
  HTTP1_PS_TRAILER_NAME,
  HTTP1_PS_TRAILER_COLON,
  HTTP1_PS_TRAILER_VALUE,
  HTTP1_PS_TRAILER_CR,
  HTTP1_PS_TRAILER_LF,
  HTTP1_PS_TRAILERS_END_LF,

  /* Terminal states */
  HTTP1_PS_COMPLETE, /* Message complete */
  HTTP1_PS_ERROR,    /* Parse error */

  HTTP1_NUM_STATES /* Number of states */
} HTTP1_InternalState;

/* ============================================================================
 * DFA Tables (defined in SocketHTTP1-parser.c)
 * ============================================================================
 */

/**
 * @brief Precomputed character classification table for HTTP/1.1 DFA.
 * @ingroup http
 * @ingroup http1_private
 * @internal
 *
 * Lookup table mapping every possible byte (0-255) to its HTTP1_CharClass.
 * Enables O(1) classification during parsing without runtime conditionals.
 * Size: exactly 256 bytes (uint8_t array).
 *
 * Usage:
 * @code{.c}
 * uint8_t cls = http1_char_class[(uint8_t)byte];  // Classify input byte
 * uint8_t next_state = http1_req_state[state][cls];  // Transition
 * @endcode
 *
 * Table generated at compile-time based on RFC 9112 ABNF rules and legacy
 * obs-text. Covers controls, whitespace, separators, digits, tokens, VCHAR,
 * obs-text.
 *
 * @note Accessed frequently in hot parsing loop; kept in data segment for
 * speed.
 * @complexity O(1) lookup
 *
 * @see HTTP1_CharClass for enumerated classes
 * @see http1_req_state, http1_resp_state for using classes in transitions
 * @see SocketHTTP1_Parser_execute() for runtime usage
 */
extern const uint8_t http1_char_class[256];

/**
 * @brief DFA state transition table for HTTP request parsing.
 * @ingroup http
 * @ingroup http1_private
 * @internal
 *
 * 2D table defining next state for each current state and input char class.
 * Size: HTTP1_NUM_STATES * HTTP1_NUM_CLASSES bytes (~300 bytes).
 * Drives deterministic parsing of request lines, headers, body directives.
 *
 * Transitions enforce HTTP/1.1 syntax: method SP request-target SP version
 * CRLF headers, chunked encoding, etc. Invalid transitions lead to error
 * state.
 *
 * Usage in parser loop:
 * @code{.c}
 * HTTP1_CharClass cls = http1_char_class[(uint8_t)*p];
 * state = http1_req_state[state][cls];
 * if (state == HTTP1_PS_ERROR) { // handle error }
 * @endcode
 *
 * @note Compile-time constant; optimized for cache locality in inner loop.
 * @complexity O(1) per byte parsed
 *
 * @see http1_resp_state for response variant
 * @see HTTP1_InternalState for states
 * @see HTTP1_CharClass for classes
 * @see http1_req_action for concurrent actions
 */
extern const uint8_t http1_req_state[HTTP1_NUM_STATES][HTTP1_NUM_CLASSES];

/**
 * @brief DFA state transition table for HTTP response parsing.
 * @ingroup http
 * @ingroup http1_private
 * @internal
 *
 * Companion to req_state table, specialized for response messages.
 * Handles status line: version SP status-code SP reason-phrase CRLF
 * then headers, body, etc. Shares states but differs in start transitions.
 *
 * Size and usage identical to request table.
 *
 * @code{.c}
 * // In response-mode parser
 * state = http1_resp_state[state][cls];
 * @endcode
 *
 * @see http1_req_state for request variant
 * @see http1_resp_action for actions in response context
 */
extern const uint8_t http1_resp_state[HTTP1_NUM_STATES][HTTP1_NUM_CLASSES];

/**
 * @brief DFA action table for HTTP request parsing.
 * @ingroup http
 * @ingroup http1_private
 * @internal
 *
 * 2D table specifying actions to execute alongside state transitions for
 * requests. Paired with http1_req_state table; looked up simultaneously for
 * each input byte.
 *
 * Actions include buffering tokens (method, URI), completing fields, adding
 * headers, and error handling. Enables complete parsing in single loop pass.
 *
 * @code{.c}
 * HTTP1_Action act = http1_req_action[state][cls];
 * switch (act) {
 *   case HTTP1_ACT_STORE_METHOD: http1_tokenbuf_append(&method_buf, byte);
 * break;
 *   // ... other cases
 * }
 * @endcode
 *
 * @see http1_resp_action for response actions
 * @see HTTP1_Action for enumerated actions
 * @see http1_req_state for concurrent state transitions
 */
extern const uint8_t http1_req_action[HTTP1_NUM_STATES][HTTP1_NUM_CLASSES];

/**
 * @brief DFA action table for HTTP response parsing.
 * @ingroup http
 * @ingroup http1_private
 * @internal
 *
 * Similar to req_action but tailored for response message syntax.
 * Handles status code digits, reason phrase buffering, etc.
 * Used in response-mode parsers (SocketHTTP1_ParseMode::HTTP1_PARSE_RESPONSE).
 *
 * Shares action enum with request table but different triggers per state.
 *
 * @see http1_req_action for request variant
 * @see HTTP1_Action for action details
 * @see http1_resp_state for state transitions
 */
extern const uint8_t http1_resp_action[HTTP1_NUM_STATES][HTTP1_NUM_CLASSES];

/* ============================================================================
 * Token Accumulator
 * ============================================================================
 */

/**
 * @brief Dynamic resizable buffer for accumulating parsed HTTP tokens.
 * @ingroup http
 * @internal

 * Used to build method names, URIs, header names/values, reason phrases during
 * incremental parsing. Allocations from provided Arena_T; grows by doubling
 * capacity as needed up to configured limits.

 * Fields:
 * - data: Pointer to the allocated buffer data (null-terminated after
 terminate()).
 * - len: Current length of data stored (excluding null terminator).
 * - capacity: Current allocated size of the data buffer.

 * @see http1_tokenbuf_init() to allocate and initialize.
 * @see http1_tokenbuf_append() to add characters with growth.
 * @see http1_tokenbuf_reset() to clear without deallocation.
 * @see http1_tokenbuf_terminate() to null-terminate for string use.
 * @see Arena_T for underlying memory management and Arena_alloc() for growth.
 * @see SocketHTTP1_Config for max sizes enforced during append/terminate.
 */
typedef struct
{
  char *data;      /**< Buffer data */
  size_t len;      /**< Current length */
  size_t capacity; /**< Buffer capacity */
} HTTP1_TokenBuf;

/* ============================================================================
 * Parser Structure
 * ============================================================================
 */

/**
 * @brief Internal implementation structure for the HTTP/1.1 parser
 (SocketHTTP1_Parser_T).
 * @ingroup http
 * @internal

 * Manages all aspects of incremental HTTP/1.1 message parsing: configuration,
 * DFA state machine, message construction (request/response), header/trailer
 * accumulation, token buffering, body handling (content-length, chunked,
 until-close),
 * limits enforcement, and connection flags.

 * Memory: All dynamic allocations (buffers, headers) from the 'arena' member.
 * Parsing: Advances via internal_state using DFA tables; high-level state
 tracks progress.
 * Limits: Counters prevent DoS (e.g., too many headers, oversized lines).
 * Body: Supports transfer-encoding: chunked (with trailers) or content-length.
 * Flags: Determines keep-alive, upgrades (e.g., WebSocket), 100-continue
 expectations.

 * Field groups:
 * - Configuration: mode, config, arena
 * - Parser state: state, error, internal_state
 * - Current message: message union (request or response)
 * - Headers/Trailers: headers (main), trailers (chunked end)
 * - Token buffers: method_buf, uri_buf, reason_buf, name_buf, value_buf
 * - Counters: header_count, total_header_size, line_length, etc. (and
 trailers)
 * - Body state: body_mode, content_length, body_remaining, body_complete
 * - Chunked state: chunk_size, chunk_remaining
 * - Parsed values: version_major/minor, status_code
 * - Flags: keepalive, is_upgrade, upgrade_protocol, expects_continue

 * @note Not thread-safe; single-threaded use only.
 * @note User must not access fields directly; use public API getters.
 * @see SocketHTTP1_Parser_new() for creation with config.
 * @see SocketHTTP1_Parser_execute() for feeding data and advancing state.
 * @see SocketHTTP1_Parser_get_request(), SocketHTTP1_Parser_get_response() for
 results.
 * @see SocketHTTP_Request, SocketHTTP_Response for message details.
 * @see SocketHTTP_Headers_T for header handling.
 * @see HTTP1_TokenBuf for token accumulation.
 * @see HTTP1_InternalState for DFA states.
 * @see SocketHTTP1_Config for configurable limits and behavior.
 * @see RFC 7230 for HTTP/1.1 specification compliance details.
 */
struct SocketHTTP1_Parser
{
  /* Configuration */
  SocketHTTP1_ParseMode mode;
  SocketHTTP1_Config config;
  Arena_T arena;

  /* High-level state */
  SocketHTTP1_State state;
  SocketHTTP1_Result error;

  /* Low-level DFA state */
  HTTP1_InternalState internal_state;

  /* Request/response data */
  union
  {
    SocketHTTP_Request request;
    SocketHTTP_Response response;
  } message;

  /* Headers being built */
  SocketHTTP_Headers_T headers;
  SocketHTTP_Headers_T trailers;

  /* Token accumulators */
  HTTP1_TokenBuf method_buf; /* Method token */
  HTTP1_TokenBuf uri_buf;    /* Request target */
  HTTP1_TokenBuf reason_buf; /* Reason phrase */
  HTTP1_TokenBuf name_buf;   /* Current header name */
  HTTP1_TokenBuf value_buf;  /* Current header value */

  /* Parsing counters */
  size_t header_count;       /* Number of headers parsed */
  size_t total_header_size;  /* Total header bytes */
  size_t line_length;        /* Current line length */
  size_t header_line_length; /* Current header line length */

  /* Trailer parsing counters */
  size_t trailer_count;      /* Number of trailer headers parsed */
  size_t total_trailer_size; /* Total trailer bytes parsed */

  /* Body handling */
  SocketHTTP1_BodyMode body_mode;
  int64_t content_length; /* From header, or -1 */
  int64_t body_remaining; /* Bytes remaining */
  int body_complete;      /* Body fully received */

  /* Chunked encoding */
  size_t chunk_size;      /* Current chunk size */
  size_t chunk_remaining; /* Bytes remaining in chunk */

  /* Version parsing */
  int version_major;
  int version_minor;

  /* Status code parsing */
  int status_code;

  /* Connection flags */
  int keepalive;  /* Keep-alive determined */
  int is_upgrade; /* Upgrade requested */
  const char *upgrade_protocol;

  /* 100-continue */
  int expects_continue;
};

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================
 */

/**
 * @brief Initialize HTTP1_TokenBuf, allocating initial buffer from arena.
 * @ingroup http
 * @internal
 * @param buf Pointer to HTTP1_TokenBuf structure to initialize (overwritten).
 * @param arena Arena_T from which to allocate buf->data.
 * @param initial_capacity Initial size (in bytes) for the data buffer.
 * @return 0 on success (buf ready for use), -1 on allocation failure.
 * @note Sets buf->len = 0, buf->capacity = initial_capacity.
 * @note Does not zero the buffer contents; undefined until first append.
 * @throws Arena_Failed if Arena_alloc() fails (via exception handling).
 * @see Arena_alloc() invoked internally with file/line tracking.
 * @see HTTP1_TokenBuf for structure fields.
 * @see http1_tokenbuf_reset() if needing to clear after init (though len=0).
 * @see http1_tokenbuf_append() for first data addition.
 */
static inline int
http1_tokenbuf_init (HTTP1_TokenBuf *buf, Arena_T arena,
                     size_t initial_capacity)
{
  buf->data = Arena_alloc (arena, initial_capacity, __FILE__, __LINE__);
  if (!buf->data)
    return -1;
  buf->len = 0;
  buf->capacity = initial_capacity;
  return 0;
}

/**
 * @brief Reset token buffer to empty (len=0) without deallocating memory or
 * changing capacity.
 * @ingroup http
 * @internal
 * @param buf Pointer to initialized HTTP1_TokenBuf to reset.
 * @note data and capacity unchanged; safe to call repeatedly for reuse.
 * @note Previous data remains in buffer until overwritten; use secureclear if
 * sensitive.
 * @see http1_tokenbuf_init() for initial setup.
 * @see http1_tokenbuf_append() to start adding new data after reset.
 * @see HTTP1_TokenBuf::len for the reset field.
 */
static inline void
http1_tokenbuf_reset (HTTP1_TokenBuf *buf)
{
  buf->len = 0;
}

/**
 * @brief Append a single character to the token buffer, growing capacity if
 * necessary.
 * @ingroup http
 * @internal
 * @param buf The HTTP1_TokenBuf to append to (must be initialized).
 * @param arena Arena_T for reallocating larger buffer if full.
 * @param c The character (char) to append to buf->data[buf->len++].
 * @param max_size Absolute maximum len allowed (enforced before append and
 * growth).
 * @return 0 on success (char appended, len increased), -1 if len would exceed
 * max_size or Arena_alloc fails.
 * @note If buf->len == buf->capacity, doubles capacity (capped at max_size)
 * and copies data.
 * @note Does not null-terminate; call http1_tokenbuf_terminate() after
 * completion.
 * @throws Arena_Failed via Arena_alloc() during growth.
 * @see Arena_alloc() for reallocation details.
 * @see http1_tokenbuf_terminate() to finalize string.
 * @see SocketHTTP1_Config for parser-wide size limits (this is per-call cap).
 */
static inline int
http1_tokenbuf_append (HTTP1_TokenBuf *buf, Arena_T arena, char c,
                       size_t max_size)
{
  if (buf->len >= max_size)
    return -1;

  if (buf->len >= buf->capacity)
    {
      /* Double capacity */
      size_t new_capacity = buf->capacity * 2;
      if (new_capacity > max_size)
        new_capacity = max_size;

      char *new_data = Arena_alloc (arena, new_capacity, __FILE__, __LINE__);
      if (!new_data)
        return -1;

      memcpy (new_data, buf->data, buf->len);
      buf->data = new_data;
      buf->capacity = new_capacity;
    }

  buf->data[buf->len++] = c;
  return 0;
}

/**
 * @brief Null-terminate the token buffer and return pointer to the string.
 * @ingroup http
 * @internal
 * @param buf The HTTP1_TokenBuf to terminate (adds '\0' at buf->len).
 * @param arena Arena_T for possible reallocation if no space for null
 * terminator.
 * @param max_size Maximum allowed len INCLUDING the null terminator (buf->len
 * + 1 <= max_size).
 * @return Pointer to buf->data (now null-terminated string) on success, NULL
 * if reallocation fails or too large.
 * @note If buf->len < buf->capacity, simply sets data[len] = '\0' without
 * realloc.
 * @note If realloc needed, allocates buf->len + 1, copies data, updates
 * buf->data/capacity; old data invalid.
 * @note Returned pointer valid until next append/reset/growth; do not free.
 * @throws Arena_Failed via Arena_alloc() if growth required and fails.
 * @see Arena_alloc() for reallocation.
 * @see http1_tokenbuf_append() which may invalidate previous terminate result.
 * @see SocketHTTP1_Config for overall size limits.
 */
static inline char *
http1_tokenbuf_terminate (HTTP1_TokenBuf *buf, Arena_T arena, size_t max_size)
{
  if (buf->len >= buf->capacity)
    {
      /* Need space for null terminator */
      size_t new_capacity = buf->len + 1;
      if (new_capacity > max_size + 1)
        return NULL;

      char *new_data = Arena_alloc (arena, new_capacity, __FILE__, __LINE__);
      if (!new_data)
        return NULL;

      memcpy (new_data, buf->data, buf->len);
      buf->data = new_data;
      buf->capacity = new_capacity;
    }

  buf->data[buf->len] = '\0';
  return buf->data;
}

/* ============================================================================
 * Validation Helpers (using Phase 3 tables)
 * ============================================================================
 */

/**
 * @brief Determine if a byte is a valid HTTP token character (tchar).
 * @ingroup http
 * @internal
 * @param c The input byte/character to classify (treated as unsigned char).
 * @return Non-zero (true) if c is a valid tchar per HTTP/1.1 token rules, 0
 * (false) otherwise.
 *
 * Token chars (tchar): !#$%&'*+-.^_`|~ and ALPHA/DIGIT, excluding separators.
 * Optimized via precomputed table lookup from core HTTP module.
 * Used in DFA for header names, methods, etc.
 * @see SocketHTTP-private.h for SOCKETHTTP_IS_TCHAR and tchar_table
 * definition.
 * @see RFC 7230 section 3.2.6 "token" production.
 * @see http1_char_class[HTTP1_CC_TCHAR] related DFA class.
 */
#define http1_is_tchar(c) SOCKETHTTP_IS_TCHAR (c)

/**
 * @brief Check if a character is an ASCII decimal digit (0-9).
 * @ingroup http
 * @internal
 * @param c Character to test.
 * @return 1 (true) if '0' <= c <= '9', 0 (false) otherwise.
 * @note Simple range check; used in version parsing, status codes, chunk
 * sizes.
 * @see http1_is_hex() for hexadecimal digit check.
 * @see http1_char_class[HTTP1_CC_DIGIT] in DFA classification.
 */
#define http1_is_digit(c) ((c) >= '0' && (c) <= '9')

/**
 * @brief Test if a character is a valid hexadecimal digit (0-9, a-f, A-F).
 * @ingroup http
 * @internal
 * @param c Character to test.
 * @return 1 (true) if valid hex digit, 0 (false) otherwise.
 * @note Used primarily for chunk-size parsing in transfer-encoding: chunked.
 * @see http1_hex_value() to convert valid hex to numeric 0-15.
 * @see http1_char_class[HTTP1_CC_HEX] for DFA usage (hex letters only,
 * excluding digits).
 */
#define http1_is_hex(c)                                                       \
  (((c) >= '0' && (c) <= '9') || ((c) >= 'a' && (c) <= 'f')                   \
   || ((c) >= 'A' && (c) <= 'F'))

/**
 * @brief Convert a hexadecimal digit character to its integer value (0-15).
 * @ingroup http
 * @internal
 * @param c Valid hex digit char ('0'-'9', 'a'-'f', 'A'-'F').
 * @return Integer value 0-15 corresponding to the hex digit; behavior
 * undefined for invalid input.
 * @warning Caller must validate with http1_is_hex(c) before calling to avoid
 * garbage.
 * @note Delegates to core HTTP module's macro for table lookup or computation.
 * @see http1_is_hex() for validation prior to conversion.
 * @see SocketHTTP-private.h SOCKETHTTP_HEX_VALUE for implementation.
 * @see Chunk size parsing in HTTP1_PS_CHUNK_SIZE state.
 */
#define http1_hex_value(c) SOCKETHTTP_HEX_VALUE (c)

/**
 * @brief Check if character is optional whitespace (OWS: SP or HTAB).
 * @ingroup http
 * @internal
 * @param c Character to test.
 * @return 1 (true) if c == ' ' (SP, 0x20) or c == '\t' (HTAB, 0x09), 0
 * otherwise.
 * @note OWS = *( SP / HTAB ) per RFC 7230; used after colon in headers, around
 * values.
 * @see RFC 7230 section 3.2.3 "optional whitespace" (OWS).
 * @see http1_char_class[HTTP1_CC_SP, HTTP1_CC_HTAB] for DFA classes.
 */
#define http1_is_ows(c) ((c) == ' ' || (c) == '\t')

/**
 * @brief Check if byte is a visible (non-control) US-ASCII character (VCHAR).
 * @ingroup http
 * @internal
 * @param c Byte/character to test (cast to unsigned char internally).
 * @return 1 (true) if 0x21 <= c <= 0x7E (printable ASCII excluding controls),
 * 0 otherwise.
 * @note VCHAR from RFC 5234 ABNF: visible US-ASCII excluding NUL, controls,
 * DEL.
 * @note Used in header field values, reason phrases; excludes SP (separate
 * class).
 * @see http1_is_field_vchar() which adds obs-text for header values.
 * @see RFC 7230 section 3.2.4 field-value allows VCHAR / SP / HTAB / obs-text.
 */
#define http1_is_vchar(c)                                                     \
  ((unsigned char)(c) >= 0x21 && (unsigned char)(c) <= 0x7E)

/**
 * @brief Check if byte is obsolete text (high octet characters 0x80-0xFF).
 * @ingroup http
 * @internal
 * @param c Byte/character to test (unsigned char).
 * @return 1 (true) if c >= 0x80 (allows legacy non-ASCII in headers), 0
 * otherwise.
 * @note obs-text from RFC 7230: allows HTTP/1.0 legacy high bytes in field
 * values.
 * @note Lenient for interoperability; strict mode may reject.
 * @see http1_is_field_vchar() = VCHAR / SP / HTAB / obs-text for header
 * values.
 * @see RFC 7230 section 3.2.6 errata for obs-text allowance.
 */
#define http1_is_obs_text(c) ((unsigned char)(c) >= 0x80)

/**
 * @brief Check if character is valid in HTTP header field values
 * (field-vchar).
 * @ingroup http
 * @internal
 * @param c Character/byte to test.
 * @return 1 (true) if valid field-vchar (VCHAR or obs-text), 0 otherwise.
 * @note field-vchar = VCHAR / obs-text (RFC 7230); excludes whitespace
 * (separate).
 * @note Used in DFA for HTTP1_PS_HEADER_VALUE state to validate value chars.
 * @note Full field-value = *( field-content / obs-fold ); field-content =
 * field-vchar [ 1*( SP / HTAB ) field-vchar ]
 * @see http1_is_vchar() for VCHAR (0x21-0x7E).
 * @see http1_is_obs_text() for obs-text (0x80+).
 * @see RFC 7230 section 3.2.4 "header fields" for field-value grammar.
 */
#define http1_is_field_vchar(c) (http1_is_vchar (c) || http1_is_obs_text (c))

/**
 * @brief Default initial capacities for HTTP/1.1 token buffers used in
 * parsing.
 * @ingroup http
 * @internal
 *
 * Chosen to balance memory efficiency and common case performance:
 * - Small for fixed-size tokens (methods, names)
 * - Larger for variable (URIs, values)
 * Buffers start at these sizes in http1_tokenbuf_init() and grow dynamically.
 * Enforced against SocketHTTP1_Config limits during growth.
 *
 * @see HTTP1_TokenBuf for buffer management.
 * @see http1_tokenbuf_init() where these are passed as initial_capacity.
 * @see SocketHTTP1_Config::max_method_size, max_uri_size, etc. for runtime
 * limits.
 */

/**
 * @brief Default initial capacity for method token buffer (e.g., "GET",
 * "POST").
 */
#define HTTP1_DEFAULT_METHOD_BUF_SIZE 16

/**
 * @brief Default initial capacity for request-target/URI buffer.
 */
#define HTTP1_DEFAULT_URI_BUF_SIZE 256

/**
 * @brief Default initial capacity for HTTP status reason-phrase buffer.
 */
#define HTTP1_DEFAULT_REASON_BUF_SIZE 64

/**
 * @brief Default initial capacity for HTTP header name buffer.
 */
#define HTTP1_DEFAULT_HEADER_NAME_BUF_SIZE 64

/**
 * @brief Default initial capacity for HTTP header value buffer.
 */
#define HTTP1_DEFAULT_HEADER_VALUE_BUF_SIZE 256

/** @} */ /* http1_private */

#endif /* SOCKETHTTP1_PRIVATE_INCLUDED */
