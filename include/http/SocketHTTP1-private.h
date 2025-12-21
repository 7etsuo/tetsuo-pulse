/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTP1-private.h
 * @brief Internal HTTP/1.1 parser structures and DFA state machine.
 * @internal
 */

#ifndef SOCKETHTTP1_PRIVATE_INCLUDED
#define SOCKETHTTP1_PRIVATE_INCLUDED

#include <string.h>

#include "http/SocketHTTP-private.h"
#include "http/SocketHTTP1.h"

#define HTTP1_CRLF_STR "\r\n"
#define HTTP1_CRLF_LEN 2
#define HTTP1_SP_STR " "
#define HTTP1_SP_LEN 1
#define HTTP1_HEADER_SEP_STR ": "
#define HTTP1_HEADER_SEP_LEN 2
#define HTTP1_HEX_RADIX 16

/* Character classification for table-driven DFA (following SocketUTF8 pattern) */
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

  HTTP1_NUM_STATES
} HTTP1_InternalState;

extern const uint8_t http1_char_class[256];
extern const uint8_t http1_req_state[HTTP1_NUM_STATES][HTTP1_NUM_CLASSES];
extern const uint8_t http1_resp_state[HTTP1_NUM_STATES][HTTP1_NUM_CLASSES];
extern const uint8_t http1_req_action[HTTP1_NUM_STATES][HTTP1_NUM_CLASSES];
extern const uint8_t http1_resp_action[HTTP1_NUM_STATES][HTTP1_NUM_CLASSES];
typedef struct
{
  char *data;
  size_t len;
  size_t capacity;
} HTTP1_TokenBuf;
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
  uint64_t body_read;       /**< Total body bytes processed */

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

/* Reset token buffer to empty */
static inline void
http1_tokenbuf_reset (HTTP1_TokenBuf *buf)
{
  buf->len = 0;
}

/* Append character to buffer, growing if needed */
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

      memmove (new_data, buf->data, buf->len);
      buf->data = new_data;
      buf->capacity = new_capacity;
    }

  buf->data[buf->len++] = c;
  return 0;
}

/* Null-terminate buffer and return string pointer */
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

      memmove (new_data, buf->data, buf->len);
      buf->data = new_data;
      buf->capacity = new_capacity;
    }

  buf->data[buf->len] = '\0';
  return buf->data;
}

#define http1_is_tchar(c) SOCKETHTTP_IS_TCHAR (c)
#define http1_is_digit(c) ((c) >= '0' && (c) <= '9')
#define http1_is_hex(c)                                                       \
  (((c) >= '0' && (c) <= '9') || ((c) >= 'a' && (c) <= 'f')                   \
   || ((c) >= 'A' && (c) <= 'F'))
#define http1_hex_value(c) SOCKETHTTP_HEX_VALUE (c)
#define http1_is_ows(c) ((c) == ' ' || (c) == '\t')
#define http1_is_vchar(c)                                                     \
  ((unsigned char)(c) >= 0x21 && (unsigned char)(c) <= 0x7E)
#define http1_is_obs_text(c) ((unsigned char)(c) >= 0x80)
#define http1_is_field_vchar(c) (http1_is_vchar (c) || http1_is_obs_text (c))

#define HTTP1_DEFAULT_METHOD_BUF_SIZE 16
#define HTTP1_DEFAULT_URI_BUF_SIZE 256
#define HTTP1_DEFAULT_REASON_BUF_SIZE 64
#define HTTP1_DEFAULT_HEADER_NAME_BUF_SIZE 64
#define HTTP1_DEFAULT_HEADER_VALUE_BUF_SIZE 256

#endif /* SOCKETHTTP1_PRIVATE_INCLUDED */
