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

typedef enum
{
  HTTP1_CC_CTL = 0,
  HTTP1_CC_SP,
  HTTP1_CC_HTAB,
  HTTP1_CC_CR,
  HTTP1_CC_LF,
  HTTP1_CC_COLON,
  HTTP1_CC_SLASH,
  HTTP1_CC_DOT,
  HTTP1_CC_DIGIT,
  HTTP1_CC_HEX,
  HTTP1_CC_ALPHA,
  HTTP1_CC_H,
  HTTP1_CC_T,
  HTTP1_CC_P,
  HTTP1_CC_TCHAR,
  HTTP1_CC_VCHAR,
  HTTP1_CC_OBS,
  HTTP1_CC_INVALID,
  HTTP1_NUM_CLASSES
} HTTP1_CharClass;
typedef enum
{
  HTTP1_ACT_NONE = 0,
  HTTP1_ACT_STORE_METHOD,
  HTTP1_ACT_STORE_URI,
  HTTP1_ACT_STORE_REASON,
  HTTP1_ACT_STORE_NAME,
  HTTP1_ACT_STORE_VALUE,
  HTTP1_ACT_METHOD_END,
  HTTP1_ACT_URI_END,
  HTTP1_ACT_VERSION_MAJ,
  HTTP1_ACT_VERSION_MIN,
  HTTP1_ACT_STATUS_DIGIT,
  HTTP1_ACT_REASON_END,
  HTTP1_ACT_HEADER_END,
  HTTP1_ACT_HEADERS_DONE,
  HTTP1_ACT_ERROR
} HTTP1_Action;
typedef enum
{
  HTTP1_PS_START = 0,
  HTTP1_PS_METHOD,
  HTTP1_PS_SP_AFTER_METHOD,
  HTTP1_PS_URI,
  HTTP1_PS_SP_AFTER_URI,
  HTTP1_PS_STATUS_CODE,
  HTTP1_PS_SP_AFTER_STATUS,
  HTTP1_PS_REASON,
  HTTP1_PS_VERSION_H,
  HTTP1_PS_VERSION_T1,
  HTTP1_PS_VERSION_T2,
  HTTP1_PS_VERSION_P,
  HTTP1_PS_VERSION_SLASH,
  HTTP1_PS_VERSION_MAJOR,
  HTTP1_PS_VERSION_DOT,
  HTTP1_PS_VERSION_MINOR,
  HTTP1_PS_LINE_CR,
  HTTP1_PS_LINE_LF,
  HTTP1_PS_HEADER_START,
  HTTP1_PS_HEADER_NAME,
  HTTP1_PS_HEADER_COLON,
  HTTP1_PS_HEADER_VALUE,
  HTTP1_PS_HEADER_VALUE_OWS,
  HTTP1_PS_HEADER_CR,
  HTTP1_PS_HEADER_LF,
  HTTP1_PS_HEADERS_END_LF,
  HTTP1_PS_BODY_IDENTITY,
  HTTP1_PS_BODY_UNTIL_CLOSE,
  HTTP1_PS_CHUNK_SIZE,
  HTTP1_PS_CHUNK_SIZE_EXT,
  HTTP1_PS_CHUNK_SIZE_CR,
  HTTP1_PS_CHUNK_SIZE_LF,
  HTTP1_PS_CHUNK_DATA,
  HTTP1_PS_CHUNK_DATA_CR,
  HTTP1_PS_CHUNK_DATA_LF,
  HTTP1_PS_TRAILER_START,
  HTTP1_PS_TRAILER_NAME,
  HTTP1_PS_TRAILER_COLON,
  HTTP1_PS_TRAILER_VALUE,
  HTTP1_PS_TRAILER_CR,
  HTTP1_PS_TRAILER_LF,
  HTTP1_PS_TRAILERS_END_LF,
  HTTP1_PS_COMPLETE,
  HTTP1_PS_ERROR,
  HTTP1_NUM_STATES
} HTTP1_InternalState;

extern const uint8_t http1_char_class[256];
extern const uint8_t http1_req_state[HTTP1_NUM_STATES][HTTP1_NUM_CLASSES];
extern const uint8_t http1_resp_state[HTTP1_NUM_STATES][HTTP1_NUM_CLASSES];
extern const uint8_t http1_req_action[HTTP1_NUM_STATES][HTTP1_NUM_CLASSES];
extern const uint8_t http1_resp_action[HTTP1_NUM_STATES][HTTP1_NUM_CLASSES];

#define HTTP1_DEFAULT_METHOD_BUF_SIZE 16
#define HTTP1_DEFAULT_URI_BUF_SIZE 256
#define HTTP1_DEFAULT_REASON_BUF_SIZE 64
#define HTTP1_DEFAULT_HEADER_NAME_BUF_SIZE 64
#define HTTP1_DEFAULT_HEADER_VALUE_BUF_SIZE 256
#define HTTP1_DEFAULT_TOKEN_BUF_SIZE 64

typedef struct
{
  char *data;
  size_t len;
  size_t capacity;
} HTTP1_TokenBuf;
struct SocketHTTP1_Parser
{
  SocketHTTP1_ParseMode mode;
  SocketHTTP1_Config config;
  Arena_T arena;
  SocketHTTP1_State state;
  SocketHTTP1_Result error;
  HTTP1_InternalState internal_state;
  union
  {
    SocketHTTP_Request request;
    SocketHTTP_Response response;
  } message;
  SocketHTTP_Headers_T headers;
  SocketHTTP_Headers_T trailers;
  HTTP1_TokenBuf method_buf;
  HTTP1_TokenBuf uri_buf;
  HTTP1_TokenBuf reason_buf;
  HTTP1_TokenBuf name_buf;
  HTTP1_TokenBuf value_buf;
  size_t header_count;
  size_t total_header_size;
  size_t line_length;
  size_t header_line_length;
  size_t trailer_count;
  size_t total_trailer_size;
  SocketHTTP1_BodyMode body_mode;
  int64_t content_length;
  int64_t body_remaining;
  int body_complete;
  uint64_t body_read;
  size_t chunk_size;
  size_t chunk_remaining;
  int version_major;
  int version_minor;
  int status_code;
  int keepalive;
  int is_upgrade;
  const char *upgrade_protocol;
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

static inline void
http1_tokenbuf_reset (HTTP1_TokenBuf *buf)
{
  buf->len = 0;
}

static inline void
http1_tokenbuf_release (HTTP1_TokenBuf *buf)
{
  /* Release ownership - data stays in arena, will be used by header */
  buf->data = NULL;
  buf->len = 0;
  buf->capacity = 0;
  /* Next append will allocate fresh buffer */
}

static inline int
http1_tokenbuf_append (HTTP1_TokenBuf *buf, Arena_T arena, char c,
                       size_t max_size)
{
  if (buf->len >= max_size)
    return -1;

  if (buf->len >= buf->capacity)
    {
      /* After release, capacity is 0 - use default initial size */
      size_t new_capacity
          = (buf->capacity == 0) ? HTTP1_DEFAULT_TOKEN_BUF_SIZE : (buf->capacity * 2);
      if (new_capacity > max_size)
        new_capacity = max_size;

      char *new_data = Arena_alloc (arena, new_capacity, __FILE__, __LINE__);
      if (!new_data)
        return -1;

      if (buf->data && buf->len > 0)
        memmove (new_data, buf->data, buf->len);
      buf->data = new_data;
      buf->capacity = new_capacity;
    }

  buf->data[buf->len++] = c;
  return 0;
}

static inline int
http1_tokenbuf_append_block (HTTP1_TokenBuf *buf, Arena_T arena,
                             const char *src, size_t count, size_t max_size)
{
  size_t new_len;
  size_t new_capacity;
  char *new_data;

  if (count == 0)
    return 0;

  new_len = buf->len + count;
  if (new_len > max_size)
    return -1;

  if (new_len > buf->capacity)
    {
      new_capacity = (buf->capacity == 0) ? HTTP1_DEFAULT_TOKEN_BUF_SIZE : buf->capacity;
      while (new_capacity < new_len)
        new_capacity *= 2;
      if (new_capacity > max_size)
        new_capacity = max_size;

      new_data = Arena_alloc (arena, new_capacity, __FILE__, __LINE__);
      if (!new_data)
        return -1;

      if (buf->data && buf->len > 0)
        memcpy (new_data, buf->data, buf->len);
      buf->data = new_data;
      buf->capacity = new_capacity;
    }

  memcpy (buf->data + buf->len, src, count);
  buf->len = new_len;
  return 0;
}

static inline char *
http1_tokenbuf_terminate (HTTP1_TokenBuf *buf, Arena_T arena, size_t max_size)
{
  if (buf->len >= buf->capacity)
    {
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

/**
 * CRLF parsing result codes for incremental parsing.
 */
typedef enum
{
  HTTP1_CRLF_OK = 0,        /**< Valid CRLF sequence found */
  HTTP1_CRLF_INCOMPLETE,    /**< Need more data to determine validity */
  HTTP1_CRLF_INVALID        /**< Invalid sequence (not CRLF or bare LF) */
} HTTP1_CRLFResult;

/**
 * Skip CRLF sequence in HTTP/1.1 parsing with lenient bare LF support.
 *
 * Accepts both "\r\n" (strict RFC 9112) and "\n" (lenient bare LF).
 * This is used in chunked encoding and trailer parsing.
 *
 * @param p Pointer to current position (advanced on success)
 * @param end End of input buffer
 * @return HTTP1_CRLF_OK if valid CRLF/LF found (advances *p),
 *         HTTP1_CRLF_INCOMPLETE if need more data,
 *         HTTP1_CRLF_INVALID if invalid sequence
 */
static inline HTTP1_CRLFResult
http1_skip_crlf (const char **p, const char *end)
{
  if (*p >= end)
    return HTTP1_CRLF_INCOMPLETE;

  if (**p == '\r')
    {
      (*p)++;
      if (*p >= end)
        return HTTP1_CRLF_INCOMPLETE;
      if (**p == '\n')
        {
          (*p)++;
          return HTTP1_CRLF_OK;
        }
      else
        return HTTP1_CRLF_INVALID;
    }
  else if (**p == '\n')
    {
      (*p)++;
      return HTTP1_CRLF_OK;
    }
  else
    return HTTP1_CRLF_INVALID;
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

#endif /* SOCKETHTTP1_PRIVATE_INCLUDED */
