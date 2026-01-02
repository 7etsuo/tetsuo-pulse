/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTPClient-body.c
 * @brief Response body accumulation for HTTP client
 *
 * Handles response body buffering with:
 * - Size limit enforcement
 * - Exponential buffer growth
 * - Benchmark/discard mode support
 * - Arena-based allocation
 */

#include <assert.h>
#include <string.h>

#include "core/Arena.h"
#include "core/SocketMetrics.h"
#include "core/SocketSecurity.h"
#include "http/SocketHTTPClient-private.h"

int
httpclient_body_check_size_limit (HTTPBodyAccumulator *acc,
                                  size_t len,
                                  size_t *potential_size)
{
  if (!SocketSecurity_check_add (acc->total_body, len, potential_size)
      || (acc->max_size > 0 && *potential_size > acc->max_size))
    {
      SocketMetrics_counter_inc (SOCKET_CTR_LIMIT_RESPONSE_SIZE_EXCEEDED);
      return -2;
    }
  return 0;
}

size_t
httpclient_body_calculate_capacity (HTTPBodyAccumulator *acc,
                                    size_t needed_size)
{
  size_t base_cap = acc->body_capacity == 0 ? HTTPCLIENT_BODY_CHUNK_SIZE
                                            : acc->body_capacity;
  size_t new_cap = SocketSecurity_safe_multiply (base_cap, 2);

  if (new_cap == 0)
    return 0;

  /* Exponential growth until sufficient */
  for (int i = 0; i < 32 && new_cap < needed_size; i++)
    {
      size_t temp = SocketSecurity_safe_multiply (new_cap, 2);
      if (temp == 0)
        return 0;
      new_cap = temp;
    }

  /* Clamp to max_size */
  if (acc->max_size > 0 && new_cap > acc->max_size)
    new_cap = acc->max_size;

  return new_cap;
}

/* Grow arena buffer for body accumulation (exponential doubling) */
int
httpclient_grow_body_buffer (Arena_T arena,
                             char **buf,
                             size_t *capacity,
                             size_t *total,
                             size_t needed_size,
                             size_t max_size)
{
  size_t base_cap = (*capacity == 0) ? HTTPCLIENT_BODY_CHUNK_SIZE : *capacity;
  size_t new_cap;

  if (needed_size <= *capacity)
    return 0;

  /* Exponential growth with safe multiply */
  new_cap = base_cap;
  for (int i = 0; i < 32 && new_cap < needed_size; i++)
    {
      size_t temp = SocketSecurity_safe_multiply (new_cap, 2);
      if (temp == 0 || temp / 2 != new_cap) /* Overflow check */
        return -1;
      new_cap = temp;
    }

  /* Clamp to max_size */
  if (max_size > 0 && new_cap > max_size)
    new_cap = max_size;

  if (new_cap < needed_size)
    return -1; /* Still too small after growth */

  char *new_buf = Arena_alloc (arena, new_cap, __FILE__, __LINE__);
  if (new_buf == NULL)
    return -1;

  if (*buf != NULL && *total > 0)
    memcpy (new_buf, *buf, *total);

  *buf = new_buf;
  *capacity = new_cap;
  return 0;
}

/* Note: Caller must update *total after adding data to reach needed_size. */

int
httpclient_body_grow_buffer (HTTPBodyAccumulator *acc, size_t needed_size)
{
  return httpclient_grow_body_buffer (acc->arena,
                                      &acc->body_buf,
                                      &acc->body_capacity,
                                      &acc->total_body,
                                      needed_size,
                                      acc->max_size);
}

int
httpclient_body_accumulate_chunk (HTTPBodyAccumulator *acc,
                                  const char *data,
                                  size_t len)
{
  size_t needed_size;
  int result;

  assert (acc != NULL);
  (void)data; /* May be unused in discard mode */

  if (len == 0)
    return 0;

  /* Check size limit */
  result = httpclient_body_check_size_limit (acc, len, &needed_size);
  if (result != 0)
    return result;

  /* Benchmark mode: just count bytes, skip allocation and copy */
  if (acc->discard_body)
    {
      acc->total_body = needed_size;
      return 0;
    }

  /* Grow buffer if needed */
  if (httpclient_body_grow_buffer (acc, needed_size) != 0)
    return -1;

  /* Append data */
  memcpy (acc->body_buf + acc->total_body, data, len);
  acc->total_body = needed_size;

  return 0;
}

void
httpclient_body_fill_response (SocketHTTPClient_Response *response,
                               const SocketHTTP_Response *parsed_resp,
                               HTTPBodyAccumulator *acc,
                               Arena_T resp_arena)
{
  response->status_code = parsed_resp->status_code;
  response->version = parsed_resp->version;
  response->headers = parsed_resp->headers;
  response->body = acc->body_buf;
  response->body_len = acc->total_body;
  response->arena = resp_arena;
}
