/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* SocketHTTPClient-retry.c - HTTP Client Retry Logic with Exponential Backoff
 */

#include <errno.h>
#include <string.h>
#include <time.h>

#include "core/SocketRetry.h"
#include "core/SocketUtil.h"
#include "http/SocketHTTPClient-private.h"

#define CLEAR_RESPONSE(r)                          \
  do                                               \
    {                                              \
      if ((r))                                     \
        {                                          \
          SocketHTTP_Headers_clear ((r)->headers); \
          memset ((r), 0, sizeof (*(r)));          \
        }                                          \
    }                                              \
  while (0)

int
httpclient_calculate_retry_delay (const SocketHTTPClient_T client, int attempt)
{
  SocketRetry_Policy policy;

  if (client == NULL || attempt < 1)
    return HTTPCLIENT_MIN_DELAY_MS;

  if (attempt > SOCKET_RETRY_MAX_ATTEMPTS)
    {
      SOCKET_LOG_WARN_MSG ("Attempt %d exceeds max %d, clamping to max_delay",
                           attempt,
                           SOCKET_RETRY_MAX_ATTEMPTS);
      return client->config.retry_max_delay_ms > 0
                 ? client->config.retry_max_delay_ms
                 : SOCKET_RETRY_DEFAULT_MAX_DELAY_MS;
    }

  SocketRetry_policy_defaults (&policy);
  policy.initial_delay_ms = client->config.retry_initial_delay_ms;
  policy.max_delay_ms = client->config.retry_max_delay_ms;
  policy.multiplier = HTTPCLIENT_RETRY_MULTIPLIER;
  policy.jitter = HTTPCLIENT_RETRY_JITTER_FACTOR;

  return SocketRetry_calculate_delay (&policy, attempt);
}

void
httpclient_retry_sleep_ms (int ms)
{
  struct timespec req;
  struct timespec rem;

  if (ms <= 0)
    return;

  req = socket_util_ms_to_timespec ((unsigned long)ms);

  while (nanosleep (&req, &rem) == -1)
    {
      if (errno != EINTR)
        break;
      req = rem;
    }
}

int
httpclient_should_retry_error (const SocketHTTPClient_T client,
                               SocketHTTPClient_Error error)
{
  if (client == NULL)
    return 0;

  switch (error)
    {
    case HTTPCLIENT_ERROR_DNS:
    case HTTPCLIENT_ERROR_CONNECT:
      return client->config.retry_on_connection_error;

    case HTTPCLIENT_ERROR_TIMEOUT:
      return client->config.retry_on_timeout;

    default:
      return 0;
    }
}

int
httpclient_should_retry_status_with_method (const SocketHTTPClient_T client,
                                            int status,
                                            SocketHTTP_Method method)
{
  if (client == NULL)
    return 0;

  if (SocketHTTP_status_category (status) == HTTP_STATUS_SERVER_ERROR
      && client->config.retry_on_5xx)
    {
      /* SECURITY: Only retry 5xx for idempotent methods (RFC 7231) */
      switch (method)
        {
        case HTTP_METHOD_GET:
        case HTTP_METHOD_HEAD:
        case HTTP_METHOD_PUT:
        case HTTP_METHOD_DELETE:
        case HTTP_METHOD_OPTIONS:
        case HTTP_METHOD_TRACE:
          break; /* Idempotent - allow retry */
        default:
          SOCKET_LOG_DEBUG_MSG ("Not retrying %d on non-idempotent method",
                                status);
          return 0;
        }
      return 1;
    }

  return 0;
}

/* Legacy wrapper - assumes GET for backward compat */
int
httpclient_should_retry_status (const SocketHTTPClient_T client, int status)
{
  /* Assume GET method for backward compatibility */
  return httpclient_should_retry_status_with_method (
      client, status, HTTP_METHOD_GET);
}

void
httpclient_clear_response_for_retry (SocketHTTPClient_Response *response)
{
  CLEAR_RESPONSE (response);
}

/* Functions exported via SocketHTTPClient-private.h */
