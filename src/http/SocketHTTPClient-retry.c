/**
 * SocketHTTPClient-retry.c - HTTP Client Retry Logic
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Centralized retry helpers for HTTP client: delay calculation, sleeping, retry decisions.
 * Integrates SocketRetry module for validated exponential backoff with jitter and improved RNG.
 * Handles config-based retry decisions for errors and 5xx status codes.
 *
 * Exported via SocketHTTPClient-private.h for use in core client implementation.
 */

#include <errno.h>
#include <time.h>

#include "core/SocketRetry.h"
#include "http/SocketHTTPClient-private.h"
#include "core/SocketUtil.h"

/**
 * calculate_retry_delay - Calculate backoff delay for retry attempt
 * @client: HTTP client with retry config (read-only)
 * @attempt: Current attempt number (1-based, must be >=1)
 *
 * Returns: Delay in milliseconds with jitter applied, or 1 if invalid input
 * Thread-safe: Yes
 *
 * Uses SocketRetry_calculate_delay for consistent exponential backoff with jitter.
 * Backoff formula: initial * multiplier^(attempt-1), capped at max_delay.
 * multiplier = HTTPCLIENT_RETRY_MULTIPLIER (2.0)
 * Applies +/- HTTPCLIENT_RETRY_JITTER_FACTOR jitter using improved RNG.
 * Handles FP overflow/NaN by clamping to max_delay.
 */
int
httpclient_calculate_retry_delay (const SocketHTTPClient_T client, int attempt)
{
  if (client == NULL || attempt < 1)
    return 1;

  SocketRetry_Policy policy;
  SocketRetry_policy_defaults(&policy);
  policy.initial_delay_ms = client->config.retry_initial_delay_ms;
  policy.max_delay_ms = client->config.retry_max_delay_ms;
  policy.multiplier = HTTPCLIENT_RETRY_MULTIPLIER;
  policy.jitter = HTTPCLIENT_RETRY_JITTER_FACTOR;

  return SocketRetry_calculate_delay(&policy, attempt);
}

/**
 * retry_sleep_ms - Sleep for specified milliseconds using nanosleep
 * @ms: Milliseconds to sleep (0 or negative = no sleep)
 *
 * Thread-safe: Yes
 *
 * Implements precise sleep with EINTR retry loop per POSIX.1-2008.
 * Uses CLOCK_REALTIME via nanosleep (not monotonic, but suitable for backoff delays).
 * Converts ms to timespec: tv_sec = ms/1000, tv_nsec = (ms%1000)*1e6.
 */
void
httpclient_retry_sleep_ms (int ms)
{
  struct timespec req;
  struct timespec rem;

  if (ms <= 0)
    return;

  static const int MS_PER_SEC = 1000;
  static const long NS_PER_MS = 1000000L;

  req.tv_sec = ms / MS_PER_SEC;
  req.tv_nsec = (ms % MS_PER_SEC) * NS_PER_MS;

  while (nanosleep (&req, &rem) == -1)
    {
      if (errno != EINTR)
        break;
      req = rem;
    }
}



/**
 * httpclient_should_retry_error - Check if error code should trigger retry
 * @client: HTTP client with retry config (read-only)
 * @error: Error code to check
 *
 * Returns: 1 if should retry based on config, 0 otherwise
 * Thread-safe: Yes
 *
 * Checks config flags:
 * - retry_on_connection_error for DNS/CONNECT errors
 * - retry_on_timeout for TIMEOUT errors
 * Other errors always non-retryable.
 */
int
httpclient_should_retry_error (const SocketHTTPClient_T client, SocketHTTPClient_Error error)
{
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

/**
 * should_retry_status - Check if HTTP status should trigger retry
 * @client: HTTP client with retry config (read-only)
 * @status: HTTP status code
 *
 * Returns: 1 if should retry, 0 otherwise
 * Thread-safe: Yes
 *
 * Retries 5xx server errors only if config.retry_on_5xx is enabled.
 * IMPORTANT: Enable only for idempotent requests (GET, HEAD, etc.) to avoid
 * duplicate side effects on retry.
 * Non-5xx status codes (including 4xx client errors) are never retried.
 */
int
httpclient_should_retry_status (const SocketHTTPClient_T client, int status)
{
  if (status >= HTTP_STATUS_5XX_MIN && status <= HTTP_STATUS_5XX_MAX)
    return client->config.retry_on_5xx;

  return 0;
}

/**
 * clear_response_for_retry - Clear response state for retry attempt
 * @response: Response to clear (modified)
 *
 * Disposes response arena (frees headers, body) and zeros structure.
 * Prepares response for reuse in next retry attempt.
 * Thread-safe: No (modifies response)
 *
 * clear_response_for_retry - Clear response for retry
 * @response: Response to clear (modified)
 *
 * Disposes response arena (frees headers, body) and zeros structure.
 * Prepares response for reuse in next retry attempt.
 * Thread-safe: No (modifies response)
 *
 * Note: Caller must ensure no concurrent access to response.
 */
void
clear_response_for_retry (SocketHTTP_Response *response)
{
  SocketHTTP_Headers_clear (response->headers);
  memset (response, 0, sizeof (*response));
}

void
httpclient_clear_response_for_retry (SocketHTTPClient_Response *response)
{
  if (response)
    {
      SocketHTTP_Headers_clear (response->headers);
      memset (response, 0, sizeof (*response));
    }
}

/* Functions exported via SocketHTTPClient-private.h */