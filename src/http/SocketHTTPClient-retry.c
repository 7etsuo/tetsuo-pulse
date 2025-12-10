/**
 * SocketHTTPClient-retry.c - HTTP Client Retry Logic
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Centralized retry helpers for HTTP client: delay calculation, sleeping,
 * retry decisions. Integrates SocketRetry module for validated exponential
 * backoff with jitter and improved RNG. Handles config-based retry decisions
 * for errors and 5xx status codes.
 *
 * Exported via SocketHTTPClient-private.h for use in core client
 * implementation.
 */

#include <errno.h>
#include <string.h>
#include <time.h>

#include "core/SocketRetry.h"
#include "http/SocketHTTPClient-private.h"

/* ============================================================================
 * Constants
 * ============================================================================
 */

/** Minimum delay to return on invalid input (ms) */
#define HTTPCLIENT_MIN_DELAY_MS 1

/** Time conversion: milliseconds per second */
#define MILLISECONDS_PER_SECOND 1000

/** Time conversion: nanoseconds per millisecond */
#define NANOSECONDS_PER_MILLISECOND 1000000L

/* ============================================================================
 * Response Clearing
 * ============================================================================
 *
 * Two functions exist to clear responses for retry:
 * - clear_response_for_retry: For SocketHTTP_Response (core HTTP type)
 * - httpclient_clear_response_for_retry: For SocketHTTPClient_Response (client
 * type)
 *
 * Both use the same macro pattern but operate on different struct types.
 * The SocketHTTPClient_Response wraps SocketHTTP_Response with additional
 * client-specific fields (arena, version).
 */

/**
 * CLEAR_RESPONSE - Clear response structure for retry reuse
 * @r: Pointer to response structure (SocketHTTP_Response or
 * SocketHTTPClient_Response)
 *
 * Clears headers collection and zeros the structure for reuse.
 * Handles NULL gracefully (no-op).
 */
#define CLEAR_RESPONSE(r)                                                     \
  do                                                                          \
    {                                                                         \
      if ((r))                                                                \
        {                                                                     \
          SocketHTTP_Headers_clear ((r)->headers);                            \
          memset ((r), 0, sizeof (*(r)));                                     \
        }                                                                     \
    }                                                                         \
  while (0)

/* ============================================================================
 * Retry Delay Calculation
 * ============================================================================
 */

/**
 * httpclient_calculate_retry_delay - Calculate backoff delay for retry attempt
 * @client: HTTP client with retry config (read-only)
 * @attempt: Current attempt number (1-based, must be >=1)
 *
 * Returns: Delay in milliseconds with jitter applied, or
 * HTTPCLIENT_MIN_DELAY_MS if invalid input Thread-safe: Yes
 *
 * Uses SocketRetry_calculate_delay for consistent exponential backoff with
 * jitter. Backoff formula: initial * multiplier^(attempt-1), capped at
 * max_delay.
 *
 * Parameters from client config:
 * - retry_initial_delay_ms: Starting delay
 * - retry_max_delay_ms: Maximum cap
 *
 * Fixed parameters:
 * - multiplier: HTTPCLIENT_RETRY_MULTIPLIER (2.0)
 * - jitter: HTTPCLIENT_RETRY_JITTER_FACTOR (0.25)
 *
 * Handles FP overflow/NaN by clamping to max_delay.
 *
 * @see SocketRetry_calculate_delay() for underlying computation.
 * @see SocketHTTPClient_Config for retry settings.
 */
int
httpclient_calculate_retry_delay (const SocketHTTPClient_T client, int attempt)
{
  SocketRetry_Policy policy;

  if (client == NULL || attempt < 1)
    return HTTPCLIENT_MIN_DELAY_MS;

  if (attempt > SOCKET_RETRY_MAX_ATTEMPTS)
    {
      SOCKET_LOG_WARN_MSG ("Attempt %d exceeds max %d, clamping to max_delay",
                           attempt, SOCKET_RETRY_MAX_ATTEMPTS);
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

/* ============================================================================
 * Sleep Helper
 * ============================================================================
 */

/**
 * httpclient_retry_sleep_ms - Sleep for specified milliseconds using nanosleep
 * @ms: Milliseconds to sleep (0 or negative = no sleep)
 *
 * Thread-safe: Yes
 *
 * Implements precise sleep with EINTR retry loop per POSIX.1-2008.
 * Nanosleep provides relative sleep not affected by clock changes,
 * suitable for backoff delays.
 *
 * Conversion: tv_sec = ms / 1000, tv_nsec = (ms % 1000) * 1e6.
 *
 * @see nanosleep(2) for underlying system call.
 * @see httpclient_calculate_retry_delay() for delay value source.
 */
void
httpclient_retry_sleep_ms (int ms)
{
  struct timespec req;
  struct timespec rem;

  if (ms <= 0)
    return;

  req.tv_sec = ms / MILLISECONDS_PER_SECOND;
  req.tv_nsec = (ms % MILLISECONDS_PER_SECOND) * NANOSECONDS_PER_MILLISECOND;

  while (nanosleep (&req, &rem) == -1)
    {
      if (errno != EINTR)
        break;
      req = rem;
    }
}

/* ============================================================================
 * Retry Decision Logic
 * ============================================================================
 */

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
 *
 * Other errors (TLS, protocol, redirects, size, cancelled, OOM) are
 * non-retryable by design.
 *
 * @see SocketHTTPClient_Error for error code definitions.
 * @see SocketHTTPClient_error_is_retryable() for public API.
 */
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

/**
 * httpclient_should_retry_status - Check if HTTP status should trigger retry
 * @client: HTTP client with retry config (read-only)
 * @status: HTTP status code
 *
 * Returns: 1 if should retry, 0 otherwise
 * Thread-safe: Yes
 *
 * Retries server errors (HTTP status category 5) only if config.retry_on_5xx
 * is enabled. Uses SocketHTTP_status_category for accurate classification.
 *
 * IMPORTANT: Enable only for idempotent requests (GET, HEAD, OPTIONS, PUT,
 * DELETE) to avoid duplicate side effects on retry. Non-idempotent methods
 * (POST, PATCH) may cause unintended duplicate actions.
 *
 * Non-server-error status codes (including 4xx client errors) are never
 * retried as they indicate permanent failures or client-side issues.
 *
 * @see SocketHTTP_status_category() for status classification.
 * @see SocketHTTPClient_Config::retry_on_5xx for enabling.
 */
int
httpclient_should_retry_status (const SocketHTTPClient_T client, int status)
{
  if (client == NULL)
    return 0;

  if (SocketHTTP_status_category (status) == HTTP_STATUS_SERVER_ERROR)
    return client->config.retry_on_5xx;

  return 0;
}

/* ============================================================================
 * Response Clearing Functions
 * ============================================================================
 */

/**
 * clear_response_for_retry - Clear SocketHTTP_Response for retry attempt
 * @response: Response to clear (modified)
 *
 * Clears headers and zeros the structure for reuse in retry attempts.
 * Caller responsible for freeing body if separately allocated.
 *
 * Thread-safe: No (modifies response)
 *
 * This function operates on SocketHTTP_Response (core HTTP type).
 * For SocketHTTPClient_Response, use httpclient_clear_response_for_retry().
 *
 * @note Handles NULL response gracefully (no-op).
 * @see httpclient_clear_response_for_retry() for client response type.
 */
void
clear_response_for_retry (SocketHTTP_Response *response)
{
  CLEAR_RESPONSE (response);
}

/**
 * httpclient_clear_response_for_retry - Clear SocketHTTPClient_Response for
 * retry
 * @response: Client response to clear (modified)
 *
 * Clears headers and zeros the structure for reuse in retry attempts.
 * Caller responsible for managing arena and body memory separately.
 *
 * Thread-safe: No (modifies response)
 *
 * This function operates on SocketHTTPClient_Response (client-specific type
 * with arena field). For core SocketHTTP_Response, use
 * clear_response_for_retry().
 *
 * @note Handles NULL response gracefully (no-op).
 * @see clear_response_for_retry() for core HTTP response type.
 * @see SocketHTTPClient_Response for structure definition.
 */
void
httpclient_clear_response_for_retry (SocketHTTPClient_Response *response)
{
  CLEAR_RESPONSE (response);
}

/* Functions exported via SocketHTTPClient-private.h */
