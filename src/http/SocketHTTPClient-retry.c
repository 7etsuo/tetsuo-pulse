/**
 * SocketHTTPClient-retry.c - HTTP Client Retry Logic
 *
 * Part of the Socket Library
 *
 * Implements automatic retry with exponential backoff for transient failures.
 * Separated for modularity - retry policy is independent of core client logic.
 */

#include "http/SocketHTTPClient-private.h"
#include "core/SocketUtil.h"

#include <math.h>
#include <stdlib.h>

/**
 * calculate_retry_delay - Calculate backoff delay for retry attempt
 * @client: HTTP client with retry config
 * @attempt: Current attempt number (1-based)
 *
 * Returns: Delay in milliseconds with jitter applied
 * Thread-safe: Yes (uses rand() - seed externally if needed)
 *
 * Uses exponential backoff: initial * 2^(attempt-1), capped at max_delay.
 * Applies +/- HTTPCLIENT_RETRY_JITTER_FACTOR jitter to prevent thundering herd.
 */
int
httpclient_calculate_retry_delay (SocketHTTPClient_T client, int attempt)
{
  double delay;
  double jitter_range;
  double random_factor;

  /* Exponential backoff: initial * 2^(attempt-1) */
  delay = (double)client->config.retry_initial_delay_ms
          * pow (2.0, (double)(attempt - 1));

  /* Cap at max delay */
  if (delay > (double)client->config.retry_max_delay_ms)
    delay = (double)client->config.retry_max_delay_ms;

  /* Apply jitter: delay * (1 +/- jitter_factor * random) */
  random_factor = (double)rand () / (double)RAND_MAX; /* 0 to 1 */
  jitter_range = delay * HTTPCLIENT_RETRY_JITTER_FACTOR;
  delay += jitter_range * (2.0 * random_factor - 1.0);

  /* Ensure positive delay */
  if (delay < 1.0)
    delay = 1.0;

  return (int)delay;
}

/**
 * retry_sleep_ms - Sleep for specified milliseconds
 * @ms: Milliseconds to sleep
 *
 * Thread-safe: Yes
 */
static void
retry_sleep_ms (int ms)
{
  struct timespec req;
  struct timespec rem;

  if (ms <= 0)
    return;

  req.tv_sec = ms / 1000;
  req.tv_nsec = (ms % 1000) * 1000000L;

  while (nanosleep (&req, &rem) == -1)
    {
      if (errno != EINTR)
        break;
      req = rem;
    }
}

/**
 * should_retry_error - Check if error code should trigger retry
 * @client: HTTP client with retry config
 * @error: Error code to check
 *
 * Returns: 1 if should retry, 0 otherwise
 */
static int
should_retry_error (SocketHTTPClient_T client, SocketHTTPClient_Error error)
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
 * @client: HTTP client with retry config
 * @status: HTTP status code
 *
 * Returns: 1 if should retry, 0 otherwise
 */
static int
should_retry_status (SocketHTTPClient_T client, int status)
{
  if (status >= 500 && status < 600)
    return client->config.retry_on_5xx;

  return 0;
}

/**
 * clear_response_for_retry - Clear response state for retry attempt
 * @response: Response to clear
 */
static void
clear_response_for_retry (SocketHTTPClient_Response *response)
{
  if (response->arena != NULL)
    {
      Arena_dispose (&response->arena);
      response->arena = NULL;
    }
  memset (response, 0, sizeof (*response));
}

/* Export for main .c file */
extern int httpclient_should_retry_error (SocketHTTPClient_T client, SocketHTTPClient_Error error);
extern int httpclient_should_retry_status (SocketHTTPClient_T client, int status);
extern int httpclient_calculate_retry_delay (SocketHTTPClient_T client, int attempt);
extern void httpclient_retry_sleep_ms (int ms);
extern void httpclient_clear_response_for_retry (SocketHTTPClient_Response *response);