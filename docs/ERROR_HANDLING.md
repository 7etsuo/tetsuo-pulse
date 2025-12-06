# Error Handling and Recovery Guide

This guide documents error handling patterns, error categorization, retry strategies, and best practices for the socket library.

## Overview

The socket library uses exception-based error handling. Errors are categorized to help determine appropriate recovery strategies.

## Error Categories

Errors are classified into six categories:

| Category | Description | Typical Retryability |
|----------|-------------|---------------------|
| NETWORK | Network-level errors (connection, DNS) | Usually retryable |
| PROTOCOL | Protocol/format errors | Not retryable |
| APPLICATION | Application-level errors (auth, redirects) | Context-dependent |
| TIMEOUT | Timeout errors | Usually retryable |
| RESOURCE | Resource exhaustion (memory, fd limits) | May be retryable |
| UNKNOWN | Unclassified errors | Not retryable |

### Using Error Categories

```c
#include "core/SocketUtil.h"

void handle_error(int err)
{
    SocketErrorCategory category = SocketError_categorize_errno(err);
    
    switch (category) {
    case SOCKET_ERROR_CATEGORY_NETWORK:
        /* Transient network issue - consider retry */
        if (SocketError_is_retryable_errno(err))
            schedule_retry();
        break;
        
    case SOCKET_ERROR_CATEGORY_TIMEOUT:
        /* Timeout - retry with longer timeout */
        schedule_retry_with_backoff();
        break;
        
    case SOCKET_ERROR_CATEGORY_PROTOCOL:
        /* Configuration or protocol error - don't retry */
        log_error("Protocol error: %s", Socket_safe_strerror(err));
        abort_operation();
        break;
        
    default:
        log_error("Unhandled error: %s", Socket_safe_strerror(err));
        break;
    }
}
```

## Exception Reference

### Socket Module

| Exception | Category | Retryable | Notes |
|-----------|----------|-----------|-------|
| `Socket_Failed` | NETWORK* | Depends | Check errno for specifics |
| `Socket_Closed` | NETWORK | Yes | Peer closed connection |
| `SocketUnix_Failed` | NETWORK | Depends | Unix socket specific |

### HTTP Client Module

| Exception | Category | Retryable | Notes |
|-----------|----------|-----------|-------|
| `SocketHTTPClient_Failed` | Varies | Depends | General failure |
| `SocketHTTPClient_DNSFailed` | NETWORK | Yes | DNS may recover |
| `SocketHTTPClient_ConnectFailed` | NETWORK | Yes | Server may restart |
| `SocketHTTPClient_TLSFailed` | PROTOCOL | No | Configuration issue |
| `SocketHTTPClient_Timeout` | TIMEOUT | Yes | Transient congestion |
| `SocketHTTPClient_ProtocolError` | PROTOCOL | No | Malformed response |
| `SocketHTTPClient_TooManyRedirects` | APPLICATION | No | Redirect loop |
| `SocketHTTPClient_ResponseTooLarge` | RESOURCE | No | Size limit exceeded |

### TLS Module

| Exception | Category | Retryable | Notes |
|-----------|----------|-----------|-------|
| `SocketTLS_Failed` | PROTOCOL | No | TLS setup error |
| `SocketTLS_HandshakeFailed` | PROTOCOL | No | Protocol mismatch |
| `SocketTLS_VerifyFailed` | PROTOCOL | No | Certificate error |
| `SocketTLS_ProtocolError` | PROTOCOL | No | Protocol violation |
| `SocketTLS_ShutdownFailed` | PROTOCOL | No | Shutdown error |

### DNS Module

| Exception | Category | Retryable | Notes |
|-----------|----------|-----------|-------|
| `SocketDNS_Failed` | NETWORK | Yes* | Check error code |

### Pool Module

| Exception | Category | Retryable | Notes |
|-----------|----------|-----------|-------|
| `SocketPool_Failed` | RESOURCE | Depends | Pool exhaustion may clear |

## Retry Patterns

### Using SocketRetry_T

The `SocketRetry_T` module provides generic retry with exponential backoff:

```c
#include "core/SocketRetry.h"
#include "core/SocketUtil.h"

/* Operation to retry - returns 0 on success, error code on failure */
int connect_operation(void *context, int attempt)
{
    ConnectContext *ctx = context;
    
    TRY {
        Socket_connect(ctx->socket, ctx->host, ctx->port);
        return 0;  /* Success */
    }
    EXCEPT(Socket_Failed) {
        return Socket_geterrno();  /* Return error code */
    }
    END_TRY;
    
    return -1;  /* Should not reach here */
}

/* Retry decision callback */
int should_retry_connect(int error, int attempt, void *context)
{
    (void)attempt;
    (void)context;
    return SocketError_is_retryable_errno(error);
}

void connect_with_retry(const char *host, int port)
{
    SocketRetry_Policy policy;
    SocketRetry_T retry;
    ConnectContext ctx;
    int result;
    
    SocketRetry_policy_defaults(&policy);
    policy.max_attempts = 5;
    policy.initial_delay_ms = 100;
    policy.max_delay_ms = 10000;
    
    retry = SocketRetry_new(&policy);
    
    ctx.socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    ctx.host = host;
    ctx.port = port;
    
    result = SocketRetry_execute(retry, connect_operation,
                                  should_retry_connect, &ctx);
    
    if (result != 0) {
        fprintf(stderr, "Connection failed after retries: %s\n",
                Socket_safe_strerror(result));
    }
    
    SocketRetry_free(&retry);
}
```

### Retry Statistics

```c
SocketRetry_Stats stats;
SocketRetry_get_stats(retry, &stats);

printf("Attempts: %d\n", stats.attempts);
printf("Last error: %d\n", stats.last_error);
printf("Total delay: %lld ms\n", stats.total_delay_ms);
printf("Total time: %lld ms\n", stats.total_time_ms);
```

## HTTP Client Retry Configuration

The HTTP client supports automatic retry with configuration:

```c
#include "http/SocketHTTPClient.h"

void setup_http_client_with_retry(void)
{
    SocketHTTPClient_Config config;
    SocketHTTPClient_T client;
    
    SocketHTTPClient_config_defaults(&config);
    
    /* Enable automatic retry */
    config.enable_retry = 1;
    config.max_retries = 3;
    config.retry_initial_delay_ms = 100;
    config.retry_max_delay_ms = 10000;
    
    /* Configure what to retry */
    config.retry_on_connection_error = 1;  /* ECONNREFUSED, etc. */
    config.retry_on_timeout = 1;           /* Timeout errors */
    config.retry_on_5xx = 0;               /* Don't retry server errors */
    
    client = SocketHTTPClient_new(&config);
    
    /* Requests will automatically retry on transient failures */
    SocketHTTPClient_Response response;
    if (SocketHTTPClient_get(client, "https://example.com/api", &response) == 0) {
        /* Handle response */
        Arena_dispose(&response.arena);
    }
    
    SocketHTTPClient_free(&client);
}
```

### Checking Error Retryability

```c
/* For async operations */
SocketHTTPClient_Error error = SocketHTTPClient_Request_error(req);
if (SocketHTTPClient_error_is_retryable(error)) {
    /* Schedule manual retry */
    schedule_retry();
}

/* For socket operations */
if (Socket_error_is_retryable(errno)) {
    /* Connection may recover */
    schedule_retry();
}
```

## Circuit Breaker Pattern

For persistent connections, use `SocketReconnect` which implements the circuit breaker pattern:

```c
#include "socket/SocketReconnect.h"

void state_callback(SocketReconnect_T conn,
                    SocketReconnect_State old_state,
                    SocketReconnect_State new_state,
                    void *userdata)
{
    printf("State: %s -> %s\n",
           SocketReconnect_state_name(old_state),
           SocketReconnect_state_name(new_state));
    
    if (new_state == RECONNECT_CIRCUIT_OPEN) {
        /* Circuit breaker opened - too many failures */
        alert_operations_team();
    }
}

void setup_reconnecting_connection(void)
{
    SocketReconnect_Policy_T policy;
    SocketReconnect_T conn;
    
    SocketReconnect_policy_defaults(&policy);
    
    /* Backoff configuration */
    policy.initial_delay_ms = 100;
    policy.max_delay_ms = 30000;
    policy.multiplier = 2.0;
    policy.jitter = 0.25;
    policy.max_attempts = 10;
    
    /* Circuit breaker configuration */
    policy.circuit_failure_threshold = 5;   /* Open after 5 failures */
    policy.circuit_reset_timeout_ms = 60000; /* Probe after 60s */
    
    conn = SocketReconnect_new("example.com", 8080, &policy,
                               state_callback, NULL);
    
    SocketReconnect_connect(conn);
    
    /* Event loop integration */
    while (running) {
        int timeout = SocketReconnect_next_timeout_ms(conn);
        /* poll/select with timeout */
        SocketReconnect_process(conn);
        SocketReconnect_tick(conn);
    }
    
    SocketReconnect_free(&conn);
}
```

### State Machine

```
              +--------------+
              | DISCONNECTED |
              +------+-------+
                     |
                     v
              +------+-------+
         +--->| CONNECTING   |<---+
         |    +------+-------+    |
         |           |            |
         |     success|failure    |
         |           |            |
         |    +------v-------+    |
         |    | CONNECTED    |    |
         |    +------+-------+    |
         |           |            |
         |     failure            |
         |           |            |
         |    +------v-------+    |
         +----+  BACKOFF     +----+
              +------+-------+
                     |
              (consecutive failures)
                     |
              +------v-------+
              | CIRCUIT_OPEN |
              +------+-------+
                     |
              (reset timeout)
                     |
                     v
              (probe attempt)
```

## Best Practices

### 1. Idempotency for Safe Retry

Only retry operations that are idempotent:

```c
/* Safe to retry - idempotent */
SocketHTTPClient_get(client, url, &response);  /* GET */
SocketHTTPClient_head(client, url, &response); /* HEAD */
SocketHTTPClient_delete(client, url, &response); /* DELETE (usually) */

/* Unsafe to retry - may cause duplicates */
SocketHTTPClient_post(client, url, body, len, &response); /* POST */
```

When enabling `retry_on_5xx`, only do so for GET/HEAD requests:

```c
config.retry_on_5xx = (method == HTTP_METHOD_GET || 
                       method == HTTP_METHOD_HEAD);
```

### 2. Timeout Budgeting

Account for retries in overall timeout:

```c
void request_with_total_timeout(int total_timeout_ms)
{
    int64_t deadline = SocketTimeout_deadline_ms(total_timeout_ms);
    int attempt = 0;
    
    while (!SocketTimeout_expired(deadline) && attempt < max_retries) {
        int remaining = SocketTimeout_remaining_ms(deadline);
        
        /* Use remaining time for this attempt */
        config.request_timeout_ms = (remaining > 10000) ? 10000 : remaining;
        
        if (try_request() == 0)
            return;
        
        attempt++;
        
        /* Only sleep if we have time for another attempt */
        int delay = calculate_backoff(attempt);
        if (SocketTimeout_remaining_ms(deadline) > delay)
            sleep_ms(delay);
    }
}
```

### 3. Logging and Metrics

Log retry attempts for visibility:

```c
SocketRetry_Stats stats;
SocketRetry_get_stats(retry, &stats);

if (stats.attempts > 1) {
    SocketLog_emitf(SOCKET_LOG_WARN, "HTTPClient",
                    "Request succeeded after %d attempts (total delay: %lld ms)",
                    stats.attempts, stats.total_delay_ms);
}

/* Track metrics */
SocketMetrics_counter_add(SOCKET_CTR_HTTP_CLIENT_RETRIES, 
                          stats.attempts - 1);
```

### 4. Graceful Degradation

Implement fallback strategies:

```c
int fetch_with_fallback(const char *primary_url, const char *backup_url,
                        SocketHTTPClient_Response *response)
{
    /* Try primary with retries */
    if (try_request(primary_url, response) == 0)
        return 0;
    
    /* Fall back to backup */
    SocketLog_emit(SOCKET_LOG_WARN, "HTTPClient",
                   "Primary failed, trying backup");
    return try_request(backup_url, response);
}
```

### 5. Error Categorization in Application Code

Use error categories for clean error handling:

```c
void handle_socket_error(void)
{
    int err = Socket_geterrno();
    SocketErrorCategory cat = SocketError_categorize_errno(err);
    
    switch (cat) {
    case SOCKET_ERROR_CATEGORY_NETWORK:
        user_message("Network error - please check your connection");
        break;
    case SOCKET_ERROR_CATEGORY_TIMEOUT:
        user_message("Request timed out - please try again");
        break;
    case SOCKET_ERROR_CATEGORY_PROTOCOL:
        log_bug("Protocol error: %s", Socket_safe_strerror(err));
        user_message("Internal error - please contact support");
        break;
    case SOCKET_ERROR_CATEGORY_RESOURCE:
        log_critical("Resource exhaustion: %s", Socket_safe_strerror(err));
        user_message("System overloaded - please try later");
        break;
    default:
        log_error("Unknown error: %s", Socket_safe_strerror(err));
        user_message("An error occurred");
        break;
    }
}
```

## Exception Handling Patterns

### Basic TRY/EXCEPT

```c
TRY {
    Socket_connect(sock, host, port);
    /* Success path */
}
EXCEPT(Socket_Failed) {
    /* Handle specific exception */
    if (Socket_error_is_retryable(Socket_geterrno()))
        schedule_retry();
    else
        report_error();
}
END_TRY;
```

### Multiple Exception Types

```c
TRY {
    response = make_http_request(url);
}
EXCEPT(SocketHTTPClient_DNSFailed) {
    /* DNS failed - retryable */
    schedule_dns_retry();
}
EXCEPT(SocketHTTPClient_ConnectFailed) {
    /* Connection failed - retryable */
    schedule_connect_retry();
}
EXCEPT(SocketHTTPClient_TLSFailed) {
    /* TLS failed - not retryable */
    report_tls_config_error();
}
EXCEPT(SocketHTTPClient_Timeout) {
    /* Timeout - retryable */
    schedule_retry_with_longer_timeout();
}
END_TRY;
```

### FINALLY for Cleanup

```c
Socket_T socket = NULL;

TRY {
    socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_connect(socket, host, port);
    /* ... use socket ... */
}
FINALLY {
    /* Always clean up, even on exception */
    if (socket != NULL)
        Socket_free(&socket);
}
END_TRY;
```

## See Also

- [SocketRetry.h](../include/core/SocketRetry.h) - Generic retry module
- [SocketReconnect.h](../include/socket/SocketReconnect.h) - Auto-reconnection with circuit breaker
- [SocketUtil.h](../include/core/SocketUtil.h) - Error categorization utilities
- [TIMEOUTS.md](TIMEOUTS.md) - Timeout configuration guide
- [LOGGING.md](LOGGING.md) - Logging infrastructure
