# Logging Infrastructure
**Brief**: Production-grade logging with structured output and correlation IDs | **Tags**: `logging`, `structured`, `correlation`, `thread-safe`, `backends`

The socket library includes a production-grade logging subsystem with pluggable backends, log level filtering, structured logging, and correlation ID support.

**Module Group**: Utilities | **Related Modules**: SocketUtil (logging macros)

## Features
**Brief**: Comprehensive logging capabilities for production use | **Tags**: `features`, `levels`, `filtering`, `structured`, `correlation`

- **Six log levels**: TRACE, DEBUG, INFO, WARN, ERROR, FATAL
- **Level filtering**: Suppress messages below configured threshold
- **Custom callbacks**: Integrate with any logging framework
- **Structured logging**: Key-value pairs for machine-parseable output
- **Correlation IDs**: Thread-local context for distributed tracing
- **Thread-safe**: All operations are safe for concurrent use

**Cross-References**:
- [Logging API](../rules/module-patterns.mdc) - Implementation details
- [Thread safety patterns](../rules/memory-management.mdc) - Thread-local correlation IDs

---

## Quick Start

```c
#include "core/SocketUtil.h"

/* Set log level (default is INFO) */
SocketLog_setlevel(SOCKET_LOG_DEBUG);

/* Use convenience macros */
SOCKET_LOG_INFO_MSG("Server started on port %d", port);
SOCKET_LOG_DEBUG_MSG("Connection fd=%d from %s", fd, addr);
SOCKET_LOG_ERROR_MSG("Failed to bind: %s", strerror(errno));
```

---

## Log Levels

| Level | Value | Description | Use Case |
|-------|-------|-------------|----------|
| `SOCKET_LOG_TRACE` | 0 | Most verbose | Detailed tracing, packet dumps |
| `SOCKET_LOG_DEBUG` | 1 | Debugging info | Development, troubleshooting |
| `SOCKET_LOG_INFO` | 2 | Normal events | Production default |
| `SOCKET_LOG_WARN` | 3 | Warning conditions | Recoverable issues |
| `SOCKET_LOG_ERROR` | 4 | Error conditions | Operation failures |
| `SOCKET_LOG_FATAL` | 5 | Critical errors | Before crash/abort |

### Level Filtering

Messages below the configured minimum level are silently discarded:

```c
/* Only show warnings and above */
SocketLog_setlevel(SOCKET_LOG_WARN);

/* These are suppressed */
SOCKET_LOG_DEBUG_MSG("This is hidden");
SOCKET_LOG_INFO_MSG("This is also hidden");

/* These are shown */
SOCKET_LOG_WARN_MSG("Warning shown");
SOCKET_LOG_ERROR_MSG("Error shown");
```

### Querying Current Level

```c
SocketLogLevel current = SocketLog_getlevel();
if (current <= SOCKET_LOG_DEBUG) {
    /* Expensive debug computation only when needed */
    char *debug_info = expensive_debug_string();
    SOCKET_LOG_DEBUG_MSG("State: %s", debug_info);
    free(debug_info);
}
```

---

## Module Component Names

Each module should define its component name before including SocketUtil.h:

```c
/* In your module's .c file, BEFORE including SocketUtil.h */
#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "MyModule"

#include "core/SocketUtil.h"

/* Now logs will show [MyModule] prefix */
SOCKET_LOG_INFO_MSG("Operation completed");
/* Output: 2025-12-05 10:30:45 [INFO] MyModule: Operation completed */
```

The default component is "Socket" if not overridden.

---

## Custom Logging Callbacks

### Basic Callback

Replace the default logger with your own:

```c
void my_logger(void *userdata, SocketLogLevel level,
               const char *component, const char *message)
{
    FILE *logfile = (FILE *)userdata;
    const char *level_str = SocketLog_levelname(level);
    
    fprintf(logfile, "[%s] %s: %s\n", level_str, component, message);
    fflush(logfile);
}

/* Register custom logger */
FILE *logfile = fopen("/var/log/myapp.log", "a");
SocketLog_setcallback(my_logger, logfile);
```

### Restoring Default Logger

```c
/* Pass NULL to restore default stderr/stdout logger */
SocketLog_setcallback(NULL, NULL);
```

### Syslog Integration

```c
#include <syslog.h>

static int level_to_syslog(SocketLogLevel level)
{
    switch (level) {
        case SOCKET_LOG_TRACE:
        case SOCKET_LOG_DEBUG: return LOG_DEBUG;
        case SOCKET_LOG_INFO:  return LOG_INFO;
        case SOCKET_LOG_WARN:  return LOG_WARNING;
        case SOCKET_LOG_ERROR: return LOG_ERR;
        case SOCKET_LOG_FATAL: return LOG_CRIT;
        default: return LOG_INFO;
    }
}

void syslog_callback(void *userdata, SocketLogLevel level,
                     const char *component, const char *message)
{
    (void)userdata;
    syslog(level_to_syslog(level), "[%s] %s", component, message);
}

/* Setup */
openlog("myapp", LOG_PID | LOG_NDELAY, LOG_DAEMON);
SocketLog_setcallback(syslog_callback, NULL);
```

### systemd Journal Integration

```c
#include <systemd/sd-journal.h>

void journal_callback(void *userdata, SocketLogLevel level,
                      const char *component, const char *message)
{
    int priority;
    (void)userdata;
    
    switch (level) {
        case SOCKET_LOG_TRACE:
        case SOCKET_LOG_DEBUG: priority = LOG_DEBUG; break;
        case SOCKET_LOG_INFO:  priority = LOG_INFO; break;
        case SOCKET_LOG_WARN:  priority = LOG_WARNING; break;
        case SOCKET_LOG_ERROR: priority = LOG_ERR; break;
        case SOCKET_LOG_FATAL: priority = LOG_CRIT; break;
        default: priority = LOG_INFO;
    }
    
    sd_journal_send("PRIORITY=%d", priority,
                    "SYSLOG_IDENTIFIER=%s", "myapp",
                    "COMPONENT=%s", component,
                    "MESSAGE=%s", message,
                    NULL);
}

SocketLog_setcallback(journal_callback, NULL);
```

---

## Structured Logging

For machine-parseable output (JSON, logfmt), use structured logging with key-value pairs:

### Basic Usage

```c
SocketLogField fields[] = {
    {"fd", "42"},
    {"bytes", "1024"},
    {"peer", "192.168.1.100"},
    {"latency_ms", "15"}
};

SocketLog_emit_structured(SOCKET_LOG_INFO, "Socket",
                          "Data received",
                          fields, 4);
```

### Convenience Macro

```c
SocketLog_emit_structured(SOCKET_LOG_INFO, "Socket",
                          "Connection established",
                          SOCKET_LOG_FIELDS(
                              {"fd", fd_str},
                              {"peer", peer_addr},
                              {"port", port_str}
                          ));
```

### Structured Callback for JSON Output

```c
void json_logger(void *userdata, SocketLogLevel level,
                 const char *component, const char *message,
                 const SocketLogField *fields, size_t field_count,
                 const SocketLogContext *context)
{
    FILE *out = (FILE *)userdata;
    
    fprintf(out, "{\"level\":\"%s\",\"component\":\"%s\",\"message\":\"%s\"",
            SocketLog_levelname(level), component, message);
    
    /* Add context if present */
    if (context && context->trace_id[0]) {
        fprintf(out, ",\"trace_id\":\"%s\"", context->trace_id);
    }
    if (context && context->request_id[0]) {
        fprintf(out, ",\"request_id\":\"%s\"", context->request_id);
    }
    
    /* Add structured fields */
    for (size_t i = 0; i < field_count; i++) {
        if (fields[i].key && fields[i].value) {
            fprintf(out, ",\"%s\":\"%s\"", fields[i].key, fields[i].value);
        }
    }
    
    fprintf(out, "}\n");
    fflush(out);
}

/* Register structured callback */
SocketLog_setstructuredcallback(json_logger, stdout);
```

### Fallback Behavior

If no structured callback is registered, `SocketLog_emit_structured()` formats fields as `key=value` pairs appended to the message and uses the regular callback:

```
2025-12-05 10:30:45 [INFO] Socket: Data received fd=42 bytes=1024 peer=192.168.1.100
```

---

## Correlation IDs and Context

For distributed tracing and request tracking, set thread-local context:

### Setting Context

```c
void handle_request(int client_fd, const char *trace_id)
{
    SocketLogContext ctx = {0};
    
    /* Set trace ID (e.g., from X-Request-ID header) */
    strncpy(ctx.trace_id, trace_id, SOCKET_LOG_ID_SIZE - 1);
    
    /* Generate request-specific ID */
    snprintf(ctx.request_id, SOCKET_LOG_ID_SIZE, "req-%d-%ld",
             client_fd, (long)time(NULL));
    
    ctx.connection_fd = client_fd;
    
    SocketLog_setcontext(&ctx);
    
    /* All logs in this thread now have context available */
    SOCKET_LOG_INFO_MSG("Processing request");
    
    /* ... handle request ... */
    
    /* Clear context when done */
    SocketLog_clearcontext();
}
```

### Accessing Context in Callbacks

```c
void context_aware_logger(void *userdata, SocketLogLevel level,
                          const char *component, const char *message)
{
    const SocketLogContext *ctx = SocketLog_getcontext();
    
    if (ctx && ctx->trace_id[0]) {
        fprintf(stderr, "[%s] trace=%s %s: %s\n",
                SocketLog_levelname(level), ctx->trace_id,
                component, message);
    } else {
        fprintf(stderr, "[%s] %s: %s\n",
                SocketLog_levelname(level), component, message);
    }
}
```

### Context Fields

| Field | Size | Description |
|-------|------|-------------|
| `trace_id` | 37 chars | Distributed trace ID (UUID format) |
| `request_id` | 37 chars | Request-specific ID |
| `connection_fd` | int | Associated file descriptor (-1 if none) |

---

## Thread Safety

All logging functions are thread-safe:

| Function | Thread Safety |
|----------|---------------|
| `SocketLog_emit()` | Yes (reads callback under mutex) |
| `SocketLog_emitf()` | Yes |
| `SocketLog_setcallback()` | Yes (mutex protected) |
| `SocketLog_setlevel()` | Yes (mutex protected) |
| `SocketLog_getlevel()` | Yes (mutex protected) |
| `SocketLog_setcontext()` | Yes (thread-local storage) |
| `SocketLog_getcontext()` | Yes (thread-local storage) |
| `SocketLog_clearcontext()` | Yes (thread-local storage) |
| `SocketLog_emit_structured()` | Yes |

**Note**: Context is per-thread. Each thread has its own independent context that does not affect other threads.

---

## Performance Considerations

### Level Check Before Formatting

Log level is checked before message formatting, avoiding expensive `snprintf()` calls for suppressed messages:

```c
/* This is efficient - no string formatting if level is suppressed */
SOCKET_LOG_DEBUG_MSG("Complex data: %s", expensive_to_string(data));
```

### Expensive Debug Logging

For computationally expensive debug output, check the level first:

```c
if (SocketLog_getlevel() <= SOCKET_LOG_DEBUG) {
    /* Only compute when DEBUG is enabled */
    char *hex_dump = hexdump(buffer, length);
    SOCKET_LOG_DEBUG_MSG("Packet contents:\n%s", hex_dump);
    free(hex_dump);
}
```

### Callback Lock Contention

The callback is read under a mutex, but this is typically very fast. For extremely high-throughput scenarios, consider:

1. Using a lock-free logging library as the backend
2. Buffering logs in the callback and flushing periodically
3. Using async I/O for log output

---

## Default Output Format

The default logger outputs to stdout (INFO and below) or stderr (WARN and above):

```
2025-12-05 10:30:45 [INFO] Socket: Message text
2025-12-05 10:30:46 [ERROR] SocketTLS: Handshake failed
```

Format: `<timestamp> [<level>] <component>: <message>`

---

## API Reference

### Types

```c
typedef enum SocketLogLevel {
    SOCKET_LOG_TRACE = 0,
    SOCKET_LOG_DEBUG,
    SOCKET_LOG_INFO,
    SOCKET_LOG_WARN,
    SOCKET_LOG_ERROR,
    SOCKET_LOG_FATAL
} SocketLogLevel;

typedef void (*SocketLogCallback)(void *userdata, SocketLogLevel level,
                                  const char *component, const char *message);

typedef struct SocketLogField {
    const char *key;
    const char *value;
} SocketLogField;

typedef struct SocketLogContext {
    char trace_id[37];
    char request_id[37];
    int connection_fd;
} SocketLogContext;
```

### Functions

| Function | Description |
|----------|-------------|
| `SocketLog_emit(level, component, message)` | Emit log message |
| `SocketLog_emitf(level, component, fmt, ...)` | Emit formatted message |
| `SocketLog_setcallback(cb, userdata)` | Set custom callback |
| `SocketLog_getcallback(userdata)` | Get current callback |
| `SocketLog_setlevel(level)` | Set minimum log level |
| `SocketLog_getlevel()` | Get current log level |
| `SocketLog_levelname(level)` | Get level name string |
| `SocketLog_setcontext(ctx)` | Set thread-local context |
| `SocketLog_getcontext()` | Get thread-local context |
| `SocketLog_clearcontext()` | Clear thread-local context |
| `SocketLog_setstructuredcallback(cb, userdata)` | Set structured callback |
| `SocketLog_emit_structured(level, component, msg, fields, count)` | Emit with fields |

### Macros

| Macro | Description |
|-------|-------------|
| `SOCKET_LOG_TRACE_MSG(fmt, ...)` | Log at TRACE level |
| `SOCKET_LOG_DEBUG_MSG(fmt, ...)` | Log at DEBUG level |
| `SOCKET_LOG_INFO_MSG(fmt, ...)` | Log at INFO level |
| `SOCKET_LOG_WARN_MSG(fmt, ...)` | Log at WARN level |
| `SOCKET_LOG_ERROR_MSG(fmt, ...)` | Log at ERROR level |
| `SOCKET_LOG_FATAL_MSG(fmt, ...)` | Log at FATAL level |
| `SOCKET_LOG_FIELDS(...)` | Create field array for structured logging |
| `SOCKET_LOG_COMPONENT` | Module component name (override before include) |
