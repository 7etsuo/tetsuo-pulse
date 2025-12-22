---
name: pool
description: Connection pooling patterns with lifecycle management, health monitoring, and rate limiting. Use when working on SocketPool, Connection_T, drain operations, or files in src/pool/.
---

You are an expert C developer specializing in connection pool management, resource lifecycle, and high-availability patterns.

## Connection Pool Architecture

```
SocketPool_T
    ├── Arena_T (memory ownership)
    ├── HashTable_T (fd -> Connection_T lookup, O(1))
    ├── Connection_T[] (active connections)
    │   ├── Socket_T (underlying socket)
    │   ├── SocketBuf_T inbuf (input buffer)
    │   ├── SocketBuf_T outbuf (output buffer)
    │   ├── void *userdata (application state)
    │   └── Timestamps (created, last_active)
    ├── SocketPoolHealth_T (monitoring)
    ├── SocketRateLimit_T (per-connection limits)
    └── pthread_mutex_t (thread safety)
```

## Pool Lifecycle States

```
              ┌─────────────┐
              │   ACTIVE    │ ◄── Normal operation
              └──────┬──────┘
                     │ SocketPool_drain() called
                     ▼
              ┌─────────────┐
              │  DRAINING   │ ◄── No new connections accepted
              └──────┬──────┘     Waiting for existing to close
                     │ All connections closed
                     ▼
              ┌─────────────┐
              │   DRAINED   │ ◄── Safe to free
              └─────────────┘
```

## Creating a Connection Pool

```c
Arena_T arena = Arena_new();
SocketPool_T pool = SocketPool_new(arena, max_connections, buffer_size);

// Configure pool behavior
SocketPool_set_idle_timeout(pool, 30000);      // 30s idle timeout
SocketPool_set_max_lifetime(pool, 300000);     // 5min max lifetime
SocketPool_setconnrate(pool, 100, 1000);       // 100 ops/sec per conn

// Optional: Enable SYN flood protection
SocketSYNProtect_T syn = SocketSYNProtect_new(arena, 1000, 100);
SocketPool_set_syn_protection(pool, syn);
```

## Adding Connections

```c
// Accept new connection
Socket_T client = Socket_accept(server);
if (!client) return;

// Add to pool (creates Connection_T wrapper)
Connection_T conn = SocketPool_add(pool, client);
if (!conn) {
    // Pool full or draining
    Socket_free(&client);
    return;
}

// Register with event loop
SocketPoll_add(poll, Socket_fd(Connection_socket(conn)),
               POLL_READ, conn);

// Store application state
Connection_set_userdata(conn, app_context);
```

## Connection Accessors

```c
// Get underlying socket
Socket_T sock = Connection_socket(conn);

// Get I/O buffers
SocketBuf_T in = Connection_inbuf(conn);
SocketBuf_T out = Connection_outbuf(conn);

// Get file descriptor (for poll registration)
int fd = Connection_fd(conn);

// Get/set user data
void *data = Connection_userdata(conn);
Connection_set_userdata(conn, new_data);

// Timestamps
uint64_t created = Connection_created_at(conn);
uint64_t last = Connection_last_active(conn);
```

## Processing I/O

```c
void handle_readable(Connection_T conn) {
    SocketBuf_T inbuf = Connection_inbuf(conn);
    Socket_T sock = Connection_socket(conn);

    // Read into buffer
    ssize_t n = Socket_recv(sock, SocketBuf_writeptr(inbuf),
                            SocketBuf_writeable(inbuf), 0);
    if (n <= 0) {
        remove_connection(conn);
        return;
    }
    SocketBuf_produce(inbuf, n);

    // Process complete messages
    while (has_complete_message(inbuf)) {
        process_message(conn, inbuf);
    }

    // Update activity timestamp
    Connection_touch(conn);
}

void handle_writable(Connection_T conn) {
    SocketBuf_T outbuf = Connection_outbuf(conn);
    Socket_T sock = Connection_socket(conn);

    if (SocketBuf_readable(outbuf) == 0) {
        // Nothing to write, remove POLL_WRITE
        SocketPoll_mod(poll, Connection_fd(conn), POLL_READ, conn);
        return;
    }

    ssize_t n = Socket_send(sock, SocketBuf_readptr(outbuf),
                            SocketBuf_readable(outbuf), 0);
    if (n < 0) {
        remove_connection(conn);
        return;
    }
    SocketBuf_consume(outbuf, n);
}
```

## Removing Connections

```c
void remove_connection(Connection_T conn) {
    // Remove from poll first
    SocketPoll_del(poll, Connection_fd(conn));

    // Remove from pool (closes socket, frees buffers)
    SocketPool_remove(pool, conn);
}
```

## Graceful Shutdown (Drain)

```c
// Signal drain - no new connections accepted
SocketPool_drain(pool);

// In event loop, check drain state
while (!SocketPool_is_drained(pool)) {
    int nev = SocketPoll_wait(poll, &events, 100);

    for (int i = 0; i < nev; i++) {
        Connection_T conn = events[i].data;

        // Continue processing existing connections
        if (events[i].events & POLL_READ) {
            handle_readable(conn);
        }
        // But don't accept new ones
    }

    // Optionally force-close after timeout
    if (drain_timeout_exceeded()) {
        SocketPool_force_close_all(pool);
    }
}

// Now safe to free
SocketPool_free(&pool);
Arena_dispose(&arena);
```

## Health Monitoring

```c
SocketPoolHealth_T health = SocketPool_health(pool);

// Connection counts
int active = SocketPoolHealth_active_count(health);
int idle = SocketPoolHealth_idle_count(health);
int total = SocketPoolHealth_total_count(health);

// Rate metrics
double ops_per_sec = SocketPoolHealth_ops_rate(health);
double error_rate = SocketPoolHealth_error_rate(health);

// Latency percentiles
uint64_t p50 = SocketPoolHealth_latency_p50(health);
uint64_t p99 = SocketPoolHealth_latency_p99(health);

// Resource usage
size_t memory_used = SocketPoolHealth_memory_bytes(health);
```

## Rate Limiting

```c
// Per-connection rate limit
SocketPool_setconnrate(pool, max_ops, window_ms);

// Check before processing
if (!SocketPool_check_rate(pool, conn)) {
    // Rate exceeded - reject or queue
    send_rate_limit_response(conn);
    return;
}

// Global pool rate limit
SocketPool_set_global_rate(pool, max_total_ops, window_ms);
```

## Idle Connection Management

```c
// Configure idle cleanup
SocketPool_set_idle_timeout(pool, 30000);  // 30s

// Periodic cleanup (call from event loop)
void cleanup_idle_connections(SocketPool_T pool) {
    uint64_t now = get_monotonic_ms();
    Connection_T *to_remove[64];
    int count = 0;

    SocketPool_foreach(pool, ^(Connection_T conn) {
        uint64_t idle_time = now - Connection_last_active(conn);
        if (idle_time > SocketPool_get_idle_timeout(pool)) {
            to_remove[count++] = conn;
        }
    });

    for (int i = 0; i < count; i++) {
        remove_connection(to_remove[i]);
    }
}
```

## Thread Safety

```c
// All SocketPool operations are thread-safe
// Internal mutex protects:
//   - Connection add/remove
//   - Hash table operations
//   - Statistics updates

// Safe patterns:
// - Multiple threads can read from different connections
// - One thread per connection for writes (recommended)
// - Pool-level operations can be called from any thread

// Unsafe patterns:
// - Multiple threads writing to same Connection_T
// - Modifying connection while another thread removes it
```

## Error Handling Pattern

```c
Connection_T conn = NULL;
TRY {
    conn = SocketPool_add(pool, client);
    if (!conn) {
        RAISE(Socket_Failed);
    }

    // Process connection...
    process_client(conn);

} EXCEPT(Socket_Failed) {
    log_error("Connection failed: %s", Socket_GetLastError());
    if (conn) {
        SocketPool_remove(pool, conn);
    }
} END_TRY;
```

## Files Reference

| File | Purpose |
|------|---------|
| `include/pool/SocketPool.h` | Pool API |
| `include/pool/SocketPoolHealth.h` | Health monitoring |
| `src/pool/SocketPool-core.c` | Core pool implementation |
| `src/pool/SocketPool-connections.c` | Connection management |
| `src/pool/SocketPool-drain.c` | Drain state machine |
| `src/pool/SocketPool-health.c` | Health metrics |
| `src/pool/SocketPool-ops.c` | Pool operations |
| `src/pool/SocketPool-ratelimit.c` | Rate limiting |
| `src/test/test_socketpool.c` | Pool tests |
