---
name: dns
description: Async DNS resolution patterns with thread pool, caching, and event loop integration. Use when working on SocketDNS, DNS callbacks, caching, or files in src/dns/.
---

You are an expert C developer specializing in asynchronous DNS resolution, thread pool management, and event loop integration.

## Async DNS Architecture

```
SocketDNS_T
    ├── Thread Pool (worker threads for getaddrinfo)
    │   ├── Worker 1 ─► getaddrinfo() ─► callback/queue
    │   ├── Worker 2 ─► getaddrinfo() ─► callback/queue
    │   └── Worker N ─► getaddrinfo() ─► callback/queue
    ├── Request Queue (pending resolutions)
    ├── Result Queue (completed, for polling mode)
    ├── DNS Cache (TTL-based)
    │   └── HashTable<hostname, addrinfo+expiry>
    ├── Pipe/Eventfd (for poll notification)
    └── pthread_mutex_t (thread safety)
```

## Two Resolution Modes

### 1. Callback Mode (Worker Thread Context)

```c
// Callback invoked from worker thread - NOT main thread!
void dns_callback(SocketDNS_Request_T *req,
                  struct addrinfo *result,
                  int error,
                  void *userdata) {
    if (error != 0) {
        log_error("DNS failed: %s", gai_strerror(error));
        return;
    }

    // IMPORTANT: You're in a worker thread here!
    // Must synchronize with main thread for shared state
    pthread_mutex_lock(&app_mutex);
    enqueue_connection_attempt(result, userdata);
    pthread_cond_signal(&app_cond);
    pthread_mutex_unlock(&app_mutex);

    freeaddrinfo(result);
}

// Submit request
SocketDNS_resolve(dns, "example.com", 443, dns_callback, userdata);
```

### 2. Polling Mode (Main Thread Integration)

```c
// Submit with NULL callback = polling mode
SocketDNS_Request_T *req = SocketDNS_resolve(dns, "example.com", 443,
                                              NULL, NULL);

// Get pollable fd for event loop integration
int dns_fd = SocketDNS_pollfd(dns);
SocketPoll_add(poll, dns_fd, POLL_READ, dns);

// In event loop
void handle_dns_readable(SocketDNS_T dns) {
    int n = SocketDNS_check(dns);  // Process completed requests

    // Check specific request
    if (SocketDNS_is_complete(dns, req)) {
        int err = SocketDNS_geterror(dns, req);
        if (err == 0) {
            struct addrinfo *result = SocketDNS_getresult(dns, req);
            connect_to_address(result);
            freeaddrinfo(result);
        }
        SocketDNS_free_request(dns, req);
    }
}
```

## DNS Cache Management

```c
// Configure cache
SocketDNS_cache_set_max_entries(dns, 10000);
SocketDNS_cache_set_min_ttl(dns, 60);      // Min 60s
SocketDNS_cache_set_max_ttl(dns, 3600);    // Max 1 hour
SocketDNS_cache_set_negative_ttl(dns, 30); // Cache failures 30s

// Manual cache operations
SocketDNS_cache_clear(dns);
SocketDNS_cache_remove(dns, "example.com");

// Cache statistics
SocketDNS_CacheStats stats;
SocketDNS_cache_stats(dns, &stats);
printf("Hits: %lu, Misses: %lu, Hit rate: %.2f%%\n",
       stats.hits, stats.misses,
       100.0 * stats.hits / (stats.hits + stats.misses));
```

## Synchronous Resolution (with Timeout)

```c
// Blocking resolve with guaranteed timeout
// Uses worker thread internally but blocks caller
struct addrinfo *result = SocketDNS_resolve_sync(dns, "example.com", 443,
                                                  5000);  // 5s timeout
if (!result) {
    log_error("DNS failed: %s", SocketDNS_geterror_string(dns));
    return -1;
}

// Use result
connect_to_first(result);
freeaddrinfo(result);
```

## IPv4/IPv6 Preference

```c
// Prefer IPv6 (for Happy Eyeballs)
SocketDNS_prefer_ipv6(dns, true);

// Get both address families
SocketDNS_set_family(dns, AF_UNSPEC);  // Default: both
SocketDNS_set_family(dns, AF_INET);    // IPv4 only
SocketDNS_set_family(dns, AF_INET6);   // IPv6 only
```

## Custom Nameservers

```c
// Use specific nameservers (bypasses /etc/resolv.conf)
const char *servers[] = {"8.8.8.8", "8.8.4.4", NULL};
SocketDNS_set_nameservers(dns, servers);

// Reset to system default
SocketDNS_set_nameservers(dns, NULL);
```

## Thread Pool Configuration

```c
// Create with specific thread count
SocketDNS_T dns = SocketDNS_new(arena, num_threads);

// Default: 4 threads (reasonable for most workloads)
// High-volume: 8-16 threads
// Low-latency: Consider per-core thread

// Queue depth limits (DoS protection)
SocketDNS_set_max_pending(dns, 1000);
```

## Integration with Happy Eyeballs

```c
// DNS resolution is first step in Happy Eyeballs
void start_connection(const char *host, int port) {
    // Start async DNS for both families
    SocketDNS_set_family(dns, AF_UNSPEC);

    req = SocketDNS_resolve(dns, host, port, NULL, NULL);

    // When complete, pass to Happy Eyeballs
    // which will race IPv6 vs IPv4
}

void on_dns_complete(SocketDNS_Request_T *req) {
    struct addrinfo *addrs = SocketDNS_getresult(dns, req);

    // Separate IPv6 and IPv4 addresses
    struct addrinfo *ipv6_list = filter_family(addrs, AF_INET6);
    struct addrinfo *ipv4_list = filter_family(addrs, AF_INET);

    // Start Happy Eyeballs connection racing
    SocketHappyEyeballs_start(he, ipv6_list, ipv4_list);

    freeaddrinfo(addrs);
}
```

## Error Handling

```c
// Error codes from gai_strerror()
switch (SocketDNS_geterror(dns, req)) {
    case 0:
        // Success
        break;
    case EAI_NONAME:
        // Host not found
        break;
    case EAI_AGAIN:
        // Temporary failure - retry
        break;
    case EAI_FAIL:
        // Permanent failure
        break;
    case EAI_MEMORY:
        // Out of memory
        break;
    default:
        log_error("DNS error: %s",
                  gai_strerror(SocketDNS_geterror(dns, req)));
}
```

## DoS Protection

```c
// Limit concurrent requests
SocketDNS_set_max_pending(dns, 1000);

// Request timeout (kills hung getaddrinfo)
SocketDNS_set_request_timeout(dns, 30000);  // 30s

// Rate limiting per source
SocketDNS_set_rate_limit(dns, 100, 1000);  // 100 req/sec

// Negative caching prevents repeated failures
SocketDNS_cache_set_negative_ttl(dns, 60);
```

## Thread Safety Notes

```c
// SocketDNS_T is thread-safe for:
//   - SocketDNS_resolve() from any thread
//   - SocketDNS_check() from one thread (typically main)
//   - SocketDNS_cache_* from any thread

// Callbacks execute in worker threads!
// Must synchronize access to shared application state

// Request handles (SocketDNS_Request_T*) are:
//   - Valid until SocketDNS_free_request() called
//   - Safe to check from main thread
//   - NOT safe to use after free
```

## Exception Handling

```c
SocketDNS_Request_T *req = NULL;
TRY {
    req = SocketDNS_resolve(dns, hostname, port, NULL, NULL);
    if (!req) {
        RAISE(SocketDNS_Failed);
    }

    // Wait for completion (in real code, use event loop)
    while (!SocketDNS_is_complete(dns, req)) {
        SocketDNS_check(dns);
    }

    if (SocketDNS_geterror(dns, req) != 0) {
        RAISE(SocketDNS_Failed);
    }

} EXCEPT(SocketDNS_Failed) {
    log_error("DNS resolution failed");
} FINALLY {
    if (req) SocketDNS_free_request(dns, req);
} END_TRY;
```

## Files Reference

| File | Purpose |
|------|---------|
| `include/dns/SocketDNS.h` | DNS resolver API |
| `src/dns/SocketDNS.c` | Main implementation |
| `src/dns/SocketDNS-internal.c` | Internal helpers |
| `src/test/test_socketdns.c` | DNS tests |
