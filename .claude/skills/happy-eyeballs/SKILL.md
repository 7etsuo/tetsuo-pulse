---
name: happy-eyeballs
description: RFC 8305 Happy Eyeballs v2 dual-stack connection racing implementation. Use when working on IPv4/IPv6 fallback, connection racing, or files containing HappyEyeballs.
---

You are an expert C developer specializing in Happy Eyeballs v2 (RFC 8305) implementation for fast, reliable dual-stack TCP connection establishment.

## Happy Eyeballs Overview

Happy Eyeballs solves the problem of slow fallback when IPv6 is broken or slow. Instead of waiting for IPv6 timeout before trying IPv4, it races both in parallel with a small head start for IPv6.

```
Timeline (RFC 8305):

T=0ms    Start IPv6 connection attempt
         │
T=250ms  Start IPv4 connection attempt (if IPv6 not connected)
         │
         ├── IPv6 connects first → Use IPv6, cancel IPv4
         │
         └── IPv4 connects first → Use IPv4, cancel IPv6
```

## Architecture

```
SocketHappyEyeballs_T
    ├── IPv6 Addresses (sorted by preference)
    ├── IPv4 Addresses (sorted by preference)
    ├── Active Attempts (socket + state per address)
    ├── Connection Delay Timer (250ms default)
    ├── Resolution Delay Timer (50ms for DNS)
    └── Winner Socket (first successful)

State Machine:
    IDLE → WAITING_DNS → CONNECTING → CONNECTED/FAILED
```

## RFC 8305 Algorithm

### Step 1: Address Sorting

```c
typedef struct AddrEntry {
    struct sockaddr_storage addr;
    int family;       // AF_INET or AF_INET6
    int precedence;   // From RFC 6724
    bool attempted;
    Socket_T socket;
} AddrEntry_T;

// Sort addresses per RFC 6724 (prefer IPv6, then by precedence)
void sort_addresses(AddrEntry_T *addrs, int count) {
    // 1. Separate IPv6 and IPv4
    // 2. Sort each list by precedence
    // 3. Interleave: IPv6[0], IPv4[0], IPv6[1], IPv4[1], ...

    AddrEntry_T *ipv6[count], *ipv4[count];
    int n6 = 0, n4 = 0;

    for (int i = 0; i < count; i++) {
        if (addrs[i].family == AF_INET6) {
            ipv6[n6++] = &addrs[i];
        } else {
            ipv4[n4++] = &addrs[i];
        }
    }

    // Interleave for racing
    int out = 0;
    for (int i = 0; i < MAX(n6, n4); i++) {
        if (i < n6) sorted[out++] = *ipv6[i];
        if (i < n4) sorted[out++] = *ipv4[i];
    }
}
```

### Step 2: Connection Racing

```c
#define CONNECTION_ATTEMPT_DELAY_MS  250  // RFC 8305 recommendation
#define RESOLUTION_DELAY_MS          50   // Wait for both A/AAAA

typedef struct HappyEyeballs {
    AddrEntry_T *addresses;
    int addr_count;
    int next_attempt;
    Socket_T winner;
    SocketPoll_T poll;
    uint64_t attempt_timer;
} *SocketHappyEyeballs_T;

Socket_T happy_eyeballs_connect(SocketHappyEyeballs_T he,
                                 const char *host, int port,
                                 int timeout_ms) {
    // Phase 1: DNS Resolution (parallel A and AAAA queries)
    resolve_addresses(he, host, port);

    // Phase 2: Sort addresses (interleave IPv6/IPv4)
    sort_addresses(he->addresses, he->addr_count);

    // Phase 3: Start first connection
    start_connection_attempt(he, 0);
    he->attempt_timer = get_monotonic_ms() + CONNECTION_ATTEMPT_DELAY_MS;

    // Phase 4: Event loop
    while (!he->winner && he->next_attempt < he->addr_count) {
        int remaining = timeout_ms - elapsed_ms(start_time);
        if (remaining <= 0) break;

        // Wait for events or timer
        int delay = MIN(remaining, time_until(he->attempt_timer));
        SocketEvent_T *events;
        int n = SocketPoll_wait(he->poll, &events, delay);

        // Check for successful connections
        for (int i = 0; i < n; i++) {
            if (events[i].events & POLL_WRITE) {
                // Check if connect() succeeded
                int err = get_socket_error(events[i].fd);
                if (err == 0) {
                    he->winner = find_socket_by_fd(he, events[i].fd);
                    cancel_other_attempts(he);
                    return he->winner;
                } else {
                    // This attempt failed, continue
                    close_attempt(he, events[i].fd);
                }
            }
        }

        // Timer expired - start next attempt
        if (get_monotonic_ms() >= he->attempt_timer) {
            if (he->next_attempt < he->addr_count) {
                start_connection_attempt(he, he->next_attempt++);
                he->attempt_timer = get_monotonic_ms() + CONNECTION_ATTEMPT_DELAY_MS;
            }
        }
    }

    // All attempts failed
    return NULL;
}
```

### Step 3: Starting Attempts

```c
void start_connection_attempt(SocketHappyEyeballs_T he, int index) {
    AddrEntry_T *entry = &he->addresses[index];

    // Create non-blocking socket
    Socket_T sock = Socket_new(entry->family, SOCK_STREAM, 0);
    Socket_setnonblocking(sock, true);

    // Start async connect
    int ret = connect(Socket_fd(sock),
                      (struct sockaddr *)&entry->addr,
                      entry->family == AF_INET6 ?
                          sizeof(struct sockaddr_in6) :
                          sizeof(struct sockaddr_in));

    if (ret == 0) {
        // Immediate success (rare, but possible on localhost)
        he->winner = sock;
        return;
    }

    if (errno != EINPROGRESS) {
        // Immediate failure
        Socket_free(&sock);
        return;
    }

    // In progress - register for write event (connect completion)
    entry->socket = sock;
    entry->attempted = true;
    SocketPoll_add(he->poll, Socket_fd(sock), POLL_WRITE, entry);
}
```

### Step 4: Cancellation

```c
void cancel_other_attempts(SocketHappyEyeballs_T he) {
    for (int i = 0; i < he->addr_count; i++) {
        if (he->addresses[i].socket &&
            he->addresses[i].socket != he->winner) {

            SocketPoll_del(he->poll, Socket_fd(he->addresses[i].socket));
            Socket_free(&he->addresses[i].socket);
        }
    }
}
```

## Integration with DNS

```c
// Parallel DNS resolution with Resolution Delay
void resolve_with_happy_eyeballs(const char *host, int port,
                                  SocketHappyEyeballs_T he) {
    SocketDNS_Request_T *req6, *req4;

    // Start both queries
    req6 = SocketDNS_resolve_family(dns, host, port, AF_INET6, NULL, NULL);
    req4 = SocketDNS_resolve_family(dns, host, port, AF_INET, NULL, NULL);

    uint64_t start = get_monotonic_ms();

    // Wait up to RESOLUTION_DELAY for both
    while (get_monotonic_ms() - start < RESOLUTION_DELAY_MS) {
        SocketDNS_check(dns);

        if (SocketDNS_is_complete(dns, req6) &&
            SocketDNS_is_complete(dns, req4)) {
            break;  // Both complete
        }
    }

    // Process whatever we have
    if (SocketDNS_is_complete(dns, req6)) {
        add_addresses(he, SocketDNS_getresult(dns, req6));
    }
    if (SocketDNS_is_complete(dns, req4)) {
        add_addresses(he, SocketDNS_getresult(dns, req4));
    }

    // If we have addresses, start connecting
    // Late DNS results can still add addresses mid-race
}
```

## Timing Parameters (RFC 8305)

```c
// Recommended values
#define CONNECTION_ATTEMPT_DELAY_MS  250   // Between attempts
#define RESOLUTION_DELAY_MS          50    // Wait for slower DNS
#define FIRST_ADDRESS_FAMILY_DELAY   0     // No delay for preferred family

// Adjustable based on network conditions
typedef struct HEConfig {
    int attempt_delay_ms;    // 250ms default
    int resolution_delay_ms; // 50ms default
    bool prefer_ipv6;        // true by default
    int max_attempts;        // Limit parallel sockets
} HEConfig_T;
```

## Error Handling

```c
typedef enum {
    HE_SUCCESS = 0,
    HE_DNS_FAILED,        // No addresses resolved
    HE_ALL_FAILED,        // All connection attempts failed
    HE_TIMEOUT,           // Overall timeout
    HE_CANCELLED,         // User cancelled
} HEResult;

HEResult happy_eyeballs_get_error(SocketHappyEyeballs_T he) {
    if (he->winner) return HE_SUCCESS;
    if (he->addr_count == 0) return HE_DNS_FAILED;
    if (he->all_attempted) return HE_ALL_FAILED;
    return HE_TIMEOUT;
}

// Get detailed per-attempt errors
void happy_eyeballs_get_attempt_errors(SocketHappyEyeballs_T he,
                                        int *errors, int *count) {
    for (int i = 0; i < he->addr_count; i++) {
        if (he->addresses[i].attempted) {
            errors[*count++] = he->addresses[i].error;
        }
    }
}
```

## State Caching (RFC 8305 Section 6)

```c
// Remember which family worked for a host
typedef struct {
    char hostname[256];
    int preferred_family;   // AF_INET or AF_INET6
    uint64_t timestamp;
} HECacheEntry_T;

// Check cache before racing
int get_cached_family(const char *host) {
    HECacheEntry_T *entry = cache_lookup(host);
    if (entry && !cache_expired(entry)) {
        return entry->preferred_family;
    }
    return AF_UNSPEC;  // No preference, race both
}

// Update cache on success
void cache_successful_family(const char *host, int family) {
    cache_put(host, family, get_monotonic_ms());
}
```

## Thread Safety

```c
// SocketHappyEyeballs_T is NOT thread-safe
// Use one instance per connection attempt
// Can run multiple instances in parallel from different threads

// Safe pattern:
void connect_async(const char *host, int port, ConnectCallback cb) {
    // Each task gets its own HE instance
    Task_T task = Task_new(^{
        SocketHappyEyeballs_T he = SocketHappyEyeballs_new(arena);
        Socket_T sock = happy_eyeballs_connect(he, host, port, 30000);
        cb(sock);
        SocketHappyEyeballs_free(&he);
    });
    Task_start(task);
}
```

## Files Reference

| File | Purpose |
|------|---------|
| `include/socket/SocketHappyEyeballs.h` | Happy Eyeballs API |
| `src/socket/SocketHappyEyeballs.c` | Main implementation |
| `src/socket/SocketHappyEyeballs-sort.c` | Address sorting (RFC 6724) |
| `src/socket/SocketHappyEyeballs-cache.c` | Family caching |
| `src/test/test_happy_eyeballs.c` | Racing tests |
