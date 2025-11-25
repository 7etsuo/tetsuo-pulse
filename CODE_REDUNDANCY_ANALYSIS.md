# Code Redundancy Analysis

This document identifies code redundancy patterns found in the tetsuo-socket codebase. Redundant code increases maintenance burden, risks inconsistent bug fixes, and makes the codebase harder to understand.

## Summary

The analysis found **11 categories of redundant code** across the Socket and SocketDgram modules, which share significant functionality but have duplicated implementations.

---

## 1. Timeout Default Getters/Setters (Exact Duplicates)

### Files Affected
- `src/socket/Socket-options.c` (lines 134-166)
- `src/socket/SocketCommon.c` (lines 262-300)

### Description
`Socket_timeouts_getdefaults()` and `Socket_timeouts_setdefaults()` are **exact duplicates** of `SocketCommon_timeouts_getdefaults()` and `SocketCommon_timeouts_setdefaults()`.

### Recommendation
The `Socket_*` versions should call the `SocketCommon_*` implementations instead of duplicating the code:
```c
void Socket_timeouts_getdefaults(SocketTimeouts_T *timeouts) {
    SocketCommon_timeouts_getdefaults(timeouts);
}

void Socket_timeouts_setdefaults(const SocketTimeouts_T *timeouts) {
    SocketCommon_timeouts_setdefaults(timeouts);
}
```

---

## 2. Bind Error Handling Functions (Functionally Identical)

### Files Affected
- `src/socket/Socket-bind.c` (`handle_bind_error`, lines 51-69)
- `src/socket/SocketDgram-bind.c` (`handle_dgram_bind_error`, lines 279-296)
- `src/socket/SocketCommon-bind.c` (`SocketCommon_handle_bind_error`, lines 108-135)

### Description
Three near-identical implementations of bind error handling:
- `handle_bind_error()` in Socket-bind.c
- `handle_dgram_bind_error()` in SocketDgram-bind.c (near duplicate of handle_bind_error)
- `SocketCommon_handle_bind_error()` in SocketCommon-bind.c (slightly different)

### Recommendation
Consolidate into a single `SocketCommon_handle_bind_error()` function and call it from both Socket and SocketDgram modules.

---

## 3. Wildcard Host Normalization (Logically Equivalent)

### Files Affected
- `src/socket/SocketDgram-bind.c` (`normalize_dgram_host`, lines 403-410)
- `src/socket/SocketCommon-validate.c` (`SocketCommon_normalize_wildcard_host`, lines 72-78)

### Description
`normalize_dgram_host()` duplicates `SocketCommon_normalize_wildcard_host()`, implementing equivalent logic with inverted conditional structure:
```c
// SocketDgram-bind.c - normalize_dgram_host
if (host != NULL && strcmp(host, "0.0.0.0") != 0 && strcmp(host, "::") != 0)
    return host;
return NULL;

// SocketCommon-validate.c - SocketCommon_normalize_wildcard_host
if (host == NULL || strcmp(host, "0.0.0.0") == 0 || strcmp(host, "::") == 0)
    return NULL;
return host;
```

### Recommendation
Remove `normalize_dgram_host()` and use `SocketCommon_normalize_wildcard_host()` directly in SocketDgram-bind.c.

---

## 4. EAGAIN/EWOULDBLOCK Check Functions (Duplicated Helpers)

### Files Affected
- `src/socket/SocketIO.c` (`is_wouldblock_error`, lines 71-74)
- `src/socket/SocketIO-tls.c` (`socket_is_recoverable_io_error`, lines 71-75)

### Description
Two identical inline helper functions checking for EAGAIN/EWOULDBLOCK:
```c
// Both check: return errno == EAGAIN || errno == EWOULDBLOCK;
```

Additionally, the same pattern `(errno == EAGAIN || errno == EWOULDBLOCK)` is repeated in:
- `SocketDgram.c` (lines 195, 212)
- `SocketDgram-bind.c` (lines 147, 176)
- `SocketDgram-iov.c` (lines 75, 107)
- `Socket-accept.c` (line 224)
- `Socket-iov.c` (multiple lines)

### Recommendation
Export a single `SocketCommon_is_wouldblock_error()` function and use it throughout the codebase.

---

## 5. Socket State Query Functions (Similar Implementations)

### Files Affected
- `src/socket/Socket-state.c` (`Socket_isconnected`, `Socket_isbound`)
- `src/socket/SocketDgram-state.c` (`SocketDgram_isconnected`, `SocketDgram_isbound`)

### Description
`SocketDgram_isconnected()` and `Socket_isconnected()` share the same core logic:
- Use `getpeername()` to check connection state
- Handle ENOTCONN error
- Return 1/0 based on result

`SocketDgram_isbound()` duplicates inline the logic from `check_bound_ipv4()` and `check_bound_ipv6()` static functions defined in Socket-state.c.

### Recommendation
Create shared helper functions in SocketCommon:
```c
int SocketCommon_isconnected(SocketBase_T base);
int SocketCommon_isbound(SocketBase_T base);
```

---

## 6. Accessor Functions (Trivial Duplicates)

### Files Affected
- `src/socket/Socket-state.c` (lines 172-204)
- `src/socket/SocketDgram-state.c` (lines 52-71)

### Description
Nearly identical accessor implementations:
```c
// Both modules have essentially:
Socket_fd() / SocketDgram_fd()         -> SocketBase_fd(socket->base)
Socket_getlocaladdr() / SocketDgram_getlocaladdr() -> socket->base->localaddr
Socket_getlocalport() / SocketDgram_getlocalport() -> socket->base->localport
```

### Recommendation
These are intentional API differences for type safety. However, the implementation could use shared macros or inline functions to reduce duplication.

---

## 7. sendall/recvall Implementations (Pattern Duplicates)

### Files Affected
- `src/socket/Socket-all.c` (`Socket_sendall`, `Socket_recvall`)
- `src/socket/SocketDgram-iov.c` (`SocketDgram_sendall`, `SocketDgram_recvall`)

### Description
Both implement the same "loop until all data sent/received" pattern:
```c
TRY while (total < len) {
    sent = Socket_send/SocketDgram_send(...);
    if (sent == 0) return total;
    total += sent;
}
EXCEPT(...) RERAISE;
END_TRY;
```

### Recommendation
While the exception types differ, a macro-based solution or template pattern could reduce duplication:
```c
#define IMPLEMENT_SENDALL(name, send_fn, except_type) \
ssize_t name(T socket, const void *buf, size_t len) { \
    ... common implementation calling send_fn ... \
}
```

---

## 8. sendvall/recvvall IOV Advancement Logic

### Files Affected
- `src/socket/Socket-iov-all.c` (lines 26-157)
- `src/socket/SocketDgram-iov.c` (lines 191-325)

### Description
Both Socket-iov-all.c and SocketDgram-iov.c have complex iovec advancement logic after partial sends/receives. While `SocketCommon_advance_iov()` exists in SocketCommon-iov.c, Socket-iov-all.c doesn't use it and implements its own inline logic.

### Recommendation
Refactor Socket-iov-all.c to use `SocketCommon_advance_iov()` and `SocketCommon_calculate_total_iov_len()`.

---

## 9. Try Bind Addresses Functions

### Files Affected
- `src/socket/SocketDgram-bind.c` (`try_dgram_bind_addresses`, lines 248-271)
- `src/socket/SocketCommon-bind.c` (`SocketCommon_try_bind_resolved_addresses`, lines 68-96)

### Description
`try_dgram_bind_addresses()` implements its own bind loop with special IPv6 handling, duplicating most of the logic in `SocketCommon_try_bind_resolved_addresses()`.

### Recommendation
Add IPv6 dual-stack handling to `SocketCommon_try_bind_resolved_addresses()` or provide a callback mechanism.

---

## 10. Setup Hints Helper Functions

### Files Affected
- `src/socket/SocketDgram-bind.c` (`setup_sendto_hints`, `setup_dgram_bind_hints`, `setup_dgram_connect_hints`)

### Description
Multiple one-liner functions that just call `SocketCommon_setup_hints()` with different parameters:
```c
static void setup_sendto_hints(struct addrinfo *hints) {
    SocketCommon_setup_hints(hints, SOCKET_DGRAM_TYPE, 0);
}
static void setup_dgram_bind_hints(struct addrinfo *hints) {
    SocketCommon_setup_hints(hints, SOCKET_DGRAM_TYPE, SOCKET_AI_PASSIVE);
}
```

### Recommendation
These wrappers add minimal value and could be replaced with direct calls to `SocketCommon_setup_hints()`.

---

## 11. Get Socket Family Functions

### Files Affected
- `src/socket/SocketDgram-options.c` (`get_socket_domain`, lines 113-119)
- `src/socket/SocketDgram-bind.c` (`get_dgram_socket_family`, lines 330-335)

### Description
Both functions are thin wrappers around `SocketCommon_get_family()`:
```c
static int get_socket_domain(T socket) {
    return SocketCommon_get_family(socket->base, true, SocketDgram_Failed);
}
```

### Recommendation
These are acceptable thin wrappers for readability, but could be consolidated into a single shared helper.

---

## Priority Recommendations

### High Priority (Clear Waste)
1. **Timeout getters/setters** - Replace duplicates with delegating calls
2. **Bind error handling** - Consolidate into single SocketCommon function
3. **Wildcard host normalization** - Use existing SocketCommon function

### Medium Priority (Maintainability)
4. **EAGAIN/EWOULDBLOCK checks** - Create shared helper
5. **isconnected/isbound** - Create shared base implementations
6. **sendvall/recvvall IOV advancement** - Use SocketCommon_advance_iov

### Low Priority (Minor Cleanup)
7. **Setup hints helpers** - Could be inlined
8. **get_socket_family wrappers** - Acceptable as-is

---

## Estimated Impact

Addressing high-priority items would:
- Remove ~150 lines of duplicate code
- Ensure consistent error handling across modules
- Reduce risk of divergent bug fixes
- Improve code maintainability

---

*Analysis generated by code redundancy review*
