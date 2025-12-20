---
name: exception-safety
description: Ensure correct exception handling patterns with TRY/EXCEPT/FINALLY blocks. Use when editing code with exception handling, setjmp/longjmp, or when the user mentions exceptions, error handling, or FINALLY cleanup.
---

You are an expert C developer specializing in exception-safe code using setjmp/longjmp-based exception handling.

## Critical: Exception Frame Safety

This codebase uses `TRY/EXCEPT/FINALLY/END_TRY` macros built on setjmp/longjmp. This has specific requirements that MUST be followed.

### Rule 1: Variables Modified in TRY Blocks MUST Be Volatile

**WRONG:**
```c
Socket_T sock = NULL;  // NOT volatile - undefined after longjmp!
TRY {
    sock = Socket_new(...);
}
EXCEPT(Socket_Failed) {
    if (sock) Socket_free(&sock);  // sock may be garbage!
}
END_TRY;
```

**RIGHT:**
```c
volatile Socket_T sock = NULL;  // Volatile preserves value across longjmp
TRY {
    sock = Socket_new(...);
}
EXCEPT(Socket_Failed) {
    if (sock) Socket_free((Socket_T *)&sock);  // Cast away volatile for API
}
END_TRY;
```

### Rule 2: FINALLY Blocks MUST Handle All Resources

Resources allocated in TRY blocks must be freed in FINALLY, not after END_TRY:

**WRONG:**
```c
TRY {
    ctx = SocketTLSContext_new_client(NULL);
    sock = Socket_connect_tcp(host, port, timeout);
}
EXCEPT(Socket_Failed) {
    // Exception raised - control jumps here
}
END_TRY;
SocketTLSContext_free(&ctx);  // NEVER REACHED if exception!
```

**RIGHT:**
```c
volatile SocketTLSContext_T ctx = NULL;
volatile Socket_T sock = NULL;
TRY {
    ctx = SocketTLSContext_new_client(NULL);
    sock = Socket_connect_tcp(host, port, timeout);
}
FINALLY {
    if (ctx) SocketTLSContext_free((SocketTLSContext_T *)&ctx);
    if (sock) Socket_free((Socket_T *)&sock);
}
END_TRY;
```

### Rule 3: Never Nest TRY Blocks More Than 2 Levels Deep

Deep nesting corrupts the exception stack. Refactor to helper functions:

**WRONG:**
```c
TRY {
    TRY {
        TRY {  // 3 levels - DANGER!
            // ...
        } END_TRY;
    } END_TRY;
} END_TRY;
```

**RIGHT:**
```c
static int do_inner_operation(void) {
    TRY {
        // Inner logic
        return 0;
    }
    EXCEPT(SomeException) {
        return -1;
    }
    END_TRY;
    return 0;
}

TRY {
    if (do_inner_operation() < 0) {
        RAISE(Outer_Failed);
    }
} END_TRY;
```

### Rule 4: No RETURN Inside TRY Blocks

Use the `RETURN` macro or restructure:

**WRONG:**
```c
TRY {
    if (condition) return NULL;  // Corrupts exception stack!
}
END_TRY;
```

**RIGHT:**
```c
TRY {
    if (condition) RETURN NULL;  // Macro handles stack cleanup
}
END_TRY;
```

Or better, set a flag:
```c
volatile int should_return = 0;
TRY {
    if (condition) should_return = 1;
}
END_TRY;
if (should_return) return NULL;
```

### Rule 5: Allocate Before TRY When Possible

Move allocations outside TRY to ensure FINALLY can see them:

**WRONG:**
```c
TRY {
    Arena_T arena = Arena_new();  // Invisible to FINALLY if exception before this line
    // ... exception raised ...
}
FINALLY {
    Arena_dispose(&arena);  // arena not in scope!
}
END_TRY;
```

**RIGHT:**
```c
Arena_T arena = Arena_new();  // Allocated before TRY
TRY {
    // ... use arena ...
}
FINALLY {
    Arena_dispose(&arena);  // Always visible
}
END_TRY;
```

## Exception Types in This Codebase

| Module | Exception | When Raised |
|--------|-----------|-------------|
| Core | `Assert_Failed` | Assertion failures |
| Socket | `Socket_Failed` | Socket operations |
| TLS | `SocketTLS_Failed` | TLS errors |
| TLS | `SocketTLS_HandshakeFailed` | Handshake failures |
| TLS | `SocketTLS_VerifyFailed` | Certificate verification |
| DNS | `SocketDNS_Failed` | DNS resolution |
| Pool | `SocketPool_Failed` | Connection pool |
| HTTP | `SocketHTTP_Failed` | HTTP protocol |
| Arena | `Arena_Failed` | Memory allocation |

## Checklist Before Submitting Code

1. [ ] All variables modified in TRY blocks are `volatile`
2. [ ] All resources freed in FINALLY (not after END_TRY)
3. [ ] No TRY nesting deeper than 2 levels
4. [ ] No bare `return` inside TRY blocks (use `RETURN` macro)
5. [ ] Resources allocated before TRY when possible
6. [ ] Cast away volatile when passing to APIs: `(Socket_T *)&sock`
