# Redundancy Removal Command - Socket Library

You are an expert C developer specializing in code optimization and redundancy elimination. When `@redundancy` is used with a file reference (e.g., `@redundancy @file`), perform a comprehensive analysis to identify and remove ALL forms of redundancy from the provided code while preserving functionality and following socket library conventions.

## Socket Library Context

This codebase follows **C Interfaces and Implementations** patterns with:
- **Arena-based memory management** (`Arena_T`, `ALLOC`, `CALLOC`)
- **Exception-based error handling** (`TRY`, `EXCEPT`, `FINALLY`, `RAISE`)
- **Module-prefixed naming** (`Socket_*`, `Arena_*`, etc.)
- **Thread-safe design** (thread-local storage, mutex protection)
- **GNU C coding style** (8-space indentation, return types on separate lines)
- **Opaque types** with `T` macro pattern
- **Centralized utilities** (see `.claude/references/module-apis.md` for all available helpers)

## Step-by-Step Redundancy Removal Process

1. **Analyze the Entire File**: Read through the complete file to understand structure, dependencies, and patterns before making changes.

2. **Map All Code Blocks**: Identify every function, macro, include, and code block. Create a mental model of what each piece does.

3. **Cross-Reference with Codebase**: Check if functionality already exists in base layer components. See `.claude/references/module-apis.md` for comprehensive listing of available functions. Remove local implementations that duplicate existing functionality.

4. **Verify Public API Ground Truth (CRITICAL)**: Treat `include/` as the source of truth for public APIs. Do not "dedupe" by inventing new helper APIs unless they belong in the codebase and are added intentionally.

5. **Prioritize Findings**: Categorize redundancies by severity (Critical/High/Medium/Low).

6. **Remove Redundancies Safely**: Eliminate redundant code while ensuring no functionality is lost. Prefer existing codebase functions over local implementations.

7. **Verify Correctness**: Mentally trace execution paths to ensure the refactored code behaves identically.

8. **Cross-File Check**: Note any redundancies that span multiple files for separate refactoring.

## Redundancy Categories

### 1. Duplicate Code Blocks [HIGH]
- Identical or near-identical code appearing multiple times
- Similar logic with minor variations (consolidate into parameterized function)
- Copy-pasted code with different variable names
- Repeated patterns across functions that could be extracted

**When to Extract vs Inline**:
- Extract if: 3+ lines repeated 2+ times, OR complex logic repeated anywhere
- Inline if: Simple expression, single use adds clarity, performance-critical hot path

### 2. Redundant Expressions [MEDIUM]
- Same expression computed multiple times (cache in variable)
- Subexpressions that can be hoisted out of loops
- Function calls with identical arguments repeated
- Arithmetic that can be simplified

### 3. Redundant Conditionals [MEDIUM]
- Conditions that always evaluate to true/false
- Nested conditions that can be combined
- Conditions checking same thing multiple times
- Conditions that are implied by earlier checks
- Dead branches (else after return/RAISE)

### 4. Redundant Variables [LOW]
- Variables assigned but never read
- Variables that only hold another variable's value (pass-through)
- Variables used only once immediately after assignment
- Temporary variables that add no clarity

**Decision Rule**: Keep if variable name documents intent; remove if just `temp`, `result`, `ret`.

### 5. Redundant Includes [LOW]
- Headers included but nothing used from them
- Headers included multiple times (even with guards)
- Headers that are transitively included by other headers

### 6. Redundant Error Handling [HIGH]
- Same error checked multiple times in same path
- Error handling that duplicates what caller already handles
- TRY/EXCEPT blocks that just re-raise without cleanup
- Redundant null checks (already validated upstream)

**Rule**: Validate at API boundaries; use `assert()` for internal invariants.

### 7. Redundant Initialization [LOW]
- Variables initialized and immediately overwritten
- Zero-initialization that's immediately replaced
- Struct members set in initializer and again in code

### 8. Redundant Loop Constructs [MEDIUM]
- Loops that always execute exactly once
- Loop conditions that are always true on first iteration
- Break/continue that's immediately followed by end of loop
- Multiple loops that could be combined into one pass

### 9. Redundant Type Casts [LOW]
- Casts to the same type
- Casts that compiler performs implicitly (and safely)
- Double casts that cancel out

**Keep**: Intentional truncation or signedness change (documents intent)

### 10. Redundant String Operations [MEDIUM]
- Multiple strlen() calls on same string
- String copies to temporary buffers that are immediately used
- Repeated string comparisons with same value
- snprintf() followed by strlen() on result (use return value)

### 11. Redundant Memory Operations [MEDIUM]
- memset immediately followed by full overwrite
- Copying data that's about to be discarded
- Zero-initialization when Arena already zeros (CALLOC)

### 12. Redundant Documentation [LOW]
- Comments that repeat what code clearly shows
- Outdated comments that don't match code
- Comments stating the obvious

**Keep**: Comments explaining WHY, not WHAT

### 13. Redundant Macros [MEDIUM]
- Macros that just wrap a single function call
- Macros identical to existing ones in SocketConfig.h
- Macros that could be inline functions
- Duplicate macro definitions

## Socket Library Specific Redundancies

### 14. Redundant TRY/EXCEPT Blocks [HIGH]
- Nested TRY blocks where outer handles all exceptions
- TRY/EXCEPT that just re-raises without cleanup
- FINALLY blocks that are empty or duplicate cleanup

### 15. Redundant Socket Operations [HIGH]
- Same socket option set multiple times
- SAFE_CLOSE called on already-closed fd (redundant check)
- Repeated address resolution for same host
- Duplicate bind/connect error handling

### 16. Redundant Mutex Operations [CRITICAL]
- Lock/unlock without any critical section between
- Nested locks on same mutex (deadlock risk)
- Mutex operations in non-threaded code paths

### 17. Redundant Assertions [LOW]
- Assert after runtime validation already performed
- Assert checking same condition multiple times
- Assert with always-true condition

### 18. Redundant Error Buffer Formatting [MEDIUM]
- Multiple snprintf to same error buffer
- Error message formatted but exception not raised
- SOCKET_ERROR_FMT called multiple times for same error

### 19. Redundant Error+Raise Patterns [HIGH]
Instead of:
```c
SOCKET_ERROR_FMT("connect failed to %s:%d", host, port);
RAISE_MODULE_ERROR(Socket_Failed);
```

Use unified macros:
```c
SOCKET_RAISE_FMT(Socket, Socket_Failed, "connect failed to %s:%d", host, port);
SOCKET_RAISE_MSG(Socket, Socket_Failed, "invalid port: %d", port);
```

### 20. Redundant Module Exception Setup [HIGH]
Instead of manual thread-local declarations, use:
```c
SOCKET_DECLARE_MODULE_EXCEPTION(Module);
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(Module, e)
```

### 21. Redundant Helper Function Implementations [CRITICAL]
**DO NOT re-implement functionality that exists in the codebase.**

See `.claude/references/module-apis.md` for comprehensive listing of available helper functions from:
- `SocketConfig.h` - Constants, macros, SAFE_CLOSE
- `SocketUtil.h` - Error formatting, logging, hash functions, monotonic time
- `SocketCommon.h` - Socket base, address resolution, validation, iovec helpers
- `SocketIO.h` - TLS-aware I/O abstraction
- `SocketBuf.h` - Circular buffer operations
- `SocketCrypto.h` - Cryptographic primitives (hashes, HMAC, Base64, random)
- `SocketUTF8.h` - UTF-8 validation
- `SocketHTTP.h` - HTTP types (methods, status, headers, URI, dates)
- `SocketHTTP1.h` - HTTP/1.1 parsing, serialization, chunked encoding
- `SocketHPACK.h` - HPACK header compression
- `SocketHTTP2.h` - HTTP/2 protocol implementation
- `SocketProxy.h` - Proxy tunneling (HTTP CONNECT, SOCKS4/5)
- `SocketWS.h` - WebSocket protocol (RFC 6455)
- `SocketTLS.h` / `SocketTLSContext.h` - TLS/SSL support
- `SocketRateLimit.h` - Token bucket rate limiting
- `SocketIPTracker.h` - Per-IP connection tracking
- `SocketTimer.h` - Timer management
- `SocketPool.h` - Connection pooling with graceful shutdown

**Examples of Common Redundancies**:

Hash Functions:
```c
/* REDUNDANT */
unsigned hash = ((unsigned)fd * 2654435761u) % size;

/* USE */
unsigned hash = socket_util_hash_fd(fd, size);
```

DJB2 String Hashing:
```c
/* REDUNDANT */
unsigned hash = 5381;
while (*str) hash = ((hash << 5) + hash) + *str++;

/* USE */
unsigned hash = socket_util_hash_djb2(str, table_size);
unsigned hash = socket_util_hash_djb2_ci(header_name, table_size);  /* case-insensitive for HTTP */
```

Monotonic Time:
```c
/* REDUNDANT - manual clock access */
struct timespec ts;
clock_gettime(CLOCK_MONOTONIC, &ts);
int64_t now_ms = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;

/* USE */
int64_t now_ms = Socket_get_monotonic_ms();
```

TLS I/O Routing:
```c
/* REDUNDANT - manual TLS check */
if (socket->tls_enabled)
    n = SSL_read(socket->tls_ssl, buf, len);
else
    n = recv(socket->fd, buf, len, 0);

/* USE */
ssize_t n = socket_recv_internal(socket, buf, len, 0);
```

Socket Options:
```c
/* REDUNDANT */
int value = 1;
if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) < 0) {
    SOCKET_ERROR_FMT("Failed to set SO_REUSEADDR");
    RAISE_MODULE_ERROR(Socket_Failed);
}

/* USE */
SocketCommon_set_option_int(base, SOL_SOCKET, SO_REUSEADDR, 1, Socket_Failed);
```

UTF-8 Validation:
```c
/* REDUNDANT - manual UTF-8 validation */
int is_valid_utf8(const char *s) {
    while (*s) {
        if ((*s & 0x80) == 0) { s++; continue; }
        /* ... complex byte checks ... */
    }
    return 1;
}

/* USE */
if (SocketUTF8_validate((const unsigned char *)s, strlen(s)) == UTF8_VALID) {
    /* Valid UTF-8 */
}
```

Cryptographic Operations:
```c
/* REDUNDANT */
unsigned char hash[SHA256_DIGEST_LENGTH];
SHA256(data, len, hash);

/* USE */
unsigned char hash[SOCKET_CRYPTO_SHA256_SIZE];
SocketCrypto_sha256(data, len, hash);

/* REDUNDANT */
memset(password, 0, sizeof(password));  /* May be optimized away */

/* USE */
SocketCrypto_secure_clear(password, sizeof(password));  /* Never optimized away */
```

## Output Format

When analyzing a file, provide:

1. **Summary Statistics**:
   - Total redundancies found (by category)
   - Estimated lines saved
   - Priority distribution (Critical/High/Medium/Low)

2. **Detailed Findings**:
   For each redundancy:
   - **Category**: e.g., "Duplicate Code Blocks"
   - **Severity**: Critical/High/Medium/Low
   - **Location**: File and line numbers
   - **Issue**: What is redundant
   - **Recommendation**: How to fix (with code example if needed)
   - **Reference**: Link to helper function in `.claude/references/module-apis.md` if applicable

3. **Refactored Code**: Complete, production-ready code with redundancies removed

4. **Verification Notes**: How to verify the refactoring preserves functionality

## Critical Requirements

- **DO NOT** remove code that serves a purpose (clarity, error handling, validation)
- **DO NOT** inline everything - keep readable variable names
- **DO** verify all functionality is preserved
- **DO** prefer existing codebase functions over local implementations
- **DO** check `.claude/references/module-apis.md` before declaring something doesn't exist
- **DO** maintain thread safety
- **DO** preserve exception handling patterns
- **DO** keep security-critical validation

Provide a comprehensive redundancy analysis that improves code quality without changing functionality.
