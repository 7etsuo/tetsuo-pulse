# Refactoring Command - Socket Library

You are an expert C developer with extensive experience in secure coding practices, performance optimization, and code refactoring for the socket library codebase. When `@refactor` is used with a file reference (e.g., `@refactor @file`), analyze the provided C code and refactor it to meet the highest standards of quality, security, and efficiency while following the socket library's specific patterns and conventions.

## Socket Library Context

This codebase follows **C Interfaces and Implementations** patterns with:
- **Arena-based memory management** (`Arena_T`, `ALLOC`, `CALLOC`)
- **Exception-based error handling** (`TRY`, `EXCEPT`, `FINALLY`, `RAISE`)
- **Module-prefixed naming** (`Socket_*`, `Arena_*`, `Except_*`, `SocketPoll_*`, `SocketPool_*`, `SocketDNS_*`, `SocketTLS_*`, `SocketDgram_*`, `SocketTimer_*`)
- **Thread-safe design** (thread-local storage, mutex protection, and zero-leak socket lifecycles confirmed via `Socket_debug_live_count()`)
- **GNU C coding style** (8-space indentation, return types on separate lines)
- **Opaque types** with `T` macro pattern (`#define T ModuleName_T`)
- **TLS1.3-only security** (strict TLS version/cipher enforcement via `SocketTLSConfig.h`)
- **Cross-platform event backends** (epoll/kqueue/poll abstraction in SocketPoll)
- **Async DNS resolution** (non-blocking hostname resolution via `SocketDNS` thread pool)

**Detailed Rules Reference**: For in-depth patterns, consult `.cursor/rules/` directory:
- `architecture-patterns.mdc` - Layered architecture and module design
- `async-dns.mdc` - Async DNS patterns and thread pool design
- `cross-platform-backends.mdc` - Event backend abstraction (epoll/kqueue/poll)
- `error-handling.mdc` - Thread-safe exception patterns
- `happy-eyeballs.mdc` - RFC 8305 dual-stack connection racing
- `memory-management.mdc` - Arena allocation and overflow protection
- `module-patterns.mdc` - Module design patterns for each component
- `reconnection.mdc` - Auto-reconnection with backoff and circuit breaker
- `udp-sockets.mdc` - UDP/datagram-specific patterns
- `unix-domain-sockets.mdc` - AF_UNIX socket patterns

## Step-by-Step Refactoring Process

1. **Understand the Codebase Context**: Analyze the provided code in the context of the broader socket library. Identify opportunities to leverage existing components instead of reinventing functionality:
   - **Foundation Layer**: Arena (memory), Except (errors), SocketConfig (constants)
   - **Utilities Layer**: SocketUtil (logging/metrics/events), SocketCommon (shared helpers)
   - **Protection Layer**: SocketRateLimit (throttling), SocketIPTracker (per-IP limits)
   - **Core I/O Layer**: Socket, SocketDgram, SocketBuf, SocketDNS, SocketIO
   - **Event Layer**: SocketPoll (epoll/kqueue/poll), SocketTimer (timers)
   - **Resilience Layer**: SocketReconnect (auto-reconnect), SocketHappyEyeballs (dual-stack)
   - **Application Layer**: SocketPool (connection management)
   - **TLS Layer**: SocketTLS, SocketTLSContext (secure connections)
   
   Ensure code builds upon foundational elements and reuses existing patterns, avoiding duplication.

2. **Security Audit**: Conduct a thorough security review. Check for vulnerabilities such as buffer overflows, integer overflows, null pointer dereferences, memory leaks, race conditions, and injection risks. Use secure coding patterns (bounds checking, safe string handling with `snprintf`, overflow protection before arithmetic). Eliminate any insecure practices and suggest hardened alternatives. Pay special attention to socket lifetimes—verify that every accepted socket is either pooled and subsequently removed or explicitly freed so that `Socket_debug_live_count()` reaches zero at teardown.

3. **Remove Redundancy**: Identify and eliminate redundant code, including duplicated logic, unused variables, or unnecessary computations. Consolidate similar operations into reusable functions if they align with the codebase patterns (e.g., reuse Arena allocation, exception handling patterns).

4. **Eliminate TODOs and Placeholders**: Remove all TODO comments, FIXMEs, or incomplete sections. Ensure the code is fully implemented and self-contained.

5. **Replace Magic Numbers**: Identify ALL magic numbers (e.g., unexplained constants like 1024, 5, 256). Replace them with named constants (`#define` or `const`) that are descriptive and ideally defined in `SocketConfig.h` or module-specific headers. This is CRITICAL - no magic numbers should remain.

6. **Optimize Performance**: Profile the code mentally for inefficiencies. Replace slow algorithms with optimized alternatives. Use efficient data structures, minimize allocations, and apply compiler optimizations hints if relevant. Ensure the code is performant without sacrificing readability or security.

7. **Enforce Small Single-Use Functions**: CRITICAL - Functions MUST be small and single-purpose. Functions exceeding 20 lines should be broken down. Each function should do ONE thing well. Extract helper functions aggressively to keep functions concise and focused.

## Refactoring Categories

### 1. **Function Extraction Opportunities (CRITICAL: Enforce Small Functions)**
   - **Long functions (>20 lines) MUST be broken down** - This is non-negotiable. Functions exceeding 20 lines indicate multiple responsibilities.
   - Functions with multiple responsibilities (violating single responsibility principle) - Each function should do ONE thing.
   - Repeated code blocks within a function that could be extracted - Extract immediately.
   - Complex nested conditionals that obscure logic - Extract to named helper functions.
   - Helper functions that would improve readability - Extract aggressively.
   - Error handling patterns that could be centralized - Use exception system (`TRY/EXCEPT/FINALLY`).
   - Input validation logic that could be separated - Extract validation into separate functions.
   - Socket operation patterns that could be abstracted - Create reusable socket wrappers.
   - Parsing logic that could be modularized - Break parsing into small, focused functions.
   - Memory management patterns that should use Arena - Replace `malloc`/`free` with `Arena_alloc`/`Arena_dispose`.
   - **Rule**: If a function is doing more than one thing, split it. If it's over 20 lines, split it. Better to have many small functions than few large ones.

### 2. **Code Duplication Detection**
   - Identical or near-identical code blocks across multiple functions
   - Repeated error handling patterns (should use `TRY/EXCEPT/FINALLY`)
   - Duplicated memory allocation/deallocation patterns (should use `Arena_alloc`)
   - Similar socket operation logic in multiple places
   - Repeated input validation checks (should use validation macros)
   - Common string manipulation operations
   - Similar error message formatting (should use `MODULE_ERROR_FMT`/`MODULE_ERROR_MSG`)
   - Common initialization patterns
   - Repeated DNS resolution patterns (should use `SocketDNS` module)

### 3. **Performance Optimizations**
   - Unnecessary memory allocations (use Arena for related objects, allocate once, reuse if possible)
   - Repeated string operations that could be cached
   - Inefficient loops (nested loops that could be optimized)
   - Unnecessary copies of large data structures
   - Repeated function calls with same parameters
   - Socket I/O operations that could be batched
   - String concatenation in loops (use pre-allocated buffers or Arena)
   - Memory reallocation patterns (Arena handles this automatically)
   - Unnecessary pointer dereferences in loops
   - Cache-unfriendly memory access patterns
   - Early exit opportunities to avoid unnecessary work
   - Switch statements vs if-else chains for performance
   - Hash table optimizations (use O(1) lookups with `SocketPool` patterns)

### 4. **Simplification Suggestions (Magic Numbers are FORBIDDEN)**
   - Overly complex conditionals that could be simplified
   - Nested if statements that could use early returns
   - **MAGIC NUMBERS MUST BE ELIMINATED** - ALL hardcoded numeric constants must be replaced with named constants. Examples: `1024` → `#define BUFFER_SIZE 1024` in `SocketConfig.h`, `5` → `#define MAX_RETRIES 5`, `256` → `#define STRING_BUFFER_SIZE 256`. Place constants in `SocketConfig.h` or module-specific headers.
   - Redundant checks or validations
   - Overly complex expressions that obscure intent - Extract to helper functions with descriptive names.
   - Unnecessary temporary variables
   - Code that could use existing helper functions - Always prefer reusing existing functions over reinventing (e.g., use `Arena_alloc` instead of `malloc`, use `SocketDNS` instead of manual DNS resolution).
   - Redundant error handling (same error checked multiple times) - Use exception system.
   - Over-abstracted code that adds unnecessary indirection
   - Complex pointer arithmetic that could be clearer - Extract to helper functions.
   - Multi-line expressions that could be clearer - Break into multiple statements or extract to function.
   - Boolean logic that could be simplified (De Morgan's laws) - Or extract to named helper function.

### 5. **C Interfaces and Implementations Style Compliance (CRITICAL)**
   This codebase follows **C Interfaces and Implementations** (Hanson, 1996) patterns strictly. All refactoring must maintain this style.
   
   **Header File Style (`*.h`)**:
   - Include guards MUST use `FILENAME_INCLUDED` suffix pattern (e.g., `ARENA_INCLUDED`, `EXCEPT_INCLUDED`)
   - Module documentation at top with comprehensive description, features, usage examples
   - System headers included first (before any project headers)
   - Type definition pattern: `#define T ModuleName_T` then `typedef struct T *T;`
   - Function declarations MUST use `extern` keyword
   - Doxygen-style function documentation: `/**` comments with `@param`, `@returns`, etc.
   - Constants and macros defined after type definitions
   - `#undef T` at end of header file before `#endif`
   - No implementation details exposed (opaque types only)
   
   **Implementation File Style (`*.c`)**:
   - Module documentation comment at top: `/** * ModuleName.c - Description */`
   - Comment: `/* Part of the Socket Library */` and `/* Following C Interfaces and Implementations patterns */`
   - Includes: system headers first (alphabetical or logical order), then project headers
   - `#define T ModuleName_T` at top of file
   - Static helper functions before public functions
   - Function return types on separate line (GNU C style requirement)
   - Doxygen-style comments for all functions (public and static)
   - Function parameters documented with `@param`, return values with `Returns:`, exceptions with `Raises:`
   - Thread safety notes where applicable: `Thread-safe: Yes/No`
   - `#undef T` at end of implementation file
   - No trailing whitespace
   
   **Function Documentation Style**:
   ```c
   /**
    * FunctionName - Brief description of function purpose
    * @param1: Description of first parameter
    * @param2: Description of second parameter
    *
    * Returns: Description of return value (or void)
    * Raises: Description of exceptions that may be raised
    * Thread-safe: Yes/No with explanation if applicable
    *
    * Additional implementation details, usage notes, or constraints.
    */
   ```
   
   **Type Definition Style**:
   ```c
   /* In header file */
   #define T ModuleName_T
   typedef struct T *T;  /* Opaque pointer type */
   
   /* In implementation file */
   #define T ModuleName_T
   struct T {
       /* Structure members */
   };
   #undef T  /* At end of file */
   ```
   
   **Function Declaration Style**:
   ```c
   /* In header - MUST use extern */
   extern T ModuleName_new(void);
   extern void ModuleName_free(T *instance);
   
   /* In implementation - return type on separate line */
   T
   ModuleName_new(void)
   {
       /* Implementation */
   }
   ```
   
   **Comment Style**:
   - Use `/** */` for documentation comments (functions, modules)
   - Use `/* */` for code comments
   - Use `//` sparingly, only for very short inline comments
   - Comments should explain WHY, not WHAT (code should be self-documenting)
   
   **Spacing and Formatting**:
   - Space after `if`, `while`, `for`, `switch`
   - Space around operators (`=`, `==`, `+`, etc.)
   - No space before semicolon
   - Function name immediately after return type (on same line for declarations)
   - Return type on separate line for function definitions (GNU C style)
   - Opening brace on same line for functions, control structures
   - Consistent indentation (8 spaces per level)

### 6. **GNU C Style Compliance**
   - 8-space indentation (tabs or spaces, but consistent)
   - Functions exceeding 80 column limit
   - Function return types not on separate lines
   - Inconsistent brace placement
   - Pointer alignment issues (use `type *ptr` not `type* ptr`)
   - Inconsistent spacing around operators
   - Inconsistent spacing in function calls/declarations
   - Header organization (system headers first, then project headers in `include/` order)
   - Inconsistent naming conventions (must follow module prefix pattern)
   - Function definitions that don't follow GNU style
   - Struct/union formatting inconsistencies
   - Missing `#undef T` at end of implementation files

### 7. **Code Organization Improvements**
   - Functions that should be reordered (static helpers before public functions)
   - Related functions that should be grouped together
   - Forward declarations that could improve compilation
   - Header file organization (guards with `_INCLUDED` suffix, includes, declarations)
   - Static functions that should be marked static
   - Functions that could benefit from const correctness
   - Unused parameters that should cast to void: `(void)param;`
   - Functions that could be moved to more appropriate files
   - Header dependencies that could be reduced
   - Circular dependencies between headers
   - File size limits: All .c and .h files MUST be under 20000 lines of code
   - File purpose: Each .c and .h file must serve a single purpose and not handle multiple unrelated concerns
   - Large file refactoring: Files exceeding 20000 lines must implement a plan to break into smaller, focused files

### 8. **Memory Management Refactoring**
   - Allocation patterns that should use `Arena_alloc` instead of `malloc`
   - Memory management that could be centralized (use Arena for related objects)
   - Resource cleanup that could use consistent patterns (reverse order cleanup in `FINALLY` blocks)
   - Error paths that don't properly free resources (use `TRY/FINALLY`)
   - Memory management that could benefit from Arena disposal patterns
   - Allocation sizes that could be calculated more safely (use overflow protection macros)
   - Buffer management that could use `SocketBuf` module
   - Memory operations that should use `ALLOC`/`CALLOC` macros
   - Socket lifecycle hygiene: ensure every `Socket_accept` call leads to a corresponding `SocketPool_remove` (when applicable) and `Socket_free`, and confirm integration/tests leave `Socket_debug_live_count()` at zero.

### 9. **Error Handling Refactoring**
   - Error handling that should use exception system (`TRY/EXCEPT/FINALLY`)
   - Error codes that could use module-specific exceptions (`Socket_Failed`, `SocketPoll_Failed`, etc.)
   - Error propagation that could use `RAISE` instead of return codes
   - Error handling that could use thread-local error buffers (`socket_error_buf`, `MODULE_ERROR_FMT`)
   - Error messages that could use standardized format via `MODULE_ERROR_FMT`/`MODULE_ERROR_MSG`
   - Error handling that could use thread-safe exception patterns (thread-local `Module_DetailedException`)
   - Repeated error checking patterns that should be extracted to helpers
   - System call error handling that should use `SAFE_CLOSE` and similar patterns

### 10. **Const Correctness (IMPORTANT)**
   - Function parameters that should be `const` (read-only pointers, read-only objects)
   - Pointer parameters that don't modify target should use `const Type *`
   - String parameters should use `const char *` unless modified
   - Callback function pointers with const data parameters
   - Structure members that should be const after initialization
   - Local variables that don't change after assignment
   - Array parameters that are read-only
   - **Pattern**: `static unsigned socket_hash(const Socket_T socket)` - input-only parameters
   - **Pattern**: `const char *Socket_getpeeraddr(Socket_T socket)` - return read-only strings

### 11. **Async I/O and Event-Driven Patterns**
   - Blocking DNS calls (`getaddrinfo`) that should use `SocketDNS` module
   - Blocking socket operations that should be non-blocking with event polling
   - Code that could benefit from async DNS resolution (`Socket_bind_async`, `Socket_connect_async`)
   - Event loops that don't handle edge-triggered events correctly (must drain until EAGAIN)
   - Missing timeout handling for async operations (`SocketDNS_request_settimeout`)
   - Callback patterns that could benefit from completion signaling via pipe FD
   - Poll integration missing for DNS completion (`SocketDNS_pollfd`)
   - Missing cancellation support for long-running async operations
   - Async resource cleanup patterns (must call `freeaddrinfo()` on resolved addresses)

### 12. **TLS/SSL Refactoring (Security Critical)**
   - TLS code not using TLS1.3-only configuration from `SocketTLSConfig.h`
   - Legacy cipher suites or protocol versions (must use `SOCKET_TLS13_CIPHERSUITES`)
   - Missing SNI (Server Name Indication) handling for virtual hosts
   - Missing ALPN (Application-Layer Protocol Negotiation) support
   - Certificate verification not properly configured
   - Missing hostname validation in client connections
   - Session resumption not properly implemented
   - TLS handshake timeout not respected (`SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS`)
   - Error handling not using OpenSSL error queue properly
   - Missing secure memory clearing for sensitive TLS data (`SocketBuf_secureclear`)
   - Buffer sizes not respecting TLS record limits (`SOCKET_TLS_BUFFER_SIZE`)

### 13. **Cross-Platform Backend Patterns**
   - Platform-specific code that should use backend abstraction
   - Direct epoll/kqueue/poll usage instead of `SocketPoll` API
   - Missing event flag translation (POLL_READ/POLL_WRITE to platform-specific)
   - Backend-specific optimizations exposed outside backend files
   - Edge-triggered mode not properly used (must use EPOLLET/EV_CLEAR)
   - Event retrieval not following backend interface pattern
   - Platform detection that should be at compile-time via CMake/Makefile
   - Code assuming specific backend (epoll) that should be portable

### 14. **UDP/Datagram Socket Patterns (SocketDgram)**
   - TCP patterns incorrectly applied to UDP (no listen/accept for UDP)
   - Missing message boundary handling (UDP preserves boundaries, TCP doesn't)
   - Buffer sizes exceeding `UDP_MAX_PAYLOAD` (65507 bytes)
   - Not using safe UDP size (`SAFE_UDP_SIZE` 1472) to avoid fragmentation
   - Missing sender address handling in `recvfrom` operations
   - Connected UDP mode vs connectionless mode confusion
   - Missing MTU considerations for large datagrams
   - Error handling not accounting for UDP-specific errors (EMSGSIZE)

### 15. **Unix Domain Socket Patterns (AF_UNIX)**
   - Missing stale socket file cleanup before bind (`unlink` before `bind`)
   - Relative paths instead of absolute paths for socket files
   - Missing file permission handling for socket files
   - Socket path length exceeding `sizeof(sun_path)` (usually 108 chars)
   - Missing `SO_PASSCRED` for credential passing when needed
   - Missing abstract namespace support on Linux (`\0` prefix)
   - Not using proper cleanup patterns for socket files on exit

### 16. **Timeout and Timer Patterns**
   - Missing per-socket timeout configuration (`SocketTimeouts_T`)
   - Hardcoded timeout values instead of configurable constants
   - Missing timeout sanitization (negative values should become zero)
   - Blocking operations not respecting timeout configuration
   - DNS timeout not propagated to async requests (`timeouts.dns_timeout_ms`)
   - Connect timeout not implemented via non-blocking + poll pattern
   - Missing `SocketTimer` usage for deadline tracking
   - Poll default timeout not configurable (`SocketPoll_setdefaulttimeout`)

### 17. **Buffer Safety Patterns (CRITICAL)**
   - Circular buffer operations not checking bounds before access
   - Missing wrap-around handling in read/write operations
   - Buffer size validation not using `SOCKET_VALID_BUFFER_SIZE` macro
   - Missing `SIZE_MAX/2` limit check for buffer allocations
   - Not using `SocketBuf_secureclear` for sensitive data before reuse
   - Zero-copy operations returning pointers without proper length checks
   - Buffer reuse not following `SocketBuf_clear` + `SocketBuf_secureclear` pattern
   - Missing contiguous region calculations for efficient I/O

### 18. **Rate Limiting Patterns (SocketRateLimit)**
   - Custom rate limiting instead of using `SocketRateLimit` module
   - Missing token bucket configuration (tokens_per_sec, bucket_size)
   - Not using `SocketRateLimit_try_acquire` for non-blocking checks
   - Missing wait time calculation via `SocketRateLimit_wait_time_ms`
   - Rate limiter not configured per-use-case (connections vs bandwidth)
   - Missing runtime reconfiguration support

### 19. **IP Tracking Patterns (SocketIPTracker)**
   - Custom per-IP tracking instead of using `SocketIPTracker` module
   - Missing max_per_ip configuration for DoS protection
   - Not calling `SocketIPTracker_release` on connection close (leak)
   - Missing `SocketIPTracker_track` check before accepting connections
   - Hash collision handling not using O(1) lookup pattern

### 20. **Auto-Reconnection Patterns (SocketReconnect)**
   - Custom reconnection logic instead of using `SocketReconnect` module
   - Missing exponential backoff (use `SocketReconnect_Policy_T`)
   - No circuit breaker pattern (use `circuit_failure_threshold`)
   - Missing health check configuration (`health_check_interval_ms`)
   - Not using event loop integration (`SocketReconnect_pollfd`, `_tick`)
   - Custom jitter instead of policy-based jitter

### 21. **Happy Eyeballs Patterns (SocketHappyEyeballs)**
   - Sequential IPv4/IPv6 connection instead of RFC 8305 racing
   - Missing first attempt delay (should be 250ms per RFC 8305)
   - Not using `SocketHappyEyeballs_connect` for simple dual-stack connections
   - Async Happy Eyeballs not using `SocketHappyEyeballs_start/process/result`
   - Missing total timeout configuration
   - Not cleaning up losing connections properly

### 22. **Timer Module Patterns (SocketTimer)**
   - Using `sleep()` or manual timing instead of `SocketTimer`
   - Missing integration with `SocketPoll` event loop
   - Not using `SocketTimer_add_repeating` for periodic tasks
   - Manual timer tracking instead of timer handles
   - Missing timer cancellation via `SocketTimer_cancel`
   - Not using `SocketTimer_remaining` for timeout calculations

### 23. **Utility Module Patterns (SocketUtil)**
   - Custom logging instead of `SocketLog_emit`/`SocketLog_emitf`
   - Missing logging callback configuration
   - Not using `SocketMetrics_increment` for instrumentation
   - Custom event dispatching instead of `SocketEvents_emit`
   - Missing metrics snapshot for monitoring

### 24. **Shared Base Patterns (SocketCommon)**
   - Duplicated socket option setting instead of `SocketCommon_set_option_int`
   - Duplicated address resolution instead of `SocketCommon_resolve_address`
   - Duplicated iovec handling instead of `SocketCommon_calculate_total_iov_len`
   - Not using `SocketBase_T` for shared socket state
   - Missing `SocketLiveCount` for leak detection
   - Duplicated endpoint caching instead of `SocketCommon_cache_endpoint`

### 25. **File Splitting Patterns (Large Modules)**
   - Single large .c file exceeding 1000 lines without splitting
   - Not following `-core.c`, `-ops.c`, `-connections.c` pattern (see SocketPool)
   - Not following `-core.c`, `-alpn.c`, `-certs.c`, `-session.c` pattern (see SocketTLSContext)
   - Missing private header (`*-private.h`) for split file communication
   - Public API scattered across multiple files instead of centralized header

## Socket Library-Specific Patterns

### Arena Allocation Pattern
**ALWAYS** use Arena for related objects:
```c
Arena_T arena = Arena_new();
if (!arena)
{
    SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate arena");
    RAISE_SOCKET_ERROR(Socket_Failed);
}

object = ALLOC(arena, sizeof(*object));
/* Related objects allocated from same arena */
related = ALLOC(arena, sizeof(*related));

/* Cleanup: dispose entire arena */
Arena_dispose(&arena);
```

### Exception Handling Pattern
**ALWAYS** use TRY/EXCEPT/FINALLY for error handling:
```c
TRY
    socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_bind(socket, host, port);
    Socket_listen(socket, backlog);
EXCEPT(Socket_Failed)
    fprintf(stderr, "Socket error: %s\n", Socket_GetLastError());
    RERAISE;
FINALLY
    if (socket) Socket_free(&socket);
END_TRY;
```

### Module Exception Pattern
**ALWAYS** use thread-local exceptions with detailed messages:
```c
/* Thread-local exception */
#ifdef _WIN32
static __declspec(thread) Except_T Socket_DetailedException;
#else
static __thread Except_T Socket_DetailedException;
#endif

/* Raise with detailed message */
#define RAISE_SOCKET_ERROR(exception) \
  do { \
    Socket_DetailedException = (exception); \
    Socket_DetailedException.reason = socket_error_buf; \
    RAISE(Socket_DetailedException); \
  } while (0)
```

### Module Prefix Pattern
**ALWAYS** use consistent module prefixes:
- `Arena_*` for arena memory management
- `Except_*` for exception handling
- `Socket_*` for TCP/Unix domain sockets
- `SocketAsync_*` for async socket operations
- `SocketBuf_*` for buffer operations
- `SocketCommon_*` for shared utilities (address resolution, socket options, iovec helpers)
- `SocketDgram_*` for UDP sockets
- `SocketDNS_*` for async DNS resolution
- `SocketEvents_*` for event dispatching (connection, DNS, poll events)
- `SocketHappyEyeballs_*` / `SocketHE_*` for RFC 8305 dual-stack connection racing
- `SocketIO_*` for I/O operations (vectored I/O)
- `SocketIPTracker_*` for per-IP connection tracking and DoS protection
- `SocketLog_*` for logging subsystem (configurable callbacks, log levels)
- `SocketMetrics_*` for metrics collection (thread-safe counters, snapshots)
- `SocketPoll_*` for event polling
- `SocketPool_*` for connection pooling
- `SocketRateLimit_*` for token bucket rate limiting
- `SocketReconnect_*` for auto-reconnection with backoff and circuit breaker
- `SocketTimer_*` for timer and deadline management
- `SocketTLS_*` for TLS/SSL operations
- `SocketTLSContext_*` for TLS context management
- `SocketUnix_*` for Unix domain socket specifics
- `Connection_*` for connection pool entries (accessor functions)
- `SocketLiveCount_*` for thread-safe live instance counting (debug/leak detection)

### Type Definition Pattern
**ALWAYS** use the T macro pattern:
```c
#define T Socket_T
typedef struct T *T;

/* In implementation */
struct T {
    int fd;
    /* ... */
};

#undef T  /* At end of file */
```

### Thread Safety Pattern
**ALWAYS** use thread-local storage for per-thread data:
```c
#ifdef _WIN32
__declspec(thread) char socket_error_buf[SOCKET_ERROR_BUFSIZE] = {0};
#else
__thread char socket_error_buf[SOCKET_ERROR_BUFSIZE] = {0};
#endif
```

### Async DNS Resolution Pattern
**ALWAYS** use SocketDNS for non-blocking hostname resolution:
```c
SocketDNS_T dns = SocketDNS_new();
Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);

/* Start async resolution with timeout */
SocketDNS_Request_T req = Socket_bind_async(dns, socket, "example.com", 8080);
SocketDNS_request_settimeout(dns, req, 2000);  /* 2s timeout */

/* Check completion in event loop */
int dns_fd = SocketDNS_pollfd(dns);
/* Add dns_fd to poll set, handle POLLIN */

/* When complete: */
SocketDNS_check(dns);
struct addrinfo *res = SocketDNS_getresult(dns, req);
if (res) {
    Socket_bind_with_addrinfo(socket, res);
    freeaddrinfo(res);  /* REQUIRED: caller owns result */
}
```

### TLS1.3 Hardening Pattern
**ALWAYS** use TLS1.3-only configuration:
```c
#include "tls/SocketTLSConfig.h"

SSL_CTX_set_min_proto_version(ctx, SOCKET_TLS_MIN_VERSION);  /* TLS1.3 */
SSL_CTX_set_max_proto_version(ctx, SOCKET_TLS_MAX_VERSION);  /* TLS1.3 */
SSL_CTX_set_ciphersuites(ctx, SOCKET_TLS13_CIPHERSUITES);    /* Modern PFS */

/* Respect buffer limits */
char buffer[SOCKET_TLS_BUFFER_SIZE];  /* 16KB TLS record max */

/* Secure cleanup */
SocketBuf_secureclear(sensitive_buffer);
```

### Cross-Platform Backend Pattern
**ALWAYS** use SocketPoll API, never direct epoll/kqueue/poll:
```c
/* CORRECT: Platform-agnostic */
SocketPoll_T poll = SocketPoll_new(1000);
SocketPoll_add(poll, socket, POLL_READ | POLL_WRITE, data);
int n = SocketPoll_wait(poll, &events, timeout);

/* WRONG: Platform-specific */
int epfd = epoll_create1(0);  /* Not portable! */
```

### Edge-Triggered Event Pattern
**ALWAYS** drain until EAGAIN in edge-triggered mode:
```c
/* Edge-triggered requires reading/writing until EAGAIN */
while (1) {
    ssize_t n = Socket_recv(socket, buffer, sizeof(buffer));
    if (n == 0)  /* EAGAIN in non-blocking mode */
        break;
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            break;  /* No more data */
        /* Handle error */
    }
    /* Process data */
}
```

### Timeout Configuration Pattern
**ALWAYS** use configurable timeouts with sanitization:
```c
/* Per-socket timeout configuration */
SocketTimeouts_T timeouts;
Socket_timeouts_getdefaults(&timeouts);

/* Sanitize negative values to zero */
timeouts.connect_timeout_ms = (timeout_ms < 0) ? 0 : timeout_ms;
timeouts.dns_timeout_ms = SOCKET_DEFAULT_DNS_TIMEOUT_MS;

/* Propagate to async DNS requests */
SocketDNS_request_settimeout(dns, req, timeouts.dns_timeout_ms);
```

### Safe System Call Pattern
**ALWAYS** use safe wrappers for system calls:
```c
/* SAFE_CLOSE: Per POSIX.1-2008, do NOT retry on EINTR */
SAFE_CLOSE(fd);

/* Safe non-blocking check */
ssize_t n = recv(fd, buf, len, 0);
if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK)
        return 0;  /* Would block - not an error */
    if (errno == EINTR)
        continue;  /* Interrupted - retry */
    /* Real error */
    SOCKET_ERROR_FMT("recv failed");
    RAISE_SOCKET_ERROR(Socket_Failed);
}
```

### Buffer Bounds Safety Pattern
**ALWAYS** check bounds before buffer operations:
```c
/* Validate buffer size before allocation */
if (!SOCKET_VALID_BUFFER_SIZE(requested_size))
    RAISE_ERROR(Module_InvalidInput);

/* Check for overflow before arithmetic */
if (nbytes > SIZE_MAX / 2)  /* Conservative limit */
    return NULL;

/* Circular buffer wrap-around */
size_t chunk = capacity - tail;
if (chunk > len - written)
    chunk = len - written;

/* Safety check: ensure indices are valid */
if (tail >= capacity) {
    tail = 0;
    continue;
}

/* Secure clear before reuse */
SocketBuf_secureclear(buf);
```

### Rate Limiting Pattern (SocketRateLimit)
**ALWAYS** use token bucket rate limiter for connection/bandwidth throttling:
```c
/* Create rate limiter: 100 tokens/sec, burst capacity 50 */
SocketRateLimit_T limiter = SocketRateLimit_new(arena, 100, 50);

/* Non-blocking acquire */
if (SocketRateLimit_try_acquire(limiter, 1)) {
    /* Allowed - proceed with operation */
    handle_request();
} else {
    /* Rate limited - wait or reject */
    int64_t wait_ms = SocketRateLimit_wait_time_ms(limiter, 1);
    /* Either sleep(wait_ms) or reject with 429 Too Many Requests */
}

/* Runtime reconfiguration */
SocketRateLimit_configure(limiter, new_rate, new_burst);
```

### Per-IP Connection Tracking Pattern (SocketIPTracker)
**ALWAYS** use IP tracker for DoS prevention:
```c
/* Create tracker: max 10 connections per IP */
SocketIPTracker_T tracker = SocketIPTracker_new(arena, 10);

/* On new connection */
const char *client_ip = Socket_getpeeraddr(client);
if (SocketIPTracker_track(tracker, client_ip)) {
    /* Allowed - connection tracked */
    SocketPool_add(pool, client);
} else {
    /* Limit reached - reject connection */
    Socket_free(&client);
}

/* On connection close */
SocketIPTracker_release(tracker, client_ip);
```

### Auto-Reconnection Pattern (SocketReconnect)
**ALWAYS** use reconnection context for resilient connections:
```c
/* Create reconnecting connection with policy */
SocketReconnect_Policy_T policy;
SocketReconnect_policy_defaults(&policy);
policy.max_attempts = 5;
policy.initial_delay_ms = 100;
policy.max_delay_ms = 30000;

SocketReconnect_T conn = SocketReconnect_new("example.com", 443, &policy,
                                              state_change_callback, userdata);
SocketReconnect_connect(conn);

/* Event loop integration */
while (running) {
    int timeout = SocketReconnect_next_timeout_ms(conn);
    SocketPoll_wait(poll, &events, timeout);
    SocketReconnect_process(conn);  /* Handle poll events */
    SocketReconnect_tick(conn);     /* Process timers/backoff */
}

/* I/O with auto-reconnect on error */
ssize_t n = SocketReconnect_send(conn, data, len);  /* Auto-reconnects on failure */
```

### Happy Eyeballs Pattern (RFC 8305)
**ALWAYS** use Happy Eyeballs for dual-stack connection racing:
```c
/* Synchronous (simple) - races IPv6/IPv4, returns fastest */
Socket_T sock = SocketHappyEyeballs_connect("example.com", 443, NULL);

/* Asynchronous (event-driven) */
SocketHE_Config_T config;
SocketHappyEyeballs_config_defaults(&config);
config.first_attempt_delay_ms = 250;  /* RFC 8305 recommendation */

SocketHE_T he = SocketHappyEyeballs_start(dns, poll, "example.com", 443, &config);
while (!SocketHappyEyeballs_poll(he)) {
    int timeout = SocketHappyEyeballs_next_timeout_ms(he);
    SocketPoll_wait(poll, &events, timeout);
    SocketHappyEyeballs_process(he);
}
Socket_T sock = SocketHappyEyeballs_result(he);  /* Winning socket */
SocketHappyEyeballs_free(&he);
```

### Timer Integration Pattern (SocketTimer)
**ALWAYS** use SocketTimer for event loop timer management:
```c
/* Add one-shot timer */
SocketTimer_T timer = SocketTimer_add(poll, 5000, timeout_callback, userdata);

/* Add repeating timer */
SocketTimer_T heartbeat = SocketTimer_add_repeating(poll, 30000,
                                                     heartbeat_callback, userdata);

/* Cancel timer */
SocketTimer_cancel(poll, timer);

/* Check remaining time */
int64_t remaining = SocketTimer_remaining(poll, heartbeat);
```

### Logging and Metrics Pattern (SocketUtil)
**ALWAYS** use consolidated utility functions:
```c
/* Logging with configurable callback */
SocketLog_setcallback(custom_logger, userdata);
SocketLog_emitf(SOCKET_LOG_INFO, "Socket", "Connected to %s:%d", host, port);

/* Metrics collection */
SocketMetrics_increment(SOCKET_METRIC_SOCKET_CONNECT_SUCCESS);
SocketMetricsSnapshot snap;
SocketMetrics_snapshot(&snap);

/* Event dispatching */
SocketEvents_emit(SOCKET_EVENT_CONNECTED, socket, userdata);
```

### SocketBase_T Shared State Pattern
**ALWAYS** use SocketCommon for shared socket functionality:
```c
/* Create base socket with shared state */
SocketBase_T base = SocketCommon_new_base(AF_INET, SOCK_STREAM, 0);

/* Use common helpers */
SocketCommon_set_option_int(base, SOL_SOCKET, SO_REUSEADDR, 1, Socket_Failed);
SocketCommon_set_nonblock(base, true, Socket_Failed);

/* iovec helpers for vectored I/O */
size_t total = SocketCommon_calculate_total_iov_len(iov, iovcnt);
SocketCommon_advance_iov(iov, iovcnt, bytes_sent);

/* Cleanup */
SocketCommon_free_base(&base);
```

### Live Socket Count Tracking Pattern
**ALWAYS** use SocketLiveCount for debugging/leak detection:
```c
/* Static tracker (module-level) */
static struct SocketLiveCount live_count = SOCKETLIVECOUNT_STATIC_INIT;

/* In constructor */
SocketLiveCount_increment(&live_count);

/* In destructor */
SocketLiveCount_decrement(&live_count);

/* In tests - verify all sockets freed */
assert(SocketLiveCount_get(&live_count) == 0);
/* Or use module-specific: Socket_debug_live_count() */
```

### UDP Datagram Pattern
**ALWAYS** use proper datagram semantics:
```c
/* UDP: No listen/accept, use sendto/recvfrom */
SocketDgram_T dgram = SocketDgram_new(AF_INET, 0);
SocketDgram_bind(dgram, NULL, 5000);

/* Receive with sender info */
char sender_host[NI_MAXHOST];
int sender_port;
ssize_t n = SocketDgram_recvfrom(dgram, buffer, SAFE_UDP_SIZE,
                                  sender_host, sizeof(sender_host),
                                  &sender_port);

/* Reply to sender */
SocketDgram_sendto(dgram, response, len, sender_host, sender_port);
```

### Unix Domain Socket Pattern
**ALWAYS** handle socket file cleanup:
```c
/* Remove stale socket file before bind */
const char *path = "/tmp/my_socket.sock";
unlink(path);  /* Ignore errors - file may not exist */

Socket_T unix_sock = Socket_new(AF_UNIX, SOCK_STREAM, 0);
Socket_bind_unix(unix_sock, path);

/* Cleanup on exit */
Socket_free(&unix_sock);
unlink(path);  /* Remove socket file */
```

## Refactoring Output Format

For each refactoring suggestion, provide:

1. **Category**: Function Extraction / Duplication / Performance / Simplification / Style / Organization / Memory / Error Handling
2. **Priority**: High / Medium / Low
3. **Location**: File name and line number(s)
4. **Current Code**: Brief excerpt showing the issue
5. **Issue**: Clear description of what could be improved
6. **Suggestion**: Specific refactoring recommendation with rationale
7. **Proposed Change**: Code example showing the improved version
8. **Benefits**: What improvements this would bring (readability, performance, maintainability)
9. **Risks**: Any potential issues or considerations
10. **Reference**: Link to existing good pattern in codebase (if applicable)

## Refactoring Process

1. **Analyze code structure** - Understand the overall architecture and flow
2. **Identify patterns** - Look for repeated code, similar functions, common operations
3. **Assess complexity** - Find overly complex functions or logic
4. **Check style compliance** - Verify adherence to C Interfaces and Implementations style AND GNU C style guidelines (both are required)
5. **Evaluate performance** - Look for optimization opportunities
6. **Propose improvements** - Suggest specific, actionable refactorings
7. **Consider impact** - Ensure refactorings maintain functionality and improve code quality

## Refactoring Principles

### Core Principles
- **Preserve functionality** - All refactorings must maintain existing behavior
- **Small Single-Use Functions** - CRITICAL: Functions MUST be under 20 lines and do ONE thing. Extract aggressively.
- **No Magic Numbers** - CRITICAL: ALL numeric constants must be named. Use `#define` in `SocketConfig.h` or module headers.
- **Improve readability** - Code should be easier to understand after refactoring
- **Enhance maintainability** - Code should be easier to modify and extend
- **Single responsibility** - Functions should do one thing well - enforce strictly
- **DRY principle** - Don't Repeat Yourself

### Style & Documentation
- **Maintain C Interfaces and Implementations style** - CRITICAL: All changes must strictly follow C Interfaces and Implementations patterns (Hanson, 1996). This includes header organization, type definitions, function documentation, and module structure.
- **Maintain GNU C style** - All changes must follow GNU C coding standards (return types on separate lines, 8-space indentation, etc.)
- **Opaque types only** - Headers must expose only opaque pointer types, never structure definitions
- **Comprehensive documentation** - All public functions must have Doxygen-style comments with @param, @returns, Raises:, Thread-safe: notes
- **Const correctness** - Use `const` for read-only parameters and return values

### Memory & Safety
- **Security first** - Eliminate vulnerabilities before optimizing
- **Use Arena allocation** - Prefer `Arena_alloc` over `malloc` for related objects
- **Overflow protection** - Always check for integer overflow before arithmetic
- **Buffer bounds checking** - Validate indices before buffer access
- **Secure clearing** - Use `SocketBuf_secureclear` for sensitive data

### Error Handling & Thread Safety
- **Use exception system** - Prefer `TRY/EXCEPT/FINALLY` over return codes
- **Thread-local exceptions** - Copy exceptions to thread-local storage before modifying
- **Safe system calls** - Use `SAFE_CLOSE` and similar wrappers

### Integration & Performance
- **Leverage existing codebase** - Reuse existing functions and patterns (Arena, Exception system, SocketError, SocketConfig, SocketDNS), don't reinvent
- **Follow module patterns** - Adhere to established module design patterns
- **Reduce duplication** - Extract common patterns to avoid code repetition
- **Optimize performance** - Where possible, improve efficiency without sacrificing clarity

### Async & Platform Patterns
- **Non-blocking DNS** - Use `SocketDNS` for hostname resolution to avoid blocking
- **Edge-triggered handling** - Drain until EAGAIN in edge-triggered event loops
- **Platform abstraction** - Use `SocketPoll` API, never direct epoll/kqueue/poll
- **TLS1.3 enforcement** - Always use `SocketTLSConfig.h` constants for TLS configuration

## Example Refactoring Patterns

### Function Extraction Example
```
[Function Extraction/High] Socket.c:150-185
Current Code: Socket_bind() contains 35 lines mixing DNS resolution, validation, and binding
Issue: Socket_bind() exceeds 20-line limit and does multiple things - DNS resolution, address validation, and binding
Suggestion: Extract DNS resolution to resolve_address() helper, extract validation to validate_bind_params() helper
Proposed Change:
  static int
  resolve_address(const char *host, int port, struct addrinfo **res)
  {
    // DNS resolution logic here (must be < 20 lines)
  }
  
  static void
  validate_bind_params(const char *host, int port)
  {
    // Validation logic here (must be < 20 lines)
  }
  
  void Socket_bind(T socket, const char *host, int port)
  {
    struct addrinfo *res = NULL;
    validate_bind_params(host, port);
    if (resolve_address(host, port, &res) != 0)
      RAISE_SOCKET_ERROR(Socket_Failed);
    // Binding logic here (must be < 20 lines total)
  }
Benefits: Improved readability, easier testing, single responsibility, meets 20-line limit
Risks: None - pure refactoring, no behavior change
Reference: See Socket.c resolve_address() pattern
```

### Memory Management Example
```
[Memory/High] CustomModule.c:45-60
Current Code: Uses malloc() for multiple related objects with manual cleanup
Issue: Multiple malloc/free calls create memory leak risk and don't follow Arena pattern
Suggestion: Use Arena allocation for related objects
Proposed Change:
  TRY
    arena = Arena_new();
    if (!arena)
    {
      MODULE_ERROR_MSG(MODULE_ENOMEM ": Cannot allocate arena");
      RAISE_MODULE_ERROR(Module_Failed);
    }
    
    object1 = ALLOC(arena, sizeof(*object1));
    object2 = ALLOC(arena, sizeof(*object2));
    object3 = ALLOC(arena, sizeof(*object3));
    
    // Use objects...
    
  FINALLY
    Arena_dispose(&arena);  // Frees all objects at once
  END_TRY;
Benefits: Automatic cleanup, no memory leaks, follows codebase patterns
Risks: None - Arena is designed for this pattern
Reference: See Socket.c for Arena usage patterns
```

### Error Handling Example
```
[Error Handling/High] CustomModule.c:120-145
Current Code: Uses return codes and manual error handling with goto cleanup
Issue: Doesn't follow exception-based error handling pattern used throughout codebase
Suggestion: Convert to TRY/EXCEPT/FINALLY pattern
Proposed Change:
  TRY
    resource1 = acquire_resource1();
    resource2 = acquire_resource2();
    resource3 = acquire_resource3();
    
    perform_operation(resource1, resource2, resource3);
    
  EXCEPT(Module_Failed)
    fprintf(stderr, "Error: %s\n", Module_GetLastError());
    RERAISE;
  FINALLY
    if (resource3) release_resource3(&resource3);
    if (resource2) release_resource2(&resource2);
    if (resource1) release_resource1(&resource1);
  END_TRY;
Benefits: Consistent error handling, automatic cleanup, follows codebase patterns
Risks: None - exception system is thread-safe and reliable
Reference: See Socket.c, SocketPoll.c for exception handling patterns
```

### Magic Number Elimination Example
```
[Simplification/Critical] CustomModule.c:78, 142
Current Code: Hardcoded values like `1024`, `256`, `5` used directly in code
Issue: Magic numbers make code unmaintainable and unclear
Suggestion: Replace ALL magic numbers with named constants in SocketConfig.h or module header
Proposed Change:
  // In SocketConfig.h or CustomModule.h:
  #define MODULE_DEFAULT_BUFFER_SIZE 1024
  #define MODULE_ERROR_BUFSIZE 256
  #define MODULE_MAX_RETRIES 5
  
  // In code:
  char buffer[MODULE_DEFAULT_BUFFER_SIZE];
  if (retries < MODULE_MAX_RETRIES) { ... }
Benefits: Self-documenting code, easier to maintain, consistent values across codebase
Risks: None - improves code quality
Reference: See SocketConfig.h for configuration constant patterns
```

### Duplication Detection Example
```
[Duplication/Medium] Socket.c:200, SocketDgram.c:150
Current Code: Similar DNS resolution logic in two places
Issue: DNS resolution code duplicated with slight variations
Suggestion: Extract to SocketDNS module or shared helper function
Proposed Change: Use SocketDNS_resolve() from DNS module, or extract to shared resolve_address() helper
Benefits: Single source of truth, easier to maintain, consistent error handling
Risks: Need to ensure both use cases are compatible
Reference: See SocketDNS module for async DNS resolution patterns
```

### Const Correctness Example
```
[Style/Medium] SocketPoll.c:85
Current Code: static unsigned socket_hash(Socket_T socket)
Issue: Parameter is read-only but not marked const
Suggestion: Add const qualifier to read-only parameters
Proposed Change:
  static unsigned socket_hash(const Socket_T socket)
  {
      int fd;
      assert(socket);
      fd = Socket_fd(socket);
      assert(fd >= 0);  /* Defensive check */
      return ((unsigned)fd * 2654435761u) % SOCKET_HASH_SIZE;
  }
Benefits: Compiler can optimize, documents intent, catches accidental modifications
Risks: None - pure improvement
Reference: See SocketPool.c socket_hash() pattern
```

### Large File Splitting Example
```
[Organization/Medium] LargeModule.c (1500+ lines)
Current Code: Single file with all functionality mixed together
Issue: File exceeds recommended size, making navigation and maintenance difficult
Suggestion: Split into focused files following codebase patterns
Proposed Change:
  /* Split pattern (see SocketPool as reference): */
  LargeModule-core.c     - Creation, destruction, configuration
  LargeModule-ops.c      - Main operations, data manipulation
  LargeModule-internal.c - Internal helpers, private functions

  /* Split pattern (see SocketTLSContext as reference): */
  LargeModule-core.c     - Primary module logic
  LargeModule-feature1.c - Feature-specific code (e.g., certs, alpn)
  LargeModule-feature2.c - Another feature (e.g., session, verify)

  /* Create private header for cross-file communication: */
  LargeModule-private.h  - Internal structures, shared between split files

Benefits: Easier navigation, focused files, parallel development possible
Risks: Must maintain include order and private header consistency
Reference: See SocketPool-*.c and SocketTLSContext-*.c patterns
```

### Rate Limiting Integration Example
```
[Rate Limiting/Medium] Server.c:accept_connection()
Current Code: No rate limiting on incoming connections
Issue: Server vulnerable to connection floods/DoS
Suggestion: Add rate limiter using SocketRateLimit module
Proposed Change:
  static SocketRateLimit_T conn_limiter = NULL;

  void server_init(void)
  {
      /* Allow 100 connections/sec with burst of 50 */
      conn_limiter = SocketRateLimit_new(arena, 100, 50);
  }

  void accept_connection(Socket_T server)
  {
      if (!SocketRateLimit_try_acquire(conn_limiter, 1)) {
          /* Rate limited - optionally log and return */
          SocketLog_emitf(SOCKET_LOG_WARN, "Server",
                          "Connection rate limited");
          return;
      }
      /* Proceed with accept */
      Socket_T client = Socket_accept(server);
      /* ... */
  }
Benefits: DoS protection, configurable limits, thread-safe
Risks: May reject legitimate traffic if misconfigured
Reference: See SocketRateLimit.h for full API
```

### Happy Eyeballs Migration Example
```
[Happy Eyeballs/High] Client.c:connect_to_server()
Current Code: Sequential IPv4-only connection
Issue: Not using dual-stack, may be slow if IPv6 available
Suggestion: Use Happy Eyeballs for RFC 8305 compliant connection racing
Proposed Change:
  /* Before (IPv4-only, blocking) */
  Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
  Socket_connect(sock, "example.com", 443);

  /* After (dual-stack, races IPv6/IPv4) */
  Socket_T sock = SocketHappyEyeballs_connect("example.com", 443, NULL);
  /* sock is connected via fastest address family */

  /* For custom timeouts: */
  SocketHE_Config_T config;
  SocketHappyEyeballs_config_defaults(&config);
  config.total_timeout_ms = 10000;  /* 10 second total timeout */
  Socket_T sock = SocketHappyEyeballs_connect("example.com", 443, &config);
Benefits: Faster connections on dual-stack networks, RFC 8305 compliant
Risks: Slightly more complex error handling (multiple failures possible)
Reference: See SocketHappyEyeballs.h and .cursor/rules/happy-eyeballs.mdc
```

### Async DNS Migration Example
```
[Async I/O/High] Module.c:120-150
Current Code: Uses blocking getaddrinfo() directly
Issue: getaddrinfo() can block for 30+ seconds during DNS failures - DoS vulnerability
Suggestion: Migrate to SocketDNS async resolution
Proposed Change:
  /* Before (blocking - DANGEROUS) */
  Socket_bind(socket, "example.com", 8080);  /* Blocks! */

  /* After (non-blocking) */
  SocketDNS_T dns = SocketDNS_new();
  SocketDNS_Request_T req = Socket_bind_async(dns, socket, "example.com", 8080);
  SocketDNS_request_settimeout(dns, req, 2000);  /* 2s timeout */
  
  /* In event loop: check SocketDNS_pollfd(dns) for completion */
  SocketDNS_check(dns);
  struct addrinfo *res = SocketDNS_getresult(dns, req);
  if (res) {
      Socket_bind_with_addrinfo(socket, res);
      freeaddrinfo(res);  /* REQUIRED */
  }
Benefits: Non-blocking, timeout protection, DoS resistant
Risks: More complex code flow - document async pattern clearly
Reference: See .cursor/rules/async-dns.mdc for complete patterns
```

### TLS Security Hardening Example
```
[TLS/Critical] TLSModule.c:45-60
Current Code: Uses TLS1.2 or allows legacy cipher suites
Issue: Not using TLS1.3-only configuration - security risk
Suggestion: Use SocketTLSConfig.h constants for TLS1.3-only
Proposed Change:
  #include "tls/SocketTLSConfig.h"
  
  /* Configure TLS1.3-only (REQUIRED) */
  SSL_CTX_set_min_proto_version(ctx, SOCKET_TLS_MIN_VERSION);
  SSL_CTX_set_max_proto_version(ctx, SOCKET_TLS_MAX_VERSION);
  SSL_CTX_set_ciphersuites(ctx, SOCKET_TLS13_CIPHERSUITES);
  
  /* Verify peer certificate */
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
Benefits: Eliminates legacy protocol vulnerabilities, faster handshakes, forward secrecy
Risks: TLS1.3 requires OpenSSL 1.1.1+ - verify minimum supported version
Reference: See SocketTLSConfig.h for all configuration constants
```

### Cross-Platform Backend Example
```
[Cross-Platform/Medium] EventHandler.c:80-100
Current Code: Direct epoll_create1() and epoll_wait() calls
Issue: Not portable to BSD/macOS (requires kqueue) or POSIX fallback (poll)
Suggestion: Use SocketPoll abstraction for portability
Proposed Change:
  /* Before (Linux-only) */
  int epfd = epoll_create1(0);
  struct epoll_event ev = {.events = EPOLLIN | EPOLLET};
  epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
  int n = epoll_wait(epfd, events, maxevents, timeout);
  
  /* After (portable) */
  SocketPoll_T poll = SocketPoll_new(maxevents);
  SocketPoll_add(poll, socket, POLL_READ, user_data);
  SocketEvent_T *events;
  int n = SocketPoll_wait(poll, &events, timeout);
Benefits: Works on Linux (epoll), BSD/macOS (kqueue), and all POSIX (poll fallback)
Risks: Slight abstraction overhead - negligible in practice
Reference: See .cursor/rules/cross-platform-backends.mdc
```

### Edge-Triggered Event Handling Example
```
[Performance/High] EventLoop.c:200-220
Current Code: Single read on POLL_READ event
Issue: Edge-triggered mode requires draining until EAGAIN
Suggestion: Loop until EAGAIN to handle all available data
Proposed Change:
  /* Handle readable socket in edge-triggered mode */
  while (1) {
      ssize_t n = Socket_recv(socket, buffer, sizeof(buffer));
      if (n > 0) {
          process_data(buffer, n);
          continue;
      }
      if (n == 0 || errno == EAGAIN || errno == EWOULDBLOCK)
          break;  /* No more data or would block */
      /* Real error */
      SOCKET_ERROR_FMT("recv failed");
      RAISE_SOCKET_ERROR(Socket_Failed);
  }
Benefits: Correctly handles edge-triggered semantics, no missed events
Risks: Must handle partial reads properly
Reference: See SocketPoll documentation for edge-triggered behavior
```

### Buffer Safety Example
```
[Security/Critical] BufferOps.c:150-180
Current Code: No bounds checking before buffer arithmetic
Issue: Potential buffer overflow if indices become invalid
Suggestion: Add comprehensive bounds checking
Proposed Change:
  size_t SocketBuf_write(T buf, const void *data, size_t len)
  {
      assert(buf && buf->data);
      assert(data || len == 0);
      assert(buf->size <= buf->capacity);
      
      /* Check space available */
      size_t space = buf->capacity - buf->size;
      if (len > space)
          len = space;
      
      while (written < len) {
          size_t chunk = buf->capacity - buf->tail;
          if (chunk > len - written)
              chunk = len - written;
          
          /* Safety: ensure tail is valid */
          if (buf->tail >= buf->capacity) {
              buf->tail = 0;
              continue;
          }
          
          /* Safety: don't write beyond buffer */
          if (buf->tail + chunk > buf->capacity)
              chunk = buf->capacity - buf->tail;
          
          memcpy(buf->data + buf->tail, src + written, chunk);
          buf->tail = (buf->tail + chunk) % buf->capacity;
          written += chunk;
      }
      
      buf->size += written;
      return written;
  }
Benefits: Prevents buffer overflows, handles wrap-around safely
Risks: None - defensive programming
Reference: See SocketBuf.c for complete circular buffer implementation
```

## Focus Areas by File Type

### Core Modules
- **Arena.c**: Already well-refactored; use as reference for patterns. Chunk management, overflow protection.
- **Except.c**: Exception handling foundation. Thread-local stack, RAISE/TRY/EXCEPT implementation.
- **SocketUtil.c**: Consolidated utilities (logging, metrics, events, error handling). Thread-safe callbacks.
- **SocketRateLimit.c**: Token bucket rate limiter. Thread-safe acquire/wait patterns.
- **SocketIPTracker.c**: Per-IP connection tracking. O(1) hash table lookups, automatic cleanup.
- **SocketTimer.c**: Timer subsystem. Min-heap storage, one-shot/repeating timers, event loop integration.

### Socket Modules
- **Socket.c / Socket-*.c**: Function extraction, socket operation abstraction, timeout configuration, option setters.
- **SocketDgram.c**: UDP-specific patterns, sendto/recvfrom semantics, message boundary handling.
- **SocketCommon.c**: Shared utilities (address resolution, socket options, iovec helpers, SocketBase_T).
- **SocketAsync.c**: Async operation patterns, non-blocking mode, completion callbacks.
- **SocketBuf.c**: Circular buffer safety, bounds checking, secure clearing, zero-copy operations.
- **SocketIO.c**: Vectored I/O (iovec), scatter-gather patterns.
- **SocketReconnect.c**: Auto-reconnection with exponential backoff, circuit breaker, health monitoring.
- **SocketHappyEyeballs.c**: RFC 8305 dual-stack connection racing, async/sync APIs, timeout management.

### DNS Module
- **SocketDNS.c / SocketDNS-internal.c**: Thread pool patterns, request queue management, completion signaling via pipe, timeout enforcement.

### Event System
- **SocketPoll.c**: Frontend event loop, socket→data mapping, default timeout handling.
- **SocketPoll_epoll.c**: Linux epoll backend, edge-triggered mode, event translation.
- **SocketPoll_kqueue.c**: BSD/macOS kqueue backend, EV_CLEAR for edge-trigger behavior.
- **SocketPoll_poll.c**: POSIX poll(2) fallback, FD→index mapping for O(1) lookup.

### Connection Management
- **SocketPool-core.c**: Pool creation/destruction, configuration, statistics.
- **SocketPool-connections.c**: Connection add/remove, hash table management.
- **SocketPool-ops.c**: Connection operations, iteration, cleanup.
- **SocketPool-ratelimit.c**: Per-pool rate limiting integration.

### TLS/SSL Modules
- **SocketTLS.c**: TLS1.3 operations, handshake handling, secure I/O wrappers.
- **SocketTLSContext-core.c**: SSL_CTX creation/destruction, basic configuration.
- **SocketTLSContext-certs.c**: Certificate/key loading, chain configuration.
- **SocketTLSContext-alpn.c**: ALPN protocol negotiation.
- **SocketTLSContext-session.c**: Session resumption, ticket handling.
- **SocketTLSContext-verify.c**: Certificate verification, hostname validation.
- **SocketTLSConfig.h**: Configuration constants, cipher suites, buffer sizes - DO NOT weaken security settings.

### Headers
- **Organization**: Include guards with `_INCLUDED` suffix, system headers first, module documentation.
- **Private headers** (`*-private.h`): Internal structures, not part of public API. Used for split-file modules.
- **Public headers**: Opaque types only, `extern` function declarations, comprehensive Doxygen comments.

## Output Format for Refactored Code

When refactoring a file, provide:

1. **Fully refactored C code** - Complete, production-ready code in a single block
2. **Change Summary** - Categorized by:
   - Security improvements (vulnerabilities fixed)
   - Function extraction (functions split, new helpers created)
   - Magic number elimination (constants added, locations - should go in SocketConfig.h or module headers)
   - Performance optimizations
   - Redundancy removal
   - Error handling improvements (conversion to exception system)
   - Style compliance fixes
   - Memory management improvements (Arena usage)
3. **Assumptions** - Note any assumptions made about the codebase context
4. **Function Breakdown** - List of new helper functions created and their purposes
5. **Constants Added** - List of new named constants with their locations (preferably SocketConfig.h or module headers)

## Critical Requirements Checklist

Before completing refactoring, verify:

### Code Structure
- [ ] All functions are under 20 lines (extract helpers aggressively)
- [ ] All functions have single responsibility
- [ ] All magic numbers replaced with named constants (preferably in SocketConfig.h)
- [ ] All TODOs/FIXMEs removed or implemented
- [ ] All .c and .h files are under 20000 lines of code
- [ ] Each .c and .h file serves a single purpose
- [ ] No functionality changed (only refactored)
- [ ] Code is production-ready

### Style Compliance
- [ ] Code follows C Interfaces and Implementations style (header organization, type definitions, documentation, opaque types)
- [ ] Code follows GNU C style (return types on separate lines, 8-space indentation, spacing)
- [ ] Module naming conventions followed (ModuleName_ prefix pattern)
- [ ] Type definitions use T macro pattern with `#undef T` at end
- [ ] Include guards use `_INCLUDED` suffix pattern
- [ ] Header files expose only opaque types (no structure definitions in headers)
- [ ] All public functions have comprehensive Doxygen-style documentation
- [ ] Function declarations use `extern` keyword in headers
- [ ] Static functions documented with Doxygen comments

### Memory Management
- [ ] Memory allocations use Arena where appropriate (for related objects)
- [ ] Buffer sizes validated with `SOCKET_VALID_BUFFER_SIZE`
- [ ] Overflow protection before arithmetic (check `SIZE_MAX/2` limit)
- [ ] Sensitive data cleared with `SocketBuf_secureclear`
- [ ] Socket lifecycle verified (`Socket_debug_live_count()` is zero at teardown)

### Error Handling
- [ ] Error handling uses exception system (TRY/EXCEPT/FINALLY)
- [ ] Thread-safe exception patterns (thread-local `Module_DetailedException`)
- [ ] System calls use safe wrappers (`SAFE_CLOSE`, etc.)
- [ ] Error messages use standardized format (`MODULE_ERROR_FMT`/`MODULE_ERROR_MSG`)

### Thread Safety
- [ ] Thread-local storage for per-thread data
- [ ] Mutex protection for shared data structures
- [ ] No modification of global exception structures directly
- [ ] Const correctness for read-only parameters

### Security
- [ ] Security vulnerabilities addressed (buffer overflows, integer overflows)
- [ ] TLS code uses TLS1.3-only configuration from `SocketTLSConfig.h`
- [ ] No legacy cipher suites or protocol versions
- [ ] Input validation at API boundaries

### Async & Event Patterns
- [ ] Blocking DNS uses `SocketDNS` async resolution
- [ ] Edge-triggered events drain until EAGAIN
- [ ] Timeout configuration respected and propagated
- [ ] Async resources properly cleaned up (`freeaddrinfo`)
- [ ] Timer-based operations use `SocketTimer` module

### Platform Compatibility
- [ ] Uses `SocketPoll` API, not direct epoll/kqueue/poll
- [ ] Platform-specific code isolated to backend files
- [ ] No assumptions about specific backend

### Rate Limiting & DoS Protection
- [ ] Connection rate limiting uses `SocketRateLimit` module
- [ ] Per-IP tracking uses `SocketIPTracker` module
- [ ] Max connections per IP configured appropriately
- [ ] Rate limiter tokens/burst configured for use case

### Resilience Patterns
- [ ] Client connections use `SocketReconnect` for auto-reconnection
- [ ] Exponential backoff configured with appropriate limits
- [ ] Circuit breaker thresholds set appropriately
- [ ] Dual-stack connections use `SocketHappyEyeballs`

### Observability
- [ ] Logging uses `SocketLog_emit`/`SocketLog_emitf`
- [ ] Key operations increment appropriate metrics
- [ ] Live socket count tracked via `SocketLiveCount` or `Socket_debug_live_count()`

### Existing Codebase Integration
- [ ] Existing codebase functions leveraged (Arena, Exception system, SocketUtil, SocketConfig)
- [ ] Shared utilities use `SocketCommon_*` helpers (address resolution, iovec, options)
- [ ] Patterns match existing modules (consult `.cursor/rules/` for details)
- [ ] Large files split following SocketPool/SocketTLSContext patterns

## C Interfaces and Implementations Style Examples

### Correct Header File Pattern
```c
#ifndef MODULENAME_INCLUDED
#define MODULENAME_INCLUDED

#include <stddef.h>  /* System headers first */

/**
 * ModuleName - Brief module description
 *
 * Detailed description of module purpose, features, and behavior.
 * Include information about thread safety, performance characteristics,
 * and any important usage notes.
 *
 * Features:
 * - Feature 1 with brief description
 * - Feature 2 with brief description
 *
 * Usage example:
 *   ModuleName_T instance = ModuleName_new();
 *   ModuleName_operation(instance);
 *   ModuleName_free(&instance);
 */

#define T ModuleName_T
typedef struct T *T;  /* Opaque pointer type */

/**
 * ModuleName_new - Create a new module instance
 *
 * Returns: New instance, or NULL on failure
 * Thread-safe: Yes
 */
extern T ModuleName_new(void);

/**
 * ModuleName_free - Free module instance
 * @instance: Pointer to instance pointer (will be set to NULL)
 *
 * Thread-safe: No
 */
extern void ModuleName_free(T *instance);

#undef T
#endif
```

### Correct Implementation File Pattern
```c
/**
 * ModuleName.c - Module implementation description
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 */

#include <assert.h>  /* System headers first */
#include <stdlib.h>
#include "core/ModuleName.h"  /* Project headers */
#include "core/SocketConfig.h"

#define T ModuleName_T

/* Static helper functions first */
static void helper_function(T instance)
{
    /* Implementation */
}

/* Public function implementations */
T
ModuleName_new(void)
{
    T instance;
    
    instance = malloc(sizeof(*instance));
    if (instance == NULL)
        return NULL;
    
    /* Initialize */
    return instance;
}

void
ModuleName_free(T *instancep)
{
    assert(instancep && *instancep);
    
    free(*instancep);
    *instancep = NULL;
}

#undef T
```

Provide prioritized refactoring suggestions when analyzing, starting with high-impact improvements that enhance maintainability and code quality while preserving functionality and adhering to **both** C Interfaces and Implementations style standards **and** GNU C style standards, plus socket library patterns. When actually refactoring, provide complete refactored code ready for production use that follows all conventions.
