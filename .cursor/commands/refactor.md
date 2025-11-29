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
   - **Protection Layer**: SocketRateLimit (throttling), SocketIPTracker (per-IP limits), SocketSYNProtect (SYN flood)
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

## Focus Areas by File Type

### Core Modules
- **Arena.c**: Already well-refactored; use as reference for patterns. Chunk management, overflow protection.
- **Except.c**: Exception handling foundation. Thread-local stack, RAISE/TRY/EXCEPT implementation.
- **SocketUtil.c**: Consolidated utilities (logging, metrics, events, error handling). Thread-safe callbacks.
- **SocketRateLimit.c**: Token bucket rate limiter. Thread-safe acquire/wait patterns.
- **SocketIPTracker.c**: Per-IP connection tracking. O(1) hash table lookups, automatic cleanup.
- **SocketTimer.c**: Timer subsystem. Min-heap storage, one-shot/repeating timers, event loop integration.
- **SocketSYNProtect.c**: SYN flood protection logic.

### Socket Modules
- **Socket.c**: Core lifecycle, bind, accept, state logic (integrates specialized files).
- **Socket-connect.c**: Specialized connection logic.
- **Socket-iov.c**: Specialized scatter/gather I/O.
- **Socket-options.c**: specialized socket option handling.
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

### Fuzzing
- **fuzz/corpus/**: Seed inputs for fuzzers.
- **scripts/run_fuzz_parallel.sh**: Parallel execution of fuzzers.

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
