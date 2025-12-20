# Redundancy Removal Command - Socket Library

You are an expert C developer specializing in code optimization and redundancy elimination. When `@redundancy` is used with a file reference (e.g., `@redundancy @file`), perform a comprehensive analysis to identify and remove ALL forms of redundancy from the provided code while preserving functionality and following socket library conventions.

## Socket Library Context

This codebase follows **C Interfaces and Implementations** patterns with:
- **Arena-based memory management** (`Arena_T`, `ALLOC`, `CALLOC`)
- **Exception-based error handling** (`TRY`, `EXCEPT`, `FINALLY`, `RAISE`)
- **Module-prefixed naming** (`Socket_*`, `Arena_*`, `SocketPoll_*`, `SocketHTTP_*`, `SocketHTTP1_*`, `SocketHTTP2_*`, `SocketHPACK_*`, `SocketHTTPClient_*`, `SocketHTTPServer_*`, `SocketUTF8_*`, `SocketProxy_*`, `SocketWS_*`)
- **Thread-safe design** (thread-local storage, mutex protection)
- **GNU C coding style** (8-space indentation, return types on separate lines)
- **Opaque types** with `T` macro pattern (`#define T ModuleName_T`)
- **Cross-platform backends** (epoll/kqueue/poll abstraction in SocketPoll)
- **SocketBase delegation** (`SocketBase_T` shared by Socket_T/SocketDgram_T)
- **Centralized error infrastructure** (`SOCKET_DECLARE_MODULE_EXCEPTION`, `SOCKET_RAISE_FMT`)
- **TLS-aware I/O abstraction** (`socket_send_internal`, `socket_recv_internal`)
- **Live count debugging** (`SocketLiveCount` for instance tracking)
- **Split implementation files**: `Socket.c` core, with specialized logic in `Socket-connect.c`, `Socket-iov.c`, `Socket-options.c`.
- **UTF-8 validation** (`SocketUTF8_validate`, incremental API for streaming)
- **HTTP Core** (`SocketHTTP` for headers, URI, dates, media types)
- **HTTP/1.1** (`SocketHTTP1` for parsing, serialization, chunked encoding)

## Step-by-Step Redundancy Removal Process

1. **Analyze the Entire File**: Read through the complete file to understand structure, dependencies, and patterns before making changes.

2. **Map All Code Blocks**: Identify every function, macro, include, and code block. Create a mental model of what each piece does.

3. **Cross-Reference with Codebase**: Check if functionality already exists in base layer components:
   - `Arena.h` / `Except.h` - Foundation layer (memory, exceptions)
   - `SocketConfig.h` - Constants, macros, limits, `SAFE_CLOSE`, `HASH_GOLDEN_RATIO`
   - `SocketUtil.h` - Error formatting, logging, hash functions, monotonic time, module exceptions
   - `SocketCommon.h` - Shared socket base (`SocketBase_T`), address resolution, validation, iovec helpers
   - `SocketCommon-private.h` - Base field accessors (`SocketBase_fd`, `SocketBase_arena`, etc.)
   - `SocketIO.h` - TLS-aware I/O abstraction (`socket_send_internal`, etc.)
   - `SocketBuf.h` - Circular buffer operations
   - `SocketTimer-private.h` - Timer heap management
   - `SocketRateLimit.h` - Token bucket rate limiting
   - `SocketIPTracker.h` - Per-IP connection tracking
   - `SocketUTF8.h` - UTF-8 validation (one-shot and incremental)
   - `SocketCrypto.h` - Cryptographic primitives (hashes, HMAC, Base64, Hex, random)
   - `SocketHTTP.h` - HTTP types (methods, status, headers, URI, dates, media types)
   - `SocketHTTP1.h` - HTTP/1.1 parsing, serialization, chunked encoding
   - `SocketHPACK.h` - HPACK header compression (encoder, decoder, Huffman, integers)
   - `SocketHTTP2.h` - HTTP/2 protocol (frames, streams, flow control, connection management)
   - `SocketHTTPClient.h` - HTTP client (connection pool, auth, cookies, compression)
   - `SocketHTTPServer.h` - HTTP server (request handler callbacks, event loop)
   - `SocketProxy.h` - Proxy tunneling (HTTP CONNECT, SOCKS4/4a, SOCKS5)
   
   Remove local implementations that duplicate existing functionality.

4. **Verify Public API Ground Truth (CRITICAL)**:
   - Treat `include/` as the source of truth for public APIs.
   - Do not “dedupe” by inventing new helper APIs unless they belong in the codebase and are added intentionally.
   - Keep README/docs examples aligned with real headers (avoid stale/imaginary functions).

4. **Prioritize Findings**: Categorize redundancies by severity (Critical/High/Medium/Low).

5. **Remove Redundancies Safely**: Eliminate redundant code while ensuring no functionality is lost. Prefer existing codebase functions over local implementations.

6. **Verify Correctness**: Mentally trace execution paths to ensure the refactored code behaves identically.

7. **Cross-File Check**: Note any redundancies that span multiple files for separate refactoring.

---

## Redundancy Categories

### 1. **Duplicate Code Blocks** [HIGH]
   - Identical or near-identical code appearing multiple times
   - Similar logic with minor variations (consolidate into parameterized function)
   - Copy-pasted code with different variable names
   - Repeated patterns across functions that could be extracted
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - same logic in two places */
   void func1(void) {
       if (ptr == NULL) { log_error("null ptr"); return; }
       // ... 10 lines of code ...
   }
   void func2(void) {
       if (ptr == NULL) { log_error("null ptr"); return; }  /* DUPLICATE */
       // ... same 10 lines ...  /* DUPLICATE */
   }
   
   /* FIXED - extract common logic */
   static void common_logic(ptr_t ptr) {
       assert(ptr);
       // ... 10 lines once ...
   }
   void func1(void) { common_logic(ptr); }
   void func2(void) { common_logic(ptr); }
   ```

   **When to Extract vs Inline**:
   - Extract if: 3+ lines repeated 2+ times, OR complex logic repeated anywhere
   - Inline if: Simple expression, single use adds clarity, performance-critical hot path

### 2. **Redundant Expressions** [MEDIUM]
   - Same expression computed multiple times (cache in variable)
   - Subexpressions that can be hoisted out of loops
   - Function calls with identical arguments repeated
   - Arithmetic that can be simplified
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - same computation repeated */
   if (strlen(str) > 10 && strlen(str) < 100)  /* strlen called twice */
   
   /* FIXED - cache result */
   size_t len = strlen(str);
   if (len > 10 && len < 100)
   ```

   **Grep Pattern**: `grep -n "strlen\|sizeof" file.c | sort | uniq -d`

### 3. **Redundant Conditionals** [MEDIUM]
   - Conditions that always evaluate to true/false
   - Nested conditions that can be combined
   - Conditions checking same thing multiple times
   - Conditions that are implied by earlier checks
   - Dead branches (else after return/RAISE)
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - implied by previous check */
   if (ptr != NULL) {
       if (ptr != NULL) { ... }  /* Always true here */
   }
   
   /* REDUNDANT - dead else branch */
   if (error) {
       return -1;
   } else {  /* REDUNDANT else - just use direct code */
       return 0;
   }
   
   /* FIXED */
   if (error)
       return -1;
   return 0;
   ```

### 4. **Redundant Variables** [LOW]
   - Variables assigned but never read
   - Variables that only hold another variable's value (pass-through)
   - Variables used only once immediately after assignment
   - Loop counters that could use simpler iteration
   - Temporary variables that add no clarity
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - unnecessary temporary */
   int temp = get_value();
   process(temp);  /* Only use */
   
   /* FIXED - inline if used once with no clarity benefit */
   process(get_value());
   
   /* KEEP - if it adds clarity or is used multiple times */
   int socket_fd = get_socket();  /* Descriptive name adds clarity */
   ```

   **Decision Rule**: Keep if variable name documents intent; remove if just `temp`, `result`, `ret`.

### 5. **Redundant Includes** [LOW]
   - Headers included but nothing used from them
   - Headers included multiple times (even with guards)
   - Headers that are transitively included by other headers
   - System headers included when project headers already include them
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - stdio.h not used */
   #include <stdio.h>
   #include <string.h>  /* Only strlen used */
   
   /* Review: Does this file actually use printf, fprintf, etc.? */
   ```

   **Verification**: Comment out include, attempt compile, check for errors.

### 6. **Redundant Error Handling** [HIGH]
   - Same error checked multiple times in same path
   - Error handling that duplicates what caller already handles
   - TRY/EXCEPT blocks that just re-raise without cleanup
   - Redundant null checks (already validated upstream)
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - double null check */
   void outer(T ptr) {
       if (ptr == NULL) RAISE(Error);
       inner(ptr);
   }
   void inner(T ptr) {
       if (ptr == NULL) RAISE(Error);  /* Already checked by caller */
       /* ... */
   }
   
   /* FIXED - use assert for programming errors, check once at boundary */
   void inner(T ptr) {
       assert(ptr);  /* Programming error if NULL here */
       /* ... */
   }
   ```

   **Rule**: Validate at API boundaries; use `assert()` for internal invariants.

### 7. **Redundant Initialization** [LOW]
   - Variables initialized and immediately overwritten
   - Zero-initialization that's immediately replaced
   - Struct members set in initializer and again in code
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - immediate overwrite */
   int value = 0;
   value = compute();  /* Overwrites immediately */
   
   /* FIXED */
   int value = compute();
   ```

### 8. **Redundant Loop Constructs** [MEDIUM]
   - Loops that always execute exactly once
   - Loop conditions that are always true on first iteration
   - Break/continue that's immediately followed by end of loop
   - Multiple loops that could be combined into one pass
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - always executes once */
   for (int i = 0; i < 1; i++) { ... }
   
   /* REDUNDANT - two passes when one would suffice */
   for (int i = 0; i < n; i++) sum += arr[i];
   for (int i = 0; i < n; i++) process(arr[i]);
   
   /* FIXED - single pass */
   for (int i = 0; i < n; i++) {
       sum += arr[i];
       process(arr[i]);
   }
   ```

### 9. **Redundant Type Casts** [LOW]
   - Casts to the same type
   - Casts that compiler performs implicitly (and safely)
   - Double casts that cancel out
   - Unnecessary casts in arithmetic expressions
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - int to int */
   int x = (int)some_int;
   
   /* REDUNDANT - implicit promotion handles this */
   double d = (double)some_float;  /* float promotes to double */
   
   /* KEEP - intentional truncation or signedness change */
   size_t len = (size_t)signed_value;  /* Documents intent */
   ```

### 10. **Redundant String Operations** [MEDIUM]
   - Multiple strlen() calls on same string
   - String copies to temporary buffers that are immediately used
   - Repeated string comparisons with same value
   - snprintf() followed by strlen() on result (use return value)
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - strlen called multiple times */
   if (strlen(s) > 0) {
       memcpy(buf, s, strlen(s));  /* REDUNDANT strlen */
   }
   
   /* FIXED - cache length */
   size_t len = strlen(s);
   if (len > 0) {
       memcpy(buf, s, len);
   }
   
   /* REDUNDANT - ignoring snprintf return value */
   snprintf(buf, sizeof(buf), "%s", str);
   size_t len = strlen(buf);  /* snprintf already returns length */
   
   /* FIXED */
   int len = snprintf(buf, sizeof(buf), "%s", str);
   ```

### 11. **Redundant Memory Operations** [MEDIUM]
   - memset immediately followed by full overwrite
   - Copying data that's about to be discarded
   - Allocating then immediately reallocating
   - Zero-initialization when Arena already zeros (CALLOC)
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - immediate overwrite */
   memset(buf, 0, sizeof(buf));
   strcpy(buf, source);  /* Overwrites the zeros */
   
   /* REDUNDANT - CALLOC already zeros */
   obj = CALLOC(arena, 1, sizeof(*obj));
   memset(obj, 0, sizeof(*obj));  /* REDUNDANT */
   ```

### 12. **Redundant Return Statements** [LOW]
   - Multiple return points that return same value
   - Return at end of void function
   - Explicit return 0 at end of main() in C99+
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - void function */
   void func(void) {
       /* ... */
       return;  /* Implicit at end of void */
   }
   ```

### 13. **Redundant Documentation** [LOW]
   - Comments that repeat what code clearly shows
   - Duplicate documentation (header and implementation)
   - Outdated comments that don't match code
   - Comments stating the obvious
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - states the obvious */
   i++;  /* Increment i */
   
   /* KEEP - explains why, not what */
   i++;  /* Skip header row in CSV */
   ```

### 14. **Redundant Macros** [MEDIUM]
   - Macros that just wrap a single function call
   - Macros identical to existing ones in SocketConfig.h
   - Macros that could be inline functions
   - Duplicate macro definitions
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - just use the function */
   #define MY_ALLOC(a, n) Arena_alloc(a, n, __FILE__, __LINE__)
   
   /* EXISTS - use ALLOC from SocketConfig.h */
   obj = ALLOC(arena, sizeof(*obj));
   ```

---

## Socket Library Specific Redundancies

### 15. **Redundant TRY/EXCEPT Blocks** [HIGH]
   - Nested TRY blocks where outer handles all exceptions
   - TRY/EXCEPT that just re-raises without cleanup
   - FINALLY blocks that are empty or duplicate cleanup
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - nested TRY with no added value */
   TRY
       TRY
           do_something();
       EXCEPT(Socket_Error)
           RERAISE;  /* Just re-raises */
       END_TRY;
   EXCEPT(Socket_Error)
       handle_error();
   END_TRY;
   
   /* FIXED - single TRY block */
   TRY
       do_something();
   EXCEPT(Socket_Error)
       handle_error();
   END_TRY;
   ```

### 16. **Redundant Socket Operations** [HIGH]
   - Same socket option set multiple times
   - SAFE_CLOSE called on already-closed fd
   - Repeated address resolution for same host
   - Duplicate bind/connect error handling
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - setting same option twice */
   setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
   /* ... other code ... */
   setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));  /* DUPLICATE */
   
   /* REDUNDANT - double close protection already in SAFE_CLOSE */
   if (fd >= 0)  /* SAFE_CLOSE already checks this */
       SAFE_CLOSE(fd);
   
   /* FIXED */
   SAFE_CLOSE(fd);  /* Handles fd < 0 internally */
   ```

### 17. **Redundant Mutex Operations** [CRITICAL]
   - Lock/unlock without any critical section between
   - Nested locks on same mutex (deadlock risk)
   - Mutex operations in non-threaded code paths
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - empty critical section */
   pthread_mutex_lock(&mutex);
   pthread_mutex_unlock(&mutex);  /* Nothing protected */
   
   /* DANGEROUS - nested lock on same mutex */
   pthread_mutex_lock(&mutex);
   /* ... */
   pthread_mutex_lock(&mutex);  /* DEADLOCK if not recursive mutex */
   ```

### 18. **Redundant Assertions** [LOW]
   - Assert after runtime validation already performed
   - Assert checking same condition multiple times
   - Assert with always-true condition
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - already validated with runtime check */
   if (ptr == NULL)
       RAISE(Null_Error);
   assert(ptr != NULL);  /* Always true here */
   
   /* FIXED - choose one: assert for debug, runtime check for production */
   assert(ptr);  /* OR */
   if (ptr == NULL) RAISE(Null_Error);  /* Pick one, not both */
   ```

### 19. **Redundant Error Buffer Formatting** [MEDIUM]
   - Multiple snprintf to same error buffer
   - Error message formatted but exception not raised
   - SOCKET_ERROR_FMT called multiple times for same error
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - error formatted but not used */
   SOCKET_ERROR_FMT("connect failed");
   return -1;  /* Error message lost */
   
   /* FIXED - use RAISE_MODULE_ERROR or remove formatting */
   SOCKET_ERROR_FMT("connect failed");
   RAISE_MODULE_ERROR(Socket_Error);
   ```

### 20. **Redundant Platform Checks** [LOW]
   - #ifdef blocks that are always true/false for target platform
   - Runtime platform checks when compile-time is sufficient
   - Dead code in wrong platform branches
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT on Linux-only build */
   #ifdef __linux__
   use_epoll();
   #else
   use_poll();  /* Dead code if only building for Linux */
   #endif
   
   /* KEEP - if truly cross-platform */
   ```

### 21. **Redundant Error+Raise Patterns** [HIGH]
   - Separate SOCKET_ERROR_FMT followed by RAISE_MODULE_ERROR
   - Multiple steps that could be combined into single SOCKET_RAISE_FMT
   - Duplicated error formatting + exception raising logic
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - two-step pattern */
   SOCKET_ERROR_FMT("connect failed to %s:%d", host, port);
   RAISE_MODULE_ERROR(Socket_Failed);
   
   /* FIXED - use unified macro from SocketUtil.h */
   SOCKET_RAISE_FMT(Socket, Socket_Failed, "connect failed to %s:%d", host, port);
   
   /* For messages without errno */
   SOCKET_RAISE_MSG(Socket, Socket_Failed, "invalid port: %d", port);
   ```
   
   **Note**: Use `SOCKET_RAISE_FMT` (with errno) or `SOCKET_RAISE_MSG` (without errno).

### 22. **Redundant Module Exception Setup** [HIGH]
   - Manual thread-local exception declarations
   - Custom RAISE_MODULE_ERROR implementations
   - Duplicated exception infrastructure across modules
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - manual declaration */
   #ifdef _WIN32
   static __declspec(thread) Except_T Module_DetailedException;
   #else
   static __thread Except_T Module_DetailedException;
   #endif
   
   #define RAISE_MODULE_ERROR(exception) \
     do { \
       Module_DetailedException = (exception); \
       Module_DetailedException.reason = socket_error_buf; \
       RAISE(Module_DetailedException); \
     } while (0)
   
   /* FIXED - use centralized macro from SocketUtil.h */
   SOCKET_DECLARE_MODULE_EXCEPTION(Module);
   #define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(Module, e)
   ```

### 23. **Redundant SocketBase Functionality** [HIGH]
   - Duplicated socket fd/arena/endpoint fields across Socket_T and SocketDgram_T
   - Local implementations of address resolution that exist in SocketCommon
   - Custom socket option setters duplicating SocketCommon_set_option_int
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - duplicated setsockopt wrapper */
   int value = 1;
   if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) < 0) {
       SOCKET_ERROR_FMT("Failed to set SO_REUSEADDR");
       RAISE_MODULE_ERROR(Socket_Failed);
   }
   
   /* FIXED - use SocketCommon helper */
   SocketCommon_set_option_int(base, SOL_SOCKET, SO_REUSEADDR, 1, Socket_Failed);
   
   /* REDUNDANT - manual address resolution */
   struct addrinfo hints, *res;
   memset(&hints, 0, sizeof(hints));
   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_STREAM;
   /* ... getaddrinfo call ... */
   
   /* FIXED - use SocketCommon helper */
   SocketCommon_resolve_address(host, port, &hints, &res, Socket_Failed, AF_UNSPEC, 1);
   ```
   
   **Available SocketCommon helpers**:
   - `SocketCommon_new_base()` / `SocketCommon_free_base()` - Lifecycle
   - `SocketCommon_set_option_int()` - Socket options
   - `SocketCommon_set_nonblock()` - Non-blocking mode
   - `SocketCommon_set_ttl()` - TTL/hop limit
   - `SocketCommon_join_multicast()` / `SocketCommon_leave_multicast()`
   - `SocketCommon_resolve_address()` - DNS resolution
   - `SocketCommon_cache_endpoint()` - Address formatting
   - `SocketCommon_validate_port()` / `SocketCommon_validate_hostname()`

### 24. **Redundant iovec Calculations** [MEDIUM]
   - Manual total iov_len calculation loops
   - Custom iovec advancement after partial I/O
   - Duplicated overflow checks in scatter/gather operations
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - manual iov length calculation */
   size_t total = 0;
   for (int i = 0; i < iovcnt; i++) {
       if (total > SIZE_MAX - iov[i].iov_len) {
           /* overflow check */
       }
       total += iov[i].iov_len;
   }
   
   /* FIXED - use SocketCommon helper */
   size_t total = SocketCommon_calculate_total_iov_len(iov, iovcnt);
   
   /* REDUNDANT - manual iov advancement */
   size_t remaining = bytes;
   for (int i = 0; i < iovcnt && remaining > 0; i++) {
       if (iov[i].iov_len <= remaining) {
           remaining -= iov[i].iov_len;
           iov[i].iov_len = 0;
           iov[i].iov_base = NULL;
       } else {
           iov[i].iov_base += remaining;
           iov[i].iov_len -= remaining;
           remaining = 0;
       }
   }
   
   /* FIXED - use SocketCommon helper */
   SocketCommon_advance_iov(iov, iovcnt, bytes);
   ```
   
   **Available helpers**:
   - `SocketCommon_calculate_total_iov_len()` - Total with overflow protection
   - `SocketCommon_advance_iov()` - Advance past consumed bytes
   - `SocketCommon_find_active_iov()` - Find first non-empty iovec
   - `SocketCommon_alloc_iov_copy()` - Allocate working copy
   - `SocketCommon_sync_iov_progress()` - Sync progress back to original

### 25. **Redundant Hash Functions** [MEDIUM]
   - Custom golden ratio hash implementations
   - Duplicated fd-to-bucket calculations
   - Multiple hash functions for same key types
   - Custom DJB2 string hashing
   - Manual case-insensitive hashing for headers
   - Custom power-of-2 rounding for table sizing
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - local hash function */
   static unsigned socket_hash(Socket_T socket) {
       int fd = Socket_fd(socket);
       return ((unsigned)fd * 2654435761u) % HASH_SIZE;
   }
   
   /* FIXED - use SocketUtil helper */
   unsigned hash = socket_util_hash_fd(Socket_fd(socket), HASH_SIZE);
   
   /* For pointers */
   unsigned hash = socket_util_hash_ptr(ptr, HASH_SIZE);
   
   /* For unsigned integers (request IDs, etc.) */
   unsigned hash = socket_util_hash_uint(id, HASH_SIZE);
   
   /* REDUNDANT - custom DJB2 hash */
   unsigned hash = 5381;
   while (*str) hash = ((hash << 5) + hash) + *str++;
   
   /* FIXED - use SocketUtil DJB2 helpers */
   unsigned hash = socket_util_hash_djb2(str, TABLE_SIZE);
   
   /* For length-aware (non-null-terminated strings) */
   unsigned hash = socket_util_hash_djb2_len(str, len, TABLE_SIZE);
   
   /* For case-insensitive HTTP header hashing */
   unsigned hash = socket_util_hash_djb2_ci(header_name, TABLE_SIZE);
   
   /* Combined: length-aware + case-insensitive (ideal for HTTP/2) */
   unsigned hash = socket_util_hash_djb2_ci_len(header_name, name_len, TABLE_SIZE);
   
   /* REDUNDANT - custom power-of-2 rounding */
   n--;
   n |= n >> 1;
   n |= n >> 2;
   /* ... */
   n++;
   
   /* FIXED - use SocketUtil helper */
   size_t capacity = socket_util_round_up_pow2(initial_size);
   ```
   
   **Note**: All hash functions use HASH_GOLDEN_RATIO (2654435761u) from SocketConfig.h.
   **Note**: DJB2 functions use SOCKET_UTIL_DJB2_SEED (5381u) from SocketUtil.h.

### 26. **Redundant Monotonic Time Calls** [MEDIUM]
   - Manual clock_gettime(CLOCK_MONOTONIC) with fallback logic
   - Duplicated time conversion (seconds to milliseconds)
   - Local implementations of timestamp acquisition
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - manual clock access */
   struct timespec ts;
   int64_t now_ms;
   if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
       now_ms = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
   } else {
       /* fallback to CLOCK_REALTIME */
   }
   
   /* FIXED - use SocketUtil helper */
   int64_t now_ms = Socket_get_monotonic_ms();
   ```

### 27. **Redundant Live Count Tracking** [LOW]
   - Custom atomic/mutex-protected counters for instance tracking
   - Duplicated increment/decrement patterns across modules
   - Local debug count implementations
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - custom counter with mutex */
   static int live_count = 0;
   static pthread_mutex_t count_mutex = PTHREAD_MUTEX_INITIALIZER;
   
   void increment_count(void) {
       pthread_mutex_lock(&count_mutex);
       live_count++;
       pthread_mutex_unlock(&count_mutex);
   }
   
   /* FIXED - use SocketLiveCount from SocketCommon.h */
   static struct SocketLiveCount tracker = SOCKETLIVECOUNT_STATIC_INIT;
   
   #define module_live_increment() SocketLiveCount_increment(&tracker)
   #define module_live_decrement() SocketLiveCount_decrement(&tracker)
   
   int Module_debug_live_count(void) {
       return SocketLiveCount_get(&tracker);
   }
   ```

### 28. **Redundant TLS I/O Routing** [HIGH]
   - Manual if/else chains checking TLS status before I/O
   - Duplicated SSL_read/SSL_write vs recv/send logic
   - Local TLS error mapping to errno
   - Manual TLS teardown logic instead of `SocketTLS_disable()`
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - manual TLS routing */
   ssize_t n;
   if (socket->tls_enabled) {
       n = SSL_read(socket->tls_ssl, buf, len);
       if (n <= 0) {
           int err = SSL_get_error(socket->tls_ssl, n);
           if (err == SSL_ERROR_WANT_READ) {
               errno = EAGAIN;
               return 0;
           }
           /* ... more error handling ... */
       }
   } else {
       n = recv(socket->fd, buf, len, 0);
   }
   
   /* FIXED - use SocketIO internal abstractions */
   #include "socket/SocketIO.h"
   
   ssize_t n = socket_recv_internal(socket, buf, len, 0);
   /* TLS routing handled automatically */
   
   /* REDUNDANT - manual TLS teardown for STARTTLS reversal */
   SSL_shutdown(socket->tls_ssl);
   SSL_free(socket->tls_ssl);
   socket->tls_ssl = NULL;
   socket->tls_enabled = 0;
   /* ... missing secure memory clearing ... */
   
   /* FIXED - use SocketTLS_disable() */
   int result = SocketTLS_disable(socket);
   /* Socket is now in plain mode, TLS resources securely cleaned up */
   ```
   
   **Available SocketIO functions**:
   - `socket_send_internal()` - TLS-aware send
   - `socket_recv_internal()` - TLS-aware recv
   - `socket_sendv_internal()` - TLS-aware scatter send
   - `socket_recvv_internal()` - TLS-aware gather recv
   - `socket_is_tls_enabled()` - Check TLS status
   - `socket_tls_want_read()` / `socket_tls_want_write()` - Handshake state
   
   **Available SocketTLS functions**:
   - `SocketTLS_enable()` - Enable TLS on socket
   - `SocketTLS_disable()` - Best-effort TLS teardown (1=clean, 0=partial, -1=not enabled)
   - `SocketTLS_shutdown()` - Strict TLS shutdown (raises on failure)

### 29. **Redundant TLS Context Configuration** [HIGH]
   - Custom TLS context setup instead of `SocketTLSContext_new_client/server()`
   - Manual protocol version configuration instead of library defaults (TLS 1.3)
   - Custom cipher suite configuration instead of `SOCKET_TLS13_CIPHERSUITES`
   - Manual session cache setup instead of `SocketTLSContext_enable_session_cache()`
   - Custom CRL loading instead of `SocketTLSContext_load_crl()`
   - Manual OCSP stapling instead of `SocketTLSContext_set_ocsp_response()`
   - Custom certificate pinning instead of `SocketTLSContext_add_pin()`
   - Manual verify callback wiring instead of `SocketTLSContext_set_verify_callback()`
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - manual TLS context setup */
   SSL_CTX *ctx = SSL_CTX_new(TLS_method());
   SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
   SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
   SSL_CTX_set_cipher_list(ctx, "TLS_AES_256_GCM_SHA384:...");
   
   /* FIXED - use SocketTLSContext */
   SocketTLSContext_T ctx = SocketTLSContext_new_client("ca-bundle.pem");
   /* TLS 1.3 and secure defaults already configured */
   ```

### 30. **Redundant DTLS Configuration** [HIGH]
   - Custom DTLS context setup instead of `SocketDTLSContext_new_server/client()`
   - Manual cookie exchange instead of `SocketDTLSContext_enable_cookie_exchange()`
   - Custom cookie secret management instead of `SocketDTLSContext_set_cookie_secret()`
   - Manual MTU handling instead of `SocketDTLSContext_set_mtu()`
   - Custom retransmission timeout logic instead of library defaults
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - manual DTLS cookie */
   SSL_CTX_set_cookie_generate_cb(ctx, my_cookie_generate);
   SSL_CTX_set_cookie_verify_cb(ctx, my_cookie_verify);
   
   /* FIXED - use SocketDTLSContext */
   SocketDTLSContext_enable_cookie_exchange(ctx);
   SocketDTLSContext_rotate_cookie_secret(ctx);  /* Periodic rotation */
   ```

### 31. **Redundant TLS Performance Features** [MEDIUM]
   - Manual session resumption instead of built-in session cache
   - Custom session ticket handling instead of `SocketTLSContext_enable_session_tickets()`
   - Manual kTLS setup instead of `SocketTLS_enable_ktls()`
   - Custom TCP optimization instead of `SocketTLS_optimize_handshake()`
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - manual session save/restore */
   SSL_SESSION *sess = SSL_get1_session(ssl);
   /* ... save to disk ... */
   SSL_set_session(ssl, cached_session);
   
   /* FIXED - use SocketTLS session API */
   SocketTLS_session_save(socket, buffer, &len);
   SocketTLS_session_restore(socket, buffer, len);
   ```

### 32. **Redundant Token Bucket Calculations** [LOW]
   - Manual token refill rate calculations
   - Duplicated elapsed time to tokens conversion
   - Custom wait time estimation for rate limiting
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - manual token calculation */
   int64_t elapsed_ms = now - last_refill;
   size_t tokens_to_add = (elapsed_ms * tokens_per_sec) / 1000;
   
   /* KEEP if custom rate limiter needed, otherwise use SocketRateLimit */
   SocketRateLimit_T limiter = SocketRateLimit_new(arena, tokens_per_sec, bucket_size);
   if (SocketRateLimit_acquire(limiter, 1)) {
       /* allowed */
   }
   ```

### 30. **Redundant Timer Management** [MEDIUM]
   - Manual min-heap implementations for timeouts
   - Duplicated timer expiry checking logic
   - Custom callback scheduling
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - custom timer heap */
   typedef struct Timer {
       int64_t expiry;
       void (*callback)(void*);
       void *data;
   } Timer;
   Timer *timers[MAX_TIMERS];
   /* manual heap operations */
   
   /* FIXED - use SocketTimer from SocketTimer-private.h */
   SocketTimer_heap_T *heap = SocketTimer_heap_new(arena);
   struct SocketTimer_T *timer = /* ... */;
   SocketTimer_heap_push(heap, timer);
   int fired = SocketTimer_process_expired(heap);
   ```

### 31. **Redundant Graceful Shutdown Logic** [HIGH]
   - Custom drain/shutdown state machines instead of using `SocketPool_drain`
   - Manual connection iteration for shutdown instead of `SocketPool_drain_force`
   - Custom timeout-based force close logic
   - Duplicated health status tracking
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - custom shutdown state */
   static int is_shutting_down = 0;
   static time_t shutdown_deadline;
   
   void start_shutdown(int timeout_sec) {
       is_shutting_down = 1;
       shutdown_deadline = time(NULL) + timeout_sec;
   }
   
   int accept_connection() {
       if (is_shutting_down) return NULL;  /* Manual check */
       /* ... */
   }
   
   /* FIXED - use SocketPool drain API */
   SocketPool_drain(pool, timeout_ms);  /* Non-blocking */
   
   /* Or for blocking shutdown */
   int result = SocketPool_drain_wait(pool, timeout_ms);
   
   /* Health check for load balancers */
   if (SocketPool_health(pool) == POOL_HEALTH_DRAINING) {
       /* Return 503 */
   }
   ```
   
   **Available SocketPool drain functions**:
   - `SocketPool_drain(pool, timeout_ms)` - Non-blocking drain initiation
   - `SocketPool_drain_poll(pool)` - Poll progress (for event loops)
   - `SocketPool_drain_force(pool)` - Immediate force close
   - `SocketPool_drain_wait(pool, timeout_ms)` - Blocking drain
   - `SocketPool_drain_remaining_ms(pool)` - Time until timeout
   - `SocketPool_state(pool)` - Get RUNNING/DRAINING/STOPPED
   - `SocketPool_health(pool)` - Get HEALTHY/DRAINING/STOPPED
   - `SocketPool_set_drain_callback(pool, cb, data)` - Completion callback

### 32. **Redundant Connection Cleanup Loops** [MEDIUM]
   - Manual iteration to close all connections
   - Custom force-close logic that duplicates drain behavior
   - Duplicated socket shutdown + remove + free patterns
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - manual force close all */
   for (size_t i = 0; i < pool->maxconns; i++) {
       if (pool->connections[i].active) {
           Socket_shutdown(pool->connections[i].socket, SHUT_RDWR);
           SocketPool_remove(pool, pool->connections[i].socket);
           Socket_free(&pool->connections[i].socket);
       }
   }
   
   /* FIXED - use SocketPool_drain_force */
   SocketPool_drain_force(pool);  /* Handles all connections atomically */
   ```

### 33. **Redundant UTF-8 Validation** [MEDIUM]
   - Custom UTF-8 byte sequence validation instead of `SocketUTF8_validate()`
   - Manual overlong encoding checks instead of built-in DFA detection
   - Custom surrogate pair rejection (U+D800-U+DFFF)
   - Manual continuation byte validation
   - Custom codepoint range checking (> U+10FFFF)
   - Not using incremental API for streaming (`SocketUTF8_init/update/finish`)
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - manual UTF-8 validation */
   int is_valid_utf8(const char *s) {
       while (*s) {
           if ((*s & 0x80) == 0) { s++; continue; }
           /* ... complex byte checks ... */
       }
       return 1;
   }
   
   /* FIXED - use SocketUTF8 */
   if (SocketUTF8_validate((const unsigned char *)s, strlen(s)) == UTF8_VALID) {
       /* Valid UTF-8 */
   }
   ```
   
   **Available SocketUTF8 functions**:
   - `SocketUTF8_validate()` - One-shot validation
   - `SocketUTF8_validate_str()` - Null-terminated string validation
   - `SocketUTF8_init()` / `_update()` / `_finish()` - Incremental validation
   - `SocketUTF8_encode()` / `_decode()` - Codepoint conversion
   - `SocketUTF8_count_codepoints()` - Count codepoints in string

### 34. **Redundant HTTP Parsing** [HIGH]
   - Custom HTTP method parsing instead of `SocketHTTP_method_parse()`
   - Custom status code reason phrases instead of `SocketHTTP_status_reason()`
   - Manual header name/value parsing instead of `SocketHTTP_Headers_T`
   - Custom case-insensitive header lookup (linear scan vs hash table)
   - Manual HTTP-date parsing instead of `SocketHTTP_date_parse()`
   - Custom URI parsing instead of `SocketHTTP_URI_parse()`
   - Manual percent-encoding instead of `SocketHTTP_URI_encode/decode()`
   - Custom media type parsing instead of `SocketHTTP_MediaType_parse()`
   - Manual Accept header q-value parsing instead of `SocketHTTP_parse_accept()`
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - manual method parsing */
   if (strncmp(line, "GET ", 4) == 0) method = METHOD_GET;
   else if (strncmp(line, "POST ", 5) == 0) method = METHOD_POST;
   /* ... */
   
   /* FIXED - use SocketHTTP */
   SocketHTTP_Method m = SocketHTTP_method_parse(line, method_len);
   
   /* REDUNDANT - manual header lookup (linear scan) */
   for (int i = 0; i < num_headers; i++) {
       if (strcasecmp(headers[i].name, "Content-Type") == 0) {
           /* found */
       }
   }
   
   /* FIXED - use SocketHTTP_Headers_T (O(1) hash lookup) */
   SocketHTTP_Headers_T hdrs = SocketHTTP_Headers_new(arena);
   const char *ct = SocketHTTP_Headers_get(hdrs, "Content-Type");
   
   /* REDUNDANT - manual date parsing */
   struct tm tm;
   strptime(date_str, "%a, %d %b %Y %H:%M:%S GMT", &tm);
   
   /* FIXED - use SocketHTTP (handles all 3 RFC 9110 formats) */
   time_t t;
   SocketHTTP_date_parse(date_str, 0, &t);
   ```
   
   **Available SocketHTTP functions**:
   - `SocketHTTP_method_parse()` / `_name()` / `_properties()` - HTTP methods
   - `SocketHTTP_status_reason()` / `_category()` / `_valid()` - Status codes
   - `SocketHTTP_Headers_new()` / `_add()` / `_get()` / `_remove()` - Header collection
   - `SocketHTTP_URI_parse()` / `_encode()` / `_decode()` / `_build()` - URI handling
   - `SocketHTTP_date_parse()` / `_format()` - HTTP-date handling
   - `SocketHTTP_MediaType_parse()` / `_matches()` - Content-Type parsing
   - `SocketHTTP_parse_accept()` - Accept header with q-values
   - `SocketHTTP_coding_parse()` / `_name()` - Transfer/content codings

### 35. **Redundant Cryptographic Operations** [HIGH]
   - Direct OpenSSL hash calls instead of `SocketCrypto_sha256()` etc.
   - Direct `HMAC()` calls instead of `SocketCrypto_hmac_sha256()`
   - Direct `RAND_bytes()` calls instead of `SocketCrypto_random_bytes()`
   - Custom hex encode/decode instead of `SocketCrypto_hex_encode/decode()`
   - Custom base64 encode/decode instead of `SocketCrypto_base64_encode/decode()`
   - Custom constant-time comparison instead of `SocketCrypto_secure_compare()`
   - Custom `memset` for sensitive data instead of `SocketCrypto_secure_clear()`
   - Custom WebSocket key generation instead of `SocketCrypto_websocket_key()`
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - direct OpenSSL hash */
   unsigned char hash[SHA256_DIGEST_LENGTH];
   SHA256(data, len, hash);
   
   /* FIXED - use SocketCrypto */
   unsigned char hash[SOCKET_CRYPTO_SHA256_SIZE];
   SocketCrypto_sha256(data, len, hash);
   
   /* REDUNDANT - direct HMAC call */
   unsigned char hmac[32];
   HMAC(EVP_sha256(), key, key_len, data, data_len, hmac, NULL);
   
   /* FIXED - use SocketCrypto */
   unsigned char hmac[SOCKET_CRYPTO_SHA256_SIZE];
   SocketCrypto_hmac_sha256(key, key_len, data, data_len, hmac);
   
   /* REDUNDANT - custom hex decode */
   static int hex_char_to_nibble(char c) { ... }
   
   /* FIXED - use SocketCrypto */
   ssize_t len = SocketCrypto_hex_decode(hex_str, strlen(hex_str), output);
   
   /* REDUNDANT - memset for sensitive data (may be optimized away) */
   memset(password, 0, sizeof(password));
   
   /* FIXED - use SocketCrypto */
   SocketCrypto_secure_clear(password, sizeof(password));
   ```
   
   **Available SocketCrypto functions**:
   - `SocketCrypto_sha1()` / `SocketCrypto_sha256()` / `SocketCrypto_md5()` - Hash functions
   - `SocketCrypto_hmac_sha256()` - HMAC-SHA256 for message authentication
   - `SocketCrypto_base64_encode()` / `SocketCrypto_base64_decode()` - Base64 (RFC 4648)
   - `SocketCrypto_hex_encode()` / `SocketCrypto_hex_decode()` - Hexadecimal encoding
   - `SocketCrypto_random_bytes()` / `SocketCrypto_random_uint32()` - Secure random
   - `SocketCrypto_websocket_accept()` / `SocketCrypto_websocket_key()` - RFC 6455
   - `SocketCrypto_secure_compare()` - Constant-time comparison
   - `SocketCrypto_secure_clear()` - Secure memory clearing

### 36. **Redundant HTTP/1.1 Parsing** [HIGH]
   - Custom HTTP/1.1 request/response parsing instead of `SocketHTTP1_Parser`
   - Manual DFA state machines for HTTP message parsing
   - Custom chunked decoder instead of `SocketHTTP1_Parser_read_body()`
   - Manual chunk encoding instead of `SocketHTTP1_chunk_encode()`
   - Custom request smuggling detection (should use built-in RFC 9112 Section 6.3)
   - Manual Content-Length/Transfer-Encoding header validation
   - Custom HTTP version string parsing
   - Manual keep-alive detection instead of `SocketHTTP1_Parser_should_keepalive()`
   - Custom request/response serialization instead of `SocketHTTP1_serialize_*`
   - Not using incremental parser API for streaming data
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - manual request line parsing */
   char method[16], uri[8192], version[16];
   sscanf(line, "%s %s %s", method, uri, version);
   
   /* FIXED - use SocketHTTP1 */
   SocketHTTP1_Parser_T parser = SocketHTTP1_Parser_new(HTTP1_PARSE_REQUEST, NULL, arena);
   SocketHTTP1_Parser_execute(parser, data, len, &consumed);
   const SocketHTTP_Request *req = SocketHTTP1_Parser_get_request(parser);
   
   /* REDUNDANT - manual chunked decoding */
   size_t chunk_size;
   sscanf(line, "%zx", &chunk_size);
   /* ... manual CRLF handling ... */
   
   /* FIXED - use SocketHTTP1 body reading */
   SocketHTTP1_Parser_read_body(parser, input, input_len, &consumed,
                                 output, output_len, &written);
   
   /* REDUNDANT - manual chunk encoding */
   snprintf(buf, sizeof(buf), "%zx\r\n", len);
   memcpy(buf + offset, data, len);
   memcpy(buf + offset + len, "\r\n", 2);
   
   /* FIXED - use SocketHTTP1 */
   ssize_t n = SocketHTTP1_chunk_encode(data, len, output, output_size);
   
   /* REDUNDANT - manual request serialization */
   snprintf(buf, sizeof(buf), "%s %s HTTP/1.1\r\nHost: %s\r\n\r\n", method, uri, host);
   
   /* FIXED - use SocketHTTP1 */
   ssize_t n = SocketHTTP1_serialize_request(&request, buffer, sizeof(buffer));
   ```
   
   **Available SocketHTTP1 functions**:
   - `SocketHTTP1_Parser_new()` / `_free()` / `_reset()` - Parser lifecycle
   - `SocketHTTP1_Parser_execute()` - Incremental parsing
   - `SocketHTTP1_Parser_get_request()` / `_get_response()` - Get parsed message
   - `SocketHTTP1_Parser_body_mode()` - Detect NONE/CONTENT_LENGTH/CHUNKED/UNTIL_CLOSE
   - `SocketHTTP1_Parser_read_body()` - Read body with automatic chunked decoding
   - `SocketHTTP1_Parser_should_keepalive()` - Connection persistence check
   - `SocketHTTP1_serialize_request()` / `_response()` - Message serialization
   - `SocketHTTP1_chunk_encode()` / `_final()` - Chunked encoding
   - `SocketHTTP1_Decoder_new()` / `_decode()` - Optional compression (gzip/deflate/br)

### 37. **Redundant HPACK Header Compression** [HIGH]
   - Custom HPACK encoding/decoding instead of `SocketHPACK_Encoder/Decoder`
   - Custom Huffman coding instead of `SocketHPACK_huffman_encode/decode()`
   - Custom variable-length integer coding instead of `SocketHPACK_int_encode/decode()`
   - Manual static table lookup instead of `SocketHPACK_static_find()`
   - Custom dynamic table management instead of `SocketHPACK_Table_T`
   - Manual HPACK bomb protection instead of built-in decoder limits
   - Custom power-of-2 capacity rounding instead of `socket_util_round_up_pow2()`
   - Not using `socket_util_hash_djb2_ci_len()` for header name hashing
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - custom Huffman encoding */
   static const struct { uint32_t code; uint8_t bits; } huffman_table[257];
   /* ... manual bit packing ... */
   
   /* FIXED - use SocketHPACK */
   size_t encoded_size = SocketHPACK_huffman_encoded_size(data, len);
   SocketHPACK_huffman_encode(data, len, output, output_size);
   
   /* REDUNDANT - custom integer coding */
   if (value < (1 << prefix_bits) - 1) {
       *out = value;
   } else {
       *out = (1 << prefix_bits) - 1;
       value -= (1 << prefix_bits) - 1;
       while (value >= 128) {
           *out++ = (value & 127) | 128;
           value >>= 7;
       }
       *out = value;
   }
   
   /* FIXED - use SocketHPACK */
   SocketHPACK_int_encode(value, prefix_bits, output, output_size);
   
   /* REDUNDANT - custom dynamic table */
   struct DynamicEntry *entries;
   size_t head, tail, count;
   /* ... manual eviction logic ... */
   
   /* FIXED - use SocketHPACK */
   SocketHPACK_Table_T table = SocketHPACK_Table_new(4096, arena);
   SocketHPACK_Table_add(table, name, name_len, value, value_len);
   
   /* REDUNDANT - custom encoder/decoder */
   /* ... hundreds of lines of HPACK implementation ... */
   
   /* FIXED - use SocketHPACK */
   SocketHPACK_Encoder_T enc = SocketHPACK_Encoder_new(arena, 4096);
   SocketHPACK_Decoder_T dec = SocketHPACK_Decoder_new(arena, NULL);
   SocketHPACK_encode(enc, headers, count, output, size, &output_len);
   SocketHPACK_decode(dec, input, len, headers, max, &count);
   ```
   
   **Available SocketHPACK functions**:
   - `SocketHPACK_Encoder_new()` / `_free()` - Encoder lifecycle
   - `SocketHPACK_Decoder_new()` / `_free()` - Decoder lifecycle
   - `SocketHPACK_encode()` / `_encode_header()` - Header encoding
   - `SocketHPACK_decode()` / `_get_header()` - Header decoding
   - `SocketHPACK_Table_new()` / `_add()` / `_get()` / `_find()` - Dynamic table
   - `SocketHPACK_static_get()` / `_find()` - Static table lookup
   - `SocketHPACK_int_encode()` / `_decode()` - Variable-length integer coding
   - `SocketHPACK_huffman_encode()` / `_decode()` - Huffman coding
   - `SocketHPACK_huffman_encoded_size()` - Calculate encoded size

### 38. **Redundant HTTP/2 Protocol Implementation** [HIGH]
   - Custom HTTP/2 frame parsing instead of `SocketHTTP2_frame_header_parse/serialize()`
   - Custom stream state machine instead of `SocketHTTP2_Stream_*` API
   - Manual flow control window tracking instead of `http2_flow_*` functions
   - Custom connection preface handling instead of `SocketHTTP2_Conn_handshake()`
   - Manual SETTINGS frame handling instead of `SocketHTTP2_Conn_settings()`
   - Custom h2c upgrade logic instead of `SocketHTTP2_Conn_upgrade_client/server()`
   - Manual stream ID assignment instead of `SocketHTTP2_Stream_new()` auto-assignment
   - Custom HPACK encoder/decoder management instead of built-in connection integration
   - Manual GOAWAY handling instead of `SocketHTTP2_Conn_goaway()`
   - Custom stream callback dispatching instead of `SocketHTTP2_Conn_set_stream_callback()`
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - custom frame parsing */
   uint32_t length = (buf[0] << 16) | (buf[1] << 8) | buf[2];
   uint8_t type = buf[3];
   uint8_t flags = buf[4];
   uint32_t stream_id = ((buf[5] & 0x7F) << 24) | (buf[6] << 16) | (buf[7] << 8) | buf[8];
   
   /* FIXED - use SocketHTTP2 */
   SocketHTTP2_FrameHeader header;
   SocketHTTP2_frame_header_parse(buf, &header);
   
   /* REDUNDANT - custom stream state machine */
   typedef enum { IDLE, OPEN, HALF_CLOSED, CLOSED } StreamState;
   StreamState states[MAX_STREAMS];
   /* ... manual state transitions ... */
   
   /* FIXED - use SocketHTTP2 */
   SocketHTTP2_Stream_T stream = SocketHTTP2_Stream_new(conn);
   SocketHTTP2_StreamState state = SocketHTTP2_Stream_state(stream);
   
   /* REDUNDANT - custom flow control */
   int32_t conn_window = 65535;
   int32_t stream_windows[MAX_STREAMS];
   /* ... manual window updates ... */
   
   /* FIXED - use SocketHTTP2 */
   SocketHTTP2_Conn_window_update(conn, increment);
   SocketHTTP2_Stream_window_update(stream, increment);
   int32_t available = http2_flow_available_send(&conn->send_flow, &stream->send_flow);
   
   /* REDUNDANT - custom connection preface */
   write(fd, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24);
   /* ... manual SETTINGS exchange ... */
   
   /* FIXED - use SocketHTTP2 */
   while (SocketHTTP2_Conn_handshake(conn) > 0) {
       SocketHTTP2_Conn_flush(conn);
       SocketHTTP2_Conn_process(conn, POLL_READ);
   }
   ```
   
   **Available SocketHTTP2 functions**:
   - `SocketHTTP2_Conn_new()` / `_free()` - Connection lifecycle
   - `SocketHTTP2_Conn_handshake()` - Connection preface exchange
   - `SocketHTTP2_Conn_process()` - Frame processing with event dispatch
   - `SocketHTTP2_Conn_flush()` - Flush pending frames to socket
   - `SocketHTTP2_Conn_settings()` / `_ping()` / `_goaway()` - Control frames
   - `SocketHTTP2_Conn_window_update()` - Connection-level flow control
   - `SocketHTTP2_Conn_set_stream_callback()` / `_set_conn_callback()` - Event callbacks
   - `SocketHTTP2_Conn_upgrade_client()` / `_upgrade_server()` - h2c upgrade
   - `SocketHTTP2_Stream_new()` - Create stream (auto-assigns ID)
   - `SocketHTTP2_Stream_send_headers()` / `_send_data()` / `_send_trailers()` - Sending
   - `SocketHTTP2_Stream_recv_headers()` / `_recv_data()` / `_recv_trailers()` - Receiving
   - `SocketHTTP2_Stream_window_update()` - Stream-level flow control
   - `SocketHTTP2_Stream_state()` - Query current stream state
   - `SocketHTTP2_frame_header_parse()` / `_serialize()` - Frame header I/O
   - `http2_flow_consume_send/recv()` - Window consumption
   - `http2_flow_update_send/recv()` - Window updates
   - `http2_flow_available_send()` - Available send window

### 39. **Redundant HTTP Client/Server Implementation** [HIGH]
   - Custom HTTP client connection pooling instead of `SocketHTTPClient` pool
   - Manual HTTP authentication (Basic/Digest/Bearer) instead of `SocketHTTPClient_setauth()`
   - Custom cookie handling instead of `SocketHTTPClient_CookieJar_*`
   - Manual HTTP request building instead of `SocketHTTPClient_Request_*`
   - Custom redirect following instead of `SocketHTTPClient` built-in
   - Manual compression handling instead of `SocketHTTPClient` auto-decompress
   - Custom HTTP server request dispatching instead of `SocketHTTPServer_set_handler()`
   - Manual keep-alive management instead of `SocketHTTPServer` built-in
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - custom HTTP client */
   Socket_T sock = Socket_new();
   Socket_connect(sock, host, port);
   /* ... manual HTTP request building ... */
   send(fd, "GET / HTTP/1.1\r\nHost: ...\r\n\r\n", ...);
   
   /* FIXED - use SocketHTTPClient */
   SocketHTTPClient_T client = SocketHTTPClient_new(NULL);
   SocketHTTPClient_Response response;
   SocketHTTPClient_get(client, "http://example.com/", &response);
   
   /* REDUNDANT - custom auth header */
   char auth[256];
   snprintf(auth, sizeof(auth), "Basic %s", base64_encode(user_pass));
   
   /* FIXED - use SocketHTTPClient auth */
   SocketHTTPClient_setauth(client, AUTH_BASIC, "user", "pass");
   
   /* REDUNDANT - custom cookie handling */
   struct Cookie cookies[100];
   /* ... manual parsing, domain matching ... */
   
   /* FIXED - use SocketHTTPClient_CookieJar */
   SocketHTTPClient_CookieJar_T jar = SocketHTTPClient_CookieJar_new(arena);
   SocketHTTPClient_set_cookiejar(client, jar);
   ```
   
   **Available SocketHTTPClient functions**:
   - `SocketHTTPClient_new()` / `_free()` - Client lifecycle
   - `SocketHTTPClient_get()` / `_post()` / `_put()` / `_delete()` / `_head()` - Simple API
   - `SocketHTTPClient_Request_new()` / `_header()` / `_body()` / `_execute()` - Request builder
   - `SocketHTTPClient_setauth()` - Set authentication (Basic/Digest/Bearer)
   - `SocketHTTPClient_CookieJar_new()` / `_set()` / `_get()` / `_clear()` - Cookie management
   - `SocketHTTPClient_get_async()` / `_Request_submit()` / `_poll()` - Async API
   - `SocketHTTPClient_pool_stats()` / `_pool_clear()` - Pool management
   
   **Available SocketHTTPServer functions**:
   - `SocketHTTPServer_new()` / `_free()` - Server lifecycle
   - `SocketHTTPServer_start()` / `_stop()` - Server control
   - `SocketHTTPServer_set_handler()` - Set request handler callback
   - `SocketHTTPServer_poll()` / `_process()` - Event loop integration
   - `SocketHTTPServer_Request_method()` / `_uri()` / `_header()` / `_body()` - Request accessors
   - `SocketHTTPServer_Response_status()` / `_header()` / `_body()` / `_send()` - Response building

### 40. **Redundant Proxy Tunneling Implementation** [HIGH]
   - Custom HTTP CONNECT implementation instead of `SocketProxy_connect()` with `SOCKET_PROXY_HTTP`
   - Custom SOCKS4/4a implementation instead of `SocketProxy_connect()` with `SOCKET_PROXY_SOCKS4/4A`
   - Custom SOCKS5 implementation instead of `SocketProxy_connect()` with `SOCKET_PROXY_SOCKS5`
   - Manual proxy URL parsing instead of `SocketProxy_parse_url()`
   - Custom SOCKS5 authentication handling instead of built-in `proxy.username`/`proxy.password`
   - Manual HTTP CONNECT response parsing instead of reusing `SocketHTTP1_Parser_T`
   - Custom credential clearing instead of `SocketCrypto_secure_clear()` integration
   - Manual async proxy state machine instead of `SocketProxy_connect_async()`
   - Custom SOCKS5 method negotiation instead of built-in method selection
   - Manual hostname-to-IP resolution for SOCKS4 instead of SOCKS4a automatic handling
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - custom HTTP CONNECT */
   char request[512];
   snprintf(request, sizeof(request), "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n",
            target, port, target, port);
   send(proxy_fd, request, strlen(request), 0);
   /* ... manual response parsing ... */
   
   /* FIXED - use SocketProxy */
   SocketProxy_Config proxy;
   SocketProxy_config_defaults(&proxy);
   proxy.type = SOCKET_PROXY_HTTP;
   proxy.host = "proxy.example.com";
   proxy.port = 8080;
   Socket_T sock = SocketProxy_connect(&proxy, target, port);
   
   /* REDUNDANT - custom SOCKS5 handshake */
   uint8_t greeting[] = { 0x05, 0x01, 0x00 };  /* Version, 1 method, no auth */
   send(proxy_fd, greeting, 3, 0);
   recv(proxy_fd, response, 2, 0);
   /* ... more manual protocol handling ... */
   
   /* FIXED - use SocketProxy */
   proxy.type = SOCKET_PROXY_SOCKS5;
   proxy.username = "user";      /* Optional auth */
   proxy.password = "pass";
   Socket_T sock = SocketProxy_connect(&proxy, target, port);
   
   /* REDUNDANT - custom proxy URL parsing */
   if (strncmp(url, "socks5://", 9) == 0) {
       /* ... manual parsing ... */
   }
   
   /* FIXED - use SocketProxy_parse_url */
   SocketProxy_parse_url("socks5://user:pass@proxy:1080", &proxy, arena);
   ```
   
   **Available SocketProxy functions**:
   - `SocketProxy_connect()` - Synchronous proxy connection
   - `SocketProxy_connect_tls()` - Sync with TLS to target after tunnel
   - `SocketProxy_connect_async()` - Async proxy connection (for event loops)
   - `SocketProxy_Conn_process()` - Process async connection events
   - `SocketProxy_Conn_poll_events()` - Get events to poll for
   - `SocketProxy_Conn_state()` - Get current state
   - `SocketProxy_Conn_result()` - Get result code
   - `SocketProxy_Conn_socket()` - Get tunneled socket (transfers ownership)
   - `SocketProxy_Conn_free()` - Free async connection context
   - `SocketProxy_parse_url()` - Parse `socks5://user:pass@host:port` URLs
   - `SocketProxy_config_defaults()` - Initialize config with defaults
   - `SocketProxy_result_string()` - Get error description
   - `SocketProxy_type_string()` - Get proxy type name
   - `SocketProxy_state_string()` - Get state name

### 41. **Redundant WebSocket Implementation** [HIGH]
   - Custom WebSocket handshake instead of `SocketWS_client_new()` / `SocketWS_server_accept()`
   - Manual Sec-WebSocket-Key generation instead of `SocketCrypto_websocket_key()`
   - Manual Sec-WebSocket-Accept computation instead of `SocketCrypto_websocket_accept()`
   - Custom XOR masking instead of `SocketWS` built-in optimized masking
   - Custom frame parsing instead of `SocketWS_recv_message()`
   - Custom UTF-8 validation for text frames instead of `SocketUTF8_update()` integration
   - Manual ping/pong handling instead of `SocketWS_ping()` / `SocketWS_pong()`
   - Custom close handshake instead of `SocketWS_close()`
   - Manual permessage-deflate instead of `SocketWS` built-in compression
   - Custom frame fragmentation instead of `SocketWS` automatic handling
   - Manual upgrade request detection instead of `SocketWS_is_upgrade()`
   - Custom message reassembly instead of `SocketWS_recv_message()` auto-reassembly
   - Manual state machine instead of `SocketWS_state()` queries
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - custom WebSocket key generation */
   unsigned char key_bytes[16];
   RAND_bytes(key_bytes, 16);
   char key[25];
   base64_encode(key_bytes, 16, key);
   
   /* FIXED - use SocketCrypto */
   char key[SOCKET_CRYPTO_WEBSOCKET_KEY_SIZE];
   SocketCrypto_websocket_key(key);
   
   /* REDUNDANT - custom accept computation */
   char concat[60];
   snprintf(concat, sizeof(concat), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key);
   unsigned char sha1[20];
   SHA1(concat, strlen(concat), sha1);
   char accept[29];
   base64_encode(sha1, 20, accept);
   
   /* FIXED - use SocketCrypto */
   char accept[SOCKET_CRYPTO_WEBSOCKET_ACCEPT_SIZE];
   SocketCrypto_websocket_accept(key, accept);
   
   /* REDUNDANT - custom XOR masking */
   for (size_t i = 0; i < len; i++)
       data[i] ^= mask[i % 4];
   
   /* FIXED - use SocketWS optimized masking (8-byte aligned) */
   /* Handled internally by SocketWS_send_text() / SocketWS_send_binary() */
   
   /* REDUNDANT - custom frame parsing */
   int fin = (header[0] >> 7) & 1;
   int opcode = header[0] & 0x0F;
   int masked = (header[1] >> 7) & 1;
   uint64_t len = header[1] & 0x7F;
   /* ... manual extended length handling ... */
   
   /* FIXED - use SocketWS */
   SocketWS_T ws = SocketWS_client_new(socket, host, path, &config);
   SocketWS_handshake(ws);
   SocketWS_send_text(ws, message, strlen(message));
   ```
   
   **Available SocketWS functions**:
   - `SocketWS_config_defaults()` - Initialize config with defaults
   - `SocketWS_client_new()` - Create client WebSocket
   - `SocketWS_server_accept()` - Accept server WebSocket upgrade
   - `SocketWS_server_reject()` - Reject upgrade with HTTP status
   - `SocketWS_is_upgrade()` - Check if HTTP request is WebSocket upgrade
   - `SocketWS_handshake()` - Perform/continue handshake
   - `SocketWS_send_text()` / `SocketWS_send_binary()` - Send messages
   - `SocketWS_recv_message()` - Receive complete message (with auto-reassembly)
   - `SocketWS_recv_available()` - Check if data available
   - `SocketWS_ping()` / `SocketWS_pong()` - Control frames
   - `SocketWS_close()` - Initiate close handshake
   - `SocketWS_state()` - Get connection state (CONNECTING/OPEN/CLOSING/CLOSED)
   - `SocketWS_socket()` - Get underlying TCP socket
   - `SocketWS_pollfd()` / `SocketWS_poll_events()` / `SocketWS_process()` - Event loop
   - `SocketWS_enable_auto_ping()` / `SocketWS_disable_auto_ping()` - Keepalive
   - `SocketWS_close_code()` / `SocketWS_close_reason()` - Close status
   - `SocketWS_last_error()` / `SocketWS_error_string()` - Error handling
   - `SocketWS_selected_subprotocol()` - Get negotiated subprotocol
   - `SocketWS_compression_enabled()` - Check if deflate active
   - `SocketWS_free()` - Free WebSocket

### 42. **Redundant SCM_RIGHTS FD Passing** [HIGH]
   - Custom sendmsg/recvmsg with SCM_RIGHTS instead of `Socket_sendfd()`/`Socket_recvfd()`
   - Manual CMSG_SPACE/CMSG_LEN/CMSG_FIRSTHDR/CMSG_DATA construction
   - Custom control message buffer allocation instead of stack-allocated
   - Manual FD validation after receiving via SCM_RIGHTS
   - Missing FD leak prevention (not closing extra FDs on error)
   - Custom MSG_CTRUNC handling instead of built-in error handling
   - Manual dummy byte handling (Linux requires 1 byte with SCM_RIGHTS)
   - Not checking socket domain before FD passing (must be AF_UNIX)
   - Custom would-block handling (EAGAIN/EWOULDBLOCK) instead of return 0 pattern
   
   **Detection Pattern**:
   ```c
   /* REDUNDANT - custom SCM_RIGHTS sendmsg */
   struct msghdr msg;
   struct iovec iov;
   char cmsg_buf[CMSG_SPACE(sizeof(int))];
   struct cmsghdr *cmsg;
   
   memset(&msg, 0, sizeof(msg));
   msg.msg_control = cmsg_buf;
   msg.msg_controllen = sizeof(cmsg_buf);
   
   cmsg = CMSG_FIRSTHDR(&msg);
   cmsg->cmsg_level = SOL_SOCKET;
   cmsg->cmsg_type = SCM_RIGHTS;
   cmsg->cmsg_len = CMSG_LEN(sizeof(int));
   memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
   
   sendmsg(sock_fd, &msg, 0);
   
   /* FIXED - use Socket_sendfd */
   Socket_sendfd(unix_socket, fd);
   
   /* REDUNDANT - custom SCM_RIGHTS recvmsg */
   struct msghdr msg;
   char cmsg_buf[CMSG_SPACE(sizeof(int) * 10)];
   /* ... manual parsing ... */
   cmsg = CMSG_FIRSTHDR(&msg);
   while (cmsg) {
       if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
           memcpy(&received_fd, CMSG_DATA(cmsg), sizeof(int));
       }
       cmsg = CMSG_NXTHDR(&msg, cmsg);
   }
   
   /* FIXED - use Socket_recvfd */
   int received_fd = -1;
   Socket_recvfd(unix_socket, &received_fd);
   if (received_fd >= 0) {
       /* Use fd... */
       close(received_fd);  /* Caller owns FD */
   }
   
   /* REDUNDANT - custom multiple FD passing */
   int fds[3] = { fd1, fd2, fd3 };
   cmsg->cmsg_len = CMSG_LEN(sizeof(int) * 3);
   memcpy(CMSG_DATA(cmsg), fds, sizeof(fds));
   
   /* FIXED - use Socket_sendfds */
   int fds[3] = { fd1, fd2, fd3 };
   Socket_sendfds(unix_socket, fds, 3);
   ```
   
   **Available Socket FD Passing functions**:
   - `Socket_sendfd()` - Send single FD over Unix socket
   - `Socket_recvfd()` - Receive single FD over Unix socket
   - `Socket_sendfds()` - Send multiple FDs (max `SOCKET_MAX_FDS_PER_MSG`)
   - `Socket_recvfds()` - Receive multiple FDs with count output
   
   **Notes**:
   - Only works with Unix domain sockets (AF_UNIX)
   - Returns 0 on would-block (EAGAIN/EWOULDBLOCK)
   - Raises `Socket_Failed` on error, `Socket_Closed` on disconnect
   - Receiver owns passed FDs and must close them
   - Max FDs per message: `SOCKET_MAX_FDS_PER_MSG` (253)

---

## Priority Levels

| Priority | Description | Action |
|----------|-------------|--------|
| **CRITICAL** | Causes bugs, deadlocks, or security issues | Fix immediately |
| **HIGH** | Significant code duplication, maintainability issues | Fix in current pass |
| **MEDIUM** | Minor inefficiencies, readability improvements | Fix if time permits |
| **LOW** | Style nits, micro-optimizations | Optional cleanup |

---

## Output Format

### Analysis Report

Provide a structured report with:

1. **Redundancy Summary**
   - Total redundancies found by category and priority
   - Estimated lines removable
   - Complexity reduction estimate

2. **Detailed Findings** (sorted by priority)
   For each redundancy:
   - **Priority**: CRITICAL/HIGH/MEDIUM/LOW
   - **Category**: (from list above)
   - **Location**: Line numbers
   - **Current**: Code snippet
   - **Issue**: Description
   - **Action**: What to do
   - **Risk**: None/Low/Medium

3. **Cross-File Notes** (if applicable)
   - Related redundancies in other files
   - Suggested follow-up refactoring

4. **Refactored Code**
   - Complete file with all redundancies removed
   - Inline comments marking significant changes
   - Preserved functionality guarantee

### Example Output Format

```
=== REDUNDANCY ANALYSIS: filename.c ===

SUMMARY:
- CRITICAL: 1 (mutex deadlock risk)
- HIGH: 4 (duplicate code, error handling)
- MEDIUM: 6 (expressions, loops)
- LOW: 3 (includes, style)
- Total: 14 redundancies, ~80 lines removable

FINDINGS (by priority):

[CRITICAL] Redundant Mutex - Line 234
Current: Nested pthread_mutex_lock on same mutex
Issue: Potential deadlock with non-recursive mutex
Action: Remove inner lock, verify thread safety
Risk: Medium - verify no concurrent access

[HIGH] Duplicate Code - Lines 45-52, 78-85
Current: Identical null-check and error handling in two functions
Action: Extract to static helper `validate_input()`
Risk: None

[HIGH] Redundant TRY/EXCEPT - Lines 120-135
Current: Inner TRY just re-raises Socket_Error
Action: Remove inner TRY block
Risk: None

[MEDIUM] Redundant Expression - Line 156
Current: strlen(name) called 3 times in same function
Action: Cache in local variable `name_len`
Risk: None

[LOW] Redundant Include - Line 8
Current: `#include <stdlib.h>` - nothing from stdlib used
Action: Remove include
Risk: Low - verify no implicit dependencies

CROSS-FILE NOTES:
- Similar validation pattern in Socket.c:234 and SocketPool.c:89
- Consider extracting to SocketCommon.c

=== REFACTORED CODE ===

[Complete refactored file with redundancies removed]
```

---

## Redundancy Removal Principles

1. **Preserve Functionality** - Code must behave identically after removal
2. **Prefer Existing** - Use existing codebase functions over local implementations
3. **One Source of Truth** - Eliminate all but one copy of duplicated logic
4. **Minimal Code** - Less code = fewer bugs, easier maintenance
5. **Clarity Over Brevity** - Don't remove code that adds meaningful clarity
6. **Safe Removal** - When uncertain, keep the code and note it
7. **DRY Principle** - Don't Repeat Yourself
8. **Fix Critical First** - Address CRITICAL/HIGH before MEDIUM/LOW

---

## Safety Checklist

Before finalizing, verify:

- [ ] All removed code was truly redundant (not just similar)
- [ ] No functionality changed or lost
- [ ] No new warnings introduced
- [ ] File still compiles correctly (`-Wall -Wextra -Werror`)
- [ ] All edge cases still handled
- [ ] Thread safety preserved (no new race conditions)
- [ ] Exception paths still correct
- [ ] Arena cleanup still complete in FINALLY blocks
- [ ] Module naming conventions preserved
- [ ] CRITICAL issues all addressed
- [ ] New dependencies properly included (SocketUtil.h, SocketCommon.h, etc.)
- [ ] Module exception properly declared with SOCKET_DECLARE_MODULE_EXCEPTION
- [ ] SocketBase_T used instead of duplicated fd/arena fields (for socket subtypes)

---

## Integration with Socket Library

When removing redundancy, leverage existing components:

| Need | Use This | Not This |
|------|----------|----------|
| Memory allocation | `ALLOC`/`CALLOC` from SocketConfig.h | Custom malloc wrappers |
| Error formatting | `SOCKET_ERROR_FMT`/`SOCKET_ERROR_MSG` from SocketUtil.h | Local snprintf patterns |
| Error + exception | `SOCKET_RAISE_FMT`/`SOCKET_RAISE_MSG` from SocketUtil.h | Separate error format + raise |
| Module exception | `SOCKET_DECLARE_MODULE_EXCEPTION` from SocketUtil.h | Manual __thread declaration |
| Exception raising | `SOCKET_RAISE_MODULE_ERROR(Module, e)` | Direct `.reason` modification |
| Socket validation | Existing `SOCKET_VALID_*` macros | Custom validation logic |
| Safe close | `SAFE_CLOSE(fd)` | Manual close with EINTR handling |
| Thread-local errors | `socket_error_buf` from SocketUtil.h | Local __thread buffers |
| Constants/limits | SocketConfig.h | Magic numbers |
| Hash golden ratio | `HASH_GOLDEN_RATIO` from SocketConfig.h | Magic `2654435761u` |
| Hash functions | `socket_util_hash_fd/ptr/uint()` from SocketUtil.h | Custom hash functions |
| DJB2 string hash | `socket_util_hash_djb2()` from SocketUtil.h | Custom DJB2 implementation |
| Length-aware hash | `socket_util_hash_djb2_len()` from SocketUtil.h | Manual loop with length |
| Case-insensitive hash | `socket_util_hash_djb2_ci()` from SocketUtil.h | Manual tolower loop |
| CI + length hash | `socket_util_hash_djb2_ci_len()` from SocketUtil.h | Combined manual hashing |
| Power-of-2 rounding | `socket_util_round_up_pow2()` from SocketUtil.h | Manual bit manipulation |
| Monotonic time | `Socket_get_monotonic_ms()` from SocketUtil.h | Manual clock_gettime |
| Socket base | `SocketCommon_new_base()` / `SocketBase_T` | Duplicated fd/arena fields |
| Socket options | `SocketCommon_set_option_int()` | Manual setsockopt wrappers |
| Address resolution | `SocketCommon_resolve_address()` | Manual getaddrinfo |
| Non-blocking mode | `SocketCommon_set_nonblock()` | Manual fcntl O_NONBLOCK |
| iovec total length | `SocketCommon_calculate_total_iov_len()` | Manual loop with overflow checks |
| iovec advancement | `SocketCommon_advance_iov()` | Manual iov pointer/len updates |
| Live count debug | `SocketLiveCount` struct + macros | Custom mutex-protected counters |
| TLS-aware I/O | `socket_send_internal()` / `socket_recv_internal()` | Manual if TLS_enabled routing |
| Port validation | `SocketCommon_validate_port()` | Custom range checks |
| Hostname validation | `SocketCommon_validate_hostname()` | Manual strlen checks |
| Endpoint caching | `SocketCommon_cache_endpoint()` | Manual getnameinfo calls |
| Graceful shutdown | `SocketPool_drain()` / `SocketPool_drain_wait()` | Custom shutdown state machines |
| Force close all | `SocketPool_drain_force()` | Manual connection iteration loops |
| Health status | `SocketPool_health()` / `SocketPool_state()` | Custom status tracking |
| Shutdown callback | `SocketPool_set_drain_callback()` | Manual completion signaling |
| SHA-256 hash | `SocketCrypto_sha256()` | Direct `SHA256()` OpenSSL call |
| HMAC-SHA256 | `SocketCrypto_hmac_sha256()` | Direct `HMAC()` OpenSSL call |
| Random bytes | `SocketCrypto_random_bytes()` | Direct `RAND_bytes()` OpenSSL call |
| Base64 encode/decode | `SocketCrypto_base64_encode/decode()` | Custom Base64 implementations |
| Hex encode/decode | `SocketCrypto_hex_encode/decode()` | Custom hex nibble functions |
| Secure comparison | `SocketCrypto_secure_compare()` | Custom constant-time compare |
| Secure memory clear | `SocketCrypto_secure_clear()` | `memset()` (may be optimized away) |
| WebSocket key/accept | `SocketCrypto_websocket_key/accept()` | Manual SHA1+Base64 composition |
| UTF-8 validation | `SocketUTF8_validate()` | Manual byte sequence checks |
| UTF-8 streaming | `SocketUTF8_init/update/finish()` | Custom state machine |
| HTTP method parsing | `SocketHTTP_method_parse()` | Manual string comparisons |
| HTTP status phrases | `SocketHTTP_status_reason()` | Custom status tables |
| HTTP headers | `SocketHTTP_Headers_T` | Custom linked list/array |
| HTTP header lookup | `SocketHTTP_Headers_get()` | Linear scan (O(n)) |
| HTTP date parsing | `SocketHTTP_date_parse()` | strptime (single format) |
| URI parsing | `SocketHTTP_URI_parse()` | Manual string splitting |
| Percent-encoding | `SocketHTTP_URI_encode/decode()` | Custom hex nibble functions |
| Media type parsing | `SocketHTTP_MediaType_parse()` | Manual Content-Type parsing |
| Accept q-values | `SocketHTTP_parse_accept()` | Custom quality sorting |
| HTTP/1.1 parsing | `SocketHTTP1_Parser_new/execute()` | Custom DFA/switch parser |
| Chunked encoding | `SocketHTTP1_chunk_encode()` | Manual hex size + CRLF |
| Chunked decoding | `SocketHTTP1_Parser_read_body()` | Custom chunk decoder |
| Request serialize | `SocketHTTP1_serialize_request()` | Manual snprintf formatting |
| Response serialize | `SocketHTTP1_serialize_response()` | Manual snprintf formatting |
| Body mode detect | `SocketHTTP1_Parser_body_mode()` | Manual header inspection |
| Keep-alive check | `SocketHTTP1_Parser_should_keepalive()` | Manual Connection header check |
| HTTP/1.1 compression | `SocketHTTP1_Decoder_decode()` | Direct zlib/brotli calls |
| HPACK encoding | `SocketHPACK_encode()` | Custom HPACK encoder |
| HPACK decoding | `SocketHPACK_decode()` | Custom HPACK decoder |
| Huffman encode | `SocketHPACK_huffman_encode()` | Custom bit packing |
| Huffman decode | `SocketHPACK_huffman_decode()` | Custom DFA/lookup table |
| HPACK int encode | `SocketHPACK_int_encode()` | Custom variable-length coding |
| HPACK int decode | `SocketHPACK_int_decode()` | Custom continuation byte handling |
| HPACK static table | `SocketHPACK_static_get/find()` | Custom header array |
| HPACK dynamic table | `SocketHPACK_Table_T` | Custom circular buffer |
| HTTP/2 connection | `SocketHTTP2_Conn_new()` | Custom connection management |
| HTTP/2 handshake | `SocketHTTP2_Conn_handshake()` | Manual preface exchange |
| HTTP/2 frame parse | `SocketHTTP2_frame_header_parse()` | Custom 9-byte parsing |
| HTTP/2 frame serialize | `SocketHTTP2_frame_header_serialize()` | Manual byte packing |
| HTTP/2 streams | `SocketHTTP2_Stream_new()` | Custom stream tracking |
| HTTP/2 stream state | `SocketHTTP2_Stream_state()` | Custom state machine |
| HTTP/2 send headers | `SocketHTTP2_Stream_send_headers()` | Manual HEADERS frame |
| HTTP/2 send data | `SocketHTTP2_Stream_send_data()` | Manual DATA frame |
| HTTP/2 flow control | `SocketHTTP2_*_window_update()` | Manual window management |
| HTTP/2 settings | `SocketHTTP2_Conn_settings()` | Custom SETTINGS handling |
| HTTP/2 goaway | `SocketHTTP2_Conn_goaway()` | Custom GOAWAY handling |
| HTTP/2 h2c upgrade | `SocketHTTP2_Conn_upgrade_*()` | Manual upgrade logic |
| HTTP client requests | `SocketHTTPClient_get/post/put/delete()` | Manual HTTP request building |
| HTTP auth (Basic) | `SocketHTTPClient_setauth()` | Custom Base64 header construction |
| HTTP auth (Digest) | `SocketHTTPClient_setauth()` | Custom MD5/SHA256 response |
| HTTP cookies | `SocketHTTPClient_CookieJar_*()` | Custom cookie parsing/storage |
| HTTP redirects | `SocketHTTPClient` (built-in) | Custom redirect following |
| HTTP connection pool | `SocketHTTPClient` (built-in) | Custom per-host pooling |
| HTTP server handler | `SocketHTTPServer_set_handler()` | Custom request dispatching |
| HTTP server lifecycle | `SocketHTTPServer_start/stop()` | Custom bind/listen/accept |
| Proxy connection | `SocketProxy_connect()` | Custom HTTP CONNECT/SOCKS implementation |
| Proxy URL parsing | `SocketProxy_parse_url()` | Manual URL parsing for proxy |
| Proxy config | `SocketProxy_config_defaults()` | Manual struct initialization |
| Async proxy | `SocketProxy_connect_async()` | Custom async state machine |
| SOCKS5 auth | `SocketProxy` with username/password | Custom SOCKS5 RFC 1929 handling |
| HTTP CONNECT auth | `SocketProxy` with `extra_headers` | Custom Proxy-Authorization header |
| WebSocket key | `SocketCrypto_websocket_key()` | Manual random + Base64 |
| WebSocket accept | `SocketCrypto_websocket_accept()` | Manual SHA1 + Base64 |
| WebSocket handshake | `SocketWS_client_new()` / `SocketWS_server_accept()` | Custom HTTP upgrade |
| WebSocket frames | `SocketWS_send_text()` / `SocketWS_recv_message()` | Custom frame parsing |
| WebSocket masking | `SocketWS` (built-in 8-byte aligned) | Custom XOR loop |
| WebSocket UTF-8 | `SocketWS` + `SocketUTF8` (integrated) | Custom UTF-8 validation |
| WebSocket ping/pong | `SocketWS_ping()` / `SocketWS_pong()` | Custom control frames |
| WebSocket close | `SocketWS_close()` | Custom close handshake |
| WebSocket deflate | `SocketWS` (built-in when zlib) | Custom zlib integration |
| WebSocket upgrade check | `SocketWS_is_upgrade()` | Manual header inspection |
| WebSocket state | `SocketWS_state()` | Custom state tracking |
| WebSocket auto-ping | `SocketWS_enable_auto_ping()` | Custom timer management |
| WebSocket message reassembly | `SocketWS_recv_message()` | Custom fragment handling |
| FD passing (single) | `Socket_sendfd()` / `Socket_recvfd()` | Custom sendmsg/recvmsg SCM_RIGHTS |
| FD passing (multiple) | `Socket_sendfds()` / `Socket_recvfds()` | Custom CMSG construction |
| FD validation after recv | Use `fcntl(fd, F_GETFD)` (built-in) | Manual FD validity checks |
| TLS context (client) | `SocketTLSContext_new_client()` | Manual `SSL_CTX_new()` setup |
| TLS context (server) | `SocketTLSContext_new_server()` | Manual cert/key loading |
| TLS enable | `SocketTLS_enable()` | Manual `SSL_new()` + `SSL_set_fd()` |
| TLS handshake | `SocketTLS_handshake_auto()` | Manual handshake loop |
| TLS I/O | `SocketTLS_send()` / `SocketTLS_recv()` | Direct `SSL_read/write()` |
| TLS disable | `SocketTLS_disable()` | Manual teardown with memory issues |
| TLS session save | `SocketTLS_session_save()` | Manual `SSL_get1_session()` |
| TLS session restore | `SocketTLS_session_restore()` | Manual `SSL_set_session()` |
| TLS key rotation | `SocketTLS_request_key_update()` | No rotation (security risk) |
| kTLS offload | `SocketTLS_enable_ktls()` | Manual kernel TLS setup |
| TLS sendfile | `SocketTLS_sendfile()` | Manual file reading + send |
| TLS session cache | `SocketTLSContext_enable_session_cache()` | Manual cache management |
| TLS session tickets | `SocketTLSContext_enable_session_tickets()` | Manual ticket key setup |
| OCSP stapling (server) | `SocketTLSContext_set_ocsp_response()` | Manual OCSP response handling |
| OCSP must-staple | `SocketTLSContext_set_ocsp_must_staple()` | No enforcement |
| Certificate pinning | `SocketTLSContext_add_pin()` | Custom pin verification |
| CRL loading | `SocketTLSContext_load_crl()` | Manual X509_STORE ops |
| CRL auto-refresh | `SocketTLSContext_set_crl_auto_refresh()` | Custom timer + reload |
| Certificate Transparency | `SocketTLSContext_enable_ct()` | No CT verification |
| Custom verify callback | `SocketTLSContext_set_verify_callback()` | Direct OpenSSL callback |
| DTLS context (client) | `SocketDTLSContext_new_client()` | Manual DTLS_method() setup |
| DTLS context (server) | `SocketDTLSContext_new_server()` | Manual DTLS cert loading |
| DTLS cookie exchange | `SocketDTLSContext_enable_cookie_exchange()` | Custom cookie callbacks |
| DTLS cookie rotation | `SocketDTLSContext_rotate_cookie_secret()` | Manual secret management |
| DTLS enable | `SocketDTLS_enable()` | Manual SSL/BIO setup |
| DTLS handshake | `SocketDTLS_handshake_loop()` | Manual DTLSv1_listen() |
| DTLS I/O | `SocketDTLS_send()` / `SocketDTLS_recv()` | Direct SSL_read/write() |
| DTLS MTU | `SocketDTLSContext_set_mtu()` | Manual DTLS_set_link_mtu() |

---

## Automated Detection Patterns

Use these grep/ripgrep patterns to find common redundancies:

```bash
# Multiple strlen on same variable
rg 'strlen\s*\(\s*(\w+)\s*\)' -o | sort | uniq -c | sort -rn

# Potential double-close
rg 'close\s*\(' --context=5 | grep -B5 'close'

# Empty TRY blocks
rg 'TRY\s*$' -A3 | grep -B1 'END_TRY'

# Redundant NULL checks after assert
rg 'assert\s*\(\s*\w+\s*\)' -A2 | grep 'NULL'

# Duplicate setsockopt
rg 'setsockopt.*SO_' | cut -d: -f2 | sort | uniq -c | grep -v '^\s*1'

# Two-step error+raise (should use SOCKET_RAISE_FMT)
rg 'SOCKET_ERROR_FMT|SOCKET_ERROR_MSG' -A1 | grep 'RAISE_MODULE_ERROR'

# Manual module exception declaration (should use SOCKET_DECLARE_MODULE_EXCEPTION)
rg '__thread.*Except_T.*DetailedException'

# Manual hash function (should use socket_util_hash_*)
rg '2654435761u|HASH_GOLDEN_RATIO' --type c

# Manual clock_gettime (should use Socket_get_monotonic_ms)
rg 'clock_gettime.*CLOCK_MONOTONIC' --type c

# Manual iov length calculation loops
rg 'for.*iovcnt.*iov_len' --type c

# Manual TLS routing (should use socket_*_internal)
rg 'if.*tls_enabled.*SSL_' --type c

# Duplicated socket option setters
rg 'setsockopt.*SOL_SOCKET' --type c | cut -d: -f1 | sort | uniq -c | sort -rn

# Manual live count tracking (should use SocketLiveCount)
rg 'pthread_mutex.*count|live_count' --type c

# Manual shutdown state tracking (should use SocketPool_drain)
rg 'is_shutting_down|shutdown_state|draining' --type c

# Manual connection close loops (should use SocketPool_drain_force)
rg 'for.*maxconns.*shutdown|for.*connections.*Socket_free' --type c

# Manual health status (should use SocketPool_health)
rg 'HEALTH_HEALTHY|HEALTH_DRAINING|health_status' --type c

# Direct OpenSSL hash calls (should use SocketCrypto)
rg 'SHA256\(|SHA1\(|MD5\(' --type c | grep -v SocketCrypto

# Direct HMAC calls (should use SocketCrypto_hmac_sha256)
rg 'HMAC\s*\(' --type c | grep -v SocketCrypto

# Direct RAND_bytes calls (should use SocketCrypto_random_bytes)
rg 'RAND_bytes\s*\(' --type c | grep -v SocketCrypto

# Custom hex decode (should use SocketCrypto_hex_decode)
rg 'hex_char_to_nibble|hex_to_byte|parse_hex' --type c | grep -v SocketCrypto

# memset for sensitive data (should use SocketCrypto_secure_clear)
rg 'memset.*password|memset.*secret|memset.*key' --type c

# Manual UTF-8 validation (should use SocketUTF8_validate)
rg '0x80|0xC0|0xE0|0xF0' --type c | grep -i 'utf\|valid'

# Manual HTTP method parsing (should use SocketHTTP_method_parse)
rg 'strncmp.*GET\|strncmp.*POST\|strcmp.*DELETE' --type c

# Manual HTTP header lookup (should use SocketHTTP_Headers_get)
rg 'strcasecmp.*Content-Type\|strcasecmp.*Host' --type c

# Manual HTTP date parsing (should use SocketHTTP_date_parse)
rg 'strptime.*GMT\|strftime.*GMT' --type c

# Manual URI parsing (should use SocketHTTP_URI_parse)
rg 'strstr.*://\|strchr.*:.*/' --type c | grep -i 'uri\|url'

# Manual percent-decode (should use SocketHTTP_URI_decode)
rg '%[0-9A-Fa-f][0-9A-Fa-f]' --type c | grep -i 'decode\|unescape'

# Manual HTTP/1.1 request line parsing (should use SocketHTTP1_Parser)
rg 'sscanf.*%s.*%s.*HTTP' --type c
rg 'GET \|POST \|PUT \|DELETE ' --type c | grep -v SocketHTTP

# Manual chunk size parsing (should use SocketHTTP1_Parser)
rg 'strtoul.*16|sscanf.*%[xX]' --type c | grep -i chunk

# Manual chunked encoding (should use SocketHTTP1_chunk_encode)
rg 'snprintf.*%[xX].*\\\\r\\\\n' --type c

# Manual HTTP version parsing (should use SocketHTTP1_Parser)
rg 'HTTP/1\.[01]' --type c | grep 'strncmp\|strcmp\|sscanf'

# Manual Content-Length parsing (should use SocketHTTP1_Parser)
rg 'Content-Length.*strtol\|atoi.*Content-Length' --type c

# Manual Transfer-Encoding detection (should use SocketHTTP1_Parser_body_mode)
rg 'Transfer-Encoding.*chunked' --type c | grep 'strcasecmp\|strstr'

# Manual keep-alive detection (should use SocketHTTP1_Parser_should_keepalive)
rg 'Connection.*keep-alive\|Connection.*close' --type c | grep 'strcasecmp'

# Manual DJB2 hash (should use socket_util_hash_djb2*)
rg '5381.*hash|hash.*33|hash << 5' --type c | grep -v SocketUtil

# Manual power-of-2 rounding (should use socket_util_round_up_pow2)
rg 'n \|= n >> [12]' --type c | grep -v SocketUtil

# Custom HPACK encoding (should use SocketHPACK_encode)
rg 'hpack.*encode|huffman.*encode' -i --type c | grep -v SocketHPACK

# Custom HPACK integer coding (should use SocketHPACK_int_*)
rg '\(1 << prefix.*- 1\|0x7f.*continue' --type c | grep -v SocketHPACK

# Custom Huffman table (should use SocketHPACK_huffman_*)
rg 'huffman_table|huffman_codes' -i --type c | grep -v SocketHPACK

# Custom dynamic table (should use SocketHPACK_Table_T)
rg 'dynamic.*table.*head.*tail|circular.*buffer.*hpack' -i --type c

# Manual HTTP/2 frame parsing (should use SocketHTTP2_frame_header_parse)
rg 'buf\[0\].*<<.*16.*buf\[1\].*<<.*8' --type c | grep -v SocketHTTP2

# Custom HTTP/2 stream state machine (should use SocketHTTP2_Stream_state)
rg 'IDLE.*OPEN.*HALF_CLOSED|stream_state.*enum' --type c | grep -v SocketHTTP2

# Manual HTTP/2 flow control (should use SocketHTTP2_*_window_update)
rg 'send_window.*recv_window|window_size.*65535' --type c | grep -v SocketHTTP2

# Custom HTTP/2 connection preface (should use SocketHTTP2_Conn_handshake)
rg 'PRI \* HTTP/2\.0|connection.*preface' -i --type c | grep -v SocketHTTP2

# Manual SETTINGS frame handling (should use SocketHTTP2_Conn_settings)
rg 'SETTINGS_HEADER_TABLE_SIZE|SETTINGS_MAX_CONCURRENT' --type c | grep -v SocketHTTP2

# Custom HTTP/2 GOAWAY handling (should use SocketHTTP2_Conn_goaway)
rg 'goaway.*last_stream|GOAWAY.*error_code' -i --type c | grep -v SocketHTTP2

# Custom HTTP CONNECT (should use SocketProxy with SOCKET_PROXY_HTTP)
rg 'CONNECT.*HTTP/1\.[01]|HTTP.*CONNECT' --type c | grep -v SocketProxy

# Custom SOCKS handshake (should use SocketProxy)
rg '0x05.*0x01.*0x00|SOCKS.*greeting|socks.*version' -i --type c | grep -v SocketProxy

# Custom SOCKS5 auth (should use SocketProxy with username/password)
rg 'socks.*auth|0x02.*password|RFC.*1929' -i --type c | grep -v SocketProxy

# Custom proxy URL parsing (should use SocketProxy_parse_url)
rg 'socks5://|socks4://|http://.*proxy' -i --type c | grep 'strstr\|strncmp' | grep -v SocketProxy

# Manual proxy state machine (should use SocketProxy_connect_async)
rg 'PROXY_STATE|proxy.*state.*machine' -i --type c | grep -v SocketProxy

# Custom WebSocket key generation (should use SocketCrypto_websocket_key)
rg 'RAND_bytes.*16.*base64|websocket.*key.*random' -i --type c | grep -v SocketCrypto

# Custom WebSocket accept (should use SocketCrypto_websocket_accept)
rg '258EAFA5|SHA1.*websocket|websocket.*sha1' -i --type c | grep -v SocketCrypto

# Custom XOR masking (should use SocketWS built-in)
rg 'mask\[i.*%.*4\]|data\[i\].*\^=.*mask' --type c | grep -v SocketWS

# Custom frame parsing (should use SocketWS)
rg 'opcode.*0x0F|FIN.*0x80|payload.*0x7F' --type c | grep -v SocketWS

# Custom WebSocket state machine (should use SocketWS)
rg 'WS_STATE|websocket.*state|ws_state' -i --type c | grep -v SocketWS

# Custom WebSocket upgrade detection (should use SocketWS_is_upgrade)
rg 'Upgrade.*websocket|Sec-WebSocket-Key' -i --type c | grep 'strcasecmp\|strstr' | grep -v SocketWS

# Custom WebSocket message reassembly (should use SocketWS_recv_message)
rg 'fragment.*reassembl|continuation.*frame' -i --type c | grep -v SocketWS

# Custom WebSocket auto-ping (should use SocketWS_enable_auto_ping)
rg 'ping.*interval|auto.*ping|ping.*timer' -i --type c | grep -v SocketWS

# Custom SCM_RIGHTS FD passing (should use Socket_sendfd/recvfd)
rg 'SCM_RIGHTS|cmsg_type.*SCM_RIGHTS' --type c | grep -v Socket-fd
rg 'CMSG_SPACE.*sizeof.*int|CMSG_LEN.*sizeof.*int' --type c | grep -v Socket-fd

# Custom sendmsg/recvmsg for FD passing (should use Socket_sendfd/recvfd)
rg 'sendmsg.*SCM|recvmsg.*cmsg' -i --type c | grep -v Socket-fd

# Manual CMSG construction (should use Socket_sendfds/recvfds)
rg 'CMSG_FIRSTHDR|CMSG_NXTHDR|CMSG_DATA' --type c | grep -v Socket-fd

# Manual TLS context setup (should use SocketTLSContext_new_*)
rg 'SSL_CTX_new.*TLS_method' --type c | grep -v SocketTLS

# Manual TLS protocol version (should use library defaults)
rg 'SSL_CTX_set_min_proto_version|SSL_CTX_set_max_proto_version' --type c | grep -v SocketTLS

# Manual TLS handshake loop (should use SocketTLS_handshake_auto)
rg 'SSL_do_handshake.*while\|SSL_ERROR_WANT' --type c | grep -v SocketTLS

# Manual TLS session handling (should use SocketTLS_session_*)
rg 'SSL_get1_session|SSL_set_session' --type c | grep -v SocketTLS

# Manual OCSP stapling (should use SocketTLSContext_set_ocsp_response)
rg 'SSL_CTX_set_tlsext_status' --type c | grep -v SocketTLS

# Manual certificate pinning (should use SocketTLSContext_add_pin)
rg 'X509_pubkey_digest|SPKI.*pin' -i --type c | grep -v SocketTLS

# Manual CRL loading (should use SocketTLSContext_load_crl)
rg 'X509_STORE_add_crl|d2i_X509_CRL' --type c | grep -v SocketTLS

# Manual DTLS context (should use SocketDTLSContext_new_*)
rg 'SSL_CTX_new.*DTLS_method' --type c | grep -v SocketDTLS

# Manual DTLS cookie (should use SocketDTLSContext_enable_cookie_exchange)
rg 'SSL_CTX_set_cookie_generate_cb|SSL_CTX_set_cookie_verify_cb' --type c | grep -v SocketDTLS

# Manual DTLS listen (should use SocketDTLS_listen)
rg 'DTLSv1_listen' --type c | grep -v SocketDTLS

# Manual kTLS setup (should use SocketTLS_enable_ktls)
rg 'SSL_set_options.*SSL_OP_ENABLE_KTLS' --type c | grep -v SocketTLS

# Unused includes (requires compilation)
# gcc -H file.c 2>&1 | grep '^\.'
```

---

## Critical Requirements

After redundancy removal, the code MUST:

1. Compile without warnings (`-Wall -Wextra -Werror`)
2. Maintain all functionality (behavioral equivalence)
3. Follow C Interfaces and Implementations style
4. Follow GNU C style (8-space indent, return types on separate lines)
5. Keep functions under 50 lines (prefer <30)
6. Use existing codebase patterns and utilities
7. Pass all existing tests

Provide the complete analysis and fully refactored code ready for immediate use.
