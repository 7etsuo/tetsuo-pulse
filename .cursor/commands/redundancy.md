# Redundancy Removal Command - Socket Library

You are an expert C developer specializing in code optimization and redundancy elimination. When `@redundancy` is used with a file reference (e.g., `@redundancy @file`), perform a comprehensive analysis to identify and remove ALL forms of redundancy from the provided code while preserving functionality and following socket library conventions.

## Socket Library Context

This codebase follows **C Interfaces and Implementations** patterns with:
- **Arena-based memory management** (`Arena_T`, `ALLOC`, `CALLOC`)
- **Exception-based error handling** (`TRY`, `EXCEPT`, `FINALLY`, `RAISE`)
- **Module-prefixed naming** (`Socket_*`, `Arena_*`, `SocketPoll_*`)
- **Thread-safe design** (thread-local storage, mutex protection)
- **GNU C coding style** (8-space indentation, return types on separate lines)
- **Opaque types** with `T` macro pattern (`#define T ModuleName_T`)
- **Cross-platform backends** (epoll/kqueue/poll abstraction in SocketPoll)
- **SocketBase delegation** (`SocketBase_T` shared by Socket_T/SocketDgram_T)
- **Centralized error infrastructure** (`SOCKET_DECLARE_MODULE_EXCEPTION`, `SOCKET_RAISE_FMT`)
- **TLS-aware I/O abstraction** (`socket_send_internal`, `socket_recv_internal`)
- **Live count debugging** (`SocketLiveCount` for instance tracking)

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
   
   Remove local implementations that duplicate existing functionality.

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
   ```
   
   **Note**: All hash functions use HASH_GOLDEN_RATIO (2654435761u) from SocketConfig.h.

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
   ```
   
   **Available SocketIO functions**:
   - `socket_send_internal()` - TLS-aware send
   - `socket_recv_internal()` - TLS-aware recv
   - `socket_sendv_internal()` - TLS-aware scatter send
   - `socket_recvv_internal()` - TLS-aware gather recv
   - `socket_is_tls_enabled()` - Check TLS status
   - `socket_tls_want_read()` / `socket_tls_want_write()` - Handshake state

### 29. **Redundant Token Bucket Calculations** [LOW]
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
6. Keep files under 1500 lines (prefer <1000)
7. Use existing codebase patterns and utilities
8. Pass all existing tests

Provide the complete analysis and fully refactored code ready for immediate use.
