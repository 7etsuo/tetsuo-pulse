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

## Step-by-Step Redundancy Removal Process

1. **Analyze the Entire File**: Read through the complete file to understand structure, dependencies, and patterns before making changes.

2. **Map All Code Blocks**: Identify every function, macro, include, and code block. Create a mental model of what each piece does.

3. **Cross-Reference with Codebase**: Check if functionality already exists in base layer components:
   - `Arena.h` / `Except.h` - Foundation layer
   - `SocketConfig.h` - Constants, macros, limits
   - `SocketUtil.h` - Error formatting, logging, thread-local exceptions
   - `SocketCommon.h` - Shared socket base functionality
   - `SocketBuf.h` - Buffer operations
   
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

---

## Integration with Socket Library

When removing redundancy, leverage existing components:

| Need | Use This | Not This |
|------|----------|----------|
| Memory allocation | `ALLOC`/`CALLOC` from SocketConfig.h | Custom malloc wrappers |
| Error formatting | `SOCKET_ERROR_FMT`/`SOCKET_ERROR_MSG` from SocketUtil.h | Local snprintf patterns |
| Exception raising | `RAISE_MODULE_ERROR` macro | Direct `.reason` modification |
| Socket validation | Existing `SOCKET_VALID_*` macros | Custom validation logic |
| Safe close | `SAFE_CLOSE(fd)` | Manual close with EINTR handling |
| Thread-local errors | `socket_error_buf` from SocketUtil.h | Local __thread buffers |
| Constants/limits | SocketConfig.h | Magic numbers |

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
