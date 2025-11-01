# Code Review Command - Socket Library

Perform a comprehensive code review of the specified file(s) or entire codebase of the socket library, analyzing for security vulnerabilities, memory safety issues, error handling completeness, C Interfaces and Implementations style compliance, GNU C style compliance, and best practices alignment.

## Review Categories

### 1. **Security Vulnerabilities**
   - Buffer overflows (array bounds, string operations)
   - Integer overflow/underflow (especially in arithmetic operations)
   - Use of unsafe functions (strcpy, sprintf, gets, etc.)
   - Format string vulnerabilities
   - Unvalidated input (file paths, user input, parsed data)
   - Race conditions (if applicable)
   - TOCTOU (Time-of-check-time-of-use) vulnerabilities
   - Potential injection points (command injection, path injection)
   - **Socket Library Specific**: Network protocol vulnerabilities, DNS injection, socket option manipulation

### 2. **Memory Safety**
   - Memory leaks (check all allocation paths, especially exception paths)
   - Double-free vulnerabilities
   - Use-after-free issues
   - Dangling pointer access
   - Uninitialized memory access
   - Verify all Arena allocations use `ALLOC`/`CALLOC` macros
   - Check that Arena lifetime matches object lifetime
   - Ensure all allocated memory is disposed in all code paths (including exception paths)
   - Verify `TRY/FINALLY` blocks properly dispose resources
   - Check for missing `FINALLY` blocks in resource-allocating functions
   - **Socket Library**: Verify Arena disposal in `FINALLY` blocks for all exception paths

### 3. **Error Handling**
   - All system calls checked for errors (socket, bind, listen, accept, etc.)
   - Exception handling uses `TRY/EXCEPT/FINALLY` pattern consistently
   - Module-specific exceptions used correctly (`Socket_Failed`, `SocketPoll_Failed`, etc.)
   - Thread-local error buffers used for detailed error messages
   - `RAISE_MODULE_ERROR` macro used correctly (thread-safe pattern)
   - Proper cleanup on exception paths using `FINALLY` blocks
   - Error messages are informative and non-revealing
   - Switch statements handle all enum cases (including default)
   - **Socket Library**: Verify exception-based error handling, not return codes

### 4. **C Interfaces and Implementations Style Compliance**
   - Include guards use `FILENAME_INCLUDED` suffix pattern
   - Module documentation at top of headers with comprehensive description
   - System headers included first (before project headers)
   - Type definition pattern: `#define T ModuleName_T` then `typedef struct T *T;`
   - Function declarations use `extern` keyword
   - Doxygen-style function documentation: `/**` comments with `@param`, `Returns:`, `Raises:`, `Thread-safe:`
   - `#undef T` at end of header and implementation files
   - No implementation details exposed in headers (opaque types only)
   - Return types on separate lines for function definitions (GNU C style)

### 5. **GNU C Style Compliance**
   - 8-space indentation (consistent tabs or spaces)
   - 80 column limit respected
   - Function return types on separate lines
   - Brace placement matches GNU style
   - Pointer alignment: Right (`type *ptr` not `type* ptr`)
   - Consistent spacing around operators
   - Proper indentation

### 6. **Code Quality & Best Practices**
   - **CRITICAL**: Functions are under 20 lines (must be enforced)
   - **CRITICAL**: Files are under 400 lines (must be enforced)
   - Thread-safe functions used (mutex protection, thread-local storage)
   - Const correctness (use const for parameters that shouldn't be modified)
   - Unused parameters cast to void: `(void)param;`
   - Forward declarations when appropriate
   - Header guards present and correct (`#ifndef FILENAME_INCLUDED`)
   - Include order: system headers first, then project headers
   - No magic numbers (use named constants from `SocketConfig.h`)
   - Functions are reasonably sized and focused (single responsibility)
   - Code duplication identified and opportunities for extraction
   - Dead code removal opportunities

### 7. **Documentation Standards**
   - File header comments present with module description
   - Functions have Doxygen-style comments with `@param`, `Returns:`, `Raises:`, `Thread-safe:`
   - Complex logic has inline comments explaining why (not what)
   - Module-level documentation in headers with Features, Thread Safety, Usage examples
   - TODO comments are actionable and have context (should be removed or implemented)

### 8. **Logic & Correctness**
   - Off-by-one errors in loops and array access
   - Loop termination conditions are correct
   - Boundary conditions handled properly
   - Edge cases considered (empty input, NULL pointers, max values)
   - Logic errors in conditionals
   - Potential NULL dereferences
   - Division by zero risks
   - Signed/unsigned mismatches
   - Overflow checks before arithmetic operations

### 9. **Socket Library-Specific Patterns**
   - **Arena-based memory management**: Related objects use `ALLOC`/`CALLOC`, not raw malloc
   - **Exception-based error handling**: Uses `TRY/EXCEPT/FINALLY`, not return codes
   - **Module naming**: Functions use module prefixes (`Socket_*`, `Arena_*`, `SocketPoll_*`, etc.)
   - **Thread safety**: Proper mutex protection, thread-local storage usage
   - **Opaque types**: Headers expose only opaque pointer types
   - **Resource cleanup**: All cleanup in `FINALLY` blocks, reverse order of allocation
   - **Error reporting**: Thread-local error buffers with `MODULE_ERROR_FMT`/`MODULE_ERROR_MSG`

## Review Output Format

For each issue found, provide:

1. **Severity**: Critical / High / Medium / Low / Style
2. **Category**: Security / Memory / Error Handling / Style / Quality / Logic / Socket Library Pattern
3. **Location**: File name and line number(s)
4. **Issue**: Clear description of the problem
5. **Risk**: What could go wrong if not fixed
6. **Recommendation**: Specific fix suggestion with code example
7. **Reference**: Link to existing good pattern in codebase (if applicable)

## Review Process

1. **Analyze the code structure** - Understand the function's purpose and control flow
2. **Trace memory allocations** - Follow all Arena allocation paths to ensure proper disposal
3. **Trace exception paths** - Verify all exception conditions use `TRY/FINALLY` cleanup
4. **Check input validation** - Verify all inputs are validated before use
5. **Verify style compliance** - Check against C Interfaces and Implementations style and GNU C style
6. **Suggest improvements** - Provide actionable recommendations

## Example Review Pattern

```
[Memory/High] Socket.c:150
Issue: Arena allocated but not disposed in exception path
Risk: Memory leak if exception is raised before Arena_dispose
Recommendation: Wrap in TRY/FINALLY block:
  TRY
    arena = Arena_new();
    socket = ALLOC(arena, sizeof(*socket));
    // ... operations ...
  FINALLY
    Arena_dispose(&arena);
  END_TRY;
Reference: See SocketPoll.c for proper Arena cleanup pattern
```

```
[Style/Critical] CustomModule.c:45-78
Issue: Function exceeds 20-line limit (33 lines)
Risk: Violates single responsibility principle, difficult to maintain
Recommendation: Extract helper functions:
  static void helper1(...) { /* < 20 lines */ }
  static void helper2(...) { /* < 20 lines */ }
  void main_function(...) {
    helper1(...);
    helper2(...);
    // < 20 lines total
  }
Reference: See refactor.md for function extraction patterns
```

```
[Socket Library Pattern/High] CustomModule.c:120
Issue: Uses return code for error instead of exception system
Risk: Inconsistent error handling, doesn't follow codebase patterns
Recommendation: Use exception system:
  TRY
    result = operation();
  // Handle success
  EXCEPT(Module_Failed)
    // Handle error
    fprintf(stderr, "Error: %s\n", Module_GetLastError());
  END_TRY;
Reference: See Socket.c for exception handling patterns
```

## Focus Areas by File Type

- **Core modules** (`Arena.c`, `Except.c`): Memory management patterns, thread safety, overflow protection
- **Socket modules** (`Socket.c`, `SocketBuf.c`, `SocketDgram.c`): Network operations, error handling, Arena usage
- **Poll modules** (`SocketPoll_*.c`): Event handling, platform-specific code, thread safety
- **Pool modules** (`SocketPool.c`): Connection management, hash tables, Arena usage
- **DNS modules** (`SocketDNS.c`): Async operations, thread pools, request queues
- **Headers**: Organization, opaque types, documentation completeness

## Socket Library Priority Focus

1. **Critical**: Functions >20 lines, files >400 lines, missing `FINALLY` blocks, memory leaks
2. **High**: Missing exception handling, Arena misuse, missing documentation, thread safety issues
3. **Medium**: Style violations, code duplication, minor optimizations
4. **Low**: Documentation improvements, minor style tweaks

Provide a prioritized list of issues, with critical security and memory safety issues first, followed by function size violations, error handling gaps, then style and quality improvements. All issues should reference socket library patterns and C Interfaces and Implementations style requirements.
