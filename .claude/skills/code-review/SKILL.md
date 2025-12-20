---
name: review
description: Code Review Command - Socket Library. Use when reviewing code, checking for issues, or when the user mentions code review, security, or code quality.
---

# Code Review Command

Perform comprehensive code review analyzing security, memory safety, error handling, style compliance, and best practices.

## Review Categories

### 1. Security Vulnerabilities

- Buffer overflows (array bounds, string operations)
- Integer overflow/underflow in arithmetic
- Unsafe functions (strcpy, sprintf, gets)
- Format string vulnerabilities
- Unvalidated input (paths, user input, parsed data)
- Race conditions, TOCTOU vulnerabilities
- Injection points (command, path injection)
- **Socket-specific**: Network protocol vulnerabilities, DNS injection, socket option manipulation

### 2. Memory Safety

- Memory leaks (all paths, especially exception paths)
- Double-free vulnerabilities
- Use-after-free issues
- Dangling pointer access
- Uninitialized memory access
- Arena allocation using `ALLOC/CALLOC` macros
- Arena lifetime matches object lifetime
- All memory disposed in all paths (including exceptions)
- `TRY/FINALLY` blocks properly dispose resources
- Missing `FINALLY` blocks in resource-allocating functions

### 3. Error Handling

- System calls checked for errors
- Exception handling uses `TRY/EXCEPT/FINALLY` consistently
- Module-specific exceptions used (`Socket_Failed`, `SocketPoll_Failed`)
- Thread-local error buffers used
- `RAISE_MODULE_ERROR` macro used correctly
- Proper cleanup in `FINALLY` blocks
- Informative, non-revealing error messages
- Switch statements handle all enum cases
- **Exception-based, not return codes**

### 4. C Interfaces and Implementations Style

- Include guards: `FILENAME_INCLUDED` suffix
- Module documentation at top of headers
- System headers before project headers
- Type pattern: `#define T ModuleName_T` then `typedef struct T *T;`
- Function declarations use `extern`
- Doxygen comments: `/**` with `@param`, `Returns:`, `Raises:`, `Thread-safe:`
- `#undef T` at end of header/implementation
- No implementation details in headers (opaque types)
- Return types on separate lines (GNU C style)

### 5. GNU C Style

- 8-space indentation (tabs or spaces)
- 80 column limit
- Function return types on separate lines
- GNU-style brace placement
- Pointer alignment right: `type *ptr`
- Consistent operator spacing
- Proper indentation

### 6. Code Quality & Best Practices

- **CRITICAL**: Functions under 20 lines
- **CRITICAL**: Files under 20000 lines
- Thread-safe functions (mutex, thread-local storage)
- Const correctness
- Unused parameters: `(void)param;`
- Forward declarations when appropriate
- Header guards correct
- Include order: system then project
- No magic numbers (use SocketConfig.h)
- Functions focused (single responsibility)
- Code duplication identified
- Dead code removal opportunities

### 7. Documentation Standards

- File headers with module description
- Doxygen function comments with `@param`, `Returns:`, `Raises:`, `Thread-safe:`
- Complex logic has inline comments (why, not what)
- Module-level documentation in headers
- Actionable TODOs with context (or removed/implemented)

### 8. Logic & Correctness

- Off-by-one errors
- Loop termination correct
- Boundary conditions handled
- Edge cases considered (empty, NULL, max)
- Logic errors in conditionals
- Potential NULL dereferences
- Division by zero risks
- Signed/unsigned mismatches
- Overflow checks before arithmetic

### 9. Socket Library Patterns

- **Arena-based memory**: `ALLOC/CALLOC`, not raw malloc
- **Exception-based errors**: `TRY/EXCEPT/FINALLY`, not return codes
- **Module naming**: Module prefixes (`Socket_*`, `Arena_*`)
- **Thread safety**: Mutex protection, thread-local storage
- **Opaque types**: Headers expose only opaque pointers
- **Resource cleanup**: All in `FINALLY` blocks, reverse order
- **Error reporting**: Thread-local buffers with `MODULE_ERROR_FMT/MSG`

## Review Output Format

For each issue:

1. **Severity**: Critical / High / Medium / Low / Style
2. **Category**: Security / Memory / Error Handling / Style / Quality / Logic / Socket Library Pattern
3. **Location**: File and line number(s)
4. **Issue**: Clear description
5. **Risk**: What could go wrong
6. **Recommendation**: Specific fix with code example
7. **Reference**: Link to good pattern in codebase

## Review Process

1. **Analyze code structure** - Understand function purpose and control flow
2. **Trace memory allocations** - Follow Arena paths to ensure disposal
3. **Trace exception paths** - Verify TRY/FINALLY cleanup
4. **Check input validation** - Verify validation before use
5. **Verify style compliance** - Check C Interfaces style and GNU C style
6. **Suggest improvements** - Actionable recommendations

## Example Review Patterns

```
[Memory/High] Socket.c:150
Issue: Arena allocated but not disposed in exception path
Risk: Memory leak if exception raised before Arena_dispose
Recommendation: Wrap in TRY/FINALLY:
  TRY
    arena = Arena_new();
    socket = ALLOC(arena, sizeof(*socket));
    // operations
  FINALLY
    Arena_dispose(&arena);
  END_TRY;
Reference: SocketPoll.c for proper Arena cleanup
```

```
[Style/Critical] CustomModule.c:45-78
Issue: Function exceeds 20-line limit (33 lines)
Risk: Violates single responsibility, difficult to maintain
Recommendation: Extract helpers:
  static void helper1(...) { /* <20 lines */ }
  static void helper2(...) { /* <20 lines */ }
  void main_function(...) {
    helper1(...);
    helper2(...);
  }
Reference: See refactor skill for extraction patterns
```

```
[Socket Library Pattern/High] CustomModule.c:120
Issue: Uses return code instead of exception
Risk: Inconsistent error handling
Recommendation: Use exception system:
  TRY
    result = operation();
  EXCEPT(Module_Failed)
    fprintf(stderr, "Error: %s\n", Module_GetLastError());
  END_TRY;
Reference: Socket.c for exception patterns
```

## Focus by File Type

- **Core** (`Arena.c`, `Except.c`): Memory patterns, thread safety, overflow
- **Socket** (`Socket.c`, `SocketBuf.c`): Network ops, error handling, Arena
- **Poll** (`SocketPoll_*.c`): Event handling, platform code, thread safety
- **Pool** (`SocketPool.c`): Connection management, hash tables, Arena
- **DNS** (`SocketDNS.c`): Async ops, thread pools, request queues
- **Headers**: Organization, opaque types, documentation

## Priority Focus

1. **Critical**: Functions >20 lines, files >20000 lines, missing `FINALLY`, memory leaks
2. **High**: Missing exception handling, Arena misuse, missing docs, thread safety
3. **Medium**: Style violations, code duplication, minor optimizations
4. **Low**: Documentation improvements, minor style tweaks

Provide prioritized issues: critical security/memory first, then function size violations, error handling gaps, then style/quality improvements. Reference socket library patterns and C Interfaces style.
