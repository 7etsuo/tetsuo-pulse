---
name: implement
description: Implement Function Helper - Socket Library. Use when implementing new functions, writing function bodies, or when the user mentions implementing, adding functionality, or creating new code.
---

# Implement Function Helper

Implement functions following C Interfaces and Implementations patterns with Arena allocation and exception-based error handling.

## Implementation Guidelines

### 1. Code Style

**C Interfaces and Implementations patterns**:
- Function return types on separate lines (GNU C)
- 8-space indentation (tabs or spaces)
- 80 column limit
- GNU-style brace placement
- Pointer alignment right: `type *ptr`
- Module prefixes: `Socket_*`, `Arena_*`, `SocketPoll_*`
- Opaque types: `T` macro pattern (`#define T ModuleName_T`)

### 2. Documentation

**Doxygen-style comments**:
```c
/**
 * FunctionName - Brief description
 * @param1: Description
 * @param2: Description
 *
 * Returns: Return value or NULL on failure
 * Raises: Exceptions that may be raised
 * Thread-safe: Yes/No with explanation
 *
 * Additional details, usage notes, constraints.
 */
```

### 3. Error Handling

**CRITICAL: Use exception-based error handling**:
- Use `TRY/EXCEPT/FINALLY/END_TRY` blocks
- Raise module exceptions: `RAISE_SOCKET_ERROR(Socket_Failed)`
- Use thread-local error buffers: `MODULE_ERROR_FMT`, `MODULE_ERROR_MSG`
- Clean up in `FINALLY` blocks
- **Never use return codes for errors**

Example:
```c
TRY
    resource1 = acquire_resource1();
    resource2 = acquire_resource2();
    perform_operation(resource1, resource2);
EXCEPT(Module_Failed)
    fprintf(stderr, "Error: %s\n", Module_GetLastError());
    RERAISE;
FINALLY
    if (resource2) release_resource2(&resource2);
    if (resource1) release_resource1(&resource1);
END_TRY;
```

### 4. Memory Management

**CRITICAL: Use Arena allocation**:
- Prefer `Arena_alloc` over `malloc` for related objects
- Use `ALLOC(arena, sizeof(*object))` macro
- Use `CALLOC(arena, count, sizeof(*object))` for zeroed
- Dispose arena: `Arena_dispose(&arena)`
- Only `malloc` for arena structure or standalone allocations

Example:
```c
Arena_T arena = Arena_new();
if (!arena)
{
    MODULE_ERROR_MSG(MODULE_ENOMEM ": Cannot allocate arena");
    RAISE_MODULE_ERROR(Module_Failed);
}

object = ALLOC(arena, sizeof(*object));
related = ALLOC(arena, sizeof(*related));

// Cleanup
Arena_dispose(&arena);  // Frees all at once
```

### 5. Pattern Matching

**Study existing patterns**:
- **Socket operations**: `Socket.c` for socket patterns
- **Memory management**: `Arena.c` for arena patterns
- **Exception handling**: Any module for `TRY/EXCEPT/FINALLY`
- **Thread safety**: Modules with mutex protection
- **Module structure**: Existing modules for organization

### 6. Function Size

**CRITICAL: Functions MUST be under 20 lines**:
- If >20 lines, break into smaller helpers
- Each function does ONE thing
- Extract complex logic to static helpers
- Aggressively extract to keep functions small

### 7. Input Validation

**Always validate inputs**:
- `assert()` for programming errors (NULL, invalid params)
- Check system call return values
- Validate buffer sizes before operations
- Use validation macros (`SOCKET_VALID_PORT`)

### 8. Thread Safety

**For thread-safe functions**:
- Mutex protection for shared resources
- Thread-local storage for per-thread data (`__thread`, `__declspec(thread)`)
- Document thread safety
- Follow existing mutex patterns

## Module Patterns

### Socket Module
- Prefix: `Socket_*`
- Exception: `Socket_Failed`, `Socket_Closed`
- Error buffer: `socket_error_buf`
- Macro: `RAISE_SOCKET_ERROR`

### Arena Module
- Prefix: `Arena_*`
- Uses `malloc` for arena structure
- Thread-safe with per-arena mutex
- Free chunk cache for reuse

### SocketPoll Module
- Prefix: `SocketPoll_*`
- Exception: `SocketPoll_Failed`
- Platform backends (epoll, kqueue, poll)
- Event translation functions

### SocketPool Module
- Prefix: `SocketPool_*`
- Uses Arena for connection structures
- Hash table for O(1) lookups
- Thread-safe with mutex

### SocketDNS Module
- Prefix: `SocketDNS_*`
- Async DNS resolution
- Thread pool for workers
- Request queue with condition variables

## Implementation Process

1. **Analyze signature** - Understand return type, parameters, purpose
2. **Identify module** - Determine which module
3. **Study similar functions** - Find similar in codebase
4. **Plan implementation** - Break into steps, identify helpers
5. **Implement small** - Each helper <20 lines, main <20 lines
6. **Add documentation** - Complete Doxygen comments
7. **Add error handling** - Use `TRY/EXCEPT/FINALLY`
8. **Use Arena allocation** - For related objects
9. **Test** - Verify functionality and error handling

## Example Implementation

**Function: `Socket_settimeout`**

Analysis:
- Module: Socket
- Purpose: Set socket timeout
- Parameters: Socket, timeout in seconds
- Error: Raises `Socket_Failed` on error

Implementation:
```c
/**
 * Socket_settimeout - Set socket receive/send timeout
 * @socket: Socket instance
 * @timeout_sec: Timeout in seconds (0 to disable)
 *
 * Sets both receive and send timeouts. Timeout of 0 disables
 * (waits indefinitely).
 *
 * Raises: Socket_Failed on setsockopt failure
 * Thread-safe: Yes (socket operations thread-safe)
 */
void
Socket_settimeout(T socket, int timeout_sec)
{
    struct timeval tv;

    assert(socket);
    assert(timeout_sec >= 0);

    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    if (setsockopt(Socket_fd(socket), SOL_SOCKET, SO_RCVTIMEO,
                   &tv, sizeof(tv)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to set receive timeout");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }

    if (setsockopt(Socket_fd(socket), SOL_SOCKET, SO_SNDTIMEO,
                   &tv, sizeof(tv)) < 0)
    {
        SOCKET_ERROR_FMT("Failed to set send timeout");
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
}
```

## Key Rules

1. **Never exceed 20 lines per function** - Extract helpers
2. **Always use exceptions for errors** - Never return codes
3. **Use Arena for related objects** - Prefer `ALLOC` over `malloc`
4. **Document everything** - Complete Doxygen comments
5. **Follow module patterns** - Match existing style exactly
6. **Validate inputs** - Use `assert()` and validation macros
7. **Thread-safe by default** - Document guarantees
8. **Single responsibility** - Each function does ONE thing

Provide implementations that seamlessly integrate with existing codebase following all C Interfaces and Implementations patterns.
