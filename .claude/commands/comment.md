# Comment Documentation Helper - Socket Library

Generate and update documentation for C code following production-quality Doxygen standards used by major libraries (libevent, c-ares, OpenSSL).

## Production Documentation Template

### Complete Function Documentation

**ALWAYS** generate documentation in this format:

```c
/**
 * @brief One-sentence description of what function does.
 * @ingroup module_group
 *
 * Detailed explanation of behavior, purpose, and important implementation
 * notes. Include information about edge cases, error conditions, and
 * typical usage patterns.
 *
 * @param[in] input_param Description of input parameter
 * @param[out] output_param Description of output parameter (populated by function)
 * @param[in,out] modify_param Description of parameter modified in place
 *
 * @return Description of return value and error conditions
 *
 * @throws ExceptionType Description of when/why exception is raised
 *
 * @threadsafe Yes/No - detailed explanation of thread safety guarantees
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Basic usage pattern
 * Type_T obj = Type_new(param1, param2);
 * if (obj) {
 *     Type_operation(obj, data);
 *     Type_free(&obj);
 * }
 * @endcode
 *
 * @note Important implementation notes or caveats
 *
 * @warning Critical warnings about misuse or security implications
 *
 * @complexity O(1) / O(n) - performance characteristics
 *
 * @see RelatedFunction() for related functionality
 * @see docs/FEATURE.md for detailed guide
 */
```

## Required Elements

### 1. Parameter Direction Tags (MANDATORY)

| Tag | Use For | Example |
|-----|---------|---------|
| `@param[in]` | Input only | `@param[in] config Configuration to apply` |
| `@param[out]` | Output only | `@param[out] result Populated with result` |
| `@param[in,out]` | Modified | `@param[in,out] buffer Modified in place` |

### 2. Code Examples (MANDATORY for non-trivial functions)

```c
/**
 * ## Basic Usage
 *
 * @code{.c}
 * Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
 * Socket_connect(sock, "example.com", 80);
 * Socket_send(sock, "GET / HTTP/1.0\r\n\r\n", 18);
 * Socket_free(&sock);
 * @endcode
 *
 * ## With Error Handling
 *
 * @code{.c}
 * TRY {
 *     Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
 *     Socket_connect(sock, host, port);
 *     // ... use socket ...
 * } EXCEPT(Socket_Failed) {
 *     fprintf(stderr, "Error: %s\n", Socket_GetLastError());
 * } FINALLY {
 *     Socket_free(&sock);
 * } END_TRY;
 * @endcode
 */
```

### 3. Tables for Configuration/Return Values

```c
/**
 * ## Default Values
 *
 * | Setting | Default | Description |
 * |---------|---------|-------------|
 * | timeout_ms | 30000 | Connection timeout |
 * | max_retries | 3 | Maximum retry attempts |
 * | buffer_size | 4096 | Default buffer size |
 *
 * ## Return Codes
 *
 * | Value | Meaning |
 * |-------|---------|
 * | 1 | Success |
 * | 0 | Failure |
 * | -1 | Invalid parameter |
 */
```

### 4. Thread Safety Documentation

```c
/**
 * @threadsafe Yes - internal mutex protects all shared state
 *
 * @threadsafe No - caller must synchronize access
 *
 * @threadsafe Partial - reads safe, writes need sync
 */
```

### 5. Complexity Annotations

```c
/**
 * @complexity O(1) average case - hash table lookup
 * @complexity O(n) worst case - collision chain traversal
 */
```

### 6. Exception Documentation

```c
/**
 * @throws Socket_Failed System call failed (check errno)
 * @throws Socket_Closed Connection terminated by peer
 * @throws Socket_Timeout Operation timed out
 */
```

## Module Groups

Assign to appropriate group with `@ingroup`:

| Group ID | Description | Example Modules |
|----------|-------------|-----------------|
| `foundation` | Base infrastructure | Arena, Except, SocketUtil |
| `core_io` | Socket primitives | Socket, SocketBuf, SocketDNS |
| `event_system` | I/O multiplexing | SocketPoll, SocketTimer |
| `connection_mgmt` | Connection lifecycle | SocketPool, SocketReconnect |
| `security` | TLS & protection | SocketTLS, SocketSYNProtect |
| `http` | HTTP protocols | SocketHTTP, SocketHTTPClient |
| `async_io` | Advanced I/O | SocketAsync, SocketHappyEyeballs |
| `utilities` | Helper modules | SocketRateLimit, SocketRetry |

## File Documentation Template

```c
/**
 * @defgroup module_group Module Group Name
 * @brief Brief description of the module group.
 *
 * ## Architecture Overview
 *
 * ```
 * ┌────────────────────────────────────┐
 * │         Application Layer          │
 * └────────────────┬───────────────────┘
 *                  │ Uses
 * ┌────────────────▼───────────────────┐
 * │          This Module               │
 * └────────────────┬───────────────────┘
 *                  │ Uses
 * ┌────────────────▼───────────────────┐
 * │        Foundation Layer            │
 * └────────────────────────────────────┘
 * ```
 *
 * ## Module Relationships
 *
 * - **Depends on**: List dependencies
 * - **Used by**: List consumers
 *
 * @see @ref other_module for related functionality
 * @{
 */

/**
 * @file ModuleName.h
 * @ingroup module_group
 * @brief One-line file description.
 *
 * Detailed description of the file's purpose, contents,
 * and typical usage patterns.
 *
 * ## Features
 *
 * - Feature 1
 * - Feature 2
 *
 * ## Platform Requirements
 *
 * - POSIX-compliant system
 * - Thread support (pthreads)
 *
 * @see ModuleName_new() for initialization
 * @see docs/MODULE.md for detailed guide
 */
```

## Type Documentation Template

```c
/**
 * @brief Brief description of the type.
 * @ingroup module_group
 *
 * Detailed description including:
 * - What the type represents
 * - Lifecycle management
 * - Thread safety characteristics
 * - Related types and functions
 *
 * @note Important notes about usage
 *
 * @see Type_new() for creation
 * @see Type_free() for cleanup
 */
typedef struct Type_T *Type_T;
```

## Enum Documentation Template

```c
/**
 * @brief Description of what the enum represents.
 * @ingroup module_group
 *
 * Detailed explanation of enum usage and values.
 *
 * @see FunctionUsingEnum() for usage
 */
typedef enum EnumName {
    ENUM_VALUE_ONE = 0,  /**< Description of value one */
    ENUM_VALUE_TWO,      /**< Description of value two */
    ENUM_VALUE_THREE     /**< Description of value three */
} EnumName;
```

## Struct Documentation Template

```c
/**
 * @brief Description of the structure.
 * @ingroup module_group
 *
 * Detailed description of structure purpose and usage.
 *
 * @note Thread safety notes
 */
typedef struct StructName {
    int field1;      /**< Description of field1 */
    char *field2;    /**< Description of field2 */
    size_t field3;   /**< Description of field3 */
} StructName;
```

## Structured Sections

Use markdown headers for complex documentation:

```c
/**
 * @brief Complex function with multiple aspects.
 *
 * ## Overview
 *
 * High-level description of what the function does.
 *
 * ## What Gets Processed
 *
 * - Item 1
 * - Item 2
 * - Item 3
 *
 * ## What Is Preserved
 *
 * - Preserved item 1
 * - Preserved item 2
 *
 * ## Integration Patterns
 *
 * ### Pattern 1: Event Loop
 *
 * @code{.c}
 * // Event loop integration
 * @endcode
 *
 * ### Pattern 2: Manual Loop
 *
 * @code{.c}
 * // Manual loop integration
 * @endcode
 *
 * ## Performance Considerations
 *
 * - Note about performance 1
 * - Note about performance 2
 */
```

## Documentation Quality Checklist

Before finalizing documentation:

- [ ] Brief tag present and concise (<80 chars)
- [ ] All parameters have direction tags (`[in]`, `[out]`, `[in,out]`)
- [ ] Return value documented
- [ ] All exceptions documented with `@throws`
- [ ] Thread safety explicitly stated
- [ ] Code examples for non-trivial functions
- [ ] Complexity noted where relevant
- [ ] Cross-references with `@see` tags
- [ ] Assigned to correct `@ingroup`
- [ ] No typos or grammatical errors

## Generation Process

1. **Analyze** the function signature and implementation
2. **Identify** the module group and related functions
3. **Determine** thread safety and complexity
4. **Write** brief description (what it does, not how)
5. **Document** all parameters with direction tags
6. **Add** return value and exception documentation
7. **Create** practical code examples
8. **Add** notes, warnings, and cross-references
9. **Verify** against quality checklist

## Example: Before and After

### Before (Minimal Documentation)

```c
/**
 * Socket_new - Create a new socket
 * @domain: Socket domain
 * @type: Socket type
 * @protocol: Protocol
 */
extern Socket_T Socket_new(int domain, int type, int protocol);
```

### After (Production Quality)

```c
/**
 * @brief Create a new socket with specified domain, type, and protocol.
 * @ingroup core_io
 *
 * Creates and initializes a new socket instance. The socket is created in
 * blocking mode by default. SIGPIPE is automatically handled internally.
 *
 * @param[in] domain Address family (AF_INET, AF_INET6, AF_UNIX)
 * @param[in] type Socket type (SOCK_STREAM, SOCK_DGRAM)
 * @param[in] protocol Protocol (usually 0 for default)
 *
 * @return New socket instance
 *
 * @throws Socket_Failed on system call failure (EACCES, EMFILE, ENFILE, ENOMEM)
 *
 * @threadsafe Yes - creates independent instance safe from any thread
 *
 * ## Basic Usage
 *
 * @code{.c}
 * // Create TCP socket
 * Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
 * Socket_connect(sock, "example.com", 80);
 * // ... use socket ...
 * Socket_free(&sock);
 * @endcode
 *
 * ## IPv6 with Error Handling
 *
 * @code{.c}
 * TRY {
 *     Socket_T sock = Socket_new(AF_INET6, SOCK_STREAM, 0);
 *     Socket_setnodelay(sock, 1);
 *     Socket_connect(sock, "::1", 8080);
 * } EXCEPT(Socket_Failed) {
 *     fprintf(stderr, "Socket error: %s\n", Socket_GetLastError());
 * } END_TRY;
 * @endcode
 *
 * @note Socket is blocking by default; use Socket_setnonblocking() for async I/O
 *
 * @complexity O(1) - single system call
 *
 * @see Socket_free() for cleanup
 * @see Socket_connect() for establishing connections
 * @see Socket_setnonblocking() for non-blocking mode
 * @see SocketDgram_new() for UDP sockets
 */
extern Socket_T Socket_new(int domain, int type, int protocol);
```

This command helps maintain consistent, production-quality documentation across the entire socket library codebase.
