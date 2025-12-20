# Documentation Generator - Socket Library

Generate and improve Doxygen documentation for functions, types, and modules. Use when working on header files, adding new functions, or when documentation is missing.

## Usage Modes

### Scan Mode (Default)
Scan codebase to find undocumented or incomplete documentation:
- Functions without Doxygen comments
- Functions with incomplete documentation (missing `@param`, `@return`, `@throws`, `@threadsafe`)
- Functions with signatures that don't match documentation
- Module-level documentation missing or incomplete

### Improve Mode
Enhance existing documentation for specific functions or files.

## Documentation Template

Use this production-quality template for all function documentation:

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
 * Type_T obj = Type_new(param1, param2);
 * if (obj) {
 *     Type_operation(obj, data);
 *     Type_free(&obj);
 * }
 * @endcode
 *
 * @note Important implementation notes or caveats
 * @warning Critical warnings about misuse or security implications
 * @complexity O(1) / O(n) - performance characteristics
 *
 * @see RelatedFunction() for related functionality
 */
```

### Required Elements

**Parameter Direction Tags** (MANDATORY)
- `@param[in]` - Input only
- `@param[out]` - Output only (populated by function)
- `@param[in,out]` - Modified in place

**Thread Safety** (MANDATORY)
```c
@threadsafe Yes - internal mutex protects all shared state
@threadsafe No - caller must synchronize access
@threadsafe Partial - reads safe, writes need sync
```

**Exception Documentation**
```c
@throws Socket_Failed System call failed (check errno)
@throws Socket_Closed Connection terminated by peer
@throws Socket_Timeout Operation timed out
```

**Code Examples** (MANDATORY for non-trivial functions)
```c
## Basic Usage

@code{.c}
Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
Socket_connect(sock, "example.com", 80);
Socket_free(&sock);
@endcode

## With Error Handling

@code{.c}
TRY {
    Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_connect(sock, host, port);
} EXCEPT(Socket_Failed) {
    fprintf(stderr, "Error: %s\n", Socket_GetLastError());
} FINALLY {
    Socket_free(&sock);
} END_TRY;
@endcode
```

## Module Groups

Assign functions to appropriate module groups with `@ingroup`:

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

## Type Documentation

**Opaque Types**
```c
/**
 * @brief Brief description of the type.
 * @ingroup module_group
 *
 * Detailed description including:
 * - What the type represents
 * - Lifecycle management
 * - Thread safety characteristics
 *
 * @see Type_new() for creation
 * @see Type_free() for cleanup
 */
typedef struct Type_T *Type_T;
```

**Enums**
```c
/**
 * @brief Description of what the enum represents.
 * @ingroup module_group
 */
typedef enum EnumName {
    ENUM_VALUE_ONE = 0,  /**< Description of value one */
    ENUM_VALUE_TWO,      /**< Description of value two */
} EnumName;
```

**Structs** (in implementation files only)
```c
/**
 * @brief Description of the structure.
 * @ingroup module_group
 *
 * @note Thread safety notes
 */
typedef struct StructName {
    int field1;      /**< Description of field1 */
    char *field2;    /**< Description of field2 */
} StructName;
```

## Module Documentation

For header files, add module-level documentation:

```c
/**
 * @defgroup module_group Module Group Name
 * @brief Brief description of the module group.
 *
 * ## Features
 *
 * - Feature 1
 * - Feature 2
 *
 * ## Thread Safety
 *
 * Description of thread safety guarantees
 *
 * ## Platform Requirements
 *
 * - POSIX-compliant system
 * - Thread support (pthreads)
 *
 * @see ModuleName_new() for initialization
 * @{
 */

/**
 * @file ModuleName.h
 * @ingroup module_group
 * @brief One-line file description.
 */
```

## Example: Before and After

**Before** (Minimal Documentation)
```c
/**
 * Socket_new - Create a new socket
 * @domain: Socket domain
 * @type: Socket type
 * @protocol: Protocol
 */
extern Socket_T Socket_new(int domain, int type, int protocol);
```

**After** (Production Quality)
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
 * Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
 * Socket_connect(sock, "example.com", 80);
 * Socket_free(&sock);
 * @endcode
 *
 * @note Socket is blocking by default; use Socket_setnonblocking() for async I/O
 * @complexity O(1) - single system call
 *
 * @see Socket_free() for cleanup
 * @see Socket_connect() for establishing connections
 */
extern Socket_T Socket_new(int domain, int type, int protocol);
```

## Documentation Inference Guidelines

When generating documentation:

1. **Analyze** function signature, implementation, and call sites
2. **Identify** module group from file location and naming
3. **Determine** thread safety from mutex usage and thread-local storage
4. **Infer** parameter descriptions from:
   - Variable names (`arena` -> "Arena instance to allocate from")
   - Parameter types (`Arena_T` -> "Arena instance")
   - Function name context
   - Similar documented functions
5. **Generate** return descriptions based on:
   - Return type (`void *` -> "Pointer to allocated memory, or NULL on failure")
   - Function name patterns
   - Common patterns in codebase
6. **Document** exceptions by scanning for `RAISE` calls
7. **Add** code examples for non-trivial functions
8. **Cross-reference** related functions with `@see` tags

## Quality Checklist

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

## Style Reference

See `.claude/references/style-guide.md` for additional style patterns and conventions used throughout the socket library.
