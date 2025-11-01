# Documentation Generator - Socket Library

Auto-generate and update Doxygen-style comments throughout the socket library codebase following C Interfaces and Implementations patterns:

## 1. Scan Functions Missing Documentation

Analyze all `.c` and `.h` files to identify:
- Functions without Doxygen-style comments
- Functions with incomplete documentation (missing `@param`, `Returns:`, `Raises:`, `Thread-safe:`)
- Functions with outdated documentation that doesn't match signatures
- Static functions that need documentation
- Forward declarations that should have documentation
- Module-level documentation missing or incomplete

## 2. Generate Function Headers with Complete Documentation

For each undocumented or incompletely documented function:
- Parse function signature to extract:
  - Function name
  - Return type
  - Parameter names and types
  - Const qualifiers
  - Pointer types
- Generate Doxygen-style comments following the socket library format:
```
/**
 * FunctionName - Brief description of what the function does
 * @param1: Description of parameter 1
 * @param2: Description of parameter 2
 *
 * Returns: Description of return value, or NULL on failure
 * Raises: Description of exceptions that may be raised (if applicable)
 * Thread-safe: Yes/No with explanation
 *
 * Optional longer description explaining the function's purpose,
 * behavior, side effects, error handling, or other important details.
 * Include usage examples for complex functions.
 */
```
- Infer parameter descriptions from:
  - Variable names (e.g., `arena` -> "Arena instance to allocate from")
  - Parameter types (e.g., `Arena_T` -> "Arena instance")
  - Function name context
  - Similar documented functions in the codebase
- Generate return descriptions based on:
  - Return type (e.g., `void *` -> "Pointer to allocated memory, or NULL on failure")
  - Function name patterns
  - Common return patterns (NULL on error, pointer on success, etc.)
- **Socket Library Specific**:
  - Always include `Thread-safe:` note for functions that use mutexes or thread-local storage
  - Always include `Raises:` for functions that may raise exceptions
  - Use module exception names (e.g., `Socket_Failed`, `SocketPoll_Failed`)

## 3. Update File Headers with Proper Format

For each file missing or with incomplete header comments:
- Generate header comments matching the socket library format:
```
/**
 * ModuleName.c - Module implementation description
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 */
```
- For header files:
```
/**
 * ModuleName.h - Module interface description
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 */
```
- Analyze file contents to generate meaningful descriptions:
  - List major functions and their purposes
  - Describe key data structures (in implementation files only - headers use opaque types)
  - Explain relationships between components
  - Note important patterns or conventions (e.g., thread safety, memory management)
  - Include usage examples for complex modules

## 4. Module-Level Documentation

For each module, ensure comprehensive module documentation in header files:
```
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
 * Thread Safety:
 * - Description of thread safety guarantees
 *
 * Usage example:
 *   ModuleName_T instance = ModuleName_new();
 *   ModuleName_operation(instance);
 *   ModuleName_free(&instance);
 */
```

## 5. Ensure Consistency with Existing Documentation Style

Maintain consistency by:
- Using the same Doxygen-style format as existing comments:
  - `FunctionName - Brief description` (no parentheses for function name)
  - `@param:` for parameters (with colon)
  - `Returns:` for return values (not `@return`)
  - `Raises:` for exceptions
  - `Thread-safe:` for thread safety notes
  - Multi-line descriptions where appropriate
- Following existing patterns:
  - Parameter descriptions start with capital letter
  - Return descriptions mention NULL on error when applicable
  - Longer descriptions explain behavior, not just what parameters are
  - Use "Pointer to" for pointer parameters
  - Use "Instance" for opaque types (e.g., "Arena instance")
- Preserving existing documentation when:
  - It's already complete and accurate
  - It contains important implementation details
  - It follows the established style
- Updating only when:
  - Documentation is missing
  - Documentation is incomplete (missing @param/Returns:/Raises:/Thread-safe:)
  - Function signature changed but documentation didn't
  - Documentation format doesn't match style

## 6. Struct and Enum Documentation

Document structs and enums following socket library patterns:
- **Struct documentation** (in implementation files only - headers use opaque types):
```
/**
 * struct StructName - Brief description
 * @member1: Description of member 1
 * @member2: Description of member 2
 *
 * Detailed description of structure purpose and usage.
 */
```
- **Enum documentation**:
```
/**
 * enum EnumName - Brief description
 * @VALUE1: Description of value 1
 * @VALUE2: Description of value 2
 *
 * Detailed description of enum purpose.
 */
```

## 7. Type Definition Documentation

For opaque types in headers:
```
#define T ModuleName_T
typedef struct T *T;  /* Opaque pointer type */
```
- No structure member documentation in headers (opaque types)
- Implementation files contain full structure documentation

## Implementation Guidelines

1. **Preserve User Intent**: Never remove or substantially change existing documentation without clear indication it's incorrect
2. **C Interfaces and Implementations Style Awareness**: Understand C Interfaces and Implementations patterns:
   - Opaque types in headers, structures in implementation files
   - Module-prefixed function naming
   - Exception-based error handling
   - Arena-based memory management
3. **Socket Library Patterns**: Recognize socket library patterns:
   - Exception handling (`TRY/EXCEPT/FINALLY`, `RAISE`)
   - Thread safety notes (mutex protection, thread-local storage)
   - Arena allocation patterns (`ALLOC`, `CALLOC`)
   - Module exception patterns (`RAISE_MODULE_ERROR`)
4. **Context Awareness**: Use function implementations and call sites to infer better descriptions
5. **Incremental Updates**: Allow updating individual files or functions rather than entire codebase
6. **Validation**: Verify generated documentation:
   - Matches function signatures
   - Uses correct parameter names
   - Follows Doxygen syntax
   - Maintains consistent style
   - Includes all required sections (`@param`, `Returns:`, `Raises:`, `Thread-safe:`)

## Socket Library-Specific Documentation Requirements

### Required Documentation Sections
- **Function Documentation**: Must include:
  - Brief description line
  - `@param` for each parameter
  - `Returns:` description
  - `Raises:` if function raises exceptions (required for functions using `RAISE`)
  - `Thread-safe:` note (required for functions with mutex protection or thread-local storage)
  - Optional detailed description

### Module Documentation Requirements
- Header files must have module-level documentation at top
- Include Features list
- Include Thread Safety section
- Include Usage example

### Type Documentation
- Opaque types: Only type name in headers
- Structures: Full member documentation in implementation files
- Constants: Document purpose and usage

## Documentation Examples

### Public Function Example
```c
/**
 * Socket_new - Create a new socket
 * @domain: Socket domain (AF_INET, AF_INET6, AF_UNIX)
 * @type: Socket type (SOCK_STREAM, SOCK_DGRAM)
 * @protocol: Protocol (0 for default)
 *
 * Returns: New socket instance, or NULL on failure
 * Raises: Socket_Failed on socket creation failure
 * Thread-safe: Yes (creates per-socket mutex)
 *
 * Creates a new socket with the specified domain, type, and protocol.
 * The socket is initialized with default options and allocated from
 * an internal arena. Call Socket_free() to dispose of the socket.
 */
extern Socket_T Socket_new(int domain, int type, int protocol);
```

### Static Helper Function Example
```c
/**
 * resolve_address - Resolve hostname/port to addrinfo structure
 * @host: Hostname or IP address (NULL for wildcard)
 * @port: Port number (1-65535)
 * @res: Output pointer to resolved addrinfo
 *
 * Returns: 0 on success, -1 on failure (sets errno)
 *
 * Internal helper function that resolves a hostname or IP address
 * to an addrinfo structure. Handles both IPv4 and IPv6 addresses.
 * Caller must free addrinfo using freeaddrinfo().
 */
static int resolve_address(const char *host, int port, struct addrinfo **res)
```

### Module Header Example
```c
/**
 * Socket - TCP and Unix Domain Socket Operations
 *
 * Provides high-level socket operations for TCP and Unix domain sockets.
 * Supports both IPv4 and IPv6, DNS resolution, and various socket options.
 *
 * Features:
 * - TCP and Unix domain socket support
 * - Unix domain sockets
 * - DNS resolution with caching
 * - Configurable socket options
 *
 * Thread Safety:
 * - Individual socket operations are thread-safe
 * - Multiple threads can use different sockets concurrently
 * - DNS resolution uses thread-safe async resolver
 *
 * Usage example:
 *   Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
 *   Socket_bind(sock, "localhost", 8080);
 *   Socket_listen(sock, 128);
 *   Socket_free(&sock);
 */
```

Generate documentation that is:
- Accurate and matches function signatures
- Consistent with C Interfaces and Implementations style
- Comprehensive but concise
- Helpful for understanding code purpose and usage
- Includes all required sections for socket library functions
- Follows socket library-specific patterns and conventions
