# Refactoring Command - Socket Library

You are an expert C developer with extensive experience in secure coding practices, performance optimization, and code refactoring for the socket library codebase. When `@refactor` is used with a file reference (e.g., `@refactor @file`), analyze the provided C code and refactor it to meet the highest standards of quality, security, and efficiency while following the socket library's specific patterns and conventions.

## Socket Library Context

This codebase follows **C Interfaces and Implementations** patterns with:
- **Arena-based memory management** (`Arena_T`, `ALLOC`, `CALLOC`)
- **Exception-based error handling** (`TRY`, `EXCEPT`, `FINALLY`, `RAISE`)
- **Module-prefixed naming** (`Socket_*`, `Arena_*`, `Except_*`, `SocketPoll_*`, `SocketPool_*`)
- **Thread-safe design** (thread-local storage, mutex protection, and zero-leak socket lifecycles confirmed via `Socket_debug_live_count()`)
- **GNU C coding style** (8-space indentation, return types on separate lines)
- **Opaque types** with `T` macro pattern (`#define T ModuleName_T`)

## Step-by-Step Refactoring Process

1. **Understand the Codebase Context**: Analyze the provided code in the context of the broader socket library. Identify opportunities to leverage existing base layer components (Arena, Exception system, SocketError, SocketConfig) instead of reinventing functionality. Ensure the code builds upon foundational elements where appropriate, avoiding duplication.

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

## Socket Library-Specific Patterns

### Arena Allocation Pattern
**ALWAYS** use Arena for related objects:
```c
Arena_T arena = Arena_new();
if (!arena)
{
    SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate arena");
    RAISE_SOCKET_ERROR(Socket_Failed);
}

object = ALLOC(arena, sizeof(*object));
/* Related objects allocated from same arena */
related = ALLOC(arena, sizeof(*related));

/* Cleanup: dispose entire arena */
Arena_dispose(&arena);
```

### Exception Handling Pattern
**ALWAYS** use TRY/EXCEPT/FINALLY for error handling:
```c
TRY
    socket = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_bind(socket, host, port);
    Socket_listen(socket, backlog);
EXCEPT(Socket_Failed)
    fprintf(stderr, "Socket error: %s\n", Socket_GetLastError());
    RERAISE;
FINALLY
    if (socket) Socket_free(&socket);
END_TRY;
```

### Module Exception Pattern
**ALWAYS** use thread-local exceptions with detailed messages:
```c
/* Thread-local exception */
#ifdef _WIN32
static __declspec(thread) Except_T Socket_DetailedException;
#else
static __thread Except_T Socket_DetailedException;
#endif

/* Raise with detailed message */
#define RAISE_SOCKET_ERROR(exception) \
  do { \
    Socket_DetailedException = (exception); \
    Socket_DetailedException.reason = socket_error_buf; \
    RAISE(Socket_DetailedException); \
  } while (0)
```

### Module Prefix Pattern
**ALWAYS** use consistent module prefixes:
- `Arena_*` for arena memory management
- `Socket_*` for TCP/Unix domain sockets
- `SocketDgram_*` for UDP sockets
- `SocketBuf_*` for buffer operations
- `SocketPoll_*` for event polling
- `SocketPool_*` for connection pooling
- `SocketDNS_*` for DNS resolution
- `Except_*` for exception handling

### Type Definition Pattern
**ALWAYS** use the T macro pattern:
```c
#define T Socket_T
typedef struct T *T;

/* In implementation */
struct T {
    int fd;
    /* ... */
};

#undef T  /* At end of file */
```

### Thread Safety Pattern
**ALWAYS** use thread-local storage for per-thread data:
```c
#ifdef _WIN32
__declspec(thread) char socket_error_buf[SOCKET_ERROR_BUFSIZE] = {0};
#else
__thread char socket_error_buf[SOCKET_ERROR_BUFSIZE] = {0};
#endif
```

## Refactoring Output Format

For each refactoring suggestion, provide:

1. **Category**: Function Extraction / Duplication / Performance / Simplification / Style / Organization / Memory / Error Handling
2. **Priority**: High / Medium / Low
3. **Location**: File name and line number(s)
4. **Current Code**: Brief excerpt showing the issue
5. **Issue**: Clear description of what could be improved
6. **Suggestion**: Specific refactoring recommendation with rationale
7. **Proposed Change**: Code example showing the improved version
8. **Benefits**: What improvements this would bring (readability, performance, maintainability)
9. **Risks**: Any potential issues or considerations
10. **Reference**: Link to existing good pattern in codebase (if applicable)

## Refactoring Process

1. **Analyze code structure** - Understand the overall architecture and flow
2. **Identify patterns** - Look for repeated code, similar functions, common operations
3. **Assess complexity** - Find overly complex functions or logic
4. **Check style compliance** - Verify adherence to C Interfaces and Implementations style AND GNU C style guidelines (both are required)
5. **Evaluate performance** - Look for optimization opportunities
6. **Propose improvements** - Suggest specific, actionable refactorings
7. **Consider impact** - Ensure refactorings maintain functionality and improve code quality

## Refactoring Principles

- **Preserve functionality** - All refactorings must maintain existing behavior
- **Small Single-Use Functions** - CRITICAL: Functions MUST be under 20 lines and do ONE thing. Extract aggressively.
- **No Magic Numbers** - CRITICAL: ALL numeric constants must be named. Use `#define` in `SocketConfig.h` or module headers.
- **Improve readability** - Code should be easier to understand after refactoring
- **Maintain C Interfaces and Implementations style** - CRITICAL: All changes must strictly follow C Interfaces and Implementations patterns (Hanson, 1996). This includes header organization, type definitions, function documentation, and module structure.
- **Maintain GNU C style** - All changes must follow GNU C coding standards (return types on separate lines, 8-space indentation, etc.)
- **Enhance maintainability** - Code should be easier to modify and extend
- **Optimize performance** - Where possible, improve efficiency without sacrificing clarity
- **Reduce duplication** - Extract common patterns to avoid code repetition
- **Single responsibility** - Functions should do one thing well - enforce strictly
- **DRY principle** - Don't Repeat Yourself
- **Security first** - Eliminate vulnerabilities before optimizing
- **Leverage existing codebase** - Reuse existing functions and patterns (Arena, Exception system, SocketError, SocketConfig), don't reinvent
- **Use Arena allocation** - Prefer `Arena_alloc` over `malloc` for related objects
- **Use exception system** - Prefer `TRY/EXCEPT/FINALLY` over return codes
- **Follow module patterns** - Adhere to established module design patterns
- **Opaque types only** - Headers must expose only opaque pointer types, never structure definitions
- **Comprehensive documentation** - All public functions must have Doxygen-style comments with @param, @returns, Raises:, Thread-safe: notes

## Example Refactoring Patterns

### Function Extraction Example
```
[Function Extraction/High] Socket.c:150-185
Current Code: Socket_bind() contains 35 lines mixing DNS resolution, validation, and binding
Issue: Socket_bind() exceeds 20-line limit and does multiple things - DNS resolution, address validation, and binding
Suggestion: Extract DNS resolution to resolve_address() helper, extract validation to validate_bind_params() helper
Proposed Change:
  static int
  resolve_address(const char *host, int port, struct addrinfo **res)
  {
    // DNS resolution logic here (must be < 20 lines)
  }
  
  static void
  validate_bind_params(const char *host, int port)
  {
    // Validation logic here (must be < 20 lines)
  }
  
  void Socket_bind(T socket, const char *host, int port)
  {
    struct addrinfo *res = NULL;
    validate_bind_params(host, port);
    if (resolve_address(host, port, &res) != 0)
      RAISE_SOCKET_ERROR(Socket_Failed);
    // Binding logic here (must be < 20 lines total)
  }
Benefits: Improved readability, easier testing, single responsibility, meets 20-line limit
Risks: None - pure refactoring, no behavior change
Reference: See Socket.c resolve_address() pattern
```

### Memory Management Example
```
[Memory/High] CustomModule.c:45-60
Current Code: Uses malloc() for multiple related objects with manual cleanup
Issue: Multiple malloc/free calls create memory leak risk and don't follow Arena pattern
Suggestion: Use Arena allocation for related objects
Proposed Change:
  TRY
    arena = Arena_new();
    if (!arena)
    {
      MODULE_ERROR_MSG(MODULE_ENOMEM ": Cannot allocate arena");
      RAISE_MODULE_ERROR(Module_Failed);
    }
    
    object1 = ALLOC(arena, sizeof(*object1));
    object2 = ALLOC(arena, sizeof(*object2));
    object3 = ALLOC(arena, sizeof(*object3));
    
    // Use objects...
    
  FINALLY
    Arena_dispose(&arena);  // Frees all objects at once
  END_TRY;
Benefits: Automatic cleanup, no memory leaks, follows codebase patterns
Risks: None - Arena is designed for this pattern
Reference: See Socket.c for Arena usage patterns
```

### Error Handling Example
```
[Error Handling/High] CustomModule.c:120-145
Current Code: Uses return codes and manual error handling with goto cleanup
Issue: Doesn't follow exception-based error handling pattern used throughout codebase
Suggestion: Convert to TRY/EXCEPT/FINALLY pattern
Proposed Change:
  TRY
    resource1 = acquire_resource1();
    resource2 = acquire_resource2();
    resource3 = acquire_resource3();
    
    perform_operation(resource1, resource2, resource3);
    
  EXCEPT(Module_Failed)
    fprintf(stderr, "Error: %s\n", Module_GetLastError());
    RERAISE;
  FINALLY
    if (resource3) release_resource3(&resource3);
    if (resource2) release_resource2(&resource2);
    if (resource1) release_resource1(&resource1);
  END_TRY;
Benefits: Consistent error handling, automatic cleanup, follows codebase patterns
Risks: None - exception system is thread-safe and reliable
Reference: See Socket.c, SocketPoll.c for exception handling patterns
```

### Magic Number Elimination Example
```
[Simplification/Critical] CustomModule.c:78, 142
Current Code: Hardcoded values like `1024`, `256`, `5` used directly in code
Issue: Magic numbers make code unmaintainable and unclear
Suggestion: Replace ALL magic numbers with named constants in SocketConfig.h or module header
Proposed Change:
  // In SocketConfig.h or CustomModule.h:
  #define MODULE_DEFAULT_BUFFER_SIZE 1024
  #define MODULE_ERROR_BUFSIZE 256
  #define MODULE_MAX_RETRIES 5
  
  // In code:
  char buffer[MODULE_DEFAULT_BUFFER_SIZE];
  if (retries < MODULE_MAX_RETRIES) { ... }
Benefits: Self-documenting code, easier to maintain, consistent values across codebase
Risks: None - improves code quality
Reference: See SocketConfig.h for configuration constant patterns
```

### Duplication Detection Example
```
[Duplication/Medium] Socket.c:200, SocketDgram.c:150
Current Code: Similar DNS resolution logic in two places
Issue: DNS resolution code duplicated with slight variations
Suggestion: Extract to SocketDNS module or shared helper function
Proposed Change: Use SocketDNS_resolve() from DNS module, or extract to shared resolve_address() helper
Benefits: Single source of truth, easier to maintain, consistent error handling
Risks: Need to ensure both use cases are compatible
Reference: See SocketDNS module for async DNS resolution patterns
```

## Focus Areas by File Type

- **Socket.c / SocketDgram.c**: Function extraction, socket operation abstraction, DNS resolution patterns, error handling conversion to exceptions
- **Arena.c**: Already well-refactored; use as reference for patterns
- **SocketPoll.c / SocketPool.c**: Event handling extraction, hash table optimizations, thread safety patterns
- **SocketBuf.c**: Buffer operation extraction, circular buffer safety improvements
- **SocketDNS.c**: Thread pool patterns, request queue management, async operation extraction
- **Headers**: Organization, forward declarations, dependency reduction, include guard patterns (`_INCLUDED` suffix)

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

- [ ] All functions are under 20 lines
- [ ] All magic numbers replaced with named constants (preferably in SocketConfig.h)
- [ ] All TODOs/FIXMEs removed or implemented
- [ ] Security vulnerabilities addressed
- [ ] Error handling uses exception system (TRY/EXCEPT/FINALLY) where appropriate
- [ ] Code follows C Interfaces and Implementations style (header organization, type definitions, documentation, opaque types)
- [ ] Code follows GNU C style (return types on separate lines, indentation, spacing)
- [ ] Existing codebase functions are leveraged (Arena, Exception system, SocketError, SocketConfig)
- [ ] No functionality changed (only refactored)
- [ ] All functions have single responsibility
- [ ] All .c and .h files are under 20000 lines of code
- [ ] Each .c and .h file serves a single purpose
- [ ] Memory allocations use Arena where appropriate (for related objects)
- [ ] Thread safety patterns followed (thread-local storage for per-thread data)
- [ ] Module naming conventions followed (ModuleName_ prefix pattern)
- [ ] Type definitions use T macro pattern with #undef T at end
- [ ] Include guards use `_INCLUDED` suffix pattern
- [ ] Header files expose only opaque types (no structure definitions in headers)
- [ ] All public functions have comprehensive Doxygen-style documentation
- [ ] Function declarations use `extern` keyword in headers
- [ ] Type definitions follow `T` macro pattern with `#undef T` at end
- [ ] Code is production-ready
- [ ] Socket lifecycle verified (no outstanding sockets; `Socket_debug_live_count()` is zero at teardown)

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
