# Generate Cursor Rules - Socket Library

Analyze the entire socket library codebase and generate a comprehensive `.cursorrules` file in the project root that enforces best practices based on:

1. **Code Style**: C Interfaces and Implementations style with GNU C style
   - 8-space indentation
   - 80 column limit
   - Function return types on separate lines
   - Brace placement per GNU style
   - Pointer alignment: Right (`type *ptr` not `type* ptr`)

2. **Documentation Standards**: Doxygen-style comments
   - Every file must have module header comment
   - Every function must have Doxygen-style comments with `@param`, `Returns:`, `Raises:`, `Thread-safe:`
   - Struct members documented with `@member` syntax (in implementation files)
   - Module-level documentation in headers with Features, Thread Safety, Usage examples

3. **Error Handling**: Exception-based error handling patterns
   - Functions use `TRY/EXCEPT/FINALLY/END_TRY` blocks
   - Use module-specific exceptions (`Socket_Failed`, `SocketPoll_Failed`, etc.)
   - Use thread-local error buffers (`socket_error_buf`, `MODULE_ERROR_FMT`)
   - Always use `RAISE_MODULE_ERROR` for detailed error messages
   - Never use return codes for errors

4. **Memory Management**: Arena-based allocation patterns
   - Always use Arena allocation (`ALLOC`, `CALLOC`) for related objects
   - Only use `malloc` for Arena structure itself or standalone allocations
   - Dispose entire Arena at once with `Arena_dispose(&arena)`
   - Cleanup in `FINALLY` blocks (reverse order of allocation)

5. **Header Organization**:
   - Always use include guards (`#ifndef FILENAME_INCLUDED / #define FILENAME_INCLUDED`)
   - Include system headers first, then project headers
   - Opaque types only in headers (no structure definitions)
   - Forward declarations before struct definitions (in implementation files)
   - `#undef T` at end of files

6. **Naming Conventions**:
   - Functions: Module-prefixed (`Socket_*`, `Arena_*`, `SocketPoll_*`, etc.)
   - Types: Opaque types with `T` macro (`#define T ModuleName_T`)
   - Static functions: No module prefix, descriptive names
   - Constants: ALL_CAPS in `SocketConfig.h` or module headers
   - Macros: ALL_CAPS with module prefix

7. **Code Organization**:
   - Static helper functions before public functions
   - Related functions grouped together
   - Functions must be under 20 lines (extract helpers aggressively)
   - Files must be under 400 lines (split if needed)
   - Use const pointers for parameters that shouldn't be modified
   - Cast unused parameters to void: `(void)param;`

8. **Safety Practices**:
   - Always check return values from system calls
   - Use `assert()` for programming errors (NULL pointers, invalid parameters)
   - Validate buffer sizes before operations
   - Use overflow protection before arithmetic operations
   - Use thread-local storage for per-thread data (`__thread`, `__declspec(thread)`)
   - Protect shared resources with mutexes

9. **File Structure**:
   - Header files (.h) contain declarations and documentation (opaque types)
   - Implementation files (.c) contain implementations (full structures)
   - Configuration constants in `SocketConfig.h`
   - One logical unit per file when possible
   - Module organization: core/, socket/, poll/, pool/, dns/

10. **Thread Safety**:
    - Document thread safety guarantees in function documentation
    - Use mutex protection for shared resources
    - Use thread-local storage for per-thread data
    - Follow existing thread safety patterns from codebase

Generate rules that are:

- Specific and actionable
- Include examples of both good and bad patterns
- Explain the rationale for each rule
- Reference existing code patterns from the socket library codebase
- Organized by category for maintainability
- Aligned with C Interfaces and Implementations patterns
- Enforce socket library-specific conventions

The generated `.cursorrules` file should help maintain consistency and quality across the entire socket library codebase while following C Interfaces and Implementations patterns and GNU C style standards.
