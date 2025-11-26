# Static Analysis - Socket Library

Perform comprehensive static analysis on the entire C codebase of the socket library and provide actionable insights aligned with C Interfaces and Implementations patterns:

## 1. Unused Functions/Variables Detection

### Functions
- Identify all function definitions across `.c` files
- Check if each function is:
  - Called from other files (requires cross-file analysis)
  - Called within the same file
  - Declared in headers but never implemented
  - Implemented but never declared/used
- Mark functions with `static` that could be static but aren't
- Flag public functions in headers that have no callers (may be library API)
- Distinguish between intentionally unused (e.g., callback stubs) and dead code
- **Socket Library Context**: Module-prefixed functions (`Socket_*`, `Arena_*`, `SocketPoll_*`) may be public API

### Variables
- Detect unused local variables in functions
- Identify unused function parameters (cast to `(void)param` instead of UNUSED macro)
- Find unused global variables
- Check for unused static variables
- Flag variables that are assigned but never read
- Identify variables declared but never initialized before use
- **Thread-local variables**: Recognize thread-local storage patterns (`__thread`, `__declspec(thread)`)

### Output Format
- List file name, line number, and entity name
- Categorize: unused function, unused variable, unused parameter
- Suggest fixes (make static, remove, or cast to void)

## 2. Dead Code Detection

### Unreachable Code
- Find code after `return` statements
- Identify code after `goto` labels that jump past it
- Detect `if (0)` or `if (false)` blocks
- Find unreachable `break`/`continue` statements
- Identify functions that always return before end
- Check exception handlers (`EXCEPT` blocks) that are never reached

### Unused Includes
- Detect `#include` directives that are never used
- Check if headers only contain unused declarations
- Verify forward declarations that aren't needed
- **Socket Library**: Check for proper include order (system headers first, then project headers)

### Unused Macros
- Find `#define` macros that are never referenced
- Check enum values that are never used
- Identify constant definitions without references
- **Socket Library**: Check module-specific macros (`ALLOC`, `CALLOC`, `RAISE_MODULE_ERROR`)

### Conditional Compilation Dead Code
- Find `#ifdef` blocks that are always false
- Detect platform-specific code that never applies
- **Socket Library**: Check backend selection (`epoll` vs `kqueue` vs `poll`)

## 3. Complexity Analysis

### Cyclomatic Complexity
- Calculate cyclomatic complexity for each function
- **Thresholds for Socket Library**:
  - 1-10: Simple (acceptable)
  - 11-20: Moderate (consider refactoring)
  - 21-30: Complex (should refactor)
  - 31+: Very complex (must refactor)
- **CRITICAL**: Functions exceeding 20 lines indicate multiple responsibilities - flag for refactoring
- Identify complexity hotspots (functions with high complexity)
- Suggest refactoring strategies for complex functions

### Cognitive Complexity
- Analyze nested conditionals
- Count levels of indentation
- Evaluate logical operators (&&, ||) complexity
- Identify functions with multiple responsibilities
- Check exception handling blocks (`TRY/EXCEPT/FINALLY`) complexity

### Function Metrics
- Count lines of code per function
- **CRITICAL**: Flag functions exceeding 20 lines (must be broken down)
- Calculate number of parameters (suggest reduction if >5)
- Identify functions with too many local variables
- **Socket Library**: Functions should be small, single-purpose, following C Interfaces and Implementations patterns

### File-Level Metrics
- Total lines of code per file
- **CRITICAL**: Flag files exceeding 20000 lines (must be split)
- Number of functions per file
- Average complexity per file
- Identify files that may need splitting

## 4. Compiler Warning Suggestions

### Missing Warnings
- Analyze current compiler flags
- Suggest additional warnings to enable:
  - `-Wshadow` - Warn about shadowed variables
  - `-Wstrict-prototypes` - Warn about non-prototyped functions
  - `-Wmissing-prototypes` - Warn about missing function prototypes
  - `-Wconversion` - Warn about implicit conversions
  - `-Wsign-conversion` - Warn about sign conversions
  - `-Wcast-qual` - Warn about casts that discard qualifiers
  - `-Wpointer-arith` - Warn about pointer arithmetic
  - `-Wformat=2` - Enhanced format string checking
  - `-Wuninitialized` - Warn about uninitialized variables
  - `-Wstrict-overflow` - Warn about optimizations that assume overflow doesn't occur
  - `-Warray-bounds` - Warn about array bounds violations
  - `-Wmaybe-uninitialized` - Warn about possibly uninitialized variables
- **Socket Library**: Current flags include `-Wall -Wextra -Werror` - verify all warnings are enabled

### Warning Analysis
- Check if `-Werror` would catch issues (already enabled in socket library)
- Identify warnings that should be errors
- Suggest warning-specific fixes

## 5. Code Metrics

### Complexity Metrics
- **Cyclomatic Complexity**: Measure decision points
- **Halstead Complexity**: Measure program vocabulary and length
- **Maintainability Index**: Composite metric for maintainability

### Size Metrics
- Lines of code (LOC) per file
- Non-comment lines of code
- Function count per file
- Average function length
- Maximum function length
- **Critical Threshold**: 20 lines per function, 20000 lines per file

### Quality Metrics
- Comment-to-code ratio
- Function documentation coverage (% with Doxygen-style comments)
- Error handling coverage (% functions with exception handling)
- **Memory safety**: Count of Arena allocation (`ALLOC`/`CALLOC`) vs raw malloc usage
- Const correctness: identify functions that could use `const` parameters

### Coupling Metrics
- File dependencies (include graph)
- Circular dependencies
- High coupling files (too many includes)
- **Socket Library**: Check for proper module separation (core/, socket/, poll/, pool/, dns/)

## 6. Analysis Output Format

Generate a comprehensive report with:

### Summary Section
- Total files analyzed
- Total functions/variables checked
- Overall complexity score
- Critical issues count (functions >20 lines, files >20000 lines)
- Recommendations summary

### Detailed Sections
1. **Unused Code**: List all unused functions/variables with locations
2. **Dead Code**: Unreachable code sections with line numbers
3. **Complexity Issues**: Functions exceeding thresholds with scores
4. **Warning Recommendations**: Missing compiler flags and rationale
5. **Metrics Table**: Per-file metrics summary
6. **Priority Fixes**: Ordered list of most critical issues

### Formatting
- Use clear headings and sections
- Include file paths and line numbers for all findings
- Provide code snippets for context where helpful
- Include fix suggestions for each issue
- Categorize by severity: Critical, Warning, Info

## 7. Analysis Rules

### Context Awareness
- Understand C Interfaces and Implementations patterns
- Respect existing error handling patterns (`TRY/EXCEPT/FINALLY`, exception system)
- Recognize intentional patterns (Arena allocation, thread-local storage)
- Account for library interfaces (module-prefixed functions may be public API)
- Understand opaque types (`#define T ModuleName_T` pattern)
- Recognize thread-safe patterns (mutex protection, thread-local storage)

### False Positive Avoidance
- Don't flag `main()` as unused
- Don't flag callback function pointers that are assigned but not directly called
- Recognize exported API functions in headers (module-prefixed)
- Understand exception handling patterns (`RAISE`, `TRY/EXCEPT/FINALLY`)
- Recognize Arena allocation patterns (`ALLOC`, `CALLOC`)
- Understand module exception patterns (`RAISE_MODULE_ERROR`)

### Priority Ranking
1. **Critical**: Dead code, unused critical functions, high complexity (>30), functions >20 lines, files >20000 lines
2. **Warning**: Unused variables, moderate complexity (11-20), missing error checks, missing documentation
3. **Info**: Style suggestions, minor optimizations, documentation gaps

## 8. Socket Library-Specific Patterns

### Module Patterns
- Functions with module prefixes (`Socket_*`, `Arena_*`, `SocketPoll_*`, etc.) are likely public API
- Static helper functions should not have module prefixes
- Type definitions use `T` macro pattern (`#define T ModuleName_T`)
- Opaque types in headers, structures only in implementation files

### Memory Management Patterns
- Arena allocation (`ALLOC`, `CALLOC`) is preferred over raw malloc
- Arena disposal (`Arena_dispose`) frees all related allocations
- Check for Arena usage consistency

### Error Handling Patterns
- Exception-based error handling (`TRY/EXCEPT/FINALLY`)
- Module-specific exceptions (`Socket_Failed`, `SocketPoll_Failed`, etc.)
- Thread-local error buffers (`socket_error_buf`, `MODULE_ERROR_FMT`)
- Thread-safe exception patterns (thread-local `Module_DetailedException`)

### Thread Safety Patterns
- Thread-local storage (`__thread`, `__declspec(thread)`)
- Mutex protection (`pthread_mutex_t`)
- Per-arena mutexes for thread-safe allocation

## 9. Integration Suggestions

- Suggest tools integration (cppcheck, splint, clang-static-analyzer)
- Recommend continuous analysis in build process
- Propose pre-commit hooks for static analysis
- Suggest IDE plugins for real-time analysis
- **Socket Library**: Verify analysis tools respect C Interfaces and Implementations patterns

The analysis should be thorough, actionable, and aligned with C Interfaces and Implementations patterns, GNU C style standards, and the socket library's specific conventions.
