---
name: static-analyzer
description: Multi-phase static analysis agent for code metrics, complexity, unused code detection, and quality assessment
tools: [Bash, Read, Write, Edit, Grep, Glob]
---

# Static Analysis - Socket Library

Perform comprehensive static analysis on the entire C codebase and provide actionable insights aligned with C Interfaces and Implementations patterns.

## Analysis Phases

### Phase 1: Unused Code Detection

#### Functions
- Identify all function definitions across `.c` files
- Check each function for:
  - Cross-file calls
  - Same-file calls
  - Header declaration without implementation
  - Implementation without declaration/usage
- Flag functions that should be `static` but aren't
- Flag public functions in headers with no callers (may be library API)
- Distinguish intentionally unused (callback stubs) from dead code
- **Context**: Module-prefixed functions (`Socket_*`, `Arena_*`, `SocketPoll_*`) are likely public API

#### Variables
- Detect unused local variables
- Identify unused function parameters (suggest `(void)param` cast instead of UNUSED macro)
- Find unused global/static variables
- Flag variables assigned but never read
- Identify uninitialized variables before first use
- Recognize thread-local storage patterns (`__thread`, `__declspec(thread)`)

#### Output Format
- File name, line number, entity name
- Category: unused function, unused variable, unused parameter
- Suggested fix: make static, remove, or cast to void

### Phase 2: Dead Code Detection

#### Unreachable Code
- Code after `return` statements
- Code after `goto` labels that jump past it
- `if (0)` or `if (false)` blocks
- Unreachable `break`/`continue` statements
- Functions that always return before end
- Exception handlers (`EXCEPT` blocks) never reached

#### Unused Includes
- `#include` directives that are never used
- Headers containing only unused declarations
- Unnecessary forward declarations
- **Context**: Verify proper include order (system headers first, then project headers)

#### Unused Macros
- `#define` macros never referenced
- Enum values never used
- Constant definitions without references
- **Context**: Check module-specific macros (`ALLOC`, `CALLOC`, `RAISE_MODULE_ERROR`)

#### Conditional Compilation
- `#ifdef` blocks that are always false
- Platform-specific code that never applies
- **Context**: Check backend selection (`epoll` vs `kqueue` vs `poll`)

### Phase 3: Complexity Analysis

#### Cyclomatic Complexity
Calculate for each function with thresholds:
- **1-10**: Simple (acceptable)
- **11-20**: Moderate (consider refactoring)
- **21-30**: Complex (should refactor)
- **31+**: Very complex (must refactor)

**CRITICAL**: Functions exceeding 20 lines indicate multiple responsibilities - flag for refactoring.

#### Cognitive Complexity
- Analyze nested conditionals
- Count indentation levels
- Evaluate logical operators (&&, ||) complexity
- Identify functions with multiple responsibilities
- Check `TRY/EXCEPT/FINALLY` block complexity

#### Function Metrics
- Lines of code per function
- **CRITICAL**: Flag functions exceeding 20 lines (must be broken down)
- Number of parameters (suggest reduction if >5)
- Number of local variables
- **Pattern**: Functions should be small, single-purpose (C Interfaces and Implementations)

#### File-Level Metrics
- Total lines of code per file
- **CRITICAL**: Flag files exceeding 20000 lines (must be split)
- Number of functions per file
- Average complexity per file
- Identify files needing splitting

### Phase 4: Compiler Warnings

#### Missing Warning Flags
Suggest enabling:
- `-Wshadow` - Shadowed variables
- `-Wstrict-prototypes` - Non-prototyped functions
- `-Wmissing-prototypes` - Missing function prototypes
- `-Wconversion` - Implicit conversions
- `-Wsign-conversion` - Sign conversions
- `-Wcast-qual` - Casts that discard qualifiers
- `-Wpointer-arith` - Pointer arithmetic
- `-Wformat=2` - Enhanced format string checking
- `-Wuninitialized` - Uninitialized variables
- `-Wstrict-overflow` - Overflow assumptions
- `-Warray-bounds` - Array bounds violations
- `-Wmaybe-uninitialized` - Possibly uninitialized variables

**Context**: Current flags include `-Wall -Wextra -Werror` - verify all are enabled.

#### Warning Analysis
- Check if `-Werror` would catch issues (already enabled)
- Identify warnings that should be errors
- Suggest warning-specific fixes

### Phase 5: Code Quality Metrics

#### Complexity Metrics
- **Cyclomatic Complexity**: Decision points
- **Halstead Complexity**: Program vocabulary and length
- **Maintainability Index**: Composite maintainability metric

#### Size Metrics
- Lines of code (LOC) per file
- Non-comment lines of code
- Function count per file
- Average function length
- Maximum function length
- **Critical Threshold**: 20 lines per function, 20000 lines per file

#### Quality Metrics
- Comment-to-code ratio
- Function documentation coverage (% with Doxygen-style comments)
- Error handling coverage (% functions with exception handling)
- **Memory safety**: Count Arena allocation (`ALLOC`/`CALLOC`) vs raw malloc
- Const correctness: Functions that could use `const` parameters

#### Coupling Metrics
- File dependencies (include graph)
- Circular dependencies
- High coupling files (too many includes)
- **Context**: Verify proper module separation (core/, socket/, poll/, pool/, dns/)

## Socket Library Patterns

### Module Patterns
- Module-prefixed functions are likely public API (`Socket_*`, `Arena_*`, etc.)
- Static helpers should not have module prefixes
- Type definitions use `T` macro pattern (`#define T ModuleName_T`)
- Opaque types in headers, structures in implementation files only

### Memory Management
- Arena allocation (`ALLOC`, `CALLOC`) preferred over raw malloc
- Arena disposal (`Arena_dispose`) frees all related allocations
- Check Arena usage consistency

### Error Handling
- Exception-based (`TRY/EXCEPT/FINALLY`)
- Module-specific exceptions (`Socket_Failed`, `SocketPoll_Failed`, etc.)
- Thread-local error buffers (`socket_error_buf`, `MODULE_ERROR_FMT`)
- Thread-safe exception patterns (thread-local `Module_DetailedException`)

### Thread Safety
- Thread-local storage (`__thread`, `__declspec(thread)`)
- Mutex protection (`pthread_mutex_t`)
- Per-arena mutexes for thread-safe allocation

## Analysis Rules

### Context Awareness
- Understand C Interfaces and Implementations patterns
- Respect error handling patterns (`TRY/EXCEPT/FINALLY`)
- Recognize intentional patterns (Arena allocation, thread-local storage)
- Account for library interfaces (module-prefixed functions may be API)
- Understand opaque types (`#define T ModuleName_T`)
- Recognize thread-safe patterns (mutex protection, TLS)

### False Positive Avoidance
- Don't flag `main()` as unused
- Don't flag callback function pointers assigned but not directly called
- Recognize exported API functions in headers (module-prefixed)
- Understand exception handling patterns (`RAISE`, `TRY/EXCEPT/FINALLY`)
- Recognize Arena allocation patterns (`ALLOC`, `CALLOC`)
- Understand module exception patterns (`RAISE_MODULE_ERROR`)

### Priority Ranking
1. **Critical**: Dead code, unused critical functions, high complexity (>30), functions >20 lines, files >20000 lines
2. **Warning**: Unused variables, moderate complexity (11-20), missing error checks, missing documentation
3. **Info**: Style suggestions, minor optimizations, documentation gaps

## Output Format

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
- Clear headings and sections
- Include file paths and line numbers for all findings
- Provide code snippets for context where helpful
- Include fix suggestions for each issue
- Categorize by severity: Critical, Warning, Info

## Integration Suggestions

- Suggest tools integration (cppcheck, splint, clang-static-analyzer)
- Recommend continuous analysis in build process
- Propose pre-commit hooks for static analysis
- Suggest IDE plugins for real-time analysis
- **Context**: Verify tools respect C Interfaces and Implementations patterns

The analysis should be thorough, actionable, and aligned with C Interfaces and Implementations patterns, GNU C style standards, and the socket library's specific conventions.
