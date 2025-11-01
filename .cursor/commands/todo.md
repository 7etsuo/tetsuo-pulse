# TODO Tracker & Implementer - Socket Library

Analyze, track, and help implement TODO comments throughout the socket library codebase. Parse all TODO/FIXME/XXX/HACK comments, understand their context, suggest implementation approaches, and generate code following existing C Interfaces and Implementations patterns.

## TODO Discovery

Scan the entire codebase for TODO markers:

- `// TODO:` - Standard todo items
- `// FIXME:` - Bugs that need fixing
- `// XXX:` - Problems or warnings
- `// HACK:` - Temporary workarounds
- `// NOTE:` - Important notes about implementation

For each TODO found, extract:

1. **Location**: File path and line number
2. **Context**: Surrounding code (at least 10 lines before/after)
3. **Description**: What needs to be done
4. **Dependencies**: Related functions, structs, or files
5. **Complexity**: Estimated difficulty (Simple/Medium/Complex)
6. **Priority**: Based on impact and dependencies

## TODO Analysis Process

### 1. Context Understanding

For each TODO:

- Read the function/file where it appears
- Understand the data structures involved
- Identify related code patterns
- Determine dependencies (what else needs to change)
- Check if partial implementation exists
- **Socket Library Context**: Understand module structure, Arena patterns, exception handling

### 2. Implementation Planning

For each TODO, provide:

- **Approach**: Step-by-step implementation strategy
- **Files to modify**: List of files that need changes
- **New code needed**: Functions, structs, or constants required
- **Pattern references**: Point to similar existing code patterns
- **Error handling**: How to handle errors following exception system
- **Testing considerations**: What edge cases to consider

### 3. Code Generation

When implementing a TODO, follow these patterns:

#### Error Handling Pattern
```c
TRY
    // Operations that may fail
    resource = acquire_resource();
    perform_operation(resource);
EXCEPT(Module_Failed)
    fprintf(stderr, "Error: %s\n", Module_GetLastError());
    RERAISE;
FINALLY
    if (resource) release_resource(&resource);
END_TRY;
```

#### Memory Management Pattern
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
Arena_dispose(&arena);  // Frees all objects at once
```

#### Function Documentation Pattern
```c
/**
 * FunctionName - Brief description of function purpose
 * @param1: Description of parameter 1
 * @param2: Description of parameter 2
 *
 * Returns: Description of return value, or NULL on failure
 * Raises: Description of exceptions that may be raised
 * Thread-safe: Yes/No with explanation
 *
 * Additional implementation details and usage notes.
 */
```

#### Code Style Pattern
```c
// C Interfaces and Implementations style
// Function return type on separate line
ReturnType
FunctionName(Type1 param1, Type2 param2)
{
    // Implementation (< 20 lines)
}

// Use module prefix for public functions
Socket_T Socket_new(int domain, int type, int protocol);

// Use static for helper functions
static void helper_function(Socket_T socket)
{
    // Helper implementation (< 20 lines)
}
```

## TODO Output Format

For each TODO, provide:

```
[TODO #N] Location: file.c:line
Priority: High/Medium/Low
Complexity: Simple/Medium/Complex
Status: Pending/In Progress/Blocked/Completed

Description:
[Clear description of what needs to be done]

Context:
[Relevant code context]

Dependencies:
- Function X needs modification
- Struct Y needs new fields
- File Z needs to be created
- Module W needs new functionality

Implementation Plan:
1. Step one...
2. Step two...
3. Step three...

Code Pattern References:
- Similar pattern: file.c:function_name()
- Memory pattern: See Arena.c for Arena allocation patterns
- Error pattern: See Socket.c for exception handling patterns
- Thread safety: See SocketPoll.c for mutex patterns

Generated Code:
[If implementing, provide complete code following socket library patterns]
```

## TODO Management Commands

When user types `/todo`:

- **List all TODOs**: Show all pending TODOs with priorities
- **Analyze specific TODO**: Deep dive into a specific TODO with implementation plan
- **Implement TODO**: Generate code for a specific TODO following all patterns
- **Track progress**: Mark TODOs as in-progress or completed
- **Dependencies**: Show which TODOs depend on others

## Code Generation Guidelines

When generating code for TODOs:

1. **Follow existing patterns exactly** - Match code style, exception handling, Arena allocation
2. **Include all necessary includes** - Don't assume headers are included
3. **Add Doxygen comments** - Document functions properly with all required sections
4. **Handle all error cases** - Use exception system, TRY/FINALLY cleanup
5. **Use Arena allocation** - For related objects, use `ALLOC`/`CALLOC`
6. **Match formatting** - C Interfaces and Implementations style, 8-space indentation, return types on separate lines
7. **Add module headers** - Include module description comments
8. **Keep functions small** - Under 20 lines, extract helpers aggressively

## Socket Library-Specific Patterns

### Module Implementation
- Use module prefix for public functions (`Socket_*`, `Arena_*`, etc.)
- Use `#define T ModuleName_T` pattern for types
- Use opaque types in headers, full structures in implementation files
- Follow module-specific exception patterns

### Error Handling
- Always use `TRY/EXCEPT/FINALLY` for error handling
- Use module-specific exceptions (`Socket_Failed`, `SocketPoll_Failed`, etc.)
- Use thread-local error buffers (`MODULE_ERROR_FMT`, `MODULE_ERROR_MSG`)
- Use `RAISE_MODULE_ERROR` for detailed error messages

### Memory Management
- Use Arena allocation for related objects
- Dispose Arena in `FINALLY` blocks
- Only use `malloc` for Arena structure or standalone allocations

### Thread Safety
- Document thread safety in function documentation
- Use mutex protection for shared resources
- Use thread-local storage for per-thread data

## TODO Priority Assessment

Prioritize TODOs based on:

- **Critical**: Blocks core functionality, security issues, memory leaks
- **High**: Important features, performance improvements, missing functionality
- **Medium**: Enhancements, refactoring opportunities, documentation improvements
- **Low**: Nice-to-have features, minor optimizations

## Completion Tracking

When a TODO is implemented:

1. Verify code follows all socket library patterns
2. Check exception handling is complete (TRY/FINALLY blocks)
3. Ensure memory is properly managed (Arena allocation/disposal)
4. Verify documentation is added (Doxygen-style comments)
5. Verify functions are under 20 lines
6. Verify files are under 400 lines
7. Suggest removing TODO comment or updating to note completion

Provide actionable, prioritized TODO management with code generation that seamlessly integrates with the existing socket library codebase following C Interfaces and Implementations patterns.
