---
name: memory
description: Memory Safety Analyzer - Socket Library. Use when analyzing memory leaks, Arena allocation patterns, exception cleanup paths, or when the user mentions memory safety, leaks, or allocation issues.
---

# Memory Safety Analyzer

Perform deep memory analysis to identify leaks, double-frees, and Arena allocation violations, focusing on exception-based cleanup patterns.

## Analysis Categories

### 1. Arena Allocation Tracking

**Find all allocation sites**:
- Search for `ALLOC`, `CALLOC`, `Arena_alloc`, `Arena_calloc`
- Flag raw `malloc/calloc/realloc` calls (should use Arena for related objects)
- Verify Arena lifetime matches object lifetime
- Document: function, line, variable, type

**Find all deallocation sites**:
- Search for `Arena_dispose`, `Arena_clear`, `free()` calls
- Map each free to corresponding allocation
- Verify balanced allocation/deallocation pairs
- Check Arena disposal frees all related allocations

**Create allocation lifecycle map**:
- Trace pointer paths through code
- Identify assignments, passes, modifications
- Verify pointer doesn't escape scope before freed
- Verify Arena lifetime matches object lifetime

### 2. Memory Leak Detection

**Error path analysis**:
- Verify all return paths dispose Arena or free memory
- Check early returns don't skip cleanup
- Verify `TRY/FINALLY` blocks properly dispose resources
- Check error handling after allocation doesn't leak

**Arena lifecycle leaks**:
- Verify `Arena_dispose` called for every `Arena_new`
- Check exception paths dispose Arena in `FINALLY` blocks
- Verify Arena not used after disposal

**Function exit point analysis**:
- List all return statements, goto targets, exception paths
- For each exit, verify all Arenas/allocations disposed
- Verify cleanup reachable from all error paths
- **All cleanup must be in FINALLY blocks**

**Nested allocation leaks**:
- Check functions allocating multiple resources
- Verify early failure disposes previously allocated resources

### 3. Double-Free Vulnerabilities

**Direct double-free**:
- Find same pointer freed multiple times
- Check `Arena_dispose` might dispose same Arena twice
- Verify `Arena_dispose` sets pointer to NULL
- Check `Arena_clear` followed by `Arena_dispose`

**Indirect double-free**:
- Check if Arena disposed in function A, then function B also disposes
- Verify ownership semantics (who owns Arena?)
- Check cleanup functions don't dispose already-disposed Arenas

**Use-after-free leading to double-free**:
- Find use-after-free patterns
- Check disposed Arena stored elsewhere and disposed again
- Verify Arena set to NULL after disposal

### 4. Arena Allocation Compliance

**Find raw malloc/calloc/realloc**:
- Search for direct `malloc(`, `calloc(`, `realloc(`
- Flag any that should use Arena
- **Acceptable**: Arena structure allocation, standalone allocations
- **Exception**: `Arena.c` uses malloc for chunk allocation (by design)

**Verify Arena usage**:
- Check `ALLOC/CALLOC` syntax correct
- Verify Arena parameter valid (not NULL, not disposed)
- Verify related objects from same Arena

**Overflow protection**:
- Verify Arena allocation checks for overflow
- Check size calculations before allocation
- Verify `ARENA_MAX_ALLOC_SIZE` limit enforced

### 5. Exception-Based Cleanup Analysis

**Identify all TRY blocks**:
- Find `TRY/EXCEPT/FINALLY/END_TRY` blocks
- Map control flow to cleanup
- Verify resource allocation in `TRY` block

**Verify FINALLY completeness**:
- List all resources allocated before reaching `FINALLY`
- Verify each disposed at `FINALLY` label
- Check cleanup order (LIFO: last allocated, first freed)

**Exception path cleanup**:
- Check functions with multiple allocation sites
- Verify cleanup handles partial allocation
- Verify both Arena and objects handled in `FINALLY`

**Missing FINALLY blocks**:
- Check resource-allocating functions lack `FINALLY`
- Verify all error conditions have cleanup paths
- Check functions raising exceptions without cleanup

### 6. Thread Safety Memory Issues

**Arena thread safety**:
- Verify Arena operations protected by mutex
- Check concurrent allocation from same Arena is safe
- Verify thread-local storage usage correct

**Shared resource access**:
- Check race conditions in memory allocation
- Verify mutex protection for shared data
- Check use-after-free in multithreaded contexts

## Analysis Process

1. **Static Analysis**: Read each source file, trace allocation/deallocation pairs, map Arena and object lifetimes
2. **Control Flow Analysis**: Identify all paths, verify memory properly managed, check exception/error paths
3. **Pattern Matching**: Compare against known good patterns in `Arena.c`, Socket modules
4. **Cross-Function Analysis**: Trace Arenas between functions, verify ownership, check double-dispose

## Known Patterns to Verify

**Arena allocation pattern**:
```c
TRY
    arena = Arena_new();
    object = ALLOC(arena, sizeof(*object));
    // ... use objects ...
EXCEPT(Module_Failed)
    // Handle error
FINALLY
    Arena_dispose(&arena);  // Frees all objects
END_TRY;
```

**Module structure allocation**:
- Structures allocated with `malloc` (standalone)
- Data allocated with Arena (related objects)
- Disposal frees structure and disposes Arena

## Output Format

For each issue:

1. **Severity**: Critical / High / Medium / Low
2. **Type**: Leak / Double-Free / Missing Cleanup / Arena Violation / Overflow Risk
3. **Location**: File and line number(s)
4. **Issue**: Clear description
5. **Impact**: What could happen
6. **Current State**: What code does now
7. **Fix**: Specific code change with before/after
8. **Reference**: Link to good pattern in codebase

## Priority Order

1. **Critical**: Double-free, use-after-free, security vulnerabilities, missing `FINALLY`
2. **High**: Leaks in common paths, missing exception cleanup, Arena misuse
3. **Medium**: Leaks in rare error paths, raw malloc where Arena should be used
4. **Low**: Style issues, minor cleanup improvements

## Socket Library-Specific Checks

- Verify related objects use Arena allocation
- Check Arena lifetime matches object lifetime
- Verify Arena disposal in `FINALLY` blocks
- Check Arena not used after disposal
- Verify all allocations in `TRY` blocks
- Verify all cleanup in `FINALLY` blocks
- Check exception paths don't skip cleanup
- Verify `RERAISE` doesn't skip cleanup
- Verify mutex protection for Arena operations
- Check thread-local storage usage
- Verify no race conditions in memory operations

Provide comprehensive report organized by file, then severity, with actionable fixes following socket library Arena and exception patterns.
