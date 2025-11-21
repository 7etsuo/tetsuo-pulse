# Memory Safety Analyzer - Socket Library

Perform deep memory analysis of the socket library codebase to identify memory safety issues, leaks, and vulnerabilities, focusing on Arena-based memory management patterns.

## Analysis Categories

### 1. **Arena Allocation Tracking**

Track all memory allocations and deallocations:

- **Find all allocation sites**:
  - Search for `ALLOC`, `CALLOC`, `Arena_alloc`, `Arena_calloc` calls
  - Search for raw `malloc`, `calloc`, `realloc` calls (should be rare)
  - Verify all related objects use Arena allocation (not raw malloc)
  - Document each allocation with: function name, line number, variable name, type allocated
  - **Socket Library Pattern**: Related objects should use Arena, standalone allocations may use malloc

- **Find all deallocation sites**:
  - Search for `Arena_dispose`, `Arena_clear` calls
  - Search for `free()` calls (should be minimal, mostly for arena structures)
  - Map each free to its corresponding allocation
  - Verify balanced allocation/deallocation pairs
  - **Socket Library Pattern**: Arena disposal frees all related allocations at once

- **Create allocation lifecycle map**:
  - For each allocated pointer, trace its path through the code
  - Identify all places where pointer is assigned, passed, or modified
  - Verify pointer doesn't escape scope before being freed
  - **Arena Pattern**: Verify Arena lifetime matches object lifetime

### 2. **Memory Leak Detection**

Find potential leaks in all code paths:

- **Error path analysis**:
  - For each function with multiple return paths, verify all paths dispose Arena or free memory
  - Check early returns don't skip cleanup
  - Verify `TRY/FINALLY` blocks properly dispose resources
  - Check error handling after allocation doesn't leak
  - **Exception Pattern**: Verify `FINALLY` blocks clean up in all exception paths

- **Arena lifecycle leaks**:
  - Check that Arenas are properly disposed in all code paths
  - Verify `Arena_dispose` is called for every `Arena_new`
  - Check exception paths dispose Arena in `FINALLY` blocks
  - Verify Arena is not used after disposal

- **Function exit point analysis**:
  - List all return statements and goto targets
  - List all exception paths (`RAISE` calls)
  - For each exit point, verify all Arenas and allocations made before that point are disposed/freed
  - Check that cleanup code is reachable from all error paths
  - **Exception Pattern**: All cleanup should be in `FINALLY` blocks

- **Nested allocation leaks**:
  - Check functions that allocate multiple resources (Arenas, objects)
  - Verify if early failure disposes previously allocated resources
  - Example: Function allocates Arena, then objects from Arena - verify Arena disposal in `FINALLY`

### 3. **Double-Free Vulnerabilities**

Check for double-free vulnerabilities:

- **Direct double-free**:
  - Find places where same pointer is freed multiple times
  - Check `Arena_dispose` calls that might dispose same Arena twice
  - Verify `Arena_dispose` sets pointer to NULL (prevents double-free)
  - Check `Arena_clear` followed by `Arena_dispose` (should be safe, but verify)

- **Indirect double-free**:
  - Check if Arena is disposed in function A, then function B also disposes it
  - Verify ownership semantics (who owns the Arena?)
  - Check cleanup functions don't dispose already-disposed Arenas
  - **Socket Library Pattern**: Pointer parameters to dispose functions should be set to NULL

- **Use-after-free leading to double-free**:
  - Find use-after-free patterns that might cause double-free
  - Check if disposed Arena is stored elsewhere and disposed again
  - Verify Arena is set to NULL after disposal

- **Null pointer checks**:
  - Verify `Arena_dispose` checks for NULL before disposing (already handled via assert)
  - Check cleanup code handles NULL pointers gracefully

### 4. **Arena Allocation Compliance**

Verify all allocations follow Arena patterns:

- **Find raw malloc/calloc/realloc calls**:
  - Search for direct `malloc(`, `calloc(`, `realloc(` calls
  - Flag any raw calls that should use Arena allocation
  - **Acceptable uses**: Arena structure allocation, standalone allocations not related to other objects
  - **Exception**: `Arena.c` itself uses malloc for chunk allocation (by design)

- **Verify Arena usage**:
  - Check all `ALLOC`/`CALLOC` calls use correct syntax
  - Verify Arena parameter is valid (not NULL, not disposed)
  - Check Arena lifetime matches object lifetime
  - Verify related objects are allocated from same Arena

- **Overflow protection**:
  - Verify Arena allocation checks for overflow (see `Arena_alloc` implementation)
  - Check size calculations before allocation
  - Verify `ARENA_MAX_ALLOC_SIZE` limit is enforced

### 5. **Exception-Based Cleanup Path Analysis**

Review exception cleanup paths for completeness:

- **Identify all TRY blocks**:
  - Find all `TRY/EXCEPT/FINALLY/END_TRY` blocks
  - Map control flow from each `TRY` to its cleanup
  - Verify all resource allocation happens in `TRY` block

- **Verify FINALLY completeness**:
  - For each `FINALLY` block, list all resources allocated before reaching it
  - Verify each resource is disposed/freed at the `FINALLY` label
  - Check cleanup order (LIFO: last allocated, first freed)
  - **Socket Library Pattern**: Cleanup in reverse order of allocation

- **Exception path cleanup**:
  - Check functions with multiple allocation sites
  - Verify cleanup handles partial allocation (some resources allocated, some not)
  - Example: Function allocates Arena, then objects from Arena - verify both handled in `FINALLY`

- **Missing FINALLY blocks**:
  - Check if resource-allocating functions lack `FINALLY` blocks
  - Verify all error conditions have cleanup paths
  - Check functions that raise exceptions without cleanup

### 6. **Thread Safety Memory Issues**

Check for thread safety issues in memory operations:

- **Arena thread safety**:
  - Verify Arena operations are protected by mutex (per-arena mutex)
  - Check concurrent allocation from same Arena is safe
  - Verify thread-local storage usage is correct

- **Shared resource access**:
  - Check for race conditions in memory allocation
  - Verify mutex protection for shared data structures
  - Check for use-after-free in multithreaded contexts

## Analysis Process

1. **Static Analysis**:
   - Read through each source file systematically
   - For each function, trace all allocation/deallocation pairs
   - Build a map of Arena lifetimes and object lifetimes

2. **Control Flow Analysis**:
   - Identify all paths through each function
   - For each path, verify memory is properly managed
   - Check exception/error paths especially carefully
   - Verify `TRY/EXCEPT/FINALLY` coverage

3. **Pattern Matching**:
   - Compare against known good patterns:
     - `Arena.c` shows proper Arena allocation pattern
     - Any module shows proper `TRY/FINALLY` cleanup pattern
     - Socket modules show proper Arena usage
   - Flag deviations from good patterns

4. **Cross-Function Analysis**:
   - Trace Arenas passed between functions
   - Verify ownership transfer (who disposes?)
   - Check for double-dispose across function boundaries

## Known Patterns to Verify

Based on socket library patterns, verify:

1. **Arena allocation pattern**:
   - `Arena_new()` followed by `Arena_dispose(&arena)` in `FINALLY`
   - Related objects allocated with `ALLOC(arena, ...)`
   - All allocations from Arena disposed together

2. **Exception cleanup pattern**:
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

3. **Module structure allocation**:
   - Module structures allocated with `malloc` (standalone)
   - Module data allocated with Arena (related objects)
   - Module disposal frees structure and disposes Arena

## Output Format

For each issue found, provide:

1. **Severity**: Critical / High / Medium / Low
2. **Type**: Leak / Double-Free / Missing Cleanup / Arena Violation / Overflow Risk
3. **Location**: File name and line number(s)
4. **Issue**: Clear description of the memory safety problem
5. **Impact**: What could happen (leak, crash, security issue)
6. **Current State**: What the code currently does
7. **Fix**: Specific code change with before/after example
8. **Reference**: Link to good pattern in codebase (if applicable)

## Priority Order

1. **Critical**: Double-free, use-after-free, security vulnerabilities, missing `FINALLY` blocks
2. **High**: Memory leaks in common code paths, missing cleanup in exception paths, Arena misuse
3. **Medium**: Potential leaks in rare error paths, raw malloc usage where Arena should be used
4. **Low**: Style issues, minor cleanup improvements

## Tools & Techniques

- Manual code review for each function
- Trace Arena and pointer assignments and usage
- Verify exception paths systematically
- Check function contracts (who owns allocated memory?)
- Compare against established patterns in codebase
- Verify `TRY/FINALLY` coverage for all allocations

## Socket Library-Specific Checks

### Arena Pattern Compliance
- Verify related objects use Arena allocation
- Check Arena lifetime matches object lifetime
- Verify Arena disposal in `FINALLY` blocks
- Check for Arena usage after disposal

### Exception Pattern Compliance
- Verify all allocations in `TRY` blocks
- Verify all cleanup in `FINALLY` blocks
- Check exception paths don't skip cleanup
- Verify `RERAISE` after error handling doesn't skip cleanup

### Thread Safety Compliance
- Verify mutex protection for Arena operations
- Check thread-local storage usage is correct
- Verify no race conditions in memory operations

Provide a comprehensive report organized by file, then by severity, with actionable fixes for each issue, following socket library Arena and exception patterns.
