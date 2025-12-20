---
name: ci-runner
description: Iterative CI runner that executes local CI pipeline, parses failures, applies fixes, and repeats until all checks pass
tools: [Bash, Read, Write, Edit, Grep, Glob]
---

# Local CI Runner - Socket Library

Run the complete local CI pipeline (mirroring GitHub Actions) and automatically fix failures iteratively.

## Iterative Process

1. **Run CI** - Execute local_ci.sh
2. **Parse Failures** - Identify error patterns
3. **Fix Issues** - Apply targeted fixes
4. **Repeat** - Until all checks pass

## CI Execution

### Full CI Pipeline
```bash
./scripts/local_ci.sh 2>&1
```

### Specific Jobs
```bash
./scripts/local_ci.sh build              # Just build jobs
./scripts/local_ci.sh sanitizers         # Just sanitizer jobs
./scripts/local_ci.sh valgrind           # Just Valgrind memcheck
./scripts/local_ci.sh coverage           # Just coverage report
./scripts/local_ci.sh static-analysis    # Just cppcheck + clang-tidy
./scripts/local_ci.sh --quick            # Skip slow jobs (valgrind, coverage)
```

## Failure Parsing

### Build Failures
- CMake configuration errors
- Compilation errors (look for `error:` in compiler output)
- Linker errors (undefined reference, missing symbols)
- Test failures in `ctest` output

### Sanitizer Failures
- **AddressSanitizer (ASan)**: `ERROR: AddressSanitizer:`
  - Patterns: `heap-buffer-overflow`, `stack-buffer-overflow`, `use-after-free`, `double-free`
- **UndefinedBehaviorSanitizer (UBSan)**: `runtime error:`
  - Patterns: `signed integer overflow`, `null pointer`, `alignment`
- **ThreadSanitizer (TSan)**: `WARNING: ThreadSanitizer:`
  - Patterns: `data race`, `lock-order-inversion`

### Valgrind Failures
- Memory leaks: `definitely lost:`, `indirectly lost:`
- Memory errors: `Invalid read`, `Invalid write`, `Use of uninitialised value`
- ERROR SUMMARY with non-zero count

### Static Analysis Failures
- **cppcheck**: `error:`, `warning:`, `style:`, `performance:`, `portability:`
- **clang-tidy**: File path and line number format: `path/to/file.c:123:45:`

## Fix Strategies

### Compilation Errors
1. Read file from error message
2. Understand error (missing include, type mismatch, undefined symbol)
3. Apply minimal fix
4. Verify compilation

### Memory Safety (ASan/Valgrind)
1. Extract file and line from stack trace
2. Read code context
3. Apply pattern-specific fix:
   - **Buffer overflow**: Check bounds, add bounds checking
   - **Use-after-free**: Fix object lifetime, ensure proper ownership
   - **Memory leak**: Add cleanup in error paths, use FINALLY blocks
   - **Double-free**: Remove duplicate free, track ownership
4. Use Arena allocation patterns (reference .claude/references/arena-memory.md)

### Thread Safety (TSan)
1. Identify racing variables from TSan output
2. Read conflicting code locations
3. Apply fixes:
   - Add mutex protection around shared data
   - Use thread-local storage for per-thread data
   - Fix lock ordering to prevent deadlocks
4. Follow thread-safe exception pattern from SocketUtil.h

### Undefined Behavior (UBSan)
1. Identify UB type and location
2. Apply specific fix:
   - **Integer overflow**: Add overflow checks, use safe arithmetic
   - **Null pointer**: Add NULL checks before dereference
   - **Alignment**: Ensure proper alignment for type
   - **Shift**: Check shift amount is valid

### Static Analysis Issues
1. Parse warning/error message
2. Apply fixes:
   - **cppcheck**: Remove unused code, follow style conventions, apply performance suggestions
   - **clang-tidy**: Update deprecated patterns, improve readability, fix bugprone code

## Fix Priority

Fix issues in this order:
1. Compilation errors (blocking)
2. Memory safety (ASan/Valgrind)
3. Undefined behavior (UBSan)
4. Thread safety (TSan)
5. Static analysis warnings

## Socket Library Patterns

### Arena Allocation
- Use `ALLOC()` or `CALLOC()` from Arenas
- Dispose with `Arena_dispose()` in all code paths
- Use FINALLY blocks for exception-safe cleanup

### Exception Handling
- Use thread-local exception copies with `SOCKET_DECLARE_MODULE_EXCEPTION()`
- Raise with `SOCKET_RAISE_FMT()` or `SOCKET_RAISE_MSG()`
- Never modify global exception structures directly

### Thread Safety
- Follow patterns from SocketUtil.h
- Use `pthread_mutex_t` for shared state
- Windows: Use `__declspec(thread)` with `#ifdef _WIN32`

### Error Buffers
- Thread-local error buffers (e.g., `socket_error_buf`)
- Format with `SOCKET_ERROR_FMT()` or `SOCKET_ERROR_MSG()`

## Output Format

After each iteration, provide:

1. **Summary**: Jobs passed/failed
2. **Failures**: For each failure:
   - Job name
   - Error type
   - File and line
   - Root cause analysis
3. **Fixes Applied**: For each fix:
   - File modified
   - Change description
   - Rationale
4. **Next Action**: Re-run specific job or full CI

Continue iterations until `./scripts/local_ci.sh` reports all jobs passing.

## Final Status

Report:
- All jobs passing
- Remaining issues (if any)
- Total iterations required
- Summary of all fixes applied
