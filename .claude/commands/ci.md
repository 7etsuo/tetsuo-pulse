# Local CI Runner - Socket Library

Run the complete local CI pipeline (mirroring GitHub Actions) and automatically fix any failures.

## Execution Steps

### Step 1: Run Local CI

Execute the local CI script to run all checks:

```bash
./scripts/local_ci.sh 2>&1
```

If running specific jobs is needed:
```bash
./scripts/local_ci.sh build              # Just build jobs
./scripts/local_ci.sh sanitizers         # Just sanitizer jobs
./scripts/local_ci.sh valgrind           # Just Valgrind memcheck
./scripts/local_ci.sh coverage           # Just coverage report
./scripts/local_ci.sh static-analysis    # Just cppcheck + clang-tidy
./scripts/local_ci.sh --quick            # Skip slow jobs (valgrind, coverage)
```

### Step 2: Parse CI Output

Analyze the CI output for failures. Look for these failure patterns:

#### Build Failures
- CMake configuration errors
- Compilation errors (look for `error:` in compiler output)
- Linker errors (undefined reference, missing symbols)
- Test failures in `ctest` output

#### Sanitizer Failures
- **AddressSanitizer (ASan)**: Memory errors, use-after-free, buffer overflow
  - Look for: `ERROR: AddressSanitizer:`
  - Look for: `heap-buffer-overflow`, `stack-buffer-overflow`, `use-after-free`, `double-free`
- **UndefinedBehaviorSanitizer (UBSan)**: Undefined behavior
  - Look for: `runtime error:`
  - Look for: `signed integer overflow`, `null pointer`, `alignment`
- **ThreadSanitizer (TSan)**: Data races, deadlocks
  - Look for: `WARNING: ThreadSanitizer:`
  - Look for: `data race`, `lock-order-inversion`

#### Valgrind Failures
- Memory leaks: `definitely lost:`, `indirectly lost:`
- Memory errors: `Invalid read`, `Invalid write`, `Use of uninitialised value`
- ERROR SUMMARY with non-zero count

#### Static Analysis Failures
- **cppcheck**: `error:`, `warning:`, `style:`, `performance:`, `portability:`
- **clang-tidy**: `error:`, `warning:`
  - File path and line number in format: `path/to/file.c:123:45:`

### Step 3: Fix Issues

For each failure category, apply the appropriate fix:

#### Compilation Errors
1. Read the file mentioned in the error
2. Understand the error message (missing include, type mismatch, undefined symbol)
3. Apply the minimal fix to resolve the error
4. Verify the fix compiles

#### Memory Safety Issues (ASan/Valgrind)
1. Identify the file and line from the stack trace
2. Read the surrounding code context
3. Common fixes:
   - **Buffer overflow**: Check bounds, increase buffer size, add bounds checking
   - **Use-after-free**: Fix object lifetime, ensure proper ownership
   - **Memory leak**: Add proper cleanup in error paths, use FINALLY blocks
   - **Double-free**: Remove duplicate free, track ownership better
4. Ensure fix follows Arena allocation patterns where applicable

#### Thread Safety Issues (TSan)
1. Identify the racing variables from TSan output
2. Read the code locations involved
3. Common fixes:
   - Add mutex protection around shared data
   - Use thread-local storage for per-thread data
   - Fix lock ordering to prevent deadlocks
4. Follow the thread-safe exception pattern from SocketUtil.h

#### Undefined Behavior (UBSan)
1. Identify the specific UB type and location
2. Common fixes:
   - **Integer overflow**: Add overflow checks, use safe arithmetic
   - **Null pointer**: Add NULL checks before dereference
   - **Alignment**: Ensure proper alignment for type
   - **Shift**: Check shift amount is valid

#### Static Analysis Issues
1. Read the warning/error message
2. Common cppcheck fixes:
   - Unused variables: Remove or use them
   - Style issues: Follow coding conventions
   - Performance: Use suggested optimization
3. Common clang-tidy fixes:
   - Modernization: Update deprecated patterns
   - Readability: Improve code clarity
   - Bugprone: Fix potential bugs

### Step 4: Re-run CI

After applying fixes, re-run the specific failing job to verify:

```bash
./scripts/local_ci.sh <failing_job>
```

Repeat Steps 2-4 until all checks pass.

### Step 5: Final Verification

Run the complete CI to ensure all jobs pass:

```bash
./scripts/local_ci.sh
```

## CI Jobs Reference

| Job | Description | Environment Variables |
|-----|-------------|----------------------|
| `build` | Debug + Release builds with tests | - |
| `sanitizers` | ASan, UBSan, ASan+UBSan, TSan | `ASAN_OPTIONS`, `UBSAN_OPTIONS`, `TSAN_OPTIONS` |
| `valgrind` | Memory leak checking | - |
| `coverage` | Code coverage with lcov | - |
| `static-analysis` | cppcheck + clang-tidy | - |

## Common Failure Patterns and Fixes

### Pattern: Missing Include
```
error: implicit declaration of function 'foo'
```
**Fix**: Add `#include "appropriate_header.h"`

### Pattern: Type Mismatch
```
error: incompatible types when assigning to type 'X' from type 'Y'
```
**Fix**: Cast appropriately or fix the type declaration

### Pattern: Buffer Overflow (ASan)
```
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
WRITE of size N at 0x...
```
**Fix**: Check buffer bounds, increase allocation size, or add bounds checking

### Pattern: Use After Free (ASan)
```
ERROR: AddressSanitizer: heap-use-after-free on address 0x...
READ of size N at 0x...
```
**Fix**: Ensure object lifetime extends through all uses, don't use freed memory

### Pattern: Memory Leak (Valgrind)
```
definitely lost: X bytes in Y blocks
```
**Fix**: Add proper cleanup in all code paths, especially error paths with FINALLY blocks

### Pattern: Data Race (TSan)
```
WARNING: ThreadSanitizer: data race
  Write of size N at 0x... by thread T1:
  Previous read of size N at 0x... by thread T2:
```
**Fix**: Protect shared data with mutex, or use thread-local storage

### Pattern: Integer Overflow (UBSan)
```
runtime error: signed integer overflow: X + Y cannot be represented in type 'int'
```
**Fix**: Add overflow check before operation, use wider type, or use unsigned arithmetic

### Pattern: Null Pointer Dereference (UBSan)
```
runtime error: member access within null pointer of type 'struct X'
```
**Fix**: Add NULL check before dereference, ensure pointer is valid

### Pattern: cppcheck Warning
```
[file.c:123]: (warning) Possible null pointer dereference: ptr
```
**Fix**: Add NULL check or document why it can't be NULL

### Pattern: clang-tidy Error
```
file.c:123:45: error: ... [check-name]
```
**Fix**: Follow the suggestion in the error message

## Socket Library-Specific Considerations

### Arena Allocation
- Memory should be allocated from Arenas using `ALLOC()` or `CALLOC()`
- Arenas must be disposed with `Arena_dispose()` in all code paths
- Use FINALLY blocks to ensure cleanup on exceptions

### Exception Handling
- Use thread-local exception copies with `SOCKET_DECLARE_MODULE_EXCEPTION()`
- Use `SOCKET_RAISE_FMT()` or `SOCKET_RAISE_MSG()` for raising exceptions
- Never modify global exception structures directly

### Thread Safety
- Follow patterns from `SocketUtil.h` for thread-local storage
- Use `pthread_mutex_t` for protecting shared state
- Windows compatibility: Use `__declspec(thread)` with `#ifdef _WIN32`

### Error Buffers
- Use thread-local error buffers (e.g., `socket_error_buf`)
- Use `SOCKET_ERROR_FMT()` or `SOCKET_ERROR_MSG()` for formatting

## Output Format

After running CI, provide:

1. **Summary**: Which jobs passed/failed
2. **Failures**: List each failure with:
   - Job name
   - Error type
   - File and line
   - Root cause analysis
3. **Fixes Applied**: For each fix:
   - File modified
   - Change description
   - Why this fixes the issue
4. **Final Status**: All jobs passing or remaining issues

## Iterative Fixing

If multiple issues exist:
1. Fix compilation errors first (blocking)
2. Fix memory safety issues (ASan/Valgrind)
3. Fix undefined behavior (UBSan)
4. Fix thread safety issues (TSan)
5. Fix static analysis warnings

Continue until `./scripts/local_ci.sh` reports all jobs passing.

