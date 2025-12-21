---
name: comment-cleanup
description: Comment Cleanup Command - Socket Library. Use when cleaning up excessive comments in .c and .h files, removing redundant documentation, or when the user mentions comment cleanup, over-commenting, or documentation redundancy.
---

# Comment Cleanup Command

Clean up excessive comments in .c and .h files. This codebase uses doxygen-style documentation in headers, so implementation files (.c) should have minimal comments and headers should avoid redundant internal comments.

## Philosophy

- **Headers (.h)**: Doxygen-style documentation for public API only
- **Implementation (.c)**: Minimal comments - code should be self-documenting
- **Comments explain WHY, not WHAT** - the code shows what happens

## What to Remove

### In .c Files (Implementation)

1. **Redundant function header comments** - Already documented in .h
   ```c
   // BAD - duplicates .h documentation
   /**
    * @brief Connects to a server
    * @param socket The socket
    * @param host The hostname
    */
   void Socket_connect(Socket_T socket, const char *host, int port)

   // GOOD - no comment needed, documented in header
   void
   Socket_connect(Socket_T socket, const char *host, int port)
   ```

2. **Obvious inline comments**
   ```c
   // BAD
   i++;  // increment i
   return result;  // return the result

   // GOOD - no comment needed
   i++;
   return result;
   ```

3. **Section dividers and decorative comments**
   ```c
   // BAD
   /************************************/
   /*       HELPER FUNCTIONS           */
   /************************************/

   // OK only if truly complex section
   ```

4. **Commented-out code** - Use git history instead
   ```c
   // BAD
   // old_function();
   // if (legacy_mode) { ... }
   ```

5. **TODO/FIXME without context** - Either fix or remove
   ```c
   // BAD
   // TODO: fix this
   // FIXME

   // OK - actionable with context
   // TODO(#42): Add timeout handling after pool refactor
   ```

### In .h Files (Headers)

1. **Internal implementation comments** - Headers are for API docs only
   ```c
   // BAD - implementation detail in header
   struct Socket_T {
       int fd;           // file descriptor
       Arena_T arena;    // memory arena for allocations
   };

   // GOOD - opaque type, no comments needed
   typedef struct T *T;
   ```

2. **Redundant @brief tags**
   ```c
   // BAD - overly verbose
   /**
    * @brief Creates a new socket.
    * @details This function creates a new socket structure.
    * It allocates memory and initializes the socket.
    * @param arena The arena to use for allocation
    * @return A new socket
    */

   // GOOD - concise
   /**
    * Create a new socket.
    *
    * @param arena  Memory arena for allocations
    * Returns: New socket instance
    * Raises: Socket_Failed on error
    */
   ```

3. **Excessive whitespace in doc blocks**
   ```c
   // BAD
   /**
    *
    *
    * Creates a socket.
    *
    *
    */

   // GOOD
   /**
    * Creates a socket.
    */
   ```

## What to Keep

### Always Keep

1. **Non-obvious logic explanations (WHY)**
   ```c
   // GOOD - explains non-obvious behavior
   // Use SO_REUSEADDR to allow quick restart after crash
   setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
   ```

2. **Security/safety notes**
   ```c
   // GOOD - important safety note
   // SECURITY: Validate input length before copy to prevent overflow
   ```

3. **Protocol/RFC references**
   ```c
   // GOOD - references standard
   // RFC 6455 Section 5.2: Frame format
   ```

4. **Platform-specific notes**
   ```c
   // GOOD - explains platform difference
   // Linux uses epoll, BSD/macOS use kqueue
   #ifdef __linux__
   ```

5. **Bug workarounds with issue references**
   ```c
   // GOOD - explains workaround
   // Workaround for glibc bug #12345: AI_ADDRCONFIG fails on some systems
   ```

6. **Doxygen documentation in headers** - Keep for public API

## Cleanup Process

### Step 1: Analyze Target Files

```bash
# Find .c files with high comment ratio
find src/ -name "*.c" -exec sh -c 'echo "$(grep -c "^\s*//" "$1") $(wc -l < "$1") $1"' _ {} \; | sort -rn

# Find .h files with excessive internal comments
find include/ -name "*.h" -exec sh -c 'echo "$(grep -c "^\s*//" "$1") $(wc -l < "$1") $1"' _ {} \; | sort -rn
```

### Step 2: Review Each File

For each file, identify comments that fall into "What to Remove" categories.

### Step 3: Clean Systematically

1. Remove redundant function header comments in .c files
2. Remove obvious inline comments
3. Remove section dividers (unless truly needed)
4. Remove commented-out code
5. Convert actionless TODOs to issues or remove
6. Clean up .h file internal comments

### Step 4: Verify

- Code still compiles: `cmake --build build`
- Tests still pass: `cd build && ctest --output-on-failure`
- Doxygen still generates: `cd build && make doc`

## Output Format

When running cleanup, report:

```
## Comment Cleanup Report

### Files Analyzed
- src/socket/Socket.c: 45 comment lines → 12 (removed 33)
- include/socket/Socket.h: 120 comment lines → 95 (removed 25)

### Changes Made
| File | Removed | Type |
|------|---------|------|
| Socket.c:45 | `// connects to server` | redundant |
| Socket.c:78-82 | function header block | duplicates .h |
| Socket.h:34 | `// file descriptor` | internal detail |

### Kept (Important Comments)
- Socket.c:123: RFC 6455 reference
- Socket.c:156: Security note about validation
```

## Quick Checks

Run these to find over-commented files:

```bash
# .c files with >20% comment lines
for f in src/**/*.c; do
  total=$(wc -l < "$f")
  comments=$(grep -c "^\s*//" "$f" 2>/dev/null || echo 0)
  pct=$((comments * 100 / total))
  [ $pct -gt 20 ] && echo "$pct% $f"
done

# Count // comments per file
grep -r "^\s*//" src/ --include="*.c" | cut -d: -f1 | sort | uniq -c | sort -rn | head -20
```

## Anti-Patterns to Flag

| Pattern | Issue | Action |
|---------|-------|--------|
| `// getter` / `// setter` | Obvious | Remove |
| `// constructor` / `// destructor` | Obvious | Remove |
| `// initialize X` then `X = 0;` | Obvious | Remove |
| `// check if X` then `if (X)` | Obvious | Remove |
| `// loop through` then `for` | Obvious | Remove |
| `// return success` then `return 0;` | Obvious | Remove |
| `// TODO` without issue/context | Unactionable | Remove or file issue |
| `// old code` / `// backup` | Use git | Remove |
| `/*===*/` section dividers | Noise | Remove unless needed |

## Priority Order

1. **First**: Remove redundant .c function headers (biggest win)
2. **Second**: Remove obvious inline comments
3. **Third**: Remove commented-out code
4. **Fourth**: Clean up .h internal comments
5. **Fifth**: Consolidate or remove TODOs
