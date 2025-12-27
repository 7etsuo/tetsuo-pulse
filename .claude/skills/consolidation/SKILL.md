---
name: consolidation
description: Cross-file code consolidation patterns for C codebases. Use when extracting shared constants, functions, or patterns across multiple files. Auto-invoked by /pipeline for Phase 3 consolidation decisions.
allowed-tools: Read,Grep,Glob
---

# Cross-File Consolidation Skill

This skill provides decision rules for consolidating duplicated code across multiple C source files. It helps determine when to extract shared code vs when to leave it inline, and where to place extracted code.

## When This Skill Activates

- During `/pipeline` Phase 3 (Consolidation)
- When redundancy-agent identifies duplications across multiple files
- When asked to consolidate or extract shared code

## Core Decision Framework

### Extract vs Inline Decision

**EXTRACT when ALL of these are true**:
1. Pattern appears in **3+ locations** OR is **complex (>5 lines)**
2. The code performs a **distinct, nameable operation**
3. Extraction **reduces total lines** (accounting for function overhead)
4. The pattern is **stable** (not likely to diverge between uses)

**KEEP INLINE when ANY of these are true**:
1. Pattern appears in only **1-2 locations** AND is **simple (<5 lines)**
2. Slight variations exist that would require many parameters
3. Code is in a **hot path** where function call overhead matters
4. The pattern is **evolving differently** in different contexts

### Decision Matrix

| Occurrences | Lines of Code | Decision |
|-------------|---------------|----------|
| 1 | Any | Keep inline |
| 2 | <5 | Keep inline, add TODO if complex |
| 2 | 5-20 | Consider extraction, evaluate parameters |
| 2 | >20 | Extract to helper function |
| 3+ | Any | Extract (mandatory) |

## Placement Guidelines

### Constants

**Cross-cutting constants** → `include/core/SocketConfig.h`:
```c
/* Buffer sizes used across modules */
#define SOCKET_READ_BUFFER_SIZE   4096
#define SOCKET_MAX_LINE_LENGTH    8192

/* Timeouts used across modules */
#define SOCKET_DEFAULT_TIMEOUT_SEC  30
#define SOCKET_CONNECT_TIMEOUT_MS   5000

/* Limits used across modules */
#define SOCKET_MAX_RETRIES          5
#define SOCKET_MAX_PORT             65535
```

**Module-specific constants** → Module's header file:
```c
/* In SocketHTTP2.h - only used by HTTP/2 module */
#define HTTP2_MAX_FRAME_SIZE        16384
#define HTTP2_INITIAL_WINDOW_SIZE   65535
```

**Function-local constants** → `static const` at function start:
```c
static int
parse_chunk_size(const char *line)
{
        static const int MAX_CHUNK_DIGITS = 8;  /* Only used here */
        /* ... */
}
```

### Functions

**Utility functions** → Appropriate utility module:

| Domain | Target Location |
|--------|-----------------|
| Generic helpers | `include/core/SocketUtil.h`, `src/core/SocketUtil.c` |
| Crypto/security | `include/core/SocketCrypto.h`, `src/core/SocketCrypto.c` |
| Socket operations | `include/socket/SocketCommon.h`, `src/socket/SocketCommon.c` |
| Buffer operations | `include/socket/SocketBuf.h`, `src/socket/SocketBuf.c` |
| HTTP utilities | `include/http/SocketHTTP.h`, `src/http/SocketHTTP.c` |

**Module-internal helpers** → `static` in the .c file:
```c
/* At top of file, before public functions */
static int
validate_port(int port)
{
        return port > 0 && port <= SOCKET_MAX_PORT;
}
```

### Macros

**Public macros** → Module's header file:
```c
/* In SocketConfig.h */
#define SAFE_CLOSE(fd) do { if ((fd) >= 0) { close(fd); (fd) = -1; } } while(0)
```

**Internal macros** → Top of .c file before functions:
```c
/* Internal helper, not exposed in header */
#define ALIGN_UP(x, align) (((x) + (align) - 1) & ~((align) - 1))
```

## Naming Conventions for Extracted Code

### Functions

```c
/* Public function: ModuleName_verb_noun */
int SocketUtil_hash_djb2(const char *str, size_t table_size);

/* Static helper: lower_snake_case */
static int validate_buffer_size(size_t size);
```

### Constants

```c
/* Public constant: MODULE_NOUN_ADJECTIVE */
#define SOCKET_BUFFER_DEFAULT_SIZE  4096
#define HTTP2_STREAM_MAX_COUNT      100

/* Local constant: NOUN_ADJECTIVE */
static const size_t CHUNK_MAX_SIZE = 1024;
```

### Macros

```c
/* Public utility macro: MODULE_ACTION */
#define SOCKET_RAISE_FMT(module, exc, fmt, ...)

/* Internal macro: ACTION_NOUN */
#define ALIGN_POINTER(p) ((void *)(((uintptr_t)(p) + 7) & ~7))
```

## Consolidation Process

### Step 1: Categorize Duplications

Group findings from redundancy-agent into:
1. **Constants**: Magic numbers appearing in multiple files
2. **Patterns**: Same code block in multiple locations
3. **Re-implementations**: Code that duplicates existing utilities

### Step 2: Prioritize

1. **Security-critical duplications** (crypto, validation) - extract immediately
2. **High-frequency duplications** (5+ occurrences) - extract to utilities
3. **Medium-frequency duplications** (3-4 occurrences) - extract to module or static
4. **Low-frequency duplications** (2 occurrences) - document, possibly defer

### Step 3: Plan Extraction

For each extraction target, specify:
1. **Source files** affected
2. **Target location** (which header/source file)
3. **Function signature** or constant definition
4. **Dependencies** (what else needs to be included)

### Step 4: Verify No Behavior Change

Before extraction:
- Confirm all instances are **truly identical** in behavior
- Check for **subtle differences** (different error handling, edge cases)
- Ensure extraction doesn't break **compilation order**

## Anti-Patterns to Avoid

### Over-Extraction
```c
/* BAD - extracting a single, simple operation */
static int add_one(int x) { return x + 1; }

/* GOOD - inline simple operations */
count = count + 1;
```

### Under-Parameterization
```c
/* BAD - different functions for slightly different cases */
static int hash_string_case_sensitive(const char *s);
static int hash_string_case_insensitive(const char *s);

/* GOOD - one function with a parameter */
static int hash_string(const char *s, bool case_insensitive);
```

### Wrong Abstraction Level
```c
/* BAD - too specific, couples to implementation */
static void ssl_read_and_check_error_and_retry_on_want_read(...);

/* GOOD - right level of abstraction */
static ssize_t socket_recv_internal(Socket_T sock, void *buf, size_t len, int flags);
```

## Example Consolidation Report

```markdown
## Consolidation Plan

### Constants to Extract

1. **SOCKET_DEFAULT_BUFFER_SIZE = 4096**
   - Found in: socket/Socket.c, socket/SocketBuf.c, http/SocketHTTP1.c
   - Target: include/core/SocketConfig.h
   - Reason: Used across 3+ modules, affects buffer allocation

2. **HASH_DJB2_SEED = 5381**
   - Found in: core/SocketUtil.c (already), but duplicated in pool/SocketPool.c
   - Action: Remove duplicate from SocketPool.c, use socket_util_hash_djb2()

### Functions to Extract

1. **validate_port_range(int port) -> bool**
   - Found in: socket/Socket.c:142, socket/SocketCommon.c:88, simple/SocketSimple.c:50
   - Target: include/socket/SocketCommon.h
   - Signature: `bool SocketCommon_validate_port(int port);`
   - Implementation: `return port > 0 && port <= SOCKET_MAX_PORT;`

### No Action Needed

1. **Error message formatting in HTTP modules**
   - Reason: Each use has slightly different error context, extraction would over-parameterize
```

## Integration with Pipeline

When invoked during `/pipeline` Phase 3:

1. **Receive** redundancy-agent findings
2. **Apply** decision framework to each finding
3. **Generate** consolidation plan with specific actions
4. **Output** actionable extraction targets for Phase 4
