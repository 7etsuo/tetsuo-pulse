---
name: fuzz
description: Fuzzing harness development with libFuzzer. Use when creating or editing fuzz_*.c files in src/fuzz/, writing fuzzing harnesses, or when the user mentions fuzzing, corpus, or libFuzzer.
---

You are an expert C developer specializing in fuzz testing with libFuzzer.

## Fuzzing Harness Pattern

Every fuzzing harness follows this structure:

```c
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Include module under test
#include "socket/SocketBuf.h"
#include "core/Arena.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // 1. Early exit for trivial inputs
    if (size < 4) return 0;

    // 2. Create arena for this iteration (automatic cleanup)
    Arena_T arena = Arena_new();
    if (!arena) return 0;

    // 3. Parse fuzz input into structured data
    size_t buf_size = data[0] | (data[1] << 8);
    if (buf_size > 65536) buf_size = 65536;  // Limit allocation

    // 4. Exercise the API with fuzz data
    TRY {
        SocketBuf_T buf = SocketBuf_new(arena, buf_size);
        SocketBuf_write(buf, data + 2, size - 2);
        // ... more operations
    }
    EXCEPT(SocketBuf_Failed) {
        // Expected - input triggered error handling
    }
    END_TRY;

    // 5. Cleanup via arena (handles all allocations)
    Arena_dispose(&arena);

    return 0;  // Always return 0 (non-zero = input should be saved)
}
```

## Key Principles

### 1. Never Crash on Invalid Input

The code under test should handle any input gracefully:

```c
// WRONG - crashes on malformed input
assert(header->magic == 0xDEADBEEF);

// RIGHT - reject gracefully
if (header->magic != 0xDEADBEEF) {
    return -1;  // Or raise exception
}
```

### 2. Limit Resource Consumption

Fuzzers generate pathological inputs. Bound everything:

```c
// Bound allocations
size_t alloc_size = *(uint32_t *)data;
if (alloc_size > MAX_ALLOC) alloc_size = MAX_ALLOC;

// Bound iterations
uint32_t iterations = *(uint32_t *)(data + 4);
if (iterations > 10000) iterations = 10000;

// Bound nesting depth
if (depth > MAX_DEPTH) return 0;
```

### 3. Use Arena for Automatic Cleanup

Arena-based allocation ensures no leaks even on exceptions:

```c
Arena_T arena = Arena_new();
TRY {
    // All allocations from arena
    void *a = Arena_alloc(arena, size1);
    void *b = Arena_alloc(arena, size2);
    // If exception raised, FINALLY still runs
}
FINALLY {
    Arena_dispose(&arena);  // Frees everything
}
END_TRY;
```

### 4. Handle Exceptions Properly

Wrap exception-raising code in TRY blocks:

```c
TRY {
    result = Socket_connect(sock, host, port);
}
EXCEPT(Socket_Failed) {
    // Expected - fuzzer found error path
    // Don't crash, just continue
}
END_TRY;
```

### 5. Structure-Aware Fuzzing

Parse fuzz input into meaningful structures:

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Parse header
    if (size < sizeof(FuzzHeader)) return 0;
    FuzzHeader *hdr = (FuzzHeader *)data;

    // Use header to control behavior
    switch (hdr->operation % 5) {
        case 0: test_add(data + sizeof(FuzzHeader), size - sizeof(FuzzHeader)); break;
        case 1: test_remove(...); break;
        case 2: test_lookup(...); break;
        // ...
    }
    return 0;
}
```

## Protocol Fuzzing Patterns

### HTTP Parsing

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Arena_T arena = Arena_new();

    TRY {
        SocketHTTP1_Parser_T parser = SocketHTTP1_Parser_new(arena);

        // Feed data in chunks (tests incremental parsing)
        size_t chunk_size = (size > 0) ? (data[0] % 64) + 1 : 1;
        for (size_t i = 0; i < size; i += chunk_size) {
            size_t remaining = size - i;
            size_t feed = (remaining < chunk_size) ? remaining : chunk_size;
            SocketHTTP1_Parser_feed(parser, data + i, feed);
        }
    }
    EXCEPT(SocketHTTP_Failed) {
        // Parser correctly rejected invalid input
    }
    END_TRY;

    Arena_dispose(&arena);
    return 0;
}
```

### Binary Protocol (HPACK, HTTP/2 frames)

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Test decoder with raw bytes
    HPACK_Context_T ctx = HPACK_Context_new(4096);

    TRY {
        char *name, *value;
        size_t name_len, value_len;

        HPACK_decode(ctx, data, size, &name, &name_len, &value, &value_len);
    }
    EXCEPT(HPACK_Failed) {
        // Malformed HPACK data
    }
    END_TRY;

    HPACK_Context_free(&ctx);
    return 0;
}
```

## Build and Run

```bash
# Build with fuzzing enabled (requires Clang)
CC=clang cmake -S . -B build -DENABLE_FUZZING=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j

# Run single fuzzer
cd build
./fuzz_socketbuf corpus/socketbuf/ -max_len=4096

# Run with multiple cores
./fuzz_http1_request corpus/http1/ -fork=8 -max_len=65536

# Run for fixed time
./fuzz_hpack_decode corpus/hpack/ -max_total_time=3600

# Minimize corpus
./fuzz_socketbuf -merge=1 corpus/socketbuf_min/ corpus/socketbuf/
```

## Corpus Management

```bash
# Create initial corpus from test fixtures
mkdir -p corpus/http1/
cp test_fixtures/http_requests/* corpus/http1/

# Add interesting inputs manually
echo -e "GET / HTTP/1.1\r\nHost: test\r\n\r\n" > corpus/http1/simple_get

# Merge and minimize after fuzzing
./fuzz_http1_request -merge=1 corpus/http1_min/ corpus/http1/
```

## Files Reference

| File | Purpose |
|------|---------|
| `src/fuzz/fuzz_*.c` | Fuzzing harnesses (99 total) |
| `CMakeLists.txt` | Fuzzing build config |
| `corpus/` | Seed inputs (if exists) |

## Checklist for New Fuzzers

1. [ ] Returns 0 always (never crash)
2. [ ] Uses Arena for memory management
3. [ ] Wraps exceptions in TRY/EXCEPT
4. [ ] Bounds all allocations and iterations
5. [ ] Tests incremental/chunked input for parsers
6. [ ] Handles size=0 gracefully
7. [ ] No global state mutation between runs
