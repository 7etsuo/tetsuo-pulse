# Fuzzing Patterns Reference

This document contains implementation patterns for libFuzzer harnesses in the socket library.

## File Structure Template

Every fuzzer follows this structure:

```c
/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_module_name.c - Brief description of fuzzer purpose
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - Target 1 (e.g., "Buffer creation with various capacities")
 * - Target 2 (e.g., "Circular buffer wraparound edge cases")
 * - Target 3 (e.g., "Memory safety under stress")
 *
 * Security focus:
 * - Attack vector 1 (e.g., "Buffer overflow prevention")
 * - Attack vector 2 (e.g., "Integer overflow in lengths")
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_module_name
 * Run:   ./fuzz_module_name corpus/module_name/ -fork=16 -max_len=4096
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Project headers */
#include "core/Arena.h"
#include "core/Except.h"
#include "module/SocketModule.h"

/* Static helpers before main function */
static void
helper_function(const uint8_t *data, size_t size)
{
    /* Implementation */
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Implementation */
    return 0;
}
```

## Operation Enum Pattern

For fuzzers testing multiple operations, use an enum to dispatch:

```c
/* Operation codes */
enum ModuleOp {
    OP_CREATE = 0,
    OP_WRITE_READ,
    OP_EDGE_CASE,
    OP_STRESS_TEST,
    OP_COUNT
};

/* In LLVMFuzzerTestOneInput: */
uint8_t op = data[0];
switch (op % OP_COUNT) {
    case OP_CREATE:
        /* Test creation */
        break;
    case OP_WRITE_READ:
        /* Test read/write */
        break;
    /* ... */
}
```

## Byte Extraction Helpers

Standard helpers for reading multi-byte values from fuzz input:

```c
/**
 * read_u16 - Read 16-bit value from byte stream (little-endian)
 */
static uint16_t
read_u16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

/**
 * read_u32 - Read 32-bit value from byte stream (little-endian)
 */
static uint32_t
read_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/**
 * get_op - Extract operation selector
 */
static uint8_t
get_op(const uint8_t *data, size_t size)
{
    return size > 0 ? data[0] % OP_COUNT : 0;
}
```

## Input Format Documentation

Document the expected input format in the function header:

```c
/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 *
 * Input format:
 * - Byte 0: Operation selector
 * - Bytes 1-2: Capacity parameter
 * - Bytes 3-4: Length parameter
 * - Remaining: Data payload
 */
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 5)
        return 0;  /* Minimum input size */

    uint8_t op = data[0];
    uint16_t capacity = read_u16(data + 1);
    uint16_t length = read_u16(data + 3);
    const uint8_t *payload = data + 5;
    size_t payload_len = size - 5;
    /* ... */
}
```

## Arena Memory Pattern

Always use Arena for memory management in fuzzers:

```c
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Arena_T arena = NULL;
    ModuleType_T instance = NULL;

    if (size < MINIMUM_SIZE)
        return 0;

    TRY {
        arena = Arena_new();
        if (!arena)
            return 0;

        instance = Module_new(arena, ...);
        /* Test operations */
    }
    EXCEPT(Module_Failed) {
        /* Expected for invalid inputs */
    }
    EXCEPT(Arena_Failed) {
        /* Memory allocation failure */
    }
    FINALLY {
        if (instance)
            Module_release(&instance);
        if (arena)
            Arena_dispose(&arena);
    }
    END_TRY;

    return 0;
}
```

## Exception Handling Pattern

Catch all relevant exceptions - never let them propagate:

```c
TRY {
    /* Fuzzing operations */
}
EXCEPT(SocketHTTP1_ParseError) {
    /* Expected on malformed HTTP input */
}
EXCEPT(SocketHPACK_Error) {
    /* Expected on malformed HPACK input */
}
EXCEPT(SocketWS_ProtocolError) {
    /* Expected on WebSocket protocol violations */
}
EXCEPT(SocketTLS_Failed) {
    /* Expected on TLS errors */
}
EXCEPT(Arena_Failed) {
    /* Memory exhaustion */
}
ELSE {
    /* Catch any other exceptions */
}
END_TRY;
```

## Volatile Variables for Exception Safety

Variables modified in TRY and read after EXCEPT must be volatile:

```c
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Arena_T arena_instance = Arena_new();
    if (!arena_instance)
        return 0;
    volatile Arena_T arena = arena_instance;  /* Volatile for exception safety */

    TRY {
        /* Operations using arena_instance */
    }
    EXCEPT(Module_Failed) {
        /* arena still valid */
    }
    END_TRY;

    arena_instance = arena;  /* Restore for cleanup */
    Arena_dispose(&arena_instance);
    return 0;
}
```

## GCC Clobbered Warning Suppression

Suppress false-positive warnings for TRY/EXCEPT:

```c
/* Suppress GCC clobbered warnings for TRY/EXCEPT */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif
```

## SIGPIPE Handling

For network-related fuzzers, ignore SIGPIPE:

```c
#include <signal.h>

/* Ignore SIGPIPE for socket operations */
__attribute__((constructor)) static void
ignore_sigpipe(void)
{
    signal(SIGPIPE, SIG_IGN);
}
```

## Conditional Compilation for Optional Features

Handle optional features like TLS:

```c
#if SOCKET_HAS_TLS

/* TLS-specific fuzzer code */

#else /* !SOCKET_HAS_TLS */

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    (void)data;
    (void)size;
    return 0;
}

#endif /* SOCKET_HAS_TLS */
```

## Accessor Coverage Pattern

Exercise all getter functions to ensure complete coverage:

```c
static void
exercise_parser_accessors(Parser_T parser)
{
    /* State queries */
    State state = Parser_state(parser);
    (void)state;

    BodyMode mode = Parser_body_mode(parser);
    (void)mode;

    /* Content info */
    int64_t content_length = Parser_content_length(parser);
    (void)content_length;

    int body_complete = Parser_body_complete(parser);
    (void)body_complete;

    /* Connection info */
    int keepalive = Parser_should_keepalive(parser);
    (void)keepalive;

    /* Header iteration if available */
    if (state >= STATE_HEADERS_COMPLETE) {
        const Headers *headers = Parser_get_headers(parser);
        if (headers) {
            size_t count = Headers_count(headers);
            for (size_t i = 0; i < count && i < 50; i++) {
                const Header *h = Headers_at(headers, i);
                if (h) {
                    (void)h->name;
                    (void)h->value;
                }
            }
        }
    }
}
```

## Incremental Parsing Pattern

Test parsers with variable chunk sizes:

```c
static void
test_incremental_parsing(Parser_T parser, const uint8_t *data,
                         size_t size, size_t chunk_size)
{
    size_t offset = 0;
    size_t consumed;
    Result result = INCOMPLETE;

    while (offset < size && result == INCOMPLETE) {
        size_t remaining = size - offset;
        size_t to_parse = (remaining < chunk_size) ? remaining : chunk_size;

        result = Parser_execute(parser, (const char *)data + offset,
                                to_parse, &consumed);
        offset += consumed;

        /* Prevent infinite loop if no progress */
        if (consumed == 0 && result == INCOMPLETE)
            offset++;
    }
}

/* In main fuzzer: */
size_t chunk_sizes[] = { 1, 2, 7, 13, 64, 256, 1024 };
for (size_t i = 0; i < sizeof(chunk_sizes) / sizeof(chunk_sizes[0]); i++) {
    parser = Parser_new(...);
    if (parser) {
        test_incremental_parsing(parser, data, size, chunk_sizes[i]);
        Parser_free(&parser);
    }
}
```

## Known Input Testing Pattern

Test with known valid/invalid inputs modified by fuzz data:

```c
/* Known valid requests */
const char *valid_requests[] = {
    "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    "POST /data HTTP/1.1\r\nHost: test.com\r\nContent-Length: 5\r\n\r\nhello",
    "PUT /resource HTTP/1.1\r\nHost: api.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
};

for (size_t i = 0; i < sizeof(valid_requests) / sizeof(valid_requests[0]); i++) {
    parser = Parser_new(...);
    if (parser) {
        Parser_execute(parser, valid_requests[i], strlen(valid_requests[i]), &consumed);
        exercise_parser_accessors(parser);
        Parser_free(&parser);
    }
}
```

## Security Attack Vector Pattern

Explicitly test known attack vectors:

```c
/* Malformed requests (security edge cases) */
const char *malformed_requests[] = {
    /* No CRLF */
    "GET / HTTP/1.1 Host: test.com",
    /* Header injection attempt */
    "GET / HTTP/1.1\r\nHost: test.com\r\nX-Inject: value\r\nEvil: header\r\n\r\n",
    /* Duplicate Content-Length (smuggling) */
    "POST / HTTP/1.1\r\nHost: test.com\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\nhello",
    /* CL + TE (smuggling) */
    "POST / HTTP/1.1\r\nHost: test.com\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    /* Null byte in header */
    "GET / HTTP/1.1\r\nHost: test\x00.com\r\n\r\n",
    /* Negative content length */
    "POST / HTTP/1.1\r\nHost: test.com\r\nContent-Length: -1\r\n\r\n",
    /* Huge content length (DoS) */
    "POST / HTTP/1.1\r\nHost: test.com\r\nContent-Length: 99999999999999999999\r\n\r\n",
};

Config strict_cfg;
config_defaults(&strict_cfg);
strict_cfg.strict_mode = 1;

for (size_t i = 0; i < sizeof(malformed_requests) / sizeof(malformed_requests[0]); i++) {
    parser = Parser_new(PARSE_REQUEST, &strict_cfg, arena);
    if (parser) {
        Parser_execute(parser, malformed_requests[i],
                       strlen(malformed_requests[i]), &consumed);
        Parser_free(&parser);
    }
}
```

## Configuration Variation Pattern

Test with different configuration combinations:

```c
/* Test 1: Default configuration */
{
    parser = Parser_new(PARSE_REQUEST, NULL, arena);
    /* ... test ... */
}

/* Test 2: Strict mode */
{
    Config strict_cfg;
    config_defaults(&strict_cfg);
    strict_cfg.strict_mode = 1;
    parser = Parser_new(PARSE_REQUEST, &strict_cfg, arena);
    /* ... test ... */
}

/* Test 3: Lenient with larger limits */
{
    Config lenient_cfg;
    config_defaults(&lenient_cfg);
    lenient_cfg.strict_mode = 0;
    lenient_cfg.max_header_size = 32768;
    lenient_cfg.max_headers = 200;
    parser = Parser_new(PARSE_REQUEST, &lenient_cfg, arena);
    /* ... test ... */
}

/* Test 4: Restrictive limits for DoS testing */
{
    Config restrictive_cfg;
    config_defaults(&restrictive_cfg);
    restrictive_cfg.max_header_size = 1024;
    restrictive_cfg.max_headers = 10;
    restrictive_cfg.max_request_line = 256;
    parser = Parser_new(PARSE_REQUEST, &restrictive_cfg, arena);
    /* ... test ... */
}
```

## Fuzzed Configuration Pattern

Use fuzz data to drive configuration:

```c
static void
test_fuzzed_config(const uint8_t *data, size_t size)
{
    if (size < 16)
        return;

    Config config;
    config_defaults(&config);

    /* Fuzz configuration values */
    config.max_frame_size = ((size_t)data[0] << 24) | ((size_t)data[1] << 16) |
                            ((size_t)data[2] << 8) | data[3];
    config.max_message_size = ((size_t)data[4] << 24) | ((size_t)data[5] << 16) |
                              ((size_t)data[6] << 8) | data[7];
    config.validate_utf8 = data[10] & 1;
    config.strict_mode = data[11] & 1;
    config.timeout_ms = ((int)data[14] << 8) | data[15];

    /* Use config in tests */
}
```

## Error/Result String Coverage

Test all error code string conversions:

```c
{
    Result results[] = {
        RESULT_OK,
        RESULT_INCOMPLETE,
        RESULT_ERROR,
        RESULT_ERROR_OVERFLOW,
        RESULT_ERROR_INVALID_INPUT,
        /* ... all result codes ... */
    };

    for (size_t i = 0; i < sizeof(results) / sizeof(results[0]); i++) {
        const char *str = result_string(results[i]);
        (void)str;
    }

    /* Also test with fuzzed values */
    if (size >= 1) {
        result_string((Result)data[0]);
    }
}
```

## Multi-Test Organization

Organize multiple test cases with clear section headers:

```c
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* ... setup ... */

    TRY {
        /* ====================================================================
         * Test 1: Default configuration parsing
         * ==================================================================== */
        {
            /* ... test code ... */
        }

        /* ====================================================================
         * Test 2: Strict mode configuration
         * ==================================================================== */
        {
            /* ... test code ... */
        }

        /* ====================================================================
         * Test 3: Incremental parsing
         * ==================================================================== */
        {
            /* ... test code ... */
        }

        /* ====================================================================
         * Test 4: Known attack vectors
         * ==================================================================== */
        {
            /* ... test code ... */
        }
    }
    EXCEPT(...) {}
    END_TRY;

    /* ... cleanup ... */
    return 0;
}
```

## Limits and Bounds

Define fuzzing-specific limits:

```c
/* Limits for fuzzing */
#define MAX_FUZZ_CAPACITY 4096
#define MIN_FUZZ_CAPACITY 64
#define MAX_FUZZ_HEADERS 64
#define MAX_FUZZ_FRAGMENTS 100
#define MAX_FUZZ_ITERATIONS 20

/* Bound parameters to limits */
size_t capacity = (capacity_raw % (MAX_FUZZ_CAPACITY - MIN_FUZZ_CAPACITY))
                  + MIN_FUZZ_CAPACITY;

/* Limit iteration counts */
for (size_t i = 0; i < size && i < MAX_FUZZ_ITERATIONS; i++) {
    /* ... */
}
```

## Parser Reset and Reuse

Test parser reset functionality:

```c
/* Parse once */
result = Parser_execute(parser, data, size, &consumed);
exercise_parser_accessors(parser);

/* Reset and reparse */
Parser_reset(parser);
result = Parser_execute(parser, data, size, &consumed);
exercise_parser_accessors(parser);
```

## Body Reading Pattern

Handle body content after header parsing:

```c
if (result == RESULT_OK && Parser_state(parser) >= STATE_BODY) {
    char body_buf[8192];
    size_t body_consumed, body_written;
    size_t remaining = size - consumed;

    while (remaining > 0 && !Parser_body_complete(parser)) {
        Result body_result = Parser_read_body(
            parser, data + consumed, remaining, &body_consumed,
            body_buf, sizeof(body_buf), &body_written);

        if (body_consumed == 0)
            break;

        consumed += body_consumed;
        remaining -= body_consumed;

        if (body_result != RESULT_OK && body_result != RESULT_INCOMPLETE)
            break;
    }
}
```

## Return Value

Always return 0 from LLVMFuzzerTestOneInput:

```c
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* ... all fuzzing logic ... */

    return 0;  /* Always return 0 */
}
```

## Build Commands

Standard fuzzer build and run commands:

```bash
# Configure with fuzzing enabled (requires Clang)
CC=clang cmake -S . -B build -DENABLE_FUZZING=ON

# Build ALL fuzzers (~100 harnesses)
cmake --build build --target fuzzers -j$(nproc)

# Or build a single fuzzer
cmake --build build --target fuzz_socketbuf -j$(nproc)

# List available fuzzers
ls build/fuzz_*

# Run single fuzzer
cd build && ./fuzz_module corpus/module/ -fork=16 -max_len=4096

# Run with memory limits
./fuzz_module corpus/module/ -fork=16 -max_len=4096 -rss_limit_mb=2048

# Run for specific duration
./fuzz_module corpus/module/ -fork=16 -max_len=4096 -max_total_time=3600

# Merge corpus
./fuzz_module -merge=1 corpus/module/ corpus/module_new/

# Minimize crash
./fuzz_module -minimize_crash=1 -exact_artifact_path=minimized crash_file
```
