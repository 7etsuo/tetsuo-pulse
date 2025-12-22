# Fuzzing Harness Templates

This document contains complete harness templates for different types of fuzzers in the socket library.

## Parser Fuzzer Template

For protocol parsers (HTTP/1.1, HTTP/2, HPACK, WebSocket):

```c
/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_protocol_parser.c - Protocol Parser Fuzzer
 *
 * Targets:
 * - Message parsing (headers, body)
 * - State machine transitions
 * - Incremental parsing with arbitrary boundaries
 * - Configuration variations
 * - Resource limits enforcement
 * - Error handling paths
 *
 * Security focus:
 * - Injection prevention
 * - Buffer overflow prevention
 * - Integer overflow in lengths
 * - Resource exhaustion protection
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_protocol_parser
 * ./fuzz_protocol_parser corpus/protocol/ -fork=16 -max_len=65536
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "protocol/SocketProtocol.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/**
 * Exercise all parser accessor functions
 */
static void
exercise_parser_accessors(Parser_T parser)
{
    State state = Parser_state(parser);
    (void)state;

    /* Query all available state */
    int64_t length = Parser_content_length(parser);
    (void)length;

    int complete = Parser_is_complete(parser);
    (void)complete;

    /* Access parsed structures if available */
    if (state >= STATE_COMPLETE) {
        const ParsedData *data = Parser_get_data(parser);
        if (data) {
            (void)data->field1;
            (void)data->field2;
        }
    }
}

/**
 * Test incremental parsing with variable chunk sizes
 */
static void
test_incremental_parsing(Parser_T parser, const uint8_t *data,
                         size_t size, size_t chunk_size)
{
    size_t offset = 0;
    size_t consumed;
    Result result = RESULT_INCOMPLETE;

    while (offset < size && result == RESULT_INCOMPLETE) {
        size_t remaining = size - offset;
        size_t to_parse = (remaining < chunk_size) ? remaining : chunk_size;

        result = Parser_execute(parser, (const char *)data + offset,
                                to_parse, &consumed);
        offset += consumed;

        if (consumed == 0 && result == RESULT_INCOMPLETE)
            offset++;
    }

    exercise_parser_accessors(parser);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Arena_T arena = NULL;
    Parser_T parser = NULL;
    size_t consumed;
    Result result;

    if (size == 0)
        return 0;

    arena = Arena_new();
    if (!arena)
        return 0;

    TRY {
        /* ====================================================================
         * Test 1: Default configuration
         * ==================================================================== */
        {
            parser = Parser_new(NULL, arena);
            if (parser) {
                result = Parser_execute(parser, (const char *)data, size, &consumed);
                exercise_parser_accessors(parser);

                /* Test reset and reparse */
                Parser_reset(parser);
                Parser_execute(parser, (const char *)data, size, &consumed);

                Parser_free(&parser);
            }
        }

        /* ====================================================================
         * Test 2: Strict mode
         * ==================================================================== */
        {
            Config strict_cfg;
            config_defaults(&strict_cfg);
            strict_cfg.strict_mode = 1;

            parser = Parser_new(&strict_cfg, arena);
            if (parser) {
                Parser_execute(parser, (const char *)data, size, &consumed);
                exercise_parser_accessors(parser);
                Parser_free(&parser);
            }
        }

        /* ====================================================================
         * Test 3: Restrictive limits
         * ==================================================================== */
        {
            Config restrictive_cfg;
            config_defaults(&restrictive_cfg);
            restrictive_cfg.max_size = 1024;
            restrictive_cfg.max_count = 10;

            parser = Parser_new(&restrictive_cfg, arena);
            if (parser) {
                Parser_execute(parser, (const char *)data, size, &consumed);
                Parser_free(&parser);
            }
        }

        /* ====================================================================
         * Test 4: Incremental parsing
         * ==================================================================== */
        {
            size_t chunk_sizes[] = { 1, 2, 7, 13, 64, 256, 1024 };

            for (size_t i = 0; i < sizeof(chunk_sizes) / sizeof(chunk_sizes[0]); i++) {
                parser = Parser_new(NULL, arena);
                if (parser) {
                    test_incremental_parsing(parser, data, size, chunk_sizes[i]);
                    Parser_free(&parser);
                }
            }
        }

        /* ====================================================================
         * Test 5: Known valid inputs
         * ==================================================================== */
        {
            const char *valid_inputs[] = {
                "VALID INPUT 1",
                "VALID INPUT 2",
                "VALID INPUT 3",
            };

            for (size_t i = 0; i < sizeof(valid_inputs) / sizeof(valid_inputs[0]); i++) {
                parser = Parser_new(NULL, arena);
                if (parser) {
                    Parser_execute(parser, valid_inputs[i], strlen(valid_inputs[i]), &consumed);
                    exercise_parser_accessors(parser);
                    Parser_free(&parser);
                }
            }
        }

        /* ====================================================================
         * Test 6: Security attack vectors
         * ==================================================================== */
        {
            const char *attack_vectors[] = {
                "ATTACK VECTOR 1 - injection",
                "ATTACK VECTOR 2 - overflow",
                "ATTACK VECTOR 3 - smuggling",
            };

            Config strict_cfg;
            config_defaults(&strict_cfg);
            strict_cfg.strict_mode = 1;

            for (size_t i = 0; i < sizeof(attack_vectors) / sizeof(attack_vectors[0]); i++) {
                parser = Parser_new(&strict_cfg, arena);
                if (parser) {
                    Parser_execute(parser, attack_vectors[i], strlen(attack_vectors[i]), &consumed);
                    Parser_free(&parser);
                }
            }
        }
    }
    EXCEPT(Parser_Error) {
        /* Expected on malformed input */
    }
    EXCEPT(Arena_Failed) {
        /* Expected on memory exhaustion */
    }
    END_TRY;

    Arena_dispose(&arena);

    return 0;
}
```

## Buffer Fuzzer Template

For buffer operations (SocketBuf, circular buffers):

```c
/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_buffer.c - Buffer Operations Fuzzer
 *
 * Targets:
 * - Buffer creation with various capacities
 * - Write/read/peek operations
 * - Wraparound edge cases
 * - Dynamic resizing
 * - Zero-copy pointer access
 * - Secure memory clearing
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_buffer
 * ./fuzz_buffer corpus/buffer/ -fork=16 -max_len=4096
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "buffer/Buffer.h"

/* Operation codes */
enum BufOp {
    OP_CREATE = 0,
    OP_WRITE_READ,
    OP_PEEK_CONSUME,
    OP_RESERVE_GROW,
    OP_ZERO_COPY,
    OP_WRAPAROUND,
    OP_SECURE_CLEAR,
    OP_MIXED_OPS,
    OP_COUNT
};

/* Limits */
#define MAX_FUZZ_CAPACITY 4096
#define MIN_FUZZ_CAPACITY 64

static uint16_t
read_u16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Arena_T arena = NULL;
    Buffer_T buf = NULL;
    char read_buffer[MAX_FUZZ_CAPACITY];

    if (size < 5)
        return 0;

    uint8_t op = data[0];
    uint16_t capacity_raw = read_u16(data + 1);
    size_t capacity = (capacity_raw % (MAX_FUZZ_CAPACITY - MIN_FUZZ_CAPACITY))
                      + MIN_FUZZ_CAPACITY;
    uint16_t len_param = read_u16(data + 3);
    size_t data_offset = 5;
    size_t data_len = size > data_offset ? size - data_offset : 0;

    TRY {
        arena = Arena_new();
        if (!arena)
            return 0;

        switch (op % OP_COUNT) {
            case OP_CREATE:
                {
                    buf = Buffer_new(arena, capacity);
                    assert(Buffer_available(buf) == 0);
                    assert(Buffer_space(buf) == capacity);
                    assert(Buffer_empty(buf));
                }
                break;

            case OP_WRITE_READ:
                {
                    buf = Buffer_new(arena, capacity);
                    size_t to_write = data_len > capacity ? capacity : data_len;
                    size_t written = 0;

                    if (to_write > 0)
                        written = Buffer_write(buf, data + data_offset, to_write);

                    assert(Buffer_available(buf) == written);

                    size_t bytes_read = Buffer_read(buf, read_buffer, written);
                    assert(bytes_read == written);
                    assert(Buffer_empty(buf));

                    if (written > 0)
                        assert(memcmp(read_buffer, data + data_offset, written) == 0);
                }
                break;

            case OP_PEEK_CONSUME:
                {
                    buf = Buffer_new(arena, capacity);
                    size_t to_write = data_len > capacity ? capacity : data_len;
                    size_t written = 0;

                    if (to_write > 0)
                        written = Buffer_write(buf, data + data_offset, to_write);

                    size_t peeked = Buffer_peek(buf, read_buffer, written);
                    assert(peeked == written);
                    assert(Buffer_available(buf) == written);

                    size_t consume_amt = len_param % (written + 1);
                    if (consume_amt > 0 && consume_amt <= written) {
                        Buffer_consume(buf, consume_amt);
                        assert(Buffer_available(buf) == written - consume_amt);
                    }

                    Buffer_clear(buf);
                    assert(Buffer_empty(buf));
                }
                break;

            case OP_RESERVE_GROW:
                {
                    buf = Buffer_new(arena, capacity);
                    size_t initial = data_len > capacity / 2 ? capacity / 2 : data_len;

                    if (initial > 0)
                        Buffer_write(buf, data + data_offset, initial);

                    size_t reserve_amt = len_param % MAX_FUZZ_CAPACITY;
                    if (reserve_amt > 0) {
                        TRY {
                            Buffer_reserve(buf, reserve_amt);
                            assert(Buffer_space(buf) >= reserve_amt);
                        }
                        EXCEPT(Buffer_Failed) {
                            /* Expected for overflow */
                        }
                        END_TRY;
                    }
                }
                break;

            case OP_ZERO_COPY:
                {
                    buf = Buffer_new(arena, capacity);
                    size_t write_space = 0;
                    void *write_ptr = Buffer_writeptr(buf, &write_space);

                    if (write_ptr && write_space > 0) {
                        size_t direct_write = data_len > write_space ? write_space : data_len;
                        if (direct_write > 0) {
                            memcpy(write_ptr, data + data_offset, direct_write);
                            Buffer_written(buf, direct_write);
                            assert(Buffer_available(buf) == direct_write);
                        }
                    }

                    size_t read_avail = 0;
                    const void *read_ptr = Buffer_readptr(buf, &read_avail);
                    (void)read_ptr;
                }
                break;

            case OP_WRAPAROUND:
                {
                    buf = Buffer_new(arena, capacity);
                    size_t first_write = capacity / 2;
                    if (first_write > data_len)
                        first_write = data_len;

                    if (first_write > 0) {
                        Buffer_write(buf, data + data_offset, first_write);
                        size_t to_read = first_write / 2;
                        Buffer_read(buf, read_buffer, to_read);

                        size_t space = Buffer_space(buf);
                        size_t remaining = data_len > first_write ? data_len - first_write : 0;
                        size_t second_write = remaining > space ? space : remaining;

                        if (second_write > 0) {
                            size_t offset = data_offset + first_write;
                            if (offset < size)
                                Buffer_write(buf, data + offset, second_write);
                        }

                        size_t total = Buffer_available(buf);
                        Buffer_read(buf, read_buffer, total);
                    }
                }
                break;

            case OP_SECURE_CLEAR:
                {
                    buf = Buffer_new(arena, capacity);
                    size_t to_write = data_len > capacity ? capacity : data_len;

                    if (to_write > 0)
                        Buffer_write(buf, data + data_offset, to_write);

                    Buffer_secureclear(buf);
                    assert(Buffer_empty(buf));

                    if (to_write > 0) {
                        size_t written = Buffer_write(buf, data + data_offset, to_write);
                        assert(written == to_write);
                    }
                }
                break;

            case OP_MIXED_OPS:
                {
                    buf = Buffer_new(arena, capacity);

                    for (size_t i = data_offset; i < size && i < data_offset + 20; i++) {
                        uint8_t sub_op = data[i] % 6;

                        switch (sub_op) {
                            case 0: /* Write */
                                {
                                    size_t space = Buffer_space(buf);
                                    size_t amt = (data[i] % 64) + 1;
                                    if (amt > space) amt = space;
                                    if (amt > 0 && i + amt < size)
                                        Buffer_write(buf, data + i, amt);
                                }
                                break;

                            case 1: /* Read */
                                {
                                    size_t avail = Buffer_available(buf);
                                    size_t amt = (data[i] % 64) + 1;
                                    if (amt > avail) amt = avail;
                                    if (amt > 0)
                                        Buffer_read(buf, read_buffer, amt);
                                }
                                break;

                            case 2: /* Peek */
                                {
                                    size_t avail = Buffer_available(buf);
                                    if (avail > 0)
                                        Buffer_peek(buf, read_buffer, avail);
                                }
                                break;

                            case 3: /* Consume */
                                {
                                    size_t avail = Buffer_available(buf);
                                    size_t amt = data[i] % (avail + 1);
                                    if (amt > 0)
                                        Buffer_consume(buf, amt);
                                }
                                break;

                            case 4: /* Clear */
                                Buffer_clear(buf);
                                break;

                            case 5: /* State check */
                                {
                                    (void)Buffer_available(buf);
                                    (void)Buffer_space(buf);
                                    (void)Buffer_empty(buf);
                                    (void)Buffer_full(buf);
                                }
                                break;
                        }
                    }
                }
                break;
        }
    }
    EXCEPT(Buffer_Failed) { /* Expected */ }
    EXCEPT(Arena_Failed) { /* Expected */ }
    FINALLY {
        if (buf)
            Buffer_release(&buf);
        if (arena)
            Arena_dispose(&arena);
    }
    END_TRY;

    return 0;
}
```

## State Machine Fuzzer Template

For protocol state machines (TLS handshake, connection lifecycle):

```c
/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_state_machine.c - State Machine Fuzzer
 *
 * Targets:
 * - State transitions
 * - Timeout handling
 * - Non-blocking operations
 * - Multiple operation steps
 * - State queries
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_state_machine
 * ./fuzz_state_machine corpus/state/ -fork=16 -max_len=4096
 */

#if FEATURE_ENABLED

#include <signal.h>
#include <stdint.h>
#include <stdlib.h>

#include "core/Except.h"
#include "module/StateMachine.h"

/* Suppress GCC clobbered warnings */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/* Ignore SIGPIPE */
__attribute__((constructor)) static void
ignore_sigpipe(void)
{
    signal(SIGPIPE, SIG_IGN);
}

typedef enum {
    OP_STEP_SINGLE = 0,
    OP_LOOP_ZERO_TIMEOUT,
    OP_LOOP_FUZZED_TIMEOUT,
    OP_LOOP_EXTENDED,
    OP_AUTO,
    OP_STATE_QUERY,
    OP_MULTIPLE_STEPS,
    OP_COUNT
} Operation;

static uint8_t
get_op(const uint8_t *data, size_t size)
{
    return size > 0 ? data[0] % OP_COUNT : 0;
}

static uint16_t
get_timeout(const uint8_t *data, size_t size)
{
    if (size < 3)
        return 0;
    return (uint16_t)data[1] | ((uint16_t)data[2] << 8);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 3)
        return 0;

    volatile uint8_t op = get_op(data, size);
    uint16_t timeout_ms = get_timeout(data, size) % 100;  /* Cap timeout */
    StateMachine_T sm = NULL;
    Context_T ctx = NULL;

    TRY {
        sm = StateMachine_new();
        if (!sm)
            return 0;

        ctx = Context_new(NULL);
        if (!ctx) {
            StateMachine_free(&sm);
            return 0;
        }

        StateMachine_init(sm, ctx);

        switch (op) {
            case OP_STEP_SINGLE:
                {
                    State state = StateMachine_step(sm);
                    (void)state;
                }
                break;

            case OP_LOOP_ZERO_TIMEOUT:
                {
                    State state = StateMachine_loop(sm, 0);
                    (void)state;
                }
                break;

            case OP_LOOP_FUZZED_TIMEOUT:
                {
                    State state = StateMachine_loop(sm, (int)timeout_ms);
                    (void)state;
                }
                break;

            case OP_LOOP_EXTENDED:
                {
                    int poll_interval = (size > 3) ? (data[3] % 50) : 10;
                    State state = StateMachine_loop_ex(sm, (int)timeout_ms, poll_interval);
                    (void)state;
                }
                break;

            case OP_AUTO:
                {
                    State state = StateMachine_auto(sm);
                    (void)state;
                }
                break;

            case OP_STATE_QUERY:
                {
                    StateMachine_step(sm);
                    (void)StateMachine_get_info(sm);
                    (void)StateMachine_get_status(sm);
                    (void)StateMachine_is_complete(sm);
                }
                break;

            case OP_MULTIPLE_STEPS:
                {
                    int steps = (size > 3) ? (data[3] % 5 + 1) : 2;
                    for (int i = 0; i < steps; i++) {
                        State state = StateMachine_step(sm);
                        if (state == STATE_COMPLETE || state == STATE_ERROR)
                            break;
                    }
                }
                break;
        }
    }
    EXCEPT(StateMachine_Failed) {}
    EXCEPT(Context_Failed) {}
    ELSE {}
    END_TRY;

    if (sm)
        StateMachine_free(&sm);
    if (ctx)
        Context_free(&ctx);

    return 0;
}

#else /* !FEATURE_ENABLED */

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    (void)data;
    (void)size;
    return 0;
}

#endif
```

## Codec Fuzzer Template

For encoding/decoding (HPACK, UTF-8, Base64):

```c
/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_codec.c - Codec Fuzzer
 *
 * Targets:
 * - Decoding malformed input
 * - Encoding roundtrip
 * - Table/state manipulation
 * - Integer overflow in sizes
 * - Limit enforcement
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_codec
 * ./fuzz_codec corpus/codec/ -fork=16 -max_len=32768
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "codec/Codec.h"

#define MAX_DECODED_ITEMS 64

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1)
        return 0;

    Arena_T arena_instance = Arena_new();
    if (!arena_instance)
        return 0;
    volatile Arena_T arena = arena_instance;
    (void)arena;

    TRY {
        /* Create decoder with default config */
        Codec_Config cfg;
        Codec_config_defaults(&cfg);
        Codec_Decoder_T decoder = Codec_Decoder_new(&cfg, arena_instance);

        /* Decode fuzzed data */
        Codec_Item items[MAX_DECODED_ITEMS];
        size_t item_count = 0;
        Codec_Result res = Codec_Decoder_decode(
            decoder, data, size, items, MAX_DECODED_ITEMS,
            &item_count, arena_instance);

        /* Access decoded items */
        (void)res;
        for (size_t i = 0; i < item_count; i++) {
            (void)items[i].field1;
            (void)items[i].field2;
        }

        /* Fuzz configuration change */
        if (size > 4) {
            uint32_t new_size = *(uint32_t *)data % CODEC_MAX_SIZE;
            Codec_Decoder_set_size(decoder, new_size);
        }

        /* Test encode if data decoded successfully */
        if (res == CODEC_OK && item_count > 0) {
            uint8_t encode_buf[4096];
            size_t encoded_len = 0;

            Codec_Encoder_T encoder = Codec_Encoder_new(&cfg, arena_instance);
            for (size_t i = 0; i < item_count && i < 10; i++) {
                Codec_Encoder_encode(encoder, &items[i],
                                     encode_buf, sizeof(encode_buf),
                                     &encoded_len);
            }
            Codec_Encoder_free(&encoder);
        }

        Codec_Decoder_free(&decoder);
    }
    EXCEPT(Codec_Error) {
        /* Expected on malformed input */
    }
    EXCEPT(Arena_Failed) {
        /* Expected on memory exhaustion */
    }
    END_TRY;

    Arena_dispose(&arena_instance);

    return 0;
}
```

## Security Attack Fuzzer Template

For security-focused testing (HTTP smuggling, injection):

```c
/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_security_attack.c - Security Attack Vector Fuzzer
 *
 * Comprehensive fuzzing targeting specific attack categories:
 *
 * Attack Categories:
 * 1. Injection attacks (header, command, etc.)
 * 2. Smuggling attacks (CL.TE, TE.CL, TE.TE)
 * 3. Parsing ambiguity attacks
 * 4. Obfuscation attacks
 * 5. Duplicate header attacks
 * 6. Length manipulation attacks
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_security_attack
 * ./fuzz_security_attack corpus/security/ -fork=16 -max_len=65536
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "protocol/Protocol.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void
test_detection(Arena_T arena, const char *input, size_t len, int strict)
{
    Parser_T parser = NULL;
    Config cfg;
    size_t consumed;

    config_defaults(&cfg);
    cfg.strict_mode = strict;

    parser = Parser_new(&cfg, arena);
    if (!parser)
        return;

    Result result = Parser_execute(parser, input, len, &consumed);

    if (result == RESULT_OK) {
        const ParsedData *data = Parser_get_data(parser);
        if (data && data->headers) {
            /* Check for conflicting indicators */
            const char *indicator1 = Headers_get(data->headers, "Header1");
            const char *indicator2 = Headers_get(data->headers, "Header2");

            if (indicator1 && indicator2) {
                /* Potential attack detected */
                (void)indicator1;
                (void)indicator2;
            }

            /* Check for multiple values */
            const char *values[10];
            size_t count = Headers_get_all(data->headers, "Header1", values, 10);
            if (count > 1) {
                /* Multiple values - potential attack */
                (void)count;
            }
        }
    }

    Parser_free(&parser);
}

static void
test_incremental(Arena_T arena, const char *input, size_t len)
{
    Parser_T parser = NULL;
    Config cfg;

    config_defaults(&cfg);
    cfg.strict_mode = 1;

    parser = Parser_new(&cfg, arena);
    if (!parser)
        return;

    /* Byte-by-byte parsing for state corruption */
    size_t offset = 0;
    size_t consumed;
    Result result = RESULT_INCOMPLETE;

    while (offset < len && result == RESULT_INCOMPLETE) {
        result = Parser_execute(parser, input + offset, 1, &consumed);
        offset += consumed;
        if (consumed == 0 && result == RESULT_INCOMPLETE)
            offset++;
    }

    Parser_free(&parser);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Arena_T arena = NULL;

    if (size < 16)
        return 0;

    arena = Arena_new();
    if (!arena)
        return 0;

    TRY {
        /* Direct fuzzed input */
        test_detection(arena, (const char *)data, size, 0);
        test_detection(arena, (const char *)data, size, 1);

        /* Byte-by-byte parsing */
        test_incremental(arena, (const char *)data, size);

        /* Attack Category 1: Type A attacks */
        {
            const char *type_a_attacks[] = {
                "ATTACK VARIANT 1",
                "ATTACK VARIANT 2",
                "ATTACK VARIANT 3",
            };

            for (size_t i = 0; i < sizeof(type_a_attacks) / sizeof(type_a_attacks[0]); i++) {
                test_detection(arena, type_a_attacks[i], strlen(type_a_attacks[i]), 0);
                test_detection(arena, type_a_attacks[i], strlen(type_a_attacks[i]), 1);
            }
        }

        /* Attack Category 2: Type B attacks */
        {
            const char *type_b_attacks[] = {
                "ATTACK VARIANT 1",
                "ATTACK VARIANT 2",
            };

            for (size_t i = 0; i < sizeof(type_b_attacks) / sizeof(type_b_attacks[0]); i++) {
                test_detection(arena, type_b_attacks[i], strlen(type_b_attacks[i]), 0);
                test_detection(arena, type_b_attacks[i], strlen(type_b_attacks[i]), 1);
            }
        }

        /* Attack Category 3: Edge cases */
        {
            const char *edge_cases[] = {
                "EDGE CASE 1 - negative value",
                "EDGE CASE 2 - zero value",
                "EDGE CASE 3 - max value",
                "EDGE CASE 4 - overflow",
            };

            for (size_t i = 0; i < sizeof(edge_cases) / sizeof(edge_cases[0]); i++) {
                test_detection(arena, edge_cases[i], strlen(edge_cases[i]), 0);
                test_detection(arena, edge_cases[i], strlen(edge_cases[i]), 1);
            }
        }

        /* Build attack with fuzzed payload */
        if (size > 50) {
            char attack_buf[8192];
            int len;
            size_t payload_len = size > 100 ? 100 : size;

            len = snprintf(attack_buf, sizeof(attack_buf),
                           "PREFIX %zu CONTENT\r\n\r\n",
                           payload_len + 7);

            if (len > 0 && (size_t)len + payload_len < sizeof(attack_buf)) {
                memcpy(attack_buf + len, data, payload_len);
                test_detection(arena, attack_buf, len + payload_len, 0);
                test_detection(arena, attack_buf, len + payload_len, 1);
            }
        }
    }
    EXCEPT(Parser_Error) {
        /* Expected */
    }
    EXCEPT(Arena_Failed) {
        /* Expected */
    }
    END_TRY;

    Arena_dispose(&arena);

    return 0;
}
```

## Frame Parsing Fuzzer Template

For frame-based protocols (WebSocket, HTTP/2):

```c
/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_frames.c - Frame Parsing Fuzzer
 *
 * Targets:
 * - Frame header parsing
 * - Payload validation
 * - Fragmentation handling
 * - Control frame limits
 * - State machine corruption
 * - Length field overflow
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_frames
 * ./fuzz_frames corpus/frames/ -fork=16 -max_len=65536
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "protocol/Frames.h"

/* Suppress GCC clobbered warnings */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

static size_t
calc_header_size(uint8_t len_indicator, int has_mask)
{
    size_t base = 2;
    if (len_indicator == 126)
        base += 2;
    else if (len_indicator == 127)
        base += 8;
    if (has_mask)
        base += 4;
    return base;
}

static uint64_t
extract_length(const uint8_t *data, size_t size, size_t *header_size)
{
    if (size < 2) {
        *header_size = 0;
        return 0;
    }

    uint8_t len_ind = data[1] & 0x7F;
    int has_mask = (data[1] >> 7) & 1;
    size_t hdr_size = calc_header_size(len_ind, has_mask);
    *header_size = hdr_size;

    if (size < hdr_size)
        return 0;

    if (len_ind <= 125)
        return len_ind;
    else if (len_ind == 126)
        return ((uint16_t)data[2] << 8) | (uint16_t)data[3];
    else {
        uint64_t len = 0;
        for (int i = 0; i < 8; i++)
            len = (len << 8) | data[2 + i];
        return len;
    }
}

static void
test_header_parsing(const uint8_t *data, size_t size)
{
    if (size < 2)
        return;

    uint8_t byte0 = data[0];
    uint8_t byte1 = data[1];

    int fin = (byte0 >> 7) & 1;
    int rsv1 = (byte0 >> 6) & 1;
    int rsv2 = (byte0 >> 5) & 1;
    int rsv3 = (byte0 >> 4) & 1;
    Opcode opcode = (Opcode)(byte0 & 0x0F);
    int masked = (byte1 >> 7) & 1;
    uint8_t len_ind = byte1 & 0x7F;

    (void)fin;
    (void)rsv1;
    (void)rsv2;
    (void)rsv3;
    (void)masked;
    (void)len_ind;

    int is_control = (opcode >= OPCODE_CONTROL_START);
    if (is_control && !fin) {
        /* Protocol violation */
    }
    if (is_control && len_ind > 125) {
        /* Protocol violation */
    }

    (void)is_control;
}

static void
test_fragmentation(const uint8_t *data, size_t size)
{
    if (size < 10)
        return;

    size_t offset = 0;
    int in_message = 0;
    Opcode message_type = OPCODE_CONTINUATION;
    int fragment_count = 0;
    const int max_fragments = 100;

    while (offset + 2 <= size && fragment_count < max_fragments) {
        uint8_t byte0 = data[offset];
        int fin = (byte0 >> 7) & 1;
        Opcode opcode = (Opcode)(byte0 & 0x0F);

        int is_control = (opcode >= OPCODE_CONTROL_START);

        if (is_control) {
            size_t header_size;
            uint64_t payload_len = extract_length(data + offset, size - offset, &header_size);
            if (header_size == 0)
                break;

            size_t frame_size = header_size + (size_t)payload_len;
            if (offset + frame_size > size)
                break;

            offset += frame_size;
            fragment_count++;
            continue;
        }

        if (!in_message) {
            if (opcode == OPCODE_CONTINUATION)
                break;
            message_type = opcode;
            in_message = 1;
        } else {
            if (opcode != OPCODE_CONTINUATION)
                break;
        }

        size_t header_size;
        uint64_t payload_len = extract_length(data + offset, size - offset, &header_size);
        if (header_size == 0)
            break;

        size_t frame_size = header_size + (size_t)payload_len;
        if (offset + frame_size > size)
            break;

        offset += frame_size;
        fragment_count++;

        if (fin)
            in_message = 0;
    }

    (void)message_type;
}

static void
test_config_validation(const uint8_t *data, size_t size)
{
    if (size < 16)
        return;

    Config config;
    config_defaults(&config);

    config.max_frame_size = ((size_t)data[0] << 24) | ((size_t)data[1] << 16) |
                            ((size_t)data[2] << 8) | data[3];
    config.max_message_size = ((size_t)data[4] << 24) | ((size_t)data[5] << 16) |
                              ((size_t)data[6] << 8) | data[7];
    config.max_fragments = ((size_t)data[8] << 8) | data[9];
    config.validate = data[10] & 1;
    config.strict = data[11] & 1;

    if (config.max_frame_size > 0 && config.max_message_size > 0 &&
        config.max_fragments > 0) {
        if (config.max_frame_size <= SIZE_MAX / config.max_fragments) {
            /* Safe */
        }
    }
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2)
        return 0;

    Arena_T arena_instance = Arena_new();
    if (!arena_instance)
        return 0;
    volatile Arena_T arena = arena_instance;

    TRY {
        test_header_parsing(data, size);
        test_fragmentation(data, size);
        test_config_validation(data, size);

        size_t header_size;
        uint64_t payload_len = extract_length(data, size, &header_size);
        (void)payload_len;

        Arena_clear(arena_instance);
    }
    EXCEPT(Frame_Failed) { /* Expected */ }
    EXCEPT(Frame_ProtocolError) { /* Expected */ }
    EXCEPT(Arena_Failed) { /* Expected */ }
    END_TRY;

    arena_instance = arena;
    Arena_dispose(&arena_instance);

    return 0;
}
```

## Validation Fuzzer Template

For input validation (UTF-8, DNS, IP, URL):

```c
/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_validation.c - Input Validation Fuzzer
 *
 * Targets:
 * - Valid input acceptance
 * - Invalid input rejection
 * - Boundary conditions
 * - Overlong sequences
 * - Edge cases
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_validation
 * ./fuzz_validation corpus/validation/ -fork=16 -max_len=4096
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "validation/Validator.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1)
        return 0;

    Arena_T arena = Arena_new();
    if (!arena)
        return 0;

    TRY {
        /* One-shot validation */
        Result result = Validator_validate(data, size);
        (void)result;

        /* Incremental validation */
        Validator_State state;
        Validator_init(&state);
        result = Validator_update(&state, data, size);

        if (result == RESULT_VALID || result == RESULT_INCOMPLETE) {
            Validator_finish(&state);
        }

        /* Chunk-based validation */
        Validator_init(&state);
        size_t chunk_size = 7;
        for (size_t offset = 0; offset < size; offset += chunk_size) {
            size_t remaining = size - offset;
            size_t to_check = (remaining < chunk_size) ? remaining : chunk_size;
            result = Validator_update(&state, data + offset, to_check);
            if (result != RESULT_VALID && result != RESULT_INCOMPLETE)
                break;
        }
        if (result == RESULT_VALID || result == RESULT_INCOMPLETE) {
            Validator_finish(&state);
        }

        /* Known valid inputs */
        const char *valid_inputs[] = {
            "valid1",
            "valid2",
            "valid3",
        };
        for (size_t i = 0; i < sizeof(valid_inputs) / sizeof(valid_inputs[0]); i++) {
            result = Validator_validate((const uint8_t *)valid_inputs[i],
                                        strlen(valid_inputs[i]));
            (void)result;
        }

        /* Known invalid inputs */
        const uint8_t *invalid_inputs[] = {
            (const uint8_t *)"invalid1",
            (const uint8_t *)"\xFF\xFE",
            (const uint8_t *)"\x00",
        };
        size_t invalid_lens[] = { 8, 2, 1 };
        for (size_t i = 0; i < sizeof(invalid_inputs) / sizeof(invalid_inputs[0]); i++) {
            result = Validator_validate(invalid_inputs[i], invalid_lens[i]);
            (void)result;
        }
    }
    EXCEPT(Validator_Failed) {
        /* Expected */
    }
    EXCEPT(Arena_Failed) {
        /* Expected */
    }
    END_TRY;

    Arena_dispose(&arena);

    return 0;
}
```
