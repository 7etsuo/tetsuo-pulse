---
name: arena
description: Arena-based memory management patterns. Use when working with Arena_T, Arena_alloc, Arena_dispose, or when the user mentions memory management, allocation, or memory lifecycle.
---

You are an expert C developer specializing in arena-based memory management.

## Arena Memory Model

Arenas provide **bulk allocation and deallocation** - all allocations from an arena are freed together:

```c
Arena_T arena = Arena_new();

// Allocate multiple objects
Socket_T *sockets = Arena_alloc(arena, 100 * sizeof(Socket_T));
char *buffer = Arena_alloc(arena, 4096);
HashTable_T table = HashTable_new(arena, 1000);

// All freed at once - no individual free() calls
Arena_dispose(&arena);
```

## Key Benefits

1. **No memory leaks**: Everything tied to arena lifecycle
2. **Fast allocation**: Bump pointer allocation
3. **Exception safety**: FINALLY { Arena_dispose(&arena); } handles cleanup
4. **Cache friendly**: Related objects allocated contiguously

## Core API

```c
// Creation
Arena_T Arena_new(void);                    // Create with default chunk size
Arena_T Arena_new_with_size(size_t chunk);  // Create with specific chunk size

// Allocation (never returns NULL - raises Arena_Failed on OOM)
void *Arena_alloc(Arena_T arena, size_t nbytes);
void *Arena_calloc(Arena_T arena, size_t count, size_t nbytes);

// Convenience macros (include file/line for debugging)
void *ptr = ALLOC(arena, nbytes);
void *arr = CALLOC(arena, count, nbytes);

// Lifecycle
void Arena_clear(Arena_T arena);    // Reset for reuse (keeps memory)
void Arena_dispose(Arena_T *arena); // Free everything, NULL the pointer
```

## Pattern 1: Request-Scoped Arena

Each request/connection gets its own arena:

```c
void handle_request(Socket_T client) {
    Arena_T arena = Arena_new();

    TRY {
        // All request processing uses this arena
        HTTPRequest_T req = HTTPRequest_parse(arena, client);
        HTTPResponse_T resp = process_request(arena, req);
        HTTPResponse_send(client, resp);
    }
    FINALLY {
        Arena_dispose(&arena);  // Entire request freed
    }
    END_TRY;
}
```

## Pattern 2: Pool with Shared Arena

Connection pool shares an arena for related objects:

```c
Arena_T arena = Arena_new();
SocketPool_T pool = SocketPool_new(arena, max_conns, buf_size);

// Pool allocates connection buffers from the arena
// When done:
Arena_dispose(&arena);  // Frees pool AND all connection buffers
```

## Pattern 3: Reusable Arena (Clear vs Dispose)

For repeated operations, clear instead of dispose:

```c
Arena_T arena = Arena_new();

for (int i = 0; i < iterations; i++) {
    // Process with arena
    process_batch(arena, data[i]);

    // Reset for next iteration (memory reused, not freed)
    Arena_clear(arena);
}

Arena_dispose(&arena);  // Final cleanup
```

## Pattern 4: Nested Arenas

Child arenas for temporary allocations:

```c
void process_with_temp(Arena_T parent_arena) {
    // Temporary arena for intermediate work
    Arena_T temp = Arena_new();

    TRY {
        // Large temporary buffers
        char *scratch = Arena_alloc(temp, 1024 * 1024);
        // ... use scratch ...

        // Copy final result to parent arena
        char *result = Arena_alloc(parent_arena, result_size);
        memcpy(result, scratch, result_size);
    }
    FINALLY {
        Arena_dispose(&temp);  // Free temporaries
    }
    END_TRY;

    // Result survives in parent_arena
}
```

## Critical: Arena Lifetime Rules

### Rule 1: Never Use Pointers After Arena Dispose

```c
// WRONG
char *ptr = Arena_alloc(arena, 100);
Arena_dispose(&arena);
strcpy(ptr, "data");  // USE AFTER FREE!

// RIGHT
char *ptr = Arena_alloc(arena, 100);
strcpy(ptr, "data");
Arena_dispose(&arena);  // ptr no longer valid
```

### Rule 2: Don't Mix Arena and malloc()

```c
// WRONG - memory leak
Arena_T arena = Arena_new();
char *a = Arena_alloc(arena, 100);
char *b = malloc(100);  // Not from arena!
Arena_dispose(&arena);   // b leaked!

// RIGHT - all from arena
Arena_T arena = Arena_new();
char *a = Arena_alloc(arena, 100);
char *b = Arena_alloc(arena, 100);
Arena_dispose(&arena);   // Both freed
```

### Rule 3: Handle Pool Resize Carefully

When pools resize, pointers may become invalid:

```c
// DANGER: resize can invalidate Connection_T pointers
Connection_T conn = SocketPool_get(pool, sock);
SocketPool_resize(pool, new_size);  // May realloc!
Connection_data(conn);  // USE AFTER FREE!

// SOLUTION: Use pre-resize callback
void on_resize(SocketPool_T pool, void *userdata) {
    cached_conn = NULL;  // Clear cached pointer
}
SocketPool_set_pre_resize_callback(pool, on_resize, NULL);
```

### Rule 4: Exception Safety with Arena

Allocate arena before TRY, dispose in FINALLY:

```c
Arena_T arena = Arena_new();  // Before TRY
TRY {
    // Allocations that might raise exceptions
    void *data = Arena_alloc(arena, size);
    risky_operation(data);
}
EXCEPT(SomeException) {
    // Handle error
}
FINALLY {
    Arena_dispose(&arena);  // Always runs
}
END_TRY;
```

## Thread Safety

- Each arena has its own mutex
- Safe to allocate from same arena in multiple threads
- But: coordinate dispose() - only one thread should dispose

```c
// Thread-safe allocation
pthread_mutex_lock(&arena_mutex);
void *ptr = Arena_alloc(shared_arena, size);
pthread_mutex_unlock(&arena_mutex);

// Better: per-thread arenas
__thread Arena_T thread_arena = NULL;
void *alloc_thread_local(size_t size) {
    if (!thread_arena) thread_arena = Arena_new();
    return Arena_alloc(thread_arena, size);
}
```

## Debugging Memory Issues

```c
// Track live arenas
size_t Arena_debug_live_count(void);

// In tests:
size_t before = Arena_debug_live_count();
// ... test code ...
size_t after = Arena_debug_live_count();
ASSERT_EQ(before, after);  // No arena leaks
```

## Files Reference

| File | Purpose |
|------|---------|
| `include/core/Arena.h` | Arena API |
| `src/core/Arena.c` | Implementation |
| `src/test/test_arena.c` | Test patterns |
