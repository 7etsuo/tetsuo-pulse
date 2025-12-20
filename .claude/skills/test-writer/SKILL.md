---
name: test
description: Test Case Generator - Socket Library. Use when creating or editing test files, writing test cases, or when the user mentions testing, test coverage, or test cases.
---

# Test Case Generator

Generate comprehensive test cases focusing on unit tests, exception handling, Arena allocation, thread safety, and edge cases.

## Test Categories

### 1. Core Module Tests

**Arena Module** (`test_arena.c`):
- Arena creation and disposal
- Basic/multiple allocations (`ALLOC`, `CALLOC`)
- Arena clearing
- Alignment verification
- Overflow protection
- Thread safety (concurrent allocation)
- Edge cases (zero-size, max-size, NULL)

**Exception Module** (`test_except.c`):
- Exception raising (`RAISE`)
- TRY/EXCEPT/FINALLY blocks
- Nested exceptions
- Exception propagation (`RERAISE`)
- Thread safety
- Uncaught exception behavior

### 2. Socket Operation Tests

**Socket Module** (`test_socket.c`):
- Socket creation (TCP, UDP, Unix)
- Binding (IPv4, IPv6, Unix paths)
- Listening, accepting, connecting
- Socket options (non-blocking, timeouts, keepalive, nodelay)
- Exception handling
- DNS resolution

**SocketDgram Module** (`test_socketdgram.c`):
- UDP socket creation
- Sendto/Recvfrom
- Connected mode
- Address handling
- Exception handling

### 3. Buffer Operation Tests

**SocketBuf Module** (`test_socketbuf.c`):
- Buffer creation with various capacities
- Write/read operations
- Circular buffer wraparound
- Full buffer handling
- Buffer clearing
- Zero-copy operations
- Size limit enforcement (SIZE_MAX/2)
- Edge cases (empty, full, single-byte)

### 4. Event Polling Tests

**SocketPoll Module** (`test_socketpoll.c`):
- Poll creation
- Socket add/modify/remove
- Event waiting with timeout
- Platform-specific event translation
- Edge-triggered mode
- Multiple simultaneous events
- Error/hangup events

### 5. Connection Pooling Tests

**SocketPool Module** (`test_socketpool.c`):
- Pool creation
- Connection retrieval by socket
- Connection add/remove
- Hash table O(1) lookup
- Idle connection cleanup
- Thread safety
- Pool limit enforcement

### 6. DNS Resolution Tests

**SocketDNS Module** (`test_socketdns.c`):
- Hostname resolution
- Async resolution
- Timeout handling
- Invalid hostname handling
- Thread pool functionality
- Thread-safe request queuing
- Completion notification

### 7. Error Path Testing

**Exception Handling Errors**:
- Allocation failures
- System call failures (socket, bind, listen, accept)
- Network errors, timeouts
- Invalid inputs (NULL, invalid params)
- Resource exhaustion
- Cleanup verification in all paths

**Memory Allocation Errors**:
- `Arena_new()` returns NULL
- `ALLOC()` returns NULL
- Size overflow before allocation
- No leaks when allocation fails
- Arena disposal in exception paths

### 8. Edge Case Testing

**Socket Edge Cases**:
- Port 0 (system-assigned)
- Port 65535
- Invalid/malformed addresses
- Long hostnames
- Unix domain path limits
- Zero-length send/receive
- Maximum buffer size

**Buffer Edge Cases**:
- Empty buffer operations
- Full buffer operations
- Single-byte buffer
- Maximum buffer (SIZE_MAX/2)
- Wraparound scenarios

**Thread Safety Edge Cases**:
- Concurrent Arena allocation
- Concurrent socket operations
- Exception handling in threads
- Thread-local error buffers

## Test Code Structure

### Basic Test Pattern

```c
#include <assert.h>
#include "test/Test.h"
#include "core/Arena.h"
#include "socket/Socket.h"

/**
 * test_socket_new_creates_socket() - Test socket creation
 *
 * Verifies Socket_new() creates a valid socket.
 */
TEST(socket_new_creates_socket)
{
    Arena_T arena = Arena_new();
    ASSERT_NOT_NULL(arena);

    TRY
        Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
        ASSERT_NOT_NULL(sock);
        Socket_free(&sock);
    EXCEPT(Socket_Failed)
        ASSERT_FAIL("Socket creation should not fail");
    FINALLY
        Arena_dispose(&arena);
    END_TRY;
}
```

### Error Path Test Pattern

```c
/**
 * test_module_function_error_scenario() - Test error handling
 *
 * Verifies proper exception raising and cleanup on error.
 */
TEST(module_function_error_scenario)
{
    Arena_T arena = Arena_new();
    ASSERT_NOT_NULL(arena);

    TRY
        Type_T object = NULL;  // Invalid input
        ModuleName_function(object);  // Should raise
        ASSERT_FAIL("Should have raised exception");
    EXCEPT(Module_Failed)
        ASSERT_NOT_NULL(Module_GetLastError());
    FINALLY
        Arena_dispose(&arena);
    END_TRY;
}
```

### Thread Safety Test Pattern

```c
/**
 * test_module_function_thread_safety() - Test thread safety
 *
 * Verifies concurrent access is safe.
 */
TEST(module_function_thread_safety)
{
    Arena_T arena = Arena_new();
    ASSERT_NOT_NULL(arena);

    // Create threads
    // Perform concurrent operations
    // Verify no race conditions
    // Verify correct results

    Arena_dispose(&arena);
}
```

## Test Guidelines

### Test Function Requirements

- Each test independent (no shared state)
- Tests idempotent (repeatable)
- Descriptive names (`test_module_function_scenario`)
- Include setup and cleanup in each test
- Use TRY/EXCEPT/FINALLY for exception testing
- Verify both success and failure paths
- Check memory leaks (verify Arena disposal)

### Test Data Requirements

- Realistic socket addresses and ports
- Both valid and invalid inputs
- Boundary conditions (0, max, empty, NULL)
- Use const where possible
- Avoid magic numbers (use SocketConfig.h constants)

### Exception Verification

- Verify exceptions raised on errors
- Check exception types (`Socket_Failed`, `SocketPoll_Failed`)
- Verify thread-local error messages
- Verify cleanup in exception paths (FINALLY)

### Memory Safety Verification

- All Arenas disposed
- No double-dispose
- No use-after-free
- NULL checks before dereferencing
- Buffer overflow prevention

## Socket Library Test Requirements

**Arena Usage**:
- Create Arena at test start
- Allocate test objects from Arena
- Dispose Arena at test end (in FINALLY if using TRY)
- Verify no leaks

**Exception Testing**:
- Use TRY/EXCEPT/FINALLY for exception tests
- Verify exceptions with correct types
- Check error messages
- Verify cleanup in FINALLY

**Thread Safety**:
- Test concurrent Arena allocation
- Test concurrent socket operations
- Verify thread-local storage
- Test mutex protection

## Focus by Module

- **Arena**: Allocation/disposal, overflow, thread safety, alignment
- **Socket**: Operations (bind/listen/accept/connect), options, DNS, errors
- **SocketBuf**: Circular buffer, wraparound, limits, zero-copy
- **SocketPoll**: Event polling, backends, event translation, edge-triggered
- **SocketPool**: Connection management, hash tables, thread safety, cleanup

## Coverage Goals

- **Function coverage**: All public functions tested
- **Branch coverage**: All exception paths tested
- **Edge case coverage**: Boundary conditions tested
- **Memory safety**: All allocation/deallocation paths verified
- **Exception handling**: All exception types verified
- **Thread safety**: Concurrent operations tested
- **Integration**: Multi-module workflows tested

Generate comprehensive test cases validating correctness, error handling, memory safety, thread safety, and edge cases while following socket library Arena and exception patterns.
