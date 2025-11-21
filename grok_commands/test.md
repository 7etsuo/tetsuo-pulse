# Test Case Generator - Socket Library

Generate comprehensive test cases for the socket library codebase, focusing on unit tests for socket operations, Arena allocation, exception handling, thread safety, and edge case testing.

## Test Categories

### 1. **Unit Tests for Core Modules**

#### Arena Module Tests (`test_arena.c`)
   - **Arena creation**: `Arena_new()` success and failure cases
   - **Basic allocation**: `ALLOC` and `CALLOC` with various sizes
   - **Multiple allocations**: Multiple objects from same Arena
   - **Arena disposal**: Verify all allocations freed together
   - **Arena clearing**: Clear allocations but keep Arena active
   - **Alignment**: Verify allocations are properly aligned
   - **Overflow protection**: Test allocation size overflow detection
   - **Thread safety**: Concurrent allocation from same Arena
   - **Edge cases**: Zero-size allocation, maximum size allocation, NULL Arena

#### Exception Module Tests (`test_except.c`)
   - **Exception raising**: Basic `RAISE` operation
   - **TRY/EXCEPT blocks**: Exception catching and handling
   - **FINALLY blocks**: Cleanup code execution
   - **Nested exceptions**: Exception handling in nested TRY blocks
   - **Exception propagation**: `RERAISE` functionality
   - **Thread safety**: Exception handling in multithreaded context
   - **Uncaught exceptions**: Behavior when exception not caught

### 2. **Unit Tests for Socket Operations**

#### Socket Module Tests (`test_socket.c`)
   - **Socket creation**: TCP, UDP, Unix domain sockets
   - **Socket binding**: IPv4, IPv6, Unix domain paths
   - **Socket listening**: Backlog size handling
   - **Socket accepting**: Accept new connections
   - **Socket connecting**: Connect to remote hosts
   - **Socket options**: Set/Get various socket options
   - **Non-blocking mode**: Non-blocking socket operations
   - **Timeouts**: Receive and send timeout settings
   - **Keepalive**: TCP keepalive configuration
   - **Nodelay**: TCP nodelay option
   - **Error handling**: Exception raising on errors
   - **DNS resolution**: Hostname to address resolution

#### SocketDgram Module Tests (`test_socketdgram.c`)
   - **Datagram socket creation**: UDP socket creation
   - **Sendto/Recvfrom**: Datagram send and receive
   - **Connected mode**: Connect datagram socket
   - **Address handling**: Peer address retrieval
   - **Error handling**: Exception handling for datagram operations

### 3. **Unit Tests for Buffer Operations**

#### SocketBuf Module Tests (`test_socketbuf.c`)
   - **Buffer creation**: Create buffer with various capacities
   - **Buffer writing**: Write data to buffer
   - **Buffer reading**: Read data from buffer
   - **Circular buffer**: Wraparound behavior
   - **Buffer capacity**: Full buffer handling
   - **Buffer clearing**: Clear buffer contents
   - **Zero-copy operations**: Direct buffer pointer access
   - **Buffer size limits**: SIZE_MAX/2 limit enforcement
   - **Edge cases**: Empty buffer, full buffer, single-byte buffer

### 4. **Unit Tests for Event Polling**

#### SocketPoll Module Tests (`test_socketpoll.c`)
   - **Poll creation**: Create poll instance with max events
   - **Socket addition**: Add sockets to poll set
   - **Socket modification**: Modify socket events
   - **Socket removal**: Remove sockets from poll set
   - **Event waiting**: Wait for events with timeout
   - **Event translation**: Platform-specific event translation
   - **Edge-triggered mode**: Edge-triggered event handling
   - **Multiple events**: Handling multiple simultaneous events
   - **Error events**: Error and hangup event handling

### 5. **Unit Tests for Connection Pooling**

#### SocketPool Module Tests (`test_socketpool.c`)
   - **Pool creation**: Create pool with max connections
   - **Connection retrieval**: Get connection by socket
   - **Connection management**: Add and remove connections
   - **Hash table operations**: O(1) lookup verification
   - **Connection cleanup**: Idle connection cleanup
   - **Thread safety**: Concurrent pool access
   - **Pool limits**: Maximum connection enforcement

### 6. **Unit Tests for DNS Resolution**

#### SocketDNS Module Tests (`test_socketdns.c`)
   - **DNS resolution**: Resolve hostname to address
   - **Async resolution**: Asynchronous DNS resolution
   - **Resolution timeout**: Timeout handling
   - **Error handling**: Invalid hostname handling
   - **Thread pool**: Worker thread functionality
   - **Request queue**: Thread-safe request queuing
   - **Completion signaling**: Completion notification

### 7. **Error Path Testing**

#### Exception Handling Error Paths
   - **Allocation failures**: Arena allocation failures
   - **System call failures**: Socket, bind, listen, accept failures
   - **Network errors**: Connection errors, timeouts
   - **Invalid inputs**: NULL pointers, invalid parameters
   - **Resource exhaustion**: Memory exhaustion scenarios
   - **Cleanup verification**: Verify cleanup in all error paths

#### Memory Allocation Error Paths
   - **Arena allocation failures**: `Arena_new()` returns NULL
   - **Object allocation failures**: `ALLOC()` returns NULL
   - **Overflow conditions**: Size overflow before allocation
   - **Cleanup on failure**: Verify no leaks when allocation fails
   - **Exception path cleanup**: Verify Arena disposal in exception paths

### 8. **Edge Case Testing**

#### Socket Edge Cases
   - **Zero port**: Port 0 handling (system-assigned port)
   - **Maximum port**: Port 65535 handling
   - **Invalid addresses**: Malformed IP addresses
   - **Very long hostnames**: Hostname length limits
   - **Unix domain paths**: Path length limits, special characters
   - **Empty buffers**: Zero-length send/receive operations
   - **Large buffers**: Maximum buffer size operations

#### Buffer Edge Cases
   - **Empty buffer**: Operations on empty buffer
   - **Full buffer**: Operations on full buffer
   - **Single-byte buffer**: Minimal buffer size
   - **Maximum buffer**: SIZE_MAX/2 limit
   - **Wraparound**: Circular buffer wraparound scenarios

#### Thread Safety Edge Cases
   - **Concurrent allocation**: Multiple threads allocating from same Arena
   - **Concurrent socket operations**: Multiple threads using same socket (should fail or be safe)
   - **Exception handling**: Exception handling in multithreaded context
   - **Thread-local storage**: Thread-local error buffers

## Test Output Format

For each test case, provide:

1. **Test Name**: Descriptive name following pattern `test_module_function_scenario`
2. **Category**: Unit Test / Error Path / Memory Failure / Edge Case / Thread Safety
3. **Function Under Test**: Function name being tested
4. **Test Setup**: Initial conditions, input data, Arena allocation
5. **Test Execution**: Function call with parameters, TRY block if needed
6. **Expected Behavior**: Expected return value, exception, side effects
7. **Assertions**: Specific checks to verify correctness
8. **Cleanup**: Verify Arena disposal, resource cleanup

## Test Code Structure

### Test Framework Pattern
```c
#include <assert.h>
#include "test/Test.h"
#include "core/Arena.h"
#include "socket/Socket.h"

/* Test basic socket creation */
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

### Test File Organization
- **test_arena.c**: Tests for Arena module
- **test_except.c**: Tests for Exception module
- **test_socket.c**: Tests for Socket module
- **test_socketbuf.c**: Tests for SocketBuf module
- **test_socketpoll.c**: Tests for SocketPoll module
- **test_socketpool.c**: Tests for SocketPool module
- **test_socketdns.c**: Tests for SocketDNS module
- **test_socketdgram.c**: Tests for SocketDgram module

## Test Case Templates

### Unit Test Template
```c
/**
 * test_module_function_scenario() - Test description
 *
 * Verifies that ModuleName_function() correctly handles scenario.
 * Tests specific behavior with given inputs and validates outputs.
 */
TEST(module_function_scenario)
{
    Arena_T arena = Arena_new();
    ASSERT_NOT_NULL(arena);
    
    TRY
        // Setup
        Type_T object = ALLOC(arena, sizeof(*object));
        ASSERT_NOT_NULL(object);
        
        // Execution
        int result = ModuleName_function(object);
        
        // Assertions
        ASSERT_EQUAL(result, EXPECTED_VALUE);
        // Additional assertions
        
    EXCEPT(Module_Failed)
        ASSERT_FAIL("Operation should not fail");
    FINALLY
        Arena_dispose(&arena);
    END_TRY;
}
```

### Error Path Test Template
```c
/**
 * test_module_function_error_scenario() - Test error handling
 *
 * Verifies that ModuleName_function() correctly handles error condition.
 * Ensures proper exception raising and resource cleanup.
 */
TEST(module_function_error_scenario)
{
    Arena_T arena = Arena_new();
    ASSERT_NOT_NULL(arena);
    
    TRY
        // Setup error condition
        Type_T object = NULL;  // Invalid input
        
        // Execution
        ModuleName_function(object);  // Should raise exception
        
        ASSERT_FAIL("Should have raised exception");
        
    EXCEPT(Module_Failed)
        // Verify exception was raised
        ASSERT_NOT_NULL(Module_GetLastError());
    FINALLY
        Arena_dispose(&arena);
    END_TRY;
}
```

### Thread Safety Test Template
```c
/**
 * test_module_function_thread_safety() - Test thread safety
 *
 * Verifies that ModuleName_function() is thread-safe.
 * Tests concurrent access from multiple threads.
 */
TEST(module_function_thread_safety)
{
    Arena_T arena = Arena_new();
    ASSERT_NOT_NULL(arena);
    
    // Create multiple threads
    // Each thread performs operations
    // Verify no race conditions or corruption
    // Verify correct results
    
    Arena_dispose(&arena);
}
```

## Test Execution Guidelines

### Test Function Requirements
- Each test function should be independent (no shared state)
- Tests should be idempotent (repeatable)
- Use descriptive test function names
- Include setup (Arena allocation) and cleanup (Arena disposal) in each test
- Use TRY/EXCEPT/FINALLY for exception testing
- Verify both success and failure paths
- Check memory leaks (verify Arena disposal)

### Test Data Requirements
- Use realistic socket addresses and ports
- Include both valid and invalid inputs
- Test boundary conditions (0, max, empty, NULL)
- Use const data where possible
- Avoid hardcoded magic numbers (use constants from SocketConfig.h)

### Exception Verification
- Verify exceptions are raised on errors
- Verify correct exception types (`Socket_Failed`, `SocketPoll_Failed`, etc.)
- Check thread-local error messages are set correctly
- Verify cleanup in exception paths (FINALLY blocks)

### Memory Safety Verification
- All Arenas must be disposed
- No double-dispose vulnerabilities
- No use-after-free issues
- NULL pointer checks before dereferencing
- Buffer overflow prevention verified

## Socket Library-Specific Test Requirements

### Arena Usage in Tests
- Always create Arena at test start
- Allocate test objects from Arena
- Dispose Arena at test end (in FINALLY if using TRY)
- Verify no memory leaks

### Exception Testing
- Use TRY/EXCEPT/FINALLY blocks for exception testing
- Verify exceptions are raised with correct types
- Check error messages are set correctly
- Verify cleanup happens in FINALLY blocks

### Thread Safety Testing
- Test concurrent Arena allocation
- Test concurrent socket operations (where applicable)
- Verify thread-local storage works correctly
- Test mutex protection

## Focus Areas by Module

### Arena Module
- Allocation and disposal correctness
- Overflow protection
- Thread safety
- Alignment guarantees

### Socket Module
- Socket operations (bind, listen, accept, connect)
- Socket options
- DNS resolution
- Error handling

### SocketBuf Module
- Circular buffer correctness
- Wraparound behavior
- Buffer limits
- Zero-copy operations

### SocketPoll Module
- Event polling
- Platform-specific backends
- Event translation
- Edge-triggered mode

### SocketPool Module
- Connection management
- Hash table operations
- Thread safety
- Cleanup operations

## Test Coverage Goals

- **Function coverage**: All public functions tested
- **Branch coverage**: All exception paths tested
- **Edge case coverage**: Boundary conditions tested
- **Memory safety**: All allocation/deallocation paths verified
- **Exception handling**: All exception types verified
- **Thread safety**: Concurrent operations tested
- **Integration**: Multi-module workflows tested

Generate comprehensive test cases that validate correctness, error handling, memory safety, thread safety, and edge case behavior while maintaining C Interfaces and Implementations style and following socket library conventions. All tests should use Arena allocation and exception-based error handling patterns.
