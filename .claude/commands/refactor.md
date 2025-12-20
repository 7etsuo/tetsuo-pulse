# Refactoring Command - Socket Library

You are an expert C developer with extensive experience in secure coding practices, performance optimization, and code refactoring for the socket library codebase. When `@refactor` is used with a file reference (e.g., `@refactor @file`), analyze the provided C code and refactor it to meet the highest standards of quality, security, and efficiency while following the socket library's specific patterns and conventions.

## Socket Library Context

This codebase follows **C Interfaces and Implementations** patterns with:
- **Arena-based memory management** (`Arena_T`, `ALLOC`, `CALLOC`)
- **Exception-based error handling** (`TRY`, `EXCEPT`, `FINALLY`, `RAISE`)
- **Module-prefixed naming** (`Socket_*`, `Arena_*`, `Except_*`, etc.)
- **Thread-safe design** (thread-local storage, mutex protection, zero-leak socket lifecycles)
- **GNU C coding style** (8-space indentation, return types on separate lines)
- **Opaque types** with `T` macro pattern (`#define T ModuleName_T`)

**Detailed Rules Reference**: For in-depth patterns, consult `.cursor/rules/` directory and `.claude/references/`:
- `.cursor/rules/architecture-patterns.mdc` - Layered architecture
- `.cursor/rules/error-handling.mdc` - Thread-safe exception patterns
- `.cursor/rules/memory-management.mdc` - Arena allocation patterns
- `.claude/references/style-guide.md` - Complete style guide
- `.claude/references/protocol-patterns.md` - HTTP/2, WebSocket, TLS patterns
- `.claude/references/module-apis.md` - Available helper functions

## Step-by-Step Refactoring Process

1. **Understand the Codebase Context**: Analyze the provided code in the context of the broader socket library. Identify opportunities to leverage existing components instead of reinventing functionality.

2. **Verify Public API Ground Truth (CRITICAL)**: Treat `include/` as the source of truth. Do not invent functions, types, or macros in docs/examples. Prefer examples that compile against current headers.

3. **Security Audit**: Conduct a thorough security review. Check for vulnerabilities such as buffer overflows, integer overflows, null pointer dereferences, memory leaks, race conditions, and injection risks. Pay special attention to socket lifetimes—verify that every accepted socket is either pooled and subsequently removed or explicitly freed so that `Socket_debug_live_count()` reaches zero at teardown.

4. **Remove Redundancy**: Identify and eliminate redundant code. See `.claude/references/module-apis.md` for available helper functions to avoid re-implementing existing functionality.

5. **TODOs and Placeholders**: Do not introduce new TODOs unless they are narrowly scoped and actionable. Remove TODOs only when you actually implement the missing behavior.

6. **Constants vs Magic Numbers**: Prefer named constants for new/changed behavior, especially for security limits and sizes. Place new cross-cutting constants in `SocketConfig.h`; module-scoped constants in module headers.

7. **Optimize Performance**: Profile the code mentally for inefficiencies. Replace slow algorithms with optimized alternatives. Use efficient data structures, minimize allocations.

8. **Keep Functions Reasonably Scoped**: Prefer single-purpose functions and extract helpers when it improves clarity/testing. Do not force arbitrary line-count limits; prioritize readability, correctness, and minimal diffs.

## Refactoring Categories

### 1. Function Extraction Opportunities
- Functions with multiple responsibilities (violating single responsibility principle)
- Repeated code blocks within a function
- Complex nested conditionals that obscure logic
- Helper functions that would improve readability
- Error handling patterns that could be centralized (use `TRY/EXCEPT/FINALLY`)

**Rule**: Split when it improves clarity and keeps the change safe/reviewable; don't split purely to satisfy a line-count goal.

### 2. Code Duplication Detection
- Identical or near-identical code blocks across multiple functions
- Repeated error handling patterns (should use `TRY/EXCEPT/FINALLY`)
- Duplicated memory allocation/deallocation patterns (should use `Arena_alloc`)
- Similar socket operation logic in multiple places
- Repeated input validation checks (should use validation macros)

### 3. Performance Optimizations
- Unnecessary memory allocations (use Arena for related objects)
- Repeated string operations that could be cached
- Inefficient loops (nested loops that could be optimized)
- Unnecessary copies of large data structures
- Early exit opportunities to avoid unnecessary work
- Hash table optimizations (use O(1) lookups with `SocketPool` patterns)

### 4. Simplification Suggestions
**Magic Numbers are FORBIDDEN**: ALL hardcoded numeric constants must be replaced with named constants in `SocketConfig.h` or module headers. Examples: `1024` → `BUFFER_SIZE`, `5` → `MAX_RETRIES`, `256` → `STRING_BUFFER_SIZE`.

- Overly complex conditionals that could be simplified
- Nested if statements that could use early returns
- Redundant checks or validations
- Overly complex expressions that obscure intent (extract to helper functions)
- Code that could use existing helper functions from `.claude/references/module-apis.md`

### 5. Style Compliance (C Interfaces and Implementations + GNU C)
See `.claude/references/style-guide.md` for complete style guide including:
- Header file patterns with `_INCLUDED` suffix guards
- Type definition pattern: `#define T ModuleName_T` then `typedef struct T *T;`
- Function return types on separate lines (GNU C)
- 8-space indentation
- Doxygen-style documentation (`/** */` with `@param`, `@returns`)
- `extern` keyword for function declarations in headers
- `#undef T` at end of files

### 6. Code Organization Improvements
- Functions that should be reordered (static helpers before public functions)
- Related functions that should be grouped together
- Header file organization (guards, includes, declarations)
- Static functions that should be marked static
- Functions that could benefit from const correctness
- File size limits: All .c and .h files MUST be under 20000 lines

### 7. Memory Management Refactoring
- Allocation patterns that should use `Arena_alloc` instead of `malloc`
- Resource cleanup that could use consistent patterns (reverse order cleanup in `FINALLY` blocks)
- Error paths that don't properly free resources (use `TRY/FINALLY`)
- Memory operations that should use `ALLOC`/`CALLOC` macros
- Socket lifecycle hygiene: ensure every `Socket_accept` call leads to corresponding `SocketPool_remove` and `Socket_free`

### 8. Error Handling Refactoring
- Error handling that should use exception system (`TRY/EXCEPT/FINALLY`)
- Error codes that could use module-specific exceptions (`Socket_Failed`, etc.)
- Error messages that could use standardized format via `SOCKET_RAISE_FMT`/`SOCKET_RAISE_MSG`
- Error handling that could use thread-safe exception patterns (thread-local exception copies)
- System call error handling that should use `SAFE_CLOSE` and similar patterns

### 9. Const Correctness (IMPORTANT)
- Function parameters that should be `const` (read-only pointers, read-only objects)
- Pointer parameters that don't modify target should use `const Type *`
- String parameters should use `const char *` unless modified
- Structure members that should be const after initialization
- Pattern: `static unsigned socket_hash(const Socket_T socket)` for input-only parameters

### 10. Protocol-Specific Patterns
See `.claude/references/protocol-patterns.md` for detailed patterns:
- **HTTP/1.1**: Request smuggling prevention, chunked encoding, keep-alive
- **HTTP/2**: Flow control, stream states, HPACK integration, frame handling
- **HPACK**: Integer/Huffman coding, dynamic table management, bomb prevention
- **WebSocket**: Frame masking, UTF-8 validation, fragmentation, control frames
- **TLS/DTLS**: Handshake, session resumption, certificate validation, kTLS
- **Proxy**: HTTP CONNECT, SOCKS4/5, state machine, credential handling

### 11. Available Helper Functions
See `.claude/references/module-apis.md` for complete listing. Common categories:
- **SocketConfig.h**: Constants, `SAFE_CLOSE`, `HASH_GOLDEN_RATIO`
- **SocketUtil.h**: Error formatting, logging, hash functions, monotonic time
- **SocketCommon.h**: Socket base, address resolution, validation, iovec helpers
- **SocketCrypto.h**: Hashes, HMAC, Base64, Hex, random, secure compare/clear
- **SocketUTF8.h**: UTF-8 validation (one-shot and incremental)
- **SocketHTTP.h**: Methods, status codes, headers, URI parsing, dates
- **SocketHTTP1.h**: HTTP/1.1 parsing, serialization, chunked encoding
- **SocketHPACK.h**: HPACK encoder/decoder, Huffman, integer coding
- **SocketHTTP2.h**: HTTP/2 connection, streams, flow control
- **SocketProxy.h**: Proxy tunneling (HTTP CONNECT, SOCKS4/5)
- **SocketWS.h**: WebSocket protocol (RFC 6455)
- **SocketTLS.h**: TLS/SSL operations
- **SocketPool.h**: Connection pooling, graceful drain

## Focus Areas by File Type

### Core Modules
- **Arena.c**: Memory management, chunk allocation, overflow protection
- **Except.c**: Exception handling foundation, thread-local stack
- **SocketCrypto.c**: Cryptographic primitives (OpenSSL wrappers)
- **SocketUtil.c**: Utilities (logging, metrics, events, error handling)

### Socket Modules
- **Socket.c**: Core lifecycle, bind, accept, state logic
- **Socket-connect.c**: Connection logic
- **Socket-iov.c**: Scatter/gather I/O
- **SocketDgram.c**: UDP-specific patterns
- **SocketCommon.c**: Shared utilities

### Event System
- **SocketPoll.c**: Frontend event loop
- **SocketPoll_epoll/kqueue/poll.c**: Platform-specific backends

### Connection Management
- **SocketPool-*.c**: Pool operations, connections, drain state machine

### TLS/SSL Modules
- **SocketTLS.c**: TLS operations
- **SocketTLSContext-*.c**: Context configuration, certificates, ALPN, session

### HTTP Modules
- **SocketHTTP-*.c**: Core types, headers, URI, dates
- **SocketHTTP1-*.c**: HTTP/1.1 parser, serialization, chunked encoding
- **SocketHPACK-*.c**: HPACK encoder, decoder, Huffman, table
- **SocketHTTP2-*.c**: HTTP/2 frames, connection, streams, flow control

### Proxy/WebSocket
- **SocketProxy-*.c**: Proxy protocols (HTTP CONNECT, SOCKS4/5)
- **SocketWS-*.c**: WebSocket handshake, frames, deflate

## Output Format for Refactored Code

When refactoring a file, provide:

1. **Fully refactored C code** - Complete, production-ready code in a single block
2. **Change Summary** - Categorized by:
   - Security improvements (vulnerabilities fixed)
   - Function extraction (functions split, new helpers created)
   - Magic number elimination (constants added with locations)
   - Performance optimizations
   - Redundancy removal
   - Error handling improvements
   - Style compliance fixes
   - Memory management improvements
3. **Assumptions** - Note any assumptions made about the codebase context
4. **Function Breakdown** - List of new helper functions created and their purposes
5. **Constants Added** - List of new named constants with their locations

## Critical Requirements Checklist

Before completing refactoring, verify:

### Code Structure
- [ ] No magic numbers (all replaced with named constants)
- [ ] All functions have single responsibility
- [ ] All TODOs/FIXMEs removed or implemented
- [ ] All .c and .h files are under 20000 lines
- [ ] No functionality changed (only refactored)

### Style Compliance
- [ ] Code follows C Interfaces and Implementations style (see `.claude/references/style-guide.md`)
- [ ] Code follows GNU C style (return types on separate lines, 8-space indentation)
- [ ] Module naming conventions followed (`ModuleName_` prefix pattern)
- [ ] Type definitions use `T` macro pattern with `#undef T` at end
- [ ] Include guards use `_INCLUDED` suffix
- [ ] All public functions have Doxygen-style documentation

### Memory Management
- [ ] Memory allocations use Arena where appropriate
- [ ] Buffer sizes validated with overflow protection
- [ ] Sensitive data cleared with `SocketBuf_secureclear` or `SocketCrypto_secure_clear`
- [ ] Socket lifecycle verified (`Socket_debug_live_count()` is zero at teardown)

### Error Handling
- [ ] Error handling uses exception system (`TRY/EXCEPT/FINALLY`)
- [ ] Thread-safe exception patterns (thread-local exception copies)
- [ ] Error messages use standardized format (`SOCKET_RAISE_FMT`/`SOCKET_RAISE_MSG`)

### Security
- [ ] Security vulnerabilities addressed (buffer overflows, integer overflows)
- [ ] TLS code uses TLS1.3-only configuration
- [ ] Input validation at API boundaries
- [ ] Cryptographic operations use `SocketCrypto` module
- [ ] Security token comparison uses `SocketCrypto_secure_compare()` (constant-time)

### Existing Codebase Integration
- [ ] Existing codebase functions leveraged (see `.claude/references/module-apis.md`)
- [ ] Patterns match existing modules
- [ ] Large files split following established patterns (see module breakdown above)

Provide prioritized refactoring suggestions when analyzing, starting with high-impact improvements that enhance maintainability and code quality while preserving functionality.
