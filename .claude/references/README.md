# Shared Reference Material

This directory contains extracted shared reference material from the large command files to reduce redundancy and improve maintainability.

## Reference Files

### 1. simple-api.md
Complete API reference for the Simple API layer - return-code-based convenience wrappers.

**Contents**:
- Error handling (Socket_simple_error, Socket_simple_code)
- TCP socket operations (connect, listen, accept, send, recv)
- UDP socket operations (sendto, recvfrom, multicast)
- TLS functions (connect_tls, enable_tls, session resumption)
- HTTP client (GET, POST, PUT, DELETE, JSON convenience)
- WebSocket client and server (connect, send, recv)
- DNS resolution (sync and async with caching)
- Poll event loop (add, mod, del, wait)
- Connection pool (rate limiting, graceful shutdown)
- Proxy tunneling (SOCKS4/5, HTTP CONNECT)

**Use when**: Writing simple applications, quick prototyping, or when exception handling is not desired.

### 2. module-apis.md (Exception-based API)
Complete API reference for all Socket library modules, extracted from command files for reuse.

**Contents**:
- SocketCommon helpers (shared socket utilities)
- SocketIO functions (vectored I/O)
- SocketCrypto functions (cryptographic primitives)
- SocketHTTP functions (HTTP core types and utilities)
- SocketHTTP1 functions (HTTP/1.1 parsing and serialization)
- SocketHPACK functions (HPACK compression for HTTP/2)
- SocketHTTP2 functions (HTTP/2 protocol)
- SocketWS functions (WebSocket protocol)
- SocketProxy functions (proxy tunneling)
- SocketTLS/DTLS functions (TLS/DTLS secure connections)
- SocketTLSContext functions (TLS context configuration)
- SocketUTF8 functions (UTF-8 validation)
- SocketUtil functions (logging, metrics, events, hash utilities)
- SocketRateLimit functions (token bucket rate limiting)
- SocketIPTracker functions (per-IP connection tracking)
- SocketTimer functions (timer subsystem)
- SocketReconnect functions (auto-reconnection with backoff)
- SocketHappyEyeballs functions (dual-stack connection racing)
- SocketPool functions (connection pool management)
- SocketDNS functions (async DNS resolution)
- SocketPoll functions (event polling abstraction)
- SocketSYNProtect functions (SYN flood protection)
- SocketHTTPClient functions (HTTP client)
- SocketHTTPServer functions (HTTP server)
- SocketBuf functions (circular buffer for efficient I/O)
- SocketDgram functions (UDP/datagram, multicast, broadcast)
- SocketAsync functions (async I/O with io_uring/kqueue)

**Use when**: Writing code that uses these modules, documenting APIs, or creating examples.

### 3. protocol-patterns.md
Implementation patterns for TLS, HTTP, WebSocket, and other protocols.

**Contents**:
- TLS lifecycle patterns (enable, handshake, shutdown, disable for STARTTLS)
- kTLS high-performance patterns (kernel TLS offload, zero-copy sendfile)
- Certificate pinning patterns
- Session resumption patterns (client and server)
- Long-lived connection forward secrecy (KeyUpdate, renegotiation control)
- DTLS server and client patterns (DoS protection with cookie exchange)
- Cryptographic patterns (SocketCrypto usage)
- File descriptor passing patterns (Unix domain sockets SCM_RIGHTS)
- HTTP header patterns (Headers API, URI parsing, date handling)
- Graceful shutdown patterns (SocketPool drain state machine)
- HTTP/1.1 message parsing patterns (incremental parser, chunked encoding)
- HPACK header compression patterns (encoder/decoder, Huffman, integer coding)
- Hash utility patterns (DJB2, golden ratio, power-of-2 rounding)
- HTTP/2 protocol patterns (connection, streams, SETTINGS, flow control, callbacks)
- Proxy tunneling patterns (HTTP CONNECT, SOCKS4/5, sync/async)
- WebSocket protocol patterns (handshake, messaging, control frames, event loop)
- UTF-8 validation patterns (one-shot and incremental)

**Use when**: Implementing protocol handlers, optimizing performance, or ensuring secure patterns.

### 4. security-limits.md
Security constants and limits from `SocketSecurity.h` and other security-critical headers.

**Contents**:
- Centralized security configuration (SocketSecurity.h API)
- Memory limits (max allocation, buffer size, arena size)
- HTTP limits (URI length, header size, header count)
- HTTP/1.1 limits (request line, chunk size, trailer size)
- HTTP/2 limits (concurrent streams, frame size, window size)
- HPACK limits (table size, header list size)
- WebSocket limits (frame size, message size, fragments)
- TLS limits (cert chain depth, SNI length, ALPN length, session cache)
- Rate limiting configuration (connections per second, max per IP)
- Timeout configuration (connect, DNS, TLS handshake)
- UDP/datagram limits (max payload, safe size for fragmentation)
- Unix domain socket limits (max FDs per message)
- Runtime limit query functions
- Compile-time override examples
- Security verification functions and macros
- TLS security configuration (protocol versions, cipher suites)
- HTTP/1.1 security limits (chunk extensions, trailers)
- HTTP/2 security limits (flow control)
- HPACK security limits (decompression)
- WebSocket security limits (control frames)
- Rate limiting configuration (token bucket)
- SYN protection limits (reputation thresholds)
- DNS resolution limits (queue size, worker threads)
- Connection pool limits (max connections, drain timeouts)

**Use when**: Configuring security limits, validating input sizes, or documenting security boundaries.

### 5. security-patterns.md
Security-focused implementation patterns and validation utilities.

**Contents**:
- SocketSecurity.h API (overflow protection, limit query, validation macros)
- Safe allocation patterns (Arena with overflow protection, buffer size validation)
- Overflow-safe arithmetic (addition, multiplication with checks)
- Input validation macros (port, buffer size)
- Cryptographic security patterns (constant-time comparison, secure clearing, CSPRNG)
- Thread-safe error handling (thread-local exceptions, error buffers)
- Safe system call patterns (SAFE_CLOSE, thread-safe strerror)
- HTTP/1.1 request smuggling prevention (CL/TE conflicts, multiple CL, TE validation, chunked encoding)
- HPACK bomb prevention (table size limits, header size limits, decompression ratio)
- HTTP/2 flow control security (window overflow, window exhaustion)
- WebSocket frame security (masking enforcement, frame validation, UTF-8 validation)
- UTF-8 security validation (overlong encoding, surrogate rejection, invalid code points)
- Proxy security patterns (credential handling, URL parsing)
- State machine security (valid transitions, atomic transitions, terminal state cleanup)
- Callback safety patterns (no module free from callback, no mutex held, thread context)
- Hash table security (collision attack mitigation, hash randomization)
- DoS protection patterns (rate limiting, per-IP tracking, circuit breaker, SYN flood)
- Timeout security (monotonic clock, operation timeouts)
- Resource limit enforcement (max connections, max message size, max pending requests)

**Use when**: Writing security-critical code, preventing attacks, or ensuring safe operations.

### 6. style-guide.md
C Interfaces and Implementations patterns and GNU C style guidelines.

**Contents**:
- Header file style (include guards, module documentation, include order, type definitions, function declarations)
- Implementation file style (module documentation, include order, function organization, documentation)
- GNU C style guidelines (indentation, line length, braces, spacing, pointer alignment)
- Naming conventions (types, public functions, private functions, constants, exceptions)
- Comment style (documentation comments, code comments, guidelines)
- Opaque type pattern (public vs private interface)
- T macro pattern (purpose, usage, benefits)
- Module prefix pattern (types, functions, constants, exceptions)
- Private header pattern (for split-file modules)
- File splitting pattern (SocketPool, SocketTLSContext examples)
- Consistency checklist (header files, implementation files, naming, formatting, documentation, code organization)
- Complete examples (header and implementation file templates)

**Use when**: Writing new code, refactoring existing code, or ensuring style compliance.

## Usage in Commands

Command files can now reference these shared materials instead of duplicating content:

```markdown
<!-- In command.md -->
For Simple API reference, see `.claude/references/simple-api.md`
For complete API reference, see `.claude/references/module-apis.md`
For protocol implementation patterns, see `.claude/references/protocol-patterns.md`
For security limits, see `.claude/references/security-limits.md`
For security patterns, see `.claude/references/security-patterns.md`
For style guidelines, see `.claude/references/style-guide.md`
```

## Benefits

1. **Reduced Redundancy**: Common content maintained in one place
2. **Easier Updates**: Change once, applies to all commands
3. **Smaller Command Files**: Focused on command-specific logic
4. **Better Organization**: Related content grouped together
5. **Faster Loading**: Claude can load smaller command files more efficiently

## Maintenance

When updating shared content:

1. Update the appropriate reference file in this directory
2. Verify all commands that reference it still work correctly
3. Keep reference files focused and well-organized
4. Add new sections as needed for new modules or patterns

## File Sizes

- `simple-api.md`: ~12KB (Simple API reference)
- `module-apis.md`: ~30KB (comprehensive API reference)
- `protocol-patterns.md`: ~14KB (implementation patterns)
- `security-limits.md`: ~9.5KB (limits and constants)
- `security-patterns.md`: ~16KB (security best practices)
- `style-guide.md`: ~14KB (coding standards)

Total: ~96KB of shared reference material extracted from commands
