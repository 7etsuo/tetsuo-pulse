# Refactoring Command - Socket Library

You are an expert C developer with extensive experience in secure coding practices, performance optimization, and code refactoring for the socket library codebase. When `@refactor` is used with a file reference (e.g., `@refactor @file`), analyze the provided C code and refactor it to meet the highest standards of quality, security, and efficiency while following the socket library's specific patterns and conventions.

## Socket Library Context

This codebase follows **C Interfaces and Implementations** patterns with:
- **Arena-based memory management** (`Arena_T`, `ALLOC`, `CALLOC`)
- **Exception-based error handling** (`TRY`, `EXCEPT`, `FINALLY`, `RAISE`)
- **Module-prefixed naming** (`Socket_*`, `Arena_*`, `Except_*`, `SocketPoll_*`, `SocketPool_*`, `SocketDNS_*`, `SocketTLS_*`, `SocketDgram_*`, `SocketTimer_*`, `SocketHTTP_*`, `SocketHTTP1_*`, `SocketHTTPClient_*`, `SocketHTTPServer_*`, `SocketUTF8_*`, `SocketProxy_*`, `SocketWS_*`)
- **Thread-safe design** (thread-local storage, mutex protection, and zero-leak socket lifecycles confirmed via `Socket_debug_live_count()`)
- **GNU C coding style** (8-space indentation, return types on separate lines)
- **Opaque types** with `T` macro pattern (`#define T ModuleName_T`)
- **TLS1.3-only security** (strict TLS version/cipher enforcement via `SocketTLSConfig.h`)
- **Cross-platform event backends** (epoll/kqueue/poll abstraction in SocketPoll)
- **Async DNS resolution** (non-blocking hostname resolution via `SocketDNS` thread pool)
- **UTF-8 validation** (DFA-based streaming validation via `SocketUTF8`)
- **HTTP Core** (RFC 9110 types, headers, URI parsing via `SocketHTTP`)

**Detailed Rules Reference**: For in-depth patterns, consult `.cursor/rules/` directory:
- `architecture-patterns.mdc` - Layered architecture and module design
- `async-dns.mdc` - Async DNS patterns and thread pool design
- `cross-platform-backends.mdc` - Event backend abstraction (epoll/kqueue/poll)
- `error-handling.mdc` - Thread-safe exception patterns
- `happy-eyeballs.mdc` - RFC 8305 dual-stack connection racing
- `memory-management.mdc` - Arena allocation and overflow protection
- `module-patterns.mdc` - Module design patterns for each component
- `reconnection.mdc` - Auto-reconnection with backoff and circuit breaker
- `udp-sockets.mdc` - UDP/datagram-specific patterns
- `unix-domain-sockets.mdc` - AF_UNIX socket patterns

## Step-by-Step Refactoring Process

1. **Understand the Codebase Context**: Analyze the provided code in the context of the broader socket library. Identify opportunities to leverage existing components instead of reinventing functionality:
   - **Foundation Layer**: Arena (memory), Except (errors), SocketConfig (constants), SocketCrypto (cryptographic primitives)
   - **Utilities Layer**: SocketUtil (logging/metrics/events), SocketCommon (shared helpers), SocketUTF8 (UTF-8 validation)
   - **Protection Layer**: SocketRateLimit (throttling), SocketIPTracker (per-IP limits), SocketSYNProtect (SYN flood)
   - **Core I/O Layer**: Socket, SocketDgram, SocketBuf, SocketDNS, SocketIO
   - **Event Layer**: SocketPoll (epoll/kqueue/poll), SocketTimer (timers)
   - **Resilience Layer**: SocketReconnect (auto-reconnect), SocketHappyEyeballs (dual-stack)
   - **Application Layer**: SocketPool (connection management)
   - **TLS Layer**: SocketTLS, SocketTLSContext (secure connections)
   - **HTTP Layer**: SocketHTTP (RFC 9110 types), SocketHTTP1 (HTTP/1.1 RFC 9112), SocketHPACK (RFC 7541), SocketHTTP2 (HTTP/2 RFC 9113), SocketHTTPClient (Client API), SocketHTTPServer (Server API)
   
   Ensure code builds upon foundational elements and reuses existing patterns, avoiding duplication.

2. **Verify Public API Ground Truth (CRITICAL)**: Treat `include/` as the source of truth.
   - Do **not** invent functions, types, or macros in docs/examples.
   - If changing public behavior, confirm it matches the declared API in headers.
   - Prefer examples that compile against current headers (especially for README/docs).

2. **Security Audit**: Conduct a thorough security review. Check for vulnerabilities such as buffer overflows, integer overflows, null pointer dereferences, memory leaks, race conditions, and injection risks. Use secure coding patterns (bounds checking, safe string handling with `snprintf`, overflow protection before arithmetic). Eliminate any insecure practices and suggest hardened alternatives. Pay special attention to socket lifetimes—verify that every accepted socket is either pooled and subsequently removed or explicitly freed so that `Socket_debug_live_count()` reaches zero at teardown.

3. **Remove Redundancy**: Identify and eliminate redundant code, including duplicated logic, unused variables, or unnecessary computations. Consolidate similar operations into reusable functions if they align with the codebase patterns (e.g., reuse Arena allocation, exception handling patterns).

4. **TODOs and Placeholders**: Do not introduce new TODOs unless they are narrowly scoped and actionable.
   - Remove TODOs only when you actually implement the missing behavior.
   - If a TODO is out of scope for the refactor, keep it and avoid “drive-by” rewrites that change behavior.

5. **Constants vs Magic Numbers**: Prefer named constants for new/changed behavior, especially for security limits and sizes.
   - Avoid churn: do not rewrite large files solely to replace existing numbers that are already documented or used consistently.
   - Place new cross-cutting constants in `SocketConfig.h`; module-scoped constants in module headers/private headers.

6. **Optimize Performance**: Profile the code mentally for inefficiencies. Replace slow algorithms with optimized alternatives. Use efficient data structures, minimize allocations, and apply compiler optimizations hints if relevant. Ensure the code is performant without sacrificing readability or security.

7. **Keep Functions Reasonably Scoped**: Prefer single-purpose functions and extract helpers when it improves clarity/testing.
   - Do not force arbitrary line-count limits; prioritize readability, correctness, and minimal diffs.
   - Avoid refactors that balloon the number of tiny helpers without improving understanding.

## Refactoring Categories

### 1. **Function Extraction Opportunities**
   - Break down functions that are doing multiple responsibilities or are hard to read/test.
   - Functions with multiple responsibilities (violating single responsibility principle) - Each function should do ONE thing.
   - Repeated code blocks within a function that could be extracted - Extract immediately.
   - Complex nested conditionals that obscure logic - Extract to named helper functions.
   - Helper functions that would improve readability - Extract aggressively.
   - Error handling patterns that could be centralized - Use exception system (`TRY/EXCEPT/FINALLY`).
   - Input validation logic that could be separated - Extract validation into separate functions.
   - Socket operation patterns that could be abstracted - Create reusable socket wrappers.
   - Parsing logic that could be modularized - Break parsing into small, focused functions.
   - Memory management patterns that should use Arena - Replace `malloc`/`free` with `Arena_alloc`/`Arena_dispose`.
   - **Rule**: Split when it improves clarity and keeps the change safe/reviewable; don’t split purely to satisfy a line-count goal.

### 2. **Code Duplication Detection**
   - Identical or near-identical code blocks across multiple functions
   - Repeated error handling patterns (should use `TRY/EXCEPT/FINALLY`)
   - Duplicated memory allocation/deallocation patterns (should use `Arena_alloc`)
   - Similar socket operation logic in multiple places
   - Repeated input validation checks (should use validation macros)
   - Common string manipulation operations
   - Similar error message formatting (should use `MODULE_ERROR_FMT`/`MODULE_ERROR_MSG`)
   - Common initialization patterns
   - Repeated DNS resolution patterns (should use `SocketDNS` module)

### 3. **Performance Optimizations**
   - Unnecessary memory allocations (use Arena for related objects, allocate once, reuse if possible)
   - Repeated string operations that could be cached
   - Inefficient loops (nested loops that could be optimized)
   - Unnecessary copies of large data structures
   - Repeated function calls with same parameters
   - Socket I/O operations that could be batched
   - String concatenation in loops (use pre-allocated buffers or Arena)
   - Memory reallocation patterns (Arena handles this automatically)
   - Unnecessary pointer dereferences in loops
   - Cache-unfriendly memory access patterns
   - Early exit opportunities to avoid unnecessary work
   - Switch statements vs if-else chains for performance
   - Hash table optimizations (use O(1) lookups with `SocketPool` patterns)

### 4. **Simplification Suggestions (Magic Numbers are FORBIDDEN)**
   - Overly complex conditionals that could be simplified
   - Nested if statements that could use early returns
   - **MAGIC NUMBERS MUST BE ELIMINATED** - ALL hardcoded numeric constants must be replaced with named constants. Examples: `1024` → `#define BUFFER_SIZE 1024` in `SocketConfig.h`, `5` → `#define MAX_RETRIES 5`, `256` → `#define STRING_BUFFER_SIZE 256`. Place constants in `SocketConfig.h` or module-specific headers.
   - Redundant checks or validations
   - Overly complex expressions that obscure intent - Extract to helper functions with descriptive names.
   - Unnecessary temporary variables
   - Code that could use existing helper functions - Always prefer reusing existing functions over reinventing (e.g., use `Arena_alloc` instead of `malloc`, use `SocketDNS` instead of manual DNS resolution).
   - Redundant error handling (same error checked multiple times) - Use exception system.
   - Over-abstracted code that adds unnecessary indirection
   - Complex pointer arithmetic that could be clearer - Extract to helper functions.
   - Multi-line expressions that could be clearer - Break into multiple statements or extract to function.
   - Boolean logic that could be simplified (De Morgan's laws) - Or extract to named helper function.

### 5. **C Interfaces and Implementations Style Compliance (CRITICAL)**
   This codebase follows **C Interfaces and Implementations** (Hanson, 1996) patterns strictly. All refactoring must maintain this style.
   
   **Header File Style (`*.h`)**:
   - Include guards MUST use `FILENAME_INCLUDED` suffix pattern (e.g., `ARENA_INCLUDED`, `EXCEPT_INCLUDED`)
   - Module documentation at top with comprehensive description, features, usage examples
   - System headers included first (before any project headers)
   - Type definition pattern: `#define T ModuleName_T` then `typedef struct T *T;`
   - Function declarations MUST use `extern` keyword
   - Doxygen-style function documentation: `/**` comments with `@param`, `@returns`, etc.
   - Constants and macros defined after type definitions
   - `#undef T` at end of header file before `#endif`
   - No implementation details exposed (opaque types only)
   
   **Implementation File Style (`*.c`)**:
   - Module documentation comment at top: `/** * ModuleName.c - Description */`
   - Comment: `/* Part of the Socket Library */` and `/* Following C Interfaces and Implementations patterns */`
   - Includes: system headers first (alphabetical or logical order), then project headers
   - `#define T ModuleName_T` at top of file
   - Static helper functions before public functions
   - Function return types on separate line (GNU C style requirement)
   - Doxygen-style comments for all functions (public and static)
   - Function parameters documented with `@param`, return values with `Returns:`, exceptions with `Raises:`
   - Thread safety notes where applicable: `Thread-safe: Yes/No`
   - `#undef T` at end of implementation file
   - No trailing whitespace
   
   **Function Documentation Style**:
   ```c
   /**
    * FunctionName - Brief description of function purpose
    * @param1: Description of first parameter
    * @param2: Description of second parameter
    *
    * Returns: Description of return value (or void)
    * Raises: Description of exceptions that may be raised
    * Thread-safe: Yes/No with explanation if applicable
    *
    * Additional implementation details, usage notes, or constraints.
    */
   ```
   
   **Type Definition Style**:
   ```c
   /* In header file */
   #define T ModuleName_T
   typedef struct T *T;  /* Opaque pointer type */
   
   /* In implementation file */
   #define T ModuleName_T
   struct T {
       /* Structure members */
   };
   #undef T  /* At end of file */
   ```
   
   **Function Declaration Style**:
   ```c
   /* In header - MUST use extern */
   extern T ModuleName_new(void);
   extern void ModuleName_free(T *instance);
   
   /* In implementation - return type on separate line */
   T
   ModuleName_new(void)
   {
       /* Implementation */
   }
   ```
   
   **Comment Style**:
   - Use `/** */` for documentation comments (functions, modules)
   - Use `/* */` for code comments
   - Use `//` sparingly, only for very short inline comments
   - Comments should explain WHY, not WHAT (code should be self-documenting)
   
   **Spacing and Formatting**:
   - Space after `if`, `while`, `for`, `switch`
   - Space around operators (`=`, `==`, `+`, etc.)
   - No space before semicolon
   - Function name immediately after return type (on same line for declarations)
   - Return type on separate line for function definitions (GNU C style)
   - Opening brace on same line for functions, control structures
   - Consistent indentation (8 spaces per level)

### 6. **GNU C Style Compliance**
   - 8-space indentation (tabs or spaces, but consistent)
   - Functions exceeding 80 column limit
   - Function return types not on separate lines
   - Inconsistent brace placement
   - Pointer alignment issues (use `type *ptr` not `type* ptr`)
   - Inconsistent spacing around operators
   - Inconsistent spacing in function calls/declarations
   - Header organization (system headers first, then project headers in `include/` order)
   - Inconsistent naming conventions (must follow module prefix pattern)
   - Function definitions that don't follow GNU style
   - Struct/union formatting inconsistencies
   - Missing `#undef T` at end of implementation files

### 7. **Code Organization Improvements**
   - Functions that should be reordered (static helpers before public functions)
   - Related functions that should be grouped together
   - Forward declarations that could improve compilation
   - Header file organization (guards with `_INCLUDED` suffix, includes, declarations)
   - Static functions that should be marked static
   - Functions that could benefit from const correctness
   - Unused parameters that should cast to void: `(void)param;`
   - Functions that could be moved to more appropriate files
   - Header dependencies that could be reduced
   - Circular dependencies between headers
   - File size limits: All .c and .h files MUST be under 20000 lines of code
   - File purpose: Each .c and .h file must serve a single purpose and not handle multiple unrelated concerns
   - Large file refactoring: Files exceeding 20000 lines must implement a plan to break into smaller, focused files

### 8. **Memory Management Refactoring**
   - Allocation patterns that should use `Arena_alloc` instead of `malloc`
   - Memory management that could be centralized (use Arena for related objects)
   - Resource cleanup that could use consistent patterns (reverse order cleanup in `FINALLY` blocks)
   - Error paths that don't properly free resources (use `TRY/FINALLY`)
   - Memory management that could benefit from Arena disposal patterns
   - Allocation sizes that could be calculated more safely (use overflow protection macros)
   - Buffer management that could use `SocketBuf` module
   - Memory operations that should use `ALLOC`/`CALLOC` macros
   - Socket lifecycle hygiene: ensure every `Socket_accept` call leads to a corresponding `SocketPool_remove` (when applicable) and `Socket_free`, and confirm integration/tests leave `Socket_debug_live_count()` at zero.

### 9. **Error Handling Refactoring**
   - Error handling that should use exception system (`TRY/EXCEPT/FINALLY`)
   - Error codes that could use module-specific exceptions (`Socket_Failed`, `SocketPoll_Failed`, etc.)
   - Error propagation that could use `RAISE` instead of return codes
   - Error handling that could use thread-local error buffers (`socket_error_buf`, `MODULE_ERROR_FMT`)
   - Error messages that could use standardized format via `MODULE_ERROR_FMT`/`MODULE_ERROR_MSG`
   - Error handling that could use thread-safe exception patterns (thread-local `Module_DetailedException`)
   - Repeated error checking patterns that should be extracted to helpers
   - System call error handling that should use `SAFE_CLOSE` and similar patterns

### 10. **Const Correctness (IMPORTANT)**
   - Function parameters that should be `const` (read-only pointers, read-only objects)
   - Pointer parameters that don't modify target should use `const Type *`
   - String parameters should use `const char *` unless modified
   - Callback function pointers with const data parameters
   - Structure members that should be const after initialization
   - Local variables that don't change after assignment
   - Array parameters that are read-only
   - **Pattern**: `static unsigned socket_hash(const Socket_T socket)` - input-only parameters
   - **Pattern**: `const char *Socket_getpeeraddr(Socket_T socket)` - return read-only strings

### 11. **Async I/O and Event-Driven Patterns**
   - Blocking DNS calls (`getaddrinfo`) that should use `SocketDNS` module
   - Blocking socket operations that should be non-blocking with event polling
   - Code that could benefit from async DNS resolution (`Socket_bind_async`, `Socket_connect_async`)
   - Event loops that don't handle edge-triggered events correctly (must drain until EAGAIN)
   - Missing timeout handling for async operations (`SocketDNS_request_settimeout`)
   - Callback patterns that could benefit from completion signaling via pipe FD
   - Poll integration missing for DNS completion (`SocketDNS_pollfd`)
   - Missing cancellation support for long-running async operations
   - Async resource cleanup patterns (must call `freeaddrinfo()` on resolved addresses)

### 12. **TLS/SSL Refactoring (Security Critical)**
   - TLS code not using TLS1.3-only configuration from `SocketTLSConfig.h`
   - Legacy cipher suites or protocol versions (must use `SOCKET_TLS13_CIPHERSUITES`)
   - Missing SNI (Server Name Indication) handling for virtual hosts
   - Missing ALPN (Application-Layer Protocol Negotiation) support
   - Certificate verification not properly configured
   - Missing hostname validation in client connections
   - Session resumption not properly implemented
   - TLS handshake timeout not respected (`SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS`)
   - Error handling not using OpenSSL error queue properly
   - Missing secure memory clearing for sensitive TLS data (use `SocketCrypto_secure_clear`)
   - Buffer sizes not respecting TLS record limits (`SOCKET_TLS_BUFFER_SIZE`)
   - Direct OpenSSL crypto calls instead of `SocketCrypto` module (hashes, HMAC, random)
   - Manual TLS teardown instead of `SocketTLS_disable()` for STARTTLS reversal patterns
   - Custom TLS-to-plain downgrade logic instead of using library function
   - Missing certificate pinning for sensitive applications (`SocketTLSContext_add_pin*()`)
   - Missing CRL management (`SocketTLSContext_load_crl()`, auto-refresh)
   - Missing OCSP stapling configuration (server or client side)
   - Missing Certificate Transparency verification (`SocketTLSContext_enable_ct()`)
   - Not using kTLS offload for high-performance scenarios (`SocketTLS_enable_ktls()`)
   - Missing TLS 1.3 KeyUpdate for long-lived connections (`SocketTLS_request_key_update()`)
   - Missing session ticket key rotation (`SocketTLSContext_rotate_session_ticket_key()`)
   - Missing session ID context for multi-tenant servers (`SocketTLSContext_set_session_id_context()`)
   - Custom renegotiation handling instead of `SocketTLS_check_renegotiation()`/`SocketTLS_disable_renegotiation()`
   - Missing OCSP Must-Staple enforcement (`SocketTLSContext_set_ocsp_must_staple()`)
   - Custom certificate lookup instead of `SocketTLSContext_set_cert_lookup_callback()` for HSM/database
   - Custom verification callback without proper thread safety or exception handling
   
   **TLS Lifecycle Pattern**:
   ```c
   /* Enable TLS on socket */
   SocketTLS_enable(socket, tls_ctx);
   SocketTLS_set_hostname(socket, "example.com");
   SocketTLS_handshake_auto(socket);  /* Complete handshake */
   
   /* ... use TLS I/O ... */
   
   /* Option 1: Strict shutdown (raises on failure) */
   SocketTLS_shutdown(socket);
   
   /* Option 2: Best-effort disable (for STARTTLS reversal) */
   int result = SocketTLS_disable(socket);  /* 1=clean, 0=partial, -1=not enabled */
   /* Socket is now in plain mode - use Socket_send/recv */
   
   /* Option 3: Half-close (send close_notify without waiting) */
   SocketTLS_shutdown_send(socket);
   ```
   
   **kTLS High-Performance Pattern**:
   ```c
   /* Check if kTLS is available on this system */
   if (SocketTLS_ktls_available()) {
       SocketTLS_enable_ktls(socket);  /* Request kTLS before handshake */
   }
   
   SocketTLS_enable(socket, ctx);
   SocketTLS_handshake_auto(socket);
   
   /* Verify kTLS activation */
   if (SocketTLS_is_ktls_tx_active(socket)) {
       /* Use zero-copy sendfile for files */
       SocketTLS_sendfile(socket, file_fd, 0, file_size);
   }
   ```
   
   **Certificate Pinning Pattern**:
   ```c
   SocketTLSContext_T ctx = SocketTLSContext_new_client("ca-bundle.pem");
   
   /* Add pins (binary SHA256 hash, hex string, or from certificate file) */
   SocketTLSContext_add_pin(ctx, pin_hash_bytes);
   SocketTLSContext_add_pin_hex(ctx, "sha256//AAAA...");
   SocketTLSContext_add_pin_from_cert(ctx, "backup-cert.pem");
   
   /* Enable strict enforcement (default is warn-only) */
   SocketTLSContext_set_pin_enforcement(ctx, 1);
   ```
   
   **Session Resumption Pattern**:
   ```c
   /* Server: Set session ID context for multi-tenant isolation */
   SocketTLSContext_set_session_id_context(ctx, (unsigned char *)"myapp", 5);
   SocketTLSContext_enable_session_cache(ctx, 1000, 300);
   
   /* Server: Enable session tickets with key rotation */
   SocketTLSContext_enable_session_tickets(ctx, ticket_key, 80);
   /* ... periodically rotate ... */
   SocketTLSContext_rotate_session_ticket_key(ctx, new_key, 80);
   
   /* Client: Save and restore sessions */
   size_t len = 0;
   SocketTLS_session_save(socket, NULL, &len);  /* Query size */
   unsigned char *session_data = malloc(len);
   SocketTLS_session_save(socket, session_data, &len);
   /* ... later ... */
   SocketTLS_session_restore(socket, session_data, len);
   ```
   
   **Long-Lived Connection Forward Secrecy**:
   ```c
   /* TLS 1.3: Use KeyUpdate for periodic key rotation */
   if (SocketTLS_request_key_update(socket, 1) > 0) {
       /* Keys rotated, peer will also rotate */
   }
   
   /* TLS 1.2: Check and limit renegotiation */
   SocketTLS_disable_renegotiation(socket);  /* Recommended for security */
   ```

### 12b. **DTLS Refactoring (Security Critical)**
   - Custom DTLS handshake instead of `SocketDTLS_handshake()`/`SocketDTLS_handshake_loop()`
   - Missing cookie exchange for DoS protection (`SocketDTLSContext_enable_cookie_exchange()`)
   - Custom cookie generation/verification instead of built-in HMAC-SHA256 implementation
   - Missing cookie secret rotation (`SocketDTLSContext_rotate_cookie_secret()`)
   - MTU not configured for network conditions (`SocketDTLSContext_set_mtu()`)
   - DTLS 1.2 not enforced via `SOCKET_DTLS_MIN_VERSION`
   - Custom DTLS frame parsing instead of using OpenSSL/library functions
   - Missing DTLS session cache (`SocketDTLSContext_enable_session_cache()`)
   - Custom retransmission handling instead of using OpenSSL's built-in
   - Missing ALPN support for DTLS (`SocketDTLSContext_set_alpn_protos()`)
   - Custom timeout handling instead of `SocketDTLSContext_set_timeout()`
   
   **DTLS Server Pattern**:
   ```c
   /* Create server context with DoS protection */
   SocketDTLSContext_T ctx = SocketDTLSContext_new_server("cert.pem", "key.pem", "ca.pem");
   SocketDTLSContext_enable_cookie_exchange(ctx);  /* CRITICAL for DoS protection */
   SocketDTLSContext_set_mtu(ctx, 1400);
   
   /* Enable DTLS on UDP socket */
   SocketDgram_T socket = SocketDgram_new(AF_INET, 0);
   SocketDgram_bind(socket, "0.0.0.0", 4433);
   SocketDTLS_enable(socket, ctx);
   
   /* Server handshake with cookie exchange */
   DTLSHandshakeState state;
   while ((state = SocketDTLS_listen(socket)) == DTLS_HANDSHAKE_COOKIE_EXCHANGE) {
       /* Cookie exchange in progress - handle retransmissions */
   }
   if (state == DTLS_HANDSHAKE_IN_PROGRESS) {
       while ((state = SocketDTLS_handshake(socket)) > DTLS_HANDSHAKE_COMPLETE) {
           /* Continue handshake */
       }
   }
   
   /* Secure I/O */
   SocketDTLS_send(socket, data, len);
   SocketDTLS_recv(socket, buffer, sizeof(buffer));
   ```
   
   **DTLS Client Pattern**:
   ```c
   SocketDTLSContext_T ctx = SocketDTLSContext_new_client("ca-bundle.pem");
   SocketDTLSContext_set_verify_mode(ctx, TLS_VERIFY_PEER);
   
   SocketDgram_T socket = SocketDgram_new(AF_INET, 0);
   SocketDTLS_enable(socket, ctx);
   SocketDTLS_set_peer(socket, "example.com", 4433);
   SocketDTLS_set_hostname(socket, "example.com");
   
   /* Complete handshake with timeout */
   if (SocketDTLS_handshake_loop(socket, 30000) != DTLS_HANDSHAKE_COMPLETE) {
       /* Handle handshake failure */
   }
   ```
   
   **Cookie Secret Rotation**:
   ```c
   /* Periodically rotate cookie secret (e.g., every hour) */
   SocketDTLSContext_rotate_cookie_secret(ctx);
   /* Previous secret still valid for grace period */
   ```

### 12c. **TLS Performance Patterns**
   - Missing kTLS offload (`SocketTLS_enable_ktls()`) for high-throughput
   - Manual file transfer instead of `SocketTLS_sendfile()` with kTLS
   - Missing session cache sharding (`SocketTLSContext_create_sharded_cache()`)
   - No buffer pooling for connections (`TLSBufferPool_new()`)
   - Missing TCP handshake optimization (`SocketTLS_optimize_handshake()`)
   - 0-RTT early data not used for latency-sensitive applications
   - KeyUpdate not used for long-lived connections (forward secrecy)

### 12d. **TLS Certificate and Trust Patterns**
   - Missing CRL auto-refresh (`SocketTLSContext_set_crl_auto_refresh()`)
   - No OCSP stapling configured (server-side)
   - Missing OCSP Must-Staple enforcement (client-side)
   - Certificate Transparency not enabled (`SocketTLSContext_enable_ct()`)
   - Missing certificate pinning (`SocketTLSContext_add_pin()`)
   - No HSM/database cert lookup (`SocketTLSContext_set_cert_lookup_callback()`)

### 12e. **Cryptographic Patterns (SocketCrypto)**
   - Direct `SHA256()`, `SHA1()`, `MD5()` calls instead of `SocketCrypto_sha*()` / `SocketCrypto_md5()`
   - Direct `HMAC()` calls instead of `SocketCrypto_hmac_sha256()`
   - Direct `RAND_bytes()` calls instead of `SocketCrypto_random_bytes()`
   - Custom Base64 encode/decode instead of `SocketCrypto_base64_encode/decode()`
   - Custom hex encode/decode functions instead of `SocketCrypto_hex_encode/decode()`
   - `memset()` for sensitive data instead of `SocketCrypto_secure_clear()` (may be optimized away)
   - Regular `memcmp()` for security tokens instead of `SocketCrypto_secure_compare()` (timing attack)
   - Custom WebSocket key/accept computation instead of `SocketCrypto_websocket_key/accept()`
   - Missing TLS check when using crypto (functions raise `SocketCrypto_Failed` if TLS unavailable)
   
   **Correct Pattern**:
   ```c
   /* Hash computation */
   unsigned char hash[SOCKET_CRYPTO_SHA256_SIZE];
   SocketCrypto_sha256(data, data_len, hash);
   
   /* HMAC for message authentication */
   unsigned char mac[SOCKET_CRYPTO_SHA256_SIZE];
   SocketCrypto_hmac_sha256(key, key_len, data, data_len, mac);
   
   /* Secure random generation */
   unsigned char nonce[16];
   if (SocketCrypto_random_bytes(nonce, sizeof(nonce)) < 0)
       handle_error();
   
   /* Constant-time comparison (prevents timing attacks) */
   if (SocketCrypto_secure_compare(computed_mac, received_mac, 32) != 0)
       reject_message();
   
   /* Clear sensitive data (won't be optimized away) */
   SocketCrypto_secure_clear(password, sizeof(password));
   
   /* WebSocket handshake (RFC 6455) */
   char accept_key[SOCKET_CRYPTO_WEBSOCKET_ACCEPT_SIZE];
   SocketCrypto_websocket_accept(client_key, accept_key);
   ```

### 13. **Cross-Platform Backend Patterns**
   - Platform-specific code that should use backend abstraction
   - Direct epoll/kqueue/poll usage instead of `SocketPoll` API
   - Missing event flag translation (POLL_READ/POLL_WRITE to platform-specific)
   - Backend-specific optimizations exposed outside backend files
   - Edge-triggered mode not properly used (must use EPOLLET/EV_CLEAR)
   - Event retrieval not following backend interface pattern
   - Platform detection that should be at compile-time via CMake/Makefile
   - Code assuming specific backend (epoll) that should be portable

### 14. **UDP/Datagram Socket Patterns (SocketDgram)**
   - TCP patterns incorrectly applied to UDP (no listen/accept for UDP)
   - Missing message boundary handling (UDP preserves boundaries, TCP doesn't)
   - Buffer sizes exceeding `UDP_MAX_PAYLOAD` (65507 bytes)
   - Not using safe UDP size (`SAFE_UDP_SIZE` 1472) to avoid fragmentation
   - Missing sender address handling in `recvfrom` operations
   - Connected UDP mode vs connectionless mode confusion
   - Missing MTU considerations for large datagrams
   - Error handling not accounting for UDP-specific errors (EMSGSIZE)

### 15. **Unix Domain Socket Patterns (AF_UNIX)**
   - Missing stale socket file cleanup before bind (`unlink` before `bind`)
   - Relative paths instead of absolute paths for socket files
   - Missing file permission handling for socket files
   - Socket path length exceeding `sizeof(sun_path)` (usually 108 chars)
   - Missing `SO_PASSCRED` for credential passing when needed
   - Missing abstract namespace support on Linux (`\0` prefix)
   - Not using proper cleanup patterns for socket files on exit
   - Custom SCM_RIGHTS implementation instead of `Socket_sendfd()`/`Socket_recvfd()`
   - Manual CMSG construction for FD passing instead of using library functions
   - Missing FD validation after receiving via SCM_RIGHTS
   - FD leaks from not closing received file descriptors
   - Passing more FDs than `SOCKET_MAX_FDS_PER_MSG` (253)
   
   **Correct FD Passing Pattern**:
   ```c
   /* Send single FD over Unix socket */
   Socket_sendfd(unix_socket, fd_to_pass);
   
   /* Receive single FD */
   int received_fd = -1;
   Socket_recvfd(unix_socket, &received_fd);
   if (received_fd >= 0) {
       /* Use fd... */
       close(received_fd);  /* Caller owns, must close */
   }
   
   /* Multiple FDs */
   int fds_to_send[3] = { fd1, fd2, fd3 };
   Socket_sendfds(unix_socket, fds_to_send, 3);
   
   int received_fds[10];
   size_t count;
   Socket_recvfds(unix_socket, received_fds, 10, &count);
   for (size_t i = 0; i < count; i++)
       close(received_fds[i]);
   ```

### 16. **Timeout and Timer Patterns**
   - Missing per-socket timeout configuration (`SocketTimeouts_T`)
   - Hardcoded timeout values instead of configurable constants
   - Missing timeout sanitization (negative values should become zero)
   - Blocking operations not respecting timeout configuration
   - DNS timeout not propagated to async requests (`timeouts.dns_timeout_ms`)
   - Connect timeout not implemented via non-blocking + poll pattern
   - Missing `SocketTimer` usage for deadline tracking
   - Poll default timeout not configurable (`SocketPoll_setdefaulttimeout`)

### 17. **Buffer Safety Patterns (CRITICAL)**
   - Circular buffer operations not checking bounds before access
   - Missing wrap-around handling in read/write operations
   - Buffer size validation not using `SOCKET_VALID_BUFFER_SIZE` macro
   - Missing `SIZE_MAX/2` limit check for buffer allocations
   - Not using `SocketBuf_secureclear` for sensitive data before reuse
   - Zero-copy operations returning pointers without proper length checks
   - Buffer reuse not following `SocketBuf_clear` + `SocketBuf_secureclear` pattern
   - Missing contiguous region calculations for efficient I/O

### 18. **Rate Limiting Patterns (SocketRateLimit)**
   - Custom rate limiting instead of using `SocketRateLimit` module
   - Missing token bucket configuration (tokens_per_sec, bucket_size)
   - Not using `SocketRateLimit_try_acquire` for non-blocking checks
   - Missing wait time calculation via `SocketRateLimit_wait_time_ms`
   - Rate limiter not configured per-use-case (connections vs bandwidth)
   - Missing runtime reconfiguration support

### 19. **IP Tracking Patterns (SocketIPTracker)**
   - Custom per-IP tracking instead of using `SocketIPTracker` module
   - Missing max_per_ip configuration for DoS protection
   - Not calling `SocketIPTracker_release` on connection close (leak)
   - Missing `SocketIPTracker_track` check before accepting connections
   - Hash collision handling not using O(1) lookup pattern

### 20. **Auto-Reconnection Patterns (SocketReconnect)**
   - Custom reconnection logic instead of using `SocketReconnect` module
   - Missing exponential backoff (use `SocketReconnect_Policy_T`)
   - No circuit breaker pattern (use `circuit_failure_threshold`)
   - Missing health check configuration (`health_check_interval_ms`)
   - Not using event loop integration (`SocketReconnect_pollfd`, `_tick`)
   - Custom jitter instead of policy-based jitter

### 21. **Happy Eyeballs Patterns (SocketHappyEyeballs)**
   - Sequential IPv4/IPv6 connection instead of RFC 8305 racing
   - Missing first attempt delay (should be 250ms per RFC 8305)
   - Not using `SocketHappyEyeballs_connect` for simple dual-stack connections
   - Async Happy Eyeballs not using `SocketHappyEyeballs_start/process/result`
   - Missing total timeout configuration
   - Not cleaning up losing connections properly

### 22. **Timer Module Patterns (SocketTimer)**
   - Using `sleep()` or manual timing instead of `SocketTimer`
   - Missing integration with `SocketPoll` event loop
   - Not using `SocketTimer_add_repeating` for periodic tasks
   - Manual timer tracking instead of timer handles
   - Missing timer cancellation via `SocketTimer_cancel`
   - Not using `SocketTimer_remaining` for timeout calculations

### 23. **Utility Module Patterns (SocketUtil)**
   - Custom logging instead of `SocketLog_emit`/`SocketLog_emitf`
   - Missing logging callback configuration
   - Not using `SocketMetrics_increment` for instrumentation
   - Custom event dispatching instead of `SocketEvents_emit`
   - Missing metrics snapshot for monitoring

### 24. **Shared Base Patterns (SocketCommon)**
   - Duplicated socket option setting instead of `SocketCommon_set_option_int`
   - Duplicated address resolution instead of `SocketCommon_resolve_address`
   - Duplicated iovec handling instead of `SocketCommon_calculate_total_iov_len`
   - Not using `SocketBase_T` for shared socket state
   - Missing `SocketLiveCount` for leak detection
   - Duplicated endpoint caching instead of `SocketCommon_cache_endpoint`

### 25. **File Splitting Patterns (Large Modules)**
   - Single large .c file exceeding 2000 lines without splitting
   - Not following `-core.c`, `-ops.c`, `-connections.c`, `-drain.c` pattern (see SocketPool)
   - Not following `-core.c`, `-alpn.c`, `-certs.c`, `-session.c` pattern (see SocketTLSContext)
   - Missing private header (`*-private.h`) for split file communication
   - Public API scattered across multiple files instead of centralized header

### 26. **UTF-8 Validation Patterns (SocketUTF8)**
   - Custom UTF-8 validation instead of using `SocketUTF8_validate()`
   - Manual byte-by-byte validation instead of DFA-based approach
   - Missing overlong encoding checks (security issue)
   - Missing surrogate pair rejection (U+D800-U+DFFF)
   - Missing code point range validation (> U+10FFFF)
   - Not using incremental API for streaming data (`SocketUTF8_init/update/finish`)
   
   **Correct Pattern**:
   ```c
   /* One-shot validation */
   if (SocketUTF8_validate(data, len) != UTF8_VALID) {
       /* Reject invalid UTF-8 */
   }
   
   /* Incremental validation for streaming */
   SocketUTF8_State state;
   SocketUTF8_init(&state);
   while (more_data) {
       SocketUTF8_Result r = SocketUTF8_update(&state, chunk, chunk_len);
       if (r == UTF8_INVALID) break;
   }
   SocketUTF8_Result final = SocketUTF8_finish(&state);
   ```

### 27. **HTTP Header Patterns (SocketHTTP)**
   - Custom HTTP header parsing instead of using `SocketHTTP_Headers_T`
   - Manual case-insensitive header lookup instead of hash table
   - Custom method/status parsing instead of `SocketHTTP_method_parse/status_reason`
   - Manual HTTP date parsing instead of `SocketHTTP_date_parse()`
   - Custom URI parsing instead of `SocketHTTP_URI_parse()`
   - Missing percent-encoding for URIs
   - Not using media type parsing for Content-Type
   - Custom Accept header parsing instead of `SocketHTTP_parse_accept()`
   
   **Correct Pattern**:
   ```c
   /* Header collection */
   SocketHTTP_Headers_T headers = SocketHTTP_Headers_new(arena);
   SocketHTTP_Headers_add(headers, "Content-Type", "application/json");
   const char *value = SocketHTTP_Headers_get(headers, "content-type");  /* Case-insensitive */
   
   /* Method/Status */
   SocketHTTP_Method m = SocketHTTP_method_parse("POST", 4);
   const char *reason = SocketHTTP_status_reason(404);  /* "Not Found" */
   
   /* URI parsing */
   SocketHTTP_URI uri;
   if (SocketHTTP_URI_parse("https://example.com:8080/path?q=1", 0, &uri, arena) == URI_PARSE_OK) {
       int port = SocketHTTP_URI_get_port(&uri, 443);
   }
   
   /* Date parsing */
   time_t t;
   SocketHTTP_date_parse("Sun, 06 Nov 1994 08:49:37 GMT", 0, &t);
   ```

### 28. **Graceful Shutdown Patterns (SocketPool Drain)**
   - Custom shutdown state tracking instead of using `SocketPool_drain`
   - Manual connection iteration for cleanup instead of `SocketPool_drain_force`
   - Missing health status for load balancer integration
   - No timeout guarantee for shutdown operations
   - Custom force-close loops instead of using drain API
   - Missing drain completion callback for cleanup coordination
   - Blocking operations during shutdown that should use `drain_poll` pattern
   - Not rejecting new connections during drain (should use state check)
   
   **Correct Pattern**:
   ```c
   /* Event-loop friendly drain (non-blocking) */
   SocketPool_drain(pool, 30000);  /* 30s timeout */
   while (SocketPool_drain_poll(pool) > 0) {
       int64_t timeout = SocketPool_drain_remaining_ms(pool);
       SocketPoll_wait(poll, &events, timeout);
       /* Continue processing - connections close naturally */
   }
   
   /* Or blocking drain for simple cases */
   int result = SocketPool_drain_wait(pool, 30000);
   if (result < 0) {
       log_warn("Drain timed out, connections force-closed");
   }
   
   /* Health check for load balancers */
   if (SocketPool_health(pool) != POOL_HEALTH_HEALTHY) {
       return HTTP_503_SERVICE_UNAVAILABLE;
   }
   ```
   
   **State Machine**:
   - `POOL_STATE_RUNNING` - Normal operation, accepting connections
   - `POOL_STATE_DRAINING` - Rejecting new, waiting for existing
   - `POOL_STATE_STOPPED` - Fully stopped, safe to free

### 29. **HTTP/1.1 Message Patterns (SocketHTTP1)**
   - Custom HTTP/1.1 request/response parsing instead of `SocketHTTP1_Parser`
   - Manual request line parsing instead of table-driven DFA parser
   - Custom chunked encoding instead of `SocketHTTP1_chunk_encode()`
   - Custom chunked decoding instead of `SocketHTTP1_Parser_read_body()`
   - Manual request/response serialization instead of `SocketHTTP1_serialize_request/response()`
   - Custom Content-Length validation instead of built-in request smuggling prevention
   - Manual Transfer-Encoding detection instead of `SocketHTTP1_Parser_body_mode()`
   - Not using incremental parser API for streaming data
   - Custom HTTP version parsing instead of built-in DFA states
   - Manual keep-alive detection instead of `SocketHTTP1_Parser_should_keepalive()`
   
   **Correct Pattern**:
   ```c
   /* Incremental HTTP/1.1 parsing */
   SocketHTTP1_Parser_T parser = SocketHTTP1_Parser_new(HTTP1_PARSE_REQUEST, NULL, arena);
   
   while (more_data) {
       size_t consumed;
       SocketHTTP1_Result r = SocketHTTP1_Parser_execute(parser, buf, len, &consumed);
       if (r == HTTP1_OK || r == HTTP1_INCOMPLETE) {
           buf += consumed;
           len -= consumed;
       }
       if (r != HTTP1_INCOMPLETE) break;
   }
   
   /* Get parsed request */
   const SocketHTTP_Request *req = SocketHTTP1_Parser_get_request(parser);
   
   /* Check body mode */
   SocketHTTP1_BodyMode mode = SocketHTTP1_Parser_body_mode(parser);
   if (mode == HTTP1_BODY_CHUNKED) {
       /* Read chunked body */
       SocketHTTP1_Parser_read_body(parser, input, input_len, &consumed, 
                                     output, output_len, &written);
   }
   
   /* Chunked encoding for responses */
   ssize_t n = SocketHTTP1_chunk_encode(data, len, output, output_size);
   n = SocketHTTP1_chunk_final(output, output_size, trailers);
   
   /* Serialization */
   ssize_t n = SocketHTTP1_serialize_request(&request, buffer, sizeof(buffer));
   ssize_t n = SocketHTTP1_serialize_response(&response, buffer, sizeof(buffer));
   ```

### 30. **HPACK Header Compression Patterns (SocketHPACK)**
   - Custom HPACK encoding/decoding instead of `SocketHPACK_Encoder/Decoder`
   - Custom Huffman coding instead of `SocketHPACK_huffman_encode/decode()`
   - Custom integer coding instead of `SocketHPACK_int_encode/decode()`
   - Manual static table lookup instead of `SocketHPACK_static_find()`
   - Custom dynamic table instead of `SocketHPACK_Table_T`
   - Manual HPACK bomb protection instead of built-in decoder limits
   - Not using incremental decoder API for streaming data
   - Custom power-of-2 rounding instead of `socket_util_round_up_pow2()`
   
   **Correct Pattern**:
   ```c
   /* Create encoder/decoder */
   SocketHPACK_Encoder_T encoder = SocketHPACK_Encoder_new(arena, 4096);
   SocketHPACK_Decoder_T decoder = SocketHPACK_Decoder_new(arena, NULL);
   
   /* Encode headers */
   SocketHPACK_Header headers[] = {
       { ":method", 7, "GET", 3, 0 },
       { ":path", 5, "/", 1, 0 },
   };
   unsigned char output[4096];
   size_t output_len;
   SocketHPACK_encode(encoder, headers, 2, output, sizeof(output), &output_len);
   
   /* Decode headers */
   SocketHPACK_Header decoded[64];
   size_t decoded_count;
   SocketHPACK_decode(decoder, input, input_len, decoded, 64, &decoded_count);
   
   /* Integer coding (for custom protocols) */
   size_t consumed;
   uint64_t value;
   SocketHPACK_int_decode(input, len, 5, &value, &consumed);  /* 5-bit prefix */
   
   /* Huffman coding */
   size_t encoded_size = SocketHPACK_huffman_encoded_size(data, len);
   SocketHPACK_huffman_encode(data, len, output, output_size);
   ```

### 31. **Hash Utility Patterns (SocketUtil)**
   - Custom DJB2 hash implementation instead of `socket_util_hash_djb2()`
   - Custom length-aware hash instead of `socket_util_hash_djb2_len()`
   - Custom case-insensitive hash instead of `socket_util_hash_djb2_ci()`
   - Manual power-of-2 rounding instead of `socket_util_round_up_pow2()`
   - Magic number `2654435761u` instead of `HASH_GOLDEN_RATIO`
   - Magic number `5381` instead of `SOCKET_UTIL_DJB2_SEED`
   
   **Correct Pattern**:
   ```c
   /* Hash file descriptor */
   unsigned hash = socket_util_hash_fd(fd, TABLE_SIZE);
   
   /* Hash string (null-terminated) */
   unsigned hash = socket_util_hash_djb2(name, TABLE_SIZE);
   
   /* Hash string with explicit length (non-null-terminated) */
   unsigned hash = socket_util_hash_djb2_len(name, name_len, TABLE_SIZE);
   
   /* Case-insensitive hash (for HTTP headers) */
   unsigned hash = socket_util_hash_djb2_ci(header_name, TABLE_SIZE);
   
   /* Combined: length-aware + case-insensitive */
   unsigned hash = socket_util_hash_djb2_ci_len(header_name, name_len, TABLE_SIZE);
   
   /* Power-of-2 capacity for efficient modulo */
   size_t capacity = socket_util_round_up_pow2(initial_size);
   unsigned index = hash & (capacity - 1);  /* Fast modulo */
   ```

### 32. **HTTP/2 Protocol Patterns (SocketHTTP2)**
   - Custom HTTP/2 frame parsing instead of `SocketHTTP2_frame_header_parse/serialize()`
   - Custom stream state tracking instead of `SocketHTTP2_Stream_state()`
   - Manual flow control window management instead of `SocketHTTP2_*_window_update()`
   - Custom connection preface handling instead of `SocketHTTP2_Conn_handshake()`
   - Manual SETTINGS frame handling instead of `SocketHTTP2_Conn_settings()`
   - Custom HPACK integration instead of using `SocketHTTP2` built-in encoder/decoder
   - Manual stream ID management instead of `SocketHTTP2_Stream_new()` auto-assignment
   - Custom h2c upgrade logic instead of `SocketHTTP2_Conn_upgrade_client/server()`
   - Not using stream/connection callbacks for event handling
   
   **Correct Pattern**:
   ```c
   /* Create HTTP/2 connection */
   SocketHTTP2_Config config;
   SocketHTTP2_config_defaults(&config, HTTP2_ROLE_CLIENT);
   SocketHTTP2_Conn_T conn = SocketHTTP2_Conn_new(socket, &config, arena);
   
   /* Perform handshake */
   while (SocketHTTP2_Conn_handshake(conn) > 0) {
       SocketHTTP2_Conn_flush(conn);
       SocketHTTP2_Conn_process(conn, POLL_READ);
   }
   
   /* Create stream and send request */
   SocketHTTP2_Stream_T stream = SocketHTTP2_Stream_new(conn);
   SocketHPACK_Header headers[] = {
       { ":method", 7, "GET", 3, 0 },
       { ":path", 5, "/", 1, 0 },
       { ":scheme", 7, "https", 5, 0 },
       { ":authority", 10, "example.com", 11, 0 },
   };
   SocketHTTP2_Stream_send_headers(stream, headers, 4, 1);  /* END_STREAM */
   
   /* Set callbacks for events */
   SocketHTTP2_Conn_set_stream_callback(conn, on_stream_event, userdata);
   SocketHTTP2_Conn_set_conn_callback(conn, on_conn_event, userdata);
   
   /* Process frames in event loop */
   while (!SocketHTTP2_Conn_is_closed(conn)) {
       SocketHTTP2_Conn_process(conn, events);
       SocketHTTP2_Conn_flush(conn);
   }
   
   /* Graceful shutdown */
   SocketHTTP2_Conn_goaway(conn, HTTP2_NO_ERROR, NULL, 0);
   SocketHTTP2_Conn_free(&conn);
   ```

### 33. **Proxy Tunneling Patterns (SocketProxy)**
   - Custom HTTP CONNECT implementation instead of `SocketProxy_connect()` with `SOCKET_PROXY_HTTP`
   - Custom SOCKS4/4a implementation instead of `SocketProxy_connect()` with `SOCKET_PROXY_SOCKS4/4A`
   - Custom SOCKS5 implementation instead of `SocketProxy_connect()` with `SOCKET_PROXY_SOCKS5`
   - Manual proxy URL parsing instead of `SocketProxy_parse_url()`
   - Custom SOCKS5 authentication instead of built-in username/password support
   - Manual credential handling instead of `SocketCrypto_secure_clear()` integration
   - Custom HTTP CONNECT response parsing instead of reusing `SocketHTTP1_Parser_T`
   - Manual state machine for async proxy connection instead of `SocketProxy_connect_async()`
   
   **Correct Pattern**:
   ```c
   /* Configure proxy */
   SocketProxy_Config proxy;
   SocketProxy_config_defaults(&proxy);
   proxy.type = SOCKET_PROXY_SOCKS5;
   proxy.host = "proxy.example.com";
   proxy.port = 1080;
   proxy.username = "user";
   proxy.password = "pass";
   
   /* Parse proxy URL (alternative) */
   SocketProxy_parse_url("socks5://user:pass@proxy:1080", &proxy, arena);
   
   /* Synchronous connection through proxy */
   Socket_T sock = SocketProxy_connect(&proxy, "target.example.com", 443);
   if (sock) {
       /* Tunnel established - can now use Socket_send/recv */
       /* Or add TLS: SocketTLS_enable(sock, tls_ctx); */
   }
   
   /* Async connection (for event loops) */
   SocketProxy_Conn_T conn = SocketProxy_connect_async(socket, &proxy, host, port, arena);
   while (SocketProxy_Conn_state(conn) < PROXY_STATE_CONNECTED) {
       unsigned events = SocketProxy_Conn_poll_events(conn);
       /* poll for events... */
       SocketProxy_Conn_process(conn, received_events);
   }
   Socket_T tunneled = SocketProxy_Conn_socket(conn);
   SocketProxy_Conn_free(&conn);
   
   /* HTTP CONNECT with custom headers */
   proxy.type = SOCKET_PROXY_HTTP;
   proxy.extra_headers = SocketHTTP_Headers_new(arena);
   SocketHTTP_Headers_add(proxy.extra_headers, "X-Custom", "value");
   ```
   
   **Available SocketProxy functions**:
   - `SocketProxy_connect()` - Synchronous proxy connection
   - `SocketProxy_connect_tls()` - Sync with TLS to target after tunnel
   - `SocketProxy_connect_async()` - Async proxy connection (for event loops)
   - `SocketProxy_Conn_process()` - Process async connection events
   - `SocketProxy_Conn_poll_events()` - Get events to poll for
   - `SocketProxy_Conn_state()` - Get current state
   - `SocketProxy_Conn_result()` - Get result code
   - `SocketProxy_Conn_socket()` - Get tunneled socket (transfers ownership)
   - `SocketProxy_Conn_free()` - Free async connection context
   - `SocketProxy_parse_url()` - Parse `socks5://user:pass@host:port` URLs
   - `SocketProxy_config_defaults()` - Initialize config with defaults
   - `SocketProxy_result_string()` - Get error description

### 34. **WebSocket Protocol Patterns (SocketWS)**
   - Custom WebSocket handshake instead of `SocketWS_client_new()` / `SocketWS_server_accept()`
   - Manual Sec-WebSocket-Key generation instead of `SocketCrypto_websocket_key()`
   - Manual Sec-WebSocket-Accept computation instead of `SocketCrypto_websocket_accept()`
   - Custom XOR masking loop instead of `SocketWS` built-in optimized masking
   - Custom frame parsing instead of `SocketWS_read()`
   - Manual UTF-8 validation for text frames instead of integrated `SocketUTF8`
   - Custom ping/pong handling instead of `SocketWS_ping()` / `SocketWS_pong()`
   - Custom close handshake instead of `SocketWS_close()`
   - Manual permessage-deflate instead of `SocketWS` built-in compression
   - Not using incremental UTF-8 validation for fragmented messages
   
   **Correct Pattern**:
   ```c
   /* Configure WebSocket */
   SocketWS_Config config;
   SocketWS_config_defaults(&config);
   config.role = WS_ROLE_CLIENT;
   config.max_message_size = 16 * 1024 * 1024;  /* 16MB */
   config.validate_utf8 = 1;
   config.ping_interval_ms = 30000;
   
   /* Client handshake */
   SocketWS_T ws = SocketWS_client_new(socket, host, path, &config);
   while (SocketWS_handshake(ws) > 0) {
       /* Poll and process */
   }
   
   /* Send messages */
   SocketWS_send_text(ws, "Hello, WebSocket!", 17);
   SocketWS_send_binary(ws, binary_data, data_len);
   
   /* Receive messages */
   SocketWS_Message msg;
   int result = SocketWS_recv_message(ws, &msg);
   if (result > 0) {
       /* Process msg.data (msg.len bytes) */
       /* msg.type is WS_OPCODE_TEXT or WS_OPCODE_BINARY */
       free(msg.data);  /* Caller owns the data */
   }
   
   /* Control frames */
   SocketWS_ping(ws, NULL, 0);
   SocketWS_pong(ws, payload, payload_len);
   
   /* Close gracefully */
   SocketWS_close(ws, WS_CLOSE_NORMAL, "Goodbye");
   SocketWS_free(&ws);
   
   /* Server: Check for upgrade request */
   if (SocketWS_is_upgrade(request)) {
       config.role = WS_ROLE_SERVER;
       SocketWS_T ws = SocketWS_server_accept(socket, request, &config);
   }
   ```
   
   **Available SocketWS functions**:
   - `SocketWS_config_defaults()` - Initialize config with defaults
   - `SocketWS_client_new()` - Create client WebSocket
   - `SocketWS_server_accept()` - Accept server WebSocket upgrade
   - `SocketWS_server_reject()` - Reject upgrade with HTTP status
   - `SocketWS_is_upgrade()` - Check if HTTP request is WebSocket upgrade
   - `SocketWS_handshake()` - Perform/continue handshake
   - `SocketWS_send_text()` / `SocketWS_send_binary()` - Send messages
   - `SocketWS_recv_message()` - Receive complete message (with auto-reassembly)
   - `SocketWS_recv_available()` - Check if data available
   - `SocketWS_ping()` / `SocketWS_pong()` - Control frames
   - `SocketWS_close()` - Initiate close handshake
   - `SocketWS_state()` - Get connection state (CONNECTING/OPEN/CLOSING/CLOSED)
   - `SocketWS_socket()` - Get underlying TCP socket
   - `SocketWS_pollfd()` / `SocketWS_poll_events()` / `SocketWS_process()` - Event loop
   - `SocketWS_enable_auto_ping()` / `SocketWS_disable_auto_ping()` - Keepalive
   - `SocketWS_close_code()` / `SocketWS_close_reason()` - Close status
   - `SocketWS_last_error()` / `SocketWS_error_string()` - Error handling
   - `SocketWS_selected_subprotocol()` - Get negotiated subprotocol
   - `SocketWS_compression_enabled()` - Check if deflate active
   - `SocketWS_free()` - Free WebSocket

## Focus Areas by File Type

### Core Modules
- **Arena.c**: Already well-refactored; use as reference for patterns. Chunk management, overflow protection.
- **Except.c**: Exception handling foundation. Thread-local stack, RAISE/TRY/EXCEPT implementation.
- **SocketCrypto.c**: Cryptographic primitives (SHA, HMAC, Base64, Hex, random, secure clear/compare). OpenSSL wrappers.
- **SocketUTF8.c**: DFA-based UTF-8 validation. One-shot and incremental APIs. Security checks for overlong/surrogates.
- **SocketUtil.c**: Consolidated utilities (logging, metrics, events, error handling). Thread-safe callbacks.
- **SocketRateLimit.c**: Token bucket rate limiter. Thread-safe acquire/wait patterns.
- **SocketIPTracker.c**: Per-IP connection tracking. O(1) hash table lookups, automatic cleanup.
- **SocketTimer.c**: Timer subsystem. Min-heap storage, one-shot/repeating timers, event loop integration.
- **SocketSYNProtect.c**: SYN flood protection logic.

### Socket Modules
- **Socket.c**: Core lifecycle, bind, accept, state logic (integrates specialized files).
- **Socket-connect.c**: Specialized connection logic.
- **Socket-iov.c**: Specialized scatter/gather I/O.
- **Socket-options.c**: specialized socket option handling.
- **SocketDgram.c**: UDP-specific patterns, sendto/recvfrom semantics, message boundary handling.
- **SocketCommon.c**: Shared utilities (address resolution, socket options, iovec helpers, SocketBase_T).
- **SocketAsync.c**: Async operation patterns, non-blocking mode, completion callbacks.
- **SocketBuf.c**: Circular buffer safety, bounds checking, secure clearing, zero-copy operations.
- **SocketIO.c**: Vectored I/O (iovec), scatter-gather patterns.
- **SocketReconnect.c**: Auto-reconnection with exponential backoff, circuit breaker, health monitoring.
- **SocketHappyEyeballs.c**: RFC 8305 dual-stack connection racing, async/sync APIs, timeout management.
- **SocketProxy.c**: Core proxy lifecycle, URL parsing, config, sync wrappers, state machine driver.
- **SocketProxy-http.c**: HTTP CONNECT protocol, reuses SocketHTTP1_Parser_T.
- **SocketProxy-socks4.c**: SOCKS4/4a protocol implementation.
- **SocketProxy-socks5.c**: SOCKS5 protocol (RFC 1928/1929), method negotiation, auth, connect.

### DNS Module
- **SocketDNS.c / SocketDNS-internal.c**: Thread pool patterns, request queue management, completion signaling via pipe, timeout enforcement.

### Event System
- **SocketPoll.c**: Frontend event loop, socket→data mapping, default timeout handling.
- **SocketPoll_epoll.c**: Linux epoll backend, edge-triggered mode, event translation.
- **SocketPoll_kqueue.c**: BSD/macOS kqueue backend, EV_CLEAR for edge-trigger behavior.
- **SocketPoll_poll.c**: POSIX poll(2) fallback, FD→index mapping for O(1) lookup.

### Connection Management
- **SocketPool-core.c**: Pool creation/destruction, configuration, statistics.
- **SocketPool-connections.c**: Connection add/remove, hash table management.
- **SocketPool-ops.c**: Connection operations, iteration, cleanup.
- **SocketPool-ratelimit.c**: Per-pool rate limiting integration.
- **SocketPool-drain.c**: Graceful shutdown state machine, drain/poll/force/wait.

### TLS/SSL Modules
- **SocketTLS.c**: TLS1.3 operations, handshake handling, secure I/O wrappers.
- **SocketTLSContext-core.c**: SSL_CTX creation/destruction, basic configuration.
- **SocketTLSContext-certs.c**: Certificate/key loading, chain configuration.
- **SocketTLSContext-alpn.c**: ALPN protocol negotiation.
- **SocketTLSContext-session.c**: Session resumption, ticket handling.
- **SocketTLSContext-verify.c**: Certificate verification, hostname validation.
- **SocketTLSConfig.h**: Configuration constants, cipher suites, buffer sizes - DO NOT weaken security settings.

### HTTP Modules
- **SocketHTTP.h**: Public types - versions, methods, status codes, headers, URI, dates, media types.
- **SocketHTTP-private.h**: Internal structures - header hash table, URI parser state, char tables.
- **SocketHTTP-core.c**: Method/status/version utilities, character classification tables, coding types.
- **SocketHTTP-headers.c**: Header collection with O(1) case-insensitive lookup (djb2 hash), insertion order iteration.
- **SocketHTTP-uri.c**: RFC 3986 URI parsing with state machine, percent-encoding, media type parsing, Accept header parsing.
- **SocketHTTP-date.c**: HTTP-date parsing (IMF-fixdate, RFC 850, ANSI C asctime), date formatting.

### HTTP/1.1 Modules (RFC 9112)
- **SocketHTTP1.h**: Public API - parser, serialization, chunked encoding, optional compression.
- **SocketHTTP1-private.h**: Internal DFA tables (char class, state, action), parser state structure.
- **SocketHTTP1-parser.c**: Table-driven DFA incremental parser (Hoehrmann-style), request smuggling prevention.
- **SocketHTTP1-serialize.c**: Request line, status line, and header serialization.
- **SocketHTTP1-chunked.c**: Chunk encoding/decoding, final chunk with trailers, body reading API.
- **SocketHTTP1-compress.c**: Optional gzip/deflate/brotli compression (requires ENABLE_HTTP_COMPRESSION).

### HPACK Modules (RFC 7541)
- **SocketHPACK.h**: Public API - encoder, decoder, tables, integer/Huffman coding.
- **SocketHPACK-private.h**: Internal structures - Huffman state, dynamic entry, decoder state.
- **SocketHPACK.c**: Core encoder/decoder, integer coding (RFC 7541 Section 5.1).
- **SocketHPACK-huffman.c**: DFA-based Huffman encoder/decoder, static encode/decode tables.
- **SocketHPACK-table.c**: Static table (61 entries), dynamic table with circular buffer.

### HTTP/2 Modules (RFC 9113)
- **SocketHTTP2.h**: Public API - frame types, error codes, settings, stream states, connection/stream management.
- **SocketHTTP2-private.h**: Internal structures - connection state, stream state machine, HPACK integration.
- **SocketHTTP2-frame.c**: Frame header parsing/serialization, validation, utility functions.
- **SocketHTTP2-connection.c**: Connection lifecycle, preface exchange, SETTINGS, PING, GOAWAY handling.
- **SocketHTTP2-stream.c**: Stream state machine (7 states), DATA/HEADERS processing, HPACK integration.
- **SocketHTTP2-flow.c**: Connection and stream-level flow control with overflow protection.
- **SocketHTTP2-priority.c**: Deprecated PRIORITY frame handling (minimal per RFC 9113).

### HTTP Client/Server Modules
- **SocketHTTPClient.h**: Public client API - config, lifecycle, sync/async requests, cookies, auth.
- **SocketHTTPClient-private.h**: Internal structures - pool entries, request context, async state.
- **SocketHTTPClient.c**: Core lifecycle, config defaults, simple sync API (GET/POST/PUT/DELETE).
- **SocketHTTPClient-pool.c**: HTTP connection pool with per-host keying, Happy Eyeballs integration.
- **SocketHTTPClient-auth.c**: Authentication (Basic/Digest/Bearer using SocketCrypto).
- **SocketHTTPClient-cookie.c**: Cookie Jar (RFC 6265) with domain/path matching, persistence.
- **SocketHTTPServer.h**: Public server API - config, lifecycle, request handler callbacks.
- **SocketHTTPServer.c**: Event-driven server, request processing, response building.

### Proxy Modules (HTTP CONNECT, SOCKS)
- **SocketProxy.h**: Public API - proxy types, config, sync/async connection functions.
- **SocketProxy-private.h**: Internal structures - state machine, protocol helpers.
- **SocketProxy.c**: Core lifecycle, URL parser, config defaults, sync wrappers, state machine driver.
- **SocketProxy-http.c**: HTTP CONNECT protocol (reuses `SocketHTTP1_Parser_T` for response parsing).
- **SocketProxy-socks4.c**: SOCKS4/4a protocol implementation.
- **SocketProxy-socks5.c**: SOCKS5 protocol (RFC 1928, RFC 1929 for username/password auth).

### WebSocket Modules (RFC 6455)
- **SocketWS.h**: Public API - config, lifecycle, send/receive, control frames.
- **SocketWS-private.h**: Internal structures - state machine, frame parsing, compression.
- **SocketWS.c**: Core lifecycle, config, state management, send/receive APIs.
- **SocketWS-handshake.c**: HTTP upgrade handshake (reuses `SocketHTTP1_Parser_T`).
- **SocketWS-frame.c**: Frame parsing/serialization, optimized XOR masking.
- **SocketWS-deflate.c**: permessage-deflate compression (conditional on zlib).

### Fuzzing
- **fuzz/corpus/**: Seed inputs for fuzzers.
- **scripts/run_fuzz_parallel.sh**: Parallel execution of fuzzers.

### Headers
- **Organization**: Include guards with `_INCLUDED` suffix, system headers first, module documentation.
- **Private headers** (`*-private.h`): Internal structures, not part of public API. Used for split-file modules.
- **Public headers**: Opaque types only, `extern` function declarations, comprehensive Doxygen comments.

## Output Format for Refactored Code

When refactoring a file, provide:

1. **Fully refactored C code** - Complete, production-ready code in a single block
2. **Change Summary** - Categorized by:
   - Security improvements (vulnerabilities fixed)
   - Function extraction (functions split, new helpers created)
   - Magic number elimination (constants added, locations - should go in SocketConfig.h or module headers)
   - Performance optimizations
   - Redundancy removal
   - Error handling improvements (conversion to exception system)
   - Style compliance fixes
   - Memory management improvements (Arena usage)
3. **Assumptions** - Note any assumptions made about the codebase context
4. **Function Breakdown** - List of new helper functions created and their purposes
5. **Constants Added** - List of new named constants with their locations (preferably SocketConfig.h or module headers)

## Critical Requirements Checklist

Before completing refactoring, verify:

### Code Structure
- [ ] All functions are under 20 lines (extract helpers aggressively)
- [ ] All functions have single responsibility
- [ ] All magic numbers replaced with named constants (preferably in SocketConfig.h)
- [ ] All TODOs/FIXMEs removed or implemented
- [ ] All .c and .h files are under 20000 lines of code
- [ ] Each .c and .h file serves a single purpose
- [ ] No functionality changed (only refactored)
- [ ] Code is production-ready

### Style Compliance
- [ ] Code follows C Interfaces and Implementations style (header organization, type definitions, documentation, opaque types)
- [ ] Code follows GNU C style (return types on separate lines, 8-space indentation, spacing)
- [ ] Module naming conventions followed (ModuleName_ prefix pattern)
- [ ] Type definitions use T macro pattern with `#undef T` at end
- [ ] Include guards use `_INCLUDED` suffix pattern
- [ ] Header files expose only opaque types (no structure definitions in headers)
- [ ] All public functions have comprehensive Doxygen-style documentation
- [ ] Function declarations use `extern` keyword in headers
- [ ] Static functions documented with Doxygen comments

### Memory Management
- [ ] Memory allocations use Arena where appropriate (for related objects)
- [ ] Buffer sizes validated with `SOCKET_VALID_BUFFER_SIZE`
- [ ] Overflow protection before arithmetic (check `SIZE_MAX/2` limit)
- [ ] Sensitive data cleared with `SocketBuf_secureclear`
- [ ] Socket lifecycle verified (`Socket_debug_live_count()` is zero at teardown)

### Error Handling
- [ ] Error handling uses exception system (TRY/EXCEPT/FINALLY)
- [ ] Thread-safe exception patterns (thread-local `Module_DetailedException`)
- [ ] System calls use safe wrappers (`SAFE_CLOSE`, etc.)
- [ ] Error messages use standardized format (`MODULE_ERROR_FMT`/`MODULE_ERROR_MSG`)

### Thread Safety
- [ ] Thread-local storage for per-thread data
- [ ] Mutex protection for shared data structures
- [ ] No modification of global exception structures directly
- [ ] Const correctness for read-only parameters

### Security
- [ ] Security vulnerabilities addressed (buffer overflows, integer overflows)
- [ ] TLS code uses TLS1.3-only configuration from `SocketTLSConfig.h`
- [ ] No legacy cipher suites or protocol versions
- [ ] Input validation at API boundaries
- [ ] Cryptographic operations use `SocketCrypto` module (not direct OpenSSL)
- [ ] Sensitive data cleared with `SocketCrypto_secure_clear()` (not `memset`)
- [ ] Security token comparison uses `SocketCrypto_secure_compare()` (constant-time)

### Async & Event Patterns
- [ ] Blocking DNS uses `SocketDNS` async resolution
- [ ] Edge-triggered events drain until EAGAIN
- [ ] Timeout configuration respected and propagated
- [ ] Async resources properly cleaned up (`freeaddrinfo`)
- [ ] Timer-based operations use `SocketTimer` module

### Platform Compatibility
- [ ] Uses `SocketPoll` API, not direct epoll/kqueue/poll
- [ ] Platform-specific code isolated to backend files
- [ ] No assumptions about specific backend

### Rate Limiting & DoS Protection
- [ ] Connection rate limiting uses `SocketRateLimit` module
- [ ] Per-IP tracking uses `SocketIPTracker` module
- [ ] Max connections per IP configured appropriately
- [ ] Rate limiter tokens/burst configured for use case

### Resilience Patterns
- [ ] Client connections use `SocketReconnect` for auto-reconnection
- [ ] Exponential backoff configured with appropriate limits
- [ ] Circuit breaker thresholds set appropriately
- [ ] Dual-stack connections use `SocketHappyEyeballs`

### Graceful Shutdown
- [ ] Server pools use `SocketPool_drain()` for graceful shutdown
- [ ] Drain timeout configured appropriately (typically 30s)
- [ ] Health status exposed for load balancer integration
- [ ] Drain completion callback used for coordination if needed
- [ ] New connections rejected during drain (automatic with API)
- [ ] Force close used only as last resort after timeout

### Observability
- [ ] Logging uses `SocketLog_emit`/`SocketLog_emitf`
- [ ] Key operations increment appropriate metrics
- [ ] Live socket count tracked via `SocketLiveCount` or `Socket_debug_live_count()`
- [ ] Pool drain events emit `SOCKET_METRIC_POOL_DRAIN_INITIATED` / `SOCKET_METRIC_POOL_DRAIN_COMPLETED`

### Existing Codebase Integration
- [ ] Existing codebase functions leveraged (Arena, Exception system, SocketUtil, SocketConfig, SocketCrypto)
- [ ] Shared utilities use `SocketCommon_*` helpers (address resolution, iovec, options)
- [ ] Cryptographic operations use `SocketCrypto_*` helpers (hashes, HMAC, Base64, random)
- [ ] Patterns match existing modules (consult `.cursor/rules/` for details)
- [ ] Large files split following SocketPool/SocketTLSContext patterns

## C Interfaces and Implementations Style Examples

### Correct Header File Pattern
```c
#ifndef MODULENAME_INCLUDED
#define MODULENAME_INCLUDED

#include <stddef.h>  /* System headers first */

/**
 * ModuleName - Brief module description
 *
 * Detailed description of module purpose, features, and behavior.
 * Include information about thread safety, performance characteristics,
 * and any important usage notes.
 *
 * Features:
 * - Feature 1 with brief description
 * - Feature 2 with brief description
 *
 * Usage example:
 *   ModuleName_T instance = ModuleName_new();
 *   ModuleName_operation(instance);
 *   ModuleName_free(&instance);
 */

#define T ModuleName_T
typedef struct T *T;  /* Opaque pointer type */

/**
 * ModuleName_new - Create a new module instance
 *
 * Returns: New instance, or NULL on failure
 * Thread-safe: Yes
 */
extern T ModuleName_new(void);

/**
 * ModuleName_free - Free module instance
 * @instance: Pointer to instance pointer (will be set to NULL)
 *
 * Thread-safe: No
 */
extern void ModuleName_free(T *instance);

#undef T
#endif
```

### Correct Implementation File Pattern
```c
/**
 * ModuleName.c - Module implementation description
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 */

#include <assert.h>  /* System headers first */
#include <stdlib.h>
#include "core/ModuleName.h"  /* Project headers */
#include "core/SocketConfig.h"

#define T ModuleName_T

/* Static helper functions first */
static void helper_function(T instance)
{
    /* Implementation */
}

/* Public function implementations */
T
ModuleName_new(void)
{
    T instance;
    
    instance = malloc(sizeof(*instance));
    if (instance == NULL)
        return NULL;
    
    /* Initialize */
    return instance;
}

void
ModuleName_free(T *instancep)
{
    assert(instancep && *instancep);
    
    free(*instancep);
    *instancep = NULL;
}

#undef T
```

Provide prioritized refactoring suggestions when analyzing, starting with high-impact improvements that enhance maintainability and code quality while preserving functionality and adhering to **both** C Interfaces and Implementations style standards **and** GNU C style standards, plus socket library patterns. When actually refactoring, provide complete refactored code ready for production use that follows all conventions.
