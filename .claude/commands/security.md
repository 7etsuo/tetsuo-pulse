# Security-Focused Review - Socket Library

Perform a comprehensive security analysis specifically tailored for the socket library that processes network data and potentially untrusted input. Focus on identifying vulnerabilities that could lead to exploitation, data corruption, or privilege escalation.

**Key Security References:**
- `include/core/SocketSecurity.h` - Centralized security limits and validation utilities
- `src/test/test_security.c` - Comprehensive security test suite (33 tests)
- `src/fuzz/` - Fuzzing harnesses (60+) for attack surface testing

## 1. Identify Unsafe String Functions

Scan for and flag all unsafe string manipulation functions:

### Dangerous Functions to Flag:
- **strcpy()** - No bounds checking, use `strncpy()` with explicit null termination or better alternatives
- **strcat()** - No bounds checking, use `strncat()` with size limits
- **sprintf()** - Vulnerable to buffer overflow, use `snprintf()` with size limits
- **gets()** - Always unsafe, never use
- **scanf() family** - Use with extreme caution, prefer `fgets()` + parsing
- **strtok()** - Not thread-safe, verify `strtok_r()` is used instead

### Safe Alternatives Analysis:
- **strncpy()** - Verify proper null termination after all uses
- **snprintf()** - Verify size parameter matches buffer size (check return value)
- **strtok_r()** - Confirm thread-safe version is used consistently
- **fgets()** - Verify buffer size matches actual buffer allocation
- **Socket Library**: Verify `MODULE_ERROR_FMT`/`MODULE_ERROR_MSG` use `snprintf` correctly

### String Function Security Checks:
- Ensure all string operations have explicit size limits
- Verify null termination after all bounded string copies
- Check for off-by-one errors in buffer sizes
- Flag any string operations without size bounds
- Verify no direct pointer arithmetic on string buffers without bounds checks

## 2. Check Input Validation

Comprehensive input validation review for all external inputs:

### Network Input Validation:
- **Socket addresses** - Check for:
  - Invalid address formats
  - Address length validation
  - Port range validation (1-65535)
  - IPv6 address validation
  - Unix domain socket path validation
- **DNS hostnames** - Validate:
  - Hostname length limits
  - Valid hostname characters
  - DNS injection prevention
  - Hostname resolution timeout
- **Socket data** - Validate:
  - Buffer size limits before operations
  - Received data length validation
  - Maximum buffer sizes enforced

### Parser Input Validation:
- **Address parsing** - Verify:
  - Port number validation (range 1-65535)
  - IP address format validation
  - Hostname validation before DNS lookup
- **Buffer operations** - Verify:
  - Buffer size checks before writes
  - Circular buffer bounds checking
  - Overflow protection in buffer growth

### Function Parameter Validation:
- Verify NULL pointer checks before dereferencing (use `assert()` for programming errors)
- Check `Arena_T` pointers are validated before use
- Validate integer parameters are within expected ranges
- Check array indices are within bounds before access
- Verify pointer parameters are not NULL when required
- Validate socket file descriptors are valid (>= 0)

## 3. Review Integer Overflow Risks

Comprehensive integer overflow/underflow analysis:

### Canonical Overflow-Safe Functions (SocketSecurity.h):
Use these functions for all size calculations:
- **SocketSecurity_check_multiply(a, b, &result)** - Returns 1 if safe, 0 if overflow
- **SocketSecurity_check_add(a, b, &result)** - Returns 1 if safe, 0 if overflow
- **SocketSecurity_safe_multiply(a, b)** - Returns product or 0 on overflow
- **SocketSecurity_safe_add(a, b)** - Returns sum or SIZE_MAX on overflow
- **SocketSecurity_check_size(size)** - Validates against SOCKET_SECURITY_MAX_ALLOCATION

### Validation Macros (SocketSecurity.h):
- **SOCKET_SECURITY_VALID_SIZE(s)** - Check size is within safe limits
- **SOCKET_SECURITY_CHECK_OVERFLOW_MUL(a, b)** - Inline multiplication overflow check
- **SOCKET_SECURITY_CHECK_OVERFLOW_ADD(a, b)** - Inline addition overflow check

### Arithmetic Operations:
- **Addition** - Check for:
  - Buffer size calculations (`size + increment`)
  - Index calculations
  - Array size calculations
  - Use `SocketSecurity_check_add()` or `SOCKET_SECURITY_CHECK_OVERFLOW_ADD()`
- **Multiplication** - Check for:
  - `sizeof(type) * count` in allocation (Arena handles this)
  - Array index calculations
  - Buffer size calculations
  - Use `SocketSecurity_check_multiply()` or `SOCKET_SECURITY_CHECK_OVERFLOW_MUL()`
- **Subtraction** - Check for:
  - Underflow in size calculations
  - Index decrements (ensure >= 0)
  - Pointer arithmetic bounds

### Type Conversion Risks:
- **Signed/Unsigned** - Check for:
  - Implicit conversions between signed/unsigned
  - Port numbers (int) vs size_t comparisons
  - Socket file descriptors (int) vs size_t comparisons
  - Negative values in unsigned contexts
- **Width Mismatches** - Check for:
  - int vs size_t comparisons
  - long vs size_t assignments
  - Potential truncation in assignments

### Arena Allocation Overflow:
- Verify `Arena_alloc` checks for overflow (already implemented)
- Check size calculations before all allocations
- Verify `ARENA_MAX_ALLOC_SIZE` limit is enforced
- Validate no arithmetic occurs on sizes without checks

## 4. Analyze Network I/O Security

Comprehensive network I/O security review:

### Socket Creation Security:
- **Address Family Validation**:
  - Verify only supported address families (AF_INET, AF_INET6, AF_UNIX)
  - Check socket type validation (SOCK_STREAM, SOCK_DGRAM)
- **Socket Options**:
  - Verify socket options are set correctly
  - Check for insecure socket option combinations
  - Validate timeout values are reasonable

### Socket Operations Security:
- **Bind/Listen Security**:
  - Verify port number validation (1-65535)
  - Check for binding to privileged ports (< 1024) - may require root
  - Validate address binding prevents hijacking
- **Accept Security**:
  - Verify accepted socket validation
  - Check for connection limits (backlog size)
  - Validate peer address information
- **Connect Security**:
  - Verify hostname/DNS validation before connection
  - Check for DNS spoofing protection
  - Validate connection timeout settings
- **Send/Receive Security**:
  - Verify buffer size validation before operations
  - Check for partial send/receive handling
  - Validate message boundaries for datagrams

### DNS Resolution Security:
- **Hostname Validation**:
  - Verify hostname length limits
  - Check for DNS injection attempts
  - Validate hostname format before resolution
- **Resolution Timeout**:
  - Verify DNS resolution doesn't hang indefinitely
  - Check for timeout settings in async DNS
  - Validate error handling for resolution failures

### Buffer Management Security:
- **Circular Buffer Safety**:
  - Verify buffer bounds checking
  - Check for buffer overflow in write operations
  - Validate buffer size limits
- **Dynamic Buffer Growth**:
  - Verify overflow checks before buffer growth
  - Check for maximum size limits
  - Validate growth doesn't exhaust memory

### UDP Socket Security (`SocketDgram`):
- **Datagram Size Validation**:
  - Verify `UDP_MAX_PAYLOAD` (65507) limit enforcement
  - Check `SAFE_UDP_SIZE` (1472) recommendation for fragmentation avoidance
  - Validate received datagram length is within expected bounds
- **Connectionless Security**:
  - Verify source address validation for `recvfrom()`
  - Check for amplification attack vectors
  - Validate multicast group membership security

### Unix Domain Socket Security:
- **Path Security**:
  - Verify absolute path preference for socket paths
  - Check for stale socket file handling (`unlink()` before bind)
  - Validate path length limits (`sizeof(sun_path)`)
- **Credential Passing**:
  - Verify `SO_PEERCRED` usage for peer authentication
  - Check `Socket_getpeercred()` validation
  - Validate UID/GID checking for access control
- **File Permission Security**:
  - Check socket file permissions after creation
  - Verify `umask` considerations for socket creation

## 5. Check for Potential Injection Points

Identify all potential injection vulnerabilities:

### DNS Injection:
- **Hostname Injection**:
  - Check user-provided hostnames are sanitized
  - Verify DNS resolution doesn't allow command injection
  - Validate hostname format before resolution
- **DNS Response Validation**:
  - Verify DNS responses are validated
  - Check for DNS spoofing protection
  - Validate resolved addresses are reasonable

### Path Injection (Unix Domain Sockets):
- **Socket Path Validation**:
  - Check Unix domain socket paths are validated
  - Verify path traversal prevention (`../`, `//`, `~`)
  - Validate path length limits
  - Check for symlink attacks (use `O_NOFOLLOW` if applicable)

### Format String Injection:
- **Error Message Formatting**:
  - Verify all format strings are literal, not user-controlled
  - Check `fprintf()`, `printf()`, `snprintf()` usage
  - Flag any user input used as format string
  - Verify `MODULE_ERROR_FMT` uses safe format strings

### Buffer Injection:
- **Stack/Heap Buffer Overflows**:
  - Identify all user-controlled buffer writes
  - Verify bounds checking before all writes
  - Check for off-by-one errors
  - Validate buffer size calculations

### Data Injection:
- **Network Data Injection**:
  - Check for malicious network data handling
  - Verify protocol validation
  - Validate message boundaries
  - Check for buffer overflows in network operations

## 6. Thread Safety Security

Check for thread safety vulnerabilities:

### Race Conditions:
- **Shared Resource Access**:
  - Verify mutex protection for shared data
  - Check for unprotected critical sections
  - Validate thread-local storage usage is correct
- **Arena Thread Safety**:
  - Verify per-arena mutex protection
  - Check for concurrent access issues
  - Validate thread-local error buffers

### Exception Safety:
- **Exception Thread Safety**:
  - Verify thread-local exception stack usage (`Except_stack` is `__thread`)
  - Check for race conditions in exception handling
  - Validate `SOCKET_RAISE_MODULE_ERROR` thread-safe pattern (uses thread-local copy)
  - Verify `SOCKET_DECLARE_MODULE_EXCEPTION()` declares thread-local exception
- **NEVER directly modify global exception `.reason` field** (race condition)

### Live Count Tracking:
- **Socket Leak Detection**:
  - Verify `SocketLiveCount_increment/decrement` are balanced
  - Check `Socket_debug_live_count()` returns 0 after cleanup
  - Validate mutex protection for live count operations

## Security Review Output Format

For each security issue found, provide:

1. **Severity**: Critical / High / Medium / Low
2. **Vulnerability Type**: 
   - Buffer Overflow / Integer Overflow / Use-After-Free / Double-Free
   - Injection (SQL, Command, Header, Path, Format String)
   - Request Smuggling / Response Splitting
   - Input Validation / Bounds Checking
   - Network I/O / Protocol Violation
   - Thread Safety / Race Condition / TOCTOU
   - Timing Attack / Side Channel
   - Resource Exhaustion / DoS
   - Cryptographic Weakness
   - State Machine Manipulation
   - Callback Re-entrancy
   - Hash Collision
   - Compression Bomb
3. **Location**: File name and line number(s)
4. **Issue**: Clear description of the security vulnerability
5. **Attack Vector**: How an attacker could exploit this vulnerability
6. **Impact**: What could happen if exploited (code execution, DoS, data corruption, information disclosure, privilege escalation)
7. **Recommendation**: Specific fix with secure code example
8. **Reference**: Link to secure pattern in codebase or security best practice (RFC, CVE, etc.)

## Security-Focused Analysis Process

1. **Static Analysis**:
   - Scan for known unsafe function patterns
   - Identify all input points (network I/O, DNS resolution, HTTP parsing)
   - Trace data flow from input to vulnerable operations
   - Identify all arithmetic operations for overflow risks
   - Check for use of non-constant-time comparisons for secrets

2. **Control Flow Analysis**:
   - Trace all error paths for resource leaks
   - Verify all input validation points
   - Check all bounds checks are performed
   - Validate cleanup in all code paths (exception paths)
   - Verify state machine transitions are complete and correct

3. **Data Flow Analysis**:
   - Track network-controlled data through the codebase
   - Identify all uses of network input
   - Verify sanitization at input boundaries
   - Check for taint propagation issues
   - Track header values through HTTP/HPACK processing

4. **Attack Surface Mapping**:
   - Identify all external interfaces (socket operations, DNS, HTTP)
   - Map input sources to processing functions
   - Identify potential injection points
   - Document attack vectors
   - Map HTTP/2 frame types to handlers

5. **Protocol-Specific Analysis**:
   - HTTP/1.1: Request smuggling vectors (CL.TE, TE.CL, TE.TE)
   - HPACK: Decompression ratio, dynamic table manipulation
   - HTTP/2: Flow control window manipulation, stream state abuse
   - TLS: Certificate validation, protocol downgrade

6. **Concurrency Analysis**:
   - Identify shared mutable state
   - Check mutex acquisition order (deadlock prevention)
   - Verify callback safety (re-entrancy, no free from callback)
   - Check for TOCTOU race conditions in state checks

7. **Resource Exhaustion Analysis**:
   - Identify unbounded allocations
   - Check for maximum limits on collections/buffers
   - Verify timeouts on all blocking operations
   - Check rate limiting is applied at correct points

## 7. TLS Security Analysis

Comprehensive TLS/SSL security review:

### TLS Protocol Hardening:
- **Version Enforcement**:
  - Verify TLS1.3-only configuration (`SOCKET_TLS_MIN_VERSION`, `SOCKET_TLS_MAX_VERSION`)
  - Check that legacy protocols (TLS 1.0, 1.1, 1.2) are disabled by default
  - Validate no fallback to insecure protocol versions
- **Cipher Suite Security**:
  - Verify only modern ciphers used (`SOCKET_TLS13_CIPHERSUITES`)
  - Check for ECDHE-based key exchange (PFS - Perfect Forward Secrecy)
  - Validate no weak ciphers (RC4, DES, export ciphers)
  - Confirm AES-GCM or ChaCha20-Poly1305 AEAD modes only

### Certificate Validation:
- **Certificate Verification**:
  - Verify peer certificate validation is enforced (`TLS_VERIFY_PEER`)
  - Check hostname verification is performed
  - Validate certificate chain depth limits (`SOCKET_TLS_MAX_CERT_CHAIN_DEPTH`)
  - Check for proper CA certificate loading
- **Revocation Checking**:
  - Verify CRL support via `SocketTLSContext_load_crl()`
  - Check OCSP stapling support via `SocketTLSContext_set_ocsp_response()`
  - Validate `SocketTLS_get_ocsp_status()` usage for client-side OCSP verification
- **Custom Verification**:
  - Review `SocketTLSVerifyCallback` implementations for security
  - Verify custom callbacks don't bypass critical checks
  - Check return values are handled correctly (1=accept, 0=reject)

### SNI and ALPN Security:
- **SNI (Server Name Indication)**:
  - Verify SNI hostname length limits (`SOCKET_TLS_MAX_SNI_LEN`)
  - Check for hostname injection in SNI
  - Validate `SocketTLSContext_add_certificate()` usage
- **ALPN (Application-Layer Protocol Negotiation)**:
  - Verify ALPN protocol string length limits (`SOCKET_TLS_MAX_ALPN_LEN`)
  - Check for protocol injection in ALPN
  - Validate `SocketTLSContext_set_alpn_protos()` input validation

### Session Management Security:
- **Session Caching**:
  - Verify session cache size limits (`SOCKET_TLS_SESSION_CACHE_SIZE`)
  - Check session timeout configuration
  - Validate `SocketTLSContext_enable_session_cache()` settings
- **Session Tickets**:
  - Verify ticket key length is correct (80 bytes for OpenSSL)
  - Check ticket encryption key management
  - Validate `SocketTLSContext_enable_session_tickets()` key handling
  - Ensure ticket keys are rotated appropriately

### TLS Handshake Security:
- **Handshake State Machine**:
  - Verify `TLSHandshakeState` transitions are correct
  - Check timeout enforcement during handshake
  - Validate `SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS` is reasonable
- **Non-Blocking Handshake**:
  - Verify `SocketTLS_handshake()` handles `WANT_READ`/`WANT_WRITE` correctly
  - Check for infinite handshake loops
  - Validate handshake timeout enforcement

### TLS Error Handling:
- **Error Information Leakage**:
  - Verify TLS error messages don't leak sensitive information
  - Check `tls_error_buf[]` contents for information disclosure
  - Validate OpenSSL error queue is cleared properly

### TLS Disable Security (STARTTLS Reversal):
- **SocketTLS_disable() Security**:
  - Verify TLS buffers are securely cleared via `SocketCrypto_secure_clear()`
  - Check SSL object is properly freed after shutdown attempt
  - Validate socket state is reset correctly (tls_enabled, tls_handshake_done, tls_shutdown_done)
  - Confirm ALPN temporary data is cleaned up (`tls_cleanup_alpn_temp()`)
- **TLS-to-Plain Transition Security**:
  - Verify peer also expects the TLS-to-plain transition (protocol coordination)
  - Check no sensitive data remains in TLS buffers after disable
  - Validate `SocketTLS_disable()` performs best-effort shutdown (no exception on failure)
  - Confirm return value indicates shutdown quality (1=clean, 0=partial, -1=not enabled)

### DTLS Security (If Applicable):
- **Cookie Verification**:
  - Verify DTLS cookies use `SocketCrypto_hmac_sha256()` for generation
  - Check cookie verification is constant-time
  - Validate cookies are bound to client address
- **Replay Protection**:
  - Verify anti-replay window is implemented
  - Check sequence number handling
  - Validate stale packets are rejected
- **Fragmentation**:
  - Verify fragmented handshake messages are bounded
  - Check reassembly timeout is enforced
  - Validate no resource exhaustion via fragments

## 8. Rate Limiting and DoS Protection

Review denial-of-service protection mechanisms:

### Token Bucket Rate Limiting (`SocketRateLimit`):
- **Configuration Validation**:
  - Verify `tokens_per_sec` and `bucket_size` are reasonable
  - Check for integer overflow in token calculations
  - Validate rate limiter state under concurrent access
- **Bypass Prevention**:
  - Check `SocketRateLimit_try_acquire()` cannot be bypassed
  - Verify `SocketRateLimit_wait_time_ms()` returns correct values
  - Validate rate limiting is applied at correct points
- **Clock Manipulation**:
  - Verify `CLOCK_MONOTONIC` usage prevents time manipulation attacks
  - Check for time rollover handling in rate calculations

### Per-IP Connection Tracking (`SocketIPTracker`):
- **IP Address Validation**:
  - Verify IP address parsing is safe (IPv4 and IPv6)
  - Check for IP address spoofing considerations
  - Validate `SocketIPTracker_track()` handles edge cases (NULL, empty)
- **Limit Enforcement**:
  - Verify `max_per_ip` limits are enforced correctly
  - Check `SocketIPTracker_release()` decrements properly
  - Validate tracking survives connection cleanup
- **Resource Exhaustion**:
  - Check for hash table size limits
  - Verify memory growth is bounded
  - Validate cleanup of zero-count entries

### Circuit Breaker Pattern (`SocketReconnect`):
- **State Machine Security**:
  - Verify state transitions are atomic
  - Check circuit breaker thresholds (`circuit_failure_threshold`)
  - Validate half-open probe behavior
- **Backoff Security**:
  - Verify exponential backoff prevents connection storms
  - Check jitter prevents synchronized retries
  - Validate `max_delay_ms` caps are enforced
- **Health Monitoring**:
  - Verify `SocketReconnect_HealthCheck` callbacks are safe
  - Check health check timeout enforcement
  - Validate unhealthy connections are disconnected

### Bandwidth Limiting (Socket Level):
- **Token Bucket for Bandwidth**:
  - Verify `Socket_setbandwidth()` configures rate correctly
  - Check `Socket_send_limited()` enforces bandwidth cap
  - Validate `Socket_bandwidth_wait_ms()` returns correct wait time
- **Overflow Protection**:
  - Verify token bucket calculations don't overflow
  - Check bandwidth values are within reasonable bounds
  - Validate 0 means unlimited (disabled)
- **Bypass Prevention**:
  - Verify non-limited send/recv still works alongside limited
  - Check bandwidth limiting can't be bypassed by switching APIs
  - Validate per-socket vs per-connection bandwidth accounting

## 9. Secure Memory Handling

Review sensitive data handling:

### Secure Memory Clearing:
- **Buffer Cleanup**:
  - Verify `SocketBuf_secureclear()` is used for sensitive data
  - Check that `SocketBuf_clear()` vs `secureclear()` usage is appropriate
  - Validate memory is zeroed before deallocation
- **Connection Pool Security**:
  - Verify pool buffers are cleared with `SocketBuf_secureclear()` on removal
  - Check for residual sensitive data in reused buffers
  - Validate buffer reuse doesn't leak data between connections
- **Compiler Optimization**:
  - Verify secure clear functions aren't optimized away
  - Check for `volatile` or memory barrier usage if needed
  - Consider `memset_s` or `explicit_bzero` alternatives

### Sensitive Data Identification:
- **TLS Keys and Certificates**:
  - Verify private keys are cleared after use
  - Check session keys are properly destroyed
  - Validate ticket encryption keys are protected
- **Authentication Data**:
  - Check for passwords in buffers
  - Verify credentials are cleared after authentication
  - Validate no sensitive data in error messages

## 10. Time-Based Security

Review time-related security considerations:

### Monotonic Clock Usage:
- **Time Source Security**:
  - Verify `CLOCK_MONOTONIC` usage for security-critical timing
  - Check `Socket_get_monotonic_ms()` is used for:
    - Rate limiting timestamps
    - Timeout calculations
    - Elapsed time measurements
  - Validate fallback to `CLOCK_REALTIME` is safe
- **Time Manipulation Prevention**:
  - Verify timeouts can't be bypassed by clock changes
  - Check rate limiters use monotonic time
  - Validate DNS timeouts use monotonic time

### Timer Security (`SocketTimer`):
- **Timer Management**:
  - Verify min-heap implementation handles edge cases
  - Check `SocketTimer_cancel()` is safe for fired/cancelled timers
  - Validate timer callbacks don't modify timer state (cancel from callback not safe)
- **Timer Overflow**:
  - Check for integer overflow in timer calculations
  - Verify timer IDs don't wrap unsafely
  - Validate `CLOCK_MONOTONIC` usage for timer expiry

### Timeout Security:
- **DNS Resolution Timeouts**:
  - Verify `SocketDNS_settimeout()` and per-request timeouts
  - Check DNS requests can't hang indefinitely
  - Validate timeout cleanup doesn't leak resources
- **Connection Timeouts**:
  - Verify `SOCKET_DEFAULT_CONNECT_TIMEOUT_MS` is enforced
  - Check blocking operations have timeouts
  - Validate non-blocking fallback for timeouts
- **TLS Handshake Timeouts**:
  - Verify `SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS` enforcement
  - Check for slow-loris style handshake attacks
  - Validate incomplete handshakes are cleaned up

## 11. Async DNS Security

Review asynchronous DNS resolution security:

### Thread Pool Security:
- **Worker Thread Safety**:
  - Verify DNS worker threads handle errors safely
  - Check for resource leaks in worker threads
  - Validate thread termination during resolver shutdown
- **Queue Security**:
  - Verify request queue bounds (`SocketDNS_setmaxpending()`)
  - Check for queue overflow handling
  - Validate request cancellation is safe

### DNS Result Handling:
- **Result Ownership**:
  - Verify caller ownership of `addrinfo` results
  - Check `freeaddrinfo()` is called appropriately
  - Validate no double-free of DNS results
- **Result Validation**:
  - Check returned addresses are valid
  - Verify port information is preserved
  - Validate result isn't used after cancellation

### Signal Pipe Security:
- **Pipe Handling**:
  - Verify `SocketDNS_pollfd()` pipe is created safely
  - Check signal bytes are consumed properly
  - Validate pipe doesn't block or leak

## 12. Happy Eyeballs (RFC 8305) Security

Review dual-stack connection racing security:

### State Machine Security:
- **State Transitions**:
  - Verify `SocketHE_State` transitions are correct (IDLE -> RESOLVING -> CONNECTING -> CONNECTED/FAILED)
  - Check cancellation (`CANCELLED` state) is handled safely
  - Validate resource cleanup in all terminal states
- **Concurrent Connection Racing**:
  - Verify multiple connection attempts don't leak sockets
  - Check losing connections are closed properly
  - Validate winning connection is returned correctly

### Timeout Security:
- **Connection Attempt Delays**:
  - Verify `first_attempt_delay` (default 250ms) prevents connection storms
  - Check `per_attempt_timeout` (default 5s) is enforced
  - Validate `total_timeout` (default 30s) caps total operation time
- **DNS Resolution Timeouts**:
  - Verify DNS timeout is propagated to resolver
  - Check for DNS timeout handling in async mode

### Resource Management:
- **Address Cleanup**:
  - Verify `freeaddrinfo()` is called for DNS results
  - Check address lists are freed on cancellation/error
  - Validate no address info leaks
- **Socket Cleanup**:
  - Verify all attempted sockets are closed except winner
  - Check for socket leaks on timeout/error/cancellation
  - Validate `SocketHappyEyeballs_result()` transfers ownership correctly

## 13. HTTP/1.1 Parser Security (RFC 9112) - CRITICAL

Review HTTP/1.1 message parsing for request smuggling and injection attacks:

### Request Smuggling Prevention (RFC 9112 Section 6.3):
- **Content-Length/Transfer-Encoding Conflict**:
  - Verify parser REJECTS messages with BOTH Content-Length AND Transfer-Encoding
  - Check for CL.TE and TE.CL smuggling variants
  - Validate EXACTLY one body length determination method
- **Multiple Content-Length Headers**:
  - Verify parser REJECTS multiple Content-Length headers with differing values
  - Check identical Content-Length headers are coalesced
  - Validate no whitespace manipulation bypasses
- **Transfer-Encoding Validation**:
  - Verify only "chunked" is accepted (reject "chunked, identity", etc.)
  - Check for Transfer-Encoding: chunked smuggling via case variations
  - Validate no HTTP/0.9 fallback allows smuggling

### Header Injection Prevention:
- **Header Name Validation**:
  - Verify only valid token characters in header names (RFC 9110)
  - Check for CRLF injection in header names
  - Validate no NULL bytes in header names
- **Header Value Validation**:
  - Verify no bare CR or LF in header values (only as line folding)
  - Check for header value CRLF injection
  - Validate obs-fold (line continuation) handling per RFC 9112
- **Request Line Validation**:
  - Verify HTTP method is valid token
  - Check request-target for injection characters
  - Validate HTTP version format strictly

### Chunked Transfer Encoding Security:
- **Chunk Size Parsing**:
  - Verify chunk size has maximum limit (`max_chunk_size` config) - enforced in `handle_chunk_size_state`
  - Check for integer overflow in chunk size parsing - using uint64_t with pre-mult check in `parse_chunk_size`
  - Validate no excessively long chunk size lines - bounded by input, hex digits limited implicitly
- **Chunk Extension Security**:
  - Verify chunk extensions are bounded in length - enforced <= `config.max_chunk_ext` (default 1024) in `parse_chunk_size`; reject with `HTTP1_ERROR_INVALID_CHUNK_SIZE`
  - Check for injection in chunk extension values - skipped without parsing (RFC-compliant), but length-limited to prevent DoS
- **Trailer Security**:
  - Verify trailer headers are validated same as regular headers - full parsing with tchar/vchar checks
  - Check trailer size limits (`max_trailer_size` config) - enforced via `total_trailer_size` and `trailer_count` before `Headers_add`; reject `HEADER_TOO_LARGE`
  - Validate forbidden trailer headers are rejected (Transfer-Encoding, Content-Length, etc.) - checked via `is_forbidden_trailer` before add; reject `INVALID_TRAILER` to prevent smuggling

### Parser Limits and DoS Prevention:
- **Configurable Limits**:
  - `max_request_line` - Maximum request/status line length
  - `max_header_size` - Maximum total header section size
  - `max_chunk_size` - Maximum single chunk size
  - `max_trailer_size` - Maximum trailer section size
- **Resource Exhaustion**:
  - Verify limits are enforced before allocation
  - Check for slowloris-style attacks via slow header sending
  - Validate parser state doesn't grow unbounded

### Parser State Machine Security:
- **State Transitions**:
  - Verify `START -> HEADERS -> BODY -> COMPLETE` transitions are correct
  - Check `CHUNK_SIZE -> CHUNK_DATA -> CHUNK_SIZE` loop is bounded
  - Validate error states properly terminate parsing
- **Incremental Parsing**:
  - Verify `SocketHTTP1_Parser_execute()` handles partial data safely
  - Check parser state is consistent across multiple calls
  - Validate no buffer overread on partial tokens

## 14. HPACK Security (RFC 7541)

Review HTTP/2 header compression for HPACK bomb and resource exhaustion attacks:

### HPACK Bomb Prevention:
- **Dynamic Table Size Limits**:
  - Verify `max_table_size` is enforced (default 4096 bytes)
  - Check SETTINGS_HEADER_TABLE_SIZE updates don't exceed limit
  - Validate table size reduction properly evicts entries
- **Header Size Limits**:
  - Verify `max_header_size` limits individual header size
  - Check `max_header_list_size` limits total decoded header size
  - Validate limits are checked BEFORE allocation
- **Decompression Ratio Attacks**:
  - Check for excessive expansion from compressed input
  - Verify decoded size is bounded relative to encoded size
  - Consider decompression ratio limits

### Integer Coding Security:
- **Variable-Length Integer Overflow**:
  - Verify integer decoding checks for overflow
  - Check continuation byte count is bounded
  - Validate no infinite loops on malformed integers
- **Prefix Size Validation**:
  - Verify prefix size is 1-8 bits
  - Check integer coding handles edge cases (max values)

### Huffman Coding Security:
- **Huffman Decoding Attacks**:
  - Verify Huffman-decoded output is bounded
  - Check for excessive expansion in Huffman decoding
  - Validate `SocketHPACK_huffman_encoded_size()` calculation
- **Huffman Padding Validation**:
  - Verify padding is at most 7 bits of 1s (EOS symbol prefix)
  - Check invalid padding is rejected
  - Validate truncated Huffman sequences are detected

### Index Reference Security:
- **Static Table Bounds**:
  - Verify static table indices 1-61 are enforced
  - Check index 0 is rejected (invalid)
  - Validate no out-of-bounds static table access
- **Dynamic Table Bounds**:
  - Verify dynamic table indices are within current table size
  - Check evicted entries cannot be referenced
  - Validate index references after table size change

### Encoder/Decoder State Security:
- **State Consistency**:
  - Verify encoder/decoder states remain synchronized
  - Check dynamic table state is consistent after errors
  - Validate partial decode doesn't corrupt state
- **Thread Safety**:
  - Encoder/decoder instances are NOT thread-safe
  - Verify one encoder/decoder per connection
  - Check no shared state between connections

## 15. HTTP/2 Security (RFC 9113)

Review HTTP/2 protocol for flow control, multiplexing, and stream attacks:

### Flow Control Attacks:
- **Window Exhaustion DoS**:
  - Verify server can't be starved by client not sending WINDOW_UPDATE
  - Check initial window size (`SETTINGS_INITIAL_WINDOW_SIZE`) is reasonable
  - Validate connection-level vs stream-level window handling
- **Window Overflow Prevention**:
  - Verify `http2_flow_update_send/recv()` check for 2^31-1 overflow
  - Check WINDOW_UPDATE doesn't exceed maximum window size
  - Validate overflow results in FLOW_CONTROL_ERROR
- **Zero Window Attacks**:
  - Check for infinite wait on zero window
  - Verify timeout handling when window is exhausted
  - Validate server doesn't hold unlimited buffered data

### Stream Multiplexing Attacks:
- **MAX_CONCURRENT_STREAMS Enforcement**:
  - Verify `SETTINGS_MAX_CONCURRENT_STREAMS` is enforced
  - Check stream creation rejects when limit reached
  - Validate limit applies to client-initiated streams
- **Stream ID Validation**:
  - Verify stream IDs are odd for client, even for server
  - Check stream IDs are strictly increasing
  - Validate no stream ID reuse after GOAWAY
- **Rapid Reset Attack (CVE-2023-44487)**:
  - Verify RST_STREAM flood protection
  - Check rate limiting on stream creation/reset
  - Validate connection-level throttling for rapid resets
- **Stream State Machine Security**:
  - Verify all 7 states transition correctly
  - Check invalid state transitions cause STREAM_CLOSED error
  - Validate resource cleanup in CLOSED state

### SETTINGS Attacks:
- **SETTINGS Flood Prevention**:
  - Verify rate limiting on SETTINGS frames
  - Check `SETTINGS_TIMEOUT` enforcement for ACK
  - Validate SETTINGS changes are bounded
- **Malicious SETTINGS Values**:
  - Verify `SETTINGS_MAX_FRAME_SIZE` bounds (16384-16777215)
  - Check `SETTINGS_HEADER_TABLE_SIZE` propagates to HPACK safely
  - Validate `SETTINGS_ENABLE_PUSH` enforcement

### Frame Layer Security:
- **Frame Size Validation**:
  - Verify frame length <= `SETTINGS_MAX_FRAME_SIZE`
  - Check frame length doesn't exceed payload for frame type
  - Validate padding length < frame length
- **CONTINUATION Attack Prevention**:
  - Verify CONTINUATION frames are bounded in count
  - Check incomplete header blocks timeout
  - Validate no infinite CONTINUATION sequences
- **PING Flood Prevention**:
  - Verify PING frames are rate limited
  - Check PING ACK is sent promptly (but not amplified)
- **GOAWAY Handling**:
  - Verify GOAWAY last_stream_id is respected
  - Check graceful shutdown completes existing streams
  - Validate no new streams after GOAWAY

### Server Push Security:
- **PUSH_PROMISE Validation**:
  - Verify `SETTINGS_ENABLE_PUSH` is checked before push
  - Check pushed request headers are valid
  - Validate pushed stream IDs are even (server-initiated)
- **Push Exhaustion**:
  - Verify push doesn't exhaust MAX_CONCURRENT_STREAMS
  - Check client can reject unwanted pushes (RST_STREAM)

### h2c Upgrade Security:
- **Cleartext Upgrade Validation**:
  - Verify HTTP/1.1 upgrade request is well-formed
  - Check HTTP2-Settings header is valid base64url-encoded SETTINGS
  - Validate upgrade completes atomically
- **Downgrade Prevention**:
  - Check h2c is only used where appropriate (not over TLS)
  - Verify ALPN negotiation for h2 over TLS

## 16. Cryptographic Security (`SocketCrypto`)

Review cryptographic primitive security:

### Constant-Time Operations:
- **Timing Attack Prevention**:
  - Verify `SocketCrypto_secure_compare()` is constant-time
  - Check HMAC verification uses constant-time comparison
  - Validate no early-exit on comparison mismatch
- **Usage Verification**:
  - Verify all authentication checks use `secure_compare()`
  - Check password/token comparisons are constant-time
  - Validate no `memcmp()` or `strcmp()` for secrets

### Secure Random Generation:
- **CSPRNG Security**:
  - Verify `SocketCrypto_random_bytes()` uses OpenSSL `RAND_bytes()` or `/dev/urandom`
  - Check for proper seeding on startup
  - Validate fallback for non-TLS builds is cryptographically secure
- **Random Usage**:
  - Verify session tokens use cryptographic random
  - Check nonces are generated with CSPRNG
  - Validate no predictable random values

### Secure Memory Clearing:
- **Compiler Optimization Prevention**:
  - Verify `SocketCrypto_secure_clear()` won't be optimized away
  - Check for `volatile` usage or memory barriers
  - Validate equivalent to `explicit_bzero()` or `memset_s()`
- **Clearing Coverage**:
  - Verify private keys are cleared after use
  - Check session keys are cleared on connection close
  - Validate intermediate cryptographic values are cleared

### Hash Function Security:
- **Algorithm Selection**:
  - Verify SHA-256 is used for security-critical hashing
  - Check MD5 and SHA-1 are only used where required by protocol (e.g., WebSocket)
  - Validate no security-critical use of weak hashes
- **HMAC Security**:
  - Verify `SocketCrypto_hmac_sha256()` uses proper key lengths
  - Check HMAC keys are generated securely
  - Validate HMAC verification is constant-time

### WebSocket Security (RFC 6455):
- **Handshake Key Validation**:
  - Verify `SocketCrypto_websocket_accept()` computes correct response
  - Check `Sec-WebSocket-Key` format validation (16 bytes base64)
  - Validate `Sec-WebSocket-Accept` generation uses SHA-1 correctly
- **Key Generation**:
  - Verify `SocketCrypto_websocket_key()` uses CSPRNG for 16-byte key
  - Check generated keys are properly base64 encoded

### Encoding Security:
- **Base64 Security**:
  - Verify `SocketCrypto_base64_decode()` validates input characters
  - Check for buffer overflow in base64 encode/decode
  - Validate padding is handled correctly
- **Hex Encoding Security**:
  - Verify `SocketCrypto_hex_decode()` validates hex characters
  - Check output buffer size is sufficient

## 17. WebSocket Security (RFC 6455) - `SocketWS`

Review WebSocket protocol implementation for security vulnerabilities:

### Frame Masking Security (RFC 6455 Section 5.3):
- **Client-to-Server Masking**:
  - Verify ALL client frames are masked (mask bit = 1)
  - Check `SocketCrypto_random_bytes()` used for mask key generation
  - Validate unmasked client frames cause connection close
- **Server-to-Client Masking**:
  - Verify server frames are NOT masked (mask bit = 0)
  - Check masked server frames cause client to close connection
- **Masking Implementation**:
  - Verify 8-byte aligned XOR masking for performance
  - Check mask key is never reused within session
  - Validate masking doesn't leak plaintext on partial operations

### Frame Validation Security:
- **Opcode Validation**:
  - Verify only valid opcodes accepted (0x0-0x2, 0x8-0xA)
  - Check reserved opcodes (0x3-0x7, 0xB-0xF) cause protocol error
- **Control Frame Limits**:
  - Verify control frames (PING, PONG, CLOSE) <= 125 bytes
  - Check control frames are not fragmented (FIN must be 1)
  - Validate control frames can be interleaved in fragmented message
- **Reserved Bits (RSV1-3)**:
  - Verify RSV bits are 0 unless extension negotiated
  - Check RSV1 allowed only with permessage-deflate
  - Validate unknown RSV bits cause protocol error

### Fragmentation Security:
- **Fragment Reassembly Limits**:
  - Verify `max_fragments` config limits fragment count
  - Check `max_message_size` bounds total reassembled size
  - Validate intermediate fragment state is bounded
- **Fragment Ordering**:
  - Verify continuation frames follow initial fragment (opcode 0)
  - Check no data frames interleave fragmented message
  - Validate final fragment has FIN bit set
- **Resource Exhaustion**:
  - Check for DoS via many small fragments
  - Verify timeout on incomplete fragmented messages
  - Validate fragment state cleanup on connection close

### Close Handshake Security:
- **Close Code Validation**:
  - Verify close codes are valid (1000-1003, 1007-1011, 3000-4999)
  - Check reserved codes (1004-1006, 1015) are not sent
  - Validate close reason is UTF-8 and <= 123 bytes
- **Close Handshake Completion**:
  - Verify server waits for client close after sending close
  - Check client initiates TCP close after receiving close response
  - Validate timeout on close handshake completion
- **Abnormal Closure**:
  - Check 1006 (Abnormal Closure) is never sent over wire
  - Verify proper state transition to CLOSED on TCP error

### UTF-8 Validation Security:
- **Text Frame Validation**:
  - Verify ALL text frame payloads are validated for UTF-8
  - Check `SocketUTF8_update()` used for incremental validation
  - Validate invalid UTF-8 causes close with 1007 (Invalid Payload)
- **Fragmented Text Validation**:
  - Verify UTF-8 validation spans fragments correctly
  - Check incomplete UTF-8 at fragment boundary is handled
  - Validate `SocketUTF8_finish()` called on final fragment
- **Close Reason Validation**:
  - Verify close reason is validated for UTF-8
  - Check invalid UTF-8 in close reason causes 1007

### Handshake Security:
- **Client Handshake**:
  - Verify `Sec-WebSocket-Key` is 16 random bytes base64 encoded
  - Check `Sec-WebSocket-Accept` validation uses constant-time compare
  - Validate HTTP/1.1 101 status is required
- **Server Handshake**:
  - Verify `Sec-WebSocket-Key` from client is validated
  - Check `Sec-WebSocket-Accept` computed correctly (SHA-1 + base64)
  - Validate origin checking if required by application
- **Subprotocol Negotiation**:
  - Verify only offered subprotocols can be selected
  - Check single subprotocol in server response
  - Validate unknown subprotocol in response causes failure

### permessage-deflate Security (RFC 7692):
- **Compression Bomb Prevention**:
  - Verify decompressed size is bounded relative to compressed
  - Check `max_message_size` applies to decompressed data
  - Validate incremental decompression with size checks
- **Context Takeover**:
  - Verify `no_context_takeover` setting is respected
  - Check compression context isolation between messages
- **Window Bits Validation**:
  - Verify window bits negotiation (8-15)
  - Check agreed parameters are enforced

### DoS Protection:
- **Frame Size Limits**:
  - Verify `max_frame_size` config (default 16MB)
  - Check frame size validated BEFORE allocation
  - Validate oversized frames cause close with 1009
- **Message Size Limits**:
  - Verify `max_message_size` config (default 64MB)
  - Check reassembled message size tracked during fragmentation
  - Validate oversized messages cause close with 1009
- **PING Flood Prevention**:
  - Verify PING frames are rate limited
  - Check PONG responses don't amplify attack
- **Auto-Ping Security**:
  - Verify ping interval is reasonable (not too frequent)
  - Check pong timeout triggers connection close
  - Validate auto-ping timer uses monotonic clock

### Available SocketWS Functions:
- `SocketWS_config_defaults()` - Initialize config with secure defaults
- `SocketWS_client_new()` / `SocketWS_server_accept()` - Connection lifecycle
- `SocketWS_handshake()` - Complete upgrade handshake
- `SocketWS_send_text()` / `SocketWS_send_binary()` - Send messages
- `SocketWS_recv_message()` - Receive complete messages
- `SocketWS_ping()` / `SocketWS_pong()` - Control frames
- `SocketWS_close()` - Initiate close handshake
- `SocketWS_state()` - Query connection state
- `SocketWS_close_code()` / `SocketWS_close_reason()` - Close status
- `SocketWS_last_error()` / `SocketWS_error_string()` - Error handling

## 18. UTF-8 Validation Security (`SocketUTF8`)

Review UTF-8 validation for encoding attacks:

### Overlong Encoding Attacks:
- **Overlong Sequence Detection**:
  - Verify `UTF8_OVERLONG` result is returned for overlong encodings
  - Check all overlong variants are detected (e.g., 0xC0 0x80 for NUL)
  - Validate no directory traversal via overlong `../`
- **Security Impact**:
  - Overlong encodings can bypass security filters
  - Verify input is rejected, not normalized

### Surrogate Pair Validation:
- **Surrogate Detection**:
  - Verify `UTF8_SURROGATE` result for UTF-16 surrogates (U+D800-U+DFFF)
  - Check surrogate pairs are rejected in UTF-8 (invalid)
  - Validate lone surrogates are detected
- **Security Impact**:
  - Surrogates in UTF-8 indicate encoding confusion attacks

### Invalid Code Point Rejection:
- **Code Point Bounds**:
  - Verify `UTF8_TOO_LARGE` for code points > U+10FFFF
  - Check non-characters are handled appropriately
  - Validate BOM (U+FEFF) handling if required
- **DFA Completeness**:
  - Verify DFA handles all invalid byte sequences
  - Check truncated sequences return `UTF8_INCOMPLETE`
  - Validate no false positives (valid UTF-8 rejected)

### Incremental Validation Security:
- **Streaming Validation**:
  - Verify `SocketUTF8_update()` handles split multi-byte sequences
  - Check state is consistent across calls
  - Validate `SocketUTF8_finish()` detects incomplete sequences
- **State Reset**:
  - Verify `SocketUTF8_init()` properly resets state
  - Check no state leakage between validations

### Usage in Protocols:
- **WebSocket Text Frames**:
  - Verify all WebSocket text frame payloads are UTF-8 validated
  - Check invalid UTF-8 causes connection close (per RFC 6455)
- **HTTP Headers**:
  - Verify header values are validated where UTF-8 is expected
  - Check Content-Disposition filename validation

## 19. SYN Flood Protection (`SocketSYNProtect`)

Review SYN flood DoS protection mechanisms:

### Implemented Mitigations (Post-Fixes):
- **CIDR Validation**: `parse_cidr_notation` uses `strtol` with endptr validation to reject invalid prefixes (e.g., `/abc` fails, no /0 bypass).
- **Whitelist Efficiency**: Single IP parse per check; byte-based matching for all CIDRs via `_bytes` functions, preventing O(n) `inet_pton` DoS.
- **Arena Safety**: Eviction disabled in arena mode; hard cap at `max_tracked_ips` to avoid bloat.
- **Metrics**: Active-only counts for blocked IPs (IP timed + blacklist non-expired).
- **Hash Randomization**: `hash_seed` in config (auto-crypto random); mixed into DJB2 for per-instance variation against collisions.

### Remaining Review Points:
- Connection attempt tracking: Per-IP counting, reputation, LRU.
- etc. (rest unchanged)

### Connection Attempt Tracking:
- **IP-Based Tracking**:
  - Verify per-IP connection attempt counting
  - Check for IPv4/IPv6 address normalization
  - Validate tracking data structure bounds
- **Attempt Rate Limiting**:
  - Verify connection attempts are rate-limited per IP
  - Check burst handling for legitimate traffic
  - Validate rate decay over time

### Reputation Scoring:
- **Score Calculation**:
  - Verify reputation scores range 0.0-1.0
  - Check score decay over time (forgiveness)
  - Validate score increases on violations
- **Score-Based Actions**:
  - `SYN_ACTION_ALLOW` - Good reputation, allow immediately
  - `SYN_ACTION_THROTTLE` - Medium reputation, add delay
  - `SYN_ACTION_CHALLENGE` - Poor reputation, require proof-of-work or TCP challenge
  - `SYN_ACTION_BLOCK` - Bad reputation, reject connection

### Kernel Integration:
- **TCP_DEFER_ACCEPT (Linux)**:
  - Verify `TCP_DEFER_ACCEPT` is used to delay accept() until data arrives
  - Check timeout is appropriate
- **SO_ACCEPTFILTER (BSD)**:
  - Verify `SO_ACCEPTFILTER` with `dataready` or `httpready` filter
  - Check filter is appropriate for protocol
- **SYN Cookies**:
  - Verify kernel SYN cookie support is enabled when available
  - Check application handles SYN cookie connections correctly

### Resource Limits:
- **Tracking Table Size**:
  - Verify tracking table has maximum size
  - Check for memory exhaustion via many unique IPs
  - Validate cleanup of stale entries
- **Action Queue**:
  - Verify pending challenge queue is bounded
  - Check challenged connections timeout

## 20. Connection Pool Security (`SocketPool`)

Review connection pool for resource exhaustion and data leakage:

### Connection Slot Exhaustion:
- **Pool Capacity**:
  - Verify pool has maximum connection limit
  - Check `SocketPool_add()` returns NULL when full
  - Validate rate limiting integration prevents flooding
- **Idle Connection Cleanup**:
  - Verify idle connections are cleaned up
  - Check idle timeout is enforced
  - Validate cleanup doesn't cause use-after-free

### Buffer Security:
- **Buffer Reuse Between Connections**:
  - Verify `SocketBuf_secureclear()` is called before buffer reuse
  - Check for data leakage between connections
  - Validate buffer state is reset properly
- **Per-Connection Buffer Limits**:
  - Verify per-connection buffer sizes are bounded
  - Check buffer growth doesn't cause memory exhaustion

### Graceful Shutdown Security:
- **Drain State Machine**:
  - Verify `RUNNING -> DRAINING -> STOPPED` transitions are correct
  - Check drain timeout is enforced
  - Validate no new connections during drain
- **Force Close**:
  - Verify `SocketPool_drain_force()` closes all connections
  - Check no connection leaks on force close
  - Validate resources are freed in correct order
- **Callback Safety**:
  - Verify `SocketPool_DrainCallback` is called safely
  - `SocketPool_free()` IS safe from drain callback (exception to callback rule)

### Thread Safety:
- **Mutex Protection**:
  - Verify all pool operations are mutex-protected
  - Check for deadlock scenarios
  - Validate mutex is not held across callbacks (to prevent deadlock)

## 21. State Machine Security

Review state machine implementations for manipulation attacks:

### State Transition Security:
- **Valid Transition Enforcement**:
  - Verify only valid state transitions are allowed
  - Check invalid transitions raise appropriate errors
  - Validate state machine cannot be forced into invalid state
- **Atomic Transitions**:
  - Verify state transitions are atomic (thread-safe where needed)
  - Check for TOCTOU race conditions in state checks
  - Validate state and associated data are updated together

### Terminal State Handling:
- **Resource Cleanup**:
  - Verify resources are freed when entering terminal states
  - Check for resource leaks on error transitions
  - Validate cleanup is idempotent (safe to call twice)
- **Post-Terminal Access**:
  - Verify operations on terminated state machines are rejected
  - Check for use-after-free on terminated instances

### Modules with State Machines:
- **SocketHappyEyeballs**: IDLE -> RESOLVING -> CONNECTING -> CONNECTED/FAILED/CANCELLED
- **SocketReconnect**: DISCONNECTED -> CONNECTING -> CONNECTED -> BACKOFF -> CIRCUIT_OPEN
- **SocketTLS**: Handshake states (WANT_READ, WANT_WRITE, COMPLETE, ERROR)
- **SocketSYNProtect**: Connection attempt state tracking
- **SocketPool**: RUNNING -> DRAINING -> STOPPED
- **SocketHTTP1_Parser**: START -> HEADERS -> BODY -> COMPLETE
- **SocketHTTP2**: Stream states (IDLE -> OPEN -> HALF_CLOSED -> CLOSED)
- **SocketProxy**: IDLE -> CONNECTING_PROXY -> TLS_TO_PROXY -> HANDSHAKE -> CONNECTED/FAILED
- **SocketWS**: CONNECTING -> OPEN -> CLOSING -> CLOSED

## 22. Callback Security

Review callback patterns for re-entrancy and safety issues:

### Re-Entrancy Attacks:
- **Callback-During-Callback**:
  - Verify callbacks don't cause re-entrant calls to same module
  - Check for stack overflow via recursive callbacks
  - Validate module state is consistent during callback
- **Module Destruction from Callback**:
  - **NEVER** call `Module_free()` from within its own callback
  - **EXCEPTION**: `SocketPool_free()` IS safe from `SocketPool_DrainCallback`
  - Verify callbacks don't trigger unexpected destruction

### Callback Thread Safety:
- **Execution Context**:
  - Callbacks execute in thread calling `process()` or `SocketPoll_wait()`
  - Verify callbacks don't assume different thread context
  - Check for thread-local state access in callbacks
- **Mutex Holding**:
  - Verify mutexes are NOT held during callbacks (deadlock risk)
  - Check callback can safely acquire mutexes if needed
  - Validate no priority inversion via callbacks

### Callback Registration Security:
- **Function Pointer Validation**:
  - Verify NULL callbacks are handled (no-op or error)
  - Check callback function pointer isn't from untrusted source
- **Userdata Lifetime**:
  - Verify userdata pointer remains valid for callback lifetime
  - Check for use-after-free of userdata

## 23. Hash Table Security

Review hash table implementations for collision attacks:

### Hash Collision DoS:
- **DJB2 Hash Security**:
  - DJB2 is vulnerable to algorithmic complexity attacks
  - Verify hash tables have collision limits or use randomization
  - Check for O(n) degradation with crafted inputs
- **Golden Ratio Hash Security**:
  - Verify `socket_util_hash_fd()` distribution is adequate
  - Check for predictable hash values with sequential FDs
- **Mitigation Strategies**:
  - Consider hash randomization (seed from CSPRNG)
  - Implement maximum chain length limits
  - Use Robin Hood hashing for bounded probe sequences

### Hash Table Limit Enforcement:
- **Size Limits**:
  - Verify hash tables have maximum size limits
  - Check for memory exhaustion via many entries
  - Validate resize operations check limits
- **Entry Cleanup**:
  - Verify stale entries are removed
  - Check for memory leaks in entry removal
  - Validate no dangling pointers after removal

### Case-Insensitive Hashing:
- **HTTP Header Hashing**:
  - Verify `socket_util_hash_djb2_ci()` is correctly case-insensitive
  - Check for Unicode case folding issues (if applicable)
  - Validate consistent hashing for lookup and insertion

## 24. Compression Security (If ENABLE_HTTP_COMPRESSION)

Review compression for bomb and side-channel attacks:

### Decompression Bomb Prevention:
- **Expansion Ratio Limits**:
  - Verify decompressed size is bounded relative to compressed size
  - Check for maximum decompressed size limit
  - Validate incremental decompression checks limits
- **Memory Allocation**:
  - Verify decompression buffer allocation is bounded
  - Check for integer overflow in size calculations
  - Validate out-of-memory handling

### BREACH-Style Attacks:
- **Compression Oracle**:
  - Be aware that compression can leak secrets via size
  - Document that BREACH mitigation is application responsibility
  - Consider disabling compression for sensitive responses
- **Mitigation Documentation**:
  - Add random padding to responses (application layer)
  - Separate secrets from attacker-controlled content
  - Use per-message compression (not connection-level)

### Supported Algorithms:
- **gzip/deflate (zlib)**:
  - Verify zlib is used safely (no buffer overruns)
  - Check for zlib version vulnerabilities
- **Brotli (libbrotli)**:
  - Verify Brotli decoder limits are configured
  - Check for Brotli-specific attacks

## Socket Library-Specific Security Considerations

Given this is a socket library:

- **Network Protocol Security**: Verify protocol handling doesn't allow injection
- **Address Handling**: Ensure address parsing doesn't allow injection
- **DNS Security**: Verify DNS resolution prevents injection and spoofing
- **Memory Safety**: Critical for network library - verify all memory operations are safe
- **Error Messages**: Ensure error messages don't leak sensitive information
- **Thread Safety**: Critical for concurrent socket operations
- **Buffer Management**: Verify all buffer operations are bounds-checked

### HTTP Layer Security:
- **Request Smuggling**: Critical for HTTP/1.1 parser (RFC 9112 Section 6.3)
- **Header Injection**: Validate all header names and values
- **HPACK Bombs**: Limit decompression expansion ratio
- **HTTP/2 Flow Control**: Prevent window exhaustion attacks
- **Rapid Reset**: Rate limit stream creation/reset (CVE-2023-44487)

### WebSocket Layer Security:
- **Frame Masking**: Enforce client masking, reject server masking
- **UTF-8 Validation**: Validate all text frames, close with 1007 on error
- **Fragmentation Limits**: Bound fragment count and reassembled size
- **Control Frame Limits**: Enforce 125-byte limit on PING/PONG/CLOSE
- **Compression Bombs**: Bound decompressed size in permessage-deflate

### Cryptographic Security:
- **Timing Attacks**: Use constant-time comparisons for all secrets
- **Secure Random**: Use CSPRNG for all security-critical random values
- **Memory Clearing**: Ensure secrets are cleared from memory
- **TLS1.3 Only**: Enforce modern protocol and cipher suites

### Connection Management Security:
- **SYN Flood Protection**: Use reputation scoring and kernel features
- **Rate Limiting**: Token bucket at connection and bandwidth levels
- **Graceful Shutdown**: Ensure resources are freed on drain timeout
- **Pool Exhaustion**: Limit maximum connections and per-IP limits

### Encoding Security:
- **UTF-8 Validation**: Reject overlong encodings and surrogates
- **Base64/Hex**: Validate input format before decoding
- **Huffman**: Bound decoded output size

## 25. Centralized Security Configuration (SocketSecurity.h)

The `SocketSecurity.h` header provides a single reference point for all security limits and validation utilities.

### Security Limits Documentation:
All security limits are documented in `SocketSecurity.h` with their source headers:

| Category | Limit | Default | Source Header |
|----------|-------|---------|---------------|
| Memory | `SOCKET_SECURITY_MAX_ALLOCATION` | 256MB | SocketSecurity.h |
| Memory | `SOCKET_MAX_BUFFER_SIZE` | 1MB | SocketConfig.h |
| Memory | `ARENA_MAX_ALLOC_SIZE` | 100MB | SocketConfig.h |
| HTTP | `SOCKETHTTP_MAX_URI_LEN` | 8KB | SocketHTTP.h |
| HTTP | `SOCKETHTTP_MAX_HEADER_SIZE` | 64KB | SocketHTTP.h |
| HTTP | `SOCKETHTTP_MAX_HEADERS` | 100 | SocketHTTP.h |
| HTTP/1.1 | `SOCKETHTTP1_MAX_REQUEST_LINE` | 8KB | SocketHTTP1.h |
| HTTP/1.1 | `SOCKETHTTP1_MAX_CHUNK_SIZE` | 16MB | SocketHTTP1.h |
| HTTP/2 | `SOCKETHTTP2_DEFAULT_MAX_CONCURRENT_STREAMS` | 100 | SocketHTTP2.h |
| HTTP/2 | `SOCKETHTTP2_DEFAULT_MAX_FRAME_SIZE` | 16KB | SocketHTTP2.h |
| HPACK | `SOCKETHPACK_MAX_TABLE_SIZE` | 64KB | SocketHPACK.h |
| WebSocket | `SOCKETWS_MAX_FRAME_SIZE` | 16MB | SocketWS-private.h |
| WebSocket | `SOCKETWS_MAX_MESSAGE_SIZE` | 64MB | SocketWS-private.h |
| TLS | `SOCKET_TLS_MAX_CERT_CHAIN_DEPTH` | 10 | SocketTLSConfig.h |
| Rate Limit | `SOCKET_RATELIMIT_DEFAULT_CONN_PER_SEC` | 100/s | SocketConfig.h |
| Rate Limit | `SOCKET_RATELIMIT_DEFAULT_MAX_PER_IP` | 10 | SocketConfig.h |
| Connections | `SOCKET_MAX_CONNECTIONS` | 10000 | SocketConfig.h |
| Timeout | `SOCKET_DEFAULT_CONNECT_TIMEOUT_MS` | 30s | SocketConfig.h |
| Timeout | `SOCKET_DEFAULT_DNS_TIMEOUT_MS` | 5s | SocketConfig.h |

### Runtime Limit Query:
```c
SocketSecurityLimits limits;
SocketSecurity_get_limits(&limits);
/* Now access: limits.max_allocation, limits.http_max_uri_length, etc. */
```

### Compile-Time Override:
All limits can be overridden at compile time:
```c
#define SOCKET_SECURITY_MAX_ALLOCATION (128 * 1024 * 1024)  /* 128MB */
#include "core/SocketSecurity.h"
```

### Security Test Suite:
The `src/test/test_security.c` file contains comprehensive security tests (33 tests):
- Integer overflow protection verification
- Buffer safety and bounds checking
- HTTP/1.1 request smuggling rejection
- Header injection prevention
- UTF-8 security validation (overlong, surrogates)
- Cryptographic security (secure_compare, secure_clear)
- Size limit enforcement

Run security tests with: `ctest -R test_security`

## Established Security Patterns to Verify

The codebase implements these security patterns - verify they are used consistently:

### Centralized Security Utilities (SocketSecurity.h):
- **SocketSecurity_get_limits(&limits)** - Query all configured security limits at runtime
- **SocketSecurity_get_max_allocation()** - Get maximum safe allocation size
- **SocketSecurity_get_http_limits()** - Query HTTP-specific limits
- **SocketSecurity_get_ws_limits()** - Query WebSocket-specific limits
- **SocketSecurity_check_size(size)** - Validate allocation size against maximum
- **SocketSecurity_check_multiply(a, b, &result)** - Overflow-safe multiplication
- **SocketSecurity_check_add(a, b, &result)** - Overflow-safe addition
- **SocketSecurity_safe_multiply(a, b)** - Inline overflow-safe multiplication
- **SocketSecurity_safe_add(a, b)** - Inline overflow-safe addition
- **SocketSecurity_has_tls()** - Check if TLS support is compiled in
- **SocketSecurity_has_compression()** - Check if HTTP compression is available

### Security Validation Macros (SocketSecurity.h):
- **SOCKET_SECURITY_VALID_SIZE(s)** - Validate size within safe limits
- **SOCKET_SECURITY_CHECK_OVERFLOW_MUL(a, b)** - Check multiplication overflow
- **SOCKET_SECURITY_CHECK_OVERFLOW_ADD(a, b)** - Check addition overflow

### Error Handling:
- **SOCKET_ERROR_FMT/MSG macros** - Use `snprintf()` with truncation handling
- **Thread-local error buffers** - `socket_error_buf[]` for thread-safe errors
- **Thread-local exception copies** - `SOCKET_DECLARE_MODULE_EXCEPTION()` pattern
- **SOCKET_RAISE_FMT/MSG macros** - Combined format-and-raise for consistency

### Safe System Calls:
- **SAFE_CLOSE macro** - Proper EINTR handling per POSIX.1-2008
- **Socket_safe_strerror()** - Thread-safe strerror alternative

### Input Validation Macros:
- **SOCKET_VALID_PORT(p)** - Port range validation (1-65535)
- **SOCKET_VALID_BUFFER_SIZE(s)** - Buffer size validation

### Hash Functions:
- **socket_util_hash_fd()** - Golden ratio multiplicative hash for FDs
- **socket_util_hash_ptr()** - Pointer hashing for opaque handles
- **socket_util_hash_uint()** - Unsigned integer hashing
- **socket_util_hash_djb2()** - String hash (null-terminated)
- **socket_util_hash_djb2_len()** - Length-aware string hash
- **socket_util_hash_djb2_ci()** - Case-insensitive hash (for HTTP headers)
- **socket_util_hash_djb2_ci_len()** - Length-aware + case-insensitive

### Cryptographic Patterns:
- **SocketCrypto_secure_compare()** - Constant-time comparison for secrets
- **SocketCrypto_secure_clear()** - Non-optimizable memory clearing
- **SocketCrypto_random_bytes()** - CSPRNG for security-critical random

### Memory Safety Patterns:
- **SocketBuf_secureclear()** - Secure buffer clearing for sensitive data
- **Arena-based allocation** - Lifecycle-bound memory management
- **SocketLiveCount** - Resource leak detection in tests

### State Machine Patterns:
- **Explicit state enums** - All states enumerated and documented
- **Terminal state cleanup** - Resources freed on terminal transitions
- **Atomic transitions** - Thread-safe state changes where needed

### Callback Safety Patterns:
- **No Module_free() from callbacks** - Except SocketPool drain callback
- **No mutex held during callbacks** - Prevents deadlock
- **Userdata lifetime management** - Caller ensures validity

## Priority Focus Areas

1. **Critical**: 
   - Buffer overflows
   - HTTP request smuggling (RFC 9112 Section 6.3)
   - TLS configuration errors
   - Injection vulnerabilities (header, path, format string)
   - Integer overflows in network operations
   - HPACK bombs / HTTP/2 flow control attacks
   - Rapid reset attacks (CVE-2023-44487)
   - WebSocket masking violations (RFC 6455)
   - WebSocket compression bombs (permessage-deflate)

2. **High**: 
   - Input validation gaps
   - DNS security issues
   - Thread safety vulnerabilities / race conditions
   - Rate limiting bypass
   - Timing attacks (non-constant-time comparisons)
   - State machine manipulation
   - Callback re-entrancy

3. **Medium**: 
   - Resource leaks
   - Unsafe string function usage
   - Missing bounds checks
   - Secure memory clearing
   - Hash collision DoS
   - UTF-8 validation bypasses
   - Compression bombs (if enabled)

4. **Low**: 
   - Style issues
   - Minor validation improvements
   - Defensive programming
   - Documentation of security limitations

## Security Verification Commands

```bash
# Run security-specific tests
ctest -R test_security --output-on-failure

# Run full test suite with sanitizers
cmake -B build -DENABLE_SANITIZERS=ON
cmake --build build
cd build && ctest --output-on-failure

# Run fuzzing (requires Clang)
cmake -B build -DENABLE_FUZZING=ON -DCMAKE_C_COMPILER=clang
cmake --build build
./scripts/run_fuzz_parallel.sh

# Valgrind memory checking
valgrind --leak-check=full --track-fds=yes ./build/test_security
```

Provide a prioritized security assessment with exploitability analysis for each vulnerability found, focusing on network-specific attack vectors and socket library usage patterns.
