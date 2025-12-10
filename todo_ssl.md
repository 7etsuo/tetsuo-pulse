# SSL/TLS Implementation Todo

Comprehensive checklist for the SSL/TLS and DTLS implementation in the tetsuo-socket library.
This document covers all aspects of the secure transport layer including implementation status,
testing requirements, documentation, security hardening, and future enhancements.

---

## Table of Contents

1. [Core TLS Implementation](#1-core-tls-implementation)
2. [TLS Context Management](#2-tls-context-management)
3. [TLS Configuration](#3-tls-configuration)
4. [Core DTLS Implementation](#4-core-dtls-implementation)
5. [DTLS Context Management](#5-dtls-context-management)
6. [DTLS Configuration](#6-dtls-configuration)
7. [Shared Internal Utilities](#7-shared-internal-utilities)
8. [Testing Requirements](#8-testing-requirements)
9. [Documentation](#9-documentation)
10. [Security Hardening](#10-security-hardening)
11. [Performance Optimizations](#11-performance-optimizations)
12. [Future Enhancements](#12-future-enhancements)

---

## 1. Core TLS Implementation

**Files:** `include/tls/SocketTLS.h`, `src/tls/SocketTLS.c`

### 1.1 TLS Enable/Disable Operations — *depends on 2.1, 3.\*, 7.\**
**Difficulty: 3/9** _(Completed - verification of existing implementation)_

- [x] **SocketTLS_enable()**: Verify that enabling TLS on an already-TLS-enabled socket raises `SocketTLS_Failed` with a clear error message indicating the socket is already secured
  - ✅ Implemented in `validate_tls_enable_preconditions()` at `SocketTLS.c:200-201` - raises "TLS already enabled on socket"
- [x] **SocketTLS_enable()**: Ensure proper cleanup of SSL object if `SSL_set_fd()` fails after `SSL_new()` succeeds (currently implemented but verify no resource leaks)
  - ✅ Implemented in `associate_ssl_with_fd()` at `SocketTLS.c:250-258` - calls `tls_cleanup_alpn_temp()` and `SSL_free()` on failure
- [x] **TLS Disable**: Consider adding `SocketTLS_disable()` function to allow graceful TLS teardown without closing the underlying socket (use case: TLS-to-plain downgrade for STARTTLS reversal)
  - ✅ Implemented `SocketTLS_disable()` at `SocketTLS.c:491-569` - best-effort shutdown, always cleans up, returns status (1=clean, 0=partial, -1=not enabled)
- [x] **Multiple Context Support**: Verify behavior when enabling TLS with different contexts on the same socket type (should reject or handle gracefully)
  - ✅ Handled by "TLS already enabled" check - attempting to enable with different context raises `SocketTLS_Failed`

### 1.2 TLS Handshake State Machine — *depends on 1.1, 3.3, 3.4*
**Difficulty: 5/9** _(Completed - state machine with edge cases)_

- [x] **SocketTLS_handshake()**: Verify all `TLSHandshakeState` transitions are correctly handled, especially edge cases like `TLS_HANDSHAKE_WANT_READ` followed by socket close
  - ✅ Verified in `tls_handle_ssl_error()` at `SocketTLS.c:261-311` - `SSL_ERROR_SYSCALL` with `errno == 0` (unexpected EOF after WANT_READ) correctly sets `errno = ECONNRESET` and returns `TLS_HANDSHAKE_ERROR`
- [x] **SocketTLS_handshake_loop()**: Add configurable poll interval parameter (currently uses `SOCKET_TLS_POLL_INTERVAL_MS` constant)
  - ✅ Added `SocketTLS_handshake_loop_ex()` at `SocketTLS.c:686-703` with configurable `poll_interval_ms` parameter
  - ✅ Declared in `SocketTLS.h` with comprehensive Doxygen documentation
  - ✅ Original `SocketTLS_handshake_loop()` uses default `SOCKET_TLS_POLL_INTERVAL_MS` (100ms)
- [x] **SocketTLS_handshake_auto()**: Verify it correctly uses socket's `operation_timeout_ms` or falls back to `SOCKET_DEFAULT_TLS_HANDSHAKE_TIMEOUT_MS`
  - ✅ Verified at `SocketTLS.c:705-715` - uses `socket->base->timeouts.operation_timeout_ms` with fallback to `SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS` (30000ms)
- [x] **Handshake Metrics**: Ensure `SOCKET_CTR_TLS_HANDSHAKES_TOTAL` and `SOCKET_CTR_TLS_HANDSHAKES_FAILED` metrics are incremented correctly
  - ✅ Added metrics to `SocketTLS_handshake()` at `SocketTLS.c:392-423`:
    - `SOCKET_CTR_TLS_HANDSHAKES_TOTAL` incremented on successful completion and on failure
    - `SOCKET_CTR_TLS_HANDSHAKES_FAILED` incremented on error (SSL not available, handshake error)
  - ✅ Added `SOCKET_HIST_TLS_HANDSHAKE_TIME_MS` histogram observation in `handshake_loop_internal()` at `SocketTLS.c:631-656` for duration tracking
  - ✅ Timeout failures also increment both metrics at `SocketTLS.c:661-668`
- [x] **Handshake Timeout Handling**: Verify that handshake timeout raises `SocketTLS_HandshakeFailed` with descriptive error including elapsed time
  - ✅ Implemented in `handshake_loop_internal()` at `SocketTLS.c:661-668` - error message now includes: "TLS handshake timeout after %lld ms (timeout: %d ms)"

### 1.3 TLS I/O Operations — *depends on 1.2*
**Difficulty: 4/9** _(Completed - I/O handling with partial writes)_

- [x] **SocketTLS_send()**: Verify partial write handling when `SSL_MODE_ENABLE_PARTIAL_WRITE` is set
  - ✅ Verified: SSL_MODE_ENABLE_PARTIAL_WRITE enabled in `create_ssl_object()`. Function returns bytes written, caller must loop for remaining data. Documented in header with example code.
- [x] **SocketTLS_send()**: Ensure proper errno setting (EAGAIN) for non-blocking sockets when send would block
  - ✅ Implemented: SSL_get_error checks for SSL_ERROR_WANT_READ/WANT_WRITE, sets errno=EAGAIN and returns 0. Documented behavior.
- [x] **SocketTLS_recv()**: Verify handling of `SSL_ERROR_ZERO_RETURN` (clean peer shutdown) vs `SSL_ERROR_SYSCALL` (abrupt close)
  - ✅ Implemented: Proper switch on SSL_get_error distinguishes:
    - SSL_ERROR_ZERO_RETURN → Socket_Closed with errno=0 (clean shutdown)
    - SSL_ERROR_SYSCALL with result=0 && errno=0 → Socket_Closed with errno=ECONNRESET (abrupt close)
- [x] **SocketTLS_recv()**: Ensure `Socket_Closed` exception is raised appropriately on clean shutdown
  - ✅ Implemented: Socket_Closed raised for both clean and abrupt shutdown, with errno differentiating the cases. Documented with example code in header.
- [x] **Large Buffer Handling**: Test send/recv with buffers larger than `SOCKET_TLS_BUFFER_SIZE` (16KB TLS record max)
  - ✅ Already implemented: Buffers > INT_MAX capped to INT_MAX. TLS record size is handled internally by OpenSSL. Documented in both send/recv functions.
- [x] **Zero-Length Operations**: Verify behavior of send/recv with zero-length buffers (should return 0 immediately or raise error)
  - ✅ Implemented: len=0 returns 0 immediately without invoking SSL_write/read. Matches POSIX semantics. Documented in header.

### 1.4 TLS Shutdown — *depends on 1.2, 3.3*
**Difficulty: 5/9** _(Completed - bidirectional shutdown with polling)_

- [x] **SocketTLS_shutdown()**: Verify bidirectional close_notify alert handling in non-blocking mode
  - ✅ Implemented dedicated `shutdown_handle_ssl_error()` that properly handles WANT_READ/WANT_WRITE via polling
  - ✅ Added proper poll loop with `POLL_READ | POLL_WRITE` events for bidirectional shutdown
- [x] **SocketTLS_shutdown()**: Test behavior when peer doesn't respond to close_notify (timeout handling)
  - ✅ Uses `SocketTimeout_deadline_ms()` with configurable timeout (default 5 seconds)
  - ✅ On timeout, sends close_notify (best effort) and raises `SocketTLS_ShutdownFailed`
- [x] **SocketTLS_shutdown()**: Ensure `SocketTLS_ShutdownFailed` is raised only on actual errors, not on EAGAIN
  - ✅ Fixed: EAGAIN/EWOULDBLOCK handled via internal polling loop, only protocol errors raise exceptions
  - ✅ Added `shutdown_handle_ssl_error()` function that returns 1 (continue polling) for WANT_*, 0 for success, -1 for fatal
- [x] **Shutdown State Tracking**: Verify `tls_shutdown_done` flag is set correctly after successful shutdown
  - ✅ Flag set to 1 on complete shutdown (SSL_shutdown returns 1)
  - ✅ Flag set to 0 on partial/failed shutdown (timeout, connection lost)
- [x] **Partial Shutdown**: Consider supporting half-close (send shutdown without waiting for peer response)
  - ✅ Added `SocketTLS_shutdown_send()` function for unidirectional (half-close) shutdown
  - ✅ Uses `SSL_set_quiet_shutdown()` to skip waiting for peer's close_notify
  - ✅ Returns 0 with errno=EAGAIN if would block on non-blocking sockets

### 1.5 Session Management — *depends on 1.2, 2.11, 2.12*
**Difficulty: 5/9** _(Completed - TLS 1.3 session handling)_

- [x] **SocketTLS_session_save()**: Verify session serialization works correctly for TLS 1.3 sessions
  - ✅ Added comprehensive TLS 1.3 documentation: sessions delivered via NewSessionTicket AFTER handshake
  - ✅ Added session expiration check using `SSL_SESSION_get_timeout()` and `SSL_SESSION_get_time()`
  - ✅ Documented timing: call after I/O activity to ensure ticket receipt
- [x] **SocketTLS_session_save()**: Test buffer size requirements and proper handling when buffer too small
  - ✅ Returns 0 and sets `*len` to required size when buffer is NULL or too small
  - ✅ Added size query pattern: `SocketTLS_session_save(sock, NULL, &len)`
- [x] **SocketTLS_session_restore()**: Verify session restoration before handshake (must be called after enable, before handshake)
  - ✅ Added explicit check: returns -1 if `tls_handshake_done` is already set
  - ✅ Added clear documentation of required call order
- [x] **SocketTLS_session_restore()**: Test with expired/invalid session data (should gracefully fall back to full handshake)
  - ✅ Checks session expiration before setting, returns 0 (not error) for expired sessions
  - ✅ Returns 0 for invalid/corrupted DER data from `d2i_SSL_SESSION()`
  - ✅ Returns 0 if `SSL_set_session()` fails (rare but handled)
- [x] **SocketTLS_is_session_reused()**: Verify accurate detection of session resumption after handshake
  - ✅ Added precondition checks: returns -1 if TLS not enabled or handshake not done
  - ✅ Added TLS 1.3 PSK resumption documentation

### 1.6 Renegotiation Control — *depends on 1.2*
**Difficulty: 4/9** _(Completed - DoS protection for TLS 1.2)_

- [x] **SocketTLS_check_renegotiation()**: Verify this correctly handles TLS 1.2 renegotiation requests
  - ✅ Implemented with proper SSL_renegotiate_pending() and SSL_get_secure_renegotiation_support() checks
  - ✅ Handles WANT_READ/WANT_WRITE for non-blocking operation
  - ✅ Raises SocketTLS_ProtocolError on handshake failure
- [x] **SocketTLS_check_renegotiation()**: Confirm TLS 1.3 correctly returns 0 (no renegotiation support)
  - ✅ TLS 1.3 check via SSL_version() >= TLS1_3_VERSION returns 0 (not -1, since there's nothing pending)
- [x] **SocketTLS_disable_renegotiation()**: Verify this sets appropriate SSL options to reject renegotiation
  - ✅ Uses SSL_OP_NO_RENEGOTIATION option (OpenSSL 1.1.0h+)
  - ✅ Resets renegotiation counter on disable
- [x] **Renegotiation DoS Protection**: Ensure renegotiation limits are enforced if renegotiation is allowed
  - ✅ Added SOCKET_TLS_MAX_RENEGOTIATIONS limit (default 3)
  - ✅ Added tls_renegotiation_count field to Socket_T
  - ✅ Added SocketTLS_get_renegotiation_count() for monitoring
  - ✅ Increments SOCKET_CTR_TLS_RENEGOTIATIONS metric on renegotiation events

### 1.7 Certificate Information — *depends on 1.2, 2.2*
**Difficulty: 4/9** _(Completed - X509 parsing and extraction)_

- [x] **SocketTLS_get_peer_cert_info()**: Verify all fields of `SocketTLS_CertInfo` are correctly populated
  - ✅ All fields populated: subject, issuer, not_before, not_after, version, serial, fingerprint
  - ✅ Uses X509_NAME_oneline() for subject/issuer (handles special characters via escaping)
  - ✅ Uses ASN1_TIME_to_tm() for time conversion
  - ✅ Uses SocketCrypto_hex_encode() for safe fingerprint generation
- [x] **SocketTLS_get_peer_cert_info()**: Test with certificates having special characters in subject/issuer
  - ✅ X509_NAME_oneline() handles special characters by escaping them (OpenSSL standard behavior)
- [x] **SocketTLS_get_cert_expiry()**: Verify correct handling of certificates with notAfter in distant future
  - ✅ Uses ASN1_TIME_to_tm() which handles dates correctly
  - ✅ Returns (time_t)-1 on error/no cert
- [x] **SocketTLS_get_cert_subject()**: Test buffer size handling when subject exceeds buffer length
  - ✅ Updated documentation to note truncation behavior (always null-terminated)
  - ✅ Return value can be checked against len-1 to detect truncation
- [x] **Certificate Chain Access**: Added function to get full certificate chain
  - ✅ Implemented SocketTLS_get_peer_cert_chain() returning X509** array
  - ✅ Array allocated from socket's arena; certs are references (caller must NOT free)
  - ✅ Documented client vs server chain behavior difference

### 1.8 OCSP Client-Side Status — *depends on 1.2, 2.6*
**Difficulty: 6/9** _(Completed - OCSP response parsing and verification)_

- [x] **SocketTLS_get_ocsp_response_status()**: Verify parsing of OCSP response from server's stapled response
  - ✅ Uses SSL_get_tlsext_status_ocsp_resp() to get stapled response
  - ✅ Parses with d2i_OCSP_RESPONSE() and OCSP_response_get1_basic()
- [x] **SocketTLS_get_ocsp_response_status()**: Test all return values (GOOD=1, REVOKED=0, UNKNOWN=-1, NO_RESPONSE=-1, VERIFY_FAILED=-2)
  - ✅ All values correctly returned based on V_OCSP_CERTSTATUS_* codes
  - ✅ Stale responses return -1 (unknown/no response)
- [x] **OCSP Response Validation**: Ensure OCSP response signature is verified against the issuer certificate
  - ✅ Added OCSP_basic_verify() with certificate chain and X509_STORE
  - ✅ Uses OCSP_TRUSTOTHER flag to trust certificates in chain for responder
  - ✅ Returns -2 on signature verification failure
- [x] **OCSP Response Freshness**: Added check for OCSP response nextUpdate field
  - ✅ Uses OCSP_check_validity() with SOCKET_TLS_OCSP_MAX_AGE_SECONDS tolerance (300s default)
  - ✅ Added SocketTLS_get_ocsp_next_update() to retrieve nextUpdate timestamp
  - ✅ Stale responses are rejected (return -1)

### 1.9 Connection Information Queries — *depends on 1.2*
**Difficulty: 3/9** _(Completed - simple accessor functions)_

- [x] **SocketTLS_get_cipher()**: Verify correct cipher name returned for all TLS 1.3 cipher suites
  - ✅ Implementation verified at `SocketTLS.c:1199-1210` - uses `SSL_get_current_cipher()` and `SSL_CIPHER_get_name()`
  - ✅ Returns IANA cipher suite names for TLS 1.3 (e.g., "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256")
  - ✅ Returns NULL for non-TLS sockets or before handshake
  - ✅ Unit test added: `tls_get_cipher_tls13` in `test_tls_integration.c`
- [x] **SocketTLS_get_version()**: Verify "TLSv1.3" string returned for TLS 1.3 connections
  - ✅ Implementation verified at `SocketTLS.c:1213-1219` - uses `SSL_get_version()`
  - ✅ Returns "TLSv1.3" for TLS 1.3 connections as expected
  - ✅ Returns NULL for non-TLS sockets
  - ✅ Unit test added: `tls_get_version_tls13` in `test_tls_integration.c`
- [x] **SocketTLS_get_alpn_selected()**: Test when no ALPN was negotiated (should return NULL)
  - ✅ Implementation verified at `SocketTLS.c:1288-1312` - uses `SSL_get0_alpn_selected()`
  - ✅ Correctly returns NULL when `alpn_data` is NULL or `alpn_len` is 0
  - ✅ Validates ALPN length against `SOCKET_TLS_MAX_ALPN_LEN` to prevent buffer overflow
  - ✅ Unit test added: `tls_get_alpn_no_negotiation` in `test_tls_integration.c`
- [x] **SocketTLS_get_verify_result()**: Verify correct X509_V_* error codes are returned
  - ✅ Implementation verified at `SocketTLS.c:1221-1234` - uses `SSL_get_verify_result()`
  - ✅ Returns `X509_V_ERR_INVALID_CALL` for invalid state (not enabled, no handshake)
  - ✅ Returns correct X509_V_* codes: `X509_V_OK`, `X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT`, `X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN`, etc.
  - ✅ Unit test added: `tls_get_verify_result_codes` in `test_tls_integration.c`
- [x] **SocketTLS_get_verify_error_string()**: Test buffer handling and truncation for long error strings
  - ✅ Implementation verified at `SocketTLS.c:1236-1265` - uses `X509_verify_cert_error_string()` and `ERR_error_string_n()`
  - ✅ Returns NULL for invalid parameters (NULL socket, NULL buf, size=0)
  - ✅ Returns NULL when verify result is X509_V_OK (no error)
  - ✅ Uses `strncpy` with `size - 1` for proper truncation
  - ✅ Always null-terminates the buffer: `buf[size - 1] = '\0'`
  - ✅ Handles edge cases: 1-byte buffer, small buffers, normal buffers
  - ✅ Unit test added: `tls_get_verify_error_string_buffer` in `test_tls_integration.c`

---

## 2. TLS Context Management

**Files:** `include/tls/SocketTLSContext.h`, `src/tls/SocketTLSContext-*.c`

### 2.1 Context Creation and Destruction — *depends on 3.\*, 7.\**
**Difficulty: 4/9** _(Mostly complete - ref counting deferred)_

- [x] **SocketTLSContext_new_server()**: Verify TLS 1.3-only enforcement via `SSL_CTX_set_min/max_proto_version()`
  - ✅ Implemented in `configure_tls13_only()` at `SocketTLSContext-core.c:219-248` - sets min/max to `SOCKET_TLS_MIN_VERSION`/`SOCKET_TLS_MAX_VERSION` (TLS1_3_VERSION)
- [x] **SocketTLSContext_new_server()**: Test with invalid cert/key paths (should raise `SocketTLS_Failed` with file path in error)
  - ✅ Implemented in `validate_file_path_or_raise()` and `ctx_raise_error_fmt()` at `SocketTLSContext-certs.c:65-70` - includes file path in error message
- [x] **SocketTLSContext_new_server()**: Verify cert/key mismatch detection via `SSL_CTX_check_private_key()`
  - ✅ Implemented at `SocketTLSContext-certs.c:110-111` - calls `SSL_CTX_check_private_key()` and raises "Private key does not match certificate"
- [x] **SocketTLSContext_new_client()**: Test with NULL ca_file (should warn but allow for testing)
  - ✅ Implemented at `SocketTLSContext-core.c:599-617` - handles NULL via system CA fallback with warning logging
- [x] **SocketTLSContext_new()**: Verify custom config struct is correctly applied
  - ✅ Implemented at `SocketTLSContext-core.c:545-572` - applies custom config via `apply_custom_protocol_config()`
- [x] **SocketTLSContext_free()**: Ensure all resources are freed including Arena, SSL_CTX, SNI arrays, ALPN data
  - ✅ Implemented at `SocketTLSContext-core.c:619-646` - frees SSL_CTX, Arena, SNI arrays, and all other resources
- [x] **SocketTLSContext_free()**: Verify sensitive key material is securely cleared via `OPENSSL_cleanse()`
  - ✅ Implemented at `SocketTLSContext-core.c:395-407` - uses `OPENSSL_cleanse()` for ticket key and `SocketCrypto_secure_clear()` for pins
- [ ] **Context Reference Counting**: Consider adding reference counting for shared contexts across threads
  - ⏳ Deferred: Not critical for current release; contexts should be created per-thread or protected by application-level synchronization

### 2.2 Certificate and Key Loading — *depends on 2.1, 7.1*
**Difficulty: 5/9** _(Completed - PEM parsing, chain handling)_

- [x] **SocketTLSContext_load_certificate()**: Verify PEM format validation and error messages
  - ✅ Uses OpenSSL's `SSL_CTX_use_certificate_file()` at `SocketTLSContext-certs.c:102-104` - OpenSSL validates PEM format; raises `ctx_raise_openssl_error()` on failure
- [x] **SocketTLSContext_load_certificate()**: Test with certificate chain files (multiple certs in one file)
  - ✅ Implemented in `load_chain_from_file()` at `SocketTLSContext-certs.c:373-406` - reads multiple certs from PEM file via `PEM_read_X509()` loop
- [x] **SocketTLSContext_add_certificate()**: Verify SNI-based certificate selection callback is installed
  - ✅ Implemented in `register_sni_callback_if_needed()` at `SocketTLSContext-certs.c:529-538` - installs `sni_callback` via `SSL_CTX_set_tlsext_servername_callback()`
- [x] **SocketTLSContext_add_certificate()**: Test with wildcard certificates (*.example.com)
  - ✅ Implemented in `validate_hostname_matches_cert()` at `SocketTLSContext-certs.c:548-563` - uses `X509_check_host()` which supports wildcard matching per RFC 6125
- [x] **Certificate File Size Limits**: Verify `SOCKET_TLS_MAX_CERT_FILE_SIZE` (1MB) limit is enforced
  - ✅ Implemented in `check_pem_file_size()` at `SocketTLSContext-certs.c:317-350` - uses `SOCKET_TLS_MAX_CERT_FILE_SIZE` constant (1MB)
- [x] **Encrypted Private Keys**: Document that encrypted keys are not supported (require passphrase callback)
  - ✅ Documented in `load_pkey_from_file()` at `SocketTLSContext-certs.c:415-445` - passphrase callback is NULL; error message updated to indicate encrypted keys not supported

### 2.3 CA Loading and Verification — *depends on 2.1*
**Difficulty: 4/9** _(Completed - OpenSSL verify integration)_

- [x] **SocketTLSContext_load_ca()**: Verify both file and directory modes work (hashed directory names)
  - ✅ Implemented at `SocketTLSContext-certs.c:114-128` - tries file mode first via `SSL_CTX_load_verify_locations(ca_file, NULL)`, then directory mode via `(NULL, ca_file)`
- [x] **SocketTLSContext_load_ca()**: Test with multiple calls (should accumulate CAs, not replace)
  - ✅ OpenSSL's `SSL_CTX_load_verify_locations()` accumulates CAs in the X509_STORE; multiple calls add to existing store
- [x] **SocketTLSContext_set_verify_mode()**: Verify correct mapping to `SSL_VERIFY_*` flags
  - ✅ Implemented in `verify_mode_to_openssl()` at `SocketTLSContext-verify.c:60-77` - correctly maps TLS_VERIFY_* to SSL_VERIFY_* flags
- [x] **SocketTLSContext_set_verify_mode()**: Test `TLS_VERIFY_FAIL_IF_NO_PEER_CERT` for mTLS enforcement
  - ✅ Maps to `SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT` at `SocketTLSContext-verify.c:70-71` - enforces client cert requirement
- [x] **Verify Depth**: Verify `SOCKET_TLS_MAX_CERT_CHAIN_DEPTH` (10) is applied
  - ✅ Implemented in `configure_tls13_only()` at `SocketTLSContext-core.c:247` - calls `SSL_CTX_set_verify_depth()` with `SOCKET_TLS_MAX_CERT_CHAIN_DEPTH`
- [x] **System CA Loading**: Test `SSL_CTX_set_default_verify_paths()` fallback when no CA file provided
  - ✅ Implemented in `try_load_system_ca()` at `SocketTLSContext-core.c:480-491` - uses `SSL_CTX_set_default_verify_paths()` as fallback

### 2.4 Custom Verification Callbacks — *depends on 2.1, 2.3*
**Difficulty: 6/9** _(Callback design, thread safety, exception handling)_

- [x] **SocketTLSContext_set_verify_callback()**: Verify callback receives correct parameters (preverify_ok, x509_ctx, tls_ctx, socket, user_data)
  - ✅ Implemented in `invoke_user_callback()` at `SocketTLSContext-verify.c:274-298` - callback receives all parameters correctly via `internal_verify_callback()` wrapper at lines 338-365
- [x] **SocketTLSContext_set_verify_callback()**: Test callback returning 0 (reject) stops handshake
  - ✅ Implemented in `invoke_user_callback()` at `SocketTLSContext-verify.c:281-297` - return 0 sets `X509_V_ERR_APPLICATION_VERIFICATION` and fails verification; tested in `test_tls_phase4.c:verify_callback_api` and `test_tls_integration.c:tls_verify_callback_integration`
- [x] **Callback Thread Safety**: Document that callbacks may be called from multiple threads if context is shared
  - ✅ Documented in `SocketTLSContext.h` - extensive thread safety documentation added to `SocketTLSVerifyCallback` typedef (lines 383-450) and `SocketTLSContext_set_verify_callback()` (lines 470-530)
- [x] **Callback Exception Handling**: Verify exceptions in callbacks are properly caught and converted to handshake failures
  - ✅ Implemented in `invoke_user_callback()` at `SocketTLSContext-verify.c:279-297` - uses TRY/EXCEPT to catch `SocketTLS_Failed` and ELSE block for all other exceptions, sets `X509_V_ERR_APPLICATION_VERIFICATION`; tested in `test_tls_phase4.c:tls_verify_callback_exception` and `tls_verify_callback_generic_exception`

### 2.5 CRL Management — *depends on 2.1, 2.3, 7.1, 7.2*
**Difficulty: 7/9** _(Complex - auto-refresh, file watching, X509_STORE integration)_

- [x] **SocketTLSContext_load_crl()**: Verify CRL file loading and X509_STORE integration
  - ✅ Implemented in `SocketTLSContext-verify.c:471-515` - loads CRL via `X509_STORE_load_locations()`, enables `X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL`; tested in `test_tls_crl.c:test_load_crl_basic`
- [x] **SocketTLSContext_load_crl()**: Test with CRL directory (multiple CRL files)
  - ✅ Tested in `test_tls_crl.c:test_load_crl_directory` - creates temp directory with hash-named CRL files, verifies directory loading works
- [x] **SocketTLSContext_refresh_crl()**: Verify CRL is reloaded from disk and added to store
  - ✅ Implemented in `SocketTLSContext-verify.c:517-527` - calls `SocketTLSContext_load_crl()` to accumulate CRLs; tested in `test_tls_crl.c:test_refresh_crl`
- [x] **SocketTLSContext_reload_crl()**: Verify alias for refresh_crl works correctly
  - ✅ Implemented in `SocketTLSContext-verify.c:529-535` - alias for `refresh_crl()`; tested in `test_tls_crl.c:test_reload_crl`
- [x] **SocketTLSContext_set_crl_auto_refresh()**: Verify interval validation (minimum 60 seconds)
  - ✅ Implemented in `SocketTLSContext-crl.c:118-135` via `validate_crl_interval()` - rejects <60s and >1 year; tested in `test_tls_crl.c:test_crl_interval_validation` and `test_crl_minimum_interval_boundary`
- [x] **SocketTLSContext_set_crl_auto_refresh()**: Test callback invocation on success and failure
  - ✅ Tested in `test_tls_crl.c:test_crl_auto_refresh_callback` (success) and `test_tls_crl_integration.c:test_crl_refresh_missing_file` (failure callback)
- [x] **SocketTLSContext_cancel_crl_auto_refresh()**: Verify refresh is stopped but current CRL retained
  - ✅ Implemented in `SocketTLSContext-crl.c:325-341` - clears interval/callback but preserves loaded CRLs; tested in `test_tls_crl.c:test_cancel_crl_auto_refresh`
- [x] **SocketTLSContext_crl_check_refresh()**: Verify monotonic time-based scheduling
  - ✅ Implemented in `SocketTLSContext-crl.c:354-400` - uses `Socket_get_monotonic_ms()` for CLOCK_MONOTONIC timing; tested in `test_tls_crl_integration.c:test_crl_refresh_timing`
- [x] **SocketTLSContext_crl_next_refresh_ms()**: Test overflow protection for far-future refreshes
  - ✅ Implemented in `SocketTLSContext-crl.c:410-441` - caps result at LONG_MAX for overflow protection; tested in `test_tls_crl.c:test_crl_next_refresh_overflow`
- [x] **CRL Path Validation**: Verify path traversal prevention and symlink rejection
  - ✅ Implemented in `SocketTLSContext-crl.c:43-188` via `validate_crl_path_security()` - checks for "..", control chars, uses `realpath()` validation; tested in `test_tls_crl.c:test_crl_path_security` and `test_crl_symlink_rejection`
- [x] **CRL File Size Limits**: Verify `SOCKET_TLS_MAX_CRL_SIZE` (10MB) limit is enforced
  - ✅ Implemented in `SocketTLSContext-verify.c:410-427` via `validate_crl_file_size()` - checks against 10MB limit; tested in `test_tls_crl.c:test_crl_file_size_limit`; fuzzer coverage in `fuzz_tls_crl.c:CRL_OP_LOAD_OVERSIZED`

### 2.6 OCSP Stapling (Server-Side) — *depends on 2.1, 2.2*
**Difficulty: 6/9** _(Server-side OCSP response generation and stapling)_

- [x] **SocketTLSContext_set_ocsp_response()**: Verify static OCSP response is stapled in handshakes
  - ✅ Implemented in `SocketTLSContext-verify.c:703-723` - validates format via `d2i_OCSP_RESPONSE()`, size limit, stores in context arena
- [x] **SocketTLSContext_set_ocsp_response()**: Test with invalid/malformed OCSP response (should reject)
  - ✅ Validates format at `SocketTLSContext-verify.c:692-700` via `validate_ocsp_response_format()` - raises `SocketTLS_Failed` on parse failure; fuzzer coverage in `fuzz_tls_ocsp.c:OCSP_SET_STATIC_RESPONSE`
- [x] **SocketTLSContext_set_ocsp_gen_callback()**: Verify dynamic callback is invoked during handshake
  - ✅ Implemented in `SocketTLSContext-verify.c:725-737` - registers `status_cb_wrapper()` via `SSL_CTX_set_tlsext_status_cb()` which invokes user callback
- [x] **SocketTLSOcspGenCallback**: Document return value ownership (OpenSSL takes ownership of OCSP_RESPONSE*)
  - ✅ Extensively documented in `SocketTLSContext.h:719-762` - includes ownership semantics, code examples, SNI support pattern, caching guidance
- [x] **SocketTLSContext_enable_ocsp_stapling()**: Verify client-side STATUS_REQUEST extension is sent
  - ✅ Implemented in `SocketTLSContext-verify.c:834-848` - calls `SSL_CTX_set_tlsext_status_type()` with `TLSEXT_STATUSTYPE_ocsp`; sets `ctx->ocsp_stapling_enabled = 1`
- [x] **SocketTLSContext_ocsp_stapling_enabled()**: Verify query function returns correct state
  - ✅ Implemented in `SocketTLSContext-verify.c:850-855` - returns `ctx->ocsp_stapling_enabled`; tested in `fuzz_tls_ocsp.c:fuzz_enable_ocsp_stapling()`
- [x] **OCSP Response Size Limits**: Verify `SOCKET_TLS_MAX_OCSP_RESPONSE_LEN` (64KB) limit
  - ✅ Enforced at `SocketTLSContext-verify.c:677-683` via `validate_ocsp_response_size()` and in `status_cb_wrapper()` at line 661-666

### 2.7 Custom Certificate Lookup — *depends on 2.1, 2.4*
**Difficulty: 5/9** _(Callback for HSM/database cert retrieval)_

- [x] **SocketTLSContext_set_cert_lookup_callback()**: Verify callback is invoked during verification
  - ✅ Implemented in `SocketTLSContext-verify.c:863-919` - stores callback and integrates with OpenSSL via `X509_STORE_set_lookup_certs_cb()` on OpenSSL 1.1.0+; wrapper at `cert_lookup_wrapper()` invokes user callback
- [x] **SocketTLSCertLookupCallback**: Document X509 ownership (caller takes ownership of returned cert)
  - ✅ Extensively documented in `SocketTLSContext.h:840-920` - includes ownership semantics, HSM example code, database example code, thread safety requirements
- [x] **HSM Integration**: Document use case for loading certificates from Hardware Security Modules
  - ✅ Documented in `SocketTLSContext.h:857-874` with complete PKCS#11 code example showing subject lookup, DER parsing, and ownership transfer
- [x] **Database Integration**: Document use case for loading certificates from database storage
  - ✅ Documented in `SocketTLSContext.h:876-893` with complete SQL/LDAP code example showing hash-based lookup, PEM parsing, and ownership transfer

### 2.8 Protocol Version Configuration — *depends on 2.1, 3.1*
**Difficulty: 3/9** _(Simple config with validation)_

- [ ] **SocketTLSContext_set_min_protocol()**: Verify TLS 1.3 enforcement (default should be TLS1_3_VERSION)
- [ ] **SocketTLSContext_set_min_protocol()**: Test fallback to options-based version control for older OpenSSL
- [ ] **SocketTLSContext_set_max_protocol()**: Verify setting works correctly
- [ ] **Version Override Warning**: Log warning if min_version < TLS1_3_VERSION (insecure configuration)

### 2.9 Cipher Suite Configuration — *depends on 2.1, 3.2* ✅ COMPLETE
**Difficulty: 4/9** _(Cipher string parsing and validation)_

- [x] **SocketTLSContext_set_cipher_list()**: Verify cipher string parsing and validation ✅
  - Implemented in `SocketTLSContext-verify.c` with SSL_CTX_set_cipher_list()
  - Uses `SOCKET_TLS_LEGACY_CIPHER_LIST` as default for TLS < 1.3
- [x] **SocketTLSContext_set_cipher_list()**: Test with NULL (should use secure defaults) ✅
  - NULL defaults to `SOCKET_TLS_LEGACY_CIPHER_LIST` = "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA"
- [x] **TLS 1.3 Ciphersuites**: Verify `SOCKET_TLS13_CIPHERSUITES` default is applied via `SSL_CTX_set_ciphersuites()` ✅
  - Applied in `configure_tls13_only()` in SocketTLSContext-core.c
  - Added `SocketTLSContext_set_ciphersuites()` for runtime TLS 1.3 suite configuration
- [x] **Cipher Validation**: Added function to validate cipher string before applying ✅
  - Added `SocketTLSContext_validate_cipher_list()` - validates TLS 1.2 cipher strings
  - Added `SocketTLSContext_validate_ciphersuites()` - validates TLS 1.3 ciphersuite strings
  - Both create temporary SSL_CTX for validation to catch OpenSSL parsing errors
  - Added `fuzz_tls_cipher.c` fuzzer for comprehensive cipher string testing

### 2.10 ALPN Protocol Negotiation — *depends on 2.1, 3.4* ✅ COMPLETE
**Difficulty: 5/9** _(Wire format encoding, callback integration)_

- [x] **SocketTLSContext_set_alpn_protos()**: Verify wire format encoding (length-prefixed) ✅
  - Implemented in `SocketTLSContext-alpn.c` with `build_wire_format()`
  - Wire format: [len1][proto1][len2][proto2]... per RFC 7301
- [x] **SocketTLSContext_set_alpn_protos()**: Test protocol name validation (1-255 bytes, printable ASCII) ✅
  - `validate_alpn_protocol_chars()` checks 0x21-0x7E range per RFC 7301 Section 3.2
  - Length checked via `limits.tls_max_alpn_len` (SOCKET_TLS_MAX_ALPN_LEN = 255)
- [x] **SocketTLSContext_set_alpn_protos()**: Verify `SOCKET_TLS_MAX_ALPN_PROTOCOLS` (16) limit ✅
  - `validate_alpn_count()` checks against runtime security limits
  - Enforced in both parsing and building
- [x] **SocketTLSContext_set_alpn_callback()**: Verify custom selection callback works correctly ✅
  - `alpn_select_cb()` invokes user callback with parsed/validated client protocols
  - Validates returned protocol against client list
- [x] **SocketTLSAlpnCallback**: Test callback return value validation (must match offered protocol) ✅
  - `validate_selected_protocol()` ensures selection:
    - Has valid length (1 to SOCKET_TLS_MAX_ALPN_LEN)
    - Exists in client's offered list
    - Contains only RFC 7301 compliant characters
- [x] **ALPN Temp Buffer**: Verify `tls_cleanup_alpn_temp()` prevents use-after-free in callbacks ✅
  - `tls_get_alpn_ex_idx()` lazily allocates ex_data index
  - Selected protocol copied to malloc'd buffer, stored in SSL ex_data
  - `tls_cleanup_alpn_temp()` frees buffer before SSL_free
  - Enhanced `fuzz_tls_alpn.c` with comprehensive callback and edge case testing

### 2.11 Session Cache Management — *depends on 2.1, 3.4* ✅ COMPLETE
**Difficulty: 5/9** _(Cache mode, size limits, thread-safe stats)_

- [x] **SocketTLSContext_enable_session_cache()**: Verify server/client mode selection ✅
  - Implemented in `SocketTLSContext-session.c`
  - Uses `ctx->is_server ? SSL_SESS_CACHE_SERVER : SSL_SESS_CACHE_CLIENT`
  - Installs `new_session_cb` and `info_callback` for statistics tracking
- [x] **SocketTLSContext_enable_session_cache()**: Test max_sessions and timeout_seconds parameters ✅
  - Validates against `SocketSecurity_get_limits()` for security limits
  - Validates timeout against `SOCKET_TLS_SESSION_MAX_TIMEOUT` (30 days)
  - Uses `SOCKET_TLS_SESSION_TIMEOUT_DEFAULT` (300s) when timeout <= 0
- [x] **SocketTLSContext_set_session_cache_size()**: Verify limit is applied ✅
  - Calls `SSL_CTX_sess_set_cache_size()` with size validation
  - Stores in `ctx->session_cache_size` for tracking
  - Validates against security limits and LONG_MAX
- [x] **SocketTLSContext_get_cache_stats()**: Verify hits/misses/stores counters are accurate ✅
  - Thread-safe via `stats_mutex` protection
  - `cache_hits` incremented in `info_callback` when `SSL_session_reused()` returns true
  - `cache_misses` incremented for non-resumed handshakes
  - `cache_stores` incremented in `new_session_cb` for new sessions
- [x] **Session Cache Thread Safety**: Verify stats_mutex protects counter updates ✅
  - `pthread_mutex_t stats_mutex` in `struct SocketTLSContext_T`
  - All counter reads/writes protected by mutex lock/unlock
- [x] **Session ID Context**: Added `SocketTLSContext_set_session_id_context()` ✅
  - New function for setting `SSL_CTX_set_session_id_context()`
  - Validates context length (1-32 bytes per `SSL_MAX_SID_CTX_LENGTH`)
  - Critical for multi-tenant servers, virtual hosting, and session isolation
  - Full test coverage in `test_tls_phase4.c`
  - Fuzzing coverage in `fuzz_tls_session.c`

### 2.12 Session Tickets — *depends on 2.1, 2.11, 3.5*
**Difficulty: 6/9** _(Key validation, secure storage, rotation)_

- [ ] **SocketTLSContext_enable_session_tickets()**: Verify key length validation (must be 80 bytes)
- [ ] **SocketTLSContext_enable_session_tickets()**: Test ticket encryption/decryption with provided key
- [ ] **Ticket Key Rotation**: Consider adding automatic key rotation support
- [ ] **Ticket Key Secure Storage**: Verify key is securely stored and cleared on context free

### 2.13 Certificate Pinning (SPKI SHA256) — *depends on 2.1, 2.4, 7.\* (crypto utils)* ✅ COMPLETE
**Difficulty: 7/9** _(Security-critical: timing attacks, chain traversal, constant-time compare)_

- [x] **SocketTLSContext_add_pin()**: Verify 32-byte binary hash is correctly stored
  - Implemented in `SocketTLSContext-pinning.c:385-396` with mutex protection
- [x] **SocketTLSContext_add_pin_hex()**: Verify 64-character hex parsing and "sha256//" prefix handling
  - Implemented in `SocketTLSContext-pinning.c:409-429` with parse_hex_hash() helper
- [x] **SocketTLSContext_add_pin_from_cert()**: Verify SPKI extraction and SHA256 hashing
  - Implemented in `SocketTLSContext-pinning.c:442-524` with file validation and symlink protection
- [x] **SocketTLSContext_add_pin_from_x509()**: Verify X509 object handling
  - Implemented in `SocketTLSContext-pinning.c:537-555`
- [x] **SocketTLSContext_clear_pins()**: Verify secure memory clearing before release
  - Implemented in `SocketTLSContext-pinning.c:567-584` using `SocketCrypto_secure_clear()`
- [x] **SocketTLSContext_set_pin_enforcement()**: Verify strict (1) vs warn-only (0) modes
  - Implemented in `SocketTLSContext-pinning.c:596-603`
- [x] **SocketTLSContext_get_pin_enforcement()**: Verify query returns correct mode
  - Implemented in `SocketTLSContext-pinning.c:612-622`
- [x] **SocketTLSContext_get_pin_count()**: Verify accurate count returned
  - Implemented in `SocketTLSContext-pinning.c:631-641`
- [x] **SocketTLSContext_has_pins()**: Verify boolean check works correctly
  - Implemented in `SocketTLSContext-pinning.c:650-660`
- [x] **SocketTLSContext_verify_pin()**: Verify constant-time hash comparison via `SocketCrypto_secure_compare()`
  - Implemented in `SocketTLSContext-pinning.c:673-686` using `tls_pinning_find()`
- [x] **SocketTLSContext_verify_cert_pin()**: Verify SPKI extraction from X509 and comparison
  - Implemented in `SocketTLSContext-pinning.c:698-718`
- [x] **tls_pinning_check_chain()**: Verify chain traversal (leaf first, then intermediates)
  - Implemented in `SocketTLSContext-pinning.c:315-368` with snapshot-based thread safety
- [x] **tls_pinning_find()**: Verify O(n) constant-time scan for timing attack prevention
  - Implemented in `SocketTLSContext-pinning.c:277-296` - scans ALL pins for constant time
- [x] **Pin Limit Enforcement**: Verify `SOCKET_TLS_MAX_PINS` (32) limit is enforced
  - Implemented via `check_pin_limit()` in `SocketTLSContext-pinning.c:101-110`
- [x] **SocketTLS_PinVerifyFailed**: Verify exception is raised on pin mismatch in strict mode
  - Defined in `SocketTLSContext-pinning.c:57-58`, raised via `handle_pin_mismatch()` in verify callback
- [x] **Verification Integration**: Pin checking integrated into TLS handshake
  - Implemented in `SocketTLSContext-verify.c:337-365` via `internal_verify_callback()`
- [x] **Fuzzing Harness**: Complete fuzzer for certificate pinning
  - Implemented in `src/fuzz/fuzz_cert_pinning.c` covering all pin operations

### 2.14 Certificate Transparency (RFC 6962) — *depends on 2.1, 2.3*
**Difficulty: 6/9** _(CT log integration, OpenSSL CT API)_

- [x] **SocketTLSContext_enable_ct()**: Verify CT is enabled via `SSL_CTX_enable_ct()`
  - Implemented in `SocketTLSContext-ct.c:57-75` with strict/permissive mode mapping
- [x] **SocketTLSContext_enable_ct()**: Test strict vs permissive mode behavior
  - Tested in `test_tls_ct.c:40-49` (ct_context_basic_operations)
- [x] **SocketTLSContext_enable_ct()**: Verify server context rejection (CT is client-only)
  - Implemented in `SocketTLSContext-ct.c:63-65`, tested in `test_tls_ct.c:132-196`
- [x] **SocketTLSContext_ct_enabled()**: Verify query returns correct state
  - Implemented in `SocketTLSContext-ct.c:84-89`, tested in `test_tls_ct.c:37,42`
- [x] **SocketTLSContext_get_ct_mode()**: Verify correct mode is returned
  - Implemented in `SocketTLSContext-ct.c:98-103`, tested in `test_tls_ct.c:38,43,49`
- [x] **SocketTLSContext_set_ctlog_list_file()**: Verify custom CT log list loading
  - Implemented in `SocketTLSContext-ct.c:116-137` with path validation
  - Tested in `test_tls_ct.c:52-95` for NULL, empty, and valid paths
- [x] **CT Support Detection**: Verify `SOCKET_HAS_CT_SUPPORT` macro correctly detects OpenSSL 1.1.0+ with CT
  - Defined in `SocketTLSConfig.h:266-270` using `OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(OPENSSL_NO_CT)`
  - Stub implementations provided for unsupported builds in `SocketTLSContext-ct.c:148-199`

---

## 3. TLS Configuration *(No dependencies — pure constants, parallelize freely)*

**File:** `include/tls/SocketTLSConfig.h`

### 3.1 Protocol Version Constants — *COMPLETE*
**Difficulty: 2/9** _(Config verification and documentation)_

- [x] **SOCKET_TLS_MIN_VERSION**: Verified set to `TLS1_3_VERSION` for security (line 313 in SocketTLSConfig.h)
- [x] **SOCKET_TLS_MAX_VERSION**: Verified set to `TLS1_3_VERSION` (strict TLS 1.3-only, line 346)
- [x] **Override Documentation**: Added comprehensive legacy compatibility override documentation with:
  - Security implications table (TLS versions vs vulnerabilities)
  - Compile-time override examples (#define before include)
  - Runtime override examples (SocketTLSConfig_T)
  - Per-context override examples (SocketTLSContext_set_min_protocol)
  - Security recommendations and migration guidance
  - Added #ifndef guards to allow proper compile-time overrides

### 3.2 Cipher Suite Defaults — *NONE*
**Difficulty: 3/9** _(Cipher priority rationale and testing)_

- [ ] **SOCKET_TLS13_CIPHERSUITES**: Verify default includes AES-256-GCM, ChaCha20-Poly1305, AES-128-GCM in that order
- [ ] **Cipher Priority Order**: Document rationale for cipher ordering (AES-256 for max security, ChaCha20 for mobile)
- [ ] **Override Documentation**: Document how to customize ciphers for specific environments

### 3.3 Timeout Configuration — *NONE*
**Difficulty: 2/9** _(Simple constant verification)_

- [ ] **SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS**: Verify 30 seconds default is appropriate
- [ ] **SOCKET_TLS_DEFAULT_SHUTDOWN_TIMEOUT_MS**: Verify 5 seconds default for shutdown
- [ ] **SOCKET_TLS_POLL_INTERVAL_MS**: Verify 100ms polling interval for non-blocking operations

### 3.4 Buffer and Size Limits — *NONE*
**Difficulty: 2/9** _(Limit verification and documentation)_

- [ ] **SOCKET_TLS_BUFFER_SIZE**: Verify 16384 bytes (TLS max record size)
- [ ] **SOCKET_TLS_MAX_CERT_CHAIN_DEPTH**: Verify 10 levels for chain validation
- [ ] **SOCKET_TLS_MAX_ALPN_LEN**: Verify 255 bytes per protocol name
- [ ] **SOCKET_TLS_MAX_ALPN_TOTAL_BYTES**: Verify 1024 bytes total for ALPN list
- [ ] **SOCKET_TLS_MAX_SNI_LEN**: Verify 255 bytes for SNI hostname
- [ ] **SOCKET_TLS_SESSION_CACHE_SIZE**: Verify 1000 sessions default
- [ ] **SOCKET_TLS_ERROR_BUFSIZE**: Verify 512 bytes for error messages
- [ ] **SOCKET_TLS_OPENSSL_ERRSTR_BUFSIZE**: Verify 256 bytes for OpenSSL error strings

### 3.5 Security Limits — *NONE*
**Difficulty: 2/9** _(Limit verification and enforcement testing)_

- [ ] **SOCKET_TLS_MAX_SNI_CERTS**: Verify 100 certificate limit for SNI
- [ ] **SOCKET_TLS_MAX_PINS**: Verify 32 pin limit for certificate pinning
- [ ] **SOCKET_TLS_TICKET_KEY_LEN**: Verify 80 bytes for session ticket keys
- [ ] **SOCKET_TLS_MAX_OCSP_RESPONSE_LEN**: Verify 64KB for OCSP responses
- [ ] **SOCKET_TLS_MAX_PATH_LEN**: Verify 4096 bytes for file paths
- [ ] **SOCKET_TLS_MAX_CRL_SIZE**: Verify 10MB for CRL files
- [ ] **SOCKET_TLS_CRL_MIN_REFRESH_INTERVAL**: Verify 60 seconds minimum
- [ ] **SOCKET_TLS_CRL_MAX_REFRESH_INTERVAL**: Verify 1 year maximum

---

## 4. Core DTLS Implementation

**Files:** `include/tls/SocketDTLS.h`, `src/tls/SocketDTLS.c`

### 4.1 DTLS Enable and Configuration — *depends on 5.1, 6.\*, 7.\**
**Difficulty: 5/9** _(DTLS-specific setup, peer management)_

- [ ] **SocketDTLS_enable()**: Verify DTLS is enabled on datagram sockets correctly
- [ ] **SocketDTLS_enable()**: Test that context ownership is transferred to socket
- [ ] **SocketDTLS_set_peer()**: Verify peer address resolution (sync, may block on DNS)
- [ ] **SocketDTLS_set_hostname()**: Verify SNI extension and hostname verification setup
- [ ] **SocketDTLS_set_mtu()**: Verify MTU range validation (576-9000 bytes)
- [ ] **SocketDTLS_get_mtu()**: Verify current effective MTU is returned

### 4.2 DTLS Handshake — *depends on 4.1, 5.3, 6.4, 6.5*
**Difficulty: 6/9** _(Cookie exchange, retransmission, state machine)_

- [ ] **SocketDTLS_handshake()**: Verify all `DTLSHandshakeState` transitions including `DTLS_HANDSHAKE_COOKIE_EXCHANGE`
- [ ] **SocketDTLS_handshake()**: Test non-blocking behavior with WANT_READ/WANT_WRITE
- [ ] **SocketDTLS_handshake_loop()**: Verify timeout handling (0=single step, -1=infinite)
- [ ] **SocketDTLS_listen()**: Verify server-side ClientHello reception and cookie handling
- [ ] **Cookie Exchange Integration**: Verify cookie exchange triggers `DTLS_HANDSHAKE_COOKIE_EXCHANGE` state
- [ ] **Handshake Retransmission**: Verify OpenSSL handles DTLS retransmission internally

### 4.3 DTLS I/O Operations — *depends on 4.2*
**Difficulty: 5/9** _(Message-oriented semantics, fragmentation)_

- [ ] **SocketDTLS_send()**: Verify message-oriented semantics (one send = one datagram)
- [ ] **SocketDTLS_send()**: Test large payload fragmentation by DTLS layer
- [ ] **SocketDTLS_recv()**: Verify complete message delivery (reassembly if fragmented)
- [ ] **SocketDTLS_recv()**: Test handling of out-of-order packets
- [ ] **SocketDTLS_sendto()**: Verify unconnected multi-peer sends work correctly
- [ ] **SocketDTLS_recvfrom()**: Verify sender address is correctly populated

### 4.4 DTLS Connection Information — *depends on 4.2*
**Difficulty: 3/9** _(Simple accessor functions)_

- [ ] **SocketDTLS_get_cipher()**: Verify cipher name returned for DTLS connections
- [ ] **SocketDTLS_get_version()**: Verify "DTLSv1.2" or "DTLSv1.3" string returned
- [ ] **SocketDTLS_get_verify_result()**: Verify X509 verification result code
- [ ] **SocketDTLS_is_session_reused()**: Verify session resumption detection
- [ ] **SocketDTLS_get_alpn_selected()**: Verify ALPN negotiation result

### 4.5 DTLS Shutdown — *depends on 4.2*
**Difficulty: 4/9** _(Best-effort over UDP)_

- [ ] **SocketDTLS_shutdown()**: Verify close_notify alert sending
- [ ] **SocketDTLS_shutdown()**: Note that DTLS shutdown is best-effort (UDP unreliable)
- [ ] **SocketDTLS_is_shutdown()**: Verify shutdown state query
- [ ] **Graceful Shutdown Loop**: Test non-blocking shutdown completion pattern

### 4.6 DTLS State Queries — *depends on 4.1*
**Difficulty: 2/9** _(Simple boolean queries)_

- [ ] **SocketDTLS_is_enabled()**: Verify DTLS enable state query
- [ ] **SocketDTLS_is_handshake_done()**: Verify handshake completion query
- [ ] **SocketDTLS_get_last_state()**: Verify last handshake state is returned

---

## 5. DTLS Context Management

**Files:** `include/tls/SocketDTLSContext.h`, `src/tls/SocketDTLSContext.c`

### 5.1 Context Creation and Destruction — *depends on 6.\*, 7.\**
**Difficulty: 4/9** _(DTLS context with DTLS 1.2 enforcement)_

- [ ] **SocketDTLSContext_new_server()**: Verify DTLS 1.2 minimum enforcement
- [ ] **SocketDTLSContext_new_server()**: Test certificate and key loading
- [ ] **SocketDTLSContext_new_client()**: Test with and without CA file
- [ ] **SocketDTLSContext_free()**: Verify all resources freed including cookie secrets

### 5.2 Certificate Management — *depends on 5.1, 7.1 (reuses 2.2 patterns)*
**Difficulty: 4/9** _(Reuses TLS patterns)_

- [ ] **SocketDTLSContext_load_certificate()**: Verify cert/key loading and validation
- [ ] **SocketDTLSContext_load_ca()**: Verify CA loading (file and directory modes)
- [ ] **SocketDTLSContext_set_verify_mode()**: Verify correct mapping to SSL_VERIFY_* flags

### 5.3 Cookie Exchange (DoS Protection) — *depends on 5.1, 6.4*
**Difficulty: 7/9** _(Security-critical: HMAC, timestamps, secret rotation)_

- [ ] **SocketDTLSContext_enable_cookie_exchange()**: Verify cookie callbacks are installed
- [ ] **SocketDTLSContext_enable_cookie_exchange()**: Verify automatic secret key generation
- [ ] **SocketDTLSContext_set_cookie_secret()**: Verify secret length validation (32 bytes)
- [ ] **SocketDTLSContext_set_cookie_secret()**: Verify secret is securely stored
- [ ] **SocketDTLSContext_rotate_cookie_secret()**: Verify new random secret generation
- [ ] **SocketDTLSContext_has_cookie_exchange()**: Verify query function
- [ ] **Cookie HMAC-SHA256**: Verify cookie = HMAC(secret, client_addr || client_port || timestamp)
- [ ] **Cookie Timestamp Buckets**: Verify time-based cookie validation with window tolerance
- [ ] **Cookie Secret Rotation**: Verify old cookies are invalid after rotation

### 5.4 MTU Configuration — *depends on 5.1, 6.3*
**Difficulty: 3/9** _(Range validation)_

- [ ] **SocketDTLSContext_set_mtu()**: Verify MTU range validation (576-9000)
- [ ] **SocketDTLSContext_set_mtu()**: Verify default MTU (1400 bytes) is appropriate
- [ ] **SocketDTLSContext_get_mtu()**: Verify current MTU is returned

### 5.5 Protocol Configuration — *depends on 5.1, 6.1, 6.2*
**Difficulty: 3/9** _(Similar to TLS config)_

- [ ] **SocketDTLSContext_set_min_protocol()**: Verify DTLS 1.2 minimum enforcement
- [ ] **SocketDTLSContext_set_max_protocol()**: Verify max version setting (DTLS 1.3 if available)
- [ ] **SocketDTLSContext_set_cipher_list()**: Verify cipher string parsing

### 5.6 ALPN Support — *depends on 5.1 (reuses 2.10 patterns)*
**Difficulty: 3/9** _(Reuses TLS ALPN logic)_

- [ ] **SocketDTLSContext_set_alpn_protos()**: Verify protocol list encoding and validation
- [ ] **ALPN Selection Callback**: Verify server-side ALPN selection works

### 5.7 Session Management — *depends on 5.1 (reuses 2.11 patterns)*
**Difficulty: 4/9** _(Reuses TLS session patterns)_

- [ ] **SocketDTLSContext_enable_session_cache()**: Verify cache enabling for server/client
- [ ] **SocketDTLSContext_get_cache_stats()**: Verify hits/misses/stores counters

### 5.8 Timeout Configuration — *depends on 5.1, 6.5*
**Difficulty: 3/9** _(Retransmission timer config)_

- [ ] **SocketDTLSContext_set_timeout()**: Verify initial and max retransmission timeout settings

### 5.9 Internal Functions — *depends on 5.1*
**Difficulty: 2/9** _(Simple internal accessors)_

- [ ] **SocketDTLSContext_get_ssl_ctx()**: Verify internal accessor returns correct SSL_CTX*
- [ ] **SocketDTLSContext_is_server()**: Verify server mode detection

---

## 6. DTLS Configuration *(No dependencies — pure constants, parallelize freely)*

**File:** `include/tls/SocketDTLSConfig.h`

### 6.1 Protocol Version Constants — *NONE*
**Difficulty: 2/9** _(Config verification)_

- [ ] **SOCKET_DTLS_MIN_VERSION**: Verify set to `DTLS1_2_VERSION`
- [ ] **SOCKET_DTLS_MAX_VERSION**: Verify set to `DTLS1_3_VERSION` if available, else `DTLS1_2_VERSION`

### 6.2 Cipher Suites — *NONE*
**Difficulty: 2/9** _(Config verification)_

- [ ] **SOCKET_DTLS_CIPHERSUITES**: Verify modern ECDHE + AEAD suites are default

### 6.3 MTU Settings — *NONE*
**Difficulty: 2/9** _(Constant verification and documentation)_

- [ ] **SOCKET_DTLS_DEFAULT_MTU**: Verify 1400 bytes default (conservative for tunnels)
- [ ] **SOCKET_DTLS_MIN_MTU**: Verify 576 bytes minimum (IPv4 minimum reassembly)
- [ ] **SOCKET_DTLS_MAX_MTU**: Verify 9000 bytes maximum (jumbo frames)
- [ ] **SOCKET_DTLS_MAX_RECORD_SIZE**: Verify 16384 bytes (TLS record max)
- [ ] **SOCKET_DTLS_RECORD_OVERHEAD**: Verify 64 bytes conservative estimate
- [ ] **SOCKET_DTLS_MAX_PAYLOAD**: Verify calculation (MTU - overhead - headers)

### 6.4 Cookie Protection Parameters — *NONE*
**Difficulty: 2/9** _(Security constant verification)_

- [ ] **SOCKET_DTLS_COOKIE_LEN**: Verify 32 bytes (HMAC-SHA256 truncated)
- [ ] **SOCKET_DTLS_COOKIE_SECRET_LEN**: Verify 32 bytes for HMAC key
- [ ] **SOCKET_DTLS_COOKIE_LIFETIME_SEC**: Verify 60 seconds validity
- [ ] **SOCKET_DTLS_MAX_PENDING_COOKIES**: Verify 1000 concurrent exchanges limit

### 6.5 Timeout Configuration — *NONE*
**Difficulty: 2/9** _(DTLS timing constants)_

- [ ] **SOCKET_DTLS_INITIAL_TIMEOUT_MS**: Verify 1000ms initial retransmission timeout
- [ ] **SOCKET_DTLS_MAX_TIMEOUT_MS**: Verify 60000ms maximum timeout
- [ ] **SOCKET_DTLS_DEFAULT_HANDSHAKE_TIMEOUT_MS**: Verify 30000ms total handshake timeout
- [ ] **SOCKET_DTLS_MAX_RETRANSMITS**: Verify 12 retransmissions maximum

### 6.6 Session and Limits — *NONE*
**Difficulty: 2/9** _(Limit constant verification)_

- [ ] **SOCKET_DTLS_SESSION_CACHE_SIZE**: Verify 1000 sessions default
- [ ] **SOCKET_DTLS_SESSION_TIMEOUT_DEFAULT**: Verify 300 seconds (5 minutes)
- [ ] **SOCKET_DTLS_ERROR_BUFSIZE**: Verify 512 bytes for error messages
- [ ] **SOCKET_DTLS_MAX_CERT_CHAIN_DEPTH**: Verify 10 levels
- [ ] **SOCKET_DTLS_MAX_SNI_LEN**: Verify 255 bytes
- [ ] **SOCKET_DTLS_MAX_ALPN_LEN**: Verify 255 bytes
- [ ] **SOCKET_DTLS_MAX_PATH_LEN**: Verify 4096 bytes
- [ ] **SOCKET_DTLS_MAX_FILE_SIZE**: Verify 1MB limit for cert/key files

### 6.7 Validation Macros — *NONE*
**Difficulty: 2/9** _(Simple macro verification)_

- [ ] **SOCKET_DTLS_VALID_MTU()**: Verify range check macro works correctly
- [ ] **SOCKET_DTLS_VALID_TIMEOUT()**: Verify timeout validation macro

---

## 7. Shared Internal Utilities *(Foundation — no dependencies, start first)*

**File:** `include/tls/SocketSSL-internal.h`

### 7.1 File Path Validation — *NONE*
**Difficulty: 5/9** _(Security-critical: path traversal, symlink attacks)_

- [ ] **ssl_validate_file_path()**: Verify path traversal detection (/../, \..\ patterns)
- [ ] **ssl_validate_file_path()**: Verify symlink rejection via lstat()
- [ ] **ssl_validate_file_path()**: Verify control character rejection (0x00-0x1F, 0x7F)
- [ ] **ssl_validate_file_path()**: Verify length limit enforcement
- [ ] **Path Security**: Test with various attack patterns (encoded traversal, null bytes)

### 7.2 OpenSSL Error Formatting — *NONE*
**Difficulty: 3/9** _(ERR_get_error handling)_

- [ ] **ssl_format_openssl_error_to_buf()**: Verify ERR_get_error() and ERR_error_string_n() usage
- [ ] **ssl_format_openssl_error_to_buf()**: Verify ERR_clear_error() is called after formatting
- [ ] **Error Buffer Sizes**: Verify `SOCKET_SSL_OPENSSL_ERRSTR_BUFSIZE` (256) is sufficient

### 7.3 Utility Macros — *NONE*
**Difficulty: 1/9** _(Simple macro)_

- [ ] **SOCKET_SSL_UNUSED()**: Verify unused parameter suppression macro

---

## 8. Testing Requirements

### 8.1 Unit Tests — *depends on all of 1.\*, 2.\*, 4.\*, 5.\**
**Difficulty: 5/9** _(Comprehensive test coverage)_

- [ ] **test_tls_enable_disable.c**: Test TLS enable/disable lifecycle
- [ ] **test_tls_handshake.c**: Test all handshake states and transitions
- [ ] **test_tls_io.c**: Test send/recv operations including edge cases
- [ ] **test_tls_session.c**: Test session save/restore and resumption
- [ ] **test_tls_context.c**: Test context creation, configuration, and destruction
- [ ] **test_tls_pinning.c**: Test certificate pinning with various hash formats
- [ ] **test_tls_crl.c**: Test CRL loading and auto-refresh
- [ ] **test_tls_ocsp.c**: Test OCSP stapling (server and client)
- [ ] **test_tls_ct.c**: Test Certificate Transparency verification
- [ ] **test_dtls_basic.c**: Test DTLS enable, handshake, I/O
- [ ] **test_dtls_cookie.c**: Test DTLS cookie exchange and DoS protection
- [ ] **test_dtls_mtu.c**: Test MTU configuration and fragmentation

### 8.2 Integration Tests — *depends on 8.1, all of 1.\*, 2.\*, 4.\*, 5.\**
**Difficulty: 6/9** _(End-to-end client-server testing)_

- [ ] **test_tls_integration.c**: End-to-end TLS client-server communication
- [ ] **test_dtls_integration.c**: End-to-end DTLS client-server communication
- [ ] **test_tls_http2.c**: TLS with HTTP/2 ALPN negotiation
- [ ] **test_mtls.c**: Mutual TLS authentication (client and server certs)
- [ ] **test_tls_reconnect.c**: TLS with automatic reconnection
- [ ] **test_tls_pool.c**: TLS with connection pooling

### 8.3 Fuzzing Harnesses — *depends on 1.2, 1.3, 2.2, 2.10, 4.2, 5.3*
**Difficulty: 7/9** _(Fuzzer setup, corpus generation, crash triage)_

- [ ] **fuzz_tls_handshake.c**: Fuzz TLS handshake message parsing
- [ ] **fuzz_tls_records.c**: Fuzz TLS record layer processing
- [ ] **fuzz_certificate_parsing.c**: Fuzz X509 certificate parsing
- [ ] **fuzz_alpn_parsing.c**: Fuzz ALPN protocol list parsing
- [ ] **fuzz_sni_parsing.c**: Fuzz SNI hostname parsing
- [ ] **fuzz_dtls_cookie.c**: Fuzz DTLS cookie generation/verification
- [ ] **fuzz_pin_hex_parsing.c**: Fuzz hex-encoded pin parsing

### 8.4 Edge Cases and Error Paths — *depends on 8.1, 8.2*
**Difficulty: 6/9** _(Tricky failure scenarios, packet simulation)_

- [ ] Test TLS on already-closed socket
- [ ] Test TLS handshake timeout handling
- [ ] Test TLS with peer abrupt disconnect during handshake
- [ ] Test TLS with certificate expired during connection
- [ ] Test TLS with CRL updated during connection
- [ ] Test DTLS with packet loss simulation
- [ ] Test DTLS with packet reordering simulation
- [ ] Test DTLS cookie with IP address change (should fail)

### 8.5 Security Tests — *depends on 8.1, 8.2, 10.\**
**Difficulty: 7/9** _(Attack simulation, bypass detection)_

- [ ] Test rejection of TLS 1.2 and earlier (downgrade attack prevention)
- [ ] Test rejection of weak cipher suites
- [ ] Test certificate pinning bypass attempts
- [ ] Test path traversal in certificate file paths
- [ ] Test null byte injection in hostnames
- [ ] Test timing attack resistance in pin verification

---

## 9. Documentation *(Can parallel implementation)*

### 9.1 API Documentation — *depends on corresponding 1.\*, 2.\*, 4.\*, 5.\* being implemented*
**Difficulty: 3/9** _(Doxygen completeness audit)_

- [ ] Verify all public functions have Doxygen comments with @brief, @param, @return, @throws
- [ ] Verify all public types have Doxygen documentation
- [ ] Verify all public constants have documentation explaining purpose and usage
- [ ] Add @ingroup tags for proper module grouping

### 9.2 Usage Examples — *depends on 9.1, working implementation*
**Difficulty: 4/9** _(Working code examples with error handling)_

- [ ] Add complete TLS client example in header documentation
- [ ] Add complete TLS server example in header documentation
- [ ] Add mTLS (mutual TLS) example
- [ ] Add certificate pinning example with pin generation instructions
- [ ] Add CRL auto-refresh integration example
- [ ] Add DTLS client example
- [ ] Add DTLS server with cookie protection example

### 9.3 Security Guides — *depends on 10.\*, 1.\*, 2.\**
**Difficulty: 4/9** _(Security best practices documentation)_

- [ ] Document TLS 1.3-only enforcement rationale
- [ ] Document cipher suite selection rationale
- [ ] Document certificate pinning best practices (pin backup keys)
- [ ] Document CRL refresh interval recommendations
- [ ] Document OCSP stapling configuration for production
- [ ] Document CT validation requirements for public CAs
- [ ] Create docs/TLS-CONFIG.md with detailed TLS configuration guide
- [ ] Create docs/DTLS-CONFIG.md with DTLS-specific configuration guide

---

## 10. Security Hardening *(Review phase — after implementation)*

### 10.1 Key Material Handling — *depends on 1.\*, 2.\*, 5.\**
**Difficulty: 6/9** _(Security-critical: secure clearing, mlock consideration)_

- [ ] Verify all private key memory is zeroed via `OPENSSL_cleanse()` or `SocketCrypto_secure_clear()`
- [ ] Verify session ticket keys are securely cleared on context destruction
- [ ] Verify cookie secrets are securely cleared on context destruction
- [ ] Verify TLS read/write buffers are securely cleared (may contain decrypted data)
- [ ] Verify SNI hostname is cleared (may be sensitive connection info)
- [ ] Consider using `mlock()` for highly sensitive key material to prevent swapping

### 10.2 Thread-Local Error Handling — *depends on all of 1.\*, 2.\*, 4.\*, 5.\*, 7.\**
**Difficulty: 4/9** _(Audit thread-local patterns)_

- [ ] Verify all modules use `SOCKET_DECLARE_MODULE_EXCEPTION()` for thread-local exceptions
- [ ] Verify error buffers are not shared across threads
- [ ] Verify OpenSSL error queue is cleared after each operation

### 10.3 Input Validation — *depends on 2.2, 2.5, 2.10, 7.1*
**Difficulty: 5/9** _(Comprehensive validation audit)_

- [ ] Verify all file paths are validated via `ssl_validate_file_path()`
- [ ] Verify all hostnames are validated via `tls_validate_hostname()`
- [ ] Verify all ALPN protocol names are validated (printable ASCII, length limits)
- [ ] Verify all certificate/key files are size-limited to prevent DoS
- [ ] Verify all CRL files are size-limited

### 10.4 Timing Attack Prevention — *depends on 2.13, 5.3*
**Difficulty: 7/9** _(Subtle: constant-time ops, early exit analysis)_

- [ ] Verify certificate pin comparison uses `SocketCrypto_secure_compare()` (constant-time)
- [ ] Verify HMAC comparison in cookie verification is constant-time
- [ ] Consider timing-safe early exit patterns in verification callbacks

### 10.5 Memory Safety — *depends on all of 1.\*, 2.\*, 4.\*, 5.\**
**Difficulty: 5/9** _(Sanitizer validation, leak detection)_

- [ ] Verify all Arena allocations are checked for NULL
- [ ] Verify all OpenSSL object creations are checked for NULL
- [ ] Verify proper cleanup in error paths (no resource leaks)
- [ ] Run with AddressSanitizer to detect memory errors
- [ ] Run with MemorySanitizer to detect uninitialized reads

### 10.6 Threat Model Coverage — *depends on 10.1–10.5*
**Difficulty: 4/9** _(Documentation of security guarantees)_

- [ ] Document protection against MITM attacks (certificate verification, pinning)
- [ ] Document protection against downgrade attacks (TLS 1.3-only, no renegotiation)
- [ ] Document protection against DoS attacks (cookie exchange, rate limiting)
- [ ] Document protection against timing attacks (constant-time operations)
- [ ] Document protection against memory disclosure (secure clearing)

---

## 11. Performance Optimizations *(Enhancement phase — after stability)*

### 11.1 kTLS (Kernel TLS) Offload — *depends on all of 1.\* complete*
**Difficulty: 9/9** _(Kernel integration, cipher key extraction, fallback handling)_

- [ ] **Priority: HIGH** - Implement kTLS support for massive performance improvement
- [ ] Add `SocketTLS_enable_ktls()` function to enable kernel TLS offload
- [ ] Extract cipher keys from OpenSSL after handshake for kernel crypto_info
- [ ] Implement `setsockopt(SOL_TCP, TCP_ULP, "tls")` for kernel TLS setup
- [ ] Implement `setsockopt(SOL_TLS, TLS_TX/TLS_RX, &crypto_info)` for key installation
- [ ] Support AES-GCM-128, AES-GCM-256, and ChaCha20-Poly1305 for kTLS
- [ ] Modify I/O path to use kernel send/recv when kTLS enabled
- [ ] Add fallback to userspace TLS when kTLS not available
- [ ] Document kernel version requirements (Linux 4.13+ for TLS_TX, 4.17+ for TLS_RX)

### 11.2 Session Resumption Optimization — *depends on 1.5, 2.11, 2.12*
**Difficulty: 6/9** _(0-RTT, ticket rotation, cache sharding)_

- [ ] Verify TLS 1.3 0-RTT support (early data) is properly configured
- [ ] Add session ticket rotation support for server scalability
- [ ] Implement session cache sharding for multi-threaded servers
- [ ] Consider external session cache (Redis, memcached) for distributed systems

### 11.3 Connection Optimization — *depends on all of 1.\* complete*
**Difficulty: 5/9** _(TCP tuning, profiling)_

- [ ] Verify TCP_NODELAY is set for TLS handshake responsiveness
- [ ] Consider TCP_QUICKACK during handshake for reduced latency
- [ ] Verify non-blocking handshake doesn't spin-wait (uses poll correctly)
- [ ] Profile and optimize hot paths in TLS I/O

### 11.4 Memory Optimization — *depends on all of 1.\*, 2.\* complete*
**Difficulty: 5/9** _(Profiling, buffer pooling)_

- [ ] Verify Arena-based allocation reduces malloc overhead
- [ ] Consider buffer pooling for high-connection-count servers
- [ ] Profile memory usage per TLS connection
- [ ] Optimize certificate chain storage in SNI maps

### 11.5 Zero-Copy Optimization — *depends on 11.1, 1.3*
**Difficulty: 7/9** _(SSL_sendfile, MSG_ZEROCOPY, kernel integration)_

- [ ] Investigate `SSL_sendfile()` for kernel sendfile with TLS (OpenSSL 3.0+)
- [ ] Consider MSG_ZEROCOPY integration with kTLS
- [ ] Evaluate `SSL_read_ex()` / `SSL_write_ex()` for reduced copying

---

## 12. Future Enhancements *(Long-term — after full implementation)*

### 12.1 DTLS 1.3 Support — *depends on all of 4.\*, 5.\*, 6.\* complete*
**Difficulty: 7/9** _(Depends on OpenSSL, new protocol features)_

- [ ] Monitor OpenSSL 3.2+ for DTLS 1.3 support
- [ ] Update `SOCKET_DTLS_MAX_VERSION` when DTLS 1.3 is available
- [ ] Test DTLS 1.3 handshake and I/O when supported
- [ ] Document DTLS 1.3 benefits (improved security, reduced handshake RTT)

### 12.2 Post-Quantum Cryptography Readiness — *depends on all sections complete*
**Difficulty: 8/9** _(Research-level, evolving standards)_

- [ ] Monitor OpenSSL for post-quantum key exchange support (e.g., Kyber, Dilithium)
- [ ] Plan API for hybrid key exchange configuration
- [ ] Consider cipher suite updates for PQ algorithms
- [ ] Document migration path for PQ readiness

### 12.3 Additional Protocol Features — *depends on 1.\*, 2.\* complete*
**Difficulty: 7/9** _(0-RTT, ECH, QUIC integration)_

- [ ] Consider adding TLS 1.3 KeyUpdate support for long-lived connections
- [ ] Consider adding TLS 1.3 early data (0-RTT) API
- [ ] Consider adding encrypted client hello (ECH) support when standardized
- [ ] Consider adding QUIC integration (shared TLS 1.3 handshake)

### 12.4 Enhanced Observability — *depends on all of 1.\*, 4.\* complete*
**Difficulty: 5/9** _(Metrics, tracing hooks)_

- [ ] Add TLS-specific metrics (handshake latency, session reuse rate)
- [ ] Add DTLS-specific metrics (retransmission count, cookie failures)
- [ ] Add distributed tracing hooks for TLS handshake phases
- [ ] Consider integration with OpenTelemetry for TLS spans

### 12.5 Additional Security Features — *depends on 2.5, 2.6, 2.14 complete*
**Difficulty: 7/9** _(DANE, CAA, CT log submission)_

- [ ] Consider adding certificate revocation via OCSP Must-Staple
- [ ] Consider adding CAA (Certificate Authority Authorization) checking
- [ ] Consider adding DANE (DNS-Based Authentication) support
- [ ] Consider adding CT log submission for server-issued certificates

---

## Parallelization Summary

This section summarizes dependencies to help coordinate multiple agents working in parallel.

### Execution Waves

| Wave | Sections | Reason |
|------|----------|--------|
| **1 (Start first)** | **3.\***, **6.\***, **7.\*** | Pure config/utils, foundation for everything — no dependencies |
| **2 (Foundation)** | **2.1**, **5.1** | Context creation, unlocks all context features |
| **3 (Context features)** | **2.2–2.14**, **5.2–5.9** | Can parallelize within each group after wave 2 |
| **4 (Core I/O)** | **1.1–1.9**, **4.1–4.6** | Depends on contexts being ready from wave 2–3 |
| **5 (Validation)** | **8.\***, **10.\*** | Testing + security hardening after implementation |
| **6 (Polish)** | **9.\***, **11.\*** | Docs + performance after stability |
| **7 (Future)** | **12.\*** | Post-release roadmap |

### Dependency Legend

- `X.*` — All subsections of section X (e.g., `3.*` = 3.1, 3.2, 3.3, 3.4, 3.5)
- `NONE` — No dependencies, can start immediately
- Sections with multiple dependencies must wait for ALL listed sections

### Independent Work Streams

**Stream A (TLS):** 3.* → 7.* → 2.1 → 2.2–2.14 → 1.1–1.9  
**Stream B (DTLS):** 6.* → 7.* → 5.1 → 5.2–5.9 → 4.1–4.6  
**Stream C (Testing):** Waits for A+B, then 8.* → 10.*  
**Stream D (Docs):** Can parallel A+B for 9.1, then 9.2–9.3 after testing  
**Stream E (Perf):** After A complete, then 11.*  

---

## Reference: OpenSSL API Usage Summary

### SSL_CTX Functions Used

| Function | Purpose | File |
|----------|---------|------|
| `SSL_CTX_new()` | Create SSL context | SocketTLSContext-core.c |
| `SSL_CTX_free()` | Free SSL context | SocketTLSContext-core.c |
| `SSL_CTX_set_min_proto_version()` | Set TLS 1.3 minimum | SocketTLSContext-core.c |
| `SSL_CTX_set_max_proto_version()` | Set TLS 1.3 maximum | SocketTLSContext-core.c |
| `SSL_CTX_set_ciphersuites()` | Set TLS 1.3 ciphers | SocketTLSContext-core.c |
| `SSL_CTX_set_cipher_list()` | Set TLS 1.2 ciphers | SocketTLSContext-verify.c |
| `SSL_CTX_set_options()` | Set context options | SocketTLSContext-core.c |
| `SSL_CTX_set_verify()` | Set verification mode | SocketTLSContext-verify.c |
| `SSL_CTX_use_certificate_file()` | Load certificate | SocketTLSContext-certs.c |
| `SSL_CTX_use_PrivateKey_file()` | Load private key | SocketTLSContext-certs.c |
| `SSL_CTX_check_private_key()` | Validate key match | SocketTLSContext-certs.c |
| `SSL_CTX_load_verify_locations()` | Load CA certs | SocketTLSContext-certs.c |
| `SSL_CTX_set_session_cache_mode()` | Enable session cache | SocketTLSContext-session.c |
| `SSL_CTX_set_alpn_protos()` | Set ALPN protocols | SocketTLSContext-alpn.c |
| `SSL_CTX_set_tlsext_servername_callback()` | Set SNI callback | SocketTLSContext-certs.c |
| `SSL_CTX_set_tlsext_status_cb()` | Set OCSP callback | SocketTLSContext-verify.c |
| `SSL_CTX_enable_ct()` | Enable CT | SocketTLSContext-ct.c |
| `SSL_CTX_set_cookie_generate_cb()` | DTLS cookie gen | SocketDTLSContext.c |
| `SSL_CTX_set_cookie_verify_cb()` | DTLS cookie verify | SocketDTLSContext.c |

### SSL Functions Used

| Function | Purpose | File |
|----------|---------|------|
| `SSL_new()` | Create SSL connection | SocketTLS.c |
| `SSL_free()` | Free SSL connection | SocketTLS.c |
| `SSL_set_fd()` | Associate with socket | SocketTLS.c |
| `SSL_set_connect_state()` | Set client mode | SocketTLS.c |
| `SSL_set_accept_state()` | Set server mode | SocketTLS.c |
| `SSL_set_mode()` | Set SSL modes | SocketTLS.c |
| `SSL_do_handshake()` | Perform handshake | SocketTLS.c |
| `SSL_get_error()` | Get error code | SocketTLS.c |
| `SSL_read()` | Receive data | SocketTLS.c |
| `SSL_write()` | Send data | SocketTLS.c |
| `SSL_shutdown()` | Graceful shutdown | SocketTLS.c |
| `SSL_set_verify()` | Set per-connection verify | SocketTLS.c |
| `SSL_set_tlsext_host_name()` | Set SNI hostname | SocketTLS.c |

---

*Last updated: December 2025*
*Maintainer: tetsuo-socket development team*
