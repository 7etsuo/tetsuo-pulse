# Socket Library Feature Roadmap

Enterprise-grade implementation roadmap for HTTP/1.1, HTTP/2, WebSocket, and Proxy support.
Full RFC compliance with security hardening throughout.

---

## Phase Completion Summary

- [x] **Phase 1**: Cryptographic Utilities ✅
- [x] **Phase 2**: UTF-8 Validation ✅
- [x] **Phase 3**: HTTP Core (RFC 9110) ✅
- [x] **Phase 4**: HTTP/1.1 Message Syntax (RFC 9112) ✅
- [x] **Phase 5**: HPACK Header Compression (RFC 7541) ✅
- [x] **Phase 6**: HTTP/2 Protocol (RFC 9113) ✅
- [ ] **Phase 7**: HTTP Client and Server APIs
- [ ] **Phase 8**: Proxy Support
- [ ] **Phase 9**: WebSocket Protocol (RFC 6455)
- [ ] **Phase 10**: Security Hardening
- [ ] **Phase 11**: Testing Infrastructure
- [ ] **Phase 12**: Documentation and Examples

---

## RFC Reference Index

| RFC | Title | Phase | Status |
|-----|-------|-------|--------|
| RFC 9110 | HTTP Semantics | 3 | Planned |
| RFC 9111 | HTTP Caching | 3 | Headers Only |
| RFC 9112 | HTTP/1.1 Message Syntax | 4 | Planned |
| RFC 9113 | HTTP/2 | 6 | Completed |
| RFC 7541 | HPACK Header Compression | 5 | Completed |
| RFC 6455 | WebSocket Protocol | 9 | Planned |
| RFC 7692 | WebSocket Compression | 9 | Planned |
| RFC 6265 | HTTP Cookies | 7 | Planned |
| RFC 3986 | URI Syntax | 3 | Planned |
| RFC 7617 | HTTP Basic Auth | 7 | Planned |
| RFC 7616 | HTTP Digest Auth | 7 | Planned |
| RFC 6750 | Bearer Token Auth | 7 | Planned |
| RFC 1928 | SOCKS5 Protocol | 8 | Planned |
| RFC 1929 | SOCKS5 Auth | 8 | Planned |
| RFC 7231 | HTTP CONNECT | 8 | Planned |
| RFC 5322 | Date/Time Format | 3 | Planned |
| RFC 7932 | Brotli Compression | 4 | Planned |
| RFC 1951 | DEFLATE | 4 | Planned |
| RFC 1952 | GZIP | 4 | Planned |

---

## - [x] Phase 1: Cryptographic Utilities ✅ COMPLETED

Cryptographic primitives required for HTTP/2, WebSocket, and security features.
Thin wrappers around OpenSSL with fallbacks when TLS disabled.

**Status**: Completed (December 2025)

### - [x] Files Created ✅

- [x] `include/core/SocketCrypto.h` - Public API header
- [x] `src/core/SocketCrypto.c` - Implementation with OpenSSL wrappers

### Internal Code Refactored

The following files were refactored to use SocketCrypto instead of direct OpenSSL calls,
eliminating code duplication:

- `src/tls/SocketTLSContext-pinning.c` - Now uses `SocketCrypto_sha256()`, `SocketCrypto_hex_decode()`, `SocketCrypto_secure_clear()`
- `src/tls/SocketDTLS-cookie.c` - Now uses `SocketCrypto_hmac_sha256()`, `SocketCrypto_secure_compare()`, `SocketCrypto_secure_clear()`
- `src/tls/SocketDTLSContext.c` - Now uses `SocketCrypto_random_bytes()`, `SocketCrypto_secure_clear()`

### TLS-Disabled Behavior

When `SOCKET_HAS_TLS` is not defined:
- Hash functions (SHA-1, SHA-256, MD5) raise `SocketCrypto_Failed` exception
- HMAC-SHA256 raises `SocketCrypto_Failed` exception
- Random bytes fall back to `/dev/urandom`
- WebSocket helpers return -1 (require TLS for SHA-1)
- Base64/Hex encoding work without TLS (pure C implementation)
- `SocketCrypto_secure_compare()` and `SocketCrypto_secure_clear()` work without TLS

### Dependencies

- OpenSSL 1.1.1+ (existing dependency via `SOCKET_HAS_TLS`)
- No new external dependencies
- Conditional compilation with `SOCKET_HAS_TLS`

### - [x] API Specification ✅

```c
/* ============================================================================
 * Hash Functions
 * ============================================================================ */

/**
 * SocketCrypto_sha1 - Compute SHA-1 hash (RFC 3174)
 * @input: Input data
 * @input_len: Length of input data
 * @output: Output buffer (must be at least 20 bytes)
 *
 * Used for: WebSocket Sec-WebSocket-Accept computation
 * Security: SHA-1 is cryptographically broken for signatures but
 *           acceptable for WebSocket handshake per RFC 6455
 */
void SocketCrypto_sha1(const void *input, size_t input_len,
                       unsigned char output[20]);

/**
 * SocketCrypto_sha256 - Compute SHA-256 hash (FIPS 180-4)
 * @input: Input data
 * @input_len: Length of input data
 * @output: Output buffer (must be at least 32 bytes)
 *
 * Used for: Digest authentication, integrity checks
 */
void SocketCrypto_sha256(const void *input, size_t input_len,
                         unsigned char output[32]);

/**
 * SocketCrypto_md5 - Compute MD5 hash (RFC 1321)
 * @input: Input data
 * @input_len: Length of input data
 * @output: Output buffer (must be at least 16 bytes)
 *
 * Used for: HTTP Digest authentication (legacy, required by RFC 7616)
 * Security: MD5 is cryptographically broken; only use where required by spec
 */
void SocketCrypto_md5(const void *input, size_t input_len,
                      unsigned char output[16]);

/* ============================================================================
 * HMAC Functions
 * ============================================================================ */

/**
 * SocketCrypto_hmac_sha256 - Compute HMAC-SHA256
 * @key: HMAC key
 * @key_len: Key length
 * @data: Input data
 * @data_len: Data length
 * @output: Output buffer (32 bytes)
 *
 * Used for: Cookie signing, session tokens
 */
void SocketCrypto_hmac_sha256(const void *key, size_t key_len,
                               const void *data, size_t data_len,
                               unsigned char output[32]);

/* ============================================================================
 * Base64 Encoding (RFC 4648)
 * ============================================================================ */

/**
 * SocketCrypto_base64_encode - Base64 encode data
 * @input: Input data
 * @input_len: Length of input data
 * @output: Output buffer
 * @output_size: Size of output buffer
 * Returns: Length of encoded string (excluding null terminator), or -1 on error
 *
 * Output is null-terminated. Required buffer size: ((input_len + 2) / 3) * 4 + 1
 */
ssize_t SocketCrypto_base64_encode(const void *input, size_t input_len,
                                    char *output, size_t output_size);

/**
 * SocketCrypto_base64_decode - Base64 decode data
 * @input: Base64 encoded string
 * @input_len: Length of input (0 to auto-detect from null terminator)
 * @output: Output buffer
 * @output_size: Size of output buffer
 * Returns: Length of decoded data, or -1 on error
 *
 * Handles standard Base64 and URL-safe Base64 (RFC 4648 Section 5)
 * Ignores whitespace per RFC 4648 Section 3.3
 */
ssize_t SocketCrypto_base64_decode(const char *input, size_t input_len,
                                    unsigned char *output, size_t output_size);

/**
 * SocketCrypto_base64_encoded_size - Calculate encoded size
 * @input_len: Length of input data
 * Returns: Required buffer size including null terminator
 */
size_t SocketCrypto_base64_encoded_size(size_t input_len);

/**
 * SocketCrypto_base64_decoded_size - Calculate maximum decoded size
 * @input_len: Length of Base64 string
 * Returns: Maximum decoded size (actual may be less due to padding)
 */
size_t SocketCrypto_base64_decoded_size(size_t input_len);

/* ============================================================================
 * WebSocket Handshake Helper
 * ============================================================================ */

/**
 * SocketCrypto_websocket_accept - Compute Sec-WebSocket-Accept value
 * @client_key: Sec-WebSocket-Key from client request (24 chars base64)
 * @output: Output buffer (must be at least 29 bytes)
 * Returns: 0 on success, -1 on error
 *
 * Computes: base64(SHA1(client_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
 * Per RFC 6455 Section 4.2.2
 */
int SocketCrypto_websocket_accept(const char *client_key, char output[29]);

/**
 * SocketCrypto_websocket_key - Generate random Sec-WebSocket-Key
 * @output: Output buffer (must be at least 25 bytes)
 * Returns: 0 on success, -1 on error
 *
 * Generates 16 random bytes, base64 encodes to 24 chars + null
 * Per RFC 6455 Section 4.1
 */
int SocketCrypto_websocket_key(char output[25]);

/* ============================================================================
 * Random Number Generation
 * ============================================================================ */

/**
 * SocketCrypto_random_bytes - Generate cryptographically secure random bytes
 * @output: Output buffer
 * @len: Number of bytes to generate
 * Returns: 0 on success, -1 on error
 *
 * Uses OpenSSL RAND_bytes() or /dev/urandom fallback
 */
int SocketCrypto_random_bytes(void *output, size_t len);

/**
 * SocketCrypto_random_uint32 - Generate random 32-bit integer
 * Returns: Random uint32_t
 */
uint32_t SocketCrypto_random_uint32(void);

/* ============================================================================
 * Hex Encoding
 * ============================================================================ */

/**
 * SocketCrypto_hex_encode - Encode binary data as hexadecimal
 * @input: Input data
 * @input_len: Length of input
 * @output: Output buffer (must be at least input_len * 2 + 1)
 * @lowercase: Use lowercase hex digits
 */
void SocketCrypto_hex_encode(const void *input, size_t input_len,
                              char *output, int lowercase);

/**
 * SocketCrypto_hex_decode - Decode hexadecimal string
 * @input: Hex string
 * @input_len: Length of string (must be even)
 * @output: Output buffer (must be at least input_len / 2)
 * Returns: Decoded length, or -1 on error
 */
ssize_t SocketCrypto_hex_decode(const char *input, size_t input_len,
                                 unsigned char *output);

/* ============================================================================
 * Security Utilities (Added during implementation)
 * ============================================================================ */

/**
 * SocketCrypto_secure_compare - Constant-time memory comparison
 * @a: First buffer
 * @b: Second buffer
 * @len: Length to compare
 * Returns: 0 if equal, non-zero if different
 *
 * Use for comparing MACs, hashes, or other security-sensitive data.
 */
int SocketCrypto_secure_compare(const void *a, const void *b, size_t len);

/**
 * SocketCrypto_secure_clear - Securely clear sensitive data
 * @ptr: Buffer to clear
 * @len: Length of buffer
 *
 * Clears memory in a way that won't be optimized away by the compiler.
 */
void SocketCrypto_secure_clear(void *ptr, size_t len);
```

### - [x] Implementation Requirements ✅

- [x] SHA-1 using `SHA1()` from OpenSSL
- [x] SHA-256 using `SHA256()` from OpenSSL
- [x] MD5 using `MD5()` from OpenSSL
- [x] HMAC using `HMAC()` from OpenSSL
- [x] Base64 using manual implementation (handles URL-safe and whitespace)
- [x] Random using `RAND_bytes()` from OpenSSL with `/dev/urandom` fallback
- [x] Stub implementations when `SOCKET_HAS_TLS` is not defined (runtime exception via `SocketCrypto_Failed`)
- [x] Thread-safe (no global state)
- [x] Constant-time comparison using `CRYPTO_memcmp()` (exposed as `SocketCrypto_secure_compare()`)

### - [x] Security Considerations ✅

- [x] Clear sensitive data from stack after use
- [x] Use `OPENSSL_cleanse()` for key material (exposed as `SocketCrypto_secure_clear()`)
- [x] Validate all input lengths before operations
- [x] Return errors rather than crashing on invalid input

### - [x] Tests ✅

- [x] `src/test/test_crypto.c`
  - [x] SHA-1 test vectors from RFC 3174
  - [x] SHA-256 test vectors from NIST FIPS 180-4
  - [x] MD5 test vectors from RFC 1321
  - [x] HMAC-SHA256 test vectors from RFC 4231
  - [x] Base64 encode/decode round-trip
  - [x] Base64 RFC 4648 test vectors
  - [x] Base64 with whitespace handling
  - [x] Base64 URL-safe variant
  - [x] WebSocket accept key computation (RFC 6455 example)
  - [x] Hex encode/decode
  - [x] Random byte generation tests
  - [x] Empty input handling
  - [x] Buffer size calculations
  - [x] Secure compare and clear utilities

### - [x] Fuzzing Harnesses ✅

- [x] `src/fuzz/fuzz_base64_decode.c` - Base64 decoding
- [x] `src/fuzz/fuzz_hex_decode.c` - Hex decoding

### - [x] Build System ✅

- [x] Add `src/core/SocketCrypto.c` to `LIB_SOURCES` in CMakeLists.txt
- [x] Add `include/core/SocketCrypto.h` to `CORE_HEADERS` in CMakeLists.txt
- [x] Add `test_crypto` to test executables
- [x] Add `fuzz_base64_decode` and `fuzz_hex_decode` to fuzz harnesses

---

## - [x] Phase 2: UTF-8 Validation ✅ COMPLETED

Complete UTF-8 validation per Unicode Standard with incremental API for streaming.
Required for WebSocket text frame validation (RFC 6455 Section 8.1).

**Status**: Completed (December 2025)

### - [x] Files Created ✅

- [x] `include/core/SocketUTF8.h` - Public API header
- [x] `src/core/SocketUTF8.c` - DFA-based implementation

### - [x] API Specification ✅

```c
/* ============================================================================
 * UTF-8 Validation Result
 * ============================================================================ */

/**
 * UTF-8 validation result codes
 */
typedef enum {
    UTF8_VALID = 0,         /* Complete valid UTF-8 sequence */
    UTF8_INVALID,           /* Invalid byte sequence detected */
    UTF8_INCOMPLETE,        /* Valid prefix, needs more bytes */
    UTF8_OVERLONG,          /* Overlong encoding (security issue) */
    UTF8_SURROGATE,         /* UTF-16 surrogate (U+D800-U+DFFF) */
    UTF8_TOO_LARGE          /* Code point > U+10FFFF */
} SocketUTF8_Result;

/* ============================================================================
 * One-Shot Validation
 * ============================================================================ */

/**
 * SocketUTF8_validate - Validate UTF-8 data (complete check)
 * @data: Input data
 * @len: Length of data in bytes
 * Returns: UTF8_VALID if entire sequence is valid UTF-8
 *
 * Rejects:
 * - Invalid continuation bytes
 * - Overlong encodings (e.g., 0xC0 0x80 for NUL)
 * - UTF-16 surrogates (U+D800-U+DFFF)
 * - Code points > U+10FFFF
 * - Truncated sequences at end
 */
SocketUTF8_Result SocketUTF8_validate(const unsigned char *data, size_t len);

/**
 * SocketUTF8_validate_str - Validate null-terminated string
 * @str: Null-terminated string
 * Returns: UTF8_VALID if valid UTF-8
 */
SocketUTF8_Result SocketUTF8_validate_str(const char *str);

/* ============================================================================
 * Incremental Validation (for streaming)
 * ============================================================================ */

/**
 * UTF-8 incremental validator state
 * Public structure for stack allocation - initialized via SocketUTF8_init()
 */
typedef struct {
    uint32_t state;         /* DFA state */
    uint32_t codepoint;     /* Accumulated code point */
    uint8_t bytes_needed;   /* Remaining bytes in sequence */
    uint8_t bytes_seen;     /* Bytes seen in current sequence */
} SocketUTF8_State;

/**
 * SocketUTF8_init - Initialize incremental validator
 * @state: State structure to initialize
 */
void SocketUTF8_init(SocketUTF8_State *state);

/**
 * SocketUTF8_update - Feed data to incremental validator
 * @state: Validator state
 * @data: Input data chunk
 * @len: Length of chunk
 * Returns: UTF8_VALID (valid so far), UTF8_INCOMPLETE, or error
 *
 * Can be called multiple times with chunks of data.
 * State is preserved between calls for multi-byte sequences split across chunks.
 */
SocketUTF8_Result SocketUTF8_update(SocketUTF8_State *state,
                                     const unsigned char *data, size_t len);

/**
 * SocketUTF8_finish - Finalize incremental validation
 * @state: Validator state
 * Returns: UTF8_VALID if stream ended on complete sequence, UTF8_INCOMPLETE otherwise
 *
 * Must be called after all data has been fed to check for truncated sequences.
 */
SocketUTF8_Result SocketUTF8_finish(const SocketUTF8_State *state);

/**
 * SocketUTF8_reset - Reset validator for reuse
 * @state: Validator state
 */
void SocketUTF8_reset(SocketUTF8_State *state);

/* ============================================================================
 * UTF-8 Utilities
 * ============================================================================ */

/**
 * SocketUTF8_codepoint_len - Get byte length of code point
 * @codepoint: Unicode code point (U+0000 to U+10FFFF)
 * Returns: 1-4 for valid code points, 0 for invalid
 */
int SocketUTF8_codepoint_len(uint32_t codepoint);

/**
 * SocketUTF8_sequence_len - Get length of UTF-8 sequence from first byte
 * @first_byte: First byte of sequence
 * Returns: 1-4 for valid start bytes, 0 for invalid/continuation
 */
int SocketUTF8_sequence_len(unsigned char first_byte);

/**
 * SocketUTF8_encode - Encode code point to UTF-8
 * @codepoint: Unicode code point
 * @output: Output buffer (must be at least 4 bytes)
 * Returns: Number of bytes written (1-4), or 0 for invalid code point
 */
int SocketUTF8_encode(uint32_t codepoint, unsigned char *output);

/**
 * SocketUTF8_decode - Decode one code point from UTF-8
 * @data: Input data
 * @len: Available bytes
 * @codepoint: Output code point
 * @consumed: Output bytes consumed
 * Returns: UTF8_VALID, UTF8_INCOMPLETE, or error
 */
SocketUTF8_Result SocketUTF8_decode(const unsigned char *data, size_t len,
                                     uint32_t *codepoint, size_t *consumed);

/**
 * SocketUTF8_count_codepoints - Count code points in UTF-8 string
 * @data: Input data
 * @len: Length in bytes
 * @count: Output code point count
 * Returns: UTF8_VALID if valid, error otherwise
 */
SocketUTF8_Result SocketUTF8_count_codepoints(const unsigned char *data,
                                               size_t len, size_t *count);

/**
 * SocketUTF8_result_string - Get human-readable result description
 * @result: Validation result
 * Returns: Static string description
 */
const char *SocketUTF8_result_string(SocketUTF8_Result result);
```

### - [x] Implementation Requirements ✅

- [x] DFA-based validation (Hoehrmann algorithm)
- [x] O(n) time complexity, O(1) space complexity
- [x] Strict rejection of overlong encodings
- [x] Strict rejection of surrogate pairs (U+D800-U+DFFF)
- [x] Strict rejection of code points > U+10FFFF
- [x] Proper handling of incomplete sequences at boundaries
- [x] Thread-safe (state per-call, no globals)

### UTF-8 Encoding Reference

| Bytes | First Code Point | Last Code Point | Byte 1 | Byte 2 | Byte 3 | Byte 4 |
|-------|------------------|-----------------|--------|--------|--------|--------|
| 1 | U+0000 | U+007F | 0xxxxxxx | | | |
| 2 | U+0080 | U+07FF | 110xxxxx | 10xxxxxx | | |
| 3 | U+0800 | U+FFFF | 1110xxxx | 10xxxxxx | 10xxxxxx | |
| 4 | U+10000 | U+10FFFF | 11110xxx | 10xxxxxx | 10xxxxxx | 10xxxxxx |

### - [x] Security Considerations ✅

- [x] Reject overlong encodings (e.g., C0 80 for NUL) - security critical
- [x] Reject surrogates (used in UTF-16, invalid in UTF-8)
- [x] Reject code points > U+10FFFF
- [x] No buffer overflows in incremental parser
- [x] Validate continuation bytes strictly

### - [x] Tests ✅

- [x] `src/test/test_utf8.c` (67 tests)
  - [x] ASCII validation
  - [x] All 2-byte sequence boundaries
  - [x] All 3-byte sequence boundaries  
  - [x] All 4-byte sequence boundaries
  - [x] Maximum code point U+10FFFF
  - [x] Overlong encoding rejection (C0 80, E0 80 80, etc.)
  - [x] Surrogate pair rejection (ED A0 80 to ED BF BF)
  - [x] Code point > U+10FFFF rejection
  - [x] Invalid continuation bytes
  - [x] Missing continuation bytes
  - [x] Unexpected continuation bytes
  - [x] Incremental validation across chunk boundaries
  - [x] Multi-byte sequence split across chunks
  - [x] Empty input
  - [x] Single-byte sequences
  - [x] Encode/decode round-trip tests

### - [x] Fuzzing Harnesses ✅

- [x] `src/fuzz/fuzz_utf8_validate.c` - One-shot validation
- [x] `src/fuzz/fuzz_utf8_incremental.c` - Incremental validation

### - [x] Build System ✅

- [x] Add `src/core/SocketUTF8.c` to `LIB_SOURCES`
- [x] Add `include/core/SocketUTF8.h` to `CORE_HEADERS`
- [x] Add `test_utf8` to test executables
- [x] Add fuzz harnesses to `FUZZ_SOURCES`

---

## - [x] Phase 3: HTTP Core (RFC 9110) ✅ COMPLETED

Protocol-agnostic HTTP types, header handling, and URI parsing.
Foundation for HTTP/1.1 and HTTP/2.

**Status**: Completed (December 2025)

### - [x] Files Created ✅

- [x] `include/http/SocketHTTP.h` - Public types and utilities
- [x] `include/http/SocketHTTP-private.h` - Internal structures
- [x] `src/http/SocketHTTP-core.c` - Core utilities
- [x] `src/http/SocketHTTP-headers.c` - Header collection
- [x] `src/http/SocketHTTP-uri.c` - URI parsing
- [x] `src/http/SocketHTTP-date.c` - Date parsing

### RFC Sections Covered ✅

- RFC 9110 Section 4: Identifiers (URIs)
- RFC 9110 Section 5: Fields (Headers)
- RFC 9110 Section 6: Message Abstraction
- RFC 9110 Section 8: Representations
- RFC 9110 Section 9: Methods
- RFC 9110 Section 15: Status Codes
- RFC 3986: URI Generic Syntax

### - [x] API Specification ✅

```c
/* ============================================================================
 * HTTP Version
 * ============================================================================ */

typedef enum {
    HTTP_VERSION_0_9 = 9,    /* HTTP/0.9 (simple, no headers) */
    HTTP_VERSION_1_0 = 10,   /* HTTP/1.0 */
    HTTP_VERSION_1_1 = 11,   /* HTTP/1.1 */
    HTTP_VERSION_2 = 20,     /* HTTP/2 */
    HTTP_VERSION_3 = 30      /* HTTP/3 (future) */
} SocketHTTP_Version;

/* ============================================================================
 * HTTP Methods (RFC 9110 Section 9)
 * ============================================================================ */

typedef enum {
    HTTP_METHOD_GET = 0,     /* RFC 9110 Section 9.3.1 */
    HTTP_METHOD_HEAD,        /* RFC 9110 Section 9.3.2 */
    HTTP_METHOD_POST,        /* RFC 9110 Section 9.3.3 */
    HTTP_METHOD_PUT,         /* RFC 9110 Section 9.3.4 */
    HTTP_METHOD_DELETE,      /* RFC 9110 Section 9.3.5 */
    HTTP_METHOD_CONNECT,     /* RFC 9110 Section 9.3.6 */
    HTTP_METHOD_OPTIONS,     /* RFC 9110 Section 9.3.7 */
    HTTP_METHOD_TRACE,       /* RFC 9110 Section 9.3.8 */
    HTTP_METHOD_PATCH,       /* RFC 5789 */
    HTTP_METHOD_UNKNOWN = -1
} SocketHTTP_Method;

/**
 * Method properties (RFC 9110 Section 9.2)
 */
typedef struct {
    unsigned safe : 1;        /* Does not modify resources */
    unsigned idempotent : 1;  /* Multiple identical requests same as one */
    unsigned cacheable : 1;   /* Response may be cached */
    unsigned has_body : 1;    /* Request may have body */
    unsigned response_body : 1; /* Response has body (except HEAD) */
} SocketHTTP_MethodProperties;

/* Method functions */
const char *SocketHTTP_method_name(SocketHTTP_Method method);
SocketHTTP_Method SocketHTTP_method_parse(const char *str, size_t len);
SocketHTTP_MethodProperties SocketHTTP_method_properties(SocketHTTP_Method method);
int SocketHTTP_method_valid(const char *str, size_t len);

/* ============================================================================
 * HTTP Status Codes (RFC 9110 Section 15)
 * ============================================================================ */

typedef enum {
    /* 1xx Informational */
    HTTP_STATUS_CONTINUE = 100,
    HTTP_STATUS_SWITCHING_PROTOCOLS = 101,
    HTTP_STATUS_PROCESSING = 102,           /* RFC 2518 */
    HTTP_STATUS_EARLY_HINTS = 103,          /* RFC 8297 */
    
    /* 2xx Successful */
    HTTP_STATUS_OK = 200,
    HTTP_STATUS_CREATED = 201,
    HTTP_STATUS_ACCEPTED = 202,
    HTTP_STATUS_NON_AUTHORITATIVE = 203,
    HTTP_STATUS_NO_CONTENT = 204,
    HTTP_STATUS_RESET_CONTENT = 205,
    HTTP_STATUS_PARTIAL_CONTENT = 206,
    HTTP_STATUS_MULTI_STATUS = 207,         /* RFC 4918 */
    HTTP_STATUS_ALREADY_REPORTED = 208,     /* RFC 5842 */
    HTTP_STATUS_IM_USED = 226,              /* RFC 3229 */
    
    /* 3xx Redirection */
    HTTP_STATUS_MULTIPLE_CHOICES = 300,
    HTTP_STATUS_MOVED_PERMANENTLY = 301,
    HTTP_STATUS_FOUND = 302,
    HTTP_STATUS_SEE_OTHER = 303,
    HTTP_STATUS_NOT_MODIFIED = 304,
    HTTP_STATUS_USE_PROXY = 305,            /* Deprecated */
    HTTP_STATUS_TEMPORARY_REDIRECT = 307,
    HTTP_STATUS_PERMANENT_REDIRECT = 308,   /* RFC 7538 */
    
    /* 4xx Client Error */
    HTTP_STATUS_BAD_REQUEST = 400,
    HTTP_STATUS_UNAUTHORIZED = 401,
    HTTP_STATUS_PAYMENT_REQUIRED = 402,
    HTTP_STATUS_FORBIDDEN = 403,
    HTTP_STATUS_NOT_FOUND = 404,
    HTTP_STATUS_METHOD_NOT_ALLOWED = 405,
    HTTP_STATUS_NOT_ACCEPTABLE = 406,
    HTTP_STATUS_PROXY_AUTH_REQUIRED = 407,
    HTTP_STATUS_REQUEST_TIMEOUT = 408,
    HTTP_STATUS_CONFLICT = 409,
    HTTP_STATUS_GONE = 410,
    HTTP_STATUS_LENGTH_REQUIRED = 411,
    HTTP_STATUS_PRECONDITION_FAILED = 412,
    HTTP_STATUS_CONTENT_TOO_LARGE = 413,
    HTTP_STATUS_URI_TOO_LONG = 414,
    HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE = 415,
    HTTP_STATUS_RANGE_NOT_SATISFIABLE = 416,
    HTTP_STATUS_EXPECTATION_FAILED = 417,
    HTTP_STATUS_IM_A_TEAPOT = 418,          /* RFC 2324 */
    HTTP_STATUS_MISDIRECTED_REQUEST = 421,
    HTTP_STATUS_UNPROCESSABLE_CONTENT = 422,
    HTTP_STATUS_LOCKED = 423,               /* RFC 4918 */
    HTTP_STATUS_FAILED_DEPENDENCY = 424,    /* RFC 4918 */
    HTTP_STATUS_TOO_EARLY = 425,            /* RFC 8470 */
    HTTP_STATUS_UPGRADE_REQUIRED = 426,
    HTTP_STATUS_PRECONDITION_REQUIRED = 428,/* RFC 6585 */
    HTTP_STATUS_TOO_MANY_REQUESTS = 429,    /* RFC 6585 */
    HTTP_STATUS_HEADER_TOO_LARGE = 431,     /* RFC 6585 */
    HTTP_STATUS_UNAVAILABLE_LEGAL = 451,    /* RFC 7725 */
    
    /* 5xx Server Error */
    HTTP_STATUS_INTERNAL_ERROR = 500,
    HTTP_STATUS_NOT_IMPLEMENTED = 501,
    HTTP_STATUS_BAD_GATEWAY = 502,
    HTTP_STATUS_SERVICE_UNAVAILABLE = 503,
    HTTP_STATUS_GATEWAY_TIMEOUT = 504,
    HTTP_STATUS_VERSION_NOT_SUPPORTED = 505,
    HTTP_STATUS_VARIANT_ALSO_NEGOTIATES = 506, /* RFC 2295 */
    HTTP_STATUS_INSUFFICIENT_STORAGE = 507, /* RFC 4918 */
    HTTP_STATUS_LOOP_DETECTED = 508,        /* RFC 5842 */
    HTTP_STATUS_NOT_EXTENDED = 510,         /* RFC 2774 */
    HTTP_STATUS_NETWORK_AUTH_REQUIRED = 511 /* RFC 6585 */
} SocketHTTP_StatusCode;

/* Status code categories */
typedef enum {
    HTTP_STATUS_INFORMATIONAL = 1,  /* 1xx */
    HTTP_STATUS_SUCCESSFUL = 2,     /* 2xx */
    HTTP_STATUS_REDIRECTION = 3,    /* 3xx */
    HTTP_STATUS_CLIENT_ERROR = 4,   /* 4xx */
    HTTP_STATUS_SERVER_ERROR = 5    /* 5xx */
} SocketHTTP_StatusCategory;

/* Status code functions */
const char *SocketHTTP_status_reason(int code);
SocketHTTP_StatusCategory SocketHTTP_status_category(int code);
int SocketHTTP_status_valid(int code);

/* ============================================================================
 * HTTP Headers (RFC 9110 Section 5)
 * ============================================================================ */

/**
 * Single header field
 */
typedef struct {
    const char *name;       /* Header name (case-preserved) */
    size_t name_len;
    const char *value;      /* Header value */
    size_t value_len;
} SocketHTTP_Header;

/**
 * Header collection (opaque type)
 */
typedef struct SocketHTTP_Headers *SocketHTTP_Headers_T;

/* Header collection lifecycle */
SocketHTTP_Headers_T SocketHTTP_Headers_new(Arena_T arena);
void SocketHTTP_Headers_clear(SocketHTTP_Headers_T headers);

/* Adding headers */
int SocketHTTP_Headers_add(SocketHTTP_Headers_T headers,
                           const char *name, const char *value);
int SocketHTTP_Headers_add_n(SocketHTTP_Headers_T headers,
                             const char *name, size_t name_len,
                             const char *value, size_t value_len);
int SocketHTTP_Headers_set(SocketHTTP_Headers_T headers,
                           const char *name, const char *value);

/* Retrieving headers (case-insensitive) */
const char *SocketHTTP_Headers_get(SocketHTTP_Headers_T headers,
                                   const char *name);
int SocketHTTP_Headers_get_int(SocketHTTP_Headers_T headers,
                               const char *name, int64_t *value);
size_t SocketHTTP_Headers_get_all(SocketHTTP_Headers_T headers,
                                  const char *name,
                                  const char **values, size_t max_values);

/* Checking headers */
int SocketHTTP_Headers_has(SocketHTTP_Headers_T headers, const char *name);
int SocketHTTP_Headers_contains(SocketHTTP_Headers_T headers,
                                const char *name, const char *token);

/* Removing headers */
int SocketHTTP_Headers_remove(SocketHTTP_Headers_T headers, const char *name);
int SocketHTTP_Headers_remove_all(SocketHTTP_Headers_T headers, const char *name);

/* Iteration */
size_t SocketHTTP_Headers_count(SocketHTTP_Headers_T headers);
const SocketHTTP_Header *SocketHTTP_Headers_at(SocketHTTP_Headers_T headers,
                                                size_t index);

typedef int (*SocketHTTP_HeaderCallback)(const char *name, size_t name_len,
                                          const char *value, size_t value_len,
                                          void *userdata);
int SocketHTTP_Headers_iterate(SocketHTTP_Headers_T headers,
                               SocketHTTP_HeaderCallback callback,
                               void *userdata);

/* Header validation (RFC 9110 Section 5.1) */
int SocketHTTP_header_name_valid(const char *name, size_t len);
int SocketHTTP_header_value_valid(const char *value, size_t len);

/* ============================================================================
 * URI Parsing (RFC 3986)
 * ============================================================================ */

/**
 * Parsed URI components
 */
typedef struct {
    const char *scheme;         /* "http", "https", etc. */
    size_t scheme_len;
    const char *userinfo;       /* username:password (deprecated) */
    size_t userinfo_len;
    const char *host;           /* Hostname or IP */
    size_t host_len;
    int port;                   /* Port number or -1 */
    const char *path;           /* Path component */
    size_t path_len;
    const char *query;          /* Query string (after ?) */
    size_t query_len;
    const char *fragment;       /* Fragment (after #) */
    size_t fragment_len;
} SocketHTTP_URI;

/**
 * URI parsing results
 */
typedef enum {
    URI_PARSE_OK = 0,
    URI_PARSE_ERROR,
    URI_PARSE_INVALID_SCHEME,
    URI_PARSE_INVALID_HOST,
    URI_PARSE_INVALID_PORT,
    URI_PARSE_INVALID_PATH,
    URI_PARSE_INVALID_QUERY,
    URI_PARSE_TOO_LONG
} SocketHTTP_URIResult;

/* URI parsing */
SocketHTTP_URIResult SocketHTTP_URI_parse(const char *uri, size_t len,
                                           SocketHTTP_URI *result,
                                           Arena_T arena);

/* URI component extraction */
int SocketHTTP_URI_get_port(const SocketHTTP_URI *uri, int default_port);
int SocketHTTP_URI_is_secure(const SocketHTTP_URI *uri);

/* URI encoding/decoding (percent encoding) */
ssize_t SocketHTTP_URI_encode(const char *input, size_t len,
                               char *output, size_t output_size);
ssize_t SocketHTTP_URI_decode(const char *input, size_t len,
                               char *output, size_t output_size);

/* URI building */
ssize_t SocketHTTP_URI_build(const SocketHTTP_URI *uri,
                              char *output, size_t output_size);

/* ============================================================================
 * Date Parsing (RFC 9110 Section 5.6.7)
 * ============================================================================ */

/**
 * SocketHTTP_date_parse - Parse HTTP-date
 * @date_str: Date string in any valid HTTP-date format
 * @len: Length of string
 * @time_out: Output time_t
 * Returns: 0 on success, -1 on error
 *
 * Accepts three formats per RFC 9110:
 * - IMF-fixdate: Sun, 06 Nov 1994 08:49:37 GMT (preferred)
 * - RFC 850: Sunday, 06-Nov-94 08:49:37 GMT (obsolete)
 * - ANSI C: Sun Nov  6 08:49:37 1994 (obsolete)
 */
int SocketHTTP_date_parse(const char *date_str, size_t len, time_t *time_out);

/**
 * SocketHTTP_date_format - Format time as HTTP-date (IMF-fixdate)
 * @t: Time to format
 * @output: Output buffer (must be at least 30 bytes)
 * Returns: Length written
 */
int SocketHTTP_date_format(time_t t, char *output);

/* ============================================================================
 * Content Type Parsing (RFC 9110 Section 8.3)
 * ============================================================================ */

/**
 * Parsed media type
 */
typedef struct {
    const char *type;           /* "text", "application", etc. */
    size_t type_len;
    const char *subtype;        /* "html", "json", etc. */
    size_t subtype_len;
    const char *charset;        /* Character set parameter */
    size_t charset_len;
    const char *boundary;       /* Multipart boundary parameter */
    size_t boundary_len;
} SocketHTTP_MediaType;

/**
 * SocketHTTP_MediaType_parse - Parse Content-Type header
 * @value: Content-Type header value
 * @len: Length of value
 * @result: Output structure
 * @arena: Arena for parameter strings
 * Returns: 0 on success
 */
int SocketHTTP_MediaType_parse(const char *value, size_t len,
                                SocketHTTP_MediaType *result,
                                Arena_T arena);

/**
 * SocketHTTP_MediaType_matches - Check if media type matches pattern
 * @type: Parsed media type
 * @pattern: Pattern like "text/*" or "application/json"
 */
int SocketHTTP_MediaType_matches(const SocketHTTP_MediaType *type,
                                  const char *pattern);

/* ============================================================================
 * Content Negotiation (RFC 9110 Section 12)
 * ============================================================================ */

/**
 * Quality value (q-value) from Accept headers
 */
typedef struct {
    const char *value;
    size_t value_len;
    float quality;      /* 0.0 to 1.0, default 1.0 */
} SocketHTTP_QualityValue;

/**
 * SocketHTTP_parse_accept - Parse Accept-style header
 * @value: Header value
 * @len: Length
 * @results: Output array
 * @max_results: Maximum results
 * @arena: Arena for strings
 * Returns: Number of results parsed
 */
size_t SocketHTTP_parse_accept(const char *value, size_t len,
                                SocketHTTP_QualityValue *results,
                                size_t max_results, Arena_T arena);

/* ============================================================================
 * Request/Response Structures
 * ============================================================================ */

/**
 * HTTP Request (protocol-agnostic)
 */
typedef struct {
    SocketHTTP_Method method;
    SocketHTTP_Version version;
    
    /* Target (different forms per RFC 9112) */
    const char *scheme;         /* "http" or "https" */
    const char *authority;      /* host:port */
    const char *path;           /* Path and query */
    
    SocketHTTP_Headers_T headers;
    
    /* Body information */
    int has_body;
    int64_t content_length;     /* -1 if unknown/chunked */
} SocketHTTP_Request;

/**
 * HTTP Response (protocol-agnostic)
 */
typedef struct {
    SocketHTTP_Version version;
    int status_code;
    const char *reason_phrase;  /* HTTP/1.x only, NULL for HTTP/2+ */
    
    SocketHTTP_Headers_T headers;
    
    /* Body information */
    int has_body;
    int64_t content_length;     /* -1 if unknown/chunked */
} SocketHTTP_Response;

/* ============================================================================
 * Transfer and Content Codings
 * ============================================================================ */

typedef enum {
    HTTP_CODING_IDENTITY = 0,
    HTTP_CODING_CHUNKED,
    HTTP_CODING_GZIP,
    HTTP_CODING_DEFLATE,
    HTTP_CODING_COMPRESS,       /* LZW - rarely used */
    HTTP_CODING_BR,             /* Brotli (RFC 7932) */
    HTTP_CODING_UNKNOWN = -1
} SocketHTTP_Coding;

SocketHTTP_Coding SocketHTTP_coding_parse(const char *name, size_t len);
const char *SocketHTTP_coding_name(SocketHTTP_Coding coding);

/* ============================================================================
 * Exception Types
 * ============================================================================ */

extern const Except_T SocketHTTP_ParseError;
extern const Except_T SocketHTTP_InvalidURI;
extern const Except_T SocketHTTP_InvalidHeader;
```

### - [x] Implementation Requirements ✅

#### Header Collection ✅
- [x] Case-insensitive name lookup (ASCII only per RFC 9110)
- [x] Preserve original case for serialization
- [x] Support multiple headers with same name
- [x] Efficient iteration and lookup (O(1) hash table)
- [x] Token parsing for headers like Connection, Transfer-Encoding
- [x] Comma-separated value handling

#### URI Parsing (RFC 3986) ✅
- [x] Full URI-reference parsing
- [x] Absolute URI support
- [x] Relative reference support
- [x] Percent-encoding handling
- [x] IPv6 address support in host
- [x] Query string parsing
- [x] Fragment handling

#### Date Parsing ✅
- [x] IMF-fixdate format (preferred)
- [x] RFC 850 format (obsolete, must accept)
- [x] ANSI C asctime() format (obsolete, must accept)
- [x] Timezone handling (always GMT)

### - [x] Security Considerations ✅

- [x] Header name validation (reject control chars, space, etc.)
- [x] Header value validation (reject bare CR, LF, NUL)
- [x] URI length limits (8KB default)
- [x] Header count limits (128 default)
- [x] Total header size limits (64KB default)
- [x] Protection against header injection

### - [x] Tests ✅

- [x] `src/test/test_http_core.c` (190 tests)
  - [x] All HTTP methods
  - [x] Method properties (safe, idempotent, etc.)
  - [x] All status codes
  - [x] Status categories
  - [x] Header add/get/remove
  - [x] Case-insensitive header lookup
  - [x] Multi-value headers
  - [x] URI parsing (various formats)
  - [x] URI encoding/decoding
  - [x] Date parsing (all three formats)
  - [x] Date formatting
  - [x] Media type parsing
  - [x] Accept header parsing
  - [x] Content negotiation

### - [x] Fuzzing Harnesses ✅

- [x] `src/fuzz/fuzz_uri_parse.c`
- [x] `src/fuzz/fuzz_http_date.c`
- [ ] `src/fuzz/fuzz_media_type.c` (future)
- [ ] `src/fuzz/fuzz_accept_header.c` (future)

### - [x] Build System ✅

- [x] Add HTTP source files to `LIB_SOURCES`
- [x] Add `test_http_core` to test executables

---

## - [x] Phase 4: HTTP/1.1 Message Syntax (RFC 9112) ✅ COMPLETED

Complete HTTP/1.1 message parsing and serialization with security hardening.

**Status**: Completed (December 2025)

### - [x] Files Created ✅

- [x] `include/http/SocketHTTP1.h`
- [x] `include/http/SocketHTTP1-private.h`
- [x] `src/http/SocketHTTP1-parser.c` (Table-driven DFA, Hoehrmann-style)
- [x] `src/http/SocketHTTP1-serialize.c`
- [x] `src/http/SocketHTTP1-chunked.c`
- [x] `src/http/SocketHTTP1-compress.c`

### RFC Sections Covered ✅

- RFC 9112 Section 2: Message
- RFC 9112 Section 3: Request Line
- RFC 9112 Section 4: Status Line
- RFC 9112 Section 5: Field Syntax
- RFC 9112 Section 6: Message Body
- RFC 9112 Section 7: Transfer Codings

### - [x] Configuration Limits ✅

```c
/**
 * HTTP/1.1 Parser Limits
 * All limits configurable at compile time and runtime
 */

/* Request/Status line limits */
#ifndef SOCKETHTTP1_MAX_REQUEST_LINE
#define SOCKETHTTP1_MAX_REQUEST_LINE (8 * 1024)     /* 8KB */
#endif

#ifndef SOCKETHTTP1_MAX_METHOD_LEN
#define SOCKETHTTP1_MAX_METHOD_LEN 16               /* Longest standard: OPTIONS */
#endif

#ifndef SOCKETHTTP1_MAX_URI_LEN
#define SOCKETHTTP1_MAX_URI_LEN (8 * 1024)          /* 8KB URI */
#endif

/* Header limits */
#ifndef SOCKETHTTP1_MAX_HEADER_NAME
#define SOCKETHTTP1_MAX_HEADER_NAME 256             /* Header name length */
#endif

#ifndef SOCKETHTTP1_MAX_HEADER_VALUE
#define SOCKETHTTP1_MAX_HEADER_VALUE (8 * 1024)     /* 8KB per header value */
#endif

#ifndef SOCKETHTTP1_MAX_HEADERS
#define SOCKETHTTP1_MAX_HEADERS 100                 /* Maximum header count */
#endif

#ifndef SOCKETHTTP1_MAX_HEADER_SIZE
#define SOCKETHTTP1_MAX_HEADER_SIZE (64 * 1024)     /* 64KB total headers */
#endif

/* Body limits */
#ifndef SOCKETHTTP1_MAX_CHUNK_SIZE
#define SOCKETHTTP1_MAX_CHUNK_SIZE (16 * 1024 * 1024)  /* 16MB max chunk */
#endif

#ifndef SOCKETHTTP1_MAX_CHUNK_EXT
#define SOCKETHTTP1_MAX_CHUNK_EXT 1024              /* Chunk extension length */
#endif

#ifndef SOCKETHTTP1_MAX_TRAILER_SIZE
#define SOCKETHTTP1_MAX_TRAILER_SIZE (4 * 1024)     /* 4KB trailers */
#endif

/* Timeouts */
#ifndef SOCKETHTTP1_HEADER_TIMEOUT_MS
#define SOCKETHTTP1_HEADER_TIMEOUT_MS 30000         /* 30 seconds for headers */
#endif

#ifndef SOCKETHTTP1_BODY_TIMEOUT_MS
#define SOCKETHTTP1_BODY_TIMEOUT_MS 300000          /* 5 minutes for body */
#endif
```

### - [x] API Specification ✅

```c
/* ============================================================================
 * Parser State
 * ============================================================================ */

/**
 * Parser mode
 */
typedef enum {
    HTTP1_PARSE_REQUEST,
    HTTP1_PARSE_RESPONSE
} SocketHTTP1_ParseMode;

/**
 * Parser state
 */
typedef enum {
    HTTP1_STATE_START,          /* Waiting for first line */
    HTTP1_STATE_HEADERS,        /* Parsing headers */
    HTTP1_STATE_BODY,           /* Reading body */
    HTTP1_STATE_CHUNK_SIZE,     /* Reading chunk size line */
    HTTP1_STATE_CHUNK_DATA,     /* Reading chunk data */
    HTTP1_STATE_CHUNK_END,      /* Reading chunk CRLF */
    HTTP1_STATE_TRAILERS,       /* Reading trailers */
    HTTP1_STATE_COMPLETE,       /* Message complete */
    HTTP1_STATE_ERROR           /* Parse error */
} SocketHTTP1_State;

/**
 * Parse result codes
 */
typedef enum {
    HTTP1_OK = 0,               /* Complete message parsed */
    HTTP1_INCOMPLETE,           /* Need more data */
    HTTP1_ERROR,                /* Generic error */
    
    /* Specific errors */
    HTTP1_ERROR_LINE_TOO_LONG,
    HTTP1_ERROR_INVALID_METHOD,
    HTTP1_ERROR_INVALID_URI,
    HTTP1_ERROR_INVALID_VERSION,
    HTTP1_ERROR_INVALID_STATUS,
    HTTP1_ERROR_INVALID_HEADER_NAME,
    HTTP1_ERROR_INVALID_HEADER_VALUE,
    HTTP1_ERROR_HEADER_TOO_LARGE,
    HTTP1_ERROR_TOO_MANY_HEADERS,
    HTTP1_ERROR_INVALID_CONTENT_LENGTH,
    HTTP1_ERROR_INVALID_CHUNK_SIZE,
    HTTP1_ERROR_CHUNK_TOO_LARGE,
    HTTP1_ERROR_INVALID_TRAILER,
    HTTP1_ERROR_UNEXPECTED_EOF,
    HTTP1_ERROR_SMUGGLING_DETECTED  /* Request smuggling attempt */
} SocketHTTP1_Result;

/**
 * Parser configuration (runtime limits)
 */
typedef struct {
    size_t max_request_line;
    size_t max_header_name;
    size_t max_header_value;
    size_t max_headers;
    size_t max_header_size;
    size_t max_chunk_size;
    size_t max_trailer_size;
    int allow_obs_fold;         /* Allow obsolete header folding */
    int strict_mode;            /* Reject ambiguous input */
} SocketHTTP1_Config;

/**
 * Parser instance
 */
typedef struct SocketHTTP1_Parser *SocketHTTP1_Parser_T;

/* ============================================================================
 * Parser Lifecycle
 * ============================================================================ */

/**
 * SocketHTTP1_config_defaults - Initialize config with defaults
 */
void SocketHTTP1_config_defaults(SocketHTTP1_Config *config);

/**
 * SocketHTTP1_Parser_new - Create parser
 * @mode: Request or response mode
 * @config: Configuration (NULL for defaults)
 * @arena: Memory arena
 */
SocketHTTP1_Parser_T SocketHTTP1_Parser_new(SocketHTTP1_ParseMode mode,
                                             const SocketHTTP1_Config *config,
                                             Arena_T arena);

/**
 * SocketHTTP1_Parser_free - Free parser
 */
void SocketHTTP1_Parser_free(SocketHTTP1_Parser_T *parser);

/**
 * SocketHTTP1_Parser_reset - Reset for next message
 */
void SocketHTTP1_Parser_reset(SocketHTTP1_Parser_T parser);

/* ============================================================================
 * Parsing API
 * ============================================================================ */

/**
 * SocketHTTP1_Parser_execute - Parse data incrementally
 * @parser: Parser instance
 * @data: Input data buffer
 * @len: Data length
 * @consumed: Output - bytes consumed from input
 * Returns: Parse result
 *
 * Can be called multiple times with partial data.
 * Parsing stops at message boundary (after headers for HEAD/204/304,
 * after body otherwise).
 */
SocketHTTP1_Result SocketHTTP1_Parser_execute(SocketHTTP1_Parser_T parser,
                                               const char *data, size_t len,
                                               size_t *consumed);

/**
 * SocketHTTP1_Parser_state - Get current parser state
 */
SocketHTTP1_State SocketHTTP1_Parser_state(SocketHTTP1_Parser_T parser);

/**
 * SocketHTTP1_Parser_get_request - Get parsed request (after headers complete)
 */
const SocketHTTP_Request *SocketHTTP1_Parser_get_request(SocketHTTP1_Parser_T parser);

/**
 * SocketHTTP1_Parser_get_response - Get parsed response
 */
const SocketHTTP_Response *SocketHTTP1_Parser_get_response(SocketHTTP1_Parser_T parser);

/* ============================================================================
 * Body Handling
 * ============================================================================ */

/**
 * Body transfer mode detected from headers
 */
typedef enum {
    HTTP1_BODY_NONE,            /* No body (GET, HEAD, 1xx, 204, 304) */
    HTTP1_BODY_CONTENT_LENGTH,  /* Fixed Content-Length */
    HTTP1_BODY_CHUNKED,         /* Transfer-Encoding: chunked */
    HTTP1_BODY_UNTIL_CLOSE      /* Read until connection close */
} SocketHTTP1_BodyMode;

/**
 * SocketHTTP1_Parser_body_mode - Get body transfer mode
 */
SocketHTTP1_BodyMode SocketHTTP1_Parser_body_mode(SocketHTTP1_Parser_T parser);

/**
 * SocketHTTP1_Parser_content_length - Get Content-Length
 * Returns: Content-Length or -1 if not specified
 */
int64_t SocketHTTP1_Parser_content_length(SocketHTTP1_Parser_T parser);

/**
 * SocketHTTP1_Parser_body_remaining - Get remaining body bytes
 * Returns: Remaining bytes or -1 if unknown (chunked/until-close)
 */
int64_t SocketHTTP1_Parser_body_remaining(SocketHTTP1_Parser_T parser);

/**
 * SocketHTTP1_Parser_read_body - Read body data
 * @parser: Parser instance
 * @input: Input buffer (raw socket data)
 * @input_len: Input length
 * @consumed: Output - bytes consumed from input
 * @output: Output buffer for decoded body
 * @output_len: Output buffer size
 * @written: Output - bytes written to output
 * Returns: Result code
 *
 * Handles chunked decoding transparently.
 */
SocketHTTP1_Result SocketHTTP1_Parser_read_body(SocketHTTP1_Parser_T parser,
                                                 const char *input, size_t input_len,
                                                 size_t *consumed,
                                                 char *output, size_t output_len,
                                                 size_t *written);

/**
 * SocketHTTP1_Parser_body_complete - Check if body fully received
 */
int SocketHTTP1_Parser_body_complete(SocketHTTP1_Parser_T parser);

/**
 * SocketHTTP1_Parser_get_trailers - Get trailer headers (chunked only)
 */
SocketHTTP_Headers_T SocketHTTP1_Parser_get_trailers(SocketHTTP1_Parser_T parser);

/* ============================================================================
 * Connection Management
 * ============================================================================ */

/**
 * SocketHTTP1_Parser_should_keepalive - Check keep-alive status
 * Returns: 1 if connection should be kept alive, 0 otherwise
 *
 * Based on HTTP version and Connection header:
 * - HTTP/1.0: Keep-alive only if "Connection: keep-alive"
 * - HTTP/1.1: Keep-alive unless "Connection: close"
 */
int SocketHTTP1_Parser_should_keepalive(SocketHTTP1_Parser_T parser);

/**
 * SocketHTTP1_Parser_is_upgrade - Check if Upgrade requested
 * Returns: 1 if Upgrade header present and valid
 */
int SocketHTTP1_Parser_is_upgrade(SocketHTTP1_Parser_T parser);

/**
 * SocketHTTP1_Parser_upgrade_protocol - Get requested upgrade protocol
 * Returns: Protocol name (e.g., "websocket", "h2c") or NULL
 */
const char *SocketHTTP1_Parser_upgrade_protocol(SocketHTTP1_Parser_T parser);

/* ============================================================================
 * 100 Continue Handling (RFC 9110 Section 10.1.1)
 * ============================================================================ */

/**
 * SocketHTTP1_Parser_expects_continue - Check for Expect: 100-continue
 */
int SocketHTTP1_Parser_expects_continue(SocketHTTP1_Parser_T parser);

/* ============================================================================
 * Serialization API
 * ============================================================================ */

/**
 * SocketHTTP1_serialize_request - Serialize request to buffer
 * @request: Request to serialize
 * @output: Output buffer
 * @output_size: Buffer size
 * Returns: Bytes written, or -1 on error (buffer too small)
 *
 * Serializes request line and headers. Does NOT serialize body.
 * Automatically adds Host header if missing.
 * Terminates with CRLF CRLF.
 */
ssize_t SocketHTTP1_serialize_request(const SocketHTTP_Request *request,
                                       char *output, size_t output_size);

/**
 * SocketHTTP1_serialize_response - Serialize response to buffer
 */
ssize_t SocketHTTP1_serialize_response(const SocketHTTP_Response *response,
                                        char *output, size_t output_size);

/**
 * SocketHTTP1_serialize_headers - Serialize headers only
 */
ssize_t SocketHTTP1_serialize_headers(SocketHTTP_Headers_T headers,
                                       char *output, size_t output_size);

/* ============================================================================
 * Chunked Encoding
 * ============================================================================ */

/**
 * SocketHTTP1_chunk_encode - Encode data as single chunk
 * @data: Input data
 * @len: Data length
 * @output: Output buffer
 * @output_size: Buffer size
 * Returns: Total bytes written
 *
 * Output format: SIZE\r\nDATA\r\n
 */
ssize_t SocketHTTP1_chunk_encode(const void *data, size_t len,
                                  char *output, size_t output_size);

/**
 * SocketHTTP1_chunk_final - Write final (zero-length) chunk
 * @output: Output buffer
 * @output_size: Buffer size
 * @trailers: Optional trailer headers (NULL for none)
 * Returns: Bytes written
 *
 * Output format: 0\r\n[trailers]\r\n
 */
ssize_t SocketHTTP1_chunk_final(char *output, size_t output_size,
                                 SocketHTTP_Headers_T trailers);

/* ============================================================================
 * Error Handling
 * ============================================================================ */

/**
 * SocketHTTP1_result_string - Get human-readable error description
 */
const char *SocketHTTP1_result_string(SocketHTTP1_Result result);

/**
 * Exception type for parse errors
 */
extern const Except_T SocketHTTP1_ParseError;
```

### - [x] Compression Support ✅ (Optional, via ENABLE_HTTP_COMPRESSION)

```c
/* ============================================================================
 * Content Encoding (RFC 9110 Section 8.4)
 * ============================================================================ */

/**
 * Content decoder for gzip/deflate/br
 */
typedef struct SocketHTTP1_Decoder *SocketHTTP1_Decoder_T;

/**
 * SocketHTTP1_Decoder_new - Create content decoder
 * @coding: Coding type (GZIP, DEFLATE, BR)
 * @arena: Memory arena
 */
SocketHTTP1_Decoder_T SocketHTTP1_Decoder_new(SocketHTTP_Coding coding,
                                               Arena_T arena);

/**
 * SocketHTTP1_Decoder_free - Free decoder
 */
void SocketHTTP1_Decoder_free(SocketHTTP1_Decoder_T *decoder);

/**
 * SocketHTTP1_Decoder_decode - Decode compressed data
 * @decoder: Decoder instance
 * @input: Compressed input
 * @input_len: Input length
 * @consumed: Output - bytes consumed
 * @output: Decompressed output buffer
 * @output_len: Output buffer size
 * @written: Output - bytes written
 * Returns: Result (OK, INCOMPLETE, ERROR)
 */
SocketHTTP1_Result SocketHTTP1_Decoder_decode(SocketHTTP1_Decoder_T decoder,
                                               const unsigned char *input, size_t input_len,
                                               size_t *consumed,
                                               unsigned char *output, size_t output_len,
                                               size_t *written);

/**
 * SocketHTTP1_Decoder_finish - Finalize decoding
 */
SocketHTTP1_Result SocketHTTP1_Decoder_finish(SocketHTTP1_Decoder_T decoder,
                                               unsigned char *output, size_t output_len,
                                               size_t *written);

/**
 * Content encoder
 */
typedef struct SocketHTTP1_Encoder *SocketHTTP1_Encoder_T;

/**
 * Compression level
 */
typedef enum {
    HTTP1_COMPRESS_FAST = 1,
    HTTP1_COMPRESS_DEFAULT = 6,
    HTTP1_COMPRESS_BEST = 9
} SocketHTTP1_CompressLevel;

SocketHTTP1_Encoder_T SocketHTTP1_Encoder_new(SocketHTTP_Coding coding,
                                               SocketHTTP1_CompressLevel level,
                                               Arena_T arena);
void SocketHTTP1_Encoder_free(SocketHTTP1_Encoder_T *encoder);

ssize_t SocketHTTP1_Encoder_encode(SocketHTTP1_Encoder_T encoder,
                                    const unsigned char *input, size_t input_len,
                                    unsigned char *output, size_t output_len,
                                    int flush);

ssize_t SocketHTTP1_Encoder_finish(SocketHTTP1_Encoder_T encoder,
                                    unsigned char *output, size_t output_len);
```

### - [x] Implementation Requirements ✅

#### Request Line Parsing (RFC 9112 Section 3) ✅
- [x] Method SP Request-Target SP HTTP-Version CRLF
- [x] Handle origin-form: /path?query
- [x] Handle absolute-form: http://host/path (for proxies)
- [x] Handle authority-form: host:port (CONNECT only)
- [x] Handle asterisk-form: * (OPTIONS only)
- [x] Reject requests with mismatched forms

#### Status Line Parsing (RFC 9112 Section 4) ✅
- [x] HTTP-Version SP Status-Code SP [Reason-Phrase] CRLF
- [x] Accept empty reason phrase
- [x] Validate status code range (100-599)

#### Header Parsing (RFC 9112 Section 5) ✅
- [x] Field-Name ":" OWS Field-Value OWS CRLF
- [x] Case-insensitive field names
- [x] Handle obsolete line folding (obs-fold) - optional
- [x] Reject bare CR without LF
- [x] Reject NUL in header values
- [x] Handle multiple headers with same name

#### Body Determination (RFC 9112 Section 6) ✅
- [x] HEAD responses have no body
- [x] 1xx, 204, 304 responses have no body
- [x] CONNECT 2xx responses have no body (tunnel)
- [x] Transfer-Encoding takes precedence over Content-Length
- [x] Reject conflicting Content-Length values
- [x] Handle chunked transfer encoding
- [x] Handle until-close for HTTP/1.0

#### Chunked Encoding (RFC 9112 Section 7.1) ✅
- [x] chunk-size [chunk-ext] CRLF chunk-data CRLF
- [x] Last chunk has size 0
- [x] Support trailer headers after last chunk
- [x] Reject disallowed trailer headers (Transfer-Encoding, Content-Length, etc.)

### - [x] Security Requirements ✅

#### Request Smuggling Prevention (CRITICAL) ✅
- [x] Reject requests with both Content-Length and Transfer-Encoding (RFC 9112 Section 6.3)
- [x] In strict mode: reject Transfer-Encoding values other than "chunked"
- [x] Reject multiple Content-Length headers with different values
- [x] Reject Content-Length with invalid characters
- [x] Reject chunk sizes with leading zeros (ambiguous)
- [x] Enforce consistent parsing of chunk size

#### Header Injection Prevention ✅
- [x] Reject CR without LF in header values
- [x] Reject LF without CR in header values
- [x] Reject NUL bytes in headers
- [x] Reject control characters in header names
- [x] Length limit on header names and values

#### Response Splitting Prevention ✅
- [x] Validate header values when serializing
- [x] Reject CR/LF in user-provided header values
- [x] URL-encode untrusted values in Location headers

#### Resource Exhaustion Prevention ✅
- [x] Configurable limits on all sizes
- [x] Timeout on header reception
- [x] Timeout on body reception
- [x] Maximum total message size

### - [x] Tests ✅

- [x] `src/test/test_http1_parser.c` (27 tests)
  - [x] Simple GET request
  - [x] GET with query string
  - [x] POST with Content-Length
  - [x] POST with chunked encoding
  - [x] Multiple chunks
  - [x] Chunked with trailers
  - [x] Keep-alive detection
  - [x] Connection: close
  - [x] HTTP/1.0 behavior
  - [x] HEAD response
  - [x] 204 No Content response
  - [x] 304 Not Modified response
  - [x] 100 Continue handling
  - [x] Upgrade header
  - [x] Invalid method rejection
  - [x] Invalid version rejection
  - [x] Header too large
  - [x] Too many headers
  - [x] Invalid Content-Length
  - [x] Negative Content-Length
  - [x] Smuggling: both CL and TE (reject)
  - [x] Smuggling: multiple CL values (reject)
  - [x] Incremental parsing
  - [x] Request serialization
  - [x] Response serialization
  - [x] Chunk encoding
  - [ ] gzip decompression (optional, requires ENABLE_HTTP_COMPRESSION)
  - [ ] deflate decompression (optional, requires ENABLE_HTTP_COMPRESSION)

### - [x] Fuzzing Harnesses ✅

- [x] `src/fuzz/fuzz_http1_request.c`
- [x] `src/fuzz/fuzz_http1_response.c`
- [x] `src/fuzz/fuzz_http1_chunked.c`
- [x] `src/fuzz/fuzz_http1_headers.c`

### - [x] Build System ✅

- [x] Add HTTP/1.1 sources to `LIB_SOURCES`
- [x] Add zlib dependency for gzip/deflate (optional via ENABLE_HTTP_COMPRESSION)
- [x] Add brotli dependency for br (optional via ENABLE_HTTP_COMPRESSION)
- [x] Add `test_http1_parser` to test executables

### Parser Optimization Note

The HTTP/1.1 parser uses a **table-driven DFA** (Hoehrmann-style) for O(n) parsing with minimal branch misprediction:
- 256-byte character classification table
- State transition tables (~1KB each for request/response)
- Action tables for side-effects
- 2-5x faster than equivalent switch-based implementation

---

## - [x] Phase 5: HPACK Header Compression (RFC 7541) ✅ COMPLETED

Header compression for HTTP/2. Critical for performance and required for HTTP/2 compliance.

**Status**: Completed (December 2025)

### - [x] Files Created ✅

- [x] `include/http/SocketHPACK.h` - Public API
- [x] `include/http/SocketHPACK-private.h` - Internal structures
- [x] `src/http/SocketHPACK.c` - Integer coding, encoder, decoder
- [x] `src/http/SocketHPACK-huffman.c` - Huffman encode/decode
- [x] `src/http/SocketHPACK-table.c` - Static and dynamic tables

### RFC Sections Covered

- RFC 7541 Section 2: Compression Process
- RFC 7541 Section 3: Header Block Decoding
- RFC 7541 Section 4: Dynamic Table Management
- RFC 7541 Section 5: Primitive Type Representations
- RFC 7541 Section 6: Binary Format

### - [x] Configuration ✅

```c
/* HPACK Configuration Limits */

#ifndef SOCKETHPACK_DEFAULT_TABLE_SIZE
#define SOCKETHPACK_DEFAULT_TABLE_SIZE 4096     /* RFC default */
#endif

#ifndef SOCKETHPACK_MAX_TABLE_SIZE
#define SOCKETHPACK_MAX_TABLE_SIZE (64 * 1024)  /* 64KB maximum */
#endif

#ifndef SOCKETHPACK_MAX_HEADER_SIZE
#define SOCKETHPACK_MAX_HEADER_SIZE (8 * 1024)  /* 8KB per header */
#endif

#ifndef SOCKETHPACK_MAX_HEADER_LIST_SIZE
#define SOCKETHPACK_MAX_HEADER_LIST_SIZE (64 * 1024)  /* Total decoded size */
#endif
```

### - [x] API Specification ✅

```c
/* ============================================================================
 * HPACK Header Representation
 * ============================================================================ */

/**
 * HPACK header field
 */
typedef struct {
    const char *name;
    size_t name_len;
    const char *value;
    size_t value_len;
    int never_index;    /* Sensitive - never add to dynamic table */
} SocketHPACK_Header;

/**
 * HPACK result codes
 */
typedef enum {
    HPACK_OK = 0,
    HPACK_INCOMPLETE,           /* Need more data */
    HPACK_ERROR,                /* Generic error */
    HPACK_ERROR_INVALID_INDEX,  /* Index out of range */
    HPACK_ERROR_HUFFMAN,        /* Huffman decoding error */
    HPACK_ERROR_INTEGER,        /* Integer overflow */
    HPACK_ERROR_TABLE_SIZE,     /* Dynamic table size update invalid */
    HPACK_ERROR_HEADER_SIZE,    /* Individual header too large */
    HPACK_ERROR_LIST_SIZE,      /* Total header list too large */
    HPACK_ERROR_BOMB            /* HPACK bomb detected */
} SocketHPACK_Result;

/* ============================================================================
 * Dynamic Table
 * ============================================================================ */

/**
 * HPACK dynamic table
 */
typedef struct SocketHPACK_Table *SocketHPACK_Table_T;

/**
 * SocketHPACK_Table_new - Create dynamic table
 * @max_size: Maximum table size in bytes (32 per entry overhead)
 * @arena: Memory arena
 */
SocketHPACK_Table_T SocketHPACK_Table_new(size_t max_size, Arena_T arena);

/**
 * SocketHPACK_Table_free - Free dynamic table
 */
void SocketHPACK_Table_free(SocketHPACK_Table_T *table);

/**
 * SocketHPACK_Table_set_max_size - Update maximum table size
 * @table: Dynamic table
 * @max_size: New maximum size
 *
 * Evicts entries as needed to fit new size.
 */
void SocketHPACK_Table_set_max_size(SocketHPACK_Table_T table, size_t max_size);

/**
 * SocketHPACK_Table_size - Get current table size in bytes
 */
size_t SocketHPACK_Table_size(SocketHPACK_Table_T table);

/**
 * SocketHPACK_Table_count - Get number of entries
 */
size_t SocketHPACK_Table_count(SocketHPACK_Table_T table);

/* ============================================================================
 * Encoder
 * ============================================================================ */

/**
 * HPACK encoder
 */
typedef struct SocketHPACK_Encoder *SocketHPACK_Encoder_T;

/**
 * Encoder options
 */
typedef struct {
    size_t max_table_size;      /* Maximum dynamic table size */
    int huffman_encode;         /* Use Huffman encoding (default: yes) */
    int use_indexing;           /* Add headers to dynamic table (default: yes) */
} SocketHPACK_EncoderConfig;

/**
 * SocketHPACK_encoder_config_defaults - Initialize encoder config
 */
void SocketHPACK_encoder_config_defaults(SocketHPACK_EncoderConfig *config);

/**
 * SocketHPACK_Encoder_new - Create encoder
 * @config: Configuration (NULL for defaults)
 * @arena: Memory arena
 */
SocketHPACK_Encoder_T SocketHPACK_Encoder_new(const SocketHPACK_EncoderConfig *config,
                                               Arena_T arena);

/**
 * SocketHPACK_Encoder_free - Free encoder
 */
void SocketHPACK_Encoder_free(SocketHPACK_Encoder_T *encoder);

/**
 * SocketHPACK_Encoder_encode - Encode header block
 * @encoder: Encoder instance
 * @headers: Array of headers to encode
 * @count: Number of headers
 * @output: Output buffer
 * @output_size: Buffer size
 * Returns: Bytes written, or -1 on error
 */
ssize_t SocketHPACK_Encoder_encode(SocketHPACK_Encoder_T encoder,
                                    const SocketHPACK_Header *headers, size_t count,
                                    unsigned char *output, size_t output_size);

/**
 * SocketHPACK_Encoder_set_table_size - Signal table size change
 * @encoder: Encoder
 * @max_size: New maximum size
 *
 * Emits dynamic table size update at start of next header block.
 */
void SocketHPACK_Encoder_set_table_size(SocketHPACK_Encoder_T encoder,
                                         size_t max_size);

/**
 * SocketHPACK_Encoder_get_table - Get encoder's dynamic table
 */
SocketHPACK_Table_T SocketHPACK_Encoder_get_table(SocketHPACK_Encoder_T encoder);

/* ============================================================================
 * Decoder
 * ============================================================================ */

/**
 * HPACK decoder
 */
typedef struct SocketHPACK_Decoder *SocketHPACK_Decoder_T;

/**
 * Decoder options
 */
typedef struct {
    size_t max_table_size;          /* Maximum dynamic table size */
    size_t max_header_size;         /* Maximum individual header size */
    size_t max_header_list_size;    /* Maximum total decoded size */
} SocketHPACK_DecoderConfig;

/**
 * SocketHPACK_decoder_config_defaults - Initialize decoder config
 */
void SocketHPACK_decoder_config_defaults(SocketHPACK_DecoderConfig *config);

/**
 * SocketHPACK_Decoder_new - Create decoder
 * @config: Configuration (NULL for defaults)
 * @arena: Memory arena
 */
SocketHPACK_Decoder_T SocketHPACK_Decoder_new(const SocketHPACK_DecoderConfig *config,
                                               Arena_T arena);

/**
 * SocketHPACK_Decoder_free - Free decoder
 */
void SocketHPACK_Decoder_free(SocketHPACK_Decoder_T *decoder);

/**
 * SocketHPACK_Decoder_decode - Decode header block
 * @decoder: Decoder instance
 * @input: Encoded header block
 * @input_len: Block length
 * @headers: Output array for decoded headers
 * @max_headers: Maximum headers to decode
 * @header_count: Output - number of headers decoded
 * @arena: Arena for header string allocation
 * Returns: Result code
 *
 * Must decode complete header block in one call (no streaming).
 */
SocketHPACK_Result SocketHPACK_Decoder_decode(SocketHPACK_Decoder_T decoder,
                                               const unsigned char *input, size_t input_len,
                                               SocketHPACK_Header *headers, size_t max_headers,
                                               size_t *header_count,
                                               Arena_T arena);

/**
 * SocketHPACK_Decoder_set_table_size - Handle SETTINGS table size update
 */
void SocketHPACK_Decoder_set_table_size(SocketHPACK_Decoder_T decoder,
                                         size_t max_size);

/**
 * SocketHPACK_Decoder_get_table - Get decoder's dynamic table
 */
SocketHPACK_Table_T SocketHPACK_Decoder_get_table(SocketHPACK_Decoder_T decoder);

/* ============================================================================
 * Huffman Coding
 * ============================================================================ */

/**
 * SocketHPACK_huffman_encode - Huffman encode string
 * @input: Input string
 * @input_len: Input length
 * @output: Output buffer
 * @output_size: Buffer size
 * Returns: Encoded length, or -1 on error
 */
ssize_t SocketHPACK_huffman_encode(const unsigned char *input, size_t input_len,
                                    unsigned char *output, size_t output_size);

/**
 * SocketHPACK_huffman_decode - Huffman decode string
 * @input: Encoded input
 * @input_len: Input length
 * @output: Output buffer
 * @output_size: Buffer size
 * Returns: Decoded length, or -1 on error
 */
ssize_t SocketHPACK_huffman_decode(const unsigned char *input, size_t input_len,
                                    unsigned char *output, size_t output_size);

/**
 * SocketHPACK_huffman_encoded_size - Calculate encoded size
 * @input: Input string
 * @input_len: Input length
 * Returns: Encoded size in bytes
 */
size_t SocketHPACK_huffman_encoded_size(const unsigned char *input, size_t input_len);

/* ============================================================================
 * Integer Coding (RFC 7541 Section 5.1)
 * ============================================================================ */

/**
 * SocketHPACK_int_encode - Encode integer with prefix
 * @value: Integer value
 * @prefix_bits: Number of prefix bits (1-8)
 * @output: Output buffer
 * @output_size: Buffer size
 * Returns: Bytes written
 */
size_t SocketHPACK_int_encode(uint64_t value, int prefix_bits,
                               unsigned char *output, size_t output_size);

/**
 * SocketHPACK_int_decode - Decode integer with prefix
 * @input: Input buffer
 * @input_len: Input length
 * @prefix_bits: Number of prefix bits
 * @value: Output value
 * @consumed: Output bytes consumed
 * Returns: Result code
 */
SocketHPACK_Result SocketHPACK_int_decode(const unsigned char *input, size_t input_len,
                                           int prefix_bits,
                                           uint64_t *value, size_t *consumed);

/* ============================================================================
 * Error Handling
 * ============================================================================ */

/**
 * SocketHPACK_result_string - Get error description
 */
const char *SocketHPACK_result_string(SocketHPACK_Result result);

extern const Except_T SocketHPACK_Error;
```

### - [x] Static Table (RFC 7541 Appendix A) ✅

The static table has 61 entries (index 1-61):

| Index | Header Name | Header Value |
|-------|-------------|--------------|
| 1 | :authority | |
| 2 | :method | GET |
| 3 | :method | POST |
| 4 | :path | / |
| 5 | :path | /index.html |
| 6 | :scheme | http |
| 7 | :scheme | https |
| 8 | :status | 200 |
| ... | ... | ... |
| 61 | www-authenticate | |

### - [x] Implementation Requirements ✅

#### Integer Representation (RFC 7541 Section 5.1)
- [x] Variable-length integer encoding with prefix
- [x] Support all prefix sizes (1-8 bits)
- [x] Overflow detection for large integers

#### String Representation (RFC 7541 Section 5.2)
- [x] Length-prefixed strings
- [x] Huffman encoding flag (H bit)
- [x] Support both literal and Huffman-encoded strings

#### Huffman Coding (RFC 7541 Appendix B)
- [x] Static Huffman table (256 symbols + EOS)
- [x] Variable-length codes (5-30 bits)
- [x] EOS symbol validation
- [x] Efficient decoding (bit-by-bit with lookup tables)

#### Indexed Header Field (RFC 7541 Section 6.1)
- [x] Single index references static or dynamic table
- [x] Index 0 is invalid

#### Literal Header Field (RFC 7541 Section 6.2)
- [x] With Indexing - add to dynamic table
- [x] Without Indexing - don't add
- [x] Never Indexed - sensitive, never index

#### Dynamic Table (RFC 7541 Section 4)
- [x] FIFO eviction when size exceeded (circular buffer O(1))
- [x] Entry size = name length + value length + 32
- [x] Size updates from SETTINGS
- [x] Must process size update at start of header block

### - [x] Security Requirements ✅

#### HPACK Bomb Prevention
- [x] Limit total decoded header size (max_header_list_size)
- [x] Limit individual header size (max_header_size)
- [x] Limit dynamic table size (max_table_size)
- [x] Detect and reject malicious patterns:
  - [x] Repeated dynamic table updates after headers
  - [x] Validate Huffman padding (max 7 bits of 1s)

### - [x] Tests ✅

- [x] `src/test/test_hpack.c`
  - [x] Static table lookup
  - [x] Dynamic table add/evict
  - [x] Dynamic table size update
  - [x] Integer encoding (all prefix sizes)
  - [x] Integer decoding
  - [x] Integer overflow handling
  - [x] Huffman encoding
  - [x] Huffman decoding
  - [x] Indexed header field
  - [x] Literal with indexing
  - [x] Literal without indexing
  - [x] Literal never indexed
  - [x] RFC 7541 Appendix C examples (C.2.1, C.3)
  - [x] Maximum header size
  - [x] Invalid index detection

### - [x] Fuzzing Harnesses ✅

- [x] `src/fuzz/fuzz_hpack_decode.c`
- [x] `src/fuzz/fuzz_hpack_huffman.c`
- [x] `src/fuzz/fuzz_hpack_integer.c`

### - [x] Build System ✅

- [x] Add HPACK sources to `LIB_SOURCES`
- [x] Add `test_hpack` to test executables
- [x] Add HPACK fuzz harnesses to `FUZZ_SOURCES`

---

## - [x] Phase 6: HTTP/2 Protocol (RFC 9113) ✅ COMPLETED

Complete HTTP/2 implementation with multiplexing, flow control, and server push.

**Status**: Completed (December 2025)

### - [x] Files Created ✅

- [x] `include/http/SocketHTTP2.h`
- [x] `include/http/SocketHTTP2-private.h`
- [x] `src/http/SocketHTTP2-connection.c`
- [x] `src/http/SocketHTTP2-stream.c`
- [x] `src/http/SocketHTTP2-frame.c`
- [x] `src/http/SocketHTTP2-flow.c`
- [x] `src/http/SocketHTTP2-priority.c`

### RFC Sections Covered

- RFC 9113 Section 3: Starting HTTP/2
- RFC 9113 Section 4: HTTP Frames
- RFC 9113 Section 5: Streams and Multiplexing
- RFC 9113 Section 6: Frame Definitions
- RFC 9113 Section 7: Error Handling
- RFC 9113 Section 8: Expressing HTTP Semantics

### - [x] Configuration ✅

```c
/* HTTP/2 Configuration Limits */

/* Connection-level settings (RFC 9113 Section 6.5.2) */
#ifndef SOCKETHTTP2_DEFAULT_HEADER_TABLE_SIZE
#define SOCKETHTTP2_DEFAULT_HEADER_TABLE_SIZE 4096
#endif

#ifndef SOCKETHTTP2_DEFAULT_ENABLE_PUSH
#define SOCKETHTTP2_DEFAULT_ENABLE_PUSH 1           /* Server only */
#endif

#ifndef SOCKETHTTP2_DEFAULT_MAX_CONCURRENT_STREAMS
#define SOCKETHTTP2_DEFAULT_MAX_CONCURRENT_STREAMS 100
#endif

#ifndef SOCKETHTTP2_DEFAULT_INITIAL_WINDOW_SIZE
#define SOCKETHTTP2_DEFAULT_INITIAL_WINDOW_SIZE 65535
#endif

#ifndef SOCKETHTTP2_DEFAULT_MAX_FRAME_SIZE
#define SOCKETHTTP2_DEFAULT_MAX_FRAME_SIZE 16384
#endif

#ifndef SOCKETHTTP2_MAX_MAX_FRAME_SIZE
#define SOCKETHTTP2_MAX_MAX_FRAME_SIZE 16777215     /* 2^24 - 1 */
#endif

#ifndef SOCKETHTTP2_DEFAULT_MAX_HEADER_LIST_SIZE
#define SOCKETHTTP2_DEFAULT_MAX_HEADER_LIST_SIZE (16 * 1024)
#endif

/* Implementation limits */
#ifndef SOCKETHTTP2_MAX_STREAMS
#define SOCKETHTTP2_MAX_STREAMS 1000
#endif

#ifndef SOCKETHTTP2_CONNECTION_WINDOW_SIZE
#define SOCKETHTTP2_CONNECTION_WINDOW_SIZE (1 << 20)  /* 1MB */
#endif
```

### - [x] API Specification ✅

```c
/* ============================================================================
 * Frame Types (RFC 9113 Section 6)
 * ============================================================================ */

typedef enum {
    HTTP2_FRAME_DATA = 0x0,           /* Section 6.1 */
    HTTP2_FRAME_HEADERS = 0x1,        /* Section 6.2 */
    HTTP2_FRAME_PRIORITY = 0x2,       /* Section 6.3 - Deprecated */
    HTTP2_FRAME_RST_STREAM = 0x3,     /* Section 6.4 */
    HTTP2_FRAME_SETTINGS = 0x4,       /* Section 6.5 */
    HTTP2_FRAME_PUSH_PROMISE = 0x5,   /* Section 6.6 */
    HTTP2_FRAME_PING = 0x6,           /* Section 6.7 */
    HTTP2_FRAME_GOAWAY = 0x7,         /* Section 6.8 */
    HTTP2_FRAME_WINDOW_UPDATE = 0x8,  /* Section 6.9 */
    HTTP2_FRAME_CONTINUATION = 0x9    /* Section 6.10 */
} SocketHTTP2_FrameType;

/* Frame flags */
#define HTTP2_FLAG_END_STREAM   0x01  /* DATA, HEADERS */
#define HTTP2_FLAG_END_HEADERS  0x04  /* HEADERS, PUSH_PROMISE, CONTINUATION */
#define HTTP2_FLAG_PADDED       0x08  /* DATA, HEADERS, PUSH_PROMISE */
#define HTTP2_FLAG_PRIORITY     0x20  /* HEADERS */
#define HTTP2_FLAG_ACK          0x01  /* SETTINGS, PING */

/* ============================================================================
 * Error Codes (RFC 9113 Section 7)
 * ============================================================================ */

typedef enum {
    HTTP2_NO_ERROR = 0x0,
    HTTP2_PROTOCOL_ERROR = 0x1,
    HTTP2_INTERNAL_ERROR = 0x2,
    HTTP2_FLOW_CONTROL_ERROR = 0x3,
    HTTP2_SETTINGS_TIMEOUT = 0x4,
    HTTP2_STREAM_CLOSED = 0x5,
    HTTP2_FRAME_SIZE_ERROR = 0x6,
    HTTP2_REFUSED_STREAM = 0x7,
    HTTP2_CANCEL = 0x8,
    HTTP2_COMPRESSION_ERROR = 0x9,
    HTTP2_CONNECT_ERROR = 0xa,
    HTTP2_ENHANCE_YOUR_CALM = 0xb,
    HTTP2_INADEQUATE_SECURITY = 0xc,
    HTTP2_HTTP_1_1_REQUIRED = 0xd
} SocketHTTP2_ErrorCode;

/* ============================================================================
 * Settings Identifiers (RFC 9113 Section 6.5.2)
 * ============================================================================ */

typedef enum {
    HTTP2_SETTINGS_HEADER_TABLE_SIZE = 0x1,
    HTTP2_SETTINGS_ENABLE_PUSH = 0x2,
    HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS = 0x3,
    HTTP2_SETTINGS_INITIAL_WINDOW_SIZE = 0x4,
    HTTP2_SETTINGS_MAX_FRAME_SIZE = 0x5,
    HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE = 0x6
} SocketHTTP2_SettingsId;

/* ============================================================================
 * Stream States (RFC 9113 Section 5.1)
 * ============================================================================ */

typedef enum {
    HTTP2_STREAM_IDLE,
    HTTP2_STREAM_RESERVED_LOCAL,
    HTTP2_STREAM_RESERVED_REMOTE,
    HTTP2_STREAM_OPEN,
    HTTP2_STREAM_HALF_CLOSED_LOCAL,
    HTTP2_STREAM_HALF_CLOSED_REMOTE,
    HTTP2_STREAM_CLOSED
} SocketHTTP2_StreamState;

/* ============================================================================
 * Frame Header
 * ============================================================================ */

/**
 * HTTP/2 frame header (9 bytes)
 */
typedef struct {
    uint32_t length;      /* 24-bit payload length */
    uint8_t type;         /* Frame type */
    uint8_t flags;        /* Frame flags */
    uint32_t stream_id;   /* 31-bit stream ID (R bit reserved) */
} SocketHTTP2_FrameHeader;

#define HTTP2_FRAME_HEADER_SIZE 9

/* ============================================================================
 * Connection Configuration
 * ============================================================================ */

typedef enum {
    HTTP2_ROLE_CLIENT,
    HTTP2_ROLE_SERVER
} SocketHTTP2_Role;

/**
 * HTTP/2 connection configuration
 */
typedef struct {
    SocketHTTP2_Role role;
    
    /* Local settings (we send to peer) */
    uint32_t header_table_size;
    uint32_t enable_push;
    uint32_t max_concurrent_streams;
    uint32_t initial_window_size;
    uint32_t max_frame_size;
    uint32_t max_header_list_size;
    
    /* Connection-level flow control */
    uint32_t connection_window_size;
    
    /* Timeouts */
    int settings_timeout_ms;
    int ping_timeout_ms;
    int idle_timeout_ms;
} SocketHTTP2_Config;

/* ============================================================================
 * Connection
 * ============================================================================ */

typedef struct SocketHTTP2_Conn *SocketHTTP2_Conn_T;

/**
 * SocketHTTP2_config_defaults - Initialize config with defaults
 */
void SocketHTTP2_config_defaults(SocketHTTP2_Config *config,
                                  SocketHTTP2_Role role);

/**
 * SocketHTTP2_Conn_new - Create HTTP/2 connection
 * @socket: Underlying TCP socket (after TLS handshake for h2)
 * @config: Configuration (NULL for defaults)
 * @arena: Memory arena
 */
SocketHTTP2_Conn_T SocketHTTP2_Conn_new(Socket_T socket,
                                         const SocketHTTP2_Config *config,
                                         Arena_T arena);

/**
 * SocketHTTP2_Conn_free - Free connection and all streams
 */
void SocketHTTP2_Conn_free(SocketHTTP2_Conn_T *conn);

/**
 * SocketHTTP2_Conn_handshake - Perform HTTP/2 connection preface
 * @conn: Connection
 * Returns: 0 on success, 1 if in progress, -1 on error
 *
 * Client: Sends "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + SETTINGS
 * Server: Expects preface, sends SETTINGS
 */
int SocketHTTP2_Conn_handshake(SocketHTTP2_Conn_T conn);

/**
 * SocketHTTP2_Conn_process - Process incoming data
 * @conn: Connection
 * @events: Poll events
 * Returns: 0 on success, -1 on error
 */
int SocketHTTP2_Conn_process(SocketHTTP2_Conn_T conn, unsigned events);

/**
 * SocketHTTP2_Conn_flush - Flush pending output
 */
int SocketHTTP2_Conn_flush(SocketHTTP2_Conn_T conn);

/**
 * SocketHTTP2_Conn_socket - Get underlying socket
 */
Socket_T SocketHTTP2_Conn_socket(SocketHTTP2_Conn_T conn);

/**
 * SocketHTTP2_Conn_is_closed - Check if connection closed
 */
int SocketHTTP2_Conn_is_closed(SocketHTTP2_Conn_T conn);

/* ============================================================================
 * Connection Control
 * ============================================================================ */

/**
 * SocketHTTP2_Conn_settings - Send SETTINGS frame
 * @conn: Connection
 * @settings: Array of settings
 * @count: Number of settings
 */
int SocketHTTP2_Conn_settings(SocketHTTP2_Conn_T conn,
                               const struct { uint16_t id; uint32_t value; } *settings,
                               size_t count);

/**
 * SocketHTTP2_Conn_get_setting - Get current setting value (peer's)
 */
uint32_t SocketHTTP2_Conn_get_setting(SocketHTTP2_Conn_T conn,
                                       SocketHTTP2_SettingsId id);

/**
 * SocketHTTP2_Conn_get_local_setting - Get our setting value
 */
uint32_t SocketHTTP2_Conn_get_local_setting(SocketHTTP2_Conn_T conn,
                                             SocketHTTP2_SettingsId id);

/**
 * SocketHTTP2_Conn_ping - Send PING frame
 * @conn: Connection
 * @opaque: 8 bytes opaque data (NULL for auto-generate)
 */
int SocketHTTP2_Conn_ping(SocketHTTP2_Conn_T conn,
                           const unsigned char opaque[8]);

/**
 * SocketHTTP2_Conn_goaway - Send GOAWAY frame
 * @conn: Connection
 * @error_code: Error code
 * @debug_data: Optional debug data (NULL for none)
 * @debug_len: Debug data length
 *
 * Initiates graceful shutdown. No new streams will be accepted.
 */
int SocketHTTP2_Conn_goaway(SocketHTTP2_Conn_T conn,
                             SocketHTTP2_ErrorCode error_code,
                             const void *debug_data, size_t debug_len);

/**
 * SocketHTTP2_Conn_last_stream_id - Get last processed stream ID
 */
uint32_t SocketHTTP2_Conn_last_stream_id(SocketHTTP2_Conn_T conn);

/* ============================================================================
 * Flow Control
 * ============================================================================ */

/**
 * SocketHTTP2_Conn_window_update - Update connection-level window
 * @conn: Connection
 * @increment: Window size increment
 */
int SocketHTTP2_Conn_window_update(SocketHTTP2_Conn_T conn,
                                    uint32_t increment);

/**
 * SocketHTTP2_Conn_send_window - Get available send window
 */
int32_t SocketHTTP2_Conn_send_window(SocketHTTP2_Conn_T conn);

/**
 * SocketHTTP2_Conn_recv_window - Get receive window
 */
int32_t SocketHTTP2_Conn_recv_window(SocketHTTP2_Conn_T conn);

/* ============================================================================
 * Stream
 * ============================================================================ */

typedef struct SocketHTTP2_Stream *SocketHTTP2_Stream_T;

/**
 * SocketHTTP2_Stream_new - Create new stream
 * @conn: Parent connection
 * Returns: New stream with auto-assigned ID
 *
 * Client streams use odd IDs (1, 3, 5, ...)
 * Server streams (push) use even IDs (2, 4, 6, ...)
 */
SocketHTTP2_Stream_T SocketHTTP2_Stream_new(SocketHTTP2_Conn_T conn);

/**
 * SocketHTTP2_Stream_id - Get stream ID
 */
uint32_t SocketHTTP2_Stream_id(SocketHTTP2_Stream_T stream);

/**
 * SocketHTTP2_Stream_state - Get stream state
 */
SocketHTTP2_StreamState SocketHTTP2_Stream_state(SocketHTTP2_Stream_T stream);

/**
 * SocketHTTP2_Stream_close - Close stream
 * @stream: Stream to close
 * @error_code: Error code (HTTP2_NO_ERROR for normal close)
 */
void SocketHTTP2_Stream_close(SocketHTTP2_Stream_T stream,
                               SocketHTTP2_ErrorCode error_code);

/* ============================================================================
 * Sending (Client/Server)
 * ============================================================================ */

/**
 * SocketHTTP2_Stream_send_headers - Send HEADERS frame
 * @stream: Stream
 * @headers: Header array (includes pseudo-headers)
 * @header_count: Number of headers
 * @end_stream: Set END_STREAM flag (no body follows)
 * Returns: 0 on success, -1 on error
 *
 * Pseudo-headers for requests: :method, :scheme, :authority, :path
 * Pseudo-headers for responses: :status
 */
int SocketHTTP2_Stream_send_headers(SocketHTTP2_Stream_T stream,
                                     const SocketHPACK_Header *headers,
                                     size_t header_count,
                                     int end_stream);

/**
 * SocketHTTP2_Stream_send_request - Send request (convenience)
 * @stream: Stream
 * @request: HTTP request
 * @end_stream: No body follows
 */
int SocketHTTP2_Stream_send_request(SocketHTTP2_Stream_T stream,
                                     const SocketHTTP_Request *request,
                                     int end_stream);

/**
 * SocketHTTP2_Stream_send_response - Send response (convenience)
 */
int SocketHTTP2_Stream_send_response(SocketHTTP2_Stream_T stream,
                                      const SocketHTTP_Response *response,
                                      int end_stream);

/**
 * SocketHTTP2_Stream_send_data - Send DATA frame
 * @stream: Stream
 * @data: Payload data
 * @len: Data length
 * @end_stream: Set END_STREAM flag
 * Returns: Bytes accepted (may be less due to flow control)
 *
 * If flow control limits sending, returns amount accepted.
 * Caller should retry with remainder after window update.
 */
ssize_t SocketHTTP2_Stream_send_data(SocketHTTP2_Stream_T stream,
                                      const void *data, size_t len,
                                      int end_stream);

/**
 * SocketHTTP2_Stream_send_trailers - Send trailer headers
 * @stream: Stream
 * @trailers: Trailer header array
 * @count: Number of trailers
 */
int SocketHTTP2_Stream_send_trailers(SocketHTTP2_Stream_T stream,
                                      const SocketHPACK_Header *trailers,
                                      size_t count);

/* ============================================================================
 * Receiving
 * ============================================================================ */

/**
 * SocketHTTP2_Stream_recv_headers - Check for received headers
 * @stream: Stream
 * @headers: Output header array
 * @max_headers: Maximum headers to receive
 * @header_count: Output - number of headers
 * @end_stream: Output - END_STREAM was set
 * Returns: 1 if headers available, 0 if not, -1 on error
 */
int SocketHTTP2_Stream_recv_headers(SocketHTTP2_Stream_T stream,
                                     SocketHPACK_Header *headers,
                                     size_t max_headers,
                                     size_t *header_count,
                                     int *end_stream);

/**
 * SocketHTTP2_Stream_recv_data - Receive DATA
 * @stream: Stream
 * @buf: Output buffer
 * @len: Buffer size
 * @end_stream: Output - END_STREAM was set
 * Returns: Bytes received, 0 if would block, -1 on error
 */
ssize_t SocketHTTP2_Stream_recv_data(SocketHTTP2_Stream_T stream,
                                      void *buf, size_t len,
                                      int *end_stream);

/**
 * SocketHTTP2_Stream_recv_trailers - Receive trailer headers
 */
int SocketHTTP2_Stream_recv_trailers(SocketHTTP2_Stream_T stream,
                                      SocketHPACK_Header *trailers,
                                      size_t max_trailers,
                                      size_t *trailer_count);

/* ============================================================================
 * Stream Flow Control
 * ============================================================================ */

/**
 * SocketHTTP2_Stream_window_update - Update stream window
 */
int SocketHTTP2_Stream_window_update(SocketHTTP2_Stream_T stream,
                                      uint32_t increment);

/**
 * SocketHTTP2_Stream_send_window - Get stream send window
 */
int32_t SocketHTTP2_Stream_send_window(SocketHTTP2_Stream_T stream);

/**
 * SocketHTTP2_Stream_recv_window - Get stream receive window
 */
int32_t SocketHTTP2_Stream_recv_window(SocketHTTP2_Stream_T stream);

/* ============================================================================
 * Server Push (RFC 9113 Section 8.4)
 * ============================================================================ */

/**
 * SocketHTTP2_Stream_push_promise - Send PUSH_PROMISE (server only)
 * @stream: Parent stream
 * @request_headers: Pushed request headers
 * @header_count: Number of headers
 * Returns: New reserved stream for pushing response
 */
SocketHTTP2_Stream_T SocketHTTP2_Stream_push_promise(
    SocketHTTP2_Stream_T stream,
    const SocketHPACK_Header *request_headers,
    size_t header_count);

/* ============================================================================
 * Callbacks
 * ============================================================================ */

/**
 * Stream event callback
 */
typedef void (*SocketHTTP2_StreamCallback)(
    SocketHTTP2_Conn_T conn,
    SocketHTTP2_Stream_T stream,
    int event,
    void *userdata);

/* Event types */
#define HTTP2_EVENT_STREAM_START      1   /* New stream started */
#define HTTP2_EVENT_HEADERS_RECEIVED  2   /* Headers ready */
#define HTTP2_EVENT_DATA_RECEIVED     3   /* Data available */
#define HTTP2_EVENT_TRAILERS_RECEIVED 4   /* Trailers ready */
#define HTTP2_EVENT_STREAM_END        5   /* Stream ended normally */
#define HTTP2_EVENT_STREAM_RESET      6   /* Stream reset by peer */
#define HTTP2_EVENT_PUSH_PROMISE      7   /* Push promise received */
#define HTTP2_EVENT_WINDOW_UPDATE     8   /* Window increased */

/**
 * SocketHTTP2_Conn_set_callback - Set stream event callback
 */
void SocketHTTP2_Conn_set_callback(SocketHTTP2_Conn_T conn,
                                    SocketHTTP2_StreamCallback callback,
                                    void *userdata);

/**
 * Connection event callback
 */
typedef void (*SocketHTTP2_ConnCallback)(
    SocketHTTP2_Conn_T conn,
    int event,
    void *userdata);

#define HTTP2_EVENT_SETTINGS_ACK      20  /* SETTINGS acknowledged */
#define HTTP2_EVENT_PING_ACK          21  /* PING response received */
#define HTTP2_EVENT_GOAWAY_RECEIVED   22  /* GOAWAY received */
#define HTTP2_EVENT_CONNECTION_ERROR  23  /* Connection error */

/**
 * SocketHTTP2_Conn_set_conn_callback - Set connection callback
 */
void SocketHTTP2_Conn_set_conn_callback(SocketHTTP2_Conn_T conn,
                                         SocketHTTP2_ConnCallback callback,
                                         void *userdata);

/* ============================================================================
 * h2c Upgrade (Cleartext HTTP/2)
 * ============================================================================ */

/**
 * SocketHTTP2_Conn_upgrade_client - Upgrade from HTTP/1.1 (client)
 * @socket: Socket after sending upgrade request
 * @settings_payload: Base64-decoded HTTP2-Settings header value
 * @settings_len: Length of settings payload
 * Returns: HTTP/2 connection
 */
SocketHTTP2_Conn_T SocketHTTP2_Conn_upgrade_client(
    Socket_T socket,
    const unsigned char *settings_payload,
    size_t settings_len,
    Arena_T arena);

/**
 * SocketHTTP2_Conn_upgrade_server - Upgrade from HTTP/1.1 (server)
 * @socket: Socket after receiving upgrade request
 * @initial_request: The HTTP/1.1 request that triggered upgrade
 * @settings_payload: Decoded HTTP2-Settings from client
 * @settings_len: Length of settings
 * Returns: HTTP/2 connection with stream 1 pre-created
 */
SocketHTTP2_Conn_T SocketHTTP2_Conn_upgrade_server(
    Socket_T socket,
    const SocketHTTP_Request *initial_request,
    const unsigned char *settings_payload,
    size_t settings_len,
    Arena_T arena);

/* ============================================================================
 * Error Handling
 * ============================================================================ */

/**
 * SocketHTTP2_error_string - Get error code description
 */
const char *SocketHTTP2_error_string(SocketHTTP2_ErrorCode code);

extern const Except_T SocketHTTP2_ProtocolError;
extern const Except_T SocketHTTP2_StreamError;
extern const Except_T SocketHTTP2_FlowControlError;
```

### - [x] Implementation Requirements ✅

#### Connection Preface (RFC 9113 Section 3.4) ✅
- [x] Client sends: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" (24 bytes magic)
- [x] Followed by SETTINGS frame
- [x] Server responds with SETTINGS frame
- [x] Both must acknowledge with SETTINGS ACK

#### Frame Processing (RFC 9113 Section 4) ✅
- [x] 9-byte frame header parsing
- [x] Validate frame length against SETTINGS_MAX_FRAME_SIZE
- [x] Validate stream ID rules per frame type
- [x] Handle unknown frame types gracefully (ignore)
- [x] Handle padding correctly

#### Stream State Machine (RFC 9113 Section 5.1) ✅
- [x] Implement all 7 states
- [x] Validate transitions
- [x] Track open streams count
- [x] Enforce MAX_CONCURRENT_STREAMS
- [x] Handle stream ID exhaustion

#### Flow Control (RFC 9113 Section 5.2) ✅
- [x] Connection-level window
- [x] Per-stream windows
- [x] Window update processing
- [x] Prevent window overflow (error)
- [x] Automatic window updates

#### HPACK Integration ✅
- [x] Use separate encoder/decoder per connection
- [x] Handle SETTINGS_HEADER_TABLE_SIZE updates
- [x] Compression error handling (COMPRESSION_ERROR)

#### CONTINUATION Frames (RFC 9113 Section 6.10) ✅
- [x] Support headers spanning multiple frames
- [x] CONTINUATION must immediately follow HEADERS/PUSH_PROMISE
- [x] END_HEADERS flag processing

### - [x] Security Requirements ✅

#### Protocol-Level Security ✅
- [x] Require TLS for h2 (ALPN "h2")
- [x] Allow cleartext for h2c only with upgrade
- [x] Validate all frame types
- [x] Validate all flags
- [x] Stream ID validation

#### Resource Exhaustion Prevention ✅
- [x] Limit concurrent streams
- [x] Limit header list size
- [x] SETTINGS_TIMEOUT for acknowledgment
- [x] Idle connection timeout
- [x] ENHANCE_YOUR_CALM for abuse

#### Flow Control Attacks ✅
- [x] Prevent window overflow
- [x] Detect zero-window attacks
- [x] Connection-level limits

### - [x] Tests ✅

- [x] `src/test/test_http2.c`
  - [x] Connection preface (client/server)
  - [x] SETTINGS exchange
  - [x] SETTINGS ACK
  - [x] Simple request/response
  - [x] Multiple concurrent streams
  - [x] Stream state transitions
  - [x] Flow control
  - [x] Window updates
  - [x] PING/PONG
  - [x] GOAWAY
  - [x] RST_STREAM
  - [x] CONTINUATION frames
  - [x] Server push
  - [x] h2c upgrade
  - [x] Error handling
  - [x] Max concurrent streams
  - [x] Header compression

### - [x] Fuzzing Harnesses ✅

- [x] `src/fuzz/fuzz_http2_frames.c`
- [x] `src/fuzz/fuzz_http2_headers.c`
- [x] `src/fuzz/fuzz_http2_settings.c`

### - [x] Build System ✅

- [x] Add HTTP/2 sources to `LIB_SOURCES`
- [x] Add `test_http2` to test executables

---

## - [ ] Phase 7: HTTP Client and Server APIs

High-level APIs abstracting HTTP/1.1 and HTTP/2, with connection pooling,
authentication, cookies, and compression.

### - [ ] Files to Create

- [ ] `include/http/SocketHTTPClient.h`
- [ ] `include/http/SocketHTTPServer.h`
- [ ] `src/http/SocketHTTPClient.c`
- [ ] `src/http/SocketHTTPClient-pool.c`
- [ ] `src/http/SocketHTTPClient-auth.c`
- [ ] `src/http/SocketHTTPClient-cookie.c`
- [ ] `src/http/SocketHTTPServer.c`

### - [ ] API Specification - Client

```c
/* ============================================================================
 * HTTP Client Configuration
 * ============================================================================ */

/**
 * Client configuration
 */
typedef struct {
    /* Protocol */
    SocketHTTP_Version max_version;     /* Max HTTP version (default: HTTP/2) */
    int allow_http2_cleartext;          /* Allow h2c upgrade (default: no) */
    
    /* Connection pooling */
    int enable_connection_pool;         /* Enable pooling (default: yes) */
    size_t max_connections_per_host;    /* Per-host limit (default: 6) */
    size_t max_total_connections;       /* Total limit (default: 100) */
    int idle_timeout_ms;                /* Idle connection timeout */
    
    /* Timeouts */
    int connect_timeout_ms;             /* Connection timeout */
    int request_timeout_ms;             /* Request timeout */
    int dns_timeout_ms;                 /* DNS resolution timeout */
    
    /* Redirects */
    int follow_redirects;               /* Max redirects (0 = disabled) */
    int redirect_on_post;               /* Follow redirects for POST */
    
    /* Compression */
    int accept_encoding;                /* Bitmask: GZIP | DEFLATE | BR */
    int auto_decompress;                /* Auto-decompress responses */
    
    /* TLS */
    SocketTLSContext_T tls_context;     /* Custom TLS context (NULL for default) */
    int verify_ssl;                     /* Verify certificates (default: yes) */
    
    /* Proxy */
    SocketProxy_Config *proxy;          /* Default proxy (NULL for none) */
    
    /* User agent */
    const char *user_agent;             /* User-Agent header */
    
    /* Limits */
    size_t max_response_size;           /* Max response body (0 = unlimited) */
} SocketHTTPClient_Config;

typedef struct SocketHTTPClient *SocketHTTPClient_T;

/* ============================================================================
 * Client Lifecycle
 * ============================================================================ */

void SocketHTTPClient_config_defaults(SocketHTTPClient_Config *config);
SocketHTTPClient_T SocketHTTPClient_new(const SocketHTTPClient_Config *config);
void SocketHTTPClient_free(SocketHTTPClient_T *client);

/* ============================================================================
 * Simple Synchronous API
 * ============================================================================ */

/**
 * HTTP response (owned by caller)
 */
typedef struct {
    int status_code;
    SocketHTTP_Headers_T headers;
    void *body;
    size_t body_len;
    SocketHTTP_Version version;
    Arena_T arena;  /* For cleanup */
} SocketHTTPClient_Response;

/**
 * SocketHTTPClient_get - Perform GET request
 * @client: Client instance
 * @url: Full URL
 * @response: Output response (caller owns)
 * Returns: 0 on success, -1 on error
 */
int SocketHTTPClient_get(SocketHTTPClient_T client,
                          const char *url,
                          SocketHTTPClient_Response *response);

/**
 * SocketHTTPClient_head - Perform HEAD request
 */
int SocketHTTPClient_head(SocketHTTPClient_T client,
                           const char *url,
                           SocketHTTPClient_Response *response);

/**
 * SocketHTTPClient_post - Perform POST request
 * @client: Client
 * @url: Full URL
 * @content_type: Content-Type header value
 * @body: Request body
 * @body_len: Body length
 * @response: Output response
 */
int SocketHTTPClient_post(SocketHTTPClient_T client,
                           const char *url,
                           const char *content_type,
                           const void *body, size_t body_len,
                           SocketHTTPClient_Response *response);

/**
 * SocketHTTPClient_put - Perform PUT request
 */
int SocketHTTPClient_put(SocketHTTPClient_T client,
                          const char *url,
                          const char *content_type,
                          const void *body, size_t body_len,
                          SocketHTTPClient_Response *response);

/**
 * SocketHTTPClient_delete - Perform DELETE request
 */
int SocketHTTPClient_delete(SocketHTTPClient_T client,
                             const char *url,
                             SocketHTTPClient_Response *response);

/**
 * SocketHTTPClient_Response_free - Free response
 */
void SocketHTTPClient_Response_free(SocketHTTPClient_Response *response);

/* ============================================================================
 * Custom Request API
 * ============================================================================ */

/**
 * Request builder
 */
typedef struct SocketHTTPClient_Request *SocketHTTPClient_Request_T;

SocketHTTPClient_Request_T SocketHTTPClient_Request_new(
    SocketHTTPClient_T client,
    SocketHTTP_Method method,
    const char *url);

void SocketHTTPClient_Request_free(SocketHTTPClient_Request_T *req);

/* Request configuration */
int SocketHTTPClient_Request_header(SocketHTTPClient_Request_T req,
                                     const char *name, const char *value);
int SocketHTTPClient_Request_body(SocketHTTPClient_Request_T req,
                                   const void *data, size_t len);
int SocketHTTPClient_Request_body_stream(SocketHTTPClient_Request_T req,
                                          ssize_t (*read_cb)(void *buf, size_t len, void *userdata),
                                          void *userdata);
void SocketHTTPClient_Request_timeout(SocketHTTPClient_Request_T req, int ms);
void SocketHTTPClient_Request_proxy(SocketHTTPClient_Request_T req,
                                     const SocketProxy_Config *proxy);

/* Execute request */
int SocketHTTPClient_Request_execute(SocketHTTPClient_Request_T req,
                                      SocketHTTPClient_Response *response);

/* ============================================================================
 * Asynchronous API
 * ============================================================================ */

typedef struct SocketHTTPClient_AsyncRequest *SocketHTTPClient_AsyncRequest_T;

/**
 * Async completion callback
 */
typedef void (*SocketHTTPClient_Callback)(
    SocketHTTPClient_AsyncRequest_T req,
    SocketHTTPClient_Response *response,
    int error,
    void *userdata);

/**
 * SocketHTTPClient_get_async - Start async GET
 */
SocketHTTPClient_AsyncRequest_T SocketHTTPClient_get_async(
    SocketHTTPClient_T client,
    const char *url,
    SocketHTTPClient_Callback callback,
    void *userdata);

/**
 * SocketHTTPClient_post_async - Start async POST
 */
SocketHTTPClient_AsyncRequest_T SocketHTTPClient_post_async(
    SocketHTTPClient_T client,
    const char *url,
    const char *content_type,
    const void *body, size_t body_len,
    SocketHTTPClient_Callback callback,
    void *userdata);

/**
 * SocketHTTPClient_Request_async - Start async custom request
 */
SocketHTTPClient_AsyncRequest_T SocketHTTPClient_Request_async(
    SocketHTTPClient_Request_T req,
    SocketHTTPClient_Callback callback,
    void *userdata);

/**
 * SocketHTTPClient_AsyncRequest_cancel - Cancel async request
 */
void SocketHTTPClient_AsyncRequest_cancel(SocketHTTPClient_AsyncRequest_T req);

/**
 * SocketHTTPClient_process - Process async requests
 * @client: Client
 * @timeout_ms: Poll timeout
 * Returns: Number of completed requests
 *
 * Call in event loop to process pending async requests.
 */
int SocketHTTPClient_process(SocketHTTPClient_T client, int timeout_ms);

/* ============================================================================
 * Cookie Jar (RFC 6265)
 * ============================================================================ */

typedef struct SocketHTTPClient_CookieJar *SocketHTTPClient_CookieJar_T;

/**
 * Cookie attributes
 */
typedef struct {
    const char *name;
    const char *value;
    const char *domain;
    const char *path;
    time_t expires;
    int secure;
    int http_only;
    int same_site;  /* 0=None, 1=Lax, 2=Strict */
} SocketHTTPClient_Cookie;

SocketHTTPClient_CookieJar_T SocketHTTPClient_CookieJar_new(void);
void SocketHTTPClient_CookieJar_free(SocketHTTPClient_CookieJar_T *jar);

/* Associate jar with client */
void SocketHTTPClient_set_cookie_jar(SocketHTTPClient_T client,
                                      SocketHTTPClient_CookieJar_T jar);
SocketHTTPClient_CookieJar_T SocketHTTPClient_get_cookie_jar(
    SocketHTTPClient_T client);

/* Cookie operations */
int SocketHTTPClient_CookieJar_set(SocketHTTPClient_CookieJar_T jar,
                                    const SocketHTTPClient_Cookie *cookie);
const SocketHTTPClient_Cookie *SocketHTTPClient_CookieJar_get(
    SocketHTTPClient_CookieJar_T jar,
    const char *domain, const char *path, const char *name);
void SocketHTTPClient_CookieJar_clear(SocketHTTPClient_CookieJar_T jar);
void SocketHTTPClient_CookieJar_clear_expired(SocketHTTPClient_CookieJar_T jar);

/* Persistence */
int SocketHTTPClient_CookieJar_load(SocketHTTPClient_CookieJar_T jar,
                                     const char *filename);
int SocketHTTPClient_CookieJar_save(SocketHTTPClient_CookieJar_T jar,
                                     const char *filename);

/* ============================================================================
 * Authentication (RFC 7617, RFC 7616, RFC 6750)
 * ============================================================================ */

typedef enum {
    HTTP_AUTH_NONE,
    HTTP_AUTH_BASIC,        /* RFC 7617 */
    HTTP_AUTH_DIGEST,       /* RFC 7616 */
    HTTP_AUTH_BEARER,       /* RFC 6750 */
    HTTP_AUTH_NTLM,         /* Microsoft NTLM */
    HTTP_AUTH_NEGOTIATE     /* SPNEGO/Kerberos */
} SocketHTTPClient_AuthType;

/**
 * Authentication credentials
 */
typedef struct {
    SocketHTTPClient_AuthType type;
    const char *username;       /* Basic, Digest, NTLM */
    const char *password;       /* Basic, Digest, NTLM */
    const char *token;          /* Bearer */
    const char *realm;          /* Optional realm filter */
} SocketHTTPClient_Auth;

/**
 * SocketHTTPClient_set_auth - Set default authentication
 */
void SocketHTTPClient_set_auth(SocketHTTPClient_T client,
                                const SocketHTTPClient_Auth *auth);

/**
 * SocketHTTPClient_Request_auth - Set per-request auth
 */
void SocketHTTPClient_Request_auth(SocketHTTPClient_Request_T req,
                                    const SocketHTTPClient_Auth *auth);

/* ============================================================================
 * Connection Pool Management
 * ============================================================================ */

/**
 * Pool statistics
 */
typedef struct {
    size_t active_connections;
    size_t idle_connections;
    size_t total_requests;
    size_t reused_connections;
} SocketHTTPClient_PoolStats;

void SocketHTTPClient_pool_stats(SocketHTTPClient_T client,
                                  SocketHTTPClient_PoolStats *stats);
void SocketHTTPClient_pool_clear(SocketHTTPClient_T client);

/* ============================================================================
 * Error Information
 * ============================================================================ */

typedef enum {
    HTTP_CLIENT_OK = 0,
    HTTP_CLIENT_ERROR_DNS,
    HTTP_CLIENT_ERROR_CONNECT,
    HTTP_CLIENT_ERROR_TLS,
    HTTP_CLIENT_ERROR_TIMEOUT,
    HTTP_CLIENT_ERROR_PROTOCOL,
    HTTP_CLIENT_ERROR_TOO_MANY_REDIRECTS,
    HTTP_CLIENT_ERROR_RESPONSE_TOO_LARGE,
    HTTP_CLIENT_ERROR_CANCELLED
} SocketHTTPClient_Error;

SocketHTTPClient_Error SocketHTTPClient_last_error(SocketHTTPClient_T client);
const char *SocketHTTPClient_error_string(SocketHTTPClient_Error error);
```

### - [ ] API Specification - Server

```c
/* ============================================================================
 * HTTP Server Configuration
 * ============================================================================ */

typedef struct {
    /* Listeners */
    int port;
    const char *bind_address;           /* NULL for all interfaces */
    int backlog;                        /* Listen backlog */
    
    /* TLS */
    SocketTLSContext_T tls_context;     /* NULL for HTTP only */
    
    /* Protocol */
    SocketHTTP_Version max_version;     /* Max HTTP version */
    int enable_h2c_upgrade;             /* Allow HTTP/2 upgrade */
    
    /* Limits */
    size_t max_header_size;
    size_t max_body_size;
    int request_timeout_ms;
    int keepalive_timeout_ms;
    size_t max_connections;
    size_t max_requests_per_connection;
} SocketHTTPServer_Config;

typedef struct SocketHTTPServer *SocketHTTPServer_T;

/* ============================================================================
 * Server Lifecycle
 * ============================================================================ */

void SocketHTTPServer_config_defaults(SocketHTTPServer_Config *config);
SocketHTTPServer_T SocketHTTPServer_new(const SocketHTTPServer_Config *config);
void SocketHTTPServer_free(SocketHTTPServer_T *server);

int SocketHTTPServer_start(SocketHTTPServer_T server);
void SocketHTTPServer_stop(SocketHTTPServer_T server);

/* ============================================================================
 * Request Handler
 * ============================================================================ */

/**
 * Server request context
 */
typedef struct SocketHTTPServer_Request *SocketHTTPServer_Request_T;

/**
 * Request handler callback
 */
typedef void (*SocketHTTPServer_Handler)(
    SocketHTTPServer_Request_T req,
    void *userdata);

/**
 * SocketHTTPServer_set_handler - Set request handler
 */
void SocketHTTPServer_set_handler(SocketHTTPServer_T server,
                                   SocketHTTPServer_Handler handler,
                                   void *userdata);

/* Request accessors */
SocketHTTP_Method SocketHTTPServer_Request_method(SocketHTTPServer_Request_T req);
const char *SocketHTTPServer_Request_path(SocketHTTPServer_Request_T req);
const char *SocketHTTPServer_Request_query(SocketHTTPServer_Request_T req);
SocketHTTP_Headers_T SocketHTTPServer_Request_headers(SocketHTTPServer_Request_T req);
const void *SocketHTTPServer_Request_body(SocketHTTPServer_Request_T req);
size_t SocketHTTPServer_Request_body_len(SocketHTTPServer_Request_T req);
const char *SocketHTTPServer_Request_client_addr(SocketHTTPServer_Request_T req);
SocketHTTP_Version SocketHTTPServer_Request_version(SocketHTTPServer_Request_T req);

/* Response building */
void SocketHTTPServer_Request_status(SocketHTTPServer_Request_T req, int code);
void SocketHTTPServer_Request_header(SocketHTTPServer_Request_T req,
                                      const char *name, const char *value);
void SocketHTTPServer_Request_body_data(SocketHTTPServer_Request_T req,
                                         const void *data, size_t len);
void SocketHTTPServer_Request_body_string(SocketHTTPServer_Request_T req,
                                           const char *str);
void SocketHTTPServer_Request_finish(SocketHTTPServer_Request_T req);

/* WebSocket upgrade */
int SocketHTTPServer_Request_is_websocket(SocketHTTPServer_Request_T req);
SocketWS_T SocketHTTPServer_Request_upgrade_websocket(SocketHTTPServer_Request_T req);

/* ============================================================================
 * Event Loop Integration
 * ============================================================================ */

int SocketHTTPServer_fd(SocketHTTPServer_T server);
int SocketHTTPServer_process(SocketHTTPServer_T server, int timeout_ms);
```

### - [ ] Implementation Requirements

- [ ] Connection pool with per-host limits
- [ ] Automatic HTTP/2 negotiation via ALPN
- [ ] HTTP/1.1 upgrade to HTTP/2 (h2c)
- [ ] Automatic retry on connection failure
- [ ] Redirect following with loop detection
- [ ] Cookie handling per RFC 6265
- [ ] Content-Encoding handling (gzip, deflate, br)
- [ ] Chunked transfer encoding
- [ ] Basic authentication (RFC 7617)
- [ ] Digest authentication (RFC 7616)
- [ ] Bearer token authentication (RFC 6750)

### - [ ] Tests

- [ ] `src/test/test_http_client.c`
  - [ ] Simple GET
  - [ ] POST with body
  - [ ] Custom headers
  - [ ] Timeouts
  - [ ] Redirects
  - [ ] Cookies
  - [ ] Authentication
  - [ ] Compression
  - [ ] Connection reuse
  - [ ] HTTP/2 negotiation
  - [ ] Error handling

### - [ ] Build System

- [ ] Add client/server sources to `LIB_SOURCES`
- [ ] Add `test_http_client` to test executables

---

## - [ ] Phase 8: Proxy Support

HTTP CONNECT and SOCKS proxy protocols for tunneling connections.

### - [ ] Files to Create

- [ ] `include/socket/SocketProxy.h`
- [ ] `include/socket/SocketProxy-private.h`
- [ ] `src/socket/SocketProxy.c`
- [ ] `src/socket/SocketProxy-http.c`
- [ ] `src/socket/SocketProxy-socks4.c`
- [ ] `src/socket/SocketProxy-socks5.c`

### RFC Coverage

- RFC 7231 Section 4.3.6: CONNECT method
- RFC 1928: SOCKS Protocol Version 5
- RFC 1929: Username/Password Authentication for SOCKS V5
- SOCKS4/4a: De-facto standard (no RFC)

### - [ ] API Specification

```c
/* ============================================================================
 * Proxy Types
 * ============================================================================ */

typedef enum {
    SOCKET_PROXY_NONE = 0,
    SOCKET_PROXY_HTTP,          /* HTTP CONNECT */
    SOCKET_PROXY_HTTPS,         /* HTTPS CONNECT (TLS to proxy) */
    SOCKET_PROXY_SOCKS4,        /* SOCKS4 */
    SOCKET_PROXY_SOCKS4A,       /* SOCKS4a (DNS at proxy) */
    SOCKET_PROXY_SOCKS5,        /* SOCKS5 */
    SOCKET_PROXY_SOCKS5H        /* SOCKS5 with DNS at proxy */
} SocketProxyType;

/* ============================================================================
 * Proxy Configuration
 * ============================================================================ */

typedef struct {
    SocketProxyType type;
    
    /* Proxy server */
    const char *host;
    int port;
    
    /* Authentication */
    const char *username;
    const char *password;
    
    /* HTTP CONNECT specific */
    SocketHTTP_Headers_T extra_headers;  /* Additional headers */
    
    /* Timeouts */
    int connect_timeout_ms;     /* Timeout connecting to proxy */
    int handshake_timeout_ms;   /* Timeout for proxy handshake */
} SocketProxy_Config;

/* ============================================================================
 * Proxy Results
 * ============================================================================ */

typedef enum {
    PROXY_OK = 0,
    PROXY_ERROR,
    PROXY_ERROR_CONNECT,            /* Failed to connect to proxy */
    PROXY_ERROR_AUTH_REQUIRED,      /* Proxy requires authentication */
    PROXY_ERROR_AUTH_FAILED,        /* Authentication rejected */
    PROXY_ERROR_FORBIDDEN,          /* Proxy refused connection */
    PROXY_ERROR_HOST_UNREACHABLE,   /* Target unreachable */
    PROXY_ERROR_NETWORK_UNREACHABLE,
    PROXY_ERROR_CONNECTION_REFUSED,
    PROXY_ERROR_TTL_EXPIRED,
    PROXY_ERROR_PROTOCOL,           /* Protocol error */
    PROXY_ERROR_UNSUPPORTED,        /* Unsupported feature */
    PROXY_ERROR_TIMEOUT
} SocketProxy_Result;

/* ============================================================================
 * Synchronous API
 * ============================================================================ */

/**
 * SocketProxy_connect - Connect to target through proxy
 * @socket: Unconnected socket
 * @proxy: Proxy configuration
 * @target_host: Destination hostname or IP
 * @target_port: Destination port
 * Returns: Result code
 *
 * After success, socket is tunneled to target.
 * Perform TLS handshake after this if needed.
 */
SocketProxy_Result SocketProxy_connect(Socket_T socket,
                                        const SocketProxy_Config *proxy,
                                        const char *target_host,
                                        int target_port);

/**
 * SocketProxy_connect_tls - Connect and establish TLS through proxy
 * @socket: Unconnected socket
 * @proxy: Proxy configuration
 * @target_host: Destination hostname
 * @target_port: Destination port
 * @tls_ctx: TLS context
 */
SocketProxy_Result SocketProxy_connect_tls(Socket_T socket,
                                            const SocketProxy_Config *proxy,
                                            const char *target_host,
                                            int target_port,
                                            SocketTLSContext_T tls_ctx);

/* ============================================================================
 * Asynchronous API
 * ============================================================================ */

typedef struct SocketProxy_Conn *SocketProxy_Conn_T;

/**
 * SocketProxy_connect_async - Start async proxy connection
 * @socket: Non-blocking socket
 * @proxy: Proxy configuration
 * @target_host: Destination
 * @target_port: Destination port
 */
SocketProxy_Conn_T SocketProxy_connect_async(Socket_T socket,
                                              const SocketProxy_Config *proxy,
                                              const char *target_host,
                                              int target_port);

/**
 * SocketProxy_Conn_process - Process async connection
 * @conn: Connection state
 * @events: Poll events
 * Returns: PROXY_OK when complete, 1 if in progress, negative on error
 */
int SocketProxy_Conn_process(SocketProxy_Conn_T conn, unsigned events);

/**
 * SocketProxy_Conn_poll_events - Get events to poll for
 */
unsigned SocketProxy_Conn_poll_events(SocketProxy_Conn_T conn);

/**
 * SocketProxy_Conn_free - Free connection state
 */
void SocketProxy_Conn_free(SocketProxy_Conn_T *conn);

/**
 * SocketProxy_Conn_result - Get result after completion
 */
SocketProxy_Result SocketProxy_Conn_result(SocketProxy_Conn_T conn);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * SocketProxy_result_string - Get error description
 */
const char *SocketProxy_result_string(SocketProxy_Result result);

/**
 * SocketProxy_parse_url - Parse proxy URL
 * @url: Proxy URL (e.g., "socks5://user:pass@proxy:1080")
 * @config: Output configuration
 * @arena: Arena for string allocation
 */
int SocketProxy_parse_url(const char *url, SocketProxy_Config *config,
                           Arena_T arena);

/* Exception */
extern const Except_T SocketProxy_Failed;
```

### - [ ] Protocol Details

#### HTTP CONNECT (RFC 7231)
```
Client -> Proxy:
  CONNECT target:443 HTTP/1.1
  Host: target:443
  Proxy-Authorization: Basic base64(user:pass)
  
Proxy -> Client:
  HTTP/1.1 200 Connection Established
  
(Now tunnel is transparent)
```

#### SOCKS4
```
Client -> Proxy:
  VN(1)=4, CD(1)=1, DSTPORT(2), DSTIP(4), USERID, NULL
  
Proxy -> Client:
  VN(1)=0, CD(1)=90, DSTPORT(2), DSTIP(4)
  
CD: 90=granted, 91=rejected, 92=no identd, 93=identd mismatch
```

#### SOCKS4a
```
Same as SOCKS4 but:
- DSTIP = 0.0.0.x (invalid IP signals domain follows)
- Domain name appended after USERID NULL
```

#### SOCKS5 (RFC 1928)
```
1. Greeting:
   Client: VER(1)=5, NMETHODS(1), METHODS(NMETHODS)
   Server: VER(1)=5, METHOD(1)
   
   Methods: 0=no auth, 2=username/password
   
2. Authentication (if METHOD=2, RFC 1929):
   Client: VER(1)=1, ULEN(1), UNAME(ULEN), PLEN(1), PASSWD(PLEN)
   Server: VER(1)=1, STATUS(1)  [0=success]
   
3. Connect:
   Client: VER(1)=5, CMD(1)=1, RSV(1)=0, ATYP(1), DST.ADDR, DST.PORT(2)
   Server: VER(1)=5, REP(1), RSV(1)=0, ATYP(1), BND.ADDR, BND.PORT(2)
   
   ATYP: 1=IPv4, 3=domain, 4=IPv6
   REP: 0=success, 1=failure, 2=not allowed, 3=network unreachable,
        4=host unreachable, 5=connection refused, 6=TTL expired,
        7=command not supported, 8=address type not supported
```

### - [ ] Implementation Requirements

- [ ] HTTP CONNECT with optional authentication
- [ ] HTTP CONNECT via HTTPS (TLS to proxy)
- [ ] SOCKS4 connect
- [ ] SOCKS4a with hostname resolution at proxy
- [ ] SOCKS5 without authentication
- [ ] SOCKS5 with username/password (RFC 1929)
- [ ] SOCKS5 with hostname (ATYP=3)
- [ ] SOCKS5 with IPv6 (ATYP=4)
- [ ] Async state machine for all protocols
- [ ] Timeout handling

### - [ ] Security Considerations

- [ ] Validate proxy responses
- [ ] Timeout on proxy handshake
- [ ] Don't leak credentials in logs
- [ ] Clear credentials from memory

### - [ ] Tests

- [ ] `src/test/test_proxy.c`
  - [ ] HTTP CONNECT success
  - [ ] HTTP CONNECT with auth
  - [ ] HTTP CONNECT auth failure
  - [ ] HTTP CONNECT via HTTPS
  - [ ] SOCKS4 connect
  - [ ] SOCKS4a with hostname
  - [ ] SOCKS5 no auth
  - [ ] SOCKS5 with auth
  - [ ] SOCKS5 with hostname
  - [ ] SOCKS5 with IPv6
  - [ ] Timeout handling
  - [ ] Error responses
  - [ ] Async connection

### - [ ] Fuzzing Harnesses

- [ ] `src/fuzz/fuzz_proxy_http_response.c`
- [ ] `src/fuzz/fuzz_proxy_socks4.c`
- [ ] `src/fuzz/fuzz_proxy_socks5.c`

### - [ ] Build System

- [ ] Add proxy sources to `LIB_SOURCES`
- [ ] Add `test_proxy` to test executables

---

## - [ ] Phase 9: WebSocket Protocol (RFC 6455)

Complete WebSocket implementation with compression extension support.

### - [ ] Files to Create

- [ ] `include/socket/SocketWS.h`
- [ ] `include/socket/SocketWS-private.h`
- [ ] `src/socket/SocketWS.c`
- [ ] `src/socket/SocketWS-handshake.c`
- [ ] `src/socket/SocketWS-frame.c`
- [ ] `src/socket/SocketWS-deflate.c`

### RFC Coverage

- RFC 6455: The WebSocket Protocol
- RFC 7692: Compression Extensions for WebSocket (permessage-deflate)

### - [ ] API Specification

```c
/* ============================================================================
 * WebSocket Opcodes (RFC 6455 Section 5.2)
 * ============================================================================ */

typedef enum {
    WS_OPCODE_CONTINUATION = 0x0,
    WS_OPCODE_TEXT = 0x1,
    WS_OPCODE_BINARY = 0x2,
    /* 0x3-0x7 reserved for further non-control frames */
    WS_OPCODE_CLOSE = 0x8,
    WS_OPCODE_PING = 0x9,
    WS_OPCODE_PONG = 0xA
    /* 0xB-0xF reserved for further control frames */
} SocketWS_Opcode;

/* ============================================================================
 * Close Status Codes (RFC 6455 Section 7.4.1)
 * ============================================================================ */

typedef enum {
    WS_CLOSE_NORMAL = 1000,
    WS_CLOSE_GOING_AWAY = 1001,
    WS_CLOSE_PROTOCOL_ERROR = 1002,
    WS_CLOSE_UNSUPPORTED_DATA = 1003,
    /* 1004 reserved */
    WS_CLOSE_NO_STATUS = 1005,          /* Must not be sent */
    WS_CLOSE_ABNORMAL = 1006,           /* Must not be sent */
    WS_CLOSE_INVALID_PAYLOAD = 1007,    /* e.g., non-UTF-8 text */
    WS_CLOSE_POLICY_VIOLATION = 1008,
    WS_CLOSE_MESSAGE_TOO_BIG = 1009,
    WS_CLOSE_MANDATORY_EXT = 1010,
    WS_CLOSE_INTERNAL_ERROR = 1011,
    WS_CLOSE_SERVICE_RESTART = 1012,    /* RFC 6455 Section 7.4.1 */
    WS_CLOSE_TRY_AGAIN_LATER = 1013,
    WS_CLOSE_BAD_GATEWAY = 1014,
    WS_CLOSE_TLS_HANDSHAKE = 1015       /* Must not be sent */
} SocketWS_CloseCode;

/* ============================================================================
 * Connection State
 * ============================================================================ */

typedef enum {
    WS_STATE_CONNECTING,    /* Handshake in progress */
    WS_STATE_OPEN,          /* Ready for messages */
    WS_STATE_CLOSING,       /* Close handshake in progress */
    WS_STATE_CLOSED         /* Connection terminated */
} SocketWS_State;

typedef enum {
    WS_ROLE_CLIENT,
    WS_ROLE_SERVER
} SocketWS_Role;

/* ============================================================================
 * Configuration
 * ============================================================================ */

typedef struct {
    SocketWS_Role role;
    
    /* Limits */
    size_t max_frame_size;          /* Max single frame (default: 16MB) */
    size_t max_message_size;        /* Max reassembled message (default: 64MB) */
    size_t max_fragments;           /* Max fragments per message (default: 1000) */
    
    /* Validation */
    int validate_utf8;              /* Validate UTF-8 in text frames (default: yes) */
    
    /* Extensions */
    int enable_permessage_deflate;  /* Enable compression (default: yes) */
    int deflate_no_context_takeover;/* Don't reuse compression context */
    int deflate_max_window_bits;    /* LZ77 window size (8-15, default: 15) */
    
    /* Subprotocols */
    const char **subprotocols;      /* NULL-terminated list */
    
    /* Keepalive */
    int ping_interval_ms;           /* Auto-ping interval (0 = disabled) */
    int ping_timeout_ms;            /* Pong timeout */
} SocketWS_Config;

/* ============================================================================
 * Frame Structure
 * ============================================================================ */

/**
 * Received frame
 */
typedef struct {
    SocketWS_Opcode opcode;
    int fin;                    /* Final fragment flag */
    int rsv1;                   /* Reserved bit 1 (compression) */
    const unsigned char *payload;
    size_t payload_len;
} SocketWS_Frame;

/**
 * Received message (reassembled from fragments)
 */
typedef struct {
    SocketWS_Opcode type;       /* TEXT or BINARY */
    unsigned char *data;        /* Message data (caller must free) */
    size_t len;
} SocketWS_Message;

/* ============================================================================
 * WebSocket Connection
 * ============================================================================ */

typedef struct SocketWS *SocketWS_T;

void SocketWS_config_defaults(SocketWS_Config *config);

/* ============================================================================
 * Client API
 * ============================================================================ */

/**
 * SocketWS_connect - Connect to WebSocket server
 * @url: WebSocket URL (ws:// or wss://)
 * @config: Configuration (NULL for defaults)
 * Returns: Connected WebSocket
 *
 * Performs DNS resolution, TCP connect, optional TLS, and WS handshake.
 */
SocketWS_T SocketWS_connect(const char *url, const SocketWS_Config *config);

/**
 * SocketWS_connect_proxy - Connect through proxy
 * @url: WebSocket URL
 * @proxy: Proxy configuration
 * @config: WebSocket configuration
 */
SocketWS_T SocketWS_connect_proxy(const char *url,
                                   const SocketProxy_Config *proxy,
                                   const SocketWS_Config *config);

/**
 * SocketWS_client_new - Create client from existing socket
 * @socket: Connected TCP socket
 * @host: Host header value
 * @path: Request path (e.g., "/ws")
 * @config: Configuration
 */
SocketWS_T SocketWS_client_new(Socket_T socket,
                                const char *host,
                                const char *path,
                                const SocketWS_Config *config);

/* ============================================================================
 * Server API
 * ============================================================================ */

/**
 * SocketWS_is_upgrade - Check if HTTP request is WebSocket upgrade
 * @request: Parsed HTTP request
 */
int SocketWS_is_upgrade(const SocketHTTP_Request *request);

/**
 * SocketWS_server_accept - Accept WebSocket upgrade
 * @socket: TCP socket with pending upgrade request
 * @request: Parsed HTTP upgrade request
 * @config: Configuration
 * Returns: WebSocket in OPEN state
 */
SocketWS_T SocketWS_server_accept(Socket_T socket,
                                   const SocketHTTP_Request *request,
                                   const SocketWS_Config *config);

/**
 * SocketWS_server_reject - Reject upgrade with HTTP response
 * @socket: TCP socket
 * @status_code: HTTP status (e.g., 403)
 * @reason: Rejection reason
 */
void SocketWS_server_reject(Socket_T socket, int status_code,
                             const char *reason);

/* ============================================================================
 * Connection Lifecycle
 * ============================================================================ */

/**
 * SocketWS_free - Free WebSocket connection
 */
void SocketWS_free(SocketWS_T *ws);

/**
 * SocketWS_handshake - Perform/continue handshake
 * Returns: 0 complete, 1 in progress, -1 error
 */
int SocketWS_handshake(SocketWS_T ws);

/**
 * SocketWS_state - Get current state
 */
SocketWS_State SocketWS_state(SocketWS_T ws);

/**
 * SocketWS_socket - Get underlying socket
 */
Socket_T SocketWS_socket(SocketWS_T ws);

/**
 * SocketWS_selected_subprotocol - Get negotiated subprotocol
 */
const char *SocketWS_selected_subprotocol(SocketWS_T ws);

/**
 * SocketWS_compression_enabled - Check if compression active
 */
int SocketWS_compression_enabled(SocketWS_T ws);

/* ============================================================================
 * Sending
 * ============================================================================ */

/**
 * SocketWS_send_text - Send text message
 * @ws: WebSocket
 * @data: UTF-8 text
 * @len: Length in bytes
 * Returns: 0 on success, -1 on error
 *
 * Data is validated for UTF-8 if validate_utf8 enabled.
 * Large messages are automatically fragmented.
 */
int SocketWS_send_text(SocketWS_T ws, const char *data, size_t len);

/**
 * SocketWS_send_binary - Send binary message
 */
int SocketWS_send_binary(SocketWS_T ws, const void *data, size_t len);

/**
 * SocketWS_send_text_fragment - Send text fragment
 * @ws: WebSocket
 * @data: Fragment data
 * @len: Fragment length
 * @fin: Final fragment flag
 */
int SocketWS_send_text_fragment(SocketWS_T ws, const char *data,
                                 size_t len, int fin);

/**
 * SocketWS_send_binary_fragment - Send binary fragment
 */
int SocketWS_send_binary_fragment(SocketWS_T ws, const void *data,
                                   size_t len, int fin);

/**
 * SocketWS_ping - Send PING control frame
 * @ws: WebSocket
 * @data: Optional payload (max 125 bytes)
 * @len: Payload length
 */
int SocketWS_ping(SocketWS_T ws, const void *data, size_t len);

/**
 * SocketWS_pong - Send unsolicited PONG
 */
int SocketWS_pong(SocketWS_T ws, const void *data, size_t len);

/**
 * SocketWS_close - Initiate close handshake
 * @ws: WebSocket
 * @code: Close status code
 * @reason: Optional UTF-8 reason (max 123 bytes)
 */
int SocketWS_close(SocketWS_T ws, SocketWS_CloseCode code, const char *reason);

/* ============================================================================
 * Receiving (Blocking)
 * ============================================================================ */

/**
 * SocketWS_recv - Receive next frame (blocking)
 * @ws: WebSocket
 * @frame: Output frame (payload points to internal buffer)
 * Returns: 1 if frame received, 0 if closed, -1 on error
 *
 * Control frames (PING/PONG/CLOSE) handled automatically.
 * Returns data frames only.
 */
int SocketWS_recv(SocketWS_T ws, SocketWS_Frame *frame);

/**
 * SocketWS_recv_message - Receive complete message (blocking)
 * @ws: WebSocket
 * @msg: Output message (caller must free msg->data)
 * Returns: 1 if message received, 0 if closed, -1 on error
 *
 * Reassembles fragmented messages.
 */
int SocketWS_recv_message(SocketWS_T ws, SocketWS_Message *msg);

/* ============================================================================
 * Receiving (Non-blocking)
 * ============================================================================ */

/**
 * SocketWS_recv_available - Check if data available
 */
int SocketWS_recv_available(SocketWS_T ws);

/**
 * SocketWS_recv_frame_nonblock - Non-blocking frame receive
 * Returns: 1 if frame, 0 if would block, -1 on error
 */
int SocketWS_recv_frame_nonblock(SocketWS_T ws, SocketWS_Frame *frame);

/**
 * SocketWS_recv_message_nonblock - Non-blocking message receive
 */
int SocketWS_recv_message_nonblock(SocketWS_T ws, SocketWS_Message *msg);

/* ============================================================================
 * Event Loop Integration
 * ============================================================================ */

/**
 * SocketWS_pollfd - Get file descriptor for polling
 */
int SocketWS_pollfd(SocketWS_T ws);

/**
 * SocketWS_poll_events - Get events to poll for
 */
unsigned SocketWS_poll_events(SocketWS_T ws);

/**
 * SocketWS_process - Process poll events
 * @ws: WebSocket
 * @events: Events from poll
 * Returns: 0 on success, -1 on error
 *
 * Handles internal bookkeeping, auto-ping, etc.
 */
int SocketWS_process(SocketWS_T ws, unsigned events);

/* ============================================================================
 * Close Status
 * ============================================================================ */

/**
 * SocketWS_close_code - Get peer's close code
 * Returns: Close code or 0 if not received
 */
int SocketWS_close_code(SocketWS_T ws);

/**
 * SocketWS_close_reason - Get peer's close reason
 */
const char *SocketWS_close_reason(SocketWS_T ws);

/* ============================================================================
 * Error Handling
 * ============================================================================ */

typedef enum {
    WS_OK = 0,
    WS_ERROR,
    WS_ERROR_HANDSHAKE,
    WS_ERROR_PROTOCOL,
    WS_ERROR_FRAME_TOO_LARGE,
    WS_ERROR_MESSAGE_TOO_LARGE,
    WS_ERROR_INVALID_UTF8,
    WS_ERROR_COMPRESSION,
    WS_ERROR_CLOSED
} SocketWS_Error;

SocketWS_Error SocketWS_last_error(SocketWS_T ws);
const char *SocketWS_error_string(SocketWS_Error error);

extern const Except_T SocketWS_Failed;
extern const Except_T SocketWS_ProtocolError;
extern const Except_T SocketWS_Closed;
```

### - [ ] Frame Format (RFC 6455 Section 5.2)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-------+-+-------------+-------------------------------+
|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
|N|V|V|V|       |S|             |   (if payload len==126/127)   |
| |1|2|3|       |K|             |                               |
+-+-+-+-+-------+-+-------------+-------------------------------+
|     Extended payload length continued, if payload len == 127  |
+-------------------------------+-------------------------------+
|                               |Masking-key, if MASK set to 1  |
+-------------------------------+-------------------------------+
| Masking-key (continued)       |          Payload Data         |
+-------------------------------- - - - - - - - - - - - - - - - +
```

### - [ ] Implementation Requirements

#### Handshake (RFC 6455 Section 4)
- [ ] Client generates random 16-byte key, base64 encodes
- [ ] Server computes: base64(SHA1(key + GUID))
- [ ] Validate Sec-WebSocket-Accept
- [ ] Handle Sec-WebSocket-Protocol negotiation
- [ ] Handle Sec-WebSocket-Extensions negotiation

#### Framing (RFC 6455 Section 5)
- [ ] Parse 2-14 byte frame header
- [ ] Handle 7-bit, 16-bit, 64-bit payload lengths
- [ ] Client MUST mask all frames
- [ ] Server MUST NOT mask frames
- [ ] 4-byte XOR masking/unmasking
- [ ] Control frame size limit (125 bytes)
- [ ] Control frames MUST NOT be fragmented

#### Control Frames (RFC 6455 Section 5.5)
- [ ] PING: Auto-respond with PONG (same payload)
- [ ] PONG: Process silently
- [ ] CLOSE: Respond with CLOSE, transition state
- [ ] Control frames can interleave with data fragments

#### Data Frames (RFC 6455 Section 5.6)
- [ ] TEXT: UTF-8 encoded
- [ ] BINARY: Arbitrary bytes
- [ ] Fragmentation with CONTINUATION frames
- [ ] Message reassembly

#### UTF-8 Validation (RFC 6455 Section 8.1)
- [ ] Validate TEXT frames as UTF-8
- [ ] Validate CLOSE reason as UTF-8
- [ ] Incremental validation for fragmented messages
- [ ] Send CLOSE(1007) on invalid UTF-8

#### permessage-deflate (RFC 7692)
- [ ] Extension negotiation during handshake
- [ ] Per-message compression using DEFLATE
- [ ] RSV1 bit indicates compressed
- [ ] client_no_context_takeover parameter
- [ ] server_no_context_takeover parameter
- [ ] client_max_window_bits parameter
- [ ] server_max_window_bits parameter

### - [ ] Security Requirements

- [ ] Always mask client-to-server frames
- [ ] Never mask server-to-client frames
- [ ] Generate cryptographically random mask keys
- [ ] Validate Sec-WebSocket-Accept value
- [ ] Limit frame and message sizes
- [ ] Timeout on handshake
- [ ] Reject unknown reserved bits
- [ ] UTF-8 validation on text frames

### - [ ] Tests

- [ ] `src/test/test_websocket.c`
  - [ ] Client handshake
  - [ ] Server handshake
  - [ ] Invalid handshake rejection
  - [ ] Send/receive text
  - [ ] Send/receive binary
  - [ ] Large message
  - [ ] Fragmented message
  - [ ] Ping/pong
  - [ ] Close handshake
  - [ ] Close with code and reason
  - [ ] Invalid UTF-8 rejection
  - [ ] Masking validation
  - [ ] Control frame interleaving
  - [ ] permessage-deflate
  - [ ] Subprotocol negotiation

### - [ ] Fuzzing Harnesses

- [ ] `src/fuzz/fuzz_ws_frame.c`
- [ ] `src/fuzz/fuzz_ws_handshake.c`
- [ ] `src/fuzz/fuzz_ws_deflate.c`

### - [ ] Build System

- [ ] Add WebSocket sources to `LIB_SOURCES`
- [ ] Add zlib dependency for permessage-deflate
- [ ] Add `test_websocket` to test executables

---

## - [ ] Phase 10: Security Hardening

Comprehensive security measures across all components.

### - [ ] Security Checklist

#### - [ ] Input Validation
- [ ] Validate all sizes before allocation
- [ ] Validate all lengths before copy operations
- [ ] Reject negative sizes
- [ ] Check for integer overflow in size calculations
- [ ] Validate string encodings (UTF-8, ASCII)
- [ ] Validate header names (token characters only)
- [ ] Validate header values (no bare CR/LF)
- [ ] Validate URIs before use
- [ ] Validate IP addresses
- [ ] Validate port numbers

#### - [ ] Buffer Safety
- [ ] Bounds checking on all array access
- [ ] Length-limited string operations
- [ ] No unbounded string copies
- [ ] Clear sensitive buffers after use
- [ ] Use secure memory clearing (avoid optimizer removal)

#### - [ ] Protocol Security
- [ ] Request smuggling prevention (HTTP/1.1)
- [ ] Header injection prevention
- [ ] Response splitting prevention
- [ ] HPACK bomb prevention (HTTP/2)
- [ ] Stream exhaustion prevention (HTTP/2)
- [ ] Compression ratio limits (HTTP/2)
- [ ] WebSocket masking enforcement
- [ ] Frame size limits
- [ ] Connection limits

#### - [ ] TLS Security
- [ ] TLS 1.3 only by default
- [ ] Certificate verification enabled by default
- [ ] Hostname verification
- [ ] ALPN protocol negotiation
- [ ] Session resumption security
- [ ] Secure cipher suite selection

#### - [ ] Resource Management
- [ ] Memory allocation limits
- [ ] Connection count limits
- [ ] Per-host connection limits
- [ ] Timeout enforcement
- [ ] Graceful degradation under load

#### - [ ] Credential Handling
- [ ] Clear passwords from memory after use
- [ ] Don't log credentials
- [ ] Secure comparison for tokens
- [ ] Time-constant comparison where needed

### - [ ] Configuration Limits

```c
/**
 * Security configuration (compile-time defaults)
 * All can be overridden before including headers
 */

/* Memory limits */
#ifndef SOCKET_MAX_ALLOCATION
#define SOCKET_MAX_ALLOCATION (256 * 1024 * 1024)   /* 256MB */
#endif

/* HTTP limits */
#ifndef SOCKET_HTTP_MAX_URI_LENGTH
#define SOCKET_HTTP_MAX_URI_LENGTH (8 * 1024)
#endif

#ifndef SOCKET_HTTP_MAX_HEADER_SIZE
#define SOCKET_HTTP_MAX_HEADER_SIZE (64 * 1024)
#endif

#ifndef SOCKET_HTTP_MAX_HEADERS
#define SOCKET_HTTP_MAX_HEADERS 100
#endif

#ifndef SOCKET_HTTP_MAX_BODY_SIZE
#define SOCKET_HTTP_MAX_BODY_SIZE (100 * 1024 * 1024)  /* 100MB */
#endif

/* HTTP/2 limits */
#ifndef SOCKET_HTTP2_MAX_CONCURRENT_STREAMS
#define SOCKET_HTTP2_MAX_CONCURRENT_STREAMS 100
#endif

#ifndef SOCKET_HTTP2_MAX_HEADER_LIST_SIZE
#define SOCKET_HTTP2_MAX_HEADER_LIST_SIZE (16 * 1024)
#endif

/* WebSocket limits */
#ifndef SOCKET_WS_MAX_FRAME_SIZE
#define SOCKET_WS_MAX_FRAME_SIZE (16 * 1024 * 1024)    /* 16MB */
#endif

#ifndef SOCKET_WS_MAX_MESSAGE_SIZE
#define SOCKET_WS_MAX_MESSAGE_SIZE (64 * 1024 * 1024)  /* 64MB */
#endif

/* Timeout defaults (milliseconds) */
#ifndef SOCKET_DEFAULT_CONNECT_TIMEOUT
#define SOCKET_DEFAULT_CONNECT_TIMEOUT 30000
#endif

#ifndef SOCKET_DEFAULT_REQUEST_TIMEOUT
#define SOCKET_DEFAULT_REQUEST_TIMEOUT 60000
#endif

#ifndef SOCKET_DEFAULT_IDLE_TIMEOUT
#define SOCKET_DEFAULT_IDLE_TIMEOUT 300000
#endif
```

### - [ ] Security Tests

- [ ] `src/test/test_security.c`
  - [ ] Integer overflow handling
  - [ ] Buffer overflow prevention
  - [ ] Request smuggling rejection
  - [ ] Header injection rejection
  - [ ] Invalid UTF-8 handling
  - [ ] Timeout enforcement
  - [ ] Size limit enforcement
  - [ ] Resource exhaustion handling

---

## - [ ] Phase 11: Testing Infrastructure

Comprehensive testing covering all components.

### - [ ] Test Categories

#### - [ ] Unit Tests
- [ ] `test_crypto.c` - Cryptographic utilities
- [ ] `test_utf8.c` - UTF-8 validation
- [ ] `test_http_core.c` - HTTP types and utilities
- [ ] `test_http1_parser.c` - HTTP/1.1 parsing
- [ ] `test_hpack.c` - HPACK compression
- [ ] `test_http2.c` - HTTP/2 protocol
- [ ] `test_http_client.c` - HTTP client API
- [ ] `test_proxy.c` - Proxy protocols
- [ ] `test_websocket.c` - WebSocket protocol
- [ ] `test_security.c` - Security measures

#### - [ ] Integration Tests
- [ ] `test_http_integration.c` - End-to-end HTTP tests
- [ ] `test_http2_integration.c` - HTTP/2 with real TLS
- [ ] `test_ws_integration.c` - WebSocket end-to-end
- [ ] `test_proxy_integration.c` - Proxy tunneling

#### - [ ] Compliance Tests
- [ ] RFC 9112 compliance (HTTP/1.1)
- [ ] RFC 9113 compliance (HTTP/2)
- [x] RFC 7541 test vectors (HPACK) ✅
- [ ] RFC 6455 compliance (WebSocket)

### - [ ] Fuzzing Harnesses

#### - [ ] Core Fuzzing
- [ ] `fuzz_base64_decode.c`
- [ ] `fuzz_hex_decode.c`
- [ ] `fuzz_utf8_validate.c`
- [ ] `fuzz_utf8_incremental.c`

#### - [ ] HTTP Fuzzing
- [ ] `fuzz_uri_parse.c`
- [ ] `fuzz_http_date.c`
- [ ] `fuzz_media_type.c`
- [ ] `fuzz_http1_request.c`
- [ ] `fuzz_http1_response.c`
- [ ] `fuzz_http1_chunked.c`
- [ ] `fuzz_hpack_decode.c`
- [ ] `fuzz_hpack_huffman.c`
- [ ] `fuzz_http2_frames.c`

#### - [ ] Proxy Fuzzing
- [ ] `fuzz_proxy_http_response.c`
- [ ] `fuzz_proxy_socks4.c`
- [ ] `fuzz_proxy_socks5.c`

#### - [ ] WebSocket Fuzzing
- [ ] `fuzz_ws_frame.c`
- [ ] `fuzz_ws_handshake.c`
- [ ] `fuzz_ws_deflate.c`

### - [ ] Test Infrastructure

- [ ] Test framework extensions for HTTP
- [ ] Mock server for testing
- [ ] Test TLS certificates
- [ ] Test proxy server
- [ ] CI integration for all tests
- [ ] Code coverage tracking
- [ ] Memory leak detection (Valgrind)
- [ ] Thread safety testing (TSan)

---

## - [ ] Phase 12: Documentation and Examples

### - [ ] API Documentation

- [ ] Complete Doxygen comments for all public APIs
- [ ] Generate HTML documentation
- [ ] Include in build system

### - [ ] Guides

- [ ] `docs/HTTP.md` - HTTP/1.1 and HTTP/2 guide
- [ ] `docs/WEBSOCKET.md` - WebSocket guide
- [ ] `docs/PROXY.md` - Proxy configuration guide
- [ ] `docs/SECURITY.md` - Security best practices
- [ ] `docs/MIGRATION.md` - Migration from other libraries

### - [ ] Examples

- [ ] `examples/http_get.c` - Simple HTTP GET
- [ ] `examples/http_post.c` - HTTP POST with JSON
- [ ] `examples/http2_client.c` - HTTP/2 client
- [ ] `examples/http_server.c` - Basic HTTP server
- [ ] `examples/websocket_client.c` - WebSocket client
- [ ] `examples/websocket_server.c` - WebSocket server
- [ ] `examples/proxy_connect.c` - Proxy tunneling
- [ ] `examples/Makefile` - Build examples

### - [ ] Build System Updates

- [ ] Add all new sources to CMakeLists.txt
- [ ] Add all new tests
- [ ] Add all fuzz harnesses
- [ ] Add example build targets
- [ ] Update pkg-config file
- [ ] Update installation targets

---

## Dependency Summary

```
Phase 1  (Crypto)  ────────────────────────────────────────────┐
                                                               │
Phase 2  (UTF-8)   ────────────────────────────────────────────┤
                                                               │
Phase 3  (HTTP Core) ─────────────────────┬────────────────────┤
                                          │                    │
                                          ▼                    │
Phase 4  (HTTP/1.1) ◄───────────────── Phase 3                 │
                                          │                    │
Phase 5  (HPACK) ◄────────────────────────┘                    │
                                          │                    │
                                          ▼                    │
Phase 6  (HTTP/2) ◄──────────────────── Phase 5                │
                                          │                    │
                     ┌────────────────────┤                    │
                     │                    │                    │
                     ▼                    ▼                    │
Phase 7  (Client/Server) ◄──── Phase 4 + Phase 6               │
                     │                                         │
                     │         ┌───────────────────────────────┘
                     │         │
                     ▼         ▼
Phase 8  (Proxy) ◄──────── Phase 4 + Phase 1
                     │
                     │         ┌─── Phase 1 + Phase 2 + Phase 4
                     │         │
                     ▼         ▼
Phase 9  (WebSocket) ◄──── Crypto + UTF-8 + HTTP Parser
                     │
                     ▼
Phase 10 (Security) ◄──── All phases (continuous)
                     │
                     ▼
Phase 11 (Testing)  ◄──── All phases (continuous)
                     │
                     ▼
Phase 12 (Docs)     ◄──── All phases (final)
```

---

## File Summary

| Phase | New Files | Estimated Lines |
|-------|-----------|-----------------|
| 1 - Crypto | 2 | ~400 |
| 2 - UTF-8 | 2 | ~300 |
| 3 - HTTP Core | 6 | ~1500 |
| 4 - HTTP/1.1 | 6 | ~2500 |
| 5 - HPACK | 5 | ~1500 |
| 6 - HTTP/2 | 7 | ~4000 |
| 7 - Client/Server | 7 | ~3000 |
| 8 - Proxy | 6 | ~1200 |
| 9 - WebSocket | 6 | ~2000 |
| 10 - Security | - | Integrated |
| 11 - Testing | ~25 | ~5000 |
| 12 - Documentation | ~10 | ~2000 |
| **Total** | **~82** | **~23,400** |

---

## HTTP/3 Extensibility

The architecture supports future HTTP/3 addition:

### Shared with HTTP/3
- HTTP core types (methods, status codes, headers)
- Header collection API
- HTTP client/server abstraction
- Cookie handling
- Authentication

### HTTP/3 Specific (Future)
- QUIC transport (requires UDP infrastructure)
- QPACK header compression (similar to HPACK)
- HTTP/3 framing
- Connection migration
- 0-RTT support

### QUIC Prerequisites
- Your existing `SocketDgram` for UDP
- Your existing TLS 1.3 support
- Timer infrastructure (`SocketTimer`)
- Congestion control algorithms
