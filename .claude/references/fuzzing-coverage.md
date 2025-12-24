# Fuzzing Coverage Reference

This document maps all fuzzers to their target modules, attack vectors, and coverage goals.

## Fuzzer Index

| Fuzzer | Target Module | Category | Max Input Size |
|--------|---------------|----------|----------------|
| `fuzz_address_parse` | SocketCommon | Validation | 4096 |
| `fuzz_arena` | Arena | Memory | 4096 |
| `fuzz_async` | SocketAsync | I/O | 4096 |
| `fuzz_base64_decode` | SocketCrypto | Codec | 4096 |
| `fuzz_cert_pinning` | SocketTLS | TLS | 4096 |
| `fuzz_certificate_parsing` | SocketTLS | TLS | 4096 |
| `fuzz_cidr_parse` | SocketCommon | Validation | 4096 |
| `fuzz_connect` | Socket | Core | 4096 |
| `fuzz_dns_inj` | SocketDNS | Security | 4096 |
| `fuzz_dns_validate` | SocketDNS | Validation | 4096 |
| `fuzz_dns_cache` | SocketDNS | DNS | 4096 |
| `fuzz_dns_config` | SocketDNSConfig | DNS | 4096 |
| `fuzz_dns_cookie_client` | SocketDNSCookie | DNS | 4096 |
| `fuzz_dns_deadserver` | SocketDNSDeadServer | DNS | 4096 |
| `fuzz_dns_doh` | SocketDNSoverHTTPS | DNS | 4096 |
| `fuzz_dns_dot` | SocketDNSoverTLS | DNS | 4096 |
| `fuzz_dns_encode` | SocketDNSWire | DNS | 4096 |
| `fuzz_dns_resolver` | SocketDNSResolver | DNS | 4096 |
| `fuzz_dns_transport` | SocketDNSTransport | DNS | 4096 |
| `fuzz_dnssec` | SocketDNSSEC | DNS | 4096 |
| `fuzz_dns_header` | SocketDNSWire | DNS | 4096 |
| `fuzz_dns_name` | SocketDNSWire | DNS | 4096 |
| `fuzz_dns_response` | SocketDNSWire | DNS | 4096 |
| `fuzz_dns_edns0` | SocketDNSWire | DNS | 4096 |
| `fuzz_dns_cookie` | SocketDNSCookie | DNS | 4096 |
| `fuzz_dns_soa` | SocketDNSWire | DNS | 4096 |
| `fuzz_dtls_config` | SocketDTLS | TLS | 4096 |
| `fuzz_dtls_context` | SocketDTLS | TLS | 4096 |
| `fuzz_dtls_cookie` | SocketDTLS | TLS | 4096 |
| `fuzz_dtls_enable_config` | SocketDTLS | TLS | 4096 |
| `fuzz_dtls_handshake` | SocketDTLS | TLS | 4096 |
| `fuzz_dtls_io` | SocketDTLS | TLS | 4096 |
| `fuzz_dtls_replay` | SocketDTLS | TLS | 4096 |
| `fuzz_exception` | Except | Core | 4096 |
| `fuzz_except_unwind` | Except | Core | 4096 |
| `fuzz_happy_eyeballs` | SocketHappyEyeballs | Connection | 4096 |
| `fuzz_hex_decode` | SocketCrypto | Codec | 4096 |
| `fuzz_hpack` | SocketHPACK | HTTP/2 | 32768 |
| `fuzz_hpack_decode` | SocketHPACK | HTTP/2 | 32768 |
| `fuzz_hpack_encode` | SocketHPACK | HTTP/2 | 32768 |
| `fuzz_hpack_huffman` | SocketHPACK | HTTP/2 | 4096 |
| `fuzz_hpack_integer` | SocketHPACK | HTTP/2 | 4096 |
| `fuzz_http1_chunked` | SocketHTTP1 | HTTP | 65536 |
| `fuzz_http1_compression` | SocketHTTP1 | HTTP | 65536 |
| `fuzz_http1_headers` | SocketHTTP1 | HTTP | 65536 |
| `fuzz_http1_request` | SocketHTTP1 | HTTP | 65536 |
| `fuzz_http1_response` | SocketHTTP1 | HTTP | 65536 |
| `fuzz_http1_serialize` | SocketHTTP1 | HTTP | 65536 |
| `fuzz_http2_connection` | SocketHTTP2 | HTTP/2 | 65536 |
| `fuzz_http2_frames` | SocketHTTP2 | HTTP/2 | 65536 |
| `fuzz_http2_frames_full` | SocketHTTP2 | HTTP/2 | 65536 |
| `fuzz_http2_headers` | SocketHTTP2 | HTTP/2 | 65536 |
| `fuzz_http2_settings` | SocketHTTP2 | HTTP/2 | 65536 |
| `fuzz_http2_flow` | SocketHTTP2 | HTTP/2 | 65536 |
| `fuzz_http2_stream` | SocketHTTP2 | HTTP/2 | 65536 |
| `fuzz_http_auth` | SocketHTTPClient | HTTP | 32768 |
| `fuzz_http_client` | SocketHTTPClient | HTTP | 65536 |
| `fuzz_http_client_async` | SocketHTTPClient | HTTP | 65536 |
| `fuzz_http_client_pool` | SocketHTTPClient | HTTP | 65536 |
| `fuzz_http_client_retry` | SocketHTTPClient | HTTP | 65536 |
| `fuzz_http_content_type` | SocketHTTP | HTTP | 32768 |
| `fuzz_http_cookies` | SocketHTTP | HTTP | 32768 |
| `fuzz_http_cookies_simple` | SocketSimple | HTTP | 32768 |
| `fuzz_http_core` | SocketHTTP | HTTP | 32768 |
| `fuzz_http_date` | SocketHTTP | HTTP | 4096 |
| `fuzz_http_headers_collection` | SocketHTTP | HTTP | 32768 |
| `fuzz_http_server` | SocketHTTPServer | HTTP | 65536 |
| `fuzz_http_smuggling` | SocketHTTP1 | Security | 65536 |
| `fuzz_ip_parse` | SocketCommon | Validation | 4096 |
| `fuzz_iptracker` | SocketIPTracker | Security | 4096 |
| `fuzz_metrics` | SocketMetrics | Util | 4096 |
| `fuzz_new_features` | Various | Mixed | 65536 |
| `fuzz_pin_hex_parsing` | SocketTLS | TLS | 4096 |
| `fuzz_pool_dos` | SocketPool | Security | 4096 |
| `fuzz_proxy_http` | SocketProxy | Proxy | 4096 |
| `fuzz_proxy_socks4` | SocketProxy | Proxy | 4096 |
| `fuzz_proxy_socks5` | SocketProxy | Proxy | 4096 |
| `fuzz_proxy_url` | SocketProxy | Proxy | 4096 |
| `fuzz_ratelimit` | SocketRateLimit | Security | 4096 |
| `fuzz_reconnect` | SocketReconnect | Connection | 4096 |
| `fuzz_security` | Various | Security | 65536 |
| `fuzz_socketbuf` | SocketBuf | Buffer | 4096 |
| `fuzz_socketbuf_stress` | SocketBuf | Buffer | 4096 |
| `fuzz_socketdgram` | SocketDgram | UDP | 65536 |
| `fuzz_socketio` | SocketIO | I/O | 4096 |
| `fuzz_socketpoll` | SocketPoll | Event | 4096 |
| `fuzz_socketpool` | SocketPool | Pool | 4096 |
| `fuzz_ssl_path_validation` | SocketTLS | TLS | 4096 |
| `fuzz_synprotect` | SocketSYNProtect | Security | 4096 |
| `fuzz_synprotect_ip` | SocketSYNProtect | Security | 4096 |
| `fuzz_synprotect_list` | SocketSYNProtect | Security | 4096 |
| `fuzz_timer` | SocketTimer | Util | 4096 |
| `fuzz_tls_alpn` | SocketTLS | TLS | 4096 |
| `fuzz_tls_buffer_pool` | SocketTLS | TLS | 4096 |
| `fuzz_tls_cert_lookup` | SocketTLSContext | TLS | 4096 |
| `fuzz_tls_certs` | SocketTLSContext | TLS | 4096 |
| `fuzz_tls_cipher` | SocketTLSContext | TLS | 4096 |
| `fuzz_tls_config` | SocketTLSContext | TLS | 4096 |
| `fuzz_tls_context` | SocketTLSContext | TLS | 4096 |
| `fuzz_tls_crl` | SocketTLSContext | TLS | 4096 |
| `fuzz_tls_ct` | SocketTLS | TLS | 4096 |
| `fuzz_tls_error` | SocketTLS | TLS | 4096 |
| `fuzz_tls_handshake` | SocketTLS | TLS | 4096 |
| `fuzz_tls_io` | SocketTLS | TLS | 4096 |
| `fuzz_tls_key_update` | SocketTLS | TLS | 4096 |
| `fuzz_tls_ktls` | SocketTLS | TLS | 4096 |
| `fuzz_tls_ocsp` | SocketTLS | TLS | 4096 |
| `fuzz_tls_protocol_version` | SocketTLS | TLS | 4096 |
| `fuzz_tls_records` | SocketTLS | TLS | 4096 |
| `fuzz_tls_record` | SocketTLS | TLS | 4096 |
| `fuzz_tls_alert` | SocketTLS | TLS | 4096 |
| `fuzz_tls_session` | SocketTLS | TLS | 4096 |
| `fuzz_tls_shutdown` | SocketTLS | TLS | 4096 |
| `fuzz_tls_sni` | SocketTLS | TLS | 4096 |
| `fuzz_tls_verify` | SocketTLS | TLS | 4096 |
| `fuzz_tls_verify_callback` | SocketTLS | TLS | 4096 |
| `fuzz_unix_path` | SocketUnix | Validation | 4096 |
| `fuzz_uri_parse` | SocketHTTP | Validation | 4096 |
| `fuzz_utf8` | SocketUTF8 | Validation | 4096 |
| `fuzz_utf8_incremental` | SocketUTF8 | Validation | 4096 |
| `fuzz_utf8_validate` | SocketUTF8 | Validation | 4096 |
| `fuzz_websocket_handshake` | SocketWS | WebSocket | 4096 |
| `fuzz_ws_deflate` | SocketWS | WebSocket | 4096 |
| `fuzz_ws_frame` | SocketWS | WebSocket | 4096 |
| `fuzz_ws_frames` | SocketWS | WebSocket | 65536 |
| `fuzz_ws_handshake` | SocketWS | WebSocket | 4096 |

## Coverage by Module

### Core Modules

**Arena** (`fuzz_arena`):
- Arena creation with various sizes
- Allocation patterns
- Deallocation and reset
- Overflow protection
- Memory exhaustion

**Except** (`fuzz_exception`):
- Exception raising
- TRY/EXCEPT/FINALLY blocks
- Nested exception handling
- RERAISE functionality
- Thread-local exception state

### Socket Core

**Socket** (`fuzz_connect`):
- Socket creation
- Connection operations
- Timeout handling
- Error conditions

**SocketBuf** (`fuzz_socketbuf`, `fuzz_socketbuf_stress`):
- Buffer creation
- Write/read operations
- Peek/consume
- Wraparound handling
- Dynamic resizing
- Secure clear
- Mixed operations stress test

**SocketDgram** (`fuzz_socketdgram`):
- UDP socket operations
- Multicast
- Broadcast
- Message boundaries

**SocketIO** (`fuzz_socketio`):
- Vectored I/O
- Partial reads/writes
- Scatter/gather operations

### DNS Wire Format (Issue #141, #251)

**SocketDNSWire Header** (`fuzz_dns_header`):
- DNS message header parsing (RFC 1035 §4.1.1)
- ID, flags, and count field validation
- Opcode and RCODE handling
- Truncation bit (TC) edge cases

**SocketDNSWire Name** (`fuzz_dns_name`):
- Domain name compression (RFC 1035 §4.1.4)
- Label length validation
- Pointer loop detection
- Maximum name length (255 bytes)
- Label compression attacks

**SocketDNSWire Response** (`fuzz_dns_response`):
- Full DNS response parsing
- Question/Answer/Authority/Additional sections
- Resource record parsing
- RDATA validation per record type

**SocketDNSWire EDNS0** (`fuzz_dns_edns0`):
- OPT record parsing (RFC 6891)
- Extended RCODE and flags
- UDP payload size handling
- Option parsing (client subnet, cookies, EDE)

**SocketDNS Cookie** (`fuzz_dns_cookie`):
- DNS Cookie option parsing (RFC 7873)
- Client cookie validation (8 bytes)
- Server cookie validation (8-32 bytes)
- Cookie regeneration

**SocketDNSWire SOA** (`fuzz_dns_soa`):
- SOA record parsing for negative caching
- MNAME/RNAME domain name parsing
- Serial, refresh, retry, expire, minimum fields
- TTL calculation for NXDOMAIN/NODATA

### HTTP/1.1 Parsing

**SocketHTTP1 Request** (`fuzz_http1_request`):
- Request line parsing (method, URI, version)
- Header parsing
- Body mode detection
- Incremental parsing
- Parser state transitions
- Configuration variations
- Resource limits
- Keep-alive detection
- 100-continue handling
- Malformed request rejection

**SocketHTTP1 Response** (`fuzz_http1_response`):
- Status line parsing
- Response header parsing
- Body handling
- Chunked encoding
- Connection close detection

**SocketHTTP1 Chunked** (`fuzz_http1_chunked`):
- Chunk size parsing
- Chunk extension handling
- Trailer headers
- Malformed chunks
- Chunk overflow

**SocketHTTP1 Headers** (`fuzz_http1_headers`):
- Header name validation
- Header value validation
- Obs-fold handling
- Header injection prevention
- Multiple headers

**SocketHTTP1 Serialize** (`fuzz_http1_serialize`):
- Request serialization
- Response serialization
- Header serialization
- Body encoding

### HTTP/2 and HPACK

**SocketHPACK** (`fuzz_hpack`, `fuzz_hpack_decode`, `fuzz_hpack_encode`):
- HPACK decoding
- HPACK encoding
- Dynamic table manipulation
- Table size changes
- Integer encoding/decoding
- Huffman encoding/decoding
- HPACK bomb prevention

**SocketHPACK Huffman** (`fuzz_hpack_huffman`):
- Huffman decoding
- Padding validation
- Truncated sequences
- EOS symbol

**SocketHPACK Integer** (`fuzz_hpack_integer`):
- Integer prefix decoding
- Overflow handling
- Multi-byte integers

**SocketHTTP2 Frames** (`fuzz_http2_frames`, `fuzz_http2_frames_full`):
- Frame type parsing
- Frame header validation
- Payload length validation
- Stream ID handling
- Flag interpretation

**SocketHTTP2 Connection** (`fuzz_http2_connection`):
- Connection preface
- SETTINGS frames
- Flow control
- Stream management
- GOAWAY handling

**SocketHTTP2 Settings** (`fuzz_http2_settings`):
- SETTINGS payload parsing
- Setting value validation
- ACK handling

**SocketHTTP2 Headers** (`fuzz_http2_headers`):
- HEADERS frame parsing
- CONTINUATION handling
- Priority information
- Pseudo-headers

### WebSocket

**SocketWS Frames** (`fuzz_ws_frames`, `fuzz_ws_frame`):
- Frame header parsing
- Opcode validation
- Masking/unmasking
- Payload length (7/16/64-bit)
- Control frame limits
- RSV bits
- Fragment handling

**SocketWS Handshake** (`fuzz_websocket_handshake`, `fuzz_ws_handshake`):
- Upgrade request parsing
- Sec-WebSocket-Key handling
- Protocol negotiation
- Extension negotiation

**SocketWS Deflate** (`fuzz_ws_deflate`):
- Permessage-deflate
- Compression parameters
- Decompression

### TLS/DTLS

**SocketTLS Handshake** (`fuzz_tls_handshake`):
- Handshake state machine
- Non-blocking handshake
- Timeout handling
- State queries

**SocketTLS Context** (`fuzz_tls_context`, `fuzz_tls_config`):
- Context creation
- Configuration options
- Protocol version selection
- Cipher suite selection

**SocketTLS Certificates** (`fuzz_tls_certs`, `fuzz_certificate_parsing`):
- Certificate loading
- Certificate chain validation
- Certificate pinning

**SocketTLS Pinning** (`fuzz_cert_pinning`, `fuzz_pin_hex_parsing`):
- Pin parsing
- Pin validation
- Backup pins

**SocketTLS ALPN** (`fuzz_tls_alpn`):
- Protocol list parsing
- Protocol negotiation
- Callback handling

**SocketTLS Session** (`fuzz_tls_session`):
- Session caching
- Session resumption
- Session tickets

**SocketTLS CRL** (`fuzz_tls_crl`):
- CRL loading
- CRL checking
- Revocation handling

**SocketTLS OCSP** (`fuzz_tls_ocsp`):
- OCSP stapling
- OCSP response parsing
- Status checking

**SocketDTLS** (`fuzz_dtls_*`):
- Cookie exchange
- Retransmission
- MTU handling
- DoS protection

### Proxy

**SocketProxy HTTP** (`fuzz_proxy_http`):
- HTTP CONNECT parsing
- Authentication
- Response handling

**SocketProxy SOCKS** (`fuzz_proxy_socks4`, `fuzz_proxy_socks5`):
- SOCKS4/4a parsing
- SOCKS5 authentication
- Address types (IPv4, IPv6, domain)

**SocketProxy URL** (`fuzz_proxy_url`):
- Proxy URL parsing
- Credential extraction
- Scheme detection

### Validation

**SocketUTF8** (`fuzz_utf8`, `fuzz_utf8_incremental`, `fuzz_utf8_validate`):
- UTF-8 validation
- Overlong sequence detection
- Surrogate rejection
- Invalid code point detection
- Incremental validation

**IP Parsing** (`fuzz_ip_parse`, `fuzz_cidr_parse`, `fuzz_address_parse`):
- IPv4 parsing
- IPv6 parsing
- CIDR notation
- Address validation

**URI Parsing** (`fuzz_uri_parse`):
- URI component parsing
- Scheme detection
- Authority parsing
- Path normalization

**Unix Path** (`fuzz_unix_path`):
- Unix socket path validation
- Abstract socket names
- Path length limits

### Security Features

**HTTP Smuggling** (`fuzz_http_smuggling`):
- CL.TE attacks
- TE.CL attacks
- TE.TE obfuscation
- Duplicate headers
- Header injection
- Chunk attacks

**Rate Limiting** (`fuzz_ratelimit`):
- Token bucket algorithm
- Rate calculations
- Burst handling

**IP Tracking** (`fuzz_iptracker`):
- Per-IP connection tracking
- Limit enforcement
- Hash collisions

**SYN Protection** (`fuzz_synprotect`):
- Reputation system
- Challenge generation
- Action decisions

**Pool DoS** (`fuzz_pool_dos`):
- Resource exhaustion
- Connection limits
- Drain handling

### Utility Modules

**SocketTimer** (`fuzz_timer`):
- Timer creation
- Expiration handling
- Cancellation

**SocketMetrics** (`fuzz_metrics`):
- Metric recording
- Counter operations
- Gauge operations

## Attack Vector Coverage

### Buffer Attacks
| Attack | Fuzzer(s) |
|--------|-----------|
| Buffer overflow | All buffer/parser fuzzers |
| Integer overflow in length | `fuzz_http1_*`, `fuzz_http2_*`, `fuzz_hpack_*` |
| Stack buffer overflow | All fuzzers (assert-based) |
| Heap buffer overflow | All fuzzers with Arena |

### Injection Attacks
| Attack | Fuzzer(s) |
|--------|-----------|
| Header injection | `fuzz_http1_*`, `fuzz_http_smuggling` |
| CRLF injection | `fuzz_http1_*`, `fuzz_http_smuggling` |
| Null byte injection | `fuzz_http1_*`, `fuzz_dns_inj` |
| Command injection | `fuzz_proxy_*` |

### Smuggling Attacks
| Attack | Fuzzer(s) |
|--------|-----------|
| CL.TE | `fuzz_http_smuggling` |
| TE.CL | `fuzz_http_smuggling` |
| TE.TE obfuscation | `fuzz_http_smuggling` |
| Duplicate CL | `fuzz_http_smuggling`, `fuzz_http1_request` |
| Obs-fold | `fuzz_http_smuggling`, `fuzz_http1_headers` |

### DoS Attacks
| Attack | Fuzzer(s) |
|--------|-----------|
| HPACK bomb | `fuzz_hpack`, `fuzz_hpack_decode` |
| Huge allocations | All fuzzers with size parameters |
| Resource exhaustion | `fuzz_pool_dos`, `fuzz_socketpool` |
| Slowloris | `fuzz_http1_*` (incremental parsing) |
| Hash collision | `fuzz_iptracker` |
| Fragment bomb | `fuzz_ws_frames` |

### Protocol Attacks
| Attack | Fuzzer(s) |
|--------|-----------|
| State machine corruption | All state machine fuzzers |
| Invalid state transitions | `fuzz_tls_handshake`, `fuzz_ws_frames` |
| Protocol downgrade | `fuzz_tls_protocol_version` |
| Renegotiation attack | `fuzz_tls_*` |

### Encoding Attacks
| Attack | Fuzzer(s) |
|--------|-----------|
| Overlong UTF-8 | `fuzz_utf8*` |
| Surrogate pairs | `fuzz_utf8*` |
| Invalid Huffman | `fuzz_hpack_huffman` |
| Base64 malformed | `fuzz_base64_decode` |
| Hex decode malformed | `fuzz_hex_decode` |

## Running Fuzzers

### Quick Start
```bash
# Configure with fuzzing enabled (requires Clang)
CC=clang cmake -S . -B build -DENABLE_FUZZING=ON

# Build ALL fuzzers (~100 harnesses)
cmake --build build --target fuzzers -j$(nproc)

# Or build a single fuzzer
cmake --build build --target fuzz_http1_request -j$(nproc)

# List available fuzzers
ls build/fuzz_*

# Run single fuzzer
cd build && ./fuzz_http1_request corpus/http1_request/ -fork=16 -max_len=65536
```

### Recommended Parameters by Category

**Parser Fuzzers** (HTTP, HPACK, WebSocket):
```bash
./fuzz_parser corpus/ -fork=16 -max_len=65536 -rss_limit_mb=2048
```

**Buffer Fuzzers**:
```bash
./fuzz_buffer corpus/ -fork=8 -max_len=4096 -rss_limit_mb=512
```

**TLS Fuzzers**:
```bash
./fuzz_tls corpus/ -fork=8 -max_len=4096 -timeout=60
```

**Security Fuzzers**:
```bash
./fuzz_security corpus/ -fork=16 -max_len=65536 -rss_limit_mb=4096
```

### Continuous Fuzzing
```bash
# Run for 24 hours
./fuzz_target corpus/ -fork=16 -max_total_time=86400

# Run until N new crashes
./fuzz_target corpus/ -fork=16 -max_crashes=10

# Minimize corpus
./fuzz_target -merge=1 corpus_minimal/ corpus/
```

## Adding New Fuzzers

### Checklist
1. [ ] Follow file structure template from `fuzzing-patterns.md`
2. [ ] Use appropriate harness template from `fuzzing-harnesses.md`
3. [ ] Add to CMakeLists.txt fuzzer list
4. [ ] Create initial corpus directory
5. [ ] Document in this coverage file
6. [ ] Test with sanitizers enabled

### CMakeLists.txt Entry
```cmake
if(ENABLE_FUZZING)
    add_executable(fuzz_new_module src/fuzz/fuzz_new_module.c)
    target_link_libraries(fuzz_new_module PRIVATE socket_lib)
    target_compile_options(fuzz_new_module PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_options(fuzz_new_module PRIVATE -fsanitize=fuzzer,address,undefined)
endif()
```

### Initial Corpus
```bash
# Create corpus directory
mkdir -p corpus/new_module

# Add seed files
echo "minimal valid input" > corpus/new_module/seed_valid
echo -e "\x00\x01\x02" > corpus/new_module/seed_binary
```

## Fuzzer Dependencies

### Required Features
| Fuzzer | Required Feature |
|--------|------------------|
| `fuzz_tls_*` | `SOCKET_HAS_TLS` |
| `fuzz_dtls_*` | `SOCKET_HAS_TLS` |
| `fuzz_http1_compression` | `ENABLE_HTTP_COMPRESSION` |
| `fuzz_ws_deflate` | `ENABLE_HTTP_COMPRESSION` |
| `fuzz_async` | Platform-specific async I/O |

### Conditional Compilation
```c
#if SOCKET_HAS_TLS
/* TLS fuzzer implementation */
#else
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    (void)data; (void)size;
    return 0;
}
#endif
```
