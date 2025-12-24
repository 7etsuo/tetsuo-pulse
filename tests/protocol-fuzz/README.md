# Protocol-Level Fuzzing

External protocol fuzzers for testing network protocol behavior. These complement the in-process libFuzzer harnesses in `src/fuzz/`.

## Overview

| Tool | Target | What it Tests |
|------|--------|---------------|
| [http2fuzz](https://github.com/c0nrad/http2fuzz) | HTTP/2 server | Frame parsing, state machine, flow control |
| [tlsfuzzer](https://github.com/tlsfuzzer/tlsfuzzer) | TLS server | RFC compliance, known vulnerabilities |
| [dns-fuzz-server](https://github.com/sischkg/dns-fuzz-server) | DNS resolver | Response parsing, malformed packets |

## Comparison with libFuzzer

| Approach | Speed | Finds | Coverage |
|----------|-------|-------|----------|
| **libFuzzer** (src/fuzz/) | Very fast (millions/sec) | Memory bugs, crashes | Code-guided |
| **Protocol fuzzers** (this dir) | Slow (network I/O) | Logic bugs, RFC violations | Protocol-guided |

Both approaches are valuable and complementary.

## Prerequisites

### Common

```bash
# Build the harnesses
cmake -S . -B build \
    -DENABLE_TLS=ON \
    -DBUILD_PROTOCOL_FUZZ_HARNESSES=ON

cmake --build build -j$(nproc)
```

### http2fuzz

```bash
# Requires Go
sudo apt install golang-go  # Debian/Ubuntu
brew install go              # macOS

# Install http2fuzz
go install github.com/c0nrad/http2fuzz@latest
```

### tlsfuzzer

```bash
# Requires Python 3
pip3 install --user tlsfuzzer tlslite-ng
```

### dns-fuzz-server

```bash
# Cloned and built automatically by run script
# Manual install:
git clone https://github.com/sischkg/dns-fuzz-server.git
cd dns-fuzz-server && cmake . && make
```

## Usage

### HTTP/2 Fuzzing

```bash
# Run http2fuzz against our HTTP/2 server
./tests/protocol-fuzz/http2/run_http2fuzz.sh [port]

# Or manually:
./build/http2_server_harness 8443 &
http2fuzz -target=localhost:8443 -fuzz-delay=50
```

### TLS Fuzzing

```bash
# Run tlsfuzzer test suite
./tests/protocol-fuzz/tls/run_tlsfuzzer.sh [port] [test-name]

# Or manually:
./build/tls_server_harness 4433 &
python3 -m tlsfuzzer.scripts.test-tls13-conversation -h localhost -p 4433

# With RSA certificate (some tests require RSA):
./build/tls_server_harness 4433 --rsa &
```

### DNS Fuzzing

```bash
# Run dns-fuzz-server against our resolver
./tests/protocol-fuzz/dns/run_dnsfuzz.sh [iterations]

# Or manually:
dns-fuzz-server --address 127.0.0.1 --port 10053 &
./build/dns_resolver_harness -s 127.0.0.1 -p 10053 -n 1000
```

## Harness Details

### http2_server_harness

A minimal HTTP/2 server that:
- Accepts TLS connections with ALPN (h2)
- Parses HTTP/2 frames
- Responds to SETTINGS, PING, HEADERS
- Sends GOAWAY on protocol errors

### tls_server_harness

A TLS echo server that:
- Supports TLS 1.2 and 1.3
- Uses EC (P-256) or RSA certificates
- Echoes received data back
- Handles session resumption

### dns_resolver_harness

A DNS client that:
- Sends various query types (A, AAAA, CNAME, etc.)
- Connects to a specified DNS server
- Logs query results and errors

## Finding Bugs

When a fuzzer finds an issue:

1. **http2fuzz**: Check harness stderr for frame details
2. **tlsfuzzer**: Script output shows specific test failure
3. **dns-fuzz-server**: Resolver harness logs the malformed response

Crashes are caught by the harness process exiting unexpectedly. Run with sanitizers for memory bug detection:

```bash
cmake -S . -B build \
    -DENABLE_TLS=ON \
    -DENABLE_SANITIZERS=ON \
    -DBUILD_PROTOCOL_FUZZ_HARNESSES=ON
```

## Recommended Test Duration

| Fuzzer | Quick Check | Thorough |
|--------|-------------|----------|
| http2fuzz | 1 minute | 1 hour |
| tlsfuzzer | 5 minutes (basic tests) | 30 minutes (all tests) |
| dns-fuzz-server | 1000 iterations | 100000 iterations |

## Troubleshooting

### http2fuzz: "connection refused"

Ensure the harness is running and TLS is working:
```bash
openssl s_client -connect localhost:8443 -alpn h2
```

### tlsfuzzer: "test not found"

List available tests:
```bash
python3 -c "from tlsfuzzer import scripts; print(dir(scripts))"
```

### dns-fuzz-server: build fails

Requires CMake 3.10+ and a C++17 compiler:
```bash
sudo apt install cmake g++
```
