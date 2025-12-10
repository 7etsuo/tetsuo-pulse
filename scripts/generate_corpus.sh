#!/bin/bash
#
# generate_corpus.sh - Generate seed corpus files for all fuzzers
#
# This script creates seed corpus directories and files to give libFuzzer
# a starting point for each fuzzer harness. Seeds are minimal valid inputs
# that exercise the target functionality.
#
# Usage: ./scripts/generate_corpus.sh [build_dir]
#   build_dir: Optional path to build directory (default: build_fuzz)

set -e

BUILD_DIR="${1:-build_fuzz}"
CORPUS_BASE="${BUILD_DIR}/corpus"

echo "Generating seed corpus in ${CORPUS_BASE}..."

# Create base corpus directory
mkdir -p "${CORPUS_BASE}"

# ============================================================================
# HTTP/1.1 Request Parser Seeds
# ============================================================================
HTTP1_REQ="${CORPUS_BASE}/http1_request"
mkdir -p "${HTTP1_REQ}"

# Valid GET request
echo -ne "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n" > "${HTTP1_REQ}/get_simple"

# POST with body
echo -ne "POST /api HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello" > "${HTTP1_REQ}/post_body"

# Chunked request
echo -ne "POST /api HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n" > "${HTTP1_REQ}/chunked"

# Multiple headers
echo -ne "GET / HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\nUser-Agent: fuzzer\r\nConnection: keep-alive\r\n\r\n" > "${HTTP1_REQ}/multi_headers"

# ============================================================================
# HTTP/1.1 Response Parser Seeds
# ============================================================================
HTTP1_RESP="${CORPUS_BASE}/http1_response"
mkdir -p "${HTTP1_RESP}"

# 200 OK
echo -ne "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello" > "${HTTP1_RESP}/ok_simple"

# 404 Not Found
echo -ne "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n" > "${HTTP1_RESP}/not_found"

# Redirect
echo -ne "HTTP/1.1 302 Found\r\nLocation: /new\r\nContent-Length: 0\r\n\r\n" > "${HTTP1_RESP}/redirect"

# Set-Cookie
echo -ne "HTTP/1.1 200 OK\r\nSet-Cookie: session=abc123; Path=/; HttpOnly\r\nContent-Length: 0\r\n\r\n" > "${HTTP1_RESP}/setcookie"

# Chunked response
echo -ne "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n" > "${HTTP1_RESP}/chunked"

# ============================================================================
# HTTP/2 Frame Seeds
# ============================================================================
HTTP2="${CORPUS_BASE}/http2_frames"
mkdir -p "${HTTP2}"

# SETTINGS frame (empty)
printf '\x00\x00\x00\x04\x00\x00\x00\x00\x00' > "${HTTP2}/settings_empty"

# SETTINGS frame with values
printf '\x00\x00\x06\x04\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x64' > "${HTTP2}/settings_streams"

# PING frame
printf '\x00\x00\x08\x06\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08' > "${HTTP2}/ping"

# GOAWAY frame
printf '\x00\x00\x08\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > "${HTTP2}/goaway"

# WINDOW_UPDATE frame
printf '\x00\x00\x04\x08\x00\x00\x00\x00\x00\x00\x00\x10\x00' > "${HTTP2}/window_update"

# RST_STREAM frame
printf '\x00\x00\x04\x03\x00\x00\x00\x00\x01\x00\x00\x00\x08' > "${HTTP2}/rst_stream"

# ============================================================================
# HTTP Server Seeds
# ============================================================================
HTTP_SERVER="${CORPUS_BASE}/http_server"
mkdir -p "${HTTP_SERVER}"

# Copy HTTP/1.1 request seeds
cp "${HTTP1_REQ}"/* "${HTTP_SERVER}/" 2>/dev/null || true

# WebSocket upgrade
echo -ne "GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n" > "${HTTP_SERVER}/ws_upgrade"

# H2C upgrade
echo -ne "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\nHTTP2-Settings: AAMAAABkAAQAoAAAAAIAAAAA\r\n\r\n" > "${HTTP_SERVER}/h2c_upgrade"

# ============================================================================
# HTTP Client Seeds (same as response)
# ============================================================================
HTTP_CLIENT="${CORPUS_BASE}/http_client"
mkdir -p "${HTTP_CLIENT}"
cp "${HTTP1_RESP}"/* "${HTTP_CLIENT}/" 2>/dev/null || true

# ============================================================================
# WebSocket Frame Seeds
# ============================================================================
WS="${CORPUS_BASE}/ws_frames"
mkdir -p "${WS}"

# Text frame (unmasked, server sends)
printf '\x81\x05hello' > "${WS}/text_simple"

# Binary frame
printf '\x82\x05\x01\x02\x03\x04\x05' > "${WS}/binary_simple"

# Ping frame
printf '\x89\x00' > "${WS}/ping"

# Pong frame
printf '\x8a\x00' > "${WS}/pong"

# Close frame (code 1000)
printf '\x88\x02\x03\xe8' > "${WS}/close_normal"

# Close frame with reason
printf '\x88\x08\x03\xe8Normal' > "${WS}/close_reason"

# Masked text frame (client sends)
printf '\x81\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58' > "${WS}/text_masked"

# Fragmented message
printf '\x01\x05hello' > "${WS}/frag_first"
printf '\x80\x05world' > "${WS}/frag_last"

# ============================================================================
# HPACK Seeds
# ============================================================================
HPACK="${CORPUS_BASE}/hpack"
mkdir -p "${HPACK}"

# Static table reference
printf '\x82' > "${HPACK}/static_method_get"

# Indexed header
printf '\xc0' > "${HPACK}/indexed_high"

# Literal with indexing
printf '\x40\x0a\x63\x75\x73\x74\x6f\x6d\x2d\x6b\x65\x79\x0d\x63\x75\x73\x74\x6f\x6d\x2d\x76\x61\x6c\x75\x65' > "${HPACK}/literal_indexed"

# Huffman encoded
printf '\x82\x86\x84\x41\x8a\x08\x9d\x5c\x0b\x81\x70\xdc\x78\x0f\x03' > "${HPACK}/huffman"

# ============================================================================
# DNS Seeds
# ============================================================================
DNS="${CORPUS_BASE}/dns"
mkdir -p "${DNS}"

# Simple hostname
echo -n "localhost" > "${DNS}/localhost"
echo -n "example.com" > "${DNS}/example_com"
echo -n "test.example.org" > "${DNS}/subdomain"

# IPv4 address (no DNS needed)
echo -n "127.0.0.1" > "${DNS}/ipv4"
echo -n "192.168.1.1" > "${DNS}/ipv4_private"

# IPv6 address
echo -n "::1" > "${DNS}/ipv6_loopback"
echo -n "2001:db8::1" > "${DNS}/ipv6"

# ============================================================================
# SYN Protection Seeds
# ============================================================================
SYN="${CORPUS_BASE}/synprotect"
mkdir -p "${SYN}"

# Random bytes for config fuzzing
dd if=/dev/urandom bs=64 count=1 of="${SYN}/random_config" 2>/dev/null

# IP addresses
echo -n "192.168.1.1" > "${SYN}/ipv4"
echo -n "10.0.0.1" > "${SYN}/ipv4_private"
echo -n "2001:db8::1" > "${SYN}/ipv6"

# CIDR notation
echo -n "192.168.1.0/24" > "${SYN}/cidr_24"
echo -n "10.0.0.0/8" > "${SYN}/cidr_8"

# ============================================================================
# Rate Limit Seeds
# ============================================================================
RATELIMIT="${CORPUS_BASE}/ratelimit"
mkdir -p "${RATELIMIT}"

# Configuration bytes
dd if=/dev/urandom bs=32 count=1 of="${RATELIMIT}/random_config" 2>/dev/null

# ============================================================================
# Socket Buffer Seeds
# ============================================================================
SOCKETBUF="${CORPUS_BASE}/socketbuf"
mkdir -p "${SOCKETBUF}"

# Various sized data
echo -n "x" > "${SOCKETBUF}/1byte"
dd if=/dev/urandom bs=100 count=1 of="${SOCKETBUF}/100bytes" 2>/dev/null
dd if=/dev/urandom bs=1024 count=1 of="${SOCKETBUF}/1kb" 2>/dev/null

# ============================================================================
# Metrics Seeds
# ============================================================================
METRICS="${CORPUS_BASE}/metrics"
mkdir -p "${METRICS}"

# Random operation sequences
dd if=/dev/urandom bs=64 count=1 of="${METRICS}/random_ops" 2>/dev/null

# ============================================================================
# Security Seeds
# ============================================================================
SECURITY="${CORPUS_BASE}/security"
mkdir -p "${SECURITY}"

# Size values
printf '\xff\xff\xff\xff\xff\xff\xff\xff' > "${SECURITY}/size_max"
printf '\x00\x00\x00\x00\x00\x00\x00\x00' > "${SECURITY}/size_zero"
printf '\x00\x00\x00\x00\x00\x00\x00\x01' > "${SECURITY}/size_one"

# Random config
dd if=/dev/urandom bs=64 count=1 of="${SECURITY}/random" 2>/dev/null

# ============================================================================
# Pool DoS Seeds
# ============================================================================
POOL="${CORPUS_BASE}/pool_dos"
mkdir -p "${POOL}"

# Operation sequences
dd if=/dev/urandom bs=64 count=1 of="${POOL}/random_ops" 2>/dev/null

# ============================================================================
# UTF-8 Seeds
# ============================================================================
UTF8="${CORPUS_BASE}/utf8"
mkdir -p "${UTF8}"

# Valid ASCII
echo -n "Hello World" > "${UTF8}/ascii"

# Valid UTF-8 multi-byte
echo -n "Héllo Wörld" > "${UTF8}/latin"
echo -n "こんにちは" > "${UTF8}/japanese"
echo -n "🎉🚀💻" > "${UTF8}/emoji"

# Edge cases
printf '\xc0\x80' > "${UTF8}/overlong_null"
printf '\xed\xa0\x80' > "${UTF8}/surrogate"
printf '\xf4\x90\x80\x80' > "${UTF8}/over_max"
printf '\x80' > "${UTF8}/continuation_only"

# ============================================================================
# Proxy Seeds
# ============================================================================
PROXY="${CORPUS_BASE}/proxy"
mkdir -p "${PROXY}"

# SOCKS5 method response
printf '\x05\x00' > "${PROXY}/socks5_method"

# SOCKS5 connect response
printf '\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50' > "${PROXY}/socks5_connect"

# SOCKS4 response
printf '\x00\x5a\x00\x50\x7f\x00\x00\x01' > "${PROXY}/socks4_ok"

# ============================================================================
# TLS Seeds (if TLS enabled)
# ============================================================================
TLS="${CORPUS_BASE}/tls"
mkdir -p "${TLS}"

# Random bytes for TLS operations
dd if=/dev/urandom bs=128 count=1 of="${TLS}/random" 2>/dev/null

# Hostname for SNI
echo -n "example.com" > "${TLS}/sni_host"

# ALPN protocol
echo -n "h2" > "${TLS}/alpn_h2"
echo -n "http/1.1" > "${TLS}/alpn_http1"

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "Corpus generation complete!"
echo ""
echo "Directories created:"
find "${CORPUS_BASE}" -type d | sort | while read -r dir; do
    count=$(find "$dir" -maxdepth 1 -type f | wc -l)
    echo "  ${dir}: ${count} files"
done

echo ""
echo "To use with fuzzer:"
echo "  ./fuzz_http1_request ${HTTP1_REQ}"
echo "  ./fuzz_http_server ${HTTP_SERVER}"
echo "  ./fuzz_ws_frames ${WS}"
echo "  etc."
