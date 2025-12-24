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
# Core/Foundation Seeds
# ============================================================================

# Arena allocator
ARENA="${CORPUS_BASE}/arena"
mkdir -p "${ARENA}"
printf '\x01\x00\x10' > "${ARENA}/small_alloc"
printf '\x02\x00\x00\x10\x00' > "${ARENA}/medium_alloc"
printf '\x03\x01\x00\x00\x00' > "${ARENA}/large_alloc"
dd if=/dev/urandom bs=64 count=1 of="${ARENA}/random_ops" 2>/dev/null

# Exception handling
EXCEPT="${CORPUS_BASE}/exception"
mkdir -p "${EXCEPT}"
printf '\x00' > "${EXCEPT}/no_exception"
printf '\x01' > "${EXCEPT}/raise"
printf '\x02' > "${EXCEPT}/nested"
printf '\x03\x01\x02' > "${EXCEPT}/multi_level"
dd if=/dev/urandom bs=32 count=1 of="${EXCEPT}/random" 2>/dev/null

# Exception unwind
EXCEPT_UNWIND="${CORPUS_BASE}/except_unwind"
mkdir -p "${EXCEPT_UNWIND}"
printf '\x00\x01\x02\x03' > "${EXCEPT_UNWIND}/basic"
printf '\x01\x02\x03\x04\x05\x06\x07\x08' > "${EXCEPT_UNWIND}/complex"
dd if=/dev/urandom bs=64 count=1 of="${EXCEPT_UNWIND}/random" 2>/dev/null

# Timer
TIMER="${CORPUS_BASE}/timer"
mkdir -p "${TIMER}"
printf '\x01\x00\x00\x00\x64' > "${TIMER}/short_timeout"
printf '\x02\x00\x00\x03\xe8' > "${TIMER}/1sec"
printf '\x03\x00\x00\x00\x01' > "${TIMER}/minimal"
dd if=/dev/urandom bs=32 count=1 of="${TIMER}/random" 2>/dev/null

# Async I/O
ASYNC="${CORPUS_BASE}/async"
mkdir -p "${ASYNC}"
printf '\x01\x00\x00\x00\x40' > "${ASYNC}/small_io"
printf '\x02\x00\x00\x04\x00' > "${ASYNC}/1kb_io"
dd if=/dev/urandom bs=64 count=1 of="${ASYNC}/random" 2>/dev/null

# ============================================================================
# Socket Seeds
# ============================================================================

# Socket buffer
SOCKETBUF="${CORPUS_BASE}/socketbuf"
mkdir -p "${SOCKETBUF}"
echo -n "x" > "${SOCKETBUF}/1byte"
dd if=/dev/urandom bs=100 count=1 of="${SOCKETBUF}/100bytes" 2>/dev/null
dd if=/dev/urandom bs=1024 count=1 of="${SOCKETBUF}/1kb" 2>/dev/null
dd if=/dev/urandom bs=4096 count=1 of="${SOCKETBUF}/4kb" 2>/dev/null

# Socket buffer stress
SOCKETBUF_STRESS="${CORPUS_BASE}/socketbuf_stress"
mkdir -p "${SOCKETBUF_STRESS}"
dd if=/dev/urandom bs=256 count=1 of="${SOCKETBUF_STRESS}/stress1" 2>/dev/null
dd if=/dev/urandom bs=512 count=1 of="${SOCKETBUF_STRESS}/stress2" 2>/dev/null

# Socket I/O
SOCKETIO="${CORPUS_BASE}/socketio"
mkdir -p "${SOCKETIO}"
printf '\x01\x00\x00\x00\x10' > "${SOCKETIO}/read_16"
printf '\x02\x00\x00\x01\x00' > "${SOCKETIO}/write_256"
dd if=/dev/urandom bs=64 count=1 of="${SOCKETIO}/random" 2>/dev/null

# Socket poll
SOCKETPOLL="${CORPUS_BASE}/socketpoll"
mkdir -p "${SOCKETPOLL}"
printf '\x01\x00\x01' > "${SOCKETPOLL}/single_fd"
printf '\x02\x00\x10' > "${SOCKETPOLL}/multi_fd"
printf '\x03\x01\x00\x00\x00\x64' > "${SOCKETPOLL}/with_timeout"
dd if=/dev/urandom bs=64 count=1 of="${SOCKETPOLL}/random" 2>/dev/null

# Socket pool
SOCKETPOOL="${CORPUS_BASE}/socketpool"
mkdir -p "${SOCKETPOOL}"
printf '\x01\x00\x04' > "${SOCKETPOOL}/4_conns"
printf '\x02\x00\x10' > "${SOCKETPOOL}/16_conns"
printf '\x03\x01\x00\x00\x00\x64' > "${SOCKETPOOL}/with_config"
dd if=/dev/urandom bs=128 count=1 of="${SOCKETPOOL}/random" 2>/dev/null

# Socket datagram (UDP)
SOCKETDGRAM="${CORPUS_BASE}/socketdgram"
mkdir -p "${SOCKETDGRAM}"
echo -n "hello" > "${SOCKETDGRAM}/simple"
dd if=/dev/urandom bs=512 count=1 of="${SOCKETDGRAM}/max_dgram" 2>/dev/null
printf '\x00' > "${SOCKETDGRAM}/empty"

# Connect
CONNECT="${CORPUS_BASE}/connect"
mkdir -p "${CONNECT}"
echo -n "127.0.0.1:8080" > "${CONNECT}/ipv4_port"
echo -n "[::1]:8080" > "${CONNECT}/ipv6_port"
echo -n "localhost:80" > "${CONNECT}/hostname"
printf '\x01\x7f\x00\x00\x01\x1f\x90' > "${CONNECT}/binary"

# Reconnect
RECONNECT="${CORPUS_BASE}/reconnect"
mkdir -p "${RECONNECT}"
printf '\x01\x00\x03' > "${RECONNECT}/3_retries"
printf '\x02\x00\x00\x03\xe8' > "${RECONNECT}/1sec_delay"
dd if=/dev/urandom bs=32 count=1 of="${RECONNECT}/random" 2>/dev/null

# Happy Eyeballs
HAPPY="${CORPUS_BASE}/happy_eyeballs"
mkdir -p "${HAPPY}"
echo -n "example.com" > "${HAPPY}/hostname"
echo -n "localhost" > "${HAPPY}/localhost"
printf '\x01\x00\x00\x00\xfa' > "${HAPPY}/250ms"
dd if=/dev/urandom bs=32 count=1 of="${HAPPY}/random" 2>/dev/null

# Unix path
UNIX_PATH="${CORPUS_BASE}/unix_path"
mkdir -p "${UNIX_PATH}"
echo -n "/tmp/socket.sock" > "${UNIX_PATH}/simple"
echo -n "/var/run/app.sock" > "${UNIX_PATH}/var_run"
echo -n "@abstract" > "${UNIX_PATH}/abstract"
printf '\x00abstract' > "${UNIX_PATH}/abstract_null"

# ============================================================================
# Address/IP Parsing Seeds
# ============================================================================

# IP parse
IP_PARSE="${CORPUS_BASE}/ip_parse"
mkdir -p "${IP_PARSE}"
echo -n "127.0.0.1" > "${IP_PARSE}/ipv4_loopback"
echo -n "192.168.1.1" > "${IP_PARSE}/ipv4_private"
echo -n "255.255.255.255" > "${IP_PARSE}/ipv4_broadcast"
echo -n "0.0.0.0" > "${IP_PARSE}/ipv4_any"
echo -n "::1" > "${IP_PARSE}/ipv6_loopback"
echo -n "::" > "${IP_PARSE}/ipv6_any"
echo -n "2001:db8::1" > "${IP_PARSE}/ipv6_doc"
echo -n "::ffff:192.168.1.1" > "${IP_PARSE}/ipv4_mapped"
echo -n "fe80::1%eth0" > "${IP_PARSE}/ipv6_scoped"

# Address parse
ADDR_PARSE="${CORPUS_BASE}/address_parse"
mkdir -p "${ADDR_PARSE}"
echo -n "127.0.0.1:8080" > "${ADDR_PARSE}/ipv4_port"
echo -n "[::1]:8080" > "${ADDR_PARSE}/ipv6_port"
echo -n "example.com:443" > "${ADDR_PARSE}/host_port"
echo -n "localhost" > "${ADDR_PARSE}/host_only"
echo -n ":8080" > "${ADDR_PARSE}/port_only"

# CIDR parse
CIDR="${CORPUS_BASE}/cidr_parse"
mkdir -p "${CIDR}"
echo -n "192.168.1.0/24" > "${CIDR}/class_c"
echo -n "10.0.0.0/8" > "${CIDR}/class_a"
echo -n "172.16.0.0/12" > "${CIDR}/class_b"
echo -n "0.0.0.0/0" > "${CIDR}/default"
echo -n "2001:db8::/32" > "${CIDR}/ipv6"
echo -n "::1/128" > "${CIDR}/ipv6_host"

# IP tracker
IPTRACKER="${CORPUS_BASE}/iptracker"
mkdir -p "${IPTRACKER}"
printf '\x01\x7f\x00\x00\x01' > "${IPTRACKER}/add_ipv4"
printf '\x02\x7f\x00\x00\x01' > "${IPTRACKER}/check_ipv4"
dd if=/dev/urandom bs=32 count=1 of="${IPTRACKER}/random" 2>/dev/null

# ============================================================================
# HTTP/1.1 Seeds
# ============================================================================

# HTTP/1.1 Request Parser
HTTP1_REQ="${CORPUS_BASE}/http1_request"
mkdir -p "${HTTP1_REQ}"
echo -ne "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n" > "${HTTP1_REQ}/get_simple"
echo -ne "POST /api HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello" > "${HTTP1_REQ}/post_body"
echo -ne "POST /api HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n" > "${HTTP1_REQ}/chunked"
echo -ne "GET / HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\nUser-Agent: fuzzer\r\nConnection: keep-alive\r\n\r\n" > "${HTTP1_REQ}/multi_headers"
echo -ne "HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n" > "${HTTP1_REQ}/head"
echo -ne "OPTIONS * HTTP/1.1\r\nHost: localhost\r\n\r\n" > "${HTTP1_REQ}/options"
echo -ne "DELETE /resource HTTP/1.1\r\nHost: localhost\r\n\r\n" > "${HTTP1_REQ}/delete"
echo -ne "PUT /resource HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\ndata" > "${HTTP1_REQ}/put"

# HTTP/1.1 Response Parser
HTTP1_RESP="${CORPUS_BASE}/http1_response"
mkdir -p "${HTTP1_RESP}"
echo -ne "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello" > "${HTTP1_RESP}/ok_simple"
echo -ne "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n" > "${HTTP1_RESP}/not_found"
echo -ne "HTTP/1.1 302 Found\r\nLocation: /new\r\nContent-Length: 0\r\n\r\n" > "${HTTP1_RESP}/redirect"
echo -ne "HTTP/1.1 200 OK\r\nSet-Cookie: session=abc123; Path=/; HttpOnly\r\nContent-Length: 0\r\n\r\n" > "${HTTP1_RESP}/setcookie"
echo -ne "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n" > "${HTTP1_RESP}/chunked"
echo -ne "HTTP/1.1 204 No Content\r\n\r\n" > "${HTTP1_RESP}/no_content"
echo -ne "HTTP/1.1 304 Not Modified\r\n\r\n" > "${HTTP1_RESP}/not_modified"
echo -ne "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\n\r\nerror" > "${HTTP1_RESP}/server_error"

# HTTP/1.1 Headers
HTTP1_HEADERS="${CORPUS_BASE}/http1_headers"
mkdir -p "${HTTP1_HEADERS}"
echo -ne "Content-Type: application/json\r\n" > "${HTTP1_HEADERS}/content_type"
echo -ne "Accept-Encoding: gzip, deflate, br\r\n" > "${HTTP1_HEADERS}/accept_encoding"
echo -ne "Cache-Control: max-age=3600\r\n" > "${HTTP1_HEADERS}/cache_control"
echo -ne "X-Custom-Header: value\r\n" > "${HTTP1_HEADERS}/custom"

# HTTP/1.1 Chunked
HTTP1_CHUNKED="${CORPUS_BASE}/http1_chunked"
mkdir -p "${HTTP1_CHUNKED}"
echo -ne "5\r\nhello\r\n0\r\n\r\n" > "${HTTP1_CHUNKED}/simple"
echo -ne "5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n" > "${HTTP1_CHUNKED}/multi"
echo -ne "0\r\n\r\n" > "${HTTP1_CHUNKED}/empty"
echo -ne "a\r\n0123456789\r\n0\r\nTrailer: value\r\n\r\n" > "${HTTP1_CHUNKED}/with_trailer"

# HTTP/1.1 Compression
HTTP1_COMP="${CORPUS_BASE}/http1_compression"
mkdir -p "${HTTP1_COMP}"
printf '\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\xcb\x48\xcd\xc9\xc9\x07\x00\x86\xa6\x10\x36\x05\x00\x00\x00' > "${HTTP1_COMP}/gzip"
printf '\x78\x9c\xcb\x48\xcd\xc9\xc9\x07\x00\x06\x2c\x02\x15' > "${HTTP1_COMP}/deflate"
dd if=/dev/urandom bs=64 count=1 of="${HTTP1_COMP}/random" 2>/dev/null

# HTTP/1.1 Serialize
HTTP1_SER="${CORPUS_BASE}/http1_serialize"
mkdir -p "${HTTP1_SER}"
printf '\x01GET\x00/\x00' > "${HTTP1_SER}/get"
printf '\x02POST\x00/api\x00' > "${HTTP1_SER}/post"
dd if=/dev/urandom bs=32 count=1 of="${HTTP1_SER}/random" 2>/dev/null

# ============================================================================
# HTTP/2 Seeds
# ============================================================================

# HTTP/2 Frames
HTTP2="${CORPUS_BASE}/http2_frames"
mkdir -p "${HTTP2}"
printf '\x00\x00\x00\x04\x00\x00\x00\x00\x00' > "${HTTP2}/settings_empty"
printf '\x00\x00\x06\x04\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x64' > "${HTTP2}/settings_streams"
printf '\x00\x00\x08\x06\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08' > "${HTTP2}/ping"
printf '\x00\x00\x08\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > "${HTTP2}/goaway"
printf '\x00\x00\x04\x08\x00\x00\x00\x00\x00\x00\x00\x10\x00' > "${HTTP2}/window_update"
printf '\x00\x00\x04\x03\x00\x00\x00\x00\x01\x00\x00\x00\x08' > "${HTTP2}/rst_stream"
printf '\x00\x00\x00\x04\x01\x00\x00\x00\x00' > "${HTTP2}/settings_ack"

# HTTP/2 Frames Full
HTTP2_FULL="${CORPUS_BASE}/http2_frames_full"
mkdir -p "${HTTP2_FULL}"
cp "${HTTP2}"/* "${HTTP2_FULL}/" 2>/dev/null || true
printf '\x00\x00\x05\x00\x01\x00\x00\x00\x01hello' > "${HTTP2_FULL}/data_end"
printf '\x00\x00\x01\x01\x04\x00\x00\x00\x01\x82' > "${HTTP2_FULL}/headers"

# HTTP/2 Headers
HTTP2_HEADERS="${CORPUS_BASE}/http2_headers"
mkdir -p "${HTTP2_HEADERS}"
printf '\x82\x86\x84\x41\x8a\x08\x9d\x5c\x0b\x81\x70\xdc\x78\x0f\x03' > "${HTTP2_HEADERS}/compressed"
printf '\x82' > "${HTTP2_HEADERS}/method_get"
printf '\x83' > "${HTTP2_HEADERS}/method_post"

# HTTP/2 Settings
HTTP2_SETTINGS="${CORPUS_BASE}/http2_settings"
mkdir -p "${HTTP2_SETTINGS}"
printf '\x00\x01\x00\x00\x10\x00' > "${HTTP2_SETTINGS}/header_table"
printf '\x00\x03\x00\x00\x00\x64' > "${HTTP2_SETTINGS}/max_streams"
printf '\x00\x04\x00\x00\xff\xff' > "${HTTP2_SETTINGS}/window_size"
printf '\x00\x05\x00\x00\x40\x00' > "${HTTP2_SETTINGS}/max_frame"

# HTTP/2 Stream
HTTP2_STREAM="${CORPUS_BASE}/http2_stream"
mkdir -p "${HTTP2_STREAM}"
dd if=/dev/urandom bs=64 count=1 of="${HTTP2_STREAM}/random" 2>/dev/null

# HTTP/2 Flow control
HTTP2_FLOW="${CORPUS_BASE}/http2_flow"
mkdir -p "${HTTP2_FLOW}"
printf '\x00\x00\x04\x08\x00\x00\x00\x00\x00\x00\x00\xff\xff' > "${HTTP2_FLOW}/window_max"
dd if=/dev/urandom bs=32 count=1 of="${HTTP2_FLOW}/random" 2>/dev/null

# HTTP/2 Connection
HTTP2_CONN="${CORPUS_BASE}/http2_connection"
mkdir -p "${HTTP2_CONN}"
# Preface + settings
printf 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00' > "${HTTP2_CONN}/preface"
dd if=/dev/urandom bs=128 count=1 of="${HTTP2_CONN}/random" 2>/dev/null

# ============================================================================
# HTTP Common Seeds
# ============================================================================

# HTTP Server
HTTP_SERVER="${CORPUS_BASE}/http_server"
mkdir -p "${HTTP_SERVER}"
cp "${HTTP1_REQ}"/* "${HTTP_SERVER}/" 2>/dev/null || true
echo -ne "GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n" > "${HTTP_SERVER}/ws_upgrade"
echo -ne "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\nHTTP2-Settings: AAMAAABkAAQAoAAAAAIAAAAA\r\n\r\n" > "${HTTP_SERVER}/h2c_upgrade"

# HTTP Client
HTTP_CLIENT="${CORPUS_BASE}/http_client"
mkdir -p "${HTTP_CLIENT}"
cp "${HTTP1_RESP}"/* "${HTTP_CLIENT}/" 2>/dev/null || true

# HTTP Client Async
HTTP_CLIENT_ASYNC="${CORPUS_BASE}/http_client_async"
mkdir -p "${HTTP_CLIENT_ASYNC}"
cp "${HTTP1_RESP}"/* "${HTTP_CLIENT_ASYNC}/" 2>/dev/null || true

# HTTP Client Pool
HTTP_CLIENT_POOL="${CORPUS_BASE}/http_client_pool"
mkdir -p "${HTTP_CLIENT_POOL}"
dd if=/dev/urandom bs=64 count=1 of="${HTTP_CLIENT_POOL}/random" 2>/dev/null

# HTTP Client Retry
HTTP_CLIENT_RETRY="${CORPUS_BASE}/http_client_retry"
mkdir -p "${HTTP_CLIENT_RETRY}"
cp "${HTTP1_RESP}"/* "${HTTP_CLIENT_RETRY}/" 2>/dev/null || true

# HTTP Core
HTTP_CORE="${CORPUS_BASE}/http_core"
mkdir -p "${HTTP_CORE}"
echo -ne "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n" > "${HTTP_CORE}/request"
echo -ne "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" > "${HTTP_CORE}/response"

# HTTP Headers Collection
HTTP_HEADERS="${CORPUS_BASE}/http_headers_collection"
mkdir -p "${HTTP_HEADERS}"
echo -ne "Content-Type: text/html\r\nContent-Length: 100\r\nCache-Control: no-cache\r\n" > "${HTTP_HEADERS}/multi"
echo -ne "Set-Cookie: a=1\r\nSet-Cookie: b=2\r\n" > "${HTTP_HEADERS}/duplicate"

# HTTP Auth
HTTP_AUTH="${CORPUS_BASE}/http_auth"
mkdir -p "${HTTP_AUTH}"
echo -n "Basic dXNlcjpwYXNz" > "${HTTP_AUTH}/basic"
echo -n "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" > "${HTTP_AUTH}/bearer"
echo -n 'Digest username="user", realm="test", nonce="abc123"' > "${HTTP_AUTH}/digest"

# HTTP Content-Type
HTTP_CT="${CORPUS_BASE}/http_content_type"
mkdir -p "${HTTP_CT}"
echo -n "text/html; charset=utf-8" > "${HTTP_CT}/html"
echo -n "application/json" > "${HTTP_CT}/json"
echo -n "multipart/form-data; boundary=----WebKitFormBoundary" > "${HTTP_CT}/multipart"

# HTTP Date
HTTP_DATE="${CORPUS_BASE}/http_date"
mkdir -p "${HTTP_DATE}"
echo -n "Sun, 06 Nov 1994 08:49:37 GMT" > "${HTTP_DATE}/rfc1123"
echo -n "Sunday, 06-Nov-94 08:49:37 GMT" > "${HTTP_DATE}/rfc850"
echo -n "Sun Nov  6 08:49:37 1994" > "${HTTP_DATE}/asctime"

# HTTP Cookies
HTTP_COOKIES="${CORPUS_BASE}/http_cookies"
mkdir -p "${HTTP_COOKIES}"
echo -n "session=abc123" > "${HTTP_COOKIES}/simple"
echo -n "session=abc123; user=test" > "${HTTP_COOKIES}/multi"
echo -n "id=abc; Path=/; Domain=.example.com; Secure; HttpOnly" > "${HTTP_COOKIES}/full"

# HTTP Cookies Simple
HTTP_COOKIES_SIMPLE="${CORPUS_BASE}/http_cookies_simple"
mkdir -p "${HTTP_COOKIES_SIMPLE}"
cp "${HTTP_COOKIES}"/* "${HTTP_COOKIES_SIMPLE}/" 2>/dev/null || true

# HTTP Smuggling
HTTP_SMUGGLING="${CORPUS_BASE}/http_smuggling"
mkdir -p "${HTTP_SMUGGLING}"
echo -ne "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED" > "${HTTP_SMUGGLING}/cl_te"
echo -ne "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n0\r\n\r\n" > "${HTTP_SMUGGLING}/te_cl"
dd if=/dev/urandom bs=64 count=1 of="${HTTP_SMUGGLING}/random" 2>/dev/null

# ============================================================================
# HPACK Seeds
# ============================================================================

HPACK="${CORPUS_BASE}/hpack"
mkdir -p "${HPACK}"
printf '\x82' > "${HPACK}/static_method_get"
printf '\xc0' > "${HPACK}/indexed_high"
printf '\x40\x0a\x63\x75\x73\x74\x6f\x6d\x2d\x6b\x65\x79\x0d\x63\x75\x73\x74\x6f\x6d\x2d\x76\x61\x6c\x75\x65' > "${HPACK}/literal_indexed"
printf '\x82\x86\x84\x41\x8a\x08\x9d\x5c\x0b\x81\x70\xdc\x78\x0f\x03' > "${HPACK}/huffman"

# HPACK Decode
HPACK_DECODE="${CORPUS_BASE}/hpack_decode"
mkdir -p "${HPACK_DECODE}"
cp "${HPACK}"/* "${HPACK_DECODE}/" 2>/dev/null || true

# HPACK Encode
HPACK_ENCODE="${CORPUS_BASE}/hpack_encode"
mkdir -p "${HPACK_ENCODE}"
echo -n ":method: GET" > "${HPACK_ENCODE}/method"
echo -n ":path: /" > "${HPACK_ENCODE}/path"
echo -n "content-type: application/json" > "${HPACK_ENCODE}/content_type"

# HPACK Huffman
HPACK_HUFFMAN="${CORPUS_BASE}/hpack_huffman"
mkdir -p "${HPACK_HUFFMAN}"
printf '\x8a\x08\x9d\x5c\x0b\x81\x70\xdc\x78\x0f\x03' > "${HPACK_HUFFMAN}/encoded"
echo -n "www.example.com" > "${HPACK_HUFFMAN}/decode_target"

# HPACK Integer
HPACK_INT="${CORPUS_BASE}/hpack_integer"
mkdir -p "${HPACK_INT}"
printf '\x0a' > "${HPACK_INT}/small"
printf '\x1f\x9a\x0a' > "${HPACK_INT}/multibyte"
printf '\x1f\xff\xff\xff\x0f' > "${HPACK_INT}/large"

# ============================================================================
# WebSocket Seeds
# ============================================================================

WS="${CORPUS_BASE}/ws_frames"
mkdir -p "${WS}"
printf '\x81\x05hello' > "${WS}/text_simple"
printf '\x82\x05\x01\x02\x03\x04\x05' > "${WS}/binary_simple"
printf '\x89\x00' > "${WS}/ping"
printf '\x8a\x00' > "${WS}/pong"
printf '\x88\x02\x03\xe8' > "${WS}/close_normal"
printf '\x88\x08\x03\xe8Normal' > "${WS}/close_reason"
printf '\x81\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58' > "${WS}/text_masked"
printf '\x01\x05hello' > "${WS}/frag_first"
printf '\x80\x05world' > "${WS}/frag_last"

# WS Frame (singular)
WS_FRAME="${CORPUS_BASE}/ws_frame"
mkdir -p "${WS_FRAME}"
cp "${WS}"/* "${WS_FRAME}/" 2>/dev/null || true

# WebSocket Handshake
WS_HANDSHAKE="${CORPUS_BASE}/websocket_handshake"
mkdir -p "${WS_HANDSHAKE}"
echo -ne "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n" > "${WS_HANDSHAKE}/server_accept"
echo -ne "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n" > "${WS_HANDSHAKE}/client_request"

# WS Handshake (alternate name)
WS_HS="${CORPUS_BASE}/ws_handshake"
mkdir -p "${WS_HS}"
cp "${WS_HANDSHAKE}"/* "${WS_HS}/" 2>/dev/null || true

# WS Deflate
WS_DEFLATE="${CORPUS_BASE}/ws_deflate"
mkdir -p "${WS_DEFLATE}"
printf '\xc1\x07\xf2\x48\xcd\xc9\xc9\x07\x00' > "${WS_DEFLATE}/compressed"
dd if=/dev/urandom bs=64 count=1 of="${WS_DEFLATE}/random" 2>/dev/null

# ============================================================================
# DNS Seeds
# ============================================================================

DNS="${CORPUS_BASE}/dns"
mkdir -p "${DNS}"
echo -n "localhost" > "${DNS}/localhost"
echo -n "example.com" > "${DNS}/example_com"
echo -n "test.example.org" > "${DNS}/subdomain"
echo -n "127.0.0.1" > "${DNS}/ipv4"
echo -n "::1" > "${DNS}/ipv6_loopback"

# DNS Header
DNS_HEADER="${CORPUS_BASE}/dns_header"
mkdir -p "${DNS_HEADER}"
# Standard query header
printf '\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' > "${DNS_HEADER}/query"
# Response header
printf '\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00' > "${DNS_HEADER}/response"

# DNS Name
DNS_NAME="${CORPUS_BASE}/dns_name"
mkdir -p "${DNS_NAME}"
# Wire format names
printf '\x07example\x03com\x00' > "${DNS_NAME}/example_com"
printf '\x03www\x07example\x03com\x00' > "${DNS_NAME}/www_example"
printf '\x00' > "${DNS_NAME}/root"
printf '\xc0\x0c' > "${DNS_NAME}/pointer"

# DNS Response
DNS_RESP="${CORPUS_BASE}/dns_response"
mkdir -p "${DNS_RESP}"
# Minimal A record response
printf '\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x5d\xb8\xd8\x22' > "${DNS_RESP}/a_record"

# DNS EDNS0
DNS_EDNS="${CORPUS_BASE}/dns_edns0"
mkdir -p "${DNS_EDNS}"
# OPT record
printf '\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00' > "${DNS_EDNS}/opt_basic"
printf '\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x0c\x00\x0a\x00\x08\x00\x01\x02\x03\x04\x05\x06\x07' > "${DNS_EDNS}/opt_cookie"

# DNS Cookie
DNS_COOKIE="${CORPUS_BASE}/dns_cookie"
mkdir -p "${DNS_COOKIE}"
printf '\x01\x02\x03\x04\x05\x06\x07\x08' > "${DNS_COOKIE}/client"
printf '\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10' > "${DNS_COOKIE}/server"

# DNS Cookie Client
DNS_COOKIE_CLIENT="${CORPUS_BASE}/dns_cookie_client"
mkdir -p "${DNS_COOKIE_CLIENT}"
cp "${DNS_COOKIE}"/* "${DNS_COOKIE_CLIENT}/" 2>/dev/null || true

# DNS SOA
DNS_SOA="${CORPUS_BASE}/dns_soa"
mkdir -p "${DNS_SOA}"
# SOA RDATA
printf '\x02ns\x07example\x03com\x00\x05admin\x07example\x03com\x00\x00\x00\x00\x01\x00\x00\x1c\x20\x00\x00\x0e\x10\x00\x09\x3a\x80\x00\x00\x0e\x10' > "${DNS_SOA}/soa_rdata"

# DNS Injection
DNS_INJ="${CORPUS_BASE}/dns_inj"
mkdir -p "${DNS_INJ}"
printf '\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' > "${DNS_INJ}/query"
dd if=/dev/urandom bs=64 count=1 of="${DNS_INJ}/random" 2>/dev/null

# DNS Validate
DNS_VALIDATE="${CORPUS_BASE}/dns_validate"
mkdir -p "${DNS_VALIDATE}"
cp "${DNS_RESP}"/* "${DNS_VALIDATE}/" 2>/dev/null || true

# DNS Encode
DNS_ENCODE="${CORPUS_BASE}/dns_encode"
mkdir -p "${DNS_ENCODE}"
echo -n "example.com" > "${DNS_ENCODE}/domain"
echo -n "www.test.example.org" > "${DNS_ENCODE}/subdomain"

# DNS Cache
DNS_CACHE="${CORPUS_BASE}/dns_cache"
mkdir -p "${DNS_CACHE}"
printf '\x01\x07example\x03com\x00\x00\x01\x00\x01' > "${DNS_CACHE}/insert"
printf '\x02\x07example\x03com\x00\x00\x01\x00\x01' > "${DNS_CACHE}/lookup"
dd if=/dev/urandom bs=128 count=1 of="${DNS_CACHE}/random" 2>/dev/null

# DNS Config
DNS_CONFIG="${CORPUS_BASE}/dns_config"
mkdir -p "${DNS_CONFIG}"
echo -n "nameserver 8.8.8.8" > "${DNS_CONFIG}/resolv"
echo -n "nameserver 8.8.8.8\nnameserver 8.8.4.4" > "${DNS_CONFIG}/multi"
dd if=/dev/urandom bs=32 count=1 of="${DNS_CONFIG}/random" 2>/dev/null

# DNS Deadserver
DNS_DEAD="${CORPUS_BASE}/dns_deadserver"
mkdir -p "${DNS_DEAD}"
printf '\x01\x08\x08\x08\x08' > "${DNS_DEAD}/mark_dead"
dd if=/dev/urandom bs=32 count=1 of="${DNS_DEAD}/random" 2>/dev/null

# DNS Transport
DNS_TRANSPORT="${CORPUS_BASE}/dns_transport"
mkdir -p "${DNS_TRANSPORT}"
cp "${DNS_RESP}"/* "${DNS_TRANSPORT}/" 2>/dev/null || true
dd if=/dev/urandom bs=64 count=1 of="${DNS_TRANSPORT}/random" 2>/dev/null

# DNS Resolver
DNS_RESOLVER="${CORPUS_BASE}/dns_resolver"
mkdir -p "${DNS_RESOLVER}"
echo -n "example.com" > "${DNS_RESOLVER}/hostname"
cp "${DNS_RESP}"/* "${DNS_RESOLVER}/" 2>/dev/null || true

# DNSSEC
DNSSEC="${CORPUS_BASE}/dnssec"
mkdir -p "${DNSSEC}"
# DNSKEY record
printf '\x01\x01\x03\x08' > "${DNSSEC}/dnskey_flags"
# DS record
printf '\x12\x34\x08\x02' > "${DNSSEC}/ds_digest"
dd if=/dev/urandom bs=64 count=1 of="${DNSSEC}/random" 2>/dev/null

# DNS over TLS
DNS_DOT="${CORPUS_BASE}/dns_dot"
mkdir -p "${DNS_DOT}"
# Length-prefixed DNS query
printf '\x00\x1d\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' > "${DNS_DOT}/query"

# DNS over HTTPS
DNS_DOH="${CORPUS_BASE}/dns_doh"
mkdir -p "${DNS_DOH}"
# DoH uses same wire format
cp "${DNS_DOT}"/* "${DNS_DOH}/" 2>/dev/null || true

# ============================================================================
# Proxy Seeds
# ============================================================================

PROXY="${CORPUS_BASE}/proxy"
mkdir -p "${PROXY}"
printf '\x05\x00' > "${PROXY}/socks5_method"
printf '\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50' > "${PROXY}/socks5_connect"
printf '\x00\x5a\x00\x50\x7f\x00\x00\x01' > "${PROXY}/socks4_ok"

# Proxy SOCKS5
PROXY_SOCKS5="${CORPUS_BASE}/proxy_socks5"
mkdir -p "${PROXY_SOCKS5}"
printf '\x05\x01\x00' > "${PROXY_SOCKS5}/auth_none"
printf '\x05\x02\x00\x02' > "${PROXY_SOCKS5}/auth_multi"
printf '\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50' > "${PROXY_SOCKS5}/connect_ipv4"
printf '\x05\x00\x00\x03\x0bexample.com\x00\x50' > "${PROXY_SOCKS5}/connect_domain"

# Proxy SOCKS4
PROXY_SOCKS4="${CORPUS_BASE}/proxy_socks4"
mkdir -p "${PROXY_SOCKS4}"
printf '\x00\x5a\x00\x50\x7f\x00\x00\x01' > "${PROXY_SOCKS4}/granted"
printf '\x00\x5b\x00\x50\x7f\x00\x00\x01' > "${PROXY_SOCKS4}/rejected"

# Proxy HTTP
PROXY_HTTP="${CORPUS_BASE}/proxy_http"
mkdir -p "${PROXY_HTTP}"
echo -ne "HTTP/1.1 200 Connection established\r\n\r\n" > "${PROXY_HTTP}/connect_ok"
echo -ne "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n" > "${PROXY_HTTP}/auth_required"

# Proxy URL
PROXY_URL="${CORPUS_BASE}/proxy_url"
mkdir -p "${PROXY_URL}"
echo -n "http://proxy.example.com:8080" > "${PROXY_URL}/http"
echo -n "socks5://user:pass@proxy.example.com:1080" > "${PROXY_URL}/socks5_auth"
echo -n "socks4://proxy.example.com:1080" > "${PROXY_URL}/socks4"

# ============================================================================
# TLS Seeds
# ============================================================================

TLS="${CORPUS_BASE}/tls"
mkdir -p "${TLS}"
dd if=/dev/urandom bs=128 count=1 of="${TLS}/random" 2>/dev/null
echo -n "example.com" > "${TLS}/sni_host"
echo -n "h2" > "${TLS}/alpn_h2"
echo -n "http/1.1" > "${TLS}/alpn_http1"

# TLS Context
TLS_CTX="${CORPUS_BASE}/tls_context"
mkdir -p "${TLS_CTX}"
dd if=/dev/urandom bs=64 count=1 of="${TLS_CTX}/random" 2>/dev/null

# TLS Config
TLS_CONFIG="${CORPUS_BASE}/tls_config"
mkdir -p "${TLS_CONFIG}"
dd if=/dev/urandom bs=32 count=1 of="${TLS_CONFIG}/random" 2>/dev/null

# TLS ALPN
TLS_ALPN="${CORPUS_BASE}/tls_alpn"
mkdir -p "${TLS_ALPN}"
printf '\x02h2\x08http/1.1' > "${TLS_ALPN}/protocols"
printf '\x02h2' > "${TLS_ALPN}/h2_only"

# TLS Cipher
TLS_CIPHER="${CORPUS_BASE}/tls_cipher"
mkdir -p "${TLS_CIPHER}"
echo -n "TLS_AES_256_GCM_SHA384" > "${TLS_CIPHER}/tls13"
echo -n "ECDHE-RSA-AES256-GCM-SHA384" > "${TLS_CIPHER}/tls12"

# TLS Session
TLS_SESSION="${CORPUS_BASE}/tls_session"
mkdir -p "${TLS_SESSION}"
dd if=/dev/urandom bs=256 count=1 of="${TLS_SESSION}/ticket" 2>/dev/null

# TLS Shutdown
TLS_SHUTDOWN="${CORPUS_BASE}/tls_shutdown"
mkdir -p "${TLS_SHUTDOWN}"
printf '\x15\x03\x03\x00\x02\x01\x00' > "${TLS_SHUTDOWN}/close_notify"

# TLS Certs
TLS_CERTS="${CORPUS_BASE}/tls_certs"
mkdir -p "${TLS_CERTS}"
dd if=/dev/urandom bs=256 count=1 of="${TLS_CERTS}/random" 2>/dev/null

# TLS Verify
TLS_VERIFY="${CORPUS_BASE}/tls_verify"
mkdir -p "${TLS_VERIFY}"
dd if=/dev/urandom bs=64 count=1 of="${TLS_VERIFY}/random" 2>/dev/null

# TLS Verify Callback
TLS_VERIFY_CB="${CORPUS_BASE}/tls_verify_callback"
mkdir -p "${TLS_VERIFY_CB}"
dd if=/dev/urandom bs=32 count=1 of="${TLS_VERIFY_CB}/random" 2>/dev/null

# TLS SNI
TLS_SNI="${CORPUS_BASE}/tls_sni"
mkdir -p "${TLS_SNI}"
echo -n "example.com" > "${TLS_SNI}/simple"
echo -n "www.example.com" > "${TLS_SNI}/subdomain"
echo -n "very-long-subdomain.deep.nested.example.com" > "${TLS_SNI}/long"

# TLS IO
TLS_IO="${CORPUS_BASE}/tls_io"
mkdir -p "${TLS_IO}"
dd if=/dev/urandom bs=64 count=1 of="${TLS_IO}/random" 2>/dev/null

# TLS OCSP
TLS_OCSP="${CORPUS_BASE}/tls_ocsp"
mkdir -p "${TLS_OCSP}"
dd if=/dev/urandom bs=128 count=1 of="${TLS_OCSP}/random" 2>/dev/null

# TLS Protocol Version
TLS_VERSION="${CORPUS_BASE}/tls_protocol_version"
mkdir -p "${TLS_VERSION}"
printf '\x03\x03' > "${TLS_VERSION}/tls12"
printf '\x03\x04' > "${TLS_VERSION}/tls13"

# TLS Record
TLS_RECORD="${CORPUS_BASE}/tls_record"
mkdir -p "${TLS_RECORD}"
# Application data record
printf '\x17\x03\x03\x00\x05hello' > "${TLS_RECORD}/app_data"
# Alert record
printf '\x15\x03\x03\x00\x02\x02\x32' > "${TLS_RECORD}/alert"

# TLS Records
TLS_RECORDS="${CORPUS_BASE}/tls_records"
mkdir -p "${TLS_RECORDS}"
cp "${TLS_RECORD}"/* "${TLS_RECORDS}/" 2>/dev/null || true

# TLS Alert
TLS_ALERT="${CORPUS_BASE}/tls_alert"
mkdir -p "${TLS_ALERT}"
printf '\x01\x00' > "${TLS_ALERT}/close_notify"
printf '\x02\x28' > "${TLS_ALERT}/handshake_failure"
printf '\x02\x2e' > "${TLS_ALERT}/certificate_expired"

# TLS Error
TLS_ERROR="${CORPUS_BASE}/tls_error"
mkdir -p "${TLS_ERROR}"
dd if=/dev/urandom bs=32 count=1 of="${TLS_ERROR}/random" 2>/dev/null

# TLS CRL
TLS_CRL="${CORPUS_BASE}/tls_crl"
mkdir -p "${TLS_CRL}"
dd if=/dev/urandom bs=128 count=1 of="${TLS_CRL}/random" 2>/dev/null

# TLS CT (Certificate Transparency)
TLS_CT="${CORPUS_BASE}/tls_ct"
mkdir -p "${TLS_CT}"
dd if=/dev/urandom bs=128 count=1 of="${TLS_CT}/random" 2>/dev/null

# TLS Handshake
TLS_HS="${CORPUS_BASE}/tls_handshake"
mkdir -p "${TLS_HS}"
# ClientHello
printf '\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00' > "${TLS_HS}/client_hello_min"
dd if=/dev/urandom bs=128 count=1 of="${TLS_HS}/random" 2>/dev/null

# TLS kTLS
TLS_KTLS="${CORPUS_BASE}/tls_ktls"
mkdir -p "${TLS_KTLS}"
dd if=/dev/urandom bs=32 count=1 of="${TLS_KTLS}/random" 2>/dev/null

# TLS Key Update
TLS_KEY_UPDATE="${CORPUS_BASE}/tls_key_update"
mkdir -p "${TLS_KEY_UPDATE}"
printf '\x18' > "${TLS_KEY_UPDATE}/request"

# TLS Buffer Pool
TLS_BUFPOOL="${CORPUS_BASE}/tls_buffer_pool"
mkdir -p "${TLS_BUFPOOL}"
dd if=/dev/urandom bs=64 count=1 of="${TLS_BUFPOOL}/random" 2>/dev/null

# TLS Cert Lookup
TLS_CERT_LOOKUP="${CORPUS_BASE}/tls_cert_lookup"
mkdir -p "${TLS_CERT_LOOKUP}"
echo -n "example.com" > "${TLS_CERT_LOOKUP}/hostname"

# SSL Path Validation
SSL_PATH="${CORPUS_BASE}/ssl_path_validation"
mkdir -p "${SSL_PATH}"
echo -n "/etc/ssl/certs" > "${SSL_PATH}/system"
echo -n "./certs" > "${SSL_PATH}/relative"

# Certificate Parsing
CERT_PARSE="${CORPUS_BASE}/certificate_parsing"
mkdir -p "${CERT_PARSE}"
dd if=/dev/urandom bs=256 count=1 of="${CERT_PARSE}/random" 2>/dev/null

# Cert Pinning
CERT_PIN="${CORPUS_BASE}/cert_pinning"
mkdir -p "${CERT_PIN}"
echo -n "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" > "${CERT_PIN}/sha256"

# Pin Hex Parsing
PIN_HEX="${CORPUS_BASE}/pin_hex_parsing"
mkdir -p "${PIN_HEX}"
echo -n "0123456789abcdef" > "${PIN_HEX}/lower"
echo -n "0123456789ABCDEF" > "${PIN_HEX}/upper"

# ============================================================================
# DTLS Seeds
# ============================================================================

DTLS="${CORPUS_BASE}/dtls"
mkdir -p "${DTLS}"
dd if=/dev/urandom bs=64 count=1 of="${DTLS}/random" 2>/dev/null

# DTLS Context
DTLS_CTX="${CORPUS_BASE}/dtls_context"
mkdir -p "${DTLS_CTX}"
dd if=/dev/urandom bs=32 count=1 of="${DTLS_CTX}/random" 2>/dev/null

# DTLS Config
DTLS_CONFIG="${CORPUS_BASE}/dtls_config"
mkdir -p "${DTLS_CONFIG}"
dd if=/dev/urandom bs=32 count=1 of="${DTLS_CONFIG}/random" 2>/dev/null

# DTLS Cookie
DTLS_COOKIE="${CORPUS_BASE}/dtls_cookie"
mkdir -p "${DTLS_COOKIE}"
dd if=/dev/urandom bs=32 count=1 of="${DTLS_COOKIE}/cookie" 2>/dev/null

# DTLS Enable Config
DTLS_ENABLE="${CORPUS_BASE}/dtls_enable_config"
mkdir -p "${DTLS_ENABLE}"
printf '\x00\x02\x40' > "${DTLS_ENABLE}/basic"
printf '\x0c\x05\x78' > "${DTLS_ENABLE}/combined"
dd if=/dev/urandom bs=16 count=1 of="${DTLS_ENABLE}/random" 2>/dev/null

# DTLS Handshake
DTLS_HS="${CORPUS_BASE}/dtls_handshake"
mkdir -p "${DTLS_HS}"
# DTLS record with handshake
printf '\x16\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10' > "${DTLS_HS}/record"
dd if=/dev/urandom bs=64 count=1 of="${DTLS_HS}/random" 2>/dev/null

# DTLS IO
DTLS_IO="${CORPUS_BASE}/dtls_io"
mkdir -p "${DTLS_IO}"
dd if=/dev/urandom bs=64 count=1 of="${DTLS_IO}/random" 2>/dev/null

# DTLS Replay
DTLS_REPLAY="${CORPUS_BASE}/dtls_replay"
mkdir -p "${DTLS_REPLAY}"
printf '\x00\x00\x00\x00\x00\x00\x00\x01' > "${DTLS_REPLAY}/seq1"
printf '\x00\x00\x00\x00\x00\x00\x00\x02' > "${DTLS_REPLAY}/seq2"
dd if=/dev/urandom bs=64 count=1 of="${DTLS_REPLAY}/random" 2>/dev/null

# ============================================================================
# Security Seeds
# ============================================================================

# SYN Protection
SYN="${CORPUS_BASE}/synprotect"
mkdir -p "${SYN}"
dd if=/dev/urandom bs=64 count=1 of="${SYN}/random_config" 2>/dev/null
echo -n "192.168.1.1" > "${SYN}/ipv4"
echo -n "2001:db8::1" > "${SYN}/ipv6"
echo -n "192.168.1.0/24" > "${SYN}/cidr_24"

# SYN Protect IP
SYN_IP="${CORPUS_BASE}/synprotect_ip"
mkdir -p "${SYN_IP}"
echo -n "192.168.1.1" > "${SYN_IP}/ipv4"
echo -n "10.0.0.1" > "${SYN_IP}/private"
echo -n "2001:db8::1" > "${SYN_IP}/ipv6"
dd if=/dev/urandom bs=64 count=1 of="${SYN_IP}/random" 2>/dev/null

# SYN Protect List
SYN_LIST="${CORPUS_BASE}/synprotect_list"
mkdir -p "${SYN_LIST}"
echo -n "192.168.1.0/24" > "${SYN_LIST}/single"
echo -ne "192.168.1.0/24\n10.0.0.0/8" > "${SYN_LIST}/multi"
dd if=/dev/urandom bs=64 count=1 of="${SYN_LIST}/random" 2>/dev/null

# Rate Limit
RATELIMIT="${CORPUS_BASE}/ratelimit"
mkdir -p "${RATELIMIT}"
dd if=/dev/urandom bs=32 count=1 of="${RATELIMIT}/random_config" 2>/dev/null
printf '\x00\x00\x00\x64\x00\x00\x03\xe8' > "${RATELIMIT}/100_per_sec"

# Security
SECURITY="${CORPUS_BASE}/security"
mkdir -p "${SECURITY}"
printf '\xff\xff\xff\xff\xff\xff\xff\xff' > "${SECURITY}/size_max"
printf '\x00\x00\x00\x00\x00\x00\x00\x00' > "${SECURITY}/size_zero"
dd if=/dev/urandom bs=64 count=1 of="${SECURITY}/random" 2>/dev/null

# Pool DoS
POOL="${CORPUS_BASE}/pool_dos"
mkdir -p "${POOL}"
dd if=/dev/urandom bs=64 count=1 of="${POOL}/random_ops" 2>/dev/null
printf '\x01\x00\x10' > "${POOL}/acquire"
printf '\x02\x00\x10' > "${POOL}/release"

# Metrics
METRICS="${CORPUS_BASE}/metrics"
mkdir -p "${METRICS}"
dd if=/dev/urandom bs=64 count=1 of="${METRICS}/random_ops" 2>/dev/null

# ============================================================================
# Encoding Seeds
# ============================================================================

# UTF-8
UTF8="${CORPUS_BASE}/utf8"
mkdir -p "${UTF8}"
echo -n "Hello World" > "${UTF8}/ascii"
echo -n "Héllo Wörld" > "${UTF8}/latin"
echo -n "こんにちは" > "${UTF8}/japanese"
echo -n "🎉🚀💻" > "${UTF8}/emoji"
printf '\xc0\x80' > "${UTF8}/overlong_null"
printf '\xed\xa0\x80' > "${UTF8}/surrogate"
printf '\xf4\x90\x80\x80' > "${UTF8}/over_max"
printf '\x80' > "${UTF8}/continuation_only"

# UTF-8 Validate
UTF8_VALIDATE="${CORPUS_BASE}/utf8_validate"
mkdir -p "${UTF8_VALIDATE}"
cp "${UTF8}"/* "${UTF8_VALIDATE}/" 2>/dev/null || true

# UTF-8 Incremental
UTF8_INC="${CORPUS_BASE}/utf8_incremental"
mkdir -p "${UTF8_INC}"
cp "${UTF8}"/* "${UTF8_INC}/" 2>/dev/null || true

# Base64 Decode
BASE64="${CORPUS_BASE}/base64_decode"
mkdir -p "${BASE64}"
echo -n "SGVsbG8gV29ybGQ=" > "${BASE64}/hello"
echo -n "Zm9vYmFy" > "${BASE64}/foobar"
echo -n "YWJjZA==" > "${BASE64}/padded"
echo -n "" > "${BASE64}/empty"

# Hex Decode
HEX="${CORPUS_BASE}/hex_decode"
mkdir -p "${HEX}"
echo -n "48656c6c6f" > "${HEX}/hello_lower"
echo -n "48656C6C6F" > "${HEX}/hello_upper"
echo -n "00ff" > "${HEX}/boundary"

# URI Parse
URI="${CORPUS_BASE}/uri_parse"
mkdir -p "${URI}"
echo -n "http://example.com/path?query=value#fragment" > "${URI}/full"
echo -n "https://user:pass@example.com:8080/path" > "${URI}/with_auth"
echo -n "/relative/path" > "${URI}/relative"
echo -n "//example.com/protocol-relative" > "${URI}/protocol_relative"
echo -n "mailto:user@example.com" > "${URI}/mailto"

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "Corpus generation complete!"
echo ""
echo "Directories created:"
find "${CORPUS_BASE}" -type d | sort | while read -r dir; do
    count=$(find "$dir" -maxdepth 1 -type f 2>/dev/null | wc -l)
    if [ "$count" -gt 0 ]; then
        echo "  ${dir}: ${count} files"
    fi
done

TOTAL_FILES=$(find "${CORPUS_BASE}" -type f | wc -l)
TOTAL_DIRS=$(find "${CORPUS_BASE}" -type d | wc -l)

echo ""
echo "Total: ${TOTAL_FILES} seed files in ${TOTAL_DIRS} directories"
echo ""
echo "To use with fuzzer:"
echo "  ./fuzz_http1_request ${CORPUS_BASE}/http1_request"
echo "  ./fuzz_dns_cache ${CORPUS_BASE}/dns_cache"
echo "  ./fuzz_websocket_handshake ${CORPUS_BASE}/websocket_handshake"
echo "  etc."
