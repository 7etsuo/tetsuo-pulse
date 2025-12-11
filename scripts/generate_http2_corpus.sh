#!/bin/bash
#
# generate_http2_corpus.sh - Generate high-quality HTTP/2 fuzzing corpus
#
# Creates binary seed files with valid HTTP/2 frame sequences that exercise
# different protocol paths. Each seed includes the mode byte (client/server)
# followed by valid frame data that the fuzzer can mutate.
#
# Usage: ./scripts/generate_http2_corpus.sh <corpus_dir>

set -e

CORPUS_DIR="${1:-build/corpus_http2}"
mkdir -p "$CORPUS_DIR"

# Helper function to create binary files
create_seed() {
    local name="$1"
    shift
    printf "$@" > "$CORPUS_DIR/$name"
    echo "Created: $name ($(wc -c < "$CORPUS_DIR/$name") bytes)"
}

# Helper to write hex bytes
hex() {
    printf '%s' "$1" | xxd -r -p
}

echo "=== Generating HTTP/2 Corpus Seeds ==="
echo "Target: $CORPUS_DIR"
echo

# Clean old seeds
rm -f "$CORPUS_DIR"/http2_*.bin

# =============================================================================
# SETTINGS Frames (Frame Type 0x04)
# =============================================================================

# Empty SETTINGS (server mode)
(
    printf '\x00'                           # Mode: server
    hex "000000 04 00 00000000"             # Empty SETTINGS
) > "$CORPUS_DIR/http2_settings_empty.bin"
echo "Created: http2_settings_empty.bin"

# SETTINGS with common parameters
(
    printf '\x00'
    # SETTINGS frame: 18 bytes payload (3 settings x 6 bytes each)
    hex "000012 04 00 00000000"             # Frame header
    hex "0001 00001000"                     # HEADER_TABLE_SIZE = 4096
    hex "0003 00000064"                     # MAX_CONCURRENT_STREAMS = 100
    hex "0004 0000ffff"                     # INITIAL_WINDOW_SIZE = 65535
) > "$CORPUS_DIR/http2_settings_common.bin"
echo "Created: http2_settings_common.bin"

# SETTINGS ACK
(
    printf '\x01'                           # Mode: client
    hex "000000 04 01 00000000"             # SETTINGS with ACK flag
) > "$CORPUS_DIR/http2_settings_ack.bin"
echo "Created: http2_settings_ack.bin"

# All 6 settings
(
    printf '\x00'
    hex "000024 04 00 00000000"             # 36 bytes = 6 settings
    hex "0001 00001000"                     # HEADER_TABLE_SIZE
    hex "0002 00000000"                     # ENABLE_PUSH = 0
    hex "0003 00000100"                     # MAX_CONCURRENT_STREAMS = 256
    hex "0004 0000ffff"                     # INITIAL_WINDOW_SIZE
    hex "0005 00004000"                     # MAX_FRAME_SIZE = 16384
    hex "0006 00002000"                     # MAX_HEADER_LIST_SIZE = 8192
) > "$CORPUS_DIR/http2_settings_all.bin"
echo "Created: http2_settings_all.bin"

# =============================================================================
# PING Frames (Frame Type 0x06)
# =============================================================================

# PING request
(
    printf '\x00'
    hex "000008 06 00 00000000"             # PING, no flags
    hex "0102030405060708"                  # 8 opaque bytes
) > "$CORPUS_DIR/http2_ping.bin"
echo "Created: http2_ping.bin"

# PING ACK
(
    printf '\x01'
    hex "000008 06 01 00000000"             # PING with ACK flag
    hex "deadbeefcafebabe"                  # 8 opaque bytes
) > "$CORPUS_DIR/http2_ping_ack.bin"
echo "Created: http2_ping_ack.bin"

# =============================================================================
# WINDOW_UPDATE Frames (Frame Type 0x08)
# =============================================================================

# Connection-level WINDOW_UPDATE
(
    printf '\x00'
    hex "000004 08 00 00000000"             # Stream 0
    hex "7fffffff"                          # Max increment
) > "$CORPUS_DIR/http2_window_update_conn.bin"
echo "Created: http2_window_update_conn.bin"

# Stream-level WINDOW_UPDATE
(
    printf '\x00'
    hex "000004 08 00 00000001"             # Stream 1
    hex "00010000"                          # 65536 increment
) > "$CORPUS_DIR/http2_window_update_stream.bin"
echo "Created: http2_window_update_stream.bin"

# Zero increment (protocol error)
(
    printf '\x00'
    hex "000004 08 00 00000001"
    hex "00000000"                          # Zero increment - error
) > "$CORPUS_DIR/http2_window_update_zero.bin"
echo "Created: http2_window_update_zero.bin"

# =============================================================================
# HEADERS Frames (Frame Type 0x01)
# =============================================================================

# Minimal GET request (indexed headers from static table)
(
    printf '\x00'                           # Server mode
    # HEADERS frame with END_HEADERS(0x04) + END_STREAM(0x01)
    hex "000004 01 05 00000001"             # Stream 1
    hex "82848687"                          # :method GET, :path /, :scheme https, :authority
) > "$CORPUS_DIR/http2_headers_get.bin"
echo "Created: http2_headers_get.bin"

# POST request
(
    printf '\x00'
    hex "000004 01 04 00000003"             # Stream 3, END_HEADERS only
    hex "83848687"                          # :method POST, :path /, :scheme https, :authority
) > "$CORPUS_DIR/http2_headers_post.bin"
echo "Created: http2_headers_post.bin"

# Response 200 OK
(
    printf '\x01'                           # Client mode
    hex "000001 01 05 00000001"             # Stream 1, END_HEADERS + END_STREAM
    hex "88"                                # :status 200
) > "$CORPUS_DIR/http2_headers_200.bin"
echo "Created: http2_headers_200.bin"

# Response 404 Not Found
(
    printf '\x01'
    hex "000001 01 05 00000001"
    hex "8c"                                # :status 404
) > "$CORPUS_DIR/http2_headers_404.bin"
echo "Created: http2_headers_404.bin"

# =============================================================================
# DATA Frames (Frame Type 0x00)
# =============================================================================

# Empty DATA with END_STREAM
(
    printf '\x00'
    hex "000000 00 01 00000001"             # END_STREAM flag
) > "$CORPUS_DIR/http2_data_empty.bin"
echo "Created: http2_data_empty.bin"

# DATA with payload
(
    printf '\x00'
    hex "00000c 00 00 00000001"             # 12 bytes payload
    printf 'Hello World!'                  # Payload
) > "$CORPUS_DIR/http2_data_hello.bin"
echo "Created: http2_data_hello.bin"

# DATA with padding
(
    printf '\x00'
    hex "000011 00 09 00000001"             # 17 bytes, PADDED + END_STREAM
    hex "04"                                # Pad length = 4
    printf 'Hello World!'                  # 12 bytes payload
    hex "00000000"                          # 4 bytes padding
) > "$CORPUS_DIR/http2_data_padded.bin"
echo "Created: http2_data_padded.bin"

# =============================================================================
# RST_STREAM Frames (Frame Type 0x03)
# =============================================================================

# RST_STREAM NO_ERROR
(
    printf '\x00'
    hex "000004 03 00 00000001"
    hex "00000000"                          # NO_ERROR
) > "$CORPUS_DIR/http2_rst_no_error.bin"
echo "Created: http2_rst_no_error.bin"

# RST_STREAM CANCEL
(
    printf '\x00'
    hex "000004 03 00 00000001"
    hex "00000008"                          # CANCEL
) > "$CORPUS_DIR/http2_rst_cancel.bin"
echo "Created: http2_rst_cancel.bin"

# RST_STREAM various error codes
for code in 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d; do
    (
        printf '\x00'
        hex "000004 03 00 00000001"
        hex "000000$code"
    ) > "$CORPUS_DIR/http2_rst_err_$code.bin"
done
echo "Created: http2_rst_err_*.bin (13 variants)"

# =============================================================================
# GOAWAY Frames (Frame Type 0x07)
# =============================================================================

# GOAWAY NO_ERROR
(
    printf '\x00'
    hex "000008 07 00 00000000"
    hex "00000001"                          # Last stream ID
    hex "00000000"                          # NO_ERROR
) > "$CORPUS_DIR/http2_goaway.bin"
echo "Created: http2_goaway.bin"

# GOAWAY with debug data
(
    printf '\x00'
    hex "000010 07 00 00000000"             # 16 bytes
    hex "00000001"                          # Last stream ID
    hex "00000001"                          # PROTOCOL_ERROR
    printf 'shutdown'                      # Debug data
) > "$CORPUS_DIR/http2_goaway_debug.bin"
echo "Created: http2_goaway_debug.bin"

# =============================================================================
# PRIORITY Frames (Frame Type 0x02)
# =============================================================================

# PRIORITY frame
(
    printf '\x00'
    hex "000005 02 00 00000003"             # Stream 3
    hex "80000001"                          # Exclusive, depends on stream 1
    hex "10"                                # Weight 16
) > "$CORPUS_DIR/http2_priority.bin"
echo "Created: http2_priority.bin"

# =============================================================================
# CONTINUATION Frames (Frame Type 0x09)
# =============================================================================

# HEADERS + CONTINUATION sequence
(
    printf '\x00'
    hex "000002 01 00 00000001"             # HEADERS without END_HEADERS
    hex "8284"                              # :method GET, :path /
    hex "000002 09 04 00000001"             # CONTINUATION with END_HEADERS
    hex "8687"                              # :scheme https, :authority
) > "$CORPUS_DIR/http2_continuation.bin"
echo "Created: http2_continuation.bin"

# =============================================================================
# Multi-Frame Sequences
# =============================================================================

# Full request: SETTINGS + HEADERS + DATA
(
    printf '\x00'
    # SETTINGS
    hex "000006 04 00 00000000"
    hex "0003 00000064"                     # MAX_CONCURRENT_STREAMS = 100
    # HEADERS (POST)
    hex "000004 01 04 00000001"             # END_HEADERS only
    hex "83848687"                          # :method POST, :path /, :scheme, :authority
    # DATA
    hex "00000d 00 01 00000001"             # END_STREAM
    printf 'request body!'
) > "$CORPUS_DIR/http2_full_request.bin"
echo "Created: http2_full_request.bin"

# Full response: SETTINGS_ACK + HEADERS + DATA
(
    printf '\x01'
    # SETTINGS ACK
    hex "000000 04 01 00000000"
    # HEADERS (200 OK)
    hex "000001 01 04 00000001"
    hex "88"
    # DATA
    hex "00000e 00 01 00000001"
    printf 'response body!'
) > "$CORPUS_DIR/http2_full_response.bin"
echo "Created: http2_full_response.bin"

# Multiple streams
(
    printf '\x00'
    # SETTINGS
    hex "000000 04 00 00000000"
    # Stream 1 - GET
    hex "000004 01 05 00000001"
    hex "82848687"
    # Stream 3 - GET
    hex "000004 01 05 00000003"
    hex "82848687"
    # Stream 5 - POST
    hex "000004 01 04 00000005"
    hex "83848687"
    # Data for stream 5
    hex "000005 00 01 00000005"
    printf 'data!'
) > "$CORPUS_DIR/http2_multi_stream.bin"
echo "Created: http2_multi_stream.bin"

# =============================================================================
# Edge Cases and Protocol Errors
# =============================================================================

# Invalid frame on stream 0 (DATA must have stream_id > 0)
(
    printf '\x00'
    hex "000005 00 00 00000000"             # DATA on stream 0
    printf 'test!'
) > "$CORPUS_DIR/http2_data_stream0_error.bin"
echo "Created: http2_data_stream0_error.bin"

# Oversized frame header (tests length validation)
(
    printf '\x00'
    hex "ffffff 00 00 00000001"             # Max frame length
    printf 'x'                             # Minimal payload
) > "$CORPUS_DIR/http2_oversized_length.bin"
echo "Created: http2_oversized_length.bin"

# Unknown frame type
(
    printf '\x00'
    hex "000008 ff 00 00000001"             # Unknown type 0xFF
    hex "0102030405060708"
) > "$CORPUS_DIR/http2_unknown_frame.bin"
echo "Created: http2_unknown_frame.bin"

# Push promise (if server)
(
    printf '\x00'
    hex "000008 05 04 00000001"             # PUSH_PROMISE, END_HEADERS
    hex "00000002"                          # Promised stream ID
    hex "88"                                # :status 200
    hex "000000"                            # Padding for alignment
) > "$CORPUS_DIR/http2_push_promise.bin"
echo "Created: http2_push_promise.bin"

# =============================================================================
# Flow Control Scenarios
# =============================================================================

# Large WINDOW_UPDATE + DATA sequence
(
    printf '\x00'
    # WINDOW_UPDATE on connection
    hex "000004 08 00 00000000"
    hex "00100000"                          # 1MB increment
    # WINDOW_UPDATE on stream 1
    hex "000004 08 00 00000001"
    hex "00100000"
    # Large DATA frame
    hex "000100 00 00 00000001"             # 256 bytes
    printf '%0256d' 0 | tr ' 0' 'xx'        # 256 x's
) > "$CORPUS_DIR/http2_flow_control.bin"
echo "Created: http2_flow_control.bin"

# =============================================================================
# Summary
# =============================================================================

echo
echo "=== Corpus Generation Complete ==="
TOTAL=$(ls -1 "$CORPUS_DIR"/http2_*.bin 2>/dev/null | wc -l)
SIZE=$(du -sh "$CORPUS_DIR" | cut -f1)
echo "Total seeds: $TOTAL"
echo "Total size: $SIZE"
echo
echo "Run fuzzer with: ./fuzz_http2_connection $CORPUS_DIR -fork=16"
