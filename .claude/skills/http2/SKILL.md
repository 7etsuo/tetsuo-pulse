---
name: http2
description: HTTP/2 and HPACK implementation patterns. Use when working on HTTP/2 frames, streams, HPACK encoding/decoding, header compression, or files in src/http/SocketHTTP2*.c or src/http/SocketHPACK*.c.
---

You are an expert C developer specializing in HTTP/2 (RFC 9113) and HPACK (RFC 7541) implementation.

## HTTP/2 Architecture

```
SocketHTTP2_Connection_T (multiplexed connection)
    ├── Stream 1 (request/response)
    ├── Stream 3 (request/response)
    ├── Stream 5 (server push)
    └── ... (odd = client-initiated, even = server-initiated)

HPACK Context (per-connection)
    ├── Dynamic Table (header compression state)
    └── Huffman Codec (static)
```

## Frame Processing Pattern

HTTP/2 is frame-based. Always validate frame structure:

```c
// Frame header: 9 bytes
// [Length: 3 bytes][Type: 1 byte][Flags: 1 byte][R + Stream ID: 4 bytes]

int process_frame(const uint8_t *data, size_t len, HTTP2Frame *frame) {
    if (len < 9) return -1;  // Incomplete header

    frame->length = (data[0] << 16) | (data[1] << 8) | data[2];
    frame->type = data[3];
    frame->flags = data[4];
    frame->stream_id = ((data[5] & 0x7F) << 24) | (data[6] << 16) |
                       (data[7] << 8) | data[8];

    if (len < 9 + frame->length) return -1;  // Incomplete payload

    // Validate frame constraints per RFC 9113
    if (frame->length > SETTINGS_MAX_FRAME_SIZE) {
        return send_goaway(conn, HTTP2_FRAME_SIZE_ERROR);
    }

    return 0;
}
```

## Stream State Machine (RFC 9113 Section 5.1)

```
                         +--------+
                 send PP |        | recv PP
                ,--------|  idle  |--------.
               /         |        |         \
              v          +--------+          v
       +----------+          |           +----------+
       |          |          | send H /  |          |
,------| reserved |          | recv H    | reserved |------.
|      | (local)  |          |           | (remote) |      |
|      +----------+          v           +----------+      |
|          |             +--------+             |          |
|          |     recv ES |        | send ES     |          |
|   send H |     ,-------|  open  |-------.     | recv H   |
|          |    /        |        |        \    |          |
|          v   v         +--------+         v   v          |
|      +----------+          |           +----------+      |
|      |   half   |          |           |   half   |      |
|      |  closed  |          | send R /  |  closed  |      |
|      | (remote) |          | recv R    | (local)  |      |
|      +----------+          |           +----------+      |
|           |                |                 |           |
|           | send ES /      |       recv ES / |           |
|           | send R /       v        send R / |           |
|           | recv R     +--------+   recv R   |           |
| send R /  `----------->|        |<-----------'  send R / |
| recv R                 | closed |               recv R   |
`----------------------->|        |<-----------------------'
                         +--------+
```

Always check stream state before processing:

```c
if (stream->state == STREAM_CLOSED) {
    return send_rst_stream(stream, HTTP2_STREAM_CLOSED);
}
```

## HPACK Encoding/Decoding

### Integer Encoding (RFC 7541 Section 5.1)

```c
// Encode integer with N-bit prefix
void hpack_encode_integer(SocketBuf_T buf, uint32_t value, uint8_t prefix_bits) {
    uint8_t max_prefix = (1 << prefix_bits) - 1;

    if (value < max_prefix) {
        SocketBuf_write_byte(buf, value);
    } else {
        SocketBuf_write_byte(buf, max_prefix);
        value -= max_prefix;
        while (value >= 128) {
            SocketBuf_write_byte(buf, (value & 0x7F) | 0x80);
            value >>= 7;
        }
        SocketBuf_write_byte(buf, value);
    }
}
```

### Huffman Coding (RFC 7541 Appendix B)

```c
// Huffman decode - watch for padding!
// Per RFC 7541: Padding MUST be 1-bits, max 7 bits
// Do NOT add EOS symbol when encoding - only pad with 1s

int hpack_huffman_decode(const uint8_t *data, size_t len, char *out, size_t *out_len) {
    // State machine with static Huffman table
    // Check for invalid padding (not all 1s)
    // Check for EOS symbol in data (protocol error)
}
```

### Dynamic Table Management

```c
// Table size update must be first in header block
if (first_header && instruction == TABLE_SIZE_UPDATE) {
    hpack_set_dynamic_table_size(ctx, new_size);
}

// Eviction when adding entries
while (ctx->dynamic_table_size + entry_size > ctx->max_table_size) {
    hpack_evict_oldest(ctx);
}
```

## Flow Control (RFC 9113 Section 5.2)

```c
// Connection-level and stream-level windows
#define DEFAULT_WINDOW_SIZE 65535

// Before sending DATA
if (bytes_to_send > stream->send_window) {
    bytes_to_send = stream->send_window;  // Respect window
}
stream->send_window -= bytes_to_send;
conn->send_window -= bytes_to_send;

// On receiving WINDOW_UPDATE
stream->send_window += increment;
if (stream->send_window > MAX_WINDOW_SIZE) {
    return send_goaway(conn, HTTP2_FLOW_CONTROL_ERROR);
}
```

## Error Handling

| Error Code | Meaning | Action |
|------------|---------|--------|
| NO_ERROR (0x0) | Graceful close | Close stream/connection |
| PROTOCOL_ERROR (0x1) | Generic protocol violation | GOAWAY |
| INTERNAL_ERROR (0x2) | Implementation error | GOAWAY |
| FLOW_CONTROL_ERROR (0x3) | Flow control violated | GOAWAY |
| SETTINGS_TIMEOUT (0x4) | SETTINGS not acknowledged | GOAWAY |
| STREAM_CLOSED (0x5) | Frame on closed stream | RST_STREAM |
| FRAME_SIZE_ERROR (0x6) | Invalid frame size | GOAWAY or RST_STREAM |
| COMPRESSION_ERROR (0x9) | HPACK decompression failed | GOAWAY (fatal!) |

**COMPRESSION_ERROR is always fatal** - HPACK state is shared, so any error corrupts the connection.

## Security Considerations

1. **Header size limits**: Enforce `SETTINGS_MAX_HEADER_LIST_SIZE`
2. **Dynamic table attacks**: Limit table size, monitor eviction patterns
3. **Stream exhaustion**: Limit concurrent streams per `SETTINGS_MAX_CONCURRENT_STREAMS`
4. **Slow loris**: Implement timeouts for incomplete frames
5. **HPACK bomb**: Limit decompressed header size

## Files Reference

| File | Purpose |
|------|---------|
| `include/http/SocketHTTP2.h` | HTTP/2 API |
| `include/http/SocketHPACK.h` | HPACK API |
| `src/http/SocketHTTP2-frames.c` | Frame processing |
| `src/http/SocketHTTP2-streams.c` | Stream state machine |
| `src/http/SocketHPACK.c` | Header compression |
| `src/http/SocketHPACK-huffman.c` | Huffman codec |
| `src/test/test_http2.c` | Test patterns |
| `src/test/test_hpack.c` | HPACK tests |
