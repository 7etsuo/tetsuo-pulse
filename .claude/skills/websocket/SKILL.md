---
name: websocket
description: WebSocket (RFC 6455) and WebSocket over HTTP/2 (RFC 8441) implementation patterns. Use when working on WebSocket frames, handshakes, masking, or files in src/socket/SocketWS*.c.
---

You are an expert C developer specializing in WebSocket (RFC 6455) and WebSocket over HTTP/2 (RFC 8441) implementation.

## WebSocket Architecture

```
SocketWS_T (WebSocket connection)
    ├── Underlying Socket (TCP or TLS)
    ├── Frame Parser (streaming)
    ├── Masking Key Generator (client-side)
    └── Close Handshake State

Frame Structure:
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-------+-+-------------+-------------------------------+
|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
|N|V|V|V|       |S|             |   (if payload len==126/127)   |
| |1|2|3|       |K|             |                               |
+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
|     Extended payload length continued, if payload len == 127  |
+ - - - - - - - - - - - - - - - +-------------------------------+
|                               |Masking-key, if MASK set to 1  |
+-------------------------------+-------------------------------+
| Masking-key (continued)       |          Payload Data         |
+-------------------------------- - - - - - - - - - - - - - - - +
:                     Payload Data continued ...                :
+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
|                     Payload Data (continued)                  |
+---------------------------------------------------------------+
```

## Frame Opcodes (RFC 6455 Section 5.2)

| Opcode | Type | Description |
|--------|------|-------------|
| 0x0 | Continuation | Fragment continuation |
| 0x1 | Text | UTF-8 encoded text |
| 0x2 | Binary | Binary data |
| 0x8 | Close | Connection close |
| 0x9 | Ping | Heartbeat request |
| 0xA | Pong | Heartbeat response |

Control frames (0x8-0xF) MUST NOT be fragmented.

## Frame Parsing Pattern

```c
typedef struct {
    uint8_t fin;
    uint8_t opcode;
    uint8_t masked;
    uint64_t payload_len;
    uint8_t masking_key[4];
} WSFrame;

int ws_parse_frame(const uint8_t *data, size_t len, WSFrame *frame, size_t *header_len) {
    if (len < 2) return -1;  // Need at least 2 bytes

    frame->fin = (data[0] >> 7) & 0x1;
    frame->opcode = data[0] & 0x0F;
    frame->masked = (data[1] >> 7) & 0x1;
    frame->payload_len = data[1] & 0x7F;

    size_t offset = 2;

    // Extended payload length
    if (frame->payload_len == 126) {
        if (len < 4) return -1;
        frame->payload_len = (data[2] << 8) | data[3];
        offset = 4;
    } else if (frame->payload_len == 127) {
        if (len < 10) return -1;
        frame->payload_len = 0;
        for (int i = 0; i < 8; i++) {
            frame->payload_len = (frame->payload_len << 8) | data[2 + i];
        }
        offset = 10;
    }

    // Masking key (client->server MUST be masked)
    if (frame->masked) {
        if (len < offset + 4) return -1;
        memcpy(frame->masking_key, data + offset, 4);
        offset += 4;
    }

    *header_len = offset;
    return (len >= offset + frame->payload_len) ? 0 : -1;
}
```

## Masking (RFC 6455 Section 5.3)

**Critical**: Client-to-server frames MUST be masked. Server-to-client frames MUST NOT be masked.

```c
void ws_mask_payload(uint8_t *payload, size_t len, const uint8_t *mask) {
    // XOR each byte with corresponding mask byte
    for (size_t i = 0; i < len; i++) {
        payload[i] ^= mask[i % 4];
    }
}

// Generate cryptographically random masking key
void ws_generate_mask(uint8_t mask[4]) {
    // MUST use cryptographic RNG, not rand()
    if (RAND_bytes(mask, 4) != 1) {
        RAISE(Socket_Failed);
    }
}
```

## Opening Handshake (RFC 6455 Section 4)

```c
// Client request
const char *request =
    "GET /chat HTTP/1.1\r\n"
    "Host: server.example.com\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n";

// Server must validate and respond
int ws_validate_handshake(const char *key, char *accept_out) {
    // Concatenate with magic GUID
    const char *magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char combined[128];
    snprintf(combined, sizeof(combined), "%s%s", key, magic);

    // SHA-1 hash then Base64 encode
    unsigned char sha1_result[20];
    SHA1((unsigned char *)combined, strlen(combined), sha1_result);
    Base64_encode(sha1_result, 20, accept_out);

    return 0;
}
```

## Close Handshake (RFC 6455 Section 7)

```c
// Close frame format: [2-byte status code][optional reason]
typedef enum {
    WS_CLOSE_NORMAL       = 1000,  // Normal closure
    WS_CLOSE_GOING_AWAY   = 1001,  // Server shutting down
    WS_CLOSE_PROTOCOL_ERR = 1002,  // Protocol error
    WS_CLOSE_UNSUPPORTED  = 1003,  // Unsupported data type
    WS_CLOSE_NO_STATUS    = 1005,  // No status (reserved, never sent)
    WS_CLOSE_ABNORMAL     = 1006,  // Abnormal (reserved, never sent)
    WS_CLOSE_INVALID_DATA = 1007,  // Invalid UTF-8 in text frame
    WS_CLOSE_POLICY       = 1008,  // Policy violation
    WS_CLOSE_TOO_BIG      = 1009,  // Message too big
    WS_CLOSE_EXTENSION    = 1010,  // Missing required extension
    WS_CLOSE_INTERNAL_ERR = 1011,  // Internal server error
    WS_CLOSE_TLS_FAIL     = 1015,  // TLS handshake failure (reserved)
} WSCloseCode;

int ws_send_close(SocketWS_T ws, uint16_t code, const char *reason) {
    uint8_t payload[125];  // Max control frame payload
    size_t len = 0;

    // Status code in network byte order
    payload[0] = (code >> 8) & 0xFF;
    payload[1] = code & 0xFF;
    len = 2;

    // Optional reason (must be valid UTF-8)
    if (reason) {
        size_t reason_len = strlen(reason);
        if (reason_len > 123) reason_len = 123;  // Limit
        memcpy(payload + 2, reason, reason_len);
        len += reason_len;
    }

    return ws_send_frame(ws, WS_OPCODE_CLOSE, payload, len);
}
```

## UTF-8 Validation (RFC 6455 Section 8.1)

**All text frames MUST contain valid UTF-8**. Invalid UTF-8 requires closing with 1007.

```c
int ws_validate_text_frame(const uint8_t *data, size_t len) {
    // Use SocketUTF8_validate() from core
    if (!SocketUTF8_validate(data, len)) {
        ws_send_close(ws, WS_CLOSE_INVALID_DATA, "Invalid UTF-8");
        return -1;
    }
    return 0;
}
```

## Fragmentation (RFC 6455 Section 5.4)

```c
// Sending fragmented message
ws_send_frame(ws, WS_OPCODE_TEXT, chunk1, len1);        // FIN=0, opcode=text
ws_send_frame(ws, WS_OPCODE_CONTINUATION, chunk2, len2); // FIN=0, opcode=0
ws_send_frame(ws, WS_OPCODE_CONTINUATION, chunk3, len3); // FIN=1, opcode=0

// Receiving: reassemble until FIN=1
// Control frames CAN interleave data fragments
```

## Ping/Pong (RFC 6455 Section 5.5.2-3)

```c
// Pong MUST echo ping payload exactly
int ws_handle_ping(SocketWS_T ws, const uint8_t *data, size_t len) {
    return ws_send_frame(ws, WS_OPCODE_PONG, data, len);
}

// Unsolicited pongs are allowed (heartbeat)
// Only most recent ping needs response
```

## WebSocket over HTTP/2 (RFC 8441)

```c
// Uses CONNECT method with :protocol pseudo-header
// HEADERS frame:
//   :method = CONNECT
//   :protocol = websocket
//   :scheme = https
//   :path = /chat
//   :authority = server.example.com

// After HEADERS accepted, DATA frames carry WebSocket frames
// Each DATA frame = one or more WebSocket frames
```

## Security Considerations

1. **Origin validation**: Check `Origin` header against whitelist
2. **Masking requirement**: Reject unmasked client frames
3. **Frame size limits**: Enforce maximum payload size
4. **UTF-8 validation**: Validate all text frame content
5. **Rate limiting**: Limit frames/second per connection
6. **Close frame flooding**: Limit close attempts

## Files Reference

| File | Purpose |
|------|---------|
| `include/socket/SocketWS.h` | WebSocket API |
| `include/socket/SocketWSH2.h` | WebSocket over HTTP/2 |
| `src/socket/SocketWS.c` | WebSocket implementation |
| `src/socket/SocketWS-frame.c` | Frame encoding/decoding |
| `src/socket/SocketWSH2.c` | HTTP/2 WebSocket tunneling |
| `src/test/test_websocket.c` | WebSocket tests |
