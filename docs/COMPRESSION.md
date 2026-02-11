# DEFLATE and gzip Compression

Native DEFLATE (RFC 1951) and gzip (RFC 1952) implementation with no external dependencies. Used for HTTP Content-Encoding and WebSocket permessage-deflate (RFC 7692).

## Build

Compression is built by default:

```bash
cmake -S . -B build
cmake --build build -j$(nproc)
```

Build options:

| Option | Default | Description |
|--------|---------|-------------|
| `ENABLE_HTTP_COMPRESSION` | ON | HTTP gzip/deflate Content-Encoding |
| `ENABLE_NATIVE_DEFLATE` | ON | Use native DEFLATE (no zlib dependency) |
| `ENABLE_WS_NATIVE_DEFLATE` | ON | Use native DEFLATE for WebSocket |

## Headers

```c
#include "deflate/SocketDeflate.h"
```

## Decompression (Inflate)

### Streaming API

```c
Arena_T arena = Arena_new();

/* Create inflater with bomb protection (max 10MB output) */
SocketDeflate_Inflater_T inf = SocketDeflate_Inflater_new(arena, 10 * 1024 * 1024);

uint8_t output[4096];
size_t consumed, written;

SocketDeflate_Result rc = SocketDeflate_Inflater_inflate(inf,
    compressed_data, compressed_len, &consumed,
    output, sizeof(output), &written);

switch (rc) {
case DEFLATE_OK:
    /* Final block complete — all done */
    break;
case DEFLATE_INCOMPLETE:
    /* Need more input data */
    break;
case DEFLATE_OUTPUT_FULL:
    /* Output buffer full — call again with more space */
    break;
case DEFLATE_ERROR_BOMB:
    /* Decompression bomb detected */
    break;
default:
    fprintf(stderr, "Error: %s\n", SocketDeflate_result_string(rc));
    break;
}

/* Query state */
int done = SocketDeflate_Inflater_finished(inf);
size_t total_out = SocketDeflate_Inflater_total_out(inf);
size_t total_in = SocketDeflate_Inflater_total_in(inf);

/* Reset for reuse */
SocketDeflate_Inflater_reset(inf);

Arena_dispose(&arena);
```

### Multi-chunk Decompression

```c
SocketDeflate_Inflater_T inf = SocketDeflate_Inflater_new(arena, 0);
size_t offset = 0;

while (!SocketDeflate_Inflater_finished(inf) && offset < input_len) {
    size_t consumed, written;
    SocketDeflate_Result rc = SocketDeflate_Inflater_inflate(inf,
        input + offset, input_len - offset, &consumed,
        output + out_pos, output_cap - out_pos, &written);

    offset += consumed;
    out_pos += written;

    if (rc == DEFLATE_ERROR || rc == DEFLATE_ERROR_BOMB)
        break;
}
```

## Compression (Deflate)

### Compression Levels

| Level | Enum | Strategy | Block Type |
|-------|------|----------|------------|
| 0 | `DEFLATE_LEVEL_STORE` | No compression | Stored blocks only |
| 1 | `DEFLATE_LEVEL_FASTEST` | Fastest | Fixed Huffman |
| 3 | `DEFLATE_LEVEL_FAST` | Fast | Fixed Huffman |
| 6 | `DEFLATE_LEVEL_DEFAULT` | Balanced | Dynamic Huffman |
| 9 | `DEFLATE_LEVEL_BEST` | Best compression | Dynamic Huffman |

### Streaming API

```c
Arena_T arena = Arena_new();

/* Create deflater at default level */
SocketDeflate_Deflater_T def = SocketDeflate_Deflater_new(arena, DEFLATE_LEVEL_DEFAULT);

uint8_t output[8192];
size_t consumed, written;

/* Compress data */
SocketDeflate_Deflater_deflate(def,
    input_data, input_len, &consumed,
    output, sizeof(output), &written);

/* Finish (flush remaining data as final block) */
SocketDeflate_Deflater_finish(def, output + written, sizeof(output) - written, &written);

/* Reset for reuse */
SocketDeflate_Deflater_reset(def);

Arena_dispose(&arena);
```

### Buffer Sizing

```c
/* Compute maximum compressed size for buffer allocation */
size_t max_size = SocketDeflate_compress_bound(input_len);
uint8_t *buf = Arena_alloc(arena, max_size);
```

### Sync Flush (WebSocket)

For WebSocket permessage-deflate with context takeover:

```c
/* Compress message without final block marker */
SocketDeflate_Deflater_deflate(def, message, msg_len, &consumed,
    output, output_cap, &written);

/* Flush with sync marker (0x00 0x00 0xFF 0xFF) */
size_t flush_written;
SocketDeflate_Deflater_sync_flush(def,
    output + written, output_cap - written, &flush_written);
written += flush_written;

/* Strip 4-byte trailer for WebSocket transmission */
written -= 4;

/* Deflater state preserved — next message reuses LZ77 dictionary */
```

## gzip (RFC 1952)

gzip wraps DEFLATE with a header (metadata) and trailer (CRC-32 + size).

### Parse Header

```c
SocketDeflate_GzipHeader header;
SocketDeflate_Result rc = SocketDeflate_gzip_parse_header(data, len, &header);

if (rc == DEFLATE_OK) {
    printf("Method: %d\n", header.method);        /* 8 = DEFLATE */
    printf("OS: %s\n", SocketDeflate_gzip_os_string(header.os));
    if (header.filename)
        printf("Filename: %s\n", header.filename);
    printf("DEFLATE data starts at offset %zu\n", header.header_size);
}
```

### Verify Trailer

```c
/* After decompression, verify the 8-byte trailer */
uint32_t crc = SocketDeflate_crc32(0, decompressed_data, decompressed_len);

SocketDeflate_Result rc = SocketDeflate_gzip_verify_trailer(
    trailer_bytes,     /* 8 bytes: CRC32 + ISIZE (little-endian) */
    crc,               /* Computed CRC-32 */
    (uint32_t)decompressed_len);  /* Original size mod 2^32 */
```

### CRC-32

```c
/* Single-pass CRC */
uint32_t crc = SocketDeflate_crc32(0, data, len);

/* Incremental CRC */
uint32_t crc = 0;
crc = SocketDeflate_crc32(crc, chunk1, chunk1_len);
crc = SocketDeflate_crc32(crc, chunk2, chunk2_len);

/* Combine two CRCs (for parallel computation) */
uint32_t combined = SocketDeflate_crc32_combine(crc_a, crc_b, len_b);
```

## HTTP Content-Encoding

When `ENABLE_HTTP_COMPRESSION` is ON, the HTTP client/server layers handle Content-Encoding automatically:

- **Client**: Sends `Accept-Encoding: gzip, deflate` and decompresses responses
- **Server**: Compresses responses when client supports it

## WebSocket permessage-deflate (RFC 7692)

When `ENABLE_WS_NATIVE_DEFLATE` is ON, WebSocket compression uses this native DEFLATE implementation:

| Mode | Compression | LZ77 Dictionary |
|------|-------------|-----------------|
| Context takeover (default) | `sync_flush()` (BFINAL=0) | Preserved across messages |
| No context takeover | `finish()` (BFINAL=1) | Reset between messages |

The 4-byte trailer (`0x00 0x00 0xFF 0xFF`) is automatically stripped on send and restored on receive per RFC 7692 Section 7.2.1.

## Error Codes

| Code | Description |
|------|-------------|
| `DEFLATE_OK` | Success |
| `DEFLATE_INCOMPLETE` | Need more input |
| `DEFLATE_OUTPUT_FULL` | Output buffer full |
| `DEFLATE_ERROR` | General error |
| `DEFLATE_ERROR_INVALID_BTYPE` | Invalid block type (BTYPE=11) |
| `DEFLATE_ERROR_INVALID_CODE` | Invalid Huffman code |
| `DEFLATE_ERROR_INVALID_DISTANCE` | Invalid distance code (30-31) |
| `DEFLATE_ERROR_DISTANCE_TOO_FAR` | Distance exceeds window |
| `DEFLATE_ERROR_HUFFMAN_TREE` | Invalid Huffman tree |
| `DEFLATE_ERROR_BOMB` | Decompression bomb detected |
| `DEFLATE_ERROR_GZIP_MAGIC` | Invalid gzip magic bytes |
| `DEFLATE_ERROR_GZIP_METHOD` | Unsupported compression method |
| `DEFLATE_ERROR_GZIP_CRC` | CRC-32 mismatch |
| `DEFLATE_ERROR_GZIP_SIZE` | Original size mismatch |

## See Also

- [WebSocket](WEBSOCKET.md) — WebSocket permessage-deflate
- [HTTP](HTTP.md) — HTTP Content-Encoding
- [HTTP/3](HTTP3.md) — HTTP/3 (uses QPACK, not DEFLATE for headers)
