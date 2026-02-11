# QPACK Header Compression (RFC 9204)

QPACK compresses HTTP headers for HTTP/3. Unlike HPACK (HTTP/2), QPACK avoids head-of-line blocking by using separate encoder/decoder streams.

## Overview

QPACK uses three components:
1. **Static table** — 99 pre-defined header entries (RFC 9204 Appendix A)
2. **Dynamic table** — Connection-scoped table of recently used headers
3. **Encoder/decoder streams** — Unidirectional QUIC streams for table synchronization

```
Encoder                              Decoder
   │                                    │
   ├── Encoder Stream (type 0x02) ────→ │  (table updates)
   │                                    │
   │ ←──── Decoder Stream (type 0x03) ──┤  (acknowledgments)
   │                                    │
   ├── HEADERS frame on request ──────→ │  (compressed headers)
   │                                    │
```

## Settings

QPACK behavior is negotiated via HTTP/3 SETTINGS:

| Setting | ID | Default | Description |
|---------|-----|---------|-------------|
| `QPACK_MAX_TABLE_CAPACITY` | 0x01 | 0 | Maximum dynamic table size in bytes |
| `QPACK_BLOCKED_STREAMS` | 0x07 | 0 | Max streams that can be blocked on table updates |

```c
/* Configure via HTTP/3 settings */
SocketHTTP3_Settings settings;
SocketHTTP3_Settings_init(&settings);
settings.qpack_max_table_capacity = 4096;  /* 4KB dynamic table */
settings.qpack_blocked_streams = 100;       /* Allow 100 blocked streams */
```

## Index Addressing (RFC 9204 Section 3.2)

QPACK uses four index types:

| Type | Base | Direction | Usage |
|------|------|-----------|-------|
| **Absolute** | 0 = first insertion | Monotonically increasing | Internal tracking |
| **Encoder-relative** | 0 = most recent | Decreasing from insertion point | Encoder stream |
| **Field-relative** | 0 = Base - 1 | Decreasing from field section Base | Field sections |
| **Post-base** | 0 = Base | Increasing from Base | Entries added during encoding |

## Encoder Stream Instructions (Section 4.3)

The encoder stream carries table modification instructions:

```c
/* Set dynamic table capacity */
SocketQPACK_EncoderStream_write_capacity(enc, 4096);

/* Insert with name reference (static or dynamic) */
SocketQPACK_EncoderStream_write_insert_nameref(enc,
    /*is_static=*/1, /*name_index=*/1,
    "example.com", 11);

/* Insert with literal name */
SocketQPACK_EncoderStream_write_insert_literal(enc,
    "x-custom", 8, "value", 5);

/* Duplicate existing entry */
SocketQPACK_EncoderStream_write_duplicate(enc, /*index=*/0);
```

## Decoder Stream Instructions (Section 4.4)

The decoder stream carries acknowledgments:

```c
/* Acknowledge a field section (frees references) */
SocketQPACK_DecoderStream_write_section_ack(dec, stream_id);

/* Cancel a stream (free references without processing) */
SocketQPACK_DecoderStream_write_stream_cancel(dec, stream_id);

/* Increment Known Received Count */
SocketQPACK_DecoderStream_write_insert_count_inc(dec, increment);
```

## Field Section Encoding (Section 4.5)

### Prefix

Every encoded field section begins with a prefix:

```c
/* Encode prefix (Required Insert Count + Base) */
SocketQPACK_encode_prefix(buf, buflen, &written,
    required_insert_count, base, max_entries);

/* Decode prefix */
SocketQPACK_decode_prefix(buf, buflen, &consumed,
    &required_insert_count, &base, max_entries);
```

### Representation Types

Six encoding modes are available, chosen based on whether the header exists in the static/dynamic table:

| Type | Prefix Bits | Description |
|------|-------------|-------------|
| Indexed (static) | `1` + `1` | Reference static table entry |
| Indexed (dynamic) | `1` + `0` | Reference dynamic table entry |
| Indexed post-base | `0001` | Entry inserted during this encoding |
| Literal with name ref (static) | `01` + `N` + `1` | Static name, literal value |
| Literal with name ref (dynamic) | `01` + `N` + `0` | Dynamic name, literal value |
| Literal with post-base name | `0000` | Post-base name, literal value |
| Literal with literal name | `001` | Both name and value are literal |

## Dynamic Table

### Capacity

The dynamic table has a maximum capacity set by `QPACK_MAX_TABLE_CAPACITY`. Each entry occupies:

```
entry_size = len(name) + len(value) + 32
```

The 32-byte overhead accounts for internal tracking. When the table is full, oldest entries are evicted.

### Entry Lifecycle

1. **Insertion** — Encoder adds entry via encoder stream instruction
2. **Reference** — Field sections reference entries by index
3. **Acknowledgment** — Decoder acknowledges field sections via decoder stream
4. **Eviction** — Oldest entries removed when capacity exceeded

## Blocked Streams

When a field section references dynamic table entries that haven't been received yet, the stream is "blocked" until the encoder stream delivers the required insertions.

The `QPACK_BLOCKED_STREAMS` setting limits how many streams can be in this state. The encoder respects this limit when choosing whether to use dynamic table references.

## Error Codes

| Code | Name | Trigger |
|------|------|---------|
| 0x0200 | `QPACK_DECOMPRESSION_FAILED` | Field section decode failure |
| 0x0201 | `QPACK_ENCODER_STREAM_ERROR` | Invalid encoder stream instruction |
| 0x0202 | `QPACK_DECODER_STREAM_ERROR` | Invalid decoder stream instruction |

## Integration with HTTP/3

QPACK is used automatically by `SocketHTTP3_Request_send_headers()` and `SocketHTTP3_Request_recv_headers()`. The connection layer manages encoder/decoder streams transparently.

For most applications, you do not need to interact with QPACK directly — just configure the settings and the HTTP/3 layer handles the rest.

## See Also

- [HTTP/3](HTTP3.md) — HTTP/3 protocol
- [HTTP/1.1 and HTTP/2](HTTP.md) — HPACK for HTTP/2
