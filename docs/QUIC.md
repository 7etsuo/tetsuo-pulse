# QUIC Transport (RFC 9000)

QUIC provides reliable, multiplexed transport over UDP with built-in TLS 1.3 encryption. This library implements QUIC v1 with client and server transport APIs.

## Build Requirements

```bash
cmake -S . -B build -DENABLE_TLS=ON
cmake --build build -j$(nproc)
```

Requires OpenSSL or LibreSSL with TLS 1.3 support.

## Architecture

```
SocketQUICTransport_T / SocketQUICServer_T
    │
    ├── Handshake (SocketQUICHandshake + SocketQUICTLS)
    │       └── TLS 1.3 via OpenSSL (ALPN, transport params)
    │
    ├── Packet Protection (SocketQUICCrypto)
    │       ├── AEAD: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
    │       └── Header Protection: AES-ECB / ChaCha20 masks
    │
    ├── Frames (SocketQUICFrame)
    │       └── 22 standard frame types + DATAGRAM
    │
    ├── Streams (SocketQUICStream + SocketQUICFlow)
    │       ├── Bidirectional / Unidirectional
    │       └── Connection + stream flow control
    │
    ├── Loss Detection (SocketQUICLoss)
    │       ├── RTT estimation (smoothed_rtt, rttvar, min_rtt)
    │       ├── Packet/time threshold detection
    │       └── Probe Timeout (PTO)
    │
    ├── Congestion Control (SocketQUICCongestion)
    │       ├── NewReno: slow start, congestion avoidance, recovery
    │       ├── Persistent congestion (§7.6)
    │       └── ECN-CE handling
    │
    └── UDP Socket
```

## Client Transport

### Headers

```c
#include "quic/SocketQUICTransport.h"
```

### Quick Start

```c
Arena_T arena = Arena_new();

/* Create transport with defaults */
SocketQUICTransport_T t = SocketQUICTransport_new(arena, NULL);

/* Set stream data callback */
SocketQUICTransport_set_stream_callback(t, on_stream_data, userdata);

/* Connect (blocking QUIC handshake) */
if (SocketQUICTransport_connect(t, "example.com", 443) < 0) {
    fprintf(stderr, "QUIC connect failed\n");
    Arena_dispose(&arena);
    return -1;
}

/* Open a bidirectional stream */
uint64_t stream_id = SocketQUICTransport_open_bidi_stream(t);

/* Send data */
SocketQUICTransport_send_stream(t, stream_id,
    (const uint8_t *)"Hello", 5, /*fin=*/0);

/* Poll for responses */
while (SocketQUICTransport_is_connected(t)) {
    SocketQUICTransport_poll(t, 1000);
}

/* Close */
SocketQUICTransport_close(t);
Arena_dispose(&arena);
```

### Configuration

```c
SocketQUICTransportConfig config;
SocketQUICTransportConfig_defaults(&config);

config.idle_timeout_ms = 30000;           /* Connection idle timeout */
config.max_stream_data = 262144;          /* 256KB per-stream window */
config.initial_max_data = 1048576;        /* 1MB connection window */
config.initial_max_streams_bidi = 100;    /* Max concurrent bidi streams */
config.connect_timeout_ms = 5000;         /* Handshake timeout */
config.alpn = "h3";                       /* ALPN protocol */
config.ca_file = NULL;                    /* NULL = system CAs */
config.verify_peer = 1;                   /* Verify server certificate */

SocketQUICTransport_T t = SocketQUICTransport_new(arena, &config);
```

### Stream Callback

```c
static void
on_stream_data(uint64_t stream_id,
               const uint8_t *data,
               size_t len,
               int fin,
               void *userdata)
{
    printf("Stream %lu: %zu bytes%s\n",
           stream_id, len, fin ? " (FIN)" : "");
    /* Process data... */
}
```

## Server Transport

### Headers

```c
#include "quic/SocketQUICServer.h"
```

### Quick Start

```c
Arena_T arena = Arena_new();

/* Configure server */
SocketQUICServerConfig config;
SocketQUICServerConfig_defaults(&config);
config.bind_addr = "0.0.0.0";
config.port = 443;
config.cert_file = "server.crt";
config.key_file = "server.key";

/* Create and start */
SocketQUICServer_T server = SocketQUICServer_new(arena, &config);

SocketQUICServer_set_callbacks(server, on_connection, on_stream, userdata);

if (SocketQUICServer_listen(server) < 0) {
    fprintf(stderr, "Listen failed\n");
    Arena_dispose(&arena);
    return -1;
}

/* Event loop */
while (running) {
    SocketQUICServer_poll(server, 100);
}

SocketQUICServer_close(server);
Arena_dispose(&arena);
```

### Server Callbacks

```c
static void
on_connection(QUICServerConn_T conn, void *userdata)
{
    printf("New QUIC connection\n");
}

static void
on_stream(QUICServerConn_T conn,
          uint64_t stream_id,
          const uint8_t *data,
          size_t len,
          int fin,
          void *userdata)
{
    printf("Stream %lu: %zu bytes\n", stream_id, len);

    /* Echo back */
    SocketQUICServer_send_stream(conn, stream_id, data, len, fin);
}
```

### Server Configuration

```c
SocketQUICServerConfig config;
SocketQUICServerConfig_defaults(&config);

config.bind_addr = "0.0.0.0";             /* Bind address */
config.port = 443;                          /* Listen port */
config.cert_file = "server.crt";            /* TLS certificate (required) */
config.key_file = "server.key";             /* TLS private key (required) */
config.idle_timeout_ms = 30000;             /* Per-connection idle timeout */
config.max_stream_data = 262144;            /* 256KB per-stream window */
config.initial_max_data = 1048576;          /* 1MB connection window */
config.initial_max_streams_bidi = 100;      /* Max concurrent streams */
config.alpn = "h3";                         /* ALPN protocol */
config.max_connections = 256;               /* Max concurrent connections */
```

## Streams

QUIC multiplexes data over independent streams within a single connection.

### Stream Types

| Type | ID Pattern | Initiator | Example IDs |
|------|-----------|-----------|-------------|
| Client bidi | 4n | Client | 0, 4, 8, 12 |
| Server bidi | 4n+1 | Server | 1, 5, 9, 13 |
| Client unidi | 4n+2 | Client | 2, 6, 10, 14 |
| Server unidi | 4n+3 | Server | 3, 7, 11, 15 |

### Opening Streams

```c
/* Client opens bidirectional stream: 0, 4, 8, ... */
uint64_t id = SocketQUICTransport_open_bidi_stream(t);
if (id == UINT64_MAX)
    /* Error: stream limit reached */
```

### Sending Data

```c
/* Send with FIN=0 (more data to come) */
SocketQUICTransport_send_stream(t, stream_id, data, len, 0);

/* Send with FIN=1 (end of stream) */
SocketQUICTransport_send_stream(t, stream_id, final_data, final_len, 1);
```

## Flow Control

QUIC enforces flow control at two levels:

- **Connection level**: Total bytes across all streams (controlled by `initial_max_data`)
- **Stream level**: Bytes per stream (controlled by `max_stream_data`)

Both are configured via transport parameters and updated via `MAX_DATA` / `MAX_STREAM_DATA` frames.

## Loss Detection (RFC 9002)

### RTT Estimation

The loss module tracks:
- **smoothed_rtt**: Exponentially weighted moving average
- **rttvar**: RTT variance for timeout calculations
- **min_rtt**: Minimum observed RTT

### Packet Loss Detection

Two mechanisms detect lost packets:
- **Packet threshold**: A packet is lost if 3 later packets have been acknowledged
- **Time threshold**: A packet is lost if 9/8 * max(smoothed_rtt, latest_rtt) has elapsed since it was sent

### Probe Timeout (PTO)

```
PTO = smoothed_rtt + max(4 * rttvar, 1ms) + max_ack_delay
```

PTO triggers when no ACK is received, with exponential backoff.

## Congestion Control (RFC 9002 Section 7)

NewReno congestion control gates all 1-RTT packet sends:

### Phases

| Phase | Window Growth | Trigger |
|-------|--------------|---------|
| **Slow Start** | cwnd += acked_bytes | Initial phase |
| **Recovery** | cwnd frozen | Packet loss detected |
| **Congestion Avoidance** | cwnd += mds * acked / cwnd | Recovery exit |

### Key Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| Initial cwnd | 12000 bytes | 10 * max_datagram_size |
| Min cwnd | 2400 bytes | 2 * max_datagram_size |
| Max cwnd | 1MB | Upper bound |
| Loss reduction | 1/2 | Multiplicative decrease factor |
| Persistent congestion threshold | 3 | PTO multiplier for persistent detection |

### Persistent Congestion

If lost packets span longer than `3 * (smoothed_rtt + max(4*rttvar, 1ms) + max_ack_delay)` with no ACKs between them, the congestion window resets to minimum (2400 bytes) and returns to slow start.

### ECN Support

The congestion controller handles ECN Congestion Experienced (ECN-CE) signals, which trigger the same recovery entry as packet loss. ACK frames with ECN counts are processed and compared against previous counts.

## Connection ID Management

Each connection uses opaque Connection IDs (CIDs) for routing:

- Default CID length: 8 bytes
- Multiple CIDs per connection (max 8)
- NEW_CONNECTION_ID / RETIRE_CONNECTION_ID frames for rotation
- Server demuxes by Destination CID

## Packet Types

| Type | Header | Encryption Level | Usage |
|------|--------|-----------------|-------|
| Initial | Long | Initial keys (from DCID) | Handshake start |
| Handshake | Long | Handshake keys | TLS completion |
| 1-RTT | Short | Application keys | Data transfer |

## Frame Types

All 22 standard QUIC frame types are implemented:

| Frame | Type | Purpose |
|-------|------|---------|
| PADDING | 0x00 | Padding for amplification protection |
| PING | 0x01 | Keep-alive / RTT probe |
| ACK | 0x02-03 | Acknowledge received packets |
| RESET_STREAM | 0x04 | Abort stream sending |
| STOP_SENDING | 0x05 | Request stream abort |
| CRYPTO | 0x06 | TLS handshake data |
| NEW_TOKEN | 0x07 | Address validation token |
| STREAM | 0x08-0f | Application data |
| MAX_DATA | 0x10 | Connection flow control |
| MAX_STREAM_DATA | 0x11 | Stream flow control |
| MAX_STREAMS | 0x12-13 | Stream limit |
| DATA_BLOCKED | 0x14 | Flow control blocked |
| STREAM_DATA_BLOCKED | 0x15 | Stream flow control blocked |
| STREAMS_BLOCKED | 0x16-17 | Stream limit blocked |
| NEW_CONNECTION_ID | 0x18 | Supply new CID |
| RETIRE_CONNECTION_ID | 0x19 | Retire old CID |
| PATH_CHALLENGE | 0x1a | Path validation |
| PATH_RESPONSE | 0x1b | Path validation response |
| CONNECTION_CLOSE | 0x1c-1d | Close connection |
| HANDSHAKE_DONE | 0x1e | Server confirms handshake |
| DATAGRAM | 0x30-31 | Unreliable datagram |

## V1 Simplifications

These are explicitly documented and planned for future versions:

| Feature | Status | Impact |
|---------|--------|--------|
| Retransmission | Detect only | Lost packets not retransmitted |
| 0-RTT | Infrastructure ready | Always full handshake |
| Connection migration | Module exists | Fixed path only |
| PMTU discovery | Not implemented | 1200-byte minimum assumed |
| Delayed ACK | Not implemented | Immediate ACK (more overhead) |
| Coalesced packets | Not implemented | One QUIC packet per UDP datagram |
| CID rotation | Implemented | Not used in V1 transport |
| Version negotiation | Not implemented | QUIC v1 only |

## See Also

- [HTTP/3](HTTP3.md) — HTTP/3 over QUIC
- [TLS Configuration](TLS-CONFIG.md) — TLS/DTLS settings
- [QPACK](QPACK.md) — HTTP/3 header compression
