# HTTP/3 (RFC 9114)

HTTP/3 runs HTTP semantics over QUIC (RFC 9000), replacing TCP+TLS with UDP-based transport. This library provides complete client and server APIs.

## Build Requirements

```bash
cmake -S . -B build -DENABLE_TLS=ON
cmake --build build -j$(nproc)

# Optional: enable server push (disabled by default)
cmake -S . -B build -DENABLE_TLS=ON -DENABLE_H3_PUSH=ON
```

Requires OpenSSL or LibreSSL with TLS 1.3 support.

## Architecture

```
Application
    │
    ├── SocketHTTP3_Client_T  (or SocketHTTP3_Server_T)
    │       │
    │       ├── SocketHTTP3_Conn_T      (HTTP/3 framing + connection lifecycle)
    │       │       ├── Stream Map       (request/control/QPACK streams)
    │       │       ├── QPACK            (header compression)
    │       │       └── Output Queue     (wire data staging)
    │       │
    │       └── SocketQUICTransport_T    (or SocketQUICServer_T)
    │               ├── TLS 1.3          (handshake, key derivation)
    │               ├── Loss Detection   (RTT, PTO, packet tracking)
    │               ├── Congestion Ctrl  (NewReno cwnd gating)
    │               └── UDP Socket
    │
    └── Arena_T  (memory lifecycle)
```

The **output queue model** bridges HTTP/3 and QUIC: HTTP/3 operations generate wire data into an output queue; the transport layer drains and sends it over UDP.

## Client API

### Headers

```c
#include "http/SocketHTTP3-client.h"
```

### Quick Start

```c
Arena_T arena = Arena_new();

/* Create client with defaults */
SocketHTTP3_Client_T client = SocketHTTP3_Client_new(arena, NULL);

/* Connect (blocking QUIC handshake + H3 init) */
if (SocketHTTP3_Client_connect(client, "example.com", 443) < 0) {
    fprintf(stderr, "Connect failed\n");
    Arena_dispose(&arena);
    return -1;
}

/* Synchronous GET request */
SocketHTTP_Headers_T resp_headers;
int status;
void *body;
size_t body_len;

int rc = SocketHTTP3_Client_request(client,
    HTTP_METHOD_GET, "/index.html",
    NULL,            /* no extra headers */
    NULL, 0,         /* no body */
    &resp_headers, &status, &body, &body_len);

if (rc == 0) {
    printf("Status: %d\n", status);
    printf("Body: %.*s\n", (int)body_len, (char *)body);
}

/* Cleanup */
SocketHTTP3_Client_close(client);
Arena_dispose(&arena);
```

### Configuration

```c
SocketHTTP3_ClientConfig config;
SocketHTTP3_ClientConfig_defaults(&config);

/* QUIC transport */
config.idle_timeout_ms = 30000;           /* Connection idle timeout */
config.max_stream_data = 262144;          /* 256KB per-stream flow control */
config.initial_max_streams_bidi = 100;    /* Max concurrent requests */

/* TLS */
config.ca_file = "/path/to/ca-bundle.crt"; /* NULL = system CAs */
config.verify_peer = 1;                     /* Verify server certificate */

/* Timeouts */
config.connect_timeout_ms = 5000;         /* QUIC handshake timeout */
config.request_timeout_ms = 30000;        /* Per-request timeout */

/* HTTP/3 settings (sent in SETTINGS frame) */
config.h3_settings.max_field_section_size = 65536;
config.h3_settings.qpack_max_table_capacity = 4096;
config.h3_settings.qpack_blocked_streams = 100;

SocketHTTP3_Client_T client = SocketHTTP3_Client_new(arena, &config);
```

### Streaming API

For fine-grained control over request/response lifecycle:

```c
/* Create a streaming request */
SocketHTTP3_Request_T req = SocketHTTP3_Client_new_request(client);

/* Build and send headers */
SocketHTTP_Headers_T hdrs = SocketHTTP_Headers_new(arena);
SocketHTTP_Headers_add(hdrs, ":method", "POST");
SocketHTTP_Headers_add(hdrs, ":path", "/api/data");
SocketHTTP_Headers_add(hdrs, ":scheme", "https");
SocketHTTP_Headers_add(hdrs, ":authority", "example.com");
SocketHTTP_Headers_add(hdrs, "content-type", "application/json");

SocketHTTP3_Request_send_headers(req, hdrs, /*end_stream=*/0);
SocketHTTP3_Client_flush(client);  /* Send queued data */

/* Send body */
const char *body = "{\"key\": \"value\"}";
SocketHTTP3_Request_send_data(req, body, strlen(body), /*end_stream=*/1);
SocketHTTP3_Client_flush(client);

/* Poll for response */
while (SocketHTTP3_Request_recv_state(req) < H3_REQ_RECV_HEADERS_RECEIVED) {
    SocketHTTP3_Client_poll(client, 1000);
}

/* Read response headers */
SocketHTTP_Headers_T resp;
int status;
SocketHTTP3_Request_recv_headers(req, &resp, &status);

/* Read response body */
char buf[4096];
int end = 0;
while (!end) {
    SocketHTTP3_Client_poll(client, 1000);
    ssize_t n = SocketHTTP3_Request_recv_data(req, buf, sizeof(buf), &end);
    if (n > 0)
        fwrite(buf, 1, n, stdout);
}
```

### Alt-Svc Discovery

Detect HTTP/3 support from HTTP/1.1 or HTTP/2 responses:

```c
/* Parse Alt-Svc header from prior HTTP response */
char alt_host[256];
uint16_t h3_port = SocketHTTP3_parse_alt_svc(
    "h3=\":443\"; ma=86400", alt_host, sizeof(alt_host));

if (h3_port > 0) {
    /* Connect via HTTP/3 */
    SocketHTTP3_Client_connect(client, alt_host[0] ? alt_host : host, h3_port);
}
```

## Server API

### Headers

```c
#include "http/SocketHTTP3-server.h"
```

### Quick Start

```c
Arena_T arena = Arena_new();

/* Configure server */
SocketHTTP3_ServerConfig config;
SocketHTTP3_ServerConfig_defaults(&config);
config.bind_addr = "0.0.0.0";
config.port = 443;
config.cert_file = "/path/to/cert.pem";
config.key_file = "/path/to/key.pem";

/* Create and start */
SocketHTTP3_Server_T server = SocketHTTP3_Server_new(arena, &config);

/* Register request handler */
SocketHTTP3_Server_on_request(server, handle_request, NULL);

/* Start listening */
if (SocketHTTP3_Server_start(server) < 0) {
    fprintf(stderr, "Failed to start server\n");
    Arena_dispose(&arena);
    return -1;
}

/* Event loop */
while (running) {
    SocketHTTP3_Server_poll(server, 100);
}

/* Graceful shutdown */
SocketHTTP3_Server_shutdown(server);
SocketHTTP3_Server_close(server);
Arena_dispose(&arena);
```

### Request Handler

```c
static void
handle_request(SocketHTTP3_Request_T req,
               const SocketHTTP_Headers_T headers,
               void *userdata)
{
    /* Read request info from headers */
    const char *method = SocketHTTP_Headers_get(headers, ":method");
    const char *path = SocketHTTP_Headers_get(headers, ":path");

    /* Build response headers */
    Arena_T arena = /* get from server context */;
    SocketHTTP_Headers_T resp = SocketHTTP_Headers_new(arena);
    SocketHTTP_Headers_add(resp, ":status", "200");
    SocketHTTP_Headers_add(resp, "content-type", "text/html");

    /* Send response */
    const char *body = "<h1>Hello from HTTP/3</h1>";
    SocketHTTP3_Request_send_headers(req, resp, /*end_stream=*/0);
    SocketHTTP3_Request_send_data(req, body, strlen(body), /*end_stream=*/1);
}
```

### Server Configuration

```c
SocketHTTP3_ServerConfig config;
SocketHTTP3_ServerConfig_defaults(&config);

config.bind_addr = "0.0.0.0";        /* Bind address */
config.port = 443;                     /* Listen port */
config.cert_file = "server.crt";       /* TLS certificate (required) */
config.key_file = "server.key";        /* TLS private key (required) */
config.idle_timeout_ms = 30000;        /* Per-connection idle timeout */
config.initial_max_streams_bidi = 100; /* Max concurrent requests per conn */
config.max_stream_data = 262144;       /* 256KB per-stream window */
config.max_connections = 256;          /* Max concurrent connections */
config.max_header_size = 65536;        /* Max decoded header size */
```

## Request/Response Lifecycle

Both client and server use `SocketHTTP3_Request_T` for request/response exchange:

### Send State Machine

```
IDLE → HEADERS_SENT → BODY_SENT → TRAILERS_SENT → DONE
```

- `send_headers(req, hdrs, end_stream)` — Send initial HEADERS frame
- `send_data(req, data, len, end_stream)` — Send DATA frame
- `send_trailers(req, trailers)` — Send trailing HEADERS (implicitly closes)

### Receive State Machine

```
IDLE → HEADERS_RECEIVED → BODY_RECEIVING → COMPLETE
```

- `recv_headers(req, &hdrs, &status)` — Read decoded headers
- `recv_data(req, buf, len, &end_stream)` — Read DATA payload

### Header Validation

Headers are validated per RFC 9114 Section 4.3:

**Request headers** (client → server):
- Required pseudo-headers: `:method`, `:path`, `:scheme`
- `:authority` recommended
- No connection-specific headers (`Connection`, `Transfer-Encoding`, `Upgrade`)

**Response headers** (server → client):
- Required: `:status`
- Status `101` (Switching Protocols) is prohibited
- No connection-specific headers

## Server Push (Optional)

Build with `-DENABLE_H3_PUSH=ON`. Server push allows pre-emptive responses.

```c
#include "http/SocketHTTP3-push.h"

/* Server: push a resource during request handling */
static void
handle_request(SocketHTTP3_Request_T req,
               const SocketHTTP_Headers_T headers,
               void *userdata)
{
    SocketHTTP3_Conn_T conn = /* get from server context */;

    /* Allocate a push ID */
    uint64_t push_id;
    if (SocketHTTP3_Conn_allocate_push_id(conn, &push_id) < 0)
        return;  /* Client hasn't sent MAX_PUSH_ID */

    /* Send PUSH_PROMISE on the request stream */
    SocketHTTP_Headers_T promised = SocketHTTP_Headers_new(arena);
    SocketHTTP_Headers_add(promised, ":method", "GET");
    SocketHTTP_Headers_add(promised, ":path", "/style.css");
    SocketHTTP_Headers_add(promised, ":scheme", "https");
    SocketHTTP_Headers_add(promised, ":authority", "example.com");

    uint64_t req_stream = SocketHTTP3_Request_stream_id(req);
    SocketHTTP3_Conn_send_push_promise(conn, req_stream, push_id, promised);

    /* Open push stream and send the pushed response */
    SocketHTTP3_Request_T push = SocketHTTP3_Conn_open_push_stream(conn, push_id);

    SocketHTTP_Headers_T push_resp = SocketHTTP_Headers_new(arena);
    SocketHTTP_Headers_add(push_resp, ":status", "200");
    SocketHTTP_Headers_add(push_resp, "content-type", "text/css");

    SocketHTTP3_Request_send_headers(push, push_resp, 0);
    SocketHTTP3_Request_send_data(push, css_data, css_len, 1);

    /* Continue with the original response... */
}
```

**Client-side push handling:**

```c
/* Register callback for incoming push promises */
SocketHTTP3_Conn_on_push(conn, on_push_promise, userdata);

/* Send MAX_PUSH_ID to allow server pushes */
SocketHTTP3_Conn_send_max_push_id(conn, 10);

/* Cancel an unwanted push */
SocketHTTP3_Conn_cancel_push(conn, push_id);
```

## Connection Lifecycle

### States

```
IDLE → OPEN → GOAWAY_SENT/GOAWAY_RECV → CLOSING → CLOSED
```

- **IDLE**: Created but not initialized
- **OPEN**: Critical streams opened, SETTINGS exchanged
- **GOAWAY_SENT/RECV**: Graceful shutdown in progress
- **CLOSING**: Both sides have sent GOAWAY
- **CLOSED**: Connection terminated

### Critical Streams

Each HTTP/3 connection opens three unidirectional streams:

| Stream | Client IDs | Server IDs | Purpose |
|--------|-----------|-----------|---------|
| Control | 2 | 3 | SETTINGS, GOAWAY, MAX_PUSH_ID |
| QPACK Encoder | 6 | 7 | Dynamic table updates |
| QPACK Decoder | 10 | 11 | Acknowledgments |

## Error Codes

| Code | Name | Meaning |
|------|------|---------|
| 0x0100 | `H3_NO_ERROR` | Graceful close |
| 0x0101 | `H3_GENERAL_PROTOCOL_ERROR` | Protocol violation |
| 0x0102 | `H3_INTERNAL_ERROR` | Internal error |
| 0x0103 | `H3_STREAM_CREATION_ERROR` | Stream creation failed |
| 0x0104 | `H3_CLOSED_CRITICAL_STREAM` | Required stream closed |
| 0x0105 | `H3_FRAME_UNEXPECTED` | Frame on wrong stream |
| 0x0106 | `H3_FRAME_ERROR` | Malformed frame |
| 0x0107 | `H3_EXCESSIVE_LOAD` | Resource exhaustion |
| 0x0108 | `H3_ID_ERROR` | Invalid ID |
| 0x0109 | `H3_SETTINGS_ERROR` | Bad settings |
| 0x010A | `H3_MISSING_SETTINGS` | No SETTINGS received |
| 0x010B | `H3_REQUEST_REJECTED` | Request not processed |
| 0x010C | `H3_REQUEST_CANCELLED` | Request cancelled |
| 0x010D | `H3_REQUEST_INCOMPLETE` | Partial request |
| 0x010E | `H3_MESSAGE_ERROR` | Malformed message |
| 0x010F | `H3_CONNECT_ERROR` | CONNECT failure |
| 0x0110 | `H3_VERSION_FALLBACK` | Retry with HTTP/1.1 |

## V1 Simplifications

The transport layer has documented simplifications that don't prevent HTTP/3 from functioning:

- **No retransmission** — Lost packets detected but not retransmitted
- **No 0-RTT** — Always full QUIC handshake
- **No connection migration** — Fixed network path
- **Immediate ACK** — No delayed ACK optimization
- **Fixed 4-byte packet numbers**
- **One QUIC packet per UDP datagram** (no coalescing)

## See Also

- [QUIC Transport](QUIC.md) — Underlying QUIC transport layer
- [QPACK](QPACK.md) — Header compression
- [COMPRESSION](COMPRESSION.md) — DEFLATE/gzip compression
- [TLS Configuration](TLS-CONFIG.md) — TLS settings
- [HTTP/1.1 and HTTP/2](HTTP.md) — Earlier HTTP versions
