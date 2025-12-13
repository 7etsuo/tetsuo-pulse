# HTTP/2 Server Completion Checklist (and RFC 8441 WebSockets-over-h2)
**Brief**: Checklist of remaining work for “full” HTTP/2 server support in `SocketHTTPServer` | **Tags**: `http2`, `server`, `h2`, `h2c`, `rfc9113`, `rfc8441`, `websocket`

This document tracks what is still missing (or incomplete) for a production-quality
HTTP/2 server integration in this repo’s high-level server API (`SocketHTTPServer`).

Scope:
- HTTP/2 server operation via `SocketHTTPServer` over TLS+ALPN (`h2`)
- HTTP/2 cleartext modes: h2c upgrade and prior-knowledge preface
- Correct connection lifecycle: draining, GOAWAY, stream teardown
- RFC 8441 “Extended CONNECT” WebSockets-over-h2 (optional but requested)

Non-goals (for this checklist):
- HTTP/2 client improvements (covered by `SocketHTTPClient`)
- HTTP/3 / QUIC

---

### Current Status (quick snapshot)
- **HTTP/2 core exists**: `include/http/SocketHTTP2.h` + `src/http/SocketHTTP2-*.c`
- **HTTP/2 server over TLS is wired into `SocketHTTPServer`**:
  - TLS handshake drives ALPN and switches to `CONN_STATE_HTTP2`
  - Streams are handled via `SocketHTTP2_Conn_set_stream_callback()`
  - Push is supported via `SocketHTTP2_Stream_push_promise()`
- **Gaps remain**: h2c upgrade, prior-knowledge, trailers, drain/GOAWAY, stream-error semantics, RFC 8441

---

## HTTP/2 Server: Missing / Incomplete Items

### Protocol negotiation & connection entrypoints

- [ ] **Implement h2c (HTTP/1.1 Upgrade: h2c) in `SocketHTTPServer`**
  - **Why**: `SocketHTTPServer_Config::enable_h2c_upgrade` exists, but the server
    currently does not perform upgrade detection or call the HTTP/2 upgrade API.
  - **Primary files**:
    - `src/http/SocketHTTPServer.c` (HTTP/1 request parse/dispatch path)
    - `include/http/SocketHTTPServer.h` (document behavior/limits)
    - `include/http/SocketHTTP2.h` / `src/http/SocketHTTP2-connection.c` (upgrade API)
  - **Implementation checklist**:
    - [ ] Detect h2c upgrade request: `Connection: Upgrade`, `Upgrade: h2c`,
      and `HTTP2-Settings` header.
    - [ ] Base64-decode `HTTP2-Settings` header value (RFC 9113 §3.2 / RFC 7540 legacy).
    - [ ] Call `SocketHTTP2_Conn_upgrade_server(socket, initial_request, settings, len, arena)`
      and transition connection into `CONN_STATE_HTTP2`.
    - [ ] Ensure stream 1 is pre-created and dispatched through the same handler path
      as native HTTP/2 streams.
    - [ ] Send `101 Switching Protocols` only as required by the upgrade path,
      and ensure no extra bytes are lost between HTTP/1 parser and HTTP/2 state.
  - **Done when**:
    - [ ] A cleartext HTTP/1.1 client can upgrade to h2c and the server processes
      requests over HTTP/2 on the same TCP connection.

- [ ] **Implement HTTP/2 prior-knowledge (cleartext preface) in `SocketHTTPServer`**
  - **Why**: A client may connect directly in cleartext HTTP/2 and send the connection
    preface `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` (RFC 9113 §3.4).
  - **Primary files**:
    - `src/http/SocketHTTPServer.c` (connection read/parse path)
    - `src/http/SocketHTTPServer-connections.c` (connection state/init)
    - `include/http/SocketHTTP2.h` (preface size constants)
  - **Implementation checklist**:
    - [ ] On a non-TLS connection, before HTTP/1 parsing, peek/accumulate first
      `HTTP2_PREFACE_SIZE` bytes and compare to the HTTP/2 preface.
    - [ ] If matched, create `SocketHTTP2_Conn_T` in server role and move to
      `CONN_STATE_HTTP2` without going through HTTP/1 parsing.
    - [ ] If not matched, continue HTTP/1 parsing as today.
  - **Done when**:
    - [ ] A prior-knowledge h2 client can connect (without TLS) and the server
      correctly processes streams/requests.

---

### Correct stream semantics & events

- [ ] **Handle `HTTP2_EVENT_TRAILERS_RECEIVED` in `SocketHTTPServer`**
  - **Why**: The core HTTP/2 stack emits trailers events, but the server wrapper
    does not consume them, so request bodies with trailers lose metadata.
  - **Primary files**:
    - `src/http/SocketHTTPServer.c` (see `server_http2_stream_cb()`)
    - `include/http/SocketHTTP2.h` (recv trailers API)
  - **Implementation checklist**:
    - [ ] In the HTTP/2 stream callback, handle `HTTP2_EVENT_TRAILERS_RECEIVED`.
    - [ ] Call `SocketHTTP2_Stream_recv_trailers()` and merge trailers into the
      request representation (or expose separately).
    - [ ] Decide server API: either merge into `SocketHTTP_Headers_T` or expose
      a separate trailers accessor on `SocketHTTPServer_Request_T`.
  - **Done when**:
    - [ ] Incoming request trailers are accessible to middleware/handler.

- [ ] **Fix stream-error handling: don’t close the entire connection on `SocketHTTP2_StreamError`**
  - **Why**: `SocketHTTP2_StreamError` is a stream-level error; other streams
    should typically continue (RFC 9113). The server wrapper currently treats it
    as fatal.
  - **Primary files**:
    - `src/http/SocketHTTPServer.c` (see `server_process_http2()`)
  - **Implementation checklist**:
    - [ ] In `server_process_http2()`, handle `SocketHTTP2_StreamError` as non-fatal:
      keep the connection alive, and rely on stream reset behavior in the core.
    - [ ] Ensure poll interest is still updated correctly after the exception.
  - **Done when**:
    - [ ] A single stream error resets that stream but other streams keep working.

---

### Graceful shutdown / draining for HTTP/2

- [ ] **Implement HTTP/2-aware drain using GOAWAY**
  - **Why**: Stopping accept() is not sufficient for HTTP/2; existing connections
    can open new streams unless GOAWAY is sent.
  - **Primary files**:
    - `src/http/SocketHTTPServer.c` (drain functions)
    - `include/http/SocketHTTP2.h` (GOAWAY API)
  - **Implementation checklist**:
    - [ ] On `SocketHTTPServer_drain()`, iterate existing connections:
      - [ ] For HTTP/2 connections, call `SocketHTTP2_Conn_goaway(conn, HTTP2_NO_ERROR, ...)`
        (or a best-effort equivalent) to stop creation of new streams.
    - [ ] Continue to service existing active streams until they complete or drain timeout expires.
    - [ ] Ensure `drain_poll()` considers “streams still active” (not only “connections open”)
      if you want strict drain semantics.
  - **Done when**:
    - [ ] Once drain begins, clients cannot start new streams and existing streams finish cleanly.

---

### Response feature parity / API completeness

- [ ] **Decide and document trailer sending for HTTP/2 responses**
  - **Why**: The HTTP/2 core supports `SocketHTTP2_Stream_send_trailers()`, but
    `SocketHTTPServer_Request_*` does not provide a way to set/send response trailers.
  - **Primary files**:
    - `include/http/SocketHTTPServer.h` (public API)
    - `src/http/SocketHTTPServer.c` (request helpers)
  - **Implementation checklist**:
    - [ ] Add request API to set trailers (e.g., `SocketHTTPServer_Request_trailer()`).
    - [ ] Ensure trailers are only legal at end-of-stream and are correctly ordered
      after DATA.
  - **Done when**:
    - [ ] Handlers can send trailers on HTTP/2 responses (and HTTP/1 behavior is
      defined—either unsupported or chunked trailers).

---

## RFC 8441: WebSockets-over-HTTP/2 (Extended CONNECT) Checklist

RFC 8441 replaces HTTP/1 Upgrade with an HTTP/2 `CONNECT` request that uses:
- `:method = CONNECT`
- `:protocol = websocket`
- `:scheme`, `:authority`, `:path`
and then exchanges WebSocket frames on the HTTP/2 DATA stream.

### Design decisions to make first
- [ ] **Decide whether RFC 8441 lives inside `SocketWS` or `SocketHTTP2`**
  - **Option A (recommended)**: new module `SocketWSH2` (thin adapter) that depends
    on `SocketHTTP2_Stream_T`.
  - **Option B**: extend `SocketWS` to accept an abstract I/O backend (TCP vs HTTP/2 stream).
  - **Option C**: embed directly into `SocketHTTPServer` (least reusable).

### Server-side support (HTTP/2)
- [ ] **Detect Extended CONNECT requests in `SocketHTTPServer`’s HTTP/2 request builder**
  - **Primary file**: `src/http/SocketHTTPServer.c` (`server_http2_build_request()`)
  - **Checklist**:
    - [ ] Parse and store the `:protocol` pseudo-header value.
    - [ ] Identify WebSocket-over-h2 when `:method == CONNECT` and `:protocol == websocket`.
    - [ ] Validate required pseudo-headers and reject invalid combinations with
      appropriate HTTP/2 errors (RST_STREAM / 4xx response mapping as chosen).

- [ ] **Expose an accept/upgrade API for RFC 8441**
  - **Public API options**:
    - [ ] Add a new function on request object:
      - `SocketWS_T SocketHTTPServer_Request_accept_websocket_h2(SocketHTTPServer_Request_T req);`
    - [ ] Or expose the underlying `SocketHTTP2_Stream_T` to a new adapter API.
  - **Done when**:
    - [ ] Handlers can accept a WebSocket-over-h2 request and then send/recv frames.

- [ ] **Implement WebSocket framing over HTTP/2 DATA**
  - **Checklist**:
    - [ ] Map WebSocket frames to/from HTTP/2 DATA payload bytes (no masking in either direction
      for RFC 8441; masking is specific to RFC 6455 over TCP).
    - [ ] Handle end-of-stream semantics: HTTP/2 END_STREAM should map to WebSocket close.
    - [ ] Support PING/PONG/CLOSE semantics.
    - [ ] Decide compression story:
      - [ ] Either disallow permessage-deflate initially for RFC 8441,
      - [ ] or wire it similarly to RFC 6455 path if already generic.

### Flow control & backpressure (critical)
- [ ] **Correctly interact with HTTP/2 flow control**
  - **Checklist**:
    - [ ] When receiving WebSocket DATA, ensure window updates occur (core may do it automatically;
      confirm behavior).
    - [ ] When sending, handle partial acceptance from `SocketHTTP2_Stream_send_data()` and
      buffer unsent bytes (similar to current response streaming buffering).
  - **Done when**:
    - [ ] Large WebSocket messages do not deadlock due to flow control windows.

### Close / error mapping
- [ ] **Define and implement error mappings**
  - **Checklist**:
    - [ ] WebSocket close code ↔ HTTP/2 RST_STREAM / response status
    - [ ] Protocol violations → close + stream reset
    - [ ] Connection-level GOAWAY interactions with active WebSocket streams

### Documentation & examples
- [ ] **Document RFC 8441 usage**
  - **Files**:
    - `docs/WEBSOCKET.md` (add a section on WebSockets-over-h2)
    - `docs/HTTP.md` (mention extended CONNECT support)
  - **Done when**:
    - [ ] A minimal server example exists (in `examples/`) showing acceptance and echo.

---

## Suggested implementation order (minimize risk)
- [ ] Fix stream-error handling (safe, isolated)
- [ ] Add GOAWAY-on-drain for HTTP/2
- [ ] Add trailers receive support
- [ ] Add h2c upgrade support
- [ ] Add prior-knowledge support
- [ ] Add RFC 8441 (largest surface area; do last)

---

## Notes / References
- RFC 9113 (HTTP/2): `https://www.rfc-editor.org/rfc/rfc9113`
- RFC 8441 (WebSockets over HTTP/2): `https://www.rfc-editor.org/rfc/rfc8441`


