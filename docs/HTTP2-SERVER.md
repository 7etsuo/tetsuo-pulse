# HTTP/2 Server Guide {#http2_server_guide}
**Brief**: How `SocketHTTPServer` negotiates and serves HTTP/2 (ALPN, h2c, prior-knowledge), stream lifecycle, trailers, GOAWAY/drain, and RFC 8441 status.

This document explains how HTTP/2 server support is wired into `SocketHTTPServer_T` on top of `SocketHTTP2_Conn_T`.

Related:
- `docs/HTTP.md` (HTTP overview; client + general patterns)
- `include/http/SocketHTTPServer.h` (public server API reference)
- `include/http/SocketHTTP2.h` (HTTP/2 connection/stream API)
- `docs/http_2.md` (implementation checklist + status notes)

---

## What “HTTP/2 server support” means in this repo

`SocketHTTPServer` supports:
- **HTTP/1.1** request parsing and response writing
- **HTTP/2** multiplexed streams on a single connection (RFC 9113)
- **HTTP/2 server push** via `SocketHTTPServer_Request_push()`
- **Request trailers (HTTP/2)** exposed via `SocketHTTPServer_Request_trailers()`
- **Response trailers (HTTP/2)** via `SocketHTTPServer_Request_trailer()`
- **Graceful shutdown** for HTTP/2 connections via **GOAWAY** during drain

`SocketHTTPServer` does **not** expose a public “HTTP/2-only server API”. The public API is **request-centric** (`SocketHTTPServer_Request_T`) and works for both HTTP/1.1 and HTTP/2.

---

## Protocol negotiation: how a connection becomes HTTP/2

`SocketHTTPServer` supports three server-side entry paths into HTTP/2:

### 1) HTTPS + ALPN (“h2”) (recommended)

If `SocketHTTPServer_Config.tls_context` is set, accepted sockets are TLS-enabled and driven through a TLS handshake. Once TLS completes, the server checks ALPN:

- If ALPN negotiated `"h2"` and `config.max_version >= HTTP_VERSION_2`, the connection switches to HTTP/2 mode.
- Otherwise, it continues as HTTP/1.1.

**To enable ALPN “h2”** you must configure the TLS context’s ALPN list to include `"h2"` (and usually `"http/1.1"` as fallback).

### 2) Cleartext prior-knowledge HTTP/2 (preface sniff)

For cleartext listeners (no TLS), the server peeks the first 24 bytes for the HTTP/2 client connection preface:

```
PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
```

If present, it consumes the preface and initializes an HTTP/2 connection immediately.

### 3) h2c upgrade from HTTP/1.1 (optional)

If `config.enable_h2c_upgrade = 1`, and an HTTP/1.1 request includes:
- `Upgrade: h2c`
- `HTTP2-Settings: <base64url>`

the server responds with `101 Switching Protocols`, upgrades the connection, applies the decoded settings payload, and continues in HTTP/2 mode.

**Security note**: h2c is cleartext; do not enable on untrusted networks unless you fully understand the implications (see Security section below).

---

## How HTTP/2 requests are surfaced to your handler

For HTTP/2 connections, `SocketHTTPServer`:
- Creates a `SocketHTTP2_Conn_T` bound to the underlying socket
- Registers an internal per-stream callback
- Builds a `SocketHTTP_Request` object from `:method`, `:path`, `:scheme`, `:authority` and regular headers
- Invokes your `SocketHTTPServer_Handler(req, userdata)` when the request is complete (headers-only, or headers+body complete)

### Request bodies (buffered vs streaming)

The server supports two request body handling modes:

- **Buffered**: the server buffers request body data and then your handler can read it via `SocketHTTPServer_Request_body()` / `SocketHTTPServer_Request_body_len()`.
- **Streaming**: your handler calls `SocketHTTPServer_Request_body_stream(req, cb, userdata)` and the server delivers body chunks to the callback as DATA arrives (and does not buffer the full body).

This works for both HTTP/1.1 and HTTP/2; in HTTP/2 it is driven by DATA frames.

### Request trailers (HTTP/2)

If the client sends trailing headers at end of stream, they are collected and exposed via:

- `SocketHTTPServer_Request_trailers(req)`

---

## Sending responses on HTTP/2

Your handler builds a response via the request object:

- **Status**: `SocketHTTPServer_Request_status(req, 200);`
- **Headers**: `SocketHTTPServer_Request_header(req, "content-type", "text/plain");`
- **Body (buffered)**: `SocketHTTPServer_Request_body_string(req, "ok");` then `SocketHTTPServer_Request_finish(req);`
- **Body (streaming)**:
  - `SocketHTTPServer_Request_begin_stream(req);`
  - `SocketHTTPServer_Request_send_chunk(req, data, len);` (repeat)
  - optionally add response trailers (HTTP/2): `SocketHTTPServer_Request_trailer(req, "grpc-status", "0");`
  - `SocketHTTPServer_Request_end_stream(req);`

### Response trailers (HTTP/2)

Trailers are only emitted on HTTP/2 responses:
- Use `SocketHTTPServer_Request_trailer(req, name, value)` before finalization.
- They are sent at end-of-stream (either after a buffered body on `finish()`, or after streaming `end_stream()`).

---

## HTTP/2 server push

From an HTTP/2 request handler, you can initiate server push:

- `SocketHTTPServer_Request_push(req, "/style.css", headers);`

Push is ignored/unsupported on HTTP/1.x (returns -1). Client settings (e.g., `ENABLE_PUSH=0`) can disable push.

---

## Graceful shutdown for HTTP/2 (GOAWAY + drain)

When `SocketHTTPServer_drain()` begins, HTTP/2 connections:
- Send **GOAWAY** to stop new streams from being created.
- Continue to service in-flight streams until completion or drain timeout.

If drain times out, remaining connections are closed (some streams may be aborted).

---

## Error semantics (connection vs stream)

HTTP/2 distinguishes:
- **Connection errors** (protocol/flow control violations): typically lead to GOAWAY and connection close.
- **Stream errors** (a single stream is invalid): only that stream is reset/closed; other streams continue.

`SocketHTTPServer` follows this model:
- `SocketHTTP2_StreamError` is treated as **non-fatal** at the connection level.
- `SocketHTTP2_ProtocolError` / `SocketHTTP2_FlowControlError` are treated as **fatal** (GOAWAY + close).

---

## RFC 8441: WebSockets over HTTP/2 (Extended CONNECT) — current status

The HTTP/2 server path recognizes the Extended CONNECT shape:
- `:method = CONNECT`
- `:protocol = websocket`

However, **full RFC 8441 support is not complete** in the public server API:
- There is currently **no `SocketWS_T` that can be backed by an HTTP/2 stream**, so handlers cannot “upgrade” an HTTP/2 stream into a `SocketWS_T` the same way HTTP/1.1 upgrade works.

**What to do today**
- Use **HTTP/1.1 WebSocket upgrade (RFC 6455)** via `SocketHTTPServer_Request_upgrade_websocket()` (works over HTTP/1.1 and HTTPS).

**Design note for future work**
- Proper RFC 8441 support requires a stream-backed WebSocket transport, backpressure integration with HTTP/2 flow control, and mapping close/error semantics between WebSocket and HTTP/2 stream resets.

---

## Security notes

- **Prefer TLS + ALPN** for HTTP/2. It’s the most interoperable and easiest to secure.
- **Treat h2c as advanced/opt-in** (`enable_h2c_upgrade`). It is cleartext and easier to misuse.
- **Flow control matters**: HTTP/2 servers must enforce connection/stream windows and limits to avoid memory/bandwidth DoS.
- **Trailers are untrusted input**: validate and bound trailer counts/sizes like normal headers.

See also:
- `SECURITY.md` (project security policy + best practices)
- `docs/SECURITY.md` (detailed technical security notes)

---

## Minimal example (server loop)

```c
#include "http/SocketHTTPServer.h"
#include "http/SocketHTTP.h"

static void
handle_request (SocketHTTPServer_Request_T req, void *userdata)
{
  (void)userdata;

  if (SocketHTTPServer_Request_method (req) == HTTP_METHOD_GET)
    {
      SocketHTTPServer_Request_status (req, 200);
      SocketHTTPServer_Request_header (req, "content-type", "text/plain");
      SocketHTTPServer_Request_body_string (req, "hello\n");
      SocketHTTPServer_Request_finish (req);
      return;
    }

  SocketHTTPServer_Request_status (req, 404);
  SocketHTTPServer_Request_body_string (req, "not found\n");
  SocketHTTPServer_Request_finish (req);
}

int
main (void)
{
  SocketHTTPServer_Config cfg;
  SocketHTTPServer_T server;

  SocketHTTPServer_config_defaults (&cfg);
  cfg.port = 8080;
  cfg.max_version = HTTP_VERSION_2;
  cfg.enable_h2c_upgrade = 0;

  server = SocketHTTPServer_new (&cfg);
  SocketHTTPServer_set_handler (server, handle_request, NULL);
  SocketHTTPServer_start (server);

  for (;;)
    SocketHTTPServer_process (server, 1000);
}
```


