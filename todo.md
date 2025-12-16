# HTTP/2 “FULL RFC” TODO (Socket Library)

This checklist is for making HTTP/2 **fully RFC-compliant and non-hacky** across the repo:

- **HTTP/2 protocol**: RFC 9113
- **HPACK**: RFC 7541
- **h2c upgrade**: RFC 7540 §3.2 (legacy semantics still seen in the wild; deprecated/obsoleted by RFC 9113 Appendix B)
- **WebSockets over HTTP/2 (Extended CONNECT)**: RFC 8441

Scope includes **core protocol**, **SocketHTTPServer**, and **SocketHTTPClient**.  
An agent should check items off as they’re implemented, reviewed, and verified.

---

## Checklist conventions

- Each item has:
  - **What to do**
  - **Where** (files/modules)
  - **Done when** (clear acceptance criteria)

---

## A) Critical correctness fixes (must do first)

### A1) Fix invalid iteration in `SocketHTTP2_Conn_get_concurrent_streams()`

- [x] **What to do**: Fix `SocketHTTP2_Conn_get_concurrent_streams()`; it currently iterates `i < conn->stream_count` but `conn->streams` is a hash table (`HTTP2_STREAM_HASH_SIZE` buckets), so this can undercount and/or go out of bounds.
- [x] **Where**: `src/http/SocketHTTP2-connection.c`
- [x] **Done when**:
  - [x] Iteration is over the hash table bucket count (or a maintained list of streams), not `stream_count`.
  - [x] Returns correct count for active (non-idle, non-closed) streams.
  - [x] No OOB access possible.

### A2) Make flow-control window consumption atomic (no partial decrement)

- [x] **What to do**: `http2_flow_consume_level()` now checks both connection and stream windows before decrementing either, preventing partial consumption.
- [x] **Where**: `src/http/SocketHTTP2-flow.c` (`http2_flow_consume_level`)
- [x] **Done when**:
  - [x] Consume stream+connection only after both checks pass (implemented with pre-checks then atomic decrement).
  - [x] Same guarantee for both recv and send window consumption paths (handled uniformly in shared helper).

### A3) Implement RFC timeouts that are currently configured but not enforced

- [x] **What to do**: Enforced `settings_timeout_ms`, `ping_timeout_ms`, `idle_timeout_ms` in `SocketHTTP2_Conn_process()` with GOAWAY on expiration (tracked via new time fields in conn struct).
- [x] **Where**: `src/http/SocketHTTP2-connection.c` (process, new, flush, frame handlers), `include/http/SocketHTTP2-private.h` (added tracking fields)
- [x] **Done when**:
  - [x] SETTINGS ack timeout triggers GOAWAY with `HTTP2_SETTINGS_TIMEOUT` if unacked after timeout.
  - [x] PING ack timeout enforced when `ping_pending` set, GOAWAY with `HTTP2_PROTOCOL_ERROR`.
  - [x] Idle timeout closes idle (no active streams) connections with GOAWAY `HTTP2_NO_ERROR`, skips if active streams present.
  - [x] All times use `Socket_get_monotonic_ms()` for reliable, non-wall-clock checks; updated on recv/process/send activity.

---

## B) Core HTTP/2 protocol completeness (RFC 9113)

### B1) SETTINGS: implement and negotiate all settings required for planned features ✅ COMPLETED

- [x] **What to do**: Add missing settings that the project claims/needs, especially for RFC 8441:
  - `SETTINGS_ENABLE_CONNECT_PROTOCOL (0x8)` (required to legitimately use `:protocol`)
- [x] **Where**:
  - `include/http/SocketHTTP2.h` (settings enums/constants)
  - `include/http/SocketHTTP2-private.h` (settings arrays + indices)
  - `src/http/SocketHTTP2-connection.c` (parse/apply settings + ACK behavior)
- [x] **Done when**:
  - [x] Unknown settings are ignored per RFC rules (unless you intentionally treat some as protocol errors—document that choice).
  - [x] `SETTINGS_ENABLE_CONNECT_PROTOCOL` is stored and enforced for `:protocol` usage.
  - [x] Settings changes correctly update dependent state (e.g., window deltas for `INITIAL_WINDOW_SIZE`).

### B2) HEADERS / pseudo-header validation audit (strict RFC behavior) ✅ COMPLETED

- [x] **What to do**: Audit header decoding and request/response construction for:
  - pseudo-header order and duplication rules
  - forbidden connection-specific headers (`Connection`, `Upgrade`, etc.)
  - `TE` only allowed value: `trailers`
  - request required pseudo-headers `:method`, `:scheme`, `:authority`, `:path` (as applicable)
  - response required pseudo-header `:status`
- [x] **Where**:
  - `src/http/SocketHTTP2-stream.c` (HEADERS processing)
  - `src/http/SocketHTTP2-connection.c` (PUSH_PROMISE / CONTINUATION integration)
  - `src/http/SocketHTTPServer.c` (`server_http2_build_request`)
- [x] **Done when**:
  - [x] Violations map to correct stream vs connection errors (RST_STREAM vs GOAWAY).
  - [x] Behavior is documented in headers/docs (what error code is used).

### B2a) Enforce "malformed message" rules (field validity + Content-Length consistency) ✅ COMPLETED

- [x] **What to do**: Implement/verify strict malformed-message handling per RFC 9113:
  - Field names MUST be lowercase when constructing HTTP/2 messages.
  - Minimal field name/value validation (reject prohibited chars like NUL/CR/LF; reject leading/trailing whitespace in values).
  - Treat messages as malformed when `content-length` doesn't match total DATA payload length (subject to HTTP semantics like 204/304/HEAD).
  - Ensure malformed requests/responses are treated as **stream errors** of type `PROTOCOL_ERROR` (and optionally send an HTTP 400 for malformed requests when possible).
- [x] **Where**:
  - `src/http/SocketHTTP2-stream.c` (decoded header validation, trailer validation)
  - `src/http/SocketHTTP2-connection.c` (error mapping: stream vs connection)
  - `src/http/SocketHTTPServer.c` / `src/http/SocketHTTPClient.c` (semantic translation, Content-Length accounting)
- [x] **Done when**:
  - [x] Uppercase field names are rejected (malformed).
  - [x] Prohibited characters (NUL/CR/LF) and invalid whitespace boundaries are rejected (malformed).
  - [x] `content-length` mismatch with DATA bytes is detected and handled as malformed.
  - [x] Malformed messages do not get forwarded/accepted by higher layers.

### B2b) Cookie header splitting/recombination rules (RFC 9113 §8.2.3) ✅ COMPLETED

- [x] **What to do**: Support Cookie header splitting for better compression, and ensure correct recombination when translating out of HTTP/2:
  - If multiple `cookie` fields are received after decompression, they MUST be concatenated into one octet string using delimiter `"; "` before passing to a non-HTTP/2 context (e.g., HTTP/1.1, generic app server expectations).
- [x] **Where**:
  - `src/http/SocketHTTP2-stream.c` (header decode normalization)
  - `src/http/SocketHTTPServer.c` / `src/http/SocketHTTPClient.c` (request/response object construction)
- [x] **Done when**:
  - [x] Multiple Cookie fields become a single effective Cookie string with `"; "` delimiters when exposed to apps/HTTP/1.1 translation paths.

### B3) CONTINUATION sequencing and interleaving rules (hard guarantee) ✅ COMPLETED

- [x] **What to do**: Confirm that while `expecting_continuation` is set:
  - only CONTINUATION frames for the same stream are accepted
  - interleaving other frames is rejected per RFC
  - max continuation frames and max header list size limits are enforced (DoS)
- [x] **Where**: `src/http/SocketHTTP2-connection.c`, `src/http/SocketHTTP2-stream.c`, `include/http/SocketHTTP2-private.h`
- [x] **Done when**:
  - [x] Violations produce correct GOAWAY/stream reset behavior.
  - [x] No state leaks across streams after END_HEADERS.

### B4) GOAWAY correctness (last stream id + stream creation rules)

- [ ] **What to do**:
  - Ensure `last_peer_stream_id` / `max_peer_stream_id` are correctly maintained.
  - Ensure no new streams are created beyond peer GOAWAY limit.
  - Ensure graceful close behavior does not break in-flight streams.
- [ ] **Where**: `src/http/SocketHTTP2-connection.c`, `src/http/SocketHTTP2-stream.c`
- [ ] **Done when**:
  - [ ] New streams after GOAWAY are rejected correctly.
  - [ ] Connection closes cleanly once in-flight work completes or timeout triggers.

### B4a) Stream state machine compliance (allowed frames per state; correct error level)

- [ ] **What to do**: Validate the stream state machine enforces RFC 9113 frame-type constraints per state (IDLE/RESERVED/OPEN/HALF_CLOSED/CLOSED):
  - In `reserved (local)` / `reserved (remote)` states, enforce allowed send/receive frame types and treat invalid frame types as **connection errors** of type `PROTOCOL_ERROR` where required.
  - In `half-closed (local)`, ensure only `WINDOW_UPDATE`, `PRIORITY`, and `RST_STREAM` are sent; other outbound frames are blocked.
  - Ensure protocol loop avoidance: MUST NOT send `RST_STREAM` in response to `RST_STREAM`.
- [ ] **Where**:
  - `src/http/SocketHTTP2-stream.c` (state transitions + per-frame handlers)
  - `src/http/SocketHTTP2-connection.c` (error mapping: stream vs connection, GOAWAY vs RST_STREAM)
- [ ] **Done when**:
  - [ ] Frame-type/state violations reliably map to the correct stream/connection error behavior.
  - [ ] No RST_STREAM ping-pong loops are possible.

### B5) Frame validation audit (length/flags/stream-id constraints)

- [ ] **What to do**: Confirm `http2_frame_validate()` enforces RFC constraints for each frame type:
  - Stream 0 vs non-zero requirements
  - Fixed-length frames (PING=8, RST=4, WINDOW_UPDATE=4, etc.)
  - Invalid flags rejection
  - `MAX_FRAME_SIZE` enforcement for inbound frames
- [ ] **Where**: `src/http/SocketHTTP2-frame.c`
- [ ] **Done when**:
  - [ ] Any deviation triggers correct `HTTP2_FRAME_SIZE_ERROR` / `HTTP2_PROTOCOL_ERROR` mapping.

### B6) PRIORITY is deprecated (RFC 9113) — keep behavior explicit

- [ ] **What to do**: Keep ignoring PRIORITY frames (allowed), but ensure validation does not create false protocol errors.
- [ ] **Where**: `src/http/SocketHTTP2-priority.c`, `src/http/SocketHTTP2-frame.c`
- [ ] **Done when**:
  - [ ] PRIORITY frames never crash/kill connection; they’re ignored with optional debug logs.

### B7) Extension points: unknown frames + extensible elements (RFC 9113 §5.5)

- [ ] **What to do**:
  - Implementations MUST ignore unknown/unsupported values in extensible protocol elements.
  - Implementations MUST discard frames with unknown or unsupported frame types.
  - Extension frames MUST NOT appear “in the middle of a field block”; if they do, treat as a **connection error** of type `PROTOCOL_ERROR`.
- [ ] **Where**:
  - `src/http/SocketHTTP2-frame.c` (frame parsing/validation surface)
  - `src/http/SocketHTTP2-connection.c` (dispatch rules + header-block/continuation state machine)
- [ ] **Done when**:
  - [ ] Unknown frame types are safely discarded without corrupting state.
  - [ ] Unknown/unsupported values in extensible elements are ignored.
  - [ ] Extension frames during an in-progress header block reliably produce connection `PROTOCOL_ERROR`.

---

## C) HPACK completeness (RFC 7541)

### C1) HPACK security and limits audit (“HPACK bombs”)

- [ ] **What to do**: Ensure header decompression is protected:
  - max header list size enforcement
  - dynamic table size updates via SETTINGS_HEADER_TABLE_SIZE
  - bounded number of decoded headers
- [ ] **Where**:
  - `src/http/SocketHPACK*.c`
  - `src/http/SocketHTTP2-stream.c` (decode integration)
  - `include/http/SocketHTTP2.h` (limits constants like `SOCKETHTTP2_MAX_DECODED_HEADERS`)
- [ ] **Done when**:
  - [ ] Oversized/abusive inputs trigger `HTTP2_COMPRESSION_ERROR` or appropriate stream/conn error.
  - [ ] No unbounded allocations from peer-controlled header blocks.

### C2) HPACK dynamic table size update ordering (RFC 7541 §4.2) + bounds (RFC 7541 §6.3)

- [ ] **What to do**:
  - When SETTINGS changes `SETTINGS_HEADER_TABLE_SIZE`, ensure the encoder signals the new max via a dynamic table size update at the **start** of the first header block after the change (in HTTP/2: after SETTINGS is acknowledged).
  - If max size changes multiple times between header blocks, ensure signaling rules are followed (smallest then final; at most two updates).
  - Treat a dynamic table size update exceeding the peer’s acknowledged limit as a decoding error.
- [ ] **Where**:
  - `src/http/SocketHPACK*.c` (encoder/decoder table size update handling)
  - `src/http/SocketHTTP2-stream.c` (integration around SETTINGS ACK and first header block)
- [ ] **Done when**:
  - [ ] Table size updates are emitted in the correct place/order and never violate the negotiated maximum.
  - [ ] Violations reliably map to `HTTP2_COMPRESSION_ERROR`.

### C3) HPACK Huffman strict decoding (RFC 7541 §5.2)

- [ ] **What to do**: Ensure the HPACK decoder rejects invalid Huffman encodings:
  - Padding longer than 7 bits is a decoding error.
  - Padding that isn’t a prefix of the EOS code is a decoding error.
  - A Huffman-encoded string containing the EOS symbol is a decoding error.
- [ ] **Where**: `src/http/SocketHPACK*.c`
- [ ] **Done when**:
  - [ ] Invalid Huffman inputs reliably produce decoding errors and are surfaced as `HTTP2_COMPRESSION_ERROR`.

---

## D) SocketHTTPServer: “production full” HTTP/2 behavior

### D1) Confirm server push is RFC-correct and not leaky

- [ ] **What to do**: Validate server push behavior:
  - honor peer `ENABLE_PUSH`
  - correct promised stream id allocation and state (`RESERVED_LOCAL`)
  - correct request pseudo-headers for pushed resources
- [ ] **Where**:
  - `src/http/SocketHTTPServer.c` (push API surface)
  - `src/http/SocketHTTP2-stream.c` (push promise)
- [ ] **Done when**:
  - [ ] Push works only when enabled and never violates stream id parity rules.

### D2) Ensure HTTP/2 request/response trailers are RFC-correct

- [ ] **What to do**:
  - Confirm request trailers are captured and exposed consistently.
  - Confirm response trailer API only emits trailers at end-of-stream and rejects pseudo-headers in trailers.
- [ ] **Where**:
  - `src/http/SocketHTTPServer.c`
  - `include/http/SocketHTTPServer.h` (`SocketHTTPServer_Request_trailers`, `SocketHTTPServer_Request_trailer`)
- [ ] **Done when**:
  - [ ] Trailers cannot be sent before headers/body ordering rules allow.
  - [ ] Trailers are visible to handlers (request) and delivered to peers (response).

### D3) h2c + prior-knowledge are “real”, not hacky (verify edge cases)

- [ ] **What to do**: Audit upgrade and prior-knowledge entry:
  - Ensure HTTP/1 parser does not consume bytes incorrectly before upgrade.
  - Ensure buffered bytes are correctly transferred into HTTP/2 recv buffer.
  - Ensure 101 response is correct for h2c upgrade.
- [ ] **Where**: `src/http/SocketHTTPServer.c`, `src/http/SocketHTTP2-connection.c`
- [ ] **Done when**:
  - [ ] Upgrade and prior-knowledge work with real clients without dropped bytes.
  - [ ] h2c upgrade request requires **exactly one** `HTTP2-Settings` header and `Connection: Upgrade, HTTP2-Settings` (server MUST NOT upgrade otherwise).
  - [ ] Server MUST ignore `"h2"` tokens in the HTTP/1.1 `Upgrade` header (h2 is TLS-only).
  - [ ] Server MUST NOT send `HTTP2-Settings` header field in responses; SETTINGS are sent as HTTP/2 frames.
  - [ ] HTTP2-Settings decoding uses base64url rules (token68; no trailing `=`).
  - [ ] After sending 101, server’s first HTTP/2 frame is SETTINGS; client then sends the HTTP/2 connection preface (including SETTINGS).
  - [ ] If the HTTP/1.1 upgrade request contains a payload body, it is fully received before switching to HTTP/2 frames (client-side requirement; server-side robustness).
  - [ ] Behavior is documented in `docs/HTTP2-SERVER.md`.

---

## E) SocketHTTPClient: implement real HTTP/2 (currently incomplete)

### E1) Stop claiming “automatic HTTP/2 negotiation” unless it’s true

- [ ] **What to do**: Align documentation with reality OR implement negotiation fully.
- [ ] **Where**:
  - `docs/HTTP.md` currently claims “automatic protocol negotiation”
  - `src/http/SocketHTTPClient-pool.c` explicitly says “HTTP/2 stream multiplexing (future)”
- [ ] **Done when**:
  - [ ] Either docs are corrected to “HTTP/2 WIP” OR the client actually negotiates and uses HTTP/2 end-to-end.

### E2) Implement HTTP/2 connection establishment for client

- [ ] **What to do**:
  - TLS: configure ALPN to include `"h2"` and select HTTP/2 when negotiated.
  - Cleartext (optional): support prior-knowledge and/or h2c upgrade if `allow_http2_cleartext`.
  - Create/manage `SocketHTTP2_Conn_T` per origin and complete handshake.
- [ ] **Where**:
  - `src/http/SocketHTTPClient.c`
  - `src/http/SocketHTTPClient-pool.c`
  - TLS integration: `include/tls/SocketTLS*.h`, client TLS setup code paths
- [ ] **Done when**:
  - [ ] A client can make a GET to an h2-capable server and actually uses HTTP/2 frames/streams.

### E3) Implement request/response mapping over HTTP/2 streams

- [ ] **What to do**:
  - Open a stream per request.
  - Send request HEADERS (+ DATA if body).
  - Receive response HEADERS/DATA/TRAILERS and populate `SocketHTTPClient_Response`.
  - Correctly handle `END_STREAM`, backpressure, and partial sends.
- [ ] **Where**:
  - `src/http/SocketHTTPClient.c`
  - `src/http/SocketHTTPClient-*.c` (pool/retry/auth if needed)
  - `src/http/SocketHTTP2-*.c` (if missing APIs for client use)
- [ ] **Done when**:
  - [ ] HTTP/2 responses behave like HTTP/1 client API semantics (status/headers/body).
  - [ ] Errors map to client error codes consistently.

### E4) Implement real HTTP/2 multiplexing in the pool (not “future”)

- [ ] **What to do**:
  - Track active streams per connection.
  - Queue or open new connections when `MAX_CONCURRENT_STREAMS` reached.
  - Handle GOAWAY by draining/retrying requests as appropriate.
- [ ] **Where**: `src/http/SocketHTTPClient-pool.c`, `include/http/SocketHTTPClient-private.h`
- [ ] **Done when**:
  - [ ] Multiple concurrent requests to same origin share a single HTTP/2 connection.

---

## F) RFC 8441 WebSockets-over-HTTP/2 (no hacky “just bytes”)

### F1) Implement `SETTINGS_ENABLE_CONNECT_PROTOCOL (0x8)` and enforce it

- [ ] **What to do**: Add support and enforce `:protocol` usage only when negotiated.
- [ ] **Where**: `include/http/SocketHTTP2.h`, `src/http/SocketHTTP2-connection.c`
- [ ] **Done when**:
  - [ ] Server and client correctly negotiate and validate Extended CONNECT.
  - [ ] `SETTINGS_ENABLE_CONNECT_PROTOCOL` value is validated as 0 or 1.
  - [ ] A sender MUST NOT send value 0 after previously sending value 1 (enforced in our local settings behavior).
  - [ ] If a client uses `:protocol` without first receiving `SETTINGS_ENABLE_CONNECT_PROTOCOL=1`, the peer treats it as malformed and triggers the correct stream error (`PROTOCOL_ERROR`).
  - [ ] On requests bearing `:protocol`, `:scheme` and `:path` are also required; and `:authority` semantics follow the RFC 8441 override (server MUST NOT treat `:authority` as a proxy-tunnel host).

### F2) Replace “callback-only DATA delivery” with a real stream-backed WebSocket transport

- [ ] **What to do**:
  - Provide a real WebSocket framing API over an HTTP/2 stream (RFC 8441).
  - Correctly map close/error semantics between WebSocket and HTTP/2 (RST_STREAM, END_STREAM).
  - Integrate with HTTP/2 flow control (WINDOW_UPDATE) for backpressure-safe operation.
- [ ] **Where**:
  - Current hook: `src/http/SocketHTTPServer.c` (`SocketHTTPServer_Request_accept_websocket_h2`)
  - Candidate design: adapt `SocketWS` to accept a “transport vtable” (TCP vs HTTP/2 stream), or create a dedicated adapter module (e.g., `SocketWSH2`) and wire it here.
- [ ] **Done when**:
  - [ ] Users can handle RFC 8441 WebSockets with the same high-level ergonomics as RFC 6455 WebSockets.
  - [ ] No masking assumptions leak from RFC 6455 into RFC 8441 behavior.
  - [ ] The CONNECT request for WebSockets uses `:method=CONNECT` and `:protocol=websocket`, and does **not** include HTTP/1.1-only `Connection`/`Upgrade` headers.
  - [ ] Do not perform RFC 6455 `Sec-WebSocket-Key` / `Sec-WebSocket-Accept` processing for RFC 8441 (it is superseded); but still support `Origin`, `sec-websocket-version`, `sec-websocket-protocol`, and `sec-websocket-extensions` headers as per RFC 8441.
  - [ ] WebSocket “orderly close” maps to END_STREAM; abnormal closure/reset maps to `RST_STREAM` with `CANCEL`.

---

## G) Documentation accuracy fixes (must not invent APIs)

### G1) Fix incorrect HTTP version symbol names in docs

- [x] **What to do**: Replace `HTTP_VERSION_2_0` with the real `HTTP_VERSION_2` symbol in docs/examples.
- [x] **Where**:
  - `docs/HTTP.md`
  - `include/http/SocketHTTP.h` (source of truth)
- [x] **Done when**:
  - [x] Docs compile mentally against headers (no nonexistent symbols).

### G2) Ensure HTTP/2 docs reflect reality (no outdated status notes)

- [ ] **What to do**: Update HTTP/2 docs to match current code status (avoid stale “missing” items for already-implemented features like h2c, prior-knowledge, trailers, drain/GOAWAY).
- [ ] **Where**: `docs/HTTP2-SERVER.md` (and any other HTTP/2 sections in `docs/HTTP.md`)
- [ ] **Done when**:
  - [ ] Doc reflects the current code and only lists real remaining gaps.

---

## H) Final “FULL RFC” definition-of-done (must satisfy all)

- [ ] **HTTP/2 core**: passes RFC 9113 compliance review for frame/state/flow control behavior and error mapping (stream vs connection).
- [ ] **HPACK**: passes RFC 7541 compliance + DoS/limits review.
- [ ] **Server**: supports ALPN h2, h2c upgrade, prior-knowledge, push, trailers, GOAWAY drain; no hacks/byte-loss edge cases.
- [ ] **Client**: actually negotiates and uses HTTP/2, supports multiplexing, and maps semantics into `SocketHTTPClient_Response`.
- [ ] **RFC 8441**: Extended CONNECT supported with proper settings negotiation and a real WebSocket-over-h2 transport (not a “raw DATA callback”).
- [ ] **Docs**: no invented APIs; examples match headers in `include/`.


