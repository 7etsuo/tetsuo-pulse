# gRPC Client Guide

This guide covers the `SocketGRPC` client APIs for unary and streaming calls.

## Minimal Unary Flow

```c
SocketGRPC_Client_T client = SocketGRPC_Client_new(NULL);
SocketGRPC_Channel_T channel = SocketGRPC_Channel_new(client, "https://127.0.0.1:50051", NULL);
SocketGRPC_Call_T call = SocketGRPC_Call_new(channel, "/example.Echo/Ping", NULL);

Arena_T arena = Arena_new();
uint8_t *resp = NULL;
size_t resp_len = 0;
int rc = SocketGRPC_Call_unary_h2(call, req, req_len, arena, &resp, &resp_len);
SocketGRPC_Status status = SocketGRPC_Call_status(call);
```

`SocketGRPC_Call_unary_h2()` is the unified unary entrypoint. It routes to
HTTP/2 or HTTP/3 based on `SocketGRPC_ChannelConfig.channel_mode`.

## Channel Configuration

Use `SocketGRPC_ChannelConfig_defaults()` and override only what you need.

Common fields:

- `channel_mode`: `SOCKET_GRPC_CHANNEL_MODE_HTTP2` (default) or HTTP/3
- `verify_peer`: TLS peer verification toggle
- `tls_context`: HTTP/2 TLS context path
- `ca_file`: CA bundle path (used by HTTP/3 client path)
- `enable_request_compression`: gzip request compression (HTTP/2 only)
- `enable_response_decompression`: gzip response decode (HTTP/2 only)
- `max_inbound_message_bytes`, `max_outbound_message_bytes`
- `max_metadata_entries`, `max_cumulative_inflight_bytes`

## Deadlines and Cancellation

Per-call behavior is configured in `SocketGRPC_CallConfig`:

- `deadline_ms`: absolute RPC budget
- `wait_for_ready`: wait behavior for unavailable backends
- `retry_policy`: bounded backoff policy

Cancellation:

- `SocketGRPC_Call_cancel(call)` transitions active calls to `CANCELLED`
- Cancellation is best-effort and transport-aware

## Streaming APIs

Client streaming and bidi-style client behavior use:

- `SocketGRPC_Call_send_message()`
- `SocketGRPC_Call_close_send()`
- `SocketGRPC_Call_recv_message()`

`recv_message()` contract:

- `done = 0`: one message received
- `done = 1`: stream finished; inspect status/trailers on call

## Metadata and Interceptors

Client metadata:

- `SocketGRPC_Call_metadata_add_ascii()`
- `SocketGRPC_Call_metadata_add_binary()`

Interceptors:

- Unary: `SocketGRPC_Call_add_unary_interceptor()`
- Stream: `SocketGRPC_Call_add_stream_interceptor()`

Reference interceptors include metadata injector and structured logging hooks.

## Failure Handling Pattern

Recommended pattern:

1. Check integer return code (`-1` indicates local/transport failure path).
2. Always inspect `SocketGRPC_Call_status()` for final canonical status.
3. Use trailers via `SocketGRPC_Call_trailers()` for error details.

## HTTP/3 Notes

When `channel_mode` is HTTP/3:

- Use HTTPS targets (`https://host:port`).
- Request compression is not currently supported.
- Compressed response decoding is not currently supported.
- `tls_context` is ignored on the current HTTP/3 client path.

See `docs/grpc-http3.md` for details and limitations.
