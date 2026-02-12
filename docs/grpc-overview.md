# gRPC Overview

This guide describes the public gRPC surface in `SocketGRPC` and how it maps to
HTTP/2 and HTTP/3 transports in this repository.

## Scope

`SocketGRPC` currently provides:

- Unary client and server calls over HTTP/2
- Unary client and server calls over HTTP/3
- Client streaming and bidi-style client APIs (`send_message`, `recv_message`)
- Metadata/trailers helpers
- Deadline, cancellation, retry policy, and interceptor hooks

## Lifecycle

Core object lifecycle is explicit and handle-based:

1. `SocketGRPC_Client_new()`
2. `SocketGRPC_Channel_new()`
3. `SocketGRPC_Call_new()`
4. Execute unary or streaming API
5. `SocketGRPC_Call_free()`
6. `SocketGRPC_Channel_free()`
7. `SocketGRPC_Client_free()`

Server lifecycle:

1. `SocketGRPC_Server_new()`
2. `SocketGRPC_Server_register_unary()` (or `_except`)
3. Bind dispatcher with `SocketGRPC_Server_bind_http2()` or
   `SocketGRPC_Server_bind_http3()`
4. Run transport server loop
5. `SocketGRPC_Server_begin_shutdown()`
6. `SocketGRPC_Server_free()`

## Error Model

`SocketGRPC` returns canonical gRPC status codes (`0-16`) for protocol
completion and uses `-1` for local argument/setup failures.

- Per-call final status: `SocketGRPC_Call_status()`
- Status message fallback: `SocketGRPC_Status_message()`
- Symbolic status name: `SocketGRPC_Status_code_name()`

Common terminal semantics:

- `OK`: RPC completed successfully
- `DEADLINE_EXCEEDED`: call deadline elapsed
- `CANCELLED`: call cancelled locally or remotely
- `UNAVAILABLE`: transport/connectivity issue
- `RESOURCE_EXHAUSTED`: configured payload/metadata limits exceeded

## Thread Safety

- `SocketGRPC_*_new()` and config default helpers are thread-safe.
- Individual call/server handles are not intended for unsynchronized concurrent
  mutation by multiple threads.
- Treat each active call and server instance as thread-confined unless you
  provide external synchronization.

## Limits and Defaults

Channel and runtime limits are configured via `SocketGRPC_ChannelConfig` and
`SocketGRPC_CallConfig`.

Important defaults (see `include/grpc/SocketGRPCConfig.h`):

- `max_inbound_message_bytes`: 4 MiB
- `max_outbound_message_bytes`: 4 MiB
- `max_metadata_entries`: 64
- `max_cumulative_inflight_bytes`: 8 MiB
- `deadline_ms`: 30000
- `verify_peer`: enabled

## Transport Matrix

| Capability | HTTP/2 | HTTP/3 |
| --- | --- | --- |
| Unary client | Yes | Yes |
| Unary server | Yes | Yes |
| Client stream APIs | Yes | Yes |
| Request compression | Yes | No |
| Compressed response decode | Yes | No |
| Channel `tls_context` | Yes | No (use `ca_file` + `verify_peer`) |

See also:

- `docs/grpc-client.md`
- `docs/grpc-server.md`
- `docs/grpc-http3.md`
- `docs/GRPC-CODEGEN.md`
