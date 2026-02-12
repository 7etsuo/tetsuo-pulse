# gRPC Server Guide

This guide describes server-side gRPC setup for HTTP/2 and HTTP/3 dispatchers.

## Server Setup

```c
SocketGRPC_Server_T grpc_server = SocketGRPC_Server_new(NULL);
SocketGRPC_Server_register_unary(grpc_server,
                                 "/example.Echo/Ping",
                                 ping_handler,
                                 NULL);
```

Unary handler signature:

```c
int handler(SocketGRPC_ServerContext_T ctx,
            const uint8_t *request_payload,
            size_t request_payload_len,
            Arena_T arena,
            uint8_t **response_payload,
            size_t *response_payload_len,
            void *userdata)
```

Return a canonical gRPC code (`0-16`).

## Binding to HTTP/2

1. Configure and start `SocketHTTPServer_T` with HTTP/2 enabled.
2. Bind gRPC dispatcher:

```c
SocketGRPC_Server_bind_http2(grpc_server, http_server);
```

## Binding to HTTP/3

1. Configure/start `SocketHTTP3_Server_T`.
2. Bind gRPC dispatcher:

```c
SocketGRPC_Server_bind_http3(grpc_server, http3_server);
```

## Context and Trailers

Within handlers, `SocketGRPC_ServerContext_T` exposes:

- Request metadata (`SocketGRPC_ServerContext_metadata`)
- Peer and method fields
- Cancellation state (`SocketGRPC_ServerContext_is_cancelled`)
- Status/trailer setters:
  - `SocketGRPC_ServerContext_set_status`
  - `SocketGRPC_ServerContext_set_status_details_bin`
  - `SocketGRPC_ServerContext_add_trailing_metadata_*`

## Interceptors and Observability

Server extensions:

- Unary interceptor chain:
  `SocketGRPC_Server_add_unary_interceptor()`
- Structured lifecycle hook:
  `SocketGRPC_Server_set_observability_hook()`

Use interceptors for auth, metadata policy, and structured logging.

## Shutdown

Graceful shutdown sequence:

1. `SocketGRPC_Server_begin_shutdown(grpc_server)`
2. Stop/drain transport server
3. `SocketGRPC_Server_free(&grpc_server)`

`SocketGRPC_Server_inflight_calls()` exposes active unary call count.

## Current Limits

The public server registration API currently supports unary method handlers.
Streaming server registration APIs are not yet exposed in `SocketGRPC.h`.

For client-streaming/bidi endpoint interop today, use explicit HTTP/2 or HTTP/3
transport handlers where needed.
