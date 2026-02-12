# gRPC Examples

This directory contains small gRPC examples that align with the current
`SocketGRPC` public API surface.

## Programs

- `grpc_example_unary_hello_world`
  - Unary hello-world client flow.
- `grpc_example_bidi_stream_chat`
  - Client-side bidi/streaming call pattern.
- `grpc_example_deadline_cancellation`
  - Deadline and explicit cancellation usage.
- `grpc_example_tls_mtls_h2`
  - HTTP/2 TLS and mTLS channel configuration pattern.

## CI Smoke Mode

Each program supports `--smoke` for deterministic no-network validation. CI runs
these smoke paths to ensure examples compile and execute.

## Manual Usage

```bash
# unary over HTTP/2
./grpc_example_unary_hello_world \
  --target https://127.0.0.1:50051 \
  --method /example.Echo/Ping \
  --message "hello"

# bidi client pattern over HTTP/3
./grpc_example_bidi_stream_chat \
  --h3 \
  --target https://127.0.0.1:50053 \
  --method /example.Chat/Chat

# deadline + cancellation
./grpc_example_deadline_cancellation \
  --target https://127.0.0.1:50051 \
  --deadline-ms 50 \
  --cancel-before-send

# TLS + mTLS (HTTP/2)
./grpc_example_tls_mtls_h2 \
  --target https://127.0.0.1:50051 \
  --ca ./ca.pem \
  --client-cert ./client.pem \
  --client-key ./client.key
```
