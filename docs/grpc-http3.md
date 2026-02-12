# gRPC over HTTP/3

This document captures current HTTP/3 behavior for `SocketGRPC`.

## Enabling HTTP/3 Mode

Set channel mode:

```c
SocketGRPC_ChannelConfig cfg;
SocketGRPC_ChannelConfig_defaults(&cfg);
cfg.channel_mode = SOCKET_GRPC_CHANNEL_MODE_HTTP3;
cfg.verify_peer = 1;
cfg.ca_file = "/path/to/ca.pem";
```

Target should be HTTPS form:

- `https://host:port`

## Supported Today

- Unary gRPC client calls over HTTP/3
- Unary gRPC server dispatch via `SocketGRPC_Server_bind_http3`
- Client streaming APIs over HTTP/3 transport
- Metadata/trailer handling and status propagation

## Current HTTP/3 Limits

The following are intentionally not supported yet:

- Request compression over HTTP/3
- Compressed response decoding over HTTP/3
- Client-side `tls_context` parity with HTTP/2 channel path

Current client TLS knobs for HTTP/3 are:

- `ca_file`
- `verify_peer`

## Error/Skip Expectations

In environments where QUIC/TLS runtime support is not available, HTTP/3 call
paths may return `UNAVAILABLE`. CI and local smoke checks should treat this as
runtime capability-aware skip, not as a protocol correctness regression.

## mTLS Note

mTLS parity differs by transport today:

- HTTP/2 client paths can use `SocketTLSContext_T` via `tls_context`
- HTTP/3 client paths currently do not accept `tls_context`

If mTLS is required today, prefer HTTP/2 transport mode.

## Recommended Rollout Pattern

1. Keep HTTP/2 as default transport.
2. Enable HTTP/3 per-channel for known-compatible environments.
3. Keep compression disabled for HTTP/3 channels.
4. Monitor status code distribution and retry behavior before broad rollout.
