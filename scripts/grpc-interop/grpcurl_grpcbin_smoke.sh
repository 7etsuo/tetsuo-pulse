#!/usr/bin/env bash
set -euo pipefail

PORT="${GRPC_INTEROP_GRPCBIN_PORT:-59090}"
IMAGE="${GRPC_INTEROP_GRPCBIN_IMAGE:-moul/grpcbin}"
CID=""
LIST_OUT="$(mktemp)"
LIST_ERR="$(mktemp)"

cleanup() {
  rm -f "$LIST_OUT" "$LIST_ERR"
  if [ -n "$CID" ]; then
    docker rm -f "$CID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

CID="$(docker run -d --rm -p "${PORT}:9000" "$IMAGE")"

for _ in $(seq 1 30); do
  if grpcurl -plaintext "localhost:${PORT}" list >"$LIST_OUT" 2>"$LIST_ERR"; then
    break
  fi
  sleep 1
done

if ! grpcurl -plaintext "localhost:${PORT}" list >"$LIST_OUT" 2>"$LIST_ERR"; then
  echo "grpcurl reflection check failed" >&2
  cat "$LIST_ERR" >&2
  exit 1
fi

if ! grep -q "grpcbin.GRPCBin" "$LIST_OUT"; then
  echo "expected grpcbin.GRPCBin service not found" >&2
  cat "$LIST_OUT" >&2
  exit 1
fi

# Metadata path smoke: ensure grpcurl can send custom metadata in a request path.
if ! grpcurl -plaintext -H "x-interop-smoke: 1" "localhost:${PORT}" list >/dev/null 2>&1; then
  echo "grpcurl metadata smoke check failed" >&2
  exit 1
fi

echo "grpcurl grpcbin smoke passed"
