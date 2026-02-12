# gRPC Interop Matrix

This directory contains the gRPC interoperability/conformance matrix and a
runner that emits machine-readable pass/fail/skip reports.

## Supported Conformance Subset

The core profile validates the following semantics with deterministic local
checks:

| Requirement | Core Case ID | Backing Command |
| --- | --- | --- |
| Unary behavior over HTTP/2 | `unary_h2_core` | `ctest -R test_grpc_unary_h2` |
| Server unary semantics and interceptors | `unary_server_h2_core` | `ctest -R test_grpc_unary_server_h2` |
| Metadata and trailer behavior | `metadata_trailers_core` | `ctest -R test_grpc_metadata` |
| Status code mapping / framing semantics | `status_mapping_core` | `ctest -R test_grpc_wire` |
| HTTP/3 transport path checks | `transport_h3_core` | `ctest -R test_grpc_h3` |

Deadlines, cancellation, and compression negotiation are covered by
`test_grpc_unary_h2` scenarios in the core profile.

## Profiles

- `core`: Blocking profile for CI. Uses internal deterministic tests only.
- `extended`: Optional local profile. Includes `core` plus external-tool smoke
  checks for maintainers.

## Skip Semantics

The runner marks a case as skipped when command output includes one of:

- `[SKIP]`
- `[SKIPPED]`

This is required because test binaries can return success while signaling
runtime capability skips in output.

## Usage

Run via wrapper:

```bash
scripts/grpc-interop/run.sh --profile core --build-dir build
scripts/grpc-interop/run.sh --profile extended --build-dir build
```

Run runner directly:

```bash
python3 tests/grpc/interop/run_matrix.py \
  --matrix tests/grpc/interop/matrix-core.json \
  --build-dir build \
  --output build/grpc-interop-core-report.json
```
