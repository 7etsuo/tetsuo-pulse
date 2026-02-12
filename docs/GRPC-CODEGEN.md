# gRPC C Stub Code Generation

This repository ships a first-party generator for protobuf messages and gRPC
service stubs:

- `tools/protoc-gen-socketgrpc`

It produces deterministic C outputs that link against `SocketGRPC` and
`SocketProto`.

## One-Command Generation

```bash
tools/protoc-gen-socketgrpc --proto path/to/service.proto --out-dir generated
```

For `service.proto`, this writes:

- `generated/service.socketgrpc.h`
- `generated/service.socketgrpc.c`

## CMake Helper

The top-level CMake integrates a helper module:

- `cmake/SocketGRPCCodegen.cmake`

Use `socketgrpc_generate(...)` in CMake to wire generated files directly into
targets.

Minimal usage:

```cmake
include(${CMAKE_SOURCE_DIR}/cmake/SocketGRPCCodegen.cmake)
find_package(Python3 COMPONENTS Interpreter REQUIRED)

socketgrpc_generate(
  PROTO ${CMAKE_SOURCE_DIR}/src/test/proto/unary.proto
  OUTPUT_DIR ${CMAKE_BINARY_DIR}/generated/socketgrpc
  OUT_SRC GENERATED_SRC
  OUT_HDR GENERATED_HDR
)

add_executable(my_grpc_test my_test.c ${GENERATED_SRC})
target_include_directories(my_grpc_test PRIVATE ${CMAKE_BINARY_DIR}/generated/socketgrpc)
```

## Test Coverage

Codegen coverage in this repo includes:

- Golden output checks for unary/streaming/complex schemas
- Determinism checks (same proto generated twice must match byte-for-byte)
- Compile and runtime tests for:
  - unary client/server local handler invocation
  - streaming method stubs
  - nested/oneof/repeated field message encode/decode
