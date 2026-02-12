#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

BUILD_DIR="${REPO_ROOT}/build"
REPORT=""
SMOKE=0
ITERATIONS=""
WARMUP=""

usage() {
  cat <<USAGE
Usage: scripts/grpc-bench/run.sh [options]

Options:
  --build-dir <path>    CMake build directory (default: ./build)
  --report <path>       Output JSON report path (default: <build-dir>/grpc-bench-report.json)
  --smoke               Run quick smoke profile
  --iterations <n>      Override measured calls per scenario
  --warmup <n>          Override warmup calls per scenario
  -h, --help            Show this help
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --build-dir)
      BUILD_DIR="$2"
      shift 2
      ;;
    --report)
      REPORT="$2"
      shift 2
      ;;
    --smoke)
      SMOKE=1
      shift
      ;;
    --iterations)
      ITERATIONS="$2"
      shift 2
      ;;
    --warmup)
      WARMUP="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [ -d "${BUILD_DIR}" ]; then
  BUILD_DIR="$(cd "${BUILD_DIR}" && pwd)"
else
  BUILD_DIR="$(cd "$(dirname "${BUILD_DIR}")" && pwd)/$(basename "${BUILD_DIR}")"
fi

BENCH_BIN="${BUILD_DIR}/benchmark_grpc_transport"
if [ ! -x "${BENCH_BIN}" ]; then
  echo "Benchmark binary not found/executable: ${BENCH_BIN}" >&2
  echo "Build first: cmake --build ${BUILD_DIR} --parallel \$(nproc)" >&2
  exit 2
fi

if [ -z "${REPORT}" ]; then
  REPORT="${BUILD_DIR}/grpc-bench-report.json"
fi

CMD=("${BENCH_BIN}" "--report" "${REPORT}")

if [ "${SMOKE}" -eq 1 ]; then
  CMD+=("--smoke")
fi
if [ -n "${ITERATIONS}" ]; then
  CMD+=("--iterations" "${ITERATIONS}")
fi
if [ -n "${WARMUP}" ]; then
  CMD+=("--warmup" "${WARMUP}")
fi

echo "Running gRPC transport benchmark"
printf 'Command:'
printf ' %q' "${CMD[@]}"
echo

BENCH_ASAN_OPTIONS="${ASAN_OPTIONS:-}"
if [ -n "${BENCH_ASAN_OPTIONS}" ]; then
  BENCH_ASAN_OPTIONS="detect_leaks=0:${BENCH_ASAN_OPTIONS}"
else
  BENCH_ASAN_OPTIONS="detect_leaks=0"
fi

ASAN_OPTIONS="${BENCH_ASAN_OPTIONS}" "${CMD[@]}"

echo "Benchmark report: ${REPORT}"
