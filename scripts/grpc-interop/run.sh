#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PROFILE="core"
BUILD_DIR="${REPO_ROOT}/build"
REPORT=""
STRICT_OPTIONAL=0

usage() {
  cat <<USAGE
Usage: scripts/grpc-interop/run.sh [options]

Options:
  --profile <core|extended>   Matrix profile to run (default: core)
  --build-dir <path>          CMake build directory (default: ./build)
  --report <path>             Output report path
  --strict-optional           Fail if optional cases fail
  -h, --help                  Show this help
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --profile)
      PROFILE="$2"
      shift 2
      ;;
    --build-dir)
      BUILD_DIR="$2"
      shift 2
      ;;
    --report)
      REPORT="$2"
      shift 2
      ;;
    --strict-optional)
      STRICT_OPTIONAL=1
      shift
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

if [ "${PROFILE}" != "core" ] && [ "${PROFILE}" != "extended" ]; then
  echo "Invalid profile: ${PROFILE}" >&2
  exit 2
fi

if [ -d "${BUILD_DIR}" ]; then
  BUILD_DIR="$(cd "${BUILD_DIR}" && pwd)"
else
  BUILD_DIR="$(cd "$(dirname "${BUILD_DIR}")" && pwd)/$(basename "${BUILD_DIR}")"
fi

MATRIX_PATH="${REPO_ROOT}/tests/grpc/interop/matrix-${PROFILE}.json"
if [ ! -f "${MATRIX_PATH}" ]; then
  echo "Matrix not found: ${MATRIX_PATH}" >&2
  exit 2
fi

if [ -z "${REPORT}" ]; then
  REPORT="${BUILD_DIR}/grpc-interop-${PROFILE}-report.json"
fi

CMD=(
  python3
  "${REPO_ROOT}/tests/grpc/interop/run_matrix.py"
  --matrix "${MATRIX_PATH}"
  --build-dir "${BUILD_DIR}"
  --repo-root "${REPO_ROOT}"
  --output "${REPORT}"
)

if [ "${STRICT_OPTIONAL}" -eq 1 ]; then
  CMD+=(--strict-optional)
fi

echo "Running gRPC interop profile '${PROFILE}'"
printf 'Command:'
printf ' %q' "${CMD[@]}"
echo

"${CMD[@]}"
