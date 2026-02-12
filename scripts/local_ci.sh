#!/bin/bash
# Local CI - Mirrors GitHub Actions workflow (.github/workflows/ci.yml)
# Usage:
#   ./scripts/local_ci.sh           # Run all jobs
#   ./scripts/local_ci.sh --quick   # Skip slow jobs (valgrind, coverage)
#   ./scripts/local_ci.sh build     # Run specific job(s)
#   ./scripts/local_ci.sh sanitizers valgrind  # Run multiple jobs
#
# Available jobs: build, sanitizers, valgrind, coverage, static-analysis

set -o pipefail

# =============================================================================
# Configuration
# =============================================================================

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NPROC=$(nproc 2>/dev/null || echo 4)

# Environment variables matching CI exactly
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"
# ASan stack-use-after-return detection conflicts with setjmp/longjmp used by the exception system.
# This is a known false positive - the exception frames are properly managed via the RETURN macro.
# All other ASan checks (leaks, overflows, etc.) remain active.
export ASAN_OPTIONS="detect_stack_use_after_return=0:detect_leaks=1:abort_on_error=1:halt_on_error=1"
# TSan uses suppressions file for known library races in async connect
export TSAN_OPTIONS="halt_on_error=1:second_deadlock_stack=1:suppressions=$PROJECT_ROOT/tsan.supp"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Track job results
declare -A JOB_RESULTS
declare -A JOB_TIMES

# =============================================================================
# Utility Functions
# =============================================================================

log_header() {
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC} ${BOLD}$1${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

log_subheader() {
    echo -e "${CYAN}>>> $1${NC}"
}

log_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

log_error() {
    echo -e "${RED}✗ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

log_info() {
    echo -e "${CYAN}ℹ $1${NC}"
}

# Record job result
record_result() {
    local job_name="$1"
    local result="$2"
    local duration="$3"
    JOB_RESULTS["$job_name"]="$result"
    JOB_TIMES["$job_name"]="$duration"
}

# Run a job and track its result
run_job() {
    local job_name="$1"
    local job_func="$2"
    
    local start_time=$(date +%s)
    
    if $job_func; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        record_result "$job_name" "PASS" "${duration}s"
        log_success "$job_name completed in ${duration}s"
        return 0
    else
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        record_result "$job_name" "FAIL" "${duration}s"
        log_error "$job_name failed after ${duration}s"
        return 1
    fi
}

# Check if a command exists
check_command() {
    if ! command -v "$1" &> /dev/null; then
        log_error "Required command not found: $1"
        return 1
    fi
    return 0
}

# =============================================================================
# Build Jobs (matches CI 'build' job)
# =============================================================================

run_build_debug() {
    log_subheader "Build (Debug)"
    
    local build_dir="$PROJECT_ROOT/build-ci-debug"
    rm -rf "$build_dir"
    mkdir -p "$build_dir"
    
    log_info "Configuring CMake (Debug)..."
    cmake -B "$build_dir" -S "$PROJECT_ROOT" \
        -DCMAKE_BUILD_TYPE=Debug \
        -DENABLE_TLS=ON || return 1
    
    log_info "Building..."
    cmake --build "$build_dir" --parallel "$NPROC" || return 1
    
    log_info "Running tests..."
    cd "$build_dir"
    ctest --output-on-failure --parallel "$NPROC" || return 1

    log_info "Running gRPC example smoke tests..."
    ctest --output-on-failure -R "grpc_example_.*_smoke" || return 1

    log_info "Running gRPC core conformance matrix..."
    "$PROJECT_ROOT/scripts/grpc-interop/run.sh" \
        --profile core \
        --build-dir "$build_dir" \
        --report "$build_dir/grpc-interop-core-debug.json" || return 1

    log_info "Running gRPC benchmark smoke report..."
    "$PROJECT_ROOT/scripts/grpc-bench/run.sh" \
        --build-dir "$build_dir" \
        --smoke \
        --report "$build_dir/grpc-bench-debug.json" || return 1
    
    return 0
}

run_build_release() {
    log_subheader "Build (Release)"
    
    local build_dir="$PROJECT_ROOT/build-ci-release"
    rm -rf "$build_dir"
    mkdir -p "$build_dir"
    
    log_info "Configuring CMake (Release)..."
    cmake -B "$build_dir" -S "$PROJECT_ROOT" \
        -DCMAKE_BUILD_TYPE=Release \
        -DENABLE_TLS=ON || return 1
    
    log_info "Building..."
    cmake --build "$build_dir" --parallel "$NPROC" || return 1
    
    log_info "Running tests..."
    cd "$build_dir"
    ctest --output-on-failure --parallel "$NPROC" || return 1

    log_info "Running gRPC example smoke tests..."
    ctest --output-on-failure -R "grpc_example_.*_smoke" || return 1

    log_info "Running gRPC core conformance matrix..."
    "$PROJECT_ROOT/scripts/grpc-interop/run.sh" \
        --profile core \
        --build-dir "$build_dir" \
        --report "$build_dir/grpc-interop-core-release.json" || return 1

    log_info "Running gRPC benchmark smoke report..."
    "$PROJECT_ROOT/scripts/grpc-bench/run.sh" \
        --build-dir "$build_dir" \
        --smoke \
        --report "$build_dir/grpc-bench-release.json" || return 1
    
    return 0
}

job_build() {
    log_header "BUILD JOB"
    
    local failed=0
    
    run_job "build-debug" run_build_debug || failed=1
    run_job "build-release" run_build_release || failed=1
    
    return $failed
}

# =============================================================================
# Sanitizer Jobs (matches CI 'sanitizers' job)
# =============================================================================

run_sanitizer_asan() {
    log_subheader "Sanitizers (AddressSanitizer)"
    
    local build_dir="$PROJECT_ROOT/build-ci-asan"
    rm -rf "$build_dir"
    mkdir -p "$build_dir"
    
    log_info "Configuring CMake with ASan..."
    cmake -B "$build_dir" -S "$PROJECT_ROOT" \
        -DCMAKE_BUILD_TYPE=Debug \
        -DENABLE_TLS=ON \
        -DENABLE_ASAN=ON || return 1
    
    log_info "Building..."
    cmake --build "$build_dir" --parallel "$NPROC" || return 1
    
    log_info "Running tests with ASan..."
    cd "$build_dir"
    ctest --output-on-failure --parallel "$NPROC" || return 1
    
    return 0
}

run_sanitizer_ubsan() {
    log_subheader "Sanitizers (UBSanitizer)"
    
    local build_dir="$PROJECT_ROOT/build-ci-ubsan"
    rm -rf "$build_dir"
    mkdir -p "$build_dir"
    
    log_info "Configuring CMake with UBSan..."
    cmake -B "$build_dir" -S "$PROJECT_ROOT" \
        -DCMAKE_BUILD_TYPE=Debug \
        -DENABLE_TLS=ON \
        -DENABLE_UBSAN=ON || return 1
    
    log_info "Building..."
    cmake --build "$build_dir" --parallel "$NPROC" || return 1
    
    log_info "Running tests with UBSan..."
    cd "$build_dir"
    ctest --output-on-failure --parallel "$NPROC" || return 1
    
    return 0
}

run_sanitizer_combo() {
    log_subheader "Sanitizers (ASan+UBSan)"
    
    local build_dir="$PROJECT_ROOT/build-ci-sanitizers"
    rm -rf "$build_dir"
    mkdir -p "$build_dir"
    
    log_info "Configuring CMake with ASan+UBSan..."
    cmake -B "$build_dir" -S "$PROJECT_ROOT" \
        -DCMAKE_BUILD_TYPE=Debug \
        -DENABLE_TLS=ON \
        -DENABLE_SANITIZERS=ON || return 1
    
    log_info "Building..."
    cmake --build "$build_dir" --parallel "$NPROC" || return 1
    
    log_info "Running tests with ASan+UBSan..."
    cd "$build_dir"
    ctest --output-on-failure --parallel "$NPROC" || return 1
    
    return 0
}

run_sanitizer_tsan() {
    log_subheader "Sanitizers (ThreadSanitizer)"
    
    local build_dir="$PROJECT_ROOT/build-ci-tsan"
    rm -rf "$build_dir"
    mkdir -p "$build_dir"
    
    log_info "Configuring CMake with TSan..."
    cmake -B "$build_dir" -S "$PROJECT_ROOT" \
        -DCMAKE_BUILD_TYPE=Debug \
        -DENABLE_TLS=ON \
        -DENABLE_TSAN=ON || return 1
    
    log_info "Building..."
    cmake --build "$build_dir" --parallel "$NPROC" || return 1
    
    log_info "Running tests with TSan..."
    cd "$build_dir"
    # TSan requires ASLR disabled due to memory mapping issues on modern kernels
    # See: https://github.com/google/sanitizers/issues/1716
    setarch "$(uname -m)" -R ctest --output-on-failure --parallel "$NPROC" || return 1
    
    return 0
}

job_sanitizers() {
    log_header "SANITIZERS JOB"
    
    local failed=0
    
    run_job "asan" run_sanitizer_asan || failed=1
    run_job "ubsan" run_sanitizer_ubsan || failed=1
    run_job "asan+ubsan" run_sanitizer_combo || failed=1
    run_job "tsan" run_sanitizer_tsan || failed=1
    
    return $failed
}

# =============================================================================
# Valgrind Job (matches CI 'valgrind' job)
# =============================================================================

job_valgrind() {
    log_header "VALGRIND JOB"
    
    check_command valgrind || return 1
    
    local build_dir="$PROJECT_ROOT/build-ci-valgrind"
    rm -rf "$build_dir"
    mkdir -p "$build_dir"
    
    log_info "Configuring CMake (Debug, no sanitizers)..."
    cmake -B "$build_dir" -S "$PROJECT_ROOT" \
        -DCMAKE_BUILD_TYPE=Debug \
        -DENABLE_TLS=ON || return 1
    
    log_info "Building..."
    cmake --build "$build_dir" --parallel "$NPROC" || return 1
    
    log_info "Running tests under Valgrind..."
    cd "$build_dir"
    
    local failed=0
    local valgrind_output="valgrind_output.txt"
    
    for test in test_*; do
        if [ -x "$test" ] && [ -f "$test" ]; then
            log_subheader "Running $test under Valgrind"
            
            # Run Valgrind and capture output (matches CI exactly)
            valgrind --leak-check=full --track-fds=yes \
                --suppressions="$PROJECT_ROOT/valgrind.supp" ./"$test" 2>&1 | tee "$valgrind_output"
            
            # Parse ERROR SUMMARY to check for actual memory errors
            # Format: "ERROR SUMMARY: X errors from Y contexts"
            local error_count
            error_count=$(grep -oP "ERROR SUMMARY: \K[0-9]+" "$valgrind_output" | tail -1)
            if [ -n "$error_count" ] && [ "$error_count" -gt 0 ]; then
                log_error "Valgrind detected $error_count memory error(s) in $test"
                failed=1
            fi
            
            # Check for definitely lost memory (real leaks, not "still reachable")
            local definitely_lost
            definitely_lost=$(grep -oP "definitely lost: \K[0-9,]+" "$valgrind_output" | tr -d ',' | tail -1)
            if [ -n "$definitely_lost" ] && [ "$definitely_lost" -gt 0 ]; then
                log_error "Memory leak in $test ($definitely_lost bytes definitely lost)"
                failed=1
            fi
            
            # Check for indirectly lost memory (also real leaks)
            local indirectly_lost
            indirectly_lost=$(grep -oP "indirectly lost: \K[0-9,]+" "$valgrind_output" | tr -d ',' | tail -1)
            if [ -n "$indirectly_lost" ] && [ "$indirectly_lost" -gt 0 ]; then
                log_error "Memory leak in $test ($indirectly_lost bytes indirectly lost)"
                failed=1
            fi
            
            if [ "$failed" -eq 0 ]; then
                log_success "$test: OK (errors=${error_count:-0}, definitely_lost=${definitely_lost:-0}, indirectly_lost=${indirectly_lost:-0})"
            fi
        fi
    done
    
    rm -f "$valgrind_output"
    
    if [ $failed -eq 0 ]; then
        log_success "All Valgrind memory checks passed"
    else
        log_error "One or more tests failed Valgrind memory checks"
    fi
    
    return $failed
}

# =============================================================================
# Coverage Job (matches CI 'coverage' job)
# =============================================================================

job_coverage() {
    log_header "COVERAGE JOB"
    
    check_command lcov || return 1
    
    local build_dir="$PROJECT_ROOT/build-ci-coverage"
    rm -rf "$build_dir"
    mkdir -p "$build_dir"
    
    log_info "Configuring CMake with coverage..."
    cmake -B "$build_dir" -S "$PROJECT_ROOT" \
        -DCMAKE_BUILD_TYPE=Debug \
        -DENABLE_TLS=ON \
        -DENABLE_COVERAGE=ON || return 1
    
    log_info "Building..."
    cmake --build "$build_dir" --parallel "$NPROC" || return 1
    
    log_info "Running tests..."
    cd "$build_dir"
    ctest --output-on-failure --parallel "$NPROC" || return 1
    
    log_info "Generating coverage report..."
    lcov --capture --directory "$build_dir" --output-file coverage.info --ignore-errors mismatch || return 1
    lcov --remove coverage.info '/usr/*' '*/test/*' '*/benchmark*' --output-file coverage.info --ignore-errors mismatch,unused || return 1
    
    log_info "Coverage summary:"
    lcov --list coverage.info --ignore-errors mismatch || return 1
    
    log_success "Coverage report generated: $build_dir/coverage.info"
    
    return 0
}

# =============================================================================
# Static Analysis Job (matches CI 'static-analysis' job)
# =============================================================================

job_static_analysis() {
    log_header "STATIC ANALYSIS JOB"
    
    check_command cppcheck || return 1
    check_command clang-tidy || return 1
    
    local build_dir="$PROJECT_ROOT/build-ci-analysis"
    rm -rf "$build_dir"
    mkdir -p "$build_dir"
    
    log_info "Configuring CMake..."
    cmake -B "$build_dir" -S "$PROJECT_ROOT" \
        -DCMAKE_BUILD_TYPE=Debug \
        -DENABLE_TLS=ON \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON || return 1
    
    local failed=0
    
    # Run cppcheck (matches CI exactly)
    log_subheader "Running cppcheck"
    local cppcheck_output="$build_dir/cppcheck-output.txt"
    
    # Only fail on errors/warnings, not style issues (which are pre-existing)
    # Suppress nullPointerRedundantCheck in test files - these are intentional
    # patterns where we use a value then assert it's not NULL.
    if cppcheck -j "$NPROC" --enable=warning,performance,portability \
        --error-exitcode=1 \
        --suppress=missingIncludeSystem \
        --suppress=unmatchedSuppression \
        --suppress=toomanyconfigs \
        '--suppress=nullPointerRedundantCheck:*test*.c' \
        --std=c11 \
        -I "$PROJECT_ROOT/include" \
        --inline-suppr \
        "$PROJECT_ROOT/src/" "$PROJECT_ROOT/include/" 2>&1 | tee "$cppcheck_output"; then
        log_success "cppcheck passed"
    else
        log_error "cppcheck found issues"
        failed=1
    fi
    
    # Run clang-tidy (matches CI exactly)
    log_subheader "Running clang-tidy"
    local clang_tidy_output="$build_dir/clang-tidy-output.txt"
    
    # Find all source files and run clang-tidy
    # Exclude platform-specific and benchmark files not analyzable on Linux:
    # - SocketPoll_kqueue.c: BSD/macOS only (uses sys/event.h)
    # - benchmark_*.c: Benchmarks are not core library code
    find "$PROJECT_ROOT/src" -name '*.c' \
        ! -name 'SocketPoll_kqueue.c' \
        ! -name 'benchmark_*.c' \
        -print0 | xargs -0 -P "$NPROC" -I {} \
        clang-tidy {} -p "$build_dir" --warnings-as-errors='*' 2>&1 | tee "$clang_tidy_output"
    
    # Check if any errors were found
    if grep -q "error:" "$clang_tidy_output"; then
        log_error "clang-tidy found errors"
        failed=1
    else
        log_success "clang-tidy passed"
    fi
    
    return $failed
}

# =============================================================================
# Summary Report
# =============================================================================

print_summary() {
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC} ${BOLD}CI SUMMARY${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    printf "%-20s %-10s %-10s\n" "JOB" "STATUS" "TIME"
    printf "%-20s %-10s %-10s\n" "---" "------" "----"
    
    local all_passed=true
    
    for job in "${!JOB_RESULTS[@]}"; do
        local result="${JOB_RESULTS[$job]}"
        local time="${JOB_TIMES[$job]}"
        
        if [ "$result" = "PASS" ]; then
            printf "%-20s ${GREEN}%-10s${NC} %-10s\n" "$job" "$result" "$time"
        else
            printf "%-20s ${RED}%-10s${NC} %-10s\n" "$job" "$result" "$time"
            all_passed=false
        fi
    done
    
    echo ""
    
    if [ "$all_passed" = true ]; then
        echo -e "${GREEN}${BOLD}All CI checks passed!${NC}"
        return 0
    else
        echo -e "${RED}${BOLD}Some CI checks failed!${NC}"
        return 1
    fi
}

# =============================================================================
# Dependency Check
# =============================================================================

check_dependencies() {
    log_header "CHECKING DEPENDENCIES"
    
    local missing=0
    
    for cmd in cmake gcc make; do
        if check_command "$cmd"; then
            log_success "$cmd found"
        else
            missing=1
        fi
    done
    
    # Optional but recommended
    for cmd in valgrind lcov cppcheck clang-tidy; do
        if command -v "$cmd" &> /dev/null; then
            log_success "$cmd found"
        else
            log_warning "$cmd not found (some jobs may be skipped)"
        fi
    done
    
    return $missing
}

# =============================================================================
# Main
# =============================================================================

print_usage() {
    echo "Usage: $0 [OPTIONS] [JOBS...]"
    echo ""
    echo "Options:"
    echo "  -j N          Use N parallel jobs (default: $(nproc))"
    echo "  --quick       Skip slow jobs (valgrind, coverage)"
    echo "  --help        Show this help"
    echo ""
    echo "Jobs:"
    echo "  build         Run Debug and Release builds with tests"
    echo "  sanitizers    Run all sanitizer builds (ASan, UBSan, TSan)"
    echo "  valgrind      Run Valgrind memory checks"
    echo "  coverage      Generate code coverage report"
    echo "  static-analysis  Run cppcheck and clang-tidy"
    echo ""
    echo "Examples:"
    echo "  $0                    # Run all jobs"
    echo "  $0 --quick            # Run fast jobs only"
    echo "  $0 build sanitizers   # Run specific jobs"
}

main() {
    local quick_mode=false
    local jobs=()
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -j)
                if [[ -n "$2" ]] && [[ "$2" =~ ^[0-9]+$ ]]; then
                    NPROC="$2"
                    shift 2
                else
                    log_error "-j requires a numeric argument"
                    exit 1
                fi
                ;;
            -j*)
                # Handle -jN format (no space)
                NPROC="${1#-j}"
                if [[ ! "$NPROC" =~ ^[0-9]+$ ]]; then
                    log_error "-j requires a numeric argument"
                    exit 1
                fi
                shift
                ;;
            --quick)
                quick_mode=true
                shift
                ;;
            --help|-h)
                print_usage
                exit 0
                ;;
            build|sanitizers|valgrind|coverage|static-analysis)
                jobs+=("$1")
                shift
                ;;
            *)
                log_error "Unknown argument: $1"
                print_usage
                exit 1
                ;;
        esac
    done
    
    # If no jobs specified, run all
    if [ ${#jobs[@]} -eq 0 ]; then
        if [ "$quick_mode" = true ]; then
            jobs=("build" "sanitizers" "static-analysis")
        else
            jobs=("build" "sanitizers" "valgrind" "coverage" "static-analysis")
        fi
    fi
    
    echo -e "${BOLD}"
    echo "╔═══════════════════════════════════════════════════════════════════╗"
    echo "║           LOCAL CI - Socket Library                               ║"
    echo "║           Mirrors GitHub Actions workflow                         ║"
    echo "╚═══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    log_info "Project root: $PROJECT_ROOT"
    log_info "Parallel jobs: $NPROC"
    log_info "Jobs to run: ${jobs[*]}"
    
    # Check dependencies
    check_dependencies || exit 1
    
    local overall_failed=0
    local start_time=$(date +%s)
    
    # Run requested jobs
    for job in "${jobs[@]}"; do
        case $job in
            build)
                run_job "build" job_build || overall_failed=1
                ;;
            sanitizers)
                run_job "sanitizers" job_sanitizers || overall_failed=1
                ;;
            valgrind)
                run_job "valgrind" job_valgrind || overall_failed=1
                ;;
            coverage)
                run_job "coverage" job_coverage || overall_failed=1
                ;;
            static-analysis)
                run_job "static-analysis" job_static_analysis || overall_failed=1
                ;;
        esac
    done
    
    local end_time=$(date +%s)
    local total_duration=$((end_time - start_time))
    
    # Print summary
    print_summary
    
    echo ""
    log_info "Total time: ${total_duration}s"
    
    exit $overall_failed
}

main "$@"
