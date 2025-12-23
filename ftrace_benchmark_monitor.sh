#!/bin/bash
#
# ftrace_benchmark_monitor.sh - Monitor syscalls during HTTP benchmarks
#
# This script uses ftrace to prove that benchmarks are making real network
# calls (connect, read, write, etc.) and not just faking results.
#
# Usage:
#   sudo ./ftrace_benchmark_monitor.sh                    # Monitor all benchmark processes
#   sudo ./ftrace_benchmark_monitor.sh -p <pid>          # Monitor specific PID
#   sudo ./ftrace_benchmark_monitor.sh -n tetsuo         # Monitor by name pattern
#   sudo ./ftrace_benchmark_monitor.sh --summary         # Show syscall summary only
#
# Run in one terminal while benchmark runs in another:
#   Terminal 1: sudo ./ftrace_benchmark_monitor.sh -n benchmark_http
#   Terminal 2: ./run_http_benchmarks.sh --reqs=100
#
# Requires: root/sudo, CONFIG_FTRACE enabled kernel

# Note: Do NOT use 'set -e' here - we need explicit error handling for ftrace ops

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Ftrace paths
TRACEFS="/sys/kernel/tracing"
if [ ! -d "$TRACEFS" ]; then
    TRACEFS="/sys/kernel/debug/tracing"
fi

# Default values
MONITOR_PID=""
MONITOR_NAME=""
SUMMARY_MODE=0
VERBOSE=0

# Syscalls to monitor (network I/O related)
# Note: recv/send don't exist as separate syscalls on Linux - they use recvfrom/sendto
SYSCALLS=(
    "sys_enter_connect"
    "sys_enter_accept"
    "sys_enter_accept4"
    "sys_enter_read"
    "sys_enter_write"
    "sys_enter_recvfrom"
    "sys_enter_sendto"
    "sys_enter_recvmsg"
    "sys_enter_sendmsg"
    "sys_enter_socket"
    "sys_enter_close"
    "sys_enter_epoll_wait"
    "sys_enter_poll"
)

usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Monitor syscalls to verify benchmark is doing real network I/O."
    echo ""
    echo "Options:"
    echo "  -p, --pid <pid>      Monitor specific PID"
    echo "  -n, --name <pattern> Monitor processes matching name pattern"
    echo "  -s, --summary        Show syscall count summary only (less verbose)"
    echo "  -v, --verbose        Show all syscall arguments"
    echo "  -h, --help           Show this help"
    echo ""
    echo "Examples:"
    echo "  sudo $0 -n benchmark_http   # Monitor benchmark processes"
    echo "  sudo $0 -p 12345            # Monitor specific PID"
    echo "  sudo $0 --summary           # Summary mode for cleaner output"
    echo ""
    echo "Run in one terminal while benchmark runs in another terminal."
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--pid)
            MONITOR_PID="$2"
            shift 2
            ;;
        -n|--name)
            MONITOR_NAME="$2"
            shift 2
            ;;
        -s|--summary)
            SUMMARY_MODE=1
            shift
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script requires root privileges${NC}"
    echo "Run with: sudo $0 $*"
    exit 1
fi

# Check ftrace availability
if [ ! -d "$TRACEFS" ]; then
    echo -e "${RED}Error: ftrace not available${NC}"
    echo "Tracefs not found at /sys/kernel/tracing or /sys/kernel/debug/tracing"
    echo "Ensure CONFIG_FTRACE is enabled in kernel config"
    exit 1
fi

# Check we can write to ftrace (pre-flight check)
if [ ! -w "$TRACEFS/tracing_on" ]; then
    echo -e "${RED}Error: Cannot write to ftrace${NC}"
    echo "File $TRACEFS/tracing_on is not writable"
    echo "Make sure you're running with sudo"
    exit 1
fi

# Cleanup function
cleanup() {
    echo ""
    echo -e "${YELLOW}Cleaning up ftrace...${NC}"

    # Disable tracing
    echo 0 > "$TRACEFS/tracing_on" 2>/dev/null || true

    # Clear filters
    echo > "$TRACEFS/set_ftrace_filter" 2>/dev/null || true
    echo > "$TRACEFS/set_event_pid" 2>/dev/null || true

    # Disable syscall events (silently ignore missing ones)
    for syscall in "${SYSCALLS[@]}"; do
        if [ -f "$TRACEFS/events/syscalls/$syscall/enable" ]; then
            echo 0 > "$TRACEFS/events/syscalls/$syscall/enable"
        fi
    done

    # Clear buffer
    echo > "$TRACEFS/trace" 2>/dev/null || true

    echo -e "${GREEN}Cleanup complete${NC}"
}

trap cleanup EXIT INT TERM

# Setup ftrace
setup_ftrace() {
    echo -e "${CYAN}Setting up ftrace monitoring...${NC}"

    # Stop tracing and clear buffer
    if ! echo 0 > "$TRACEFS/tracing_on" 2>/dev/null; then
        echo -e "${RED}Error: Failed to disable tracing${NC}"
        exit 1
    fi

    if ! echo > "$TRACEFS/trace" 2>/dev/null; then
        echo -e "${RED}Error: Failed to clear trace buffer${NC}"
        exit 1
    fi

    # Set tracer to nop (we'll use events)
    if ! echo nop > "$TRACEFS/current_tracer" 2>/dev/null; then
        echo -e "${RED}Error: Failed to set tracer to nop${NC}"
        exit 1
    fi

    # Enable syscall events
    local enabled=0
    for syscall in "${SYSCALLS[@]}"; do
        if [ -f "$TRACEFS/events/syscalls/$syscall/enable" ]; then
            if echo 1 > "$TRACEFS/events/syscalls/$syscall/enable" 2>/dev/null; then
                ((enabled++))
            fi
        fi
    done

    if [ $enabled -eq 0 ]; then
        echo -e "${RED}Error: No syscall events could be enabled${NC}"
        echo "Check that /sys/kernel/tracing/events/syscalls/ contains event directories"
        exit 1
    fi

    echo -e "  Enabled $enabled syscall events"

    # Set PID filter if specified
    if [ -n "$MONITOR_PID" ]; then
        if echo "$MONITOR_PID" > "$TRACEFS/set_event_pid" 2>/dev/null; then
            echo -e "  Filtering to PID: $MONITOR_PID"
        else
            echo -e "${YELLOW}Warning: Could not set PID filter${NC}"
        fi
    fi

    # Increase buffer size for high-throughput monitoring
    echo 32768 > "$TRACEFS/buffer_size_kb" 2>/dev/null || true

    # Enable tracing
    if ! echo 1 > "$TRACEFS/tracing_on" 2>/dev/null; then
        echo -e "${RED}Error: Failed to enable tracing${NC}"
        exit 1
    fi

    echo -e "${GREEN}Ftrace monitoring active${NC}"
    echo ""
}

# Summary mode: count syscalls
run_summary_mode() {
    echo -e "${CYAN}Running in summary mode - press Ctrl+C to stop${NC}"
    if [ -n "$MONITOR_NAME" ]; then
        echo -e "Filtering for processes matching: ${GREEN}$MONITOR_NAME${NC}"
    fi
    echo ""
    echo -e "${YELLOW}Waiting for syscalls... (start benchmark in another terminal)${NC}"
    echo ""

    declare -A syscall_counts
    local total_count=0
    local start_time=$(date +%s)

    # Monitor trace_pipe and count syscalls
    # Read directly from trace_pipe (blocking) and filter in the loop
    while IFS= read -r line; do
        # Filter by name if specified
        if [ -n "$MONITOR_NAME" ]; then
            if [[ ! "$line" =~ $MONITOR_NAME ]]; then
                continue
            fi
        fi

        # Extract syscall name
        if [[ "$line" =~ sys_([a-z_]+) ]]; then
            syscall="${BASH_REMATCH[1]}"
            ((syscall_counts[$syscall]++))
            ((total_count++))

            # Print summary every 100 syscalls (more responsive)
            if ((total_count % 100 == 0)); then
                local elapsed=$(($(date +%s) - start_time))
                elapsed=$((elapsed > 0 ? elapsed : 1))
                local rate=$((total_count / elapsed))

                echo -ne "\r${GREEN}Total: $total_count syscalls (${rate}/sec) "
                echo -ne "| connect:${syscall_counts[connect]:-0} "
                echo -ne "read:${syscall_counts[read]:-0} "
                echo -ne "write:${syscall_counts[write]:-0} "
                echo -ne "sendto:${syscall_counts[sendto]:-0} "
                echo -ne "recvfrom:${syscall_counts[recvfrom]:-0}${NC}"
            fi
        fi
    done < "$TRACEFS/trace_pipe"
}

# Verbose mode: show syscall details
run_verbose_mode() {
    echo -e "${CYAN}Running in verbose mode - press Ctrl+C to stop${NC}"
    if [ -n "$MONITOR_NAME" ]; then
        echo -e "Filtering for processes matching: ${GREEN}$MONITOR_NAME${NC}"
    fi
    echo ""
    echo "Format: PROCESS-PID [CPU] TIMESTAMP: SYSCALL(args)"
    echo "---------------------------------------------------"
    echo -e "${YELLOW}Waiting for syscalls... (start benchmark in another terminal)${NC}"
    echo ""

    while IFS= read -r line; do
        # Filter by name if specified
        if [ -n "$MONITOR_NAME" ]; then
            if [[ ! "$line" =~ $MONITOR_NAME ]]; then
                continue
            fi
        fi

        # Colorize different syscalls
        if [[ "$line" =~ connect ]]; then
            echo -e "${GREEN}$line${NC}"
        elif [[ "$line" =~ (read|recv|recvfrom|recvmsg) ]]; then
            echo -e "${CYAN}$line${NC}"
        elif [[ "$line" =~ (write|send|sendto|sendmsg) ]]; then
            echo -e "${YELLOW}$line${NC}"
        elif [[ "$line" =~ (epoll|poll) ]]; then
            echo -e "${NC}$line${NC}"
        else
            echo "$line"
        fi
    done < "$TRACEFS/trace_pipe"
}

# Default mode: show filtered syscalls
run_default_mode() {
    echo -e "${CYAN}Monitoring syscalls - press Ctrl+C to stop${NC}"
    if [ -n "$MONITOR_NAME" ]; then
        echo -e "Filtering for processes matching: ${GREEN}$MONITOR_NAME${NC}"
    fi
    echo ""
    echo -e "  ${GREEN}GREEN${NC}  = connect (new connections)"
    echo -e "  ${CYAN}CYAN${NC}   = read/recv (incoming data)"
    echo -e "  ${YELLOW}YELLOW${NC} = write/send (outgoing data)"
    echo ""
    echo "---------------------------------------------------"
    echo -e "${YELLOW}Waiting for syscalls... (start benchmark in another terminal)${NC}"
    echo ""

    while IFS= read -r line; do
        # Filter by name if specified
        if [ -n "$MONITOR_NAME" ]; then
            if [[ ! "$line" =~ $MONITOR_NAME ]]; then
                continue
            fi
        fi

        # Skip poll/epoll spam
        if [[ "$line" =~ (epoll_wait|poll) ]]; then
            continue
        fi

        # Colorize different syscalls
        if [[ "$line" =~ connect ]]; then
            echo -e "${GREEN}$line${NC}"
        elif [[ "$line" =~ (read|recv|recvfrom|recvmsg) ]]; then
            echo -e "${CYAN}$line${NC}"
        elif [[ "$line" =~ (write|send|sendto|sendmsg) ]]; then
            echo -e "${YELLOW}$line${NC}"
        else
            echo "$line"
        fi
    done < "$TRACEFS/trace_pipe"
}

# Main
echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  Ftrace Benchmark Monitor${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

setup_ftrace

if [ $SUMMARY_MODE -eq 1 ]; then
    run_summary_mode
elif [ $VERBOSE -eq 1 ]; then
    run_verbose_mode
else
    run_default_mode
fi
