#!/bin/bash
#
# setup_ramdisk.sh - Mount tmpfs ramdisk for fuzzing corpus
#
# Part of the Socket Library Fuzzing Suite
#
# This script creates a RAM-based filesystem for the fuzzing corpus to
# eliminate disk I/O bottlenecks. Optimized for systems with 1TB+ RAM.
#
# Usage:
#   sudo ./scripts/setup_ramdisk.sh [SIZE_GB]
#   ./scripts/setup_ramdisk.sh unmount
#
# Examples:
#   sudo ./scripts/setup_ramdisk.sh          # Mount 200GB ramdisk (default)
#   sudo ./scripts/setup_ramdisk.sh 500      # Mount 500GB ramdisk
#   sudo ./scripts/setup_ramdisk.sh unmount  # Unmount ramdisk

set -e

MOUNT_POINT="/mnt/fuzz_corpus"
DEFAULT_SIZE_GB=200

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (sudo)"
        exit 1
    fi
}

# Get available RAM in GB
get_available_ram() {
    local mem_kb=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
    echo $((mem_kb / 1024 / 1024))
}

# Check system has enough RAM
check_ram() {
    local required_gb=$1
    local available_gb=$(get_available_ram)
    
    log_info "Available RAM: ${available_gb}GB"
    log_info "Requested ramdisk: ${required_gb}GB"
    
    if [[ $available_gb -lt $required_gb ]]; then
        log_error "Not enough available RAM. Need ${required_gb}GB, have ${available_gb}GB"
        exit 1
    fi
    
    # Warn if using more than 50% of available RAM
    local half_available=$((available_gb / 2))
    if [[ $required_gb -gt $half_available ]]; then
        log_warn "Ramdisk will use more than 50% of available RAM"
    fi
}

# Mount the ramdisk
mount_ramdisk() {
    local size_gb=${1:-$DEFAULT_SIZE_GB}
    
    check_root
    check_ram $size_gb
    
    # Create mount point if needed
    if [[ ! -d "$MOUNT_POINT" ]]; then
        log_info "Creating mount point: $MOUNT_POINT"
        mkdir -p "$MOUNT_POINT"
    fi
    
    # Check if already mounted
    if mountpoint -q "$MOUNT_POINT"; then
        log_warn "Ramdisk already mounted at $MOUNT_POINT"
        df -h "$MOUNT_POINT"
        return 0
    fi
    
    # Mount tmpfs
    log_info "Mounting ${size_gb}GB tmpfs at $MOUNT_POINT"
    mount -t tmpfs -o size=${size_gb}G,mode=1777 tmpfs "$MOUNT_POINT"
    
    # Create corpus directories (match fuzzer target names without fuzz_ prefix)
    log_info "Creating corpus directories"
    mkdir -p "$MOUNT_POINT"/{socketbuf,arena,ip_parse,dns_validate,socketbuf_stress}
    chmod 777 "$MOUNT_POINT"/{socketbuf,arena,ip_parse,dns_validate,socketbuf_stress}
    
    # Copy seed corpus if available
    local seed_dir="$(dirname "$0")/../src/fuzz/corpus"
    if [[ -d "$seed_dir" ]]; then
        log_info "Copying seed corpus"
        for target in socketbuf arena ip_parse dns_validate socketbuf_stress; do
            if [[ -d "$seed_dir/$target" ]]; then
                cp -r "$seed_dir/$target"/* "$MOUNT_POINT/$target/" 2>/dev/null || true
            fi
        done
    fi
    
    log_info "Ramdisk mounted successfully!"
    df -h "$MOUNT_POINT"
    echo ""
    log_info "Run fuzzers with: ./fuzz_socketbuf $MOUNT_POINT/socketbuf/ -fork=16"
}

# Unmount the ramdisk
unmount_ramdisk() {
    check_root
    
    if ! mountpoint -q "$MOUNT_POINT"; then
        log_warn "No ramdisk mounted at $MOUNT_POINT"
        return 0
    fi
    
    log_warn "WARNING: All data in ramdisk will be lost!"
    read -p "Continue? (y/N) " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "Unmounting ramdisk"
        umount "$MOUNT_POINT"
        log_info "Ramdisk unmounted"
    else
        log_info "Cancelled"
    fi
}

# Show usage
show_usage() {
    echo "Usage: $0 [SIZE_GB|unmount]"
    echo ""
    echo "Commands:"
    echo "  <SIZE_GB>   Mount ramdisk with specified size (default: ${DEFAULT_SIZE_GB}GB)"
    echo "  unmount     Unmount the ramdisk"
    echo ""
    echo "Examples:"
    echo "  sudo $0           # Mount ${DEFAULT_SIZE_GB}GB ramdisk"
    echo "  sudo $0 500       # Mount 500GB ramdisk"
    echo "  sudo $0 unmount   # Unmount ramdisk"
}

# Main
case "${1:-}" in
    unmount)
        unmount_ramdisk
        ;;
    -h|--help)
        show_usage
        ;;
    "")
        mount_ramdisk $DEFAULT_SIZE_GB
        ;;
    *)
        if [[ "$1" =~ ^[0-9]+$ ]]; then
            mount_ramdisk "$1"
        else
            log_error "Unknown argument: $1"
            show_usage
            exit 1
        fi
        ;;
esac

