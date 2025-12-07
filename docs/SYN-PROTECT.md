# SYN Flood Protection Guide

## Overview
SocketSYNProtect provides layered protection against SYN flood attacks using:
- Per-IP attempt tracking with sliding windows
- Reputation scoring with automatic decay
- Action escalation (throttle/challenge/block)
- Whitelist/blacklist with CIDR support
- Global rate limiting via token bucket
- LRU eviction for memory bounds

## Security Fixes and Mitigations
- **CIDR Parsing Validation**: Invalid prefixes (e.g., `/abc`) are rejected, preventing /0 wildcard bypass that whitelists all IPs.
- **Whitelist DoS Mitigation**: IP parsed to bytes once per check; CIDR matching uses efficient byte memcmp, avoiding multiple `inet_pton` calls (O(1) avg vs O(n) CIDRs).
- **Arena Mode Safety**: No eviction in arena allocation to prevent memory bloat; hard cap at `max_tracked_ips`.
- **Metrics Accuracy**: `current_blocked_ips` counts only active (non-expired) blocks from both IP tracking and blacklists.
- **Hash Collision Resistance**: Configurable `hash_seed` (auto-randomized via `SocketCrypto_random_bytes` if 0) for DJB2 seed variation; monitor chain lengths.

## Configuration Recommendations
- `max_tracked_ips`: 10k-100k based on memory; lower for high-traffic.
- `window_duration_ms`: 10s for burst detection.
- `score_decay_per_sec`: 0.01-0.05 for gradual recovery.
- `hash_seed`: Set to 0 for auto-random (recommended); fixed for reproducible tests.
- Enable in `SocketPool_set_syn_protection(pool, protect)` for pool integration.

## Usage Examples
```c
SocketSYNProtect_Config cfg;
SocketSYNProtect_config_defaults(&cfg);
cfg.max_attempts_per_window = 50;
cfg.hash_seed = 0;  // Randomize

SocketSYNProtect_T protect = SocketSYNProtect_new(arena, &cfg);
SocketSYNProtect_whitelist_add_cidr(protect, "10.0.0.0/8");  // Trusted net

// In accept loop:
SocketSYN_Action action = SocketSYNProtect_check(protect, client_ip, NULL);
if (action != SYN_ACTION_ALLOW) {
  // Throttle, challenge, or drop
  close(fd);
  continue;
}

// On success:
SocketSYNProtect_report_success(protect, client_ip);
```

## Monitoring
- Metrics: `SOCKET_CTR_SYNPROTECT_*` counters, `SOCKET_GAU_SYNPROTECT_TRACKED_IPS/BLOCKED_IPS`.
- Logs: Warn on full lists, high evictions.
- Tests: Run `ctest -R synprotect`; fuzz with `./fuzz_synprotect`.

## Limitations
- Hash DoS: Mitigated but monitor; consider radix tree for CIDRs if >1k.
- Thread contention: Single mutex; scale with multiple instances if needed.
- No kernel SYN cookies auto; pair with sysctl net.ipv4.tcp_syncookies=1.

See src/core/SocketSYNProtect.c for implementation details.
