# Refactor Analysis Report

**Generated**: 2025-12-29
**Target**: /home/tetsuo/git/tetsuo-socket/src/core/
**Files Analyzed**: 19

## Executive Summary

- **Nested If Issues**: 18 (CRITICAL: 0, HIGH: 0, MEDIUM: 16, LOW: 2)
- **Single-Use Subroutines**: 67 (inline candidates: 31, review needed: 10, justified: 26)

## Statistics Overview

| File | Lines | Nested If (3+) | Single-Use Functions | Priority |
|------|-------|----------------|---------------------|----------|
| TimeWindow.c | 121 | 0 | 0 | NONE |
| SocketSYNProtect-list.c | 160 | 0 | 0 | NONE |
| SocketError.c | 184 | 0 | 1 | LOW |
| Except.c | 208 | 0 | 3 (inline) + 1 (review) | MEDIUM |
| SocketEvent.c | 238 | 0 | 2 (inline) + 3 (review) | LOW |
| SocketSecurity.c | 243 | 0 | 9 | MEDIUM |
| SocketUtil.c | 253 | 2 | 1 | LOW |
| HashTable.c | 272 | 1 | 1 | LOW |
| SocketSYNProtect-ip.c | 303 | 1 | 0 | LOW |
| SocketLog.c | 396 | 2 | 2 | MEDIUM |
| SocketRetry.c | 462 | 2 | 4 | MEDIUM |
| SocketRateLimit.c | 503 | 0 | 2 | LOW |
| Arena.c | 619 | 2 | 0 | LOW |
| SocketIPTracker.c | 673 | 2 | 2 | LOW |
| SocketUTF8.c | 767 | 0 | 4 | MEDIUM |
| SocketCrypto.c | 808 | 5 | 4 | MEDIUM |
| SocketTimer.c | 815 | 0 | 3 | LOW |
| SocketMetrics.c | 1133 | 0 | 3 | LOW |
| SocketSYNProtect.c | 1621 | 4 | 5 | MEDIUM |

---

## Nested If Statements (18 total)

### MEDIUM Severity (16)

| File:Lines | Depth | Function | Recommendation |
|------------|-------|----------|----------------|
| SocketCrypto.c:399-414 | 3 | base64_decode_char | Flatten with early return for padding validation |
| SocketCrypto.c:460-471 | 3 | base64_validate_input | Flatten with early returns for input validation |
| SocketCrypto.c:690-696 | 3 | SocketCrypto_cleanup | Flatten with guard clause for cleanup |
| SocketCrypto.c:756-765 | 3 | SocketCrypto_generate_websocket_key | Restructure to ensure cleanup on all paths |
| SocketCrypto.c:626-633 | 3 | urandom_read_all | Simplify EINTR retry logic |
| SocketSYNProtect.c:899-908 | 3 | SocketSYNProtect_new | Remove unnecessary block nesting |
| SocketSYNProtect.c:1025-1032 | 3 | SocketSYNProtect_reward | Use guard clause for null entry |
| SocketSYNProtect.c:1055-1067 | 3 | SocketSYNProtect_penalize | Use guard clause for null entry |
| SocketRetry.c:66-73 | 3 | init_random_state | Simplify nested if-else for crypto fallback |
| SocketRetry.c:286-295 | 3 | SocketRetry_new | Handle NULL case first for clarity |
| SocketLog.c:47-56 | 3 | socketlog_format_timestamp | Flatten with early return for zero bufsize |
| SocketLog.c:369-383 | 3 | socketlog_emit_structured_with_all | Convert if-else-if chain to early returns |
| SocketIPTracker.c:396-404 | 3 | cleanup_failed_tracker | Invert arena check to guard clause |
| SocketIPTracker.c:555-562 | 3 | SocketIPTracker_release | Split conditions with early return |
| Arena.c:497-506 | 3 | Arena_alloc | Mutex cleanup pattern - acceptable |
| Arena.c:604-609 | 3 | Arena_reset | Invert condition to reduce nesting |

### LOW Severity (2)

| File:Lines | Depth | Function | Recommendation |
|------------|-------|----------|----------------|
| SocketUtil.c:103-107 | 3 | Socket_get_monotonic_ms | Minor restructure with inverted condition |
| SocketSYNProtect-ip.c:162-180 | 3 | whitelist_check_bucket_bytes | Flatten with early continue for CIDR case |

---

## Single-Use Subroutines

### Inline Candidates (31 functions)

These small helper functions are called exactly once and can be safely inlined:

#### SocketSecurity.c (9 functions) - All populate_* helpers
| Function | Lines | Action |
|----------|-------|--------|
| populate_memory_limits | 10 | INLINE into SocketSecurity_get_limits |
| populate_http_limits | 12 | INLINE |
| populate_http1_limits | 8 | INLINE |
| populate_http2_limits | 11 | INLINE |
| populate_hpack_limits | 7 | INLINE |
| populate_ws_limits | 8 | INLINE |
| populate_tls_limits | 13 | INLINE |
| populate_ratelimit_limits | 9 | INLINE |
| populate_timeout_limits | 10 | INLINE |

#### Except.c (3 functions)
| Function | Lines | Action |
|----------|-------|--------|
| except_flush_stderr | 4 | INLINE - trivial fflush wrapper |
| except_emit_reason | 6 | INLINE - small helper |
| except_pop_frame | 5 | INLINE - simple operation |

#### SocketTimer.c (3 functions)
| Function | Lines | Action |
|----------|-------|--------|
| sockettimer_allocate_timer | 5 | INLINE - trivial wrapper |
| sockettimer_heap_alloc_structure | 4 | INLINE - trivial wrapper |
| sockettimer_heap_alloc_timers | 5 | INLINE - trivial wrapper |

#### SocketRetry.c (3 functions)
| Function | Lines | Action |
|----------|-------|--------|
| exponential_backoff | 18 | INLINE into calculate_backoff_delay |
| apply_jitter_to_delay | 19 | INLINE |
| clamp_final_delay | 10 | INLINE |

#### SocketCrypto.c (4 functions)
| Function | Lines | Action |
|----------|-------|--------|
| base64_encode_triplet | 7 | INLINE - hot path |
| base64_encode_remainder | 16 | INLINE |
| base64_is_whitespace | 4 | INLINE - trivial check |
| urandom_ensure_open | 8 | INLINE - simple lazy init |

#### SocketUTF8.c (3 functions)
| Function | Lines | Action |
|----------|-------|--------|
| dfa_transition | 5 | INLINE - trivial array lookup |
| is_continuation_byte | 5 | INLINE - simple predicate |
| classify_first_byte_error | 7 | INLINE - simple classification |

#### SocketEvent.c (2 functions)
| Function | Lines | Action |
|----------|-------|--------|
| socketevent_copy_handlers_unlocked | 6 | INLINE - simple memcpy |
| socketevent_add_handler_unlocked | 6 | INLINE - simple assignment |

#### Other Files (4 functions)
| File | Function | Lines | Action |
|------|----------|-------|--------|
| SocketError.c | socket_errno_to_errorcode | 5 | INLINE |
| SocketUtil.c | socket_timespec_to_ms | 5 | INLINE |
| SocketRateLimit.c | ratelimit_allocate | 7 | INLINE |
| SocketRateLimit.c | ratelimit_reset_locked | 5 | INLINE |

### Review Needed (10 functions)

These functions merit discussion - could be inlined but may have justification for separation:

| File | Function | Lines | Notes |
|------|----------|-------|-------|
| Except.c | except_store_exception | 10 | Borderline - name documents intent |
| SocketMetrics.c | histogram_copy_basic_stats | 9 | Mutex wrapper - trivial |
| SocketMetrics.c | histogram_compute_derived_stats | 11 | Single calculation |
| SocketMetrics.c | export_prometheus_histogram_summary | 9 | Only 2 export_append calls |
| SocketUTF8.c | update_sequence_tracking | 19 | Moderate size, may improve caller readability |
| SocketIPTracker.c | allocate_entry | 4 | Trivial wrapper |
| SocketIPTracker.c | allocate_tracker | 7 | Trivial wrapper |
| SocketEvent.c | socketevent_invoke_handlers | 11 | May improve testability |
| SocketEvent.c | socketevent_can_register_unlocked | 15 | Good semantic abstraction |
| SocketRetry.c | perform_single_attempt | 22 | Larger - may justify separation |

### Justified Separation (26 functions)

These single-use functions should **NOT** be inlined for good reasons:

| Category | Count | Reason |
|----------|-------|--------|
| Error path helpers (COLD/NORETURN) | 6 | Compiler hints for branch prediction |
| Initialization patterns | 5 | init/destroy pairs, clear separation |
| Complex logic (>20 lines) | 4 | Would harm readability if inlined |
| Callback functions | 2 | Used as function pointers |
| Export format helpers | 9 | DRY principle, symmetry across formats |

---

## Files With No Issues (2)

These files demonstrate excellent readability practices:

1. **TimeWindow.c** (121 lines) - Clean control flow, proper helper reuse (3 calls)
2. **SocketSYNProtect-list.c** (160 lines) - Good LRU abstractions, module boundaries

---

## Recommendations by Priority

### High Priority (Consider First)
1. **SocketSecurity.c**: Inline all 9 populate_* functions into SocketSecurity_get_limits
2. **SocketCrypto.c**: Fix 5 nested if issues with guard clauses

### Medium Priority
3. **SocketRetry.c**: Consolidate backoff calculation pipeline (3 functions)
4. **SocketTimer.c**: Inline 3 trivial allocation wrappers
5. **Except.c**: Inline 3 small helpers (flush_stderr, emit_reason, pop_frame)

### Low Priority (Optional)
6. Other files have minor improvements available but are already well-structured

---

## Summary Statistics

| Metric | Count |
|--------|-------|
| Files analyzed | 19 |
| Total lines of code | 9,779 |
| Nested if issues (3+ depth) | 18 |
| Single-use functions found | 67 |
| Recommended for inlining | 31 |
| Recommended to keep | 26 |
| Needs review | 10 |

---

*Report generated by /pipeline refactor*
