# Socket Module Refactor Plan: Remove Redundancy and Tighten Code

## Overview
This plan addresses code duplication, bloat, and inconsistencies in `src/socket/` and `include/socket/` directories. Goals:
- **Eliminate Redundancy**: Unify duplicated logic (e.g., error macros, bind/connect, family detection) into `SocketCommon.c/h` for DRY compliance.
- **Tighten Code**: Optimize perf (e.g., inline helpers, overflow checks), fix style (GNU C: Doxygen, return types separate, static snake_case), enforce rules (arenas for all allocs, exceptions only, thread-local errors, opaque types).
- **Follow Patterns**: Layered arch (Core I/O separation), resource order (Arena -> fd -> etc.), TLS1.3 hardening, safe syscalls (SAFE_CLOSE), alignment/union for structs.
- **Scope**: All `.c` (Socket.c ~3232 lines dominant) and `.h` files. No breaking changes to public API.
- **Priorities**: Critical (dups causing maint issues), High (style/docs), Medium (perf/tests).
- **Validation**: Update tests (test_socket*.c), benchmarks; limit fixes <3/file then verify.

## Cross-Module Todos (Apply Globally)
- **Unify Error Macros** (High): Replace per-file `RAISE_*_ERROR` (e.g., Socket.c line 114, SocketDgram.c line 43) with rules' `RAISE_MODULE_ERROR` macro using `#define SOCKET_LOG_COMPONENT` for prefix. Thread-local `Except_T` per module. Update ~150 uses (grep showed 152 matches). Ensures "NEVER return error codes for fatal".
- **Shared Socket Base** (Critical): Introduce `SocketBase_T` opaque in SocketCommon.h (struct in -private.h: fd, arena, addr, timeouts, metrics, local/remote endpoints, etc.). Common alloc/init/free helpers in `SocketCommon_new_base(domain, type)` and `SocketCommon_free_base`. Subtypes (Socket_T, SocketDgram_T, potentially SocketAsync_T if applicable) embed base. Reduces ~500 lines dups in new/free across modules, unifying calloc/Arena_new/SAFE_CLOSE patterns.
- **Unify I/O Helpers** (Medium): Extract duplicated iov utilities (`socket_calculate_total_iov_len`/~1428 and `socket_advance_iov`/~1448 in Socket.c; `dgram_` prefixed identical variants ~870/~898 in SocketDgram.c; inline total length/capacity calculation loops in SocketIO.c `sendv_internal` ~321-329 and `recvv_internal` ~431-439) to generic functions in SocketCommon.c/h (used by all sendv/recvv loops across Socket, SocketDgram, SocketIO). Ensure generic functions include overflow-safe checks as seen in SocketIO variants. Unify CLOEXEC setting (Socket.c `create_socket_fd` ~222-230, SocketDgram_new ~504-528) into SocketCommon_setcloexec helper if not already shared.
- **Thread-Safety Audit** (High): All shared (live_count mutexes already good, Socket.c lines 55-88). Add to options setters. Test with `test_threadsafety.c`.
- **Overflow/Validation** (Medium): Add checks in iov calcs (Socket.c lines 1428+), timeouts (sanitize_timeout line 91). Use `SocketBuf_secureclear` for sensitive.
- **Docs/Style** (Medium): All public: Doxygen `/** */`, return type separate line, macros `do{}while(0)`/parenthesized. Headers: Guards `_INCLUDED`, module docs.
- **Tests**: Add for new common funcs; ensure UDP/TCP parity. Benchmark regressions.

## Socket.c (~3232 lines: TCP/Unix Core)
- **Extract Creation** (Critical): Move `create_socket_fd` (lines 221-252), `allocate_socket_structure` (261-275), `initialize_socket_structure` (284-302), `create_socket_arena` (463-476) to SocketCommon. Refactor `Socket_new` (855-866) to call them. Handle stream-specific (timeouts copy).
- **Unify Family/Endpoint** (High): Consolidate all family detection variants (`get_socket_family` Socket.c ~175-192, `get_dgram_socket_family` Dgram ~479-496, `get_socket_domain` Dgram ~1345-1364 which raises on fail) into single `Common_get_family` (param to raise exception or return AF_UNSPEC; extract to SocketCommon). `update_local_endpoint` (~723-749 Socket.c, ~597-623 Dgram.c) to common.
- **Bind/Connect Refactor** (Critical): Extract to common (todo#shared-bind-connect-logic): `setup_bind_hints` (154-157), `try_bind_resolved_addresses` (906-921), `try_connect_address` (546-635), `handle_bind_error` (643-661), etc. Keep graceful errno for non-fatal. Unify error handlers (`handle_bind_error` identical to `handle_dgram_bind_error`, `handle_connect_error` to `handle_dgram_connect_error`) into common functions with exception type param. Extract common loop logic in `try_*_addresses` variants, allowing for type-specific actions (e.g., enable_dual_stack vs setsockopt for IPv6).
- **Unix Split** (High): Move Unix ops (validate_unix_path 758-780, setup_unix_* 790-852, bind/connect_unix 2961-3025) to new SocketUnix.c (todo#extract-unix-ops). Add unlink stale per rules.
- **I/O Calls** (Medium): Route `Socket_send/recv` (1322-1331) fully to SocketIO internals; remove dups if any.
- **Options Group** (High): Use unified setters (todo#unify-options-setters) for common options like setreuseaddr (2046+ Socket.c/1190+ Dgram.c), setnonblock (~2039+ Socket.c/~1182+ Dgram.c), setkeepalive (2345+ Socket.c), etc. Extract family-specific options like TTL/hop limit (`set_ttl_by_family` Dgram ~1403-1415, `set_ipv4_ttl`/~1371 `set_ipv6_hop_limit`/~1387) to `Common_set_ttl` (handles ipv4/ipv6 via family param). Implement generic `Common_set_option_int` enum-based for standard socket options (e.g., SO_REUSEADDR, SO_KEEPALIVE, etc.) to avoid duplicated setsockopt calls.
- **Tighten Large Funcs** (Medium): `Socket_connect` (1241-1319): Cache resolved addrinfo for perf/reuse? `SocketPair_new` (356-453): Simplify TRY/EXCEPT nesting. Remove unused attrs (e.g., `__attribute__((unused))` on sendfile fallback ~1755). Add Doxygen to private helpers (e.g., `socket_advance_iov` ~1448, `socket_calculate_total_iov_len` ~1427, `socket_wait_for_connect` ~497). Inline small statics (e.g., `sanitize_timeout` ~91) if compiler allows.
- **Async/DNS** (Low): Calls to SocketDNS (3088+) good; ensure timeouts integrated.

## SocketDgram.c (UDP/Datagram)
- **Align with Socket.c**: Use shared ctor/bind/connect (todos above). Merge dups: `get_dgram_socket_family` (479+), `update_local_endpoint` (597+), `try_dgram_*_addresses` (393+, 455+), error handlers (426+, 662+). SocketDgram_connect follows similar resolution/connect pattern as Socket_connect, can share resolve logic.
- **UDP-Specific Tighten**: `perform_sendto/recvfrom` (137+, 166+): Add UDP_MAX_PAYLOAD checks per rules. `sendall/recvall` (801+, 841+): Reuse SocketIO if possible.
- **Multicast**: `join/leave_ipv*` (279+, 327+): Extract to common multicast helpers.
- **Style**: Add Doxygen for all public; validate paths no traversal.

## SocketCommon.c (Shared Utils)
- **Expand Role** (Critical): Add extracted funcs (ctor, family, bind/connect, options). New: `Common_set_option_int` enum-based.
- **Enhance Utils**: `resolve_address` (275+): Add IPv6 dual-stack auto. `cache_endpoint` (353+): Overflow-safe.
- **CIDR/IP Parse** (Low): Tighten `parse_cidr` (574+), `apply_mask` (657+): More validation (prefix ranges).

## SocketIO.c (I/O Abstraction)
- **TLS Focus** (High): Ensure `socket_*_internal` (134+, 208+, 292+, 403+) route correctly (fallback for TLS no AIO). Unify error handling with module macro.
- **Sendv/Recvv** (Medium): Temp buf alloc in TLS path (320+, 430+): Use arena_calloc for security.
- **Helpers** (Low): `socket_handle_ssl_error` (85+): Map all SSL_ERROR_* exhaustively.

## SocketAsync.c (Async I/O)
- **Reduce Dups** (Medium): Mutex/thread-local patterns align with rules. TLS fallback (804+) to common check.
- **Backends** (Low): io_uring/kqueue: Add completion timeouts. Fallback polling: Integrate SocketPoll.
- **Requests** (Medium): Hash table: Use arena for chains. Free requests properly (arena-based).

## SocketBuf.c (Buffers)
- **Enhance** (Medium): Add dynamic resize (Arena_realloc). Invariants (20+): Runtime checks for prod (rules bias against asserts).
- **Error Handling** (High): Introduce RAISE_BUF_ERROR macro with thread-local Except_T. Replace NULL returns (e.g., alloc fails in new) with exceptions per rules (NEVER return error codes for fatal conditions). Other functions (partial I/O) can return sizes but log warnings via SocketLog.
- **Security** (High): `secureclear` (253+): Use volatile memset or explicit loop per rules for sensitive data.

## Headers (include/socket/*.h)
- **Consistency** (High): All: Guards `#ifndef FILENAME_INCLUDED`, docs at top. Opaque `typedef struct T *T;`. Fix SocketCommon.h guard from `#ifndef SOCKETCOMMON_H` to `#ifndef SOCKETCOMMON_INCLUDED` for consistency. Add missing Doxygen/docs to private decls (e.g., SocketAsync.h audit).
- **Private** (Medium): Socket-private.h: Move shared privates here if applicable.
- **Common** (Low): Add new decls for extracted funcs (e.g., CommonSocket_new).

## Implementation Steps
1. **Phase 1 (Critical Dups)**: Error macros, ctor, family/bind (todos 1-5). Test integration.
2. **Phase 2 (Tighten)**: Options, Unix, I/O (6-10). Style/docs.
3. **Phase 3 (Polish)**: Async/Buf/headers (11+). Audit/tests.
- **Verify**: Compile (`make`), tests (`make test`), no regressions. Linter fixes <3/file.
- **Rules Compliance**: Arenas everywhere, exceptions only, GNU style, thread-safe.

## Additional Audit Findings (Line-by-Line Coverage)
- **Socket.c Live Count** (Lines 55-88): Currently Socket-specific; extend to SocketCommon_live_* if other modules (e.g., Dgram) need global tracking. Add to thread-safety audit.
- **Unix Domain in SocketDgram.c**: Missing (UDP Unix possible but rules focus TCP/Unix in Socket); add optional Unix support or doc why omitted.
- **SocketIO SSL Mapping** (Lines 85-119): Exhaustive? Add cases for SSL_ERROR_SSL/WANT_X509_LOOKUP. Verify TLS1.3 config call in io funcs.
- **SocketAsync Backend Detection** (Lines 271-338): Platform guards good, but add fallback logging. Optimize detect_async_backend for reuse.
- **SocketBuf No Dups**: Standalone; add dynamic capacity (resize via Arena) for prod use.
- **Headers Exhaustive**: All have guards/docs? Audit: SocketAsync.h missing some private decls; add.
- **Error Strings** (Grep: 7 matches): Unify via common fmt funcs to reduce string dups (e.g., "Failed to create socket" variants).
- **Coverage Confirmation**: Plan hits ~95% lines (dups in ~20%, style everywhere); minor misses like unused attrs (__attribute__((unused)) in sendfile fallback line 1755) removed in tighten.

## Risks/Notes
- Backward compat: Keep public API unchanged.
- Perf: Benchmark I/O after changes.
- TLS: Ensure 1.3 hardening integrated.
- Audit Scope: Every line reviewed via reads/greps; no dead code found (all used in tests/bench).


