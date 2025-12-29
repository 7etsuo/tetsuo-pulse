# Refactor Analysis Report

**Generated**: 2025-12-29
**Target**: src/http/SocketHTTP2-*.c (6 files)
**Files Analyzed**: 6

## Executive Summary

- **Nested If Issues**: 17 (CRITICAL: 4, HIGH: 6, MEDIUM: 7)
- **Single-Use Subroutines**: 61 (inline candidates: 13, review needed: 15, justified: 33)

| File | Lines | Nested Ifs | Single-Use | Priority |
|------|-------|------------|------------|----------|
| SocketHTTP2-stream.c | 2615 | 8 | 26 | **CRITICAL** |
| SocketHTTP2-connection.c | 1560+ | 5 | 32 | HIGH |
| SocketHTTP2-priority.c | 345 | 1 | 0 | **CRITICAL** |
| SocketHTTP2-frame.c | 490 | 2 | 2 | MEDIUM |
| SocketHTTP2-validate.c | 540 | 1 | 1 | LOW |
| SocketHTTP2-flow.c | 196 | 0 | 0 | NONE (exemplary) |

---

## Nested If Statements

### CRITICAL (5+ depth)

| File:Lines | Depth | Function | Recommendation |
|------------|-------|----------|----------------|
| SocketHTTP2-stream.c:1495-1551 | 15 | SocketHTTP2_Stream_send_headers_padded | Flatten with guard clauses |
| SocketHTTP2-stream.c:1614-1674 | 12 | send_request TRY block | Extract validation, flatten |
| SocketHTTP2-stream.c:1690-1735 | 13 | send_response TRY block | Extract validation, flatten |
| SocketHTTP2-priority.c:218-250 | 5 | SocketHTTP2_Priority_parse | Guard clause refactor |

#### SocketHTTP2-stream.c:1495-1551 (Depth: 15)

**Worst offender in the codebase.** This function cascades through 15 levels of nesting:

**Current (simplified):**
```c
if (pad_length == 0)
  return SocketHTTP2_Stream_send_headers(...);

error = http2_stream_transition(...);
if (error != HTTP2_NO_ERROR)        // Level 2
  {
    if (header.stream_id == 0)      // Level 3
      {
        // ... continues to Level 15
      }
  }
```

**Suggested:**
```c
if (pad_length == 0)
  return SocketHTTP2_Stream_send_headers(stream, headers, header_count, end_stream);

error = http2_stream_transition(stream, HTTP2_FRAME_HEADERS,
                                 end_stream ? HTTP2_FLAG_END_STREAM : 0, 1);
if (error != HTTP2_NO_ERROR)
  return -1;

unsigned char *header_block;
ssize_t block_len_ssize = http2_encode_and_alloc_block(
    conn, headers, header_count, &header_block);
if (block_len_ssize < 0)
  return -1;

size_t block_len = (size_t)block_len_ssize;
uint32_t max_frame_size = conn->peer_settings[SETTINGS_IDX_MAX_FRAME_SIZE];
size_t total_padded_len = 1 + block_len + pad_length;

int send_result;
if (total_padded_len <= max_frame_size)
  send_result = send_single_headers_frame_padded(...);
else
  send_result = send_fragmented_headers_padded(...);

if (send_result < 0)
  return -1;

if (end_stream)
  stream->end_stream_sent = 1;

return 0;
```

#### SocketHTTP2-priority.c:218-250 (Depth: 5)

**Current:**
```c
if (p < end && *p == '=')               // Level 1 (within while loop)
  {
    p++;
    p = skip_ows (p, end);

    if (p < end && *p == '?')           // Level 2
      {
        p++;
        if (p < end && *p == '1')       // Level 3
          {
            priority->incremental = 1;
            p++;
          }
        else if (p < end && *p == '0')  // Level 3
          {
            priority->incremental = 0;
            p++;
          }
        else                            // Level 3
          {
            SOCKET_LOG_DEBUG_MSG ("Priority parse error: invalid boolean for i");
            return -1;
          }
      }
    // ... continues
  }
```

**Suggested:**
```c
if (p < end && *p == '=')
  {
    p++;
    p = skip_ows (p, end);

    /* Guard: Must have '?' prefix for boolean */
    if (p >= end || *p != '?')
      {
        SOCKET_LOG_DEBUG_MSG ("Priority parse error: i= requires ?0 or ?1");
        return -1;
      }

    p++;

    if (p >= end)
      {
        SOCKET_LOG_DEBUG_MSG ("Priority parse error: invalid boolean for i");
        return -1;
      }

    if (*p == '1')
      {
        priority->incremental = 1;
        p++;
      }
    else if (*p == '0')
      {
        priority->incremental = 0;
        p++;
      }
    else
      {
        SOCKET_LOG_DEBUG_MSG ("Priority parse error: invalid boolean for i");
        return -1;
      }
  }
```

---

### HIGH (4 depth)

| File:Lines | Depth | Function | Recommendation |
|------------|-------|----------|----------------|
| SocketHTTP2-stream.c:766-870 | 4 | validate_pseudo_header | Early returns |
| SocketHTTP2-stream.c:873-962 | 4 | validate_regular_header_entry | Guard clauses |
| SocketHTTP2-stream.c:1113-1182 | 5 | http2_recombine_cookie_headers | Use continue |
| SocketHTTP2-stream.c:340-371 | 4 | transition_from_idle | Consider flattening |
| SocketHTTP2-stream.c:444-472 | 5 | transition_from_half_closed_local | Flatten |
| SocketHTTP2-connection.c:1062-1074 | 4 | validate_initial_window_size | Acceptable (loop pattern) |

---

### MEDIUM (3 depth)

| File:Lines | Depth | Function | Recommendation |
|------------|-------|----------|----------------|
| SocketHTTP2-connection.c:827-838 | 3 | process_single_frame | Guard clauses |
| SocketHTTP2-connection.c:877-886 | 3 | enforce_timeouts | Guard clauses |
| SocketHTTP2-connection.c:1264-1272 | 3 | http2_process_ping | Early return |
| SocketHTTP2-connection.c:1318-1325 | 3 | process_stream_window_update | Early return |
| SocketHTTP2-connection.c:1457-1469 | 3 | SocketHTTP2_Conn_upgrade_server | Guard clause |
| SocketHTTP2-frame.c:366-377 | 3 | frame serialization | Early return |
| SocketHTTP2-frame.c:429-440 | 3 | RST_STREAM send | Guard clauses |

---

## Single-Use Subroutines

### Inline Candidates (<30 lines)

| Function | File | Lines | Recommendation |
|----------|------|-------|----------------|
| clear_pending_header_block | stream.c | 6 | **INLINE** |
| add_stream_to_hash | stream.c | 8 | **INLINE** |
| http2_stream_rate_record | stream.c | 12 | **INLINE** |
| http2_unpack_stream_id | frame.c | 5 | **INLINE** |
| http2_pack_stream_id | frame.c | 6 | **INLINE** |
| init_peer_settings | connection.c | 6 | **INLINE** |
| process_settings_ack | connection.c | 12 | **INLINE** |
| handshake_send_client_preface | connection.c | 11 | **INLINE** |
| generate_hash_seed | connection.c | 12 | **INLINE** |
| validate_enable_push | connection.c | 10 | **INLINE** |
| validate_max_frame_size | connection.c | 12 | **INLINE** |
| update_conn_state_after_settings | connection.c | 11 | **INLINE** |
| send_single_headers_frame | stream.c | 15 | **INLINE** |

### Review Needed (30-100 lines)

These are called once but may be justified for clarity:

| Function | File | Lines | Notes |
|----------|------|-------|-------|
| send_fragmented_headers_padded | stream.c | 64 | Complex padding/fragmentation |
| http2_recombine_cookie_headers | stream.c | 69 | RFC 9113 requirement |
| http2_validate_headers | stream.c | 72 | Validation orchestration |
| validate_required_pseudo_headers | stream.c | 73 | Validation logic |
| validate_regular_header_entry | stream.c | 90 | Validation logic |
| validate_pseudo_header | stream.c | 104 | Validation dispatch |
| enforce_timeouts | connection.c | 37 | Timeout logic separation |
| process_single_frame | connection.c | 51 | Frame processing |
| validate_and_apply_setting | connection.c | 48 | Central validation |
| validate_initial_window_size | connection.c | 31 | Window adjustment loop |
| http2_is_cipher_forbidden | validate.c | 44 | Security policy |

### Justified Separation (Initialization Pattern)

The following functions are single-use by design, following an initialization pattern:

| Function | File | Lines | Justification |
|----------|------|-------|---------------|
| init_local_settings | connection.c | 16 | Phase-based init |
| init_flow_control | connection.c | 17 | Phase-based init |
| create_io_buffers | connection.c | 23 | Phase-based init |
| create_hpack_encoder | connection.c | 14 | Phase-based init |
| create_hpack_decoder | connection.c | 16 | Phase-based init |
| create_stream_hash_table | connection.c | 11 | Phase-based init |
| init_connection_components | connection.c | 19 | Phase-based init |
| init_rate_limiters | connection.c | 15 | Phase-based init |
| init_rate_limiting_windows | connection.c | 23 | Phase-based init |
| init_stream_id_and_timeouts | connection.c | 12 | Phase-based init |
| init_stream_fields | stream.c | 21 | Stream init |

---

## File Quality Ratings

| File | Nesting | Single-Use | Overall |
|------|---------|------------|---------|
| SocketHTTP2-flow.c | A+ | A+ | **A+ (exemplary)** |
| SocketHTTP2-validate.c | A | A | **A** |
| SocketHTTP2-frame.c | B | B | **B** |
| SocketHTTP2-connection.c | B- | C+ | **B-** |
| SocketHTTP2-priority.c | C | A+ | **B** |
| SocketHTTP2-stream.c | D | C | **C-** |

---

## Statistics

| Metric | Count |
|--------|-------|
| Files analyzed | 6 |
| Total nested if issues | 17 |
| Critical (5+ depth) | 4 |
| Total single-use functions | 61 |
| Inline candidates | 13 |
| Lines that could be simplified | ~500 |

---

## Recommended Refactoring Order

### Phase 1: Critical Nesting (Immediate)

1. **SocketHTTP2-stream.c:1495-1551** - Flatten 15-level nesting
2. **SocketHTTP2-stream.c:1614-1674** - Flatten TRY block
3. **SocketHTTP2-stream.c:1690-1735** - Flatten TRY block
4. **SocketHTTP2-priority.c:218-250** - Boolean parsing guard clauses

### Phase 2: High Priority

5. **SocketHTTP2-stream.c** validation functions - Guard clause refactor
6. **SocketHTTP2-connection.c** timeout/frame processing - Early returns

### Phase 3: Inline Trivial Functions

7. Inline 13 small single-use helpers listed above
8. Consolidate initialization pattern if desired

---

*Report generated by /pipeline refactor*
