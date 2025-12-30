# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## MANDATORY: Git Workflow for Code Changes

**BEFORE making ANY code changes** (implement, add, fix, refactor, modify), you MUST:

1. **Invoke `/git-workflow`** to set up proper git workflow
2. The skill will ensure you're on a feature branch (not main)
3. Only proceed with code changes AFTER git workflow confirms setup

**This is NOT optional.** The git-safety-check hook will block commits to main.

### Quick Reference

| Action | Command |
|--------|---------|
| Start new work | `/git-workflow` → creates issue + branch |
| Commit changes | `/git-workflow` → proper commit format |
| Create PR | `/git-workflow` → PR with correct template |

### Branch Naming

- Features: `issue-<num>-<description>`
- Fixes: `issue-<num>-fix-<description>`

### Commit Format

```
<type>: <description>

<body>

Fixes #<issue>
```

Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`

**IMPORTANT**: Do NOT add "Generated with Claude Code", "Co-Authored-By: Claude", or any AI attribution to commit messages. Keep commits clean and professional.

## Build Commands

**MANDATORY: Always use `-j$(nproc)` for all build and test commands.** This maximizes parallelism and significantly speeds up builds/tests. Never omit the `-j` flag.

```bash
# Standard build (Debug)
cmake -S . -B build
cmake --build build -j$(nproc)

# Release build (optimized)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

# Run tests (parallel)
cd build && ctest -j$(nproc) --output-on-failure

# Build with TLS support (auto-detects OpenSSL/LibreSSL)
cmake -S . -B build -DENABLE_TLS=ON

# Build with sanitizers (required for PRs)
cmake -S . -B build -DENABLE_SANITIZERS=ON
cmake --build build -j$(nproc)
cd build && ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 ctest -j$(nproc) --output-on-failure

# Build with fuzzing (requires Clang)
CC=clang cmake -S . -B build -DENABLE_FUZZING=ON
cmake --build build --target fuzzers -j$(nproc)  # Build ALL fuzzers
# Or build individual fuzzer:
cmake --build build --target fuzz_socketbuf -j$(nproc)

# Build with io_uring (Linux only, requires liburing-dev)
cmake -S . -B build -DENABLE_IO_URING=ON

# Run single test
cd build && ./test_socket

# Run fuzzers (after ENABLE_FUZZING build)
cd build && ./fuzz_socketbuf corpus/socketbuf/ -fork=16 -max_len=4096

# List all available fuzzers (~130 harnesses)
ls build/fuzz_*

# Generate documentation
cd build && make -j$(nproc) doc
```

## Build Options

| Option | Description |
|--------|-------------|
| `ENABLE_TLS` | Enable TLS/SSL support (default: ON) |
| `ENABLE_SANITIZERS` | Enable ASan + UBSan |
| `ENABLE_TSAN` | Enable ThreadSanitizer (incompatible with ASan) |
| `ENABLE_COVERAGE` | Enable gcov code coverage |
| `ENABLE_FUZZING` | Enable libFuzzer harnesses (requires Clang) |
| `ENABLE_IO_URING` | Enable io_uring async I/O backend (Linux 5.1+, requires liburing) |
| `ENABLE_HTTP_COMPRESSION` | Enable gzip/deflate/brotli for HTTP |
| `BUILD_EXAMPLES` | Build example programs |

## Architecture Overview

This is a high-performance C socket library for POSIX systems with two API styles:
1. **Exception-based API** - Uses `TRY/EXCEPT/FINALLY` blocks for clean error propagation
2. **Simple API** - Return-code based convenience layer (no exceptions needed)

### Module Organization

```
include/
├── core/       # Foundation: Arena (memory), Except (exceptions), utilities
├── socket/     # TCP/UDP/Unix sockets, buffers, async I/O, reconnection
├── dns/        # Async DNS resolver (RFC 1035), DoT (RFC 7858), DoH (RFC 8484), DNSSEC (RFC 4033-4035)
├── poll/       # Event polling (epoll/kqueue/poll backends)
├── pool/       # Connection pooling with rate limiting
├── tls/        # TLS/DTLS support (OpenSSL/LibreSSL)
├── http/       # HTTP/1.1, HTTP/2, HPACK, client/server APIs
├── simple/     # Return-code based convenience API (no TRY/EXCEPT)
└── test/       # Test framework

src/
├── core/       # Arena, Except, timers, rate limiting, crypto, UTF-8
├── socket/     # Socket ops, WebSocket (RFC 6455), proxy (SOCKS4/5, HTTP CONNECT)
├── dns/        # Wire format, transport (UDP/TCP/DoT/DoH), cache, resolver, DNSSEC, cookies
├── poll/       # Platform backends (SocketPoll_epoll.c, SocketPoll_kqueue.c)
├── pool/       # Connection pool, drain state machine
├── tls/        # TLS context, kTLS, DTLS, certificate pinning
├── http/       # HTTP parsing, HPACK codec, HTTP/2 framing
├── simple/     # Simple API implementation wrapping core modules
├── test/       # Test files (test_*.c)
└── fuzz/       # Fuzzing harnesses (fuzz_*.c)
```

### Key Design Patterns

**Exception-Based Error Handling** - Variables modified in TRY blocks must be `volatile`:
```c
volatile int result = 0;
TRY {
    Socket_connect(socket, host, port);
    result = 1;
} EXCEPT(Socket_Failed) {
    fprintf(stderr, "Error: %s\n", Socket_GetLastError());
} FINALLY {
    // Cleanup (always executed, even on RERAISE)
} END_TRY;
```

**Simple API Alternative** - Return codes instead of exceptions:
```c
SocketSimple_Socket_T sock = Socket_simple_connect("example.com", 80);
if (!sock) {
    fprintf(stderr, "Error: %s\n", Socket_simple_error());
    return -1;
}
```

**Arena Memory Management** - Related objects share an arena for lifecycle management:
```c
Arena_T arena = Arena_new();
SocketPool_T pool = SocketPool_new(arena, maxconns, bufsize);
// Arena_dispose frees everything
```

**Opaque Types with T Macro Pattern**:
```c
#define T Socket_T
typedef struct T *T;
```

### Naming Conventions

| Type | Convention | Example |
|------|------------|---------|
| Types | `ModuleName_T` | `Socket_T`, `Arena_T` |
| Public functions | `Module_Verb` | `Socket_bind`, `Arena_alloc` |
| Private functions | `lower_snake_case` | `socket_hash` |
| Constants | `MODULE_NAME` | `SOCKET_MAX_SIZE` |
| Exceptions | `Module_ErrorType` | `Socket_Failed` |

### Platform Backends

The poll backend is auto-selected at build time:
- **Linux**: epoll (`src/poll/SocketPoll_epoll.c`)
- **Linux (optional)**: io_uring for async I/O (`-DENABLE_IO_URING=ON`, requires kernel 5.1+)
- **BSD/macOS**: kqueue (`src/poll/SocketPoll_kqueue.c`)
- **Fallback**: poll(2) (`src/poll/SocketPoll_poll.c`)

### Key Module Dependencies

```
Foundation (Arena, Except)
    └── Core I/O (Socket, SocketBuf, SocketDNS)
        └── Event System (SocketPoll, SocketTimer)
            └── Connection Mgmt (SocketPool, SocketReconnect)

Security (SocketTLS, SocketSYNProtect) requires Foundation + Core I/O
HTTP modules require Foundation + Core I/O + Security (optional)
```

## Code Style

- **C11 with GNU extensions** (`-D_GNU_SOURCE`)
- Compile with `-Wall -Wextra -Werror` (some warnings selectively disabled in CMakeLists.txt)
- Return type on separate line from function name
- Use `do { } while(0)` for multi-statement macros
- Include guards use `_INCLUDED` suffix: `#ifndef SOCKET_INCLUDED`
- Doxygen-style comments for public APIs

## C Anti-Patterns and Fixes

This section documents common code smells and their fixes. Follow these patterns to maintain code quality.

### Magic Numbers

**Anti-pattern:**
```c
if (status == 3) {
    buffer = Arena_alloc(arena, 1024);
    for (int i = 0; i < 86400; i++) { /* ... */ }
}
```

**Fix:** Use named constants or enums:
```c
#define SOCKET_BUFFER_SIZE 1024
#define SECONDS_PER_DAY    86400

typedef enum {
    STATUS_PENDING  = 1,
    STATUS_ACTIVE   = 2,
    STATUS_COMPLETE = 3
} Status;

if (status == STATUS_COMPLETE) {
    buffer = Arena_alloc(arena, SOCKET_BUFFER_SIZE);
    for (int i = 0; i < SECONDS_PER_DAY; i++) { /* ... */ }
}
```

### Deep Nesting (Arrow Code)

**Anti-pattern:**
```c
int
Socket_process(Socket_T sock, const char *path)
{
    if (sock != NULL) {
        char *buffer = Arena_alloc(sock->arena, 1024);
        if (buffer != NULL) {
            if (Socket_read(sock, buffer, 1024) > 0) {
                if (validate(buffer)) {
                    /* actual logic buried here */
                }
            }
        }
    }
    return -1;
}
```

**Fix:** Use early returns (guard clauses):
```c
int
Socket_process(Socket_T sock, const char *path)
{
    if (sock == NULL) return -1;

    char *buffer = Arena_alloc(sock->arena, 1024);
    if (buffer == NULL) return -1;

    if (Socket_read(sock, buffer, 1024) <= 0) return -1;
    if (!validate(buffer)) return -1;

    /* actual logic at normal indentation */
    return do_work(buffer);
}
```

### Ignoring Return Values

**Anti-pattern:**
```c
void
read_config(Arena_T arena)
{
    FILE *f = fopen("config.txt", "r");
    char *buf = Arena_alloc(arena, 256);
    fgets(buf, 256, f);    /* what if fopen failed? */
    fclose(f);
}
```

**Fix:** Always check and handle errors:
```c
int
read_config(Arena_T arena)
{
    FILE *f = fopen("config.txt", "r");
    if (f == NULL) {
        perror("Failed to open config");
        return -1;
    }

    char *buf = Arena_alloc(arena, 256);
    if (buf == NULL) {
        fclose(f);
        return -1;
    }

    if (fgets(buf, 256, f) == NULL) {
        fclose(f);
        return -1;
    }

    /* use buf... */
    fclose(f);
    return 0;
}
```

### Unsafe String Handling

**Anti-pattern:**
```c
void
format_error(char *dest, const char *msg)
{
    sprintf(dest, "Error: %s", msg);
    strcpy(global_error, dest);
}
```

**Fix:** Use size-bounded functions:
```c
void
format_error(char *dest, size_t dest_size, const char *msg)
{
    snprintf(dest, dest_size, "Error: %s", msg);
    strncpy(global_error, dest, sizeof(global_error) - 1);
    global_error[sizeof(global_error) - 1] = '\0';
}
```

### Memory Leaks (Multiple Exit Points)

**Anti-pattern:**
```c
int
process_request(int x)
{
    char *a = malloc(100);
    char *b = malloc(200);

    if (x < 0) return -1;          /* leaks a and b! */

    if (x == 0) {
        free(a);
        return 0;                   /* leaks b! */
    }

    free(a);
    free(b);
    return 1;
}
```

**Fix:** Use single cleanup path with `goto`, or use Arena allocation:
```c
/* Option 1: goto cleanup (for non-arena code) */
int
process_request(int x)
{
    int result = -1;
    char *a = malloc(100);
    char *b = malloc(200);

    if (a == NULL || b == NULL) goto cleanup;
    if (x < 0) goto cleanup;

    if (x == 0) {
        result = 0;
        goto cleanup;
    }

    result = 1;

cleanup:
    free(a);
    free(b);
    return result;
}

/* Option 2: Arena allocation (preferred in this codebase) */
int
process_request(Arena_T arena, int x)
{
    char *a = Arena_alloc(arena, 100);
    char *b = Arena_alloc(arena, 200);

    if (x < 0) return -1;
    if (x == 0) return 0;

    return 1;
    /* Arena_dispose handles all cleanup */
}
```

### Boolean Blindness

**Anti-pattern:**
```c
Socket_configure(sock, true, false, true, false, true);
```

**Fix:** Use enums or flags:
```c
typedef enum {
    SOCKET_OPT_NONBLOCK  = 1 << 0,
    SOCKET_OPT_REUSEADDR = 1 << 1,
    SOCKET_OPT_KEEPALIVE = 1 << 2,
    SOCKET_OPT_NODELAY   = 1 << 3
} SocketOpts;

Socket_configure(sock, SOCKET_OPT_NONBLOCK | SOCKET_OPT_KEEPALIVE | SOCKET_OPT_NODELAY);
```

### Missing `const` Correctness

**Anti-pattern:**
```c
int
count_delimiters(char *str, char delim)
{
    int count = 0;
    while (*str) {
        if (*str == delim) count++;
        str++;
    }
    return count;
}
```

**Fix:** Mark read-only parameters as `const`:
```c
int
count_delimiters(const char *str, char delim)
{
    int count = 0;
    while (*str) {
        if (*str == delim) count++;
        str++;
    }
    return count;
}
```

### Global State Abuse

**Anti-pattern:**
```c
static int current_socket_fd;
static char last_error[256];
static int connection_count;

void
connect_to_server(const char *host)
{
    current_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    connection_count++;
}
```

**Fix:** Use structs and pass explicitly (opaque pointer pattern):
```c
struct Connection {
    int fd;
    char last_error[256];
    Arena_T arena;
};

typedef struct Connection *Connection_T;

Connection_T
Connection_new(Arena_T arena)
{
    Connection_T conn = Arena_alloc(arena, sizeof(*conn));
    conn->arena = arena;
    conn->fd = -1;
    conn->last_error[0] = '\0';
    return conn;
}

int
Connection_connect(Connection_T conn, const char *host, int port)
{
    conn->fd = socket(AF_INET, SOCK_STREAM, 0);
    /* ... */
}
```

### God Functions

**Anti-pattern:**
```c
void
handle_http_request(Request *req)
{
    /* 50 lines of validation... */
    /* 80 lines of parsing... */
    /* 100 lines of business logic... */
    /* 40 lines of formatting response... */
    /* 30 lines of logging... */
}
```

**Fix:** Break into smaller, focused functions:
```c
static bool validate_request(const Request *req);
static ParsedData *parse_request(Arena_T arena, const Request *req);
static Result *process_data(Arena_T arena, const ParsedData *data);
static Response *format_response(Arena_T arena, const Result *result);
static void log_request(const Request *req, const Response *resp);

void
handle_http_request(Arena_T arena, Request *req)
{
    if (!validate_request(req)) return;

    ParsedData *data = parse_request(arena, req);
    Result *result = process_data(arena, data);
    Response *resp = format_response(arena, result);
    log_request(req, resp);
}
```

### Exception Safety Violations

**Anti-pattern:**
```c
int result = 0;  /* NOT volatile! */
TRY {
    Socket_connect(socket, host, port);
    result = 1;  /* may be optimized out after longjmp */
} EXCEPT(Socket_Failed) {
    fprintf(stderr, "Failed, result=%d\n", result);  /* undefined! */
} END_TRY;
```

**Fix:** Use `volatile` for variables modified in TRY:
```c
volatile int result = 0;
TRY {
    Socket_connect(socket, host, port);
    result = 1;
} EXCEPT(Socket_Failed) {
    fprintf(stderr, "Failed, result=%d\n", result);  /* safe */
} END_TRY;
```

## Dispatch Tables

Dispatch tables replace long `switch`/`if-else` chains with O(1) array lookups. They're faster, more maintainable, and easier to extend.

### Command Dispatch

**Anti-pattern:** Long switch chain:
```c
int
handle_command(Command cmd, Context *ctx)
{
    switch (cmd) {
        case CMD_START:  return cmd_start(ctx);
        case CMD_STOP:   return cmd_stop(ctx);
        case CMD_PAUSE:  return cmd_pause(ctx);
        case CMD_RESUME: return cmd_resume(ctx);
        case CMD_STATUS: return cmd_status(ctx);
        /* ... 20 more cases */
        default: return -1;
    }
}
```

**Fix:** Dispatch table:
```c
typedef enum {
    CMD_START, CMD_STOP, CMD_PAUSE, CMD_RESUME, CMD_STATUS, CMD_COUNT
} Command;

typedef int (*CommandHandler)(Context *ctx);

static int cmd_start(Context *ctx)  { ctx->running = true;  return 0; }
static int cmd_stop(Context *ctx)   { ctx->running = false; return 0; }
static int cmd_pause(Context *ctx)  { ctx->paused = true;   return 0; }
static int cmd_resume(Context *ctx) { ctx->paused = false;  return 0; }
static int cmd_status(Context *ctx) { /* ... */ return 0; }

static const CommandHandler dispatch[CMD_COUNT] = {
    [CMD_START]  = cmd_start,
    [CMD_STOP]   = cmd_stop,
    [CMD_PAUSE]  = cmd_pause,
    [CMD_RESUME] = cmd_resume,
    [CMD_STATUS] = cmd_status,
};

int
handle_command(Command cmd, Context *ctx)
{
    if (cmd < 0 || cmd >= CMD_COUNT) return -1;
    if (dispatch[cmd] == NULL) return -1;
    return dispatch[cmd](ctx);  /* O(1) lookup */
}
```

### String-Based Dispatch

**Anti-pattern:** If-else string comparison:
```c
int
execute(const char *cmd)
{
    if (strcmp(cmd, "help") == 0)    return do_help();
    if (strcmp(cmd, "version") == 0) return do_version();
    if (strcmp(cmd, "list") == 0)    return do_list();
    /* ... 20 more commands */
    return -1;
}
```

**Fix:** Lookup table:
```c
typedef int (*Handler)(void);

typedef struct {
    const char *name;
    Handler     handler;
} CommandEntry;

static const CommandEntry commands[] = {
    { "help",    do_help    },
    { "version", do_version },
    { "list",    do_list    },
    { NULL,      NULL       }  /* sentinel */
};

int
execute(const char *cmd)
{
    for (const CommandEntry *e = commands; e->name != NULL; e++) {
        if (strcmp(cmd, e->name) == 0) {
            return e->handler();
        }
    }
    return -1;
}
```

For large tables, sort and use `bsearch()` for O(log n) lookup.

### State Machine Dispatch

**Anti-pattern:** Nested switch:
```c
void
state_machine(Event e)
{
    switch (current_state) {
        case STATE_IDLE:
            switch (e) {
                case EVENT_START: current_state = STATE_RUNNING; break;
                case EVENT_QUIT:  current_state = STATE_DONE; break;
                default: break;
            }
            break;
        case STATE_RUNNING:
            switch (e) {
                case EVENT_PAUSE: current_state = STATE_PAUSED; break;
                case EVENT_STOP:  current_state = STATE_IDLE; break;
                default: break;
            }
            break;
        /* ... more states */
    }
}
```

**Fix:** 2D dispatch table:
```c
typedef enum { STATE_IDLE, STATE_RUNNING, STATE_PAUSED, STATE_DONE, STATE_COUNT } State;
typedef enum { EVENT_START, EVENT_STOP, EVENT_PAUSE, EVENT_RESUME, EVENT_QUIT, EVENT_COUNT } Event;

typedef State (*TransitionFn)(void);

static State on_start(void)  { return STATE_RUNNING; }
static State on_stop(void)   { return STATE_IDLE; }
static State on_pause(void)  { return STATE_PAUSED; }
static State on_resume(void) { return STATE_RUNNING; }
static State on_quit(void)   { return STATE_DONE; }
static State no_op(void)     { return (State)-1; }  /* no change */

static const TransitionFn transitions[STATE_COUNT][EVENT_COUNT] = {
    /*                  START      STOP     PAUSE     RESUME    QUIT     */
    [STATE_IDLE]    = { on_start,  no_op,   no_op,    no_op,    on_quit  },
    [STATE_RUNNING] = { no_op,     on_stop, on_pause, no_op,    on_quit  },
    [STATE_PAUSED]  = { no_op,     on_stop, no_op,    on_resume, on_quit },
    [STATE_DONE]    = { no_op,     no_op,   no_op,    no_op,    no_op    },
};

static State current_state = STATE_IDLE;

void
handle_event(Event e)
{
    if (e < 0 || e >= EVENT_COUNT) return;

    State new_state = transitions[current_state][e]();
    if (new_state != (State)-1) {
        current_state = new_state;
    }
}
```

### Computed Goto (GCC Extension)

For ultra-hot loops (interpreters, protocol parsers), computed goto avoids dispatch overhead:

```c
void
interpret(uint8_t *bytecode)
{
    static const void *dispatch[] = {
        [OP_NOP]  = &&op_nop,
        [OP_PUSH] = &&op_push,
        [OP_POP]  = &&op_pop,
        [OP_ADD]  = &&op_add,
        [OP_HALT] = &&op_halt,
    };

    #define DISPATCH() goto *dispatch[*ip++]

    uint8_t *ip = bytecode;
    int stack[256], sp = -1;
    DISPATCH();

op_nop:  DISPATCH();
op_push: stack[++sp] = *ip++; DISPATCH();
op_pop:  sp--; DISPATCH();
op_add:  stack[sp-1] += stack[sp]; sp--; DISPATCH();
op_halt: return;

    #undef DISPATCH
}
```

### Dispatch Table Performance

| Aspect | Switch/If-Else | Dispatch Table |
|--------|----------------|----------------|
| Time complexity | O(n) worst case | O(1) |
| Branch prediction | Can thrash | Single indirect call |
| Extensibility | Modify switch | Add to array |
| Testability | Monolithic | Individual handlers |

**Notes:**
- For 2-4 cases, compiler often generates efficient code anyway
- Indirect calls have slight overhead vs inlined code
- Use dispatch tables when you have 5+ cases or need extensibility

## Performance Patterns

### HTTP Header Lookups

When looking up well-known HTTP headers (string literals), use the `_n` variants with `STRLEN_LIT()` to avoid runtime `strlen()` calls:

```c
/* Hot path - use compile-time length */
#define STRLEN_LIT(s) (sizeof(s) - 1)

const char *value = SocketHTTP_Headers_get_n(headers, "Content-Length",
                                              STRLEN_LIT("Content-Length"));

int has_te = SocketHTTP_Headers_has_n(headers, "Transfer-Encoding",
                                       STRLEN_LIT("Transfer-Encoding"));

int is_close = SocketHTTP_Headers_contains_n(headers, "Connection",
                                              STRLEN_LIT("Connection"),
                                              "close", STRLEN_LIT("close"));
```

Available `_n` variants: `get_n`, `get_all_n`, `has_n`, `contains_n`

For dynamic header names (user input), use the standard functions which handle `strlen()` internally.

## Automated Hooks

The project uses Claude Code hooks (`.claude/settings.json`) that run automatically:

| Hook | Trigger | Action |
|------|---------|--------|
| `git-safety-check.sh` | Before `git` commands | Blocks commits to main, force push to main |
| `pre-commit-sanitizer.sh` | Before `git commit` | Runs full test suite with ASan/UBSan |
| `volatile-check.sh` | After C file edits | Warns about exception safety issues |
| `build-check.sh` | After C file edits | Quick syntax check with gcc |

These hooks enforce the git workflow and catch common issues early.

## Testing

All PRs must pass with sanitizers enabled:
```bash
cmake -B build -DENABLE_SANITIZERS=ON
cmake --build build -j$(nproc)
cd build && ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 ctest -j$(nproc) --output-on-failure

# Run a single test by name
cd build && ./test_socket

# Run with verbose output
cd build && ctest -V -R test_socket

# List all available tests
cd build && ctest -N
```

Test files are in `src/test/` and map to modules:
- `test_socket.c` - TCP socket operations
- `test_socketdgram.c` - UDP sockets
- `test_socketpool.c` - Connection pooling
- `test_tls_*.c` - TLS/SSL tests (integration, handshake, pinning, CRL, OCSP, kTLS, etc.)
- `test_dtls_*.c` - DTLS tests (basic, cookie exchange, MTU, integration)
- `test_http*.c` - HTTP/1.1 parser, HTTP/2, HPACK, client, server
- `test_websocket*.c` - WebSocket (RFC 6455), WebSocket-over-HTTP/2
- `test_proxy*.c` - SOCKS4/5, HTTP CONNECT proxy
- `test_dns_*.c` - DNS wire format, cache, transport, resolver, DoT, DoH, DNSSEC, cookies
- `test_except.c` - Exception handling framework
- `test_arena.c` - Memory arena management
- `test_async*.c` - Async I/O and io_uring tests

## Thread Safety

- Socket operations are thread-safe per socket (one thread per socket recommended)
- Error reporting uses thread-local storage (`__thread` / `__declspec(thread)`)
- Shared structures (SocketPoll, SocketPool) are mutex-protected
- DNS callbacks are invoked from worker threads, not main thread
- Exception stack (`Except_stack`) is thread-local - each thread has independent TRY context

## Exception Safety

When writing code with `TRY/EXCEPT/FINALLY`:
- Use `volatile` for variables modified inside TRY that are read after exception
- Use `RETURN` macro (not bare `return`) to properly unwind exception stack
- `FINALLY` always executes, even after `RERAISE`
- Avoid raising exceptions inside `FINALLY` blocks
- Use `RERAISE` to propagate caught exceptions to outer handlers

## DNS Module Features

The DNS module (`include/dns/`, `src/dns/`) provides comprehensive DNS resolution:

### Core Resolution (RFC 1035)
- Async resolver with query multiplexing
- UDP and TCP transport with automatic fallback
- Response caching with TTL support
- `/etc/resolv.conf` parsing

### Encrypted DNS
- **DNS-over-TLS (DoT)** - RFC 7858, RFC 8310 (opportunistic/strict modes)
- **DNS-over-HTTPS (DoH)** - RFC 8484 (POST/GET methods)

### Security Features
- **DNSSEC Validation** - RFC 4033, 4034, 4035 (chain of trust, NSEC/NSEC3)
- **DNS Cookies** - RFC 7873 (spoofing protection via EDNS0 option 10)
- **Extended DNS Errors** - RFC 8914 (25 detailed error codes via EDNS0 option 15)
- **Negative Caching** - RFC 2308 (proper NXDOMAIN/NODATA key tuples)
- **Dead Server Tracking** - RFC 2308 §7.2 (5-minute blacklist for unresponsive servers)

### EDNS0 Support (RFC 6891)
- OPT record validation (§6.1.1)
- Version negotiation and BADVERS handling (§6.1.3)
- UDP payload size fallback (§6.2.5)
- Option parsing framework for extensions

## io_uring Support (Linux 5.1+)

The async I/O module supports io_uring for high-performance networking:

### Build
```bash
cmake -S . -B build -DENABLE_IO_URING=ON
```

### Features
- **SQPOLL mode** - Kernel-side submission thread for reduced syscalls
- **Registered buffers** - Zero-copy I/O with fixed buffer sets
- **Batch submissions** - Amortize submission overhead across multiple ops
- **Poll integration** - Automatic eventfd integration with SocketPoll for timers
- **Graceful fallback** - Transparent degradation on unsupported systems

### Usage Pattern
```c
SocketAsync_T async = SocketAsync_new(arena, 256);
SocketAsync_enable_sqpoll(async);  /* Enable SQPOLL if available */

/* Batch multiple operations */
SocketAsync_send(async, sock1, data1, len1, 0, cb1, ud1);
SocketAsync_send(async, sock2, data2, len2, 0, cb2, ud2);
SocketAsync_submit_batch(async);  /* Submit all at once */
```

## GitHub CLI Workaround

The `gh issue view` command may fail with a GraphQL error about "Projects (classic)" deprecation:
```
GraphQL: Projects (classic) is being deprecated in favor of the new Projects experience
```

**Workaround**: Use `gh issue list --search` instead:
```bash
# Instead of: gh issue view 141 --repo 7etsuo/tetsuo-socket
# Use:
gh issue list --repo 7etsuo/tetsuo-socket --state all --search "141" --limit 5

# Or search by keyword:
gh issue list --repo 7etsuo/tetsuo-socket --state all --search "fuzz" --limit 20
```
