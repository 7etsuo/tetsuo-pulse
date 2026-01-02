# HTTP Module Structure

This document describes the separation between public-facing code and private/internal implementation in `src/http/`, and guidelines for where helper functions should be placed.

## Directory Structure

```
src/http/
├── Main folder (public API implementations)
│   ├── SocketHTTP-core.c          # Core types, methods, status codes
│   ├── SocketHTTP-date.c          # HTTP date parsing (RFC 9110)
│   ├── SocketHTTP-headers.c       # Header collection with hash table
│   ├── SocketHTTP-uri.c           # URI parsing (RFC 3986)
│   ├── SocketHTTP1-chunked.c      # Chunked transfer encoding
│   ├── SocketHTTP1-compress.c     # Content compression (gzip/deflate/brotli)
│   ├── SocketHTTP1-parser.c       # DFA-based HTTP/1.1 parser
│   ├── SocketHTTP1-serialize.c    # HTTP/1.1 message serialization
│   ├── SocketHTTPClient.c         # HTTP client main implementation
│   └── SocketHTTPServer.c         # HTTP server main implementation
│
├── client/ (client-specific internals)
│   ├── SocketHTTPClient-arena.c   # Thread-local arena caching
│   ├── SocketHTTPClient-async.c   # Async I/O support
│   ├── SocketHTTPClient-auth.c    # Basic/Digest/Bearer authentication
│   ├── SocketHTTPClient-cookie.c  # Cookie jar management
│   ├── SocketHTTPClient-pool.c    # Connection pooling
│   └── SocketHTTPClient-retry.c   # Retry logic
│
├── server/ (server-specific internals)
│   ├── SocketHTTPServer-core.c       # Server lifecycle
│   ├── SocketHTTPServer-connections.c # Connection management
│   ├── SocketHTTPServer-h2.c         # HTTP/2 server handling
│   ├── SocketHTTPServer-http1.c      # HTTP/1.1 server handling
│   ├── SocketHTTPServer-metrics.c    # Metrics tracking
│   └── SocketHTTPServer-static.c     # Static file serving
│
├── h2/ (HTTP/2 protocol internals)
│   ├── SocketHTTP2-connection.c   # Connection state machine
│   ├── SocketHTTP2-flow.c         # Flow control windows
│   ├── SocketHTTP2-frame.c        # Frame parsing/serialization
│   ├── SocketHTTP2-priority.c     # Stream prioritization
│   ├── SocketHTTP2-stream.c       # Stream state machine
│   └── SocketHTTP2-validate.c     # Frame validation rules
│
└── hpack/ (HPACK compression internals)
    ├── SocketHPACK.c              # Main HPACK codec
    ├── SocketHPACK-huffman.c      # Huffman encoding/decoding
    └── SocketHPACK-table.c        # Dynamic table management
```

## Public vs Private Separation

### Principle

| Location | Purpose | Public Header | Private Header |
|----------|---------|---------------|----------------|
| `src/http/*.c` | Public API implementation | `include/http/Socket*.h` | `*-private.h` |
| `src/http/client/` | Client internals | None | `SocketHTTPClient-private.h` |
| `src/http/server/` | Server internals | None | `SocketHTTPServer-private.h` |
| `src/http/h2/` | HTTP/2 internals | None | `SocketHTTP2-private.h` |
| `src/http/hpack/` | HPACK internals | None | `SocketHPACK-private.h` |

### Rules

1. **Main folder files** implement functions declared in **public headers** (`include/http/`)
2. **Subfolder files** implement internal functionality used by the main files
3. **Private headers** (with `-private.h` suffix) define internal structures shared between implementation files
4. **Config headers** (like `SocketHTTPClient-config.h`) contain only `#define` constants, no structures

## Function Placement Guidelines

### Where Functions Should Go

| Function Type | Location | Visibility |
|---------------|----------|------------|
| Public API | Main folder `.c` file | Declared in `include/http/*.h` |
| Single-file helper | Same `.c` file | `static` |
| Subsystem-shared helper | Appropriate subfolder file | `static` or internal linkage |
| Protocol-agnostic utility | Main folder (core, headers, uri, date) | `static` or public if widely needed |

### Decision Tree

```
Is the function part of the public API?
├── YES → Put in main folder .c file, declare in include/http/*.h
└── NO → Is it used by only one .c file?
    ├── YES → Make it static in that file
    └── NO → Is it specific to a subsystem?
        ├── YES → Put in appropriate subfolder
        │   ├── Client-specific → client/
        │   ├── Server-specific → server/
        │   ├── HTTP/2-specific → h2/
        │   └── HPACK-specific → hpack/
        └── NO → Put in protocol-agnostic main folder file
            ├── Type/method handling → SocketHTTP-core.c
            ├── Header operations → SocketHTTP-headers.c
            ├── URI operations → SocketHTTP-uri.c
            └── Date operations → SocketHTTP-date.c
```

## Function Naming Patterns

### Public Functions (main folder)

```c
// Declared in include/http/SocketHTTP.h
SocketHTTP_Headers_add(headers, name, value)
SocketHTTP_URI_parse(uri_str, flags, &uri, arena)
SocketHTTP_method_string(method)

// Declared in include/http/SocketHTTP1.h
SocketHTTP1_Parser_new(type, config, arena)
SocketHTTP1_Parser_execute(parser, data, len, &consumed)

// Declared in include/http/SocketHTTPClient.h
SocketHTTPClient_new(config, arena)
SocketHTTPClient_get(client, url, &response)
```

### Private/Internal Functions (main folder and subfolders)

```c
// Static helpers - lowercase_snake_case
static void httpclient_auth_copy_to_arena(...)
static int connection_setup_body_buffer(...)
static const char *parse_quoted_string(...)

// Internal helpers shared via private header
static SocketHTTP2_ErrorCode validate_data_frame(...)
```

## Include Patterns

### Public API Files

```c
#include "http/SocketHTTP.h"           // Public types
#include "http/SocketHTTP1.h"          // Public HTTP/1.1 API
#include "http/SocketHTTPClient.h"     // Public client API
#include "socket/Socket.h"              // Dependencies
#include "core/Arena.h"                 // Dependencies
```

### Private Implementation Files

```c
#include "http/SocketHTTPClient-private.h"  // Internal structures
#include "http/SocketHTTP-private.h"        // Character tables, helpers
#include "http/SocketHTTPClient-config.h"   // Configuration constants
```

### Subfolder Files

```c
// client/SocketHTTPClient-auth.c
#include "http/SocketHTTPClient-private.h"  // Parent private API
#include "http/SocketHTTP-private.h"        // Core internals

// h2/SocketHTTP2-stream.c
#include "http/SocketHTTP2-private.h"       // HTTP/2 internals
#include "http/SocketHTTP.h"                // Public types
```

## Examples

### Adding a Client Helper

**Scenario**: You need to add a helper for parsing Digest authentication challenges.

**Correct**: Put it in `client/SocketHTTPClient-auth.c`:
```c
// client/SocketHTTPClient-auth.c
static int
parse_digest_challenge(const char *challenge, DigestParams *params)
{
    // Implementation
}
```

### Adding an HTTP/2 Helper

**Scenario**: You need a helper for computing priority weights.

**Correct**: Put it in `h2/SocketHTTP2-priority.c`:
```c
// h2/SocketHTTP2-priority.c
static int
compute_effective_weight(SocketHTTP2_Stream_T stream)
{
    // Implementation
}
```

### Adding a Protocol-Agnostic Helper

**Scenario**: You need a helper for parsing header field names.

**Correct**: Put it in `SocketHTTP-headers.c`:
```c
// SocketHTTP-headers.c
static bool
is_valid_header_name(const char *name, size_t len)
{
    // Implementation
}
```

## Anti-Patterns

### Don't: Put implementation helpers in public headers

```c
// BAD - include/http/SocketHTTP.h
static inline int internal_helper(void) { ... }  // Never do this
```

### Don't: Put subsystem-specific code in wrong files

```c
// BAD - SocketHTTP-core.c contains HTTP/2 stream logic
static void handle_h2_stream_state(...) { ... }  // Should be in h2/

// BAD - client/SocketHTTPClient-pool.c contains server code
static void server_connection_cleanup(...) { ... }  // Should be in server/
```

### Don't: Put shared helpers only in one subsystem file

```c
// BAD - client/SocketHTTPClient-auth.c has a general URL parser
static int parse_url_general(...) { ... }  // Should be in SocketHTTP-uri.c
```

## File Category Summary

| Category | Files | Purpose |
|----------|-------|---------|
| **Protocol Core** | `SocketHTTP-*.c` | Types, headers, URI, dates |
| **HTTP/1.1** | `SocketHTTP1-*.c` | Parser, serializer, chunked, compress |
| **HTTP/2** | `h2/SocketHTTP2-*.c` | Frames, streams, flow, priority |
| **HPACK** | `hpack/SocketHPACK*.c` | Codec, Huffman, dynamic table |
| **Client** | `SocketHTTPClient.c` + `client/` | Client API + internals |
| **Server** | `SocketHTTPServer.c` + `server/` | Server API + internals |
