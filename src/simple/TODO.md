# Simple API Implementation Plan

## Phase 0: Restructure into Sub-files

Split implementation into modules, keep SocketSimple.c as thin wrappers:

```
src/simple/
  SocketSimple.c          # Thin wrappers + error state (stays small)
  SocketSimple-internal.h # Shared internals (error helpers, handle struct)
  SocketSimple-tcp.c      # TCP/UDP implementation
  SocketSimple-tls.c      # TLS implementation
  SocketSimple-dns.c      # DNS implementation
  SocketSimple-http.c     # HTTP implementation
  SocketSimple-ws.c       # WebSocket implementation
```

Update CMakeLists.txt to compile all .c files.

## Phase 1: UDP (SocketDgram)
- Implement in SocketSimple-tcp.c
- Replace stubbed sendto/recvfrom with SocketDgram wrappers

## Phase 2: DNS (SocketDNS)
- Create SocketSimple-dns.c
- Replace raw getaddrinfo() with SocketDNS module
- Implement async DNS with timeout

## Phase 3: TLS Server
- Add to SocketSimple-tls.c
- Implement listen_tls/accept_tls

## Phase 4: HTTP (SocketHTTPClient)
- Create SocketSimple-http.c
- Wrap SocketHTTPClient for all methods
- URL parsing, response population

## Phase 5: WebSocket (SocketWS)
- Create SocketSimple-ws.c
- Wrap SocketWS connect/send/recv/close

---

**Current Status:** TCP client/server and TLS client work. Everything else stubbed.
