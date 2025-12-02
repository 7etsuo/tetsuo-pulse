# WebSocket Guide {#websocket_guide}

Complete guide to WebSocket protocol (RFC 6455) support in the Socket Library.

---

## Overview

The `SocketWS_T` module provides full RFC 6455 WebSocket support with:
- Client and server modes
- Text and binary messages
- Fragmented message reassembly
- UTF-8 validation for text frames
- permessage-deflate compression (RFC 7692)
- Automatic ping/pong keepalive
- Non-blocking I/O support

---

## Quick Start

### WebSocket Client

```c
#include "socket/Socket.h"
#include "socket/SocketWS.h"

/* Connect TCP socket */
Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
Socket_connect(sock, "echo.websocket.org", 80);

/* Create WebSocket client */
SocketWS_Config config;
SocketWS_config_defaults(&config);

SocketWS_T ws = SocketWS_client_new(sock, "echo.websocket.org", "/", &config);

/* Perform handshake */
while (SocketWS_handshake(ws) > 0) { /* wait */ }

/* Send and receive messages */
SocketWS_send_text(ws, "Hello, WebSocket!", 17);

SocketWS_Message msg;
if (SocketWS_recv_message(ws, &msg) > 0) {
    printf("Received: %.*s\n", (int)msg.len, (char*)msg.data);
    free(msg.data);
}

/* Clean close */
SocketWS_close(ws, WS_CLOSE_NORMAL, "Goodbye");
SocketWS_free(&ws);
Socket_free(&sock);
```

---

## Client API

### Creating a Client Connection

```c
/* Create TCP socket and connect */
Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
Socket_connect(sock, host, port);

/* For wss:// (secure WebSocket), enable TLS first */
#ifdef SOCKET_HAS_TLS
SocketTLSContext_T tls_ctx = SocketTLSContext_new_client(NULL);
SocketTLS_enable(sock, tls_ctx);
SocketTLS_set_hostname(sock, host);
while (SocketTLS_handshake(sock) > 0) { /* wait */ }
#endif

/* Configure WebSocket */
SocketWS_Config config;
SocketWS_config_defaults(&config);
config.role = WS_ROLE_CLIENT;           /* Client mode */
config.validate_utf8 = 1;               /* Validate text frames */
config.ping_interval_ms = 30000;        /* Auto-ping every 30s */

/* Create WebSocket */
SocketWS_T ws = SocketWS_client_new(sock, host, path, &config);
```

### Configuration Options

```c
typedef struct {
    SocketWS_Role role;              /* WS_ROLE_CLIENT or WS_ROLE_SERVER */
    
    /* Limits */
    size_t max_frame_size;           /* Max frame: 16MB default */
    size_t max_message_size;         /* Max message: 64MB default */
    size_t max_fragments;            /* Max fragments: 1000 default */
    
    /* Validation */
    int validate_utf8;               /* Validate text frames: yes */
    
    /* Compression (RFC 7692) */
    int enable_permessage_deflate;   /* Enable compression: no */
    int deflate_no_context_takeover; /* Don't reuse context */
    int deflate_max_window_bits;     /* LZ77 window: 15 */
    
    /* Subprotocols */
    const char **subprotocols;       /* NULL-terminated list */
    
    /* Keepalive */
    int ping_interval_ms;            /* Auto-ping interval: 0 (disabled) */
    int ping_timeout_ms;             /* Pong timeout */
} SocketWS_Config;
```

### Performing the Handshake

The handshake sends the HTTP upgrade request (client) or response (server):

```c
/* Blocking socket - completes immediately */
while (SocketWS_handshake(ws) > 0) {
    /* Returns 1 if in progress, 0 on complete, -1 on error */
}

/* Check state */
if (SocketWS_state(ws) == WS_STATE_OPEN) {
    /* Ready for messages */
}
```

---

## Server API

### Accepting WebSocket Connections

When integrated with HTTP server:

```c
/* In HTTP request handler */
void handler(SocketHTTPServer_Request_T req, void *userdata) {
    if (SocketHTTPServer_Request_is_websocket(req)) {
        /* Accept the upgrade */
        SocketWS_T ws = SocketHTTPServer_Request_upgrade_websocket(req);
        
        if (ws) {
            /* Complete server handshake */
            while (SocketWS_handshake(ws) > 0) { }
            
            if (SocketWS_state(ws) == WS_STATE_OPEN) {
                /* Handle WebSocket connection */
            }
        }
        return;  /* Don't call finish after upgrade */
    }
}
```

### Manual Server Setup

For custom server implementations:

```c
/* After receiving HTTP upgrade request */
SocketWS_Config config;
SocketWS_config_defaults(&config);
config.role = WS_ROLE_SERVER;

/* Check if valid upgrade request */
if (SocketWS_is_upgrade(&http_request)) {
    SocketWS_T ws = SocketWS_server_accept(socket, &http_request, &config);
    
    /* Send 101 response */
    while (SocketWS_handshake(ws) > 0) { }
}
```

---

## Sending Messages

### Text Messages

Text messages are UTF-8 encoded:

```c
const char *message = "Hello, World!";
if (SocketWS_send_text(ws, message, strlen(message)) < 0) {
    /* Handle error */
    SocketWS_Error err = SocketWS_last_error(ws);
    printf("Error: %s\n", SocketWS_error_string(err));
}
```

### Binary Messages

Binary messages can contain any data:

```c
unsigned char data[] = {0x01, 0x02, 0x03, 0x04};
SocketWS_send_binary(ws, data, sizeof(data));
```

### Control Frames

```c
/* Ping with optional payload (max 125 bytes) */
SocketWS_ping(ws, "heartbeat", 9);

/* Unsolicited pong */
SocketWS_pong(ws, NULL, 0);

/* Close connection */
SocketWS_close(ws, WS_CLOSE_NORMAL, "Done");
```

---

## Receiving Messages

### Complete Messages

The simplest way to receive complete, reassembled messages:

```c
SocketWS_Message msg;

int result = SocketWS_recv_message(ws, &msg);

if (result > 0) {
    /* Message received */
    if (msg.type == WS_OPCODE_TEXT) {
        printf("Text: %.*s\n", (int)msg.len, (char*)msg.data);
    } else {
        printf("Binary: %zu bytes\n", msg.len);
    }
    
    /* IMPORTANT: Caller must free message data */
    free(msg.data);
}
else if (result == 0) {
    /* Connection closed */
    printf("Closed: %d - %s\n", 
           SocketWS_close_code(ws),
           SocketWS_close_reason(ws));
}
else {
    /* Error */
    printf("Error: %s\n", 
           SocketWS_error_string(SocketWS_last_error(ws)));
}
```

### Message Structure

```c
typedef struct {
    SocketWS_Opcode type;    /* WS_OPCODE_TEXT or WS_OPCODE_BINARY */
    unsigned char *data;     /* Message data (caller must free) */
    size_t len;              /* Message length */
} SocketWS_Message;
```

---

## Connection States

```c
typedef enum {
    WS_STATE_CONNECTING,  /* Handshake in progress */
    WS_STATE_OPEN,        /* Ready for messages */
    WS_STATE_CLOSING,     /* Close handshake in progress */
    WS_STATE_CLOSED       /* Connection terminated */
} SocketWS_State;

/* Check current state */
SocketWS_State state = SocketWS_state(ws);
```

---

## Close Codes

RFC 6455 defines status codes for close frames:

| Code | Constant | Description |
|------|----------|-------------|
| 1000 | `WS_CLOSE_NORMAL` | Normal closure |
| 1001 | `WS_CLOSE_GOING_AWAY` | Endpoint going away |
| 1002 | `WS_CLOSE_PROTOCOL_ERROR` | Protocol error |
| 1003 | `WS_CLOSE_UNSUPPORTED_DATA` | Unsupported data |
| 1007 | `WS_CLOSE_INVALID_PAYLOAD` | Invalid payload (bad UTF-8) |
| 1008 | `WS_CLOSE_POLICY_VIOLATION` | Policy violation |
| 1009 | `WS_CLOSE_MESSAGE_TOO_BIG` | Message too big |
| 1010 | `WS_CLOSE_MANDATORY_EXT` | Missing extension |
| 1011 | `WS_CLOSE_INTERNAL_ERROR` | Internal error |

### Closing a Connection

```c
/* Initiate close handshake */
SocketWS_close(ws, WS_CLOSE_NORMAL, "Goodbye");

/* Wait for close response */
while (SocketWS_state(ws) != WS_STATE_CLOSED) {
    SocketWS_Message msg;
    if (SocketWS_recv_message(ws, &msg) <= 0) {
        break;  /* Connection closed */
    }
    free(msg.data);
}

/* Get peer's close info */
int code = SocketWS_close_code(ws);
const char *reason = SocketWS_close_reason(ws);
```

---

## Event Loop Integration

### Non-Blocking Operation

```c
/* Set socket non-blocking */
Socket_setnonblocking(sock);

/* Get poll information */
int fd = SocketWS_pollfd(ws);
unsigned events = SocketWS_poll_events(ws);

/* Add to poll */
SocketPoll_add(poll, SocketWS_socket(ws), events, ws);

/* In event loop */
while (running) {
    SocketEvent_T events[100];
    int n = SocketPoll_wait(poll, events, 100, 1000);
    
    for (int i = 0; i < n; i++) {
        SocketWS_T ws = events[i].data;
        
        /* Process events */
        if (SocketWS_process(ws, events[i].events) < 0) {
            /* Error or closed */
        }
        
        /* Try to receive */
        SocketWS_Message msg;
        while (SocketWS_recv_available(ws) && 
               SocketWS_recv_message(ws, &msg) > 0) {
            /* Handle message */
            free(msg.data);
        }
    }
}
```

### Auto-Ping

Automatic keepalive can be enabled with SocketPoll integration:

```c
/* Configure ping interval */
config.ping_interval_ms = 30000;  /* 30 seconds */
config.ping_timeout_ms = 5000;    /* 5 second pong timeout */

/* Enable after connection open */
SocketWS_enable_auto_ping(ws, poll);

/* Disable if needed */
SocketWS_disable_auto_ping(ws);
```

---

## Compression (permessage-deflate)

Enable RFC 7692 compression:

```c
config.enable_permessage_deflate = 1;
config.deflate_max_window_bits = 15;  /* Default */
config.deflate_no_context_takeover = 0;  /* Reuse context */
```

Check if compression was negotiated:

```c
if (SocketWS_compression_enabled(ws)) {
    printf("Compression active\n");
}
```

**Note**: Requires zlib at compile time (`SOCKETWS_HAS_DEFLATE`).

---

## Subprotocols

Negotiate application-specific protocols:

```c
/* Client offers subprotocols */
const char *subprotocols[] = {"graphql-ws", "wamp", NULL};
config.subprotocols = subprotocols;

/* After handshake, check what was selected */
const char *selected = SocketWS_selected_subprotocol(ws);
if (selected) {
    printf("Using subprotocol: %s\n", selected);
}
```

---

## Error Handling

### Error Codes

```c
typedef enum {
    WS_OK = 0,
    WS_ERROR,                   /* General error */
    WS_ERROR_HANDSHAKE,         /* Handshake failed */
    WS_ERROR_PROTOCOL,          /* Protocol violation */
    WS_ERROR_FRAME_TOO_LARGE,   /* Frame exceeds limit */
    WS_ERROR_MESSAGE_TOO_LARGE, /* Message exceeds limit */
    WS_ERROR_INVALID_UTF8,      /* Invalid UTF-8 in text */
    WS_ERROR_COMPRESSION,       /* Compression error */
    WS_ERROR_CLOSED,            /* Connection closed */
    WS_ERROR_WOULD_BLOCK,       /* Would block */
    WS_ERROR_TIMEOUT            /* Operation timed out */
} SocketWS_Error;

/* Get last error */
SocketWS_Error err = SocketWS_last_error(ws);
const char *msg = SocketWS_error_string(err);
```

### Exceptions

```c
TRY {
    ws = SocketWS_client_new(sock, host, path, &config);
    while (SocketWS_handshake(ws) > 0) { }
    SocketWS_send_text(ws, message, len);
}
EXCEPT(SocketWS_Failed) {
    /* General WebSocket failure */
}
EXCEPT(SocketWS_ProtocolError) {
    /* Protocol violation detected */
}
EXCEPT(SocketWS_Closed) {
    /* Connection closed unexpectedly */
}
FINALLY {
    if (ws) SocketWS_free(&ws);
    Socket_free(&sock);
}
END_TRY;
```

---

## Best Practices

### Security

1. **Always validate origin** on server side
2. **Use wss://** (TLS) for sensitive data
3. **Set reasonable limits** for frame/message size
4. **Enable UTF-8 validation** for text frames

### Performance

1. **Use binary** for non-text data (no UTF-8 overhead)
2. **Enable compression** for text-heavy protocols
3. **Use non-blocking I/O** for multiple connections
4. **Set appropriate keepalive** intervals

### Connection Management

1. **Handle close properly** - Always perform close handshake
2. **Set ping timeout** - Detect dead connections
3. **Handle reconnection** - Network is unreliable
4. **Monitor state** - Check `SocketWS_state()` before operations

---

## Thread Safety

- `SocketWS_T` instances are **NOT** thread-safe
- Use one WebSocket per thread
- Or protect with external mutex
- Multiple instances can be used from different threads

---

## See Also

- [HTTP Guide](@ref http_guide) - HTTP server integration
- [Security Guide](@ref security_guide) - TLS configuration
- @ref SocketWS.h - API reference

