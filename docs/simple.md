# Simple API Reference

The Simple API provides a return-code-based convenience layer over the exception-based socket library. All functions return error codes instead of raising exceptions, making it easier to use for straightforward applications.

## Table of Contents

- [Quick Start](#quick-start)
- [Error Handling](#error-handling)
- [TCP Sockets](#tcp-sockets)
- [UDP Sockets](#udp-sockets)
- [TLS/SSL](#tlsssl)
- [HTTP Client](#http-client)
- [WebSocket](#websocket)
- [DNS Resolution](#dns-resolution)

---

## Quick Start

```c
#include <simple/SocketSimple.h>

int main(void)
{
    // Simple TCP client
    SocketSimple_Socket_T sock = Socket_simple_connect("example.com", 80);
    if (!sock) {
        fprintf(stderr, "Error: %s\n", Socket_simple_error());
        return 1;
    }

    const char *request = "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n";
    Socket_simple_send(sock, request, strlen(request));

    char buf[4096];
    ssize_t n = Socket_simple_recv(sock, buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        printf("%s\n", buf);
    }

    Socket_simple_close(&sock);
    return 0;
}
```

---

## Error Handling

All Simple API functions use return codes instead of exceptions:

| Return Value | Meaning |
|-------------|---------|
| `NULL` | Function returning pointer failed |
| `-1` | Function returning int/ssize_t failed |
| `0` or positive | Success |

### Error Functions

```c
// Get human-readable error message
const char *Socket_simple_error(void);

// Get preserved errno from last error
int Socket_simple_errno(void);

// Get error code for programmatic handling
SocketSimple_ErrorCode Socket_simple_code(void);

// Check if error is retryable (EAGAIN, EINTR, etc.)
int Socket_simple_is_retryable(void);

// Clear error state
void Socket_simple_clear_error(void);
```

### Error Codes

```c
typedef enum {
    SOCKET_SIMPLE_OK = 0,

    // Socket/Network errors
    SOCKET_SIMPLE_ERR_SOCKET,        // General socket failure
    SOCKET_SIMPLE_ERR_CONNECT,       // Connection failed
    SOCKET_SIMPLE_ERR_BIND,          // Bind failed
    SOCKET_SIMPLE_ERR_LISTEN,        // Listen failed
    SOCKET_SIMPLE_ERR_ACCEPT,        // Accept failed
    SOCKET_SIMPLE_ERR_SEND,          // Send failed
    SOCKET_SIMPLE_ERR_RECV,          // Receive failed
    SOCKET_SIMPLE_ERR_CLOSED,        // Connection closed by peer
    SOCKET_SIMPLE_ERR_TIMEOUT,       // Operation timed out

    // DNS errors
    SOCKET_SIMPLE_ERR_DNS,           // DNS resolution failed

    // TLS errors
    SOCKET_SIMPLE_ERR_TLS,           // General TLS error
    SOCKET_SIMPLE_ERR_TLS_HANDSHAKE, // TLS handshake failed
    SOCKET_SIMPLE_ERR_TLS_VERIFY,    // Certificate verification failed

    // HTTP errors
    SOCKET_SIMPLE_ERR_HTTP,          // HTTP protocol error
    SOCKET_SIMPLE_ERR_HTTP_PARSE,    // HTTP response parse error

    // WebSocket errors
    SOCKET_SIMPLE_ERR_WS,            // WebSocket error
    SOCKET_SIMPLE_ERR_WS_PROTOCOL,   // WebSocket protocol violation
    SOCKET_SIMPLE_ERR_WS_CLOSED,     // WebSocket closed

    // Resource errors
    SOCKET_SIMPLE_ERR_MEMORY,        // Memory allocation failed
    SOCKET_SIMPLE_ERR_INVALID_ARG,   // Invalid argument
    SOCKET_SIMPLE_ERR_UNSUPPORTED,   // Feature not supported
    SOCKET_SIMPLE_ERR_IO             // File I/O error
} SocketSimple_ErrorCode;
```

### Error Handling Example

```c
SocketSimple_Socket_T sock = Socket_simple_connect("example.com", 80);
if (!sock) {
    SocketSimple_ErrorCode code = Socket_simple_code();

    switch (code) {
    case SOCKET_SIMPLE_ERR_DNS:
        fprintf(stderr, "DNS resolution failed\n");
        break;
    case SOCKET_SIMPLE_ERR_TIMEOUT:
        fprintf(stderr, "Connection timed out\n");
        break;
    case SOCKET_SIMPLE_ERR_CONNECT:
        if (Socket_simple_is_retryable()) {
            // Can retry
        }
        break;
    default:
        fprintf(stderr, "Error: %s (errno=%d)\n",
                Socket_simple_error(), Socket_simple_errno());
    }
    return 1;
}
```

---

## TCP Sockets

### Client Connection

```c
// Basic connect
SocketSimple_Socket_T Socket_simple_connect(const char *host, int port);

// Connect with timeout
SocketSimple_Socket_T Socket_simple_connect_timeout(const char *host,
                                                      int port,
                                                      int timeout_ms);
```

**Example:**

```c
// Simple connection
SocketSimple_Socket_T sock = Socket_simple_connect("api.example.com", 80);

// With 5 second timeout
SocketSimple_Socket_T sock = Socket_simple_connect_timeout("api.example.com", 80, 5000);
```

### Server Socket

```c
// Create listening socket
SocketSimple_Socket_T Socket_simple_listen(const char *host,
                                            int port,
                                            int backlog);

// Accept connection
SocketSimple_Socket_T Socket_simple_accept(SocketSimple_Socket_T server);

// Accept with timeout
SocketSimple_Socket_T Socket_simple_accept_timeout(SocketSimple_Socket_T server,
                                                     int timeout_ms);
```

**Example:**

```c
// Create server
SocketSimple_Socket_T server = Socket_simple_listen(NULL, 8080, 128);
if (!server) {
    fprintf(stderr, "Failed to listen: %s\n", Socket_simple_error());
    return 1;
}

printf("Server listening on port 8080\n");

while (1) {
    SocketSimple_Socket_T client = Socket_simple_accept(server);
    if (client) {
        // Handle client...
        Socket_simple_close(&client);
    }
}

Socket_simple_close(&server);
```

### I/O Operations

```c
// Send all data (loops until complete)
int Socket_simple_send(SocketSimple_Socket_T sock, const void *data, size_t len);

// Receive up to len bytes
ssize_t Socket_simple_recv(SocketSimple_Socket_T sock, void *buf, size_t len);

// Receive with timeout
ssize_t Socket_simple_recv_timeout(SocketSimple_Socket_T sock,
                                    void *buf, size_t len, int timeout_ms);

// Receive exactly len bytes (blocks until complete)
int Socket_simple_recv_all(SocketSimple_Socket_T sock, void *buf, size_t len);

// Receive a line (up to newline)
ssize_t Socket_simple_recv_line(SocketSimple_Socket_T sock, char *buf, size_t maxlen);
```

### Socket Options

```c
// Set send/receive timeouts
int Socket_simple_set_timeout(SocketSimple_Socket_T sock,
                               int send_ms, int recv_ms);

// Get file descriptor (for poll/select)
int Socket_simple_fd(SocketSimple_Socket_T sock);

// Check connection status
int Socket_simple_is_connected(SocketSimple_Socket_T sock);
```

### Cleanup

```c
// Close socket (sets pointer to NULL)
void Socket_simple_close(SocketSimple_Socket_T *sock);
```

---

## UDP Sockets

```c
// Create bound UDP socket
SocketSimple_Socket_T Socket_simple_udp_bind(const char *host, int port);

// Create unbound UDP socket
SocketSimple_Socket_T Socket_simple_udp_new(void);

// Send datagram
int Socket_simple_udp_sendto(SocketSimple_Socket_T sock,
                              const void *data, size_t len,
                              const char *host, int port);

// Receive datagram
ssize_t Socket_simple_udp_recvfrom(SocketSimple_Socket_T sock,
                                    void *buf, size_t len,
                                    char *from_host, size_t host_len,
                                    int *from_port);
```

**Example:**

```c
// UDP echo server
SocketSimple_Socket_T udp = Socket_simple_udp_bind("0.0.0.0", 5353);
if (!udp) return 1;

char buf[1024];
char sender[46];
int port;

while (1) {
    ssize_t n = Socket_simple_udp_recvfrom(udp, buf, sizeof(buf),
                                            sender, sizeof(sender), &port);
    if (n > 0) {
        printf("From %s:%d - %.*s\n", sender, port, (int)n, buf);
        Socket_simple_udp_sendto(udp, buf, n, sender, port);
    }
}
```

---

## TLS/SSL

### Quick TLS Connection

```c
// One-liner TLS connect (with certificate verification)
SocketSimple_Socket_T Socket_simple_connect_tls(const char *host, int port);

// TLS connect with options
SocketSimple_Socket_T Socket_simple_connect_tls_ex(const char *host, int port,
                                                     const SocketSimple_TLSOptions *opts);
```

**Example:**

```c
// Simple HTTPS connection
SocketSimple_Socket_T sock = Socket_simple_connect_tls("api.example.com", 443);
if (!sock) {
    fprintf(stderr, "TLS error: %s\n", Socket_simple_error());
    return 1;
}

const char *request = "GET /data HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
Socket_simple_send(sock, request, strlen(request));

char buf[8192];
ssize_t n = Socket_simple_recv(sock, buf, sizeof(buf) - 1);
// ...

Socket_simple_close(&sock);
```

### TLS Options

```c
typedef struct {
    int timeout_ms;          // Connection timeout (0 = default 30s)
    int verify_cert;         // Verify server certificate (default: 1)
    const char *ca_file;     // Custom CA file path (NULL = system default)
    const char *ca_path;     // Custom CA directory
    const char *client_cert; // Client certificate path
    const char *client_key;  // Client private key path
    const char *alpn;        // ALPN protocols, comma-separated
    int min_version;         // Minimum TLS version: 0=default, 12=1.2, 13=1.3
} SocketSimple_TLSOptions;

// Initialize to defaults
void Socket_simple_tls_options_init(SocketSimple_TLSOptions *opts);
```

**Example with options:**

```c
SocketSimple_TLSOptions opts;
Socket_simple_tls_options_init(&opts);
opts.verify_cert = 0;           // Skip certificate verification
opts.timeout_ms = 10000;        // 10 second timeout
opts.client_cert = "client.pem";
opts.client_key = "client.key";

SocketSimple_Socket_T sock = Socket_simple_connect_tls_ex("secure.example.com", 443, &opts);
```

### Upgrading Existing Socket

```c
// Upgrade plain socket to TLS
int Socket_simple_enable_tls(SocketSimple_Socket_T sock, const char *hostname);

// With options
int Socket_simple_enable_tls_ex(SocketSimple_Socket_T sock,
                                 const char *hostname,
                                 const SocketSimple_TLSOptions *opts);
```

### TLS Server

```c
// Create TLS server
SocketSimple_Socket_T Socket_simple_listen_tls(const char *host, int port,
                                                 int backlog,
                                                 const char *cert_file,
                                                 const char *key_file);

// Accept with TLS handshake
SocketSimple_Socket_T Socket_simple_accept_tls(SocketSimple_Socket_T server);
```

### TLS Information

```c
// Check if TLS enabled
int Socket_simple_is_tls(SocketSimple_Socket_T sock);

// Get negotiated ALPN protocol
const char *Socket_simple_get_alpn(SocketSimple_Socket_T sock);

// Get TLS version string (e.g., "TLSv1.3")
const char *Socket_simple_get_tls_version(SocketSimple_Socket_T sock);

// Get peer certificate info
int Socket_simple_get_cert_info(SocketSimple_Socket_T sock, char *buf, size_t len);

// Get certificate common name
int Socket_simple_get_cert_cn(SocketSimple_Socket_T sock, char *buf, size_t len);
```

---

## HTTP Client

### One-Liner Requests

```c
// GET request
int Socket_simple_http_get(const char *url, SocketSimple_HTTPResponse *response);

// GET with custom headers
int Socket_simple_http_get_ex(const char *url, const char **headers,
                               SocketSimple_HTTPResponse *response);

// POST request
int Socket_simple_http_post(const char *url, const char *content_type,
                             const void *body, size_t body_len,
                             SocketSimple_HTTPResponse *response);

// PUT request
int Socket_simple_http_put(const char *url, const char *content_type,
                            const void *body, size_t body_len,
                            SocketSimple_HTTPResponse *response);

// DELETE request
int Socket_simple_http_delete(const char *url, SocketSimple_HTTPResponse *response);
```

### Response Structure

```c
typedef struct {
    int status_code;      // HTTP status code (200, 404, etc.)
    char *body;           // Response body (caller must free)
    size_t body_len;      // Body length
    char *content_type;   // Content-Type header (may be NULL)
    char *location;       // Location header for redirects (may be NULL)
} SocketSimple_HTTPResponse;

// Free response resources
void Socket_simple_http_response_free(SocketSimple_HTTPResponse *response);
```

**Example:**

```c
SocketSimple_HTTPResponse resp;

if (Socket_simple_http_get("https://api.example.com/users", &resp) == 0) {
    printf("Status: %d\n", resp.status_code);
    printf("Content-Type: %s\n", resp.content_type ? resp.content_type : "unknown");
    printf("Body (%zu bytes): %.*s\n", resp.body_len, (int)resp.body_len, resp.body);

    Socket_simple_http_response_free(&resp);
} else {
    fprintf(stderr, "HTTP error: %s\n", Socket_simple_error());
}
```

### JSON Convenience

```c
// GET returning JSON
int Socket_simple_http_get_json(const char *url, char **json_out, size_t *json_len);

// POST with JSON body
int Socket_simple_http_post_json(const char *url, const char *json_body,
                                  char **json_out, size_t *json_len);

// PUT with JSON body
int Socket_simple_http_put_json(const char *url, const char *json_body,
                                 char **json_out, size_t *json_len);
```

Returns HTTP status code on success, -1 on error.

**Example:**

```c
char *json;
size_t len;

int status = Socket_simple_http_get_json("https://api.example.com/users", &json, &len);
if (status == 200) {
    printf("Users: %s\n", json);
    free(json);
} else if (status > 0) {
    printf("HTTP error: %d\n", status);
} else {
    printf("Request failed: %s\n", Socket_simple_error());
}
```

### File Operations

```c
// Download file
int Socket_simple_http_download(const char *url, const char *filepath);

// Upload file (PUT)
int Socket_simple_http_upload(const char *url, const char *filepath,
                               const char *content_type);
```

**Example:**

```c
// Download
if (Socket_simple_http_download("https://example.com/file.zip", "/tmp/file.zip") != 0) {
    fprintf(stderr, "Download failed: %s\n", Socket_simple_error());
}

// Upload
int status = Socket_simple_http_upload("https://api.example.com/upload",
                                        "/tmp/data.json",
                                        "application/json");
printf("Upload status: %d\n", status);
```

### Reusable HTTP Client

For multiple requests, use a client handle for connection pooling:

```c
// Create client
SocketSimple_HTTP_T Socket_simple_http_new(void);
SocketSimple_HTTP_T Socket_simple_http_new_ex(const SocketSimple_HTTPOptions *opts);

// Make requests
int Socket_simple_http_client_get(SocketSimple_HTTP_T client, const char *url,
                                   SocketSimple_HTTPResponse *response);

int Socket_simple_http_client_post(SocketSimple_HTTP_T client, const char *url,
                                    const char *content_type, const void *body,
                                    size_t body_len, SocketSimple_HTTPResponse *response);

// Free client
void Socket_simple_http_free(SocketSimple_HTTP_T *client);
```

### HTTP Options

```c
typedef struct {
    int connect_timeout_ms;  // Connection timeout (0 = default 30s)
    int request_timeout_ms;  // Request timeout (0 = default 60s)
    int max_redirects;       // Max redirects to follow (default 5, 0 = disabled)
    int verify_ssl;          // Verify TLS certificates (default: 1)
    const char *user_agent;  // Custom User-Agent
    const char *proxy_url;   // Proxy URL
    const char *auth_user;   // Basic auth username
    const char *auth_pass;   // Basic auth password
    const char *bearer_token;// Bearer token
} SocketSimple_HTTPOptions;

void Socket_simple_http_options_init(SocketSimple_HTTPOptions *opts);
```

---

## WebSocket

### Connection

```c
// Connect (handles ws:// and wss://)
SocketSimple_WS_T Socket_simple_ws_connect(const char *url);

// Connect with options
SocketSimple_WS_T Socket_simple_ws_connect_ex(const char *url,
                                                const SocketSimple_WSOptions *opts);
```

### WebSocket Options

```c
typedef struct {
    int connect_timeout_ms;   // Connection timeout (0 = default 30s)
    int ping_interval_ms;     // Auto-ping interval (0 = disabled)
    const char *subprotocols; // Subprotocols, comma-separated
    const char *origin;       // Origin header
    const char **headers;     // Extra headers, NULL-terminated
} SocketSimple_WSOptions;

void Socket_simple_ws_options_init(SocketSimple_WSOptions *opts);
```

### Sending Messages

```c
// Send text (UTF-8)
int Socket_simple_ws_send_text(SocketSimple_WS_T ws, const char *text, size_t len);

// Send binary data
int Socket_simple_ws_send_binary(SocketSimple_WS_T ws, const void *data, size_t len);

// Send JSON (as text)
int Socket_simple_ws_send_json(SocketSimple_WS_T ws, const char *json);

// Send ping
int Socket_simple_ws_ping(SocketSimple_WS_T ws);
```

### Receiving Messages

```c
typedef enum {
    SOCKET_SIMPLE_WS_TEXT = 1,
    SOCKET_SIMPLE_WS_BINARY = 2,
    SOCKET_SIMPLE_WS_PING = 9,
    SOCKET_SIMPLE_WS_PONG = 10,
    SOCKET_SIMPLE_WS_CLOSE = 8
} SocketSimple_WSMessageType;

typedef struct {
    SocketSimple_WSMessageType type;
    void *data;            // Caller must free
    size_t len;
    int close_code;        // For CLOSE type
    char *close_reason;    // For CLOSE type (caller frees)
} SocketSimple_WSMessage;

// Receive (blocking)
int Socket_simple_ws_recv(SocketSimple_WS_T ws, SocketSimple_WSMessage *msg);

// Receive with timeout (returns 1 on timeout)
int Socket_simple_ws_recv_timeout(SocketSimple_WS_T ws, SocketSimple_WSMessage *msg,
                                   int timeout_ms);

// Free message data
void Socket_simple_ws_message_free(SocketSimple_WSMessage *msg);
```

### Closing

```c
// Graceful close
int Socket_simple_ws_close(SocketSimple_WS_T ws, int code, const char *reason);

// Free resources
void Socket_simple_ws_free(SocketSimple_WS_T *ws);
```

### Status

```c
// Check if open
int Socket_simple_ws_is_open(SocketSimple_WS_T ws);

// Get selected subprotocol
const char *Socket_simple_ws_protocol(SocketSimple_WS_T ws);

// Get file descriptor (for poll/select)
int Socket_simple_ws_fd(SocketSimple_WS_T ws);
```

**Complete Example:**

```c
#include <simple/SocketSimple.h>

int main(void)
{
    SocketSimple_WS_T ws = Socket_simple_ws_connect("wss://echo.websocket.org");
    if (!ws) {
        fprintf(stderr, "Error: %s\n", Socket_simple_error());
        return 1;
    }

    // Send message
    Socket_simple_ws_send_text(ws, "Hello WebSocket!", 16);

    // Receive response
    SocketSimple_WSMessage msg;
    if (Socket_simple_ws_recv(ws, &msg) == 0) {
        switch (msg.type) {
        case SOCKET_SIMPLE_WS_TEXT:
            printf("Received text: %.*s\n", (int)msg.len, (char *)msg.data);
            break;
        case SOCKET_SIMPLE_WS_BINARY:
            printf("Received %zu bytes binary\n", msg.len);
            break;
        case SOCKET_SIMPLE_WS_CLOSE:
            printf("Closed: %d %s\n", msg.close_code,
                   msg.close_reason ? msg.close_reason : "");
            break;
        default:
            break;
        }
        Socket_simple_ws_message_free(&msg);
    }

    // Graceful close
    Socket_simple_ws_close(ws, 1000, "Goodbye");
    Socket_simple_ws_free(&ws);

    return 0;
}
```

---

## DNS Resolution

```c
typedef struct {
    char **addresses;  // NULL-terminated array (caller must free)
    int count;         // Number of addresses
    int family;        // AF_INET or AF_INET6
} SocketSimple_DNSResult;

// Resolve hostname to all addresses
int Socket_simple_dns_resolve(const char *hostname, SocketSimple_DNSResult *result);

// Resolve with timeout
int Socket_simple_dns_resolve_timeout(const char *hostname,
                                        SocketSimple_DNSResult *result,
                                        int timeout_ms);

// Get single IP (any family)
int Socket_simple_dns_lookup(const char *hostname, char *buf, size_t len);

// Get single IPv4
int Socket_simple_dns_lookup4(const char *hostname, char *buf, size_t len);

// Get single IPv6
int Socket_simple_dns_lookup6(const char *hostname, char *buf, size_t len);

// Reverse lookup
int Socket_simple_dns_reverse(const char *ip, char *hostname, size_t len);

// Free result
void Socket_simple_dns_result_free(SocketSimple_DNSResult *result);
```

**Example:**

```c
// Simple lookup
char ip[46];
if (Socket_simple_dns_lookup("example.com", ip, sizeof(ip)) == 0) {
    printf("IP: %s\n", ip);
}

// Get all addresses
SocketSimple_DNSResult result;
if (Socket_simple_dns_resolve("google.com", &result) == 0) {
    printf("Found %d addresses:\n", result.count);
    for (int i = 0; i < result.count; i++) {
        printf("  %s\n", result.addresses[i]);
    }
    Socket_simple_dns_result_free(&result);
}
```

---

## Comparison: Simple API vs Full API

| Task | Simple API | Full API |
|------|-----------|----------|
| TCP Connect | `Socket_simple_connect(host, port)` | `Socket_new() + TRY { Socket_connect() } EXCEPT...` |
| TLS Connect | `Socket_simple_connect_tls(host, port)` | `Socket_new() + SocketTLSContext_new_client() + TRY { SocketTLS_enable() + SocketTLS_handshake_auto() } EXCEPT...` |
| HTTP GET | `Socket_simple_http_get(url, &resp)` | `SocketHTTPClient_new() + TRY { SocketHTTPClient_get() } EXCEPT...` |
| Error check | `if (!sock) { Socket_simple_error() }` | `EXCEPT(Socket_Failed) { Socket_GetLastError() }` |

**When to use Simple API:**
- Quick scripts and prototypes
- Applications preferring return codes
- Simple client applications
- Learning the library

**When to use Full API:**
- High-performance servers
- Complex error recovery
- Async/non-blocking I/O
- Connection pooling
- Advanced TLS configuration
