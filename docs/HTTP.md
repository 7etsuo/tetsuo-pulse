# HTTP Guide {#http_guide}
**Brief**: Complete HTTP/1.1 and HTTP/2 client/server implementation | **Tags**: `http`, `http1`, `http2`, `client`, `server`, `parsing`

Complete guide to HTTP/1.1 and HTTP/2 support in the Socket Library.

**Module Group**: HTTP | **Related Modules**: SocketHTTP, SocketHTTP1, SocketHTTP2, SocketHTTPClient, SocketHTTPServer

For server-side HTTP/2 wiring details (ALPN vs h2c vs prior-knowledge, stream lifecycle,
trailers, GOAWAY/drain, RFC 8441 status), see `docs/HTTP2-SERVER.md`.

---

## Quick Start

### Simple HTTP GET

```c
#include "http/SocketHTTPClient.h"

SocketHTTPClient_T client = SocketHTTPClient_new(NULL);
SocketHTTPClient_Response response = {0};

if (SocketHTTPClient_get(client, "https://example.com", &response) == 0) {
    printf("Status: %d\n", response.status_code);
    printf("Body: %.*s\n", (int)response.body_len, (char*)response.body);
}

SocketHTTPClient_Response_free(&response);
SocketHTTPClient_free(&client);
```

### Simple HTTP POST

```c
const char *json = "{\"name\": \"value\"}";

if (SocketHTTPClient_post(client, "https://api.example.com/data",
                          "application/json", json, strlen(json),
                          &response) == 0) {
    printf("Status: %d\n", response.status_code);
}
```

---

## HTTP Client API

The `SocketHTTPClient_T` provides a high-level HTTP client with automatic:
- Protocol negotiation (HTTP/1.1 and HTTP/2)
- Connection pooling
- Cookie handling
- Redirect following
- Compression (gzip/deflate/brotli)

### Creating a Client

```c
/* With default configuration */
SocketHTTPClient_T client = SocketHTTPClient_new(NULL);

/* With custom configuration */
SocketHTTPClient_Config config;
SocketHTTPClient_config_defaults(&config);

config.max_version = HTTP_VERSION_2;          /* Prefer HTTP/2 */
config.follow_redirects = 5;                   /* Max 5 redirects */
config.connect_timeout_ms = 10000;             /* 10 second timeout */
config.enable_connection_pool = 1;             /* Enable pooling */
config.max_connections_per_host = 6;           /* HTTP/1.1 default */

SocketHTTPClient_T client = SocketHTTPClient_new(&config);
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `max_version` | `HTTP_VERSION_2` | Maximum HTTP version to use |
| `enable_connection_pool` | `1` | Enable connection reuse |
| `max_connections_per_host` | `6` | Per-host connection limit |
| `max_total_connections` | `100` | Total connection limit |
| `connect_timeout_ms` | `30000` | Connection timeout |
| `request_timeout_ms` | `60000` | Request timeout |
| `follow_redirects` | `10` | Max redirects (0 = disabled) |
| `accept_encoding` | All | Accepted compression methods |
| `auto_decompress` | `1` | Auto-decompress responses |
| `verify_ssl` | `1` | Verify TLS certificates |

### Simple API

The simple API covers common use cases:

```c
/* GET request */
int SocketHTTPClient_get(client, url, &response);

/* HEAD request */
int SocketHTTPClient_head(client, url, &response);

/* POST request */
int SocketHTTPClient_post(client, url, content_type, body, body_len, &response);

/* PUT request */
int SocketHTTPClient_put(client, url, content_type, body, body_len, &response);

/* DELETE request */
int SocketHTTPClient_delete(client, url, &response);
```

### Request Builder API

For more control, use the request builder:

```c
SocketHTTPClient_Request_T req = SocketHTTPClient_Request_new(
    client, HTTP_METHOD_POST, "https://api.example.com/upload");

/* Add headers */
SocketHTTPClient_Request_header(req, "Content-Type", "application/json");
SocketHTTPClient_Request_header(req, "Authorization", "Bearer token123");
SocketHTTPClient_Request_header(req, "X-Custom-Header", "value");

/* Set body */
const char *body = "{\"data\": \"test\"}";
SocketHTTPClient_Request_body(req, body, strlen(body));

/* Set timeout */
SocketHTTPClient_Request_timeout(req, 5000);  /* 5 seconds */

/* Execute */
SocketHTTPClient_Response response;
if (SocketHTTPClient_Request_execute(req, &response) == 0) {
    /* Handle response */
}

SocketHTTPClient_Request_free(&req);
SocketHTTPClient_Response_free(&response);
```

### Response Handling

```c
typedef struct {
    int status_code;              /* HTTP status code (200, 404, etc.) */
    SocketHTTP_Headers_T headers; /* Response headers */
    void *body;                   /* Response body */
    size_t body_len;              /* Body length */
    SocketHTTP_Version version;   /* Protocol version used */
    Arena_T arena;                /* Internal - for cleanup */
} SocketHTTPClient_Response;

/* Access headers */
const char *content_type = SocketHTTP_Headers_get(response.headers, "Content-Type");

/* Always free response when done */
SocketHTTPClient_Response_free(&response);
```

---

## Authentication

The client supports three authentication schemes. All authentication is handled
automatically - the client will retry requests when receiving 401 responses.

### Supported Authentication Types

| Type | RFC | Description | Use Case |
|------|-----|-------------|----------|
| `HTTP_AUTH_BASIC` | RFC 7617 | Base64 encoded credentials | Simple APIs |
| `HTTP_AUTH_DIGEST` | RFC 7616 | Challenge-response with hash | Legacy systems |
| `HTTP_AUTH_BEARER` | RFC 6750 | Token-based (OAuth 2.0) | Modern APIs |

**Not Supported:**
- NTLM (Microsoft proprietary, requires DES/MD4)
- Negotiate/SPNEGO (requires GSSAPI/Kerberos)
- AWS Signature (use dedicated AWS SDK)

### Basic Authentication (RFC 7617)

Sends `Authorization: Basic base64(username:password)` with every request.

**WARNING:** Credentials are sent in cleartext (base64 is encoding, not encryption).
Only use Basic auth over HTTPS!

```c
SocketHTTPClient_Auth auth = {0};
auth.type = HTTP_AUTH_BASIC;
auth.username = "user";
auth.password = "secret";

/* Set as default for all requests */
SocketHTTPClient_set_auth(client, &auth);

/* Or per-request */
SocketHTTPClient_Request_T req = SocketHTTPClient_Request_new(
    client, HTTP_METHOD_GET, "https://api.example.com/protected");
SocketHTTPClient_Request_auth(req, &auth);
SocketHTTPClient_Request_execute(req, &response);
```

### Digest Authentication (RFC 7616)

More secure than Basic - uses challenge-response with hashing. The client:
1. Makes initial request
2. Receives 401 with `WWW-Authenticate: Digest ...` challenge
3. Computes response using MD5 or SHA-256
4. Retries request with `Authorization: Digest ...` header

```c
SocketHTTPClient_Auth auth = {0};
auth.type = HTTP_AUTH_DIGEST;
auth.username = "user";
auth.password = "secret";

/* Digest auth handles 401 challenges automatically */
SocketHTTPClient_set_auth(client, &auth);
SocketHTTPClient_get(client, "https://api.example.com/data", &response);
```

**Supported Features:**
- MD5 and SHA-256 algorithms
- `qop=auth` (authentication quality of protection)
- Stale nonce handling (automatic retry on expired nonce)

**Limitations:**
- `qop=auth-int` (integrity protection) is NOT supported
- Session-based algorithms (`MD5-sess`, `SHA-256-sess`) are NOT supported

### Bearer Token (RFC 6750)

For OAuth 2.0 and JWT-based authentication:

```c
SocketHTTPClient_Auth auth = {0};
auth.type = HTTP_AUTH_BEARER;
auth.token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";

SocketHTTPClient_set_auth(client, &auth);
```

Sends `Authorization: Bearer <token>` with every request.

**Note:** The application is responsible for:
- Obtaining tokens (OAuth flows, API key management)
- Refreshing expired tokens
- Handling token revocation

### Credential Security

Credentials are securely cleared from memory when:
- Setting new authentication (old credentials cleared)
- Freeing the client (`SocketHTTPClient_free()`)
- After generating authorization headers

The library uses `SocketCrypto_secure_clear()` which prevents compiler
optimization from removing the clearing operation.

### Automatic 401 Retry

The client automatically handles 401 responses:

1. **Basic Auth:** If credentials weren't sent, retries once
2. **Digest Auth:** Computes response from challenge, retries
3. **Stale Nonce:** If server indicates `stale=true`, retries with new nonce
4. **Max Retries:** 2 retries to prevent infinite loops

After max retries, the 401 response is returned to the application.

---

## Cookie Handling

The client includes a cookie jar (RFC 6265):

```c
/* Create cookie jar */
SocketHTTPClient_CookieJar_T jar = SocketHTTPClient_CookieJar_new(NULL);

/* Associate with client */
SocketHTTPClient_set_cookie_jar(client, jar);

/* Cookies are automatically managed:
 * - Set-Cookie headers populate the jar
 * - Matching cookies sent with requests
 * - Domain/path/expiry honored */

/* Manual cookie operations */
SocketHTTPClient_CookieJar_set(jar, "example.com", "/", "session", "abc123");
const char *value = SocketHTTPClient_CookieJar_get(jar, "example.com", "/", "session");

/* Persistence */
SocketHTTPClient_CookieJar_save(jar, "/path/to/cookies.txt");
SocketHTTPClient_CookieJar_load(jar, "/path/to/cookies.txt");

SocketHTTPClient_CookieJar_free(&jar);
```

---

## HTTP/2 Features

When connecting to an HTTPS endpoint, the client automatically negotiates HTTP/2 via ALPN if the server supports it.

### Flow Control Security Enhancements

Recent updates strengthen HTTP/2 flow control against attacks (RFC 9113 §5.2, §6.5.2):

- **Overflow/Underflow Protection**: Window updates use 64-bit checks to prevent exceeding 2^31-1. Adjustments for `SETTINGS_INITIAL_WINDOW_SIZE` (signed delta) validate against negative values or overflows; invalid cases trigger `FLOW_CONTROL_ERROR` and connection closure.
- **Validation**: Zero increments rejected as `PROTOCOL_ERROR`. Consumption clamps to prevent negative windows; queries return safe >=0 values.
- **Mitigations**: Reasonable initials (streams: 65KB, connection: 1MB) limit DoS blast radius. Errors logged + metricated (e.g., `SOCKET_CTR_HTTP2_FLOW_OVERFLOW`) for monitoring.
- **Best Practices**: Pair with pool rate limits; monitor metrics for anomalies. See `SocketHTTP2-flow.c` and [security.md](SECURITY.md#http2-security-rfc-9113) for details.

This hardening prevents exhaustion DoS, invalid state manipulation, and UB from malformed frames/SETTINGS.

### Checking Protocol Version

```c
SocketHTTPClient_Response response;
SocketHTTPClient_get(client, "https://example.com", &response);

if (response.version == HTTP_VERSION_2) {
    printf("Using HTTP/2\n");
}
```

### HTTP/2 Benefits

- **Multiplexing**: Multiple requests over single connection
- **Header Compression**: HPACK reduces overhead
- **Binary Protocol**: More efficient parsing
- **Server Push**: Server can push resources (server-side)

### HTTP/2 Cleartext (h2c)

For non-TLS HTTP/2 (rare):

```c
config.allow_http2_cleartext = 1;  /* Enable h2c upgrade */
```

---

## HTTP Server API

The `SocketHTTPServer_T` provides an event-driven HTTP server:

### Creating a Server

```c
#include "http/SocketHTTPServer.h"

SocketHTTPServer_Config config;
SocketHTTPServer_config_defaults(&config);
config.port = 8080;
config.bind_address = "0.0.0.0";
config.max_connections = 1000;

SocketHTTPServer_T server = SocketHTTPServer_new(&config);
```

### Request Handler

```c
void my_handler(SocketHTTPServer_Request_T req, void *userdata) {
    /* Get request details */
    SocketHTTP_Method method = SocketHTTPServer_Request_method(req);
    const char *path = SocketHTTPServer_Request_path(req);
    const char *query = SocketHTTPServer_Request_query(req);
    SocketHTTP_Headers_T headers = SocketHTTPServer_Request_headers(req);
    const void *body = SocketHTTPServer_Request_body(req);
    size_t body_len = SocketHTTPServer_Request_body_len(req);
    
    /* Set response */
    SocketHTTPServer_Request_status(req, 200);
    SocketHTTPServer_Request_header(req, "Content-Type", "text/html");
    SocketHTTPServer_Request_body_string(req, "<h1>Hello!</h1>");
    
    /* Finish response */
    SocketHTTPServer_Request_finish(req);
}

SocketHTTPServer_set_handler(server, my_handler, NULL);
```

### Running the Server

```c
/* Start listening */
SocketHTTPServer_start(server);

/* Event loop */
while (running) {
    SocketHTTPServer_process(server, 1000);  /* 1 second timeout */
}

/* Shutdown */
SocketHTTPServer_stop(server);
SocketHTTPServer_free(&server);
```

### WebSocket Upgrade

The server can detect and handle WebSocket upgrades:

```c
void my_handler(SocketHTTPServer_Request_T req, void *userdata) {
    if (SocketHTTPServer_Request_is_websocket(req)) {
        SocketWS_T ws = SocketHTTPServer_Request_upgrade_websocket(req);
        if (ws) {
            /* Handle WebSocket - see WEBSOCKET.md */
            /* Don't call finish() after upgrade */
            return;
        }
    }
    
    /* Normal HTTP handling */
    SocketHTTPServer_Request_finish(req);
}
```

---

## Error Handling

### Client Exceptions

```c
TRY {
    SocketHTTPClient_get(client, url, &response);
}
EXCEPT(SocketHTTPClient_DNSFailed) {
    /* DNS resolution failed */
}
EXCEPT(SocketHTTPClient_ConnectFailed) {
    /* Connection to server failed */
}
EXCEPT(SocketHTTPClient_TLSFailed) {
    /* TLS/SSL error */
}
EXCEPT(SocketHTTPClient_Timeout) {
    /* Request timed out */
}
EXCEPT(SocketHTTPClient_TooManyRedirects) {
    /* Redirect limit exceeded */
}
EXCEPT(SocketHTTPClient_ProtocolError) {
    /* HTTP parse error */
}
EXCEPT(SocketHTTPClient_ResponseTooLarge) {
    /* Response exceeded max_response_size */
}
FINALLY {
    SocketHTTPClient_Response_free(&response);
}
END_TRY;
```

### Server Exceptions

```c
TRY {
    SocketHTTPServer_start(server);
}
EXCEPT(SocketHTTPServer_BindFailed) {
    /* Port in use or permission denied */
}
EXCEPT(SocketHTTPServer_Failed) {
    /* General server error */
}
END_TRY;
```

---

## Proxy Support

The HTTP client can connect through proxies:

```c
#include "socket/SocketProxy.h"

/* Configure proxy */
SocketProxy_Config proxy;
SocketProxy_config_defaults(&proxy);
proxy.type = SOCKET_PROXY_SOCKS5;
proxy.host = "proxy.example.com";
proxy.port = 1080;

/* Set as default proxy for client */
config.proxy = &proxy;
SocketHTTPClient_T client = SocketHTTPClient_new(&config);
```

See [PROXY.md](@ref proxy_guide) for complete proxy documentation.

---

## Advanced Topics

### Streaming Requests

For large uploads:

```c
ssize_t read_callback(void *buf, size_t len, void *userdata) {
    FILE *fp = userdata;
    return fread(buf, 1, len, fp);
}

FILE *fp = fopen("large_file.bin", "rb");
SocketHTTPClient_Request_body_stream(req, read_callback, fp);
```

### Custom TLS Context

```c
SocketTLSContext_T tls = SocketTLSContext_new_client(NULL);
SocketTLSContext_set_verify_mode(tls, SSL_VERIFY_PEER);
SocketTLSContext_set_ca_file(tls, "/path/to/ca-bundle.crt");

config.tls_context = tls;
```

### Connection Pooling Behavior

- HTTP/1.1: Multiple connections per host (default: 6)
- HTTP/2: Single connection with multiplexed streams
- Idle connections automatically closed after `idle_timeout_ms`
- Pool cleaned on `SocketHTTPClient_free()`

---

## Thread Safety

- `SocketHTTPClient_T` instances are **NOT** thread-safe
- Use one client per thread, or protect with mutex
- Response data can be safely used from any thread after request completes
- `SocketHTTPServer_T` instances are **NOT** thread-safe
- Use one server per thread for event loop

---

## Performance Tips

1. **Reuse clients** - Creating clients is expensive
2. **Use HTTP/2** - Better for multiple requests to same host
3. **Enable pooling** - Avoid connection setup overhead
4. **Set appropriate timeouts** - Prevent hung connections
5. **Use compression** - Reduce bandwidth (auto-enabled)
6. **Consider async** - For high concurrency scenarios

---

## See Also

- [WebSocket Guide](@ref websocket_guide)
- [Proxy Guide](@ref proxy_guide)
- [Security Guide](@ref security_guide)
- @ref SocketHTTPClient.h
- @ref SocketHTTPServer.h


### HTTP/1.1 Parser Security Enhancements (Recent Fixes)

The SocketHTTP1 parser now includes stronger protections against HTTP request smuggling and DoS:

- **Multi-Header Validation**: 
  - Content-Length: All instances must parse to identical value; mismatch triggers `HTTP1_ERROR_INVALID_CONTENT_LENGTH` (strict mode detects smuggling).
  - Transfer-Encoding: Scans **all** TE headers for "chunked" token. Hidden chunked in later headers now detected.

- **Strict Transfer-Encoding Handling**:
  - Reject unsupported codings (gzip, compress, deflate, identity) in strict mode.
  - For "chunked" with extras (e.g., "chunked,identity"), reject if strict_mode=1 (`HTTP1_ERROR_UNSUPPORTED_TRANSFER_CODING`).
  - Fallback to until_close only if no chunked and not strict.

- **DoS Mitigations**:
  - New config `max_header_line` (default 16KB): Limits individual header line length (name + value + OWS).
  - Existing limits (max_headers, max_header_size) enforced before alloc.

- **URI Validation**:
  - Post-parse `SocketHTTP_URI_parse` integration in finalize_request: Rejects invalid syntax/encodings (`HTTP1_ERROR_INVALID_URI`).

- **Testing**:
  - New tests in `test_http1_parser.c`: Multi-header vectors, strict rejections, long lines, invalid URI.
  - Run `ctest -R http1` to verify.

Update configs for production: Set `strict_mode=1` for servers/proxies.

For full details, see security.md and SocketHTTP1.h docs.
