/*
 @licstart  The following is the entire license notice for the JavaScript code in this file.

 The MIT License (MIT)

 Copyright (C) 1997-2020 by Dimitri van Heesch

 Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 and associated documentation files (the "Software"), to deal in the Software without restriction,
 including without limitation the rights to use, copy, modify, merge, publish, distribute,
 sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all copies or
 substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
 BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 @licend  The above is the entire license notice for the JavaScript code in this file
*/
var NAVTREE =
[
  [ "Socket Library", "index.html", [
    [ "Features", "index.html#autotoc_md1", [
      [ "Core Networking", "index.html#autotoc_md2", null ],
      [ "Async & Event-Driven", "index.html#autotoc_md3", null ],
      [ "Performance", "index.html#autotoc_md4", null ]
    ] ],
    [ "Quick Start", "index.html#autotoc_md6", null ],
    [ "Examples", "index.html#autotoc_md8", [
      [ "TCP Echo Server", "index.html#autotoc_md9", null ],
      [ "TCP Client", "index.html#autotoc_md11", null ],
      [ "Event-Driven Server (Non-Blocking)", "index.html#autotoc_md13", null ],
      [ "UDP Echo Server", "index.html#autotoc_md15", null ],
      [ "UDP Client", "index.html#autotoc_md17", null ],
      [ "TLS Client (Secure Connection)", "index.html#autotoc_md19", null ],
      [ "Unix Domain Socket Server", "index.html#autotoc_md21", null ],
      [ "Happy Eyeballs (Fast Dual-Stack)", "index.html#autotoc_md23", null ],
      [ "Auto-Reconnecting Client", "index.html#autotoc_md25", null ],
      [ "Connection Pool with Buffers", "index.html#autotoc_md27", null ],
      [ "Async DNS Resolution", "index.html#autotoc_md29", null ],
      [ "Zero-Copy File Transfer", "index.html#autotoc_md31", null ],
      [ "Scatter/Gather I/O", "index.html#autotoc_md33", null ],
      [ "Advanced TCP Options", "index.html#autotoc_md35", null ]
    ] ],
    [ "Header Files", "index.html#autotoc_md37", null ],
    [ "Error Handling", "index.html#autotoc_md39", [
      [ "Exception Types", "index.html#autotoc_md40", null ]
    ] ],
    [ "Platform Support", "index.html#autotoc_md42", null ],
    [ "Documentation", "index.html#autotoc_md44", [
      [ "API Reference", "index.html#autotoc_md45", null ],
      [ "Guides", "index.html#autotoc_md46", null ],
      [ "Examples", "index.html#autotoc_md47", null ]
    ] ],
    [ "Asynchronous I/O Guide", "async_io_guide.html", [
      [ "Overview", "async_io_guide.html#autotoc_md48", null ],
      [ "Platform Support", "async_io_guide.html#autotoc_md49", null ],
      [ "Key Benefits", "async_io_guide.html#autotoc_md50", null ],
      [ "Basic Usage", "async_io_guide.html#autotoc_md51", [
        [ "Getting Async Context", "async_io_guide.html#autotoc_md52", null ],
        [ "Async Send", "async_io_guide.html#autotoc_md53", null ],
        [ "Async Receive", "async_io_guide.html#autotoc_md54", null ],
        [ "Processing Completions", "async_io_guide.html#autotoc_md55", null ],
        [ "Cancellation", "async_io_guide.html#autotoc_md56", null ]
      ] ],
      [ "Complete Example: Echo Server", "async_io_guide.html#autotoc_md57", null ],
      [ "Performance Tuning", "async_io_guide.html#autotoc_md58", [
        [ "io_uring (Linux)", "async_io_guide.html#autotoc_md59", null ],
        [ "kqueue (macOS/BSD)", "async_io_guide.html#autotoc_md60", null ]
      ] ],
      [ "Fallback Mode", "async_io_guide.html#autotoc_md61", null ],
      [ "Thread Safety", "async_io_guide.html#autotoc_md62", null ],
      [ "Error Handling", "async_io_guide.html#autotoc_md63", null ],
      [ "Migration Guide", "async_io_guide.html#autotoc_md64", [
        [ "From Synchronous to Async", "async_io_guide.html#autotoc_md65", null ]
      ] ],
      [ "Best Practices", "async_io_guide.html#autotoc_md66", null ],
      [ "Limitations", "async_io_guide.html#autotoc_md67", null ],
      [ "Troubleshooting", "async_io_guide.html#autotoc_md68", [
        [ "Async Not Available", "async_io_guide.html#autotoc_md69", null ],
        [ "High CPU Usage", "async_io_guide.html#autotoc_md70", null ],
        [ "Memory Leaks", "async_io_guide.html#autotoc_md71", null ]
      ] ],
      [ "API Reference", "async_io_guide.html#autotoc_md72", null ],
      [ "Performance Benchmarks", "async_io_guide.html#autotoc_md73", null ]
    ] ],
    [ "HTTP Guide", "http_guide.html", [
      [ "Quick Start", "http_guide.html#autotoc_md75", [
        [ "Simple HTTP GET", "http_guide.html#autotoc_md76", null ],
        [ "Simple HTTP POST", "http_guide.html#autotoc_md77", null ]
      ] ],
      [ "HTTP Client API", "http_guide.html#autotoc_md79", [
        [ "Creating a Client", "http_guide.html#autotoc_md80", null ],
        [ "Configuration Options", "http_guide.html#autotoc_md81", null ],
        [ "Simple API", "http_guide.html#autotoc_md82", null ],
        [ "Request Builder API", "http_guide.html#autotoc_md83", null ],
        [ "Response Handling", "http_guide.html#autotoc_md84", null ]
      ] ],
      [ "Authentication", "http_guide.html#autotoc_md86", [
        [ "Basic Authentication (RFC 7617)", "http_guide.html#autotoc_md87", null ],
        [ "Digest Authentication (RFC 7616)", "http_guide.html#autotoc_md88", null ],
        [ "Bearer Token (RFC 6750)", "http_guide.html#autotoc_md89", null ]
      ] ],
      [ "Cookie Handling", "http_guide.html#autotoc_md91", null ],
      [ "HTTP/2 Features", "http_guide.html#autotoc_md93", [
        [ "Checking Protocol Version", "http_guide.html#autotoc_md94", null ],
        [ "HTTP/2 Benefits", "http_guide.html#autotoc_md95", null ],
        [ "HTTP/2 Cleartext (h2c)", "http_guide.html#autotoc_md96", null ]
      ] ],
      [ "HTTP Server API", "http_guide.html#autotoc_md98", [
        [ "Creating a Server", "http_guide.html#autotoc_md99", null ],
        [ "Request Handler", "http_guide.html#autotoc_md100", null ],
        [ "Running the Server", "http_guide.html#autotoc_md101", null ],
        [ "WebSocket Upgrade", "http_guide.html#autotoc_md102", null ]
      ] ],
      [ "Error Handling", "http_guide.html#autotoc_md104", [
        [ "Client Exceptions", "http_guide.html#autotoc_md105", null ],
        [ "Server Exceptions", "http_guide.html#autotoc_md106", null ]
      ] ],
      [ "Proxy Support", "http_guide.html#autotoc_md108", null ],
      [ "Advanced Topics", "http_guide.html#autotoc_md110", [
        [ "Streaming Requests", "http_guide.html#autotoc_md111", null ],
        [ "Custom TLS Context", "http_guide.html#autotoc_md112", null ],
        [ "Connection Pooling Behavior", "http_guide.html#autotoc_md113", null ]
      ] ],
      [ "Thread Safety", "http_guide.html#autotoc_md115", null ],
      [ "Performance Tips", "http_guide.html#autotoc_md117", null ],
      [ "See Also", "http_guide.html#autotoc_md119", null ]
    ] ],
    [ "WebSocket Guide", "websocket_guide.html", [
      [ "Overview", "websocket_guide.html#autotoc_md121", null ],
      [ "Quick Start", "websocket_guide.html#autotoc_md123", [
        [ "WebSocket Client", "websocket_guide.html#autotoc_md124", null ]
      ] ],
      [ "Client API", "websocket_guide.html#autotoc_md126", [
        [ "Creating a Client Connection", "websocket_guide.html#autotoc_md127", null ],
        [ "Configuration Options", "websocket_guide.html#autotoc_md128", null ],
        [ "Performing the Handshake", "websocket_guide.html#autotoc_md129", null ]
      ] ],
      [ "Server API", "websocket_guide.html#autotoc_md131", [
        [ "Accepting WebSocket Connections", "websocket_guide.html#autotoc_md132", null ],
        [ "Manual Server Setup", "websocket_guide.html#autotoc_md133", null ]
      ] ],
      [ "Sending Messages", "websocket_guide.html#autotoc_md135", [
        [ "Text Messages", "websocket_guide.html#autotoc_md136", null ],
        [ "Binary Messages", "websocket_guide.html#autotoc_md137", null ],
        [ "Control Frames", "websocket_guide.html#autotoc_md138", null ]
      ] ],
      [ "Receiving Messages", "websocket_guide.html#autotoc_md140", [
        [ "Complete Messages", "websocket_guide.html#autotoc_md141", null ],
        [ "Message Structure", "websocket_guide.html#autotoc_md142", null ]
      ] ],
      [ "Connection States", "websocket_guide.html#autotoc_md144", null ],
      [ "Close Codes", "websocket_guide.html#autotoc_md146", [
        [ "Closing a Connection", "websocket_guide.html#autotoc_md147", null ]
      ] ],
      [ "Event Loop Integration", "websocket_guide.html#autotoc_md149", [
        [ "Non-Blocking Operation", "websocket_guide.html#autotoc_md150", null ],
        [ "Auto-Ping", "websocket_guide.html#autotoc_md151", null ]
      ] ],
      [ "Compression (permessage-deflate)", "websocket_guide.html#autotoc_md153", null ],
      [ "Subprotocols", "websocket_guide.html#autotoc_md155", null ],
      [ "Error Handling", "websocket_guide.html#autotoc_md157", [
        [ "Error Codes", "websocket_guide.html#autotoc_md158", null ],
        [ "Exceptions", "websocket_guide.html#autotoc_md159", null ]
      ] ],
      [ "Best Practices", "websocket_guide.html#autotoc_md161", [
        [ "Security", "websocket_guide.html#autotoc_md162", null ],
        [ "Performance", "websocket_guide.html#autotoc_md163", null ],
        [ "Connection Management", "websocket_guide.html#autotoc_md164", null ]
      ] ],
      [ "Thread Safety", "websocket_guide.html#autotoc_md166", null ],
      [ "See Also", "websocket_guide.html#autotoc_md168", null ]
    ] ],
    [ "Proxy Guide", "proxy_guide.html", [
      [ "Overview", "proxy_guide.html#autotoc_md170", null ],
      [ "Quick Start", "proxy_guide.html#autotoc_md172", [
        [ "SOCKS5 Proxy", "proxy_guide.html#autotoc_md173", null ],
        [ "With Authentication", "proxy_guide.html#autotoc_md174", null ],
        [ "Using URL Parser", "proxy_guide.html#autotoc_md175", null ]
      ] ],
      [ "Proxy Types", "proxy_guide.html#autotoc_md177", [
        [ "HTTP CONNECT", "proxy_guide.html#autotoc_md178", null ],
        [ "HTTPS CONNECT", "proxy_guide.html#autotoc_md179", null ],
        [ "SOCKS4", "proxy_guide.html#autotoc_md180", null ],
        [ "SOCKS4a", "proxy_guide.html#autotoc_md181", null ],
        [ "SOCKS5 (RFC 1928)", "proxy_guide.html#autotoc_md182", null ],
        [ "SOCKS5H", "proxy_guide.html#autotoc_md183", null ]
      ] ],
      [ "Configuration", "proxy_guide.html#autotoc_md185", [
        [ "Full Configuration Structure", "proxy_guide.html#autotoc_md186", null ],
        [ "Default Ports", "proxy_guide.html#autotoc_md187", null ],
        [ "URL Parser", "proxy_guide.html#autotoc_md188", null ]
      ] ],
      [ "Synchronous API", "proxy_guide.html#autotoc_md190", [
        [ "Simple Connection", "proxy_guide.html#autotoc_md191", null ],
        [ "Using Existing Socket", "proxy_guide.html#autotoc_md192", null ]
      ] ],
      [ "Asynchronous API", "proxy_guide.html#autotoc_md194", [
        [ "Starting Connection", "proxy_guide.html#autotoc_md195", null ],
        [ "Polling Progress", "proxy_guide.html#autotoc_md196", null ],
        [ "Processing Events", "proxy_guide.html#autotoc_md197", null ],
        [ "Getting Result", "proxy_guide.html#autotoc_md198", null ],
        [ "Cancellation", "proxy_guide.html#autotoc_md199", null ]
      ] ],
      [ "Result Codes", "proxy_guide.html#autotoc_md201", null ],
      [ "TLS Over Proxy", "proxy_guide.html#autotoc_md203", null ],
      [ "HTTP Client Integration", "proxy_guide.html#autotoc_md205", null ],
      [ "Security Considerations", "proxy_guide.html#autotoc_md207", [
        [ "Credential Handling", "proxy_guide.html#autotoc_md208", null ],
        [ "DNS Privacy", "proxy_guide.html#autotoc_md209", null ],
        [ "Response Validation", "proxy_guide.html#autotoc_md210", null ]
      ] ],
      [ "Error Handling", "proxy_guide.html#autotoc_md212", null ],
      [ "Connection State Machine", "proxy_guide.html#autotoc_md214", null ],
      [ "Best Practices", "proxy_guide.html#autotoc_md216", null ],
      [ "Thread Safety", "proxy_guide.html#autotoc_md218", null ],
      [ "See Also", "proxy_guide.html#autotoc_md220", null ]
    ] ],
    [ "Security Guide", "security_guide.html", [
      [ "TLS 1.3 Configuration", "security_guide.html#autotoc_md222", [
        [ "Default Configuration", "security_guide.html#autotoc_md223", null ],
        [ "TLS Settings (SocketTLSConfig.h)", "security_guide.html#autotoc_md224", null ],
        [ "Why TLS 1.3?", "security_guide.html#autotoc_md225", null ]
      ] ],
      [ "Certificate Pinning", "security_guide.html#autotoc_md227", [
        [ "SPKI SHA256 Pinning", "security_guide.html#autotoc_md228", null ],
        [ "When to Use Pinning", "security_guide.html#autotoc_md229", null ],
        [ "Pin Rotation", "security_guide.html#autotoc_md230", null ]
      ] ],
      [ "Input Validation", "security_guide.html#autotoc_md232", [
        [ "Hostname Validation", "security_guide.html#autotoc_md233", null ],
        [ "Port Validation", "security_guide.html#autotoc_md234", null ],
        [ "Buffer Size Validation", "security_guide.html#autotoc_md235", null ]
      ] ],
      [ "DNS Security", "security_guide.html#autotoc_md237", [
        [ "Blocking DNS Warning", "security_guide.html#autotoc_md238", null ],
        [ "DNS DoS Prevention", "security_guide.html#autotoc_md239", null ]
      ] ],
      [ "Credential Handling", "security_guide.html#autotoc_md241", [
        [ "Secure Memory Clearing", "security_guide.html#autotoc_md242", null ],
        [ "The Library Does This Internally", "security_guide.html#autotoc_md243", null ],
        [ "Constant-Time Comparison", "security_guide.html#autotoc_md244", null ]
      ] ],
      [ "DoS Protection", "security_guide.html#autotoc_md246", [
        [ "SYN Flood Protection", "security_guide.html#autotoc_md247", null ],
        [ "Rate Limiting", "security_guide.html#autotoc_md248", null ],
        [ "Per-IP Connection Limits", "security_guide.html#autotoc_md249", null ]
      ] ],
      [ "Thread Safety", "security_guide.html#autotoc_md251", [
        [ "Thread-Local Error Buffers", "security_guide.html#autotoc_md252", null ],
        [ "Exception Thread Safety", "security_guide.html#autotoc_md253", null ],
        [ "What's NOT Thread-Safe", "security_guide.html#autotoc_md254", null ]
      ] ],
      [ "Exception Handling", "security_guide.html#autotoc_md256", [
        [ "Always Handle Security Exceptions", "security_guide.html#autotoc_md257", null ],
        [ "Don't Ignore Verification Failures", "security_guide.html#autotoc_md258", null ]
      ] ],
      [ "HTTP Security", "security_guide.html#autotoc_md260", [
        [ "Request Smuggling Prevention", "security_guide.html#autotoc_md261", null ],
        [ "WebSocket Security", "security_guide.html#autotoc_md262", null ],
        [ "Cookie Security", "security_guide.html#autotoc_md263", null ]
      ] ],
      [ "File Descriptor Hygiene", "security_guide.html#autotoc_md265", [
        [ "Safe Close", "security_guide.html#autotoc_md266", null ],
        [ "Prevent FD Leaks", "security_guide.html#autotoc_md267", null ]
      ] ],
      [ "Audit Logging", "security_guide.html#autotoc_md269", [
        [ "What to Log", "security_guide.html#autotoc_md270", null ],
        [ "How to Log Safely", "security_guide.html#autotoc_md271", null ]
      ] ],
      [ "Security Checklist", "security_guide.html#autotoc_md273", [
        [ "Server Applications", "security_guide.html#autotoc_md274", null ],
        [ "Client Applications", "security_guide.html#autotoc_md275", null ],
        [ "General", "security_guide.html#autotoc_md276", null ]
      ] ],
      [ "See Also", "security_guide.html#autotoc_md278", null ]
    ] ],
    [ "Migration Guide", "migration_guide.html", [
      [ "Migration from BSD Sockets", "migration_guide.html#autotoc_md280", [
        [ "Socket Creation", "migration_guide.html#autotoc_md281", null ],
        [ "Connecting", "migration_guide.html#autotoc_md282", null ],
        [ "Sending Data", "migration_guide.html#autotoc_md283", null ],
        [ "Socket Options", "migration_guide.html#autotoc_md284", null ],
        [ "API Mapping (BSD -> Socket Library)", "migration_guide.html#autotoc_md285", null ]
      ] ],
      [ "Migration from libcurl", "migration_guide.html#autotoc_md287", [
        [ "Simple GET Request", "migration_guide.html#autotoc_md288", null ],
        [ "POST Request", "migration_guide.html#autotoc_md289", null ],
        [ "Custom Headers", "migration_guide.html#autotoc_md290", null ],
        [ "Proxy Configuration", "migration_guide.html#autotoc_md291", null ],
        [ "Error Handling", "migration_guide.html#autotoc_md292", null ],
        [ "API Mapping (libcurl -> Socket Library)", "migration_guide.html#autotoc_md293", null ]
      ] ],
      [ "Migration from libevent", "migration_guide.html#autotoc_md295", [
        [ "Event Loop", "migration_guide.html#autotoc_md296", null ],
        [ "Callback Style", "migration_guide.html#autotoc_md297", null ],
        [ "Timers", "migration_guide.html#autotoc_md298", null ],
        [ "API Mapping (libevent -> Socket Library)", "migration_guide.html#autotoc_md299", null ]
      ] ],
      [ "Migration from libev", "migration_guide.html#autotoc_md301", [
        [ "Event Loop", "migration_guide.html#autotoc_md302", null ]
      ] ],
      [ "Migration from OpenSSL Direct", "migration_guide.html#autotoc_md304", [
        [ "TLS Client", "migration_guide.html#autotoc_md305", null ],
        [ "API Mapping (OpenSSL -> Socket Library)", "migration_guide.html#autotoc_md306", null ]
      ] ],
      [ "Common Patterns", "migration_guide.html#autotoc_md308", [
        [ "Error Handling Pattern", "migration_guide.html#autotoc_md309", null ],
        [ "Resource Cleanup Pattern", "migration_guide.html#autotoc_md310", null ]
      ] ],
      [ "Key Differences", "migration_guide.html#autotoc_md312", [
        [ "Memory Management", "migration_guide.html#autotoc_md313", null ],
        [ "Error Handling", "migration_guide.html#autotoc_md314", null ],
        [ "Thread Safety", "migration_guide.html#autotoc_md315", null ]
      ] ],
      [ "Getting Started", "migration_guide.html#autotoc_md317", null ],
      [ "See Also", "migration_guide.html#autotoc_md319", null ]
    ] ],
    [ "Data Structures", "annotated.html", [
      [ "Data Structures", "annotated.html", "annotated_dup" ],
      [ "Data Structure Index", "classes.html", null ],
      [ "Data Fields", "functions.html", [
        [ "All", "functions.html", "functions_dup" ],
        [ "Variables", "functions_vars.html", "functions_vars" ]
      ] ]
    ] ],
    [ "Files", "files.html", [
      [ "File List", "files.html", "files_dup" ],
      [ "Globals", "globals.html", [
        [ "All", "globals.html", "globals_dup" ],
        [ "Functions", "globals_func.html", "globals_func" ],
        [ "Variables", "globals_vars.html", null ],
        [ "Typedefs", "globals_type.html", null ],
        [ "Enumerations", "globals_enum.html", null ],
        [ "Enumerator", "globals_eval.html", "globals_eval" ],
        [ "Macros", "globals_defs.html", "globals_defs" ]
      ] ]
    ] ]
  ] ]
];

var NAVTREEINDEX =
[
"Arena_8h.html",
"SocketConfig_8h.html#aa5594e0bf4a9a492cc6e9dd7bcdae74c",
"SocketDgram_8h.html#af54f02197f8c0dc53fbdf333d476aae2",
"SocketHTTP2_8h.html#aac66e768242c701bf092296fa1dd2e19",
"SocketHTTP_8h.html#a905b7faf61f39aaa3cfcfed80d1675d5a37bc28ad2189c682b316e17c9357e8d0",
"SocketPool_8h.html#ae5f905ecace343c3b462dfadd5fa8056",
"SocketSecurity_8h.html#a71de06121ef88aa459fc42e9f087be64",
"SocketUtil_8h.html#acb8273a8b69ebd471d3bf7da0290349b",
"async_io_guide.html#autotoc_md68",
"proxy__connect_8c.html#a3c04138a5bfe5d72780bb7e82a18e627"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';