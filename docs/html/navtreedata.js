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
    [ "Features", "index.html#autotoc_md13", [
      [ "Core Networking", "index.html#autotoc_md14", null ],
      [ "Async & Event-Driven", "index.html#autotoc_md15", null ],
      [ "Performance", "index.html#autotoc_md16", null ]
    ] ],
    [ "Quick Start", "index.html#autotoc_md18", null ],
    [ "Examples", "index.html#autotoc_md20", [
      [ "TCP Echo Server", "index.html#autotoc_md21", null ],
      [ "TCP Client", "index.html#autotoc_md23", null ],
      [ "Event-Driven Server (Non-Blocking)", "index.html#autotoc_md25", null ],
      [ "UDP Echo Server", "index.html#autotoc_md27", null ],
      [ "UDP Client", "index.html#autotoc_md29", null ],
      [ "TLS Client (Secure Connection)", "index.html#autotoc_md31", null ],
      [ "Unix Domain Socket Server", "index.html#autotoc_md33", null ],
      [ "Happy Eyeballs (Fast Dual-Stack)", "index.html#autotoc_md35", null ],
      [ "Auto-Reconnecting Client", "index.html#autotoc_md37", null ],
      [ "Connection Pool with Buffers", "index.html#autotoc_md39", null ],
      [ "Async DNS Resolution", "index.html#autotoc_md41", null ],
      [ "Zero-Copy File Transfer", "index.html#autotoc_md43", null ],
      [ "Scatter/Gather I/O", "index.html#autotoc_md45", null ],
      [ "Advanced TCP Options", "index.html#autotoc_md47", null ]
    ] ],
    [ "Header Files", "index.html#autotoc_md49", null ],
    [ "Error Handling", "index.html#autotoc_md51", [
      [ "Exception Types", "index.html#autotoc_md52", null ]
    ] ],
    [ "Platform Support", "index.html#autotoc_md54", null ],
    [ "Documentation", "index.html#autotoc_md56", [
      [ "API Reference", "index.html#autotoc_md57", null ],
      [ "Guides", "index.html#autotoc_md58", null ],
      [ "Examples", "index.html#autotoc_md59", null ]
    ] ],
    [ "Proxy Tunneling Guide", "proxy_guide.html", [
      [ "Overview", "proxy_guide.html#autotoc_md191", null ],
      [ "Quick Start", "proxy_guide.html#autotoc_md193", [
        [ "SOCKS5 Proxy", "proxy_guide.html#autotoc_md194", null ],
        [ "With Authentication", "proxy_guide.html#autotoc_md195", null ],
        [ "Using URL Parser", "proxy_guide.html#autotoc_md196", null ]
      ] ],
      [ "Proxy Types", "proxy_guide.html#autotoc_md198", [
        [ "HTTP CONNECT", "proxy_guide.html#autotoc_md199", null ],
        [ "HTTPS CONNECT", "proxy_guide.html#autotoc_md200", null ],
        [ "SOCKS4", "proxy_guide.html#autotoc_md201", null ],
        [ "SOCKS4a", "proxy_guide.html#autotoc_md202", null ],
        [ "SOCKS5 (RFC 1928)", "proxy_guide.html#autotoc_md203", null ],
        [ "SOCKS5H", "proxy_guide.html#autotoc_md204", null ]
      ] ],
      [ "Configuration", "proxy_guide.html#autotoc_md206", [
        [ "Full Configuration Structure", "proxy_guide.html#autotoc_md207", null ],
        [ "Default Ports", "proxy_guide.html#autotoc_md208", null ],
        [ "URL Parser", "proxy_guide.html#autotoc_md209", null ]
      ] ],
      [ "Synchronous API", "proxy_guide.html#autotoc_md211", [
        [ "Simple Connection", "proxy_guide.html#autotoc_md212", null ],
        [ "Using Existing Socket", "proxy_guide.html#autotoc_md213", null ]
      ] ],
      [ "Asynchronous API", "proxy_guide.html#autotoc_md215", [
        [ "Fully Async API (Recommended)", "proxy_guide.html#autotoc_md216", null ],
        [ "Blocking Connect API", "proxy_guide.html#autotoc_md217", null ],
        [ "Polling for Handshake", "proxy_guide.html#autotoc_md218", null ],
        [ "Processing Events", "proxy_guide.html#autotoc_md219", null ],
        [ "Getting Result", "proxy_guide.html#autotoc_md220", null ],
        [ "Cancellation", "proxy_guide.html#autotoc_md221", null ],
        [ "API Comparison", "proxy_guide.html#autotoc_md222", null ]
      ] ],
      [ "Result Codes", "proxy_guide.html#autotoc_md224", null ],
      [ "TLS Over Proxy", "proxy_guide.html#autotoc_md226", null ],
      [ "HTTP Client Integration", "proxy_guide.html#autotoc_md228", null ],
      [ "Security Considerations", "proxy_guide.html#autotoc_md230", [
        [ "Credential Handling", "proxy_guide.html#autotoc_md231", null ],
        [ "DNS Privacy", "proxy_guide.html#autotoc_md232", null ],
        [ "Response Validation", "proxy_guide.html#autotoc_md233", null ]
      ] ],
      [ "Error Handling", "proxy_guide.html#autotoc_md235", null ],
      [ "Connection State Machine", "proxy_guide.html#autotoc_md237", null ],
      [ "Best Practices", "proxy_guide.html#autotoc_md239", null ],
      [ "Thread Safety", "proxy_guide.html#autotoc_md241", null ],
      [ "See Also", "proxy_guide.html#autotoc_md243", null ]
    ] ],
    [ "Asynchronous I/O Guide", "async_io_guide.html", [
      [ "Overview", "async_io_guide.html#autotoc_md60", null ],
      [ "Platform Support", "async_io_guide.html#autotoc_md61", null ],
      [ "Key Benefits", "async_io_guide.html#autotoc_md62", null ],
      [ "Basic Usage", "async_io_guide.html#autotoc_md63", [
        [ "Getting Async Context", "async_io_guide.html#autotoc_md64", null ],
        [ "Async Send", "async_io_guide.html#autotoc_md65", null ],
        [ "Async Receive", "async_io_guide.html#autotoc_md66", null ],
        [ "Processing Completions", "async_io_guide.html#autotoc_md67", null ],
        [ "Cancellation", "async_io_guide.html#autotoc_md68", null ]
      ] ],
      [ "Complete Example: Echo Server", "async_io_guide.html#autotoc_md69", null ],
      [ "Performance Tuning", "async_io_guide.html#autotoc_md70", [
        [ "io_uring (Linux)", "async_io_guide.html#autotoc_md71", null ],
        [ "kqueue (macOS/BSD)", "async_io_guide.html#autotoc_md72", null ]
      ] ],
      [ "Fallback Mode", "async_io_guide.html#autotoc_md73", null ],
      [ "Thread Safety", "async_io_guide.html#autotoc_md74", null ],
      [ "Error Handling", "async_io_guide.html#autotoc_md75", null ],
      [ "Migration Guide", "async_io_guide.html#autotoc_md76", [
        [ "From Synchronous to Async", "async_io_guide.html#autotoc_md77", null ]
      ] ],
      [ "Best Practices", "async_io_guide.html#autotoc_md78", null ],
      [ "Limitations", "async_io_guide.html#autotoc_md79", null ],
      [ "Troubleshooting", "async_io_guide.html#autotoc_md80", [
        [ "Async Not Available", "async_io_guide.html#autotoc_md81", null ],
        [ "High CPU Usage", "async_io_guide.html#autotoc_md82", null ],
        [ "Memory Leaks", "async_io_guide.html#autotoc_md83", null ]
      ] ],
      [ "API Reference", "async_io_guide.html#autotoc_md84", null ],
      [ "Performance Benchmarks", "async_io_guide.html#autotoc_md85", null ]
    ] ],
    [ "HTTP Guide", "http_guide.html", [
      [ "Quick Start", "http_guide.html#autotoc_md87", [
        [ "Simple HTTP GET", "http_guide.html#autotoc_md88", null ],
        [ "Simple HTTP POST", "http_guide.html#autotoc_md89", null ]
      ] ],
      [ "HTTP Client API", "http_guide.html#autotoc_md91", [
        [ "Creating a Client", "http_guide.html#autotoc_md92", null ],
        [ "Configuration Options", "http_guide.html#autotoc_md93", null ],
        [ "Simple API", "http_guide.html#autotoc_md94", null ],
        [ "Request Builder API", "http_guide.html#autotoc_md95", null ],
        [ "Response Handling", "http_guide.html#autotoc_md96", null ]
      ] ],
      [ "Authentication", "http_guide.html#autotoc_md98", [
        [ "Supported Authentication Types", "http_guide.html#autotoc_md99", null ],
        [ "Basic Authentication (RFC 7617)", "http_guide.html#autotoc_md100", null ],
        [ "Digest Authentication (RFC 7616)", "http_guide.html#autotoc_md101", null ],
        [ "Bearer Token (RFC 6750)", "http_guide.html#autotoc_md102", null ],
        [ "Credential Security", "http_guide.html#autotoc_md103", null ],
        [ "Automatic 401 Retry", "http_guide.html#autotoc_md104", null ]
      ] ],
      [ "Cookie Handling", "http_guide.html#autotoc_md106", null ],
      [ "HTTP/2 Features", "http_guide.html#autotoc_md108", [
        [ "Flow Control Security Enhancements", "http_guide.html#autotoc_md109", null ],
        [ "Checking Protocol Version", "http_guide.html#autotoc_md110", null ],
        [ "HTTP/2 Benefits", "http_guide.html#autotoc_md111", null ],
        [ "HTTP/2 Cleartext (h2c)", "http_guide.html#autotoc_md112", null ]
      ] ],
      [ "HTTP Server API", "http_guide.html#autotoc_md114", [
        [ "Creating a Server", "http_guide.html#autotoc_md115", null ],
        [ "Request Handler", "http_guide.html#autotoc_md116", null ],
        [ "Running the Server", "http_guide.html#autotoc_md117", null ],
        [ "WebSocket Upgrade", "http_guide.html#autotoc_md118", null ]
      ] ],
      [ "Error Handling", "http_guide.html#autotoc_md120", [
        [ "Client Exceptions", "http_guide.html#autotoc_md121", null ],
        [ "Server Exceptions", "http_guide.html#autotoc_md122", null ]
      ] ],
      [ "Proxy Support", "http_guide.html#autotoc_md124", null ],
      [ "Advanced Topics", "http_guide.html#autotoc_md126", [
        [ "Streaming Requests", "http_guide.html#autotoc_md127", null ],
        [ "Custom TLS Context", "http_guide.html#autotoc_md128", null ],
        [ "Connection Pooling Behavior", "http_guide.html#autotoc_md129", null ]
      ] ],
      [ "Thread Safety", "http_guide.html#autotoc_md131", null ],
      [ "Performance Tips", "http_guide.html#autotoc_md133", null ],
      [ "See Also", "http_guide.html#autotoc_md135", [
        [ "HTTP/1.1 Parser Security Enhancements (Recent Fixes)", "http_guide.html#autotoc_md136", null ]
      ] ]
    ] ],
    [ "WebSocket Guide", "websocket_guide.html", [
      [ "Overview", "websocket_guide.html#autotoc_md138", null ],
      [ "Security Considerations", "websocket_guide.html#autotoc_md140", [
        [ "Key Security Features", "websocket_guide.html#autotoc_md141", null ],
        [ "Best Practices", "websocket_guide.html#autotoc_md142", null ],
        [ "Potential Risks & Mitigations", "websocket_guide.html#autotoc_md143", null ]
      ] ],
      [ "Quick Start", "websocket_guide.html#autotoc_md144", [
        [ "WebSocket Client", "websocket_guide.html#autotoc_md145", null ]
      ] ],
      [ "Client API", "websocket_guide.html#autotoc_md147", [
        [ "Creating a Client Connection", "websocket_guide.html#autotoc_md148", null ],
        [ "Configuration Options", "websocket_guide.html#autotoc_md149", null ],
        [ "Performing the Handshake", "websocket_guide.html#autotoc_md150", null ]
      ] ],
      [ "Server API", "websocket_guide.html#autotoc_md152", [
        [ "Accepting WebSocket Connections", "websocket_guide.html#autotoc_md153", null ],
        [ "Manual Server Setup", "websocket_guide.html#autotoc_md154", null ]
      ] ],
      [ "Sending Messages", "websocket_guide.html#autotoc_md156", [
        [ "Text Messages", "websocket_guide.html#autotoc_md157", null ],
        [ "Binary Messages", "websocket_guide.html#autotoc_md158", null ],
        [ "Control Frames", "websocket_guide.html#autotoc_md159", null ]
      ] ],
      [ "Receiving Messages", "websocket_guide.html#autotoc_md161", [
        [ "Complete Messages", "websocket_guide.html#autotoc_md162", null ],
        [ "Message Structure", "websocket_guide.html#autotoc_md163", null ]
      ] ],
      [ "Connection States", "websocket_guide.html#autotoc_md165", null ],
      [ "Close Codes", "websocket_guide.html#autotoc_md167", [
        [ "Closing a Connection", "websocket_guide.html#autotoc_md168", null ]
      ] ],
      [ "Event Loop Integration", "websocket_guide.html#autotoc_md170", [
        [ "Non-Blocking Operation", "websocket_guide.html#autotoc_md171", null ],
        [ "Auto-Ping", "websocket_guide.html#autotoc_md172", null ]
      ] ],
      [ "Compression (permessage-deflate)", "websocket_guide.html#autotoc_md174", null ],
      [ "Subprotocols", "websocket_guide.html#autotoc_md176", null ],
      [ "Error Handling", "websocket_guide.html#autotoc_md178", [
        [ "Error Codes", "websocket_guide.html#autotoc_md179", null ],
        [ "Exceptions", "websocket_guide.html#autotoc_md180", null ]
      ] ],
      [ "Best Practices", "websocket_guide.html#autotoc_md182", [
        [ "Security", "websocket_guide.html#autotoc_md183", null ],
        [ "Performance", "websocket_guide.html#autotoc_md184", null ],
        [ "Connection Management", "websocket_guide.html#autotoc_md185", null ]
      ] ],
      [ "Thread Safety", "websocket_guide.html#autotoc_md187", null ],
      [ "See Also", "websocket_guide.html#autotoc_md189", null ]
    ] ],
    [ "Security Guide", "security_guide.html", [
      [ "TLS 1.3 Configuration", "security_guide.html#autotoc_md245", [
        [ "Default Configuration", "security_guide.html#autotoc_md246", null ],
        [ "TLS Settings (SocketTLSConfig.h)", "security_guide.html#autotoc_md247", null ],
        [ "Why TLS 1.3?", "security_guide.html#autotoc_md248", null ]
      ] ],
      [ "Certificate Transparency (CT)", "security_guide.html#autotoc_md250", [
        [ "Usage", "security_guide.html#autotoc_md251", null ],
        [ "Security Benefits", "security_guide.html#autotoc_md252", null ],
        [ "Requirements", "security_guide.html#autotoc_md253", null ],
        [ "Custom Logs", "security_guide.html#autotoc_md254", null ],
        [ "Verification", "security_guide.html#autotoc_md255", null ],
        [ "Limits", "security_guide.html#autotoc_md256", null ]
      ] ],
      [ "Certificate Pinning", "security_guide.html#autotoc_md257", [
        [ "SPKI SHA256 Pinning", "security_guide.html#autotoc_md258", null ],
        [ "When to Use Pinning", "security_guide.html#autotoc_md259", null ],
        [ "Pin Rotation", "security_guide.html#autotoc_md260", null ]
      ] ],
      [ "Input Validation", "security_guide.html#autotoc_md262", [
        [ "Hostname Validation", "security_guide.html#autotoc_md263", null ],
        [ "Port Validation", "security_guide.html#autotoc_md264", null ],
        [ "Buffer Size Validation", "security_guide.html#autotoc_md265", null ]
      ] ],
      [ "DNS Security", "security_guide.html#autotoc_md267", [
        [ "Blocking DNS Warning", "security_guide.html#autotoc_md268", null ],
        [ "DNS DoS Prevention", "security_guide.html#autotoc_md269", null ]
      ] ],
      [ "Credential Handling", "security_guide.html#autotoc_md271", [
        [ "Secure Memory Clearing", "security_guide.html#autotoc_md272", null ],
        [ "The Library Does This Internally", "security_guide.html#autotoc_md273", null ],
        [ "Constant-Time Comparison", "security_guide.html#autotoc_md274", null ]
      ] ],
      [ "DoS Protection", "security_guide.html#autotoc_md276", [
        [ "SYN Flood Protection", "security_guide.html#autotoc_md277", null ],
        [ "Rate Limiting", "security_guide.html#autotoc_md278", null ],
        [ "Per-IP Connection Limits", "security_guide.html#autotoc_md279", null ]
      ] ],
      [ "Thread Safety", "security_guide.html#autotoc_md281", [
        [ "Thread-Local Error Buffers", "security_guide.html#autotoc_md282", null ],
        [ "Exception Thread Safety", "security_guide.html#autotoc_md283", null ],
        [ "What's NOT Thread-Safe", "security_guide.html#autotoc_md284", null ]
      ] ],
      [ "Exception Handling", "security_guide.html#autotoc_md286", [
        [ "Always Handle Security Exceptions", "security_guide.html#autotoc_md287", null ],
        [ "Don't Ignore Verification Failures", "security_guide.html#autotoc_md288", null ]
      ] ],
      [ "HTTP Security", "security_guide.html#autotoc_md290", [
        [ "Request Smuggling Prevention", "security_guide.html#autotoc_md291", null ],
        [ "WebSocket Security", "security_guide.html#autotoc_md292", null ],
        [ "Cookie Security", "security_guide.html#autotoc_md293", null ],
        [ "HTTP/2 Flow Control Hardening", "security_guide.html#autotoc_md294", null ]
      ] ],
      [ "File Descriptor Hygiene", "security_guide.html#autotoc_md296", [
        [ "Safe Close", "security_guide.html#autotoc_md297", null ],
        [ "Prevent FD Leaks", "security_guide.html#autotoc_md298", null ]
      ] ],
      [ "Audit Logging", "security_guide.html#autotoc_md300", [
        [ "What to Log", "security_guide.html#autotoc_md301", null ],
        [ "How to Log Safely", "security_guide.html#autotoc_md302", null ]
      ] ],
      [ "Security Checklist", "security_guide.html#autotoc_md304", [
        [ "Server Applications", "security_guide.html#autotoc_md305", null ],
        [ "Client Applications", "security_guide.html#autotoc_md306", null ],
        [ "General", "security_guide.html#autotoc_md307", null ]
      ] ],
      [ "TLS Configuration Best Practices", "security_guide.html#autotoc_md309", [
        [ "Protocol Version", "security_guide.html#autotoc_md310", null ],
        [ "Cipher Suite Configuration", "security_guide.html#autotoc_md311", null ],
        [ "Certificate Verification", "security_guide.html#autotoc_md312", null ],
        [ "Mutual TLS (mTLS)", "security_guide.html#autotoc_md313", null ],
        [ "OCSP Stapling", "security_guide.html#autotoc_md314", null ],
        [ "Certificate Transparency", "security_guide.html#autotoc_md315", null ],
        [ "Certificate Revocation Lists (CRL)", "security_guide.html#autotoc_md316", null ],
        [ "Session Resumption Security", "security_guide.html#autotoc_md317", null ],
        [ "Renegotiation Protection", "security_guide.html#autotoc_md318", null ],
        [ "Private Key Protection", "security_guide.html#autotoc_md319", null ],
        [ "TLS Security Checklist", "security_guide.html#autotoc_md320", null ]
      ] ],
      [ "See Also", "security_guide.html#autotoc_md322", null ]
    ] ],
    [ "Migration Guide", "migration_guide.html", [
      [ "Migration from BSD Sockets", "migration_guide.html#autotoc_md324", [
        [ "Socket Creation", "migration_guide.html#autotoc_md325", null ],
        [ "Connecting", "migration_guide.html#autotoc_md326", null ],
        [ "Sending Data", "migration_guide.html#autotoc_md327", null ],
        [ "Socket Options", "migration_guide.html#autotoc_md328", null ],
        [ "API Mapping (BSD -> Socket Library)", "migration_guide.html#autotoc_md329", null ]
      ] ],
      [ "Migration from libcurl", "migration_guide.html#autotoc_md331", [
        [ "Simple GET Request", "migration_guide.html#autotoc_md332", null ],
        [ "POST Request", "migration_guide.html#autotoc_md333", null ],
        [ "Custom Headers", "migration_guide.html#autotoc_md334", null ],
        [ "Proxy Configuration", "migration_guide.html#autotoc_md335", null ],
        [ "Error Handling", "migration_guide.html#autotoc_md336", null ],
        [ "API Mapping (libcurl -> Socket Library)", "migration_guide.html#autotoc_md337", null ]
      ] ],
      [ "Migration from libevent", "migration_guide.html#autotoc_md339", [
        [ "Event Loop", "migration_guide.html#autotoc_md340", null ],
        [ "Callback Style", "migration_guide.html#autotoc_md341", null ],
        [ "Timers", "migration_guide.html#autotoc_md342", null ],
        [ "API Mapping (libevent -> Socket Library)", "migration_guide.html#autotoc_md343", null ]
      ] ],
      [ "Migration from libev", "migration_guide.html#autotoc_md345", [
        [ "Event Loop", "migration_guide.html#autotoc_md346", null ]
      ] ],
      [ "Migration from OpenSSL Direct", "migration_guide.html#autotoc_md348", [
        [ "TLS Client", "migration_guide.html#autotoc_md349", null ],
        [ "API Mapping (OpenSSL -> Socket Library)", "migration_guide.html#autotoc_md350", null ]
      ] ],
      [ "Common Patterns", "migration_guide.html#autotoc_md352", [
        [ "Error Handling Pattern", "migration_guide.html#autotoc_md353", null ],
        [ "Resource Cleanup Pattern", "migration_guide.html#autotoc_md354", null ]
      ] ],
      [ "Key Differences", "migration_guide.html#autotoc_md356", [
        [ "Memory Management", "migration_guide.html#autotoc_md357", null ],
        [ "Error Handling", "migration_guide.html#autotoc_md358", null ],
        [ "Thread Safety", "migration_guide.html#autotoc_md359", null ]
      ] ],
      [ "Getting Started", "migration_guide.html#autotoc_md361", null ],
      [ "See Also", "migration_guide.html#autotoc_md363", null ]
    ] ],
    [ "Deprecated List", "deprecated.html", null ],
    [ "Topics", "topics.html", "topics" ],
    [ "Data Structures", "annotated.html", [
      [ "Data Structures", "annotated.html", "annotated_dup" ],
      [ "Data Structure Index", "classes.html", null ],
      [ "Data Fields", "functions.html", [
        [ "All", "functions.html", "functions_dup" ],
        [ "Functions", "functions_func.html", null ],
        [ "Variables", "functions_vars.html", "functions_vars" ],
        [ "Enumerations", "functions_enum.html", null ],
        [ "Enumerator", "functions_eval.html", null ]
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
    ] ],
    [ "Examples", "examples.html", "examples" ]
  ] ]
];

var NAVTREEINDEX =
[
"Arena_8h.html",
"group__async__io.html",
"group__connection__mgmt.html#ga9b0182834888e8b3136846f5fca1bc64",
"group__core__io.html#ga6d8596dc13da264d86966c08b435110a",
"group__dns.html#afb60ae86fa4e34c68f4b19248c0a6224",
"group__foundation.html#a3766cfcaec1653412a3c0310bf5f289c",
"group__foundation.html#ggacf807f3c720486767d282324cacd4908a475f39fb23ebd0bec24b2e3c223e7a16",
"group__http.html#aa21dae3f3eb3b5f5a8a071a678b597fa",
"group__http.html#ga4c7d8b975c0f5cab7a44547028b5d98a",
"group__http.html#gga8cc947a0df8404588ec5ca3e179d4e57a0fd4e94594311959f7781debf2ab9930",
"group__http1.html#gga5b086c700986994685f83dd033821f0ead046cbedac23049ecf363b915c3d103a",
"group__http2__private.html#a6c31351e912c6c5cf5114a5eff3e9263",
"group__proxy.html#a507287d832417162da30794693e16a6e",
"group__security.html#aee78309674162f25f5e7420359968eb0",
"group__security.html#structSocketSYN__BlacklistEntry",
"group__utilities.html#gga1c2d3a4ca0a94b5d52917b2020796ceead596032b7866cc489959efe27c8a161c",
"group__websocket.html#ggabd79199a60ad91cf785166f24f41101faa41b8e2f5c20dd621e69746820e10ecd",
"security_guide.html#autotoc_md318"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';