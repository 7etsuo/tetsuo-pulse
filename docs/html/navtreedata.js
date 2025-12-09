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
    [ "Features", "index.html#autotoc_md4", [
      [ "Core Networking", "index.html#autotoc_md5", null ],
      [ "Async & Event-Driven", "index.html#autotoc_md6", null ],
      [ "Performance", "index.html#autotoc_md7", null ]
    ] ],
    [ "Quick Start", "index.html#autotoc_md9", null ],
    [ "Examples", "index.html#autotoc_md11", [
      [ "TCP Echo Server", "index.html#autotoc_md12", null ],
      [ "TCP Client", "index.html#autotoc_md14", null ],
      [ "Event-Driven Server (Non-Blocking)", "index.html#autotoc_md16", null ],
      [ "UDP Echo Server", "index.html#autotoc_md18", null ],
      [ "UDP Client", "index.html#autotoc_md20", null ],
      [ "TLS Client (Secure Connection)", "index.html#autotoc_md22", null ],
      [ "Unix Domain Socket Server", "index.html#autotoc_md24", null ],
      [ "Happy Eyeballs (Fast Dual-Stack)", "index.html#autotoc_md26", null ],
      [ "Auto-Reconnecting Client", "index.html#autotoc_md28", null ],
      [ "Connection Pool with Buffers", "index.html#autotoc_md30", null ],
      [ "Async DNS Resolution", "index.html#autotoc_md32", null ],
      [ "Zero-Copy File Transfer", "index.html#autotoc_md34", null ],
      [ "Scatter/Gather I/O", "index.html#autotoc_md36", null ],
      [ "Advanced TCP Options", "index.html#autotoc_md38", null ]
    ] ],
    [ "Header Files", "index.html#autotoc_md40", null ],
    [ "Error Handling", "index.html#autotoc_md42", [
      [ "Exception Types", "index.html#autotoc_md43", null ]
    ] ],
    [ "Platform Support", "index.html#autotoc_md45", null ],
    [ "Documentation", "index.html#autotoc_md47", [
      [ "API Reference", "index.html#autotoc_md48", null ],
      [ "Guides", "index.html#autotoc_md49", null ],
      [ "Examples", "index.html#autotoc_md50", null ]
    ] ],
    [ "HTTP/1.1 Module Overview", "http1_page.html", null ],
    [ "Asynchronous I/O Guide", "async_io_guide.html", [
      [ "Overview", "async_io_guide.html#autotoc_md51", null ],
      [ "Platform Support", "async_io_guide.html#autotoc_md52", null ],
      [ "Key Benefits", "async_io_guide.html#autotoc_md53", null ],
      [ "Basic Usage", "async_io_guide.html#autotoc_md54", [
        [ "Getting Async Context", "async_io_guide.html#autotoc_md55", null ],
        [ "Async Send", "async_io_guide.html#autotoc_md56", null ],
        [ "Async Receive", "async_io_guide.html#autotoc_md57", null ],
        [ "Processing Completions", "async_io_guide.html#autotoc_md58", null ],
        [ "Cancellation", "async_io_guide.html#autotoc_md59", null ]
      ] ],
      [ "Complete Example: Echo Server", "async_io_guide.html#autotoc_md60", null ],
      [ "Performance Tuning", "async_io_guide.html#autotoc_md61", [
        [ "io_uring (Linux)", "async_io_guide.html#autotoc_md62", null ],
        [ "kqueue (macOS/BSD)", "async_io_guide.html#autotoc_md63", null ]
      ] ],
      [ "Fallback Mode", "async_io_guide.html#autotoc_md64", null ],
      [ "Thread Safety", "async_io_guide.html#autotoc_md65", null ],
      [ "Error Handling", "async_io_guide.html#autotoc_md66", null ],
      [ "Migration Guide", "async_io_guide.html#autotoc_md67", [
        [ "From Synchronous to Async", "async_io_guide.html#autotoc_md68", null ]
      ] ],
      [ "Best Practices", "async_io_guide.html#autotoc_md69", null ],
      [ "Limitations", "async_io_guide.html#autotoc_md70", null ],
      [ "Troubleshooting", "async_io_guide.html#autotoc_md71", [
        [ "Async Not Available", "async_io_guide.html#autotoc_md72", null ],
        [ "High CPU Usage", "async_io_guide.html#autotoc_md73", null ],
        [ "Memory Leaks", "async_io_guide.html#autotoc_md74", null ]
      ] ],
      [ "API Reference", "async_io_guide.html#autotoc_md75", null ],
      [ "Performance Benchmarks", "async_io_guide.html#autotoc_md76", null ]
    ] ],
    [ "HTTP Guide", "http_guide.html", [
      [ "Quick Start", "http_guide.html#autotoc_md78", [
        [ "Simple HTTP GET", "http_guide.html#autotoc_md79", null ],
        [ "Simple HTTP POST", "http_guide.html#autotoc_md80", null ]
      ] ],
      [ "HTTP Client API", "http_guide.html#autotoc_md82", [
        [ "Creating a Client", "http_guide.html#autotoc_md83", null ],
        [ "Configuration Options", "http_guide.html#autotoc_md84", null ],
        [ "Simple API", "http_guide.html#autotoc_md85", null ],
        [ "Request Builder API", "http_guide.html#autotoc_md86", null ],
        [ "Response Handling", "http_guide.html#autotoc_md87", null ]
      ] ],
      [ "Authentication", "http_guide.html#autotoc_md89", [
        [ "Supported Authentication Types", "http_guide.html#autotoc_md90", null ],
        [ "Basic Authentication (RFC 7617)", "http_guide.html#autotoc_md91", null ],
        [ "Digest Authentication (RFC 7616)", "http_guide.html#autotoc_md92", null ],
        [ "Bearer Token (RFC 6750)", "http_guide.html#autotoc_md93", null ],
        [ "Credential Security", "http_guide.html#autotoc_md94", null ],
        [ "Automatic 401 Retry", "http_guide.html#autotoc_md95", null ]
      ] ],
      [ "Cookie Handling", "http_guide.html#autotoc_md97", null ],
      [ "HTTP/2 Features", "http_guide.html#autotoc_md99", [
        [ "Flow Control Security Enhancements", "http_guide.html#autotoc_md100", null ],
        [ "Checking Protocol Version", "http_guide.html#autotoc_md101", null ],
        [ "HTTP/2 Benefits", "http_guide.html#autotoc_md102", null ],
        [ "HTTP/2 Cleartext (h2c)", "http_guide.html#autotoc_md103", null ]
      ] ],
      [ "HTTP Server API", "http_guide.html#autotoc_md105", [
        [ "Creating a Server", "http_guide.html#autotoc_md106", null ],
        [ "Request Handler", "http_guide.html#autotoc_md107", null ],
        [ "Running the Server", "http_guide.html#autotoc_md108", null ],
        [ "WebSocket Upgrade", "http_guide.html#autotoc_md109", null ]
      ] ],
      [ "Error Handling", "http_guide.html#autotoc_md111", [
        [ "Client Exceptions", "http_guide.html#autotoc_md112", null ],
        [ "Server Exceptions", "http_guide.html#autotoc_md113", null ]
      ] ],
      [ "Proxy Support", "http_guide.html#autotoc_md115", null ],
      [ "Advanced Topics", "http_guide.html#autotoc_md117", [
        [ "Streaming Requests", "http_guide.html#autotoc_md118", null ],
        [ "Custom TLS Context", "http_guide.html#autotoc_md119", null ],
        [ "Connection Pooling Behavior", "http_guide.html#autotoc_md120", null ]
      ] ],
      [ "Thread Safety", "http_guide.html#autotoc_md122", null ],
      [ "Performance Tips", "http_guide.html#autotoc_md124", null ],
      [ "See Also", "http_guide.html#autotoc_md126", [
        [ "HTTP/1.1 Parser Security Enhancements (Recent Fixes)", "http_guide.html#autotoc_md127", null ]
      ] ]
    ] ],
    [ "WebSocket Guide", "websocket_guide.html", [
      [ "Overview", "websocket_guide.html#autotoc_md129", null ],
      [ "Security Considerations", "websocket_guide.html#autotoc_md131", [
        [ "Key Security Features", "websocket_guide.html#autotoc_md132", null ],
        [ "Best Practices", "websocket_guide.html#autotoc_md133", null ],
        [ "Potential Risks & Mitigations", "websocket_guide.html#autotoc_md134", null ]
      ] ],
      [ "Quick Start", "websocket_guide.html#autotoc_md135", [
        [ "WebSocket Client", "websocket_guide.html#autotoc_md136", null ]
      ] ],
      [ "Client API", "websocket_guide.html#autotoc_md138", [
        [ "Creating a Client Connection", "websocket_guide.html#autotoc_md139", null ],
        [ "Configuration Options", "websocket_guide.html#autotoc_md140", null ],
        [ "Performing the Handshake", "websocket_guide.html#autotoc_md141", null ]
      ] ],
      [ "Server API", "websocket_guide.html#autotoc_md143", [
        [ "Accepting WebSocket Connections", "websocket_guide.html#autotoc_md144", null ],
        [ "Manual Server Setup", "websocket_guide.html#autotoc_md145", null ]
      ] ],
      [ "Sending Messages", "websocket_guide.html#autotoc_md147", [
        [ "Text Messages", "websocket_guide.html#autotoc_md148", null ],
        [ "Binary Messages", "websocket_guide.html#autotoc_md149", null ],
        [ "Control Frames", "websocket_guide.html#autotoc_md150", null ]
      ] ],
      [ "Receiving Messages", "websocket_guide.html#autotoc_md152", [
        [ "Complete Messages", "websocket_guide.html#autotoc_md153", null ],
        [ "Message Structure", "websocket_guide.html#autotoc_md154", null ]
      ] ],
      [ "Connection States", "websocket_guide.html#autotoc_md156", null ],
      [ "Close Codes", "websocket_guide.html#autotoc_md158", [
        [ "Closing a Connection", "websocket_guide.html#autotoc_md159", null ]
      ] ],
      [ "Event Loop Integration", "websocket_guide.html#autotoc_md161", [
        [ "Non-Blocking Operation", "websocket_guide.html#autotoc_md162", null ],
        [ "Auto-Ping", "websocket_guide.html#autotoc_md163", null ]
      ] ],
      [ "Compression (permessage-deflate)", "websocket_guide.html#autotoc_md165", null ],
      [ "Subprotocols", "websocket_guide.html#autotoc_md167", null ],
      [ "Error Handling", "websocket_guide.html#autotoc_md169", [
        [ "Error Codes", "websocket_guide.html#autotoc_md170", null ],
        [ "Exceptions", "websocket_guide.html#autotoc_md171", null ]
      ] ],
      [ "Best Practices", "websocket_guide.html#autotoc_md173", [
        [ "Security", "websocket_guide.html#autotoc_md174", null ],
        [ "Performance", "websocket_guide.html#autotoc_md175", null ],
        [ "Connection Management", "websocket_guide.html#autotoc_md176", null ]
      ] ],
      [ "Thread Safety", "websocket_guide.html#autotoc_md178", null ],
      [ "See Also", "websocket_guide.html#autotoc_md180", null ]
    ] ],
    [ "Proxy Guide", "proxy_guide.html", [
      [ "Overview", "proxy_guide.html#autotoc_md182", null ],
      [ "Quick Start", "proxy_guide.html#autotoc_md184", [
        [ "SOCKS5 Proxy", "proxy_guide.html#autotoc_md185", null ],
        [ "With Authentication", "proxy_guide.html#autotoc_md186", null ],
        [ "Using URL Parser", "proxy_guide.html#autotoc_md187", null ]
      ] ],
      [ "Proxy Types", "proxy_guide.html#autotoc_md189", [
        [ "HTTP CONNECT", "proxy_guide.html#autotoc_md190", null ],
        [ "HTTPS CONNECT", "proxy_guide.html#autotoc_md191", null ],
        [ "SOCKS4", "proxy_guide.html#autotoc_md192", null ],
        [ "SOCKS4a", "proxy_guide.html#autotoc_md193", null ],
        [ "SOCKS5 (RFC 1928)", "proxy_guide.html#autotoc_md194", null ],
        [ "SOCKS5H", "proxy_guide.html#autotoc_md195", null ]
      ] ],
      [ "Configuration", "proxy_guide.html#autotoc_md197", [
        [ "Full Configuration Structure", "proxy_guide.html#autotoc_md198", null ],
        [ "Default Ports", "proxy_guide.html#autotoc_md199", null ],
        [ "URL Parser", "proxy_guide.html#autotoc_md200", null ]
      ] ],
      [ "Synchronous API", "proxy_guide.html#autotoc_md202", [
        [ "Simple Connection", "proxy_guide.html#autotoc_md203", null ],
        [ "Using Existing Socket", "proxy_guide.html#autotoc_md204", null ]
      ] ],
      [ "Asynchronous API", "proxy_guide.html#autotoc_md206", [
        [ "Fully Async API (Recommended)", "proxy_guide.html#autotoc_md207", null ],
        [ "Blocking Connect API", "proxy_guide.html#autotoc_md208", null ],
        [ "Polling for Handshake", "proxy_guide.html#autotoc_md209", null ],
        [ "Processing Events", "proxy_guide.html#autotoc_md210", null ],
        [ "Getting Result", "proxy_guide.html#autotoc_md211", null ],
        [ "Cancellation", "proxy_guide.html#autotoc_md212", null ],
        [ "API Comparison", "proxy_guide.html#autotoc_md213", null ]
      ] ],
      [ "Result Codes", "proxy_guide.html#autotoc_md215", null ],
      [ "TLS Over Proxy", "proxy_guide.html#autotoc_md217", null ],
      [ "HTTP Client Integration", "proxy_guide.html#autotoc_md219", null ],
      [ "Security Considerations", "proxy_guide.html#autotoc_md221", [
        [ "Credential Handling", "proxy_guide.html#autotoc_md222", null ],
        [ "DNS Privacy", "proxy_guide.html#autotoc_md223", null ],
        [ "Response Validation", "proxy_guide.html#autotoc_md224", null ]
      ] ],
      [ "Error Handling", "proxy_guide.html#autotoc_md226", null ],
      [ "Connection State Machine", "proxy_guide.html#autotoc_md228", null ],
      [ "Best Practices", "proxy_guide.html#autotoc_md230", null ],
      [ "Thread Safety", "proxy_guide.html#autotoc_md232", null ],
      [ "See Also", "proxy_guide.html#autotoc_md234", null ]
    ] ],
    [ "Security Guide", "security_guide.html", [
      [ "TLS 1.3 Configuration", "security_guide.html#autotoc_md236", [
        [ "Default Configuration", "security_guide.html#autotoc_md237", null ],
        [ "TLS Settings (SocketTLSConfig.h)", "security_guide.html#autotoc_md238", null ],
        [ "Why TLS 1.3?", "security_guide.html#autotoc_md239", null ]
      ] ],
      [ "Certificate Transparency (CT)", "security_guide.html#autotoc_md241", [
        [ "Usage", "security_guide.html#autotoc_md242", null ],
        [ "Security Benefits", "security_guide.html#autotoc_md243", null ],
        [ "Requirements", "security_guide.html#autotoc_md244", null ],
        [ "Custom Logs", "security_guide.html#autotoc_md245", null ],
        [ "Verification", "security_guide.html#autotoc_md246", null ],
        [ "Limits", "security_guide.html#autotoc_md247", null ]
      ] ],
      [ "Certificate Pinning", "security_guide.html#autotoc_md248", [
        [ "SPKI SHA256 Pinning", "security_guide.html#autotoc_md249", null ],
        [ "When to Use Pinning", "security_guide.html#autotoc_md250", null ],
        [ "Pin Rotation", "security_guide.html#autotoc_md251", null ]
      ] ],
      [ "Input Validation", "security_guide.html#autotoc_md253", [
        [ "Hostname Validation", "security_guide.html#autotoc_md254", null ],
        [ "Port Validation", "security_guide.html#autotoc_md255", null ],
        [ "Buffer Size Validation", "security_guide.html#autotoc_md256", null ]
      ] ],
      [ "DNS Security", "security_guide.html#autotoc_md258", [
        [ "Blocking DNS Warning", "security_guide.html#autotoc_md259", null ],
        [ "DNS DoS Prevention", "security_guide.html#autotoc_md260", null ]
      ] ],
      [ "Credential Handling", "security_guide.html#autotoc_md262", [
        [ "Secure Memory Clearing", "security_guide.html#autotoc_md263", null ],
        [ "The Library Does This Internally", "security_guide.html#autotoc_md264", null ],
        [ "Constant-Time Comparison", "security_guide.html#autotoc_md265", null ]
      ] ],
      [ "DoS Protection", "security_guide.html#autotoc_md267", [
        [ "SYN Flood Protection", "security_guide.html#autotoc_md268", null ],
        [ "Rate Limiting", "security_guide.html#autotoc_md269", null ],
        [ "Per-IP Connection Limits", "security_guide.html#autotoc_md270", null ]
      ] ],
      [ "Thread Safety", "security_guide.html#autotoc_md272", [
        [ "Thread-Local Error Buffers", "security_guide.html#autotoc_md273", null ],
        [ "Exception Thread Safety", "security_guide.html#autotoc_md274", null ],
        [ "What's NOT Thread-Safe", "security_guide.html#autotoc_md275", null ]
      ] ],
      [ "Exception Handling", "security_guide.html#autotoc_md277", [
        [ "Always Handle Security Exceptions", "security_guide.html#autotoc_md278", null ],
        [ "Don't Ignore Verification Failures", "security_guide.html#autotoc_md279", null ]
      ] ],
      [ "HTTP Security", "security_guide.html#autotoc_md281", [
        [ "Request Smuggling Prevention", "security_guide.html#autotoc_md282", null ],
        [ "WebSocket Security", "security_guide.html#autotoc_md283", null ],
        [ "Cookie Security", "security_guide.html#autotoc_md284", null ],
        [ "HTTP/2 Flow Control Hardening", "security_guide.html#autotoc_md285", null ]
      ] ],
      [ "File Descriptor Hygiene", "security_guide.html#autotoc_md287", [
        [ "Safe Close", "security_guide.html#autotoc_md288", null ],
        [ "Prevent FD Leaks", "security_guide.html#autotoc_md289", null ]
      ] ],
      [ "Audit Logging", "security_guide.html#autotoc_md291", [
        [ "What to Log", "security_guide.html#autotoc_md292", null ],
        [ "How to Log Safely", "security_guide.html#autotoc_md293", null ]
      ] ],
      [ "Security Checklist", "security_guide.html#autotoc_md295", [
        [ "Server Applications", "security_guide.html#autotoc_md296", null ],
        [ "Client Applications", "security_guide.html#autotoc_md297", null ],
        [ "General", "security_guide.html#autotoc_md298", null ]
      ] ],
      [ "TLS Configuration Best Practices", "security_guide.html#autotoc_md300", [
        [ "Protocol Version", "security_guide.html#autotoc_md301", null ],
        [ "Cipher Suite Configuration", "security_guide.html#autotoc_md302", null ],
        [ "Certificate Verification", "security_guide.html#autotoc_md303", null ],
        [ "Mutual TLS (mTLS)", "security_guide.html#autotoc_md304", null ],
        [ "OCSP Stapling", "security_guide.html#autotoc_md305", null ],
        [ "Certificate Transparency", "security_guide.html#autotoc_md306", null ],
        [ "Certificate Revocation Lists (CRL)", "security_guide.html#autotoc_md307", null ],
        [ "Session Resumption Security", "security_guide.html#autotoc_md308", null ],
        [ "Renegotiation Protection", "security_guide.html#autotoc_md309", null ],
        [ "Private Key Protection", "security_guide.html#autotoc_md310", null ],
        [ "TLS Security Checklist", "security_guide.html#autotoc_md311", null ]
      ] ],
      [ "See Also", "security_guide.html#autotoc_md313", null ]
    ] ],
    [ "Migration Guide", "migration_guide.html", [
      [ "Migration from BSD Sockets", "migration_guide.html#autotoc_md315", [
        [ "Socket Creation", "migration_guide.html#autotoc_md316", null ],
        [ "Connecting", "migration_guide.html#autotoc_md317", null ],
        [ "Sending Data", "migration_guide.html#autotoc_md318", null ],
        [ "Socket Options", "migration_guide.html#autotoc_md319", null ],
        [ "API Mapping (BSD -> Socket Library)", "migration_guide.html#autotoc_md320", null ]
      ] ],
      [ "Migration from libcurl", "migration_guide.html#autotoc_md322", [
        [ "Simple GET Request", "migration_guide.html#autotoc_md323", null ],
        [ "POST Request", "migration_guide.html#autotoc_md324", null ],
        [ "Custom Headers", "migration_guide.html#autotoc_md325", null ],
        [ "Proxy Configuration", "migration_guide.html#autotoc_md326", null ],
        [ "Error Handling", "migration_guide.html#autotoc_md327", null ],
        [ "API Mapping (libcurl -> Socket Library)", "migration_guide.html#autotoc_md328", null ]
      ] ],
      [ "Migration from libevent", "migration_guide.html#autotoc_md330", [
        [ "Event Loop", "migration_guide.html#autotoc_md331", null ],
        [ "Callback Style", "migration_guide.html#autotoc_md332", null ],
        [ "Timers", "migration_guide.html#autotoc_md333", null ],
        [ "API Mapping (libevent -> Socket Library)", "migration_guide.html#autotoc_md334", null ]
      ] ],
      [ "Migration from libev", "migration_guide.html#autotoc_md336", [
        [ "Event Loop", "migration_guide.html#autotoc_md337", null ]
      ] ],
      [ "Migration from OpenSSL Direct", "migration_guide.html#autotoc_md339", [
        [ "TLS Client", "migration_guide.html#autotoc_md340", null ],
        [ "API Mapping (OpenSSL -> Socket Library)", "migration_guide.html#autotoc_md341", null ]
      ] ],
      [ "Common Patterns", "migration_guide.html#autotoc_md343", [
        [ "Error Handling Pattern", "migration_guide.html#autotoc_md344", null ],
        [ "Resource Cleanup Pattern", "migration_guide.html#autotoc_md345", null ]
      ] ],
      [ "Key Differences", "migration_guide.html#autotoc_md347", [
        [ "Memory Management", "migration_guide.html#autotoc_md348", null ],
        [ "Error Handling", "migration_guide.html#autotoc_md349", null ],
        [ "Thread Safety", "migration_guide.html#autotoc_md350", null ]
      ] ],
      [ "Getting Started", "migration_guide.html#autotoc_md352", null ],
      [ "See Also", "migration_guide.html#autotoc_md354", null ]
    ] ],
    [ "Topics", "topics.html", "topics" ],
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
    ] ],
    [ "Examples", "examples.html", "examples" ]
  ] ]
];

var NAVTREEINDEX =
[
"Arena_8h.html",
"group__async__io.html#gae0ecf4f023555d16b855d39841521f2b",
"group__core__io.html#ga38939e0f4010e9cc311360b1d974d068",
"group__core__io.html#ggaf9f1c72bfcb303aa9ee5dae6d903b9bea93b0009c07bfe02286b9151523792043",
"group__foundation.html#ga48f3e3abb4afe6f9031f1df9c0796718",
"group__foundation.html#gga422e43ad3ca4ce64261dda7879e73e5aa7e78a886cdc9334f8a7b5f0df750fd63",
"group__http.html#ga07b465d99995da22fc317dc170d09787",
"group__http.html#gadea7c22d784dde56835abffcd57ee516",
"group__http.html#structSocketHTTPClient__Response",
"group__security.html#ad6ecd5f04a5c197c4a740ee02611fdae",
"group__utilities.html#a939cbbd0e2c2537391a2e970991a1c9d",
"proxy_guide.html#autotoc_md189"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';