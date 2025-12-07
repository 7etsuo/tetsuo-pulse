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
    [ "Features", "index.html#autotoc_md3", [
      [ "Core Networking", "index.html#autotoc_md4", null ],
      [ "Async & Event-Driven", "index.html#autotoc_md5", null ],
      [ "Performance", "index.html#autotoc_md6", null ]
    ] ],
    [ "Quick Start", "index.html#autotoc_md8", null ],
    [ "Examples", "index.html#autotoc_md10", [
      [ "TCP Echo Server", "index.html#autotoc_md11", null ],
      [ "TCP Client", "index.html#autotoc_md13", null ],
      [ "Event-Driven Server (Non-Blocking)", "index.html#autotoc_md15", null ],
      [ "UDP Echo Server", "index.html#autotoc_md17", null ],
      [ "UDP Client", "index.html#autotoc_md19", null ],
      [ "TLS Client (Secure Connection)", "index.html#autotoc_md21", null ],
      [ "Unix Domain Socket Server", "index.html#autotoc_md23", null ],
      [ "Happy Eyeballs (Fast Dual-Stack)", "index.html#autotoc_md25", null ],
      [ "Auto-Reconnecting Client", "index.html#autotoc_md27", null ],
      [ "Connection Pool with Buffers", "index.html#autotoc_md29", null ],
      [ "Async DNS Resolution", "index.html#autotoc_md31", null ],
      [ "Zero-Copy File Transfer", "index.html#autotoc_md33", null ],
      [ "Scatter/Gather I/O", "index.html#autotoc_md35", null ],
      [ "Advanced TCP Options", "index.html#autotoc_md37", null ]
    ] ],
    [ "Header Files", "index.html#autotoc_md39", null ],
    [ "Error Handling", "index.html#autotoc_md41", [
      [ "Exception Types", "index.html#autotoc_md42", null ]
    ] ],
    [ "Platform Support", "index.html#autotoc_md44", null ],
    [ "Documentation", "index.html#autotoc_md46", [
      [ "API Reference", "index.html#autotoc_md47", null ],
      [ "Guides", "index.html#autotoc_md48", null ],
      [ "Examples", "index.html#autotoc_md49", null ]
    ] ],
    [ "Asynchronous I/O Guide", "async_io_guide.html", [
      [ "Overview", "async_io_guide.html#autotoc_md50", null ],
      [ "Platform Support", "async_io_guide.html#autotoc_md51", null ],
      [ "Key Benefits", "async_io_guide.html#autotoc_md52", null ],
      [ "Basic Usage", "async_io_guide.html#autotoc_md53", [
        [ "Getting Async Context", "async_io_guide.html#autotoc_md54", null ],
        [ "Async Send", "async_io_guide.html#autotoc_md55", null ],
        [ "Async Receive", "async_io_guide.html#autotoc_md56", null ],
        [ "Processing Completions", "async_io_guide.html#autotoc_md57", null ],
        [ "Cancellation", "async_io_guide.html#autotoc_md58", null ]
      ] ],
      [ "Complete Example: Echo Server", "async_io_guide.html#autotoc_md59", null ],
      [ "Performance Tuning", "async_io_guide.html#autotoc_md60", [
        [ "io_uring (Linux)", "async_io_guide.html#autotoc_md61", null ],
        [ "kqueue (macOS/BSD)", "async_io_guide.html#autotoc_md62", null ]
      ] ],
      [ "Fallback Mode", "async_io_guide.html#autotoc_md63", null ],
      [ "Thread Safety", "async_io_guide.html#autotoc_md64", null ],
      [ "Error Handling", "async_io_guide.html#autotoc_md65", null ],
      [ "Migration Guide", "async_io_guide.html#autotoc_md66", [
        [ "From Synchronous to Async", "async_io_guide.html#autotoc_md67", null ]
      ] ],
      [ "Best Practices", "async_io_guide.html#autotoc_md68", null ],
      [ "Limitations", "async_io_guide.html#autotoc_md69", null ],
      [ "Troubleshooting", "async_io_guide.html#autotoc_md70", [
        [ "Async Not Available", "async_io_guide.html#autotoc_md71", null ],
        [ "High CPU Usage", "async_io_guide.html#autotoc_md72", null ],
        [ "Memory Leaks", "async_io_guide.html#autotoc_md73", null ]
      ] ],
      [ "API Reference", "async_io_guide.html#autotoc_md74", null ],
      [ "Performance Benchmarks", "async_io_guide.html#autotoc_md75", null ]
    ] ],
    [ "HTTP Guide", "http_guide.html", [
      [ "Quick Start", "http_guide.html#autotoc_md77", [
        [ "Simple HTTP GET", "http_guide.html#autotoc_md78", null ],
        [ "Simple HTTP POST", "http_guide.html#autotoc_md79", null ]
      ] ],
      [ "HTTP Client API", "http_guide.html#autotoc_md81", [
        [ "Creating a Client", "http_guide.html#autotoc_md82", null ],
        [ "Configuration Options", "http_guide.html#autotoc_md83", null ],
        [ "Simple API", "http_guide.html#autotoc_md84", null ],
        [ "Request Builder API", "http_guide.html#autotoc_md85", null ],
        [ "Response Handling", "http_guide.html#autotoc_md86", null ]
      ] ],
      [ "Authentication", "http_guide.html#autotoc_md88", [
        [ "Supported Authentication Types", "http_guide.html#autotoc_md89", null ],
        [ "Basic Authentication (RFC 7617)", "http_guide.html#autotoc_md90", null ],
        [ "Digest Authentication (RFC 7616)", "http_guide.html#autotoc_md91", null ],
        [ "Bearer Token (RFC 6750)", "http_guide.html#autotoc_md92", null ],
        [ "Credential Security", "http_guide.html#autotoc_md93", null ],
        [ "Automatic 401 Retry", "http_guide.html#autotoc_md94", null ]
      ] ],
      [ "Cookie Handling", "http_guide.html#autotoc_md96", null ],
      [ "HTTP/2 Features", "http_guide.html#autotoc_md98", [
        [ "Flow Control Security Enhancements", "http_guide.html#autotoc_md99", null ],
        [ "Checking Protocol Version", "http_guide.html#autotoc_md100", null ],
        [ "HTTP/2 Benefits", "http_guide.html#autotoc_md101", null ],
        [ "HTTP/2 Cleartext (h2c)", "http_guide.html#autotoc_md102", null ]
      ] ],
      [ "HTTP Server API", "http_guide.html#autotoc_md104", [
        [ "Creating a Server", "http_guide.html#autotoc_md105", null ],
        [ "Request Handler", "http_guide.html#autotoc_md106", null ],
        [ "Running the Server", "http_guide.html#autotoc_md107", null ],
        [ "WebSocket Upgrade", "http_guide.html#autotoc_md108", null ]
      ] ],
      [ "Error Handling", "http_guide.html#autotoc_md110", [
        [ "Client Exceptions", "http_guide.html#autotoc_md111", null ],
        [ "Server Exceptions", "http_guide.html#autotoc_md112", null ]
      ] ],
      [ "Proxy Support", "http_guide.html#autotoc_md114", null ],
      [ "Advanced Topics", "http_guide.html#autotoc_md116", [
        [ "Streaming Requests", "http_guide.html#autotoc_md117", null ],
        [ "Custom TLS Context", "http_guide.html#autotoc_md118", null ],
        [ "Connection Pooling Behavior", "http_guide.html#autotoc_md119", null ]
      ] ],
      [ "Thread Safety", "http_guide.html#autotoc_md121", null ],
      [ "Performance Tips", "http_guide.html#autotoc_md123", null ],
      [ "See Also", "http_guide.html#autotoc_md125", null ]
    ] ],
    [ "WebSocket Guide", "websocket_guide.html", [
      [ "Overview", "websocket_guide.html#autotoc_md127", null ],
      [ "Security Considerations", "websocket_guide.html#autotoc_md129", [
        [ "Key Security Features", "websocket_guide.html#autotoc_md130", null ],
        [ "Best Practices", "websocket_guide.html#autotoc_md131", null ],
        [ "Potential Risks & Mitigations", "websocket_guide.html#autotoc_md132", null ]
      ] ],
      [ "Quick Start", "websocket_guide.html#autotoc_md133", [
        [ "WebSocket Client", "websocket_guide.html#autotoc_md134", null ]
      ] ],
      [ "Client API", "websocket_guide.html#autotoc_md136", [
        [ "Creating a Client Connection", "websocket_guide.html#autotoc_md137", null ],
        [ "Configuration Options", "websocket_guide.html#autotoc_md138", null ],
        [ "Performing the Handshake", "websocket_guide.html#autotoc_md139", null ]
      ] ],
      [ "Server API", "websocket_guide.html#autotoc_md141", [
        [ "Accepting WebSocket Connections", "websocket_guide.html#autotoc_md142", null ],
        [ "Manual Server Setup", "websocket_guide.html#autotoc_md143", null ]
      ] ],
      [ "Sending Messages", "websocket_guide.html#autotoc_md145", [
        [ "Text Messages", "websocket_guide.html#autotoc_md146", null ],
        [ "Binary Messages", "websocket_guide.html#autotoc_md147", null ],
        [ "Control Frames", "websocket_guide.html#autotoc_md148", null ]
      ] ],
      [ "Receiving Messages", "websocket_guide.html#autotoc_md150", [
        [ "Complete Messages", "websocket_guide.html#autotoc_md151", null ],
        [ "Message Structure", "websocket_guide.html#autotoc_md152", null ]
      ] ],
      [ "Connection States", "websocket_guide.html#autotoc_md154", null ],
      [ "Close Codes", "websocket_guide.html#autotoc_md156", [
        [ "Closing a Connection", "websocket_guide.html#autotoc_md157", null ]
      ] ],
      [ "Event Loop Integration", "websocket_guide.html#autotoc_md159", [
        [ "Non-Blocking Operation", "websocket_guide.html#autotoc_md160", null ],
        [ "Auto-Ping", "websocket_guide.html#autotoc_md161", null ]
      ] ],
      [ "Compression (permessage-deflate)", "websocket_guide.html#autotoc_md163", null ],
      [ "Subprotocols", "websocket_guide.html#autotoc_md165", null ],
      [ "Error Handling", "websocket_guide.html#autotoc_md167", [
        [ "Error Codes", "websocket_guide.html#autotoc_md168", null ],
        [ "Exceptions", "websocket_guide.html#autotoc_md169", null ]
      ] ],
      [ "Best Practices", "websocket_guide.html#autotoc_md171", [
        [ "Security", "websocket_guide.html#autotoc_md172", null ],
        [ "Performance", "websocket_guide.html#autotoc_md173", null ],
        [ "Connection Management", "websocket_guide.html#autotoc_md174", null ]
      ] ],
      [ "Thread Safety", "websocket_guide.html#autotoc_md176", null ],
      [ "See Also", "websocket_guide.html#autotoc_md178", null ]
    ] ],
    [ "Proxy Guide", "proxy_guide.html", [
      [ "Overview", "proxy_guide.html#autotoc_md180", null ],
      [ "Quick Start", "proxy_guide.html#autotoc_md182", [
        [ "SOCKS5 Proxy", "proxy_guide.html#autotoc_md183", null ],
        [ "With Authentication", "proxy_guide.html#autotoc_md184", null ],
        [ "Using URL Parser", "proxy_guide.html#autotoc_md185", null ]
      ] ],
      [ "Proxy Types", "proxy_guide.html#autotoc_md187", [
        [ "HTTP CONNECT", "proxy_guide.html#autotoc_md188", null ],
        [ "HTTPS CONNECT", "proxy_guide.html#autotoc_md189", null ],
        [ "SOCKS4", "proxy_guide.html#autotoc_md190", null ],
        [ "SOCKS4a", "proxy_guide.html#autotoc_md191", null ],
        [ "SOCKS5 (RFC 1928)", "proxy_guide.html#autotoc_md192", null ],
        [ "SOCKS5H", "proxy_guide.html#autotoc_md193", null ]
      ] ],
      [ "Configuration", "proxy_guide.html#autotoc_md195", [
        [ "Full Configuration Structure", "proxy_guide.html#autotoc_md196", null ],
        [ "Default Ports", "proxy_guide.html#autotoc_md197", null ],
        [ "URL Parser", "proxy_guide.html#autotoc_md198", null ]
      ] ],
      [ "Synchronous API", "proxy_guide.html#autotoc_md200", [
        [ "Simple Connection", "proxy_guide.html#autotoc_md201", null ],
        [ "Using Existing Socket", "proxy_guide.html#autotoc_md202", null ]
      ] ],
      [ "Asynchronous API", "proxy_guide.html#autotoc_md204", [
        [ "Fully Async API (Recommended)", "proxy_guide.html#autotoc_md205", null ],
        [ "Blocking Connect API", "proxy_guide.html#autotoc_md206", null ],
        [ "Polling for Handshake", "proxy_guide.html#autotoc_md207", null ],
        [ "Processing Events", "proxy_guide.html#autotoc_md208", null ],
        [ "Getting Result", "proxy_guide.html#autotoc_md209", null ],
        [ "Cancellation", "proxy_guide.html#autotoc_md210", null ],
        [ "API Comparison", "proxy_guide.html#autotoc_md211", null ]
      ] ],
      [ "Result Codes", "proxy_guide.html#autotoc_md213", null ],
      [ "TLS Over Proxy", "proxy_guide.html#autotoc_md215", null ],
      [ "HTTP Client Integration", "proxy_guide.html#autotoc_md217", null ],
      [ "Security Considerations", "proxy_guide.html#autotoc_md219", [
        [ "Credential Handling", "proxy_guide.html#autotoc_md220", null ],
        [ "DNS Privacy", "proxy_guide.html#autotoc_md221", null ],
        [ "Response Validation", "proxy_guide.html#autotoc_md222", null ]
      ] ],
      [ "Error Handling", "proxy_guide.html#autotoc_md224", null ],
      [ "Connection State Machine", "proxy_guide.html#autotoc_md226", null ],
      [ "Best Practices", "proxy_guide.html#autotoc_md228", null ],
      [ "Thread Safety", "proxy_guide.html#autotoc_md230", null ],
      [ "See Also", "proxy_guide.html#autotoc_md232", null ]
    ] ],
    [ "Security Guide", "security_guide.html", [
      [ "TLS 1.3 Configuration", "security_guide.html#autotoc_md234", [
        [ "Default Configuration", "security_guide.html#autotoc_md235", null ],
        [ "TLS Settings (SocketTLSConfig.h)", "security_guide.html#autotoc_md236", null ],
        [ "Why TLS 1.3?", "security_guide.html#autotoc_md237", null ]
      ] ],
      [ "Certificate Transparency (CT)", "security_guide.html#autotoc_md239", [
        [ "Usage", "security_guide.html#autotoc_md240", null ],
        [ "Security Benefits", "security_guide.html#autotoc_md241", null ],
        [ "Requirements", "security_guide.html#autotoc_md242", null ],
        [ "Custom Logs", "security_guide.html#autotoc_md243", null ],
        [ "Verification", "security_guide.html#autotoc_md244", null ],
        [ "Limits", "security_guide.html#autotoc_md245", null ]
      ] ],
      [ "Certificate Pinning", "security_guide.html#autotoc_md246", [
        [ "SPKI SHA256 Pinning", "security_guide.html#autotoc_md247", null ],
        [ "When to Use Pinning", "security_guide.html#autotoc_md248", null ],
        [ "Pin Rotation", "security_guide.html#autotoc_md249", null ]
      ] ],
      [ "Input Validation", "security_guide.html#autotoc_md251", [
        [ "Hostname Validation", "security_guide.html#autotoc_md252", null ],
        [ "Port Validation", "security_guide.html#autotoc_md253", null ],
        [ "Buffer Size Validation", "security_guide.html#autotoc_md254", null ]
      ] ],
      [ "DNS Security", "security_guide.html#autotoc_md256", [
        [ "Blocking DNS Warning", "security_guide.html#autotoc_md257", null ],
        [ "DNS DoS Prevention", "security_guide.html#autotoc_md258", null ]
      ] ],
      [ "Credential Handling", "security_guide.html#autotoc_md260", [
        [ "Secure Memory Clearing", "security_guide.html#autotoc_md261", null ],
        [ "The Library Does This Internally", "security_guide.html#autotoc_md262", null ],
        [ "Constant-Time Comparison", "security_guide.html#autotoc_md263", null ]
      ] ],
      [ "DoS Protection", "security_guide.html#autotoc_md265", [
        [ "SYN Flood Protection", "security_guide.html#autotoc_md266", null ],
        [ "Rate Limiting", "security_guide.html#autotoc_md267", null ],
        [ "Per-IP Connection Limits", "security_guide.html#autotoc_md268", null ]
      ] ],
      [ "Thread Safety", "security_guide.html#autotoc_md270", [
        [ "Thread-Local Error Buffers", "security_guide.html#autotoc_md271", null ],
        [ "Exception Thread Safety", "security_guide.html#autotoc_md272", null ],
        [ "What's NOT Thread-Safe", "security_guide.html#autotoc_md273", null ]
      ] ],
      [ "Exception Handling", "security_guide.html#autotoc_md275", [
        [ "Always Handle Security Exceptions", "security_guide.html#autotoc_md276", null ],
        [ "Don't Ignore Verification Failures", "security_guide.html#autotoc_md277", null ]
      ] ],
      [ "HTTP Security", "security_guide.html#autotoc_md279", [
        [ "Request Smuggling Prevention", "security_guide.html#autotoc_md280", null ],
        [ "WebSocket Security", "security_guide.html#autotoc_md281", null ],
        [ "Cookie Security", "security_guide.html#autotoc_md282", null ],
        [ "HTTP/2 Flow Control Hardening", "security_guide.html#autotoc_md283", null ]
      ] ],
      [ "File Descriptor Hygiene", "security_guide.html#autotoc_md285", [
        [ "Safe Close", "security_guide.html#autotoc_md286", null ],
        [ "Prevent FD Leaks", "security_guide.html#autotoc_md287", null ]
      ] ],
      [ "Audit Logging", "security_guide.html#autotoc_md289", [
        [ "What to Log", "security_guide.html#autotoc_md290", null ],
        [ "How to Log Safely", "security_guide.html#autotoc_md291", null ]
      ] ],
      [ "Security Checklist", "security_guide.html#autotoc_md293", [
        [ "Server Applications", "security_guide.html#autotoc_md294", null ],
        [ "Client Applications", "security_guide.html#autotoc_md295", null ],
        [ "General", "security_guide.html#autotoc_md296", null ]
      ] ],
      [ "TLS Configuration Best Practices", "security_guide.html#autotoc_md298", [
        [ "Protocol Version", "security_guide.html#autotoc_md299", null ],
        [ "Cipher Suite Configuration", "security_guide.html#autotoc_md300", null ],
        [ "Certificate Verification", "security_guide.html#autotoc_md301", null ],
        [ "Mutual TLS (mTLS)", "security_guide.html#autotoc_md302", null ],
        [ "OCSP Stapling", "security_guide.html#autotoc_md303", null ],
        [ "Certificate Transparency", "security_guide.html#autotoc_md304", null ],
        [ "Certificate Revocation Lists (CRL)", "security_guide.html#autotoc_md305", null ],
        [ "Session Resumption Security", "security_guide.html#autotoc_md306", null ],
        [ "Renegotiation Protection", "security_guide.html#autotoc_md307", null ],
        [ "Private Key Protection", "security_guide.html#autotoc_md308", null ],
        [ "TLS Security Checklist", "security_guide.html#autotoc_md309", null ]
      ] ],
      [ "See Also", "security_guide.html#autotoc_md311", null ]
    ] ],
    [ "Migration Guide", "migration_guide.html", [
      [ "Migration from BSD Sockets", "migration_guide.html#autotoc_md313", [
        [ "Socket Creation", "migration_guide.html#autotoc_md314", null ],
        [ "Connecting", "migration_guide.html#autotoc_md315", null ],
        [ "Sending Data", "migration_guide.html#autotoc_md316", null ],
        [ "Socket Options", "migration_guide.html#autotoc_md317", null ],
        [ "API Mapping (BSD -> Socket Library)", "migration_guide.html#autotoc_md318", null ]
      ] ],
      [ "Migration from libcurl", "migration_guide.html#autotoc_md320", [
        [ "Simple GET Request", "migration_guide.html#autotoc_md321", null ],
        [ "POST Request", "migration_guide.html#autotoc_md322", null ],
        [ "Custom Headers", "migration_guide.html#autotoc_md323", null ],
        [ "Proxy Configuration", "migration_guide.html#autotoc_md324", null ],
        [ "Error Handling", "migration_guide.html#autotoc_md325", null ],
        [ "API Mapping (libcurl -> Socket Library)", "migration_guide.html#autotoc_md326", null ]
      ] ],
      [ "Migration from libevent", "migration_guide.html#autotoc_md328", [
        [ "Event Loop", "migration_guide.html#autotoc_md329", null ],
        [ "Callback Style", "migration_guide.html#autotoc_md330", null ],
        [ "Timers", "migration_guide.html#autotoc_md331", null ],
        [ "API Mapping (libevent -> Socket Library)", "migration_guide.html#autotoc_md332", null ]
      ] ],
      [ "Migration from libev", "migration_guide.html#autotoc_md334", [
        [ "Event Loop", "migration_guide.html#autotoc_md335", null ]
      ] ],
      [ "Migration from OpenSSL Direct", "migration_guide.html#autotoc_md337", [
        [ "TLS Client", "migration_guide.html#autotoc_md338", null ],
        [ "API Mapping (OpenSSL -> Socket Library)", "migration_guide.html#autotoc_md339", null ]
      ] ],
      [ "Common Patterns", "migration_guide.html#autotoc_md341", [
        [ "Error Handling Pattern", "migration_guide.html#autotoc_md342", null ],
        [ "Resource Cleanup Pattern", "migration_guide.html#autotoc_md343", null ]
      ] ],
      [ "Key Differences", "migration_guide.html#autotoc_md345", [
        [ "Memory Management", "migration_guide.html#autotoc_md346", null ],
        [ "Error Handling", "migration_guide.html#autotoc_md347", null ],
        [ "Thread Safety", "migration_guide.html#autotoc_md348", null ]
      ] ],
      [ "Getting Started", "migration_guide.html#autotoc_md350", null ],
      [ "See Also", "migration_guide.html#autotoc_md352", null ]
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
"SocketConfig_8h.html#a8c43db9a86f5f49f85c535b7e01a9cd2",
"SocketDgram_8h.html#a08371cbf32cb15528b42e189f8267923",
"SocketHTTP2_8h.html#a553a90f9d384e7ac9667e03d146a873b",
"SocketHTTPClient_8h.html#a9a5d4cac43fdb9d880edef1dc778273a",
"SocketHappyEyeballs_8h.html#a07e470dce144233028bfd6d2193e8c03",
"SocketPoll_8h.html#a665b3363d16ab859ec60e69a792d1ff0",
"SocketReconnect_8h.html#aaa80956d1e58e84adfab7063e1936f95",
"SocketTLSContext_8h.html#a71084c00bec22f65b90301188868b759",
"SocketUtil_8h.html#acf807f3c720486767d282324cacd4908a4f7a06893610177371a7c901f5f7cbae",
"async_io_guide.html#autotoc_md71",
"migration_guide.html#autotoc_md326"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';