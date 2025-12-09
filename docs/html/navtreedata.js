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
    [ "Features", "index.html#autotoc_md801", [
      [ "Core Networking", "index.html#autotoc_md802", null ],
      [ "Async & Event-Driven", "index.html#autotoc_md803", null ],
      [ "Performance", "index.html#autotoc_md804", null ]
    ] ],
    [ "Quick Start", "index.html#autotoc_md806", null ],
    [ "Examples", "index.html#autotoc_md808", [
      [ "TCP Echo Server", "index.html#autotoc_md809", null ],
      [ "TCP Client", "index.html#autotoc_md811", null ],
      [ "Event-Driven Server (Non-Blocking)", "index.html#autotoc_md813", null ],
      [ "UDP Echo Server", "index.html#autotoc_md815", null ],
      [ "UDP Client", "index.html#autotoc_md817", null ],
      [ "TLS Client (Secure Connection)", "index.html#autotoc_md819", null ],
      [ "Unix Domain Socket Server", "index.html#autotoc_md821", null ],
      [ "Happy Eyeballs (Fast Dual-Stack)", "index.html#autotoc_md823", null ],
      [ "Auto-Reconnecting Client", "index.html#autotoc_md825", null ],
      [ "Connection Pool with Buffers", "index.html#autotoc_md827", null ],
      [ "Async DNS Resolution", "index.html#autotoc_md829", null ],
      [ "Zero-Copy File Transfer", "index.html#autotoc_md831", null ],
      [ "Scatter/Gather I/O", "index.html#autotoc_md833", null ],
      [ "Advanced TCP Options", "index.html#autotoc_md835", null ]
    ] ],
    [ "Header Files", "index.html#autotoc_md837", null ],
    [ "Error Handling", "index.html#autotoc_md839", [
      [ "Exception Types", "index.html#autotoc_md840", null ]
    ] ],
    [ "Platform Support", "index.html#autotoc_md842", null ],
    [ "Documentation", "index.html#autotoc_md844", [
      [ "API Reference", "index.html#autotoc_md845", null ],
      [ "Guides", "index.html#autotoc_md846", null ],
      [ "Examples", "index.html#autotoc_md847", null ]
    ] ],
    [ "Proxy Tunneling Guide", "proxy_guide.html", [
      [ "Overview", "proxy_guide.html#autotoc_md979", null ],
      [ "Quick Start", "proxy_guide.html#autotoc_md981", [
        [ "SOCKS5 Proxy", "proxy_guide.html#autotoc_md982", null ],
        [ "With Authentication", "proxy_guide.html#autotoc_md983", null ],
        [ "Using URL Parser", "proxy_guide.html#autotoc_md984", null ]
      ] ],
      [ "Proxy Types", "proxy_guide.html#autotoc_md986", [
        [ "HTTP CONNECT", "proxy_guide.html#autotoc_md987", null ],
        [ "HTTPS CONNECT", "proxy_guide.html#autotoc_md988", null ],
        [ "SOCKS4", "proxy_guide.html#autotoc_md989", null ],
        [ "SOCKS4a", "proxy_guide.html#autotoc_md990", null ],
        [ "SOCKS5 (RFC 1928)", "proxy_guide.html#autotoc_md991", null ],
        [ "SOCKS5H", "proxy_guide.html#autotoc_md992", null ]
      ] ],
      [ "Configuration", "proxy_guide.html#autotoc_md994", [
        [ "Full Configuration Structure", "proxy_guide.html#autotoc_md995", null ],
        [ "Default Ports", "proxy_guide.html#autotoc_md996", null ],
        [ "URL Format", "proxy_guide.html#url-format", null ],
        [ "URL Parser", "proxy_guide.html#autotoc_md997", null ]
      ] ],
      [ "Synchronous API", "proxy_guide.html#autotoc_md999", [
        [ "Simple Connection", "proxy_guide.html#autotoc_md1000", null ],
        [ "Using Existing Socket", "proxy_guide.html#custom-socket", null ]
      ] ],
      [ "Asynchronous API", "proxy_guide.html#async-api", [
        [ "Fully Async API (Recommended)", "proxy_guide.html#autotoc_md1002", null ],
        [ "Blocking Connect API", "proxy_guide.html#hybrid-api", null ],
        [ "Polling for Handshake", "proxy_guide.html#autotoc_md1003", null ],
        [ "Processing Events", "proxy_guide.html#autotoc_md1004", null ],
        [ "Getting Result", "proxy_guide.html#autotoc_md1005", null ],
        [ "Cancellation", "proxy_guide.html#autotoc_md1006", null ],
        [ "API Comparison", "proxy_guide.html#autotoc_md1007", null ]
      ] ],
      [ "Result Codes", "proxy_guide.html#autotoc_md1009", null ],
      [ "TLS Over Proxy", "proxy_guide.html#autotoc_md1011", null ],
      [ "HTTP Client Integration", "proxy_guide.html#autotoc_md1013", null ],
      [ "Security Considerations", "proxy_guide.html#autotoc_md1015", [
        [ "Credential Handling", "proxy_guide.html#autotoc_md1016", null ],
        [ "DNS Privacy", "proxy_guide.html#autotoc_md1017", null ],
        [ "Response Validation", "proxy_guide.html#autotoc_md1018", null ]
      ] ],
      [ "Error Handling", "proxy_guide.html#autotoc_md1020", null ],
      [ "Connection State Machine", "proxy_guide.html#autotoc_md1022", null ],
      [ "Best Practices", "proxy_guide.html#autotoc_md1024", null ],
      [ "Thread Safety", "proxy_guide.html#autotoc_md1026", null ],
      [ "Behaviors and Limitations", "proxy_guide.html#behaviors", [
        [ "Behaviors", "proxy_guide.html#autotoc_md1028", null ],
        [ "Limitations", "proxy_guide.html#autotoc_md1029", null ]
      ] ],
      [ "See Also", "proxy_guide.html#autotoc_md1030", null ]
    ] ],
    [ "Asynchronous I/O Guide", "async_io_guide.html", [
      [ "Overview", "async_io_guide.html#autotoc_md848", null ],
      [ "Platform Support", "async_io_guide.html#autotoc_md849", null ],
      [ "Key Benefits", "async_io_guide.html#autotoc_md850", null ],
      [ "Basic Usage", "async_io_guide.html#autotoc_md851", [
        [ "Getting Async Context", "async_io_guide.html#autotoc_md852", null ],
        [ "Async Send", "async_io_guide.html#autotoc_md853", null ],
        [ "Async Receive", "async_io_guide.html#autotoc_md854", null ],
        [ "Processing Completions", "async_io_guide.html#autotoc_md855", null ],
        [ "Cancellation", "async_io_guide.html#autotoc_md856", null ]
      ] ],
      [ "Complete Example: Echo Server", "async_io_guide.html#autotoc_md857", null ],
      [ "Performance Tuning", "async_io_guide.html#autotoc_md858", [
        [ "io_uring (Linux)", "async_io_guide.html#autotoc_md859", null ],
        [ "kqueue (macOS/BSD)", "async_io_guide.html#autotoc_md860", null ]
      ] ],
      [ "Fallback Mode", "async_io_guide.html#autotoc_md861", null ],
      [ "Thread Safety", "async_io_guide.html#autotoc_md862", null ],
      [ "Error Handling", "async_io_guide.html#autotoc_md863", null ],
      [ "Migration Guide", "async_io_guide.html#autotoc_md864", [
        [ "From Synchronous to Async", "async_io_guide.html#autotoc_md865", null ]
      ] ],
      [ "Best Practices", "async_io_guide.html#autotoc_md866", null ],
      [ "Limitations", "async_io_guide.html#autotoc_md867", null ],
      [ "Troubleshooting", "async_io_guide.html#autotoc_md868", [
        [ "Async Not Available", "async_io_guide.html#autotoc_md869", null ],
        [ "High CPU Usage", "async_io_guide.html#autotoc_md870", null ],
        [ "Memory Leaks", "async_io_guide.html#autotoc_md871", null ]
      ] ],
      [ "API Reference", "async_io_guide.html#autotoc_md872", null ],
      [ "Performance Benchmarks", "async_io_guide.html#autotoc_md873", null ]
    ] ],
    [ "HTTP Guide", "http_guide.html", [
      [ "Quick Start", "http_guide.html#autotoc_md875", [
        [ "Simple HTTP GET", "http_guide.html#autotoc_md876", null ],
        [ "Simple HTTP POST", "http_guide.html#autotoc_md877", null ]
      ] ],
      [ "HTTP Client API", "http_guide.html#autotoc_md879", [
        [ "Creating a Client", "http_guide.html#autotoc_md880", null ],
        [ "Configuration Options", "http_guide.html#autotoc_md881", null ],
        [ "Simple API", "http_guide.html#autotoc_md882", null ],
        [ "Request Builder API", "http_guide.html#autotoc_md883", null ],
        [ "Response Handling", "http_guide.html#autotoc_md884", null ]
      ] ],
      [ "Authentication", "http_guide.html#autotoc_md886", [
        [ "Supported Authentication Types", "http_guide.html#autotoc_md887", null ],
        [ "Basic Authentication (RFC 7617)", "http_guide.html#autotoc_md888", null ],
        [ "Digest Authentication (RFC 7616)", "http_guide.html#autotoc_md889", null ],
        [ "Bearer Token (RFC 6750)", "http_guide.html#autotoc_md890", null ],
        [ "Credential Security", "http_guide.html#autotoc_md891", null ],
        [ "Automatic 401 Retry", "http_guide.html#autotoc_md892", null ]
      ] ],
      [ "Cookie Handling", "http_guide.html#autotoc_md894", null ],
      [ "HTTP/2 Features", "http_guide.html#autotoc_md896", [
        [ "Flow Control Security Enhancements", "http_guide.html#autotoc_md897", null ],
        [ "Checking Protocol Version", "http_guide.html#autotoc_md898", null ],
        [ "HTTP/2 Benefits", "http_guide.html#autotoc_md899", null ],
        [ "HTTP/2 Cleartext (h2c)", "http_guide.html#autotoc_md900", null ]
      ] ],
      [ "HTTP Server API", "http_guide.html#autotoc_md902", [
        [ "Creating a Server", "http_guide.html#autotoc_md903", null ],
        [ "Request Handler", "http_guide.html#autotoc_md904", null ],
        [ "Running the Server", "http_guide.html#autotoc_md905", null ],
        [ "WebSocket Upgrade", "http_guide.html#autotoc_md906", null ]
      ] ],
      [ "Error Handling", "http_guide.html#autotoc_md908", [
        [ "Client Exceptions", "http_guide.html#autotoc_md909", null ],
        [ "Server Exceptions", "http_guide.html#autotoc_md910", null ]
      ] ],
      [ "Proxy Support", "http_guide.html#autotoc_md912", null ],
      [ "Advanced Topics", "http_guide.html#autotoc_md914", [
        [ "Streaming Requests", "http_guide.html#autotoc_md915", null ],
        [ "Custom TLS Context", "http_guide.html#autotoc_md916", null ],
        [ "Connection Pooling Behavior", "http_guide.html#autotoc_md917", null ]
      ] ],
      [ "Thread Safety", "http_guide.html#autotoc_md919", null ],
      [ "Performance Tips", "http_guide.html#autotoc_md921", null ],
      [ "See Also", "http_guide.html#autotoc_md923", [
        [ "HTTP/1.1 Parser Security Enhancements (Recent Fixes)", "http_guide.html#autotoc_md924", null ]
      ] ]
    ] ],
    [ "WebSocket Guide", "websocket_guide.html", [
      [ "Overview", "websocket_guide.html#autotoc_md926", null ],
      [ "Security Considerations", "websocket_guide.html#autotoc_md928", [
        [ "Key Security Features", "websocket_guide.html#autotoc_md929", null ],
        [ "Best Practices", "websocket_guide.html#autotoc_md930", null ],
        [ "Potential Risks & Mitigations", "websocket_guide.html#autotoc_md931", null ]
      ] ],
      [ "Quick Start", "websocket_guide.html#autotoc_md932", [
        [ "WebSocket Client", "websocket_guide.html#autotoc_md933", null ]
      ] ],
      [ "Client API", "websocket_guide.html#autotoc_md935", [
        [ "Creating a Client Connection", "websocket_guide.html#autotoc_md936", null ],
        [ "Configuration Options", "websocket_guide.html#autotoc_md937", null ],
        [ "Performing the Handshake", "websocket_guide.html#autotoc_md938", null ]
      ] ],
      [ "Server API", "websocket_guide.html#autotoc_md940", [
        [ "Accepting WebSocket Connections", "websocket_guide.html#autotoc_md941", null ],
        [ "Manual Server Setup", "websocket_guide.html#autotoc_md942", null ]
      ] ],
      [ "Sending Messages", "websocket_guide.html#autotoc_md944", [
        [ "Text Messages", "websocket_guide.html#autotoc_md945", null ],
        [ "Binary Messages", "websocket_guide.html#autotoc_md946", null ],
        [ "Control Frames", "websocket_guide.html#autotoc_md947", null ]
      ] ],
      [ "Receiving Messages", "websocket_guide.html#autotoc_md949", [
        [ "Complete Messages", "websocket_guide.html#autotoc_md950", null ],
        [ "Message Structure", "websocket_guide.html#autotoc_md951", null ]
      ] ],
      [ "Connection States", "websocket_guide.html#autotoc_md953", null ],
      [ "Close Codes", "websocket_guide.html#autotoc_md955", [
        [ "Closing a Connection", "websocket_guide.html#autotoc_md956", null ]
      ] ],
      [ "Event Loop Integration", "websocket_guide.html#autotoc_md958", [
        [ "Non-Blocking Operation", "websocket_guide.html#autotoc_md959", null ],
        [ "Auto-Ping", "websocket_guide.html#autotoc_md960", null ]
      ] ],
      [ "Compression (permessage-deflate)", "websocket_guide.html#autotoc_md962", null ],
      [ "Subprotocols", "websocket_guide.html#autotoc_md964", null ],
      [ "Error Handling", "websocket_guide.html#autotoc_md966", [
        [ "Error Codes", "websocket_guide.html#autotoc_md967", null ],
        [ "Exceptions", "websocket_guide.html#autotoc_md968", null ]
      ] ],
      [ "Best Practices", "websocket_guide.html#autotoc_md970", [
        [ "Security", "websocket_guide.html#autotoc_md971", null ],
        [ "Performance", "websocket_guide.html#autotoc_md972", null ],
        [ "Connection Management", "websocket_guide.html#autotoc_md973", null ]
      ] ],
      [ "Thread Safety", "websocket_guide.html#autotoc_md975", null ],
      [ "See Also", "websocket_guide.html#autotoc_md977", null ]
    ] ],
    [ "Security Guide", "security_guide.html", [
      [ "TLS 1.3 Configuration", "security_guide.html#autotoc_md1032", [
        [ "Default Configuration", "security_guide.html#autotoc_md1033", null ],
        [ "TLS Settings (SocketTLSConfig.h)", "security_guide.html#autotoc_md1034", null ],
        [ "Why TLS 1.3?", "security_guide.html#autotoc_md1035", null ]
      ] ],
      [ "Certificate Transparency (CT)", "security_guide.html#autotoc_md1037", [
        [ "Usage", "security_guide.html#autotoc_md1038", null ],
        [ "Security Benefits", "security_guide.html#autotoc_md1039", null ],
        [ "Requirements", "security_guide.html#autotoc_md1040", null ],
        [ "Custom Logs", "security_guide.html#autotoc_md1041", null ],
        [ "Verification", "security_guide.html#autotoc_md1042", null ],
        [ "Limits", "security_guide.html#autotoc_md1043", null ]
      ] ],
      [ "Certificate Pinning", "security_guide.html#autotoc_md1044", [
        [ "SPKI SHA256 Pinning", "security_guide.html#autotoc_md1045", null ],
        [ "When to Use Pinning", "security_guide.html#autotoc_md1046", null ],
        [ "Pin Rotation", "security_guide.html#autotoc_md1047", null ]
      ] ],
      [ "Input Validation", "security_guide.html#autotoc_md1049", [
        [ "Hostname Validation", "security_guide.html#autotoc_md1050", null ],
        [ "Port Validation", "security_guide.html#autotoc_md1051", null ],
        [ "Buffer Size Validation", "security_guide.html#autotoc_md1052", null ]
      ] ],
      [ "DNS Security", "security_guide.html#autotoc_md1054", [
        [ "Blocking DNS Warning", "security_guide.html#autotoc_md1055", null ],
        [ "DNS DoS Prevention", "security_guide.html#autotoc_md1056", null ]
      ] ],
      [ "Credential Handling", "security_guide.html#autotoc_md1058", [
        [ "Secure Memory Clearing", "security_guide.html#autotoc_md1059", null ],
        [ "The Library Does This Internally", "security_guide.html#autotoc_md1060", null ],
        [ "Constant-Time Comparison", "security_guide.html#autotoc_md1061", null ]
      ] ],
      [ "DoS Protection", "security_guide.html#autotoc_md1063", [
        [ "SYN Flood Protection", "security_guide.html#autotoc_md1064", null ],
        [ "Rate Limiting", "security_guide.html#autotoc_md1065", null ],
        [ "Per-IP Connection Limits", "security_guide.html#autotoc_md1066", null ]
      ] ],
      [ "Thread Safety", "security_guide.html#autotoc_md1068", [
        [ "Thread-Local Error Buffers", "security_guide.html#autotoc_md1069", null ],
        [ "Exception Thread Safety", "security_guide.html#autotoc_md1070", null ],
        [ "What's NOT Thread-Safe", "security_guide.html#autotoc_md1071", null ]
      ] ],
      [ "Exception Handling", "security_guide.html#autotoc_md1073", [
        [ "Always Handle Security Exceptions", "security_guide.html#autotoc_md1074", null ],
        [ "Don't Ignore Verification Failures", "security_guide.html#autotoc_md1075", null ]
      ] ],
      [ "HTTP Security", "security_guide.html#autotoc_md1077", [
        [ "Request Smuggling Prevention", "security_guide.html#autotoc_md1078", null ],
        [ "WebSocket Security", "security_guide.html#autotoc_md1079", null ],
        [ "Cookie Security", "security_guide.html#autotoc_md1080", null ],
        [ "HTTP/2 Flow Control Hardening", "security_guide.html#autotoc_md1081", null ]
      ] ],
      [ "File Descriptor Hygiene", "security_guide.html#autotoc_md1083", [
        [ "Safe Close", "security_guide.html#autotoc_md1084", null ],
        [ "Prevent FD Leaks", "security_guide.html#autotoc_md1085", null ]
      ] ],
      [ "Audit Logging", "security_guide.html#autotoc_md1087", [
        [ "What to Log", "security_guide.html#autotoc_md1088", null ],
        [ "How to Log Safely", "security_guide.html#autotoc_md1089", null ]
      ] ],
      [ "Security Checklist", "security_guide.html#autotoc_md1091", [
        [ "Server Applications", "security_guide.html#autotoc_md1092", null ],
        [ "Client Applications", "security_guide.html#autotoc_md1093", null ],
        [ "General", "security_guide.html#autotoc_md1094", null ]
      ] ],
      [ "TLS Configuration Best Practices", "security_guide.html#autotoc_md1096", [
        [ "Protocol Version", "security_guide.html#autotoc_md1097", null ],
        [ "Cipher Suite Configuration", "security_guide.html#autotoc_md1098", null ],
        [ "Certificate Verification", "security_guide.html#autotoc_md1099", null ],
        [ "Mutual TLS (mTLS)", "security_guide.html#autotoc_md1100", null ],
        [ "OCSP Stapling", "security_guide.html#autotoc_md1101", null ],
        [ "Certificate Transparency", "security_guide.html#autotoc_md1102", null ],
        [ "Certificate Revocation Lists (CRL)", "security_guide.html#autotoc_md1103", null ],
        [ "Session Resumption Security", "security_guide.html#autotoc_md1104", null ],
        [ "Renegotiation Protection", "security_guide.html#autotoc_md1105", null ],
        [ "Private Key Protection", "security_guide.html#autotoc_md1106", null ],
        [ "TLS Security Checklist", "security_guide.html#autotoc_md1107", null ]
      ] ],
      [ "See Also", "security_guide.html#autotoc_md1109", null ]
    ] ],
    [ "Migration Guide", "migration_guide.html", [
      [ "Migration from BSD Sockets", "migration_guide.html#autotoc_md1111", [
        [ "Socket Creation", "migration_guide.html#autotoc_md1112", null ],
        [ "Connecting", "migration_guide.html#autotoc_md1113", null ],
        [ "Sending Data", "migration_guide.html#autotoc_md1114", null ],
        [ "Socket Options", "migration_guide.html#autotoc_md1115", null ],
        [ "API Mapping (BSD -> Socket Library)", "migration_guide.html#autotoc_md1116", null ]
      ] ],
      [ "Migration from libcurl", "migration_guide.html#autotoc_md1118", [
        [ "Simple GET Request", "migration_guide.html#autotoc_md1119", null ],
        [ "POST Request", "migration_guide.html#autotoc_md1120", null ],
        [ "Custom Headers", "migration_guide.html#autotoc_md1121", null ],
        [ "Proxy Configuration", "migration_guide.html#autotoc_md1122", null ],
        [ "Error Handling", "migration_guide.html#autotoc_md1123", null ],
        [ "API Mapping (libcurl -> Socket Library)", "migration_guide.html#autotoc_md1124", null ]
      ] ],
      [ "Migration from libevent", "migration_guide.html#autotoc_md1126", [
        [ "Event Loop", "migration_guide.html#autotoc_md1127", null ],
        [ "Callback Style", "migration_guide.html#autotoc_md1128", null ],
        [ "Timers", "migration_guide.html#autotoc_md1129", null ],
        [ "API Mapping (libevent -> Socket Library)", "migration_guide.html#autotoc_md1130", null ]
      ] ],
      [ "Migration from libev", "migration_guide.html#autotoc_md1132", [
        [ "Event Loop", "migration_guide.html#autotoc_md1133", null ]
      ] ],
      [ "Migration from OpenSSL Direct", "migration_guide.html#autotoc_md1135", [
        [ "TLS Client", "migration_guide.html#autotoc_md1136", null ],
        [ "API Mapping (OpenSSL -> Socket Library)", "migration_guide.html#autotoc_md1137", null ]
      ] ],
      [ "Common Patterns", "migration_guide.html#autotoc_md1139", [
        [ "Error Handling Pattern", "migration_guide.html#autotoc_md1140", null ],
        [ "Resource Cleanup Pattern", "migration_guide.html#autotoc_md1141", null ]
      ] ],
      [ "Key Differences", "migration_guide.html#autotoc_md1143", [
        [ "Memory Management", "migration_guide.html#autotoc_md1144", null ],
        [ "Error Handling", "migration_guide.html#autotoc_md1145", null ],
        [ "Thread Safety", "migration_guide.html#autotoc_md1146", null ]
      ] ],
      [ "Getting Started", "migration_guide.html#autotoc_md1148", null ],
      [ "See Also", "migration_guide.html#autotoc_md1150", null ]
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
"graceful__shutdown_8c.html#ae342ec361b98a9de5121b60e3e886972",
"group__connection__mgmt.html#gacf51388d2a06f1d1b1caa4d55fe29159",
"group__core__io.html#gaaa278a4a5238ff43c2eedd874cd289b0",
"group__dns.html#ggaba752f803497a475aa1b96ed2351dd99aae3ddf1daeda71dca3b2cb763696b941",
"group__foundation.html#ga5340f6016fe6c58b24400b7cfd34a4c0",
"group__hpack__private.html#aa26d4af777700af33e7dd9a719e9c696",
"group__http.html#ae083e7f71d92ed3805ade974c60f0789",
"group__http.html#gae26015dc94d7a799afa06e5af4a06028",
"group__http1.html#a92d57170c7f01130d0b2f55e869bc273",
"group__http2.html#ga2c94bfd0344f644c485a5b20ac0f9227",
"group__http2__private.html#ac28cf40a6c772a6ec57237b159510f6e",
"group__proxy.html#aa04cfa88d52d6c1f889f9f936a141141",
"group__security.html#a293318fc59356e9559991efa47f13551",
"group__security.html#ga8a972b0da962c5515936444b6921182d",
"group__utilities.html#ga02b7ac016b2dbc2c374081887ef684d5",
"group__utilities.html#gga1c2d3a4ca0a94b5d52917b2020796ceead4c08a4071bac7bc3be7021dcded790f",
"group__websocket.html#gacba3d485716ab762c1ecd90312174721",
"security_guide.html#autotoc_md1039"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';