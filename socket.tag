<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<tagfile doxygen_version="1.9.8">
  <compound kind="file">
    <name>ASYNC_IO.md</name>
    <path>docs/</path>
    <filename>ASYNC__IO_8md.html</filename>
  </compound>
  <compound kind="file">
    <name>HTTP.md</name>
    <path>docs/</path>
    <filename>HTTP_8md.html</filename>
  </compound>
  <compound kind="file">
    <name>mainpage.md</name>
    <path>docs/</path>
    <filename>mainpage_8md.html</filename>
  </compound>
  <compound kind="file">
    <name>MIGRATION.md</name>
    <path>docs/</path>
    <filename>MIGRATION_8md.html</filename>
  </compound>
  <compound kind="file">
    <name>PROXY.md</name>
    <path>docs/</path>
    <filename>PROXY_8md.html</filename>
  </compound>
  <compound kind="file">
    <name>SECURITY.md</name>
    <path>docs/</path>
    <filename>SECURITY_8md.html</filename>
  </compound>
  <compound kind="file">
    <name>WEBSOCKET.md</name>
    <path>docs/</path>
    <filename>WEBSOCKET_8md.html</filename>
  </compound>
  <compound kind="file">
    <name>graceful_shutdown.c</name>
    <path>examples/</path>
    <filename>graceful__shutdown_8c.html</filename>
    <includes id="Arena_8h" name="Arena.h" local="yes" import="no" module="no" objc="no">core/Arena.h</includes>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="SocketPoll_8h" name="SocketPoll.h" local="yes" import="no" module="no" objc="no">poll/SocketPoll.h</includes>
    <includes id="SocketPool_8h" name="SocketPool.h" local="yes" import="no" module="no" objc="no">pool/SocketPool.h</includes>
    <includes id="Socket_8h" name="Socket.h" local="yes" import="no" module="no" objc="no">socket/Socket.h</includes>
    <member kind="define">
      <type>#define</type>
      <name>DEFAULT_PORT</name>
      <anchorfile>graceful__shutdown_8c.html</anchorfile>
      <anchor>a16b710f592bf8f7900666392adc444dc</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>MAX_CONNECTIONS</name>
      <anchorfile>graceful__shutdown_8c.html</anchorfile>
      <anchor>a053b7859476cc9867ec62c49e68d3fa1</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>BUFFER_SIZE</name>
      <anchorfile>graceful__shutdown_8c.html</anchorfile>
      <anchor>a6b20d41d6252e9871430c242cb1a56e7</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>DRAIN_TIMEOUT_MS</name>
      <anchorfile>graceful__shutdown_8c.html</anchorfile>
      <anchor>a13c5505a632e51fbe8500992d7a17b3a</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>POLL_TIMEOUT_MS</name>
      <anchorfile>graceful__shutdown_8c.html</anchorfile>
      <anchor>ae185e948f0542226cd0c076cd159576c</anchor>
      <arglist></arglist>
    </member>
    <member kind="function" static="yes">
      <type>static void</type>
      <name>signal_handler</name>
      <anchorfile>graceful__shutdown_8c.html</anchorfile>
      <anchor>ac8e66a8857ca7f368cfc16bdbbac37d9</anchor>
      <arglist>(int signo)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static int</type>
      <name>setup_signal_handling</name>
      <anchorfile>graceful__shutdown_8c.html</anchorfile>
      <anchor>a419cdf3aeb93a4a2758b620b47584438</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static int</type>
      <name>check_signal_pipe</name>
      <anchorfile>graceful__shutdown_8c.html</anchorfile>
      <anchor>a295e7ddacbf8bd557b8d625970fd6244</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static void</type>
      <name>cleanup_signal_handling</name>
      <anchorfile>graceful__shutdown_8c.html</anchorfile>
      <anchor>ae342ec361b98a9de5121b60e3e886972</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static int</type>
      <name>handle_client_data</name>
      <anchorfile>graceful__shutdown_8c.html</anchorfile>
      <anchor>aa28a4c169a33f7f9821322e49230c62e</anchor>
      <arglist>(Socket_T client, SocketBuf_T inbuf, SocketBuf_T outbuf)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>main</name>
      <anchorfile>graceful__shutdown_8c.html</anchorfile>
      <anchor>a0ddf1224851353fc92bfbff6f499fa97</anchor>
      <arglist>(int argc, char *argv[])</arglist>
    </member>
    <member kind="variable" static="yes">
      <type>static int</type>
      <name>g_signal_pipe</name>
      <anchorfile>graceful__shutdown_8c.html</anchorfile>
      <anchor>a7316cc6af9d04132b3715730cf300100</anchor>
      <arglist>[2]</arglist>
    </member>
    <member kind="variable" static="yes">
      <type>static volatile sig_atomic_t</type>
      <name>g_last_signal</name>
      <anchorfile>graceful__shutdown_8c.html</anchorfile>
      <anchor>a7340cff19af378cc7a10afa52708590f</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>http2_client.c</name>
    <path>examples/</path>
    <filename>http2__client_8c.html</filename>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="SocketHTTPClient_8h" name="SocketHTTPClient.h" local="yes" import="no" module="no" objc="no">http/SocketHTTPClient.h</includes>
    <member kind="function" static="yes">
      <type>static const char *</type>
      <name>http_version_string</name>
      <anchorfile>http2__client_8c.html</anchorfile>
      <anchor>a5b8feac3bec67885d0e195b2ea729700</anchor>
      <arglist>(SocketHTTP_Version version)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>main</name>
      <anchorfile>http2__client_8c.html</anchorfile>
      <anchor>a3c04138a5bfe5d72780bb7e82a18e627</anchor>
      <arglist>(int argc, char **argv)</arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>http_get.c</name>
    <path>examples/</path>
    <filename>http__get_8c.html</filename>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="SocketHTTPClient_8h" name="SocketHTTPClient.h" local="yes" import="no" module="no" objc="no">http/SocketHTTPClient.h</includes>
    <member kind="function">
      <type>int</type>
      <name>main</name>
      <anchorfile>http__get_8c.html</anchorfile>
      <anchor>a3c04138a5bfe5d72780bb7e82a18e627</anchor>
      <arglist>(int argc, char **argv)</arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>http_post.c</name>
    <path>examples/</path>
    <filename>http__post_8c.html</filename>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="SocketHTTPClient_8h" name="SocketHTTPClient.h" local="yes" import="no" module="no" objc="no">http/SocketHTTPClient.h</includes>
    <member kind="function">
      <type>int</type>
      <name>main</name>
      <anchorfile>http__post_8c.html</anchorfile>
      <anchor>a3c04138a5bfe5d72780bb7e82a18e627</anchor>
      <arglist>(int argc, char **argv)</arglist>
    </member>
    <member kind="variable" static="yes">
      <type>static const char *</type>
      <name>json_payload</name>
      <anchorfile>http__post_8c.html</anchorfile>
      <anchor>a127799c7929ced53036a93a6c24c86ac</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>http_server.c</name>
    <path>examples/</path>
    <filename>http__server_8c.html</filename>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="SocketHTTP_8h" name="SocketHTTP.h" local="yes" import="no" module="no" objc="no">http/SocketHTTP.h</includes>
    <includes id="SocketHTTPServer_8h" name="SocketHTTPServer.h" local="yes" import="no" module="no" objc="no">http/SocketHTTPServer.h</includes>
    <member kind="function" static="yes">
      <type>static void</type>
      <name>signal_handler</name>
      <anchorfile>http__server_8c.html</anchorfile>
      <anchor>ac8e66a8857ca7f368cfc16bdbbac37d9</anchor>
      <arglist>(int signo)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static void</type>
      <name>request_handler</name>
      <anchorfile>http__server_8c.html</anchorfile>
      <anchor>a029441ff8281d934bb949f7c64e9bff5</anchor>
      <arglist>(SocketHTTPServer_Request_T req, void *userdata)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>main</name>
      <anchorfile>http__server_8c.html</anchorfile>
      <anchor>a3c04138a5bfe5d72780bb7e82a18e627</anchor>
      <arglist>(int argc, char **argv)</arglist>
    </member>
    <member kind="variable" static="yes">
      <type>static volatile int</type>
      <name>running</name>
      <anchorfile>http__server_8c.html</anchorfile>
      <anchor>af1f449cc09f8d36befcce07bc38c29c0</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>proxy_connect.c</name>
    <path>examples/</path>
    <filename>proxy__connect_8c.html</filename>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="Socket_8h" name="Socket.h" local="yes" import="no" module="no" objc="no">socket/Socket.h</includes>
    <includes id="SocketProxy_8h" name="SocketProxy.h" local="yes" import="no" module="no" objc="no">socket/SocketProxy.h</includes>
    <includes id="SocketTLS_8h" name="SocketTLS.h" local="yes" import="no" module="no" objc="no">tls/SocketTLS.h</includes>
    <includes id="SocketTLSContext_8h" name="SocketTLSContext.h" local="yes" import="no" module="no" objc="no">tls/SocketTLSContext.h</includes>
    <member kind="function" static="yes">
      <type>static const char *</type>
      <name>proxy_type_name</name>
      <anchorfile>proxy__connect_8c.html</anchorfile>
      <anchor>a55da5ed30bd1853bac8e253ed4e1db47</anchor>
      <arglist>(SocketProxyType type)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static const char *</type>
      <name>proxy_result_string</name>
      <anchorfile>proxy__connect_8c.html</anchorfile>
      <anchor>ad2f461e754355dd291de5191cd9d6e94</anchor>
      <arglist>(SocketProxy_Result result)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static void</type>
      <name>print_usage</name>
      <anchorfile>proxy__connect_8c.html</anchorfile>
      <anchor>aabc38c84d6370a74bc1987510537bb20</anchor>
      <arglist>(const char *program)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>main</name>
      <anchorfile>proxy__connect_8c.html</anchorfile>
      <anchor>a3c04138a5bfe5d72780bb7e82a18e627</anchor>
      <arglist>(int argc, char **argv)</arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>websocket_client.c</name>
    <path>examples/</path>
    <filename>websocket__client_8c.html</filename>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="Socket_8h" name="Socket.h" local="yes" import="no" module="no" objc="no">socket/Socket.h</includes>
    <includes id="SocketWS_8h" name="SocketWS.h" local="yes" import="no" module="no" objc="no">socket/SocketWS.h</includes>
    <member kind="function" static="yes">
      <type>static void</type>
      <name>signal_handler</name>
      <anchorfile>websocket__client_8c.html</anchorfile>
      <anchor>ac8e66a8857ca7f368cfc16bdbbac37d9</anchor>
      <arglist>(int signo)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>main</name>
      <anchorfile>websocket__client_8c.html</anchorfile>
      <anchor>a3c04138a5bfe5d72780bb7e82a18e627</anchor>
      <arglist>(int argc, char **argv)</arglist>
    </member>
    <member kind="variable" static="yes">
      <type>static volatile int</type>
      <name>running</name>
      <anchorfile>websocket__client_8c.html</anchorfile>
      <anchor>af1f449cc09f8d36befcce07bc38c29c0</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>websocket_server.c</name>
    <path>examples/</path>
    <filename>websocket__server_8c.html</filename>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="SocketHTTP_8h" name="SocketHTTP.h" local="yes" import="no" module="no" objc="no">http/SocketHTTP.h</includes>
    <includes id="SocketHTTPServer_8h" name="SocketHTTPServer.h" local="yes" import="no" module="no" objc="no">http/SocketHTTPServer.h</includes>
    <includes id="SocketPoll_8h" name="SocketPoll.h" local="yes" import="no" module="no" objc="no">poll/SocketPoll.h</includes>
    <includes id="Socket_8h" name="Socket.h" local="yes" import="no" module="no" objc="no">socket/Socket.h</includes>
    <includes id="SocketWS_8h" name="SocketWS.h" local="yes" import="no" module="no" objc="no">socket/SocketWS.h</includes>
    <member kind="define">
      <type>#define</type>
      <name>MAX_CLIENTS</name>
      <anchorfile>websocket__server_8c.html</anchorfile>
      <anchor>a0a8f91f93d75a07f0ae45077db45b3eb</anchor>
      <arglist></arglist>
    </member>
    <member kind="function" static="yes">
      <type>static void</type>
      <name>signal_handler</name>
      <anchorfile>websocket__server_8c.html</anchorfile>
      <anchor>ac8e66a8857ca7f368cfc16bdbbac37d9</anchor>
      <arglist>(int signo)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static int</type>
      <name>add_ws_client</name>
      <anchorfile>websocket__server_8c.html</anchorfile>
      <anchor>ae21ade27ece05cb1b1ab839bc341ef9d</anchor>
      <arglist>(SocketWS_T ws)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static void</type>
      <name>remove_ws_client</name>
      <anchorfile>websocket__server_8c.html</anchorfile>
      <anchor>a076c7de77cb74d1a0468ee51bf569ba5</anchor>
      <arglist>(SocketWS_T ws)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static void</type>
      <name>request_handler</name>
      <anchorfile>websocket__server_8c.html</anchorfile>
      <anchor>a029441ff8281d934bb949f7c64e9bff5</anchor>
      <arglist>(SocketHTTPServer_Request_T req, void *userdata)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static void</type>
      <name>process_websocket_clients</name>
      <anchorfile>websocket__server_8c.html</anchorfile>
      <anchor>a551ea234e572046dad50df6fc5ecc0da</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>main</name>
      <anchorfile>websocket__server_8c.html</anchorfile>
      <anchor>a3c04138a5bfe5d72780bb7e82a18e627</anchor>
      <arglist>(int argc, char **argv)</arglist>
    </member>
    <member kind="variable" static="yes">
      <type>static volatile int</type>
      <name>running</name>
      <anchorfile>websocket__server_8c.html</anchorfile>
      <anchor>af1f449cc09f8d36befcce07bc38c29c0</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable" static="yes">
      <type>static SocketWS_T</type>
      <name>ws_clients</name>
      <anchorfile>websocket__server_8c.html</anchorfile>
      <anchor>a1ecbd69317b6899634ceb14e9acb2e59</anchor>
      <arglist>[100]</arglist>
    </member>
    <member kind="variable" static="yes">
      <type>static int</type>
      <name>ws_count</name>
      <anchorfile>websocket__server_8c.html</anchorfile>
      <anchor>a2cdaafcd37f5f95ef53ba4b70091f6b7</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>Arena.h</name>
    <path>include/core/</path>
    <filename>Arena_8h.html</filename>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <member kind="define">
      <type>#define</type>
      <name>T</name>
      <anchorfile>Arena_8h.html</anchorfile>
      <anchor>a0acb682b8260ab1c60b918599864e2e5</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>ALLOC</name>
      <anchorfile>Arena_8h.html</anchorfile>
      <anchor>a7897b95c53808a539b0f7a18587a9b54</anchor>
      <arglist>(arena, nbytes)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>CALLOC</name>
      <anchorfile>Arena_8h.html</anchorfile>
      <anchor>af5249a1778cd6cf5db0e2e410b292934</anchor>
      <arglist>(arena, count, nbytes)</arglist>
    </member>
    <member kind="typedef">
      <type>struct Arena_T *</type>
      <name>Arena_T</name>
      <anchorfile>Arena_8h.html</anchorfile>
      <anchor>ac1ed22b9df4eff7a3398cac608c090cc</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>Arena_T</type>
      <name>Arena_new</name>
      <anchorfile>Arena_8h.html</anchorfile>
      <anchor>a6a6d6890eb6ed1248ae1a5f0c677c7a4</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Arena_dispose</name>
      <anchorfile>Arena_8h.html</anchorfile>
      <anchor>a6842e66018614df08139e67826cf3e0d</anchor>
      <arglist>(Arena_T *ap)</arglist>
    </member>
    <member kind="function">
      <type>void *</type>
      <name>Arena_alloc</name>
      <anchorfile>Arena_8h.html</anchorfile>
      <anchor>ad93b1dd7d771cbed846dcc3c5c836917</anchor>
      <arglist>(Arena_T arena, size_t nbytes, const char *file, int line)</arglist>
    </member>
    <member kind="function">
      <type>void *</type>
      <name>Arena_calloc</name>
      <anchorfile>Arena_8h.html</anchorfile>
      <anchor>a3b920b3eed0306dc5afb36934955f6a2</anchor>
      <arglist>(Arena_T arena, size_t count, size_t nbytes, const char *file, int line)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Arena_clear</name>
      <anchorfile>Arena_8h.html</anchorfile>
      <anchor>a0af0c54c1c64ff88ad43aadd48ce3ebe</anchor>
      <arglist>(Arena_T arena)</arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>Arena_Failed</name>
      <anchorfile>Arena_8h.html</anchorfile>
      <anchor>a6053a34c90a976ac971313bd5f201fb3</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>Except.h</name>
    <path>include/core/</path>
    <filename>Except_8h.html</filename>
    <class kind="struct">Except_T</class>
    <class kind="struct">Except_Frame</class>
    <member kind="define">
      <type>#define</type>
      <name>RAISE</name>
      <anchorfile>Except_8h.html</anchorfile>
      <anchor>a45e87c4d7dee50346b15c7761b0b340a</anchor>
      <arglist>(e)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>RERAISE</name>
      <anchorfile>Except_8h.html</anchorfile>
      <anchor>a947ef43f0f0def3fcc050a8df849fd16</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>RETURN</name>
      <anchorfile>Except_8h.html</anchorfile>
      <anchor>a6a0e6b80dd3d5ca395cf58151749f5e2</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>EXCEPT_POP_FRAME_IF_ENTERED</name>
      <anchorfile>Except_8h.html</anchorfile>
      <anchor>a05f22e2dc12bcb0f4bfdf22cd81f8ab8</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>TRY</name>
      <anchorfile>Except_8h.html</anchorfile>
      <anchor>ad2746371528bdf15c3910b7bf217dac0</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>EXCEPT</name>
      <anchorfile>Except_8h.html</anchorfile>
      <anchor>ab5e72fc2bd41014c75e0ace4feabfe8e</anchor>
      <arglist>(e)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>ELSE</name>
      <anchorfile>Except_8h.html</anchorfile>
      <anchor>a0a70ee0cbf5b1738be4c9463c529ce72</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>FINALLY</name>
      <anchorfile>Except_8h.html</anchorfile>
      <anchor>a0e2a75478cd44f1666a6aca626c5c50b</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>END_TRY</name>
      <anchorfile>Except_8h.html</anchorfile>
      <anchor>ae6628ac788ad213363b89dba9868420b</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>Except_entered</name>
      <anchorfile>Except_8h.html</anchorfile>
      <anchor>a06fc87d81c62e9abb8790b6e5713c55ba388ad603a03109702c508bd464b66da2</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>Except_raised</name>
      <anchorfile>Except_8h.html</anchorfile>
      <anchor>a06fc87d81c62e9abb8790b6e5713c55ba80cdb3635fb4b8d00925dea5821c9fbb</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>Except_handled</name>
      <anchorfile>Except_8h.html</anchorfile>
      <anchor>a06fc87d81c62e9abb8790b6e5713c55bac0d9956bf062b2f2db1f9294563e73b4</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>Except_finalized</name>
      <anchorfile>Except_8h.html</anchorfile>
      <anchor>a06fc87d81c62e9abb8790b6e5713c55ba8f2b6b8b0f719ecda31559637209f40b</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Except_raise</name>
      <anchorfile>Except_8h.html</anchorfile>
      <anchor>a9199ea10e7cd2cf2422ae8ffa9ac43a1</anchor>
      <arglist>(const Except_T *e, const char *file, int line)</arglist>
    </member>
    <member kind="variable">
      <type>Except_Frame *</type>
      <name>Except_stack</name>
      <anchorfile>Except_8h.html</anchorfile>
      <anchor>a3d38c6361ecf1c4873bbcb2de8a50874</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>Assert_Failed</name>
      <anchorfile>Except_8h.html</anchorfile>
      <anchor>a02c91dd1cedbfe4b9e31d7775e0ead7f</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketConfig.h</name>
    <path>include/core/</path>
    <filename>SocketConfig_8h.html</filename>
    <class kind="struct">SocketTimeouts_T</class>
    <class kind="struct">SocketTimeouts_Extended_T</class>
    <class kind="union">align</class>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_VERSION_MAJOR</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a804342bb2c0ff468a794cefdbe784581</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_VERSION_MINOR</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a5e8e7af9a925dfd168fd9d57d420b31e</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_VERSION_PATCH</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ae9e9c414384981ffd1cb1f4ce1242c18</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_VERSION_STRING</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ac86c0a6be253f84d0f811e4d522332b1</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_VERSION</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a56f6263f07f74e065a182e5508c00779</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_MAX_CONNECTIONS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a72f1e9bc10cc82fb4ee1915335d60152</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_MAX_BUFFER_SIZE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a72443e4b95fbd8ef4d191b754b4324dc</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_MIN_BUFFER_SIZE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a8ae494bcc57f791a1f8cbcf48b96b9a8</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>UDP_MAX_PAYLOAD</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a7b0cb8d09882f145ebd41ad5a5932a30</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SAFE_UDP_SIZE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a7f6c789e54c4efbc66d4a9cbc947734f</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SENDFILE_FALLBACK_BUFFER_SIZE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>af86c34b79f0c5546c8b538edcd9372e1</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_MAX_TTL</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ad19b3a142a302a366a345ce7272763a6</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_IPV6_MAX_PREFIX</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>acddf48aa583cfb80ca7caa6efd4f7143</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_IPV4_MAX_PREFIX</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a08fcedac2973fd36f2ed55cc2f2c13d2</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_MAX_PORT</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a5d3af7fc5447a76f5f64430362d6dfcf</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_MAX_POLL_EVENTS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ab6d7f45fcb5eae5fe42694e8e123cab4</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_MAX_LISTEN_BACKLOG</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a2fb10bfccfe83fb0bb5873949cf8a2f7</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_MAX_FDS_PER_MSG</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a9b64483d1dd5d32bba7937741c36cabf</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_HASH_TABLE_SIZE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a9aab9f1282519c6c66aca1271deffe84</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>ARENA_CHUNK_SIZE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a9ae8a98b44ad6ae722e484144907b3b5</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>ARENA_MAX_ALLOC_SIZE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a56ca9e70161f78a70b367eaf8feb0a44</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>ARENA_MAX_FREE_CHUNKS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ab329c6b2c13d14e3cf0bd9138bd3a7fc</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>ARENA_ERROR_BUFSIZE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a5e690294cf5966dce9003c888766d18b</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETBUF_MIN_CAPACITY</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ab0563923535025dbd7c98a992dbf8df2</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETBUF_INITIAL_CAPACITY</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a2209ca43107de5bec46f534bc7830e04</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETBUF_ALLOC_OVERHEAD</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a3fb43699cef4e69257db533e71c8265a</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETBUF_MAX_CAPACITY</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a2eeb416200865c4512082543ce983a6f</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DNS_THREAD_COUNT</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a7333dd84db01bccd272a0a535cb69ffa</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DNS_MAX_PENDING</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>afe6640a153bf74038b7a011808d6bf78</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DNS_MAX_LABEL_LENGTH</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ab9d107f9984dd45f9ba4b1618ad373ad</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DNS_WORKER_STACK_SIZE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a30e7a628ce9483f24b2f86ef0e985639</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DNS_REQUEST_HASH_SIZE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ad93bb14bccd4fd5d8f37a22b30a4c944</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DNS_PIPE_BUFFER_SIZE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>aabf88e7e79136014eb538ec90cf2a0f4</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DNS_COMPLETION_SIGNAL_BYTE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a38939e0f4010e9cc311360b1d974d068</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DNS_PORT_STR_SIZE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a8dd2e41af45c32418159edb2bfa3d4b8</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DNS_THREAD_NAME_SIZE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ae19af4d3535b2bb856fa673bdaa45983</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>POLL_INITIAL_FDS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a673275383493d8cff8bc582fef311e42</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>POLL_INITIAL_FD_MAP_SIZE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a211a6387523fa6487af971831aabf461</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>POLL_FD_MAP_EXPAND_INCREMENT</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a834e79d67b92d737d55e4ba2b0684025</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_POLL_MAX_REGISTERED</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a9e03e27adad67f322a99e86a6a5fd29f</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_MAX_TIMER_TIMEOUT_MS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ad738dd2be8abca1d0353d31f888ba3eb</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_MAX_TIMER_DELAY_MS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a7f5492f9166c78ee14f4b69362ccaf51</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TIMER_ERROR_BUFSIZE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ab56cfec8835c59bfb69bb1c1cb128c93</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TIMER_HEAP_INITIAL_CAPACITY</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a115b76003aaf131241e5b091a63b3285</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TIMER_HEAP_GROWTH_FACTOR</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>aca5f033531acb4f68ba5823ce2b769d7</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_MAX_TIMERS_PER_HEAP</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a53de6720fd3fc8accf99751c1e4e0d50</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TIMER_MIN_DELAY_MS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ab0ced17c77c552330176b69557fb83fc</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TIMER_MIN_INTERVAL_MS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a59221d1781370448def350dafb2d7e24</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TIMER_INITIAL_ID</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>acd3100d409a6fd3f6d160700ba6c64c6</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_EVENT_MAX_HANDLERS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a76ac815951cb4cbc800c781eb143b8cb</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_RATELIMIT_DEFAULT_CONN_PER_SEC</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a3a21bf722ae35407887616e93beb4b2c</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_RATELIMIT_DEFAULT_BURST</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>aa0d908b960f55f05fad9422db204c38d</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_RATELIMIT_DEFAULT_MAX_PER_IP</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a520c5f8d3888ec23a2623dfcc8932997</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_RATELIMIT_DEFAULT_BANDWIDTH_BPS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a2f47fe62f8c23f11f6e791281c72b040</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_IP_TRACKER_HASH_SIZE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ae01e59a813f363fb3fe000809646df28</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_IP_MAX_LEN</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a05cfd90047517ee1ae9f869294c834a4</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SYN_DEFAULT_WINDOW_MS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ae062b2bac82d2ca78edc6658135b25a4</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SYN_DEFAULT_MAX_PER_WINDOW</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a8c43db9a86f5f49f85c535b7e01a9cd2</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SYN_DEFAULT_GLOBAL_PER_SEC</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>af02ac0a68cee3923b135a1e423622f61</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SYN_DEFAULT_MIN_SUCCESS_RATIO</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ae0b03e45dca47aec6f4203011b1161f3</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SYN_DEFAULT_THROTTLE_DELAY_MS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>aae5bbd0b37027680dfa2c0c58773fef6</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SYN_DEFAULT_BLOCK_DURATION_MS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>aff44ca76156e6010520f4d231fbf7109</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SYN_DEFAULT_DEFER_SEC</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a7883d7f2995a8046776d818de6dbaa2e</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SYN_DEFAULT_SCORE_THROTTLE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a8a91a7da051b6462f126bc329f1e5cda</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SYN_DEFAULT_SCORE_CHALLENGE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a67a51dcadef9eb934f3342e9e02f6fd5</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SYN_DEFAULT_SCORE_BLOCK</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a9608aa5a6bbbe4cbc60c9442d094cfd0</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SYN_DEFAULT_SCORE_DECAY</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a8b8d879d7477b5a59170487f2ef38cd0</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SYN_DEFAULT_PENALTY_ATTEMPT</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a4122f191a253666fdb691929b3cd4173</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SYN_DEFAULT_PENALTY_FAILURE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a4f01c6ca60bf199d42dde59f0159074c</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SYN_DEFAULT_REWARD_SUCCESS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a9a0acbe7229a03abfe70205717d511c4</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SYN_DEFAULT_MAX_TRACKED_IPS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a842d1a441b3a55a43f2066087ff6ff59</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SYN_DEFAULT_MAX_WHITELIST</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ac1a28d9573c05725ca3abb96239b83ee</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SYN_DEFAULT_MAX_BLACKLIST</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ac82e2e73ae29b0b0e8699d8b81bb29c3</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SYN_TRUSTED_SCORE_THRESHOLD</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ab0908a428243a18d0260754d417e023a</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_IPV6_ADDR_BYTES</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a812e1a3066fafa145324e13ec013cb47</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_IPV4_ADDR_BYTES</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ae1b769b5903588b4e6cbd40864a30d8e</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_BITS_PER_BYTE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a0c869f123d7c29c39cfe7d1dedd998a0</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_LOG_BUFFER_SIZE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a6359d7f5856bc1d8e19de36b71156f7a</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_LOG_TIMESTAMP_BUFSIZE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a9f03e9a6199dbb18586a36f2a6b9fe03</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_LOG_TIMESTAMP_FORMAT</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ace3fad409b02d99b41b0dd404521291f</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_LOG_DEFAULT_TIMESTAMP</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a88eea454f08ac7601d29bde68168ba5d</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_LOG_TRUNCATION_SUFFIX</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a2d9c77a58bc1bafac674a2f3e7fd6110</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_LOG_TRUNCATION_SUFFIX_LEN</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a440d1a233318f110550568f5f2d29340</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_ERROR_BUFSIZE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ab28724709065957c1e13fd4c9b8e873a</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_STRERROR_BUFSIZE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a88a91dddef3e3d02a87b3f8074e75ca7</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_ERROR_MAX_HOSTNAME</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a25b54bdeec6e6e945e62eb8b6e5cc8e6</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_ERROR_MAX_MESSAGE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>affaa8cfbcac4b123df8da0f9279a247f</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_ERROR_TRUNCATION_MARKER</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a22d6df423f7c13e8d4f1b4192037f537</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_ERROR_TRUNCATION_SIZE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a6969c4f53c182cf7112aa6dd0421571f</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_PORT_STR_BUFSIZE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>aa5594e0bf4a9a492cc6e9dd7bcdae74c</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_PLATFORM_MACOS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>afe51dc34402f488f54f734a1ebd48307</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_HAS_HTTP</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a54e17fd055aa5d310409f7e73e944f9a</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_HAS_WEBSOCKET</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ae1f8127d7a7541fb20f280f60b3dc308</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>IOV_MAX</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a25080e819a36fcf9aede01a6e7298ea4</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_HAS_SENDMSG</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a3d1b69dbf142e7aaa4b329f0e0f34dee</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_HAS_RECVMSG</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a1b4cba449b689c0e2069c5592d65ff70</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DEFAULT_CONNECT_TIMEOUT_MS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>aaa099b2101176b12abb25299a6ac5bd1</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_CONNECT_HAPPY_EYEBALLS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a68b9522f84336d319f6b629906c3128c</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DEFAULT_DNS_TIMEOUT_MS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ac01d46f482abd08d6fb51a115b3590c4</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DEFAULT_OPERATION_TIMEOUT_MS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a4f0df33f87080b6004ea3a3400e388c7</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DEFAULT_IDLE_TIMEOUT</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>aa656899af348069271d2878e221b95e3</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DEFAULT_POLL_TIMEOUT</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a71cb10d1eefc15616a20bcd7ae21e875</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DEFAULT_TLS_TIMEOUT_MS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a1b06aa0632dd6d7cb1eaea90a2aadcd8</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DEFAULT_REQUEST_TIMEOUT_MS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a6365c1f9dad48871009f0580a72d7a9d</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DEFAULT_POOL_SIZE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a2ab0335d59ba489638143cfcdbeb131c</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DEFAULT_POOL_BUFSIZE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ae566ef3ebb6568218b7f7dbf8feea2c6</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_POOL_DEFAULT_PREWARM_PCT</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a46e9cd9dc6e5eabbe91e5fa71ec00b81</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_POOL_MAX_BATCH_ACCEPTS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a331e1002cf6dfb30695f5af41625cf46</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_POOL_MAX_ASYNC_PENDING</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ae34901523f9a628eab93a9f50bf70366</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_PERCENTAGE_DIVISOR</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a775d9db592e6205d00a2b6ad81bf3492</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_POOL_DEFAULT_IDLE_TIMEOUT</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a10afdbc4e530ae2745037155bb78ebb6</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_POOL_DEFAULT_CLEANUP_INTERVAL_MS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a354014b5198b0b853d17d21752d5193c</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_POOL_STATS_WINDOW_SEC</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>aa6d9e9b8f4116f114766da91e8dd0744</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HASH_GOLDEN_RATIO</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ae5597cbeaa3012e797eb99aaf9570030</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>ARENA_ALIGNMENT_SIZE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>aa5fcd2a71e9dd699dd7db574c5d70d8b</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>ARENA_VALIDATION_SUCCESS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a52f2e715ab8051dc17b23d6a90b35c80</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>ARENA_VALIDATION_FAILURE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a235602fcede4fb9bc69be7f5ca97665e</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>ARENA_SUCCESS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ae0ed91b25c305280f9b71295fe1a3360</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>ARENA_FAILURE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a78d9c75a31ffd984a1165184a0387d8a</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>ARENA_CHUNK_REUSED</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a330e671ddbefb1ef08ee48275781353f</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>ARENA_CHUNK_NOT_REUSED</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ad92e368c5798a837d8417e68e448d1f0</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>ARENA_SIZE_VALID</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a9c85173f39d617fc9c01f0dc1b05eb61</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>ARENA_SIZE_INVALID</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>af5726e1d3fb61d34d3041ec202c15e1e</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>ARENA_ENOMEM</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a8f1d456ae6fcdcfae1ca0d188d08e471</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_MS_PER_SECOND</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a56c9492db4685ae9864baf230a439a30</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_NS_PER_MS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a0dd0226b79f2dc57e6741601fd56b51d</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_NS_PER_SECOND</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a3c2718b359486f4075a4b70b5ddfde1c</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DEFAULT_IO_URING_ENTRIES</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>aa0d6d53cd106cb84028fd2e568b0216b</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_MAX_EVENT_BATCH</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a5528f1e60147c0bb8dfa520faa03988e</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_STRINGIFY</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ade5be545e65cd20a1da8d7ba01f59928</anchor>
      <arglist>(x)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TO_STRING</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a577a3038bd7dfef7bd123c8ed26f7074</anchor>
      <arglist>(x)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_PORT_VALID_RANGE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>af1293b9728b8f28d2b171010978521f2</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TTL_VALID_RANGE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a71b9ed2c54e37de9fd46d2500167b384</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_IPV4_PREFIX_RANGE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a5679030989b20fcc0607ae1231e660d8</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_IPV6_PREFIX_RANGE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a8d8ba5a29a7c41c38751668ec17b5759</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_STREAM_TYPE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ae91c5e89e959589a4c72b572da87aed1</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DGRAM_TYPE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>aeb19a3aa101d92d9befe7a980238bf0d</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_AF_UNSPEC</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a723007dbfa6e622f70650dce72fe4949</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_AF_INET</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a04ce265041d74932e7d3354651fd0a79</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_AF_INET6</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a7a754a1f4470597ea52da2a678378100</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_AF_UNIX</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>af26b9f671650b58e0bd264a71ec3cbfa</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_IPPROTO_TCP</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a23ac52f2e8e200798e44cdbf8704096b</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_IPPROTO_UDP</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>affc1bd28b038fdf084f3363167b1f4f4</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_IPPROTO_IP</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>af4deb45fce6ccd9618225ad46d6c414b</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_IPPROTO_IPV6</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a98c4b46c80919077e8a17075c1843ecf</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SOL_SOCKET</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>aa4457fd2dac639801c08d5b7633cf0e8</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SO_REUSEADDR</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a7a238f64c49ef6c7aea7cfe16d1e0ac5</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SO_REUSEPORT</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>aa677c5c4c9fb9c2901f59bae61218989</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_HAS_SO_REUSEPORT</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a2ec065ddbde3ec44ad0f0f6bce1c3c30</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SOCK_CLOEXEC</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a3e9c0eecdab0e5173a8a5c75d84dc932</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_HAS_SOCK_CLOEXEC</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a4df9ceb2961f6a063fc5c97374f00fea</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_HAS_ACCEPT4</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a179e47f6c98b38853e2f9e223586dc5d</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SO_DOMAIN</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a2dc95be9cd7108d68e532aa6e032f36f</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_HAS_SO_DOMAIN</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ac2c905681cea26eada867ab143d2c48d</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_FD_CLOEXEC</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ac0cac1c13bb3060c9311bba91b026c63</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SO_BROADCAST</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a1d16a51106f47efdc76e1495f3cf9ead</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SO_KEEPALIVE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a0f7074b869b88f5fb750473b41e6eb5e</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SO_RCVTIMEO</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ae523e4269e9d3d8d811d9b201cd22bda</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SO_SNDTIMEO</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a4e79c5dbef56609cfb2ca32a5cf82257</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SO_RCVBUF</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a057781fff8a16936f1d2f81e639d17e9</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SO_SNDBUF</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a458bafdef6d2bfdd698d25935a9a05a8</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SO_PEERCRED</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ac9a84a186673663e3306d00e73e6abc1</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TCP_NODELAY</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a50e904b0adcc6c319bc93af43aa172ee</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TCP_KEEPIDLE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a213393dd843fb9bbb3a8e452fea5838e</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TCP_KEEPINTVL</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>acddb57a19b17c1e8730658e051d7cb97</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TCP_KEEPCNT</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ae9b4cfc38baeb5d092a9dbc968868e17</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_HAS_TCP_CONGESTION</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ae59b371249a0e487e26d4f9e087351e5</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_HAS_TCP_FASTOPEN</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a680a9b46408253f21f2fae08fab1a073</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_HAS_TCP_USER_TIMEOUT</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a2e0034bad5cc9db994f51ea107fed151</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_HAS_TCP_DEFER_ACCEPT</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ab97bd3e7337b376f6be804f25d4d9c6d</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_HAS_SO_ACCEPTFILTER</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a219b0a63c1ee02ecb27a9c932da08a51</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_IPV6_V6ONLY</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>abc73d2f6f2da35365e09b28eff6364b8</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_IPV6_UNICAST_HOPS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a6718d10ef55392425b3e4eea07ee15ce</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_IP_TTL</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>aaa278a4a5238ff43c2eedd874cd289b0</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_IP_ADD_MEMBERSHIP</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a3a982d41e0cbfea982c0ee35cab78ae3</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_IP_DROP_MEMBERSHIP</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a057793cb88e55bf92024c4c36e81a9e5</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_AI_PASSIVE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>af554ab0a276793e3c2211071e90d2379</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_AI_NUMERICHOST</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ac5c758285ea3ec616ebef228524e5870</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_AI_NUMERICSERV</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a9650f9a758e7db73f81549f62c336c06</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_NI_NUMERICHOST</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>aed05968c714f431c7489dbbd6491c4da</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_NI_NUMERICSERV</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a189adadf65e2effcf336ae92be1453a3</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_NI_MAXHOST</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>abb714afb577d800a5b6388c5ff985e45</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_NI_MAXSERV</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a0470d30293aefa9d90b1adeae8b2a893</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SHUT_RD</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ad846caae5ed6ec066d9ae975c23d0e10</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SHUT_WR</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a5549c3faf506d9057ac05de132462f87</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SHUT_RDWR</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a30e4937ecabbc1aafef3092ed4d062e4</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>MSG_NOSIGNAL</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a9f55d0e90dc8cc6b2287312435cdde48</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_MSG_NOSIGNAL</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a6d8596dc13da264d86966c08b435110a</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_HAS_SO_NOSIGPIPE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ac8ffdac83de0d6abd074776faf8eb016</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DEFAULT_KEEPALIVE_IDLE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a72227e2f5945efa472401c12608ae6f0</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DEFAULT_KEEPALIVE_INTERVAL</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ac35dee011f3919c4720812ef8b163f03</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DEFAULT_KEEPALIVE_COUNT</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>afd745a2d91d7bc8aad76a133ef1cb0bf</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DEFAULT_DATAGRAM_TTL</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a4c36ad0507aab15f0b59b4ccde5dfb31</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_MULTICAST_DEFAULT_INTERFACE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>af69be862b0cece4e20e7ea283ad91c70</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_VALID_PORT</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a79772cb715462c6705db6d9440786f2d</anchor>
      <arglist>(p)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_VALID_BUFFER_SIZE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ad203163c86ed5dd20746385d2a43ea6f</anchor>
      <arglist>(s)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_VALID_CONNECTION_COUNT</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a43c348045ef81f2408c0afd49c1f299a</anchor>
      <arglist>(c)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_VALID_POLL_EVENTS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>af3934edfea9b109a06dc66e7487959b4</anchor>
      <arglist>(e)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_VALID_IP_STRING</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>abaa7560b3f05cac2ed3d0a2f245c8bdb</anchor>
      <arglist>(ip)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SAFE_CLOSE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a71b9fcff797cf3624ea3ec9c02805291</anchor>
      <arglist>(fd)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>Socket_safe_strerror</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a481ecfe6b9e5c83515c92d1808e4b2f9</anchor>
      <arglist>(int errnum)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketConfig_set_max_memory</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>aed9ff2b1bf0e03f310bb9ade53ea5d12</anchor>
      <arglist>(size_t max_bytes)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketConfig_get_max_memory</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>aabcf66346ca3fe8e418cc692f11ff279</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketConfig_get_memory_used</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>aab4be8d7fbe44f61e567e06012b5e224</anchor>
      <arglist>(void)</arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketCrypto.h</name>
    <path>include/core/</path>
    <filename>SocketCrypto_8h.html</filename>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_CRYPTO_SHA1_SIZE</name>
      <anchorfile>SocketCrypto_8h.html</anchorfile>
      <anchor>a4146e6487ed50541dfd26378ba17803d</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_CRYPTO_SHA256_SIZE</name>
      <anchorfile>SocketCrypto_8h.html</anchorfile>
      <anchor>a2939672d8ed14c71789b094ddfc906fe</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_CRYPTO_MD5_SIZE</name>
      <anchorfile>SocketCrypto_8h.html</anchorfile>
      <anchor>a413c2643e3f0988cccbcfd5d34c4cbda</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_CRYPTO_WEBSOCKET_GUID</name>
      <anchorfile>SocketCrypto_8h.html</anchorfile>
      <anchor>a390b8039fab9556833f72626cbfd47f6</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_CRYPTO_WEBSOCKET_KEY_SIZE</name>
      <anchorfile>SocketCrypto_8h.html</anchorfile>
      <anchor>a4bf259fd90694f37b713c62bf8807312</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_CRYPTO_WEBSOCKET_ACCEPT_SIZE</name>
      <anchorfile>SocketCrypto_8h.html</anchorfile>
      <anchor>a90800f80ea4bcfa066bee419fd6b42a9</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketCrypto_sha1</name>
      <anchorfile>SocketCrypto_8h.html</anchorfile>
      <anchor>ab852f17f17eb272912f698bead0b8dc7</anchor>
      <arglist>(const void *input, size_t input_len, unsigned char output[20])</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketCrypto_sha256</name>
      <anchorfile>SocketCrypto_8h.html</anchorfile>
      <anchor>a91324fc869353b60385a325367ee88db</anchor>
      <arglist>(const void *input, size_t input_len, unsigned char output[32])</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketCrypto_md5</name>
      <anchorfile>SocketCrypto_8h.html</anchorfile>
      <anchor>ac843ec3b2ea1885955d9866a9cba7ac4</anchor>
      <arglist>(const void *input, size_t input_len, unsigned char output[16])</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketCrypto_hmac_sha256</name>
      <anchorfile>SocketCrypto_8h.html</anchorfile>
      <anchor>af63711dccfbba5ed31224035cb541d37</anchor>
      <arglist>(const void *key, size_t key_len, const void *data, size_t data_len, unsigned char output[32])</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketCrypto_base64_encode</name>
      <anchorfile>SocketCrypto_8h.html</anchorfile>
      <anchor>ae97600ec3667d60bfa5cbfa1d945e0a9</anchor>
      <arglist>(const void *input, size_t input_len, char *output, size_t output_size)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketCrypto_base64_decode</name>
      <anchorfile>SocketCrypto_8h.html</anchorfile>
      <anchor>aaf7e5b5acebdb206c46b4e848b3108b8</anchor>
      <arglist>(const char *input, size_t input_len, unsigned char *output, size_t output_size)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketCrypto_base64_encoded_size</name>
      <anchorfile>SocketCrypto_8h.html</anchorfile>
      <anchor>a0db3f49e65df22cd5824c3a65995800f</anchor>
      <arglist>(size_t input_len)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketCrypto_base64_decoded_size</name>
      <anchorfile>SocketCrypto_8h.html</anchorfile>
      <anchor>a1cf99c5eeadfeec437513ae0cd63991b</anchor>
      <arglist>(size_t input_len)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketCrypto_hex_encode</name>
      <anchorfile>SocketCrypto_8h.html</anchorfile>
      <anchor>af8dd87ea9b8cd776e3434139d6339fb5</anchor>
      <arglist>(const void *input, size_t input_len, char *output, int lowercase)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketCrypto_hex_decode</name>
      <anchorfile>SocketCrypto_8h.html</anchorfile>
      <anchor>a48f3e3abb4afe6f9031f1df9c0796718</anchor>
      <arglist>(const char *input, size_t input_len, unsigned char *output, size_t output_capacity)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketCrypto_random_bytes</name>
      <anchorfile>SocketCrypto_8h.html</anchorfile>
      <anchor>ae153fb5408e633479d6a61ac233d3676</anchor>
      <arglist>(void *output, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>uint32_t</type>
      <name>SocketCrypto_random_uint32</name>
      <anchorfile>SocketCrypto_8h.html</anchorfile>
      <anchor>a5028bf521bc54469347820c429b3b64e</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketCrypto_websocket_accept</name>
      <anchorfile>SocketCrypto_8h.html</anchorfile>
      <anchor>a0a44e9f5e169c8359a4bcd57a0c08e36</anchor>
      <arglist>(const char *client_key, char output[29])</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketCrypto_websocket_key</name>
      <anchorfile>SocketCrypto_8h.html</anchorfile>
      <anchor>a39b2220140687eefcc86e920b6bf9731</anchor>
      <arglist>(char output[25])</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketCrypto_secure_compare</name>
      <anchorfile>SocketCrypto_8h.html</anchorfile>
      <anchor>ae5f9b65e71620529159130c81b6d0dba</anchor>
      <arglist>(const void *a, const void *b, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketCrypto_secure_clear</name>
      <anchorfile>SocketCrypto_8h.html</anchorfile>
      <anchor>a00f94677d393f24e0b0c549be7bbcdf2</anchor>
      <arglist>(void *ptr, size_t len)</arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketCrypto_Failed</name>
      <anchorfile>SocketCrypto_8h.html</anchorfile>
      <anchor>a1b0be74d809b6dc7d119ef835fd21fc9</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketIPTracker.h</name>
    <path>include/core/</path>
    <filename>SocketIPTracker_8h.html</filename>
    <includes id="Arena_8h" name="Arena.h" local="yes" import="no" module="no" objc="no">core/Arena.h</includes>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <member kind="define">
      <type>#define</type>
      <name>T</name>
      <anchorfile>SocketIPTracker_8h.html</anchorfile>
      <anchor>a0acb682b8260ab1c60b918599864e2e5</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketIPTracker_T *</type>
      <name>SocketIPTracker_T</name>
      <anchorfile>SocketIPTracker_8h.html</anchorfile>
      <anchor>a763b573474982e2761d5b7fbdf9155fc</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>SocketIPTracker_T</type>
      <name>SocketIPTracker_new</name>
      <anchorfile>SocketIPTracker_8h.html</anchorfile>
      <anchor>ab87cad57ddf1ed19226cf8535456bbde</anchor>
      <arglist>(Arena_T arena, int max_per_ip)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketIPTracker_free</name>
      <anchorfile>SocketIPTracker_8h.html</anchorfile>
      <anchor>a1a9850f5f3c08335dd18e2a8dbfaed39</anchor>
      <arglist>(SocketIPTracker_T *tracker)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketIPTracker_track</name>
      <anchorfile>SocketIPTracker_8h.html</anchorfile>
      <anchor>a796a06e82e58c6fea3deaf767101dea3</anchor>
      <arglist>(SocketIPTracker_T tracker, const char *ip)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketIPTracker_release</name>
      <anchorfile>SocketIPTracker_8h.html</anchorfile>
      <anchor>a340ee75715f9dd3a6446dc3ec2c528dc</anchor>
      <arglist>(SocketIPTracker_T tracker, const char *ip)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketIPTracker_count</name>
      <anchorfile>SocketIPTracker_8h.html</anchorfile>
      <anchor>a01a74a09256ae28c23c79244f6b832c0</anchor>
      <arglist>(SocketIPTracker_T tracker, const char *ip)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketIPTracker_setmax</name>
      <anchorfile>SocketIPTracker_8h.html</anchorfile>
      <anchor>a3ae1930faa05574038978e46612e5385</anchor>
      <arglist>(SocketIPTracker_T tracker, int max_per_ip)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketIPTracker_getmax</name>
      <anchorfile>SocketIPTracker_8h.html</anchorfile>
      <anchor>a2633ef22c045d2a4ab7f260b508bd5fc</anchor>
      <arglist>(SocketIPTracker_T tracker)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketIPTracker_setmaxunique</name>
      <anchorfile>SocketIPTracker_8h.html</anchorfile>
      <anchor>a9f416e973e3f32b1c9cf2a2b620214f4</anchor>
      <arglist>(SocketIPTracker_T tracker, size_t max_unique)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketIPTracker_getmaxunique</name>
      <anchorfile>SocketIPTracker_8h.html</anchorfile>
      <anchor>a0e4510d8147198039726bd8250b95afb</anchor>
      <arglist>(SocketIPTracker_T tracker)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketIPTracker_total</name>
      <anchorfile>SocketIPTracker_8h.html</anchorfile>
      <anchor>a3e69b52a3b64cbba1b17711c9961095f</anchor>
      <arglist>(SocketIPTracker_T tracker)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketIPTracker_unique_ips</name>
      <anchorfile>SocketIPTracker_8h.html</anchorfile>
      <anchor>ad8639fe1f640949b820cd1496a67ca56</anchor>
      <arglist>(SocketIPTracker_T tracker)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketIPTracker_clear</name>
      <anchorfile>SocketIPTracker_8h.html</anchorfile>
      <anchor>a47055e396eb7fa4f633bb19ec7720620</anchor>
      <arglist>(SocketIPTracker_T tracker)</arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketIPTracker_Failed</name>
      <anchorfile>SocketIPTracker_8h.html</anchorfile>
      <anchor>a4692098ecf52e6929c8763f0fa9fe222</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketMetrics.h</name>
    <path>include/core/</path>
    <filename>SocketMetrics_8h.html</filename>
    <class kind="struct">SocketMetrics_HistogramSnapshot</class>
    <class kind="struct">SocketMetrics_Snapshot</class>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_METRICS_HISTOGRAM_BUCKETS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>aee8eaea7cccafbe22afa9435a95aacf2</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_METRICS_EXPORT_BUFFER_SIZE</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>ae9d038b13784880e2ae832f1410613ea</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_METRICS_MAX_LABEL_LEN</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a3284619df6a76d185a0112459a176ad8</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_METRICS_MAX_HELP_LEN</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a871d9f89307a302723ffc03db3135746</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_METRICS_TIME_START</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>abca89a8f013fc5feae9b6663171f8062</anchor>
      <arglist>()</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_METRICS_TIME_OBSERVE</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>afb13f2b83918ab1e5ed4fbe94fa0813a</anchor>
      <arglist>(metric)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_METRICS_HTTP_RESPONSE_CLASS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a058d4b283a626069fce638da98446105</anchor>
      <arglist>(status)</arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketMetricType</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a15ccb5af3b5e42916f5a329763c5b73d</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_TYPE_COUNTER</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a15ccb5af3b5e42916f5a329763c5b73da3b97886e5e49aa6cd10fbecc97717a23</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_TYPE_GAUGE</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a15ccb5af3b5e42916f5a329763c5b73dae412561b9220367088fbc0b4badbb54d</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_TYPE_HISTOGRAM</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a15ccb5af3b5e42916f5a329763c5b73daf4eb6f92091cf411d473f95656d5ffea</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketMetricCategory</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a33af252a522ec94fe17be7f5e6aecf66</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_CAT_POOL</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a33af252a522ec94fe17be7f5e6aecf66a5c4b42ef28417b53a62e04c52ed9102c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_CAT_HTTP_CLIENT</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a33af252a522ec94fe17be7f5e6aecf66a13c2a6f9a020cfb48e871fad684c67b2</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_CAT_HTTP_SERVER</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a33af252a522ec94fe17be7f5e6aecf66a1efa2be51eaef017fa79e7ab729c6058</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_CAT_TLS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a33af252a522ec94fe17be7f5e6aecf66a512451cf5b9457ed15e4433001c3afb0</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_CAT_DNS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a33af252a522ec94fe17be7f5e6aecf66ac4e87e55794a5eda33f91a320d85d2ac</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_CAT_SOCKET</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a33af252a522ec94fe17be7f5e6aecf66aaedb13c47c45a45c7414ed6eb2985a2f</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_CAT_POLL</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a33af252a522ec94fe17be7f5e6aecf66aad530adfdedefa080ca04f67a5154581</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_CAT_COUNT</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a33af252a522ec94fe17be7f5e6aecf66a48dd3ffeeff316169d3afead7dd7f5ff</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketCounterMetric</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796cee</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_POOL_CONNECTIONS_CREATED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea23bac1496677cbfff2ead8150ad6c67b</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_POOL_CONNECTIONS_DESTROYED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea0b0528da3ffe7351fa991416ab138ad9</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_POOL_CONNECTIONS_FAILED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea49233167e0dcbfa60f3ca6d980e76e44</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_POOL_CONNECTIONS_REUSED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea70f4cf0b9927a60fedbeff0cc47ac25c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_POOL_CONNECTIONS_EVICTED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceeaa7076d6bed0ebfc621bbbaa8eb373ae6</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_POOL_DRAIN_STARTED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea6bca8daae014fc82bb7b7b08c12d744a</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_POOL_DRAIN_COMPLETED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea9760372f2bb1ab740a09959e21a99802</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_HTTP_CLIENT_REQUESTS_TOTAL</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceeaf1511efc40227013ff639abf4f4d9b13</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_HTTP_CLIENT_REQUESTS_FAILED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea6528013f375d126375f32f18bdf25222</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_HTTP_CLIENT_REQUESTS_TIMEOUT</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea507a12413d55f789ffe5e9c565dd99e9</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_HTTP_CLIENT_BYTES_SENT</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea47ea62eaadbbbb19ebbea31ef087f01c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_HTTP_CLIENT_BYTES_RECEIVED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea55ecbc6f23460ffb5901a53f8b2ad5e3</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_HTTP_CLIENT_RETRIES</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea091def884e648a2cedaacaff2dd6cec6</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_HTTP_SERVER_REQUESTS_TOTAL</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceead8207230f2d1b6bd84abe11c6be841f3</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_HTTP_SERVER_REQUESTS_FAILED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea137f714bad61f63fbb3a6b70ac730363</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_HTTP_SERVER_BYTES_SENT</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea8147ac333d05a2289a840bc971df80e8</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_HTTP_SERVER_BYTES_RECEIVED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea488ec1787e7822bba4dbe180a2f4b324</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_HTTP_SERVER_CONNECTIONS_TOTAL</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea82505a4094f64e44e3efaebb91dcdcd7</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_HTTP_RESPONSES_1XX</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea5ac222dcd2941ded4d577ee70f7a6d02</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_HTTP_RESPONSES_2XX</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea0fd5fbc4a0cad3431306f26e94c4a6b1</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_HTTP_RESPONSES_3XX</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea60781cacece44aec6d71297d0756d831</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_HTTP_RESPONSES_4XX</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceeaf947fe39578c5421c0ee798b7afbc7c5</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_HTTP_RESPONSES_5XX</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea9ea9f8afe24ace748c8c4b612530cc72</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_TLS_HANDSHAKES_TOTAL</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceeaaf7d0baea6e4e3930da7314edbfa7bb6</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_TLS_HANDSHAKES_FAILED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceeac310776f7b4aae593e90730f0e213d2b</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_TLS_SESSION_REUSE_COUNT</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea3ddea97b6728cd7d48218615e95926a4</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_TLS_CERT_VERIFY_FAILURES</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea2b3cf1bb5dcf3df362a38b24521eda00</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_TLS_RENEGOTIATIONS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea3aaf76f030b15e405bba3d7d83b2f360</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_TLS_PINNING_FAILURES</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea1123d27ca90ba8abe74f33cd98e3385c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_TLS_CT_VERIFICATION_FAILURES</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea9708c06f97d86ece5ebfca3baf3a7f7e</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_TLS_CRL_CHECK_FAILURES</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea6e4638e88f27c45dca6b2c0b1b27ef27</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_DTLS_HANDSHAKES_TOTAL</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea3a29654ecced6f3de9989af568f8d592</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_DTLS_HANDSHAKES_FAILED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceeaa8976118ea565782357f220d181dbd34</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_DTLS_COOKIES_GENERATED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea515eb7dc187e9a2746c17c6309bf5281</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_DTLS_COOKIE_VERIFICATION_FAILURES</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea11af47970a03a26c436ef1bc616485e9</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_DTLS_REPLAY_PACKETS_DETECTED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea4ecac180c7f1bff26623a21bdf276e63</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_DTLS_FRAGMENT_FAILURES</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceead4c08a4071bac7bc3be7021dcded790f</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_DNS_QUERIES_TOTAL</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceeac8439ab5fccc233ac13d82aaff13f42d</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_DNS_QUERIES_FAILED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea14e93ae606e4404c3b3e9183126a67ae</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_DNS_QUERIES_TIMEOUT</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea763f84409208d14e38c7c586263b7e7e</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_DNS_QUERIES_CANCELLED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceeac504adb93c00ae711283026876673d40</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_DNS_CACHE_HITS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea1cde4dca10c4717a6e50c171ac14f70a</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_DNS_CACHE_MISSES</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea19512f0a4c325655cce541b490c62b3d</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_SOCKET_CREATED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceeab856f40396326b740f635ecdec4b78cb</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_SOCKET_CLOSED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceeacc9f32e8a51e4720b53f2f4c6018c055</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_SOCKET_CONNECT_SUCCESS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea4d7c9119fae6202cf8c5bcc1f6cf32ef</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_SOCKET_CONNECT_FAILED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea012e33d28bff41de7468fbb3099c6f9a</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_SOCKET_ACCEPT_TOTAL</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea8748be5c6643b3ebccebb8e3b0c9efaf</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_POLL_WAKEUPS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceead596032b7866cc489959efe27c8a161c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_POLL_EVENTS_DISPATCHED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceeaa519ace23a45810a059ff78ea83f242b</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_POLL_TIMEOUT_EXPIRATIONS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea33ddef985af75f21110138587921557b</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_LIMIT_HEADER_SIZE_EXCEEDED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea87c5cab0d076faf0d8545269857630c0</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_LIMIT_BODY_SIZE_EXCEEDED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea469ad98c6f71e2eb6108ebc62901782e</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_LIMIT_RESPONSE_SIZE_EXCEEDED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceeaefa721fc08c63dceb684b172e52db5e7</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_LIMIT_MEMORY_EXCEEDED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceeab6e4bc443557892912c5bfe9d9f841bb</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_LIMIT_CONNECTIONS_EXCEEDED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea229217bf0b8e0b6f3de27e979cf7ef79</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_LIMIT_STREAMS_EXCEEDED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea6ccae8e4b2e293d7e632a18173313ed4</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_LIMIT_HEADER_LIST_EXCEEDED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea3978f99611080420a4340adb5651ddbd</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_SYNPROTECT_ATTEMPTS_TOTAL</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea114c39672ec4a163cdf4098cf8a0a6eb</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_SYNPROTECT_ALLOWED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceeaa2bdcf00107013bb1ad170891a037fe0</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_SYNPROTECT_THROTTLED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceeaa59d06736065393b3eb7dc485f908731</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_SYNPROTECT_CHALLENGED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea249dcb3f8a49e03f275b8ce71919e339</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_SYNPROTECT_BLOCKED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceead26d8e35ef134d11c6b749b3129ee546</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_SYNPROTECT_WHITELISTED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea13baf5d07c8a93a675dcfef0abe26b98</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_SYNPROTECT_BLACKLISTED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea108cb443d96bcb01a2befa326f800baa</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_CTR_SYNPROTECT_LRU_EVICTIONS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea49e65f7d780e8f5b401428c372738ca1</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_COUNTER_METRIC_COUNT</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1c2d3a4ca0a94b5d52917b2020796ceea0c101f986764f3478eafe2c1bf1b7ea3</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketGaugeMetric</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a9c3c61abc039bebe2eda8b6f9b0574ff</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_GAU_POOL_ACTIVE_CONNECTIONS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a9c3c61abc039bebe2eda8b6f9b0574ffa446185d2f544667977af003ef330602a</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_GAU_POOL_IDLE_CONNECTIONS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a9c3c61abc039bebe2eda8b6f9b0574ffac47f1bdaf5d0df3ffae6504fbe1884d6</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_GAU_POOL_PENDING_CONNECTIONS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a9c3c61abc039bebe2eda8b6f9b0574ffa984ad78555d7b236536ee2311528a4b4</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_GAU_POOL_SIZE</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a9c3c61abc039bebe2eda8b6f9b0574ffade5a4447463c80b1cf103c0e4474b38d</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_GAU_HTTP_CLIENT_ACTIVE_REQUESTS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a9c3c61abc039bebe2eda8b6f9b0574ffabb4d6a47fdc81281817010e07eb1bab8</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_GAU_HTTP_CLIENT_OPEN_CONNECTIONS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a9c3c61abc039bebe2eda8b6f9b0574ffaea6ddc03976de41a6a7aa39a90cea006</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_GAU_HTTP_SERVER_ACTIVE_CONNECTIONS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a9c3c61abc039bebe2eda8b6f9b0574ffad93011513d4df141b8a1c75c061eb601</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_GAU_HTTP_SERVER_ACTIVE_REQUESTS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a9c3c61abc039bebe2eda8b6f9b0574ffa46d69a1bc861fd2e34b032d700d60d47</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_GAU_HTTP_SERVER_QUEUED_REQUESTS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a9c3c61abc039bebe2eda8b6f9b0574ffa701762a5f2fe51a57539f8368e40fdd4</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_GAU_TLS_ACTIVE_SESSIONS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a9c3c61abc039bebe2eda8b6f9b0574ffa42520d99aa0fce9b66eee159a3fcb9bd</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_GAU_TLS_CACHED_SESSIONS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a9c3c61abc039bebe2eda8b6f9b0574ffa6a3c6ce4d17be23ecb15647fc6fb950a</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_GAU_DTLS_ACTIVE_SESSIONS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a9c3c61abc039bebe2eda8b6f9b0574ffa30428b3ed5b61e0877f63406775e9713</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_GAU_DNS_PENDING_QUERIES</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a9c3c61abc039bebe2eda8b6f9b0574ffaabcab9f22c06831d559b83e6195b66ae</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_GAU_DNS_WORKER_THREADS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a9c3c61abc039bebe2eda8b6f9b0574ffa9fe5f07b11823411a057ec5f61f26c9d</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_GAU_DNS_CACHE_SIZE</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a9c3c61abc039bebe2eda8b6f9b0574ffade63dd14fcf55271418604c47509c3f1</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_GAU_SOCKET_OPEN_FDS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a9c3c61abc039bebe2eda8b6f9b0574ffa5597c8e13a2ae6ea7f622fab80e00fa3</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_GAU_POLL_REGISTERED_FDS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a9c3c61abc039bebe2eda8b6f9b0574ffa49bc0db3a4078ebb6dfc37dbf2fa5e2d</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_GAU_POLL_ACTIVE_TIMERS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a9c3c61abc039bebe2eda8b6f9b0574ffac5f5f50c18cbd1e4df4c6f566520b865</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_GAU_SYNPROTECT_TRACKED_IPS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a9c3c61abc039bebe2eda8b6f9b0574ffa2ac4f038181ceef8dd45e2b9fd680156</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_GAU_SYNPROTECT_BLOCKED_IPS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a9c3c61abc039bebe2eda8b6f9b0574ffac6f8904f525325cef938129163b2f0c9</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_GAUGE_METRIC_COUNT</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a9c3c61abc039bebe2eda8b6f9b0574ffa543681a9ea9c38dcc7219e1dde7e7ba4</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketHistogramMetric</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a92d395571ae200be798481ea090e0e1e</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_HIST_POOL_ACQUIRE_TIME_MS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a92d395571ae200be798481ea090e0e1ead858cc3443872f53a524e2a285b9ca07</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_HIST_POOL_CONNECTION_AGE_MS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a92d395571ae200be798481ea090e0e1ea5572c534600bddc6ca7fbb15691343aa</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_HIST_POOL_IDLE_TIME_MS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a92d395571ae200be798481ea090e0e1eadfcc746d42cc93726a3af20e9fefe517</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a92d395571ae200be798481ea090e0e1ea197f63027af31a6a5783184aa9ae4fbd</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_HIST_HTTP_CLIENT_CONNECT_TIME_MS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a92d395571ae200be798481ea090e0e1eabb53719cb13c0d7cf1836a5797224335</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_HIST_HTTP_CLIENT_TTFB_MS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a92d395571ae200be798481ea090e0e1ea99e50c80c5ed5aba18f505ab29941e01</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_HIST_HTTP_CLIENT_RESPONSE_SIZE</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a92d395571ae200be798481ea090e0e1eae6a142e47042024c332d29373618dadf</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_HIST_HTTP_SERVER_REQUEST_LATENCY_MS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a92d395571ae200be798481ea090e0e1ea639c5c4fe6ff72fa817325146734d53f</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_HIST_HTTP_SERVER_RESPONSE_SIZE</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a92d395571ae200be798481ea090e0e1ea6bbd73226e6de01dad82d740f3285e15</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_HIST_HTTP_SERVER_REQUEST_SIZE</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a92d395571ae200be798481ea090e0e1ea8709b38d3289c4c5953d05c883a422ef</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_HIST_TLS_HANDSHAKE_TIME_MS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a92d395571ae200be798481ea090e0e1ead64e5997211c75d4abaa90cd98b8ab39</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_HIST_DTLS_HANDSHAKE_TIME_MS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a92d395571ae200be798481ea090e0e1ea60c53d1297cc720618318af476b452d1</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_HIST_DNS_QUERY_TIME_MS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a92d395571ae200be798481ea090e0e1ea1f82aed60677494fd74769d1b2c975b7</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_HIST_SOCKET_CONNECT_TIME_MS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a92d395571ae200be798481ea090e0e1eafff7ca822fdc69eb6319d04487b88e63</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_HISTOGRAM_METRIC_COUNT</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a92d395571ae200be798481ea090e0e1eaeb16a87bb4144f588f27145249e184b7</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketMetrics_init</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>aeefb37a161dced1c0dcf35cb8c472977</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketMetrics_shutdown</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>ac71136a870ed0e20e810cd9642aa6e88</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketMetrics_counter_inc</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a051f576075a7c5fa39982fc3256127db</anchor>
      <arglist>(SocketCounterMetric metric)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketMetrics_counter_add</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>af6d348200d7a3feabb7be75c73800e3b</anchor>
      <arglist>(SocketCounterMetric metric, uint64_t value)</arglist>
    </member>
    <member kind="function">
      <type>uint64_t</type>
      <name>SocketMetrics_counter_get</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a289b82a795a5b051f500601746c23dcc</anchor>
      <arglist>(SocketCounterMetric metric)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketMetrics_gauge_set</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a136f209696f9bc3f2fc3ad47cdac0458</anchor>
      <arglist>(SocketGaugeMetric metric, int64_t value)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketMetrics_gauge_inc</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a7282975cd0ea7f0b5fd354c13a12a9d0</anchor>
      <arglist>(SocketGaugeMetric metric)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketMetrics_gauge_dec</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a0fff1810314dc75d6082e982243794b4</anchor>
      <arglist>(SocketGaugeMetric metric)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketMetrics_gauge_add</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1063ad9bcbfe8286a7f45af6e4089771</anchor>
      <arglist>(SocketGaugeMetric metric, int64_t value)</arglist>
    </member>
    <member kind="function">
      <type>int64_t</type>
      <name>SocketMetrics_gauge_get</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a35cb4ad83b57507c697c3af957873ce6</anchor>
      <arglist>(SocketGaugeMetric metric)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketMetrics_histogram_observe</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>ade1b121ba0fc5aaf631a0ec0a060843c</anchor>
      <arglist>(SocketHistogramMetric metric, double value)</arglist>
    </member>
    <member kind="function">
      <type>double</type>
      <name>SocketMetrics_histogram_percentile</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a6b7dac1935b1cd51f43a54026a9c2081</anchor>
      <arglist>(SocketHistogramMetric metric, double percentile)</arglist>
    </member>
    <member kind="function">
      <type>uint64_t</type>
      <name>SocketMetrics_histogram_count</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a78400f007fa3b02037322fa951b526b4</anchor>
      <arglist>(SocketHistogramMetric metric)</arglist>
    </member>
    <member kind="function">
      <type>double</type>
      <name>SocketMetrics_histogram_sum</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a7bba5d5d82bd9e034920520a5e0a549e</anchor>
      <arglist>(SocketHistogramMetric metric)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketMetrics_histogram_snapshot</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a4276215e9db206451d0bf5c0277895a2</anchor>
      <arglist>(SocketHistogramMetric metric, SocketMetrics_HistogramSnapshot *snapshot)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketMetrics_get</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a88d6bd8b457374f89aaa5896e0b7bcca</anchor>
      <arglist>(SocketMetrics_Snapshot *snapshot)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketMetrics_reset</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>ab129aa3dd03bc8e5670da9abf0c41a47</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketMetrics_reset_counters</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>abf9b8dc5b74a93097dd1abc4d1c6f173</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketMetrics_reset_histograms</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>ad058c5608e74545a1b26ba51a9c2d579</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketMetrics_export_prometheus</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>ad2d2769789054962f81f3212df75ef35</anchor>
      <arglist>(char *buffer, size_t buffer_size)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketMetrics_export_statsd</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a9dadc443aa052757354ab207cf2261cc</anchor>
      <arglist>(char *buffer, size_t buffer_size, const char *prefix)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketMetrics_export_json</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a2614425d193cc298f59cf4edb4b401f3</anchor>
      <arglist>(char *buffer, size_t buffer_size)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketMetrics_counter_name</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>ab0dea3a76b37f5631595f4a1c429b3ec</anchor>
      <arglist>(SocketCounterMetric metric)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketMetrics_gauge_name</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a1688939050a2c8207534463961107b3c</anchor>
      <arglist>(SocketGaugeMetric metric)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketMetrics_histogram_name</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a339fc134239b6f057572e4d868abb6cb</anchor>
      <arglist>(SocketHistogramMetric metric)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketMetrics_counter_help</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>ae21f0f4d73455a7b37a6de0323fdee41</anchor>
      <arglist>(SocketCounterMetric metric)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketMetrics_gauge_help</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>ab5d0fbf4fb34d69db29bd55f15ddc4a0</anchor>
      <arglist>(SocketGaugeMetric metric)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketMetrics_histogram_help</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>aa5e1f5a07ebccb6667f60603a9f0aaa9</anchor>
      <arglist>(SocketHistogramMetric metric)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketMetrics_category_name</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a6991175422fbbdf883b75713242b0e0f</anchor>
      <arglist>(SocketMetricCategory category)</arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketRateLimit.h</name>
    <path>include/core/</path>
    <filename>SocketRateLimit_8h.html</filename>
    <includes id="Arena_8h" name="Arena.h" local="yes" import="no" module="no" objc="no">core/Arena.h</includes>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <member kind="define">
      <type>#define</type>
      <name>T</name>
      <anchorfile>SocketRateLimit_8h.html</anchorfile>
      <anchor>a0acb682b8260ab1c60b918599864e2e5</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketRateLimit_T *</type>
      <name>SocketRateLimit_T</name>
      <anchorfile>SocketRateLimit_8h.html</anchorfile>
      <anchor>a241a48be9b0f1c7f74e0b8edefeb10a5</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>SocketRateLimit_T</type>
      <name>SocketRateLimit_new</name>
      <anchorfile>SocketRateLimit_8h.html</anchorfile>
      <anchor>a984414b5ee576c6acb3fbd9e8a96ef0f</anchor>
      <arglist>(Arena_T arena, size_t tokens_per_sec, size_t bucket_size)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketRateLimit_free</name>
      <anchorfile>SocketRateLimit_8h.html</anchorfile>
      <anchor>ac871476460ec6f0eeea5ecea0b9e8747</anchor>
      <arglist>(SocketRateLimit_T *limiter)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketRateLimit_try_acquire</name>
      <anchorfile>SocketRateLimit_8h.html</anchorfile>
      <anchor>abb5d1321362b759ed688cfc414c4b2a7</anchor>
      <arglist>(SocketRateLimit_T limiter, size_t tokens)</arglist>
    </member>
    <member kind="function">
      <type>int64_t</type>
      <name>SocketRateLimit_wait_time_ms</name>
      <anchorfile>SocketRateLimit_8h.html</anchorfile>
      <anchor>a5a231dd056cc866fc7652660374e3e3f</anchor>
      <arglist>(SocketRateLimit_T limiter, size_t tokens)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketRateLimit_available</name>
      <anchorfile>SocketRateLimit_8h.html</anchorfile>
      <anchor>aeccac0acfc81db650718aa84162c51f3</anchor>
      <arglist>(SocketRateLimit_T limiter)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketRateLimit_reset</name>
      <anchorfile>SocketRateLimit_8h.html</anchorfile>
      <anchor>a32ac5df3f02155bbf440553f7729978b</anchor>
      <arglist>(SocketRateLimit_T limiter)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketRateLimit_configure</name>
      <anchorfile>SocketRateLimit_8h.html</anchorfile>
      <anchor>a04a0e83dac474ff6a45597eb4e8a37a0</anchor>
      <arglist>(SocketRateLimit_T limiter, size_t tokens_per_sec, size_t bucket_size)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketRateLimit_get_rate</name>
      <anchorfile>SocketRateLimit_8h.html</anchorfile>
      <anchor>a33a8790eeb8ee8f3f2cb7f9c8e7d16c9</anchor>
      <arglist>(SocketRateLimit_T limiter)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketRateLimit_get_bucket_size</name>
      <anchorfile>SocketRateLimit_8h.html</anchorfile>
      <anchor>ab29dadd4e6a32a10eb577cf6f1399994</anchor>
      <arglist>(SocketRateLimit_T limiter)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketRateLimit_debug_live_count</name>
      <anchorfile>SocketRateLimit_8h.html</anchorfile>
      <anchor>ae39058e1d9114bc4dc403587d062b2d6</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketRateLimit_Failed</name>
      <anchorfile>SocketRateLimit_8h.html</anchorfile>
      <anchor>af06f7fa3fe589c3d406f8f12cbc4e59e</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketRetry.h</name>
    <path>include/core/</path>
    <filename>SocketRetry_8h.html</filename>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <class kind="struct">SocketRetry_Policy</class>
    <class kind="struct">SocketRetry_Stats</class>
    <member kind="define">
      <type>#define</type>
      <name>T</name>
      <anchorfile>SocketRetry_8h.html</anchorfile>
      <anchor>a0acb682b8260ab1c60b918599864e2e5</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_RETRY_DEFAULT_MAX_ATTEMPTS</name>
      <anchorfile>SocketRetry_8h.html</anchorfile>
      <anchor>a9e4c6bdc5f6ab59683cef18bb3f58211</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_RETRY_DEFAULT_INITIAL_DELAY_MS</name>
      <anchorfile>SocketRetry_8h.html</anchorfile>
      <anchor>a1b9f06edcbcdd60e892086a4b8c2b9ba</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_RETRY_DEFAULT_MAX_DELAY_MS</name>
      <anchorfile>SocketRetry_8h.html</anchorfile>
      <anchor>ae4c30a1ed41ff40ca11fbdb21c2ec947</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_RETRY_DEFAULT_MULTIPLIER</name>
      <anchorfile>SocketRetry_8h.html</anchorfile>
      <anchor>a2addc89cb7a7a9b6e75f3cd51eef65ac</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_RETRY_DEFAULT_JITTER</name>
      <anchorfile>SocketRetry_8h.html</anchorfile>
      <anchor>afbe9a9852b0477755c295af74aa0f2c7</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_RETRY_MAX_ATTEMPTS</name>
      <anchorfile>SocketRetry_8h.html</anchorfile>
      <anchor>a6245d4aca908bb154e7cd34f6a36d8dd</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketRetry_T *</type>
      <name>SocketRetry_T</name>
      <anchorfile>SocketRetry_8h.html</anchorfile>
      <anchor>a419cec86f54612ef9204c059be3ec0a9</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>int(*</type>
      <name>SocketRetry_Operation</name>
      <anchorfile>SocketRetry_8h.html</anchorfile>
      <anchor>a683a32a8d8f572bacd7470f3d386a445</anchor>
      <arglist>)(void *context, int attempt)</arglist>
    </member>
    <member kind="typedef">
      <type>int(*</type>
      <name>SocketRetry_ShouldRetry</name>
      <anchorfile>SocketRetry_8h.html</anchorfile>
      <anchor>aebff54019f122cf3c0cb72a8ec2ed1b8</anchor>
      <arglist>)(int error, int attempt, void *context)</arglist>
    </member>
    <member kind="function">
      <type>SocketRetry_T</type>
      <name>SocketRetry_new</name>
      <anchorfile>SocketRetry_8h.html</anchorfile>
      <anchor>ac4c2c785391a4a69f76ddb4d9d25f19e</anchor>
      <arglist>(const SocketRetry_Policy *policy)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketRetry_free</name>
      <anchorfile>SocketRetry_8h.html</anchorfile>
      <anchor>ad758455d31f43b861881522be0982d62</anchor>
      <arglist>(SocketRetry_T *retry)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketRetry_execute</name>
      <anchorfile>SocketRetry_8h.html</anchorfile>
      <anchor>ae9cb61aec8d7c8934a7481ed21e3bedf</anchor>
      <arglist>(SocketRetry_T retry, SocketRetry_Operation operation, SocketRetry_ShouldRetry should_retry, void *context)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketRetry_execute_simple</name>
      <anchorfile>SocketRetry_8h.html</anchorfile>
      <anchor>a3a533ebca7a1e19c736a6a1debc07336</anchor>
      <arglist>(SocketRetry_T retry, SocketRetry_Operation operation, void *context)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketRetry_get_stats</name>
      <anchorfile>SocketRetry_8h.html</anchorfile>
      <anchor>aa606e706f22216af24351ee324c0a468</anchor>
      <arglist>(const SocketRetry_T retry, SocketRetry_Stats *stats)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketRetry_reset</name>
      <anchorfile>SocketRetry_8h.html</anchorfile>
      <anchor>aceefc84a75ae5e4ed461d0139ceefaa3</anchor>
      <arglist>(SocketRetry_T retry)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketRetry_get_policy</name>
      <anchorfile>SocketRetry_8h.html</anchorfile>
      <anchor>a16584da7cc4271a025fd7d831446d028</anchor>
      <arglist>(const SocketRetry_T retry, SocketRetry_Policy *policy)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketRetry_set_policy</name>
      <anchorfile>SocketRetry_8h.html</anchorfile>
      <anchor>a29d7511f7531f4a23bd88f656df4636e</anchor>
      <arglist>(SocketRetry_T retry, const SocketRetry_Policy *policy)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketRetry_policy_defaults</name>
      <anchorfile>SocketRetry_8h.html</anchorfile>
      <anchor>ae60e4575d034cfe56be8b50e94ad5481</anchor>
      <arglist>(SocketRetry_Policy *policy)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketRetry_calculate_delay</name>
      <anchorfile>SocketRetry_8h.html</anchorfile>
      <anchor>a04fda3694b0be59a6427d2188af4e9de</anchor>
      <arglist>(const SocketRetry_Policy *policy, int attempt)</arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketRetry_Failed</name>
      <anchorfile>SocketRetry_8h.html</anchorfile>
      <anchor>aee6d3d64f3c5b84ac6bbf38c67834fc4</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketSecurity.h</name>
    <path>include/core/</path>
    <filename>SocketSecurity_8h.html</filename>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="SocketConfig_8h" name="SocketConfig.h" local="yes" import="no" module="no" objc="no">core/SocketConfig.h</includes>
    <class kind="struct">SocketSecurityLimits</class>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SECURITY_MAX_ALLOCATION</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a96a4c4c07078b24744bf2accf84ccaf0</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SECURITY_MAX_BODY_SIZE</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a2c9ad192fd1c92f1b2af612d213f8dc5</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SECURITY_MAX_REQUEST_TIMEOUT_MS</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>aecf2f2b54a209d002ce224d7de9c5e4b</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SECURITY_VALID_SIZE</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>ab118e25b6e3d4b7ba3abb6fb465a4908</anchor>
      <arglist>(s)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SECURITY_CHECK_OVERFLOW_MUL</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>ac0f2047bd8559eff753e7eeeac8c10d2</anchor>
      <arglist>(a, b)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_SECURITY_CHECK_OVERFLOW_ADD</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>ac5270b656510253faca9dca69f21a0fb</anchor>
      <arglist>(a, b)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketSecurity_get_limits</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a8285c075f5ae76fe9d20f4caaf1cee05</anchor>
      <arglist>(SocketSecurityLimits *limits)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketSecurity_get_max_allocation</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a79be1e38c94c11981392c4ef9b272a20</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketSecurity_get_http_limits</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a06285f75bf78cdd2066e8cf6dd17906f</anchor>
      <arglist>(size_t *max_uri, size_t *max_header_size, size_t *max_headers, size_t *max_body)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketSecurity_get_ws_limits</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>aa779b8e16d99a119516a883b12efa558</anchor>
      <arglist>(size_t *max_frame, size_t *max_message)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketSecurity_get_arena_limits</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a6ad722cc32d48bcf38c13c56fb6716bd</anchor>
      <arglist>(size_t *max_alloc)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketSecurity_get_hpack_limits</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>abdf9fc30963bf73b15d168407144a3a1</anchor>
      <arglist>(size_t *max_table)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketSecurity_check_size</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>aa01e772f756ea6885182b7800f50c5f7</anchor>
      <arglist>(size_t size)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketSecurity_check_multiply</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>aa5e5f01fe52f1e55de0e686cf32003aa</anchor>
      <arglist>(size_t a, size_t b, size_t *result)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketSecurity_check_add</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a808c8911cd0b5d129ad1a3ea2e25e2b0</anchor>
      <arglist>(size_t a, size_t b, size_t *result)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static size_t</type>
      <name>SocketSecurity_safe_multiply</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a6270d5672e9d74232fdc5dfca266aa8e</anchor>
      <arglist>(size_t a, size_t b)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static size_t</type>
      <name>SocketSecurity_safe_add</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>ab7fb48da631c0adf8ba5892d1edb2959</anchor>
      <arglist>(size_t a, size_t b)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static int</type>
      <name>SocketSecurity_has_tls</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a85d842e423cb2cf351f0e49b4302f138</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static int</type>
      <name>SocketSecurity_has_compression</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>ab104c1727674778ad21a4648148f3ce1</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketSecurity_SizeExceeded</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a5340f6016fe6c58b24400b7cfd34a4c0</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketSecurity_ValidationFailed</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a4b734ce605590d01801f84c53db3abb0</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketSYNProtect.h</name>
    <path>include/core/</path>
    <filename>SocketSYNProtect_8h.html</filename>
    <includes id="Arena_8h" name="Arena.h" local="yes" import="no" module="no" objc="no">core/Arena.h</includes>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="SocketConfig_8h" name="SocketConfig.h" local="yes" import="no" module="no" objc="no">core/SocketConfig.h</includes>
    <class kind="struct">SocketSYN_IPState</class>
    <class kind="struct">SocketSYNProtect_Config</class>
    <class kind="struct">SocketSYNProtect_Stats</class>
    <member kind="define">
      <type>#define</type>
      <name>T</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a0acb682b8260ab1c60b918599864e2e5</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketSYNProtect_T *</type>
      <name>SocketSYNProtect_T</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a2d44b8e90f00f2e635f7bf123e2e4c10</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketSYN_Action</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>aca8f2a71ab649ccd408fd3fdb3b693b9</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SYN_ACTION_ALLOW</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>aca8f2a71ab649ccd408fd3fdb3b693b9ab7af7c3605f188d109f9528dd72a7af8</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SYN_ACTION_THROTTLE</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>aca8f2a71ab649ccd408fd3fdb3b693b9a57b3e54beba358c83e8a91f2136d61d9</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SYN_ACTION_CHALLENGE</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>aca8f2a71ab649ccd408fd3fdb3b693b9a47e6cde53adccac1b4948afbc22b16d1</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SYN_ACTION_BLOCK</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>aca8f2a71ab649ccd408fd3fdb3b693b9aefd772a5165c7769765f8008396893fa</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketSYN_Reputation</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>ad7b655dd229bc52cb32ec3cc1674d423</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SYN_REP_TRUSTED</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>ad7b655dd229bc52cb32ec3cc1674d423a3c7fc4e1a973261af722ef5a72067c34</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SYN_REP_NEUTRAL</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>ad7b655dd229bc52cb32ec3cc1674d423a3af21cd252d430b04f39badf787d06a2</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SYN_REP_SUSPECT</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>ad7b655dd229bc52cb32ec3cc1674d423ac0634349dad12cd7a8d2a74b9b7cf1be</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SYN_REP_HOSTILE</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>ad7b655dd229bc52cb32ec3cc1674d423a5f79b45826a9103f4f8346e74286ad9d</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>SocketSYNProtect_T</type>
      <name>SocketSYNProtect_new</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a5f5d6f2ac8cbd366d57c1e8e55983143</anchor>
      <arglist>(Arena_T arena, const SocketSYNProtect_Config *config)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketSYNProtect_free</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a9f5cc1e61a0b44b8b1b330ae54382511</anchor>
      <arglist>(SocketSYNProtect_T *protect)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketSYNProtect_config_defaults</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>ade1b436117d4a0854881ac52ce43f115</anchor>
      <arglist>(SocketSYNProtect_Config *config)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketSYNProtect_configure</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a59e979862677789482cb5f297f544001</anchor>
      <arglist>(SocketSYNProtect_T protect, const SocketSYNProtect_Config *config)</arglist>
    </member>
    <member kind="function">
      <type>SocketSYN_Action</type>
      <name>SocketSYNProtect_check</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a45b12919783a7ba4426db4134fda1a5f</anchor>
      <arglist>(SocketSYNProtect_T protect, const char *client_ip, SocketSYN_IPState *state_out)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketSYNProtect_report_success</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a979954abc96c529d1205d432fc13c661</anchor>
      <arglist>(SocketSYNProtect_T protect, const char *client_ip)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketSYNProtect_report_failure</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a573fee7bcaf625b171053b87159af53e</anchor>
      <arglist>(SocketSYNProtect_T protect, const char *client_ip, int error_code)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketSYNProtect_whitelist_add</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a2a601f0c4520ae271b27a49c5bd19108</anchor>
      <arglist>(SocketSYNProtect_T protect, const char *ip)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketSYNProtect_whitelist_add_cidr</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a67fef0b3b6d93c87648e8b0caa1c4bc0</anchor>
      <arglist>(SocketSYNProtect_T protect, const char *cidr)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketSYNProtect_whitelist_remove</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>aa2b5e921cf7b0b24e270870f0ddc92be</anchor>
      <arglist>(SocketSYNProtect_T protect, const char *ip)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketSYNProtect_whitelist_contains</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a5036b24b808b28a69de280c9ce0727fc</anchor>
      <arglist>(SocketSYNProtect_T protect, const char *ip)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketSYNProtect_whitelist_clear</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a50962d47d9b56957714f313e2051e1bf</anchor>
      <arglist>(SocketSYNProtect_T protect)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketSYNProtect_blacklist_add</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a02eca11c24cc41b3f1fafdcbcae6e485</anchor>
      <arglist>(SocketSYNProtect_T protect, const char *ip, int duration_ms)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketSYNProtect_blacklist_remove</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a4e67e158bb567ffb7620738ba28b16f8</anchor>
      <arglist>(SocketSYNProtect_T protect, const char *ip)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketSYNProtect_blacklist_contains</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a88d4fb38017492beca3f130d311dadd5</anchor>
      <arglist>(SocketSYNProtect_T protect, const char *ip)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketSYNProtect_blacklist_clear</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a9519e23838092f497693c4a488789f1b</anchor>
      <arglist>(SocketSYNProtect_T protect)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketSYNProtect_get_ip_state</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a36629010083cc94526b37d57cc40bbce</anchor>
      <arglist>(SocketSYNProtect_T protect, const char *ip, SocketSYN_IPState *state)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketSYNProtect_stats</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a602057379b47f0e3dbf46b6efd70a09a</anchor>
      <arglist>(SocketSYNProtect_T protect, SocketSYNProtect_Stats *stats)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketSYNProtect_stats_reset</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a59f2d1168a808c2c2d0584b031d96422</anchor>
      <arglist>(SocketSYNProtect_T protect)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketSYNProtect_action_name</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a6be6d5871d5869421280eb62f3492ca3</anchor>
      <arglist>(SocketSYN_Action action)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketSYNProtect_reputation_name</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>aaf2b0ff9a3054e262ba32b395c2abe50</anchor>
      <arglist>(SocketSYN_Reputation rep)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketSYNProtect_cleanup</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a89041cde278498408febb062da3dd23b</anchor>
      <arglist>(SocketSYNProtect_T protect)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketSYNProtect_clear_all</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>ae797fcaf42654cdba172ab72a327a8b1</anchor>
      <arglist>(SocketSYNProtect_T protect)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketSYNProtect_reset</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a01aa18277f6346e8803de9f705573528</anchor>
      <arglist>(SocketSYNProtect_T protect)</arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketSYNProtect_Failed</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>acfbf054296946c43e621dcf10b9295a9</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketTimer.h</name>
    <path>include/core/</path>
    <filename>SocketTimer_8h.html</filename>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <member kind="define">
      <type>#define</type>
      <name>T</name>
      <anchorfile>SocketTimer_8h.html</anchorfile>
      <anchor>a0acb682b8260ab1c60b918599864e2e5</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketTimer_T *</type>
      <name>SocketTimer_T</name>
      <anchorfile>SocketTimer_8h.html</anchorfile>
      <anchor>a89e39166f8e24595119733321f2a313e</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketPoll_T *</type>
      <name>SocketPoll_T</name>
      <anchorfile>SocketTimer_8h.html</anchorfile>
      <anchor>af9e4be8bc025aedb61cc0b77e8926312</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>void(*</type>
      <name>SocketTimerCallback</name>
      <anchorfile>SocketTimer_8h.html</anchorfile>
      <anchor>afb51f69cdbf1b882a7a4226959c4fca7</anchor>
      <arglist>)(void *userdata)</arglist>
    </member>
    <member kind="function">
      <type>SocketTimer_T</type>
      <name>SocketTimer_add</name>
      <anchorfile>SocketTimer_8h.html</anchorfile>
      <anchor>a2537cebf106e583079ec472086a26d65</anchor>
      <arglist>(SocketPoll_T poll, int64_t delay_ms, SocketTimerCallback callback, void *userdata)</arglist>
    </member>
    <member kind="function">
      <type>SocketTimer_T</type>
      <name>SocketTimer_add_repeating</name>
      <anchorfile>SocketTimer_8h.html</anchorfile>
      <anchor>a6961bde0e491d732450b66577294d097</anchor>
      <arglist>(SocketPoll_T poll, int64_t interval_ms, SocketTimerCallback callback, void *userdata)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketTimer_cancel</name>
      <anchorfile>SocketTimer_8h.html</anchorfile>
      <anchor>a6f7ca05c6cfc7c69ddc3d676a681bc62</anchor>
      <arglist>(SocketPoll_T poll, SocketTimer_T timer)</arglist>
    </member>
    <member kind="function">
      <type>int64_t</type>
      <name>SocketTimer_remaining</name>
      <anchorfile>SocketTimer_8h.html</anchorfile>
      <anchor>a4c5519b89e0bba69f26d03b6893ba779</anchor>
      <arglist>(SocketPoll_T poll, SocketTimer_T timer)</arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketTimer_Failed</name>
      <anchorfile>SocketTimer_8h.html</anchorfile>
      <anchor>a2f0acf311c238671c6d9d14d4cc7c158</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketUTF8.h</name>
    <path>include/core/</path>
    <filename>SocketUTF8_8h.html</filename>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <class kind="struct">SocketUTF8_State</class>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_UTF8_MAX_BYTES</name>
      <anchorfile>SocketUTF8_8h.html</anchorfile>
      <anchor>ac2c24c8a574da982e47bc14c90c51fcb</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_UTF8_MAX_CODEPOINT</name>
      <anchorfile>SocketUTF8_8h.html</anchorfile>
      <anchor>aa9c7795dd42c45a40d759b981ea2a124</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_UTF8_SURROGATE_MIN</name>
      <anchorfile>SocketUTF8_8h.html</anchorfile>
      <anchor>a93252af0c4c16e848f1faad437679dea</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_UTF8_SURROGATE_MAX</name>
      <anchorfile>SocketUTF8_8h.html</anchorfile>
      <anchor>a45fdc9df7fba5033d071135c934b8547</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_UTF8_1BYTE_MAX</name>
      <anchorfile>SocketUTF8_8h.html</anchorfile>
      <anchor>a79465648f060b79ec961cc626975a533</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_UTF8_2BYTE_MAX</name>
      <anchorfile>SocketUTF8_8h.html</anchorfile>
      <anchor>a93e8c5ea6de08b28ab080057cd17423c</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_UTF8_3BYTE_MAX</name>
      <anchorfile>SocketUTF8_8h.html</anchorfile>
      <anchor>a02b7ac016b2dbc2c374081887ef684d5</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_UTF8_4BYTE_MIN</name>
      <anchorfile>SocketUTF8_8h.html</anchorfile>
      <anchor>ad3cc04d775e04588a8446aedca62326f</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketUTF8_Result</name>
      <anchorfile>SocketUTF8_8h.html</anchorfile>
      <anchor>ae8b6c527962e3019992746f49aac247b</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>UTF8_VALID</name>
      <anchorfile>SocketUTF8_8h.html</anchorfile>
      <anchor>ae8b6c527962e3019992746f49aac247ba99d5b2d72aaf988d870a6d9528251f71</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>UTF8_INVALID</name>
      <anchorfile>SocketUTF8_8h.html</anchorfile>
      <anchor>ae8b6c527962e3019992746f49aac247ba5517838e6342334352553b1013ced8e6</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>UTF8_INCOMPLETE</name>
      <anchorfile>SocketUTF8_8h.html</anchorfile>
      <anchor>ae8b6c527962e3019992746f49aac247ba4d8dbfb5b4a4d95abd8662b58f0ec402</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>UTF8_OVERLONG</name>
      <anchorfile>SocketUTF8_8h.html</anchorfile>
      <anchor>ae8b6c527962e3019992746f49aac247baa8dc4f40f8b669aaf6dcc16cf64c9b6c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>UTF8_SURROGATE</name>
      <anchorfile>SocketUTF8_8h.html</anchorfile>
      <anchor>ae8b6c527962e3019992746f49aac247ba9b6f15c76888c3639b5d42aab0f8c26f</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>UTF8_TOO_LARGE</name>
      <anchorfile>SocketUTF8_8h.html</anchorfile>
      <anchor>ae8b6c527962e3019992746f49aac247ba6dbaccc954823626b88b579a7f6d6fb0</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>SocketUTF8_Result</type>
      <name>SocketUTF8_validate</name>
      <anchorfile>SocketUTF8_8h.html</anchorfile>
      <anchor>a68491b1f63c513ccc96a83a14d069e7b</anchor>
      <arglist>(const unsigned char *data, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>SocketUTF8_Result</type>
      <name>SocketUTF8_validate_str</name>
      <anchorfile>SocketUTF8_8h.html</anchorfile>
      <anchor>a409d0ca4c468b8ca69e7b3b75c58841d</anchor>
      <arglist>(const char *str)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketUTF8_init</name>
      <anchorfile>SocketUTF8_8h.html</anchorfile>
      <anchor>a63e171e87998e78fb1398213e4ebc9a5</anchor>
      <arglist>(SocketUTF8_State *state)</arglist>
    </member>
    <member kind="function">
      <type>SocketUTF8_Result</type>
      <name>SocketUTF8_update</name>
      <anchorfile>SocketUTF8_8h.html</anchorfile>
      <anchor>ac7bf6c0717c79f93d931fcd50bf04b60</anchor>
      <arglist>(SocketUTF8_State *state, const unsigned char *data, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>SocketUTF8_Result</type>
      <name>SocketUTF8_finish</name>
      <anchorfile>SocketUTF8_8h.html</anchorfile>
      <anchor>a388818b9081b6d4f7ad496c6f4a364ad</anchor>
      <arglist>(const SocketUTF8_State *state)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketUTF8_reset</name>
      <anchorfile>SocketUTF8_8h.html</anchorfile>
      <anchor>a46408361a51a348e46420dfeeb3cca5c</anchor>
      <arglist>(SocketUTF8_State *state)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketUTF8_codepoint_len</name>
      <anchorfile>SocketUTF8_8h.html</anchorfile>
      <anchor>a1563bde34c7c6e25d605d3d4d64ca103</anchor>
      <arglist>(uint32_t codepoint)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketUTF8_sequence_len</name>
      <anchorfile>SocketUTF8_8h.html</anchorfile>
      <anchor>a1544e5297cf89454b89912f8c8af9046</anchor>
      <arglist>(unsigned char first_byte)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketUTF8_encode</name>
      <anchorfile>SocketUTF8_8h.html</anchorfile>
      <anchor>a0d7d4a24b88fb2a7add5dce1a5ffdecf</anchor>
      <arglist>(uint32_t codepoint, unsigned char *output)</arglist>
    </member>
    <member kind="function">
      <type>SocketUTF8_Result</type>
      <name>SocketUTF8_decode</name>
      <anchorfile>SocketUTF8_8h.html</anchorfile>
      <anchor>aa22db28501f980ac3124b9ec4986fdb8</anchor>
      <arglist>(const unsigned char *data, size_t len, uint32_t *codepoint, size_t *consumed)</arglist>
    </member>
    <member kind="function">
      <type>SocketUTF8_Result</type>
      <name>SocketUTF8_count_codepoints</name>
      <anchorfile>SocketUTF8_8h.html</anchorfile>
      <anchor>a473245344234f9352a2b968201d39634</anchor>
      <arglist>(const unsigned char *data, size_t len, size_t *count)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketUTF8_result_string</name>
      <anchorfile>SocketUTF8_8h.html</anchorfile>
      <anchor>a305b150f1e0b525b236bf0a8952c5315</anchor>
      <arglist>(SocketUTF8_Result result)</arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketUTF8_Failed</name>
      <anchorfile>SocketUTF8_8h.html</anchorfile>
      <anchor>a96b509b874774db6b22b3f25438a21d2</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketUtil.h</name>
    <path>include/core/</path>
    <filename>SocketUtil_8h.html</filename>
    <includes id="Arena_8h" name="Arena.h" local="yes" import="no" module="no" objc="no">core/Arena.h</includes>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="SocketConfig_8h" name="SocketConfig.h" local="yes" import="no" module="no" objc="no">core/SocketConfig.h</includes>
    <class kind="struct">SocketLogContext</class>
    <class kind="struct">SocketLogField</class>
    <class kind="struct">SocketMetricsSnapshot</class>
    <class kind="struct">SocketEventRecord</class>
    <class kind="union">SocketEventRecord.data</class>
    <class kind="struct">SocketEventRecord.data.connection</class>
    <class kind="struct">SocketEventRecord.data.dns</class>
    <class kind="struct">SocketEventRecord.data.poll</class>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_LOG_COMPONENT</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>ae461bf5ddae6eda683926a6303af87f6</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_LOG_TRACE_MSG</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a365ac6909cf8507f035810946214e639</anchor>
      <arglist>(fmt,...)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_LOG_DEBUG_MSG</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a7853a630bcaead9d41536ccbfd598f6d</anchor>
      <arglist>(fmt,...)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_LOG_INFO_MSG</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a9fe70c7ab8b971af2971f3a102b82819</anchor>
      <arglist>(fmt,...)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_LOG_WARN_MSG</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>ae560ccd4aef66d44e8ecbd256844059c</anchor>
      <arglist>(fmt,...)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_LOG_ERROR_MSG</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a16642c35dec627aeb4976538671b1552</anchor>
      <arglist>(fmt,...)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_LOG_FATAL_MSG</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a6b6e85cf504e70eab7723ba1b685fcdb</anchor>
      <arglist>(fmt,...)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_LOG_ID_SIZE</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>af0a8020773c3515507db1705a81b7fe4</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_LOG_FIELDS</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a7bcc2412d2238abb586fedf1e5fd6f0f</anchor>
      <arglist>(...)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_ERROR_APPLY_TRUNCATION</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acb8273a8b69ebd471d3bf7da0290349b</anchor>
      <arglist>(ret)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_ERROR_FMT</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>adf114e63024eabf6e40f1ed7f89c79b8</anchor>
      <arglist>(fmt,...)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_ERROR_MSG</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a1feea47474a6b6e939c442cdd7c42fdb</anchor>
      <arglist>(fmt,...)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_ENOMEM</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a234dada5f4ad714b6c7d5b0bbdb6e286</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_EINVAL</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>aef414ad0ad23570de1d46006702ea335</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_ECONNREFUSED</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>af177b6c500b1dd0c533d3388339ba9f9</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_ETIMEDOUT</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acaa8bd0edd40626f55e609edb16a99c9</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_EADDRINUSE</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a4fcf3dfb4b98cdacaa2c5f81991f0cde</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_ENETUNREACH</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a9389acfe091c635a5dedfe9f8875cb05</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_EHOSTUNREACH</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>aa13fca165325d7951760a812e42437a8</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_EPIPE</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>aa25bef791e389cebb192959272a2705d</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_ECONNRESET</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>ab8a20870f3b2306f710567014393d9d7</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DECLARE_MODULE_EXCEPTION</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a9a80f14591d4cdb7347af54b5f66e766</anchor>
      <arglist>(module_name)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_RAISE_MODULE_ERROR</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>aba03b2fa3f583e8cc687a3247db5a91b</anchor>
      <arglist>(module_name, exception)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_RAISE_FMT</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>ad3f0d856a8ffbd9d81975ccacb7ff6d8</anchor>
      <arglist>(module_name, exception, fmt,...)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_RAISE_MSG</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>aa7d4ca3a984cb2df9849f6b501d65cc3</anchor>
      <arglist>(module_name, exception, fmt,...)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_UTIL_DJB2_SEED</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a647c48c32c0eedfad4a47d3ebaf4650e</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>void(*</type>
      <name>SocketLogCallback</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>add820ca01810b616cfe1d6fef0cbf899</anchor>
      <arglist>)(void *userdata, SocketLogLevel level, const char *component, const char *message)</arglist>
    </member>
    <member kind="typedef">
      <type>void(*</type>
      <name>SocketLogStructuredCallback</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>ad6d1accb7b4404506736d8778ebe47e0</anchor>
      <arglist>)(void *userdata, SocketLogLevel level, const char *component, const char *message, const SocketLogField *fields, size_t field_count, const SocketLogContext *context)</arglist>
    </member>
    <member kind="typedef">
      <type>void(*</type>
      <name>SocketEventCallback</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a3d3a15715d38d991d2e0227b21d70bf1</anchor>
      <arglist>)(void *userdata, const SocketEventRecord *event)</arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketLogLevel</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>adf209a9f107e88a5df277fcc3e2641d1</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_LOG_TRACE</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>adf209a9f107e88a5df277fcc3e2641d1a92a6d90e1c955ab3ad5fff67e93e969e</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_LOG_DEBUG</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>adf209a9f107e88a5df277fcc3e2641d1afcef44613645b3fd4a45bf5b4bfdbba7</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_LOG_INFO</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>adf209a9f107e88a5df277fcc3e2641d1a0c366302769a94f7e8f4d535f4cc5716</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_LOG_WARN</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>adf209a9f107e88a5df277fcc3e2641d1ae3b46610cd2f65cecc4fa333a827212c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_LOG_ERROR</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>adf209a9f107e88a5df277fcc3e2641d1a541aa883db8e38a0c52a2d7ccfb795b3</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_LOG_FATAL</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>adf209a9f107e88a5df277fcc3e2641d1a675d837d7437c7792d86366a567acb57</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketMetric</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5a</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_SOCKET_CONNECT_SUCCESS</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aa7e78a886cdc9334f8a7b5f0df750fd63</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_SOCKET_CONNECT_FAILURE</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aa96d0ebae18f954ff3648e641e104f120</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_SOCKET_SHUTDOWN_CALL</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aa087373eb2e3fb13088acaa7f881b019c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_DNS_REQUEST_SUBMITTED</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aad1a05af32712ded666342aaaab4e56fb</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_DNS_REQUEST_COMPLETED</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aac408edbfed5539bd89168cb9ad611f81</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_DNS_REQUEST_FAILED</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aabeaeaceee778c6b88164609a4caf95ca</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_DNS_REQUEST_CANCELLED</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aafbf83854162fbc828b0d116f1c2951e3</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_DNS_REQUEST_TIMEOUT</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aa7f1ef6385e38262925cabed4c0400a89</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_POLL_WAKEUPS</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aacbd607b50fdb083e406bfdb6e7121071</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_POLL_EVENTS_DISPATCHED</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aa10fcaa4ca61ed9049d38588cfee7ae19</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_POOL_CONNECTIONS_ADDED</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aaa72d81d8975ba0f5b168f3257cadccbc</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_POOL_CONNECTIONS_REMOVED</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aa4f00b666298a269e694162e94de57eaf</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_POOL_CONNECTIONS_REUSED</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aa31fb10d34aa5b27a3bca9813c66699ea</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_POOL_DRAIN_INITIATED</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aaa03c9846d735de7d02e5238fc55eef2d</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_POOL_DRAIN_COMPLETED</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aa2b6bee98ce6b6dabc241e660f00ddfd0</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_POOL_HEALTH_CHECKS</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aa4f5a9a50e20a5872837a315e260edd14</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_POOL_HEALTH_FAILURES</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aa8d93d6bb51819fafab7432caa04ccb3c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_POOL_VALIDATION_FAILURES</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aa964a9546827911dd206d1421fd350c2e</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_POOL_IDLE_CLEANUPS</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aa002fb5e2a1f84e978823670f7744f624</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_COUNT</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aaac38b493847141d2bfc1600c6b093fbb</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketEventType</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a3d88a760170998089d33794edca8d1bf</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_EVENT_ACCEPTED</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a3d88a760170998089d33794edca8d1bfa4865afb9d526d792c2afd8ca6168f2d7</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_EVENT_CONNECTED</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a3d88a760170998089d33794edca8d1bfa007de01376b29a77df52df9f87676ad6</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_EVENT_DNS_TIMEOUT</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a3d88a760170998089d33794edca8d1bfa54b71a4bbfbe3ef9fec249a2ce9f23f3</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_EVENT_POLL_WAKEUP</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a3d88a760170998089d33794edca8d1bfa4b3179bc062ecb5767e4fd69509f654e</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketErrorCode</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_NONE</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908ac605c1464f7a5fce4d2bf43db9604c9e</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EINVAL</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908ad7caea7b3de0e8a2d61efd49ed592127</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EACCES</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a9725ca6ddcb4e92ff1e9ecfdafd00ce7</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EADDRINUSE</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a08206822505583f83a334ade68139a75</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EADDRNOTAVAIL</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908ae812c8ca9ef677ef71a1d2421ce95135</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EAFNOSUPPORT</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a480e61645ca011af9282df6dacc4c2b3</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EAGAIN</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a00acb29ee302472a59b7e01718965ad3</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EALREADY</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908aebbc124b3c19fddedb3b8b45ab27f55c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EBADF</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a41de97b600a4478d3a512694d7c133e6</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_ECONNREFUSED</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908adfe88ce6edfed915da57d0ffae22b344</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_ECONNRESET</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a475f39fb23ebd0bec24b2e3c223e7a16</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EFAULT</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908ac3466349867e835c0004904a49a5db2f</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EHOSTUNREACH</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a32950d5582e28113e55151572acb71c8</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EINPROGRESS</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a9036b8ffc6fdf52e82ae24cc0b99f5fe</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EINTR</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a14dbd2cfb803fb498d9fe739b064ba46</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EISCONN</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908ac228d15b5fa5ec6fd8cd597f798cd3e9</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EMFILE</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a5e48f23169549a7d8bcbf436e4c69ad9</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_ENETUNREACH</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a4eea48e149cc5a90c78e7c73e0993840</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_ENOBUFS</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a36af864cb84c9e3b8e39a881ca5922bb</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_ENOMEM</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a06cc3f5f024f0e7fdee572949b186b4d</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_ENOTCONN</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908aac4990877a3f397ce4992bed66feaf3f</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_ENOTSOCK</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a4f7a06893610177371a7c901f5f7cbae</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EOPNOTSUPP</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a6cbb58736db2c84e95ffd6ab98c8c8cc</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EPIPE</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a0fd072c863033aa60d6d07aac9ac0fd8</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EPROTONOSUPPORT</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a3f9e0c3e6d07ffa0c67cf253fb70b543</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_ETIMEDOUT</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908aa0e56c1808b8ffda13e17400a31bc504</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EWOULDBLOCK</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908ae027d95cf67fde3c178b082cf1770dc5</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_UNKNOWN</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a77387cd59d0eaec78ac8af7a8d8c1b7e</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketErrorCategory</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a03afe0122d51352f66339825b1eb23b9</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_CATEGORY_NETWORK</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a03afe0122d51352f66339825b1eb23b9a6652ea8ed6fd071490684c61ec3bb89b</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_CATEGORY_PROTOCOL</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a03afe0122d51352f66339825b1eb23b9a68506b7a00d8744bc266b799c46c253b</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_CATEGORY_APPLICATION</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a03afe0122d51352f66339825b1eb23b9a5dfb3fbb41aaf264675f3575bb6932f6</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_CATEGORY_TIMEOUT</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a03afe0122d51352f66339825b1eb23b9a71956723dac39958d452934301e4bd32</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_CATEGORY_RESOURCE</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a03afe0122d51352f66339825b1eb23b9aed5f3770fcdda96b52d1ec13776ab328</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_CATEGORY_UNKNOWN</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a03afe0122d51352f66339825b1eb23b9a1e44c5da343948255455a1f0fb019419</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketLog_setcallback</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a1e1c2036c1e8e227409d3cb2dfab8fc2</anchor>
      <arglist>(SocketLogCallback callback, void *userdata)</arglist>
    </member>
    <member kind="function">
      <type>SocketLogCallback</type>
      <name>SocketLog_getcallback</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>afb6f1052e2778e1b46a084ef457881dc</anchor>
      <arglist>(void **userdata)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketLog_levelname</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a6bf61f863971355d13751fa2d76bc1d4</anchor>
      <arglist>(SocketLogLevel level)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketLog_emit</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a1364e85e147f0f6d43c82b4ce3e326c1</anchor>
      <arglist>(SocketLogLevel level, const char *component, const char *message)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketLog_emitf</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a32c7a8dfa2948f777cdb62152fe2f6ac</anchor>
      <arglist>(SocketLogLevel level, const char *component, const char *fmt,...)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketLog_emitfv</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a9e7b0a943fc425eb44f0f22c7f2e304d</anchor>
      <arglist>(SocketLogLevel level, const char *component, const char *fmt, va_list args)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketLog_setlevel</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>ad555b9c9e333d03766b0a0a5d1718111</anchor>
      <arglist>(SocketLogLevel min_level)</arglist>
    </member>
    <member kind="function">
      <type>SocketLogLevel</type>
      <name>SocketLog_getlevel</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>adea5df0324ab107503097ef91327cf1f</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketLog_setcontext</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a0c14479ea972fb3ae90c7f13d449e1ff</anchor>
      <arglist>(const SocketLogContext *ctx)</arglist>
    </member>
    <member kind="function">
      <type>const SocketLogContext *</type>
      <name>SocketLog_getcontext</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a1af6754916a1a307ddbbedd2a1f1497a</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketLog_clearcontext</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a13d1f0df4c0447eba5d723c3f2a81ff3</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketLog_setstructuredcallback</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acea087e19ba17c0c7d2ee7eaf7be97d9</anchor>
      <arglist>(SocketLogStructuredCallback callback, void *userdata)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketLog_emit_structured</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>ab0d6c6969a0d1866a35b8a7cb89a70dd</anchor>
      <arglist>(SocketLogLevel level, const char *component, const char *message, const SocketLogField *fields, size_t field_count)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketMetrics_increment</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a84618017b97e3f0eeb3c4814e939a7b4</anchor>
      <arglist>(SocketMetric metric, unsigned long value)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketMetrics_getsnapshot</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>adf35517a39395522a5884f9d92c7086d</anchor>
      <arglist>(SocketMetricsSnapshot *snapshot)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketMetrics_legacy_reset</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a9697727ca9f22ed6b849da5bc5f6742e</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketMetrics_name</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a6651459184d27e580841a193a5380bf8</anchor>
      <arglist>(SocketMetric metric)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketMetrics_count</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>ae500ae3a4e6dc4b4ba83182988453cc7</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static unsigned long long</type>
      <name>SocketMetrics_snapshot_value</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a820e9846700ad0b85c0ad19e7324825e</anchor>
      <arglist>(const SocketMetricsSnapshot *snapshot, SocketMetric metric)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketEvent_register</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a2c2f3b63d230253cdd09e88a376a0c65</anchor>
      <arglist>(SocketEventCallback callback, void *userdata)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketEvent_unregister</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a901a01760a9d58ba637808d77070cb18</anchor>
      <arglist>(SocketEventCallback callback, const void *userdata)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketEvent_emit_accept</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>afa5f95ceb1326a7d8ec9f9ee73e43ae3</anchor>
      <arglist>(int fd, const char *peer_addr, int peer_port, const char *local_addr, int local_port)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketEvent_emit_connect</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>aa055221abd54d23cd82ec0b192c13efa</anchor>
      <arglist>(int fd, const char *peer_addr, int peer_port, const char *local_addr, int local_port)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketEvent_emit_dns_timeout</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>ac4791bcfc3ee22f39b3924782434a6f8</anchor>
      <arglist>(const char *host, int port)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketEvent_emit_poll_wakeup</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a25ba2d0eb453e5e42f9c5ed8b8a64e09</anchor>
      <arglist>(int nfds, int timeout_ms)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>Socket_GetLastError</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>ac71a25566cdc9e11eaecb16c966081db</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_geterrno</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>aacd3ef2f86186c451f2eb90cd490eae5</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>SocketErrorCode</type>
      <name>Socket_geterrorcode</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a46f8d730d28e8c5cbd55e3cbe4c83945</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>Socket_safe_strerror</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a481ecfe6b9e5c83515c92d1808e4b2f9</anchor>
      <arglist>(int errnum)</arglist>
    </member>
    <member kind="function">
      <type>SocketErrorCategory</type>
      <name>SocketError_categorize_errno</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a4b19847d604cdc5896376e694ee2a9c1</anchor>
      <arglist>(int err)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketError_category_name</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>ac08e05a6f47966909427f4f327d33192</anchor>
      <arglist>(SocketErrorCategory category)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketError_is_retryable_errno</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a78065a32bc90c30a5d062b0b9ac88163</anchor>
      <arglist>(int err)</arglist>
    </member>
    <member kind="function">
      <type>int64_t</type>
      <name>Socket_get_monotonic_ms</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a264bfa9d1cf07aa22446a4df6c4936bf</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static unsigned</type>
      <name>socket_util_hash_fd</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a62f7a03bb960ab153cb4b8dd0f114980</anchor>
      <arglist>(int fd, unsigned table_size)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static unsigned</type>
      <name>socket_util_hash_ptr</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a0c1ed7481fd58c8cbb7e47b8a614b556</anchor>
      <arglist>(const void *ptr, unsigned table_size)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static unsigned</type>
      <name>socket_util_hash_uint</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a81d733432a2030afb97cd12be61e7054</anchor>
      <arglist>(unsigned value, unsigned table_size)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static unsigned</type>
      <name>socket_util_hash_uint_seeded</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>ac2f441288fd2e497dd99474ef017f31f</anchor>
      <arglist>(unsigned value, unsigned table_size, uint32_t seed)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static unsigned</type>
      <name>socket_util_hash_djb2</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a9fdc2111b7d6f5bce04dce7a5af67dea</anchor>
      <arglist>(const char *str, unsigned table_size)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static unsigned</type>
      <name>socket_util_hash_djb2_len</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a501ef681ae3253891ee2058bebff5af2</anchor>
      <arglist>(const char *str, size_t len, unsigned table_size)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static unsigned</type>
      <name>socket_util_hash_djb2_ci</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acef886c3ad801fa342744f5f1e7cc6a5</anchor>
      <arglist>(const char *str, unsigned table_size)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static unsigned</type>
      <name>socket_util_hash_djb2_ci_len</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>aacb8ea34fa3de46f676cc0b1bd887f66</anchor>
      <arglist>(const char *str, size_t len, unsigned table_size)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static size_t</type>
      <name>socket_util_round_up_pow2</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>acd7c2df90f755def2ac7e1edeef37538</anchor>
      <arglist>(size_t n)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static char *</type>
      <name>socket_util_arena_strdup</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a1af76425187cb52fda8d569dcc931e2d</anchor>
      <arglist>(Arena_T arena, const char *str)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static char *</type>
      <name>socket_util_arena_strndup</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a0309fe77e3df0b7cd2c662f77c21c045</anchor>
      <arglist>(Arena_T arena, const char *str, size_t maxlen)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static int64_t</type>
      <name>SocketTimeout_now_ms</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a528ca682da1482e87bfa1e2af9d9ccf1</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static int64_t</type>
      <name>SocketTimeout_deadline_ms</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>ab64414cb92e686d4410c702aecbc46be</anchor>
      <arglist>(int timeout_ms)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static int64_t</type>
      <name>SocketTimeout_remaining_ms</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a199880a57fe7bebb439b5d1f1aa967c7</anchor>
      <arglist>(int64_t deadline_ms)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static int</type>
      <name>SocketTimeout_expired</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a22d242f7f47f94f867a687b05eaf1d2c</anchor>
      <arglist>(int64_t deadline_ms)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static int</type>
      <name>SocketTimeout_poll_timeout</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a0ade80c651b5f022bf9fec6aea303e71</anchor>
      <arglist>(int current_timeout_ms, int64_t deadline_ms)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static int64_t</type>
      <name>SocketTimeout_elapsed_ms</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a179e76e704b475882b35ccef7e7f8787</anchor>
      <arglist>(int64_t start_ms)</arglist>
    </member>
    <member kind="variable">
      <type>char</type>
      <name>socket_error_buf</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>aad11dd8cef83792df92437f8d7ae3991</anchor>
      <arglist>[1024]</arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>socket_last_errno</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>af5b8b680923b7f67d1ec0aa8c0b0434e</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketDNS.h</name>
    <path>include/dns/</path>
    <filename>SocketDNS_8h.html</filename>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <member kind="define">
      <type>#define</type>
      <name>T</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>a0acb682b8260ab1c60b918599864e2e5</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>Request_T</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>aa9ba864e1a3353563283aa17b57abd88</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketDNS_T *</type>
      <name>SocketDNS_T</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>ac9190fe07142a017f86dae46145cb2fd</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketDNS_Request_T *</type>
      <name>SocketDNS_Request_T</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>a2d39e79bb7d4fa2271b6158750267c13</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>void(*</type>
      <name>SocketDNS_Callback</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>a09004bbc0b6c4d606530226f9fff912a</anchor>
      <arglist>)(SocketDNS_Request_T req, struct addrinfo *result, int error, void *data)</arglist>
    </member>
    <member kind="function">
      <type>SocketDNS_T</type>
      <name>SocketDNS_new</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>a799f4d96c77eef54ecb9be5523b591fd</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDNS_free</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>abdc83f21f67b5b8557f35d7ffa4c839c</anchor>
      <arglist>(SocketDNS_T *dns)</arglist>
    </member>
    <member kind="function">
      <type>SocketDNS_Request_T</type>
      <name>SocketDNS_resolve</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>ac4df82b60dff42e9104a19062074a2f5</anchor>
      <arglist>(SocketDNS_T dns, const char *host, int port, SocketDNS_Callback callback, void *data)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDNS_cancel</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>ae1d672627973547345ad91e2e83f30b6</anchor>
      <arglist>(SocketDNS_T dns, SocketDNS_Request_T req)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketDNS_getmaxpending</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>a68f007d40e50ed2894c962ee91509fcc</anchor>
      <arglist>(SocketDNS_T dns)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDNS_setmaxpending</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>a55b33b7c9a44dc087be0f74b259d54f7</anchor>
      <arglist>(SocketDNS_T dns, size_t max_pending)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDNS_gettimeout</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>a2f4c54acbc79bbb31a4ce3ec75928ee8</anchor>
      <arglist>(SocketDNS_T dns)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDNS_settimeout</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>a390b733f1a522dcaccede3adf56fece0</anchor>
      <arglist>(SocketDNS_T dns, int timeout_ms)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDNS_pollfd</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>a9228880ada42145db04298282b5f0c80</anchor>
      <arglist>(SocketDNS_T dns)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDNS_check</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>ad8f2fa5ee464e84f44b4b6059b4813e5</anchor>
      <arglist>(SocketDNS_T dns)</arglist>
    </member>
    <member kind="function">
      <type>struct addrinfo *</type>
      <name>SocketDNS_getresult</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>af116c65d3617976fd55b1e3cf68d01ff</anchor>
      <arglist>(SocketDNS_T dns, SocketDNS_Request_T req)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDNS_geterror</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>a69d8d4c9f020bf781d541df7ecaf5acf</anchor>
      <arglist>(SocketDNS_T dns, const struct SocketDNS_Request_T *req)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDNS_request_settimeout</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>a009b2ac023375f1416344ab445d15667</anchor>
      <arglist>(SocketDNS_T dns, SocketDNS_Request_T req, int timeout_ms)</arglist>
    </member>
    <member kind="function">
      <type>SocketDNS_Request_T</type>
      <name>SocketDNS_create_completed_request</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>a1d42c9ab57cf57e394874bf801db4087</anchor>
      <arglist>(SocketDNS_T dns, struct addrinfo *result, int port)</arglist>
    </member>
    <member kind="function">
      <type>struct addrinfo *</type>
      <name>SocketDNS_resolve_sync</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>ab988727825887d34e87d144d30c30c2f</anchor>
      <arglist>(SocketDNS_T dns, const char *host, int port, const struct addrinfo *hints, int timeout_ms)</arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketDNS_Failed</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>a329324a0e4a1450a6b968b375bb9b333</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketHPACK.h</name>
    <path>include/http/</path>
    <filename>SocketHPACK_8h.html</filename>
    <includes id="Arena_8h" name="Arena.h" local="yes" import="no" module="no" objc="no">core/Arena.h</includes>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <class kind="struct">SocketHPACK_Header</class>
    <class kind="struct">SocketHPACK_EncoderConfig</class>
    <class kind="struct">SocketHPACK_DecoderConfig</class>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHPACK_DEFAULT_TABLE_SIZE</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>af6f02b4c16e51b058621e83fbfb1293a</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHPACK_MAX_TABLE_SIZE</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a0e75d44640cb3681b7fdbc8c49cb10b9</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHPACK_MAX_HEADER_SIZE</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a36d782a874a13b4da38f86fea6e40244</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHPACK_MAX_HEADER_LIST_SIZE</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>ab598ca8ec96369a45b756a956d248dd0</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHPACK_MAX_TABLE_UPDATES</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>ac25417892f0002db253f31bb5bab7be2</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHPACK_STATIC_TABLE_SIZE</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a09450c50e4284b2cdc1613f7f8062752</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHPACK_ENTRY_OVERHEAD</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a08c1b9076dbeb65dd345874ce9b51824</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketHPACK_Table *</type>
      <name>SocketHPACK_Table_T</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a689301e4de369172c0566705afe33156</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketHPACK_Result</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a623ed321b4ede47b3ac642a001c57ef4</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HPACK_OK</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a623ed321b4ede47b3ac642a001c57ef4a370961ee61b12c85a811642cc58d8d2a</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HPACK_INCOMPLETE</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a623ed321b4ede47b3ac642a001c57ef4a07efa48e67fe81302926870297c48d35</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HPACK_ERROR</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a623ed321b4ede47b3ac642a001c57ef4a47f5862e9cc9fae330636ff1edbf13ff</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HPACK_ERROR_INVALID_INDEX</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a623ed321b4ede47b3ac642a001c57ef4af02adcb51c871f252f716049d9d9704c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HPACK_ERROR_HUFFMAN</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a623ed321b4ede47b3ac642a001c57ef4af0bf15fa26ec1b20b193858a09e94ded</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HPACK_ERROR_INTEGER</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a623ed321b4ede47b3ac642a001c57ef4a1073a331e5d3dafeecfdec8cc315cc88</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HPACK_ERROR_TABLE_SIZE</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a623ed321b4ede47b3ac642a001c57ef4a7b1b9278ae10f718b6a364045254ef97</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HPACK_ERROR_HEADER_SIZE</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a623ed321b4ede47b3ac642a001c57ef4a023382e5da09bb3fcdb39a868b309080</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HPACK_ERROR_LIST_SIZE</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a623ed321b4ede47b3ac642a001c57ef4a75eafdd5ed49cc27a3d6f39fecc43532</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HPACK_ERROR_BOMB</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a623ed321b4ede47b3ac642a001c57ef4a83f74a40301b95d6d3b2626a0f6f32e6</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>SocketHPACK_Table_T</type>
      <name>SocketHPACK_Table_new</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>ad2e8414c30906d4f093a213b088edf03</anchor>
      <arglist>(size_t max_size, Arena_T arena)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHPACK_Table_free</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a821f51d4c73a41cfb01e75068c83e29e</anchor>
      <arglist>(SocketHPACK_Table_T *table)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHPACK_Table_set_max_size</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>aa6f9521e46c52adbe47ecb48c2abc307</anchor>
      <arglist>(SocketHPACK_Table_T table, size_t max_size)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketHPACK_Table_size</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a43f69e69234e33e6fba377e1eeb53d89</anchor>
      <arglist>(SocketHPACK_Table_T table)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketHPACK_Table_count</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>add54bf8828aec9d319682da54106537b</anchor>
      <arglist>(SocketHPACK_Table_T table)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketHPACK_Table_max_size</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>aa2e92ca751d06de523bc2667fd958010</anchor>
      <arglist>(SocketHPACK_Table_T table)</arglist>
    </member>
    <member kind="function">
      <type>SocketHPACK_Result</type>
      <name>SocketHPACK_Table_get</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>ac85e6b622a9cb7a19ce3bd0fdb2be551</anchor>
      <arglist>(SocketHPACK_Table_T table, size_t index, SocketHPACK_Header *header)</arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketHPACK_Error</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>aaf99a02bd5f3dd4baedcbde590cc5d09</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketHPACK_Encoder *</type>
      <name>SocketHPACK_Encoder_T</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>ab3d2fec45b36d20aff38b5b5f8ccc317</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketHPACK_Decoder *</type>
      <name>SocketHPACK_Decoder_T</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a47e194052251cf94ee0a17ab490ed56d</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>SocketHPACK_Result</type>
      <name>SocketHPACK_Table_add</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>ad46ef6fbf9994cc55c982d507ce473eb</anchor>
      <arglist>(SocketHPACK_Table_T table, const char *name, size_t name_len, const char *value, size_t value_len)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHPACK_encoder_config_defaults</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a2c85a114ea3e6b15fed7ca4714b6f367</anchor>
      <arglist>(SocketHPACK_EncoderConfig *config)</arglist>
    </member>
    <member kind="function">
      <type>SocketHPACK_Encoder_T</type>
      <name>SocketHPACK_Encoder_new</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a5f3f8543f2a9e0c48ca33d30019f8b87</anchor>
      <arglist>(const SocketHPACK_EncoderConfig *config, Arena_T arena)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHPACK_Encoder_free</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a944a4c3304e03e56cbf30ad689cc9074</anchor>
      <arglist>(SocketHPACK_Encoder_T *encoder)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketHPACK_Encoder_encode</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>aa40bb459b0df6cf69d3fd41c03deb872</anchor>
      <arglist>(SocketHPACK_Encoder_T encoder, const SocketHPACK_Header *headers, size_t count, unsigned char *output, size_t output_size)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHPACK_Encoder_set_table_size</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a702c12cdda50ff1c09ef2d2f086eda45</anchor>
      <arglist>(SocketHPACK_Encoder_T encoder, size_t max_size)</arglist>
    </member>
    <member kind="function">
      <type>SocketHPACK_Table_T</type>
      <name>SocketHPACK_Encoder_get_table</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>ab2be704f8ac8301d890421bbc2a8140c</anchor>
      <arglist>(SocketHPACK_Encoder_T encoder)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHPACK_decoder_config_defaults</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a945f44e73f0a313402745875d9102d1f</anchor>
      <arglist>(SocketHPACK_DecoderConfig *config)</arglist>
    </member>
    <member kind="function">
      <type>SocketHPACK_Decoder_T</type>
      <name>SocketHPACK_Decoder_new</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a4208e13edf5343f21c566a146ff8d5e0</anchor>
      <arglist>(const SocketHPACK_DecoderConfig *config, Arena_T arena)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHPACK_Decoder_free</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a780b420084cdeebd327cf2f2cdcdc94b</anchor>
      <arglist>(SocketHPACK_Decoder_T *decoder)</arglist>
    </member>
    <member kind="function">
      <type>SocketHPACK_Result</type>
      <name>SocketHPACK_Decoder_decode</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a80929db456c087b62dd8f59935bbd359</anchor>
      <arglist>(SocketHPACK_Decoder_T decoder, const unsigned char *input, size_t input_len, SocketHPACK_Header *headers, size_t max_headers, size_t *header_count, Arena_T arena)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHPACK_Decoder_set_table_size</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a71187fb60d8bbf1a6494b0b7f4566d4d</anchor>
      <arglist>(SocketHPACK_Decoder_T decoder, size_t max_size)</arglist>
    </member>
    <member kind="function">
      <type>SocketHPACK_Table_T</type>
      <name>SocketHPACK_Decoder_get_table</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a0afe40cbbca1731a702e44ec87052f6a</anchor>
      <arglist>(SocketHPACK_Decoder_T decoder)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketHPACK_huffman_encode</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a87187d3bcd990229f2366e09f4d0c0a0</anchor>
      <arglist>(const unsigned char *input, size_t input_len, unsigned char *output, size_t output_size)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketHPACK_huffman_decode</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>ad444bc6faa547e95f0b7ed31dc886e11</anchor>
      <arglist>(const unsigned char *input, size_t input_len, unsigned char *output, size_t output_size)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketHPACK_huffman_encoded_size</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>aa8e54f3347574c82323260b229279756</anchor>
      <arglist>(const unsigned char *input, size_t input_len)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketHPACK_int_encode</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a62d88dd2fa0079b167701d14a6e584db</anchor>
      <arglist>(uint64_t value, int prefix_bits, unsigned char *output, size_t output_size)</arglist>
    </member>
    <member kind="function">
      <type>SocketHPACK_Result</type>
      <name>SocketHPACK_int_decode</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>ad77418b9eae24b504a03e6d1021e46fe</anchor>
      <arglist>(const unsigned char *input, size_t input_len, int prefix_bits, uint64_t *value, size_t *consumed)</arglist>
    </member>
    <member kind="function">
      <type>SocketHPACK_Result</type>
      <name>SocketHPACK_static_get</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a2134dc86dd6393df244bfeeaf1ab5c69</anchor>
      <arglist>(size_t index, SocketHPACK_Header *header)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHPACK_static_find</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a201240b0d9259e2a9da91530a86d8ed1</anchor>
      <arglist>(const char *name, size_t name_len, const char *value, size_t value_len)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketHPACK_result_string</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a09650dc7a68806989192e4cd31b4393b</anchor>
      <arglist>(SocketHPACK_Result result)</arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketHTTP.h</name>
    <path>include/http/</path>
    <filename>SocketHTTP_8h.html</filename>
    <includes id="Arena_8h" name="Arena.h" local="yes" import="no" module="no" objc="no">core/Arena.h</includes>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <class kind="struct">SocketHTTP_MethodProperties</class>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP_MAX_HEADER_NAME</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>a67cb8ab40e2085b3682e91a79aea2553</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP_MAX_HEADER_VALUE</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>a711feea372680c3db3f52cb12954e8d8</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP_MAX_HEADER_SIZE</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>a7bb4c78960a2783f19b993f193932727</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP_MAX_HEADERS</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>a2f5713c3b88ddc329d0119a789847ba6</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP_MAX_URI_LEN</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>a13dfbee4ad8c1b29949c1fd0cc360f45</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP_DATE_BUFSIZE</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>a613a2fead5a6288d5d4e794ba95adeee</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP_STATUS_CODE_MIN</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>a7182eca7a6bd99ccbf0cb12b275adf9d</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP_STATUS_CODE_MAX</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>ab6a83b3daff3f633c8deda4408cea03c</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP_STATUS_1XX_MIN</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aee82a204474700c91dad9a806e48f64f</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP_STATUS_1XX_MAX</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>a261a87375b42933ff21a2b0fc7fdc8c3</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP_STATUS_2XX_MIN</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>a803cba6422aa720d629c3a9bd660cb4c</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP_STATUS_2XX_MAX</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aa802911b92b079f19b3e1f4049cc36d7</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP_STATUS_3XX_MIN</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>a3991461d2ca50eeab1c693aaf37717a8</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP_STATUS_3XX_MAX</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>a1f0660454bb40ecd77d30150ec42e198</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP_STATUS_4XX_MIN</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>a530d36f357344463eb4b5ca8a46157b6</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP_STATUS_4XX_MAX</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>af38c37f224e9e3cf82aeec28f1da00b5</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP_STATUS_5XX_MIN</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>abe599c847c5cf301bd5d9f151bba17d7</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP_STATUS_5XX_MAX</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>a18bd3c97e4435317e073b63c13ca6aa1</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketHTTP_Version</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>ac46610efb2f138f9f5c58f9134f11a78</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_VERSION_0_9</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>ac46610efb2f138f9f5c58f9134f11a78abca6852c70f3b9617834ca911ee9e737</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_VERSION_1_0</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>ac46610efb2f138f9f5c58f9134f11a78a3932308db22120ce049dd60f3430b814</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_VERSION_1_1</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>ac46610efb2f138f9f5c58f9134f11a78af1a34119b438038bc609a273f9bc08c6</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_VERSION_2</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>ac46610efb2f138f9f5c58f9134f11a78a2240d6f65d5af421be670655fed8b202</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_VERSION_3</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>ac46610efb2f138f9f5c58f9134f11a78a907296c738aa0848b48cc07b0b776751</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketHTTP_Method</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>af6f90bb536a5cd085f4327bda4d3ee8f</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_METHOD_GET</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>af6f90bb536a5cd085f4327bda4d3ee8fa90754abc55dbb76862fa50abee5af659</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_METHOD_HEAD</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>af6f90bb536a5cd085f4327bda4d3ee8fa27e993d38ff6b43284014a10798b6223</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_METHOD_POST</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>af6f90bb536a5cd085f4327bda4d3ee8fa1944682922ac79b2e682312d8f3f71e2</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_METHOD_PUT</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>af6f90bb536a5cd085f4327bda4d3ee8faf7557927b605c64f35f629b43823b1c9</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_METHOD_DELETE</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>af6f90bb536a5cd085f4327bda4d3ee8fa761371f7807255b7912afbac2f665ffe</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_METHOD_CONNECT</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>af6f90bb536a5cd085f4327bda4d3ee8fa3755246bea87120e8311dc914d573fbf</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_METHOD_OPTIONS</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>af6f90bb536a5cd085f4327bda4d3ee8faf6b02f8ff0467dbdaebb24f0a996cdd4</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_METHOD_TRACE</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>af6f90bb536a5cd085f4327bda4d3ee8fa95b5b19305a14de1400aedfdec1c1eed</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_METHOD_PATCH</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>af6f90bb536a5cd085f4327bda4d3ee8fac1adf0f44043552b637a6235ae3ff283</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_METHOD_UNKNOWN</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>af6f90bb536a5cd085f4327bda4d3ee8fafaba39836e3963977f2d329394f8df31</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketHTTP_StatusCode</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_CONTINUE</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75cad397c30fb0f937e965c1f23e19763a5c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_SWITCHING_PROTOCOLS</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75cabdff771301c12ef6b9ae9b7b5b87c30d</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_PROCESSING</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca4edd1153b1090c6b04f41a9728184c69</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_EARLY_HINTS</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75caff74945405d29d86c567878f1514dcb6</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_OK</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75cad34cd21de350cd4fa83b8099e3993b91</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_CREATED</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75caa9a59ef7151e4a9944519c2a7b5a4193</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_ACCEPTED</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca95022d17916c4aa66324379ecdd53247</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_NON_AUTHORITATIVE</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca690301c36a7a04247e4828a3361fcb0f</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_NO_CONTENT</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75cad000a2e30c534c201201dd74fac8d2f9</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_RESET_CONTENT</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca72431bee6eae3e12040af717a0af2df1</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_PARTIAL_CONTENT</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75caa55ceddb5bb2104bfcfefb16995192a4</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_MULTI_STATUS</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca5b5f6b48a150926864f66aa8882708df</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_ALREADY_REPORTED</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75caf60c8de8de4eb8fe02562aff8ee96f1f</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_IM_USED</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75caadd5b6f83dd05c6de2ef12de1dd006cd</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_MULTIPLE_CHOICES</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75cace45e0a70d239d5883e023655d9c381c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_MOVED_PERMANENTLY</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca9632802fcd318d1676be7589e6004e96</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_FOUND</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca53df069872b37830e4296f32e7ec20d8</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_SEE_OTHER</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75cae301c12d0cf56920659cb7b947a95267</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_NOT_MODIFIED</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca67de2c448cc952048485e4261a5dab19</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_USE_PROXY</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75cab13f90697368bfecc05dc5a8b18fc87c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_TEMPORARY_REDIRECT</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca70de6a18224da6df336ce0c4be7d52e7</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_PERMANENT_REDIRECT</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75cac0f841f58eb31779ca76bb3cfb600267</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_BAD_REQUEST</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca49cf9c4c184f9e4d265ceae249e92477</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_UNAUTHORIZED</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75cad771b2a0ab88db11b2719c8e5086fb48</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_PAYMENT_REQUIRED</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75cafac24097912a70f224166528ce44b83b</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_FORBIDDEN</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca419c919f74b88d18803358141ab9471c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_NOT_FOUND</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75caf06c31278cb67d7eec4b2b8157b9ad25</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_METHOD_NOT_ALLOWED</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca63eb71a406e943d4634c357d60dd96df</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_NOT_ACCEPTABLE</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca1558c42d80f54def5f3277dc879d2844</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_PROXY_AUTH_REQUIRED</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca40246e02220192ce8d7f86591ca1cfe4</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_REQUEST_TIMEOUT</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca36b5bcf2059ae3c84a47e080822239c7</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_CONFLICT</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca6964f9591ba7284dc4bd388d40c106a9</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_GONE</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca67278d96cfa0eb507535b94338810d65</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_LENGTH_REQUIRED</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75cab42dfcbd67b4e66096e3a8e924b6d6c9</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_PRECONDITION_FAILED</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75cac3d4da4de851d5c8f95748145b59716a</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_CONTENT_TOO_LARGE</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca43bd00c293731a84ef3f2ae1b4cb725d</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_URI_TOO_LONG</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca033ec26aabe2b7ece963fd3e43d0d064</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca145570ed1178d3d90ad9b7652fea83cf</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_RANGE_NOT_SATISFIABLE</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca5398c5b8f1a8d3b7656994638dba2ad5</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_EXPECTATION_FAILED</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca08107f6b0e1d7c9e2ca100700cc7200f</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_IM_A_TEAPOT</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca034d9620babe01011810fe384375a92b</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_MISDIRECTED_REQUEST</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca3e8907f1d75b7b2f41a1e3015a212d2e</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_UNPROCESSABLE_CONTENT</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca837ed1203940888cbc53bdc8e1e743cb</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_LOCKED</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75caa6e28f289443c753660cddc9b4ce28a1</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_FAILED_DEPENDENCY</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75cac268c2f9a1c531f403403a99da6a80cd</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_TOO_EARLY</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca92e9f9944fc5c40bd23de3ab5a7c9bfa</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_UPGRADE_REQUIRED</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca5ce4ed593a2ebd6f7fb3cd86c8ab5fb8</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_PRECONDITION_REQUIRED</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca9ddf391ade5190c8d685d998ef35e604</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_TOO_MANY_REQUESTS</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca892176fbdf3f79e2c888f677ea34d451</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_HEADER_TOO_LARGE</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca136b0743cb135e8a710fda41f129dd09</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_UNAVAILABLE_LEGAL</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca8a21f739779622311f20253467449575</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_INTERNAL_ERROR</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca998e34987c3c8322f4cfb89d5c0724f9</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_NOT_IMPLEMENTED</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75cac9c5b4e80aa858cfe2763656db1f16e3</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_BAD_GATEWAY</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75cac96829d2c2cb76feb1549f0fac72c69e</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_SERVICE_UNAVAILABLE</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75cab355dd546e62b1478fe3ef94b554f75c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_GATEWAY_TIMEOUT</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75caefdfc7b525c87b911d6e92a30e36cfec</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_VERSION_NOT_SUPPORTED</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca59783212e968b200a33ff495fd4eec7b</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_VARIANT_ALSO_NEGOTIATES</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75cac5f77dc9692876a7f19cabdc12d42c5d</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_INSUFFICIENT_STORAGE</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca2876de0bf7f4302883626399b868b49b</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_LOOP_DETECTED</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca5db103eeafcd3c0b245f42065a8a096f</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_NOT_EXTENDED</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75ca9f989de7a400bb10b4a75613504bd889</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_NETWORK_AUTH_REQUIRED</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aceb714c26b828fe187a7fa72749ee75cae60954618af03c3b7f9a24f6e57974c7</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketHTTP_StatusCategory</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>a905b7faf61f39aaa3cfcfed80d1675d5</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_INFORMATIONAL</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>a905b7faf61f39aaa3cfcfed80d1675d5a45a7cf54667d5b2df0ec0a24fdab8249</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_SUCCESSFUL</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>a905b7faf61f39aaa3cfcfed80d1675d5a37bc28ad2189c682b316e17c9357e8d0</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_REDIRECTION</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>a905b7faf61f39aaa3cfcfed80d1675d5a3298165f45b28384f35c073b19e1f80b</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_CLIENT_ERROR</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>a905b7faf61f39aaa3cfcfed80d1675d5ad0050914cb5041feedb0d11d04e7151b</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_STATUS_SERVER_ERROR</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>a905b7faf61f39aaa3cfcfed80d1675d5a271ea994d1cabf358e86b2f9c7e327ad</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketHTTP_version_string</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>afd6a702248ad5bce0c0d6f1825795f1e</anchor>
      <arglist>(SocketHTTP_Version version)</arglist>
    </member>
    <member kind="function">
      <type>SocketHTTP_Version</type>
      <name>SocketHTTP_version_parse</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>a2c1cc8d1f48f39b8a3cabe4a47aaa295</anchor>
      <arglist>(const char *str, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketHTTP_method_name</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>aeebb1299d256377b2abc6756c77827ef</anchor>
      <arglist>(SocketHTTP_Method method)</arglist>
    </member>
    <member kind="function">
      <type>SocketHTTP_Method</type>
      <name>SocketHTTP_method_parse</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>a98ea0fbffa4e6f97e009b3772c251007</anchor>
      <arglist>(const char *str, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>SocketHTTP_MethodProperties</type>
      <name>SocketHTTP_method_properties</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>a80b627d3253567e6c73b94ddd6fe1bb5</anchor>
      <arglist>(SocketHTTP_Method method)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTP_method_valid</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>ac30c95d487cc694a02c2b46796c27d07</anchor>
      <arglist>(const char *str, size_t len)</arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketHTTP_Failed</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>a4f683bdd1ab1acf36a383a7be5f5b6d2</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketHTTP1.h</name>
    <path>include/http/</path>
    <filename>SocketHTTP1_8h.html</filename>
    <includes id="Arena_8h" name="Arena.h" local="yes" import="no" module="no" objc="no">core/Arena.h</includes>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="SocketHTTP_8h" name="SocketHTTP.h" local="yes" import="no" module="no" objc="no">http/SocketHTTP.h</includes>
    <class kind="struct">SocketHTTP1_Config</class>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP1_MAX_REQUEST_LINE</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a31c24401916c5664adb6ea3616681b46</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP1_MAX_METHOD_LEN</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>ac4b9886203defffcd90cddff2540b6e6</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP1_MAX_URI_LEN</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>aad40b2eeddd7e9517f82d47349f9d271</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP1_MAX_HEADER_NAME</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a5f5ecb6e846886cb5a2adf261a197f77</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP1_MAX_HEADER_VALUE</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a02fdc5c8df1cd6d293ce80c4647e8278</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP1_MAX_HEADERS</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>aa3441412b165e62bb60e49f703acd245</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP1_MAX_HEADER_SIZE</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a11553aa6152c3065fee134ea4924cc26</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP1_MAX_CHUNK_SIZE</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a6a2a172023b9fc8609f638e37fc28781</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP1_MAX_CHUNK_EXT</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a2b4e16b62a1a792c810cb1fc94519c85</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP1_MAX_TRAILER_SIZE</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a207d48fb770893866f7a01d4ec09390d</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP1_MAX_HEADER_LINE</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>afac78449ad6cedf3dc9f703d5bd338b1</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP1_INT_STRING_BUFSIZE</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a17c37ff959acffa4e20330b701877924</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP1_CONTENT_LENGTH_BUFSIZE</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a1ee215b68e39922641052018f578a002</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketHTTP1_Parser *</type>
      <name>SocketHTTP1_Parser_T</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a06fc705e348330ddf1d6644fc80c3b59</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketHTTP1_ParseMode</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>ae0c5248b52a9b32c1def93401bbabe96</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_PARSE_REQUEST</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>ae0c5248b52a9b32c1def93401bbabe96a1f628e563408ccbc0f6f93973845e0f1</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_PARSE_RESPONSE</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>ae0c5248b52a9b32c1def93401bbabe96aab0293475cda774be4e2e2fd417eef87</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketHTTP1_State</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>ad8ddb65bb2ebb0dfb013c19bceb3074e</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_STATE_START</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>ad8ddb65bb2ebb0dfb013c19bceb3074ea9ef28d3428d6bf4269b6188ccce295e1</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_STATE_HEADERS</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>ad8ddb65bb2ebb0dfb013c19bceb3074eade98f14dc018677523eb4dd5eade8892</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_STATE_BODY</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>ad8ddb65bb2ebb0dfb013c19bceb3074eaed34954e4bc5ada417b736ea8762a381</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_STATE_CHUNK_SIZE</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>ad8ddb65bb2ebb0dfb013c19bceb3074ea03634fa688c3a4b61d2e33770d10aae5</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_STATE_CHUNK_DATA</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>ad8ddb65bb2ebb0dfb013c19bceb3074ea0d1c2b238a0bafb0d8863b1cfab9d5d8</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_STATE_CHUNK_END</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>ad8ddb65bb2ebb0dfb013c19bceb3074ea1bc28b2d1b80f9aa51e112e6bffff72e</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_STATE_TRAILERS</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>ad8ddb65bb2ebb0dfb013c19bceb3074ea270022e51ea38ce543b1648c327da9d4</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_STATE_COMPLETE</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>ad8ddb65bb2ebb0dfb013c19bceb3074ea1a17feeec742feb1412f1ac3185a830e</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_STATE_ERROR</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>ad8ddb65bb2ebb0dfb013c19bceb3074eaf90803082504ceffc09b45ea78b0cee9</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketHTTP1_Result</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a2ece68fcfe3c3e99a855f93f6a46f78e</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_OK</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a2ece68fcfe3c3e99a855f93f6a46f78eac4f4eafbbea56118c44708aa5591107d</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_INCOMPLETE</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a2ece68fcfe3c3e99a855f93f6a46f78ea8f11d915cd16f4b89b5b3d97059ed82f</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_ERROR</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a2ece68fcfe3c3e99a855f93f6a46f78ea690680a1e66e6b072695744e820e55e0</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_ERROR_LINE_TOO_LONG</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a2ece68fcfe3c3e99a855f93f6a46f78eaaedfedfb6f588d75b33f47171d146383</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_ERROR_INVALID_METHOD</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a2ece68fcfe3c3e99a855f93f6a46f78eaa2f28b43265eadae410ef7deb12e9d76</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_ERROR_INVALID_URI</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a2ece68fcfe3c3e99a855f93f6a46f78ea823f1cfa7c3e988629f8250fa4fdd1f0</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_ERROR_INVALID_VERSION</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a2ece68fcfe3c3e99a855f93f6a46f78ead0504ca0c546e70ca2528cb9d3c03bb3</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_ERROR_INVALID_STATUS</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a2ece68fcfe3c3e99a855f93f6a46f78ea6b7979cd9589a5f851983e2b6a0db535</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_ERROR_INVALID_HEADER_NAME</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a2ece68fcfe3c3e99a855f93f6a46f78eab9780e3960f83e96ecc306dc21ba606d</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_ERROR_INVALID_HEADER_VALUE</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a2ece68fcfe3c3e99a855f93f6a46f78eae374130e7a16313a55c7346c835f6f2a</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_ERROR_HEADER_TOO_LARGE</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a2ece68fcfe3c3e99a855f93f6a46f78ea02f5ea09ed263639285edf4457542441</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_ERROR_TOO_MANY_HEADERS</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a2ece68fcfe3c3e99a855f93f6a46f78eac7d0ef00c011c53c0481d49d054c14dc</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_ERROR_INVALID_CONTENT_LENGTH</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a2ece68fcfe3c3e99a855f93f6a46f78ead50a7e38db6d2197a2e3b740f7b8bd2a</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_ERROR_INVALID_CHUNK_SIZE</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a2ece68fcfe3c3e99a855f93f6a46f78eadecd89036519fac2069f6261967ad9a4</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_ERROR_CHUNK_TOO_LARGE</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a2ece68fcfe3c3e99a855f93f6a46f78ea6b628f58fac38dbc2fb615ae075f053d</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_ERROR_BODY_TOO_LARGE</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a2ece68fcfe3c3e99a855f93f6a46f78eaeb698ed6d2d4a79eb41d9b69346e6743</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_ERROR_INVALID_TRAILER</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a2ece68fcfe3c3e99a855f93f6a46f78ea9ad0d4f3b9cb3164139491d0f22f296c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_ERROR_UNEXPECTED_EOF</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a2ece68fcfe3c3e99a855f93f6a46f78ea45da2dd8b558188c3c25ec3ca678187f</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_ERROR_SMUGGLING_DETECTED</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a2ece68fcfe3c3e99a855f93f6a46f78ea459fb16283ed5b28f9cb7b1dd988e229</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketHTTP1_BodyMode</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a5b086c700986994685f83dd033821f0e</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_BODY_NONE</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a5b086c700986994685f83dd033821f0ead046cbedac23049ecf363b915c3d103a</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_BODY_CONTENT_LENGTH</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a5b086c700986994685f83dd033821f0eaf53be77b9110eb429f3f76f152a918e8</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_BODY_CHUNKED</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a5b086c700986994685f83dd033821f0ea8fc42a2eca05bc22c21e39819cf2ce68</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP1_BODY_UNTIL_CLOSE</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a5b086c700986994685f83dd033821f0eae35df2245221a5bebe7ba5bfc6c51e86</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTP1_config_defaults</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>aed53869d1481794448fd6e3d9d6d5e84</anchor>
      <arglist>(SocketHTTP1_Config *config)</arglist>
    </member>
    <member kind="function">
      <type>SocketHTTP1_Parser_T</type>
      <name>SocketHTTP1_Parser_new</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a7fb2e95c0a39df0a5c075faa55d6a6f3</anchor>
      <arglist>(SocketHTTP1_ParseMode mode, const SocketHTTP1_Config *config, Arena_T arena)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTP1_Parser_free</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>af0a2a42b97cd8ab5340958a4aa30124f</anchor>
      <arglist>(SocketHTTP1_Parser_T *parser)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTP1_Parser_reset</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a49a9ded0a495db9d15e7b6ec5abce5cb</anchor>
      <arglist>(SocketHTTP1_Parser_T parser)</arglist>
    </member>
    <member kind="function">
      <type>SocketHTTP1_Result</type>
      <name>SocketHTTP1_Parser_execute</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a83fa0ae51796710bc10e16154b448a3f</anchor>
      <arglist>(SocketHTTP1_Parser_T parser, const char *data, size_t len, size_t *consumed)</arglist>
    </member>
    <member kind="function">
      <type>SocketHTTP1_State</type>
      <name>SocketHTTP1_Parser_state</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>ae628eea962092f79332744f005bfe81f</anchor>
      <arglist>(SocketHTTP1_Parser_T parser)</arglist>
    </member>
    <member kind="function">
      <type>const SocketHTTP_Request *</type>
      <name>SocketHTTP1_Parser_get_request</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a2ea1bef9e80e9ed39b960bc375c7d83b</anchor>
      <arglist>(SocketHTTP1_Parser_T parser)</arglist>
    </member>
    <member kind="function">
      <type>const SocketHTTP_Response *</type>
      <name>SocketHTTP1_Parser_get_response</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>ace300f1b370727b195654a02e3fd7ec0</anchor>
      <arglist>(SocketHTTP1_Parser_T parser)</arglist>
    </member>
    <member kind="function">
      <type>SocketHTTP1_BodyMode</type>
      <name>SocketHTTP1_Parser_body_mode</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>ac425dba4f2dfcd61c19cd8933482db99</anchor>
      <arglist>(SocketHTTP1_Parser_T parser)</arglist>
    </member>
    <member kind="function">
      <type>int64_t</type>
      <name>SocketHTTP1_Parser_content_length</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a7f8d17864cc2a6d6a00055b8b6a8152d</anchor>
      <arglist>(SocketHTTP1_Parser_T parser)</arglist>
    </member>
    <member kind="function">
      <type>int64_t</type>
      <name>SocketHTTP1_Parser_body_remaining</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a66d78b9f96cb10365f7aa7c0fb142f3f</anchor>
      <arglist>(SocketHTTP1_Parser_T parser)</arglist>
    </member>
    <member kind="function">
      <type>SocketHTTP1_Result</type>
      <name>SocketHTTP1_Parser_read_body</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a4d5411b548fb2d9139c5a98c96888c10</anchor>
      <arglist>(SocketHTTP1_Parser_T parser, const char *input, size_t input_len, size_t *consumed, char *output, size_t output_len, size_t *written)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTP1_Parser_body_complete</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a43509d51fdb403d3e0917d0edace81dc</anchor>
      <arglist>(SocketHTTP1_Parser_T parser)</arglist>
    </member>
    <member kind="function">
      <type>SocketHTTP_Headers_T</type>
      <name>SocketHTTP1_Parser_get_trailers</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>aaaab6bad3178f0109b69f5f0c83e6805</anchor>
      <arglist>(SocketHTTP1_Parser_T parser)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTP1_Parser_should_keepalive</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a6207068650f6737b8f98ed419e51d56c</anchor>
      <arglist>(SocketHTTP1_Parser_T parser)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTP1_Parser_is_upgrade</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a92d722afa530f7e28512dae210a5be17</anchor>
      <arglist>(SocketHTTP1_Parser_T parser)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketHTTP1_Parser_upgrade_protocol</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a5cfd27ea3f2fd476c4f3e45aa88968d6</anchor>
      <arglist>(SocketHTTP1_Parser_T parser)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTP1_Parser_expects_continue</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>ae0a96206e67a279005be9686d159faf3</anchor>
      <arglist>(SocketHTTP1_Parser_T parser)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketHTTP1_serialize_request</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a66bdb40cb195c23e4e02dfa41ad1e4b7</anchor>
      <arglist>(const SocketHTTP_Request *request, char *output, size_t output_size)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketHTTP1_serialize_response</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>ab8921dc474a57cdb9e68ac329f70a100</anchor>
      <arglist>(const SocketHTTP_Response *response, char *output, size_t output_size)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketHTTP1_serialize_headers</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>af49c3054b9785e30c0377c57b4df4bf4</anchor>
      <arglist>(SocketHTTP_Headers_T headers, char *output, size_t output_size)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketHTTP1_chunk_encode</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a1ee4d308dc266c293146b181d75c0fd9</anchor>
      <arglist>(const void *data, size_t len, char *output, size_t output_size)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketHTTP1_chunk_final</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a6c018b4a237cb0c87a529e1332ddad5c</anchor>
      <arglist>(char *output, size_t output_size, SocketHTTP_Headers_T trailers)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketHTTP1_chunk_encode_size</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>ad77e06b6dd656dede4191a51d1c27661</anchor>
      <arglist>(size_t data_len)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketHTTP1_result_string</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a2978becba9896924c0543135477ec4ff</anchor>
      <arglist>(SocketHTTP1_Result result)</arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketHTTP1_ParseError</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>ab0e624687447c4ade518d16bf70ac8a4</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketHTTP1_SerializeError</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a7fe3d14ed6f02dfecfc98f4872d95372</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketHTTP2.h</name>
    <path>include/http/</path>
    <filename>SocketHTTP2_8h.html</filename>
    <includes id="Arena_8h" name="Arena.h" local="yes" import="no" module="no" objc="no">core/Arena.h</includes>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="SocketHPACK_8h" name="SocketHPACK.h" local="yes" import="no" module="no" objc="no">http/SocketHPACK.h</includes>
    <includes id="SocketHTTP_8h" name="SocketHTTP.h" local="yes" import="no" module="no" objc="no">http/SocketHTTP.h</includes>
    <includes id="Socket_8h" name="Socket.h" local="yes" import="no" module="no" objc="no">socket/Socket.h</includes>
    <class kind="struct">SocketHTTP2_FrameHeader</class>
    <class kind="struct">SocketHTTP2_Config</class>
    <class kind="struct">SocketHTTP2_Setting</class>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP2_DEFAULT_HEADER_TABLE_SIZE</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>ad309986a2472f83336a6c729ad0d156d</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP2_DEFAULT_ENABLE_PUSH</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a8b4e24b22d60c9645398e5f1fc3ccc53</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP2_DEFAULT_MAX_CONCURRENT_STREAMS</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a7f27dd764ccecc089bbb7ce2577662e8</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP2_DEFAULT_INITIAL_WINDOW_SIZE</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a008ef8cd5efb615ef740375625831c13</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP2_DEFAULT_MAX_FRAME_SIZE</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>ac73b5673480ac469a0d351ab5ff00b04</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP2_MAX_MAX_FRAME_SIZE</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>ac0f80f8048c437b3bd97740c70981ba2</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP2_DEFAULT_MAX_HEADER_LIST_SIZE</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>aab92659a1ac39f911a7031a8fa57532b</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP2_DEFAULT_STREAM_RECV_BUF_SIZE</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a9ce8bfc64e6a1da3f3c8c0058845733f</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP2_DEFAULT_INITIAL_HEADER_BLOCK_SIZE</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a58ac0ff2518d8345a13646c636bfd2e8</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP2_MAX_DECODED_HEADERS</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>af6d5bb6cb0869bc0426836bf076c9c34</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP2_MAX_CONTINUATION_FRAMES</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a1c458f4c39b9d980a6adbc022fa49abf</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP2_REQUEST_PSEUDO_HEADER_COUNT</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>abca4f7f273c332090bc14e9f950519ea</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP2_MAX_STREAMS</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>aaaacd21ea311866f022dc2819cdf3970</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP2_CONNECTION_WINDOW_SIZE</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a8f09ebf529638d4a69b1c52465d50985</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP2_RST_RATE_LIMIT</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>aa20a27a38e12d263a948524dd53c6fa6</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP2_RST_RATE_WINDOW_MS</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a9887f36b7f564f07f4aaf2edbbb380c0</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP2_PING_RATE_LIMIT</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a348b0240c0ad1819de8e1c5aac87788b</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP2_PING_RATE_WINDOW_MS</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a31f0fa5dd50b7518853bc761bab152a9</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP2_SETTINGS_RATE_LIMIT</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a0e84d0a8fa6b2fb3c9cd937eae11cf09</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP2_SETTINGS_RATE_WINDOW_MS</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>aa1404eba0c1374b3ef16a9ce84964773</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP2_DEFAULT_SETTINGS_TIMEOUT_MS</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a771d4aff12b7d59ed835526388a9da1f</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP2_DEFAULT_PING_TIMEOUT_MS</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a765dac93880ebf4f64f313d3fad02c1d</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP2_MAX_WINDOW_SIZE</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a4c45c0b678bddd3940ec141601a23f50</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETHTTP2_IO_BUFFER_SIZE</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>ab0f69e66f311f76212458acd539d5eb9</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP2_FRAME_HEADER_SIZE</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>ac20a5b006752190a32f4a20df79ced4f</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP2_WINDOW_UPDATE_PAYLOAD_SIZE</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a3cc871112302c2c15fdde2c478a74329</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP2_PUSH_PROMISE_ID_SIZE</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>afc6d5cdfcb6fb6ff19beedc1987c2473</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP2_PRIORITY_PAYLOAD_SIZE</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a64ae18bf7e0c54612b4009eccb94baa2</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP2_PREFACE_SIZE</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a668002a6051465af0c29b9910c88b266</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP2_STREAM_HASH_SIZE</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>ae35b9df3c241695e01ac2e16d7418952</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP2_FLAG_END_STREAM</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>af96bfb997270d8a4519b9d534be37293</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP2_FLAG_END_HEADERS</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a5bc7ebf29a16604e5a17c681c759640a</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP2_FLAG_PADDED</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a652f2f3f3d9d6209ac279f6329d02060</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP2_FLAG_PRIORITY</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a55ea092a93d72104d9056d382a6828f6</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP2_FLAG_ACK</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a35a939fb6876e1fb431d74e8170d827a</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP2_SETTINGS_COUNT</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a5520a61b7f70500149663a3114dff963</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP2_EVENT_STREAM_START</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a2c94bfd0344f644c485a5b20ac0f9227</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP2_EVENT_HEADERS_RECEIVED</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a07966f54d5b07cfc49a3a24d71985a92</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP2_EVENT_DATA_RECEIVED</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a744693010981e58b5bcd1686b9822a47</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP2_EVENT_TRAILERS_RECEIVED</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>adb428bd7088428a517f9c903f368f593</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP2_EVENT_STREAM_END</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a3fd002f643fcca1c9c7331b8da34142b</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP2_EVENT_STREAM_RESET</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>ac3a13560e46c50bc9835071c46ebed80</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP2_EVENT_PUSH_PROMISE</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>ac1c9a596fbb0c330bf23b8753721b369</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP2_EVENT_WINDOW_UPDATE</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>afc0f6fd18c23c0960c6d24ca70b9cfc1</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP2_EVENT_SETTINGS_ACK</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a611109bc229fe25b4bcf6b577a8d6421</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP2_EVENT_PING_ACK</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a9a3b7c165b9a0c3bcbd00157c4e2442b</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP2_EVENT_GOAWAY_RECEIVED</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a313617c033a22263d35fb9ae735177f3</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTP2_EVENT_CONNECTION_ERROR</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a9bd25930b28f582a346fd5c0e83861ce</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketHTTP2_Conn *</type>
      <name>SocketHTTP2_Conn_T</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a71710b60048bb252c74115f947f14e6a</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketHTTP2_Stream *</type>
      <name>SocketHTTP2_Stream_T</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>aae451408b4b91d69d78281b872773000</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>void(*</type>
      <name>SocketHTTP2_StreamCallback</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a990cec8dae4a5eb79e28e30039038a98</anchor>
      <arglist>)(SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream, int event, void *userdata)</arglist>
    </member>
    <member kind="typedef">
      <type>void(*</type>
      <name>SocketHTTP2_ConnCallback</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a82daab7aba48e58f206a541e11b63bb2</anchor>
      <arglist>)(SocketHTTP2_Conn_T conn, int event, void *userdata)</arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketHTTP2_FrameType</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>aeb74330a70e149eb7b10547a6b83fa0a</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_FRAME_DATA</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>aeb74330a70e149eb7b10547a6b83fa0aa04554819e8fccfd4a5e3af472d297c05</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_FRAME_HEADERS</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>aeb74330a70e149eb7b10547a6b83fa0aacfab4408ab345f3e125932618bc2a797</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_FRAME_PRIORITY</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>aeb74330a70e149eb7b10547a6b83fa0aaeb5e132de27090a912bdf4608770dad2</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_FRAME_RST_STREAM</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>aeb74330a70e149eb7b10547a6b83fa0aa01cb150f545986ecf7b644d1c0d55a9b</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_FRAME_SETTINGS</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>aeb74330a70e149eb7b10547a6b83fa0aa958eea494ddddc4a9dae9bb92b306158</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_FRAME_PUSH_PROMISE</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>aeb74330a70e149eb7b10547a6b83fa0aa0a45b8840463a20beff3ceb88c6c928b</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_FRAME_PING</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>aeb74330a70e149eb7b10547a6b83fa0aa39d39c46b34c78d84ea93738f6878612</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_FRAME_GOAWAY</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>aeb74330a70e149eb7b10547a6b83fa0aa373e3880213bbd8865b1e180ce84a492</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_FRAME_WINDOW_UPDATE</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>aeb74330a70e149eb7b10547a6b83fa0aacb8ce16978aa358ee7d98cbb41338396</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_FRAME_CONTINUATION</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>aeb74330a70e149eb7b10547a6b83fa0aac5d7b06ae7255f7fd60724a8a74a0b67</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketHTTP2_ErrorCode</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a0dae3fde0d9081ed887d2476442f6ee9</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_NO_ERROR</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a0dae3fde0d9081ed887d2476442f6ee9ac23405996c11dae9e88239ce88a16ea8</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_PROTOCOL_ERROR</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a0dae3fde0d9081ed887d2476442f6ee9a1bb78671b75564a3eb2ff5aceccd90dc</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_INTERNAL_ERROR</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a0dae3fde0d9081ed887d2476442f6ee9a81f3b3d6f4c3bd15763d0141fb64a167</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_FLOW_CONTROL_ERROR</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a0dae3fde0d9081ed887d2476442f6ee9a6d14aa74e9963c9a6353bc78b2d1f692</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_SETTINGS_TIMEOUT</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a0dae3fde0d9081ed887d2476442f6ee9af0559ab4d1a0307b036aba800c58b5be</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_STREAM_CLOSED</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a0dae3fde0d9081ed887d2476442f6ee9a320592477b4417654e4b9f0930f5b7a8</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_FRAME_SIZE_ERROR</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a0dae3fde0d9081ed887d2476442f6ee9a84f82454caaecec6ef5b59e65e91b174</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_REFUSED_STREAM</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a0dae3fde0d9081ed887d2476442f6ee9ad3fa8cc0ff8952f30ddd054844d230b6</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_CANCEL</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a0dae3fde0d9081ed887d2476442f6ee9aede75f5387b7175bb15ee13f9385044a</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_COMPRESSION_ERROR</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a0dae3fde0d9081ed887d2476442f6ee9a18aad6cf9299f0c586e34470f91ad54b</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_CONNECT_ERROR</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a0dae3fde0d9081ed887d2476442f6ee9aa1e6461cadd786960db3c57644d6bfe8</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_ENHANCE_YOUR_CALM</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a0dae3fde0d9081ed887d2476442f6ee9ad241898d450e04e101a411e8bfdb6c95</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_INADEQUATE_SECURITY</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a0dae3fde0d9081ed887d2476442f6ee9a775b0e49c491ebe333f7e9a3a8d764ef</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_HTTP_1_1_REQUIRED</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a0dae3fde0d9081ed887d2476442f6ee9aa0e39cae17fa95dbdaa49000f021ad13</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketHTTP2_SettingsId</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a4040b0e6d05a8901e50c497254a8176d</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_SETTINGS_HEADER_TABLE_SIZE</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a4040b0e6d05a8901e50c497254a8176da0dcdd60d4c429d558c4cebc9c1527e06</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_SETTINGS_ENABLE_PUSH</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a4040b0e6d05a8901e50c497254a8176dad1c9118f459a93bce47b0ad1546b50b4</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a4040b0e6d05a8901e50c497254a8176da844c0af59b8b254301d47b0888886304</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_SETTINGS_INITIAL_WINDOW_SIZE</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a4040b0e6d05a8901e50c497254a8176da1152ff63cb965c24f05419e92112d6f0</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_SETTINGS_MAX_FRAME_SIZE</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a4040b0e6d05a8901e50c497254a8176daf09a348b42a97e9d8ae57bff5e252a9e</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a4040b0e6d05a8901e50c497254a8176da763095cc59fc3a905a4612e9a2843705</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketHTTP2_StreamState</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a6a90f4be9250fb7b967b5deefc0df5dc</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_STREAM_STATE_IDLE</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a6a90f4be9250fb7b967b5deefc0df5dcac5a700175844c3bcd24fc3896224d7ac</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_STREAM_STATE_RESERVED_LOCAL</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a6a90f4be9250fb7b967b5deefc0df5dca86b0c77c9b97e3ee828aa146440f645f</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_STREAM_STATE_RESERVED_REMOTE</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a6a90f4be9250fb7b967b5deefc0df5dca9c21d501045fdb865828fe73d9381bc6</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_STREAM_STATE_OPEN</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a6a90f4be9250fb7b967b5deefc0df5dca9ca1bb93131bcc5e4507162e71ad3ba0</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_STREAM_STATE_HALF_CLOSED_LOCAL</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a6a90f4be9250fb7b967b5deefc0df5dcad7d0667b7befb31c19321ca53f01767f</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_STREAM_STATE_HALF_CLOSED_REMOTE</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a6a90f4be9250fb7b967b5deefc0df5dca78e35d835f4cc4905f7e670985f0266c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_STREAM_STATE_CLOSED</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a6a90f4be9250fb7b967b5deefc0df5dca325a861687bc4a0028a5c1ee096a611c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketHTTP2_Role</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>abdba00019b45cc844046f038c7c7d590</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_ROLE_CLIENT</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>abdba00019b45cc844046f038c7c7d590a2e00d0d9453a99443244c64e1013d458</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP2_ROLE_SERVER</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>abdba00019b45cc844046f038c7c7d590acf94ddf824fa513af626e9fcaf922f0e</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTP2_config_defaults</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>af25e213512222a83030da6049be7c659</anchor>
      <arglist>(SocketHTTP2_Config *config, SocketHTTP2_Role role)</arglist>
    </member>
    <member kind="function">
      <type>SocketHTTP2_Conn_T</type>
      <name>SocketHTTP2_Conn_new</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>aac497f685932335cce6c3868243edf3c</anchor>
      <arglist>(Socket_T socket, const SocketHTTP2_Config *config, Arena_T arena)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTP2_Conn_free</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a13128ca7c1208a2a4694ea9926e2ff20</anchor>
      <arglist>(SocketHTTP2_Conn_T *conn)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTP2_Conn_handshake</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a3d2680dfe3afbbf9c6e9f09dad9f91d0</anchor>
      <arglist>(SocketHTTP2_Conn_T conn)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTP2_Conn_process</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>aecd0eb2455f15e9c9cea360331dcff5b</anchor>
      <arglist>(SocketHTTP2_Conn_T conn, unsigned events)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTP2_Conn_flush</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a667e2c409b1c71f702559904a823c6af</anchor>
      <arglist>(SocketHTTP2_Conn_T conn)</arglist>
    </member>
    <member kind="function">
      <type>Socket_T</type>
      <name>SocketHTTP2_Conn_socket</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>ab805b04d372fb6fdc75a5495d2cde2b2</anchor>
      <arglist>(SocketHTTP2_Conn_T conn)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTP2_Conn_is_closed</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>afa8022932a5b7a53fcc7f27a4aa0bf8a</anchor>
      <arglist>(SocketHTTP2_Conn_T conn)</arglist>
    </member>
    <member kind="function">
      <type>Arena_T</type>
      <name>SocketHTTP2_Conn_arena</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a12d9e2a8985ca9063c60842fcde83980</anchor>
      <arglist>(SocketHTTP2_Conn_T conn)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTP2_Conn_settings</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>ae0eb32c4b96fbf53f984c778859ca7c3</anchor>
      <arglist>(SocketHTTP2_Conn_T conn, const SocketHTTP2_Setting *settings, size_t count)</arglist>
    </member>
    <member kind="function">
      <type>uint32_t</type>
      <name>SocketHTTP2_Conn_get_setting</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a4e07a686761551bf19c8fb513feb0103</anchor>
      <arglist>(SocketHTTP2_Conn_T conn, SocketHTTP2_SettingsId id)</arglist>
    </member>
    <member kind="function">
      <type>uint32_t</type>
      <name>SocketHTTP2_Conn_get_local_setting</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>ad7e3dd8d7d156d66f0e7a020ecdb75d4</anchor>
      <arglist>(SocketHTTP2_Conn_T conn, SocketHTTP2_SettingsId id)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTP2_Conn_ping</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a6af782386d1634eb1a7fe105b82938cf</anchor>
      <arglist>(SocketHTTP2_Conn_T conn, const unsigned char opaque[8])</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTP2_Conn_goaway</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a572c83da10b0028e5c8eba35daad06d5</anchor>
      <arglist>(SocketHTTP2_Conn_T conn, SocketHTTP2_ErrorCode error_code, const void *debug_data, size_t debug_len)</arglist>
    </member>
    <member kind="function">
      <type>uint32_t</type>
      <name>SocketHTTP2_Conn_last_stream_id</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a8b438032a990cdc059ec3afcf002a501</anchor>
      <arglist>(SocketHTTP2_Conn_T conn)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTP2_Conn_window_update</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a2a0c736743250c55dbcdbea743774447</anchor>
      <arglist>(SocketHTTP2_Conn_T conn, uint32_t increment)</arglist>
    </member>
    <member kind="function">
      <type>int32_t</type>
      <name>SocketHTTP2_Conn_send_window</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a7d6946f3ae6907c3e2207cd87f7c84f0</anchor>
      <arglist>(SocketHTTP2_Conn_T conn)</arglist>
    </member>
    <member kind="function">
      <type>int32_t</type>
      <name>SocketHTTP2_Conn_recv_window</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a835634eb0dbb8316097e755768956306</anchor>
      <arglist>(SocketHTTP2_Conn_T conn)</arglist>
    </member>
    <member kind="function">
      <type>SocketHTTP2_Stream_T</type>
      <name>SocketHTTP2_Stream_new</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a5b78067e17aeddcd3b61748033c9e871</anchor>
      <arglist>(SocketHTTP2_Conn_T conn)</arglist>
    </member>
    <member kind="function">
      <type>uint32_t</type>
      <name>SocketHTTP2_Stream_id</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>addacfb14fd837b4dda70a77339cd3e30</anchor>
      <arglist>(SocketHTTP2_Stream_T stream)</arglist>
    </member>
    <member kind="function">
      <type>SocketHTTP2_StreamState</type>
      <name>SocketHTTP2_Stream_state</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a769baab55e16f038f085a579eac6aab3</anchor>
      <arglist>(SocketHTTP2_Stream_T stream)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTP2_Stream_close</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a5a81c4cf3cbde03b2b22b763e50d8d17</anchor>
      <arglist>(SocketHTTP2_Stream_T stream, SocketHTTP2_ErrorCode error_code)</arglist>
    </member>
    <member kind="function">
      <type>void *</type>
      <name>SocketHTTP2_Stream_get_userdata</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>aa270fdaf04a54c3d7bf5a795aa00481f</anchor>
      <arglist>(SocketHTTP2_Stream_T stream)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTP2_Stream_set_userdata</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a176621579ec7edc82efdaf6e96ef70e3</anchor>
      <arglist>(SocketHTTP2_Stream_T stream, void *userdata)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTP2_Stream_send_headers</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>ab70f7e768dd89aca7fd859aae33c74a1</anchor>
      <arglist>(SocketHTTP2_Stream_T stream, const SocketHPACK_Header *headers, size_t header_count, int end_stream)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTP2_Stream_send_request</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>ade9cdeda99348242667dfe65e4c1f054</anchor>
      <arglist>(SocketHTTP2_Stream_T stream, const SocketHTTP_Request *request, int end_stream)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTP2_Stream_send_response</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a553a90f9d384e7ac9667e03d146a873b</anchor>
      <arglist>(SocketHTTP2_Stream_T stream, const SocketHTTP_Response *response, int end_stream)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketHTTP2_Stream_send_data</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a1daa1717c92531030eef02f38035103b</anchor>
      <arglist>(SocketHTTP2_Stream_T stream, const void *data, size_t len, int end_stream)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTP2_Stream_send_trailers</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a3655b8f926656c6307e7db0377908e23</anchor>
      <arglist>(SocketHTTP2_Stream_T stream, const SocketHPACK_Header *trailers, size_t count)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTP2_Stream_recv_headers</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>ae764cf10037efdba2b3aabc30f47c034</anchor>
      <arglist>(SocketHTTP2_Stream_T stream, SocketHPACK_Header *headers, size_t max_headers, size_t *header_count, int *end_stream)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketHTTP2_Stream_recv_data</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a2af1317d69ebb7fcebdf0a916a6f0676</anchor>
      <arglist>(SocketHTTP2_Stream_T stream, void *buf, size_t len, int *end_stream)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTP2_Stream_recv_trailers</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>aac66e768242c701bf092296fa1dd2e19</anchor>
      <arglist>(SocketHTTP2_Stream_T stream, SocketHPACK_Header *trailers, size_t max_trailers, size_t *trailer_count)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTP2_Stream_window_update</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>ac6a15b2e7183cb4408510bac49674c36</anchor>
      <arglist>(SocketHTTP2_Stream_T stream, uint32_t increment)</arglist>
    </member>
    <member kind="function">
      <type>int32_t</type>
      <name>SocketHTTP2_Stream_send_window</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>afc20f969c971accab7bad1b1a8540581</anchor>
      <arglist>(SocketHTTP2_Stream_T stream)</arglist>
    </member>
    <member kind="function">
      <type>int32_t</type>
      <name>SocketHTTP2_Stream_recv_window</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a5dd00b82918a7db53168cb45e351705a</anchor>
      <arglist>(SocketHTTP2_Stream_T stream)</arglist>
    </member>
    <member kind="function">
      <type>SocketHTTP2_Stream_T</type>
      <name>SocketHTTP2_Stream_push_promise</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a7d284dfe8264dcc527215e2231d25e1d</anchor>
      <arglist>(SocketHTTP2_Stream_T stream, const SocketHPACK_Header *request_headers, size_t header_count)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTP2_Conn_set_stream_callback</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a93ddae7c32f498ea89e5d089b10e7080</anchor>
      <arglist>(SocketHTTP2_Conn_T conn, SocketHTTP2_StreamCallback callback, void *userdata)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTP2_Conn_set_conn_callback</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a86560d058cbae3ae5fd5b3964c308d84</anchor>
      <arglist>(SocketHTTP2_Conn_T conn, SocketHTTP2_ConnCallback callback, void *userdata)</arglist>
    </member>
    <member kind="function">
      <type>SocketHTTP2_Conn_T</type>
      <name>SocketHTTP2_Conn_upgrade_client</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>acee40a42125d8297c8537a4e5fd995d1</anchor>
      <arglist>(Socket_T socket, const unsigned char *settings_payload, size_t settings_len, Arena_T arena)</arglist>
    </member>
    <member kind="function">
      <type>SocketHTTP2_Conn_T</type>
      <name>SocketHTTP2_Conn_upgrade_server</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a5d0f7810c2a14c2a3afb5bfcd1f0ff88</anchor>
      <arglist>(Socket_T socket, const SocketHTTP_Request *initial_request, const unsigned char *settings_payload, size_t settings_len, Arena_T arena)</arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketHTTP2_ProtocolError</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>ac51371422726d9cacab52b583dcd7587</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketHTTP2_StreamError</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>aad19ee7b4b3a371cb35bd42c9247dda8</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketHTTP2_FlowControlError</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a7f79462d19b6633911fbf1d683df1ad5</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketHTTPClient-config.h</name>
    <path>include/http/</path>
    <filename>SocketHTTPClient-config_8h.html</filename>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_ERROR_BUFSIZE</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a27a6899380c014f0f1a08432877602b2</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_POOL_HASH_SIZE</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a2a80107d7741ba2a46baf779f7928730</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_POOL_LARGE_HASH_SIZE</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>ae7f6a04a117e98e557b38a582158c4bb</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_POOL_LARGE_THRESHOLD</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>afaff4a2f91f9687bf4149fde554c11b8</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_IO_BUFFER_SIZE</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a51703354cc9bc0603b78726aefab346f</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_DEFAULT_CONNECT_TIMEOUT_MS</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>ad6976b035b7becf34c067ecbfe122a99</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_DEFAULT_REQUEST_TIMEOUT_MS</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a86b91e7fbe633ea8ca189984af9b3547</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_DEFAULT_DNS_TIMEOUT_MS</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a02939decbb5546f8c00a4af02891beaf</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_DEFAULT_IDLE_TIMEOUT_MS</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a9668cac2b62d9570871b2865fcc2d562</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_DEFAULT_MAX_REDIRECTS</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a64838d8d2643dbec1c43f8e50055dbf7</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_DEFAULT_MAX_CONNS_PER_HOST</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a6495bfe151f30ebab1389fa05229498d</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_DEFAULT_MAX_TOTAL_CONNS</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a48547cb7f217429e34d7fa5c925d9dea</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_MAX_AUTH_RETRIES</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a447d54118ee03f42f7f2877718afae7f</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_DEFAULT_ENABLE_RETRY</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a66d096fe772967107d0642d303b1a51c</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_DEFAULT_MAX_RETRIES</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a43548f5c8b02196dd3bd71ccb9836c26</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_DEFAULT_RETRY_INITIAL_DELAY_MS</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a1827f78650d15ca622a674b130a2b926</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_DEFAULT_RETRY_MAX_DELAY_MS</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>af7e91b18a488977f7e7d333f0f7c0611</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_DEFAULT_RETRY_ON_CONNECT</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>afe6a8409016e05e46305b9f7042c7c7a</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_DEFAULT_RETRY_ON_TIMEOUT</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a2d9b8b306cf8b1a3a926e909f969315f</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_DEFAULT_RETRY_ON_5XX</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a82f5bad7555e08cf800e56ea7b04d0db</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_DEFAULT_ENFORCE_SAMESITE</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>ab32a3ecd078fc6919d2f5e0a06d12388</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_DEFAULT_MAX_RESPONSE_SIZE</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a4a61970445f2f7a4a8d23da8680fc09b</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_COOKIE_HASH_SIZE</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a2fc6723b3285e4aefbfe964932dca82c</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_COOKIE_MAX_NAME_LEN</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>ae4c2b4b036298405fa4df86655f40da0</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_COOKIE_MAX_VALUE_LEN</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a865ebc94fbbecd210790ee6724f25ad0</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_COOKIE_MAX_DOMAIN_LEN</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a6232822d5354e8e3a454b9aac0ab3405</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_COOKIE_MAX_PATH_LEN</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a9d065c123fe18985ed947ed344bfabe8</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_COOKIE_FILE_LINE_SIZE</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a93971a79c1854b341367aa92f1dfe657</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_COOKIE_MAX_AGE_SIZE</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>ab56546d633bcdabb80f6fa61ad4f3c3f</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_COOKIE_SAMESITE_SIZE</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a1f5201287c752c90005b22c9a07c8011</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_AUTH_CREDENTIALS_SIZE</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>aba4e506b5b48afa5c9e19f692619db35</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_DIGEST_A_BUFFER_SIZE</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a3db68e362a4cd23917b2e2b6dc05ef22</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_DIGEST_RESPONSE_SIZE</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a19c913be80fdc2a1778a5cf592fa5a32</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_DIGEST_CNONCE_SIZE</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a3e4e900df8359ef28d95b0ead64dbcf5</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_DIGEST_CNONCE_HEX_SIZE</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a1fbe044368878287464a35d2887c23cf</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_DIGEST_NC_SIZE</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a78e4b4357664a978b08470dc5110b5e9</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_REQUEST_BUFFER_SIZE</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a3de25c3d345626920f73bd6ceb4faefe</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_BODY_CHUNK_SIZE</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a9252df768faf5ccb5438f1e0e9d68b33</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_HOST_HEADER_SIZE</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a14236d3d25877900fe49a8c2b7c90e25</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_COOKIE_HEADER_SIZE</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a2bf0debe9f0685663a1f5b1fcaf56510</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_AUTH_HEADER_SIZE</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>ae0d219a3146b29914fb7f7169c6aa566</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_AUTH_HEADER_LARGE_SIZE</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a81ac4eefb96b3c919042f5fdd1ea361d</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_URI_BUFFER_SIZE</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a1421459188743de98f5eb1d489d70ec0</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_MAX_SET_COOKIES</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a134a20a8c6c468864bb0d94e9d9abb91</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_ACCEPT_ENCODING_SIZE</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a846e1eb9e4ecd57dc03a065776981e0b</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_CONTENT_LENGTH_SIZE</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a4063c6077aa71b96a83dbe475a59e5a9</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_RETRY_JITTER_FACTOR</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a441f1405cd4774e167f08b83b3b1e117</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_RETRY_MULTIPLIER</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a5f5f7ee22b430f5cb019b8b0a6803348</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_DEFAULT_USER_AGENT</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>ad23bab3060a93bc022b891a925e34f94</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_ENCODING_IDENTITY</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>a1a94747fcfaf987c84d4a91bc3bd7513</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_ENCODING_GZIP</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>aca301afd15b5701276655faf5cdf3104</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_ENCODING_DEFLATE</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>ae68f134e13b2a94d9f4f5973fc02bf3c</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPCLIENT_ENCODING_BR</name>
      <anchorfile>SocketHTTPClient-config_8h.html</anchorfile>
      <anchor>acf069f17c344d63494b465eb5dcec7b8</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketHTTPClient.h</name>
    <path>include/http/</path>
    <filename>SocketHTTPClient_8h.html</filename>
    <includes id="Arena_8h" name="Arena.h" local="yes" import="no" module="no" objc="no">core/Arena.h</includes>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="SocketHTTP_8h" name="SocketHTTP.h" local="yes" import="no" module="no" objc="no">http/SocketHTTP.h</includes>
    <includes id="SocketHTTPClient-config_8h" name="SocketHTTPClient-config.h" local="yes" import="no" module="no" objc="no">http/SocketHTTPClient-config.h</includes>
    <includes id="SocketTLSContext_8h" name="SocketTLSContext.h" local="yes" import="no" module="no" objc="no">tls/SocketTLSContext.h</includes>
    <class kind="struct">SocketHTTPClient_Auth</class>
    <class kind="struct">SocketHTTPClient_Config</class>
    <class kind="struct">SocketHTTPClient_Response</class>
    <class kind="struct">SocketHTTPClient_Cookie</class>
    <class kind="struct">SocketHTTPClient_PoolStats</class>
    <member kind="typedef">
      <type>struct SocketHTTPClient *</type>
      <name>SocketHTTPClient_T</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>aba14ae9994f5645e5aa8488f905aad54</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketHTTPClient_Request *</type>
      <name>SocketHTTPClient_Request_T</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a265c0209bd77c39f219d72c3956a8818</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketHTTPClient_AsyncRequest *</type>
      <name>SocketHTTPClient_AsyncRequest_T</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a1f0f539e54a607bea5559f6577f987df</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketHTTPClient_CookieJar *</type>
      <name>SocketHTTPClient_CookieJar_T</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a118e7e43ad387b22241607355dbdec9f</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketHTTPClient_Error</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a6b0f544308db17e698b4c05ac3358b75</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTPCLIENT_OK</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a6b0f544308db17e698b4c05ac3358b75a0d7b07825c19819fb9d1adbe3f28fd7d</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTPCLIENT_ERROR_DNS</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a6b0f544308db17e698b4c05ac3358b75ae1f6869bacb82ecbe3914f3d52a7c5ef</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTPCLIENT_ERROR_CONNECT</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a6b0f544308db17e698b4c05ac3358b75aa0a0bf606da8e46eba8cf29cec56bd25</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTPCLIENT_ERROR_TLS</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a6b0f544308db17e698b4c05ac3358b75abea0c5bb21ff179f4bff79115f26a9a5</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTPCLIENT_ERROR_TIMEOUT</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a6b0f544308db17e698b4c05ac3358b75a5099780b4bb3fee36f2432496843bac8</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTPCLIENT_ERROR_PROTOCOL</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a6b0f544308db17e698b4c05ac3358b75a3a208d6e1419093b96cb8335741f2abe</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTPCLIENT_ERROR_TOO_MANY_REDIRECTS</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a6b0f544308db17e698b4c05ac3358b75a178aabd112e942f1ce3c9c9e92d8f657</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTPCLIENT_ERROR_RESPONSE_TOO_LARGE</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a6b0f544308db17e698b4c05ac3358b75a686c1f9288cfc49b1f887b1786ea85e5</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTPCLIENT_ERROR_CANCELLED</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a6b0f544308db17e698b4c05ac3358b75aa1effb555a4ca8cb0f483adf8319eea8</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTPCLIENT_ERROR_OUT_OF_MEMORY</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a6b0f544308db17e698b4c05ac3358b75aeb7ea1f2504e427a5e5d962af382dd1c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTPCLIENT_ERROR_LIMIT_EXCEEDED</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a6b0f544308db17e698b4c05ac3358b75a40c972700be18d6b9c5d6c1db5cec9fb</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketHTTPClient_AuthType</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a720036180c834b3f4b41f437d0ce1f30</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_AUTH_NONE</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a720036180c834b3f4b41f437d0ce1f30a208f0926853b84d7acf3ce0669e9dc1c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_AUTH_BASIC</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a720036180c834b3f4b41f437d0ce1f30a946b7e60a754342e83205964b31a77ba</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_AUTH_DIGEST</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a720036180c834b3f4b41f437d0ce1f30a2de9030bd220adb7701f5cbdeadfc4a3</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTP_AUTH_BEARER</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a720036180c834b3f4b41f437d0ce1f30acda827d72fd9c0a84535434c81558c96</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTPClient_error_is_retryable</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>af69fc4efa6d5b4df9cdf207cfa05b6b9</anchor>
      <arglist>(SocketHTTPClient_Error error)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTPClient_config_defaults</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>aad5ad81c60bb230588b5f660a834f40e</anchor>
      <arglist>(SocketHTTPClient_Config *config)</arglist>
    </member>
    <member kind="function">
      <type>SocketHTTPClient_T</type>
      <name>SocketHTTPClient_new</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a2d57db3a9a6388315f253caa099e4205</anchor>
      <arglist>(const SocketHTTPClient_Config *config)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTPClient_free</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a01d6c9bebdcda63949ba9af698f8e7e5</anchor>
      <arglist>(SocketHTTPClient_T *client)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTPClient_get</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>afef425814e66932f7cf1f36e9356b70e</anchor>
      <arglist>(SocketHTTPClient_T client, const char *url, SocketHTTPClient_Response *response)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTPClient_head</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a4efcd265a023ce14464f07ef360fb030</anchor>
      <arglist>(SocketHTTPClient_T client, const char *url, SocketHTTPClient_Response *response)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTPClient_post</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a9b47bc2dd38d4a6700af79ced0acecb2</anchor>
      <arglist>(SocketHTTPClient_T client, const char *url, const char *content_type, const void *body, size_t body_len, SocketHTTPClient_Response *response)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTPClient_put</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a9d15a2624c43ac163f993827d3756efc</anchor>
      <arglist>(SocketHTTPClient_T client, const char *url, const char *content_type, const void *body, size_t body_len, SocketHTTPClient_Response *response)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTPClient_delete</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a6bc9ded2b6017d03733c50c493605ef7</anchor>
      <arglist>(SocketHTTPClient_T client, const char *url, SocketHTTPClient_Response *response)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTPClient_Response_free</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a826bca53483c23de2c8b03d456010149</anchor>
      <arglist>(SocketHTTPClient_Response *response)</arglist>
    </member>
    <member kind="function">
      <type>SocketHTTPClient_Request_T</type>
      <name>SocketHTTPClient_Request_new</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a46c9c2ab8d3334dd0ad1359d2bb93102</anchor>
      <arglist>(SocketHTTPClient_T client, SocketHTTP_Method method, const char *url)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTPClient_Request_free</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a31f46990e2a8d948bfe7db2e22b85565</anchor>
      <arglist>(SocketHTTPClient_Request_T *req)</arglist>
    </member>
    <member kind="function">
      <type>const SocketHTTPClient_Cookie *</type>
      <name>SocketHTTPClient_CookieJar_get</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a79838faf1567b0b9946b95b946de4392</anchor>
      <arglist>(SocketHTTPClient_CookieJar_T jar, const char *domain, const char *path, const char *name)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTPClient_CookieJar_clear</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>aad4e0041def5bbfdbd42f1192b5f588a</anchor>
      <arglist>(SocketHTTPClient_CookieJar_T jar)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTPClient_CookieJar_clear_expired</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a52288a166212725fc43156b1bb2fc5b4</anchor>
      <arglist>(SocketHTTPClient_CookieJar_T jar)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTPClient_CookieJar_load</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a0804b639cfe122234e22b14498f2af13</anchor>
      <arglist>(SocketHTTPClient_CookieJar_T jar, const char *filename)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTPClient_CookieJar_save</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a4f086bf1231cc24fee20d8b0461fec05</anchor>
      <arglist>(SocketHTTPClient_CookieJar_T jar, const char *filename)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTPClient_set_auth</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a1e9410043754e2ad4dbaa3572c595547</anchor>
      <arglist>(SocketHTTPClient_T client, const SocketHTTPClient_Auth *auth)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTPClient_pool_stats</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>aca84ba9dfcb00f58533dafe869f8c548</anchor>
      <arglist>(SocketHTTPClient_T client, SocketHTTPClient_PoolStats *stats)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTPClient_pool_clear</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a1fd6bae0397b3156f49100f444fdaac6</anchor>
      <arglist>(SocketHTTPClient_T client)</arglist>
    </member>
    <member kind="function">
      <type>SocketHTTPClient_Error</type>
      <name>SocketHTTPClient_last_error</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>ac8680d78a9d70c7662d39466c63aab72</anchor>
      <arglist>(SocketHTTPClient_T client)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketHTTPClient_error_string</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a859120de13b0764564f3c1ce111b3379</anchor>
      <arglist>(SocketHTTPClient_Error error)</arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketHTTPClient_Failed</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a5dc1b9ac7f30436bc422f312cd6db709</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketHTTPClient_DNSFailed</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a50039c8c595271d7d51b28ed5a4e7196</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketHTTPClient_ConnectFailed</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a83bda6e77bc5fb165e4e7fead483094b</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketHTTPClient_TLSFailed</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>ac109f9bf9ba67f2f56db130172b3dd94</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketHTTPClient_Timeout</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>aa0847dd6efa2f627e07173f29b29c8ae</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketHTTPClient_ProtocolError</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a24ffae352f53c9580d861d3590b61e2a</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketHTTPClient_TooManyRedirects</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>afd7d2611128ad32cc65cb256403c671f</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketHTTPClient_ResponseTooLarge</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a4ed14f04119b1dec3cb25c432b7a383d</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketHTTPClient_SameSite</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a5a9d40d261a12f620aba6b26e8fb714b</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>COOKIE_SAMESITE_NONE</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a5a9d40d261a12f620aba6b26e8fb714baa133f9bf67acb51315ada8cd26d83946</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>COOKIE_SAMESITE_LAX</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a5a9d40d261a12f620aba6b26e8fb714ba9360362eafff108453d53fe004670bb5</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>COOKIE_SAMESITE_STRICT</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a5a9d40d261a12f620aba6b26e8fb714ba1f862e6251a539d010cf430eb0052f80</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>void(*</type>
      <name>SocketHTTPClient_Callback</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a3cb9ba239e5a623795bae1ddfd084201</anchor>
      <arglist>)(SocketHTTPClient_AsyncRequest_T req, SocketHTTPClient_Response *response, SocketHTTPClient_Error error, void *userdata)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTPClient_Request_header</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a8a7c54a81dc916af60f9747162e844a2</anchor>
      <arglist>(SocketHTTPClient_Request_T req, const char *name, const char *value)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTPClient_Request_body</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>ae8f21b1fc1aae1ef8b1bbe43ce875247</anchor>
      <arglist>(SocketHTTPClient_Request_T req, const void *data, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTPClient_Request_body_stream</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a8470d0864afe35f5265bda12d221f14e</anchor>
      <arglist>(SocketHTTPClient_Request_T req, ssize_t(*read_cb)(void *buf, size_t len, void *userdata), void *userdata)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTPClient_Request_timeout</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>abe918e0dacc9d507f1ad288a399dfca6</anchor>
      <arglist>(SocketHTTPClient_Request_T req, int ms)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTPClient_Request_auth</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a4aaf34db687d93fcbaa8e13b35916b6a</anchor>
      <arglist>(SocketHTTPClient_Request_T req, const SocketHTTPClient_Auth *auth)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTPClient_Request_execute</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a4ba09b6d59cc2aee465749978f62ad76</anchor>
      <arglist>(SocketHTTPClient_Request_T req, SocketHTTPClient_Response *response)</arglist>
    </member>
    <member kind="function">
      <type>SocketHTTPClient_AsyncRequest_T</type>
      <name>SocketHTTPClient_get_async</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a887d2e7f1b676b7a1bd44de4a2964e03</anchor>
      <arglist>(SocketHTTPClient_T client, const char *url, SocketHTTPClient_Callback callback, void *userdata)</arglist>
    </member>
    <member kind="function">
      <type>SocketHTTPClient_AsyncRequest_T</type>
      <name>SocketHTTPClient_post_async</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>addf401e4175374852073d0de27407fef</anchor>
      <arglist>(SocketHTTPClient_T client, const char *url, const char *content_type, const void *body, size_t body_len, SocketHTTPClient_Callback callback, void *userdata)</arglist>
    </member>
    <member kind="function">
      <type>SocketHTTPClient_AsyncRequest_T</type>
      <name>SocketHTTPClient_Request_async</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a64e1155f06853b28f5619690840d3962</anchor>
      <arglist>(SocketHTTPClient_Request_T req, SocketHTTPClient_Callback callback, void *userdata)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTPClient_AsyncRequest_cancel</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>adedb2c16bf1b0081fb02c8c681973429</anchor>
      <arglist>(SocketHTTPClient_AsyncRequest_T req)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTPClient_process</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a9f4f6e7641bef38d356a7349e1d589a4</anchor>
      <arglist>(SocketHTTPClient_T client, int timeout_ms)</arglist>
    </member>
    <member kind="function">
      <type>SocketHTTPClient_CookieJar_T</type>
      <name>SocketHTTPClient_CookieJar_new</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a7f6bd73797f507766f9edc1242b9772e</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTPClient_CookieJar_free</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a628b803f0ccfdc41d8425bf1c1064d7e</anchor>
      <arglist>(SocketHTTPClient_CookieJar_T *jar)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTPClient_set_cookie_jar</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a07b465d99995da22fc317dc170d09787</anchor>
      <arglist>(SocketHTTPClient_T client, SocketHTTPClient_CookieJar_T jar)</arglist>
    </member>
    <member kind="function">
      <type>SocketHTTPClient_CookieJar_T</type>
      <name>SocketHTTPClient_get_cookie_jar</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a52e891cd45c787d4025e15d8c4c42849</anchor>
      <arglist>(SocketHTTPClient_T client)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTPClient_CookieJar_set</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>ae276f63daea601b662eae51e1973f3e5</anchor>
      <arglist>(SocketHTTPClient_CookieJar_T jar, const SocketHTTPClient_Cookie *cookie)</arglist>
    </member>
    <member kind="function">
      <type>const SocketHTTPClient_Cookie *</type>
      <name>SocketHTTPClient_CookieJar_get</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a79838faf1567b0b9946b95b946de4392</anchor>
      <arglist>(SocketHTTPClient_CookieJar_T jar, const char *domain, const char *path, const char *name)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTPClient_CookieJar_clear</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>aad4e0041def5bbfdbd42f1192b5f588a</anchor>
      <arglist>(SocketHTTPClient_CookieJar_T jar)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTPClient_CookieJar_clear_expired</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a52288a166212725fc43156b1bb2fc5b4</anchor>
      <arglist>(SocketHTTPClient_CookieJar_T jar)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTPClient_CookieJar_load</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a0804b639cfe122234e22b14498f2af13</anchor>
      <arglist>(SocketHTTPClient_CookieJar_T jar, const char *filename)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTPClient_CookieJar_save</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a4f086bf1231cc24fee20d8b0461fec05</anchor>
      <arglist>(SocketHTTPClient_CookieJar_T jar, const char *filename)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTPClient_set_auth</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a1e9410043754e2ad4dbaa3572c595547</anchor>
      <arglist>(SocketHTTPClient_T client, const SocketHTTPClient_Auth *auth)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTPClient_pool_stats</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>aca84ba9dfcb00f58533dafe869f8c548</anchor>
      <arglist>(SocketHTTPClient_T client, SocketHTTPClient_PoolStats *stats)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTPClient_pool_clear</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a1fd6bae0397b3156f49100f444fdaac6</anchor>
      <arglist>(SocketHTTPClient_T client)</arglist>
    </member>
    <member kind="function">
      <type>SocketHTTPClient_Error</type>
      <name>SocketHTTPClient_last_error</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>ac8680d78a9d70c7662d39466c63aab72</anchor>
      <arglist>(SocketHTTPClient_T client)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketHTTPClient_error_string</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a859120de13b0764564f3c1ce111b3379</anchor>
      <arglist>(SocketHTTPClient_Error error)</arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketHTTPServer.h</name>
    <path>include/http/</path>
    <filename>SocketHTTPServer_8h.html</filename>
    <includes id="Arena_8h" name="Arena.h" local="yes" import="no" module="no" objc="no">core/Arena.h</includes>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="SocketRateLimit_8h" name="SocketRateLimit.h" local="yes" import="no" module="no" objc="no">core/SocketRateLimit.h</includes>
    <includes id="SocketHTTP_8h" name="SocketHTTP.h" local="yes" import="no" module="no" objc="no">http/SocketHTTP.h</includes>
    <includes id="SocketPoll_8h" name="SocketPoll.h" local="yes" import="no" module="no" objc="no">poll/SocketPoll.h</includes>
    <includes id="Socket_8h" name="Socket.h" local="yes" import="no" module="no" objc="no">socket/Socket.h</includes>
    <includes id="SocketTLSContext_8h" name="SocketTLSContext.h" local="yes" import="no" module="no" objc="no">tls/SocketTLSContext.h</includes>
    <class kind="struct">SocketHTTPServer_Config</class>
    <member kind="define">
      <type>#define</type>
      <name>HTTPSERVER_DEFAULT_BACKLOG</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a4522c2e543c78b0021fca2f4e4e731e6</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPSERVER_DEFAULT_PORT</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>adcd2ff25d89289e51c96fe57c120717f</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPSERVER_DEFAULT_BIND_ADDR</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a0667730c5595188e1bdf991b20180ddf</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPSERVER_DEFAULT_ENABLE_H2C_UPGRADE</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a305cd6f6613872a906cd1bc1150645c7</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPSERVER_CONTENT_LENGTH_BUF_SIZE</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a303e75df1224167a8e5a69e0258c1533</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPSERVER_CHUNK_FINAL_BUF_SIZE</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>abe7c219136e39fcb63d1edd1bd029dcd</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPSERVER_CLIENT_ADDR_MAX</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a04264611026dfbf30d986e60368536f9</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPSERVER_DRAIN_POLL_MS</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a6828829545fd5f379e44e960700bdc21</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPSERVER_DEFAULT_MAX_CONNECTIONS</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a458d6caf223ed54cf1dd9c231954dffc</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPSERVER_DEFAULT_REQUEST_TIMEOUT_MS</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a0fa61fa2afd1f2d2c57e165ca1c534c4</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPSERVER_DEFAULT_KEEPALIVE_TIMEOUT_MS</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a8d3b7bb7934d1baa38eeac26a28fbf4f</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPSERVER_DEFAULT_MAX_HEADER_SIZE</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a75c229ac6f33c83ed5b903888f748707</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPSERVER_DEFAULT_MAX_BODY_SIZE</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>aa5715a9f50d6f8766088fbafbc7608b3</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPSERVER_DEFAULT_MAX_REQUESTS_PER_CONN</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a689bbacaca6f6ceff8d330ab6650ed84</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPSERVER_DEFAULT_REQUEST_READ_TIMEOUT_MS</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>aeb21a7a41a54fc1f559a29b3b8ae87c9</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPSERVER_DEFAULT_RESPONSE_WRITE_TIMEOUT_MS</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a45662a88175b71660de7e17d0908de1d</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPSERVER_DEFAULT_MAX_CONNECTIONS_PER_CLIENT</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>ab341f7aa2e0d398e7fcf27469bc1a62d</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPSERVER_DEFAULT_MAX_CONCURRENT_REQUESTS</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>aed3e151f56c9277c3b5b63ab23c3e09a</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPSERVER_DEFAULT_STREAM_CHUNK_SIZE</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a441035c0576c57af0fe9d979b5a42df1</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPSERVER_RPS_WINDOW_SECONDS</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>af7a1376f4194e9507953d89b715fa656</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPSERVER_IO_BUFFER_SIZE</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a2d15e59f13b41ae609043cef1fe0d02f</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPSERVER_RECV_BUFFER_SIZE</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>ad6df29e2fea722ad22368a2b940b5531</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPSERVER_RESPONSE_HEADER_BUFFER_SIZE</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>adbc773d7bce0c70ba39358448aa0ace0</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPSERVER_MAX_CLIENTS_PER_ACCEPT</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>ae8e00010a149a907589ccf535454dde8</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPSERVER_CHUNK_BUFFER_SIZE</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a1ebce2db0ae2bba492c06324e38b7370</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPSERVER_MAX_RATE_LIMIT_ENDPOINTS</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>ad9ded082ab5a397fd3386ca1c63fe114</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>HTTPSERVER_LATENCY_SAMPLES</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a3473805e79004874242125148c096a88</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketWS *</type>
      <name>SocketWS_T</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a62eac457c36851d5e4a184e1a5602555</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketHTTPServer *</type>
      <name>SocketHTTPServer_T</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>ad59859e8ae07bfb95f5807590dd034f4</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketHTTPServer_Request *</type>
      <name>SocketHTTPServer_Request_T</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a071a3760545fbd5fca4c2df224af0fad</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>void(*</type>
      <name>SocketHTTPServer_Handler</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a8805b706921b37e2e91e68a861ddc97c</anchor>
      <arglist>)(SocketHTTPServer_Request_T req, void *userdata)</arglist>
    </member>
    <member kind="typedef">
      <type>int(*</type>
      <name>SocketHTTPServer_BodyCallback</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>ab347055b7285aedad5fa0f504c3a655e</anchor>
      <arglist>)(SocketHTTPServer_Request_T req, const void *chunk, size_t len, int is_final, void *userdata)</arglist>
    </member>
    <member kind="typedef">
      <type>int(*</type>
      <name>SocketHTTPServer_Validator</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>ab095eb6d03d06f9c1d8041dc3aa56094</anchor>
      <arglist>)(SocketHTTPServer_Request_T req, int *reject_status, void *userdata)</arglist>
    </member>
    <member kind="typedef">
      <type>void(*</type>
      <name>SocketHTTPServer_DrainCallback</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a6eeba038caf0b48d3ae3527155ab8162</anchor>
      <arglist>)(SocketHTTPServer_T server, int timed_out, void *userdata)</arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketHTTPServer_State</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a0ac9162aaf92d18d40cf0443909e3e97</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTPSERVER_STATE_RUNNING</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a0ac9162aaf92d18d40cf0443909e3e97a71eb63ea64bc63130077055f5def4470</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTPSERVER_STATE_DRAINING</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a0ac9162aaf92d18d40cf0443909e3e97ab9ea109b294256f80f9c605af4ee33da</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HTTPSERVER_STATE_STOPPED</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a0ac9162aaf92d18d40cf0443909e3e97a40470a42c264e62630500ec3e55f5570</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTPServer_config_defaults</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a08bbe8e6a3560817cd898a51622bc6ce</anchor>
      <arglist>(SocketHTTPServer_Config *config)</arglist>
    </member>
    <member kind="function">
      <type>SocketHTTPServer_T</type>
      <name>SocketHTTPServer_new</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>aea4fe38f3115faefc4bbc7f28e6b7362</anchor>
      <arglist>(const SocketHTTPServer_Config *config)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTPServer_free</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>acf5856e5b1728e44bbb68ef2e4637318</anchor>
      <arglist>(SocketHTTPServer_T *server)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTPServer_start</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>afa06caca93c0fac3e52f7749abe03be9</anchor>
      <arglist>(SocketHTTPServer_T server)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTPServer_stop</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>af332d06f999890e277dc83777d669f00</anchor>
      <arglist>(SocketHTTPServer_T server)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHTTPServer_set_handler</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>aaf56db2565e6fdebcebf0bb7df24b959</anchor>
      <arglist>(SocketHTTPServer_T server, SocketHTTPServer_Handler handler, void *userdata)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTPServer_fd</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a23f97a896233d7ca6259ab43684e784d</anchor>
      <arglist>(SocketHTTPServer_T server)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHTTPServer_process</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>ab2ad4e6a795964f1edabf14a71b83985</anchor>
      <arglist>(SocketHTTPServer_T server, int timeout_ms)</arglist>
    </member>
    <member kind="function">
      <type>SocketPoll_T</type>
      <name>SocketHTTPServer_poll</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>af4e5392eaefa9ee259824571a1c5487d</anchor>
      <arglist>(SocketHTTPServer_T server)</arglist>
    </member>
    <member kind="function">
      <type>SocketHTTP_Method</type>
      <name>SocketHTTPServer_Request_method</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a62a61206448cffe1710070a6c64b554d</anchor>
      <arglist>(SocketHTTPServer_Request_T req)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketHTTPServer_Request_path</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a62b0e10b9c135a08852e56eb1eae8ac4</anchor>
      <arglist>(SocketHTTPServer_Request_T req)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketHTTPServer_Request_query</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a7bb246b4e39b4d74d3821201b6f72456</anchor>
      <arglist>(SocketHTTPServer_Request_T req)</arglist>
    </member>
    <member kind="function">
      <type>SocketHTTP_Headers_T</type>
      <name>SocketHTTPServer_Request_headers</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a51f26503d221c39a5e867b5d4c683ae7</anchor>
      <arglist>(SocketHTTPServer_Request_T req)</arglist>
    </member>
    <member kind="function">
      <type>const void *</type>
      <name>SocketHTTPServer_Request_body</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a7e95ae3464cb9cf8c0d0b172db13456e</anchor>
      <arglist>(SocketHTTPServer_Request_T req)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketHTTPServer_Request_body_len</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a5ac308a85217f94c0fc5ced8525b55e5</anchor>
      <arglist>(SocketHTTPServer_Request_T req)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketHTTPServer_Request_client_addr</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a2f5234c0311c21a800e1145ff06c88a4</anchor>
      <arglist>(SocketHTTPServer_Request_T req)</arglist>
    </member>
    <member kind="function">
      <type>SocketHTTP_Version</type>
      <name>SocketHTTPServer_Request_version</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a28be52d1b6393421dd306dc400d443ee</anchor>
      <arglist>(SocketHTTPServer_Request_T req)</arglist>
    </member>
    <member kind="function">
      <type>Arena_T</type>
      <name>SocketHTTPServer_Request_arena</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>ab962af94432e50a19c4a4d09b307cd68</anchor>
      <arglist>(SocketHTTPServer_Request_T req)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketHTTPServer_Request_memory_used</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a9b44e54c60728c855c3cfad99196dc64</anchor>
      <arglist>(SocketHTTPServer_Request_T req)</arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketHTTPServer_Failed</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>ab0e17c60a6e02fe69434302760371464</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketHTTPServer_BindFailed</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>ab0cf03445c053391004f6234e29812f5</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketHTTPServer_ProtocolError</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a46e1179e3239aac920a2afa2fc6711b3</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketPoll.h</name>
    <path>include/poll/</path>
    <filename>SocketPoll_8h.html</filename>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="SocketTimer_8h" name="SocketTimer.h" local="yes" import="no" module="no" objc="no">core/SocketTimer.h</includes>
    <includes id="Socket_8h" name="Socket.h" local="yes" import="no" module="no" objc="no">socket/Socket.h</includes>
    <class kind="struct">SocketEvent_T</class>
    <member kind="define">
      <type>#define</type>
      <name>T</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>a0acb682b8260ab1c60b918599864e2e5</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_POLL_TIMEOUT_USE_DEFAULT</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>a0fc8aa94a3e9bb10cb26d85c6474d04e</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketAsync_T *</type>
      <name>SocketAsync_T</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>a733615fa159421d6c73d01f6bb34bac8</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketPoll_T *</type>
      <name>SocketPoll_T</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>af9e4be8bc025aedb61cc0b77e8926312</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketPoll_Events</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>a9e8943c9cb47aba63dda4ad9083142b6</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>POLL_READ</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>a9e8943c9cb47aba63dda4ad9083142b6a19f5d65c083268df50040f34f306d1b8</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>POLL_WRITE</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>a9e8943c9cb47aba63dda4ad9083142b6acd6f685ba9cebb83074be444222ae195</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>POLL_ERROR</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>a9e8943c9cb47aba63dda4ad9083142b6a29422ea3bfa0fde21ed413e6f9d7b0d9</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>POLL_HANGUP</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>a9e8943c9cb47aba63dda4ad9083142b6aaa263b6ed4ed526b0d9c55f0c2702f4c</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>SocketPoll_T</type>
      <name>SocketPoll_new</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>ac1fbd1a09d564f7988b0e427e5707ca7</anchor>
      <arglist>(int maxevents)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPoll_free</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>aca744c50badbdb869c52088b9f32f8d2</anchor>
      <arglist>(SocketPoll_T *poll)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPoll_add</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>a6c9f3f1a23dd85dd2d44ff9b0ced4e1e</anchor>
      <arglist>(SocketPoll_T poll, Socket_T socket, unsigned events, void *data)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPoll_mod</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>a3755cc4d5ed8838ce2261f0efd1d5d85</anchor>
      <arglist>(SocketPoll_T poll, Socket_T socket, unsigned events, void *data)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPoll_del</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>a3074c5a225a7c49880951ecfb984498f</anchor>
      <arglist>(SocketPoll_T poll, Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketPoll_getdefaulttimeout</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>a1bb5e288308c3de5a479b27366bba257</anchor>
      <arglist>(SocketPoll_T poll)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPoll_setdefaulttimeout</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>a945845cc57758a91e47a75ef17064d2a</anchor>
      <arglist>(SocketPoll_T poll, int timeout)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketPoll_wait</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>aa3d47365dd18329d50ee636284839738</anchor>
      <arglist>(SocketPoll_T poll, SocketEvent_T **events, int timeout)</arglist>
    </member>
    <member kind="function">
      <type>SocketAsync_T</type>
      <name>SocketPoll_get_async</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>a665b3363d16ab859ec60e69a792d1ff0</anchor>
      <arglist>(SocketPoll_T poll)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketPoll_getmaxregistered</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>a16688a9e444183863bab8051f57fe688</anchor>
      <arglist>(SocketPoll_T poll)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPoll_setmaxregistered</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>a35d4052d444bcab4cae26f41cf5729eb</anchor>
      <arglist>(SocketPoll_T poll, int max)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketPoll_getregisteredcount</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>ac79e719de24f09f84eb3816b3ab60c65</anchor>
      <arglist>(SocketPoll_T poll)</arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketPoll_Failed</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>ab4754362476e3ffc3e000b1cbcc2a6f0</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketPoll_backend.h</name>
    <path>include/poll/</path>
    <filename>SocketPoll__backend_8h.html</filename>
    <includes id="SocketPoll_8h" name="SocketPoll.h" local="yes" import="no" module="no" objc="no">poll/SocketPoll.h</includes>
    <includes id="Socket_8h" name="Socket.h" local="yes" import="no" module="no" objc="no">socket/Socket.h</includes>
    <includes id="Arena_8h" name="Arena.h" local="yes" import="no" module="no" objc="no">core/Arena.h</includes>
    <member kind="define">
      <type>#define</type>
      <name>VALIDATE_MAXEVENTS</name>
      <anchorfile>SocketPoll__backend_8h.html</anchorfile>
      <anchor>ad5c973c74b3941d078d573439e92c65b</anchor>
      <arglist>(maxevents, event_type)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>VALIDATE_FD</name>
      <anchorfile>SocketPoll__backend_8h.html</anchorfile>
      <anchor>a72ef813749c8c54d8f8ccf64ba724a0a</anchor>
      <arglist>(fd)</arglist>
    </member>
    <member kind="typedef">
      <type>struct PollBackend_T *</type>
      <name>PollBackend_T</name>
      <anchorfile>SocketPoll__backend_8h.html</anchorfile>
      <anchor>add97c2d63f6b491ef855bd928211e71b</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>PollBackend_T</type>
      <name>backend_new</name>
      <anchorfile>SocketPoll__backend_8h.html</anchorfile>
      <anchor>aa198b207e04b5bb6bec2746c7d86b735</anchor>
      <arglist>(Arena_T arena, int maxevents)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>backend_free</name>
      <anchorfile>SocketPoll__backend_8h.html</anchorfile>
      <anchor>a30a767499b3aa80b77e4fb63368be228</anchor>
      <arglist>(PollBackend_T backend)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>backend_add</name>
      <anchorfile>SocketPoll__backend_8h.html</anchorfile>
      <anchor>aa51ec4e5f966a860cdd9359c36e977c6</anchor>
      <arglist>(PollBackend_T backend, int fd, unsigned events)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>backend_mod</name>
      <anchorfile>SocketPoll__backend_8h.html</anchorfile>
      <anchor>a4b929e888a5088e59cd045c41759363e</anchor>
      <arglist>(PollBackend_T backend, int fd, unsigned events)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>backend_del</name>
      <anchorfile>SocketPoll__backend_8h.html</anchorfile>
      <anchor>ae9ec719e250346605c00e5b3efb2e7d8</anchor>
      <arglist>(PollBackend_T backend, int fd)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>backend_wait</name>
      <anchorfile>SocketPoll__backend_8h.html</anchorfile>
      <anchor>a5b2c06638f0c76ea3c6c2f38503d266b</anchor>
      <arglist>(PollBackend_T backend, int timeout_ms)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>backend_get_event</name>
      <anchorfile>SocketPoll__backend_8h.html</anchorfile>
      <anchor>ad998de1df9f46711f5c3b4dc0257f548</anchor>
      <arglist>(const PollBackend_T backend, int index, int *fd_out, unsigned *events_out)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>backend_name</name>
      <anchorfile>SocketPoll__backend_8h.html</anchorfile>
      <anchor>a2edb00f128ad773d62c8f11c516153d9</anchor>
      <arglist>(void)</arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketPool.h</name>
    <path>include/pool/</path>
    <filename>SocketPool_8h.html</filename>
    <includes id="Arena_8h" name="Arena.h" local="yes" import="no" module="no" objc="no">core/Arena.h</includes>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="SocketSYNProtect_8h" name="SocketSYNProtect.h" local="yes" import="no" module="no" objc="no">core/SocketSYNProtect.h</includes>
    <includes id="SocketUtil_8h" name="SocketUtil.h" local="yes" import="no" module="no" objc="no">core/SocketUtil.h</includes>
    <includes id="Socket_8h" name="Socket.h" local="yes" import="no" module="no" objc="no">socket/Socket.h</includes>
    <includes id="SocketBuf_8h" name="SocketBuf.h" local="yes" import="no" module="no" objc="no">socket/SocketBuf.h</includes>
    <includes id="SocketReconnect_8h" name="SocketReconnect.h" local="yes" import="no" module="no" objc="no">socket/SocketReconnect.h</includes>
    <includes id="SocketDNS_8h" name="SocketDNS.h" local="yes" import="no" module="no" objc="no">dns/SocketDNS.h</includes>
    <class kind="struct">SocketPool_Stats</class>
    <member kind="define">
      <type>#define</type>
      <name>T</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a0acb682b8260ab1c60b918599864e2e5</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketPool_T *</type>
      <name>SocketPool_T</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a9b894da8ce452934ac1e3ab806060ae9</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct Connection *</type>
      <name>Connection_T</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a424a0221f5eef0991c244d83d02d8b2c</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>int(*</type>
      <name>SocketPool_ValidationCallback</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a9a848b27d2034b028ceb2febdc6471b5</anchor>
      <arglist>)(Connection_T conn, void *data)</arglist>
    </member>
    <member kind="typedef">
      <type>void(*</type>
      <name>SocketPool_ResizeCallback</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a6ec7b7f0dae3b1366f32f93294dc8b4a</anchor>
      <arglist>)(SocketPool_T pool, size_t old_size, size_t new_size, void *data)</arglist>
    </member>
    <member kind="typedef">
      <type>void(*</type>
      <name>SocketPool_ConnectCallback</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a5441c8cf779cd74fbb9f39bd322c33bd</anchor>
      <arglist>)(Connection_T conn, int error, void *data)</arglist>
    </member>
    <member kind="typedef">
      <type>void(*</type>
      <name>SocketPool_DrainCallback</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>ad7679db7b1be62e465d9896944f3ad20</anchor>
      <arglist>)(SocketPool_T pool, int timed_out, void *data)</arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketPool_State</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>ae5f905ecace343c3b462dfadd5fa8056</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>POOL_STATE_RUNNING</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>ae5f905ecace343c3b462dfadd5fa8056a6c2b7ace544a9999526d4314075694f5</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>POOL_STATE_DRAINING</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>ae5f905ecace343c3b462dfadd5fa8056a24af61ac7dffa2f526a693507b11075b</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>POOL_STATE_STOPPED</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>ae5f905ecace343c3b462dfadd5fa8056a937e01590410f41013603cedffd2d2d9</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketPool_Health</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a97c30d41df98c69bb394f0a91c3759ae</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>POOL_HEALTH_HEALTHY</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a97c30d41df98c69bb394f0a91c3759aea42517e08f6d9119b5f96fe68b5623e2d</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>POOL_HEALTH_DRAINING</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a97c30d41df98c69bb394f0a91c3759aea972a5e12c8d2b2b17477779aece54c74</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>POOL_HEALTH_STOPPED</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a97c30d41df98c69bb394f0a91c3759aea083eb1503d53d80d116c0ee25022b819</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketPool_ConnHealth</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a92931382e16ec0f93619d6fe95c68fdf</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>POOL_CONN_HEALTHY</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a92931382e16ec0f93619d6fe95c68fdfa92d5c5da87579cc06fcbe3ff7f3c312e</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>POOL_CONN_DISCONNECTED</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a92931382e16ec0f93619d6fe95c68fdfae8b36f49ecaf54a76a78bed5a38da457</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>POOL_CONN_ERROR</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a92931382e16ec0f93619d6fe95c68fdfa6d7a0c62f6bf32b8e47f29eed6533f69</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>POOL_CONN_STALE</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a92931382e16ec0f93619d6fe95c68fdfa38972b76d931672d61056eea4fec704a</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>SocketPool_T</type>
      <name>SocketPool_new</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a2774ba952af4a9a218e33b492aed1a18</anchor>
      <arglist>(Arena_T arena, size_t maxconns, size_t bufsize)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketPool_prepare_connection</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a2c6952c25bc0d5ca0264e795036a2653</anchor>
      <arglist>(SocketPool_T pool, SocketDNS_T dns, const char *host, int port, Socket_T *out_socket, SocketDNS_Request_T *out_req)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPool_free</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>afb57544a14c977302953fd36634bd004</anchor>
      <arglist>(SocketPool_T *pool)</arglist>
    </member>
    <member kind="function">
      <type>SocketDNS_Request_T</type>
      <name>SocketPool_connect_async</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a56db54df36b153155bc5428f56598b67</anchor>
      <arglist>(SocketPool_T pool, const char *host, int port, SocketPool_ConnectCallback callback, void *data)</arglist>
    </member>
    <member kind="function">
      <type>Connection_T</type>
      <name>SocketPool_get</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a21b17f01e3036b53fed194c6b3c0b95f</anchor>
      <arglist>(SocketPool_T pool, Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>Connection_T</type>
      <name>SocketPool_add</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>ac7720c7b7d679624fa95bdefe9a38494</anchor>
      <arglist>(SocketPool_T pool, Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketPool_accept_batch</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a283d343a8192530c349dc9a02b987c26</anchor>
      <arglist>(SocketPool_T pool, Socket_T server, int max_accepts, size_t accepted_capacity, Socket_T *accepted)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPool_remove</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>acdffcf1802367df60db15c649fc7072d</anchor>
      <arglist>(SocketPool_T pool, Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPool_cleanup</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>ab2a7df0479b8f9ac899672afdb488b94</anchor>
      <arglist>(SocketPool_T pool, time_t idle_timeout)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketPool_count</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a618413d296dac8730047cf248273461e</anchor>
      <arglist>(SocketPool_T pool)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPool_resize</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>ae7d2acf643422a026241225f245f8d26</anchor>
      <arglist>(SocketPool_T pool, size_t new_maxconns)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPool_prewarm</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a8363470d36d9cac714f087b8dcb1a048</anchor>
      <arglist>(SocketPool_T pool, int percentage)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPool_set_bufsize</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a83ad1fb6ad736f4169297af3fd255410</anchor>
      <arglist>(SocketPool_T pool, size_t new_bufsize)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPool_foreach</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>ab6ffb3b44d5214daeed16af0c4cae08c</anchor>
      <arglist>(SocketPool_T pool, void(*func)(Connection_T, void *), void *arg)</arglist>
    </member>
    <member kind="function">
      <type>Socket_T</type>
      <name>Connection_socket</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>aaeff7efb1109a312f56e35689b67c652</anchor>
      <arglist>(const Connection_T conn)</arglist>
    </member>
    <member kind="function">
      <type>SocketBuf_T</type>
      <name>Connection_inbuf</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a24170577512ce3a19fe195ab9c3576bf</anchor>
      <arglist>(const Connection_T conn)</arglist>
    </member>
    <member kind="function">
      <type>SocketBuf_T</type>
      <name>Connection_outbuf</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a6d7573f71d8853943029cfd55fa3fb3a</anchor>
      <arglist>(const Connection_T conn)</arglist>
    </member>
    <member kind="function">
      <type>void *</type>
      <name>Connection_data</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a1faf8c706d1ed9418446fc155fa289dd</anchor>
      <arglist>(const Connection_T conn)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Connection_setdata</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>ab48a53bc1b36954d521104fedf9012c1</anchor>
      <arglist>(Connection_T conn, void *data)</arglist>
    </member>
    <member kind="function">
      <type>time_t</type>
      <name>Connection_lastactivity</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a68397aca39e8902ee26108dcb86b5db1</anchor>
      <arglist>(const Connection_T conn)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Connection_isactive</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>af52bba490d68b2dd5448a61a1cc820a1</anchor>
      <arglist>(const Connection_T conn)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPool_set_reconnect_policy</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>ae4b6b07007da08326b53c069a4c1f2ea</anchor>
      <arglist>(SocketPool_T pool, const SocketReconnect_Policy_T *policy)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPool_enable_reconnect</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a94ef5658ee53e87337b931b549ff35f2</anchor>
      <arglist>(SocketPool_T pool, Connection_T conn, const char *host, int port)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPool_disable_reconnect</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a7be3d82708a40f4d7601737467cdd51a</anchor>
      <arglist>(SocketPool_T pool, Connection_T conn)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPool_process_reconnects</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a817b53044890ea7978afb73f51584bce</anchor>
      <arglist>(SocketPool_T pool)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketPool_reconnect_timeout_ms</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a4bfa04a134354dcebd077ea54dbb2d9e</anchor>
      <arglist>(SocketPool_T pool)</arglist>
    </member>
    <member kind="function">
      <type>SocketReconnect_T</type>
      <name>Connection_reconnect</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a0ea55ad82560acb8b5b44dceebc7c02f</anchor>
      <arglist>(const Connection_T conn)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Connection_has_reconnect</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a548e5fadc02daadb2388d09bf8aec167</anchor>
      <arglist>(const Connection_T conn)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPool_setconnrate</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a204d43047f820499ae59b7984f00b148</anchor>
      <arglist>(SocketPool_T pool, int conns_per_sec, int burst)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketPool_getconnrate</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>adc0d9937eb377068134cab141b8bcfad</anchor>
      <arglist>(SocketPool_T pool)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPool_setmaxperip</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>af8991c65cdec81d2a8db01a2f820a42b</anchor>
      <arglist>(SocketPool_T pool, int max_conns)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketPool_getmaxperip</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a952bad4a5d699878fef42407a1260cfe</anchor>
      <arglist>(SocketPool_T pool)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketPool_accept_allowed</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>aac8b8b6c2075b758c5c85426194c2539</anchor>
      <arglist>(SocketPool_T pool, const char *client_ip)</arglist>
    </member>
    <member kind="function">
      <type>Socket_T</type>
      <name>SocketPool_accept_limited</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>abd8219ceff615ad4a4064cf389f137a6</anchor>
      <arglist>(SocketPool_T pool, Socket_T server)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketPool_track_ip</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a9b0182834888e8b3136846f5fca1bc64</anchor>
      <arglist>(SocketPool_T pool, const char *ip)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPool_release_ip</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a930ce5b0eddb884de4c8514e4d6068c4</anchor>
      <arglist>(SocketPool_T pool, const char *ip)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketPool_ip_count</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>ace0da0754ae023a89aee4b96a4e50845</anchor>
      <arglist>(SocketPool_T pool, const char *ip)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPool_set_syn_protection</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a847e3ae8d165d8a999ef76a68d21ffa5</anchor>
      <arglist>(SocketPool_T pool, SocketSYNProtect_T protect)</arglist>
    </member>
    <member kind="function">
      <type>SocketSYNProtect_T</type>
      <name>SocketPool_get_syn_protection</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a9047fb0f2c05a4f208c023b5e81196e3</anchor>
      <arglist>(SocketPool_T pool)</arglist>
    </member>
    <member kind="function">
      <type>Socket_T</type>
      <name>SocketPool_accept_protected</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a899c660b21bf96befd2b5ea9f6937988</anchor>
      <arglist>(SocketPool_T pool, Socket_T server, SocketSYN_Action *action_out)</arglist>
    </member>
    <member kind="function">
      <type>SocketPool_State</type>
      <name>SocketPool_state</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a0a62267ba3008f826b6952624dbc6a29</anchor>
      <arglist>(SocketPool_T pool)</arglist>
    </member>
    <member kind="function">
      <type>SocketPool_Health</type>
      <name>SocketPool_health</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>ac801c2d9c4fd944334de2a551993bd89</anchor>
      <arglist>(SocketPool_T pool)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketPool_is_draining</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a5245d1cd6578a86f1045529d07fe511c</anchor>
      <arglist>(SocketPool_T pool)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketPool_is_stopped</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a6ee3c9502d314b58f9eba33827dd28cf</anchor>
      <arglist>(SocketPool_T pool)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPool_drain</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a24cd4e2f757497906a5aef89b133b068</anchor>
      <arglist>(SocketPool_T pool, int timeout_ms)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketPool_drain_poll</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a2cbe6c95119cbb4b30f981b9d07f3e9b</anchor>
      <arglist>(SocketPool_T pool)</arglist>
    </member>
    <member kind="function">
      <type>int64_t</type>
      <name>SocketPool_drain_remaining_ms</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>ae14b85a2cd7a0a4302f84478840cfb23</anchor>
      <arglist>(SocketPool_T pool)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPool_drain_force</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a0cbc1088d796c166f582de4d17e5d968</anchor>
      <arglist>(SocketPool_T pool)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketPool_drain_wait</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a3f0fdd6e4245f2844081d935b2d3c8a2</anchor>
      <arglist>(SocketPool_T pool, int timeout_ms)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPool_set_drain_callback</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a254e5c125de7413e1fa2a8809350d4e0</anchor>
      <arglist>(SocketPool_T pool, SocketPool_DrainCallback cb, void *data)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPool_set_idle_timeout</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a76151bb579f44bdf79aeca57dbd8122e</anchor>
      <arglist>(SocketPool_T pool, time_t timeout_sec)</arglist>
    </member>
    <member kind="function">
      <type>time_t</type>
      <name>SocketPool_get_idle_timeout</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>aee19a772a9cf21b2c50fd1deec498b0b</anchor>
      <arglist>(SocketPool_T pool)</arglist>
    </member>
    <member kind="function">
      <type>int64_t</type>
      <name>SocketPool_idle_cleanup_due_ms</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>ab0d0f088107c8034fff0a9f87d056100</anchor>
      <arglist>(SocketPool_T pool)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketPool_run_idle_cleanup</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a8efd44a4a7089eea19819785b0e2de4b</anchor>
      <arglist>(SocketPool_T pool)</arglist>
    </member>
    <member kind="function">
      <type>SocketPool_ConnHealth</type>
      <name>SocketPool_check_connection</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a3e6eccb3c5a10e8ac40b057a56e77ed5</anchor>
      <arglist>(SocketPool_T pool, Connection_T conn)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPool_set_validation_callback</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a11a46794f10d4d659cf75412e84cef31</anchor>
      <arglist>(SocketPool_T pool, SocketPool_ValidationCallback cb, void *data)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPool_set_resize_callback</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a9c7cd8aa28512bb3e73885f5968a46cd</anchor>
      <arglist>(SocketPool_T pool, SocketPool_ResizeCallback cb, void *data)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPool_get_stats</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a8289eac993efd5cac1c6147c06d6d645</anchor>
      <arglist>(SocketPool_T pool, SocketPool_Stats *stats)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPool_reset_stats</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a2f8bfb464d9ab7068fefa9c0ba57c436</anchor>
      <arglist>(SocketPool_T pool)</arglist>
    </member>
    <member kind="function">
      <type>time_t</type>
      <name>Connection_created_at</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>adeb31a2cef7f4d6b590baf9c3e4fd048</anchor>
      <arglist>(const Connection_T conn)</arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketPool_Failed</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>adba094d10381f1646de6a3e1e2bd0c36</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>Socket.h</name>
    <path>include/socket/</path>
    <filename>Socket_8h.html</filename>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="SocketConfig_8h" name="SocketConfig.h" local="yes" import="no" module="no" objc="no">core/SocketConfig.h</includes>
    <includes id="SocketDNS_8h" name="SocketDNS.h" local="yes" import="no" module="no" objc="no">dns/SocketDNS.h</includes>
    <includes id="SocketCommon_8h" name="SocketCommon.h" local="yes" import="no" module="no" objc="no">socket/SocketCommon.h</includes>
    <member kind="define">
      <type>#define</type>
      <name>T</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a0acb682b8260ab1c60b918599864e2e5</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct Socket_T *</type>
      <name>Socket_T</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a1bcdb0c6d5827c2493bd622fa7751f14</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_error_is_retryable</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a8517adf0df2e5331a952fb713ec314f9</anchor>
      <arglist>(int err)</arglist>
    </member>
    <member kind="function">
      <type>Socket_T</type>
      <name>Socket_new</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a6212fb2b6eefa567592a59f55c25a6f1</anchor>
      <arglist>(int domain, int type, int protocol)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPair_new</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a1290da3d1c546b8c550a59e138f722b8</anchor>
      <arglist>(int type, Socket_T *socket1, Socket_T *socket2)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_free</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a74ad7a9bb8deaf499c59d90d6e411f37</anchor>
      <arglist>(Socket_T *socket)</arglist>
    </member>
    <member kind="function">
      <type>Socket_T</type>
      <name>Socket_new_from_fd</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>ae7c6b82ec5bf6be8131532de9ade5caf</anchor>
      <arglist>(int fd)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_debug_live_count</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>aa8cacd863c275e6e12f7c63b65708e1b</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_bind</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>acb65d693d8c93e2a1fe6411dd0d0af98</anchor>
      <arglist>(Socket_T socket, const char *host, int port)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_listen</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>ab24b026bc4c69e6f766211f44675e189</anchor>
      <arglist>(Socket_T socket, int backlog)</arglist>
    </member>
    <member kind="function">
      <type>Socket_T</type>
      <name>Socket_accept</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a32b67d95639513cd6a602f6175b48f15</anchor>
      <arglist>(Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_connect</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>ac14390090ee26136c1f7a816fc08406e</anchor>
      <arglist>(Socket_T socket, const char *host, int port)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>Socket_send</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a23ace6e065fe4b9a01db8caa6513515b</anchor>
      <arglist>(Socket_T socket, const void *buf, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>Socket_recv</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a95db343f47445925cecd6b20054518e9</anchor>
      <arglist>(Socket_T socket, void *buf, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>Socket_sendall</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a6ea9ad33d78c50d327c9677b52849bcb</anchor>
      <arglist>(Socket_T socket, const void *buf, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>Socket_recvall</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a18ea888b05b09714cc010463b8cead4b</anchor>
      <arglist>(Socket_T socket, void *buf, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>Socket_sendv</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>adb50371f84b2c796c4e57a34d41f180a</anchor>
      <arglist>(Socket_T socket, const struct iovec *iov, int iovcnt)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>Socket_recvv</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>abb1c8e39587d4ea5e3ffe4b06dcaca0f</anchor>
      <arglist>(Socket_T socket, struct iovec *iov, int iovcnt)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>Socket_sendvall</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>af6d033a04d5041249950fa2f54a8d9fd</anchor>
      <arglist>(Socket_T socket, const struct iovec *iov, int iovcnt)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>Socket_recvvall</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a3472c67c78cd29944a87783e09247f9a</anchor>
      <arglist>(Socket_T socket, struct iovec *iov, int iovcnt)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>Socket_sendfile</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>ad1003c289820587894dbfcad9b567c43</anchor>
      <arglist>(Socket_T socket, int file_fd, off_t *offset, size_t count)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>Socket_sendfileall</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a6262f6ab4c927347abc0fb3c105a0575</anchor>
      <arglist>(Socket_T socket, int file_fd, off_t *offset, size_t count)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>Socket_sendmsg</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>aeb12f81392f3c1fb21255bf44521e20c</anchor>
      <arglist>(Socket_T socket, const struct msghdr *msg, int flags)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>Socket_recvmsg</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a92c972ba69ef189d5d802e4d1889a9c6</anchor>
      <arglist>(Socket_T socket, struct msghdr *msg, int flags)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_isconnected</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a10d49f774ed335cf4e42f77c07948119</anchor>
      <arglist>(Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_isbound</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a1710f1e1251df44fb4f82c60ff199a76</anchor>
      <arglist>(Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_islistening</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>ab693dfb51bcfe2b284969a5f1db14a84</anchor>
      <arglist>(Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_fd</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a4d727948c677509eec04746585819877</anchor>
      <arglist>(const Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>Socket_getpeeraddr</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>ab0957f43694d0728e70b23364a89623c</anchor>
      <arglist>(const Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_getpeerport</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a38d7e5845519867261a9f24dfe0e03db</anchor>
      <arglist>(const Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>Socket_getlocaladdr</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a04e55475bcedbc100767663e1e7d9de1</anchor>
      <arglist>(const Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_getlocalport</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a3bdedaea9dac966d75343cdffa5d1f3e</anchor>
      <arglist>(const Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_setnonblocking</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a35309677a1760480783d5f0c294d0db4</anchor>
      <arglist>(Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_setreuseaddr</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a2c6f352cec920859c71206898ed135fc</anchor>
      <arglist>(Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_setreuseport</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a2126127d2fa85fb5de27587e0d41a466</anchor>
      <arglist>(Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_settimeout</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a210cbf763685c0b201b0f5caa2dc0f06</anchor>
      <arglist>(Socket_T socket, int timeout_sec)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_setkeepalive</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>af03ef2a81d1894713aeb96c12bb2389b</anchor>
      <arglist>(Socket_T socket, int idle, int interval, int count)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_setnodelay</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a55174d7f9aca0e94d25321540646e6b0</anchor>
      <arglist>(Socket_T socket, int nodelay)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_gettimeout</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>aa40c1cdc37abfc34cbc17cdcbf607241</anchor>
      <arglist>(Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_getkeepalive</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>acd2f2e66892b062079f4c0a1dd7f8bac</anchor>
      <arglist>(Socket_T socket, int *idle, int *interval, int *count)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_getnodelay</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a01aa484c370addf3f117cfdb4f9adb8a</anchor>
      <arglist>(Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_getrcvbuf</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a73b2908934ed8757725da6e6d22ff60c</anchor>
      <arglist>(Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_getsndbuf</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a23a3e2bbff42609e2e4089d5e6c55bbd</anchor>
      <arglist>(Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_setrcvbuf</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>ad59dc86a3f3728e75983daa0f5b34550</anchor>
      <arglist>(Socket_T socket, int size)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_setsndbuf</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a430b3464f6e656f4d8884031deffa507</anchor>
      <arglist>(Socket_T socket, int size)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_setcongestion</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>ae144a341a05e25011d95761368eefe13</anchor>
      <arglist>(Socket_T socket, const char *algorithm)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_getcongestion</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>aebaf7f944985462e9198998a650f2b5c</anchor>
      <arglist>(Socket_T socket, char *algorithm, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_setfastopen</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>aa7c1651e6f9e3e97ddab01d40ac1d39d</anchor>
      <arglist>(Socket_T socket, int enable)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_getfastopen</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a762ad6759e76f58f5a8f1fcb305387a8</anchor>
      <arglist>(Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_setusertimeout</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>abfad0f5567b5f8720a4667e13e79f282</anchor>
      <arglist>(Socket_T socket, unsigned int timeout_ms)</arglist>
    </member>
    <member kind="function">
      <type>unsigned int</type>
      <name>Socket_getusertimeout</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a2b81fe340e400d96d2552a65cfde5430</anchor>
      <arglist>(Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_shutdown</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a559b1aaebbe5d0ca69ec99e15b1c7e68</anchor>
      <arglist>(Socket_T socket, int how)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_setcloexec</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a18ad1f92bb3233c463ea4067b69f73c2</anchor>
      <arglist>(Socket_T socket, int enable)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_setdeferaccept</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>ab5b9e684faf1a8d5c1ccb9e231ef1354</anchor>
      <arglist>(Socket_T socket, int timeout_sec)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_getdeferaccept</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a80f9fc5782bf3caf5228e458d3f3c112</anchor>
      <arglist>(Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_timeouts_get</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a5fa0449e34ebfb141da236023da3edb7</anchor>
      <arglist>(const Socket_T socket, SocketTimeouts_T *timeouts)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_timeouts_set</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a3e3b95a49618f5a56869606adeeda58f</anchor>
      <arglist>(Socket_T socket, const SocketTimeouts_T *timeouts)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_timeouts_getdefaults</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>acfcc79428e54b0284cc7cad257d56adf</anchor>
      <arglist>(SocketTimeouts_T *timeouts)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_timeouts_setdefaults</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a0385e87c51740c37c9d90ff5bba1eced</anchor>
      <arglist>(const SocketTimeouts_T *timeouts)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_timeouts_set_extended</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>ad663873fbc8f0846c092a380f64b1f52</anchor>
      <arglist>(Socket_T socket, const SocketTimeouts_Extended_T *extended)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_timeouts_get_extended</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a4affc77e30721f266acfc9ba7870dff5</anchor>
      <arglist>(const Socket_T socket, SocketTimeouts_Extended_T *extended)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_setbandwidth</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>acab565f9a6e6c40c56d6d21df89b30a9</anchor>
      <arglist>(Socket_T socket, size_t bytes_per_sec)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>Socket_getbandwidth</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>ae49a9ad4c524354506bef71ec6cffdf9</anchor>
      <arglist>(Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>Socket_send_limited</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a274b6782b2029d2d8aa33579ad60a4c1</anchor>
      <arglist>(Socket_T socket, const void *buf, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>Socket_recv_limited</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a6839d0b5738d2764b47de35bf7e16430</anchor>
      <arglist>(Socket_T socket, void *buf, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>int64_t</type>
      <name>Socket_bandwidth_wait_ms</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a89643e52780099fe0012e2fa22725e07</anchor>
      <arglist>(Socket_T socket, size_t bytes)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_bind_unix</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>ad85ee4be563a1006b7518645995ab65e</anchor>
      <arglist>(Socket_T socket, const char *path)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_connect_unix</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>ad353c95a8994569af7b650f1fda7036f</anchor>
      <arglist>(Socket_T socket, const char *path)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_getpeerpid</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>aabc2fdbcfb3c619c05c7aa3c4c555382</anchor>
      <arglist>(const Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_getpeeruid</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a0bf945a195478ed5a85c881b0f163a08</anchor>
      <arglist>(const Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_getpeergid</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a64a5bd6dc33ef5f000b9f7d334a1fdfa</anchor>
      <arglist>(const Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_sendfd</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a001e932180b059a805ca53a8edbeef15</anchor>
      <arglist>(Socket_T socket, int fd_to_pass)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_recvfd</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>ad1236a73c0cac828b3079b74d1b0996d</anchor>
      <arglist>(Socket_T socket, int *fd_received)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_sendfds</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a70c2f94b87d307842c7d11de0b6a2bce</anchor>
      <arglist>(Socket_T socket, const int *fds, size_t count)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_recvfds</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>ab806cbdac1b78ff644c4f841151cf3a8</anchor>
      <arglist>(Socket_T socket, int *fds, size_t max_count, size_t *received_count)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketUnix_bind</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>ad12cd27d2531c8ea2b762e0ab4659d63</anchor>
      <arglist>(SocketBase_T base, const char *path, Except_T exc_type)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketUnix_connect</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>afadda7c72f287b85c490f04aec8623e1</anchor>
      <arglist>(SocketBase_T base, const char *path, Except_T exc_type)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketUnix_validate_unix_path</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a039fc234ac9f3aa259ea01e22218e442</anchor>
      <arglist>(const char *path, size_t path_len)</arglist>
    </member>
    <member kind="function">
      <type>SocketDNS_Request_T</type>
      <name>Socket_bind_async</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>ab17262422d628bfd3c64e219b7474d3f</anchor>
      <arglist>(SocketDNS_T dns, Socket_T socket, const char *host, int port)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_bind_async_cancel</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>ad6e2d6b94b41a45e9d9fb43f6122e489</anchor>
      <arglist>(SocketDNS_T dns, SocketDNS_Request_T req)</arglist>
    </member>
    <member kind="function">
      <type>SocketDNS_Request_T</type>
      <name>Socket_connect_async</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>aa3f4e3781b8abe542d0fd907788c5c01</anchor>
      <arglist>(SocketDNS_T dns, Socket_T socket, const char *host, int port)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_connect_async_cancel</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>ac935e4853e90426e05722f6e54c2e7b9</anchor>
      <arglist>(SocketDNS_T dns, SocketDNS_Request_T req)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_bind_with_addrinfo</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a7147a127f3463d5861da5a16435ef4e7</anchor>
      <arglist>(Socket_T socket, struct addrinfo *res)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_connect_with_addrinfo</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a28271af8ebad671a64fd37ffb2d07e0c</anchor>
      <arglist>(Socket_T socket, struct addrinfo *res)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_ignore_sigpipe</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a410b67062c053c3af7e86531acc1620c</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>Socket_Failed</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a225f4a8fd657fd52a05146c6fc4f58b0</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>Socket_Closed</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a2db3d742dcea3f39ad2eb37d4fb1e453</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketUnix_Failed</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>ab05e641cc9abed67180036e51a1dc633</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketAsync.h</name>
    <path>include/socket/</path>
    <filename>SocketAsync_8h.html</filename>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="Socket_8h" name="Socket.h" local="yes" import="no" module="no" objc="no">socket/Socket.h</includes>
    <member kind="define">
      <type>#define</type>
      <name>T</name>
      <anchorfile>SocketAsync_8h.html</anchorfile>
      <anchor>a0acb682b8260ab1c60b918599864e2e5</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketAsync_T *</type>
      <name>SocketAsync_T</name>
      <anchorfile>SocketAsync_8h.html</anchorfile>
      <anchor>a733615fa159421d6c73d01f6bb34bac8</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>void(*</type>
      <name>SocketAsync_Callback</name>
      <anchorfile>SocketAsync_8h.html</anchorfile>
      <anchor>ad6644a0c3153b65fa217ecbc45b5b8f9</anchor>
      <arglist>)(Socket_T socket, ssize_t bytes, int err, void *user_data)</arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketAsync_Flags</name>
      <anchorfile>SocketAsync_8h.html</anchorfile>
      <anchor>ae66259c675b6f9658c95d34e1fbfefdf</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>ASYNC_FLAG_NONE</name>
      <anchorfile>SocketAsync_8h.html</anchorfile>
      <anchor>ae66259c675b6f9658c95d34e1fbfefdfa3b607e56f470ff08783c2f3385c1041c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>ASYNC_FLAG_ZERO_COPY</name>
      <anchorfile>SocketAsync_8h.html</anchorfile>
      <anchor>ae66259c675b6f9658c95d34e1fbfefdfa5b1a5dc7d9ed8ace5643e4cef11cb50d</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>ASYNC_FLAG_URGENT</name>
      <anchorfile>SocketAsync_8h.html</anchorfile>
      <anchor>ae66259c675b6f9658c95d34e1fbfefdfaf08a13c5b932be67e3f0ed7de0499ef8</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>SocketAsync_T</type>
      <name>SocketAsync_new</name>
      <anchorfile>SocketAsync_8h.html</anchorfile>
      <anchor>a1c4916e173cffa9153c983a4fd0d0d56</anchor>
      <arglist>(Arena_T arena)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketAsync_free</name>
      <anchorfile>SocketAsync_8h.html</anchorfile>
      <anchor>a0d3a7b456b962c6abf4dfd91859492e0</anchor>
      <arglist>(SocketAsync_T *async)</arglist>
    </member>
    <member kind="function">
      <type>unsigned</type>
      <name>SocketAsync_send</name>
      <anchorfile>SocketAsync_8h.html</anchorfile>
      <anchor>ae0ecf4f023555d16b855d39841521f2b</anchor>
      <arglist>(SocketAsync_T async, Socket_T socket, const void *buf, size_t len, SocketAsync_Callback cb, void *user_data, SocketAsync_Flags flags)</arglist>
    </member>
    <member kind="function">
      <type>unsigned</type>
      <name>SocketAsync_recv</name>
      <anchorfile>SocketAsync_8h.html</anchorfile>
      <anchor>a46adb5a1db31901afa5d1d6514e41b64</anchor>
      <arglist>(SocketAsync_T async, Socket_T socket, void *buf, size_t len, SocketAsync_Callback cb, void *user_data, SocketAsync_Flags flags)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketAsync_cancel</name>
      <anchorfile>SocketAsync_8h.html</anchorfile>
      <anchor>a275aefb76cdeb48b9b9330a777a2bb8c</anchor>
      <arglist>(SocketAsync_T async, unsigned request_id)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketAsync_process_completions</name>
      <anchorfile>SocketAsync_8h.html</anchorfile>
      <anchor>a1cc05d5d1dd032943b57a03da3061da7</anchor>
      <arglist>(SocketAsync_T async, int timeout_ms)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketAsync_is_available</name>
      <anchorfile>SocketAsync_8h.html</anchorfile>
      <anchor>a0f304bcb93351c8555f9afa74fa9e665</anchor>
      <arglist>(const SocketAsync_T async)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketAsync_backend_name</name>
      <anchorfile>SocketAsync_8h.html</anchorfile>
      <anchor>afae22c23e82d55f6fa3eaf74c0c37f5d</anchor>
      <arglist>(const SocketAsync_T async)</arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketAsync_Failed</name>
      <anchorfile>SocketAsync_8h.html</anchorfile>
      <anchor>a55b9b96eff9c17f45ff5bfb37f431075</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketBuf.h</name>
    <path>include/socket/</path>
    <filename>SocketBuf_8h.html</filename>
    <includes id="Arena_8h" name="Arena.h" local="yes" import="no" module="no" objc="no">core/Arena.h</includes>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <member kind="define">
      <type>#define</type>
      <name>T</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>a0acb682b8260ab1c60b918599864e2e5</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketBuf_T *</type>
      <name>SocketBuf_T</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>ad4b3ec10874282833e1b15760efa1b6c</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>SocketBuf_T</type>
      <name>SocketBuf_new</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>ac82b13f33ba79d9fa97582a64654e8ef</anchor>
      <arglist>(Arena_T arena, size_t capacity)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketBuf_release</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>a7e38c8dbadd8bd771d70ec98eda9f448</anchor>
      <arglist>(SocketBuf_T *buf)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketBuf_write</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>abad296e666bf8d65669ab7c71d6b8d97</anchor>
      <arglist>(SocketBuf_T buf, const void *data, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketBuf_read</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>a4aacfb9008833f24abec18b1d65d0d42</anchor>
      <arglist>(SocketBuf_T buf, void *data, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketBuf_peek</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>a55cfa577b17ee4e2ea965a841deccab0</anchor>
      <arglist>(SocketBuf_T buf, void *data, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketBuf_consume</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>ad11c3dede8563afbb1a3e9b9f4e936e6</anchor>
      <arglist>(SocketBuf_T buf, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketBuf_available</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>a4f350e096708c438bc2002909325b143</anchor>
      <arglist>(const SocketBuf_T buf)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketBuf_space</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>a4f511809edb33ba3ff3a051544bff0d1</anchor>
      <arglist>(const SocketBuf_T buf)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketBuf_empty</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>a886e91e5cdff04cbc06b2d99eb887808</anchor>
      <arglist>(const SocketBuf_T buf)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketBuf_full</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>a8ae7a3d2576f6d28c91511e10790e99a</anchor>
      <arglist>(const SocketBuf_T buf)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketBuf_clear</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>a61b062261e8e954240edf8d3a6a01fb8</anchor>
      <arglist>(SocketBuf_T buf)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketBuf_secureclear</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>af0f12ab9bbed33398141c41561c1fcb7</anchor>
      <arglist>(SocketBuf_T buf)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketBuf_reserve</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>a77d70e899c26ac30bad4aac232505f1e</anchor>
      <arglist>(SocketBuf_T buf, size_t min_space)</arglist>
    </member>
    <member kind="function">
      <type>bool</type>
      <name>SocketBuf_check_invariants</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>a884735923c2cf7dbe7def9d9062ac512</anchor>
      <arglist>(const SocketBuf_T buf)</arglist>
    </member>
    <member kind="function">
      <type>const void *</type>
      <name>SocketBuf_readptr</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>ae4d5d95ed126030f6414b7f607cd555e</anchor>
      <arglist>(SocketBuf_T buf, size_t *len)</arglist>
    </member>
    <member kind="function">
      <type>void *</type>
      <name>SocketBuf_writeptr</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>a0d845ceca49625b8c317310a757ad9dc</anchor>
      <arglist>(SocketBuf_T buf, size_t *len)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketBuf_written</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>a2e4e93aa0feab70464515b0ef3a57186</anchor>
      <arglist>(SocketBuf_T buf, size_t len)</arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketBuf_Failed</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>a246f86a3226316f3922ee9eba0436777</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketCommon.h</name>
    <path>include/socket/</path>
    <filename>SocketCommon_8h.html</filename>
    <includes id="Arena_8h" name="Arena.h" local="yes" import="no" module="no" objc="no">core/Arena.h</includes>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="SocketConfig_8h" name="SocketConfig.h" local="yes" import="no" module="no" objc="no">core/SocketConfig.h</includes>
    <class kind="struct">SocketLiveCount</class>
    <member kind="define">
      <type>#define</type>
      <name>SocketBase_T</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a875ae9df41c30f375802590471923dd1</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKETLIVECOUNT_STATIC_INIT</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>afdd7aa5138146bb99a2360fface85b12</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketBase_T *</type>
      <name>SocketBase_T</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>ac716bcecf8b2060038ad6ede113539a2</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketDNS_T *</type>
      <name>SocketDNS_T</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>ac9190fe07142a017f86dae46145cb2fd</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketCommon_setup_hints</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a47abb5d32959260cc8251419d652de1b</anchor>
      <arglist>(struct addrinfo *hints, int socktype, int flags)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketCommon_resolve_address</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a7fc66958f42deef2824a80188baf4534</anchor>
      <arglist>(const char *host, int port, const struct addrinfo *hints, struct addrinfo **res, Except_T exception_type, int socket_family, int use_exceptions)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketCommon_validate_port</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>ac849aa92d4bd728b61c37b6e63e2a804</anchor>
      <arglist>(int port, Except_T exception_type)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketCommon_validate_hostname</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>ab782ed7ac027b9d3c92cb4bef1b20b4a</anchor>
      <arglist>(const char *host, Except_T exception_type)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketCommon_normalize_wildcard_host</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a68b10ea8fcfd5f154b54d81a8000c827</anchor>
      <arglist>(const char *host)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketCommon_cache_endpoint</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>adfc31bff834af43e2a6ee2facd9951d4</anchor>
      <arglist>(Arena_T arena, const struct sockaddr *addr, socklen_t addrlen, char **addr_out, int *port_out)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketCommon_setcloexec</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>ad3eb3f6fe09b2b58693a7044631916d8</anchor>
      <arglist>(int fd, int enable)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketCommon_has_cloexec</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a5641340520942ec7ba2412f3d50f3f12</anchor>
      <arglist>(int fd)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketCommon_getoption_int</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a229de2f12f6169d6817195fb6490267d</anchor>
      <arglist>(int fd, int level, int optname, int *value, Except_T exception_type)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketCommon_getoption_timeval</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a5c81dabc2c964625f56fd02b0a4f9c93</anchor>
      <arglist>(int fd, int level, int optname, struct timeval *tv, Except_T exception_type)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketCommon_reverse_lookup</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a19eb14b9730f57df54eb5db71e1f5489</anchor>
      <arglist>(const struct sockaddr *addr, socklen_t addrlen, char *host, socklen_t hostlen, char *serv, socklen_t servlen, int flags, Except_T exception_type)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketCommon_parse_ip</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>af8d4b6a3c291b6ebbb73c13743304b42</anchor>
      <arglist>(const char *ip_str, int *family)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketCommon_cidr_match</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a5584b123bcf71749129a64c8312d0023</anchor>
      <arglist>(const char *ip_str, const char *cidr_str)</arglist>
    </member>
    <member kind="function">
      <type>SocketBase_T</type>
      <name>SocketCommon_new_base</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>ae9498d7bdb363435a4efce0f32011914</anchor>
      <arglist>(int domain, int type, int protocol)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketCommon_free_base</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>aaeb641ee1edaa618b8680babae9a98c6</anchor>
      <arglist>(SocketBase_T *base_ptr)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketCommon_set_option_int</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a0a2e7917d36f5e23eab8c1238433dfba</anchor>
      <arglist>(SocketBase_T base, int level, int optname, int value, Except_T exc_type)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketCommon_set_ttl</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a1eab30cecc7dae2a4c02efd95c5feae5</anchor>
      <arglist>(SocketBase_T base, int family, int ttl, Except_T exc_type)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketCommon_join_multicast</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a59068eaf0e0e017bb7492f2804a342b5</anchor>
      <arglist>(SocketBase_T base, const char *group, const char *interface, Except_T exc_type)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketCommon_leave_multicast</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a1c4923693d222515c078f6bcfbf9d0f5</anchor>
      <arglist>(SocketBase_T base, const char *group, const char *interface, Except_T exc_type)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketCommon_set_nonblock</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>aff179c5fc64896d364008582e755a8c4</anchor>
      <arglist>(SocketBase_T base, bool enable, Except_T exc_type)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketCommon_calculate_total_iov_len</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>abb36ce89ba4091b0a1bee148506d586b</anchor>
      <arglist>(const struct iovec *iov, int iovcnt)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketCommon_advance_iov</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a33af6b6698782c490ff383bb37c197e7</anchor>
      <arglist>(struct iovec *iov, int iovcnt, size_t bytes)</arglist>
    </member>
    <member kind="function">
      <type>struct iovec *</type>
      <name>SocketCommon_find_active_iov</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a0b9037b75f684ba9a4fda235b0bf0ca0</anchor>
      <arglist>(struct iovec *iov, int iovcnt, int *active_iovcnt)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketCommon_sync_iov_progress</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>aad5b4b92ce57c8168a7cb4462ee73d99</anchor>
      <arglist>(struct iovec *original, const struct iovec *copy, int iovcnt)</arglist>
    </member>
    <member kind="function">
      <type>struct iovec *</type>
      <name>SocketCommon_alloc_iov_copy</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a0ccd95f99962c7a6631b93bf9adfea4d</anchor>
      <arglist>(const struct iovec *iov, int iovcnt, Except_T exc_type)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketCommon_set_cloexec_fd</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>ac32f45a0216c1be50d0a411459bc426c</anchor>
      <arglist>(int fd, bool enable, Except_T exc_type)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketCommon_try_bind_address</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>aecff13e4edc3230da4141714e2e9297f</anchor>
      <arglist>(SocketBase_T base, const struct sockaddr *addr, socklen_t addrlen, Except_T exc_type)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketCommon_try_bind_resolved_addresses</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>ae257e8500385dffd243e9be383ade862</anchor>
      <arglist>(SocketBase_T base, struct addrinfo *res, int family, Except_T exc_type)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketCommon_handle_bind_error</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>ab28feafa0784876f732f4b79e03dcc8b</anchor>
      <arglist>(int err, const char *addr_str, Except_T exc_type)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketCommon_format_bind_error</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>ae1c533bda5b245453885e07e2a7b4e83</anchor>
      <arglist>(const char *host, int port)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketCommon_update_local_endpoint</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>ae2e1b3e6d9c494062a97bcc88a0e6a97</anchor>
      <arglist>(SocketBase_T base)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketCommon_get_socket_family</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>ab555c6739c1f1582b1d1aebfb008897e</anchor>
      <arglist>(SocketBase_T base)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketCommon_validate_host_not_null</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a552530543d655ce8871dcfe96a6675fb</anchor>
      <arglist>(const char *host, Except_T exception_type)</arglist>
    </member>
    <member kind="function">
      <type>struct addrinfo *</type>
      <name>SocketCommon_copy_addrinfo</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a1d98c31897344c8c2e6e6cde65045f09</anchor>
      <arglist>(const struct addrinfo *src)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketCommon_free_addrinfo</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a6c73595d93eeee7b21ad12b980770f5a</anchor>
      <arglist>(struct addrinfo *ai)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketCommon_timeouts_getdefaults</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>ad2318fb3606f6a71c2a11e247ff876d5</anchor>
      <arglist>(SocketTimeouts_T *timeouts)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketCommon_timeouts_setdefaults</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a98a87ba229cdf264bec87129ce8918f5</anchor>
      <arglist>(const SocketTimeouts_T *timeouts)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static int</type>
      <name>SocketCommon_check_bound_ipv4</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a37fb698963ebcc4f8f1d86d03b2ba3b7</anchor>
      <arglist>(const struct sockaddr_storage *addr)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static int</type>
      <name>SocketCommon_check_bound_ipv6</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a560dfe8bbb25d43c0ade5b295e20e1a7</anchor>
      <arglist>(const struct sockaddr_storage *addr)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static int</type>
      <name>SocketCommon_check_bound_unix</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a06bdea854665ec5ea7e4578b316092a4</anchor>
      <arglist>(const struct sockaddr_storage *addr)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static int</type>
      <name>SocketCommon_check_bound_by_family</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a7a0c8010b4e1cb65941a1c9be090742c</anchor>
      <arglist>(const struct sockaddr_storage *addr)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static void</type>
      <name>SocketLiveCount_increment</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a93d46dcf1a875ef525eb96d5f2271fb3</anchor>
      <arglist>(struct SocketLiveCount *tracker)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static void</type>
      <name>SocketLiveCount_decrement</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a433d928caa9de0b29ab9f2d48e166c5c</anchor>
      <arglist>(struct SocketLiveCount *tracker)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static int</type>
      <name>SocketLiveCount_get</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a02b16726c7750c470af8a59ffe041098</anchor>
      <arglist>(struct SocketLiveCount *tracker)</arglist>
    </member>
    <member kind="function">
      <type>SocketDNS_T</type>
      <name>SocketCommon_get_dns_resolver</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a70954c6e125769d15ffd6c3e31c89b75</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketCommon_set_dns_timeout</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a8df045c4215eb7538ad543cd9368864c</anchor>
      <arglist>(int timeout_ms)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketCommon_get_dns_timeout</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a4abf1412f29d6cec69326ca2a10e9e21</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>Socket_Failed</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a225f4a8fd657fd52a05146c6fc4f58b0</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketDgram_Failed</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a28354c49d1726c674932f420a57bb21d</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketCommon_Failed</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a4218ae116e8def59908f76fd1e9dbe3e</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>SocketTimeouts_T</type>
      <name>socket_default_timeouts</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a34162df185e6971334bb98c3c00a2ad0</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>pthread_mutex_t</type>
      <name>socket_default_timeouts_mutex</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a9c962297b30fb9c609c3170d508a8c12</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketDgram.h</name>
    <path>include/socket/</path>
    <filename>SocketDgram_8h.html</filename>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="SocketCommon_8h" name="SocketCommon.h" local="yes" import="no" module="no" objc="no">socket/SocketCommon.h</includes>
    <member kind="define">
      <type>#define</type>
      <name>T</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a0acb682b8260ab1c60b918599864e2e5</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketDgram_T *</type>
      <name>SocketDgram_T</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a178c1e09efbfdacb14740d3a0265721f</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>SocketDgram_T</type>
      <name>SocketDgram_new</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>ad6902c87ab5883f155dab2adfa950c52</anchor>
      <arglist>(int domain, int protocol)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDgram_free</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a020169c79640786afa4c36fd1dc965e4</anchor>
      <arglist>(SocketDgram_T *socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDgram_bind</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a0c81d9ef1d90e7ab34dd7286f13878ee</anchor>
      <arglist>(SocketDgram_T socket, const char *host, int port)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDgram_connect</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>abcb18c16142d3b5ef49bee08a96e15fa</anchor>
      <arglist>(SocketDgram_T socket, const char *host, int port)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketDgram_sendto</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a08371cbf32cb15528b42e189f8267923</anchor>
      <arglist>(SocketDgram_T socket, const void *buf, size_t len, const char *host, int port)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketDgram_recvfrom</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>ada4b76edaec59a44eb5bc959e6948d3f</anchor>
      <arglist>(SocketDgram_T socket, void *buf, size_t len, char *host, size_t host_len, int *port)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketDgram_send</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a08b2ab199a5c50a654683ba1ddb4d004</anchor>
      <arglist>(SocketDgram_T socket, const void *buf, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketDgram_recv</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>af832ef8734ab4dfb43ad639470461bda</anchor>
      <arglist>(SocketDgram_T socket, void *buf, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketDgram_sendall</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>adc08ada68a6f9a6922d4e2b0b8f4c081</anchor>
      <arglist>(SocketDgram_T socket, const void *buf, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketDgram_recvall</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>af96de127ecced1b5d8166e6a039e664c</anchor>
      <arglist>(SocketDgram_T socket, void *buf, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketDgram_sendv</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a2527bddec3459405a6a989de06727a2f</anchor>
      <arglist>(SocketDgram_T socket, const struct iovec *iov, int iovcnt)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketDgram_recvv</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a485908b4ff4a79f514f8e86ec6030107</anchor>
      <arglist>(SocketDgram_T socket, struct iovec *iov, int iovcnt)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketDgram_sendvall</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>aa208c4a07e76579c3e924ee31ea02777</anchor>
      <arglist>(SocketDgram_T socket, const struct iovec *iov, int iovcnt)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketDgram_recvvall</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a31fd826092fb6b9c1a3b11953568f2d6</anchor>
      <arglist>(SocketDgram_T socket, struct iovec *iov, int iovcnt)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDgram_setnonblocking</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a1817a8561af1801a9baa7630bc277ce6</anchor>
      <arglist>(SocketDgram_T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDgram_setreuseaddr</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a74995a7164d93c4e958da6642e0f317d</anchor>
      <arglist>(SocketDgram_T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDgram_setreuseport</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a9770b3c571ac6a900071db266a632816</anchor>
      <arglist>(SocketDgram_T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDgram_setbroadcast</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a637a1a778f293e4843f2355a9299d381</anchor>
      <arglist>(SocketDgram_T socket, int enable)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDgram_joinmulticast</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>ae25dbfe6a79cb46494ec438accb53db0</anchor>
      <arglist>(SocketDgram_T socket, const char *group, const char *interface)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDgram_leavemulticast</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a53cb8e627cf35e3d0c6db85e3bc33bab</anchor>
      <arglist>(SocketDgram_T socket, const char *group, const char *interface)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDgram_setttl</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a22d94185a6ccf28eceb98d69240ba3d2</anchor>
      <arglist>(SocketDgram_T socket, int ttl)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDgram_settimeout</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>afe579d108c83517ff9ceeac750139bc4</anchor>
      <arglist>(SocketDgram_T socket, int timeout_sec)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDgram_gettimeout</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a99243c75f546aab2534b529611b647f8</anchor>
      <arglist>(SocketDgram_T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDgram_getbroadcast</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>ae6c2bde38c3a7addb7cfffe98a253f60</anchor>
      <arglist>(SocketDgram_T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDgram_getttl</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a6b91970d4ffe2a7162c4104b0b6de78f</anchor>
      <arglist>(SocketDgram_T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDgram_getrcvbuf</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>ab0dd532f19eef5d8220480e06cc3a7db</anchor>
      <arglist>(SocketDgram_T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDgram_getsndbuf</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>af54f02197f8c0dc53fbdf333d476aae2</anchor>
      <arglist>(SocketDgram_T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDgram_isconnected</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a73455982ede6d44649f85adb25c4bda2</anchor>
      <arglist>(SocketDgram_T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDgram_isbound</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a06d3085b3b7287330e8cb49d6d9a4da1</anchor>
      <arglist>(SocketDgram_T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDgram_fd</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a54e91e6824df0c114a5e6a4d79e5c6fb</anchor>
      <arglist>(const SocketDgram_T socket)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketDgram_getlocaladdr</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a9822234959be9508363bb3c0f2bd47b7</anchor>
      <arglist>(const SocketDgram_T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDgram_getlocalport</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a8b2685e6ad39d1c2fc16df7234f7a87a</anchor>
      <arglist>(const SocketDgram_T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDgram_setcloexec</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>acc7a0ae08dfe973bee1067aa4a6869d2</anchor>
      <arglist>(SocketDgram_T socket, int enable)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDgram_debug_live_count</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a0e8f0a454d58b2ff87878e39960c9187</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketDgram_Failed</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a28354c49d1726c674932f420a57bb21d</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketHappyEyeballs.h</name>
    <path>include/socket/</path>
    <filename>SocketHappyEyeballs_8h.html</filename>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="SocketDNS_8h" name="SocketDNS.h" local="yes" import="no" module="no" objc="no">dns/SocketDNS.h</includes>
    <includes id="SocketPoll_8h" name="SocketPoll.h" local="yes" import="no" module="no" objc="no">poll/SocketPoll.h</includes>
    <includes id="Socket_8h" name="Socket.h" local="yes" import="no" module="no" objc="no">socket/Socket.h</includes>
    <class kind="struct">SocketHE_Config_T</class>
    <member kind="define">
      <type>#define</type>
      <name>T</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>a0acb682b8260ab1c60b918599864e2e5</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_HE_DEFAULT_FIRST_ATTEMPT_DELAY_MS</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>a015f1e24903699e20cea8af2bd44b781</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_HE_DEFAULT_ATTEMPT_TIMEOUT_MS</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>a66b65910ea1f4b358406d1fb9add485e</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_HE_DEFAULT_TOTAL_TIMEOUT_MS</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>a1400e0f9bd9e1de9d861c5ebfab5a877</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_HE_DEFAULT_DNS_TIMEOUT_MS</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>a0eca938e489f47d663007b6c0a7ab18f</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_HE_DEFAULT_MAX_ATTEMPTS</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>ac03b01e1dccf0fd3b0c78d26e4343646</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_HE_SYNC_POLL_INTERVAL_MS</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>a869ed228765bfcb7b4aab39b7cfc8c9d</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_HE_PORT_STR_SIZE</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>a07e470dce144233028bfd6d2193e8c03</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketHE_T *</type>
      <name>SocketHE_T</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>aa6c35b0180840e5c2f9fe45cefbae03d</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketHE_State</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>ac1b193256ec44f27e6f0f307b0c2e524</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HE_STATE_IDLE</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>ac1b193256ec44f27e6f0f307b0c2e524a12a52375165d28d6f3de5737a90c9f97</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HE_STATE_RESOLVING</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>ac1b193256ec44f27e6f0f307b0c2e524ab70cde7846b5284942af2d54f407df8e</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HE_STATE_CONNECTING</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>ac1b193256ec44f27e6f0f307b0c2e524a710fbd21ce364cf129054158e14106f2</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HE_STATE_CONNECTED</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>ac1b193256ec44f27e6f0f307b0c2e524afc61138380fa654235b963249af25d21</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HE_STATE_FAILED</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>ac1b193256ec44f27e6f0f307b0c2e524a4c6d8bc45fa1b7e19329162553fa9519</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>HE_STATE_CANCELLED</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>ac1b193256ec44f27e6f0f307b0c2e524a888ca7f61cc029908d4ef63b7ca96bd8</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>Socket_T</type>
      <name>SocketHappyEyeballs_connect</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>a5ef2e9ba01aa72f8a3ae864a1ba58bc3</anchor>
      <arglist>(const char *host, int port, const SocketHE_Config_T *config)</arglist>
    </member>
    <member kind="function">
      <type>SocketHE_T</type>
      <name>SocketHappyEyeballs_start</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>aac613520b1e674db06e60155150fef63</anchor>
      <arglist>(SocketDNS_T dns, SocketPoll_T poll, const char *host, int port, const SocketHE_Config_T *config)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHappyEyeballs_poll</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>a0a9452621088791eecef4112e36e4176</anchor>
      <arglist>(SocketHE_T he)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHappyEyeballs_process</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>a84e7ceec1f0f61c40664e76db29336de</anchor>
      <arglist>(SocketHE_T he)</arglist>
    </member>
    <member kind="function">
      <type>Socket_T</type>
      <name>SocketHappyEyeballs_result</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>aeedc2998806b4e465a999688333bae1d</anchor>
      <arglist>(SocketHE_T he)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHappyEyeballs_cancel</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>ae3383dd7df82083ec8d7f72fbae76cb5</anchor>
      <arglist>(SocketHE_T he)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHappyEyeballs_free</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>a5426942471b0a00d69094f1c8787523f</anchor>
      <arglist>(SocketHE_T *he)</arglist>
    </member>
    <member kind="function">
      <type>SocketHE_State</type>
      <name>SocketHappyEyeballs_state</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>a3307a26e1e23ff4be5d2e33895e6ae79</anchor>
      <arglist>(SocketHE_T he)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketHappyEyeballs_error</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>afd216882131853124a2894e7aed8b039</anchor>
      <arglist>(SocketHE_T he)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketHappyEyeballs_config_defaults</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>a3a5b3e45e53cfda16c76fec1cd4fd637</anchor>
      <arglist>(SocketHE_Config_T *config)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketHappyEyeballs_next_timeout_ms</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>a120f34eb8ef4b3f902a029b800577663</anchor>
      <arglist>(SocketHE_T he)</arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketHE_Failed</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>a2189771ae05195653ab16170d72a251d</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketIO.h</name>
    <path>include/socket/</path>
    <filename>SocketIO_8h.html</filename>
    <includes id="Socket_8h" name="Socket.h" local="yes" import="no" module="no" objc="no">socket/Socket.h</includes>
    <member kind="define">
      <type>#define</type>
      <name>T</name>
      <anchorfile>SocketIO_8h.html</anchorfile>
      <anchor>a0acb682b8260ab1c60b918599864e2e5</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>socket_send_internal</name>
      <anchorfile>SocketIO_8h.html</anchorfile>
      <anchor>ad65971e86ea8dcbaa79e4e457612d3a6</anchor>
      <arglist>(Socket_T socket, const void *buf, size_t len, int flags)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>socket_recv_internal</name>
      <anchorfile>SocketIO_8h.html</anchorfile>
      <anchor>a12c16a6d184c96f82dd1185d315f29e2</anchor>
      <arglist>(Socket_T socket, void *buf, size_t len, int flags)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>socket_sendv_internal</name>
      <anchorfile>SocketIO_8h.html</anchorfile>
      <anchor>a714a501a951663d0248972ef6cc75818</anchor>
      <arglist>(Socket_T socket, const struct iovec *iov, int iovcnt, int flags)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>socket_recvv_internal</name>
      <anchorfile>SocketIO_8h.html</anchorfile>
      <anchor>aa7fc21bc639d4077480b1d2b7c2bef7e</anchor>
      <arglist>(Socket_T socket, struct iovec *iov, int iovcnt, int flags)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>socket_is_tls_enabled</name>
      <anchorfile>SocketIO_8h.html</anchorfile>
      <anchor>abc70395a3d965153d4502752c496544e</anchor>
      <arglist>(const Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>socket_tls_want_read</name>
      <anchorfile>SocketIO_8h.html</anchorfile>
      <anchor>a665b41107ebf850f631386135fa58791</anchor>
      <arglist>(const Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>socket_tls_want_write</name>
      <anchorfile>SocketIO_8h.html</anchorfile>
      <anchor>ae7a7fe487c65b17fdea95a118bc98a97</anchor>
      <arglist>(const Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>socket_handle_ssl_error</name>
      <anchorfile>SocketIO_8h.html</anchorfile>
      <anchor>a92f7b61974c6adb4ac454b4fb671c6b8</anchor>
      <arglist>(Socket_T socket, SSL *ssl, int ssl_result)</arglist>
    </member>
    <member kind="function">
      <type>SSL *</type>
      <name>socket_get_ssl</name>
      <anchorfile>SocketIO_8h.html</anchorfile>
      <anchor>a326db6a48e839e56bd1599fc3a651723</anchor>
      <arglist>(Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>SSL *</type>
      <name>socket_validate_tls_ready</name>
      <anchorfile>SocketIO_8h.html</anchorfile>
      <anchor>a10ddc2a7b61b559013a79f7d1297d409</anchor>
      <arglist>(Socket_T socket)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static int</type>
      <name>socketio_is_wouldblock</name>
      <anchorfile>SocketIO_8h.html</anchorfile>
      <anchor>acc6b10100f449aef91c884fcebc9f9a5</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static int</type>
      <name>socketio_is_connection_closed_send</name>
      <anchorfile>SocketIO_8h.html</anchorfile>
      <anchor>a74bde3935e0a14d633eb374dada531d1</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function" static="yes">
      <type>static int</type>
      <name>socketio_is_connection_closed_recv</name>
      <anchorfile>SocketIO_8h.html</anchorfile>
      <anchor>a9ed3e966870af6d524f8956253594ef4</anchor>
      <arglist>(void)</arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketProxy.h</name>
    <path>include/socket/</path>
    <filename>SocketProxy_8h.html</filename>
    <includes id="Arena_8h" name="Arena.h" local="yes" import="no" module="no" objc="no">core/Arena.h</includes>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="SocketDNS_8h" name="SocketDNS.h" local="yes" import="no" module="no" objc="no">dns/SocketDNS.h</includes>
    <includes id="SocketPoll_8h" name="SocketPoll.h" local="yes" import="no" module="no" objc="no">poll/SocketPoll.h</includes>
    <includes id="Socket_8h" name="Socket.h" local="yes" import="no" module="no" objc="no">socket/Socket.h</includes>
    <includes id="SocketTLSContext_8h" name="SocketTLSContext.h" local="yes" import="no" module="no" objc="no">tls/SocketTLSContext.h</includes>
    <class kind="struct">SocketProxy_Config</class>
    <member kind="define">
      <type>#define</type>
      <name>T</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>a0acb682b8260ab1c60b918599864e2e5</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_PROXY_DEFAULT_CONNECT_TIMEOUT_MS</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>a6b08f5d67aab6be5b659223ae32a45f0</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_PROXY_DEFAULT_HANDSHAKE_TIMEOUT_MS</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>a9f89412ba3bf491edcac4617c03dd39b</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_PROXY_MAX_HOSTNAME_LEN</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>a8eab241f263ed3b03ed6071c87c0b3e2</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_PROXY_MAX_USERNAME_LEN</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>a42ca2ffbfb0de8352e90cf75fc40fc65</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_PROXY_MAX_PASSWORD_LEN</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>a3e1be1cb4883cf9ffb8740802a13e80d</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_PROXY_DEFAULT_SOCKS_PORT</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>ac5d2dd3c09cef803b630431503f55972</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_PROXY_DEFAULT_HTTP_PORT</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>abc8fb5cad208dd7c9fa2a09021a1b514</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_PROXY_DEFAULT_HTTPS_PORT</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>a7f65090a7ed6c0d2e6168714dfe0b2c7</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketHTTP_Headers *</type>
      <name>SocketHTTP_Headers_T</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>af1f6772bf122ad6e2e90639b2877754f</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketProxy_Conn_T *</type>
      <name>SocketProxy_Conn_T</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>a7f08cbaf58cda2bfda0fa9ce8cc28007</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketProxyType</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>aaa33f7bdae951cc7b53a2fb049e89132</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_PROXY_NONE</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>aaa33f7bdae951cc7b53a2fb049e89132af06430c3c302df7671528157c73c4e0b</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_PROXY_HTTP</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>aaa33f7bdae951cc7b53a2fb049e89132a687548e806513e256fcf2534ddf9cbd6</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_PROXY_HTTPS</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>aaa33f7bdae951cc7b53a2fb049e89132a7b26d4906e2233ed613ea9b00d402abb</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_PROXY_SOCKS4</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>aaa33f7bdae951cc7b53a2fb049e89132ab789e6a114edbf61a4df42d8240a51c1</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_PROXY_SOCKS4A</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>aaa33f7bdae951cc7b53a2fb049e89132a8d530f085d00940efe69768b8cf374c6</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_PROXY_SOCKS5</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>aaa33f7bdae951cc7b53a2fb049e89132a65e12b32adeb0ad03fc8a1031423c21f</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_PROXY_SOCKS5H</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>aaa33f7bdae951cc7b53a2fb049e89132ae87246b34aba7c6500664e7be36d8820</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketProxy_Result</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>ae980e6a437316380a792464ce32a595e</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>PROXY_OK</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>ae980e6a437316380a792464ce32a595ea6493782f06c64d4240b03ebc37d10754</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>PROXY_IN_PROGRESS</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>ae980e6a437316380a792464ce32a595eac8e28cc62a3365a1732c669edf48ede1</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>PROXY_ERROR</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>ae980e6a437316380a792464ce32a595ea6e9669d107d6f667fc65e467f8ee6424</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>PROXY_ERROR_CONNECT</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>ae980e6a437316380a792464ce32a595ea65f9d23b989fea3c0578f03bf69dcbc3</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>PROXY_ERROR_AUTH_REQUIRED</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>ae980e6a437316380a792464ce32a595eaae7c553c156d0bc0673280b02c1ed7a0</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>PROXY_ERROR_AUTH_FAILED</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>ae980e6a437316380a792464ce32a595eaeaa9baf16d7658f8553f19fc887ba82f</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>PROXY_ERROR_FORBIDDEN</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>ae980e6a437316380a792464ce32a595ea9519d7d7a824bbb8527737bb565a8d26</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>PROXY_ERROR_HOST_UNREACHABLE</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>ae980e6a437316380a792464ce32a595ea79f3625d5f0c085c05bd00e79c7b4878</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>PROXY_ERROR_NETWORK_UNREACHABLE</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>ae980e6a437316380a792464ce32a595ea2415989b5d247d71236686d18b1eeb9d</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>PROXY_ERROR_CONNECTION_REFUSED</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>ae980e6a437316380a792464ce32a595ea533fd840f7baa208f63174952243f28e</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>PROXY_ERROR_TTL_EXPIRED</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>ae980e6a437316380a792464ce32a595ea942a19cc1c6152dba3f615c94c8190b9</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>PROXY_ERROR_PROTOCOL</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>ae980e6a437316380a792464ce32a595ea743f6cf01e958374a7cae9cce8960552</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>PROXY_ERROR_UNSUPPORTED</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>ae980e6a437316380a792464ce32a595ea9acb784df31ca1f49007e0dbec3899ae</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>PROXY_ERROR_TIMEOUT</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>ae980e6a437316380a792464ce32a595ea6f79c29997ae1e1063f0f4c079e42128</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>PROXY_ERROR_CANCELLED</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>ae980e6a437316380a792464ce32a595ea15fe5e5fc15227e92086cc3c76e468d8</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketProxy_State</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>af9f1c72bfcb303aa9ee5dae6d903b9be</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>PROXY_STATE_IDLE</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>af9f1c72bfcb303aa9ee5dae6d903b9beacba676410c89ad0ae99458a19e8ee240</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>PROXY_STATE_CONNECTING_PROXY</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>af9f1c72bfcb303aa9ee5dae6d903b9beaa138c1108967670476f171409859906c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>PROXY_STATE_TLS_TO_PROXY</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>af9f1c72bfcb303aa9ee5dae6d903b9bea5e6d9c22e92e5264322ca6229d697200</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>PROXY_STATE_HANDSHAKE_SEND</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>af9f1c72bfcb303aa9ee5dae6d903b9beaec64bc3a56940bb0b95bd533d3f575d1</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>PROXY_STATE_HANDSHAKE_RECV</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>af9f1c72bfcb303aa9ee5dae6d903b9bea6692865ae9a1d5913dc9b11bb8ecc053</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>PROXY_STATE_AUTH_SEND</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>af9f1c72bfcb303aa9ee5dae6d903b9bea33e574e11d2391e830bb512b5f4cba10</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>PROXY_STATE_AUTH_RECV</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>af9f1c72bfcb303aa9ee5dae6d903b9beaebe4dde2fe06562c2e05cbe78cdf75d7</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>PROXY_STATE_CONNECTED</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>af9f1c72bfcb303aa9ee5dae6d903b9bea93b0009c07bfe02286b9151523792043</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>PROXY_STATE_FAILED</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>af9f1c72bfcb303aa9ee5dae6d903b9bea002d0ae5e052492f5a003f240cce1a07</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>PROXY_STATE_CANCELLED</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>af9f1c72bfcb303aa9ee5dae6d903b9beaefd3cf70c9901425e0b6aa6a8325b71a</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketProxy_config_defaults</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>a197242786615adf218d849747bc0fd67</anchor>
      <arglist>(SocketProxy_Config *config)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketProxy_parse_url</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>ae16c20e1d43f38171ccaad8408598490</anchor>
      <arglist>(const char *url, SocketProxy_Config *config, Arena_T arena)</arglist>
    </member>
    <member kind="function">
      <type>Socket_T</type>
      <name>SocketProxy_connect</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>aad72c8e58d88ee4bbc975c9163266ef0</anchor>
      <arglist>(const SocketProxy_Config *proxy, const char *target_host, int target_port)</arglist>
    </member>
    <member kind="function">
      <type>SocketProxy_Result</type>
      <name>SocketProxy_tunnel</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>a42d87dba201e99194eec8df1a9522516</anchor>
      <arglist>(Socket_T socket, const SocketProxy_Config *proxy, const char *target_host, int target_port)</arglist>
    </member>
    <member kind="function">
      <type>SocketProxy_Conn_T</type>
      <name>SocketProxy_Conn_start</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>a5f6fd1cde0a54b41805862ce002f6f97</anchor>
      <arglist>(SocketDNS_T dns, SocketPoll_T poll, const SocketProxy_Config *proxy, const char *target_host, int target_port)</arglist>
    </member>
    <member kind="function">
      <type>SocketProxy_Conn_T</type>
      <name>SocketProxy_Conn_new</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>a6d17fac3f6b21b9905aa7c4b0d7d47f7</anchor>
      <arglist>(const SocketProxy_Config *proxy, const char *target_host, int target_port)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketProxy_Conn_poll</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>ac12fc736c9952313a4846dd50380bc3f</anchor>
      <arglist>(SocketProxy_Conn_T conn)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketProxy_Conn_process</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>af45ecd7d9e7c6214e6bfcc6b2a42f977</anchor>
      <arglist>(SocketProxy_Conn_T conn)</arglist>
    </member>
    <member kind="function">
      <type>Socket_T</type>
      <name>SocketProxy_Conn_socket</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>aff1d539486b8b250489938c4b71c89a9</anchor>
      <arglist>(SocketProxy_Conn_T conn)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketProxy_Conn_cancel</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>a2853a36e933b9ac3803173169b1b159e</anchor>
      <arglist>(SocketProxy_Conn_T conn)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketProxy_Conn_free</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>afee164cf3e979f5cfe745a33366812d9</anchor>
      <arglist>(SocketProxy_Conn_T *conn)</arglist>
    </member>
    <member kind="function">
      <type>SocketProxy_State</type>
      <name>SocketProxy_Conn_state</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>a1ee518c3b280abda4ae21871fae53040</anchor>
      <arglist>(SocketProxy_Conn_T conn)</arglist>
    </member>
    <member kind="function">
      <type>SocketProxy_Result</type>
      <name>SocketProxy_Conn_result</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>af191ce0cae571b057d5ea278392bdf24</anchor>
      <arglist>(SocketProxy_Conn_T conn)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketProxy_Conn_error</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>a93a495a98a7efa7ecc9d42ce838d4a3e</anchor>
      <arglist>(SocketProxy_Conn_T conn)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketProxy_Conn_fd</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>a9d1139d24bcabc22e6e2b07762e8f753</anchor>
      <arglist>(SocketProxy_Conn_T conn)</arglist>
    </member>
    <member kind="function">
      <type>unsigned</type>
      <name>SocketProxy_Conn_events</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>a8d7492a46210e78249073e289c556ea8</anchor>
      <arglist>(SocketProxy_Conn_T conn)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketProxy_Conn_next_timeout_ms</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>af64af0e87ee1735152783f2b7fd132c9</anchor>
      <arglist>(SocketProxy_Conn_T conn)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketProxy_result_string</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>a2a0ac262c4e03ed00c5eeb2aa8d210bd</anchor>
      <arglist>(SocketProxy_Result result)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketProxy_state_string</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>a6340dd7fd6f41c692c0a2f770dbd5877</anchor>
      <arglist>(SocketProxy_State state)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketProxy_type_string</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>a50b7d727085605b2f6bc620118462b13</anchor>
      <arglist>(SocketProxyType type)</arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketProxy_Failed</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>a8c1385083c8f3a50e20e1ce11faec7b1</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketReconnect.h</name>
    <path>include/socket/</path>
    <filename>SocketReconnect_8h.html</filename>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="Socket_8h" name="Socket.h" local="yes" import="no" module="no" objc="no">socket/Socket.h</includes>
    <class kind="struct">SocketReconnect_Policy_T</class>
    <member kind="define">
      <type>#define</type>
      <name>T</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>a0acb682b8260ab1c60b918599864e2e5</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_RECONNECT_DEFAULT_INITIAL_DELAY_MS</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>a85a14030855898b980c0f942cb15933b</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_RECONNECT_DEFAULT_MAX_DELAY_MS</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>a8f392ce1becc811dd7cb1fa23a2c7976</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_RECONNECT_DEFAULT_MULTIPLIER</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>a8b3825c4901d297714102179ce6d54bc</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_RECONNECT_DEFAULT_JITTER</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>af4fd623aa776027105e0a5453afcd420</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_RECONNECT_DEFAULT_MAX_ATTEMPTS</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>a6a4a1e6545095e28e978e647dc704c75</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_RECONNECT_DEFAULT_CIRCUIT_THRESHOLD</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>a30f98f14fbe5283f91ea4325d676a3e7</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_RECONNECT_DEFAULT_CIRCUIT_RESET_MS</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>a854271c42b01950918a698c6360f997c</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_RECONNECT_DEFAULT_HEALTH_INTERVAL_MS</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>add9fbe38d51abd1d4be51ae9a1c60be6</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_RECONNECT_DEFAULT_HEALTH_TIMEOUT_MS</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>a4e5f9eafa549522bc2f7e9fdf4cbbaf1</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketReconnect_T *</type>
      <name>SocketReconnect_T</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>a58c9f07cd1532f285c63cb039c548eed</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>void(*</type>
      <name>SocketReconnect_Callback</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>a0d4cc030dc9989344d20a170b6410220</anchor>
      <arglist>)(SocketReconnect_T conn, SocketReconnect_State old_state, SocketReconnect_State new_state, void *userdata)</arglist>
    </member>
    <member kind="typedef">
      <type>int(*</type>
      <name>SocketReconnect_HealthCheck</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>ae24b576ed367f734f434ef30ad8386c3</anchor>
      <arglist>)(SocketReconnect_T conn, Socket_T socket, int timeout_ms, void *userdata)</arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketReconnect_State</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>ab0f7f9254ebc5d681f058d6b2c26f548</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>RECONNECT_DISCONNECTED</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>ab0f7f9254ebc5d681f058d6b2c26f548aad8113419cbfb25276d1139df9831611</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>RECONNECT_CONNECTING</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>ab0f7f9254ebc5d681f058d6b2c26f548aa8ce7a5b74cbcbbaf91d733e39ec0c07</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>RECONNECT_CONNECTED</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>ab0f7f9254ebc5d681f058d6b2c26f548adb2277c5ef340a4d2f2e3ed98525ebe1</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>RECONNECT_BACKOFF</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>ab0f7f9254ebc5d681f058d6b2c26f548a32ae482a193f2b27c73f934837a458a6</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>RECONNECT_CIRCUIT_OPEN</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>ab0f7f9254ebc5d681f058d6b2c26f548a2bf78e833dbbbf5bc17e6098ba8d55db</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>SocketReconnect_T</type>
      <name>SocketReconnect_new</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>a2064741bf60283ac3315823128fa2082</anchor>
      <arglist>(const char *host, int port, const SocketReconnect_Policy_T *policy, SocketReconnect_Callback callback, void *userdata)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketReconnect_free</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>a9d8b4dd4a693ba7acb20ff8e78defe91</anchor>
      <arglist>(SocketReconnect_T *conn)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketReconnect_connect</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>a2669844f3ad8a19649f2bc204eee8401</anchor>
      <arglist>(SocketReconnect_T conn)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketReconnect_disconnect</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>aa3794b861d4dad021064bae97ea12e78</anchor>
      <arglist>(SocketReconnect_T conn)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketReconnect_reset</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>ace6fc797f7fe9c6cd3319f540db4b672</anchor>
      <arglist>(SocketReconnect_T conn)</arglist>
    </member>
    <member kind="function">
      <type>Socket_T</type>
      <name>SocketReconnect_socket</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>a4c91b5c376059d9c35d2623cbc6bd7b5</anchor>
      <arglist>(SocketReconnect_T conn)</arglist>
    </member>
    <member kind="function">
      <type>SocketReconnect_State</type>
      <name>SocketReconnect_state</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>ac2a144f4c67fde49d88d0a53aa528c14</anchor>
      <arglist>(SocketReconnect_T conn)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketReconnect_isconnected</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>a490043a4bfaba8214f5d10a3c7b956de</anchor>
      <arglist>(SocketReconnect_T conn)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketReconnect_attempts</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>ae798b2ae7451bbc7247fe71481190ee6</anchor>
      <arglist>(SocketReconnect_T conn)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketReconnect_failures</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>a9f80ff5ac565edacc7b5c08a263ec73d</anchor>
      <arglist>(SocketReconnect_T conn)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketReconnect_pollfd</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>aa2db0dea41db5bb5a7efeec947323da8</anchor>
      <arglist>(SocketReconnect_T conn)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketReconnect_process</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>a4ca4375d521b1eddcc4cf3f75fe3b538</anchor>
      <arglist>(SocketReconnect_T conn)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketReconnect_next_timeout_ms</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>af5bf725fe34ae1de58a3ee05fbe270fd</anchor>
      <arglist>(SocketReconnect_T conn)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketReconnect_tick</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>a8dd2c1fe7147188da2be29f7623d2822</anchor>
      <arglist>(SocketReconnect_T conn)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketReconnect_set_health_check</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>acf257c08816a36a97c02b32e034c0ea0</anchor>
      <arglist>(SocketReconnect_T conn, SocketReconnect_HealthCheck check)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketReconnect_policy_defaults</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>a4bc781f13408c70bfe9d28148ac87212</anchor>
      <arglist>(SocketReconnect_Policy_T *policy)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketReconnect_send</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>ae1f6cbe69ac37f9bae1efccfe98538ee</anchor>
      <arglist>(SocketReconnect_T conn, const void *buf, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketReconnect_recv</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>a92485113993efb3a1302bbcb8f57a908</anchor>
      <arglist>(SocketReconnect_T conn, void *buf, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketReconnect_state_name</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>a0678924e4ecd0f43e1385d2e0b5354d4</anchor>
      <arglist>(SocketReconnect_State state)</arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketReconnect_Failed</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>a3dc308919d4ccef64b7674cae246d9c0</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketWS.h</name>
    <path>include/socket/</path>
    <filename>SocketWS_8h.html</filename>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="SocketHTTP_8h" name="SocketHTTP.h" local="yes" import="no" module="no" objc="no">http/SocketHTTP.h</includes>
    <includes id="Socket_8h" name="Socket.h" local="yes" import="no" module="no" objc="no">socket/Socket.h</includes>
    <class kind="struct">SocketWS_Config</class>
    <class kind="struct">SocketWS_Frame</class>
    <class kind="struct">SocketWS_Message</class>
    <member kind="define">
      <type>#define</type>
      <name>T</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a0acb682b8260ab1c60b918599864e2e5</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketPoll_T *</type>
      <name>SocketPoll_T</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>af9e4be8bc025aedb61cc0b77e8926312</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketWS *</type>
      <name>SocketWS_T</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a62eac457c36851d5e4a184e1a5602555</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketWS_Opcode</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a174740343c7f920060f8640f23600c7b</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_OPCODE_CONTINUATION</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a174740343c7f920060f8640f23600c7ba414ed52e10fc98a59c9fbadc896b3ea3</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_OPCODE_TEXT</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a174740343c7f920060f8640f23600c7bab290478c848bb099a2fefe6c7b633558</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_OPCODE_BINARY</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a174740343c7f920060f8640f23600c7ba01f825533b31920937ba5ddb2315a361</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_OPCODE_CLOSE</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a174740343c7f920060f8640f23600c7ba847b054f16b331a8a701b7e76255d8e5</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_OPCODE_PING</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a174740343c7f920060f8640f23600c7ba2e1dad19209b2641fcb2d12025651539</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_OPCODE_PONG</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a174740343c7f920060f8640f23600c7ba809eaa105785fd07440fa833f602469c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketWS_CloseCode</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a386c437e966aeaeb091d1d81c0e77b13</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_CLOSE_NORMAL</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a386c437e966aeaeb091d1d81c0e77b13a297d5e27c1ad4b7c6660b005308a5f30</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_CLOSE_GOING_AWAY</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a386c437e966aeaeb091d1d81c0e77b13a9bb565620ebf9a5c79afa6281a253b6d</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_CLOSE_PROTOCOL_ERROR</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a386c437e966aeaeb091d1d81c0e77b13aaf641b4eedfe849aeed35a84f61709bf</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_CLOSE_UNSUPPORTED_DATA</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a386c437e966aeaeb091d1d81c0e77b13a2852358b8d5151feda017ab29972f16e</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_CLOSE_NO_STATUS</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a386c437e966aeaeb091d1d81c0e77b13a859b46a0f5a7a29e664a22a1c1c86919</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_CLOSE_ABNORMAL</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a386c437e966aeaeb091d1d81c0e77b13aa5b58d4bfbfbeb754edc424760ff4b04</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_CLOSE_INVALID_PAYLOAD</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a386c437e966aeaeb091d1d81c0e77b13a5fcad814a12fede092794145c328fb9f</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_CLOSE_POLICY_VIOLATION</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a386c437e966aeaeb091d1d81c0e77b13a35ac58f4457834de3faeb1fa7792366d</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_CLOSE_MESSAGE_TOO_BIG</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a386c437e966aeaeb091d1d81c0e77b13adbdae48a85dc5e937a163e01508001c6</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_CLOSE_MANDATORY_EXT</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a386c437e966aeaeb091d1d81c0e77b13a1f6f581ca2b8fc652c8ffb993fb8194a</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_CLOSE_INTERNAL_ERROR</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a386c437e966aeaeb091d1d81c0e77b13a5724188e50f92c13d3673f08ce69412a</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_CLOSE_SERVICE_RESTART</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a386c437e966aeaeb091d1d81c0e77b13a9af38cc3ecad679dcf15e666000dfa4b</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_CLOSE_TRY_AGAIN_LATER</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a386c437e966aeaeb091d1d81c0e77b13ae899716cd2fc4d8f76d4dad9889129e2</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_CLOSE_BAD_GATEWAY</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a386c437e966aeaeb091d1d81c0e77b13ac0935030c6af954b99019692f8757b1b</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_CLOSE_TLS_HANDSHAKE</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a386c437e966aeaeb091d1d81c0e77b13aceffd9fee405e4dee36e9596939ba5ec</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketWS_State</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>ab8b49607a661224d66bb264b1e597e2d</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_STATE_CONNECTING</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>ab8b49607a661224d66bb264b1e597e2da782bbde9b515882abdd6b712c127af31</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_STATE_OPEN</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>ab8b49607a661224d66bb264b1e597e2dab0325195f22aca5be7491a425f84808c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_STATE_CLOSING</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>ab8b49607a661224d66bb264b1e597e2daa3bafc31c6e8514011174ffeb2dd1eac</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_STATE_CLOSED</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>ab8b49607a661224d66bb264b1e597e2da4356293e46722d1fa27ca8624f62b296</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketWS_Role</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a9d14d3d0f1b05e44fcd74782107cbd94</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_ROLE_CLIENT</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a9d14d3d0f1b05e44fcd74782107cbd94adb564f62107e65c4ba508183929404d1</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_ROLE_SERVER</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a9d14d3d0f1b05e44fcd74782107cbd94afa4a0c78e19b98cca7f556560ca4061b</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketWS_Error</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>abd79199a60ad91cf785166f24f41101f</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_OK</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>abd79199a60ad91cf785166f24f41101fa8d6c24a81bab48a188c7f458bf6ecddb</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_ERROR</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>abd79199a60ad91cf785166f24f41101faa41b8e2f5c20dd621e69746820e10ecd</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_ERROR_HANDSHAKE</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>abd79199a60ad91cf785166f24f41101fa326cba4dbca2cd3fc40aa705e3c8c43c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_ERROR_PROTOCOL</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>abd79199a60ad91cf785166f24f41101fac3b45ed8d1cffbe97ae99ad9368edfec</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_ERROR_FRAME_TOO_LARGE</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>abd79199a60ad91cf785166f24f41101fad67cba0f02674ecdb494d3c897945304</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_ERROR_MESSAGE_TOO_LARGE</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>abd79199a60ad91cf785166f24f41101fa202edc337483e9a546142eeadae60afa</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_ERROR_INVALID_UTF8</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>abd79199a60ad91cf785166f24f41101fa276c19a5f29e2a5d3032eeebf7d54a8e</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_ERROR_COMPRESSION</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>abd79199a60ad91cf785166f24f41101fa7bb811cc75e39503c96e5e58f41e392f</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_ERROR_CLOSED</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>abd79199a60ad91cf785166f24f41101fa4b6bd8241f6074e7efa54cc113fce39c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_ERROR_WOULD_BLOCK</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>abd79199a60ad91cf785166f24f41101fad8bea1e89b1464f633c15cc454699761</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>WS_ERROR_TIMEOUT</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>abd79199a60ad91cf785166f24f41101fab7f48522858a5f62bb83f2102996daaf</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketWS_config_defaults</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>ac129f58e59f8b169f2c2a48a330fb176</anchor>
      <arglist>(SocketWS_Config *config)</arglist>
    </member>
    <member kind="function">
      <type>SocketWS_T</type>
      <name>SocketWS_client_new</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>acad45d5dbc4f2191ba5f732a1b648842</anchor>
      <arglist>(Socket_T socket, const char *host, const char *path, const SocketWS_Config *config)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketWS_is_upgrade</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>abd34fccaadaee0c043bbb1368c3d0673</anchor>
      <arglist>(const SocketHTTP_Request *request)</arglist>
    </member>
    <member kind="function">
      <type>SocketWS_T</type>
      <name>SocketWS_server_accept</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a29e02ecca2d5a1b78d0eaf2c08883960</anchor>
      <arglist>(Socket_T socket, const SocketHTTP_Request *request, const SocketWS_Config *config)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketWS_server_reject</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>ad6e400c85623f8603c5965d38b1a60e0</anchor>
      <arglist>(Socket_T socket, int status_code, const char *reason)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketWS_free</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>aa040ebe5bc5f2673b04b15091a45b944</anchor>
      <arglist>(SocketWS_T *ws)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketWS_handshake</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>acbbea030dbe9d643b7f8bd6c1656ff06</anchor>
      <arglist>(SocketWS_T ws)</arglist>
    </member>
    <member kind="function">
      <type>SocketWS_State</type>
      <name>SocketWS_state</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>aa40def588d31ab50126603fa720f83b0</anchor>
      <arglist>(SocketWS_T ws)</arglist>
    </member>
    <member kind="function">
      <type>Socket_T</type>
      <name>SocketWS_socket</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a00e6f2953f92843874cd7b6c3e363288</anchor>
      <arglist>(SocketWS_T ws)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketWS_selected_subprotocol</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a2a1ce264ad5e6d3cf25ce2442504aa20</anchor>
      <arglist>(SocketWS_T ws)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketWS_compression_enabled</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a02790d0b994d613324052794269b0e22</anchor>
      <arglist>(SocketWS_T ws)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketWS_send_text</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a4b8450a05502aaa70e88cdf14a73fa03</anchor>
      <arglist>(SocketWS_T ws, const char *data, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketWS_send_binary</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a1a8aff35f7c69172e0c2f9c0ec53abcb</anchor>
      <arglist>(SocketWS_T ws, const void *data, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketWS_ping</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a2be521a2fe8aa5eb5d30869905371a71</anchor>
      <arglist>(SocketWS_T ws, const void *data, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketWS_pong</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a3e17279abcb92810c8066f1813287334</anchor>
      <arglist>(SocketWS_T ws, const void *data, size_t len)</arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketWS_Failed</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a0fb92a65a798e17aca6df1cdba118067</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketWS_ProtocolError</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a8400199bb1b785111015ff06d16de370</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketWS_Closed</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a51caf3b6f8086dc6535fd843593dcbde</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketDTLS.h</name>
    <path>include/tls/</path>
    <filename>SocketDTLS_8h.html</filename>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="SocketDgram_8h" name="SocketDgram.h" local="yes" import="no" module="no" objc="no">socket/SocketDgram.h</includes>
    <member kind="typedef">
      <type>struct SocketDTLSContext_T *</type>
      <name>SocketDTLSContext_T</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>a05a015dd6cc639dd38a5853194c9002f</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>DTLSHandshakeState</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>a8e83c28a6ad188b97243c4b237ee075a</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>DTLS_HANDSHAKE_NOT_STARTED</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>a8e83c28a6ad188b97243c4b237ee075aac64c8906fdc9860f22cacc933593f01d</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>DTLS_HANDSHAKE_IN_PROGRESS</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>a8e83c28a6ad188b97243c4b237ee075aad8f8ad815c25bf8e696b02a71795f66d</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>DTLS_HANDSHAKE_WANT_READ</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>a8e83c28a6ad188b97243c4b237ee075aaa17434dadb8cec2cfe51d9437f6fdbd9</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>DTLS_HANDSHAKE_WANT_WRITE</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>a8e83c28a6ad188b97243c4b237ee075aad5e0e23bed76e7569444db7c50c38fc8</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>DTLS_HANDSHAKE_COOKIE_EXCHANGE</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>a8e83c28a6ad188b97243c4b237ee075aa206e6713dc03f89a32b4567221dedb78</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>DTLS_HANDSHAKE_COMPLETE</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>a8e83c28a6ad188b97243c4b237ee075aa11985350a6b101701d89412f26fdeba5</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>DTLS_HANDSHAKE_ERROR</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>a8e83c28a6ad188b97243c4b237ee075aa929e6faa551a280db427a04ae5ced133</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDTLS_enable</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>ad2f26460b23a711e0fa74605371cf127</anchor>
      <arglist>(SocketDgram_T socket, SocketDTLSContext_T ctx)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDTLS_set_peer</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>af742a2fb837173f6fd8d347e5bc1d1d3</anchor>
      <arglist>(SocketDgram_T socket, const char *host, int port)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDTLS_set_hostname</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>abf3857e3cea92190f4c6eca7a8418be3</anchor>
      <arglist>(SocketDgram_T socket, const char *hostname)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDTLS_set_mtu</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>a804d5dd4b27255e3c9c28c58a2914a18</anchor>
      <arglist>(SocketDgram_T socket, size_t mtu)</arglist>
    </member>
    <member kind="function">
      <type>DTLSHandshakeState</type>
      <name>SocketDTLS_handshake</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>a17e8bd79af2c5a20b5dbb9e8dff6f84c</anchor>
      <arglist>(SocketDgram_T socket)</arglist>
    </member>
    <member kind="function">
      <type>DTLSHandshakeState</type>
      <name>SocketDTLS_handshake_loop</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>a095bfc830b421398fbecacb1ac3d6755</anchor>
      <arglist>(SocketDgram_T socket, int timeout_ms)</arglist>
    </member>
    <member kind="function">
      <type>DTLSHandshakeState</type>
      <name>SocketDTLS_listen</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>a0e2af3b3ad31869d659162ea06cf667b</anchor>
      <arglist>(SocketDgram_T socket)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketDTLS_send</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>a9fe6acb926cc7fbc8c4f0239834b5460</anchor>
      <arglist>(SocketDgram_T socket, const void *buf, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketDTLS_recv</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>ac4fc033d5799456ce6d1b1417228c7e1</anchor>
      <arglist>(SocketDgram_T socket, void *buf, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketDTLS_sendto</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>a4e060f6143e7c9896452a6e0654041e5</anchor>
      <arglist>(SocketDgram_T socket, const void *buf, size_t len, const char *host, int port)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketDTLS_recvfrom</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>ac974bd84fcd68c06870530c11908170f</anchor>
      <arglist>(SocketDgram_T socket, void *buf, size_t len, char *host, size_t host_len, int *port)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketDTLS_get_cipher</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>a12039ba9c9513fbf9df6e02f997d09ab</anchor>
      <arglist>(SocketDgram_T socket)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketDTLS_get_version</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>a4651d3701fdc086051bc90cecb79b11e</anchor>
      <arglist>(SocketDgram_T socket)</arglist>
    </member>
    <member kind="function">
      <type>long</type>
      <name>SocketDTLS_get_verify_result</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>ad0e45780e041b9ddb58956d9f0fb20d1</anchor>
      <arglist>(SocketDgram_T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDTLS_is_session_reused</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>aeeca3aaa5a1e0f7fbb22b16a465421fd</anchor>
      <arglist>(SocketDgram_T socket)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketDTLS_get_alpn_selected</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>ae91ad38ad7d4a00961f342e3366d7097</anchor>
      <arglist>(SocketDgram_T socket)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketDTLS_get_mtu</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>a7752aae6c38da47f187f8d766b4ae12e</anchor>
      <arglist>(SocketDgram_T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDTLS_shutdown</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>ab42fd91bb31edaf15149d75920446a0a</anchor>
      <arglist>(SocketDgram_T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDTLS_is_shutdown</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>aad0b27539517934a510df081364e08ab</anchor>
      <arglist>(SocketDgram_T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDTLS_is_enabled</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>a861c0da7896b4275fb38ee2d0ac73af1</anchor>
      <arglist>(SocketDgram_T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDTLS_is_handshake_done</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>ae702a60aae194a098bdc6af32549f1ae</anchor>
      <arglist>(SocketDgram_T socket)</arglist>
    </member>
    <member kind="function">
      <type>DTLSHandshakeState</type>
      <name>SocketDTLS_get_last_state</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>a42abbf654fe23dd417b2115dc00590db</anchor>
      <arglist>(SocketDgram_T socket)</arglist>
    </member>
    <member kind="variable">
      <type>char</type>
      <name>dtls_error_buf</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>a98be42b85e655b670661ae1690f1c433</anchor>
      <arglist>[]</arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketDTLS_Failed</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>a083605c4d8e6ea5658b72883f8e41be9</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketDTLS_HandshakeFailed</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>adffbcee0cdd3e2ea80a6a03a73755085</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketDTLS_VerifyFailed</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>af1324e42b633182c01b0157ebfba0e9e</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketDTLS_CookieFailed</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>a69b6e30fa30bd7fe0a621d807796d73f</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketDTLS_TimeoutExpired</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>a9a2543bc8c6671e774391f4861d4fa5d</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketDTLS_ShutdownFailed</name>
      <anchorfile>SocketDTLS_8h.html</anchorfile>
      <anchor>a28d15a7e6fc136b5d542236ef27f0be6</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketDTLSConfig.h</name>
    <path>include/tls/</path>
    <filename>SocketDTLSConfig_8h.html</filename>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DTLS_MIN_VERSION</name>
      <anchorfile>SocketDTLSConfig_8h.html</anchorfile>
      <anchor>abc3e53580ef4039e6bd2b0453f1dec35</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DTLS_MAX_VERSION</name>
      <anchorfile>SocketDTLSConfig_8h.html</anchorfile>
      <anchor>a30edede1360b062e9c399fd7bb73daeb</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DTLS_CIPHERSUITES</name>
      <anchorfile>SocketDTLSConfig_8h.html</anchorfile>
      <anchor>a26d2482e8ab9e3023996ea54a1e2b93a</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DTLS_DEFAULT_MTU</name>
      <anchorfile>SocketDTLSConfig_8h.html</anchorfile>
      <anchor>a3752ff3ec87ae648dca7a04ec26ac7ad</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DTLS_MIN_MTU</name>
      <anchorfile>SocketDTLSConfig_8h.html</anchorfile>
      <anchor>a4e20e95db1f3cb5f21c2d10649ac36da</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DTLS_MAX_MTU</name>
      <anchorfile>SocketDTLSConfig_8h.html</anchorfile>
      <anchor>a3ac75939ec0806b6b2bbcc594aa16c55</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DTLS_MAX_RECORD_SIZE</name>
      <anchorfile>SocketDTLSConfig_8h.html</anchorfile>
      <anchor>a7f08bebbfcba5b41f95024251becb4bd</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DTLS_RECORD_OVERHEAD</name>
      <anchorfile>SocketDTLSConfig_8h.html</anchorfile>
      <anchor>adc0eac3a553975d605f281a788d3a884</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DTLS_MAX_PAYLOAD</name>
      <anchorfile>SocketDTLSConfig_8h.html</anchorfile>
      <anchor>a5514d14a0a82cfae0d503315e3eee143</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DTLS_COOKIE_LEN</name>
      <anchorfile>SocketDTLSConfig_8h.html</anchorfile>
      <anchor>a89aefff932cc08acb034d8c67cdb6bed</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DTLS_COOKIE_SECRET_LEN</name>
      <anchorfile>SocketDTLSConfig_8h.html</anchorfile>
      <anchor>a9e9f01674c7cbf477f77366cc88c5790</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DTLS_COOKIE_LIFETIME_SEC</name>
      <anchorfile>SocketDTLSConfig_8h.html</anchorfile>
      <anchor>a975d2fe81acd04965feb450aa7bf28c5</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DTLS_MAX_PENDING_COOKIES</name>
      <anchorfile>SocketDTLSConfig_8h.html</anchorfile>
      <anchor>a66094f34cc81cc40b65329dc209d6096</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DTLS_INITIAL_TIMEOUT_MS</name>
      <anchorfile>SocketDTLSConfig_8h.html</anchorfile>
      <anchor>a2b3017975dec54b0743d7d23ed6667b5</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DTLS_MAX_TIMEOUT_MS</name>
      <anchorfile>SocketDTLSConfig_8h.html</anchorfile>
      <anchor>ab68a21771cbdedd0e891ba7e9784c668</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DTLS_DEFAULT_HANDSHAKE_TIMEOUT_MS</name>
      <anchorfile>SocketDTLSConfig_8h.html</anchorfile>
      <anchor>aeac9f29b196910c31f0ca88253dc7265</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DTLS_MAX_RETRANSMITS</name>
      <anchorfile>SocketDTLSConfig_8h.html</anchorfile>
      <anchor>a68b8c2dba420bccf1c37a01884a1408a</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DTLS_SESSION_CACHE_SIZE</name>
      <anchorfile>SocketDTLSConfig_8h.html</anchorfile>
      <anchor>a5752ace7cf4781e4dad0786bd493af2e</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DTLS_SESSION_TIMEOUT_DEFAULT</name>
      <anchorfile>SocketDTLSConfig_8h.html</anchorfile>
      <anchor>a2b97166b3033d92fb8fb9dca5c70ea4f</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DTLS_ERROR_BUFSIZE</name>
      <anchorfile>SocketDTLSConfig_8h.html</anchorfile>
      <anchor>a6d22e3b756e5a6f1c5df5d05a94e8de9</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DTLS_OPENSSL_ERRSTR_BUFSIZE</name>
      <anchorfile>SocketDTLSConfig_8h.html</anchorfile>
      <anchor>a83416fe8d965d7133943298dcd693bd3</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DTLS_MAX_CERT_CHAIN_DEPTH</name>
      <anchorfile>SocketDTLSConfig_8h.html</anchorfile>
      <anchor>a0ce437be6ce966c60ba60e165485bb4a</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DTLS_MAX_SNI_LEN</name>
      <anchorfile>SocketDTLSConfig_8h.html</anchorfile>
      <anchor>ae00f82ec2c7d49c2aa2ecdaa98754371</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DTLS_MAX_ALPN_LEN</name>
      <anchorfile>SocketDTLSConfig_8h.html</anchorfile>
      <anchor>ab718fe1ccbb2793374a74bdd3fad5902</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DTLS_MAX_ALPN_PROTOCOLS</name>
      <anchorfile>SocketDTLSConfig_8h.html</anchorfile>
      <anchor>afcde6945b87c4def2497c74bf3115e87</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DTLS_MAX_PATH_LEN</name>
      <anchorfile>SocketDTLSConfig_8h.html</anchorfile>
      <anchor>a8c4f3d639af33633c811568f89124e6d</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DTLS_MAX_FILE_SIZE</name>
      <anchorfile>SocketDTLSConfig_8h.html</anchorfile>
      <anchor>ab42fd5a40a391bb5d2e3c5f44a1b24fa</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DTLS_VALID_MTU</name>
      <anchorfile>SocketDTLSConfig_8h.html</anchorfile>
      <anchor>a187a9aeb5d1836c6756595bde48e659e</anchor>
      <arglist>(mtu)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_DTLS_VALID_TIMEOUT</name>
      <anchorfile>SocketDTLSConfig_8h.html</anchorfile>
      <anchor>aac963ab68af70b569e6ee98ae7062887</anchor>
      <arglist>(ms)</arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketDTLSContext.h</name>
    <path>include/tls/</path>
    <filename>SocketDTLSContext_8h.html</filename>
    <includes id="Arena_8h" name="Arena.h" local="yes" import="no" module="no" objc="no">core/Arena.h</includes>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="SocketTLS_8h" name="SocketTLS.h" local="yes" import="no" module="no" objc="no">tls/SocketTLS.h</includes>
    <member kind="define">
      <type>#define</type>
      <name>T</name>
      <anchorfile>SocketDTLSContext_8h.html</anchorfile>
      <anchor>a0acb682b8260ab1c60b918599864e2e5</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketDTLSContext_T *</type>
      <name>SocketDTLSContext_T</name>
      <anchorfile>SocketDTLSContext_8h.html</anchorfile>
      <anchor>a05a015dd6cc639dd38a5853194c9002f</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketDgram_T *</type>
      <name>SocketDgram_T</name>
      <anchorfile>SocketDTLSContext_8h.html</anchorfile>
      <anchor>a178c1e09efbfdacb14740d3a0265721f</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>SocketDTLSContext_T</type>
      <name>SocketDTLSContext_new_server</name>
      <anchorfile>SocketDTLSContext_8h.html</anchorfile>
      <anchor>a0e99fc1644e610eb26324fb12cb96a57</anchor>
      <arglist>(const char *cert_file, const char *key_file, const char *ca_file)</arglist>
    </member>
    <member kind="function">
      <type>SocketDTLSContext_T</type>
      <name>SocketDTLSContext_new_client</name>
      <anchorfile>SocketDTLSContext_8h.html</anchorfile>
      <anchor>afa2f96caa6d90a1fae0ce4f8fb52970a</anchor>
      <arglist>(const char *ca_file)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDTLSContext_free</name>
      <anchorfile>SocketDTLSContext_8h.html</anchorfile>
      <anchor>af05f6e0175668dd52a2d68af50f67983</anchor>
      <arglist>(SocketDTLSContext_T *ctx_p)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDTLSContext_load_certificate</name>
      <anchorfile>SocketDTLSContext_8h.html</anchorfile>
      <anchor>a52fb3ca5d16466a21ac871ad2217904c</anchor>
      <arglist>(SocketDTLSContext_T ctx, const char *cert_file, const char *key_file)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDTLSContext_load_ca</name>
      <anchorfile>SocketDTLSContext_8h.html</anchorfile>
      <anchor>a210798613a063bb2be1fdf07a5d9648c</anchor>
      <arglist>(SocketDTLSContext_T ctx, const char *ca_file)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDTLSContext_set_verify_mode</name>
      <anchorfile>SocketDTLSContext_8h.html</anchorfile>
      <anchor>a167f13bc2d88dd59da040a6423cbb741</anchor>
      <arglist>(SocketDTLSContext_T ctx, TLSVerifyMode mode)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDTLSContext_enable_cookie_exchange</name>
      <anchorfile>SocketDTLSContext_8h.html</anchorfile>
      <anchor>abbffd63c9a5c7551ecaf8f89a4034eb4</anchor>
      <arglist>(SocketDTLSContext_T ctx)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDTLSContext_set_cookie_secret</name>
      <anchorfile>SocketDTLSContext_8h.html</anchorfile>
      <anchor>a19b67aa468ee1ad317683b1839b26e7b</anchor>
      <arglist>(SocketDTLSContext_T ctx, const unsigned char *secret, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDTLSContext_rotate_cookie_secret</name>
      <anchorfile>SocketDTLSContext_8h.html</anchorfile>
      <anchor>a488bdfe1b7d278bbcb2d2f80a9540df5</anchor>
      <arglist>(SocketDTLSContext_T ctx)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDTLSContext_set_mtu</name>
      <anchorfile>SocketDTLSContext_8h.html</anchorfile>
      <anchor>a473e4425731c220ae48a1bfec9ba279d</anchor>
      <arglist>(SocketDTLSContext_T ctx, size_t mtu)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketDTLSContext_get_mtu</name>
      <anchorfile>SocketDTLSContext_8h.html</anchorfile>
      <anchor>a9edc0ddb77ac1a52c2d65e202d6c4fdc</anchor>
      <arglist>(SocketDTLSContext_T ctx)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDTLSContext_set_min_protocol</name>
      <anchorfile>SocketDTLSContext_8h.html</anchorfile>
      <anchor>ad674b683e396a1af639691d9a18c6aa0</anchor>
      <arglist>(SocketDTLSContext_T ctx, int version)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDTLSContext_set_max_protocol</name>
      <anchorfile>SocketDTLSContext_8h.html</anchorfile>
      <anchor>a47bb5aa1a1eafa97c6e026d5b66b0ad9</anchor>
      <arglist>(SocketDTLSContext_T ctx, int version)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDTLSContext_set_cipher_list</name>
      <anchorfile>SocketDTLSContext_8h.html</anchorfile>
      <anchor>ada5ef3bbfb37dfe6c7f92c09958cf75c</anchor>
      <arglist>(SocketDTLSContext_T ctx, const char *ciphers)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDTLSContext_set_alpn_protos</name>
      <anchorfile>SocketDTLSContext_8h.html</anchorfile>
      <anchor>a090ce55e808027fc886ea6e6232b5a01</anchor>
      <arglist>(SocketDTLSContext_T ctx, const char **protos, size_t count)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDTLSContext_enable_session_cache</name>
      <anchorfile>SocketDTLSContext_8h.html</anchorfile>
      <anchor>a880ec894956f1a3a9029c512259df71b</anchor>
      <arglist>(SocketDTLSContext_T ctx, size_t max_sessions, long timeout_seconds)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDTLSContext_get_cache_stats</name>
      <anchorfile>SocketDTLSContext_8h.html</anchorfile>
      <anchor>aeaff18122638de5b79f9e261a4a63761</anchor>
      <arglist>(SocketDTLSContext_T ctx, size_t *hits, size_t *misses, size_t *stores)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDTLSContext_set_timeout</name>
      <anchorfile>SocketDTLSContext_8h.html</anchorfile>
      <anchor>af81e36256b380aaf7060607a22842d20</anchor>
      <arglist>(SocketDTLSContext_T ctx, int initial_ms, int max_ms)</arglist>
    </member>
    <member kind="function">
      <type>void *</type>
      <name>SocketDTLSContext_get_ssl_ctx</name>
      <anchorfile>SocketDTLSContext_8h.html</anchorfile>
      <anchor>a3319b2d0dcdfd165af1cb81448cdb9f9</anchor>
      <arglist>(SocketDTLSContext_T ctx)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDTLSContext_is_server</name>
      <anchorfile>SocketDTLSContext_8h.html</anchorfile>
      <anchor>a25c64fa874902c37b8aafcd9601b7cef</anchor>
      <arglist>(SocketDTLSContext_T ctx)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDTLSContext_has_cookie_exchange</name>
      <anchorfile>SocketDTLSContext_8h.html</anchorfile>
      <anchor>af77697da681e01b26f48c9472f13efad</anchor>
      <arglist>(SocketDTLSContext_T ctx)</arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketTLS.h</name>
    <path>include/tls/</path>
    <filename>SocketTLS_8h.html</filename>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="Socket_8h" name="Socket.h" local="yes" import="no" module="no" objc="no">socket/Socket.h</includes>
    <member kind="define">
      <type>#define</type>
      <name>T</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>a0acb682b8260ab1c60b918599864e2e5</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketTLS_T *</type>
      <name>SocketTLS_T</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>a63e73c93350813167a68162c5cb3d819</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketTLSContext_T *</type>
      <name>SocketTLSContext_T</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>ac46f2ab9dacbb1af2d590f2974e21577</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>TLSHandshakeState</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>ad092160c037d01929df1bb8d5b75b43c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>TLS_HANDSHAKE_NOT_STARTED</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>ad092160c037d01929df1bb8d5b75b43cae3a7df914ebdf339b8e7d711779670e2</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>TLS_HANDSHAKE_IN_PROGRESS</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>ad092160c037d01929df1bb8d5b75b43ca445915a69a47e09546e8d5b275eedf2a</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>TLS_HANDSHAKE_WANT_READ</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>ad092160c037d01929df1bb8d5b75b43cab268d75e71356121ccf44e8e5f4ab592</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>TLS_HANDSHAKE_WANT_WRITE</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>ad092160c037d01929df1bb8d5b75b43cad39cdf43af44417566b39aa9929f7aac</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>TLS_HANDSHAKE_COMPLETE</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>ad092160c037d01929df1bb8d5b75b43cac9d764c27bc5b541bd5e7a4c42eddfce</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>TLS_HANDSHAKE_ERROR</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>ad092160c037d01929df1bb8d5b75b43caca78870a105a05fffb3d5d6ca022aff2</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>TLSVerifyMode</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>ac32c3958835b92ff683ae15f78448694</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>TLS_VERIFY_NONE</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>ac32c3958835b92ff683ae15f78448694a0ada1cef646c3b57e9a793035dcc0a6f</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>TLS_VERIFY_PEER</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>ac32c3958835b92ff683ae15f78448694ae56010acbcb7edcdcd7707be028cc6fe</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>TLS_VERIFY_FAIL_IF_NO_PEER_CERT</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>ac32c3958835b92ff683ae15f78448694a29928ea4593855bb860f7a0bb8eb027d</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>TLS_VERIFY_CLIENT_ONCE</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>ac32c3958835b92ff683ae15f78448694abbcde32e72faadf92044da1ccc76f183</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLS_enable</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>ab9a8fb788aa1f0d21b5773bc43a48d6f</anchor>
      <arglist>(Socket_T socket, SocketTLSContext_T ctx)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLS_set_hostname</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>a15d2c8f4eaea80114bbd2123da025e56</anchor>
      <arglist>(Socket_T socket, const char *hostname)</arglist>
    </member>
    <member kind="function">
      <type>TLSHandshakeState</type>
      <name>SocketTLS_handshake</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>aeaa77dd7852b535baf17b53ee2518454</anchor>
      <arglist>(Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>TLSHandshakeState</type>
      <name>SocketTLS_handshake_loop</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>a439248f2ff7b87470520de0607569d06</anchor>
      <arglist>(Socket_T socket, int timeout_ms)</arglist>
    </member>
    <member kind="function">
      <type>TLSHandshakeState</type>
      <name>SocketTLS_handshake_auto</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>a54a01327e253586278c0f740c2764010</anchor>
      <arglist>(Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLS_shutdown</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>ab11506db6f41f31e9fc170b3d0e848f1</anchor>
      <arglist>(Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketTLS_send</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>abdb38e692dde58bbec4ab905eeb8b3aa</anchor>
      <arglist>(Socket_T socket, const void *buf, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketTLS_recv</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>a1c71fc02141cd9e6da4fdf1c88dbbaf3</anchor>
      <arglist>(Socket_T socket, void *buf, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketTLS_get_cipher</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>a0859f0a6e05840bdc037c3765e22b7b1</anchor>
      <arglist>(Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketTLS_get_version</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>aef0f67021658d05419f1da479be2957e</anchor>
      <arglist>(Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>long</type>
      <name>SocketTLS_get_verify_result</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>a4fd56e743762151aa449744a8d574164</anchor>
      <arglist>(Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketTLS_get_verify_error_string</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>a39a966c33421653c64f78261f24ee1f1</anchor>
      <arglist>(Socket_T socket, char *buf, size_t size)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketTLS_is_session_reused</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>a315ccceb9cb5b74d8b90f1439ce57344</anchor>
      <arglist>(Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketTLS_get_alpn_selected</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>a56acd283757bb0af4f4d59d3c0f218ea</anchor>
      <arglist>(Socket_T socket)</arglist>
    </member>
    <member kind="variable">
      <type>char</type>
      <name>tls_error_buf</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>ae74b3921236213de2e979bbd2039e452</anchor>
      <arglist>[]</arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketTLS_Failed</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>abc011202dd4f2e080b6ea8eb0f24287e</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketTLS_HandshakeFailed</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>a82be75dd764021fb64cd6824768e2254</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketTLS_VerifyFailed</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>abe406e483a861198db5bca58300f1728</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketTLS_ProtocolError</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>ad97195716332983bae10a77f275740bd</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketTLS_ShutdownFailed</name>
      <anchorfile>SocketTLS_8h.html</anchorfile>
      <anchor>aa724dbe4115729ef621c0f1f74b5afd6</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketTLSConfig.h</name>
    <path>include/tls/</path>
    <filename>SocketTLSConfig_8h.html</filename>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TLS_MIN_VERSION</name>
      <anchorfile>SocketTLSConfig_8h.html</anchorfile>
      <anchor>a3d1a24e799511be7b94d7cb83e30c826</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TLS_MAX_VERSION</name>
      <anchorfile>SocketTLSConfig_8h.html</anchorfile>
      <anchor>a1bb6850b2066656bb9ca5be7bc4e7a26</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TLS13_CIPHERSUITES</name>
      <anchorfile>SocketTLSConfig_8h.html</anchorfile>
      <anchor>a8c3a6a178964eee6129e588f6f18861b</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS</name>
      <anchorfile>SocketTLSConfig_8h.html</anchorfile>
      <anchor>a261f36b20bf9986a7f09fa9ed31b793e</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TLS_DEFAULT_SHUTDOWN_TIMEOUT_MS</name>
      <anchorfile>SocketTLSConfig_8h.html</anchorfile>
      <anchor>ab30f8121a683dd31fff11c10934b1137</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TLS_POLL_INTERVAL_MS</name>
      <anchorfile>SocketTLSConfig_8h.html</anchorfile>
      <anchor>a5ca7b5f2bc6a521f8b7fb7b94196a94e</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TLS_BUFFER_SIZE</name>
      <anchorfile>SocketTLSConfig_8h.html</anchorfile>
      <anchor>a21c94d7068bbee12788fb1af5b90a393</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TLS_MAX_CERT_CHAIN_DEPTH</name>
      <anchorfile>SocketTLSConfig_8h.html</anchorfile>
      <anchor>a4d5991568275ac5f8d677aea34656f0a</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TLS_MAX_ALPN_LEN</name>
      <anchorfile>SocketTLSConfig_8h.html</anchorfile>
      <anchor>accea5587344f8cc4d28f5d862dc2fa96</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TLS_MAX_ALPN_TOTAL_BYTES</name>
      <anchorfile>SocketTLSConfig_8h.html</anchorfile>
      <anchor>aa52cffca1d260f855e90946554827278</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TLS_MAX_SNI_LEN</name>
      <anchorfile>SocketTLSConfig_8h.html</anchorfile>
      <anchor>a2f3a226ee7b72b9153e60d985e90fd15</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TLS_SESSION_CACHE_SIZE</name>
      <anchorfile>SocketTLSConfig_8h.html</anchorfile>
      <anchor>addb5f5a6224c2d4c50908c19baab9a2d</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TLS_ERROR_BUFSIZE</name>
      <anchorfile>SocketTLSConfig_8h.html</anchorfile>
      <anchor>aa6df1c1fb5a0bcfe9a77b4dbb037c77f</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TLS_OPENSSL_ERRSTR_BUFSIZE</name>
      <anchorfile>SocketTLSConfig_8h.html</anchorfile>
      <anchor>ae6650ea0075b47d60f5dcfc068c9cb69</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TLS_MAX_SNI_CERTS</name>
      <anchorfile>SocketTLSConfig_8h.html</anchorfile>
      <anchor>ac5d4211edcb3114d8d9b26c22b50fac3</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TLS_SNI_INITIAL_CAPACITY</name>
      <anchorfile>SocketTLSConfig_8h.html</anchorfile>
      <anchor>aed59df6881f4fbedd888f060a563eca0</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TLS_MAX_ALPN_PROTOCOLS</name>
      <anchorfile>SocketTLSConfig_8h.html</anchorfile>
      <anchor>a31c8aa5bed2b0db51e53847e6b6bc22c</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TLS_TICKET_KEY_LEN</name>
      <anchorfile>SocketTLSConfig_8h.html</anchorfile>
      <anchor>ac328cd9a67a36754bdeb92361fb9526b</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TLS_SESSION_TIMEOUT_DEFAULT</name>
      <anchorfile>SocketTLSConfig_8h.html</anchorfile>
      <anchor>a5554586ea5eb4bf0a81c54963d0cbb2f</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TLS_MAX_OCSP_RESPONSE_LEN</name>
      <anchorfile>SocketTLSConfig_8h.html</anchorfile>
      <anchor>a5249d9cf8a8fd02a5c2fcc84b393d160</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TLS_MAX_PATH_LEN</name>
      <anchorfile>SocketTLSConfig_8h.html</anchorfile>
      <anchor>abd952b038e2ba7a919097a1c3fca116d</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TLS_MAX_LABEL_LEN</name>
      <anchorfile>SocketTLSConfig_8h.html</anchorfile>
      <anchor>a17ff6f02c79ea2099d8329a0e82a6000</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TLS_MAX_PINS</name>
      <anchorfile>SocketTLSConfig_8h.html</anchorfile>
      <anchor>acf406dfb5329bd8170f908b258660a72</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TLS_PIN_HASH_LEN</name>
      <anchorfile>SocketTLSConfig_8h.html</anchorfile>
      <anchor>ab727e6443392c2d7a9b350723f4bf827</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TLS_PIN_INITIAL_CAPACITY</name>
      <anchorfile>SocketTLSConfig_8h.html</anchorfile>
      <anchor>a3e34a6589554ee91a77d39057681e22e</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TLS_CRL_MIN_REFRESH_INTERVAL</name>
      <anchorfile>SocketTLSConfig_8h.html</anchorfile>
      <anchor>a1c682687285a8a50d6ade71bc8941560</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TLS_CRL_MAX_REFRESH_INTERVAL</name>
      <anchorfile>SocketTLSConfig_8h.html</anchorfile>
      <anchor>adbfa56fdcb0238beabd54ceecdf8aba7</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TLS_MAX_CRL_SIZE</name>
      <anchorfile>SocketTLSConfig_8h.html</anchorfile>
      <anchor>abcf496a1134e5bff5ea583e6395f4a44</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TLS_MAX_CRL_FILES_IN_DIR</name>
      <anchorfile>SocketTLSConfig_8h.html</anchorfile>
      <anchor>a65c50bd768a726e7a7f036f32a58e49d</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_TLS_CRL_MAX_PATH_LEN</name>
      <anchorfile>SocketTLSConfig_8h.html</anchorfile>
      <anchor>a362c108e58b5204fa5141920db407ed0</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketTLSContext.h</name>
    <path>include/tls/</path>
    <filename>SocketTLSContext_8h.html</filename>
    <includes id="Arena_8h" name="Arena.h" local="yes" import="no" module="no" objc="no">core/Arena.h</includes>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="SocketTLS_8h" name="SocketTLS.h" local="yes" import="no" module="no" objc="no">tls/SocketTLS.h</includes>
    <member kind="define">
      <type>#define</type>
      <name>T</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a0acb682b8260ab1c60b918599864e2e5</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketTLSContext_T *</type>
      <name>SocketTLSContext_T</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>ac46f2ab9dacbb1af2d590f2974e21577</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>int(*</type>
      <name>SocketTLSVerifyCallback</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>ac9a12208531822c8304c23dcbcb8ba97</anchor>
      <arglist>)(int preverify_ok, X509_STORE_CTX *x509_ctx, SocketTLSContext_T tls_ctx, Socket_T socket, void *user_data)</arglist>
    </member>
    <member kind="typedef">
      <type>void(*</type>
      <name>SocketTLSCrlCallback</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a60686895b6fbdd1290a6f6176484bf5b</anchor>
      <arglist>)(SocketTLSContext_T ctx, const char *path, int success, void *user_data)</arglist>
    </member>
    <member kind="typedef">
      <type>OCSP_RESPONSE *(*</type>
      <name>SocketTLSOcspGenCallback</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a1acd7a590114ffbf4307a6f5a3bab35c</anchor>
      <arglist>)(SSL *ssl, void *arg)</arglist>
    </member>
    <member kind="function">
      <type>SocketTLSContext_T</type>
      <name>SocketTLSContext_new_server</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a79a403f2f54f21c90a92e9cb73e24cbc</anchor>
      <arglist>(const char *cert_file, const char *key_file, const char *ca_file)</arglist>
    </member>
    <member kind="function">
      <type>SocketTLSContext_T</type>
      <name>SocketTLSContext_new_client</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a7fe51da14439d768bdf72f4ed8fbb022</anchor>
      <arglist>(const char *ca_file)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_load_certificate</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a1e2af3e4421c3c20c7dbc4b99cfb4211</anchor>
      <arglist>(SocketTLSContext_T ctx, const char *cert_file, const char *key_file)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_add_certificate</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a92be47dab18fc79c409fc8b450e7aa0d</anchor>
      <arglist>(SocketTLSContext_T ctx, const char *hostname, const char *cert_file, const char *key_file)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_load_ca</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>ac4de1881e05f041a3d5016cba7d5a045</anchor>
      <arglist>(SocketTLSContext_T ctx, const char *ca_file)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_set_verify_mode</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a71084c00bec22f65b90301188868b759</anchor>
      <arglist>(SocketTLSContext_T ctx, TLSVerifyMode mode)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_free</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>aea7ca3e656e9b58706fafc3232147203</anchor>
      <arglist>(SocketTLSContext_T *ctx_p)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_set_verify_callback</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a2712efd6f1918aa87a3120547c0cf64d</anchor>
      <arglist>(SocketTLSContext_T ctx, SocketTLSVerifyCallback callback, void *user_data)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_load_crl</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a8bf03223d7c3b3cd28f8d03fe082d15e</anchor>
      <arglist>(SocketTLSContext_T ctx, const char *crl_path)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_refresh_crl</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a9ea9577387ebc9edb186a6c491c67ab4</anchor>
      <arglist>(SocketTLSContext_T ctx, const char *crl_path)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_reload_crl</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>ac5ba25c0153bc63b6087cff6304f4938</anchor>
      <arglist>(SocketTLSContext_T ctx, const char *crl_path)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_set_crl_auto_refresh</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>ac049c86b0b5edba0a7bcb73ca2e1e2eb</anchor>
      <arglist>(SocketTLSContext_T ctx, const char *crl_path, long interval_seconds, SocketTLSCrlCallback callback, void *user_data)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_cancel_crl_auto_refresh</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>ab4bee293124b9d83681f9471f0519689</anchor>
      <arglist>(SocketTLSContext_T ctx)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketTLSContext_crl_check_refresh</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a516c739f9ab7a0a5968279aba78a250c</anchor>
      <arglist>(SocketTLSContext_T ctx)</arglist>
    </member>
    <member kind="function">
      <type>long</type>
      <name>SocketTLSContext_crl_next_refresh_ms</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a1e822bd45ec2dad56c13d541dcd0c23d</anchor>
      <arglist>(SocketTLSContext_T ctx)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_set_ocsp_response</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>acad0c368922de598277e4237779504b7</anchor>
      <arglist>(SocketTLSContext_T ctx, const unsigned char *response, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_set_ocsp_gen_callback</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a0b49040701aa37f11720d9539c046347</anchor>
      <arglist>(SocketTLSContext_T ctx, SocketTLSOcspGenCallback cb, void *arg)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketTLS_get_ocsp_status</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>ae1a1b2392cfa8dd68e636bbef9df443f</anchor>
      <arglist>(Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_enable_ocsp_stapling</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a414fb627189037256afd8c4e015b74d1</anchor>
      <arglist>(SocketTLSContext_T ctx)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketTLSContext_ocsp_stapling_enabled</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a7f214a19238ce8cd567d6ad6efa806c9</anchor>
      <arglist>(SocketTLSContext_T ctx)</arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>CTValidationMode</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a4d930163393a67950a5378e540c0e939</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>CT_VALIDATION_PERMISSIVE</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a4d930163393a67950a5378e540c0e939aea499abb40ae318f0fd2b596ce6cbaa8</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>CT_VALIDATION_STRICT</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a4d930163393a67950a5378e540c0e939a102a7857300a9c88684ed50efe69d3ab</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>X509 *(*</type>
      <name>SocketTLSCertLookupCallback</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a5c2914ee879d575869932c3a3aed4863</anchor>
      <arglist>)(X509_STORE_CTX *store_ctx, X509_NAME *name, void *user_data)</arglist>
    </member>
    <member kind="typedef">
      <type>const char *(*</type>
      <name>SocketTLSAlpnCallback</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>aa53566f8d54960bb2d44516a50f67c70</anchor>
      <arglist>)(const char **client_protos, size_t client_count, void *user_data)</arglist>
    </member>
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketTLS_PinVerifyFailed</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a445003fff70029dd096df971801be0e4</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_set_cert_lookup_callback</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>ae1d9ff9d7e15f5a798d316ddf6ec6d53</anchor>
      <arglist>(SocketTLSContext_T ctx, SocketTLSCertLookupCallback callback, void *user_data)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_set_min_protocol</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>aa7703e1d2c80b49601af8237e81729ef</anchor>
      <arglist>(SocketTLSContext_T ctx, int version)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_set_max_protocol</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>ad094c4db92c9979bcde108166193abee</anchor>
      <arglist>(SocketTLSContext_T ctx, int version)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_set_cipher_list</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a2e731151980c8c30a7fbb18da74ddffa</anchor>
      <arglist>(SocketTLSContext_T ctx, const char *ciphers)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_set_alpn_protos</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a4fcc29a81cf5c643ee9a56deb46b9ec8</anchor>
      <arglist>(SocketTLSContext_T ctx, const char **protos, size_t count)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_set_alpn_callback</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>ab7c088402bdf132a710551ebe2268ed0</anchor>
      <arglist>(SocketTLSContext_T ctx, SocketTLSAlpnCallback callback, void *user_data)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_enable_session_cache</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a6f0a68e802e789df40eaa28cb641a422</anchor>
      <arglist>(SocketTLSContext_T ctx, size_t max_sessions, long timeout_seconds)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_set_session_cache_size</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a51fa29a23c87a8f2a9c7b71b6731fb50</anchor>
      <arglist>(SocketTLSContext_T ctx, size_t size)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_get_cache_stats</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a2093721c235cb8ebc83e90606abdcb33</anchor>
      <arglist>(SocketTLSContext_T ctx, size_t *hits, size_t *misses, size_t *stores)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_enable_session_tickets</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>ae7d40e475eec529625a3d6ba74d23f4a</anchor>
      <arglist>(SocketTLSContext_T ctx, const unsigned char *key, size_t key_len)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_add_pin</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a34caeef50e78017625d2eb62142a7e45</anchor>
      <arglist>(SocketTLSContext_T ctx, const unsigned char *sha256_hash)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_add_pin_hex</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>afd50881da0db97098204ff6fa920bb26</anchor>
      <arglist>(SocketTLSContext_T ctx, const char *hex_hash)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_add_pin_from_cert</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>aa535f69cf93b2f0dec403e71336b0682</anchor>
      <arglist>(SocketTLSContext_T ctx, const char *cert_file)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_add_pin_from_x509</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>acf5982c65823fa0eedc34d8d933710a9</anchor>
      <arglist>(SocketTLSContext_T ctx, const X509 *cert)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_clear_pins</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>ae201aacce977d32ab0187dd8b97d6c9a</anchor>
      <arglist>(SocketTLSContext_T ctx)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_set_pin_enforcement</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a8a972b0da962c5515936444b6921182d</anchor>
      <arglist>(SocketTLSContext_T ctx, int enforce)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketTLSContext_get_pin_enforcement</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a9d03fb564c11628d54e76a1c177b8494</anchor>
      <arglist>(SocketTLSContext_T ctx)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketTLSContext_get_pin_count</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>aec2e531425cc03bff359517f60aa474c</anchor>
      <arglist>(SocketTLSContext_T ctx)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketTLSContext_has_pins</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>aea37c149f7babbf14c28caf0ffef97cf</anchor>
      <arglist>(SocketTLSContext_T ctx)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketTLSContext_verify_pin</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>ac051204c676250b114e00af223055686</anchor>
      <arglist>(SocketTLSContext_T ctx, const unsigned char *sha256_hash)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketTLSContext_verify_cert_pin</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>ae69fbca6dae1712eb7abd1f1b268926b</anchor>
      <arglist>(SocketTLSContext_T ctx, const X509 *cert)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_enable_ct</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>af27bede9402c6c8c7541143e019c635f</anchor>
      <arglist>(SocketTLSContext_T ctx, CTValidationMode mode)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketTLSContext_ct_enabled</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a3b70029e86352f55e3710673ba30c23f</anchor>
      <arglist>(SocketTLSContext_T ctx)</arglist>
    </member>
    <member kind="function">
      <type>CTValidationMode</type>
      <name>SocketTLSContext_get_ct_mode</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>af18e867664012c78a758c5454f62c367</anchor>
      <arglist>(SocketTLSContext_T ctx)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketTLSContext_set_ctlog_list_file</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>ada967caf61c070399281b088b35ed78a</anchor>
      <arglist>(SocketTLSContext_T ctx, const char *log_file)</arglist>
    </member>
    <member kind="function">
      <type>void *</type>
      <name>SocketTLSContext_get_ssl_ctx</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a6e8aae1b6b1182d3f83b8673fdbbe945</anchor>
      <arglist>(SocketTLSContext_T ctx)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketTLSContext_is_server</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a39bd71708494c1c833d3064c3a70f8ad</anchor>
      <arglist>(SocketTLSContext_T ctx)</arglist>
    </member>
  </compound>
  <compound kind="union">
    <name>align</name>
    <filename>unionalign.html</filename>
    <member kind="variable">
      <type>int</type>
      <name>i</name>
      <anchorfile>unionalign.html</anchorfile>
      <anchor>a8f750b35b1359be92173466ddd63b7e7</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>long</type>
      <name>l</name>
      <anchorfile>unionalign.html</anchorfile>
      <anchor>a6c286090dc9659f1970848ab5ebb4d6a</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>long *</type>
      <name>lp</name>
      <anchorfile>unionalign.html</anchorfile>
      <anchor>a29dae4b4cadb165fc2b69d8a997327d3</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>void *</type>
      <name>p</name>
      <anchorfile>unionalign.html</anchorfile>
      <anchor>ad023bcc02a5fb5381a305b7ed83a644f</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>void(*</type>
      <name>fp</name>
      <anchorfile>unionalign.html</anchorfile>
      <anchor>a24af03c2c2b13ef5e8dac1130ded4f4d</anchor>
      <arglist>)(void)</arglist>
    </member>
    <member kind="variable">
      <type>float</type>
      <name>f</name>
      <anchorfile>unionalign.html</anchorfile>
      <anchor>a363eff2b501a06a5f2b8cac89d2674c3</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>double</type>
      <name>d</name>
      <anchorfile>unionalign.html</anchorfile>
      <anchor>a2e1b983804fcd308a884ad14d938b443</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>long double</type>
      <name>ld</name>
      <anchorfile>unionalign.html</anchorfile>
      <anchor>a34622fd1a776983ddec8000bdd7cdaa8</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>Except_Frame</name>
    <filename>Except_8h.html</filename>
    <anchor>structExcept__Frame</anchor>
    <member kind="variable">
      <type>Except_Frame *</type>
      <name>prev</name>
      <anchorfile>Except_8h.html</anchorfile>
      <anchor>a4a5323a9c98b198d171a7f0409f3bbae</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>jmp_buf</type>
      <name>env</name>
      <anchorfile>Except_8h.html</anchorfile>
      <anchor>abce4b8de2bbf7d6fb6ef52d618309264</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const char *</type>
      <name>file</name>
      <anchorfile>Except_8h.html</anchorfile>
      <anchor>a4c8d0ea0c9437ede53e8703feefe0dc6</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>line</name>
      <anchorfile>Except_8h.html</anchorfile>
      <anchor>aff1099dac68f6f3b8392f2ebe5c8341f</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const Except_T *</type>
      <name>exception</name>
      <anchorfile>Except_8h.html</anchorfile>
      <anchor>a41f49d856fa1e252bc5f7439f6feeaf8</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>Except_T</name>
    <filename>Except_8h.html</filename>
    <anchor>structExcept__T</anchor>
    <member kind="variable">
      <type>const struct Except_T *</type>
      <name>type</name>
      <anchorfile>Except_8h.html</anchorfile>
      <anchor>a343b5beb0d02c17f95cceb95f4598405</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const char *</type>
      <name>reason</name>
      <anchorfile>Except_8h.html</anchorfile>
      <anchor>a6a35b57fc58f0ba7cc0d4f939dd3f773</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="interface">
    <name>Interface</name>
    <filename>namespace_3globalScope_4.html</filename>
    <anchor>interfaceInterface</anchor>
  </compound>
  <compound kind="protocol">
    <name>Protocol-p</name>
    <filename>namespace_3globalScope_4.html</filename>
    <anchor>protocolProtocol-p</anchor>
  </compound>
  <compound kind="struct">
    <name>SocketEvent_T</name>
    <filename>SocketPoll_8h.html</filename>
    <anchor>structSocketEvent__T</anchor>
    <member kind="variable">
      <type>Socket_T</type>
      <name>socket</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>a98544b5a507331adac069acd7f42d593</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>void *</type>
      <name>data</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>acb5b92ec2f2954ee3baa024a74ce4655</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>unsigned</type>
      <name>events</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>ac526bc7e51851919ae7b0f3cec5934bc</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketEventRecord</name>
    <filename>SocketUtil_8h.html</filename>
    <anchor>structSocketEventRecord</anchor>
    <member kind="variable">
      <type>SocketEventType</type>
      <name>type</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a2ef831e31103812b3c31c099cea65c2c</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const char *</type>
      <name>component</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a1ce3b46734d680830bf0ce719bc55f7a</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>union SocketEventRecord::@1</type>
      <name>data</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a46454b1b915024075996facfd55e75a2</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="union">
    <name>SocketEventRecord.data</name>
    <filename>SocketUtil_8h.html</filename>
    <anchor>unionSocketEventRecord_8data</anchor>
    <member kind="variable">
      <type>struct SocketEventRecord::@1::@2</type>
      <name>connection</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a4717d53ebfdfea8477f780ec66151dcb</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>struct SocketEventRecord::@1::@3</type>
      <name>dns</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>ab3bf60b851ebaeb2768b01a32e2ef32f</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>struct SocketEventRecord::@1::@4</type>
      <name>poll</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>ab0f6dfb42fa80caee6825bfecd30f094</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketEventRecord.data.connection</name>
    <filename>SocketUtil_8h.html</filename>
    <anchor>structSocketEventRecord_8data_8connection</anchor>
    <member kind="variable">
      <type>int</type>
      <name>fd</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a36eba1e1e343279857ea7f69a597324e</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const char *</type>
      <name>peer_addr</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a2acfab89d50b27af645bfecf305c9b90</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>peer_port</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a78f4755292fae2f109358763bfbebb3b</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const char *</type>
      <name>local_addr</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>aa60ad6083f67002afce9c31664ad1202</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>local_port</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>ac4c65a3a63aa48e49aedceb7cf6e06a2</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketEventRecord.data.dns</name>
    <filename>SocketUtil_8h.html</filename>
    <anchor>structSocketEventRecord_8data_8dns</anchor>
    <member kind="variable">
      <type>const char *</type>
      <name>host</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a67b3dba8bc6778101892eb77249db32e</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>port</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a901555fb06e346cb065ceb9808dcfc25</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketEventRecord.data.poll</name>
    <filename>SocketUtil_8h.html</filename>
    <anchor>structSocketEventRecord_8data_8poll</anchor>
    <member kind="variable">
      <type>int</type>
      <name>nfds</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a1a0729dccd2773490730cb1118488677</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>timeout_ms</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a3a551bf8b969bfa6309e26c2fa4c1901</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketHE_Config_T</name>
    <filename>SocketHappyEyeballs_8h.html</filename>
    <anchor>structSocketHE__Config__T</anchor>
    <member kind="variable">
      <type>int</type>
      <name>first_attempt_delay_ms</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>a718ced26ae9d5f1a9c51980686007af9</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>attempt_timeout_ms</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>a6102505cbcca11148c1e2cbcda5caa16</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>total_timeout_ms</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>a30f77ee5bd25329726485101935e8a2a</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>dns_timeout_ms</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>ae94ef758ca842d9231733fbc9b910e2f</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>prefer_ipv6</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>a2286078d8352300a92ddd005f756ae8b</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>max_attempts</name>
      <anchorfile>SocketHappyEyeballs_8h.html</anchorfile>
      <anchor>a844dbed92f4e7fbcedd41f78089d4edc</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketHPACK_DecoderConfig</name>
    <filename>SocketHPACK_8h.html</filename>
    <anchor>structSocketHPACK__DecoderConfig</anchor>
    <member kind="variable">
      <type>size_t</type>
      <name>max_table_size</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a375555fac1dd16cf11832600c367108c</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>max_header_size</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>aed7143ab948850cc88b622d69b96e6f1</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>max_header_list_size</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a1acbffb311a85436e98b0d2e0a723d1d</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketHPACK_EncoderConfig</name>
    <filename>SocketHPACK_8h.html</filename>
    <anchor>structSocketHPACK__EncoderConfig</anchor>
    <member kind="variable">
      <type>size_t</type>
      <name>max_table_size</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a80995982f5e4bc991bb7549ee70dbb59</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>huffman_encode</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>aba9258c14594154c007f55e14213cf2f</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>use_indexing</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>af2abf6915fc7c46c2205371def976d39</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketHPACK_Header</name>
    <filename>SocketHPACK_8h.html</filename>
    <anchor>structSocketHPACK__Header</anchor>
    <member kind="variable">
      <type>const char *</type>
      <name>name</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a46d227219a888ba2170521fbce3467c1</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>name_len</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a97bac7e84874c5e753a10a8ecb44e3a5</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const char *</type>
      <name>value</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>acce8321d450efabcb974f62beb953b27</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>value_len</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>a7903ffe078d8355010272c36a0ee5413</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>never_index</name>
      <anchorfile>SocketHPACK_8h.html</anchorfile>
      <anchor>aa6aaa27657ef2d2ea3f24e629b1af16b</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketHTTP1_Config</name>
    <filename>SocketHTTP1_8h.html</filename>
    <anchor>structSocketHTTP1__Config</anchor>
    <member kind="variable">
      <type>size_t</type>
      <name>max_request_line</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a8f681f902def11b16a7eea20eb7f8e08</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>max_header_name</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a8672fe4cd385d1f07f2a28af17f2bb33</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>max_header_value</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a88447b7bd33d2baa80abe9ee97c64b21</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>max_headers</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>abfbe5b0b91d60339154b3b6c6ed7549e</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>max_header_size</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a108f87a5b1d893862a9a53da200141b2</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>max_chunk_size</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a210e4001f9c4495e5e59ec63992fafcf</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>max_trailer_size</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>a92d57170c7f01130d0b2f55e869bc273</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>max_header_line</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>ad52814be2bcde961f89fd28531af8471</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>allow_obs_fold</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>acf3abe5c5f8346ef4dc94771023f0c65</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>strict_mode</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>af0674dfcd3ff95d357c22a68ac7fcf36</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>max_decompressed_size</name>
      <anchorfile>SocketHTTP1_8h.html</anchorfile>
      <anchor>aeda690045f7731461b2a5f29d9c3cc03</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketHTTP2_Config</name>
    <filename>SocketHTTP2_8h.html</filename>
    <anchor>structSocketHTTP2__Config</anchor>
    <member kind="variable">
      <type>SocketHTTP2_Role</type>
      <name>role</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a8baa42ce5d63ef1d1269bfc2e3ae83ee</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint32_t</type>
      <name>header_table_size</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a0a3a1ca12e972c4cc3eb021be7edfb3a</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint32_t</type>
      <name>enable_push</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>ade8731b7297accc9c4ab533cb8a91dcf</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint32_t</type>
      <name>max_concurrent_streams</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a4f948d55c4fc6947b5da693aad073731</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint32_t</type>
      <name>max_stream_open_rate</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a47341b7c9c96d8de9fbbd75debe89d0e</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint32_t</type>
      <name>max_stream_open_burst</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>aa7d444c755f09f5ebca1a996c71b5120</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint32_t</type>
      <name>max_stream_close_rate</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a938e74eab04a08111335da2fcec3f2d0</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint32_t</type>
      <name>max_stream_close_burst</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a4572833d76ee10a1bddd1470cc789d4f</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint32_t</type>
      <name>initial_window_size</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a27e2a7a74af88f8ce2403fe7405acf6e</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint32_t</type>
      <name>max_frame_size</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>ae782ebee629c89a54830be6dbe1b9dc0</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint32_t</type>
      <name>max_header_list_size</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>ae41f20c6701d09c2282323da601db1dc</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint32_t</type>
      <name>connection_window_size</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>ab1162906710ac2724ea9d0abf0384851</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>settings_timeout_ms</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>affa0492a72097f3972ca3aa8ba5ea651</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>ping_timeout_ms</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a50c501438f1e35ef6260bb4de12719fa</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>idle_timeout_ms</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a4675986a4a1964712533e8596627b0b1</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketHTTP2_FrameHeader</name>
    <filename>SocketHTTP2_8h.html</filename>
    <anchor>structSocketHTTP2__FrameHeader</anchor>
    <member kind="variable">
      <type>uint32_t</type>
      <name>length</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a2bed570c22bd36b3e61a4b6e1e0b8033</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint8_t</type>
      <name>type</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a55fab70be967b0da3d407a27ba926711</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint8_t</type>
      <name>flags</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a4008ece540896b7489aff8776f970b79</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint32_t</type>
      <name>stream_id</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a65726cc5062e6479d5e204997395cf31</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketHTTP2_Setting</name>
    <filename>SocketHTTP2_8h.html</filename>
    <anchor>structSocketHTTP2__Setting</anchor>
    <member kind="variable">
      <type>uint16_t</type>
      <name>id</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>a068ddfa03ae28958ad77cafb0f884fcc</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint32_t</type>
      <name>value</name>
      <anchorfile>SocketHTTP2_8h.html</anchorfile>
      <anchor>aa503c5a217c84181f7adf368f5eea13f</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketHTTP_MethodProperties</name>
    <filename>SocketHTTP_8h.html</filename>
    <anchor>structSocketHTTP__MethodProperties</anchor>
    <member kind="variable">
      <type>unsigned</type>
      <name>safe</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>a73218e27f40ce28175276e72244863c6</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>unsigned</type>
      <name>idempotent</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>a6665b6641419663e5d2f89bcb4eff8dc</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>unsigned</type>
      <name>cacheable</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>a7c626100bb166521094c508c2907cab3</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>unsigned</type>
      <name>has_body</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>a49f204f98e783e66d7ff44a41d776a91</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>unsigned</type>
      <name>response_body</name>
      <anchorfile>SocketHTTP_8h.html</anchorfile>
      <anchor>a56b452f5e749b9785b8926e469093417</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketHTTPClient_Auth</name>
    <filename>SocketHTTPClient_8h.html</filename>
    <anchor>structSocketHTTPClient__Auth</anchor>
    <member kind="variable">
      <type>SocketHTTPClient_AuthType</type>
      <name>type</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>aea321b9aeb6d8d36babd95cd7af87d35</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const char *</type>
      <name>username</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>aebecaec836c2d21aeb36c83c6a037b58</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const char *</type>
      <name>password</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a709145c7dcf32bbfbdbc68da8da0842f</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const char *</type>
      <name>token</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a75371d88c2cb09feb95620c237b37882</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const char *</type>
      <name>realm</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a89774175b3f815b3c17b8b150347b453</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketHTTPClient_Config</name>
    <filename>SocketHTTPClient_8h.html</filename>
    <anchor>structSocketHTTPClient__Config</anchor>
    <member kind="variable">
      <type>SocketHTTP_Version</type>
      <name>max_version</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>aeeeb2ea03d33db0ba500da1c7782f7f3</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>allow_http2_cleartext</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a9a480ef82e914f17714c7c57d12f88af</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>enable_connection_pool</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>ac81b35696b105b13f703c5d71f5c5692</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>max_connections_per_host</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>ad87a23b29168c1a6a738bd07268247de</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>max_total_connections</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>aacd5591ab8f36783e6f759052439eb30</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>idle_timeout_ms</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a867974712621670ef1dc975b2b396f84</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>max_connection_age_ms</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a82bcf56254c541ebd8fbdbba0a7ba7bb</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>acquire_timeout_ms</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a12094d3f2718443658de2cab3f8873b4</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>connect_timeout_ms</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>ad0964ac6e0738a3c4914054529bb51a7</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>request_timeout_ms</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a5d89d81bfb2401b06059048425fafb93</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>dns_timeout_ms</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a6e7fd7c2a4f862fc8d613d4662a7e2e1</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>follow_redirects</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a1e5a28b4e256802af5f979726c728553</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>redirect_on_post</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a847eaef5232b2ada9149eea8aa9d4d4c</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>accept_encoding</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>aa6bd2632f03fadb8a08f023e641c2c64</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>auto_decompress</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a39d5d74dbbdec57ac84fed12f747e299</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>SocketTLSContext_T</type>
      <name>tls_context</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a30f979d083088bc46c8c7de3bc37a3db</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>verify_ssl</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>aa5c6daa6286ff5a701a804da14108a4c</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>SocketProxy_Config *</type>
      <name>proxy</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>af1c22aca38ea27645e9400fe42680bdf</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const char *</type>
      <name>user_agent</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a0d03d16dc3eae06b6ab0b89b288c44df</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>max_response_size</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>aa26d176771f3b6ddee9a2d95142e9c46</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>enable_retry</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>adb6071171fe058cbc1c221e1b0d6ec98</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>max_retries</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>ad8b244df21d9337ed74c872e694d10ba</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>retry_initial_delay_ms</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a1b02030b2c83c6e7bd1812de2362ede3</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>retry_max_delay_ms</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>afd505949c45d0fb48c0810759cb66176</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>retry_on_connection_error</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a6355fa7fdfcc9db5d6069189aef62928</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>retry_on_timeout</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a58a60bcfb2edaa6accced6acd52191ad</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>retry_on_5xx</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a86ed34fbe021d156e6ee5ac2bc8e9b6e</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>enforce_samesite</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>ae9bb372f96fd426c9fcf729fa78f26e3</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketHTTPClient_Cookie</name>
    <filename>SocketHTTPClient_8h.html</filename>
    <anchor>structSocketHTTPClient__Cookie</anchor>
    <member kind="variable">
      <type>const char *</type>
      <name>name</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>ae7076917489dca85561ff672d120551c</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const char *</type>
      <name>value</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a21b390a321565e4ebf8be575550c1498</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const char *</type>
      <name>domain</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a0dc75016531006762afa85a21130ac13</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const char *</type>
      <name>path</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a7259b82f78dc6e60c52ef6c5d741ca06</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>time_t</type>
      <name>expires</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a76752117eaf672a88292a3c7c250b52d</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>secure</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a3300f627ad07cd15a596451a41dc4b69</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>http_only</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>ae47a67be4b88e83dd7c877f63af2ae8a</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>SocketHTTPClient_SameSite</type>
      <name>same_site</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>ad1fc2e3ea45172e27a07aaacfe3c7eeb</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketHTTPClient_PoolStats</name>
    <filename>SocketHTTPClient_8h.html</filename>
    <anchor>structSocketHTTPClient__PoolStats</anchor>
    <member kind="variable">
      <type>size_t</type>
      <name>active_connections</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a102cdd1136d87673c4eb8ca42cd64942</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>idle_connections</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>aaab49cd26a75dd2f3f7ed96eafc09a25</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>total_requests</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>acbe290157d79e718d8397a6d7078487c</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>reused_connections</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a0bb94abb8c7aa981d1aae1d47469b316</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>connections_created</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a9a5d4cac43fdb9d880edef1dc778273a</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>connections_failed</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a1dfc46ee0c2d61f3facd7daf0d93f0a0</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>connections_timed_out</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>ac9548fe3f865ed4d99c7366b0f64937d</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>stale_connections_removed</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a822cd3674285e9ee5a3e541b42cc8f9a</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>pool_exhausted_waits</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a2388e92ca44d26b70ce6904abbcf0d13</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketHTTPClient_Response</name>
    <filename>SocketHTTPClient_8h.html</filename>
    <anchor>structSocketHTTPClient__Response</anchor>
    <member kind="variable">
      <type>int</type>
      <name>status_code</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a0baa2f233436d7bb00f28214d6382542</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>SocketHTTP_Headers_T</type>
      <name>headers</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>a8b459516887245f8e4b77f8d8517ede1</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>void *</type>
      <name>body</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>ab7f8558743b64c751b64ac26231dca31</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>body_len</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>aae64f48637811f9ddbc8e12aea55e0e6</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>SocketHTTP_Version</type>
      <name>version</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>accda45708658a8ada478121524f85e5e</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>Arena_T</type>
      <name>arena</name>
      <anchorfile>SocketHTTPClient_8h.html</anchorfile>
      <anchor>ab3f98045a2f32cb3249ee62d036654c3</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketHTTPServer_Config</name>
    <filename>SocketHTTPServer_8h.html</filename>
    <anchor>structSocketHTTPServer__Config</anchor>
    <member kind="variable">
      <type>int</type>
      <name>port</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>aaa846da9282ae7cc08293d9e3ae100c5</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const char *</type>
      <name>bind_address</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>ab0bf8c280cce766a64efd9064f93bef2</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>backlog</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a92d76f73dd8d83287a36bdd3643022ea</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>SocketTLSContext_T</type>
      <name>tls_context</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a2bbd51b98734877f1e4dd9e0176b82b7</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>SocketHTTP_Version</type>
      <name>max_version</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>ae89b5a0849cde455e84fb2eb41309cb0</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>enable_h2c_upgrade</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>aba94ad7a26eb19a5fa9eb671ac38e39b</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>max_header_size</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a4e960d114a23d30cead50fdb3189525b</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>max_body_size</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>ac1e10ab5e4e74aac02cefdf9c5555bae</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>request_timeout_ms</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>acee81724c46b258607d762187f5b25ac</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>keepalive_timeout_ms</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a1e78410c99812889132c0977539d170b</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>request_read_timeout_ms</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>aae5feb01178bcf0f41095d30ec718240</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>response_write_timeout_ms</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a7c6c518a1861c3ee10b133297d47444c</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>max_connections</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>aba7a435867737c5dda694445481fbc7c</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>max_requests_per_connection</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a411213143aa7aa44c27de10d645da50c</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>max_connections_per_client</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>a5ed0dc426933e2d4fc092685c2f37d3b</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>max_concurrent_requests</name>
      <anchorfile>SocketHTTPServer_8h.html</anchorfile>
      <anchor>aff8dceb976118d9ad3726cac957f6e97</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketLiveCount</name>
    <filename>SocketCommon_8h.html</filename>
    <anchor>structSocketLiveCount</anchor>
    <member kind="variable">
      <type>int</type>
      <name>count</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>aa0eb80c5ca5d1e5862958659252abf7e</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>pthread_mutex_t</type>
      <name>mutex</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a2184fefc1d68daf0fa7309d8de989e88</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketLogContext</name>
    <filename>SocketUtil_8h.html</filename>
    <anchor>structSocketLogContext</anchor>
    <member kind="variable">
      <type>char</type>
      <name>trace_id</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a8402ba34dfee2fe5117f314071abdcb6</anchor>
      <arglist>[37]</arglist>
    </member>
    <member kind="variable">
      <type>char</type>
      <name>request_id</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>aabe172fe52213ef60ac3e0ce7c4c65d1</anchor>
      <arglist>[37]</arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>connection_fd</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a405290fc36dbecb3fb00cb2e78358d82</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketLogField</name>
    <filename>SocketUtil_8h.html</filename>
    <anchor>structSocketLogField</anchor>
    <member kind="variable">
      <type>const char *</type>
      <name>key</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>a9705557e4cfe1b045966c7d2b40a7ab6</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const char *</type>
      <name>value</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>aca7bd4c1b8c5b420e41ba5c949495d96</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketMetrics_HistogramSnapshot</name>
    <filename>SocketMetrics_8h.html</filename>
    <anchor>structSocketMetrics__HistogramSnapshot</anchor>
    <member kind="variable">
      <type>uint64_t</type>
      <name>count</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>ae65da7d40c1b636bd5d688c6ab36176a</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>double</type>
      <name>sum</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a4088038d1883a118b9818b15772582b0</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>double</type>
      <name>min</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>ad353d502eaa2af3ba9f5027c024bdad1</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>double</type>
      <name>max</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a92aa2bf4c9b19983fa3417159929df81</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>double</type>
      <name>mean</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a39b4ba97214ae557d6664a60881731ee</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>double</type>
      <name>p50</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a8b172fd16d7a741708785715acde4b57</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>double</type>
      <name>p75</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a86b3fe4f2f16158efcd05739be0be2c7</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>double</type>
      <name>p90</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>ae642be44e4add2bc25d809c22cf75a28</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>double</type>
      <name>p95</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a5009b287c8bfd50a87d3278be6b76d6b</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>double</type>
      <name>p99</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a4d8eaa0353371329afd9e8ebc7cd5fd0</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>double</type>
      <name>p999</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a117aeb2403d9212a3476a0f5f506d1ba</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketMetrics_Snapshot</name>
    <filename>SocketMetrics_8h.html</filename>
    <anchor>structSocketMetrics__Snapshot</anchor>
    <member kind="variable">
      <type>uint64_t</type>
      <name>timestamp_ms</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>af00d4802f4ec042ec70c2b6cca0ef439</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint64_t</type>
      <name>counters</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>ac3d167ae7fb495b924c2b9ace863445a</anchor>
      <arglist>[SOCKET_COUNTER_METRIC_COUNT]</arglist>
    </member>
    <member kind="variable">
      <type>int64_t</type>
      <name>gauges</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a052116cbac741e511d1354dcee03aa14</anchor>
      <arglist>[SOCKET_GAUGE_METRIC_COUNT]</arglist>
    </member>
    <member kind="variable">
      <type>SocketMetrics_HistogramSnapshot</type>
      <name>histograms</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a2df8269ceffa8db53191bb61ce5a4e08</anchor>
      <arglist>[SOCKET_HISTOGRAM_METRIC_COUNT]</arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketMetricsSnapshot</name>
    <filename>SocketUtil_8h.html</filename>
    <anchor>structSocketMetricsSnapshot</anchor>
    <member kind="variable">
      <type>unsigned long long</type>
      <name>values</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>ad4bec382c27642da1ce45dcf676684e6</anchor>
      <arglist>[SOCKET_METRIC_COUNT]</arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketPool_Stats</name>
    <filename>SocketPool_8h.html</filename>
    <anchor>structSocketPool__Stats</anchor>
    <member kind="variable">
      <type>uint64_t</type>
      <name>total_added</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>ab6181f0361304b9dc0ca22b2b5b63422</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint64_t</type>
      <name>total_removed</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>af3a48d372811cdc1995449539e7fa244</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint64_t</type>
      <name>total_reused</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>ae4a38edcc6f06de4427a3fab17df8059</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint64_t</type>
      <name>total_health_checks</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a2b87e1f7d01cca34d283f2a198d55582</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint64_t</type>
      <name>total_health_failures</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>abc785aa6c8bf923e442c2d8ff6de17ea</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint64_t</type>
      <name>total_validation_failures</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a12b67886dc33365dacefdbf6898dbaa9</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint64_t</type>
      <name>total_idle_cleanups</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a93f503d21a575444867f078913f9fdeb</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>current_active</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a27243a0956a835deca459b97c6d102f6</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>current_idle</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>ae3f9de28a86d86ad1fb47f81934396e4</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>max_connections</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>aeb1d2bc03018eb8cf873ca9c7cf1d591</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>double</type>
      <name>reuse_rate</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>acddc4228468fcc3b685ed125e6dcbe4c</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>double</type>
      <name>avg_connection_age_sec</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a95ea2264615189143e51b08b2372bde5</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>double</type>
      <name>churn_rate_per_sec</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a58155d80879fa628a209dcf26d9ed813</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketProxy_Config</name>
    <filename>SocketProxy_8h.html</filename>
    <anchor>structSocketProxy__Config</anchor>
    <member kind="variable">
      <type>SocketProxyType</type>
      <name>type</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>aa04cfa88d52d6c1f889f9f936a141141</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const char *</type>
      <name>host</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>a507287d832417162da30794693e16a6e</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>port</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>aff28145ee5466be9d0e12fba3e07dc97</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const char *</type>
      <name>username</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>a579714517d79e28bb9b03190d67158d5</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const char *</type>
      <name>password</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>ae619303ab820c36c920c509d735748f2</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>SocketHTTP_Headers_T</type>
      <name>extra_headers</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>a1a667bd87d678a4e0cb64c14aa0ffd3d</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>SocketTLSContext_T *</type>
      <name>tls_ctx</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>a7bd4b0058fd2a869d2ccb2f2d1fd740c</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>connect_timeout_ms</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>aa761e79e5c6644f3ccb22a4c0300105a</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>handshake_timeout_ms</name>
      <anchorfile>SocketProxy_8h.html</anchorfile>
      <anchor>aaefad91d7469f34f214a7fac5e1779d6</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketReconnect_Policy_T</name>
    <filename>SocketReconnect_8h.html</filename>
    <anchor>structSocketReconnect__Policy__T</anchor>
    <member kind="variable">
      <type>int</type>
      <name>initial_delay_ms</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>abf740738ffd922747329556ebd6052ca</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>max_delay_ms</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>aea494798fa2b191e8a0cc3b7c64ca0a2</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>double</type>
      <name>multiplier</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>ae9bbefd1a50c5e291395ca3af920a22d</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>double</type>
      <name>jitter</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>a803e0eaa631385205819346d33db4974</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>max_attempts</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>abd49613f2c70d36afe1822ca33ec1a0e</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>circuit_failure_threshold</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>af4176c02c394de525164d44893fd5c5a</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>circuit_reset_timeout_ms</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>ae99b002f9e873e6b101c1356f5a7df02</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>health_check_interval_ms</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>aaa80956d1e58e84adfab7063e1936f95</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>health_check_timeout_ms</name>
      <anchorfile>SocketReconnect_8h.html</anchorfile>
      <anchor>ade4054b2276dfc3c6b06a4b759241208</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketRetry_Policy</name>
    <filename>SocketRetry_8h.html</filename>
    <anchor>structSocketRetry__Policy</anchor>
    <member kind="variable">
      <type>int</type>
      <name>max_attempts</name>
      <anchorfile>SocketRetry_8h.html</anchorfile>
      <anchor>ae4fc9812297db12344b02e21d638a618</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>initial_delay_ms</name>
      <anchorfile>SocketRetry_8h.html</anchorfile>
      <anchor>a3738bc8ccc78b3f879df09d685494714</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>max_delay_ms</name>
      <anchorfile>SocketRetry_8h.html</anchorfile>
      <anchor>aa9acfb8be959ffd198d16e2446a30710</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>double</type>
      <name>multiplier</name>
      <anchorfile>SocketRetry_8h.html</anchorfile>
      <anchor>ae292a46f8c68e19cb29e72d49b48317e</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>double</type>
      <name>jitter</name>
      <anchorfile>SocketRetry_8h.html</anchorfile>
      <anchor>ac44aa265265c65b8c29fd80aa3e0f61d</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketRetry_Stats</name>
    <filename>SocketRetry_8h.html</filename>
    <anchor>structSocketRetry__Stats</anchor>
    <member kind="variable">
      <type>int</type>
      <name>attempts</name>
      <anchorfile>SocketRetry_8h.html</anchorfile>
      <anchor>a7b978de556278e018fccc199dadd4a7d</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>last_error</name>
      <anchorfile>SocketRetry_8h.html</anchorfile>
      <anchor>a560a11b7408ab6b745312cc2552aa387</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int64_t</type>
      <name>total_delay_ms</name>
      <anchorfile>SocketRetry_8h.html</anchorfile>
      <anchor>aba725a298fa2b675bcdc8ea77ba8b27e</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int64_t</type>
      <name>total_time_ms</name>
      <anchorfile>SocketRetry_8h.html</anchorfile>
      <anchor>a939cbbd0e2c2537391a2e970991a1c9d</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketSecurityLimits</name>
    <filename>SocketSecurity_8h.html</filename>
    <anchor>structSocketSecurityLimits</anchor>
    <member kind="variable">
      <type>size_t</type>
      <name>max_allocation</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a1dd545a749e77aa5cb82b7e85bf09e36</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>max_buffer_size</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>ae43b81b8cf9129c9d6752f34894ba71c</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>max_connections</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a144d096fe53602d03295e18d0464232a</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>arena_max_alloc_size</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a504b6f75d0cf2e797ef5e838aea973ba</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>http_max_uri_length</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a3b32fafb211e38e9838e9181a8d4531a</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>http_max_header_name</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a1a92f68da0f5b92ee678237cc2646da3</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>http_max_header_value</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a1f586f4e595e16955e23998e04caecf9</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>http_max_header_size</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a0c619f8e0d4dd70f4400c29a624e8c19</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>http_max_headers</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>afdd207e3668e2e11458948a3aad76833</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>http_max_body_size</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a38f13b676cb92ff0a15389c309e19650</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>http1_max_request_line</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>ae52e94d13f09404b25ea5e6ce8b9a244</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>http1_max_chunk_size</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a09d8b8ba81dbdfd054852704521c3e3b</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>http2_max_concurrent_streams</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>aa6ebf2ebd20aad81fe2e3878840af1d3</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>http2_max_frame_size</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a8a7f143c56f078ca8b586edf7fde4b01</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>http2_max_header_list_size</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>af58899d383dfd65a1776b6c01d209728</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>tls_max_alpn_protocols</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>aa7bc20fce590c4e1ee35ec373c3c680e</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>tls_max_alpn_len</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a8192f6e1eaf496898449c75854882f6d</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>tls_max_alpn_total_bytes</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a3766cfcaec1653412a3c0310bf5f289c</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>hpack_max_table_size</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a3be4155262be8579d60d13ca4dbf2456</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>ws_max_frame_size</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a71de06121ef88aa459fc42e9f087be64</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>ws_max_message_size</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a7066039979bec29150ec1607406bb82f</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>tls_max_cert_chain_depth</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a51b777a9f3dbcfa40b08249110df5c21</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>tls_session_cache_size</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>af0437c76d97f1c1060cd64292f1d27ff</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>ratelimit_conn_per_sec</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>aad4c405c76c951df4eb1047556616fc9</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>ratelimit_burst</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a1201fdfce0a6d52d800643ff4bfe439a</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>ratelimit_max_per_ip</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a8c183e16c7d5bc9ee671fd0d9dd19534</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>timeout_connect_ms</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a57fc2fdec5241008f1d6da53f9e00cf0</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>timeout_dns_ms</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a59af712b30f6d94c681a272029976e7d</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>timeout_idle_ms</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>a896b59f955bafd0a580728136858820f</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>timeout_request_ms</name>
      <anchorfile>SocketSecurity_8h.html</anchorfile>
      <anchor>ac1311a4929ead36e3ce915720008e206</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketSYN_IPState</name>
    <filename>SocketSYNProtect_8h.html</filename>
    <anchor>structSocketSYN__IPState</anchor>
    <member kind="variable">
      <type>char</type>
      <name>ip</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a856b3a23c98e17f5c213a3d26a0a9590</anchor>
      <arglist>[64]</arglist>
    </member>
    <member kind="variable">
      <type>int64_t</type>
      <name>window_start_ms</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a346232b13c475cfaaa53eff914d4a0dd</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint32_t</type>
      <name>attempts_current</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a6d2446089e798132b58c0333ba78cb3e</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint32_t</type>
      <name>attempts_previous</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a4cbf6f33a74f2df4daeacbff135931a8</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint32_t</type>
      <name>successes</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>abe2bcfaef720a4a375fe1c67b92c37d6</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint32_t</type>
      <name>failures</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a77f8fbce111a5f7338f8cc8cb4a7bca9</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int64_t</type>
      <name>last_attempt_ms</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a7b49dd6e199c1e1e91b1eb71fc245509</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int64_t</type>
      <name>block_until_ms</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>ae664aa07891130d5bb60edf6a1d72bf7</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>SocketSYN_Reputation</type>
      <name>rep</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a3f543090a343b51bdf4e7930e182366d</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>float</type>
      <name>score</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>aaa43aaa7c28639d949e57ac1e14b2189</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketSYNProtect_Config</name>
    <filename>SocketSYNProtect_8h.html</filename>
    <anchor>structSocketSYNProtect__Config</anchor>
    <member kind="variable">
      <type>int</type>
      <name>window_duration_ms</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a73ebdc5d7fdeb3217b8c0dfc99347bbb</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>max_attempts_per_window</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a5f9976be0331359859284315ebf66e1a</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>max_global_per_second</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a575daabf11edf0ee687ff8a547240c77</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>float</type>
      <name>min_success_ratio</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a906abceb1945a950293d0c050f6c376b</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>throttle_delay_ms</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>af8dd3acb9ac939027f76995bac4b2cf5</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>block_duration_ms</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a58785babfc923ba70d9c8f0d5b7a44cf</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>challenge_defer_sec</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a732b2bfe41c8d449ea5be9401f818eb3</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>float</type>
      <name>score_throttle</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a1d688c73198839dedc956d3b8912f66d</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>float</type>
      <name>score_challenge</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a5e02553a2f9e15f3d1c9f79d82529388</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>float</type>
      <name>score_block</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>ab9ce44543382518e5ed2a7471dd67413</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>float</type>
      <name>score_decay_per_sec</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>ad86ba3309adf0a1b6ee5ef26f7031281</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>float</type>
      <name>score_penalty_attempt</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>af65955bb61462c59140d05b5dabb1a94</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>float</type>
      <name>score_penalty_failure</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>ae55192b1a0a6bf438bf424cd87f9572a</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>float</type>
      <name>score_reward_success</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>ad6ecd5f04a5c197c4a740ee02611fdae</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>max_tracked_ips</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a2a865bdf6cf3990a6d2e100c96164d80</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>max_whitelist</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a0acad8adbb06f59ee96249bb1f5a417b</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>max_blacklist</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a7429afc5fc724582c34ce06cb3d3f5fa</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>unsigned</type>
      <name>hash_seed</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>ae8aea9e4cc570341d5cc8901f3cb814e</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketSYNProtect_Stats</name>
    <filename>SocketSYNProtect_8h.html</filename>
    <anchor>structSocketSYNProtect__Stats</anchor>
    <member kind="variable">
      <type>uint64_t</type>
      <name>total_attempts</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a6e80ed205ec9330c6291d010863f810b</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint64_t</type>
      <name>total_allowed</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a158331134454296a07e713e4efe46ae1</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint64_t</type>
      <name>total_throttled</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a109c6d0a07655ac0ab5a48b5ba09c5ae</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint64_t</type>
      <name>total_challenged</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a03ba7e002b3ac41d8aa5e9042cd99211</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint64_t</type>
      <name>total_blocked</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a7c029f370305000dd71a42aaa52c393a</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint64_t</type>
      <name>total_whitelisted</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a5a571ad87a6efbfaa2c7521f8589fa80</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint64_t</type>
      <name>total_blacklisted</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a614ae093175b9319c4523296d16569d8</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint64_t</type>
      <name>current_tracked_ips</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a5c6dc902b20931d955219b937f8ed2d6</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint64_t</type>
      <name>current_blocked_ips</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a62d7ed28eb018dac7c46b19f7447a420</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint64_t</type>
      <name>lru_evictions</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>a0e134430eac30ed54777c52221adec76</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int64_t</type>
      <name>uptime_ms</name>
      <anchorfile>SocketSYNProtect_8h.html</anchorfile>
      <anchor>addc5d09c4b26fa03979894a037830a03</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketTimeouts_Extended_T</name>
    <filename>SocketConfig_8h.html</filename>
    <anchor>structSocketTimeouts__Extended__T</anchor>
    <member kind="variable">
      <type>int</type>
      <name>dns_timeout_ms</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>abea0b97e93ab95cb1b94a4df51dc4755</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>connect_timeout_ms</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a933213f87e1e773af80ae832d9cc6d47</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>tls_timeout_ms</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a07e7e9d0eba5129a439e104e64d0d9b4</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>request_timeout_ms</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a1528bed9d677efdb9685cca4b0eb9b69</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>operation_timeout_ms</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a69615eb41365b169b06a5dd15bfb53c6</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketTimeouts_T</name>
    <filename>SocketConfig_8h.html</filename>
    <anchor>structSocketTimeouts__T</anchor>
    <member kind="variable">
      <type>int</type>
      <name>connect_timeout_ms</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a5d4d6de98cb88315bbe1d3768bedd373</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>dns_timeout_ms</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ad49a90a8aab8a8b6c63592c7856737ba</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>operation_timeout_ms</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a410363ec6b5e6156686edf7c442d8441</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketUTF8_State</name>
    <filename>SocketUTF8_8h.html</filename>
    <anchor>structSocketUTF8__State</anchor>
    <member kind="variable">
      <type>uint32_t</type>
      <name>state</name>
      <anchorfile>SocketUTF8_8h.html</anchorfile>
      <anchor>a48fe27868c9570c5e60189e4c91dbd26</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint8_t</type>
      <name>bytes_needed</name>
      <anchorfile>SocketUTF8_8h.html</anchorfile>
      <anchor>a075c37180d67223a22af1724ebdd9278</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>uint8_t</type>
      <name>bytes_seen</name>
      <anchorfile>SocketUTF8_8h.html</anchorfile>
      <anchor>a216e9dcd5edcfb520dd193928984a537</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketWS_Config</name>
    <filename>SocketWS_8h.html</filename>
    <anchor>structSocketWS__Config</anchor>
    <member kind="variable">
      <type>SocketWS_Role</type>
      <name>role</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>aa895fa89617603768d89d043b41b3bc9</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>max_frame_size</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a622a5556ac8a0b6888819a40851a11fd</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>max_message_size</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a2100320f9508ad064f387dc26bbef62f</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>max_fragments</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>ac3b980e3936f7e3763e4a6c2c5e466d3</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>validate_utf8</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a1873fe17fa2f2d2d3c0d16cbfbcfc3f1</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>enable_permessage_deflate</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a5b4cb5b34e0960b4964eec24547ebe29</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>deflate_no_context_takeover</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a6990f2e1597412e0fd8101407944f51d</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>deflate_max_window_bits</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>aaaf3a4b3929373f6d34097ee3360edd7</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const char **</type>
      <name>subprotocols</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a72bb5bfa2a49c7bdd770303635e0e49d</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>ping_interval_ms</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a376fe666ac3f3654087792edae1ce054</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>ping_timeout_ms</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a4ca65b7722835ec62374763fa625596f</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketWS_Frame</name>
    <filename>SocketWS_8h.html</filename>
    <anchor>structSocketWS__Frame</anchor>
    <member kind="variable">
      <type>SocketWS_Opcode</type>
      <name>opcode</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a3316616d6bd9228919cf2eac7df3c780</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>fin</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a54987d666286860044d3f6bd3f513d85</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>rsv1</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a40b506b65f89a2c8d96acecf636c5191</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const unsigned char *</type>
      <name>payload</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>ab17b0ddda509759d90d3c7f5aa09144b</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>payload_len</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>ab6da903ab04e63a093ed73f861b7d5c8</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketWS_Message</name>
    <filename>SocketWS_8h.html</filename>
    <anchor>structSocketWS__Message</anchor>
    <member kind="variable">
      <type>SocketWS_Opcode</type>
      <name>type</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>acb9416eb06a0a6e95260acebee3544b2</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>unsigned char *</type>
      <name>data</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>af7c3a0707d0a280d08242b3668e4bc14</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>size_t</type>
      <name>len</name>
      <anchorfile>SocketWS_8h.html</anchorfile>
      <anchor>a48e400e0db4731142c0baa97427de817</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="page">
    <name>async_io_guide</name>
    <title>Asynchronous I/O Guide</title>
    <filename>async_io_guide.html</filename>
  </compound>
  <compound kind="page">
    <name>http_guide</name>
    <title>HTTP Guide</title>
    <filename>http_guide.html</filename>
  </compound>
  <compound kind="page">
    <name>websocket_guide</name>
    <title>WebSocket Guide</title>
    <filename>websocket_guide.html</filename>
  </compound>
  <compound kind="page">
    <name>proxy_guide</name>
    <title>Proxy Guide</title>
    <filename>proxy_guide.html</filename>
  </compound>
  <compound kind="page">
    <name>security_guide</name>
    <title>Security Guide</title>
    <filename>security_guide.html</filename>
  </compound>
  <compound kind="page">
    <name>migration_guide</name>
    <title>Migration Guide</title>
    <filename>migration_guide.html</filename>
  </compound>
  <compound kind="page">
    <name>index</name>
    <title>Socket Library</title>
    <filename>index.html</filename>
    <docanchor file="index.html" title="Socket Library">mainpage</docanchor>
  </compound>
</tagfile>
