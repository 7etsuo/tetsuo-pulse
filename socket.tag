<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<tagfile doxygen_version="1.9.8">
  <compound kind="file">
    <name>ASYNC_IO.md</name>
    <path>docs/</path>
    <filename>ASYNC__IO_8md.html</filename>
  </compound>
  <compound kind="file">
    <name>mainpage.md</name>
    <path>docs/</path>
    <filename>mainpage_8md.html</filename>
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
    <class kind="union">align</class>
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
      <name>SOCKET_MAX_TIMER_TIMEOUT_MS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ad738dd2be8abca1d0353d31f888ba3eb</anchor>
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
      <name>SOCKET_LOG_BUFFER_SIZE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a6359d7f5856bc1d8e19de36b71156f7a</anchor>
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
      <name>SOCKET_MSG_NOSIGNAL</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a6d8596dc13da264d86966c08b435110a</anchor>
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
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketRateLimit_Failed</name>
      <anchorfile>SocketRateLimit_8h.html</anchorfile>
      <anchor>af06f7fa3fe589c3d406f8f12cbc4e59e</anchor>
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
    <name>SocketUtil.h</name>
    <path>include/core/</path>
    <filename>SocketUtil_8h.html</filename>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="SocketConfig_8h" name="SocketConfig.h" local="yes" import="no" module="no" objc="no">core/SocketConfig.h</includes>
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
    <member kind="typedef">
      <type>void(*</type>
      <name>SocketLogCallback</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>add820ca01810b616cfe1d6fef0cbf899</anchor>
      <arglist>)(void *userdata, SocketLogLevel level, const char *component, const char *message)</arglist>
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
      <name>SocketMetrics_reset</name>
      <anchorfile>SocketUtil_8h.html</anchorfile>
      <anchor>ab129aa3dd03bc8e5670da9abf0c41a47</anchor>
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
      <anchor>a558726d00fc4c532a2ee0febce55c66e</anchor>
      <arglist>(SocketEventCallback callback, void *userdata)</arglist>
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
      <anchor>a6cacdd3d812c8cdc353239e4af4aa624</anchor>
      <arglist>(SocketDNS_T dns, SocketDNS_Request_T req)</arglist>
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
    <member kind="variable">
      <type>const Except_T</type>
      <name>SocketDNS_Failed</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>a329324a0e4a1450a6b968b375bb9b333</anchor>
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
      <anchor>ae1b5045d5537dde7eb2cce1e8deae997</anchor>
      <arglist>(int maxevents)</arglist>
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
      <anchor>a9ca26eabe4ea3174d20ea5169a21f15c</anchor>
      <arglist>(PollBackend_T backend, int timeout)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>backend_get_event</name>
      <anchorfile>SocketPoll__backend_8h.html</anchorfile>
      <anchor>ac8fe3c2f41388223c47cb0c59d9428d1</anchor>
      <arglist>(PollBackend_T backend, int index, int *fd_out, unsigned *events_out)</arglist>
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
    <includes id="SocketUtil_8h" name="SocketUtil.h" local="yes" import="no" module="no" objc="no">core/SocketUtil.h</includes>
    <includes id="Socket_8h" name="Socket.h" local="yes" import="no" module="no" objc="no">socket/Socket.h</includes>
    <includes id="SocketBuf_8h" name="SocketBuf.h" local="yes" import="no" module="no" objc="no">socket/SocketBuf.h</includes>
    <includes id="SocketReconnect_8h" name="SocketReconnect.h" local="yes" import="no" module="no" objc="no">socket/SocketReconnect.h</includes>
    <includes id="SocketDNS_8h" name="SocketDNS.h" local="yes" import="no" module="no" objc="no">dns/SocketDNS.h</includes>
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
      <type>void(*</type>
      <name>SocketPool_ConnectCallback</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a5441c8cf779cd74fbb9f39bd322c33bd</anchor>
      <arglist>)(Connection_T conn, int error, void *data)</arglist>
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
      <anchor>aaeae09452d4cfc38c39945cb45c84093</anchor>
      <arglist>(SocketPool_T pool, Socket_T server, int max_accepts, Socket_T *accepted)</arglist>
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
      <anchor>afed48d9f1859fe37c82e1c2f412354d0</anchor>
      <arglist>(SocketBase_T *base)</arglist>
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
      <anchor>ac72a1247fceed09210753d03ae2ebb5e</anchor>
      <arglist>)(SocketReconnect_T conn, Socket_T socket, void *userdata)</arglist>
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
      <type>OCSP_RESPONSE *(*</type>
      <name>SocketTLSOcspGenCallback</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>a1acd7a590114ffbf4307a6f5a3bab35c</anchor>
      <arglist>)(SSL *ssl, void *arg)</arglist>
    </member>
    <member kind="typedef">
      <type>const char *(*</type>
      <name>SocketTLSAlpnCallback</name>
      <anchorfile>SocketTLSContext_8h.html</anchorfile>
      <anchor>aa53566f8d54960bb2d44516a50f67c70</anchor>
      <arglist>)(const char **client_protos, size_t client_count, void *user_data)</arglist>
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
  <compound kind="page">
    <name>md_docs_2ASYNC__IO</name>
    <title>Asynchronous I/O Guide</title>
    <filename>md_docs_2ASYNC__IO.html</filename>
  </compound>
  <compound kind="page">
    <name>index</name>
    <title>Socket Library</title>
    <filename>index.html</filename>
    <docanchor file="index.html" title="Socket Library">mainpage</docanchor>
  </compound>
</tagfile>
