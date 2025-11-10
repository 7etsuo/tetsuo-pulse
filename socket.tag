<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<tagfile doxygen_version="1.9.8">
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
      <type>struct T *</type>
      <name>T</name>
      <anchorfile>Arena_8h.html</anchorfile>
      <anchor>a24514489b0962fafe8414bfae95aa268</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>T</type>
      <name>Arena_new</name>
      <anchorfile>Arena_8h.html</anchorfile>
      <anchor>a89ed54bb26ea8d3b5adf6dd91bbfabcc</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Arena_dispose</name>
      <anchorfile>Arena_8h.html</anchorfile>
      <anchor>a6df3c4a3be9c2ad42567ac454d21605b</anchor>
      <arglist>(T *ap)</arglist>
    </member>
    <member kind="function">
      <type>void *</type>
      <name>Arena_alloc</name>
      <anchorfile>Arena_8h.html</anchorfile>
      <anchor>a6199ed44c60cefaaf970a01fd3328a1c</anchor>
      <arglist>(T arena, size_t nbytes, const char *file, int line)</arglist>
    </member>
    <member kind="function">
      <type>void *</type>
      <name>Arena_calloc</name>
      <anchorfile>Arena_8h.html</anchorfile>
      <anchor>ae2cf7d22ec2b62831335221869418f0a</anchor>
      <arglist>(T arena, size_t count, size_t nbytes, const char *file, int line)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Arena_clear</name>
      <anchorfile>Arena_8h.html</anchorfile>
      <anchor>a28209b936f419970ae096bb9131391e4</anchor>
      <arglist>(T arena)</arglist>
    </member>
    <member kind="variable">
      <type>Except_T</type>
      <name>Arena_Failed</name>
      <anchorfile>Arena_8h.html</anchorfile>
      <anchor>a2167676d05c626995008942b13186dbc</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>Except.h</name>
    <path>include/core/</path>
    <filename>Except_8h.html</filename>
    <class kind="struct">T</class>
    <class kind="struct">Except_Frame</class>
    <member kind="define">
      <type>#define</type>
      <name>T</name>
      <anchorfile>Except_8h.html</anchorfile>
      <anchor>a0acb682b8260ab1c60b918599864e2e5</anchor>
      <arglist></arglist>
    </member>
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
    <member kind="typedef">
      <type>struct T</type>
      <name>T</name>
      <anchorfile>Except_8h.html</anchorfile>
      <anchor>adec21d234619c8f0afbf0914249837b1</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct Except_Frame</type>
      <name>Except_Frame</name>
      <anchorfile>Except_8h.html</anchorfile>
      <anchor>ae9476933f67b88456bce2b1445851f6f</anchor>
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
      <anchor>a74a6737ffcaaf94b7c8137a651f9d94b</anchor>
      <arglist>(const T *e, const char *file, int line)</arglist>
    </member>
    <member kind="variable">
      <type>__thread Except_Frame *</type>
      <name>Except_stack</name>
      <anchorfile>Except_8h.html</anchorfile>
      <anchor>a83beb50c01f16c3fb874b4925b8e76ec</anchor>
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
    <member kind="define">
      <type>#define</type>
      <name>IOV_MAX</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a25080e819a36fcf9aede01a6e7298ea4</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_HAS_SENDFILE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a344295e98b08de11d12e7a2992d44bc5</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_HAS_SPLICE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>a7254b404e987f6bff7c2c562ad1cefbd</anchor>
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
      <name>SOCKET_MAX_POLL_EVENTS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ab6d7f45fcb5eae5fe42694e8e123cab4</anchor>
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
      <name>HASH_GOLDEN_RATIO</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ae5597cbeaa3012e797eb99aaf9570030</anchor>
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
      <name>SOCKET_DEFAULT_CONNECT_TIMEOUT_MS</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>aaa099b2101176b12abb25299a6ac5bd1</anchor>
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
      <name>SOCKET_DNS_REQUEST_HASH_SIZE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ad93bb14bccd4fd5d8f37a22b30a4c944</anchor>
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
      <name>SOCKET_PORT_STR_BUFSIZE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>aa5594e0bf4a9a492cc6e9dd7bcdae74c</anchor>
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
      <name>SOCKET_HAS_SO_DOMAIN</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>ac2c905681cea26eada867ab143d2c48d</anchor>
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
      <name>SOCKET_DNS_PIPE_BUFFER_SIZE</name>
      <anchorfile>SocketConfig_8h.html</anchorfile>
      <anchor>aabf88e7e79136014eb538ec90cf2a0f4</anchor>
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
  </compound>
  <compound kind="file">
    <name>SocketError.h</name>
    <path>include/core/</path>
    <filename>SocketError_8h.html</filename>
    <includes id="SocketLog_8h" name="SocketLog.h" local="yes" import="no" module="no" objc="no">core/SocketLog.h</includes>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_ERROR_BUFSIZE</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>ab28724709065957c1e13fd4c9b8e873a</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_ERROR_TRUNCATION_MARKER</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>a22d6df423f7c13e8d4f1b4192037f537</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_ERROR_TRUNCATION_SIZE</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>a6969c4f53c182cf7112aa6dd0421571f</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_ERROR_MAX_HOSTNAME</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>a25b54bdeec6e6e945e62eb8b6e5cc8e6</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_ERROR_MAX_MESSAGE</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>affaa8cfbcac4b123df8da0f9279a247f</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_LOG_COMPONENT</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>ae461bf5ddae6eda683926a6303af87f6</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_ERROR_FMT</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>adf114e63024eabf6e40f1ed7f89c79b8</anchor>
      <arglist>(fmt,...)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_ERROR_MSG</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>a1feea47474a6b6e939c442cdd7c42fdb</anchor>
      <arglist>(fmt,...)</arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_ENOMEM</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>a234dada5f4ad714b6c7d5b0bbdb6e286</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_EINVAL</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>aef414ad0ad23570de1d46006702ea335</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_ECONNREFUSED</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>af177b6c500b1dd0c533d3388339ba9f9</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_ETIMEDOUT</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>acaa8bd0edd40626f55e609edb16a99c9</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_EADDRINUSE</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>a4fcf3dfb4b98cdacaa2c5f81991f0cde</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_ENETUNREACH</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>a9389acfe091c635a5dedfe9f8875cb05</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_EHOSTUNREACH</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>aa13fca165325d7951760a812e42437a8</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_EPIPE</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>aa25bef791e389cebb192959272a2705d</anchor>
      <arglist></arglist>
    </member>
    <member kind="define">
      <type>#define</type>
      <name>SOCKET_ECONNRESET</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>ab8a20870f3b2306f710567014393d9d7</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>enum SocketErrorCode</type>
      <name>SocketErrorCode</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>aa2ffc4b7a7d85e05f1dcec54bea38b3d</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketErrorCode</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_NONE</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908ac605c1464f7a5fce4d2bf43db9604c9e</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EINVAL</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908ad7caea7b3de0e8a2d61efd49ed592127</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EACCES</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a9725ca6ddcb4e92ff1e9ecfdafd00ce7</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EADDRINUSE</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a08206822505583f83a334ade68139a75</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EADDRNOTAVAIL</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908ae812c8ca9ef677ef71a1d2421ce95135</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EAFNOSUPPORT</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a480e61645ca011af9282df6dacc4c2b3</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EAGAIN</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a00acb29ee302472a59b7e01718965ad3</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EALREADY</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908aebbc124b3c19fddedb3b8b45ab27f55c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EBADF</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a41de97b600a4478d3a512694d7c133e6</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_ECONNREFUSED</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908adfe88ce6edfed915da57d0ffae22b344</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_ECONNRESET</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a475f39fb23ebd0bec24b2e3c223e7a16</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EFAULT</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908ac3466349867e835c0004904a49a5db2f</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EHOSTUNREACH</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a32950d5582e28113e55151572acb71c8</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EINPROGRESS</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a9036b8ffc6fdf52e82ae24cc0b99f5fe</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EINTR</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a14dbd2cfb803fb498d9fe739b064ba46</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EISCONN</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908ac228d15b5fa5ec6fd8cd597f798cd3e9</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EMFILE</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a5e48f23169549a7d8bcbf436e4c69ad9</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_ENETUNREACH</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a4eea48e149cc5a90c78e7c73e0993840</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_ENOBUFS</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a36af864cb84c9e3b8e39a881ca5922bb</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_ENOMEM</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a06cc3f5f024f0e7fdee572949b186b4d</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_ENOTCONN</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908aac4990877a3f397ce4992bed66feaf3f</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_ENOTSOCK</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a4f7a06893610177371a7c901f5f7cbae</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EOPNOTSUPP</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a6cbb58736db2c84e95ffd6ab98c8c8cc</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EPIPE</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a0fd072c863033aa60d6d07aac9ac0fd8</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EPROTONOSUPPORT</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a3f9e0c3e6d07ffa0c67cf253fb70b543</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_ETIMEDOUT</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908aa0e56c1808b8ffda13e17400a31bc504</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_EWOULDBLOCK</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908ae027d95cf67fde3c178b082cf1770dc5</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_ERROR_UNKNOWN</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>acf807f3c720486767d282324cacd4908a77387cd59d0eaec78ac8af7a8d8c1b7e</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>Socket_GetLastError</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>ac71a25566cdc9e11eaecb16c966081db</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_geterrno</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>aacd3ef2f86186c451f2eb90cd490eae5</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>SocketErrorCode</type>
      <name>Socket_geterrorcode</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>a46f8d730d28e8c5cbd55e3cbe4c83945</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="variable">
      <type>__thread char</type>
      <name>socket_error_buf</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>a7f0b1d7d79898b2686bef06b51b2b545</anchor>
      <arglist>[SOCKET_ERROR_BUFSIZE]</arglist>
    </member>
    <member kind="variable">
      <type>__thread int</type>
      <name>socket_last_errno</name>
      <anchorfile>SocketError_8h.html</anchorfile>
      <anchor>a3c1fb6cfefccd611a21188d0f8d6a021</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketEvents.h</name>
    <path>include/core/</path>
    <filename>SocketEvents_8h.html</filename>
    <class kind="struct">SocketEventRecord</class>
    <member kind="typedef">
      <type>enum SocketEventType</type>
      <name>SocketEventType</name>
      <anchorfile>SocketEvents_8h.html</anchorfile>
      <anchor>ad6014622d0d04810b433c4c7d69a82ec</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketEventRecord</type>
      <name>SocketEventRecord</name>
      <anchorfile>SocketEvents_8h.html</anchorfile>
      <anchor>a29c0a610463ce770084d097f3d4bc28b</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>void(*</type>
      <name>SocketEventCallback</name>
      <anchorfile>SocketEvents_8h.html</anchorfile>
      <anchor>a3d3a15715d38d991d2e0227b21d70bf1</anchor>
      <arglist>)(void *userdata, const SocketEventRecord *event)</arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketEventType</name>
      <anchorfile>SocketEvents_8h.html</anchorfile>
      <anchor>a3d88a760170998089d33794edca8d1bf</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_EVENT_ACCEPTED</name>
      <anchorfile>SocketEvents_8h.html</anchorfile>
      <anchor>a3d88a760170998089d33794edca8d1bfa4865afb9d526d792c2afd8ca6168f2d7</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_EVENT_CONNECTED</name>
      <anchorfile>SocketEvents_8h.html</anchorfile>
      <anchor>a3d88a760170998089d33794edca8d1bfa007de01376b29a77df52df9f87676ad6</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_EVENT_DNS_TIMEOUT</name>
      <anchorfile>SocketEvents_8h.html</anchorfile>
      <anchor>a3d88a760170998089d33794edca8d1bfa54b71a4bbfbe3ef9fec249a2ce9f23f3</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_EVENT_POLL_WAKEUP</name>
      <anchorfile>SocketEvents_8h.html</anchorfile>
      <anchor>a3d88a760170998089d33794edca8d1bfa4b3179bc062ecb5767e4fd69509f654e</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketEvent_register</name>
      <anchorfile>SocketEvents_8h.html</anchorfile>
      <anchor>a2c2f3b63d230253cdd09e88a376a0c65</anchor>
      <arglist>(SocketEventCallback callback, void *userdata)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketEvent_unregister</name>
      <anchorfile>SocketEvents_8h.html</anchorfile>
      <anchor>a558726d00fc4c532a2ee0febce55c66e</anchor>
      <arglist>(SocketEventCallback callback, void *userdata)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketEvent_emit_accept</name>
      <anchorfile>SocketEvents_8h.html</anchorfile>
      <anchor>afa5f95ceb1326a7d8ec9f9ee73e43ae3</anchor>
      <arglist>(int fd, const char *peer_addr, int peer_port, const char *local_addr, int local_port)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketEvent_emit_connect</name>
      <anchorfile>SocketEvents_8h.html</anchorfile>
      <anchor>aa055221abd54d23cd82ec0b192c13efa</anchor>
      <arglist>(int fd, const char *peer_addr, int peer_port, const char *local_addr, int local_port)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketEvent_emit_dns_timeout</name>
      <anchorfile>SocketEvents_8h.html</anchorfile>
      <anchor>ac4791bcfc3ee22f39b3924782434a6f8</anchor>
      <arglist>(const char *host, int port)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketEvent_emit_poll_wakeup</name>
      <anchorfile>SocketEvents_8h.html</anchorfile>
      <anchor>a25ba2d0eb453e5e42f9c5ed8b8a64e09</anchor>
      <arglist>(int nfds, int timeout_ms)</arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketLog.h</name>
    <path>include/core/</path>
    <filename>SocketLog_8h.html</filename>
    <member kind="typedef">
      <type>enum SocketLogLevel</type>
      <name>SocketLogLevel</name>
      <anchorfile>SocketLog_8h.html</anchorfile>
      <anchor>a60c353a4ac7a38ca0b694cbfe4d8e4ea</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>void(*</type>
      <name>SocketLogCallback</name>
      <anchorfile>SocketLog_8h.html</anchorfile>
      <anchor>add820ca01810b616cfe1d6fef0cbf899</anchor>
      <arglist>)(void *userdata, SocketLogLevel level, const char *component, const char *message)</arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketLogLevel</name>
      <anchorfile>SocketLog_8h.html</anchorfile>
      <anchor>adf209a9f107e88a5df277fcc3e2641d1</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_LOG_TRACE</name>
      <anchorfile>SocketLog_8h.html</anchorfile>
      <anchor>adf209a9f107e88a5df277fcc3e2641d1a92a6d90e1c955ab3ad5fff67e93e969e</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_LOG_DEBUG</name>
      <anchorfile>SocketLog_8h.html</anchorfile>
      <anchor>adf209a9f107e88a5df277fcc3e2641d1afcef44613645b3fd4a45bf5b4bfdbba7</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_LOG_INFO</name>
      <anchorfile>SocketLog_8h.html</anchorfile>
      <anchor>adf209a9f107e88a5df277fcc3e2641d1a0c366302769a94f7e8f4d535f4cc5716</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_LOG_WARN</name>
      <anchorfile>SocketLog_8h.html</anchorfile>
      <anchor>adf209a9f107e88a5df277fcc3e2641d1ae3b46610cd2f65cecc4fa333a827212c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_LOG_ERROR</name>
      <anchorfile>SocketLog_8h.html</anchorfile>
      <anchor>adf209a9f107e88a5df277fcc3e2641d1a541aa883db8e38a0c52a2d7ccfb795b3</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_LOG_FATAL</name>
      <anchorfile>SocketLog_8h.html</anchorfile>
      <anchor>adf209a9f107e88a5df277fcc3e2641d1a675d837d7437c7792d86366a567acb57</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketLog_setcallback</name>
      <anchorfile>SocketLog_8h.html</anchorfile>
      <anchor>a1e1c2036c1e8e227409d3cb2dfab8fc2</anchor>
      <arglist>(SocketLogCallback callback, void *userdata)</arglist>
    </member>
    <member kind="function">
      <type>SocketLogCallback</type>
      <name>SocketLog_getcallback</name>
      <anchorfile>SocketLog_8h.html</anchorfile>
      <anchor>afb6f1052e2778e1b46a084ef457881dc</anchor>
      <arglist>(void **userdata)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketLog_levelname</name>
      <anchorfile>SocketLog_8h.html</anchorfile>
      <anchor>a6bf61f863971355d13751fa2d76bc1d4</anchor>
      <arglist>(SocketLogLevel level)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketLog_emit</name>
      <anchorfile>SocketLog_8h.html</anchorfile>
      <anchor>a1364e85e147f0f6d43c82b4ce3e326c1</anchor>
      <arglist>(SocketLogLevel level, const char *component, const char *message)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketLog_emitf</name>
      <anchorfile>SocketLog_8h.html</anchorfile>
      <anchor>a32c7a8dfa2948f777cdb62152fe2f6ac</anchor>
      <arglist>(SocketLogLevel level, const char *component, const char *fmt,...)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketLog_emitfv</name>
      <anchorfile>SocketLog_8h.html</anchorfile>
      <anchor>a9e7b0a943fc425eb44f0f22c7f2e304d</anchor>
      <arglist>(SocketLogLevel level, const char *component, const char *fmt, va_list args)</arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketMetrics.h</name>
    <path>include/core/</path>
    <filename>SocketMetrics_8h.html</filename>
    <class kind="struct">SocketMetricsSnapshot</class>
    <member kind="typedef">
      <type>enum SocketMetric</type>
      <name>SocketMetric</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>add1803a039a286e798d793441ffe335b</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketMetricsSnapshot</type>
      <name>SocketMetricsSnapshot</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a3e4edf21ba1b2068d043edbccde4e4d9</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumeration">
      <type></type>
      <name>SocketMetric</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5a</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_SOCKET_CONNECT_SUCCESS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aa7e78a886cdc9334f8a7b5f0df750fd63</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_SOCKET_CONNECT_FAILURE</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aa96d0ebae18f954ff3648e641e104f120</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_SOCKET_SHUTDOWN_CALL</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aa087373eb2e3fb13088acaa7f881b019c</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_DNS_REQUEST_SUBMITTED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aad1a05af32712ded666342aaaab4e56fb</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_DNS_REQUEST_COMPLETED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aac408edbfed5539bd89168cb9ad611f81</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_DNS_REQUEST_FAILED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aabeaeaceee778c6b88164609a4caf95ca</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_DNS_REQUEST_CANCELLED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aafbf83854162fbc828b0d116f1c2951e3</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_DNS_REQUEST_TIMEOUT</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aa7f1ef6385e38262925cabed4c0400a89</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_POLL_WAKEUPS</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aacbd607b50fdb083e406bfdb6e7121071</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_POLL_EVENTS_DISPATCHED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aa10fcaa4ca61ed9049d38588cfee7ae19</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_POOL_CONNECTIONS_ADDED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aaa72d81d8975ba0f5b168f3257cadccbc</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_POOL_CONNECTIONS_REMOVED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aa4f00b666298a269e694162e94de57eaf</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_POOL_CONNECTIONS_REUSED</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aa31fb10d34aa5b27a3bca9813c66699ea</anchor>
      <arglist></arglist>
    </member>
    <member kind="enumvalue">
      <name>SOCKET_METRIC_COUNT</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a422e43ad3ca4ce64261dda7879e73e5aaac38b493847141d2bfc1600c6b093fbb</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketMetrics_increment</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a84618017b97e3f0eeb3c4814e939a7b4</anchor>
      <arglist>(SocketMetric metric, unsigned long value)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketMetrics_getsnapshot</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>adf35517a39395522a5884f9d92c7086d</anchor>
      <arglist>(SocketMetricsSnapshot *snapshot)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketMetrics_reset</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>ab129aa3dd03bc8e5670da9abf0c41a47</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketMetrics_name</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>a6651459184d27e580841a193a5380bf8</anchor>
      <arglist>(SocketMetric metric)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketMetrics_count</name>
      <anchorfile>SocketMetrics_8h.html</anchorfile>
      <anchor>ae500ae3a4e6dc4b4ba83182988453cc7</anchor>
      <arglist>(void)</arglist>
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
      <type>struct T *</type>
      <name>T</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>a24514489b0962fafe8414bfae95aa268</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct Request_T *</type>
      <name>Request_T</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>abed9b1a79ca074827284111e500f8b22</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>void(*</type>
      <name>SocketDNS_Callback</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>af6b5779cfd95203ac45b76e5fccbfe20</anchor>
      <arglist>)(Request_T req, struct addrinfo *result, int error, void *data)</arglist>
    </member>
    <member kind="function">
      <type>T</type>
      <name>SocketDNS_new</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>a2b71ee0fa3c022f0342dd1bf9d2d9c14</anchor>
      <arglist>(void)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDNS_free</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>a5aa225e09d741aebee12bf0b5ab61e3c</anchor>
      <arglist>(T *dns)</arglist>
    </member>
    <member kind="function">
      <type>Request_T</type>
      <name>SocketDNS_resolve</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>a3da13a84fbce512f59c75d3cdf53a3f9</anchor>
      <arglist>(T dns, const char *host, int port, SocketDNS_Callback callback, void *data)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDNS_cancel</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>ab8a9f6d43d9a9044391e3d91a050e7bf</anchor>
      <arglist>(T dns, Request_T req)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketDNS_getmaxpending</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>a3dc9c864dd199a69a6a3d186439219a0</anchor>
      <arglist>(T dns)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDNS_setmaxpending</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>aedb55dea32906adadb740f9bc554768c</anchor>
      <arglist>(T dns, size_t max_pending)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDNS_gettimeout</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>a138bb4cdede6de597d17450f19f4530c</anchor>
      <arglist>(T dns)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDNS_settimeout</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>a7742ae0f0a34ecc0188df415e88a3c79</anchor>
      <arglist>(T dns, int timeout_ms)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDNS_pollfd</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>a5bad005b6f546b3014c95735b5503020</anchor>
      <arglist>(T dns)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDNS_check</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>abd6710a0d5f406255e39a6ab44fa7603</anchor>
      <arglist>(T dns)</arglist>
    </member>
    <member kind="function">
      <type>struct addrinfo *</type>
      <name>SocketDNS_getresult</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>a9bf4ce3f4cc95b946d7a3418a74da3df</anchor>
      <arglist>(T dns, Request_T req)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDNS_geterror</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>a2e368f3eae045faa5d591d9279c9ce2e</anchor>
      <arglist>(T dns, Request_T req)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDNS_request_settimeout</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>a28f34d74dafd3ea4c4c05dbd1844fa50</anchor>
      <arglist>(T dns, Request_T req, int timeout_ms)</arglist>
    </member>
    <member kind="function">
      <type>Request_T</type>
      <name>SocketDNS_create_completed_request</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>a9b5cb57084527d92a827b62b4adfcd94</anchor>
      <arglist>(T dns, struct addrinfo *result, int port)</arglist>
    </member>
    <member kind="variable">
      <type>Except_T</type>
      <name>SocketDNS_Failed</name>
      <anchorfile>SocketDNS_8h.html</anchorfile>
      <anchor>a152c227261ddef33b34fb3a3578d8a5e</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketPoll.h</name>
    <path>include/poll/</path>
    <filename>SocketPoll_8h.html</filename>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="Socket_8h" name="Socket.h" local="yes" import="no" module="no" objc="no">socket/Socket.h</includes>
    <class kind="struct">SocketEvent</class>
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
      <type>struct T *</type>
      <name>T</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>a24514489b0962fafe8414bfae95aa268</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketEvent</type>
      <name>SocketEvent_T</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>a6473a43b209b9b48b6acee00f1e1bb01</anchor>
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
      <type>T</type>
      <name>SocketPoll_new</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>aae64ff18791dbd4acacc3c5ee6f4f710</anchor>
      <arglist>(int maxevents)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPoll_free</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>ac93edae1d8976b9f30f1dff1d18ca62b</anchor>
      <arglist>(T *poll)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPoll_add</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>a13c47bc69be50329371df6dd5e8bee70</anchor>
      <arglist>(T poll, Socket_T socket, unsigned events, void *data)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPoll_mod</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>a1430c3ad9eea988697e1d6c32ceef909</anchor>
      <arglist>(T poll, Socket_T socket, unsigned events, void *data)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPoll_del</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>a1490cf11e085381381480a18c889b3b2</anchor>
      <arglist>(T poll, Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketPoll_getdefaulttimeout</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>a54dfccc1496c17f97bdca464e3ebf6e4</anchor>
      <arglist>(T poll)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPoll_setdefaulttimeout</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>a5b94934d4bdf73131cb851ef356da102</anchor>
      <arglist>(T poll, int timeout)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketPoll_wait</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>a838225b94dfd40f308c49482bca2e7fd</anchor>
      <arglist>(T poll, SocketEvent_T **events, int timeout)</arglist>
    </member>
    <member kind="variable">
      <type>Except_T</type>
      <name>SocketPoll_Failed</name>
      <anchorfile>SocketPoll_8h.html</anchorfile>
      <anchor>a86a0b655cec6077638e85d6bbb8da574</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketPoll_backend.h</name>
    <path>include/poll/</path>
    <filename>SocketPoll__backend_8h.html</filename>
    <includes id="Socket_8h" name="Socket.h" local="yes" import="no" module="no" objc="no">socket/Socket.h</includes>
    <includes id="SocketPoll_8h" name="SocketPoll.h" local="yes" import="no" module="no" objc="no">poll/SocketPoll.h</includes>
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
    <includes id="Socket_8h" name="Socket.h" local="yes" import="no" module="no" objc="no">socket/Socket.h</includes>
    <includes id="SocketBuf_8h" name="SocketBuf.h" local="yes" import="no" module="no" objc="no">socket/SocketBuf.h</includes>
    <member kind="define">
      <type>#define</type>
      <name>T</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a0acb682b8260ab1c60b918599864e2e5</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct T *</type>
      <name>T</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a24514489b0962fafe8414bfae95aa268</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct Connection *</type>
      <name>Connection_T</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a424a0221f5eef0991c244d83d02d8b2c</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>T</type>
      <name>SocketPool_new</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a74388803e1d08380acf64f7abbd00414</anchor>
      <arglist>(Arena_T arena, size_t maxconns, size_t bufsize)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPool_free</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a4d90769ccea1288fb30e50ec18e4f0c4</anchor>
      <arglist>(T *pool)</arglist>
    </member>
    <member kind="function">
      <type>Connection_T</type>
      <name>SocketPool_get</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a85a96cfcffc6de6cfce0f3571e7adb18</anchor>
      <arglist>(T pool, Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>Connection_T</type>
      <name>SocketPool_add</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a4b466dc021839d7eeec5f1ab320a7715</anchor>
      <arglist>(T pool, Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPool_remove</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a2a5f1ef514ea1ccbe5133b4eca4f5dfb</anchor>
      <arglist>(T pool, Socket_T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPool_cleanup</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a7087165181060dbdd9e37d5ff5e92c85</anchor>
      <arglist>(T pool, time_t idle_timeout)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketPool_count</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a624d0bec224f70a7ac067a891c258b45</anchor>
      <arglist>(T pool)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPool_foreach</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a2fa63691a53322bc10f6e11d75982705</anchor>
      <arglist>(T pool, void(*func)(Connection_T, void *), void *arg)</arglist>
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
    <member kind="variable">
      <type>Except_T</type>
      <name>SocketPool_Failed</name>
      <anchorfile>SocketPool_8h.html</anchorfile>
      <anchor>a0e9aa7d82b00e7c8c8899029ddfa5a67</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>Socket.h</name>
    <path>include/socket/</path>
    <filename>Socket_8h.html</filename>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="SocketDNS_8h" name="SocketDNS.h" local="yes" import="no" module="no" objc="no">dns/SocketDNS.h</includes>
    <class kind="struct">SocketTimeouts</class>
    <member kind="define">
      <type>#define</type>
      <name>T</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a0acb682b8260ab1c60b918599864e2e5</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct T *</type>
      <name>T</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a24514489b0962fafe8414bfae95aa268</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct SocketTimeouts</type>
      <name>SocketTimeouts_T</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a3debcc5506f258fc65706fa6455f1a05</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>T</type>
      <name>Socket_new</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a48a12cae4cd51b880e7927a22ab82641</anchor>
      <arglist>(int domain, int type, int protocol)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketPair_new</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a98ea06a38e059da3259baf352f74bf15</anchor>
      <arglist>(int type, T *socket1, T *socket2)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_free</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a221d64c385da1687c988f7ffeb67697d</anchor>
      <arglist>(T *socket)</arglist>
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
      <anchor>aa20213f48dd43a3129c9c9f3b03c9854</anchor>
      <arglist>(T socket, const char *host, int port)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_listen</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>afb9495f689b00ffc14f393d8173c98a4</anchor>
      <arglist>(T socket, int backlog)</arglist>
    </member>
    <member kind="function">
      <type>T</type>
      <name>Socket_accept</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>af21e0268831aeee010b41d28ac61b464</anchor>
      <arglist>(T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_connect</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a6425897f52a2ee266a88f674de18ddd3</anchor>
      <arglist>(T socket, const char *host, int port)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>Socket_send</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>ab72bbc8824c7adf5aa55af88b784b9d0</anchor>
      <arglist>(T socket, const void *buf, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>Socket_recv</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>af5ec96ac4f3517384ca22c1ef50d646a</anchor>
      <arglist>(T socket, void *buf, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>Socket_sendall</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>afa7bde7e1ab3130c4674e0c7bcb94ea8</anchor>
      <arglist>(T socket, const void *buf, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>Socket_recvall</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>af21e86cdf39ae94b27c74b19e6c29c28</anchor>
      <arglist>(T socket, void *buf, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>Socket_sendv</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>ab675b5c1dbc4531aa0c1fc289475823b</anchor>
      <arglist>(T socket, const struct iovec *iov, int iovcnt)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>Socket_recvv</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>af2a76fbae389a57c9a0389a691f90766</anchor>
      <arglist>(T socket, struct iovec *iov, int iovcnt)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>Socket_sendvall</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>abb71b00d768e2285da07038dd6144e8e</anchor>
      <arglist>(T socket, const struct iovec *iov, int iovcnt)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>Socket_recvvall</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>ac157beed03142752182021261a263671</anchor>
      <arglist>(T socket, struct iovec *iov, int iovcnt)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>Socket_sendfile</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>acb117caeae8c8c1ce3b50a0568be35da</anchor>
      <arglist>(T socket, int file_fd, off_t *offset, size_t count)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>Socket_sendfileall</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a618437cdccde7f979f09307b99ad2b73</anchor>
      <arglist>(T socket, int file_fd, off_t *offset, size_t count)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>Socket_sendmsg</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>ab76433dc005a43612f7ce752d01884e3</anchor>
      <arglist>(T socket, const struct msghdr *msg, int flags)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>Socket_recvmsg</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a3aec26ecfd893efb26b95ec741c46656</anchor>
      <arglist>(T socket, struct msghdr *msg, int flags)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_setnonblocking</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a08886d4588009f86d4e5778363fd379e</anchor>
      <arglist>(T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_setreuseaddr</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>aa9ad5151bf257e772cf3cfb32f4b13bb</anchor>
      <arglist>(T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_setreuseport</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a0ce3128becb062e541c093f2277f03fe</anchor>
      <arglist>(T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_settimeout</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a12e9038dc4c692fb378b28d221bf7236</anchor>
      <arglist>(T socket, int timeout_sec)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_setkeepalive</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a168b58f8fb7cb65ddb1a417c79cf0d6c</anchor>
      <arglist>(T socket, int idle, int interval, int count)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_setnodelay</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a228f425d55147dafd5e29799d5c03af0</anchor>
      <arglist>(T socket, int nodelay)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_gettimeout</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>ac2179b048d3749e7a8962f0863d5d9d0</anchor>
      <arglist>(T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_getkeepalive</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a480a8c19b4cbdb1131da3c770cd4aa84</anchor>
      <arglist>(T socket, int *idle, int *interval, int *count)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_getnodelay</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>af0b7b670397c95fa75e613ecb593c8db</anchor>
      <arglist>(T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_getrcvbuf</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a9262ae6cbe3a40b63967ba700a011016</anchor>
      <arglist>(T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_getsndbuf</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>ad9c1ac9908662a224b8c818e6d55f0ec</anchor>
      <arglist>(T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_setrcvbuf</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>ac74d806db96f89a2e08338ddf59ad16a</anchor>
      <arglist>(T socket, int size)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_setsndbuf</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>aeecc754a971fa566e2b396d9025b961a</anchor>
      <arglist>(T socket, int size)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_setcongestion</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a914404cbf71b91e14240ae961b30df73</anchor>
      <arglist>(T socket, const char *algorithm)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_getcongestion</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a4e65e3db5bd05c0ff61ba863b9b8732e</anchor>
      <arglist>(T socket, char *algorithm, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_setfastopen</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a2a60e026631198fa2ee225a74565afd5</anchor>
      <arglist>(T socket, int enable)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_getfastopen</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a0734cbd1a3c15bd40d84878102f4cb3f</anchor>
      <arglist>(T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_setusertimeout</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>af4873c11dcc702d693ee8bc930e61387</anchor>
      <arglist>(T socket, unsigned int timeout_ms)</arglist>
    </member>
    <member kind="function">
      <type>unsigned int</type>
      <name>Socket_getusertimeout</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a5fa721bd54b028d6e92cc459c76b96ef</anchor>
      <arglist>(T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_isconnected</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a4c832b75a949f8716f52b2a25fa54071</anchor>
      <arglist>(T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_isbound</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a87607a3fb7bb47442e3ca5c8664cadf3</anchor>
      <arglist>(T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_islistening</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>aaf51b653c9d3ad62e91c87ffb8977459</anchor>
      <arglist>(T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_shutdown</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a04bb2a02d1e1cde1316ebb24bc6d33ee</anchor>
      <arglist>(T socket, int how)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_setcloexec</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>adef76ca110b35a97542a01abd96b56d3</anchor>
      <arglist>(T socket, int enable)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_timeouts_get</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a590cc74ce83a3ed92afa6f50bb6de788</anchor>
      <arglist>(const T socket, SocketTimeouts_T *timeouts)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_timeouts_set</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a617c15d23eeff4b6b91aca2d1993a407</anchor>
      <arglist>(T socket, const SocketTimeouts_T *timeouts)</arglist>
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
      <type>int</type>
      <name>Socket_fd</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>ac3a53c77fcff7863928e76e3f1d853eb</anchor>
      <arglist>(const T socket)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>Socket_getpeeraddr</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a8058df51c22be9a27f033e320020226f</anchor>
      <arglist>(const T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_getpeerport</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a4debb3b40b2e412f4e6d309d907870ec</anchor>
      <arglist>(const T socket)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>Socket_getlocaladdr</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a8781ea1a54f7f756e2b17ace876b0d82</anchor>
      <arglist>(const T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_getlocalport</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a06481f8a3cb3d7bdf6c3f659d2b8f578</anchor>
      <arglist>(const T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_bind_unix</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>af0950e48831143dd9b3915939e2ef345</anchor>
      <arglist>(T socket, const char *path)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_connect_unix</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a9687684ea5825b2f45fae02f115db74d</anchor>
      <arglist>(T socket, const char *path)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_getpeerpid</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>ac12a023e06a98edb7ccb24a1dfb00a23</anchor>
      <arglist>(const T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_getpeeruid</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a64ebfd0c98dd5f04ce68019c730d03c9</anchor>
      <arglist>(const T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>Socket_getpeergid</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a47d4f0341dee9e90eacb2bb242902999</anchor>
      <arglist>(const T socket)</arglist>
    </member>
    <member kind="function">
      <type>SocketDNS_Request_T</type>
      <name>Socket_bind_async</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>aead803904d888461d2ae5f372ffd10c7</anchor>
      <arglist>(SocketDNS_T dns, T socket, const char *host, int port)</arglist>
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
      <anchor>abbe9f97d6fd318de336ef8857532f602</anchor>
      <arglist>(SocketDNS_T dns, T socket, const char *host, int port)</arglist>
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
      <anchor>adf837d398667975ee992c77abd3af593</anchor>
      <arglist>(T socket, struct addrinfo *res)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>Socket_connect_with_addrinfo</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a4ae9a4a80d9034ea713f3e41c428131e</anchor>
      <arglist>(T socket, struct addrinfo *res)</arglist>
    </member>
    <member kind="variable">
      <type>Except_T</type>
      <name>Socket_Failed</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>a84516221c8fd2d4bdfde8d05eaf42cc6</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>Except_T</type>
      <name>Socket_Closed</name>
      <anchorfile>Socket_8h.html</anchorfile>
      <anchor>ae149a16c5ec76f277f565783bc39469e</anchor>
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
      <type>struct T *</type>
      <name>T</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>a24514489b0962fafe8414bfae95aa268</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>T</type>
      <name>SocketBuf_new</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>a3bf21f035828a8427ab9190fcb864062</anchor>
      <arglist>(Arena_T arena, size_t capacity)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketBuf_release</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>adcf958f842426764dc619f941b976c4a</anchor>
      <arglist>(T *buf)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketBuf_write</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>a2ab0fc2f53dfd288874bc101611397a8</anchor>
      <arglist>(T buf, const void *data, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketBuf_read</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>a52bdacbb4bdbb33f791a3b42041d0978</anchor>
      <arglist>(T buf, void *data, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketBuf_peek</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>a0de33b1ad02cd2b92da27de821e22eb1</anchor>
      <arglist>(T buf, void *data, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketBuf_consume</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>a2b0f1f39925ead88382c8fa3a376ce1a</anchor>
      <arglist>(T buf, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketBuf_available</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>a1c24cb001b8719e744e7b23102cf9cbf</anchor>
      <arglist>(const T buf)</arglist>
    </member>
    <member kind="function">
      <type>size_t</type>
      <name>SocketBuf_space</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>a7fbe3e226b9ca23669dff9dc45ec1fec</anchor>
      <arglist>(const T buf)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketBuf_empty</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>aa095538b04982085714da1b0c8536ed5</anchor>
      <arglist>(const T buf)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketBuf_full</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>afdaed887af908cf955504cd0258cf26a</anchor>
      <arglist>(const T buf)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketBuf_clear</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>a1901d45150be93f028ceb17fae25a9a9</anchor>
      <arglist>(T buf)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketBuf_secureclear</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>af23c64b3d936f901d970330ec945f9e5</anchor>
      <arglist>(T buf)</arglist>
    </member>
    <member kind="function">
      <type>const void *</type>
      <name>SocketBuf_readptr</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>af677e1247f6f8e3af0556dd9403afc3f</anchor>
      <arglist>(T buf, size_t *len)</arglist>
    </member>
    <member kind="function">
      <type>void *</type>
      <name>SocketBuf_writeptr</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>a87441b4a7a435eba0aef8d0ba1617a5d</anchor>
      <arglist>(T buf, size_t *len)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketBuf_written</name>
      <anchorfile>SocketBuf_8h.html</anchorfile>
      <anchor>ac317b47fb64444fbadc087018059ad5a</anchor>
      <arglist>(T buf, size_t len)</arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketCommon.h</name>
    <path>include/socket/</path>
    <filename>SocketCommon_8h.html</filename>
    <includes id="Arena_8h" name="Arena.h" local="yes" import="no" module="no" objc="no">core/Arena.h</includes>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <includes id="SocketConfig_8h" name="SocketConfig.h" local="yes" import="no" module="no" objc="no">core/SocketConfig.h</includes>
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
    <member kind="variable">
      <type>Except_T</type>
      <name>Socket_Failed</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>a84516221c8fd2d4bdfde8d05eaf42cc6</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>Except_T</type>
      <name>SocketDgram_Failed</name>
      <anchorfile>SocketCommon_8h.html</anchorfile>
      <anchor>ad4aff23af59c3312be6d886a029b80a5</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>SocketDgram.h</name>
    <path>include/socket/</path>
    <filename>SocketDgram_8h.html</filename>
    <includes id="Except_8h" name="Except.h" local="yes" import="no" module="no" objc="no">core/Except.h</includes>
    <member kind="define">
      <type>#define</type>
      <name>T</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a0acb682b8260ab1c60b918599864e2e5</anchor>
      <arglist></arglist>
    </member>
    <member kind="typedef">
      <type>struct T *</type>
      <name>T</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a24514489b0962fafe8414bfae95aa268</anchor>
      <arglist></arglist>
    </member>
    <member kind="function">
      <type>T</type>
      <name>SocketDgram_new</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a5f43b6d23b1541f9779c401be7c457a9</anchor>
      <arglist>(int domain, int protocol)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDgram_free</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>ab3b092057e1cc0df4b645d749571569a</anchor>
      <arglist>(T *socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDgram_bind</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>ac461e869db9bcc13afce9670f50befc2</anchor>
      <arglist>(T socket, const char *host, int port)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDgram_connect</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a09d2f34ab008429afe4706f6a0080c63</anchor>
      <arglist>(T socket, const char *host, int port)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketDgram_sendto</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a1a5b340d1fcc92169e6205a94afd7de2</anchor>
      <arglist>(T socket, const void *buf, size_t len, const char *host, int port)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketDgram_recvfrom</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>aacd858e5105c8899e691c06f10cead6c</anchor>
      <arglist>(T socket, void *buf, size_t len, char *host, size_t host_len, int *port)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketDgram_send</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a29f7bba242b53faa2e1d2ebbb77b484a</anchor>
      <arglist>(T socket, const void *buf, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketDgram_recv</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a36406c4a6e9073a01665493fcf56684f</anchor>
      <arglist>(T socket, void *buf, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketDgram_sendall</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>af2211ccb0fe4e9c39936b9214dfcad57</anchor>
      <arglist>(T socket, const void *buf, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketDgram_recvall</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>acdf18d210c55d4f6683cb714445d6298</anchor>
      <arglist>(T socket, void *buf, size_t len)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketDgram_sendv</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a4cdff701bb596a34edbad25c1c3fe0e4</anchor>
      <arglist>(T socket, const struct iovec *iov, int iovcnt)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketDgram_recvv</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a20bdc35f196074cf7e79d48efe175ff4</anchor>
      <arglist>(T socket, struct iovec *iov, int iovcnt)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketDgram_sendvall</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a8583cc87120211fb72fe2475beefd8a8</anchor>
      <arglist>(T socket, const struct iovec *iov, int iovcnt)</arglist>
    </member>
    <member kind="function">
      <type>ssize_t</type>
      <name>SocketDgram_recvvall</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a1bee9ae981b2503ee294007d9686563c</anchor>
      <arglist>(T socket, struct iovec *iov, int iovcnt)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDgram_setnonblocking</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a40000e2980258b9c224d03d3bdf9ceaf</anchor>
      <arglist>(T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDgram_setreuseaddr</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a0c2d80edfb8a0792d40312cd6aa58fc7</anchor>
      <arglist>(T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDgram_setreuseport</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a3697007ec7de1035909fb147458e1f8c</anchor>
      <arglist>(T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDgram_setbroadcast</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a2029cc165b79dff7810c98406ee5c8d2</anchor>
      <arglist>(T socket, int enable)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDgram_joinmulticast</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>aa6f2048ba657fe825576360cc1b77200</anchor>
      <arglist>(T socket, const char *group, const char *interface)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDgram_leavemulticast</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a88b83d6cc970818b6a3d65e775f14efd</anchor>
      <arglist>(T socket, const char *group, const char *interface)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDgram_setttl</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a8e6f537e879fee3ef5e16ba91cd05ecb</anchor>
      <arglist>(T socket, int ttl)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDgram_settimeout</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a5232bf6345f850cd58346de4bc91f695</anchor>
      <arglist>(T socket, int timeout_sec)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDgram_gettimeout</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a113f3bfb0f56205733f4820ab6884ba1</anchor>
      <arglist>(T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDgram_getbroadcast</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a938c95777017c7d1c89bafe4a0b6459b</anchor>
      <arglist>(T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDgram_getttl</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a6bd9e8206535e29ac2896c9bde921ffb</anchor>
      <arglist>(T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDgram_getrcvbuf</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a01f5f370c2ebdf629a0361e3a40d73fb</anchor>
      <arglist>(T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDgram_getsndbuf</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a716cf462174c4bbadd30919ef5c44bb0</anchor>
      <arglist>(T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDgram_isconnected</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>ab94c1cd04fb37a553c8811d305142a48</anchor>
      <arglist>(T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDgram_isbound</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a467564f594aa8e9779956218761ebf2d</anchor>
      <arglist>(T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDgram_fd</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a6e51cdf58e57c98b365c962528718c89</anchor>
      <arglist>(const T socket)</arglist>
    </member>
    <member kind="function">
      <type>const char *</type>
      <name>SocketDgram_getlocaladdr</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>ab9b56e925b77999485bc030e8523406c</anchor>
      <arglist>(const T socket)</arglist>
    </member>
    <member kind="function">
      <type>int</type>
      <name>SocketDgram_getlocalport</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a2514999c145334d862fae3d3372426e1</anchor>
      <arglist>(const T socket)</arglist>
    </member>
    <member kind="function">
      <type>void</type>
      <name>SocketDgram_setcloexec</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>a9410288d1d7a829a135ccad7a7948db1</anchor>
      <arglist>(T socket, int enable)</arglist>
    </member>
    <member kind="variable">
      <type>Except_T</type>
      <name>SocketDgram_Failed</name>
      <anchorfile>SocketDgram_8h.html</anchorfile>
      <anchor>ad4aff23af59c3312be6d886a029b80a5</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="file">
    <name>README.md</name>
    <path></path>
    <filename>README_8md.html</filename>
  </compound>
  <compound kind="struct">
    <name>Except_Frame</name>
    <filename>structExcept__Frame.html</filename>
    <member kind="variable">
      <type>Except_Frame *</type>
      <name>prev</name>
      <anchorfile>structExcept__Frame.html</anchorfile>
      <anchor>a4a5323a9c98b198d171a7f0409f3bbae</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>jmp_buf</type>
      <name>env</name>
      <anchorfile>structExcept__Frame.html</anchorfile>
      <anchor>abce4b8de2bbf7d6fb6ef52d618309264</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const char *</type>
      <name>file</name>
      <anchorfile>structExcept__Frame.html</anchorfile>
      <anchor>a4c8d0ea0c9437ede53e8703feefe0dc6</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>line</name>
      <anchorfile>structExcept__Frame.html</anchorfile>
      <anchor>aff1099dac68f6f3b8392f2ebe5c8341f</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const T *</type>
      <name>exception</name>
      <anchorfile>structExcept__Frame.html</anchorfile>
      <anchor>af94963d421b72862ad98d190f02919fe</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="interface">
    <name>Interface</name>
    <filename>interfaceInterface.html</filename>
  </compound>
  <compound kind="protocol">
    <name>Protocol-p</name>
    <filename>protocolProtocol-p.html</filename>
  </compound>
  <compound kind="struct">
    <name>SocketEvent</name>
    <filename>structSocketEvent.html</filename>
    <member kind="variable">
      <type>Socket_T</type>
      <name>socket</name>
      <anchorfile>structSocketEvent.html</anchorfile>
      <anchor>a609a22a6854c4771febb24b8642f8b0b</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>void *</type>
      <name>data</name>
      <anchorfile>structSocketEvent.html</anchorfile>
      <anchor>af4aeacc9896cef31c5a5c9afc9e1061c</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>unsigned</type>
      <name>events</name>
      <anchorfile>structSocketEvent.html</anchorfile>
      <anchor>a0e8eac7870fd0ca415bca9e451b1c968</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketEventRecord</name>
    <filename>structSocketEventRecord.html</filename>
    <member kind="variable">
      <type>SocketEventType</type>
      <name>type</name>
      <anchorfile>structSocketEventRecord.html</anchorfile>
      <anchor>a2ef831e31103812b3c31c099cea65c2c</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const char *</type>
      <name>component</name>
      <anchorfile>structSocketEventRecord.html</anchorfile>
      <anchor>a1ce3b46734d680830bf0ce719bc55f7a</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>fd</name>
      <anchorfile>structSocketEventRecord.html</anchorfile>
      <anchor>a97e68a348cf1c03285373831ec514140</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const char *</type>
      <name>peer_addr</name>
      <anchorfile>structSocketEventRecord.html</anchorfile>
      <anchor>ae021d59d3adb38d71c2ba26efcce7338</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>peer_port</name>
      <anchorfile>structSocketEventRecord.html</anchorfile>
      <anchor>a42fb5110ec062ac83a9b36e898b59a75</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const char *</type>
      <name>local_addr</name>
      <anchorfile>structSocketEventRecord.html</anchorfile>
      <anchor>a0cea70562d6b7c2652b73ca802cbb02d</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>local_port</name>
      <anchorfile>structSocketEventRecord.html</anchorfile>
      <anchor>a52d282239d83a254db8d3503fb26c0fb</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>struct SocketEventRecord::@1::@2</type>
      <name>connection</name>
      <anchorfile>structSocketEventRecord.html</anchorfile>
      <anchor>a6277f2004c9c26edcaa6abbaf9c1a970</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>const char *</type>
      <name>host</name>
      <anchorfile>structSocketEventRecord.html</anchorfile>
      <anchor>a18885f3e5dede775985597bcffd144e0</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>port</name>
      <anchorfile>structSocketEventRecord.html</anchorfile>
      <anchor>a7f7340908cdff2dd85aa2d6e6ca6ed7a</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>struct SocketEventRecord::@1::@3</type>
      <name>dns</name>
      <anchorfile>structSocketEventRecord.html</anchorfile>
      <anchor>af33711caebc2c989291dd9441c893b27</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>nfds</name>
      <anchorfile>structSocketEventRecord.html</anchorfile>
      <anchor>af43951ea25c34d38bfe5c7f8bef9a159</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>timeout_ms</name>
      <anchorfile>structSocketEventRecord.html</anchorfile>
      <anchor>a86d7adcdaa97718936b5d5c1f3234393</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>struct SocketEventRecord::@1::@4</type>
      <name>poll</name>
      <anchorfile>structSocketEventRecord.html</anchorfile>
      <anchor>ae744331ff3191371ebce1f51984a2567</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>union SocketEventRecord::@1</type>
      <name>data</name>
      <anchorfile>structSocketEventRecord.html</anchorfile>
      <anchor>a46454b1b915024075996facfd55e75a2</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketMetricsSnapshot</name>
    <filename>structSocketMetricsSnapshot.html</filename>
    <member kind="variable">
      <type>unsigned long long</type>
      <name>values</name>
      <anchorfile>structSocketMetricsSnapshot.html</anchorfile>
      <anchor>ad4bec382c27642da1ce45dcf676684e6</anchor>
      <arglist>[SOCKET_METRIC_COUNT]</arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>SocketTimeouts</name>
    <filename>structSocketTimeouts.html</filename>
    <member kind="variable">
      <type>int</type>
      <name>connect_timeout_ms</name>
      <anchorfile>structSocketTimeouts.html</anchorfile>
      <anchor>a53af6ea34a5afb83e97dc205e88a5df0</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>dns_timeout_ms</name>
      <anchorfile>structSocketTimeouts.html</anchorfile>
      <anchor>a736142191c923c26705b75234d09bc65</anchor>
      <arglist></arglist>
    </member>
    <member kind="variable">
      <type>int</type>
      <name>operation_timeout_ms</name>
      <anchorfile>structSocketTimeouts.html</anchorfile>
      <anchor>a14d40ecee50f5401530d5034866ed127</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="struct">
    <name>T</name>
    <filename>structT.html</filename>
    <member kind="variable">
      <type>const char *</type>
      <name>reason</name>
      <anchorfile>structT.html</anchorfile>
      <anchor>a8984328ed338fdfb0fb2641c9451d431</anchor>
      <arglist></arglist>
    </member>
  </compound>
  <compound kind="page">
    <name>index</name>
    <title>Socket Library</title>
    <filename>index.html</filename>
    <docanchor file="index.html" title="Socket Library">md_README</docanchor>
  </compound>
</tagfile>
