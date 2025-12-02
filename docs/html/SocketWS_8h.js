var SocketWS_8h =
[
    [ "SocketWS_Config", "SocketWS_8h.html#structSocketWS__Config", [
      [ "deflate_max_window_bits", "SocketWS_8h.html#aaaf3a4b3929373f6d34097ee3360edd7", null ],
      [ "deflate_no_context_takeover", "SocketWS_8h.html#a6990f2e1597412e0fd8101407944f51d", null ],
      [ "enable_permessage_deflate", "SocketWS_8h.html#a5b4cb5b34e0960b4964eec24547ebe29", null ],
      [ "max_fragments", "SocketWS_8h.html#ac3b980e3936f7e3763e4a6c2c5e466d3", null ],
      [ "max_frame_size", "SocketWS_8h.html#a622a5556ac8a0b6888819a40851a11fd", null ],
      [ "max_message_size", "SocketWS_8h.html#a2100320f9508ad064f387dc26bbef62f", null ],
      [ "ping_interval_ms", "SocketWS_8h.html#a376fe666ac3f3654087792edae1ce054", null ],
      [ "ping_timeout_ms", "SocketWS_8h.html#a4ca65b7722835ec62374763fa625596f", null ],
      [ "role", "SocketWS_8h.html#aa895fa89617603768d89d043b41b3bc9", null ],
      [ "subprotocols", "SocketWS_8h.html#a72bb5bfa2a49c7bdd770303635e0e49d", null ],
      [ "validate_utf8", "SocketWS_8h.html#a1873fe17fa2f2d2d3c0d16cbfbcfc3f1", null ]
    ] ],
    [ "SocketWS_Frame", "SocketWS_8h.html#structSocketWS__Frame", [
      [ "fin", "SocketWS_8h.html#a54987d666286860044d3f6bd3f513d85", null ],
      [ "opcode", "SocketWS_8h.html#a3316616d6bd9228919cf2eac7df3c780", null ],
      [ "payload", "SocketWS_8h.html#ab17b0ddda509759d90d3c7f5aa09144b", null ],
      [ "payload_len", "SocketWS_8h.html#ab6da903ab04e63a093ed73f861b7d5c8", null ],
      [ "rsv1", "SocketWS_8h.html#a40b506b65f89a2c8d96acecf636c5191", null ]
    ] ],
    [ "SocketWS_Message", "SocketWS_8h.html#structSocketWS__Message", [
      [ "data", "SocketWS_8h.html#af7c3a0707d0a280d08242b3668e4bc14", null ],
      [ "len", "SocketWS_8h.html#a48e400e0db4731142c0baa97427de817", null ],
      [ "type", "SocketWS_8h.html#acb9416eb06a0a6e95260acebee3544b2", null ]
    ] ],
    [ "T", "SocketWS_8h.html#a0acb682b8260ab1c60b918599864e2e5", null ],
    [ "SocketPoll_T", "SocketWS_8h.html#af9e4be8bc025aedb61cc0b77e8926312", null ],
    [ "SocketWS_T", "SocketWS_8h.html#a62eac457c36851d5e4a184e1a5602555", null ],
    [ "SocketWS_CloseCode", "SocketWS_8h.html#a386c437e966aeaeb091d1d81c0e77b13", [
      [ "WS_CLOSE_NORMAL", "SocketWS_8h.html#a386c437e966aeaeb091d1d81c0e77b13a297d5e27c1ad4b7c6660b005308a5f30", null ],
      [ "WS_CLOSE_GOING_AWAY", "SocketWS_8h.html#a386c437e966aeaeb091d1d81c0e77b13a9bb565620ebf9a5c79afa6281a253b6d", null ],
      [ "WS_CLOSE_PROTOCOL_ERROR", "SocketWS_8h.html#a386c437e966aeaeb091d1d81c0e77b13aaf641b4eedfe849aeed35a84f61709bf", null ],
      [ "WS_CLOSE_UNSUPPORTED_DATA", "SocketWS_8h.html#a386c437e966aeaeb091d1d81c0e77b13a2852358b8d5151feda017ab29972f16e", null ],
      [ "WS_CLOSE_NO_STATUS", "SocketWS_8h.html#a386c437e966aeaeb091d1d81c0e77b13a859b46a0f5a7a29e664a22a1c1c86919", null ],
      [ "WS_CLOSE_ABNORMAL", "SocketWS_8h.html#a386c437e966aeaeb091d1d81c0e77b13aa5b58d4bfbfbeb754edc424760ff4b04", null ],
      [ "WS_CLOSE_INVALID_PAYLOAD", "SocketWS_8h.html#a386c437e966aeaeb091d1d81c0e77b13a5fcad814a12fede092794145c328fb9f", null ],
      [ "WS_CLOSE_POLICY_VIOLATION", "SocketWS_8h.html#a386c437e966aeaeb091d1d81c0e77b13a35ac58f4457834de3faeb1fa7792366d", null ],
      [ "WS_CLOSE_MESSAGE_TOO_BIG", "SocketWS_8h.html#a386c437e966aeaeb091d1d81c0e77b13adbdae48a85dc5e937a163e01508001c6", null ],
      [ "WS_CLOSE_MANDATORY_EXT", "SocketWS_8h.html#a386c437e966aeaeb091d1d81c0e77b13a1f6f581ca2b8fc652c8ffb993fb8194a", null ],
      [ "WS_CLOSE_INTERNAL_ERROR", "SocketWS_8h.html#a386c437e966aeaeb091d1d81c0e77b13a5724188e50f92c13d3673f08ce69412a", null ],
      [ "WS_CLOSE_SERVICE_RESTART", "SocketWS_8h.html#a386c437e966aeaeb091d1d81c0e77b13a9af38cc3ecad679dcf15e666000dfa4b", null ],
      [ "WS_CLOSE_TRY_AGAIN_LATER", "SocketWS_8h.html#a386c437e966aeaeb091d1d81c0e77b13ae899716cd2fc4d8f76d4dad9889129e2", null ],
      [ "WS_CLOSE_BAD_GATEWAY", "SocketWS_8h.html#a386c437e966aeaeb091d1d81c0e77b13ac0935030c6af954b99019692f8757b1b", null ],
      [ "WS_CLOSE_TLS_HANDSHAKE", "SocketWS_8h.html#a386c437e966aeaeb091d1d81c0e77b13aceffd9fee405e4dee36e9596939ba5ec", null ]
    ] ],
    [ "SocketWS_Error", "SocketWS_8h.html#abd79199a60ad91cf785166f24f41101f", [
      [ "WS_OK", "SocketWS_8h.html#abd79199a60ad91cf785166f24f41101fa8d6c24a81bab48a188c7f458bf6ecddb", null ],
      [ "WS_ERROR", "SocketWS_8h.html#abd79199a60ad91cf785166f24f41101faa41b8e2f5c20dd621e69746820e10ecd", null ],
      [ "WS_ERROR_HANDSHAKE", "SocketWS_8h.html#abd79199a60ad91cf785166f24f41101fa326cba4dbca2cd3fc40aa705e3c8c43c", null ],
      [ "WS_ERROR_PROTOCOL", "SocketWS_8h.html#abd79199a60ad91cf785166f24f41101fac3b45ed8d1cffbe97ae99ad9368edfec", null ],
      [ "WS_ERROR_FRAME_TOO_LARGE", "SocketWS_8h.html#abd79199a60ad91cf785166f24f41101fad67cba0f02674ecdb494d3c897945304", null ],
      [ "WS_ERROR_MESSAGE_TOO_LARGE", "SocketWS_8h.html#abd79199a60ad91cf785166f24f41101fa202edc337483e9a546142eeadae60afa", null ],
      [ "WS_ERROR_INVALID_UTF8", "SocketWS_8h.html#abd79199a60ad91cf785166f24f41101fa276c19a5f29e2a5d3032eeebf7d54a8e", null ],
      [ "WS_ERROR_COMPRESSION", "SocketWS_8h.html#abd79199a60ad91cf785166f24f41101fa7bb811cc75e39503c96e5e58f41e392f", null ],
      [ "WS_ERROR_CLOSED", "SocketWS_8h.html#abd79199a60ad91cf785166f24f41101fa4b6bd8241f6074e7efa54cc113fce39c", null ],
      [ "WS_ERROR_WOULD_BLOCK", "SocketWS_8h.html#abd79199a60ad91cf785166f24f41101fad8bea1e89b1464f633c15cc454699761", null ],
      [ "WS_ERROR_TIMEOUT", "SocketWS_8h.html#abd79199a60ad91cf785166f24f41101fab7f48522858a5f62bb83f2102996daaf", null ]
    ] ],
    [ "SocketWS_Opcode", "SocketWS_8h.html#a174740343c7f920060f8640f23600c7b", [
      [ "WS_OPCODE_CONTINUATION", "SocketWS_8h.html#a174740343c7f920060f8640f23600c7ba414ed52e10fc98a59c9fbadc896b3ea3", null ],
      [ "WS_OPCODE_TEXT", "SocketWS_8h.html#a174740343c7f920060f8640f23600c7bab290478c848bb099a2fefe6c7b633558", null ],
      [ "WS_OPCODE_BINARY", "SocketWS_8h.html#a174740343c7f920060f8640f23600c7ba01f825533b31920937ba5ddb2315a361", null ],
      [ "WS_OPCODE_CLOSE", "SocketWS_8h.html#a174740343c7f920060f8640f23600c7ba847b054f16b331a8a701b7e76255d8e5", null ],
      [ "WS_OPCODE_PING", "SocketWS_8h.html#a174740343c7f920060f8640f23600c7ba2e1dad19209b2641fcb2d12025651539", null ],
      [ "WS_OPCODE_PONG", "SocketWS_8h.html#a174740343c7f920060f8640f23600c7ba809eaa105785fd07440fa833f602469c", null ]
    ] ],
    [ "SocketWS_Role", "SocketWS_8h.html#a9d14d3d0f1b05e44fcd74782107cbd94", [
      [ "WS_ROLE_CLIENT", "SocketWS_8h.html#a9d14d3d0f1b05e44fcd74782107cbd94adb564f62107e65c4ba508183929404d1", null ],
      [ "WS_ROLE_SERVER", "SocketWS_8h.html#a9d14d3d0f1b05e44fcd74782107cbd94afa4a0c78e19b98cca7f556560ca4061b", null ]
    ] ],
    [ "SocketWS_State", "SocketWS_8h.html#ab8b49607a661224d66bb264b1e597e2d", [
      [ "WS_STATE_CONNECTING", "SocketWS_8h.html#ab8b49607a661224d66bb264b1e597e2da782bbde9b515882abdd6b712c127af31", null ],
      [ "WS_STATE_OPEN", "SocketWS_8h.html#ab8b49607a661224d66bb264b1e597e2dab0325195f22aca5be7491a425f84808c", null ],
      [ "WS_STATE_CLOSING", "SocketWS_8h.html#ab8b49607a661224d66bb264b1e597e2daa3bafc31c6e8514011174ffeb2dd1eac", null ],
      [ "WS_STATE_CLOSED", "SocketWS_8h.html#ab8b49607a661224d66bb264b1e597e2da4356293e46722d1fa27ca8624f62b296", null ]
    ] ],
    [ "SocketWS_client_new", "SocketWS_8h.html#acad45d5dbc4f2191ba5f732a1b648842", null ],
    [ "SocketWS_compression_enabled", "SocketWS_8h.html#a02790d0b994d613324052794269b0e22", null ],
    [ "SocketWS_config_defaults", "SocketWS_8h.html#ac129f58e59f8b169f2c2a48a330fb176", null ],
    [ "SocketWS_free", "SocketWS_8h.html#aa040ebe5bc5f2673b04b15091a45b944", null ],
    [ "SocketWS_handshake", "SocketWS_8h.html#acbbea030dbe9d643b7f8bd6c1656ff06", null ],
    [ "SocketWS_is_upgrade", "SocketWS_8h.html#abd34fccaadaee0c043bbb1368c3d0673", null ],
    [ "SocketWS_ping", "SocketWS_8h.html#a2be521a2fe8aa5eb5d30869905371a71", null ],
    [ "SocketWS_pong", "SocketWS_8h.html#a3e17279abcb92810c8066f1813287334", null ],
    [ "SocketWS_selected_subprotocol", "SocketWS_8h.html#a2a1ce264ad5e6d3cf25ce2442504aa20", null ],
    [ "SocketWS_send_binary", "SocketWS_8h.html#a1a8aff35f7c69172e0c2f9c0ec53abcb", null ],
    [ "SocketWS_send_text", "SocketWS_8h.html#a4b8450a05502aaa70e88cdf14a73fa03", null ],
    [ "SocketWS_server_accept", "SocketWS_8h.html#a29e02ecca2d5a1b78d0eaf2c08883960", null ],
    [ "SocketWS_server_reject", "SocketWS_8h.html#ad6e400c85623f8603c5965d38b1a60e0", null ],
    [ "SocketWS_socket", "SocketWS_8h.html#a00e6f2953f92843874cd7b6c3e363288", null ],
    [ "SocketWS_state", "SocketWS_8h.html#aa40def588d31ab50126603fa720f83b0", null ],
    [ "SocketWS_Closed", "SocketWS_8h.html#a51caf3b6f8086dc6535fd843593dcbde", null ],
    [ "SocketWS_Failed", "SocketWS_8h.html#a0fb92a65a798e17aca6df1cdba118067", null ],
    [ "SocketWS_ProtocolError", "SocketWS_8h.html#a8400199bb1b785111015ff06d16de370", null ]
];