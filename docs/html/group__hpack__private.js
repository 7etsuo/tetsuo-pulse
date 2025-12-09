var group__hpack__private =
[
    [ "SocketHPACK-private.h", "SocketHPACK-private_8h.html", null ],
    [ "HPACK_DynamicEntry", "group__http.html#structHPACK__DynamicEntry", [
      [ "name", "group__http.html#aaf38824aa9d15e2897bc4175df8cf174", null ],
      [ "name_len", "group__http.html#ae5cff4f699f7bc99322b1b05cc0a941c", null ],
      [ "value", "group__http.html#a0c2ef0e32af91b0095cb1d4e2b68640a", null ],
      [ "value_len", "group__http.html#ae5a6402faf5340e8f53e13371ccb8b34", null ]
    ] ],
    [ "SocketHPACK_Table_T", "group__http.html#structSocketHPACK__Table", [
      [ "arena", "group__http.html#a8ef1bc9523a821cd345ea3cecf64464f", null ],
      [ "capacity", "group__http.html#a6c163c2869d04eb47de479cdbf01d5d7", null ],
      [ "count", "group__http.html#a78b5dcfe765af4dbaf0cd5c27c926ba0", null ],
      [ "entries", "group__http.html#acdfefc6df12fb449f04b83dfe53600b2", null ],
      [ "head", "group__http.html#ac484c8a394da7962c59f388aecf3a6fd", null ],
      [ "max_size", "group__http.html#ab6a428895561bc70efa6cdbf9f7f9588", null ],
      [ "size", "group__http.html#aa26d4af777700af33e7dd9a719e9c696", null ],
      [ "tail", "group__http.html#a57a896d93426cece2640353814e6cdf6", null ]
    ] ],
    [ "SocketHPACK_Encoder_T", "group__http.html#structSocketHPACK__Encoder", [
      [ "arena", "group__http.html#aadf9716eef8a648d913f5ba781273dc8", null ],
      [ "huffman_encode", "group__http.html#ad947e2f67bc1041dd00883aa3d8aaf29", null ],
      [ "pending_table_size", "group__http.html#a41fbbf708db674889957fd945907a96a", null ],
      [ "pending_table_size_update", "group__http.html#a15c308cf5bef84fedc07a69a2e131450", null ],
      [ "table", "group__http.html#a9c27fe02791883c173fe35ec57063755", null ],
      [ "use_indexing", "group__http.html#a22c7126c261d1170ddda78e5ca50560b", null ]
    ] ],
    [ "SocketHPACK_Decoder_T", "group__http.html#structSocketHPACK__Decoder", [
      [ "arena", "group__http.html#adf82bc9df6877c14cb5c94a5f6bd4716", null ],
      [ "decode_input_bytes", "group__http.html#adddcba989971c8c7ef82134dec31cb9a", null ],
      [ "decode_output_bytes", "group__http.html#ad4ddfdec635a15924237dc94757270c0", null ],
      [ "max_expansion_ratio", "group__http.html#acc40a2ae4da1308222a5518f834dad82", null ],
      [ "max_header_list_size", "group__http.html#ad481cccc9c93cae9589e32e117ff75b5", null ],
      [ "max_header_size", "group__http.html#aff8c1c127b63ee1304e7e5e353af8a17", null ],
      [ "settings_max_table_size", "group__http.html#a52a71c17f16f11abc5cc3c164e30d2aa", null ],
      [ "table", "group__http.html#a263eaf0e8a043fb3312aa04c66b27916", null ]
    ] ],
    [ "HPACK_StaticEntry", "group__http.html#structHPACK__StaticEntry", [
      [ "name", "group__http.html#a49643b573332398ec78e425dc5e3e980", null ],
      [ "name_len", "group__http.html#af6a73615ec19eadf253cb4fa8cc034f9", null ],
      [ "value", "group__http.html#ad0e5ee57a7c3de1e823b3d43b5b647a0", null ],
      [ "value_len", "group__http.html#a73f42f0a717d6d4e4f8c38845a001ea7", null ]
    ] ],
    [ "HPACK_HuffmanSymbol", "group__http.html#structHPACK__HuffmanSymbol", [
      [ "bits", "group__http.html#af601652287a777c885cfed6c61046257", null ],
      [ "code", "group__http.html#ab8f97d8476a1a8b8a464ff039bf7d4f8", null ]
    ] ],
    [ "HPACK_HuffmanTransition", "group__http.html#structHPACK__HuffmanTransition", [
      [ "flags", "group__http.html#a4d1e72ef25a0ef39679a5931d7665b70", null ],
      [ "next_state", "group__http.html#a26f953198c6ca62e58fafbfbdb65ed9d", null ],
      [ "sym", "group__http.html#ac2555f64670eb57686cd77bb36676b1f", null ]
    ] ],
    [ "HPACK_AVERAGE_DYNAMIC_ENTRY_SIZE", "group__hpack__private.html#gae0304bbcc6c90643a7e3a2d274533d10", null ],
    [ "HPACK_DFA_ACCEPT", "group__hpack__private.html#gafd975c9395b773cfe1f998aa0e0168b2", null ],
    [ "HPACK_HUFFMAN_EOS", "group__hpack__private.html#ga879c884f8d47c7fa563e0ef3d94b0c9e", null ],
    [ "HPACK_HUFFMAN_MAX_BITS", "group__hpack__private.html#gac142229a8069073871247a112e183378", null ],
    [ "HPACK_HUFFMAN_NUM_STATES", "group__hpack__private.html#ga9bec6ff24fdb0960bbd7b095b0f52fff", null ],
    [ "HPACK_HUFFMAN_STATE_ACCEPT", "group__hpack__private.html#ga0040745e9b620e7161fa96270ae2284a", null ],
    [ "HPACK_HUFFMAN_STATE_ERROR", "group__hpack__private.html#gae9150b89a92e9eaa22af1b417785ccb6", null ],
    [ "HPACK_HUFFMAN_SYMBOLS", "group__hpack__private.html#ga83188dc49cbbf3579289e6e4fb7aae0e", null ],
    [ "HPACK_MIN_DYNAMIC_TABLE_CAPACITY", "group__hpack__private.html#ga8fc60b01be138b4e378fd9cc7ad14652", null ],
    [ "hpack_entry_size", "group__hpack__private.html#ga58a0802cdc3a99af5f7f1cb5b7ca9fe8", null ],
    [ "hpack_table_evict", "group__hpack__private.html#gac25f68940182c09fbe7f99e847b9f34f", null ],
    [ "hpack_huffman_decode", "group__hpack__private.html#ga6ac50cbaa6f5bfc19372fa7b656342ef", null ],
    [ "hpack_huffman_encode", "group__hpack__private.html#gafedbf3fdd77193dc9d1419e9eaa8abd0", null ],
    [ "hpack_static_table", "group__hpack__private.html#ga68ff3c1525cfd78881c6140936758c78", null ]
];