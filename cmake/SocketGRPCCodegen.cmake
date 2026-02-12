# SocketGRPC code generation helpers.

include (CMakeParseArguments)

function (socketgrpc_generate)
  set (options)
  set (one_value_args PROTO OUTPUT_DIR OUT_SRC OUT_HDR)
  set (multi_value_args)
  cmake_parse_arguments (SOCKETGRPC "${options}" "${one_value_args}" "${multi_value_args}" ${ARGN})

  if (NOT SOCKETGRPC_PROTO)
    message (FATAL_ERROR "socketgrpc_generate requires PROTO")
  endif ()
  if (NOT SOCKETGRPC_OUTPUT_DIR)
    message (FATAL_ERROR "socketgrpc_generate requires OUTPUT_DIR")
  endif ()
  if (NOT SOCKETGRPC_OUT_SRC OR NOT SOCKETGRPC_OUT_HDR)
    message (FATAL_ERROR "socketgrpc_generate requires OUT_SRC and OUT_HDR variable names")
  endif ()
  if (NOT Python3_EXECUTABLE)
    message (FATAL_ERROR "Python3 interpreter is required for socketgrpc_generate")
  endif ()

  get_filename_component (_proto_abs "${SOCKETGRPC_PROTO}" ABSOLUTE BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
  get_filename_component (_proto_stem "${_proto_abs}" NAME_WE)

  set (_out_src "${SOCKETGRPC_OUTPUT_DIR}/${_proto_stem}.socketgrpc.c")
  set (_out_hdr "${SOCKETGRPC_OUTPUT_DIR}/${_proto_stem}.socketgrpc.h")

  add_custom_command (
    OUTPUT "${_out_src}" "${_out_hdr}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${SOCKETGRPC_OUTPUT_DIR}"
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/tools/protoc-gen-socketgrpc"
            --proto "${_proto_abs}"
            --out-dir "${SOCKETGRPC_OUTPUT_DIR}"
    DEPENDS "${_proto_abs}" "${CMAKE_SOURCE_DIR}/tools/protoc-gen-socketgrpc"
    COMMENT "Generating SocketGRPC stubs for ${_proto_stem}.proto"
    VERBATIM
  )

  set (${SOCKETGRPC_OUT_SRC} "${_out_src}" PARENT_SCOPE)
  set (${SOCKETGRPC_OUT_HDR} "${_out_hdr}" PARENT_SCOPE)
endfunction ()
