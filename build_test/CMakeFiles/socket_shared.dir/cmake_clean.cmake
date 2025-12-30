file(REMOVE_RECURSE
  "libsocket.pdb"
  "libsocket.so"
)

# Per-language clean rules from dependency scanning.
foreach(lang C)
  include(CMakeFiles/socket_shared.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
