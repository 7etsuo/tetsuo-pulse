file(REMOVE_RECURSE
  "libsocket.a"
  "libsocket.pdb"
)

# Per-language clean rules from dependency scanning.
foreach(lang C)
  include(CMakeFiles/socket_static.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
