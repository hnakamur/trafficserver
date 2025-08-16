# The compiler and linker options below are copied from Compiler Options
# Hardening Guide for C and C++ by the Open Source Security Foundation (OpenSSF)
# Best Practices Working Group, 2023-11-29
# https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html
# with changes:
#
# * remove -Wl,-z,nodlopen since built plugins cannot be loaded
# * remove -Wconversion since there are a lot of narrowing conversions
#
add_compile_options(
  -O2
  -Wall
  -Wformat=2
  -Wimplicit-fallthrough
  -Wno-error=conversion
  -Wno-error=format-nonliteral
  -Wno-error=maybe-uninitialized
  -Wno-error=stringop-truncation
  -U_FORTIFY_SOURCE
  -D_FORTIFY_SOURCE=3
  -D_GLIBCXX_ASSERTIONS
  -fstack-clash-protection
  -fstack-protector-strong
)
if((CMAKE_CXX_COMPILER_ID MATCHES "Clang" AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 16)
   OR (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 13)
)
  add_compile_options(-fstrict-flex-arrays=3)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang" AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 15)
  add_compile_options(-fstrict-flex-arrays=2)
endif()
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
  add_compile_options(-Wtrampolines)
endif()
add_link_options(-Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now)
