cmake_minimum_required(VERSION 2.6.2)

project(stun-msg)

add_subdirectory(gtest)

config_compiler_and_linker()  # Defined in gtest/cmake/internal_utils.cmake.
set(CMAKE_C_FLAGS ${CMAKE_CXX_FLAGS})
set(CMAKE_C_FLAGS_DEBUG ${CMAKE_CXX_FLAGS_DEBUG})
set(CMAKE_C_FLAGS_RELEASE ${CMAKE_CXX_FLAGS_RELEASE})
set(CMAKE_C_FLAGS_MINSIZEREL ${CMAKE_CXX_FLAGS_MINSIZEREL})
set(CMAKE_C_FLAGS_RELWITHDEBINFO ${CMAKE_CXX_FLAGS_RELWITHDEBINFO})

add_library(stunmsg STATIC
  src/crc32.c src/crc32.h
  src/hmac_sha1.c src/hmac_sha1.h
  src/sha1.c src/sha1.h
  src/md5.c src/md5.h
  src/stunmsg.c src/stunmsg.h
)

include_directories(gtest/include src)

add_executable(stunmsg_tests
  tests/stunmsg_unittest.cc
  tests/sha1_unittest.cc
  tests/hmac_sha1_unittest.cc
  tests/md5_unittest.cc
  tests/crc32_unittest.cc
)

add_dependencies(stunmsg_tests stunmsg gtest gtest_main)
target_link_libraries(stunmsg_tests stunmsg gtest gtest_main)

if(WIN32)
  target_link_libraries(stunmsg_tests Ws2_32)
endif()
