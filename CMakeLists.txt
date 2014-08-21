cmake_minimum_required(VERSION 2.8.0 FATAL_ERROR)

project(stun-msg)

add_subdirectory(gtest)

config_compiler_and_linker()  # Defined in gtest/cmake/internal_utils.cmake.
set(CMAKE_C_FLAGS ${CMAKE_CXX_FLAGS})
set(CMAKE_C_FLAGS_DEBUG ${CMAKE_CXX_FLAGS_DEBUG})
set(CMAKE_C_FLAGS_RELEASE ${CMAKE_CXX_FLAGS_RELEASE})
set(CMAKE_C_FLAGS_MINSIZEREL ${CMAKE_CXX_FLAGS_MINSIZEREL})
set(CMAKE_C_FLAGS_RELWITHDEBINFO ${CMAKE_CXX_FLAGS_RELWITHDEBINFO})

add_library(stun-msg STATIC
  src/crc32.c src/crc32.h
  src/hmac_sha1.c src/hmac_sha1.h
  src/sha1.c src/sha1.h
  src/md5.c src/md5.h
  src/stun.c src/stun.h
)

include_directories(gtest/include src)

add_executable(stun-msg_tests
  tests/stun_unittests.cc
)

add_dependencies(stun-msg_tests stun-msg gtest gtest_main)
target_link_libraries(stun-msg_tests stun-msg gtest gtest_main)

if(WIN32)
  target_link_libraries(stun-msg_tests Ws2_32)
endif()

add_executable(sha1_test src/sha1.c)
set_property(TARGET sha1_test PROPERTY COMPILE_DEFINITIONS SHA1_TEST)

add_executable(hmac_sha1_test src/hmac_sha1.c src/sha1.c)
set_property(TARGET hmac_sha1_test PROPERTY COMPILE_DEFINITIONS HMAC_SHA1_TEST)

