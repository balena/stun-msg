cmake_minimum_required(VERSION 2.8.0 FATAL_ERROR)

project(stun-msg)

add_library(stun-msg STATIC
  crc32.c crc32.h
  hmac_sha1.c hmac_sha1.h
  sha1.c sha1.h
  stun.c stun.h
)
