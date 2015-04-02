#!/usr/bin/env python

from distutils.core import setup, Extension

setup(
  name = "stunmsg",
  version = "1.0",
  author = "G. B. Versiani <guibv@yahoo.com>",
  description = "Public domain implementation of STUN message",
  ext_modules = [Extension('stunmsg/_stunmsg_c', [
      'stunmsg/stunmsg_c.i',
      '../src/crc32.c',
      '../src/hmac_sha1.c',
      '../src/md5.c',
      '../src/sha1.c',
      '../src/stun_msg.c',
    ],
    swig_opts=['-modern', '-I../include'],
    include_dirs=["../include"]
  )],
  packages = ['stunmsg'],
  scripts = ['nat_type'],
)

