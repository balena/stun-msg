# Copyright (c) 2015 Guilherme Balena Versiani.
#
# I dedicate any and all copyright interest in this software to the
# public domain. I make this dedication for the benefit of the public at
# large and to the detriment of my heirs and successors. I intend this
# dedication to be an overt act of relinquishment in perpetuity of all
# present and future rights to this software under copyright law.

import unittest
from stunmsg import StunMsg

class TestStunMsg(unittest.TestCase):

  def test_basic_binding_request(self):
    expected_result = bytearray(b''.join([
      b'\x00\x01\x00\x00', #    Request type and message length
      b'\x21\x12\xa4\x42', #    Magic cookie
      b'\xfd\x95\xe8\x83', # }
      b'\x8a\x05\x28\x45', # }  Transaction ID
      b'\x6a\x8e\xf1\xe2'  # }
    ]))

    tsx_id = bytearray(b''.join([
      b'\xfd\x95\xe8\x83',
      b'\x8a\x05\x28\x45',
      b'\x6a\x8e\xf1\xe2'
    ]))

    msg = StunMsg(buf=expected_result)
    self.assertEqual(len(msg.data()), 20)
    self.assertTrue(msg.verify())

    msg = StunMsg(StunMsg.BINDING_REQUEST, tsx_id)

    self.assertEqual(msg.data(), expected_result)

    # Now decoding
    self.assertEqual(StunMsg.BINDING_REQUEST, msg.type())
    self.assertEqual(len(msg.data()), len(expected_result))

    it = msg.iterattrs()
    with self.assertRaises(StopIteration):
      it.next()


  def test_rfc5769_sample_request(self):
    software_name = "STUN test client"
    username = "evtj:h6vY"
    password = "VOkJxbRl1RmTxUk/WvJxBt"

    expected_result = bytearray(b''.join([
      b'\x00\x01\x00\x58', #    Request type and message length
      b'\x21\x12\xa4\x42', #    Magic cookie
      b'\xb7\xe7\xa7\x01', # }
      b'\xbc\x34\xd6\x86', # }  Transaction ID
      b'\xfa\x87\xdf\xae', # }
      b'\x80\x22\x00\x10', #    SOFTWARE attribute header
      b'\x53\x54\x55\x4e', # }
      b'\x20\x74\x65\x73', # }  User-agent...
      b'\x74\x20\x63\x6c', # }  ...name
      b'\x69\x65\x6e\x74', # }
      b'\x00\x24\x00\x04', #    PRIORITY attribute header
      b'\x6e\x00\x01\xff', #    ICE priority value
      b'\x80\x29\x00\x08', #    ICE-CONTROLLED attribute header
      b'\x93\x2f\xf9\xb1', # }  Pseudo-random tie breaker...
      b'\x51\x26\x3b\x36', # }   ...for ICE control
      b'\x00\x06\x00\x09', #    USERNAME attribute header
      b'\x65\x76\x74\x6a', # }
      b'\x3a\x68\x36\x76', # }  Username (9 bytes) and padding (3 bytes)
      b'\x59\x20\x20\x20', # }
      b'\x00\x08\x00\x14', #    MESSAGE-INTEGRITY attribute header
      b'\x9a\xea\xa7\x0c', # }
      b'\xbf\xd8\xcb\x56', # }
      b'\x78\x1e\xf2\xb5', # }  HMAC-SHA1 fingerprint
      b'\xb2\xd3\xf2\x49', # }
      b'\xc1\xb5\x71\xa2', # }
      b'\x80\x28\x00\x04', #    FINGERPRINT attribute header
      b'\xe5\x7a\x3b\xcf', #    CRC\x32 fingerprint
    ]))

    tsx_id = bytearray(b''.join([
      b'\xb7\xe7\xa7\x01',
      b'\xbc\x34\xd6\x86',
      b'\xfa\x87\xdf\xae',
    ]))

    msg = StunMsg(buf=expected_result)
    self.assertEqual(len(msg.data()), len(expected_result))
    self.assertTrue(msg.verify())

    msg = StunMsg(StunMsg.BINDING_REQUEST, tsx_id)
    msg.appendattr(StunMsg.ATTR_SOFTWARE, (software_name, ord(' ')))
    msg.appendattr(StunMsg.ATTR_PRIORITY, 0x6e0001ff)
    msg.appendattr(StunMsg.ATTR_ICE_CONTROLLED, 0x932ff9b151263b36L)
    msg.appendattr(StunMsg.ATTR_USERNAME, (username, ord(' ')))
    msg.appendattr(StunMsg.ATTR_MESSAGE_INTEGRITY, password)
    msg.appendattr(StunMsg.ATTR_FINGERPRINT)

    self.assertEqual(msg.data(), expected_result)

    # Now decoding
    msg = StunMsg(buf=expected_result)
    self.assertEqual(StunMsg.BINDING_REQUEST, msg.type())
    self.assertEqual(len(expected_result), len(msg.data()))

    it = msg.iterattrs()

    attr_type, value = it.next()
    self.assertEqual(StunMsg.ATTR_SOFTWARE, attr_type)
    self.assertEqual(value, software_name)

    attr_type, value = it.next()
    self.assertEqual(StunMsg.ATTR_PRIORITY, attr_type)
    self.assertEqual(value, 0x6e0001ff)

    attr_type, value = it.next()
    self.assertEqual(StunMsg.ATTR_ICE_CONTROLLED, attr_type)
    self.assertEqual(value, 0x932ff9b151263b36L)

    attr_type, value = it.next()
    self.assertEqual(StunMsg.ATTR_USERNAME, attr_type)
    self.assertEqual(value, username)

    attr_type, value = it.next()
    self.assertEqual(StunMsg.ATTR_MESSAGE_INTEGRITY, attr_type)
    self.assertTrue(value(password))

    attr_type, value = it.next()
    self.assertEqual(StunMsg.ATTR_FINGERPRINT, attr_type)
    self.assertTrue(True)

    with self.assertRaises(StopIteration):
      it.next()


  def test_rfc5769_sample_ipv4_response(self):
    software_name = "test vector"
    password = "VOkJxbRl1RmTxUk/WvJxBt"

    expected_result = bytearray(b''.join([
      b'\x01\x01\x00\x3c', #    Request type and message length
      b'\x21\x12\xa4\x42', #    Magic cookie
      b'\xb7\xe7\xa7\x01', # }
      b'\xbc\x34\xd6\x86', # }  Transaction ID
      b'\xfa\x87\xdf\xae', # }
      b'\x80\x22\x00\x0b', #    SOFTWARE attribute header
      b'\x74\x65\x73\x74', # }
      b'\x20\x76\x65\x63', # }  UTF-8 server name
      b'\x74\x6f\x72\x20', # }
      b'\x00\x20\x00\x08', #    XOR-MAPPED-ADDRESS attribute header
      b'\x00\x01\xa1\x47', #    Address family (IPv4) and xor'd mapped port number
      b'\xe1\x12\xa6\x43', #    Xor'd mapped IPv4 address
      b'\x00\x08\x00\x14', #    MESSAGE-INTEGRITY attribute header
      b'\x2b\x91\xf5\x99', # }
      b'\xfd\x9e\x90\xc3', # }
      b'\x8c\x74\x89\xf9', # }  HMAC-SHA1 fingerprint
      b'\x2a\xf9\xba\x53', # }
      b'\xf0\x6b\xe7\xd7', # }
      b'\x80\x28\x00\x04', #    FINGERPRINT attribute header
      b'\xc0\x7d\x4c\x96', #    CRC32 fingerprint
    ]))

    tsx_id = bytearray(b''.join([
      b'\xb7\xe7\xa7\x01',
      b'\xbc\x34\xd6\x86',
      b'\xfa\x87\xdf\xae',
    ]))

    ipv4 = ("192.0.2.1", 32853)

    msg = StunMsg(buf=expected_result)
    self.assertEqual(len(msg.data()), len(expected_result))
    self.assertTrue(msg.verify())

    msg = StunMsg(StunMsg.BINDING_RESPONSE, tsx_id)
    msg.appendattr(StunMsg.ATTR_SOFTWARE, (software_name, ord(' ')))
    msg.appendattr(StunMsg.ATTR_XOR_MAPPED_ADDRESS, ipv4)
    msg.appendattr(StunMsg.ATTR_MESSAGE_INTEGRITY, password)
    msg.appendattr(StunMsg.ATTR_FINGERPRINT)

    self.assertEqual(msg.data(), expected_result)

    # Now decoding
    msg = StunMsg(buf=expected_result)
    self.assertEqual(StunMsg.BINDING_RESPONSE, msg.type())
    self.assertEqual(len(expected_result), len(msg.data()))

    it = msg.iterattrs()

    attr_type, value = it.next()
    self.assertEqual(StunMsg.ATTR_SOFTWARE, attr_type)
    self.assertEqual(value, software_name)

    attr_type, value = it.next()
    self.assertEqual(StunMsg.ATTR_XOR_MAPPED_ADDRESS, attr_type)
    self.assertEqual(value, ipv4)

    attr_type, value = it.next()
    self.assertEqual(StunMsg.ATTR_MESSAGE_INTEGRITY, attr_type)
    self.assertTrue(value(password))

    attr_type, value = it.next()
    self.assertEqual(StunMsg.ATTR_FINGERPRINT, attr_type)
    self.assertTrue(value)

    with self.assertRaises(StopIteration):
      it.next()


  def test_rfc5769_sample_ipv6_response(self):
    software_name = "test vector"
    password = "VOkJxbRl1RmTxUk/WvJxBt"

    expected_result = bytearray(b''.join([
      b'\x01\x01\x00\x48', #    Request type and message length
      b'\x21\x12\xa4\x42', #    Magic cookie
      b'\xb7\xe7\xa7\x01', # }
      b'\xbc\x34\xd6\x86', # }  Transaction ID
      b'\xfa\x87\xdf\xae', # }
      b'\x80\x22\x00\x0b', #    SOFTWARE attribute header
      b'\x74\x65\x73\x74', # }
      b'\x20\x76\x65\x63', # }  UTF-8 server name
      b'\x74\x6f\x72\x20', # }
      b'\x00\x20\x00\x14', #    XOR-MAPPED-ADDRESS attribute header
      b'\x00\x02\xa1\x47', #    Address family (IPv4) and xor'd mapped port number
      b'\x01\x13\xa9\xfa', # }
      b'\xa5\xd3\xf1\x79', # }  Xor'd mapped IPv6 address
      b'\xbc\x25\xf4\xb5', # }
      b'\xbe\xd2\xb9\xd9', # }
      b'\x00\x08\x00\x14', #    MESSAGE-INTEGRITY attribute header
      b'\xa3\x82\x95\x4e', # }
      b'\x4b\xe6\x7b\xf1', # }
      b'\x17\x84\xc9\x7c', # }  HMAC-SHA1 fingerprint
      b'\x82\x92\xc2\x75', # }
      b'\xbf\xe3\xed\x41', # }
      b'\x80\x28\x00\x04', #    FINGERPRINT attribute header
      b'\xc8\xfb\x0b\x4c', #    CRC32 fingerprint
    ]))

    tsx_id = bytearray(b''.join([
      b'\xb7\xe7\xa7\x01',
      b'\xbc\x34\xd6\x86',
      b'\xfa\x87\xdf\xae',
    ]))

    ipv6 = ("2001:db8:1234:5678:11:2233:4455:6677", 32853)

    msg = StunMsg(buf=expected_result)
    self.assertEqual(len(msg.data()), len(expected_result))
    self.assertTrue(msg.verify())

    msg = StunMsg(StunMsg.BINDING_RESPONSE, tsx_id)
    msg.appendattr(StunMsg.ATTR_SOFTWARE, (software_name, ord(' ')))
    msg.appendattr(StunMsg.ATTR_XOR_MAPPED_ADDRESS, ipv6)
    msg.appendattr(StunMsg.ATTR_MESSAGE_INTEGRITY, password)
    msg.appendattr(StunMsg.ATTR_FINGERPRINT)

    self.assertEqual(msg.data(), expected_result)

    # Now decoding
    msg = StunMsg(buf=expected_result)
    self.assertEqual(StunMsg.BINDING_RESPONSE, msg.type())
    self.assertEqual(len(expected_result), len(msg.data()))

    it = msg.iterattrs()

    attr_type, value = it.next()
    self.assertEqual(StunMsg.ATTR_SOFTWARE, attr_type)
    self.assertEqual(value, software_name)

    attr_type, value = it.next()
    self.assertEqual(StunMsg.ATTR_XOR_MAPPED_ADDRESS, attr_type)
    self.assertEqual(value, ipv6)

    attr_type, value = it.next()
    self.assertEqual(StunMsg.ATTR_MESSAGE_INTEGRITY, attr_type)
    self.assertTrue(value(password))

    attr_type, value = it.next()
    self.assertEqual(StunMsg.ATTR_FINGERPRINT, attr_type)
    self.assertTrue(value)

    with self.assertRaises(StopIteration):
      it.next()


  def test_rfc5769_sample_request_long_term(self):
    username = bytearray(b''.join([
      b'\xE3\x83\x9E\xE3',
      b'\x83\x88\xE3\x83',
      b'\xAA\xE3\x83\x83',
      b'\xE3\x82\xAF\xE3',
      b'\x82\xB9',
    ]))

    password = "TheMatrIX"
    nonce = "f//499k954d6OL34oL9FSTvy64sA"
    realm = "example.org"

    expected_result = bytearray(b''.join([
      b'\x00\x01\x00\x60', #    Request type and message length
      b'\x21\x12\xa4\x42', #    Magic cookie
      b'\x78\xad\x34\x33', # }
      b'\xc6\xad\x72\xc0', # }  Transaction ID
      b'\x29\xda\x41\x2e', # }
      b'\x00\x06\x00\x12', #    USERNAME attribute header
      b'\xe3\x83\x9e\xe3', # }
      b'\x83\x88\xe3\x83', # }
      b'\xaa\xe3\x83\x83', # }  Username value (0x18,bytes) and padding (2 bytes)
      b'\xe3\x82\xaf\xe3', # }
      b'\x82\xb9\x00\x00', # }
      b'\x00\x15\x00\x1c', #    NONCE attribute header
      b'\x66\x2f\x2f\x34', # }
      b'\x39\x39\x6b\x39', # }
      b'\x35\x34\x64\x36', # }
      b'\x4f\x4c\x33\x34', # }  Nonce value
      b'\x6f\x4c\x39\x46', # }
      b'\x53\x54\x76\x79', # }
      b'\x36\x34\x73\x41', # }
      b'\x00\x14\x00\x0b', #    REALM attribute header
      b'\x65\x78\x61\x6d', # }
      b'\x70\x6c\x65\x2e', # }  Realm value (0x11,bytes) and padding (1 byte)
      b'\x6f\x72\x67\x00', # }
      b'\x00\x08\x00\x14', #    MESSAGE-INTEGRITY attribute header
      b'\xf6\x70\x24\x65', # }
      b'\x6d\xd6\x4a\x3e', # }
      b'\x02\xb8\xe0\x71', # }  HMAC-SHA1 fingerprint
      b'\x2e\x85\xc9\xa2', # }
      b'\x8c\xa8\x96\x66', # }
    ]))

    tsx_id = bytearray(b''.join([
      b'\x78\xad\x34\x33',
      b'\xc6\xad\x72\xc0',
      b'\x29\xda\x41\x2e',
    ]))

    key = StunMsg.hashkey(username, realm, password)

    msg = StunMsg(buf=expected_result)
    self.assertEqual(len(msg.data()), len(expected_result))
    self.assertTrue(msg.verify())

    msg = StunMsg(StunMsg.BINDING_REQUEST, tsx_id)
    msg.appendattr(StunMsg.ATTR_USERNAME, username)
    msg.appendattr(StunMsg.ATTR_NONCE, nonce)
    msg.appendattr(StunMsg.ATTR_REALM, realm)
    msg.appendattr(StunMsg.ATTR_MESSAGE_INTEGRITY, key)

    self.assertEqual(msg.data(), expected_result)

    # Now decoding
    msg = StunMsg(buf=expected_result)
    self.assertEqual(StunMsg.BINDING_REQUEST, msg.type())
    self.assertEqual(len(expected_result), len(msg.data()))

    it = msg.iterattrs()

    attr_type, value = it.next()
    self.assertEqual(StunMsg.ATTR_USERNAME, attr_type)
    self.assertEqual(value, username)

    attr_type, value = it.next()
    self.assertEqual(StunMsg.ATTR_NONCE, attr_type)
    self.assertEqual(value, nonce)

    attr_type, value = it.next()
    self.assertEqual(StunMsg.ATTR_REALM, attr_type)
    self.assertEqual(value, realm)

    attr_type, value = it.next()
    self.assertEqual(StunMsg.ATTR_MESSAGE_INTEGRITY, attr_type)
    self.assertTrue(value(key))

    with self.assertRaises(StopIteration):
      it.next()

  def test_error_response(self):
    reason_phrase = "Unknown Attribute"

    expected_result = bytearray(b''.join([
      b'\x01\x11\x00\x28', #    Request type and message length
      b'\x21\x12\xa4\x42', #    Magic cookie
      b'\x78\xad\x34\x33', # }
      b'\xc6\xad\x72\xc0', # }  Transaction ID
      b'\x29\xda\x41\x2e', # }
      b'\x00\x09\x00\x15', #    ERROR-CODE attribute header
      b'\x00\x00\x04\x14', #    class = 4, code = 20 (420)
      b'\x55\x6e\x6b\x6e', # }
      b'\x6f\x77\x6e\x20', # }
      b'\x41\x74\x74\x72', # }  Reason: Unknown Attribute
      b'\x69\x62\x75\x74', # }
      b'\x65\x00\x00\x00', # }
      b'\x00\x0a\x00\x06', #    UNKNOWN-ATTRIBUTES attribute header
      b'\x00\x1a\x00\x1b', #    0x001A, 0x001B
      b'\x80\x2c\x00\x00', #    0x802C
    ]))

    tsx_id = bytearray(b''.join([
      b'\x78\xad\x34\x33',
      b'\xc6\xad\x72\xc0',
      b'\x29\xda\x41\x2e',
    ]))
    unknown = [ 0x001a, 0x001b, 0x802c ]

    msg = StunMsg(buf=expected_result)
    self.assertEqual(len(msg.data()), len(expected_result))
    self.assertTrue(msg.verify())

    msg = StunMsg(StunMsg.BINDING_ERROR_RESPONSE, tsx_id)
    msg.appendattr(StunMsg.ATTR_ERROR_CODE, (420, reason_phrase))
    msg.appendattr(StunMsg.ATTR_UNKNOWN_ATTRIBUTES, unknown)

    self.assertEqual(msg.data(), expected_result)

    # Now decoding
    msg = StunMsg(buf=expected_result)
    self.assertEqual(StunMsg.BINDING_ERROR_RESPONSE, msg.type())
    self.assertEqual(len(expected_result), len(msg.data()))

    it = msg.iterattrs()

    attr_type, value = it.next()
    self.assertEqual(StunMsg.ATTR_ERROR_CODE, attr_type)
    status_code, status_text = value
    self.assertEqual(status_code, 420)
    self.assertEqual(status_text, reason_phrase)

    attr_type, value = it.next()
    self.assertEqual(StunMsg.ATTR_UNKNOWN_ATTRIBUTES, attr_type)
    self.assertEqual(value, unknown)

    with self.assertRaises(StopIteration):
      it.next()


if __name__ == '__main__':
    unittest.main()
