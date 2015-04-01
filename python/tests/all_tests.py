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

if __name__ == '__main__':
    unittest.main()
