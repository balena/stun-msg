# Copyright (c) 2015 Guilherme Balena Versiani.
#
# I dedicate any and all copyright interest in this software to the
# public domain. I make this dedication for the benefit of the public at
# large and to the detriment of my heirs and successors. I intend this
# dedication to be an overt act of relinquishment in perpetuity of all
# present and future rights to this software under copyright law.

import stunmsg_c

class StunMsg(object):

  def __init__(self, buf = bytearray(20)):
    self.buf = buf

  def iterattrs(self):
    i = stunmsg_c.next_attr(self.buf, 0)
    while (i != None):
      yield self._build_attr(i)

  def _build_attrs(self, i):
    attr_type = stunmsg_c.stun_attr_type(self.buf, i)
    return (attr_type, self._build_attr_type(attr_type, i))

  def _build_attr_type(self, attr_type, i):
    if attr_type == stunmsg_c.STUN_ATTR_MAPPED_ADDRESS:
      return self._build_sockaddr(i)
    elif attr_type == stunmsg_c.STUN_ATTR_RESPONSE_ADDRESS:
      return self._build_sockaddr(i)
    elif attr_type == stunmsg_c.STUN_ATTR_CHANGE_REQUEST:
      return self._build_uint32(i)
    elif attr_type == stunmsg_c.STUN_ATTR_SOURCE_ADDRESS:
      return self._build_sockaddr(i)
    elif attr_type == stunmsg_c.STUN_ATTR_CHANGED_ADDRESS:
      return self._build_sockaddr(i)
    elif attr_type == stunmsg_c.STUN_ATTR_USERNAME:
      return self._build_string(i)
    elif attr_type == stunmsg_c.STUN_ATTR_PASSWORD:
      return self._build_string(i)
    elif attr_type == stunmsg_c.STUN_ATTR_MESSAGE_INTEGRITY:
      return self._build_msgint(i)
    elif attr_type == stunmsg_c.STUN_ATTR_ERROR_CODE:
      return self._build_errcode(i)
    elif attr_type == stunmsg_c.STUN_ATTR_UNKNOWN_ATTRIBUTES:
      return self._build_unknown(i)
    elif attr_type == stunmsg_c.STUN_ATTR_REFLECTED_FROM:
      return self._build_sockaddr(i)
    elif attr_type == stunmsg_c.STUN_ATTR_CHANNEL_NUMBER:
      return self._build_uint32(i)
    elif attr_type == stunmsg_c.STUN_ATTR_LIFETIME:
      return self._build_uint32(i)
    elif attr_type == stunmsg_c.STUN_ATTR_BANDWIDTH:
      return self._build_uint32(i)
    elif attr_type == stunmsg_c.STUN_ATTR_XOR_PEER_ADDRESS:
      return self._build_xor_sockaddr(i)
    elif attr_type == stunmsg_c.STUN_ATTR_DATA:
      return self._build_data(i)
    elif attr_type == stunmsg_c.STUN_ATTR_REALM:
      return self._build_string(i)
    elif attr_type == stunmsg_c.STUN_ATTR_NONCE:
      return self._build_string(i)
    elif attr_type == stunmsg_c.STUN_ATTR_XOR_RELAYED_ADDRESS:
      return self._build_xor_sockaddr(i)
    elif attr_type == stunmsg_c.STUN_ATTR_REQ_ADDRESS_FAMILY:
      return self._build_uint8(i)
    elif attr_type == stunmsg_c.STUN_ATTR_EVEN_PORT:
      return self._build_uint8_pad(i)
    elif attr_type == stunmsg_c.STUN_ATTR_REQUESTED_TRANSPORT:
      return self._build_uint32(i)
    elif attr_type == stunmsg_c.STUN_ATTR_DONT_FRAGMENT:
      return self._build_empty()
    elif attr_type == stunmsg_c.STUN_ATTR_XOR_MAPPED_ADDRESS:
      return self._build_xor_sockaddr(i)
    elif attr_type == stunmsg_c.STUN_ATTR_TIMER_VAL:
      return self._build_uint32(i)
    elif attr_type == stunmsg_c.STUN_ATTR_RESERVATION_TOKEN:
      return self._build_uint64(i)
    elif attr_type == stunmsg_c.STUN_ATTR_PRIORITY:
      return self._build_uint32(i)
    elif attr_type == stunmsg_c.STUN_ATTR_USE_CANDIDATE:
      return self._build_empty()
    elif attr_type == stunmsg_c.STUN_ATTR_PADDING:
      return self._build_data(i)
    elif attr_type == stunmsg_c.STUN_ATTR_RESPONSE_PORT:
      return self._build_uint16(i)
    elif attr_type == stunmsg_c.STUN_ATTR_CONNECTION_ID:
      return self._build_uint32(i)
    elif attr_type == stunmsg_c.STUN_ATTR_SOFTWARE:
      return self._build_string(i)
    elif attr_type == stunmsg_c.STUN_ATTR_ALTERNATE_SERVER:
      return self._build_sockaddr(i)
    elif attr_type == stunmsg_c.STUN_ATTR_FINGERPRINT:
      return self._build_fingerprint(i)
    elif attr_type == stunmsg_c.STUN_ATTR_ICE_CONTROLLED:
      return self._build_uint64(i)
    elif attr_type == stunmsg_c.STUN_ATTR_ICE_CONTROLLING:
      return self._build_uint64(i)
    elif attr_type == stunmsg_c.STUN_ATTR_RESPONSE_ORIGIN:
      return self._build_sockaddr(i)
    elif attr_type == stunmsg_c.STUN_ATTR_OTHER_ADDRESS:
      return self._build_sockaddr(i)
    else:
      return self._build_empty() # defaults to empty

  def _build_empty():
    return None

  def _build_errcode(i):
    status_code = stunmsg_c.stun_attr_errcode_status((self.buf, i));
    status_text = stunmsg_c.errcode_reason((self.buf, i));
    return (status_code, status_text)

  def _build_uint8(i):
    return stunmsg_c.stun_attr_uint8_read((self.buf, i))

  def _build_uint16(i):
    return stunmsg_c.stun_attr_uint16_read((self.buf, i))

  def _build_uint32(i):
    return stunmsg_c.stun_attr_uint32_read((self.buf, i))

  def _build_uint64(i):
    return stunmsg_c.stun_attr_uint64_read((self.buf, i))

  def _build_unknown(i):
    len = stunmsg_c.stun_attr_unknown_count((self.buf, i))
    result = []
    for n in range(0, len):
      result.append(stunmsg_c.stun_attr_unknown_get((self.buf, i), n))
    return result

  def _build_string(i):
    return stunmsg_c.string_read((self.buf, i))

  def _build_data(i):
    return stunmsg_c.data_read((self.buf, i))

  def _build_sockaddr(i):
    res, addr = stun_attr_sockaddr_read((self.buf, i))
    return addr if res == 0 else None

  def _build_xor_sockaddr(i):
    res, addr = stun_attr_xor_sockaddr_read((self.buf, i), self.buf)
    return addr if res == 0 else None

  def _build_msgint(i):
    def check(password):
      res = stunmsg_c.stun_attr_msgint_check((self.buf, i), self.buf, password)
      return True if res == 1 else False
    return check

  def _build_fingerprint(i):
    def check():
      res = stunmsg_c.stun_attr_fingerprint_check((self.buf, i), self.buf)
      return True if res == 1 else False
    return check

