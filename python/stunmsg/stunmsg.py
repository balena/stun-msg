# Copyright (c) 2015 Guilherme Balena Versiani.
#
# I dedicate any and all copyright interest in this software to the
# public domain. I make this dedication for the benefit of the public at
# large and to the detriment of my heirs and successors. I intend this
# dedication to be an overt act of relinquishment in perpetuity of all
# present and future rights to this software under copyright law.

import stunmsg_c

class StunMsg(object):

  BINDING_REQUEST                   = stunmsg_c.STUN_BINDING_REQUEST                  
  BINDING_RESPONSE                  = stunmsg_c.STUN_BINDING_RESPONSE                 
  BINDING_ERROR_RESPONSE            = stunmsg_c.STUN_BINDING_ERROR_RESPONSE           
  BINDING_INDICATION                = stunmsg_c.STUN_BINDING_INDICATION               
  SHARED_SECRET_REQUEST             = stunmsg_c.STUN_SHARED_SECRET_REQUEST            
  SHARED_SECRET_RESPONSE            = stunmsg_c.STUN_SHARED_SECRET_RESPONSE           
  SHARED_SECRET_ERROR_RESPONSE      = stunmsg_c.STUN_SHARED_SECRET_ERROR_RESPONSE     
  ALLOCATE_REQUEST                  = stunmsg_c.STUN_ALLOCATE_REQUEST                 
  ALLOCATE_RESPONSE                 = stunmsg_c.STUN_ALLOCATE_RESPONSE                
  ALLOCATE_ERROR_RESPONSE           = stunmsg_c.STUN_ALLOCATE_ERROR_RESPONSE          
  REFRESH_REQUEST                   = stunmsg_c.STUN_REFRESH_REQUEST                  
  REFRESH_RESPONSE                  = stunmsg_c.STUN_REFRESH_RESPONSE                 
  REFRESH_ERROR_RESPONSE            = stunmsg_c.STUN_REFRESH_ERROR_RESPONSE           
  SEND_INDICATION                   = stunmsg_c.STUN_SEND_INDICATION                  
  DATA_INDICATION                   = stunmsg_c.STUN_DATA_INDICATION                  
  CREATE_PERM_REQUEST               = stunmsg_c.STUN_CREATE_PERM_REQUEST              
  CREATE_PERM_RESPONSE              = stunmsg_c.STUN_CREATE_PERM_RESPONSE             
  CREATE_PERM_ERROR_RESPONSE        = stunmsg_c.STUN_CREATE_PERM_ERROR_RESPONSE       
  CHANNEL_BIND_REQUEST              = stunmsg_c.STUN_CHANNEL_BIND_REQUEST             
  CHANNEL_BIND_RESPONSE             = stunmsg_c.STUN_CHANNEL_BIND_RESPONSE            
  CHANNEL_BIND_ERROR_RESPONSE       = stunmsg_c.STUN_CHANNEL_BIND_ERROR_RESPONSE      
  CONNECT_REQUEST                   = stunmsg_c.STUN_CONNECT_REQUEST                  
  CONNECT_RESPONSE                  = stunmsg_c.STUN_CONNECT_RESPONSE                 
  CONNECT_ERROR_RESPONSE            = stunmsg_c.STUN_CONNECT_ERROR_RESPONSE           
  CONNECTION_BIND_REQUEST           = stunmsg_c.STUN_CONNECTION_BIND_REQUEST          
  CONNECTION_BIND_RESPONSE          = stunmsg_c.STUN_CONNECTION_BIND_RESPONSE         
  CONNECTION_BIND_ERROR_RESPONSE    = stunmsg_c.STUN_CONNECTION_BIND_ERROR_RESPONSE   
  CONNECTION_ATTEMPT_REQUEST        = stunmsg_c.STUN_CONNECTION_ATTEMPT_REQUEST       
  CONNECTION_ATTEMPT_RESPONSE       = stunmsg_c.STUN_CONNECTION_ATTEMPT_RESPONSE      
  CONNECTION_ATTEMPT_ERROR_RESPONSE = stunmsg_c.STUN_CONNECTION_ATTEMPT_ERROR_RESPONSE

  ATTR_MAPPED_ADDRESS      = stunmsg_c.STUN_ATTR_MAPPED_ADDRESS
  ATTR_RESPONSE_ADDRESS    = stunmsg_c.STUN_ATTR_RESPONSE_ADDRESS
  ATTR_CHANGE_REQUEST      = stunmsg_c.STUN_ATTR_CHANGE_REQUEST
  ATTR_SOURCE_ADDRESS      = stunmsg_c.STUN_ATTR_SOURCE_ADDRESS
  ATTR_CHANGED_ADDRESS     = stunmsg_c.STUN_ATTR_CHANGED_ADDRESS
  ATTR_USERNAME            = stunmsg_c.STUN_ATTR_USERNAME
  ATTR_PASSWORD            = stunmsg_c.STUN_ATTR_PASSWORD
  ATTR_MESSAGE_INTEGRITY   = stunmsg_c.STUN_ATTR_MESSAGE_INTEGRITY
  ATTR_ERROR_CODE          = stunmsg_c.STUN_ATTR_ERROR_CODE
  ATTR_UNKNOWN_ATTRIBUTES  = stunmsg_c.STUN_ATTR_UNKNOWN_ATTRIBUTES
  ATTR_REFLECTED_FROM      = stunmsg_c.STUN_ATTR_REFLECTED_FROM
  ATTR_CHANNEL_NUMBER      = stunmsg_c.STUN_ATTR_CHANNEL_NUMBER
  ATTR_LIFETIME            = stunmsg_c.STUN_ATTR_LIFETIME
  ATTR_BANDWIDTH           = stunmsg_c.STUN_ATTR_BANDWIDTH
  ATTR_XOR_PEER_ADDRESS    = stunmsg_c.STUN_ATTR_XOR_PEER_ADDRESS
  ATTR_DATA                = stunmsg_c.STUN_ATTR_DATA
  ATTR_REALM               = stunmsg_c.STUN_ATTR_REALM
  ATTR_NONCE               = stunmsg_c.STUN_ATTR_NONCE
  ATTR_XOR_RELAYED_ADDRESS = stunmsg_c.STUN_ATTR_XOR_RELAYED_ADDRESS
  ATTR_REQ_ADDRESS_FAMILY  = stunmsg_c.STUN_ATTR_REQ_ADDRESS_FAMILY
  ATTR_EVEN_PORT           = stunmsg_c.STUN_ATTR_EVEN_PORT
  ATTR_REQUESTED_TRANSPORT = stunmsg_c.STUN_ATTR_REQUESTED_TRANSPORT
  ATTR_DONT_FRAGMENT       = stunmsg_c.STUN_ATTR_DONT_FRAGMENT
  ATTR_XOR_MAPPED_ADDRESS  = stunmsg_c.STUN_ATTR_XOR_MAPPED_ADDRESS
  ATTR_TIMER_VAL           = stunmsg_c.STUN_ATTR_TIMER_VAL
  ATTR_RESERVATION_TOKEN   = stunmsg_c.STUN_ATTR_RESERVATION_TOKEN
  ATTR_PRIORITY            = stunmsg_c.STUN_ATTR_PRIORITY
  ATTR_USE_CANDIDATE       = stunmsg_c.STUN_ATTR_USE_CANDIDATE
  ATTR_PADDING             = stunmsg_c.STUN_ATTR_PADDING
  ATTR_RESPONSE_PORT       = stunmsg_c.STUN_ATTR_RESPONSE_PORT
  ATTR_CONNECTION_ID       = stunmsg_c.STUN_ATTR_CONNECTION_ID
  ATTR_SOFTWARE            = stunmsg_c.STUN_ATTR_SOFTWARE
  ATTR_ALTERNATE_SERVER    = stunmsg_c.STUN_ATTR_ALTERNATE_SERVER
  ATTR_FINGERPRINT         = stunmsg_c.STUN_ATTR_FINGERPRINT
  ATTR_ICE_CONTROLLED      = stunmsg_c.STUN_ATTR_ICE_CONTROLLED
  ATTR_ICE_CONTROLLING     = stunmsg_c.STUN_ATTR_ICE_CONTROLLING
  ATTR_RESPONSE_ORIGIN     = stunmsg_c.STUN_ATTR_RESPONSE_ORIGIN
  ATTR_OTHER_ADDRESS       = stunmsg_c.STUN_ATTR_OTHER_ADDRESS

  ERROR_TRY_ALTERNATE             = stunmsg_c.STUN_ERROR_TRY_ALTERNATE
  ERROR_BAD_REQUEST               = stunmsg_c.STUN_ERROR_BAD_REQUEST
  ERROR_UNAUTHORIZED              = stunmsg_c.STUN_ERROR_UNAUTHORIZED
  ERROR_FORBIDDEN                 = stunmsg_c.STUN_ERROR_FORBIDDEN
  ERROR_UNKNOWN_ATTRIBUTE         = stunmsg_c.STUN_ERROR_UNKNOWN_ATTRIBUTE
  ERROR_ALLOCATION_MISMATCH       = stunmsg_c.STUN_ERROR_ALLOCATION_MISMATCH
  ERROR_STALE_NONCE               = stunmsg_c.STUN_ERROR_STALE_NONCE
  ERROR_ADDR_FAMILY_NOT_SUPP      = stunmsg_c.STUN_ERROR_ADDR_FAMILY_NOT_SUPP
  ERROR_WRONG_CREDENTIALS         = stunmsg_c.STUN_ERROR_WRONG_CREDENTIALS
  ERROR_UNSUPP_TRANSPORT_PROTO    = stunmsg_c.STUN_ERROR_UNSUPP_TRANSPORT_PROTO
  ERROR_PEER_ADD_FAMILY_MISMATCH  = stunmsg_c.STUN_ERROR_PEER_ADD_FAMILY_MISMATCH
  ERROR_CONNECTION_ALREADY_EXISTS = stunmsg_c.STUN_ERROR_CONNECTION_ALREADY_EXISTS
  ERROR_CONNECTION_FAILURE        = stunmsg_c.STUN_ERROR_CONNECTION_FAILURE
  ERROR_ALLOCATION_QUOTA_REACHED  = stunmsg_c.STUN_ERROR_ALLOCATION_QUOTA_REACHED
  ERROR_ROLE_CONFLICT             = stunmsg_c.STUN_ERROR_ROLE_CONFLICT
  ERROR_SERVER_ERROR              = stunmsg_c.STUN_ERROR_SERVER_ERROR
  ERROR_INSUFFICIENT_CAPACITY     = stunmsg_c.STUN_ERROR_INSUFFICIENT_CAPACITY

  translators = {
    stunmsg_c.STUN_ATTR_MAPPED_ADDRESS      : 'sockaddr',
    stunmsg_c.STUN_ATTR_RESPONSE_ADDRESS    : 'sockaddr',
    stunmsg_c.STUN_ATTR_CHANGE_REQUEST      : 'uint32',
    stunmsg_c.STUN_ATTR_SOURCE_ADDRESS      : 'sockaddr',
    stunmsg_c.STUN_ATTR_CHANGED_ADDRESS     : 'sockaddr',
    stunmsg_c.STUN_ATTR_USERNAME            : 'string',
    stunmsg_c.STUN_ATTR_PASSWORD            : 'string',
    stunmsg_c.STUN_ATTR_MESSAGE_INTEGRITY   : 'msgint',
    stunmsg_c.STUN_ATTR_ERROR_CODE          : 'errcode',
    stunmsg_c.STUN_ATTR_UNKNOWN_ATTRIBUTES  : 'unknown',
    stunmsg_c.STUN_ATTR_REFLECTED_FROM      : 'sockaddr',
    stunmsg_c.STUN_ATTR_CHANNEL_NUMBER      : 'uint32',
    stunmsg_c.STUN_ATTR_LIFETIME            : 'uint32',
    stunmsg_c.STUN_ATTR_BANDWIDTH           : 'uint32',
    stunmsg_c.STUN_ATTR_XOR_PEER_ADDRESS    : 'xor_sockaddr',
    stunmsg_c.STUN_ATTR_DATA                : 'data',
    stunmsg_c.STUN_ATTR_REALM               : 'string',
    stunmsg_c.STUN_ATTR_NONCE               : 'string',
    stunmsg_c.STUN_ATTR_XOR_RELAYED_ADDRESS : 'xor_sockaddr',
    stunmsg_c.STUN_ATTR_REQ_ADDRESS_FAMILY  : 'uint8',
    stunmsg_c.STUN_ATTR_EVEN_PORT           : 'uint8_pad',
    stunmsg_c.STUN_ATTR_REQUESTED_TRANSPORT : 'uint32',
    stunmsg_c.STUN_ATTR_DONT_FRAGMENT       : 'empty',
    stunmsg_c.STUN_ATTR_XOR_MAPPED_ADDRESS  : 'xor_sockaddr',
    stunmsg_c.STUN_ATTR_TIMER_VAL           : 'uint32',
    stunmsg_c.STUN_ATTR_RESERVATION_TOKEN   : 'uint64',
    stunmsg_c.STUN_ATTR_PRIORITY            : 'uint32',
    stunmsg_c.STUN_ATTR_USE_CANDIDATE       : 'empty',
    stunmsg_c.STUN_ATTR_PADDING             : 'data',
    stunmsg_c.STUN_ATTR_RESPONSE_PORT       : 'uint16_pad',
    stunmsg_c.STUN_ATTR_CONNECTION_ID       : 'uint32',
    stunmsg_c.STUN_ATTR_SOFTWARE            : 'string',
    stunmsg_c.STUN_ATTR_ALTERNATE_SERVER    : 'sockaddr',
    stunmsg_c.STUN_ATTR_FINGERPRINT         : 'uint32',
    stunmsg_c.STUN_ATTR_ICE_CONTROLLED      : 'uint64',
    stunmsg_c.STUN_ATTR_ICE_CONTROLLING     : 'uint64',
    stunmsg_c.STUN_ATTR_RESPONSE_ORIGIN     : 'sockaddr',
    stunmsg_c.STUN_ATTR_OTHER_ADDRESS       : 'sockaddr',
  }

  def __init__(self, msg_type=None, tsx_id=None, buf=bytearray(20)):
    assert type(buf) is bytearray
    self.buf = buf
    if msg_type != None and tsx_id != None:
      stunmsg_c.stun_msg_hdr_init(self.buf, msg_type, tsx_id)

  def data(self):
    return self.buf[:stunmsg_c.stun_msg_len(self.buf)]

  def type(self):
    return stunmsg_c.stun_msg_type(self.buf)

  def verify(self):
    return True if stunmsg_c.stun_msg_verify(self.buf, len(self.buf)) == 1 else False

  def iterattrs(self):
    i = stunmsg_c.next_attr(self.buf, 0)
    while (i != None):
      yield self._get_attr(i)

  def appendattr(attr_type, value):
    valtype = translators[attr_type]
    if valtype == None:
      valtype = 'data' # defaults to data
    return getattr(self, '_append_' + valtype)(attr_type, value)

  def _get_attrs(self, i):
    attr_type = stunmsg_c.stun_attr_type(self.buf, i)
    return (attr_type, self._get_attr_type(attr_type, i))

  def _get_attr_type(self, attr_type, i):
    valtype = translators[attr_type]
    if valtype == None:
      valtype = 'data' # defaults to data
    return getattr(self, '_get_' + valtype)(i)

  def _get_empty():
    return None

  def _append_empty(attr_type, value):
    self.buf[len(self.buf):] = bytearray(4)
    stunmsg_c.stun_attr_empty_add(self.buf, attr_type)

  def _get_errcode(i):
    status_code = stunmsg_c.stun_attr_errcode_status((self.buf, i));
    status_text = stunmsg_c.errcode_reason((self.buf, i));
    return (status_code, status_text)

  def _append_errcode(attr_type, value):
    status_code, status_text = value
    self.buf[len(self.buf):] = \
        bytearray(stunmsg_c.stun_attr_error_code_size(len(status_text)))
    stunmsg_c.stun_attr_errcode_add(self.buf, status_code, status_text, 0)

  def _get_uint8(i):
    return stunmsg_c.stun_attr_uint8_read((self.buf, i))

  def _append_uint8(attr_type, value):
    self.buf[len(self.buf):] = bytearray(stunmsg_c.stun_attr_uint8_size)
    stunmsg_c.stun_attr_uint8_add(self.buf, attr_type, value)

  def _get_uint16(i):
    return stunmsg_c.stun_attr_uint16_read((self.buf, i))

  def _append_uint16(attr_type, value):
    self.buf[len(self.buf):] = bytearray(stunmsg_c.stun_attr_uint16_size)
    stunmsg_c.stun_attr_uint16_add(self.buf, attr_type, value)

  def _get_uint32(i):
    return stunmsg_c.stun_attr_uint32_read((self.buf, i))

  def _append_uint32(attr_type, value):
    self.buf[len(self.buf):] = bytearray(stunmsg_c.stun_attr_uint32_size)
    stunmsg_c.stun_attr_uint32_add(self.buf, attr_type, value)

  def _get_uint64(i):
    return stunmsg_c.stun_attr_uint64_read((self.buf, i))

  def _append_uint64(attr_type, value):
    self.buf[len(self.buf):] = bytearray(stunmsg_c.stun_attr_uint64_size)
    stunmsg_c.stun_attr_uint64_add(self.buf, attr_type, value)

  def _get_unknown(i):
    len = stunmsg_c.stun_attr_unknown_count((self.buf, i))
    result = []
    for n in range(0, len):
      result.append(stunmsg_c.stun_attr_unknown_get((self.buf, i), n))
    return result

  def _append_unknown(attr_type, value):
    self.buf[len(self.buf):] = \
        bytearray(stunmsg_c.stun_attr_unknown_size(len(value)))
    stunmsg_c.stun_attr_unknown_add(self.buf, attr_type, value, 0)

  def _get_string(i):
    return stunmsg_c.string_read((self.buf, i))

  def _append_string(attr_type, value):
    self.buf[len(self.buf):] = \
        bytearray(stunmsg_c.stun_attr_varsize_size(len(value)))
    stunmsg_c.stun_attr_varsize_add(self.buf, attr_type, value, 0)

  def _get_data(i):
    return stunmsg_c.data_read((self.buf, i))

  def _append_data(attr_type, value):
    self.buf[len(self.buf):] = \
        bytearray(stunmsg_c.stun_attr_varsize_size(len(value)))
    stunmsg_c.stun_attr_varsize_add(self.buf, attr_type, value, 0)

  def _get_sockaddr(i):
    res, addr = stun_attr_sockaddr_read((self.buf, i))
    return addr if res == 0 else None

  def _append_sockaddr(attr_type, value):
    addr, port = value
    if len(addr.split(':')) == 0:
      family = stunmsg_c.STUN_IPV4
    else:
      family = stunmsg_c.STUN_IPV6
    self.buf[len(self.buf):] = \
        bytearray(stunmsg_c.stun_attr_sockaddr_size(family))
    stunmsg_c.stun_attr_sockaddr_add(self.buf, attr_type, (addr, port))

  def _get_xor_sockaddr(i):
    res, addr = stun_attr_xor_sockaddr_read((self.buf, i), self.buf)
    return addr if res == 0 else None

  def _append_xor_sockaddr(attr_type, value):
    addr, port = value
    if len(addr.split(':')) == 0:
      family = stunmsg_c.STUN_IPV4
    else:
      family = stunmsg_c.STUN_IPV6
    self.buf[len(self.buf):] = \
        bytearray(stunmsg_c.stun_attr_sockaddr_size(family))
    stunmsg_c.stun_attr_xor_sockaddr_add(self.buf, attr_type, (addr, port))

  def _get_msgint(i):
    def check(password):
      res = stunmsg_c.stun_attr_msgint_check((self.buf, i), self.buf, password)
      return True if res == 1 else False
    return check

  def _append_msgint(attr_type, key):
    self.buf[len(self.buf):] = bytearray(stunmsg_c.stun_attr_msgint_size)
    stunmsg_c.stun_attr_msgint_add(self.buf, key)

  def _get_fingerprint(i):
    def check():
      res = stunmsg_c.stun_attr_fingerprint_check((self.buf, i), self.buf)
      return True if res == 1 else False
    return check

  def _append_fingerprint(attr_type, key):
    self.buf[len(self.buf):] = bytearray(stunmsg_c.stun_attr_fingerprint_size)
    stunmsg_c.stun_attr_fingerprint_add(self.buf)

