# Copyright (c) 2015 Guilherme Balena Versiani.
#
# I dedicate any and all copyright interest in this software to the
# public domain. I make this dedication for the benefit of the public at
# large and to the detriment of my heirs and successors. I intend this
# dedication to be an overt act of relinquishment in perpetuity of all
# present and future rights to this software under copyright law.

import binascii
import logging
import random
import socket
from stunmsg import StunMsg

version = '1.0'
log = logging.getLogger("stunmsg")

STUN_SERVERS = [
  ( 'stun.ekiga.net', 3478 ),
  ( 'stun.ideasip.com', 3478 ),
  ( 'stun.voiparound.com', 3478 ),
  ( 'stun.voipbuster.com', 3478 ),
  ( 'stun.voipstunt.com', 3478 ),
  ( 'stun.voxgratia.org', 3478 ),
]

DEFAULTS = {
  'stun_port': 3478,
  'source_ip': '0.0.0.0',
  'source_port': 54320
}

Blocked = "Blocked"
OpenInternet = "Open Internet"
FullCone = "Full Cone"
SymmetricFirewall = "Symmetric Firewall"
RestrictedCone = "Restricted Cone"
PortRestrictedCone = "Port Restricted Cone"
Symmetric = "Symmetric"
ChangedAddressError = "Found error in Test1 on Changed IP/Port"

def _random_tsx_id():
  a = ''.join(random.choice('0123456789ABCDEF') for i in range(24))
  return binascii.a2b_hex(a)

def _send_request(sock, host, port, change_request=None):
  class Result(object):
    succeeded = False
    external_ip = None
    external_port = None
    source_ip = None
    source_port = None
    changed_ip = None
    changed_port = None

    def __str__(self):
      return str(self.__dict__)

  result = Result()
  tsx_id = _random_tsx_id()
  msg = StunMsg(StunMsg.BINDING_REQUEST, tsx_id)
  if change_request != None:
    msg.appendattr(StunMsg.ATTR_CHANGE_REQUEST, change_request)
  recvCorr = False
  while not recvCorr:
    received = False
    count = 3
    while not received:
      log.debug("sendto: %s", (host, port))
      try:
        sock.sendto(msg.data, (host, port))
      except socket.gaierror:
        return result
      try:
        buf, addr = sock.recvfrom(2048)
        log.debug("recvfrom: %s", addr)
        received = True
      except Exception:
        received = False
        if count == 0:
          return result
        count -= 1
    resp = StunMsg(data=buf)
    if resp.type == StunMsg.BINDING_RESPONSE and msg.tsx_id == tsx_id:
      recvCorr = True
      result.succeeded = True
      for attr_type, attr_value in resp.iterattrs():
        if attr_type == StunMsg.ATTR_MAPPED_ADDRESS:
          result.external_ip, result.external_port = attr_value
        elif attr_type == StunMsg.ATTR_SOURCE_ADDRESS:
          result.source_ip, result.source_port = attr_value
        elif attr_type == StunMsg.ATTR_CHANGED_ADDRESS:
          result.changed_ip, result.changed_port = attr_value
  return result

def _get_nat_type(s, local_address, server_address):
  source_ip, source_port = local_address
  stun_host, stun_port = server_address
  port = stun_port
  log.debug("Do Test1")
  log.debug('Trying STUN host: %s', stun_host)
  resp = _send_request(s, stun_host, port)
  if not resp.succeeded:
    return Blocked, resp
  log.debug("Result: %s", resp)
  external_ip = resp.external_ip
  external_port = resp.external_port
  changed_ip = resp.changed_ip
  changed_port = resp.changed_port
  if resp.external_ip == source_ip:
    change_request = 0x06 # change address and port
    resp = _send_request(s, stun_host, port, change_request)
    if resp.succeeded:
      typ = OpenInternet
    else:
      typ = SymmetricFirewall
  else:
    change_request = 0x06 # change address and port
    log.debug("Do Test2")
    resp = _send_request(s, stun_host, port, change_request)
    log.debug("Result: %s", resp)
    if resp.succeeded:
      typ = FullCone
    else:
      log.debug("Do Test1")
      resp = _send_request(s, changed_ip, changed_port)
      log.debug("Result: %s", resp)
      if not resp.succeeded:
        typ = ChangedAddressError
      else:
        if external_ip == resp.external_ip and \
           external_port == resp.external_port:
          change_request = 0x02 # change port
          log.debug("Do Test3")
          resp = _send_request(s, changed_ip, port, change_request)
          log.debug("Result: %s", resp)
          if resp.succeeded:
            typ = RestrictedCone
          else:
            typ = PortRestrictedCone
        else:
          typ = Symmetric
  return typ, resp

def _parse_hostport(hostport):
  if hostport[0] == '[': # an IPv6 address
    colon = hostport.rfind(':')
    sqb_end = hostport.rfind(']')
    if colon > sqb_end:
      host = hostport[1:colon-1]
      port = int(hostport[colon+1:])
    else:
      host = hostport[1:len(hostport)-1]
      port = DEFAULTS['stun_port']
  else:
    pair = hostport.split(':')
    host = pair[0]
    if len(pair) == 1:
      port = DEFAULTS['stun_port']
    else:
      port = int(pair[1])
  return host, port

def get_nat_type(server_address, local_address=("0.0.0.0", 0)):
  host, port = server_address
  socket.setdefaulttimeout(2)
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  s.bind(local_address)
  nat_type, resp = _get_nat_type(s, s.getsockname(), server_address)
  s.close()
  return (nat_type, resp.external_ip, resp.external_port)

def run():
  import argparse
  import logging
  import sys

  parser = argparse.ArgumentParser()
  parser.add_argument('servers', metavar='server', type=str, nargs='*',
                      help='a STUN server to perform the NAT test')
  parser.add_argument('-d', '--debug', default=True, action='store_true',
                      help='Enable debug logging')
  parser.add_argument('-i', '--interface', default="0.0.0.0:0",
                      help='Network interface to listen to')
  parser.add_argument('--version', action='version', version=version)
  options = parser.parse_args()

  if options.debug:
    logging.basicConfig()
    log.setLevel(logging.DEBUG)

  if options.servers:
    server_addresses = [_parse_hostport(server) for server in options.server_addresses]
  else:
    server_addresses = STUN_SERVERS

  local_address = _parse_hostport(options.interface)

  try:
    for server_address in server_addresses:
      nat_type, external_ip, external_port = get_nat_type(
          server_address, local_address)
      print 'NAT Type:', nat_type
      print 'External IP:', external_ip
      print 'External Port:', external_port

  except KeyboardInterrupt:
    sys.exit()

