/* Copyright (c) 2014 Guilherme Balena Versiani.
 *
 * I dedicate any and all copyright interest in this software to the
 * public domain. I make this dedication for the benefit of the public at
 * large and to the detriment of my heirs and successors. I intend this
 * dedication to be an overt act of relinquishment in perpetuity of all
 * present and future rights to this software under copyright law.
 */

#include <sstream>
#include <stun++/message.h>
#include <gtest/gtest.h>

/* Include these for sockaddr_in and sockaddr_in6 */
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif


#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

namespace {

void PrintWord(const uint8_t *v, size_t size, std::ostream &out) {
  size_t i;
  for (i = 0; i < size; i++) {
    if (i > 0)
      out << " ";
    out << std::setfill('0')
        << std::setw(2)
        << std::hex
        << (int)v[i];
  }
}

::testing::AssertionResult IsEqual(const void *vec_a, const void *vec_b,
                                   size_t size) {
  std::ostringstream out;
  const uint8_t *a = reinterpret_cast<const uint8_t*>(vec_a);
  const uint8_t *b = reinterpret_cast<const uint8_t*>(vec_b);
  size_t i, errors = 0;
  for (i = 0; i < size; i += 4) {
    size_t len = 4;
    if (i + len > size)
      len = size - i;
    out << "  ";
    PrintWord(a+i, len, out);
    if (memcmp(a+i, b+i, len) == 0) {
      out << "   ";
    } else {
      out << " ! ";
      ++errors;
    }
    PrintWord(b+i, len, out);
    out << "\n";
  }
  if (!errors)
    return ::testing::AssertionSuccess();
  else
    return ::testing::AssertionFailure()
        << "A and B aren't equal:\n"
        << out.str();
}

} // empty namespace

TEST(StunMsgCxx, BasicBindingRequest) {
  const uint8_t expected_result[] = {
    0x00,0x01,0x00,0x00, //    Request type and message length
    0x21,0x12,0xa4,0x42, //    Magic cookie
    0xfd,0x95,0xe8,0x83, // }
    0x8a,0x05,0x28,0x45, // }  Transaction ID
    0x6a,0x8e,0xf1,0xe2  // }
  };
  
  uint8_t tsx_id[12] = {
    0xfd,0x95,0xe8,0x83,
    0x8a,0x05,0x28,0x45,
    0x6a,0x8e,0xf1,0xe2
  };

  stun::message message(stun::message::binding_request, tsx_id);
  ASSERT_EQ(sizeof(expected_result), message.size());
  EXPECT_TRUE(IsEqual(expected_result, message.data(),
      sizeof(expected_result)));

  // Now decoding
  EXPECT_EQ(stun::message::binding_request, message.type());

  stun::message::iterator i = message.begin();
  ASSERT_TRUE(message.end() == i);
}

TEST(StunMsgCxx, RFC5769SampleRequest) {
  const char software_name[] = "STUN test client";
  const char username[] = "evtj:h6vY";
  const char password[] = "VOkJxbRl1RmTxUk/WvJxBt";

  const uint8_t expected_result[] = {
    0x00,0x01,0x00,0x58, //    Request type and message length
    0x21,0x12,0xa4,0x42, //    Magic cookie
    0xb7,0xe7,0xa7,0x01, // }
    0xbc,0x34,0xd6,0x86, // }  Transaction ID
    0xfa,0x87,0xdf,0xae, // }
    0x80,0x22,0x00,0x10, //    SOFTWARE attribute header
    0x53,0x54,0x55,0x4e, // }
    0x20,0x74,0x65,0x73, // }  User-agent...
    0x74,0x20,0x63,0x6c, // }  ...name
    0x69,0x65,0x6e,0x74, // }
    0x00,0x24,0x00,0x04, //    PRIORITY attribute header
    0x6e,0x00,0x01,0xff, //    ICE priority value
    0x80,0x29,0x00,0x08, //    ICE-CONTROLLED attribute header
    0x93,0x2f,0xf9,0xb1, // }  Pseudo-random tie breaker...
    0x51,0x26,0x3b,0x36, // }   ...for ICE control
    0x00,0x06,0x00,0x09, //    USERNAME attribute header
    0x65,0x76,0x74,0x6a, // }
    0x3a,0x68,0x36,0x76, // }  Username (9 bytes) and padding (3 bytes)
    0x59,0x20,0x20,0x20, // }
    0x00,0x08,0x00,0x14, //    MESSAGE-INTEGRITY attribute header
    0x9a,0xea,0xa7,0x0c, // }
    0xbf,0xd8,0xcb,0x56, // }
    0x78,0x1e,0xf2,0xb5, // }  HMAC-SHA1 fingerprint
    0xb2,0xd3,0xf2,0x49, // }
    0xc1,0xb5,0x71,0xa2, // }
    0x80,0x28,0x00,0x04, //    FINGERPRINT attribute header
    0xe5,0x7a,0x3b,0xcf, //    CRC0x32, fingerprint
  };

  uint8_t tsx_id[12] = {
    0xb7,0xe7,0xa7,0x01,
    0xbc,0x34,0xd6,0x86,
    0xfa,0x87,0xdf,0xae
  };

  stun::message message(stun::message::binding_request, tsx_id);
  message << stun::attribute::software(software_name, ' ')
          << stun::attribute::priority(0x6e0001fful)
          << stun::attribute::ice_controlled(0x932ff9b151263b36ull)
          << stun::attribute::username(username, ' ')
          << stun::attribute::message_integrity(password)
          << stun::attribute::fingerprint();
  ASSERT_EQ(sizeof(expected_result), message.size());
  EXPECT_TRUE(IsEqual(expected_result, message.data(),
      sizeof(expected_result)));

  // Now decoding
  using namespace stun::attribute;
  EXPECT_EQ(stun::message::binding_request, message.type());

  stun::message::iterator i = message.begin();
  ASSERT_TRUE(message.end() != i);
  EXPECT_EQ(type::software, i->type());
  ASSERT_EQ(software_name,
    i->to<type::software>().to_string());

  ASSERT_TRUE(message.end() != ++i);
  EXPECT_EQ(type::priority, i->type());
  EXPECT_EQ(0x6e0001fful,
    i->to<type::priority>().value());

  ASSERT_TRUE(message.end() != ++i);
  EXPECT_EQ(type::ice_controlled, i->type());
  EXPECT_EQ(0x932ff9b151263b36ull,
    i->to<type::ice_controlled>().value());

  ASSERT_TRUE(message.end() != ++i);
  EXPECT_EQ(type::username, i->type());
  EXPECT_EQ(username,
    i->to<type::username>().to_string());

  ASSERT_TRUE(message.end() != ++i);
  EXPECT_EQ(type::message_integrity, i->type());
  EXPECT_TRUE(
    i->to<type::message_integrity>().check_integrity(password));

  ASSERT_TRUE(message.end() != ++i);
  EXPECT_EQ(type::fingerprint, i->type());

  ASSERT_TRUE(message.end() == ++i);
}

TEST(StunMsgCxx, RFC5769SampleIPv4Response) {
  const char software_name[] = "test vector";
  const char password[] = "VOkJxbRl1RmTxUk/WvJxBt";

  const uint8_t expected_result[] = {
    0x01,0x01,0x00,0x3c, //    Request type and message length
    0x21,0x12,0xa4,0x42, //    Magic cookie
    0xb7,0xe7,0xa7,0x01, // }
    0xbc,0x34,0xd6,0x86, // }  Transaction ID
    0xfa,0x87,0xdf,0xae, // }
    0x80,0x22,0x00,0x0b, //    SOFTWARE attribute header
    0x74,0x65,0x73,0x74, // }
    0x20,0x76,0x65,0x63, // }  UTF-8 server name
    0x74,0x6f,0x72,0x20, // }
    0x00,0x20,0x00,0x08, //    XOR-MAPPED-ADDRESS attribute header
    0x00,0x01,0xa1,0x47, //    Address family (IPv4) and xor'd mapped port number
    0xe1,0x12,0xa6,0x43, //    Xor'd mapped IPv4 address
    0x00,0x08,0x00,0x14, //    MESSAGE-INTEGRITY attribute header
    0x2b,0x91,0xf5,0x99, // }
    0xfd,0x9e,0x90,0xc3, // }
    0x8c,0x74,0x89,0xf9, // }  HMAC-SHA1 fingerprint
    0x2a,0xf9,0xba,0x53, // }
    0xf0,0x6b,0xe7,0xd7, // }
    0x80,0x28,0x00,0x04, //    FINGERPRINT attribute header
    0xc0,0x7d,0x4c,0x96, //    CRC32 fingerprint
  };

  uint8_t tsx_id[12] = {
    0xb7,0xe7,0xa7,0x01,
    0xbc,0x34,0xd6,0x86,
    0xfa,0x87,0xdf,0xae
  };

  sockaddr_in ipv4;
  ipv4.sin_family = AF_INET;
  ipv4.sin_port = htons(32853);
  inet_pton(AF_INET, "192.0.2.1", &ipv4.sin_addr);

  stun::message message(stun::message::binding_response, tsx_id);
  message << stun::attribute::software(software_name, ' ')
          << stun::attribute::xor_mapped_address(ipv4)
          << stun::attribute::message_integrity(password)
          << stun::attribute::fingerprint();
  ASSERT_EQ(sizeof(expected_result), message.size());
  EXPECT_TRUE(IsEqual(expected_result, message.data(),
      sizeof(expected_result)));

  // Now decoding
  using namespace stun::attribute;
  EXPECT_EQ(stun::message::binding_response, message.type());

  stun::message::iterator i = message.begin();
  ASSERT_TRUE(message.end() != i);
  EXPECT_EQ(type::software, i->type());
  ASSERT_EQ(software_name,
    i->to<type::software>().to_string());

  ASSERT_TRUE(message.end() != ++i);
  EXPECT_EQ(type::xor_mapped_address, i->type());
  sockaddr_in test_addr;
  memset(&test_addr, 0, sizeof(test_addr));
  EXPECT_TRUE(
    i->to<type::xor_mapped_address>().to_sockaddr((sockaddr*)&test_addr));
  EXPECT_EQ(AF_INET, test_addr.sin_family);
  EXPECT_EQ(htons(32853), test_addr.sin_port);
  EXPECT_EQ(0, memcmp(&test_addr.sin_addr, &ipv4.sin_addr,
      sizeof(ipv4.sin_addr)));

  ASSERT_TRUE(message.end() != ++i);
  EXPECT_EQ(type::message_integrity, i->type());
  EXPECT_TRUE(
    i->to<type::message_integrity>().check_integrity(password));

  ASSERT_TRUE(message.end() != ++i);
  EXPECT_EQ(type::fingerprint, i->type());

  ASSERT_TRUE(message.end() == ++i);
}

TEST(StunMsgEncode, RFC5769SampleIPv6Response) {
  const char software_name[] = "test vector";
  const char password[] = "VOkJxbRl1RmTxUk/WvJxBt";

  const uint8_t expected_result[] = {
    0x01,0x01,0x00,0x48, //    Request type and message length
    0x21,0x12,0xa4,0x42, //    Magic cookie
    0xb7,0xe7,0xa7,0x01, // }
    0xbc,0x34,0xd6,0x86, // }  Transaction ID
    0xfa,0x87,0xdf,0xae, // }
    0x80,0x22,0x00,0x0b, //    SOFTWARE attribute header
    0x74,0x65,0x73,0x74, // }
    0x20,0x76,0x65,0x63, // }  UTF-8 server name
    0x74,0x6f,0x72,0x20, // }
    0x00,0x20,0x00,0x14, //    XOR-MAPPED-ADDRESS attribute header
    0x00,0x02,0xa1,0x47, //    Address family (IPv4) and xor'd mapped port number
    0x01,0x13,0xa9,0xfa, // }
    0xa5,0xd3,0xf1,0x79, // }  Xor'd mapped IPv6 address
    0xbc,0x25,0xf4,0xb5, // }
    0xbe,0xd2,0xb9,0xd9, // }
    0x00,0x08,0x00,0x14, //    MESSAGE-INTEGRITY attribute header
    0xa3,0x82,0x95,0x4e, // }
    0x4b,0xe6,0x7b,0xf1, // }
    0x17,0x84,0xc9,0x7c, // }  HMAC-SHA1 fingerprint
    0x82,0x92,0xc2,0x75, // }
    0xbf,0xe3,0xed,0x41, // }
    0x80,0x28,0x00,0x04, //    FINGERPRINT attribute header
    0xc8,0xfb,0x0b,0x4c, //    CRC32 fingerprint
  };

  uint8_t tsx_id[12] = {
    0xb7,0xe7,0xa7,0x01,
    0xbc,0x34,0xd6,0x86,
    0xfa,0x87,0xdf,0xae
  };

  sockaddr_in6 ipv6;
  ipv6.sin6_family = AF_INET6;
  ipv6.sin6_port = htons(32853);
  inet_pton(AF_INET6, "2001:db8:1234:5678:11:2233:4455:6677", &ipv6.sin6_addr);

  stun::message message(stun::message::binding_response, tsx_id);
  message << stun::attribute::software(software_name, ' ')
          << stun::attribute::xor_mapped_address(ipv6)
          << stun::attribute::message_integrity(password)
          << stun::attribute::fingerprint();
  ASSERT_EQ(sizeof(expected_result), message.size());
  EXPECT_TRUE(IsEqual(expected_result, message.data(),
      sizeof(expected_result)));

  // Now decoding
  using namespace stun::attribute;
  EXPECT_EQ(stun::message::binding_response, message.type());

  stun::message::iterator i = message.begin();
  ASSERT_TRUE(message.end() != i);
  EXPECT_EQ(type::software, i->type());
  ASSERT_EQ(software_name,
    i->to<type::software>().to_string());

  ASSERT_TRUE(message.end() != ++i);
  EXPECT_EQ(type::xor_mapped_address, i->type());
  sockaddr_in6 test_addr;
  memset(&test_addr, 0, sizeof(test_addr));
  EXPECT_TRUE(
    i->to<type::xor_mapped_address>().to_sockaddr((sockaddr*)&test_addr));
  EXPECT_EQ(AF_INET6, test_addr.sin6_family);
  EXPECT_EQ(htons(32853), test_addr.sin6_port);
  EXPECT_EQ(0, memcmp(&test_addr.sin6_addr, &ipv6.sin6_addr,
      sizeof(ipv6.sin6_addr)));

  ASSERT_TRUE(message.end() != ++i);
  EXPECT_EQ(type::message_integrity, i->type());
  EXPECT_TRUE(
    i->to<type::message_integrity>().check_integrity(password));

  ASSERT_TRUE(message.end() != ++i);
  EXPECT_EQ(type::fingerprint, i->type());

  ASSERT_TRUE(message.end() == ++i);
}

TEST(StunMsgCxx, RFC5769SampleRequestLongTerm) {
  const char username[] =
    "\xE3\x83\x9E\xE3"
    "\x83\x88\xE3\x83"
    "\xAA\xE3\x83\x83"
    "\xE3\x82\xAF\xE3"
    "\x82\xB9";
  const char password[] = "TheMatrIX";
  const char nonce[] = "f//499k954d6OL34oL9FSTvy64sA";
  const char realm[] = "example.org";

  const uint8_t expected_result[] = {
    0x00,0x01,0x00,0x60, //    Request type and message length
    0x21,0x12,0xa4,0x42, //    Magic cookie
    0x78,0xad,0x34,0x33, // }
    0xc6,0xad,0x72,0xc0, // }  Transaction ID
    0x29,0xda,0x41,0x2e, // }
    0x00,0x06,0x00,0x12, //    USERNAME attribute header
    0xe3,0x83,0x9e,0xe3, // }
    0x83,0x88,0xe3,0x83, // }
    0xaa,0xe3,0x83,0x83, // }  Username value (0x18,bytes) and padding (2 bytes)
    0xe3,0x82,0xaf,0xe3, // }
    0x82,0xb9,0x00,0x00, // }
    0x00,0x15,0x00,0x1c, //    NONCE attribute header
    0x66,0x2f,0x2f,0x34, // }
    0x39,0x39,0x6b,0x39, // }
    0x35,0x34,0x64,0x36, // }
    0x4f,0x4c,0x33,0x34, // }  Nonce value
    0x6f,0x4c,0x39,0x46, // }
    0x53,0x54,0x76,0x79, // }
    0x36,0x34,0x73,0x41, // }
    0x00,0x14,0x00,0x0b, //    REALM attribute header
    0x65,0x78,0x61,0x6d, // }
    0x70,0x6c,0x65,0x2e, // }  Realm value (0x11,bytes) and padding (1 byte)
    0x6f,0x72,0x67,0x00, // }
    0x00,0x08,0x00,0x14, //    MESSAGE-INTEGRITY attribute header
    0xf6,0x70,0x24,0x65, // }
    0x6d,0xd6,0x4a,0x3e, // }
    0x02,0xb8,0xe0,0x71, // }  HMAC-SHA1 fingerprint
    0x2e,0x85,0xc9,0xa2, // }
    0x8c,0xa8,0x96,0x66, // }
  };

  uint8_t tsx_id[12] = {
    0x78,0xad,0x34,0x33,
    0xc6,0xad,0x72,0xc0,
    0x29,0xda,0x41,0x2e,
  };

  uint8_t key[16];
  stun_genkey(username, sizeof(username)-1, realm, sizeof(realm)-1,
              password, sizeof(password)-1, key);

  stun::message message(stun::message::binding_request, tsx_id);
  message << stun::attribute::username(username)
          << stun::attribute::nonce(nonce)
          << stun::attribute::realm(realm)
          << stun::attribute::message_integrity(key, sizeof(key));
  ASSERT_EQ(sizeof(expected_result), message.size());
  EXPECT_TRUE(IsEqual(expected_result, message.data(),
      sizeof(expected_result)));

  // Now decoding
  using namespace stun::attribute;
  EXPECT_EQ(stun::message::binding_request, message.type());

  stun::message::iterator i = message.begin();
  ASSERT_TRUE(message.end() != i);
  EXPECT_EQ(type::username, i->type());
  ASSERT_EQ(username,
    i->to<type::username>().to_string());

  ASSERT_TRUE(message.end() != ++i);
  EXPECT_EQ(type::nonce, i->type());
  ASSERT_EQ(nonce,
    i->to<type::nonce>().to_string());

  ASSERT_TRUE(message.end() != ++i);
  EXPECT_EQ(type::realm, i->type());
  ASSERT_EQ(realm,
    i->to<type::realm>().to_string());

  ASSERT_TRUE(message.end() != ++i);
  EXPECT_EQ(type::message_integrity, i->type());
  EXPECT_TRUE(
    i->to<type::message_integrity>().check_integrity(key, key + sizeof(key)));

  ASSERT_TRUE(message.end() == ++i);
}

TEST(StunMsgCxx, ErrorResponse) {
  const char reason_phrase[] = "Unknown Attribute";
  const uint8_t expected_result[] = {
    0x01,0x11,0x00,0x28, //    Request type and message length
    0x21,0x12,0xa4,0x42, //    Magic cookie
    0x78,0xad,0x34,0x33, // }
    0xc6,0xad,0x72,0xc0, // }  Transaction ID
    0x29,0xda,0x41,0x2e, // }
    0x00,0x09,0x00,0x15, //    ERROR-CODE attribute header
    0x00,0x00,0x04,0x14, //    class = 4, code = 20 (420)
    0x55,0x6e,0x6b,0x6e, // }
    0x6f,0x77,0x6e,0x20, // }
    0x41,0x74,0x74,0x72, // }  Reason: Unknown Attribute
    0x69,0x62,0x75,0x74, // }
    0x65,0x00,0x00,0x00, // }
    0x00,0x0A,0x00,0x06, //    UNKNOWN-ATTRIBUTES attribute header
    0x00,0x1A,0x00,0x1B, //    0x001A, 0x001B
    0x80,0x2C,0x00,0x00, //    0x802C
  };

  uint8_t tsx_id[12] = {
    0x78,0xad,0x34,0x33,
    0xc6,0xad,0x72,0xc0,
    0x29,0xda,0x41,0x2e,
  };
  uint16_t unknown[] = { 0x001a, 0x001b, 0x802c };

  stun::message message(stun::message::binding_error_response, tsx_id);
  message << stun::attribute::error_code(420, reason_phrase)
          << stun::attribute::unknown_attributes(unknown, ARRAY_SIZE(unknown));
  ASSERT_EQ(sizeof(expected_result), message.size());
  EXPECT_TRUE(IsEqual(expected_result, message.data(),
      sizeof(expected_result)));

  // Now decoding
  using namespace stun::attribute;
  EXPECT_EQ(stun::message::binding_error_response, message.type());

  stun::message::iterator i = message.begin();
  ASSERT_TRUE(message.end() != i);
  EXPECT_EQ(type::error_code, i->type());
  stun::attribute::decoding::error_code errcode =
    i->to<type::error_code>();
  EXPECT_EQ(420, errcode.status_code());
  EXPECT_EQ(reason_phrase, errcode.reason_phrase());

  ASSERT_TRUE(message.end() != ++i);
  EXPECT_EQ(type::unknown_attributes, i->type());
  stun::attribute::decoding::unknown_attributes unk =
    i->to<type::unknown_attributes>();
  ASSERT_EQ(ARRAY_SIZE(unknown), unk.size());
  for (size_t i = 0; i < ARRAY_SIZE(unknown); i++) {
    EXPECT_EQ(unknown[i], unk[i]);
  }

  ASSERT_TRUE(message.end() == ++i);
}
