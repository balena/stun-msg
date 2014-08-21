/* Copyright (c) 2014 Guilherme Balena Versiani.
 *
 * I dedicate any and all copyright interest in this software to the
 * public domain. I make this dedication for the benefit of the public at
 * large and to the detriment of my heirs and successors. I intend this
 * dedication to be an overt act of relinquishment in perpetuity of all
 * present and future rights to this software under copyright law.
 */

#include <stun.h>
#include <gtest/gtest.h>

void dump_vector(const uint8_t *v, size_t size) {
  size_t i;
  printf("  ");
  for (i = 0; i < size; i++) {
    if (i > 0)
      printf(", ");
    if (i > 0 && (i % 4) == 0)
      printf("\n  ");
    printf("0x%02x", v[i]);
  }
  printf("\n");
}

TEST(StunMsg, BasicBindingRequest) {
  const uint8_t expected_result[] = {
    0x00,0x01,0x00,0x00, //    Request type and message length
    0x21,0x12,0xa4,0x42, //    Magic cookie
    0xfd,0x95,0xe8,0x83, // }
    0x8a,0x05,0x28,0x45, // }  Transaction ID
    0x6a,0x8e,0xf1,0xe2  // }
  };
  uint8_t buffer[sizeof(expected_result)];
  stun_msg msg;
  uint8_t tsx_id[12] = {
    0xfd,0x95,0xe8,0x83,
    0x8a,0x05,0x28,0x45,
    0x6a,0x8e,0xf1,0xe2
  };
  stun_msg_init(&msg, STUN_BINDING_REQUEST, tsx_id);
  int rv = stun_msg_encode(&msg, buffer, sizeof(buffer), NULL, 0);
  ASSERT_EQ(sizeof(buffer), rv);
  EXPECT_EQ(0, memcmp(expected_result, buffer, rv));
}

TEST(StunMsg, RFC5769SampleRequest) {
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
  uint8_t buffer[sizeof(expected_result)];
  stun_msg msg;
  uint8_t tsx_id[12] = {
    0xb7,0xe7,0xa7,0x01,
    0xbc,0x34,0xd6,0x86,
    0xfa,0x87,0xdf,0xae
  };
  stun_attr_string software;
  stun_attr_uint32 priority;
  stun_attr_uint64 ice_controlled;
  stun_attr_string username_attr;
  stun_attr_msgint msgint;
  stun_attr_uint32 fingerprint;
  stun_msg_init(&msg, STUN_BINDING_REQUEST, tsx_id);
  stun_attr_string_init(&software, STUN_SOFTWARE, software_name,
      strlen(software_name));
  stun_msg_add_attr(&msg, &software.hdr);
  stun_attr_uint32_init(&priority, STUN_PRIORITY, 0x6e0001fful);
  stun_msg_add_attr(&msg, &priority.hdr);
  stun_attr_uint64_init(&ice_controlled, STUN_ICE_CONTROLLED,
      0x932ff9b151263b36ull);
  stun_msg_add_attr(&msg, &ice_controlled.hdr);
  stun_attr_string_init(&username_attr, STUN_USERNAME, username,
      strlen(username));
  stun_msg_add_attr(&msg, &username_attr.hdr);
  stun_attr_msgint_init(&msgint);
  stun_msg_add_attr(&msg, &msgint.hdr);
  stun_attr_uint32_init(&fingerprint, STUN_FINGERPRINT, 0);
  stun_msg_add_attr(&msg, &fingerprint.hdr);
  stun_set_padding_byte((uint8_t)' ');
  int rv = stun_msg_encode(&msg, buffer, sizeof(buffer),
      (uint8_t*)password, strlen(password));
  ASSERT_EQ(sizeof(buffer), rv);
  dump_vector(buffer, sizeof(buffer));
  EXPECT_EQ(0, memcmp(expected_result, buffer, rv));
}
