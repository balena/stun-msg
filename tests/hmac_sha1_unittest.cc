/* Copyright (c) 2014 Guilherme Balena Versiani.
 *
 * I dedicate any and all copyright interest in this software to the
 * public domain. I make this dedication for the benefit of the public at
 * large and to the detriment of my heirs and successors. I intend this
 * dedication to be an overt act of relinquishment in perpetuity of all
 * present and future rights to this software under copyright law.
 */

#include <string>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <hmac_sha1.h>
#include <gtest/gtest.h>

namespace {

std::string digest_to_hex(const uint8_t digest[20]) {
  int i,j;
  std::ostringstream out;
  for (i = 0; i < 20/4; i++) {
    if (i > 0)
      out << " ";
    for (j = 0; j < 4; j++) {
      out << std::setfill('0')
          << std::setw(2)
          << std::uppercase
          << std::hex
          << (int)digest[i*4+j];
    }
  }
  return out.str();
}

::testing::AssertionResult IsEqual(const char *test_data,
                                   const uint8_t *digest,
                                   const char *test_result) {
  std::string output = digest_to_hex(digest);
  if (strcmp(output.c_str(), test_result) == 0) {
    return ::testing::AssertionSuccess();
  } else {
    return ::testing::AssertionFailure()
        << "hash of \"" << test_data << "\" incorrect:\n"
        << "\t" << output << " returned\n"
        << "\t" << test_result << " is correct\n";
  }
}

} // empty namespace

TEST(HmacSha1Hash, TestVectors) {
  struct {
    const char *test_data;
    const char *key;
    size_t key_len;
    const char *data;
    size_t data_len;
    const char *digest;
  } test[] = {
    { "Hi There",
      "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 16,
      "Hi There", 8,
      "675B0B3A 1B4DDF4E 124872DA 6C2F632B FED957E9" },
    { "what do ya want for nothing?",
      "Jefe", 4,
      "what do ya want for nothing?", 28,
      "EFFCDF6A E5EB2FA2 D27416D5 F184DF9C 259A7C79" },
    { "Fifty repetitions of \\xDD",
      "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA", 16,
      "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
      "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
      "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD", 50,
      "D730594D 167E35D5 956FD800 3D0DB3D3 F46DC7BB" },
  };

  uint8_t digest[20];
  for (int k = 0; k < sizeof(test)/sizeof(test[0]); k++){
    hmac_sha1((uint8_t*)test[k].data, test[k].data_len,
        (uint8_t*)test[k].key, test[k].key_len, digest);
    EXPECT_TRUE(IsEqual(test[k].test_data, digest, test[k].digest));
  }
}
