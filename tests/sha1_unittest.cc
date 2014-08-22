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
#include <sha1.h>
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

TEST(Sha1Hash, TestVectors) {
  SHA1_CTX context;
  uint8_t digest[20];

  static const char *test_data[] = {
    "abc",
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    "A million repetitions of 'a'"};

  static const char *test_results[] = {
    "A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D",
    "84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1",
    "34AA973C D4C4DAA4 F61EEB2B DBAD2731 6534016F"};

  for (int k = 0; k < 2; k++){
    SHA1_Init(&context);
    SHA1_Update(&context, (uint8_t*)test_data[k], strlen(test_data[k]));
    SHA1_Final(digest, &context);
    EXPECT_TRUE(IsEqual(test_data[k], digest, test_results[k]));
  }

  // million 'a' vector we feed separately
  SHA1_Init(&context);
  for (int k = 0; k < 1000000; k++)
    SHA1_Update(&context, (uint8_t*)"a", 1);
  SHA1_Final(digest, &context);
  EXPECT_TRUE(IsEqual(test_data[2], digest, test_results[2]));
}
