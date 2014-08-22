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
#include <crc32.h>
#include <gtest/gtest.h>

namespace {

std::string digest_to_hex(uint32_t digest) {
  std::ostringstream out;
  out << std::setfill('0')
      << std::setw(8)
      << std::showbase
      << std::hex
      << digest;
  return out.str();
}

::testing::AssertionResult IsEqual(const char *test_data,
                                   uint32_t digest,
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

TEST(Crc32Hash, TestVectors) {
  struct {
    const char *input;
    const char *result;
  } test[] = {
    { "123456789",
      "0xcbf43926" },
    { "1234",
      "0x9be3e0a3" },
  };
  
  uint32_t digest;
  for (int i = 0; i < sizeof(test)/sizeof(test[0]); i++) {
    digest = crc32(0, test[i].input, strlen(test[i].input));
    EXPECT_TRUE(IsEqual(test[i].input, digest, test[i].result));
  }

  // Testing partial digest
  digest = crc32(0, "1234", 4);
  digest = crc32(digest, "56789", 5);
  EXPECT_TRUE(IsEqual("'1234' + '56789'", digest, "0xcbf43926"));
}
