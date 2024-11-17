//
// Copyright (C) 2024 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include "CrcChecksum.h"
#include <gtest/gtest.h>
#include <fstream>
#include <iostream>
#include <string>

void writeFileWithChecksum(const std::string& filename, const std::string& data,
                           uint16_t checksum)
{
  std::ofstream file(filename, std::ios::binary);
  if (file.is_open()) {
    file.write(reinterpret_cast<const char*>(&checksum),
               sizeof(checksum));
    file.write(data.c_str(), data.size());
    file.close();
  }
}
class CrcChecksumTest : public ::testing::Test {
 protected:
  void SetUp() override {}
  void TearDown() override {}
};
TEST_F(CrcChecksumTest, EmptyBuffer) {
  unsigned char buffer[] = {};
  uint16_t result = crcChecksumCompute(buffer, sizeof(buffer));
  EXPECT_EQ(result, 0);
}

class CrcChecksumFileTest : public ::testing::Test {
 protected:
  void SetUp() override {}
  void TearDown() override {}
};
TEST_F(CrcChecksumFileTest, VerifyFileIntegrity) {
  // Define test data and compute the expected checksum
  std::string data = "Hello, CRC!";
  uint16_t expectedChecksum = crcChecksumCompute(
      reinterpret_cast<const unsigned char*>(data.c_str()), data.size());
  std::string filename = "test_file_with_crc.bin";
  writeFileWithChecksum(filename, data, expectedChecksum);
  bool result = crcChecksumVerifyIntegrity(
      filename.c_str());
  EXPECT_TRUE(result);
  remove(filename.c_str());
}


TEST_F(CrcChecksumFileTest, VerifyFileIntegrityWithCorruptedChecksum)
{
  std::string data = "Hello, CRC!";
  uint16_t expectedChecksum = crcChecksumCompute(
      reinterpret_cast<const unsigned char*>(data.c_str()), data.size());
  uint16_t corruptedChecksum = expectedChecksum + 1;
  std::string filename = "test_file_with_corrupted_crc.bin";
  writeFileWithChecksum(filename, data, corruptedChecksum);
  bool result = crcChecksumVerifyIntegrity(
      filename.c_str());
  EXPECT_FALSE(result);
  remove(filename.c_str());
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
