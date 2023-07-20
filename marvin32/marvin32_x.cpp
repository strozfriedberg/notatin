// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
//
// Based on:
//
// https://github.com/dotnet/coreclr/blob/v1.0.0/src/inc/marvin32.h
// https://github.com/dotnet/coreclr/blob/v1.0.0/src/vm/marvin32.cpp
// https://github.com/mono/corefx/blob/c4eeab9fc2faa0195a812e552cd73ee298d39386/src/Common/tests/Tests/System/MarvinTests.cs
//

// To build:
//
// $ g++ -Wall -std=c++20 -I/home/juckelman/projects/make_world/install/include -L/home/juckelman/projects/make_world/install/lib -lCatch2Main -lCatch2 -o marvin32 marvin32_x.cpp
// $ LD_LIBRARY_PATH=/home/juckelman/projects/make_world/install/lib ./marvin32
//

#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>

#include <bit>
#include <cstddef>
#include <cstdint>
#include <tuple>
#include <vector>

#define BLOCK(a, b) \
{\
    b ^= a; a = std::rotl(a, 20);\
    a += b; b = std::rotl(b,  9);\
    b ^= a; a = std::rotl(a, 27);\
    a += b; b = std::rotl(b, 19);\
}

uint64_t marvin32_0(uint64_t seed, const uint8_t* data, size_t dlen) {
  uint32_t s0 = seed & 0xFFFFFFFF;
  uint32_t s1 = seed >> 32;

  while (dlen > 7) {
    s0 += *reinterpret_cast<const uint32_t*>(data);
    BLOCK(s0, s1);
    s0 += *reinterpret_cast<const uint32_t*>(data + 4);
    BLOCK(s0, s1);
    data += 8;
    dlen -= 8;
  }

  uint32_t tmp;

  switch (dlen) {
  default:
  case 4:
    s0 += *reinterpret_cast<const uint32_t*>(data);
    BLOCK(s0, s1);
    data += 4;
  case 0:
    tmp = 0x80;
    break;
  case 5:
    s0 += *reinterpret_cast<const uint32_t*>(data);
    BLOCK(s0, s1);
    data += 4;
  case 1:
    tmp = 0x8000 | data[0];
    break;
  case 6:
    s0 += *reinterpret_cast<const uint32_t*>(data);
    BLOCK(s0, s1);
    data += 4;
  case 2:
    tmp = 0x800000 | *reinterpret_cast<const uint16_t*>(data);
    break;
  case 7:
    s0 += *reinterpret_cast<const uint32_t*>(data);
    BLOCK(s0, s1);
    data += 4;
  case 3:
    tmp = *reinterpret_cast<const uint16_t*>(data) | (data[2] << 16) | 0x80000000;
    break;
  }

  s0 += tmp;

  BLOCK(s0, s1);
  BLOCK(s0, s1);

  return s0 | (static_cast<uint64_t>(s1) << 32);
}

uint64_t marvin32_1(uint64_t seed, const uint8_t* data, size_t dlen) {
  uint32_t s0 = seed & 0xFFFFFFFF;
  uint32_t s1 = seed >> 32;

  while (dlen > 7) {
    s0 += *reinterpret_cast<const uint32_t*>(data);
    BLOCK(s0, s1);
    s0 += *reinterpret_cast<const uint32_t*>(data + 4);
    BLOCK(s0, s1);
    data += 8;
    dlen -= 8;
  }

  switch (dlen) {
  default:
  case 4:
    s0 += *reinterpret_cast<const uint32_t*>(data);
    BLOCK(s0, s1);
    data += 4;
  case 0:
    s0 += 0x80;
    break;
  case 5:
    s0 += *reinterpret_cast<const uint32_t*>(data);
    BLOCK(s0, s1);
    data += 4;
  case 1:
    s0 += 0x8000 | data[0];
    break;
  case 6:
    s0 += *reinterpret_cast<const uint32_t*>(data);
    BLOCK(s0, s1);
    data += 4;
  case 2:
    s0 += 0x800000 | *reinterpret_cast<const uint16_t*>(data);
    break;
  case 7:
    s0 += *reinterpret_cast<const uint32_t*>(data);
    BLOCK(s0, s1);
    data += 4;
  case 3:
    s0 += 0x80000000 | (data[2] << 16) | *reinterpret_cast<const uint16_t*>(data);
    break;
  }

  BLOCK(s0, s1);
  BLOCK(s0, s1);

  return s0 | (static_cast<uint64_t>(s1) << 32);
}

uint64_t marvin32_2(uint64_t seed, const uint8_t* data, size_t dlen) {
  uint32_t s0 = seed & 0xFFFFFFFF;
  uint32_t s1 = seed >> 32;

  while (dlen > 3) {
    s0 += *reinterpret_cast<const uint32_t*>(data);
    BLOCK(s0, s1);
    data += 4;
    dlen -= 4;
  }

  switch (dlen) {
  default:
  case 0:
    s0 += 0x80;
    break;
  case 1:
    s0 += 0x8000 | data[0];
    break;
  case 2:
    s0 += 0x800000 | *reinterpret_cast<const uint16_t*>(data);
    break;
  case 3:
    s0 += 0x80000000 | (data[2] << 16) | *reinterpret_cast<const uint16_t*>(data);
    break;
  }

  BLOCK(s0, s1);
  BLOCK(s0, s1);

  return s0 | (static_cast<uint64_t>(s1) << 32);
}

TEST_CASE("tests") {
  const uint64_t seed_1 = 0x4FB61A001BDBCC;
  const uint64_t seed_2 = 0x804FB61A001BDBCC;
  const uint64_t seed_3 = 0x804FB61A801BDBCC;
  const std::vector<uint8_t> data_0 = {};
  const std::vector<uint8_t> data_1 = { 0xAF };
  const std::vector<uint8_t> data_2 = { 0xE7, 0x0F };
  const std::vector<uint8_t> data_3 = { 0x37, 0xF4, 0x95 };
  const std::vector<uint8_t> data_4 = { 0x86, 0x42, 0xDC, 0x59 };
  const std::vector<uint8_t> data_5 = { 0x15, 0x3F, 0xB7, 0x98, 0x26 };
  const std::vector<uint8_t> data_6 = { 0x09, 0x32, 0xE6, 0x24, 0x6C, 0x47 };
  const std::vector<uint8_t> data_7 = { 0xAB, 0x42, 0x7E, 0xA8, 0xD1, 0x0F, 0xC7 };

  const std::vector<uint8_t> data_k(1024);

  const std::vector<std::tuple<uint64_t, std::vector<uint8_t>, uint64_t>> tests = {
    { seed_1, data_0, 0x30ED35C100CD3C7D },
    { seed_1, data_1, 0x48E73FC77D75DDC1 },
    { seed_1, data_2, 0xB5F6E1FC485DBFF8 },
    { seed_1, data_3, 0xF0B07C789B8CF7E8 },
    { seed_1, data_4, 0x7008F2E87E9CF556 },
    { seed_1, data_5, 0xE6C08C6DA2AFA997 },
    { seed_1, data_6, 0x6F04BF1A5EA24060 },
    { seed_1, data_7, 0xE11847E4F0678C41  },
    { seed_2, data_0, 0x10A9D5D3996FD65D },
    { seed_2, data_1, 0x68201F91960EBF91 },
    { seed_2, data_2, 0x64B581631F6AB378 },
    { seed_2, data_3, 0xE1F2DFA6E5131408 },
    { seed_2, data_4, 0x36289D9654FB49F6 },
    { seed_2, data_5, 0x0A06114B13464DBD },
    { seed_2, data_6, 0xD6DD5E40AD1BC2ED },
    { seed_2, data_7, 0xE203987DBA252FB3 },
    { seed_3, { 0x00 }, 0xA37FB0DA2ECAE06C },
    { seed_3, { 0xFF }, 0xFECEF370701AE054 },
    { seed_3, { 0x00, 0xFF }, 0xA638E75700048880 },
    { seed_3, { 0xFF, 0x00 }, 0xBDFB46D969730E2A },
    { seed_3, { 0xFF, 0x00, 0xFF }, 0x9D8577C0FE0D30BF },
    { seed_3, { 0x00, 0xFF, 0x00 }, 0x4F9FBDDE15099497 },
    { seed_3, { 0x00, 0xFF, 0x00, 0xFF }, 0x24EAA279D9A529CA },
    { seed_3, { 0xFF, 0x00, 0xFF, 0x00 }, 0xD3BEC7726B057943 },
    { seed_3, { 0xFF, 0x00, 0xFF, 0x00, 0xFF }, 0x920B62BBCA3E0B72 },
    { seed_3, { 0x00, 0xFF, 0x00, 0xFF, 0x00 }, 0x1D7DDF9DFDF3C1BF },
    { seed_3, { 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF }, 0xEC21276A17E821A5 },
    { seed_3, { 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00 }, 0x6911A53CA8C12254 },
    { seed_3, { 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF }, 0xFDFD187B1D3CE784 },
    { seed_3, { 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00 }, 0x71876F2EFB1B0EE8 },
    { seed_3, data_k, 0x40D0D89D379BD1EE }
  };

  const auto funcs = { marvin32_0, marvin32_1, marvin32_2 };

  for (const auto& [seed, data, exp]: tests) {
    for (const auto f: funcs) {
      CHECK(f(seed, data.data(), data.size()) == exp);
    }
  }

  int i = 0;
  for (const auto f: funcs) {
    BENCHMARK(std::to_string(i)) {
      for (const auto& [seed, data, exp]: tests) {
        CHECK(f(seed, data.data(), data.size()) == exp);
      }
    };
    ++i;
  }
}
