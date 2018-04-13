#pragma once
#include <string>
#include <cstdint>
#include <array>
#include <arpa/inet.h>
#include <string.h>

template<int N>
struct SafeArray
{
  std::array<uint8_t, N> payload;
  uint16_t payloadpos{0}, payloadsize{0};

  void rewind()
  {
    payloadpos = 0;
  }

  uint8_t getUInt8()
  {
    return payload.at(payloadpos++);
  }
  
  uint16_t getUInt16()
  {
    uint16_t ret;
    memcpy(&ret, &payload.at(payloadpos+2)-2, 2);
    payloadpos+=2;
    return htons(ret);
  }
  
  std::string getBlob(int size)
  {
    std::string ret(&payload.at(payloadpos), &payload.at(payloadpos+size));
    payloadpos += size;
    return ret;
  }

  std::string serialize() const
  {
    return std::string((const char*)&payload.at(0), (const char*)&payload.at(payloadpos));
  }
};
