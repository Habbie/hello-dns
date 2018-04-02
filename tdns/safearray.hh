#pragma once
#include <string>
#include <cstdint>

template<int N>
struct SafeArray
{
  std::array<uint8_t, N> payload;
  uint16_t payloadpos{0}, payloadsize{0};

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

  void putUInt8(uint8_t val)
  {
    payload.at(payloadpos++)=val;
  }

  void putUInt16(uint16_t val)
  {
    val = htons(val);
    memcpy(&payload.at(payloadpos+2)-2, &val, 2);
    payloadpos+=2;
  }

  void putUInt32(uint32_t val)
  {
    val = htonl(val);
    memcpy(&payload.at(payloadpos+sizeof(val)) - sizeof(val), &val, sizeof(val));
    payloadpos += sizeof(val);
  }

  void putBlob(const std::string& blob)
  {
    memcpy(&payload.at(payloadpos+blob.size()) - blob.size(), blob.c_str(), blob.size());
    payloadpos += blob.size();;
  }

  std::string getBlob(int size)
  {
    std::string ret(&payload.at(payloadpos), &payload.at(payloadpos+size));
    payloadpos += size;
    return ret;
  }
  
};
