#pragma once
#include "dns.hh"
#include "safearray.hh"
#include "dns-storage.hh"
#include <vector>

struct DNSMessageReader
{
  struct dnsheader dh=dnsheader{};
  SafeArray<500> payload;

  dnsname getName();
  void getQuestion(dnsname& name, DNSType& type);
  
  std::string serialize() const;
}; 

struct DNSMessageWriter
{
  explicit DNSMessageWriter(int maxsize=512)
  {
    payload.resize(maxsize);
  }
  struct dnsheader dh=dnsheader{};
  std::vector<uint8_t> payload;
  void setQuestion(const dnsname& name, DNSType type);
  void putRR(DNSSection section, const dnsname& name, DNSType type, uint32_t ttl, const std::unique_ptr<RRGen>& rr);

  void putEDNS(uint16_t bufsize, bool doBit);
  std::string serialize() const;

  uint16_t payloadpos=0;
  void putUInt8(uint8_t val)
  {
    payload.at(payloadpos++)=val;
  }

  uint16_t putUInt16(uint16_t val)
  {
    val = htons(val);
    memcpy(&payload.at(payloadpos+2)-2, &val, 2);
    payloadpos+=2;
    return payloadpos - 2;
  }

  void putUInt16At(uint16_t pos, uint16_t val)
  {
    val = htons(val);
    memcpy(&payload.at(pos+2)-2, &val, 2);
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

  void putBlob(const unsigned char* blob, int size)
  {
    memcpy(&payload.at(payloadpos+size) - size, blob, size);
    payloadpos += size;
  }
  void putName(const dnsname& name)
  {
    for(const auto& l : name) {
      putUInt8(l.size());
      putBlob(l.d_s);
    }
    putUInt8(0);
  }

  
};

