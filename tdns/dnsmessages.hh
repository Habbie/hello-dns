#pragma once
#include "dns.hh"
#include "safearray.hh"
#include "dns-storage.hh"

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
  struct dnsheader dh=dnsheader{};
  SafeArray<1500> payload;
  void setQuestion(const dnsname& name, DNSType type);
  void putRR(DNSSection section, const dnsname& name, DNSType type, uint32_t ttl, const std::unique_ptr<RRGenerator>& rr);
  std::string serialize() const;
};

void putName(auto& payload, const dnsname& name)
  {
  for(const auto& l : name) {
    if(l.size() > 63)
      throw std::runtime_error("Can't emit a label larger than 63 characters");
    payload.putUInt8(l.size());
    payload.putBlob(l);
  }
  payload.putUInt8(0);
}

