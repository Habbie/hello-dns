#pragma once
#include "dns-storage.hh"
#include "dnsmessages.hh"

struct RRGenerator
{
  virtual void toPacket(DNSMessageWriter& dpw) = 0;
};

struct AGenerator : RRGenerator
{
  std::unique_ptr<RRGenerator> make(ComboAddress);
  std::unique_ptr<RRGenerator> make(std::string);
  void toPacket(DNSMessageWriter& dpw) override;
  uint32_t d_ip;
};
