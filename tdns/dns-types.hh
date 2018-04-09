#pragma once
#include "dns-storage.hh"

struct DNSPacketWriter;

struct RRGenerator
{
  virtual void toPacket(DNSPacketWriter& dpw) = 0;
};

struct AGenerator : RRGenerator
{
  std::unique_ptr<RRGenerator> make(ComboAddress);
  std::unique_ptr<RRGenerator> make(std::string);
  void toPacket(DNSPacketWriter& dpw) override;
  uint32_t d_ip;
};
