#include "dns-types.hh"

std::unique_ptr<RRGenerator> AGenerator::make(const ComboAddress& ca)
{
  return std::move(std::make_unique<AGenerator>(ca.sin4.sin_addr.s_addr));
}

void AGenerator::toMessage(DNSMessageWriter& dmw)
{
  dmw.payload.putUInt32(d_ip);
}


std::unique_ptr<RRGenerator> AAAAGenerator::make(const ComboAddress& ca)
{
  if(ca.sin4.sin_family != AF_INET6)
    throw std::runtime_error("This was not an IPv6 address in AAAA generator");
  auto p = (const unsigned char*)ca.sin6.sin6_addr.s6_addr;
  unsigned char ip[16];
  memcpy(&ip, p, 16);

  return std::move(std::make_unique<AAAAGenerator>(ip));
}

void AAAAGenerator::toMessage(DNSMessageWriter& dmw)
{
  dmw.payload.putBlob(d_ip, 16);
}

void SOAGenerator::toMessage(DNSMessageWriter& dmw)
{
  putName(dmw.payload, d_mname);    putName(dmw.payload, d_rname);
  dmw.payload.putUInt32(d_serial);  dmw.payload.putUInt32(d_refresh);
  dmw.payload.putUInt32(d_retry);   dmw.payload.putUInt32(d_expire);
  dmw.payload.putUInt32(d_minimum);
}

#if 0
std::string serializeMXRecord(uint16_t prio, const dnsname& mname)
{
  SafeArray<256> sa;
  sa.putUInt16(prio);
  putName(sa, mname);
  return sa.serialize();
}
#endif


