#include "record-types.hh"

std::unique_ptr<RRGen> AGen::make(const ComboAddress& ca)
{
  return std::make_unique<AGen>(ntohl(ca.sin4.sin_addr.s_addr));
}

void AGen::toMessage(DNSMessageWriter& dmw)
{
  dmw.putUInt32(d_ip);
}

std::unique_ptr<RRGen> AAAAGen::make(const ComboAddress& ca)
{
  if(ca.sin4.sin_family != AF_INET6)
    throw std::runtime_error("This was not an IPv6 address in AAAA generator");
  auto p = (const unsigned char*)ca.sin6.sin6_addr.s6_addr;
  unsigned char ip[16];
  memcpy(&ip, p, 16);

  return std::make_unique<AAAAGen>(ip);
}

void AAAAGen::toMessage(DNSMessageWriter& dmw)
{
  dmw.putBlob(d_ip, 16);
}

void SOAGen::toMessage(DNSMessageWriter& dmw)
{
  dmw.putName(d_mname);    dmw.putName(d_rname);
  dmw.putUInt32(d_serial);  dmw.putUInt32(d_refresh);
  dmw.putUInt32(d_retry);   dmw.putUInt32(d_expire);
  dmw.putUInt32(d_minimum);
}

void CNAMEGen::toMessage(DNSMessageWriter& dmw)
{
  dmw.putName(d_name);
}

void NSGen::toMessage(DNSMessageWriter& dmw)
{
  dmw.putName(d_name);
}


void MXGen::toMessage(DNSMessageWriter& dmw) 
{
  dmw.putUInt16(d_prio);
  dmw.putName(d_name);
}

void TXTGen::toMessage(DNSMessageWriter& dmw) 
{
  for(auto segment: d_txts) {
    while(segment.length() > 0) {
      const auto fragment = segment.substr(0, 254);
      dmw.putUInt8(fragment.length());
      dmw.putBlob(fragment);
      segment.erase(0, fragment.length());
    }
  }
}

void ClockTXTGen::toMessage(DNSMessageWriter& dmw) 
{
  struct tm tm;
  time_t now = time(0);
  localtime_r(&now, &tm);

  std::string txt("overflow");
  char buffer[160];
  if(strftime(buffer, sizeof(buffer), d_format.c_str(), &tm))
    txt=buffer;

  TXTGen gen(txt);
  gen.toMessage(dmw);
}
