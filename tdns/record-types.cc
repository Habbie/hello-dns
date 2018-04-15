#include "record-types.hh"

void UnknownGen::toMessage(DNSMessageWriter& dmw)
{
  dmw.xfrBlob(d_rr);
}

std::unique_ptr<RRGen> AGen::make(const ComboAddress& ca)
{
  return std::make_unique<AGen>(ntohl(ca.sin4.sin_addr.s_addr));
}

void AGen::toMessage(DNSMessageWriter& dmw)
{
  dmw.xfrUInt32(d_ip);
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
  dmw.xfrBlob(d_ip, 16);
}

SOAGen::SOAGen(DNSMessageReader& dmr)
{
  dmr.xfrName(d_mname);    dmr.xfrName(d_rname);
  dmr.xfrUInt32(d_serial);  dmr.xfrUInt32(d_refresh);
  dmr.xfrUInt32(d_retry);   dmr.xfrUInt32(d_expire);
  dmr.xfrUInt32(d_minimum);
}

void SOAGen::toMessage(DNSMessageWriter& dmw)
{
  dmw.xfrName(d_mname);    dmw.xfrName(d_rname);
  dmw.xfrUInt32(d_serial);  dmw.xfrUInt32(d_refresh);
  dmw.xfrUInt32(d_retry);   dmw.xfrUInt32(d_expire);
  dmw.xfrUInt32(d_minimum);
}

CNAMEGen::CNAMEGen(DNSMessageReader& x)
{
  x.xfrName(d_name);
}
void CNAMEGen::toMessage(DNSMessageWriter& x)
{
  x.xfrName(d_name);
}

PTRGen::PTRGen(DNSMessageReader& x)
{
  x.xfrName(d_name);
}
void PTRGen::toMessage(DNSMessageWriter& x)
{
  x.xfrName(d_name);
}

NSGen::NSGen(DNSMessageReader& x)
{
  x.xfrName(d_name);
}

void NSGen::toMessage(DNSMessageWriter& x)
{
  x.xfrName(d_name);
}

MXGen::MXGen(DNSMessageReader& x)
{
  x.xfrUInt16(d_prio);
  x.xfrName(d_name);
}

void MXGen::toMessage(DNSMessageWriter& x) 
{
  x.xfrUInt16(d_prio);
  x.xfrName(d_name);
}

void TXTGen::toMessage(DNSMessageWriter& dmw) 
{
  // XXX should autosplit or throw
  dmw.xfrUInt8(d_txt.length());
  dmw.xfrBlob(d_txt);
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
