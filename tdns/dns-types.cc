#include "dns-types.hh"

std::unique_ptr<RRGen> AGen::make(const ComboAddress& ca)
{
  return std::make_unique<AGen>(ca.sin4.sin_addr.s_addr);
}

void AGen::toMessage(DNSMessageWriter& dmw)
{
  dmw.payload.putUInt32(d_ip);
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
  dmw.payload.putBlob(d_ip, 16);
}

void SOAGen::toMessage(DNSMessageWriter& dmw)
{
  putName(dmw.payload, d_mname);    putName(dmw.payload, d_rname);
  dmw.payload.putUInt32(d_serial);  dmw.payload.putUInt32(d_refresh);
  dmw.payload.putUInt32(d_retry);   dmw.payload.putUInt32(d_expire);
  dmw.payload.putUInt32(d_minimum);
}

void CNAMEGen::toMessage(DNSMessageWriter& dmw)
{
  putName(dmw.payload, d_name);
}

void NSGen::toMessage(DNSMessageWriter& dmw)
{
  putName(dmw.payload, d_name);
}


void MXGen::toMessage(DNSMessageWriter& dmw) 
{
  dmw.payload.putUInt16(d_prio);
  putName(dmw.payload, d_name);
}

void TXTGen::toMessage(DNSMessageWriter& dmw) 
{
  // XXX should autosplit
  dmw.payload.putUInt8(d_txt.length());
  dmw.payload.putBlob(d_txt);
}

void ClockTXTGen::toMessage(DNSMessageWriter& dmw) 
{
  char buffer[160];
  struct tm tm;
  time_t now = time(0);
  localtime_r(&now, &tm);
  std::string txt;
  if(strftime(buffer, sizeof(buffer), d_format.c_str(), &tm))
    txt=buffer;
  else
    txt="Overflow";
  // XXX should autosplit
  dmw.payload.putUInt8(txt.length());
  dmw.payload.putBlob(txt);
}
