#pragma once
#include <memory>
#include "dns-storage.hh"
#include "dnsmessages.hh"
#include "comboaddress.hh"

struct AGen : RRGen
{
  AGen(uint32_t ip) : d_ip(ip) {}
  uint32_t d_ip;
  static std::unique_ptr<RRGen> make(const ComboAddress&);
  static std::unique_ptr<RRGen> make(const std::string& s)
  {
    return make(ComboAddress(s));
  }
  void toMessage(DNSMessageWriter& dpw) override;
  DNSType getType() const override { return DNSType::A; }
};

struct AAAAGen : RRGen
{
  AAAAGen(unsigned char ip[16])
  {
    memcpy(d_ip, ip, 16);
  }
  static std::unique_ptr<RRGen> make(const ComboAddress&);
  static std::unique_ptr<RRGen> make(const std::string& s)
  {
    return make(ComboAddress(s));
  }
  void toMessage(DNSMessageWriter& dpw) override;
  DNSType getType() const override { return DNSType::AAAA; }
  unsigned char d_ip[16];
};

struct SOAGen : RRGen
{
  SOAGen(const DNSName& mname, const DNSName& rname, uint32_t serial, uint32_t minimum=3600, uint32_t refresh=10800, uint32_t retry=3600, uint32_t expire=604800) :
    d_mname(mname), d_rname(rname), d_serial(serial), d_minimum(minimum), d_refresh(refresh), d_retry(retry), d_expire(expire)
  {}

  template<typename ... Targs>
  static std::unique_ptr<RRGen> make(const DNSName& mname, const DNSName& rname, Targs&& ... fargs)
  {
    return std::make_unique<SOAGen>(mname, rname, std::forward<Targs>(fargs)...);
  }
  void toMessage(DNSMessageWriter& dpw) override;
  DNSType getType() const override { return DNSType::SOA; }
  DNSName d_mname, d_rname;
  uint32_t d_serial, d_minimum, d_refresh, d_retry, d_expire;
};

struct CNAMEGen : RRGen
{
  CNAMEGen(const DNSName& name) : d_name(name) {}
  static std::unique_ptr<RRGen> make(const DNSName& mname)
  {
    return std::make_unique<CNAMEGen>(mname);
  }
  void toMessage(DNSMessageWriter& dpw) override;
  DNSType getType() const override { return DNSType::CNAME; }
  DNSName d_name;
};

struct NSGen : RRGen
{
  NSGen(const DNSName& name) : d_name(name) {}
  static std::unique_ptr<RRGen> make(const DNSName& mname)
  {
    return std::make_unique<NSGen>(mname);
  }
  void toMessage(DNSMessageWriter& dpw) override;
  DNSType getType() const override { return DNSType::NS; }
  DNSName d_name;
};


struct MXGen : RRGen
{
  MXGen(uint16_t prio, const DNSName& name) : d_prio(prio), d_name(name) {}
  static std::unique_ptr<RRGen> make(uint16_t prio, const DNSName& name)
  {
    return std::make_unique<MXGen>(prio, name);
  }
  void toMessage(DNSMessageWriter& dpw) override;
  DNSType getType() const override { return DNSType::MX; }
  uint16_t d_prio;
  DNSName d_name;
};

struct TXTGen : RRGen
{
  TXTGen(const std::vector<std::string>& txts) : d_txts(txts) {}
  TXTGen(const std::string& txt) : d_txts({txt}) {}

  static std::unique_ptr<RRGen> make(const std::vector<std::string>& txts)
  {
    return std::make_unique<TXTGen>(txts);
  }

  static std::unique_ptr<RRGen> make(const std::string& txt)
  {
    return std::make_unique<TXTGen>(txt);
  }

  void toMessage(DNSMessageWriter& dpw) override;
  DNSType getType() const override { return DNSType::TXT; }
  std::vector<std::string> d_txts;
};

struct ClockTXTGen : RRGen
{
  ClockTXTGen(const std::string& format) : d_format(format) {}
  static std::unique_ptr<RRGen> make(const std::string& format)
  {
    return std::make_unique<ClockTXTGen>(format);
  }
  void toMessage(DNSMessageWriter& dpw) override;
  DNSType getType() const override { return DNSType::TXT; }
  std::string d_format;
};
