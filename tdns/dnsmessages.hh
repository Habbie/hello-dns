#pragma once
#include "dns.hh"
#include "safearray.hh"
#include "dns-storage.hh"
#include "record-types.hh"
#include <vector>

class DNSMessageReader
{
public:
  DNSMessageReader(const char* input, uint16_t length);
  DNSMessageReader(const std::string& str) : DNSMessageReader(str.c_str(), str.size()) {}
  struct dnsheader dh=dnsheader{};
  SafeArray<500> payload;

  void getQuestion(DNSName& name, DNSType& type) const;
  bool getEDNS(uint16_t* newsize, bool* doBit) const;
  uint8_t d_ednsVersion{0};
private:
  DNSName getName();
  DNSName d_qname;
  DNSType d_qtype;
  DNSClass d_qclass;
  uint16_t d_bufsize;
  bool d_doBit{false};
  
  bool d_haveEDNS{false};
}; 

class DNSMessageWriter
{
public:
  struct dnsheader dh=dnsheader{};
  std::vector<uint8_t> payload;
  uint16_t payloadpos=0;
  DNSName d_qname;
  DNSType d_qtype;
  DNSClass d_qclass;
  bool haveEDNS{false};
  bool d_doBit;
  RCode d_ercode{(RCode)0};

  DNSMessageWriter(const DNSName& name, DNSType type, int maxsize=500);
  ~DNSMessageWriter() { delete d_comptree;}
  DNSMessageWriter(const DNSMessageWriter&) = delete;
  DNSMessageWriter& operator=(const DNSMessageWriter&) = delete;
  void clearRRs();
  void putRR(DNSSection section, const DNSName& name, DNSType type, uint32_t ttl, const std::unique_ptr<RRGen>& rr);
  void setEDNS(uint16_t bufsize, bool doBit, RCode ercode = (RCode)0);
  std::string serialize();

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
  void putName(const DNSName& name, bool compress=true);
private:
  DNSNode* d_comptree{0};
  void putEDNS(uint16_t bufsize, RCode ercode, bool doBit);
};

