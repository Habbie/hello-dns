#pragma once
#include "dns-storage.hh"
#include "record-types.hh"
#include <arpa/inet.h>
#include <vector>

/*!
  @file
  @brief Defines DNSMessageReader and DNSMessageWriter
*/

//! A class that parses a DNS Message 
class DNSMessageReader
{
public:
  DNSMessageReader(const char* input, uint16_t length);
  DNSMessageReader(const std::string& str) : DNSMessageReader(str.c_str(), str.size()) {}
  struct dnsheader dh=dnsheader{}; //!< the DNS header
  std::vector<uint8_t> payload;    //!< The payload
  uint16_t payloadpos{0};          //!< Current position of processing
  uint16_t rrpos{0};               //!< Used in getRR to set section correctly
  uint16_t d_endofrecord;
  //! are we at the end of a record?
  bool eor() const { return payloadpos == d_endofrecord; } 

  //! For debugging, size of our payload
  size_t size() const { return payload.size() + sizeof(struct dnsheader); }
  
  //! Copies the qname and type to you
  void getQuestion(DNSName& name, DNSType& type) const;
  //! Returns true if there was an EDNS record, plus copies details
  bool getEDNS(uint16_t* newsize, bool* doBit) const;

  //! Puts the next RR in content, unless at 'end of message', in which case it returns false
  bool getRR(DNSSection& section, DNSName& name, DNSType& type, uint32_t& ttl, std::unique_ptr<RRGen>& content);
  void skipRRs(int n); //!< Skip over n RRs
  
  uint8_t d_ednsVersion{0};

  void xfrName(DNSName& ret, uint16_t* pos=0); //!< put the next name in ret, or copy it from pos
  //! Convenience form of xfrName that returns its result
  DNSName getName(uint16_t* pos=0) { DNSName res; xfrName(res, pos); return res;}
  //! Gets the next 8 bit unsigned integer from the message, or the one from 'pos'
  void xfrUInt8(uint8_t&res, uint16_t* pos = 0)
  {
    if(!pos) pos = &payloadpos;
    res=payload.at((*pos)++);
  }
  //! Convenience form that returns the next 8 bit integer, or from pos
  uint8_t getUInt8(uint16_t* pos=0) 
  { uint8_t ret; xfrUInt8(ret, pos); return ret; }

  //! Gets the next 16 bit unsigned integer from the message
  void xfrUInt16(uint16_t& res)
  {
    memcpy(&res, &payload.at(payloadpos+1)-1, 2);
    payloadpos+=2;
    res=htons(res);
  }

  //! For symmetry, this reads a type
  void xfrType(DNSType& type)
  {
    xfrUInt16((uint16_t&)type);
  }
  
  //! Convenience form that returns the next 16 bit integer
  uint16_t getUInt16()
  { uint16_t ret; xfrUInt16(ret); return ret; }

  //! Gets the next 32 bit unsigned integer from the message
  void xfrUInt32(uint32_t& res)
  {
    memcpy(&res, &payload.at(payloadpos+3)-3, 4);
    payloadpos+=4;
    res=ntohl(res);
  }

  void xfrTxt(std::string& blob)
  {
    auto len = getUInt8();
    xfrBlob(blob, len);
  }
  //! Gets the next size bytes from the message, of from pos
  void xfrBlob(std::string& blob, int size, uint16_t* pos = 0)
  {
    if(!pos) pos = &payloadpos;
    if(!size) {
      blob.clear();
      return;
    }
    blob.assign(&payload.at(*pos), &payload.at(*pos+size-1)+1);
    (*pos) += size;
  }

  //! Convenience function that returns next size bytes of the message, or from pos
  std::string getBlob(int size, uint16_t* pos = 0)
  {
    std::string res;
    xfrBlob(res, size, pos);
    return res;
  }
  
  DNSName d_qname;
  DNSType d_qtype{(DNSType)0};
  DNSClass d_qclass{(DNSClass)0};
  uint16_t d_bufsize;
  bool d_doBit{false};
  bool d_haveEDNS{false};
}; 

//! A DNS Message writer
class DNSMessageWriter
{
public:
  struct dnsheader dh=dnsheader{};
  std::vector<uint8_t> payload;
  uint16_t payloadpos=0;
  DNSName d_qname;
  DNSType d_qtype;
  DNSClass d_qclass{DNSClass::IN};
  bool haveEDNS{false};
  bool d_doBit;
  bool d_nocompress{false}; // if set, never compress. For AXFR/IXFR
  RCode d_ercode{(RCode)0};

  DNSMessageWriter(const DNSName& name, DNSType type, DNSClass qclass=DNSClass::IN, int maxsize=500);
  ~DNSMessageWriter();
  DNSMessageWriter(const DNSMessageWriter&) = delete;
  DNSMessageWriter& operator=(const DNSMessageWriter&) = delete;
  void randomizeID(); //!< Randomize the id field of our dnsheader
  void clearRRs();
  void putRR(DNSSection section, const DNSName& name, uint32_t ttl, const std::unique_ptr<RRGen>& rr, DNSClass dclass = DNSClass::IN);
  void setEDNS(uint16_t bufsize, bool doBit, RCode ercode = (RCode)0);
  std::string serialize();

  void xfrUInt8(uint8_t val)
  {
    payload.at(payloadpos++)=val;
  }

  void xfrType(DNSType val)
  {
    xfrUInt16((uint16_t)val);
  }
  
  uint16_t xfrUInt16(uint16_t val)
  {
    val = htons(val);
    memcpy(&payload.at(payloadpos+2)-2, &val, 2);
    payloadpos+=2;
    return payloadpos - 2;
  }

  void xfrUInt16At(uint16_t pos, uint16_t val)
  {
    val = htons(val);
    memcpy(&payload.at(pos+2)-2, &val, 2);
  }

  void xfrUInt32(uint32_t val)
  {
    val = htonl(val);
    memcpy(&payload.at(payloadpos+sizeof(val)) - sizeof(val), &val, sizeof(val));
    payloadpos += sizeof(val);
  }

  void xfrTxt(const std::string& blob)
  {
    if(blob.size() > 255)
      throw std::runtime_error("Overly large TXT segment");
    xfrUInt8(blob.size());
    xfrBlob(blob);
  }
  
  void xfrBlob(const std::string& blob)
  {
    memcpy(&payload.at(payloadpos+blob.size()) - blob.size(), blob.c_str(), blob.size());
    payloadpos += blob.size();;
  }

  void xfrBlob(const unsigned char* blob, int size)
  {
    memcpy(&payload.at(payloadpos+size) - size, blob, size);
    payloadpos += size;
  }
  
  void xfrName(const DNSName& name, bool compress=true);
private:
  std::unique_ptr<DNSNode> d_comptree;
  void putEDNS(uint16_t bufsize, RCode ercode, bool doBit);
  bool d_serialized{false};  // needed to make serialize() idempotent
};

