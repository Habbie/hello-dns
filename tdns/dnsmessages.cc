#include "dnsmessages.hh"
#include "record-types.hh"

using namespace std;

DNSMessageReader::DNSMessageReader(const char* in, uint16_t size)
{
  if(size < sizeof(dnsheader))
    throw std::runtime_error("DNS message too small");
  memcpy(&dh, in, sizeof(dh));
  auto rest = size-sizeof(dh);
  memcpy(&payload.payload.at(rest)-rest, in+sizeof(dh), rest);
  d_qname = getName();
  d_qtype = (DNSType) payload.getUInt16();
  d_qclass = (DNSClass) payload.getUInt16();
  if(dh.arcount) {
    if(payload.getUInt8() == 0 && payload.getUInt16() == (uint16_t)DNSType::OPT) {
      d_bufsize=payload.getUInt16();
      payload.getUInt16(); // extended RCODE, EDNS version XXX check this is 0
      auto flags = payload.getUInt8();
      d_doBit = flags & 0x80;
      payload.getUInt8(); payload.getUInt16(); // ignore rest
      cout<<"   There was an EDNS section, size supported: "<< d_bufsize<<endl;
    }
  }
}

DNSName DNSMessageReader::getName()
{
  DNSName name;
  for(;;) {
    uint8_t labellen=payload.getUInt8();
    if(labellen > 63)
      throw std::runtime_error("Got a compressed label");
    if(!labellen) // end of DNSName
      break;
    DNSLabel label = payload.getBlob(labellen);
    name.push_back(label);
  }
  return name;
}

void DNSMessageReader::getQuestion(DNSName& name, DNSType& type) const
{
  name = d_qname; type = d_qtype;
}

bool DNSMessageReader::getEDNS(uint16_t* bufsize, bool* doBit) const
{
  if(!d_haveEDNS)
    return false;
  *bufsize = d_bufsize;
  *doBit = doBit;
  return true;
}

void DNSMessageWriter::putRR(DNSSection section, const DNSName& name, DNSType type, uint32_t ttl, const std::unique_ptr<RRGen>& content)
{
  auto cursize = payloadpos;
  try {
    putName(name);
    putUInt16((int)type); putUInt16(1);
    putUInt32(ttl);
    auto pos = putUInt16(0); // placeholder
    content->toMessage(*this);
    putUInt16At(pos, payloadpos-pos-2);
  }
  catch(...) {
    payloadpos = cursize;
    throw;
  }
  switch(section) {
    case DNSSection::Question:
      throw runtime_error("Can't add questions to a DNS Message with putRR");
    case DNSSection::Answer:
      dh.ancount = htons(ntohs(dh.ancount) + 1);
      break;
    case DNSSection::Authority:
      dh.nscount = htons(ntohs(dh.nscount) + 1);
      break;
    case DNSSection::Additional:
      dh.arcount = htons(ntohs(dh.arcount) + 1);
      break;
  }
}

void DNSMessageWriter::putEDNS(uint16_t bufsize, bool doBit)
{
  auto cursize = payloadpos;
  try {
    putUInt8(0); putUInt16((uint16_t)DNSType::OPT); // 'root' name, our type
    putUInt16(bufsize); putUInt16(0); putUInt8(doBit ? 0x80 : 0); putUInt8(0);
    putUInt16(0);
  }
  catch(...) {
    payloadpos = cursize;
    throw;
  }
  dh.nscount = htons(ntohs(dh.nscount)+1);
}

void DNSMessageWriter::setQuestion(const DNSName& name, DNSType type)
{
  dh.ancount = dh.arcount = dh.nscount = 0;
  payloadpos=0;
  putName(name);
  putUInt16((uint16_t)type);
  putUInt16(1); // class
}

string DNSMessageReader::serialize() const
{
  return string((const char*)this, (const char*)this + sizeof(dnsheader) + payload.payloadpos);
}
string DNSMessageWriter::serialize() const
{
  std::string ret((const char*)this, (const char*)this + sizeof(dnsheader));
  ret.append((const unsigned char*)&payload[0], (const unsigned char*)&payload[payloadpos]);
  return ret;
}

