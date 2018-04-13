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
      payload.getUInt8(); // extended RCODE
      d_ednsVersion = payload.getUInt8(); 
      auto flags = payload.getUInt8();
      d_doBit = flags & 0x80;
      payload.getUInt8(); payload.getUInt16(); // ignore rest
      cout<<"   There was an EDNS section, size supported: "<< d_bufsize<<endl;
      d_haveEDNS = true;
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

void DNSMessageWriter::putEDNS(uint16_t bufsize, RCode ercode, bool doBit)
{
  auto cursize = payloadpos;
  try {
    putUInt8(0); putUInt16((uint16_t)DNSType::OPT); // 'root' name, our type
    putUInt16(bufsize); putUInt8(((int)ercode)>>4); putUInt8(0); putUInt8(doBit ? 0x80 : 0); putUInt8(0);
    putUInt16(0);
  }
  catch(...) {
    payloadpos = cursize;
    throw;
  }
  dh.arcount = htons(ntohs(dh.arcount)+1);
}

DNSMessageWriter::DNSMessageWriter(const DNSName& name, DNSType type, int maxsize) : d_qname(name), d_qtype(type)
{
  memset(&dh, 0, sizeof(dh));
  payload.resize(maxsize);
  clearRRs();
}

void DNSMessageWriter::clearRRs()
{
  dh.qdcount = htons(1) ; dh.ancount = dh.arcount = dh.nscount = 0;
  payloadpos=0;
  putName(d_qname);
  putUInt16((uint16_t)d_qtype);
  putUInt16(1); // class
}

string DNSMessageWriter::serialize() const
{
  DNSMessageWriter act = *this;
  try {
    if(haveEDNS) {
      cout<<"Adding EDNS to DNS Message"<<endl;
      act.putEDNS(payload.size() + sizeof(dnsheader), d_ercode, d_doBit);
    }
  }
  catch(std::out_of_range& e) {
    cout<<"Got truncated while adding EDNS! Truncating"<<endl;
    act.clearRRs();
    act.dh.tc = 1; act.dh.aa = 0;
    act.putEDNS(payload.size() + sizeof(dnsheader), d_ercode, d_doBit);
  }
  std::string ret((const char*)&act.dh, ((const char*)&act.dh) + sizeof(dnsheader));
  ret.append((const unsigned char*)&act.payload.at(0), (const unsigned char*)&act.payload.at(act.payloadpos));
  return ret;
}

void DNSMessageWriter::setEDNS(uint16_t newsize, bool doBit, RCode ercode)
{
  cout<<"Setting new buffer size "<<newsize<<" for writer"<<endl;
  if(newsize > sizeof(dnsheader))
    payload.resize(newsize - sizeof(dnsheader));
  d_doBit = doBit;
  d_ercode = ercode;
  haveEDNS=true;
}
