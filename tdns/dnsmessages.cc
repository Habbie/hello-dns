#include "dnsmessages.hh"
#include "record-types.hh"
using namespace std;

DNSMessageReader::DNSMessageReader(const char* in, uint16_t size)
{
  if(size < sizeof(dnsheader))
    throw std::runtime_error("DNS message too small");
  memcpy(&dh, in, sizeof(dh));
  payload.reserve(size-12);
  payload.insert(payload.begin(), (const unsigned char*)in + 12, (const unsigned char*)in + size);

  if(dh.qdcount) { // AXFR can skip this
    xfrName(d_qname);
    d_qtype = (DNSType) getUInt16();
    d_qclass = (DNSClass) getUInt16();
  }

  if(dh.arcount) {
    auto nowpos=payloadpos;
    skipRRs(ntohs(dh.ancount) + ntohs(dh.nscount) + ntohs(dh.arcount) - 1);
    if(getUInt8() == 0 && getUInt16() == (uint16_t)DNSType::OPT) {
      xfrUInt16(d_bufsize);
      getUInt8(); // extended RCODE
      d_ednsVersion = getUInt8();
      auto flags=getUInt8();
      d_doBit = flags & 0x80;
      getUInt8(); getUInt16(); // ignore rest
      d_haveEDNS = true;
    }
    payloadpos=nowpos;
  }
}

void DNSMessageReader::xfrName(DNSName& res, uint16_t* pos)
{
  if(!pos) pos = &payloadpos;
  res.clear();
  for(;;) {
    uint8_t labellen= getUInt8(pos);
    if(labellen & 0xc0) {
      uint16_t labellen2 = getUInt8(pos);
      uint16_t newpos = ((labellen & ~0xc0) << 8) | labellen2;
      newpos -= sizeof(dnsheader); // includes struct dnsheader

      if(newpos < *pos) {
        res=res+getName(&newpos);
        return;
      }
      else {
        throw std::runtime_error("forward compression: " + std::to_string(newpos) + " >= " + std::to_string(*pos));
      }
    }
    if(!labellen) // end of DNSName
      break;
    DNSLabel label = getBlob(labellen, pos);
    res.push_back(label);
  }
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
  *doBit = d_doBit;
  return true;
}

void DNSMessageReader::skipRRs(int num)
{
  for(int n = 0; n < num; ++n) {
    getName();
    payloadpos += 8; // type, class, ttl
    auto len = getUInt16();
    payloadpos += len;
    if(payloadpos >= payload.size())
      throw std::out_of_range("Asked to skip beyond end of packet");
  }
}

bool DNSMessageReader::getRR(DNSSection& section, DNSName& name, DNSType& type, uint32_t& ttl, std::unique_ptr<RRGen>& content)
{
  if(payloadpos == payload.size())
    return false;
  if(rrpos < ntohs(dh.ancount))
    section = DNSSection::Answer;
  else if(rrpos < ntohs(dh.ancount) + ntohs(dh.nscount))
    section = DNSSection::Authority;
  else
    section = DNSSection::Additional;
  ++rrpos;
  name = getName();
  type=(DNSType)getUInt16();
  /* uint16_t lclass = */ getUInt16(); // class
  xfrUInt32(ttl);
  auto len = getUInt16();
  d_endofrecord = payloadpos + len;
  // this should care about RP, AFSDB too (RFC3597).. if anyone cares
#define CONVERT(x) if(type == DNSType::x) { content = std::make_unique<x##Gen>(*this);} else
  CONVERT(A) CONVERT(AAAA) CONVERT(NS) CONVERT(SOA) CONVERT(MX) CONVERT(CNAME)
  CONVERT(NAPTR) CONVERT(SRV)
  CONVERT(TXT) CONVERT(RRSIG)
  CONVERT(PTR) 
  {
    content = std::make_unique<UnknownGen>(type, getBlob(len));
  }
#undef CONVERT
  return true;
}

// this is required to make the std::unique_ptr to DNSZone work. Long story.
DNSMessageWriter::~DNSMessageWriter() = default;

void DNSMessageWriter::randomizeID()
{
  dh.id = random();
}

void DNSMessageWriter::xfrName(const DNSName& name, bool compress)
{
  DNSName oname(name);
  //  cout<<"Attempt to emit "<<oname<<" (compress = "<<compress<<", d_nocompress= "<<d_nocompress<<")"<<endl;
  DNSName fname(oname), flast;

  if(compress && !d_nocompress)  {
    auto node = d_comptree->find(fname, flast);
    
    if(node) {
      //      cout<<" Did lookup for "<<oname<<", left: "<<fname<<", node: "<<flast<<", pos: "<<node->namepos<<endl;
      if(flast.size() >= 1) {
        uint16_t pos = node->namepos;
        //        cout<<" Using the pointer we found to pos "<<pos<<", have to emit "<<fname.size()<<" labels first"<<endl;

        DNSName sname(oname);
        for(const auto& lab : fname) {
          auto anode = d_comptree->add(sname);
          if(!anode->namepos) {
            //            cout<<"Storing that "<<sname<<" can be found at " << payloadpos + 12 << endl;
            anode->namepos = payloadpos + 12;
          }
          sname.pop_front();
          xfrUInt8(lab.size());
          xfrBlob(lab.d_s);
        }
        xfrUInt8((pos>>8) | (uint8_t)0xc0 );
        xfrUInt8(pos & 0xff);
        return;
      }
    }
  }
  // if we are here, we know we need to write out the whole thing
  for(const auto& l : name) {
    if(!d_nocompress) { // even with compress=false, we want to store this name, unless this is a nocompress message (AXFR)
      auto anode = d_comptree->add(oname);
      if(!anode->namepos) {
        //        cout<<"Storing that "<<oname<<" can be found at " << payloadpos + 12 << endl;
        anode->namepos = payloadpos + 12;
      }
    }
    oname.pop_front();
    xfrUInt8(l.size());
    xfrBlob(l.d_s);
  }
  xfrUInt8(0);
}

static void nboInc(uint16_t& counter) // network byte order inc
{
  counter = htons(ntohs(counter) + 1);  
}

void DNSMessageWriter::putRR(DNSSection section, const DNSName& name, uint32_t ttl, const std::unique_ptr<RRGen>& content, DNSClass dclass)
{
  auto cursize = payloadpos;
  try {
    xfrName(name);
    xfrUInt16((int)content->getType()); xfrUInt16((int)dclass);
    xfrUInt32(ttl);
    auto pos = xfrUInt16(0); // placeholder
    content->toMessage(*this);
    xfrUInt16At(pos, payloadpos-pos-2);
  }
  catch(...) {
    payloadpos = cursize;
    throw;
  }
  switch(section) {
    case DNSSection::Question:
      throw runtime_error("Can't add questions to a DNS Message with putRR");
    case DNSSection::Answer:
      if(dh.nscount || dh.arcount) throw runtime_error("Can't add answer RRs out of order to a DNS Message");
      nboInc(dh.ancount);
      break;
    case DNSSection::Authority:
      if(dh.arcount) throw runtime_error("Can't add authority RRs out of order to a DNS Message");
      nboInc(dh.nscount);
      break;
    case DNSSection::Additional:
      nboInc(dh.arcount);
      break;
  }
}

void DNSMessageWriter::putEDNS(uint16_t bufsize, RCode ercode, bool doBit)
{
  auto cursize = payloadpos;
  try {
    xfrUInt8(0); xfrUInt16((uint16_t)DNSType::OPT); // 'root' name, our type
    xfrUInt16(bufsize); xfrUInt8(((int)ercode)>>4); xfrUInt8(0); xfrUInt8(doBit ? 0x80 : 0); xfrUInt8(0);
    xfrUInt16(0);
  }
  catch(...) {  // went beyond message size, roll it all back
    payloadpos = cursize;
    throw;
  }
  nboInc(dh.arcount);
}

DNSMessageWriter::DNSMessageWriter(const DNSName& name, DNSType type, DNSClass qclass, int maxsize) : d_qname(name), d_qtype(type), d_qclass(qclass)
{
  memset(&dh, 0, sizeof(dh));
  payload.resize(maxsize - sizeof(dh));
  clearRRs();
}

void DNSMessageWriter::clearRRs()
{
  d_comptree = std::make_unique<DNSNode>();
  dh.qdcount = htons(1) ; dh.ancount = dh.arcount = dh.nscount = 0;
  payloadpos=0;
  xfrName(d_qname, false);
  xfrUInt16((uint16_t)d_qtype);
  xfrUInt16((uint16_t)d_qclass);
}

string DNSMessageWriter::serialize() 
{
  try {
    if(haveEDNS && !d_serialized) {
      d_serialized=true;
      putEDNS(payload.size() + sizeof(dnsheader), d_ercode, d_doBit);
    }
    std::string ret((const char*)&dh, ((const char*)&dh) + sizeof(dnsheader));
    if(payloadpos)
      ret.append((const unsigned char*)&payload.at(0), (const unsigned char*)&payload.at(payloadpos-1)+1);
    return ret;
  }
  catch(std::out_of_range& e) {
    cout<<"Got truncated while adding EDNS! Truncating. haveEDNS="<<haveEDNS<<", payloadpos="<<payloadpos<<endl;
    DNSMessageWriter act(d_qname, d_qtype);
    act.dh = dh;
    act.putEDNS(payload.size() + sizeof(dnsheader), d_ercode, d_doBit);
    std::string ret((const char*)&act.dh, ((const char*)&act.dh) + sizeof(dnsheader));
    ret.append((const unsigned char*)&act.payload.at(0), (const unsigned char*)&act.payload.at(act.payloadpos));
    return ret;
  }
}

void DNSMessageWriter::setEDNS(uint16_t newsize, bool doBit, RCode ercode)
{
  if(newsize > sizeof(dnsheader))
    payload.resize(newsize - sizeof(dnsheader));
  d_doBit = doBit;
  d_ercode = ercode;
  haveEDNS=true;
}
