#include "record-types.hh"
#include <iomanip>

/*! 
   @file
   @brief Defines has the actual Resource Record Generators
*/

//! Used by an RRGen to output record content to 'zone text' format
/*! this exploits the similarity in writing/reading DNS messages
   and outputting master file format text */
class DNSStringWriter
{
public:
  void xfrName(const DNSName& name)
  {
    if(!d_string.empty()) d_string.append(1, ' ');
    d_string += name.toString();
  }
  void xfrUInt8(uint8_t v)
  {
    if(!d_string.empty()) d_string.append(1, ' ');
    d_string += std::to_string((unsigned int)v);
  }

  void xfrType(DNSType type)
  {
    if(!d_string.empty()) d_string.append(1, ' ');
    d_string += toString(type);
  }
  
  void xfrUInt16(uint16_t v)
  {
    if(!d_string.empty()) d_string.append(1, ' ');
    d_string += std::to_string(v);
  }
  void xfrUInt32(uint32_t v)
  {
    if(!d_string.empty()) d_string.append(1, ' ');
    d_string += std::to_string(v);
  }
  // XXX SHOULD ESCAPE
  void xfrTxt(const std::string& txt)
  {
    if(!d_string.empty()) d_string.append(1, ' ');
    d_string += "\"" + txt + "\"";
  }
  std::string d_string;
};


/*! this exploits the similarity in writing/reading DNS messages
   and outputting master file format text */

DNSStringReader::DNSStringReader(const std::string& str) : d_string(str), d_iter(d_string.cbegin())
{}

void DNSStringReader::skipSpaces()
{
  while(d_iter != d_string.end() && isspace(*d_iter))
    d_iter++;
  if(d_iter == d_string.end())
    throw std::runtime_error("End of string while parsing RR");
}

void DNSStringReader::xfrName(DNSName& name)
{
  skipSpaces();
  
  auto begin = d_iter;
  while(d_iter != d_string.end() && !isspace(*d_iter)) {
    ++d_iter;
  }
  
  std::string tmp(begin, d_iter);
  name=makeDNSName(tmp);
}

void DNSStringReader::xfrType(DNSType& name)
{
  skipSpaces();
  
  auto begin = d_iter;
  while(d_iter != d_string.end() && !isspace(*d_iter)) {
    ++d_iter;
  }
  
  std::string tmp(begin, d_iter);
  name=makeDNSType(tmp.c_str());
}


void DNSStringReader::xfrUInt8(uint8_t& v)
{
  skipSpaces();
  auto begin = d_iter;
  while(d_iter != d_string.end() && !isspace(*d_iter))
    ++d_iter;
  v = atoi(&*begin);
}

void DNSStringReader::xfrUInt16(uint16_t& v)
{
  skipSpaces();
  auto begin = d_iter;
  while(d_iter != d_string.end() && !isspace(*d_iter))
    ++d_iter;
  v = atoi(&*begin);
}
void DNSStringReader::xfrUInt32(uint32_t& v)
{
  skipSpaces();
  auto begin = d_iter;
  while(d_iter != d_string.end() && !isspace(*d_iter))
    ++d_iter;
  v = atoi(&*begin);
}
// XXX SHOULD UNESCAPE
void DNSStringReader::xfrTxt(std::string& txt)
{
  txt.clear();
  skipSpaces();
  if(*d_iter != '"')
    throw std::runtime_error("Text segment in DNS string should start with a quote");
  auto begin = ++d_iter;
  while(d_iter != d_string.end() && *d_iter != '"')
    ++d_iter;
  if(*d_iter != '"')
    throw std::runtime_error("Text segment in DNS string should end with a quote");
  txt.assign(begin, d_iter);
}

AGen::AGen(DNSMessageReader& x)
{
  x.xfrUInt32(d_ip);
}

void AGen::toMessage(DNSMessageWriter& dmw)
{
  dmw.xfrUInt32(d_ip);
}

ComboAddress AGen::getIP() const
{
  ComboAddress ca;
  ca.sin4.sin_family = AF_INET;
  ca.sin4.sin_addr.s_addr = ntohl(d_ip);
  return ca;
}
std::string AGen::toString() const
{
  return getIP().toString();
}

std::unique_ptr<RRGen> AGen::make(const ComboAddress& ca)
{
  return std::make_unique<AGen>(ntohl(ca.sin4.sin_addr.s_addr));
}

//////////////////////////

std::unique_ptr<RRGen> AAAAGen::make(const ComboAddress& ca)
{
  if(ca.sin4.sin_family != AF_INET6)
    throw std::runtime_error("This was not an IPv6 address in AAAA generator");
  auto p = (const unsigned char*)ca.sin6.sin6_addr.s6_addr;
  unsigned char ip[16];
  memcpy(&ip, p, 16);

  return std::make_unique<AAAAGen>(ip);
}

AAAAGen::AAAAGen(DNSMessageReader& x)
{
  std::string tmp;
  x.xfrBlob(tmp, 16);
  memcpy(&d_ip, tmp.c_str(), tmp.size());
}

void AAAAGen::toMessage(DNSMessageWriter& x)
{
  x.xfrBlob(d_ip, 16);
}

ComboAddress AAAAGen::getIP() const
{
  ComboAddress ca;
  memset(&ca, 0, sizeof(ca));
  ca.sin4.sin_family = AF_INET6;
  memcpy(&ca.sin6.sin6_addr.s6_addr, d_ip, 16);
  return ca;
}
std::string AAAAGen::toString() const
{
  return getIP().toString();
}

////////////////////////////////////////


#define BOILERPLATE(x)                                  \
x##Gen::x##Gen(DNSMessageReader& dmr)                   \
{                                                       \
  doConv(dmr);                                          \
}                                                       \
x##Gen::x##Gen(DNSStringReader dmr)                   \
{                                                       \
  doConv(dmr);                                          \
}                                                       \
void x##Gen::toMessage(DNSMessageWriter& dmw)           \
{                                                       \
  doConv(dmw);                                          \
}                                                       \
std::string x##Gen::toString() const                    \
{                                                       \
  DNSStringWriter sb;                                     \
  const_cast<x##Gen*>(this)->doConv(sb);                \
  return sb.d_string;                                   \
}                                                       \
///////////////////////////////
template<typename X>
void SOAGen::doConv(X& x) 
{
  x.xfrName(d_mname);    x.xfrName(d_rname);
  x.xfrUInt32(d_serial);  x.xfrUInt32(d_refresh);
  x.xfrUInt32(d_retry);   x.xfrUInt32(d_expire);
  x.xfrUInt32(d_minimum);
}
BOILERPLATE(SOA)
////////////////

template<typename X>
void SRVGen::doConv(X& x)
{
  x.xfrUInt16(d_preference); x.xfrUInt16(d_weight); x.xfrUInt16(d_port); 
  x.xfrName(d_target);
}
BOILERPLATE(SRV)
////////////////

template<typename X>
void NAPTRGen::doConv(X& x)
{
  x.xfrUInt16(d_order); x.xfrUInt16(d_pref);
  x.xfrTxt(d_flags);   x.xfrTxt(d_services);   x.xfrTxt(d_regexp);
  x.xfrName(d_replacement);
}
BOILERPLATE(NAPTR)

////////////////////////
CNAMEGen::CNAMEGen(DNSMessageReader& x)
{
  x.xfrName(d_name);
}
void CNAMEGen::toMessage(DNSMessageWriter& x)
{
  x.xfrName(d_name);
}
std::string CNAMEGen::toString() const
{
  return d_name.toString();
}

////////////////////////////////

PTRGen::PTRGen(DNSMessageReader& x)
{
  x.xfrName(d_name);
}
void PTRGen::toMessage(DNSMessageWriter& x)
{
  x.xfrName(d_name);
}
std::string PTRGen::toString() const
{
  return d_name.toString();
}
///////////////////////////////////

NSGen::NSGen(DNSMessageReader& x)
{
  x.xfrName(d_name);
}
void NSGen::toMessage(DNSMessageWriter& x)
{
  x.xfrName(d_name);
}
std::string NSGen::toString() const
{
  return d_name.toString();
}

///////////////////

MXGen::MXGen(DNSMessageReader& x)
{
  x.xfrUInt16(d_prio);  x.xfrName(d_name);
}

void MXGen::toMessage(DNSMessageWriter& x) 
{
  x.xfrUInt16(d_prio);  x.xfrName(d_name);
}

std::string MXGen::toString() const
{
  return std::to_string(d_prio)+" "+d_name.toString();
}

/////////////////////////////

TXTGen::TXTGen(DNSMessageReader& dmr) 
{
  while(!dmr.eor()) {
    std::string txt;
    dmr.xfrTxt(txt);
    d_txts.push_back(txt);
  }
}

void TXTGen::toMessage(DNSMessageWriter& dmw) 
{
  for(const auto& txt : d_txts)
    dmw.xfrTxt(txt);
}

std::string TXTGen::toString() const
{
  DNSStringWriter dsw;
  for(const auto& txt : d_txts) 
    dsw.xfrTxt(txt);
  return dsw.d_string;
}

/////////////////////////////

void UnknownGen::toMessage(DNSMessageWriter& dmw)
{
  dmw.xfrBlob(d_rr);
}

std::string UnknownGen::toString() const
{
  std::ostringstream ret;
  ret<< "\\# " + std::to_string(d_rr.size());
  if(!d_rr.empty()) {
    ret<<" ";
    ret<< std::setw(2) << std::setbase(16) << std::setfill('0');
    
    for(const auto& c : d_rr) {
      ret<<(unsigned int)(unsigned char)c;
    }
  }
  return ret.str();
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

  TXTGen gen({txt});
  gen.toMessage(dmw);
}


///////////////////////////////
template<typename X>
void RRSIGGen::doConv(X& x) 
{
  x.xfrType(d_type);    x.xfrUInt8(d_algo);
  x.xfrUInt8(d_labels);
  x.xfrUInt32(d_origttl);  x.xfrUInt32(d_expire);
  x.xfrUInt32(d_inception);   x.xfrUInt16(d_tag);
  x.xfrName(d_signer);
  xfrSignature(x);
}

void RRSIGGen::xfrSignature(DNSMessageReader& dmr)
{
  d_signature.clear();
  while(!dmr.eor()) 
    d_signature.append(1, dmr.getUInt8());
}

void RRSIGGen::xfrSignature(DNSMessageWriter& dmw)
{
  for(uint8_t v : d_signature)
    dmw.xfrUInt8(v);
}

void RRSIGGen::xfrSignature(DNSStringWriter& dmw)
{
}

void RRSIGGen::xfrSignature(DNSStringReader& dmw)
{
}

BOILERPLATE(RRSIG)
