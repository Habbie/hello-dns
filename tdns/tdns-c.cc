#include "tdns-c.h"
#include "comboaddress.hh"
#include "record-types.hh"
#include "swrappers.hh"
#include "sclasses.hh"
#include <memory>
using namespace std;

namespace {


template<typename T>
struct TDNSCleanUp
{
  void operator()(vector<T*>* vec)
  {
    for(auto& p : *vec) {
      delete p;
    }
    delete vec;
  }
};


DNSMessageReader getDNSResponse(Socket& sock, const DNSName& dn, const DNSType& dt)
{

  DNSMessageWriter dmw(dn, dt);
  dmw.dh.rd = true;
  dmw.randomizeID();
  
  SWrite(sock, dmw.serialize());
  ComboAddress server;
  string resp =SRecvfrom(sock, 65535, server);
  
  return DNSMessageReader(resp);

}

Socket makeResolverSocket()
{
  ComboAddress server("192.168.1.91", 53);
  Socket sock(server.sin4.sin_family, SOCK_DGRAM);
  SConnect(sock, server);
  return sock;
}
}

extern "C" {
const char* TDNSErrorMessage(int err)
{
  static const char *errors[]={"No error", "Timeout", "Server failure", "No such domain", "Unknown error"};
  static constexpr int size = sizeof(errors)/sizeof(errors[0]);

  if(err >= size)
    err = size-1; 
  return errors[err];
};


void freeTDNSIPAddresses(struct TDNSIPAddresses*vec)
{
  auto ptr = (vector<struct sockaddr_storage*>*) vec->__handle;
  TDNSCleanUp<struct sockaddr_storage>()(ptr);
  delete vec;
}

int TDNSLookupIPs(const char* name, int timeoutMsec, int lookupIPv4, int lookupIPv6,  struct TDNSIPAddresses** ret)
{
  Socket sock = makeResolverSocket();

  vector<DNSType> dtypes;
  if(lookupIPv4)
    dtypes.push_back(DNSType::A);
  if(lookupIPv6)
    dtypes.push_back(DNSType::AAAA);
  DNSName dn = makeDNSName(name);

  std::unique_ptr<vector<struct sockaddr_storage*>, TDNSCleanUp<struct sockaddr_storage>> sas(new vector<struct sockaddr_storage*>());
  uint32_t resttl = std::numeric_limits<uint32_t>::max();
  
  for(const auto& dt : dtypes) {
    DNSMessageReader dmr = getDNSResponse(sock, dn, dt);
    DNSName rrdn;
    DNSType rrdt;

    dmr.getQuestion(rrdn, rrdt);
    if(dmr.dh.rcode) {
      return 3; 
    }
    //    cout<<"Received response with RCode "<<(RCode)dmr.dh.rcode<<", qname " <<rrdn<<", qtype "<<rrdt<<endl;
      
    std::unique_ptr<RRGen> rr;


    DNSSection rrsection;
    uint32_t rrttl;
    
    while(dmr.getRR(rrsection, rrdn, rrdt, rrttl, rr)) {
      if(rrttl < resttl)
        resttl = rrttl;
      //      cout << rrsection << " " << rrdn<< " IN " << rrdt << " " << rrttl << " " <<rr->toString()<<endl;
      if(rrsection != DNSSection::Answer || rrdt != dt)
        continue;
      ComboAddress ca;
      if(dt == DNSType::A) {
        auto agen =dynamic_cast<AGen*>(rr.get());
        ca = agen->getIP();
      }
      else {
        auto agen =dynamic_cast<AAAAGen*>(rr.get());
        ca = agen->getIP();
      }
      auto sa = new struct sockaddr_storage();
      memcpy(sa, &ca, sizeof(ca));
      sas->push_back(sa);
    }
  }
  sas->push_back(0);

  *ret = new struct TDNSIPAddresses();
  (*ret)->ttl = resttl;
  (*ret)->addresses = (struct sockaddr_storage**)(&(*sas)[0]);
  (*ret)->__handle = sas.get();
  sas.release();
  return 0;
}

int TDNSLookupMXs(const char* name, int timeoutMsec, struct TDNSMXs** ret)
{
  Socket sock = makeResolverSocket();

  std::unique_ptr<vector<struct TDNSMX*>, TDNSCleanUp<struct TDNSMX>> sas(new vector<struct TDNSMX*>());
  uint32_t resttl = std::numeric_limits<uint32_t>::max();
  DNSName dn = makeDNSName(name);
  DNSMessageReader dmr = getDNSResponse(sock, dn, DNSType::MX);
  DNSName rrdn;
  DNSType rrdt;

  dmr.getQuestion(rrdn, rrdt);
      
  //  cout<<"Received response with RCode "<<(RCode)dmr.dh.rcode<<", qname " <<rrdn<<", qtype "<<rrdt<<endl;
      
  std::unique_ptr<RRGen> rr;
  DNSSection rrsection;
  uint32_t rrttl;
  
  while(dmr.getRR(rrsection, rrdn, rrdt, rrttl, rr)) {
    if(rrttl < resttl)
      resttl = rrttl;
    //    cout << rrsection << " " << rrdn<< " IN " << rrdt << " " << rrttl << " " <<rr->toString()<<endl;
    if(rrsection != DNSSection::Answer || rrdt != DNSType::MX)
        continue;
    if(rrdt == DNSType::MX) {
        auto mxgen =dynamic_cast<MXGen*>(rr.get());
        auto sa = new struct TDNSMX();
        sa->priority = mxgen->d_prio;
        sa->name = strdup(mxgen->d_name.toString().c_str());
        sas->push_back(sa);
    }
  }
  sas->push_back(0);

  *ret = new struct TDNSMXs();
  (*ret)->ttl = resttl;
  (*ret)->mxs = (struct TDNSMX**)(&(*sas)[0]);
  (*ret)->__handle = sas.get();
  sas.release();
  return 0;
}

void freeTDNSMXs(struct TDNSMXs* vec)
{
  auto ptr = (vector<struct TDNSMX*>*) vec->__handle;
  for(auto& p : *ptr) {
    if(!p) break;
    free((void*)p->name);
    delete p;
  }
  delete ptr;
  delete vec;
}

int TDNSLookupTXTs(const char* name, int timeoutMsec, struct TDNSTXTs** ret)
{
  Socket sock = makeResolverSocket();

  std::unique_ptr<vector<struct TDNSTXT*>, TDNSCleanUp<struct TDNSTXT>> sas(new vector<struct TDNSTXT*>());
  uint32_t resttl = std::numeric_limits<uint32_t>::max();
  DNSName dn = makeDNSName(name);
  DNSMessageReader dmr = getDNSResponse(sock, dn, DNSType::TXT);
  DNSName rrdn;
  DNSType rrdt;

  dmr.getQuestion(rrdn, rrdt);
      
  //  cout<<"Received response with RCode "<<(RCode)dmr.dh.rcode<<", qname " <<rrdn<<", qtype "<<rrdt<<endl;
      
  std::unique_ptr<RRGen> rr;
  DNSSection rrsection;
  uint32_t rrttl;
  
  while(dmr.getRR(rrsection, rrdn, rrdt, rrttl, rr)) {
    if(rrttl < resttl)
      resttl = rrttl;
    //    cout << rrsection << " " << rrdn<< " IN " << rrdt << " " << rrttl << " " <<rr->toString()<<endl;
    if(rrsection != DNSSection::Answer || rrdt != DNSType::TXT)
        continue;
    if(rrdt == DNSType::TXT) {
        auto txtgen =dynamic_cast<TXTGen*>(rr.get());
        auto sa = new struct TDNSTXT();
        sa->content = strdup(txtgen->toString().c_str());
        sas->push_back(sa);
    }
  }
  sas->push_back(0);

  *ret = new struct TDNSTXTs();
  (*ret)->ttl = resttl;
  (*ret)->txts = (struct TDNSTXT**)(&(*sas)[0]);
  (*ret)->__handle = sas.get();
  sas.release();
  return 0;
}

void freeTDNSTXTs(struct TDNSTXTs* vec)
{
  auto ptr = (vector<struct TDNSTXT*>*) vec->__handle;
  for(auto& p : *ptr) {
    if(!p) break;
    free((void*)p->content);
    delete p;
  }
  delete ptr;
  delete vec;
}
  
  
}
