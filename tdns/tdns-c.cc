#include "tdns-c.h"
#include "comboaddress.hh"
#include "record-types.hh"
#include "swrappers.hh"
#include "sclasses.hh"
using namespace std;

extern "C" {
int TDNSLookupIPs(const char* name, int timeoutMsec, int lookupIPv4, int lookupIPv6,  struct TDNSIPAddresses** ret)
{
  DNSName dn = makeDNSName(name);
  DNSType dt = DNSType::A;
  ComboAddress server("198.41.0.4", 53);

  DNSMessageWriter dmw(dn, dt);
          
  dmw.dh.rd = true;
  dmw.randomizeID();

  Socket sock(server.sin4.sin_family, SOCK_DGRAM);
  SConnect(sock, server);
  SWrite(sock, dmw.serialize());
  string resp =SRecvfrom(sock, 65535, server);

  DNSMessageReader dmr(resp);

  DNSSection rrsection;
  uint32_t ttl;

  dmr.getQuestion(dn, dt);
  
  cout<<"Received "<<resp.size()<<" byte response with RCode "<<(RCode)dmr.dh.rcode<<", qname " <<dn<<", qtype "<<dt<<endl;

  std::unique_ptr<RRGen> rr;
  auto sas = new vector<struct sockaddr_storage*>();
  uint32_t resttl = std::numeric_limits<uint32_t>::max();
  while(dmr.getRR(rrsection, dn, dt, ttl, rr)) {
    
    if(ttl < resttl)
      resttl = ttl;
    cout << rrsection << " " << dn<< " IN " << dt << " " << ttl << " " <<rr->toString()<<endl;
    auto agen=dynamic_cast<AGen*>(rr.get());
    if(agen) {
      auto ca = agen->getIP();
      auto sa = new struct sockaddr_storage();
      memcpy(sa, &ca, sizeof(ca));
      sas->push_back(sa);
    }
    
  }
  sas->push_back(0);
  cout<<"vec: "<<(void*)sas<<endl;
  for(const auto& t : *sas) {
    cout << "in: "<<(void*) t <<endl;
  }
  *ret = new struct TDNSIPAddresses();
  (*ret)->addresses = (struct sockaddr_storage**)(&(*sas)[0]);
  return 0;
}
}
