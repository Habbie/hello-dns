#include <cstdint>
#include <vector>
#include <map>
#include <stdexcept>
#include "sclasses.hh"
#include <thread>
#include <signal.h>
#include "record-types.hh"

/*! 
   @file
   @brief Tiny 'dig'-like utility to create DNS queries & print responses
*/


using namespace std;

DNSName fromString(const std::string& str)
{
  DNSName ret;
  string part;
  for(const auto& c: str) {
    if(c=='.') {
      ret.push_back(part);
      part.clear();
    }
    else part.append(1, c);
  }
  if(!part.empty())
    ret.push_back(part);
  return ret;
}

int main(int argc, char** argv)
try
{
  if(argc != 4) {
    cerr<<"Syntax: tdig name type ip[:port]"<<endl;
    return(EXIT_FAILURE);
  }
  signal(SIGPIPE, SIG_IGN);

  DNSName dn = fromString(argv[1]);
  DNSType dt = makeDNSType(argv[2]);
  ComboAddress server(argv[3]);

  DNSMessageWriter dmw(dn, dt);
  dmw.dh.rd = true;
  dmw.setEDNS(4000, false);
  
  Socket sock(server.sin4.sin_family, SOCK_DGRAM);
  SConnect(sock, server);
  SWrite(sock, dmw.serialize());
  string resp =SRecvfrom(sock, 65535, server);

  DNSMessageReader dmr(resp);
  DNSName rrname;
  DNSType rrtype;
  DNSSection rrsection;
  uint32_t ttl;
  std::unique_ptr<RRGen> rr;
  dmr.getQuestion(rrname, rrtype);
  cout<<"Received "<<resp.size()<<" byte response with RCode "<<(RCode)dmr.dh.rcode<<", qname " <<rrname<<", qtype "<<rrtype<<endl;
  while(dmr.getRR(rrsection, rrname, rrtype, ttl, rr)) {
    cout << rrname<< " IN " << rrtype << " " << ttl << " " <<rr->toString()<<endl;
  }

}
catch(std::exception& e)
{
  cerr<<"Fatal error: "<<e.what()<<endl;
  return EXIT_FAILURE;
}
