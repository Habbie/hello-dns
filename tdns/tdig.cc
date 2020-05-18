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

int main(int argc, char** argv)
try
{
  if(argc != 4) {
    cerr<<"Syntax: tdig name type ip[:port]"<<endl;
    return(EXIT_FAILURE);
  }
  signal(SIGPIPE, SIG_IGN);
  
  DNSName dn = makeDNSName(argv[1]);
  DNSType dt = makeDNSType(argv[2]);
  ComboAddress server(argv[3], 53);

  DNSMessageWriter dmw(dn, dt);
          
  dmw.dh.rd = true;
  dmw.randomizeID();
  dmw.setEDNS(4000, false);
  
  Socket sock(server.sin4.sin_family, SOCK_DGRAM);
  SConnect(sock, server);

  SWrite(sock, dmw.serialize());
  
  string resp = SRecvfrom(sock, 65535, server);
  
  DNSMessageReader dmr(resp);
  
  DNSSection rrsection;
  uint32_t ttl;
  
  dmr.getQuestion(dn, dt);
  
  cout<<"Received "<<resp.size()<<" byte response with RCode "<<(RCode)dmr.dh.rcode<<", qname " <<dn<<", qtype "<<dt<<endl;
  
  std::unique_ptr<RRGen> rr;
  while(dmr.getRR(rrsection, dn, dt, ttl, rr)) {
    cout << rrsection<<" "<<dn<< " IN " << dt << " " << ttl << " " <<rr->toString()<<endl;
  }
}
catch(std::exception& e)
{
  cerr<<"Fatal error: "<<e.what()<<endl;
  return EXIT_FAILURE;
}
