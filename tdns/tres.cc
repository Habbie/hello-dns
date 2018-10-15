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
   @brief Tiny resolver
*/

using namespace std;

multimap<DNSName, ComboAddress> g_root;

ComboAddress getIP(const std::unique_ptr<RRGen>& rr)
{
  ComboAddress ret;
  if(auto ptr = dynamic_cast<AGen*>(rr.get()))
    ret=ptr->getIP();
  else if(auto ptr = dynamic_cast<AAAAGen*>(rr.get()))
    ret=ptr->getIP();

  ret.sin4.sin_port = htons(53);
  return ret;
}

vector<std::unique_ptr<RRGen>> resolveAt(const DNSName& dn, const DNSType& dt, int depth=0, const multimap<DNSName, ComboAddress>& servers=g_root)
{
  std::string prefix(depth, ' ');
  prefix += dn.toString() + " ";
  DNSMessageWriter dmw(dn, dt);
          
  dmw.dh.rd = false;
  dmw.randomizeID();
  dmw.setEDNS(4000, false);

  vector<std::unique_ptr<RRGen>> ret;
  for(auto& sp : servers) {
    ret.clear();
    ComboAddress server=sp.second;
    server.sin4.sin_port = htons(53);

    try {
      cout << prefix<<"Sending to server "<<server.toString()<<endl;
      Socket sock(server.sin4.sin_family, SOCK_DGRAM);
      SConnect(sock, server);
      SWrite(sock, dmw.serialize());
      double timeout=1;
      if(waitForData(sock, &timeout) <= 0) {
        throw std::runtime_error("Error waiting for data from "+server.toStringWithPort()+": "+string(strerror(errno)));
      }
      string resp =SRecvfrom(sock, 65535, server); 
      
      DNSMessageReader dmr(resp);
      
      DNSSection rrsection;
      uint32_t ttl;
      
      DNSName rrdn;
      DNSType rrdt;
      
      dmr.getQuestion(rrdn, rrdt);
      
      cout << prefix<<"Received "<<resp.size()<<" byte response with RCode "<<(RCode)dmr.dh.rcode<<", qname " <<dn<<", qtype "<<dt<<", aa: "<<dmr.dh.aa << endl;
      
      // check rrdn == dn, rrdt == dt, transaction id

      if((RCode)dmr.dh.rcode == RCode::Nxdomain) {
        cout << prefix<<"Got an Nxdomain, it does not exist"<<endl;
        return ret;
      }
      if((RCode)dmr.dh.rcode != RCode::Noerror) {
        throw std::runtime_error(string("Answer from authoritative server had an error: ") + toString((RCode)dmr.dh.rcode));
      }
      if(dmr.dh.aa) {
        cout << prefix<<"Answer says it is authoritative!"<<endl;
      }
      
      std::unique_ptr<RRGen> rr;
      set<DNSName> nsses;
      multimap<DNSName, ComboAddress> addresses;
      while(dmr.getRR(rrsection, rrdn, rrdt, ttl, rr)) {
        cout << prefix << rrsection<<" "<<rrdn<< " IN " << rrdt << " " << ttl << " " <<rr->toString()<<endl;
        if(dmr.dh.aa==1) {
          if(dn == rrdn && dt == rrdt) {
            cout << prefix<<"We got an answer to our question!"<<endl;
            ret.push_back(std::move(rr));
          }
          if(dn == rrdn && rrdt == DNSType::CNAME) {
            DNSName target = dynamic_cast<CNAMEGen*>(rr.get())->d_name;
            cout << prefix<<"We got a CNAME to " << target <<", chasing"<<endl;
            return resolveAt(target, dt, depth + 1);
          }
        }
        else {
          if(rrsection == DNSSection::Authority && rrdt == DNSType::NS)
            nsses.insert(dynamic_cast<NSGen*>(rr.get())->d_name);
          else if(rrsection == DNSSection::Additional && nsses.count(rrdn) && (rrdt == DNSType::A || rrdt == DNSType::AAAA)) {
            addresses.insert({rrdn, getIP(rr)});
          }
        }
      }
      if(!ret.empty()) {
        cout << prefix<<"Done, returning "<<ret.size()<<" results\n";
        return ret;
      }
      if(!addresses.empty()) {
        cout << prefix<<"Have "<<addresses.size()<<" IP addresses to iterate to: ";
        for(const auto& p : addresses)
          cout << p.first <<"="<<p.second.toString()<<" ";
        cout <<endl;
        return resolveAt(dn, dt, depth+1, addresses);
      }
      else {
        cout << prefix<<"Don't have a resolved nameserver to ask, trying to resolve "<<nsses.size()<<" names"<<endl;
        multimap<DNSName, ComboAddress> newns;
        for(const auto& name: nsses) {
          cout << prefix<<"Attempting to resolve NS "<<name<<endl;
          auto result = resolveAt(name, DNSType::A, depth+1);
          cout << prefix<<"Got "<<result.size()<<" nameserver IPv4 addresses, adding to list"<<endl;
          for(const auto& res : result)
            newns.insert({name, getIP(res)});
          result = resolveAt(name, DNSType::AAAA, depth+1);
          cout << prefix<<"Got "<<result.size()<<" nameserver IPv6 addresses, adding to list"<<endl;
          for(const auto& res : result)
            newns.insert({name, getIP(res)});
        }
        cout << prefix<<"We now have "<<newns.size()<<" resolved names to try"<<endl;
        auto res2 = resolveAt(dn, dt, depth+1, newns);
        if(!res2.empty())
          return res2;
      }
      break;
    }
    catch(std::exception& e) {
      cout << prefix <<"Error resolving: " << e.what() << endl;
    }
  }
  return ret;
}

int main(int argc, char** argv)
try
{
  if(argc != 3) {
    cerr<<"Syntax: tres name type\n";
    return(EXIT_FAILURE);
  }
  signal(SIGPIPE, SIG_IGN);

  DNSName dn = makeDNSName(argv[1]);
  DNSType dt = makeDNSType(argv[2]);
  g_root = {{makeDNSName("k.root-servers.net"), ComboAddress("193.0.14.129", 53)}};;

  auto res = resolveAt(dn, dt);
  cout<<"Result: "<<endl;
  for(const auto& r : res) {
    cout<<r->toString()<<endl;
  }
  
}
catch(std::exception& e)
{
  cerr<<"Fatal error: "<<e.what()<<endl;
  return EXIT_FAILURE;
}
