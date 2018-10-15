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


/** This function guarantees that you will get an answer from this server. It will drop EDNS for you
    and eventually it will even fall back to TCP for you. If nothing works, an exception is thrown.
    Note that this function does not think about actual DNS errors, you get those back verbatim.
    Only the TC bit is checked.

    This function does check if the ID field of the response matches the query, but the caller should
    check qname and qtype.
*/
DNSMessageReader getResponse(const ComboAddress& server, const DNSName& dn, const DNSType& dt, int depth=0)
{
  std::string prefix(depth, ' ');
  prefix += dn.toString() + "|"+toString(dt)+" ";

  bool doEDNS=true, doTCP=false;

  for(int tries = 0; tries < 4 ; ++ tries) {
    DNSMessageWriter dmw(dn, dt);
    dmw.dh.rd = false;
    dmw.randomizeID();
    if(doEDNS)
      dmw.setEDNS(700, true);
    string resp;
    if(doTCP) {
      Socket sock(server.sin4.sin_family, SOCK_STREAM);
      SConnect(sock, server);
      string ser = dmw.serialize();
      uint16_t len = htons(ser.length());
      string tmp((char*)&len, 2);
      SWrite(sock, tmp);
      SWrite(sock, ser);

      tmp=SRead(sock, 2);
      len = ntohs(*((uint16_t*)tmp.c_str()));
      resp = SRead(sock, len);
    }
    else {
      Socket sock(server.sin4.sin_family, SOCK_DGRAM);
      SConnect(sock, server);
      SWrite(sock, dmw.serialize());
      double timeout=1;
      int err = waitForData(sock, &timeout);
      if( err <= 0) {
        throw std::runtime_error("Error waiting for data from "+server.toStringWithPort()+": "+ (err ? string(strerror(errno)): string("Timeout")));
      }
      ComboAddress ign=server;
      resp =SRecvfrom(sock, 65535, ign); 
    }
    DNSMessageReader dmr(resp);
    if(dmr.dh.id != dmw.dh.id) {
      cout << prefix << "ID mismatch on answer" << endl;
      continue;
    }
    
    if((RCode)dmr.dh.rcode == RCode::Formerr) {
      cout << prefix <<"Got a Formerr, resending without EDNS"<<endl;
      doEDNS=false;
      continue;
    }
    if(dmr.dh.tc) {
      cout << prefix <<"Got a truncated answer, retrying over TCP"<<endl;
      doTCP=true;
      continue;
    }
    return dmr;
  }
  // should never get here
}

// this is a different kind of error: we KNOW your thing does not exist
struct NxdomainException{};
struct NodataException{};



vector<std::unique_ptr<RRGen>> resolveAt(const DNSName& dn, const DNSType& dt, int depth=0, const multimap<DNSName, ComboAddress>& servers=g_root)
{
  std::string prefix(depth, ' ');
  prefix += dn.toString() + "|"+toString(dt)+" ";
 
  vector<std::unique_ptr<RRGen>> ret;
  for(auto& sp : servers) {
    ret.clear();
    ComboAddress server=sp.second;
    server.sin4.sin_port = htons(53);

    try {
      cout << prefix<<"Sending to server "<<sp.first<<" on "<<server.toString()<<endl;
      DNSMessageReader dmr = getResponse(server, dn, dt, depth); // takes care of EDNS and TCP

      DNSSection rrsection;
      uint32_t ttl;
      
      DNSName rrdn;
      DNSType rrdt;
      
      dmr.getQuestion(rrdn, rrdt);
      cout << prefix<<"Received response with RCode "<<(RCode)dmr.dh.rcode<<", qname " <<dn<<", qtype "<<dt<<", aa: "<<dmr.dh.aa << endl;
      if(rrdn != dn || dt != rrdt) {
        cout << prefix << "Got a response to a different question or different type than we asked for!"<<endl;
        continue; // see if another server wants to work with us
      }

      if((RCode)dmr.dh.rcode == RCode::Nxdomain) {
        cout << prefix<<"Got an Nxdomain, it does not exist"<<endl;
        throw NxdomainException();
      }
      else if((RCode)dmr.dh.rcode != RCode::Noerror) {
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
      else if(dmr.dh.aa) {
        cout << prefix <<"No data response"<<endl;
        throw NodataException();
      }
      if(!addresses.empty()) {
        cout << prefix<<"Have "<<addresses.size()<<" IP addresses to iterate to: ";
        for(const auto& p : addresses)
          cout << p.first <<"="<<p.second.toString()<<" ";
        cout <<endl;
        auto res2=resolveAt(dn, dt, depth+1, addresses);
        if(!res2.empty())
          return res2;
        cout << prefix<<"The IP addresses we had did not provide a good answer"<<endl;
      }
      
      cout << prefix<<"Don't have a resolved nameserver to ask anymore, trying to resolve "<<nsses.size()<<" names"<<endl;

      for(const auto& name: nsses) {
        multimap<DNSName, ComboAddress> newns;
        cout << prefix<<"Attempting to resolve NS "<<name<<endl;
        for(const DNSType& qtype : {DNSType::A, DNSType::AAAA}) {
          try {
            auto result = resolveAt(name, qtype, depth+1);
            cout << prefix<<"Got "<<result.size()<<" nameserver IPv4 addresses, adding to list"<<endl;
            for(const auto& res : result)
              newns.insert({name, getIP(res)});
          }
          catch(...)
          {
            cout << prefix <<"Failed to resolve name for "<<name<<"|"<<qtype<<endl;
          }
        }
        cout << prefix<<"We now have "<<newns.size()<<" resolved addresses to try"<<endl;
        if(newns.empty())
          continue;
        auto res2 = resolveAt(dn, dt, depth+1, newns);
        if(!res2.empty())
          return res2;
      }
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
catch(NxdomainException& e)
{
  cout<<"Name does not exist"<<endl;
  return EXIT_FAILURE;
}
catch(NodataException& e)
{
  cout<<"Name does not have datatype requested"<<endl;
  return EXIT_FAILURE;
}
