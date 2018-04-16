/* Goal: a fully standards compliant basic authoritative server. In <1000 lines.
   Non-goals: notifications, slaving zones, name compression, edns,
              performance
*/
#include <cstdint>
#include <vector>
#include <map>
#include <stdexcept>
#include "sclasses.hh"
#include "dns.hh"
#include <thread>
#include <signal.h>
#include "record-types.hh"
#include "dns-storage.hh"

using namespace std;

void addAdditional(const DNSNode* bestzone, const DNSName& zone, const vector<DNSName>& toresolve, DNSMessageWriter& response)
{
  for(auto addname : toresolve ) {
    cout<<"Doing additional or glue lookup for "<<addname<<" in "<<zone<<endl;
    if(!addname.makeRelative(zone)) {
      cout<<addname<<" is not within our zone, not doing glue"<<endl;
      continue;
    }
    DNSName wuh;
    auto addnode = bestzone->find(addname, wuh);
    if(!addnode || !addname.empty())  {
      cout<<"  Found nothing, continuing"<<endl;
      continue;
    }
    for(auto& type : {DNSType::A, DNSType::AAAA}) {
      auto iter2 = addnode->rrsets.find(type);
      if(iter2 != addnode->rrsets.end()) {
        const auto& rrset = iter2->second;
        for(const auto& rr : rrset.contents) {
          response.putRR(DNSSection::Additional, wuh+zone, type, rrset.ttl, rr);
        }
      }
    }
  }  
}

bool processQuestion(const DNSNode& zones, DNSMessageReader& dm, const ComboAddress& local, const ComboAddress& remote, DNSMessageWriter& response)
{
  if(dm.dh.qr) {
    cerr<<"Dropping non-query from "<<remote.toStringWithPort()<<endl;
    return false; // should not send ANY kind of response, loop potential
  }

  DNSName qname;
  DNSType qtype;
  dm.getQuestion(qname, qtype);

  DNSName origname=qname; // we need this for error reporting, we munch the original name
  cout<<"Received a query from "<<remote.toStringWithPort()<<" for "<<qname<<" and type "<<qtype<<endl;

  try {
    response.dh.id = dm.dh.id; response.dh.rd = dm.dh.rd;
    response.dh.ad = response.dh.ra = response.dh.aa = 0;
    response.dh.qr = 1; response.dh.opcode = dm.dh.opcode;

    uint16_t newsize; bool doBit;

    if(dm.getEDNS(&newsize, &doBit)) {
      if(dm.d_ednsVersion != 0) {
        cout<<"Bad EDNS version: "<<(int)dm.d_ednsVersion<<endl;
        response.setEDNS(newsize, doBit, RCode::Badvers);
        return true;
      }
      response.setEDNS(newsize, doBit);
    }
    
    if(qtype == DNSType::AXFR || qtype == DNSType::IXFR)  {
      cout<<"Query was for AXFR or IXFR over UDP, can't do that"<<endl;
      response.dh.rcode = (int)RCode::Servfail;
      return true;
    }

    if(dm.dh.opcode != 0) {
      cout<<"Query had non-zero opcode "<<dm.dh.opcode<<", sending NOTIMP"<<endl;
      response.dh.rcode = (int)RCode::Notimp;
      return true;
    }
    
    DNSName zonename;
    auto fnd = zones.find(qname, zonename); 
    if(!fnd || !fnd->zone) {
      cout<<"No zone matched"<<endl;
      response.dh.rcode = (uint8_t)RCode::Refused;
      return true;
    }
    
    cout<<"---\nFound best zone: "<<zonename<<", qname now "<<qname<<endl;
    response.dh.aa = 1; 
    
    auto bestzone = fnd->zone.get();
    DNSName searchname(qname), lastnode, zonecutname;
    const DNSNode* passedZonecut=0;
    int CNAMELoopCount = 0;
    
  loopCNAME:;
    auto node = bestzone->find(searchname, lastnode, true, &passedZonecut, &zonecutname);
    if(passedZonecut) {
      response.dh.aa = false;
      cout<<"This is a delegation, zonecutname: '"<<zonecutname<<"'"<<endl;
      
      for(const auto& rr: passedZonecut->rrsets) {
        cout<<"  Have type "<<rr.first<<endl;
      }
      auto iter = passedZonecut->rrsets.find(DNSType::NS);
      if(iter != passedZonecut->rrsets.end()) {
        const auto& rrset = iter->second;
        vector<DNSName> toresolve;
        for(const auto& rr : rrset.contents) {
          response.putRR(DNSSection::Authority, zonecutname+zonename, DNSType::NS, rrset.ttl, rr);
          toresolve.push_back(dynamic_cast<NSGen*>(rr.get())->d_name);
        }
        addAdditional(bestzone, zonename, toresolve, response);
      }
    }
    else if(!searchname.empty()) {
      cout<<"This is an NXDOMAIN situation"<<endl;
      if(!CNAMELoopCount) // RFC 1034, 4.3.2, step 3.c
        response.dh.rcode = (int)RCode::Nxdomain;
      const auto& rrset = bestzone->rrsets[DNSType::SOA];
      
      response.putRR(DNSSection::Authority, zonename, DNSType::SOA, rrset.ttl, rrset.contents[0]);
    }
    else {
      cout<<"Found something in zone '"<<zonename<<"' for lhs '"<<qname<<"', searchname now '"<<searchname<<"', lastnode '"<<lastnode<<"', passedZonecut="<<passedZonecut<<endl;
      
      decltype(node->rrsets)::const_iterator iter;
      vector<DNSName> additional;
      if(iter = node->rrsets.find(DNSType::CNAME), iter != node->rrsets.end()) {
        cout<<"We have a CNAME!"<<endl;
        const auto& rrset = iter->second;
        response.putRR(DNSSection::Answer, lastnode+zonename, DNSType::CNAME, rrset.ttl, rrset.contents[0]);
        DNSName target=dynamic_cast<CNAMEGen*>(rrset.contents[0].get())->d_name;

        if(target.makeRelative(zonename)) {
          cout<<"  Should follow CNAME to "<<target<<" within our zone"<<endl;
          searchname = target; 
          if(qtype != DNSType::CNAME && CNAMELoopCount++ < 10) {  // do not loop if they *wanted* the CNAME
            lastnode.clear();
            zonecutname.clear();
            goto loopCNAME;
          }
        }
        else
          cout<<"  CNAME points to record "<<target<<" in other zone, good luck"<<endl;
      }
      else if(iter = node->rrsets.find(qtype), iter != node->rrsets.end() || (!node->rrsets.empty() && qtype==DNSType::ANY)) {
        auto range = make_pair(iter, iter);
        if(qtype == DNSType::ANY)
          range = make_pair(node->rrsets.begin(), node->rrsets.end());
        else
          ++range.second;
        for(auto i2 = range.first; i2 != range.second; ++i2) {
          const auto& rrset = i2->second;
          for(const auto& rr : rrset.contents) {
            response.putRR(DNSSection::Answer, lastnode+zonename, i2->first, rrset.ttl, rr);
            if(i2->first == DNSType::MX)
              additional.push_back(dynamic_cast<MXGen*>(rr.get())->d_name);
          }
        }
      }
      else {
        cout<<"Node exists, qtype doesn't, NOERROR situation, inserting SOA"<<endl;
        const auto& rrset = bestzone->rrsets[DNSType::SOA];
        response.putRR(DNSSection::Answer, zonename, DNSType::SOA, rrset.ttl, rrset.contents[0]);
      }
      addAdditional(bestzone, zonename, additional, response);      
    }
    return true;
  }
  catch(std::out_of_range& e) { // exceeded packet size
    cout<<"Query for '"<<origname<<"'|"<<qtype<<" got truncated"<<endl;
    response.clearRRs(); 
    response.dh.aa = 0;   response.dh.tc = 1; 
    return true;
  }
  catch(std::exception& e) {
    cout<<"Error processing query: "<<e.what()<<endl;
    return false;
  }
}

void udpThread(ComboAddress local, Socket* sock, const DNSNode* zones)
{
  for(;;) {
    ComboAddress remote(local);

    string message = SRecvfrom(*sock, 512, remote);
    DNSMessageReader dm(message);

    DNSName qname;
    DNSType qtype;
    dm.getQuestion(qname, qtype);
    DNSMessageWriter response(qname, qtype);

    if(processQuestion(*zones, dm, local, remote, response)) {
      cout<<"Sending response with rcode "<<(RCode)response.dh.rcode <<endl;
      string ret = response.serialize();
      SSendto(*sock, ret, remote);
    }
  }
}

static void writeTCPMessage(int sock, DNSMessageWriter& response)
{
  string ser="00"+response.serialize();
  //  cout<<"Sending a message of "<<ser.size()<<" bytes in response"<<endl;
  uint16_t len = htons(ser.length()-2);
  ser[0] = *((char*)&len);
  ser[1] = *(((char*)&len) + 1);
  SWriten(sock, ser);
}

uint16_t tcpGetLen(int sock)
{
  string message = SRead(sock, 2);
  if(message.empty())
    return 0;
  if(message.size() != 2) {
    throw std::runtime_error("Incomplete TCP/IP message");
  }
  uint16_t len;
  memcpy(&len, &message.at(1)-1, 2);
  return htons(len);
}

void tcpClientThread(ComboAddress local, ComboAddress remote, int s, const DNSNode* zones)
{
  Socket sock(s);
  cout<<"TCP Connection from "<<remote.toStringWithPort()<<endl;
  for(;;) {
    uint16_t len=tcpGetLen(sock);
    if(!len)
      return;
    if(len > 512) {
      cerr<<"Remote "<<remote.toStringWithPort()<<" sent question that was too big"<<endl;
      return;
    }
    
    if(len < sizeof(dnsheader)) {
      cerr<<"Dropping query from "<<remote.toStringWithPort()<<", too short"<<endl;
      return;
    }

    std::string message = SRead(sock, len);
    DNSMessageReader dm(message);

    DNSName name;
    DNSType type;
    dm.getQuestion(name, type);

    DNSMessageWriter response(name, type, 16384);
    //    response.d_nocompress = true;
    if(type == DNSType::AXFR || type == DNSType::IXFR) {
      if(dm.dh.opcode || dm.dh.qr) {
        cerr<<"Dropping non-query AXFR from "<<remote.toStringWithPort()<<endl; // too weird
        return;
      }

      cout<<"AXFR requested for "<<name<<endl;

      response.dh.id = dm.dh.id;
      response.dh.ad = response.dh.ra = response.dh.aa = 0;
      response.dh.qr = 1;
      
      DNSName zone;
      auto fnd = zones->find(name, zone);
      if(!fnd || !fnd->zone || !name.empty() || !fnd->zone->rrsets.count(DNSType::SOA)) {
        cout<<"   This was not a zone, or zone had no SOA"<<endl;
        response.dh.rcode = (int)RCode::Refused;
        writeTCPMessage(sock, response);
        continue;
      }
      cout<<"Have zone, walking it"<<endl;

      auto node = fnd->zone.get();

      // send SOA
      response.putRR(DNSSection::Answer, zone, DNSType::SOA, node->rrsets[DNSType::SOA].ttl, node->rrsets[DNSType::SOA].contents[0]);

      writeTCPMessage(sock, response);
      response.clearRRs();

      // send all other records
      node->visit([&response,&sock,&name,&type,&zone](const DNSName& nname, const DNSNode* n) {
          for(const auto& p : n->rrsets) {
            if(p.first == DNSType::SOA)
              continue;
            for(const auto& rr : p.second.contents) {
            retry:
              try {
                response.putRR(DNSSection::Answer, nname, p.first, p.second.ttl, rr);
              }
              catch(std::out_of_range& e) { // exceeded packet size 
                writeTCPMessage(sock, response);
                response.clearRRs();
                goto retry;
              }
            }
          }
        }, zone);

      writeTCPMessage(sock, response);
      response.clearRRs();

      // send SOA again
      response.putRR(DNSSection::Answer, zone, DNSType::SOA, node->rrsets[DNSType::SOA].ttl, node->rrsets[DNSType::SOA].contents[0]);

      writeTCPMessage(sock, response);
      return;
    }
    else {
      if(processQuestion(*zones, dm, local, remote, response)) {
        writeTCPMessage(sock, response);
      }
      else
        return;
    }
  }
}

std::unique_ptr<DNSNode> retrieveZone(const ComboAddress& remote, const DNSName& zone)
{
  cout<<"Attempting to retrieve zone "<<zone<<" from "<<remote.toStringWithPort()<<endl;
  Socket tcp(remote.sin4.sin_family, SOCK_STREAM);
  SConnect(tcp, remote);

  DNSMessageWriter dmw(zone, DNSType::AXFR);
  writeTCPMessage(tcp, dmw);

  auto ret = std::make_unique<DNSNode>();
  
  int soaCount=0;
  for(;;) {
    uint16_t len = tcpGetLen(tcp);
    string message = SRead(tcp, len);
    
    cout<<"Got "<<message.length()<<" bytes out of "<<len<<endl;
    DNSMessageReader dmr(message);

    if(dmr.dh.rcode != (int)RCode::Noerror) {
      cout<<"Got error "<<dmr.dh.rcode<<" from auth "<<remote.toStringWithPort()<< " when attempting to retrieve "<<zone<<endl;
      return std::unique_ptr<DNSNode>();
    }
    
    DNSName rrname;
    DNSType rrtype;
    DNSSection rrsection;
    uint32_t ttl;
    std::unique_ptr<RRGen> rr;
    while(dmr.getRR(rrsection, rrname, rrtype, ttl, rr)) {
      if(!rrname.makeRelative(zone))
        continue;
      if(rrtype == DNSType::SOA && ++soaCount==2)
        goto done;
      cout << rrname<< " IN " << rrtype << " " << ttl << " " <<rr->toString()<<endl;
      ret->add(rrname)->addRRs(std::move(rr));
      ret->add(rrname)->rrsets[rrtype].ttl = ttl;
    }
  }
 done:
  cout<<"Done"<<endl;
  return ret;
}

int main(int argc, char** argv)
try
{
  if(argc != 2) {
    cerr<<"Syntax: tdns ipaddress:port"<<endl;
    return(EXIT_FAILURE);
  }
  signal(SIGPIPE, SIG_IGN);

  ComboAddress local(argv[1], 53);

  Socket udplistener(local.sin4.sin_family, SOCK_DGRAM);
  SBind(udplistener, local);

  Socket tcplistener(local.sin4.sin_family, SOCK_STREAM);
  SSetsockopt(tcplistener, SOL_SOCKET, SO_REUSEPORT, 1);
  SBind(tcplistener, local);
  SListen(tcplistener, 10);
  
  DNSNode zones;
  loadZones(zones);

  /*
  zones.add({})->zone=retrieveZone(ComboAddress("2001:500:2f::f", 53), {});
  zones.add({"hubertnet", "nl"})->zone=retrieveZone(ComboAddress("52.48.64.3", 53), {"hubertnet", "nl"});
  zones.add({"ds9a", "nl"})->zone=retrieveZone(ComboAddress("52.48.64.3", 53), {"ds9a", "nl"});
  */
  thread udpServer(udpThread, local, &udplistener, &zones);

  for(;;) {
    ComboAddress remote(local); // so it has room for IPv6
    int client = SAccept(tcplistener, remote);
    thread t(tcpClientThread, local, remote, client, &zones);
    t.detach();
  }
}
catch(std::exception& e)
{
  cerr<<"Fatal error: "<<e.what()<<endl;
  return EXIT_FAILURE;
}
