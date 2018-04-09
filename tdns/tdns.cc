/* Goal: a fully standards compliant basic authoritative server. In <500 lines.
   Non-goals: notifications, slaving zones, name compression, edns,
              performance
*/
#include <cstdint>
#include <string>
#include <vector>
#include <deque>
#include <map>
#include <stdexcept>
#include "sclasses.hh"
#include "dns.hh"
#include "safearray.hh"
#include <thread>
#include <signal.h>
#include "dns-types.hh"
#include "dns-storage.hh"

using namespace std;



std::string serializeDNSName(const dnsname& dn)
{
  std::string ret;
  for(const auto & l : dn) {
    ret.append(1, l.size());
    ret+=l;
  }
  ret.append(1, (char)0);
  return ret;
}

std::string serializeMXRecord(uint16_t prio, const dnsname& mname)
{
  SafeArray<256> sa;
  sa.putUInt16(prio);
  putName(sa, mname);
  return sa.serialize();
}


std::string serializeSOARecord(const dnsname& mname, const dnsname& rname, uint32_t serial, uint32_t minimum=3600, uint32_t refresh=10800, uint32_t retry=3600, uint32_t expire=604800)
{
  SafeArray<256> sa;
  putName(sa, mname);    putName(sa, rname);
  sa.putUInt32(serial);  sa.putUInt32(refresh);
  sa.putUInt32(retry);   sa.putUInt32(expire);
  sa.putUInt32(minimum);
  
  return sa.serialize();
}

std::string serializeARecord(const std::string& src)
{
  ComboAddress ca(src);
  if(ca.sin4.sin_family != AF_INET)
    throw std::runtime_error("Could not convert '"+src+"' to an IPv4 address");
  auto p = (const char*)&ca.sin4.sin_addr.s_addr;
  return std::string(p, p+4);
}

std::string serializeAAAARecord(const std::string& src)
{
  ComboAddress ca(src);
  if(ca.sin4.sin_family != AF_INET6)
    throw std::runtime_error("Could not convert '"+src+"' to an IPv6 address");
  auto p = (const char*)ca.sin6.sin6_addr.s6_addr;
  return std::string(p, p+16);
}

bool processQuestion(const DNSNode& zones, DNSMessageReader& dm, const ComboAddress& local, const ComboAddress& remote, DNSMessageWriter& response)
try
{
  dnsname name;
  DNSType type;
  dm.getQuestion(name, type);
  cout<<"Received a query from "<<remote.toStringWithPort()<<" for "<<name<<" and type "<<type<<endl;
  
  response.dh = dm.dh;
  response.dh.ad = 0;
  response.dh.ra = 0;
  response.dh.aa = 0;
  response.dh.qr = 1;
  response.dh.ancount = response.dh.arcount = response.dh.nscount = 0;
  response.setQuestion(name, type);
  
  if(type == DNSType::AXFR) {
    cout<<"Query was for AXFR or IXFR over UDP, can't do that"<<endl;
    response.dh.rcode = (int)RCode::Servfail;
    return true;
  }

  if(dm.dh.opcode != 0) {
    cout<<"Query had non-zero opcode "<<dm.dh.opcode<<", sending NOTIMP"<<endl;
    response.dh.rcode = (int)RCode::Notimp;
    return true;
  }
    
  dnsname zone;
  auto fnd = zones.find(name, zone);
  if(fnd && fnd->zone) {
    cout<<"---\nBest zone: "<<zone<<", name now "<<name<<", loaded: "<<(void*)fnd->zone<<endl;

    response.dh.aa = 1; 
    
    auto bestzone = fnd->zone;
    dnsname searchname(name), lastnode;
    bool passedZonecut=false;
    auto node = bestzone->find(searchname, lastnode, &passedZonecut);
    if(passedZonecut)
      response.dh.aa = false;
    
    if(!node) {
      cout<<"Found nothing in zone '"<<zone<<"' for lhs '"<<name<<"'"<<endl;
    }
    else if(!searchname.empty()) {
      cout<<"This was a partial match, searchname now "<<searchname<<endl;
      
      for(const auto& rr: node->rrsets) {
        cout<<"  Have type "<<rr.first<<endl;
      }
      auto iter = node->rrsets.find(DNSType::NS);
      if(iter != node->rrsets.end() && passedZonecut) {
        cout<<"Have delegation"<<endl;
        const auto& rrset = iter->second;
        for(const auto& rr : rrset.contents) {
          response.putRR(DNSSection::Authority, lastnode+zone, DNSType::NS, rrset.ttl, rr);
        }
        dnsname addname{"ns1", "fra"}, wuh;
        cout<<"Looking up glue record "<<addname<<endl;
        auto addnode = bestzone->find(addname, wuh);
        auto iter2 = addnode->rrsets.find(DNSType::A);
        if(iter2 != addnode->rrsets.end()) {
          cout<<"Lastnode for '"<<addname<<"' glue: "<<wuh<<endl;
          const auto& rrset = iter2->second;
          for(const auto& rr : rrset.contents) {
            response.putRR(DNSSection::Additional, wuh+zone, DNSType::A, rrset.ttl, rr);
          }
        }
        // should do additional processing here
      }
      else {
        cout<<"This is an NXDOMAIN situation"<<endl;
        const auto& rrset = fnd->zone->rrsets[DNSType::SOA];
        response.dh.rcode = (int)RCode::Nxdomain;
        response.putRR(DNSSection::Authority, zone, DNSType::SOA, rrset.ttl, rrset.contents[0]);
      }
    }
    else {
      cout<<"Found something in zone '"<<zone<<"' for lhs '"<<name<<"', searchname now '"<<searchname<<"', lastnode '"<<lastnode<<"', passedZonecut="<<passedZonecut<<endl;
      
      auto iter = node->rrsets.cbegin();
      if(type == DNSType::ANY) {
        for(const auto& t : node->rrsets) {
          const auto& rrset = t.second;
          for(const auto& rr : rrset.contents) {
            response.putRR(DNSSection::Answer, lastnode+zone, t.first, rrset.ttl, rr);
          }
        }
      }
      else if(iter = node->rrsets.find(type), iter != node->rrsets.end()) {
        const auto& rrset = iter->second;
        for(const auto& rr : rrset.contents) {
          response.putRR(DNSSection::Answer, lastnode+zone, type, rrset.ttl, rr);
        }
      }
      else if(iter = node->rrsets.find(DNSType::CNAME), iter != node->rrsets.end()) {
        cout<<"We do have a CNAME!"<<endl;
        const auto& rrset = iter->second;
        for(const auto& rr : rrset.contents) {
          response.putRR(DNSSection::Answer, lastnode+zone, DNSType::CNAME, rrset.ttl, rr);
        }
        cout<<" We should actually follow this, at least within our zone"<<endl;
      }
      else {
        cout<<"Node exists, qtype doesn't, NOERROR situation, inserting SOA"<<endl;
        const auto& rrset = fnd->zone->rrsets[DNSType::SOA];
        response.putRR(DNSSection::Answer, zone, DNSType::SOA, rrset.ttl, rrset.contents[0]);
      }
    }
  }
  else {
    cout<<"No zone matched"<<endl;
    response.dh.rcode = (uint8_t)RCode::Refused;
  }
  return true;
}
catch(std::exception& e) {
  cout<<"Error processing query: "<<e.what()<<endl;
  return false;
}

void udpThread(ComboAddress local, Socket* sock, const DNSNode* zones)
{
  for(;;) {
    ComboAddress remote(local);
    DNSMessageReader dm;
    string message = SRecvfrom(*sock, sizeof(dm), remote);
    if(message.size() < sizeof(dnsheader)) {
      cerr<<"Dropping query from "<<remote.toStringWithPort()<<", too short"<<endl;
      continue;
    }
    memcpy(&dm, message.c_str(), message.size());

    if(dm.dh.qr) {
      cerr<<"Dropping non-query from "<<remote.toStringWithPort()<<endl;
      continue;
    }

    DNSMessageWriter response;
    if(processQuestion(*zones, dm, local, remote, response)) {
      cout<<"Sending response with rcode "<<(RCode)response.dh.rcode <<endl;
      SSendto(*sock, response.serialize(), remote);
    }
  }
}

void writeTCPResponse(int sock, const DNSMessageWriter& response)
{
  string ser="00"+response.serialize();
  cout<<"Should send a message of "<<ser.size()<<" bytes in response"<<endl;
  uint16_t len = htons(ser.length()-2);
  ser[0] = *((char*)&len);
  ser[1] = *(((char*)&len) + 1);
  SWriten(sock, ser);
  cout<<"Sent!"<<endl;
}

void tcpClientThread(ComboAddress local, ComboAddress remote, int s, const DNSNode* zones)
{
  Socket sock(s);
  cout<<"TCP Connection from "<<remote.toStringWithPort()<<endl;
  for(;;) {
    uint16_t len;
    
    string message = SRead(sock, 2);
    if(message.size() != 2)
      break;
    memcpy(&len, &message.at(1)-1, 2);
    len=htons(len);
    
    if(len > 512) {
      cerr<<"Remote "<<remote.toStringWithPort()<<" sent question that was too big"<<endl;
      return;
    }
    
    if(len < sizeof(dnsheader)) {
      cerr<<"Dropping query from "<<remote.toStringWithPort()<<", too short"<<endl;
      return;
    }

    cout<<"Reading "<<len<<" bytes"<<endl;
    
    message = SRead(sock, len);
    DNSMessageReader dm;
    memcpy(&dm, message.c_str(), message.size());

    if(dm.dh.qr) {
      cerr<<"Dropping non-query from "<<remote.toStringWithPort()<<endl;
      return;
    }

    dnsname name;
    DNSType type;
    dm.getQuestion(name, type);
    DNSMessageWriter response;
    
    if(type == DNSType::AXFR) {
      cout<<"Should do AXFR for "<<name<<endl;

      dnsname zone;
      auto fnd = zones->find(name, zone);
      if(!fnd || !fnd->zone || !name.empty()) {
        cout<<"   This was not a zone"<<endl;
        return;
      }
      cout<<"Have zone, walking it"<<endl;
      response.dh = dm.dh;
      response.dh.ad = 0;
      response.dh.ra = 0;
      response.dh.aa = 0;
      response.dh.qr = 1;
      response.dh.ancount = response.dh.arcount = response.dh.nscount = 0;
      response.setQuestion(zone, type);

      auto node = fnd->zone;

      // send SOA
      response.putRR(DNSSection::Answer, zone, DNSType::SOA, node->rrsets[DNSType::SOA].ttl, node->rrsets[DNSType::SOA].contents[0]);

      writeTCPResponse(sock, response);
      response.dh.ancount = response.dh.arcount = response.dh.nscount = 0;
      response.payload.rewind();
      response.setQuestion(zone, type);

      // send all other records
      node->visit([&response,&sock,&name,&type,&zone](const dnsname& nname, const DNSNode* n) {
          cout<<nname<<", types: ";
          for(const auto& p : n->rrsets) {
            if(p.first == DNSType::SOA)
              continue;
            for(const auto& rr : p.second.contents) {
            retry:
              try {
                response.putRR(DNSSection::Answer, nname, p.first, p.second.ttl, rr);
              }
              catch(...) { // exceeded packet size
                writeTCPResponse(sock, response);
                response.dh.ancount = response.dh.arcount = response.dh.nscount = 0;
                response.payload.rewind();
                response.setQuestion(zone, type);
                goto retry;
              }
            }
            cout<<p.first<<" ";
          }
          cout<<endl;
        }, zone);

      writeTCPResponse(sock, response);
      response.dh.ancount = response.dh.arcount = response.dh.nscount = 0;
      response.payload.rewind();
      response.setQuestion(zone, type);

      // send SOA again
      response.putRR(DNSSection::Answer, zone, DNSType::SOA, node->rrsets[DNSType::SOA].ttl, node->rrsets[DNSType::SOA].contents[0]);

      writeTCPResponse(sock, response);
      return;
    }
    else {
      dm.payload.rewind();
      
      if(processQuestion(*zones, dm, local, remote, response)) {
        writeTCPResponse(sock, response);
      }
      else
        return;
    }
  }
}

void loadZones(DNSNode& zones)
{
  auto zone = zones.add({"powerdns", "org"});
  zone->zone = new DNSNode(); // XXX ICK
  zone->zone->rrsets[DNSType::SOA]={{serializeSOARecord({"ns1", "powerdns", "org"}, {"admin", "powerdns", "org"}, 1)}};
  zone->zone->rrsets[DNSType::MX]={{serializeMXRecord(25, {"server1", "powerdns", "org"})}};
    
  zone->zone->rrsets[DNSType::A]={{serializeARecord("1.2.3.4")}, 300};
  zone->zone->rrsets[DNSType::AAAA]={{serializeAAAARecord("::1"), serializeAAAARecord("2001::1"), serializeAAAARecord("2a02:a440:b085:1:beee:7bff:fe89:f0fb")}, 900};
  zone->zone->rrsets[DNSType::NS]={{serializeDNSName({"ns1", "powerdns", "org"})}, 300};

  zone->zone->add({"www"})->rrsets[DNSType::CNAME]={{serializeDNSName({"server1","powerdns","org"})}};

  zone->zone->add({"server1"})->rrsets[DNSType::A]={{serializeARecord("213.244.168.210")}};
  zone->zone->add({"server1"})->rrsets[DNSType::AAAA]={{serializeAAAARecord("::1")}};
  
  //  zone->zone->add({"*"})->rrsets[(dnstype)DNSType::A]={"\x05\x06\x07\x08"};

  zone->zone->add({"fra"})->rrsets[DNSType::NS]={{serializeDNSName({"ns1","fra","powerdns","org"})}};

  zone->zone->add({"ns1", "fra"})->rrsets[DNSType::A]={{serializeARecord("12.13.14.15")}, 86400};
  zone->zone->add({"NS2", "fra"})->rrsets[DNSType::A]={{serializeARecord("12.13.14.16")}, 86400};
}

int main(int argc, char** argv)
{
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
  
  thread udpServer(udpThread, local, &udplistener, &zones);

  for(;;) {
    ComboAddress remote;
    int client = SAccept(tcplistener, remote);
    thread t(tcpClientThread, local, remote, client, &zones);
    t.detach();
  }
}
