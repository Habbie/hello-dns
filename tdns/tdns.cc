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

using namespace std;

typedef std::string dnslabel;

enum class RCode 
{
  Noerror = 0, Servfail =2, Nxdomain =3, Notimp = 4, Refused = 5
};

enum class DNSType : uint16_t
{
  A = 1, NS = 2, CNAME = 5, SOA=6, AAAA = 28, IXFR = 251, AXFR = 252, ANY = 255
};

enum class DNSSection
{
  Question, Answer, Authority, Additional
};

typedef deque<dnslabel> dnsname;
// this should perform escaping rules!
static std::ostream & operator<<(std::ostream &os, const dnsname& d)
{
  for(const auto& l : d) {
    os<<l<<".";
  }
  return os;
}

struct RRSet
{
  vector<string> contents;
  uint32_t ttl{3600};
};

struct DNSNode
{
  const DNSNode* find(dnsname& name, dnsname& last, bool* passedZonecut=0) const;
  DNSNode* add(dnsname name);
  map<dnslabel, DNSNode> children;
  map<DNSType, RRSet > rrsets;
  
  DNSNode* zone{0}; // if this is set, this node is a zone
};

const DNSNode* DNSNode::find(dnsname& name, dnsname& last, bool* passedZonecut) const
{
  cout<<"find for '"<<name<<"', last is now '"<<last<<"'"<<endl;
  if(!last.empty() && passedZonecut && rrsets.count(DNSType::NS)) {
    *passedZonecut=true;
  }

  if(name.empty()) {
    cout<<"Empty lookup, returning this node or 0"<<endl;
    if(!zone && rrsets.empty()) // only root zone can have this
      return 0;
    else
      return this;
  }
  cout<<"Children at this node: ";
  for(const auto& c: children) cout <<"'"<<c.first<<"' ";
  cout<<endl;
  auto iter = children.find(name.back());
  cout<<"Looked for child called '"<<name.back()<<"'"<<endl;
  if(iter == children.end()) {
    cout<<"Found nothing, trying wildcard"<<endl;
    iter = children.find("*");
    if(iter == children.end()) {
      cout<<"Still nothing, returning leaf"<<endl;
      return this;
    }
    else {
      cout<<"Had wildcard match, following"<<endl;
    }
  }
  cout<<"Had match, continuing to child '"<<iter->first<<"'"<<endl;
  last.push_front(name.back());
  name.pop_back();
  return iter->second.find(name, last, passedZonecut);
}

DNSNode* DNSNode::add(dnsname name) 
{
  cout<<"Add for '"<<name<<"'"<<endl;
  if(name.size() == 1) {
    cout<<"Last label, adding "<<name.front()<<endl;
    return &children[name.front()];
  }

  auto back = name.back();
  name.pop_back();
  auto iter = children.find(back);

  if(iter == children.end()) {
    cout<<"Inserting new child for "<<back<<endl;
    return children[back].add(name);
  }
  return iter->second.add(name);
}

struct DNSMessage
{
  struct dnsheader dh=dnsheader{};
  SafeArray<500> payload;

  dnsname getName();
  void getQuestion(dnsname& name, DNSType& type);
  void setQuestion(const dnsname& name, DNSType type);
  void putRR(DNSSection section, const dnsname& name, DNSType type, uint32_t ttl, const std::string& rr);

  string serialize() const;
}; // __attribute__((packed));

dnsname DNSMessage::getName()
{
  dnsname name;
  for(;;) {
    uint8_t labellen=payload.getUInt8();
    if(labellen > 63)
      throw std::runtime_error("Got a compressed label");
    if(!labellen) // end of dnsname
      break;
    dnslabel label = payload.getBlob(labellen);
    name.push_back(label);
  }
  return name;
}

void DNSMessage::getQuestion(dnsname& name, DNSType& type)
{
  name=getName();
  type=(DNSType)payload.getUInt16();
}

void putName(auto& payload, const dnsname& name)
{
  for(const auto& l : name) {
    if(l.size() > 63)
      throw std::runtime_error("Can't emit a label larger than 63 characters");
    payload.putUInt8(l.size());
    payload.putBlob(l);
  }
  payload.putUInt8(0);
}

void DNSMessage::putRR(DNSSection section, const dnsname& name, DNSType type, uint32_t ttl, const std::string& content)
{
  putName(payload, name);
  payload.putUInt16((int)type); payload.putUInt16(1);
  payload.putUInt32(ttl);
  payload.putUInt16(content.size()); // check for overflow!
  payload.putBlob(content);

  switch(section) {
    case DNSSection::Question:
      throw runtime_error("Can't add questions to a DNS Message with putRR");
    case DNSSection::Answer:
      dh.ancount = htons(ntohs(dh.ancount) + 1);
      break;
    case DNSSection::Authority:
      dh.nscount = htons(ntohs(dh.nscount) + 1);
      break;
    case DNSSection::Additional:
      dh.arcount = htons(ntohs(dh.arcount) + 1);
      break;
  }
}

void DNSMessage::setQuestion(const dnsname& name, DNSType type)
{
  putName(payload, name);
  payload.putUInt16((uint16_t)type);
  payload.putUInt16(1); // class
}

string DNSMessage::serialize() const
{
  return string((const char*)this, (const char*)this + sizeof(dnsheader) + payload.payloadpos);
}


static_assert(sizeof(DNSMessage) == 516, "dnsmessage size must be 516");

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

std::string serializeSOARecord(const dnsname& mname, const dnsname& rname, uint32_t serial, uint32_t minimum=3600, uint32_t refresh=10800, uint32_t retry=3600, uint32_t expire=604800)
{
  SafeArray<256> sa;
  putName(sa, mname);
  putName(sa, rname);
  sa.putUInt32(serial);
  sa.putUInt32(refresh);
  sa.putUInt32(retry);
  sa.putUInt32(expire);
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


dnsname operator+(const dnsname& a, const dnsname& b)
{
  dnsname ret=a;
  for(const auto& l : b)
    ret.push_back(l);
  return ret;
}

void udpThread(ComboAddress local, const DNSNode* zones)
{
  Socket udplistener(local.sin4.sin_family, SOCK_DGRAM);
  SBind(udplistener, local);

  for(;;) {
    ComboAddress remote(local);
    DNSMessage dm;
    string message = SRecvfrom(udplistener, sizeof(dm), remote);
    if(message.size() < sizeof(dnsheader)) {
      cerr<<"Dropping query from "<<remote.toStringWithPort()<<", too short"<<endl;
      continue;
    }
    memcpy(&dm, message.c_str(), message.size());

    if(dm.dh.qr) {
      cerr<<"Dropping non-query from "<<remote.toStringWithPort()<<endl;
      continue;
    }

    dnsname name;
    DNSType type;
    dm.getQuestion(name, type);
    cout<<"Received a query from "<<remote.toStringWithPort()<<" for "<<name<<" and type "<<(int)type<<endl;

    
    DNSMessage response;
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
      SSendto(udplistener, response.serialize(), remote);
      continue;
    }

    if(dm.dh.opcode != 0) {
      cout<<"Query had non-zero opcode "<<dm.dh.opcode<<", sending NOTIMP"<<endl;
      response.dh.rcode = (int)RCode::Notimp;
      SSendto(udplistener, response.serialize(), remote);
      continue;
    }
    
    dnsname zone;
    auto fnd = zones->find(name, zone);
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
          cout<<"  Have type "<<(int)rr.first<<endl;
        }
        auto iter = node->rrsets.find(DNSType::NS);
        if(iter != node->rrsets.end() && passedZonecut) {
          cout<<"Have delegation"<<endl;
          const auto& rrset = iter->second;
          for(const auto& rr : rrset.contents) {
            response.putRR(DNSSection::Answer, lastnode+zone, DNSType::NS, rrset.ttl, rr);
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
      response.dh.rcode = (uint8_t)RCode::Refused;
    }
    SSendto(udplistener, response.serialize(), remote);
  }

}

void loadZones(DNSNode& zones)
{
  auto zone = zones.add({"powerdns", "org"});
  zone->zone = new DNSNode(); // XXX ICK
  zone->zone->rrsets[DNSType::SOA]={{serializeSOARecord({"ns1", "powerdns", "org"}, {"admin", "powerdns", "org"}, 1)}};
  zone->zone->rrsets[DNSType::A]={{serializeARecord("1.2.3.4")}, 300};
  zone->zone->rrsets[DNSType::AAAA]={{serializeAAAARecord("::1"), serializeAAAARecord("2001::1")}, 900};
  zone->zone->rrsets[DNSType::NS]={{serializeDNSName({"ns1", "powerdns", "org"})}, 300};

  zone->zone->add({"www"})->rrsets[DNSType::CNAME]={{serializeDNSName({"server1","powerdns","org"})}};

  zone->zone->add({"server1"})->rrsets[DNSType::A]={{serializeARecord("213.244.168.210")}};
  
  //  zone->zone->add({"*"})->rrsets[(dnstype)DNSType::A]={"\x05\x06\x07\x08"};

  zone->zone->add({"fra"})->rrsets[DNSType::NS]={{serializeDNSName({"ns1","fra","powerdns","org"})}};

  zone->zone->add({"ns1", "fra"})->rrsets[DNSType::A]={{serializeARecord("12.13.14.15")}, 86400};
}

int main(int argc, char** argv)
{
  ComboAddress local(argv[1], 53);

  DNSNode zones;

  loadZones(zones);
  
  thread udpServer(udpThread, local, &zones);
  //  thread tcpServer(tcpThread, local, &zones);

  udpServer.join();
  //  tcpServer.join();
  
}
