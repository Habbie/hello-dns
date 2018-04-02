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

using namespace std;

typedef uint16_t dnstype;
typedef std::string dnslabel;

enum class RCode 
{
  Refused=5
};

enum class DNSType
{
  A = 1,
  NS = 2,
  CNAME = 5,
  SOA=6,
  AAAA = 28
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

struct DNSNode
{
  DNSNode* find(dnsname& name, dnsname& last, bool* passedZonecut=0);
  DNSNode* add(dnsname name);
  map<dnslabel, DNSNode> children;
  map<dnstype, vector<string> > rrsets;
  
  DNSNode* zone{0}; // if this is set, this node is a zone
};

DNSNode* DNSNode::find(dnsname& name, dnsname& last, bool* passedZonecut) 
{
  cout<<"find for '"<<name<<"', last is now '"<<last<<"'"<<endl;
  if(passedZonecut && rrsets.count((int)DNSType::NS)) {
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
  void putName(const dnsname& name);
  void getQuestion(dnsname& name, dnstype& type);
  void setQuestion(const dnsname& name, dnstype type);
  void putRR(const dnsname& name, uint16_t type, uint32_t ttl, const std::string& rr);
  std::string serialize() const;
} __attribute__((packed));

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


void DNSMessage::getQuestion(dnsname& name, dnstype& type)
{
  name=getName();
  type=payload.getUInt16();
}

void DNSMessage::putName(const dnsname& name)
{
  for(const auto& l : name) {
    payload.putUInt8(l.size());
    payload.putBlob(l);
  }
  payload.putUInt8(0);
}

void DNSMessage::putRR(const dnsname& name, uint16_t type, uint32_t ttl, const std::string& content)
{
  putName(name);
  payload.putUInt16(type); payload.putUInt16(1);
  payload.putUInt32(ttl);
  payload.putUInt16(content.size()); // check for overflow!
  payload.putBlob(content);
}

void DNSMessage::setQuestion(const dnsname& name, dnstype type)
{
  putName(name);
  payload.putUInt16(type);
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

dnsname operator+(const dnsname& a, const dnsname& b)
{
  dnsname ret=a;
  for(const auto& l : b)
    ret.push_back(l);
  return ret;
}

int main(int argc, char** argv)
{
  ComboAddress local(argv[1], 53);
  Socket udplistener(local.sin4.sin_family, SOCK_DGRAM);
  SBind(udplistener, local);

  DNSNode zones;
  auto zone = zones.add({"powerdns", "org"});
  zone->zone = new DNSNode(); // XXX ICK
  zone->zone->rrsets[(dnstype)DNSType::SOA]={"hello"};
  zone->zone->rrsets[(dnstype)DNSType::A]={"\x01\x02\x03\x04"};

  zone->zone->add({"www"})->rrsets[(dnstype)DNSType::CNAME]={serializeDNSName({"server1","powerdns","com"})};

  //  zone->zone->add({"*"})->rrsets[(dnstype)DNSType::A]={"\x05\x06\x07\x08"};

  zone->zone->add({"fra"})->rrsets[(dnstype)DNSType::NS]={serializeDNSName({"ns1","fra","powerdns","org"})};

  zone->zone->add({"ns1", "fra"})->rrsets[(dnstype)DNSType::A]={"\x05\x06\x07\x08"};
  
  
  for(;;) {
    ComboAddress remote(local);
    DNSMessage dm;
    string message = SRecvfrom(udplistener, sizeof(dm), remote);
    if(message.size() < sizeof(dnsheader)) {
      cerr<<"Dropping query from "<<remote.toStringWithPort()<<", too short"<<endl;
      continue;
    }
    memcpy(&dm, message.c_str(), message.size());

    if(dm.dh.qr || dm.dh.opcode) {
      cerr<<"Dropping non-query from "<<remote.toStringWithPort()<<endl;
    }

    dnsname name;
    dnstype type;
    dm.getQuestion(name, type);
    cout<<"Received a query from "<<remote.toStringWithPort()<<" for "<<name<<" and type "<<type<<endl;

    DNSMessage response;
    response.dh = dm.dh;
    response.dh.ad = 0;
    response.dh.ra = 0;
    response.dh.aa = 0;
    response.dh.qr = 1;
    response.dh.ancount = response.dh.arcount = response.dh.nscount = 0;
    response.setQuestion(name, type);

    dnsname zone;
    auto fnd = zones.find(name, zone);
    if(fnd && fnd->zone) {
      cout<<"---\nBest zone: "<<zone<<", name now "<<name<<", loaded: "<<(void*)fnd->zone<<endl;

      response.dh.aa = 1; 
            
      auto bestzone = fnd->zone;
      dnsname searchname(name), lastnode;
      bool passedZonecut=false;
      auto node = bestzone->find(searchname, lastnode, &passedZonecut);
      if(!node) {
        cout<<"Found nothing in zone '"<<zone<<"' for lhs '"<<name<<"'"<<endl;
      }
      else if(!searchname.empty()) {
        cout<<"This was a partial match, searchname now "<<searchname<<endl;
        for(const auto& rr: node->rrsets) {
          cout<<"  Have type "<<rr.first<<endl;
        }
        if(node->rrsets.count((int)DNSType::NS)) {
          for(const auto& rr : node->rrsets[(int)DNSType::NS]) {
            response.putRR(lastnode+zone, (int)DNSType::NS, 3600, rr);
            response.dh.nscount = htons(ntohs(response.dh.ancount)+1);
          }
          // should do additional processing here
        }
      }
      else {
        cout<<"Found something in zone '"<<zone<<"' for lhs '"<<name<<"', searchname now '"<<searchname<<"', lastnode '"<<lastnode<<"', passedZonecut="<<passedZonecut<<endl;

        if(passedZonecut)
          response.dh.aa = false;
        if(node->rrsets.count(type)) {
          cout<<"Had qtype too!"<<endl;
          for(const auto& rr : node->rrsets[type]) {
            response.putRR(lastnode+zone, type, 3600, rr);
            response.dh.ancount = htons(ntohs(response.dh.ancount)+1);
          }
        }
        else if(node->rrsets.count((int)DNSType::CNAME)) {
          cout<<"We do have a CNAME!"<<endl;
          for(const auto& rr : node->rrsets[(int)DNSType::CNAME]) {
            response.putRR(lastnode+zone, (int)DNSType::CNAME, 3600, rr);
            response.dh.ancount = htons(ntohs(response.dh.ancount)+1);
          }
        }
        
      }
    }
    else {
      response.dh.rcode = (uint8_t)RCode::Refused;
    }
    SSendto(udplistener, response.serialize(), remote);
  }
}
