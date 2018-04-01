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
  DNSNode* find(dnsname& name, dnsname& last);
  DNSNode* add(dnsname name);
  map<dnslabel, DNSNode> children;
  map<dnstype, vector<string> > rrsets;
  
  DNSNode* zone{0}; // if this is set, this node is a zone
};

DNSNode* DNSNode::find(dnsname& name, dnsname& last) 
{
  cout<<"Lookup for '"<<name<<"', last is now '"<<last<<"'"<<endl;
  if(name.empty()) {
    if(!zone && rrsets.empty()) // only root zone can have this
      return 0;
    else
      return this;
  }
  auto iter = children.find(name.back());
  cout<<"Looked for child called '"<<name.back()<<"'"<<endl;
  if(iter == children.end()) {
    cout<<"Found nothing, returning leaf"<<endl;
    return this;
  }
  last.push_front(name.back());
  name.pop_back();
  return iter->second.find(name, last);
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
  std::array<uint8_t, 500> payload;
  uint16_t payloadpos{0}, payloadsize{0};

  dnsname getName();
  uint16_t getUInt16();
  uint32_t getUInt32();

  void putName(const dnsname& name);
  void putUInt16(uint16_t val);
  void putUInt32(uint32_t val);
  void putBlob(const std::string& blob);

  void getQuestion(dnsname& name, dnstype& type);
  void setQuestion(const dnsname& name, dnstype type);
  void putRR(const dnsname& name, uint16_t type, uint32_t ttl, const std::string& rr);
  std::string serialize() const;
} __attribute__((packed));

dnsname DNSMessage::getName()
{
  dnsname name;
  for(;;) {
    uint8_t labellen=payload.at(payloadpos++);
    if(labellen > 63)
      throw std::runtime_error("Got a compressed label");
    if(!labellen) // end of dnsname
      break;
    dnslabel label(&payload.at(payloadpos), &payload.at(payloadpos+labellen));
    payloadpos += labellen;
    name.push_back(label);
  }
  return name;
}

uint16_t DNSMessage::getUInt16()
{
  uint16_t ret;
  memcpy(&ret, &payload.at(payloadpos+2)-2, 2);
  payloadpos+=2;
  return htons(ret);
}

void DNSMessage::getQuestion(dnsname& name, dnstype& type)
{
  name=getName();
  type=getUInt16();
}

void DNSMessage::putName(const dnsname& name)
{
  for(const auto& l : name) {
    payload.at(payloadpos++)=l.size();
    for(const auto& a : l)
      payload.at(payloadpos++)=(uint8_t)a;
  }
  payload.at(payloadpos++)=0;
}

void DNSMessage::putUInt16(uint16_t val)
{
  val = htons(val);
  memcpy(&payload.at(payloadpos+2)-2, &val, 2);
  payloadpos+=2;
}

void DNSMessage::putUInt32(uint32_t val)
{
  val = htonl(val);
  memcpy(&payload.at(payloadpos+sizeof(val)) - sizeof(val), &val, sizeof(val));
  payloadpos += sizeof(val);
}


void DNSMessage::putBlob(const std::string& blob)
{
  memcpy(&payload.at(payloadpos+blob.size()) - blob.size(), blob.c_str(), blob.size());
  payloadpos += blob.size();;
}


void DNSMessage::putRR(const dnsname& name, uint16_t type, uint32_t ttl, const std::string& payload)
{
  putName(name);
  putUInt16(type); putUInt16(1);
  putUInt32(ttl);
  putUInt16(payload.size()); // check for overflow!
  putBlob(payload);
}

void DNSMessage::setQuestion(const dnsname& name, dnstype type)
{
  putName(name);
  putUInt16(type);
  putUInt16(1); // class
}

string DNSMessage::serialize() const
{
  return string((const char*)this, (const char*)this + sizeof(dnsheader) + payloadpos);
}
  

static_assert(sizeof(DNSMessage) == 516, "dnsmessage size must be 516");

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

  zone->zone->add({"www"})->rrsets[(dnstype)DNSType::CNAME]={"\x03www\x02nl\x00"};
  
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
      cout<<"Best zone: "<<zone<<", name now "<<name<<", loaded: "<<(void*)fnd->zone<<endl;

      response.dh.aa = 1; 
            
      auto bestzone = fnd->zone;
      dnsname searchname(name), lastnode;
      auto rrsets = bestzone->find(searchname, lastnode);
      if(!rrsets) {
        cout<<"Found nothing in zone '"<<zone<<"' for lhs '"<<name<<"'"<<endl;
      }
      else {
        cout<<"Found something in zone '"<<zone<<"' for lhs '"<<name<<"', searchname now '"<<searchname<<"', lastnode '"<<lastnode<<"'"<<endl;
        if(rrsets->rrsets.count(type)) {
          cout<<"Had qtype too!"<<endl;
          for(const auto& rr : rrsets->rrsets[type]) {
            response.putRR({"powerdns", "org"}, type, 3600, rr);
            response.dh.ancount = htons(ntohs(response.dh.ancount)+1);
          }
        }
        else {
          cout<<"Node exists, but no matching qtype"<<endl;
          if(rrsets->rrsets.count((int)DNSType::CNAME)) {
            cout<<"We do have a CNAME!"<<endl;
            for(const auto& rr : rrsets->rrsets[(int)DNSType::CNAME]) {
              response.putRR({"www", "powerdns", "org"}, type, 3600, rr);
              response.dh.ancount = htons(ntohs(response.dh.ancount)+1);
            }
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
