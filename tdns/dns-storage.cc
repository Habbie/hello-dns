#include "dns-storage.hh"
#include <iomanip>
using namespace std;

//! Makes us relative to 'root', returns false if we weren't part of root
bool DNSName::makeRelative(const DNSName& root)
{
  auto us = d_name, them=root.d_name;
  while(!them.empty()) {
    if(us.empty())
      return false;
    if(us.back() == them.back()) {
      us.pop_back();
      them.pop_back();
    }
    else
      return false;
  }
  d_name = us;
  return true;
}

//! Append two DNSNames
DNSName operator+(const DNSName& a, const DNSName& b)
{
  DNSName ret=a;
  for(const auto& l : b.d_name)
    ret.d_name.push_back(l);
  return ret;
}

DNSNode::~DNSNode() = default; 

//! The big RFC 1034-compatible find function. Will perform wildcard synth if requested
const DNSNode* DNSNode::find(DNSName& name, DNSName& last, bool wildcard, const DNSNode** passedZonecut, DNSName* zonecutname) const
{
  if(!last.empty() && rrsets.count(DNSType::NS)) {
    if(passedZonecut)
      *passedZonecut=this;
    if(zonecutname)
      *zonecutname=last;
  }

  if(name.empty()) {
    return this;
  }
  auto iter = children.find(name.back());

  if(iter == children.end()) {
    if(!wildcard)
      return this;

    iter = children.find("*");
    if(iter == children.end()) { // also no wildcard
      return this;
    }
    else {
      //  Had wildcard match, picking that, matching all labels
      while(name.size() > 1) {
        last.push_front(name.back());
        name.pop_back();
      }
    }
  }

  last.push_front(name.back()); // this grows the part that we matched
  name.pop_back();              // and removes same parts from name
  return iter->second.find(name, last, wildcard, passedZonecut, zonecutname);
}

//! Idempotent way of creating/accessing the DNSName in a tree
DNSNode* DNSNode::add(DNSName name) 
{
  if(name.empty()) return this;
  auto back = name.back();
  name.pop_back();
  return children[back].add(name); // will make child node if needed
}

//! Used to travel the tree, 'visitor' gets called on all nodes
void DNSNode::visit(std::function<void(const DNSName& name, const DNSNode*)> visitor, DNSName name) const
{
  visitor(name, this);
  for(const auto& c : children)
    c.second.visit(visitor, DNSName{c.first}+name);
}

void DNSNode::addRRs(std::unique_ptr<RRGen>&&a)
{
  if(a->getType() == DNSType::CNAME && rrsets.size())
    throw std::runtime_error("Can't add CNAME RR to a node that already has RRs present");
  else if(rrsets.count(DNSType::CNAME))
    throw std::runtime_error("Can't add an RR to a node that already has a CNAME");
  rrsets[a->getType()].add(std::move(a));
}

// Emit an escaped DNSLabel in 'master file' format
std::ostream & operator<<(std::ostream &os, const DNSLabel& d)
{
  for(uint8_t a : d.d_s) {
    if(a <= 0x20 || a >= 0x7f) {  // RFC 4343
      os<<'\\'<<setfill('0')<<setw(3)<<(int)a;
      setfill(' '); // setw resets itself
    }
    else {
      if((char)a =='.' || (char)a=='\\')
        os<<"\\";
      os<<(char)a;
    }
  }
  return os;
}

// emit a DNSName
std::ostream & operator<<(std::ostream &os, const DNSName& d)
{
  if(d.empty()) os<<'.';
  else for(const auto& l : d.d_name) 
    os<<l<<".";
  return os;
}

// Convenience function, turns DNSName into master file format string
std::string DNSName::toString() const
{
  ostringstream str;
  str << *this;
  return str.str();
}
