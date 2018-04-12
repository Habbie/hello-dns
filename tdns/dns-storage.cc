#include "dns-storage.hh"
using namespace std;

bool dnsname::makeRelative(const dnsname& root)
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

const DNSNode* DNSNode::find(dnsname& name, dnsname& last, const DNSNode** passedZonecut, dnsname* zonecutname) const
{
  cout<<"find for '"<<name<<"', last is now '"<<last<<"'"<<endl;
  if(!last.empty() && rrsets.count(DNSType::NS)) {
    cout<<"  passed a zonecut, making note of this"<<endl;
    if(passedZonecut)
      *passedZonecut=this;
    if(zonecutname)
      *zonecutname=last;
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
      cout<<"  Had wildcard match, picking that, matching all labels"<<endl;
      while(name.size() > 1) {
        last.push_front(name.back());
        name.pop_back();
      }
    }
  }
  cout<<"  Had match, continuing to child '"<<iter->first<<"'"<<endl;
  last.push_front(name.back());
  name.pop_back();
  return iter->second.find(name, last, passedZonecut, zonecutname);
}

DNSNode* DNSNode::add(dnsname name) 
{
  cout<<"Add called for '"<<name<<"'"<<endl;
  if(name.size() == 1) {
    cout<<"  Last label, done with add. ";
    if(children.count(name.front()))
      cout<<"Label was present already"<<endl;
    else
      cout<<"Added label as new child"<<endl;
    return &children[name.front()];
  }

  auto back = name.back();
  name.pop_back();
  auto iter = children.find(back);

  if(iter == children.end()) {
    cout<<"Inserting new child for "<<back<<", continuing add there"<<endl;
    return children[back].add(name);
  }
  return iter->second.add(name);
}

dnsname operator+(const dnsname& a, const dnsname& b)
{
  dnsname ret=a;
  for(const auto& l : b.d_name)
    ret.d_name.push_back(l);
  return ret;
}

void DNSNode::visit(std::function<void(const dnsname& name, const DNSNode*)> visitor, dnsname name) const
{
  visitor(name, this);
  for(const auto& c : children)
    c.second.visit(visitor, dnsname{c.first}+name);
}

// this should perform escaping rules!
std::ostream & operator<<(std::ostream &os, const dnslabel& d)
{
  os<<d.d_s;
  return os;
}

std::ostream & operator<<(std::ostream &os, const dnsname& d)
{
  for(const auto& l : d.d_name) 
    os<<l<<".";
  return os;
}

void DNSNode::addRRs(std::unique_ptr<RRGen>&&a)
{
  rrsets[a->getType()].add(std::move(a));
}
