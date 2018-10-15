#include "dns-storage.hh"
#include "record-types.hh"
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

//! Checks is this DNSName is part of root
bool DNSName::isPartOf(const DNSName& root) const
{
  auto them = root.d_name.crbegin(), us = d_name.crbegin();
  for(;;) {
    if(them == root.d_name.crend())
      return true;
    if(us == d_name.crend())
      return false;
    
    if(*them == *us) {
      ++them;
      ++us;
    }
    else
      break;
  }
  return false;
}


//! Append two DNSNames
DNSName operator+(const DNSName& a, const DNSName& b)
{
  DNSName ret=a;
  for(const auto& l : b.d_name)
    ret.d_name.push_back(l);
  return ret;
}

//! This function is plain wrong and does unescape its input XXX
DNSName makeDNSName(const std::string& str)
{
  DNSName ret;
  if(str==".")
    return ret;

  string part;
  for(const auto& c: str) {
    if(c=='.') {
      ret.push_back(part);
      part.clear();
    }
    else part.append(1, c);
  }
  if(!part.empty())
    ret.push_back(part);
  return ret;
}


DNSNode::~DNSNode() = default;
RRGen::~RRGen() = default;

//! The big RFC 1034-compatible find function. Will perform wildcard synth if requested & let you know about it
const DNSNode* DNSNode::find(DNSName& name, DNSName& last, bool wildcard, const DNSNode** passedZonecut, const DNSNode** passedwcard) const
{
  if(!last.empty() && rrsets.count(DNSType::NS)) {
    if(passedZonecut)  *passedZonecut=this;
  }

  if(name.empty()) {
    return this;
  }
  auto iter = children.find(name.back());

  if(iter == children.end()) {
    if(!wildcard)
      return this;

    iter = children.find(DNSLabel("*"));
    if(iter == children.end()) { // also no wildcard
      return this;
    }
    else {  //  Had wildcard match, picking that, matching all labels
      if(passedwcard) *passedwcard = &*iter;
      
      while(name.size() > 1) {
        last.push_front(name.back());
        name.pop_back();
      }
    }
  }

  last.push_front(name.back()); // this grows the part that we matched
  name.pop_back();              // and removes same parts from name
  return iter->find(name, last, wildcard, passedZonecut, passedwcard);
}

//! Idempotent way of creating/accessing the DNSName in a tree
DNSNode* DNSNode::add(DNSName name) 
{
  if(name.empty()) return this;
  auto back = name.back();
  name.pop_back();
  children.emplace(back, this);
  return const_cast<DNSNode&>(*children.find(back)).add(name); // sorry
}

const DNSNode* DNSNode::next() const
{
  if(children.size()) {
    //    cout<<"Descending to leftmost child"<<endl;
    return &*children.begin();
  }
  else if(!d_parent) {
    //    cout<<"We hit the end"<<endl;
    return 0;
  }
  else {
    // need to go back up
    auto us = this; 
    while(us->d_parent) {
//      cout<<"Looking for node "<<us->d_name<<" at parent"<<endl;
      auto iter=us->d_parent->children.find(*us);
      if(iter == us->d_parent->children.cend()) {
        //        cout<<"Ehm, parent doesn't know about us?"<<endl;
        return 0;
      }
      ++iter;
      if(iter != us->d_parent->children.cend()) {
        //        cout<<"Found that at parent node, returning the one right to it"<<endl;
        return &*iter;
      }
      else {
        //        cout<<"That was the rightmost node already at parent, need to go a level up"<<endl;
        us = us->d_parent;
      }
    }
  }
  return 0;
}


const DNSNode* DNSNode::prev() const
{
  auto us = this;
  if(!us->d_parent)
    return 0;
  
  while(us->d_parent) {
    //  cout<<"Looking for node "<<us->d_name<<" at parent"<<endl;
    auto iter=us->d_parent->children.find(*us);
    if(iter != us->d_parent->children.cbegin()) {
      //cout<<"Found that at parent node, returning the one left it"<<endl;
      --iter;
      return &*iter;
    }
    else {
      //cout<<"That was the leftmost node already at parent, need to go a level up"<<endl;
      us = us->d_parent;
    }
  }
  return us;
}

void DNSNode::addRRs(std::unique_ptr<RRGen>&&a)
{
  if(auto rrsig = dynamic_cast<RRSIGGen*>(a.get())) {
    rrsets[rrsig->d_type].add(std::move(a));
  }
  else if(a->getType() == DNSType::CNAME && std::count_if(rrsets.begin(), rrsets.end(), [](const auto& a) { return a.first != DNSType::NSEC; })) {
    throw std::runtime_error("Can't add CNAME RR to a node that already has RRs present");
  }
  else if(rrsets.count(DNSType::CNAME) && a->getType() != DNSType::NSEC)
    throw std::runtime_error("Can't add non-NSEC RR to a node that already has a CNAME");
  else
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
