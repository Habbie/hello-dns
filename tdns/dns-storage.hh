#pragma once
#include <strings.h>
#include <string>
#include <map>
#include <vector>
#include <deque>
#include <iostream>
#include <cstdint>
#include <functional>
#include <memory>
#include "nenum.hh"

class dnslabel
{
public:
  dnslabel() {}
  dnslabel(const char* s) : dnslabel(std::string(s)) {} 
  dnslabel(const std::string& s) : d_s(s)
  {
    if(d_s.size() > 63)
      throw std::out_of_range("label too long");
  }
  bool operator<(const dnslabel& rhs) const
  {
    return std::lexicographical_compare(d_s.begin(), d_s.end(), rhs.d_s.begin(), rhs.d_s.end(), charcomp);
  }
  bool operator==(const dnslabel &rhs) const
  {
    return !(*this < rhs) && !(rhs<*this);
  }
  auto size() const { return d_s.size(); }
  std::string d_s;
private:
  static bool charcomp(char a, char b)
  {
    if(a >= 0x61 && a <= 0x7A)
      a -= 0x20;
    if(b >= 0x61 && b <= 0x7A)
      b -= 0x20;
    return a < b;
  }
};
std::ostream & operator<<(std::ostream &os, const dnslabel& d);

enum class RCode 
{
  Noerror = 0, Servfail = 2, Nxdomain = 3, Notimp = 4, Refused = 5
};

SMARTENUMSTART(RCode)
SENUM5(RCode, Noerror, Servfail, Nxdomain, Notimp, Refused)
SMARTENUMEND(RCode)

enum class DNSType : uint16_t
{
  A = 1, NS = 2, CNAME = 5, SOA=6, PTR=12, MX=15, TXT=16, AAAA = 28, SRV=33, OPT=41, IXFR = 251, AXFR = 252, ANY = 255
};

SMARTENUMSTART(DNSType)
SENUM13(DNSType, A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, IXFR, AAAA, SRV, OPT, IXFR)
SENUM2(DNSType, AXFR, ANY)
SMARTENUMEND(DNSType)

COMBOENUM4(DNSSection, Question, 0, Answer, 1, Authority, 2, Additional, 3)

struct dnsname
{
  dnsname() {}
  dnsname(std::initializer_list<dnslabel> dls) : d_name(dls) {}
  void push_back(const dnslabel& l) { d_name.push_back(l); }
  auto back() const { return d_name.back(); }
  auto begin() const { return d_name.begin(); }
  bool empty() const { return d_name.empty(); }
  auto end() const { return d_name.end(); }
  auto front() const { return d_name.front(); }
  void pop_back() { d_name.pop_back(); }
  auto push_front(const dnslabel& dn) { return d_name.push_front(dn); }
  auto size() { return d_name.size(); }
  void clear() { d_name.clear(); }
  bool makeRelative(const dnsname& root);
  
  std::deque<dnslabel> d_name;
};

std::ostream & operator<<(std::ostream &os, const dnsname& d);
dnsname operator+(const dnsname& a, const dnsname& b);

struct DNSMessageWriter;
struct RRGen
{
  virtual void toMessage(DNSMessageWriter& dpw) = 0;
  virtual DNSType getType() const = 0;
};

struct RRSet
{
  std::vector<std::unique_ptr<RRGen>> contents;
  void add(std::unique_ptr<RRGen>&& rr)
  {
    contents.emplace_back(std::move(rr));
  }
  uint32_t ttl{3600};
};

struct DNSNode
{
  const DNSNode* find(dnsname& name, dnsname& last, const DNSNode** passedZonecut=0, dnsname* zonecutname=0) const;
  DNSNode* add(dnsname name);
  std::map<dnslabel, DNSNode> children;
  std::map<DNSType, RRSet > rrsets;

  
  void addRRs(std::unique_ptr<RRGen>&&a);

  template<typename... Types>
  void addRRs(std::unique_ptr<RRGen>&&a, Types&&... args)
  {
    addRRs(std::move(a));
    addRRs(std::forward<Types>(args)...);
  }
  
  void visit(std::function<void(const dnsname& name, const DNSNode*)> visitor, dnsname name) const;
  DNSNode* zone{0}; // if this is set, this node is a zone
};

void loadZones(DNSNode& zones);
