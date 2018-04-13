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

class DNSLabel
{
public:
  DNSLabel() {}
  DNSLabel(const char* s) : DNSLabel(std::string(s)) {} 
  DNSLabel(const std::string& s) : d_s(s)
  {
    if(d_s.size() > 63)
      throw std::out_of_range("label too long");
  }
  bool operator<(const DNSLabel& rhs) const
  {
    return std::lexicographical_compare(d_s.begin(), d_s.end(), rhs.d_s.begin(), rhs.d_s.end(), charcomp);
  }
  bool operator==(const DNSLabel &rhs) const
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
std::ostream & operator<<(std::ostream &os, const DNSLabel& d);

enum class RCode 
{
  Noerror = 0, Servfail = 2, Nxdomain = 3, Notimp = 4, Refused = 5, Badvers=16
};

SMARTENUMSTART(RCode)
SENUM6(RCode, Noerror, Servfail, Nxdomain, Notimp, Refused, Badvers)
SMARTENUMEND(RCode)

enum class DNSType : uint16_t
{
  A = 1, NS = 2, CNAME = 5, SOA=6, PTR=12, MX=15, TXT=16, AAAA = 28, SRV=33, OPT=41, IXFR = 251, AXFR = 252, ANY = 255
};

SMARTENUMSTART(DNSType)
SENUM13(DNSType, A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, IXFR, AAAA, SRV, OPT, IXFR)
SENUM2(DNSType, AXFR, ANY)
SMARTENUMEND(DNSType)

enum class DNSClass : uint16_t
{
  IN=1, CHAOS=3
};
SMARTENUMSTART(DNSClass) SENUM2(DNSClass, IN, CHAOS) SMARTENUMEND(DNSClass)

COMBOENUM4(DNSSection, Question, 0, Answer, 1, Authority, 2, Additional, 3)

struct DNSName
{
  DNSName() {}
  DNSName(std::initializer_list<DNSLabel> dls) : d_name(dls) {}
  void push_back(const DNSLabel& l) { d_name.push_back(l); }
  auto back() const { return d_name.back(); }
  auto begin() const { return d_name.begin(); }
  bool empty() const { return d_name.empty(); }
  auto end() const { return d_name.end(); }
  auto front() const { return d_name.front(); }
  void pop_back() { d_name.pop_back(); }
  auto push_front(const DNSLabel& dn) { return d_name.push_front(dn); }
  auto size() { return d_name.size(); }
  void clear() { d_name.clear(); }
  bool makeRelative(const DNSName& root);
  bool operator==(const DNSName& rhs) const
  {
    return std::lexicographical_compare(begin(), end(), rhs.begin(), rhs.end())==0;
  }
  std::deque<DNSLabel> d_name;
};

std::ostream & operator<<(std::ostream &os, const DNSName& d);
DNSName operator+(const DNSName& a, const DNSName& b);

class DNSMessageWriter;
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
  const DNSNode* find(DNSName& name, DNSName& last, const DNSNode** passedZonecut=0, DNSName* zonecutname=0) const;
  DNSNode* add(DNSName name);
  std::map<DNSLabel, DNSNode> children;
  std::map<DNSType, RRSet > rrsets;
  
  void addRRs(std::unique_ptr<RRGen>&&a);

  template<typename... Types>
  void addRRs(std::unique_ptr<RRGen>&&a, Types&&... args)
  {
    addRRs(std::move(a));
    addRRs(std::forward<Types>(args)...);
  }
  
  void visit(std::function<void(const DNSName& name, const DNSNode*)> visitor, DNSName name) const;
  DNSNode* zone{0}; // if this is set, this node is a zone
};

void loadZones(DNSNode& zones);
