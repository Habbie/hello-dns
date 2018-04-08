#pragma once
#include <strings.h>
#include <string>
#include <map>
#include <vector>
#include <deque>
#include <iostream>
#include <cstdint>
#include <functional>
#include "nenum.hh"

typedef std::string dnslabel;

enum class RCode 
{
  Noerror = 0, Servfail = 2, Nxdomain = 3, Notimp = 4, Refused = 5
};

SMARTENUMSTART(RCode)
SENUM5(RCode, Noerror, Servfail, Nxdomain, Notimp, Refused)
SMARTENUMEND(RCode)


enum class DNSType : uint16_t
{
  A = 1, NS = 2, CNAME = 5, SOA=6, MX=15, AAAA = 28, IXFR = 251, AXFR = 252, ANY = 255
};

SMARTENUMSTART(DNSType)
SENUM11(DNSType, A, NS, CNAME, SOA, MX, AAAA, IXFR, AAAA, IXFR, AXFR, ANY)
SMARTENUMEND(DNSType)

enum class DNSSection
{
  Question, Answer, Authority, Additional
};

SMARTENUMSTART(DNSSection)
SENUM4(DNSSection, Question, Answer, Authority, Additional)
SMARTENUMEND(DNSSection)

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
  std::deque<dnslabel> d_name;
};


std::ostream & operator<<(std::ostream &os, const dnsname& d);
dnsname operator+(const dnsname& a, const dnsname& b);
struct RRSet
{
  std::vector<std::string> contents;
  uint32_t ttl{3600};
};

struct DNSLabelCompare: public std::binary_function<std::string, std::string, bool>
{
  bool operator()(const dnslabel& a, const dnslabel& b) const
  {
    return strcasecmp(a.c_str(), b.c_str()) < 0; // XXX locale pain, plus embedded zeros
  }
};

struct DNSNode
{
  const DNSNode* find(dnsname& name, dnsname& last, bool* passedZonecut=0) const;
  DNSNode* add(dnsname name);
  std::map<dnslabel, DNSNode, DNSLabelCompare> children;
  std::map<DNSType, RRSet > rrsets;
  void visit(std::function<void(const dnsname& name, const DNSNode*)> visitor, dnsname name) const;
  DNSNode* zone{0}; // if this is set, this node is a zone
};


