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
#include "comboaddress.hh"

/*! 
   @file
   @brief Defines DNSLabel, DNSType, DNSClass and DNSNode, which together store DNS details
*/

// note - some platforms are confused over these #defines. Specifically, BYTE_ORDER without __ is a false prophet and may lie!

//! DNS header struct
struct dnsheader {
        unsigned        id :16;         /* query identification number */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
                        /* fields in third byte */
        unsigned        qr: 1;          /* response flag */
        unsigned        opcode: 4;      /* purpose of message */
        unsigned        aa: 1;          /* authoritative answer */
        unsigned        tc: 1;          /* truncated message */
        unsigned        rd: 1;          /* recursion desired */
                        /* fields in fourth byte */
        unsigned        ra: 1;          /* recursion available */
        unsigned        unused :1;      /* unused bits (MBZ as of 4.9.3a3) */
        unsigned        ad: 1;          /* authentic data from named */
        unsigned        cd: 1;          /* checking disabled by resolver */
        unsigned        rcode :4;       /* response code */
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ 
                        /* fields in third byte */
        unsigned        rd :1;          /* recursion desired */
        unsigned        tc :1;          /* truncated message */
        unsigned        aa :1;          /* authoritative answer */
        unsigned        opcode :4;      /* purpose of message */
        unsigned        qr :1;          /* response flag */
                        /* fields in fourth byte */
        unsigned        rcode :4;       /* response code */
        unsigned        cd: 1;          /* checking disabled by resolver */
        unsigned        ad: 1;          /* authentic data from named */
        unsigned        unused :1;      /* unused bits (MBZ as of 4.9.3a3) */
        unsigned        ra :1;          /* recursion available */
#endif
                        /* remaining bytes */
        uint16_t        qdcount;    /* number of question entries */
        uint16_t        ancount;    /* number of answer entries */
        uint16_t        nscount;    /* number of authority entries */
        uint16_t        arcount;    /* number of resource entries */
};

static_assert(sizeof(dnsheader) == 12, "dnsheader size must be 12");

// enums
enum class RCode 
{
  Noerror = 0, Servfail = 2, Nxdomain = 3, Notimp = 4, Refused = 5, Badvers=16
};

// this makes enums printable, which is nice
SMARTENUMSTART(RCode)
SENUM6(RCode, Noerror, Servfail, Nxdomain, Notimp, Refused, Badvers)
SMARTENUMEND(RCode)

enum class DNSType : uint16_t
{
  A = 1, NS = 2, CNAME = 5, SOA=6, PTR=12, MX=15, TXT=16, AAAA = 28, SRV=33, DS=43, RRSIG=46,
  NSEC=47, OPT=41, IXFR = 251, AXFR = 252, ANY = 255
};

SMARTENUMSTART(DNSType)
SENUM13(DNSType, A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, SRV,DS, RRSIG, NSEC, OPT)
SENUM3(DNSType, IXFR, AXFR, ANY)
SMARTENUMEND(DNSType)

enum class DNSClass : uint16_t
{
  IN=1, CHAOS=3
};
SMARTENUMSTART(DNSClass) SENUM2(DNSClass, IN, CHAOS) SMARTENUMEND(DNSClass)

COMBOENUM4(DNSSection, Question, 0, Answer, 1, Authority, 2, Additional, 3);
// this semicolon makes Doxygen happy

/*! \brief Represents a DNS label, which is part of a DNS Name */
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
  //! Equality and comparison are case insensitive
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


//! A DNS Name with helpful methods. Inherits case insensitivity from DNSLabel
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
  void pop_front() { d_name.pop_front(); }
  auto push_front(const DNSLabel& dn) { return d_name.push_front(dn); }
  auto size() { return d_name.size(); }
  void clear() { d_name.clear(); }
  bool makeRelative(const DNSName& root);
  std::string toString() const;
  bool operator==(const DNSName& rhs) const
  {
    return std::lexicographical_compare(begin(), end(), rhs.begin(), rhs.end())==0;
  }
  std::deque<DNSLabel> d_name;
};

// printing, concatenation
std::ostream & operator<<(std::ostream &os, const DNSName& d);
DNSName operator+(const DNSName& a, const DNSName& b);

class DNSMessageWriter;

/*!  this is the how all resource records are stored, as generators
 *   that can convert their content to a human readable string or to a DNSMessage
 */
struct RRGen
{
  virtual void toMessage(DNSMessageWriter& dpw) = 0;
  virtual std::string toString() const = 0;
  virtual DNSType getType() const = 0;
};

//! Resource records are treated as a set and have one TTL for the whole set
struct RRSet
{
  std::vector<std::unique_ptr<RRGen>> contents;
  void add(std::unique_ptr<RRGen>&& rr)
  {
    contents.emplace_back(std::move(rr));
  }
  uint32_t ttl{3600};
};

//! A node in the DNS tree 
struct DNSNode
{
  ~DNSNode();
  //! This is the key function that finds names, returns where it found them and if any zonecuts were passsed
  const DNSNode* find(DNSName& name, DNSName& last, bool wildcards=false, const DNSNode** passedZonecut=0, DNSName* zonecutname=0) const;

  //! This is an idempotent way to add a node to a DNS tree
  DNSNode* add(DNSName name);
  
  //! add one RRGen to this node  
  void addRRs(std::unique_ptr<RRGen>&&a);
  //! add multiple RRGen to this node  
  template<typename... Types>
  void addRRs(std::unique_ptr<RRGen>&&a, Types&&... args)
  {
    addRRs(std::move(a));
    addRRs(std::forward<Types>(args)...);
  }
  //! Walk the tree and visit each node
  void visit(std::function<void(const DNSName& name, const DNSNode*)> visitor, DNSName name) const;

  //! children, found by DNSLabel
  std::map<DNSLabel, DNSNode> children;

  // !the RRSets, grouped by type
  std::map<DNSType, RRSet > rrsets;
  std::unique_ptr<DNSNode> zone; //!< if this is set, this node is a zone
  uint16_t namepos{0}; //!< for label compression, we also use DNSNodes
};

//! Called by main() to load zone information
void loadZones(DNSNode& zones);

std::unique_ptr<DNSNode> retrieveZone(const ComboAddress& remote, const DNSName& zone); 
