#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file
#include "ext/catch/catch.hpp"
#include "dnsmessages.hh"
#include "dns-storage.hh"

using namespace std;

TEST_CASE("DNSLabel equality", "[dnslabel]") {
  DNSLabel a("www"), b("WWW");
  REQUIRE(a==b);
  REQUIRE(!(a<b));
  REQUIRE(!(b<a));
        
}

TEST_CASE( "DNSName escaping", "[escapes]" ) {
  DNSName test({"powerdns", "com."});
  ostringstream str;

  str<<test;
  REQUIRE(str.str() == "powerdns.com\\..");

  str=ostringstream();
  
  const char zero[]="p\x0werdns";
  DNSName test2({std::string(zero, sizeof(zero)-1), "com"});

  str<<test2;
  REQUIRE(str.str() == "p\\000werdns.com.");
};

TEST_CASE("DNSName operations", "[dnsname]") {
  DNSName test({"www", "powerdns", "org"}), test2;
  test2 = test;

  REQUIRE(test2 == test);
  test.pop_back();
  REQUIRE(test == DNSName({"www", "powerdns"}));

  REQUIRE(test2.makeRelative({"org"}));
  REQUIRE(test2 == DNSName({"www", "powerdns"}));

  DNSName parent({"powerdns", "com"}), root({}), child({"www", "powerdns", "com"});
  DNSName unrelated({"www", "isc", "org"});
  DNSName Org({"Org"});
  REQUIRE(parent.isPartOf(root));
  REQUIRE(child.isPartOf(parent));
  REQUIRE(child.isPartOf(root));
  REQUIRE(!root.isPartOf(parent));
  REQUIRE(!parent.isPartOf(child));
  REQUIRE(!unrelated.isPartOf(child));
  REQUIRE(!child.isPartOf(unrelated));
  REQUIRE(unrelated.isPartOf(Org));
}

TEST_CASE("DNS Messages", "[dnsmessage]") {
  DNSName qname({"www", "powerdns", "com"}), rname;
  DNSType rtype;
  DNSMessageWriter dmw(qname, DNSType::SOA);
  std::string ser = dmw.serialize();
  DNSMessageReader dmr(ser);

  dmr.getQuestion(rname, rtype);
  REQUIRE(rname == qname);
  REQUIRE(rtype == DNSType::SOA);
}
