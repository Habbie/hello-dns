#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file
#include "catch.hpp"

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
}
