#include "dns-storage.hh"
#include "record-types.hh"
#include "sclasses.hh"
using namespace std;

/*! 
   @file
   @brief Actual zone contents can be put / retrieved from this file
*/

//! Called by tdns.cc main() to load user content
void loadZones(DNSNode& zones)
{
  auto addresses=resolveName("localhost"); // this retrieves IPv4 and IPv6
  for(auto& a: addresses) {
    try {
      a.sin4.sin_port = htons(5300);
      zones.add({})->zone=retrieveZone(a, {});
      zones.add({"2", "0", "192", "in-addr", "arpa"})->zone=retrieveZone(a, {"2", "0", "192", "in-addr", "arpa"});
      zones.add({"addzone", "com"})->zone=retrieveZone(a, {"addzone", "com"});
      zones.add({"cdnskey-cds-test", "com"})->zone=retrieveZone(a, {"cdnskey-cds-test", "com"});
      zones.add({"cryptokeys", "org"})->zone=retrieveZone(a, {"cryptokeys", "org"});
      zones.add({"delegated", "dnssec-parent", "com"})->zone=retrieveZone(a, {"delegated", "dnssec-parent", "com"});
      zones.add({"dnssec-parent", "com"})->zone=retrieveZone(a, {"dnssec-parent", "com"});
      zones.add({"example", "com"})->zone=retrieveZone(a, {"example", "com"});
      zones.add({"minimal", "com"})->zone=retrieveZone(a, {"minimal", "com"});
      zones.add({"nztest", "com"})->zone=retrieveZone(a, {"nztest", "com"});
      zones.add({"powerdnssec", "org"})->zone=retrieveZone(a, {"powerdnssec", "org"});
      zones.add({"secure-delegated", "dnssec-parent", "com"})->zone=retrieveZone(a, {"secure-delegated", "dnssec-parent", "com"});
      zones.add({"stest", "com"})->zone=retrieveZone(a, {"stest", "com"});
      zones.add({"test", "com"})->zone=retrieveZone(a, {"test", "com"});
      zones.add({"test", "dyndns"})->zone=retrieveZone(a, {"test", "dyndns"});
      zones.add({"test", "dyndns", "orig"})->zone=retrieveZone(a, {"test", "dyndns", "orig"});
      zones.add({"tsig", "com"})->zone=retrieveZone(a, {"tsig", "com"});
      zones.add({"unit", "test"})->zone=retrieveZone(a, {"unit", "test"});
      zones.add({"wtest", "com"})->zone=retrieveZone(a, {"wtest", "com"});
      break;
    }
    catch(std::exception& e) {
      cout<<"Unable to retrieve root zone from f-root server "+a.toStringWithPort()<<": " << e.what() << endl;
    }
  }
  /*
  zones.add({"hubertnet", "nl"})->zone=retrieveZone(ComboAddress("52.48.64.3", 53), {"hubertnet", "nl"});
  zones.add({"ds9a", "nl"})->zone=retrieveZone(ComboAddress("52.48.64.3", 53), {"ds9a", "nl"});
  */

}
