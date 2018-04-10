#include "dns-storage.hh"
#include "dns-types.hh"

void loadZones(DNSNode& zones)
{
  auto zone = zones.add({"powerdns", "org"});
  auto newzone = zone->zone = new DNSNode(); // XXX ICK
  
  newzone->rrsets[DNSType::SOA].add(SOAGenerator::make({"ns1", "powerdns", "org"}, {"admin", "powerdns", "org"}, 1));
  newzone->rrsets[DNSType::MX].add(MXGenerator::make(25, {"server1", "powerdns", "org"}));
    
  newzone->rrsets[DNSType::A].add(AGenerator::make("1.2.3.4"));
  newzone->rrsets[DNSType::AAAA].add(AAAAGenerator::make("::1"));
  newzone->rrsets[DNSType::AAAA].ttl= 900;
  newzone->rrsets[DNSType::NS].add(NameGenerator::make({"ns1", "powerdns", "org"}));
  newzone->rrsets[DNSType::TXT].add(TXTGenerator::make("Proudly served by tdns " __DATE__ " " __TIME__));

  newzone->add({"www"})->rrsets[DNSType::CNAME].add(NameGenerator::make({"server1","powerdns","org"}));
  newzone->add({"www2"})->rrsets[DNSType::CNAME].add(NameGenerator::make({"nosuchserver1","powerdns","org"}));

  newzone->add({"server1"})->rrsets[DNSType::A].add(AGenerator::make("213.244.168.210"));
  newzone->add({"server1"})->rrsets[DNSType::AAAA].add(AAAAGenerator::make("::1"));

  newzone->add({"server2"})->rrsets[DNSType::A].add(AGenerator::make("213.244.168.210"));
  newzone->add({"server2"})->rrsets[DNSType::AAAA].add(AAAAGenerator::make("::1"));
  
  newzone->add({"*", "nl"})->rrsets[DNSType::A].add(AGenerator::make("5.6.7.8"));
  newzone->add({"*", "fr"})->rrsets[DNSType::CNAME].add(NameGenerator::make({"server2", "powerdns", "org"}));

  newzone->add({"fra"})->rrsets[DNSType::NS].add(NameGenerator::make({"ns1","fra","powerdns","org"}));
  newzone->add({"fra"})->rrsets[DNSType::NS].add(NameGenerator::make({"ns2","fra","powerdns","org"}));

  newzone->add({"ns1", "fra"})->rrsets[DNSType::A].add(AGenerator::make("12.13.14.15"));
  newzone->add({"NS2", "fra"})->rrsets[DNSType::A].add(AGenerator::make("12.13.14.16"));
  newzone->add({"NS2", "fra"})->rrsets[DNSType::AAAA].add(AAAAGenerator::make("::1"));
}
