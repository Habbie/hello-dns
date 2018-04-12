#include "dns-storage.hh"
#include "record-types.hh"

void loadZones(DNSNode& zones)
{
  auto zone = zones.add({"powerdns", "org"});
  auto newzone = zone->zone = new DNSNode(); // XXX ICK
  
  newzone->addRRs(SOAGen::make({"ns1", "powerdns", "org"}, {"admin", "powerdns", "org"}, 1),
                   NSGen::make({"ns1", "powerdns", "org"}), NSGen::make({"ns2", "powerdns", "org"}),
                   MXGen::make(25, {"server1", "powerdns", "org"})
                  );
  newzone->add({"server1"})->addRRs(AGen::make("213.244.168.210"), AAAAGen::make("::1"));
  
  newzone->addRRs(AGen::make("1.2.3.4"));
  newzone->addRRs(AAAAGen::make("::1"));
  newzone->rrsets[DNSType::AAAA].ttl= 900;

  newzone->addRRs(TXTGen::make("Proudly served by tdns compiled on " __DATE__ " " __TIME__),
                  TXTGen::make("This is some more filler to make this packet exceed 512 bytes"));
  
  newzone->add({"www"})->rrsets[DNSType::CNAME].add(CNAMEGen::make({"server1","powerdns","org"}));
  newzone->add({"www2"})->rrsets[DNSType::CNAME].add(CNAMEGen::make({"nosuchserver1","powerdns","org"}));


  newzone->add({"server2"})->addRRs(AGen::make("213.244.168.210"), AAAAGen::make("::1"));
  
  newzone->add({"*", "nl"})->rrsets[DNSType::A].add(AGen::make("5.6.7.8"));
  newzone->add({"*", "fr"})->rrsets[DNSType::CNAME].add(CNAMEGen::make({"server2", "powerdns", "org"}));

  newzone->add({"fra"})->addRRs(NSGen::make({"ns1","fra","powerdns","org"}), NSGen::make({"ns1","fra","powerdns","org"}));
  newzone->add({"ns1"})->addRRs(AGen::make("212.13.14.15"));
  newzone->add({"ns1", "fra"})->addRRs(AGen::make("12.13.14.15"));
  newzone->add({"NS2", "fra"})->addRRs(AGen::make("12.13.14.16"));
  newzone->add({"ns2", "fra"})->addRRs(AAAAGen::make("::1"));  

  newzone->add({"something"})->addRRs(AAAAGen::make("::1"), AGen::make("12.13.14.15"));
  newzone->add({"time"})->addRRs(ClockTXTGen::make("The time is %a, %d %b %Y %T %z"));
}
