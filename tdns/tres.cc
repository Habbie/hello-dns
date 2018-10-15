#include <cstdint>
#include <vector>
#include <map>
#include <stdexcept>
#include "sclasses.hh"
#include <thread>
#include <signal.h>
#include "record-types.hh"

/*! 
   @file
   @brief Tiny resolver
*/

using namespace std;

multimap<DNSName, ComboAddress> g_root;
unsigned int g_numqueries;
bool g_skipIPv6{true};  //!< set this if you have no functioning IPv6

/** Helper function that extracts a useable IP address from an
    A or AAAA resource record. Returns sin_family == 0 if it didn't work */
ComboAddress getIP(const std::unique_ptr<RRGen>& rr)
{
  ComboAddress ret;
  ret.sin4.sin_family = 0;
  if(auto ptr = dynamic_cast<AGen*>(rr.get()))
    ret=ptr->getIP();
  else if(auto ptr = dynamic_cast<AAAAGen*>(rr.get()))
    ret=ptr->getIP();

  ret.sin4.sin_port = htons(53);
  return ret;
}

//! Thrown if too many queries have been sent.
struct TooManyQueriesException{};

/** This function guarantees that you will get an answer from this server. It will drop EDNS for you
    and eventually it will even fall back to TCP for you. If nothing works, an exception is thrown.
    Note that this function does not think about actual DNS errors, you get those back verbatim.
    Only the TC bit is checked.

    This function does check if the ID field of the response matches the query, but the caller should
    check qname and qtype.
*/
DNSMessageReader getResponse(const ComboAddress& server, const DNSName& dn, const DNSType& dt, int depth=0)
{
  std::string prefix(depth, ' ');
  prefix += dn.toString() + "|"+toString(dt)+" ";

  bool doEDNS=true, doTCP=false;

  for(int tries = 0; tries < 4 ; ++tries) {
    if(++g_numqueries > 30) // there is the possibility our algorithm will loop
      throw TooManyQueriesException(); // and send out thousands of queries, so let's not

    DNSMessageWriter dmw(dn, dt);
    dmw.dh.rd = false;
    dmw.randomizeID();
    if(doEDNS) 
      dmw.setEDNS(1500, true); 
    string resp;
    double timeout=1.0;
    if(doTCP) {
      Socket sock(server.sin4.sin_family, SOCK_STREAM);
      SConnect(sock, server);
      string ser = dmw.serialize();
      uint16_t len = htons(ser.length());
      string tmp((char*)&len, 2);
      SWrite(sock, tmp);
      SWrite(sock, ser);

      int err = waitForData(sock, &timeout);

      if( err <= 0) {
        throw std::runtime_error("Error waiting for data from "+server.toStringWithPort()+": "+ (err ? string(strerror(errno)): string("Timeout")));
      }

      tmp=SRead(sock, 2);
      len = ntohs(*((uint16_t*)tmp.c_str()));

      // so yes, you need to check for a timeout here again!
      err = waitForData(sock, &timeout);

      if( err <= 0) {
        throw std::runtime_error("Error waiting for data from "+server.toStringWithPort()+": "+ (err ? string(strerror(errno)): string("Timeout")));
      }
      // and even this is not good enough, an authoritative server could be trickling us bytes
      resp = SRead(sock, len);
    }
    else {
      Socket sock(server.sin4.sin_family, SOCK_DGRAM);
      SConnect(sock, server);
      SWrite(sock, dmw.serialize());

      int err = waitForData(sock, &timeout);

      // so one could simply retry on a timeout, but here we don't
      if( err <= 0) {
        throw std::runtime_error("Error waiting for data from "+server.toStringWithPort()+": "+ (err ? string(strerror(errno)): string("Timeout")));
      }
      ComboAddress ign=server;
      resp = SRecvfrom(sock, 65535, ign); 
    }
    DNSMessageReader dmr(resp);
    if(dmr.dh.id != dmw.dh.id) {
      cout << prefix << "ID mismatch on answer" << endl;
      continue;
    }
    if(!dmr.dh.qr) { // for security reasons, you really need this
      cout << prefix << "What we received was not a response, ignoring"<<endl;
      continue;
    }
    if((RCode)dmr.dh.rcode == RCode::Formerr) { // XXX this should check that there is no OPT in the response
      cout << prefix <<"Got a Formerr, resending without EDNS"<<endl;
      doEDNS=false;
      continue;
    }
    if(dmr.dh.tc) {
      cout << prefix <<"Got a truncated answer, retrying over TCP"<<endl;
      doTCP=true;
      continue;
    }
    return dmr;
  }
  // should never get here
  return DNSMessageReader(""); // just to make compiler happy
}

//! this is a different kind of error: we KNOW your name does not exist
struct NxdomainException{};
//! Or if your type does not exist
struct NodataException{};


/** This attempts to look up the name dn with type dt. The depth parameter is for 
    trace output. The multimap specifies the servers to try with. Defaults to a list of
    root-servers.
*/

vector<std::unique_ptr<RRGen>> resolveAt(const DNSName& dn, const DNSType& dt, int depth=0, const multimap<DNSName, ComboAddress>& servers=g_root)
{
  std::string prefix(depth, ' ');
  prefix += dn.toString() + "|"+toString(dt)+" ";
 
  vector<std::unique_ptr<RRGen>> ret;
  // it is good form to sort the servers in order of response time
  // for tres, this is not done, but it would be good to randomize this a bit
  
  for(auto& sp : servers) {
    ret.clear();
    ComboAddress server=sp.second;
    server.sin4.sin_port = htons(53);
    
    if(g_skipIPv6 && server.sin4.sin_family == AF_INET6)
      continue;
    try {
      cout << prefix<<"Sending to server "<<sp.first<<" on "<<server.toString()<<endl;
      DNSMessageReader dmr = getResponse(server, dn, dt, depth); // takes care of EDNS and TCP for us

      DNSSection rrsection;
      uint32_t ttl;
      
      DNSName rrdn;
      DNSType rrdt;
      
      dmr.getQuestion(rrdn, rrdt); // parse
      
      cout << prefix<<"Received response with RCode "<<(RCode)dmr.dh.rcode<<", qname " <<dn<<", qtype "<<dt<<", aa: "<<dmr.dh.aa << endl;
      if(rrdn != dn || dt != rrdt) {
        cout << prefix << "Got a response to a different question or different type than we asked for!"<<endl;
        continue; // see if another server wants to work with us
      }

      // in a real resolver, you must ignore NXDOMAIN in case of a CNAME. Because that is how the internet rolls.
      if((RCode)dmr.dh.rcode == RCode::Nxdomain) {
        cout << prefix<<"Got an Nxdomain, it does not exist"<<endl;
        throw NxdomainException();
      }
      else if((RCode)dmr.dh.rcode != RCode::Noerror) {
        throw std::runtime_error(string("Answer from authoritative server had an error: ") + toString((RCode)dmr.dh.rcode));
      }
      if(dmr.dh.aa) {
        cout << prefix<<"Answer says it is authoritative!"<<endl;
      }
      
      std::unique_ptr<RRGen> rr;
      set<DNSName> nsses;
      multimap<DNSName, ComboAddress> addresses;

      /* here we loop over records. Perhaps the answer is there, perhaps
         there is a CNAME we should follow, perhaps we get a delegation.
         And if we do get a delegation, there might even be useful glue */
      
      while(dmr.getRR(rrsection, rrdn, rrdt, ttl, rr)) {
        cout << prefix << rrsection<<" "<<rrdn<< " IN " << rrdt << " " << ttl << " " <<rr->toString()<<endl;
        if(dmr.dh.aa==1) {
          if(dn == rrdn && dt == rrdt) {
            cout << prefix<<"We got an answer to our question!"<<endl;
            ret.push_back(std::move(rr));
          }
          if(dn == rrdn && rrdt == DNSType::CNAME) {
            DNSName target = dynamic_cast<CNAMEGen*>(rr.get())->d_name;
            cout << prefix<<"We got a CNAME to " << target <<", chasing"<<endl;
            return resolveAt(target, dt, depth + 1);
            // note, this means we disregard any subsequent records carrying IP addresses
            // for whatever your CNAME pointed at
            // this leads to extra queries, but does make the security model simpler
            // to know if we could have accepted that query would have meant keeping track of
            // what we think your server is authoritative for exactly
          }
        }
        else {
          // this picks up nameserver records, and we even believe your glue.. but ONLY for this query
          // from a security perspective, all an auth can do is ruin the result, since we don't cache
          // if an auth serves confused glue, resolution will suffer
          // (so in other words, if you have an out of zone NS record, we will believe your glue)
          if(rrsection == DNSSection::Authority && rrdt == DNSType::NS) {
            if(dn.isPartOf(rrdn))  {
              DNSName nsname = dynamic_cast<NSGen*>(rr.get())->d_name;
              nsses.insert(nsname);
            }
            else
              cout<< prefix << "Authoritative server gave us NS record to which this query does not belong" <<endl;
          }
          else if(rrsection == DNSSection::Additional && nsses.count(rrdn) && (rrdt == DNSType::A || rrdt == DNSType::AAAA)) {
            addresses.insert({rrdn, getIP(rr)}); // this only picks up addresses for NS records we've seen already
                                                 // but that is ok: NS is in Authority section
          }
        }
      }
      if(!ret.empty()) {
        // the answer is in!
        cout << prefix<<"Done, returning "<<ret.size()<<" results\n";
        return ret;
      }
      else if(dmr.dh.aa) {
        cout << prefix <<"No data response"<<endl;
        throw NodataException();
      }
      // we got a delegation
      if(!addresses.empty()) {
        // in addresses are nameservers for which we have IP or IPv6 addresses
        cout << prefix<<"Have "<<addresses.size()<<" IP addresses to iterate to: ";
        for(const auto& p : addresses)
          cout << p.first <<"="<<p.second.toString()<<" ";
        cout <<endl;
        auto res2=resolveAt(dn, dt, depth+1, addresses);
        if(!res2.empty())
          return res2;
        cout << prefix<<"The IP addresses we had did not provide a good answer"<<endl;
      }

      // well we could not make it work using the servers we had addresses for. Let's try
      // to get addresses for the rest
      cout << prefix<<"Don't have a resolved nameserver to ask anymore, trying to resolve "<<nsses.size()<<" names"<<endl;

      for(const auto& name: nsses) {
        multimap<DNSName, ComboAddress> newns;
        cout << prefix<<"Attempting to resolve NS "<<name<<endl;
        for(const DNSType& qtype : {DNSType::A, DNSType::AAAA}) {
          try {
            auto result = resolveAt(name, qtype, depth+1);
            cout << prefix<<"Got "<<result.size()<<" nameserver IPv4 addresses, adding to list"<<endl;
            for(const auto& res : result)
              newns.insert({name, getIP(res)});
          }
          catch(...)
          {
            cout << prefix <<"Failed to resolve name for "<<name<<"|"<<qtype<<endl;
          }
        }
        cout << prefix<<"We now have "<<newns.size()<<" resolved addresses to try"<<endl;
        if(newns.empty())
          continue;

        // we have a new (set) of addresses to try
        auto res2 = resolveAt(dn, dt, depth+1, newns);
        if(!res2.empty()) // it worked!
          return res2;
        // it didn't, let's move on to the next server
      }
    }
    catch(std::exception& e) {
      cout << prefix <<"Error resolving: " << e.what() << endl;
    }
  }
  // if we get here, we have no results for you.
  return ret;
}

int main(int argc, char** argv)
try
{
  if(argc != 3) {
    cerr<<"Syntax: tres name type\n";
    return(EXIT_FAILURE);
  }
  signal(SIGPIPE, SIG_IGN); // TCP, so we need this
  // configure some hints
  multimap<DNSName, ComboAddress> hints = {{makeDNSName("a.root-servers.net"), ComboAddress("198.41.0.4", 53)},
                                           {makeDNSName("f.root-servers.net"), ComboAddress("192.5.5.241", 53)},
                                           {makeDNSName("k.root-servers.net"), ComboAddress("193.0.14.129", 53)},
  };

  // retrieve the actual live NSSET from the hints
  for(const auto& h : hints) {
    try {
      DNSMessageReader dmr = getResponse(h.second, makeDNSName("."), DNSType::NS);
      DNSSection rrsection;
      DNSName rrdn;
      DNSType rrdt;
      uint32_t ttl;
      std::unique_ptr<RRGen> rr;
      // this assumes the root will only send us relevant NS records
      // we could check with the NS records if we wanted
      // but if a root wants to mess with us, it can
      while(dmr.getRR(rrsection, rrdn, rrdt, ttl, rr)) {
        if(rrdt == DNSType::A || rrdt == DNSType::AAAA)
          g_root.insert({rrdn, getIP(rr)});
      }
      break;
    }
    catch(...){}
  }

  cout<<"Retrieved . NSSET from hints, have "<<g_root.size()<<" addresses"<<endl;

  DNSName dn = makeDNSName(argv[1]);
  DNSType dt = makeDNSType(argv[2]);


  auto res = resolveAt(dn, dt);
  cout<<"Result or query for "<< dn <<"|"<<toString(dt)<<endl;
  for(const auto& r : res) {
    cout<<r->toString()<<endl;
  }
  cout<<"Used "<<g_numqueries << " queries"<<endl;
}
catch(std::exception& e)
{
  cerr<<"Fatal error: "<<e.what()<<endl;
  return EXIT_FAILURE;
}
catch(NxdomainException& e)
{
  cout<<"Name does not exist"<<endl;
  return EXIT_FAILURE;
}
catch(NodataException& e)
{
  cout<<"Name does not have datatype requested"<<endl;
  return EXIT_FAILURE;
}
