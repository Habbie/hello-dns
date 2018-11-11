#include <fstream>
#include <vector>
#include <map>
#include <stdexcept>
#include "sclasses.hh"
#include <signal.h>
#include <random>
#include "record-types.hh"
#include <thread>
#include <chrono>
#include "nlohmann/json.hpp"
/*! 
   @file
   @brief Teachable resolver
*/

using namespace std;

//! Thrown if too many queries have been sent.
struct TooManyQueriesException{};
//! this is a different kind of error: we KNOW your name does not exist
struct NxdomainException{};
//! Or if your type does not exist
struct NodataException{};

multimap<DNSName, ComboAddress> g_root;
class TDNSResolver
{
public:

  TDNSResolver(multimap<DNSName, ComboAddress>& root) : d_root(root)
  {}
  TDNSResolver()
  {}

  //! This describes a single resource record returned
  struct ResolveRR
  {
    DNSName name;
    uint32_t ttl;
    std::unique_ptr<RRGen> rr;
  };
  
  //! This is the end result of our resolving work
  struct ResolveResult
  {
    vector<ResolveRR> res; //!< what you asked for
    vector<ResolveRR> intermediate; //!< a CNAME chain that gets you there
    void clear()
    {
      res.clear();
      intermediate.clear();
    }
  };

  ResolveResult resolveAt(const DNSName& dn, const DNSType& dt, int depth=0, const DNSName& auth={}, const multimap<DNSName, ComboAddress>& mservers=g_root);

  void setPlot(ostream& fs)
  {
    d_dot = &fs;
    (*d_dot) << "digraph { "<<endl;
  }

  void endPlot()
  {
    if(d_dot)
      (*d_dot) << "}\n";
  }
  
  void setLog(ostream& fs)
  {
    d_log = &fs;
  }
  
  ~TDNSResolver()
  {
  }
  DNSMessageReader getResponse(const ComboAddress& server, const DNSName& dn, const DNSType& dt, int depth=0);
private:
  void dotQuery(const DNSName& auth, const DNSName& server);
  void dotAnswer(const DNSName& dn, const DNSType& rrdt, const DNSName& server);
  void dotCNAME(const DNSName& target, const DNSName& server, const DNSName& dn);
  void dotDelegation(const DNSName& rrdn, const DNSName& server);
  multimap<DNSName, ComboAddress> d_root;
  unsigned int d_maxqueries{100};

  bool d_skipIPv6{false};
  ostream* d_dot{nullptr};
  ostream* d_log{nullptr};
  ostream& lstream()
  {
    return d_log ? *d_log : cout;
  }

public:
  unsigned int d_numqueries{0};
  unsigned int d_numtimeouts{0};
  unsigned int d_numformerrs{0};
  
};

/** Helper function that extracts a useable IP address from an
    A or AAAA resource record. Returns sin_family == 0 if it didn't work */
static ComboAddress getIP(const std::unique_ptr<RRGen>& rr)
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


/** This function guarantees that you will get an answer from this server. It will drop EDNS for you
    and eventually it will even fall back to TCP for you. If nothing works, an exception is thrown.
    Note that this function does not think about actual DNS errors, you get those back verbatim.
    Only the TC bit is checked.

    This function does check if the ID field of the response matches the query, but the caller should
    check qname and qtype.
*/
DNSMessageReader TDNSResolver::getResponse(const ComboAddress& server, const DNSName& dn, const DNSType& dt, int depth)
{
  // quick hack to prevent us from hammering dead servers 
  static thread_local map<std::tuple<ComboAddress, DNSName, DNSType>, int> skips;
  std::string prefix(depth, ' ');
  prefix += dn.toString() + "|"+toString(dt)+" ";

  auto skipiter = skips.find(std::tie(server,dn,dt));
  if(skipiter != skips.end() && skipiter->second > 3) {
    throw std::runtime_error("Skipping query to "+server.toString()+": failed before");
  }
  
  bool doEDNS=true, doTCP=false;
  
  for(int tries = 0; tries < 4 ; ++tries) {
    if(++d_numqueries > d_maxqueries) // there is the possibility our algorithm will loop
      throw TooManyQueriesException(); // and send out thousands of queries, so let's not

    DNSMessageWriter dmw(dn, dt);
    dmw.dh.rd = false;
    dmw.randomizeID();
    if(doEDNS) 
      dmw.setEDNS(1500, false);  // no DNSSEC for now, 1500 byte buffer size
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
        if(!err) d_numtimeouts++;
        throw std::runtime_error("Error waiting for data from "+server.toStringWithPort()+": "+ (err ? string(strerror(errno)): string("Timeout")));
      }

      tmp=SRead(sock, 2);
      len = ntohs(*((uint16_t*)tmp.c_str()));

      // so yes, you need to check for a timeout here again!
      err = waitForData(sock, &timeout);

      if( err <= 0) {
        if(!err) d_numtimeouts++;
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
        skips[std::tie(server,dn,dt)]++;
        if(!err) d_numtimeouts++;
        
        throw std::runtime_error("Error waiting for data from "+server.toStringWithPort()+": "+ (err ? string(strerror(errno)): string("Timeout")));
      }
      ComboAddress ign=server;
      resp = SRecvfrom(sock, 65535, ign); 
    }
    skips.erase(std::tie(server,dn,dt));
    DNSMessageReader dmr(resp);
    if(dmr.dh.id != dmw.dh.id) {
      lstream() << prefix << "ID mismatch on answer" << endl;
      continue;
    }
    if(!dmr.dh.qr) { // for security reasons, you really need this
      lstream() << prefix << "What we received was not a response, ignoring"<<endl;
      continue;
    }
    if((RCode)dmr.dh.rcode == RCode::Formerr) { // XXX this should check that there is no OPT in the response
      lstream() << prefix <<"Got a Formerr, resending without EDNS"<<endl;
      doEDNS=false;
      d_numformerrs++;
      continue;
    }
    if(dmr.dh.tc) {
      lstream() << prefix <<"Got a truncated answer, retrying over TCP"<<endl;
      doTCP=true;
      continue;
    }
    return dmr;
  }
  // should never get here
  return DNSMessageReader(""); // just to make compiler happy
}



/** This takes a list of servers (in a specific order) and shuffles them to a vector.
    This is to spread the load across nameservers
*/
    
static auto randomizeServers(const multimap<DNSName, ComboAddress>& mservers)
{
  vector<pair<DNSName, ComboAddress> > servers;
  for(auto& sp : mservers) 
    servers.push_back(sp);

  std::random_device rd;
  std::mt19937 g(rd());
  std::shuffle(servers.begin(), servers.end(), g);
  return servers;
}

void TDNSResolver::dotQuery(const DNSName& auth, const DNSName& server)
{
  if(!d_dot) return;
  (*d_dot) << '"' << auth << "\" [shape=diamond]\n";
  (*d_dot) << '"' << auth << "\" -> \"" << server << "\" [ label = \" " << d_numqueries<<"\"]" << endl;
}

void TDNSResolver::dotAnswer(const DNSName& dn, const DNSType& rrdt, const DNSName& server)
{
  if(!d_dot) return;
  (*d_dot) <<"\"" << dn << "/"<<rrdt<<"\" [shape=box]\n";
  (*d_dot) << '"' << server << "\" -> \"" << dn << "/"<<rrdt<<"\""<<endl;
}

void TDNSResolver::dotCNAME(const DNSName& target, const DNSName& server, const DNSName& dn)
{
  if(!d_dot) return;
  (*d_dot) << '"' << target << "\" [shape=box]"<<endl;
  (*d_dot) << '"' << server << "\" -> \"" << dn << "/CNAME\" -> \"" << target <<"\"\n";
}

void TDNSResolver::dotDelegation(const DNSName& rrdn, const DNSName& server)
{
  if(!d_dot) return;
  (*d_dot) << '"' << rrdn << "\" [shape=diamond]\n";
  (*d_dot) << '"' << server << "\" -> \"" << rrdn << "\"" <<endl;
}

/** This attempts to look up the name dn with type dt. The depth parameter is for 
    trace output.
    the 'auth' field describes the authority of the servers we will be talking to. Defaults to root ('believe everything')
    The multimap specifies the servers to try with. Defaults to a list of
    root-servers.
*/

TDNSResolver::ResolveResult TDNSResolver::resolveAt(const DNSName& dn, const DNSType& dt, int depth, const DNSName& auth, const multimap<DNSName, ComboAddress>& mservers)
{
  std::string prefix(depth, ' ');
  prefix += dn.toString() + "|"+toString(dt)+" ";
  lstream() << prefix << "Starting query at authority = "<<auth<< ", have "<<mservers.size() << " addresses to try"<<endl;

  ResolveResult ret;
  // it is good form to sort the servers in order of response time
  // for tres, this is not done (since we have no memory), but we do randomize:

  auto servers = randomizeServers(mservers);

  for(auto& sp : servers) {      
    dotQuery(auth, sp.first);

    ret.clear();
    ComboAddress server=sp.second;
    server.sin4.sin_port = htons(53); // just to be sure
    
    if(d_skipIPv6 && server.sin4.sin_family == AF_INET6)
      continue;
    try {
      lstream() << prefix<<"Sending to server "<<sp.first<<" on "<<server.toString()<<endl;

      DNSMessageReader dmr = getResponse(server, dn, dt, depth); // takes care of EDNS and TCP for us

      DNSSection rrsection;
      uint32_t ttl;
      DNSName rrdn, newAuth;
      DNSType rrdt;
      
      dmr.getQuestion(rrdn, rrdt); // parse into rrdn and rrdt
      
      lstream() << prefix<<"Received a "<< dmr.size() << " byte response with RCode "<<(RCode)dmr.dh.rcode<<", qname " <<dn<<", qtype "<<dt<<", aa: "<<dmr.dh.aa << endl;
      if(rrdn != dn || dt != rrdt) {
        lstream() << prefix << "Got a response to a different question or different type than we asked for!"<<endl;
        continue; // see if another server wants to work with us
      }

      // in a real resolver, you must ignore NXDOMAIN in case of a CNAME. Because that is how the internet rolls.
      if((RCode)dmr.dh.rcode == RCode::Nxdomain) {
        lstream() << prefix<<"Got an Nxdomain, it does not exist"<<endl;
        throw NxdomainException();
      }
      else if((RCode)dmr.dh.rcode != RCode::Noerror) {
        throw std::runtime_error(string("Answer from authoritative server had an error: ") + toString((RCode)dmr.dh.rcode));
      }
      if(dmr.dh.aa) {
        lstream() << prefix<<"Answer says it is authoritative!"<<endl;
      }
      
      std::unique_ptr<RRGen> rr;
      set<DNSName> nsses;
      multimap<DNSName, ComboAddress> addresses;

      /* here we loop over records. Perhaps the answer is there, perhaps
         there is a CNAME we should follow, perhaps we get a delegation.
         And if we do get a delegation, there might even be useful glue */
      
      while(dmr.getRR(rrsection, rrdn, rrdt, ttl, rr)) {
        lstream() << prefix << rrsection<<" "<<rrdn<< " IN " << rrdt << " " << ttl << " " <<rr->toString()<<endl;
        if(dmr.dh.aa==1) { // authoritative answer. We trust this.
          if(rrsection == DNSSection::Answer && dn == rrdn && dt == rrdt) {
            lstream() << prefix<<"We got an answer to our question!"<<endl;
            dotAnswer(dn, rrdt, sp.first);
            ret.res.push_back({dn, ttl, std::move(rr)});
          }
          else if(dn == rrdn && rrdt == DNSType::CNAME) {
            DNSName target = dynamic_cast<CNAMEGen*>(rr.get())->d_name;
            ret.intermediate.push_back({dn, ttl, std::move(rr)}); // rr is DEAD now!
            lstream() << prefix<<"We got a CNAME to " << target <<", chasing"<<endl;
            dotCNAME(target, sp.first, dn);
            if(target.isPartOf(auth)) { // this points to something we consider this server auth for
              lstream() << prefix << "target " << target << " is within " << auth<<", harvesting from packet"<<endl;
              bool hadMatch=false;      // perhaps the answer is in this DNS message
              while(dmr.getRR(rrsection, rrdn, rrdt, ttl, rr)) {
                if(rrsection==DNSSection::Answer && rrdn == target && rrdt == dt) {
                  hadMatch=true;
                  ret.res.push_back({dn, ttl, std::move(rr)});
                }
              }
              if(hadMatch) {            // if it worked, great, otherwise actual chase
                lstream() << prefix << "in-message chase worked, we're done"<<endl;
                return ret;
              }
              else
                lstream() <<prefix<<"in-message chase not successful, will do new query for "<<target<<endl;
            }
                        
            auto chaseres=resolveAt(target, dt, depth + 1);
            ret.res = std::move(chaseres.res);
            for(auto& rr : chaseres.intermediate)   // add up their intermediates to ours
              ret.intermediate.push_back(std::move(rr)); 
            return ret;
          }
        }
        else {
          // this picks up nameserver records. We check if glue records are within the authority
          // of what we approached this server for.
          if(rrsection == DNSSection::Authority && rrdt == DNSType::NS) {
            if(dn.isPartOf(rrdn))  {
              DNSName nsname = dynamic_cast<NSGen*>(rr.get())->d_name;

              if(!dmr.dh.aa && (newAuth != rrdn || nsses.empty())) {
                dotDelegation(rrdn, sp.first);
              }
              nsses.insert(nsname);
              newAuth = rrdn;
            }
            else
              lstream()<< prefix << "Authoritative server gave us NS record to which this query does not belong" <<endl;
          }
          else if(rrsection == DNSSection::Additional && nsses.count(rrdn) && (rrdt == DNSType::A || rrdt == DNSType::AAAA)) {
            // this only picks up addresses for NS records we've seen already
            // but that is ok: NS is in Authority section
            if(rrdn.isPartOf(auth)) 
              addresses.insert({rrdn, getIP(rr)}); 
            else
              lstream() << prefix << "Not accepting IP address of " << rrdn <<": out of authority of this server"<<endl;
          }
        }
      }
      if(!ret.res.empty()) {
        // the answer is in!
        lstream() << prefix<<"Done, returning "<<ret.res.size()<<" results, "<<ret.intermediate.size()<<" intermediate\n";
        return ret;
      }
      else if(dmr.dh.aa) {
        lstream() << prefix <<"No data response"<<endl;
        throw NodataException();
      }
      // we got a delegation
      lstream() << prefix << "We got delegated to " << nsses.size() << " " << newAuth << " nameserver names " << endl;
      if(!addresses.empty()) {
        // in addresses are nameservers for which we have IP or IPv6 addresses
        lstream() << prefix<<"Have "<<addresses.size()<<" IP addresses to iterate to: ";
        for(const auto& p : addresses)
          lstream() << p.first <<"="<<p.second.toString()<<" ";
        lstream() <<endl;
        auto res2=resolveAt(dn, dt, depth+1, newAuth, addresses);
        if(!res2.res.empty())
          return res2;
        lstream() << prefix<<"The IP addresses we had did not provide a good answer"<<endl;
      }

      // well we could not make it work using the servers we had addresses for. Let's try
      // to get addresses for the rest
      lstream() << prefix<<"Don't have a resolved nameserver to ask anymore, trying to resolve "<<nsses.size()<<" names"<<endl;
      vector<DNSName> rnsses;
      for(const auto& name: nsses) 
        rnsses.push_back(name);
      std::random_device rd;
      std::mt19937 g(rd());
      std::shuffle(rnsses.begin(), rnsses.end(), g);

      for(const auto& name: rnsses) {
        for(const DNSType& qtype : {DNSType::A, DNSType::AAAA}) {
          multimap<DNSName, ComboAddress> newns;
          lstream() << prefix<<"Attempting to resolve NS " <<name<< "|"<<qtype<<endl;

          try {
            auto result = resolveAt(name, qtype, depth+1);
            lstream() << prefix<<"Got "<<result.res.size()<<" nameserver " << qtype <<" addresses, adding to list"<<endl;
            for(const auto& res : result.res)
              newns.insert({name, getIP(res.rr)});
            lstream() << prefix<<"We now have "<<newns.size()<<" resolved " << qtype<<" addresses to try"<<endl;
            if(newns.empty())
              continue;
          }
          catch(std::exception& e)
          {
            lstream() << prefix <<"Failed to resolve name for "<<name<<"|"<<qtype<<": "<<e.what()<<endl;
            continue;
          }

          catch(...)
          {
            lstream() << prefix <<"Failed to resolve name for "<<name<<"|"<<qtype<<endl;
            continue;
          }
          // we have a new (set) of addresses to try
          auto res2 = resolveAt(dn, dt, depth+1, newAuth, newns);
          if(!res2.res.empty()) // it worked!
            return res2;
          // this could throw an NodataException or a NxdomainException, and we should let that fall through
          // it didn't, let's move on to the next server
            
        }
      }
    }
    catch(std::exception& e) {
      lstream() << prefix <<"Error resolving: " << e.what() << endl;
    }
  }
  // if we get here, we have no results for you.
  return ret;
}

//! This is a thread that will create an answer to the query in `dmr`
void processQuery(int sock, ComboAddress client, DNSMessageReader dmr)
try
{
  DNSName dn;
  DNSType dt;
  dmr.getQuestion(dn, dt);

  DNSMessageWriter dmw(dn, dt);
  dmw.dh.rd = dmr.dh.rd;
  dmw.dh.ra = true;
  dmw.dh.qr = true;
  dmw.dh.id = dmr.dh.id;

  TDNSResolver::ResolveResult res;
  TDNSResolver tdr(g_root);
  try {

    res = tdr.resolveAt(dn, dt);
    
    cout<<"Result of query for "<< dn <<"|"<<toString(dt)<<endl;
    for(const auto& r : res.intermediate) {
      cout<<r.name <<" "<<r.ttl<<" "<<r.rr->getType()<<" " << r.rr->toString()<<endl;
    }
    
    for(const auto& r : res.res) {
      cout<<r.name <<" "<<r.ttl<<" "<<r.rr->getType()<<" "<<r.rr->toString()<<endl;
    }
    cout<<"Result for "<< dn <<"|"<<toString(dt)<<" took "<<tdr.d_numqueries <<" queries"<<endl;
  }
  catch(NodataException& nd)
  {
    cout<<"No Data for "<< dn <<"|"<<toString(dt)<<" took "<<tdr.d_numqueries <<" queries"<<endl;
    SSendto(sock, dmw.serialize(), client);
    return;
  }
  catch(NxdomainException& nx)
  {
    cout<<"NXDOMAIN for "<< dn <<"|"<<toString(dt)<<" took "<<tdr.d_numqueries <<" queries"<<endl;
    dmw.dh.rcode = (int)RCode::Nxdomain;
    SSendto(sock, dmw.serialize(), client);
    return;
  }
  // Put in the CNAME chain
  for(const auto& rr : res.intermediate)
    dmw.putRR(DNSSection::Answer, rr.name, rr.ttl, rr.rr);
  for(const auto& rr : res.res) // and the actual answer
    dmw.putRR(DNSSection::Answer, rr.name, rr.ttl, rr.rr);
  string resp = dmw.serialize();
  SSendto(sock, resp, client); // and send it!
}
catch(TooManyQueriesException& e)
{
  cerr << "Thread died after too many queries" << endl;
}

catch(exception& e)
{
  cerr << "Thread died: " << e.what() << endl;
}

static nlohmann::json rrToJSON(const TDNSResolver::ResolveRR& r)
{
  nlohmann::json record;
  record["name"]=r.name.toString();
  record["ttl"]=r.ttl;
  record["type"]=toString(r.rr->getType());
  record["content"]=r.rr->toString();
  return record;
}


int main(int argc, char** argv)
try
{
  if(argc != 2 && argc != 3) {
    cerr<<"Syntax: tres name type\n";
    cerr<<"Syntax: tres ip:port\n";
    cerr<<"\n";
    cerr<<"When name and type are specified, tres looks up a DNS record.\n";
    cerr<<"types: A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, ...\n";
    cerr<<"       see https://en.wikipedia.org/wiki/List_of_DNS_record_types\n";
    cerr<<"\n";
    cerr<<"When ip:port is specified, tres acts as a DNS server.\n";
    return(EXIT_FAILURE);
  }
  signal(SIGPIPE, SIG_IGN); // TCP, so we need this
  // configure some hints
  multimap<DNSName, ComboAddress> hints = {{makeDNSName("a.root-servers.net"), ComboAddress("198.41.0.4", 53)},
                                           {makeDNSName("f.root-servers.net"), ComboAddress("192.5.5.241", 53)},
                                           {makeDNSName("k.root-servers.net"), ComboAddress("193.0.14.129", 53)},
  };

  // retrieve the actual live root NSSET from the hints
  for(const auto& h : hints) {
    try {
      TDNSResolver tdr;
      DNSMessageReader dmr = tdr.getResponse(h.second, makeDNSName("."), DNSType::NS);
      DNSSection rrsection;
      DNSName rrdn;
      DNSType rrdt;
      uint32_t ttl;
      std::unique_ptr<RRGen> rr;

      // XXX should check if response name and type match query
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

  if(argc == 2) { // be a server
    ComboAddress local(argv[1], 53);
    Socket sock(local.sin4.sin_family, SOCK_DGRAM);
    SBind(sock, local);
    string packet;
    ComboAddress client;
    
    for(;;) {
      try {
        packet = SRecvfrom(sock, 1500, client);
        cout<<"Received packet from "<< client.toStringWithPort() << endl;
        DNSMessageReader dmr(packet);
        if(dmr.dh.qr) {
          cout << "Packet from " << client.toStringWithPort()<< " was not a query"<<endl;
          continue;
        }
        std::thread t(processQuery, (int)sock, client, dmr);
        t.detach();
      }
      catch(exception& e) {
        cout << "Processing packet from " << client.toStringWithPort() <<": "<<e.what() << endl;
      }
    }
  }
  
  // single shot operation
  DNSName dn = makeDNSName(argv[1]);
  DNSType dt = makeDNSType(argv[2]);

  
  TDNSResolver tdr(g_root);
  ostringstream logstream;
  ostringstream dotstream;
  tdr.setLog(logstream);
  tdr.setPlot(dotstream);
  
  auto start = chrono::high_resolution_clock::now();

  int rc = EXIT_SUCCESS;

  nlohmann::json jres;
  jres["name"]=dn.toString();
  jres["type"]=toString(dt);
  jres["intermediate"]= nlohmann::json::array();
  jres["answer"]= nlohmann::json::array();  
  try {

    auto res = tdr.resolveAt(dn, dt);
    
    jres["numqueries"]=tdr.d_numqueries;
    cout<<"Result of query for "<< dn <<"|"<<toString(dt)<< " ("<<res.intermediate.size()<<" intermediate, "<<res.res.size()<<" actual)\n";
    for(const auto& r : res.intermediate) {
      jres["intermediate"].push_back(rrToJSON(r));
      cout<<r.name <<" "<<r.ttl<<" "<<r.rr->getType()<<" " << r.rr->toString()<<endl;
    }
    
    for(const auto& r : res.res) {
      jres["answer"].push_back(rrToJSON(r));
      cout<<r.name <<" "<<r.ttl<<" "<<r.rr->getType()<<" "<<r.rr->toString()<<endl;
    }
    cout<<"Used "<<tdr.d_numqueries << " queries"<<endl;
    jres["rcode"]=0;
  }
  catch(NxdomainException& e)
  {
    cout<<argv[1]<<": name does not exist"<<endl;
    cout<<"Used "<<tdr.d_numqueries << " queries"<<endl;
    rc=EXIT_FAILURE;
    jres["rcode"]=3;
  }
  catch(NodataException& e)
  {
    cout<<argv[1]<< ": name does not have datatype requested"<<endl;
    cout<<"Used "<<tdr.d_numqueries << " queries"<<endl;
    rc=EXIT_FAILURE;
    jres["rcode"]=0;
  }
  catch(TooManyQueriesException& e)
  {
    cout<<argv[1]<< ": exceeded maximum number of queries (" << tdr.d_numqueries<<")"<<endl;
    rc= EXIT_FAILURE;

    jres["rcode"]=2;
  }
  jres["numqueries"]=tdr.d_numqueries;
  jres["numtimeouts"]=tdr.d_numtimeouts;
  jres["numformerrs"]=tdr.d_numformerrs;
  jres["trace"]=logstream.str();
  auto finish = chrono::high_resolution_clock::now();
  auto msecs = chrono::duration_cast<chrono::milliseconds>(finish-start);
  
  jres["msec"]= msecs.count();
  {
    tdr.endPlot();

    ofstream tmpstr(dn.toString()+"dot");
    tmpstr << dotstream.str();
    tmpstr.flush();
  }

  FILE* dotfp = popen(string("dot -Tsvg < "+dn.toString()+"dot").c_str(), "r");
  if(!dotfp) {
    cerr << "popen failed: " << strerror(errno) <<endl;
  }
  else {
    char buffer[100000];
    int siz = fread(buffer, 1, sizeof(buffer), dotfp);
    //    unlink(string(dn.toString()+"dot").c_str());
    jres["dot"]=std::string(buffer, siz);
    pclose(dotfp);
  }
  cout << jres << endl;

  ofstream logfile(dn.toString()+"txt");
  logfile << logstream.str();
  
  std::vector<std::uint8_t> v_cbor = nlohmann::json::to_cbor(jres);
  FILE* out = fopen("cbor", "w");
  fwrite(&v_cbor[0], 1, v_cbor.size(), out);
  fclose(out);
  return rc;
}
catch(std::exception& e)
{
  cerr<<argv[1]<<": fatal error: "<<e.what()<<endl;
  return EXIT_FAILURE;
}
