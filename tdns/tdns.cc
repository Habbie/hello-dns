/* Goal: a fully standards compliant basic authoritative server. In <1000 lines.
   Non-goals: notifications, slaving zones, name compression, edns,
              performance
*/
/*!
   @file 
   @brief This is the main file of the tdns authoritative server
*/
#include <cstdint>
#include <vector>
#include <map>
#include <stdexcept>
#include "sclasses.hh"
#include <thread>
#include <signal.h>
#include "record-types.hh"
#include "dns-storage.hh"

using namespace std;

/*! \mainpage Welcome to tdns
    \section Introduction
    tdns is a simple authoritative nameserver that is fully faithful to the 
    DNS storage model as outlined in RFC 1034.

*/

void addAdditional(const DNSNode* bestzone, const DNSName& zone, const vector<DNSName>& toresolve, DNSMessageWriter& response);

/** \brief This is the main DNS logic function

   This is the main 'DNS logic' function. It receives a set of zones,
   a readable DNS query from a certain IP address, and a writable
   DNS response.

   This function is called by both UDP and TCP listeners. It therefore
   does not do any IXFR/AXFR. It does however perform several sanity checks.

   Returns false if no response should be sent.

   This function implements "the algorithm" from RFC 1034 and is key to 
   unstanding DNS */
bool processQuestion(const DNSNode& zones, DNSMessageReader& dm, const ComboAddress& remote, DNSMessageWriter& response)
{
  if(dm.dh.qr) {
    cerr<<"Dropping non-query from "<<remote.toStringWithPort()<<endl;
    return false; // should not send ANY kind of response, loop potential
  }

  DNSName qname;
  DNSType qtype;
  dm.getQuestion(qname, qtype);

  DNSName origname=qname; // we need this for error reporting, we munch the original name
  cout<<"Received a query from "<<remote.toStringWithPort()<<" for "<<qname<<" and type "<<qtype<<endl;

  try {
    response.dh.id = dm.dh.id; response.dh.rd = dm.dh.rd;
    response.dh.ad = response.dh.ra = response.dh.aa = 0;
    response.dh.qr = 1; response.dh.opcode = dm.dh.opcode;

    uint16_t newsize; bool doBit;

    if(dm.getEDNS(&newsize, &doBit)) {
      cout<<"\tHave EDNS, buffer size = "<<newsize<<", DO bit = "<<doBit<<endl;
      if(dm.d_ednsVersion != 0) {
        cout<<"\tBad EDNS version: "<<(int)dm.d_ednsVersion<<endl;
        response.setEDNS(newsize, doBit, RCode::Badvers);
        return true;
      }
      response.setEDNS(newsize, doBit);
    }
    
    if(qtype == DNSType::AXFR || qtype == DNSType::IXFR)  {
      cout<<"\tQuery was for AXFR or IXFR over UDP, can't do that"<<endl;
      response.dh.rcode = (int)RCode::Servfail;
      return true;
    }

    if(dm.dh.opcode != 0) {
      cout<<"\tQuery had non-zero opcode "<<dm.dh.opcode<<", sending NOTIMP"<<endl;
      response.dh.rcode = (int)RCode::Notimp;
      return true;
    }

    // find the best zone for this query
    DNSName zonename;
    auto fnd = zones.find(qname, zonename); 
    if(!fnd || !fnd->zone) {  // check if we found an actual zone
      cout<<"\tNo zone matched"<<endl;
      response.dh.rcode = (uint8_t)RCode::Refused;
      return true;
    }

    // qname is now relative to the zonename
    cout<<"\tFound best zone: "<<zonename<<", qname now "<<qname<<endl;
    response.dh.aa = 1; 
    
    auto bestzone = fnd->zone.get(); // this loads a pointer to the zone contents
    
    DNSName searchname(qname), lastnode, zonecutname;
    const DNSNode* passedZonecut=0;
    int CNAMELoopCount = 0;
    
  loopCNAME:;
    /* search for the best node, where we want to benefit from wildcard synthesis
       note that this is the same 'find' we used to find the best zone, but we did not
       want any wildcard procssing there */
    
    auto node = bestzone->find(searchname, lastnode, true, &passedZonecut, &zonecutname);
    if(passedZonecut) {
      response.dh.aa = false;
      cout<<"\tThis is a delegation, zonecutname: '"<<zonecutname<<"'"<<endl;

      auto iter = passedZonecut->rrsets.find(DNSType::NS);  // is there an NS record here? should be!
      if(iter != passedZonecut->rrsets.end()) {
        const auto& rrset = iter->second;

        vector<DNSName> toresolve;
        for(const auto& rr : rrset.contents) {
          /* add the NS records to the authority section. Note that for this we have to make
             the name absolute again: zonecutname + zonename */
          response.putRR(DNSSection::Authority, zonecutname+zonename, DNSType::NS, rrset.ttl, rr);
          // and add for additional processing
          toresolve.push_back(dynamic_cast<NSGen*>(rr.get())->d_name);
        }
        addAdditional(bestzone, zonename, toresolve, response);
      }
    }
    else if(!searchname.empty()) { // we had parts of the qname that did not match
      cout<<"\tThis is an NXDOMAIN situation"<<endl;
      if(!CNAMELoopCount) // RFC 1034, 4.3.2, step 3.c
        response.dh.rcode = (int)RCode::Nxdomain;

      const auto& rrset = bestzone->rrsets[DNSType::SOA]; // fetch the SOA record to indicate NXDOMAIN ttl
      auto ttl = min(rrset.ttl, dynamic_cast<SOAGen*>(rrset.contents[0].get())->d_minimum); // 2308 3

      response.putRR(DNSSection::Authority, zonename, DNSType::SOA, ttl, rrset.contents[0]);
    }
    else {
      cout<<"\tFound node in zone '"<<zonename<<"' for lhs '"<<qname<<"', searchname now '"<<searchname<<"', lastnode '"<<lastnode<<"', passedZonecut="<<passedZonecut<<endl;
      
      decltype(node->rrsets)::const_iterator iter;

      vector<DNSName> additional;
      // first we always check for a CNAME, which should be the only RRType at a node if present
      if(iter = node->rrsets.find(DNSType::CNAME), iter != node->rrsets.end()) {
        cout<<"\tNo CNAME"<<endl;
        const auto& rrset = iter->second;
        response.putRR(DNSSection::Answer, lastnode+zonename, DNSType::CNAME, rrset.ttl, rrset.contents[0]);
        DNSName target=dynamic_cast<CNAMEGen*>(rrset.contents[0].get())->d_name;

        // we'll only follow in-zone CNAMEs, which is not quite per-RFC, but a good idea
        if(target.makeRelative(zonename)) {
          cout<<"\tFound CNAME, chasing to "<<target<<endl;
          searchname = target; 
          if(qtype != DNSType::CNAME && CNAMELoopCount++ < 10) {  // do not loop if they *wanted* the CNAME
            lastnode.clear();
            zonecutname.clear();
            goto loopCNAME;
          }
        }
      }  // we have a node, and it might even have RRSets we want
      else if(iter = node->rrsets.find(qtype), iter != node->rrsets.end() || (!node->rrsets.empty() && qtype==DNSType::ANY)) {
        auto range = make_pair(iter, iter);
        
        if(qtype == DNSType::ANY) // if ANY, loop over all types
          range = make_pair(node->rrsets.begin(), node->rrsets.end());
        else
          ++range.second;         // only the qtype they wanted
        for(auto i2 = range.first; i2 != range.second; ++i2) {
          const auto& rrset = i2->second;
          for(const auto& rr : rrset.contents) {
            cout<<"\tAdding a " << i2->first <<" RR\n";
            response.putRR(DNSSection::Answer, lastnode+zonename, i2->first, rrset.ttl, rr);
            if(i2->first == DNSType::MX)
              additional.push_back(dynamic_cast<MXGen*>(rr.get())->d_name);
          }
        }
      }
      else {
        cout<<"\tNode exists, qtype doesn't, NOERROR situation, inserting SOA"<<endl;
        const auto& rrset = bestzone->rrsets[DNSType::SOA];
        auto ttl = min(rrset.ttl, dynamic_cast<SOAGen*>(rrset.contents[0].get())->d_minimum); // 2308 3

        response.putRR(DNSSection::Authority, zonename, DNSType::SOA, ttl, rrset.contents[0]);
      }
      addAdditional(bestzone, zonename, additional, response);
    }
    return true;
  }
  catch(std::out_of_range& e) { // exceeded packet size
    cout<<"\tQuery for '"<<origname<<"'|"<<qtype<<" got truncated"<<endl;
    response.clearRRs(); 
    response.dh.aa = 0;   response.dh.tc = 1; 
    return true;
  }
  catch(std::exception& e) {
    cout<<"\tError processing query: "<<e.what()<<endl;
    return false;
  }
}

/* this is where all UDP questions come in. Note that 'zones' is const, 
   which protects us from accidentally changing anything */
void udpThread(ComboAddress local, Socket* sock, const DNSNode* zones)
{
  DNSName qname;
  DNSType qtype;

  for(;;) {
    ComboAddress remote(local);

    string message = SRecvfrom(*sock, 512, remote);
    DNSMessageReader dm(message);
    dm.getQuestion(qname, qtype);

    DNSMessageWriter response(qname, qtype);

    if(processQuestion(*zones, dm, remote, response)) {
      if(response.dh.rcode)
        cout<<"\tSending response with rcode "<<(RCode)response.dh.rcode <<endl;

      SSendto(*sock, response.serialize(), remote);
    }
  }
}

/** \brief Looks up additional records

   This function is called to do additional processing on records we encountered 
   earlier that would benefit. This includes MX and NS records.

   Note that this function will only ook within 'bestzone', the best zone we had 
   for the original query. This means we will not look at potentially helpful 
   records in other zones. RFCs tell us that resolvers should not use/trust such
   out of zone data anyhow, but no RFC tells us we should not add that data.

   But we don't */
void addAdditional(const DNSNode* bestzone, const DNSName& zone, const vector<DNSName>& toresolve, DNSMessageWriter& response)
try
{
  for(auto addname : toresolve ) {
    if(!addname.makeRelative(zone)) {
      //      cout<<addname<<" is not within our zone, not doing glue"<<endl;
      continue;
    }
    DNSName wuh;
    auto addnode = bestzone->find(addname, wuh);
    if(!addnode || !addname.empty())  {
      continue;
    }
    for(auto& type : {DNSType::A, DNSType::AAAA}) {
      auto iter2 = addnode->rrsets.find(type);
      if(iter2 != addnode->rrsets.end()) {
        const auto& rrset = iter2->second;
        for(const auto& rr : rrset.contents) {
          response.putRR(DNSSection::Additional, wuh+zone, type, rrset.ttl, rr);
        }
      }
    }
  }  
}
catch(std::out_of_range& e) { // exceeded packet size
  cout<<"\tAdditional records would have overflowed the packet, stopped adding them, not truncating yet\n";
}

/*! \brief Writes a DNSMessageWriter to a TCP/IP socket, with length envelope

   helper function which encapsulates a DNS message within an 'envelope' 
   Note that it is highly recommended to send the envelope (with length)
   as a single call. This saves packets and works around implementation bugs
   over at resolvers */
static void writeTCPMessage(int sock, DNSMessageWriter& response)
{
  string ser="00"+response.serialize();
  uint16_t len = htons(ser.length()-2);
  ser[0] = *((char*)&len);
  ser[1] = *(((char*)&len) + 1);
  SWriten(sock, ser); 
}

/*! helper to read a 16 bit length in network order. Returns 0 on EOF */
uint16_t tcpGetLen(int sock)
{
  string message = SRead(sock, 2);
  if(message.empty())
    return 0;
  if(message.size() != 2) {
    throw std::runtime_error("Incomplete TCP/IP message");
  }
  uint16_t len;
  memcpy(&len, &message.at(1)-1, 2);
  return htons(len);
}

/*! spawned for each new TCP/IP client. In actual production this is not a good idea. */
void tcpClientThread(ComboAddress remote, int s, const DNSNode* zones)
{
  signal(SIGPIPE, SIG_IGN);
  Socket sock(s); // this will close for us
  cout<<"TCP Connection from "<<remote.toStringWithPort()<<endl;

  // multiple questions can come in over a single TCP/IP connection
  for(;;) {
    uint16_t len=tcpGetLen(sock);
    if(!len) // likely EOF
      return;
    if(len > 512) {
      cerr<<"Remote "<<remote.toStringWithPort()<<" sent question that was too big"<<endl;
      return;
    }
    
    if(len < sizeof(dnsheader)) {
      cerr<<"Dropping query from "<<remote.toStringWithPort()<<", too short"<<endl;
      return;
    }

    std::string message = SRead(sock, len);
    DNSMessageReader dm(message);

    DNSName name;
    DNSType type;
    dm.getQuestion(name, type);

    DNSMessageWriter response(name, type, 16384);

    if(type == DNSType::AXFR || type == DNSType::IXFR) {
      if(dm.dh.opcode || dm.dh.qr) {
        cerr<<"Dropping non-query AXFR from "<<remote.toStringWithPort()<<endl; // too weird
        return;
      }

      cout<<"AXFR requested for "<<name<<endl;

      response.dh.id = dm.dh.id;
      response.dh.ad = response.dh.ra = response.dh.aa = 0;
      response.dh.qr = 1;
      
      DNSName zone;
      // as in processQuestion, find the best zone
      auto fnd = zones->find(name, zone);
      if(!fnd || !fnd->zone || !name.empty() || !fnd->zone->rrsets.count(DNSType::SOA)) {
        cout<<"   This was not a zone, or zone had no SOA"<<endl;
        response.dh.rcode = (int)RCode::Refused;
        writeTCPMessage(sock, response);
        continue;
      }

      auto node = fnd->zone.get();

      // send SOA, which is how an AXFR must start
      response.putRR(DNSSection::Answer, zone, DNSType::SOA, node->rrsets[DNSType::SOA].ttl, node->rrsets[DNSType::SOA].contents[0]);

      writeTCPMessage(sock, response);
      response.clearRRs();

      // send all other records
      node->visit([&response,&sock,&name,&type,&zone](const DNSName& nname, const DNSNode* n) {
          for(const auto& p : n->rrsets) {
            if(p.first == DNSType::SOA) // skip the SOA, as it indicates end of AXFR
              continue;
            for(const auto& rr : p.second.contents) {
            retry:
              try {
                response.putRR(DNSSection::Answer, nname, p.first, p.second.ttl, rr);
              }
              catch(std::out_of_range& e) { // exceeded packet size 
                writeTCPMessage(sock, response);
                response.clearRRs();
                goto retry;
              }
            }
          }
        }, zone);

      writeTCPMessage(sock, response);
      response.clearRRs();

      // send SOA again
      response.putRR(DNSSection::Answer, zone, DNSType::SOA, node->rrsets[DNSType::SOA].ttl, node->rrsets[DNSType::SOA].contents[0]);

      writeTCPMessage(sock, response);
      return;
    }
    else {
      if(processQuestion(*zones, dm, remote, response)) {
        writeTCPMessage(sock, response);
      }
      else
        return;
    }
  }
}

//! connects to an authoritative server, retrieves a zone, returns it as a smart pointer
std::unique_ptr<DNSNode> retrieveZone(const ComboAddress& remote, const DNSName& zone)
{
  cout<<"Attempting to retrieve zone "<<zone<<" from "<<remote.toStringWithPort()<<endl;
  Socket tcp(remote.sin4.sin_family, SOCK_STREAM);

  SConnect(tcp, remote);

  DNSMessageWriter dmw(zone, DNSType::AXFR);
  writeTCPMessage(tcp, dmw);

  auto ret = std::make_unique<DNSNode>();
  
  int soaCount=0;
  uint32_t rrcount=0;
  for(;;) {
    uint16_t len = tcpGetLen(tcp);
    string message = SRead(tcp, len);
    
    DNSMessageReader dmr(message);

    if(dmr.dh.rcode != (int)RCode::Noerror) {
      cout<<"Got error "<<dmr.dh.rcode<<" from auth "<<remote.toStringWithPort()<< " when attempting to retrieve "<<zone<<endl;
      return std::unique_ptr<DNSNode>();
    }
    
    DNSName rrname;
    DNSType rrtype;
    DNSSection rrsection;
    uint32_t ttl;
    std::unique_ptr<RRGen> rr;

    while(dmr.getRR(rrsection, rrname, rrtype, ttl, rr)) {
      ++rrcount;
      if(!rrname.makeRelative(zone))
        continue;
      if(rrtype == DNSType::SOA && ++soaCount==2)
        goto done;

      ret->add(rrname)->addRRs(std::move(rr));
      ret->add(rrname)->rrsets[rrtype].ttl = ttl;
    }
  }
 done:
  cout<<"Done with AXFR of "<<zone<<" from "<<remote.toStringWithPort()<<", retrieved "<<rrcount<<" records"<<endl;
  return ret;
}

//! This is the main tdns function
int main(int argc, char** argv)
try
{
  if(argc != 2) {
    cerr<<"Syntax: tdns ipaddress:port"<<endl;
    return(EXIT_FAILURE);
  }
  cout<<"Hello and welcome to tdns, the teaching authoritative nameserver"<<endl;
  signal(SIGPIPE, SIG_IGN);
  
  ComboAddress local(argv[1], 53);

  Socket udplistener(local.sin4.sin_family, SOCK_DGRAM);
  SBind(udplistener, local);

  
  Socket tcplistener(local.sin4.sin_family, SOCK_STREAM);
  SSetsockopt(tcplistener, SOL_SOCKET, SO_REUSEPORT, 1);
  SBind(tcplistener, local);
  SListen(tcplistener, 10);

  DNSNode zones;
  cout<<"Loading & retrieving zone data"<<endl;
  loadZones(zones);

  cout<<"Listening on TCP & UDP on "<<local.toStringWithPort()<<endl;

  thread udpServer(udpThread, local, &udplistener, &zones);
  cout<<"Server is live"<<endl;
  for(;;) {
    ComboAddress remote(local); // this sets the family correctly
    int client = SAccept(tcplistener, remote);
    thread t(tcpClientThread, remote, client, &zones);
    t.detach();
  }
}
catch(std::exception& e)
{
  cerr<<"Fatal error: "<<e.what()<<endl;
  return EXIT_FAILURE;
}
