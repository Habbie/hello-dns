#include "tdnssec.hh"
#include <iostream>

using namespace std;

void addDSToDelegation(DNSMessageWriter& response, const DNSNode* passedZonecut, const DNSName& zonename)
{
  auto iter = passedZonecut->rrsets.find(DNSType::DS);
  if( iter != passedZonecut->rrsets.end()) {
    cout<<"\tDNSSEC OK query delegation, found a DS at "<<(passedZonecut->getName() + zonename)<<endl;
    const auto& rrset = iter->second;
    response.putRR(DNSSection::Authority, passedZonecut->getName() + zonename, rrset.ttl, rrset.contents[0]);
    cout<<"\tAdding signatures for DS (have "<<rrset.signatures.size()<<")"<<endl;
    for(const auto& sig : rrset.signatures) {
      response.putRR(DNSSection::Authority, passedZonecut->getName()+zonename, rrset.ttl, sig);
    }
  }
}

void addNoErrorDNSSEC(DNSMessageWriter& response, const DNSNode* node, const RRSet& rrset, const DNSName& zonename)
{
  cout<<"\tAdding signatures for SOA (have "<<rrset.signatures.size()<<")"<<endl;
  for(const auto& sig : rrset.signatures) {
    response.putRR(DNSSection::Authority, zonename, rrset.ttl, sig);
  }
  
  if(node->rrsets.count(DNSType::NSEC)) {
    const auto& nsecrr = *node->rrsets.find(DNSType::NSEC);
    cout<<"\tAdding NSEC & signatures (have "<<nsecrr.second.signatures.size()<<")"<<endl;
    
    response.putRR(DNSSection::Authority, node->getName()+zonename, rrset.ttl, nsecrr.second.contents[0]);
    for(const auto& sig : nsecrr.second.signatures) {
      response.putRR(DNSSection::Authority, node->getName()+zonename, rrset.ttl, sig);
    }
  }
}

void addSignatures(DNSMessageWriter& response, const RRSet& rrset, const DNSName& lastnode, const DNSNode* passedWcard, const DNSName& zonename)
{
  for(const auto& sig : rrset.signatures) {
    response.putRR(DNSSection::Answer, lastnode+zonename, rrset.ttl, sig);
  }
            
  if(passedWcard) {
    cout<<"\tAdding the wildcard NSEC at "<<passedWcard->getName()<<endl;
    auto nseciter = passedWcard->rrsets.find(DNSType::NSEC);
    if(nseciter != passedWcard->rrsets.end()) {
      response.putRR(DNSSection::Authority, passedWcard->getName()+zonename, nseciter->second.ttl, nseciter->second.contents[0]);
      
      for(const auto& sig : nseciter->second.signatures) {
        response.putRR(DNSSection::Authority, passedWcard->getName()+zonename, nseciter->second.ttl, sig);
      }
    }
  }
}

void addNXDOMAINDNSSEC(DNSMessageWriter& response, const RRSet& rrset, const DNSName& qname, const DNSNode* node, const DNSNode* passedZonecut, const DNSName& zonename)
{
  for(const auto& sig : rrset.signatures) {
    response.putRR(DNSSection::Authority, passedZonecut->getName()+zonename, rrset.ttl, sig);
  }
        
  cout<<"\tAt the last node, we have "<< node->children.size()<< " children\n";
  cout<<"\tLast node left "<<qname.back()<<endl;
  
  auto place = node->children.lower_bound(qname.back());
  cout<<"\tplace: "<<place->getName()<<endl;
  
  auto prev = place->prev();
  for(;;) {
    if(!prev) {
      cout<<"\tNSEC should maybe loop? there is no previous???"<<endl;
    }
    cout<<"\tNSEC should start at "<<prev->getName()<<endl;
    if(!prev->rrsets.count(DNSType::NSEC)) {
      cout<<"\tCould not find NSEC record at "<<prev->getName()<<", it is an ENT, going back further"<<endl;
    }
    break;
  }
  const auto& nsecrr = prev->rrsets.find(DNSType::NSEC);
  cout<<"\tAdding NSEC & signatures (have "<<nsecrr->second.signatures.size()<<")"<<endl;
  response.putRR(DNSSection::Authority, prev->getName()+zonename, nsecrr->second.ttl, nsecrr->second.contents[0]);
  for(const auto& sig : nsecrr->second.signatures) {
    response.putRR(DNSSection::Authority, prev->getName()+zonename, nsecrr->second.ttl, sig);
  }
}
