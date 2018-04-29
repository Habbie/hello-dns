#pragma once
#include "dnsmessages.hh"
#include "dns-storage.hh"

void addDSToDelegation(DNSMessageWriter& response, const DNSNode* passedZonecut, const DNSName& zonename);
void addNoErrorDNSSEC(DNSMessageWriter& response, const DNSNode* node, const RRSet& rrset, const DNSName& zonename);
void addSignatures(DNSMessageWriter& response, const RRSet& rrset, const DNSName& lastnode, const DNSNode* passedWcard, const DNSName& zonename);
void addNXDOMAINDNSSEC(DNSMessageWriter& response, const RRSet& rrset, const DNSName& qname, const DNSNode* node, const DNSNode* passedZonecut, const DNSName& zonename);

