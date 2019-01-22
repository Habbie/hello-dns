#include "tdns-c.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char **argv)
{
  struct TDNSContext* tdns = TDNSMakeContext("");
  if(!tdns) {
    fprintf(stderr, "Unable to initialize tdns\n");
    return EXIT_FAILURE;
  }
  struct TDNSIPAddresses* ips;
  int err = TDNSLookupIPs(tdns, "www.nosuchdomain234234.nl", 1000, 1, 1, &ips);
  if(err) {
    fprintf(stderr, "Error looking up domain name: %s\n", TDNSErrorMessage(err));
  }

  err = TDNSLookupIPs(tdns, "www.dns-oarc.net", 1000, 1, 1, &ips);
  if(err) {
    fprintf(stderr, "Error looking up domain name: %s\n", TDNSErrorMessage(err));
    return EXIT_FAILURE;
  }

  for(int n = 0; ips->addresses[n]; ++n) {
    struct sockaddr_storage* res = ips->addresses[n];
    char ip[INET6_ADDRSTRLEN];
    if(res->ss_family == AF_INET)
      inet_ntop(res->ss_family, &((struct sockaddr_in*)res)->sin_addr, ip, INET6_ADDRSTRLEN);
    else
      inet_ntop(res->ss_family, &((struct sockaddr_in6*)res)->sin6_addr, ip, INET6_ADDRSTRLEN);
    printf("IP address: %s\n", ip);
  }
  freeTDNSIPAddresses(ips);


  struct TDNSMXs* mxs;
  err = TDNSLookupMXs(tdns, "isc.org", 1000, &mxs);
  if(err) {
    fprintf(stderr, "Error looking up domain name: %s\n", TDNSErrorMessage(err));
    return EXIT_FAILURE;
  }

  for(int n = 0; mxs->mxs[n]; ++n) {
    struct TDNSMX* res = mxs->mxs[n];
    printf("MX %d %s\n", res->priority, res->name);
  }
  freeTDNSMXs(mxs);


  struct TDNSTXTs* txts;
  err = TDNSLookupTXTs(tdns, "nl", 1000, &txts);
  if(err) {
    fprintf(stderr, "Error looking up domain name: %s\n", TDNSErrorMessage(err));
    return EXIT_FAILURE;
  }

  for(int n = 0; txts->txts[n]; ++n) {
    struct TDNSTXT* res = txts->txts[n];
    printf("TXT %s\n", res->content);
  }
  freeTDNSTXTs(txts);

  freeTDNSContext(tdns);
}
