#ifndef TDNS_TDNS_H
#define TDNS_TDNS_H

#ifdef __cplusplus
extern "C" {
#endif


struct TDNSIPAddresses
{
  struct sockaddr_storage** addresses;
  unsigned int ttl;
  void* __handle;
};


int TDNSLookupIPs(const char* name, int timeoutMsec, int lookupIPv4, int lookupIPv6,   struct TDNSIPAddresses** ret);
void freeTDNSIPAddresses(struct TDNSIPAddresses*);

#ifdef __cplusplus
}
#endif

  
#endif
