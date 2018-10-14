#ifndef TDNS_TDNS_H
#define TDNS_TDNS_H

#ifdef __cplusplus
extern "C" {
#endif

const char* TDNSErrorMessage(int err);

struct TDNSIPAddresses
{
  struct sockaddr_storage** addresses;
  unsigned int ttl;
  void* __handle;
};

struct TDNSMXRecords
{
  struct sockaddr_storage** addresses;
  unsigned int ttl;
  void* __handle;
};

struct TDNSTXTRecords
{
  struct sockaddr_storage** addresses;
  unsigned int ttl;
  void* __handle;
};

struct TDNSMX
{
  const char* name;
  unsigned int priority;
};
  
struct TDNSMXs
{
  struct TDNSMX** mxs;
  unsigned int ttl;
  void *__handle;
};
  

int TDNSLookupIPs(const char* name, int timeoutMsec, int lookupIPv4, int lookupIPv6,   struct TDNSIPAddresses** ret);
void freeTDNSIPAddresses(struct TDNSIPAddresses*);

int TDNSLookupMXs(const char* name, int timeoutMsec, struct TDNSMXs** ret);
void freeTDNSMXs(struct TDNSMXs*);


struct TDNSTXT
{
  const char* content;
};
  
struct TDNSTXTs
{
  struct TDNSTXT** txts;
  unsigned int ttl;
  void *__handle;
};

int TDNSLookupTXTs(const char* name, int timeoutMsec, struct TDNSTXTs** ret);
void freeTDNSTXTs(struct TDNSTXTs*);

  
#ifdef __cplusplus
}
#endif

  
#endif
