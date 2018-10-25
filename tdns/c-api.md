                <meta charset="utf-8" emacsmode="-*- markdown -*-">
                            **A warm welcome to DNS**
<!--<link rel="stylesheet" href="https://casual-effects.com/markdeep/latest/apidoc.css?">-->
Note: this page is part of the
'[hello-dns](https://powerdns.org/hello-dns/)' documentation effort.

# teaching DNS: C library
Based on `tdns`, a C++ project, a C API is also available.

This is meant as an easy gateway for C users. The tdns C-API is aimed to
resolve simple queries, without having to import all the glory that is
[`getdns`](https://getdnsapi.net/). For any advanced work, including
asynchronous queries, encryption and cryptography, please use getdns.

# Basics
To start, initialize a `TDNSContext` object like this:

```
  struct TDNSContext* tdns = TDNSMakeContext("");
  if(!tdns) {
    fprintf(stderr, "Unable to initialize tdns\n");
    return EXIT_FAILURE;
  }
```
This will lift resolver addresses from the system default. To use a specific
resolver, pass its address to `TDNSMakeContext`.

A context needs to be freed by calling `freeTDNSContext`.

# Queries

Once a context is acquired, it can be used to perform queries:

```
  struct TDNSIPAddresses* ips;
  err = TDNSLookupIPs(tdns, "www.dns-oarc.net", 1000, 1, 1, &ips);
  if(err) {
    fprintf(stderr, "Error looking up domain name: %s\n", TDNSErrorMessage(err));
    return EXIT_FAILURE;
  }
```

This call specifies a timeout of 1000 milliseconds, and requests IPv4 and
IPv6 addresses.

An error is indicated by a non-zero return value, in which case the error is
available through `TDNSErrorMessage`.

Actual IP addresses, IPv4 or IPv6, are returned as `struct sockaddr_storage` 
pointers in `TDNSIpAddressess::addresses`:

```
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
```
The sequence is terminated by a 0 pointer in `addressses`. Note that the
answer must also be freed with `freeTDNSIPAddresses`.

## MX Records
Looking up MX records proceeds among similar lines:

```
  struct TDNSMXs* mxs;
  err = TDNSLookupMXs(tdns, "isc.org", 1000, &mxs);

  (...)

  for(int n = 0; mxs->mxs[n]; ++n) {
    struct TDNSMX* res = mxs->mxs[n];
    printf("MX %d %s\n", res->priority, res->name);
  }
  freeTDNSMXs(mxs);
```

## TXT Records
And TXT records:

```
  struct TDNSTXTs* txts;
  err = TDNSLookupTXTs(tdns, "nl", 1000, &txts);

  (...)

  for(int n = 0; txts->txts[n]; ++n) {
    struct TDNSTXT* res = txts->txts[n];
    printf("TXT %s\n", res->content);
  }
  freeTDNSTXTs(txts);
```

# Full code
The full code of these examples can be found on
[GitHub](https://github.com/ahupowerdns/hello-dns/blob/master/tdns/tdns-c-test.c).

<script>
window.markdeepOptions={};
window.markdeepOptions.tocStyle = "long";
</script>
<!-- Markdeep: --><style class="fallback">body{visibility:hidden;white-space:pre;font-family:monospace}</style><script src="../ext/markdeep.min.js"></script><script>window.alreadyProcessedMarkdeep||(document.body.style.visibility="visible")</script>
