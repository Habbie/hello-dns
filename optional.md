                <meta charset="utf-8" emacsmode="-*- markdown -*-">
                            **A warm welcome to DNS**

# EDNS, Dynamic Updates, TSIG, DNAME, DNS Cookies & more
So far we've focussed on the simplest possible form of DNS that is
interoperable with today's internet. Over the past 3 decades however, a lot
has been added to DNS however.

In this document, we will cover:

 * EDNS: Extra fields carried in the additional section of a DNS message,
   including arbitrary options. The main use of EDNS today is specifying a
   larger supported UDP packet size, indicating DNSSEC support and carrying
   Client Subnet information. Defined in [RFC
   2671](https://tools.ietf.org/html/rfc2671), which also specifies several
   deprecated innovations, like additional label types.
 * Dynamic Updates: Transmitting changes to zones to master servers. Mostly
   used by DHCP servers to publish names of hosts. Defined in [RFC
   2136](https://tools.ietf.org/html/rfc2136)
 * TSIG: Secret Key Transaction Authentication for DNS. Ways to sign DNS
   messages or a list of DNS messages with a secret key. Used to authenticate
   AXFR requests and to guarantee zone integrity during AXFR. Defined in
   [RFC 2845](https://tools.ietf.org/html/rfc2136).
 * EDNS Client Subnet:
 * DNAME:  ...
 * DNS Cookies:  ...

Resolvers can safely ignore dynamic updates and TSIG as they are not
applicable to caches. 

EDNS is very much an enabling technology and it can't really be regarded as
optional anymore.  It enables DNSSEC, DNS Cookies, EDNS Client Subnet as
well as larger UDP packets.



...

<!-- Markdeep: --><style class="fallback">body{visibility:hidden;white-space:pre;font-family:monospace}</style><script src="ext/markdeep.min.js"></script><script>window.alreadyProcessedMarkdeep||(document.body.style.visibility="visible")</script>
