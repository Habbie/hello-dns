                <meta charset="utf-8" emacsmode="-*- markdown -*-">
                            **A warm welcome to DNS**

# Hello, and welcome to DNS!

This series of documents attempts to provide a correct introduction to the
Domain Name System as of 2018.  The original RFCs remain the authoritative
source of normative text, but this document tries to make this venerable
protocol more accessible, while maintaining full alignment with all relevant
and useful RFCs.

This effort is developed cooperatively on GitHub, the repository can be
found [https://github.com/ahupowerdns/hello-dns/](here) and help is highly
welcome!  Feedback can also be sent to bert.hubert@powerdns.com or
[@PowerDNS_Bert](https://twitter.com/PowerDNS_Bert).

Contributors so far include: Michał Kępień, Jan-Piet Mens, Andrew Babichev,
Jacob Hoffman-Andrews, Peter van Dijk, Nathan Froyd, Gene McCulley,
Charles-Henri Bruyand, jose nazario, Warren Kumari, Patrick Cloke, and
Andrew Tunnell-Jones.  Thanks!

Although we start from relatively basic principles, the reader is expected
to know what IP addresses are, what a (stub) resolver is and what an
authoritative server is supposed to do.  When in doubt: authoritative
servers 'host' DNS data, 'resolvers' look up things over at authoritative
servers and clients run 'stub resolvers' to look things up over at
resolvers.  This document is aimed at developers, but may also be of aid for
administrators.

DNS was originally written down in August 1979 in '[IEN
116](https://www.rfc-editor.org/ien/ien116.txt)', part of a parallel
series of documents describing the Internet.  IEN 116-era DNS is not
compatible with today's DNS.  In 1983, RFC 882 and 883 were released,
describing a version of the DNS very similar but not quite interoperable
with the one we have today.

DNS attained its modern form in 1987 when RFC 1034 and 1035 were published.
Although much of 1034/1035 remains valid, these standards are not that easy
to read because they were written in a very different time. There are 100s
of pages of updates that can only be found in later documents.

The main goal of this effort is not to contradict the DNS RFCs but to
provide an easier entrypoint into understanding the Domain Name System.

If you will, the goal is to be a mini "[TCP/IP
Illustrated](https://en.wikipedia.org/wiki/TCP/IP_Illustrated)" of DNS. For
more about the philosophy of these documents, and how to contribute, please read
[meta.md](meta.md.html).
Your help & insights are highly welcome!

I want to thank Ólafur Guðmundsson and Job Snijders for their input and
enthusiasm for improving the state of DNS.

## Layout
The content is spread out over several documents:

 * [The core of DNS](basic.md.html)
 * [Relevant to stub resolvers and applications](stub.md.html)
 * [Relevant to authoritative servers](auth.md.html)
 * [Relevant to resolvers](resolver.md.html)
 * [tdns: a 'from scratch' DNS library](tdns/README.md.html)
   * [tauth: a minimal but feature complete authoritative server](tdns/tauth.md.html)
   * [tres: a minimal but feature complete DNS resolver](tdns/tres.md.html)
   * [C API: a C library for doing DNS queries](tdns/c-api.md.html)
 * Optional elements: [EDNS, TSIG, Dynamic Updates, DNAME, DNS Cookies](optional.md.html)
 * [Privacy related](privacy.md.html): QName minimization, DNS-over-TLS, DNS-over-HTTPS, EDNS Padding
 * [DNSSEC](dnssec.md.html)
 * [non-IETF standards](non-ietf.md.html): RRL and RPZ
 * [Rare parts of DNS](rare.md.html) - not obsolete, but not frequently encountered in production

We start off with a general introduction of DNS basics: what is a resource
record, what is an RRSET, what is a zone, what is a zone-cut, how are packets
laid out. This part is required reading for anyone ever wanting to query a
nameserver or emit a valid response.

We then specialize into what applications can expect when they send
questions to a resolver, or what a stub resolver can expect.

The next part is about what an authoritative server is supposed to do. On
top of this, we describe in slightly less detail how a resolver could
operate. Finally, there is a section on optional elements like EDNS, TSIG,
Dynamic Updates and DNSSEC.

RFCs, especially earlier ones, tend to describe servers that perform both
authoritative and resolver functions. This turns out to make both code and
troubleshooting harder. Therefore, in these documents, the authoritative and
caching functions are described separately.

Next up: [DNS Basics](basic.md.html).

<!-- Markdeep: --><style class="fallback">body{visibility:hidden;white-space:pre;font-family:monospace}</style><script src="ext/markdeep.min.js"></script><script>window.alreadyProcessedMarkdeep||(document.body.style.visibility="visible")</script>
