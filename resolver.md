                <meta charset="utf-8" emacsmode="-*- markdown -*-">
                            **A warm welcome to DNS**

Note: this page is part of the
'[hello-dns](https://powerdns.org/hello-dns/)' documentation effort.

# Resolver
Writing a modern resolver is the hardest part of DNS. A fully standards
compliant DNS resolver is not a resolver that can be used in practice.

In reality, resolvers are expected to process malformed queries coming from
clients (stub-resolvers).  Furthermore, many authoritative servers respond
incorrectly to modern DNS queries.  Zones are frequently misconfigured on
authoritative servers but still expected to work correctly.

Meanwhile, operators desire top performance, with individual CPU cores
expected to satisfy the DNS needs of hundreds of thousands of users.

To top this off, a modern DNS resolver will have to validate DNSSEC
correctly. This may be among the hardest challenges of any widely used
Internet protocol.

Excellent resolvers that are freely available and open source include:

 * [BIND 9](https://www.isc.org/downloads/bind/)
 * [Knot resolver](https://www.knot-resolver.cz/)
 * [Unbound](https://www.unbound.net/)
 * [PowerDNS Recursor](https://www.powerdns.com/recursor.html)

So in short, before attempting to write a DNS resolver, ponder if you really
need to. 

As part of this project a [`teaching resolver`](tdns/tres.md.html) (or `tres`) is
provided.  Understanding `tres` and its source code is easier after reading
this page.

# Resolver algorithm
## In-zone nameservers, no CNAMEs
There are various strategies to resolve names. The most basic form is to
send the same query for the full query name to a series of ever more
specific nameservers.

So, to resolve `www.powerdns.com`, send a query for that name to one of the
26 root-server IP address.  The root-servers will return a non-authoritative
answer ('aa=0') with the NS records of the `COM` servers, and helpfully also
provide IP addresses for those servers.

The resolver can believe these NS records and even the 'glue' - we trust the
root-servers to serve the root and everything under it.

Based on the IP addresses provided in the glue, the same `www.powerdns.com`
query can now be sent to one of the `COM` servers, which in turn replies
with another non-authoritative answer that does however list the names & IP
addresses for the `powerdns.com` zones. 

Finally, the `www.powerdns.com` query can get sent to one of the
`powerdns.com` nameserver IP addresses, and finally an answer arrives.

This is the simplest case where resolution can proceed iteratively - each
response carries full information where the next query can get sent.

## Out-of-zone nameservers
To resolve `www.powerdns.org`, the situation is more difficult. The
root-servers again provide the first help by telling us about the `ORG`
nameservers & their IP addresses. 

When we then ask the `ORG` nameservers for `www.powerdns.org`, these return
with a set of nameservers for `powerdns.org`.. but no IP addresses. This is
because the `powerdns.org` nameservers do not reside in the `ORG` zone.

This means that the same algorithm we are using to resolve
`www.powerdns.org` now needs to be started in parallel for finding the IP
address of `ns1.ds9a.nl`. Luckily, resolving `ns1.ds9a.nl` proceeds as
described in the previous section, without the need to resolve further
nameserver names.

Once we have an IP address for a `powerdns.org` nameserver, we can ask it
about `www.powerdns.org`.

## CNAMEs
CNAMEs complicate this process slightly but not fundamentally. A CNAME
redirects our query to a new name. This means that once a CNAME is hit, the
initial algorithm terminates, and gets restarted for the new CNAME target.

Frequently, a CNAME points to a name that is also within the same zone, for
example `www.powerdns.org. IN CNAME powerdns.org`. Authoritative servers
then typically also include the requested type for `powerdns.org` in the
same DNS response. As an optimization, a resolver can use this CNAME record
and terminate the algorithm.

# Security
At every point a resolver must be vigilant to not store data coming from an
authoritative server that can not be trusted to provide that data.

In addition, if a cache is used, care must be taken that an authoritative
server must not be allowed to 'extend its own authority' infinitely. This is
a problem when a domain gets assigned new nameservers, but a resolver
'sticks' to the old one.

There are many many other security pitfalls within a resolver, which is why
we recommend not writing another one unless this is really really necessary
somehow.


<!-- Markdeep: --><style class="fallback">body{visibility:hidden;white-space:pre;font-family:monospace}</style><script src="ext/markdeep.min.js"></script><script>window.alreadyProcessedMarkdeep||(document.body.style.visibility="visible")</script>
