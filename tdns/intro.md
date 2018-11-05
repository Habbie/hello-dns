                <meta charset="utf-8" emacsmode="-*- markdown -*-">
                            **A warm welcome to DNS**
<!--<link rel="stylesheet" href="https://casual-effects.com/markdeep/latest/apidoc.css?">-->
Note: this page is part of the
'[hello-dns](https://powerdns.org/hello-dns/)' documentation effort.


# teaching DNS
Welcome to tdns, a 'from scratch' teaching authoritative server,
implementing all of [basic DNS](https://powerdns.org/hello-dns/basic.md.html) in
~~1400~~ ~~1500~~ 1600 lines of code.  Code is
[here](https://github.com/ahupowerdns/hello-dns/tree/master/tdns).  To
compile, see [here](https://powerdns.org/hello-dns/tdns/README.md.html).

`tdns` is part of the '[hello-dns](https://powerdns.org/hello-dns)' effort
to provide a good entry point into DNS.  This project was started after an
[IETF
presentation](https://blog.powerdns.com/2018/03/22/the-dns-camel-or-the-rise-in-dns-complexit/)
by Bert Hubert of PowerDNS in which it was discovered the DNS standards have
now grown to 2500 pages, and we can no longer expect new entrants to the
field to read all that.  After 30 years, DNS deserves a fresh explanation
and [hello-dns](https://powerdns.org/hello-dns) is it.

Even though the 'hello-dns' documents describe how basic DNS works, and how
an authoritative server should function, nothing quite says how to do things
like actual running code.  `tdns` is small enough to read in one sitting and
shows how DNS packets are parsed and generated.  `tdns` is currently written
in C++ 2014, and is MIT licensed.  Reimplementations in other languages are
highly welcome, as these may be more accessible to programmers not fluent in
C++.

The goals of tdns are:

 * Showing the DNS algorithms 'in code'
 * Protocol correctness, except where the protocol needs updating
 * Suitable for educational purposes
 * Display best practices, both in DNS and security
 * **Be a living warning for how hard it is to write a nameserver correctly**

The target audience of `tdns` is anyone pondering or actually implementing
an authoritative nameserver or a stub resolver. 

Non-goals are:

 * Performance (beyond 100kqps)
 * Implementing more features (unless very educational)
 * DNSSEC (for now)

Besides being 'teachable', `tdns` could actually be useful if you need a
4-file dependency-light library that can look up DNS things for you.

## Features
Despite being very small, `tdns` covers a lot of ground, implementing all
parts of 'basic DNS' (as defined by the 'hello-dns' pages):

 * A, AAAA, CNAME, MX, NS, PTR, SOA, NAPTR, SRV, TXT, "Unknown"
 * UDP & TCP
 * Empty non-terminals
 * AXFR (incoming and outgoing)
 * Wildcards
 * Delegations
 * Glue records
 * Truncation
 * Compression / Decompression

As a bonus:
 * EDNS (buffer size, flags, extended RCode, no options)

What this means is that with `tdns`, you can actually host your domain name,
or even slave it from another master server.

# What makes `tdns` different?
There is no shortage of nameservers.  In fact, there is an embarrassing
richness of very good ones out there already.  So why bother?  The biggest
problem with DNS today is not the great open source implementations.  It is
the absolutely dreadful stuff we find in appliances, modems, load balancers,
CDNs, CPEs and routers.

The DNS community frequently laments how much work our resolvers have to do
to work around broken implementations.  In fact, we are so fed up with this
that ISC, NLNetLabs, CZNIC and PowerDNS together have announced that
starting 2019 [we will no longer work around certain classes of
breakage](https://blog.powerdns.com/2018/03/22/removing-edns-workarounds/).

In addition, with the advent of RFCs like [RFC
8020](https://tools.ietf.org/html/rfc8020) sending incorrect answers will
start wiping out your domain name.

However, we can't put the all (or even most) of the blame for disappointing
quality on the embedded and closed source implementation community.  It was
indeed frighteningly hard to out find how to write a correct authoritative
nameserver.

Existing open source nameservers are all highly optimized and/or have
decades of operational expertise (and trauma) worked into their code.  What
this means is that actually reading that code to learn about DNS is not
easy.  Achieving millions of queries per second does not leave the luxury of
keeping code in an accessible or educational state.

`tdns` addresses this gap by being a 1500 line long server that is well
documented and commented. Any competent programmer can read the entire
source code a few hours and observe how things really should be done.

## That sounds like hubris
In a sense, this is by design. `tdns` attempts to do everything not only
correctly but also in a best practice fashion. It wants to be an excellent
nameserver that is fully compliant to all relevant standards and lore.

It is hoped that the DNS community will rally to this cause and pore over
the `tdns` source code to spot everything that could potentially be wrong or
could be done better. 

In other words, where `tdns` is currently not right, we hope that with
sufficient attention it soon will be. Bikeshed away!

# How did all those features fit in ~1500 lines?
Key to a good DNS implementation is having a faithful DNS storage model,
with the correct kind of objects in them.

Over the decades, many many nameservers have started out with an incorrect
storage model, leading to pain later on with empty non-terminals, case
sensitivity, setting the 'AA' bit on glue (or not) and eventually DNSSEC
ordering problems.

When storing DNS as a tree, as described in [RFC
1034](https://tools.ietf.org/html/rfc1034), a lot of things go right
"automatically".  When DNS Names are a fundamental type composed out of DNS
Labels with the correct case-insensitive equivalence and identity rules,
lots of problems can never happen.  Tons of conversion mechanics also does
not need to be typed in (or forgotten in some places).

The core of `tdns` therefore is the tree of nodes as intended in 1034,
containing DNS native objects like `DNSLabel`s and `DNSName`s. These get
escaping, case sensitivity and binary correctness right 'automatically'.

## The DNS Tree
Of specific note is the DNS Tree as described in RFC 1034.  Because DNS is
never shown to us as a tree, and in fact is usually presented as a flat
'zone file', it is easy to ignore the tree-like nature of DNS.

*************************************************************************************************
*                                                                                               *
*                                   .---.                                                       *
*   1                    +---------+     +--------+                                             *
*                       /           '-+-'          \                                            *
*                      /              |             \                                           *
*                   .-+-.           .-+-.          .-+-.                                        *
*   2              + ietf+         | ietg+        | ... +                                       *
*                   '-+-'           '-+-'          '---'                                        *
*                    / \              |                                                         *
*                   /   \             |                                                         *
*               .--+.    +---.      .-+-.                                                       *
*   3          + ord |  | fra +    | ... +                                                      *  
*               '-+-'    '-+-'      '---'                                                       *
*                 |        |                                                                    *
*               .-+-.    .-+-.                                                                  *                   
*   4          + ns1 |  | ns2 +                                                                 *                   
*               '-+-'    '---'                                                                  *                   
*                                                                                               *
*************************************************************************************************
[Figure [diagram]: DNS Tree containing data nodes `ns1.ord.ietf.org`, `ns2.fra.ietf.org`, `ietf.org` and `org` ] 

To find nodes within the DNS tree, start matching from the top. This zone is
called `org`, so at depth 4 we can find `ns1.ord.ietf.org`, after first
matching nodes called `ietf`, `ord` and finally `ns1`.

If this tree is embraced, it turns out that a nameserver can use the very
same tree implementation three times:

1. To find the most specific zone to be serving answers from
2. To traverse that zone to find the correct answers or delegation
3. To implement DNS name compression

By reusing the same logic three times, there is less code to type and less
to explain.

Interestingly, when asked (via Paul Vixie), Paul Mockapetris indicated he
was surprised that the DNS Tree could in fact be reused for DNS name
compression. This 2018 discovery in a 1985 protocol turns out to work
surprisingly well!

## Putting the tricky bits at a fundamental level
DNS names look surprisingly like text strings, but they very much are not. 
For starters, DNS is case insensitive in its own special way, and such rules
must be obeyed for DNSSEC to ever work.

Furthermore, despite appearances, DNS is 8-bit safe. This means that
individual DNS labels (usually separated by dots) can contain embedded 0
characters, but also actual dots themselves.

A lot of code 'up the stack' can be simplified by having basic types that
are fully DNS native, like DNS Labels which are case insensitive, stored in
binary and length limited by themselves.

Code that uses "strings" for DNS may struggle to recognize (in all places!)
that `www.PowerDNS.COM`, `www.powerdns.com`, `www.p\079werdns.com.` and
`www.p\111werdns.com` are all equivalent, but that `www\046powerdns.com` is
not.

## The inner symmetry of DNS
In what is likely not an accident, all known DNS record types are laid out
exactly the same in the packet as in the zone file. So in other words the
well known SOA record looks like this on our screen:

```
ripe.net. SOA	manus.authdns.ripe.net. dns.ripe.net. 1523965801 3600 600 864000 300
#                      mname               rname         serial  ref  ret  exp   min
```

And in the packet, this very same record looks like this:

***********************************************************
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+    *
*    /                     MNAME                     /    *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+    *
*    /                     RNAME                     /    *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+    *
*    |                    SERIAL                     |    *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+    *
*    |                    REFRESH                    |    *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+    *
*    |                     RETRY                     |    *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+    *
*    |                    EXPIRE                     |    *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+    *
*    |                    MINIMUM                    |    *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+    *
***********************************************************

DNS Records need to be: 1) parsed from a message 2) serialized to a message
3) parsed from zone file format 4) emitted in zone file format.

It turns out these four conversions exhibit complete symmetry for all
regular DNS resource types.

This means we can define one conversion 'operator':

```
void SOAGen::doConv(auto& x) 
{
  x.xfrName(d_mname);     x.xfrName(d_rname);
  x.xfrUInt32(d_serial);  x.xfrUInt32(d_refresh);
  x.xfrUInt32(d_retry);   x.xfrUInt32(d_expire);
  x.xfrUInt32(d_minimum);
}
```

And actually reuse that for all four cases:

```
SOAGen::SOAGen(DNSMessageReader& dmr)         { doConv(dmr); }
void SOAGen::toMessage(DNSMessageWriter& dmw) { doConv(dmw); }
SOAGen::SOAGen(StringReader& sr)              { doConv(sr);  }

std::string SOAGen::toString() 
{
  StringBuilder sb;
  doConv(sb);
  return sb.d_string;
}

```

Exploiting this symmetry does not only save a lot of typing, it also saves
us from potential inconsistencies.

# Next steps
It is the hope that `tdns` is educational and will lead to a better
understanding of DNS. `tdns` is not yet done and we anxiously await comments
from the rest of the DNS community, as well as reimplementations in other
languages (like Go and Rust).

`tdns` is described more fully in its
[README](https://powerdns.org/hello-dns/tdns/README.md.html).  In addition,
the code is richly commented with Doxygen annotations, which can be seen
[here](https://powerdns.org/hello-dns/tdns/codedocs/html/).  The code itself
meanwhile is on [GitHub](https://github.com/ahuPowerDNS/hello-dns)


<script>
window.markdeepOptions={};
window.markdeepOptions.tocStyle = "long";
</script>
<!-- Markdeep: --><style class="fallback">body{visibility:hidden;white-space:pre;font-family:monospace}</style><script src="../ext/markdeep.min.js"></script><script>window.alreadyProcessedMarkdeep||(document.body.style.visibility="visible")</script>
