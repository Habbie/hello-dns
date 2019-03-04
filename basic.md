                <meta charset="utf-8" emacsmode="-*- markdown -*-">
                            **A warm welcome to DNS**
<!-- <link rel="stylesheet" href="https://casual-effects.com/markdeep/latest/apidoc.css?">
-->

Note: this page is part of the
'[hello-dns](https://powerdns.org/hello-dns/)' documentation effort.

In this section we will initially ignore optional extensions that were added
to DNS later, specifically EDNS and DNSSEC.

This file corresponds roughly to the fundamental parts of RFCs 1034, 1035,
2181, 2308, 3596, 4343, 5452, 6604, 7766 and 8020.

**This page, which describes DNS basics, absolutely must be read from
beginning to end in order for the rest of the documents (or DNS) to make
sense.**

# DNS Basics

DNS is mostly used to serve IP addresses and mailserver details, but it can
contain arbitrary data.  DNS is all about names.  Every name can have data
of several *types*.  The most well known externally useful types are *A* for
IPv4 addresses, *AAAA* for IPv6 addresses and *MX* for mailserver details.
DNS also has types that have meaning for its own use, like *NS*, *CNAME* and
*SOA*.

When we ask a DNS question we call this a *query*. We call the reply the
*response*.  These queries and responses are contained in DNS messages. When
UDP is used, the message is also the packet. Note that [TCP support is
mandatory](https://tools.ietf.org/html/rfc7766.txt) for DNS in 2018.

A DNS message has:

 * A header
 * A query name and query type
 * An answer section
 * An authority section
 * An additional section

In basic DNS, query messages should have empty answer, authority and
additional sections.

The header has the following fields that are useful for queries and
responses:

 * ID: a 16 bit identifier used as part of the process of matching queries to responses
 * QR: Set to 0 to identify a message as a query, 1 for a response
 * OPCODE: 0 for a standard query, other opcodes also exist
 * RD: Set to indicate that this question wants *recursion*

Relevant for responses:
 * AA: This response has Authoritative Answers
 * RA: Recursive service was available
 * TC: Not all the required parts of the response fit in the UDP message
 * RCODE: Result code. 0 is ok, 2 is SERVFAIL, 3 is NXDOMAIN.

DNS queries are mostly sent over UDP, and UDP packets can easily be spoofed.
To recognize the authentic response to a query it is important that the ID
field is random or at least unpredictable.  This is however not enough
protection, so the source port of a UDP DNS query [must also be
unpredictable](https://tools.ietf.org/html/rfc5452#section-9).

DNS messages can also be sent over TCP/IP. Because TCP is not a datagram
oriented protocol, each DNS message in TCP/IP is preceded by a 16 bit
network endian length field.

DNS servers must listen on both UDP and TCP, port 53.

The header of a question for the IPv6 address of www.ietf.org looks like
this:


***************************************************************
*                                    1  1  1  1  1  1
*      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*    |                      ID = random 16 bits      |
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
*    |0 |      0    |0 | 0| 0|0 |   0    |     0     |
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*    |                    QDCOUNT = 1                |
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*    |                    ANCOUNT = 0                |
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*    |                    NSCOUNT = 0                |
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*    |                    ARCOUNT = 0                |
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*
***************************************************************


Note that we did not spend time on field Z, this is because it is defined to
be 0 at all times.  This packet does not request recursion.  QDCOUNT = 1
means there is 1 question.  In theory DNS supported several questions in one
message, but this has not been implemented.  ANCOUNT, NSCOUNT and ARCOUNT
are all zero, indicating there are no answers in this question packet.

Here is the actual question:

********************************************************
*                                    1  1  1  1  1  1  *
*      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5  *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ *
*    |           3           |             w         | *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ *
*    |           w           |             w         | *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ *
*    |           4           |             i         | *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ *
*    |           e           |             t         | *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ *
*    |           f           |             3         | *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ *
*    |           о           |             r         | *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ *
*    |           g           |             0         | *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ *
*    |           0           |            28         | *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ *
*    |           0           |             1         | *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ *
********************************************************

This consists of the 'www.ietf.org' encoded in DNS wire format (for which
see below), followed by a 16 bit type field.  For AAAA, which denotes the
IPv6 address, this is 28.  This is then followed by the 'class' of the
question.  It was originally intended that DNS records would exist in
different 'classes', but the semantics of this were not specified completely
and it was not really implemented.  For now, always set class to 1.

The query name, type and class are also called 'qname', 'qtype' and 'qclass'
respectively.

Of specific note is the somewhat unusual way the name 'www.ietf.org' is
serialized in DNS.  'www.ietf.org' consists of 3 'labels' of lengths 3, 4
and 3 respectively.  In DNS messages, this is encoded as the value 3, then
www, then the value 4, then ietf, then 3 followed by org.  Then there is a
trailing 0 which denotes this is the end.

This format is unusual, but has several highly attractive properties. For
example, it is binary safe and it needs no escaping. When writing DNS
software, it may be tempting to pass DNS names around as "ASCII". This then
leads to escaping and unescaping code in lots of places. It is highly
recommended to use the native DNS encoding to store DNS names. This will
save a lot of pain when processing DNS names with spaces or dots in them.

Finally, DNS queries are
[case-insensitive](https://tools.ietf.org/html/rfc4343).  This however is
defined rather mechanically, and limited to ASCII.  Operators do not need to know that in some
encodings a Ü is equivalent to ü when compared case insensitively.
For DNS purposes, the fifth bit (0x20) is ignored when comparing octets
within a-z and A-Z.

Note that individual labels of a name may only be 63 octets long.

Next up, a DNS response. Note that this again is a DNS message, and it looks
a lot like the original DNS query. Here is the beginning of a response:


*****************************************************************
*                                    1  1  1  1  1  1           *
*      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5           *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+          *
*    |                 ID = same random 16 bits      |          *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+          *
*    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |          *
*    |1 |      0    | 1| 0| 0| 0|   0    |     0     |          *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+          *
*    |                    QDCOUNT = 1                |          *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+          *
*    |                    ANCOUNT = 1                |          *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+          *
*    |                    NSCOUNT = 0                |          *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+          *
*    |                    ARCOUNT = 0                |          *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+          *
*    |           3           |             w         |          *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+          *
*    |           w           |             w         |          *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+          *
*    |           4           |             i         |          *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+          *
*    |           e           |             t         |          *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+          *
*    |           f           |             3         |          *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+          *
*    |           о           |             r         |          *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+          *
*    |           g           |             0         |          *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+          *
*    |           0           |            28 (= 0x1c)|          *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+          *
*    |           0           |             1         |          *
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+          *
*****************************************************************

Note that QR is now set to 1 to denote a response.  The 'AA' bit was set
because this answer came from a server authoritative for this name.

In addition, ANCOUNT is now set to '1', indicating a single answer is to be
found in the message, immediately after the original question, which has been
repeated from the query message.

To recognize the right response, check that the ID field is the same as in the
query, make sure the answer arrives on the right source port and that the
query name and type match up with the original query. In addition, make sure
not to send out more than one equivalent query when still waiting for the
response, as doing so opens a security hole.

After the header and the original question we find the answer:

*****************************************************************
*                                    1  1  1  1  1  1
*      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*    |           0xc0        |          0x0c         |
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*    |             00        |            28         |
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*    |             00        |            01         |
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*    |                     TTL = 3600                |
*    |                                               |
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*    |                   RDLENGTH = 16               |
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
*    |             24        |            00         |
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*    |             cb        |            00         |
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*    |             20        |            48         |
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*    |             00        |            01         |
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*    |             00        |            00         |
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*    |             00        |            00         |
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*    |             68        |            14         |
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*    |             00        |            55         |
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*****************************************************************
The first two bytes (`0xc0 0x0c`) look rather mysterious.  When DNS was
created, 512 octets was considered the maximum size of a UDP datagram and
thus the maximum size of a DNS message transported without using the (then
slow) TCP protocol.

In order to squeeze as much information as possible into the 512 bytes, DNS
names can (and often MUST) be compressed.  The details of this compression
are arcane and easy to get wrong, leading to infinite loops or buffer
overflows.  So tread very carefully. If you remember one thing, make sure
that a pointer always has to go to a lower position in the packet. Also
beware of signed/unsigned arithmetic.

In this case, the DNS name of the answer is encoded is `0xc0 0x0c`.  The c0
part has the two most significant bits set, indicating that the following
6+8 bits are a pointer to somewhere earlier in the message.  In this case,
this points to position 12 (= `0x0c`) within the packet, which is immediately
after the DNS header.  There we find 'www.ietf.org'.

So what this means is that the answer about the DNS name `www.ietf.org` is
also called `www.ietf.org`.

This is then followed in the packet by '28', which denotes AAAA (IPv6), and
the usual 'class' of 1. Then a whole 32 bits are devoted to the Time To Live
of this record, followed by a 16 bits length field. Since this is an IPv6
address, the actual answer payload length is 16 bytes (or 128 bits).

This is then followed by the binary representation of the current IPv6
address of www.ietf.org, 2400:cb00:2048:1::6814:55.

If there had been further answers, these would follow this first one, and
the ANCOUNT would have been higher than 1. If there had been data in the
'authoritative' and 'additional' sections, that would follow here too, with
the corresponding adjustments to 'NSCOUNT' and 'ARCOUNT' fields. More about
these sections later.

## RRSETs
In the example above, the question for the AAAA record of 'www.ietf.org' had
exactly one corresponding resource record. In a human readable 'zone file',
this would be stored as:

```
www.ietf.org	IN	AAAA	3600	2400:cb00:2048:1::6814:55
```

It is however possible to have multiple AAAA records for the same name. Even
if there is only one record, the DNS specifications talk about 'Resource
Record Sets', or RRSETs. These operate in unity. So even though the encoding
in the DNS packet allows different TTL values within a single RRSET, this
should never happen.

## Zone files
Zone files are one way of storing DNS data, but these are not integral to
the operation of a nameserver.  The zone file format is standardized
([section 5 of RFC 1035](https://tools.ietf.org/html/rfc1035)), but it
is highly non-trivial to parse.  It is entirely possible to write useful
nameserver that does not read or write DNS zone files.  When embarking on
parsing zonefiles, do not do so lightly.  As an example, various fields
within a single line can appear in many orders.  Most fields are optional,
and some will then be copied from the previous line.  But not all.

Of specific note, many people have attempted to write a grammar (say, in
Yacc) for zonefiles and it is almost impossible.

## DNS Names
The concept of a DNS name is non-trivial and frequently misunderstood.
Despite writing 'www.ietf.org' from left to right, within DNS it is fairer
to describe it as 'org' below the root node, with below the 'org' node a
node called 'ietf'.  Finally to the 'ietf' node is attached a node called
'www'.


Or in graphical form:

***************************
*             +-----+
*             |     |
*             +--+--+
*                |
*             +--+--+
*             | ORG |
*             +--+--+
*                |
*             +--+---+
*             | IETF |
*             +--+---+
*                |
*             +--+--+
*             | WWW |
*             +-----+
***************************

The 'tree' of nodes as shown above is real and not just another way of
visualizing a DNS name.  This for example means that if there is a name
called 'ns1.ord.ietf.org' and a query comes in for 'ns2.fra.ietf.org', that
name exists - even though no records may be assigned to it.

The 'org' zone for example might look like this:

*************************************************************************************************
*                                                                                               *
*                                   .---.                                                       *
*                        +---------+ org +--------+                                             *
*                       /           '-+-'          \                                            *
*                      /              |             \                                           *
*                   .-+-.           .-+-.          .-+-.                                        *
*                  + ietf+         | ietg+        | ... +                                       *
*                   '-+-'           '-+-'          '---'                                        *
*                    / \              |                                                         *
*                   /   \             |                                                         *
*               .--+.    +---.      .-+-.                                                       *
*              + ord |  | fra +    | ... +                                                      *
*               '-+-'    '-+-'      '---'                                                       *
*                 |        |                                                                    *
*               .-+-.    .-+-.                                                                  *
*              + ns1 |  | ns2 +                                                                 *
*               '-+-'    '---'                                                                  *
*                                                                                               *
*************************************************************************************************


NOTE: This means that any implementation that sees DNS as a simple
'key/value' store, where only records that exist can match is headed for
trouble down the line.  The [DNS
standard](https://tools.ietf.org/html/rfc8020)  allows implementations to assume
that if 'ord.ietf.org' does not exist, neither does ns1. This saves queries
but will kill your domain names if you get this wrong.

## Zones
As noted, DNS is more complicated than a simple key/value store.  This is
not only because of the tree style nature of names but also because the same
data can live in multiple places, but always lives in a 'zone'.

Various DNS implementations over time have found out that you can mostly
ignore the concept of 'zone' for simple nameservers or load balancers, but
not implementing zones correctly will eventually trip you up.

To make life confusing, 'www.ietf.org' can be defined in four different
places. It could be in the 'root' zone itself, fully written out:

```
www.ietf.org	IN	AAAA	3600	2400:cb00:2048:1::6814:55
```
Or it could be in the org zone, where it might look like this:

```
$origin ORG
www.ietf	IN	AAAA	3600	2400:cb00:2048:1::6814:55
```

Or, (as is actually the case), this name could live in the 'ietf.org' zone:

```
$origin ietf.org
www	IN	AAAA	3600	2400:cb00:2048:1::6814:55
```

And finally, it is even possible that there is a zone called 'www.ietf.org',
where the record lives like this:

```
$origin www.ietf.org
@	IN	AAAA	3600	2400:cb00:2048:1::6814:55
```


### Start of Authority
A zone always starts with a SOA or Start Of Authority record.  A SOA record
is DNS metadata.  It stores various things that may be of interest about a
zone, like the email address of the maintainer, the name of the most
authoritative server.  It also has values that describe how or if a zone
needs to be replicated.  Finally, the SOA record has a number that
influences TTL values for names that do not exist.

There is only one SOA that is guaranteed to exist on the internet and that
is the one for the root zone (called '.').  As of 2018, it looks like this:

```
.   86400   IN   SOA   a.root-servers.net. nstld.verisign-grs.com. 2018032802 1800 900 604800 86400
```

For details of what all these fields mean, please see the [authoritative
server document](auth.md.html).

The final number however is important here.  86400 denotes that if a
response says a name or RRSET does not exist, it will continue to not exist
for the next day, and that this knowledge may be cached.

### Zone cuts
As noted, 'www.ietf.org' can live in four places. If it lives where it
currently does, in the 'ietf.org' zone, it passes through two zone cuts:
From . to org, from org to ietf.org.

When an authoritative server receives a query for 'www.ietf.org', it
consults which zones it knows about and answers from the most specific zone
it has available.

For a root-server, which only knows about the root zone, this means
consulting the '.' zone. As noted, 'www.ietf.org' is actually a tree, 'org'
-> 'ietf' -> 'www'. And as luck will have it, the first node 'org' is
present in the root zone.

Attached to that node is an NS RRSET, which has the names of nameservers
that host the ORG zone.

If we ask these servers about 'www.ietf.org', they too find the best zone to
answer from, which in this case is 'org'. Within the 'org' zone they then
find the 'ietf' node, which again contains an NS RRSET.

When we ask the servers named in that RRSET about 'www.ietf.org', they find
a node called 'www' with several RRSETs on it, one of which is for AAAA and
contains the IPv6 address we were looking for.

Any authoritative server which does not implement 'zones' in this way will
eventually run into trouble. It is not enough to consult a list of known
names and answer records attached to those names.

### NS Records
These are a mandatory part of a zone, at the 'apex'. The 'apex' is the name
of the zone, at which point there is also a SOA record. So a typical zone
will start like this:

```
$ORIGIN ietf.org.
@	IN	SOA	ns1  admin 2018032802 1800 900 604800 86400
	IN	NS	ns1
	IN	NS	ns2
```

Note how in this zone file example names not ending on a '.' are interpreted
as being part of ietf.org. The '@' is a way to specify the name of the
apex. Lines two and three omit a name, so they default to '@' too.

This zone lists ns1.ietf.org and ns2.ietf.org as its nameservers.
Being part of the zone, this data is *authoritative*. Any queries sent to
this nameserver for the NS RRSET of 'ietf.org' will receive responses
with the AA bit set.

Note however that above we learned that the parent zone, 'org' also needs to
list the nameservers for example.org, and it does:

```
$ORIGIN org.
...
ietf	IN	NS	ns1.ietf
ietf	IN	NS	ns2.ietf
```

If we ask the 'org' nameservers for the NS RRSET of 'ietf.org', we receive a
response with AA=0, indicating that the 'org' servers know they aren't
'authoritative' for ietf.org.

### Glue records
The astute reader will have spotted a chicken and egg problem here.  If
ns1.ietf.org is the nameserver for ietf.org... where do we get the IP
address of ns1.ietf.org?

To solve this problem, the parent zone can provide a free chicken. In the
org zone, we would actually find:

```
$ORIGIN org.
...
ietf	IN	NS	ns1.ietf
ietf	IN	NS	ns2.ietf
ns1.ietf	IN	A	192.0.2.1
ns2.ietf	IN	A	198.51.100.1
```

These entries are mirrored in the 'ietf.org' zone hosted on ns1.ietf.org and
ns2.ietf.org. And as with the NS records, any queries for ns1.ietf.org sent
to the org servers receive AA=0 answers, whereas ns1.ietf.org itself answers
with AA=1.

Note that for various reasons the AA=0 answer from the parent zone may be
different than the AA=1 answer, and resolvers must be aware of the
difference.


# Further aspects

The description up to this point is correct, but far from functionally
complete even for basic DNS. The following sections describe additional
aspects of basic DNS:

## CNAME
A CNAME provides the 'Canonical Name' for another DNS name. For example:

```
www	IN	CNAME	www.ietf.org.cdn.cloudflare.net.
```

This is frequently used to redirect to a Content Distribution Network. The
CNAME is for a name, and not for a type. This means that *any* query for
www.ietf.org is sent to Cloudflare. This simultaneously means that what
everyone wants is impossible:

```
$ORIGIN ietf.org
@	IN	CNAME this.does.not.work.int.
```

This collides with the SOA and NS records, which are then also redirected
and not found. Often, using this 'apex CNAME' may seem to work, but it
really doesn't.

In hindsight, the CNAME should have been 'typed' to apply only to specific
query types.

When a server encounters a CNAME with the name of a name it was looking for,
it will 'follow' the chain to where it points. And please be aware that this
can loop.

## Wildcards
Wildcards allow for the following:

```
$ORIGIN ietf.org.
*	IN	A	192.0.2.1
	IN	AAAA	2001:db8:85a3::8a2e:0370:7334
smtp	IN	A	192.0.2.222
```

A query for the A record of 'smtp.ietf.org' will return 192.0.2.222. A query
for 'www.ietf.org' however will return 192.0.2.1.

Interestingly, as another example of how DNS really is a tree, a query for
the AAAA record of smtp.ietf.org will return... nothing.  This is because
the node 'smtp.ietf.org' does exist, and processing ends there.  The
wildcard match will not proceed to the '*' entry.

Wildcards synthesize new answers. This means that, unless explicitly
queried, no '*.ietf.org' record will be served. Instead, a 'www.ietf.org'
record is created on the fly.

## Truncation
Without implementing the optional EDNS protocol extension, all UDP responses
must fit in 512 bytes of payload. If on writing an answer a server finds
itself exceeding this limit, it must truncate the packet and set the TC bit
to 1.

The originator of the query will then resend the query over TCP.

Sometimes DNS responses contain optional data that could be left out, and
this could be done to stay under the 512 byte limit.

It is recommended however to keep it simple and send an empty response
packet with TC=1 whenever the byte limit is reached.

## Names and nodes that do not exist
DNS queries can fail to match in two ways: the whole node does not exist,
or, the requested type is not present at that node.

As an example of the first case, 'doesnotexist.ietf.org' really does not
exist, which leads to a response with RCODE NXDOMAIN and no answer records.

As an example of the second case, 'www.ietf.org' does exist, but has no MX
record. The RCODE is normal, but there are no answer records.

Empty answers however are hard to cache. To alleviate this situation, in
these cases the authoritative server sends a copy of the SOA record in the
Authority section of the response. The TTL of that record tells us how long
the knowledge of 'no such name' or 'no such data' can be cached.

## Query types that are not RRSET types
In addition to the resource record types covered above, like A, AAAA, NS and
SOA, two additional types exist that can only be used in queries: ANY, AXFR
and IXFR.

An ANY query instructs a nameserver to return all types it immediately has
available for a name. This 'immediately' qualification makes ANY queries
unsuitable for talking to resolvers - it is not sure the response is in any
way complete.

Because of the potential of creating huge answers, the use of ANY is
problematic even when talking to authoritative servers, and it may no longer
work well in the future.

AXFR and IXFR are requests for (incremental) zone transfers, almost always
over TCP. This query asks an authoritative server to list an entire zone.
Resolvers do not process AXFR or IXFR queries.

# That's it for basic DNS!
This is the core of DNS. There are quite some parts that have not been
discussed, but based on the explanations above, it is possible to write a
compliant authoritative server.

## Further reading

### RFC 1034 / 1035

These ([1034](https://tools.ietf.org/html/rfc1034) &
[1035](https://tools.ietf.org/html/rfc1035)) describe the core of DNS in
1987 language.  When reading, disregard mentions of IQUERY and experimental
records.  They did not survive.  Also realize that in this world,
authoritative and resolver service were described as a single function.  We
now know this to be confusing.

### RFC 2181: "Clarifications to the DNS Specification"
From 1997, [2181](https://tools.ietf.org/html/rfc2181) performs a decade of
cleanup work on 1034/1035.  It also talks about an early version of DNSSEC
(NXT, SIG, KEY records), these sections should not be read as this is
unrelated to current DNSSEC (aka DNSSEC-bis).

Of specific note, 5.4.1 describes very exact ordering rules which data a
server is supposed to prefer. This list becomes a lot simpler when split up
between pure authoritative and pure resolver functions.

### RFC 2308: "Negative caching of DNS Queries (NCACHE)
This [RFC](https://tools.ietf.org/html/rfc2308) describes how negative
responses are to be cached. The details matter for both authoritative servers and
resolvers. Of specific note are the parts that dwell on CNAME chains which
lead to a 'no data' or 'NXDOMAIN' situation.

As with 2181, this RFC speaks about an earlier version of DNSSEC, and these
parts should be fully ignored.

### RFC 3596: "DNS Extensions to Support IP Version 6"
This [RFC](https://tools.ietf.org/html/rfc3596) describes the AAAA record,
which is core to DNS as it is required to look up addresses of nameservers.

### RFC 4343: "Domain Name System Case Insensitivity Clarification"
[4343](https://tools.ietf.org/html/rfc4343) clarifies the somewhat odd
case insensitivity of DNS but also writes out the escaping rules when using
non-ASCII or whitespace in DNS names. As noted before, try not to have to
use these rules except when reading DNS data from text files or showing DNS
data meant for human consumption. Use native DNS names as much as possible,
and create 4343-compliant comparison and equivalence functions.

### RFC 5452: "Measures for Making DNS More Resilient against Forged Answers"
This [RFC](https://tools.ietf.org/html/rfc5452) makes source port
randomization mandatory for UDP-based DNS messages and also has rules on
preventing "birthday attacks".

### RFC 6604: "xNAME RCODE Clarification"
[6604](https://tools.ietf.org/html/rfc6604) further describes the meanings
of header bits (AA) and RCODEs when following CNAME chains. Also discusses
an earlier version of DNAMEs, these parts are best ignored in lieu of
(later) reading the newer DNAME specification.

### RFC 7766: DNS Transport over TCP - Implementation Requirements
[This RFC](https://tools.ietf.org/html/rfc7766.txt) updates 1034/1035 to
state that TCP is a mandatory part of DNS and a first class citizen. It also
updates timeout rules, recommending rather brief timeouts compared to the
'minutes' noted in the original DNS standard.

### RFC 8020: NXDOMAIN: There really is nothing underneath
[8020](https://tools.ietf.org/html/rfc8020) clarifies 1034 and 2308 to state
that if 'ord.ietf.org' does not exist, resolvers can safely assume that
neither will 'ns1.ord.ietf.org' - without doing any further queries.

<!-- Markdeep: --><style class="fallback">body{visibility:hidden;white-space:pre;font-family:monospace}</style><script src="ext/markdeep.min.js"></script><script>window.alreadyProcessedMarkdeep||(document.body.style.visibility="visible")</script>
