# hello-dns
Hello and welcome to DNS!

This document attempts to provide a correct introduction to the Domain Name
System as of 2018. The original RFCs remain the authoritative source of
normative text, but this document tries to be in full alignment with all
relevant and useful RFCs.

Although we start from relatively basic principles, the reader is expected
to know what IP addresses are, what a (stub) resolver is and what an
authoritative server is supposed to do. When in doubt: authoritative servers
'host' DNS, 'resolvers' look up things over at authoritative servers and
clients run 'stub resolvers' to look things up over at resolvers.

DNS was originally written down in August 1979 in 'IEN 116', a parallel
series of documents describing the internet.  IEN 116 era DNS is not
compatible with today's DNS.  In 1983, RFC 882 was released, and stunningly
enough, an implementation of this 35 year old document would function
on the internet and be interoperable. 

DNS attained its modern form in 1987 when RFC 1034 and 1035 were published.
Although most of 1034/1035 remains valid, these standards are not that easy
to read because they were written in a very different time.

The main goal of this document is not to contradict 1034 and 1035 but to
provide an easier entrypoint into DNS.

If you will, the goal is to be a mini "[TCP/IP
Illustrated](https://en.wikipedia.org/wiki/TCP/IP_Illustrated)" of DNS.

## Layout
The content is spread out over several documents:

 * The core of DNS
 * Relevant to stub resolvers and applications
 * Relevant to authoritative servers
 * Relevant to resolvers
 * Optional elements: EDNS, TSIG, Dynamic Updates, DNSSEC, DNAME, DNS
 Cookies

We start off with a general introduction of DNS basics: what is a resource
record, what is a RRSET, what is a zone, what is a zone-cut, how are packets
laid out. This part is required reading for anyone ever wanting to query a
nameserver or emit a valid response.

We then specialize into what applications can expect when they send
questions to a resolver, or what a stub-resolver can expect.

The next part is about what an authoritative server is supposed to do. On
top of this, we describe in slightly less detail how a resolver could
operate. Finally, there is a section on optional elements like EDNS, TSIG,
Dynamic Upates andDNSSEC

Note that this file, which describes DNS basics, absolutely must be read from
beginning to end in order for the rest of the documents (or DNS) to make
sense.

## DNS Basics
In this section we will initially ignore optional extensions that were added
to DNS later, specifically EDNS and DNSSEC which requires EDNS to function.

This file corresponds roughly to the fundamental parts of RFCs 1034, 1035,
1982, 2181, 2308, 3596, 4343, 5452, 6604.

DNS is mostly used to serve IP addresses and mailserver details, but it can
contain arbitrary data.  DNS is all about names.  Every name can have data
of several *types*.  The most well known externally useful types are *A* for
IPv4 addresses, *AAAA* for IPv6 addresses and *MX* for mailserver details.
DNS also has types that have meaning for its own use, like *NS*, *CNAME* and
*SOA*. 

When we ask a DNS question we call this a *query*. We call the reply the
*response*.  These queries and responses are contained in DNS messages. When
UDP is used, the message is also the packet. 

A DNS message has: 

 * A header
 * A query name and query type
 * An answer section
 * An authority section
 * An additional section

The header has the following fields that are useful for queries and
responses:

 * ID: a 16 bit identifier used as part of the process of matching queries to responses 
 * QR: Set to 0 to identify a message as a query, 1 for a response
 * OPCODE: 0 for a standard query, other opcodes also exist
 * RD: Set to indicate that this question wants *recursion* 
 
Relevant for responses:
 * AA: This answer has Authoritative Answers
 * RA: Recursive service was available
 * TC: Not all the required parts of the answer fit in the message

In basic DNS, query messages should have no answer, authority or additional
sections. DNS queries are mostly sent over UDP, and UDP packets can easily
be spoofed. To recognize the authentic response to a query it is important
that the ID field is random or at least unpredictable. This is however not
enough protection, so the source port of a UDP DNS query must also be
unpredictable.

DNS messages can also be sent over TCP/IP. Because TCP is not a datagram
oriented protocol, each DNS message in TCP/IP is preceded by a 16 bit
network endian length field.

The header of a question for the IPv6 address of www.ietf.org looks like
this:

```
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID = random 16 bits      |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    |0 |      0    |0 | 0| 0|0 |   0    |     0     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT = 1                |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT = 0                |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT = 0                |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT = 0                |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

Note that we did not spend time on field Z, this is because it is defined to
be 0 at all times.  This packets does not request recursion.  QDCOUNT = 1
means there is 1 question.  In theory DNS supported several questions in one
message, but this has not been implemented.  ANCOUNT, NSCOUNT and ARCOUNT
are all zero, indicating there as no answers in this question packet.

Here is the actual question:

```
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |           3                         w         |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |           w                         w         |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |           4                         i         |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |           e                         t         |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |           f                         3         |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |           o                         r         |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |           g                         0         |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |           0                        28         |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |           0                         1         |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

This consists of the 'www.ietf.org' encoded in DNS wire format (for which
see below), followed by a 16 bit type field.  For AAAA, which denotes the
IPv6 address, this is 28.  This is then followed by the 'class' of the
question.  It was originally intended that DNS records would exist in
different 'classes', but the semantics of this were not specified completely
and it was not really implemented.  For now, always set class to 1.

Of specific note is the somewhat unusual way the name 'www.ietf.org' is
serialized in DNS.  'www.ietf.org' consists of 3 'labels' of lenghts 3, 4
and 3 respectively.  In DNS messages, this is encoded as the value 3, then
www, then the value 4, then ietf, then 3 followed by org.  Then there is a
trailing 0 which denotes this is the end.

This format is unusual, but has several highly attractive properties. For
example, it is binary safe and it needs no escaping. When writing DNS
software, it may be tempting to pass DNS names around as "ASCII". This then
leads to escaping an unescaping code in lots of places. It is highly
recommended to use the native DNS encoding to store DNS names. This will
save a lot of pain when processing DNS names with spaces or dots in them.

Finally, DNS queries are
[case-insensitive](https://tools.ietf.org/html/rfc4343).  This however is
defined rather mechanically.  Operators do not need to know that in some
ASCII encodings a Ü is equivalent to ü when compared case insensitively. 
For DNS purposes, the fifth bit (0x20) is ignored when comparing octets
within a-Z and A-Z.

Note that individual labels of a name may only be 63 octets long.

Next up, a DNS response. Note that this again is a DNS message, and it looks
a lot like the original DNS query. Here is the beginning of a response:

```
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                 ID = same random 16 bits      |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    |1 |      0    | 1| 0| 0| 0|   0    |     0     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT = 1                |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT = 1                |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT = 0                |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT = 0                |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |           3                         w         |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |           w                         w         |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |           4                         i         |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |           e                         t         |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |           f                         3         |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |           o                         r         |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |           g                         0         |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |           0                        28 (0x1c)  |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |           0                         1         |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

```

Note that QR is now set to 1 to denote a response.  The 'AA' bit was set
because this answer came from a from a server authoriative for this name.

In addition, ANCOUNT is now set to '1', indicating a single answer is to be
found in the message, immediately after the original question, which has been
repeated from the query message. 

To recognize the right response, check that the ID field is the same as the
query, make sure the answer arrives on the right source port and that the
query name and type match up with the original query. In addition, make sure
not to send out more than one equivalent query when still waiting for the
response, as doing so opens a security hole.

After the header and the original question we find the answer:

```
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |           0xc0                   0x0c         |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |             00                     28         |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |             00                     01         |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     TTL = 3600                |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH = 16               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    |             24                     00         |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |             cb                     00         |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |             20                     48         |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |             00                     01         |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |             00                     00         |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |             00                     00         |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |             68                     14         |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |             00                     55         |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

The first two bytes (0xc0 0c0c) look rather mysterious.  When DNS was
created, 512 octets was considered the maximum size of a UDP datagram and
thus the maximum size of a DNS message transported without using the (then
slow) TCP protocol.

In order to squeeze as much information as possible into the 512 bytes, DNS
names can (and often MUST) be compressed.  The details of this compression
are arcane and easy to get wrong, leading to infinite loops or buffer
overflows.  So tread very carefully. If you remember one thing, make sure
that a pointer always has to go to a lower position in the packet. Also
beware of signed/unsigned arithmetic. 

In this case, the DNS name of the answer is encoded is '0xc0 0x0c'.  The c0
part has the two most significant bits set, indicating that the following
6+8 bits are a pointer to somewhere earlier in the message.  In this case,
this points to position 12 (= 0x0c) within the packet, which is immediately
after the DNS header.  There we find 'www.ietf.org'.

So what this means is that the answer about the DNS name 'www.ietf.org' is
also called 'www.ietf.org'. 

This is then followed in the packet by '28', which denotes AAAA (IPv6), and
the usual 'class' of 1. Then a whole 32 bits are devoted to the Time To Live
of this record, followed by a 16 bits length field. Since this is an IPv6
address, the actual answer payload length is 16 bytes (or 128 bits).

This is then followed by the binary representation of the current IPv6
address of www.ietf.org, 2400:cb00:2048:1::6814:55.

## RRSETs
In the example above, the question for the AAAA record of 'www.ietf.org' had
exactly one corresponding resource record. In a human readable 'zone file',
this would stored as:

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
the operation of a nameserver. The zone file format is standardised, but it
is highly non-trivial to parse. It is entirely possible to write useful
nameserver that do not read or write DNS zone files. When embarking on
parsing zonefiles, do not do so lightly. As an example, various fields
within a single line can appear in many orders. Most fields are optional,
and some will then be copied from the previous line. But not all.

Of specific note, many people have attempted to write a grammar (parser) for
zonefiles and it is almost impossible. 

## DNS Names
The concept of a DNS name is non-trivial and frequently misunderstood. 
Despite writing 'www.ietf.org' from left to right, within DNS it is fairer
to describe it as 'org' below the root node, with below the 'org' node a
node called 'ietf'.  Finally to the 'ietf' node is attached a node called
'www'.


Or in graphical form:

```
             +-----+
             |  .  |
             +-----+
                |
             +-----+
             | ORG |
             +-----+
                |
             +------+
             | IETF |
             +------+
                |
             +-----+
             | WWW |
             +-----+
```


The 'tree' of nodes as shown above is real and not just another way of
visualizing a DNS name.  This for example means that if there is a name
called 'www.fr.ietf.org' and a query comes in for 'fr.ietf.org', that name
exists - even though no records may be assigned to it. 

NOTE: This means that any implementation that sees DNS as a simple
'key/value' store, where only records that exist can match, is headed for
trouble down the line. 

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
authoritative server.  It also has vales that describe how or if a zone
needs to be replicated.  Finally, the SOA record has a number that
influences TTL values for names that do not exist.

There is only one SOA that is guaranteed to exist on the internet and that
is the one for the root zone (called '.').  As of 2018, it looks like this:

```
.   86400   IN   SOA   a.root-servers.net. nstld.verisign-grs.com. 2018032802 1800 900 604800 86400
```

This says: the authoritative server for the root zone is called
'a.root-servers.net'. This name is however only used for diagnostics.
Secondly, nstld@verisign-grs.com is the email address of the zone
maintainer. Note that the '@' is replaced by a dot. Specifically, if the
email address had been 'nstld.maintainer@verisign-grs.com', this would have
been stored as nstld\\.maintainer.verisign-grs.com. This name would then
still be 3 labels long, but the first one has a dot in it.

The following field, 2018032802, is a serial number.  Quite often, but by
all means not always, this is a date in proper order (YYYYMMDD), followed by
two digits indicating updates over the day.  This serial number is used for
replication purposes, as are the following 3 numbers.

Zones are hosted on 'masters'. Meanwhile, 'slave' servers poll the master
for updates, and pull down a new zone if they see new contents, as noted by
an increase in serial number.

The numbers 1800 and 900 describe how often a zone should be checked for
updates (twice an hour), and that if an update check fails it should be
repeated after 900 seconds.  Finally, 604800 says that if a master server
was unreachable for over a week, the zone should be deleted from the slave.
This is not a popular feature.

The final number, 86400, denotes that if a response says a name or RRSET
does not exist, it will continue to not exist for the next day, and that
this knowledge may be cached.

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
a node called 'www' with several RRSETs on it, one if which is for AAAA and
contains the IPv6 address we were looking for.

Any authoritative server which does not implement 'zones' in this way will
eventually run into trouble. It is not enough to consult a list of known
names and answer records attached to those names.

### NS Records
These are a mandatory part of a zone, at the 'apex'. The 'apex' is the name
of the zone, at which point there is also a SOA record. So a typical zone
will start like this:

```
$ORIGIN ietf.org
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
$ORIGIN org
...
ietf	IN	NS	ns1.ietf
ietf	IN	NS	ns2.ietf
```

If we ask the 'org' nameservers for the NS RRSET of 'ietf.org', we receive a
response with AA=0, indicating that the 'org' servers know they aren't
'authoritative' for ietf.org.

### Glue records
The astute reader will have spotted a chicken and egg problem here.  If
ns1.ietf.org is the nameserver for ietf.org..  where do we get the IP
address of ns1.ietf.org?

To solve this problem, the parent zone can provide a free chicken. In the
org zone, we would actually find:

```
$ORIGIN org
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
