                <meta charset="utf-8" emacsmode="-*- markdown -*-">
                            **A warm welcome to DNS**

<!-- <link rel="stylesheet" href="https://casual-effects.com/markdeep/latest/apidoc.css?">
-->

Note: this page is part of the
'[hello-dns](https://powerdns.org/hello-dns/)' documentation effort.

# Authoritative servers

The basics of DNS Authoritative operation have already been described in the
[Basic DNS](index.html) document.  In this file, we delve deeper into zone
transfers and notifications.

This document covers RFCs 1982, 1995, 1996 (all three related to zone
transfers), 4592 (Wildcards), 5936 (again zone transfers) and 7766 (TCP).

# Incoming queries
An authoritative server ignores the value of the Recursion Desired (RD) bit
in the DNS header. On any responses it generates, the Recursion Available
bit is set to zero.

Take special care not to send responses to what is already a DNS response. 
This leads to tight loops and denial of service attacks.  In other words, QR
must be 0 on incoming packets.

# Delegation
As noted in the basic DNS document, finding the answer to a query may mean
consulting multiple zones: the root zone, the org zone, the ietf.org zone,
for example.

The process of traversing such a zone-cut is called a delegation. A
delegation is signified by the presence of NS records outside of the zone
apex (aka the name of the zone).

*************************************************************************************************
*                                                                                               *
*                                        .---. SOA                                              *
*                             +---------+ org +--------+                                        *
*                            /           '-+-' NS       \                                       *
*                           /              |             \                                      *
*                        .-+-.           .-+-.          .-+-.                                   *
*---ZONE CUT---         + ietf+ NS      | ietg+ NS     | ... +  ---ZONE CUT---                  *
*                        '-+-'           '-+-'          '---'                                   *
*                         / \              |                                                    *
*                        /   \             |                                                    *
*                    .--+.    +---.      .-+-.                                                  *
*   EMPTY -->       + ord |  | fra +    | ... +                                                 *  
*NON-TERMINAL        '-+-'    '-+-'      '---'                                                  *
*                      |        |                                                               *
*                    .-+-.    .-+-.                                                             *                   
*    GLUE -->     A + ns1 |  | ns2 + A     <-- GLUE                                             *                   
*              AAAA  '-+-'    '---'  AAAA                                                       *                   
*                                                                                               *
*************************************************************************************************

# Sending answers
Fundamentally, the following answers are possible (this omits CNAME and
wildcard processing, more about which below).

1. No applicable zone is loaded. Send REFUSED answer.
2. From best zone, there was an exact match for the qname and qtype, send RRSET, set NO ERROR
3. From best zone, the name queried exists, but no matching qtype and no NS type present (send NO DATA)
4. From best zone, the name may exist, but there is a node or a parent has an NS record. Send delegation


# The algorithm
Section 4.3.2 of [RFC 1034](https://tools.ietf.org/html/rfc1034)  explains
this process well, except that it also discusses what to do when operating
as a resolver, which confuses matters.

Here is the RFC 1034 algorithm cleaned of outdated instructions and items
that are only applicable to resolvers, with new instructions in **bold**.

 1. Removed
 2. Search the available zones for the zone which is the nearest  
    ancestor to QNAME.  If such a zone is found, go to step 3,  
    otherwise **set RCODE to REFUSED** and go to step **7**.
 3. Start matching down, label by label, in the zone.  The  
    matching process can terminate several ways:
    1. If the whole of QNAME is matched, we have found the  
       node.  
       If the data at the node is a CNAME, and QTYPE doesn't  
       match CNAME, copy the CNAME RR into the answer section  
       of the response, change QNAME to the canonical name in  
       the CNAME RR, and go back to step 1.  
       Otherwise, copy all RRs which match QTYPE into the  
       answer section and go to step 6.
    2. If a match would take us out of the authoritative data,  
       we have a referral.  This happens when we encounter a  
       node with NS RRs marking cuts along the bottom of a  
       zone.  
       Copy the NS RRs for the subzone into the authority  
       section of the reply.  Put whatever addresses are  
       available into the additional section, using glue RRs  
       if the addresses are not available from authoritative  
       data ~~or the cache~~.  Go to step 4.  
    3. If at some label, a match is impossible (i.e., the  
       corresponding label does not exist), look to see if
       the * label exists.
       If the * label does not exist, check whether the name  
       we are looking for is the original QNAME in the query  
       or a name we have followed due to a CNAME.  If the name  
       is original, set an authoritative name error in the  
       response and exit.  Otherwise just exit.  
       If the * label does exist, match RRs at that node  
       against QTYPE.  If any match, copy them into the answer  
       section, but set the owner of the RR to be QNAME, and  
       not the node with the * label.  Go to step 6.  
 4. Removed
 5. Removed
 6. Using local data only, attempt to add other RRs which may be  
    useful to the additional section of the query.  
 7. **Exit.**

This description is valid, but its 'node' language may be confusing. An
alternate way to describe the process is as follows:

 2. If the query name is `www.ietf.org`, check the store for a  
    `www.ietf.org` zone.  If not found, try `ietf.org`, that is not found try  
    `org`, otherwise try the root zone. If no zones were found, send out  
    REFUSED.  
 3. Within the first zone that matched (say, `org`), search for `www.ietf`.
    If that was not found, search for `ietf` etc etc

This is effectively the same thing but implemented on a regular key/value
lookup engine.

## Wildcards
The algorithm as described in the previous section does mention wildcards,
but not in great detail, and not coherently. [RFC
4592](https://tools.ietf.org/html/rfc4592) by comparison discusses wildcards
in exhaustive detail. 

4592 specifically notes that `one.two.three.ietf.org` is still matched by
`*.ietf.org`. It also specifies that `one.*.three.ietf.org` is a valid DNS
name, but that it will only match itself, and not `one.two.three.ietf.org`.

4592 attempts to clarify every possible misunderstanding relating to
wildcards (including interactions with DNSSEC), but because of its
overwhelming detail may itself be a confusing document to read.  It is
recommended to refer to 4592 to resolve difficult wildcard questions, but if
possible to stay well clear of difficult wildcard situations in the first
place.

Specifically, this means not using wildcards for NS records or in other
exciting places.

# SOA Records
There is only one SOA that is guaranteed to exist on the internet and that
is the one for the root zone (called `.`).  As of 2018, it looks like this:

```
.   86400   IN   SOA   a.root-servers.net. nstld.verisign-grs.com. 2018032802 1800 900 604800 86400
```

This says: the authoritative server for the root zone is called
`a.root-servers.net`. This name is however only used for diagnostics.
Secondly, nstld@verisign-grs.com is the email address of the zone
maintainer. Note that the `@` is replaced by a dot. Specifically, if the
email address had been `nstld.maintainer@verisign-grs.com`, this would have
been stored as nstld\\.maintainer.verisign-grs.com. This name would then
still be 3 labels long, but the first one has a dot in it.

The following field, 2018032802, is a serial number.  Quite often, but by
all means not always, this is a date in proper order (YYYYMMDD), followed by
two digits indicating updates over the day.  This serial number is used for
replication purposes, as are the following 3 numbers.

Zones are hosted on 'masters`. Meanwhile, 'slave' servers poll the master
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


# Replication 
An authoritative server can serve the entire contents of a zone over TCP and
this is called a zone transfer or AXFR. A "slave server" can request such an
AXFR and then also serve the contents of the zone.

Master servers typically restrict AXFR access to specific IP addresses.  A
slave need not necessarily be known to the master as a slave - as long as it
has AXFR access, it can retrieve the zone.

Zone transfers proceed over TCP, and every zone transfer consists of one or
more DNS messages. Much as TCP has no datagram functionality to denote the
begin and end of a message, neither does DNS over TCP. So individual
messages are prefixed with a 16 bit network endian length field. The stream
of messages comprising a zone transfer in turn is terminated by the receipt
of a second copy of the SOA record of a zone.

1034 and 1035 speak about zone transfers, but not in sufficient detail.
Instead, consult [RFC 5936](https://tools.ietf.org/html/rfc5936) and
disregard anything found in 1034, 1035 and even 2181 about AXFR.

Note that [RFC 1982](https://tools.ietf.org/html/rfc1982) describes in
exhaustive detail how serial numbers should be compared. The SOA serial
number is an indication on if one zone is newer than the other. RFC 1982
describes how to deal with 32-bit wraps.

## Notification
As outlined above in the description of the SOA record, slave servers
periodically check the master server to find out if there have been any
updates that need to be retrieved.

Since this periodic check may be far in the future, optionally master
servers can send out notifications when they load new zone data.

Notification was not in 1034/1035 and is described well in [RFC
1996](https://tools.ietf.org/html/rfc1996).

In short, a notification is a regular DNS message, sent out as a query, but
then with OPCODE=5. Notifications are repeated until acknowledged by the
slave server.

# TBC

<!-- Markdeep: --><style class="fallback">body{visibility:hidden;white-space:pre;font-family:monospace}</style><script src="ext/markdeep.min.js"></script><script>window.alreadyProcessedMarkdeep||(document.body.style.visibility="visible")</script>
