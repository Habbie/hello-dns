                <meta charset="utf-8" emacsmode="-*- markdown -*-">
                            **A warm welcome to DNS**


# Authoritative servers

The basics of DNS Authoritative operation have already been described in the
[Basic DNS](index.html) document.  In this file, we delve deeper into zone
transfers and and notifications.

This document covers RFCs 1982, 1995, 1996, 4592, 5936, 7766.

# Incoming queries
An authoritative server ignores the value of the Recursion Desired (RD) bit
in the DNS header. On any responses it generates, the Recursion Available
bit is set to zero.

Take special care not to send answers to what is already a DNS answer. This
leads to tight loops and denial of service attacks. In other words, QR must
be 0 on incoming packets.

# The algorithm
As noted before, DNS is fundamentally a tree and hierarchical in nature.
This means that when a query comes in to an authoritative nameserver, it
first needs to find the most applicable zone to answer from. And in fact,
the same name may be present in multiple zones on the name server, and may
very well have different types and even record contents.

The most specific zone is located for a query name (qname). If no zone can
be found, set RCODE to 'REFUSED' and send out the response. This is unlike
many example responses shown in RFCs and other documents listing 'root
referrals' and other things. Just send 'REFUSED'.

Within the most specific zone, see if the entire qname can be matched. If
so, determine if that name has the type the query asked for ('qtype'). If
yes, send out that RRSET.



xxx
RFC1982

## SOA Records
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

<!-- Markdeep: --><style class="fallback">body{visibility:hidden;white-space:pre;font-family:monospace}</style><script src="markdeep.min.js"></script><script src="https://casual-effects.com/markdeep/latest/markdeep.min.js"></script><script>window.alreadyProcessedMarkdeep||(document.body.style.visibility="visible")</script>