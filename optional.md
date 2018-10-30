                <meta charset="utf-8" emacsmode="-*- markdown -*-">
                            **A warm welcome to DNS**

# EDNS, Dynamic Updates, TSIG, DNAME, DNS Cookies & more
So far we've focussed on the simplest possible form of DNS that is
interoperable with today's internet. Over the past 3 decades however, a lot
has been added to DNS.

Items relevant for authoritative servers and resolvers:

 * EDNS: Extra fields carried in the additional section of a DNS message,
   including arbitrary options. The main use of EDNS today is specifying a
   larger supported UDP packet size, indicating DNSSEC support and carrying
   Client Subnet information. Defined in [RFC
   6891](https://tools.ietf.org/html/rfc6891).
 * EDNS Client Subnet: Convey (part) of client addresses to authoritative 
   resolvers. Defined in [RFC 7871](https://tools.ietf.org/html/rfc7871).
 * DNAME: Domain redirection [RFC 6672](https://tools.ietf.org/html/rfc6672)
 * DNS Cookies: Lightweight transaction security mechanism [RFC 7873](https://tools.ietf.org/html/rfc7873)

Relevant for authoritative servers:

 * Dynamic Updates: Transmitting changes to zones to master servers. Mostly
   used by DHCP servers to publish names of hosts. Defined in [RFC
   2136](https://tools.ietf.org/html/rfc2136)
 * TSIG: Secret Key Transaction Authentication for DNS. A way to sign DNS
   messages or a list of DNS messages with a secret key. Used to authenticate
   AXFR requests and to guarantee zone integrity during AXFR. Defined in
   [RFC 2845](https://tools.ietf.org/html/rfc2845).


## Extended DNS (EDNS or EDNS(0))
EDNS is very much an enabling technology and it can't really be regarded as
optional anymore.  It enables DNSSEC, DNS Cookies, EDNS Client Subnet as
well as larger UDP packets. It also expands on the 4-bit RCODE field of
un-extended DNS.

The EDNS content is attached to a pseudo-record called OPT in the additional
section of a message and an answer. 

The following EDNS fields are always present:
 
 * Requestor's maximum UDP payload size
 * Extended RCODE (an additional 8 bits)
 * EDNS Version
 * DNSSEC OK bit (which indicates DNSSEC support from the requestor)
 * Yet another field called 'Z' which must be zero

In order to save size, the EDNS 'OPT' pseudo-record reuses existing resource
record fields to store its data. For example, the UDP payload size is stored
in the 16 bit class field, and the extended RCODE, version and flags hang
out in the TTL field.

Just like regular record types, the OPT pseudo-record can carry a payload.
This consists of 0 or more 'Type Length Value' tuples. The following types
are currently in common use, or will soon be:

 * NSID (3): Return the 'nameserver identifier' [RFC
   5001](https://tools.ietf.org/html/rfc5001)
 * EDNS Client Subnet (8): Convey part of client subnet [RFC 6891](https://tools.ietf.org/html/rfc2671).
 * Cookie (10): Lightweight transaction security [RFC  7873](https://tools.ietf.org/html/rfc7873)

[RFC 7871](https://tools.ietf.org/html/rfc7871) is a concise specification
that is completely applicable to 2018 DNS. Its implementation is highly
recommended.

## Dynamic Updates (DNS UPDATE)
Defined in [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS UPDATE is a
somewhat underused extension that allows a client to request an authoritative
server add or remove RR or RRSETs in a zone. While primarily useful for
allowing distributed management of a zone, a side benefit for authoritative
server implementors is effectively free support for new RR types as the burden
of supporting new types shifts to the client.

Dynamic Update access is generally limited by some combination of client IP
address, RR name and/or type, or message signature such as TSIG or more rarely
SIG(0). For example, on a trusted network clients may be allowed to update a
reverse entry based on their IP address. Over the internet controls using
stronger authentication like TSIG or SIG(0) should be employed.

On the wire DNS UPDATE uses the standard DNS message format with some
repurposing of the message body. Messages begin with a standard header
with the OPCODE set to UPDATE (5). The question section is repurposed to
specify the zone to update, answers becomes prerequisites, and the authority
section holds the updates themselves.

*****************************************
*
*  +------------+      +---------------+
*  + Header     + ---> + Header        +
*  +------------+      +---------------+
*  + Question   + ---> + Zone          +
*  +------------+      +---------------+
*  + Answers    + ---> + Prerequisites +
*  +------------+      +---------------+
*  + Authority  + ---> + Updates       +
*  +------------+      +---------------+
*  + Additional + ---> + Additional    +
*  +------------+      +---------------+
*
*****************************************

**Zone**

A question (name, type and class) of type SOA is used to specify the (single)
target zone's name and class.

**Prerequisites**

Prerequisites are constraints that must pass before any updates are processed.
All of the constraints apply to entire RRSETs as opposed to individual RRs.
Prerequisite failures are signalled by a response message's RCODE.

Prerequiste            | Type         | Class         | Data | Failure RCODE
-----------------------|--------------|---------------|------|--------------
RRSET exists           | RRSET's Type | ANY (255)     | No   | NXRRSET (8)
RRSET exists with data | RRSET's Type | RRSET's Class | Yes  | NXRRSET (8)
RRSET does not exist   | RRSET's Type | NONE (254)    | No   | YXRRSET (7)
Name is in use         | ANY (255)    | ANY (255)     | No   | NXDOMAIN (3) 
Name is not in use     | ANY (255)    | NONE (254)    | No   | YXDOMAIN (6)

TTLs are not used in prerequisites and must be set to zero. Prerequisites without
data must include the RDLEN field set to zero.

**Updates**

Change                      | Type       | Class        | Data
----------------------------|------------|--------------|-----
Add an RR to an RRSET       | RRSET Type | Zone's Class | Yes
Delete an RRSET             | RRSET Type | ANY (255)    | No
Delete all RRSETs at a name | ANY (255)  | ANY (255)    | No
Delete an RR from an RRSET  | RRSET Type | NONE (254)   | Yes

With the exception of adding an RR, TTLs are not used and must be set to zero.
Should adding an RR cause duplicate data, or should a type be a singleton type
the server will silently deduplicate the data. If a delete refers to something
that doesn't exist the server will silently ignore the change. As with
prerequisites changes that don't reference data must still include the RDLEN
field.

...
 
<!-- Markdeep: --><style class="fallback">body{visibility:hidden;white-space:pre;font-family:monospace}</style><script src="ext/markdeep.min.js"></script><script>window.alreadyProcessedMarkdeep||(document.body.style.visibility="visible")</script>
