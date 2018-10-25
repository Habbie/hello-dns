                <meta charset="utf-8" emacsmode="-*- markdown -*-">
                            **A warm welcome to DNS**
<!--<link rel="stylesheet" href="https://casual-effects.com/markdeep/latest/apidoc.css?">-->
Note: this page is part of the
'[hello-dns](https://powerdns.org/hello-dns/)' documentation effort.

# tauth: the teaching authoritative server
`tauth` is based on the [`tdns`](README.md.html) teachable DNS library.
`tauth` is a relatively full-featured authoritative server.

# Current status
All 'basic DNS' items are implemented:

 * UDP & TCP
 * AXFR (incoming and outgoing)
 * Wildcards
 * Delegations
 * Glue records
 * Truncation
 * Compression

As a bonus:
 * EDNS (buffer size, no options)
 * Serving of DNSSEC signed zones

Known broken:
 * TCP/IP does not follow recommended timeouts

The code is not quite in a teachable state yet and still contains ugly bits. 
But well worth [a
read](https://github.com/ahupowerdns/hello-dns/tree/master/tdns).

# Layout
Key to a good DNS implementation is having a faithful DNS storage model,
with the correct kind of objects in them.

Over the decades, many many nameservers have started out with an incorrect
storage model, leading to pain later on with empty non-terminals, case
sensitivity, setting the 'AA' bit on glue (or not) and eventually DNSSEC
ordering problems.

When storing DNS as a tree, as described in RFC 1034, a lot of things go
right "automatically".  When DNS Names are a fundamental type composed out
of DNS Labels with the correct case-insensitive equivalence and identity
rules, lots of problems can never happen.

The core or `tauth` therefore is the tree of nodes as intended in 1034,
containing DNS native objects like DNS Labels and DNS Names.

# The DNS Tree
The DNS Tree is of fundamental importance, and is used a number of times
within `tauth`.

When storing the contents of the `org` zone, it may look like this:

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

This tree has a depth of four. The top node has an empty name, and is
relative to the name of the zone, in this case `org`.

On layer 4, we find the names `ns1.ord.ietf.org` and `ns2.fra.ietf.org`. Key
to looking up anything in DNS is to follow the tree downwards and to observe
what nodes are passed.

For example, a lookup for `www.ietf.org` starts as a lookup for `www.ietf`
in the `org` zone (if loaded, of course).  Layer 1 is where we start (and
find the Start of Authority record), and we look if there is a child node
called `ietf`.  And there is.

As we look at that node, we could see NS records attached to it (`ietf.org NS
ns1.ord.ietf.org`) for example. This means our lookup is done: we've found
a zonecut. The authoritative server should now respond with a delegation by
returning those NS records in the Nameserver section.

To complete the packet, we need to look up the IPv4 and IPv6 addresses of
`ns1.ord.ietf.org` and `ns2.fra.ietf.org`. To do this, we traverse the tree
downward again, starting at the apex with `ns1.ord.ietf` and going to the
`ietf`, `ord` and finally `ns1` labels. There we find attached the IP(v6)
addresses.

## Objects
`tdns` uses a DNS tree in three places: 1) to quickly find the right zone for
a query 2) within that zone, to traverse the names 3) DNS name compression.

The DNS tree within `tdns` consists of `DNSNode` objects, each of which can
have:
 
 * Child nodes
 * Pointer to a zone
 * Attached RRSets, keyed on type

The child nodes are always used in the DNS tree. The pointer to a zone is
only used when consulting the 'tree of zones'. The attached RRsets meanwhile
are only consulted when the right zone is found, to provide actual DNS
answers.

## Manipulating the tree
To add nodes to the DNS tree, or to add things to existing nodes, use the
`add` method like this:

```
	newzone->add({"www"})->addRRs(CNAMEGen::make({"server1","powerdns","org"}));
	newzone->add({"www"})->rrsets[DNSType::CNAME].ttl = 1200;
```
The first line creates the `www` node, and provisions a CNAME there. The
second line updates the new node to set the ttl. Note that `addRRs` accepts
multiple 'generator' parameters, more about which later.

`add` accepts `DNSName`s as parameter, so to populate
www.fra.ietf.org, use `newzone->add({"www", "fra", "ietf", "org"})`.

Within `tdns`, the sample `powerdns.org` zone is populated within
[contents.cc](https://github.com/ahupowerdns/hello-dns/blob/master/tdns/contents.cc).

Finding nodes in the tree uses a slightly more complicated method called
`find`. Unlike `add` it will not modify the tree, even though it has in
common that it will return a pointer to a node.

`find` however also returns some additional things: which parts of the
`DNSName` did not match a node, if a DNS zonecut was encountered while
traversing the tree, and what name it had.

The syntax:

```
	DNSName searchname({"www", "ietf", "org"}), lastname, zonecutname;
	DNSNode* passedZonecut;
	DNSNode* node = bestzone->find(searchname, lastname, &passedZonecut, &zonecutname);
```

When this operates on the `org` zone tree displayed above, after the call to
`find`, `searchname` will be `www`, while `lastname` is `{"ietf", "org"}`.
What this means was that the `www` label could not be matched in the tree,
since it isn't there. 

`passedZonecut` is set to the node that describes `ietf.org`, where NS
records live that describe the delegation. `zonecutname` is therefore set to
`ietf.org`.

To clarify this further, a lookup for `ns1.ord.ietf.org` would end up with:

 * `searchname` empty: all labels of `ns1.ord.ietf.org` were matched
 * `lastname` is then `ns1.ord.ietf.org`
 * `passedZonecut` again points to the `{"ietf", "org"}` node, which has the NS RRSet that describes the delegation
 * `zonecutname` is set to `{"ietf", "org"}`.

The DNS Tree is aware of `*` semantics, and when traversing nodes and not
finding a match, it will look for a `*` node. The tree does not do any
special processing for CNAMEs though.

Based on the `find` method, implementing the RFC 1034 DNS algorithm is very
straightforward.

## Record generators
As noted above, `RRSet`s contain things like `CNAMEGen::make`. These are
generators that are stored in a `DNSNode` and that know how to put their
content into a `DNSMessageWriter`. Each implemented `DNSType` has at least
one associated generator. A more complete example of populating a zone looks
like this:

```
	newzone->addRRs(SOAGen::make({"ns1", "powerdns", "org"}, {"admin", "powerdns", "org"}, 1),
	                 NSGen::make({"ns1", "powerdns", "org"}), NSGen::make({"ns2", "powerdns", "org"}),
	                 MXGen::make(25, {"server1", "powerdns", "org"})
	               );
	newzone->add({"server1"})->addRRs(AGen::make("213.244.168.210"), AAAAGen::make("::1"));
```
This attaches SOA, NS and MX records to the apex of a zone, and defines a
`server1` node that is also referenced in the MX record. 

This code can be found in
[record-types.cc](https://github.com/ahupowerdns/hello-dns/blob/master/tdns/record-types.cc)
and
[record-types.hh](https://github.com/ahupowerdns/hello-dns/blob/master/tdns/record-types.cc).

Since there are many record types, it is imperative that adding a new one
needs to happen in only one place. Within `tauth`, it actually requires two
places: the `DNSType` enum needs to be updated with the numerical value of
the type, and a 'XGen` struct needs to be written. Luckily this is simple
enough. Here is the entire MX record implementation:

```
1	struct MXGen : RRGen
2	{
3	  MXGen(uint16_t prio, const DNSName& name) : d_prio(prio), d_name(name) {}
4	  static std::unique_ptr< RRGen > make(uint16_t prio, const DNSName& name)
5	  {
6	    return std::make_unique< MXGen >(prio, name);
7	  }
8	  void toMessage(DNSMessageWriter& dpw) override;
9	  DNSType getType() const override { return DNSType::MX; }
10	  uint16_t d_prio;
11	  DNSName d_name;
12	};

	...

13	void MXGen::toMessage(DNSMessageWriter& dmw) 
14	{
15	  dmw.putUInt16(d_prio);
16	  dmw.putName(d_name);
17	}
```

Line 3 stores the priority and server name of this MX record (as defined in
lines 10 and 11).

Lines 4-7 are mechanics so we can make a smart pointer for an MXGen type
using a call to `make`. This smart pointer is sort of reference counted in
that its reference count is always 1. This means there is no overhead.

Line 8 defines the call that transposes this record into a
`DNSMessageWriter`. Line 9 announces to anyone who wants to know what the
`DNSType` of this generator is. This is used by `addRRs` as shown above to
put the generator in the right RRSet place.

13 to 17 show the construction of the actual DNS resource record in a
packet: the 16 bit priority, followed by the name.


## A bit of fun: dynamic record contents
Although names can not easily be dynamic within the DNS tree (either they
exist or they don't), contents can be changed at will. 

`tdns` defines a `time.tdns.powerdns.org` node which has a `ClockTXTGen`:

```
	newzone->add({"time"})->addRRs(ClockTXTGen::make("The time is %a, %d %b %Y %T %z"));
```

The code behind this generator:

```
	void ClockTXTGen::toMessage(DNSMessageWriter& dmw) 
	{
		struct tm tm;
		time_t now = time(0);
		localtime_r(&now, &tm);

		std::string txt("overflow");
		char buffer[160];
		if(strftime(buffer, sizeof(buffer), d_format.c_str(), &tm))
			txt=buffer;

		TXTGen gen(txt);
		gen.toMessage(dmw);
	}
```
Note that this generator uses the existing TXT code to encode itself. 
# The RFC 1034 algorithm
As noted in the [basic DNS](../basic.md.html) and
[authoritative](../auth.md.html) pages, the RFC 1034
algorithm can be simplified for a pure authoritative server.

## Finding the right zone and node
In [tdns.cc](https://github.com/ahupowerdns/hello-dns/blob/master/tdns/tdns.cc) , processing starts like this:

```
1	DNSName zonename;
2	auto fnd = zones.find(qname, zonename);
3	...
4	response.dh.aa = 1; 
5    
6	auto bestzone = fnd->zone;
7	DNSName searchname(qname), lastnode, zonecutname;
8	const DNSNode* passedZonecut=0;
9	auto node = bestzone->find(searchname, lastnode, &passedZonecut, &zonecutname);
```

In line 1 we declare the DNSName where we will store the name of the
matching zone. On line 2 we look up the query name, and get the node
containing the zone, plus its name.

Line 3 elides error response if no zone was found. In line 4 we declare we
have authority. Line 6 saves some typing later on.

Lines 7 and 8 declare what we are looking for, and reserves names for where
we store what we found.

Line 9 finally calls `find` to find the best node within our zone. As noted
above, `find` not only finds the best node, but also lets us know if we
passed any NS records along the way.

## If we passed a zone cut

```
1	if(passedZonecut) {
2		response.dh.aa = false;
3		cout<<"This is a delegation, zonecutname: '" << zonecutname << "'" << endl;
4		auto iter = passedZonecut->rrsets.find(DNSType::NS);
5		if(iter != passedZonecut->rrsets.end()) {
6			const auto& rrset = iter->second;
7			vector< DNSName > toresolve;
8			for(const auto& rr : rrset.contents) {
9				response.putRR(DNSSection::Authority, zonecutname+zonename, DNSType::NS, rrset.ttl, rr);
10				toresolve.push_back(dynamic_cast< NSGen* >(rr.get())->d_name);
11			}
12			addAdditional(bestzone, zonename, toresolve, response);
13		}
14	}
```

This is the first thing we check: did we pass a zone cut? If so, on line 2
we drop the aa bit, since we clearly are not providing an authoritative
answer.

Lines 4 and 5 lookup and verify if there is actually an NS record at the
zone cut. This should always be true. 

In line 7 we store room for the NS server names we will need to look up
glue for. In line 8 we iterate over the NS records, which we put in the
`DNSMessageWriter` on line 9. On line 10 we store glue record names. 

Finally on line 12, we call `addAdditional` which will look up the glue
names for us. This completes the response in case of a delegation.

Note that contrary to RFC 1034, `addAdditional` **only** looks for glue
within the `bestzone` itself. 

## NXDOMAIN

```
1	else if(!searchname.empty()) {
2		if(!CNAMELoopCount) // RFC 1034, 4.3.2, step 3.c
3			response.dh.rcode = (int)RCode::Nxdomain;
4		const auto& rrset = bestzone->rrsets[DNSType::SOA];
5      
6		response.putRR(DNSSection::Authority, zonename, DNSType::SOA, rrset.ttl, rrset.contents[0]);
7	}
```

If `find` returned with a non-empty `searchname`, it meant there were parts
of the query name that could not be matched to a node. We checked for a
zonecut earlier (in the previous section), there was none. So this name
really does not exist.

In line 3 we set the response status to NXDOMAIN, unless we've looped
through a CNAME already.

In line 4 we look up the SOA record of our `bestzone` and in line 6 we put
it in the message.

## Node exists
At this stage we know a node exists for this name, although it may actually
be a wildcard node. We do not actually care if it is. Here is what we have
to do first though.

### Check for a CNAME

```
1	auto iter = node->rrsets.cbegin();
2	if(iter = node->rrsets.find(DNSType::CNAME), iter != node->rrsets.end()) {
5		const auto& rrset = iter->second;
6		response.putRR(DNSSection::Answer, lastnode+zonename, DNSType::CNAME, rrset.ttl, rrset.contents[0]);
7		DNSName target=dynamic_cast<CNAMEGen*>(rrset.contents[0].get())->d_name;
8		if(target.makeRelative(zonename)) {
9			searchname = target; 
10			if(CNAMELoopCount++ < 10) {
11				lastnode.clear();
12				zonecutname.clear();
13				goto loopCNAME;
14			}
15		}
16		else
17			cout<<"  CNAME points to record " << target << " in other zone, good luck" << endl;
18	}
```

Line 1 defines an iterator for our subsequent lookup in line 2: is there a
CNAME at this node? If so, in line 6 we put it in the DNSMessage. In line 7
we extract the target of the CNAME.

In line 8 we again violate the RFC 1034 algorithm by checking if the CNAME
points to somewhere within our own zone. If it points to another zone, we
are not going to chase this CNAME.

On line 9 we redirect ourselves if within the same zone. We also check if we
haven't looped 'too much' already. It appears everyone has picked the number
10 for this. We do some cleanup on lines 11 and 12 and finally on line 13 we
restart our algorithm. With a goto.

### Name exists, no CNAME, matching types
```
1	if(iter = node->rrsets.find(qtype), iter != node->rrsets.end() || (!node->rrsets.empty() && qtype==DNSType::ANY)) {
2		auto range = make_pair(iter, iter);
3		if(qtype == DNSType::ANY)
4			range = make_pair(node->rrsets.begin(), node->rrsets.end());
5		else
6			++range.second;        
7		for(auto i2 = range.first; i2 != range.second; ++i2) {
8			const auto& rrset = i2->second;
9			for(const auto& rr : rrset.contents) {
10				response.putRR(DNSSection::Answer, lastnode+zonename, i2->first, rrset.ttl, rr);
11				if(i2->first == DNSType::MX)
12					additional.push_back(dynamic_cast< MXGen* >(rr.get())->d_name);
13			}
14		}
15	}
```

On line 1 is a somewhat tricky lookup that tries to find the query type in
the RRSET, and if it could not be found, if the query maybe was for ANY and
there are records that could be matched.

On lines 2 to 6 we either pick the matching RRSet to put in the DNSMessage,
or we set it up so we iterate over all types, which we then do on lines 8 to
14.

Note that again we gather up the server name of the MX record for additional
processing. If we supported SRV records, we would do the same for them.

### The name exists, but no types or no types match
Finally one of the most vexing parts of DNS: a name that exists, but there
are no types or at least no matching types. This could be an 'empty
non-terminal', created out of thin air by 'some.long.name.powerdns.org'.
This DNS Name populates nodes all along its length, even if no RRSets are
attached to 'long.name.powerdns.org' for example.

In many servers this is tricky, but since we followed a DNS tree based
design with nodes, our code is trivial:

```
1	else {
2		const auto& rrset = bestzone->rrsets[DNSType::SOA];
3		response.putRR(DNSSection::Authority, zonename, DNSType::SOA, rrset.ttl, rrset.contents[0]);
4	}
```

All we have to do is 'else' off the previous case, and add the SOA record.

# AXFR
AXFR over TCP/IP consists of a series of DNS messages, each prefixed by a 16
bit length field. The first and last RRSet contained within these DNS
message(s) must be the SOA record of a zone. Code:

```
1	DNSMessageWriter response(std::numeric_limits< uint16_t >::max()-sizeof(dnsheader));
2	DNSName zone;
3	auto fnd = zones->find(name, zone);
4	if(!fnd || !fnd->zone || !name.empty() || !fnd->zone->rrsets.count(DNSType::SOA)) {
5	  cout<< "   This was not a zone, or zone had no SOA" << endl;
6	  return;
7	}
8	response.dh = dm.dh;
9	response.dh.ad = response.dh.ra = response.dh.aa = 0;
10	response.dh.qr = 1;
11	response.setQuestion(zone, type);
12
13	auto node = fnd->zone;
14
15	// send SOA
16	response.putRR(DNSSection::Answer, zone, DNSType::SOA, node->rrsets[DNSType::SOA].ttl, node->rrsets[DNSType::SOA].contents[0]);
17
18	writeTCPResponse(sock, response);
```

In line 1 we allocate a `DNSMessageWriter` of maximum size. Lines 2-7 find
the best zone, as in the RFC 1034 algorithm. Of specific note is that 'empty
non-terminal zones' could be found by this tree walking function, so we check for this.

The response is then prepared, copying in the original dnsheader (with the
transaction id), and setting the flags, qname and qtype correctly.

Line 13 is again a convenience to save some typing. Line 16 adds the initial
SOA record, and the response gets sent out on line 18.

Note that it is possible to use this first DNSMessage for the initial SOA
record and subsequent records too. To keep things simple, we don't do this
here.

Next up is the loop to pass the rest of the zone contents:

```
1	response.setQuestion(zone, type);
2
3	node->visit([&response,&sock,&name,&type,&zone](const DNSName& nname, const DNSNode* n) {
4		for(const auto& p : n->rrsets) {
5			if(p.first == DNSType::SOA)
6				continue;
7			for(const auto& rr : p.second.contents) {
8				retry:
9				try {
10					response.putRR(DNSSection::Answer, nname, p.first, p.second.ttl, rr);
11				}
12				catch(std::out_of_range& e) { // exceeded packet size 
13					writeTCPResponse(sock, response);
14					response.setQuestion(zone, type);
15					goto retry;
16				}
17			}
18		}
19	}, zone);
20
21	writeTCPResponse(sock, response);
```

In line 1, the DNS message is emptied of RRSets. Line 3 launches a visitor
that walks the DNS Tree and calls putRR on all RRSets it finds, except the
SOA record, which was sent already., so we skip it on line 5.

Lines 9 to 11 attempt to put this resource record in the message. If the
record does not fit, `putRR` rolls back the addition, and throws an
exception which we catch on line 12. There we write out the message to TCP,
reset the packet, and try again. 

Finally in line 21 we write out the last `DNSMessageWriter` we filled.

To terminate the AXFR, we now need to resend the SOA record, which we do as
follows:

```
	response.putRR(DNSSection::Answer, zone, DNSType::SOA, node->rrsets[DNSType::SOA].ttl, node->rrsets[DNSType::SOA].contents[0]);
	writeTCPResponse(sock, response);
```

Note: this code, in `tcpClientThread` of
[tdns.cc](https://github.com/ahupowerdns/hello-dns/blob/master/tdns/record-types.cc)
does not yet implement best TCP practices on timeouts and keeping open
connections.

<script>
window.markdeepOptions={};
window.markdeepOptions.tocStyle = "long";
</script>
<!-- Markdeep: --><style class="fallback">body{visibility:hidden;white-space:pre;font-family:monospace}</style><script src="../ext/markdeep.min.js"></script><script>window.alreadyProcessedMarkdeep||(document.body.style.visibility="visible")</script>
