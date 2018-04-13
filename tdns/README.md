                <meta charset="utf-8" emacsmode="-*- markdown -*-">
                            **A warm welcome to DNS**
<!--<link rel="stylesheet" href="https://casual-effects.com/markdeep/latest/apidoc.css?">-->
Note: this page is part of the
'[hello-dns](https://powerdns.org/hello-dns/)' documentation effort.

# teaching DNS
Welcome to tdns, the teaching authoritative server, implementing all of
[basic DNS](../basic.md.html) in ~~1000~~ 1100 lines of code.

The goals of tdns are:

 * Protocol correctness
 * Suitable for educational purposes
 * Display best practices, both in DNS and security

Non-goals are:

 * Performance
 * Implementing more features (unless very educational)

# Current status
All 'basic DNS' items are implemented.

 * A, AAAA, NS, MX, CNAME, TXT, SOA
 * UDP & TCP
 * AXFR
 * Wildcards
 * Delegations
 * Glue records
 * Truncation

As a bonus:
 * EDNS (buffer size, no options)

Missing:
 * DNS Compression (may not fit in, say, 1200 lines!)

Known broken:
 * ~~Embedded 0s in DNS labels don't yet work~~
 * ~~Case-insensitive comparison isn't 100% correct~~
 * ~~RCode after one CNAME chase~~
 * ~~On output (to screen) we do not escape DNS names correctly~~
 * TCP/IP does not follow recommended timeouts

The code is not yet in a teachable state, and the layout is somewhat
confusing: some stuff is in the wrong files.

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

The core or `tdns` therefore is the tree of nodes as intended in 1034,
containing DNS native objects like DNS Labels and DNS Names.

# Objects
## DNSLabel
The most basic object in `tdns` is DNSLabel. `www.powerdns.com` consists of
three labels, `www`, `powerdns` and `com`. DNS is fundamentally case
insensitive (in its own unique way), and so is DNSLabel. So for example:

```
	DNSLabel a("www"), b("WWW");
	if(a==b) cout<<"The same\n";
```
Will print 'the same'.

In DNS a label consists of between 1 and 63 characters, and these characters
can be any 8 bit value, including `0x0`. By making our fundamental data type
`DNSLabel` behave like this, all the rest of `tdns` automatically gets all
of this right.

When DNS labels contain spaces or other non-ascii characters, and a label
needs to be converted for screen display or entry, escaping rules apply. The
only place in a nameserver where these escaping rules should be enabled is
in the parsing or printing of DNS Labels.

The input to a `DNSLabel` is an unescaped binary string. The escaping
example from RFC 4343 thus works like this:

```
	DNSLabel dl("Donald E. Eastlake 3rd");
	cout << dl << endl; // prints: Donald\032E\.\032Eastlake\0323rd
```

## DNSName
A sequence of DNS Labels makes a DNS name. We store such a sequence as a
`DNSName`. To make this safe, even in the face of embedded dots, spaces and
other things, within `tdns` we make no effort to parse `www.powerdns.com` in
the code. Instead, use this:

```
	DNSName sample({"www", "powerdns", "com"});
	cout << sample <<"\n"; // prints www.powerdns.com.

	sample.pop_back();
	cout << sample << ", size: " << sample.size() << sample.size() << '\n';
	// prints www.powerdns., size 2

```

Since a `DNSName` consists of `DNSLabel`s, it gets the same escaping. To
again emphasise how we interpret the input as binary, ponder:

```
	DNSName test({"powerdns", "com."});
	cout << test << endl; // prints: powerdns.com\..

	const char zero[]="p\x0werdns";
	DNSName test2({std::string(zero, sizeof(zero)-1), "com"});

	cout << test2 << endl; // prints: p\000werdns.com.
```

## DNSType, RCode, DNSSection
This is an enum that contains the names and numerical values of the DNS
types. This means for example that `DNSType::A` corresponds to 1 and
`DNSType::SOA` to 6.

To make life a little bit easier, an operator has been defined which allows
the printing of `DNSTypes` as symbolic names. Sample:

```
	DNSType a = DNSType::CNAME;
	cout << a << "\n";    // prints: CNAME

	a = (DNSType) 6;
	cout << a <<" is "<< (int)a << "\n"; // prints: SOA is 6
```

Similar enums are defined for RCodes (response codes, RCode::Nxdomain for
example) and DNS Sections (Question, Answer, Nameserver/Authority,
Additional). These too can be printed.

# The DNS Tree
The DNS Tree is of fundamental importance, and is used a number of times
within `tdns`.

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
`tdns` uses a DNS tree in two places: 1) to quickly find the right zone for
a query 2) within that zone, to traverse the names. 

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

Since there are many record types, it is imperative that adding a new one
needs to happen in only one place. Within `tdns`, it actually requires two
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

# The RFC 1034 algorithm
As noted in the [basic DNS](../basic.md.html) and
[authoritative](../auth.md.html) pages, the RFC 1034
algorithm can be simplified for a pure authoritative server.


## Finding the right zone and node
In tdns.cc, processing starts like this:

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
3		cout<<"This is a delegation, zonecutname: '"<<zonecutname<<"'"<<endl;
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
3		response.putRR(DNSSection::Answer, zonename, DNSType::SOA, rrset.ttl, rrset.contents[0]);
4	}
```

All we have to do is 'else' off the previous case, and add the SOA record.

# DNSMessageWriter

# DNSMessageReader

<script>
window.markdeepOptions={};
window.markdeepOptions.tocStyle = "long";
</script>
<!-- Markdeep: --><style class="fallback">body{visibility:hidden;white-space:pre;font-family:monospace}</style><script src="../ext/markdeep.min.js"></script><script>window.alreadyProcessedMarkdeep||(document.body.style.visibility="visible")</script>