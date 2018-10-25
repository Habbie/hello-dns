                <meta charset="utf-8" emacsmode="-*- markdown -*-">
                            **A warm welcome to DNS**
<!--<link rel="stylesheet" href="https://casual-effects.com/markdeep/latest/apidoc.css?">-->
Note: this page is part of the
'[hello-dns](https://powerdns.org/hello-dns/)' documentation effort.

# teaching DNS: Library, Authoritative, Resolver
Welcome to tdns, a 'from scratch' teaching DNS library.  Based on `tdns`,
[`tauth`](tauth.md.html) and [`tres`](tres.md.html) implement all of [basic
DNS](../basic.md.html) and large parts of DNSSEC in ~~2000~~ ~~3000~~ 3100
lines of code.  Code is
[here](https://github.com/ahupowerdns/hello-dns/tree/master/tdns).  To
compile, see the end of this document.

Even though the 'hello-dns' documents describe how basic DNS works, and how
servers should function, nothing quite says how to do things
like actual running code.  `tdns` is small enough to read in one sitting and
shows how DNS packets are parsed and generated.  `tdns` is currently written
in C++ 2014, and is MIT licensed.  Reimplementations in other languages are
highly welcome, as these may be more accessible to other programmers. 

Please contact bert.hubert@powerdns.com or
[@PowerDNS_Bert](https://twitter.com/PowerDNS_Bert) if you have plans or
feedback.

The goals of `tdns`, `tauth` & `tres` are:

 * Showing the DNS algorithms 'in code'
 * Protocol correctness, except where the protocol needs updating
 * Suitable for educational purposes
 * Display best practices, both in DNS and security
 * **Be a living warning for how hard it is to write a nameserver correctly**

Non-goals are:

 * Performance
 * Implementing more features (unless very educational)
 * DNSSEC signing, validation

A more narrative explanation of what `tdns` is and what we hope it will
achieve can be found [here](intro.md.html).

The code for `tdns` can be found on [GitHub](https://github.com/ahupowerdns/hello-dns/blob/master/tdns/) and is also documented 
using [Doxygen](codedocs/html).

# Objects in `tdns`
These are found in [dns-storage.hh](https://github.com/ahupowerdns/hello-dns/blob/master/tdns/dns-storage.hh)
and
[dns-storage.cc](https://github.com/ahupowerdns/hello-dns/blob/master/tdns/dns-storage.hh).

## DNSLabel
The most basic object in `tdns` is DNSLabel. `www.powerdns.com` consists of
three labels, `www`, `powerdns` and `com`. DNS is fundamentally case
insensitive (in its own unique way), and so is DNSLabel. So for example:

```
	DNSLabel a("www"), b("WWW");
	if(a==b) cout << "The same\n";
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

Note: for convenience, when parsing human-generated input, `makeDNSName()`
is available to make a DNSName from a string.

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
These is an enums that contains the names and numerical values of the DNS
types and error codes.  This means for example that `DNSType::A` corresponds
to 1 and `DNSType::SOA` to 6.

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

## `tdig`
To discover how `tdns` works, let's start with the basics: sending DNS
queries and parsing responses. For this purpose, the `tdig` tool is
provided, somewhat modelled after the famous `dig` program created by ISC.

The code:
``` C++ linenumbers
	int main(int argc, char** argv)
	{
		/* ... */
		DNSName dn = makeDNSName(argv[1]);
		DNSType dt = makeDNSType(argv[2]);
		ComboAddress server(argv[3]);

		DNSMessageWriter dmw(dn, dt);
		dmw.dh.rd = true;
		dmw.setEDNS(4000, false);
```

This starts out with the basics: it reads a `DNSName` from the first
argument to `tdns`, a `DNSType` from the second and finally a server IP
address from the third argument.

With this knowledge, in line 8 we create a `DNSMessageWriter` to make a
question for query name `dn` and query type `dt`. In addition, we set the
'recursion desired' flag. 

Finally on line 10, we indicate our support for up to 4000 byte responses,
but we set the 'DNSSEC Ok' flag to false.

Next, mechanics:

``` 
1	Socket sock(server.sin4.sin_family, SOCK_DGRAM);
2	SConnect(sock, server);
3	SWrite(sock, dmw.serialize());
4	string resp = SRecvfrom(sock, 65535, server);
5
6	DNSMessageReader dmr(resp);
```

In line 1 we create a datagram socket appropriate for the protocol of
`server`. This is based on a small set of socket wrappers called
[simplesockets](https://github.com/ahuPowerDNS/simplesocket). On line 2 we
connect and on line 3 we serialize our DNSMessageWriter and send the
resulting packet. On line 4 we receive a response.

Finally on line 6 we parse that response into a `DNSMessageReader`.

```
1	DNSSection rrsection;
2	uint32_t ttl;
3 
4	dmr.getQuestion(dn, dt);
5	
6	cout<<"Received " << resp.size() << " byte response with RCode ";
7	cout << (RCode)dmr.dh.rcode << ", qname " << dn << ", qtype " << dt << endl;
8	std::unique_ptr< RRGen > rr;
9	while(dmr.getRR(rrsection, dn, dt, ttl, rr)) {
10	  cout << dn<< " IN " << dt << " " << ttl << " " << rr->toString() << endl;
11	}
```

On lines 1 and 2 we declare some variable we'll need later to actually
retrieve the resource records. On line 4 we retrieved the name and type we
received an answer for, and on line 6 this all is displayed.

Line 8 declares 'rr' ready to receive our Resource Records, which are then
retrieved using the `getRR` method from the `DNSMessageReader` on line 9.

On line 10 we print what we found. Note that the `RRGen` object helpfully
has a `toString()` method for human friendly output.




# Parsing and generating DNS Messages
This code is in [dnsmessages.cc](https://github.com/ahupowerdns/hello-dns/blob/master/tdns/dnsmessages.cc)
and [dnsmessages.hh](https://github.com/ahupowerdns/hello-dns/blob/master/tdns/dnsmessages.hh).

## `RRGen`s: dealing with all the record types
DNS knows many record types, so we need a unified interface that can pass
all of them. For this purpose, `tdns` uses `RRGen` instances. `RRGen`s are
classes, one for each record type, all deriving from the `RRGen` base.

Each `RRGen` has a method called `toString()` which emits the record's
contents in familiar 'zonefile' format. 

`RRGen`s can be created using their specific instance types, for example
like this:

```
	ComboAddress ip("203.0.113.1");
	auto agen = AGen::make(ip);

	cout << agen->toString() << endl; // prints 203.0.113.1

	auto soagen = SOAGen::make({"ns1", "powerdns", "com"}, 
		{"bert.hubert", "powerdns", "com"}, 2018102301);
```

`RRGen`s also know how to serialize themselves from a `DNSMessageReader`, or how to
write themselves out to a `DNSMessageWriter`.

When reading DNS Messages (see below), `DNSMessageReader::getRR()` will
return `RRGen` instances to you, if you want to do more than print their
contents, you need to cast them to the specific type, for example:

```
  ComboAddress ret;
  ret.sin4.sin_family = 0;
  if(auto ptr = dynamic_cast<AGen*>(rr.get()))
    ret=ptr->getIP();
  else if(auto ptr = dynamic_cast<AAAAGen*>(rr.get()))
    ret=ptr->getIP();
```

This code from `tres` checks if a record is an IP or IPv6 address and
extracts the IP address - all without using ASCII.

## DNSMessageReader
This class reads a DNS message, and makes available:
 
 * The query name (qname) and type (qtype)
 * The dnsheader containing the flags
 * EDNS buffer size and value of DNSSEC Ok flag

Of specific security note, this is one area where we might potentially have
to do pointer arithmetic. For security purposes, `DNSMessageReader` uses
bounds checking access methods exclusively.

Somewhat unexpectedly, parsing a packet does not immediately give the user
access to the query and type of the query (or response). The reason for this
is that there are packets that have no query defined. So to get the query,
call `getQuery()`.

Getting resource records from a `DNSMessageReader` happens via `getRR` which
returns record details and a smart pointer to an `RRGen` instance (as
described above). 

A good example of how `DNSMessageReader` works can be found in
[`tdig.cc`](https://github.com/ahupowerdns/hello-dns/blob/master/tdns/dns-storage.hh).

## DNSMessageWriter
This class creates DNS messages, and in its constructor it needs to know the
name and type it is creating a message for.

Packets are only written in order. So it is not possible to
change the `qname` after adding a resource record. Resource records must
also be added together as RRSets, and in 'section order'.

Internally `DNSMessageWriter` again only uses bounds checked methods for
modifying its state.

A `DNSMessageWriter` has a maximum length (set via its constructor).  If new
resource record, as written by `putRR`, would exceed this maximum length,
that record is rolled back and a std::out_of_range() exception is thrown. 
This allows the caller to either truncate or decide this data was optional
anyhow.

Writing actual records to DNSMessageWriter proceeds via `putRR()` which
serializes `RRGen` instances to the message.

Samples of how to do this can be found in
[tres.cc](https://github.com/ahupowerdns/hello-dns/blob/master/tdns/dns-storage.hh)
and
[tauth.cc](https://github.com/ahupowerdns/hello-dns/blob/master/tdns/dns-storage.hh).

### Compression
DNS compression is unreasonably difficult to get right. In what happens to
be a coincidence, it turns out the DNS Tree can also be used to perform
DNS name compression.

For every invocation of `putName()` in `DNSMessageWriter()` we check the DNS
tree if it has a match on the full name, and if not, we add the name
and its components of the name to a DNS tree. 

This effectively gets us the desired compression behaviour, except special
care has to be taken to not do wildcard processing.

## EDNS and truncation
EDNS tells us that a larger buffer size is available. However, even with
such a larger buffer size, a packet may exceed the available space. In that
case, the standard tells us to truncate the packet, and then still put an
EDNS record in the response.

The DNSMessageWriter, in somewhat of a layering violation, takes care of
this in `serialize()`.


# Internals
`tdns` uses several small pieces of code not core to dns:

 * [nenum](https://github.com/ahupowerdns/hello-dns/blob/master/tdns/nenum.hh)
   this is a simple 'named ENUM' construct that enables the printing of
   DNSName::A
 * [Simplesocket](https://github.com/ahupowerdns/simplesocket) a small set
   of convenience functions for making sockets, parsing IP addresses etc.
 * [Catch2](https://github.com/catchorg/Catch2) a unit test framework

# Compiling and running tdns
This requires a recent compiler version that supports C++ 2014. If you
encounter problems, please let me know (see above for address details).

```
$ git clone https://github.com/ahupowerdns/hello-dns.git
$ cd hello-dns/tdns
$ git submodule init
$ git submodule update
$ make
$ ./tauth [::1]:5300 &
$ dig -t any time.powerdns.org @::1 -p 5300 +short 
time.powerdns.org.	3600	IN	TXT	"The time is Fri, 13 Apr 2018 12:55:54 +0200"
```

For more detauls, read on about [`tauth`](tauth.md.html), [`tres`](tres.md.html)
or the [C API](c-api.md.html).

<script>
window.markdeepOptions={};
window.markdeepOptions.tocStyle = "long";
</script>
<!-- Markdeep: --><style class="fallback">body{visibility:hidden;white-space:pre;font-family:monospace}</style><script src="../ext/markdeep.min.js"></script><script>window.alreadyProcessedMarkdeep||(document.body.style.visibility="visible")</script>
