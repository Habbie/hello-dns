                <meta charset="utf-8" emacsmode="-*- markdown -*-">
                            **A warm welcome to DNS**
<!--<link rel="stylesheet" href="https://casual-effects.com/markdeep/latest/apidoc.css?">-->
Note: this page is part of the
'[hello-dns](https://powerdns.org/hello-dns/)' documentation effort.

# teaching Resolver
Welcome to `tres`, a 'from scratch' teaching resolver,
implementing a basic resolver in 500 lines of code.  Code is
[here](https://github.com/ahupowerdns/hello-dns/tree/master/tdns).  To
compile, see the end of this document.

Even though the 'hello-dns' documents describe how basic DNS works,  nothing
quite says how to do things like actual running code.  `tres` is small
enough to read in one sitting and shows how DNS packets are parsed and
generated.  `tres` is currently written in C++ 2014, and is MIT licensed. 
Reimplementations in other languages are highly welcome, as these may be
more accessible to other programmers.

Please contact bert.hubert@powerdns.com or
[@PowerDNS_Bert](https://twitter.com/PowerDNS_Bert) if you have plans or
feedback.

The goals of `tres` are:

 * Showing the DNS resolver algorithm 'in code'
 * Protocol correctness, except where the protocol needs updating
 * Suitable for educational purposes
 * Display best practices, both in DNS and security
 * **Be a living warning for how hard it is to write a resolver correctly**

Non-goals are:

 * Performance
 * Implementing more features (unless very educational)
 * DNSSEC
 * Resolving domains that are broken.

A more narrative explanation of what `tdns` is and what we hope it will
achieve can be found [here](intro.md.html).

# Current status
`tres` can be used to browse the web successfully.  All popular domains
work.  The code is not quite in a teachable state yet and still contains
some ugly bits.  But well worth [a
read](https://github.com/ahupowerdns/hello-dns/blob/master/tdns/tres.cc).

# Infrastructure
`tres` uses the same DNS packet parsing/generating code as the `tdns`
authoritative server. For details, please see [its
documentation](README.md.html). 

# Algorithm
`tres` implements a straightforward resolving algorithm. 

## Hints
Resolvers should come with a list of nameserver IP addresses that function
as 'hints'. The idea is that if at least one of the hint IP addresses is
still in operation, the full set of Internet root-servers can be retrieved.

`tres` has its hints compiled in. Customarily, resolvers are expected to be
able to read hints from a file at startup.

`tres` asks the hint IP addresses for the NS records for the root zone, and
expects to receive A and AAAA records for the root-servers in return. 

## Resolving names
To resolve a name (for a given type), a query for it is sent to the root
servers. These will in general not know the answer, but will provide a
delegation to other nameservers, typically with glue that provides IP
addresses.

`tres` will try to use that glue to follow the delegation, and this
generally succeeds. If it doesn't the resolving algorithm itself is used to
resolve addresses of the nameserver names we do have.

## Trace output
When run in single-shot mode (ie, `./tres www.powerdns.org A`), a file
called `plot.dot` is created. Using `graphviz`, this can be turned into a
pretty diagram like this:

```
dot -Tpng plot.dot > plot.png
```

# Further details
The `tres` source code is less than 500 lines of code, so it is suggested to
read it from [beginning to end](tres.cc). The code may make more sense after
first having studied the inner workings of the `tdns` authoritative server,
which is described [here](README.md.html).

# Compiling and running tres
This requires a recent compiler version that supports C++ 2014. If you
encounter problems, please let me know (see above for address details).

```
$ git clone --recursive https://github.com/ahupowerdns/hello-dns.git
$ cd hello-dns/tdns
$ make -j4 tres
$ ./tres www.powerdns.org A
...
Result or query for www.powerdns.org.|A
www.powerdns.org. 3600 CNAME powerdns.org.
www.powerdns.org. 3600 A 52.48.64.3
Used 10 queries
```

To use as a network service, run:
```
# ./tres 127.0.0.1:53
```
<script>
window.markdeepOptions={};
window.markdeepOptions.tocStyle = "long";
</script>
<!-- Markdeep: --><style class="fallback">body{visibility:hidden;white-space:pre;font-family:monospace}</style><script src="../ext/markdeep.min.js"></script><script>window.alreadyProcessedMarkdeep||(document.body.style.visibility="visible")</script>
