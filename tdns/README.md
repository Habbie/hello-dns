                <meta charset="utf-8" emacsmode="-*- markdown -*-">
                            **A warm welcome to DNS**
<link rel="stylesheet" href="https://casual-effects.com/markdeep/latest/apidoc.css?">

# teaching DNS
Welcome to tdns, the teaching authoritative server, implementing all of
basic DNS in ~~1000~~ 1100 lines of code.

The goals of tdns are:

 * Protocol correctness
 * Suitable for educational purposes
 * Display best practices

Non-goals are:
 * Performance
 * Implementing more features

# Current status
Features are complete:

 * A, AAAA, NS, MX, CNAME, TXT, SOA
 * UDP & TCP
 * AXFR
 * Wildcards
 * Delegations
 * Glue records
 * Truncation

Missing:
 * Compression (may not fit in the 1000 lines!)
 * EDNS (not 'basic' DNS by our definition, but ok)

Known broken:
 * Embedded 0s in DNS labels don't yet work
 * Case-insensitive comparison isn't 100% correct 
 * RCode after one CNAME chase
 * On output (to screen) we do not escape DNS names correctly
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

## The DNS Tree
The DNS Tree is of fundamental importance, and is used a number of times
within `tdns`.

When storing data for the org zone, it may look like this:

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

This three has a depth of four. The top node has an empty name, and is
relative to the name of the zone, in this case `org`.

On layer 4, we find the names `ns1.ord.ietf.org` and `ns2.fra.ietf.org`. Key
to looking up anything in DNS is to follow the tree downwards and to observe
what nodes are passed.

For example, a lookup for `www.ietf.org` starts as a lookup for `www.ietf`
in the `org` zone (if loaded, of course). Layer 1 is where we start, and we
look if there is a child node called `ietf`. And there is.

As we look at that node, we could see NS records attached to it (`ietf.org NS
ns1.ord.ietf.org`) for example. This means our lookup is done: we've found
a zonecut. The authoritative server should now respond with a delegation by
returning those NS records in the Nameserver section.

To complete the packet, we need to look up the IPv4 and IPv6 addresses of
`ns1.ord.ietf.org` and `ns2.fra.ietf.org`. To do this, we traverse the tree
downward again, starting at the apex with `ns1.ord.ietf` and going to the
`ietf`, `ord` and finally `ns1` labels. There we find attached the IP(v6)
addresses.

TBC..


 This is implemented in `dns-storage.cc` and `dns-storage.hh`. 

This lookup mechanism will tell you if a name is fully present in a zone, or
if it was matched by an NS record. It will also perform wildcard matching,
but not CNAME chasing.

# Best practices
The code does not do any form of DNS escaping. Instead, DNS names are stored
and manipulated as a sequence of DNS labels. So instead of messing with
"www.powerdns.org", we use {"www", "powerdns", "org"}. 

<!-- Markdeep: --><style class="fallback">body{visibility:hidden;white-space:pre;font-family:monospace}</style><script src="../ext/markdeep.min.js"></script><script>window.alreadyProcessedMarkdeep||(document.body.style.visibility="visible")</script>