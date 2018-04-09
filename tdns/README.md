# teaching DNS
Welcome to tdns, the teaching authoritative server, implementing all of
basic DNS in 1000 lines of code.

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

Missing:
 * Truncation
 * Compression (may not fit in the 1000 lines!)
 * EDNS (not 'basic' DNS by our definition, but ok)

Known broken:
 * Embedded 0s in DNS labels don't yet work
 * Case-insensitive comparison isn't 100% correct 
 * RCode after one CNAME chase
 * On output (to screen) we do not escape DNS names correctly

The code is not yet in a teachable state, and the layout is somewhat
confusing: some stuff is in the wrong files.

# Layout
Key to a good DNS implementation is having a faithful DNS storage model.
Over the decades, many many nameservers have started out with an incorrect
storage model, leading to pain later on with empty non-terminals, setting
the 'AA' bit on glue (or not) and eventually DNSSEC ordering problems.

When storing DNS as a tree, as described in RFC 1034, a lot of things go
right "automatically".

The core or `tdns` therefore is the tree of nodes as intended in 1034. This
is implemented in `dns-storage.cc` and `dns-storage.hh`. 

This lookup mechanism will tell you if a name is fully present in a zone, or
if it was matched by an NS record. It will also perform wildcard matching,
but not CNAME chasing.

# Best practices
The code does not do any form of DNS escaping. Instead, DNS names are stored
and manipulated as a sequence of DNS labels. So instead of messing with
"www.powerdns.org", we use {"www", "powerdns", "org"}. 
