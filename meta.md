                <meta charset="utf-8" emacsmode="-*- markdown -*-">
                            **A warm welcome to DNS**
Note: this page is part of the
'[hello-dns](https://powerdns.org/hello-dns/)' documentation effort.

# The why and what of these documents
There are now between 1500 and 3000 pages of RFC documents describing DNS,
containing around 1700 'MUST' statements.

Not only are there a lot of documents, the earlier ones are not that easy to
read for newcomers, and contain a lot of obsoleted baggage that new readers
do not know they can skip.

Inspired by the wonderful books by W. Richard Stevens (like [TCP
Illustrated](https://en.wikipedia.org/wiki/TCP/IP_Illustrated), UNIX Network
Programming, Advanced Programming in the UNIX Environment), the goal of
these documents is to make DNS far more accessible, in an authoritative way.

In other words, everything in these documents should be correct. But not
everything that is in the RFCs will be in these documents. 

Specifically, we steer clear of obsoleted protocol elements.  We also
simplify DNS by not introducing obscure elements needlessly, except maybe in
a footnote. If there are three ways to do something, and one is common, this
should be written something like 'To do X, it is recommended to do Y'. This
is not a lie, but also does not confuse the reader with obscure option Z.

Richard Stevens mastered the art of writing sentences that left out as much
as possible, while still not misleading or underinforming the reader, and
this is the inspiration for the "Welcome to DNS series".

# Status
Currently only the basic introduction has been written, and it is an early
form: it probably lacks some parts, and the parts that are there need
tightening.

Pull requests welcome!

# Specific notes
The introduction of DNS really starts with the very bare bones. No EDNS, no
DNSSEC, no servers that serve both authoritative and cached data. Even zone
files are described only briefly, since these are not required to write a
functioning nameserver.

It may be tempting to insert fun features like EDNS into the early document,
for fear that readers might not make it to the advanced sections. We must
resist this urge. Further complicating the beginning of the documents
guarantees users will not make it to the end.

Also, this document is a 'reader' to the standards documents. That means
that different language is used: as precise as required, but not so precise
that the documents are no longer fun or easy to read. We should resist the
urge to write 'standardese'  here.


<!-- Markdeep: --><style class="fallback">body{visibility:hidden;white-space:pre;font-family:monospace}</style><script src="ext/markdeep.min.js"></script><script>window.alreadyProcessedMarkdeep||(document.body.style.visibility="visible")</script>

