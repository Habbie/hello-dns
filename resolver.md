                <meta charset="utf-8" emacsmode="-*- markdown -*-">
                            **A warm welcome to DNS**

# Resolver
Writing a modern resolver is the hardest part of DNS. A fully standards
compliant DNS resolver is not a resolver that can be used in practice.

In reality, resolvers are expected to process malformed queries coming from
clients (stub-resolvers).  Furthermore, many authoritative servers respond
incorrectly to modern DNS queries.  Zones are frequently misconfigured on
authoritative servers but still expected to work correctly.

Meanwhile, operators desire top performance, with individual CPU cores
expected to satisfy the DNS needs of hundreds of thousands of users.

To top this off, a modern DNS resolver will have to validate DNSSEC
correctly. This may be among the hardest challenges of any widely used
Internet protocol.

So in short, before attempting to write a DNS resolver, ponder if you really
need to.

TBC..

<!-- Markdeep: --><style class="fallback">body{visibility:hidden;white-space:pre;font-family:monospace}</style><script src="ext/markdeep.min.js"></script><script>window.alreadyProcessedMarkdeep||(document.body.style.visibility="visible")</script>
