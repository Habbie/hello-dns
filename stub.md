# Stub resolvers, applications
As a client of DNS, life is relatively easy. You can use operating system
functions like `gethostbyname()` or `getaddrinfo()`, and these will take
care of everything for you, including applying local overrides and policy.

This may not always be what you want, or you may in fact be reading this
because you need to implement those functions.

In either case, what you are attempting to become is called a 'stub
resolver'. This is assumed to be a very simple DNS client that sends out DNS
queries and receives ready to use answers in response.

And this is indeed true. A stub resolver should not do anything exciting
beyond sending queries and parsing responses. 

It should specifically not process any NS records or even chase CNAMEs. The
resolver a stub talks to should take care of everything.

XXX - where does it say so?

A few things do matter. For security purposes, the stub resolver must take
good care to fully randomize source port and ID fields. It must also guard
against sending out multiple equivalent queries at the same time as this
would allow a 'birthday attack' that could spoof in harmful answers.

It is also important to actually test the TC=1 response path, something that
may be triggered when sending queries that lead to huge answers.

If a resolver sends out two different questions in parallel, like for A and
AAAA of a name, it should be prepared to receive responses out of order -
even over TCP!

<!-- Markdeep: --><style class="fallback">body{visibility:hidden;white-space:pre;font-family:monospace}</style><script src="ext/markdeep.min.js"></script><script>window.alreadyProcessedMarkdeep||(document.body.style.visibility="visible")</script>
