# Intro

xxx

## SOA Records
There is only one SOA that is guaranteed to exist on the internet and that
is the one for the root zone (called '.').  As of 2018, it looks like this:

```
.   86400   IN   SOA   a.root-servers.net. nstld.verisign-grs.com. 2018032802 1800 900 604800 86400
```

For details of what all these fields mean, please see the [authoritative
server document](auth.md).
 
This says: the authoritative server for the root zone is called
'a.root-servers.net'. This name is however only used for diagnostics.
Secondly, nstld@verisign-grs.com is the email address of the zone
maintainer. Note that the '@' is replaced by a dot. Specifically, if the
email address had been 'nstld.maintainer@verisign-grs.com', this would have
been stored as nstld\\.maintainer.verisign-grs.com. This name would then
still be 3 labels long, but the first one has a dot in it.

The following field, 2018032802, is a serial number.  Quite often, but by
all means not always, this is a date in proper order (YYYYMMDD), followed by
two digits indicating updates over the day.  This serial number is used for
replication purposes, as are the following 3 numbers.

Zones are hosted on 'masters'. Meanwhile, 'slave' servers poll the master
for updates, and pull down a new zone if they see new contents, as noted by
an increase in serial number.

The numbers 1800 and 900 describe how often a zone should be checked for
updates (twice an hour), and that if an update check fails it should be
repeated after 900 seconds.  Finally, 604800 says that if a master server
was unreachable for over a week, the zone should be deleted from the slave.
This is not a popular feature.

The final number, 86400, denotes that if a response says a name or RRSET
does not exist, it will continue to not exist for the next day, and that
this knowledge may be cached.
