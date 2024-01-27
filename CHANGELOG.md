# CHANGELOG

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [unreleased]

## TODO for [v0.0.1]

### General items
- [ ] use Logger throughout all modules

### DNS
- [x] handle timeout & retries in Dns.resolve
- [x] handle a list of nameservers to try, rather than one
- [x] handle retries when using multiple nameservers
- [ ] add DNSSEC validation code
- [x] in DNS.ex rename ctx to ctx, since ctx is limiting to options while
      context (ctx) is more logical & storing additional stuff is less weird
- [x] recurse or not to recurse?
      1. caller supplies nameserver(s)
         - recurse=false, query sent with RD-bit as set by caller
      2. caller does not supply namerserver(s)
         - recurse=true, DNS.resolve sends queries with RD=0
      Note: RD defaults to 1, so if caller wants to query public, recursive,
      resolvers RD is already 1.  If caller sets RD=0 in this case, she should
      be aware that e.g. 1.1.1.1/9.9.9.9 will servfail, while 8.8.8.8 happily
      recurses for her and supplies an answer.
      See also:
      - https://blog.cloudflare.com/black-lies/
      - https://datatracker.ietf.org/doc/html/draft-valsorda-dnsop-black-lies
      - https://www.ietf.org/rfc/rfc4470.txt (white lies)
- [x] dname_normalize should handle escaped chars, see RFC4343
- [ ] add an option for IPv4 only (maybe resolver is on an ipv4 only network)
      or maybe check interfaces on machine we're running on
      :inet.getifaddrs/0 yields info on IP addresses in use on the machine
      `-> add :ip4/:ip6 capabilities & use that to select/filter NSs
- [x] query (hdr) should take opcode as parameter that defaults to QUERY
- [x] change iana.update hints -> store hints as [{:inet.ip_address, 53}], and
      use Code.eval_file("priv/root.nss") here (so priv/root.nss is readable)
- [c] sort the root hints fastest to slowest RTT
- [x] randomize NSs for root.nss each time they're used
- [ ] add time spent to result of resolve (plus last NS seen?),
      stats: qtime = total, qrtt = last NS, qtstamp = timestamp, ns, port, rxsize (bytes received)
- [ ] add check when recursing to see if delegated NSs are closer to QNAME
      if not, ignore them as bogus (use label match count as per rfc?)
- [ ] store IP addresses as tuples in Msg components, right now there is lot
      of needless conversions between binary & tuples.
- [ ] likewise, there is a lot of dname_normalize'ing for the same name going on
- [x] add spec to resolve, detailing all possible error reasons
- [x] resolve must try to answer from cache first and response_make
- [ ] detect when a referral omits required glue records -> drop the NS
      referred to
- [?] detect when a NS refers to an alias instead of a canonical name
      warn (!). BIND drops the NS, PowerDNS/Knot simple resolve it.
- [x] if qname is ip address, convert it to reverse ptr name
- [x] query for NS names in aut section (ex. tourdewadden.nl)
- [ ] detect NS loops => need a working solution
      normal referral                  lame referral
      q -> NSS0 -> zone1 + NSS1        q -> NSS0 -> zone1 + NSS1
      q -> NSS1 -> zone2 + NSS2        q -> NSS1 -> zone2 + NSS2
      q -> NSS2 -> answer              q -> NSS2 -> zone1 + NSS1
      So {q, zone<x>} MUST only happen once!
      Note that during recursing, a set of NNSx may be visited more
      than once when resolving NS records for their A/AAAA records!
      Note that zone<x> may come back in different cases
      Note that loop protection goes across recursion boundaries => ctx!
- [ ] detect CNAME loops => ditto, need a working solution
      q  -> NSS0 -> c1 [NSS + A/AAAA if possible]
      c1 -> NSSx -> c2
      c2 -> c1
      So {q, c<x>} MUST only happen once!
      Note that c<x> may come back in different cases
      Note that loop protection goes across recursion boundaries => ctx!
- [ ] responses must be better evaluated in query_nss
      - including extra validation rules for msg's (e.g. max 1 :OPT in additional, TSIG
        at the end, etc...)
- [ ] check that resolve's {:error, reason} typespec is actually correct!
      {:ok, msg} means successful reply that is deemed a valid answer
      might still be NODATA -> needs a public response_type/1
      How about: @spec resolve(..) :: {:ok, msg} | {:error, {reason, msg | DNS.MsgError.t}}
      Some :error situations could include: {:nodata, msg}, {:nxdomain, msg},
      {:eencode, DNS.MsgError), {:edecode, DNS.MsgError} etc ...
- [x] dname encoding/decoding etc.. should support escaped dots like \\. in a label
- [x] randomize each nss set upon resolving/recursing (less predictable)
- [?] NSS storage/retrieval -> donot query for all new NSS, just the first
      one and later, when trying others, query for their address
- [ ] add negative caching
- [x] do Cache.put(msg) in only one place (in handle response?)
- [?] add resolve/1 for resolve("name") and resolve("10.10.10.10") and resolve({1,1,1,1})
      it will always ask for A & AAAA or PTR RR's
- [?] resolve should return {:ok, {xrcode, msg}} | {:error, {:reason, msg}}
      `-> FIXME: this @spec & make response_make respond accordingly
- [x] add resolvep which can be called with ctx instead of opts
      allows recursion with loop protection in ctx when following a cname chain
      ditto for following referrals (ctx.referrals & ctx.cnames)
      additional purpose is that these donot have to be included in opts as a
      hidden option. Caller's call to resolve(..opts) always starts fresh,
      during iteration call resolvep(.., ctx) so history is preserved and loops
      detected.

### DNS.Msg
- [ ] accessor functions for `t:DNS.Msg.t/0` struct.
      Alternative to hd(msg.question).name etc ...
- [ ] documentation
- [ ] implement List.Chars.to_string (eh... why was that again?)
- [ ] unit tests
- [x] clean up lib/dns/msg.ex and move funcs to lib/dns.ex

### DNS.Msg.Hdr
- [x] documentation
- [x] unit tests
- [ ] implement List.Chars.to_string

### DNS.Msg.Qtn
    - [x] documentation
    - [x] unit tests
    - [ ] implement List.Chars.to_string

### DNS.Msg.RR
- [x] documentation
- [ ] implement List.Chars.to_string
- [x] unit tests
- [x] get a bunch of rdata de/encoders for relevant RR's
- [x] move MsgXYZ into DNS.Msg.Xyz and files under lib/dns/msg/xyz.ex


### DNS.Msg.Terms
- [ ] add tcp/udp services lookup: nr -> proto name (for presentation only)
- [ ] add all/more RR types, not just the ones supported by en/de-coding
- [x] documentation
- [x] unit tests


### DNS.Cache
- [!] DS does appear in msg.authority in case of a referral
- [ ] cache negative answers
- [ ] use max for TTL if exceptionally large
- [ ] retrieval should support DO=1, if cache has no DNSSEC records,
      then return cache miss, even if insecure record is available
- [ ] msg.aut may contain: SOA, NS, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM?
- [x] also cache *relevant* add records when msg is referral
- [ ] response answer-RRs from AA=1 response are preferred over cached RRs
     - means put(RR) probably should be a private func and user should
       always use put(qry, rsp) so qry.hdr/qtn section can be compared
     - AA-bit is not stored w/ RRs in cache, so if rsp AA=1, always replace
     - otherwise hang onto RRs with largest amount of time remaining since RRs
           from AA=0 might come from some other cache where they lived a long time
- [ ] Need to detect when cached answer doesn't match DO-bit (both ways)
      and respond accordingly

### DNS.Utils
- [c] initialize cache with root name servers (query via priv/named.root.rrs)
- [x] maybe add nss(domain name) -> searches the cache?
- [ ] handle put_msg better!
- [x] clear rdata/wdata before caching if not raw
- [x] should we cache RR's with wildcard domain names? -> NO!
- [ ] cache negative responses, but NXDOMAIN has only a SOA in aut
- [?] prime the cache using DNS.resolve & root hints
-     see https://datatracker.ietf.org/doc/draft-ietf-dnsop-rfc8109bis/
- [x] shuffle NSs around before handing off

### Dnscheck
- [ ] documentation
- [ ] tests
- [ ] cli to handle commands
- [ ] commands as workers

