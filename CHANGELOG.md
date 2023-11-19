# CHANGELOG

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [unreleased]

### TODO

- [ ] DNS.Msg
    - [ ] documentation
    - [ ] tests
    - [ ] accessor functions for `t:DNS.Msg.t/0` struct.
    - [x] clean up lib/dns/msg.ex and move funcs to lib/dns.ex
- [ ] DNS.Msg.Hdr
    - [ ] documentation
    - [ ] tests
- [ ] DNS.Msg.Qtn
    - [ ] documentation
    - [ ] tests
- [ ] DNS.Msg.RR
    - [ ] documentation
    - [ ] tests
    - [x] get a bunch of rdata de/encoders for relevant RR's
    - [x] move MsgXX into DNS.Msg.xx and files under lib/dns/msg/xx.ex
- [ ] DNS
    - [ ] handle timeout & retires in Dns.resolve
    - [ ] handle a list of nameservers to try, rather than one
    - [ ] handle retries when using multiple nameservers
    - [ ] add DNSSEC validation code
- [ ] Dnscheck
    - [ ] documentation
    - [ ] tests
    - [ ] cli to handle commands
    - [ ] commands as workers

