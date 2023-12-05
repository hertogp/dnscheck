# CHANGELOG

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [unreleased]

### TODO

- [ ] DNS.Msg
    - [ ] accessor functions for `t:DNS.Msg.t/0` struct.
    - [ ] documentation
    - [ ] implement List.Chars.to_string
    - [ ] unit tests
    - [x] clean up lib/dns/msg.ex and move funcs to lib/dns.ex
- [ ] DNS.Msg.Hdr
    - [ ] documentation
    - [ ] unit tests
    - [ ] implement List.Chars.to_string
- [ ] DNS.Msg.Qtn
    - [x] documentation
    - [x] unit tests
    - [ ] implement List.Chars.to_string
- [ ] DNS.Msg.RR
    - [x] documentation
    - [ ] implement List.Chars.to_string
    - [x] unit tests
    - [x] get a bunch of rdata de/encoders for relevant RR's
    - [x] move MsgXYZ into DNS.Msg.Xyz and files under lib/dns/msg/xyz.ex
- [ ] DNS.Msg.Terms
    - [x] documentation
    - [x] unit tests
- [x] DNS.Msg.Fields
    - [x] documentation
    - [x] unit tests
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

