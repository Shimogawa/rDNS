# rDNS

A **trash** DNS resolver written in Rust. Together with this implementation
is the library to deal with DNS packets.

Currently it should be able to deal with every RR types, but just is not
able to analyze/extract fields of the not implemented ones.

## Progress

Something not done:

- [x] ~~caching~~
- [ ] domain name compression
- [ ] more record types
- [ ] DNSSEC
