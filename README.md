# DNS64 for yggdrasil network

A simple DNS64 proxy written in go based on [github.com/miekg/dns](https://github.com/miekg/dns)

Unlike 'regular' DNS64 servers, it does not return a 'white' IPv6 address even if one exists. However, if there is an AAAA record with the yggdrasil address, it returns that specifically.

## Fork

Features added compared to the original [ufm/yggdns64](https://github.com/ufm/yggdns64):

- Docker builds
- Binary builds
- More flexible configuration for forwarders and prefix translation

### TODOs
- [x] Add pipeline for docker builds
- [x] Add pipeline for binary builds
- [x] Config rework
- [ ] Support TCP
- [x] Forward query to multiple upstreams