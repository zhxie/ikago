# IkaGo

**IkaGo** is a proxy which turns UDP traffic to TCP traffic written in Go.

*IkaGo is currently under development and is not suitable for production.*

## Features

- Cross platform

## Usage

```
# Client
go run client.go -f [filters] -s [address:port]

# Server
go run server.go -p [port]
```

`-list-devices`: (Optional, exclusively) List all valid pcap devices in current computer.

`-listen-loopback-device`: (Client only, optional) Listen loopback device only.

`-listen-devices devices`: (Client only, optional) Designated pcap devices for listening, use comma to separate multiple devices. If this value is not set, all valid pcap devices will be used.

`-upstream-loopback-device`: (Optional) Route upstream to loopback device only.

`-upstream-device device`: (Server only, optional) Designated pcap device for routing upstream to. If this value is not set, the first valid pcap device with the same domain of gateway will be used.

`-ipv4-device`: (Optional) Use IPv4 device only.

`-ipv6-device`: (Optional) Use IPv6 device only.

`-f filters`: (Client only) Filters, use comma to separate multiple filters, must not contain the server. A filter may an IP, an IP port endpoint, or a port starts with a colon.

`-p port`: (Server only) Port for listening.

`-upstream-port port`: (Client only, optional) Port for routing upstream, must be different with any port filter. If this value is not set or set as 0, a random port from 49152 to 65535 will be used.

`-s address:port`: (Client only) Server.

## Todo

- [x] Support TCP proxy
- [x] Support UDP proxy
- [ ] Test NAT using STUN
- [ ] Test latency
- [x] Use filters instead of listen port
- [ ] Retransmission and out of order packets detection
- [ ] Handle packets with unrecognizable transport layer
- [ ] Log
