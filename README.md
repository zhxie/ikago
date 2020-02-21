# IkaGo

**IkaGo** is a proxy which turns UDP traffic to TCP traffic written in Go.

*IkaGo is currently under development and is not suitable for production.*

## Features

- Cross platform

## Usage

```
go run ikago.go [-list-devices] [-local-only] [-d device] -p [port] -s [address:port]
```

`-list-devices`: (Optional, Exclusively) List all valid pcap devices in current computer.

`-listen-local`: (Optional) Listen loopback device only.

`-local`: (Optional) Route upstream to loopback device.

`-d device`: (Optional) Route upstream to designated pcap device.

`-p port`: Port for listening.

`-s address:port`: Server.

## Todo

- [ ] Support TCP proxy
- [ ] Support UDP proxy using [FakeTCP](https://github.com/wangyu-/udp2raw-tunnel)
- [ ] Test NAT using STUN
- [ ] Test latency
