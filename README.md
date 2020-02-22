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

`-listen-devices devices`: (Optional) Designated pcap devices for listening, use comma to separate multiple devices. If this value is not set, all valid pcap devices will be used.

`-upstream-local`: (Optional) Route upstream to loopback device only.

`-upstream-device device`: (Optional) Designated pcap device for routing upstream to. If this value is not set, the first valid pcap device with the same domain of gateway will be used.

`-p port`: Port for listening.

`-upstream-port -port`: (Optional) Port for routing upstream, must be different with port for listening. If this value is not set, a random port from 49152 to 65535 will be used.

`-s address:port`: Server.

## Todo

- [ ] Support TCP proxy
- [ ] Support UDP proxy using [FakeTCP](https://github.com/wangyu-/udp2raw-tunnel)
- [ ] Test NAT using STUN
- [ ] Test latency
