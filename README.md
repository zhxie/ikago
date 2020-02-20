# IkaGo

**IkaGo** is a proxy which turns UDP traffic to TCP traffic written in Go.

*IkaGo is currently under development and is not suitable for production.*

## Features

- Cross platform

## Usage

```
go run ikago.go [-list-devices] [-local-only] [-d device] -p [port] -s [address:port]
```

`-list-devices`: (Optional, Exclusively) List all valid network devices in current computer.

`-local-only`: (Optional) Use loopback devices for listening only.

`-d device`: (Optional) Remote device for sending and listening packets to and from server.

`-p port`: Local port for listening.

`-s address:port`: Server.

## Todo

- [ ] Support TCP proxy
- [ ] Support UDP proxy using [FakeTCP](https://github.com/wangyu-/udp2raw-tunnel)
- [ ] Test NAT using STUN
- [ ] Test latency
