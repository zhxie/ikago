# IkaGo

**IkaGo** is a proxy which turns UDP traffic to TCP traffic written in Go.

*IkaGo is currently under development and may not suitable for production.*

## Dependencies

1. pcap like [Npcap](http://www.npcap.org/) or WinPcap in Windows, and libpcap in macOS or Linux.

## Features

- **FakeTCP** All TCP and UDP packets are sent with a TCP header to bypass UDP blocking and UDP QoS. Inspired by [Udp2raw-tunnel](https://github.com/wangyu-/udp2raw-tunnel). The handshaking of TCP is also simulated.
- **Multiple clients** One server can serve multiple clients.
- **Cross platform** Works well with Windows and Linux, and macOS in theory.
- **NAT support** Performs a full cone NAT.

## Usage

```
# Client
go run client.go -f [filters] -s [address:port]

# Server
go run server.go -p [port]
```

`-list-devices`: (Optional, exclusively) List all valid pcap devices in current computer.

`-listen-loopback-device`: (Optional) Listen loopback device only.

`-listen-devices devices`: (Optional) Designated pcap devices for listening, use comma to separate multiple devices. If this value is not set, all valid pcap devices will be used. For example, `-listen-devices eth0,wifi0,lo`. Use `-listen-loopback-device` will select loopback device in designated devices.

`-upstream-loopback-device`: (Optional) Route upstream to loopback device only.

`-upstream-device device`: (Optional) Designated pcap device for routing upstream to. If this value is not set, the first valid pcap device with the same domain of gateway will be used. Use `-upstream-loopback-device` will select loopback device in designated devices.

`-ipv4-device`: (Optional) Use IPv4 device only. Use `-ipv4-device` and `-ipv6-device` together will use both IPv4 and IPv6 devices.

`-ipv6-device`: (Optional) Use IPv6 device only. Use `-ipv4-device` and `-ipv6-device` together will use both IPv4 and IPv6 devices.

`-f filters`: (Client only) Filters, use comma to separate multiple filters, must not contain the server. A filter may an IP, an IP port endpoint, or a port starts with a colon and any IPv6 address should be encapsulated by a pair of brackets. For example, `-f 192.168.1.1,[2001:0DB8::1428:57ab]:443,:1080`.

`-p port`: (Server only) Port for listening.

`-upstream-port port`: (Optional) Port for routing upstream, must be different with any port filter. If this value is not set or set as 0, a random port from 49152 to 65535 will be used.

`-s address:port`: (Client only) Server. Any IPv6 address should be encapsulated by a pair of brackets.

`-v`: (Optional) Print verbose messages.

## Toubleshoot

1. Because IkaGo use pcap to handle packets, it will not notify the OS if IkaGo is listening to any ports, all the connections are built manually. Some Linux kernels may operate with the packet in advance, while they have no information of the packet in there TCP stacks, and respond with a RST packet. You may configure the iptables with the rule below to solve the problem:
	```
	iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
	```

## Todo

- [ ] Test NAT using STUN
- [ ] Retransmission and out of order packets detection
- [ ] Handle packets with unrecognizable transport layer

