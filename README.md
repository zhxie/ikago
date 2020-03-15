# IkaGo

**IkaGo** is a proxy which helps bypassing UDP blocking, UDP QoS and NAT firewall written in Go.

_IkaGo is currently under development and may not suitable for production._

<p align="center">
  <img src="/assets/squid.jpg">
</p>
<p align="center">
  Pass the firewall like a squid : )
</p>

## Features

- **FakeTCP** All TCP, UDP and ICMPv4 packets will be sent with a TCP header to bypass UDP blocking and UDP QoS. Inspired by [Udp2raw-tunnel](https://github.com/wangyu-/udp2raw-tunnel). The handshaking of TCP is also simulated.
- **Multiple clients** One server can serve multiple clients.
- **Cross platform** Works well with Windows and Linux, and macOS in theory.
- **NAT support** Performs a full cone NAT.
- **Encryption** Traffic can be encrypted.

## Dependencies

1. pcap like [Npcap](http://www.npcap.org/) or WinPcap in Windows, libpcap in macOS or Linux.

## Usage

```
# Client
go run ./cmd/ikago-client -f [filters] -s [address:port]

# Server
go run ./cmd/ikago-server -p [port]
```

### Common options

`-list-devices`: (Optional, exclusively) List all valid pcap devices in current computer.

`-c`: (Optional, exclusively) Configuration file. An example of configuration file is [here](/configs/config.json).

`-listen-devices devices`: (Optional) pcap devices for listening, use comma to separate multiple devices. If this value is not set, all valid pcap devices will be used. For example, `-listen-devices eth0,wifi0,lo`.

`-upstream-device device`: (Optional) pcap device for routing upstream to. If this value is not set, the first valid pcap device with the same domain of gateway will be used.

`-method method`: (Optional) Method of encryption, can be `plain`, `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`, `chacha20-poly1305` or `xchacha20-poly1305`. Default as `plain`.

`-password password`: (Optional) Password of the encryption, must be set only when method is not `plain`.

`-v`: (Optional) Print verbose messages.

### Client options

`-upstream-port port`: (Optional) Port for routing upstream, must be different with any port filter. If this value is not set or set as `0`, a random port from 49152 to 65535 will be used.

`-f filters`: (Client only) Filters, use comma to separate multiple filters, must not contain the server. A filter may an IP, an IP port endpoint, or a port starts with a colon. Any IPv6 address should be encapsulated by a pair of brackets. For example, `-f 192.168.1.1,[2001:0DB8::1428:57ab]:443,:1080`.

`-s address:port`: (Client only) Server. Any IPv6 address should be encapsulated by a pair of brackets.

### Server options

`-p port`: (Server only) Port for listening.

## Troubleshoot

1. Because IkaGo use pcap to handle packets, it will not notify the OS if IkaGo is listening to any ports, all the connections are built manually. Some Linux kernels may operate with the packet in advance, while they have no information of the packet in there TCP stacks, and respond with a RST packet. You may configure `iptables` with the rule below to solve the problem:
   ```
   iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
   ```

## Todo

- [ ] Retransmission and out of order packets detection
- [ ] Bypass filters

## License

IkaGo is licensed under [the MIT License](/LICENSE).
