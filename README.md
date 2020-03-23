# IkaGo

**IkaGo** is a proxy which helps bypassing UDP blocking, UDP QoS and NAT firewall written in Go.

<p align="center">
  <img src="/assets/squid.jpg" alt="an Inkling going through a grate">
</p>
<p align="center">
  Pass the firewall like a squid : )
</p>

## Features

<p align="center">
  <img src="/assets/diagram.png" alt="diagram">
</p>

- **FakeTCP** All TCP, UDP and ICMPv4 packets will be sent with a TCP header to bypass UDP blocking and UDP QoS. Inspired by [Udp2raw-tunnel](https://github.com/wangyu-/udp2raw-tunnel). The handshaking of TCP is also simulated.
- **Multiplexing** One client can handle multiple connections from different devices. And one server can serve multiple clients.
- **Cross platform** Works well with Windows and Linux, and macOS and others in theory.
- **NAT support** Performs a full cone NAT.
- **Encryption** Traffic can be encrypted.

## Dependencies

1. pcap like [Npcap](http://www.npcap.org/) or WinPcap in Windows, libpcap in macOS, Linux and others.

## Usage

```
# Client
go run ./cmd/ikago-client -f [filters] -s [address:port]

# Server
go run ./cmd/ikago-server -p [port]
```

### Common options

`-list-devices`: (Optional, exclusively) List all valid devices in current computer.

`-c`: (Optional, exclusively) Configuration file. An example of configuration file is [here](/configs/config.json).

`-listen-devices devices`: (Optional) Devices for listening, use comma to separate multiple devices. If this value is not set, all valid devices excluding loopback devices will be used. For example, `-listen-devices eth0,wifi0,lo`.

`-upstream-device device`: (Optional) Device for routing upstream to. If this value is not set, the first valid device with the same domain of gateway will be used.

`-gateway address`: (Optional) Gateway address. If this value is not set, the first gateway address in the routing table will be used.

`-method method`: (Optional) Method of encryption, can be `plain`, `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`, `chacha20-poly1305` or `xchacha20-poly1305`. Default as `plain`.

`-password password`: (Optional) Password of encryption, must be set only when method is not `plain`.

`-v`: (Optional) Print verbose messages.

### Client options

`-p port`: (Optional) Port for routing upstream, must be different with any port filter. If this value is not set or set as `0`, a random port from 49152 to 65535 will be used.

`-f filters`: Filters, use comma to separate multiple filters, must not contain the server. A filter may an IP address, an IP port endpoint, or a port starts with a colon. Any IPv6 address should be encapsulated by a pair of brackets. For example, `-f 192.168.1.1,[2001:0DB8::1428:57ab]:443,:1080`.

`-s ip:port`: Server. Any IPv6 address should be encapsulated by a pair of brackets.

### Server options

`-p port`: Port for listening.

## Troubleshoot

1. Because IkaGo use pcap to handle packets, it will not notify the OS if IkaGo is listening to any ports, all the connections are built manually. Some OS may operate with the packet in advance, while they have no information of the packet in there TCP stacks, and respond with a RST packet. You may configure `iptables` in Linux or `pfctl` in macOS and FreeBSD with the rule below to solve the problem:
   ```
   // Linux
   // You can use stricter policies to maintain a stable network environment if you are using IkaGo-client.
   iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
   
   // macOS, FreeBSD
   // You can specify source and destination addresses instead of "any" to maintain a stable network environment
   // if you are using IkaGo-client.
   echo "block drop proto tcp from any to any flags R/R" >> /etc/pf.conf
   pfctl -f /etc/pf.conf
   pfctl -e
   ```

## Todo

- [ ] Retransmission and out of order packets detection
- [ ] Bypass filters
- [ ] Handle ARP
- [ ] Support KCP

## License

IkaGo is licensed under [the MIT License](/LICENSE).
