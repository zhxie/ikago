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
  <img src="/assets/diagram.jpg" alt="diagram">
</p>

- **FakeTCP**: All TCP, UDP and ICMPv4 packets will be sent with a TCP header to bypass UDP blocking and UDP QoS. Inspired by [Udp2raw-tunnel](https://github.com/wangyu-/udp2raw-tunnel). The handshaking of TCP is also simulated.
- **Proxy ARP**: Reply ARP request as it owns the specified address which is not on the network.
- **Multiplexing and Multiple**: One client can handle multiple connections from different devices. And one server can serve multiple clients.
- **Cross Platform**: Works well with Windows and Linux, and macOS and others in theory.
- **Full Cone NAT**
- **Encryption**
- **KCP Support**

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

`-method method`: (Optional) Method of encryption, can be `plain`, `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`, `chacha20-poly1305` or `xchacha20-poly1305`. Default as `plain`. For more about encryption, please refer to the [development documentation](/dev.md).

`-password password`: (Optional) Password of encryption, must be set only when method is not `plain`.

`-kcp`: (Optional) Enable KCP.

`-kcp-mtu`, `-kcp-sndwnd`, `-kcp-rcvwnd`, `-kcp-datashard`, `-kcp-parityshard`, `-kcp-acknodelay`: (Optional) KCP tuning options, available when KCP is enabled. Please refer to the [kcp-go](https://godoc.org/github.com/xtaci/kcp-go).

`-kcp-nodelay`, `-kcp-interval`, `kcp-resend`, `kcp-nc`: (Optional) KCP tuning options, available when KCP is enabled. Please refer to the [kcp](https://github.com/skywind3000/kcp/blob/master/README.en.md#protocol-configuration).

`-rule`: (Optional) Add firewall rule. In some OS, firewall rules need to be added to ensure the operation of IkaGo. Rules are described in [troubleshoot](https://github.com/zhxie/ikago#troubleshoot) below.

`-v`: (Optional) Print verbose messages.

`-log path`: (Optional) Log.

### Client options

`-publish addresses`: (Optional) ARP publishing address, use comma to separate multiple addresses. If this value is set, IkaGo will reply ARP request as it owns the specified address which is not on the network, also called proxy ARP.

`-fragment size`: (Optional) Max size of the outbound packets. If this value is not set or set as `0`, outbound packets will not be fragmented. For more about MTU and fragmentation, please refer to the [Troubleshoot](https://github.com/zhxie/ikago#troubleshoot).

`-dummy`: (Optional) Initialize a dummy TCP listener, the listener will listen on the port for routing upstream.

`-p port`: (Optional) Port for routing upstream, must be different with any port filter. If this value is not set or set as `0`, a random port from 49152 to 65535 will be used.

`-f filters`: Filters, use comma to separate multiple filters, must not contain the server. A filter may an IP address, an IP port endpoint, or a port starts with a colon. For example, `-f 192.168.1.1,:1080`.

`-s ip:port`: Server.

### Server options

`-p port`: Port for listening.

## Troubleshoot

1. Because IkaGo use pcap to handle packets, it will not notify the OS if IkaGo is listening to any ports, all the connections are built manually. Some OS may operate with the packet in advance, while they have no information of the packet in there TCP stacks, and respond with a RST packet. You may configure `iptables` in Linux, `pfctl` in macOS and BSD, or `netsh` in Windows with the following rules to solve the problem:
   ```
   // Linux
   iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
   // You can specify source and destination address to maintain a stable network environment if you are using
   // IkaGo-client with proxy ARP.
   iptables -A OUTPUT -s server_ip/32 -p tcp --tcp-flags RST RST --dport server_port -j DROP
   
   // macOS, BSD
   echo "block drop proto tcp from any to any flags R/R" >> /etc/pf.conf
   pfctl -f /etc/pf.conf
   pfctl -e
   // You can specify source and destination addresses instead of "any" to maintain a stable network environment
   // if you are using IkaGo-client with proxy ARP.
   echo "block drop proto tcp from any to server_ip flags R/R port server_port" >> /etc/pf.conf
   pfctl -f /etc/pf.conf
   pfctl -e
   
   // Windows (You may not have to)
   // If you are using IkaGo-client with proxy ARP.
   netsh advfirewall firewall add rule name=IkaGo-client protocol=TCP dir=in remoteip=server_ip/32 remoteport=server_port action=block
   netsh advfirewall firewall add rule name=IkaGo-client protocol=TCP dir=out remoteip=server_ip/32 remoteport=server_port action=block
   ```

2. IkaGo prepend packets with TCP header, so an extra IPv4 and TCP header will be added to the packet. As a consequence, an extra 40 Bytes will be added to the total packet size. For encryption, extra bytes according to the method, up to 40 Bytes, and for KCP support, another 24 Bytes. IkaGo will never do IP fragmentation between client-server transmissions, so please make sure the MTU in your proxied device was set to a reasonable value. Assuming your IPv4 network has a MRU value of 1400 Bytes, when you enable AES-256-GCM encryption(consuming 28 Bytes) and KCP support, you should set the proxied device's MTU value to no more than 1308 Bytes.

3. In scenarios such as P2P games, devices on both sides may not actively perform packet fragmentation, and the device's MRU will be set to be the same as the MTU. Even if you set the MTU in your device, the packets sent by the other side may exceed the MRU of your device. Use `-fragment` to fragment outbound packets in IkaGo.

## Limitations

1. IPv6 is not supported because the dependency package [gopacket](https://github.com/google/gopacket) does not fully implement the serialization of the IPv6 extension header.

## Todo

- [ ] Retransmission and out of order packets detection

## License

IkaGo is licensed under [the MIT License](/LICENSE).
