package pcap

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
)

// Pcap describes a packet capture
type Pcap struct {
	ListenPort    uint16
	ServerIP      net.IP
	ServerPort    uint16
	IsListenLocal bool
	ListenDevs    []*Device
	IsLocal       bool
	UpDev         *Device
	gatewayDev    *Device
	listenHandles []*pcap.Handle
	upHandle      *pcap.Handle
	seq           uint32
	// TODO: attempt to initialize IPv4 id to reduce the possibility of collision
	id            uint16
	nat           map[Quintuple]*pcap.Handle
}

// Open implements a method opens the pcap
func (p *Pcap) Open() error {
	p.id = 0
	p.nat = make(map[Quintuple]*pcap.Handle)

	// Find devices for listening
	if len(p.ListenDevs) <= 0 {
		if p.IsListenLocal {
			loopDev, err := FindLoopDev()
			if err != nil {
				return fmt.Errorf("open: %w", err)
			}
			p.ListenDevs = append(make([]*Device, 0), loopDev)
		} else {
			devs, err := FindAllDevs()
			if err != nil {
				return fmt.Errorf("open: %w", err)
			}
			p.ListenDevs = devs
		}
	}

	// Find route upstream and gateway device
	if p.UpDev == nil {
		if p.IsLocal {
			loopDev, err := FindLoopDev()
			if err != nil {
				return fmt.Errorf("open: %w", err)
			}
			p.UpDev = loopDev
			p.gatewayDev = p.UpDev
		} else {
			gatewayAddr, err := FindGatewayAddr()
			if err != nil {
				return fmt.Errorf("open: %w", err)
			}
			devs, err := FindAllDevs()
			if err != nil {
				return fmt.Errorf("open: %w", err)
			}
			for _, dev := range devs {
				if dev.IsLoop {
					continue
				}
				// Test if device's IP is in the same domain of the gateway's
				for _, addr := range dev.IPAddrs {
					ipnet := net.IPNet{IP:addr.IP, Mask:addr.Mask}
					if ipnet.Contains(gatewayAddr.IP) {
						p.gatewayDev, err = FindGatewayDev(dev.Name)
						if err != nil {
							continue
						}
						p.UpDev = &Device{
							Name:         dev.Name,
							FriendlyName: dev.FriendlyName,
							IPAddrs:      append(make([]IPAddr, 0), addr),
							HardwareAddr: dev.HardwareAddr,
							IsLoop:       dev.IsLoop,
						}
						break
					}
				}
				if p.UpDev != nil {
					break
				}
			}
		}
	} else {
		if p.UpDev.IsLoop {
			p.gatewayDev = p.UpDev
		} else {
			var err error
			p.gatewayDev, err = FindGatewayDev(p.UpDev.Name)
			if err != nil {
				return fmt.Errorf("open: %w", err)
			}
			// Test if device's IP is in the same domain of the gateway's
			var newDev *Device
			for _, addr := range p.UpDev.IPAddrs {
				ipnet := net.IPNet{IP:addr.IP, Mask:addr.Mask}
				if ipnet.Contains(p.gatewayDevIP()) {
					newDev = &Device{
						Name:         p.UpDev.Name,
						FriendlyName: p.UpDev.FriendlyName,
						IPAddrs:      append(make([]IPAddr, 0), addr),
						HardwareAddr: p.UpDev.HardwareAddr,
						IsLoop:       p.UpDev.IsLoop,
					}
					break
				}
			}
			if newDev == nil {
				return fmt.Errorf("open: %w",
					errors.New("different domain in upstream device and gateway"))
			}
			p.UpDev = newDev
		}
	}

	if len(p.ListenDevs) <= 0 {
		return fmt.Errorf("open: %w", errors.New("can not listen device"))
	}
	if p.UpDev == nil {
		return fmt.Errorf("open: %w", errors.New("can not determine upstream device"))
	}
	if p.gatewayDev == nil {
		return fmt.Errorf("open: %w", errors.New("can not determine gateway"))
	}
	strDevs := ""
	for i, dev := range p.ListenDevs {
		if i != 0 {
			strDevs = strDevs + ", "
		}
		strIPs := ""
		for j, addr := range dev.IPAddrs {
			if j != 0 {
				strIPs = strIPs + fmt.Sprintf(", %s", addr.IP)
			} else {
				strIPs = strIPs + addr.IP.String()
			}
		}
		if dev.IsLoop {
			strDevs = strDevs + fmt.Sprintf("%s: %s", dev.FriendlyName, strIPs)
		} else {
			strDevs = strDevs + fmt.Sprintf("%s [%s]: %s", dev.FriendlyName, dev.HardwareAddr, strIPs)
		}
	}
	fmt.Printf("Listen on %s\n", strDevs)
	strUpIPs := ""
	for i, addr := range p.UpDev.IPAddrs {
		if i != 0 {
			strUpIPs = strUpIPs + fmt.Sprintf(", %s", addr.IP)
		} else {
			strUpIPs = strUpIPs + addr.IP.String()
		}
	}
	if !p.gatewayDev.IsLoop {
		fmt.Printf("Route upstream from %s [%s]: %s to gateway [%s]: %s\n", p.UpDev.FriendlyName,
			p.UpDev.HardwareAddr, strUpIPs, p.gatewayDev.HardwareAddr, p.gatewayDevIP())
	} else {
		fmt.Printf("Route upstream to loopback %s\n", p.UpDev.FriendlyName)
	}

	// Handles for listening
	p.listenHandles = make([]*pcap.Handle, 0)
	for _, dev := range p.ListenDevs {
		handle, err := pcap.OpenLive(dev.Name, 1600, true, pcap.BlockForever)
		if err != nil {
			return fmt.Errorf("open: %w", err)
		}
		err = handle.SetBPFFilter(fmt.Sprintf("tcp && dst port %d", p.ListenPort))
		p.listenHandles = append(p.listenHandles, handle)
	}
	for _, handle := range p.listenHandles {
		packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
		go func() {
			for packet := range packetSrc.Packets() {
				p.handleListen(packet, handle)
			}
		}()
	}

	// Handles for listening and sending
	var err error
	p.upHandle, err = pcap.OpenLive(p.UpDev.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	err = p.upHandle.SetBPFFilter(fmt.Sprintf("tcp && src host %s && src port %d && dst port %d",
		p.ServerIP, p.ServerPort, p.ListenPort))
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	packetSrc := gopacket.NewPacketSource(p.upHandle, p.upHandle.LinkType())
	go func() {
		for packet := range packetSrc.Packets() {
			p.handle(packet)
		}
	}()

	select {}
}

// Close implements a method closes the pcap
func (p *Pcap) Close() {
	for _, handle := range p.listenHandles {
		handle.Close()
	}
	p.upHandle.Close()
}

func (p *Pcap) gatewayDevIP() net.IP {
	return p.gatewayDev.IPAddrs[0].IP
}

func (p *Pcap) handleListen(packet gopacket.Packet, handle *pcap.Handle) {
	var (
		networkLayer        gopacket.NetworkLayer
		networkLayerType    gopacket.LayerType
		srcIP               net.IP
		dstIP               net.IP
		ttl                 uint8
		transportLayer      gopacket.TransportLayer
		transportLayerType  gopacket.LayerType
		srcPort             uint16
		dstPort             uint16
		isPortUnknown       bool
		applicationLayer    gopacket.ApplicationLayer
		newTransportLayer   *layers.TCP
		upDevIP             *IPAddr
		newNetworkLayer     gopacket.NetworkLayer
		newNetworkLayerType gopacket.LayerType
		newLinkLayer        gopacket.Layer
		newLinkLayerType    gopacket.LayerType
	)

	// Parse packet
	networkLayer = packet.NetworkLayer()
	if networkLayer == nil {
		fmt.Println(fmt.Errorf("handle listen: %w", errors.New("missing network layer")))
		return
	}
	networkLayerType = networkLayer.LayerType()
	switch networkLayerType {
	case layers.LayerTypeIPv4:
		ipv4Layer := networkLayer.(*layers.IPv4)
		srcIP = ipv4Layer.SrcIP
		dstIP = ipv4Layer.DstIP
		ttl = ipv4Layer.TTL
	case layers.LayerTypeIPv6:
		ipv6Layer := networkLayer.(*layers.IPv6)
		srcIP = ipv6Layer.SrcIP
		dstIP = ipv6Layer.DstIP
	default:
		fmt.Println(fmt.Errorf("handle listen: %w", fmt.Errorf("%s not support", networkLayerType)))
		return
	}
	transportLayer = packet.TransportLayer()
	if transportLayer == nil {
		fmt.Println(fmt.Errorf("handle listen: %w", errors.New("missing transport layer")))
		return
	}
	transportLayerType = transportLayer.LayerType()
	switch transportLayerType {
	case layers.LayerTypeTCP:
		tcpLayer := transportLayer.(*layers.TCP)
		srcPort = uint16(tcpLayer.SrcPort)
		dstPort = uint16(tcpLayer.DstPort)
	case layers.LayerTypeUDP:
		udpLayer := transportLayer.(*layers.UDP)
		srcPort = uint16(udpLayer.SrcPort)
		dstPort = uint16(udpLayer.DstPort)
	case layers.LayerTypeICMPv4, layers.LayerTypeICMPv6:
	default:
		isPortUnknown = true
	}
	applicationLayer = packet.ApplicationLayer()

	// Construct contents of new application layer
	contents := make([]byte, 0)
	contents = append(contents, networkLayer.LayerContents()...)
	contents = append(contents, transportLayer.LayerContents()...)
	if applicationLayer != nil {
		contents = append(contents, applicationLayer.LayerContents()...)
	}

	// Create new transport layer in TCP
	newTransportLayer = createTCP(p.ListenPort, p.ServerPort, p.seq)
	p.seq++

	// Decide IPv4 of IPv6
	isIPv4 := p.gatewayDevIP().To4() != nil
	if isIPv4 {
		upDevIP = p.UpDev.IPv4()
		if upDevIP == nil {
			fmt.Println(fmt.Errorf("handle listen: %w", errors.New("ip version transition not support")))
			return
		}
	} else {
		upDevIP = p.UpDev.IPv6()
		if upDevIP == nil {
			fmt.Println(fmt.Errorf("handle listen: %w", errors.New("ip version transition not support")))
			return
		}
	}

	// Create new network layer
	if isIPv4 {
		// Create in IPv4
		newNetworkLayer = createIPv4(upDevIP.IP, p.ServerIP, p.id, ttl-1)
		p.id++

		ipv4 := newNetworkLayer.(*layers.IPv4)

		// Checksum of transport layer
		newTransportLayer.Checksum = CheckTCPIPv4Sum(newTransportLayer, contents, ipv4)

		// Fill length and checksum of network layer
		ipv4.Length = (uint16(ipv4.IHL) + uint16(len(newTransportLayer.LayerContents())) + uint16(len(contents))) * 8
		ipv4.Checksum = checkSum(ipv4.LayerContents())
	} else {
		fmt.Println(fmt.Errorf("handle listen: %w", errors.New("ipv6 not support")))
		return
	}

	// Create new link layer
	newNetworkLayerType = newNetworkLayer.LayerType()
	if p.UpDev.IsLoop {
		// Create in loopback
		newLinkLayer = &layers.Loopback{}
	} else {
		// Create in Ethernet
		var t layers.EthernetType
		switch newNetworkLayerType {
		case layers.LayerTypeIPv4:
			t = layers.EthernetTypeIPv4
		default:
			fmt.Println(fmt.Errorf("handle listen: %w", fmt.Errorf("%s not support", newNetworkLayerType)))
			return
		}
		newLinkLayer = &layers.Ethernet{
			SrcMAC:       p.UpDev.HardwareAddr,
			DstMAC:       p.gatewayDev.HardwareAddr,
			EthernetType: t,
		}
	}

	// Append quintuple
	q := Quintuple{
		SrcIP:    srcIP.String(),
		SrcPort:  srcPort,
		DstIP:    dstIP.String(),
		DstPort:  dstPort,
		Protocol: transportLayerType,
	}
	p.nat[q] = handle

	// Serialize layers
	options := gopacket.SerializeOptions{}
	buffer := gopacket.NewSerializeBuffer()
	var err error
	newLinkLayerType = newLinkLayer.LayerType()
	switch newLinkLayerType {
	case layers.LayerTypeLoopback:
		switch newNetworkLayerType {
		case layers.LayerTypeIPv4:
			err = gopacket.SerializeLayers(buffer, options,
				newLinkLayer.(*layers.Loopback),
				newNetworkLayer.(*layers.IPv4),
				newTransportLayer,
				gopacket.Payload(contents),
			)
		default:
			fmt.Println(fmt.Errorf("handle listen: %w", fmt.Errorf("%s not support", newNetworkLayerType)))
			return
		}
	case layers.LayerTypeEthernet:
		switch newNetworkLayerType {
		case layers.LayerTypeIPv4:
			err = gopacket.SerializeLayers(buffer, options,
				newLinkLayer.(*layers.Ethernet),
				newNetworkLayer.(*layers.IPv4),
				newTransportLayer,
				gopacket.Payload(contents),
			)
		default:
			fmt.Println(fmt.Errorf("handle listen: %w", fmt.Errorf("%s not support", newNetworkLayerType)))
			return
		}
	default:
		fmt.Println(fmt.Errorf("handle listen: %w", fmt.Errorf("%s not support", newLinkLayerType)))
		return
	}
	if err != nil {
		fmt.Println(fmt.Errorf("handle listen: %w", err))
		return
	}

	// Write packet data
	data := buffer.Bytes()
	err = p.upHandle.WritePacketData(data)
	if err != nil {
		fmt.Println(fmt.Errorf("handle listen: %w", err))
	}
	if isPortUnknown {
		fmt.Printf("Redirect a %s packet from %s to %s of size %d Bytes\n",
			transportLayerType, srcIP, dstIP, packet.Metadata().Length)
	} else {
		fmt.Printf("Redirect a %s packet from %s:%d to %s:%d of size %d Bytes\n",
			transportLayerType, srcIP, srcPort, dstIP, dstPort, packet.Metadata().Length)
	}
}

func (p *Pcap) handle(packet gopacket.Packet) {
	var (
		applicationLayer           gopacket.ApplicationLayer
		encappedNetworkLayer       gopacket.NetworkLayer
		encappedNetworkLayerType   gopacket.LayerType
		encappedDstIP              net.IP
		encappedSrcIP              net.IP
		encappedTransportLayer     gopacket.TransportLayer
		encappedTransportLayerType gopacket.LayerType
		encappedDstPort            uint16
		encappedSrcPort            uint16
		isEncappedDstPortUnknown   bool
		newLinkLayer               gopacket.Layer
		newLinkLayerType           gopacket.LayerType
	)

	// Parse packet
	applicationLayer = packet.ApplicationLayer()
	if applicationLayer == nil {
		fmt.Println(fmt.Errorf("handle: %w", errors.New("empty payload")))
		return
	}

	// Guess network layer type
	encappedPacket := gopacket.NewPacket(applicationLayer.LayerContents(), layers.LayerTypeIPv4, gopacket.Default)
	encappedNetworkLayer = encappedPacket.NetworkLayer()
	if encappedNetworkLayer == nil {
		fmt.Println(fmt.Errorf("handle: %w", errors.New("missing network layer")))
		return
	}
	if encappedNetworkLayer.LayerType() != layers.LayerTypeIPv4 {
		fmt.Println(fmt.Errorf("handle: %w", errors.New("type not support")))
		return
	}
	ipVersion := encappedNetworkLayer.(*layers.IPv4).Version
	switch ipVersion {
	case 4:
		encappedNetworkLayerType = layers.LayerTypeIPv4
		encappedIPv4Layer := encappedNetworkLayer.(*layers.IPv4)
		encappedDstIP = encappedIPv4Layer.DstIP
		encappedSrcIP = encappedIPv4Layer.SrcIP
	case 6:
		// Not IPv4, but IPv6
		encappedPacket := gopacket.NewPacket(applicationLayer.LayerContents(), layers.LayerTypeIPv6, gopacket.Default)
		encappedNetworkLayer = encappedPacket.NetworkLayer()
		if encappedNetworkLayer == nil {
			fmt.Println(fmt.Errorf("handle: %w", errors.New("missing network layer")))
			return
		}
		if encappedNetworkLayer.LayerType() != layers.LayerTypeIPv6 {
			fmt.Println(fmt.Errorf("handle: %w", errors.New("type not support")))
			return
		}
		encappedNetworkLayerType = layers.LayerTypeIPv6
		encappedIPv6Layer := encappedNetworkLayer.(*layers.IPv6)
		encappedDstIP = encappedIPv6Layer.DstIP
		encappedSrcIP = encappedIPv6Layer.SrcIP
	default:
		fmt.Println(fmt.Errorf("handle: %w", fmt.Errorf("IP version %d not support", ipVersion)))
		return
	}
	encappedTransportLayer = encappedPacket.TransportLayer()
	if encappedTransportLayer == nil {
		fmt.Println(fmt.Errorf("handle: %w", errors.New("missing transport layer")))
		return
	}
	encappedTransportLayerType = encappedTransportLayer.LayerType()
	switch encappedTransportLayerType {
	case layers.LayerTypeTCP:
		encappedTCPLayer := encappedTransportLayer.(*layers.TCP)
		encappedDstPort = uint16(encappedTCPLayer.DstPort)
		encappedSrcPort = uint16(encappedTCPLayer.SrcPort)
	case layers.LayerTypeUDP:
		encappedUDPLayer := encappedTransportLayer.(*layers.UDP)
		encappedDstPort = uint16(encappedUDPLayer.DstPort)
		encappedSrcPort = uint16(encappedUDPLayer.SrcPort)
	case layers.LayerTypeICMPv4, layers.LayerTypeICMPv6:
	default:
		isEncappedDstPortUnknown = true
	}

	// Create new link layer
	if p.UpDev.IsLoop {
		// Create in loopback
		newLinkLayer = &layers.Loopback{}
	} else {
		// Create in Ethernet
		var t layers.EthernetType
		switch encappedNetworkLayerType {
		case layers.LayerTypeIPv4:
			t = layers.EthernetTypeIPv4
		default:
			fmt.Println(fmt.Errorf("handle: %w", fmt.Errorf("%s not support", encappedNetworkLayerType)))
			return
		}
		newLinkLayer = &layers.Ethernet{
			SrcMAC:       p.UpDev.HardwareAddr,
			DstMAC:       p.gatewayDev.HardwareAddr,
			EthernetType: t,
		}
	}

	// Serialize layers
	options := gopacket.SerializeOptions{}
	buffer := gopacket.NewSerializeBuffer()
	var err error
	newLinkLayerType = newLinkLayer.LayerType()
	switch newLinkLayerType {
	case layers.LayerTypeLoopback:
		err = gopacket.SerializeLayers(buffer, options,
			newLinkLayer.(*layers.Loopback),
			gopacket.Payload(applicationLayer.LayerContents()),
		)
	case layers.LayerTypeEthernet:
		err = gopacket.SerializeLayers(buffer, options,
			newLinkLayer.(*layers.Ethernet),
			gopacket.Payload(applicationLayer.LayerContents()),
		)
	default:
		fmt.Println(fmt.Errorf("handle: %w", fmt.Errorf("%s not support", newLinkLayerType)))
		return
	}
	if err != nil {
		fmt.Println(fmt.Errorf("handle: %w", err))
		return
	}

	// Check map
	q := Quintuple{
		SrcIP:    encappedDstIP.String(),
		SrcPort:  encappedDstPort,
		DstIP:    encappedSrcIP.String(),
		DstPort:  encappedSrcPort,
		Protocol: encappedTransportLayerType,
	}
	handle, ok := p.nat[q]
	if !ok {
		handle = p.upHandle
	}

	// Write packet data
	data := buffer.Bytes()
	err = handle.WritePacketData(data)
	if err != nil {
		fmt.Println(fmt.Errorf("handle: %w", err))
	}
	if isEncappedDstPortUnknown {
		fmt.Printf("Redirect a %s packet from %s to %s of size %d Bytes\n",
			encappedTransportLayerType, encappedSrcIP, encappedDstIP, len(data))
	} else {
		fmt.Printf("Redirect a %s packet from %s:%d to %s:%d of size %d Bytes\n",
			encappedTransportLayerType, encappedSrcIP, encappedSrcPort, encappedDstIP, encappedDstPort, len(data))
	}
}

func createTCP(srcPort, dstPort uint16, seq uint32) *layers.TCP {
	return &layers.TCP{
		SrcPort:    layers.TCPPort(srcPort),
		DstPort:    layers.TCPPort(dstPort),
		Seq:        seq,
		DataOffset: 5,
		PSH:        true,
		ACK:        true,
		// Checksum:   0,
	}
}

func createIPv4(srcIP, dstIP net.IP, id uint16, ttl uint8) *layers.IPv4 {
	return &layers.IPv4{
		Version:    4,
		IHL:        5,
		// Length:     0,
		Id:         id,
		Flags:      layers.IPv4DontFragment,
		TTL:        ttl,
		Protocol:   layers.IPProtocolTCP,
		// Checksum:   0,
		SrcIP:      srcIP,
		DstIP:      dstIP,
	}
}
