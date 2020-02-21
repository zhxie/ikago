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
	listenDevs    []*Device
	IsLocal       bool
	Dev           *Device
	gatewayDev    *Device
	listenHandles []*pcap.Handle
	handles       *pcap.Handle
	// TODO: attempt to initialize values below to reduce the possibility of collision
	seq           uint32
	id            uint16
}

// Open implements a method opens the pcap
func (p *Pcap) Open() error {
	// Find devices for listening
	if p.IsListenLocal {
		loopDev, err := FindLoopDev()
		if err != nil {
			return fmt.Errorf("open: %w", err)
		}
		p.listenDevs = append(make([]*Device, 0), loopDev)
	} else {
		devs, err := FindAllDevs()
		if err != nil {
			return fmt.Errorf("open: %w", err)
		}
		p.listenDevs = devs
	}

	// Find dev and gateway device
	if p.Dev == nil {
		if p.IsLocal {
			loopDev, err := FindLoopDev()
			if err != nil {
				return fmt.Errorf("open: %w", err)
			}
			p.Dev = loopDev
			p.gatewayDev = p.Dev
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
						p.Dev = &Device{
							Name:         dev.Name,
							FriendlyName: dev.FriendlyName,
							IPAddrs:      append(make([]IPAddr, 0), addr),
							HardwareAddr: dev.HardwareAddr,
							IsLoop:       dev.IsLoop,
						}
						break
					}
				}
				if p.Dev != nil {
					break
				}
			}
		}
	} else {
		if p.Dev.IsLoop {
			p.gatewayDev = p.Dev
		} else {
			var err error
			p.gatewayDev, err = FindGatewayDev(p.Dev.Name)
			if err != nil {
				return fmt.Errorf("open: %w", err)
			}
			// Test if device's IP is in the same domain of the gateway's
			var newDev *Device
			for _, addr := range p.Dev.IPAddrs {
				ipnet := net.IPNet{IP:addr.IP, Mask:addr.Mask}
				if ipnet.Contains(p.gatewayDevIP()) {
					newDev = &Device{
						Name:         p.Dev.Name,
						FriendlyName: p.Dev.FriendlyName,
						IPAddrs:      append(make([]IPAddr, 0), addr),
						HardwareAddr: p.Dev.HardwareAddr,
						IsLoop:       p.Dev.IsLoop,
					}
					break
				}
			}
			if newDev == nil {
				return fmt.Errorf("open: %w", errors.New("different domain in device and gateway"))
			}
			p.Dev = newDev
		}
	}

	if p.listenDevs == nil || len(p.listenDevs) <= 0 || p.Dev == nil || p.gatewayDev == nil {
		return fmt.Errorf("open: %w", errors.New("can not determine device"))
	}
	strDevs := ""
	for i, dev := range p.listenDevs {
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
	if !p.gatewayDev.IsLoop {
		fmt.Printf("Route upstream from %s [%s]: %s to gateway [%s]: %s\n", p.Dev.FriendlyName,
			p.Dev.HardwareAddr, p.devIP(), p.gatewayDev.HardwareAddr, p.gatewayDevIP())
	} else {
		fmt.Printf("Route upstream to loopback %s\n", p.Dev.FriendlyName)
	}

	// Handles for listening
	p.listenHandles = make([]*pcap.Handle, 0)
	for _, dev := range p.listenDevs {
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
				p.handleListen(packet)
			}
		}()
	}

	// Handles for listening and sending
	var err error
	p.handles, err = pcap.OpenLive(p.Dev.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	err = p.handles.SetBPFFilter(fmt.Sprintf("tcp && src host %s && src port %d && dst port %d",
		p.ServerIP, p.ServerPort, p.ListenPort))
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	packetSrc := gopacket.NewPacketSource(p.handles, p.handles.LinkType())
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
	p.handles.Close()
}

func (p *Pcap) devIP() net.IP {
	// TODO: device may owns multiple IPs
	return p.Dev.IPAddrs[0].IP
}

func (p *Pcap) gatewayDevIP() net.IP {
	return p.gatewayDev.IPAddrs[0].IP
}

func (p *Pcap) handleListen(packet gopacket.Packet) {
	var (
		networkLayer        gopacket.NetworkLayer
		networkLayerType    gopacket.LayerType
		srcIP               net.IP
		ttl                 uint8
		transportLayer      gopacket.TransportLayer
		transportLayerType  gopacket.LayerType
		srcPort             uint16
		isSrcPortUnknown    bool
		applicationLayer    gopacket.ApplicationLayer
		newTransportLayer   *layers.TCP
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
		ipv4 := networkLayer.(*layers.IPv4)
		srcIP = ipv4.SrcIP
		ttl = ipv4.TTL
		break
	case layers.LayerTypeIPv6:
		srcIP = networkLayer.(*layers.IPv6).SrcIP
		break
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
		srcPort = uint16(transportLayer.(*layers.TCP).SrcPort)
		break
	case layers.LayerTypeUDP:
		srcPort = uint16(transportLayer.(*layers.UDP).SrcPort)
		break
	case layers.LayerTypeICMPv4, layers.LayerTypeICMPv6:
	default:
		isSrcPortUnknown = true
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
	isDevIPv4 := p.devIP().To4() != nil
	isGatewayDevIPv4 := p.gatewayDevIP().To4() != nil
	var isIPv4 bool
	if isDevIPv4 && isGatewayDevIPv4 {
		isIPv4 = true
	} else if !isDevIPv4 && !isGatewayDevIPv4 {
		isIPv4 = false
	} else {
		fmt.Println(fmt.Errorf("handle listen: %w", errors.New("ipv6 transition not support")))
		return
	}

	// Create new network layer
	if isIPv4 {
		// Create in IPv4
		newNetworkLayer = createIPv4(p.devIP(), p.ServerIP, p.id, ttl-1)
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
	if p.Dev.IsLoop {
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
			SrcMAC:       p.Dev.HardwareAddr,
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
	err = p.handles.WritePacketData(data)
	if err != nil {
		fmt.Println(fmt.Errorf("handle listen: %w", err))
	}
	if isSrcPortUnknown {
		fmt.Printf("Redirect a %s packet from %s of size %d Bytes\n",
			transportLayerType, srcIP, packet.Metadata().Length)
	} else {
		fmt.Printf("Redirect a %s packet from %s:%d of size %d Bytes\n",
			transportLayerType, srcIP, srcPort, packet.Metadata().Length)
	}

	pp := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	p.handle(pp)
}

func (p *Pcap) handle(packet gopacket.Packet) {
	var (
		applicationLayer           gopacket.ApplicationLayer
		encappedNetworkLayer       gopacket.NetworkLayer
		encappedNetworkLayerType   gopacket.LayerType
		encappedDstIP              net.IP
		encappedTransportLayer     gopacket.TransportLayer
		encappedTransportLayerType gopacket.LayerType
		encappedDstPort            uint16
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
		encappedDstPort = uint16(encappedTransportLayer.(*layers.TCP).DstPort)
	case layers.LayerTypeUDP:
		encappedDstPort = uint16(encappedTransportLayer.(*layers.UDP).DstPort)
	case layers.LayerTypeICMPv4, layers.LayerTypeICMPv6:
	default:
		isEncappedDstPortUnknown = true
	}

	// Create new link layer
	if p.Dev.IsLoop {
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
			SrcMAC:       p.Dev.HardwareAddr,
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

	// Write packet data
	data := buffer.Bytes()
	err = p.handles.WritePacketData(data)
	if err != nil {
		fmt.Println(fmt.Errorf("handle: %w", err))
	}
	if isEncappedDstPortUnknown {
		fmt.Printf("Redirect a %s packet to %s of size %d Bytes\n",
			encappedTransportLayerType, encappedDstIP, packet.Metadata().Length)
	} else {
		fmt.Printf("Redirect a %s packet to %s:%d of size %d Bytes\n",
			encappedTransportLayerType, encappedDstIP, encappedDstPort, packet.Metadata().Length)
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
