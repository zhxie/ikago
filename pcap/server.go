package pcap

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
)

// Server describes the packet capture on the server side
type Server struct {
	ListenPort    uint16
	ListenDevs    []*Device
	UpDev         *Device
	GatewayDev    *Device
	listenHandles []*pcap.Handle
	upHandle      *pcap.Handle
	seq           uint32
	// TODO: attempt to initialize IPv4 id to reduce the possibility of collision
	id            uint16
	nat           map[Quintuple][]BackQuintuple
}

// Open implements a method opens the pcap
func (p *Server) Open() error {
	p.id = 0
	p.nat = make(map[Quintuple][]BackQuintuple)

	// Verify
	if len(p.ListenDevs) <= 0 {
		return fmt.Errorf("open: %w", errors.New("missing listen device"))
	}
	if p.UpDev == nil {
		return fmt.Errorf("open: %w", errors.New("missing upstream device"))
	}
	if p.GatewayDev == nil {
		return fmt.Errorf("open: %w", errors.New("missing gateway"))
	}
	if len(p.ListenDevs) == 1 {
		dev := p.ListenDevs[0]
		strIPs := ""
		for i, addr := range dev.IPAddrs {
			if i != 0 {
				strIPs = strIPs + fmt.Sprintf(", %s", addr.IP)
			} else {
				strIPs = strIPs + addr.IP.String()
			}
		}
		if dev.IsLoop {
			fmt.Printf("Listen on %s: %s\n", dev.FriendlyName, strIPs)
		} else {
			fmt.Printf("Listen on %s [%s]: %s\n", dev.FriendlyName, dev.HardwareAddr, strIPs)
		}
	} else {
		fmt.Println("Listen on:")
		for _, dev := range p.ListenDevs {
			strIPs := ""
			for j, addr := range dev.IPAddrs {
				if j != 0 {
					strIPs = strIPs + fmt.Sprintf(", %s", addr.IP)
				} else {
					strIPs = strIPs + addr.IP.String()
				}
			}
			if dev.IsLoop {
				fmt.Printf("  %s: %s\n", dev.FriendlyName, strIPs)
			} else {
				fmt.Printf("  %s [%s]: %s\n", dev.FriendlyName, dev.HardwareAddr, strIPs)
			}
		}
	}
	strUpIPs := ""
	for i, addr := range p.UpDev.IPAddrs {
		if i != 0 {
			strUpIPs = strUpIPs + fmt.Sprintf(", %s", addr.IP)
		} else {
			strUpIPs = strUpIPs + addr.IP.String()
		}
	}
	if !p.GatewayDev.IsLoop {
		fmt.Printf("Route upstream from %s [%s]: %s to gateway [%s]: %s\n", p.UpDev.FriendlyName,
			p.UpDev.HardwareAddr, strUpIPs, p.GatewayDev.HardwareAddr, p.GatewayDev.IPAddr().IP)
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
		err = handle.SetBPFFilter(fmt.Sprintf("(tcp || udp) && dst port %d", p.ListenPort))
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

	// Handles for routing upstream
	var err error
	p.upHandle, err = pcap.OpenLive(p.UpDev.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	packetSrc := gopacket.NewPacketSource(p.upHandle, p.upHandle.LinkType())
	go func() {
		for packet := range packetSrc.Packets() {
			p.handleUpstream(packet)
		}
	}()

	select {}
}

// Close implements a method closes the pcap
func (p *Server) Close() {
	for _, handle := range p.listenHandles {
		handle.Close()
	}
	p.upHandle.Close()
}

func (p *Server) handleListen(packet gopacket.Packet, handle *pcap.Handle) {
	var (
		networkLayer               gopacket.NetworkLayer
		networkLayerType           gopacket.LayerType
		srcIP                      net.IP
		transportLayer             gopacket.TransportLayer
		transportLayerType         gopacket.LayerType
		srcPort                    uint16
		applicationLayer           gopacket.ApplicationLayer
		encappedPacket             gopacket.Packet
		encappedNetworkLayer       gopacket.NetworkLayer
		encappedNetworkLayerType   gopacket.LayerType
		encappedDstIP              net.IP
		encappedSrcIP              net.IP
		id                         uint16
		ttl                        uint8
		encappedTransportLayer     gopacket.TransportLayer
		encappedTransportLayerType gopacket.LayerType
		encappedDstPort            uint16
		encappedSrcPort            uint16
		isEncappedPortUnknown      bool
		encappedApplicationLayer   gopacket.ApplicationLayer
		newNetworkLayer            gopacket.NetworkLayer
		newNetworkLayerType        gopacket.LayerType
		newLinkLayer               gopacket.Layer
		newLinkLayerType           gopacket.LayerType
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
	case layers.LayerTypeIPv6:
		ipv6Layer := networkLayer.(*layers.IPv6)
		srcIP = ipv6Layer.SrcIP
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
	case layers.LayerTypeUDP:
		udpLayer := transportLayer.(*layers.UDP)
		srcPort = uint16(udpLayer.SrcPort)
	default:
		break
	}

	applicationLayer = packet.ApplicationLayer()
	if applicationLayer == nil {
		fmt.Println(fmt.Errorf("handle listen: %w", errors.New("empty payload")))
		return
	}

	// Guess network layer type
	encappedPacket = gopacket.NewPacket(applicationLayer.LayerContents(), layers.LayerTypeIPv4, gopacket.Default)
	encappedNetworkLayer = encappedPacket.NetworkLayer()
	if encappedNetworkLayer == nil {
		fmt.Println(fmt.Errorf("handle listen: %w", errors.New("missing encapped network layer")))
		return
	}
	if encappedNetworkLayer.LayerType() != layers.LayerTypeIPv4 {
		fmt.Println(fmt.Errorf("handle listen: %w", errors.New("type not support")))
		return
	}
	ipVersion := encappedNetworkLayer.(*layers.IPv4).Version
	switch ipVersion {
	case 4:
		encappedNetworkLayerType = layers.LayerTypeIPv4
		encappedIPv4Layer := encappedNetworkLayer.(*layers.IPv4)
		encappedDstIP = encappedIPv4Layer.DstIP
		encappedSrcIP = encappedIPv4Layer.SrcIP
		id = encappedIPv4Layer.Id
		ttl = encappedIPv4Layer.TTL
	case 6:
		// Not IPv4, but IPv6
		encappedPacket := gopacket.NewPacket(applicationLayer.LayerContents(), layers.LayerTypeIPv6, gopacket.Default)
		encappedNetworkLayer = encappedPacket.NetworkLayer()
		if encappedNetworkLayer == nil {
			fmt.Println(fmt.Errorf("handle listen: %w", errors.New("missing encapped network layer")))
			return
		}
		if encappedNetworkLayer.LayerType() != layers.LayerTypeIPv6 {
			fmt.Println(fmt.Errorf("handle listen: %w", errors.New("type not support")))
			return
		}
		encappedNetworkLayerType = layers.LayerTypeIPv6
		encappedIPv6Layer := encappedNetworkLayer.(*layers.IPv6)
		encappedDstIP = encappedIPv6Layer.DstIP
		encappedSrcIP = encappedIPv6Layer.SrcIP
	default:
		fmt.Println(fmt.Errorf("handle listen: %w", fmt.Errorf("IP version %d not support", ipVersion)))
		return
	}

	encappedTransportLayer = encappedPacket.TransportLayer()
	if encappedTransportLayer == nil {
		fmt.Println(fmt.Errorf("handle listen: %w", errors.New("missing encapped transport layer")))
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
	default:
		isEncappedPortUnknown = true
	}

	contents := make([]byte, 0)
	encappedApplicationLayer = encappedPacket.ApplicationLayer()
	if encappedApplicationLayer != nil {
		contents = append(contents, encappedApplicationLayer.LayerContents()...)
	}

	// Create new network layer
	switch encappedNetworkLayerType {
	case layers.LayerTypeIPv4:
		// Create in IPv4
		newNetworkLayer = createIPv4Layer(p.UpDev.IPv4Addr().IP, encappedDstIP, id, ttl-1)

		ipv4Layer := newNetworkLayer.(*layers.IPv4)

		// Checksum of transport layer
		switch encappedTransportLayerType {
		case layers.LayerTypeTCP:
			tcpLayer := encappedTransportLayer.(*layers.TCP)

			// Checksum of TCP layer
			tcpLayer.Checksum = CheckTCPIPv4Sum(tcpLayer, contents, ipv4Layer)
		case layers.LayerTypeUDP:
			udpLayer := encappedTransportLayer.(*layers.UDP)

			// Checksum of UDP layer
			udpLayer.Checksum = CheckUDPIPv4Sum(udpLayer, contents, ipv4Layer)
		default:
			fmt.Println(fmt.Errorf("handle listen: %w",
				fmt.Errorf("%s not support", encappedTransportLayerType)))
			return
		}

		// Fill length and checksum of network layer
		ipv4Layer.Length = (uint16(ipv4Layer.IHL) +
			uint16(len(encappedTransportLayer.LayerContents())) + uint16(len(contents))) * 8
		ipv4Layer.Checksum = checkSum(ipv4Layer.LayerContents())
	case layers.LayerTypeIPv6:
		fmt.Println(fmt.Errorf("handle listen: %w", errors.New("ipv6 not support")))
		return
	default:
		fmt.Println(fmt.Errorf("handle listen: %w", fmt.Errorf("%s not support", encappedNetworkLayerType)))
		return
	}
	newNetworkLayerType = newNetworkLayer.LayerType()

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
		case layers.LayerTypeIPv6:
			t = layers.EthernetTypeIPv6
		default:
			fmt.Println(fmt.Errorf("handle upstream: %w", fmt.Errorf("%s not support", encappedNetworkLayerType)))
			return
		}
		newLinkLayer = &layers.Ethernet{
			SrcMAC:       p.UpDev.HardwareAddr,
			DstMAC:       p.GatewayDev.HardwareAddr,
			EthernetType: t,
		}
	}

	// Record the source and the source device of the packet
	q := Quintuple{
		SrcIP:    p.UpDev.IPv4Addr().IP.String(),
		SrcPort:  encappedSrcPort,
		DstIP:    encappedDstIP.String(),
		DstPort:  encappedDstPort,
		Protocol: encappedTransportLayerType,
	}
	bq := BackQuintuple{
		SrcIP:           srcIP.String(),
		SrcPort:         srcPort,
		EncappedSrcIP:   encappedSrcIP.String(),
		EncappedSrcPort: encappedSrcPort,
		Handle:          handle,
	}
	bts, ok := p.nat[q]
	if !ok {
		bts = make([]BackQuintuple, 0)
	}
	bts = append(bts, bq)

	// Serialize layers
	options := gopacket.SerializeOptions{}
	buffer := gopacket.NewSerializeBuffer()
	var err error
	newLinkLayerType = newLinkLayer.LayerType()
	switch newLinkLayerType {
	case layers.LayerTypeLoopback:
		switch newNetworkLayerType {
		case layers.LayerTypeIPv4:
			switch encappedTransportLayerType {
			case layers.LayerTypeTCP:
				err = gopacket.SerializeLayers(buffer, options,
					newLinkLayer.(*layers.Loopback),
					newNetworkLayer.(*layers.IPv4),
					encappedTransportLayer.(*layers.TCP),
					gopacket.Payload(contents),
				)
			case layers.LayerTypeUDP:
				err = gopacket.SerializeLayers(buffer, options,
					newLinkLayer.(*layers.Loopback),
					newNetworkLayer.(*layers.IPv4),
					encappedTransportLayer.(*layers.UDP),
					gopacket.Payload(contents),
				)
			default:
				fmt.Println(fmt.Errorf("handle upstream: %w",
					fmt.Errorf("%s not support", encappedTransportLayerType)))
				return
			}
		case layers.LayerTypeIPv6:
			switch encappedTransportLayerType {
			case layers.LayerTypeTCP:
				err = gopacket.SerializeLayers(buffer, options,
					newLinkLayer.(*layers.Loopback),
					newNetworkLayer.(*layers.IPv6),
					encappedTransportLayer.(*layers.TCP),
					gopacket.Payload(contents),
				)
			case layers.LayerTypeUDP:
				err = gopacket.SerializeLayers(buffer, options,
					newLinkLayer.(*layers.Loopback),
					newNetworkLayer.(*layers.IPv6),
					encappedTransportLayer.(*layers.UDP),
					gopacket.Payload(contents),
				)
			default:
				fmt.Println(fmt.Errorf("handle upstream: %w",
					fmt.Errorf("%s not support", encappedTransportLayerType)))
				return
			}
		default:
			fmt.Println(fmt.Errorf("handle upstream: %w",
				fmt.Errorf("%s not support", newNetworkLayerType)))
			return
		}
	case layers.LayerTypeEthernet:
		switch newNetworkLayerType {
		case layers.LayerTypeIPv4:
			switch encappedTransportLayerType {
			case layers.LayerTypeTCP:
				err = gopacket.SerializeLayers(buffer, options,
					newLinkLayer.(*layers.Ethernet),
					newNetworkLayer.(*layers.IPv4),
					encappedTransportLayer.(*layers.TCP),
					gopacket.Payload(contents),
				)
			case layers.LayerTypeUDP:
				err = gopacket.SerializeLayers(buffer, options,
					newLinkLayer.(*layers.Ethernet),
					newNetworkLayer.(*layers.IPv4),
					encappedTransportLayer.(*layers.UDP),
					gopacket.Payload(contents),
				)
			default:
				fmt.Println(fmt.Errorf("handle upstream: %w",
					fmt.Errorf("%s not support", encappedTransportLayerType)))
				return
			}
		case layers.LayerTypeIPv6:
			switch encappedTransportLayerType {
			case layers.LayerTypeTCP:
				err = gopacket.SerializeLayers(buffer, options,
					newLinkLayer.(*layers.Ethernet),
					newNetworkLayer.(*layers.IPv6),
					encappedTransportLayer.(*layers.TCP),
					gopacket.Payload(contents),
				)
			case layers.LayerTypeUDP:
				err = gopacket.SerializeLayers(buffer, options,
					newLinkLayer.(*layers.Ethernet),
					newNetworkLayer.(*layers.IPv6),
					encappedTransportLayer.(*layers.UDP),
					gopacket.Payload(contents),
				)
			default:
				fmt.Println(fmt.Errorf("handle upstream: %w",
					fmt.Errorf("%s not support", encappedTransportLayerType)))
				return
			}
		default:
			fmt.Println(fmt.Errorf("handle upstream: %w",
				fmt.Errorf("%s not support", newNetworkLayerType)))
			return
		}
	default:
		fmt.Println(fmt.Errorf("handle upstream: %w", fmt.Errorf("%s not support", newLinkLayerType)))
		return
	}
	if err != nil {
		fmt.Println(fmt.Errorf("handle upstream: %w", err))
		return
	}

	// Write packet data
	data := buffer.Bytes()
	err = p.upHandle.WritePacketData(data)
	if err != nil {
		fmt.Println(fmt.Errorf("handle listen: %w", err))
	}
	if isEncappedPortUnknown {
		fmt.Printf("Redirect an inbound %s packet from %s to %s (%d Bytes)\n",
			encappedTransportLayerType, encappedSrcIP, encappedDstIP, packet.Metadata().Length)
	} else {
		fmt.Printf("Redirect an inbound %s packet from %s:%d to %s:%d (%d Bytes)\n",
			encappedTransportLayerType, encappedSrcIP, encappedSrcPort, encappedDstIP, encappedDstPort,
			packet.Metadata().Length)
	}
}

func (p *Server) handleUpstream(packet gopacket.Packet) {

}
