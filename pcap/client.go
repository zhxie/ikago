package pcap

import (
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Client describes the packet capture on the client side
type Client struct {
	ListenPort    uint16
	UpPort        uint16
	ServerIP      net.IP
	ServerPort    uint16
	ListenDevs    []*Device
	UpDev         *Device
	GatewayDev    *Device
	listenHandles []*pcap.Handle
	upHandle      *pcap.Handle
	seq           uint32
	// TODO: attempt to initialize IPv4 id to reduce the possibility of collision
	id            uint16
	nat           map[Quintuple]*pcap.Handle
}

// Open implements a method opens the pcap
func (p *Client) Open() error {
	p.id = 0
	p.nat = make(map[Quintuple]*pcap.Handle)

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
		err = handle.SetBPFFilter(fmt.Sprintf("(tcp || udp) && dst port %d && not (src host %s && src port %d)",
			p.ListenPort, p.ServerIP, p.ServerPort))
		if err != nil {
			return fmt.Errorf("open: %w", err)
		}
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
	err = p.upHandle.SetBPFFilter(fmt.Sprintf("(tcp || udp) && dst port %d && (src host %s && src port %d)",
		p.UpPort, p.ServerIP, p.ServerPort))
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
func (p *Client) Close() {
	for _, handle := range p.listenHandles {
		handle.Close()
	}
	p.upHandle.Close()
}

func (p *Client) handleListen(packet gopacket.Packet, handle *pcap.Handle) {
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
		upDevIP             net.IP
		newNetworkLayer     gopacket.NetworkLayer
		newNetworkLayerType gopacket.LayerType
		newLinkLayer        gopacket.Layer
		newLinkLayerType    gopacket.LayerType
	)

	// Parse packet
	networkLayer = packet.NetworkLayer()
	if networkLayer == nil {
		fmt.Println(fmt.Errorf("handle listen: %w",
			fmt.Errorf("parse: %w", errors.New("missing network layer"))))
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
		fmt.Println(fmt.Errorf("handle listen: %w",
			fmt.Errorf("parse: %w", fmt.Errorf("type %s not support", networkLayerType))))
		return
	}

	transportLayer = packet.TransportLayer()
	if transportLayer == nil {
		fmt.Println(fmt.Errorf("handle listen: %w",
			fmt.Errorf("parse: %w", errors.New("missing transport layer"))))
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
	newTransportLayer = createTCPLayer(p.UpPort, p.ServerPort, p.seq)
	p.seq++

	// Decide IPv4 of IPv6
	isIPv4 := p.GatewayDev.IPAddr().IP.To4() != nil
	if isIPv4 {
		upDevIP = p.UpDev.IPv4Addr().IP
		if upDevIP == nil {
			fmt.Println(fmt.Errorf("handle listen: %w",
				fmt.Errorf("create transport layer: %w", errors.New("ip version transition not support"))))
			return
		}
	} else {
		upDevIP = p.UpDev.IPv6Addr().IP
		if upDevIP == nil {
			fmt.Println(fmt.Errorf("handle listen: %w",
				fmt.Errorf("create transport layer: %w", errors.New("ip version transition not support"))))
			return
		}
	}

	// Create new network layer
	if isIPv4 {
		// Create in IPv4
		newNetworkLayer = createIPv4Layer(upDevIP, p.ServerIP, p.id, ttl-1)
		p.id++

		ipv4Layer := newNetworkLayer.(*layers.IPv4)

		// Protocol and length
		ipv4Layer.Protocol = layers.IPProtocolUDP
		ipv4Layer.Length = uint16(ipv4Layer.IHL * 4) + uint16(newTransportLayer.DataOffset * 4) + uint16(len(contents))

		// Checksum of transport layer
		err := newTransportLayer.SetNetworkLayerForChecksum(ipv4Layer)
		if err != nil {
			fmt.Println(fmt.Errorf("handle listen: %w", fmt.Errorf("create transport layer: %w", err)))
		}
	} else {
		fmt.Println(fmt.Errorf("handle listen: %w",
			fmt.Errorf("create transport layer: %w", errors.New("ipv6 not support"))))
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
		case layers.LayerTypeIPv6:
			t = layers.EthernetTypeIPv6
		default:
			fmt.Println(fmt.Errorf("handle listen: %w",
				fmt.Errorf("create link layer: %w",
					fmt.Errorf("type %s not support", newNetworkLayerType))))
			return
		}
		newLinkLayer = &layers.Ethernet{
			SrcMAC:       p.UpDev.HardwareAddr,
			DstMAC:       p.GatewayDev.HardwareAddr,
			EthernetType: t,
		}
	}

	// Record the source device of the packet
	q := Quintuple{
		SrcIP:    srcIP.String(),
		SrcPort:  srcPort,
		DstIP:    dstIP.String(),
		DstPort:  dstPort,
		Protocol: transportLayerType,
	}
	p.nat[q] = handle

	// Serialize layers
	options := gopacket.SerializeOptions{ComputeChecksums:true}
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
		case layers.LayerTypeIPv6:
			err = gopacket.SerializeLayers(buffer, options,
				newLinkLayer.(*layers.Loopback),
				newNetworkLayer.(*layers.IPv6),
				newTransportLayer,
				gopacket.Payload(contents),
			)
		default:
			fmt.Println(fmt.Errorf("handle listen: %w",
				fmt.Errorf("serialize: %w", fmt.Errorf("type %s not support", newNetworkLayerType))))
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
		case layers.LayerTypeIPv6:
			err = gopacket.SerializeLayers(buffer, options,
				newLinkLayer.(*layers.Ethernet),
				newNetworkLayer.(*layers.IPv6),
				newTransportLayer,
				gopacket.Payload(contents),
			)
		default:
			fmt.Println(fmt.Errorf("handle listen: %w",
				fmt.Errorf("serialize: %w", fmt.Errorf("type %s not support", newNetworkLayerType))))
			return
		}
	default:
		fmt.Println(fmt.Errorf("handle listen: %w",
			fmt.Errorf("serialize: %w", fmt.Errorf("type %s not support", newLinkLayer))))
		return
	}
	if err != nil {
		fmt.Println(fmt.Errorf("handle listen: %w", fmt.Errorf("serialize: %w", err)))
		return
	}

	// Write packet data
	data := buffer.Bytes()
	err = p.upHandle.WritePacketData(data)
	if err != nil {
		fmt.Println(fmt.Errorf("handle listen: %w", fmt.Errorf("write: %w", err)))
	}
	if isPortUnknown {
		fmt.Printf("Redirect an outbound %s packet from %s to %s (%d Bytes)\n",
			transportLayerType, srcIP, dstIP, packet.Metadata().Length)
	} else {
		fmt.Printf("Redirect an outbound %s packet from %s:%d to %s:%d (%d Bytes)\n",
			transportLayerType, srcIP, srcPort, dstIP, dstPort, packet.Metadata().Length)
	}
}

func (p *Client) handleUpstream(packet gopacket.Packet) {
	var (
		applicationLayer           gopacket.ApplicationLayer
		encappedPacket             gopacket.Packet
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
		fmt.Println(fmt.Errorf("handle upstream: %w",
			fmt.Errorf("parse: %w", errors.New("empty payload"))))
		return
	}
	// Guess network layer type
	encappedPacket = gopacket.NewPacket(applicationLayer.LayerContents(), layers.LayerTypeIPv4, gopacket.Default)
	encappedNetworkLayer = encappedPacket.NetworkLayer()
	if encappedNetworkLayer == nil {
		fmt.Println(fmt.Errorf("handle upstream: %w",
			fmt.Errorf("parse: %w", errors.New("missing network layer"))))
		return
	}
	if encappedNetworkLayer.LayerType() != layers.LayerTypeIPv4 {
		fmt.Println(fmt.Errorf("handle upstream: %w",
			fmt.Errorf("parse: %w", errors.New("type not support"))))
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
			fmt.Println(fmt.Errorf("handle upstream: %w",
				fmt.Errorf("parse: %w", errors.New("missing network layer"))))
			return
		}
		if encappedNetworkLayer.LayerType() != layers.LayerTypeIPv6 {
			fmt.Println(fmt.Errorf("handle upstream: %w",
				fmt.Errorf("parse: %w", errors.New("type not support"))))
			return
		}
		encappedNetworkLayerType = layers.LayerTypeIPv6
		encappedIPv6Layer := encappedNetworkLayer.(*layers.IPv6)
		encappedDstIP = encappedIPv6Layer.DstIP
		encappedSrcIP = encappedIPv6Layer.SrcIP
	default:
		fmt.Println(fmt.Errorf("handle upstream: %w",
			fmt.Errorf("parse: %w", fmt.Errorf("ip version %d not support", ipVersion))))
		return
	}
	encappedTransportLayer = encappedPacket.TransportLayer()
	if encappedTransportLayer == nil {
		fmt.Println(fmt.Errorf("handle upstream: %w",
			fmt.Errorf("parse: %w", errors.New("missing transport layer"))))
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
		case layers.LayerTypeIPv6:
			t = layers.EthernetTypeIPv6
		default:
			fmt.Println(fmt.Errorf("handle upstream: %w",
				fmt.Errorf("create link layer: %w",
					fmt.Errorf("type %s not support", encappedNetworkLayerType))))
			return
		}
		newLinkLayer = &layers.Ethernet{
			SrcMAC:       p.UpDev.HardwareAddr,
			DstMAC:       p.GatewayDev.HardwareAddr,
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
		fmt.Println(fmt.Errorf("handle upstream: %w",
			fmt.Errorf("serialize: %w", fmt.Errorf("type %s not support", newLinkLayerType))))
		return
	}
	if err != nil {
		fmt.Println(fmt.Errorf("handle upstream: %w", fmt.Errorf("serialize: %w", err)))
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
		fmt.Println(fmt.Errorf("handle upstream: %w", fmt.Errorf("write: %w", err)))
	}
	if isEncappedDstPortUnknown {
		fmt.Printf("Redirect an inbound %s packet from %s to %s (%d Bytes)\n",
			encappedTransportLayerType, encappedSrcIP, encappedDstIP, len(data))
	} else {
		fmt.Printf("Redirect an inbound %s packet from %s:%d to %s:%d (%d Bytes)\n",
			encappedTransportLayerType, encappedSrcIP, encappedSrcPort, encappedDstIP, encappedDstPort, len(data))
	}
}
