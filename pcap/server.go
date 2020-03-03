package pcap

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Server describes the packet capture on the server side
type Server struct {
	ListenPort     uint16
	ListenDevs     []*Device
	UpDev          *Device
	GatewayDev     *Device
	listenHandles  []*pcap.Handle
	upHandle       *pcap.Handle
	cListenPackets chan devPacket
	seqsLock       sync.RWMutex
	seqs           map[string]uint32
	acksLock       sync.RWMutex
	acks           map[string]uint32
	id             uint16
	tcpPort        uint16
	udpPort        uint16
	// Port translation
	pt      map[quintuple]uint16
	natLock sync.RWMutex
	nat     map[quintuple]*serverNATIndicator
}

// Open implements a method opens the pcap
func (p *Server) Open() error {
	p.cListenPackets = make(chan devPacket, 1000)
	p.seqs = make(map[string]uint32)
	p.acks = make(map[string]uint32)
	p.id = 0
	p.pt = make(map[quintuple]uint16)
	p.nat = make(map[quintuple]*serverNATIndicator)

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
			fmt.Printf("Listen on %s: %s\n", dev.Alias, strIPs)
		} else {
			fmt.Printf("Listen on %s [%s]: %s\n", dev.Alias, dev.HardwareAddr, strIPs)
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
				fmt.Printf("  %s: %s\n", dev.Alias, strIPs)
			} else {
				fmt.Printf("  %s [%s]: %s\n", dev.Alias, dev.HardwareAddr, strIPs)
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
		fmt.Printf("Route upstream from %s [%s]: %s to gateway [%s]: %s\n", p.UpDev.Alias, p.UpDev.HardwareAddr, strUpIPs, p.GatewayDev.HardwareAddr, p.GatewayDev.IPAddr().IP)
	} else {
		fmt.Printf("Route upstream to loopback %s\n", p.UpDev.Alias)
	}

	// Handles for listening
	p.listenHandles = make([]*pcap.Handle, 0)
	for _, dev := range p.ListenDevs {
		handle, err := pcap.OpenLive(dev.Name, 1600, true, pcap.BlockForever)
		if err != nil {
			return fmt.Errorf("open: %w", err)
		}
		err = handle.SetBPFFilter(fmt.Sprintf("tcp && dst port %d", p.ListenPort))
		if err != nil {
			return fmt.Errorf("open: %w", err)
		}
		p.listenHandles = append(p.listenHandles, handle)
	}
	// Handles for routing upstream
	var err error
	p.upHandle, err = pcap.OpenLive(p.UpDev.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	err = p.upHandle.SetBPFFilter(fmt.Sprintf("(tcp || udp) && not dst port %d", p.ListenPort))
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}

	// Start handling
	for i, handle := range p.listenHandles {
		dev := p.ListenDevs[i]
		packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
		copyHandle := handle
		go func() {
			for packet := range packetSrc.Packets() {
				// Avoid conflict
				p.cListenPackets <- devPacket{Packet: packet, Dev: dev, Handle: copyHandle}
			}
		}()
	}
	go func() {
		for devPacket := range p.cListenPackets {
			p.handleListen(devPacket.Packet, devPacket.Dev, devPacket.Handle)
		}
	}()
	packetSrc := gopacket.NewPacketSource(p.upHandle, p.upHandle.LinkType())
	for packet := range packetSrc.Packets() {
		p.handleUpstream(packet)
	}

	return nil
}

// Close implements a method closes the pcap
func (p *Server) Close() {
	for _, handle := range p.listenHandles {
		handle.Close()
	}
	p.upHandle.Close()
}

func (p *Server) handshake(indicator *packetIndicator) error {
	var (
		newTransportLayer   *layers.TCP
		newNetworkLayerType gopacket.LayerType
		newNetworkLayer     gopacket.NetworkLayer
		newLinkLayerType    gopacket.LayerType
		newLinkLayer        gopacket.Layer
	)

	// Initial TCP Seq
	srcAddr := indicator.SrcAddr()
	p.seqsLock.Lock()
	p.seqs[srcAddr.String()] = 0
	p.seqsLock.Unlock()

	// TCK Ack
	p.acksLock.Lock()
	p.acks[srcAddr.String()] = indicator.Seq + 1
	p.acksLock.Unlock()

	// Create transport layer
	p.seqsLock.RLock()
	p.acksLock.RLock()
	newTransportLayer = createTCPLayerSYNACK(p.ListenPort, indicator.SrcPort, p.seqs[srcAddr.String()], p.acks[srcAddr.String()])
	p.seqsLock.RUnlock()
	p.acksLock.RUnlock()

	// Decide IPv4 or IPv6
	if indicator.DstIP.To4() != nil {
		newNetworkLayerType = layers.LayerTypeIPv4
	} else {
		newNetworkLayerType = layers.LayerTypeIPv6
	}

	// Create new network layer
	var err error
	switch newNetworkLayerType {
	case layers.LayerTypeIPv4:
		newNetworkLayer, err = createNetworkLayerIPv4(indicator.DstIP, indicator.SrcIP, p.id, 128, newTransportLayer)
	case layers.LayerTypeIPv6:
		newNetworkLayer, err = createNetworkLayerIPv6(indicator.DstIP, indicator.SrcIP, newTransportLayer)
	default:
		return fmt.Errorf("handshake: %w",
			fmt.Errorf("create network layer: %w",
				fmt.Errorf("type %s not support", newNetworkLayerType)))
	}
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	// Decide Loopback or Ethernet
	if p.UpDev.IsLoop {
		newLinkLayerType = layers.LayerTypeLoopback
	} else {
		newLinkLayerType = layers.LayerTypeEthernet
	}

	// Create new link layer
	switch newLinkLayerType {
	case layers.LayerTypeLoopback:
		newLinkLayer = createLinkLayerLoopback()
	case layers.LayerTypeEthernet:
		newLinkLayer, err = createLinkLayerEthernet(p.UpDev.HardwareAddr, p.GatewayDev.HardwareAddr, newNetworkLayer)
	default:
		return fmt.Errorf("handshake: %w",
			fmt.Errorf("create link layer: %w", fmt.Errorf("type %s not support", newLinkLayerType)))
	}
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	// Serialize layers
	data, err := serialize(newLinkLayer, newNetworkLayer, newTransportLayer, nil)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	// Write packet data
	err = p.upHandle.WritePacketData(data)
	if err != nil {
		return fmt.Errorf("handshake: %w", fmt.Errorf("write: %w", err))
	}

	// TCP Seq
	p.seqsLock.Lock()
	p.seqs[srcAddr.String()]++
	p.seqsLock.Unlock()

	// IPv4 Id
	if newNetworkLayerType == layers.LayerTypeIPv4 {
		p.id++
	}

	return nil
}

func (p *Server) handleListen(packet gopacket.Packet, dev *Device, handle *pcap.Handle) {
	var (
		indicator           *packetIndicator
		encappedIndicator   *packetIndicator
		newNetworkLayerType gopacket.LayerType
		newNetworkLayer     gopacket.NetworkLayer
		newLinkLayerType    gopacket.LayerType
		newLinkLayer        gopacket.Layer
	)

	// Parse packet
	indicator, err := parsePacket(packet)
	if err != nil {
		fmt.Println(fmt.Errorf("handle listen: %w", err))
		return
	}

	// Handshaking with client (SYN+ACK)
	if indicator.SYN {
		err := p.handshake(indicator)
		if err != nil {
			fmt.Println(fmt.Errorf("handle listen: %w", err))
			return
		}
		fmt.Printf("Connect from client %s\n", indicator.SrcAddr())
		return
	}

	// Empty payload
	if indicator.ApplicationLayer == nil {
		return
	}

	// Ack
	srcAddr := indicator.SrcAddr()
	p.acksLock.Lock()
	p.acks[srcAddr.String()] = p.acks[srcAddr.String()] + uint32(len(indicator.ApplicationLayer.LayerContents()))
	p.acksLock.Unlock()

	// Parse encapped packet
	encappedIndicator, err = parseEncappedPacket(indicator.ApplicationLayer.LayerContents())
	if err != nil {
		fmt.Println(fmt.Errorf("handle listen: %w", err))
		return
	}

	// Distribute port
	qPT := quintuple{
		SrcIP:    encappedIndicator.SrcIP.String(),
		SrcPort:  encappedIndicator.SrcPort,
		DstIP:    indicator.SrcIP.String(),
		DstPort:  indicator.SrcPort,
		Protocol: encappedIndicator.TransportLayerType,
	}
	upPort, ok := p.pt[qPT]
	if !ok {
		upPort, err = p.distPort(encappedIndicator.TransportLayerType)
		if err != nil {
			fmt.Println(fmt.Errorf("handle listen: %w", err))
		}
		p.pt[qPT] = upPort
	}

	// Modify transport layer
	switch encappedIndicator.TransportLayerType {
	case layers.LayerTypeTCP:
		tcpLayer := encappedIndicator.TransportLayer.(*layers.TCP)
		tcpLayer.SrcPort = layers.TCPPort(upPort)
	case layers.LayerTypeUDP:
		udpLayer := encappedIndicator.TransportLayer.(*layers.UDP)
		udpLayer.SrcPort = layers.UDPPort(upPort)
	default:
		fmt.Println(fmt.Errorf("handle listen: %w", fmt.Errorf("create transport layer: %w", fmt.Errorf("type %s not support", encappedIndicator.TransportLayerType))))
		return
	}

	// Create new network layer
	newNetworkLayerType = encappedIndicator.NetworkLayerType
	switch newNetworkLayerType {
	case layers.LayerTypeIPv4:
		newNetworkLayer, err = createNetworkLayerIPv4(p.UpDev.IPv4Addr().IP, encappedIndicator.DstIP, encappedIndicator.Id, encappedIndicator.TTL-1, encappedIndicator.TransportLayer)
	case layers.LayerTypeIPv6:
		newNetworkLayer, err = createNetworkLayerIPv6(p.UpDev.IPv6Addr().IP, encappedIndicator.DstIP, encappedIndicator.TransportLayer)
	default:
		fmt.Println(fmt.Errorf("handle listen: %w", fmt.Errorf("create network layer: %w", fmt.Errorf("type %s not support", newNetworkLayerType))))
		return
	}
	if err != nil {
		fmt.Println(fmt.Errorf("handle listen: %w", err))
		return
	}

	// Decide Loopback or Ethernet
	if p.UpDev.IsLoop {
		newLinkLayerType = layers.LayerTypeLoopback
	} else {
		newLinkLayerType = layers.LayerTypeEthernet
	}

	// Create new link layer
	switch newLinkLayerType {
	case layers.LayerTypeLoopback:
		newLinkLayer = createLinkLayerLoopback()
	case layers.LayerTypeEthernet:
		newLinkLayer, err = createLinkLayerEthernet(p.UpDev.HardwareAddr, p.GatewayDev.HardwareAddr, newNetworkLayer)
	default:
		fmt.Println(fmt.Errorf("handle listen: %w", fmt.Errorf("create link layer: %w", fmt.Errorf("type %s not support", newLinkLayerType))))
		return
	}
	if err != nil {
		fmt.Println(fmt.Errorf("handle listen: %w", err))
		return
	}

	// Record the source and the source device of the packet
	qNAT := quintuple{
		SrcIP:    p.UpDev.IPv4Addr().IP.String(),
		SrcPort:  upPort,
		DstIP:    encappedIndicator.DstIP.String(),
		DstPort:  encappedIndicator.DstPort,
		Protocol: encappedIndicator.TransportLayerType,
	}
	natIndicator := serverNATIndicator{
		SrcIP:           indicator.SrcIP.String(),
		SrcPort:         indicator.SrcPort,
		EncappedSrcIP:   encappedIndicator.SrcIP.String(),
		EncappedSrcPort: encappedIndicator.SrcPort,
		Dev:             dev,
		Handle:          handle,
	}
	p.natLock.Lock()
	p.nat[qNAT] = &natIndicator
	p.natLock.Unlock()

	// Serialize layers
	data, err := serialize(newLinkLayer, newNetworkLayer, encappedIndicator.TransportLayer, encappedIndicator.Payload())
	if err != nil {
		fmt.Println(fmt.Errorf("handle listen: %w", err))
		return
	}

	// Write packet data
	err = p.upHandle.WritePacketData(data)
	if err != nil {
		fmt.Println(fmt.Errorf("handle listen: %w", fmt.Errorf("write: %w", err)))
	}
	fmt.Printf("Redirect an inbound %s packet: %s -> %s (%d Bytes)\n",
		encappedIndicator.TransportLayerType, encappedIndicator.SrcAddr(), encappedIndicator.DstAddr(), packet.Metadata().Length)
}

func (p *Server) handleUpstream(packet gopacket.Packet) {
	var (
		indicator           *packetIndicator
		newTransportLayer   *layers.TCP
		upDevIP             net.IP
		newNetworkLayerType gopacket.LayerType
		newNetworkLayer     gopacket.NetworkLayer
		newLinkLayerType    gopacket.LayerType
		newLinkLayer        gopacket.Layer
	)

	// Parse packet
	indicator, err := parsePacket(packet)
	if err != nil {
		fmt.Println(fmt.Errorf("handle upstream: %w", err))
		return
	}

	// NAT
	q := quintuple{
		SrcIP:    indicator.DstIP.String(),
		SrcPort:  indicator.DstPort,
		DstIP:    indicator.SrcIP.String(),
		DstPort:  indicator.SrcPort,
		Protocol: indicator.TransportLayerType,
	}
	p.natLock.RLock()
	natIndicator, ok := p.nat[q]
	p.natLock.RUnlock()
	if !ok {
		return
	}

	// NAT back encapped transport layer
	switch indicator.TransportLayerType {
	case layers.LayerTypeTCP:
		tcpLayer := indicator.TransportLayer.(*layers.TCP)
		tcpLayer.DstPort = layers.TCPPort(natIndicator.EncappedSrcPort)
	case layers.LayerTypeUDP:
		udpLayer := indicator.TransportLayer.(*layers.UDP)
		udpLayer.DstPort = layers.UDPPort(natIndicator.EncappedSrcPort)
	default:
		fmt.Println(fmt.Errorf("handle upstream: %w", fmt.Errorf("create encapped transport layer: %w", fmt.Errorf("type %s not support", indicator.TransportLayerType))))
		return
	}

	// NAT back encapped network layer
	switch indicator.NetworkLayerType {
	case layers.LayerTypeIPv4:
		ipv4Layer := indicator.NetworkLayer.(*layers.IPv4)
		ipv4Layer.DstIP = net.ParseIP(natIndicator.EncappedSrcIP)
	case layers.LayerTypeIPv6:
		ipv6Layer := indicator.NetworkLayer.(*layers.IPv6)
		ipv6Layer.DstIP = net.ParseIP(natIndicator.EncappedSrcIP)
	default:
		fmt.Println(fmt.Errorf("handle upstream: %w", fmt.Errorf("create encapped network layer: %w", fmt.Errorf("type %s not support", indicator.NetworkLayerType))))
		return
	}

	// Set network layer for transport layer
	switch indicator.TransportLayerType {
	case layers.LayerTypeTCP:
		tcpLayer := indicator.TransportLayer.(*layers.TCP)
		err := tcpLayer.SetNetworkLayerForChecksum(indicator.NetworkLayer)
		if err != nil {
			fmt.Println(fmt.Errorf("handle upstream: %w", fmt.Errorf("create encapped network layer: %w", err)))
			return
		}
	case layers.LayerTypeUDP:
		udpLayer := indicator.TransportLayer.(*layers.UDP)
		err := udpLayer.SetNetworkLayerForChecksum(indicator.NetworkLayer)
		if err != nil {
			fmt.Println(fmt.Errorf("handle upstream: %w", fmt.Errorf("create encapped network layer: %w", err)))
			return
		}
	default:
		// TODO: escape default
		break
	}

	// Construct contents of new application layer
	contents, err := serializeWithoutLinkLayer(indicator.NetworkLayer, indicator.TransportLayer, indicator.Payload())
	if err != nil {
		fmt.Println(fmt.Errorf("handle upstream: %w", fmt.Errorf("create application layer: %w", err)))
		return
	}

	// Create new transport layer
	addr := IPPort{IP: net.ParseIP(natIndicator.SrcIP), Port: natIndicator.SrcPort}.String()
	p.seqsLock.RLock()
	p.acksLock.RLock()
	newTransportLayer = createTransportLayerTCP(p.ListenPort, natIndicator.SrcPort, p.seqs[addr], p.acks[addr])
	p.seqsLock.RUnlock()
	p.acksLock.RUnlock()

	// Decide IPv4 or IPv6
	isIPv4 := p.GatewayDev.IPAddr().IP.To4() != nil
	if isIPv4 {
		upDevIP = p.UpDev.IPv4Addr().IP
		newNetworkLayerType = layers.LayerTypeIPv4
	} else {
		upDevIP = p.UpDev.IPv6Addr().IP
		newNetworkLayerType = layers.LayerTypeIPv6
	}
	if upDevIP == nil {
		fmt.Println(fmt.Errorf("handle upstream: %w", errors.New("ip version transition not support")))
		return
	}

	// Create new network layer
	switch newNetworkLayerType {
	case layers.LayerTypeIPv4:
		newNetworkLayer, err = createNetworkLayerIPv4(upDevIP, net.ParseIP(natIndicator.SrcIP), p.id, indicator.TTL-1, newTransportLayer)
	case layers.LayerTypeIPv6:
		newNetworkLayer, err = createNetworkLayerIPv6(upDevIP, net.ParseIP(natIndicator.SrcIP), newTransportLayer)
	default:
		fmt.Println(fmt.Errorf("handle upstream: %w", fmt.Errorf("create network layer: %w", fmt.Errorf("type %s not support", newNetworkLayerType))))
		return
	}
	if err != nil {
		fmt.Println(fmt.Errorf("handle upstream: %w", err))
		return
	}

	// Decide Loopback or Ethernet
	if natIndicator.Dev.IsLoop {
		newLinkLayerType = layers.LayerTypeLoopback
	} else {
		newLinkLayerType = layers.LayerTypeEthernet
	}

	// Create new link layer
	switch newLinkLayerType {
	case layers.LayerTypeLoopback:
		newLinkLayer = createLinkLayerLoopback()
	case layers.LayerTypeEthernet:
		newLinkLayer, err = createLinkLayerEthernet(natIndicator.Dev.HardwareAddr, p.GatewayDev.HardwareAddr, newNetworkLayer)
	default:
		fmt.Println(fmt.Errorf("handle upstream: %w", fmt.Errorf("create link layer: %w", fmt.Errorf("type %s not support", newLinkLayerType))))
		return
	}
	if err != nil {
		fmt.Println(fmt.Errorf("handle upstream: %w", err))
		return
	}

	// Serialize layers
	data, err := serialize(newLinkLayer, newNetworkLayer, newTransportLayer, contents)
	if err != nil {
		fmt.Println(fmt.Errorf("handle upstream: %w", err))
		return
	}

	// Write packet data
	err = natIndicator.Handle.WritePacketData(data)
	if err != nil {
		fmt.Println(fmt.Errorf("handle upstream: %w", fmt.Errorf("write: %w", err)))
		return
	}

	// TCP Seq
	p.seqsLock.Lock()
	p.seqs[addr] = p.seqs[addr] + uint32(len(contents))
	p.seqsLock.Unlock()

	// IPv4 Id
	if newNetworkLayerType == layers.LayerTypeIPv4 {
		p.id++
	}

	fmt.Printf("Redirect an outbound %s packet: %s <- %s (%d Bytes)\n",
		indicator.TransportLayerType, IPPort{IP: net.ParseIP(natIndicator.EncappedSrcIP), Port: natIndicator.EncappedSrcPort}, indicator.SrcAddr(), len(data))
}

func (p *Server) distPort(t gopacket.LayerType) (uint16, error) {
	switch t {
	case layers.LayerTypeTCP:
		port := 49152 + p.tcpPort%16384
		p.tcpPort++
		return port, nil
	case layers.LayerTypeUDP:
		port := 49152 + p.udpPort%16384
		p.udpPort++
		return port, nil
	default:
		return 0, fmt.Errorf("dist port: %w", fmt.Errorf("type %s not support", t))
	}
}
