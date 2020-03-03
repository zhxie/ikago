package pcap

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Client describes the packet capture on the client side
type Client struct {
	Filters         []Filter
	UpPort          uint16
	ServerIP        net.IP
	ServerPort      uint16
	ListenDevs      []*Device
	UpDev           *Device
	GatewayDev      *Device
	listenHandles   []*pcap.Handle
	upHandle        *pcap.Handle
	handshakeHandle *pcap.Handle
	cListenPackets  chan devPacket
	seq             uint32
	ack             uint32
	id              uint16
	natLock         sync.RWMutex
	nat             map[quintuple]*clientNATIndicator
}

// Open implements a method opens the pcap
func (p *Client) Open() error {
	p.cListenPackets = make(chan devPacket, 1000)
	p.nat = make(map[quintuple]*clientNATIndicator)

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
		fmt.Printf("Listen on %s\n", p.ListenDevs[0].AliasString())
	} else {
		fmt.Println("Listen on:")
		for _, dev := range p.ListenDevs {
			fmt.Printf("  %s\n", dev.AliasString())
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

	// Handle for handshaking
	var err error
	p.handshakeHandle, err = pcap.OpenLive(p.UpDev.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer p.handshakeHandle.Close()
	err = p.handshakeHandle.SetBPFFilter(fmt.Sprintf("tcp && tcp[tcpflags] & tcp-ack != 0 && dst port %d && (src host %s && src port %d)",
		p.UpPort, p.ServerIP, p.ServerPort))
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}

	c := make(chan gopacket.Packet, 1)
	go func() {
		packetSrc := gopacket.NewPacketSource(p.handshakeHandle, p.handshakeHandle.LinkType())
		for packet := range packetSrc.Packets() {
			c <- packet
		}
	}()
	go func() {
		time.Sleep(3 * time.Second)
		c <- nil
	}()

	// Latency test
	t := time.Now()

	// Handshaking with server (SYN)
	err = p.handshakeSYN()
	if err != nil {
		return fmt.Errorf("open: %w", fmt.Errorf("handshake: %w", err))
	}
	fmt.Printf("Connect to server %s\n", IPPort{IP: p.ServerIP, Port: p.ServerPort})

	packet := <-c
	if packet == nil {
		return fmt.Errorf("open: %w", fmt.Errorf("handshake: %w", errors.New("timeout")))
	}
	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return fmt.Errorf("open: %w", fmt.Errorf("handshake: %w", errors.New("missing transport layer")))
	}
	transportLayerType := transportLayer.LayerType()
	switch transportLayerType {
	case layers.LayerTypeTCP:
		tcpLayer := transportLayer.(*layers.TCP)
		if tcpLayer.RST {
			return fmt.Errorf("open: %w", fmt.Errorf("handshake: %w", errors.New("connection reset")))
		}
		if !tcpLayer.SYN {
			return fmt.Errorf("open: %w", fmt.Errorf("handshake: %w", errors.New("missing synchronization flag")))
		}
	default:
		return fmt.Errorf("open: %w", fmt.Errorf("handshake: %w", fmt.Errorf("type %s not support", transportLayerType)))
	}

	// Latency test
	d := time.Now().Sub(t)

	// Handshaking with server (ACK)
	err = p.handshakeACK(packet)
	if err != nil {
		return fmt.Errorf("open: %w", fmt.Errorf("handshake: %w", err))
	}
	fmt.Printf("Connected to server %s in %d ms\n", IPPort{IP: p.ServerIP, Port: p.ServerPort}, d.Milliseconds())

	// Close in advance
	p.handshakeHandle.Close()

	// TODO: STUN

	// Handles for listening
	p.listenHandles = make([]*pcap.Handle, 0)
	for _, dev := range p.ListenDevs {
		handle, err := pcap.OpenLive(dev.Name, 1600, true, pcap.BlockForever)
		if err != nil {
			return fmt.Errorf("open: %w", err)
		}
		err = handle.SetBPFFilter(fmt.Sprintf("(tcp || udp) && %s && not (src host %s && src port %d)",
			formatOrSrcFilters(p.Filters), p.ServerIP, p.ServerPort))
		if err != nil {
			return fmt.Errorf("open: %w", err)
		}
		p.listenHandles = append(p.listenHandles, handle)
	}

	// Handle for routing upstream
	p.upHandle, err = pcap.OpenLive(p.UpDev.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	err = p.upHandle.SetBPFFilter(fmt.Sprintf("(tcp || udp) && dst port %d && (src host %s && src port %d)",
		p.UpPort, p.ServerIP, p.ServerPort))
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}

	// Start handling
	for i, handle := range p.listenHandles {
		dev := p.ListenDevs[i]
		packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
		go func() {
			for packet := range packetSrc.Packets() {
				// Avoid conflict
				p.cListenPackets <- devPacket{Packet: packet, Dev: dev, Handle: handle}
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
func (p *Client) Close() {
	for _, handle := range p.listenHandles {
		handle.Close()
	}
	p.upHandle.Close()
}

func (p *Client) handshakeSYN() error {
	var (
		transportLayer   *layers.TCP
		upDevIP          net.IP
		networkLayerType gopacket.LayerType
		networkLayer     gopacket.NetworkLayer
		linkLayerType    gopacket.LayerType
		linkLayer        gopacket.Layer
	)

	// Create transport layer
	transportLayer = createTCPLayerSYN(p.UpPort, p.ServerPort, p.seq)

	// Decide IPv4 or IPv6
	isIPv4 := p.GatewayDev.IPAddr().IP.To4() != nil
	if isIPv4 {
		upDevIP = p.UpDev.IPv4Addr().IP
		networkLayerType = layers.LayerTypeIPv4
	} else {
		upDevIP = p.UpDev.IPv6Addr().IP
		networkLayerType = layers.LayerTypeIPv6
	}
	if upDevIP == nil {
		return fmt.Errorf("handshake: %w", errors.New("ip version transition not support"))
	}

	// Create new network layer
	var err error
	switch networkLayerType {
	case layers.LayerTypeIPv4:
		networkLayer, err = createNetworkLayerIPv4(upDevIP, p.ServerIP, p.id, 128, transportLayer)
	case layers.LayerTypeIPv6:
		networkLayer, err = createNetworkLayerIPv6(upDevIP, p.ServerIP, transportLayer)
	default:
		return fmt.Errorf("handshake: %w", fmt.Errorf("create network layer: %w", fmt.Errorf("type %s not support", networkLayerType)))
	}
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	// Decide Loopback or Ethernet
	if p.UpDev.IsLoop {
		linkLayerType = layers.LayerTypeLoopback
	} else {
		linkLayerType = layers.LayerTypeEthernet
	}

	// Create new link layer
	switch linkLayerType {
	case layers.LayerTypeLoopback:
		linkLayer = createLinkLayerLoopback()
	case layers.LayerTypeEthernet:
		linkLayer, err = createLinkLayerEthernet(p.UpDev.HardwareAddr, p.GatewayDev.HardwareAddr, networkLayer)
	default:
		return fmt.Errorf("handshake: %w", fmt.Errorf("create link layer: %w", fmt.Errorf("type %s not support", linkLayerType)))
	}
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	// Serialize layers
	data, err := serialize(linkLayer, networkLayer, transportLayer, nil)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	// Write packet data
	err = p.handshakeHandle.WritePacketData(data)
	if err != nil {
		return fmt.Errorf("handshake: %w", fmt.Errorf("write: %w", err))
	}

	// TCP Seq
	p.seq++

	// IPv4 Id
	if networkLayerType == layers.LayerTypeIPv4 {
		p.id++
	}

	return nil
}

func (p *Client) handshakeACK(packet gopacket.Packet) error {
	var (
		indicator           *packetIndicator
		newTransportLayer   *layers.TCP
		newNetworkLayerType gopacket.LayerType
		newNetworkLayer     gopacket.NetworkLayer
		newLinkLayerType    gopacket.LayerType
		newLinkLayer        gopacket.Layer
	)

	// Parse packet
	indicator, err := parsePacket(packet)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	// TCP Ack
	p.ack = indicator.Seq + 1

	// Create transport layer
	newTransportLayer = createTCPLayerACK(indicator.DstPort, indicator.SrcPort, p.seq, p.ack)

	// Decide IPv4 or IPv6
	if indicator.DstIP.To4() != nil {
		newNetworkLayerType = layers.LayerTypeIPv4
	} else {
		newNetworkLayerType = layers.LayerTypeIPv6
	}

	// Create new network layer
	switch newNetworkLayerType {
	case layers.LayerTypeIPv4:
		newNetworkLayer, err = createNetworkLayerIPv4(indicator.DstIP, indicator.SrcIP, p.id, 128, newTransportLayer)
	case layers.LayerTypeIPv6:
		newNetworkLayer, err = createNetworkLayerIPv6(indicator.DstIP, indicator.SrcIP, newTransportLayer)
	default:
		return fmt.Errorf("handshake: %w", fmt.Errorf("create network layer: %w", fmt.Errorf("type %s not support", newNetworkLayerType)))
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
		return fmt.Errorf("handshake: %w", fmt.Errorf("create link layer: %w", fmt.Errorf("type %s not support", newLinkLayerType)))
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
	err = p.handshakeHandle.WritePacketData(data)
	if err != nil {
		return fmt.Errorf("handshake: %w", fmt.Errorf("write: %w", err))
	}

	// IPv4 Id
	if newNetworkLayerType == layers.LayerTypeIPv4 {
		p.id++
	}

	return nil
}

func (p *Client) handleListen(packet gopacket.Packet, dev *Device, handle *pcap.Handle) {
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
		fmt.Println(fmt.Errorf("handle listen: %w", err))
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
		break
	}

	// Construct contents of new application layer
	contents, err := serializeWithoutLinkLayer(indicator.NetworkLayer, indicator.TransportLayer, indicator.Payload())
	if err != nil {
		fmt.Println(fmt.Errorf("handle upstream: %w", fmt.Errorf("create application layer: %w", err)))
		return
	}

	// Create new transport layer in TCP
	newTransportLayer = createTransportLayerTCP(p.UpPort, p.ServerPort, p.seq, p.ack)

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
		fmt.Println(fmt.Errorf("handle listen: %w", errors.New("ip version transition not support")))
		return
	}

	// Create new network layer
	switch newNetworkLayerType {
	case layers.LayerTypeIPv4:
		newNetworkLayer, err = createNetworkLayerIPv4(upDevIP, p.ServerIP, p.id, indicator.TTL-1, newTransportLayer)
	case layers.LayerTypeIPv6:
		newNetworkLayer, err = createNetworkLayerIPv6(upDevIP, p.ServerIP, newTransportLayer)
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

	// Record the source device of the packet
	q := quintuple{
		SrcIP:    indicator.SrcIP.String(),
		SrcPort:  indicator.SrcPort,
		DstIP:    indicator.DstIP.String(),
		DstPort:  indicator.DstPort,
		Protocol: indicator.TransportLayerType,
	}
	p.natLock.Lock()
	p.nat[q] = &clientNATIndicator{Dev: dev, Handle: handle}
	p.natLock.Unlock()

	// Serialize layers
	data, err := serialize(newLinkLayer, newNetworkLayer, newTransportLayer, contents)
	if err != nil {
		fmt.Println(fmt.Errorf("handle listen: %w", err))
		return
	}

	// Write packet data
	err = p.upHandle.WritePacketData(data)
	if err != nil {
		fmt.Println(fmt.Errorf("handle listen: %w", fmt.Errorf("write: %w", err)))
		return
	}

	// TCP Seq
	p.seq = p.seq + uint32(len(contents))

	// IPv4 Id
	if newNetworkLayerType == layers.LayerTypeIPv4 {
		p.id++
	}

	fmt.Printf("Redirect an outbound %s packet: %s -> %s (%d Bytes)\n",
		indicator.TransportLayerType, indicator.SrcAddr(), indicator.DstAddr(), packet.Metadata().Length)
}

func (p *Client) handleUpstream(packet gopacket.Packet) {
	var (
		encappedIndicator *packetIndicator
		newLinkLayer      gopacket.Layer
		newLinkLayerType  gopacket.LayerType
		dev               *Device
		handle            *pcap.Handle
	)

	// Parse packet
	applicationLayer := packet.ApplicationLayer()

	// Empty payload
	if applicationLayer == nil {
		return
	}

	// TCP Ack
	p.ack = p.ack + uint32(len(applicationLayer.LayerContents()))

	// Parse encapped packet
	encappedIndicator, err := parseEncappedPacket(applicationLayer.LayerContents())
	if err != nil {
		fmt.Println(fmt.Errorf("handle upstream: %w", err))
		return
	}

	// Set network layer for encapped transport layer
	switch encappedIndicator.TransportLayerType {
	case layers.LayerTypeTCP:
		tcpLayer := encappedIndicator.TransportLayer.(*layers.TCP)
		err := tcpLayer.SetNetworkLayerForChecksum(encappedIndicator.NetworkLayer)
		if err != nil {
			fmt.Println(fmt.Errorf("handle upstream: %w", fmt.Errorf("create network layer: %w", err)))
			return
		}
	case layers.LayerTypeUDP:
		udpLayer := encappedIndicator.TransportLayer.(*layers.UDP)
		err := udpLayer.SetNetworkLayerForChecksum(encappedIndicator.NetworkLayer)
		if err != nil {
			fmt.Println(fmt.Errorf("handle upstream: %w", fmt.Errorf("create network layer: %w", err)))
			return
		}
	default:
		break
	}

	// Check map
	q := quintuple{
		SrcIP:    encappedIndicator.DstIP.String(),
		SrcPort:  encappedIndicator.DstPort,
		DstIP:    encappedIndicator.SrcIP.String(),
		DstPort:  encappedIndicator.SrcPort,
		Protocol: encappedIndicator.TransportLayerType,
	}
	p.natLock.RLock()
	ps, ok := p.nat[q]
	p.natLock.RUnlock()
	if !ok {
		dev = p.UpDev
		handle = p.upHandle
	} else {
		dev = ps.Dev
		handle = ps.Handle
	}

	// Decide Loopback or Ethernet
	if dev.IsLoop {
		newLinkLayerType = layers.LayerTypeLoopback
	} else {
		newLinkLayerType = layers.LayerTypeEthernet
	}

	// Create new link layer
	switch newLinkLayerType {
	case layers.LayerTypeLoopback:
		newLinkLayer = createLinkLayerLoopback()
	case layers.LayerTypeEthernet:
		newLinkLayer, err = createLinkLayerEthernet(dev.HardwareAddr, p.GatewayDev.HardwareAddr, encappedIndicator.NetworkLayer)
	default:
		fmt.Println(fmt.Errorf("handle upstream: %w", fmt.Errorf("create link layer: %w", fmt.Errorf("type %s not support", newLinkLayerType))))
		return
	}
	if err != nil {
		fmt.Println(fmt.Errorf("handle upstream: %w", err))
		return
	}

	// Serialize layers
	data, err := serialize(newLinkLayer, encappedIndicator.NetworkLayer, encappedIndicator.TransportLayer, encappedIndicator.Payload())
	if err != nil {
		fmt.Println(fmt.Errorf("handle upstream: %w", err))
		return
	}

	// Write packet data
	err = handle.WritePacketData(data)
	if err != nil {
		fmt.Println(fmt.Errorf("handle upstream: %w", fmt.Errorf("write: %w", err)))
		return
	}
	fmt.Printf("Redirect an inbound %s packet: %s <- %s (%d Bytes)\n",
		encappedIndicator.TransportLayerType, encappedIndicator.SrcAddr(), encappedIndicator.DstAddr(), len(data))
}
