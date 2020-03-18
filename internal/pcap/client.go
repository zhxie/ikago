package pcap

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"ikago/internal/crypto"
	"ikago/internal/log"
	"net"
	"sync"
	"time"
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
	Crypto          crypto.Crypto
	listenHandles   []*pcap.Handle
	upHandle        *pcap.Handle
	handshakeHandle *pcap.Handle
	cListenPackets  chan devPacket
	seq             uint32
	ack             uint32
	id              uint16
	devMapLock      sync.RWMutex
	devMap          map[string]*devIndicator
}

// Open implements a method opens the pcap
func (p *Client) Open() error {
	p.cListenPackets = make(chan devPacket, 1000)
	p.devMap = make(map[string]*devIndicator)

	// Verify
	if len(p.ListenDevs) <= 0 {
		return errors.New("missing listen device")
	}
	if p.UpDev == nil {
		return errors.New("missing upstream device")
	}
	if p.GatewayDev == nil {
		return errors.New("missing gateway device")
	}
	if len(p.ListenDevs) == 1 {
		log.Infof("Listen on %s\n", p.ListenDevs[0].AliasString())
	} else {
		log.Infoln("Listen on:")
		for _, dev := range p.ListenDevs {
			log.Infof("  %s\n", dev.AliasString())
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
		log.Infof("Route upstream from %s [%s]: %s to gateway [%s]: %s\n", p.UpDev.Alias, p.UpDev.HardwareAddr, strUpIPs, p.GatewayDev.HardwareAddr, p.GatewayDev.IPAddr().IP)
	} else {
		log.Infof("Route upstream to loopback %s\n", p.UpDev.Alias)
	}

	// Handle for handshaking
	var err error
	p.handshakeHandle, err = pcap.OpenLive(p.UpDev.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open handshake device %s: %w", p.UpDev.Name, err)
	}
	defer p.handshakeHandle.Close()
	err = p.handshakeHandle.SetBPFFilter(fmt.Sprintf("tcp && tcp[tcpflags] & tcp-ack != 0 && dst port %d && (src host %s && src port %d)",
		p.UpPort, p.ServerIP, p.ServerPort))
	if err != nil {
		return fmt.Errorf("set bpf filter: %w", err)
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
		return fmt.Errorf("handshake: %w", err)
	}
	log.Infof("Connect to server %s\n", IPPort{IP: p.ServerIP, Port: p.ServerPort})

	packet := <-c

	if packet == nil {
		return fmt.Errorf("handshake: %w", errors.New("timeout"))
	}
	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return fmt.Errorf("handshake: %w", fmt.Errorf("parse packet: %w", errors.New("missing transport layer")))
	}
	transportLayerType := transportLayer.LayerType()
	switch transportLayerType {
	case layers.LayerTypeTCP:
		tcpLayer := transportLayer.(*layers.TCP)
		if tcpLayer.RST {
			return fmt.Errorf("handshake: %w", errors.New("connection reset"))
		}
		if !tcpLayer.SYN {
			return fmt.Errorf("handshake: %w", fmt.Errorf("parse packet: %w", errors.New("invalid")))
		}
	default:
		return fmt.Errorf("handshake: %w", fmt.Errorf("parse packet: %w", fmt.Errorf("transport layer type %s not support", transportLayerType)))
	}

	// Latency test
	d := time.Now().Sub(t)

	// Handshaking with server (ACK)
	err = p.handshakeACK(packet)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	log.Infof("Connected to server %s in %.3f ms (two-way)\n", IPPort{IP: p.ServerIP, Port: p.ServerPort}, float64(d.Microseconds())/1000)

	// Close in advance
	p.handshakeHandle.Close()

	// Handles for listening
	p.listenHandles = make([]*pcap.Handle, 0)
	for _, dev := range p.ListenDevs {
		handle, err := pcap.OpenLive(dev.Name, 1600, true, pcap.BlockForever)
		if err != nil {
			return fmt.Errorf("open listen device %s: %w", dev.Name, err)
		}
		f := formatOrSrcFilters(p.Filters)
		err = handle.SetBPFFilter(fmt.Sprintf("((tcp || udp) && %s && not (src host %s && src port %d)) || (icmp && %s && not src host %s)",
			f, p.ServerIP, p.ServerPort, f, p.ServerIP))
		if err != nil {
			return fmt.Errorf("set bpf fileter: %w", err)
		}
		p.listenHandles = append(p.listenHandles, handle)
	}

	// Handle for routing upstream
	p.upHandle, err = pcap.OpenLive(p.UpDev.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open upstream device %s: %w", p.UpDev.Name, err)
	}
	err = p.upHandle.SetBPFFilter(fmt.Sprintf("(tcp && dst port %d && (src host %s && src port %d))",
		p.UpPort, p.ServerIP, p.ServerPort))
	if err != nil {
		return fmt.Errorf("set bpf filter: %w", err)
	}

	// Start handling
	for i, handle := range p.listenHandles {
		dev := p.ListenDevs[i]
		packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
		copyHandle := handle
		go func() {
			for packet := range packetSrc.Packets() {
				// Avoid conflict
				p.cListenPackets <- devPacket{packet: packet, dev: dev, handle: copyHandle}
			}
		}()
	}
	go func() {
		for devPacket := range p.cListenPackets {
			err := p.handleListen(devPacket.packet, devPacket.dev, devPacket.handle)
			if err != nil {
				log.Errorln(fmt.Errorf("handle listen in %s: %w", devPacket.dev.Alias, err))
				log.Verboseln(devPacket.packet)
			}
		}
	}()
	packetSrc := gopacket.NewPacketSource(p.upHandle, p.upHandle.LinkType())
	for packet := range packetSrc.Packets() {
		err := p.handleUpstream(packet)
		if err != nil {
			log.Errorln(fmt.Errorf("handle upstream: %w", err))
			log.Verboseln(packet)
		}
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

// handshakeSYN sends TCP SYN to the server in handshaking
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
		return errors.New("ip version transition not support")
	}

	// Create new network layer
	var err error
	switch networkLayerType {
	case layers.LayerTypeIPv4:
		networkLayer, err = createNetworkLayerIPv4(upDevIP, p.ServerIP, p.id, 128, transportLayer)
	case layers.LayerTypeIPv6:
		networkLayer, err = createNetworkLayerIPv6(upDevIP, p.ServerIP, 128, transportLayer)
	default:
		return fmt.Errorf("create network layer: %w", fmt.Errorf("network layer type %s not support", networkLayerType))
	}
	if err != nil {
		return fmt.Errorf("create network layer: %w", err)
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
		return fmt.Errorf("create link layer: %w", fmt.Errorf("link layer type %s not support", linkLayerType))
	}
	if err != nil {
		return fmt.Errorf("create link layer: %w", err)
	}

	// Serialize layers
	data, err := serialize(linkLayer.(gopacket.SerializableLayer), networkLayer.(gopacket.SerializableLayer), transportLayer)
	if err != nil {
		return fmt.Errorf("serialize: %w", err)
	}

	// Write packet data
	err = p.handshakeHandle.WritePacketData(data)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}

	// TCP Seq
	p.seq++

	// IPv4 Id
	if networkLayerType == layers.LayerTypeIPv4 {
		p.id++
	}

	return nil
}

// handshakeACK sends TCP ACK to the server in handshaking
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
		return fmt.Errorf("parse packet: %w", err)
	}

	if indicator.transportLayerType != layers.LayerTypeTCP {
		return fmt.Errorf("transport layer type %s not support", indicator.transportLayerType)
	}

	// TCP Ack
	p.ack = indicator.tcpLayer().Seq + 1

	// Create transport layer
	newTransportLayer = createTCPLayerACK(indicator.dstPort(), indicator.srcPort(), p.seq, p.ack)

	// Decide IPv4 or IPv6
	if indicator.dstIP().To4() != nil {
		newNetworkLayerType = layers.LayerTypeIPv4
	} else {
		newNetworkLayerType = layers.LayerTypeIPv6
	}

	// Create new network layer
	switch newNetworkLayerType {
	case layers.LayerTypeIPv4:
		newNetworkLayer, err = createNetworkLayerIPv4(indicator.dstIP(), indicator.srcIP(), p.id, 128, newTransportLayer)
	case layers.LayerTypeIPv6:
		newNetworkLayer, err = createNetworkLayerIPv6(indicator.dstIP(), indicator.srcIP(), 128, newTransportLayer)
	default:
		return fmt.Errorf("create network layer: %w", fmt.Errorf("network layer type %s not support", newNetworkLayerType))
	}
	if err != nil {
		return fmt.Errorf("create network layer: %w", err)
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
		return fmt.Errorf("create link layer: %w", fmt.Errorf("link layer type %s not support", newLinkLayerType))
	}
	if err != nil {
		return fmt.Errorf("create link layer: %w", err)
	}

	// Serialize layers
	data, err := serialize(newLinkLayer.(gopacket.SerializableLayer), newNetworkLayer.(gopacket.SerializableLayer), newTransportLayer)
	if err != nil {
		return fmt.Errorf("serialize: %w", err)
	}

	// Write packet data
	err = p.handshakeHandle.WritePacketData(data)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}

	// IPv4 Id
	if newNetworkLayerType == layers.LayerTypeIPv4 {
		p.id++
	}

	return nil
}

// handleListen handles TCP and UDP packets from sources
func (p *Client) handleListen(packet gopacket.Packet, dev *Device, handle *pcap.Handle) error {
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
		return fmt.Errorf("parse packet: %w", err)
	}

	// Construct contents of new application layer
	contents, err := serializeRaw(indicator.networkLayer.(gopacket.SerializableLayer),
		indicator.transportLayer.(gopacket.SerializableLayer),
		gopacket.Payload(indicator.payload()))
	if err != nil {
		return fmt.Errorf("create application layer: %w", err)
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
		return errors.New("ip version transition not support")
	}

	// Create new network layer
	switch newNetworkLayerType {
	case layers.LayerTypeIPv4:
		newNetworkLayer, err = createNetworkLayerIPv4(upDevIP, p.ServerIP, p.id, indicator.ipv4Layer().TTL-1, newTransportLayer)
	case layers.LayerTypeIPv6:
		newNetworkLayer, err = createNetworkLayerIPv6(upDevIP, p.ServerIP, 128, newTransportLayer)
	default:
		return fmt.Errorf("create network layer: %w", fmt.Errorf("network layer type %s not support", newNetworkLayerType))
	}
	if err != nil {
		return fmt.Errorf("create network layer: %w", err)
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
		return fmt.Errorf("create link layer: %w", fmt.Errorf("link layer type %s not support", newLinkLayerType))
	}
	if err != nil {
		return fmt.Errorf("create link layer: %w", err)
	}

	// Encrypt
	contents, err = p.Crypto.Encrypt(contents)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	// Serialize layers
	data, err := serialize(newLinkLayer.(gopacket.SerializableLayer),
		newNetworkLayer.(gopacket.SerializableLayer),
		newTransportLayer,
		gopacket.Payload(contents))
	if err != nil {
		return fmt.Errorf("serialize: %w", err)
	}

	// Write packet data
	err = p.upHandle.WritePacketData(data)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}

	// Record the source device of the packet
	p.devMapLock.Lock()
	p.devMap[indicator.natSrc().String()] = &devIndicator{dev: dev, handle: handle}
	p.devMapLock.Unlock()

	// TCP Seq
	p.seq = p.seq + uint32(len(contents))

	// IPv4 Id
	if newNetworkLayerType == layers.LayerTypeIPv4 {
		p.id++
	}

	log.Verbosef("Redirect an outbound %s packet: %s -> %s (%d Bytes)\n",
		indicator.transportLayerType, indicator.src(), indicator.dst(), packet.Metadata().Length)

	return nil
}

// handleUpstream handles TCP packets from the server
func (p *Client) handleUpstream(packet gopacket.Packet) error {
	var (
		embIndicator     *packetIndicator
		newLinkLayer     gopacket.Layer
		newLinkLayerType gopacket.LayerType
		dev              *Device
		handle           *pcap.Handle
	)

	// Parse packet
	applicationLayer := packet.ApplicationLayer()

	// Empty payload
	if applicationLayer == nil {
		return errors.New("empty payload")
	}

	// TCP Ack
	p.ack = p.ack + uint32(len(applicationLayer.LayerContents()))

	// Decrypt
	contents, err := p.Crypto.Decrypt(applicationLayer.LayerContents())
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	// Parse embedded packet
	embIndicator, err = parseEmbPacket(contents)
	if err != nil {
		return fmt.Errorf("parse embedded packet: %w", err)
	}

	// Check map
	p.devMapLock.RLock()
	devIndicator, ok := p.devMap[embIndicator.natDst().String()]
	p.devMapLock.RUnlock()
	if !ok {
		log.Verboseln(fmt.Errorf("missing %s nat to %s", embIndicator.natProto(), embIndicator.natDst()))
		dev = p.UpDev
		handle = p.upHandle
	} else {
		dev = devIndicator.dev
		handle = devIndicator.handle
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
		newLinkLayer, err = createLinkLayerEthernet(dev.HardwareAddr, p.GatewayDev.HardwareAddr, embIndicator.networkLayer)
	default:
		return fmt.Errorf("create link layer: %w", fmt.Errorf("link layer type %s not support", newLinkLayerType))
	}
	if err != nil {
		return fmt.Errorf("create link layer: %w", err)
	}

	// Serialize layers
	data, err := serializeRaw(newLinkLayer.(gopacket.SerializableLayer),
		embIndicator.networkLayer.(gopacket.SerializableLayer),
		embIndicator.transportLayer.(gopacket.SerializableLayer),
		gopacket.Payload(embIndicator.payload()))
	if err != nil {
		return fmt.Errorf("serialize: %w", err)
	}

	// Write packet data
	err = handle.WritePacketData(data)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}

	log.Verbosef("Redirect an inbound %s packet: %s <- %s (%d Bytes)\n",
		embIndicator.transportLayerType, embIndicator.dst(), embIndicator.src(), len(data))

	return nil
}

func (p *Client) bypass(packet gopacket.Packet) error {
	if len(packet.Layers()) < 0 {
		return fmt.Errorf("missing link layer")
	}
	linkLayer := packet.Layers()[0]
	if linkLayer == nil {
		return fmt.Errorf("missing link layer")
	}

	// Create link layer
	linkLayerType := linkLayer.LayerType()
	switch linkLayerType {
	case layers.LayerTypeLoopback:
		break
	case layers.LayerTypeEthernet:
		ethernetLayer := linkLayer.(*layers.Ethernet)
		ethernetLayer.DstMAC = p.GatewayDev.HardwareAddr
	default:
		return fmt.Errorf("create link layer: %w", fmt.Errorf("link layer type %s not support", linkLayerType))
	}

	// Serialize layers
	data, err := serializeRaw(linkLayer.(gopacket.SerializableLayer), gopacket.Payload(linkLayer.LayerPayload()))
	if err != nil {
		return fmt.Errorf("serialize: %w", err)
	}

	// Write packet data
	err = p.upHandle.WritePacketData(data)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}

	return nil
}
