package pcap

import (
	"errors"
	"fmt"
	"ikago/internal/addr"
	"ikago/internal/crypto"
	"ikago/internal/log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Server describes the packet capture on the server side
type Server struct {
	Port           uint16
	ListenDevs     []*Device
	UpDev          *Device
	GatewayDev     *Device
	Crypto         crypto.Crypto
	listenHandles  []*pcap.Handle
	upHandle       *pcap.Handle
	cListenPackets chan devPacket
	seqsLock       sync.RWMutex
	seqs           map[string]uint32
	acksLock       sync.RWMutex
	acks           map[string]uint32
	id             uint16
	nextTCPPort    uint16
	tcpPortPool    []time.Time
	nextUDPPort    uint16
	udpPortPool    []time.Time
	nextICMPv4Id   uint16
	icmpv4IdPool   []time.Time
	valueMap       map[quintuple]uint16
	natLock        sync.RWMutex
	nat            map[natGuide]*natIndicator
}

const keepAlive float64 = 30 // seconds

// NewServer returns a new pcap server
func NewServer() *Server {
	return &Server{
		cListenPackets: make(chan devPacket, 1000),
		seqs:           make(map[string]uint32),
		acks:           make(map[string]uint32),
		id:             0,
		tcpPortPool:    make([]time.Time, 16384),
		udpPortPool:    make([]time.Time, 16384),
		icmpv4IdPool:   make([]time.Time, 65536),
		valueMap:       make(map[quintuple]uint16),
		nat:            make(map[natGuide]*natIndicator),
	}
}

// Open implements a method opens the pcap
func (p *Server) Open() error {
	// Verify
	if p.Port <= 0 || p.Port > 65535 {
		return fmt.Errorf("port %d out of range", p.Port)
	}
	if len(p.ListenDevs) <= 0 {
		return errors.New("missing listen device")
	}
	if p.UpDev == nil {
		return errors.New("missing upstream device")
	}
	if p.GatewayDev == nil {
		return errors.New("missing gateway")
	}

	if len(p.ListenDevs) == 1 {
		log.Infof("Listen on %s\n", p.ListenDevs[0])
	} else {
		log.Infoln("Listen on:")
		for _, dev := range p.ListenDevs {
			log.Infof("  %s\n", dev)
		}
	}
	if !p.GatewayDev.IsLoop {
		log.Infof("Route upstream from %s to %s\n", p.UpDev, p.GatewayDev)
	} else {
		log.Infof("Route upstream in %s\n", p.UpDev)
	}

	// Handles for listening
	p.listenHandles = make([]*pcap.Handle, 0)
	for _, dev := range p.ListenDevs {
		handle, err := pcap.OpenLive(dev.Name, 1600, true, pcap.BlockForever)
		if err != nil {
			return fmt.Errorf("open listen device %s: %w", dev.Name, err)
		}
		err = handle.SetBPFFilter(fmt.Sprintf("tcp && dst port %d", p.Port))
		if err != nil {
			return fmt.Errorf("set bpf filter: %w", err)
		}
		p.listenHandles = append(p.listenHandles, handle)
	}
	// Handles for routing upstream
	var err error
	p.upHandle, err = pcap.OpenLive(p.UpDev.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open upstream device %s: %w", p.UpDev.Name, err)
	}
	err = p.upHandle.SetBPFFilter(fmt.Sprintf("((tcp || udp) && not dst port %d) || icmp", p.Port))
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
func (p *Server) Close() {
	for _, handle := range p.listenHandles {
		handle.Close()
	}
	p.upHandle.Close()
}

// handshake sends TCP SYN ACK to the client in handshaking
func (p *Server) handshake(indicator *packetIndicator) error {
	var (
		newTransportLayer   *layers.TCP
		newNetworkLayerType gopacket.LayerType
		newNetworkLayer     gopacket.NetworkLayer
		newLinkLayerType    gopacket.LayerType
		newLinkLayer        gopacket.Layer
	)

	if indicator.transportLayerType != layers.LayerTypeTCP {
		return fmt.Errorf("transport layer type %s not support", indicator.transportLayerType)
	}

	// Initial TCP Seq
	srcIPPort := addr.IPPort{MemberIP: indicator.srcIP(), Port: indicator.srcPort()}
	p.seqsLock.Lock()
	p.seqs[srcIPPort.String()] = 0
	p.seqsLock.Unlock()

	// TCK Ack
	p.acksLock.Lock()
	p.acks[srcIPPort.String()] = indicator.tcpLayer().Seq + 1
	p.acksLock.Unlock()

	// Create transport layer
	p.seqsLock.RLock()
	p.acksLock.RLock()
	newTransportLayer = createTCPLayerSYNACK(p.Port, indicator.srcPort(), p.seqs[srcIPPort.String()], p.acks[srcIPPort.String()])
	p.seqsLock.RUnlock()
	p.acksLock.RUnlock()

	// Decide IPv4 or IPv6
	if indicator.dstIP().To4() != nil {
		newNetworkLayerType = layers.LayerTypeIPv4
	} else {
		newNetworkLayerType = layers.LayerTypeIPv6
	}

	// Create new network layer
	var err error
	switch newNetworkLayerType {
	case layers.LayerTypeIPv4:
		newNetworkLayer, err = createNetworkLayerIPv4(indicator.dstIP(), indicator.srcIP(), p.id, 128, newTransportLayer)
	case layers.LayerTypeIPv6:
		newNetworkLayer, err = createNetworkLayerIPv6(indicator.dstIP(), indicator.srcIP(), 64, newTransportLayer)
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
	err = p.upHandle.WritePacketData(data)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}

	// TCP Seq
	p.seqsLock.Lock()
	p.seqs[srcIPPort.String()]++
	p.seqsLock.Unlock()

	// IPv4 Id
	if newNetworkLayerType == layers.LayerTypeIPv4 {
		p.id++
	}

	return nil
}

// handleListen handles TCP packets from clients
func (p *Server) handleListen(packet gopacket.Packet, dev *Device, handle *pcap.Handle) error {
	var (
		indicator             *packetIndicator
		embIndicator          *packetIndicator
		upValue               uint16
		newTransportLayerType gopacket.LayerType
		newTransportLayer     gopacket.Layer
		newNetworkLayerType   gopacket.LayerType
		newNetworkLayer       gopacket.NetworkLayer
		upIP                  net.IP
		newLinkLayerType      gopacket.LayerType
		newLinkLayer          gopacket.Layer
		guide                 natGuide
		ni                    *natIndicator
	)

	// Parse packet
	indicator, err := parsePacket(packet)
	if err != nil {
		return fmt.Errorf("parse packet: %w", err)
	}

	if indicator.transportLayerType != layers.LayerTypeTCP {
		return fmt.Errorf("transport layer type %s not support", indicator.transportLayerType)
	}

	// Handshaking with client (SYN+ACK)
	if indicator.tcpLayer().SYN {
		err := p.handshake(indicator)
		if err != nil {
			return fmt.Errorf("handshake: %w", err)
		}

		log.Infof("Connect from client %s\n", indicator.natSrc())

		return nil
	}

	// Empty payload (An ACK handshaking will also be recognized as empty payload)
	if len(indicator.payload()) <= 0 {
		return errors.New("empty payload")
	}

	// Ack
	srcIPPort := addr.IPPort{MemberIP: indicator.srcIP(), Port: indicator.srcPort()}
	p.acksLock.Lock()
	p.acks[srcIPPort.String()] = p.acks[srcIPPort.String()] + uint32(len(indicator.payload()))
	p.acksLock.Unlock()

	// Decrypt
	contents, err := p.Crypto.Decrypt(indicator.payload())
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	// Parse embedded packet
	embIndicator, err = parseEmbPacket(contents)
	if err != nil {
		return fmt.Errorf("parse embedded packet: %w", err)
	}

	// Distribute port/Id by source and client address and protocol
	q := quintuple{
		src:   embIndicator.natSrc().String(),
		dst:   indicator.natSrc().String(),
		proto: embIndicator.natProto(),
	}
	upValue, ok := p.valueMap[q]
	if !ok {
		// if ICMPv4 error is not in NAT, drop it
		if embIndicator.transportLayerType == layers.LayerTypeICMPv4 && !embIndicator.icmpv4Indicator.isQuery() {
			return errors.New("missing nat")
		}
		upValue, err = p.dist(embIndicator.transportLayerType)
		if err != nil {
			return fmt.Errorf("distribute: %w", err)
		}
		p.valueMap[q] = upValue
	}

	// Create new transport layer
	newTransportLayerType = embIndicator.transportLayerType
	switch newTransportLayerType {
	case layers.LayerTypeTCP:
		tcpLayer := embIndicator.tcpLayer()
		temp := *tcpLayer
		newTransportLayer = &temp

		newTCPLayer := newTransportLayer.(*layers.TCP)

		newTCPLayer.SrcPort = layers.TCPPort(upValue)
	case layers.LayerTypeUDP:
		udpLayer := embIndicator.udpLayer()
		temp := *udpLayer
		newTransportLayer = &temp

		newUDPLayer := newTransportLayer.(*layers.UDP)

		newUDPLayer.SrcPort = layers.UDPPort(upValue)
	case layers.LayerTypeICMPv4:
		if embIndicator.icmpv4Indicator.isQuery() {
			temp := *embIndicator.icmpv4Indicator.layer
			newTransportLayer = &temp

			newICMPv4Layer := newTransportLayer.(*layers.ICMPv4)

			newICMPv4Layer.Id = upValue
		} else {
			newTransportLayer = embIndicator.icmpv4Indicator.newPureICMPv4Layer()

			newICMPv4Layer := newTransportLayer.(*layers.ICMPv4)

			temp := *embIndicator.icmpv4Indicator.embIPv4Layer
			newEmbIPv4Layer := &temp

			newEmbIPv4Layer.DstIP = p.UpDev.IPv4Addr().IP

			var newEmbTransportLayer gopacket.Layer
			switch embIndicator.icmpv4Indicator.embTransportLayerType {
			case layers.LayerTypeTCP:
				temp := *embIndicator.icmpv4Indicator.embTransportLayer.(*layers.TCP)
				newEmbTransportLayer = &temp

				newEmbTCPLayer := newEmbTransportLayer.(*layers.TCP)

				newEmbTCPLayer.DstPort = layers.TCPPort(upValue)

				err := newEmbTCPLayer.SetNetworkLayerForChecksum(newEmbIPv4Layer)
				if err != nil {
					return fmt.Errorf("create transport layer: %w", fmt.Errorf("create embedded network layer: %w", fmt.Errorf("set network layer for checksum: %w", err)))
				}
			case layers.LayerTypeUDP:
				temp := *embIndicator.icmpv4Indicator.embTransportLayer.(*layers.UDP)
				newEmbTransportLayer = &temp

				newEmbUDPLayer := newEmbTransportLayer.(*layers.UDP)

				newEmbUDPLayer.DstPort = layers.UDPPort(upValue)

				err := newEmbUDPLayer.SetNetworkLayerForChecksum(newEmbIPv4Layer)
				if err != nil {
					return fmt.Errorf("create transport layer: %w", fmt.Errorf("create embedded network layer: %w", fmt.Errorf("set network layer for checksum: %w", err)))
				}
			case layers.LayerTypeICMPv4:
				temp := *embIndicator.icmpv4Indicator.embTransportLayer.(*layers.ICMPv4)
				newEmbTransportLayer = &temp

				if embIndicator.icmpv4Indicator.isEmbQuery() {
					newEmbICMPv4Layer := newEmbTransportLayer.(*layers.ICMPv4)

					newEmbICMPv4Layer.Id = upValue
				}
			default:
				return fmt.Errorf("create transport layer: %w", fmt.Errorf("create embedded network layer: %w", fmt.Errorf("transport layer type %s not support", embIndicator.icmpv4Indicator.embTransportLayerType)))
			}

			payload, err := serialize(newEmbIPv4Layer, newEmbTransportLayer.(gopacket.SerializableLayer))
			if err != nil {
				return fmt.Errorf("create transport layer: %w", fmt.Errorf("create embedded network layer: %w", fmt.Errorf("serialize: %w", err)))
			}

			newICMPv4Layer.Payload = payload
		}
	default:
		return fmt.Errorf("create transport layer: %w", fmt.Errorf("transport layer type %s not support", newTransportLayerType))
	}

	// Create new network layer
	newNetworkLayerType = embIndicator.networkLayerType
	switch newNetworkLayerType {
	case layers.LayerTypeIPv4:
		ipv4Layer := embIndicator.networkLayer.(*layers.IPv4)
		temp := *ipv4Layer
		newNetworkLayer = &temp

		newIPv4Layer := newNetworkLayer.(*layers.IPv4)

		newIPv4Layer.SrcIP = p.UpDev.IPv4Addr().IP
		upIP = newIPv4Layer.SrcIP
	case layers.LayerTypeIPv6:
		ipv6Layer := embIndicator.networkLayer.(*layers.IPv6)
		temp := *ipv6Layer
		newNetworkLayer = &temp

		newIPv6Layer := newNetworkLayer.(*layers.IPv6)

		newIPv6Layer.SrcIP = p.UpDev.IPv6Addr().IP
		upIP = newIPv6Layer.SrcIP
	default:
		return fmt.Errorf("create network layer: %w", fmt.Errorf("network layer type %s not support", newNetworkLayerType))
	}

	// Set network layer for transport layer
	switch newTransportLayerType {
	case layers.LayerTypeTCP:
		tcpLayer := newTransportLayer.(*layers.TCP)

		err = tcpLayer.SetNetworkLayerForChecksum(newNetworkLayer)
	case layers.LayerTypeUDP:
		udpLayer := newTransportLayer.(*layers.UDP)

		err = udpLayer.SetNetworkLayerForChecksum(newNetworkLayer)
	case layers.LayerTypeICMPv4:
		break
	default:
		return fmt.Errorf("create network layer: %w", fmt.Errorf("transport layer type %s not support", newTransportLayerType))
	}
	if err != nil {
		return fmt.Errorf("set network layer for checksum: %w", err)
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
	data, err := serialize(newLinkLayer.(gopacket.SerializableLayer),
		newNetworkLayer.(gopacket.SerializableLayer),
		newTransportLayer.(gopacket.SerializableLayer),
		gopacket.Payload(embIndicator.payload()))
	if err != nil {
		return fmt.Errorf("serialize: %w", err)
	}

	// Write packet data
	err = p.upHandle.WritePacketData(data)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}

	// Record the source and the source device of the packet
	var addNAT bool
	switch newTransportLayerType {
	case layers.LayerTypeTCP, layers.LayerTypeUDP:
		guide = natGuide{
			src: addr.IPPort{
				MemberIP: upIP,
				Port:     upValue,
			}.String(),
			proto: newTransportLayerType,
		}
		addNAT = true
	case layers.LayerTypeICMPv4:
		if embIndicator.icmpv4Indicator.isQuery() {
			guide = natGuide{
				src: addr.IPId{
					MemberIP: upIP,
					Id:       upValue,
				}.String(),
				proto: newTransportLayerType,
			}
			addNAT = true
		}
	default:
		return fmt.Errorf("record nat: %w", fmt.Errorf("transport layer type %s not support", newTransportLayerType))
	}
	if addNAT {
		ni = &natIndicator{
			src:    indicator.src().(*addr.IPPort),
			embSrc: embIndicator.natSrc(),
			dev:    dev,
			handle: handle,
		}
		p.natLock.Lock()
		p.nat[guide] = ni
		p.natLock.Unlock()
	}

	// Keep alive
	proto := embIndicator.natProto()
	switch proto {
	case layers.LayerTypeTCP:
		p.tcpPortPool[convertFromPort(upValue)] = time.Now()
	case layers.LayerTypeUDP:
		p.udpPortPool[convertFromPort(upValue)] = time.Now()
	case layers.LayerTypeICMPv4:
		p.icmpv4IdPool[upValue] = time.Now()
	default:
		return fmt.Errorf("keep alive: %w", fmt.Errorf("protocol type %s not support", proto))
	}

	log.Verbosef("Redirect an inbound %s packet: %s -> %s (%d Bytes)\n",
		embIndicator.transportLayerType, embIndicator.src(), embIndicator.dst(), packet.Metadata().Length)

	return nil
}

// handleUpstream handles TCP and UDP packets from destinations
func (p *Server) handleUpstream(packet gopacket.Packet) error {
	var (
		indicator             *packetIndicator
		newTransportLayer     *layers.TCP
		upDevIP               net.IP
		embTransportLayerType gopacket.LayerType
		embTransportLayer     gopacket.Layer
		embNetworkLayerType   gopacket.LayerType
		embNetworkLayer       gopacket.NetworkLayer
		newNetworkLayerType   gopacket.LayerType
		newNetworkLayer       gopacket.NetworkLayer
		newLinkLayerType      gopacket.LayerType
		newLinkLayer          gopacket.Layer
	)

	// Parse packet
	indicator, err := parsePacket(packet)
	if err != nil {
		return fmt.Errorf("parse packet: %w", err)
	}

	// NAT
	guide := natGuide{
		src:   indicator.natDst().String(),
		proto: indicator.transportLayerType,
	}
	p.natLock.RLock()
	ni, ok := p.nat[guide]
	p.natLock.RUnlock()
	if !ok {
		return nil
	}

	// Keep alive
	proto := indicator.natProto()
	switch proto {
	case layers.LayerTypeTCP:
		p.tcpPortPool[convertFromPort(indicator.dstPort())] = time.Now()
	case layers.LayerTypeUDP:
		p.udpPortPool[convertFromPort(indicator.dstPort())] = time.Now()
	case layers.LayerTypeICMPv4:
		p.icmpv4IdPool[indicator.icmpv4Indicator.id()] = time.Now()
	default:
		return fmt.Errorf("look up nat: %w", fmt.Errorf("protocol type %s not support", proto))
	}

	// Create embedded transport layer
	embTransportLayerType = indicator.transportLayerType
	switch embTransportLayerType {
	case layers.LayerTypeTCP:
		embTCPLayer := indicator.transportLayer.(*layers.TCP)
		temp := *embTCPLayer
		embTransportLayer = &temp

		newEmbTCPLayer := embTransportLayer.(*layers.TCP)

		newEmbTCPLayer.DstPort = layers.TCPPort(ni.embSrc.(*addr.IPPort).Port)
	case layers.LayerTypeUDP:
		embUDPLayer := indicator.transportLayer.(*layers.UDP)
		temp := *embUDPLayer
		embTransportLayer = &temp

		newEmbUDPLayer := embTransportLayer.(*layers.UDP)

		newEmbUDPLayer.DstPort = layers.UDPPort(ni.embSrc.(*addr.IPPort).Port)
	case layers.LayerTypeICMPv4:
		if indicator.icmpv4Indicator.isQuery() {
			embICMPv4Layer := indicator.icmpv4Indicator.layer
			temp := *embICMPv4Layer
			embTransportLayer = &temp

			newEmbICMPv4Layer := embTransportLayer.(*layers.ICMPv4)

			newEmbICMPv4Layer.Id = ni.embSrc.(*addr.IPId).Id
		} else {
			embTransportLayer = indicator.icmpv4Indicator.newPureICMPv4Layer()

			newEmbICMPv4Layer := embTransportLayer.(*layers.ICMPv4)

			temp := *indicator.icmpv4Indicator.embIPv4Layer
			newEmbEmbIPv4Layer := &temp

			newEmbEmbIPv4Layer.SrcIP = ni.embSrc.IP()

			var newEmbEmbTransportLayer gopacket.Layer
			switch indicator.icmpv4Indicator.embTransportLayerType {
			case layers.LayerTypeTCP:
				temp := *indicator.icmpv4Indicator.embTransportLayer.(*layers.TCP)
				newEmbEmbTransportLayer = &temp

				newEmbEmbTCPLayer := newEmbEmbTransportLayer.(*layers.TCP)

				newEmbEmbTCPLayer.SrcPort = layers.TCPPort(ni.embSrc.(*addr.IPPort).Port)

				err := newEmbEmbTCPLayer.SetNetworkLayerForChecksum(newEmbEmbIPv4Layer)
				if err != nil {
					return fmt.Errorf("create embedded transport layer: %w", fmt.Errorf("create embedded network layer: %w", fmt.Errorf("set network layer for checksum: %w", err)))
				}
			case layers.LayerTypeUDP:
				temp := *indicator.icmpv4Indicator.embTransportLayer.(*layers.UDP)
				newEmbEmbTransportLayer = &temp

				newEmbEmbUDPLayer := newEmbEmbTransportLayer.(*layers.UDP)

				newEmbEmbUDPLayer.SrcPort = layers.UDPPort(ni.embSrc.(*addr.IPPort).Port)

				err := newEmbEmbUDPLayer.SetNetworkLayerForChecksum(newEmbEmbIPv4Layer)
				if err != nil {
					return fmt.Errorf("create embedded transport layer: %w", fmt.Errorf("create embedded network layer: %w", fmt.Errorf("set network layer for checksum: %w", err)))
				}
			case layers.LayerTypeICMPv4:
				temp := *indicator.icmpv4Indicator.embTransportLayer.(*layers.ICMPv4)
				newEmbEmbTransportLayer = &temp

				if indicator.icmpv4Indicator.isEmbQuery() {
					newEmbEmbICMPv4Layer := newEmbEmbTransportLayer.(*layers.ICMPv4)

					newEmbEmbICMPv4Layer.Id = ni.embSrc.(*addr.IPId).Id
				}
			default:
				return fmt.Errorf("create embedded transport layer: %w", fmt.Errorf("create embedded network layer: %w", fmt.Errorf("transport layer type %s not support", indicator.icmpv4Indicator.embTransportLayerType)))
			}

			payload, err := serialize(newEmbEmbIPv4Layer, newEmbEmbTransportLayer.(gopacket.SerializableLayer))
			if err != nil {
				return fmt.Errorf("create embedded transport layer: %w", fmt.Errorf("create embedded network layer: %w", fmt.Errorf("serialize: %w", err)))
			}

			newEmbICMPv4Layer.Payload = payload
		}
	default:
		return fmt.Errorf("create embedded transport layer: %w", fmt.Errorf("type %s not support", embTransportLayerType))
	}

	// Create embedded network layer
	embNetworkLayerType = indicator.networkLayerType
	switch embNetworkLayerType {
	case layers.LayerTypeIPv4:
		embIPv4Layer := indicator.networkLayer.(*layers.IPv4)
		temp := *embIPv4Layer
		embNetworkLayer = &temp

		newEmbIPv4Layer := embNetworkLayer.(*layers.IPv4)

		newEmbIPv4Layer.DstIP = ni.embSrc.IP()
	case layers.LayerTypeIPv6:
		embIPv6Layer := indicator.networkLayer.(*layers.IPv6)
		temp := *embIPv6Layer
		embNetworkLayer = &temp

		newEmbIPv6Layer := embNetworkLayer.(*layers.IPv6)

		newEmbIPv6Layer.DstIP = ni.embSrc.IP()
	default:
		return fmt.Errorf("create embedded network layer: %w", fmt.Errorf("network layer type %s not support", embNetworkLayerType))
	}

	// Set network layer for transport layer
	switch embTransportLayerType {
	case layers.LayerTypeTCP:
		embTCPLayer := embTransportLayer.(*layers.TCP)

		err = embTCPLayer.SetNetworkLayerForChecksum(embNetworkLayer)
	case layers.LayerTypeUDP:
		embUDPLayer := embTransportLayer.(*layers.UDP)

		err = embUDPLayer.SetNetworkLayerForChecksum(embNetworkLayer)
	case layers.LayerTypeICMPv4:
		break
	default:
		return fmt.Errorf("create embedded network layer: %w", fmt.Errorf("transport layer type %s not support", embTransportLayerType))
	}
	if err != nil {
		return fmt.Errorf("create embedded network layer: %w", fmt.Errorf("set network layer for checksum: %w", err))
	}

	// Construct contents of new application layer
	contents, err := serialize(embNetworkLayer.(gopacket.SerializableLayer),
		embTransportLayer.(gopacket.SerializableLayer),
		gopacket.Payload(indicator.payload()))
	if err != nil {
		return fmt.Errorf("create application layer: %w", fmt.Errorf("serialize: %w", err))
	}

	// Create new transport layer
	src := ni.src.String()
	p.seqsLock.RLock()
	p.acksLock.RLock()
	newTransportLayer = createTransportLayerTCP(p.Port, ni.src.Port, p.seqs[src], p.acks[src])
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
		return errors.New("ip version transition not support")
	}

	// Create new network layer
	switch newNetworkLayerType {
	case layers.LayerTypeIPv4:
		newNetworkLayer, err = createNetworkLayerIPv4(upDevIP, ni.src.MemberIP, p.id, indicator.ipv4Layer().TTL-1, newTransportLayer)
	case layers.LayerTypeIPv6:
		newNetworkLayer, err = createNetworkLayerIPv6(upDevIP, ni.src.MemberIP, indicator.ipv6Layer().HopLimit-1, newTransportLayer)
	default:
		return fmt.Errorf("create network layer: %w", fmt.Errorf("network layer type %s not support", newNetworkLayerType))
	}
	if err != nil {
		return fmt.Errorf("create network layer: %w", err)
	}

	// Decide Loopback or Ethernet
	if ni.dev.IsLoop {
		newLinkLayerType = layers.LayerTypeLoopback
	} else {
		newLinkLayerType = layers.LayerTypeEthernet
	}

	// Create new link layer
	switch newLinkLayerType {
	case layers.LayerTypeLoopback:
		newLinkLayer = createLinkLayerLoopback()
	case layers.LayerTypeEthernet:
		newLinkLayer, err = createLinkLayerEthernet(ni.dev.HardwareAddr, p.GatewayDev.HardwareAddr, newNetworkLayer)
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
	err = ni.handle.WritePacketData(data)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}

	// TCP Seq
	p.seqsLock.Lock()
	p.seqs[src] = p.seqs[src] + uint32(len(contents))
	p.seqsLock.Unlock()

	// IPv4 Id
	if newNetworkLayerType == layers.LayerTypeIPv4 {
		p.id++
	}

	log.Verbosef("Redirect an outbound %s packet: %s <- %s (%d Bytes)\n",
		indicator.transportLayerType, ni.embSrc.String(), indicator.src(), len(data))

	return nil
}

func (p *Server) dist(t gopacket.LayerType) (uint16, error) {
	now := time.Now()

	switch t {
	case layers.LayerTypeTCP:
		for i := 0; i < 16384; i++ {
			s := p.nextTCPPort % 16384

			// Point to next port
			p.nextTCPPort++

			// Check if the port is alive
			last := p.tcpPortPool[s]
			if now.Sub(last).Seconds() > keepAlive {
				return 49152 + s, nil
			}
		}
	case layers.LayerTypeUDP:
		for i := 0; i < 16384; i++ {
			s := p.nextUDPPort % 16384

			// Point to next port
			p.nextUDPPort++

			// Check if the port is alive
			last := p.udpPortPool[s]
			if now.Sub(last).Seconds() > keepAlive {
				return 49152 + s, nil
			}
		}
	case layers.LayerTypeICMPv4:
		for i := 0; i < 65536; i++ {
			s := p.nextICMPv4Id

			// Point to next Id
			p.nextICMPv4Id++

			// Check if the Id is alive
			last := p.icmpv4IdPool[s]
			if now.Sub(last).Seconds() > keepAlive {
				return s, nil
			}
		}
	default:
		return 0, fmt.Errorf("transport layer type %s not support", t)
	}
	return 0, fmt.Errorf("%s pool empty", t)
}

func convertFromPort(port uint16) uint16 {
	return port - 49152
}
