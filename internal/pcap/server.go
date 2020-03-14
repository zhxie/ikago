package pcap

import (
	"errors"
	"fmt"
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
	ListenPort     uint16
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

// Open implements a method opens the pcap
func (p *Server) Open() error {
	p.cListenPackets = make(chan devPacket, 1000)
	p.seqs = make(map[string]uint32)
	p.acks = make(map[string]uint32)
	p.id = 0
	p.tcpPortPool = make([]time.Time, 16384)
	p.udpPortPool = make([]time.Time, 16384)
	p.icmpv4IdPool = make([]time.Time, 65536)
	p.valueMap = make(map[quintuple]uint16)
	p.nat = make(map[natGuide]*natIndicator)

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
			log.Infof("Listen on %s: %s\n", dev.Alias, strIPs)
		} else {
			log.Infof("Listen on %s [%s]: %s\n", dev.Alias, dev.HardwareAddr, strIPs)
		}
	} else {
		log.Infoln("Listen on:")
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
				log.Infof("  %s: %s\n", dev.Alias, strIPs)
			} else {
				log.Infof("  %s [%s]: %s\n", dev.Alias, dev.HardwareAddr, strIPs)
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
		log.Infof("Route upstream from %s [%s]: %s to gateway [%s]: %s\n", p.UpDev.Alias, p.UpDev.HardwareAddr, strUpIPs, p.GatewayDev.HardwareAddr, p.GatewayDev.IPAddr().IP)
	} else {
		log.Infof("Route upstream to loopback %s\n", p.UpDev.Alias)
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
	err = p.upHandle.SetBPFFilter(fmt.Sprintf("((tcp || udp) && not dst port %d) || icmp", p.ListenPort))
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
				p.cListenPackets <- devPacket{packet: packet, dev: dev, handle: copyHandle}
			}
		}()
	}
	go func() {
		for devPacket := range p.cListenPackets {
			p.handleListen(devPacket.packet, devPacket.dev, devPacket.handle)
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
		return fmt.Errorf("handshake: %w", fmt.Errorf("transport layer type %s not support", indicator.transportLayerType))
	}

	// Initial TCP Seq
	srcIPPort := IPPort{IP: indicator.srcIP(), Port: indicator.srcPort()}
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
	newTransportLayer = createTCPLayerSYNACK(p.ListenPort, indicator.srcPort(), p.seqs[srcIPPort.String()], p.acks[srcIPPort.String()])
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
		newNetworkLayer, err = createNetworkLayerIPv6(indicator.dstIP(), indicator.srcIP(), newTransportLayer)
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
	data, err := serialize(newLinkLayer.(gopacket.SerializableLayer), newNetworkLayer.(gopacket.SerializableLayer), newTransportLayer)
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
	p.seqs[srcIPPort.String()]++
	p.seqsLock.Unlock()

	// IPv4 Id
	if newNetworkLayerType == layers.LayerTypeIPv4 {
		p.id++
	}

	return nil
}

// handleListen handles TCP packets from clients
func (p *Server) handleListen(packet gopacket.Packet, dev *Device, handle *pcap.Handle) {
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
		log.Errorln(fmt.Errorf("handle listen: %w", err))
		return
	}

	if indicator.transportLayerType != layers.LayerTypeTCP {
		log.Errorln(fmt.Errorf("handle listen: %w", fmt.Errorf("parse: %w", fmt.Errorf("transport layer type %s not support", indicator.transportLayerType))))
		return
	}

	// Handshaking with client (SYN+ACK)
	if indicator.tcpLayer().SYN {
		err := p.handshake(indicator)
		if err != nil {
			log.Errorln(fmt.Errorf("handle listen: %w", err))
			return
		}
		log.Infof("Connect from client %s\n", indicator.natSrc())
		return
	}

	// Empty payload (An ACK handshaking will also be recognized as empty payload)
	if len(indicator.payload()) <= 0 {
		log.Verboseln(fmt.Errorf("handle listen: %w", errors.New("empty payload")))
		return
	}

	// Ack
	srcIPPort := IPPort{IP: indicator.srcIP(), Port: indicator.srcPort()}
	p.acksLock.Lock()
	p.acks[srcIPPort.String()] = p.acks[srcIPPort.String()] + uint32(len(indicator.payload()))
	p.acksLock.Unlock()

	// Decrypt
	contents, err := p.Crypto.Decrypt(indicator.payload())
	if err != nil {
		log.Errorln(fmt.Errorf("handle listen: %w", err))
		return
	}

	// Parse embedded packet
	embIndicator, err = parseEmbPacket(contents)
	if err != nil {
		log.Errorln(fmt.Errorf("handle listen: %w", err))
		return
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
			log.Errorln(fmt.Errorf("handle listen: %w", fmt.Errorf("nat: %w", fmt.Errorf("missing nat"))))
			return
		}
		upValue, err = p.dist(embIndicator.transportLayerType)
		if err != nil {
			log.Errorln(fmt.Errorf("handle listen: %w", fmt.Errorf("nat: %w", err)))
			return
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
					log.Errorln(fmt.Errorf("handle listen: %w", fmt.Errorf("create transport layer: %w", fmt.Errorf("create emb network layer: %w", err))))
				}
			case layers.LayerTypeUDP:
				temp := *embIndicator.icmpv4Indicator.embTransportLayer.(*layers.UDP)
				newEmbTransportLayer = &temp

				newEmbUDPLayer := newEmbTransportLayer.(*layers.UDP)

				newEmbUDPLayer.DstPort = layers.UDPPort(upValue)

				err := newEmbUDPLayer.SetNetworkLayerForChecksum(newEmbIPv4Layer)
				if err != nil {
					log.Errorln(fmt.Errorf("handle listen: %w", fmt.Errorf("create transport layer: %w", fmt.Errorf("create emb network layer: %w", err))))
				}
			case layers.LayerTypeICMPv4:
				temp := *embIndicator.icmpv4Indicator.embTransportLayer.(*layers.ICMPv4)
				newEmbTransportLayer = &temp

				if embIndicator.icmpv4Indicator.isEmbQuery() {
					newEmbICMPv4Layer := newEmbTransportLayer.(*layers.ICMPv4)

					newEmbICMPv4Layer.Id = upValue
				}
			default:
				log.Errorln(fmt.Errorf("handle listen: %w", fmt.Errorf("create transport layer: %w", fmt.Errorf("create emb transport layer: %w", fmt.Errorf("type %s not support", embIndicator.icmpv4Indicator.embTransportLayerType)))))
			}

			payload, err := serialize(newEmbIPv4Layer, newEmbTransportLayer.(gopacket.SerializableLayer))
			if err != nil {
				log.Errorln(fmt.Errorf("handle listen: %w", fmt.Errorf("create transport layer: %w", err)))
			}

			newICMPv4Layer.Payload = payload
		}
	default:
		log.Errorln(fmt.Errorf("handle listen: %w", fmt.Errorf("create transport layer: %w", fmt.Errorf("type %s not support", newTransportLayerType))))
		return
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
		log.Errorln(fmt.Errorf("handle listen: %w", fmt.Errorf("create network layer: %w", fmt.Errorf("type %s not support", newNetworkLayerType))))
		return
	}

	// Set network layer for transport layer
	switch newTransportLayerType {
	case layers.LayerTypeTCP:
		tcpLayer := newTransportLayer.(*layers.TCP)

		err := tcpLayer.SetNetworkLayerForChecksum(newNetworkLayer)
		if err != nil {
			log.Errorln(fmt.Errorf("handle listen: %w", fmt.Errorf("create network layer: %w", err)))
			return
		}
	case layers.LayerTypeUDP:
		udpLayer := newTransportLayer.(*layers.UDP)

		err := udpLayer.SetNetworkLayerForChecksum(newNetworkLayer)
		if err != nil {
			log.Errorln(fmt.Errorf("handle listen: %w", fmt.Errorf("create network layer: %w", err)))
			return
		}
	case layers.LayerTypeICMPv4:
		break
	default:
		log.Errorln(fmt.Errorf("handle listen: %w", fmt.Errorf("create network layer: %w", fmt.Errorf("transport layer type %s not support", newTransportLayerType))))
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
		var err error

		newLinkLayer, err = createLinkLayerEthernet(p.UpDev.HardwareAddr, p.GatewayDev.HardwareAddr, newNetworkLayer)
		if err != nil {
			log.Errorln(fmt.Errorf("handle listen: %w", err))
			return
		}
	default:
		log.Errorln(fmt.Errorf("handle listen: %w", fmt.Errorf("create link layer: %w", fmt.Errorf("type %s not support", newLinkLayerType))))
		return
	}

	// Serialize layers
	data, err := serialize(newLinkLayer.(gopacket.SerializableLayer),
		newNetworkLayer.(gopacket.SerializableLayer),
		newTransportLayer.(gopacket.SerializableLayer),
		gopacket.Payload(embIndicator.payload()))
	if err != nil {
		log.Errorln(fmt.Errorf("handle listen: %w", err))
		return
	}

	// Write packet data
	err = p.upHandle.WritePacketData(data)
	if err != nil {
		log.Errorln(fmt.Errorf("handle listen: %w", fmt.Errorf("write: %w", err)))
		return
	}

	// Record the source and the source device of the packet
	var addNAT bool
	switch newTransportLayerType {
	case layers.LayerTypeTCP, layers.LayerTypeUDP:
		guide = natGuide{
			src: IPPort{
				IP:   upIP,
				Port: upValue,
			}.String(),
			proto: newTransportLayerType,
		}
		addNAT = true
	case layers.LayerTypeICMPv4:
		if embIndicator.icmpv4Indicator.isQuery() {
			guide = natGuide{
				src: IPId{
					IP: upIP,
					Id: upValue,
				}.String(),
				proto: newTransportLayerType,
			}
			addNAT = true
		}
	default:
		log.Errorln(fmt.Errorf("handle listen: %w", fmt.Errorf("nat: %w", fmt.Errorf("type %s not support", newTransportLayerType))))
		return
	}
	if addNAT {
		ni = &natIndicator{
			src:    indicator.src().(*IPPort),
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
		log.Errorln(fmt.Errorf("handle listen: %w", fmt.Errorf("nat: %w", fmt.Errorf("type %s not support", proto))))
		return
	}

	log.Verbosef("Redirect an inbound %s packet: %s -> %s (%d Bytes)\n",
		embIndicator.transportLayerType, embIndicator.src(), embIndicator.dst(), packet.Metadata().Length)
}

// handleUpstream handles TCP and UDP packets from destinations
func (p *Server) handleUpstream(packet gopacket.Packet) {
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
		log.Errorln(fmt.Errorf("handle upstream: %w", err))
		return
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
		return
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
		log.Errorln(fmt.Errorf("handle upstream: %w", fmt.Errorf("nat: %w", fmt.Errorf("type %s not support", proto))))
		return
	}

	// Create embedded transport layer
	embTransportLayerType = indicator.transportLayerType
	switch embTransportLayerType {
	case layers.LayerTypeTCP:
		embTCPLayer := indicator.transportLayer.(*layers.TCP)
		temp := *embTCPLayer
		embTransportLayer = &temp

		newEmbTCPLayer := embTransportLayer.(*layers.TCP)

		newEmbTCPLayer.DstPort = layers.TCPPort(ni.embSrc.(*IPPort).Port)
	case layers.LayerTypeUDP:
		embUDPLayer := indicator.transportLayer.(*layers.UDP)
		temp := *embUDPLayer
		embTransportLayer = &temp

		newEmbUDPLayer := embTransportLayer.(*layers.UDP)

		newEmbUDPLayer.DstPort = layers.UDPPort(ni.embSrc.(*IPPort).Port)
	case layers.LayerTypeICMPv4:
		if indicator.icmpv4Indicator.isQuery() {
			embICMPv4Layer := indicator.icmpv4Indicator.layer
			temp := *embICMPv4Layer
			embTransportLayer = &temp

			newEmbICMPv4Layer := embTransportLayer.(*layers.ICMPv4)

			newEmbICMPv4Layer.Id = ni.embSrc.(*IPId).Id
		} else {
			embTransportLayer = indicator.icmpv4Indicator.newPureICMPv4Layer()

			newEmbICMPv4Layer := embTransportLayer.(*layers.ICMPv4)

			temp := *indicator.icmpv4Indicator.embIPv4Layer
			newEmbEmbIPv4Layer := &temp

			newEmbEmbIPv4Layer.SrcIP = ni.embSrc.ip()

			var newEmbEmbTransportLayer gopacket.Layer
			switch indicator.icmpv4Indicator.embTransportLayerType {
			case layers.LayerTypeTCP:
				temp := *indicator.icmpv4Indicator.embTransportLayer.(*layers.TCP)
				newEmbEmbTransportLayer = &temp

				newEmbEmbTCPLayer := newEmbEmbTransportLayer.(*layers.TCP)

				newEmbEmbTCPLayer.SrcPort = layers.TCPPort(ni.embSrc.(*IPPort).Port)

				err := newEmbEmbTCPLayer.SetNetworkLayerForChecksum(newEmbEmbIPv4Layer)
				if err != nil {
					log.Errorln(fmt.Errorf("handle upstream: %w", fmt.Errorf("create emb transport layer: %w", fmt.Errorf("create emb network layer: %w", err))))
				}
			case layers.LayerTypeUDP:
				temp := *indicator.icmpv4Indicator.embTransportLayer.(*layers.UDP)
				newEmbEmbTransportLayer = &temp

				newEmbEmbUDPLayer := newEmbEmbTransportLayer.(*layers.UDP)

				newEmbEmbUDPLayer.SrcPort = layers.UDPPort(ni.embSrc.(*IPPort).Port)

				err := newEmbEmbUDPLayer.SetNetworkLayerForChecksum(newEmbEmbIPv4Layer)
				if err != nil {
					log.Errorln(fmt.Errorf("handle upstream: %w", fmt.Errorf("create emb transport layer: %w", fmt.Errorf("create emb network layer: %w", err))))
				}
			case layers.LayerTypeICMPv4:
				temp := *indicator.icmpv4Indicator.embTransportLayer.(*layers.ICMPv4)
				newEmbEmbTransportLayer = &temp

				if indicator.icmpv4Indicator.isEmbQuery() {
					newEmbEmbICMPv4Layer := newEmbEmbTransportLayer.(*layers.ICMPv4)

					newEmbEmbICMPv4Layer.Id = ni.embSrc.(*IPId).Id
				}
			default:
				log.Errorln(fmt.Errorf("handle upstream: %w", fmt.Errorf("create emb transport layer: %w", fmt.Errorf("create emb transport layer: %w", fmt.Errorf("type %s not support", indicator.icmpv4Indicator.embTransportLayerType)))))
			}

			payload, err := serialize(newEmbEmbIPv4Layer, newEmbEmbTransportLayer.(gopacket.SerializableLayer))
			if err != nil {
				log.Errorln(fmt.Errorf("handle upstream: %w", fmt.Errorf("create emb transport layer: %w", err)))
			}

			newEmbICMPv4Layer.Payload = payload
		}
	default:
		log.Errorln(fmt.Errorf("handle upstream: %w", fmt.Errorf("create emb transport layer: %w", fmt.Errorf("type %s not support", embTransportLayerType))))
		return
	}

	// Create embedded network layer
	embNetworkLayerType = indicator.networkLayerType
	switch embNetworkLayerType {
	case layers.LayerTypeIPv4:
		embIPv4Layer := indicator.networkLayer.(*layers.IPv4)
		temp := *embIPv4Layer
		embNetworkLayer = &temp

		newEmbIPv4Layer := embNetworkLayer.(*layers.IPv4)

		newEmbIPv4Layer.DstIP = ni.embSrc.ip()
	case layers.LayerTypeIPv6:
		embIPv6Layer := indicator.networkLayer.(*layers.IPv6)
		temp := *embIPv6Layer
		embNetworkLayer = &temp

		newEmbIPv6Layer := embNetworkLayer.(*layers.IPv6)

		newEmbIPv6Layer.DstIP = ni.embSrc.ip()
	default:
		log.Errorln(fmt.Errorf("handle upstream: %w", fmt.Errorf("create emb network layer: %w", fmt.Errorf("type %s not support", embNetworkLayerType))))
		return
	}

	// Set network layer for transport layer
	switch embTransportLayerType {
	case layers.LayerTypeTCP:
		embTCPLayer := embTransportLayer.(*layers.TCP)

		err := embTCPLayer.SetNetworkLayerForChecksum(embNetworkLayer)
		if err != nil {
			log.Errorln(fmt.Errorf("handle upstream: %w", fmt.Errorf("create emb network layer: %w", err)))
			return
		}
	case layers.LayerTypeUDP:
		embUDPLayer := embTransportLayer.(*layers.UDP)

		err := embUDPLayer.SetNetworkLayerForChecksum(embNetworkLayer)
		if err != nil {
			log.Errorln(fmt.Errorf("handle upstream: %w", fmt.Errorf("create emb network layer: %w", err)))
			return
		}
	case layers.LayerTypeICMPv4:
		break
	default:
		log.Errorln(fmt.Errorf("handle upstream: %w", fmt.Errorf("create emb network layer: %w", fmt.Errorf("transport layer type %s not support", embTransportLayerType))))
		return
	}

	// Construct contents of new application layer
	contents, err := serialize(embNetworkLayer.(gopacket.SerializableLayer),
		embTransportLayer.(gopacket.SerializableLayer),
		gopacket.Payload(indicator.payload()))
	if err != nil {
		log.Errorln(fmt.Errorf("handle upstream: %w", fmt.Errorf("create application layer: %w", err)))
		return
	}

	// Create new transport layer
	addr := ni.src.String()
	p.seqsLock.RLock()
	p.acksLock.RLock()
	newTransportLayer = createTransportLayerTCP(p.ListenPort, ni.src.Port, p.seqs[addr], p.acks[addr])
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
		log.Errorln(fmt.Errorf("handle upstream: %w", errors.New("ip version transition not support")))
		return
	}

	// Create new network layer
	switch newNetworkLayerType {
	case layers.LayerTypeIPv4:
		newNetworkLayer, err = createNetworkLayerIPv4(upDevIP, ni.src.IP, p.id, indicator.ipv4Layer().TTL-1, newTransportLayer)
	case layers.LayerTypeIPv6:
		newNetworkLayer, err = createNetworkLayerIPv6(upDevIP, ni.src.IP, newTransportLayer)
	default:
		log.Errorln(fmt.Errorf("handle upstream: %w", fmt.Errorf("create network layer: %w", fmt.Errorf("type %s not support", newNetworkLayerType))))
		return
	}
	if err != nil {
		log.Errorln(fmt.Errorf("handle upstream: %w", err))
		return
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
		log.Errorln(fmt.Errorf("handle upstream: %w", fmt.Errorf("create link layer: %w", fmt.Errorf("type %s not support", newLinkLayerType))))
		return
	}
	if err != nil {
		log.Errorln(fmt.Errorf("handle upstream: %w", err))
		return
	}

	// Encrypt
	contents, err = p.Crypto.Encrypt(contents)
	if err != nil {
		log.Errorln(fmt.Errorf("handle upstream: %w", err))
		return
	}

	// Serialize layers
	data, err := serialize(newLinkLayer.(gopacket.SerializableLayer),
		newNetworkLayer.(gopacket.SerializableLayer),
		newTransportLayer,
		gopacket.Payload(contents))
	if err != nil {
		log.Errorln(fmt.Errorf("handle upstream: %w", err))
		return
	}

	// Write packet data
	err = ni.handle.WritePacketData(data)
	if err != nil {
		log.Errorln(fmt.Errorf("handle upstream: %w", fmt.Errorf("write: %w", err)))
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

	log.Verbosef("Redirect an outbound %s packet: %s <- %s (%d Bytes)\n",
		indicator.transportLayerType, ni.embSrc.String(), indicator.src(), len(data))
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
		return 0, fmt.Errorf("dist port: %w", fmt.Errorf("type %s not support", t))
	}
	return 0, fmt.Errorf("dist port: %w", fmt.Errorf("empty %s port pool", t))
}

func convertFromPort(port uint16) uint16 {
	return port - 49152
}
