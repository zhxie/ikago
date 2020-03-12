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
	portMap        map[quintuple]uint16
	natLock        sync.RWMutex
	nat            map[natGuide]natIndicator
}

const portKeepAlive float64 = 30 // seconds

// Open implements a method opens the pcap
func (p *Server) Open() error {
	p.cListenPackets = make(chan devPacket, 1000)
	p.seqs = make(map[string]uint32)
	p.acks = make(map[string]uint32)
	p.id = 0
	p.tcpPortPool = make([]time.Time, 16384)
	p.udpPortPool = make([]time.Time, 16384)
	p.portMap = make(map[quintuple]uint16)
	p.nat = make(map[natGuide]natIndicator)

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

	transportLayerType := indicator.transportLayerType
	if transportLayerType != layers.LayerTypeTCP {
		return fmt.Errorf("handshake: %w", fmt.Errorf("transport layer type %s not support", transportLayerType))
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
		encappedIndicator     *packetIndicator
		upPort                uint16
		newTransportLayerType gopacket.LayerType
		newTransportLayer     gopacket.TransportLayer
		newNetworkLayerType   gopacket.LayerType
		newNetworkLayer       gopacket.NetworkLayer
		upIP                  net.IP
		newLinkLayerType      gopacket.LayerType
		newLinkLayer          gopacket.Layer
	)

	// Parse packet
	indicator, err := parsePacket(packet)
	if err != nil {
		log.Errorln(fmt.Errorf("handle listen: %w", err))
		return
	}

	transportLayerType := indicator.transportLayerType
	if transportLayerType != layers.LayerTypeTCP {
		log.Errorln(fmt.Errorf("handle listen: %w", fmt.Errorf("parse: %w", fmt.Errorf("transport layer type %s not support", transportLayerType))))
		return
	}

	// Handshaking with client (SYN+ACK)
	if indicator.tcpLayer().SYN {
		err := p.handshake(indicator)
		if err != nil {
			log.Errorln(fmt.Errorf("handle listen: %w", err))
			return
		}
		log.Infof("Connect from client %s\n", indicator.natSource())
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

	// Parse encapped packet
	encappedIndicator, err = parseEncappedPacket(contents)
	if err != nil {
		log.Errorln(fmt.Errorf("handle listen: %w", err))
		return
	}

	// Distribute port by source and client address and protocol
	q := quintuple{
		srcIP:    encappedIndicator.srcIP().String(),
		srcPort:  encappedIndicator.srcPort(),
		dstIP:    indicator.srcIP().String(),
		dstPort:  indicator.srcPort(),
		protocol: encappedIndicator.transportLayerType,
	}
	upPort, ok := p.portMap[q]
	if !ok {
		upPort, err = p.distPort(encappedIndicator.transportLayerType)
		if err != nil {
			log.Errorln(fmt.Errorf("handle listen: %w", err))
			return
		}
		p.portMap[q] = upPort
	}

	// Create new transport layer
	newTransportLayerType = encappedIndicator.transportLayerType
	switch newTransportLayerType {
	case layers.LayerTypeTCP:
		tcpLayer := encappedIndicator.tcpLayer()
		temp := *tcpLayer
		newTransportLayer = &temp

		newTCPLayer := newTransportLayer.(*layers.TCP)

		newTCPLayer.SrcPort = layers.TCPPort(upPort)
	case layers.LayerTypeUDP:
		udpLayer := encappedIndicator.udpLayer()
		temp := *udpLayer
		newTransportLayer = &temp

		newUDPLayer := newTransportLayer.(*layers.UDP)

		newUDPLayer.SrcPort = layers.UDPPort(upPort)
	default:
		log.Errorln(fmt.Errorf("handle listen: %w", fmt.Errorf("create transport layer: %w", fmt.Errorf("type %s not support", newTransportLayerType))))
		return
	}

	// Create new network layer
	newNetworkLayerType = encappedIndicator.networkLayerType
	switch newNetworkLayerType {
	case layers.LayerTypeIPv4:
		ipv4Layer := encappedIndicator.networkLayer.(*layers.IPv4)
		temp := *ipv4Layer
		newNetworkLayer = &temp

		newIPv4Layer := newNetworkLayer.(*layers.IPv4)

		newIPv4Layer.SrcIP = p.UpDev.IPv4Addr().IP
		upIP = newIPv4Layer.SrcIP
	case layers.LayerTypeIPv6:
		ipv6Layer := encappedIndicator.networkLayer.(*layers.IPv6)
		temp := *ipv6Layer
		newNetworkLayer = &temp

		newIPv6Layer := newNetworkLayer.(*layers.IPv6)

		newIPv6Layer.SrcIP = p.UpDev.IPv6Addr().IP
		upIP = newIPv6Layer.SrcIP
	default:
		log.Errorln(fmt.Errorf("handle listen: %w", fmt.Errorf("create network layer: %w", fmt.Errorf("type %s not support", newNetworkLayerType))))
		return
	}
	if err != nil {
		log.Errorln(fmt.Errorf("handle listen: %w", err))
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
		newLinkLayer, err = createLinkLayerEthernet(p.UpDev.HardwareAddr, p.GatewayDev.HardwareAddr, newNetworkLayer)
	default:
		log.Errorln(fmt.Errorf("handle listen: %w", fmt.Errorf("create link layer: %w", fmt.Errorf("type %s not support", newLinkLayerType))))
		return
	}
	if err != nil {
		log.Errorln(fmt.Errorf("handle listen: %w", err))
		return
	}

	// Serialize layers
	data, err := serialize(newLinkLayer.(gopacket.SerializableLayer),
		newNetworkLayer.(gopacket.SerializableLayer),
		newTransportLayer.(gopacket.SerializableLayer),
		gopacket.Payload(encappedIndicator.payload()))
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
	guide := natGuide{
		src:      IPPort{
			IP:   upIP,
			Port: upPort,
		}.String(),
		protocol: encappedIndicator.transportLayerType,
	}
	natIndicator := portNATIndicator{
		srcIP:           indicator.srcIP().String(),
		srcPort:         indicator.srcPort(),
		encappedSrcIP:   encappedIndicator.srcIP().String(),
		encappedSrcPort: encappedIndicator.srcPort(),
		mDev:            dev,
		mHandle:         handle,
	}
	p.natLock.Lock()
	p.nat[guide] = &natIndicator
	p.natLock.Unlock()

	// Keep port alive
	switch encappedIndicator.transportLayerType {
	case layers.LayerTypeTCP:
		p.tcpPortPool[convertFromPort(upPort)] = time.Now()
	case layers.LayerTypeUDP:
		p.udpPortPool[convertFromPort(upPort)] = time.Now()
	default:
		log.Errorln(fmt.Errorf("handle listen: %w", fmt.Errorf("nat: %w", fmt.Errorf("type %s not support", encappedIndicator.transportLayerType))))
		return
	}

	log.Verbosef("Redirect an inbound %s packet: %s -> %s (%d Bytes)\n",
		encappedIndicator.transportLayerType, encappedIndicator.source(), encappedIndicator.destination(), packet.Metadata().Length)
}

// handleUpstream handles TCP and UDP packets from destinations
func (p *Server) handleUpstream(packet gopacket.Packet) {
	var (
		indicator                  *packetIndicator
		newTransportLayer          *layers.TCP
		upDevIP                    net.IP
		encappedTransportLayerType gopacket.LayerType
		encappedTransportLayer     gopacket.TransportLayer
		encappedNetworkLayerType   gopacket.LayerType
		encappedNetworkLayer       gopacket.NetworkLayer
		newNetworkLayerType        gopacket.LayerType
		newNetworkLayer            gopacket.NetworkLayer
		newLinkLayerType           gopacket.LayerType
		newLinkLayer               gopacket.Layer
	)

	// Parse packet
	indicator, err := parsePacket(packet)
	if err != nil {
		log.Errorln(fmt.Errorf("handle upstream: %w", err))
		return
	}

	// NAT
	guide := natGuide{
		src:      indicator.destination(),
		protocol: indicator.transportLayerType,
	}
	p.natLock.RLock()
	natIndicator, ok := p.nat[guide]
	p.natLock.RUnlock()
	if !ok {
		return
	}

	// Keep port alive
	switch indicator.transportLayerType {
	case layers.LayerTypeTCP:
		p.tcpPortPool[convertFromPort(indicator.dstPort())] = time.Now()
	case layers.LayerTypeUDP:
		p.udpPortPool[convertFromPort(indicator.dstPort())] = time.Now()
	default:
		log.Errorln(fmt.Errorf("handle upstream: %w", fmt.Errorf("nat: %w", fmt.Errorf("type %s not support", indicator.transportLayerType))))
		return
	}

	// Create encapped transport layer
	encappedTransportLayerType = indicator.transportLayerType
	switch encappedTransportLayerType {
	case layers.LayerTypeTCP:
		tcpLayer := indicator.transportLayer.(*layers.TCP)
		temp := *tcpLayer
		encappedTransportLayer = &temp

		newTCPLayer := encappedTransportLayer.(*layers.TCP)

		newTCPLayer.DstPort = layers.TCPPort(natIndicator.(*portNATIndicator).encappedSrcPort)
	case layers.LayerTypeUDP:
		udpLayer := indicator.transportLayer.(*layers.UDP)
		temp := *udpLayer
		encappedTransportLayer = &temp

		newUDPLayer := encappedTransportLayer.(*layers.UDP)

		newUDPLayer.DstPort = layers.UDPPort(natIndicator.(*portNATIndicator).encappedSrcPort)
	default:
		log.Errorln(fmt.Errorf("handle upstream: %w", fmt.Errorf("create encapped transport layer: %w", fmt.Errorf("type %s not support", encappedTransportLayerType))))
		return
	}

	// Create encapped network layer
	encappedNetworkLayerType = indicator.networkLayerType
	switch encappedNetworkLayerType {
	case layers.LayerTypeIPv4:
		ipv4Layer := indicator.networkLayer.(*layers.IPv4)
		temp := *ipv4Layer
		encappedNetworkLayer = &temp

		newIPv4Layer := encappedNetworkLayer.(*layers.IPv4)

		newIPv4Layer.DstIP = net.ParseIP(natIndicator.(*portNATIndicator).encappedSrcIP)
	case layers.LayerTypeIPv6:
		ipv6Layer := indicator.networkLayer.(*layers.IPv6)
		temp := *ipv6Layer
		encappedNetworkLayer = &temp

		newIPv6Layer := encappedNetworkLayer.(*layers.IPv6)

		newIPv6Layer.DstIP = net.ParseIP(natIndicator.(*portNATIndicator).encappedSrcIP)
	default:
		log.Errorln(fmt.Errorf("handle upstream: %w", fmt.Errorf("create encapped network layer: %w", fmt.Errorf("type %s not support", encappedNetworkLayerType))))
		return
	}

	// Set network layer for transport layer
	switch encappedTransportLayerType {
	case layers.LayerTypeTCP:
		tcpLayer := encappedTransportLayer.(*layers.TCP)

		err := tcpLayer.SetNetworkLayerForChecksum(encappedNetworkLayer)
		if err != nil {
			log.Errorln(fmt.Errorf("handle upstream: %w", fmt.Errorf("create encapped network layer: %w", err)))
			return
		}
	case layers.LayerTypeUDP:
		udpLayer := encappedTransportLayer.(*layers.UDP)

		err := udpLayer.SetNetworkLayerForChecksum(encappedNetworkLayer)
		if err != nil {
			log.Errorln(fmt.Errorf("handle upstream: %w", fmt.Errorf("create encapped network layer: %w", err)))
			return
		}
	default:
		log.Errorln(fmt.Errorf("handle upstream: %w", fmt.Errorf("create encapped network layer: %w", fmt.Errorf("transport layer type %s not support", encappedTransportLayerType))))
		return
	}

	// Construct contents of new application layer
	contents, err := serialize(encappedNetworkLayer.(gopacket.SerializableLayer),
		encappedTransportLayer.(gopacket.SerializableLayer),
		gopacket.Payload(indicator.payload()))
	if err != nil {
		log.Errorln(fmt.Errorf("handle upstream: %w", fmt.Errorf("create application layer: %w", err)))
		return
	}

	// Create new transport layer
	addr := IPPort{IP: net.ParseIP(natIndicator.(*portNATIndicator).srcIP), Port: natIndicator.(*portNATIndicator).srcPort}.String()
	p.seqsLock.RLock()
	p.acksLock.RLock()
	newTransportLayer = createTransportLayerTCP(p.ListenPort, natIndicator.(*portNATIndicator).srcPort, p.seqs[addr], p.acks[addr])
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
		newNetworkLayer, err = createNetworkLayerIPv4(upDevIP, net.ParseIP(natIndicator.(*portNATIndicator).srcIP), p.id, indicator.ipv4Layer().TTL-1, newTransportLayer)
	case layers.LayerTypeIPv6:
		newNetworkLayer, err = createNetworkLayerIPv6(upDevIP, net.ParseIP(natIndicator.(*portNATIndicator).srcIP), newTransportLayer)
	default:
		log.Errorln(fmt.Errorf("handle upstream: %w", fmt.Errorf("create network layer: %w", fmt.Errorf("type %s not support", newNetworkLayerType))))
		return
	}
	if err != nil {
		log.Errorln(fmt.Errorf("handle upstream: %w", err))
		return
	}

	// Decide Loopback or Ethernet
	if natIndicator.dev().IsLoop {
		newLinkLayerType = layers.LayerTypeLoopback
	} else {
		newLinkLayerType = layers.LayerTypeEthernet
	}

	// Create new link layer
	switch newLinkLayerType {
	case layers.LayerTypeLoopback:
		newLinkLayer = createLinkLayerLoopback()
	case layers.LayerTypeEthernet:
		newLinkLayer, err = createLinkLayerEthernet(natIndicator.dev().HardwareAddr, p.GatewayDev.HardwareAddr, newNetworkLayer)
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
	err = natIndicator.(*portNATIndicator).handle().WritePacketData(data)
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
		indicator.transportLayerType, IPPort{IP: net.ParseIP(natIndicator.(*portNATIndicator).encappedSrcIP), Port: natIndicator.(*portNATIndicator).encappedSrcPort}, indicator.source(), len(data))
}

func (p *Server) distPort(t gopacket.LayerType) (uint16, error) {
	now := time.Now()

	switch t {
	case layers.LayerTypeTCP:
		for i := 0; i < 16384; i++ {
			s := p.nextTCPPort % 16384

			// Point to next port
			p.nextTCPPort++

			// Check if the port is alive
			last := p.tcpPortPool[s]
			if now.Sub(last).Seconds() > portKeepAlive {
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
			if now.Sub(last).Seconds() > portKeepAlive {
				return 49152 + s, nil
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
