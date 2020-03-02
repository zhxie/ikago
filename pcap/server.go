package pcap

import (
	"./proxy"
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Server describes the packet capture on the server side
type Server struct {
	ListenPort uint16
	UpDev      *Device
	GatewayDev *Device
	proxy      proxy.Server
	upHandle   *pcap.Handle
	port       uint16
	portDist   map[quintuple]uint16
	nat        map[quintuple]*encappedPacketSrc
}

// Open implements a method opens the pcap
func (p *Server) Open() error {
	p.portDist = make(map[quintuple]uint16)
	p.nat = make(map[quintuple]*encappedPacketSrc)

	// Verify
	if p.UpDev == nil {
		return fmt.Errorf("open: %w", errors.New("missing upstream device"))
	}
	if p.GatewayDev == nil {
		return fmt.Errorf("open: %w", errors.New("missing gateway"))
	}
	fmt.Printf("Listen on :%d\n", p.ListenPort)
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

	// Proxy for listening
	p.proxy = proxy.Server{Port: p.ListenPort}
	err := p.proxy.Open()
	if err != nil {
		return fmt.Errorf("open: %w", fmt.Errorf("proxy: %w", err))
	}

	// Handles for routing upstream
	p.upHandle, err = pcap.OpenLive(p.UpDev.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	err = p.upHandle.SetBPFFilter(fmt.Sprintf("(tcp || udp) && not dst port %d", p.ListenPort))
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}

	// Start handling
	go func() {
		for data := range p.proxy.Read() {
			p.handleListen(data.Data, data.Conn)
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
	p.proxy.Close()
	p.upHandle.Close()
}

func (p *Server) handleListen(data []byte, conn net.Conn) {
	var (
		encappedIndicator   *packetIndicator
		newNetworkLayerType gopacket.LayerType
		newNetworkLayer     gopacket.NetworkLayer
		newLinkLayerType    gopacket.LayerType
		newLinkLayer        gopacket.Layer
	)

	// Empty payload
	if data == nil {
		return
	}

	// Parse encapped packet
	encappedIndicator, err := parseEncappedPacket(data)
	if err != nil {
		fmt.Println(fmt.Errorf("handle listen: %w", err))
		return
	}

	// Distribute port
	remoteIPPort, err := ParseIPPort(conn.RemoteAddr().String())
	if err != nil {
		fmt.Println(fmt.Errorf("handle listen: %w", err))
		return
	}
	qPortDist := quintuple{
		SrcIP:    encappedIndicator.SrcIP.String(),
		SrcPort:  encappedIndicator.SrcPort,
		DstIP:    remoteIPPort.IP.String(),
		DstPort:  remoteIPPort.Port,
		Protocol: encappedIndicator.TransportLayerType,
	}
	distPort, ok := p.portDist[qPortDist]
	if !ok {
		distPort = p.distPort()
		p.port++
		p.portDist[qPortDist] = distPort
	}

	// Modify transport layer
	switch encappedIndicator.TransportLayerType {
	case layers.LayerTypeTCP:
		tcpLayer := encappedIndicator.TransportLayer.(*layers.TCP)
		tcpLayer.SrcPort = layers.TCPPort(distPort)
	case layers.LayerTypeUDP:
		udpLayer := encappedIndicator.TransportLayer.(*layers.UDP)
		udpLayer.SrcPort = layers.UDPPort(distPort)
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
		SrcPort:  distPort,
		DstIP:    encappedIndicator.DstIP.String(),
		DstPort:  encappedIndicator.DstPort,
		Protocol: encappedIndicator.TransportLayerType,
	}
	eps := encappedPacketSrc{
		SrcIP:           remoteIPPort.IP.String(),
		SrcPort:         remoteIPPort.Port,
		EncappedSrcIP:   encappedIndicator.SrcIP.String(),
		EncappedSrcPort: encappedIndicator.SrcPort,
		Conn:            conn,
	}
	p.nat[qNAT] = &eps

	// Serialize layers
	newData, err := serialize(newLinkLayer, newNetworkLayer, encappedIndicator.TransportLayer, encappedIndicator.Payload())
	if err != nil {
		fmt.Println(fmt.Errorf("handle listen: %w", err))
		return
	}

	// Write packet data
	err = p.upHandle.WritePacketData(newData)
	if err != nil {
		fmt.Println(fmt.Errorf("handle listen: %w", fmt.Errorf("write: %w", err)))
	}
	fmt.Printf("Redirect an inbound %s packet: %s -> %s (Payload %d Bytes)\n",
		encappedIndicator.TransportLayerType, encappedIndicator.SrcAddr(), encappedIndicator.DstAddr(), len(data))
}

func (p *Server) handleUpstream(packet gopacket.Packet) {
	var (
		indicator *packetIndicator
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
	eps, ok := p.nat[q]
	if !ok {
		return
	}

	// NAT back encapped transport layer
	switch indicator.TransportLayerType {
	case layers.LayerTypeTCP:
		tcpLayer := indicator.TransportLayer.(*layers.TCP)
		tcpLayer.DstPort = layers.TCPPort(eps.EncappedSrcPort)
	case layers.LayerTypeUDP:
		udpLayer := indicator.TransportLayer.(*layers.UDP)
		udpLayer.DstPort = layers.UDPPort(eps.EncappedSrcPort)
	default:
		fmt.Println(fmt.Errorf("handle upstream: %w", fmt.Errorf("create encapped transport layer: %w", fmt.Errorf("type %s not support", indicator.TransportLayerType))))
		return
	}

	// NAT back encapped network layer
	switch indicator.NetworkLayerType {
	case layers.LayerTypeIPv4:
		ipv4Layer := indicator.NetworkLayer.(*layers.IPv4)
		ipv4Layer.DstIP = net.ParseIP(eps.EncappedSrcIP)
	case layers.LayerTypeIPv6:
		ipv6Layer := indicator.NetworkLayer.(*layers.IPv6)
		ipv6Layer.DstIP = net.ParseIP(eps.EncappedSrcIP)
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

	// Construct data of new application layer
	data, err := serializeWithoutLinkLayer(indicator.NetworkLayer, indicator.TransportLayer, indicator.Payload())
	if err != nil {
		fmt.Println(fmt.Errorf("handle upstream: %w", fmt.Errorf("create application layer: %w", err)))
		return
	}

	// Write packet data
	_, err = eps.Conn.Write(data)
	if err != nil {
		fmt.Println(fmt.Errorf("handle upstream: %w", err))
		return
	}

	fmt.Printf("Redirect an outbound %s packet: %s <- %s (Payload %d Bytes)\n",
		indicator.TransportLayerType, IPPort{IP: net.ParseIP(eps.EncappedSrcIP), Port: eps.EncappedSrcPort}, indicator.SrcAddr(), len(data))
}

func (p *Server) distPort() uint16 {
	return 49152 + p.port%16384
}
