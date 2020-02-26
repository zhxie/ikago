package pcap

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
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
	nat           map[quintuple][]backQuintuple
}

// Open implements a method opens the pcap
func (p *Server) Open() error {
	p.id = 0
	p.nat = make(map[quintuple][]backQuintuple)

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
	for _, handle := range p.listenHandles {
		packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
		go func() {
			for packet := range packetSrc.Packets() {
				p.handleListen(packet, handle)
			}
		}()
	}
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

	// Create transport layer
	newTransportLayer = createTCPLayerSYNACK(p.ListenPort, indicator.SrcPort, p.seq, indicator.Seq+1)
	p.seq++

	// Create new network layer
	var err error
	switch newNetworkLayerType {
	case layers.LayerTypeIPv4:
		newNetworkLayer, err = createNetworkLayerIPv4(indicator.DstIP,
			indicator.SrcIP, p.id, 128, newTransportLayer)
		p.id++
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

	return nil
}

func (p *Server) handleListen(packet gopacket.Packet, handle *pcap.Handle) {
	var (
		indicator             *packetIndicator
		encappedIndicator     *packetIndicator
		newNetworkLayerType   gopacket.LayerType
		newNetworkLayer       gopacket.NetworkLayer
		newLinkLayerType      gopacket.LayerType
		newLinkLayer          gopacket.Layer
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
			fmt.Println(fmt.Errorf("handshake: %w", err))
			return
		}
		fmt.Printf("Connect from client %s:%d\n", indicator.SrcIP, indicator.SrcPort)
		return
	}

	// Empty payload
	if indicator.ApplicationLayer == nil {
		fmt.Println(fmt.Errorf("handle listen: %w",
			fmt.Errorf("parse: %w", errors.New("empty payload"))))
		return
	}

	// Parse encapped packet
	encappedIndicator, err = parseEncappedPacket(indicator.ApplicationLayer.LayerContents())
	if err != nil {
		fmt.Println(fmt.Errorf("handle listen: %w", err))
		return
	}

	// Create new network layer
	newNetworkLayerType = encappedIndicator.NetworkLayerType
	switch newNetworkLayerType {
	case layers.LayerTypeIPv4:
		newNetworkLayer, err = createNetworkLayerIPv4(p.UpDev.IPv4Addr().IP,
			encappedIndicator.DstIP, encappedIndicator.Id, encappedIndicator.TTL-1, encappedIndicator.TransportLayer)
	case layers.LayerTypeIPv6:
		newNetworkLayer, err = createNetworkLayerIPv6(p.UpDev.IPv6Addr().IP,
			encappedIndicator.DstIP, encappedIndicator.TransportLayer)
	default:
		fmt.Println(fmt.Errorf("handle listen: %w",
			fmt.Errorf("create network layer: %w",
				fmt.Errorf("type %s not support", newNetworkLayerType))))
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
		newLinkLayer, err = createLinkLayerEthernet(p.UpDev.HardwareAddr,
			p.GatewayDev.HardwareAddr, newNetworkLayer)
	default:
		fmt.Println(fmt.Errorf("handle listen: %w",
			fmt.Errorf("create link layer: %w", fmt.Errorf("type %s not support", newLinkLayerType))))
		return
	}
	if err != nil {
		fmt.Println(fmt.Errorf("handle listen: %w", err))
		return
	}

	// Record the source and the source device of the packet
	q := quintuple{
		SrcIP:    p.UpDev.IPv4Addr().IP.String(),
		SrcPort:  encappedIndicator.SrcPort,
		DstIP:    encappedIndicator.DstIP.String(),
		DstPort:  encappedIndicator.DstPort,
		Protocol: encappedIndicator.TransportLayerType,
	}
	bq := backQuintuple{
		SrcIP:           indicator.SrcIP.String(),
		SrcPort:         indicator.SrcPort,
		EncappedSrcIP:   encappedIndicator.SrcIP.String(),
		EncappedSrcPort: encappedIndicator.SrcPort,
		Handle:          handle,
	}
	bts, ok := p.nat[q]
	if !ok {
		bts = make([]backQuintuple, 0)
	}
	bts = append(bts, bq)

	// Serialize layers
	data, err := serialize(newLinkLayer, newNetworkLayer,
		encappedIndicator.TransportLayer, encappedIndicator.ApplicationLayer.LayerContents())
	if err != nil {
		fmt.Println(fmt.Errorf("handle listen: %w", err))
		return
	}

	// Write packet data
	err = p.upHandle.WritePacketData(data)
	if err != nil {
		fmt.Println(fmt.Errorf("handle listen: %w", fmt.Errorf("write: %w", err)))
	}
	fmt.Printf("Redirect an inbound %s packet from %s to %s (%d Bytes)\n",
		encappedIndicator.TransportLayerType,
		encappedIndicator.SrcAddr(), encappedIndicator.DstAddr(), packet.Metadata().Length)
}

func (p *Server) handleUpstream(packet gopacket.Packet) {

}
