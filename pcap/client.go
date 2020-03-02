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

// Client describes the packet capture on the client side
type Client struct {
	Filters       []Filter
	UpPort        uint16
	ServerIP      net.IP
	ServerPort    uint16
	ListenDevs    []*Device
	GatewayDev    *Device
	listenHandles []*pcap.Handle
	proxy         proxy.Client
	nat           map[quintuple]*packetSrc
}

// Open implements a method opens the pcap
func (p *Client) Open() error {
	p.nat = make(map[quintuple]*packetSrc)

	// Verify
	if len(p.ListenDevs) <= 0 {
		return fmt.Errorf("open: %w", errors.New("missing listen device"))
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
	if !p.GatewayDev.IsLoop {
		fmt.Printf("Route upstream to gateway [%s]: %s\n", p.GatewayDev.HardwareAddr, p.GatewayDev.IPAddr().IP)
	} else {
		fmt.Println("Route upstream to loopback")
	}

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

	// Proxy for routing upstream
	p.proxy = proxy.Client{LocalPort: p.UpPort, Server: IPPort{IP: p.ServerIP, Port: p.ServerPort}.String()}
	err := p.proxy.Open()
	if err != nil {
		return fmt.Errorf("open: %w", fmt.Errorf("proxy: %w", err))
	}

	// Start handling
	for i, handle := range p.listenHandles {
		dev := p.ListenDevs[i]
		ps := packetSrc{Dev: dev, Handle: handle}
		packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
		go func() {
			for packet := range packetSrc.Packets() {
				p.handleListen(packet, &ps)
			}
		}()
	}
	for data := range p.proxy.Read() {
		p.handleUpstream(data)
	}

	return nil
}

// Close implements a method closes the pcap
func (p *Client) Close() {
	for _, handle := range p.listenHandles {
		handle.Close()
	}
	p.proxy.Close()
}

func (p *Client) handleListen(packet gopacket.Packet, ps *packetSrc) {
	var (
		indicator *packetIndicator
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
	data, err := serializeWithoutLinkLayer(indicator.NetworkLayer, indicator.TransportLayer, indicator.Payload())
	if err != nil {
		fmt.Println(fmt.Errorf("handle upstream: %w", fmt.Errorf("create application layer: %w", err)))
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
	p.nat[q] = ps

	// Write packet data
	err = p.proxy.Write(data)
	if err != nil {
		fmt.Println(fmt.Errorf("handle listen: %w", err))
		return
	}

	fmt.Printf("Redirect an outbound %s packet: %s -> %s (Payload %d Bytes)\n",
		indicator.TransportLayerType, indicator.SrcAddr(), indicator.DstAddr(), len(data))
}

func (p *Client) handleUpstream(data []byte) {
	var (
		encappedIndicator *packetIndicator
		newLinkLayer      gopacket.Layer
		newLinkLayerType  gopacket.LayerType
		dev               *Device
		handle            *pcap.Handle
	)

	// Empty payload
	if data == nil {
		return
	}

	// Parse encapped packet
	encappedIndicator, err := parseEncappedPacket(data)
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
	ps, ok := p.nat[q]
	if !ok {
		fmt.Println(fmt.Errorf("handle upstream: %w", errors.New("missing nat rule")))
		return
	}
	dev = ps.Dev
	handle = ps.Handle

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
	newData, err := serialize(newLinkLayer, encappedIndicator.NetworkLayer, encappedIndicator.TransportLayer, encappedIndicator.Payload())
	if err != nil {
		fmt.Println(fmt.Errorf("handle upstream: %w", err))
		return
	}

	// Write packet data
	err = handle.WritePacketData(newData)
	if err != nil {
		fmt.Println(fmt.Errorf("handle upstream: %w", fmt.Errorf("write: %w", err)))
		return
	}
	fmt.Printf("Redirect an inbound %s packet: %s <- %s (Payload %d Bytes)\n",
		encappedIndicator.TransportLayerType, encappedIndicator.SrcAddr(), encappedIndicator.DstAddr(), len(data))
}
