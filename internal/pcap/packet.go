package pcap

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"ikago/internal/addr"
	"net"
)

// ConnPacket describes a packet and its connection.
type ConnPacket struct {
	// Packet is a packet.
	Packet gopacket.Packet
	// Conn is the connection of the packet.
	Conn *RawConn
}

// ConnBytes describes an array of bytes and its connection.
type ConnBytes struct {
	// Bytes is an array of byte.
	Bytes []byte
	// Conn is the connection of the bytes.
	Conn net.Conn
}

// NATGuide describes simplified information about a NAT.
type NATGuide struct {
	// Src is the source in NAT.
	Src string
	// Protocol is the protocol in NAT.
	Protocol gopacket.LayerType
}

// PacketIndicator indicates a packet.
type PacketIndicator struct {
	packet            gopacket.Packet
	linkLayer         gopacket.Layer
	networkLayer      gopacket.Layer
	transportLayer    gopacket.Layer
	icmpv4Indicator   *ICMPv4Indicator
	applicationLayer  gopacket.ApplicationLayer
}

// LinkLayer returns the link layer.
func (indicator *PacketIndicator) LinkLayer() gopacket.Layer {
	return indicator.linkLayer
}

// LinkLayerType returns the type of the link layer.
func (indicator *PacketIndicator) LinkLayerType() gopacket.LayerType {
	return indicator.linkLayer.LayerType()
}

// SrcHardwareAddr returns the source hardware address.
func (indicator *PacketIndicator) SrcHardwareAddr() net.HardwareAddr {
	switch t := indicator.LinkLayerType(); t {
	case layers.LayerTypeLoopback:
		return nil
	case layers.LayerTypeEthernet:
		return indicator.linkLayer.(*layers.Ethernet).SrcMAC
	default:
		panic(fmt.Errorf("link layer type %s not support", t))
	}
}

// DstHardwareAddr returns the destination hardware address.
func (indicator *PacketIndicator) DstHardwareAddr() net.HardwareAddr {
	switch t := indicator.LinkLayerType(); t {
	case layers.LayerTypeLoopback:
		return nil
	case layers.LayerTypeEthernet:
		return indicator.linkLayer.(*layers.Ethernet).DstMAC
	default:
		panic(fmt.Errorf("link layer type %s not support", t))
	}
}

// NetworkLayer returns the network layer.
func (indicator *PacketIndicator) NetworkLayer() gopacket.Layer {
	return indicator.networkLayer
}

// IPv4Layer returns the IPv4 layer.
func (indicator *PacketIndicator) IPv4Layer() *layers.IPv4 {
	if indicator.NetworkLayer().LayerType() == layers.LayerTypeIPv4 {
		return indicator.networkLayer.(*layers.IPv4)
	}

	return nil
}

// ARPLayer returns the ARP layer.
func (indicator *PacketIndicator) ARPLayer() *layers.ARP {
	if indicator.NetworkLayer().LayerType() == layers.LayerTypeARP {
		return indicator.networkLayer.(*layers.ARP)
	}

	return nil
}

// SrcIP returns the source IP.
func (indicator *PacketIndicator) SrcIP() net.IP {
	switch t := indicator.NetworkLayer().LayerType(); t {
	case layers.LayerTypeIPv4:
		return indicator.IPv4Layer().SrcIP
	case layers.LayerTypeARP:
		return indicator.ARPLayer().SourceProtAddress
	default:
		panic(fmt.Errorf("network layer type %s not support", t))
	}
}

// DstIP returns the destination IP.
func (indicator *PacketIndicator) DstIP() net.IP {
	switch t := indicator.NetworkLayer().LayerType(); t {
	case layers.LayerTypeIPv4:
		return indicator.IPv4Layer().DstIP
	case layers.LayerTypeARP:
		return indicator.ARPLayer().DstProtAddress
	default:
		panic(fmt.Errorf("network layer type %s not support", t))
	}
}

// TTL returns the TTL.
func (indicator *PacketIndicator) TTL() uint8 {
	switch t := indicator.NetworkLayer().LayerType(); t {
	case layers.LayerTypeIPv4:
		return indicator.IPv4Layer().TTL
	default:
		panic(fmt.Errorf("network layer type %s not support", t))
	}
}

// Id returns the Id in the network layer.
func (indicator *PacketIndicator) NetworkId() uint {
	switch t := indicator.NetworkLayer().LayerType(); t {
	case layers.LayerTypeIPv4:
		return uint(indicator.IPv4Layer().Id)
	default:
		panic(fmt.Errorf("network layer type %s not support", t))
	}
}

// IsFrag returns if the packet is a fragment.
func (indicator *PacketIndicator) IsFrag() bool {
	switch t := indicator.NetworkLayer().LayerType(); t {
	case layers.LayerTypeIPv4:
		ipv4Layer := indicator.IPv4Layer()

		if ipv4Layer.Flags&layers.IPv4MoreFragments != 0 {
			return true
		}

		return ipv4Layer.FragOffset != 0
	default:
		panic(fmt.Errorf("network layer type %s not support", t))
	}
}

// FragOffset returns the fragment offset.
func (indicator *PacketIndicator) FragOffset() uint16 {
	switch t := indicator.NetworkLayer().LayerType(); t {
	case layers.LayerTypeIPv4:
		return indicator.IPv4Layer().FragOffset
	default:
		panic(fmt.Errorf("network layer type %s not support", t))
	}
}

// MoreFragments returns if more fragments follow.
func (indicator *PacketIndicator) MoreFragments() bool {
	switch t := indicator.NetworkLayer().LayerType(); t {
	case layers.LayerTypeIPv4:
		return indicator.IPv4Layer().Flags&layers.IPv4MoreFragments != 0
	default:
		panic(fmt.Errorf("network layer type %s not support", t))
	}
}

// TransportProtocol returns the protocol of the transport layer.
func (indicator *PacketIndicator) TransportProtocol() gopacket.LayerType {
	switch t := indicator.NetworkLayer().LayerType(); t {
	case layers.LayerTypeIPv4:
		p, err := parseIPProtocol(indicator.IPv4Layer().Protocol)
		if err != nil {
			panic(err)
		}

		return p
	default:
		panic(fmt.Errorf("network layer type %s not support", t))
	}
}

// TransportLayer returns the transport layer.
func (indicator *PacketIndicator) TransportLayer() gopacket.Layer {
	return indicator.transportLayer
}

// TCPLayer returns the TCP layer.
func (indicator *PacketIndicator) TCPLayer() *layers.TCP {
	if indicator.TransportLayer().LayerType() == layers.LayerTypeTCP {
		return indicator.transportLayer.(*layers.TCP)
	}

	return nil
}

// UDPLayer returns the UDP layer.
func (indicator *PacketIndicator) UDPLayer() *layers.UDP {
	if indicator.TransportLayer().LayerType() == layers.LayerTypeUDP {
		return indicator.transportLayer.(*layers.UDP)
	}

	return nil
}

// ICMPv4Indicator returns the ICMPv4 indicator.
func (indicator *PacketIndicator) ICMPv4Indicator() *ICMPv4Indicator {
	return indicator.icmpv4Indicator
}

// SrcPort returns the source port.
func (indicator *PacketIndicator) SrcPort() uint16 {
	switch t := indicator.TransportLayer().LayerType(); t {
	case layers.LayerTypeTCP:
		return uint16(indicator.TCPLayer().SrcPort)
	case layers.LayerTypeUDP:
		return uint16(indicator.UDPLayer().SrcPort)
	default:
		panic(fmt.Errorf("transport layer type %s not support", t))
	}
}

// DstPort returns the destination port.
func (indicator *PacketIndicator) DstPort() uint16 {
	switch t := indicator.TransportLayer().LayerType(); t {
	case layers.LayerTypeTCP:
		return uint16(indicator.TCPLayer().DstPort)
	case layers.LayerTypeUDP:
		return uint16(indicator.UDPLayer().DstPort)
	default:
		panic(fmt.Errorf("transport layer type %s not support", t))
	}
}

// NATSrc returns the source used in NAT.
func (indicator *PacketIndicator) NATSrc() net.Addr {
	switch t := indicator.TransportLayer().LayerType(); t {
	case layers.LayerTypeTCP:
		return &net.TCPAddr{
			IP:   indicator.SrcIP(),
			Port: int(indicator.SrcPort()),
		}
	case layers.LayerTypeUDP:
		return &net.UDPAddr{
			IP:   indicator.SrcIP(),
			Port: int(indicator.SrcPort()),
		}
	case layers.LayerTypeICMPv4:
		if indicator.icmpv4Indicator.IsQuery() {
			return &addr.ICMPQueryAddr{
				IP: indicator.SrcIP(),
				Id: indicator.icmpv4Indicator.Id(),
			}
		}

		return indicator.icmpv4Indicator.EmbSrc()
	default:
		panic(fmt.Errorf("transport layer type %s not support", t))
	}
}

// NATDst returns the destination used in NAT.
func (indicator *PacketIndicator) NATDst() net.Addr {
	switch t := indicator.TransportLayer().LayerType(); t {
	case layers.LayerTypeTCP:
		return &net.TCPAddr{
			IP:   indicator.DstIP(),
			Port: int(indicator.DstPort()),
		}
	case layers.LayerTypeUDP:
		return &net.UDPAddr{
			IP:   indicator.DstIP(),
			Port: int(indicator.DstPort()),
		}
	case layers.LayerTypeICMPv4:
		if indicator.icmpv4Indicator.IsQuery() {
			return &addr.ICMPQueryAddr{
				IP: indicator.DstIP(),
				Id: indicator.icmpv4Indicator.Id(),
			}
		}

		return indicator.icmpv4Indicator.EmbDst()
	default:
		panic(fmt.Errorf("transport layer type %s not support", t))
	}
}

// NATProtocol returns the protocol used in NAT.
func (indicator *PacketIndicator) NATProtocol() gopacket.LayerType {
	switch t := indicator.TransportLayer().LayerType(); t {
	case layers.LayerTypeTCP, layers.LayerTypeUDP:
		return t
	case layers.LayerTypeICMPv4:
		if indicator.icmpv4Indicator.IsQuery() {
			return t
		}

		return indicator.icmpv4Indicator.EmbTransportLayer().LayerType()
	default:
		panic(fmt.Errorf("transport layer type %s not support", t))
	}
}

// Src returns the source.
func (indicator *PacketIndicator) Src() net.Addr {
	if indicator.TransportLayer() == nil {
		return &net.IPAddr{
			IP: indicator.SrcIP(),
		}
	}

	switch t := indicator.TransportLayer().LayerType(); t {
	case layers.LayerTypeTCP:
		return &net.TCPAddr{
			IP:   indicator.SrcIP(),
			Port: int(indicator.SrcPort()),
		}
	case layers.LayerTypeUDP:
		return &net.UDPAddr{
			IP:   indicator.SrcIP(),
			Port: int(indicator.SrcPort()),
		}
	case layers.LayerTypeICMPv4:
		if indicator.icmpv4Indicator.IsQuery() {
			return &addr.ICMPQueryAddr{
				IP: indicator.SrcIP(),
				Id: indicator.icmpv4Indicator.Id(),
			}
		}

		return &net.IPAddr{IP: indicator.SrcIP()}
	default:
		panic(fmt.Errorf("transport layer type %s not support", t))
	}
}

// Dst returns the destination.
func (indicator *PacketIndicator) Dst() net.Addr {
	if indicator.TransportLayer() == nil {
		return &net.IPAddr{
			IP: indicator.DstIP(),
		}
	}

	switch t := indicator.TransportLayer().LayerType(); t {
	case layers.LayerTypeTCP:
		return &net.TCPAddr{
			IP:   indicator.DstIP(),
			Port: int(indicator.DstPort()),
		}
	case layers.LayerTypeUDP:
		return &net.UDPAddr{
			IP:   indicator.DstIP(),
			Port: int(indicator.DstPort()),
		}
	case layers.LayerTypeICMPv4:
		if indicator.icmpv4Indicator.IsQuery() {
			return &addr.ICMPQueryAddr{
				IP: indicator.DstIP(),
				Id: indicator.icmpv4Indicator.Id(),
			}
		}

		return &net.IPAddr{IP: indicator.DstIP()}
	default:
		panic(fmt.Errorf("transport layer type %s not support", t))
	}
}

// NetworkPayload returns the payload of network layer.
func (indicator *PacketIndicator) NetworkPayload() []byte {
	payload := indicator.NetworkLayer().LayerPayload()
	if payload == nil {
		return nil
	}

	return payload
}

// Payload returns the payload of transport layer, or layer contents in application layer.
func (indicator *PacketIndicator) Payload() []byte {
	payload := indicator.applicationLayer.LayerContents()
	if payload == nil {
		return nil
	}

	return payload
}

// Size returns the size of the packet.
func (indicator *PacketIndicator) Size() int {
	return len(indicator.packet.Data())
}

// ParsePacket parses a packet and returns a packet indicator.
func ParsePacket(packet gopacket.Packet) (*PacketIndicator, error) {
	var (
		linkLayer         gopacket.Layer
		networkLayer      gopacket.Layer
		transportLayer    gopacket.Layer
		icmpv4Indicator   *ICMPv4Indicator
		applicationLayer  gopacket.ApplicationLayer
	)

	// Parse packet
	linkLayer = packet.LinkLayer()
	if linkLayer == nil {
		// Guess loopback
		linkLayer = packet.Layer(layers.LayerTypeLoopback)
	}
	networkLayer = packet.NetworkLayer()
	if networkLayer == nil {
		// Guess ARP
		networkLayer = packet.Layer(layers.LayerTypeARP)
		if networkLayer == nil {
			return nil, errors.New("missing network layer")
		}

		return &PacketIndicator{
			networkLayer:     networkLayer,
			transportLayer:   nil,
			icmpv4Indicator:  nil,
			applicationLayer: nil,
		}, nil
	}
	transportLayer = packet.TransportLayer()
	if transportLayer == nil {
		// Guess ICMPv4
		transportLayer = packet.Layer(layers.LayerTypeICMPv4)
		if transportLayer == nil {
			// Guess fragment
			if packet.Layer(gopacket.LayerTypeFragment) == nil {
				return nil, errors.New("missing transport layer")
			}
		}
	}
	applicationLayer = packet.ApplicationLayer()

	// Parse link layer
	if linkLayer != nil {
		switch t := linkLayer.LayerType(); t {
		case layers.LayerTypeLoopback:
			break
		case layers.LayerTypeEthernet:
			ethernetLayer := linkLayer.(*layers.Ethernet)

			_, err := parseEthernetType(ethernetLayer.EthernetType)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("link layer type %s not support", t)
		}
	}

	// Parse network layer
	switch t := networkLayer.LayerType(); t {
	case layers.LayerTypeIPv4:
		ipv4Layer := networkLayer.(*layers.IPv4)

		_, err := parseIPProtocol(ipv4Layer.Protocol)
		if err != nil {
			return nil, err
		}
	case layers.LayerTypeARP:
		break
	default:
		return nil, fmt.Errorf("network layer type %s not support", t)
	}

	// Parse transport layer
	if transportLayer != nil {
		switch t := transportLayer.LayerType(); t {
		case layers.LayerTypeTCP, layers.LayerTypeUDP:
			break
		case layers.LayerTypeICMPv4:
			var err error
			icmpv4Indicator, err = ParseICMPv4Layer(transportLayer.(*layers.ICMPv4))
			if err != nil {
				return nil, fmt.Errorf("parse icmpv4 layer: %w", err)
			}
		default:
			return nil, fmt.Errorf("transport layer type %s not support", t)
		}
	}

	return &PacketIndicator{
		packet:            packet,
		linkLayer:         linkLayer,
		networkLayer:      networkLayer,
		transportLayer:    transportLayer,
		icmpv4Indicator:   icmpv4Indicator,
		applicationLayer:  applicationLayer,
	}, nil
}

// ParseEmbPacket parses an embedded packet used in transmission between client and server without link layer.
func ParseEmbPacket(contents []byte) (*PacketIndicator, error) {
	// Guess network layer type
	packet := gopacket.NewPacket(contents, layers.LayerTypeIPv4, gopacket.Default)
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return nil, errors.New("missing network layer")
	}
	if networkLayer.LayerType() != layers.LayerTypeIPv4 {
		return nil, errors.New("network layer type not support")
	}
	switch networkLayer.(*layers.IPv4).Version {
	case 4:
		break
	default:
		return nil, errors.New("network layer type not support")
	}

	// Parse packet
	indicator, err := ParsePacket(packet)
	if err != nil {
		return nil, err
	}
	return indicator, nil
}

// ParseRawPacket parses an array of byte as a packet and returns a packet indicator.
func ParseRawPacket(contents []byte) (gopacket.Packet, error) {
	// Guess link layer type, and here we regard Ethernet layer as a link layer
	packet := gopacket.NewPacket(contents, layers.LayerTypeEthernet, gopacket.Default)
	if len(packet.Layers()) < 0 {
		return nil, errors.New("missing link layer")
	}

	linkLayer := packet.LinkLayer()
	if linkLayer == nil {
		// Guess loopback
		packet = gopacket.NewPacket(contents, layers.LayerTypeLoopback, gopacket.Default)

		linkLayer := packet.Layer(layers.LayerTypeLoopback)
		if linkLayer == nil {
			return nil, errors.New("missing link layer")
		}

		return packet, nil
	}

	if t := linkLayer.LayerType(); t != layers.LayerTypeEthernet {
		return nil, fmt.Errorf("link layer type %s not support", t)
	}

	return packet, nil
}

// SendTCPPacket opens a temporary TCP connection and sends a packet.
func SendTCPPacket(addr string, data []byte) error {
	// Create connection
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()

	// Write data
	_, err = conn.Write(data)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// SendUDPPacket opens a temporary UDP connection and sends a packet.
func SendUDPPacket(addr string, data []byte) error {
	// Create connection
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()

	// Write data
	_, err = conn.Write(data)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

func parseIPProtocol(protocol layers.IPProtocol) (gopacket.LayerType, error) {
	switch protocol {
	case layers.IPProtocolTCP:
		return layers.LayerTypeTCP, nil
	case layers.IPProtocolUDP:
		return layers.LayerTypeUDP, nil
	case layers.IPProtocolICMPv4:
		return layers.LayerTypeICMPv4, nil
	default:
		return gopacket.LayerTypeZero, fmt.Errorf("ip protocol %s not support", protocol)
	}
}

func parseEthernetType(t layers.EthernetType) (gopacket.LayerType, error) {
	switch t {
	case layers.EthernetTypeIPv4:
		return layers.LayerTypeIPv4, nil
	case layers.EthernetTypeARP:
		return layers.LayerTypeARP, nil
	default:
		return gopacket.LayerTypeZero, fmt.Errorf("ethernet type %s not support", t)
	}
}
