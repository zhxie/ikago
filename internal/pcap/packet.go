package pcap

import (
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type devPacket struct {
	Packet gopacket.Packet
	Dev    *Device
	Handle *pcap.Handle
}

// quadruple describes the source and destination's IP, and Id and protocol of a packet for NAT Id distribution
type quadruple struct {
	SrcIP    string
	DstIP    string
	Id       uint16
	Protocol gopacket.LayerType
}

// quintuple describes the source and destination's IP and ports, and protocol of a packet for NAT port distribution
type quintuple struct {
	SrcIP    string
	SrcPort  uint16
	DstIP    string
	DstPort  uint16
	Protocol gopacket.LayerType
}

type natGuide struct {
	Src      string
	Protocol gopacket.LayerType
}

type natIndicator interface {
	// Dev returns the device of the indicator
	Dev() *Device
	// Handle returns the pcap handle of the indicator
	Handle() *pcap.Handle
}

type devNATIndicator struct {
	DevMember    *Device
	HandleMember *pcap.Handle
}

func (indicator *devNATIndicator) Dev() *Device {
	return indicator.DevMember
}

func (indicator *devNATIndicator) Handle() *pcap.Handle {
	return indicator.HandleMember
}

type portNATIndicator struct {
	SrcIP           string
	SrcPort         uint16
	EncappedSrcIP   string
	EncappedSrcPort uint16
	DevMember       *Device
	HandleMember    *pcap.Handle
}

func (indicator *portNATIndicator) Dev() *Device {
	return indicator.DevMember
}

func (indicator *portNATIndicator) Handle() *pcap.Handle {
	return indicator.HandleMember
}

// sendTCPPacket implements a method sends a TCP packet
func sendTCPPacket(addr string, data []byte) error {
	// Create connection
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("send tcp packet: %w", err)
	}
	defer conn.Close()

	// Write data
	_, err = conn.Write(data)
	if err != nil {
		return fmt.Errorf("send tcp packet: %w", err)
	}
	return nil
}

// sendUDPPacket implements a method sends a UDP packet
func sendUDPPacket(addr string, data []byte) error {
	// Create connection
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return fmt.Errorf("send udp packet: %w", err)
	}
	defer conn.Close()

	// Write data
	_, err = conn.Write(data)
	if err != nil {
		return fmt.Errorf("send udp packet: %w", err)
	}
	return nil
}

type packetIndicator struct {
	NetworkLayer       gopacket.NetworkLayer
	NetworkLayerType   gopacket.LayerType
	TransportLayer     gopacket.Layer
	TransportLayerType gopacket.LayerType
	ICMPv4Indicator    *icmpv4Indicator
	ApplicationLayer   gopacket.ApplicationLayer
}

// IPv4Layer returns the IPv4 layer of the packet
func (indicator *packetIndicator) IPv4Layer() *layers.IPv4 {
	if indicator.NetworkLayerType == layers.LayerTypeIPv4 {
		return indicator.NetworkLayer.(*layers.IPv4)
	}

	return nil
}

// IPv6Layer returns the IPv6 layer of the packet
func (indicator *packetIndicator) IPv6Layer() *layers.IPv6 {
	if indicator.NetworkLayerType == layers.LayerTypeIPv6 {
		return indicator.NetworkLayer.(*layers.IPv6)
	}

	return nil
}

// TCPLayer returns the TCP layer of the packet
func (indicator *packetIndicator) TCPLayer() *layers.TCP {
	if indicator.TransportLayerType == layers.LayerTypeTCP {
		return indicator.TransportLayer.(*layers.TCP)
	}

	return nil
}

// UDPLayer returns the UDP layer of the packet
func (indicator *packetIndicator) UDPLayer() *layers.UDP {
	if indicator.TransportLayerType == layers.LayerTypeUDP {
		return indicator.TransportLayer.(*layers.UDP)
	}

	return nil
}

// SrcIP returns the source IP of the packet
func (indicator *packetIndicator) SrcIP() net.IP {
	switch indicator.NetworkLayerType {
	case layers.LayerTypeIPv4:
		return indicator.IPv4Layer().SrcIP
	case layers.LayerTypeIPv6:
		return indicator.IPv6Layer().SrcIP
	default:
		panic(fmt.Errorf("src ip: %w", fmt.Errorf("type %s not support", indicator.NetworkLayerType)))
	}
}

// DstIP returns the destination IP of the packet
func (indicator *packetIndicator) DstIP() net.IP {
	switch indicator.NetworkLayerType {
	case layers.LayerTypeIPv4:
		return indicator.IPv4Layer().DstIP
	case layers.LayerTypeIPv6:
		return indicator.IPv6Layer().DstIP
	default:
		panic(fmt.Errorf("dst ip: %w", fmt.Errorf("type %s not support", indicator.NetworkLayerType)))
	}
}

// SrcPort returns the source port of the packet
func (indicator *packetIndicator) SrcPort() uint16 {
	switch indicator.TransportLayerType {
	case layers.LayerTypeTCP:
		return uint16(indicator.TCPLayer().SrcPort)
	case layers.LayerTypeUDP:
		return uint16(indicator.UDPLayer().SrcPort)
	default:
		panic(fmt.Errorf("src port: %w", fmt.Errorf("type %s not support", indicator.TransportLayerType)))
	}
}

// DstPort returns the source port of the packet
func (indicator *packetIndicator) DstPort() uint16 {
	switch indicator.TransportLayerType {
	case layers.LayerTypeTCP:
		return uint16(indicator.TCPLayer().DstPort)
	case layers.LayerTypeUDP:
		return uint16(indicator.UDPLayer().DstPort)
	default:
		panic(fmt.Errorf("dst port: %w", fmt.Errorf("type %s not support", indicator.TransportLayerType)))
	}
}

// NATSource returns the source for NAT of the packet
func (indicator *packetIndicator) NATSource() string {
	t := indicator.TransportLayerType
	switch t {
	case layers.LayerTypeTCP, layers.LayerTypeUDP:
		return IPPort{
			IP:   indicator.SrcIP(),
			Port: indicator.SrcPort(),
		}.String()
	case layers.LayerTypeICMPv4:
		if indicator.ICMPv4Indicator.IsQuery() {
			return IPId{
				IP: indicator.SrcIP(),
				Id: indicator.ICMPv4Indicator.Id(),
			}.String()
		} else {
			// The ICMPv4 error includes the original packet, so flip it
			return indicator.ICMPv4Indicator.Destination()
		}
	default:
		panic(fmt.Errorf("source: %w", fmt.Errorf("type %s not support", t)))
	}
}

// NATDestination returns the destination for NAT of the packet
func (indicator *packetIndicator) NATDestination() string {
	t := indicator.TransportLayerType
	switch t {
	case layers.LayerTypeTCP, layers.LayerTypeUDP:
		return IPPort{
			IP:   indicator.DstIP(),
			Port: indicator.DstPort(),
		}.String()
	case layers.LayerTypeICMPv4:
		if indicator.ICMPv4Indicator.IsQuery() {
			return IPId{
				IP: indicator.DstIP(),
				Id: indicator.ICMPv4Indicator.Id(),
			}.String()
		} else {
			// The ICMPv4 error includes the original packet, so flip it
			return indicator.ICMPv4Indicator.Source()
		}
	default:
		panic(fmt.Errorf("destination: %w", fmt.Errorf("type %s not support", t)))
	}
}

// Source returns the source of the packet
func (indicator *packetIndicator) Source() string {
	t := indicator.TransportLayerType
	switch t {
	case layers.LayerTypeTCP, layers.LayerTypeUDP:
		return IPPort{
			IP:   indicator.SrcIP(),
			Port: indicator.SrcPort(),
		}.String()
	case layers.LayerTypeICMPv4:
		if indicator.ICMPv4Indicator.IsQuery() {
			return IPId{
				IP: indicator.SrcIP(),
				Id: indicator.ICMPv4Indicator.Id(),
			}.String()
		} else {
			return formatIP(indicator.SrcIP())
		}
	default:
		panic(fmt.Errorf("source: %w", fmt.Errorf("type %s not support", t)))
	}
}

// Destination returns the destination of the packet
func (indicator *packetIndicator) Destination() string {
	t := indicator.TransportLayerType
	switch t {
	case layers.LayerTypeTCP, layers.LayerTypeUDP:
		return IPPort{
			IP:   indicator.DstIP(),
			Port: indicator.DstPort(),
		}.String()
	case layers.LayerTypeICMPv4:
		return formatIP(indicator.SrcIP())
	default:
		panic(fmt.Errorf("destination: %w", fmt.Errorf("type %s not support", t)))
	}
}

// NATProtocol returns the protocol of the transport layer for NAT of the packet
func (indicator *packetIndicator) NATProtocol() gopacket.LayerType {
	t := indicator.TransportLayerType
	switch t {
	case layers.LayerTypeTCP, layers.LayerTypeUDP:
		return t
	case layers.LayerTypeICMPv4:
		if indicator.ICMPv4Indicator.IsQuery() {
			return t
		} else {
			return indicator.ICMPv4Indicator.EncappedTransportLayerType
		}
	default:
		panic(fmt.Errorf("protocol: %w", fmt.Errorf("type %s not support", t)))
	}
}

// Payload returns the application layer in array of bytes
func (indicator *packetIndicator) Payload() []byte {
	if indicator.ApplicationLayer == nil {
		return nil
	}
	return indicator.ApplicationLayer.LayerContents()
}

func parsePacket(packet gopacket.Packet) (*packetIndicator, error) {
	var (
		networkLayer       gopacket.NetworkLayer
		networkLayerType   gopacket.LayerType
		transportLayer     gopacket.Layer
		transportLayerType gopacket.LayerType
		icmpv4Indicator    *icmpv4Indicator
		applicationLayer   gopacket.ApplicationLayer
	)

	// Parse packet
	networkLayer = packet.NetworkLayer()
	if networkLayer == nil {
		return nil, fmt.Errorf("parse: %w", errors.New("missing network layer"))
	}
	networkLayerType = networkLayer.LayerType()
	transportLayer = packet.TransportLayer()
	if transportLayer == nil {
		// Guess ICMPv4
		transportLayer = packet.Layer(layers.LayerTypeICMPv4)
		if transportLayer == nil {
			return nil, fmt.Errorf("parse: %w", errors.New("missing transport layer"))
		}
	}
	transportLayerType = transportLayer.LayerType()
	applicationLayer = packet.ApplicationLayer()

	// Parse network layer
	switch networkLayerType {
	case layers.LayerTypeIPv4, layers.LayerTypeIPv6:
		break
	default:
		return nil, fmt.Errorf("parse: %w", fmt.Errorf("network layer type %s not support", networkLayerType))
	}

	// Parse transport layer
	switch transportLayerType {
	case layers.LayerTypeTCP, layers.LayerTypeUDP:
		break
	case layers.LayerTypeICMPv4:
		var err error
		icmpv4Indicator, err = parseICMPv4Layer(transportLayer.(*layers.ICMPv4))
		if err != nil {
			return nil, fmt.Errorf("parse: %w", err)
		}
	default:
		return nil, fmt.Errorf("parse: %w", fmt.Errorf("transport layer type %s not support", transportLayerType))
	}

	return &packetIndicator{
		NetworkLayer:       networkLayer,
		NetworkLayerType:   networkLayerType,
		TransportLayer:     transportLayer,
		TransportLayerType: transportLayerType,
		ICMPv4Indicator:    icmpv4Indicator,
		ApplicationLayer:   applicationLayer,
	}, nil
}

func parseEncappedPacket(contents []byte) (*packetIndicator, error) {
	// Guess network layer type
	packet := gopacket.NewPacket(contents, layers.LayerTypeIPv4, gopacket.Default)
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return nil, fmt.Errorf("parse encapped: %w", errors.New("missing network layer"))
	}
	if networkLayer.LayerType() != layers.LayerTypeIPv4 {
		return nil, fmt.Errorf("parse encapped: %w", errors.New("network layer type not support"))
	}
	ipVersion := networkLayer.(*layers.IPv4).Version
	switch ipVersion {
	case 4:
		break
	case 6:
		// Not IPv4, but IPv6
		encappedPacket := gopacket.NewPacket(contents, layers.LayerTypeIPv6, gopacket.Default)
		networkLayer = encappedPacket.NetworkLayer()
		if networkLayer == nil {
			return nil, fmt.Errorf("parse encapped: %w", errors.New("missing network layer"))
		}
		if networkLayer.LayerType() != layers.LayerTypeIPv6 {
			return nil, fmt.Errorf("parse encapped: %w", errors.New("network layer type not support"))
		}
	default:
		return nil, fmt.Errorf("parse encapped: %w", fmt.Errorf("ip version %d not support", ipVersion))
	}

	// Parse packet
	indicator, err := parsePacket(packet)
	if err != nil {
		return nil, fmt.Errorf("parse encapped: %w", err)
	}
	return indicator, nil
}

func parseRawPacket(contents []byte) (*gopacket.Packet, error) {
	// Guess link layer type, and here we regard loopback layer as a link layer
	packet := gopacket.NewPacket(contents, layers.LayerTypeLoopback, gopacket.Default)
	if len(packet.Layers()) < 0 {
		return nil, fmt.Errorf("parse raw: %w", errors.New("missing link layer"))
	}
	// Raw packet must start from the link layer
	linkLayer := packet.Layers()[0]
	if linkLayer.LayerType() != layers.LayerTypeLoopback {
		// Not Loopback, then Ethernet
		packet = gopacket.NewPacket(contents, layers.LayerTypeEthernet, gopacket.Default)
		linkLayer := packet.LinkLayer()
		if linkLayer == nil {
			return nil, fmt.Errorf("parse raw: %w", errors.New("missing link layer"))
		}
		if linkLayer.LayerType() != layers.LayerTypeEthernet {
			return nil, fmt.Errorf("parse raw: %w", errors.New("link layer type not support"))
		}
	}

	return &packet, nil
}
