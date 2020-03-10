package pcap

import (
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type triple struct {
	IP       string
	Port     uint16
	Protocol gopacket.LayerType
}

type quintuple struct {
	SrcIP    string
	SrcPort  uint16
	DstIP    string
	DstPort  uint16
	Protocol gopacket.LayerType
}

type devPacket struct {
	Packet gopacket.Packet
	Dev    *Device
	Handle *pcap.Handle
}

type devIndicator struct {
	Dev    *Device
	Handle *pcap.Handle
}

type natIndicator struct {
	SrcIP           string
	SrcPort         uint16
	EncappedSrcIP   string
	EncappedSrcPort uint16
	Dev             *Device
	Handle          *pcap.Handle
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
	TransportLayer     gopacket.TransportLayer
	TransportLayerType gopacket.LayerType
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
		panic(fmt.Errorf("src ip: %w", fmt.Errorf("invalid type %s", indicator.NetworkLayerType)))
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
		panic(fmt.Errorf("dst ip: %w", fmt.Errorf("invalid type %s", indicator.NetworkLayerType)))
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
		panic(fmt.Errorf("src port: %w", fmt.Errorf("invalid type %s", indicator.TransportLayerType)))
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
		panic(fmt.Errorf("dst port: %w", fmt.Errorf("invalid type %s", indicator.TransportLayerType)))
	}
}

// SrcIPPort returns the source IP and port of the packet
func (indicator *packetIndicator) SrcIPPort() *IPPort {
	return &IPPort{
		IP:   indicator.SrcIP(),
		Port: indicator.SrcPort(),
	}
}

// DstIPPort returns the destination IP and port of the packet
func (indicator *packetIndicator) DstIPPort() *IPPort {
	return &IPPort{
		IP:   indicator.DstIP(),
		Port: indicator.DstPort(),
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
		transportLayer     gopacket.TransportLayer
		transportLayerType gopacket.LayerType
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
		return nil, fmt.Errorf("parse: %w", errors.New("missing transport layer"))
	}
	transportLayerType = transportLayer.LayerType()
	applicationLayer = packet.ApplicationLayer()

	// Parse network layer
	switch networkLayerType {
	case layers.LayerTypeIPv4:
	case layers.LayerTypeIPv6:
		break
	default:
		return nil, fmt.Errorf("parse: %w", fmt.Errorf("network layer type %s not support", networkLayerType))
	}

	// Parse transport layer
	switch transportLayerType {
	case layers.LayerTypeTCP:
	case layers.LayerTypeUDP:
		break
	default:
		return nil, fmt.Errorf("parse: %w", fmt.Errorf("transport layer type %s not support", transportLayerType))
	}

	return &packetIndicator{
		NetworkLayer:       networkLayer,
		NetworkLayerType:   networkLayerType,
		TransportLayer:     transportLayer,
		TransportLayerType: transportLayerType,
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
