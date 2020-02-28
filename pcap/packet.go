package pcap

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
)

type quintuple struct {
	SrcIP    string
	SrcPort  uint16
	DstIP    string
	DstPort  uint16
	Protocol gopacket.LayerType
}

type packetSrc struct {
	Dev    *Device
	Handle *pcap.Handle
}

type encappedPacketSrc struct {
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
	SrcIP              net.IP
	DstIP              net.IP
	Id                 uint16
	TTL                uint8
	TransportLayer     gopacket.TransportLayer
	TransportLayerType gopacket.LayerType
	SrcPort            uint16
	DstPort            uint16
	Seq                uint32
	Ack                uint32
	SYN                bool
	ACK                bool
	IsPortUndefined    bool
	ApplicationLayer   gopacket.ApplicationLayer
}

// SrcAddr returns the source address of the packet
func (indicator *packetIndicator) SrcAddr() string {
	i := IPPort{
		IP:              indicator.SrcIP,
		Port:            indicator.SrcPort,
		IsPortUndefined: indicator.IsPortUndefined,
	}
	return i.String()
}

// DstAddr returns the destination address of the packet
func (indicator *packetIndicator) DstAddr() string {
	i := IPPort{
		IP:              indicator.DstIP,
		Port:            indicator.DstPort,
		IsPortUndefined: indicator.IsPortUndefined,
	}
	return i.String()
}

// Payload returns the application layer in array of bytes
func (indicator *packetIndicator) Payload() []byte {
	if indicator.ApplicationLayer == nil {
		return nil
	} else {
		return indicator.ApplicationLayer.LayerContents()
	}
}

func parsePacket(packet gopacket.Packet) (*packetIndicator, error) {
	var (
		networkLayer       gopacket.NetworkLayer
		networkLayerType   gopacket.LayerType
		srcIP              net.IP
		dstIP              net.IP
		id                 uint16
		ttl                uint8
		transportLayer     gopacket.TransportLayer
		transportLayerType gopacket.LayerType
		srcPort            uint16
		dstPort            uint16
		isPortUndefined    bool
		seq                uint32
		ack                uint32
		syn                bool
		bACK               bool
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
		ipv4Layer := networkLayer.(*layers.IPv4)
		srcIP = ipv4Layer.SrcIP
		dstIP = ipv4Layer.DstIP
		id = ipv4Layer.Id
		ttl = ipv4Layer.TTL
	case layers.LayerTypeIPv6:
		ipv6Layer := networkLayer.(*layers.IPv6)
		srcIP = ipv6Layer.SrcIP
		dstIP = ipv6Layer.DstIP
	default:
		return nil, fmt.Errorf("parse: %w",
			fmt.Errorf("network layer type %s not support", networkLayerType))
	}

	// Parse transport layer
	switch transportLayerType {
	case layers.LayerTypeTCP:
		tcpLayer := transportLayer.(*layers.TCP)
		srcPort = uint16(tcpLayer.SrcPort)
		dstPort = uint16(tcpLayer.DstPort)
		seq = tcpLayer.Seq
		ack = tcpLayer.Ack
		syn = tcpLayer.SYN
		bACK = tcpLayer.ACK
	case layers.LayerTypeUDP:
		udpLayer := transportLayer.(*layers.UDP)
		srcPort = uint16(udpLayer.SrcPort)
		dstPort = uint16(udpLayer.DstPort)
	default:
		isPortUndefined = true
	}

	return &packetIndicator{
		NetworkLayer:       networkLayer,
		NetworkLayerType:   networkLayerType,
		SrcIP:              srcIP,
		DstIP:              dstIP,
		Id:                 id,
		TTL:                ttl,
		TransportLayer:     transportLayer,
		TransportLayerType: transportLayerType,
		SrcPort:            srcPort,
		DstPort:            dstPort,
		IsPortUndefined:    isPortUndefined,
		Seq:                seq,
		Ack:                ack,
		SYN:                syn,
		ACK:                bACK,
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
		fmt.Println(fmt.Errorf("handle upstream: %w",
			fmt.Errorf("parse: %w", errors.New("type not support"))))
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
			fmt.Println(fmt.Errorf("handle upstream: %w",
				fmt.Errorf("parse: %w", errors.New("type not support"))))
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
