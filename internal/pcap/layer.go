package pcap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
)

func createTCPLayerSYN(srcPort, dstPort uint16, seq uint32) *layers.TCP {
	return &layers.TCP{
		SrcPort:    layers.TCPPort(srcPort),
		DstPort:    layers.TCPPort(dstPort),
		Seq:        seq,
		DataOffset: 5,
		SYN:        true,
		Window:     65535,
		// Checksum:   0,
	}
}

func createTCPLayerSYNACK(srcPort, dstPort uint16, seq, ack uint32) *layers.TCP {
	return &layers.TCP{
		SrcPort:    layers.TCPPort(srcPort),
		DstPort:    layers.TCPPort(dstPort),
		Seq:        seq,
		Ack:        ack,
		DataOffset: 5,
		SYN:        true,
		ACK:        true,
		Window:     65535,
		// Checksum:   0,
	}
}

func createTCPLayerACK(srcPort, dstPort uint16, seq, ack uint32) *layers.TCP {
	return &layers.TCP{
		SrcPort:    layers.TCPPort(srcPort),
		DstPort:    layers.TCPPort(dstPort),
		Seq:        seq,
		Ack:        ack,
		DataOffset: 5,
		ACK:        true,
		Window:     65535,
		// Checksum:   0,
	}
}

func createTransportLayerTCP(srcPort, dstPort uint16, seq, ack uint32) *layers.TCP {
	return &layers.TCP{
		SrcPort:    layers.TCPPort(srcPort),
		DstPort:    layers.TCPPort(dstPort),
		Seq:        seq,
		Ack:        ack,
		DataOffset: 5,
		PSH:        true,
		ACK:        true,
		Window:     65535,
		// Checksum:   0,
	}
}

func createTransportLayerUDP(srcPort, dstPort uint16) *layers.UDP {
	return &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
		// Length:    0,
		// Checksum:  0,
	}
}

func createNetworkLayerIPv4(srcIP, dstIP net.IP, id uint16, ttl uint8, transportLayer gopacket.TransportLayer) (*layers.IPv4, error) {
	if srcIP.To4() == nil || dstIP.To4() == nil {
		return nil, fmt.Errorf("create network layer: %w", fmt.Errorf("invalid ipv4 address %s", srcIP))
	}

	ipv4Layer := &layers.IPv4{
		Version: 4,
		IHL:     5,
		// Length:     0,
		Id:    id,
		Flags: layers.IPv4DontFragment,
		TTL:   ttl,
		// Protocol:   0,
		// Checksum:   0,
		SrcIP: srcIP,
		DstIP: dstIP,
	}

	// Protocol
	transportLayerType := transportLayer.LayerType()
	switch transportLayerType {
	case layers.LayerTypeTCP:
		ipv4Layer.Protocol = layers.IPProtocolTCP

		// Checksum of transport layer
		tcpLayer := transportLayer.(*layers.TCP)
		err := tcpLayer.SetNetworkLayerForChecksum(ipv4Layer)
		if err != nil {
			return nil, fmt.Errorf("create network layer: %w", err)
		}
	case layers.LayerTypeUDP:
		ipv4Layer.Protocol = layers.IPProtocolUDP

		// Checksum of transport layer
		udpLayer := transportLayer.(*layers.UDP)
		err := udpLayer.SetNetworkLayerForChecksum(ipv4Layer)
		if err != nil {
			return nil, fmt.Errorf("create network layer: %w", err)
		}
	default:
		return nil, fmt.Errorf("create network layer: %w", fmt.Errorf("transport layer type %s not support", transportLayerType))
	}

	return ipv4Layer, nil
}

func createNetworkLayerIPv6(srcIP, dstIP net.IP, transportLayer gopacket.TransportLayer) (*layers.IPv6, error) {
	if srcIP.To4() != nil || dstIP.To4() != nil {
		return nil, fmt.Errorf("create network layer: %w", fmt.Errorf("invalid ipv6 address %s", srcIP))
	}
	return nil, fmt.Errorf("create network layer: %w", errors.New("ipv6 not support"))
}

func createLinkLayerLoopback() *layers.Loopback {
	return &layers.Loopback{}
}

func createLinkLayerEthernet(srcMAC, dstMAC net.HardwareAddr, networkLayer gopacket.NetworkLayer) (*layers.Ethernet, error) {
	ethernetLayer := &layers.Ethernet{
		SrcMAC: srcMAC,
		DstMAC: dstMAC,
		// EthernetType: 0,
	}

	// Protocol
	networkLayerType := networkLayer.LayerType()
	switch networkLayerType {
	case layers.LayerTypeIPv4:
		ethernetLayer.EthernetType = layers.EthernetTypeIPv4
	case layers.LayerTypeIPv6:
		ethernetLayer.EthernetType = layers.EthernetTypeIPv6
	default:
		return nil, fmt.Errorf("create link layer: %w", fmt.Errorf("type %s not support", networkLayerType))
	}

	return ethernetLayer, nil
}

func serialize(layers ...gopacket.SerializableLayer) ([]byte, error) {
	// Recalculate checksum and length
	options := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	buffer := gopacket.NewSerializeBuffer()

	err := gopacket.SerializeLayers(buffer, options, layers...)
	if err != nil {
		return nil, fmt.Errorf("serialize: %w", err)
	}

	return buffer.Bytes(), nil
}

func serializeRaw(layers ...gopacket.SerializableLayer) ([]byte, error) {
	// Recalculate checksum and length
	options := gopacket.SerializeOptions{}
	buffer := gopacket.NewSerializeBuffer()

	err := gopacket.SerializeLayers(buffer, options, layers...)
	if err != nil {
		return nil, fmt.Errorf("serialize: %w", err)
	}

	return buffer.Bytes(), nil
}

type icmpv4Indicator struct {
	Type               uint8
	Code               uint8
	Id                 uint16
	Seq                uint16
	Contents           []byte
	IPv4Layer          *layers.IPv4
	SrcIP              net.IP
	DstIP              net.IP
	TransportLayer     gopacket.Layer
	TransportLayerType gopacket.LayerType
	SrcPort            uint16
	DstPort            uint16
}

func parseICMPv4Layer(layer *layers.ICMPv4) (*icmpv4Indicator, error) {
	var (
		t                  uint8
		code               uint8
		id                 uint16
		seq                uint16
		contents           []byte
		ipv4Layer          *layers.IPv4
		srcIP              net.IP
		dstIP              net.IP
		transportLayer     gopacket.Layer
		transportLayerType gopacket.LayerType
		srcPort            uint16
		dstPort            uint16
	)

	// Type and code
	t = layer.TypeCode.Type()
	code = layer.TypeCode.Code()
	id = layer.Id
	seq = layer.Seq
	contents = layer.Contents

	switch t {
	case layers.ICMPv4TypeEchoReply:
	case layers.ICMPv4TypeEchoRequest:
	case layers.ICMPv4TypeRouterAdvertisement:
	case layers.ICMPv4TypeRouterSolicitation:
	case layers.ICMPv4TypeTimestampRequest:
	case layers.ICMPv4TypeTimestampReply:
	case layers.ICMPv4TypeInfoRequest:
	case layers.ICMPv4TypeInfoReply:
	case layers.ICMPv4TypeAddressMaskRequest:
	case layers.ICMPv4TypeAddressMaskReply:
		break
	case layers.ICMPv4TypeDestinationUnreachable:
	case layers.ICMPv4TypeSourceQuench:
	case layers.ICMPv4TypeRedirect:
	case layers.ICMPv4TypeTimeExceeded:
	case layers.ICMPv4TypeParameterProblem:
		// Parse IPv4 header and 8 bytes content
		packet := gopacket.NewPacket(contents, layers.LayerTypeIPv4, gopacket.Default)
		if len(packet.Layers()) <= 0 {
			return nil, fmt.Errorf("parse icmp v4 layer: %w", errors.New("missing network layer"))
		}
		if len(packet.Layers()) <= 1 {
			return nil, fmt.Errorf("parse icmp v4 layer: %w", errors.New("missing transport layer"))
		}

		networkLayer := packet.Layers()[0]
		if networkLayer.LayerType() != layers.LayerTypeIPv4 {
			return nil, fmt.Errorf("parse icmp v4 layer: %w", errors.New("network layer type not support"))
		}

		ipv4Layer = networkLayer.(*layers.IPv4)
		version := ipv4Layer.Version
		if version != 4 {
			return nil, fmt.Errorf("parse icmp v4 layer: %w", fmt.Errorf("ip version %d not support", version))
		}

		srcIP = ipv4Layer.SrcIP
		dstIP = ipv4Layer.DstIP

		transportLayer = packet.Layers()[1]
		transportLayerType = transportLayer.LayerType()

		transportLayerContents := transportLayer.LayerContents()
		if len(transportLayerContents) < 4 {
			return nil, fmt.Errorf("parse icmp v4 layer: %w", fmt.Errorf("transport layer too short (%d Bytes)", len(transportLayerContents)))
		}

		// Regard the first 2 bytes as source port
		srcPort = binary.BigEndian.Uint16(transportLayerContents[:2])
		// Regard the next 2 bytes as destination port
		dstPort = binary.BigEndian.Uint16(transportLayerContents[2:4])
	default:
		return nil, fmt.Errorf("parse icmp v4 layer: %w", fmt.Errorf("invalid type %d", t))
	}

	return &icmpv4Indicator{
		Type:               t,
		Code:               code,
		Id:                 id,
		Seq:                seq,
		Contents:           contents,
		IPv4Layer:          ipv4Layer,
		SrcIP:              srcIP,
		DstIP:              dstIP,
		TransportLayer:     transportLayer,
		TransportLayerType: transportLayerType,
		SrcPort:            srcPort,
		DstPort:            dstPort,
	}, nil
}

// Identifier returns available Id of the ICMPv4 layer
func (indicator *icmpv4Indicator) Identifier() (uint16, bool) {
	switch indicator.Type {
	case layers.ICMPv4TypeEchoReply:
	case layers.ICMPv4TypeEchoRequest:
	case layers.ICMPv4TypeRouterAdvertisement:
	case layers.ICMPv4TypeRouterSolicitation:
	case layers.ICMPv4TypeTimestampRequest:
	case layers.ICMPv4TypeTimestampReply:
	case layers.ICMPv4TypeInfoRequest:
	case layers.ICMPv4TypeInfoReply:
	case layers.ICMPv4TypeAddressMaskRequest:
	case layers.ICMPv4TypeAddressMaskReply:
		return indicator.Id, true
	case layers.ICMPv4TypeDestinationUnreachable:
	case layers.ICMPv4TypeSourceQuench:
	case layers.ICMPv4TypeRedirect:
	case layers.ICMPv4TypeTimeExceeded:
	case layers.ICMPv4TypeParameterProblem:
		return 0, false
	default:
		break
	}

	panic(fmt.Errorf("identifier: %w", fmt.Errorf("invalid type %d", indicator.Type)))
}

// SrcIPPort returns available source IP and port of the ICMPv4 layer
func (indicator *icmpv4Indicator) SrcIPPort() (*IPPort, bool) {
	switch indicator.Type {
	case layers.ICMPv4TypeEchoReply:
	case layers.ICMPv4TypeEchoRequest:
	case layers.ICMPv4TypeRouterAdvertisement:
	case layers.ICMPv4TypeRouterSolicitation:
	case layers.ICMPv4TypeTimestampRequest:
	case layers.ICMPv4TypeTimestampReply:
	case layers.ICMPv4TypeInfoRequest:
	case layers.ICMPv4TypeInfoReply:
	case layers.ICMPv4TypeAddressMaskRequest:
	case layers.ICMPv4TypeAddressMaskReply:
		return nil, false
	case layers.ICMPv4TypeDestinationUnreachable:
	case layers.ICMPv4TypeSourceQuench:
	case layers.ICMPv4TypeRedirect:
	case layers.ICMPv4TypeTimeExceeded:
	case layers.ICMPv4TypeParameterProblem:
		return &IPPort{
			IP:   indicator.SrcIP,
			Port: indicator.SrcPort,
		}, true
	default:
		break
	}

	panic(fmt.Errorf("src ip port: %w", fmt.Errorf("invalid type %d", indicator.Type)))
}

// DstIPPort returns the available destination IP and port of the ICMPv4 layer
func (indicator *icmpv4Indicator) DstIPPort() (*IPPort, bool) {
	switch indicator.Type {
	case layers.ICMPv4TypeEchoReply:
	case layers.ICMPv4TypeEchoRequest:
	case layers.ICMPv4TypeRouterAdvertisement:
	case layers.ICMPv4TypeRouterSolicitation:
	case layers.ICMPv4TypeTimestampRequest:
	case layers.ICMPv4TypeTimestampReply:
	case layers.ICMPv4TypeInfoRequest:
	case layers.ICMPv4TypeInfoReply:
	case layers.ICMPv4TypeAddressMaskRequest:
	case layers.ICMPv4TypeAddressMaskReply:
		return nil, false
	case layers.ICMPv4TypeDestinationUnreachable:
	case layers.ICMPv4TypeSourceQuench:
	case layers.ICMPv4TypeRedirect:
	case layers.ICMPv4TypeTimeExceeded:
	case layers.ICMPv4TypeParameterProblem:
		return &IPPort{
			IP:   indicator.DstIP,
			Port: indicator.DstPort,
		}, true
	default:
		break
	}

	panic(fmt.Errorf("dst ip port: %w", fmt.Errorf("invalid type %d", indicator.Type)))
}
