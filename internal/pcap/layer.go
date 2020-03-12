package pcap

import (
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
	Layer                      *layers.ICMPv4
	EncappedIPv4Layer          *layers.IPv4
	EncappedTransportLayer     gopacket.Layer
	EncappedTransportLayerType gopacket.LayerType
}

func parseICMPv4Layer(layer *layers.ICMPv4) (*icmpv4Indicator, error) {
	var (
		encappedIPv4Layer          *layers.IPv4
		encappedTransportLayer     gopacket.Layer
		encappedTransportLayerType gopacket.LayerType
	)

	t := layer.TypeCode.Type()
	switch t {
	case layers.ICMPv4TypeEchoReply,
		layers.ICMPv4TypeEchoRequest,
		layers.ICMPv4TypeRouterAdvertisement,
		layers.ICMPv4TypeRouterSolicitation,
		layers.ICMPv4TypeTimestampRequest,
		layers.ICMPv4TypeTimestampReply,
		layers.ICMPv4TypeInfoRequest,
		layers.ICMPv4TypeInfoReply,
		layers.ICMPv4TypeAddressMaskRequest,
		layers.ICMPv4TypeAddressMaskReply:
		break
	case layers.ICMPv4TypeDestinationUnreachable,
		layers.ICMPv4TypeSourceQuench,
		layers.ICMPv4TypeRedirect,
		layers.ICMPv4TypeTimeExceeded,
		layers.ICMPv4TypeParameterProblem:
		// Parse IPv4 header and 8 bytes content
		packet := gopacket.NewPacket(layer.Payload, layers.LayerTypeIPv4, gopacket.Default)
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

		encappedIPv4Layer = networkLayer.(*layers.IPv4)
		version := encappedIPv4Layer.Version
		if version != 4 {
			return nil, fmt.Errorf("parse icmp v4 layer: %w", fmt.Errorf("ip version %d not support", version))
		}

		encappedTransportLayer = packet.Layers()[1]
		encappedTransportLayerType = encappedTransportLayer.LayerType()
	default:
		return nil, fmt.Errorf("parse icmp v4 layer: %w", fmt.Errorf("type %d not support", t))
	}

	return &icmpv4Indicator{
		Layer:                      layer,
		EncappedIPv4Layer:          encappedIPv4Layer,
		EncappedTransportLayer:     encappedTransportLayer,
		EncappedTransportLayerType: encappedTransportLayerType,
	}, nil
}

// IsQuery returns if the ICMPv4 message is either a query or an error
func (indicator *icmpv4Indicator) IsQuery() bool {
	t := indicator.Layer.TypeCode.Type()
	switch t {
	case layers.ICMPv4TypeEchoReply,
		layers.ICMPv4TypeEchoRequest,
		layers.ICMPv4TypeRouterAdvertisement,
		layers.ICMPv4TypeRouterSolicitation,
		layers.ICMPv4TypeTimestampRequest,
		layers.ICMPv4TypeTimestampReply,
		layers.ICMPv4TypeInfoRequest,
		layers.ICMPv4TypeInfoReply,
		layers.ICMPv4TypeAddressMaskRequest,
		layers.ICMPv4TypeAddressMaskReply:
		return true
	case layers.ICMPv4TypeDestinationUnreachable,
		layers.ICMPv4TypeSourceQuench,
		layers.ICMPv4TypeRedirect,
		layers.ICMPv4TypeTimeExceeded,
		layers.ICMPv4TypeParameterProblem:
		return false
	default:
		panic(fmt.Errorf("is query: %w", fmt.Errorf("type %d not support", t)))
	}
}

// EncappedSrcIP returns the encapped source IP of the ICMPv4 layer
func (indicator *icmpv4Indicator) EncappedSrcIP() net.IP {
	return indicator.EncappedIPv4Layer.SrcIP
}

// EncappedDstIP returns the encapped destination IP of the ICMPv4 layer
func (indicator *icmpv4Indicator) EncappedDstIP() net.IP {
	return indicator.EncappedIPv4Layer.DstIP
}

// EncappedTCPLayer returns the encapped TCP layer of the ICMPv4 layer
func (indicator *icmpv4Indicator) EncappedTCPLayer() *layers.TCP {
	if indicator.EncappedTransportLayerType == layers.LayerTypeTCP {
		return indicator.EncappedTransportLayer.(*layers.TCP)
	}

	return nil
}

// EncappedUDPLayer returns the encapped UDP layer of the ICMPv4 layer
func (indicator *icmpv4Indicator) EncappedUDPLayer() *layers.UDP {
	if indicator.EncappedTransportLayerType == layers.LayerTypeUDP {
		return indicator.EncappedTransportLayer.(*layers.UDP)
	}

	return nil
}

// EncappedICMPv4Layer returns the encapped ICMPv4 layer of the ICMPv4 layer
func (indicator *icmpv4Indicator) EncappedICMPv4Layer() *layers.ICMPv4 {
	if indicator.EncappedTransportLayerType == layers.LayerTypeICMPv4 {
		return indicator.EncappedTransportLayer.(*layers.ICMPv4)
	}

	return nil
}

// Id returns available Id of the ICMPv4 layer
func (indicator *icmpv4Indicator) Id() uint16 {
	return indicator.Layer.Id
}

// EncappedId returns the encapped Id of ICMPv4 layer of the ICMPv4 layer
func (indicator *icmpv4Indicator) EncappedId() uint16 {
	switch indicator.EncappedTransportLayerType {
	case layers.LayerTypeICMPv4:
		return uint16(indicator.EncappedICMPv4Layer().Id)
	default:
		panic(fmt.Errorf("encapped id: %w", fmt.Errorf("type %s not support", indicator.EncappedTransportLayerType)))
	}
}

// EncappedSrcPort returns the encapped source port of the ICMPv4 layer
func (indicator *icmpv4Indicator) EncappedSrcPort() uint16 {
	switch indicator.EncappedTransportLayerType {
	case layers.LayerTypeTCP:
		return uint16(indicator.EncappedTCPLayer().SrcPort)
	case layers.LayerTypeUDP:
		return uint16(indicator.EncappedUDPLayer().SrcPort)
	default:
		panic(fmt.Errorf("encapped src port: %w", fmt.Errorf("type %s not support", indicator.EncappedTransportLayerType)))
	}
}

// EncappedDstPort returns the encapped destination port of the ICMPv4 layer
func (indicator *icmpv4Indicator) EncappedDstPort() uint16 {
	switch indicator.EncappedTransportLayerType {
	case layers.LayerTypeTCP:
		return uint16(indicator.EncappedTCPLayer().DstPort)
	case layers.LayerTypeUDP:
		return uint16(indicator.EncappedUDPLayer().DstPort)
	default:
		panic(fmt.Errorf("encapped dst port: %w", fmt.Errorf("type %s not support", indicator.EncappedTransportLayerType)))
	}
}

// IsEncappedQuery returns if the encapped ICMPv4 message is either a query or an error
func (indicator *icmpv4Indicator) IsEncappedQuery() bool {
	t := indicator.EncappedICMPv4Layer().TypeCode.Type()
	switch t {
	case layers.ICMPv4TypeEchoReply,
		layers.ICMPv4TypeEchoRequest,
		layers.ICMPv4TypeRouterAdvertisement,
		layers.ICMPv4TypeRouterSolicitation,
		layers.ICMPv4TypeTimestampRequest,
		layers.ICMPv4TypeTimestampReply,
		layers.ICMPv4TypeInfoRequest,
		layers.ICMPv4TypeInfoReply,
		layers.ICMPv4TypeAddressMaskRequest,
		layers.ICMPv4TypeAddressMaskReply:
		return true
	case layers.ICMPv4TypeDestinationUnreachable,
		layers.ICMPv4TypeSourceQuench,
		layers.ICMPv4TypeRedirect,
		layers.ICMPv4TypeTimeExceeded,
		layers.ICMPv4TypeParameterProblem:
		return false
	default:
		panic(fmt.Errorf("is encapped query: %w", fmt.Errorf("type %d not support", t)))
	}
}

// Source returns the source of the packet
func (indicator *icmpv4Indicator) Source() string {
	if indicator.IsQuery() {
		return fmt.Sprintf("%d", indicator.Id())
	} else {
		t := indicator.EncappedTransportLayerType
		switch t {
		case layers.LayerTypeTCP, layers.LayerTypeUDP:
			return IPPort{
				IP:   indicator.EncappedSrcIP(),
				Port: indicator.EncappedSrcPort(),
			}.String()
		case layers.LayerTypeICMPv4:
			if indicator.IsEncappedQuery() {
				return IPId{
					IP: indicator.EncappedSrcIP(),
					Id: indicator.EncappedId(),
				}.String()
			} else {
				return formatIP(indicator.EncappedSrcIP())
			}
		default:
			panic(fmt.Errorf("source: %w", fmt.Errorf("type %s not support", t)))
		}
	}
}

// Destination returns the destination of the packet
func (indicator *icmpv4Indicator) Destination() string {
	if indicator.IsQuery() {
		return fmt.Sprintf("%d", indicator.Id())
	} else {
		t := indicator.EncappedTransportLayerType
		switch t {
		case layers.LayerTypeTCP, layers.LayerTypeUDP:
			return IPPort{
				IP:   indicator.EncappedDstIP(),
				Port: indicator.EncappedDstPort(),
			}.String()
		case layers.LayerTypeICMPv4:
			if indicator.IsEncappedQuery() {
				return IPId{
					IP: indicator.EncappedDstIP(),
					Id: indicator.EncappedId(),
				}.String()
			} else {
				return formatIP(indicator.EncappedDstIP())
			}
		default:
			panic(fmt.Errorf("destination: %w", fmt.Errorf("type %s not support", t)))
		}
	}
}
