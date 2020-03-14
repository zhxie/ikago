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
	layer                 *layers.ICMPv4
	encIPv4Layer          *layers.IPv4
	encTransportLayer     gopacket.Layer
	encTransportLayerType gopacket.LayerType
}

func parseICMPv4Layer(layer *layers.ICMPv4) (*icmpv4Indicator, error) {
	var (
		encIPv4Layer          *layers.IPv4
		encTransportLayer     gopacket.Layer
		encTransportLayerType gopacket.LayerType
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

		encIPv4Layer = networkLayer.(*layers.IPv4)
		if encIPv4Layer.Version != 4 {
			return nil, fmt.Errorf("parse icmp v4 layer: %w", fmt.Errorf("ip version %d not support", encIPv4Layer.Version))
		}

		encTransportLayer = packet.Layers()[1]
		encTransportLayerType = encTransportLayer.LayerType()
	default:
		return nil, fmt.Errorf("parse icmp v4 layer: %w", fmt.Errorf("type %d not support", t))
	}

	return &icmpv4Indicator{
		layer:                 layer,
		encIPv4Layer:          encIPv4Layer,
		encTransportLayer:     encTransportLayer,
		encTransportLayerType: encTransportLayerType,
	}, nil
}

func (indicator *icmpv4Indicator) newPureICMPv4Layer() *layers.ICMPv4 {
	return &layers.ICMPv4{
		TypeCode:  indicator.layer.TypeCode,
		Id:        indicator.layer.Id,
		Seq:       indicator.layer.Seq,
	}
}

func (indicator *icmpv4Indicator) isQuery() bool {
	t := indicator.layer.TypeCode.Type()
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

func (indicator *icmpv4Indicator) encSrcIP() net.IP {
	return indicator.encIPv4Layer.SrcIP
}

func (indicator *icmpv4Indicator) encDstIP() net.IP {
	return indicator.encIPv4Layer.DstIP
}

func (indicator *icmpv4Indicator) encTCPLayer() *layers.TCP {
	if indicator.encTransportLayerType == layers.LayerTypeTCP {
		return indicator.encTransportLayer.(*layers.TCP)
	}

	return nil
}

func (indicator *icmpv4Indicator) encUDPLayer() *layers.UDP {
	if indicator.encTransportLayerType == layers.LayerTypeUDP {
		return indicator.encTransportLayer.(*layers.UDP)
	}

	return nil
}

func (indicator *icmpv4Indicator) encICMPv4Layer() *layers.ICMPv4 {
	if indicator.encTransportLayerType == layers.LayerTypeICMPv4 {
		return indicator.encTransportLayer.(*layers.ICMPv4)
	}

	return nil
}

func (indicator *icmpv4Indicator) id() uint16 {
	return indicator.layer.Id
}

func (indicator *icmpv4Indicator) encId() uint16 {
	switch indicator.encTransportLayerType {
	case layers.LayerTypeICMPv4:
		return uint16(indicator.encICMPv4Layer().Id)
	default:
		panic(fmt.Errorf("enc id: %w", fmt.Errorf("type %s not support", indicator.encTransportLayerType)))
	}
}

func (indicator *icmpv4Indicator) encSrcPort() uint16 {
	switch indicator.encTransportLayerType {
	case layers.LayerTypeTCP:
		return uint16(indicator.encTCPLayer().SrcPort)
	case layers.LayerTypeUDP:
		return uint16(indicator.encUDPLayer().SrcPort)
	default:
		panic(fmt.Errorf("enc src port: %w", fmt.Errorf("type %s not support", indicator.encTransportLayerType)))
	}
}

func (indicator *icmpv4Indicator) encDstPort() uint16 {
	switch indicator.encTransportLayerType {
	case layers.LayerTypeTCP:
		return uint16(indicator.encTCPLayer().DstPort)
	case layers.LayerTypeUDP:
		return uint16(indicator.encUDPLayer().DstPort)
	default:
		panic(fmt.Errorf("enc dst port: %w", fmt.Errorf("type %s not support", indicator.encTransportLayerType)))
	}
}

func (indicator *icmpv4Indicator) isEncQuery() bool {
	t := indicator.encICMPv4Layer().TypeCode.Type()
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
		panic(fmt.Errorf("is enc query: %w", fmt.Errorf("type %d not support", t)))
	}
}

func (indicator *icmpv4Indicator) natSrc() IPEndpoint {
	if indicator.isQuery() {
		panic(fmt.Errorf("src: %w", errors.New("icmpv4 query not support")))
	} else {
		// Flip source and destination
		switch indicator.encTransportLayerType {
		case layers.LayerTypeTCP, layers.LayerTypeUDP:
			return &IPPort{
				IP:   indicator.encDstIP(),
				Port: indicator.encDstPort(),
			}
		case layers.LayerTypeICMPv4:
			if indicator.isEncQuery() {
				return &IPId{
					IP: indicator.encDstIP(),
					Id: indicator.encId(),
				}
			} else {
				return &IP{
					IP: indicator.encDstIP(),
				}
			}
		default:
			panic(fmt.Errorf("src: %w", fmt.Errorf("type %s not support", indicator.encTransportLayerType)))
		}
	}
}

func (indicator *icmpv4Indicator) natDst() IPEndpoint {
	if indicator.isQuery() {
		panic(fmt.Errorf("dst: %w", errors.New("icmpv4 query not support")))
	} else {
		// Flip source and destination
		switch indicator.encTransportLayerType {
		case layers.LayerTypeTCP, layers.LayerTypeUDP:
			return &IPPort{
				IP:   indicator.encSrcIP(),
				Port: indicator.encSrcPort(),
			}
		case layers.LayerTypeICMPv4:
			if indicator.isEncQuery() {
				return &IPId{
					IP: indicator.encSrcIP(),
					Id: indicator.encId(),
				}
			} else {
				return &IP{
					IP: indicator.encSrcIP(),
				}
			}
		default:
			panic(fmt.Errorf("dst: %w", fmt.Errorf("type %s not support", indicator.encTransportLayerType)))
		}
	}
}
