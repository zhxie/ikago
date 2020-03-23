package pcap

import (
	"errors"
	"fmt"
	"ikago/internal/addr"
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
		// Checksum: 0,
	}
}

func createTransportLayerUDP(srcPort, dstPort uint16) *layers.UDP {
	return &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
		// Length:   0,
		// Checksum: 0,
	}
}

func createNetworkLayerIPv4(srcIP, dstIP net.IP, id uint16, ttl uint8, transportLayer gopacket.TransportLayer) (*layers.IPv4, error) {
	if srcIP.To4() == nil {
		return nil, fmt.Errorf("invalid source ip %s", srcIP)
	}
	if dstIP.To4() == nil {
		return nil, fmt.Errorf("invalid destination ip %s", dstIP)
	}

	ipv4Layer := &layers.IPv4{
		Version: 4,
		IHL:     5,
		// Length: 0,
		Id:    id,
		Flags: layers.IPv4DontFragment,
		TTL:   ttl,
		// Protocol: 0,
		// Checksum: 0,
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
			return nil, fmt.Errorf("set network layer for checksum: %w", err)
		}
	case layers.LayerTypeUDP:
		ipv4Layer.Protocol = layers.IPProtocolUDP

		// Checksum of transport layer
		udpLayer := transportLayer.(*layers.UDP)
		err := udpLayer.SetNetworkLayerForChecksum(ipv4Layer)
		if err != nil {
			return nil, fmt.Errorf("set network layer for checksum: %w", err)
		}
	default:
		return nil, fmt.Errorf("transport layer type %s not support", transportLayerType)
	}

	return ipv4Layer, nil
}

func createNetworkLayerIPv6(srcIP, dstIP net.IP, hopLimit uint8, transportLayer gopacket.TransportLayer) (*layers.IPv6, error) {
	if srcIP.To4() != nil {
		return nil, fmt.Errorf("invalid source ip %s", srcIP)
	}
	if dstIP.To4() != nil {
		return nil, fmt.Errorf("invalid destination ip %s", dstIP)
	}

	ipv6Layer := &layers.IPv6{
		Version: 6,
		// Length: 0,
		HopLimit: hopLimit,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}

	// Protocol
	transportLayerType := transportLayer.LayerType()
	switch transportLayerType {
	case layers.LayerTypeTCP:
		ipv6Layer.NextHeader = layers.IPProtocolTCP
	case layers.LayerTypeUDP:
		ipv6Layer.NextHeader = layers.IPProtocolUDP
	case layers.LayerTypeICMPv4:
		ipv6Layer.NextHeader = layers.IPProtocolICMPv4
	default:
		return nil, fmt.Errorf("transport layer type %s not support", transportLayerType)
	}

	return ipv6Layer, nil
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
		return nil, fmt.Errorf("network layer type %s not support", networkLayerType)
	}

	return ethernetLayer, nil
}

func serialize(layers ...gopacket.SerializableLayer) ([]byte, error) {
	// Recalculate checksum and length
	options := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	buffer := gopacket.NewSerializeBuffer()

	err := gopacket.SerializeLayers(buffer, options, layers...)
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func serializeRaw(layers ...gopacket.SerializableLayer) ([]byte, error) {
	// Recalculate checksum and length
	options := gopacket.SerializeOptions{}
	buffer := gopacket.NewSerializeBuffer()

	err := gopacket.SerializeLayers(buffer, options, layers...)
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func wrap(srcPort, dstPort uint16, seq, ack uint32, conn *Conn, dstIP net.IP, id uint16, ttl uint8) (transportLayer, networkLayer, linkLayer gopacket.SerializableLayer, err error) {
	var (
		networkLayerType gopacket.LayerType
		linkLayerType    gopacket.LayerType
	)

	// Create transport layer
	transportLayer = createTransportLayerTCP(srcPort, dstPort, seq, ack)

	// Decide IPv4 or IPv6
	if dstIP.To4() != nil {
		networkLayerType = layers.LayerTypeIPv4
	} else {
		networkLayerType = layers.LayerTypeIPv6
	}

	// Create new network layer
	switch networkLayerType {
	case layers.LayerTypeIPv4:
		networkLayer, err = createNetworkLayerIPv4(conn.LocalAddr().(*addr.MultiIPAddr).IPv4(), dstIP, id, ttl-1, transportLayer.(gopacket.TransportLayer))
	case layers.LayerTypeIPv6:
		networkLayer, err = createNetworkLayerIPv6(conn.LocalAddr().(*addr.MultiIPAddr).IPv6(), dstIP, ttl-1, transportLayer.(gopacket.TransportLayer))
	default:
		return nil, nil, nil, fmt.Errorf("create network layer: %w", fmt.Errorf("network layer type %s not support", networkLayerType))
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create network layer: %w", err)
	}

	// Decide Loopback or Ethernet
	if conn.IsLoop() {
		linkLayerType = layers.LayerTypeLoopback
	} else {
		linkLayerType = layers.LayerTypeEthernet
	}

	// Create new link layer
	switch linkLayerType {
	case layers.LayerTypeLoopback:
		linkLayer = createLinkLayerLoopback()
	case layers.LayerTypeEthernet:
		linkLayer, err = createLinkLayerEthernet(conn.SrcDev.HardwareAddr, conn.DstDev.HardwareAddr, networkLayer.(gopacket.NetworkLayer))
	default:
		return nil, nil, nil, fmt.Errorf("create link layer: %w", fmt.Errorf("link layer type %s not support", linkLayerType))
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create link layer: %w", err)
	}

	return transportLayer, networkLayer, linkLayer, nil
}

type icmpv4Indicator struct {
	layer                 *layers.ICMPv4
	embIPv4Layer          *layers.IPv4
	embTransportLayer     gopacket.Layer
	embTransportLayerType gopacket.LayerType
}

func parseICMPv4Layer(layer *layers.ICMPv4) (*icmpv4Indicator, error) {
	var (
		embIPv4Layer          *layers.IPv4
		embTransportLayer     gopacket.Layer
		embTransportLayerType gopacket.LayerType
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
			return nil, errors.New("missing network layer")
		}
		if len(packet.Layers()) <= 1 {
			return nil, errors.New("missing transport layer")
		}

		networkLayer := packet.Layers()[0]
		networkLayerType := networkLayer.LayerType()
		if networkLayerType != layers.LayerTypeIPv4 {
			return nil, fmt.Errorf("parse network layer: %w", fmt.Errorf("type %s not support", networkLayerType))
		}

		embIPv4Layer = networkLayer.(*layers.IPv4)
		if embIPv4Layer.Version != 4 {
			return nil, fmt.Errorf("parse network layer: %w", fmt.Errorf("ip version %d not support", embIPv4Layer.Version))
		}

		embTransportLayer = packet.Layers()[1]
		embTransportLayerType = embTransportLayer.LayerType()
	default:
		return nil, fmt.Errorf("icmpv4 type %d not support", t)
	}

	return &icmpv4Indicator{
		layer:                 layer,
		embIPv4Layer:          embIPv4Layer,
		embTransportLayer:     embTransportLayer,
		embTransportLayerType: embTransportLayerType,
	}, nil
}

func (indicator *icmpv4Indicator) newPureICMPv4Layer() *layers.ICMPv4 {
	return &layers.ICMPv4{
		TypeCode: indicator.layer.TypeCode,
		Id:       indicator.layer.Id,
		Seq:      indicator.layer.Seq,
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
		panic(fmt.Errorf("icmpv4 type %d not support", t))
	}
}

func (indicator *icmpv4Indicator) embSrcIP() net.IP {
	return indicator.embIPv4Layer.SrcIP
}

func (indicator *icmpv4Indicator) embDstIP() net.IP {
	return indicator.embIPv4Layer.DstIP
}

func (indicator *icmpv4Indicator) embTCPLayer() *layers.TCP {
	if indicator.embTransportLayerType == layers.LayerTypeTCP {
		return indicator.embTransportLayer.(*layers.TCP)
	}

	return nil
}

func (indicator *icmpv4Indicator) embUDPLayer() *layers.UDP {
	if indicator.embTransportLayerType == layers.LayerTypeUDP {
		return indicator.embTransportLayer.(*layers.UDP)
	}

	return nil
}

func (indicator *icmpv4Indicator) embICMPv4Layer() *layers.ICMPv4 {
	if indicator.embTransportLayerType == layers.LayerTypeICMPv4 {
		return indicator.embTransportLayer.(*layers.ICMPv4)
	}

	return nil
}

func (indicator *icmpv4Indicator) id() uint16 {
	return indicator.layer.Id
}

func (indicator *icmpv4Indicator) embId() uint16 {
	switch indicator.embTransportLayerType {
	case layers.LayerTypeICMPv4:
		return uint16(indicator.embICMPv4Layer().Id)
	default:
		panic(fmt.Errorf("transport layer type %s not support", indicator.embTransportLayerType))
	}
}

func (indicator *icmpv4Indicator) embSrcPort() uint16 {
	switch indicator.embTransportLayerType {
	case layers.LayerTypeTCP:
		return uint16(indicator.embTCPLayer().SrcPort)
	case layers.LayerTypeUDP:
		return uint16(indicator.embUDPLayer().SrcPort)
	default:
		panic(fmt.Errorf("transport layer type %s not support", indicator.embTransportLayerType))
	}
}

func (indicator *icmpv4Indicator) embDstPort() uint16 {
	switch indicator.embTransportLayerType {
	case layers.LayerTypeTCP:
		return uint16(indicator.embTCPLayer().DstPort)
	case layers.LayerTypeUDP:
		return uint16(indicator.embUDPLayer().DstPort)
	default:
		panic(fmt.Errorf("transport layer type %s not support", indicator.embTransportLayerType))
	}
}

func (indicator *icmpv4Indicator) isEmbQuery() bool {
	t := indicator.embICMPv4Layer().TypeCode.Type()
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
		panic(fmt.Errorf("icmpv4 type %d not support", t))
	}
}

func (indicator *icmpv4Indicator) natSrc() net.Addr {
	if indicator.isQuery() {
		panic(errors.New("icmpv4 query not support"))
	} else {
		// Flip source and destination
		switch indicator.embTransportLayerType {
		case layers.LayerTypeTCP:
			return &net.TCPAddr{
				IP:   indicator.embDstIP(),
				Port: int(indicator.embDstPort()),
			}
		case layers.LayerTypeUDP:
			return &net.UDPAddr{
				IP:   indicator.embDstIP(),
				Port: int(indicator.embDstPort()),
			}
		case layers.LayerTypeICMPv4:
			if indicator.isEmbQuery() {
				return &addr.ICMPQueryAddr{
					IP: indicator.embDstIP(),
					Id: indicator.embId(),
				}
			} else {
				return &net.IPAddr{
					IP: indicator.embDstIP(),
				}
			}
		default:
			panic(fmt.Errorf("transport layer type %s not support", indicator.embTransportLayerType))
		}
	}
}

func (indicator *icmpv4Indicator) natDst() net.Addr {
	if indicator.isQuery() {
		panic(errors.New("icmpv4 query not support"))
	} else {
		// Flip source and destination
		switch indicator.embTransportLayerType {
		case layers.LayerTypeTCP:
			return &net.TCPAddr{
				IP:   indicator.embSrcIP(),
				Port: int(indicator.embSrcPort()),
			}
		case layers.LayerTypeUDP:
			return &net.UDPAddr{
				IP:   indicator.embSrcIP(),
				Port: int(indicator.embSrcPort()),
			}
		case layers.LayerTypeICMPv4:
			if indicator.isEmbQuery() {
				return &addr.ICMPQueryAddr{
					IP: indicator.embSrcIP(),
					Id: indicator.embId(),
				}
			} else {
				return &net.IPAddr{
					IP: indicator.embSrcIP(),
				}
			}
		default:
			panic(fmt.Errorf("transport layer type %s not support", indicator.embTransportLayerType))
		}
	}
}
