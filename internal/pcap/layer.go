package pcap

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"ikago/internal/addr"
	"net"
)

// CreateTCPLayer returns a TCP layer.
func CreateTCPLayer(srcPort, dstPort uint16, seq, ack uint32) *layers.TCP {
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

// FlagTCPLayer reflags flags in a TCP layer.
func FlagTCPLayer(layer *layers.TCP, syn, psh, ack bool) {
	layer.SYN = syn
	layer.PSH = psh
	layer.ACK = ack
}

// CreateUDPLayer returns an UDP layer.
func CreateUDPLayer(srcPort, dstPort uint16) *layers.UDP {
	return &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
		// Length:   0,
		// Checksum: 0,
	}
}

// CreateIPv4Layer returns an IPv4 layer.
func CreateIPv4Layer(srcIP, dstIP net.IP, id uint16, ttl uint8, transportLayer gopacket.TransportLayer) (*layers.IPv4, error) {
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
	switch t := transportLayer.LayerType(); t {
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
		return nil, fmt.Errorf("transport layer type %s not support", t)
	}

	return ipv4Layer, nil
}

// FlagIPv4Layer reflags flags in an IPv4 layer.
func FlagIPv4Layer(layer *layers.IPv4, df, mf bool, offset uint16) {
	if df {
		layer.Flags = layers.IPv4DontFragment
	}
	if mf {
		layer.Flags = layers.IPv4MoreFragments
	}
	if !df && !mf {
		layer.Flags = 0
	}

	layer.FragOffset = offset
}

// CreateIPv6Layer returns an IPv6 layer.
func CreateIPv6Layer(srcIP, dstIP net.IP, hopLimit uint8, transportLayer gopacket.TransportLayer) (*layers.IPv6, error) {
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
	switch t := transportLayer.LayerType(); t {
	case layers.LayerTypeTCP:
		ipv6Layer.NextHeader = layers.IPProtocolTCP
	case layers.LayerTypeUDP:
		ipv6Layer.NextHeader = layers.IPProtocolUDP
	case layers.LayerTypeICMPv4:
		ipv6Layer.NextHeader = layers.IPProtocolICMPv4
	default:
		return nil, fmt.Errorf("transport layer type %s not support", t)
	}

	return ipv6Layer, nil
}

// CreateLoopbackLayer returns a loopback layer.
func CreateLoopbackLayer() *layers.Loopback {
	return &layers.Loopback{}
}

// CreateEthernetLayer returns an Ethernet layer.
func CreateEthernetLayer(srcMAC, dstMAC net.HardwareAddr, networkLayer gopacket.NetworkLayer) (*layers.Ethernet, error) {
	ethernetLayer := &layers.Ethernet{
		SrcMAC: srcMAC,
		DstMAC: dstMAC,
		// EthernetType: 0,
	}

	// Protocol
	switch t := networkLayer.LayerType(); t {
	case layers.LayerTypeIPv4:
		ethernetLayer.EthernetType = layers.EthernetTypeIPv4
	case layers.LayerTypeIPv6:
		ethernetLayer.EthernetType = layers.EthernetTypeIPv6
	default:
		return nil, fmt.Errorf("network layer type %s not support", t)
	}

	return ethernetLayer, nil
}

// Serialize serializes layers to byte array.
func Serialize(layers ...gopacket.SerializableLayer) ([]byte, error) {
	// Recalculate checksum and length
	options := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	buffer := gopacket.NewSerializeBuffer()

	err := gopacket.SerializeLayers(buffer, options, layers...)
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

// SerializeRaw serializes layers to byte array without computing checksums and updating lengths.
func SerializeRaw(layers ...gopacket.SerializableLayer) ([]byte, error) {
	// Recalculate checksum and length
	options := gopacket.SerializeOptions{}
	buffer := gopacket.NewSerializeBuffer()

	err := gopacket.SerializeLayers(buffer, options, layers...)
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

// CreateLayers return layers of transferring between client and server.
func CreateLayers(srcPort, dstPort uint16, seq, ack uint32, conn *RawConn, dstIP net.IP, id uint16, hop uint8,
	dstHardwareAddr net.HardwareAddr) (transportLayer, networkLayer, linkLayer gopacket.SerializableLayer, err error) {
	var (
		networkLayerType gopacket.LayerType
		linkLayerType    gopacket.LayerType
	)

	// Create transport layer
	transportLayer = CreateTCPLayer(srcPort, dstPort, seq, ack)

	// Decide IPv4 or IPv6
	if dstIP.To4() != nil {
		networkLayerType = layers.LayerTypeIPv4
	} else {
		networkLayerType = layers.LayerTypeIPv6
	}

	// Create new network layer
	switch networkLayerType {
	case layers.LayerTypeIPv4:
		networkLayer, err = CreateIPv4Layer(conn.LocalDev().IPv4Addr().IP, dstIP, id, hop-1, transportLayer.(gopacket.TransportLayer))
	case layers.LayerTypeIPv6:
		networkLayer, err = CreateIPv6Layer(conn.LocalDev().IPv6Addr().IP, dstIP, hop-1, transportLayer.(gopacket.TransportLayer))
	default:
		return nil, nil, nil, fmt.Errorf("network layer type %s not support", networkLayerType)
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
		linkLayer = CreateLoopbackLayer()
	case layers.LayerTypeEthernet:
		linkLayer, err = CreateEthernetLayer(conn.LocalDev().HardwareAddr(), dstHardwareAddr, networkLayer.(gopacket.NetworkLayer))
	default:
		return nil, nil, nil, fmt.Errorf("link layer type %s not support", linkLayerType)
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create link layer: %w", err)
	}

	return transportLayer, networkLayer, linkLayer, nil
}

// ICMPv4Indicator indicates an ICMPv4 layer.
type ICMPv4Indicator struct {
	layer             *layers.ICMPv4
	embIPv4Layer      *layers.IPv4
	embTransportLayer gopacket.Layer
}

// ParseICMPv4Layer parses an ICMPv4 layer and returns an ICMPv4 indicator.
func ParseICMPv4Layer(layer *layers.ICMPv4) (*ICMPv4Indicator, error) {
	var (
		embIPv4Layer      *layers.IPv4
		embTransportLayer gopacket.Layer
	)

	switch t := layer.TypeCode.Type(); t {
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

		// Parse network layer
		networkLayer := packet.Layers()[0]
		if t := networkLayer.LayerType(); t != layers.LayerTypeIPv4 {
			return nil, fmt.Errorf("network layer type %s not support", t)
		}

		embIPv4Layer = networkLayer.(*layers.IPv4)
		if embIPv4Layer.Version != 4 {
			return nil, errors.New("network layer type not support")
		}

		_, err := parseIPProtocol(embIPv4Layer.Protocol)
		if err != nil {
			return nil, err
		}

		// Parse transport layer
		embTransportLayer = packet.Layers()[1]
	default:
		return nil, fmt.Errorf("icmpv4 type %d not support", t)
	}

	return &ICMPv4Indicator{
		layer:             layer,
		embIPv4Layer:      embIPv4Layer,
		embTransportLayer: embTransportLayer,
	}, nil
}

// NewPureICMPv4Layer returns an new ICMPv4 layer copied from the original ICMPv4 layer without any encapped layers.
func (indicator *ICMPv4Indicator) NewPureICMPv4Layer() *layers.ICMPv4 {
	return &layers.ICMPv4{
		TypeCode: indicator.layer.TypeCode,
		Id:       indicator.layer.Id,
		Seq:      indicator.layer.Seq,
	}
}

// ICMPv4Layer returns the ICMPv4 layer.
func (indicator *ICMPv4Indicator) ICMPv4Layer() *layers.ICMPv4 {
	return indicator.layer
}

// IsQuery returns if the ICMPv4 layer is a query.
func (indicator *ICMPv4Indicator) IsQuery() bool {
	switch t := indicator.layer.TypeCode.Type(); t {
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

// Id returns the ICMPv4 id.
func (indicator *ICMPv4Indicator) Id() uint16 {
	return indicator.layer.Id
}

// EmbIPv4Layer returns the embedded IPv4 layer.
func (indicator *ICMPv4Indicator) EmbIPv4Layer() *layers.IPv4 {
	return indicator.embIPv4Layer
}

// EmbSrcIP returns the embedded source IP.
func (indicator *ICMPv4Indicator) EmbSrcIP() net.IP {
	return indicator.embIPv4Layer.SrcIP
}

// EmbDstIP returns the embedded destination IP.
func (indicator *ICMPv4Indicator) EmbDstIP() net.IP {
	return indicator.embIPv4Layer.DstIP
}

// EmbTransportProtocol returns the protocol of the transport layer.
func (indicator *ICMPv4Indicator) EmbTransportProtocol() gopacket.LayerType {
	p, err := parseIPProtocol(indicator.EmbIPv4Layer().Protocol)
	if err != nil {
		panic(err)
	}

	return p
}

// EmbTransportLayer returns the embedded transport layer.
func (indicator *ICMPv4Indicator) EmbTransportLayer() gopacket.Layer {
	return indicator.embTransportLayer
}

// EmbTCPLayer returns the embedded TCP layer.
func (indicator *ICMPv4Indicator) EmbTCPLayer() *layers.TCP {
	if indicator.EmbTransportLayer().LayerType() == layers.LayerTypeTCP {
		return indicator.embTransportLayer.(*layers.TCP)
	}

	return nil
}

// EmbUDPLayer returns the embedded UDP layer.
func (indicator *ICMPv4Indicator) EmbUDPLayer() *layers.UDP {
	if indicator.EmbTransportLayer().LayerType() == layers.LayerTypeUDP {
		return indicator.embTransportLayer.(*layers.UDP)
	}

	return nil
}

// EmbICMPv4Layer returns the embedded ICMPv4 layer.
func (indicator *ICMPv4Indicator) EmbICMPv4Layer() *layers.ICMPv4 {
	if indicator.EmbTransportLayer().LayerType() == layers.LayerTypeICMPv4 {
		return indicator.embTransportLayer.(*layers.ICMPv4)
	}

	return nil
}

// EmbId returns the embedded ICMPv4 Id.
func (indicator *ICMPv4Indicator) EmbId() uint16 {
	switch t := indicator.EmbTransportLayer().LayerType(); t {
	case layers.LayerTypeICMPv4:
		return indicator.EmbICMPv4Layer().Id
	default:
		panic(fmt.Errorf("transport layer type %s not support", t))
	}
}

// EmbSrcPort returns the embedded source port.
func (indicator *ICMPv4Indicator) EmbSrcPort() uint16 {
	switch t := indicator.EmbTransportLayer().LayerType(); t {
	case layers.LayerTypeTCP:
		return uint16(indicator.EmbTCPLayer().SrcPort)
	case layers.LayerTypeUDP:
		return uint16(indicator.EmbUDPLayer().SrcPort)
	default:
		panic(fmt.Errorf("transport layer type %s not support", t))
	}
}

// EmbDstPort returns the embedded destination port.
func (indicator *ICMPv4Indicator) EmbDstPort() uint16 {
	switch t := indicator.EmbTransportLayer().LayerType(); t {
	case layers.LayerTypeTCP:
		return uint16(indicator.EmbTCPLayer().DstPort)
	case layers.LayerTypeUDP:
		return uint16(indicator.EmbUDPLayer().DstPort)
	default:
		panic(fmt.Errorf("transport layer type %s not support", t))
	}
}

// IsEmbQuery returns if the embedded ICMPv4 layer is a query.
func (indicator *ICMPv4Indicator) IsEmbQuery() bool {
	switch t := indicator.EmbICMPv4Layer().TypeCode.Type(); t {
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

// EmbSrc returns the embedded source.
func (indicator *ICMPv4Indicator) EmbSrc() net.Addr {
	if indicator.IsQuery() {
		panic(errors.New("icmpv4 query not support"))
	} else {
		// Flip source and destination
		switch t := indicator.EmbTransportLayer().LayerType(); t {
		case layers.LayerTypeTCP:
			return &net.TCPAddr{
				IP:   indicator.EmbDstIP(),
				Port: int(indicator.EmbDstPort()),
			}
		case layers.LayerTypeUDP:
			return &net.UDPAddr{
				IP:   indicator.EmbDstIP(),
				Port: int(indicator.EmbDstPort()),
			}
		case layers.LayerTypeICMPv4:
			if indicator.IsEmbQuery() {
				return &addr.ICMPQueryAddr{
					IP: indicator.EmbDstIP(),
					Id: indicator.EmbId(),
				}
			}

			return &net.IPAddr{
				IP: indicator.EmbDstIP(),
			}
		default:
			panic(fmt.Errorf("transport layer type %s not support", t))
		}
	}
}

// EmbDst returns the embedded destination.
func (indicator *ICMPv4Indicator) EmbDst() net.Addr {
	if indicator.IsQuery() {
		panic(errors.New("icmpv4 query not support"))
	} else {
		// Flip source and destination
		switch t := indicator.EmbTransportLayer().LayerType(); t {
		case layers.LayerTypeTCP:
			return &net.TCPAddr{
				IP:   indicator.EmbSrcIP(),
				Port: int(indicator.EmbSrcPort()),
			}
		case layers.LayerTypeUDP:
			return &net.UDPAddr{
				IP:   indicator.EmbSrcIP(),
				Port: int(indicator.EmbSrcPort()),
			}
		case layers.LayerTypeICMPv4:
			if indicator.IsEmbQuery() {
				return &addr.ICMPQueryAddr{
					IP: indicator.EmbSrcIP(),
					Id: indicator.EmbId(),
				}
			}

			return &net.IPAddr{
				IP: indicator.EmbSrcIP(),
			}
		default:
			panic(fmt.Errorf("transport layer type %s not support", t))
		}
	}
}
