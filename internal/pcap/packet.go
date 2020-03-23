package pcap

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"ikago/internal/addr"
	"net"
)

type connPacket struct {
	packet gopacket.Packet
	conn   *Conn
}

type quintuple struct {
	src   string
	dst   string
	proto gopacket.LayerType
}

type natGuide struct {
	src   string
	proto gopacket.LayerType
}

type natIndicator struct {
	src    net.Addr
	dst    net.Addr
	embSrc net.Addr
	conn   *Conn
}

func (indicator *natIndicator) EmbSrcIP() net.IP {
	switch t := indicator.embSrc.(type) {
	case *net.IPAddr:
		return indicator.embSrc.(*net.IPAddr).IP
	case *net.TCPAddr:
		return indicator.embSrc.(*net.TCPAddr).IP
	case *net.UDPAddr:
		return indicator.embSrc.(*net.UDPAddr).IP
	case *addr.ICMPQueryAddr:
		return indicator.embSrc.(*addr.ICMPQueryAddr).IP
	default:
		panic(fmt.Errorf("type %T not support", t))
	}
}

type packetIndicator struct {
	networkLayer       gopacket.NetworkLayer
	networkLayerType   gopacket.LayerType
	transportLayer     gopacket.Layer
	transportLayerType gopacket.LayerType
	icmpv4Indicator    *icmpv4Indicator
	applicationLayer   gopacket.ApplicationLayer
}

func (indicator *packetIndicator) ipv4Layer() *layers.IPv4 {
	if indicator.networkLayerType == layers.LayerTypeIPv4 {
		return indicator.networkLayer.(*layers.IPv4)
	}

	return nil
}

func (indicator *packetIndicator) ipv6Layer() *layers.IPv6 {
	if indicator.networkLayerType == layers.LayerTypeIPv6 {
		return indicator.networkLayer.(*layers.IPv6)
	}

	return nil
}

func (indicator *packetIndicator) tcpLayer() *layers.TCP {
	if indicator.transportLayerType == layers.LayerTypeTCP {
		return indicator.transportLayer.(*layers.TCP)
	}

	return nil
}

func (indicator *packetIndicator) udpLayer() *layers.UDP {
	if indicator.transportLayerType == layers.LayerTypeUDP {
		return indicator.transportLayer.(*layers.UDP)
	}

	return nil
}

func (indicator *packetIndicator) srcIP() net.IP {
	switch indicator.networkLayerType {
	case layers.LayerTypeIPv4:
		return indicator.ipv4Layer().SrcIP
	case layers.LayerTypeIPv6:
		return indicator.ipv6Layer().SrcIP
	default:
		panic(fmt.Errorf("network layer type %s not support", indicator.networkLayerType))
	}
}

func (indicator *packetIndicator) dstIP() net.IP {
	switch indicator.networkLayerType {
	case layers.LayerTypeIPv4:
		return indicator.ipv4Layer().DstIP
	case layers.LayerTypeIPv6:
		return indicator.ipv6Layer().DstIP
	default:
		panic(fmt.Errorf("network layer type %s not support", indicator.networkLayerType))
	}
}

func (indicator *packetIndicator) ttl() uint8 {
	switch indicator.networkLayerType {
	case layers.LayerTypeIPv4:
		return indicator.ipv4Layer().TTL
	case layers.LayerTypeIPv6:
		return indicator.ipv6Layer().HopLimit
	default:
		panic(fmt.Errorf("network layer type %s not support", indicator.networkLayerType))
	}
}

func (indicator *packetIndicator) srcPort() uint16 {
	switch indicator.transportLayerType {
	case layers.LayerTypeTCP:
		return uint16(indicator.tcpLayer().SrcPort)
	case layers.LayerTypeUDP:
		return uint16(indicator.udpLayer().SrcPort)
	default:
		panic(fmt.Errorf("transport layer type %s not support", indicator.transportLayerType))
	}
}

func (indicator *packetIndicator) dstPort() uint16 {
	switch indicator.transportLayerType {
	case layers.LayerTypeTCP:
		return uint16(indicator.tcpLayer().DstPort)
	case layers.LayerTypeUDP:
		return uint16(indicator.udpLayer().DstPort)
	default:
		panic(fmt.Errorf("transport layer type %s not support", indicator.transportLayerType))
	}
}

func (indicator *packetIndicator) natSrc() net.Addr {
	switch indicator.transportLayerType {
	case layers.LayerTypeTCP:
		return &net.TCPAddr{
			IP:   indicator.srcIP(),
			Port: int(indicator.srcPort()),
		}
	case layers.LayerTypeUDP:
		return &net.UDPAddr{
			IP:   indicator.srcIP(),
			Port: int(indicator.srcPort()),
		}
	case layers.LayerTypeICMPv4:
		if indicator.icmpv4Indicator.isQuery() {
			return &addr.ICMPQueryAddr{
				IP: indicator.srcIP(),
				Id: indicator.icmpv4Indicator.id(),
			}
		} else {
			return indicator.icmpv4Indicator.natSrc()
		}
	default:
		panic(fmt.Errorf("transport layer type %s not support", indicator.transportLayerType))
	}
}

func (indicator *packetIndicator) natDst() net.Addr {
	switch indicator.transportLayerType {
	case layers.LayerTypeTCP:
		return &net.TCPAddr{
			IP:   indicator.dstIP(),
			Port: int(indicator.dstPort()),
		}
	case layers.LayerTypeUDP:
		return &net.UDPAddr{
			IP:   indicator.dstIP(),
			Port: int(indicator.dstPort()),
		}
	case layers.LayerTypeICMPv4:
		if indicator.icmpv4Indicator.isQuery() {
			return &addr.ICMPQueryAddr{
				IP: indicator.dstIP(),
				Id: indicator.icmpv4Indicator.id(),
			}
		} else {
			return indicator.icmpv4Indicator.natDst()
		}
	default:
		panic(fmt.Errorf("transport layer type %s not support", indicator.transportLayerType))
	}
}

func (indicator *packetIndicator) natProto() gopacket.LayerType {
	switch indicator.transportLayerType {
	case layers.LayerTypeTCP, layers.LayerTypeUDP:
		return indicator.transportLayerType
	case layers.LayerTypeICMPv4:
		if indicator.icmpv4Indicator.isQuery() {
			return indicator.transportLayerType
		} else {
			return indicator.icmpv4Indicator.embTransportLayerType
		}
	default:
		panic(fmt.Errorf("transport layer type %s not support", indicator.transportLayerType))
	}
}

func (indicator *packetIndicator) src() net.Addr {
	switch indicator.transportLayerType {
	case layers.LayerTypeTCP:
		return &net.TCPAddr{
			IP:   indicator.srcIP(),
			Port: int(indicator.srcPort()),
		}
	case layers.LayerTypeUDP:
		return &net.UDPAddr{
			IP:   indicator.srcIP(),
			Port: int(indicator.srcPort()),
		}
	case layers.LayerTypeICMPv4:
		if indicator.icmpv4Indicator.isQuery() {
			return &addr.ICMPQueryAddr{
				IP: indicator.srcIP(),
				Id: indicator.icmpv4Indicator.id(),
			}
		} else {
			return &net.IPAddr{
				IP: indicator.srcIP(),
			}
		}
	default:
		panic(fmt.Errorf("transport layer type %s not support", indicator.transportLayerType))
	}
}

func (indicator *packetIndicator) dst() net.Addr {
	switch indicator.transportLayerType {
	case layers.LayerTypeTCP:
		return &net.TCPAddr{
			IP:   indicator.dstIP(),
			Port: int(indicator.dstPort()),
		}
	case layers.LayerTypeUDP:
		return &net.UDPAddr{
			IP:   indicator.dstIP(),
			Port: int(indicator.dstPort()),
		}
	case layers.LayerTypeICMPv4:
		if indicator.icmpv4Indicator.isQuery() {
			return &addr.ICMPQueryAddr{
				IP: indicator.dstIP(),
				Id: indicator.icmpv4Indicator.id(),
			}
		} else {
			return &net.IPAddr{
				IP: indicator.dstIP(),
			}
		}
	default:
		panic(fmt.Errorf("transport layer type %s not support", indicator.transportLayerType))
	}
}

func (indicator *packetIndicator) payload() []byte {
	if indicator.applicationLayer == nil {
		return nil
	}
	return indicator.applicationLayer.LayerContents()
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
		return nil, errors.New("missing network layer")
	}
	networkLayerType = networkLayer.LayerType()
	transportLayer = packet.TransportLayer()
	if transportLayer == nil {
		// Guess ICMPv4
		transportLayer = packet.Layer(layers.LayerTypeICMPv4)
		if transportLayer == nil {
			return nil, errors.New("missing transport layer")
		}
	}
	transportLayerType = transportLayer.LayerType()
	applicationLayer = packet.ApplicationLayer()

	// Parse network layer
	switch networkLayerType {
	case layers.LayerTypeIPv4, layers.LayerTypeIPv6:
		break
	default:
		return nil, fmt.Errorf("network layer type %s not support", networkLayerType)
	}

	// Parse transport layer
	switch transportLayerType {
	case layers.LayerTypeTCP, layers.LayerTypeUDP:
		break
	case layers.LayerTypeICMPv4:
		var err error
		icmpv4Indicator, err = parseICMPv4Layer(transportLayer.(*layers.ICMPv4))
		if err != nil {
			return nil, fmt.Errorf("parse icmpv4 layer: %w", err)
		}
	default:
		return nil, fmt.Errorf("transport layer type %s not support", transportLayerType)
	}

	return &packetIndicator{
		networkLayer:       networkLayer,
		networkLayerType:   networkLayerType,
		transportLayer:     transportLayer,
		transportLayerType: transportLayerType,
		icmpv4Indicator:    icmpv4Indicator,
		applicationLayer:   applicationLayer,
	}, nil
}

func parseEmbPacket(contents []byte) (*packetIndicator, error) {
	// Guess network layer type
	packet := gopacket.NewPacket(contents, layers.LayerTypeIPv4, gopacket.Default)
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return nil, errors.New("missing network layer")
	}
	if networkLayer.LayerType() != layers.LayerTypeIPv4 {
		return nil, errors.New("network layer type not support")
	}
	ipVersion := networkLayer.(*layers.IPv4).Version
	switch ipVersion {
	case 4:
		break
	case 6:
		// Not IPv4, but IPv6
		embPacket := gopacket.NewPacket(contents, layers.LayerTypeIPv6, gopacket.Default)
		networkLayer = embPacket.NetworkLayer()
		if networkLayer == nil {
			return nil, errors.New("missing network layer")
		}
		if networkLayer.LayerType() != layers.LayerTypeIPv6 {
			return nil, errors.New("network layer type not support")
		}
	default:
		return nil, fmt.Errorf("ip version %d not support", ipVersion)
	}

	// Parse packet
	indicator, err := parsePacket(packet)
	if err != nil {
		return nil, err
	}
	return indicator, nil
}

func parseRawPacket(contents []byte) (*gopacket.Packet, error) {
	// Guess link layer type, and here we regard loopback layer as a link layer
	packet := gopacket.NewPacket(contents, layers.LayerTypeLoopback, gopacket.Default)
	if len(packet.Layers()) < 0 {
		return nil, errors.New("missing link layer")
	}
	// Raw packet must start from the link layer
	linkLayer := packet.Layers()[0]
	if linkLayer.LayerType() != layers.LayerTypeLoopback {
		// Not Loopback, then Ethernet
		packet = gopacket.NewPacket(contents, layers.LayerTypeEthernet, gopacket.Default)
		linkLayer := packet.LinkLayer()
		if linkLayer == nil {
			return nil, errors.New("missing link layer")
		}
		if linkLayer.LayerType() != layers.LayerTypeEthernet {
			return nil, errors.New("link layer type not support")
		}
	}

	return &packet, nil
}

func sendTCPPacket(addr string, data []byte) error {
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

func sendUDPPacket(addr string, data []byte) error {
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
