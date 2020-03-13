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
	packet gopacket.Packet
	dev    *Device
	handle *pcap.Handle
}

type quintuple struct {
	srcIP    string
	srcValue uint16
	dstIP    string
	dstValue uint16
	proto    gopacket.LayerType
}

type devIndicator struct {
	dev    *Device
	handle *pcap.Handle
}

type natGuide struct {
	src   string
	proto gopacket.LayerType
}

type natIndicator interface {
	dev() *Device
	handle() *pcap.Handle
	encSource() string
}

type portNATIndicator struct {
	srcIP      string
	srcPort    uint16
	encSrcIP   string
	encSrcPort uint16
	mDev       *Device
	mHandle    *pcap.Handle
}

func (indicator *portNATIndicator) dev() *Device {
	return indicator.mDev
}

func (indicator *portNATIndicator) handle() *pcap.Handle {
	return indicator.mHandle
}

func (indicator *portNATIndicator) encSource() string {
	return IPPort{
		IP:   net.ParseIP(indicator.encSrcIP),
		Port: indicator.encSrcPort,
	}.String()
}

type idNATIndicator struct {
	srcIP    string
	srcPort  uint16
	encSrcIP string
	encId    uint16
	mDev     *Device
	mHandle  *pcap.Handle
}

func (indicator *idNATIndicator) dev() *Device {
	return indicator.mDev
}

func (indicator *idNATIndicator) handle() *pcap.Handle {
	return indicator.mHandle
}

func (indicator *idNATIndicator) encSource() string {
	return IPId{
		IP: net.ParseIP(indicator.encSrcIP),
		Id: indicator.encId,
	}.String()
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
		panic(fmt.Errorf("src ip: %w", fmt.Errorf("type %s not support", indicator.networkLayerType)))
	}
}

func (indicator *packetIndicator) dstIP() net.IP {
	switch indicator.networkLayerType {
	case layers.LayerTypeIPv4:
		return indicator.ipv4Layer().DstIP
	case layers.LayerTypeIPv6:
		return indicator.ipv6Layer().DstIP
	default:
		panic(fmt.Errorf("dst ip: %w", fmt.Errorf("type %s not support", indicator.networkLayerType)))
	}
}

func (indicator *packetIndicator) srcPort() uint16 {
	switch indicator.transportLayerType {
	case layers.LayerTypeTCP:
		return uint16(indicator.tcpLayer().SrcPort)
	case layers.LayerTypeUDP:
		return uint16(indicator.udpLayer().SrcPort)
	default:
		panic(fmt.Errorf("src port: %w", fmt.Errorf("type %s not support", indicator.transportLayerType)))
	}
}

func (indicator *packetIndicator) dstPort() uint16 {
	switch indicator.transportLayerType {
	case layers.LayerTypeTCP:
		return uint16(indicator.tcpLayer().DstPort)
	case layers.LayerTypeUDP:
		return uint16(indicator.udpLayer().DstPort)
	default:
		panic(fmt.Errorf("dst port: %w", fmt.Errorf("type %s not support", indicator.transportLayerType)))
	}
}

func (indicator *packetIndicator) natSource() string {
	t := indicator.transportLayerType
	switch t {
	case layers.LayerTypeTCP, layers.LayerTypeUDP:
		return IPPort{
			IP:   indicator.srcIP(),
			Port: indicator.srcPort(),
		}.String()
	case layers.LayerTypeICMPv4:
		if indicator.icmpv4Indicator.isQuery() {
			return IPId{
				IP: indicator.srcIP(),
				Id: indicator.icmpv4Indicator.id(),
			}.String()
		} else {
			// The ICMPv4 error includes the original packet, so flip it
			return indicator.icmpv4Indicator.destination()
		}
	default:
		panic(fmt.Errorf("source: %w", fmt.Errorf("type %s not support", t)))
	}
}

func (indicator *packetIndicator) natDestination() string {
	t := indicator.transportLayerType
	switch t {
	case layers.LayerTypeTCP, layers.LayerTypeUDP:
		return IPPort{
			IP:   indicator.dstIP(),
			Port: indicator.dstPort(),
		}.String()
	case layers.LayerTypeICMPv4:
		if indicator.icmpv4Indicator.isQuery() {
			return IPId{
				IP: indicator.dstIP(),
				Id: indicator.icmpv4Indicator.id(),
			}.String()
		} else {
			// The ICMPv4 error includes the original packet, so flip it
			return indicator.icmpv4Indicator.source()
		}
	default:
		panic(fmt.Errorf("destination: %w", fmt.Errorf("type %s not support", t)))
	}
}

func (indicator *packetIndicator) natProto() gopacket.LayerType {
	t := indicator.transportLayerType
	switch t {
	case layers.LayerTypeTCP, layers.LayerTypeUDP:
		return t
	case layers.LayerTypeICMPv4:
		if indicator.icmpv4Indicator.isQuery() {
			return t
		} else {
			return indicator.icmpv4Indicator.encTransportLayerType
		}
	default:
		panic(fmt.Errorf("proto: %w", fmt.Errorf("type %s not support", t)))
	}
}

func (indicator *packetIndicator) source() string {
	t := indicator.transportLayerType
	switch t {
	case layers.LayerTypeTCP, layers.LayerTypeUDP:
		return IPPort{
			IP:   indicator.srcIP(),
			Port: indicator.srcPort(),
		}.String()
	case layers.LayerTypeICMPv4:
		if indicator.icmpv4Indicator.isQuery() {
			return IPId{
				IP: indicator.srcIP(),
				Id: indicator.icmpv4Indicator.id(),
			}.String()
		} else {
			return formatIP(indicator.srcIP())
		}
	default:
		panic(fmt.Errorf("source: %w", fmt.Errorf("type %s not support", t)))
	}
}

func (indicator *packetIndicator) destination() string {
	t := indicator.transportLayerType
	switch t {
	case layers.LayerTypeTCP, layers.LayerTypeUDP:
		return IPPort{
			IP:   indicator.dstIP(),
			Port: indicator.dstPort(),
		}.String()
	case layers.LayerTypeICMPv4:
		return formatIP(indicator.dstIP())
	default:
		panic(fmt.Errorf("destination: %w", fmt.Errorf("type %s not support", t)))
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
		networkLayer:       networkLayer,
		networkLayerType:   networkLayerType,
		transportLayer:     transportLayer,
		transportLayerType: transportLayerType,
		icmpv4Indicator:    icmpv4Indicator,
		applicationLayer:   applicationLayer,
	}, nil
}

func parseEncPacket(contents []byte) (*packetIndicator, error) {
	// Guess network layer type
	packet := gopacket.NewPacket(contents, layers.LayerTypeIPv4, gopacket.Default)
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return nil, fmt.Errorf("parse enc: %w", errors.New("missing network layer"))
	}
	if networkLayer.LayerType() != layers.LayerTypeIPv4 {
		return nil, fmt.Errorf("parse enc: %w", errors.New("network layer type not support"))
	}
	ipVersion := networkLayer.(*layers.IPv4).Version
	switch ipVersion {
	case 4:
		break
	case 6:
		// Not IPv4, but IPv6
		encPacket := gopacket.NewPacket(contents, layers.LayerTypeIPv6, gopacket.Default)
		networkLayer = encPacket.NetworkLayer()
		if networkLayer == nil {
			return nil, fmt.Errorf("parse enc: %w", errors.New("missing network layer"))
		}
		if networkLayer.LayerType() != layers.LayerTypeIPv6 {
			return nil, fmt.Errorf("parse enc: %w", errors.New("network layer type not support"))
		}
	default:
		return nil, fmt.Errorf("parse enc: %w", fmt.Errorf("ip version %d not support", ipVersion))
	}

	// Parse packet
	indicator, err := parsePacket(packet)
	if err != nil {
		return nil, fmt.Errorf("parse enc: %w", err)
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
