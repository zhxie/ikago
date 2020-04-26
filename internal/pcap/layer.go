package pcap

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
	ipv4Layer := &layers.IPv4{
		Version: 4,
		IHL:     5,
		// Length: 0,
		Id:  id,
		TTL: ttl,
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

// CreateLayers return layers of transmission between client and server.
func CreateLayers(srcPort, dstPort uint16, seq, ack uint32, conn *RawConn, dstIP net.IP, id uint16, hop uint8,
	dstHardwareAddr net.HardwareAddr) (transportLayer, networkLayer, linkLayer gopacket.SerializableLayer, err error) {
	var (
		linkLayerType gopacket.LayerType
	)

	// Create transport layer
	transportLayer = CreateTCPLayer(srcPort, dstPort, seq, ack)

	// Create new network layer
	networkLayer, err = CreateIPv4Layer(conn.LocalDev().IPAddr().IP, dstIP, id, hop-1, transportLayer.(gopacket.TransportLayer))
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
