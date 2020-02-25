package pcap

import (
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

func createTCPLayerACK(srcPort, dstPort uint16, seq, ack uint32) *layers.TCP {
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

func createTCPLayerSYNACK(srcPort, dstPort uint16, seq, ack uint32) *layers.TCP {
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

func createTransportLayerTCP(srcPort, dstPort uint16, seq uint32) *layers.TCP {
	return &layers.TCP{
		SrcPort:    layers.TCPPort(srcPort),
		DstPort:    layers.TCPPort(dstPort),
		Seq:        seq,
		DataOffset: 5,
		PSH:        true,
		Window:     65535,
		// Checksum:   0,
	}
}

func createTransportLayerUDP(srcPort, dstPort uint16) *layers.UDP {
	return &layers.UDP{
		SrcPort:   layers.UDPPort(srcPort),
		DstPort:   layers.UDPPort(dstPort),
		// Length:    0,
		// Checksum:  0,
	}
}

func createNetworkLayerIPv4(srcIP, dstIP net.IP, id uint16, ttl uint8, transportLayer gopacket.TransportLayer) (*layers.IPv4, error) {
	ipv4Layer := &layers.IPv4{
		Version:    4,
		IHL:        5,
		// Length:     0,
		Id:         id,
		Flags:      layers.IPv4DontFragment,
		TTL:        ttl,
		// Protocol:   0,
		// Checksum:   0,
		SrcIP:      srcIP,
		DstIP:      dstIP,
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
		return nil, fmt.Errorf("create network layer: %w",
			fmt.Errorf("transport layer type %s not support", transportLayerType))
	}

	return ipv4Layer, nil
}

func createNetworkLayerIPv6(srcIP, dstIP net.IP, transportLayer gopacket.TransportLayer) (*layers.IPv6, error) {
	return nil, fmt.Errorf("create network layer: %w", errors.New("ipv6 not support"))
}

func createLinkLayerLoopback() *layers.Loopback {
	return &layers.Loopback{}
}

func createLinkLayerEthernet(srcMAC, dstMAC net.HardwareAddr, networkLayer gopacket.NetworkLayer) (*layers.Ethernet, error) {
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
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
		return nil, fmt.Errorf("create link layer: %w",
			fmt.Errorf("type %s not support", networkLayerType))
	}

	return ethernetLayer, nil
}

func serialize(linkLayer gopacket.Layer, networkLayer gopacket.NetworkLayer, transportLayer gopacket.TransportLayer, contents []byte) ([]byte, error) {
	linkLayerType := linkLayer.LayerType()
	networkLayerType := networkLayer.LayerType()
	transportLayerType := transportLayer.LayerType()

	// Recalculate checksum and length
	options := gopacket.SerializeOptions{ComputeChecksums:true, FixLengths:true}
	buffer := gopacket.NewSerializeBuffer()

	var err error
	switch linkLayerType {
	case layers.LayerTypeLoopback:
		switch networkLayerType {
		case layers.LayerTypeIPv4:
			switch transportLayerType {
			case layers.LayerTypeTCP:
				err = gopacket.SerializeLayers(buffer, options,
					linkLayer.(*layers.Loopback),
					networkLayer.(*layers.IPv4),
					transportLayer.(*layers.TCP),
					gopacket.Payload(contents),
				)
			case layers.LayerTypeUDP:
				err = gopacket.SerializeLayers(buffer, options,
					linkLayer.(*layers.Loopback),
					networkLayer.(*layers.IPv4),
					transportLayer.(*layers.UDP),
					gopacket.Payload(contents),
				)
			default:
				return nil, fmt.Errorf("serialize: %w",
					fmt.Errorf("transport layer type %s not support", transportLayerType))
			}
		case layers.LayerTypeIPv6:
			switch transportLayerType {
			case layers.LayerTypeTCP:
				err = gopacket.SerializeLayers(buffer, options,
					linkLayer.(*layers.Loopback),
					networkLayer.(*layers.IPv6),
					transportLayer.(*layers.TCP),
					gopacket.Payload(contents),
				)
			case layers.LayerTypeUDP:
				err = gopacket.SerializeLayers(buffer, options,
					linkLayer.(*layers.Loopback),
					networkLayer.(*layers.IPv6),
					transportLayer.(*layers.UDP),
					gopacket.Payload(contents),
				)
			default:
				return nil, fmt.Errorf("serialize: %w",
					fmt.Errorf("transport layer type %s not support", transportLayerType))
			}
		default:
			return nil, fmt.Errorf("serialize: %w",
				fmt.Errorf("network layer type %s not support", networkLayerType))
		}
	case layers.LayerTypeEthernet:
		switch networkLayerType {
		case layers.LayerTypeIPv4:
			switch transportLayerType {
			case layers.LayerTypeTCP:
				err = gopacket.SerializeLayers(buffer, options,
					linkLayer.(*layers.Ethernet),
					networkLayer.(*layers.IPv4),
					transportLayer.(*layers.TCP),
					gopacket.Payload(contents),
				)
			case layers.LayerTypeUDP:
				err = gopacket.SerializeLayers(buffer, options,
					linkLayer.(*layers.Ethernet),
					networkLayer.(*layers.IPv4),
					transportLayer.(*layers.UDP),
					gopacket.Payload(contents),
				)
			default:
				return nil, fmt.Errorf("serialize: %w",
					fmt.Errorf("transport layer type %s not support", transportLayerType))
			}
		case layers.LayerTypeIPv6:
			switch transportLayerType {
			case layers.LayerTypeTCP:
				err = gopacket.SerializeLayers(buffer, options,
					linkLayer.(*layers.Ethernet),
					networkLayer.(*layers.IPv6),
					transportLayer.(*layers.TCP),
					gopacket.Payload(contents),
				)
			case layers.LayerTypeUDP:
				err = gopacket.SerializeLayers(buffer, options,
					linkLayer.(*layers.Ethernet),
					networkLayer.(*layers.IPv6),
					transportLayer.(*layers.UDP),
					gopacket.Payload(contents),
				)
			default:
				return nil, fmt.Errorf("serialize: %w",
					fmt.Errorf("transport layer type %s not support", transportLayerType))
			}
		default:
			return nil, fmt.Errorf("serialize: %w",
				fmt.Errorf("network layer type %s not support", networkLayerType))
		}
	default:
		return nil, fmt.Errorf("serialize: %w",
			fmt.Errorf("link layer type %s not support", linkLayerType))
	}
	if err != nil {
		return nil, fmt.Errorf("serialize: %w", err)
	}

	return buffer.Bytes(), nil
}
