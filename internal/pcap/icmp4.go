package pcap

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"ikago/internal/addr"
	"net"
)

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
