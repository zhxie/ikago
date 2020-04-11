package pcap

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
)

// Defragmenter is a machine defragments packets.
type Defragmenter struct {
	defragmenter *ip4defrag.IPv4Defragmenter
}

// NewDefragmenter returns a new defragmenter.
func NewDefragmenter() *Defragmenter {
	return &Defragmenter{defragmenter: ip4defrag.NewIPv4Defragmenter()}
}

// Append adds a fragment to the defragmenter.
func (defrag *Defragmenter) Append(ind *PacketIndicator) (*PacketIndicator, error) {
	if !ind.IsFrag() {
		return ind, nil
	}

	layer, err := defrag.defragmenter.DefragIPv4(ind.IPv4Layer())
	if err != nil {
		return nil, fmt.Errorf("defrag: %w", err)
	}

	if layer == nil {
		return nil, nil
	}

	// Serialize
	data, err := Serialize(layer, gopacket.Payload(layer.Payload))
	if err != nil {
		return nil, fmt.Errorf("serialize: %w", err)
	}

	indicator, err := ParseEmbPacket(data)
	if err != nil {
		return nil, fmt.Errorf("parse packet: %w", err)
	}

	return indicator, nil
}

// CreateFragmentPackets creates fragments by giver layers and fragment size.
func CreateFragmentPackets(linkLayer, networkLayer, transportLayer, payload gopacket.Layer, fragment int) ([][]byte, error) {
	var (
		err                   error
		networkLayerData      []byte
		networkLayerPayload   []byte
		fragments             [][]byte
	)

	// Serialize intermediate headers
	networkLayerData, err = Serialize(networkLayer.(gopacket.SerializableLayer))
	if err != nil {
		return nil, fmt.Errorf("serialize: %w", err)
	}
	if transportLayer == nil {
		networkLayerPayload, err = Serialize(networkLayer.(gopacket.SerializableLayer),
			payload.(gopacket.SerializableLayer))
	} else {
		networkLayerPayload, err = Serialize(networkLayer.(gopacket.SerializableLayer),
			transportLayer.(gopacket.SerializableLayer),
			payload.(gopacket.SerializableLayer))
	}
	if err != nil {
		return nil, fmt.Errorf("serialize: %w", err)
	}
	networkLayerPayload = networkLayerPayload[len(networkLayerData):]

	fragments = make([][]byte, 0)

	// Fragment
	if len(networkLayerData) + len(networkLayerPayload) > fragment {
		var newNetworkLayer   gopacket.NetworkLayer

		// Create new network layer
		switch t := networkLayer.LayerType(); t {
		case layers.LayerTypeIPv4:
			newIPv4Layer := networkLayer.(*layers.IPv4)
			temp := *newIPv4Layer
			newNetworkLayer = &temp
		default:
			return nil, fmt.Errorf("network layer type %s not support", t)
		}

		// Create fragments
		for i := 0; i < len(networkLayerPayload); {
			length := min(fragment-len(networkLayerData), len(networkLayerPayload)-i)
			remain := len(networkLayerPayload) - i - length

			// Align
			if remain > 0 {
				length = length / 8 * 8
				remain = len(networkLayerPayload) - i - length
			}

			switch t := newNetworkLayer.LayerType(); t {
			case layers.LayerTypeIPv4:
				ipv4Layer := newNetworkLayer.(*layers.IPv4)

				if remain <= 0 {
					FlagIPv4Layer(ipv4Layer, false, false, uint16(i/8))
				} else {
					FlagIPv4Layer(ipv4Layer, false, true, uint16(i/8))
				}
			default:
				return nil, fmt.Errorf("network layer type %s not support", t)
			}

			// Serialize layers
			data, err := Serialize(linkLayer.(gopacket.SerializableLayer),
				newNetworkLayer.(gopacket.SerializableLayer),
				gopacket.Payload(networkLayerPayload[i:i+length]))
			if err != nil {
				return nil, fmt.Errorf("serialize: %w", err)
			}

			fragments = append(fragments, data)

			i = i + length
		}
	} else {
		// Serialize layers
		data, err := Serialize(linkLayer.(gopacket.SerializableLayer),
			networkLayer.(gopacket.SerializableLayer),
			gopacket.Payload(networkLayerPayload))
		if err != nil {
			return nil, fmt.Errorf("serialize: %w", err)
		}

		fragments = append(fragments, data)
	}

	return fragments, nil
}

func min(a, b int) int {
	if a > b {
		return b
	}

	return a
}
