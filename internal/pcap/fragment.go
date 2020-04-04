package pcap

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"sort"
)

// ConnPacket describes fragments.
type FragIndicator struct {
	length uint16
	offset uint16
	frags  []*PacketIndicator
}

// NewFragIndicator returns a new fragment indicator.
func NewFragIndicator() *FragIndicator {
	return &FragIndicator{
		frags: make([]*PacketIndicator, 0),
	}
}

// Append appends a fragment.
func (indicator *FragIndicator) Append(ind *PacketIndicator) {
	indicator.frags = append(indicator.frags, ind)

	if ind.MoreFragments() {
		indicator.length = indicator.length + uint16(len(ind.NetworkPayload()))
	} else {
		// Final fragment
		indicator.offset = ind.FragOffset()
	}

	// Sort
	if len(indicator.frags) <= 1 {
		return
	}
	sort.Slice(indicator.frags, func(i, j int) bool {
		return indicator.frags[i].FragOffset() < indicator.frags[j].FragOffset()
	})
}

// IsCompleted returns if fragments are completed.
func (indicator *FragIndicator) IsCompleted() bool {
	return indicator.length/8 == indicator.offset
}

// Concatenate concatenates fragments and returns reassembled packet indicator.
func (indicator *FragIndicator) Concatenate() (*PacketIndicator, error) {
	var (
		err                    error
		newNetworkLayer        gopacket.NetworkLayer
		contents               []byte
		data                   []byte
		ind                    *PacketIndicator
	)

	if !indicator.IsCompleted() {
		return nil, errors.New("incomplete fragments")
	}

	// Create new network layer
	switch t := indicator.frags[0].NetworkLayer().LayerType(); t {
	case layers.LayerTypeIPv4:
		ipv4Layer := indicator.frags[0].IPv4Layer()
		temp := *ipv4Layer
		newNetworkLayer = &temp

		FlagIPv4Layer(newNetworkLayer.(*layers.IPv4), false, false, 0)
	default:
		return nil, fmt.Errorf("network layer type %s not support", t)
	}

	// Concatenate network payloads
	contents = make([]byte, 0)
	for _, frag := range indicator.frags {
		contents = append(contents, frag.NetworkPayload()...)
	}

	// Serialize
	if indicator.frags[0].LinkLayer() == nil {
		data, err = Serialize(newNetworkLayer.(gopacket.SerializableLayer),
			gopacket.Payload(contents))
	} else {
		data, err = Serialize(indicator.frags[0].LinkLayer().(gopacket.SerializableLayer),
			newNetworkLayer.(gopacket.SerializableLayer),
			gopacket.Payload(contents))
	}
	if err != nil {
		return nil, fmt.Errorf("serialize: %w", err)
	}

	// Parse packet
	if indicator.frags[0].LinkLayer() == nil {
		ind, err = ParseEmbPacket(data)
	} else {
		var packet gopacket.Packet

		packet, err = ParseRawPacket(data)
		if err != nil {
			return nil, fmt.Errorf("parse packet: %w", err)
		}

		ind, err = ParsePacket(packet)
	}
	if err != nil {
		return nil, fmt.Errorf("parse packet: %w", err)
	}

	return ind, nil
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
			newIPv4Layer := newNetworkLayer.(*layers.IPv4)
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
		data, err := SerializeRaw(linkLayer.(gopacket.SerializableLayer),
			gopacket.Payload(networkLayerData),
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
