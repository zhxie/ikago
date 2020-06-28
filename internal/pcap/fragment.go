package pcap

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/zhxie/ikago/internal/log"
	"sort"
	"time"
)

type fragFlow struct {
	id  uint16
	src string
}

type fragIndicator struct {
	length   uint16
	offset   uint16
	frags    []*PacketIndicator
	lastSeen time.Time
}

func newFragIndicator() *fragIndicator {
	return &fragIndicator{
		frags:    make([]*PacketIndicator, 0),
		lastSeen: time.Now(),
	}
}

func (indicator *fragIndicator) append(ind *PacketIndicator) {
	indicator.frags = append(indicator.frags, ind)
	indicator.lastSeen = time.Now()

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

func (indicator *fragIndicator) isCompleted() bool {
	return indicator.length/8 == indicator.offset
}

func (indicator *fragIndicator) concatenate() (*PacketIndicator, error) {
	var (
		err             error
		newNetworkLayer gopacket.NetworkLayer
		contents        []byte
		data            []byte
		ind             *PacketIndicator
	)

	if !indicator.isCompleted() {
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

// Defragmenter is a machine defragments packets.
type Defragmenter interface {
	// TODO: Receive []byte instead of *PacketIndicator
	// Append adds a fragment to the defragmenter. This is a no copy (of original packets) method.
	Append(ind *PacketIndicator) (*PacketIndicator, error)
	// SetDeadline sets the deadline associated with the fragments.
	SetDeadline(t time.Duration)
}

// EasyDefragmenter is a machine defragments packets which also accepts non-standard packets.
type EasyDefragmenter struct {
	frags    map[fragFlow]*fragIndicator
	deadline time.Duration
}

// NewEasyDefragmenter returns a new easy defragmenter.
func NewEasyDefragmenter() *EasyDefragmenter {
	return &EasyDefragmenter{frags: make(map[fragFlow]*fragIndicator)}
}

func (defrag *EasyDefragmenter) Append(ind *PacketIndicator) (*PacketIndicator, error) {
	indicator, _, err := defrag.AppendOriginal(ind)

	return indicator, err
}

// AppendOriginal adds a fragment to the defragmenter and returns packets with and without defragmentation.
func (defrag *EasyDefragmenter) AppendOriginal(ind *PacketIndicator) (*PacketIndicator, []*PacketIndicator, error) {
	if !ind.IsFrag() {
		return ind, append(make([]*PacketIndicator, 0), ind), nil
	}

	flow := fragFlow{
		id:  ind.NetworkId(),
		src: ind.SrcIP().String(),
	}
	fragIndicator, ok := defrag.frags[flow]
	if !ok || fragIndicator == nil {
		fragIndicator = newFragIndicator()
		defrag.frags[flow] = fragIndicator
	}

	// Replace old fragments
	if defrag.deadline > 0 && time.Now().Sub(fragIndicator.lastSeen) > defrag.deadline {
		log.Verbosef("Recycle fragments %d from %s\n", flow.id, flow.src)
		fragIndicator = newFragIndicator()
		defrag.frags[flow] = fragIndicator
	}

	fragIndicator.append(ind)

	if !fragIndicator.isCompleted() {
		return nil, nil, nil
	}

	// Remove completed fragments
	defrag.frags[flow] = nil

	// Concatenate fragments
	indicator, err := fragIndicator.concatenate()
	if err != nil {
		return nil, nil, fmt.Errorf("concatenate: %w", err)
	}

	return indicator, fragIndicator.frags, nil
}

func (defrag *EasyDefragmenter) SetDeadline(t time.Duration) {
	defrag.deadline = t
}

// StrictDefragmenter is a machine defragments packets which drops invalid packets.
type StrictDefragmenter struct {
	defragmenter *ip4defrag.IPv4Defragmenter
	deadline     time.Duration
}

// NewStrictDefragmenter returns a new strict defragmenter.
func NewStrictDefragmenter() *StrictDefragmenter {
	return &StrictDefragmenter{defragmenter: ip4defrag.NewIPv4Defragmenter()}
}

func (defrag *StrictDefragmenter) Append(ind *PacketIndicator) (*PacketIndicator, error) {
	if !ind.IsFrag() {
		return ind, nil
	}

	// Discard old fragments
	if defrag.deadline > 0 {
		defrag.defragmenter.DiscardOlderThan(time.Now().Add(-defrag.deadline))
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

func (defrag *StrictDefragmenter) SetDeadline(t time.Duration) {
	defrag.deadline = t
}

// CreateFragmentPackets creates fragments by given layers and fragment size.
func CreateFragmentPackets(linkLayer, networkLayer, transportLayer gopacket.Layer, payload gopacket.Payload, fragment int) ([][]byte, error) {
	if transportLayer != nil && transportLayer.LayerType() == layers.LayerTypeTCP {
		return CreateTCPSegmentPackets(linkLayer, networkLayer.(gopacket.NetworkLayer), transportLayer.(*layers.TCP), payload, fragment)
	}

	switch t := networkLayer.LayerType(); t {
	case layers.LayerTypeIPv4:
		networkPayload, err := Serialize(transportLayer.(gopacket.SerializableLayer), payload)
		if err != nil {
			return nil, fmt.Errorf("serialize: %w", err)
		}

		return CreateIPv4FragmentPackets(linkLayer, networkLayer.(*layers.IPv4), networkPayload, fragment)
	default:
		return nil, fmt.Errorf("network layer type %s not support", t)
	}
}

// CreateIPFragmentPackets creates IPv4 fragments by given layers and fragment size.
func CreateIPv4FragmentPackets(linkLayer gopacket.Layer, ipv4Layer *layers.IPv4, payload gopacket.Payload, fragment int) ([][]byte, error) {
	var (
		err           error
		ipv4LayerData []byte
		fragments     [][]byte
	)

	// Serialize intermediate headers
	ipv4LayerData, err = Serialize(ipv4Layer)
	if err != nil {
		return nil, fmt.Errorf("serialize: %w", err)
	}

	fragments = make([][]byte, 0)

	// Fragment
	if len(ipv4LayerData)+len(payload) > fragment {
		// Create new IPv4 layer
		temp := *ipv4Layer
		newIPv4Layer := &temp

		// Create fragments
		for i := 0; i < len(payload); {
			var (
				err  error
				data []byte
			)
			length := min(fragment-len(ipv4LayerData), len(payload)-i)
			remain := len(payload) - i - length

			// Align
			if remain > 0 {
				length = length / 8 * 8
				remain = len(payload) - i - length
			}

			// Leave at least 8 Bytes for last fragment
			if remain > 0 && remain < 8 {
				length = length - 8
				remain = len(payload) - i - length
			}

			switch t := newIPv4Layer.LayerType(); t {
			case layers.LayerTypeIPv4:
				if remain <= 0 {
					FlagIPv4Layer(newIPv4Layer, false, false, uint16(i/8))
				} else {
					FlagIPv4Layer(newIPv4Layer, false, true, uint16(i/8))
				}
			default:
				return nil, fmt.Errorf("network layer type %s not support", t)
			}

			// Serialize layers
			if linkLayer == nil {
				data, err = Serialize(newIPv4Layer, payload[i:i+length])
			} else {
				data, err = Serialize(linkLayer.(gopacket.SerializableLayer), newIPv4Layer, payload[i:i+length])
			}
			if err != nil {
				return nil, fmt.Errorf("serialize: %w", err)
			}

			fragments = append(fragments, data)

			i = i + length
		}
	} else {
		var (
			err  error
			data []byte
		)

		// Serialize layers
		if linkLayer == nil {
			data, err = Serialize(ipv4Layer, payload)
		} else {
			data, err = Serialize(linkLayer.(gopacket.SerializableLayer), ipv4Layer, payload)
		}
		if err != nil {
			return nil, fmt.Errorf("serialize: %w", err)
		}

		fragments = append(fragments, data)
	}

	return fragments, nil
}

// CreateTCPSegmentPackets creates TCP segments by given layers and fragment size.
func CreateTCPSegmentPackets(linkLayer gopacket.Layer, networkLayer gopacket.NetworkLayer, tcpLayer *layers.TCP, payload gopacket.Payload, fragment int) ([][]byte, error) {
	var (
		err              error
		networkLayerData []byte
		tcpLayerData     []byte
		fragments        [][]byte
	)

	// Serialize intermediate headers
	networkLayerData, err = Serialize(networkLayer.(gopacket.SerializableLayer))
	if err != nil {
		return nil, fmt.Errorf("serialize: %w", err)
	}
	tcpLayerData, err = SerializeRaw(tcpLayer)
	if err != nil {
		return nil, fmt.Errorf("serialize: %w", err)
	}

	fragments = make([][]byte, 0)

	// Fragment
	if len(networkLayerData)+len(tcpLayerData)+len(payload) > fragment {
		var n uint16 = 0

		// Create fragments
		for i := 0; i < len(payload); {
			var (
				err             error
				newNetworkLayer gopacket.NetworkLayer
				newTCPLayer     *layers.TCP
				data            []byte
			)
			length := min(fragment-len(networkLayerData)-len(tcpLayerData), len(payload)-i)

			// Create new network layer
			switch t := networkLayer.LayerType(); t {
			case layers.LayerTypeIPv4:
				ipv4Layer := networkLayer.(*layers.IPv4)
				temp := *ipv4Layer
				newNetworkLayer = &temp

				newNetworkLayer.(*layers.IPv4).Id = newNetworkLayer.(*layers.IPv4).Id + n
			case layers.LayerTypeIPv6:
				ipv6Layer := networkLayer.(*layers.IPv6)
				temp := *ipv6Layer
				newNetworkLayer = &temp
			default:
				return nil, fmt.Errorf("network layer type %s not support", t)
			}

			// Create new TCP layer
			tempTCPLayer := *tcpLayer
			newTCPLayer = &tempTCPLayer
			newTCPLayer.Seq = newTCPLayer.Seq + uint32(i)

			// Set network layer for transport layer
			err = newTCPLayer.SetNetworkLayerForChecksum(newNetworkLayer)
			if err != nil {
				return nil, fmt.Errorf("set network layer for checksum: %w", err)
			}

			// Serialize layers
			if linkLayer == nil {
				data, err = Serialize(newNetworkLayer.(gopacket.SerializableLayer), newTCPLayer, payload[i:i+length])
			} else {
				data, err = Serialize(linkLayer.(gopacket.SerializableLayer),
					newNetworkLayer.(gopacket.SerializableLayer),
					tcpLayer,
					payload[i:i+length])
			}
			if err != nil {
				return nil, fmt.Errorf("serialize: %w", err)
			}

			fragments = append(fragments, data)

			i = i + length
			n++
		}
	} else {
		var (
			err  error
			data []byte
		)

		// Serialize layers
		if linkLayer == nil {
			data, err = Serialize(networkLayer.(gopacket.SerializableLayer), tcpLayer, payload)
		} else {
			data, err = Serialize(linkLayer.(gopacket.SerializableLayer), networkLayer.(gopacket.SerializableLayer), tcpLayer, payload)
		}
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
