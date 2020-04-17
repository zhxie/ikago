package stat

import (
	"errors"
	"fmt"
	"ikago/internal/log"
)

// TrafficManager describes traffic statistics from and to different nodes.
type TrafficManager struct {
	nodes      []string
	indicators map[string]*TrafficIndicator
}

// NewTrafficManager returns a new traffic manager.
func NewTrafficManager() *TrafficManager {
	return &TrafficManager{
		nodes:      make([]string, 0),
		indicators: make(map[string]*TrafficIndicator),
	}
}

// Nodes returns all nodes in the traffic manager.
func (manager *TrafficManager) Nodes() []string {
	return manager.nodes
}

// Indicator returns the traffic indicator of the given node.
func (manager *TrafficManager) Indicator(node string) (*TrafficIndicator, error) {
	indicator, ok := manager.indicators[node]
	if !ok {
		return nil, errors.New("untracked node")
	}

	return indicator, nil
}

// Add adds a data of traffic to a node.
func (manager *TrafficManager) Add(node string, size uint) {
	indicator, ok := manager.indicators[node]
	if !ok {
		indicator = &TrafficIndicator{}
		manager.indicators[node] = indicator
		log.Verbosef("Track new traffic from %s\n", node)
	}
	indicator.Add(size)
}

// TrafficIndicator describes inbound and outbound traffic statistics.
type TrafficIndicator struct {
	count uint
	size  uint
}

// Count returns the count of data.
func (indicator *TrafficIndicator) Count() uint {
	return indicator.count
}

// Size returns the size of data.
func (indicator *TrafficIndicator) Size() uint {
	return indicator.size
}

// Add adds a data of traffic.
func (indicator *TrafficIndicator) Add(size uint) {
	indicator.size = indicator.size + size
	indicator.count++
}

func (indicator *TrafficIndicator) String() string {
	return fmt.Sprintf("%d Bytes (%d packets)", indicator.size, indicator.count)
}
