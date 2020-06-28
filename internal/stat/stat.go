package stat

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zhxie/ikago/internal/log"
	"strings"
	"time"
)

// TrafficIndicator describes traffic statistics.
type TrafficIndicator struct {
	count    uint64
	size     uint64
	appear   time.Time
	lastSeen time.Time
}

// Count returns the count of data.
func (indicator *TrafficIndicator) Count() uint64 {
	return indicator.count
}

// Size returns the size of data.
func (indicator *TrafficIndicator) Size() uint64 {
	return indicator.size
}

// Appear returns the appear time of data.
func (indicator *TrafficIndicator) Appear() time.Time {
	return indicator.appear
}

// LastSeen returns the last seen time of data.
func (indicator *TrafficIndicator) LastSeen() time.Time {
	return indicator.lastSeen
}

// Add adds a data of traffic.
func (indicator *TrafficIndicator) Add(size uint) {
	indicator.count++
	indicator.size = indicator.size + uint64(size)
	indicator.lastSeen = time.Now()
}

func (indicator *TrafficIndicator) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Count    uint64 `json:"count"`
		Size     uint64 `json:"size"`
		Appear   int64  `json:"appear"`
		LastSeen int64  `json:"lastSeen"`
	}{
		Count:    indicator.Count(),
		Size:     indicator.Size(),
		Appear:   indicator.Appear().Unix(),
		LastSeen: indicator.LastSeen().Unix(),
	})
}

func (indicator TrafficIndicator) String() string {
	return fmt.Sprintf("%s (%d packets)", formatSize(indicator.Size()), indicator.Count())
}

// TrafficManager describes traffic statistics from and to different nodes.
type TrafficManager struct {
	nodes      []string
	indicators map[string]*TrafficIndicator
}

// NewTrafficManager returns a new traffic manager.
func NewTrafficManager() *TrafficManager {
	manager := &TrafficManager{
		nodes:      make([]string, 0),
		indicators: make(map[string]*TrafficIndicator),
	}
	return manager
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
		manager.nodes = append(manager.nodes, node)
		indicator = &TrafficIndicator{appear: time.Now()}
		manager.indicators[node] = indicator
		log.Verbosef("Track new traffic from %s\n", node)
	}
	indicator.Add(size)
}

func formatSize(b uint64) string {
	if b < 1024 {
		return fmt.Sprintf("%d Bytes", b)
	} else if b < 1048576 {
		return fmt.Sprintf("%.2f KB", float32(b)/1024)
	} else if b < 1073741824 {
		return fmt.Sprintf("%.2f MB", float32(b)/1048576)
	}

	return fmt.Sprintf("%.2f GB", float32(b)/1073741824)
}

func (manager TrafficManager) MarshalJSON() ([]byte, error) {
	return json.Marshal(manager.indicators)
}

func (manager TrafficManager) String() string {
	sb := strings.Builder{}

	for _, node := range manager.Nodes() {
		indicator, err := manager.Indicator(node)
		if err != nil {
			sb.WriteString(fmt.Sprintf("%s", fmt.Errorf("statistics: %s: %w", node, err)))
		}

		sb.WriteString(fmt.Sprintf("%s: %s", node, indicator))

		sb.WriteString("\n")
	}

	return sb.String()
}
