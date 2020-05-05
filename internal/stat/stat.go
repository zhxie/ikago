package stat

import (
	"errors"
	"fmt"
	"ikago/internal/log"
	"sync"
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

func (indicator *TrafficIndicator) String() string {
	return fmt.Sprintf("%s (%d packets)", formatSize(indicator.size), indicator.count)
}

// VerboseString prints string with verbose contents.
func (indicator *TrafficIndicator) VerboseString() string {
	appear := fmt.Sprintf("%d-%02d-%02d %02d:%02d:%02d",
		indicator.appear.Year(), indicator.appear.Month(), indicator.appear.Day(), indicator.appear.Hour(), indicator.appear.Minute(), indicator.appear.Second())
	update := fmt.Sprintf("%d-%02d-%02d %02d:%02d:%02d",
		indicator.lastSeen.Year(), indicator.lastSeen.Month(), indicator.lastSeen.Day(), indicator.lastSeen.Hour(), indicator.lastSeen.Minute(), indicator.lastSeen.Second())

	return fmt.Sprintf("%s (%d packets) (%s/%s)", formatSize(indicator.size), indicator.count, appear, update)
}

// TrafficManager describes traffic statistics from and to different nodes.
type TrafficManager struct {
	nodes          []string
	indicatorsLock sync.RWMutex
	indicators     map[string]*TrafficIndicator
}

// NewTrafficManager returns a new traffic manager.
func NewTrafficManager() *TrafficManager {
	manager := &TrafficManager{
		nodes:      append(make([]string, 0), "total"),
		indicators: make(map[string]*TrafficIndicator),
	}
	manager.indicators["total"] = &TrafficIndicator{appear: time.Now()}
	return manager
}

// Nodes returns all nodes in the traffic manager.
func (manager *TrafficManager) Nodes() []string {
	return manager.nodes
}

// Indicator returns the traffic indicator of the given node.
func (manager *TrafficManager) Indicator(node string) (*TrafficIndicator, error) {
	manager.indicatorsLock.RLock()
	indicator, ok := manager.indicators[node]
	manager.indicatorsLock.RUnlock()
	if !ok {
		return nil, errors.New("untracked node")
	}

	return indicator, nil
}

// Add adds a data of traffic to a node.
func (manager *TrafficManager) Add(node string, size uint) {
	manager.indicatorsLock.RLock()
	indicator, ok := manager.indicators[node]
	manager.indicatorsLock.RUnlock()
	if !ok {
		manager.nodes = append(manager.nodes, node)
		indicator = &TrafficIndicator{appear: time.Now()}
		manager.indicatorsLock.Lock()
		manager.indicators[node] = indicator
		manager.indicatorsLock.Unlock()
		log.Verbosef("Track new traffic from %s\n", node)
	}
	indicator.Add(size)
	manager.addTotal(size)
}

func (manager *TrafficManager) addTotal(size uint) {
	manager.indicatorsLock.Lock()
	indicator, _ := manager.indicators["total"]
	manager.indicatorsLock.Unlock()
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
